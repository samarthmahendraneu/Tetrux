// SPDX-License-Identifier: Apache-2.0
// Tetrux Tier-0 Linux XDP eBPF Redirect & Early DDoS Drop Program.
//
// Compile on Linux with:
//   clang -O2 -g -target bpf -c ebpf/tetrux_xdp.c -o ebpf/tetrux_xdp.o
// Attach to NIC (e.g. eth0):
//   ip link set dev eth0 xdpgeneric obj ebpf/tetrux_xdp.o sec xdp   # or xdpdrv for native zero-copy
//
// Runs inside the NIC driver BEFORE sk_buff allocation:
//   1. Drops source IPs listed in `blocklist_map` at hardware line rate (`XDP_DROP`).
//   2. Matches destination VIP:port (TCP/UDP) against `vip_map`.
//   3. Redirects matched VIP traffic directly to the per-core zero-copy AF_XDP UMEM ring (`xsks_map`).
//   4. Passes non-VIP management/BGP/SSH traffic cleanly to the Linux kernel stack (`XDP_PASS`).

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct vip_key {
    __u32 dst_ip;
    __u16 dst_port;
    __u8  proto;
    __u8  pad;
};

enum stat_idx {
    STAT_RX_TOTAL    = 0,
    STAT_XDP_DROP    = 1,
    STAT_XDP_REDIR   = 2,
    STAT_XDP_PASS    = 3,
    STAT_MAX         = 4,
};

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct vip_key);
    __type(value, __u32);
} vip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); // Blocked IPv4 source address (network byte order)
    __type(value, __u64);
} blocklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

static __always_inline void bump_stat(__u32 idx) {
    __u64 *cnt = bpf_map_lookup_elem(&stats_map, &idx);
    if (cnt) {
        (*cnt)++;
    }
}

SEC("xdp")
int tetrux_xdp_redirect(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    bump_stat(STAT_RX_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bump_stat(STAT_XDP_DROP);
        return XDP_DROP;
    }

    __u16 h_proto = eth->h_proto;
    void *l3 = (void *)(eth + 1);

    // Unwrap single 802.1Q VLAN tag if present
    if (h_proto == bpf_htons(ETH_P_8021Q)) {
        if (l3 + 4 > data_end) {
            bump_stat(STAT_XDP_DROP);
            return XDP_DROP;
        }
        h_proto = *(__u16 *)(l3 + 2);
        l3 += 4;
    }

    // Pass ARP directly to kernel + userspace neighbor discovery
    if (h_proto == bpf_htons(ETH_P_ARP)) {
        bump_stat(STAT_XDP_PASS);
        return XDP_PASS;
    }

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = l3;
        if ((void *)(iph + 1) > data_end) {
            bump_stat(STAT_XDP_DROP);
            return XDP_DROP;
        }
        if (iph->version != 4 || iph->ihl < 5) {
            bump_stat(STAT_XDP_DROP);
            return XDP_DROP;
        }

        // Line-rate DDoS source IP blocklist drop before sk_buff allocation!
        __u32 sip = iph->saddr;
        if (bpf_map_lookup_elem(&blocklist_map, &sip)) {
            bump_stat(STAT_XDP_DROP);
            return XDP_DROP;
        }

        void *l4 = l3 + ((__u32)iph->ihl * 4);
        __u16 dport = 0;
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = l4;
            if ((void *)(tcph + 1) > data_end) {
                bump_stat(STAT_XDP_DROP);
                return XDP_DROP;
            }
            dport = tcph->dest;
        } else if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = l4;
            if ((void *)(udph + 1) > data_end) {
                bump_stat(STAT_XDP_DROP);
                return XDP_DROP;
            }
            dport = udph->dest;
        } else {
            bump_stat(STAT_XDP_PASS);
            return XDP_PASS;
        }

        struct vip_key key = {
            .dst_ip   = iph->daddr,
            .dst_port = dport,
            .proto    = iph->protocol,
            .pad      = 0,
        };
        if (bpf_map_lookup_elem(&vip_map, &key)) {
            __u32 qid = ctx->rx_queue_index;
            if (bpf_map_lookup_elem(&xsks_map, &qid)) {
                bump_stat(STAT_XDP_REDIR);
                return bpf_redirect_map(&xsks_map, qid, XDP_PASS);
            }
        }
    }

    bump_stat(STAT_XDP_PASS);
    return XDP_PASS;
}

char _license[] SEC("license") = "Apache-2.0";
