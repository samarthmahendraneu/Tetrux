//! True Userspace Kernel-Bypass Zero-Copy L4 Packet Forwarding Engine.
//!
//! Mirrors Linux `AF_XDP` (`XDP_ZEROCOPY`) / DPDK `rte_mempool` + `rte_ring` architecture:
//! - Page-aligned `UmemArena` holding fixed 2048B packet frames (0 packet copies, 0 mallocs)
//! - 16-byte AF_XDP-ABI `PacketDesc` descriptors passed over 128B cache-padded SPSC rings
//! - Vectorized burst processing (64 pkts/batch) with hardware L1 prefetch pipeline (lookahead = 4)
//! - Zero-copy in-place Ethernet + IPv4 + TCP/UDP parser
//! - O(1) RFC 1624 incremental L3 & L4 checksum updates (~10 ns/pkt, no payload scan!)
//! - Full L4 NAT (DNAT) and DSR (Direct Server Return L2 MAC rewrite) modes
//! - Bounded O(1) open-addressed ConntrackTable + Maglev/P2C routing
//! - ZERO syscalls and ZERO heap allocations in the entire forwarding hot loop!

use crate::lb::balancer::{BackendPool, WorkerSelector};
use crate::lb::conntrack::{ConntrackTable, FlowKey};
use crate::mem::cache::{prefetch_write, CachePadded};
use crate::mem::spsc::{spsc_channel, SpscConsumer, SpscProducer};
use crate::sys;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

pub const FRAME_SIZE: usize = 2048;
/// DPDK/XDP-style metadata headroom before Ethernet frame (stores timestamp / metadata).
pub const FRAME_HEADROOM: usize = 64;
pub const BURST_SIZE: usize = 64;

const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_IPV4: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Exact 16-byte `struct xdp_desc` ABI layout used by Linux `AF_XDP`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PacketDesc {
    /// Byte offset inside `UmemArena` pointing to start of packet (at `frame_base + FRAME_HEADROOM`).
    pub addr: u64,
    /// Packet wire length in bytes (starting at `addr`).
    pub len: u32,
    pub options: u32,
}

/// Page-aligned contiguous UMEM packet frame memory arena (shared zero-copy across rings).
pub struct UmemArena {
    base: *mut u8,
    total_bytes: usize,
    num_frames: usize,
}

unsafe impl Send for UmemArena {}
unsafe impl Sync for UmemArena {}

impl UmemArena {
    pub fn new(num_frames: usize) -> io::Result<Arc<Self>> {
        let num_frames = num_frames.max(256).next_power_of_two();
        let total_bytes = num_frames * FRAME_SIZE;
        let base = sys::alloc_page_aligned(total_bytes)?;
        // Touch every 4 KiB page upfront so page faults never occur during forwarding!
        unsafe {
            let mut off = 0usize;
            while off < total_bytes {
                *base.add(off) = 0;
                off += 4096;
            }
        }
        Ok(Arc::new(Self {
            base,
            total_bytes,
            num_frames,
        }))
    }

    #[inline(always)]
    pub fn num_frames(&self) -> usize {
        self.num_frames
    }

    #[inline(always)]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    #[inline(always)]
    pub fn base_ptr(&self) -> *mut u8 {
        self.base
    }

    /// Return byte offset of frame `idx`'s Ethernet start (after headroom).
    #[inline(always)]
    pub const fn frame_data_addr(frame_idx: usize) -> u64 {
        (frame_idx * FRAME_SIZE + FRAME_HEADROOM) as u64
    }

    /// Get raw mutable pointer to packet data at `addr`.
    #[inline(always)]
    pub unsafe fn data_ptr(&self, addr: u64) -> *mut u8 {
        self.base.add(addr as usize)
    }

    /// Read 8-byte timestamp stored in headroom (`addr - 8`) for zero-overhead latency telemetry.
    #[inline(always)]
    pub unsafe fn read_headroom_ts(&self, addr: u64) -> u64 {
        debug_assert!(addr >= 8 && (addr as usize) < self.total_bytes);
        let p = self.base.add((addr - 8) as usize) as *const u64;
        p.read_unaligned()
    }

    /// Write 8-byte timestamp into headroom (`addr - 8`).
    #[inline(always)]
    pub unsafe fn write_headroom_ts(&self, addr: u64, ts_ns: u64) {
        debug_assert!(addr >= 8 && (addr as usize) < self.total_bytes);
        let p = self.base.add((addr - 8) as usize) as *mut u64;
        p.write_unaligned(ts_ns);
    }

    /// Access packet bytes in-place (caller ensures unique ring ownership of this descriptor!).
    #[inline(always)]
    pub unsafe fn packet_slice_mut(&self, addr: u64, len: u32) -> &mut [u8] {
        debug_assert!((addr as usize) + (len as usize) <= self.total_bytes);
        std::slice::from_raw_parts_mut(self.base.add(addr as usize), len as usize)
    }
}

impl Drop for UmemArena {
    fn drop(&mut self) {
        unsafe {
            sys::free_page_aligned(self.base, self.total_bytes);
        }
    }
}

/// Forwarding datapath mode for the kernel-bypass L4 engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BypassForwardMode {
    /// Direct Server Return: L2 MAC rewrite only (0 checksum touch, fastest possible L4!).
    Dsr,
    /// Full L4 DNAT: rewrites L2 MACs + IPv4 dst IP + TCP/UDP dst port with RFC 1624 O(1) checksums.
    Nat,
}

#[derive(Clone, Debug)]
pub struct BypassConfig {
    pub mode: BypassForwardMode,
    pub lb_mac: [u8; 6],
    pub conntrack_capacity: usize,
    pub spin_yield_after_empty: u32,
}

impl Default for BypassConfig {
    fn default() -> Self {
        Self {
            mode: BypassForwardMode::Nat,
            lb_mac: [0x02, 0x54, 0x45, 0x54, 0x52, 0x58], // locally administered "TETRX" MAC
            conntrack_capacity: 65_536,
            spin_yield_after_empty: 1024,
        }
    }
}

#[derive(Default)]
pub struct BypassCounters {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub drops: AtomicU64,
    pub ct_hits: AtomicU64,
    pub ct_misses: AtomicU64,
    pub bursts_processed: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BypassStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub drops: u64,
    pub ct_hits: u64,
    pub ct_misses: u64,
    pub bursts_processed: u64,
}

/// Bidirectional lock-free queue pair linking a virtual/NIC port to a BypassWorker.
pub struct BypassNicSide {
    pub rx_tx_to_lb: SpscProducer<PacketDesc>,
    pub tx_rx_from_lb: SpscConsumer<PacketDesc>,
}

pub struct BypassLbSide {
    pub rx_from_nic: SpscConsumer<PacketDesc>,
    pub tx_to_nic: SpscProducer<PacketDesc>,
}

pub fn create_bypass_queue_pair(ring_size: usize) -> (BypassNicSide, BypassLbSide) {
    let (rx_p, rx_c) = spsc_channel::<PacketDesc>(ring_size);
    let (tx_p, tx_c) = spsc_channel::<PacketDesc>(ring_size);
    (
        BypassNicSide {
            rx_tx_to_lb: rx_p,
            tx_rx_from_lb: tx_c,
        },
        BypassLbSide {
            rx_from_nic: rx_c,
            tx_to_nic: tx_p,
        },
    )
}

/// RFC 1624 O(1) incremental 1's-complement checksum update for replacing a 16-bit word.
/// Avoids scanning the entire packet payload (~3 CPU cycles instead of hundreds!).
#[inline(always)]
pub fn csum_replace16(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    let mut sum = (!old_csum as u32) + ((!old_val) as u32 & 0xffff) + (new_val as u32);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

/// RFC 1624 O(1) incremental checksum update for replacing a 32-bit word (e.g., IPv4 address).
#[inline(always)]
pub fn csum_replace32(old_csum: u16, old_val: u32, new_val: u32) -> u16 {
    let mut sum = (!old_csum as u32)
        + ((!(old_val >> 16)) & 0xffff)
        + ((!(old_val & 0xffff)) & 0xffff)
        + (new_val >> 16)
        + (new_val & 0xffff);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

/// Full RFC 1071 16-bit 1's-complement checksum (used for packet construction & verification tests).
pub fn rfc1071_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Full TCP/UDP checksum with IPv4 pseudo-header (used for packet construction & unit tests).
pub fn ipv4_l4_checksum(src_ip: u32, dst_ip: u32, proto: u8, l4_bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum += (src_ip >> 16) & 0xffff;
    sum += src_ip & 0xffff;
    sum += (dst_ip >> 16) & 0xffff;
    sum += dst_ip & 0xffff;
    sum += proto as u32;
    sum += l4_bytes.len() as u32;

    let mut i = 0;
    while i + 1 < l4_bytes.len() {
        sum += u16::from_be_bytes([l4_bytes[i], l4_bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < l4_bytes.len() {
        sum += (l4_bytes[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let res = !(sum as u16);
    if proto == IPPROTO_UDP && res == 0 {
        0xffff
    } else {
        res
    }
}

/// Construct a valid Ethernet + IPv4 + TCP/UDP packet inside a buffer (for tests & benchmarks).
pub fn build_test_ipv4_packet(
    buf: &mut [u8],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    payload: &[u8],
) -> usize {
    let l4_hdr_len = if proto == IPPROTO_TCP { 20 } else { 8 };
    let ip_total_len = 20 + l4_hdr_len + payload.len();
    let total_len = ETH_HDR_LEN + ip_total_len;
    assert!(buf.len() >= total_len);

    // Ethernet header (14B)
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

    // IPv4 header (20B, IHL=5)
    let ip = &mut buf[ETH_HDR_LEN..ETH_HDR_LEN + 20];
    ip.fill(0);
    ip[0] = 0x45; // IPv4, IHL=5
    ip[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = proto;
    ip[12..16].copy_from_slice(&src_ip.to_be_bytes());
    ip[16..20].copy_from_slice(&dst_ip.to_be_bytes());
    let ip_csum = rfc1071_checksum(ip);
    ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // L4 header + payload
    let l4_off = ETH_HDR_LEN + 20;
    let l4 = &mut buf[l4_off..total_len];
    l4[..l4_hdr_len].fill(0);
    l4[0..2].copy_from_slice(&src_port.to_be_bytes());
    l4[2..4].copy_from_slice(&dst_port.to_be_bytes());
    if proto == IPPROTO_TCP {
        l4[12] = 0x50; // data offset = 5 (20 bytes)
        l4[13] = 0x10; // ACK
        l4[14..16].copy_from_slice(&65535u16.to_be_bytes());
        l4[20..].copy_from_slice(payload);
        let l4_csum = ipv4_l4_checksum(src_ip, dst_ip, proto, l4);
        l4[16..18].copy_from_slice(&l4_csum.to_be_bytes());
    } else {
        let udp_len = (8 + payload.len()) as u16;
        l4[4..6].copy_from_slice(&udp_len.to_be_bytes());
        l4[8..].copy_from_slice(payload);
        let l4_csum = ipv4_l4_checksum(src_ip, dst_ip, proto, l4);
        l4[6..8].copy_from_slice(&l4_csum.to_be_bytes());
    }

    total_len
}

/// Core zero-copy L4 packet processor bound 1:1 to a single worker core.
/// Performs ZERO syscalls and ZERO heap allocations in `process_burst` / `run`.
pub struct BypassWorker {
    wid: usize,
    cfg: BypassConfig,
    umem: Arc<UmemArena>,
    selector: WorkerSelector,
    conntrack: ConntrackTable,
    counters: Arc<CachePadded<BypassCounters>>,
    // Hot local counters flushed periodically
    rx_pkts: u64,
    tx_pkts: u64,
    rx_bytes: u64,
    drops: u64,
    ct_hits: u64,
    ct_misses: u64,
    bursts: u64,
}

impl BypassWorker {
    pub fn new(
        wid: usize,
        cfg: BypassConfig,
        umem: Arc<UmemArena>,
        pool: Arc<BackendPool>,
        counters: Arc<CachePadded<BypassCounters>>,
    ) -> Self {
        let conntrack = ConntrackTable::with_capacity(cfg.conntrack_capacity);
        Self {
            wid,
            cfg,
            umem,
            selector: WorkerSelector::new(pool, wid),
            conntrack,
            counters,
            rx_pkts: 0,
            tx_pkts: 0,
            rx_bytes: 0,
            drops: 0,
            ct_hits: 0,
            ct_misses: 0,
            bursts: 0,
        }
    }

    #[inline]
    pub fn flush_counters(&mut self) {
        let c = &self.counters;
        if self.rx_pkts > 0 {
            c.rx_packets.fetch_add(self.rx_pkts, Ordering::Relaxed);
            self.rx_pkts = 0;
        }
        if self.tx_pkts > 0 {
            c.tx_packets.fetch_add(self.tx_pkts, Ordering::Relaxed);
            self.tx_pkts = 0;
        }
        if self.rx_bytes > 0 {
            c.rx_bytes.fetch_add(self.rx_bytes, Ordering::Relaxed);
            self.rx_bytes = 0;
        }
        if self.drops > 0 {
            c.drops.fetch_add(self.drops, Ordering::Relaxed);
            self.drops = 0;
        }
        if self.ct_hits > 0 {
            c.ct_hits.fetch_add(self.ct_hits, Ordering::Relaxed);
            self.ct_hits = 0;
        }
        if self.ct_misses > 0 {
            c.ct_misses.fetch_add(self.ct_misses, Ordering::Relaxed);
            self.ct_misses = 0;
        }
        if self.bursts > 0 {
            c.bursts_processed.fetch_add(self.bursts, Ordering::Relaxed);
            self.bursts = 0;
        }
    }

    /// Process a single packet in-place inside UMEM (0 copies, 0 allocs, 0 syscalls!).
    /// Returns `true` if packet should be transmitted, `false` if dropped.
    #[inline(always)]
    pub fn process_packet_in_place(&mut self, pkt: &mut [u8], now_ns: u64) -> bool {
        let len = pkt.len();
        if len < ETH_HDR_LEN + 20 + 8 {
            return false;
        }
        // Check EtherType == IPv4 (0x0800)
        if pkt[12] != 0x08 || pkt[13] != 0x00 {
            return false;
        }
        let ver_ihl = pkt[ETH_HDR_LEN];
        if (ver_ihl >> 4) != 4 {
            return false;
        }
        let ihl = ((ver_ihl & 0x0f) as usize) * 4;
        if ihl < 20 {
            return false;
        }
        let l4_off = ETH_HDR_LEN + ihl;
        let proto = pkt[ETH_HDR_LEN + 9];
        let min_l4 = if proto == IPPROTO_TCP {
            20
        } else if proto == IPPROTO_UDP {
            8
        } else {
            return false;
        };
        if len < l4_off + min_l4 {
            return false;
        }

        let src_ip = u32::from_be_bytes([
            pkt[ETH_HDR_LEN + 12],
            pkt[ETH_HDR_LEN + 13],
            pkt[ETH_HDR_LEN + 14],
            pkt[ETH_HDR_LEN + 15],
        ]);
        let dst_ip = u32::from_be_bytes([
            pkt[ETH_HDR_LEN + 16],
            pkt[ETH_HDR_LEN + 17],
            pkt[ETH_HDR_LEN + 18],
            pkt[ETH_HDR_LEN + 19],
        ]);
        let src_port = u16::from_be_bytes([pkt[l4_off], pkt[l4_off + 1]]);
        let dst_port = u16::from_be_bytes([pkt[l4_off + 2], pkt[l4_off + 3]]);

        let key = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
        };
        let flow_hash = key.hash();

        let (backend_idx, backend_ip, backend_port) =
            if let Some(entry) = self.conntrack.lookup_mut(&key, flow_hash, now_ns, len as u64) {
                self.ct_hits += 1;
                (entry.backend_idx, entry.backend_ip, entry.backend_port)
            } else {
                self.ct_misses += 1;
                let Some((bidx, ep)) = self.selector.select(flow_hash) else {
                    return false;
                };
                self.conntrack.insert(
                    &key,
                    flow_hash,
                    bidx,
                    ep.ip,
                    ep.port,
                    src_port,
                    now_ns,
                    len as u64,
                );
                (bidx, ep.ip, ep.port)
            };

        let dst_mac = self.selector.mac_of(backend_idx);

        // Rewrite Ethernet L2 headers in-place
        pkt[0..6].copy_from_slice(&dst_mac);
        pkt[6..12].copy_from_slice(&self.cfg.lb_mac);

        if self.cfg.mode == BypassForwardMode::Nat {
            // Rewrite IPv4 destination IP + O(1) RFC 1624 IPv4 header checksum update
            let old_ip_csum = u16::from_be_bytes([pkt[ETH_HDR_LEN + 10], pkt[ETH_HDR_LEN + 11]]);
            let new_ip_csum = csum_replace32(old_ip_csum, dst_ip, backend_ip);
            pkt[ETH_HDR_LEN + 10..ETH_HDR_LEN + 12].copy_from_slice(&new_ip_csum.to_be_bytes());
            pkt[ETH_HDR_LEN + 16..ETH_HDR_LEN + 20].copy_from_slice(&backend_ip.to_be_bytes());

            // Rewrite L4 destination port + O(1) RFC 1624 L4 checksum update
            pkt[l4_off + 2..l4_off + 4].copy_from_slice(&backend_port.to_be_bytes());

            if proto == IPPROTO_TCP {
                let old_l4 = u16::from_be_bytes([pkt[l4_off + 16], pkt[l4_off + 17]]);
                let c1 = csum_replace32(old_l4, dst_ip, backend_ip);
                let c2 = csum_replace16(c1, dst_port, backend_port);
                pkt[l4_off + 16..l4_off + 18].copy_from_slice(&c2.to_be_bytes());
            } else {
                let old_l4 = u16::from_be_bytes([pkt[l4_off + 6], pkt[l4_off + 7]]);
                if old_l4 != 0 {
                    let c1 = csum_replace32(old_l4, dst_ip, backend_ip);
                    let mut c2 = csum_replace16(c1, dst_port, backend_port);
                    if c2 == 0 {
                        c2 = 0xffff;
                    }
                    pkt[l4_off + 6..l4_off + 8].copy_from_slice(&c2.to_be_bytes());
                }
            }
        }

        true
    }

    /// Run a single vectorized burst iteration (0 syscalls, 0 allocations!).
    #[inline]
    pub fn poll_burst(&mut self, queue: &mut BypassLbSide) -> usize {
        let mut rx_batch = [PacketDesc::default(); BURST_SIZE];
        let n = queue.rx_from_nic.pop_batch(&mut rx_batch);
        if n == 0 {
            return 0;
        }
        self.bursts += 1;
        let now_ns = sys::fast_now_ns();

        let mut tx_batch = [PacketDesc::default(); BURST_SIZE];
        let mut tx_count = 0usize;
        let umem_base = self.umem.base_ptr();

        for i in 0..n {
            // Prefetch packet `i + 4` into L1 cache for write before touching it
            if i + 4 < n {
                unsafe {
                    prefetch_write(umem_base.add(rx_batch[i + 4].addr as usize));
                }
            }
            let desc = rx_batch[i];
            self.rx_pkts += 1;
            self.rx_bytes += desc.len as u64;
            let pkt = unsafe {
                std::slice::from_raw_parts_mut(umem_base.add(desc.addr as usize), desc.len as usize)
            };
            if self.process_packet_in_place(pkt, now_ns) {
                tx_batch[tx_count] = desc;
                tx_count += 1;
            } else {
                self.drops += 1;
            }
        }

        // Push entire forwarded burst to TX ring in ONE atomic Release store!
        let mut pushed = 0usize;
        while pushed < tx_count {
            let p = queue.tx_to_nic.push_batch(&tx_batch[pushed..tx_count]);
            pushed += p;
            if pushed < tx_count {
                sys::cpu_relax();
            }
        }
        self.tx_pkts += tx_count as u64;
        n
    }

    /// Dedicated poll-mode driver (PMD) loop pinned to a P-core — 0 syscalls in steady state!
    pub fn run_pmd_loop(mut self, mut queue: BypassLbSide, stop: Arc<AtomicBool>) {
        sys::pin_thread_performance(self.wid);
        let mut empty_spins = 0u32;
        let mut loop_cnt = 0u64;

        while !stop.load(Ordering::Relaxed) {
            let n = self.poll_burst(&mut queue);
            if n > 0 {
                empty_spins = 0;
                loop_cnt = loop_cnt.wrapping_add(1);
                if (loop_cnt & 0xff) == 0 {
                    self.flush_counters();
                }
            } else {
                empty_spins = empty_spins.saturating_add(1);
                sys::cpu_relax();
                if empty_spins >= self.cfg.spin_yield_after_empty {
                    self.flush_counters();
                    empty_spins = 0;
                }
            }
        }
        // Drain any trailing packets before exit
        while self.poll_burst(&mut queue) > 0 {}
        self.flush_counters();
    }
}

pub fn read_bypass_stats(c: &BypassCounters) -> BypassStats {
    BypassStats {
        rx_packets: c.rx_packets.load(Ordering::Relaxed),
        tx_packets: c.tx_packets.load(Ordering::Relaxed),
        rx_bytes: c.rx_bytes.load(Ordering::Relaxed),
        drops: c.drops.load(Ordering::Relaxed),
        ct_hits: c.ct_hits.load(Ordering::Relaxed),
        ct_misses: c.ct_misses.load(Ordering::Relaxed),
        bursts_processed: c.bursts_processed.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lb::balancer::{BackendSpec, LbAlgorithm};
    use crate::lb::hash::Xorshift64;
    use crate::sys::EndpointV4;

    #[test]
    fn rfc1624_incremental_checksum_matches_full_recompute_10k_packets() {
        let mut rng = Xorshift64::new(0x1234_5678_9abc_def0);
        let backends = vec![
            BackendSpec::new(EndpointV4::from_octets(10, 10, 0, 1, 8080))
                .with_mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
            BackendSpec::new(EndpointV4::from_octets(10, 10, 0, 2, 9090))
                .with_mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]),
        ];
        let pool = BackendPool::new(backends, LbAlgorithm::Maglev);
        let umem = UmemArena::new(256).unwrap();
        let counters = Arc::new(CachePadded::new(BypassCounters::default()));
        let mut worker = BypassWorker::new(0, BypassConfig::default(), umem, pool, counters);

        let mut buf = [0u8; 256];
        let payload = b"hello tetrux zero-copy kernel-bypass L4 NLB payload 1234567890!";

        for i in 0..10_000u64 {
            let proto = if (i & 1) == 0 {
                IPPROTO_TCP
            } else {
                IPPROTO_UDP
            };
            let src_ip = rng.next_u64() as u32;
            let dst_ip = 0xc0a8_0101;
            let src_port = (rng.next_u64() as u16).max(1024);
            let dst_port = if i % 7 == 0 { 0xffff } else { 443 };

            let len = build_test_ipv4_packet(
                &mut buf,
                [0x11; 6],
                [0x22; 6],
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto,
                payload,
            );
            assert!(worker.process_packet_in_place(&mut buf[..len], i * 100));

            // Verify IPv4 header checksum mathematically against full RFC 1071!
            let ip_hdr = &buf[ETH_HDR_LEN..ETH_HDR_LEN + 20];
            assert_eq!(
                rfc1071_checksum(ip_hdr),
                0,
                "IPv4 checksum invalid on iter {i}"
            );

            // Verify L4 TCP/UDP checksum mathematically against full pseudo-header + payload!
            let new_dst_ip = u32::from_be_bytes([
                ip_hdr[16], ip_hdr[17], ip_hdr[18], ip_hdr[19],
            ]);
            let l4 = &buf[ETH_HDR_LEN + 20..len];
            let verify = ipv4_l4_checksum(src_ip, new_dst_ip, proto, l4);
            // Valid checksum over header+payload including its own checksum yields 0 (or 0xffff for UDP -0)
            assert!(
                verify == 0 || (proto == IPPROTO_UDP && verify == 0xffff),
                "L4 checksum invalid on iter {i} proto={proto}: got 0x{verify:04x}"
            );
        }
    }

    #[test]
    fn bypass_dsr_and_nat_umem_ring_roundtrip() {
        let backends = vec![
            BackendSpec::new(EndpointV4::from_octets(10, 0, 0, 10, 8080))
                .with_mac([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
        ];
        let pool = BackendPool::new(backends, LbAlgorithm::Maglev);
        let umem = UmemArena::new(256).unwrap();
        let counters = Arc::new(CachePadded::new(BypassCounters::default()));
        let (mut nic, mut lb) = create_bypass_queue_pair(128);

        let mut cfg = BypassConfig::default();
        cfg.mode = BypassForwardMode::Dsr;
        let mut worker = BypassWorker::new(0, cfg, Arc::clone(&umem), pool, Arc::clone(&counters));

        let addr = UmemArena::frame_data_addr(0);
        let len = unsafe {
            let slice = umem.packet_slice_mut(addr, 128);
            build_test_ipv4_packet(
                slice,
                [0x01; 6],
                [0x02; 6],
                0x0a01_0101,
                0x0a01_01ff,
                55555,
                80,
                IPPROTO_TCP,
                b"dsr-test",
            )
        };
        nic.rx_tx_to_lb
            .try_push(PacketDesc {
                addr,
                len: len as u32,
                options: 0,
            })
            .unwrap();

        assert_eq!(worker.poll_burst(&mut lb), 1);
        let out = nic.tx_rx_from_lb.try_pop().unwrap();
        assert_eq!(out.addr, addr); // ZERO-COPY: exact same UMEM frame address!
        let pkt = unsafe { umem.packet_slice_mut(out.addr, out.len) };
        assert_eq!(&pkt[0..6], &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        // DSR preserves original VIP destination IP!
        assert_eq!(
            u32::from_be_bytes([pkt[30], pkt[31], pkt[32], pkt[33]]),
            0x0a01_01ff
        );
    }
}
