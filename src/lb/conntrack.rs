//! Fixed-capacity, zero-allocation, cache-line-friendly TCP-Stateful Open-Addressed Conntrack.
//!
//! Tier-0 hardened against SYN-flood eviction attacks:
//! - Tracks per-flow L4 state (`SynSeen`, `Established`, `Closing`, `UdpActive`)
//! - Enforces distinct per-state timeouts (`5s` SYN, `300s` ESTABLISHED, `15s` FIN/RST, `30s` UDP)
//! - NEVER evicts an active `Established` flow to insert an unestablished `SYN` packet!
//! - Supports Bidirectional Reverse-NAT lookup (`ReverseConntrackTable`) for symmetric Full-NAT

use super::hash::hash_5tuple;
use crate::mem::cache::prefetch_read;

const MAX_PROBE: usize = 16;

pub const STATE_EMPTY: u8 = 0;
pub const STATE_SYN_SEEN: u8 = 1;
pub const STATE_ESTABLISHED: u8 = 2;
pub const STATE_CLOSING: u8 = 3;
pub const STATE_UDP_ACTIVE: u8 = 4;

pub const TIMEOUT_SYN_NS: u64 = 5_000_000_000;
pub const TIMEOUT_ESTAB_NS: u64 = 300_000_000_000;
pub const TIMEOUT_CLOSING_NS: u64 = 15_000_000_000;
pub const TIMEOUT_UDP_NS: u64 = 30_000_000_000;

// TCP header flag bits
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

#[inline(always)]
pub fn classify_initial_state(proto: u8, tcp_flags: u8) -> u8 {
    if proto != 6 {
        STATE_UDP_ACTIVE
    } else if (tcp_flags & (TCP_FIN | TCP_RST)) != 0 {
        STATE_CLOSING
    } else if (tcp_flags & TCP_SYN) != 0 && (tcp_flags & TCP_ACK) == 0 {
        STATE_SYN_SEEN
    } else {
        STATE_ESTABLISHED
    }
}

#[inline(always)]
pub fn next_tcp_state(cur: u8, tcp_flags: u8) -> u8 {
    if (tcp_flags & (TCP_FIN | TCP_RST)) != 0 {
        STATE_CLOSING
    } else if cur == STATE_SYN_SEEN && (tcp_flags & TCP_ACK) != 0 {
        STATE_ESTABLISHED
    } else {
        cur
    }
}

#[inline(always)]
fn state_timeout_ns(state: u8) -> u64 {
    match state {
        STATE_SYN_SEEN => TIMEOUT_SYN_NS,
        STATE_ESTABLISHED => TIMEOUT_ESTAB_NS,
        STATE_CLOSING => TIMEOUT_CLOSING_NS,
        _ => TIMEOUT_UDP_NS,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl FlowKey {
    #[inline(always)]
    pub fn hash(&self) -> u64 {
        hash_5tuple(
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.proto,
        )
    }
}

/// Exactly 64 bytes per entry -> 2 entries fit cleanly inside one 128B Apple Silicon cache line!
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default)]
pub struct ConntrackEntry {
    pub key_hash: u64,
    pub last_seen_ns: u64,
    pub packets: u64,
    pub bytes: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub backend_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub backend_port: u16,
    pub nat_port: u16,
    pub backend_idx: u16,
    pub proto: u8,
    pub occupied: u8,
    pub state: u8,
    pub _pad: [u8; 7],
}

impl ConntrackEntry {
    #[inline(always)]
    pub fn is_expired(&self, now_ns: u64) -> bool {
        now_ns.saturating_sub(self.last_seen_ns) >= state_timeout_ns(self.state)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted,
    Updated,
    /// Probe window full of live `Established` flows while inserting an unestablished `SYN`:
    /// refuses to evict established flows (caller falls back cleanly to stateless Maglev!).
    ProtectedStatelessFallback,
}

pub struct ConntrackTable {
    entries: Box<[ConntrackEntry]>,
    mask: usize,
    active: usize,
    evictions: u64,
    syn_protected: u64,
}

impl ConntrackTable {
    pub fn with_capacity(min_capacity: usize) -> Self {
        let cap = min_capacity.max(64).next_power_of_two();
        Self {
            entries: vec![ConntrackEntry::default(); cap].into_boxed_slice(),
            mask: cap - 1,
            active: 0,
            evictions: 0,
            syn_protected: 0,
        }
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.entries.len()
    }

    #[inline(always)]
    pub fn active(&self) -> usize {
        self.active
    }

    #[inline(always)]
    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    #[inline(always)]
    pub fn syn_protected(&self) -> u64 {
        self.syn_protected
    }

    #[inline(always)]
    pub fn prefetch(&self, flow_hash: u64) {
        let idx = (flow_hash as usize) & self.mask;
        prefetch_read(unsafe { self.entries.as_ptr().add(idx) });
    }

    /// O(1) bounded lookup; transitions TCP state and updates counters in-place.
    #[inline(always)]
    pub fn lookup_mut_stateful(
        &mut self,
        key: &FlowKey,
        flow_hash: u64,
        tcp_flags: u8,
        now_ns: u64,
        pkt_bytes: u64,
    ) -> Option<&mut ConntrackEntry> {
        let start = (flow_hash as usize) & self.mask;
        let mask = self.mask;
        for step in 0..MAX_PROBE {
            let idx = (start + step) & mask;
            let e = unsafe { self.entries.get_unchecked(idx) };
            if e.occupied == 0 {
                return None;
            }
            if e.key_hash == flow_hash
                && e.src_ip == key.src_ip
                && e.dst_ip == key.dst_ip
                && e.src_port == key.src_port
                && e.dst_port == key.dst_port
                && e.proto == key.proto
            {
                if e.is_expired(now_ns) {
                    return None;
                }
                let em = unsafe { self.entries.get_unchecked_mut(idx) };
                if key.proto == 6 {
                    em.state = next_tcp_state(em.state, tcp_flags);
                }
                em.last_seen_ns = now_ns;
                em.packets += 1;
                em.bytes += pkt_bytes;
                return Some(em);
            }
        }
        None
    }

    #[inline(always)]
    pub fn lookup_mut(
        &mut self,
        key: &FlowKey,
        flow_hash: u64,
        now_ns: u64,
        pkt_bytes: u64,
    ) -> Option<&mut ConntrackEntry> {
        self.lookup_mut_stateful(key, flow_hash, TCP_ACK, now_ns, pkt_bytes)
    }

    /// O(1) SYN-flood-hardened insert:
    /// 1. Prefers vacant or expired slots.
    /// 2. If full, evicts oldest `SynSeen`/`Closing` slot before touching `Established`.
    /// 3. If inserting a `SynSeen` flow and ALL slots in the window are live `Established`,
    ///    refuses eviction (`ProtectedStatelessFallback`) so SYN floods NEVER drop live flows!
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn insert_stateful(
        &mut self,
        key: &FlowKey,
        flow_hash: u64,
        backend_idx: u16,
        backend_ip: u32,
        backend_port: u16,
        nat_port: u16,
        initial_state: u8,
        now_ns: u64,
        pkt_bytes: u64,
    ) -> InsertOutcome {
        let start = (flow_hash as usize) & self.mask;
        let mask = self.mask;

        let mut expired_idx: Option<usize> = None;
        let mut soft_victim_idx: Option<usize> = None; // SynSeen or Closing
        let mut soft_victim_ts = u64::MAX;
        let mut oldest_idx = start;
        let mut oldest_ts = u64::MAX;

        for step in 0..MAX_PROBE {
            let idx = (start + step) & mask;
            let e = unsafe { self.entries.get_unchecked(idx) };
            if e.occupied == 0 {
                self.active += 1;
                let em = unsafe { self.entries.get_unchecked_mut(idx) };
                *em = ConntrackEntry {
                    key_hash: flow_hash,
                    last_seen_ns: now_ns,
                    packets: 1,
                    bytes: pkt_bytes,
                    src_ip: key.src_ip,
                    dst_ip: key.dst_ip,
                    backend_ip,
                    src_port: key.src_port,
                    dst_port: key.dst_port,
                    backend_port,
                    nat_port,
                    backend_idx,
                    proto: key.proto,
                    occupied: 1,
                    state: initial_state,
                    _pad: [0; 7],
                };
                return InsertOutcome::Inserted;
            }
            if e.key_hash == flow_hash
                && e.src_ip == key.src_ip
                && e.dst_ip == key.dst_ip
                && e.src_port == key.src_port
                && e.dst_port == key.dst_port
                && e.proto == key.proto
            {
                let em = unsafe { self.entries.get_unchecked_mut(idx) };
                em.last_seen_ns = now_ns;
                em.state = initial_state;
                em.backend_idx = backend_idx;
                em.backend_ip = backend_ip;
                em.backend_port = backend_port;
                em.nat_port = nat_port;
                em.packets += 1;
                em.bytes += pkt_bytes;
                return InsertOutcome::Updated;
            }
            if expired_idx.is_none() && e.is_expired(now_ns) {
                expired_idx = Some(idx);
            }
            if (e.state == STATE_SYN_SEEN || e.state == STATE_CLOSING)
                && e.last_seen_ns < soft_victim_ts
            {
                soft_victim_ts = e.last_seen_ns;
                soft_victim_idx = Some(idx);
            }
            if e.last_seen_ns < oldest_ts {
                oldest_ts = e.last_seen_ns;
                oldest_idx = idx;
            }
        }

        // Choose eviction slot safely
        let target_idx = if let Some(ei) = expired_idx {
            ei
        } else if let Some(si) = soft_victim_idx {
            si
        } else if initial_state == STATE_SYN_SEEN {
            // SYN-FLOOD SHIELD: Never evict live Established flows for an unestablished SYN!
            self.syn_protected += 1;
            return InsertOutcome::ProtectedStatelessFallback;
        } else {
            oldest_idx
        };

        self.evictions += 1;
        let em = unsafe { self.entries.get_unchecked_mut(target_idx) };
        *em = ConntrackEntry {
            key_hash: flow_hash,
            last_seen_ns: now_ns,
            packets: 1,
            bytes: pkt_bytes,
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            backend_ip,
            src_port: key.src_port,
            dst_port: key.dst_port,
            backend_port,
            nat_port,
            backend_idx,
            proto: key.proto,
            occupied: 1,
            state: initial_state,
            _pad: [0; 7],
        };
        InsertOutcome::Inserted
    }

    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn insert(
        &mut self,
        key: &FlowKey,
        flow_hash: u64,
        backend_idx: u16,
        backend_ip: u32,
        backend_port: u16,
        nat_port: u16,
        now_ns: u64,
        pkt_bytes: u64,
    ) -> InsertOutcome {
        let st = if key.proto == 6 {
            STATE_ESTABLISHED
        } else {
            STATE_UDP_ACTIVE
        };
        self.insert_stateful(
            key,
            flow_hash,
            backend_idx,
            backend_ip,
            backend_port,
            nat_port,
            st,
            now_ns,
            pkt_bytes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conntrack_entry_is_64_bytes() {
        assert_eq!(std::mem::size_of::<ConntrackEntry>(), 64);
    }

    #[test]
    fn conntrack_lookup_insert_and_bounded_eviction() {
        let mut ct = ConntrackTable::with_capacity(64);
        for i in 0..200u16 {
            let key = FlowKey {
                src_ip: 0x0a00_0001,
                dst_ip: 0x0a00_0002,
                src_port: 10000 + i,
                dst_port: 80,
                proto: 6,
            };
            let h = key.hash();
            ct.insert(&key, h, i % 4, 0x0a00_0101, 8080, 20000 + i, i as u64 * 100, 64);
        }
        assert!(ct.active() <= 64);
        assert!(ct.evictions() > 0);
    }

    #[test]
    fn syn_flood_cannot_evict_live_established_flows() {
        let mut ct = ConntrackTable::with_capacity(64);
        let now = 10_000_000_000u64;

        // Fill all 64 slots with live ESTABLISHED flows
        let mut established_keys = Vec::new();
        for i in 0..64u16 {
            let k = FlowKey {
                src_ip: 0x0a00_0001,
                dst_ip: 0xc633_6401,
                src_port: 1000 + i,
                dst_port: 443,
                proto: 6,
            };
            let h = k.hash();
            if ct.insert_stateful(&k, h, 0, 0x0a01_0001, 8443, 2000 + i, STATE_ESTABLISHED, now, 64)
                == InsertOutcome::Inserted
            {
                established_keys.push((k, h));
            }
        }
        // Only keep keys that actually reside in the table right now
        established_keys.retain(|(k, h)| ct.lookup_mut(k, *h, now, 64).is_some());
        assert!(!established_keys.is_empty());

        // Spray 5,000 spoofed SYN packets 1 second later!
        for s in 0..5_000u32 {
            let syn_key = FlowKey {
                src_ip: 0x0b00_0000 + s,
                dst_ip: 0xc633_6401,
                src_port: (30000 + (s % 30000)) as u16,
                dst_port: 443,
                proto: 6,
            };
            let h = syn_key.hash();
            let _ = ct.insert_stateful(
                &syn_key,
                h,
                0,
                0x0a01_0001,
                8443,
                40000,
                STATE_SYN_SEEN,
                now + 1_000_000_000,
                64,
            );
        }

        // EVERY SINGLE established flow must still be intact!
        for (k, h) in &established_keys {
            assert!(
                ct.lookup_mut(k, *h, now + 2_000_000_000, 64).is_some(),
                "SYN flood evicted a live ESTABLISHED flow!"
            );
        }
        assert!(ct.syn_protected() > 0);
    }
}
