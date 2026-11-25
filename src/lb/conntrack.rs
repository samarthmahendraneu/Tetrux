//! Fixed-capacity, zero-allocation, cache-line-friendly Open-Addressed L4 Conntrack Table.
//! Guarantees O(1) bounded lookup/insert latency (max 16 probes) with LRU eviction under
//! SYN-floods or massive traffic bursts.

use super::hash::hash_5tuple;
use crate::mem::cache::prefetch_read;

const MAX_PROBE: usize = 16;

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
    pub flags: u8,
    pub _pad: [u8; 7],
}

pub struct ConntrackTable {
    entries: Box<[ConntrackEntry]>,
    mask: usize,
    active: usize,
    evictions: u64,
}

impl ConntrackTable {
    pub fn with_capacity(min_capacity: usize) -> Self {
        let cap = min_capacity.max(64).next_power_of_two();
        Self {
            entries: vec![ConntrackEntry::default(); cap].into_boxed_slice(),
            mask: cap - 1,
            active: 0,
            evictions: 0,
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
    pub fn prefetch(&self, flow_hash: u64) {
        let idx = (flow_hash as usize) & self.mask;
        prefetch_read(unsafe { self.entries.as_ptr().add(idx) });
    }

    /// O(1) bounded lookup; updates `last_seen_ns`, `packets`, `bytes` in-place.
    #[inline(always)]
    pub fn lookup_mut(
        &mut self,
        key: &FlowKey,
        flow_hash: u64,
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
                let em = unsafe { self.entries.get_unchecked_mut(idx) };
                em.last_seen_ns = now_ns;
                em.packets += 1;
                em.bytes += pkt_bytes;
                return Some(em);
            }
        }
        None
    }

    /// O(1) insert into open-addressed probe window; evicts oldest entry if window is full.
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
    ) -> &mut ConntrackEntry {
        let start = (flow_hash as usize) & self.mask;
        let mask = self.mask;
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
                    flags: 0,
                    _pad: [0; 7],
                };
                return em;
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
                em.packets += 1;
                em.bytes += pkt_bytes;
                return em;
            }
            if e.last_seen_ns < oldest_ts {
                oldest_ts = e.last_seen_ns;
                oldest_idx = idx;
            }
        }

        // Probe window saturated (e.g., SYN burst / flood): evict LRU slot in O(1)
        self.evictions += 1;
        let em = unsafe { self.entries.get_unchecked_mut(oldest_idx) };
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
            flags: 0,
            _pad: [0; 7],
        };
        em
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
}
