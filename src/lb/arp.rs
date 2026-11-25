//! Dynamic ARP / Neighbor Cache (RFC 826) for Kernel-Bypass DSR & IPIP Next-Hop MAC Resolution.
//! Eliminates static MAC hardcoding when forwarding raw Ethernet frames via AF_XDP / UMEM.

use std::collections::HashMap;
use std::sync::RwLock;

pub const ETH_TYPE_ARP: u16 = 0x0806;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborEntry {
    pub mac: [u8; 6],
    pub expires_ns: u64,
}

pub struct ArpTable {
    entries: RwLock<HashMap<u32, NeighborEntry>>,
    ttl_ns: u64,
}

impl ArpTable {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(256)),
            ttl_ns: ttl_secs.saturating_mul(1_000_000_000),
        }
    }

    pub fn update(&self, ip: u32, mac: [u8; 6], now_ns: u64) {
        let mut map = self.entries.write().unwrap_or_else(|e| e.into_inner());
        map.insert(
            ip,
            NeighborEntry {
                mac,
                expires_ns: now_ns.saturating_add(self.ttl_ns),
            },
        );
    }

    pub fn lookup(&self, ip: u32, now_ns: u64) -> Option<[u8; 6]> {
        let map = self.entries.read().unwrap_or_else(|e| e.into_inner());
        let e = map.get(&ip)?;
        if now_ns <= e.expires_ns {
            Some(e.mac)
        } else {
            None
        }
    }

    /// Parse an incoming Ethernet + IPv4 ARP packet (42 bytes) and learn sender IP -> MAC.
    /// Returns `Some((sender_ip, sender_mac, opcode))` (opcode 1 = Request, 2 = Reply).
    pub fn ingest_arp_frame(&self, frame: &[u8], now_ns: u64) -> Option<(u32, [u8; 6], u16)> {
        if frame.len() < 42 {
            return None;
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if ethertype != ETH_TYPE_ARP {
            return None;
        }
        let htype = u16::from_be_bytes([frame[14], frame[15]]);
        let ptype = u16::from_be_bytes([frame[16], frame[17]]);
        if htype != 1 || ptype != 0x0800 || frame[18] != 6 || frame[19] != 4 {
            return None;
        }
        let opcode = u16::from_be_bytes([frame[20], frame[21]]);
        let mut sender_mac = [0u8; 6];
        sender_mac.copy_from_slice(&frame[22..28]);
        let sender_ip = u32::from_be_bytes([frame[28], frame[29], frame[30], frame[31]]);
        self.update(sender_ip, sender_mac, now_ns);
        Some((sender_ip, sender_mac, opcode))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arp_frame_ingestion_and_expiry() {
        let tbl = ArpTable::new(60);
        let mut frame = [0u8; 42];
        frame[12..14].copy_from_slice(&ETH_TYPE_ARP.to_be_bytes());
        frame[14..16].copy_from_slice(&1u16.to_be_bytes()); // Ethernet
        frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&2u16.to_be_bytes()); // ARP Reply
        let mac = [0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33];
        let ip = 0x0a00_0005u32;
        frame[22..28].copy_from_slice(&mac);
        frame[28..32].copy_from_slice(&ip.to_be_bytes());

        let now = 1_000_000_000u64;
        assert_eq!(tbl.ingest_arp_frame(&frame, now), Some((ip, mac, 2)));
        assert_eq!(tbl.lookup(ip, now + 30_000_000_000), Some(mac));
        assert_eq!(tbl.lookup(ip, now + 61_000_000_000), None);
    }
}
