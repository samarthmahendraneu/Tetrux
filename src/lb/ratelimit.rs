//! Zero-Allocation Fixed-Capacity Per-Source-IP Token-Bucket & Connection Limiter.
//! Defends Tier-0 L4 pools against single-IP / botnet connection floods in O(1) time.

use super::hash::hash_u64;

const MAX_PROBE: usize = 8;

#[derive(Clone, Copy, Default)]
struct IpBucket {
    ip: u32,
    occupied: u8,
    active_conns: u32,
    /// Fixed-point token count (scaled by 256 for sub-token precision).
    tokens_fp: u64,
    last_ns: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    /// Maximum sustained new connections/packets per second per source IP (0 = unlimited).
    pub rate_per_sec: u32,
    /// Burst capacity per source IP.
    pub burst: u32,
    /// Maximum simultaneous open connections per source IP (0 = unlimited).
    pub max_conns_per_ip: u32,
    /// Power-of-2 table capacity (bounded constant memory).
    pub table_slots: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            rate_per_sec: 0,
            burst: 0,
            max_conns_per_ip: 0,
            table_slots: 16_384,
        }
    }
}

impl RateLimitConfig {
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        self.rate_per_sec > 0 || self.max_conns_per_ip > 0
    }
}

/// Worker-local O(1) per-IP admission limiter (zero locks, zero heap allocations on hot path).
pub struct PerIpLimiter {
    cfg: RateLimitConfig,
    slots: Box<[IpBucket]>,
    mask: usize,
    pub dropped_rate: u64,
    pub dropped_conn_cap: u64,
}

impl PerIpLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        let cap = if cfg.is_enabled() {
            cfg.table_slots.max(64).next_power_of_two()
        } else {
            8
        };
        Self {
            cfg,
            slots: vec![IpBucket::default(); cap].into_boxed_slice(),
            mask: cap - 1,
            dropped_rate: 0,
            dropped_conn_cap: 0,
        }
    }

    #[inline(always)]
    pub fn enabled(&self) -> bool {
        self.cfg.is_enabled()
    }

    /// Admit a new connection/packet from `src_ip` at `now_ns`.
    /// Returns `true` if allowed, `false` if shed due to rate or concurrent connection cap.
    #[inline]
    pub fn admit(&mut self, src_ip: u32, now_ns: u64) -> bool {
        if !self.cfg.is_enabled() {
            return true;
        }
        let start = (hash_u64(src_ip as u64) as usize) & self.mask;
        let mask = self.mask;
        let burst_fp = (self.cfg.burst.max(1) as u64) << 8;

        let mut target_idx = None;
        let mut oldest_idx = start;
        let mut oldest_ts = u64::MAX;

        for step in 0..MAX_PROBE {
            let idx = (start + step) & mask;
            let b = &self.slots[idx];
            if b.occupied == 0 {
                if target_idx.is_none() {
                    target_idx = Some(idx);
                }
                break;
            }
            if b.ip == src_ip {
                target_idx = Some(idx);
                break;
            }
            // Prefer evicting idle (0 active_conns) entries first
            let priority_ts = if b.active_conns == 0 {
                b.last_ns
            } else {
                b.last_ns.saturating_add(1u64 << 62)
            };
            if priority_ts < oldest_ts {
                oldest_ts = priority_ts;
                oldest_idx = idx;
            }
        }

        let idx = target_idx.unwrap_or(oldest_idx);
        let b = &mut self.slots[idx];

        if b.occupied == 0 || b.ip != src_ip {
            *b = IpBucket {
                ip: src_ip,
                occupied: 1,
                active_conns: 0,
                tokens_fp: burst_fp,
                last_ns: now_ns,
            };
        } else if self.cfg.rate_per_sec > 0 {
            let dt_ns = now_ns.saturating_sub(b.last_ns);
            let refill_fp = ((dt_ns as u128 * (self.cfg.rate_per_sec as u128) * 256u128)
                / 1_000_000_000u128) as u64;
            b.tokens_fp = (b.tokens_fp.saturating_add(refill_fp)).min(burst_fp);
            b.last_ns = now_ns;
        } else {
            b.last_ns = now_ns;
        }

        if self.cfg.max_conns_per_ip > 0 && b.active_conns >= self.cfg.max_conns_per_ip {
            self.dropped_conn_cap += 1;
            return false;
        }

        if self.cfg.rate_per_sec > 0 {
            if b.tokens_fp < 256 {
                self.dropped_rate += 1;
                return false;
            }
            b.tokens_fp -= 256;
        }

        b.active_conns = b.active_conns.saturating_add(1);
        true
    }

    /// Release one concurrent connection slot when a TCP connection closes.
    #[inline]
    pub fn release_conn(&mut self, src_ip: u32) {
        if self.cfg.max_conns_per_ip == 0 {
            return;
        }
        let start = (hash_u64(src_ip as u64) as usize) & self.mask;
        let mask = self.mask;
        for step in 0..MAX_PROBE {
            let idx = (start + step) & mask;
            let b = &mut self.slots[idx];
            if b.occupied == 0 {
                return;
            }
            if b.ip == src_ip {
                b.active_conns = b.active_conns.saturating_sub(1);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_enforces_burst_refill_and_conn_cap() {
        let mut lim = PerIpLimiter::new(RateLimitConfig {
            rate_per_sec: 100,
            burst: 5,
            max_conns_per_ip: 3,
            table_slots: 128,
        });
        let ip = 0x0a00_0001;
        let t0 = 1_000_000_000u64;
        assert!(lim.admit(ip, t0));
        assert!(lim.admit(ip, t0));
        assert!(lim.admit(ip, t0));
        // 4th hits max_conns_per_ip = 3
        assert!(!lim.admit(ip, t0));
        assert_eq!(lim.dropped_conn_cap, 1);

        // Release connections, exhaust remaining 2 burst tokens, then 6th hits rate limit
        lim.release_conn(ip);
        lim.release_conn(ip);
        lim.release_conn(ip);
        assert!(lim.admit(ip, t0));
        assert!(lim.admit(ip, t0));
        assert!(!lim.admit(ip, t0));
        assert_eq!(lim.dropped_rate, 1);

        // Advance 20 ms -> refills 2 tokens at 100/sec!
        lim.release_conn(ip);
        lim.release_conn(ip);
        assert!(lim.admit(ip, t0 + 20_000_000));
        assert!(lim.admit(ip, t0 + 20_000_000));
        assert!(!lim.admit(ip, t0 + 20_000_000));
    }
}
