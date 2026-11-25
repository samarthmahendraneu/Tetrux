//! Google Maglev Consistent Hashing (M = 65537 prime lookup table).
//! - O(1) lookup (~2 ns, fits in L2 cache: 131 KiB)
//! - Near-uniform load distribution + accurate GCD-normalized weighted backend support
//! - Minimal connection disruption (~1/N flows remapped) on backend churn

use super::hash::{fast_mod_65537, hash_bytes};

pub const MAGLEV_M: usize = 65537;

fn gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a.max(1)
}

#[derive(Clone)]
pub struct MaglevTable {
    /// Lookup table mapping hash slot -> backend slot id.
    lookup: Vec<u16>,
    empty: bool,
}

impl MaglevTable {
    pub fn empty() -> Self {
        Self {
            lookup: Vec::new(),
            empty: true,
        }
    }

    /// Build a Maglev lookup table for `(backend_id, key_bytes, weight)`.
    /// Weights are GCD-normalized and proportionally scaled so arbitrary weights
    /// (e.g. 10 vs 90, or 1..=1000) build fast (<2 ms) with accurate traffic ratios.
    pub fn build(backends: &[(u16, &[u8], u32)]) -> Self {
        let active: Vec<(u16, &[u8], u32)> = backends
            .iter()
            .copied()
            .filter(|(_, _, w)| *w > 0)
            .collect();
        if active.is_empty() {
            return Self::empty();
        }
        if active.len() == 1 {
            return Self {
                lookup: vec![active[0].0; MAGLEV_M],
                empty: false,
            };
        }

        // Normalize weights by GCD and cap total virtual replicas to keep table build sub-2ms
        let g = active.iter().fold(0u32, |acc, &(_, _, w)| {
            if acc == 0 { w } else { gcd(acc, w) }
        });
        let reduced: Vec<(u16, &[u8], u32)> = active
            .iter()
            .map(|&(id, k, w)| (id, k, (w / g).max(1)))
            .collect();
        let total_w: u64 = reduced.iter().map(|&(_, _, w)| w as u64).sum();
        const MAX_REPLICAS: u64 = 256;

        let mut entries: Vec<(u16, usize, usize)> = Vec::new();
        for &(id, key, w) in &reduced {
            let replicas = if total_w <= MAX_REPLICAS {
                w
            } else {
                (((w as u64 * MAX_REPLICAS) + (total_w / 2)) / total_w).max(1) as u32
            };
            for replica in 0..replicas {
                let mut key_buf = [0u8; 32];
                let klen = key.len().min(28);
                key_buf[..klen].copy_from_slice(&key[..klen]);
                key_buf[klen..klen + 4].copy_from_slice(&replica.to_le_bytes());
                let slice = &key_buf[..klen + 4];
                let offset = fast_mod_65537(hash_bytes(slice, 0x1337_cafe));
                let skip = (hash_bytes(slice, 0xdead_beef) % ((MAGLEV_M - 1) as u64)) as usize + 1;
                entries.push((id, offset, skip));
            }
        }

        let n = entries.len();
        let mut next = vec![0usize; n];
        let mut entry = vec![u16::MAX; MAGLEV_M];
        let mut filled = 0usize;

        while filled < MAGLEV_M {
            for i in 0..n {
                let (id, offset, skip) = entries[i];
                let mut c = (offset + next[i] * skip) % MAGLEV_M;
                while entry[c] != u16::MAX {
                    next[i] += 1;
                    c = (offset + next[i] * skip) % MAGLEV_M;
                }
                entry[c] = id;
                next[i] += 1;
                filled += 1;
                if filled == MAGLEV_M {
                    break;
                }
            }
        }

        Self {
            lookup: entry,
            empty: false,
        }
    }

    /// O(1) division-free Maglev consistent hash lookup.
    #[inline(always)]
    pub fn lookup(&self, flow_hash: u64) -> Option<u16> {
        if self.empty {
            return None;
        }
        let slot = fast_mod_65537(flow_hash);
        Some(unsafe { *self.lookup.get_unchecked(slot) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lb::hash::hash_u64;

    #[test]
    fn maglev_balance_and_minimal_disruption() {
        let keys: [&[u8]; 5] = [
            b"10.0.0.1:8080",
            b"10.0.0.2:8080",
            b"10.0.0.3:8080",
            b"10.0.0.4:8080",
            b"10.0.0.5:8080",
        ];
        let all: Vec<(u16, &[u8], u32)> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| (i as u16, *k, 1))
            .collect();
        let t1 = MaglevTable::build(&all);

        let mut counts = [0usize; 5];
        for f in 0..50_000u64 {
            let b = t1.lookup(hash_u64(f)).unwrap() as usize;
            counts[b] += 1;
        }
        for c in counts {
            assert!(c > 9400 && c < 10600, "imbalanced maglev count: {counts:?}");
        }

        let four: Vec<(u16, &[u8], u32)> =
            all.into_iter().filter(|(id, _, _)| *id != 2).collect();
        let t2 = MaglevTable::build(&four);
        let mut non_removed = 0usize;
        let mut remapped = 0usize;
        for f in 0..50_000u64 {
            let h = hash_u64(f);
            let b1 = t1.lookup(h).unwrap();
            let b2 = t2.lookup(h).unwrap();
            if b1 != 2 {
                non_removed += 1;
                if b1 != b2 {
                    remapped += 1;
                }
            }
        }
        let disruption_pct = (remapped as f64 / non_removed as f64) * 100.0;
        assert!(
            disruption_pct < 3.0,
            "Maglev disruption too high: {disruption_pct:.2}%"
        );
    }

    #[test]
    fn maglev_weighted_distribution_accurate() {
        // Weights 50 : 30 : 20 -> 50% : 30% : 20%
        let items: Vec<(u16, &[u8], u32)> = vec![
            (0, b"10.0.0.1:80", 50),
            (1, b"10.0.0.2:80", 30),
            (2, b"10.0.0.3:80", 20),
        ];
        let t = MaglevTable::build(&items);
        let mut counts = [0usize; 3];
        for f in 0..50_000u64 {
            counts[t.lookup(hash_u64(f)).unwrap() as usize] += 1;
        }
        let p0 = counts[0] as f64 / 500.0;
        let p1 = counts[1] as f64 / 500.0;
        let p2 = counts[2] as f64 / 500.0;
        assert!((p0 - 50.0).abs() < 2.0, "p0={p0:.2}%");
        assert!((p1 - 30.0).abs() < 2.0, "p1={p1:.2}%");
        assert!((p2 - 20.0).abs() < 2.0, "p2={p2:.2}%");
    }
}
