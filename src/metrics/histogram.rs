//! Zero-allocation Log-Linear HDR-style Latency Histogram (10 ns to >10 s, <3.1% quantization).
//! Fits in 4 KiB (512 u64 counters) for L1-resident nanosecond recording.

const SUB_BUCKETS_LOG2: u32 = 4; // 16 linear sub-buckets per power-of-2 octave
const SUB_BUCKETS: usize = 1 << SUB_BUCKETS_LOG2;
const OCTAVES: usize = 32; // Covers 0 .. 2^35 ns (~34.3 seconds)
const TOTAL_BUCKETS: usize = OCTAVES * SUB_BUCKETS;

#[derive(Clone)]
pub struct LatencyHistogram {
    buckets: [u64; TOTAL_BUCKETS],
    count: u64,
    sum_ns: u128,
    min_ns: u64,
    max_ns: u64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyHistogram {
    pub const fn new() -> Self {
        Self {
            buckets: [0; TOTAL_BUCKETS],
            count: 0,
            sum_ns: 0,
            min_ns: u64::MAX,
            max_ns: 0,
        }
    }

    #[inline(always)]
    fn value_to_bucket(ns: u64) -> usize {
        if ns < SUB_BUCKETS as u64 {
            return ns as usize;
        }
        let msb = 63 - ns.leading_zeros();
        let octave = (msb - SUB_BUCKETS_LOG2 + 1) as usize;
        if octave >= OCTAVES {
            return TOTAL_BUCKETS - 1;
        }
        let shift = msb - SUB_BUCKETS_LOG2;
        let sub = ((ns >> shift) as usize) & (SUB_BUCKETS - 1);
        octave * SUB_BUCKETS + sub
    }

    #[inline(always)]
    fn bucket_midpoint_ns(bucket: usize) -> u64 {
        let octave = bucket / SUB_BUCKETS;
        let sub = bucket % SUB_BUCKETS;
        if octave == 0 {
            return sub as u64;
        }
        let shift = (octave - 1) as u32;
        let base = ((SUB_BUCKETS + sub) as u64) << shift;
        let step = 1u64 << shift;
        base + (step >> 1)
    }

    #[inline(always)]
    pub fn record_ns(&mut self, ns: u64) {
        let idx = Self::value_to_bucket(ns);
        unsafe {
            *self.buckets.get_unchecked_mut(idx) += 1;
        }
        self.count += 1;
        self.sum_ns += ns as u128;
        if ns < self.min_ns {
            self.min_ns = ns;
        }
        if ns > self.max_ns {
            self.max_ns = ns;
        }
    }

    pub fn merge(&mut self, other: &Self) {
        if other.count == 0 {
            return;
        }
        for i in 0..TOTAL_BUCKETS {
            self.buckets[i] += other.buckets[i];
        }
        self.count += other.count;
        self.sum_ns += other.sum_ns;
        if other.min_ns < self.min_ns {
            self.min_ns = other.min_ns;
        }
        if other.max_ns > self.max_ns {
            self.max_ns = other.max_ns;
        }
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn min_ns(&self) -> u64 {
        if self.count == 0 { 0 } else { self.min_ns }
    }

    pub fn max_ns(&self) -> u64 {
        self.max_ns
    }

    pub fn mean_ns(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum_ns as f64 / self.count as f64
        }
    }

    /// Return percentile in nanoseconds (`p` in `0.0..=100.0`, e.g. `99.9`).
    pub fn percentile_ns(&self, p: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let target = ((p / 100.0) * self.count as f64).ceil() as u64;
        let target = target.clamp(1, self.count);
        let mut seen = 0u64;
        for (i, &c) in self.buckets.iter().enumerate() {
            seen += c;
            if seen >= target {
                return Self::bucket_midpoint_ns(i).clamp(self.min_ns, self.max_ns);
            }
        }
        self.max_ns
    }

    pub fn summary_us(&self) -> LatencySummaryUs {
        LatencySummaryUs {
            count: self.count,
            min_us: self.min_ns() as f64 / 1_000.0,
            mean_us: self.mean_ns() / 1_000.0,
            p50_us: self.percentile_ns(50.0) as f64 / 1_000.0,
            p90_us: self.percentile_ns(90.0) as f64 / 1_000.0,
            p95_us: self.percentile_ns(95.0) as f64 / 1_000.0,
            p99_us: self.percentile_ns(99.0) as f64 / 1_000.0,
            p999_us: self.percentile_ns(99.9) as f64 / 1_000.0,
            max_us: self.max_ns() as f64 / 1_000.0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LatencySummaryUs {
    pub count: u64,
    pub min_us: f64,
    pub mean_us: f64,
    pub p50_us: f64,
    pub p90_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
    pub p999_us: f64,
    pub max_us: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_percentiles_accurate() {
        let mut h = LatencyHistogram::new();
        for i in 1..=10_000u64 {
            h.record_ns(i * 1000); // 1us .. 10,000us
        }
        let s = h.summary_us();
        assert!((s.p50_us - 5000.0).abs() < 250.0, "p50={}", s.p50_us);
        assert!((s.p99_us - 9900.0).abs() < 400.0, "p99={}", s.p99_us);
        assert!((s.p999_us - 9990.0).abs() < 400.0, "p999={}", s.p999_us);
    }
}
