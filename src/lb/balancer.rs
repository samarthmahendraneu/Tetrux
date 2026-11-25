//! Lock-free RCU-style L4 Backend Pool with:
//! - Live target registration, deregistration, graceful connection draining, and weight tuning
//! - Weighted Maglev O(1) Consistent Hashing
//! - Weighted Power-of-Two-Choices (P2C) Least-Connections + EWMA Latency (with O(1) Vose Alias)
//! - Smooth Weighted Round-Robin (Nginx smooth interleaved schedule, O(1) lookup)
//! - Active background TCP health checking & passive failure circuit breaking
//!
//! Hot-path guarantee: ZERO locks, ZERO allocations, O(1) array indexing for active counters.

use super::hash::Xorshift64;
use super::maglev::MaglevTable;
use crate::mem::cache::CachePadded;
use crate::sys::{self, EndpointV4};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;

/// Maximum concurrent backend slots per pool (lock-free fixed slot directory).
pub const MAX_BACKENDS: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LbAlgorithm {
    /// O(1) Weighted Maglev consistent hashing on client flow 4-tuple.
    Maglev,
    /// Weighted Power-of-Two-Choices comparing effective load (`active_conns / weight`) & EWMA latency.
    P2cLeastConn,
    /// Smooth interleaved Weighted Round-Robin (O(1) precomputed schedule).
    RoundRobin,
}

#[derive(Clone, Debug)]
pub struct BackendSpec {
    pub endpoint: EndpointV4,
    /// Traffic weight (`0` = soft-drained / receives no new traffic; `1..=1000` = proportional share).
    pub weight: u32,
    /// Destination MAC address used in Kernel-Bypass DSR (Direct Server Return) mode.
    pub mac: [u8; 6],
    /// Optional originating DNS pool key (e.g. `"api.internal:8080"`) when managed by DNS discovery.
    pub dns_source: Option<String>,
}

impl BackendSpec {
    pub fn new(endpoint: EndpointV4) -> Self {
        Self {
            endpoint,
            weight: 1,
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, (endpoint.port & 0xff) as u8],
            dns_source: None,
        }
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight.min(1000);
        self
    }

    pub fn with_mac(mut self, mac: [u8; 6]) -> Self {
        self.mac = mac;
        self
    }

    pub fn with_dns_source(mut self, dns_source: impl Into<String>) -> Self {
        self.dns_source = Some(dns_source.into());
        self
    }
}

/// Lock-free per-slot hot runtime atomics padded to 128B cache lines (allocated once at pool init).
pub struct SlotRuntime {
    pub active_conns: CachePadded<AtomicU32>,
    pub total_conns: CachePadded<AtomicU64>,
    pub ewma_connect_ns: CachePadded<AtomicU64>,
    pub consec_failures: CachePadded<AtomicU32>,
    pub healthy: CachePadded<AtomicBool>,
}

impl SlotRuntime {
    fn new() -> Self {
        Self {
            active_conns: CachePadded::new(AtomicU32::new(0)),
            total_conns: CachePadded::new(AtomicU64::new(0)),
            ewma_connect_ns: CachePadded::new(AtomicU64::new(100_000)),
            consec_failures: CachePadded::new(AtomicU32::new(0)),
            healthy: CachePadded::new(AtomicBool::new(true)),
        }
    }

    fn reset_for_new_target(&self) {
        self.active_conns.store(0, Ordering::Relaxed);
        self.total_conns.store(0, Ordering::Relaxed);
        self.ewma_connect_ns.store(100_000, Ordering::Relaxed);
        self.consec_failures.store(0, Ordering::Relaxed);
        self.healthy.store(true, Ordering::Release);
    }
}

/// Control-plane metadata for one backend slot.
#[derive(Clone, Debug)]
struct SlotMeta {
    occupied: bool,
    draining: bool,
    spec: BackendSpec,
}

impl SlotMeta {
    fn vacant() -> Self {
        Self {
            occupied: false,
            draining: false,
            spec: BackendSpec::new(EndpointV4::default()),
        }
    }
}

/// Public read-only status snapshot of a registered target (returned by `list_targets` / `/targets`).
#[derive(Clone, Debug)]
pub struct TargetStatus {
    pub slot_id: u16,
    pub endpoint: EndpointV4,
    pub dns_source: Option<String>,
    pub weight: u32,
    pub effective_share_pct: f64,
    pub healthy: bool,
    pub draining: bool,
    pub active_conns: u32,
    pub total_conns: u64,
    pub ewma_connect_us: f64,
}

/// Result of a dynamic target mutation (`register`, `deregister`, `set_weight`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MutationOutcome {
    Registered { slot_id: u16, generation: u64 },
    Updated { slot_id: u16, generation: u64 },
    Draining { slot_id: u16, active_conns: u32, generation: u64 },
    Removed { slot_id: u16, generation: u64 },
    NotFound,
    PoolFull,
}

/// O(1) Vose Alias Table for exact weighted random sampling with zero divisions.
#[derive(Clone)]
struct WeightedAlias {
    ids: Vec<u16>,
    prob: Vec<u32>, // scaled to [0, u32::MAX]
    alias: Vec<u16>,
}

impl WeightedAlias {
    fn empty() -> Self {
        Self {
            ids: Vec::new(),
            prob: Vec::new(),
            alias: Vec::new(),
        }
    }

    fn build(items: &[(u16, u32)]) -> Self {
        let active: Vec<(u16, u32)> = items.iter().copied().filter(|&(_, w)| w > 0).collect();
        let n = active.len();
        if n == 0 {
            return Self::empty();
        }
        let ids: Vec<u16> = active.iter().map(|&(id, _)| id).collect();
        if n == 1 {
            return Self {
                ids,
                prob: vec![u32::MAX],
                alias: vec![0],
            };
        }

        let sum: f64 = active.iter().map(|&(_, w)| w as f64).sum();
        let mut scaled: Vec<f64> = active
            .iter()
            .map(|&(_, w)| (w as f64) * (n as f64) / sum)
            .collect();
        let mut small = Vec::with_capacity(n);
        let mut large = Vec::with_capacity(n);
        for (i, &p) in scaled.iter().enumerate() {
            if p < 1.0 {
                small.push(i);
            } else {
                large.push(i);
            }
        }

        let mut prob = vec![u32::MAX; n];
        let mut alias = vec![0u16; n];
        while let (Some(l), Some(g)) = (small.pop(), large.pop()) {
            prob[l] = (scaled[l].clamp(0.0, 1.0) * (u32::MAX as f64)) as u32;
            alias[l] = g as u16;
            scaled[g] = (scaled[g] + scaled[l]) - 1.0;
            if scaled[g] < 1.0 {
                small.push(g);
            } else {
                large.push(g);
            }
        }
        while let Some(g) = large.pop() {
            prob[g] = u32::MAX;
            alias[g] = g as u16;
        }
        while let Some(l) = small.pop() {
            prob[l] = u32::MAX;
            alias[l] = l as u16;
        }

        Self { ids, prob, alias }
    }

    #[inline(always)]
    fn sample(&self, rng: &mut Xorshift64) -> Option<u16> {
        let n = self.ids.len();
        if n == 0 {
            return None;
        }
        if n == 1 {
            return Some(self.ids[0]);
        }
        let r = rng.next_u64();
        // Low 32 bits select bucket via Lemire's fast range; high 32 bits compare threshold!
        let bucket = (((r as u32) as u64 * (n as u64)) >> 32) as usize;
        let coin = (r >> 32) as u32;
        let idx = if coin < unsafe { *self.prob.get_unchecked(bucket) } {
            bucket
        } else {
            unsafe { *self.alias.get_unchecked(bucket) as usize }
        };
        Some(unsafe { *self.ids.get_unchecked(idx) })
    }
}

fn gcd_u32(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a.max(1)
}

/// Build an Nginx Smooth Weighted Round-Robin sequence (GCD-reduced, capped at 256 slots)
/// so weighted RR interleaves smoothly (e.g. `[3,1]` -> `[0,0,1,0]`) in O(1) lookup time.
fn build_smooth_wrr_schedule(items: &[(u16, u32)]) -> Vec<u16> {
    let active: Vec<(u16, u32)> = items.iter().copied().filter(|&(_, w)| w > 0).collect();
    if active.is_empty() {
        return Vec::new();
    }
    if active.len() == 1 {
        return vec![active[0].0];
    }

    let g = active.iter().fold(0u32, |acc, &(_, w)| {
        if acc == 0 { w } else { gcd_u32(acc, w) }
    });
    let mut reduced: Vec<(u16, i64)> = active
        .iter()
        .map(|&(id, w)| (id, (w / g).max(1) as i64))
        .collect();
    let mut total_w: i64 = reduced.iter().map(|&(_, w)| w).sum();
    const MAX_SCHED: i64 = 256;
    if total_w > MAX_SCHED {
        for (_, w) in &mut reduced {
            *w = ((*w * MAX_SCHED + total_w / 2) / total_w).max(1);
        }
        total_w = reduced.iter().map(|&(_, w)| w).sum();
    }

    let mut cur = vec![0i64; reduced.len()];
    let mut sched = Vec::with_capacity(total_w as usize);
    for _ in 0..total_w {
        let mut best_idx = 0usize;
        let mut best_val = i64::MIN;
        for i in 0..reduced.len() {
            cur[i] += reduced[i].1;
            if cur[i] > best_val {
                best_val = cur[i];
                best_idx = i;
            }
        }
        cur[best_idx] -= total_w;
        sched.push(reduced[best_idx].0);
    }
    sched
}

/// Immutable routing snapshot cloned lazily into each worker ONLY when `generation` changes.
#[derive(Clone)]
pub struct RoutingSnapshot {
    pub generation: u64,
    pub healthy_ids: Vec<u16>,
    /// Slot-indexed endpoint table (O(1) direct indexing by `slot_id`).
    pub endpoints: Vec<EndpointV4>,
    /// Slot-indexed MAC table for Kernel-Bypass DSR.
    pub macs: Vec<[u8; 6]>,
    /// Slot-indexed weight table for Weighted P2C score calculation.
    pub weights: Vec<u32>,
    pub maglev: MaglevTable,
    pub smooth_wrr: Vec<u16>,
    alias: WeightedAlias,
}

struct ControlState {
    slots: Vec<SlotMeta>,
    snapshot: RoutingSnapshot,
}

pub struct BackendPool {
    pub algo: LbAlgorithm,
    /// Pre-allocated fixed lock-free runtime atomics directory (never reallocates!).
    runtimes: Box<[SlotRuntime]>,
    generation: CachePadded<AtomicU64>,
    control: RwLock<ControlState>,
    failure_threshold: u32,
}

impl BackendPool {
    pub fn new(specs: Vec<BackendSpec>, algo: LbAlgorithm) -> Arc<Self> {
        let mut runtimes_vec = Vec::with_capacity(MAX_BACKENDS);
        let mut slots = Vec::with_capacity(MAX_BACKENDS);
        for _ in 0..MAX_BACKENDS {
            runtimes_vec.push(SlotRuntime::new());
            slots.push(SlotMeta::vacant());
        }

        for (i, spec) in specs.into_iter().take(MAX_BACKENDS).enumerate() {
            slots[i] = SlotMeta {
                occupied: true,
                draining: false,
                spec,
            };
        }

        let runtimes = runtimes_vec.into_boxed_slice();
        let snapshot = Self::build_snapshot(&slots, &runtimes, 1);

        Arc::new(Self {
            algo,
            runtimes,
            generation: CachePadded::new(AtomicU64::new(1)),
            control: RwLock::new(ControlState { slots, snapshot }),
            failure_threshold: 3,
        })
    }

    fn build_snapshot(
        slots: &[SlotMeta],
        runtimes: &[SlotRuntime],
        generation: u64,
    ) -> RoutingSnapshot {
        let mut max_used = 0usize;
        for (i, s) in slots.iter().enumerate() {
            if s.occupied {
                max_used = i + 1;
            }
        }
        let table_len = max_used.max(1);
        let mut endpoints = vec![EndpointV4::default(); table_len];
        let mut macs = vec![[0u8; 6]; table_len];
        let mut weights = vec![1u32; table_len];

        let mut healthy_ids = Vec::new();
        let mut weighted_items: Vec<(u16, u32)> = Vec::new();
        let mut key_storage: Vec<(u16, [u8; 6], u32)> = Vec::new();

        for i in 0..max_used {
            let s = &slots[i];
            if !s.occupied {
                continue;
            }
            endpoints[i] = s.spec.endpoint;
            macs[i] = s.spec.mac;
            weights[i] = s.spec.weight.max(1);

            // Only route new flows to targets that are healthy, not draining, and weight > 0
            if !s.draining && s.spec.weight > 0 && runtimes[i].healthy.load(Ordering::Relaxed) {
                healthy_ids.push(i as u16);
                weighted_items.push((i as u16, s.spec.weight));
                let mut k = [0u8; 6];
                k[0..4].copy_from_slice(&s.spec.endpoint.ip.to_be_bytes());
                k[4..6].copy_from_slice(&s.spec.endpoint.port.to_be_bytes());
                key_storage.push((i as u16, k, s.spec.weight));
            }
        }

        // Fail-open safety: if active non-draining weighted targets exist but all failed health
        // checks simultaneously, route across them rather than blackholing 100% of traffic!
        if healthy_ids.is_empty() {
            for i in 0..max_used {
                let s = &slots[i];
                if s.occupied && !s.draining && s.spec.weight > 0 {
                    healthy_ids.push(i as u16);
                    weighted_items.push((i as u16, s.spec.weight));
                    let mut k = [0u8; 6];
                    k[0..4].copy_from_slice(&s.spec.endpoint.ip.to_be_bytes());
                    k[4..6].copy_from_slice(&s.spec.endpoint.port.to_be_bytes());
                    key_storage.push((i as u16, k, s.spec.weight));
                }
            }
        }

        let maglev_inputs: Vec<(u16, &[u8], u32)> = key_storage
            .iter()
            .map(|(id, k, w)| (*id, &k[..], *w))
            .collect();
        let maglev = MaglevTable::build(&maglev_inputs);
        let smooth_wrr = build_smooth_wrr_schedule(&weighted_items);
        let alias = WeightedAlias::build(&weighted_items);

        RoutingSnapshot {
            generation,
            healthy_ids,
            endpoints,
            macs,
            weights,
            maglev,
            smooth_wrr,
            alias,
        }
    }

    fn publish_locked(&self, st: &mut ControlState) -> u64 {
        // Reclaim any draining slots whose active connection count has reached 0
        for (i, s) in st.slots.iter_mut().enumerate() {
            if s.occupied && s.draining && self.runtimes[i].active_conns.load(Ordering::Acquire) == 0
            {
                s.occupied = false;
                s.draining = false;
            }
        }
        let next_gen = self.generation.load(Ordering::Relaxed) + 1;
        st.snapshot = Self::build_snapshot(&st.slots, &self.runtimes, next_gen);
        self.generation.store(next_gen, Ordering::Release);
        next_gen
    }

    /// Dynamically register a new target (or update weight / un-drain if endpoint already exists).
    pub fn register_target(&self, spec: BackendSpec) -> MutationOutcome {
        let mut st = self.control.write().unwrap();

        // If endpoint is already present, update weight & un-drain cleanly
        for (i, s) in st.slots.iter_mut().enumerate() {
            if s.occupied && s.spec.endpoint == spec.endpoint {
                s.spec.weight = spec.weight;
                if spec.dns_source.is_some() {
                    s.spec.dns_source = spec.dns_source;
                }
                s.draining = false;
                self.runtimes[i].healthy.store(true, Ordering::Release);
                self.runtimes[i].consec_failures.store(0, Ordering::Relaxed);
                let gen = self.publish_locked(&mut st);
                return MutationOutcome::Updated {
                    slot_id: i as u16,
                    generation: gen,
                };
            }
        }

        // Find a vacant slot (reclaiming any fully drained slots first)
        for (i, s) in st.slots.iter_mut().enumerate() {
            if s.occupied && s.draining && self.runtimes[i].active_conns.load(Ordering::Acquire) == 0
            {
                s.occupied = false;
                s.draining = false;
            }
            if !s.occupied {
                self.runtimes[i].reset_for_new_target();
                *s = SlotMeta {
                    occupied: true,
                    draining: false,
                    spec,
                };
                let gen = self.publish_locked(&mut st);
                return MutationOutcome::Registered {
                    slot_id: i as u16,
                    generation: gen,
                };
            }
        }
        MutationOutcome::PoolFull
    }

    /// Dynamically deregister an endpoint.
    /// - `graceful_drain = true`: immediately stops routing new traffic to this target, while
    ///   keeping its slot alive until `active_conns == 0`.
    /// - `graceful_drain = false`: removes the slot immediately.
    pub fn deregister_target(&self, ep: EndpointV4, graceful_drain: bool) -> MutationOutcome {
        let mut st = self.control.write().unwrap();
        for (i, s) in st.slots.iter_mut().enumerate() {
            if s.occupied && s.spec.endpoint == ep {
                let active = self.runtimes[i].active_conns.load(Ordering::Acquire);
                if graceful_drain && active > 0 {
                    s.draining = true;
                    let gen = self.publish_locked(&mut st);
                    return MutationOutcome::Draining {
                        slot_id: i as u16,
                        active_conns: active,
                        generation: gen,
                    };
                } else {
                    s.occupied = false;
                    s.draining = false;
                    let gen = self.publish_locked(&mut st);
                    return MutationOutcome::Removed {
                        slot_id: i as u16,
                        generation: gen,
                    };
                }
            }
        }
        MutationOutcome::NotFound
    }

    /// Live-tune weight of an existing endpoint (`weight = 0` soft-drains it without removing).
    pub fn set_weight(&self, ep: EndpointV4, weight: u32) -> MutationOutcome {
        let mut st = self.control.write().unwrap();
        for (i, s) in st.slots.iter_mut().enumerate() {
            if s.occupied && s.spec.endpoint == ep {
                s.spec.weight = weight.min(1000);
                if weight > 0 {
                    s.draining = false;
                }
                let gen = self.publish_locked(&mut st);
                return MutationOutcome::Updated {
                    slot_id: i as u16,
                    generation: gen,
                };
            }
        }
        MutationOutcome::NotFound
    }

    /// Live-tune weight for all targets belonging to a DNS source key (e.g. `"api.internal:8080"`).
    pub fn set_dns_weight(&self, dns_source: &str, weight: u32) -> (usize, u64) {
        let mut st = self.control.write().unwrap();
        let mut updated = 0usize;
        for s in st.slots.iter_mut() {
            if s.occupied && s.spec.dns_source.as_deref() == Some(dns_source) {
                s.spec.weight = weight.min(1000);
                if weight > 0 {
                    s.draining = false;
                }
                updated += 1;
            }
        }
        if updated > 0 {
            let gen = self.publish_locked(&mut st);
            (updated, gen)
        } else {
            (0, self.generation())
        }
    }

    /// Deregister all endpoints belonging to a DNS source key.
    pub fn deregister_dns_source(&self, dns_source: &str, graceful_drain: bool) -> (usize, u64) {
        let mut st = self.control.write().unwrap();
        let mut affected = 0usize;
        for (i, s) in st.slots.iter_mut().enumerate() {
            if s.occupied && s.spec.dns_source.as_deref() == Some(dns_source) {
                let active = self.runtimes[i].active_conns.load(Ordering::Acquire);
                if graceful_drain && active > 0 {
                    s.draining = true;
                } else {
                    s.occupied = false;
                    s.draining = false;
                }
                affected += 1;
            }
        }
        if affected > 0 {
            let gen = self.publish_locked(&mut st);
            (affected, gen)
        } else {
            (0, self.generation())
        }
    }

    /// Reconcile a DNS source's resolved IPv4 endpoints cleanly:
    /// - Registers newly appeared IPs with `weight`
    /// - Keeps unchanged IPs (preserving their runtime stats & connections!)
    /// - Gracefully drains IPs that disappeared from DNS!
    pub fn reconcile_dns_endpoints(
        &self,
        dns_source: &str,
        resolved: &[EndpointV4],
        weight: u32,
    ) -> (usize, usize, u64) {
        let mut st = self.control.write().unwrap();
        let mut added = 0usize;
        let mut drained = 0usize;
        let mut changed = false;

        // 1. Drain endpoints previously owned by `dns_source` that are no longer in `resolved`
        for (i, s) in st.slots.iter_mut().enumerate() {
            if s.occupied && s.spec.dns_source.as_deref() == Some(dns_source) {
                if !resolved.contains(&s.spec.endpoint) {
                    let active = self.runtimes[i].active_conns.load(Ordering::Acquire);
                    if active > 0 {
                        if !s.draining {
                            s.draining = true;
                            drained += 1;
                            changed = true;
                        }
                    } else {
                        s.occupied = false;
                        s.draining = false;
                        drained += 1;
                        changed = true;
                    }
                } else if s.draining || s.spec.weight != weight.min(1000) {
                    s.draining = false;
                    s.spec.weight = weight.min(1000);
                    changed = true;
                }
            }
        }

        // 2. Register any newly resolved endpoints
        for &ep in resolved {
            let already = st.slots.iter().any(|s| s.occupied && s.spec.endpoint == ep);
            if !already {
                for (i, s) in st.slots.iter_mut().enumerate() {
                    if !s.occupied {
                        self.runtimes[i].reset_for_new_target();
                        *s = SlotMeta {
                            occupied: true,
                            draining: false,
                            spec: BackendSpec::new(ep)
                                .with_weight(weight)
                                .with_dns_source(dns_source),
                        };
                        added += 1;
                        changed = true;
                        break;
                    }
                }
            }
        }

        let gen = if changed {
            self.publish_locked(&mut st)
        } else {
            self.generation()
        };
        (added, drained, gen)
    }

    /// Return complete target list with live weights, traffic shares, health, and connection stats.
    pub fn list_targets(&self) -> Vec<TargetStatus> {
        let st = self.control.read().unwrap();
        let mut total_active_weight: u64 = 0;
        for (i, s) in st.slots.iter().enumerate() {
            if s.occupied
                && !s.draining
                && s.spec.weight > 0
                && self.runtimes[i].healthy.load(Ordering::Relaxed)
            {
                total_active_weight += s.spec.weight as u64;
            }
        }

        let mut out = Vec::new();
        for (i, s) in st.slots.iter().enumerate() {
            if !s.occupied {
                continue;
            }
            let rt = &self.runtimes[i];
            let healthy = rt.healthy.load(Ordering::Relaxed);
            let share = if !s.draining && healthy && s.spec.weight > 0 && total_active_weight > 0 {
                (s.spec.weight as f64 / total_active_weight as f64) * 100.0
            } else {
                0.0
            };
            out.push(TargetStatus {
                slot_id: i as u16,
                endpoint: s.spec.endpoint,
                dns_source: s.spec.dns_source.clone(),
                weight: s.spec.weight,
                effective_share_pct: share,
                healthy,
                draining: s.draining,
                active_conns: rt.active_conns.load(Ordering::Relaxed),
                total_conns: rt.total_conns.load(Ordering::Relaxed),
                ewma_connect_us: rt.ewma_connect_ns.load(Ordering::Relaxed) as f64 / 1_000.0,
            });
        }
        out
    }

    #[inline(always)]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn snapshot(&self) -> RoutingSnapshot {
        self.control.read().unwrap().snapshot.clone()
    }

    #[inline(always)]
    pub fn on_conn_open(&self, idx: usize) {
        if let Some(rt) = self.runtimes.get(idx) {
            rt.active_conns.fetch_add(1, Ordering::Relaxed);
            rt.total_conns.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline(always)]
    pub fn on_conn_close(&self, idx: usize) {
        if let Some(rt) = self.runtimes.get(idx) {
            let _ = rt
                .active_conns
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(1))
                });
        }
    }

    /// Update EWMA connect latency (alpha = 1/8, branchless bitshift).
    #[inline(always)]
    pub fn record_connect_latency(&self, idx: usize, latency_ns: u64) {
        if let Some(rt) = self.runtimes.get(idx) {
            rt.consec_failures.store(0, Ordering::Relaxed);
            let prev = rt.ewma_connect_ns.load(Ordering::Relaxed);
            let next = ((prev * 7) + latency_ns) >> 3;
            rt.ewma_connect_ns.store(next, Ordering::Relaxed);
        }
    }

    /// Passive failure circuit breaker: trips target out of snapshot after consecutive failures.
    pub fn record_failure(&self, idx: usize) {
        if let Some(rt) = self.runtimes.get(idx) {
            let fails = rt.consec_failures.fetch_add(1, Ordering::Relaxed) + 1;
            if fails >= self.failure_threshold && rt.healthy.swap(false, Ordering::AcqRel) {
                let mut st = self.control.write().unwrap();
                self.publish_locked(&mut st);
            }
        }
    }

    pub fn set_healthy(&self, idx: usize, healthy: bool) {
        if let Some(rt) = self.runtimes.get(idx) {
            if healthy {
                rt.consec_failures.store(0, Ordering::Relaxed);
            }
            if rt.healthy.swap(healthy, Ordering::AcqRel) != healthy {
                let mut st = self.control.write().unwrap();
                self.publish_locked(&mut st);
            }
        }
    }

    /// Spawn active background TCP health-check loop (also reaps finished draining slots!).
    pub fn spawn_health_checker(
        self: &Arc<Self>,
        interval: Duration,
        stop: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        let pool = Arc::clone(self);
        std::thread::Builder::new()
            .name("tetrux-health".to_string())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let targets = pool.list_targets();
                    let mut need_reap = false;
                    for t in &targets {
                        if t.draining {
                            if t.active_conns == 0 {
                                need_reap = true;
                            }
                            continue;
                        }
                        let addr = std::net::SocketAddr::V4(t.endpoint.to_std());
                        let ok = std::net::TcpStream::connect_timeout(
                            &addr,
                            Duration::from_millis(250),
                        )
                        .is_ok();
                        pool.set_healthy(t.slot_id as usize, ok);
                    }
                    if need_reap {
                        let mut st = pool.control.write().unwrap();
                        pool.publish_locked(&mut st);
                    }
                    let mut slept = Duration::ZERO;
                    let step = Duration::from_millis(50);
                    while slept < interval && !stop.load(Ordering::Relaxed) {
                        std::thread::sleep(step);
                        slept += step;
                    }
                }
            })
            .expect("failed to spawn health checker")
    }
}

/// Thread-local zero-lock backend selector held by each worker core.
/// Zero mutexes, zero Arc refcount traffic on the hot path!
pub struct WorkerSelector {
    pool: Arc<BackendPool>,
    snap: RoutingSnapshot,
    rng: Xorshift64,
    rr_cursor: usize,
}

impl WorkerSelector {
    pub fn new(pool: Arc<BackendPool>, worker_id: usize) -> Self {
        let snap = pool.snapshot();
        Self {
            pool,
            snap,
            rng: Xorshift64::new(0x5445_5452_5558u64 ^ ((worker_id as u64 + 1) * 0x9e37_79b9)),
            rr_cursor: worker_id,
        }
    }

    #[inline(always)]
    fn refresh_if_stale(&mut self) {
        let current_gen = self.pool.generation();
        if current_gen != self.snap.generation {
            self.snap = self.pool.snapshot();
        }
    }

    #[inline(always)]
    pub fn endpoint_of(&self, idx: u16) -> EndpointV4 {
        self.snap.endpoints[idx as usize]
    }

    #[inline(always)]
    pub fn mac_of(&self, idx: u16) -> [u8; 6] {
        self.snap.macs[idx as usize]
    }

    /// Select a backend slot_id + endpoint with ZERO locks on the hot path.
    #[inline(always)]
    pub fn select(&mut self, flow_hash: u64) -> Option<(u16, EndpointV4)> {
        self.refresh_if_stale();
        let healthy = &self.snap.healthy_ids;
        let n = healthy.len();
        if n == 0 {
            return None;
        }
        let chosen = if n == 1 {
            healthy[0]
        } else {
            match self.pool.algo {
                LbAlgorithm::Maglev => self.snap.maglev.lookup(flow_hash)?,
                LbAlgorithm::RoundRobin => {
                    let sched = &self.snap.smooth_wrr;
                    if sched.is_empty() {
                        return None;
                    }
                    let idx = sched[self.rr_cursor % sched.len()];
                    self.rr_cursor = self.rr_cursor.wrapping_add(1);
                    idx
                }
                LbAlgorithm::P2cLeastConn => {
                    // Pick 2 distinct healthy targets; compare weight-normalized active load
                    // `((active_conns + 1) << 16) / weight` under concurrency, or sample via O(1)
                    // Vose Alias Table when idle so weights hold strictly at ALL load levels!
                    let i = self.rng.next_bounded(n);
                    let mut j = self.rng.next_bounded(n - 1);
                    if j >= i {
                        j += 1;
                    }
                    let b1 = healthy[i];
                    let b2 = healthy[j];
                    let rt1 = &self.pool.runtimes[b1 as usize];
                    let rt2 = &self.pool.runtimes[b2 as usize];
                    let c1 = rt1.active_conns.load(Ordering::Relaxed);
                    let c2 = rt2.active_conns.load(Ordering::Relaxed);
                    if c1 == 0 && c2 == 0 {
                        self.snap.alias.sample(&mut self.rng).unwrap_or(b1)
                    } else {
                        let w1 = self.snap.weights[b1 as usize].max(1) as u64;
                        let w2 = self.snap.weights[b2 as usize].max(1) as u64;
                        // Cross-multiply `(c1 + 1) * w2` vs `(c2 + 1) * w1` (0 divisions!)
                        let lhs = (c1 as u64 + 1) * w2;
                        let rhs = (c2 as u64 + 1) * w1;
                        if lhs != rhs {
                            if lhs < rhs { b1 } else { b2 }
                        } else {
                            let l1 = rt1.ewma_connect_ns.load(Ordering::Relaxed);
                            let l2 = rt2.ewma_connect_ns.load(Ordering::Relaxed);
                            if l1 <= l2 { b1 } else { b2 }
                        }
                    }
                }
            }
        };
        Some((chosen, self.snap.endpoints[chosen as usize]))
    }

    #[inline(always)]
    pub fn pool(&self) -> &Arc<BackendPool> {
        &self.pool
    }

    #[inline(always)]
    pub fn fast_now_ns(&self) -> u64 {
        sys::fast_now_ns()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lb::hash::hash_u64;

    #[test]
    fn weighted_routing_accurate_across_all_three_algorithms() {
        let specs = vec![
            BackendSpec::new(EndpointV4::from_octets(10, 0, 0, 1, 8080)).with_weight(5),
            BackendSpec::new(EndpointV4::from_octets(10, 0, 0, 2, 8080)).with_weight(3),
            BackendSpec::new(EndpointV4::from_octets(10, 0, 0, 3, 8080)).with_weight(2),
        ];
        for algo in [
            LbAlgorithm::Maglev,
            LbAlgorithm::RoundRobin,
            LbAlgorithm::P2cLeastConn,
        ] {
            let pool = BackendPool::new(specs.clone(), algo);
            let mut sel = WorkerSelector::new(pool, 0);
            let mut counts = [0usize; 3];
            let n = 40_000usize;
            for i in 0..n {
                let (id, _) = sel.select(hash_u64(i as u64)).unwrap();
                counts[id as usize] += 1;
            }
            let p0 = counts[0] as f64 * 100.0 / n as f64;
            let p1 = counts[1] as f64 * 100.0 / n as f64;
            let p2 = counts[2] as f64 * 100.0 / n as f64;
            assert!(
                (p0 - 50.0).abs() < 2.5 && (p1 - 30.0).abs() < 2.5 && (p2 - 20.0).abs() < 2.5,
                "{algo:?} weights off: {p0:.2}% / {p1:.2}% / {p2:.2}%"
            );
        }
    }

    #[test]
    fn dynamic_register_weight_tune_and_graceful_drain() {
        let ep1 = EndpointV4::from_octets(10, 0, 0, 1, 8080);
        let ep2 = EndpointV4::from_octets(10, 0, 0, 2, 8080);
        let ep3 = EndpointV4::from_octets(10, 0, 0, 3, 8080);

        let pool = BackendPool::new(
            vec![BackendSpec::new(ep1).with_weight(1)],
            LbAlgorithm::RoundRobin,
        );
        let mut sel = WorkerSelector::new(Arc::clone(&pool), 0);

        // Register ep2 with weight 3 -> 25% / 75%
        assert!(matches!(
            pool.register_target(BackendSpec::new(ep2).with_weight(3)),
            MutationOutcome::Registered { slot_id: 1, .. }
        ));
        let mut c1 = 0;
        let mut c2 = 0;
        for i in 0..400 {
            let (_, ep) = sel.select(i).unwrap();
            if ep == ep1 { c1 += 1; } else if ep == ep2 { c2 += 1; }
        }
        assert_eq!((c1, c2), (100, 300));

        // Live tune ep1 weight -> 3 (now 50% / 50%)
        assert!(matches!(
            pool.set_weight(ep1, 3),
            MutationOutcome::Updated { slot_id: 0, .. }
        ));
        c1 = 0;
        c2 = 0;
        for i in 0..400 {
            let (_, ep) = sel.select(i).unwrap();
            if ep == ep1 { c1 += 1; } else if ep == ep2 { c2 += 1; }
        }
        assert_eq!((c1, c2), (200, 200));

        // Simulate active conn on ep2, then graceful deregister -> enters Draining, 0 new flows!
        pool.on_conn_open(1);
        assert!(matches!(
            pool.deregister_target(ep2, true),
            MutationOutcome::Draining { slot_id: 1, active_conns: 1, .. }
        ));
        for i in 0..100 {
            let (_, ep) = sel.select(i).unwrap();
            assert_eq!(ep, ep1, "draining backend must receive zero new flows!");
        }
        // Finish in-flight conn -> registering ep3 reclaims slot 1!
        pool.on_conn_close(1);
        assert!(matches!(
            pool.register_target(BackendSpec::new(ep3).with_weight(1)),
            MutationOutcome::Registered { slot_id: 1, .. }
        ));
    }
}
