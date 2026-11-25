//! Lock-free RCU-style L4 Backend Pool supporting:
//! - Maglev O(1) Consistent Hashing
//! - Power-of-Two-Choices (P2C) Least-Connections + EWMA Latency (optimal tail latency!)
//! - Smooth Round-Robin
//! Plus background active TCP health checks and passive circuit-breaking.

use super::hash::Xorshift64;
use super::maglev::MaglevTable;
use crate::mem::cache::CachePadded;
use crate::sys::{self, EndpointV4};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LbAlgorithm {
    /// O(1) Maglev consistent hashing on client flow 4-tuple.
    Maglev,
    /// Power-of-Two-Choices comparing active connections & EWMA latency.
    P2cLeastConn,
    /// Per-worker lock-free Round-Robin.
    RoundRobin,
}

#[derive(Clone, Debug)]
pub struct BackendSpec {
    pub endpoint: EndpointV4,
    pub weight: u32,
    /// Destination MAC address used in Kernel-Bypass DSR (Direct Server Return) mode.
    pub mac: [u8; 6],
}

impl BackendSpec {
    pub fn new(endpoint: EndpointV4) -> Self {
        Self {
            endpoint,
            weight: 1,
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, (endpoint.port & 0xff) as u8],
        }
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight.max(1);
        self
    }

    pub fn with_mac(mut self, mac: [u8; 6]) -> Self {
        self.mac = mac;
        self
    }
}

/// Per-backend hot runtime counters padded to 128B cache lines to prevent false sharing.
pub struct BackendState {
    pub spec: BackendSpec,
    pub active_conns: CachePadded<AtomicU32>,
    pub total_conns: CachePadded<AtomicU64>,
    pub ewma_connect_ns: CachePadded<AtomicU64>,
    pub consec_failures: CachePadded<AtomicU32>,
    pub healthy: CachePadded<AtomicBool>,
}

impl BackendState {
    fn new(spec: BackendSpec) -> Self {
        Self {
            spec,
            active_conns: CachePadded::new(AtomicU32::new(0)),
            total_conns: CachePadded::new(AtomicU64::new(0)),
            ewma_connect_ns: CachePadded::new(AtomicU64::new(100_000)), // 100us initial prior
            consec_failures: CachePadded::new(AtomicU32::new(0)),
            healthy: CachePadded::new(AtomicBool::new(true)),
        }
    }
}

/// Immutable routing snapshot cloned lazily into each worker ONLY when `generation` changes.
#[derive(Clone)]
pub struct RoutingSnapshot {
    pub generation: u64,
    pub healthy_ids: Vec<u16>,
    pub endpoints: Vec<EndpointV4>,
    pub macs: Vec<[u8; 6]>,
    pub maglev: MaglevTable,
}

pub struct BackendPool {
    pub algo: LbAlgorithm,
    backends: Vec<BackendState>,
    generation: CachePadded<AtomicU64>,
    master_snapshot: RwLock<RoutingSnapshot>,
    failure_threshold: u32,
}

impl BackendPool {
    pub fn new(specs: Vec<BackendSpec>, algo: LbAlgorithm) -> Arc<Self> {
        let backends: Vec<BackendState> = specs.into_iter().map(BackendState::new).collect();
        let snap = Self::build_snapshot(&backends, 1);
        Arc::new(Self {
            algo,
            backends,
            generation: CachePadded::new(AtomicU64::new(1)),
            master_snapshot: RwLock::new(snap),
            failure_threshold: 3,
        })
    }

    fn build_snapshot(backends: &[BackendState], generation: u64) -> RoutingSnapshot {
        let mut healthy_ids = Vec::with_capacity(backends.len());
        let mut endpoints = Vec::with_capacity(backends.len());
        let mut macs = Vec::with_capacity(backends.len());
        let mut key_storage: Vec<(u16, [u8; 6], u32)> = Vec::with_capacity(backends.len());

        for (i, b) in backends.iter().enumerate() {
            endpoints.push(b.spec.endpoint);
            macs.push(b.spec.mac);
            if b.healthy.load(Ordering::Relaxed) {
                healthy_ids.push(i as u16);
                let mut k = [0u8; 6];
                k[0..4].copy_from_slice(&b.spec.endpoint.ip.to_be_bytes());
                k[4..6].copy_from_slice(&b.spec.endpoint.port.to_be_bytes());
                key_storage.push((i as u16, k, b.spec.weight));
            }
        }
        // Fallback: if all backends marked unhealthy, open all to avoid total blackout (fail-open)
        if healthy_ids.is_empty() && !backends.is_empty() {
            for (i, b) in backends.iter().enumerate() {
                healthy_ids.push(i as u16);
                let mut k = [0u8; 6];
                k[0..4].copy_from_slice(&b.spec.endpoint.ip.to_be_bytes());
                k[4..6].copy_from_slice(&b.spec.endpoint.port.to_be_bytes());
                key_storage.push((i as u16, k, b.spec.weight));
            }
        }
        let maglev_inputs: Vec<(u16, &[u8], u32)> = key_storage
            .iter()
            .map(|(id, k, w)| (*id, &k[..], *w))
            .collect();
        let maglev = MaglevTable::build(&maglev_inputs);

        RoutingSnapshot {
            generation,
            healthy_ids,
            endpoints,
            macs,
            maglev,
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.backends.len()
    }

    #[inline(always)]
    pub fn backend(&self, idx: usize) -> &BackendState {
        &self.backends[idx]
    }

    #[inline(always)]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> RoutingSnapshot {
        self.master_snapshot.read().unwrap().clone()
    }

    #[inline(always)]
    pub fn on_conn_open(&self, idx: usize) {
        if let Some(b) = self.backends.get(idx) {
            b.active_conns.fetch_add(1, Ordering::Relaxed);
            b.total_conns.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline(always)]
    pub fn on_conn_close(&self, idx: usize) {
        if let Some(b) = self.backends.get(idx) {
            let _ = b
                .active_conns
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(1))
                });
        }
    }

    /// Update EWMA connect latency (alpha = 1/8, branchless bitshift).
    #[inline(always)]
    pub fn record_connect_latency(&self, idx: usize, latency_ns: u64) {
        if let Some(b) = self.backends.get(idx) {
            b.consec_failures.store(0, Ordering::Relaxed);
            let prev = b.ewma_connect_ns.load(Ordering::Relaxed);
            let next = ((prev * 7) + latency_ns) >> 3;
            b.ewma_connect_ns.store(next, Ordering::Relaxed);
        }
    }

    /// Passive failure circuit breaker: trips backend out of snapshot after consecutive failures.
    pub fn record_failure(&self, idx: usize) {
        if let Some(b) = self.backends.get(idx) {
            let fails = b.consec_failures.fetch_add(1, Ordering::Relaxed) + 1;
            if fails >= self.failure_threshold && b.healthy.swap(false, Ordering::AcqRel) {
                self.republish_snapshot();
            }
        }
    }

    pub fn set_healthy(&self, idx: usize, healthy: bool) {
        if let Some(b) = self.backends.get(idx) {
            if healthy {
                b.consec_failures.store(0, Ordering::Relaxed);
            }
            if b.healthy.swap(healthy, Ordering::AcqRel) != healthy {
                self.republish_snapshot();
            }
        }
    }

    fn republish_snapshot(&self) {
        let mut guard = self.master_snapshot.write().unwrap();
        let next_gen = self.generation.load(Ordering::Relaxed) + 1;
        *guard = Self::build_snapshot(&self.backends, next_gen);
        self.generation.store(next_gen, Ordering::Release);
    }

    /// Spawn active background TCP health-check loop.
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
                    for (idx, b) in pool.backends.iter().enumerate() {
                        let addr = std::net::SocketAddr::V4(b.spec.endpoint.to_std());
                        let ok = std::net::TcpStream::connect_timeout(
                            &addr,
                            Duration::from_millis(250),
                        )
                        .is_ok();
                        pool.set_healthy(idx, ok);
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

    /// Select a backend index + endpoint with ZERO locks on the hot path.
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
                    let idx = healthy[self.rr_cursor % n];
                    self.rr_cursor = self.rr_cursor.wrapping_add(1);
                    idx
                }
                LbAlgorithm::P2cLeastConn => {
                    let i = self.rng.next_bounded(n);
                    let mut j = self.rng.next_bounded(n - 1);
                    if j >= i {
                        j += 1;
                    }
                    let b1 = healthy[i];
                    let b2 = healthy[j];
                    let s1 = &self.pool.backends[b1 as usize];
                    let s2 = &self.pool.backends[b2 as usize];
                    let c1 = s1.active_conns.load(Ordering::Relaxed);
                    let c2 = s2.active_conns.load(Ordering::Relaxed);
                    if c1 != c2 {
                        if c1 < c2 { b1 } else { b2 }
                    } else {
                        // Tie-break on EWMA backend connect latency for tail-latency optimization!
                        let l1 = s1.ewma_connect_ns.load(Ordering::Relaxed);
                        let l2 = s2.ewma_connect_ns.load(Ordering::Relaxed);
                        if l1 <= l2 { b1 } else { b2 }
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
