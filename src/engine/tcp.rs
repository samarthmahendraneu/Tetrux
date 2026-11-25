//! Thread-Per-Core Shared-Nothing L4 TCP Network Load Balancer.
//!
//! Low-level optimizations:
//! - Single-syscall batched `kevent` (changelist submission + event retrieval combined)
//! - Lock-free SPSC batched accept distribution (`ShardedAcceptor`) with coalesced wakeups
//!   (0 wakeups when workers are active/spinning!) or per-worker `SO_REUSEPORT` listeners
//! - Adaptive hybrid busy-polling (`busy_poll_us`) eliminating kernel sleep/wakeup jitter
//!   under bursts while dropping to ~0% idle CPU
//! - Bufferless L1-hot fast-path forwarding (~96B per idle/active connection!) with lazy
//!   page-aligned `BufferPool` ring leases ONLY on `EAGAIN` backpressure (0 heap allocs!)
//! - Per-turn fair work budgeting (`work_budget_bytes`) preventing elephant streams from
//!   inflating mouse RPC p99/p99.9 tail latency

use crate::lb::balancer::{BackendPool, WorkerSelector};
use crate::lb::hash::hash_endpoint;
use crate::mem::cache::CachePadded;
use crate::mem::slab::{BufferPool, PooledRing, Slab};
use crate::mem::spsc::{spsc_channel, SpscConsumer, SpscProducer};
use crate::sys::{self, EndpointV4, Fd, IoStatus, PollEvent, Poller, WakeHandle};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

const LISTEN_TOKEN: u64 = u64::MAX;
const SCRATCH_SIZE: usize = 65536;
const ACCEPT_BATCH: usize = 128;

// Connection flag bitmask
const F_CLIENT_EOF: u8 = 1 << 0;
const F_BACKEND_EOF: u8 = 1 << 1;
const F_CLIENT_WR_ARMED: u8 = 1 << 2;
const F_BACKEND_WR_ARMED: u8 = 1 << 3;
const F_CLIENT_RD_PAUSED: u8 = 1 << 4;
const F_BACKEND_RD_PAUSED: u8 = 1 << 5;
const F_CLIENT_SHUT_WR: u8 = 1 << 6;
const F_BACKEND_SHUT_WR: u8 = 1 << 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptStrategy {
    /// Dedicated high-priority acceptor batches `accept()` and dispatches FDs over
    /// lock-free per-worker SPSC rings (optimal on macOS XNU).
    ShardedAcceptor,
    /// Every worker binds its own `SO_REUSEPORT` listener socket (optimal on Linux).
    ReusePort,
}

#[derive(Clone, Debug)]
pub struct TcpEngineConfig {
    pub listen_addr: EndpointV4,
    pub workers: usize,
    pub accept_strategy: AcceptStrategy,
    /// Listen socket backlog for SYN burst absorption.
    pub backlog: i32,
    /// Kernel socket send/recv buffer bytes (0 = OS auto-tune).
    pub sock_buf_bytes: i32,
    /// Max concurrent connections per worker (strictly bounded memory + overload shedding).
    pub max_conns_per_worker: usize,
    /// Number of lazily-leased backpressure ring chunks per worker.
    pub pool_chunks_per_worker: usize,
    /// Size of each backpressure ring chunk (power of 2, >= 4096).
    pub pool_chunk_bytes: usize,
    /// Adaptive busy-poll window in microseconds after recent activity (0 = pure interrupt mode).
    pub busy_poll_us: u64,
    /// Fair per-connection byte budget per poll turn to protect mouse RPC tail latency.
    pub work_budget_bytes: usize,
    /// Prioritize short mouse RPC connections ahead of bulk elephant flows in each poll batch.
    pub mouse_first_scheduling: bool,
    /// Idle connection timeout in seconds (0 = disabled).
    pub idle_timeout_secs: u64,
    /// Optional active TCP health check interval (None = disabled).
    pub health_check_interval: Option<Duration>,
}

impl Default for TcpEngineConfig {
    fn default() -> Self {
        Self {
            listen_addr: EndpointV4::from_octets(127, 0, 0, 1, 0),
            workers: 4,
            #[cfg(target_os = "linux")]
            accept_strategy: AcceptStrategy::ReusePort,
            #[cfg(not(target_os = "linux"))]
            accept_strategy: AcceptStrategy::ShardedAcceptor,
            backlog: 4096,
            sock_buf_bytes: 262_144,
            max_conns_per_worker: 4096,
            pool_chunks_per_worker: 256,
            pool_chunk_bytes: 65_536,
            busy_poll_us: 150,
            work_budget_bytes: 131_072,
            mouse_first_scheduling: true,
            idle_timeout_secs: 60,
            health_check_interval: None,
        }
    }
}

/// Lock-free aggregated statistics across all workers (cache-line padded per worker).
pub struct WorkerCounters {
    pub accepted: AtomicU64,
    pub rejected: AtomicU64,
    pub active: AtomicU64,
    pub peak_active: AtomicU64,
    pub bytes_c2b: AtomicU64,
    pub bytes_b2c: AtomicU64,
    pub poll_calls: AtomicU64,
    pub poll_events: AtomicU64,
    pub read_calls: AtomicU64,
    pub write_calls: AtomicU64,
    pub fast_path_writes: AtomicU64,
    pub buffered_writes: AtomicU64,
    pub wakeups_sent: AtomicU64,
    pub wakeups_suppressed: AtomicU64,
    pub peak_buffers_used: AtomicU64,
    pub worker_cpu_ns: AtomicU64,
}

impl Default for WorkerCounters {
    fn default() -> Self {
        Self {
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            active: AtomicU64::new(0),
            peak_active: AtomicU64::new(0),
            bytes_c2b: AtomicU64::new(0),
            bytes_b2c: AtomicU64::new(0),
            poll_calls: AtomicU64::new(0),
            poll_events: AtomicU64::new(0),
            read_calls: AtomicU64::new(0),
            write_calls: AtomicU64::new(0),
            fast_path_writes: AtomicU64::new(0),
            buffered_writes: AtomicU64::new(0),
            wakeups_sent: AtomicU64::new(0),
            wakeups_suppressed: AtomicU64::new(0),
            peak_buffers_used: AtomicU64::new(0),
            worker_cpu_ns: AtomicU64::new(0),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TcpStatsSnapshot {
    pub accepted: u64,
    pub rejected: u64,
    pub active: u64,
    pub peak_active: u64,
    pub bytes_c2b: u64,
    pub bytes_b2c: u64,
    pub poll_calls: u64,
    pub poll_events: u64,
    pub read_calls: u64,
    pub write_calls: u64,
    pub fast_path_writes: u64,
    pub buffered_writes: u64,
    pub wakeups_sent: u64,
    pub wakeups_suppressed: u64,
    pub peak_buffers_used: u64,
    pub worker_cpu_ns: u64,
}

#[derive(Clone, Copy)]
struct AcceptedFd {
    fd: Fd,
    peer: EndpointV4,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnState {
    ConnectingBackend,
    Established,
}

/// Compact per-connection record (~80 bytes!) stored directly in pre-allocated `Slab<TcpConn>`.
struct TcpConn {
    client_fd: Fd,
    backend_fd: Fd,
    generation: u32,
    backend_idx: u16,
    state: ConnState,
    flags: u8,
    /// EWMA bytes moved per turn (used by Mouse-First tail-latency scheduler).
    ewma_turn_bytes: u32,
    connect_start_ns: u64,
    last_active_ns: u64,
    c2b: PooledRing,
    b2c: PooledRing,
}

#[inline(always)]
fn encode_token(slot: u32, is_backend: bool, gen: u32) -> u64 {
    (slot as u64) | ((is_backend as u64) << 32) | (((gen & 0x7fff_ffff) as u64) << 33)
}

#[inline(always)]
fn decode_token(token: u64) -> (u32, bool, u32) {
    let slot = (token & 0xffff_ffff) as u32;
    let is_backend = ((token >> 32) & 1) != 0;
    let gen = ((token >> 33) & 0x7fff_ffff) as u32;
    (slot, is_backend, gen)
}

pub struct TcpNlbHandle {
    bound_addr: EndpointV4,
    stop: Arc<AtomicBool>,
    counters: Arc<Vec<CachePadded<WorkerCounters>>>,
    wakers: Vec<WakeHandle>,
    threads: Vec<JoinHandle<()>>,
}

impl TcpNlbHandle {
    pub fn bound_addr(&self) -> EndpointV4 {
        self.bound_addr
    }

    pub fn stats(&self) -> TcpStatsSnapshot {
        let mut s = TcpStatsSnapshot::default();
        for c in self.counters.iter() {
            s.accepted += c.accepted.load(Ordering::Relaxed);
            s.rejected += c.rejected.load(Ordering::Relaxed);
            s.active += c.active.load(Ordering::Relaxed);
            s.peak_active += c.peak_active.load(Ordering::Relaxed);
            s.bytes_c2b += c.bytes_c2b.load(Ordering::Relaxed);
            s.bytes_b2c += c.bytes_b2c.load(Ordering::Relaxed);
            s.poll_calls += c.poll_calls.load(Ordering::Relaxed);
            s.poll_events += c.poll_events.load(Ordering::Relaxed);
            s.read_calls += c.read_calls.load(Ordering::Relaxed);
            s.write_calls += c.write_calls.load(Ordering::Relaxed);
            s.fast_path_writes += c.fast_path_writes.load(Ordering::Relaxed);
            s.buffered_writes += c.buffered_writes.load(Ordering::Relaxed);
            s.wakeups_sent += c.wakeups_sent.load(Ordering::Relaxed);
            s.wakeups_suppressed += c.wakeups_suppressed.load(Ordering::Relaxed);
            s.peak_buffers_used += c.peak_buffers_used.load(Ordering::Relaxed);
            s.worker_cpu_ns += c.worker_cpu_ns.load(Ordering::Relaxed);
        }
        s
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        for w in &self.wakers {
            w.wake();
        }
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Drop for TcpNlbHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for w in &self.wakers {
            w.wake();
        }
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// Start the Tetrux L4 TCP Load Balancer.
pub fn start_tcp_nlb(
    config: TcpEngineConfig,
    pool: Arc<BackendPool>,
) -> io::Result<TcpNlbHandle> {
    let num_workers = config.workers.max(1);
    let stop = Arc::new(AtomicBool::new(false));
    let counters: Arc<Vec<CachePadded<WorkerCounters>>> = Arc::new(
        (0..num_workers)
            .map(|_| CachePadded::new(WorkerCounters::default()))
            .collect(),
    );

    let mut threads = Vec::with_capacity(num_workers + 2);
    let mut wakers = Vec::with_capacity(num_workers + 1);

    if let Some(interval) = config.health_check_interval {
        threads.push(pool.spawn_health_checker(interval, Arc::clone(&stop)));
    }

    let bound_addr = match config.accept_strategy {
        AcceptStrategy::ShardedAcceptor => {
            let (listen_fd, bound) = sys::create_tcp_listener(
                config.listen_addr,
                config.backlog,
                false,
                config.sock_buf_bytes,
            )?;

            let mut producers = Vec::with_capacity(num_workers);
            let mut sleeping_flags = Vec::with_capacity(num_workers);
            let mut worker_wakers = Vec::with_capacity(num_workers);

            for wid in 0..num_workers {
                let (prod, cons) = spsc_channel::<AcceptedFd>(2048);
                let poller = Poller::new(512)?;
                let wake = poller.wake_handle();
                let sleeping = Arc::new(CachePadded::new(AtomicBool::new(false)));

                producers.push(prod);
                sleeping_flags.push(Arc::clone(&sleeping));
                worker_wakers.push(wake);
                wakers.push(wake);

                let cfg = config.clone();
                let pool_c = Arc::clone(&pool);
                let stop_c = Arc::clone(&stop);
                let cnt_c = Arc::clone(&counters);

                threads.push(
                    std::thread::Builder::new()
                        .name(format!("tetrux-tcp-w{wid}"))
                        .spawn(move || {
                            sys::pin_thread_performance(wid);
                            let mut worker = TcpWorker::new(
                                wid,
                                cfg,
                                poller,
                                None,
                                Some(cons),
                                sleeping,
                                pool_c,
                                cnt_c,
                            );
                            worker.run(stop_c);
                        })?,
                );
            }

            let acc_poller = Poller::new(64)?;
            let acc_wake = acc_poller.wake_handle();
            wakers.push(acc_wake);
            let stop_acc = Arc::clone(&stop);
            let cnt_acc = Arc::clone(&counters);

            threads.push(
                std::thread::Builder::new()
                    .name("tetrux-tcp-acc".to_string())
                    .spawn(move || {
                        sys::pin_thread_performance(num_workers);
                        run_sharded_acceptor(
                            listen_fd,
                            acc_poller,
                            producers,
                            sleeping_flags,
                            worker_wakers,
                            cnt_acc,
                            stop_acc,
                        );
                    })?,
            );

            bound
        }
        AcceptStrategy::ReusePort => {
            let (first_fd, bound) = sys::create_tcp_listener(
                config.listen_addr,
                config.backlog,
                true,
                config.sock_buf_bytes,
            )?;
            let mut listen_fds = Vec::with_capacity(num_workers);
            listen_fds.push(first_fd);
            for _ in 1..num_workers {
                let (fd, _) =
                    sys::create_tcp_listener(bound, config.backlog, true, config.sock_buf_bytes)?;
                listen_fds.push(fd);
            }

            for (wid, lfd) in listen_fds.into_iter().enumerate() {
                let poller = Poller::new(512)?;
                wakers.push(poller.wake_handle());
                let sleeping = Arc::new(CachePadded::new(AtomicBool::new(false)));
                let cfg = config.clone();
                let pool_c = Arc::clone(&pool);
                let stop_c = Arc::clone(&stop);
                let cnt_c = Arc::clone(&counters);

                threads.push(
                    std::thread::Builder::new()
                        .name(format!("tetrux-tcp-w{wid}"))
                        .spawn(move || {
                            sys::pin_thread_performance(wid);
                            let mut worker = TcpWorker::new(
                                wid,
                                cfg,
                                poller,
                                Some(lfd),
                                None,
                                sleeping,
                                pool_c,
                                cnt_c,
                            );
                            worker.run(stop_c);
                        })?,
                );
            }
            bound
        }
    };

    Ok(TcpNlbHandle {
        bound_addr,
        stop,
        counters,
        wakers,
        threads,
    })
}

fn run_sharded_acceptor(
    listen_fd: Fd,
    mut poller: Poller,
    mut producers: Vec<SpscProducer<AcceptedFd>>,
    sleeping_flags: Vec<Arc<CachePadded<AtomicBool>>>,
    wakers: Vec<WakeHandle>,
    counters: Arc<Vec<CachePadded<WorkerCounters>>>,
    stop: Arc<AtomicBool>,
) {
    poller.add_read(listen_fd, LISTEN_TOKEN, false);
    let mut events = Vec::with_capacity(64);
    let num_workers = producers.len();
    let mut rr = 0usize;
    let mut touched = vec![false; num_workers];
    let mut per_worker_batch: Vec<Vec<AcceptedFd>> =
        (0..num_workers).map(|_| Vec::with_capacity(32)).collect();

    while !stop.load(Ordering::Relaxed) {
        let _ = poller.poll(&mut events, Some(25_000_000));
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if events.is_empty() {
            continue;
        }

        // Drain a burst of accepted sockets in a tight loop!
        for _ in 0..ACCEPT_BATCH {
            // macOS inherits O_NONBLOCK/TCP_NODELAY/SO_NOSIGPIPE from listener -> ensure_opts=false saves 3 syscalls/accept!
            #[cfg(target_os = "macos")]
            let ensure_opts = false;
            #[cfg(not(target_os = "macos"))]
            let ensure_opts = true;

            match sys::accept_nonblock(listen_fd, ensure_opts) {
                Ok(Some((fd, peer))) => {
                    let wid = rr % num_workers;
                    rr = rr.wrapping_add(1);
                    per_worker_batch[wid].push(AcceptedFd { fd, peer });
                    touched[wid] = true;
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        // Flush per-worker batches with a SINGLE Release store per worker + coalesced wakeup!
        for wid in 0..num_workers {
            if !touched[wid] {
                continue;
            }
            touched[wid] = false;
            let batch = &mut per_worker_batch[wid];
            let pushed = producers[wid].push_batch(batch);
            if pushed < batch.len() {
                // Shed overflow connections cleanly instead of stalling acceptor
                for dropped in &batch[pushed..] {
                    sys::close_fd(dropped.fd);
                }
                counters[wid]
                    .rejected
                    .fetch_add((batch.len() - pushed) as u64, Ordering::Relaxed);
            }
            batch.clear();

            if pushed > 0 {
                // Only pay wakeup syscall if worker actually parked in the kernel!
                if sleeping_flags[wid].load(Ordering::Acquire) {
                    wakers[wid].wake();
                    counters[wid].wakeups_sent.fetch_add(1, Ordering::Relaxed);
                } else {
                    counters[wid]
                        .wakeups_suppressed
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    sys::close_fd(listen_fd);
}

struct TcpWorker {
    wid: usize,
    cfg: TcpEngineConfig,
    poller: Poller,
    listen_fd: Option<Fd>,
    accept_rx: Option<SpscConsumer<AcceptedFd>>,
    sleeping: Arc<CachePadded<AtomicBool>>,
    selector: WorkerSelector,
    slab: Slab<TcpConn>,
    buf_pool: BufferPool,
    /// L1/L2-hot aligned scratch buffer for bufferless fast-path forwarding.
    scratch: Box<[u8]>,
    next_gen: u32,
    counters: Arc<Vec<CachePadded<WorkerCounters>>>,
    // Worker-local hot stats flushed periodically to avoid atomic write contention
    local_accepted: u64,
    local_rejected: u64,
    local_bytes_c2b: u64,
    local_bytes_b2c: u64,
    local_poll_calls: u64,
    local_poll_events: u64,
    local_read_calls: u64,
    local_write_calls: u64,
    local_fast_writes: u64,
    local_buf_writes: u64,
    local_peak_active: u64,
    local_peak_bufs: u64,
}

impl TcpWorker {
    #[allow(clippy::too_many_arguments)]
    fn new(
        wid: usize,
        cfg: TcpEngineConfig,
        mut poller: Poller,
        listen_fd: Option<Fd>,
        accept_rx: Option<SpscConsumer<AcceptedFd>>,
        sleeping: Arc<CachePadded<AtomicBool>>,
        pool: Arc<BackendPool>,
        counters: Arc<Vec<CachePadded<WorkerCounters>>>,
    ) -> Self {
        if let Some(lfd) = listen_fd {
            poller.add_read(lfd, LISTEN_TOKEN, false);
        }
        let buf_pool = BufferPool::new(cfg.pool_chunks_per_worker, cfg.pool_chunk_bytes)
            .expect("failed to allocate page-aligned BufferPool");
        let slab = Slab::with_capacity(cfg.max_conns_per_worker);
        Self {
            wid,
            cfg,
            poller,
            listen_fd,
            accept_rx,
            sleeping,
            selector: WorkerSelector::new(pool, wid),
            slab,
            buf_pool,
            scratch: vec![0u8; SCRATCH_SIZE].into_boxed_slice(),
            next_gen: 1,
            counters,
            local_accepted: 0,
            local_rejected: 0,
            local_bytes_c2b: 0,
            local_bytes_b2c: 0,
            local_poll_calls: 0,
            local_poll_events: 0,
            local_read_calls: 0,
            local_write_calls: 0,
            local_fast_writes: 0,
            local_buf_writes: 0,
            local_peak_active: 0,
            local_peak_bufs: 0,
        }
    }

    fn flush_counters(&mut self) {
        let c = &self.counters[self.wid];
        if self.local_accepted > 0 {
            c.accepted.fetch_add(self.local_accepted, Ordering::Relaxed);
            self.local_accepted = 0;
        }
        if self.local_rejected > 0 {
            c.rejected.fetch_add(self.local_rejected, Ordering::Relaxed);
            self.local_rejected = 0;
        }
        c.active.store(self.slab.len() as u64, Ordering::Relaxed);
        c.peak_active
            .fetch_max(self.local_peak_active, Ordering::Relaxed);
        c.peak_buffers_used
            .fetch_max(self.local_peak_bufs, Ordering::Relaxed);
        if self.local_bytes_c2b > 0 {
            c.bytes_c2b
                .fetch_add(self.local_bytes_c2b, Ordering::Relaxed);
            self.local_bytes_c2b = 0;
        }
        if self.local_bytes_b2c > 0 {
            c.bytes_b2c
                .fetch_add(self.local_bytes_b2c, Ordering::Relaxed);
            self.local_bytes_b2c = 0;
        }
        if self.local_poll_calls > 0 {
            c.poll_calls
                .fetch_add(self.local_poll_calls, Ordering::Relaxed);
            self.local_poll_calls = 0;
        }
        if self.local_poll_events > 0 {
            c.poll_events
                .fetch_add(self.local_poll_events, Ordering::Relaxed);
            self.local_poll_events = 0;
        }
        if self.local_read_calls > 0 {
            c.read_calls
                .fetch_add(self.local_read_calls, Ordering::Relaxed);
            self.local_read_calls = 0;
        }
        if self.local_write_calls > 0 {
            c.write_calls
                .fetch_add(self.local_write_calls, Ordering::Relaxed);
            self.local_write_calls = 0;
        }
        if self.local_fast_writes > 0 {
            c.fast_path_writes
                .fetch_add(self.local_fast_writes, Ordering::Relaxed);
            self.local_fast_writes = 0;
        }
        if self.local_buf_writes > 0 {
            c.buffered_writes
                .fetch_add(self.local_buf_writes, Ordering::Relaxed);
            self.local_buf_writes = 0;
        }
        c.worker_cpu_ns
            .store(sys::thread_cpu_time_ns(), Ordering::Relaxed);
    }

    fn run(&mut self, stop: Arc<AtomicBool>) {
        let mut events = Vec::with_capacity(512);
        let mut deferred_elephants = Vec::with_capacity(64);
        let mut accept_buf = [AcceptedFd {
            fd: -1,
            peer: EndpointV4::default(),
        }; 64];
        let busy_poll_ns = self.cfg.busy_poll_us.saturating_mul(1_000);
        let idle_timeout_ns = self.cfg.idle_timeout_secs.saturating_mul(1_000_000_000);
        let mut last_work_ns = sys::fast_now_ns();
        let mut last_reap_ns = last_work_ns;
        let mut spin_backoff_ns: u64 = 2_000;
        let mut loop_iters: u64 = 0;

        while !stop.load(Ordering::Relaxed) {
            loop_iters = loop_iters.wrapping_add(1);
            let mut accepted_now = false;

            // 1. Drain lock-free SPSC accept ring in userspace first (0 syscalls!)
            if let Some(ref mut rx) = self.accept_rx {
                let n = rx.pop_batch(&mut accept_buf);
                if n > 0 {
                    accepted_now = true;
                    let now = sys::fast_now_ns();
                    for item in &accept_buf[..n] {
                        self.admit_connection(item.fd, item.peer, now);
                    }
                }
            }

            // 2. Adaptive hybrid busy-poll vs kernel park
            let now = sys::fast_now_ns();
            let in_busy_window =
                busy_poll_ns > 0 && now.wrapping_sub(last_work_ns) < busy_poll_ns;

            let timeout_ns = if accepted_now || in_busy_window {
                Some(0)
            } else {
                // Classic store-load barrier before blocking to guarantee zero lost wakeups
                self.sleeping.store(true, Ordering::SeqCst);
                let has_pending_accept = self
                    .accept_rx
                    .as_mut()
                    .map(|rx| !rx.is_empty())
                    .unwrap_or(false);
                if has_pending_accept {
                    self.sleeping.store(false, Ordering::Release);
                    Some(0)
                } else {
                    self.flush_counters();
                    Some(15_000_000) // 15 ms idle sleep
                }
            };

            self.local_poll_calls += 1;
            let n = match self.poller.poll(&mut events, timeout_ns) {
                Ok(n) => n,
                Err(_) => 0,
            };
            if timeout_ns != Some(0) {
                self.sleeping.store(false, Ordering::Release);
            }

            let mut did_work = accepted_now;
            if n > 0 {
                did_work = true;
                self.local_poll_events += n as u64;
                let ev_now = sys::fast_now_ns();
                if self.cfg.mouse_first_scheduling && events.len() > 1 {
                    // Two-Tier Tail-Latency Scheduler:
                    // Pass 1: Dispatch Mouse RPC / control / accept events immediately!
                    // Pass 2: Dispatch Elephant bulk streams afterward with bounded turn budget!
                    deferred_elephants.clear();
                    for i in 0..events.len() {
                        let ev = events[i];
                        if ev.is_user {
                            continue;
                        }
                        if ev.token == LISTEN_TOKEN {
                            self.accept_from_listener(ev_now);
                            continue;
                        }
                        let (slot, _, gen) = decode_token(ev.token);
                        let is_elephant = self
                            .slab
                            .get(slot)
                            .map(|c| c.generation == gen && c.ewma_turn_bytes >= 8192)
                            .unwrap_or(false);
                        if is_elephant {
                            deferred_elephants.push(ev);
                        } else {
                            self.handle_conn_event(ev, ev_now);
                        }
                    }
                    for i in 0..deferred_elephants.len() {
                        self.handle_conn_event(deferred_elephants[i], ev_now);
                    }
                } else {
                    for i in 0..events.len() {
                        let ev = events[i];
                        if ev.is_user {
                            continue;
                        }
                        if ev.token == LISTEN_TOKEN {
                            self.accept_from_listener(ev_now);
                            continue;
                        }
                        self.handle_conn_event(ev, ev_now);
                    }
                }
            }

            if did_work {
                last_work_ns = sys::fast_now_ns();
                spin_backoff_ns = 2_000;
            } else if in_busy_window {
                // Exponential userspace spin backoff (2us -> 4us -> 8us -> 16us) checking the
                // lock-free SPSC ring directly: keeps sub-ms tail latency while minimizing
                // empty kevent(timeout=0) kernel mode switches!
                let spin_until = sys::fast_now_ns() + spin_backoff_ns;
                while sys::fast_now_ns() < spin_until {
                    if let Some(ref mut rx) = self.accept_rx {
                        if !rx.is_empty() {
                            break;
                        }
                    }
                    sys::cpu_relax();
                }
                spin_backoff_ns = (spin_backoff_ns << 1).min(16_000);
            }

            if (loop_iters & 0x3f) == 0 {
                self.flush_counters();
                if idle_timeout_ns > 0 {
                    let t = sys::fast_now_ns();
                    if t.wrapping_sub(last_reap_ns) >= 2_000_000_000 {
                        last_reap_ns = t;
                        self.reap_idle_connections(t, idle_timeout_ns);
                    }
                }
            }
        }

        // Clean shutdown: close all active connections & listener
        let mut to_close = Vec::new();
        self.slab.for_each_occupied(|idx, _| to_close.push(idx));
        for idx in to_close {
            self.close_conn(idx);
        }
        if let Some(lfd) = self.listen_fd.take() {
            sys::close_fd(lfd);
        }
        self.flush_counters();
    }

    fn accept_from_listener(&mut self, now_ns: u64) {
        let Some(lfd) = self.listen_fd else {
            return;
        };
        #[cfg(target_os = "macos")]
        let ensure_opts = false;
        #[cfg(not(target_os = "macos"))]
        let ensure_opts = true;

        for _ in 0..ACCEPT_BATCH {
            match sys::accept_nonblock(lfd, ensure_opts) {
                Ok(Some((fd, peer))) => self.admit_connection(fd, peer, now_ns),
                _ => break,
            }
        }
    }

    fn admit_connection(&mut self, client_fd: Fd, peer: EndpointV4, now_ns: u64) {
        if self.slab.is_full() {
            sys::close_fd(client_fd);
            self.local_rejected += 1;
            return;
        }
        let flow_hash = hash_endpoint(peer);
        let Some((backend_idx, backend_ep)) = self.selector.select(flow_hash) else {
            sys::close_fd(client_fd);
            self.local_rejected += 1;
            return;
        };

        let (backend_fd, immediate) = match sys::connect_nonblock(backend_ep, self.cfg.sock_buf_bytes)
        {
            Ok(v) => v,
            Err(_) => {
                self.selector.pool().record_failure(backend_idx as usize);
                sys::close_fd(client_fd);
                self.local_rejected += 1;
                return;
            }
        };

        self.next_gen = self.next_gen.wrapping_add(1) & 0x7fff_ffff;
        if self.next_gen == 0 {
            self.next_gen = 1;
        }
        let gen = self.next_gen;

        let state = if immediate {
            ConnState::Established
        } else {
            ConnState::ConnectingBackend
        };

        let conn = TcpConn {
            client_fd,
            backend_fd,
            generation: gen,
            backend_idx,
            state,
            flags: if immediate { 0 } else { F_BACKEND_WR_ARMED },
            ewma_turn_bytes: 0,
            connect_start_ns: now_ns,
            last_active_ns: now_ns,
            c2b: PooledRing::empty(),
            b2c: PooledRing::empty(),
        };

        let Some(slot) = self.slab.insert(conn) else {
            sys::close_fd(client_fd);
            sys::close_fd(backend_fd);
            self.local_rejected += 1;
            return;
        };

        self.selector.pool().on_conn_open(backend_idx as usize);
        self.local_accepted += 1;
        let active = self.slab.len() as u64;
        if active > self.local_peak_active {
            self.local_peak_active = active;
        }

        let c_tok = encode_token(slot, false, gen);
        let b_tok = encode_token(slot, true, gen);

        if immediate {
            self.selector
                .pool()
                .record_connect_latency(backend_idx as usize, 1000);
            // Both sockets ready immediately -> register reads in batched changelist (0 syscalls now!)
            self.poller.add_read(client_fd, c_tok, false);
            self.poller.add_read(backend_fd, b_tok, false);
        } else {
            // Wait for async backend connect completion; also register client read only once connected
            // (keeps early client bytes safely buffered in kernel recvbuf without leasing userspace RAM!)
            self.poller.add_connect_write(backend_fd, b_tok);
        }
    }

    #[inline]
    fn handle_conn_event(&mut self, ev: PollEvent, now_ns: u64) {
        let (slot, is_backend, gen) = decode_token(ev.token);
        let (state, client_fd, backend_fd, backend_idx, conn_gen, connect_start_ns) =
            match self.slab.get_mut(slot) {
                Some(c) if c.generation == gen => {
                    c.last_active_ns = now_ns;
                    (
                        c.state,
                        c.client_fd,
                        c.backend_fd,
                        c.backend_idx,
                        c.generation,
                        c.connect_start_ns,
                    )
                }
                _ => return, // Stale event for already-closed/recycled slot
            };

        if ev.error {
            if state == ConnState::ConnectingBackend {
                self.selector.pool().record_failure(backend_idx as usize);
            }
            self.close_conn(slot);
            return;
        }

        // Complete non-blocking backend TCP handshake
        if state == ConnState::ConnectingBackend {
            if !is_backend {
                return;
            }
            match sys::get_socket_error(backend_fd) {
                Ok(0) => {
                    let lat = now_ns.saturating_sub(connect_start_ns);
                    self.selector
                        .pool()
                        .record_connect_latency(backend_idx as usize, lat);
                    if let Some(c) = self.slab.get_mut(slot) {
                        c.state = ConnState::Established;
                        c.flags &= !F_BACKEND_WR_ARMED;
                    }
                    let c_tok = encode_token(slot, false, conn_gen);
                    let b_tok = encode_token(slot, true, conn_gen);
                    self.poller.add_read(client_fd, c_tok, false);
                    self.poller.add_read(backend_fd, b_tok, false);
                    // Opportunistically pump any initial client bytes already waiting!
                    if !self.pump_direction(slot, false) {
                        self.close_conn(slot);
                    }
                }
                _ => {
                    self.selector.pool().record_failure(backend_idx as usize);
                    self.close_conn(slot);
                }
            }
            return;
        }

        // Writable event: flush buffered backpressure ring
        if ev.writable {
            if !self.flush_pending_writes(slot, is_backend) {
                self.close_conn(slot);
                return;
            }
        }

        // Readable event: bufferless fast-path pump with fair work-budgeting
        if ev.readable || ev.eof {
            if !self.pump_direction(slot, is_backend) {
                self.close_conn(slot);
                return;
            }
        }

        // Final check: tear down if both directions finished cleanly
        if let Some(c) = self.slab.get(slot) {
            if (c.flags & F_CLIENT_EOF) != 0
                && (c.flags & F_BACKEND_EOF) != 0
                && c.c2b.is_empty()
                && c.b2c.is_empty()
            {
                self.close_conn(slot);
            }
        }
    }

    /// Flush pending ring buffer to `dst` (`dst_is_backend == true` means flushing `c2b` -> `backend_fd`).
    /// Returns `false` if connection encountered a fatal error and must be closed.
    fn flush_pending_writes(&mut self, slot: u32, dst_is_backend: bool) -> bool {
        let Some(c) = self.slab.get_mut(slot) else {
            return false;
        };
        let gen = c.generation;
        let (src_fd, dst_fd) = if dst_is_backend {
            c.flags &= !F_BACKEND_WR_ARMED;
            (c.client_fd, c.backend_fd)
        } else {
            c.flags &= !F_CLIENT_WR_ARMED;
            (c.backend_fd, c.client_fd)
        };

        let mut drained_bytes = 0usize;
        loop {
            let ring = if dst_is_backend { &c.c2b } else { &c.b2c };
            if ring.is_empty() {
                break;
            }
            let (s1, s2) = ring.readable_slices(&self.buf_pool);
            self.local_write_calls += 1;
            match sys::writev2_nb(dst_fd, s1, s2) {
                IoStatus::Ok(0) | IoStatus::WouldBlock => {
                    // Still backpressured -> re-arm one-shot write
                    let dst_tok = encode_token(slot, dst_is_backend, gen);
                    self.poller.arm_write_oneshot(dst_fd, dst_tok);
                    if dst_is_backend {
                        c.flags |= F_BACKEND_WR_ARMED;
                    } else {
                        c.flags |= F_CLIENT_WR_ARMED;
                    }
                    break;
                }
                IoStatus::Ok(n) => {
                    drained_bytes += n;
                    let ring_mut = if dst_is_backend {
                        &mut c.c2b
                    } else {
                        &mut c.b2c
                    };
                    ring_mut.consume(&mut self.buf_pool, n);
                    if drained_bytes >= self.cfg.work_budget_bytes {
                        if !ring_mut.is_empty() {
                            let dst_tok = encode_token(slot, dst_is_backend, gen);
                            self.poller.arm_write_oneshot(dst_fd, dst_tok);
                            if dst_is_backend {
                                c.flags |= F_BACKEND_WR_ARMED;
                            } else {
                                c.flags |= F_CLIENT_WR_ARMED;
                            }
                        }
                        break;
                    }
                }
                IoStatus::Eof | IoStatus::Error(_) => return false,
            }
        }

        if drained_bytes > 0 {
            if dst_is_backend {
                self.local_bytes_c2b += drained_bytes as u64;
            } else {
                self.local_bytes_b2c += drained_bytes as u64;
            }
        }

        // If source read was paused due to backpressure and buffer now has headroom, resume it!
        let ring = if dst_is_backend { &c.c2b } else { &c.b2c };
        let src_paused_flag = if dst_is_backend {
            F_CLIENT_RD_PAUSED
        } else {
            F_BACKEND_RD_PAUSED
        };
        if (c.flags & src_paused_flag) != 0
            && ring.free_space(&self.buf_pool) >= (self.buf_pool.chunk_size() >> 1)
        {
            c.flags &= !src_paused_flag;
            let src_tok = encode_token(slot, !dst_is_backend, gen);
            self.poller.enable_read(src_fd, src_tok);
        }

        // Propagate half-close once ring finishes draining
        let src_eof_flag = if dst_is_backend {
            F_CLIENT_EOF
        } else {
            F_BACKEND_EOF
        };
        let dst_shut_flag = if dst_is_backend {
            F_BACKEND_SHUT_WR
        } else {
            F_CLIENT_SHUT_WR
        };
        if ring.is_empty() && (c.flags & src_eof_flag) != 0 && (c.flags & dst_shut_flag) == 0 {
            c.flags |= dst_shut_flag;
            sys::shutdown_write(dst_fd);
        }

        true
    }

    /// Bufferless L1-hot fast-path pump with fair work-budgeting.
    /// `src_is_backend == false` pumps Client -> Backend; `true` pumps Backend -> Client.
    fn pump_direction(&mut self, slot: u32, src_is_backend: bool) -> bool {
        let (gen, src_fd, dst_fd) = match self.slab.get(slot) {
            Some(c) => {
                let (s, d) = if src_is_backend {
                    (c.backend_fd, c.client_fd)
                } else {
                    (c.client_fd, c.backend_fd)
                };
                (c.generation, s, d)
            }
            None => return false,
        };
        let dst_is_backend = !src_is_backend;
        let budget = self.cfg.work_budget_bytes;
        let mut moved = 0usize;

        while moved < budget {
            let (ring_empty, free_space) = match self.slab.get(slot) {
                Some(c) => {
                    let ring = if dst_is_backend { &c.c2b } else { &c.b2c };
                    (ring.is_empty(), ring.free_space(&self.buf_pool))
                }
                None => return false,
            };

            if ring_empty {
                // === BUFFERLESS FAST PATH: read into L1-hot scratch -> immediate write ===
                // Clamp read chunk to `buf_pool.chunk_size()` so any partial/WouldBlock write
                // is guaranteed to fit inside a single lazily-leased PooledRing chunk!
                let chunk = (budget - moved)
                    .min(self.scratch.len())
                    .min(self.buf_pool.chunk_size());
                self.local_read_calls += 1;
                match sys::read_nb(src_fd, &mut self.scratch[..chunk]) {
                    IoStatus::Ok(n) => {
                        self.local_write_calls += 1;
                        match sys::write_nb(dst_fd, &self.scratch[..n]) {
                            IoStatus::Ok(w) if w == n => {
                                self.local_fast_writes += 1;
                                moved += n;
                                if dst_is_backend {
                                    self.local_bytes_c2b += n as u64;
                                } else {
                                    self.local_bytes_b2c += n as u64;
                                }
                                // Mode-switch optimization: short read means kernel recvbuf is
                                // drained for this RPC — avoid redundant EAGAIN read() syscall!
                                if n < chunk {
                                    break;
                                }
                            }
                            IoStatus::Ok(w) => {
                                // Partial write -> lease pooled ring chunk for remainder
                                if dst_is_backend {
                                    self.local_bytes_c2b += w as u64;
                                } else {
                                    self.local_bytes_b2c += w as u64;
                                }
                                if !self.enqueue_backpressure_from_scratch(
                                    slot,
                                    dst_is_backend,
                                    w,
                                    n,
                                    src_fd,
                                    dst_fd,
                                    gen,
                                ) {
                                    return false;
                                }
                                break;
                            }
                            IoStatus::WouldBlock => {
                                if !self.enqueue_backpressure_from_scratch(
                                    slot,
                                    dst_is_backend,
                                    0,
                                    n,
                                    src_fd,
                                    dst_fd,
                                    gen,
                                ) {
                                    return false;
                                }
                                break;
                            }
                            IoStatus::Eof | IoStatus::Error(_) => return false,
                        }
                    }
                    IoStatus::WouldBlock => break,
                    IoStatus::Eof => {
                        self.handle_src_eof(slot, src_is_backend, dst_fd);
                        break;
                    }
                    IoStatus::Error(_) => return false,
                }
            } else {
                // Destination currently backpressured: buffer up to ring free space
                if free_space == 0 {
                    // Pause reading from src until dst drains to prevent busy-spin
                    let pause_flag = if src_is_backend {
                        F_BACKEND_RD_PAUSED
                    } else {
                        F_CLIENT_RD_PAUSED
                    };
                    if let Some(c) = self.slab.get_mut(slot) {
                        if (c.flags & pause_flag) == 0 {
                            c.flags |= pause_flag;
                            self.poller.disable_read(src_fd);
                        }
                    }
                    break;
                }
                let chunk = free_space.min(budget - moved).min(self.scratch.len());
                self.local_read_calls += 1;
                match sys::read_nb(src_fd, &mut self.scratch[..chunk]) {
                    IoStatus::Ok(n) => {
                        if !self.enqueue_backpressure_from_scratch(
                            slot,
                            dst_is_backend,
                            0,
                            n,
                            src_fd,
                            dst_fd,
                            gen,
                        ) {
                            return false;
                        }
                        moved += n;
                        if n < chunk {
                            break;
                        }
                    }
                    IoStatus::WouldBlock => break,
                    IoStatus::Eof => {
                        self.handle_src_eof(slot, src_is_backend, dst_fd);
                        break;
                    }
                    IoStatus::Error(_) => return false,
                }
            }
        }
        // Update EWMA bytes moved per turn (alpha = 1/4) for Mouse vs Elephant classification
        if moved > 0 {
            if let Some(c) = self.slab.get_mut(slot) {
                let prev = c.ewma_turn_bytes as u64;
                c.ewma_turn_bytes = (((prev * 3) + moved as u64) >> 2).min(u32::MAX as u64) as u32;
            }
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn enqueue_backpressure_from_scratch(
        &mut self,
        slot: u32,
        dst_is_backend: bool,
        start: usize,
        end: usize,
        src_fd: Fd,
        dst_fd: Fd,
        gen: u32,
    ) -> bool {
        let Some(c) = self.slab.get_mut(slot) else {
            return false;
        };
        let data = &self.scratch[start..end];
        let ring = if dst_is_backend {
            &mut c.c2b
        } else {
            &mut c.b2c
        };
        let pushed = ring.push_bytes(&mut self.buf_pool, data);
        if pushed < data.len() {
            // Buffer pool exhausted under extreme slow-backend attack: drop connection cleanly
            return false;
        }
        self.local_buf_writes += 1;
        let used = self.buf_pool.in_use() as u64;
        if used > self.local_peak_bufs {
            self.local_peak_bufs = used;
        }

        let wr_flag = if dst_is_backend {
            F_BACKEND_WR_ARMED
        } else {
            F_CLIENT_WR_ARMED
        };
        if (c.flags & wr_flag) == 0 {
            c.flags |= wr_flag;
            let dst_tok = encode_token(slot, dst_is_backend, gen);
            self.poller.arm_write_oneshot(dst_fd, dst_tok);
        }

        if ring.free_space(&self.buf_pool) < 4096 {
            let pause_flag = if dst_is_backend {
                F_CLIENT_RD_PAUSED
            } else {
                F_BACKEND_RD_PAUSED
            };
            if (c.flags & pause_flag) == 0 {
                c.flags |= pause_flag;
                self.poller.disable_read(src_fd);
            }
        }
        true
    }

    fn handle_src_eof(&mut self, slot: u32, src_is_backend: bool, dst_fd: Fd) {
        let Some(c) = self.slab.get_mut(slot) else {
            return;
        };
        let (eof_flag, shut_flag, src_fd, ring_empty) = if src_is_backend {
            (F_BACKEND_EOF, F_CLIENT_SHUT_WR, c.backend_fd, c.b2c.is_empty())
        } else {
            (F_CLIENT_EOF, F_BACKEND_SHUT_WR, c.client_fd, c.c2b.is_empty())
        };
        c.flags |= eof_flag;
        // Disable read on EOF fd so level-triggered poller stops reporting EOF
        self.poller.disable_read(src_fd);
        if ring_empty && (c.flags & shut_flag) == 0 {
            c.flags |= shut_flag;
            sys::shutdown_write(dst_fd);
        }
    }

    fn close_conn(&mut self, slot: u32) {
        if let Some(mut c) = self.slab.remove(slot) {
            c.c2b.release_if_held(&mut self.buf_pool);
            c.b2c.release_if_held(&mut self.buf_pool);
            sys::close_fd(c.client_fd);
            sys::close_fd(c.backend_fd);
            self.selector.pool().on_conn_close(c.backend_idx as usize);
        }
    }

    fn reap_idle_connections(&mut self, now_ns: u64, timeout_ns: u64) {
        let mut expired = Vec::new();
        self.slab.for_each_occupied(|idx, c| {
            if now_ns.wrapping_sub(c.last_active_ns) >= timeout_ns {
                expired.push(idx);
            }
        });
        for idx in expired {
            self.close_conn(idx);
        }
    }
}
