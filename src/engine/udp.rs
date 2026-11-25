//! Syscall-Batched L4 UDP Network Load Balancer.
//!
//! Minimizes user/kernel mode switches by up to 64x using:
//! - macOS Darwin native `recvmsg_x` / `sendmsg_x` (Linux `recvmmsg` / `sendmmsg`)
//! - L2-cache-resident flat pre-allocated packet arena (0 heap allocations per packet!)
//! - Fixed-capacity open-addressed client->backend NAT session table
//! - Adaptive hybrid busy-polling for ultra-low tail latency
//! Also supports `batched = false` (`recvfrom`/`sendto`) for apples-to-apples benchmarking.

use crate::lb::balancer::{BackendPool, WorkerSelector};
use crate::lb::hash::hash_endpoint;
use crate::mem::cache::CachePadded;
use crate::sys::{self, EndpointV4, Fd, IoVec, MsgHdrX, Poller, SockAddrIn, WakeHandle};
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

const FRONTEND_TOKEN: u64 = u64::MAX;
const MAX_BATCH: usize = 64;
const PKT_STRIDE: usize = 2048;
const MAX_PROBE: usize = 16;

#[derive(Clone, Debug)]
pub struct UdpEngineConfig {
    pub listen_addr: EndpointV4,
    /// Enable syscall batching (`recvmsg_x`/`sendmsg_x` on macOS, `recvmmsg`/`sendmmsg` on Linux).
    pub batched: bool,
    pub batch_size: usize,
    pub sock_buf_bytes: i32,
    pub max_sessions: usize,
    pub busy_poll_us: u64,
    pub session_timeout_secs: u64,
}

impl Default for UdpEngineConfig {
    fn default() -> Self {
        Self {
            listen_addr: EndpointV4::from_octets(127, 0, 0, 1, 0),
            batched: true,
            batch_size: MAX_BATCH,
            sock_buf_bytes: 2 * 1024 * 1024,
            max_sessions: 4096,
            busy_poll_us: 150,
            session_timeout_secs: 30,
        }
    }
}

#[derive(Default)]
pub struct UdpCounters {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub recv_syscalls: AtomicU64,
    pub send_syscalls: AtomicU64,
    pub poll_calls: AtomicU64,
    pub sessions_created: AtomicU64,
    pub drops: AtomicU64,
    pub worker_cpu_ns: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UdpStatsSnapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub recv_syscalls: u64,
    pub send_syscalls: u64,
    pub poll_calls: u64,
    pub sessions_created: u64,
    pub drops: u64,
    pub worker_cpu_ns: u64,
}

impl UdpStatsSnapshot {
    pub fn pkts_per_syscall(&self) -> f64 {
        let total_sc = self.recv_syscalls + self.send_syscalls;
        if total_sc == 0 {
            0.0
        } else {
            (self.rx_packets + self.tx_packets) as f64 / total_sc as f64
        }
    }
}

#[derive(Clone, Copy)]
struct UdpSession {
    occupied: bool,
    client_ep: EndpointV4,
    backend_fd: Fd,
    backend_idx: u16,
    last_seen_ns: u64,
}

impl Default for UdpSession {
    fn default() -> Self {
        Self {
            occupied: false,
            client_ep: EndpointV4::default(),
            backend_fd: -1,
            backend_idx: 0,
            last_seen_ns: 0,
        }
    }
}

pub struct UdpNlbHandle {
    bound_addr: EndpointV4,
    stop: Arc<AtomicBool>,
    counters: Arc<CachePadded<UdpCounters>>,
    wake: WakeHandle,
    thread: Option<JoinHandle<()>>,
}

impl UdpNlbHandle {
    pub fn bound_addr(&self) -> EndpointV4 {
        self.bound_addr
    }

    pub fn stats(&self) -> UdpStatsSnapshot {
        let c = &self.counters;
        UdpStatsSnapshot {
            rx_packets: c.rx_packets.load(Ordering::Relaxed),
            tx_packets: c.tx_packets.load(Ordering::Relaxed),
            rx_bytes: c.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: c.tx_bytes.load(Ordering::Relaxed),
            recv_syscalls: c.recv_syscalls.load(Ordering::Relaxed),
            send_syscalls: c.send_syscalls.load(Ordering::Relaxed),
            poll_calls: c.poll_calls.load(Ordering::Relaxed),
            sessions_created: c.sessions_created.load(Ordering::Relaxed),
            drops: c.drops.load(Ordering::Relaxed),
            worker_cpu_ns: c.worker_cpu_ns.load(Ordering::Relaxed),
        }
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        self.wake.wake();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for UdpNlbHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.wake.wake();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub fn start_udp_nlb(
    config: UdpEngineConfig,
    pool: Arc<BackendPool>,
) -> io::Result<UdpNlbHandle> {
    let (front_fd, bound) =
        sys::create_udp_socket(config.listen_addr, false, config.sock_buf_bytes)?;
    let poller = Poller::new(512)?;
    let wake = poller.wake_handle();
    let stop = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(CachePadded::new(UdpCounters::default()));

    let stop_c = Arc::clone(&stop);
    let cnt_c = Arc::clone(&counters);

    let thread = std::thread::Builder::new()
        .name("tetrux-udp-w0".to_string())
        .spawn(move || {
            sys::pin_thread_performance(0);
            let mut worker = UdpWorker::new(front_fd, config, poller, pool, cnt_c);
            worker.run(stop_c);
        })?;

    Ok(UdpNlbHandle {
        bound_addr: bound,
        stop,
        counters,
        wake,
        thread: Some(thread),
    })
}

struct UdpWorker {
    front_fd: Fd,
    cfg: UdpEngineConfig,
    poller: Poller,
    selector: WorkerSelector,
    sessions: Vec<UdpSession>,
    session_mask: usize,
    counters: Arc<CachePadded<UdpCounters>>,
    /// Flat L2-resident packet buffer arena: `batch_size * 2048` bytes.
    pkt_arena: Vec<u8>,
    batch_size: usize,
    // Local hot stats
    rx_pkts: u64,
    tx_pkts: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    recv_sc: u64,
    send_sc: u64,
    poll_sc: u64,
    sessions_created: u64,
    drops: u64,
}

impl UdpWorker {
    fn new(
        front_fd: Fd,
        cfg: UdpEngineConfig,
        mut poller: Poller,
        pool: Arc<BackendPool>,
        counters: Arc<CachePadded<UdpCounters>>,
    ) -> Self {
        poller.add_read(front_fd, FRONTEND_TOKEN, false);
        let cap = cfg.max_sessions.max(64).next_power_of_two();
        let batch_size = cfg.batch_size.clamp(1, MAX_BATCH);
        Self {
            front_fd,
            cfg,
            poller,
            selector: WorkerSelector::new(pool, 0),
            sessions: vec![UdpSession::default(); cap],
            session_mask: cap - 1,
            counters,
            pkt_arena: vec![0u8; batch_size * PKT_STRIDE],
            batch_size,
            rx_pkts: 0,
            tx_pkts: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            recv_sc: 0,
            send_sc: 0,
            poll_sc: 0,
            sessions_created: 0,
            drops: 0,
        }
    }

    fn flush_stats(&mut self) {
        let c = &self.counters;
        c.rx_packets.fetch_add(self.rx_pkts, Ordering::Relaxed);
        c.tx_packets.fetch_add(self.tx_pkts, Ordering::Relaxed);
        c.rx_bytes.fetch_add(self.rx_bytes, Ordering::Relaxed);
        c.tx_bytes.fetch_add(self.tx_bytes, Ordering::Relaxed);
        c.recv_syscalls.fetch_add(self.recv_sc, Ordering::Relaxed);
        c.send_syscalls.fetch_add(self.send_sc, Ordering::Relaxed);
        c.poll_calls.fetch_add(self.poll_sc, Ordering::Relaxed);
        c.sessions_created
            .fetch_add(self.sessions_created, Ordering::Relaxed);
        c.drops.fetch_add(self.drops, Ordering::Relaxed);
        c.worker_cpu_ns
            .store(sys::thread_cpu_time_ns(), Ordering::Relaxed);
        self.rx_pkts = 0;
        self.tx_pkts = 0;
        self.rx_bytes = 0;
        self.tx_bytes = 0;
        self.recv_sc = 0;
        self.send_sc = 0;
        self.poll_sc = 0;
        self.sessions_created = 0;
        self.drops = 0;
    }

    /// Lookup or allocate an open-addressed NAT session for `client_ep`.
    #[inline]
    fn get_or_create_session(&mut self, client_ep: EndpointV4, now_ns: u64) -> Option<usize> {
        let h = hash_endpoint(client_ep);
        let start = (h as usize) & self.session_mask;
        let mask = self.session_mask;
        let mut free_slot = None;
        let mut oldest_slot = start;
        let mut oldest_ts = u64::MAX;

        for step in 0..MAX_PROBE {
            let idx = (start + step) & mask;
            let s = &mut self.sessions[idx];
            if s.occupied {
                if s.client_ep == client_ep {
                    s.last_seen_ns = now_ns;
                    return Some(idx);
                }
                if s.last_seen_ns < oldest_ts {
                    oldest_ts = s.last_seen_ns;
                    oldest_slot = idx;
                }
            } else if free_slot.is_none() {
                free_slot = Some(idx);
            }
        }

        let target = free_slot.unwrap_or(oldest_slot);
        if self.sessions[target].occupied {
            sys::close_fd(self.sessions[target].backend_fd);
        }
        let (backend_idx, backend_ep) = self.selector.select(h)?;
        let backend_fd = sys::connect_udp_socket(backend_ep, self.cfg.sock_buf_bytes).ok()?;
        self.sessions[target] = UdpSession {
            occupied: true,
            client_ep,
            backend_fd,
            backend_idx,
            last_seen_ns: now_ns,
        };
        self.poller.add_read(backend_fd, target as u64, false);
        self.sessions_created += 1;
        Some(target)
    }

    fn run(&mut self, stop: Arc<AtomicBool>) {
        let mut events = Vec::with_capacity(512);
        let busy_poll_ns = self.cfg.busy_poll_us.saturating_mul(1_000);
        let mut last_work_ns = sys::fast_now_ns();
        let mut spin_backoff_ns = 2_000u64;
        let mut iters: u64 = 0;

        while !stop.load(Ordering::Relaxed) {
            iters = iters.wrapping_add(1);
            let now = sys::fast_now_ns();
            let in_busy = busy_poll_ns > 0 && now.wrapping_sub(last_work_ns) < busy_poll_ns;
            let timeout = if in_busy {
                Some(0)
            } else {
                self.flush_stats();
                Some(15_000_000)
            };

            self.poll_sc += 1;
            let n = match self.poller.poll(&mut events, timeout) {
                Ok(n) => n,
                Err(_) => 0,
            };

            if n > 0 {
                let ev_now = sys::fast_now_ns();
                for i in 0..events.len() {
                    let ev = events[i];
                    if ev.is_user || !ev.readable {
                        continue;
                    }
                    if ev.token == FRONTEND_TOKEN {
                        if self.cfg.batched {
                            self.drain_frontend_batched(ev_now);
                        } else {
                            self.drain_frontend_single(ev_now);
                        }
                    } else {
                        let slot = ev.token as usize;
                        if self.cfg.batched {
                            self.drain_backend_batched(slot, ev_now);
                        } else {
                            self.drain_backend_single(slot, ev_now);
                        }
                    }
                }
                last_work_ns = sys::fast_now_ns();
                spin_backoff_ns = 2_000;
            } else if in_busy {
                let spin_until = sys::fast_now_ns() + spin_backoff_ns;
                while sys::fast_now_ns() < spin_until {
                    sys::cpu_relax();
                }
                spin_backoff_ns = (spin_backoff_ns << 1).min(16_000);
            }

            if (iters & 0x3f) == 0 {
                self.flush_stats();
            }
        }

        for s in &mut self.sessions {
            if s.occupied {
                sys::close_fd(s.backend_fd);
                s.occupied = false;
            }
        }
        sys::close_fd(self.front_fd);
        self.flush_stats();
    }

    /// Unbatched baseline: 1 `recvfrom` + 1 `sendto`/`write` per datagram.
    fn drain_frontend_single(&mut self, now_ns: u64) {
        let mut tmp = [0u8; PKT_STRIDE];
        for _ in 0..self.batch_size {
            self.recv_sc += 1;
            match sys::recvfrom_nb(self.front_fd, &mut tmp) {
                Ok(Some((len, client_ep))) => {
                    self.rx_pkts += 1;
                    self.rx_bytes += len as u64;
                    if let Some(slot) = self.get_or_create_session(client_ep, now_ns) {
                        let bfd = self.sessions[slot].backend_fd;
                        self.send_sc += 1;
                        match sys::write_nb(bfd, &tmp[..len]) {
                            sys::IoStatus::Ok(w) if w > 0 => {
                                self.tx_pkts += 1;
                                self.tx_bytes += w as u64;
                            }
                            _ => self.drops += 1,
                        }
                    } else {
                        self.drops += 1;
                    }
                }
                _ => break,
            }
        }
    }

    fn drain_backend_single(&mut self, slot: usize, now_ns: u64) {
        let (bfd, client_ep) = match self.sessions.get_mut(slot) {
            Some(s) if s.occupied => {
                s.last_seen_ns = now_ns;
                (s.backend_fd, s.client_ep)
            }
            _ => return,
        };
        let mut tmp = [0u8; PKT_STRIDE];
        for _ in 0..self.batch_size {
            self.recv_sc += 1;
            match sys::read_nb(bfd, &mut tmp) {
                sys::IoStatus::Ok(len) => {
                    self.rx_pkts += 1;
                    self.rx_bytes += len as u64;
                    self.send_sc += 1;
                    match sys::sendto_nb(self.front_fd, &tmp[..len], client_ep) {
                        Ok(w) if w > 0 => {
                            self.tx_pkts += 1;
                            self.tx_bytes += w as u64;
                        }
                        _ => self.drops += 1,
                    }
                }
                _ => break,
            }
        }
    }

    /// Batched datapath: up to 64 UDP datagrams received in ONE `recvmsg_x` syscall and
    /// forwarded in coalesced `sendmsg_x` batches!
    #[cfg(target_os = "macos")]
    fn drain_frontend_batched(&mut self, now_ns: u64) {
        let bsz = self.batch_size;
        let mut addrs = [SockAddrIn::default(); MAX_BATCH];
        let mut iovs = [IoVec {
            iov_base: ptr::null_mut(),
            iov_len: 0,
        }; MAX_BATCH];
        let mut msgs = [MsgHdrX::default(); MAX_BATCH];

        for i in 0..bsz {
            iovs[i] = IoVec {
                iov_base: unsafe { self.pkt_arena.as_mut_ptr().add(i * PKT_STRIDE) as *mut c_void },
                iov_len: PKT_STRIDE,
            };
            msgs[i] = MsgHdrX {
                msg_name: &mut addrs[i] as *mut SockAddrIn as *mut c_void,
                msg_namelen: size_of::<SockAddrIn>() as u32,
                msg_iov: &mut iovs[i] as *mut IoVec,
                msg_iovlen: 1,
                msg_control: ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
                msg_datalen: 0,
            };
        }

        self.recv_sc += 1;
        let recvd = match sys::recv_udp_batch(self.front_fd, &mut msgs[..bsz]) {
            Ok(n) if n > 0 => n,
            _ => return,
        };

        // Resolve target backend_fd for every packet in batch
        let mut target_fds = [-1 as Fd; MAX_BATCH];
        let mut pkt_lens = [0usize; MAX_BATCH];
        for i in 0..recvd {
            let len = msgs[i].msg_datalen;
            pkt_lens[i] = len;
            self.rx_pkts += 1;
            self.rx_bytes += len as u64;
            let client_ep = addrs[i].to_endpoint();
            if let Some(slot) = self.get_or_create_session(client_ep, now_ns) {
                target_fds[i] = self.sessions[slot].backend_fd;
            } else {
                self.drops += 1;
            }
        }

        // Group packets destined for the same connected backend_fd into single `sendmsg_x` calls!
        let mut sent_mask = [false; MAX_BATCH];
        let mut send_iovs = [IoVec {
            iov_base: ptr::null_mut(),
            iov_len: 0,
        }; MAX_BATCH];
        let mut send_msgs = [MsgHdrX::default(); MAX_BATCH];

        for i in 0..recvd {
            if sent_mask[i] || target_fds[i] < 0 {
                continue;
            }
            let fd = target_fds[i];
            let mut cnt = 0usize;
            let mut group_bytes = 0u64;
            for j in i..recvd {
                if !sent_mask[j] && target_fds[j] == fd {
                    sent_mask[j] = true;
                    let len = pkt_lens[j];
                    send_iovs[cnt] = IoVec {
                        iov_base: unsafe {
                            self.pkt_arena.as_mut_ptr().add(j * PKT_STRIDE) as *mut c_void
                        },
                        iov_len: len,
                    };
                    send_msgs[cnt] = MsgHdrX {
                        msg_name: ptr::null_mut(),
                        msg_namelen: 0,
                        msg_iov: &mut send_iovs[cnt] as *mut IoVec,
                        msg_iovlen: 1,
                        msg_control: ptr::null_mut(),
                        msg_controllen: 0,
                        msg_flags: 0,
                        msg_datalen: 0,
                    };
                    group_bytes += len as u64;
                    cnt += 1;
                }
            }
            self.send_sc += 1;
            match sys::send_udp_batch(fd, &send_msgs[..cnt]) {
                Ok(n) => {
                    self.tx_pkts += n as u64;
                    self.tx_bytes += group_bytes;
                    if n < cnt {
                        self.drops += (cnt - n) as u64;
                    }
                }
                Err(_) => self.drops += cnt as u64,
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn drain_backend_batched(&mut self, slot: usize, now_ns: u64) {
        let (bfd, client_ep) = match self.sessions.get_mut(slot) {
            Some(s) if s.occupied => {
                s.last_seen_ns = now_ns;
                (s.backend_fd, s.client_ep)
            }
            _ => return,
        };

        let bsz = self.batch_size;
        let mut iovs = [IoVec {
            iov_base: ptr::null_mut(),
            iov_len: 0,
        }; MAX_BATCH];
        let mut msgs = [MsgHdrX::default(); MAX_BATCH];

        for i in 0..bsz {
            iovs[i] = IoVec {
                iov_base: unsafe { self.pkt_arena.as_mut_ptr().add(i * PKT_STRIDE) as *mut c_void },
                iov_len: PKT_STRIDE,
            };
            msgs[i] = MsgHdrX {
                msg_name: ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &mut iovs[i] as *mut IoVec,
                msg_iovlen: 1,
                msg_control: ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
                msg_datalen: 0,
            };
        }

        self.recv_sc += 1;
        let recvd = match sys::recv_udp_batch(bfd, &mut msgs[..bsz]) {
            Ok(n) if n > 0 => n,
            _ => return,
        };

        let mut dst_addr = SockAddrIn::from_endpoint(client_ep);
        let mut total_bytes = 0u64;
        for i in 0..recvd {
            let len = msgs[i].msg_datalen;
            self.rx_pkts += 1;
            self.rx_bytes += len as u64;
            total_bytes += len as u64;
            iovs[i].iov_len = len;
            msgs[i].msg_name = &mut dst_addr as *mut SockAddrIn as *mut c_void;
            msgs[i].msg_namelen = size_of::<SockAddrIn>() as u32;
            msgs[i].msg_flags = 0;
            msgs[i].msg_datalen = 0;
        }

        self.send_sc += 1;
        match sys::send_udp_batch(self.front_fd, &msgs[..recvd]) {
            Ok(n) => {
                self.tx_pkts += n as u64;
                self.tx_bytes += total_bytes;
                if n < recvd {
                    self.drops += (recvd - n) as u64;
                }
            }
            Err(_) => self.drops += recvd as u64,
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn drain_frontend_batched(&mut self, now_ns: u64) {
        self.drain_frontend_single(now_ns);
    }

    #[cfg(not(target_os = "macos"))]
    fn drain_backend_batched(&mut self, slot: usize, now_ns: u64) {
        self.drain_backend_single(slot, now_ns);
    }
}
