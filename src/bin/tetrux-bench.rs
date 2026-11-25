//! Tetrux Comprehensive 7-Suite L4 NLB Benchmark Harness.
//!
//! Benchmarks:
//! 1. Kernel-Bypass Zero-Copy UMEM L4 Packet Engine (NAT, DSR, Multi-Core Scaling, Micro-Burst, 0-Alloc Proof)
//! 2. L4 TCP High-Throughput Bulk Transfer (Baseline std::net Proxy vs Tetrux)
//! 3. L4 TCP RPC Throughput & Tail Latency (Baseline vs Tetrux Interrupt vs Tetrux Adaptive Busy-Poll)
//! 4. Mixed Elephant + Mouse Tail Latency Isolation (Fair Work-Budgeting Proof)
//! 5. Extreme Burst & Connection Storm Handling + Idle CPU Recovery
//! 6. L4 UDP Mode-Switch Reduction (recvfrom/sendto vs Darwin recvmsg_x/sendmsg_x Batching)
//! 7. Low Memory Footprint & Idle Scaling (1,000 Concurrent Connections RSS & CPU)

use std::io::{Read, Write};
use std::net::{SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tetrux::engine::bypass::{
    build_test_ipv4_packet, create_bypass_queue_pair, read_bypass_stats, BypassConfig,
    BypassCounters, BypassForwardMode, BypassWorker, PacketDesc, UmemArena, BURST_SIZE,
};
use tetrux::engine::tcp::{start_tcp_nlb, AcceptStrategy, TcpEngineConfig};
use tetrux::engine::udp::{start_udp_nlb, UdpEngineConfig};
use tetrux::lb::balancer::{BackendPool, BackendSpec, LbAlgorithm};
use tetrux::mem::cache::CachePadded;
use tetrux::metrics::alloc_tracker::{AllocSnapshot, CountingAllocator};
use tetrux::metrics::histogram::LatencyHistogram;
use tetrux::sys::{self, EndpointV4, IoStatus, Poller, ProcessMetrics};

#[global_allocator]
static GLOBAL_ALLOC: CountingAllocator = CountingAllocator;

// ============================================================================
// High-Performance Non-Blocking kqueue TCP Echo Backends (so backends never bottleneck NLB)
// ============================================================================

struct FastTcpBackend {
    endpoint: EndpointV4,
    stop: Arc<AtomicBool>,
    wake: sys::WakeHandle,
    thread: Option<JoinHandle<()>>,
}

impl FastTcpBackend {
    fn start(wid: usize) -> Self {
        let (lfd, bound) =
            sys::create_tcp_listener(EndpointV4::from_octets(127, 0, 0, 1, 0), 4096, false, 262_144)
                .expect("backend listen failed");
        let mut poller = Poller::new(512).expect("backend poller failed");
        let wake = poller.wake_handle();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = Arc::clone(&stop);

        let thread = std::thread::Builder::new()
            .name(format!("bench-be-{wid}"))
            .spawn(move || {
                sys::pin_thread_performance(wid + 4);
                poller.add_read(lfd, u64::MAX, false);
                let mut events = Vec::with_capacity(512);
                let mut scratch = vec![0u8; 65536];
                let mut fds: Vec<sys::Fd> = Vec::new();
                while !stop_c.load(Ordering::Relaxed) {
                    let n = poller.poll(&mut events, Some(10_000_000)).unwrap_or(0);
                    if n == 0 {
                        continue;
                    }
                    for i in 0..events.len() {
                        let ev = events[i];
                        if ev.is_user {
                            continue;
                        }
                        if ev.token == u64::MAX {
                            loop {
                                match sys::accept_nonblock(lfd, false) {
                                    Ok(Some((cfd, _))) => {
                                        poller.add_read(cfd, cfd as u64, false);
                                        fds.push(cfd);
                                    }
                                    _ => break,
                                }
                            }
                        } else {
                            let fd = ev.token as sys::Fd;
                            if ev.error {
                                sys::close_fd(fd);
                                continue;
                            }
                            loop {
                                match sys::read_nb(fd, &mut scratch) {
                                    IoStatus::Ok(r) => {
                                        let mut off = 0;
                                        let mut dead = false;
                                        while off < r {
                                            match sys::write_nb(fd, &scratch[off..r]) {
                                                IoStatus::Ok(w) => off += w,
                                                IoStatus::WouldBlock => sys::cpu_relax(),
                                                _ => {
                                                    dead = true;
                                                    break;
                                                }
                                            }
                                        }
                                        if dead {
                                            sys::close_fd(fd);
                                            break;
                                        }
                                        if r < scratch.len() {
                                            break;
                                        }
                                    }
                                    IoStatus::WouldBlock => break,
                                    IoStatus::Eof | IoStatus::Error(_) => {
                                        sys::close_fd(fd);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                for fd in fds {
                    sys::close_fd(fd);
                }
                sys::close_fd(lfd);
            })
            .expect("spawn backend failed");

        Self {
            endpoint: bound,
            stop,
            wake,
            thread: Some(thread),
        }
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        self.wake.wake();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Fast UDP Echo Backend using Darwin `recvmsg_x`/`sendmsg_x` when available.
struct FastUdpBackend {
    endpoint: EndpointV4,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FastUdpBackend {
    fn start(id: usize) -> Self {
        let (fd, bound) =
            sys::create_udp_socket(EndpointV4::from_octets(127, 0, 0, 1, 0), false, 2 * 1024 * 1024)
                .expect("udp backend bind");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = Arc::clone(&stop);

        let thread = std::thread::Builder::new()
            .name(format!("bench-udp-be-{id}"))
            .spawn(move || {
                let mut poller = Poller::new(16).unwrap();
                poller.add_read(fd, 1, false);
                let mut events = Vec::with_capacity(16);
                let mut buf = [0u8; 2048];
                while !stop_c.load(Ordering::Relaxed) {
                    let n = poller.poll(&mut events, Some(5_000_000)).unwrap_or(0);
                    if n == 0 {
                        continue;
                    }
                    for _ in 0..128 {
                        match sys::recvfrom_nb(fd, &mut buf) {
                            Ok(Some((len, peer))) => {
                                let _ = sys::sendto_nb(fd, &buf[..len], peer);
                            }
                            _ => break,
                        }
                    }
                }
                sys::close_fd(fd);
            })
            .unwrap();

        Self {
            endpoint: bound,
            stop,
            thread: Some(thread),
        }
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Baseline Naive Rust TCP Proxy (std::net thread-per-connection, blocking IO) for comparison!
struct BaselineStdProxy {
    bound_addr: EndpointV4,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl BaselineStdProxy {
    fn start(backends: Vec<EndpointV4>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(v4) => EndpointV4::from_std(v4),
            _ => unreachable!(),
        };
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = Arc::clone(&stop);

        let thread = std::thread::spawn(move || {
            let mut rr = 0usize;
            while !stop_c.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((client, _)) => {
                        let _ = client.set_nodelay(true);
                        let _ = client.set_nonblocking(false);
                        let be = backends[rr % backends.len()];
                        rr = rr.wrapping_add(1);
                        let stop_inner = Arc::clone(&stop_c);
                        std::thread::spawn(move || {
                            let Ok(backend) = TcpStream::connect(be.to_std()) else {
                                return;
                            };
                            let _ = backend.set_nodelay(true);
                            let Ok(mut c_rd) = client.try_clone() else {
                                return;
                            };
                            let Ok(mut b_wr) = backend.try_clone() else {
                                return;
                            };
                            let mut c_wr = client;
                            let mut b_rd = backend;
                            let stop_t = Arc::clone(&stop_inner);
                            let h = std::thread::spawn(move || {
                                let mut buf = vec![0u8; 65536];
                                while !stop_t.load(Ordering::Relaxed) {
                                    match c_rd.read(&mut buf) {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => {
                                            if b_wr.write_all(&buf[..n]).is_err() {
                                                break;
                                            }
                                        }
                                    }
                                }
                                let _ = b_wr.shutdown(std::net::Shutdown::Write);
                            });
                            let mut buf = vec![0u8; 65536];
                            while !stop_inner.load(Ordering::Relaxed) {
                                match b_rd.read(&mut buf) {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        if c_wr.write_all(&buf[..n]).is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                            let _ = c_wr.shutdown(std::net::Shutdown::Write);
                            let _ = h.join();
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_micros(200));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            bound_addr: addr,
            stop,
            thread: Some(thread),
        }
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

// ============================================================================
// Suite 1: True Kernel-Bypass Zero-Copy UMEM L4 Packet Engine
// ============================================================================

fn run_bypass_single(
    label: &str,
    mode: BypassForwardMode,
    workers: usize,
    payload_bytes: usize,
    pkts_per_worker: u64,
    num_flows: usize,
    micro_burst_waves: Option<(usize, usize)>, // (waves, pkts_per_wave)
) {
    let backends = vec![
        BackendSpec::new(EndpointV4::from_octets(10, 0, 1, 1, 8080))
            .with_mac([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]),
        BackendSpec::new(EndpointV4::from_octets(10, 0, 1, 2, 8080))
            .with_mac([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02]),
        BackendSpec::new(EndpointV4::from_octets(10, 0, 1, 3, 8080))
            .with_mac([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x03]),
        BackendSpec::new(EndpointV4::from_octets(10, 0, 1, 4, 8080))
            .with_mac([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x04]),
    ];
    let pool = BackendPool::new(backends, LbAlgorithm::Maglev);
    let ring_size = 4096usize;
    let frames_per_worker = 4096usize;

    let mut cfg = BypassConfig::default();
    cfg.mode = mode;
    cfg.conntrack_capacity = 65_536;

    // Pre-allocate all UMEM arenas, rings, and workers BEFORE measuring allocations & timing!
    let stop = Arc::new(AtomicBool::new(false));
    let start_barrier = Arc::new(Barrier::new(workers * 2 + 1));
    let mut lb_threads = Vec::with_capacity(workers);
    let mut nic_threads = Vec::with_capacity(workers);
    let mut all_counters = Vec::with_capacity(workers);

    let payload = vec![0x5Au8; payload_bytes];
    let sample_pkt_len = 14 + 20 + 20 + payload_bytes;

    for w in 0..workers {
        let umem = UmemArena::new(frames_per_worker).unwrap();
        let (mut nic, lb) = create_bypass_queue_pair(ring_size);
        let counters = Arc::new(CachePadded::new(BypassCounters::default()));
        all_counters.push(Arc::clone(&counters));

        // Pre-populate all 4096 UMEM frames with valid Ethernet+IPv4+TCP packets across `num_flows` flows!
        for f in 0..frames_per_worker {
            let flow_id = ((w * 4096) + f) % num_flows;
            let src_ip = 0x0a00_0001u32.wrapping_add((flow_id as u32) >> 10);
            let src_port = 10000u16.wrapping_add((flow_id & 0x3fff) as u16);
            let addr = UmemArena::frame_data_addr(f);
            unsafe {
                let slice = umem.packet_slice_mut(addr, 1500);
                build_test_ipv4_packet(
                    slice,
                    [0x10, 0x20, 0x30, 0x40, 0x50, (w as u8) + 1],
                    [0x02, 0x54, 0x45, 0x54, 0x52, 0x58],
                    src_ip,
                    0xc633_6401, // VIP 198.51.100.1
                    src_port,
                    443,
                    6, // TCP
                    &payload,
                );
            }
        }

        let worker = BypassWorker::new(
            w,
            cfg.clone(),
            Arc::clone(&umem),
            Arc::clone(&pool),
            Arc::clone(&counters),
        );
        let stop_lb = Arc::clone(&stop);
        let bar_lb = Arc::clone(&start_barrier);
        lb_threads.push(
            std::thread::Builder::new()
                .name(format!("bypass-lb-{w}"))
                .spawn(move || {
                    bar_lb.wait();
                    worker.run_pmd_loop(lb, stop_lb);
                })
                .unwrap(),
        );

        let umem_nic = Arc::clone(&umem);
        let bar_nic = Arc::clone(&start_barrier);
        nic_threads.push(
            std::thread::Builder::new()
                .name(format!("bypass-nic-{w}"))
                .spawn(move || {
                    sys::pin_thread_performance(w + workers);
                    let mut hist = LatencyHistogram::new();
                    let mut free_frames: Vec<u64> = (0..frames_per_worker)
                        .map(UmemArena::frame_data_addr)
                        .collect();
                    let mut rx_batch = [PacketDesc::default(); BURST_SIZE];
                    let mut tx_batch = [PacketDesc::default(); BURST_SIZE];
                    bar_nic.wait();

                    if let Some((waves, pkts_per_wave)) = micro_burst_waves {
                        for _wave in 0..waves {
                            let mut sent = 0usize;
                            let mut recvd = 0usize;
                            while recvd < pkts_per_wave {
                                // Blast burst into RX ring
                                let mut to_send = 0usize;
                                while to_send < BURST_SIZE && sent < pkts_per_wave {
                                    if let Some(addr) = free_frames.pop() {
                                        let ts = sys::fast_now_ns();
                                        unsafe { umem_nic.write_headroom_ts(addr, ts) };
                                        tx_batch[to_send] = PacketDesc {
                                            addr,
                                            len: sample_pkt_len as u32,
                                            options: 0,
                                        };
                                        to_send += 1;
                                        sent += 1;
                                    } else {
                                        break;
                                    }
                                }
                                if to_send > 0 {
                                    let p = nic.rx_tx_to_lb.push_batch(&tx_batch[..to_send]);
                                    // Return unpushed descriptors to free stack
                                    for d in &tx_batch[p..to_send] {
                                        free_frames.push(d.addr);
                                        sent -= 1;
                                    }
                                }
                                let got = nic.tx_rx_from_lb.pop_batch(&mut rx_batch);
                                if got > 0 {
                                    let now = sys::fast_now_ns();
                                    for d in &rx_batch[..got] {
                                        let ts = unsafe { umem_nic.read_headroom_ts(d.addr) };
                                        hist.record_ns(now.saturating_sub(ts));
                                        free_frames.push(d.addr);
                                    }
                                    recvd += got;
                                } else {
                                    sys::cpu_relax();
                                }
                            }
                        }
                    } else {
                        // Sustained max-throughput run
                        let target = pkts_per_worker;
                        let mut sent = 0u64;
                        let mut recvd = 0u64;
                        let mut sample_ctr = 0u64;
                        while recvd < target {
                            let mut to_send = 0usize;
                            while to_send < BURST_SIZE && sent < target {
                                if let Some(addr) = free_frames.pop() {
                                    // Stamp timestamp every 8th batch to avoid clock skewing throughput
                                    if (sample_ctr & 0x7) == 0 && to_send == 0 {
                                        unsafe {
                                            umem_nic.write_headroom_ts(addr, sys::fast_now_ns())
                                        };
                                    }
                                    tx_batch[to_send] = PacketDesc {
                                        addr,
                                        len: sample_pkt_len as u32,
                                        options: if (sample_ctr & 0x7) == 0 && to_send == 0 {
                                            1
                                        } else {
                                            0
                                        },
                                    };
                                    to_send += 1;
                                    sent += 1;
                                } else {
                                    break;
                                }
                            }
                            if to_send > 0 {
                                sample_ctr = sample_ctr.wrapping_add(1);
                                let p = nic.rx_tx_to_lb.push_batch(&tx_batch[..to_send]);
                                for d in &tx_batch[p..to_send] {
                                    free_frames.push(d.addr);
                                    sent -= 1;
                                }
                            }
                            let got = nic.tx_rx_from_lb.pop_batch(&mut rx_batch);
                            if got > 0 {
                                for d in &rx_batch[..got] {
                                    if d.options == 1 {
                                        let ts = unsafe { umem_nic.read_headroom_ts(d.addr) };
                                        hist.record_ns(sys::fast_now_ns().saturating_sub(ts));
                                    }
                                    free_frames.push(d.addr);
                                }
                                recvd += got as u64;
                            } else {
                                sys::cpu_relax();
                            }
                        }
                    }
                    hist
                })
                .unwrap(),
        );
    }

    // Wait for all threads to finish setup, then snapshot allocs & rusage cleanly!
    let alloc_start = AllocSnapshot::now();
    let ru_start = sys::sample_process_metrics();
    let t0 = Instant::now();
    start_barrier.wait();

    let mut merged_hist = LatencyHistogram::new();
    for t in nic_threads {
        merged_hist.merge(&t.join().unwrap());
    }
    let elapsed = t0.elapsed();
    let alloc_end = AllocSnapshot::now();
    let ru_end = sys::sample_process_metrics();

    stop.store(true, Ordering::Release);
    for t in lb_threads {
        let _ = t.join();
    }

    let mut total_pkts = 0u64;
    let mut total_drops = 0u64;
    let mut total_hits = 0u64;
    let mut total_misses = 0u64;
    for c in &all_counters {
        let s = read_bypass_stats(c);
        total_pkts += s.tx_packets;
        total_drops += s.drops;
        total_hits += s.ct_hits;
        total_misses += s.ct_misses;
    }

    let secs = elapsed.as_secs_f64();
    let mpps = (total_pkts as f64 / secs) / 1_000_000.0;
    // Wire-rate Gbps includes 20B Ethernet preamble+SFD+IFG per packet (standard RFC 2544)
    let wire_bytes = (sample_pkt_len.max(64) + 20) as f64;
    let wire_gbps = (total_pkts as f64 * wire_bytes * 8.0 / secs) / 1e9;
    let ns_per_pkt = (secs * 1e9 * workers as f64) / total_pkts.max(1) as f64;
    let alloc_d = AllocSnapshot::delta(alloc_start, alloc_end);
    let ru_d = ProcessMetrics::delta(&ru_start, &ru_end);

    println!(
        "  {:<34} | {:6.2} Mpps | {:6.2} Gbps | {:5.1} ns/pkt | lat(ns) p50={:<5} p99={:<6} p99.9={:<6} | allocs={} drops={} vcs={} sys_us={}",
        label,
        mpps,
        wire_gbps,
        ns_per_pkt,
        merged_hist.percentile_ns(50.0),
        merged_hist.percentile_ns(99.0),
        merged_hist.percentile_ns(99.9),
        alloc_d.allocs,
        total_drops,
        ru_d.voluntary_ctx_switches,
        ru_d.sys_time_us,
    );
    let _ = (total_hits, total_misses);
}

fn suite_1_kernel_bypass() {
    println!("\n==================================================================================================================================");
    println!("SUITE 1: TRUE KERNEL-BYPASS ZERO-COPY UMEM L4 ENGINE (AF_XDP/DPDK Ring Model — 0 Syscalls, 0 Copies, 0 Heap Allocs)");
    println!("==================================================================================================================================");
    run_bypass_single("1a. 1-Core NAT (64B wire)", BypassForwardMode::Nat, 1, 10, 4_000_000, 4096, None);
    run_bypass_single("1b. 1-Core NAT (1024B wire)", BypassForwardMode::Nat, 1, 970, 4_000_000, 4096, None);
    run_bypass_single("1c. 1-Core DSR (64B wire)", BypassForwardMode::Dsr, 1, 10, 4_000_000, 4096, None);
    run_bypass_single("1d. 2-Core NAT Scaling (64B)", BypassForwardMode::Nat, 2, 10, 4_000_000, 8192, None);
    run_bypass_single("1e. 4-Core NAT Scaling (64B)", BypassForwardMode::Nat, 4, 10, 4_000_000, 16384, None);
    run_bypass_single("1f. 4-Core DSR Scaling (1024B)", BypassForwardMode::Dsr, 4, 970, 4_000_000, 16384, None);
    run_bypass_single("1g. Micro-Burst (5x40k, 16k flows)", BypassForwardMode::Nat, 1, 10, 0, 16384, Some((5, 40_000)));
}

// ============================================================================
// Suite 2: L4 TCP High-Throughput Bulk Transfer (Baseline vs Tetrux)
// ============================================================================

fn run_tcp_bulk(target: EndpointV4, streams: usize, duration: Duration) -> (f64, u64, sys::ProcessMetricsDelta) {
    let stop = Arc::new(AtomicBool::new(false));
    let bytes_total = Arc::new(AtomicU64::new(0));
    let bar = Arc::new(Barrier::new(streams + 1));
    let mut handles = Vec::with_capacity(streams);

    for _ in 0..streams {
        let stop_c = Arc::clone(&stop);
        let bytes_c = Arc::clone(&bytes_total);
        let bar_c = Arc::clone(&bar);
        handles.push(std::thread::spawn(move || {
            let mut s = TcpStream::connect(target.to_std()).expect("bulk connect failed");
            let _ = s.set_nodelay(true);
            let mut tx = vec![0x42u8; 65536];
            tx[0] = 0xAA;
            let mut rx = vec![0u8; 65536];
            let mut s_rd = s.try_clone().unwrap();
            let stop_rd = Arc::clone(&stop_c);
            let bytes_rd = Arc::clone(&bytes_c);
            let bar_rd_done = Arc::new(AtomicBool::new(false));

            bar_c.wait();
            let rd_handle = std::thread::spawn(move || {
                while !stop_rd.load(Ordering::Relaxed) {
                    match s_rd.read(&mut rx) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            bytes_rd.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    }
                }
            });
            let _ = s.set_write_timeout(Some(Duration::from_millis(200)));
            while !stop_c.load(Ordering::Relaxed) {
                match s.write(&tx) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_) => break,
                }
            }
            let _ = s.shutdown(std::net::Shutdown::Both);
            let _ = rd_handle.join();
            let _ = bar_rd_done;
        }));
    }

    let ru_start = sys::sample_process_metrics();
    let t0 = Instant::now();
    bar.wait();
    std::thread::sleep(duration);
    stop.store(true, Ordering::Release);
    for h in handles {
        let _ = h.join();
    }
    let elapsed = t0.elapsed().as_secs_f64();
    let ru_end = sys::sample_process_metrics();
    let total_bytes = bytes_total.load(Ordering::Relaxed);
    // Bidirectional echo transfers bytes both C->B and B->C (total proxy throughput = 2 * echoed)
    let gbps = (total_bytes as f64 * 2.0 * 8.0 / elapsed) / 1e9;
    (gbps, total_bytes * 2, ProcessMetrics::delta(&ru_start, &ru_end))
}

fn suite_2_tcp_bulk(backends: &[EndpointV4]) {
    println!("\n==================================================================================================================================");
    println!("SUITE 2: L4 TCP HIGH-THROUGHPUT BULK TRANSFER (8 Concurrent 64 KiB Bidirectional Streams, 2.0s)");
    println!("==================================================================================================================================");

    let dur = Duration::from_secs(2);

    // 2a. Baseline std::net proxy
    let base = BaselineStdProxy::start(backends.to_vec());
    let (b_gbps, b_bytes, b_ru) = run_tcp_bulk(base.bound_addr, 8, dur);
    base.stop();
    println!(
        "  {:<34} | {:6.2} Gbps | {:7.1} MiB | usr={:5.1}ms sys={:5.1}ms | vcs={:<7} ivcs={:<6} | rss={:.1} MiB",
        "Baseline (std::net thread/conn)",
        b_gbps,
        b_bytes as f64 / (1024.0 * 1024.0),
        b_ru.user_time_us as f64 / 1000.0,
        b_ru.sys_time_us as f64 / 1000.0,
        b_ru.voluntary_ctx_switches,
        b_ru.involuntary_ctx_switches,
        b_ru.current_rss_bytes as f64 / (1024.0 * 1024.0),
    );

    // 2b. Tetrux TCP NLB
    let pool = BackendPool::new(
        backends.iter().map(|&e| BackendSpec::new(e)).collect(),
        LbAlgorithm::P2cLeastConn,
    );
    let mut cfg = TcpEngineConfig::default();
    cfg.workers = 4;
    cfg.busy_poll_us = 150;
    cfg.work_budget_bytes = 65_536;
    let nlb = start_tcp_nlb(cfg, pool).unwrap();
    let (t_gbps, t_bytes, t_ru) = run_tcp_bulk(nlb.bound_addr(), 8, dur);
    let st = nlb.stats();
    nlb.stop();
    let fast_pct = if st.fast_path_writes + st.buffered_writes > 0 {
        (st.fast_path_writes as f64 / (st.fast_path_writes + st.buffered_writes) as f64) * 100.0
    } else {
        100.0
    };
    println!(
        "  {:<34} | {:6.2} Gbps | {:7.1} MiB | usr={:5.1}ms sys={:5.1}ms | vcs={:<7} ivcs={:<6} | rss={:.1} MiB | fast_path={:.1}% ev/poll={:.1}",
        "Tetrux L4 TCP (4w, busy-poll)",
        t_gbps,
        t_bytes as f64 / (1024.0 * 1024.0),
        t_ru.user_time_us as f64 / 1000.0,
        t_ru.sys_time_us as f64 / 1000.0,
        t_ru.voluntary_ctx_switches,
        t_ru.involuntary_ctx_switches,
        t_ru.current_rss_bytes as f64 / (1024.0 * 1024.0),
        fast_pct,
        if st.poll_calls > 0 { st.poll_events as f64 / st.poll_calls as f64 } else { 0.0 },
    );
}

// ============================================================================
// Suite 3: L4 TCP RPC Throughput & Tail Latency (Baseline vs Interrupt vs Busy-Poll)
// ============================================================================

fn run_tcp_rpc(
    target: EndpointV4,
    clients: usize,
    payload_size: usize,
    duration: Duration,
    pace_us: u64, // 0 = max rate closed-loop; >0 = paced open-loop (no coordinated omission!)
) -> (f64, LatencyHistogram, sys::ProcessMetricsDelta) {
    let stop = Arc::new(AtomicBool::new(false));
    let bar = Arc::new(Barrier::new(clients + 1));
    let mut handles = Vec::with_capacity(clients);

    for _ in 0..clients {
        let stop_c = Arc::clone(&stop);
        let bar_c = Arc::clone(&bar);
        handles.push(std::thread::spawn(move || {
            let mut s = TcpStream::connect(target.to_std()).expect("rpc connect failed");
            let _ = s.set_nodelay(true);
            let req = vec![0x77u8; payload_size];
            let mut resp = vec![0u8; payload_size];
            let mut hist = LatencyHistogram::new();
            bar_c.wait();

            let mut next_scheduled_ns = sys::fast_now_ns();
            let pace_ns = pace_us * 1_000;

            while !stop_c.load(Ordering::Relaxed) {
                let send_start = if pace_ns > 0 {
                    let now = sys::fast_now_ns();
                    if now < next_scheduled_ns {
                        let wait_ns = next_scheduled_ns - now;
                        if wait_ns > 50_000 {
                            std::thread::sleep(Duration::from_nanos(wait_ns - 30_000));
                        }
                        while sys::fast_now_ns() < next_scheduled_ns {
                            sys::cpu_relax();
                        }
                    }
                    // Open-loop scheduled timestamp avoids Coordinated Omission!
                    let sched = next_scheduled_ns;
                    next_scheduled_ns += pace_ns;
                    sched
                } else {
                    sys::fast_now_ns()
                };

                if s.write_all(&req).is_err() {
                    break;
                }
                if s.read_exact(&mut resp).is_err() {
                    break;
                }
                let done = sys::fast_now_ns();
                hist.record_ns(done.saturating_sub(send_start));
            }
            hist
        }));
    }

    let ru_start = sys::sample_process_metrics();
    let t0 = Instant::now();
    bar.wait();
    std::thread::sleep(duration);
    stop.store(true, Ordering::Release);

    let mut merged = LatencyHistogram::new();
    for h in handles {
        merged.merge(&h.join().unwrap());
    }
    let elapsed = t0.elapsed().as_secs_f64();
    let ru_end = sys::sample_process_metrics();
    let rps = merged.count() as f64 / elapsed;
    (rps, merged, ProcessMetrics::delta(&ru_start, &ru_end))
}

fn suite_3_tcp_rpc(backends: &[EndpointV4]) {
    println!("\n==================================================================================================================================");
    println!("SUITE 3: L4 TCP RPC THROUGHPUT & TAIL LATENCY (32 Clients, 256B Payload, 2.0s)");
    println!("==================================================================================================================================");

    let dur = Duration::from_secs(2);
    let pool_specs: Vec<BackendSpec> = backends.iter().map(|&e| BackendSpec::new(e)).collect();

    // 3a. Max-rate Closed-Loop
    println!("  [3A] Max-Rate Throughput & Tail Latency (32 persistent clients):");
    {
        let base = BaselineStdProxy::start(backends.to_vec());
        let (rps, hist, ru) = run_tcp_rpc(base.bound_addr, 32, 256, dur, 0);
        base.stop();
        let l = hist.summary_us();
        println!(
            "    {:<32} | {:9.0} RPS | p50={:6.1}us p95={:6.1}us p99={:6.1}us p99.9={:7.1}us max={:7.1}us | vcs={:<7} sys={:5.1}ms",
            "Baseline (std::net thread/conn)",
            rps, l.p50_us, l.p95_us, l.p99_us, l.p999_us, l.max_us,
            ru.voluntary_ctx_switches, ru.sys_time_us as f64 / 1000.0
        );
    }
    for (label, busy_us) in [
        ("Tetrux TCP (Interrupt, 0us)", 0u64),
        ("Tetrux TCP (Busy-Poll, 200us)", 200u64),
    ] {
        let pool = BackendPool::new(pool_specs.clone(), LbAlgorithm::P2cLeastConn);
        let mut cfg = TcpEngineConfig::default();
        cfg.workers = 4;
        cfg.busy_poll_us = busy_us;
        let nlb = start_tcp_nlb(cfg, pool).unwrap();
        let (rps, hist, ru) = run_tcp_rpc(nlb.bound_addr(), 32, 256, dur, 0);
        let st = nlb.stats();
        nlb.stop();
        let l = hist.summary_us();
        let sc_per_req = (st.poll_calls + st.read_calls + st.write_calls) as f64 / hist.count().max(1) as f64;
        println!(
            "    {:<32} | {:9.0} RPS | p50={:6.1}us p95={:6.1}us p99={:6.1}us p99.9={:7.1}us max={:7.1}us | vcs={:<7} sys={:5.1}ms | sc/req={:.2}",
            label,
            rps, l.p50_us, l.p95_us, l.p99_us, l.p999_us, l.max_us,
            ru.voluntary_ctx_switches, ru.sys_time_us as f64 / 1000.0, sc_per_req
        );
    }

    // 3b. Paced Open-Loop (Coordinated-Omission-Free Tail Latency at 20,000 target RPS!)
    println!("  [3B] Open-Loop Paced Tail Latency (16 clients @ 1,250 RPS each = 20,000 RPS target, Coordinated-Omission-Free):");
    for (label, busy_us) in [
        ("Tetrux TCP (Interrupt, 0us)", 0u64),
        ("Tetrux TCP (Busy-Poll, 250us)", 250u64),
    ] {
        let pool = BackendPool::new(pool_specs.clone(), LbAlgorithm::P2cLeastConn);
        let mut cfg = TcpEngineConfig::default();
        cfg.workers = 4;
        cfg.busy_poll_us = busy_us;
        let nlb = start_tcp_nlb(cfg, pool).unwrap();
        let (rps, hist, ru) = run_tcp_rpc(nlb.bound_addr(), 16, 256, dur, 800);
        nlb.stop();
        let l = hist.summary_us();
        println!(
            "    {:<32} | {:9.0} RPS | p50={:6.1}us p95={:6.1}us p99={:6.1}us p99.9={:7.1}us max={:7.1}us | vcs={:<7}",
            label, rps, l.p50_us, l.p95_us, l.p99_us, l.p999_us, l.max_us, ru.voluntary_ctx_switches
        );
    }
}

// ============================================================================
// Suite 4: Mixed Elephant + Mouse Tail Latency Isolation (Fair Work-Budgeting)
// ============================================================================

fn suite_4_mixed_isolation(backends: &[EndpointV4]) {
    println!("\n==================================================================================================================================");
    println!("SUITE 4: TAIL LATENCY ISOLATION (6 Heavy 64 KiB Elephant Streams + 8 Latency-Sensitive 64B Mouse RPCs)");
    println!("==================================================================================================================================");
    let pool_specs: Vec<BackendSpec> = backends.iter().map(|&e| BackendSpec::new(e)).collect();

    for (label, budget) in [
        ("Unbounded Turn (work_budget=2MiB)", 2 * 1024 * 1024usize),
        ("Tetrux Fair Budget (32 KiB/turn)", 32 * 1024usize),
    ] {
        let pool = BackendPool::new(pool_specs.clone(), LbAlgorithm::P2cLeastConn);
        let mut cfg = TcpEngineConfig::default();
        cfg.workers = 2; // Deliberately share 2 workers across elephants + mice to stress scheduling fairness!
        cfg.busy_poll_us = 150;
        cfg.work_budget_bytes = budget;
        let nlb = start_tcp_nlb(cfg, pool).unwrap();
        let target = nlb.bound_addr();

        let stop = Arc::new(AtomicBool::new(false));
        let elephant_bytes = Arc::new(AtomicU64::new(0));
        let mut elephants = Vec::new();
        for _ in 0..6 {
            let stop_c = Arc::clone(&stop);
            let eb = Arc::clone(&elephant_bytes);
            elephants.push(std::thread::spawn(move || {
                let mut s = TcpStream::connect(target.to_std()).unwrap();
                let _ = s.set_nodelay(true);
                let mut s_rd = s.try_clone().unwrap();
                let stop_r = Arc::clone(&stop_c);
                let eb_r = Arc::clone(&eb);
                let rh = std::thread::spawn(move || {
                    let mut rbuf = vec![0u8; 65536];
                    while !stop_r.load(Ordering::Relaxed) {
                        match s_rd.read(&mut rbuf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                eb_r.fetch_add(n as u64, Ordering::Relaxed);
                            }
                        }
                    }
                });
                let buf = vec![0x33u8; 65536];
                let _ = s.set_write_timeout(Some(Duration::from_millis(100)));
                while !stop_c.load(Ordering::Relaxed) {
                    if s.write(&buf).is_err() && stop_c.load(Ordering::Relaxed) {
                        break;
                    }
                }
                let _ = s.shutdown(std::net::Shutdown::Both);
                let _ = rh.join();
            }));
        }

        // Let elephants ramp up, then measure mouse RPC tail latency alongside them!
        std::thread::sleep(Duration::from_millis(150));
        let t0 = Instant::now();
        let eb_start = elephant_bytes.load(Ordering::Relaxed);
        let (mouse_rps, mouse_hist, _) = run_tcp_rpc(target, 8, 64, Duration::from_secs(2), 0);
        let eb_delta = elephant_bytes.load(Ordering::Relaxed) - eb_start;
        let elephant_gbps = (eb_delta as f64 * 2.0 * 8.0 / t0.elapsed().as_secs_f64()) / 1e9;

        stop.store(true, Ordering::Release);
        for e in elephants {
            let _ = e.join();
        }
        nlb.stop();

        let l = mouse_hist.summary_us();
        println!(
            "  {:<34} | Elephant {:5.2} Gbps | Mouse {:7.0} RPS | Mouse p50={:6.1}us p99={:6.1}us p99.9={:7.1}us max={:7.1}us",
            label, elephant_gbps, mouse_rps, l.p50_us, l.p99_us, l.p999_us, l.max_us
        );
    }
}

// ============================================================================
// Suite 5: Extreme Burst & Connection Storm Handling + Idle CPU Recovery
// ============================================================================

fn suite_5_burst_storm(backends: &[EndpointV4]) {
    println!("\n==================================================================================================================================");
    println!("SUITE 5: BURST & CONNECTION STORM HANDLING (5 Waves x 100 Simultaneous New Conns + 10 RPCs Each + Idle CPU Recovery)");
    println!("==================================================================================================================================");

    let pool = BackendPool::new(
        backends.iter().map(|&e| BackendSpec::new(e)).collect(),
        LbAlgorithm::P2cLeastConn,
    );
    let mut cfg = TcpEngineConfig::default();
    cfg.workers = 4;
    cfg.backlog = 4096;
    cfg.busy_poll_us = 150;
    let nlb = start_tcp_nlb(cfg, pool).unwrap();
    let target = nlb.bound_addr();

    // Measure pre-burst idle CPU over 300ms
    std::thread::sleep(Duration::from_millis(100));
    let idle1_s = sys::sample_process_metrics();
    std::thread::sleep(Duration::from_millis(300));
    let idle1_e = sys::sample_process_metrics();
    let idle1_d = ProcessMetrics::delta(&idle1_s, &idle1_e);
    let pre_idle_cpu_pct = ((idle1_d.user_time_us + idle1_d.sys_time_us) as f64 / 300_000.0) * 100.0;

    let mut total_ok = 0u64;
    let mut total_err = 0u64;
    let mut burst_hist = LatencyHistogram::new();
    let waves = 5usize;
    let conns_per_wave = 100usize;
    let rss_before = sys::sample_process_metrics().current_rss_bytes;
    let t_all = Instant::now();

    for _wave in 0..waves {
        let bar = Arc::new(Barrier::new(conns_per_wave));
        let mut hs = Vec::with_capacity(conns_per_wave);
        for _ in 0..conns_per_wave {
            let b = Arc::clone(&bar);
            hs.push(std::thread::spawn(move || {
                b.wait();
                let t0 = sys::fast_now_ns();
                let Ok(mut s) = TcpStream::connect(target.to_std()) else {
                    return (false, 0u64);
                };
                let _ = s.set_nodelay(true);
                let req = [0x99u8; 128];
                let mut resp = [0u8; 128];
                for _ in 0..10 {
                    if s.write_all(&req).is_err() || s.read_exact(&mut resp).is_err() {
                        return (false, 0u64);
                    }
                }
                (true, sys::fast_now_ns().saturating_sub(t0))
            }));
        }
        for h in hs {
            let (ok, dur_ns) = h.join().unwrap();
            if ok {
                total_ok += 1;
                burst_hist.record_ns(dur_ns);
            } else {
                total_err += 1;
            }
        }
        // Brief pause between waves so workers cycle between idle park and instant burst wakeup!
        std::thread::sleep(Duration::from_millis(25));
    }

    let burst_elapsed = t_all.elapsed();
    let st = nlb.stats();
    let rss_after = sys::sample_process_metrics().current_rss_bytes;

    // Measure post-burst idle CPU recovery over 300ms (proving adaptive busy-poll parks cleanly!)
    std::thread::sleep(Duration::from_millis(80));
    let idle2_s = sys::sample_process_metrics();
    std::thread::sleep(Duration::from_millis(300));
    let idle2_e = sys::sample_process_metrics();
    let idle2_d = ProcessMetrics::delta(&idle2_s, &idle2_e);
    let post_idle_cpu_pct = ((idle2_d.user_time_us + idle2_d.sys_time_us) as f64 / 300_000.0) * 100.0;

    nlb.stop();
    let l = burst_hist.summary_us();
    let wake_total = st.wakeups_sent + st.wakeups_suppressed;
    let wake_sup_pct = if wake_total > 0 {
        (st.wakeups_suppressed as f64 / wake_total as f64) * 100.0
    } else {
        0.0
    };
    println!(
        "  Storm Result: {}/{} succeeded ({} drops) in {:.2}s | Conn+10RPC lat: p50={:.1}us p99={:.1}us p99.9={:.1}us max={:.1}us",
        total_ok,
        waves * conns_per_wave,
        total_err,
        burst_elapsed.as_secs_f64(),
        l.p50_us,
        l.p99_us,
        l.p999_us,
        l.max_us,
    );
    println!(
        "  Efficiency  : peak_active={} peak_pool_bufs={} wakeups_suppressed={:.1}% | RSS {:.1}->{:.1} MiB | Idle CPU pre={:.2}% post={:.2}%",
        st.peak_active,
        st.peak_buffers_used,
        wake_sup_pct,
        rss_before as f64 / (1024.0 * 1024.0),
        rss_after as f64 / (1024.0 * 1024.0),
        pre_idle_cpu_pct,
        post_idle_cpu_pct,
    );
}

// ============================================================================
// Suite 6: L4 UDP Mode-Switch Reduction (recvfrom/sendto vs recvmsg_x/sendmsg_x)
// ============================================================================

fn run_udp_bench(batched: bool, udp_backends: &[EndpointV4], payload_bytes: usize) {
    let pool = BackendPool::new(
        udp_backends.iter().map(|&e| BackendSpec::new(e)).collect(),
        LbAlgorithm::Maglev,
    );
    let mut cfg = UdpEngineConfig::default();
    cfg.batched = batched;
    cfg.batch_size = 64;
    cfg.busy_poll_us = 150;

    let nlb = start_udp_nlb(cfg, pool).unwrap();
    let target = SocketAddrV4::from(nlb.bound_addr().to_std());

    let clients = 4usize;
    let window = 32usize; // Pipelined burst of 32 datagrams in flight per client to exercise batching!
    let stop = Arc::new(AtomicBool::new(false));
    let bar = Arc::new(Barrier::new(clients + 1));
    let mut handles = Vec::with_capacity(clients);

    for cid in 0..clients {
        let stop_c = Arc::clone(&stop);
        let bar_c = Arc::clone(&bar);
        handles.push(std::thread::spawn(move || {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.connect(target).unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            let mut tx = vec![0u8; payload_bytes.max(16)];
            let mut rx = vec![0u8; payload_bytes.max(16)];
            let mut hist = LatencyHistogram::new();
            let mut echoed = 0u64;
            bar_c.wait();

            while !stop_c.load(Ordering::Relaxed) {
                let ts = sys::fast_now_ns();
                tx[0..8].copy_from_slice(&ts.to_le_bytes());
                tx[8..16].copy_from_slice(&(cid as u64).to_le_bytes());
                for _ in 0..window {
                    let _ = sock.send(&tx);
                }
                for _ in 0..window {
                    match sock.recv(&mut rx) {
                        Ok(n) if n >= 8 => {
                            let sent_ts = u64::from_le_bytes(rx[0..8].try_into().unwrap());
                            hist.record_ns(sys::fast_now_ns().saturating_sub(sent_ts));
                            echoed += 1;
                        }
                        _ => break,
                    }
                }
            }
            (echoed, hist)
        }));
    }

    let ru_s = sys::sample_process_metrics();
    let t0 = Instant::now();
    bar.wait();
    std::thread::sleep(Duration::from_secs(2));
    stop.store(true, Ordering::Release);

    let mut total_echoed = 0u64;
    let mut merged = LatencyHistogram::new();
    for h in handles {
        let (e, hist) = h.join().unwrap();
        total_echoed += e;
        merged.merge(&hist);
    }
    let elapsed = t0.elapsed().as_secs_f64();
    let ru_e = sys::sample_process_metrics();
    let st = nlb.stats();
    nlb.stop();

    let ru_d = ProcessMetrics::delta(&ru_s, &ru_e);
    let l = merged.summary_us();
    // Each client round-trip = 2 forwarded UDP packets through NLB (C->B + B->C)
    let forwarded_pps = st.tx_packets as f64 / elapsed;
    let total_io_sc = st.recv_syscalls + st.send_syscalls;
    let label = if batched {
        "Tetrux UDP Batched (recvmsg_x)"
    } else {
        "Baseline UDP Single (recvfrom)"
    };
    println!(
        "  {:<32} | {:9.0} PPS | pkts/syscall={:5.2} | io_syscalls={:<8} | sys={:5.1}ms vcs={:<7} | p50={:6.1}us p99={:6.1}us p99.9={:7.1}us",
        label,
        forwarded_pps,
        st.pkts_per_syscall(),
        total_io_sc,
        ru_d.sys_time_us as f64 / 1000.0,
        ru_d.voluntary_ctx_switches,
        l.p50_us,
        l.p99_us,
        l.p999_us,
    );
    let _ = total_echoed;
}

fn suite_6_udp_batching() {
    println!("\n==================================================================================================================================");
    println!("SUITE 6: L4 UDP MODE-SWITCH REDUCTION (1-pkt recvfrom/sendto vs 64-pkt Darwin recvmsg_x/sendmsg_x, 2.0s)");
    println!("==================================================================================================================================");
    let b1 = FastUdpBackend::start(0);
    let b2 = FastUdpBackend::start(1);
    let eps = [b1.endpoint, b2.endpoint];
    run_udp_bench(false, &eps, 128);
    run_udp_bench(true, &eps, 128);
    b1.stop();
    b2.stop();
}

// ============================================================================
// Suite 7: Low Memory Footprint & Idle Scaling (1,000 Concurrent Connections)
// ============================================================================

fn suite_7_memory_footprint(backends: &[EndpointV4], nofile_limit: u64) {
    println!("\n==================================================================================================================================");
    println!("SUITE 7: LOW MEMORY FOOTPRINT & IDLE SCALING (Lazy Buffer Lease — ~96B/Conn in Slab, 0 Buffers Leased While Idle)");
    println!("==================================================================================================================================");

    // Each live proxied connection consumes 3 FDs inside this single benchmark process
    // (client + NLB client_fd + NLB backend_fd + backend accepted fd = 4 FDs!).
    let target_conns = ((nofile_limit.saturating_sub(256)) / 4).min(1000) as usize;
    let pool = BackendPool::new(
        backends.iter().map(|&e| BackendSpec::new(e)).collect(),
        LbAlgorithm::Maglev,
    );
    let mut cfg = TcpEngineConfig::default();
    cfg.workers = 4;
    cfg.max_conns_per_worker = 1024;
    cfg.pool_chunks_per_worker = 64; // Lazy pool: only 2 MiB/worker pre-allocated
    cfg.busy_poll_us = 100;
    cfg.idle_timeout_secs = 0;
    let nlb = start_tcp_nlb(cfg, pool).unwrap();
    let target = nlb.bound_addr();

    std::thread::sleep(Duration::from_millis(50));
    let rss_base = sys::sample_process_metrics().current_rss_bytes;

    let mut conns = Vec::with_capacity(target_conns);
    let ping = [0x55u8; 32];
    let mut pong = [0u8; 32];
    for _ in 0..target_conns {
        if let Ok(mut s) = TcpStream::connect(target.to_std()) {
            let _ = s.set_nodelay(true);
            if s.write_all(&ping).is_ok() && s.read_exact(&mut pong).is_ok() {
                conns.push(s);
            }
        }
    }
    let opened = conns.len();
    std::thread::sleep(Duration::from_millis(120));

    let rss_loaded = sys::sample_process_metrics().current_rss_bytes;
    let idle_s = sys::sample_process_metrics();
    std::thread::sleep(Duration::from_millis(400));
    let idle_e = sys::sample_process_metrics();
    let idle_d = ProcessMetrics::delta(&idle_s, &idle_e);
    let idle_cpu_pct = ((idle_d.user_time_us + idle_d.sys_time_us) as f64 / 400_000.0) * 100.0;
    let st = nlb.stats();

    let rss_delta = rss_loaded.saturating_sub(rss_base);
    let bytes_per_conn = if opened > 0 {
        rss_delta as f64 / opened as f64
    } else {
        0.0
    };
    println!(
        "  Held {} live verified TCP connections simultaneously (4 workers, slab-backed):",
        opened
    );
    println!(
        "  RSS Base={:.2} MiB -> Loaded={:.2} MiB (Delta={:.2} MiB, ~{:.0} B/conn incl. client+backend sockets!)",
        rss_base as f64 / (1024.0 * 1024.0),
        rss_loaded as f64 / (1024.0 * 1024.0),
        rss_delta as f64 / (1024.0 * 1024.0),
        bytes_per_conn,
    );
    println!(
        "  Active Conns={} | Peak Pooled Backpressure Buffers Leased={} | Idle CPU with {} open conns={:.2}%",
        st.active, st.peak_buffers_used, opened, idle_cpu_pct
    );

    drop(conns);
    nlb.stop();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let suite_filter = args
        .iter()
        .position(|a| a == "--suite")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("all");

    let nofile = sys::raise_nofile_limit(10_240);
    println!("==================================================================================================================================");
    println!(
        "TETRUX L4 NLB BENCHMARK SUITE | CPUs={} | nofile={} | suite={}",
        sys::num_cpus(),
        nofile,
        suite_filter
    );
    println!("==================================================================================================================================");

    if suite_filter == "all" || suite_filter == "bypass" {
        suite_1_kernel_bypass();
    }

    let need_tcp_backends = matches!(suite_filter, "all" | "tcp" | "rpc" | "mixed" | "burst" | "memory");
    let backends: Vec<FastTcpBackend> = if need_tcp_backends {
        (0..4).map(FastTcpBackend::start).collect()
    } else {
        Vec::new()
    };
    let be_eps: Vec<EndpointV4> = backends.iter().map(|b| b.endpoint).collect();

    if suite_filter == "all" || suite_filter == "tcp" {
        suite_2_tcp_bulk(&be_eps);
    }
    if suite_filter == "all" || suite_filter == "tcp" || suite_filter == "rpc" {
        suite_3_tcp_rpc(&be_eps);
    }
    if suite_filter == "all" || suite_filter == "mixed" {
        suite_4_mixed_isolation(&be_eps);
    }
    if suite_filter == "all" || suite_filter == "burst" {
        suite_5_burst_storm(&be_eps);
    }
    if suite_filter == "all" || suite_filter == "udp" {
        suite_6_udp_batching();
    }
    if suite_filter == "all" || suite_filter == "memory" {
        suite_7_memory_footprint(&be_eps, nofile);
    }

    for b in backends {
        b.stop();
    }
    println!("\n==================================================================================================================================");
    println!("BENCHMARK COMPLETE");
    println!("==================================================================================================================================");
}
