//! Tetrux — Tier-0 Ultra-Low-Level Rust L4 Network Load Balancer CLI.
//!
//! Features:
//! - Graceful `SIGTERM`/`SIGINT` BGP withdrawal + in-flight TCP connection drain
//! - `SIGHUP` live declarative state-file reload
//! - Hardened HTTP/JSON & Prometheus `/metrics` admin plane (Bearer auth + CIDR/SSRF guard)
//! - PROXY Protocol v2 client-IP preservation, TCP keepalive, per-IP rate limiting
//! - Parallel non-blocking TCP/HTTP health probes with hysteresis & panic-mode fail-open

use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tetrux::config;
use tetrux::control::{
    start_control_plane_with_config, CidrV4, ControlPlaneConfig, StatsProvider,
};
use tetrux::engine::tcp::{start_tcp_nlb, AcceptStrategy, TcpEngineConfig};
use tetrux::engine::udp::{start_udp_nlb, UdpEngineConfig};
use tetrux::lb::balancer::{BackendPool, BackendSpec, LbAlgorithm};
use tetrux::lb::bgp::BgpController;
use tetrux::lb::dns::{DnsManager, TargetInput};
use tetrux::lb::health::{spawn_parallel_health_checker, HealthCheckConfig, ProbeMode};
use tetrux::lb::ratelimit::RateLimitConfig;
use tetrux::sys::{self, signal, EndpointV4};

fn print_usage() {
    eprintln!(
        "Tetrux Tier-0 L4 Network Load Balancer\n\
         Usage:\n\
         \ttetrux --mode <tcp|udp> --listen <ip:port> [--backends <spec,...>] [options]\n\n\
         Target Specs (comma-separated in --backends or live via --admin API):\n\
         \t127.0.0.1:9001              Static IPv4 target (default weight = 1)\n\
         \t127.0.0.1:9001@5            Static IPv4 target with weight = 5 (0 = soft-drain)\n\
         \tapi.internal:8080@3         DNS target (multi-A reconciliation, weight = 3)\n\n\
         Dataplane Options:\n\
         \t--workers <N>               Worker threads (default: 4)\n\
         \t--algo <maglev|p2c|rr>      Weighted balancing algorithm (default: p2c)\n\
         \t--busy-poll-us <US>         Adaptive busy-poll window in us (default: 150; 0 = interrupt)\n\
         \t--work-budget <BYTES>       Fair per-turn byte budget per conn (default: 65536)\n\
         \t--max-conns <N>             Max connections per worker (default: 4096)\n\
         \t--proxy-protocol-v2         Prepend HAProxy PROXY Protocol v2 header to backends\n\
         \t--keepalive-secs <S>        TCP keepalive idle time (default: 30; 0 = off)\n\
         \t--rate-limit-rps <N>        Per-source-IP token bucket rate/sec (default: 0 = off)\n\
         \t--rate-limit-burst <N>      Per-source-IP burst capacity (default: 100)\n\
         \t--max-conns-per-ip <N>      Per-source-IP max concurrent conns (default: 0 = off)\n\
         \t--reuseport                 Use per-worker SO_REUSEPORT listeners\n\
         \t--unbatched-udp             Disable recvmsg_x/recvmmsg UDP batching\n\n\
         Tier-0 Ops, Security & HA Options:\n\
         \t--admin <ip:port>           Enable HTTP/JSON + Prometheus /metrics control plane\n\
         \t--admin-token <SECRET>      Require constant-time Bearer token on admin API\n\
         \t--admin-allow <CIDR,...>    Admin client IP allowlist (e.g. 127.0.0.1/32,10.0.0.0/8)\n\
         \t--state-file <PATH>         Persist & auto-reload targets/weights/DNS on SIGHUP/restart\n\
         \t--audit-log                 Emit structured JSON audit records for mutations\n\
         \t--bgp-route-file <PATH>     Write ExaBGP announce/withdraw VIP /32 commands on state change\n\
         \t--drain-timeout-secs <S>    Graceful connection drain window on SIGTERM (default: 30)\n\
         \t--dns-refresh-secs <S>      Background DNS refresh interval (default: 10; 0 = off)\n\
         \t--health-ms <MS>            Parallel non-blocking health probe interval (default: 2000; 0 = off)\n\
         \t--health-http <PATH>        Use HTTP GET <PATH> 2xx probes instead of TCP connect\n\
         \t--max-ejection-pct <PCT>    Panic-mode threshold % (default: 50)\n\
         \t--stats-secs <S>            Periodic stats print interval (default: 5)\n"
    );
}

fn parse_ep(s: &str) -> Result<EndpointV4, String> {
    let sa: SocketAddrV4 = s
        .parse()
        .map_err(|e| format!("invalid IPv4 endpoint '{s}': {e}"))?;
    Ok(EndpointV4::from_std(sa))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 || args.iter().any(|a| a == "-h" || a == "--help") {
        print_usage();
        return;
    }

    let mut mode = "tcp".to_string();
    let mut listen_str = "127.0.0.1:8080".to_string();
    let mut backends_str = String::new();
    let mut admin_str: Option<String> = None;
    let mut admin_token: Option<String> = None;
    let mut admin_allow: Vec<CidrV4> = Vec::new();
    let mut state_file: Option<PathBuf> = None;
    let mut bgp_route_file: Option<PathBuf> = None;
    let mut audit_log = false;
    let mut drain_timeout_secs: u64 = 30;
    let mut dns_refresh_secs: u64 = 10;
    let mut workers: usize = 4;
    let mut algo = LbAlgorithm::P2cLeastConn;
    let mut busy_poll_us: u64 = 150;
    let mut work_budget: usize = 65_536;
    let mut max_conns: usize = 4096;
    let mut proxy_v2 = false;
    let mut keepalive_secs: i32 = 30;
    let mut rate_rps: u32 = 0;
    let mut rate_burst: u32 = 100;
    let mut max_conns_per_ip: u32 = 0;
    let mut reuseport = cfg!(target_os = "linux");
    let mut batched_udp = true;
    let mut health_ms: u64 = 2000;
    let mut health_http_path: Option<String> = None;
    let mut max_ejection_pct: u32 = 50;
    let mut stats_secs: u64 = 5;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" => {
                i += 1;
                mode = args.get(i).cloned().unwrap_or_default();
            }
            "--listen" => {
                i += 1;
                listen_str = args.get(i).cloned().unwrap_or_default();
            }
            "--backends" => {
                i += 1;
                backends_str = args.get(i).cloned().unwrap_or_default();
            }
            "--admin" => {
                i += 1;
                admin_str = args.get(i).cloned();
            }
            "--admin-token" => {
                i += 1;
                admin_token = args.get(i).cloned();
            }
            "--admin-allow" => {
                i += 1;
                if let Some(list) = args.get(i) {
                    for c in list.split(',').filter(|s| !s.trim().is_empty()) {
                        match CidrV4::parse(c) {
                            Ok(cidr) => admin_allow.push(cidr),
                            Err(e) => {
                                eprintln!("{e}");
                                std::process::exit(1);
                            }
                        }
                    }
                }
            }
            "--state-file" => {
                i += 1;
                state_file = args.get(i).map(PathBuf::from);
            }
            "--bgp-route-file" => {
                i += 1;
                bgp_route_file = args.get(i).map(PathBuf::from);
            }
            "--audit-log" => audit_log = true,
            "--drain-timeout-secs" => {
                i += 1;
                drain_timeout_secs = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(30);
            }
            "--dns-refresh-secs" => {
                i += 1;
                dns_refresh_secs = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(10);
            }
            "--workers" => {
                i += 1;
                workers = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(4);
            }
            "--algo" => {
                i += 1;
                algo = match args.get(i).map(|s| s.as_str()) {
                    Some("maglev") => LbAlgorithm::Maglev,
                    Some("rr") => LbAlgorithm::RoundRobin,
                    _ => LbAlgorithm::P2cLeastConn,
                };
            }
            "--busy-poll-us" => {
                i += 1;
                busy_poll_us = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(150);
            }
            "--work-budget" => {
                i += 1;
                work_budget = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(65_536);
            }
            "--max-conns" => {
                i += 1;
                max_conns = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(4096);
            }
            "--proxy-protocol-v2" => proxy_v2 = true,
            "--keepalive-secs" => {
                i += 1;
                keepalive_secs = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(30);
            }
            "--rate-limit-rps" => {
                i += 1;
                rate_rps = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "--rate-limit-burst" => {
                i += 1;
                rate_burst = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(100);
            }
            "--max-conns-per-ip" => {
                i += 1;
                max_conns_per_ip = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "--reuseport" => reuseport = true,
            "--unbatched-udp" => batched_udp = false,
            "--health-ms" => {
                i += 1;
                health_ms = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(2000);
            }
            "--health-http" => {
                i += 1;
                health_http_path = args.get(i).cloned();
            }
            "--max-ejection-pct" => {
                i += 1;
                max_ejection_pct = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(50);
            }
            "--stats-secs" => {
                i += 1;
                stats_secs = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(5);
            }
            other => {
                eprintln!("Unknown option: {other}");
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if backends_str.is_empty() && admin_str.is_none() && state_file.is_none() {
        eprintln!("Error: provide --backends, --state-file, and/or --admin");
        print_usage();
        std::process::exit(1);
    }

    let listen_addr = parse_ep(&listen_str).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });

    signal::install_signal_handlers();
    let nofile = sys::raise_nofile_limit(16_384);
    let pool = BackendPool::new(Vec::new(), algo);
    pool.set_max_ejection_pct(max_ejection_pct);
    let dns = DnsManager::new(Arc::clone(&pool));
    let stop = Arc::new(AtomicBool::new(false));

    // Load persisted state file first if present
    if let Some(ref sf) = state_file {
        if sf.exists() {
            match config::load_state(sf, &pool, &dns) {
                Ok((sc, dc)) => {
                    println!(
                        "Loaded persisted state from {} (static={sc}, dns={dc})",
                        sf.display()
                    );
                }
                Err(e) => eprintln!("Warning: could not load state file {}: {e}", sf.display()),
            }
        }
    }

    // Register CLI targets & DNS subscriptions
    for raw in backends_str.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match TargetInput::parse(raw) {
            Ok(TargetInput::StaticIp { endpoint, weight }) => {
                pool.register_target(BackendSpec::new(endpoint).with_weight(weight));
            }
            Ok(TargetInput::Dns {
                host,
                port,
                weight,
                ..
            }) => match dns.register_dns(&host, port, weight) {
                Ok(rep) => println!(
                    "DNS target '{}' resolved -> {:?} (weight={weight})",
                    rep.key, rep.resolved
                ),
                Err(e) => eprintln!("Warning: DNS resolve failed for {host}:{port}: {e}"),
            },
            Err(e) => {
                eprintln!("Invalid backend spec '{raw}': {e}");
                std::process::exit(1);
            }
        }
    }

    let _dns_thread = if dns_refresh_secs > 0 {
        Some(dns.spawn_refresher(Duration::from_secs(dns_refresh_secs), Arc::clone(&stop)))
    } else {
        None
    };

    let _hc_thread = if health_ms > 0 {
        let hc_cfg = HealthCheckConfig {
            mode: match health_http_path {
                Some(path) => ProbeMode::HttpGet { path },
                None => ProbeMode::TcpConnect,
            },
            interval: Duration::from_millis(health_ms),
            timeout: Duration::from_millis(250),
            rise_threshold: 2,
            fall_threshold: 3,
        };
        Some(spawn_parallel_health_checker(
            Arc::clone(&pool),
            hc_cfg,
            Arc::clone(&stop),
        ))
    } else {
        None
    };

    let rate_limit = RateLimitConfig {
        rate_per_sec: rate_rps,
        burst: rate_burst,
        max_conns_per_ip,
        table_slots: 16_384,
    };

    let cp_cfg = ControlPlaneConfig {
        bearer_token: admin_token,
        allow_cidrs: admin_allow,
        block_metadata_targets: true,
        state_file: state_file.clone(),
        audit_log,
    };

    println!(
        "Tetrux Tier-0 L4 NLB | mode={mode} listen={listen_addr} targets={} workers={workers} algo={algo:?} proxy_v2={proxy_v2} nofile={nofile}",
        pool.list_targets().len()
    );

    match mode.as_str() {
        "tcp" => {
            let mut cfg = TcpEngineConfig::default();
            cfg.listen_addr = listen_addr;
            cfg.workers = workers;
            cfg.accept_strategy = if reuseport {
                AcceptStrategy::ReusePort
            } else {
                AcceptStrategy::ShardedAcceptor
            };
            cfg.busy_poll_us = busy_poll_us;
            cfg.work_budget_bytes = work_budget;
            cfg.max_conns_per_worker = max_conns;
            cfg.proxy_protocol_v2 = proxy_v2;
            cfg.tcp_keepalive_secs = keepalive_secs;
            cfg.rate_limit = rate_limit;
            cfg.health_check_interval = None; // handled by parallel health checker above

            let handle =
                Arc::new(start_tcp_nlb(cfg, Arc::clone(&pool)).expect("failed to start TCP NLB"));
            let bgp = BgpController::new(
                handle.bound_addr(),
                Arc::clone(&pool),
                false,
                bgp_route_file,
            );
            let bgp_st = bgp.evaluate();
            println!(
                "Listening on TCP {} | BGP: {}",
                handle.bound_addr(),
                bgp_st.exabgp_cmd
            );

            let _admin = admin_str.as_ref().map(|addr_s| {
                let ep = parse_ep(addr_s).expect("invalid --admin endpoint");
                let h = Arc::clone(&handle);
                let cp = start_control_plane_with_config(
                    ep,
                    Arc::clone(&pool),
                    Arc::clone(&dns),
                    Some(Arc::clone(&bgp)),
                    StatsProvider::Tcp(Box::new(move || h.stats())),
                    cp_cfg.clone(),
                    Arc::clone(&stop),
                )
                .expect("failed to start control plane");
                println!(
                    "Admin Control Plane listening on http://{} (/targets, /metrics, /bgp, /drain)",
                    cp.bound_addr()
                );
                cp
            });

            let mut tick = 0u64;
            while !signal::shutdown_requested() {
                std::thread::sleep(Duration::from_millis(200));
                tick += 1;
                if signal::take_reload_request() {
                    if let Some(ref sf) = state_file {
                        let _ = config::load_state(sf, &pool, &dns);
                        println!("[SIGHUP] Reloaded state from {}", sf.display());
                    }
                }
                if tick % (stats_secs.max(1) * 5) == 0 {
                    let s = handle.stats();
                    let m = sys::sample_process_metrics();
                    let bst = bgp.evaluate();
                    println!(
                        "[stats] gen={} targets={} panic={} bgp={:?} active={} accepted={} rl_drop={} c2b={:.2}MiB b2c={:.2}MiB rss={:.2}MiB",
                        pool.generation(),
                        pool.list_targets().len(),
                        pool.is_panic_mode(),
                        bst.state,
                        s.active,
                        s.accepted,
                        s.rate_limited,
                        s.bytes_c2b as f64 / (1024.0 * 1024.0),
                        s.bytes_b2c as f64 / (1024.0 * 1024.0),
                        m.current_rss_bytes as f64 / (1024.0 * 1024.0),
                    );
                }
            }

            // Graceful SIGTERM/SIGINT drain sequence!
            println!(
                "Shutdown signal received: withdrawing BGP VIP & draining active TCP connections (max {drain_timeout_secs}s)..."
            );
            let bst = bgp.set_draining(true);
            println!("BGP update: {}", bst.exabgp_cmd);
            handle.begin_drain(Duration::from_secs(drain_timeout_secs));
            stop.store(true, Ordering::Release);
            println!("Graceful drain complete (remaining active={}).", handle.stats().active);
        }
        "udp" => {
            let mut cfg = UdpEngineConfig::default();
            cfg.listen_addr = listen_addr;
            cfg.workers = workers;
            cfg.batched = batched_udp;
            cfg.busy_poll_us = busy_poll_us;
            cfg.rate_limit = rate_limit;
            let handle =
                Arc::new(start_udp_nlb(cfg, Arc::clone(&pool)).expect("failed to start UDP NLB"));
            let bgp = BgpController::new(
                handle.bound_addr(),
                Arc::clone(&pool),
                false,
                bgp_route_file,
            );
            let bst = bgp.evaluate();
            println!(
                "Listening on UDP {} (batched={}) | BGP: {}",
                handle.bound_addr(),
                batched_udp,
                bst.exabgp_cmd
            );

            let _admin = admin_str.as_ref().map(|addr_s| {
                let ep = parse_ep(addr_s).expect("invalid --admin endpoint");
                let h = Arc::clone(&handle);
                let cp = start_control_plane_with_config(
                    ep,
                    Arc::clone(&pool),
                    Arc::clone(&dns),
                    Some(Arc::clone(&bgp)),
                    StatsProvider::Udp(Box::new(move || h.stats())),
                    cp_cfg.clone(),
                    Arc::clone(&stop),
                )
                .expect("failed to start control plane");
                println!("Admin Control Plane listening on http://{}", cp.bound_addr());
                cp
            });

            let mut tick = 0u64;
            while !signal::shutdown_requested() {
                std::thread::sleep(Duration::from_millis(200));
                tick += 1;
                if tick % (stats_secs.max(1) * 5) == 0 {
                    let s = handle.stats();
                    let m = sys::sample_process_metrics();
                    println!(
                        "[udp] gen={} targets={} rx={} tx={} pkts/sc={:.2} reaped={} rl_drop={} rss={:.2}MiB",
                        pool.generation(),
                        pool.list_targets().len(),
                        s.rx_packets,
                        s.tx_packets,
                        s.pkts_per_syscall(),
                        s.sessions_reaped,
                        s.rate_limited,
                        m.current_rss_bytes as f64 / (1024.0 * 1024.0),
                    );
                }
            }
            bgp.set_draining(true);
            stop.store(true, Ordering::Release);
            println!("UDP NLB stopped cleanly.");
        }
        other => {
            eprintln!("Unsupported mode '{other}' (use tcp or udp; run tetrux-bench for bypass benchmarks)");
            std::process::exit(1);
        }
    }
}
