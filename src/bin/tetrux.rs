//! Tetrux — Ultra-Low-Level Rust L4 Network Load Balancer CLI.

use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tetrux::control::{start_control_plane, StatsProvider};
use tetrux::engine::tcp::{start_tcp_nlb, AcceptStrategy, TcpEngineConfig};
use tetrux::engine::udp::{start_udp_nlb, UdpEngineConfig};
use tetrux::lb::balancer::{BackendPool, BackendSpec, LbAlgorithm};
use tetrux::lb::dns::{DnsManager, TargetInput};
use tetrux::sys::{self, EndpointV4};

fn print_usage() {
    eprintln!(
        "Tetrux L4 Network Load Balancer\n\
         Usage:\n\
         \ttetrux --mode <tcp|udp> --listen <ip:port> [--backends <spec,...>] [options]\n\n\
         Target Specs (comma-separated in --backends or live via --admin API):\n\
         \t127.0.0.1:9001              Static IPv4 target (default weight = 1)\n\
         \t127.0.0.1:9001@5            Static IPv4 target with weight = 5\n\
         \tapi.internal:8080@3         DNS target (resolves all A records, weight = 3)\n\
         \tdns://svc.local:8080@10     Explicit DNS pool subscription\n\n\
         Options:\n\
         \t--admin <ip:port>      Enable live HTTP/JSON control plane (e.g. 127.0.0.1:9090)\n\
         \t--dns-refresh-secs <S> Background DNS re-resolution interval (default: 10; 0 = off)\n\
         \t--workers <N>          Worker threads (default: 4)\n\
         \t--algo <maglev|p2c|rr> Weighted balancing algorithm (default: p2c)\n\
         \t--busy-poll-us <US>    Adaptive busy-poll window in us (default: 150; 0 = interrupt)\n\
         \t--work-budget <BYTES>  Fair per-turn byte budget per conn (default: 65536)\n\
         \t--max-conns <N>        Max connections per worker (default: 4096)\n\
         \t--reuseport            Use per-worker SO_REUSEPORT listeners\n\
         \t--unbatched-udp        Disable recvmsg_x/sendmsg_x UDP batching\n\
         \t--health-ms <MS>       Active TCP health check interval in ms (default: 2000; 0 = off)\n\
         \t--stats-secs <S>       Periodic stats print interval (default: 5)\n"
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
    let mut dns_refresh_secs: u64 = 10;
    let mut workers: usize = 4;
    let mut algo = LbAlgorithm::P2cLeastConn;
    let mut busy_poll_us: u64 = 150;
    let mut work_budget: usize = 65_536;
    let mut max_conns: usize = 4096;
    let mut reuseport = cfg!(target_os = "linux");
    let mut batched_udp = true;
    let mut health_ms: u64 = 2000;
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
            "--reuseport" => reuseport = true,
            "--unbatched-udp" => batched_udp = false,
            "--health-ms" => {
                i += 1;
                health_ms = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(2000);
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

    if backends_str.is_empty() && admin_str.is_none() {
        eprintln!("Error: provide --backends and/or --admin (to register targets dynamically)");
        print_usage();
        std::process::exit(1);
    }

    let listen_addr = parse_ep(&listen_str).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });

    let nofile = sys::raise_nofile_limit(16_384);
    let pool = BackendPool::new(Vec::new(), algo);
    let dns = DnsManager::new(Arc::clone(&pool));
    let stop = Arc::new(AtomicBool::new(false));

    // Register initial static IPv4 & DNS targets (with weights!)
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
                Ok(rep) => {
                    println!(
                        "DNS target '{}' resolved -> {:?} (weight={weight})",
                        rep.key, rep.resolved
                    );
                }
                Err(e) => {
                    eprintln!("Warning: initial DNS resolve failed for {host}:{port}: {e}");
                }
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

    println!(
        "Tetrux L4 NLB starting | mode={mode} listen={listen_addr} targets={} workers={workers} algo={algo:?} busy_poll_us={busy_poll_us} nofile={nofile}",
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
            cfg.health_check_interval = if health_ms > 0 {
                Some(Duration::from_millis(health_ms))
            } else {
                None
            };

            let handle = Arc::new(start_tcp_nlb(cfg, Arc::clone(&pool)).expect("failed to start TCP NLB"));
            let _admin = admin_str.as_ref().map(|addr_s| {
                let ep = parse_ep(addr_s).expect("invalid --admin endpoint");
                let h = Arc::clone(&handle);
                let cp = start_control_plane(
                    ep,
                    Arc::clone(&pool),
                    Arc::clone(&dns),
                    StatsProvider::Tcp(Box::new(move || h.stats())),
                    Arc::clone(&stop),
                )
                .expect("failed to start control plane");
                println!("Admin HTTP/JSON Control Plane listening on http://{}", cp.bound_addr());
                cp
            });

            println!("Listening on TCP {}", handle.bound_addr());
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(stats_secs.max(1)));
                let s = handle.stats();
                let m = sys::sample_process_metrics();
                println!(
                    "[stats] gen={} targets={} active={} accepted={} rejected={} c2b={:.2}MiB b2c={:.2}MiB fast_wr={} buf_wr={} rss={:.2}MiB",
                    pool.generation(),
                    pool.list_targets().len(),
                    s.active,
                    s.accepted,
                    s.rejected,
                    s.bytes_c2b as f64 / (1024.0 * 1024.0),
                    s.bytes_b2c as f64 / (1024.0 * 1024.0),
                    s.fast_path_writes,
                    s.buffered_writes,
                    m.current_rss_bytes as f64 / (1024.0 * 1024.0),
                );
            }
        }
        "udp" => {
            let mut cfg = UdpEngineConfig::default();
            cfg.listen_addr = listen_addr;
            cfg.batched = batched_udp;
            cfg.busy_poll_us = busy_poll_us;
            let handle = Arc::new(start_udp_nlb(cfg, Arc::clone(&pool)).expect("failed to start UDP NLB"));
            let _admin = admin_str.as_ref().map(|addr_s| {
                let ep = parse_ep(addr_s).expect("invalid --admin endpoint");
                let h = Arc::clone(&handle);
                let cp = start_control_plane(
                    ep,
                    Arc::clone(&pool),
                    Arc::clone(&dns),
                    StatsProvider::Udp(Box::new(move || h.stats())),
                    Arc::clone(&stop),
                )
                .expect("failed to start control plane");
                println!("Admin HTTP/JSON Control Plane listening on http://{}", cp.bound_addr());
                cp
            });
            println!(
                "Listening on UDP {} (batched={})",
                handle.bound_addr(),
                batched_udp
            );
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(stats_secs.max(1)));
                let s = handle.stats();
                let m = sys::sample_process_metrics();
                println!(
                    "[udp] gen={} targets={} rx_pkts={} tx_pkts={} pkts/syscall={:.2} drops={} sessions={} rss={:.2}MiB",
                    pool.generation(),
                    pool.list_targets().len(),
                    s.rx_packets,
                    s.tx_packets,
                    s.pkts_per_syscall(),
                    s.drops,
                    s.sessions_created,
                    m.current_rss_bytes as f64 / (1024.0 * 1024.0),
                );
            }
        }
        other => {
            eprintln!("Unsupported mode '{other}' (use tcp or udp; run tetrux-bench for bypass benchmarks)");
            std::process::exit(1);
        }
    }
}
