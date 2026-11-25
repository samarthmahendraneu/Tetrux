//! Async Parallel Non-Blocking Health Checker driven by `sys::Poller` (`kqueue`/`epoll`).
//!
//! Probes hundreds of targets simultaneously in ~1 ms per sweep (never sequential blocking!):
//! - Supports L4 TCP Connect probes AND L7 HTTP `GET <path>` 200-OK probes
//! - Hysteresis (`rise_threshold` / `fall_threshold`) eliminates backend flapping
//! - ±10% jitter prevents synchronized fleet-wide health-check thundering herds
//! - Integrates with `BackendPool`'s panic-threshold (`max_ejection_pct`) & draining reaper

use super::balancer::BackendPool;
use super::hash::Xorshift64;
use crate::sys::{self, Fd, IoStatus, Poller};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Clone, Debug)]
pub enum ProbeMode {
    /// Non-blocking TCP 3-way handshake verification.
    TcpConnect,
    /// Non-blocking TCP connect + HTTP/1.1 `GET <path>` expecting 2xx response.
    HttpGet { path: String },
}

#[derive(Clone, Debug)]
pub struct HealthCheckConfig {
    pub mode: ProbeMode,
    pub interval: Duration,
    pub timeout: Duration,
    /// Consecutive passes required to mark an unhealthy target healthy (prevents flapping).
    pub rise_threshold: u32,
    /// Consecutive failures required to eject a healthy target.
    pub fall_threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            mode: ProbeMode::TcpConnect,
            interval: Duration::from_secs(2),
            timeout: Duration::from_millis(250),
            rise_threshold: 2,
            fall_threshold: 3,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbePhase {
    Connecting,
    ReadingHttp,
}

struct ActiveProbe {
    slot_id: u16,
    fd: Fd,
    phase: ProbePhase,
    rx_buf: [u8; 64],
    rx_len: usize,
}

/// Execute ONE parallel non-blocking sweep across all non-draining targets in `pool`.
pub fn run_parallel_sweep(pool: &BackendPool, cfg: &HealthCheckConfig) {
    let targets = pool.list_targets();
    let mut need_reap = false;
    let mut poller = match Poller::new(targets.len().max(64)) {
        Ok(p) => p,
        Err(_) => return,
    };

    let mut active: HashMap<u64, ActiveProbe> = HashMap::with_capacity(targets.len());
    let mut next_tok = 1u64;

    let http_req: Option<Vec<u8>> = match &cfg.mode {
        ProbeMode::TcpConnect => None,
        ProbeMode::HttpGet { path } => Some(
            format!("GET {path} HTTP/1.1\r\nHost: tetrux-hc\r\nConnection: close\r\n\r\n")
                .into_bytes(),
        ),
    };

    for t in &targets {
        if t.draining {
            if t.active_conns == 0 {
                need_reap = true;
            }
            continue;
        }
        match sys::connect_nonblock(t.endpoint, 0) {
            Ok((fd, immediate)) => {
                if immediate {
                    match &http_req {
                        None => {
                            sys::close_fd(fd);
                            pool.record_probe_result(
                                t.slot_id as usize,
                                true,
                                cfg.rise_threshold,
                                cfg.fall_threshold,
                            );
                        }
                        Some(req) => {
                            if matches!(sys::write_nb(fd, req), IoStatus::Ok(n) if n == req.len()) {
                                let tok = next_tok;
                                next_tok += 1;
                                poller.add_read(fd, tok, false);
                                active.insert(
                                    tok,
                                    ActiveProbe {
                                        slot_id: t.slot_id,
                                        fd,
                                        phase: ProbePhase::ReadingHttp,
                                        rx_buf: [0; 64],
                                        rx_len: 0,
                                    },
                                );
                            } else {
                                sys::close_fd(fd);
                                pool.record_probe_result(
                                    t.slot_id as usize,
                                    false,
                                    cfg.rise_threshold,
                                    cfg.fall_threshold,
                                );
                            }
                        }
                    }
                } else {
                    let tok = next_tok;
                    next_tok += 1;
                    poller.add_connect_write(fd, tok);
                    active.insert(
                        tok,
                        ActiveProbe {
                            slot_id: t.slot_id,
                            fd,
                            phase: ProbePhase::Connecting,
                            rx_buf: [0; 64],
                            rx_len: 0,
                        },
                    );
                }
            }
            Err(_) => {
                pool.record_probe_result(
                    t.slot_id as usize,
                    false,
                    cfg.rise_threshold,
                    cfg.fall_threshold,
                );
            }
        }
    }

    let deadline_ns = sys::fast_now_ns().saturating_add(cfg.timeout.as_nanos() as u64);
    let mut events = Vec::with_capacity(targets.len().max(64));

    while !active.is_empty() {
        let now = sys::fast_now_ns();
        if now >= deadline_ns {
            break;
        }
        let rem_ns = (deadline_ns - now).min(20_000_000);
        let n = poller.poll(&mut events, Some(rem_ns)).unwrap_or(0);
        if n == 0 {
            continue;
        }
        for i in 0..events.len() {
            let ev = events[i];
            if ev.is_user {
                continue;
            }
            let Some(mut probe) = active.remove(&ev.token) else {
                continue;
            };
            if ev.error {
                sys::close_fd(probe.fd);
                pool.record_probe_result(
                    probe.slot_id as usize,
                    false,
                    cfg.rise_threshold,
                    cfg.fall_threshold,
                );
                continue;
            }
            match probe.phase {
                ProbePhase::Connecting => {
                    let ok = matches!(sys::get_socket_error(probe.fd), Ok(0));
                    if !ok {
                        sys::close_fd(probe.fd);
                        pool.record_probe_result(
                            probe.slot_id as usize,
                            false,
                            cfg.rise_threshold,
                            cfg.fall_threshold,
                        );
                        continue;
                    }
                    match &http_req {
                        None => {
                            sys::close_fd(probe.fd);
                            pool.record_probe_result(
                                probe.slot_id as usize,
                                true,
                                cfg.rise_threshold,
                                cfg.fall_threshold,
                            );
                        }
                        Some(req) => {
                            if matches!(sys::write_nb(probe.fd, req), IoStatus::Ok(w) if w == req.len())
                            {
                                probe.phase = ProbePhase::ReadingHttp;
                                poller.add_read(probe.fd, ev.token, false);
                                active.insert(ev.token, probe);
                            } else {
                                sys::close_fd(probe.fd);
                                pool.record_probe_result(
                                    probe.slot_id as usize,
                                    false,
                                    cfg.rise_threshold,
                                    cfg.fall_threshold,
                                );
                            }
                        }
                    }
                }
                ProbePhase::ReadingHttp => {
                    let space = probe.rx_buf.len() - probe.rx_len;
                    if space > 0 {
                        if let IoStatus::Ok(r) =
                            sys::read_nb(probe.fd, &mut probe.rx_buf[probe.rx_len..])
                        {
                            probe.rx_len += r;
                        }
                    }
                    if probe.rx_len >= 12 || ev.eof {
                        let ok = is_http_2xx(&probe.rx_buf[..probe.rx_len]);
                        sys::close_fd(probe.fd);
                        pool.record_probe_result(
                            probe.slot_id as usize,
                            ok,
                            cfg.rise_threshold,
                            cfg.fall_threshold,
                        );
                    } else {
                        active.insert(ev.token, probe);
                    }
                }
            }
        }
    }

    // Any probes still pending past deadline timed out -> mark failed
    for (_, probe) in active.drain() {
        sys::close_fd(probe.fd);
        pool.record_probe_result(
            probe.slot_id as usize,
            false,
            cfg.rise_threshold,
            cfg.fall_threshold,
        );
    }

    if need_reap {
        pool.reap_drained_slots();
    }
}

fn is_http_2xx(resp: &[u8]) -> bool {
    // Matches "HTTP/1.1 2.." or "HTTP/1.0 2.."
    resp.len() >= 12
        && resp.starts_with(b"HTTP/1.")
        && resp[8] == b' '
        && resp[9] == b'2'
        && resp[10].is_ascii_digit()
        && resp[11].is_ascii_digit()
}

pub fn spawn_parallel_health_checker(
    pool: Arc<BackendPool>,
    cfg: HealthCheckConfig,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("tetrux-health".to_string())
        .spawn(move || {
            let mut rng = Xorshift64::new(sys::fast_now_ns() ^ 0x4845_414c_5448);
            while !stop.load(Ordering::Relaxed) {
                run_parallel_sweep(&pool, &cfg);
                // ±10% jitter to avoid fleet-wide probe synchronization
                let base_ms = cfg.interval.as_millis().max(100) as u64;
                let jitter_span = (base_ms / 5).max(1);
                let jitter = rng.next_bounded(jitter_span as usize) as u64;
                let wait_ms = base_ms.saturating_sub(jitter_span / 2).saturating_add(jitter);
                let mut slept = 0u64;
                while slept < wait_ms && !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(50));
                    slept += 50;
                }
            }
        })
        .unwrap_or_else(|e| panic!("failed to spawn health checker: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lb::balancer::{BackendSpec, LbAlgorithm};
    use crate::sys::EndpointV4;

    #[test]
    fn hysteresis_and_panic_mode_threshold() {
        let specs: Vec<BackendSpec> = (1..=4)
            .map(|i| BackendSpec::new(EndpointV4::from_octets(10, 0, 0, i, 8080)).with_weight(1))
            .collect();
        let pool = BackendPool::new(specs, LbAlgorithm::RoundRobin);
        pool.set_max_ejection_pct(50);

        // 2 failures on slot 0 (< fall_threshold=3) must NOT eject it
        pool.record_probe_result(0, false, 2, 3);
        pool.record_probe_result(0, false, 2, 3);
        assert!(pool.list_targets()[0].healthy);
        assert!(!pool.is_panic_mode());

        // 3rd failure ejects slot 0 (1/4 = 25% <= 50% -> normal mode)
        pool.record_probe_result(0, false, 2, 3);
        assert!(!pool.list_targets()[0].healthy);
        assert!(!pool.is_panic_mode());

        // Eject slot 1 (2/4 = 50% <= 50% -> still normal mode)
        for _ in 0..3 {
            pool.record_probe_result(1, false, 2, 3);
        }
        assert!(!pool.is_panic_mode());
        assert_eq!(pool.snapshot().healthy_ids.len(), 2);

        // Eject slot 2 (3/4 = 75% > 50% -> PANIC MODE triggers, fails open to all 4!)
        for _ in 0..3 {
            pool.record_probe_result(2, false, 2, 3);
        }
        assert!(pool.is_panic_mode());
        assert_eq!(pool.snapshot().healthy_ids.len(), 4);

        // Restore slot 2 requires rise_threshold=2 consecutive successes!
        pool.record_probe_result(2, true, 2, 3);
        assert!(pool.is_panic_mode()); // only 1 pass so far
        pool.record_probe_result(2, true, 2, 3);
        assert!(!pool.is_panic_mode()); // back to 50% ejected -> exits panic mode!
    }

    #[test]
    fn http_2xx_parser_check() {
        assert!(is_http_2xx(b"HTTP/1.1 200 OK\r\n"));
        assert!(is_http_2xx(b"HTTP/1.0 204 No Content\r\n"));
        assert!(!is_http_2xx(b"HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(!is_http_2xx(b"HTTP/1.1 404"));
    }
}
