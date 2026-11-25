//! Zero-dependency HTTP/JSON Admin Control Plane for live L4 target management:
//! - `GET  /health`           -> liveness + routing generation
//! - `GET  /targets`          -> list all targets, weights, traffic shares, health, conns & DNS pools
//! - `POST /targets`          -> register IPv4 or DNS target (with weight & optional DSR MAC)
//! - `PUT  /targets/weight`   -> live-tune weight (`0` = soft-drain, `1..=1000` = proportional share)
//! - `DELETE /targets`        -> deregister IPv4 or DNS target (`drain: true` default)
//! - `POST /targets/deregister` -> alias for `DELETE /targets`
//! - `POST /dns/refresh`      -> force immediate DNS pool reconciliation
//! - `GET  /stats`            -> live dataplane + RSS/CPU JSON telemetry
//!
//! Runs on a dedicated low-priority thread completely isolated from dataplane workers.

use crate::engine::tcp::TcpStatsSnapshot;
use crate::engine::udp::UdpStatsSnapshot;
use crate::lb::balancer::{BackendPool, BackendSpec, MutationOutcome};
use crate::lb::dns::{DnsManager, TargetInput};
use crate::sys::{self, EndpointV4};
use std::io::{Read, Write};
use std::net::{SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

/// Optional live dataplane stats provider callback plugged in by CLI/runner.
pub enum StatsProvider {
    None,
    Tcp(Box<dyn Fn() -> TcpStatsSnapshot + Send + Sync>),
    Udp(Box<dyn Fn() -> UdpStatsSnapshot + Send + Sync>),
}

pub struct ControlPlaneHandle {
    bound_addr: EndpointV4,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlPlaneHandle {
    pub fn bound_addr(&self) -> EndpointV4 {
        self.bound_addr
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for ControlPlaneHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub fn start_control_plane(
    listen_addr: EndpointV4,
    pool: Arc<BackendPool>,
    dns: Arc<DnsManager>,
    stats: StatsProvider,
    stop: Arc<AtomicBool>,
) -> std::io::Result<ControlPlaneHandle> {
    let listener = TcpListener::bind(listen_addr.to_std())?;
    let bound_addr = match listener.local_addr()? {
        std::net::SocketAddr::V4(v4) => EndpointV4::from_std(v4),
        _ => listen_addr,
    };
    listener.set_nonblocking(true)?;

    let stop_c = Arc::clone(&stop);
    let stats_arc = Arc::new(stats);
    let thread = std::thread::Builder::new()
        .name("tetrux-admin".to_string())
        .spawn(move || {
            while !stop_c.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                        handle_http_connection(&mut stream, &pool, &dns, &stats_arc);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        })?;

    Ok(ControlPlaneHandle {
        bound_addr,
        stop,
        thread: Some(thread),
    })
}

fn handle_http_connection(
    stream: &mut TcpStream,
    pool: &BackendPool,
    dns: &DnsManager,
    stats: &StatsProvider,
) {
    let mut buf = vec![0u8; 16_384];
    let mut total = 0usize;
    let mut header_end = None;
    let mut content_len = 0usize;

    loop {
        if total >= buf.len() {
            break;
        }
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if header_end.is_none() {
                    if let Some(pos) = find_subslice(&buf[..total], b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        let hdr_str = String::from_utf8_lossy(&buf[..pos]);
                        for line in hdr_str.lines().skip(1) {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    content_len = v.trim().parse().unwrap_or(0);
                                }
                            }
                        }
                    }
                }
                if let Some(he) = header_end {
                    if total >= he + content_len {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }

    if total == 0 {
        return;
    }
    let req_str = String::from_utf8_lossy(&buf[..total]);
    let first_line = req_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path_and_query = parts.next().unwrap_or("/");
    let path = path_and_query.split('?').next().unwrap_or("/");
    let body = match header_end {
        Some(he) if he <= total => &req_str[he..total.min(he + content_len.max(total - he))],
        _ => "",
    };

    let (status_code, status_text, json_body) =
        dispatch_request(method, path, body, pool, dns, stats);
    let resp = format!(
        "HTTP/1.1 {status_code} {status_text}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        json_body.len(),
        json_body
    );
    let _ = stream.write_all(resp.as_bytes());
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

/// Minimal flat-JSON string extractor: finds `"key": "value"`.
fn json_get_str(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = body.find(&needle)? + needle.len();
    let rest = body[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(esc) = chars.next() {
                out.push(esc);
            }
        } else if c == '"' {
            return Some(out);
        } else {
            out.push(c);
        }
    }
    None
}

/// Minimal flat-JSON u32 extractor: finds `"key": 123`.
fn json_get_u32(body: &str, key: &str) -> Option<u32> {
    let needle = format!("\"{key}\"");
    let start = body.find(&needle)? + needle.len();
    let rest = body[start..].trim_start().strip_prefix(':')?.trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

/// Minimal flat-JSON bool extractor: finds `"key": true|false`.
fn json_get_bool(body: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\"");
    let start = body.find(&needle)? + needle.len();
    let rest = body[start..].trim_start().strip_prefix(':')?.trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

/// Pure request router — directly callable both by the HTTP server and by unit tests.
pub fn dispatch_request(
    method: &str,
    path: &str,
    body: &str,
    pool: &BackendPool,
    dns: &DnsManager,
    stats: &StatsProvider,
) -> (u16, &'static str, String) {
    match (method, path) {
        ("GET", "/health") => {
            let targets = pool.list_targets().len();
            let gen = pool.generation();
            (
                200,
                "OK",
                format!(r#"{{"status":"ok","generation":{gen},"targets":{targets}}}"#),
            )
        }

        ("GET", "/targets") => {
            let targets = pool.list_targets();
            let subs = dns.list_subscriptions();
            let mut j = String::with_capacity(512);
            j.push_str(&format!(
                r#"{{"generation":{},"algorithm":"{:?}","targets":["#,
                pool.generation(),
                pool.algo
            ));
            for (idx, t) in targets.iter().enumerate() {
                if idx > 0 {
                    j.push(',');
                }
                let dns_val = match &t.dns_source {
                    Some(s) => format!("\"{}\"", json_escape(s)),
                    None => "null".to_string(),
                };
                j.push_str(&format!(
                    r#"{{"slot_id":{},"endpoint":"{}","dns_source":{},"weight":{},"effective_share_pct":{:.2},"healthy":{},"draining":{},"active_conns":{},"total_conns":{},"ewma_connect_us":{:.1}}}"#,
                    t.slot_id,
                    t.endpoint,
                    dns_val,
                    t.weight,
                    t.effective_share_pct,
                    t.healthy,
                    t.draining,
                    t.active_conns,
                    t.total_conns,
                    t.ewma_connect_us
                ));
            }
            j.push_str(r#"],"dns_subscriptions":["#);
            for (idx, s) in subs.iter().enumerate() {
                if idx > 0 {
                    j.push(',');
                }
                let ips: Vec<String> = s.resolved.iter().map(|e| format!("\"{e}\"")).collect();
                let err_val = match &s.last_error {
                    Some(e) => format!("\"{}\"", json_escape(e)),
                    None => "null".to_string(),
                };
                j.push_str(&format!(
                    r#"{{"key":"{}","weight":{},"resolved":[{}],"last_error":{}}}"#,
                    json_escape(&s.key),
                    s.weight,
                    ips.join(","),
                    err_val
                ));
            }
            j.push_str("]}");
            (200, "OK", j)
        }

        ("POST", "/targets") | ("POST", "/targets/register") => {
            let explicit_weight = json_get_u32(body, "weight");
            let mac = json_get_str(body, "mac").and_then(|s| parse_mac(&s));

            // Accept {"dns":"host:port","weight":3} OR {"addr":"1.2.3.4:80","weight":5}
            // OR {"target":"host:port@3"} OR raw body "1.2.3.4:80@5"
            if let Some(dns_spec) = json_get_str(body, "dns") {
                let parsed = match TargetInput::parse(&format!("dns://{dns_spec}")) {
                    Ok(TargetInput::Dns {
                        host,
                        port,
                        weight,
                        ..
                    }) => (host, port, explicit_weight.unwrap_or(weight)),
                    Ok(_) => unreachable!(),
                    Err(e) => {
                        return (
                            400,
                            "Bad Request",
                            format!(r#"{{"error":"{}"}}"#, json_escape(&e)),
                        );
                    }
                };
                return match dns.register_dns(&parsed.0, parsed.1, parsed.2) {
                    Ok(rep) => {
                        let ips: Vec<String> =
                            rep.resolved.iter().map(|e| format!("\"{e}\"")).collect();
                        (
                            200,
                            "OK",
                            format!(
                                r#"{{"status":"registered_dns","dns":"{}","weight":{},"resolved":[{}],"added":{},"drained":{},"generation":{}}}"#,
                                json_escape(&rep.key),
                                parsed.2,
                                ips.join(","),
                                rep.added,
                                rep.drained,
                                rep.generation
                            ),
                        )
                    }
                    Err(e) => (
                        502,
                        "Bad Gateway",
                        format!(r#"{{"error":"DNS resolve failed: {}"}}"#, json_escape(&e.to_string())),
                    ),
                };
            }

            let raw_spec = json_get_str(body, "addr")
                .or_else(|| json_get_str(body, "target"))
                .unwrap_or_else(|| body.trim().to_string());

            match TargetInput::parse(&raw_spec) {
                Ok(TargetInput::StaticIp { endpoint, weight }) => {
                    let w = explicit_weight.unwrap_or(weight);
                    let mut spec = BackendSpec::new(endpoint).with_weight(w);
                    if let Some(m) = mac {
                        spec = spec.with_mac(m);
                    }
                    match pool.register_target(spec) {
                        MutationOutcome::Registered {
                            slot_id,
                            generation,
                        } => (
                            200,
                            "OK",
                            format!(
                                r#"{{"status":"registered","endpoint":"{endpoint}","slot_id":{slot_id},"weight":{w},"generation":{generation}}}"#
                            ),
                        ),
                        MutationOutcome::Updated {
                            slot_id,
                            generation,
                        } => (
                            200,
                            "OK",
                            format!(
                                r#"{{"status":"updated","endpoint":"{endpoint}","slot_id":{slot_id},"weight":{w},"generation":{generation}}}"#
                            ),
                        ),
                        MutationOutcome::PoolFull => (
                            409,
                            "Conflict",
                            r#"{"error":"backend pool reached MAX_BACKENDS capacity"}"#.to_string(),
                        ),
                        _ => (500, "Internal Server Error", r#"{"error":"unexpected outcome"}"#.to_string()),
                    }
                }
                Ok(TargetInput::Dns {
                    host,
                    port,
                    weight,
                    ..
                }) => {
                    let w = explicit_weight.unwrap_or(weight);
                    match dns.register_dns(&host, port, w) {
                        Ok(rep) => {
                            let ips: Vec<String> =
                                rep.resolved.iter().map(|e| format!("\"{e}\"")).collect();
                            (
                                200,
                                "OK",
                                format!(
                                    r#"{{"status":"registered_dns","dns":"{}","weight":{w},"resolved":[{}],"added":{},"drained":{},"generation":{}}}"#,
                                    json_escape(&rep.key),
                                    ips.join(","),
                                    rep.added,
                                    rep.drained,
                                    rep.generation
                                ),
                            )
                        }
                        Err(e) => (
                            502,
                            "Bad Gateway",
                            format!(r#"{{"error":"DNS resolve failed: {}"}}"#, json_escape(&e.to_string())),
                        ),
                    }
                }
                Err(e) => (
                    400,
                    "Bad Request",
                    format!(r#"{{"error":"{}"}}"#, json_escape(&e)),
                ),
            }
        }

        ("PUT", "/targets/weight")
        | ("PATCH", "/targets/weight")
        | ("POST", "/targets/weight") => {
            let Some(weight) = json_get_u32(body, "weight") else {
                return (
                    400,
                    "Bad Request",
                    r#"{"error":"missing integer field 'weight' (0..=1000)"}"#.to_string(),
                );
            };
            if let Some(dns_key) = json_get_str(body, "dns") {
                return match dns.set_dns_weight(&dns_key, weight) {
                    Some((updated, gen)) => (
                        200,
                        "OK",
                        format!(
                            r#"{{"status":"updated_dns_weight","dns":"{}","weight":{weight},"targets_updated":{updated},"generation":{gen}}}"#,
                            json_escape(&dns_key)
                        ),
                    ),
                    None => (
                        404,
                        "Not Found",
                        format!(r#"{{"error":"DNS subscription '{}' not found"}}"#, json_escape(&dns_key)),
                    ),
                };
            }
            let Some(addr_str) = json_get_str(body, "addr").or_else(|| json_get_str(body, "target"))
            else {
                return (
                    400,
                    "Bad Request",
                    r#"{"error":"missing 'addr' or 'dns' field"}"#.to_string(),
                );
            };
            if let Ok(sa) = addr_str.parse::<SocketAddrV4>() {
                let ep = EndpointV4::from_std(sa);
                match pool.set_weight(ep, weight) {
                    MutationOutcome::Updated {
                        slot_id,
                        generation,
                    } => (
                        200,
                        "OK",
                        format!(
                            r#"{{"status":"updated","endpoint":"{ep}","slot_id":{slot_id},"weight":{weight},"generation":{generation}}}"#
                        ),
                    ),
                    _ => (
                        404,
                        "Not Found",
                        format!(r#"{{"error":"target '{ep}' not found"}}"#),
                    ),
                }
            } else {
                // Allow tuning a DNS pool by passing its key in `addr`/`target` too
                match dns.set_dns_weight(&addr_str, weight) {
                    Some((updated, gen)) => (
                        200,
                        "OK",
                        format!(
                            r#"{{"status":"updated_dns_weight","dns":"{}","weight":{weight},"targets_updated":{updated},"generation":{gen}}}"#,
                            json_escape(&addr_str)
                        ),
                    ),
                    None => (
                        404,
                        "Not Found",
                        format!(r#"{{"error":"target '{}' not found"}}"#, json_escape(&addr_str)),
                    ),
                }
            }
        }

        ("DELETE", "/targets") | ("POST", "/targets/deregister") => {
            let drain = json_get_bool(body, "drain").unwrap_or(true);
            if let Some(dns_key) = json_get_str(body, "dns") {
                return match dns.deregister_dns(&dns_key, drain) {
                    Some((affected, gen)) => (
                        200,
                        "OK",
                        format!(
                            r#"{{"status":"{}","dns":"{}","targets_affected":{affected},"generation":{gen}}}"#,
                            if drain { "draining_dns" } else { "removed_dns" },
                            json_escape(&dns_key)
                        ),
                    ),
                    None => (
                        404,
                        "Not Found",
                        format!(r#"{{"error":"DNS subscription '{}' not found"}}"#, json_escape(&dns_key)),
                    ),
                };
            }
            let raw = json_get_str(body, "addr")
                .or_else(|| json_get_str(body, "target"))
                .unwrap_or_else(|| body.trim().to_string());
            if let Ok(sa) = raw.parse::<SocketAddrV4>() {
                let ep = EndpointV4::from_std(sa);
                match pool.deregister_target(ep, drain) {
                    MutationOutcome::Draining {
                        slot_id,
                        active_conns,
                        generation,
                    } => (
                        200,
                        "OK",
                        format!(
                            r#"{{"status":"draining","endpoint":"{ep}","slot_id":{slot_id},"active_conns":{active_conns},"generation":{generation}}}"#
                        ),
                    ),
                    MutationOutcome::Removed {
                        slot_id,
                        generation,
                    } => (
                        200,
                        "OK",
                        format!(
                            r#"{{"status":"removed","endpoint":"{ep}","slot_id":{slot_id},"generation":{generation}}}"#
                        ),
                    ),
                    _ => (
                        404,
                        "Not Found",
                        format!(r#"{{"error":"target '{ep}' not found"}}"#),
                    ),
                }
            } else if let Some((affected, gen)) = dns.deregister_dns(&raw, drain) {
                (
                    200,
                    "OK",
                    format!(
                        r#"{{"status":"{}","dns":"{}","targets_affected":{affected},"generation":{gen}}}"#,
                        if drain { "draining_dns" } else { "removed_dns" },
                        json_escape(&raw)
                    ),
                )
            } else {
                (
                    404,
                    "Not Found",
                    format!(r#"{{"error":"target '{}' not found"}}"#, json_escape(&raw)),
                )
            }
        }

        ("POST", "/dns/refresh") => {
            let changes = dns.refresh_all();
            let gen = pool.generation();
            (
                200,
                "OK",
                format!(r#"{{"status":"refreshed","changes":{changes},"generation":{gen}}}"#),
            )
        }

        ("GET", "/stats") => {
            let m = sys::sample_process_metrics();
            let rss_mib = m.current_rss_bytes as f64 / (1024.0 * 1024.0);
            let gen = pool.generation();
            let body = match stats {
                StatsProvider::Tcp(f) => {
                    let s = f();
                    let fast_pct = if s.fast_path_writes + s.buffered_writes > 0 {
                        (s.fast_path_writes as f64 / (s.fast_path_writes + s.buffered_writes) as f64)
                            * 100.0
                    } else {
                        100.0
                    };
                    format!(
                        r#"{{"mode":"tcp","generation":{gen},"active_conns":{},"peak_active_conns":{},"accepted":{},"rejected":{},"bytes_c2b":{},"bytes_b2c":{},"fast_path_pct":{:.2},"wakeups_sent":{},"wakeups_suppressed":{},"nlb_cpu_ms":{:.2},"rss_mib":{:.2}}}"#,
                        s.active,
                        s.peak_active,
                        s.accepted,
                        s.rejected,
                        s.bytes_c2b,
                        s.bytes_b2c,
                        fast_pct,
                        s.wakeups_sent,
                        s.wakeups_suppressed,
                        s.worker_cpu_ns as f64 / 1_000_000.0,
                        rss_mib
                    )
                }
                StatsProvider::Udp(f) => {
                    let s = f();
                    format!(
                        r#"{{"mode":"udp","generation":{gen},"rx_packets":{},"tx_packets":{},"pkts_per_syscall":{:.2},"drops":{},"sessions":{},"nlb_cpu_ms":{:.2},"rss_mib":{:.2}}}"#,
                        s.rx_packets,
                        s.tx_packets,
                        s.pkts_per_syscall(),
                        s.drops,
                        s.sessions_created,
                        s.worker_cpu_ns as f64 / 1_000_000.0,
                        rss_mib
                    )
                }
                StatsProvider::None => {
                    format!(r#"{{"mode":"none","generation":{gen},"rss_mib":{:.2}}}"#, rss_mib)
                }
            };
            (200, "OK", body)
        }

        _ => (
            404,
            "Not Found",
            r#"{"error":"unknown endpoint; use GET /health, GET /targets, POST /targets, PUT /targets/weight, DELETE /targets, POST /dns/refresh, GET /stats"}"#.to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lb::balancer::LbAlgorithm;

    #[test]
    fn control_plane_register_reweight_dns_and_deregister_roundtrip() {
        let pool = BackendPool::new(Vec::new(), LbAlgorithm::P2cLeastConn);
        let dns = DnsManager::with_resolver(
            Arc::clone(&pool),
            Box::new(|host, port| {
                if host == "api.internal" {
                    Ok(vec![
                        EndpointV4::from_octets(10, 0, 0, 10, port),
                        EndpointV4::from_octets(10, 0, 0, 11, port),
                    ])
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "nxdomain"))
                }
            }),
        );
        let stats = StatsProvider::None;

        // 1. Register static weighted target
        let (code, _, resp) = dispatch_request(
            "POST",
            "/targets",
            r#"{"addr":"127.0.0.1:9001","weight":5}"#,
            &pool,
            &dns,
            &stats,
        );
        assert_eq!(code, 200, "{resp}");
        assert!(resp.contains("\"status\":\"registered\""));

        // 2. Register DNS pool
        let (code, _, resp) = dispatch_request(
            "POST",
            "/targets",
            r#"{"dns":"api.internal:8080","weight":3}"#,
            &pool,
            &dns,
            &stats,
        );
        assert_eq!(code, 200, "{resp}");
        assert!(resp.contains("\"added\":2"));

        // 3. Tune weight live
        let (code, _, resp) = dispatch_request(
            "PUT",
            "/targets/weight",
            r#"{"addr":"127.0.0.1:9001","weight":9}"#,
            &pool,
            &dns,
            &stats,
        );
        assert_eq!(code, 200, "{resp}");
        assert!(resp.contains("\"weight\":9"));

        // 4. List targets -> 3 targets (1 static + 2 DNS)
        let (code, _, resp) = dispatch_request("GET", "/targets", "", &pool, &dns, &stats);
        assert_eq!(code, 200);
        assert!(resp.contains("127.0.0.1:9001"));
        assert!(resp.contains("10.0.0.10:8080"));
        assert!(resp.contains("10.0.0.11:8080"));

        // 5. Deregister DNS pool
        let (code, _, resp) = dispatch_request(
            "DELETE",
            "/targets",
            r#"{"dns":"api.internal:8080","drain":true}"#,
            &pool,
            &dns,
            &stats,
        );
        assert_eq!(code, 200, "{resp}");
        assert_eq!(pool.list_targets().len(), 1);
    }
}
