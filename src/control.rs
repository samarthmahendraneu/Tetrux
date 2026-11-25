//! Tier-0 Hardened Zero-Dependency HTTP/JSON & Prometheus Control Plane.
//!
//! Security & Resilience features:
//! - Constant-time Bearer Token Authentication (`Authorization: Bearer <token>`)
//! - Admin Client Source-IP CIDR Allowlist (`403 Forbidden` before body read)
//! - Backend Target SSRF / Cloud-Metadata CIDR Guard (blocks `169.254.0.0/16` & `0.0.0.0/8`)
//! - Bounded concurrent handler pool (max 16 in-flight, 64 KiB cap, 1s timeout -> slowloris-proof)
//! - `catch_unwind` isolation (control-plane errors can NEVER crash the dataplane!)
//! - Strict RFC-8259 JSON parser (`crate::proto::json::parse_json`)
//! - Atomic `--state-file` persistence + structured JSON audit log on every mutation
//! - Native Prometheus / OpenMetrics endpoint (`GET /metrics`)
//! - Live BGP Anycast route status & maintenance drain (`GET /bgp`, `POST /drain`)

use crate::config;
use crate::engine::tcp::TcpStatsSnapshot;
use crate::engine::udp::UdpStatsSnapshot;
use crate::lb::balancer::{BackendPool, BackendSpec, MutationOutcome};
use crate::lb::bgp::{BgpController, BgpRouteState};
use crate::lb::dns::{DnsManager, TargetInput};
use crate::proto::json::{json_escape, parse_json, JsonValue};
use crate::sys::{self, EndpointV4};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_CONCURRENT_ADMIN: usize = 16;
const MAX_REQ_BYTES: usize = 65_536;

pub enum StatsProvider {
    None,
    Tcp(Box<dyn Fn() -> TcpStatsSnapshot + Send + Sync>),
    Udp(Box<dyn Fn() -> UdpStatsSnapshot + Send + Sync>),
}

/// IPv4 CIDR prefix (`network & mask`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CidrV4 {
    pub network: u32,
    pub mask: u32,
}

impl CidrV4 {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (ip_s, bits_s) = match s.trim().split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s.trim(), None),
        };
        let ip: Ipv4Addr = ip_s
            .parse()
            .map_err(|_| format!("invalid IPv4 CIDR '{s}'"))?;
        let prefix: u32 = match bits_s {
            Some(b) => b
                .parse()
                .map_err(|_| format!("invalid prefix length in '{s}'"))?,
            None => 32,
        };
        if prefix > 32 {
            return Err(format!("prefix > 32 in '{s}'"));
        }
        let mask = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        Ok(Self {
            network: u32::from(ip) & mask,
            mask,
        })
    }

    #[inline(always)]
    pub fn contains(&self, ip: u32) -> bool {
        (ip & self.mask) == self.network
    }
}

#[derive(Clone, Debug)]
pub struct ControlPlaneConfig {
    /// Optional Bearer auth secret (`Authorization: Bearer <token>`).
    pub bearer_token: Option<String>,
    /// Allowed client source CIDRs (empty = allow all).
    pub allow_cidrs: Vec<CidrV4>,
    /// Block registering link-local / cloud metadata IPs (`169.254.0.0/16`, `0.0.0.0/8`).
    pub block_metadata_targets: bool,
    /// Optional declarative state file atomically saved after every mutation.
    pub state_file: Option<PathBuf>,
    /// Emit structured JSON audit records to stderr on mutations.
    pub audit_log: bool,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            bearer_token: None,
            allow_cidrs: Vec::new(),
            block_metadata_targets: true,
            state_file: None,
            audit_log: false,
        }
    }
}

/// Constant-time string comparison to prevent timing side-channels on Bearer tokens.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn is_blocked_target_ip(ip: u32) -> bool {
    let first = (ip >> 24) & 0xff;
    let second = (ip >> 16) & 0xff;
    // Block 0.0.0.0/8 ("this network") and 169.254.0.0/16 (AWS/GCP/Azure IMDS metadata & link-local)
    first == 0 || (first == 169 && second == 254)
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

pub struct ControlContext {
    pub pool: Arc<BackendPool>,
    pub dns: Arc<DnsManager>,
    pub bgp: Option<Arc<BgpController>>,
    pub stats: StatsProvider,
    pub cfg: ControlPlaneConfig,
}

pub fn start_control_plane(
    listen_addr: EndpointV4,
    pool: Arc<BackendPool>,
    dns: Arc<DnsManager>,
    stats: StatsProvider,
    stop: Arc<AtomicBool>,
) -> std::io::Result<ControlPlaneHandle> {
    start_control_plane_with_config(
        listen_addr,
        pool,
        dns,
        None,
        stats,
        ControlPlaneConfig::default(),
        stop,
    )
}

pub fn start_control_plane_with_config(
    listen_addr: EndpointV4,
    pool: Arc<BackendPool>,
    dns: Arc<DnsManager>,
    bgp: Option<Arc<BgpController>>,
    stats: StatsProvider,
    cfg: ControlPlaneConfig,
    stop: Arc<AtomicBool>,
) -> std::io::Result<ControlPlaneHandle> {
    let listener = TcpListener::bind(listen_addr.to_std())?;
    let bound_addr = match listener.local_addr()? {
        SocketAddr::V4(v4) => EndpointV4::from_std(v4),
        _ => listen_addr,
    };
    listener.set_nonblocking(true)?;

    let ctx = Arc::new(ControlContext {
        pool,
        dns,
        bgp,
        stats,
        cfg,
    });
    let stop_c = Arc::clone(&stop);
    let inflight = Arc::new(AtomicUsize::new(0));

    let thread = std::thread::Builder::new()
        .name("tetrux-admin".to_string())
        .spawn(move || {
            while !stop_c.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        let peer_ip = match peer {
                            SocketAddr::V4(v4) => u32::from(*v4.ip()),
                            SocketAddr::V6(_) => 0,
                        };
                        // Enforce CIDR allowlist BEFORE allocating handler / reading body!
                        if !ctx.cfg.allow_cidrs.is_empty()
                            && !ctx.cfg.allow_cidrs.iter().any(|c| c.contains(peer_ip))
                        {
                            let _ = stream.write_all(
                                b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: 35\r\nConnection: close\r\n\r\n{\"error\":\"client IP not allowed\"}\n",
                            );
                            continue;
                        }
                        // Bounded concurrency protects against Slowloris / admin DoS
                        if inflight.fetch_add(1, Ordering::AcqRel) >= MAX_CONCURRENT_ADMIN {
                            inflight.fetch_sub(1, Ordering::AcqRel);
                            let _ = stream.write_all(
                                b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 34\r\nConnection: close\r\n\r\n{\"error\":\"admin server busy\"}\r\n\r\n",
                            );
                            continue;
                        }
                        let ctx_h = Arc::clone(&ctx);
                        let inf_h = Arc::clone(&inflight);
                        let _ = std::thread::Builder::new()
                            .name("tetrux-admin-req".to_string())
                            .spawn(move || {
                                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    let _ = stream.set_nonblocking(false);
                                    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                                    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
                                    handle_http_connection(&mut stream, peer_ip, &ctx_h);
                                }));
                                inf_h.fetch_sub(1, Ordering::AcqRel);
                            });
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

fn handle_http_connection(stream: &mut TcpStream, peer_ip: u32, ctx: &ControlContext) {
    let mut buf = vec![0u8; MAX_REQ_BYTES];
    let mut total = 0usize;
    let mut header_end = None;
    let mut content_len = 0usize;
    let mut auth_header: Option<String> = None;

    loop {
        if total >= buf.len() {
            let _ = stream.write_all(
                b"HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: 31\r\nConnection: close\r\n\r\n{\"error\":\"request too large\"}",
            );
            return;
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
                                } else if k.trim().eq_ignore_ascii_case("authorization") {
                                    auth_header = Some(v.trim().to_string());
                                }
                            }
                        }
                        if (pos + 4) + content_len > MAX_REQ_BYTES {
                            let _ = stream.write_all(
                                b"HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: 31\r\nConnection: close\r\n\r\n{\"error\":\"request too large\"}",
                            );
                            return;
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

    let (status_code, status_text, content_type, resp_body) =
        dispatch_with_auth(method, path, body, auth_header.as_deref(), peer_ip, ctx);
    let resp = format!(
        "HTTP/1.1 {status_code} {status_text}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        resp_body.len(),
        resp_body
    );
    let _ = stream.write_all(resp.as_bytes());
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
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

fn parse_body_json(body: &str) -> Result<JsonValue, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(JsonValue::Object(std::collections::BTreeMap::new()));
    }
    let v = parse_json(trimmed)?;
    if v.as_object().is_none() {
        return Err("JSON body must be an object".to_string());
    }
    Ok(v)
}

fn emit_audit(ctx: &ControlContext, peer_ip: u32, action: &str, detail: &str, status: u16) {
    if ctx.cfg.audit_log {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        eprintln!(
            r#"{{"audit":true,"ts_ms":{ts_ms},"actor_ip":"{}","action":"{}","status":{status},"detail":"{}"}}"#,
            Ipv4Addr::from(peer_ip),
            json_escape(action),
            json_escape(detail)
        );
    }
}

fn persist_if_configured(ctx: &ControlContext) {
    if let Some(ref path) = ctx.cfg.state_file {
        let _ = config::save_state(path, &ctx.pool, &ctx.dns);
    }
}

/// Auth-checked dispatcher (used by HTTP server and unit tests).
pub fn dispatch_with_auth(
    method: &str,
    path: &str,
    body: &str,
    auth_header: Option<&str>,
    peer_ip: u32,
    ctx: &ControlContext,
) -> (u16, &'static str, &'static str, String) {
    // Allow unauthenticated `GET /health` for liveness probes; require constant-time Bearer token
    // on all other endpoints whenever `bearer_token` is configured!
    if path != "/health" {
        if let Some(ref expected) = ctx.cfg.bearer_token {
            let provided = auth_header
                .and_then(|h| h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")))
                .unwrap_or("");
            if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
                emit_audit(ctx, peer_ip, &format!("{method} {path}"), "unauthorized", 401);
                return (
                    401,
                    "Unauthorized",
                    "application/json",
                    r#"{"error":"missing or invalid Bearer token"}"#.to_string(),
                );
            }
        }
    }

    if method == "GET" && path == "/metrics" {
        return (
            200,
            "OK",
            "text/plain; version=0.0.4; charset=utf-8",
            render_prometheus_metrics(ctx),
        );
    }

    let (code, text, json) = dispatch_json(method, path, body, peer_ip, ctx);
    (code, text, "application/json", json)
}

/// Backwards-compatible helper for direct tests without auth.
pub fn dispatch_request(
    method: &str,
    path: &str,
    body: &str,
    pool: &BackendPool,
    dns: &DnsManager,
    stats: &StatsProvider,
) -> (u16, &'static str, String) {
    dispatch_json_inner(
        method,
        path,
        body,
        0x7f00_0001,
        pool,
        dns,
        None,
        stats,
        &ControlPlaneConfig::default(),
    )
}

fn dispatch_json(
    method: &str,
    path: &str,
    body: &str,
    peer_ip: u32,
    ctx: &ControlContext,
) -> (u16, &'static str, String) {
    let (code, text, resp) = dispatch_json_inner(
        method,
        path,
        body,
        peer_ip,
        &ctx.pool,
        &ctx.dns,
        ctx.bgp.as_deref(),
        &ctx.stats,
        &ctx.cfg,
    );
    if method != "GET" {
        emit_audit(ctx, peer_ip, &format!("{method} {path}"), body.trim(), code);
        if code == 200 {
            persist_if_configured(ctx);
            if let Some(ref bgp) = ctx.bgp {
                bgp.evaluate();
            }
        }
    }
    (code, text, resp)
}

#[allow(clippy::too_many_arguments)]
fn dispatch_json_inner(
    method: &str,
    path: &str,
    body: &str,
    _peer_ip: u32,
    pool: &BackendPool,
    dns: &DnsManager,
    bgp: Option<&BgpController>,
    stats: &StatsProvider,
    cfg: &ControlPlaneConfig,
) -> (u16, &'static str, String) {
    match (method, path) {
        ("GET", "/health") => {
            let targets = pool.list_targets().len();
            let gen = pool.generation();
            let panic_mode = pool.is_panic_mode();
            let draining = bgp.map(|b| b.evaluate().draining).unwrap_or(false);
            if draining {
                (
                    503,
                    "Service Unavailable",
                    format!(
                        r#"{{"status":"draining","generation":{gen},"targets":{targets},"panic_mode":{panic_mode}}}"#
                    ),
                )
            } else {
                (
                    200,
                    "OK",
                    format!(
                        r#"{{"status":"ok","generation":{gen},"targets":{targets},"panic_mode":{panic_mode}}}"#
                    ),
                )
            }
        }

        ("GET", "/bgp") => {
            if let Some(b) = bgp {
                let st = b.evaluate();
                let (state_str, reason_str) = match st.state {
                    BgpRouteState::Announced => ("announced", "null".to_string()),
                    BgpRouteState::Withdrawn(r) => ("withdrawn", format!("\"{r}\"")),
                };
                (
                    200,
                    "OK",
                    format!(
                        r#"{{"vip":"{}","state":"{state_str}","reason":{reason_str},"draining":{},"healthy_targets":{},"total_targets":{},"panic_mode":{},"exabgp_cmd":"{}"}}"#,
                        st.vip,
                        st.draining,
                        st.healthy_targets,
                        st.total_targets,
                        st.panic_mode,
                        json_escape(&st.exabgp_cmd)
                    ),
                )
            } else {
                (
                    200,
                    "OK",
                    r#"{"state":"disabled","note":"BGP controller not enabled"}"#.to_string(),
                )
            }
        }

        ("POST", "/drain") => {
            let obj = match parse_body_json(body) {
                Ok(v) => v,
                Err(e) => {
                    return (
                        400,
                        "Bad Request",
                        format!(r#"{{"error":"invalid JSON: {}"}}"#, json_escape(&e)),
                    );
                }
            };
            let drain = obj.get_bool("drain").unwrap_or(true);
            if let Some(b) = bgp {
                let st = b.set_draining(drain);
                (
                    200,
                    "OK",
                    format!(
                        r#"{{"status":"ok","draining":{},"exabgp_cmd":"{}"}}"#,
                        st.draining,
                        json_escape(&st.exabgp_cmd)
                    ),
                )
            } else {
                (
                    200,
                    "OK",
                    format!(r#"{{"status":"ok","draining":{drain}}}"#),
                )
            }
        }

        ("GET", "/targets") => {
            let targets = pool.list_targets();
            let subs = dns.list_subscriptions();
            let mut j = String::with_capacity(512);
            j.push_str(&format!(
                r#"{{"generation":{},"algorithm":"{:?}","panic_mode":{},"targets":["#,
                pool.generation(),
                pool.algo,
                pool.is_panic_mode()
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
            let obj = match parse_body_json(body) {
                Ok(v) => v,
                Err(e) => {
                    return (
                        400,
                        "Bad Request",
                        format!(r#"{{"error":"invalid JSON: {}"}}"#, json_escape(&e)),
                    );
                }
            };
            let explicit_weight = obj.get_u32("weight");
            let mac = obj.get_str("mac").and_then(parse_mac);

            if let Some(dns_spec) = obj.get_str("dns") {
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
                        format!(
                            r#"{{"error":"DNS resolve failed: {}"}}"#,
                            json_escape(&e.to_string())
                        ),
                    ),
                };
            }

            let Some(raw_spec) = obj.get_str("addr").or_else(|| obj.get_str("target")) else {
                return (
                    400,
                    "Bad Request",
                    r#"{"error":"missing required field 'addr', 'dns', or 'target'"}"#.to_string(),
                );
            };

            match TargetInput::parse(raw_spec) {
                Ok(TargetInput::StaticIp { endpoint, weight }) => {
                    if cfg.block_metadata_targets && is_blocked_target_ip(endpoint.ip) {
                        return (
                            403,
                            "Forbidden",
                            format!(
                                r#"{{"error":"target IP {} blocked by SSRF/metadata CIDR guard"}}"#,
                                Ipv4Addr::from(endpoint.ip)
                            ),
                        );
                    }
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
                        _ => (
                            500,
                            "Internal Server Error",
                            r#"{"error":"unexpected outcome"}"#.to_string(),
                        ),
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
                            format!(
                                r#"{{"error":"DNS resolve failed: {}"}}"#,
                                json_escape(&e.to_string())
                            ),
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
            let obj = match parse_body_json(body) {
                Ok(v) => v,
                Err(e) => {
                    return (
                        400,
                        "Bad Request",
                        format!(r#"{{"error":"invalid JSON: {}"}}"#, json_escape(&e)),
                    );
                }
            };
            let Some(weight) = obj.get_u32("weight") else {
                return (
                    400,
                    "Bad Request",
                    r#"{"error":"missing integer field 'weight' (0..=1000)"}"#.to_string(),
                );
            };
            if let Some(dns_key) = obj.get_str("dns") {
                return match dns.set_dns_weight(dns_key, weight) {
                    Some((updated, gen)) => (
                        200,
                        "OK",
                        format!(
                            r#"{{"status":"updated_dns_weight","dns":"{}","weight":{weight},"targets_updated":{updated},"generation":{gen}}}"#,
                            json_escape(dns_key)
                        ),
                    ),
                    None => (
                        404,
                        "Not Found",
                        format!(
                            r#"{{"error":"DNS subscription '{}' not found"}}"#,
                            json_escape(dns_key)
                        ),
                    ),
                };
            }
            let Some(addr_str) = obj.get_str("addr").or_else(|| obj.get_str("target")) else {
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
                match dns.set_dns_weight(addr_str, weight) {
                    Some((updated, gen)) => (
                        200,
                        "OK",
                        format!(
                            r#"{{"status":"updated_dns_weight","dns":"{}","weight":{weight},"targets_updated":{updated},"generation":{gen}}}"#,
                            json_escape(addr_str)
                        ),
                    ),
                    None => (
                        404,
                        "Not Found",
                        format!(
                            r#"{{"error":"target '{}' not found"}}"#,
                            json_escape(addr_str)
                        ),
                    ),
                }
            }
        }

        ("DELETE", "/targets") | ("POST", "/targets/deregister") => {
            let obj = match parse_body_json(body) {
                Ok(v) => v,
                Err(e) => {
                    return (
                        400,
                        "Bad Request",
                        format!(r#"{{"error":"invalid JSON: {}"}}"#, json_escape(&e)),
                    );
                }
            };
            let drain = obj.get_bool("drain").unwrap_or(true);
            if let Some(dns_key) = obj.get_str("dns") {
                return match dns.deregister_dns(dns_key, drain) {
                    Some((affected, gen)) => (
                        200,
                        "OK",
                        format!(
                            r#"{{"status":"{}","dns":"{}","targets_affected":{affected},"generation":{gen}}}"#,
                            if drain { "draining_dns" } else { "removed_dns" },
                            json_escape(dns_key)
                        ),
                    ),
                    None => (
                        404,
                        "Not Found",
                        format!(
                            r#"{{"error":"DNS subscription '{}' not found"}}"#,
                            json_escape(dns_key)
                        ),
                    ),
                };
            }
            let Some(raw) = obj.get_str("addr").or_else(|| obj.get_str("target")) else {
                return (
                    400,
                    "Bad Request",
                    r#"{"error":"missing 'addr' or 'dns' field"}"#.to_string(),
                );
            };
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
            } else if let Some((affected, gen)) = dns.deregister_dns(raw, drain) {
                (
                    200,
                    "OK",
                    format!(
                        r#"{{"status":"{}","dns":"{}","targets_affected":{affected},"generation":{gen}}}"#,
                        if drain { "draining_dns" } else { "removed_dns" },
                        json_escape(raw)
                    ),
                )
            } else {
                (
                    404,
                    "Not Found",
                    format!(r#"{{"error":"target '{}' not found"}}"#, json_escape(raw)),
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
            let panic_mode = pool.is_panic_mode();
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
                        r#"{{"mode":"tcp","generation":{gen},"panic_mode":{panic_mode},"active_conns":{},"peak_active_conns":{},"accepted":{},"rejected":{},"rate_limited":{},"bytes_c2b":{},"bytes_b2c":{},"fast_path_pct":{:.2},"wakeups_sent":{},"wakeups_suppressed":{},"nlb_cpu_ms":{:.2},"rss_mib":{:.2}}}"#,
                        s.active,
                        s.peak_active,
                        s.accepted,
                        s.rejected,
                        s.rate_limited,
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
                        r#"{{"mode":"udp","generation":{gen},"panic_mode":{panic_mode},"rx_packets":{},"tx_packets":{},"pkts_per_syscall":{:.2},"drops":{},"rate_limited":{},"sessions":{},"sessions_reaped":{},"nlb_cpu_ms":{:.2},"rss_mib":{:.2}}}"#,
                        s.rx_packets,
                        s.tx_packets,
                        s.pkts_per_syscall(),
                        s.drops,
                        s.rate_limited,
                        s.sessions_created,
                        s.sessions_reaped,
                        s.worker_cpu_ns as f64 / 1_000_000.0,
                        rss_mib
                    )
                }
                StatsProvider::None => {
                    format!(
                        r#"{{"mode":"none","generation":{gen},"panic_mode":{panic_mode},"rss_mib":{:.2}}}"#,
                        rss_mib
                    )
                }
            };
            (200, "OK", body)
        }

        _ => (
            404,
            "Not Found",
            r#"{"error":"unknown endpoint; use GET /health, GET /metrics, GET /bgp, POST /drain, GET /targets, POST /targets, PUT /targets/weight, DELETE /targets, POST /dns/refresh, GET /stats"}"#.to_string(),
        ),
    }
}

/// Render standard Prometheus / OpenMetrics text exposition (`GET /metrics`).
pub fn render_prometheus_metrics(ctx: &ControlContext) -> String {
    let m = sys::sample_process_metrics();
    let targets = ctx.pool.list_targets();
    let mut out = String::with_capacity(2048);

    out.push_str("# HELP tetrux_routing_generation Current lock-free RCU routing snapshot generation\n");
    out.push_str("# TYPE tetrux_routing_generation counter\n");
    out.push_str(&format!("tetrux_routing_generation {}\n", ctx.pool.generation()));

    out.push_str("# HELP tetrux_pool_panic_mode 1 if backend pool entered fail-open panic threshold\n");
    out.push_str("# TYPE tetrux_pool_panic_mode gauge\n");
    out.push_str(&format!(
        "tetrux_pool_panic_mode {}\n",
        if ctx.pool.is_panic_mode() { 1 } else { 0 }
    ));

    out.push_str("# HELP tetrux_process_rss_bytes Current process resident set size in bytes\n");
    out.push_str("# TYPE tetrux_process_rss_bytes gauge\n");
    out.push_str(&format!("tetrux_process_rss_bytes {}\n", m.current_rss_bytes));

    if let Some(ref bgp) = ctx.bgp {
        let st = bgp.evaluate();
        let ann = if st.state == BgpRouteState::Announced { 1 } else { 0 };
        out.push_str("# HELP tetrux_bgp_route_announced 1 if Anycast VIP /32 is announced\n");
        out.push_str("# TYPE tetrux_bgp_route_announced gauge\n");
        out.push_str(&format!(
            "tetrux_bgp_route_announced{{vip=\"{}\"}} {ann}\n",
            st.vip
        ));
    }

    match &ctx.stats {
        StatsProvider::Tcp(f) => {
            let s = f();
            out.push_str("# TYPE tetrux_tcp_active_connections gauge\n");
            out.push_str(&format!("tetrux_tcp_active_connections {}\n", s.active));
            out.push_str("# TYPE tetrux_tcp_accepted_connections_total counter\n");
            out.push_str(&format!(
                "tetrux_tcp_accepted_connections_total {}\n",
                s.accepted
            ));
            out.push_str("# TYPE tetrux_tcp_rejected_connections_total counter\n");
            out.push_str(&format!(
                "tetrux_tcp_rejected_connections_total {}\n",
                s.rejected
            ));
            out.push_str("# TYPE tetrux_tcp_rate_limited_total counter\n");
            out.push_str(&format!("tetrux_tcp_rate_limited_total {}\n", s.rate_limited));
            out.push_str("# TYPE tetrux_tcp_bytes_total counter\n");
            out.push_str(&format!(
                "tetrux_tcp_bytes_total{{direction=\"c2b\"}} {}\n",
                s.bytes_c2b
            ));
            out.push_str(&format!(
                "tetrux_tcp_bytes_total{{direction=\"b2c\"}} {}\n",
                s.bytes_b2c
            ));
            out.push_str("# TYPE tetrux_worker_cpu_seconds_total counter\n");
            out.push_str(&format!(
                "tetrux_worker_cpu_seconds_total {:.6}\n",
                s.worker_cpu_ns as f64 / 1e9
            ));
        }
        StatsProvider::Udp(f) => {
            let s = f();
            out.push_str("# TYPE tetrux_udp_rx_packets_total counter\n");
            out.push_str(&format!("tetrux_udp_rx_packets_total {}\n", s.rx_packets));
            out.push_str("# TYPE tetrux_udp_tx_packets_total counter\n");
            out.push_str(&format!("tetrux_udp_tx_packets_total {}\n", s.tx_packets));
            out.push_str("# TYPE tetrux_udp_drops_total counter\n");
            out.push_str(&format!("tetrux_udp_drops_total {}\n", s.drops));
            out.push_str("# TYPE tetrux_udp_sessions_reaped_total counter\n");
            out.push_str(&format!(
                "tetrux_udp_sessions_reaped_total {}\n",
                s.sessions_reaped
            ));
            out.push_str("# TYPE tetrux_worker_cpu_seconds_total counter\n");
            out.push_str(&format!(
                "tetrux_worker_cpu_seconds_total {:.6}\n",
                s.worker_cpu_ns as f64 / 1e9
            ));
        }
        StatsProvider::None => {}
    }

    out.push_str("# TYPE tetrux_backend_healthy gauge\n");
    out.push_str("# TYPE tetrux_backend_weight gauge\n");
    out.push_str("# TYPE tetrux_backend_active_connections gauge\n");
    out.push_str("# TYPE tetrux_backend_ewma_connect_microseconds gauge\n");
    for t in &targets {
        let ep = t.endpoint;
        out.push_str(&format!(
            "tetrux_backend_healthy{{endpoint=\"{ep}\",slot=\"{}\"}} {}\n",
            t.slot_id,
            if t.healthy { 1 } else { 0 }
        ));
        out.push_str(&format!(
            "tetrux_backend_weight{{endpoint=\"{ep}\",slot=\"{}\"}} {}\n",
            t.slot_id, t.weight
        ));
        out.push_str(&format!(
            "tetrux_backend_active_connections{{endpoint=\"{ep}\",slot=\"{}\"}} {}\n",
            t.slot_id, t.active_conns
        ));
        out.push_str(&format!(
            "tetrux_backend_ewma_connect_microseconds{{endpoint=\"{ep}\",slot=\"{}\"}} {:.2}\n",
            t.slot_id, t.ewma_connect_us
        ));
    }

    out
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

        let (code, _, resp) = dispatch_request("GET", "/targets", "", &pool, &dns, &stats);
        assert_eq!(code, 200);
        assert!(resp.contains("127.0.0.1:9001"));
        assert!(resp.contains("10.0.0.10:8080"));
        assert!(resp.contains("10.0.0.11:8080"));

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

    #[test]
    fn control_plane_auth_ssrf_guard_prometheus_and_bgp_drain() {
        let vip = EndpointV4::from_octets(198, 51, 100, 1, 443);
        let pool = BackendPool::new(
            vec![BackendSpec::new(EndpointV4::from_octets(10, 0, 1, 1, 8080)).with_weight(4)],
            LbAlgorithm::Maglev,
        );
        let dns = DnsManager::new(Arc::clone(&pool));
        let bgp = BgpController::new(vip, Arc::clone(&pool), false, None);
        let mut cfg = ControlPlaneConfig::default();
        cfg.bearer_token = Some("s3cr3t-tier0-token".to_string());
        cfg.allow_cidrs = vec![CidrV4::parse("127.0.0.0/8").unwrap()];

        let ctx = ControlContext {
            pool,
            dns,
            bgp: Some(bgp),
            stats: StatsProvider::None,
            cfg,
        };

        // 1. /health works without token; /targets requires valid Bearer token
        let (c, _, _, _) = dispatch_with_auth("GET", "/health", "", None, 0x7f00_0001, &ctx);
        assert_eq!(c, 200);
        let (c, _, _, _) = dispatch_with_auth("GET", "/targets", "", None, 0x7f00_0001, &ctx);
        assert_eq!(c, 401);
        let (c, _, _, _) =
            dispatch_with_auth("GET", "/targets", "", Some("Bearer wrong"), 0x7f00_0001, &ctx);
        assert_eq!(c, 401);

        // 2. SSRF guard blocks AWS/GCP metadata IP 169.254.169.254!
        let (c, _, _, body) = dispatch_with_auth(
            "POST",
            "/targets",
            r#"{"addr":"169.254.169.254:80","weight":1}"#,
            Some("Bearer s3cr3t-tier0-token"),
            0x7f00_0001,
            &ctx,
        );
        assert_eq!(c, 403, "{body}");

        // 3. Prometheus /metrics exposition works cleanly
        let (c, _, ct, body) = dispatch_with_auth(
            "GET",
            "/metrics",
            "",
            Some("Bearer s3cr3t-tier0-token"),
            0x7f00_0001,
            &ctx,
        );
        assert_eq!(c, 200);
        assert!(ct.starts_with("text/plain"));
        assert!(body.contains("tetrux_backend_weight{endpoint=\"10.0.1.1:8080\",slot=\"0\"} 4"));
        assert!(body.contains("tetrux_bgp_route_announced{vip=\"198.51.100.1\"} 1"));

        // 4. POST /drain withdraws BGP and flips /health to 503!
        let (c, _, _, body) = dispatch_with_auth(
            "POST",
            "/drain",
            r#"{"drain":true}"#,
            Some("Bearer s3cr3t-tier0-token"),
            0x7f00_0001,
            &ctx,
        );
        assert_eq!(c, 200);
        assert!(body.contains("withdraw route 198.51.100.1/32"));
        let (c, _, _, _) = dispatch_with_auth("GET", "/health", "", None, 0x7f00_0001, &ctx);
        assert_eq!(c, 503);
    }
}
