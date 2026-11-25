//! Atomic Declarative State Persistence (`--state-file <path>`).
//! Persists static targets, weights, DSR MACs, and DNS pool subscriptions using
//! write-temp + fsync + atomic rename so process restarts/reloads never lose state.

use crate::lb::balancer::{BackendPool, BackendSpec};
use crate::lb::dns::DnsManager;
use crate::proto::json::{json_escape, parse_json};
use crate::sys::EndpointV4;
use std::fs::{self, File};
use std::io::{self, Write};
use std::net::SocketAddrV4;
use std::path::Path;

/// Save current non-draining static targets & DNS subscriptions atomically to JSON on disk.
pub fn save_state(path: &Path, pool: &BackendPool, dns: &DnsManager) -> io::Result<()> {
    let targets = pool.list_targets();
    let subs = dns.list_subscriptions();

    let mut out = String::with_capacity(1024);
    out.push_str("{\n  \"version\": 1,\n  \"static_targets\": [\n");
    let mut first = true;
    for t in &targets {
        if t.dns_source.is_some() || t.draining {
            continue;
        }
        if !first {
            out.push_str(",\n");
        }
        first = false;
        out.push_str(&format!(
            "    {{\"addr\":\"{}\",\"weight\":{}}}",
            t.endpoint, t.weight
        ));
    }
    out.push_str("\n  ],\n  \"dns_subscriptions\": [\n");
    for (idx, s) in subs.iter().enumerate() {
        if idx > 0 {
            out.push_str(",\n");
        }
        out.push_str(&format!(
            "    {{\"host\":\"{}\",\"port\":{},\"weight\":{}}}",
            json_escape(&s.host),
            s.port,
            s.weight
        ));
    }
    out.push_str("\n  ]\n}\n");

    let tmp_path = path.with_extension("json.tmp");
    {
        let mut f = File::create(&tmp_path)?;
        f.write_all(out.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Load persisted targets & DNS subscriptions into `pool` and `dns` (returns `(static_cnt, dns_cnt)`).
pub fn load_state(path: &Path, pool: &BackendPool, dns: &DnsManager) -> io::Result<(usize, usize)> {
    let raw = fs::read_to_string(path)?;
    let root = parse_json(&raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("corrupt state file: {e}")))?;

    let mut static_loaded = 0usize;
    if let Some(arr) = root.get("static_targets").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(addr_str) = item.get_str("addr") {
                if let Ok(sa) = addr_str.parse::<SocketAddrV4>() {
                    let w = item.get_u32("weight").unwrap_or(1);
                    pool.register_target(BackendSpec::new(EndpointV4::from_std(sa)).with_weight(w));
                    static_loaded += 1;
                }
            }
        }
    }

    let mut dns_loaded = 0usize;
    if let Some(arr) = root.get("dns_subscriptions").and_then(|v| v.as_array()) {
        for item in arr {
            if let (Some(host), Some(port)) = (item.get_str("host"), item.get_u32("port")) {
                let w = item.get_u32("weight").unwrap_or(1);
                if dns.register_dns(host, port as u16, w).is_ok() {
                    dns_loaded += 1;
                }
            }
        }
    }

    Ok((static_loaded, dns_loaded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lb::balancer::LbAlgorithm;
    use std::sync::Arc;

    #[test]
    fn atomic_state_file_save_and_reload_roundtrip() {
        let dir = std::env::temp_dir().join(format!("tetrux_state_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("state.json");

        let pool1 = BackendPool::new(Vec::new(), LbAlgorithm::P2cLeastConn);
        pool1.register_target(
            BackendSpec::new(EndpointV4::from_octets(10, 0, 1, 1, 8080)).with_weight(7),
        );
        pool1.register_target(
            BackendSpec::new(EndpointV4::from_octets(10, 0, 1, 2, 8080)).with_weight(3),
        );
        let dns1 = DnsManager::with_resolver(
            Arc::clone(&pool1),
            Box::new(|_, port| Ok(vec![EndpointV4::from_octets(10, 0, 2, 1, port)])),
        );
        dns1.register_dns("tier0.internal", 443, 5).unwrap();

        save_state(&path, &pool1, &dns1).unwrap();

        let pool2 = BackendPool::new(Vec::new(), LbAlgorithm::P2cLeastConn);
        let dns2 = DnsManager::with_resolver(
            Arc::clone(&pool2),
            Box::new(|_, port| Ok(vec![EndpointV4::from_octets(10, 0, 2, 1, port)])),
        );
        let (sc, dc) = load_state(&path, &pool2, &dns2).unwrap();
        assert_eq!((sc, dc), (2, 1));
        assert_eq!(pool2.list_targets().len(), 3);
        let _ = fs::remove_dir_all(&dir);
    }
}
