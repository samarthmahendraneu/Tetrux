//! Background DNS Target Discovery & Periodic Reconciliation.
//!
//! - Parses static IPv4 (`10.0.0.1:8080@5`) and DNS (`api.internal:8080@3`, `dns://svc:80@10`) inputs
//! - Resolves multi-A-record IPv4 pools off the hot path (never blocks workers!)
//! - Reconciles added/removed IPs cleanly (gracefully draining removed IPs without dropping flows)
//! - Survives transient DNS lookup errors by preserving last-known-good endpoints

use super::balancer::BackendPool;
use crate::sys::EndpointV4;
use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Parsed target specification from CLI or Control API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetInput {
    StaticIp {
        endpoint: EndpointV4,
        weight: u32,
    },
    Dns {
        host: String,
        port: u16,
        weight: u32,
        /// Canonical key `"host:port"`.
        key: String,
    },
}

impl TargetInput {
    /// Parse `"127.0.0.1:9001"`, `"127.0.0.1:9001@5"`, `"127.0.0.1:9001@w=5"`,
    /// `"api.internal:8080@3"`, or `"dns://api.internal:8080@3"`.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("empty target specification".to_string());
        }
        let (force_dns, rest) = if let Some(s) = trimmed.strip_prefix("dns://") {
            (true, s)
        } else {
            (false, trimmed)
        };

        let (addr_part, weight) = match rest.rsplit_once('@') {
            Some((addr, w_str)) => {
                let w_clean = w_str
                    .strip_prefix("w=")
                    .or_else(|| w_str.strip_prefix("weight="))
                    .unwrap_or(w_str);
                let w: u32 = w_clean
                    .parse()
                    .map_err(|_| format!("invalid weight '{w_str}' in '{raw}'"))?;
                (addr, w.min(1000))
            }
            None => (rest, 1),
        };

        // Try direct IPv4:port unless explicitly prefixed with `dns://`
        if !force_dns {
            if let Ok(sa) = addr_part.parse::<SocketAddrV4>() {
                return Ok(Self::StaticIp {
                    endpoint: EndpointV4::from_std(sa),
                    weight,
                });
            }
        }

        // Parse hostname:port
        let (host, port_str) = addr_part
            .rsplit_once(':')
            .ok_or_else(|| format!("missing :port in target '{raw}'"))?;
        if host.is_empty() {
            return Err(format!("empty hostname in target '{raw}'"));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("invalid port '{port_str}' in target '{raw}'"))?;
        Ok(Self::Dns {
            host: host.to_string(),
            port,
            weight,
            key: format!("{host}:{port}"),
        })
    }
}

pub type ResolverFn = Box<dyn Fn(&str, u16) -> io::Result<Vec<EndpointV4>> + Send + Sync>;

/// Default OS DNS resolver (`getaddrinfo` via `std::net::ToSocketAddrs`), deduplicated & IPv4-only.
pub fn system_ipv4_resolver(host: &str, port: u16) -> io::Result<Vec<EndpointV4>> {
    let addrs = (host, port).to_socket_addrs()?;
    let mut eps = Vec::new();
    for sa in addrs {
        if let SocketAddr::V4(v4) = sa {
            let ep = EndpointV4::from_std(v4);
            if !eps.contains(&ep) {
                eps.push(ep);
            }
        }
    }
    eps.sort_by_key(|e| (e.ip, e.port));
    if eps.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("DNS lookup for {host}:{port} returned no IPv4 A records"),
        ));
    }
    Ok(eps)
}

#[derive(Clone, Debug)]
struct DnsEntry {
    host: String,
    port: u16,
    weight: u32,
    last_resolved: Vec<EndpointV4>,
    last_error: Option<String>,
    last_sync_ms: u64,
}

#[derive(Clone, Debug)]
pub struct DnsSubscriptionStatus {
    pub key: String,
    pub host: String,
    pub port: u16,
    pub weight: u32,
    pub resolved: Vec<EndpointV4>,
    pub last_error: Option<String>,
    pub last_sync_ms: u64,
}

#[derive(Clone, Debug)]
pub struct DnsSyncReport {
    pub key: String,
    pub resolved: Vec<EndpointV4>,
    pub added: usize,
    pub drained: usize,
    pub generation: u64,
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Thread-safe DNS target discovery & background reconciliation manager.
pub struct DnsManager {
    pool: Arc<BackendPool>,
    resolver: ResolverFn,
    entries: RwLock<BTreeMap<String, DnsEntry>>,
}

impl DnsManager {
    pub fn new(pool: Arc<BackendPool>) -> Arc<Self> {
        Self::with_resolver(pool, Box::new(system_ipv4_resolver))
    }

    pub fn with_resolver(pool: Arc<BackendPool>, resolver: ResolverFn) -> Arc<Self> {
        Arc::new(Self {
            pool,
            resolver,
            entries: RwLock::new(BTreeMap::new()),
        })
    }

    /// Register (or update) a DNS pool, resolve its IPv4 A records immediately, and reconcile
    /// them into `BackendPool`.
    pub fn register_dns(
        &self,
        host: &str,
        port: u16,
        weight: u32,
    ) -> io::Result<DnsSyncReport> {
        let key = format!("{host}:{port}");
        let w = weight.min(1000);
        let resolved = (self.resolver)(host, port)?;
        let (added, drained, generation) = self.pool.reconcile_dns_endpoints(&key, &resolved, w);
        let mut map = self.entries.write().unwrap();
        map.insert(
            key.clone(),
            DnsEntry {
                host: host.to_string(),
                port,
                weight: w,
                last_resolved: resolved.clone(),
                last_error: None,
                last_sync_ms: now_unix_ms(),
            },
        );
        Ok(DnsSyncReport {
            key,
            resolved,
            added,
            drained,
            generation,
        })
    }

    /// Live-tune weight for a DNS pool (updates all currently resolved A records & future refreshes).
    pub fn set_dns_weight(&self, key: &str, weight: u32) -> Option<(usize, u64)> {
        let w = weight.min(1000);
        {
            let mut map = self.entries.write().unwrap();
            let entry = map.get_mut(key)?;
            entry.weight = w;
        }
        Some(self.pool.set_dns_weight(key, w))
    }

    /// Unsubscribe a DNS pool and gracefully drain/remove all endpoints it owns.
    pub fn deregister_dns(&self, key: &str, graceful_drain: bool) -> Option<(usize, u64)> {
        let removed = {
            let mut map = self.entries.write().unwrap();
            map.remove(key).is_some()
        };
        if !removed {
            return None;
        }
        Some(self.pool.deregister_dns_source(key, graceful_drain))
    }

    /// Re-resolve all subscribed DNS pools and reconcile changes into `BackendPool`.
    /// Transient DNS failures preserve last-known-good targets without dropping traffic.
    pub fn refresh_all(&self) -> usize {
        let snapshot: Vec<(String, String, u16, u32)> = {
            let map = self.entries.read().unwrap();
            map.iter()
                .map(|(k, e)| (k.clone(), e.host.clone(), e.port, e.weight))
                .collect()
        };

        let mut total_changes = 0usize;
        for (key, host, port, weight) in snapshot {
            match (self.resolver)(&host, port) {
                Ok(resolved) => {
                    let (added, drained, _) =
                        self.pool.reconcile_dns_endpoints(&key, &resolved, weight);
                    total_changes += added + drained;
                    let mut map = self.entries.write().unwrap();
                    if let Some(e) = map.get_mut(&key) {
                        e.last_resolved = resolved;
                        e.last_error = None;
                        e.last_sync_ms = now_unix_ms();
                    }
                }
                Err(err) => {
                    // Fail-safe: record error but DO NOT evict last-known-good backends!
                    let mut map = self.entries.write().unwrap();
                    if let Some(e) = map.get_mut(&key) {
                        e.last_error = Some(err.to_string());
                        e.last_sync_ms = now_unix_ms();
                    }
                }
            }
        }
        total_changes
    }

    pub fn list_subscriptions(&self) -> Vec<DnsSubscriptionStatus> {
        let map = self.entries.read().unwrap();
        map.iter()
            .map(|(k, e)| DnsSubscriptionStatus {
                key: k.clone(),
                host: e.host.clone(),
                port: e.port,
                weight: e.weight,
                resolved: e.last_resolved.clone(),
                last_error: e.last_error.clone(),
                last_sync_ms: e.last_sync_ms,
            })
            .collect()
    }

    /// Spawn a background DNS refresh thread (runs completely off the dataplane!).
    pub fn spawn_refresher(
        self: &Arc<Self>,
        interval: Duration,
        stop: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        let mgr = Arc::clone(self);
        std::thread::Builder::new()
            .name("tetrux-dns".to_string())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let mut slept = Duration::ZERO;
                    let step = Duration::from_millis(100);
                    while slept < interval && !stop.load(Ordering::Relaxed) {
                        std::thread::sleep(step);
                        slept += step;
                    }
                    if !stop.load(Ordering::Relaxed) {
                        mgr.refresh_all();
                    }
                }
            })
            .expect("failed to spawn DNS refresher")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lb::balancer::{LbAlgorithm, WorkerSelector};
    use std::sync::Mutex;

    #[test]
    fn parse_static_weighted_and_dns_specs() {
        assert_eq!(
            TargetInput::parse("127.0.0.1:9001").unwrap(),
            TargetInput::StaticIp {
                endpoint: EndpointV4::from_octets(127, 0, 0, 1, 9001),
                weight: 1,
            }
        );
        assert_eq!(
            TargetInput::parse("10.0.0.5:8080@7").unwrap(),
            TargetInput::StaticIp {
                endpoint: EndpointV4::from_octets(10, 0, 0, 5, 8080),
                weight: 7,
            }
        );
        assert_eq!(
            TargetInput::parse("api.prod.internal:443@w=12").unwrap(),
            TargetInput::Dns {
                host: "api.prod.internal".to_string(),
                port: 443,
                weight: 12,
                key: "api.prod.internal:443".to_string(),
            }
        );
        assert_eq!(
            TargetInput::parse("dns://127.0.0.1:8080@4").unwrap(),
            TargetInput::Dns {
                host: "127.0.0.1".to_string(),
                port: 8080,
                weight: 4,
                key: "127.0.0.1:8080".to_string(),
            }
        );
    }

    #[test]
    fn dns_reconciliation_add_drain_and_transient_failure_resilience() {
        let ep_a = EndpointV4::from_octets(10, 1, 0, 1, 8080);
        let ep_b = EndpointV4::from_octets(10, 1, 0, 2, 8080);
        let ep_c = EndpointV4::from_octets(10, 1, 0, 3, 8080);

        let mock_state: Arc<Mutex<Result<Vec<EndpointV4>, String>>> =
            Arc::new(Mutex::new(Ok(vec![ep_a, ep_b])));
        let mock_c = Arc::clone(&mock_state);
        let pool = BackendPool::new(Vec::new(), LbAlgorithm::RoundRobin);
        let dns = DnsManager::with_resolver(
            Arc::clone(&pool),
            Box::new(move |_h, _p| match &*mock_c.lock().unwrap() {
                Ok(v) => Ok(v.clone()),
                Err(msg) => Err(io::Error::new(io::ErrorKind::TimedOut, msg.clone())),
            }),
        );

        let rep = dns.register_dns("svc.local", 8080, 4).unwrap();
        assert_eq!(rep.added, 2);
        assert_eq!(pool.list_targets().len(), 2);

        // Simulate active connection on ep_a, then DNS rotates [ep_a, ep_b] -> [ep_b, ep_c]
        let slot_a = pool
            .list_targets()
            .into_iter()
            .find(|t| t.endpoint == ep_a)
            .unwrap()
            .slot_id;
        pool.on_conn_open(slot_a as usize);

        *mock_state.lock().unwrap() = Ok(vec![ep_b, ep_c]);
        let changes = dns.refresh_all();
        assert_eq!(changes, 2); // 1 added (ep_c), 1 draining (ep_a)

        let mut sel = WorkerSelector::new(Arc::clone(&pool), 0);
        for i in 0..50 {
            let (_, ep) = sel.select(i).unwrap();
            assert!(ep == ep_b || ep == ep_c, "draining ep_a should not receive new traffic");
        }

        // Transient DNS timeout must NOT remove ep_b or ep_c!
        *mock_state.lock().unwrap() = Err("SERVFAIL".to_string());
        assert_eq!(dns.refresh_all(), 0);
        let (_, ep) = sel.select(99).unwrap();
        assert!(ep == ep_b || ep == ep_c);
        assert!(dns.list_subscriptions()[0].last_error.is_some());
    }
}
