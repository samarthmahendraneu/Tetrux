//! Multi-VIP Service Multiplexer.
//! Hosts multiple isolated L4 VIP services (each with its own listen endpoint, BackendPool,
//! DnsManager, BgpController, rate limits, and health checker) inside one Tetrux process.

use crate::engine::tcp::{start_tcp_nlb, TcpEngineConfig, TcpNlbHandle, TcpStatsSnapshot};
use crate::engine::udp::{start_udp_nlb, UdpEngineConfig, UdpNlbHandle, UdpStatsSnapshot};
use crate::lb::balancer::BackendPool;
use crate::lb::bgp::BgpController;
use crate::lb::dns::DnsManager;
use crate::sys::EndpointV4;
use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub enum VipDataplane {
    Tcp(Arc<TcpNlbHandle>),
    Udp(Arc<UdpNlbHandle>),
}

pub struct VipService {
    pub name: String,
    pub listen_addr: EndpointV4,
    pub pool: Arc<BackendPool>,
    pub dns: Arc<DnsManager>,
    pub bgp: Arc<BgpController>,
    pub dataplane: VipDataplane,
}

impl VipService {
    pub fn tcp_stats(&self) -> Option<TcpStatsSnapshot> {
        match &self.dataplane {
            VipDataplane::Tcp(h) => Some(h.stats()),
            _ => None,
        }
    }

    pub fn udp_stats(&self) -> Option<UdpStatsSnapshot> {
        match &self.dataplane {
            VipDataplane::Udp(h) => Some(h.stats()),
            _ => None,
        }
    }
}

/// Thread-safe registry of multiple isolated L4 VIP services.
pub struct VipRegistry {
    services: RwLock<BTreeMap<String, Arc<VipService>>>,
}

impl Default for VipRegistry {
    fn default() -> Self {
        Self {
            services: RwLock::new(BTreeMap::new()),
        }
    }
}

impl VipRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            services: RwLock::new(BTreeMap::new()),
        })
    }

    pub fn add_tcp_vip(
        &self,
        name: impl Into<String>,
        cfg: TcpEngineConfig,
        pool: Arc<BackendPool>,
        dns: Arc<DnsManager>,
        withdraw_on_panic: bool,
    ) -> io::Result<Arc<VipService>> {
        let name = name.into();
        let handle = Arc::new(start_tcp_nlb(cfg, Arc::clone(&pool))?);
        let listen_addr = handle.bound_addr();
        let bgp = BgpController::new(listen_addr, Arc::clone(&pool), withdraw_on_panic, None);
        let svc = Arc::new(VipService {
            name: name.clone(),
            listen_addr,
            pool,
            dns,
            bgp,
            dataplane: VipDataplane::Tcp(handle),
        });
        let mut map = self.services.write().unwrap_or_else(|e| e.into_inner());
        map.insert(name, Arc::clone(&svc));
        Ok(svc)
    }

    pub fn add_udp_vip(
        &self,
        name: impl Into<String>,
        cfg: UdpEngineConfig,
        pool: Arc<BackendPool>,
        dns: Arc<DnsManager>,
        withdraw_on_panic: bool,
    ) -> io::Result<Arc<VipService>> {
        let name = name.into();
        let handle = Arc::new(start_udp_nlb(cfg, Arc::clone(&pool))?);
        let listen_addr = handle.bound_addr();
        let bgp = BgpController::new(listen_addr, Arc::clone(&pool), withdraw_on_panic, None);
        let svc = Arc::new(VipService {
            name: name.clone(),
            listen_addr,
            pool,
            dns,
            bgp,
            dataplane: VipDataplane::Udp(handle),
        });
        let mut map = self.services.write().unwrap_or_else(|e| e.into_inner());
        map.insert(name, Arc::clone(&svc));
        Ok(svc)
    }

    pub fn get(&self, name: &str) -> Option<Arc<VipService>> {
        let map = self.services.read().unwrap_or_else(|e| e.into_inner());
        map.get(name).cloned()
    }

    pub fn list(&self) -> Vec<Arc<VipService>> {
        let map = self.services.read().unwrap_or_else(|e| e.into_inner());
        map.values().cloned().collect()
    }

    /// Gracefully withdraw BGP routes and drain all VIPs in parallel on `SIGTERM`.
    pub fn drain_all(&self, drain_timeout: Duration) {
        let svcs = self.list();
        for s in &svcs {
            s.bgp.set_draining(true);
        }
        for s in &svcs {
            if let VipDataplane::Tcp(ref h) = s.dataplane {
                h.begin_drain(drain_timeout);
            }
        }
    }
}
