//! BGP / Anycast ECMP Health-Route Controller.
//!
//! Coordinates with upstream Anycast routers (ExaBGP / BIRD / GoBGP) across multi-DC fleets:
//! - Announces VIP `/32` only when the local node is NOT draining and has healthy backends
//! - Immediately withdraws VIP `/32` on `SIGTERM` graceful drain or total pool failure,
//!   allowing ECMP routers to shift traffic cleanly to healthy DCs in milliseconds!

use super::balancer::BackendPool;
use crate::sys::EndpointV4;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BgpRouteState {
    Announced,
    Withdrawn(&'static str),
}

#[derive(Clone, Debug)]
pub struct BgpStatus {
    pub vip: Ipv4Addr,
    pub state: BgpRouteState,
    pub draining: bool,
    pub healthy_targets: usize,
    pub total_targets: usize,
    pub panic_mode: bool,
    pub exabgp_cmd: String,
}

pub struct BgpController {
    vip: Ipv4Addr,
    pool: Arc<BackendPool>,
    draining: AtomicBool,
    withdraw_on_panic: bool,
    /// Optional ExaBGP/BIRD command pipe or status file path.
    route_file: Option<PathBuf>,
    last_state: RwLock<BgpRouteState>,
}

impl BgpController {
    pub fn new(
        vip_ep: EndpointV4,
        pool: Arc<BackendPool>,
        withdraw_on_panic: bool,
        route_file: Option<PathBuf>,
    ) -> Arc<Self> {
        Arc::new(Self {
            vip: Ipv4Addr::from(vip_ep.ip),
            pool,
            draining: AtomicBool::new(false),
            withdraw_on_panic,
            route_file,
            last_state: RwLock::new(BgpRouteState::Withdrawn("initializing")),
        })
    }

    /// Mark node draining (called immediately on `SIGTERM` / maintenance drain) and withdraw VIP!
    pub fn set_draining(&self, draining: bool) -> BgpStatus {
        self.draining.store(draining, Ordering::Release);
        self.evaluate()
    }

    /// Evaluate live pool health + drain flag and emit ExaBGP route update if state changed.
    pub fn evaluate(&self) -> BgpStatus {
        let draining = self.draining.load(Ordering::Acquire);
        let targets = self.pool.list_targets();
        let active_targets: Vec<_> = targets
            .iter()
            .filter(|t| !t.draining && t.weight > 0)
            .collect();
        let healthy_targets = active_targets.iter().filter(|t| t.healthy).count();
        let panic_mode = self.pool.is_panic_mode();

        let state = if draining {
            BgpRouteState::Withdrawn("node_draining")
        } else if active_targets.is_empty() {
            BgpRouteState::Withdrawn("no_active_targets")
        } else if healthy_targets == 0 {
            BgpRouteState::Withdrawn("all_targets_unhealthy")
        } else if self.withdraw_on_panic && panic_mode {
            BgpRouteState::Withdrawn("pool_panic_mode")
        } else {
            BgpRouteState::Announced
        };

        let exabgp_cmd = match state {
            BgpRouteState::Announced => format!("announce route {}/32 next-hop self", self.vip),
            BgpRouteState::Withdrawn(_) => format!("withdraw route {}/32 next-hop self", self.vip),
        };

        let mut prev = self.last_state.write().unwrap_or_else(|e| e.into_inner());
        if *prev != state {
            *prev = state.clone();
            if let Some(ref p) = self.route_file {
                let _ = fs::write(p, format!("{exabgp_cmd}\n"));
            }
        }

        BgpStatus {
            vip: self.vip,
            state,
            draining,
            healthy_targets,
            total_targets: active_targets.len(),
            panic_mode,
            exabgp_cmd,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lb::balancer::{BackendSpec, LbAlgorithm};

    #[test]
    fn bgp_announces_when_healthy_and_withdraws_on_drain_or_outage() {
        let vip = EndpointV4::from_octets(198, 51, 100, 1, 443);
        let pool = BackendPool::new(
            vec![BackendSpec::new(EndpointV4::from_octets(10, 0, 0, 1, 8080))],
            LbAlgorithm::Maglev,
        );
        let bgp = BgpController::new(vip, Arc::clone(&pool), false, None);

        let st = bgp.evaluate();
        assert_eq!(st.state, BgpRouteState::Announced);
        assert_eq!(st.exabgp_cmd, "announce route 198.51.100.1/32 next-hop self");

        // Graceful node drain immediately withdraws BGP route
        let st_drain = bgp.set_draining(true);
        assert_eq!(st_drain.state, BgpRouteState::Withdrawn("node_draining"));
        assert_eq!(
            st_drain.exabgp_cmd,
            "withdraw route 198.51.100.1/32 next-hop self"
        );

        // Un-drain -> re-announces; all backends down -> withdraws!
        assert_eq!(bgp.set_draining(false).state, BgpRouteState::Announced);
        pool.set_healthy(0, false);
        assert_eq!(
            bgp.evaluate().state,
            BgpRouteState::Withdrawn("all_targets_unhealthy")
        );
    }
}
