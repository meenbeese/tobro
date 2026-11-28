//! Request dispatch and helper state, platform-independent.
//!
//! [`HelperService::handle`] maps one validated [`HelperRequest`] to one
//! [`HelperResponse`]. Plans are re-validated here (the helper must treat
//! decoded values as untrusted), applies converge idempotently, and any
//! partial failure rolls back to a torn-down state so the system is never
//! left half-configured.

use tobro_tun::{
    HelperRequest, HelperResponse, HelperStatus, KillSwitchMode, PROTOCOL_VERSION, TunnelPlan,
    reject_codes,
};

use crate::engine::{EngineConfig, EngineHandle};
use crate::platform::{CreatedDevice, Platform, PlatformError};

/// The helper's state machine + dispatch. Generic over the privileged
/// backend so tests can drive it with a recording platform.
pub struct HelperService<P: Platform> {
    platform: P,
    state: HelperStatus,
    last_plan: Option<TunnelPlan>,
    /// The routing engine, when one is running (or a device is parked).
    engine: Option<EngineHandle>,
}

impl<P: Platform> std::fmt::Debug for HelperService<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The state summary is log-safe (counts only); the platform is the
        // type's own Debug impl.
        f.debug_struct("HelperService")
            .field("platform", &std::any::type_name::<P>())
            .field("state", &self.state)
            .field("last_plan_applied", &self.last_plan.is_some())
            .field("engine_running", &self.engine.is_some())
            .finish()
    }
}

impl<P: Platform> HelperService<P> {
    /// Build a service over `platform`.
    pub fn new(platform: P) -> Self {
        Self {
            platform,
            state: HelperStatus::default(),
            last_plan: None,
            engine: None,
        }
    }

    /// Current state (what `status` reports).
    pub fn state(&self) -> &HelperStatus {
        &self.state
    }

    /// The last plan that was successfully applied, if any.
    pub fn last_plan(&self) -> Option<&TunnelPlan> {
        self.last_plan.as_ref()
    }

    /// Read access to the platform backend (used by tests).
    pub fn platform(&self) -> &P {
        &self.platform
    }

    /// Handle exactly one request. Lock-step: one request in, one response
    /// out.
    pub async fn handle(&mut self, request: HelperRequest) -> HelperResponse {
        match request {
            HelperRequest::Handshake { protocol_version } => {
                tracing::debug!("request: handshake (client protocol v{protocol_version})");
                HelperResponse::HandshakeOk {
                    protocol_version: PROTOCOL_VERSION,
                    helper_version: env!("CARGO_PKG_VERSION").to_owned(),
                }
            }
            HelperRequest::ApplyPlan { plan } => self.apply(plan).await,
            HelperRequest::Status {} => {
                tracing::debug!("request: status");
                HelperResponse::Status {
                    state: self.state.clone(),
                }
            }
            HelperRequest::Teardown {} => self.teardown().await,
        }
    }

    /// Apply a plan. Idempotent for identical consecutive plans.
    async fn apply(&mut self, plan: TunnelPlan) -> HelperResponse {
        tracing::info!("request: apply_plan ({})", plan_summary(&plan));
        // Re-validate on receipt: decoded wire values are untrusted.
        if let Err(error) = plan.validate() {
            return HelperResponse::Rejected {
                code: tobro_tun::reject_codes::VALIDATION,
                message: error.to_string(),
            };
        }
        // Convergence: the exact same plan is already applied.
        if self.last_plan.as_ref() == Some(&plan) {
            tracing::debug!(
                "apply_plan: plan already active (generation {})",
                self.state.generation
            );
            return HelperResponse::Applied {
                generation: self.state.generation,
                interface: self
                    .state
                    .interface
                    .clone()
                    .unwrap_or_else(|| plan.effective_interface().to_owned()),
            };
        }

        // Stop the previous engine before touching the system: it owns the
        // previous device, and closing that device (interface included) is
        // what lets the platform create a fresh one under the same name.
        self.stop_engine().await;

        let created = match self.platform.create_device(&plan.device).await {
            Ok(created) => created,
            Err(error) => return self.reject(error).await,
        };
        let interface = created.interface.clone();
        if let Err(error) = self
            .platform
            .apply_routes(&interface, &plan.routes, &plan.bypass_routes)
            .await
        {
            return self.reject(error).await;
        }
        if let Err(error) = self.platform.apply_dns(&plan.dns).await {
            return self.reject(error).await;
        }
        if let Err(error) = self
            .platform
            .apply_kill_switch(plan.kill_switch, &plan.bypass_routes)
            .await
        {
            return self.reject(error).await;
        }
        // Persist the kill-switch policy so a killing daemon/helper is
        // recovered per the chosen policy (restore vs block) from the
        // durable journal, not just in-memory state.
        {
            let mut journal = crate::recovery::load();
            journal.kill_switch = plan.kill_switch;
            journal.block_all = plan.kill_switch.blocks_on_tunnel_loss();
            let _ = crate::recovery::save(&journal);
        }
        // The engine consumes the device; on failure the device is dropped
        // and the rollback below tears the system back down.
        if let Err(error) = self.start_engine(created, &plan) {
            return self.reject_engine(error).await;
        }

        self.state.generation += 1;
        self.state.active = true;
        self.state.interface = Some(interface.clone());
        self.state.kill_switch = plan.kill_switch;
        self.state.applied_at_ms = Some(unix_millis());
        self.last_plan = Some(plan);
        tracing::info!(
            "apply_plan: ok (generation {}, interface {interface})",
            self.state.generation
        );
        HelperResponse::Applied {
            generation: self.state.generation,
            interface,
        }
    }

    /// Hand the device's packet I/O to the routing engine.
    ///
    /// A plan without forwarding still keeps the device: it is parked, so the
    /// interface stays up and every packet is dropped (fail closed) instead
    /// of escaping unproxied.
    fn start_engine(
        &mut self,
        created: CreatedDevice,
        plan: &TunnelPlan,
    ) -> Result<(), std::io::Error> {
        let Some(packet_io) = created.packet_io else {
            // Test backends return no packet I/O; nothing can be forwarded.
            tracing::warn!("apply_plan: the platform returned no packet I/O; traffic is dropped");
            return Ok(());
        };
        let engine = match plan.forwarding {
            Some(forwarding) => EngineHandle::spawn(
                packet_io,
                EngineConfig {
                    forwarding,
                    udp_policy: plan.udp_policy,
                    mtu: plan.device.mtu,
                },
            )?,
            None => EngineHandle::park(packet_io),
        };
        self.engine = Some(engine);
        Ok(())
    }

    /// Stop the routing engine and wait until its device is closed.
    async fn stop_engine(&mut self) {
        if let Some(engine) = self.engine.take() {
            engine.stop().await;
        }
    }

    /// A privileged step failed: roll back everything best-effort so the
    /// system is not left half-configured, then report the failure.
    async fn reject(&mut self, error: PlatformError) -> HelperResponse {
        tracing::warn!("apply_plan failed: {error}; rolling back");
        self.rollback().await;
        HelperResponse::Rejected {
            code: error.reject_code(),
            message: error.to_string(),
        }
    }

    /// The engine could not start (not a platform failure: the plan was fine,
    /// the helper could not honor it). Roll back and report an internal error.
    async fn reject_engine(&mut self, error: std::io::Error) -> HelperResponse {
        tracing::warn!("apply_plan: the routing engine failed to start: {error}; rolling back");
        self.rollback().await;
        HelperResponse::Rejected {
            code: reject_codes::INTERNAL,
            message: format!("could not start the routing engine: {error}"),
        }
    }

    /// Best-effort teardown after a partial apply. The helper never leaves
    /// a device, routes, DNS, or a kill switch behind on failure.
    async fn rollback(&mut self) {
        if let Err(error) = self.platform.teardown().await {
            tracing::warn!("rollback failed: {error} (system may need manual cleanup)");
        }
        // The device (and its interface) goes last, after the platform has
        // undone everything it can still see.
        self.stop_engine().await;
        self.state.generation += 1;
        self.state.active = false;
        self.state.interface = None;
        self.state.kill_switch = KillSwitchMode::Disabled;
        self.state.applied_at_ms = None;
        self.last_plan = None;
    }

    /// Remove everything the helper set up.
    async fn teardown(&mut self) -> HelperResponse {
        tracing::info!("request: teardown");
        match self.platform.teardown().await {
            Ok(()) => {
                // Routes and DNS are gone; now close the device (and with it
                // the interface) by stopping the engine.
                self.stop_engine().await;
                self.state.generation += 1;
                self.state.active = false;
                self.state.interface = None;
                self.state.kill_switch = KillSwitchMode::Disabled;
                self.state.applied_at_ms = None;
                self.last_plan = None;
                // Explicit teardown ends any kill-switch hold: clear the
                // durable policy so a later killing process cannot re-apply it.
                let _ = crate::recovery::clear();
                tracing::info!("teardown: ok (generation {})", self.state.generation);
                HelperResponse::TornDown {
                    generation: self.state.generation,
                }
            }
            Err(error) => {
                tracing::warn!("teardown failed: {error}");
                HelperResponse::Rejected {
                    code: error.reject_code(),
                    message: error.to_string(),
                }
            }
        }
    }
}

/// Log-safe summary of a plan: kinds and counts only. Never log
/// destinations, addresses, or DNS servers (§10.5: no packet contents in
/// logs).
fn plan_summary(plan: &TunnelPlan) -> String {
    format!(
        "device(name_set={}, addresses={}, mtu={}), routes={}, bypass_routes={}, dns_servers={}, kill_switch={:?}, udp={:?}, forwarding={}",
        !plan.device.name.is_empty(),
        plan.device.addresses.len(),
        plan.device.mtu,
        plan.routes.len(),
        plan.bypass_routes.len(),
        plan.dns.servers.len(),
        plan.kill_switch,
        plan.udp_policy,
        if plan.forwarding.is_some() {
            "set"
        } else {
            "none"
        },
    )
}

/// Unix timestamp in milliseconds (0 if the clock is before the epoch).
fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;
    use tobro_tun::{DnsConfig, Prefix, RouteSpec, TunDevice, reject_codes};

    /// Test platform: records every call, can be told to fail specific ops.
    #[derive(Debug, Default)]
    struct RecordingPlatform {
        calls: Mutex<Vec<String>>,
        fail_routes: bool,
    }

    impl RecordingPlatform {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Platform for RecordingPlatform {
        async fn create_device(&self, _device: &TunDevice) -> Result<CreatedDevice, PlatformError> {
            self.calls.lock().unwrap().push("create_device".to_owned());
            // No packet I/O: the service skips the routing engine (its own
            // tests drive a real netstack over an in-memory link).
            Ok(CreatedDevice {
                interface: "tobro0".to_owned(),
                packet_io: None,
            })
        }

        async fn apply_routes(
            &self,
            _interface: &str,
            _routes: &[RouteSpec],
            _bypass_routes: &[RouteSpec],
        ) -> Result<(), PlatformError> {
            self.calls.lock().unwrap().push("apply_routes".to_owned());
            if self.fail_routes {
                return Err(PlatformError::Route("netlink said no".to_owned()));
            }
            Ok(())
        }

        async fn apply_dns(&self, _dns: &DnsConfig) -> Result<(), PlatformError> {
            self.calls.lock().unwrap().push("apply_dns".to_owned());
            Ok(())
        }

        async fn apply_kill_switch(
            &self,
            _mode: KillSwitchMode,
            _bypass_routes: &[RouteSpec],
        ) -> Result<(), PlatformError> {
            self.calls
                .lock()
                .unwrap()
                .push("apply_kill_switch".to_owned());
            Ok(())
        }

        async fn teardown(&self) -> Result<(), PlatformError> {
            self.calls.lock().unwrap().push("teardown".to_owned());
            Ok(())
        }
    }

    fn plan() -> TunnelPlan {
        TunnelPlan {
            device: TunDevice {
                name: "tobro0".to_owned(),
                addresses: vec![Prefix {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 111, 222, 252)),
                    prefix_len: 30,
                }],
                mtu: tobro_tun::DEFAULT_TUN_MTU,
            },
            routes: vec![RouteSpec {
                destination: Prefix {
                    addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    prefix_len: 0,
                },
                gateway: None,
                metric: None,
            }],
            bypass_routes: Vec::new(),
            dns: DnsConfig {
                servers: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            },
            kill_switch: KillSwitchMode::Block,
            udp_policy: tobro_tun::UdpPolicy::DnsOnly,
            forwarding: Some(tobro_tun::Forwarding {
                socks: "127.0.0.1:9050".parse().expect("valid SOCKS address"),
                dns: Some("127.0.0.1:9053".parse().expect("valid DNS address")),
            }),
        }
    }

    #[tokio::test]
    async fn full_lifecycle_with_state_updates() {
        let mut service = HelperService::new(RecordingPlatform::default());

        let handshake = service
            .handle(HelperRequest::Handshake {
                protocol_version: PROTOCOL_VERSION,
            })
            .await;
        assert_eq!(
            handshake,
            HelperResponse::HandshakeOk {
                protocol_version: PROTOCOL_VERSION,
                helper_version: env!("CARGO_PKG_VERSION").to_owned(),
            }
        );

        let applied = service
            .handle(HelperRequest::ApplyPlan { plan: plan() })
            .await;
        assert_eq!(
            applied,
            HelperResponse::Applied {
                generation: 1,
                interface: "tobro0".to_owned(),
            }
        );

        let status = service.handle(HelperRequest::Status {}).await;
        let HelperResponse::Status { state } = status else {
            panic!("expected status response");
        };
        assert!(state.active);
        assert_eq!(state.kill_switch, KillSwitchMode::Block);
        assert!(state.applied_at_ms.is_some());

        let torn = service.handle(HelperRequest::Teardown {}).await;
        assert_eq!(torn, HelperResponse::TornDown { generation: 2 });
        assert!(!service.state().active);
        assert_eq!(service.state().kill_switch, KillSwitchMode::Disabled);
        assert!(service.last_plan().is_none());

        // The platform sees every primitive exactly once, in order.
        assert_eq!(
            service.platform().calls(),
            vec![
                "create_device".to_owned(),
                "apply_routes".to_owned(),
                "apply_dns".to_owned(),
                "apply_kill_switch".to_owned(),
                "teardown".to_owned(),
            ]
        );
    }

    #[tokio::test]
    async fn identical_plan_is_idempotent() {
        let mut service = HelperService::new(RecordingPlatform::default());
        let first = service
            .handle(HelperRequest::ApplyPlan { plan: plan() })
            .await;
        let second = service
            .handle(HelperRequest::ApplyPlan { plan: plan() })
            .await;
        assert_eq!(first, second);
        assert_eq!(
            first,
            HelperResponse::Applied {
                generation: 1,
                interface: "tobro0".to_owned(),
            }
        );
        // Only one privileged apply happened.
        assert_eq!(
            service.platform().calls(),
            vec![
                "create_device".to_owned(),
                "apply_routes".to_owned(),
                "apply_dns".to_owned(),
                "apply_kill_switch".to_owned(),
            ]
        );

        // A changed plan applies again and bumps the generation.
        let mut changed = plan();
        changed.kill_switch = KillSwitchMode::Restore;
        let third = service
            .handle(HelperRequest::ApplyPlan { plan: changed })
            .await;
        assert_eq!(
            third,
            HelperResponse::Applied {
                generation: 2,
                interface: "tobro0".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn invalid_plan_is_rejected_without_touching_the_platform() {
        let mut service = HelperService::new(RecordingPlatform::default());
        let mut bad = plan();
        bad.device.mtu = 1; // below MIN_TUN_MTU
        let response = service.handle(HelperRequest::ApplyPlan { plan: bad }).await;
        match response {
            HelperResponse::Rejected { code, message } => {
                assert_eq!(code, reject_codes::VALIDATION);
                assert!(message.contains("plan.device.mtu"), "{message}");
            }
            other => panic!("expected rejection, got {other:?}"),
        }
        // No privileged calls happened.
        assert!(service.platform().calls().is_empty());
        assert!(!service.state().active);
    }

    #[tokio::test]
    async fn partial_failure_rolls_back_and_rejects() {
        let platform = RecordingPlatform {
            fail_routes: true,
            ..RecordingPlatform::default()
        };
        let mut service = HelperService::new(platform);
        let response = service
            .handle(HelperRequest::ApplyPlan { plan: plan() })
            .await;
        match response {
            HelperResponse::Rejected { code, message } => {
                assert_eq!(code, reject_codes::ROUTE_ERROR);
                assert!(message.contains("route error"), "{message}");
            }
            other => panic!("expected rejection, got {other:?}"),
        }
        // The rollback tore everything down: no half-applied state.
        assert!(!service.state().active);
        assert_eq!(service.state().kill_switch, KillSwitchMode::Disabled);
        assert!(service.state().interface.is_none());
        assert!(service.last_plan().is_none());
        // Calls: create, routes (failed), teardown (rollback).
        assert_eq!(
            service.platform().calls(),
            vec![
                "create_device".to_owned(),
                "apply_routes".to_owned(),
                "teardown".to_owned(),
            ]
        );
    }

    #[test]
    fn plan_summary_never_contains_addresses() {
        let summary = plan_summary(&plan());
        assert!(!summary.contains("10.111"), "{summary}");
        assert!(!summary.contains("9.9.9.9"), "{summary}");
        assert!(!summary.contains("127.0.0.1"), "{summary}");
        assert!(summary.contains("routes=1"), "{summary}");
        assert!(summary.contains("dns_servers=1"), "{summary}");
        assert!(summary.contains("mtu=1500"), "{summary}");
        assert!(summary.contains("forwarding=set"), "{summary}");
        assert!(summary.contains("udp=DnsOnly"), "{summary}");
    }

    #[tokio::test]
    async fn null_platform_rejects_privileged_ops_but_tears_down_cleanly() {
        let mut service = HelperService::new(crate::platform::NullPlatform);
        let rejected = service
            .handle(HelperRequest::ApplyPlan { plan: plan() })
            .await;
        assert!(matches!(
            rejected,
            HelperResponse::Rejected {
                code: reject_codes::UNSUPPORTED,
                ..
            }
        ));
        // Teardown on the null platform is an honest no-op success. The
        // failed apply's rollback bumped the generation to 1, so teardown
        // lands on 2.
        let torn = service.handle(HelperRequest::Teardown {}).await;
        assert!(matches!(torn, HelperResponse::TornDown { generation: 2 }));
    }
}
