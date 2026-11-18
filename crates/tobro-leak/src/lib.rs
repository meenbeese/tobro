//! End-to-end leak tests for the TUN path (M7).
//!
//! The suite drives the **real** privileged helper and the real OS: a TUN
//! device is created, routes and the system resolver are changed, and
//! traffic is generated through ordinary host sockets. A fake daemon
//! (loopback SOCKS5 + DNS listeners) is the only forwarding target, so a
//! packet that escapes the tunnel is *observable* instead of silently
//! reaching the internet.
//!
//! Coverage (safe tier, no default-route takeover):
//!
//! | Scenario | Leak it rules out |
//! | --- | --- |
//! | `tcp-forwarded` | TCP bypassing the engine/SOCKS path |
//! | `dns-intercepted` | DNS queries bypassing the tunnel resolver |
//! | `udp-blocked` | QUIC/other UDP escaping, DNS in `block_all` mode |
//! | `ipv6-routed` | IPv6 ignoring the IPv4-only tunnel policy |
//! | `route-change` | stale routes after a plan change or external change |
//! | `sleep-wake` | traffic/DNS escaping after kernel state loss |
//! | `helper-crash` | resolver left pointing at a dead tunnel (fail open) |
//! | `daemon-crash` | a vanished client leaving a half-applied plan |
//!
//! The intrusive tier (`--intrusive` + `TOBRO_LEAK_ALLOW_INTRUSIVE=1`)
//! captures the real default routes and, for the kill switch, blocks all
//! host traffic. Run it on a dedicated host or inside a network namespace
//! (`scripts/run-leak-tests.sh` does the latter on Linux).
//!
//! The safe tier deliberately routes the reserved `198.18.0.0/15` and
//! `2001:db8::/32` ranges instead of the default route: if the harness is
//! killed, the host keeps working and the kernel simply drops the dangling
//! routes with the device.

pub mod canary;
pub mod helper;
pub mod plan;
pub mod resolver;
pub mod route;
pub mod scenario;
pub mod traffic;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::Serialize;

/// Which blast radius a scenario has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Touches only reserved test prefixes; safe on a live workstation.
    Safe,
    /// Captures default routes and/or blocks host traffic.
    Intrusive,
}

impl Tier {
    /// Short label for human output.
    pub fn label(self) -> &'static str {
        match self {
            Tier::Safe => "safe",
            Tier::Intrusive => "intrusive",
        }
    }
}

/// One assertion inside a scenario.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// What was asserted.
    pub name: String,
    /// Whether it held.
    pub passed: bool,
    /// Observed value or explanation.
    pub detail: String,
}

/// Final status of a scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Every assertion held.
    Passed,
    /// The environment cannot run it (reported, not a failure by default).
    Skipped,
    /// An assertion or setup step failed.
    Failed,
}

/// One scenario's result, suitable for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct ScenarioReport {
    /// Stable scenario id (`tcp-forwarded`, ...).
    pub scenario: String,
    /// Blast radius.
    pub tier: Tier,
    /// Outcome.
    pub status: Status,
    /// Why the scenario was skipped (only for [`Status::Skipped`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Assertions that ran (including the one that failed).
    pub checks: Vec<Check>,
    /// Wall-clock duration.
    pub duration_ms: u64,
}

impl ScenarioReport {
    /// True when the suite should treat this report as a failure.
    pub fn is_failure(&self, fail_on_skip: bool) -> bool {
        match self.status {
            Status::Failed => true,
            Status::Skipped => fail_on_skip,
            Status::Passed => false,
        }
    }
}

/// A selectable scenario.
#[derive(Debug, Clone, Copy)]
pub struct ScenarioInfo {
    /// Stable id used by `--scenario`.
    pub id: &'static str,
    /// Blast radius.
    pub tier: Tier,
    /// One-line description.
    pub description: &'static str,
}

/// Every scenario, in report order.
pub const SCENARIOS: &[ScenarioInfo] = &[
    ScenarioInfo {
        id: "tcp-forwarded",
        tier: Tier::Safe,
        description: "TCP through the tunnel reaches the daemon's SOCKS endpoint",
    },
    ScenarioInfo {
        id: "dns-intercepted",
        tier: Tier::Safe,
        description: "system resolver points at the tunnel and DNS is intercepted",
    },
    ScenarioInfo {
        id: "udp-blocked",
        tier: Tier::Safe,
        description: "QUIC/other UDP is dropped; block_all drops DNS too",
    },
    ScenarioInfo {
        id: "ipv6-routed",
        tier: Tier::Safe,
        description: "IPv6 test traffic enters the tunnel and never leaks",
    },
    ScenarioInfo {
        id: "route-change",
        tier: Tier::Safe,
        description: "external route loss and plan changes converge without leaks",
    },
    ScenarioInfo {
        id: "sleep-wake",
        tier: Tier::Safe,
        description: "route/DNS state lost across suspend is reapplied on resume",
    },
    ScenarioInfo {
        id: "helper-crash",
        tier: Tier::Safe,
        description: "a killed helper fails closed and the resolver can be restored",
    },
    ScenarioInfo {
        id: "daemon-crash",
        tier: Tier::Safe,
        description: "a vanished daemon tears the plan down via the idle window",
    },
    ScenarioInfo {
        id: "intrusive-default-route",
        tier: Tier::Intrusive,
        description: "real default routes capture all IPv4/IPv6 traffic",
    },
    ScenarioInfo {
        id: "intrusive-kill-switch",
        tier: Tier::Intrusive,
        description: "fail-closed plan blocks host traffic and installs insurance routes",
    },
];

/// A scenario's raw outcome before it is wrapped in timing/status.
#[derive(Debug)]
pub enum ScenarioRun {
    /// Every check ran and passed (the checks are informational at this
    /// point; any failure returns an `Err` instead).
    Completed(Vec<Check>),
    /// The host cannot run this scenario.
    Skipped(String),
}

/// Harness configuration, shared by every scenario.
#[derive(Debug, Clone)]
pub struct HarnessConfig {
    /// Explicit helper binary (`--helper`), otherwise discovered.
    pub helper: Option<PathBuf>,
    /// Per-operation timeout (TCP connect/echo, DNS reply, UDP silence).
    pub timeout: Duration,
    /// Allow the intrusive tier (still requires the env opt-in).
    pub intrusive: bool,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            helper: None,
            timeout: Duration::from_secs(5),
            intrusive: false,
        }
    }
}

/// Find a scenario by id.
pub fn scenario_info(id: &str) -> Option<&'static ScenarioInfo> {
    SCENARIOS.iter().find(|info| info.id == id)
}

/// Run one scenario, applying the environment gates first.
pub async fn run_scenario(id: &str, config: &HarnessConfig) -> Result<ScenarioRun> {
    let info =
        scenario_info(id).ok_or_else(|| anyhow::anyhow!("unknown scenario {id:?} (use --list)"))?;
    if let Some(reason) = gate(config, info) {
        return Ok(ScenarioRun::Skipped(reason));
    }
    scenario::run(id, config).await
}

/// Run a batch of scenarios and wrap each outcome in a report.
///
/// An empty `ids` runs every safe scenario.
pub async fn run_all(config: &HarnessConfig, ids: &[String]) -> Vec<ScenarioReport> {
    let selected: Vec<&'static ScenarioInfo> = if ids.is_empty() {
        SCENARIOS
            .iter()
            .filter(|info| info.tier == Tier::Safe)
            .collect()
    } else {
        ids.iter().filter_map(|id| scenario_info(id)).collect()
    };

    let mut reports = Vec::with_capacity(selected.len());
    for info in selected {
        let start = Instant::now();
        let report = match run_scenario(info.id, config).await {
            Ok(ScenarioRun::Completed(checks)) => ScenarioReport {
                scenario: info.id.to_owned(),
                tier: info.tier,
                status: Status::Passed,
                reason: None,
                checks,
                duration_ms: elapsed_ms(start),
            },
            Ok(ScenarioRun::Skipped(reason)) => ScenarioReport {
                scenario: info.id.to_owned(),
                tier: info.tier,
                status: Status::Skipped,
                reason: Some(reason),
                checks: Vec::new(),
                duration_ms: elapsed_ms(start),
            },
            Err(error) => ScenarioReport {
                scenario: info.id.to_owned(),
                tier: info.tier,
                status: Status::Failed,
                reason: None,
                checks: vec![Check {
                    name: "scenario".to_owned(),
                    passed: false,
                    detail: format!("{error:#}"),
                }],
                duration_ms: elapsed_ms(start),
            },
        };
        reports.push(report);
    }
    reports
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Environment gates: intrusive opt-in, privilege, helper binary.
fn gate(config: &HarnessConfig, info: &ScenarioInfo) -> Option<String> {
    if info.tier == Tier::Intrusive {
        if !config.intrusive {
            return Some(
                "intrusive scenarios are opt-in: pass --intrusive and set \
                 TOBRO_LEAK_ALLOW_INTRUSIVE=1"
                    .to_owned(),
            );
        }
        if std::env::var_os("TOBRO_LEAK_ALLOW_INTRUSIVE").as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return Some(
                "refusing to take over the default routes without \
                 TOBRO_LEAK_ALLOW_INTRUSIVE=1 (use a dedicated host or \
                 scripts/run-leak-tests.sh)"
                    .to_owned(),
            );
        }
    }
    if !tobro_osapi::is_elevated() {
        return Some(
            "requires root (Unix) / an elevated administrator token (Windows) to create a TUN \
             device and change routes; run under sudo or in a privileged CI job"
                .to_owned(),
        );
    }
    if let Err(error) = helper::find_helper_binary(config.helper.as_deref()) {
        return Some(format!("{error:#}"));
    }
    None
}
