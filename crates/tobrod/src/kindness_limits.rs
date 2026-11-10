//! Kindness limits (M6): best-effort pause rules for the proxy sidecar.
//!
//! Two optional rules pause the `snowflake-proxy` sidecar without tearing
//! down its supervisor (the supervisor treats a stop as intentional and
//! never restarts on its own, so pause/resume map cleanly onto
//! `Start`/`Stop` commands):
//!
//! - **Metered link** (default on): pause while the platform reports the
//!   current link as metered.
//! - **Not charging** (default off): pause while the device draws battery
//!   power.
//!
//! Both are "best effort" by design: detection only enforces a pause when
//! the platform positively reports the condition. Calibration unknowns
//! (`LinkMetered::Unknown`/`BatteryCharge::Unknown`) never pause, so a
//! missing platform API never turns into a wrongly paused proxy.
//!
//! Platform support:
//! - metered: Linux via NetworkManager D-Bus (`busctl`); desktops that do
//!   not expose a metered-link flag (macOS, Windows) report `Unknown`.
//! - charging: macOS via `pmset -g batt`; Linux via
//!   `/sys/class/power_supply/*/status`. Machines without a battery report
//!   `Unknown` (no pause), so desktops are not blocked spuriously.

use std::time::Duration;

use tobro_config::KindnessConfig;

use crate::pt_supervisor::PtSidecarHandle;

/// How often the limit rules are re-evaluated while enabled.
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Whether the current link is metered, or unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum LinkMetered {
    #[default]
    Unknown,
    Yes,
    No,
}

impl LinkMetered {
    /// Label for the `kindness.status` payload.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            LinkMetered::Unknown => "unknown",
            LinkMetered::Yes => "metered",
            LinkMetered::No => "unmetered",
        }
    }
}

/// Whether the device is charging, or unknown (no battery/report failed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum BatteryCharge {
    #[default]
    Unknown,
    Charging,
    Discharging,
}

impl BatteryCharge {
    /// Label for the `kindness.status` payload.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            BatteryCharge::Unknown => "unknown",
            BatteryCharge::Charging => "charging",
            BatteryCharge::Discharging => "discharging",
        }
    }
}

/// Why the proxy is currently paused, if it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PauseReason {
    /// A metered link was detected and `pause_on_metered` is enabled.
    MeteredLink,
    /// The device is not charging and `pause_when_not_charging` is enabled.
    NotCharging,
}

impl PauseReason {
    /// Label for the `kindness.status` payload.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            PauseReason::MeteredLink => "metered",
            PauseReason::NotCharging => "not_charging",
        }
    }
}

/// Configured limit rules (the pause flags of `[kindness]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LimitRules {
    pub(crate) pause_on_metered: bool,
    pub(crate) pause_when_not_charging: bool,
}

impl LimitRules {
    pub(crate) fn from_config(cfg: &KindnessConfig) -> Self {
        Self {
            pause_on_metered: cfg.pause_on_metered,
            pause_when_not_charging: cfg.pause_when_not_charging,
        }
    }

    /// True when any rule is enabled and probing/watching is required.
    pub(crate) fn any(self) -> bool {
        self.pause_on_metered || self.pause_when_not_charging
    }
}

/// Decide whether the configured rules pause the proxy right now. A single
/// pure function so the state matrix is exhaustively testable.
pub(crate) fn decide_pause(
    rules: &LimitRules,
    metered: LinkMetered,
    charging: BatteryCharge,
) -> Option<PauseReason> {
    if rules.pause_on_metered && metered == LinkMetered::Yes {
        return Some(PauseReason::MeteredLink);
    }
    if rules.pause_when_not_charging && charging == BatteryCharge::Discharging {
        return Some(PauseReason::NotCharging);
    }
    None
}

/// Observed limit state shared with the IPC surface (`kindness.status`).
#[derive(Debug, Clone, Default)]
pub(crate) struct LimitsObserved {
    pub(crate) metered: LinkMetered,
    pub(crate) charging: BatteryCharge,
    pub(crate) paused_reason: Option<PauseReason>,
}

/// Sharable handle to the watcher state (`kindness.status` reads it).
pub(crate) type LimitShared = std::sync::Arc<std::sync::RwLock<LimitsObserved>>;

/// Asynchronous probe signature for link metered state.
type MeteredProbe = dyn Fn() -> LinkMetered + Send + Sync + 'static;
/// Asynchronous probe signature for battery charging state.
type ChargeProbe = dyn Fn() -> BatteryCharge + Send + Sync + 'static;

/// Spawn the limits watcher with production probes. Inert (no task) when
/// both rules are disabled.
///
/// The watcher polls the platform probes on [`POLL_INTERVAL`], pauses the
/// sidecar with `Stop` while a rule matches, and resumes it with `Start`
/// once conditions clear. The sidecar may still crash/restart under the
/// supervisor's crash-backoff policy at any time; the watcher only reacts
/// to changes in the rule outcome.
pub(crate) fn spawn_watcher(handle: PtSidecarHandle, cfg: &KindnessConfig, shared: LimitShared) {
    spawn_watcher_with(
        handle,
        LimitRules::from_config(cfg),
        shared,
        POLL_INTERVAL,
        &detect_metered_blocking,
        &detect_charging_blocking,
    );
}

/// [`spawn_watcher`] with injectable probes and interval (used by tests).
///
/// Both rules disabled short-circuits: no task is spawned and the probes
/// are never called.
pub(crate) fn spawn_watcher_with(
    handle: PtSidecarHandle,
    rules: LimitRules,
    shared: LimitShared,
    interval: Duration,
    probe_metered: &'static MeteredProbe,
    probe_charging: &'static ChargeProbe,
) {
    if !rules.any() {
        tracing::debug!("kindness limits: both pause rules disabled; watcher not started");
        return;
    }

    tokio::spawn(async move {
        let mut paused: Option<PauseReason> = None;
        loop {
            let metered = if rules.pause_on_metered {
                tokio::task::spawn_blocking(probe_metered)
                    .await
                    .unwrap_or(LinkMetered::Unknown)
            } else {
                LinkMetered::Unknown
            };
            let charging = if rules.pause_when_not_charging {
                tokio::task::spawn_blocking(probe_charging)
                    .await
                    .unwrap_or(BatteryCharge::Unknown)
            } else {
                BatteryCharge::Unknown
            };

            let decision = decide_pause(&rules, metered, charging);
            {
                let Ok(mut guard) = shared.write() else {
                    tracing::warn!("kindness limits lock poisoned; stopping the limits watcher");
                    return;
                };
                guard.metered = metered;
                guard.charging = charging;
                guard.paused_reason = decision;
            }

            match decision {
                Some(reason) => {
                    if paused != Some(reason) {
                        match paused {
                            Some(previous) => tracing::info!(
                                from = previous.as_str(),
                                to = reason.as_str(),
                                "kindness pause reason changed"
                            ),
                            None => {
                                tracing::info!(
                                    reason = reason.as_str(),
                                    "kindness proxy paused (limits)"
                                )
                            }
                        }
                        if let Err(error) = handle.stop().await {
                            tracing::warn!(%error, sidecar = "snowflake-proxy", "could not stop the kindness proxy for a limits pause");
                        }
                        paused = Some(reason);
                    }
                }
                None if paused.is_some() => {
                    tracing::info!("kindness limits cleared; resuming the proxy");
                    if let Err(error) = handle.start().await {
                        tracing::warn!(%error, sidecar = "snowflake-proxy", "could not resume the kindness proxy after limits");
                    }
                    paused = None;
                }
                _ => {}
            }

            tokio::time::sleep(interval).await;
        }
    });
}

/// Detect the link's metered state (blocking; run via `spawn_blocking`).
///
/// Only Linux is implemented: NetworkManager exposes a per-connection
/// `Metered` property. macOS and Windows do not expose a metered flag, and
/// report `LinkMetered::Unknown`.
pub(crate) fn detect_metered_blocking() -> LinkMetered {
    #[cfg(target_os = "linux")]
    {
        metered_via_busctl().unwrap_or(LinkMetered::Unknown)
    }
    #[cfg(not(target_os = "linux"))]
    {
        LinkMetered::Unknown
    }
}

/// Detect battery charging state (blocking; run via `spawn_blocking`).
///
/// macOS probes `pmset -g batt`; Linux scans `/sys/class/power_supply`.
/// Machines without a battery report `BatteryCharge::Unknown`.
pub(crate) fn detect_charging_blocking() -> BatteryCharge {
    #[cfg(target_os = "macos")]
    {
        parse_pmset_batt(&pmset_batt_output())
    }
    #[cfg(target_os = "linux")]
    {
        charging_from_sysfs()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        BatteryCharge::Unknown
    }
}

/// Parse `pmset -g batt` output.
///
/// `discharging` is checked first (it contains `charging` as a substring and
/// marks battery discharging); a present battery that is not discharging
/// means the machine is on AC power; `NoInternalBattery` means no battery
/// exists and the charging rule is not enforceable.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_pmset_batt(output: &str) -> BatteryCharge {
    let low = output.to_lowercase();
    if low.contains("discharging") {
        BatteryCharge::Discharging
    } else if low.contains("nointernalbattery") {
        BatteryCharge::Unknown
    } else if low.contains("internalbattery") {
        BatteryCharge::Charging
    } else {
        BatteryCharge::Unknown
    }
}

#[cfg(target_os = "macos")]
fn pmset_batt_output() -> String {
    let Ok(output) = std::process::Command::new("pmset")
        .arg("-g")
        .arg("batt")
        .stdin(std::process::Stdio::null())
        .output()
    else {
        tracing::debug!("kindness limits: pmset is unavailable; charging state unknown");
        return String::new();
    };
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Aggregate the `status` values of battery-type supplies. `statuses` holds
/// the values that were readable (`"Charging"`, `"Discharging"`, `"Full"`,
/// ...); empty means no battery supply was found.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn battery_from_statuses(statuses: &[&str]) -> BatteryCharge {
    if statuses.contains(&"Discharging") {
        BatteryCharge::Discharging
    } else if statuses.is_empty() {
        BatteryCharge::Unknown
    } else {
        BatteryCharge::Charging
    }
}

#[cfg(target_os = "linux")]
fn charging_from_sysfs() -> BatteryCharge {
    let mut statuses: Vec<String> = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/power_supply") else {
        return BatteryCharge::Unknown;
    };
    for entry in entries.flatten() {
        let Ok(kind) = std::fs::read_to_string(entry.path().join("type")) else {
            continue;
        };
        if kind.trim() != "Battery" {
            continue;
        }
        if let Ok(status) = std::fs::read_to_string(entry.path().join("status")) {
            statuses.push(status.trim().to_owned());
        }
    }
    let refs: Vec<&str> = statuses.iter().map(String::as_str).collect();
    battery_from_statuses(&refs)
}

/// Linux: ask NetworkManager whether any active connection is metered.
///
/// `Metered` values follow the NM enum: 0 Unknown, 1 Yes, 2 GuessYes,
/// 3 GuessNo, 4 No. Any active `Yes`/`GuessYes` wins; a definite
/// `No`/`GuessNo` on every connection is the only unpause; anything else is
/// `Unknown`.
#[cfg(target_os = "linux")]
fn metered_via_busctl() -> Option<LinkMetered> {
    let listing = run_busctl(
        "call",
        &[
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
            "ActiveConnections",
        ],
    )
    .ok()?;
    let paths: Vec<&str> = listing
        .split_whitespace()
        .filter(|t| t.starts_with("/org/freedesktop/NetworkManager/ActiveConnection/"))
        .collect();
    if paths.is_empty() {
        // Nothing connected: not a definite unmetered report.
        return None;
    }

    let mut values: Vec<Option<u32>> = Vec::new();
    for path in paths {
        let out = run_busctl(
            "get-property",
            &[
                "org.freedesktop.NetworkManager",
                path,
                "org.freedesktop.NetworkManager.Connection.Active",
                "Metered",
            ],
        )
        .ok()?;
        values.push(parse_busctl_property(&out));
    }
    metered_from_properties(&values)
}

/// Aggregate per-connection `Metered` values into one link verdict.
///
/// Any `Yes`/`GuessYes` (1/2) reports a metered link; a definite
/// `No`/`GuessNo` (3/4) on every connection is the only unpause; values of 0
/// or failed probes (`None`) keep the result conservative (`Unknown`).
/// `None` overall means the probe failed conclusively (caller reports
/// unknown).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn metered_from_properties(values: &[Option<u32>]) -> Option<LinkMetered> {
    let mut any_metered = false;
    let mut any_definite = false;
    for value in values.iter().filter_map(|value| *value) {
        match value {
            1 | 2 => {
                any_metered = true;
                any_definite = true;
            }
            3 | 4 => any_definite = true,
            _ => {}
        }
    }
    if any_metered {
        Some(LinkMetered::Yes)
    } else if any_definite {
        Some(LinkMetered::No)
    } else {
        Some(LinkMetered::Unknown)
    }
}

#[cfg(target_os = "linux")]
fn run_busctl(verb: &str, args: &[&str]) -> std::io::Result<String> {
    let output = std::process::Command::new("busctl")
        .arg(verb)
        .arg("--system")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "busctl {verb} failed with status {}",
            output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parse one `busctl get-property` value: the last whitespace-separated
/// integer in the output (`u 4`, or a multiline dump). Returns `None` when no
/// integer appears.
#[cfg(target_os = "linux")]
fn parse_busctl_property(output: &str) -> Option<u32> {
    output
        .split_whitespace()
        .filter(|token| token.chars().all(|c| c.is_numeric()))
        .next_back()
        .and_then(|token| token.parse().ok())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const NONE_PAUSE: LimitRules = LimitRules {
        pause_on_metered: false,
        pause_when_not_charging: false,
    };
    const RULES_PAUSE_METERED: LimitRules = LimitRules {
        pause_on_metered: true,
        pause_when_not_charging: false,
    };
    const RULES_PAUSE_NOT_CHARGING: LimitRules = LimitRules {
        pause_on_metered: false,
        pause_when_not_charging: true,
    };
    const RULES_BOTH: LimitRules = LimitRules {
        pause_on_metered: true,
        pause_when_not_charging: true,
    };

    #[test]
    fn rules_report_watching_requirements() {
        assert!(!NONE_PAUSE.any());
        assert!(RULES_PAUSE_METERED.any());
        assert!(RULES_PAUSE_NOT_CHARGING.any());
        assert!(RULES_BOTH.any());
        assert!(LimitRules::from_config(&KindnessConfig::default()).any());
    }

    #[test]
    fn decide_pause_matrix() {
        // Unknown states never pause (best-effort guarantee).
        assert_eq!(
            decide_pause(
                &RULES_PAUSE_METERED,
                LinkMetered::Unknown,
                BatteryCharge::Unknown
            ),
            None
        );
        assert_eq!(
            decide_pause(
                &RULES_PAUSE_NOT_CHARGING,
                LinkMetered::Unknown,
                BatteryCharge::Unknown
            ),
            None
        );
        assert_eq!(
            decide_pause(
                &RULES_PAUSE_METERED,
                LinkMetered::No,
                BatteryCharge::Discharging
            ),
            None,
            "metered rule only reacts to metered links"
        );
        assert_eq!(
            decide_pause(
                &RULES_PAUSE_NOT_CHARGING,
                LinkMetered::No,
                BatteryCharge::Charging
            ),
            None,
            "charging rule only reacts to discharging batteries"
        );
        assert_eq!(
            decide_pause(&NONE_PAUSE, LinkMetered::Yes, BatteryCharge::Discharging),
            None,
            "no rules means never paused"
        );
    }

    #[test]
    fn decide_pause_positive_matches() {
        assert_eq!(
            decide_pause(
                &RULES_PAUSE_METERED,
                LinkMetered::Yes,
                BatteryCharge::Charging
            ),
            Some(PauseReason::MeteredLink)
        );
        assert_eq!(
            decide_pause(
                &RULES_PAUSE_NOT_CHARGING,
                LinkMetered::No,
                BatteryCharge::Discharging
            ),
            Some(PauseReason::NotCharging)
        );
        // Precedence: an active metered rule wins when both rules match.
        assert_eq!(
            decide_pause(&RULES_BOTH, LinkMetered::Yes, BatteryCharge::Discharging),
            Some(PauseReason::MeteredLink)
        );
        // An "unmetered"/"charging" report is a definite unpause condition.
        assert_eq!(
            decide_pause(
                &RULES_PAUSE_METERED,
                LinkMetered::No,
                BatteryCharge::Unknown
            ),
            None
        );
        assert_eq!(
            decide_pause(
                &RULES_PAUSE_NOT_CHARGING,
                LinkMetered::Unknown,
                BatteryCharge::Charging
            ),
            None
        );
    }

    #[cfg(unix)]
    mod behavior {
        use super::*;
        use crate::pt_supervisor::{RestartPolicy, SidecarState, spawn_supervised};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

        /// Probe chips: 0 = unknown, 1 = discharging/metered, 2 = charging/unmetered.
        fn battery_probe(code: Arc<AtomicU8>) -> &'static ChargeProbe {
            Box::leak(Box::new(move || match code.load(Ordering::SeqCst) {
                1 => BatteryCharge::Discharging,
                2 => BatteryCharge::Charging,
                _ => BatteryCharge::Unknown,
            }) as Box<ChargeProbe>)
        }

        fn metered_probe(code: Arc<AtomicU8>) -> &'static MeteredProbe {
            Box::leak(Box::new(move || match code.load(Ordering::SeqCst) {
                1 => LinkMetered::Yes,
                2 => LinkMetered::No,
                _ => LinkMetered::Unknown,
            }) as Box<MeteredProbe>)
        }

        fn supervisor_with_sleeping_proxy(dir: &std::path::Path) -> PtSidecarHandle {
            let bin = dir.join("snowflake-proxy");
            std::fs::write(&bin, "#!/bin/sh\nwhile true; do sleep 1; done\n")
                .expect("write fake proxy");
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
                    .expect("chmod");
            }
            let mut cfg = KindnessConfig::default();
            cfg.proxy_path = Some(bin.to_string_lossy().into_owned());
            let spec = crate::kindness::build_spec(&cfg, bin, dir);
            let restart = crate::pt_supervisor::RestartPolicy {
                enabled: false,
                ..RestartPolicy::default()
            };
            let (handle, _join) = spawn_supervised(spec, restart);
            handle
        }

        async fn wait_for_state(handle: &PtSidecarHandle, wanted: SidecarState, what: &str) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                if handle.snapshot().state == wanted {
                    return;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for {what}: {state:?}",
                    state = handle.snapshot().state
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        async fn wait_for_flag(
            shared: &LimitShared,
            paused: bool,
        ) -> crate::kindness_limits::LimitsObserved {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let guard = shared.read().expect("kindness limits lock");
                if guard.paused_reason.is_some() == paused {
                    return guard.clone();
                }
                drop(guard);
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for paused={paused}"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        #[allow(clippy::expect_used, clippy::unwrap_used)]
        #[tokio::test]
        async fn watcher_pauses_and_resumes_on_charging_rule() {
            let dir = tempfile::TempDir::new().expect("tmp");
            let handle = supervisor_with_sleeping_proxy(dir.path());
            handle.start().await;
            wait_for_state(&handle, SidecarState::Ready, "initial start").await;

            let shared: LimitShared = Arc::new(std::sync::RwLock::new(LimitsObserved::default()));
            let battery = Arc::new(AtomicU8::new(0));
            spawn_watcher_with(
                handle.clone(),
                RULES_PAUSE_NOT_CHARGING,
                Arc::clone(&shared),
                Duration::from_millis(60),
                metered_probe(Arc::new(AtomicU8::new(0))),
                battery_probe(Arc::clone(&battery)),
            );

            // Discharging: the watcher must pause the proxy.
            battery.store(1, Ordering::SeqCst);
            let observed = wait_for_flag(&shared, true).await;
            assert_eq!(observed.paused_reason, Some(PauseReason::NotCharging));
            wait_for_state(&handle, SidecarState::Stopped, "limits pause").await;

            // Charging again: the watcher must resume the proxy.
            battery.store(2, Ordering::SeqCst);
            let observed = wait_for_flag(&shared, false).await;
            assert_eq!(observed.paused_reason, None);
            assert_eq!(observed.charging, BatteryCharge::Charging);
            wait_for_state(&handle, SidecarState::Ready, "limits resume").await;

            handle.shutdown().await;
        }

        #[allow(clippy::expect_used, clippy::unwrap_used)]
        #[tokio::test]
        async fn watcher_with_no_rules_never_probes() {
            let dir = tempfile::TempDir::new().expect("tmp");
            let handle = supervisor_with_sleeping_proxy(dir.path());

            let shared: LimitShared = Arc::new(std::sync::RwLock::new(LimitsObserved::default()));
            let link_calls = Arc::new(AtomicUsize::new(0));
            let charge_calls = Arc::new(AtomicUsize::new(0));
            let lc = Arc::clone(&link_calls);
            let cc = Arc::clone(&charge_calls);
            let metered: &'static MeteredProbe = Box::leak(Box::new(move || {
                lc.fetch_add(1, Ordering::SeqCst);
                LinkMetered::Unknown
            }) as Box<MeteredProbe>);
            let charging: &'static ChargeProbe = Box::leak(Box::new(move || {
                cc.fetch_add(1, Ordering::SeqCst);
                BatteryCharge::Unknown
            }) as Box<ChargeProbe>);

            spawn_watcher_with(
                handle,
                NONE_PAUSE,
                Arc::clone(&shared),
                Duration::from_millis(40),
                metered,
                charging,
            );
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(link_calls.load(Ordering::SeqCst), 0, "no rules: no probing");
            assert_eq!(
                charge_calls.load(Ordering::SeqCst),
                0,
                "no rules: no probing"
            );
            let guard = shared.read().expect("kindness limits lock");
            assert_eq!(guard.paused_reason, None);
            assert_eq!(guard.metered, LinkMetered::Unknown);
            assert_eq!(guard.charging, BatteryCharge::Unknown);
        }
    }

    #[test]
    fn parse_pmset_batt_discharging() {
        // Real macOS output shape.
        let output = "Now drawing from 'Battery Power'\n \
             -InternalBattery-0 (id=22413411)\t52%; discharging; 6:43 remaining present: true\n";
        assert_eq!(parse_pmset_batt(output), BatteryCharge::Discharging);
    }

    #[test]
    fn parse_pmset_batt_charging_and_ac() {
        assert_eq!(
            parse_pmset_batt(
                "Now drawing from 'AC Power'\n -InternalBattery-0 (id=22413411)\t52%; charging; 0:37 until full present: true\n"
            ),
            BatteryCharge::Charging
        );
        assert_eq!(
            parse_pmset_batt(
                "Now drawing from 'AC Power'\n -InternalBattery-0 (id=1)\t100%; AC Power; present: true\n"
            ),
            BatteryCharge::Charging
        );
    }

    #[test]
    fn parse_pmset_batt_no_battery_is_unknown() {
        assert_eq!(
            parse_pmset_batt(
                "Now drawing from 'AC Power'\n -NoInternalBattery-0 (id=0)\t0%; present: false\n"
            ),
            BatteryCharge::Unknown
        );
        assert_eq!(parse_pmset_batt(""), BatteryCharge::Unknown);
        // Garbage output stays unknown rather than pausing the proxy.
        assert_eq!(
            parse_pmset_batt("something entirely unexpected"),
            BatteryCharge::Unknown
        );
    }

    #[test]
    fn battery_from_statuses_matrix() {
        // No battery-type supply: unknown.
        assert_eq!(battery_from_statuses(&[]), BatteryCharge::Unknown);
        // Discharging anywhere wins.
        assert_eq!(
            battery_from_statuses(&["Charging", "Discharging"]),
            BatteryCharge::Discharging
        );
        // Battery present but nothing discharging: on AC.
        assert_eq!(
            battery_from_statuses(&["Charging", "Full"]),
            BatteryCharge::Charging
        );
        assert_eq!(battery_from_statuses(&["Full"]), BatteryCharge::Charging);
    }

    #[test]
    fn limit_state_labels() {
        assert_eq!(LinkMetered::Unknown.as_str(), "unknown");
        assert_eq!(LinkMetered::Yes.as_str(), "metered");
        assert_eq!(LinkMetered::No.as_str(), "unmetered");
        assert_eq!(BatteryCharge::Unknown.as_str(), "unknown");
        assert_eq!(BatteryCharge::Charging.as_str(), "charging");
        assert_eq!(BatteryCharge::Discharging.as_str(), "discharging");
        assert_eq!(PauseReason::MeteredLink.as_str(), "metered");
        assert_eq!(PauseReason::NotCharging.as_str(), "not_charging");
        let observed = LimitsObserved::default();
        assert_eq!(observed.metered, LinkMetered::Unknown);
        assert_eq!(observed.charging, BatteryCharge::Unknown);
        assert_eq!(observed.paused_reason, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_busctl_property_extracts_last_integer() {
        assert_eq!(parse_busctl_property("u 4"), Some(4));
        assert_eq!(
            parse_busctl_property(
                "ao 2 /org/freedesktop/NetworkManager/ActiveConnection/1 /org/freedesktop/NetworkManager/ActiveConnection/2"
            ),
            Some(2)
        );
        assert_eq!(parse_busctl_property(""), None);
        assert_eq!(parse_busctl_property("no numbers here"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn metered_from_properties_aggregates() {
        // Any metered connection wins.
        assert_eq!(
            metered_from_properties(&[Some(4), Some(1)]),
            Some(LinkMetered::Yes)
        );
        assert_eq!(
            metered_from_properties(&[Some(3), Some(2)]),
            Some(LinkMetered::Yes)
        );
        // Definite no on every connection is the only unpause.
        assert_eq!(
            metered_from_properties(&[Some(3), Some(4)]),
            Some(LinkMetered::No)
        );
        // Unknown verdicts everywhere, no definite value: still a verdict of
        // unknown-but-probed.
        assert_eq!(
            metered_from_properties(&[Some(0), Some(0)]),
            Some(LinkMetered::Unknown)
        );
    }
}
