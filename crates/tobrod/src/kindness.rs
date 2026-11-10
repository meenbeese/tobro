//! Kindness Mode (M6, F-60): the supervised `snowflake-proxy` sidecar.
//!
//! Responsibilities:
//! - **Locate** the upstream `snowflake-proxy` binary from configured or
//!   known sidecar locations (same search strategy as PT clients).
//! - **Verify** the binary via SHA-256 when `kindness.sha256_hex` is set.
//! - **Spec-build**: map `[kindness]` config onto proxy command-line flags
//!   (only configured overrides are passed; the binary applies its own
//!   defaults for everything else).
//! - **Start/Stop**: delegate the whole process lifecycle (private state dir,
//!   supervised start watch, graceful/forced stop) to the reusable
//!   sidecar supervisor in [`crate::pt_supervisor`].
//! - **Crash backoff**: restart with exponential backoff (default 1s→30s)
//!   when the proxy exits unexpectedly, resetting on a successful start.
//!
//! The proxy speaks the WebSocket/WebRTC rendezvous protocol to a broker,
//! not the Tor PT line protocol, so readiness is reported on spawn rather
//! than gated on a `CMETHOD`/`SMETHOD` line. NAT-type detection, served
//! counts, and UPnP stay separate M6 items.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};

use crate::pt_supervisor::{
    self, LocateOptions, LocatedSidecar, PtSidecarHandle, RestartPolicy, SidecarEvent, SidecarId,
    SidecarSnapshot, SidecarSpec, VerifySpec,
};
use crate::redact::redact_secrets;

/// Logical sidecar id (for logs/events).
const SIDECAR_ID: &str = "snowflake-proxy";

/// Candidate binary names, in search order (`snowflake-client` is the PT
/// client sidecar; the proxy binary has its own name).
pub(crate) const BINARY_NAMES: &[&str] = &["snowflake-proxy"];

/// Timeout applied to the final shutdown of the supervisor task.
const SHUTDOWN_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Locate the `snowflake-proxy` binary using the standard sidecar search
/// strategy: explicit config path → configured dir → app/exe-relative dirs →
/// daemon state dirs → `PATH`.
pub(crate) fn locate_binary(
    cfg: &tobro_config::KindnessConfig,
    state_dir: Option<&Path>,
) -> anyhow::Result<LocatedSidecar> {
    if let Some(p) = cfg.proxy_path.as_deref() {
        return pt_supervisor::locate(&LocateOptions {
            explicit_path: Some(PathBuf::from(p)),
            search_dirs: Vec::new(),
            names: Vec::new(),
        })
        .with_context(|| format!("configured kindness.proxy_path is not usable: {p}"));
    }

    let mut search_dirs = Vec::new();
    if let Some(d) = cfg.proxy_dir.as_deref() {
        search_dirs.push(PathBuf::from(d));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        search_dirs.push(dir.to_path_buf());
        search_dirs.push(dir.join("binaries"));
        search_dirs.push(dir.join("../Resources"));
        search_dirs.push(dir.join("../Resources/binaries"));
    }
    if let Some(sd) = state_dir {
        search_dirs.push(sd.join("pt"));
        search_dirs.push(sd.join("sidecars"));
    }

    pt_supervisor::locate(&LocateOptions {
        explicit_path: None,
        search_dirs,
        names: BINARY_NAMES.iter().map(OsString::from).collect(),
    })
}

/// Map `[kindness]` config onto the `snowflake-proxy` command line.
///
/// Only configured overrides are forwarded (`-broker`, `-relay`, `-stun`,
/// `-capacity`, `-verbose`, `-nat-type-force-unrestricted`); unset values
/// fall back to the binary's own defaults, and `kindness.capacity` is only
/// passed when explicitly set because current upstream releases removed the
/// flag in favor of broker-recommended capacity. `kindness.extra_args` is
/// appended verbatim at the end (power-user escape hatch).
pub(crate) fn build_args(cfg: &tobro_config::KindnessConfig) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();

    if let Some(url) = cfg.broker_url.as_deref().map(str::trim)
        && !url.is_empty()
    {
        args.push("-broker".into());
        args.push(url.into());
    }
    if let Some(url) = cfg.relay_url.as_deref().map(str::trim)
        && !url.is_empty()
    {
        args.push("-relay".into());
        args.push(url.into());
    }
    if let Some(url) = cfg.stun_url.as_deref().map(str::trim)
        && !url.is_empty()
    {
        args.push("-stun".into());
        args.push(url.into());
    }
    if let Some(capacity) = cfg.capacity.filter(|c| *c > 0) {
        args.push("-capacity".into());
        args.push(capacity.to_string().into());
    }
    // Upstream `<min>:<max>` passthrough; normalize the stored value so the
    // flag always gets exactly one form (validation rejects invalid values).
    if let Ok((min, max)) = cfg.parse_ephemeral_ports() {
        args.push("-ephemeral-ports-range".into());
        args.push(format!("{min}:{max}").into());
    }
    if cfg.verbose {
        args.push("-verbose".into());
    }
    if cfg.nat_type_force_unrestricted {
        args.push("-nat-type-force-unrestricted".into());
    }
    for extra in &cfg.extra_args {
        args.push(extra.into());
    }
    args
}

/// Build the sidecar spec for the proxy: a private state dir, no PT
/// required-transport gate (readiness is reported on spawn), and no extra
/// environment.
pub(crate) fn build_spec(
    cfg: &tobro_config::KindnessConfig,
    program: PathBuf,
    state_dir: &Path,
) -> SidecarSpec {
    SidecarSpec {
        id: SidecarId::new(SIDECAR_ID),
        program,
        args: build_args(cfg),
        env: HashMap::new(),
        state_dir: state_dir.join("kindness"),
        // The proxy logs via stderr, not the PT line protocol.
        required_transports: HashSet::new(),
        readiness_timeout: None,
    }
}

/// Handle for controlling a spawned (not necessarily started) proxy.
pub(crate) struct KindnessSupervisor {
    handle: PtSidecarHandle,
    join: tokio::task::JoinHandle<()>,
}

impl KindnessSupervisor {
    /// Request start (the supervisor reports when the proxy is running).
    pub(crate) async fn start(&self) {
        if let Err(error) = self.handle.start().await {
            tracing::warn!(%error, sidecar = SIDECAR_ID, "could not request kindness proxy start");
        }
    }

    /// Request a graceful stop (supervisor keeps running for restarts).
    #[allow(dead_code)]
    pub(crate) async fn stop(&self) {
        if let Err(error) = self.handle.stop().await {
            tracing::warn!(%error, sidecar = SIDECAR_ID, "could not request kindness proxy stop");
        }
    }

    /// Current snapshot of the supervised proxy.
    #[allow(dead_code)]
    pub(crate) fn snapshot(&self) -> SidecarSnapshot {
        self.handle.snapshot()
    }

    /// Subscribe to state snapshots (for future IPC/UI surface).
    #[allow(dead_code)]
    pub(crate) fn subscribe_status(&self) -> tokio::sync::watch::Receiver<SidecarSnapshot> {
        self.handle.subscribe_status()
    }

    /// Subscribe to sidecar events (for tests and the future IPC/UI surface).
    #[allow(dead_code)]
    pub(crate) fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<SidecarEvent> {
        self.handle.subscribe_events()
    }

    /// Clonable control handle for the IPC surface (`kindness.status`).
    pub(crate) fn control_handle(&self) -> PtSidecarHandle {
        self.handle.clone()
    }

    /// Spawn a task that forwards sidecar events into `tracing` so the proxy
    /// shows up in daemon logs at the existing conventions: state changes and
    /// errors at info/warn, raw output lines at debug, secrets redacted.
    pub(crate) fn spawn_event_logger(&self) -> tokio::task::JoinHandle<()> {
        use tokio::sync::broadcast::error::RecvError;

        let mut events = self.handle.subscribe_events();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => log_kindness_event(&event),
                    Err(RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            sidecar = SIDECAR_ID,
                            skipped,
                            "kindness proxy events dropped"
                        );
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        })
    }

    /// Stop the proxy for good and let the supervisor task exit.
    pub(crate) async fn shutdown(self) {
        if let Err(error) = self.handle.shutdown().await {
            tracing::warn!(%error, sidecar = SIDECAR_ID, "could not request kindness proxy shutdown");
        }
        let _ = tokio::time::timeout(SHUTDOWN_JOIN_TIMEOUT, self.join).await;
    }
}

fn log_kindness_event(event: &SidecarEvent) {
    match event {
        SidecarEvent::StdoutLine { line, .. } => {
            tracing::debug!(sidecar = SIDECAR_ID, stdout = %redact_secrets(line.trim_end()));
        }
        SidecarEvent::StderrLine { line, .. } => {
            tracing::debug!(sidecar = SIDECAR_ID, stderr = %redact_secrets(line.trim_end()));
        }
        SidecarEvent::State(snapshot) => {
            tracing::debug!(sidecar = SIDECAR_ID, state = ?snapshot.state, pid = ?snapshot.pid, "kindness proxy state");
        }
        SidecarEvent::Ready { .. } => {
            tracing::info!(
                sidecar = SIDECAR_ID,
                "snowflake-proxy running (kindness mode)"
            );
        }
        SidecarEvent::Error { message, fatal, .. } => {
            if *fatal {
                tracing::warn!(
                    sidecar = SIDECAR_ID,
                    message,
                    "snowflake-proxy reported a fatal error"
                );
            } else {
                tracing::info!(
                    sidecar = SIDECAR_ID,
                    message,
                    "snowflake-proxy reported an error"
                );
            }
        }
        SidecarEvent::Exited { code, signal, .. } => {
            tracing::info!(sidecar = SIDECAR_ID, code = ?code, signal = ?signal, "snowflake-proxy exited");
        }
    }
}

/// Locate, verify, and spawn (not start) the snowflake-proxy supervisor with
/// the default crash-backoff policy (restarts enabled, 1s→30s).
pub(crate) fn spawn_supervised(
    cfg: &tobro_config::KindnessConfig,
    state_dir: &Path,
) -> anyhow::Result<KindnessSupervisor> {
    spawn_supervised_with(cfg, state_dir, RestartPolicy::default())
}

/// [`spawn_supervised`] with an explicit restart policy (used by tests).
pub(crate) fn spawn_supervised_with(
    cfg: &tobro_config::KindnessConfig,
    state_dir: &Path,
    restart: RestartPolicy,
) -> anyhow::Result<KindnessSupervisor> {
    let located = locate_binary(cfg, Some(state_dir))
        .context("could not locate the snowflake-proxy binary")?;

    let verify_spec = VerifySpec {
        sha256_hex: cfg.sha256_hex.clone(),
    };
    match pt_supervisor::verify(&located.path, &verify_spec) {
        Ok(report) if report.ok => {
            tracing::info!(path = %located.path.display(), sha256 = %report.sha256_hex, "snowflake-proxy verified");
        }
        Ok(report) => {
            bail!(
                "snowflake-proxy failed verification ({}): {}",
                located.path.display(),
                report.detail.as_deref().unwrap_or("mismatch")
            );
        }
        Err(error) => {
            bail!(
                "snowflake-proxy verification failed for {}: {error:#}",
                located.path.display()
            );
        }
    }

    let spec = build_spec(cfg, located.path, state_dir);
    let (handle, join) = pt_supervisor::spawn_supervised(spec, restart);
    Ok(KindnessSupervisor { handle, join })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn default_cfg() -> tobro_config::KindnessConfig {
        tobro_config::KindnessConfig::default()
    }

    fn cfg_with(
        mutate: impl FnOnce(&mut tobro_config::KindnessConfig),
    ) -> tobro_config::KindnessConfig {
        let mut cfg = default_cfg();
        mutate(&mut cfg);
        cfg
    }

    #[test]
    fn default_config_yields_no_args() {
        let cfg = default_cfg();
        assert!(cfg.validate().is_ok());
        assert!(build_args(&cfg).is_empty());
    }

    #[test]
    fn build_args_passes_configured_flags_in_order() {
        let cfg = cfg_with(|c| {
            c.broker_url = Some(" https://broker.example.com/ ".to_owned());
            c.relay_url = Some("wss://relay.example.com/".to_owned());
            c.stun_url = Some("stun:stun.example.com:3478".to_owned());
            c.capacity = Some(7);
            c.verbose = true;
            c.nat_type_force_unrestricted = true;
            c.ephemeral_ports = Some("30000 : 31000".to_owned());
        });
        let args = build_args(&cfg);
        assert_eq!(
            args,
            vec![
                OsStr::new("-broker"),
                OsStr::new("https://broker.example.com/"),
                OsStr::new("-relay"),
                OsStr::new("wss://relay.example.com/"),
                OsStr::new("-stun"),
                OsStr::new("stun:stun.example.com:3478"),
                OsStr::new("-capacity"),
                OsStr::new("7"),
                OsStr::new("-ephemeral-ports-range"),
                OsStr::new("30000:31000"),
                OsStr::new("-verbose"),
                OsStr::new("-nat-type-force-unrestricted"),
            ]
        );
    }

    #[test]
    fn build_args_appends_extra_args_last() {
        let cfg = cfg_with(|c| {
            c.verbose = true;
            c.extra_args = vec!["--foo".to_owned(), "bar baz".to_owned()];
        });
        let args = build_args(&cfg);
        assert_eq!(
            args,
            vec![
                OsStr::new("-verbose"),
                OsStr::new("--foo"),
                OsStr::new("bar baz"),
            ]
        );
    }

    #[test]
    fn build_spec_uses_private_state_dir_and_no_pt_gate() {
        let cfg = cfg_with(|c| {
            c.relay_url = Some("wss://relay.example.com/".to_owned());
        });
        let spec = build_spec(
            &cfg,
            PathBuf::from("/opt/snowflake-proxy"),
            Path::new("/state"),
        );
        assert_eq!(spec.id.as_str(), "snowflake-proxy");
        assert_eq!(spec.program, PathBuf::from("/opt/snowflake-proxy"));
        assert!(spec.state_dir == Path::new("/state").join("kindness"));
        assert!(spec.required_transports.is_empty());
        assert_eq!(
            spec.args,
            vec![OsStr::new("-relay"), OsStr::new("wss://relay.example.com/")]
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn locate_binary_uses_configured_dir() {
        let dir = tempfile::TempDir::new().expect("tmp");
        let path = dir.path().join("snowflake-proxy");
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        let cfg = cfg_with(|c| {
            c.proxy_dir = Some(dir.path().to_string_lossy().into_owned());
        });
        let found = locate_binary(&cfg, None).expect("locate");
        assert!(found.path.ends_with("snowflake-proxy"));
    }

    #[test]
    fn locate_binary_rejects_missing_explicit_path() {
        let cfg = cfg_with(|c| {
            c.proxy_path = Some("/definitely/not/snowflake-proxy-here".to_owned());
        });
        assert!(locate_binary(&cfg, None).is_err());
    }

    #[test]
    fn spawn_supervised_verifies_sha256() {
        // Wrong digest must fail before any process is spawned.
        let dir = tempfile::TempDir::new().expect("tmp");
        let path = dir.path().join("snowflake-proxy");
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        let cfg = cfg_with(|c| {
            c.proxy_path = Some(path.to_string_lossy().into_owned());
            c.sha256_hex = Some("00".repeat(32));
        });
        let err = spawn_supervised(&cfg, dir.path()).err().expect("must fail");
        assert!(
            format!("{err:#}").contains("failed verification"),
            "{err:#}"
        );
    }

    #[cfg(unix)]
    fn write_fake_proxy(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join("snowflake-proxy");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    #[cfg(unix)]
    fn supervisor_with_fake(dir: &Path, body: &str, restart: RestartPolicy) -> KindnessSupervisor {
        let bin = write_fake_proxy(dir, body);
        let cfg = cfg_with(|c| {
            c.proxy_path = Some(bin.to_string_lossy().into_owned());
        });
        spawn_supervised_with(&cfg, dir, restart).expect("spawn")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn supervisor_reaches_running_and_stops() {
        let dir = tempfile::TempDir::new().expect("tmp");
        let sup = supervisor_with_fake(
            dir.path(),
            "while true; do sleep 1; done",
            RestartPolicy {
                enabled: false,
                ..RestartPolicy::default()
            },
        );
        sup.start().await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let snap = sup.snapshot();
            if snap.state == pt_supervisor::SidecarState::Ready {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out: {snap:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        sup.stop().await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(sup.snapshot().state, pt_supervisor::SidecarState::Stopped);
        sup.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn supervisor_schedules_crash_backoff_restarts() {
        let dir = tempfile::TempDir::new().expect("tmp");
        // The fake proxy exits immediately: the supervisor must schedule a
        // restart. Each spawn reports Ready (no PT gate), so counting two
        // Ready events proves a crash was followed by a respawn.
        let sup = supervisor_with_fake(
            dir.path(),
            "exit 1",
            RestartPolicy {
                enabled: true,
                initial: Duration::from_millis(100),
                max: Duration::from_millis(400),
            },
        );
        let mut events = sup.subscribe_events();
        sup.start().await;

        let mut ready_events = 0usize;
        let mut exited = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while ready_events < 2 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for the supervisor to respawn the crashed proxy"
            );
            let event = events.recv().await.expect("event channel open");
            match event {
                SidecarEvent::Ready { .. } => ready_events += 1,
                SidecarEvent::Exited { .. } => exited = true,
                _ => {}
            }
        }
        assert!(exited, "expected at least one crash before the respawn");
        assert_eq!(
            ready_events, 2,
            "expected the crash to be followed by a respawn"
        );
        sup.shutdown().await;
    }
}
