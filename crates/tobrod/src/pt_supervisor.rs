//! Pluggable Transport (PT) sidecar supervisor (M3).
//!
//! Responsibilities:
//! - **Locate** sidecar binaries from configured/known locations.
//! - **Verify** sidecars (SHA-256 hash checks; extensible verification hook).
//! - **Start** sidecars with a private state directory and PT-spec environment.
//! - **Stop** sidecars gracefully and forcefully, preventing orphan processes.
//! - **Restart** with exponential backoff when supervision is enabled.
//! - **Readiness and error parsing** from PT stdout/stderr protocol lines.
//!
//! Arti's `tor-ptmgr` can spawn/manage PT clients when transports are configured,
//! but tobro still needs to locate/verify pinned binaries, provide private state,
//! and interpret readiness/errors for UX and diagnostics. This module provides a
//! reusable, testable supervisor for PT-shaped sidecars.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tracing::debug;

use crate::redact::redact_secrets;

/// Default initial restart backoff.
pub const DEFAULT_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Default maximum restart backoff.
pub const DEFAULT_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Grace period before force-killing a stopped sidecar.
pub const DEFAULT_STOP_GRACE: Duration = Duration::from_secs(3);
/// Default readiness timeout when waiting for required transports.
pub const DEFAULT_READINESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Identifies a sidecar binary/kind.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SidecarId(pub String);

impl SidecarId {
    /// Create a sidecar identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    /// The identifier string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SidecarId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// How to locate a sidecar binary.
#[derive(Debug, Clone, Default)]
pub struct LocateOptions {
    /// Explicit binary path (highest precedence when it exists and is executable).
    pub explicit_path: Option<PathBuf>,
    /// Directories to search, in order.
    pub search_dirs: Vec<PathBuf>,
    /// Candidate executable names (e.g. `lyrebird`, `lyrebird.exe`).
    pub names: Vec<OsString>,
}

/// Result of locating a sidecar.
#[derive(Debug, Clone)]
pub struct LocatedSidecar {
    /// Resolved executable path.
    pub path: PathBuf,
    /// Where it was found.
    pub source: LocateSource,
}

/// Where a located binary came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocateSource {
    /// The explicitly configured path.
    Explicit,
    /// A searched directory.
    SearchDir(PathBuf),
    /// Found on `PATH`.
    PathEnv,
}

/// Locate a sidecar binary.
///
/// Returns the first existing, file-like candidate. On Unix, executability is
/// checked when metadata is available; on non-Unix platforms existence is used.
pub fn locate(opts: &LocateOptions) -> anyhow::Result<LocatedSidecar> {
    if let Some(path) = &opts.explicit_path {
        if is_executable_candidate(path) {
            return Ok(LocatedSidecar {
                path: canonical_or_owned(path),
                source: LocateSource::Explicit,
            });
        }
        bail!(
            "explicit sidecar path does not exist or is not executable: {}",
            path.display()
        );
    }

    for dir in &opts.search_dirs {
        for name in &opts.names {
            let path = dir.join(name);
            if is_executable_candidate(&path) {
                return Ok(LocatedSidecar {
                    path: canonical_or_owned(&path),
                    source: LocateSource::SearchDir(dir.clone()),
                });
            }
        }
    }

    for name in &opts.names {
        if let Some(path) = find_on_path(name) {
            return Ok(LocatedSidecar {
                path,
                source: LocateSource::PathEnv,
            });
        }
    }

    let names = opts
        .names
        .iter()
        .map(|n| n.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(", ");
    bail!(
        "could not locate sidecar binary (tried: {}); searched {} configured director(ies)",
        if names.is_empty() {
            "<no names>"
        } else {
            &names
        },
        opts.search_dirs.len()
    )
}

fn canonical_or_owned(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn is_executable_candidate(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn find_on_path(name: &OsString) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable_candidate(&candidate) {
            return Some(canonical_or_owned(&candidate));
        }
    }
    None
}

/// Expected verification material for a sidecar.
#[derive(Debug, Clone, Default)]
pub struct VerifySpec {
    /// Expected SHA-256 digest as lowercase hex (64 chars).
    pub sha256_hex: Option<String>,
}

/// Verification outcome.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// Path that was verified.
    pub path: PathBuf,
    /// SHA-256 hex digest of the file contents.
    pub sha256_hex: String,
    /// True if all configured checks passed (or no checks were configured).
    pub ok: bool,
    /// Human-readable detail when verification fails or is partial.
    pub detail: Option<String>,
}

/// Verify a sidecar binary against the given spec.
///
/// Hash verification is performed when `spec.sha256_hex` is set. An empty spec
/// produces `ok=true` with a detail noting that no checks were configured;
/// callers that require verification should treat "no checks" as policy failure.
pub fn verify(path: &Path, spec: &VerifySpec) -> anyhow::Result<VerifyReport> {
    let bytes = std::fs::read(path).with_context(|| {
        format!(
            "failed to read sidecar for verification: {}",
            path.display()
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let actual = hex::encode(digest);

    let (ok, detail) = if let Some(expected) = &spec.sha256_hex {
        let expected_norm = expected.trim().to_ascii_lowercase();
        if expected_norm == actual {
            (true, Some("SHA-256 verified".to_owned()))
        } else {
            (
                false,
                Some(format!(
                    "SHA-256 mismatch for {}: expected {}, got {}",
                    path.display(),
                    expected_norm,
                    actual
                )),
            )
        }
    } else {
        (
            true,
            Some(format!(
                "no verification checks configured (computed SHA-256 {})",
                actual
            )),
        )
    };

    Ok(VerifyReport {
        path: path.to_path_buf(),
        sha256_hex: actual,
        ok,
        detail,
    })
}

/// A parsed PT protocol line from sidecar stdout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtLine {
    /// `CMETHOD <transport> <socks4|socks5> <addr:port> [args...]`
    ClientMethod {
        transport: String,
        endpoint: String,
        args: Vec<String>,
    },
    /// `CMETHOD-ERROR <transport> <message>`
    ClientMethodError { transport: String, message: String },
    /// `SMETHOD <transport> <addr:port> [args...]`
    ServerMethod { transport: String, endpoint: String },
    /// `SMETHOD-ERROR <transport> <message>`
    ServerMethodError { transport: String, message: String },
    /// `PROXY DONE`
    ProxyDone,
    /// `PROXY-ERROR <message>`
    ProxyError(String),
    /// `VERSION-ERROR <message>`
    VersionError(String),
    /// `ENV-ERROR <message>`
    EnvError(String),
    /// `LOG SEVERITY=<severity> MESSAGE=<message>` (or simplified forms)
    Log { severity: String, message: String },
    /// `STATUS TYPE=<type> ...`
    Status { kind: String, raw: String },
    /// Unrecognized/non-protocol line.
    Other(String),
}

/// Severity derived from PT output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PtSeverity {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
}

impl PtSeverity {
    fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "debug" => Self::Debug,
            "info" => Self::Info,
            "notice" => Self::Notice,
            "warn" | "warning" => Self::Warning,
            "err" | "error" => Self::Error,
            _ => Self::Info,
        }
    }
}

/// Parsed readiness/error classification for a PT line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtReadiness {
    /// Transport(s) that became ready due to this line.
    pub ready_transports: Vec<String>,
    /// User-safe error message if this line indicates failure.
    pub error: Option<String>,
    /// True when the line is a hard protocol error.
    pub fatal: bool,
}

/// Parse a PT stdout line.
#[must_use]
pub fn parse_pt_line(line: &str) -> PtLine {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.split_whitespace();
    let Some(keyword) = parts.next() else {
        return PtLine::Other(trimmed.to_owned());
    };
    match keyword {
        "CMETHOD" => {
            let transport = parts.next().unwrap_or_default().to_owned();
            let _socks = parts.next(); // socks4/socks5
            let endpoint = parts.next().unwrap_or_default().to_owned();
            let args = parts.map(ToOwned::to_owned).collect();
            PtLine::ClientMethod {
                transport,
                endpoint,
                args,
            }
        }
        "CMETHOD-ERROR" => {
            let transport = parts.next().unwrap_or_default().to_owned();
            let message = parts.collect::<Vec<_>>().join(" ");
            PtLine::ClientMethodError { transport, message }
        }
        "SMETHOD" => {
            let transport = parts.next().unwrap_or_default().to_owned();
            let endpoint = parts.next().unwrap_or_default().to_owned();
            PtLine::ServerMethod {
                transport,
                endpoint,
            }
        }
        "SMETHOD-ERROR" => {
            let transport = parts.next().unwrap_or_default().to_owned();
            let message = parts.collect::<Vec<_>>().join(" ");
            PtLine::ServerMethodError { transport, message }
        }
        "PROXY" => {
            let rest = parts.collect::<Vec<_>>().join(" ");
            if rest == "DONE" {
                PtLine::ProxyDone
            } else {
                PtLine::Other(trimmed.to_owned())
            }
        }
        "PROXY-ERROR" => PtLine::ProxyError(parts.collect::<Vec<_>>().join(" ")),
        "VERSION-ERROR" => PtLine::VersionError(parts.collect::<Vec<_>>().join(" ")),
        "ENV-ERROR" => PtLine::EnvError(parts.collect::<Vec<_>>().join(" ")),
        "LOG" => parse_pt_log(trimmed),
        "STATUS" => parse_pt_status(trimmed),
        _ => PtLine::Other(trimmed.to_owned()),
    }
}

fn parse_pt_log(line: &str) -> PtLine {
    let mut severity = "info".to_owned();
    let mut message = String::new();
    // Parse key=value tokens; MESSAGE is typically last and may be quoted in
    // extensions, but PT 1.0 uses simple tokens. Keep it robust.
    let mut rest = line.trim_start_matches("LOG").trim_start();
    while !rest.is_empty() {
        if let Some((k, v_tail)) = rest.split_once('=') {
            let key = k.trim();
            if key.eq_ignore_ascii_case("MESSAGE") {
                message = v_tail.trim().trim_matches('"').to_owned();
                break;
            }
            let (value, tail) = next_token(v_tail);
            if key.eq_ignore_ascii_case("SEVERITY") {
                severity = value.to_ascii_lowercase();
            }
            rest = tail.trim_start();
        } else {
            break;
        }
    }
    if message.is_empty() {
        message = line.to_owned();
    }
    PtLine::Log { severity, message }
}

fn parse_pt_status(line: &str) -> PtLine {
    let mut kind = String::new();
    let mut rest = line.trim_start_matches("STATUS").trim_start();
    while !rest.is_empty() {
        if let Some((k, v_tail)) = rest.split_once('=') {
            let key = k.trim();
            let (value, tail) = next_token(v_tail);
            if key.eq_ignore_ascii_case("TYPE") {
                kind = value.to_owned();
            }
            rest = tail.trim_start();
        } else {
            break;
        }
    }
    PtLine::Status {
        kind,
        raw: line.to_owned(),
    }
}

fn next_token(s: &str) -> (String, &str) {
    let s = s.trim_start();
    if let Some(stripped) = s.strip_prefix('"') {
        if let Some(end) = stripped.find('"') {
            return (stripped[..end].to_owned(), &stripped[end + 1..]);
        }
        return (stripped.to_owned(), "");
    }
    let end = s.find(|c: char| c.is_whitespace()).unwrap_or(s.len());
    (s[..end].to_owned(), &s[end..])
}

/// Classify a parsed PT line for readiness/error reporting.
#[must_use]
pub fn classify_readiness(parsed: &PtLine) -> PtReadiness {
    match parsed {
        PtLine::ClientMethod { transport, .. } if !transport.is_empty() => PtReadiness {
            ready_transports: vec![transport.clone()],
            error: None,
            fatal: false,
        },
        PtLine::ServerMethod { transport, .. } if !transport.is_empty() => PtReadiness {
            ready_transports: vec![transport.clone()],
            error: None,
            fatal: false,
        },
        PtLine::ProxyDone => PtReadiness {
            ready_transports: Vec::new(),
            error: None,
            fatal: false,
        },
        PtLine::ClientMethodError { transport, message } => PtReadiness {
            ready_transports: Vec::new(),
            error: Some(safe_pt_error(&format!(
                "transport {transport} failed: {message}"
            ))),
            fatal: false,
        },
        PtLine::ServerMethodError { transport, message } => PtReadiness {
            ready_transports: Vec::new(),
            error: Some(safe_pt_error(&format!(
                "transport {transport} failed: {message}"
            ))),
            fatal: false,
        },
        PtLine::ProxyError(msg) => PtReadiness {
            ready_transports: Vec::new(),
            error: Some(safe_pt_error(&format!("proxy error: {msg}"))),
            fatal: true,
        },
        PtLine::VersionError(msg) => PtReadiness {
            ready_transports: Vec::new(),
            error: Some(safe_pt_error(&format!("PT version error: {msg}"))),
            fatal: true,
        },
        PtLine::EnvError(msg) => PtReadiness {
            ready_transports: Vec::new(),
            error: Some(safe_pt_error(&format!("PT environment error: {msg}"))),
            fatal: true,
        },
        PtLine::Log { severity, message } => {
            let sev = PtSeverity::parse(severity);
            if sev >= PtSeverity::Error {
                PtReadiness {
                    ready_transports: Vec::new(),
                    error: Some(safe_pt_error(message)),
                    fatal: false,
                }
            } else {
                PtReadiness {
                    ready_transports: Vec::new(),
                    error: None,
                    fatal: false,
                }
            }
        }
        PtLine::Status { kind, .. } => {
            // Some PTs report bootstrap progress/errors via STATUS.
            let upper = kind.to_ascii_uppercase();
            let fatal = upper.contains("ERR") || upper == "PROXY-ERROR";
            PtReadiness {
                ready_transports: Vec::new(),
                error: if fatal {
                    Some(safe_pt_error(&format!("PT status error: {kind}")))
                } else {
                    None
                },
                fatal,
            }
        }
        _ => PtReadiness {
            ready_transports: Vec::new(),
            error: None,
            fatal: false,
        },
    }
}

fn safe_pt_error(message: &str) -> String {
    let redacted = redact_secrets(message);
    let trimmed = redacted.trim();
    if trimmed.is_empty() {
        "pluggable transport reported an error".to_owned()
    } else {
        // Keep errors reasonably short for IPC/UI.
        const MAX: usize = 512;
        if trimmed.len() > MAX {
            format!("{}…", &trimmed[..trimmed.floor_char_boundary(MAX)])
        } else {
            trimmed.to_owned()
        }
    }
}

/// Specification for starting a PT sidecar.
#[derive(Debug, Clone)]
pub struct SidecarSpec {
    /// Logical sidecar id (for logs/events).
    pub id: SidecarId,
    /// Resolved executable path (should be located/verified by caller).
    pub program: PathBuf,
    /// Arguments.
    pub args: Vec<OsString>,
    /// Extra environment variables.
    pub env: HashMap<OsString, OsString>,
    /// Working/private state directory for the sidecar (created with private perms).
    pub state_dir: PathBuf,
    /// Transports that must become ready before reporting overall readiness.
    /// Empty means "process started" is sufficient (caller decides).
    pub required_transports: HashSet<String>,
    /// Optional readiness timeout override.
    pub readiness_timeout: Option<Duration>,
}

/// Runtime state of a supervised sidecar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarState {
    Stopped,
    Starting,
    Ready,
    Failed,
    Stopping,
}

/// Snapshot for observers.
#[derive(Debug, Clone)]
pub struct SidecarSnapshot {
    pub id: SidecarId,
    pub state: SidecarState,
    pub ready_transports: Vec<String>,
    pub last_error: Option<String>,
    pub pid: Option<u32>,
}

/// Events emitted by the PT sidecar supervisor.
#[derive(Debug, Clone)]
pub enum SidecarEvent {
    State(SidecarSnapshot),
    StdoutLine {
        id: SidecarId,
        line: String,
    },
    StderrLine {
        id: SidecarId,
        line: String,
    },
    Ready {
        id: SidecarId,
        transports: Vec<String>,
    },
    Error {
        id: SidecarId,
        message: String,
        fatal: bool,
    },
    Exited {
        id: SidecarId,
        code: Option<i32>,
        signal: Option<i32>,
    },
}

/// Control commands for a supervised sidecar.
#[derive(Debug)]
pub enum SidecarCommand {
    Start,
    Stop,
    Restart,
    Shutdown,
}

/// Handle for controlling and observing a supervised sidecar.
#[derive(Debug, Clone)]
pub struct PtSidecarHandle {
    cmd_tx: mpsc::Sender<SidecarCommand>,
    status_rx: watch::Receiver<SidecarSnapshot>,
    events_tx: broadcast::Sender<SidecarEvent>,
}

impl PtSidecarHandle {
    /// Request start.
    pub async fn start(&self) -> Result<(), mpsc::error::SendError<SidecarCommand>> {
        self.cmd_tx.send(SidecarCommand::Start).await
    }
    /// Request stop.
    pub async fn stop(&self) -> Result<(), mpsc::error::SendError<SidecarCommand>> {
        self.cmd_tx.send(SidecarCommand::Stop).await
    }
    /// Request restart.
    pub async fn restart(&self) -> Result<(), mpsc::error::SendError<SidecarCommand>> {
        self.cmd_tx.send(SidecarCommand::Restart).await
    }
    /// Request shutdown (stop and terminate supervisor).
    pub async fn shutdown(&self) -> Result<(), mpsc::error::SendError<SidecarCommand>> {
        self.cmd_tx.send(SidecarCommand::Shutdown).await
    }
    /// Current snapshot.
    pub fn snapshot(&self) -> SidecarSnapshot {
        self.status_rx.borrow().clone()
    }
    /// Subscribe to snapshots.
    pub fn subscribe_status(&self) -> watch::Receiver<SidecarSnapshot> {
        self.status_rx.clone()
    }
    /// Subscribe to events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<SidecarEvent> {
        self.events_tx.subscribe()
    }
}

/// Backoff/restart policy.
#[derive(Debug, Clone)]
pub struct RestartPolicy {
    pub enabled: bool,
    pub initial: Duration,
    pub max: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            initial: DEFAULT_BACKOFF_INITIAL,
            max: DEFAULT_BACKOFF_MAX,
        }
    }
}

#[derive(Debug)]
enum ChildMsg {
    Stdout(String),
    Stderr(String),
    Exited(std::io::Result<std::process::ExitStatus>),
}

struct RunningChild {
    pid: Option<u32>,
    kill_tx: Option<oneshot::Sender<()>>,
    msg_rx: mpsc::UnboundedReceiver<ChildMsg>,
    _wait: tokio::task::JoinHandle<()>,
}

async fn run_supervisor(
    spec: SidecarSpec,
    restart: RestartPolicy,
    mut cmd_rx: mpsc::Receiver<SidecarCommand>,
    status_tx: watch::Sender<SidecarSnapshot>,
    events_tx: broadcast::Sender<SidecarEvent>,
) {
    let mut desired_running = false;
    let mut backoff = restart.initial;
    let mut restart_deadline: Option<tokio::time::Instant> = None;
    let mut intentional_stop = false;
    let mut child: Option<RunningChild> = None;
    let mut ready: HashSet<String> = HashSet::new();
    let mut readiness_deadline: Option<tokio::time::Instant> = None;

    loop {
        let restart_sleep = restart_deadline;
        let ready_sleep = readiness_deadline;
        if let Some(running) = child.as_mut() {
            tokio::select! {
                biased;
                cmd = cmd_rx.recv() => {
                    if handle_supervisor_cmd(
                        cmd, &spec, &restart, &mut desired_running, &mut backoff,
                        &mut restart_deadline, &mut intentional_stop, &mut child,
                        &mut ready, &mut readiness_deadline, &status_tx, &events_tx,
                    ).await { return; }
                }
                msg = running.msg_rx.recv() => {
                    handle_child_msg(
                        &spec, &restart, msg, &desired_running, &mut backoff,
                        &mut restart_deadline, &mut intentional_stop, &mut child,
                        &mut ready, &mut readiness_deadline, &status_tx, &events_tx,
                    ).await;
                }
                _ = sleep_until_opt(ready_sleep), if ready_sleep.is_some() => {
                    readiness_deadline = None;
                    let msg = format!(
                        "sidecar {} did not report readiness within {:?}",
                        spec.id, spec.readiness_timeout.unwrap_or(DEFAULT_READINESS_TIMEOUT)
                    );
                    publish_state(&spec, SidecarState::Failed, ready.clone(), Some(msg.clone()), child_pid(&child), &status_tx, &events_tx);
                    let _ = events_tx.send(SidecarEvent::Error { id: spec.id.clone(), message: msg, fatal: false });
                    intentional_stop = true;
                    stop_child(&mut child).await;
                    intentional_stop = false;
                    maybe_schedule_restart(&spec, &restart, &desired_running, &mut backoff, &mut restart_deadline);
                }
                _ = sleep_until_opt(restart_sleep), if restart_sleep.is_some() => {
                    restart_deadline = None;
                    if desired_running && child.is_none() {
                        start_child(&spec, &mut child, &mut ready, &mut readiness_deadline, &status_tx, &events_tx).await;
                    }
                }
            }
        } else {
            tokio::select! {
                biased;
                cmd = cmd_rx.recv() => {
                    if handle_supervisor_cmd(
                        cmd, &spec, &restart, &mut desired_running, &mut backoff,
                        &mut restart_deadline, &mut intentional_stop, &mut child,
                        &mut ready, &mut readiness_deadline, &status_tx, &events_tx,
                    ).await { return; }
                }
                _ = sleep_until_opt(restart_sleep), if restart_sleep.is_some() => {
                    restart_deadline = None;
                    if desired_running && child.is_none() {
                        start_child(&spec, &mut child, &mut ready, &mut readiness_deadline, &status_tx, &events_tx).await;
                    }
                }
            }
        }
    }
}

async fn sleep_until_opt(deadline: Option<tokio::time::Instant>) {
    if let Some(d) = deadline {
        tokio::time::sleep_until(d).await;
    } else {
        std::future::pending::<()>().await;
    }
}

fn child_pid(child: &Option<RunningChild>) -> Option<u32> {
    child.as_ref().and_then(|c| c.pid)
}

async fn start_child(
    spec: &SidecarSpec,
    child: &mut Option<RunningChild>,
    ready: &mut HashSet<String>,
    readiness_deadline: &mut Option<tokio::time::Instant>,
    status_tx: &watch::Sender<SidecarSnapshot>,
    events_tx: &broadcast::Sender<SidecarEvent>,
) {
    ready.clear();
    *readiness_deadline = None;
    publish_state(
        spec,
        SidecarState::Starting,
        ready.clone(),
        None,
        None,
        status_tx,
        events_tx,
    );

    if let Err(e) = ensure_private_dir(&spec.state_dir) {
        let msg = safe_pt_error(&format!("could not prepare sidecar state dir: {e:#}"));
        publish_state(
            spec,
            SidecarState::Failed,
            ready.clone(),
            Some(msg.clone()),
            None,
            status_tx,
            events_tx,
        );
        let _ = events_tx.send(SidecarEvent::Error {
            id: spec.id.clone(),
            message: msg,
            fatal: true,
        });
        return;
    }

    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args)
        .envs(&spec.env)
        .current_dir(&spec.state_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }

    let mut spawned = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = safe_pt_error(&format!(
                "failed to start sidecar {} ({}): {e}",
                spec.id,
                spec.program.display()
            ));
            publish_state(
                spec,
                SidecarState::Failed,
                ready.clone(),
                Some(msg.clone()),
                None,
                status_tx,
                events_tx,
            );
            let _ = events_tx.send(SidecarEvent::Error {
                id: spec.id.clone(),
                message: msg,
                fatal: true,
            });
            return;
        }
    };

    let pid = spawned.id();
    let stdout = spawned.stdout.take();
    let stderr = spawned.stderr.take();
    let (msg_tx, msg_rx) = mpsc::unbounded_channel();
    let (kill_tx, mut kill_rx) = oneshot::channel::<()>();

    if let Some(out) = stdout {
        let tx = msg_tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(out).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(ChildMsg::Stdout(line)).is_err() {
                    break;
                }
            }
        });
    }
    if let Some(err) = stderr {
        let tx = msg_tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(ChildMsg::Stderr(line)).is_err() {
                    break;
                }
            }
        });
    }
    let wait_tx = msg_tx;
    let wait_pid = pid;
    let wait = tokio::spawn(async move {
        tokio::select! {
            _ = &mut kill_rx => {
                terminate_child(&mut spawned, wait_pid).await;
                let status = spawned.wait().await;
                let _ = wait_tx.send(ChildMsg::Exited(status));
            }
            status = spawned.wait() => {
                let _ = wait_tx.send(ChildMsg::Exited(status));
            }
        }
    });

    *child = Some(RunningChild {
        pid,
        kill_tx: Some(kill_tx),
        msg_rx,
        _wait: wait,
    });

    let timeout = spec.readiness_timeout.unwrap_or(DEFAULT_READINESS_TIMEOUT);
    if spec.required_transports.is_empty() {
        // No explicit readiness gate; report started/ready on spawn.
        publish_state(
            spec,
            SidecarState::Ready,
            HashSet::new(),
            None,
            pid,
            status_tx,
            events_tx,
        );
        let _ = events_tx.send(SidecarEvent::Ready {
            id: spec.id.clone(),
            transports: Vec::new(),
        });
    } else {
        *readiness_deadline = Some(tokio::time::Instant::now() + timeout);
        publish_state(
            spec,
            SidecarState::Starting,
            HashSet::new(),
            None,
            pid,
            status_tx,
            events_tx,
        );
    }
}

async fn terminate_child(child: &mut Child, pid: Option<u32>) {
    #[cfg(unix)]
    if let Some(pid) = pid {
        // Kill process group first to avoid orphans.
        let pgid = rustix::process::Pid::from_raw(pid as i32);
        if let Some(pgid) = pgid {
            let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::TERM);
        }
    }
    #[cfg(not(unix))]
    let _ = pid;

    let _ = child.start_kill();
    let grace = tokio::time::sleep(DEFAULT_STOP_GRACE);
    tokio::pin!(grace);
    tokio::select! {
        _ = child.wait() => {}
        _ = &mut grace => {
            #[cfg(unix)]
            if let Some(pid) = pid {
                if let Some(pgid) = rustix::process::Pid::from_raw(pid as i32) {
                    let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
                }
            }
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
    }
}

async fn stop_child(child: &mut Option<RunningChild>) {
    if let Some(mut c) = child.take() {
        if let Some(tx) = c.kill_tx.take() {
            let _: Result<(), ()> = tx.send(());
        }
        // Wait for the task to observe exit; bounded by its own grace logic.
        let _ = tokio::time::timeout(DEFAULT_STOP_GRACE + Duration::from_secs(2), c._wait).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_supervisor_cmd(
    cmd: Option<SidecarCommand>,
    spec: &SidecarSpec,
    restart: &RestartPolicy,
    desired_running: &mut bool,
    backoff: &mut Duration,
    restart_deadline: &mut Option<tokio::time::Instant>,
    intentional_stop: &mut bool,
    child: &mut Option<RunningChild>,
    ready: &mut HashSet<String>,
    readiness_deadline: &mut Option<tokio::time::Instant>,
    status_tx: &watch::Sender<SidecarSnapshot>,
    events_tx: &broadcast::Sender<SidecarEvent>,
) -> bool {
    match cmd {
        Some(SidecarCommand::Start) => {
            *desired_running = true;
            *intentional_stop = false;
            *restart_deadline = None;
            *backoff = restart.initial;
            if child.is_none() {
                start_child(spec, child, ready, readiness_deadline, status_tx, events_tx).await;
            }
            false
        }
        Some(SidecarCommand::Stop) => {
            *desired_running = false;
            *intentional_stop = true;
            *restart_deadline = None;
            *readiness_deadline = None;
            if child.is_some() {
                publish_state(
                    spec,
                    SidecarState::Stopping,
                    ready.clone(),
                    None,
                    child_pid(child),
                    status_tx,
                    events_tx,
                );
                stop_child(child).await;
            }
            publish_state(
                spec,
                SidecarState::Stopped,
                ready.clone(),
                None,
                None,
                status_tx,
                events_tx,
            );
            *intentional_stop = false;
            false
        }
        Some(SidecarCommand::Restart) => {
            *desired_running = true;
            *intentional_stop = true;
            *restart_deadline = None;
            *backoff = restart.initial;
            if child.is_some() {
                publish_state(
                    spec,
                    SidecarState::Stopping,
                    ready.clone(),
                    None,
                    child_pid(child),
                    status_tx,
                    events_tx,
                );
                stop_child(child).await;
            }
            *intentional_stop = false;
            start_child(spec, child, ready, readiness_deadline, status_tx, events_tx).await;
            false
        }
        Some(SidecarCommand::Shutdown) | None => {
            *desired_running = false;
            *intentional_stop = true;
            *restart_deadline = None;
            *readiness_deadline = None;
            if child.is_some() {
                publish_state(
                    spec,
                    SidecarState::Stopping,
                    ready.clone(),
                    None,
                    child_pid(child),
                    status_tx,
                    events_tx,
                );
                stop_child(child).await;
            }
            publish_state(
                spec,
                SidecarState::Stopped,
                ready.clone(),
                None,
                None,
                status_tx,
                events_tx,
            );
            true
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_child_msg(
    spec: &SidecarSpec,
    restart: &RestartPolicy,
    msg: Option<ChildMsg>,
    desired_running: &bool,
    backoff: &mut Duration,
    restart_deadline: &mut Option<tokio::time::Instant>,
    intentional_stop: &mut bool,
    child: &mut Option<RunningChild>,
    ready: &mut HashSet<String>,
    readiness_deadline: &mut Option<tokio::time::Instant>,
    status_tx: &watch::Sender<SidecarSnapshot>,
    events_tx: &broadcast::Sender<SidecarEvent>,
) {
    match msg {
        Some(ChildMsg::Stdout(line)) => {
            let _ = events_tx.send(SidecarEvent::StdoutLine {
                id: spec.id.clone(),
                line: line.clone(),
            });
            let parsed = parse_pt_line(&line);
            let cls = classify_readiness(&parsed);
            let mut changed = false;
            for t in cls.ready_transports {
                if !t.is_empty() && ready.insert(t) {
                    changed = true;
                }
            }
            if let Some(err) = cls.error.clone() {
                let _ = events_tx.send(SidecarEvent::Error {
                    id: spec.id.clone(),
                    message: err.clone(),
                    fatal: cls.fatal,
                });
                publish_state(
                    spec,
                    if cls.fatal {
                        SidecarState::Failed
                    } else {
                        SidecarState::Starting
                    },
                    ready.clone(),
                    Some(err),
                    child_pid(child),
                    status_tx,
                    events_tx,
                );
            }
            if changed
                || (!spec.required_transports.is_empty()
                    && spec.required_transports.iter().all(|r| ready.contains(r)))
            {
                if spec.required_transports.is_empty()
                    || spec.required_transports.iter().all(|r| ready.contains(r))
                {
                    *readiness_deadline = None;
                    let transports: Vec<String> = {
                        let mut v: Vec<_> = ready.iter().cloned().collect();
                        v.sort();
                        v
                    };
                    publish_state(
                        spec,
                        SidecarState::Ready,
                        ready.clone(),
                        None,
                        child_pid(child),
                        status_tx,
                        events_tx,
                    );
                    let _ = events_tx.send(SidecarEvent::Ready {
                        id: spec.id.clone(),
                        transports,
                    });
                    *backoff = restart.initial;
                } else if changed {
                    publish_state(
                        spec,
                        SidecarState::Starting,
                        ready.clone(),
                        None,
                        child_pid(child),
                        status_tx,
                        events_tx,
                    );
                }
            }
            if cls.fatal {
                *intentional_stop = true;
                stop_child(child).await;
                *intentional_stop = false;
                maybe_schedule_restart(spec, restart, desired_running, backoff, restart_deadline);
            }
        }
        Some(ChildMsg::Stderr(line)) => {
            let redacted = redact_secrets(&line);
            let _ = events_tx.send(SidecarEvent::StderrLine {
                id: spec.id.clone(),
                line: redacted,
            });
        }
        Some(ChildMsg::Exited(status)) => {
            let (code, signal) = match status {
                Ok(s) => (s.code(), exit_signal(&s)),
                Err(_) => (None, None),
            };
            *child = None;
            *readiness_deadline = None;
            let _ = events_tx.send(SidecarEvent::Exited {
                id: spec.id.clone(),
                code,
                signal,
            });
            if *intentional_stop {
                *intentional_stop = false;
                publish_state(
                    spec,
                    SidecarState::Stopped,
                    ready.clone(),
                    None,
                    None,
                    status_tx,
                    events_tx,
                );
            } else if *desired_running {
                let msg = format!(
                    "sidecar {} exited unexpectedly (code={code:?}, signal={signal:?})",
                    spec.id
                );
                publish_state(
                    spec,
                    SidecarState::Failed,
                    ready.clone(),
                    Some(safe_pt_error(&msg)),
                    None,
                    status_tx,
                    events_tx,
                );
                let _ = events_tx.send(SidecarEvent::Error {
                    id: spec.id.clone(),
                    message: safe_pt_error(&msg),
                    fatal: false,
                });
                maybe_schedule_restart(spec, restart, desired_running, backoff, restart_deadline);
            } else {
                publish_state(
                    spec,
                    SidecarState::Stopped,
                    ready.clone(),
                    None,
                    None,
                    status_tx,
                    events_tx,
                );
            }
        }
        None => {
            *child = None;
            *readiness_deadline = None;
        }
    }
}

#[cfg(unix)]
fn exit_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt as _;
    status.signal()
}
#[cfg(not(unix))]
fn exit_signal(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

fn maybe_schedule_restart(
    spec: &SidecarSpec,
    restart: &RestartPolicy,
    desired_running: &bool,
    backoff: &mut Duration,
    restart_deadline: &mut Option<tokio::time::Instant>,
) {
    if *desired_running && restart.enabled {
        let delay = *backoff;
        *restart_deadline = Some(tokio::time::Instant::now() + delay);
        *backoff = (*backoff * 2).min(restart.max);
        debug!(sidecar = %spec.id, ?delay, "scheduled PT sidecar restart");
    }
}

fn publish_state(
    spec: &SidecarSpec,
    state: SidecarState,
    ready: HashSet<String>,
    last_error: Option<String>,
    pid: Option<u32>,
    status_tx: &watch::Sender<SidecarSnapshot>,
    events_tx: &broadcast::Sender<SidecarEvent>,
) {
    let mut ready_transports: Vec<_> = ready.into_iter().collect();
    ready_transports.sort();
    let snapshot = SidecarSnapshot {
        id: spec.id.clone(),
        state,
        ready_transports,
        last_error,
        pid,
    };
    let _ = status_tx.send(snapshot.clone());
    let _ = events_tx.send(SidecarEvent::State(snapshot));
}

fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        if dir.exists() {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).with_context(
                || format!("failed to set private permissions on {}", dir.display()),
            )?;
        } else {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .with_context(|| format!("failed to create private directory {}", dir.display()))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create directory {}", dir.display()))?;
        Ok(())
    }
}

/// Spawn a supervised PT sidecar . Not started until `Start`.
pub fn spawn_supervised(
    spec: SidecarSpec,
    restart: RestartPolicy,
) -> (PtSidecarHandle, tokio::task::JoinHandle<()>) {
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let (status_tx, status_rx) = watch::channel(SidecarSnapshot {
        id: spec.id.clone(),
        state: SidecarState::Stopped,
        ready_transports: Vec::new(),
        last_error: None,
        pid: None,
    });
    let (events_tx, _) = broadcast::channel(128);
    let handle = PtSidecarHandle {
        cmd_tx,
        status_rx,
        events_tx: events_tx.clone(),
    };
    let join = tokio::spawn(run_supervisor(spec, restart, cmd_rx, status_tx, events_tx));
    (handle, join)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parses_cmethod_as_readiness() {
        let line = "CMETHOD obfs4 socks5 127.0.0.1:42000";
        let parsed = parse_pt_line(line);
        assert!(
            matches!(parsed, PtLine::ClientMethod { ref transport, .. } if transport == "obfs4")
        );
        let cls = classify_readiness(&parsed);
        assert_eq!(cls.ready_transports, vec!["obfs4".to_owned()]);
        assert!(cls.error.is_none());
        assert!(!cls.fatal);
    }

    #[test]
    fn parses_cmethod_error() {
        let parsed = parse_pt_line("CMETHOD-ERROR snowflake something went wrong");
        let cls = classify_readiness(&parsed);
        assert!(cls.ready_transports.is_empty());
        let err = cls.error.expect("error");
        assert!(err.contains("snowflake"), "{err}");
        assert!(!cls.fatal);
    }

    #[test]
    fn parses_fatal_version_error() {
        let parsed = parse_pt_line("VERSION-ERROR no compatible versions");
        let cls = classify_readiness(&parsed);
        assert!(cls.fatal);
        assert!(cls.error.as_deref().unwrap_or("").contains("version"));
    }

    #[test]
    fn parses_proxy_error_as_fatal() {
        let parsed = parse_pt_line("PROXY-ERROR could not connect");
        let cls = classify_readiness(&parsed);
        assert!(cls.fatal);
        assert!(cls.error.is_some());
    }

    #[test]
    fn parses_log_error_severity() {
        let parsed = parse_pt_line("LOG SEVERITY=error MESSAGE=\"boom\"");
        let cls = classify_readiness(&parsed);
        assert!(cls.error.as_deref().unwrap_or("").contains("boom"));
        assert!(!cls.fatal);
    }

    #[test]
    fn parses_log_info_no_error() {
        let parsed = parse_pt_line("LOG SEVERITY=info MESSAGE=hello");
        let cls = classify_readiness(&parsed);
        assert!(cls.error.is_none());
    }

    #[test]
    fn ignores_unknown_lines() {
        let parsed = parse_pt_line("SOMETHING ELSE");
        assert!(matches!(parsed, PtLine::Other(_)));
        let cls = classify_readiness(&parsed);
        assert!(cls.error.is_none());
        assert!(cls.ready_transports.is_empty());
    }

    #[test]
    fn parses_status_type() {
        let parsed = parse_pt_line("STATUS TYPE=VERSION TRANSPORT=obfs4");
        assert!(matches!(parsed, PtLine::Status { ref kind, .. } if kind == "VERSION"));
    }

    #[test]
    fn redacts_secrets_in_errors() {
        let parsed = parse_pt_line("CMETHOD-ERROR x password=hunter2");
        let cls = classify_readiness(&parsed);
        let err = cls.error.expect("error");
        assert!(!err.contains("hunter2"), "{err}");
        assert!(
            err.contains("[REDACTED]") || err.contains("REDACTED"),
            "{err}"
        );
    }

    #[test]
    fn verify_sha256_matches() {
        let dir = TempDir::new().expect("tmp");
        let path = dir.path().join("bin");
        std::fs::write(&path, b"hello-sidecar").expect("write");
        let mut hasher = Sha256::new();
        hasher.update(b"hello-sidecar");
        let expected = hex::encode(hasher.finalize());
        let report = verify(
            &path,
            &VerifySpec {
                sha256_hex: Some(expected),
            },
        )
        .expect("verify");
        assert!(report.ok, "{:?}", report.detail);
        assert!(report.detail.as_deref().unwrap_or("").contains("verified"));
    }

    #[test]
    fn verify_sha256_mismatch_fails() {
        let dir = TempDir::new().expect("tmp");
        let path = dir.path().join("bin");
        std::fs::write(&path, b"hello").expect("write");
        let report = verify(
            &path,
            &VerifySpec {
                sha256_hex: Some("00".repeat(32)),
            },
        )
        .expect("verify");
        assert!(!report.ok);
        assert!(report.detail.as_deref().unwrap_or("").contains("mismatch"));
    }

    #[test]
    fn verify_without_spec_reports_computed_hash() {
        let dir = TempDir::new().expect("tmp");
        let path = dir.path().join("bin");
        std::fs::write(&path, b"abc").expect("write");
        let report = verify(&path, &VerifySpec::default()).expect("verify");
        assert!(report.ok);
        assert_eq!(report.sha256_hex.len(), 64);
    }

    #[test]
    fn locate_finds_explicit_path() {
        let dir = TempDir::new().expect("tmp");
        let path = dir.path().join("fakept");
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        let opts = LocateOptions {
            explicit_path: Some(path.clone()),
            search_dirs: vec![],
            names: vec![],
        };
        let found = locate(&opts).expect("locate");
        assert_eq!(found.source, LocateSource::Explicit);
        assert!(found.path.ends_with("fakept"));
    }

    #[test]
    fn locate_searches_dirs() {
        let dir = TempDir::new().expect("tmp");
        let path = dir.path().join("lyrebird");
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        let opts = LocateOptions {
            explicit_path: None,
            search_dirs: vec![dir.path().to_path_buf()],
            names: vec![OsString::from("lyrebird")],
        };
        let found = locate(&opts).expect("locate");
        assert!(matches!(found.source, LocateSource::SearchDir(_)));
    }

    #[test]
    fn locate_missing_fails_clearly() {
        let dir = TempDir::new().expect("tmp");
        let opts = LocateOptions {
            explicit_path: None,
            search_dirs: vec![dir.path().to_path_buf()],
            names: vec![OsString::from("no-such-pt-binary-xyz")],
        };
        let err = locate(&opts).expect_err("should fail");
        assert!(format!("{err:#}").contains("could not locate"), "{err:#}");
    }

    #[cfg(unix)]
    fn write_fake_pt(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn supervised_sidecar_reaches_readiness_and_stops() {
        let dir = TempDir::new().expect("tmp");
        let bin = write_fake_pt(
            dir.path(),
            "fake-pt",
            r#"echo "CMETHOD obfs4 socks5 127.0.0.1:12345"; while true; do sleep 1; done"#,
        );
        let state_dir = dir.path().join("state");
        let spec = SidecarSpec {
            id: SidecarId::new("fake"),
            program: bin,
            args: vec![],
            env: HashMap::new(),
            state_dir,
            required_transports: ["obfs4".to_owned()].into_iter().collect(),
            readiness_timeout: Some(Duration::from_secs(5)),
        };
        let (h, j) = spawn_supervised(
            spec,
            RestartPolicy {
                enabled: false,
                ..Default::default()
            },
        );
        h.start().await.expect("start");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let snap = h.snapshot();
            if snap.state == SidecarState::Ready {
                assert!(snap.ready_transports.iter().any(|t| t == "obfs4"));
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out: {snap:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        h.stop().await.expect("stop");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.snapshot().state, SidecarState::Stopped);
        h.shutdown().await.expect("shutdown");
        let _ = tokio::time::timeout(Duration::from_secs(3), j).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn supervised_sidecar_reports_error_line() {
        let dir = TempDir::new().expect("tmp");
        let bin = write_fake_pt(
            dir.path(),
            "fake-pt-err",
            r#"echo "CMETHOD-ERROR obfs4 bad bridge"; sleep 2"#,
        );
        let spec = SidecarSpec {
            id: SidecarId::new("fake"),
            program: bin,
            args: vec![],
            env: HashMap::new(),
            state_dir: dir.path().join("state"),
            required_transports: HashSet::new(),
            readiness_timeout: Some(Duration::from_secs(2)),
        };
        let (h, j) = spawn_supervised(
            spec,
            RestartPolicy {
                enabled: false,
                ..Default::default()
            },
        );
        let mut events = h.subscribe_events();
        h.start().await.expect("start");
        let mut saw_error = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        while tokio::time::Instant::now() < deadline {
            if let Ok(Ok(ev)) =
                tokio::time::timeout(Duration::from_millis(200), events.recv()).await
            {
                if matches!(ev, SidecarEvent::Error { .. }) {
                    saw_error = true;
                    break;
                }
            }
        }
        assert!(saw_error, "expected PT error event");
        h.shutdown().await.expect("shutdown");
        let _ = tokio::time::timeout(Duration::from_secs(3), j).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn supervised_sidecar_restarts_on_unexpected_exit() {
        let dir = TempDir::new().expect("tmp");
        // First run exits quickly; we just verify it gets restarted (state becomes Starting again).
        let bin = write_fake_pt(
            dir.path(),
            "fake-pt-exit",
            r#"echo "CMETHOD obfs4 socks5 127.0.0.1:1"; exit 1"#,
        );
        let spec = SidecarSpec {
            id: SidecarId::new("fake"),
            program: bin,
            args: vec![],
            env: HashMap::new(),
            state_dir: dir.path().join("state"),
            required_transports: HashSet::new(),
            readiness_timeout: Some(Duration::from_secs(2)),
        };
        let restart = RestartPolicy {
            enabled: true,
            initial: Duration::from_millis(50),
            max: Duration::from_millis(100),
        };
        let (h, j) = spawn_supervised(spec, restart);
        let mut events = h.subscribe_events();
        h.start().await.expect("start");
        let mut exits = 0u32;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        while tokio::time::Instant::now() < deadline && exits < 2 {
            if let Ok(Ok(ev)) =
                tokio::time::timeout(Duration::from_millis(250), events.recv()).await
            {
                if matches!(ev, SidecarEvent::Exited { .. }) {
                    exits += 1;
                }
            }
        }
        assert!(exits >= 2, "expected restart after exit, saw {exits} exits");
        h.shutdown().await.expect("shutdown");
        let _ = tokio::time::timeout(Duration::from_secs(3), j).await;
    }
}
