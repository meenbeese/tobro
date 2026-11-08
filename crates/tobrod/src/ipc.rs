//! IPC endpoint for `tobrod`.
//!
//! Contains the M0 spike [`Hub`] and an M1 supervisor-backed server that
//! enforces method allowlist, version handshake, and dispatches connect/stop.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::json;
use tokio::sync::broadcast;

use tobro_ipc::{
    BootstrapProgress, Connection, DaemonState, DaemonStatus, Hello, IpcError, Message,
    RPC_VERSION, RequestId, RpcError, RpcNotification, RpcRequest, RpcResponse, Server, methods,
    notifications,
};

use crate::redact::redact_secrets;

/// Shared daemon state observed by IPC clients.
#[derive(Debug)]
pub struct Hub {
    status: RwLock<DaemonStatus>,
    events: broadcast::Sender<RpcNotification>,
    started: Instant,
}

impl Hub {
    /// Create the hub for a daemon about to start.
    pub fn new(socks_port: u16, http_port: u16, dns_port: u16) -> Arc<Self> {
        let (events, _receiver) = broadcast::channel(64);
        Arc::new(Self {
            status: RwLock::new(DaemonStatus {
                state: DaemonState::Starting,
                bootstrap: BootstrapProgress::default(),
                socks_port,
                http_port,
                dns_port,
                bind_all_interfaces: false,
                pid: std::process::id(),
                uptime_ms: 0,
            }),
            events,
            started: Instant::now(),
        })
    }

    /// Record bootstrap progress and notify subscribers.
    pub fn report_bootstrap(
        &self,
        percent: u8,
        ready: bool,
        blocked: Option<String>,
        detail: String,
    ) {
        let progress = BootstrapProgress {
            percent,
            ready,
            blocked: blocked.map(|s| redact_secrets(&s)),
            detail: redact_secrets(&detail),
        };
        self.update(|status| {
            status.bootstrap = progress.clone();
            status.state = if ready {
                DaemonState::Connected
            } else {
                DaemonState::Bootstrapping
            };
        });
        self.emit(notifications::BOOTSTRAP_PROGRESS, &progress);
    }

    /// Record a lifecycle transition and notify subscribers.
    pub fn set_state(&self, state: DaemonState) {
        self.update(|status| status.state = state);
        self.emit(notifications::STATE_CHANGED, &json!({ "state": state }));
    }

    /// Current snapshot, with uptime filled in.
    pub fn status(&self) -> DaemonStatus {
        let uptime_ms = self.started.elapsed().as_millis() as u64;
        let mut status = match self.status.read() {
            Ok(status) => status.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        status.uptime_ms = uptime_ms;
        status
    }

    fn update(&self, apply: impl FnOnce(&mut DaemonStatus)) {
        match self.status.write() {
            Ok(mut status) => apply(&mut status),
            Err(poisoned) => apply(&mut poisoned.into_inner()),
        }
    }

    fn emit<T: Serialize>(&self, method: &str, payload: &T) {
        let Ok(params) = serde_json::to_value(payload) else {
            return;
        };
        let _ = self.events.send(RpcNotification::new(method, Some(params)));
    }

    fn subscribe(&self) -> broadcast::Receiver<RpcNotification> {
        self.events.subscribe()
    }
}

/// Accept connections forever, serving each on its own task.
pub async fn serve(mut server: Server, hub: Arc<Hub>) -> anyhow::Result<()> {
    tracing::info!(socket = %server.path().display(), "IPC listening");
    loop {
        let connection = server.accept().await?;
        let hub = Arc::clone(&hub);
        tokio::spawn(async move {
            if let Err(error) = handle(connection, hub).await {
                tracing::debug!(%error, "IPC connection ended");
            }
        });
    }
}

async fn handle(mut connection: Connection, hub: Arc<Hub>) -> Result<(), IpcError> {
    let mut events = hub.subscribe();

    loop {
        tokio::select! {
            incoming = connection.next() => {
                match incoming {
                    Some(Ok(Message::Request(request))) => {
                        let response = dispatch(&hub, request);
                        connection.send(Message::Response(response)).await?;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Err(error),
                    None => return Ok(()),
                }
            }
            event = events.recv() => {
                match event {
                    Ok(notification) => {
                        connection.send(Message::Notification(notification)).await?;
                    }
                    // A slow client misses events; it can always re-read status.
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

fn dispatch(hub: &Hub, request: RpcRequest) -> RpcResponse {
    let id = request.id;
    match request.method.as_str() {
        methods::HELLO => encode(id, &hello()),
        methods::STATUS => encode(id, &hub.status()),
        other => RpcResponse::error(id, RpcError::method_not_found(other)),
    }
}

fn encode<T: Serialize>(id: RequestId, value: &T) -> RpcResponse {
    match serde_json::to_value(value) {
        Ok(value) => RpcResponse::success(id, value),
        Err(error) => RpcResponse::error(
            id,
            RpcError::internal(format!("could not encode response: {error}")),
        ),
    }
}

fn hello() -> Hello {
    Hello {
        daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
        rpc_version: RPC_VERSION,
        platform: std::env::consts::OS.to_owned(),
        arti_version: tobro_tor::ARTI_VERSION.to_owned(),
        pid: std::process::id(),
    }
}

// ---------------------------------------------------------------------------
// M1 supervisor-backed IPC server
// ---------------------------------------------------------------------------

use crate::lifecycle::State;
use crate::supervisor::{SupervisorEvent, SupervisorHandle};
use std::future::Future;
use tobro_tor::adapter::ListenerConfig;

/// Actions the IPC layer can invoke. Implemented by [`SupervisorHandle`] and by
/// test mocks (avoiding real Tor/bootstrap).
pub trait DaemonControl: Clone + Send + Sync + 'static {
    /// Snapshot for `daemon.status`.
    fn snapshot(&self) -> crate::supervisor::Snapshot;
    /// Request connect/start.
    fn connect(
        &self,
        state_dir: std::path::PathBuf,
        cache_dir: std::path::PathBuf,
        listeners: ListenerConfig,
    ) -> impl Future<Output = Result<(), String>> + Send;
    /// Request disconnect/stop.
    fn disconnect(&self) -> impl Future<Output = Result<(), String>> + Send;
    /// Request a new identity (new circuits) while connected.
    fn new_identity(&self) -> impl Future<Output = Result<(), String>> + Send;
    /// Get current configuration (redacted).
    fn config_get(&self) -> impl Future<Output = Result<serde_json::Value, String>> + Send;
    /// Validate a configuration patch without persisting it.
    fn config_validate(
        &self,
        patch: serde_json::Value,
    ) -> impl Future<Output = Result<serde_json::Value, String>> + Send;
    /// Validate, persist, and stage/apply a configuration patch.
    fn config_apply(
        &self,
        patch: serde_json::Value,
    ) -> impl Future<Output = Result<serde_json::Value, String>> + Send;
    /// Reload and validate configuration. Returns a JSON summary.
    fn reload_config(&self) -> impl Future<Output = Result<serde_json::Value, String>> + Send;
    /// Subscribe to supervisor events.
    fn subscribe_events(&self) -> broadcast::Receiver<SupervisorEvent>;
}

fn is_runtime_active(state: &crate::lifecycle::State) -> bool {
    !matches!(
        state,
        crate::lifecycle::State::Stopped | crate::lifecycle::State::Failed { .. }
    )
}

fn merge_json(base: &mut serde_json::Value, patch: &serde_json::Value) {
    match (base, patch) {
        (serde_json::Value::Object(base_map), serde_json::Value::Object(patch_map)) => {
            for (key, patch_value) in patch_map {
                if patch_value.is_null() {
                    base_map.remove(key);
                } else {
                    let entry = base_map
                        .entry(key.clone())
                        .or_insert(serde_json::Value::Null);
                    merge_json(entry, patch_value);
                }
            }
        }
        (base_slot, patch_value) => {
            *base_slot = patch_value.clone();
        }
    }
}

fn redacted_config_value(config: &tobro_config::Config) -> Result<serde_json::Value, String> {
    // Config currently contains no secrets; secrets belong in the keychain/store.
    serde_json::to_value(config).map_err(|e| format!("could not serialize config: {e}"))
}

fn load_current_config(path: &std::path::Path) -> Result<tobro_config::Config, String> {
    tobro_config::Config::load_or_default(path)
        .map_err(|e| format!("failed to load {}: {e}", path.display()))
}

fn merged_config(
    path: &std::path::Path,
    patch: &serde_json::Value,
) -> Result<(tobro_config::Config, tobro_config::Config), String> {
    tobro_config::check_unsupported_knobs(patch)?;
    let current = load_current_config(path)?;
    let mut merged = serde_json::to_value(&current)
        .map_err(|e| format!("could not serialize current config: {e}"))?;
    merge_json(&mut merged, patch);
    let next: tobro_config::Config =
        serde_json::from_value(merged).map_err(|e| format!("invalid config patch: {e}"))?;
    next.validate()
        .map_err(|e| format!("invalid config: {e}"))?;
    Ok((current, next))
}

fn config_effects(
    current: &tobro_config::Config,
    next: &tobro_config::Config,
    running: bool,
) -> serde_json::Value {
    let listeners_changed = current.proxy.socks_port != next.proxy.socks_port
        || current.proxy.effective_http_port() != next.proxy.effective_http_port()
        || current.proxy.dns_port != next.proxy.dns_port
        || current.proxy.bind_all_interfaces != next.proxy.bind_all_interfaces;
    let restart_required = listeners_changed;
    let mut warnings = tobro_config::proxy_warnings(&next.proxy);
    if running && restart_required {
        warnings.push(
            "active listeners require stop/connect (or restart) for network listener changes to take effect"
                .to_owned(),
        );
    }
    json!({
        "restart_required": restart_required,
        "listeners_changed": listeners_changed,
        "runtime_active": running,
        "warnings": warnings,
    })
}

fn config_get_at(path: &std::path::Path) -> Result<serde_json::Value, String> {
    let config = load_current_config(path)?;
    let warnings = tobro_config::proxy_warnings(&config.proxy);
    Ok(json!({
        "ok": true,
        "action": "config.get",
        "path": path.display().to_string(),
        "config": redacted_config_value(&config)?,
        "warnings": warnings,
    }))
}

fn config_validate_patch(
    path: &std::path::Path,
    patch: &serde_json::Value,
    running: bool,
) -> Result<serde_json::Value, String> {
    let (current, next) = merged_config(path, patch)?;
    let effects = config_effects(&current, &next, running);
    Ok(json!({
        "ok": true,
        "action": "config.validate",
        "path": path.display().to_string(),
        "valid": true,
        "config": redacted_config_value(&next)?,
        "effects": effects,
    }))
}

fn config_apply_patch(
    path: &std::path::Path,
    patch: &serde_json::Value,
    running: bool,
    listeners: &Arc<RwLock<ListenerConfig>>,
) -> Result<serde_json::Value, String> {
    let (current, next) = merged_config(path, patch)?;
    let effects = config_effects(&current, &next, running);
    next.save(path)
        .map_err(|e| format!("failed to save {}: {e}", path.display()))?;
    let next_listeners = ListenerConfig {
        socks_port: next.proxy.socks_port,
        http_port: next.proxy.effective_http_port(),
        dns_port: next.proxy.dns_port,
        bind_all_interfaces: next.proxy.bind_all_interfaces,
    };
    match listeners.write() {
        Ok(mut current) => *current = next_listeners.clone(),
        Err(poisoned) => *poisoned.into_inner() = next_listeners.clone(),
    }
    Ok(json!({
        "ok": true,
        "action": "config.apply",
        "path": path.display().to_string(),
        "saved": true,
        "config": redacted_config_value(&next)?,
        "proxy": {
            "socks_port": next_listeners.socks_port,
            "http_port": next_listeners.effective_http_port(),
            "dns_port": next_listeners.dns_port,
            "bind_all_interfaces": next_listeners.bind_all_interfaces,
        },
        "effects": effects,
    }))
}

/// Supervisor handle paired with config path and live listener settings for IPC.
#[derive(Debug, Clone)]
pub struct SupervisorControl {
    handle: SupervisorHandle,
    config_path: std::path::PathBuf,
    listeners: Arc<RwLock<ListenerConfig>>,
}

impl SupervisorControl {
    /// Create a control wrapper.
    pub fn new(
        handle: SupervisorHandle,
        config_path: std::path::PathBuf,
        listeners: Arc<RwLock<ListenerConfig>>,
    ) -> Self {
        Self {
            handle,
            config_path,
            listeners,
        }
    }
}

impl DaemonControl for SupervisorControl {
    fn snapshot(&self) -> crate::supervisor::Snapshot {
        self.handle.snapshot()
    }

    async fn connect(
        &self,
        state_dir: std::path::PathBuf,
        cache_dir: std::path::PathBuf,
        listeners: ListenerConfig,
    ) -> Result<(), String> {
        self.handle
            .connect(state_dir, cache_dir, listeners)
            .await
            .map_err(|e| e.to_string())
    }

    async fn disconnect(&self) -> Result<(), String> {
        self.handle.disconnect().await.map_err(|e| e.to_string())
    }

    async fn new_identity(&self) -> Result<(), String> {
        self.handle.new_identity().await.map_err(|e| e.to_string())
    }

    async fn config_get(&self) -> Result<serde_json::Value, String> {
        let path = self.config_path.clone();
        tokio::task::spawn_blocking(move || config_get_at(&path))
            .await
            .map_err(|e| format!("config task failed: {e}"))?
    }

    async fn config_validate(&self, patch: serde_json::Value) -> Result<serde_json::Value, String> {
        let path = self.config_path.clone();
        let snapshot = self.handle.snapshot();
        let running = is_runtime_active(&snapshot.state);
        tokio::task::spawn_blocking(move || config_validate_patch(&path, &patch, running))
            .await
            .map_err(|e| format!("config task failed: {e}"))?
    }

    async fn config_apply(&self, patch: serde_json::Value) -> Result<serde_json::Value, String> {
        let path = self.config_path.clone();
        let listeners = Arc::clone(&self.listeners);
        let snapshot = self.handle.snapshot();
        let running = is_runtime_active(&snapshot.state);
        tokio::task::spawn_blocking(move || config_apply_patch(&path, &patch, running, &listeners))
            .await
            .map_err(|e| format!("config task failed: {e}"))?
    }

    async fn reload_config(&self) -> Result<serde_json::Value, String> {
        let path = self.config_path.clone();
        let listeners = Arc::clone(&self.listeners);
        let snapshot = self.handle.snapshot();
        let running = !matches!(
            snapshot.state,
            crate::lifecycle::State::Stopped | crate::lifecycle::State::Failed { .. }
        );
        tokio::task::spawn_blocking(move || {
            let config = tobro_config::Config::load_or_default(&path)
                .map_err(|e| format!("failed to load {}: {e}", path.display()))?;
            config
                .validate()
                .map_err(|e| format!("invalid config {}: {e}", path.display()))?;
            let warnings = tobro_config::proxy_warnings(&config.proxy);
            let next = ListenerConfig {
                socks_port: config.proxy.socks_port,
                http_port: config.proxy.effective_http_port(),
                dns_port: config.proxy.dns_port,
                bind_all_interfaces: config.proxy.bind_all_interfaces,
            };
            match listeners.write() {
                Ok(mut current) => *current = next.clone(),
                Err(poisoned) => *poisoned.into_inner() = next.clone(),
            }
            let apply = if running {
                "validated and saved for next connection; active listeners require stop/connect to apply"
            } else {
                "validated and applied for next connection"
            };
            let mut result = json!({
                "ok": true,
                "action": "reload_config",
                "path": path.display().to_string(),
                "apply": apply,
                "proxy": {
                    "socks_port": next.socks_port,
                    "http_port": next.effective_http_port(),
                    "dns_port": next.dns_port,
                    "bind_all_interfaces": next.bind_all_interfaces
                },
            });
            if !warnings.is_empty() {
                result["warnings"] = json!(warnings);
            }
            Ok(result)
        })
        .await
        .map_err(|e| format!("reload task failed: {e}"))?
    }

    fn subscribe_events(&self) -> broadcast::Receiver<SupervisorEvent> {
        self.handle.subscribe_events()
    }
}

impl DaemonControl for SupervisorHandle {
    fn snapshot(&self) -> crate::supervisor::Snapshot {
        SupervisorHandle::snapshot(self)
    }

    async fn connect(
        &self,
        state_dir: std::path::PathBuf,
        cache_dir: std::path::PathBuf,
        listeners: ListenerConfig,
    ) -> Result<(), String> {
        SupervisorHandle::connect(self, state_dir, cache_dir, listeners)
            .await
            .map_err(|e| e.to_string())
    }

    async fn disconnect(&self) -> Result<(), String> {
        SupervisorHandle::disconnect(self)
            .await
            .map_err(|e| e.to_string())
    }

    async fn new_identity(&self) -> Result<(), String> {
        SupervisorHandle::new_identity(self)
            .await
            .map_err(|e| e.to_string())
    }

    async fn config_get(&self) -> Result<serde_json::Value, String> {
        Err("config operations require daemon config path context".to_owned())
    }

    async fn config_validate(
        &self,
        _patch: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        Err("config operations require daemon config path context".to_owned())
    }

    async fn config_apply(&self, _patch: serde_json::Value) -> Result<serde_json::Value, String> {
        Err("config operations require daemon config path context".to_owned())
    }

    async fn reload_config(&self) -> Result<serde_json::Value, String> {
        Err("config reload requires daemon config path context".to_owned())
    }

    fn subscribe_events(&self) -> broadcast::Receiver<SupervisorEvent> {
        SupervisorHandle::subscribe_events(self)
    }
}

pub fn snapshot_to_status(
    snapshot: &crate::supervisor::Snapshot,
    started: Instant,
) -> DaemonStatus {
    let (state, bootstrap) = match &snapshot.state {
        State::Stopped => (
            DaemonState::Stopped,
            BootstrapProgress {
                percent: 0,
                ready: false,
                blocked: None,
                detail: "stopped".to_owned(),
            },
        ),
        State::Starting => (DaemonState::Starting, BootstrapProgress::default()),
        State::Bootstrapping { percent, detail } => (
            DaemonState::Bootstrapping,
            BootstrapProgress {
                percent: percent.unwrap_or(0),
                ready: false,
                blocked: None,
                detail: redact_secrets(detail),
            },
        ),
        State::Ready => (
            DaemonState::Serving,
            BootstrapProgress {
                percent: 100,
                ready: true,
                blocked: None,
                detail: "ready".to_owned(),
            },
        ),
        State::Stopping => (
            DaemonState::Stopping,
            BootstrapProgress {
                percent: 100,
                ready: false,
                blocked: None,
                detail: "stopping".to_owned(),
            },
        ),
        State::Failed { message, .. } => {
            let redacted = redact_secrets(message);
            (
                DaemonState::Error,
                BootstrapProgress {
                    percent: 0,
                    ready: false,
                    blocked: Some(redacted.clone()),
                    detail: redacted,
                },
            )
        }
    };
    let (socks_port, http_port, dns_port, bind_all_interfaces) = snapshot
        .listeners
        .as_ref()
        .map(|l| {
            (
                l.socks_port,
                l.effective_http_port(),
                l.dns_port,
                l.bind_all_interfaces,
            )
        })
        .unwrap_or((9050, 9050, 9053, false));
    DaemonStatus {
        state,
        bootstrap,
        socks_port,
        http_port,
        dns_port,
        bind_all_interfaces,
        pid: std::process::id(),
        uptime_ms: started.elapsed().as_millis() as u64,
    }
}

/// Accept connections and dispatch M1 methods to the control plane.
pub async fn serve_daemon<C: DaemonControl>(
    mut server: Server,
    control: C,
    state_dir: std::path::PathBuf,
    cache_dir: std::path::PathBuf,
    listeners: Arc<RwLock<ListenerConfig>>,
) -> anyhow::Result<()> {
    let started = Instant::now();
    tracing::info!(socket = %server.path().display(), "IPC listening (M1)");
    loop {
        let connection = server.accept().await?;
        let control = control.clone();
        let state_dir = state_dir.clone();
        let cache_dir = cache_dir.clone();
        let listeners = Arc::clone(&listeners);
        tokio::spawn(async move {
            if let Err(error) = handle_daemon(
                connection, control, state_dir, cache_dir, listeners, started,
            )
            .await
            {
                tracing::debug!(%error, "IPC connection ended");
            }
        });
    }
}

/// Per-connection idle/read timeout (M1 baseline; avoids stuck handlers).
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

async fn handle_daemon<C: DaemonControl>(
    mut connection: Connection,
    control: C,
    state_dir: std::path::PathBuf,
    cache_dir: std::path::PathBuf,
    listeners: Arc<RwLock<ListenerConfig>>,
    started: Instant,
) -> Result<(), IpcError> {
    check_peer_auth(&connection)?;

    let mut events = control.subscribe_events();
    let mut handshaken = false;

    loop {
        tokio::select! {
            incoming = tokio::time::timeout(CONNECTION_IDLE_TIMEOUT, connection.next()) => {
                let incoming = match incoming {
                    Ok(v) => v,
                    Err(_) => {
                        tracing::debug!("IPC connection idle timeout");
                        return Ok(());
                    }
                };
                match incoming {
                    Some(Ok(Message::Request(request))) => {
                        let response = dispatch_daemon(
                            &control,
                            &state_dir,
                            &cache_dir,
                            &listeners,
                            started,
                            &mut handshaken,
                            request,
                        )
                        .await;
                        connection.send(Message::Response(response)).await?;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Err(error),
                    None => return Ok(()),
                }
            }
            event = events.recv() => {
                match event {
                    Ok(event) => {
                        if let Some(notification) = supervisor_event_to_notification(event) {
                            connection.send(Message::Notification(notification)).await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Coherent resync path: broadcast lagged; send current state so
                        // clients can reconcile without guessing. Clients may also call
                        // daemon.status.
                        let snapshot = control.snapshot();
                        let status = snapshot_to_status(&snapshot, started);
                        let notification = RpcNotification::new(
                            notifications::STATE_CHANGED,
                            Some(json!({ "state": status.state, "resync": true })),
                        );
                        connection.send(Message::Notification(notification)).await?;
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

fn current_listeners(listeners: &Arc<RwLock<ListenerConfig>>) -> ListenerConfig {
    match listeners.read() {
        Ok(listeners) => listeners.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// Peer-auth enforcement.
///
/// Unix: verifies AF_UNIX peer uid matches the daemon's effective uid (using
/// `rustix` for a safe uid query). The socket is also in a 0700 dir with 0600 mode.
/// Windows: named-pipe creation currently uses the process default security descriptor;
/// constructing a current-user DACL via `windows-sys`/`SECURITY_ATTRIBUTES` requires
/// unsafe Win32 calls, which conflicts with the workspace `unsafe_code = forbid` lint.
/// Follow-up: add an approved security-helper abstraction or a narrowly-scoped
/// `#[allow(unsafe_code)]` module for DACL creation and client SID verification.
fn check_peer_auth(connection: &Connection) -> Result<(), IpcError> {
    #[cfg(unix)]
    {
        let cred = connection.get_ref().peer_cred().map_err(|e| {
            IpcError::Protocol(format!("could not determine peer credentials: {e}"))
        })?;
        let peer_uid = cred.uid();
        let my_uid = rustix::process::geteuid().as_raw();
        if peer_uid != my_uid {
            return Err(IpcError::Protocol(format!(
                "peer uid {peer_uid} does not match daemon euid {my_uid}"
            )));
        }
    }
    #[cfg(windows)]
    {
        let _ = connection;
        // Follow-up: enforce named-pipe DACL / verify client user SID.
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = connection;
    }
    Ok(())
}

/// Validate method params.
fn validate_params(method: &str, params: &Option<serde_json::Value>) -> Result<(), RpcError> {
    tobro_ipc::validate_params(method, params)
}

pub async fn dispatch_daemon<C: DaemonControl>(
    control: &C,
    state_dir: &std::path::Path,
    cache_dir: &std::path::Path,
    listeners: &Arc<RwLock<ListenerConfig>>,
    started: Instant,
    handshaken: &mut bool,
    request: RpcRequest,
) -> RpcResponse {
    let id = request.id;
    let method = request.method.as_str();

    if !tobro_ipc::is_allowed_method(method) {
        return RpcResponse::error(id, RpcError::method_not_found(method));
    }
    if !*handshaken && !tobro_ipc::methods::PREFLIGHT.contains(&method) {
        return RpcResponse::error(
            id,
            RpcError::unauthorized("call daemon.hello before other methods"),
        );
    }
    if let Err(err) = validate_params(method, &request.params) {
        return RpcResponse::error(id, err);
    }

    match method {
        methods::HELLO => {
            // Enforce handshake: hello is the preflight method and establishes it.
            *handshaken = true;
            encode(id, &hello())
        }
        methods::STATUS => {
            let snapshot = control.snapshot();
            encode(id, &snapshot_to_status(&snapshot, started))
        }
        methods::CONNECT => {
            let snapshot = control.snapshot();
            let connect_listeners = snapshot
                .listeners
                .clone()
                .unwrap_or_else(|| current_listeners(listeners));
            let can_preflight = matches!(
                snapshot.state,
                crate::lifecycle::State::Stopped | crate::lifecycle::State::Failed { .. }
            );
            if can_preflight {
                let probe = tobro_config::ProxyConfig {
                    socks_port: connect_listeners.socks_port,
                    http_port: connect_listeners.effective_http_port(),
                    dns_port: connect_listeners.dns_port,
                    bind_all_interfaces: connect_listeners.bind_all_interfaces,
                };
                let conflicts = tobro_config::port_conflicts(&probe);
                if probe.bind_all_interfaces {
                    for warning in tobro_config::bind_all_interfaces_warnings(&probe) {
                        tracing::warn!(%warning, "bind-all-interfaces enabled at connect");
                    }
                }
                if !conflicts.is_empty() {
                    return RpcResponse::error(
                        id,
                        RpcError::new(
                            tobro_ipc::codes::INVALID_PARAMS,
                            format!(
                                "cannot connect: configured listener ports are unavailable: {}",
                                conflicts.join(" | ")
                            ),
                        ),
                    );
                }
            }
            match control
                .connect(
                    state_dir.to_path_buf(),
                    cache_dir.to_path_buf(),
                    connect_listeners,
                )
                .await
            {
                Ok(()) => encode(id, &json!({ "ok": true, "action": "connect" })),
                Err(e) => {
                    RpcResponse::error(id, RpcError::internal(format!("connect failed: {e}")))
                }
            }
        }
        methods::STOP => match control.disconnect().await {
            Ok(()) => encode(id, &json!({ "ok": true, "action": "stop" })),
            Err(e) => RpcResponse::error(id, RpcError::internal(format!("stop failed: {e}"))),
        },
        methods::NEW_IDENTITY => {
            let snapshot = control.snapshot();
            let can_request = matches!(
                snapshot.state,
                crate::lifecycle::State::Starting
                    | crate::lifecycle::State::Bootstrapping { .. }
                    | crate::lifecycle::State::Ready
            );
            if !can_request {
                return RpcResponse::error(
                    id,
                    RpcError::new(
                        tobro_ipc::codes::INVALID_REQUEST,
                        "cannot request new identity: Tor is not connected",
                    ),
                );
            }
            match control.new_identity().await {
                Ok(()) => encode(
                    id,
                    &json!({
                        "ok": true,
                        "action": "new_identity",
                        "note": "requested new circuits; guard state is preserved"
                    }),
                ),
                Err(e) => {
                    RpcResponse::error(id, RpcError::internal(format!("new identity failed: {e}")))
                }
            }
        }
        methods::CONFIG_GET => match control.config_get().await {
            Ok(value) => RpcResponse::success(id, value),
            Err(e) => RpcResponse::error(id, RpcError::internal(e)),
        },
        methods::CONFIG_VALIDATE => {
            let patch = request
                .params
                .as_ref()
                .and_then(|p| p.get("patch"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            match control.config_validate(patch).await {
                Ok(value) => RpcResponse::success(id, value),
                Err(e) => {
                    RpcResponse::error(id, RpcError::new(tobro_ipc::codes::INVALID_PARAMS, e))
                }
            }
        }
        methods::CONFIG_APPLY => {
            let patch = request
                .params
                .as_ref()
                .and_then(|p| p.get("patch"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            match control.config_apply(patch).await {
                Ok(value) => RpcResponse::success(id, value),
                Err(e) => {
                    RpcResponse::error(id, RpcError::new(tobro_ipc::codes::INVALID_PARAMS, e))
                }
            }
        }
        methods::RELOAD_CONFIG => match control.reload_config().await {
            Ok(value) => RpcResponse::success(id, value),
            Err(e) => RpcResponse::error(id, RpcError::internal(e)),
        },
        other => RpcResponse::error(id, RpcError::method_not_found(other)),
    }
}

fn supervisor_event_to_notification(event: SupervisorEvent) -> Option<RpcNotification> {
    match event {
        SupervisorEvent::StateChanged(snapshot) => {
            let state = match snapshot.state {
                State::Starting => DaemonState::Starting,
                State::Bootstrapping { .. } => DaemonState::Bootstrapping,
                State::Ready => DaemonState::Serving,
                State::Stopping => DaemonState::Stopping,
                State::Stopped => DaemonState::Stopped,
                State::Failed { .. } => DaemonState::Error,
            };
            Some(RpcNotification::new(
                notifications::STATE_CHANGED,
                Some(json!({ "state": state })),
            ))
        }
        SupervisorEvent::BootstrapProgress { percent, detail } => {
            let progress = BootstrapProgress {
                percent: percent.unwrap_or(0),
                ready: false,
                blocked: None,
                detail: redact_secrets(&detail),
            };
            Some(RpcNotification::new(
                notifications::BOOTSTRAP_PROGRESS,
                Some(serde_json::to_value(progress).ok()?),
            ))
        }
        SupervisorEvent::Failed { message } => Some(RpcNotification::new(
            notifications::STATE_CHANGED,
            Some(json!({ "state": "error", "message": redact_secrets(&message) })),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod daemon_tests {
    use super::*;
    use crate::lifecycle::{Desired, State};
    use crate::supervisor::{Snapshot, SupervisorEvent};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tobro_tor::adapter::ListenerConfig;

    #[derive(Debug, Clone)]
    struct MockControl {
        snapshot: Arc<Mutex<Snapshot>>,
        connects: Arc<Mutex<u32>>,
        disconnects: Arc<Mutex<u32>>,
        new_identities: Arc<Mutex<u32>>,
        _events_tx: broadcast::Sender<SupervisorEvent>,
        events_tx: broadcast::Sender<SupervisorEvent>,
    }

    impl MockControl {
        fn new() -> Self {
            let (events_tx, _) = broadcast::channel(16);
            Self {
                snapshot: Arc::new(Mutex::new(Snapshot {
                    desired: Desired::Stopped,
                    state: State::Stopped,
                    listeners: None,
                })),
                connects: Arc::new(Mutex::new(0)),
                disconnects: Arc::new(Mutex::new(0)),
                new_identities: Arc::new(Mutex::new(0)),
                _events_tx: events_tx.clone(),
                events_tx,
            }
        }

        fn set_state(&self, desired: Desired, state: State, listeners: Option<ListenerConfig>) {
            if let Ok(mut s) = self.snapshot.lock() {
                *s = Snapshot {
                    desired,
                    state,
                    listeners,
                };
            }
        }
    }

    impl DaemonControl for MockControl {
        fn snapshot(&self) -> Snapshot {
            self.snapshot
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        async fn connect(
            &self,
            _state_dir: PathBuf,
            _cache_dir: PathBuf,
            listeners: ListenerConfig,
        ) -> Result<(), String> {
            *self.connects.lock().unwrap_or_else(|e| e.into_inner()) += 1;
            self.set_state(Desired::Connected, State::Ready, Some(listeners));
            Ok(())
        }

        async fn disconnect(&self) -> Result<(), String> {
            *self.disconnects.lock().unwrap_or_else(|e| e.into_inner()) += 1;
            self.set_state(Desired::Stopped, State::Stopped, None);
            Ok(())
        }

        async fn new_identity(&self) -> Result<(), String> {
            *self
                .new_identities
                .lock()
                .unwrap_or_else(|e| e.into_inner()) += 1;
            Ok(())
        }

        async fn config_get(&self) -> Result<serde_json::Value, String> {
            Ok(json!({ "ok": true, "action": "config.get", "mock": true, "config": {} }))
        }

        async fn config_validate(
            &self,
            _patch: serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Ok(json!({ "ok": true, "action": "config.validate", "valid": true, "effects": {} }))
        }

        async fn config_apply(
            &self,
            _patch: serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Ok(json!({ "ok": true, "action": "config.apply", "saved": true, "effects": {} }))
        }

        async fn reload_config(&self) -> Result<serde_json::Value, String> {
            Ok(json!({ "ok": true, "action": "reload_config", "mock": true }))
        }

        fn subscribe_events(&self) -> broadcast::Receiver<SupervisorEvent> {
            self.events_tx.subscribe()
        }
    }

    fn req(id: u64, method: &str, params: Option<serde_json::Value>) -> RpcRequest {
        RpcRequest::new(RequestId::Number(id), method).with_params(params)
    }

    fn default_ctx() -> (PathBuf, PathBuf, Arc<RwLock<ListenerConfig>>, Instant) {
        (
            PathBuf::from("/tmp/state"),
            PathBuf::from("/tmp/cache"),
            Arc::new(RwLock::new(ListenerConfig::default())),
            Instant::now(),
        )
    }

    #[tokio::test]
    async fn pre_handshake_rejects_non_preflight() {
        let control = MockControl::new();
        let (state_dir, cache_dir, listeners, started) = default_ctx();
        let mut handshaken = false;
        let resp = dispatch_daemon(
            &control,
            &state_dir,
            &cache_dir,
            &listeners,
            started,
            &mut handshaken,
            req(1, methods::STATUS, None),
        )
        .await;
        let err = resp.error.expect("should error");
        assert_eq!(err.code, tobro_ipc::codes::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn allowlist_rejects_unknown_method() {
        let control = MockControl::new();
        let (state_dir, cache_dir, listeners, started) = default_ctx();
        let mut handshaken = true;
        let resp = dispatch_daemon(
            &control,
            &state_dir,
            &cache_dir,
            &listeners,
            started,
            &mut handshaken,
            req(1, "daemon.evil", None),
        )
        .await;
        let err = resp.error.expect("should error");
        assert_eq!(err.code, tobro_ipc::codes::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn param_validation_rejects_unexpected_params() {
        let control = MockControl::new();
        let (state_dir, cache_dir, listeners, started) = default_ctx();
        let mut handshaken = true;
        let resp = dispatch_daemon(
            &control,
            &state_dir,
            &cache_dir,
            &listeners,
            started,
            &mut handshaken,
            req(1, methods::STATUS, Some(json!({"nope": true}))),
        )
        .await;
        let err = resp.error.expect("should error");
        assert_eq!(err.code, tobro_ipc::codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn param_validation_accepts_null_and_empty_object() {
        let control = MockControl::new();
        let (state_dir, cache_dir, listeners, started) = default_ctx();
        let mut handshaken = true;
        for params in [None, Some(json!(null)), Some(json!({}))] {
            let resp = dispatch_daemon(
                &control,
                &state_dir,
                &cache_dir,
                &listeners,
                started,
                &mut handshaken,
                req(1, methods::STATUS, params),
            )
            .await;
            assert!(resp.error.is_none(), "params should be accepted");
            assert!(resp.result.is_some());
        }
    }

    #[tokio::test]
    async fn hello_connect_status_stop_flow_in_process() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("tobrod.sock");
        let mut server = Server::bind(&path).await?;
        let control = MockControl::new();
        let control_srv = control.clone();

        let daemon = tokio::spawn(async move {
            let conn = server.accept().await?;
            handle_daemon(
                conn,
                control_srv,
                PathBuf::from("/tmp/state"),
                PathBuf::from("/tmp/cache"),
                Arc::new(RwLock::new(ListenerConfig::default())),
                Instant::now(),
            )
            .await
        });

        // Give server a moment to accept.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut client = tobro_ipc::Client::connect(&path).await?;

        let hello = client.handshake().await?;
        assert_eq!(hello.rpc_version, RPC_VERSION);

        let status = client.call(methods::STATUS, None).await?;
        assert_eq!(status["state"], "stopped");

        let connect = client.call(methods::CONNECT, None).await?;
        assert_eq!(connect["ok"], true);
        assert_eq!(connect["action"], "connect");

        let status = client.call(methods::STATUS, None).await?;
        assert_eq!(status["state"], "serving");

        let stop = client.call(methods::STOP, None).await?;
        assert_eq!(stop["ok"], true);
        assert_eq!(stop["action"], "stop");

        let status = client.call(methods::STATUS, None).await?;
        assert_eq!(status["state"], "stopped");

        assert_eq!(*control.connects.lock().unwrap(), 1);
        assert_eq!(*control.disconnects.lock().unwrap(), 1);

        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(1), daemon).await;
        Ok(())
    }

    #[tokio::test]
    async fn new_identity_rejected_when_stopped() {
        let control = MockControl::new();
        let (state_dir, cache_dir, listeners, started) = default_ctx();
        let mut handshaken = true;
        let resp = dispatch_daemon(
            &control,
            &state_dir,
            &cache_dir,
            &listeners,
            started,
            &mut handshaken,
            req(1, methods::NEW_IDENTITY, None),
        )
        .await;
        let err = resp.error.expect("should error");
        assert_eq!(err.code, tobro_ipc::codes::INVALID_REQUEST);
        assert!(err.message.contains("not connected"));
    }

    #[tokio::test]
    async fn new_identity_succeeds_when_ready() {
        let control = MockControl::new();
        control.set_state(
            Desired::Connected,
            State::Ready,
            Some(ListenerConfig::default()),
        );
        let (state_dir, cache_dir, listeners, started) = default_ctx();
        let mut handshaken = true;
        let resp = dispatch_daemon(
            &control,
            &state_dir,
            &cache_dir,
            &listeners,
            started,
            &mut handshaken,
            req(1, methods::NEW_IDENTITY, None),
        )
        .await;
        assert!(resp.error.is_none(), "expected success: {:?}", resp.error);
        let result = resp.result.expect("result");
        assert_eq!(result["ok"], true);
        assert_eq!(result["action"], "new_identity");
        assert_eq!(
            *control
                .new_identities
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            1
        );
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn config_apply_merges_proxy_ports() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        tobro_config::Config::default().save(&path)?;
        let listeners = Arc::new(RwLock::new(ListenerConfig::default()));
        let result = config_apply_patch(
            &path,
            &json!({ "proxy": { "socks_port": 19050, "http_port": 0, "dns_port": 19053 } }),
            false,
            &listeners,
        )
        .map_err(|e| format!("{e}"))?;
        assert_eq!(result["ok"], true);
        assert_eq!(result["config"]["proxy"]["socks_port"], 19050);
        assert_eq!(result["config"]["proxy"]["dns_port"], 19053);
        assert_eq!(result["effects"]["listeners_changed"], true);
        let loaded = tobro_config::Config::load(&path)?;
        assert_eq!(loaded.proxy.socks_port, 19050);
        assert_eq!(listeners.read().unwrap().socks_port, 19050);
        Ok(())
    }

    #[test]
    fn config_validate_rejects_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        tobro_config::Config::default().save(&path)?;
        let err = config_validate_patch(&path, &json!({ "proxy": { "nope": 1 } }), false)
            .expect_err("should reject unknown field");
        assert!(err.contains("invalid config patch") || err.contains("unknown field"));
        Ok(())
    }
}
