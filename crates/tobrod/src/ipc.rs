//! IPC endpoint for `tobrod`.
//!
//! Contains the M0 spike [`Hub`] and an M1 supervisor-backed server that
//! enforces method allowlist, version handshake, and dispatches connect/stop.

use std::sync::{Arc, RwLock};
use std::time::Instant;

use futures::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::json;
use tokio::sync::broadcast;

use tobro_ipc::{
    BootstrapProgress, Connection, DaemonState, DaemonStatus, Hello, IpcError, Message,
    RPC_VERSION, RequestId, RpcError, RpcNotification, RpcRequest, RpcResponse, Server, methods,
    notifications,
};

/// Shared daemon state observed by IPC clients.
#[derive(Debug)]
pub struct Hub {
    status: RwLock<DaemonStatus>,
    events: broadcast::Sender<RpcNotification>,
    started: Instant,
}

impl Hub {
    /// Create the hub for a daemon about to start.
    pub fn new(socks_port: u16, dns_port: u16) -> Arc<Self> {
        let (events, _receiver) = broadcast::channel(64);
        Arc::new(Self {
            status: RwLock::new(DaemonStatus {
                state: DaemonState::Starting,
                bootstrap: BootstrapProgress::default(),
                socks_port,
                dns_port,
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
            blocked,
            detail,
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

use crate::supervisor::{Snapshot, SupervisorEvent, SupervisorHandle};
use tobro_tor::adapter::ListenerConfig;

fn snapshot_to_status(snapshot: &Snapshot, started: Instant) -> DaemonStatus {
    let (state, bootstrap) = match &snapshot.state {
        crate::lifecycle::State::Stopped => (
            DaemonState::Stopped,
            BootstrapProgress {
                percent: 0,
                ready: false,
                blocked: None,
                detail: "stopped".to_owned(),
            },
        ),
        crate::lifecycle::State::Starting => (DaemonState::Starting, BootstrapProgress::default()),
        crate::lifecycle::State::Bootstrapping { percent, detail } => (
            DaemonState::Bootstrapping,
            BootstrapProgress {
                percent: percent.unwrap_or(0),
                ready: false,
                blocked: None,
                detail: detail.clone(),
            },
        ),
        crate::lifecycle::State::Ready => (
            DaemonState::Serving,
            BootstrapProgress {
                percent: 100,
                ready: true,
                blocked: None,
                detail: "ready".to_owned(),
            },
        ),
        crate::lifecycle::State::Stopping => (
            DaemonState::Stopping,
            BootstrapProgress {
                percent: 100,
                ready: false,
                blocked: None,
                detail: "stopping".to_owned(),
            },
        ),
        crate::lifecycle::State::Failed { message, .. } => (
            DaemonState::Error,
            BootstrapProgress {
                percent: 0,
                ready: false,
                blocked: Some(message.clone()),
                detail: message.clone(),
            },
        ),
    };
    let (socks_port, dns_port) = snapshot
        .listeners
        .as_ref()
        .map(|l| (l.socks_port, l.dns_port))
        .unwrap_or((9050, 9053));
    DaemonStatus {
        state,
        bootstrap,
        socks_port,
        dns_port,
        pid: std::process::id(),
        uptime_ms: started.elapsed().as_millis() as u64,
    }
}

/// Accept connections and dispatch M1 methods to the supervisor.
pub async fn serve_daemon(
    mut server: Server,
    handle: SupervisorHandle,
    state_dir: std::path::PathBuf,
    cache_dir: std::path::PathBuf,
    default_listeners: ListenerConfig,
) -> anyhow::Result<()> {
    let started = Instant::now();
    tracing::info!(socket = %server.path().display(), "IPC listening (M1)");
    loop {
        let connection = server.accept().await?;
        let handle = handle.clone();
        let state_dir = state_dir.clone();
        let cache_dir = cache_dir.clone();
        let default_listeners = default_listeners.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_daemon(
                connection,
                handle,
                state_dir,
                cache_dir,
                default_listeners,
                started,
            )
            .await
            {
                tracing::debug!(%error, "IPC connection ended");
            }
        });
    }
}

async fn handle_daemon(
    mut connection: Connection,
    handle: SupervisorHandle,
    state_dir: std::path::PathBuf,
    cache_dir: std::path::PathBuf,
    default_listeners: ListenerConfig,
    started: Instant,
) -> Result<(), IpcError> {
    #[cfg(unix)]
    check_peer_auth(&connection)?;

    let mut events = handle.subscribe_events();
    let mut handshaken = false;

    loop {
        tokio::select! {
            incoming = connection.next() => {
                match incoming {
                    Some(Ok(Message::Request(request))) => {
                        let response = dispatch_daemon(
                            &handle,
                            &state_dir,
                            &cache_dir,
                            &default_listeners,
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
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

#[cfg(unix)]
fn check_peer_auth(connection: &Connection) -> Result<(), IpcError> {
    // Obtain peer credentials (ensures a same-host Unix socket peer and gives us
    // its uid for logging/auditing). Socket is created in a 0700 directory with
    // 0600 permissions, which restricts access to the owning user. A strict
    // uid==euid comparison requires platform FFI unavailable under the workspace's
    // `unsafe_code = "forbid"` lint; M1 hardening can add a safe wrapper dep.
    let _cred = connection
        .get_ref()
        .peer_cred()
        .map_err(|e| IpcError::Protocol(format!("could not determine peer credentials: {e}")))?;
    Ok(())
}

async fn dispatch_daemon(
    handle: &SupervisorHandle,
    state_dir: &std::path::Path,
    cache_dir: &std::path::Path,
    default_listeners: &ListenerConfig,
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

    match method {
        methods::HELLO => {
            *handshaken = true;
            encode(id, &hello())
        }
        methods::STATUS => {
            let snapshot = handle.snapshot();
            encode(id, &snapshot_to_status(&snapshot, started))
        }
        methods::CONNECT => {
            let listeners = handle
                .snapshot()
                .listeners
                .unwrap_or_else(|| default_listeners.clone());
            match handle
                .connect(state_dir.to_path_buf(), cache_dir.to_path_buf(), listeners)
                .await
            {
                Ok(()) => encode(id, &json!({ "ok": true, "action": "connect" })),
                Err(e) => {
                    RpcResponse::error(id, RpcError::internal(format!("connect failed: {e}")))
                }
            }
        }
        methods::STOP => match handle.disconnect().await {
            Ok(()) => encode(id, &json!({ "ok": true, "action": "stop" })),
            Err(e) => RpcResponse::error(id, RpcError::internal(format!("stop failed: {e}"))),
        },
        other => RpcResponse::error(id, RpcError::method_not_found(other)),
    }
}

fn supervisor_event_to_notification(event: SupervisorEvent) -> Option<RpcNotification> {
    match event {
        SupervisorEvent::StateChanged(snapshot) => {
            let state = match snapshot.state {
                crate::lifecycle::State::Starting => DaemonState::Starting,
                crate::lifecycle::State::Bootstrapping { .. } => DaemonState::Bootstrapping,
                crate::lifecycle::State::Ready => DaemonState::Serving,
                crate::lifecycle::State::Stopping => DaemonState::Stopping,
                crate::lifecycle::State::Stopped => DaemonState::Stopped,
                crate::lifecycle::State::Failed { .. } => DaemonState::Error,
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
                detail,
            };
            Some(RpcNotification::new(
                notifications::BOOTSTRAP_PROGRESS,
                Some(serde_json::to_value(progress).ok()?),
            ))
        }
        SupervisorEvent::Failed { message } => Some(RpcNotification::new(
            notifications::STATE_CHANGED,
            Some(json!({ "state": "error", "message": message })),
        )),
    }
}
