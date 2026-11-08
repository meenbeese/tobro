//! Minimal Tauri window for the M0 spike.
//!
//! The Rust side connects to the `tobrod` IPC socket/pipe (same default
//! location and `--socket` override as `tobroctl`), drives the handshake
//! itself, and relays every message to the webview as a `tobro-event`.
//! The webview (plain HTML/JS; React arrives in M1) renders bootstrap
//! progress and daemon state.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Manager, State};

use tobro_ipc::{Client, DaemonStatus, Message, methods, socket_path};

/// State shared between the IPC watcher task and command handlers.
#[derive(Debug, Default)]
struct AppState {
    latest: Mutex<Option<DaemonStatus>>,
}

impl AppState {
    fn set(&self, status: DaemonStatus) {
        *self.slot() = Some(status);
    }

    fn get(&self) -> Option<DaemonStatus> {
        self.slot().clone()
    }

    /// Take the lock, tolerating a poisoned mutex: the snapshot is plain
    /// data, and a panicking watcher must not wedge the UI.
    fn slot(&self) -> std::sync::MutexGuard<'_, Option<DaemonStatus>> {
        match self.latest.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Current daemon snapshot for the webview.
#[tauri::command]
fn status(state: State<'_, AppState>) -> Value {
    match state.get() {
        Some(status) => serde_json::to_value(status).unwrap_or(Value::Null),
        None => json!({ "state": "starting" }),
    }
}

/// Resolve the daemon socket path: `--socket <PATH>` on the command line
/// or the platform default used by `tobroctl`.
fn daemon_socket() -> Result<PathBuf, String> {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|arg| arg == "--socket") {
        let path = args.get(pos + 1).ok_or("--socket needs a value")?;
        return Ok(PathBuf::from(path));
    }
    let project = directories::ProjectDirs::from("", "", "tobro")
        .ok_or("could not determine the platform data directory")?;
    Ok(socket_path(&project.data_dir().join("state")))
}

fn main() {
    let daemon_socket = match daemon_socket() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("tobro: {error}");
            return;
        }
    };

    let app = tauri::Builder::default()
        .manage(AppState::default())
        .setup(move |app| {
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(watch_daemon(handle, daemon_socket));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![status])
        .build(tauri::generate_context!());
    match app {
        Ok(app) => app.run(|_handle, _run_event| {}),
        Err(error) => {
            eprintln!("tobro: error while starting the window: {error}");
            std::process::exit(1);
        }
    }
}

/// Message forwarded to the webview over the `tobro-event` channel.
///
/// Shapes:
/// - `{ "kind": "hello", "payload": <Hello> }`
/// - `{ "kind": "status", "payload": <DaemonStatus|null> }`
/// - `{ "kind": "reachable", "payload": { "socket": path } }`
/// - `{ "kind": "unreachable", "payload": { "error": String } }`
/// - `{ "kind": "event", "payload": { "method", "params" } }`
///
/// (`RpcNotification` serializes on the wire through custom impls, so the
/// watcher spells its payload out here instead.)
#[derive(Clone, serde::Serialize)]
struct ToWebview {
    kind: &'static str,
    payload: Value,
}

fn emit(handle: &AppHandle, kind: &'static str, payload: Value) -> Result<(), tauri::Error> {
    handle.emit("tobro-event", ToWebview { kind, payload })
}

/// Connect to the daemon and relay messages forever, retrying on
/// disconnect so an idle spike window lights up as soon as `tobrod`
/// comes back.
async fn watch_daemon(handle: AppHandle, daemon_socket: PathBuf) {
    loop {
        if let Err(error) = connect_once(&handle, &daemon_socket).await {
            let _ = emit(
                &handle,
                "unreachable",
                json!({ "error": format!("{} ({})", error, daemon_socket.display()) }),
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// One connect/relay cycle: handshake, initial status, then forward every
/// daemon message until the socket drops.
async fn connect_once(handle: &AppHandle, daemon_socket: &Path) -> Result<(), tobro_ipc::IpcError> {
    let mut client = Client::connect(daemon_socket).await?;
    let _ = emit(handle, "reachable", json!({ "socket": daemon_socket }));

    client.handshake().await?;

    // Fresh snapshot, then push daemon events as they arrive. A status
    // refresh after each notification keeps the headline in sync cheaply.
    refresh_status(handle, &mut client).await;
    loop {
        match client.next_message().await? {
            Some(Message::Notification(notification)) => {
                let _ = emit(
                    handle,
                    "event",
                    json!({
                        "method": notification.method,
                        "params": notification.params,
                    }),
                );
                refresh_status(handle, &mut client).await;
            }
            Some(Message::Response(response)) => {
                let _ = emit(
                    handle,
                    "event",
                    json!({
                        "method": "UNSOLICITED_RESPONSE",
                        "params": { "id": format!("{:?}", response.id) },
                    }),
                );
            }
            Some(Message::Request(request)) => {
                let _ = emit(
                    handle,
                    "event",
                    json!({
                        "method": "UNSOLICITED_REQUEST",
                        "params": {
                            "id": format!("{:?}", request.id),
                            "their": request.method,
                        },
                    }),
                );
            }
            None => return Ok(()),
        }
    }
}

/// Ask the daemon for `daemon.status`, cache it, and forward it.
async fn refresh_status(handle: &AppHandle, client: &mut Client) {
    match client.call(methods::STATUS, None).await {
        Ok(value) => {
            if let Ok(status) = serde_json::from_value::<DaemonStatus>(value.clone()) {
                handle.state::<AppState>().set(status);
            }
            let _ = emit(handle, "status", value);
        }
        Err(error) => {
            let _ = emit(handle, "status", json!(null));
            let _ = emit(handle, "unreachable", json!({ "error": error.to_string() }));
        }
    }
}
