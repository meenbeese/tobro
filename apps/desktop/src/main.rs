//! Tauri desktop shell for tobro (M1).
//!
//! Owns a single IPC connection to `tobrod`, relays daemon events to the
//! React webview, exposes connect/stop commands, and provides a tray icon
//! with quit-to-tray behavior.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut, ShortcutState};
use tauri_plugin_notification::NotificationExt;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroize;

use tobro_ipc::{Client, DaemonState, DaemonStatus, Message, methods, socket_path};

#[derive(Clone)]
struct TrayState {
    status_item: MenuItem<tauri::Wry>,
    connect_item: MenuItem<tauri::Wry>,
    stop_item: MenuItem<tauri::Wry>,
    new_identity_item: MenuItem<tauri::Wry>,
}

#[derive(Debug)]
enum IpcCommand {
    Connect(oneshot::Sender<Result<Value, String>>),
    Stop(oneshot::Sender<Result<Value, String>>),
    NewIdentity(oneshot::Sender<Result<Value, String>>),
    ConfigGet(oneshot::Sender<Result<Value, String>>),
    ConfigValidate {
        patch: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    ConfigApply {
        patch: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    BridgesTest {
        params: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    OnionList(oneshot::Sender<Result<Value, String>>),
    OnionCreate {
        params: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    OnionUpdate {
        params: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    OnionDelete {
        params: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    OnionBackup {
        params: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    OnionRestore {
        params: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    ClientAuthList(oneshot::Sender<Result<Value, String>>),
    ClientAuthGenerate {
        params: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    ClientAuthImport {
        params: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    ClientAuthExport {
        params: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    ClientAuthDelete {
        params: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    ClientAuthAttach {
        params: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    ClientAuthDetach {
        params: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
}

#[derive(Debug, Default)]
struct NotificationState {
    last_sent: Option<Instant>,
    last_key: Option<String>,
}

#[derive(Debug)]
struct AppState {
    latest: Mutex<Option<DaemonStatus>>,
    commands: mpsc::Sender<IpcCommand>,
    notifications: Mutex<NotificationState>,
}

impl AppState {
    fn set_status(&self, status: DaemonStatus) {
        *self.status_slot() = Some(status);
    }

    fn get_status(&self) -> Option<DaemonStatus> {
        self.status_slot().clone()
    }

    fn status_slot(&self) -> std::sync::MutexGuard<'_, Option<DaemonStatus>> {
        match self.latest.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Current daemon snapshot for the webview.
#[tauri::command]
fn status(state: State<'_, AppState>) -> Value {
    match state.get_status() {
        Some(status) => serde_json::to_value(status).unwrap_or(Value::Null),
        None => json!({ "state": "starting" }),
    }
}

#[tauri::command]
async fn daemon_connect(state: State<'_, AppState>) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::Connect(tx))
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_stop(state: State<'_, AppState>) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::Stop(tx))
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_new_identity(state: State<'_, AppState>) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::NewIdentity(tx))
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_get_config(state: State<'_, AppState>) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::ConfigGet(tx))
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_validate_config(state: State<'_, AppState>, patch: Value) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::ConfigValidate { patch, reply: tx })
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_apply_config(state: State<'_, AppState>, patch: Value) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::ConfigApply { patch, reply: tx })
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_test_bridges(
    state: State<'_, AppState>,
    line: Option<String>,
    lines: Option<Vec<String>>,
) -> Result<Value, String> {
    let mut params = serde_json::Map::new();
    if let Some(line) = line
        && !line.trim().is_empty()
    {
        params.insert("line".to_owned(), Value::String(line));
    }
    if let Some(lines) = lines {
        params.insert(
            "lines".to_owned(),
            Value::Array(lines.into_iter().map(Value::String).collect()),
        );
    }
    if params.is_empty() {
        return Err("provide a bridge line to test".to_owned());
    }
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::BridgesTest {
            params: Value::Object(params),
            reply: tx,
        })
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_onion_list(state: State<'_, AppState>) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::OnionList(tx))
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_onion_create(state: State<'_, AppState>, params: Value) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::OnionCreate { params, reply: tx })
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_onion_update(state: State<'_, AppState>, params: Value) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::OnionUpdate { params, reply: tx })
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_onion_delete(state: State<'_, AppState>, params: Value) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::OnionDelete { params, reply: tx })
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_onion_backup(state: State<'_, AppState>, params: Value) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::OnionBackup { params, reply: tx })
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_onion_restore(state: State<'_, AppState>, params: Value) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::OnionRestore { params, reply: tx })
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_client_auth_list(state: State<'_, AppState>) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::ClientAuthList(tx))
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_client_auth_generate(
    state: State<'_, AppState>,
    params: Value,
) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::ClientAuthGenerate { params, reply: tx })
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_client_auth_import(
    state: State<'_, AppState>,
    params: Value,
) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::ClientAuthImport { params, reply: tx })
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_client_auth_export(
    state: State<'_, AppState>,
    params: Value,
) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::ClientAuthExport { params, reply: tx })
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_client_auth_delete(
    state: State<'_, AppState>,
    params: Value,
) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::ClientAuthDelete { params, reply: tx })
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_client_auth_attach(
    state: State<'_, AppState>,
    params: Value,
) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::ClientAuthAttach { params, reply: tx })
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[tauri::command]
async fn daemon_client_auth_detach(
    state: State<'_, AppState>,
    params: Value,
) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel();
    state
        .commands
        .send(IpcCommand::ClientAuthDetach { params, reply: tx })
        .await
        .map_err(|_| "daemon connection task is not running".to_owned())?;
    rx.await
        .map_err(|_| "daemon connection task dropped the response".to_owned())?
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ProxyPorts {
    socks_port: u16,
    http_port: u16,
    dns_port: u16,
    #[serde(default)]
    bind_all_interfaces: bool,
    config_path: String,
}

#[tauri::command]
async fn get_proxy_ports(state: State<'_, AppState>) -> Result<ProxyPorts, String> {
    if let Ok(result) = daemon_get_config(state).await
        && let Some(config) = result.get("config")
        && let Some(proxy) = config.get("proxy")
    {
        return Ok(ProxyPorts {
            socks_port: proxy
                .get("socks_port")
                .and_then(Value::as_u64)
                .unwrap_or(9050) as u16,
            http_port: proxy
                .get("http_port")
                .and_then(Value::as_u64)
                .unwrap_or(9050) as u16,
            dns_port: proxy
                .get("dns_port")
                .and_then(Value::as_u64)
                .unwrap_or(9053) as u16,
            bind_all_interfaces: proxy
                .get("bind_all_interfaces")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            config_path: result
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        });
    }
    let path = tobro_config::default_path().map_err(|e| e.to_string())?;
    let config = tobro_config::Config::load_or_default(&path).map_err(|e| e.to_string())?;
    Ok(ProxyPorts {
        socks_port: config.proxy.socks_port,
        http_port: config.proxy.effective_http_port(),
        dns_port: config.proxy.dns_port,
        bind_all_interfaces: config.proxy.bind_all_interfaces,
        config_path: path.display().to_string(),
    })
}

fn apply_window_capture_protection(handle: &AppHandle, enabled: bool) {
    for (_label, window) in handle.webview_windows() {
        let _ = window.set_content_protected(enabled);
    }
}

/// Best-effort window capture/screen-recording protection toggle.
/// Applied to all app windows; support and behavior vary by OS/windowing system.
#[tauri::command]
fn set_capture_protection(app: AppHandle, enabled: bool) -> Result<(), String> {
    apply_window_capture_protection(&app, enabled);
    Ok(())
}

#[tauri::command]
fn open_external_url(url: String) -> Result<(), String> {
    let url = url.trim().to_owned();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("only http(s) URLs are allowed".to_owned());
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(&url)
            .spawn()
            .map_err(|e| format!("failed to open URL: {e}"))?;
    }
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", "", &url])
            .spawn()
            .map_err(|e| format!("failed to open URL: {e}"))?;
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        Command::new("xdg-open")
            .arg(&url)
            .spawn()
            .map_err(|e| format!("failed to open URL: {e}"))?;
    }
    Ok(())
}

#[tauri::command]
async fn save_proxy_ports(
    state: State<'_, AppState>,
    socks_port: u16,
    http_port: u16,
    dns_port: u16,
    bind_all_interfaces: bool,
) -> Result<Value, String> {
    let patch = json!({
        "proxy": {
            "socks_port": socks_port,
            "http_port": http_port,
            "dns_port": dns_port,
            "bind_all_interfaces": bind_all_interfaces
        }
    });

    if let Ok(result) = daemon_apply_config(state, patch.clone()).await {
        let effects = result.get("effects").cloned().unwrap_or_else(|| json!({}));
        let warnings = effects
            .get("warnings")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let apply = if effects
            .get("runtime_active")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            && effects
                .get("restart_required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            "validated and saved; active listeners require stop/connect for listener changes to take effect"
        } else {
            "validated and applied for next connection"
        };
        return Ok(json!({
            "ok": result.get("ok").and_then(Value::as_bool).unwrap_or(true),
            "config_path": result.get("path").cloned().unwrap_or(Value::Null),
            "proxy": result.get("proxy").cloned().unwrap_or_else(|| json!({
                "socks_port": socks_port,
                "http_port": http_port,
                "dns_port": dns_port,
                "bind_all_interfaces": bind_all_interfaces
            })),
            "reload": { "apply": apply, "warnings": warnings },
            "config": result.get("config").cloned(),
        }));
    }

    let path = tobro_config::default_path().map_err(|e| e.to_string())?;
    let mut config = tobro_config::Config::load_or_default(&path).map_err(|e| e.to_string())?;
    config.proxy.socks_port = socks_port;
    config.proxy.http_port = http_port;
    config.proxy.dns_port = dns_port;
    config.proxy.bind_all_interfaces = bind_all_interfaces;
    config.validate().map_err(|e| e.to_string())?;
    config.save(&path).map_err(|e| e.to_string())?;
    let warnings = tobro_config::proxy_warnings(&config.proxy);
    Ok(json!({
        "ok": true,
        "config_path": path.display().to_string(),
        "proxy": {
            "socks_port": config.proxy.socks_port,
            "http_port": config.proxy.effective_http_port(),
            "dns_port": config.proxy.dns_port,
            "bind_all_interfaces": config.proxy.bind_all_interfaces,
        },
        "reload": { "apply": "saved to config; daemon was unreachable, so it was not reloaded", "warnings": warnings },
    }))
}

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

#[derive(Clone, serde::Serialize)]
struct ToWebview {
    kind: &'static str,
    payload: Value,
}

fn emit(handle: &AppHandle, kind: &'static str, payload: Value) {
    let _ = handle.emit("tobro-event", ToWebview { kind, payload });
}

fn main() {
    let daemon_socket = match daemon_socket() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("tobro: {error}");
            std::process::exit(1);
        }
    };

    let (command_tx, command_rx) = mpsc::channel(32);

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, _shortcut, event| {
                    if event.state == ShortcutState::Pressed {
                        toggle_connect_stop(app);
                    }
                })
                .build(),
        )
        .manage(AppState {
            latest: Mutex::new(None),
            commands: command_tx,
            notifications: Mutex::new(NotificationState::default()),
        })
        .setup(move |app| {
            // Best-effort default: reduce accidental capture exposure until UI syncs preference.
            apply_window_capture_protection(app.handle(), true);
            setup_tray(app.handle())?;
            let start_minimized = std::env::args().any(|a| a == "--minimized" || a == "--hidden");
            if start_minimized && let Some(window) = app.get_webview_window("main") {
                let _ = window.hide();
            }
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(watch_daemon(handle, daemon_socket, command_rx));
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // M1: closing the window hides it; the daemon keeps running.
                // Quit is explicit via the tray menu.
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            status,
            open_external_url,
            set_capture_protection,
            set_global_shortcut,
            get_autostart,
            set_autostart,
            get_app_lock_status,
            set_app_lock_config,
            set_app_lock_password,
            remove_app_lock_password,
            unlock_app_lock,
            daemon_connect,
            daemon_stop,
            daemon_new_identity,
            daemon_get_config,
            daemon_validate_config,
            daemon_apply_config,
            daemon_test_bridges,
            daemon_onion_list,
            daemon_onion_create,
            daemon_onion_update,
            daemon_onion_delete,
            daemon_onion_backup,
            daemon_onion_restore,
            daemon_client_auth_list,
            daemon_client_auth_generate,
            daemon_client_auth_import,
            daemon_client_auth_export,
            daemon_client_auth_delete,
            daemon_client_auth_attach,
            daemon_client_auth_detach,
            get_proxy_ports,
            save_proxy_ports
        ])
        .build(tauri::generate_context!());

    match app {
        Ok(app) => app.run(|_app_handle, _run_event| {}),
        Err(error) => {
            eprintln!("tobro: error while starting the window: {error}");
            std::process::exit(1);
        }
    }
}

fn tray_status_text(reachable: bool, status: Option<&DaemonStatus>) -> String {
    if !reachable {
        return "Status: Daemon unavailable".to_owned();
    }
    let Some(status) = status else {
        return "Status: Waiting…".to_owned();
    };
    let pct = if status.bootstrap.percent > 0 {
        format!(" ({}%)", status.bootstrap.percent)
    } else {
        String::new()
    };
    let label = match status.state {
        DaemonState::Starting => "Starting",
        DaemonState::Bootstrapping => "Bootstrapping",
        DaemonState::Connected => "Connected",
        DaemonState::Serving => "Serving",
        DaemonState::Stopping => "Stopping",
        DaemonState::Stopped => "Stopped",
        DaemonState::Error => "Error",
    };
    format!("Status: {label}{pct}")
}

fn update_tray_menu(handle: &AppHandle, reachable: bool, status: Option<&DaemonStatus>) {
    let Some(tray) = handle.try_state::<TrayState>() else {
        return;
    };
    let _ = tray
        .status_item
        .set_text(tray_status_text(reachable, status));
    let state = status.map(|s| &s.state);
    let active = matches!(
        state,
        Some(
            DaemonState::Starting
                | DaemonState::Bootstrapping
                | DaemonState::Connected
                | DaemonState::Serving
        )
    );
    let stopping = matches!(state, Some(DaemonState::Stopping));
    let can_connect = !active && !stopping;
    let can_stop = reachable && active && !stopping;
    let can_new_identity =
        reachable && matches!(state, Some(DaemonState::Connected | DaemonState::Serving));
    let _ = tray.connect_item.set_enabled(can_connect);
    let _ = tray.stop_item.set_enabled(can_stop);
    let _ = tray.new_identity_item.set_enabled(can_new_identity);
    if let Some(t) = handle.tray_by_id("main-tray") {
        let _ = t.set_tooltip(Some(&tray_status_text(reachable, status)));
    }
}

const NOTIFY_MIN_INTERVAL: Duration = Duration::from_secs(4);
const NOTIFY_DEDUPE_WINDOW: Duration = Duration::from_secs(30);

fn maybe_notify(handle: &AppHandle, key: impl Into<String>, title: &str, body: &str) {
    let key = key.into();
    let state = handle.state::<AppState>();
    let mut guard = match state.notifications.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let now = Instant::now();
    if let Some(last) = guard.last_sent
        && now.duration_since(last) < NOTIFY_MIN_INTERVAL
    {
        return;
    }
    if guard.last_key.as_deref() == Some(key.as_str())
        && let Some(last) = guard.last_sent
        && now.duration_since(last) < NOTIFY_DEDUPE_WINDOW
    {
        return;
    }
    guard.last_sent = Some(now);
    guard.last_key = Some(key);
    drop(guard);
    let _ = handle
        .notification()
        .builder()
        .title(title)
        .body(body)
        .show();
}

fn notify_status_transition(
    handle: &AppHandle,
    previous: Option<&DaemonStatus>,
    current: Option<&DaemonStatus>,
    unreachable_error: Option<&str>,
) {
    if let Some(err) = unreachable_error {
        let short = if err.len() > 160 {
            format!("{}…", &err[..160])
        } else {
            err.to_owned()
        };
        maybe_notify(
            handle,
            format!("unreachable:{short}"),
            "Tobro: Daemon unavailable",
            &short,
        );
        return;
    }
    let Some(cur) = current else {
        return;
    };
    let prev_state = previous.map(|s| &s.state);
    if prev_state == Some(&cur.state) {
        return;
    }
    match cur.state {
        DaemonState::Connected | DaemonState::Serving => {
            maybe_notify(
                handle,
                "state:connected",
                "Tobro: Connected",
                "Tor is connected and proxy services are ready.",
            );
        }
        DaemonState::Bootstrapping => {
            // Notify when bootstrapping starts from a non-active/error context (not on percent churn).
            if !matches!(
                prev_state,
                Some(DaemonState::Starting | DaemonState::Bootstrapping)
            ) {
                maybe_notify(
                    handle,
                    "state:bootstrapping",
                    "Tobro: Connecting to Tor",
                    "Bootstrapping Tor network connection…",
                );
            }
        }
        DaemonState::Stopped => {
            if matches!(
                prev_state,
                Some(
                    DaemonState::Starting
                        | DaemonState::Bootstrapping
                        | DaemonState::Connected
                        | DaemonState::Serving
                        | DaemonState::Stopping
                )
            ) {
                maybe_notify(
                    handle,
                    "state:stopped",
                    "Tobro: Disconnected",
                    "Tor connection has stopped.",
                );
            }
        }
        DaemonState::Error => {
            let detail = if !cur.bootstrap.detail.trim().is_empty()
                && cur.bootstrap.detail != "not started"
            {
                cur.bootstrap.detail.clone()
            } else if let Some(b) = &cur.bootstrap.blocked {
                b.clone()
            } else {
                "The Tor daemon reported an error.".to_owned()
            };
            let short = if detail.len() > 180 {
                format!("{}…", &detail[..180])
            } else {
                detail
            };
            maybe_notify(
                handle,
                format!("state:error:{short}"),
                "Tobro: Connection error",
                &short,
            );
        }
        DaemonState::Starting | DaemonState::Stopping => {}
    }
}

fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let status_item = MenuItem::with_id(app, "status", "Status: Starting…", false, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let connect_item = MenuItem::with_id(app, "connect", "Connect", true, None::<&str>)?;
    let stop_item = MenuItem::with_id(app, "stop", "Stop", false, None::<&str>)?;
    let new_identity_item =
        MenuItem::with_id(app, "new_identity", "New identity", false, None::<&str>)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let open_item = MenuItem::with_id(app, "open", "Open window", true, None::<&str>)?;
    let sep3 = PredefinedMenuItem::separator(app)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &status_item,
            &sep1,
            &connect_item,
            &stop_item,
            &new_identity_item,
            &sep2,
            &open_item,
            &sep3,
            &quit_item,
        ],
    )?;

    let mut builder = TrayIconBuilder::with_id("main-tray")
        .menu(&menu)
        .tooltip("tobro")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main_window(app),
            "connect" => dispatch_tray_command(app, IpcCommandKind::Connect),
            "stop" => dispatch_tray_command(app, IpcCommandKind::Stop),
            "new_identity" => dispatch_tray_command(app, IpcCommandKind::NewIdentity),
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder.build(app)?;
    app.manage(TrayState {
        status_item,
        connect_item,
        stop_item,
        new_identity_item,
    });
    update_tray_menu(app, false, None);
    Ok(())
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[derive(Clone, Copy)]
enum IpcCommandKind {
    Connect,
    Stop,
    NewIdentity,
}

fn dispatch_tray_command(app: &AppHandle, kind: IpcCommandKind) {
    let sender = app.state::<AppState>().commands.clone();
    tauri::async_runtime::spawn(async move {
        let (tx, rx) = oneshot::channel();
        let cmd = match kind {
            IpcCommandKind::Connect => IpcCommand::Connect(tx),
            IpcCommandKind::Stop => IpcCommand::Stop(tx),
            IpcCommandKind::NewIdentity => IpcCommand::NewIdentity(tx),
        };
        if sender.send(cmd).await.is_ok() {
            let _ = rx.await;
        }
    });
}

fn toggle_connect_stop(app: &AppHandle) {
    let status = app.state::<AppState>().get_status();
    let active = matches!(
        status.as_ref().map(|s| &s.state),
        Some(
            DaemonState::Starting
                | DaemonState::Bootstrapping
                | DaemonState::Connected
                | DaemonState::Serving
        )
    );
    if active {
        dispatch_tray_command(app, IpcCommandKind::Stop);
    } else {
        dispatch_tray_command(app, IpcCommandKind::Connect);
    }
}

#[tauri::command]
fn set_global_shortcut(app: AppHandle, shortcut: Option<String>) -> Result<(), String> {
    let manager = app.global_shortcut();
    manager.unregister_all().map_err(|e| e.to_string())?;
    let Some(shortcut) = shortcut
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
    else {
        return Ok(());
    };
    let parsed: Shortcut = shortcut
        .parse()
        .map_err(|e| format!("Invalid shortcut: {e}"))?;
    manager
        .register(parsed)
        .map_err(|e| format!("Could not register shortcut (it may be in use): {e}"))?;
    Ok(())
}

#[derive(Clone, serde::Serialize)]
struct AutostartStatus {
    supported: bool,
    enabled: bool,
    start_minimized: bool,
    method: String,
    details: String,
}

fn current_exe_for_autostart() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("could not determine executable path: {e}"))
}

#[cfg(target_os = "macos")]
fn macos_launch_agent_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join("app.tobro.plist"))
}

#[cfg(target_os = "macos")]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(target_os = "macos")]
fn write_macos_launch_agent(start_minimized: bool) -> Result<String, String> {
    let exe = current_exe_for_autostart()?;
    let path = macos_launch_agent_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create LaunchAgents dir: {e}"))?;
    }
    let mut args = format!(
        "    <string>{}</string>\n",
        xml_escape(&exe.display().to_string())
    );
    if start_minimized {
        args.push_str("    <string>--minimized</string>\n");
    }
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>app.tobro</string>
  <key>ProgramArguments</key>
  <array>
{args}  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>ProcessType</key>
  <string>Interactive</string>
</dict>
</plist>
"#
    );
    std::fs::write(&path, plist).map_err(|e| format!("failed to write LaunchAgent: {e}"))?;
    Ok(path.display().to_string())
}

#[cfg(target_os = "macos")]
fn remove_macos_launch_agent() -> Result<String, String> {
    let path = macos_launch_agent_path()?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("failed to remove LaunchAgent: {e}"))?;
    }
    Ok(path.display().to_string())
}

#[cfg(target_os = "macos")]
fn read_macos_autostart() -> AutostartStatus {
    let path = macos_launch_agent_path().ok();
    let enabled = path.as_ref().is_some_and(|p| p.exists());
    let start_minimized = path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .is_some_and(|s| s.contains("--minimized") || s.contains("--hidden"));
    AutostartStatus {
        supported: true,
        enabled,
        start_minimized: enabled && start_minimized,
        method: "LaunchAgent (~/Library/LaunchAgents)".to_owned(),
        details: path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "LaunchAgent path unavailable".to_owned()),
    }
}

#[cfg(target_os = "windows")]
fn write_windows_run_key(start_minimized: bool) -> Result<String, String> {
    let exe = current_exe_for_autostart()?;
    let mut data = format!("\"{}\"", exe.display());
    if start_minimized {
        data.push_str(" --minimized");
    }
    let out = Command::new("reg")
        .args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "tobro",
            "/t",
            "REG_SZ",
            "/f",
            "/d",
            &data,
        ])
        .output()
        .map_err(|e| format!("failed to run reg.exe: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "reg add failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\tobro".to_owned())
}

#[cfg(target_os = "windows")]
fn remove_windows_run_key() -> Result<String, String> {
    let out = Command::new("reg")
        .args([
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "tobro",
            "/f",
        ])
        .output()
        .map_err(|e| format!("failed to run reg.exe: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let s = stderr.to_lowercase();
        if !s.contains("unable to find") && !s.contains("does not exist") {
            return Err(format!("reg delete failed: {}", stderr.trim()));
        }
    }
    Ok(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\tobro".to_owned())
}

#[cfg(target_os = "windows")]
fn read_windows_autostart() -> AutostartStatus {
    let out = Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "tobro",
        ])
        .output();
    let (enabled, start_minimized) = match out {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout);
            (true, s.contains("--minimized") || s.contains("--hidden"))
        }
        _ => (false, false),
    };
    AutostartStatus {
        supported: true,
        enabled,
        start_minimized: enabled && start_minimized,
        method: "Run key (HKCU)".to_owned(),
        details: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\tobro".to_owned(),
    }
}

#[cfg(target_os = "linux")]
fn linux_systemd_user_unit_path() -> Result<PathBuf, String> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or("could not determine config directory")?;
    Ok(config.join("systemd").join("user").join("tobro.service"))
}

#[cfg(target_os = "linux")]
fn write_linux_systemd_unit(start_minimized: bool) -> Result<String, String> {
    let exe = current_exe_for_autostart()?;
    let path = linux_systemd_user_unit_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create systemd user dir: {e}"))?;
    }
    let exec = if start_minimized {
        format!("\"{}\" --minimized", exe.display())
    } else {
        format!("\"{}\"", exe.display())
    };
    let unit = format!(
        r#"[Unit]
Description=tobro desktop Tor client
After=graphical-session.target
PartOf=graphical-session.target

[Service]
Type=simple
ExecStart={exec}
Restart=no

[Install]
WantedBy=default.target
"#
    );
    std::fs::write(&path, unit).map_err(|e| format!("failed to write systemd user unit: {e}"))?;
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();
    let details = match Command::new("systemctl")
        .args(["--user", "enable", "tobro.service"])
        .output()
    {
        Ok(out) if out.status.success() => path.display().to_string(),
        Ok(out) => format!(
            "{} (unit written; `systemctl --user enable` failed: {})",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => format!(
            "{} (unit written; could not run systemctl: {e})",
            path.display()
        ),
    };
    Ok(details)
}

#[cfg(target_os = "linux")]
fn remove_linux_systemd_unit() -> Result<String, String> {
    let path = linux_systemd_user_unit_path()?;
    let _ = Command::new("systemctl")
        .args(["--user", "disable", "--now", "tobro.service"])
        .output();
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("failed to remove systemd user unit: {e}"))?;
    }
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();
    Ok(path.display().to_string())
}

#[cfg(target_os = "linux")]
fn read_linux_autostart() -> AutostartStatus {
    let path = linux_systemd_user_unit_path().ok();
    let enabled = path.as_ref().is_some_and(|p| p.exists());
    let start_minimized = path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .is_some_and(|s| s.contains("--minimized") || s.contains("--hidden"));
    AutostartStatus {
        supported: true,
        enabled,
        start_minimized: enabled && start_minimized,
        method: "systemd user unit (~/.config/systemd/user)".to_owned(),
        details: path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "systemd user unit path unavailable".to_owned()),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn read_fallback_autostart() -> AutostartStatus {
    AutostartStatus {
        supported: false,
        enabled: false,
        start_minimized: false,
        method: "unsupported".to_owned(),
        details: "Autostart is not implemented for this platform.".to_owned(),
    }
}

#[tauri::command]
fn get_autostart() -> AutostartStatus {
    #[cfg(target_os = "macos")]
    {
        read_macos_autostart()
    }
    #[cfg(target_os = "windows")]
    {
        read_windows_autostart()
    }
    #[cfg(target_os = "linux")]
    {
        read_linux_autostart()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        read_fallback_autostart()
    }
}

#[tauri::command]
fn set_autostart(enabled: bool, start_minimized: bool) -> Result<AutostartStatus, String> {
    #[cfg(target_os = "macos")]
    {
        if enabled {
            let _ = write_macos_launch_agent(start_minimized)?;
        } else {
            let _ = remove_macos_launch_agent()?;
        }
        Ok(read_macos_autostart())
    }
    #[cfg(target_os = "windows")]
    {
        if enabled {
            let _ = write_windows_run_key(start_minimized)?;
        } else {
            let _ = remove_windows_run_key()?;
        }
        Ok(read_windows_autostart())
    }
    #[cfg(target_os = "linux")]
    {
        if enabled {
            let _ = write_linux_systemd_unit(start_minimized)?;
        } else {
            let _ = remove_linux_systemd_unit()?;
        }
        Ok(read_linux_autostart())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = (enabled, start_minimized);
        Err("Autostart is not implemented for this platform.".to_owned())
    }
}

// --- App lock (configurable): password fallback + best-effort OS auth hooks ---
// Password verifier is stored locally (PBKDF2-HMAC-SHA256). OS auth is
// platform-dependent; when unavailable, the UI falls back to password.

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct PasswordVerifier {
    salt_hex: String,
    hash_hex: String,
    iterations: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AppLockConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_true")]
    lock_on_idle: bool,
    #[serde(default = "default_idle_minutes")]
    idle_minutes: u16,
    #[serde(default = "default_true")]
    lock_on_close: bool,
    #[serde(default = "default_true")]
    prefer_os_auth: bool,
    #[serde(default)]
    password: Option<PasswordVerifier>,
}

fn default_true() -> bool {
    true
}
fn default_idle_minutes() -> u16 {
    5
}

impl Default for AppLockConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lock_on_idle: true,
            idle_minutes: 5,
            lock_on_close: true,
            prefer_os_auth: true,
            password: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct AppLockStatus {
    enabled: bool,
    lock_on_idle: bool,
    idle_minutes: u16,
    lock_on_close: bool,
    prefer_os_auth: bool,
    has_password: bool,
    os_auth_available: bool,
    os_auth_method: String,
}

fn app_lock_path() -> Result<PathBuf, String> {
    let project = directories::ProjectDirs::from("", "", "tobro")
        .ok_or("could not determine the platform data directory")?;
    Ok(project.data_dir().join("app-lock.json"))
}

fn read_app_lock_config() -> Result<AppLockConfig, String> {
    let path = app_lock_path()?;
    if !path.exists() {
        return Ok(AppLockConfig::default());
    }
    let data = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read app lock config: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("failed to parse app lock config: {e}"))
}

fn write_app_lock_config(cfg: &AppLockConfig) -> Result<(), String> {
    let path = app_lock_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create app data dir: {e}"))?;
    }
    let data = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("failed to serialize app lock config: {e}"))?;
    std::fs::write(&path, data).map_err(|e| format!("failed to write app lock config: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn normalize_idle_minutes(minutes: u16) -> u16 {
    minutes.clamp(1, 240)
}

fn hash_password(password: &str) -> Result<PasswordVerifier, String> {
    use pbkdf2::pbkdf2_hmac;
    use rand::RngCore;
    use sha2::Sha256;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let iterations: u32 = 600_000;
    let mut hash = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut hash);
    Ok(PasswordVerifier {
        salt_hex: hex::encode(salt),
        hash_hex: hex::encode(hash),
        iterations,
    })
}

fn verify_password(password: &str, verifier: &PasswordVerifier) -> Result<bool, String> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    let salt = hex::decode(&verifier.salt_hex)
        .map_err(|_| "invalid stored password verifier".to_owned())?;
    let expected = hex::decode(&verifier.hash_hex)
        .map_err(|_| "invalid stored password verifier".to_owned())?;
    let mut out = vec![0u8; expected.len()];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, verifier.iterations, &mut out);
    Ok(out == expected)
}

fn os_auth_status() -> (bool, String) {
    // Best-effort OS auth: native biometric/system-auth integration is platform-specific.
    // Password fallback is always available when a password is configured.
    #[cfg(target_os = "macos")]
    {
        // Touch ID / LocalAuthentication requires native framework integration; not wired here.
        (
            false,
            "macOS system auth integration not available in this build; use password".to_owned(),
        )
    }
    #[cfg(target_os = "windows")]
    {
        (
            false,
            "Windows Hello integration not available in this build; use password".to_owned(),
        )
    }
    #[cfg(target_os = "linux")]
    {
        (
            false,
            "Linux system auth integration not available in this build; use password".to_owned(),
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        (
            false,
            "OS auth not available on this platform; use password".to_owned(),
        )
    }
}

#[tauri::command]
fn get_app_lock_status() -> Result<AppLockStatus, String> {
    let cfg = read_app_lock_config()?;
    let (os_auth_available, os_auth_method) = os_auth_status();
    Ok(AppLockStatus {
        enabled: cfg.enabled && cfg.password.is_some(),
        lock_on_idle: cfg.lock_on_idle,
        idle_minutes: cfg.idle_minutes,
        lock_on_close: cfg.lock_on_close,
        prefer_os_auth: cfg.prefer_os_auth,
        has_password: cfg.password.is_some(),
        os_auth_available,
        os_auth_method,
    })
}

#[tauri::command]
fn set_app_lock_config(
    enabled: bool,
    lock_on_idle: bool,
    idle_minutes: u16,
    lock_on_close: bool,
    prefer_os_auth: bool,
) -> Result<AppLockStatus, String> {
    let mut cfg = read_app_lock_config()?;
    cfg.lock_on_idle = lock_on_idle;
    cfg.idle_minutes = normalize_idle_minutes(idle_minutes);
    cfg.lock_on_close = lock_on_close;
    cfg.prefer_os_auth = prefer_os_auth;
    if enabled && cfg.password.is_none() {
        return Err("Set a password before enabling app lock.".to_owned());
    }
    cfg.enabled = enabled;
    write_app_lock_config(&cfg)?;
    get_app_lock_status()
}

#[tauri::command]
fn set_app_lock_password(
    password: String,
    current_password: Option<String>,
) -> Result<AppLockStatus, String> {
    let mut password = password;
    if password.len() < 8 {
        password.zeroize();
        return Err("Password must be at least 8 characters.".to_owned());
    }
    let mut cfg = read_app_lock_config()?;
    if let Some(verifier) = &cfg.password {
        let Some(mut current) = current_password else {
            password.zeroize();
            return Err("Current password is required to change the password.".to_owned());
        };
        let ok = verify_password(&current, verifier)?;
        current.zeroize();
        if !ok {
            password.zeroize();
            return Err("Current password is incorrect.".to_owned());
        }
    }
    let verifier = hash_password(&password)?;
    password.zeroize();
    cfg.password = Some(verifier);
    // Do not auto-enable; user explicitly enables after setting password.
    write_app_lock_config(&cfg)?;
    get_app_lock_status()
}

#[tauri::command]
fn remove_app_lock_password(current_password: String) -> Result<AppLockStatus, String> {
    let mut current_password = current_password;
    let mut cfg = read_app_lock_config()?;
    let Some(verifier) = &cfg.password else {
        current_password.zeroize();
        return Err("No password is set.".to_owned());
    };
    let ok = verify_password(&current_password, verifier)?;
    current_password.zeroize();
    if !ok {
        return Err("Current password is incorrect.".to_owned());
    }
    cfg.password = None;
    cfg.enabled = false;
    write_app_lock_config(&cfg)?;
    get_app_lock_status()
}

#[tauri::command]
fn unlock_app_lock(password: Option<String>, use_os_auth: Option<bool>) -> Result<Value, String> {
    let cfg = read_app_lock_config()?;
    if !cfg.enabled || cfg.password.is_none() {
        return Ok(json!({ "ok": true, "locked": false }));
    }
    let (os_auth_available, os_auth_method) = os_auth_status();
    let try_os = use_os_auth.unwrap_or(false) || (cfg.prefer_os_auth && password.is_none());
    if try_os && os_auth_available {
        // Placeholder for native OS auth integration.
        let _ = os_auth_method;
    }
    if try_os && !os_auth_available && password.is_none() {
        return Ok(json!({
            "ok": false,
            "locked": true,
            "error": format!("OS authentication is unavailable ({os_auth_method}). Enter your password."),
            "os_auth_unavailable": true
        }));
    }
    let Some(mut password) = password else {
        return Ok(json!({ "ok": false, "locked": true, "error": "Password required." }));
    };
    let Some(verifier) = &cfg.password else {
        password.zeroize();
        return Ok(json!({ "ok": true, "locked": false }));
    };
    let ok = verify_password(&password, verifier)?;
    password.zeroize();
    if ok {
        Ok(json!({ "ok": true, "locked": false }))
    } else {
        Ok(json!({ "ok": false, "locked": true, "error": "Incorrect password." }))
    }
}

async fn watch_daemon(
    handle: AppHandle,
    daemon_socket: PathBuf,
    mut commands: mpsc::Receiver<IpcCommand>,
) {
    let mut last_spawn_attempt: Option<Instant> = None;
    let mut connect_pending = false;
    loop {
        match connect_once(&handle, &daemon_socket, &mut commands, &mut connect_pending).await {
            Ok(()) => {}
            Err(error) if error == "desktop command channel closed" => return,
            Err(error) => {
                let should_spawn = connect_pending
                    || last_spawn_attempt
                        .map(|t| t.elapsed() >= Duration::from_secs(10))
                        .unwrap_or(true);
                if should_spawn {
                    last_spawn_attempt = Some(Instant::now());
                    match spawn_daemon(&daemon_socket) {
                        Ok(path) => {
                            emit(
                                &handle,
                                "event",
                                json!({
                                    "method": "ui.daemon_spawn",
                                    "params": { "path": path, "socket": daemon_socket.display().to_string() }
                                }),
                            );
                            emit(
                                &handle,
                                "unreachable",
                                json!({ "error": format!("Starting tobrod ({}). {error}", daemon_socket.display()) }),
                            );
                        }
                        Err(spawn_error) => {
                            connect_pending = false;
                            let msg = format!(
                                "tobrod is not reachable: {error}. Automatic start failed: {spawn_error}. \
                                 You can set TOBROD_PATH or run `tobrod run --socket {}`.",
                                daemon_socket.display()
                            );
                            maybe_notify(
                                &handle,
                                "unreachable:spawn_failed",
                                "Tobro: Could not start daemon",
                                &msg,
                            );
                            emit(&handle, "unreachable", json!({ "error": msg }));
                        }
                    }
                } else {
                    let msg = format!("{} ({})", error, daemon_socket.display());
                    maybe_notify(
                        &handle,
                        format!("unreachable:{msg}"),
                        "Tobro: Daemon unavailable",
                        &msg,
                    );
                    emit(&handle, "unreachable", json!({ "error": msg }));
                }
            }
        }
        // Handle commands while disconnected. "Connect" starts the daemon and
        // requests Tor connect once IPC is available (Orbot-style single button).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, commands.recv()).await {
                Ok(Some(IpcCommand::Connect(tx))) => {
                    connect_pending = true;
                    let should_spawn = last_spawn_attempt
                        .map(|t| t.elapsed() >= Duration::from_secs(2))
                        .unwrap_or(true);
                    let mut note = "connecting (starting local daemon if needed)...".to_owned();
                    if should_spawn {
                        last_spawn_attempt = Some(Instant::now());
                        if let Err(spawn_error) = spawn_daemon(&daemon_socket) {
                            connect_pending = false;
                            let _ = tx.send(Err(format!(
                                "could not start tobrod: {spawn_error}. Set TOBROD_PATH or run `tobrod run --socket {}`.",
                                daemon_socket.display()
                            )));
                            continue;
                        }
                        note = "starting tobrod and connecting...".to_owned();
                    }
                    let _ = tx.send(Ok(
                        json!({ "ok": true, "action": "connect", "status": note }),
                    ));
                }
                Ok(Some(cmd)) => reject_command(cmd, "tobrod is not reachable"),
                Ok(None) => return,
                Err(_) => break,
            }
        }
    }
}

fn spawn_daemon(socket: &Path) -> Result<String, String> {
    let tobrod = find_tobrod_binary()?;
    let mut cmd = Command::new(&tobrod);
    cmd.arg("run").arg("--socket").arg(socket);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.spawn()
        .map_err(|e| format!("failed to start {}: {e}", tobrod.display()))?;
    Ok(tobrod.display().to_string())
}

fn find_tobrod_binary() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("TOBROD_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "TOBROD_PATH is set but not a file: {}",
            path.display()
        ));
    }

    let exe_name = if cfg!(windows) {
        "tobrod.exe"
    } else {
        "tobrod"
    };
    if let Ok(current) = std::env::current_exe()
        && let Some(dir) = current.parent()
    {
        let candidates = [
            dir.join(exe_name),
            dir.join("binaries").join(exe_name),
            dir.join("../").join(exe_name),
            dir.join("../Resources").join(exe_name),
            dir.join("../Resources/binaries").join(exe_name),
            dir.join("../resources").join(exe_name),
            dir.join("../lib/tobro").join(exe_name),
        ];
        for candidate in candidates {
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    // Fallback: rely on PATH (useful in dev environments).
    Ok(PathBuf::from(exe_name))
}

fn reject_command(cmd: IpcCommand, message: &str) {
    let err = Err(message.to_owned());
    match cmd {
        IpcCommand::Connect(tx)
        | IpcCommand::Stop(tx)
        | IpcCommand::NewIdentity(tx)
        | IpcCommand::ConfigGet(tx)
        | IpcCommand::OnionList(tx)
        | IpcCommand::ClientAuthList(tx) => {
            let _ = tx.send(err);
        }
        IpcCommand::ConfigValidate { reply, .. }
        | IpcCommand::ConfigApply { reply, .. }
        | IpcCommand::BridgesTest { reply, .. }
        | IpcCommand::OnionCreate { reply, .. }
        | IpcCommand::OnionUpdate { reply, .. }
        | IpcCommand::OnionDelete { reply, .. }
        | IpcCommand::OnionBackup { reply, .. }
        | IpcCommand::OnionRestore { reply, .. }
        | IpcCommand::ClientAuthGenerate { reply, .. }
        | IpcCommand::ClientAuthImport { reply, .. }
        | IpcCommand::ClientAuthExport { reply, .. }
        | IpcCommand::ClientAuthDelete { reply, .. }
        | IpcCommand::ClientAuthAttach { reply, .. }
        | IpcCommand::ClientAuthDetach { reply, .. } => {
            let _ = reply.send(err);
        }
    }
}

async fn connect_once(
    handle: &AppHandle,
    daemon_socket: &Path,
    commands: &mut mpsc::Receiver<IpcCommand>,
    connect_pending: &mut bool,
) -> Result<(), String> {
    let mut client = Client::connect(daemon_socket)
        .await
        .map_err(|e| e.to_string())?;
    emit(handle, "reachable", json!({ "socket": daemon_socket }));
    client.handshake().await.map_err(|e| e.to_string())?;
    refresh_status(handle, &mut client).await;

    if *connect_pending {
        *connect_pending = false;
        match client.call(methods::CONNECT, None).await {
            Ok(result) => emit(
                handle,
                "event",
                json!({ "method": "ui.auto_connect", "params": result }),
            ),
            Err(error) => emit(
                handle,
                "event",
                json!({ "method": "ui.auto_connect_error", "params": { "error": error.to_string() } }),
            ),
        }
        refresh_status(handle, &mut client).await;
    }

    loop {
        tokio::select! {
            cmd = commands.recv() => {
                let Some(cmd) = cmd else { return Err("desktop command channel closed".to_owned()); };
                handle_command(handle, &mut client, cmd).await;
            }
            message = client.next_message() => {
                match message {
                    Ok(Some(Message::Notification(notification))) => {
                        emit(
                            handle,
                            "event",
                            json!({
                                "method": notification.method,
                                "params": notification.params,
                            }),
                        );
                        refresh_status(handle, &mut client).await;
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => return Err("daemon connection closed".to_owned()),
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
    }
}

async fn handle_command(handle: &AppHandle, client: &mut Client, cmd: IpcCommand) {
    match cmd {
        IpcCommand::Connect(tx) => {
            let result = client
                .call(methods::CONNECT, None)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
            refresh_status(handle, client).await;
        }
        IpcCommand::Stop(tx) => {
            let result = client
                .call(methods::STOP, None)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
            refresh_status(handle, client).await;
        }
        IpcCommand::NewIdentity(tx) => {
            let result = client
                .call(methods::NEW_IDENTITY, None)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
            refresh_status(handle, client).await;
        }
        IpcCommand::ConfigGet(tx) => {
            let result = client
                .call(methods::CONFIG_GET, None)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
        }
        IpcCommand::ConfigValidate { patch, reply } => {
            let result = client
                .call(methods::CONFIG_VALIDATE, Some(json!({ "patch": patch })))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
        }
        IpcCommand::ConfigApply { patch, reply } => {
            let result = client
                .call(methods::CONFIG_APPLY, Some(json!({ "patch": patch })))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
            refresh_status(handle, client).await;
        }
        IpcCommand::BridgesTest { params, reply } => {
            let result = client
                .call(methods::BRIDGES_TEST, Some(params))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
        }
        IpcCommand::OnionList(tx) => {
            let result = client
                .call(methods::ONION_LIST, None)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
        }
        IpcCommand::OnionCreate { params, reply } => {
            let result = client
                .call(methods::ONION_CREATE, Some(params))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
        }
        IpcCommand::OnionUpdate { params, reply } => {
            let result = client
                .call(methods::ONION_UPDATE, Some(params))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
        }
        IpcCommand::OnionDelete { params, reply } => {
            let result = client
                .call(methods::ONION_DELETE, Some(params))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
        }
        IpcCommand::OnionBackup { params, reply } => {
            let result = client
                .call(methods::ONION_BACKUP, Some(params))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
        }
        IpcCommand::OnionRestore { params, reply } => {
            let result = client
                .call(methods::ONION_RESTORE, Some(params))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
        }
        IpcCommand::ClientAuthList(tx) => {
            let result = client
                .call(methods::CLIENT_AUTH_LIST, None)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
        }
        IpcCommand::ClientAuthGenerate { params, reply } => {
            let result = client
                .call(methods::CLIENT_AUTH_GENERATE, Some(params))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
        }
        IpcCommand::ClientAuthImport { params, reply } => {
            let result = client
                .call(methods::CLIENT_AUTH_IMPORT, Some(params))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
        }
        IpcCommand::ClientAuthExport { params, reply } => {
            let result = client
                .call(methods::CLIENT_AUTH_EXPORT, Some(params))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
        }
        IpcCommand::ClientAuthDelete { params, reply } => {
            let result = client
                .call(methods::CLIENT_AUTH_DELETE, Some(params))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
        }
        IpcCommand::ClientAuthAttach { params, reply } => {
            let result = client
                .call(methods::CLIENT_AUTH_ATTACH, Some(params))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
        }
        IpcCommand::ClientAuthDetach { params, reply } => {
            let result = client
                .call(methods::CLIENT_AUTH_DETACH, Some(params))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
        }
    }
}

async fn refresh_status(handle: &AppHandle, client: &mut Client) {
    let previous = handle.state::<AppState>().get_status();
    match client.call(methods::STATUS, None).await {
        Ok(value) => {
            let parsed = serde_json::from_value::<DaemonStatus>(value.clone()).ok();
            notify_status_transition(handle, previous.as_ref(), parsed.as_ref(), None);
            update_tray_menu(handle, true, parsed.as_ref());
            if let Some(status) = parsed {
                handle.state::<AppState>().set_status(status);
            }
            emit(handle, "status", value);
        }
        Err(error) => {
            let err = error.to_string();
            notify_status_transition(handle, previous.as_ref(), None, Some(&err));
            update_tray_menu(handle, false, None);
            emit(handle, "status", Value::Null);
            emit(handle, "unreachable", json!({ "error": err }));
        }
    }
}
