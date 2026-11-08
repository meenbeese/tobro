//! Tauri desktop shell for tobro (M1).
//!
//! Owns a single IPC connection to `tobrod`, relays daemon events to the
//! React webview, exposes connect/stop commands, and provides a tray icon
//! with quit-to-tray behavior.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{Value, json};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tokio::sync::{mpsc, oneshot};

use tobro_ipc::{Client, DaemonStatus, Message, methods, socket_path};

#[derive(Debug)]
enum IpcCommand {
    Connect(oneshot::Sender<Result<Value, String>>),
    Stop(oneshot::Sender<Result<Value, String>>),
    NewIdentity(oneshot::Sender<Result<Value, String>>),
    ConfigGet(oneshot::Sender<Result<Value, String>>),
    ConfigApply {
        patch: Value,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    ReloadConfig(oneshot::Sender<Result<Value, String>>),
}

#[derive(Debug)]
struct AppState {
    latest: Mutex<Option<DaemonStatus>>,
    commands: mpsc::Sender<IpcCommand>,
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ProxyPorts {
    socks_port: u16,
    http_port: u16,
    dns_port: u16,
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
        config_path: path.display().to_string(),
    })
}

#[tauri::command]
async fn save_proxy_ports(
    state: State<'_, AppState>,
    socks_port: u16,
    http_port: u16,
    dns_port: u16,
) -> Result<Value, String> {
    let patch = json!({
        "proxy": {
            "socks_port": socks_port,
            "http_port": http_port,
            "dns_port": dns_port
        }
    });

    if let Ok(result) = daemon_apply_config(state, patch.clone()).await {
        let effects = result.get("effects").cloned().unwrap_or_else(|| json!({}));
        let warnings = effects
            .get("warnings")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let apply = if effects.get("runtime_active").and_then(Value::as_bool).unwrap_or(false)
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
                "dns_port": dns_port
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
    config.validate().map_err(|e| e.to_string())?;
    config.save(&path).map_err(|e| e.to_string())?;
    Ok(json!({
        "ok": true,
        "config_path": path.display().to_string(),
        "proxy": {
            "socks_port": config.proxy.socks_port,
            "http_port": config.proxy.effective_http_port(),
            "dns_port": config.proxy.dns_port,
        },
        "reload": { "apply": "saved to config; daemon was unreachable, so it was not reloaded", "warnings": [] },
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
        .manage(AppState {
            latest: Mutex::new(None),
            commands: command_tx,
        })
        .setup(move |app| {
            setup_tray(app.handle())?;
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
            daemon_connect,
            daemon_stop,
            daemon_new_identity,
            daemon_get_config,
            daemon_apply_config,
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

fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Show tobro", true, None::<&str>)?;
    let hide = MenuItem::with_id(app, "hide", "Hide", true, None::<&str>)?;
    let connect = MenuItem::with_id(app, "connect", "Connect", true, None::<&str>)?;
    let stop = MenuItem::with_id(app, "stop", "Stop", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &hide, &connect, &stop, &sep, &quit])?;

    let mut builder = TrayIconBuilder::with_id("main-tray")
        .menu(&menu)
        .tooltip("tobro")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main_window(app),
            "hide" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            "connect" => dispatch_tray_command(app, IpcCommandKind::Connect),
            "stop" => dispatch_tray_command(app, IpcCommandKind::Stop),
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
}

fn dispatch_tray_command(app: &AppHandle, kind: IpcCommandKind) {
    let sender = app.state::<AppState>().commands.clone();
    tauri::async_runtime::spawn(async move {
        let (tx, rx) = oneshot::channel();
        let cmd = match kind {
            IpcCommandKind::Connect => IpcCommand::Connect(tx),
            IpcCommandKind::Stop => IpcCommand::Stop(tx),
        };
        if sender.send(cmd).await.is_ok() {
            let _ = rx.await;
        }
    });
}

async fn watch_daemon(
    handle: AppHandle,
    daemon_socket: PathBuf,
    mut commands: mpsc::Receiver<IpcCommand>,
) {
    loop {
        if let Err(error) = connect_once(&handle, &daemon_socket, &mut commands).await {
            emit(
                &handle,
                "unreachable",
                json!({ "error": format!("{} ({})", error, daemon_socket.display()) }),
            );
        }
        // Drain commands while disconnected so callers don't hang forever.
        while let Ok(cmd) = commands.try_recv() {
            reject_command(cmd, "tobrod is not reachable");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

fn reject_command(cmd: IpcCommand, message: &str) {
    let err = Err(message.to_owned());
    match cmd {
        IpcCommand::Connect(tx)
        | IpcCommand::Stop(tx)
        | IpcCommand::NewIdentity(tx)
        | IpcCommand::ConfigGet(tx)
        | IpcCommand::ReloadConfig(tx) => {
            let _ = tx.send(err);
        }
        IpcCommand::ConfigApply { reply, .. } => {
            let _ = reply.send(err);
        }
    }
}

async fn connect_once(
    handle: &AppHandle,
    daemon_socket: &Path,
    commands: &mut mpsc::Receiver<IpcCommand>,
) -> Result<(), String> {
    let mut client = Client::connect(daemon_socket)
        .await
        .map_err(|e| e.to_string())?;
    emit(handle, "reachable", json!({ "socket": daemon_socket }));
    client.handshake().await.map_err(|e| e.to_string())?;
    refresh_status(handle, &mut client).await;

    loop {
        tokio::select! {
            cmd = commands.recv() => {
                let Some(cmd) = cmd else { return Ok(()); };
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
                    Ok(None) => return Ok(()),
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
        IpcCommand::ConfigApply { patch, reply } => {
            let result = client
                .call(methods::CONFIG_APPLY, Some(json!({ "patch": patch })))
                .await
                .map_err(|e| e.to_string());
            let _ = reply.send(result);
            refresh_status(handle, client).await;
        }
        IpcCommand::ReloadConfig(tx) => {
            let result = client
                .call(methods::RELOAD_CONFIG, None)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
            refresh_status(handle, client).await;
        }
    }
}

async fn refresh_status(handle: &AppHandle, client: &mut Client) {
    match client.call(methods::STATUS, None).await {
        Ok(value) => {
            if let Ok(status) = serde_json::from_value::<DaemonStatus>(value.clone()) {
                handle.state::<AppState>().set_status(status);
            }
            emit(handle, "status", value);
        }
        Err(error) => {
            emit(handle, "status", Value::Null);
            emit(handle, "unreachable", json!({ "error": error.to_string() }));
        }
    }
}
