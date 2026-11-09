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
use tokio::sync::{mpsc, oneshot};

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
        .manage(AppState {
            latest: Mutex::new(None),
            commands: command_tx,
        })
        .setup(move |app| {
            // Best-effort default: reduce accidental capture exposure until UI syncs preference.
            apply_window_capture_protection(app.handle(), true);
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
            open_external_url,
            set_capture_protection,
            daemon_connect,
            daemon_stop,
            daemon_new_identity,
            daemon_get_config,
            daemon_validate_config,
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
    let _ = tray.status_item.set_text(tray_status_text(reachable, status));
    let state = status.map(|s| &s.state);
    let active = matches!(
        state,
        Some(DaemonState::Starting | DaemonState::Bootstrapping | DaemonState::Connected | DaemonState::Serving)
    );
    let stopping = matches!(state, Some(DaemonState::Stopping));
    let can_connect = !active && !stopping;
    let can_stop = reachable && active && !stopping;
    let can_new_identity = reachable
        && matches!(state, Some(DaemonState::Connected | DaemonState::Serving));
    let _ = tray.connect_item.set_enabled(can_connect);
    let _ = tray.stop_item.set_enabled(can_stop);
    let _ = tray.new_identity_item.set_enabled(can_new_identity);
    if let Some(t) = handle.tray_by_id("main-tray") {
        let _ = t.set_tooltip(Some(&tray_status_text(reachable, status)));
    }
}

fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let status_item = MenuItem::with_id(app, "status", "Status: Starting…", false, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let connect_item = MenuItem::with_id(app, "connect", "Connect", true, None::<&str>)?;
    let stop_item = MenuItem::with_id(app, "stop", "Stop", false, None::<&str>)?;
    let new_identity_item = MenuItem::with_id(app, "new_identity", "New identity", false, None::<&str>)?;
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
                            emit(
                                &handle,
                                "unreachable",
                                json!({
                                    "error": format!(
                                        "tobrod is not reachable: {error}. Automatic start failed: {spawn_error}. \
                                         You can set TOBROD_PATH or run `tobrod run --socket {}`.",
                                        daemon_socket.display()
                                    )
                                }),
                            );
                        }
                    }
                } else {
                    emit(
                        &handle,
                        "unreachable",
                        json!({ "error": format!("{} ({})", error, daemon_socket.display()) }),
                    );
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
        | IpcCommand::ConfigGet(tx) => {
            let _ = tx.send(err);
        }
        IpcCommand::ConfigValidate { reply, .. } | IpcCommand::ConfigApply { reply, .. } => {
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
    }
}

async fn refresh_status(handle: &AppHandle, client: &mut Client) {
    match client.call(methods::STATUS, None).await {
        Ok(value) => {
            let parsed = serde_json::from_value::<DaemonStatus>(value.clone()).ok();
            update_tray_menu(handle, true, parsed.as_ref());
            if let Some(status) = parsed {
                handle.state::<AppState>().set_status(status);
            }
            emit(handle, "status", value);
        }
        Err(error) => {
            update_tray_menu(handle, false, None);
            emit(handle, "status", Value::Null);
            emit(handle, "unreachable", json!({ "error": error.to_string() }));
        }
    }
}
