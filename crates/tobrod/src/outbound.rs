//! Outbound proxy resolution and Shadowsocks (`sslocal`) sidecar management (F-18/F-19).

use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, bail};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;

use tobro_config::{OutboundProxyConfig, OutboundProxyType};
use tobro_tor::adapter::OutboundProxySettings;

use crate::pt_supervisor;
use crate::redact::redact_secrets;

/// Running `sslocal` sidecar for Shadowsocks outbound.
#[derive(Debug)]
pub struct SslocalHandle {
    local_addr: SocketAddr,
    child: Option<Child>,
    kill_tx: Option<oneshot::Sender<()>>,
    _wait: Option<tokio::task::JoinHandle<()>>,
}

impl SslocalHandle {
    /// Local SOCKS5 endpoint Arti should use as its outbound proxy.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Effective outbound proxy settings for Arti.
    pub fn outbound_settings(&self) -> anyhow::Result<OutboundProxySettings> {
        OutboundProxySettings::shadowsocks_local(self.local_addr)
    }

    /// Stop the sidecar.
    pub async fn stop(mut self) {
        if let Some(tx) = self.kill_tx.take() {
            let _ = tx.send(());
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
        }
        if let Some(wait) = self._wait.take() {
            let _ = tokio::time::timeout(Duration::from_secs(3), wait).await;
        }
    }
}

impl Drop for SslocalHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.kill_tx.take() {
            let _ = tx.send(());
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
        if let Some(wait) = self._wait.take() {
            wait.abort();
        }
    }
}

/// Resolve an outbound proxy that can be determined from config alone (HTTP/SOCKS/direct).
///
/// For Shadowsocks, returns `direct()` as a placeholder; use
/// [`start_sslocal_and_resolve`] at connect time to start the sidecar and get
/// the effective local endpoint.
pub fn resolve_static_outbound_proxy(
    cfg: &OutboundProxyConfig,
) -> Result<OutboundProxySettings, String> {
    if !cfg.is_active() || cfg.proxy_type == OutboundProxyType::None {
        return Ok(OutboundProxySettings::direct());
    }
    if cfg.proxy_type == OutboundProxyType::Shadowsocks {
        // Effective endpoint is resolved when sslocal is started at connect time.
        return Ok(OutboundProxySettings::direct());
    }
    let host = cfg.normalized_host();
    let ip: IpAddr = host.parse().map_err(|_| {
        format!(
            "outbound_proxy.host must be an IP address for HTTP/SOCKS outbound proxies (got {host:?})"
        )
    })?;
    let addr = SocketAddr::new(ip, cfg.port);
    match cfg.normalized_proxy_type() {
        OutboundProxyType::Http | OutboundProxyType::Https => {
            OutboundProxySettings::http(addr, cfg.username.clone(), cfg.password.clone())
                .map_err(|e| e.to_string())
        }
        OutboundProxyType::Socks4 => {
            OutboundProxySettings::socks(4, addr, cfg.username.clone(), String::new())
                .map_err(|e| e.to_string())
        }
        OutboundProxyType::Socks5 => {
            OutboundProxySettings::socks(5, addr, cfg.username.clone(), cfg.password.clone())
                .map_err(|e| e.to_string())
        }
        OutboundProxyType::None | OutboundProxyType::Shadowsocks => {
            Ok(OutboundProxySettings::direct())
        }
    }
}

/// Start `sslocal` and return a handle whose local SOCKS endpoint can be used as
/// Arti's outbound proxy.
pub async fn start_sslocal_and_resolve(
    cfg: &OutboundProxyConfig,
    state_dir: Option<&Path>,
) -> anyhow::Result<SslocalHandle> {
    if cfg.proxy_type != OutboundProxyType::Shadowsocks {
        bail!("outbound proxy type is not Shadowsocks");
    }
    cfg.validate()
        .map_err(|e| anyhow::anyhow!("invalid Shadowsocks outbound config: {e}"))?;

    let program = locate_sslocal(cfg, state_dir)?;
    let local_port = reserve_local_port().context("could not reserve a local port for sslocal")?;
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_port);

    let server = format!("{}:{}", cfg.normalized_host(), cfg.port);
    let method = cfg.shadowsocks_method.trim();
    let password = cfg.effective_shadowsocks_password();

    // Try shadowsocks-rust style args first; keep command construction explicit.
    // `--local-addr` binds a local SOCKS5 server; `--server-addr` is the remote.
    let mut cmd = Command::new(&program);
    cmd.arg("--local-addr")
        .arg(local_addr.to_string())
        .arg("--server-addr")
        .arg(&server)
        .arg("--encrypt-method")
        .arg(method)
        .arg("--password")
        .arg(password)
        .arg("--tcp-no-delay")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }

    tracing::info!(
        program = %program.display(),
        %local_addr,
        server = %server,
        method = %method,
        "starting sslocal for Shadowsocks outbound proxy"
    );

    let mut child = cmd.spawn().with_context(|| {
        format!(
            "failed to start sslocal at {} (configure outbound_proxy.sslocal_path/sslocal_dir or install shadowsocks-rust)",
            program.display()
        )
    })?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (kill_tx, mut kill_rx) = oneshot::channel::<()>();

    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    if let Some(out) = stdout {
        let tx = log_tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(out).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = tx.send(line);
            }
        });
    }
    if let Some(err) = stderr {
        let tx = log_tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = tx.send(line);
            }
        });
    }
    drop(log_tx);

    let wait = tokio::spawn(async move {
        tokio::select! {
            _ = &mut kill_rx => {
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
            _ = child.wait() => {}
        }
    });

    // Wait for the local SOCKS port to accept connections.
    let ready = wait_for_local_port(local_addr, Duration::from_secs(10), &mut log_rx).await;
    match ready {
        Ok(()) => {
            tracing::info!(%local_addr, "sslocal is ready");
            Ok(SslocalHandle {
                local_addr,
                child: None, // owned by wait task
                kill_tx: Some(kill_tx),
                _wait: Some(wait),
            })
        }
        Err(e) => {
            let _ = kill_tx.send(());
            let _ = tokio::time::timeout(Duration::from_secs(2), wait).await;
            // Drain a few log lines for diagnostics (redacted).
            let mut logs = Vec::new();
            while let Ok(line) = log_rx.try_recv() {
                logs.push(redact_secrets(&line));
                if logs.len() >= 8 {
                    break;
                }
            }
            if logs.is_empty() {
                Err(e)
            } else {
                Err(e.context(format!("sslocal output (redacted): {}", logs.join(" | "))))
            }
        }
    }
}

async fn wait_for_local_port(
    addr: SocketAddr,
    timeout: Duration,
    log_rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            bail!("timed out waiting for sslocal to listen on {addr}");
        }
        // Drain logs (best-effort; no secrets should appear, but callers redact).
        while log_rx.try_recv().is_ok() {}
        match tokio::net::TcpStream::connect(addr).await {
            Ok(_stream) => return Ok(()),
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

fn reserve_local_port() -> anyhow::Result<u16> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .context("bind ephemeral localhost port")?;
    Ok(listener.local_addr()?.port())
}

fn locate_sslocal(
    cfg: &OutboundProxyConfig,
    state_dir: Option<&Path>,
) -> anyhow::Result<std::path::PathBuf> {
    let mut search_dirs = Vec::new();
    if let Some(d) = cfg.sslocal_dir.as_deref() {
        search_dirs.push(std::path::PathBuf::from(d));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            search_dirs.push(dir.to_path_buf());
            search_dirs.push(dir.join("binaries"));
            search_dirs.push(dir.join("../Resources"));
            search_dirs.push(dir.join("../Resources/binaries"));
        }
    }
    if let Some(sd) = state_dir {
        search_dirs.push(sd.join("pt"));
        search_dirs.push(sd.join("sidecars"));
    }
    let opts = pt_supervisor::LocateOptions {
        explicit_path: cfg.sslocal_path.as_ref().map(std::path::PathBuf::from),
        search_dirs,
        names: vec![OsString::from("sslocal"), OsString::from("sslocal.exe")],
    };
    pt_supervisor::locate(&opts)
        .map(|f| f.path)
        .context("could not locate sslocal for Shadowsocks outbound proxy (set outbound_proxy.sslocal_path/sslocal_dir or install shadowsocks-rust)")
}
