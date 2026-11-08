//! The M0 Arti feasibility spike.
//!
//! Flow:
//! 1. Bootstrap an observer `TorClient` and stream bootstrap progress.
//! 2. Request a page through Tor to prove the network path works.
//! 3. Drop the observer (it holds the state-directory lock) and start the
//!    serving client on SOCKS/HTTP + DNS.
//! 4. Fetch a page through the local SOCKS listener to prove the listener
//!    serves traffic, then keep serving until shutdown.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use clap::Args;
use serde::Serialize;
use tobro_ipc::DaemonState;
use tobro_tor::{Tor, parse_http_status};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

/// Arguments for `tobrod spike`.
#[derive(Debug, Args)]
pub struct SpikeArgs {
    /// Local SOCKS + HTTP CONNECT port.
    #[arg(long, default_value_t = 9050)]
    pub socks_port: u16,

    /// Local DNS proxy port.
    #[arg(long, default_value_t = 9053)]
    pub dns_port: u16,

    /// Host fetched through Tor for the connectivity checks.
    #[arg(long, default_value = "example.com")]
    pub check_host: String,

    /// Port fetched through Tor for the connectivity checks.
    #[arg(long, default_value_t = 80)]
    pub check_port: u16,

    /// Skip both network checks (bootstrap and serve only).
    #[arg(long)]
    pub no_check: bool,

    /// Exit once the SOCKS listener check finishes (useful for CI).
    #[arg(long)]
    pub exit_after_check: bool,

    /// Timeout for bootstrapping and for the SOCKS listener check.
    #[arg(long, default_value_t = 180)]
    pub timeout_secs: u64,

    /// IPC socket/endpoint path override.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Event {
    Bootstrap {
        percent: u8,
        ready: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        blocked: Option<String>,
        detail: String,
    },
    Bootstrapped {
        elapsed_ms: u64,
    },
    TorCheck {
        target: String,
        status: u16,
        elapsed_ms: u64,
    },
    Serving {
        socks_http: String,
        dns: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ipc_socket: Option<String>,
    },
    SocksCheck {
        target: String,
        status: u16,
        elapsed_ms: u64,
    },
    Error {
        context: String,
        message: String,
    },
}

/// Run the spike until the listener is shut down with Ctrl-C.
pub async fn run(args: SpikeArgs, state_dir: PathBuf, cache_dir: PathBuf) -> anyhow::Result<()> {
    // Start IPC first so clients can watch bootstrap progress.
    let hub = crate::ipc::Hub::new(args.socks_port, args.socks_port, args.dns_port);

    let socket_path = args
        .socket
        .clone()
        .unwrap_or_else(|| tobro_ipc::socket_path(&state_dir));

    match tobro_ipc::Server::bind(&socket_path).await {
        Ok(server) => {
            let hub = Arc::clone(&hub);
            tokio::spawn(async move {
                if let Err(error) = crate::ipc::serve(server, hub).await {
                    eprintln!("tobrod: IPC server stopped: {error:#}");
                }
            });
        }
        Err(error) => {
            eprintln!(
                "tobrod: could not start IPC on {}: {error}",
                socket_path.display()
            );
        }
    }

    let tor = Tor::create(&state_dir, &cache_dir)
        .await
        .context("could not create the Arti client")?;

    let bootstrap = tor.bootstrap(|event| {
        hub.report_bootstrap(
            event.percent,
            event.ready,
            event.blocked.clone(),
            event.detail.clone(),
        );
        emit(&Event::Bootstrap {
            percent: event.percent,
            ready: event.ready,
            blocked: event.blocked,
            detail: event.detail,
        });
    });

    let elapsed = match timeout(Duration::from_secs(args.timeout_secs), bootstrap).await {
        Ok(result) => result.context("Arti bootstrap failed")?,
        Err(_) => anyhow::bail!("Arti bootstrap timed out after {}s", args.timeout_secs),
    };
    emit(&Event::Bootstrapped {
        elapsed_ms: elapsed.as_millis() as u64,
    });

    if !args.no_check {
        let check = tor
            .check_http(&args.check_host, args.check_port, Duration::from_secs(60))
            .await
            .context("the Tor connectivity check failed")?;
        emit(&Event::TorCheck {
            target: check.target,
            status: check.status,
            elapsed_ms: check.elapsed_ms,
        });
    }

    // The serving client needs the state-directory lock, so release the
    // observer first. The consensus stays cached on disk for a fast rebootstrap.
    drop(tor);

    hub.set_state(DaemonState::Serving);

    let ipc_socket = Some(socket_path.display().to_string());

    let socks_addr = SocketAddr::from(([127, 0, 0, 1], args.socks_port));
    emit(&Event::Serving {
        socks_http: socks_addr.to_string(),
        dns: SocketAddr::from(([127, 0, 0, 1], args.dns_port)).to_string(),
        ipc_socket,
    });

    let check = if args.no_check {
        None
    } else {
        let host = args.check_host.clone();
        let port = args.check_port;
        let limit = Duration::from_secs(args.timeout_secs);
        Some(tokio::spawn(async move {
            socks_check_with_retry(socks_addr, &host, port, limit).await
        }))
    };

    let serve = tobro_tor::serve(&state_dir, &cache_dir, args.socks_port, args.dns_port);
    tokio::pin!(serve);

    match check {
        Some(handle) => {
            tokio::select! {
                result = &mut serve => result.context("the Arti listener failed")?,
                joined = handle => {
                    match joined {
                        Ok(Ok((status, elapsed_ms))) => emit(&Event::SocksCheck {
                            target: format!("{}:{}", args.check_host, args.check_port),
                            status,
                            elapsed_ms,
                        }),
                        Ok(Err(error)) => emit(&Event::Error {
                            context: "SOCKS check".to_owned(),
                            message: format!("{error:#}"),
                        }),
                        Err(error) => emit(&Event::Error {
                            context: "SOCKS check task".to_owned(),
                            message: error.to_string(),
                        }),
                    }

                    if args.exit_after_check {
                        return Ok(());
                    }
                    (&mut serve).await.context("the Arti listener failed")?;
                }
            }
        }
        None => {
            (&mut serve).await.context("the Arti listener failed")?;
        }
    }

    Ok(())
}

fn emit(event: &Event) {
    match serde_json::to_string(event) {
        Ok(line) => println!("{line}"),
        Err(error) => eprintln!("tobrod: could not encode event: {error}"),
    }
}

/// Wait for the listener, then retry the SOCKS request a few times.
///
/// A freshly started Arti client may reject the first circuit build while it
/// finishes bootstrapping, so a single failure is not meaningful.
async fn socks_check_with_retry(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    limit: Duration,
) -> anyhow::Result<(u16, u64)> {
    const ATTEMPTS: usize = 4;

    wait_for_listener(proxy, limit).await?;

    let mut last_error = None;
    for attempt in 1..=ATTEMPTS {
        match check_via_socks(proxy, host, port, limit).await {
            Ok(result) => return Ok(result),
            Err(error) => {
                if attempt < ATTEMPTS {
                    eprintln!("tobrod: SOCKS check attempt {attempt} failed: {error:#}; retrying");
                    sleep(Duration::from_secs(2)).await;
                }
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("the SOCKS check failed")))
}

/// Wait until `addr` accepts TCP connections or the deadline passes.
async fn wait_for_listener(addr: SocketAddr, limit: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + limit;
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(error).context("the SOCKS listener never accepted connections");
                }
                sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

/// Fetch `/` through the SOCKS5 listener and return the HTTP status.
async fn check_via_socks(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    limit: Duration,
) -> anyhow::Result<(u16, u64)> {
    let started = Instant::now();
    let mut stream = TcpStream::connect(proxy)
        .await
        .context("could not connect to the SOCKS listener")?;

    // Method negotiation: SOCKS5, no authentication.
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    anyhow::ensure!(
        method == [0x05, 0x00],
        "SOCKS5 method negotiation failed: {method:?}"
    );

    // CONNECT to host:port using a domain name.
    let host_bytes = host.as_bytes();
    anyhow::ensure!(
        !host_bytes.is_empty() && host_bytes.len() <= 255,
        "invalid check host"
    );
    let mut connect = Vec::with_capacity(host_bytes.len() + 7);
    connect.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    connect.extend_from_slice(host_bytes);
    connect.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&connect).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    anyhow::ensure!(reply[0] == 0x05, "unexpected SOCKS version {}", reply[0]);
    anyhow::ensure!(
        reply[1] == 0x00,
        "SOCKS connect rejected with code {}",
        reply[1]
    );
    match reply[3] {
        0x01 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address).await?;
        }
        0x04 => {
            let mut address = [0u8; 16];
            stream.read_exact(&mut address).await?;
        }
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let mut address = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut address).await?;
        }
        other => anyhow::bail!("unsupported SOCKS address type {other}"),
    }

    // The reply ends with a two-byte bound port; leaving it unread would
    // corrupt the HTTP response that follows.
    let mut bound_port = [0u8; 2];
    stream.read_exact(&mut bound_port).await?;

    let request = format!("GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let response = timeout(limit, async {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let mut response = Vec::new();
        (&mut stream)
            .take(64 * 1024)
            .read_to_end(&mut response)
            .await?;
        Ok::<_, std::io::Error>(response)
    })
    .await
    .context("timed out waiting for the SOCKS request")??;

    let status = parse_http_status(&response).with_context(|| {
        let prefix = String::from_utf8_lossy(&response[..response.len().min(120)]);
        format!(
            "no HTTP status line from the SOCKS request ({} bytes: {prefix:?})",
            response.len()
        )
    })?;
    Ok((status, started.elapsed().as_millis() as u64))
}
