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
use tokio::net::{TcpStream, UdpSocket};
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

    /// Resolve this hostname through the local DNS proxy (UDP) after serving
    /// starts. Use a `.onion` name for the M2 `.onion` resolution test. The
    /// check is opt-in because it needs Tor to be bootstrapped and a reachable
    /// target; the first DNS query can take several seconds while a circuit is
    /// built.
    #[arg(long)]
    pub dns_check_host: Option<String>,

    /// Exit once the listener checks finish (useful for CI/manual verification).
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
    DnsCheck {
        target: String,
        answers: u16,
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

    let limit = Duration::from_secs(args.timeout_secs);
    let socks_check = if args.no_check {
        None
    } else {
        let host = args.check_host.clone();
        let port = args.check_port;
        Some(tokio::spawn(async move {
            socks_check_with_retry(socks_addr, &host, port, limit).await
        }))
    };
    let dns_addr = SocketAddr::from(([127, 0, 0, 1], args.dns_port));
    let dns_check = args.dns_check_host.as_ref().map(|host| {
        let host = host.clone();
        tokio::spawn(async move { dns_check_with_retry(dns_addr, &host, limit).await })
    });

    let serve = tobro_tor::serve(
        &state_dir,
        &cache_dir,
        args.socks_port,
        args.dns_port,
        false,
        tobro_tor::adapter::StreamIsolationPolicy::default(),
    );
    tokio::pin!(serve);

    if args.exit_after_check && (socks_check.is_some() || dns_check.is_some()) {
        let checks = async {
            if let Some(handle) = socks_check {
                report_socks_check(handle, &args.check_host, args.check_port).await;
            }
            if let Some(handle) = dns_check {
                report_dns_check(handle, args.dns_check_host.as_deref().unwrap_or_default()).await;
            }
        };
        tokio::select! {
            result = &mut serve => result.context("the Arti listener failed")?,
            _ = checks => return Ok(()),
        }
        return Ok(());
    }

    // Long-running mode: report checks in the background while serving.
    if let Some(handle) = socks_check {
        let host = args.check_host.clone();
        let port = args.check_port;
        tokio::spawn(async move { report_socks_check(handle, &host, port).await });
    }
    if let Some(handle) = dns_check {
        let host = args.dns_check_host.clone().unwrap_or_default();
        tokio::spawn(async move { report_dns_check(handle, &host).await });
    }

    (&mut serve).await.context("the Arti listener failed")?;
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

async fn report_socks_check(
    handle: tokio::task::JoinHandle<anyhow::Result<(u16, u64)>>,
    host: &str,
    port: u16,
) {
    match handle.await {
        Ok(Ok((status, elapsed_ms))) => emit(&Event::SocksCheck {
            target: format!("{host}:{port}"),
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
}

/// Retry DNS resolution a few times.
///
/// Arti's DNS proxy is UDP-only and the first query after startup can take
/// several seconds while a circuit is built, so transient failures/timeouts are
/// expected early in a serving session.
async fn dns_check_with_retry(
    resolver: SocketAddr,
    host: &str,
    limit: Duration,
) -> anyhow::Result<(u16, u64)> {
    const ATTEMPTS: usize = 6;
    let per_attempt = (limit / ATTEMPTS as u32).max(Duration::from_secs(10));
    let mut last_error = None;
    for attempt in 1..=ATTEMPTS {
        match check_via_dns(resolver, host, per_attempt).await {
            Ok(result) => return Ok(result),
            Err(error) => {
                if attempt < ATTEMPTS {
                    eprintln!("tobrod: DNS check attempt {attempt} failed: {error:#}; retrying");
                    sleep(Duration::from_secs(2)).await;
                }
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("the DNS check failed")))
}

async fn report_dns_check(handle: tokio::task::JoinHandle<anyhow::Result<(u16, u64)>>, host: &str) {
    match handle.await {
        Ok(Ok((answers, elapsed_ms))) => emit(&Event::DnsCheck {
            target: host.to_owned(),
            answers,
            elapsed_ms,
        }),
        Ok(Err(error)) => emit(&Event::Error {
            context: "DNS check".to_owned(),
            message: format!("{error:#}"),
        }),
        Err(error) => emit(&Event::Error {
            context: "DNS check task".to_owned(),
            message: error.to_string(),
        }),
    }
}

/// Resolve `host` through a local DNS proxy (UDP) and return answer count.
///
/// Sends a minimal A (IN) query and accepts any NOERROR response with at least
/// one answer record. This proves DNS wiring; for `.onion` names it verifies
/// client-side `.onion` resolution through the configured Tor DNS listener.
async fn check_via_dns(
    resolver: SocketAddr,
    host: &str,
    limit: Duration,
) -> anyhow::Result<(u16, u64)> {
    let started = Instant::now();
    let id = 0xB007u16;
    let query = build_dns_a_query(id, host)?;
    let socket = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0u16))
        .await
        .context("could not bind UDP socket for DNS check")?;
    socket
        .connect(resolver)
        .await
        .context("could not target the DNS listener")?;

    let mut buf = [0u8; 1500];
    let answers = timeout(limit, async {
        socket.send(&query).await?;
        let n = socket.recv(&mut buf).await?;
        parse_dns_response(id, &buf[..n])
    })
    .await
    .context("timed out waiting for a DNS response")??;

    Ok((answers, started.elapsed().as_millis() as u64))
}

fn build_dns_a_query(id: u16, host: &str) -> anyhow::Result<Vec<u8>> {
    let host = host.trim_end_matches('.');
    anyhow::ensure!(!host.is_empty(), "DNS check host must not be empty");
    let mut out = Vec::with_capacity(host.len() + 18);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00]); // RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in host.split('.') {
        anyhow::ensure!(
            !label.is_empty() && label.len() <= 63,
            "invalid DNS label in {host:?}"
        );
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    Ok(out)
}

fn parse_dns_response(expected_id: u16, packet: &[u8]) -> anyhow::Result<u16> {
    anyhow::ensure!(
        packet.len() >= 12,
        "short DNS response ({} bytes)",
        packet.len()
    );
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    anyhow::ensure!(
        id == expected_id,
        "DNS response id {id:#06x} did not match query"
    );
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    anyhow::ensure!(flags & 0x8000 != 0, "DNS packet was not a response");
    let rcode = flags & 0x000F;
    anyhow::ensure!(rcode == 0, "DNS response returned error rcode {rcode}");
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    anyhow::ensure!(ancount > 0, "DNS response contained no answer records");
    Ok(ancount)
}

#[cfg(test)]
mod tests {
    use super::{build_dns_a_query, parse_dns_response};

    #[test]
    fn builds_dns_a_query_for_onion() -> Result<(), Box<dyn std::error::Error>> {
        let packet = build_dns_a_query(
            0x1234,
            "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
        )?;
        assert_eq!(&packet[0..2], &0x1234u16.to_be_bytes());
        assert!(packet.windows("onion".len()).any(|w| w == b"onion"));
        assert_eq!(&packet[packet.len() - 4..], &[0, 1, 0, 1]);
        Ok(())
    }

    #[test]
    fn parses_noerror_dns_response() -> Result<(), Box<dyn std::error::Error>> {
        // Minimal header: id, QR+RD+RA+NOERROR, qd=1, an=2
        let packet = [0xB0, 0x07, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0, 0, 0, 0];
        assert_eq!(parse_dns_response(0xB007, &packet)?, 2);
        Ok(())
    }

    #[test]
    fn rejects_dns_error_response() {
        let packet = [0xB0, 0x07, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0]; // NXDOMAIN
        assert!(parse_dns_response(0xB007, &packet).is_err());
    }
}
