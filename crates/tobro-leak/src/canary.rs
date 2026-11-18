//! The fake daemon the helper's routing engine forwards tunnel traffic to.
//!
//! A real leak test needs a destination-side observer that is *only*
//! reachable through the tunnel. The fake daemon is that observer: its
//! SOCKS5 listener records every destination the engine dials, and its DNS
//! listeners echo intercepted queries. Nothing here touches the physical
//! network: both listeners are loopback-only, matching the helper's
//! forwarding validation.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

/// A running fake daemon. Drop (or call [`FakeDaemon::stop`]) to close the
/// listeners; every accepted connection ends with the listener.
#[derive(Debug)]
pub struct FakeDaemon {
    socks: SocketAddr,
    dns_v4: SocketAddr,
    dns_v6: Option<SocketAddr>,
    socks_destinations: Arc<Mutex<Vec<String>>>,
    socks_bytes: Arc<AtomicU64>,
    dns_v4_queries: Arc<AtomicU64>,
    dns_v6_queries: Arc<AtomicU64>,
    tasks: Vec<JoinHandle<()>>,
}

impl FakeDaemon {
    /// Start the SOCKS5 and DNS observers on loopback.
    pub async fn start() -> Result<Self> {
        let socks_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("could not bind the fake SOCKS listener")?;
        let socks = socks_listener
            .local_addr()
            .context("the fake SOCKS listener has no address")?;
        let dns_v4_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .context("could not bind the fake DNS (v4) listener")?;
        let dns_v4 = dns_v4_socket
            .local_addr()
            .context("the fake DNS (v4) listener has no address")?;
        // IPv6 loopback is optional: hosts with IPv6 disabled still run the
        // IPv4 scenarios.
        let dns_v6_socket = UdpSocket::bind("[::1]:0").await.ok();
        let dns_v6 = dns_v6_socket
            .as_ref()
            .and_then(|socket| socket.local_addr().ok());

        let socks_destinations: Arc<Mutex<Vec<String>>> = Arc::default();
        let socks_bytes = Arc::new(AtomicU64::new(0));
        let dns_v4_queries = Arc::new(AtomicU64::new(0));
        let dns_v6_queries = Arc::new(AtomicU64::new(0));

        let mut tasks = Vec::new();

        let destinations = Arc::clone(&socks_destinations);
        let bytes = Arc::clone(&socks_bytes);
        tasks.push(tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = socks_listener.accept().await else {
                    return;
                };
                let destinations = Arc::clone(&destinations);
                let bytes = Arc::clone(&bytes);
                tokio::spawn(async move {
                    let _ = serve_socks(stream, destinations, bytes).await;
                });
            }
        }));

        tasks.push(tokio::spawn(dns_loop(
            dns_v4_socket,
            Arc::clone(&dns_v4_queries),
        )));
        if let Some(socket) = dns_v6_socket {
            tasks.push(tokio::spawn(dns_loop(socket, Arc::clone(&dns_v6_queries))));
        }

        Ok(Self {
            socks,
            dns_v4,
            dns_v6,
            socks_destinations,
            socks_bytes,
            dns_v4_queries,
            dns_v6_queries,
            tasks,
        })
    }

    /// The SOCKS5 forwarding endpoint.
    pub fn socks(&self) -> SocketAddr {
        self.socks
    }

    /// The DNS forwarding endpoint, by family.
    pub fn dns(&self, ipv6: bool) -> Option<SocketAddr> {
        if ipv6 { self.dns_v6 } else { Some(self.dns_v4) }
    }

    /// The IPv4 DNS forwarding endpoint (always present).
    pub fn dns_v4(&self) -> SocketAddr {
        self.dns_v4
    }

    /// Destinations the engine dialed, in order (`ip:port`).
    pub fn socks_destinations(&self) -> Vec<String> {
        self.socks_destinations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Payload bytes echoed over forwarded TCP flows.
    pub fn socks_bytes(&self) -> u64 {
        self.socks_bytes.load(Ordering::Relaxed)
    }

    /// Intercepted DNS queries observed by family.
    pub fn dns_queries(&self, ipv6: bool) -> u64 {
        if ipv6 {
            self.dns_v6_queries.load(Ordering::Relaxed)
        } else {
            self.dns_v4_queries.load(Ordering::Relaxed)
        }
    }

    /// Stop accepting/answering. Idempotent.
    pub fn stop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

impl Drop for FakeDaemon {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Serve one SOCKS5 connection: greet, parse CONNECT, echo the payload.
async fn serve_socks(
    mut stream: TcpStream,
    destinations: Arc<Mutex<Vec<String>>>,
    bytes: Arc<AtomicU64>,
) -> Result<()> {
    let mut greeting = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut greeting))
        .await
        .context("the SOCKS greeting timed out")??;
    if greeting[0] != 0x05 {
        bail!("the client did not speak SOCKS5");
    }
    let mut methods = vec![0u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 || header[1] != 0x01 {
        bail!("the client did not send a SOCKS5 CONNECT");
    }
    let destination = match header[3] {
        0x01 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            format!(
                "{}.{}.{}.{}:{}",
                address[0],
                address[1],
                address[2],
                address[3],
                u16::from_be_bytes(port)
            )
        }
        0x04 => {
            let mut address = [0u8; 16];
            stream.read_exact(&mut address).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let ip = IpAddr::from(address);
            format!("{ip}:{}", u16::from_be_bytes(port))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut name).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            format!(
                "{}:{}",
                String::from_utf8_lossy(&name),
                u16::from_be_bytes(port)
            )
        }
        other => bail!("unknown SOCKS5 address type {other}"),
    };
    destinations
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(destination);

    // A successful reply with a dummy bound address.
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 1])
        .await?;

    let mut buffer = vec![0u8; 8192];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        bytes.fetch_add(read as u64, Ordering::Relaxed);
        stream.write_all(&buffer[..read]).await?;
    }
}

/// Echo every DNS datagram, so the engine's spoofed reply carries the query
/// bytes back to the client.
async fn dns_loop(socket: UdpSocket, queries: Arc<AtomicU64>) {
    let mut buffer = vec![0u8; 4096];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut buffer).await else {
            return;
        };
        queries.fetch_add(1, Ordering::Relaxed);
        let _ = socket.send_to(&buffer[..len], peer).await;
    }
}
