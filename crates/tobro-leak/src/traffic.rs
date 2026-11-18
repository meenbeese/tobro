//! Client-side traffic generators.
//!
//! These use ordinary host sockets. With the test prefix routed into the
//! TUN device, the kernel hands the packets to the helper's routing engine,
//! which is exactly the path a real application would take. Nothing binds
//! to the TUN device directly: the test would miss routing bugs if it did.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, UdpSocket};

/// Connect over TCP, send `payload`, and read the echoed bytes back.
pub async fn tcp_echo(
    destination: SocketAddr,
    payload: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(destination))
        .await
        .with_context(|| format!("TCP connect to {destination} timed out"))??;
    stream.set_nodelay(true)?;
    tokio::time::timeout(timeout, stream.write_all(payload))
        .await
        .with_context(|| format!("writing to {destination} timed out"))??;
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(timeout, stream.read_exact(&mut echoed))
        .await
        .with_context(|| format!("reading from {destination} timed out"))??;
    Ok(echoed)
}

/// Send one UDP datagram and return the first reply.
///
/// The engine spoofs the reply's source as the original destination; the
/// caller asserts it (see [`dns_echo`]).
pub async fn udp_echo(
    destination: SocketAddr,
    payload: &[u8],
    timeout: Duration,
) -> Result<(Vec<u8>, SocketAddr)> {
    let bind: SocketAddr = if destination.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.send_to(payload, destination).await?;
    let mut buffer = vec![0u8; 4096];
    let (len, from) = tokio::time::timeout(timeout, socket.recv_from(&mut buffer))
        .await
        .with_context(|| format!("no UDP reply from {destination}"))??;
    buffer.truncate(len);
    Ok((buffer, from))
}

/// Send a DNS-shaped datagram to `destination:53` and expect the spoofed
/// echo reply.
pub async fn dns_echo(
    destination: SocketAddr,
    payload: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>> {
    let (reply, from) = udp_echo(destination, payload, timeout).await?;
    if from != destination {
        bail!("the DNS reply came from {from}, expected the spoofed source {destination}");
    }
    Ok(reply)
}

/// Send one UDP datagram and assert that nothing comes back.
///
/// The timeout is the assertion: a non-DNS UDP flow must be dropped by the
/// engine's policy, never forwarded and never answered.
pub async fn udp_silence(destination: SocketAddr, payload: &[u8], timeout: Duration) -> Result<()> {
    let bind: SocketAddr = if destination.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.send_to(payload, destination).await?;
    let mut buffer = vec![0u8; 4096];
    match tokio::time::timeout(timeout, socket.recv_from(&mut buffer)).await {
        Err(_) => Ok(()),
        Ok(Ok((len, from))) => bail!(
            "received {len} byte(s) from {from}; the datagram must have been dropped by policy"
        ),
        Ok(Err(error)) => Err(error.into()),
    }
}
