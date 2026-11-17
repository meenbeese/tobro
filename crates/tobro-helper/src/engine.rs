//! The TUN routing engine (M7, plan §4.7).
//!
//! The engine turns the packets the privileged helper reads from the TUN
//! device into Tor-proxied connections. It runs *inside* the helper (which
//! owns the device), never in the daemon, and it only ever talks to the
//! unprivileged daemon's loopback listeners — the helper itself is not a
//! network proxy.
//!
//! # Data path
//!
//! ```text
//! TUN device ──▶ netstack-smoltcp Stack ──▶ TCP: SOCKS5 CONNECT ──▶ 127.0.0.1:<socks>
//!                 │                          UDP: DNS relay      ──▶ 127.0.0.1:<dns>
//!                 └──▶ TUN device
//! ```
//!
//! - **TCP** — every accepted flow is dialed through the daemon's SOCKS5
//!   listener (the same listener also serves HTTP CONNECT for other apps),
//!   so all payload bytes leave through Tor. One task per flow, piped with
//!   [`tokio::io::copy_bidirectional`].
//! - **UDP** — Tor (Arti) carries no UDP. [`UdpPolicy::DnsOnly`] intercepts
//!   every datagram addressed to port 53 and relays it to the daemon's local
//!   DNS resolver (the reply is spoofed as coming from the original
//!   destination, so clients see the resolver they asked); all other UDP is
//!   dropped. [`UdpPolicy::BlockAll`] drops everything.
//! - **ICMP** — answered by the netstack itself (echo requests), so `ping`
//!   works without leaving the host.
//!
//! # Failure and logging
//!
//! A failed flow (SOCKS refusal, resolver timeout) is dropped, never leaked
//! directly: the engine has no path to the physical network. Logs carry
//! counts, flow numbers, and error kinds only — never destinations or
//! packet contents (§10.5).
//!
//! [`EngineHandle::stop`] aborts every task and awaits it, so the TUN device
//! is closed (and, on Linux/macOS, the interface disappears) before the
//! caller creates the next one.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{Stack, StackBuilder, TcpListener, TcpStream, UdpSocket};
use tobro_tun::{Forwarding, UdpPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;

/// UDP port whose traffic is intercepted when the policy is
/// [`UdpPolicy::DnsOnly`].
const DNS_PORT: u16 = 53;

/// Total budget for one DNS query + reply relay.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest DNS reply accepted from the daemon's resolver. A DNS message is
/// capped at 64 KiB by the protocol; 4 KiB covers every ordinary reply
/// (including EDNS0) without letting a misbehaving resolver pin memory.
const DNS_MAX_REPLY: usize = 4096;

/// Budget for one SOCKS5 CONNECT (dial + greeting + reply).
const SOCKS_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Everything the engine needs from the applied plan.
#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    /// The daemon's loopback listeners (validated loopback-only by the plan).
    pub forwarding: Forwarding,
    /// UDP handling policy.
    pub udp_policy: UdpPolicy,
    /// TUN interface MTU (sizes the netstack buffers).
    pub mtu: u16,
}

/// A running engine: the netstack tasks plus one per forwarded flow.
pub struct EngineHandle {
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// True when the engine actually forwards; false for a parked device.
    forwarding: bool,
}

impl std::fmt::Debug for EngineHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Task count only; never device or destination details.
        f.debug_struct("EngineHandle")
            .field("tasks", &self.tasks.len())
            .field("forwarding", &self.forwarding)
            .finish()
    }
}

impl EngineHandle {
    /// Build the netstack and start forwarding `packet_io`'s traffic.
    pub fn spawn(packet_io: tun2::AsyncDevice, config: EngineConfig) -> io::Result<Self> {
        let core = EngineCore::build(config)?;
        let (stack, mut tasks) = core.spawn();
        // The TUN device and the netstack are pumped into each other: one
        // task per direction, so backpressure on one side never stalls the
        // other.
        let framed = packet_io.into_framed();
        let (tun_sink, tun_stream) = framed.split();
        let (stack_sink, stack_stream) = stack.split();
        tasks.push(tokio::spawn(pump_tun_to_stack(tun_stream, stack_sink)));
        tasks.push(tokio::spawn(pump_stack_to_tun(stack_stream, tun_sink)));
        tracing::info!(
            "engine: started (mtu={}, udp={:?})",
            config.mtu,
            config.udp_policy
        );
        Ok(Self {
            tasks,
            forwarding: true,
        })
    }

    /// Hold the device without reading it. Used for a plan without
    /// forwarding (fail-closed: the interface stays up, every packet is
    /// dropped by the full device queue instead of escaping unproxied).
    pub fn park(packet_io: tun2::AsyncDevice) -> Self {
        tracing::info!("engine: no forwarding configured; TUN traffic is dropped");
        let tasks = vec![tokio::spawn(async move {
            let _device = packet_io;
            std::future::pending::<()>().await;
        })];
        Self {
            tasks,
            forwarding: false,
        }
    }

    /// Stop every task and wait until the device is actually closed.
    ///
    /// Awaiting the aborted tasks (not just calling `abort`) is what
    /// guarantees the TUN device's file descriptors are dropped before the
    /// caller creates the next device with the same name.
    pub async fn stop(self) {
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            let _ = task.await;
        }
        tracing::debug!(
            "engine: stopped (forwarding was {})",
            if self.forwarding { "on" } else { "off" }
        );
    }
}

/// Per-apply engine counters (log-safe: counts only).
#[derive(Debug, Default)]
struct Counters {
    tcp_flows: AtomicU64,
    tcp_failed: AtomicU64,
    dns_queries: AtomicU64,
    dns_failed: AtomicU64,
    udp_dropped: AtomicU64,
}

/// The netstack side of the engine, separated from the TUN device so tests
/// can drive it over an in-memory link.
pub(crate) struct EngineCore {
    stack: Stack,
    runner: Option<netstack_smoltcp::Runner>,
    tcp_listener: Option<TcpListener>,
    udp_socket: Option<UdpSocket>,
    forwarding: Forwarding,
    udp_policy: UdpPolicy,
}

impl EngineCore {
    /// Build the userspace TCP/IP stack for `config`.
    pub(crate) fn build(config: EngineConfig) -> io::Result<Self> {
        let udp = config.udp_policy == UdpPolicy::DnsOnly;
        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(udp)
            .enable_icmp(true)
            .mtu(usize::from(config.mtu))
            .build()?;
        Ok(Self {
            stack,
            runner,
            tcp_listener,
            udp_socket,
            forwarding: config.forwarding,
            udp_policy: config.udp_policy,
        })
    }

    /// Spawn the netstack runner and the forwarding loops. Returns the
    /// packet-facing [`Stack`] (the caller pumps it to/from the device) and
    /// the task handles.
    pub(crate) fn spawn(self) -> (Stack, Vec<tokio::task::JoinHandle<()>>) {
        let mut tasks = Vec::new();
        if let Some(runner) = self.runner {
            tasks.push(tokio::spawn(async move {
                if let Err(error) = runner.await {
                    tracing::warn!("engine: netstack runner stopped: {error}");
                }
            }));
        }
        let counters = Arc::new(Counters::default());
        if let Some(listener) = self.tcp_listener {
            let socks = self.forwarding.socks;
            let counters = Arc::clone(&counters);
            tasks.push(tokio::spawn(async move {
                run_tcp(listener, socks, counters).await
            }));
        }
        if let Some(socket) = self.udp_socket {
            let counters = Arc::clone(&counters);
            tasks.push(tokio::spawn(async move {
                run_udp(socket, self.forwarding, self.udp_policy, counters).await;
            }));
        }
        (self.stack, tasks)
    }
}

/// Pump packets the netstack produced into the TUN device.
async fn pump_stack_to_tun<S, T>(mut stack: S, mut tun: T)
where
    S: futures::Stream<Item = io::Result<Vec<u8>>> + Unpin,
    T: futures::Sink<Vec<u8>, Error = io::Error> + Unpin,
{
    while let Some(frame) = stack.next().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                tracing::warn!("engine: netstack stream failed: {error}");
                return;
            }
        };
        if let Err(error) = tun.send(frame).await {
            tracing::warn!("engine: writing to the TUN device failed: {error}");
            return;
        }
    }
}

/// Pump packets read from the TUN device into the netstack.
async fn pump_tun_to_stack<S, T>(mut tun: S, mut stack: T)
where
    S: futures::Stream<Item = io::Result<Vec<u8>>> + Unpin,
    T: futures::Sink<Vec<u8>, Error = io::Error> + Unpin,
{
    while let Some(frame) = tun.next().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                tracing::warn!("engine: reading from the TUN device failed: {error}");
                return;
            }
        };
        if let Err(error) = stack.send(frame).await {
            tracing::warn!("engine: feeding the netstack failed: {error}");
            return;
        }
    }
}

/// Accept TCP flows and forward each through the daemon's SOCKS5 listener.
///
/// Flows live in a [`JoinSet`] so stopping the engine (which aborts this
/// loop) also aborts every in-flight flow instead of leaking tasks.
async fn run_tcp(mut listener: TcpListener, socks: SocketAddr, counters: Arc<Counters>) {
    let mut flows = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            next = listener.next() => {
                let Some((stream, _client, destination)) = next else {
                    break;
                };
                let counters = Arc::clone(&counters);
                flows.spawn(async move {
                    let flow = counters.tcp_flows.fetch_add(1, Ordering::Relaxed) + 1;
                    match forward_tcp(stream, destination, socks).await {
                        Ok(()) => tracing::debug!(flow, "engine: TCP flow closed"),
                        Err(error) => {
                            counters.tcp_failed.fetch_add(1, Ordering::Relaxed);
                            // The error kind only: a destination never reaches
                            // a log.
                            tracing::debug!(
                                flow,
                                kind = ?error.kind(),
                                "engine: TCP flow failed"
                            );
                        }
                    }
                });
            }
            // Reap finished flows so the set does not grow unbounded.
            Some(_) = flows.join_next(), if !flows.is_empty() => {}
        }
    }
    flows.shutdown().await;
    tracing::warn!("engine: TCP accept loop stopped");
}

/// Forward one tunnel TCP flow: SOCKS5 CONNECT, then pipe both directions.
async fn forward_tcp(
    mut stream: TcpStream,
    destination: SocketAddr,
    socks: SocketAddr,
) -> io::Result<()> {
    let mut remote =
        tokio::time::timeout(SOCKS_CONNECT_TIMEOUT, socks5_connect(socks, destination))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 CONNECT timed out"))??;
    tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
    Ok(())
}

/// Minimal SOCKS5 CONNECT client (no authentication, IP destinations only).
///
/// The daemon's listener is Arti's local SOCKS proxy; the tunnel already
/// hands us literal IP destinations, so there is no domain-name path.
async fn socks5_connect(proxy: SocketAddr, destination: SocketAddr) -> io::Result<TokioTcpStream> {
    let mut stream = TokioTcpStream::connect(proxy).await?;
    let _ = stream.set_nodelay(true);

    // Greeting: SOCKS5, one method, "no authentication".
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [0x05, 0x00] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the SOCKS5 listener rejected the no-authentication method",
        ));
    }

    // CONNECT request: version, command, reserved, address, port.
    let mut request = Vec::with_capacity(4 + 16 + 2);
    request.extend_from_slice(&[0x05, 0x01, 0x00]);
    match destination.ip() {
        std::net::IpAddr::V4(address) => {
            request.push(0x01);
            request.extend_from_slice(&address.octets());
        }
        std::net::IpAddr::V6(address) => {
            request.push(0x04);
            request.extend_from_slice(&address.octets());
        }
    }
    request.extend_from_slice(&destination.port().to_be_bytes());
    stream.write_all(&request).await?;

    // Reply: version, status, reserved, address type, bound address, port.
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the SOCKS5 listener sent a malformed reply",
        ));
    }
    if header[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("the SOCKS5 listener refused the flow (reply {})", header[1]),
        ));
    }
    let address_len = match header[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0])
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the SOCKS5 listener sent an unknown address type",
            ));
        }
    };
    let mut bound = vec![0u8; address_len + 2];
    stream.read_exact(&mut bound).await?;
    Ok(stream)
}

/// Intercept DNS datagrams and drop everything else, per the UDP policy.
///
/// Relays live in a [`JoinSet`] so stopping the engine also aborts queries
/// still waiting on a resolver.
async fn run_udp(
    socket: UdpSocket,
    forwarding: Forwarding,
    policy: UdpPolicy,
    counters: Arc<Counters>,
) {
    let (mut read, write) = socket.split();
    let write = Arc::new(tokio::sync::Mutex::new(write));
    let mut queries = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            datagram = read.next() => {
                let Some((payload, client, destination)) = datagram else {
                    break;
                };
                let intercepted =
                    policy == UdpPolicy::DnsOnly && destination.port() == DNS_PORT;
                if !intercepted {
                    let dropped = counters.udp_dropped.fetch_add(1, Ordering::Relaxed) + 1;
                    tracing::debug!(dropped, "engine: UDP datagram dropped by policy");
                    continue;
                }
                let Some(resolver) = forwarding.dns else {
                    let dropped = counters.udp_dropped.fetch_add(1, Ordering::Relaxed) + 1;
                    tracing::debug!(dropped, "engine: UDP datagram dropped (no DNS target)");
                    continue;
                };
                let write = Arc::clone(&write);
                let counters = Arc::clone(&counters);
                queries.spawn(async move {
                    let query = counters.dns_queries.fetch_add(1, Ordering::Relaxed) + 1;
                    match relay_dns(&payload, destination, resolver).await {
                        Ok(reply) => {
                            // Spoof the source: the client asked the original
                            // destination, so the answer must come from it.
                            let mut write = write.lock().await;
                            if let Err(error) = write.send((reply, destination, client)).await {
                                tracing::debug!(
                                    query,
                                    kind = ?error.kind(),
                                    "engine: could not deliver a DNS reply"
                                );
                            }
                        }
                        Err(error) => {
                            counters.dns_failed.fetch_add(1, Ordering::Relaxed);
                            tracing::debug!(
                                query,
                                kind = ?error.kind(),
                                "engine: DNS relay failed"
                            );
                        }
                    }
                });
            }
            // Reap finished relays so the set does not grow unbounded.
            Some(_) = queries.join_next(), if !queries.is_empty() => {}
        }
    }
    queries.shutdown().await;
    tracing::warn!("engine: UDP loop stopped");
}

/// Relay one DNS query to the daemon's resolver and return its reply.
///
/// A fresh upstream socket per query keeps the relay stateless; the query is
/// small and rare enough that this costs nothing measurable.
async fn relay_dns(
    query: &[u8],
    destination: SocketAddr,
    resolver: SocketAddr,
) -> io::Result<Vec<u8>> {
    // Match the query's family: a v6 destination needs a v6 upstream socket.
    let bind: SocketAddr = if destination.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let upstream = tokio::net::UdpSocket::bind(bind).await?;
    upstream.send_to(query, resolver).await?;
    let mut buffer = vec![0u8; DNS_MAX_REPLY];
    let (len, _) = tokio::time::timeout(DNS_TIMEOUT, upstream.recv_from(&mut buffer))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the DNS resolver timed out"))??;
    buffer.truncate(len);
    Ok(buffer)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use netstack_smoltcp::smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
    use netstack_smoltcp::smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
    use netstack_smoltcp::smoltcp::socket::{tcp as tcp_socket, udp as udp_socket};
    use netstack_smoltcp::smoltcp::time::Instant as SmolInstant;
    use netstack_smoltcp::smoltcp::wire::{
        HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address,
    };

    /// The client-side address inside the tunnel subnet.
    const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(10, 111, 222, 253);

    // --- Fake daemon listeners -------------------------------------------

    /// A minimal SOCKS5 server that echoes whatever it receives.
    async fn spawn_echo_socks() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake SOCKS");
        let address = listener.local_addr().expect("fake SOCKS address");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut greeting = [0u8; 3];
                    if stream.read_exact(&mut greeting).await.is_err() {
                        return;
                    }
                    if stream.write_all(&[0x05, 0x00]).await.is_err() {
                        return;
                    }
                    let mut header = [0u8; 4];
                    if stream.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let address_len = match header[3] {
                        0x01 => 4,
                        0x04 => 16,
                        0x03 => {
                            let mut len = [0u8; 1];
                            if stream.read_exact(&mut len).await.is_err() {
                                return;
                            }
                            usize::from(len[0])
                        }
                        _ => return,
                    };
                    let mut rest = vec![0u8; address_len + 2];
                    if stream.read_exact(&mut rest).await.is_err() {
                        return;
                    }
                    if stream
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let (mut reader, mut writer) = stream.into_split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
        address
    }

    /// A UDP "DNS" server that echoes every datagram back unchanged.
    async fn spawn_echo_dns(received: Arc<AtomicU64>) -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind fake DNS");
        let address = socket.local_addr().expect("fake DNS address");
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                received.fetch_add(1, Ordering::Relaxed);
                let _ = socket.send_to(&buffer[..len], peer).await;
            }
        });
        address
    }

    // --- In-memory TUN link ----------------------------------------------

    /// smoltcp device backed by channels: frames received from the engine
    /// are handed to the client interface, frames the client emits are sent
    /// to the engine's netstack.
    struct ChannelDevice {
        inbound: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        outbound: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        pending: Vec<u8>,
    }

    impl Device for ChannelDevice {
        type RxToken<'a> = ChannelRx<'a>;
        type TxToken<'a> = ChannelTx<'a>;

        fn receive(
            &mut self,
            _timestamp: SmolInstant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            let frame = self.inbound.try_recv().ok()?;
            self.pending = frame;
            Some((ChannelRx(&self.pending), ChannelTx(&self.outbound)))
        }

        fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
            Some(ChannelTx(&self.outbound))
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut capabilities = DeviceCapabilities::default();
            capabilities.medium = Medium::Ip;
            capabilities.max_transmission_unit = 1500;
            capabilities
        }
    }

    struct ChannelRx<'a>(&'a [u8]);

    impl RxToken for ChannelRx<'_> {
        fn consume<R, F>(self, f: F) -> R
        where
            F: FnOnce(&[u8]) -> R,
        {
            f(self.0)
        }
    }

    struct ChannelTx<'a>(&'a tokio::sync::mpsc::UnboundedSender<Vec<u8>>);

    impl TxToken for ChannelTx<'_> {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            let mut buffer = vec![0u8; len];
            let result = f(&mut buffer);
            let _ = self.0.send(buffer);
            result
        }
    }

    /// The client end of the link plus its smoltcp interface.
    struct ClientStack {
        interface: Interface,
        device: ChannelDevice,
        sockets: SocketSet<'static>,
    }

    impl ClientStack {
        fn new(
            inbound: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
            outbound: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        ) -> Self {
            let mut config = IfaceConfig::new(HardwareAddress::Ip);
            config.random_seed = 0x5eed;
            let mut device = ChannelDevice {
                inbound,
                outbound,
                pending: Vec::new(),
            };
            let mut interface = Interface::new(config, &mut device, SmolInstant::now());
            interface.update_ip_addrs(|addresses| {
                addresses
                    .push(IpCidr::new(IpAddress::v4(10, 111, 222, 253), 30))
                    .expect("client IPv4 address");
                addresses
                    .push(IpCidr::new(
                        IpAddress::v6(0xfd6b, 0x626f, 0x6272, 0x6f, 0, 0, 0, 3),
                        64,
                    ))
                    .expect("client IPv6 address");
            });
            interface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::new(10, 111, 222, 254))
                .expect("client IPv4 route");
            interface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::new(0xfd6b, 0x626f, 0x6272, 0x6f, 0, 0, 0, 2))
                .expect("client IPv6 route");
            Self {
                interface,
                device,
                sockets: SocketSet::new(Vec::new()),
            }
        }

        fn poll(&mut self) {
            self.interface
                .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
        }
    }

    /// Wire an engine's [`Stack`] to channel endpoints the client device can
    /// use. Returns `(to_engine, from_engine)`.
    fn wire(
        stack: Stack,
    ) -> (
        tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let (to_client, from_engine) = tokio::sync::mpsc::unbounded_channel();
        let (to_engine, mut from_client) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (mut sink, mut stream) = stack.split();
        tokio::spawn(async move {
            while let Some(Ok(frame)) = stream.next().await {
                if to_client.send(frame).is_err() {
                    return;
                }
            }
        });
        tokio::spawn(async move {
            while let Some(frame) = from_client.recv().await {
                if sink.send(frame).await.is_err() {
                    return;
                }
            }
        });
        (to_engine, from_engine)
    }

    /// Poll the client interface until `done` holds (bounded).
    async fn drive(
        client: &mut ClientStack,
        timeout: Duration,
        mut done: impl FnMut(&mut Interface, &mut SocketSet<'_>) -> bool,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            client.poll();
            if done(&mut client.interface, &mut client.sockets) {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    fn engine_for(socks: SocketAddr, dns: Option<SocketAddr>, policy: UdpPolicy) -> EngineCore {
        EngineCore::build(EngineConfig {
            forwarding: Forwarding { socks, dns },
            udp_policy: policy,
            mtu: 1500,
        })
        .expect("engine must build")
    }

    // --- SOCKS5 unit tests ------------------------------------------------

    #[tokio::test]
    async fn socks5_connect_sends_the_literal_destination_and_returns_the_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let proxy = listener.local_addr().expect("address");
        let destination: SocketAddr = "93.184.216.34:443".parse().expect("destination");
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.expect("greeting");
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).await.expect("method");
            let mut header = [0u8; 4];
            stream.read_exact(&mut header).await.expect("header");
            assert_eq!(header, [0x05, 0x01, 0x00, 0x01]);
            let mut address = [0u8; 6];
            stream.read_exact(&mut address).await.expect("address");
            seen_tx.send(address).expect("report address");
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90])
                .await
                .expect("reply");
            stream.write_all(b"ok").await.expect("payload");
        });

        let mut stream = socks5_connect(proxy, destination)
            .await
            .expect("SOCKS5 connect");
        let mut payload = [0u8; 2];
        stream.read_exact(&mut payload).await.expect("read payload");
        assert_eq!(&payload, b"ok");

        let address = seen_rx.await.expect("address report");
        assert_eq!(&address[..4], &[93, 184, 216, 34]);
        assert_eq!(u16::from_be_bytes([address[4], address[5]]), 443);
    }

    #[tokio::test]
    async fn socks5_connect_reports_a_refused_flow() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let proxy = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buffer = [0u8; 16];
            let _ = stream.read(&mut buffer).await;
            let _ = stream.write_all(&[0x05, 0x00]).await;
            let _ = stream.read(&mut buffer).await;
            let _ = stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await;
        });
        let error = socks5_connect(proxy, "192.0.2.1:80".parse().expect("destination"))
            .await
            .expect_err("a refused flow must error");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    }

    // --- End-to-end tests over the in-memory link -------------------------

    #[tokio::test]
    async fn tcp_flows_reach_the_socks_listener_and_are_piped_back() {
        let socks = spawn_echo_socks().await;
        let core = engine_for(socks, None, UdpPolicy::DnsOnly);
        let (to_engine, from_engine) = wire(core.spawn().0);
        let mut client = ClientStack::new(from_engine, to_engine);

        let handle = client.sockets.add(tcp_socket::Socket::new(
            tcp_socket::SocketBuffer::new(vec![0u8; 4096]),
            tcp_socket::SocketBuffer::new(vec![0u8; 4096]),
        ));
        client
            .sockets
            .get_mut::<tcp_socket::Socket>(handle)
            .connect(
                client.interface.context(),
                (IpAddress::v4(93, 184, 216, 34), 443),
                49_000,
            )
            .expect("connect");

        assert!(
            drive(&mut client, Duration::from_secs(5), |_iface, sockets| {
                sockets.get::<tcp_socket::Socket>(handle).state() == tcp_socket::State::Established
            })
            .await,
            "the flow never established"
        );

        client
            .sockets
            .get_mut::<tcp_socket::Socket>(handle)
            .send_slice(b"hello through tor")
            .expect("send");
        let mut received = Vec::new();
        assert!(
            drive(&mut client, Duration::from_secs(5), |_iface, sockets| {
                let socket = sockets.get_mut::<tcp_socket::Socket>(handle);
                let mut buffer = [0u8; 64];
                while let Ok(len) = socket.recv_slice(&mut buffer) {
                    if len == 0 {
                        break;
                    }
                    received.extend_from_slice(&buffer[..len]);
                }
                received.len() >= 16
            })
            .await,
            "no echoed payload arrived"
        );
        assert_eq!(received, b"hello through tor");
    }

    #[tokio::test]
    async fn dns_only_policy_relays_port_53_and_spoofs_the_destination() {
        let received = Arc::new(AtomicU64::new(0));
        let dns = spawn_echo_dns(Arc::clone(&received)).await;
        let socks = spawn_echo_socks().await;
        let core = engine_for(socks, Some(dns), UdpPolicy::DnsOnly);
        let (to_engine, from_engine) = wire(core.spawn().0);
        let mut client = ClientStack::new(from_engine, to_engine);

        let handle = client.sockets.add(udp_socket::Socket::new(
            udp_socket::PacketBuffer::new(
                vec![udp_socket::PacketMetadata::EMPTY; 8],
                vec![0u8; 4096],
            ),
            udp_socket::PacketBuffer::new(
                vec![udp_socket::PacketMetadata::EMPTY; 8],
                vec![0u8; 4096],
            ),
        ));
        client
            .sockets
            .get_mut::<udp_socket::Socket>(handle)
            .bind((IpAddress::v4(10, 111, 222, 253), 40_000))
            .expect("bind");
        client
            .sockets
            .get_mut::<udp_socket::Socket>(handle)
            .send_slice(b"query", (IpAddress::v4(10, 111, 222, 254), DNS_PORT))
            .expect("send query");

        let mut reply = Vec::new();
        assert!(
            drive(&mut client, Duration::from_secs(5), |_iface, sockets| {
                let socket = sockets.get_mut::<udp_socket::Socket>(handle);
                let mut buffer = [0u8; 64];
                while let Ok((len, _meta)) = socket.recv_slice(&mut buffer) {
                    if len == 0 {
                        break;
                    }
                    reply.extend_from_slice(&buffer[..len]);
                }
                !reply.is_empty()
            })
            .await,
            "no DNS reply arrived"
        );
        assert_eq!(reply, b"query");
        assert_eq!(received.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn non_dns_udp_is_dropped_without_reaching_the_resolver() {
        let received = Arc::new(AtomicU64::new(0));
        let dns = spawn_echo_dns(Arc::clone(&received)).await;
        let socks = spawn_echo_socks().await;
        let core = engine_for(socks, Some(dns), UdpPolicy::DnsOnly);
        let (to_engine, from_engine) = wire(core.spawn().0);
        let mut client = ClientStack::new(from_engine, to_engine);

        let handle = client.sockets.add(udp_socket::Socket::new(
            udp_socket::PacketBuffer::new(
                vec![udp_socket::PacketMetadata::EMPTY; 8],
                vec![0u8; 4096],
            ),
            udp_socket::PacketBuffer::new(
                vec![udp_socket::PacketMetadata::EMPTY; 8],
                vec![0u8; 4096],
            ),
        ));
        client
            .sockets
            .get_mut::<udp_socket::Socket>(handle)
            .bind((IpAddress::v4(10, 111, 222, 253), 40_001))
            .expect("bind");
        client
            .sockets
            .get_mut::<udp_socket::Socket>(handle)
            .send_slice(b"quic", (IpAddress::v4(10, 111, 222, 254), 443))
            .expect("send datagram");

        // Give the engine time to (not) do something with it.
        let _ = drive(
            &mut client,
            Duration::from_millis(300),
            |_iface, sockets| sockets.get_mut::<udp_socket::Socket>(handle).can_recv(),
        )
        .await;
        assert_eq!(received.load(Ordering::Relaxed), 0);
        assert!(
            !client
                .sockets
                .get_mut::<udp_socket::Socket>(handle)
                .can_recv(),
            "a non-DNS datagram must not be answered"
        );
    }

    #[tokio::test]
    async fn block_all_policy_drops_even_dns() {
        let received = Arc::new(AtomicU64::new(0));
        let dns = spawn_echo_dns(Arc::clone(&received)).await;
        let socks = spawn_echo_socks().await;
        let core = engine_for(socks, Some(dns), UdpPolicy::BlockAll);
        let (to_engine, from_engine) = wire(core.spawn().0);
        let mut client = ClientStack::new(from_engine, to_engine);

        let handle = client.sockets.add(udp_socket::Socket::new(
            udp_socket::PacketBuffer::new(
                vec![udp_socket::PacketMetadata::EMPTY; 8],
                vec![0u8; 4096],
            ),
            udp_socket::PacketBuffer::new(
                vec![udp_socket::PacketMetadata::EMPTY; 8],
                vec![0u8; 4096],
            ),
        ));
        client
            .sockets
            .get_mut::<udp_socket::Socket>(handle)
            .bind((IpAddress::v4(10, 111, 222, 253), 40_002))
            .expect("bind");
        client
            .sockets
            .get_mut::<udp_socket::Socket>(handle)
            .send_slice(b"query", (IpAddress::v4(10, 111, 222, 254), DNS_PORT))
            .expect("send query");

        let _ = drive(
            &mut client,
            Duration::from_millis(300),
            |_iface, sockets| sockets.get_mut::<udp_socket::Socket>(handle).can_recv(),
        )
        .await;
        assert_eq!(received.load(Ordering::Relaxed), 0);
        assert!(
            !client
                .sockets
                .get_mut::<udp_socket::Socket>(handle)
                .can_recv()
        );
    }

    #[tokio::test]
    async fn relay_dns_returns_the_resolver_reply() {
        let received = Arc::new(AtomicU64::new(0));
        let resolver = spawn_echo_dns(Arc::clone(&received)).await;
        let reply = relay_dns(b"payload", SocketAddr::from((CLIENT_V4, 53)), resolver)
            .await
            .expect("relay");
        assert_eq!(reply, b"payload");
        assert_eq!(received.load(Ordering::Relaxed), 1);
    }
}
