//! Connection handling: peer-identity gating and the accept loops.
//!
//! The helper serves exactly one client at a time (sequential accept loop).
//! Every connection is peer-gated before any privileged work happens:
//!
//! - **Unix** — the peer credential of the connecting process is read from
//!   the socket. The gate locks to the uid of the *first* successful
//!   handshake and rejects every other uid from then on. A peer whose
//!   credentials cannot be determined is always denied.
//! - **Windows** — named pipes do not expose a portable peer user through
//!   tokio, so peers report [`PeerIdentity::Unknown`]; the gate admits them
//!   for now and the real check (SID-based, via the pipe's client token)
//!   lands with the Windows service install (M7 T4c).
//!
//! The first message on any connection must be a handshake; anything else
//! is answered with an `UNAUTHORIZED` rejection and the connection is
//! closed. Afterwards the connection runs in lock-step: one request in, one
//! response out, dispatched through [`HelperService`].
//!
//! "Runs only while TUN is enabled" is enforced by the idle window: the
//! serve loop exits cleanly when no client connects within it, tearing down
//! any still-applied plan first (the daemon can only have disconnected
//! without a teardown in that situation).

use std::time::Duration;

use futures::{Sink, SinkExt as _, Stream, StreamExt as _};
use tokio_util::codec::Framed;

use tobro_tun::{
    HelperCodec, HelperError, HelperMessage, HelperRequest, HelperResponse, reject_codes,
};

use crate::platform::Platform;
use crate::service::HelperService;

/// How the serve loop ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeExit {
    /// A termination signal arrived (SIGTERM/SIGINT on Unix, `CTRL+C` /
    /// service stop on Windows).
    ShutdownSignal,
    /// No client connected within the idle window.
    IdleTimeout,
    /// The IPC endpoint could not be (re)bound.
    BindError(String),
}

/// The identity of the connecting peer, as far as the transport can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerIdentity {
    /// Unix peer credential: the connecting process's effective uid.
    Uid(u32),
    /// The transport cannot identify the peer (Windows interim). Admitted,
    /// pending the SID-based check in M7 T4c.
    Unknown,
    /// The transport should be able to identify the peer but could not.
    /// Always denied: an unverifiable peer is an attack signal, not a
    /// compatibility mode.
    Unverifiable,
}

impl PeerIdentity {
    /// Log-safe name of the identity kind (never the value itself; the uid
    /// is not sensitive, but summaries stay uniform).
    fn kind(&self) -> &'static str {
        match self {
            PeerIdentity::Uid(_) => "uid",
            PeerIdentity::Unknown => "unknown",
            PeerIdentity::Unverifiable => "unverifiable",
        }
    }
}

/// Peer gate: admits the first handshaking client and locks onto it.
///
/// With the sequential accept loop the gate is owned by the serve loop, so
/// no shared locking is needed — `&mut PeerGate` is the entire interface.
#[derive(Debug, Default)]
pub struct PeerGate {
    /// Uid the gate locked onto, if any.
    locked_uid: Option<u32>,
}

impl PeerGate {
    /// A fresh, unlocked gate.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide whether `peer` may proceed to the handshake. The first
    /// admissible `Uid` peer locks the gate; later peers must match it.
    pub fn authorize(&mut self, peer: PeerIdentity) -> bool {
        match peer {
            PeerIdentity::Unverifiable => false,
            PeerIdentity::Unknown => {
                // Interim Windows behavior (M7 T4c replaces this with a
                // SID check against the service's expected client).
                true
            }
            PeerIdentity::Uid(uid) => match self.locked_uid {
                None => {
                    self.locked_uid = Some(uid);
                    true
                }
                Some(locked) => locked == uid,
            },
        }
    }

    /// The uid the gate is locked onto, if any.
    pub fn locked_uid(&self) -> Option<u32> {
        self.locked_uid
    }
}

/// Serve one connection to completion. Returns when the peer disconnects
/// or on any framing error; the accept loop decides what happens next.
async fn serve_connection<S, P>(
    stream: &mut S,
    service: &mut HelperService<P>,
    gate: &mut PeerGate,
    peer: PeerIdentity,
) where
    S: Stream<Item = Result<HelperMessage, HelperError>>
        + Sink<HelperMessage, Error = HelperError>
        + Unpin,
    P: Platform,
{
    // The first message must be the handshake; enforce it before anything
    // privileged is even thinkable.
    let first = match stream.next().await {
        Some(Ok(message)) => message,
        Some(Err(error)) => {
            tracing::debug!("connection ended before handshake: {error}");
            return;
        }
        None => return,
    };
    let HelperMessage::Request(HelperRequest::Handshake { protocol_version }) = first else {
        let _ = send_reject(
            stream,
            reject_codes::UNAUTHORIZED,
            "the first message must be a handshake",
        )
        .await;
        return;
    };
    tracing::debug!(
        "handshake from {} peer (client protocol v{protocol_version})",
        peer.kind()
    );

    if !gate.authorize(peer) {
        // Keep the reason vague in the protocol message; details go to the
        // (root-only) log.
        tracing::warn!(
            "denied {} peer: gate is locked to another client or identity unverifiable",
            peer.kind()
        );
        let _ = send_reject(
            stream,
            reject_codes::UNAUTHORIZED,
            "peer identity not permitted",
        )
        .await;
        return;
    }

    let response = HelperResponse::HandshakeOk {
        protocol_version: tobro_tun::PROTOCOL_VERSION,
        helper_version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    if let Err(error) = stream.send(HelperMessage::Response(response)).await {
        tracing::debug!("handshake reply failed: {error}");
        return;
    }

    // Lock-step loop: one request, one response.
    while let Some(message) = stream.next().await {
        let Ok(HelperMessage::Request(request)) = message else {
            // A Response from the client side is a protocol violation.
            let _ = send_reject(stream, reject_codes::INTERNAL, "expected a request").await;
            return;
        };
        let response = service.handle(request).await;
        if let Err(error) = stream.send(HelperMessage::Response(response)).await {
            tracing::debug!("reply failed: {error}");
            return;
        }
    }
}

/// Send one rejection, ignoring delivery errors (the peer may be gone).
async fn send_reject<S>(stream: &mut S, code: u32, message: &str) -> Result<(), ()>
where
    S: Sink<HelperMessage, Error = HelperError> + Unpin,
{
    stream
        .send(HelperMessage::Response(HelperResponse::Rejected {
            code,
            message: message.to_owned(),
        }))
        .await
        .map_err(|_| ())
}

/// Best-effort teardown before the helper stops. Only acts when a plan is
/// still applied (e.g. the daemon vanished without a teardown); otherwise a
/// no-op.
async fn teardown_if_active<P: Platform>(service: &mut HelperService<P>, reason: &str) {
    if !service.state().active {
        return;
    }
    match service.handle(HelperRequest::Teardown {}).await {
        HelperResponse::TornDown { .. } => {
            tracing::info!("torn down before exit ({reason})");
        }
        other => {
            tracing::warn!("teardown before exit ({reason}) did not complete: {other:?}");
        }
    }
}

/// Unix accept loop: one client at a time, gated by peer credentials.
///
/// `idle` is the window in which a new client must connect; with no client
/// the loop tears down any applied plan and returns
/// [`ServeExit::IdleTimeout`]. A termination signal returns
/// [`ServeExit::ShutdownSignal`] after the same best-effort teardown.
#[cfg(unix)]
pub async fn serve_unix<P: Platform>(
    listener: tokio::net::UnixListener,
    service: &mut HelperService<P>,
    idle: Option<Duration>,
) -> ServeExit {
    let mut gate = PeerGate::new();
    loop {
        tokio::select! {
            exit = shutdown_signal() => {
                teardown_if_active(service, "shutdown signal").await;
                return exit;
            }
            exit = idle_window(idle) => {
                teardown_if_active(service, "idle timeout").await;
                return exit;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let peer = peer_identity_unix(&stream);
                        let mut framed = Framed::new(stream, HelperCodec::new());
                        serve_connection(&mut framed, service, &mut gate, peer).await;
                    }
                    Err(error) => {
                        // Transient accept errors happen (EMFILE, ...);
                        // avoid a hot spin loop.
                        tracing::warn!("accept failed: {error}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
}

/// Read the peer credential from a Unix stream, mapping failure to
/// [`PeerIdentity::Unverifiable`].
#[cfg(unix)]
fn peer_identity_unix(stream: &tokio::net::UnixStream) -> PeerIdentity {
    match stream.peer_cred() {
        Ok(cred) => PeerIdentity::Uid(cred.uid()),
        Err(error) => {
            tracing::warn!("could not read peer credentials: {error}");
            PeerIdentity::Unverifiable
        }
    }
}

/// Windows accept loop: one pipe instance at a time; the next instance is
/// created after each served client. There is a brief window between
/// clients where connections fail; clients retry (see
/// `TunHelperClient::connect_with_retry`).
///
/// See [`serve_unix`] for idle/shutdown semantics.
#[cfg(windows)]
pub async fn serve_windows<P: Platform>(
    path: &std::path::Path,
    service: &mut HelperService<P>,
    idle: Option<Duration>,
) -> ServeExit {
    use tokio::net::windows::named_pipe::NamedPipeServer;

    let mut gate = PeerGate::new();
    loop {
        tokio::select! {
            exit = shutdown_signal() => {
                teardown_if_active(service, "shutdown signal").await;
                return exit;
            }
            exit = idle_window(idle) => {
                teardown_if_active(service, "idle timeout").await;
                return exit;
            }
            bound = tobro_tun::bind_listener(path) => {
                let server: NamedPipeServer = match bound {
                    Ok(server) => server,
                    Err(error) => {
                        return ServeExit::BindError(error.to_string());
                    }
                };
                // Wait for a client to connect, but keep honoring
                // shutdown/idle while waiting.
                tokio::select! {
                    exit = shutdown_signal() => {
                        drop(server);
                        teardown_if_active(service, "shutdown signal").await;
                        return exit;
                    }
                    exit = idle_window(idle) => {
                        drop(server);
                        teardown_if_active(service, "idle timeout").await;
                        return exit;
                    }
                    connected = server.connect() => {
                        if let Err(error) = connected {
                            tracing::warn!("pipe connect failed: {error}");
                            continue;
                        }
                        let mut framed = Framed::new(server, HelperCodec::new());
                        serve_connection(&mut framed, service, &mut gate, PeerIdentity::Unknown).await;
                    }
                }
            }
        }
    }
}

/// The idle window: `IdleTimeout` after `idle` elapses; never resolves when
/// `idle` is `None`.
async fn idle_window(idle: Option<Duration>) -> ServeExit {
    match idle {
        Some(window) => {
            tokio::time::sleep(window).await;
            ServeExit::IdleTimeout
        }
        None => std::future::pending().await,
    }
}

/// Resolves on the first termination signal.
#[cfg(unix)]
pub async fn shutdown_signal() -> ServeExit {
    use tokio::signal::unix::{SignalKind, signal};

    // Register SIGTERM first; if that fails, SIGINT via ctrl_c still works.
    let term = match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            async move {
                term.recv().await;
            }
        }
        Err(error) => {
            tracing::warn!("could not register SIGTERM handler: {error}");
            std::future::pending().await
        }
    };
    tokio::select! {
        _ = term => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    ServeExit::ShutdownSignal
}

/// Resolves on the first termination signal (Windows: console/service stop).
#[cfg(windows)]
pub async fn shutdown_signal() -> ServeExit {
    if tokio::signal::ctrl_c().await.is_ok() {
        tracing::debug!("received ctrl_c");
    } else {
        tracing::warn!("ctrl_c registration failed; relying on service stop");
    }
    ServeExit::ShutdownSignal
}

#[cfg(all(test, unix))]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod unix_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::TempDir;
    use tobro_tun::{
        DnsConfig, KillSwitchMode, Prefix, RouteSpec, TunDevice, TunHelperClient, TunnelPlan,
    };

    fn plan() -> TunnelPlan {
        TunnelPlan {
            device: TunDevice {
                name: "tobro0".to_owned(),
                addresses: vec![Prefix {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 111, 222, 252)),
                    prefix_len: 30,
                }],
                mtu: tobro_tun::DEFAULT_TUN_MTU,
            },
            routes: vec![RouteSpec {
                destination: Prefix {
                    addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    prefix_len: 0,
                },
                gateway: None,
                metric: None,
            }],
            bypass_routes: Vec::new(),
            dns: DnsConfig {
                servers: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            },
            kill_switch: KillSwitchMode::Block,
        }
    }

    /// Spawn the real serve loop over a bound listener.
    async fn spawn_helper(path: &std::path::Path) -> tokio::task::JoinHandle<ServeExit> {
        let listener = tobro_tun::bind_listener(path).await.unwrap();
        let mut service = HelperService::new(crate::NullPlatform);
        let handle = tokio::spawn(async move {
            serve_unix(listener, &mut service, Some(Duration::from_millis(400))).await
        });
        // Give the loop a beat to reach the accept arm (not strictly
        // needed: the socket is already bound and listening).
        tokio::time::sleep(Duration::from_millis(20)).await;
        handle
    }

    #[tokio::test]
    async fn full_client_flow_against_the_real_loop() {
        let dir = TempDir::with_prefix("tobro-helper-e2e").unwrap();
        let path = dir.path().join("helper.sock");
        let task = spawn_helper(&path).await;

        let mut client = TunHelperClient::connect(&path).await.unwrap();
        let info = client.handshake().await.unwrap();
        assert_eq!(info.protocol_version, tobro_tun::PROTOCOL_VERSION);

        let status = client.status().await.unwrap();
        assert!(!status.active);

        // The skeleton platform rejects privileged work with UNSUPPORTED.
        let error = client.apply_plan(&plan()).await.unwrap_err();
        assert!(
            matches!(
                error,
                tobro_tun::HelperError::Rejected {
                    code: tobro_tun::reject_codes::UNSUPPORTED,
                    ..
                }
            ),
            "{error:?}"
        );

        // Teardown is an honest no-op success. Generation is 2: the
        // failed apply's rollback bumped it to 1, the teardown to 2.
        let generation = client.teardown().await.unwrap();
        assert_eq!(generation, 2);

        drop(client);
        // Idle window expires after the client leaves -> clean exit.
        let exit = task.await.unwrap();
        assert_eq!(exit, ServeExit::IdleTimeout);
    }

    #[tokio::test]
    async fn second_client_with_the_same_uid_is_served() {
        let dir = TempDir::with_prefix("tobro-helper-e2e").unwrap();
        let path = dir.path().join("helper.sock");
        let task = spawn_helper(&path).await;

        {
            let mut first = TunHelperClient::connect(&path).await.unwrap();
            first.handshake().await.unwrap();
            first.status().await.unwrap();
        }
        {
            let mut second = TunHelperClient::connect(&path).await.unwrap();
            second.handshake().await.unwrap();
            second.status().await.unwrap();
        }
        let exit = task.await.unwrap();
        assert_eq!(exit, ServeExit::IdleTimeout);
    }

    #[tokio::test]
    async fn non_handshake_first_message_is_rejected_and_gate_stays_open() {
        let dir = TempDir::with_prefix("tobro-helper-e2e").unwrap();
        let path = dir.path().join("helper.sock");
        let task = spawn_helper(&path).await;

        // Raw connection speaking `status` first: rejected with
        // UNAUTHORIZED, connection closed, and the gate must still admit a
        // proper handshake afterwards.
        let mut raw = tobro_tun::open_stream(&path).await.unwrap();
        raw.send(HelperMessage::Request(HelperRequest::Status {}))
            .await
            .unwrap();
        let reply = raw.next().await.unwrap().unwrap();
        let HelperMessage::Response(HelperResponse::Rejected { code, .. }) = reply else {
            panic!("expected a rejection, got {reply:?}");
        };
        assert_eq!(code, reject_codes::UNAUTHORIZED);
        // The server closes the connection after the rejection.
        assert!(raw.next().await.is_none());

        let mut client = TunHelperClient::connect(&path).await.unwrap();
        client.handshake().await.unwrap();

        drop(client);
        assert_eq!(task.await.unwrap(), ServeExit::IdleTimeout);
    }

    #[tokio::test]
    async fn idle_helper_exits_without_any_client() {
        let dir = TempDir::with_prefix("tobro-helper-e2e").unwrap();
        let path = dir.path().join("helper.sock");
        let listener = tobro_tun::bind_listener(&path).await.unwrap();
        let mut service = HelperService::new(crate::NullPlatform);
        let exit = serve_unix(listener, &mut service, Some(Duration::from_millis(80))).await;
        assert_eq!(exit, ServeExit::IdleTimeout);
        // The stale socket is left for the next bind to replace; that path
        // is covered by tobro-tun's bind tests.
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod gate_tests {
    use super::*;

    #[test]
    fn gate_locks_to_the_first_uid() {
        let mut gate = PeerGate::new();
        assert_eq!(gate.locked_uid(), None);

        // Unverifiable peers are denied even before anything is locked.
        assert!(!gate.authorize(PeerIdentity::Unverifiable));
        assert_eq!(gate.locked_uid(), None);

        // First uid peer locks the gate.
        assert!(gate.authorize(PeerIdentity::Uid(1000)));
        assert_eq!(gate.locked_uid(), Some(1000));

        // Same uid admitted, different uid denied.
        assert!(gate.authorize(PeerIdentity::Uid(1000)));
        assert!(!gate.authorize(PeerIdentity::Uid(1001)));

        // Unverifiable stays denied after locking too.
        assert!(!gate.authorize(PeerIdentity::Unverifiable));
    }

    #[test]
    fn unknown_peers_are_admitted_interim_and_do_not_lock_the_gate() {
        let mut gate = PeerGate::new();
        assert!(gate.authorize(PeerIdentity::Unknown));
        // Unknown does not lock: a Unix uid can still claim the gate.
        assert_eq!(gate.locked_uid(), None);
        assert!(gate.authorize(PeerIdentity::Uid(1000)));
        assert_eq!(gate.locked_uid(), Some(1000));
        assert!(!gate.authorize(PeerIdentity::Uid(1001)));
    }
}
