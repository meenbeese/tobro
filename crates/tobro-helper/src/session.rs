//! Connection handling: peer-identity gating and the accept loops.
//!
//! The helper serves exactly one client at a time (sequential accept loop).
//! Every connection is peer-gated before any privileged work happens:
//!
//! - **Unix** — the peer credential of the connecting process is read from
//!   the socket. The gate locks to the uid of the *first* successful
//!   handshake and rejects every other uid from then on. A peer whose
//!   credentials cannot be determined is always denied.
//! - **Windows** — the connecting process's user SID is read from its token
//!   and compared with the SID the installer recorded (`--allow-sid`). Only
//!   that user is admitted; the pipe DACL already scopes connections to the
//!   same user, so the gate is the authoritative check behind it. A peer
//!   whose SID cannot be read is always denied.
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

/// Short grace for daemon reconnection after an IPC disconnect.  Heartbeats
/// normally reconnect well inside this window; an actual daemon exit tears down
/// the tunnel instead of leaving networking changed for the idle window.
const DISCONNECT_GRACE: Duration = Duration::from_secs(30);

/// How the serve loop ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeExit {
    /// A termination signal arrived (SIGTERM/SIGINT on Unix, `CTRL+C` /
    /// service stop on Windows).
    ShutdownSignal,
    /// No client connected within the idle window.
    IdleTimeout,
    /// The authorized daemon disconnected and did not reconnect during grace.
    DisconnectTimeout,
    /// The IPC endpoint could not be (re)bound.
    BindError(String),
}

/// The identity of the connecting peer, as far as the transport can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdentity {
    /// Unix peer credential: the connecting process's effective uid.
    Uid(u32),
    /// Windows peer credential: the connecting process's user SID, in the
    /// raw SID byte layout (compared byte-for-byte with the installer's SID).
    Sid(Vec<u8>),
    /// The transport should be able to identify the peer but could not.
    /// Always denied: an unverifiable peer is an attack signal, not a
    /// compatibility mode.
    Unverifiable,
}

impl PeerIdentity {
    /// Log-safe name of the identity kind (never the value itself; the uid
    /// is not sensitive, and SIDs stay out of logs too).
    fn kind(&self) -> &'static str {
        match self {
            PeerIdentity::Uid(_) => "uid",
            PeerIdentity::Sid(_) => "sid",
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
    /// Uid the gate locked onto, if any (Unix).
    locked_uid: Option<u32>,
    /// The only SID admitted, from the installer (Windows). `None` denies
    /// every SID peer: a helper without a configured client must not serve.
    allowed_sid: Option<Vec<u8>>,
}

impl PeerGate {
    /// A fresh gate for the Unix uid rule.
    pub fn new() -> Self {
        Self::default()
    }

    /// A gate that admits exactly `sid` (the installer-recorded daemon user).
    pub fn with_allowed_sid(sid: Vec<u8>) -> Self {
        Self {
            locked_uid: None,
            allowed_sid: Some(sid),
        }
    }

    /// Decide whether `peer` may proceed to the handshake. On Unix the first
    /// admissible `Uid` peer locks the gate; later peers must match it. On
    /// Windows the peer's SID must equal the installer-recorded SID.
    pub fn authorize(&mut self, peer: &PeerIdentity) -> bool {
        match peer {
            PeerIdentity::Unverifiable => false,
            PeerIdentity::Sid(sid) => self
                .allowed_sid
                .as_deref()
                .is_some_and(|allowed| allowed == sid.as_slice()),
            PeerIdentity::Uid(uid) => match self.locked_uid {
                None => {
                    self.locked_uid = Some(*uid);
                    true
                }
                Some(locked) => locked == *uid,
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
    peer: &PeerIdentity,
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
            _exit = disconnect_window(service.state().active) => {
                teardown_if_active(service, "daemon disconnect grace").await;
                return ServeExit::DisconnectTimeout;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let peer = peer_identity_unix(&stream);
                        let mut framed = Framed::new(stream, HelperCodec::new());
                        serve_connection(&mut framed, service, &mut gate, &peer).await;
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
/// `allow_sid` is the daemon user's SID the installer recorded: it scopes
/// the pipe DACL ([`tobro_osapi::win_pipe::PipeSecurity`]) and the
/// handshake gate. A malformed or missing SID fails the loop closed.
///
/// See [`serve_unix`] for idle/shutdown semantics.
#[cfg(windows)]
pub async fn serve_windows<P: Platform>(
    path: &std::path::Path,
    allow_sid: &str,
    service: &mut HelperService<P>,
    idle: Option<Duration>,
) -> ServeExit {
    use tobro_osapi::win_pipe::{PipeSecurity, peer_sid, sid_from_string};

    let (security, expected_sid) =
        match (PipeSecurity::for_sid(allow_sid), sid_from_string(allow_sid)) {
            (Ok(security), Ok(sid)) => (security, sid),
            (Err(error), _) | (_, Err(error)) => {
                return ServeExit::BindError(format!(
                    "the allowed client SID (--allow-sid) is not usable: {error}"
                ));
            }
        };
    let mut gate = PeerGate::with_allowed_sid(expected_sid);

    loop {
        let server = match security.create_server(path) {
            Ok(server) => server,
            Err(error) => return ServeExit::BindError(error.to_string()),
        };
        // Wait for a client to connect, but keep honoring shutdown/idle
        // while waiting.
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
            _exit = disconnect_window(service.state().active) => {
                drop(server);
                teardown_if_active(service, "daemon disconnect grace").await;
                return ServeExit::DisconnectTimeout;
            }
            connected = server.connect() => {
                if let Err(error) = connected {
                    tracing::warn!("pipe connect failed: {error}");
                    continue;
                }
                // Read the client's SID before any protocol bytes are
                // dispatched. A failure is an unverifiable peer, which the
                // gate denies.
                let peer = match peer_sid(&server) {
                    Ok(sid) => PeerIdentity::Sid(sid),
                    Err(error) => {
                        tracing::warn!("could not read the connecting user's SID: {error}");
                        PeerIdentity::Unverifiable
                    }
                };
                let mut framed = Framed::new(server, HelperCodec::new());
                serve_connection(&mut framed, service, &mut gate, &peer).await;
            }
        }
    }
}

/// Start a disconnect grace only while a plan is active.  Reconnecting
/// through any new accept resets this arm because the accept loop is rebuilt.
async fn disconnect_window(active: bool) -> () {
    if active {
        tokio::time::sleep(DISCONNECT_GRACE).await;
    } else {
        std::future::pending::<()>().await;
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
            udp_policy: tobro_tun::UdpPolicy::default(),
            forwarding: None,
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
        assert!(!gate.authorize(&PeerIdentity::Unverifiable));
        assert_eq!(gate.locked_uid(), None);

        // First uid peer locks the gate.
        assert!(gate.authorize(&PeerIdentity::Uid(1000)));
        assert_eq!(gate.locked_uid(), Some(1000));

        // Same uid admitted, different uid denied.
        assert!(gate.authorize(&PeerIdentity::Uid(1000)));
        assert!(!gate.authorize(&PeerIdentity::Uid(1001)));

        // Unverifiable stays denied after locking too.
        assert!(!gate.authorize(&PeerIdentity::Unverifiable));
    }

    #[test]
    fn gate_denies_every_sid_without_a_configured_sid() {
        // A helper that was never told which user it serves must not admit a
        // SID peer, even a well-formed one.
        let mut gate = PeerGate::new();
        assert!(!gate.authorize(&PeerIdentity::Sid(vec![
            1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
        ])));
        assert_eq!(gate.locked_uid(), None);
    }

    #[test]
    fn gate_admits_only_the_configured_sid() {
        let allowed = vec![1u8, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0];
        let mut gate = PeerGate::with_allowed_sid(allowed.clone());

        // The installer-recorded SID is admitted, repeatedly (one check per
        // connection; the gate is not consumed).
        assert!(gate.authorize(&PeerIdentity::Sid(allowed.clone())));
        assert!(gate.authorize(&PeerIdentity::Sid(allowed.clone())));

        // Comparison is exact: one changed byte is a different user.
        let mut other = allowed;
        *other.last_mut().expect("the SID fixture is non-empty") = 42;
        assert!(!gate.authorize(&PeerIdentity::Sid(other)));

        // Unverifiable peers stay denied, and the SID rule never locks a uid.
        assert!(!gate.authorize(&PeerIdentity::Unverifiable));
        assert_eq!(gate.locked_uid(), None);
    }
}

#[cfg(all(test, windows))]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod windows_tests {
    use super::*;
    use tobro_tun::TunHelperClient;

    /// A unique pipe name per test, so concurrently running tests cannot
    /// collide on the machine-wide named-pipe namespace.
    fn pipe_path(tag: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_nanos();
        std::path::PathBuf::from(format!(
            r"\\.\pipe\tobro-helper-test-{tag}-{}-{stamp}",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn current_user_sid_handshakes_against_the_real_loop() {
        let sid = tobro_osapi::win_pipe::current_user_sid_string()
            .expect("the test user always has a SID");
        let path = pipe_path("e2e");
        let serve_path = path.clone();
        let mut service = HelperService::new(crate::NullPlatform);
        let task = tokio::spawn(async move {
            serve_windows(
                &serve_path,
                &sid,
                &mut service,
                Some(Duration::from_millis(400)),
            )
            .await
        });

        // The first pipe instance is created immediately; retry briefly in
        // case the loop has not reached `connect` yet.
        let mut client = TunHelperClient::connect_with_retry(&path, 50, Duration::from_millis(20))
            .await
            .expect("the current user is allowed by the pipe DACL and the gate");
        let info = client.handshake().await.expect("the SID gate admits us");
        assert_eq!(info.protocol_version, tobro_tun::PROTOCOL_VERSION);
        let status = client.status().await.expect("the connection is served");
        assert!(!status.active);

        drop(client);
        // The next pipe instance is created for the next client, but none
        // arrives: the idle window ends the loop.
        assert_eq!(task.await.unwrap(), ServeExit::IdleTimeout);
    }
}
