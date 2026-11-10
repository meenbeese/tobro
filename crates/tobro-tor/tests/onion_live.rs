//! Live-network tests for hosted onion services (M5).
//!
//! These tests publish real onion services over the Tor network and connect
//! through real clients, so they are `#[ignore]`-gated. Run them explicitly
//! with:
//!
//! ```sh
//! cargo test -p tobro-tor --test onion_live -- --ignored --nocapture
//! ```
//!
//! They cover the M5 exit criteria:
//! - publishing a reachable (non-authorized) service, and
//! - a service with restricted discovery (client authorization): a client with
//!   the authorized desc-enc key reaches it, one without must not.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr as _;
use std::time::{Duration, Instant};

use arti_client::TorClient;
use arti_client::config::TorClientConfigBuilder;
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tor_hscrypto::pk::{HsClientDescEncKeypair, HsClientDescEncSecretKey, HsId};
use tor_keymgr::KeystoreSelector;
use tor_rtcompat::PreferredRuntime;

use tobro_tor::onion_service::{RunningHostedService, launch};
use tobro_tor::{HostedOnionPort, HostedOnionService, OnionServiceRuntimeStatus};

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(300);
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(180);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(240);

fn client_config(state: &Path, cache: &Path) -> arti_client::TorClientConfig {
    TorClientConfigBuilder::from_directories(state, cache)
        .build()
        .expect("valid client config")
}

/// Create a bootstrapped client with its own state/cache directories.
async fn bootstrapped_client(
    state: &Path,
    cache: &Path,
) -> std::sync::Arc<TorClient<PreferredRuntime>> {
    let _ = PreferredRuntime::current().expect("tokio runtime is a tor runtime");
    tokio::time::timeout(BOOTSTRAP_TIMEOUT, async {
        TorClient::create_bootstrapped(client_config(state, cache))
            .await
            .expect("client bootstrap")
    })
    .await
    .expect("bootstrap within timeout")
}

/// Start a local echo server; returns its socket address.
async fn spawn_echo_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo listener");
    let addr = listener.local_addr().expect("echo listener addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut read_half, mut write_half) = tokio::io::split(stream);
                let mut buf = Vec::new();
                if tokio::io::AsyncReadExt::read_to_end(&mut read_half, &mut buf)
                    .await
                    .is_ok()
                    && !buf.is_empty()
                {
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut write_half, &buf).await;
                    let _ = tokio::io::AsyncWriteExt::flush(&mut write_half).await;
                }
            });
        }
    });
    addr
}

/// Poll until the service reports a published `.onion` address.
async fn wait_for_address(running: &RunningHostedService) -> String {
    let deadline = Instant::now() + PUBLISH_TIMEOUT;
    loop {
        if let Some(addr) = running.onion_address() {
            assert!(addr.ends_with(".onion"), "unexpected address {addr}");
            return addr;
        }
        assert!(
            Instant::now() < deadline,
            "onion address was not published within {PUBLISH_TIMEOUT:?}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn service_spec(
    name: &str,
    target_port: u16,
    authorized_clients_dir: Option<String>,
) -> HostedOnionService {
    HostedOnionService {
        id: format!("test-{name}"),
        nickname: format!("tobro-live-{name}"),
        name: name.to_owned(),
        ports: vec![HostedOnionPort {
            virt_port: 80,
            target_host: "127.0.0.1".to_owned(),
            target_port,
        }],
        authorized_clients_dir,
    }
}

/// M5: publish a reachable service and connect to it through an independent
/// client over the Tor network.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires an unrestricted connection to the real Tor network"]
async fn publish_reachable_service() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = spawn_echo_server().await;

    // Publisher: hosts the service with a managed state directory.
    let publisher = bootstrapped_client(&dir.path().join("state"), &dir.path().join("cache")).await;
    let (running, status) =
        launch(&publisher, service_spec("reachable", target.port(), None)).expect("launch ok");
    assert!(matches!(
        status,
        OnionServiceRuntimeStatus::Starting | OnionServiceRuntimeStatus::Published { .. }
    ));

    let addr = wait_for_address(&running).await;
    println!("service published at {addr}");

    // Visitor: an independent client (fresh state) reaching the service.
    let visitor = bootstrapped_client(
        &dir.path().join("visitor-state"),
        &dir.path().join("visitor-cache"),
    )
    .await;
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, visitor.connect((addr.as_str(), 80u16)))
        .await
        .expect("connect within timeout")
        .expect("onion connect ok");
    stream.write_all(b"ping").await.expect("write ping");
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.expect("read echo");
    assert_eq!(&buf, b"ping");
}

/// M5: restricted discovery (client authorization). The authorized client
/// (holding the desc-enc secret key) reaches the service; an unauthorized
/// client (same setup, no key) must fail to connect.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires an unrestricted connection to the real Tor network"]
async fn authorized_vs_unauthorized_client() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = spawn_echo_server().await;

    // Service-side: authorized_clients dir with one client public key.
    let auth_dir = dir.path().join("authorized_clients");
    std::fs::create_dir_all(&auth_dir).expect("create authorized_clients dir");
    let keypair = HsClientDescEncKeypair::generate(&mut tor_llcrypto::rng::CautiousRng);
    let auth_line = keypair.public().to_string(); // "descriptor:x25519:<base32>"
    assert!(auth_line.starts_with("descriptor:x25519:"));
    std::fs::write(auth_dir.join("client-a.auth"), format!("{auth_line}\n"))
        .expect("write .auth file");

    let publisher = bootstrapped_client(&dir.path().join("state"), &dir.path().join("cache")).await;
    let (running, _status) = launch(
        &publisher,
        service_spec("authz", target.port(), Some(auth_dir.display().to_string())),
    )
    .expect("launch ok");
    let addr = wait_for_address(&running).await;
    println!("restricted-discovery service published at {addr}");
    let hsid = HsId::from_str(&addr).expect("valid HsId");

    // The client secret key is reconstructed from the keypair (the public
    // half was shared with the service above).
    let secret = HsClientDescEncSecretKey::from(keypair.secret().as_ref().clone());

    // Authorized client: installs the desc-enc key, then connects.
    let authorized = bootstrapped_client(
        &dir.path().join("authorized-state"),
        &dir.path().join("authorized-cache"),
    )
    .await;
    authorized
        .insert_service_discovery_key(KeystoreSelector::Primary, hsid, secret)
        .expect("install client authorization key");

    let mut stream =
        tokio::time::timeout(CONNECT_TIMEOUT, authorized.connect((addr.as_str(), 80u16)))
            .await
            .expect("connect within timeout")
            .expect("authorized client connect ok");
    stream.write_all(b"ping").await.expect("write ping");
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.expect("read echo");
    assert_eq!(&buf, b"ping");

    // Unauthorized client: identical setup, no key material. The descriptor's
    // introduction points are encrypted for authorized clients only, so the
    // connection must fail.
    let unauthorized = bootstrapped_client(
        &dir.path().join("unauthorized-state"),
        &dir.path().join("unauthorized-cache"),
    )
    .await;
    let result = tokio::time::timeout(
        CONNECT_TIMEOUT,
        unauthorized.connect((addr.as_str(), 80u16)),
    )
    .await
    .expect("connect attempt returns within timeout");
    assert!(
        result.is_err(),
        "unauthorized client must not reach the restricted-discovery service"
    );
}
