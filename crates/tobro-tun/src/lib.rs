//! Helper protocol and client for `tobro-helper`, the privileged TUN helper
//! (M7, plan §4.7/§10.5).
//!
//! # Trust model
//!
//! `tobro-helper` runs as root/system and owns the TUN device, routes, and
//! DNS settings. The unprivileged daemon (`tobrod`) is the only intended
//! client. The protocol is deliberately narrow:
//!
//! - **Fixed command set** — [`HelperRequest`] has exactly four commands
//!   (`handshake`, `apply_plan`, `status`, `teardown`); there is no escape
//!   hatch, no shell, no arbitrary path or command argument.
//! - **Converged desired state** — every [`TunnelPlan`] carries the complete
//!   desired routing state (device, routes, DNS, kill switch). The helper
//!   applies plans idempotently, which also makes crash recovery a plain
//!   re-`apply_plan` instead of a replay log.
//! - **Strict input validation** — all inputs (interface names, prefixes,
//!   gateways, DNS servers, counts) are validated by
//!   [`TunnelPlan::validate`] on the client before sending and re-validated
//!   by the helper on receipt. Malformed frames are rejected, never trusted.
//! - **No network listeners** — the helper listens on a local IPC endpoint
//!   only (Unix socket with `0600` permissions / Windows named pipe).
//! - **Small frames** — helper frames are capped at [`MAX_FRAME_LEN`],
//!   far below the main IPC limit.
//!
//! # Wire format
//!
//! Every frame is a 4-byte big-endian length followed by a UTF-8 JSON
//! document, mirroring `tobro-ipc` framing but with its own (smaller) cap.
//! Requests and responses are internally tagged with `"type"`.
//!
//! # Status
//!
//! Protocol only in this milestone: the helper binary itself, the platform
//! TUN backends, and the routing engine land in the following M7 tasks.

mod client;
mod codec;
mod mock;
mod protocol;
mod transport;

pub use client::{AppliedPlan, HelperInfo, TunHelperClient};
pub use codec::HelperCodec;
pub use mock::{MockHelper, MockReply, MockResponder, MockState};
pub use protocol::{
    DEFAULT_INTERFACE_NAME, DEFAULT_TUN_MTU, DnsConfig, HelperMessage, HelperRequest,
    HelperResponse, HelperStatus, KillSwitchMode, MAX_DEVICE_ADDRESSES, MAX_DNS_SERVERS,
    MAX_INTERFACE_NAME_LEN, MAX_ROUTES, MAX_TUN_MTU, MIN_TUN_MTU, PROTOCOL_VERSION, Prefix,
    RouteSpec, TunDevice, TunnelPlan, is_usable_dns_server, reject_codes, validate_interface_name,
};
pub use transport::{HelperStream, bind_listener, default_endpoint, open_stream};

/// Largest accepted helper frame, in bytes. A maximal plan (512 routes) is a
/// few dozen KiB of JSON; 128 KiB leaves comfortable headroom while staying
/// far below the daemon IPC limit.
pub const MAX_FRAME_LEN: usize = 128 * 1024;

/// Per-call timeout used by [`TunHelperClient`] unless overridden. Helper
/// commands are local and fast; five seconds is generous.
pub const DEFAULT_CALL_TIMEOUT_MS: u64 = 5_000;

/// Errors produced by the helper protocol and client.
#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    /// Transport/I-O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Malformed JSON on the wire.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Well-formed JSON that violates the helper protocol (wrong response
    /// type, oversized frame, unknown command tag, ...).
    #[error("protocol error: {0}")]
    Protocol(String),
    /// A plan or input failed validation. Caught on the client before
    /// sending and re-checked by the helper on receipt.
    #[error("validation error: {0}")]
    Validation(String),
    /// The helper refused a well-formed request; see [`reject_codes`].
    #[error("helper rejected the request (code {code}): {message}")]
    Rejected { code: u32, message: String },
    /// The helper closed the connection.
    #[error("connection closed")]
    Closed,
    /// The call exceeded its timeout.
    #[error("helper call timed out after {timeout_ms} ms")]
    Timeout { timeout_ms: u64 },
    /// The helper speaks an incompatible protocol version.
    #[error(
        "helper speaks protocol version {helper}, this client speaks {client}; upgrade tobro or tobro-helper"
    )]
    IncompatibleVersion { helper: u32, client: u32 },
    /// This platform has no helper transport wired up yet.
    #[error("the TUN helper transport is not available on this platform")]
    Unsupported,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::protocol::{KillSwitchMode, TunDevice};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use tokio_util::codec::{Decoder, Encoder};

    fn plan() -> TunnelPlan {
        TunnelPlan {
            device: TunDevice {
                name: "tobro0".to_owned(),
                addresses: vec![Prefix {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 111, 222, 252)),
                    prefix_len: 30,
                }],
                mtu: DEFAULT_TUN_MTU,
            },
            routes: vec![RouteSpec {
                destination: Prefix {
                    addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    prefix_len: 0,
                },
                gateway: None,
                metric: None,
            }],
            bypass_routes: vec![RouteSpec {
                destination: Prefix {
                    addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                    prefix_len: 24,
                },
                gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                metric: Some(50),
            }],
            dns: DnsConfig {
                servers: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            },
            kill_switch: KillSwitchMode::Block,
        }
    }

    fn codec_round_trip(message: HelperMessage) {
        let mut codec = HelperCodec::new();
        let mut buffer = bytes::BytesMut::new();
        codec
            .encode(message.clone(), &mut buffer)
            .expect("encode must succeed");
        assert_eq!(
            codec.decode(&mut buffer).expect("decode must succeed"),
            Some(message)
        );
    }

    #[test]
    fn codec_round_trips_every_request_variant() {
        codec_round_trip(HelperMessage::Request(HelperRequest::Handshake {
            protocol_version: PROTOCOL_VERSION,
        }));
        codec_round_trip(HelperMessage::Request(HelperRequest::ApplyPlan {
            plan: plan(),
        }));
        codec_round_trip(HelperMessage::Request(HelperRequest::Status {}));
        codec_round_trip(HelperMessage::Request(HelperRequest::Teardown {}));
    }

    #[test]
    fn codec_round_trips_every_response_variant() {
        codec_round_trip(HelperMessage::Response(HelperResponse::HandshakeOk {
            protocol_version: PROTOCOL_VERSION,
            helper_version: "1.0.0".to_owned(),
        }));
        codec_round_trip(HelperMessage::Response(HelperResponse::Applied {
            generation: 7,
            interface: "tobro0".to_owned(),
        }));
        codec_round_trip(HelperMessage::Response(HelperResponse::Status {
            state: HelperStatus {
                active: true,
                generation: 7,
                interface: Some("tobro0".to_owned()),
                kill_switch: KillSwitchMode::Block,
                applied_at_ms: Some(1_700_000_000_000),
            },
        }));
        codec_round_trip(HelperMessage::Response(HelperResponse::TornDown {
            generation: 8,
        }));
        codec_round_trip(HelperMessage::Response(HelperResponse::Rejected {
            code: reject_codes::VALIDATION,
            message: "bad plan".to_owned(),
        }));
    }

    #[test]
    fn codec_rejects_unknown_tags_and_oversized_frames() {
        let mut codec = HelperCodec::new();
        // Unknown request tag.
        let mut buffer = bytes::BytesMut::new();
        buffer.extend_from_slice(&(9u32).to_be_bytes());
        buffer.extend_from_slice(br#"{"type":"reboot"}"#);
        assert!(codec.decode(&mut buffer).is_err());

        // Frame longer than the cap is refused by the length codec.
        let mut big = bytes::BytesMut::new();
        let oversized = vec![b'a'; MAX_FRAME_LEN + 1];
        big.extend_from_slice(&u32::try_from(oversized.len()).unwrap().to_be_bytes());
        big.extend_from_slice(&oversized);
        assert!(codec.decode(&mut big).is_err());
    }

    #[tokio::test]
    async fn client_and_mock_helper_exchange_the_full_command_set() -> Result<(), HelperError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("helper.sock");
        let helper = MockHelper::start(&path).await?;
        let mut client = TunHelperClient::connect(&path).await?;

        let info = client.handshake().await?;
        assert_eq!(info.protocol_version, PROTOCOL_VERSION);
        assert_eq!(info.helper_version, "mock");

        let applied = client.apply_plan(&plan()).await?;
        assert_eq!(applied.generation, 1);
        assert_eq!(applied.interface, "tobro0");

        let status = client.status().await?;
        assert!(status.active);
        assert_eq!(status.kill_switch, KillSwitchMode::Block);
        assert_eq!(status.interface.as_deref(), Some("tobro0"));

        let generation = client.teardown().await?;
        assert_eq!(generation, 2);
        let status = client.status().await?;
        assert!(!status.active);
        assert_eq!(status.kill_switch, KillSwitchMode::Disabled);

        let state = helper.state();
        {
            let state = state.lock().unwrap();
            assert_eq!(state.applies, 1);
            assert_eq!(state.teardowns, 1);
            assert_eq!(state.handshakes, 1);
            assert!(state.last_plan.is_some());
        }
        drop(state);

        helper.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn connect_with_retry_waits_for_a_slow_helper() -> Result<(), HelperError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("helper.sock");
        // The helper comes up only after the first failed attempt.
        let helper_path = path.clone();
        let spawn = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            MockHelper::start(&helper_path).await
        });
        let mut client =
            TunHelperClient::connect_with_retry(&path, 5, std::time::Duration::from_millis(20))
                .await?;
        client.handshake().await?;
        drop(client);
        let helper = spawn.await.expect("mock task must not panic")?;
        helper.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn version_mismatch_is_rejected_at_handshake() -> Result<(), HelperError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("helper.sock");
        let helper = MockHelper::start(&path).await?;
        helper.set_responder(Some(Arc::new(|request| {
            matches!(request, HelperRequest::Handshake { .. })
                .then(|| {
                    MockReply::Respond(HelperResponse::HandshakeOk {
                        protocol_version: PROTOCOL_VERSION + 1,
                        helper_version: "future".to_owned(),
                    })
                })
                .unwrap_or(MockReply::Default)
        })));
        let mut client = TunHelperClient::connect(&path).await?;
        let error = client.handshake().await.expect_err("must mismatch");
        assert!(matches!(
            error,
            HelperError::IncompatibleVersion {
                helper: 2,
                client: 1
            }
        ));
        helper.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn rejections_surface_as_helper_errors() -> Result<(), HelperError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("helper.sock");
        let helper = MockHelper::start(&path).await?;
        helper.set_responder(Some(Arc::new(|request| {
            matches!(request, HelperRequest::ApplyPlan { .. })
                .then(|| {
                    MockReply::Respond(HelperResponse::Rejected {
                        code: reject_codes::DEVICE_ERROR,
                        message: "no /dev/net/tun".to_owned(),
                    })
                })
                .unwrap_or(MockReply::Default)
        })));
        let mut client = TunHelperClient::connect(&path).await?;
        client.handshake().await?;
        let error = client.apply_plan(&plan()).await.expect_err("must reject");
        assert!(matches!(
            error,
            HelperError::Rejected {
                code: reject_codes::DEVICE_ERROR,
                ..
            }
        ));
        helper.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn silent_helper_times_out() -> Result<(), HelperError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("helper.sock");
        let helper = MockHelper::start(&path).await?;
        // Responder suppresses every reply: the client must hit its timeout
        // instead of hanging forever.
        helper.set_responder(Some(Arc::new(|_request| MockReply::Silence)));
        let mut client = TunHelperClient::connect(&path).await?;
        client.set_timeout(std::time::Duration::from_millis(50));
        let error = client.status().await.expect_err("must time out");
        assert!(matches!(error, HelperError::Timeout { timeout_ms: 50 }));
        helper.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn a_second_client_is_served_after_the_first_finishes() -> Result<(), HelperError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("helper.sock");
        let helper = MockHelper::start(&path).await?;
        {
            let mut first = TunHelperClient::connect(&path).await?;
            first.handshake().await?;
            first.status().await?;
        }
        let mut second = TunHelperClient::connect(&path).await?;
        second.handshake().await?;
        helper.shutdown().await;
        Ok(())
    }
}
