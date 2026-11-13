//! Daemon-side client for the privileged TUN helper.
//!
//! One [`TunHelperClient`] drives a single lock-step connection: send one
//! request, await exactly one matching response. Every call is bounded by a
//! timeout and plans are validated client-side before anything privileged
//! is asked for.

use std::path::Path;
use std::time::Duration;

use futures::{SinkExt, StreamExt};

use crate::HelperError;
use crate::protocol::{HelperRequest, HelperResponse, HelperStatus, PROTOCOL_VERSION, TunnelPlan};
use crate::transport::{HelperStream, open_stream};

/// Client side of the helper protocol.
#[derive(Debug)]
pub struct TunHelperClient {
    stream: HelperStream,
    timeout: Duration,
}

impl TunHelperClient {
    /// Connect to the helper endpoint and verify the protocol version via
    /// the handshake.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, HelperError> {
        let stream = open_stream(path.as_ref()).await?;
        Ok(Self {
            stream,
            timeout: Duration::from_millis(crate::DEFAULT_CALL_TIMEOUT_MS),
        })
    }

    /// Connect with bounded retries: useful right after the helper (re)starts,
    /// when the socket/pipe may not be ready yet.
    pub async fn connect_with_retry(
        path: impl AsRef<Path>,
        attempts: u32,
        delay: Duration,
    ) -> Result<Self, HelperError> {
        let path = path.as_ref();
        let mut last = HelperError::Closed;
        for attempt in 0..attempts {
            if attempt > 0 {
                tokio::time::sleep(delay).await;
            }
            match open_stream(path).await {
                Ok(stream) => {
                    return Ok(Self {
                        stream,
                        timeout: Duration::from_millis(crate::DEFAULT_CALL_TIMEOUT_MS),
                    });
                }
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// Override the per-call timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Perform the handshake and check protocol-version compatibility.
    pub async fn handshake(&mut self) -> Result<HelperInfo, HelperError> {
        let response = self
            .send_receive(HelperRequest::Handshake {
                protocol_version: PROTOCOL_VERSION,
            })
            .await?;
        let HelperResponse::HandshakeOk {
            protocol_version,
            helper_version,
        } = response
        else {
            return Err(self.unexpected(response, "handshake_ok"));
        };
        if protocol_version != PROTOCOL_VERSION {
            return Err(HelperError::IncompatibleVersion {
                helper: protocol_version,
                client: PROTOCOL_VERSION,
            });
        }
        Ok(HelperInfo {
            protocol_version,
            helper_version,
        })
    }

    /// Validate `plan` client-side, then ask the helper to apply it.
    pub async fn apply_plan(&mut self, plan: &TunnelPlan) -> Result<AppliedPlan, HelperError> {
        plan.validate()?;
        let response = self
            .send_receive(HelperRequest::ApplyPlan { plan: plan.clone() })
            .await?;
        match response {
            HelperResponse::Applied {
                generation,
                interface,
            } => Ok(AppliedPlan {
                generation,
                interface,
            }),
            HelperResponse::Rejected { code, message } => {
                Err(HelperError::Rejected { code, message })
            }
            other => Err(self.unexpected(other, "applied")),
        }
    }

    /// Ask for the helper's current state (heartbeat).
    pub async fn status(&mut self) -> Result<HelperStatus, HelperError> {
        let response = self.send_receive(HelperRequest::Status {}).await?;
        match response {
            HelperResponse::Status { state } => Ok(state),
            HelperResponse::Rejected { code, message } => {
                Err(HelperError::Rejected { code, message })
            }
            other => Err(self.unexpected(other, "status_ok")),
        }
    }

    /// Tear down everything the helper set up (device, routes, DNS, kill
    /// switch). Returns the generation after the teardown.
    pub async fn teardown(&mut self) -> Result<u64, HelperError> {
        let response = self.send_receive(HelperRequest::Teardown {}).await?;
        match response {
            HelperResponse::TornDown { generation } => Ok(generation),
            HelperResponse::Rejected { code, message } => {
                Err(HelperError::Rejected { code, message })
            }
            other => Err(self.unexpected(other, "torn_down")),
        }
    }

    /// Send one request and await exactly one matching response, under the
    /// call timeout.
    async fn send_receive(
        &mut self,
        request: HelperRequest,
    ) -> Result<HelperResponse, HelperError> {
        let timeout_ms = u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX);
        let call = async {
            self.stream
                .send(crate::HelperMessage::Request(request))
                .await?;
            match self.stream.next().await {
                Some(Ok(crate::HelperMessage::Response(response))) => Ok(response),
                Some(Ok(crate::HelperMessage::Request(_))) => Err(HelperError::Protocol(
                    "helper sent a request; only the daemon sends requests".to_owned(),
                )),
                Some(Err(error)) => Err(error),
                None => Err(HelperError::Closed),
            }
        };
        match tokio::time::timeout(self.timeout, call).await {
            Ok(result) => result,
            Err(_) => Err(HelperError::Timeout { timeout_ms }),
        }
    }

    /// A response arrived with the wrong shape for the pending request.
    fn unexpected(&self, response: HelperResponse, expected: &str) -> HelperError {
        HelperError::Protocol(format!(
            "helper replied with {response:?} where {expected:?} was expected"
        ))
    }
}

/// The helper's handshake summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperInfo {
    /// Agreed [`PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// Helper build version (informational).
    pub helper_version: String,
}

/// Confirmation that a plan was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedPlan {
    /// Generation counter after the apply.
    pub generation: u64,
    /// Interface carrying the plan.
    pub interface: String,
}
