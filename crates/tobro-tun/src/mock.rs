//! In-memory mock of `tobro-helper` for tests.
//!
//! Implements the protocol semantics without touching the system: plans are
//! recorded in a [`MockState`], generations increment, and an optional
//! responder hook can override or suppress replies to exercise error paths.
//! The real helper binary (M7 T3) replaces this in production; the accept
//! loop here is deliberately the same shape so it can be promoted then.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use futures::{SinkExt, StreamExt};

use crate::protocol::{
    DEFAULT_INTERFACE_NAME, HelperRequest, HelperResponse, HelperStatus, KillSwitchMode, TunnelPlan,
};
use crate::{HelperCodec, HelperError, HelperMessage, reject_codes, transport::default_endpoint};

/// Responder override: what the mock should do with a request.
#[derive(Debug)]
pub enum MockReply {
    /// Use the built-in semantics.
    Default,
    /// Answer with this response instead.
    Respond(HelperResponse),
    /// Send nothing; the client will hit its timeout.
    Silence,
}

/// Responder hook consulted for every request.
pub type MockResponder = dyn Fn(&HelperRequest) -> MockReply + Send + Sync + 'static;

/// Mutable state the mock helper serves from.
#[derive(Debug, Default)]
pub struct MockState {
    /// Current generation counter.
    pub generation: u64,
    /// True while a plan is applied.
    pub active: bool,
    /// Interface carrying the current plan.
    pub interface: Option<String>,
    /// Kill switch mode of the current plan.
    pub kill_switch: KillSwitchMode,
    /// The last applied plan, for assertions.
    pub last_plan: Option<TunnelPlan>,
    /// Number of applied plans.
    pub applies: usize,
    /// Number of teardowns.
    pub teardowns: usize,
    /// Number of completed handshakes.
    pub handshakes: usize,
}

impl MockState {
    /// Snapshot for `status` replies.
    pub fn status(&self) -> HelperStatus {
        HelperStatus {
            active: self.active,
            generation: self.generation,
            interface: self.interface.clone(),
            kill_switch: self.kill_switch,
            applied_at_ms: None,
        }
    }
}

/// A running mock helper. Drop it (or call [`MockHelper::shutdown`]) to stop
/// listening and remove the endpoint.
pub struct MockHelper {
    path: PathBuf,
    state: Arc<Mutex<MockState>>,
    responder: Arc<std::sync::RwLock<Option<Arc<MockResponder>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for MockHelper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockHelper")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl MockHelper {
    /// Start a mock helper listening at `path`.
    pub async fn start(path: impl AsRef<Path>) -> Result<Self, HelperError> {
        let path = path.as_ref().to_path_buf();
        let listener = crate::transport::bind_listener(&path).await?;
        let state: Arc<Mutex<MockState>> = Arc::default();
        let responder: Arc<std::sync::RwLock<Option<Arc<MockResponder>>>> =
            Arc::new(std::sync::RwLock::new(None));

        let task_state = state.clone();
        let task_responder = responder.clone();
        #[cfg(windows)]
        let accept_path = path.clone();
        let task = tokio::spawn(async move {
            // Sequential accept loop: the helper serves one client at a time,
            // exactly like the production plan.
            #[cfg(unix)]
            {
                let listener = listener;
                loop {
                    let (stream, _address) = match listener.accept().await {
                        Ok(pair) => pair,
                        Err(_) => return,
                    };
                    let mut connection = tokio_util::codec::Framed::new(stream, HelperCodec::new());
                    serve_connection(&mut connection, &task_state, &task_responder).await;
                }
            }
            #[cfg(windows)]
            {
                let mut pending = listener;
                loop {
                    if pending.connect().await.is_err() {
                        return;
                    }
                    let mut connection =
                        tokio_util::codec::Framed::new(pending, HelperCodec::new());
                    serve_connection(&mut connection, &task_state, &task_responder).await;
                    pending = match crate::transport::bind_listener(&accept_path).await {
                        Ok(next) => next,
                        Err(_) => return,
                    };
                }
            }
        });

        Ok(Self {
            path,
            state,
            responder,
            task,
        })
    }

    /// Start a mock helper on the default endpoint.
    pub async fn start_default() -> Result<Self, HelperError> {
        Self::start(default_endpoint()).await
    }

    /// Endpoint the mock is listening on.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Shared state for assertions between calls.
    pub fn state(&self) -> Arc<Mutex<MockState>> {
        self.state.clone()
    }

    /// Install (or clear, with `None`) a responder override.
    pub fn set_responder(&self, responder: Option<Arc<MockResponder>>) {
        *self
            .responder
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = responder;
    }

    /// Stop the mock and remove its endpoint.
    pub async fn shutdown(self) {
        self.task.abort();
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Serve one connection to completion (lock-step request/response).
async fn serve_connection(
    connection: &mut (
             impl futures::Sink<HelperMessage, Error = HelperError>
             + futures::Stream<Item = Result<HelperMessage, HelperError>>
             + Unpin
         ),
    state: &Arc<Mutex<MockState>>,
    responder: &Arc<std::sync::RwLock<Option<Arc<MockResponder>>>>,
) {
    while let Some(message) = connection.next().await {
        let Ok(HelperMessage::Request(request)) = message else {
            let _ = connection
                .send(HelperMessage::Response(HelperResponse::Rejected {
                    code: reject_codes::INTERNAL,
                    message: "expected a request".to_owned(),
                }))
                .await;
            return;
        };
        let response = override_or_default(request, state, responder);
        let Some(response) = response else {
            // Responder suppressed the reply: leave the client hanging.
            continue;
        };
        if connection
            .send(HelperMessage::Response(response))
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Consult the responder override, falling back to built-in semantics.
fn override_or_default(
    request: HelperRequest,
    state: &Arc<Mutex<MockState>>,
    responder: &Arc<std::sync::RwLock<Option<Arc<MockResponder>>>>,
) -> Option<HelperResponse> {
    if let Some(hook) = responder
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
    {
        return match hook(&request) {
            MockReply::Default => builtin(request, state),
            MockReply::Respond(response) => Some(response),
            MockReply::Silence => None,
        };
    }
    builtin(request, state)
}

/// Built-in mock semantics.
fn builtin(request: HelperRequest, state: &Arc<Mutex<MockState>>) -> Option<HelperResponse> {
    let mut state = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Some(match request {
        HelperRequest::Handshake { .. } => {
            state.handshakes += 1;
            HelperResponse::HandshakeOk {
                protocol_version: crate::PROTOCOL_VERSION,
                helper_version: "mock".to_owned(),
            }
        }
        HelperRequest::ApplyPlan { plan } => {
            if let Err(error) = plan.validate() {
                HelperResponse::Rejected {
                    code: reject_codes::VALIDATION,
                    message: error.to_string(),
                }
            } else {
                state.generation += 1;
                state.active = true;
                state.interface = Some(plan.effective_interface().to_owned());
                state.kill_switch = plan.kill_switch;
                state.last_plan = Some(plan);
                state.applies += 1;
                HelperResponse::Applied {
                    generation: state.generation,
                    interface: state
                        .interface
                        .clone()
                        .unwrap_or_else(|| DEFAULT_INTERFACE_NAME.to_owned()),
                }
            }
        }
        HelperRequest::Status {} => HelperResponse::Status {
            state: state.status(),
        },
        HelperRequest::Teardown {} => {
            state.generation += 1;
            state.active = false;
            state.interface = None;
            state.kill_switch = KillSwitchMode::Disabled;
            state.teardowns += 1;
            HelperResponse::TornDown {
                generation: state.generation,
            }
        }
    })
}
