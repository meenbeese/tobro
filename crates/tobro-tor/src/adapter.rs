//! M1 adapter interface around Arti.
//!
//! This wraps the M0 two-phase pattern (bootstrap observer, then serving proxy)
//! required by Arti 2.8's `arti::run_proxy` ownership/lock behavior:
//! - `arti::run_proxy` owns the client it serves and holds an exclusive state-dir lock.
//! - An observer client used for bootstrap/status must be dropped before serving.
//!
//! M1 uses a supervised start: bootstrap to "ready for traffic" with progress events,
//! then hand off to a serving task. Stop cancels the serving task.
//!
//! `arti::run_proxy` returns a `!Send` future, so the serving phase is returned as a
//! future for the caller/supervisor to run (e.g. on a dedicated runtime/thread or local task).

use std::path::PathBuf;

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};

use crate::{BootstrapEvent, Tor};

/// Listener configuration for the local proxies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// SOCKS5 port (also carries HTTP CONNECT while listeners are combined).
    pub socks_port: u16,
    /// HTTP CONNECT port (reported; served on `socks_port` while combined).
    pub http_port: u16,
    /// UDP DNS proxy port.
    pub dns_port: u16,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            socks_port: crate::DEFAULT_SOCKS_PORT,
            http_port: crate::DEFAULT_HTTP_PORT,
            dns_port: crate::DEFAULT_DNS_PORT,
        }
    }
}

impl ListenerConfig {
    /// Effective HTTP port (follows SOCKS when unset/combined).
    pub fn effective_http_port(&self) -> u16 {
        if self.http_port == 0 {
            self.socks_port
        } else {
            self.http_port
        }
    }
}

/// High-level adapter status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdapterStatus {
    /// Not started.
    Stopped,
    /// Bootstrapping in progress.
    Bootstrapping {
        /// Best-effort percentage.
        percent: u8,
        /// Detail message.
        detail: String,
    },
    /// Bootstrapped and local listeners are serving.
    Ready {
        /// Active listener configuration.
        listeners: ListenerConfig,
    },
    /// Failed.
    Failed {
        /// User-safe message.
        message: String,
    },
}

/// Events emitted by the adapter.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AdapterEvent {
    /// Bootstrap progress update.
    Bootstrap(BootstrapEvent),
    /// Status changed.
    Status(AdapterStatus),
}

/// Control handle for observing a prepared/running service.
#[derive(Debug, Clone)]
pub struct ServiceControl {
    status_tx: watch::Sender<AdapterStatus>,
    events_tx: broadcast::Sender<AdapterEvent>,
    listeners: ListenerConfig,
}

impl ServiceControl {
    /// Current status snapshot.
    pub fn status(&self) -> AdapterStatus {
        self.status_tx.borrow().clone()
    }

    /// Subscribe to events.
    pub fn subscribe(&self) -> broadcast::Receiver<AdapterEvent> {
        self.events_tx.subscribe()
    }

    /// Active listener configuration.
    pub fn listeners(&self) -> &ListenerConfig {
        &self.listeners
    }

    fn set_status(&self, status: AdapterStatus) {
        let _ = self.status_tx.send(status.clone());
        let _ = self.events_tx.send(AdapterEvent::Status(status));
    }
}

/// Prepared service: bootstrap is complete and the serving future is ready to run.
///
/// The serving future is `!Send` because `arti::run_proxy` is not `Send` in Arti 2.8.
pub struct PreparedService {
    /// Observation/control handle.
    pub control: ServiceControl,
    state_dir: PathBuf,
    cache_dir: PathBuf,
    listeners: ListenerConfig,
}

impl std::fmt::Debug for PreparedService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedService")
            .field("listeners", &self.listeners)
            .finish_non_exhaustive()
    }
}

impl PreparedService {
    /// Run the proxy until `shutdown` resolves or the proxy exits/fails.
    ///
    /// This future is `!Send`; run it with `tokio::task::spawn_local`, a current-thread
    /// runtime, or a dedicated thread.
    pub async fn serve(
        self,
        mut shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> anyhow::Result<()> {
        let control = self.control.clone();
        let serve = crate::serve(
            &self.state_dir,
            &self.cache_dir,
            self.listeners.socks_port,
            self.listeners.dns_port,
        );
        tokio::pin!(serve);

        let result = tokio::select! {
            biased;
            _ = &mut shutdown => {
                control.set_status(AdapterStatus::Stopped);
                Ok(())
            }
            result = &mut serve => {
                match &result {
                    Ok(()) => control.set_status(AdapterStatus::Stopped),
                    Err(err) => control.set_status(AdapterStatus::Failed {
                        message: format!("{err:#}"),
                    }),
                }
                result
            }
        };
        result
    }
}

/// Bootstrap Tor and prepare local listeners.
///
/// `state_dir`/`cache_dir` are shared across bootstrap and serving phases; the
/// observer is dropped before serving to release the state-dir lock.
///
/// Returns once bootstrap is complete. Call [`PreparedService::serve`] to run the
/// proxy (a `!Send` future) until shutdown.
pub async fn bootstrap_and_prepare(
    state_dir: PathBuf,
    cache_dir: PathBuf,
    listeners: ListenerConfig,
) -> anyhow::Result<PreparedService> {
    let (status_tx, _status_rx) = watch::channel(AdapterStatus::Stopped);
    let (events_tx, _events_rx) = broadcast::channel(64);
    let control = ServiceControl {
        status_tx,
        events_tx,
        listeners: listeners.clone(),
    };

    control.set_status(AdapterStatus::Bootstrapping {
        percent: 0,
        detail: "starting".to_owned(),
    });

    let observer = Tor::create(&state_dir, &cache_dir)
        .await
        .context("could not create the Arti client")?;

    let events_for_bootstrap = control.events_tx.clone();
    let status_for_bootstrap = control.status_tx.clone();
    let events_for_status = control.events_tx.clone();
    observer
        .bootstrap(move |event| {
            let status = AdapterStatus::Bootstrapping {
                percent: event.percent,
                detail: event.detail.clone(),
            };
            let _ = status_for_bootstrap.send(status.clone());
            let _ = events_for_bootstrap.send(AdapterEvent::Bootstrap(event));
            let _ = events_for_status.send(AdapterEvent::Status(status));
        })
        .await
        .context("Arti bootstrap failed")?;

    // Release the exclusive state-dir lock before starting the serving client.
    drop(observer);

    control.set_status(AdapterStatus::Ready {
        listeners: listeners.clone(),
    });

    Ok(PreparedService {
        control,
        state_dir,
        cache_dir,
        listeners,
    })
}

/// Convenience: create status/event channels for an externally managed service.
pub fn channels() -> (
    watch::Sender<AdapterStatus>,
    broadcast::Sender<AdapterEvent>,
) {
    let (status_tx, _status_rx) = watch::channel(AdapterStatus::Stopped);
    let (events_tx, _events_rx) = broadcast::channel(64);
    (status_tx, events_tx)
}
