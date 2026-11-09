//! M1 daemon supervisor.
//!
//! Drives [`crate::lifecycle::Lifecycle`] and supervises the Tor adapter. Arti's
//! serving future is `!Send` (see `tobro-tor::adapter`), so Tor start/serve runs on
//! a dedicated current-thread runtime thread. The supervisor runs on the main async
//! runtime, accepts commands, updates lifecycle state, and applies restart backoff
//! when desired state is connected and failures are retryable.

use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tracing::{debug, info, warn};

use tobro_tor::adapter::{AdapterEvent, AdapterStatus, ListenerConfig, bootstrap_and_prepare};

use crate::lifecycle::{Desired, Event, Lifecycle, State};

/// Default initial restart backoff.
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Maximum restart backoff.
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Commands sent to the supervisor.
#[derive(Debug)]
pub enum Command {
    /// Request that Tor connect and serve.
    Connect {
        /// State directory.
        state_dir: PathBuf,
        /// Cache directory.
        cache_dir: PathBuf,
        /// Local listener ports.
        listeners: ListenerConfig,
    },
    /// Request that Tor stop serving.
    Disconnect,
    /// Request a new identity (restart client/listeners for new circuits).
    NewIdentity,
    /// Shut down the supervisor.
    Shutdown,
}

/// Snapshot of supervisor state for status/IPC.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Desired intent.
    #[allow(dead_code)] // read by IPC/status consumers as API evolves
    pub desired: Desired,
    /// Lifecycle state.
    pub state: State,
    /// Active listener config when known.
    pub listeners: Option<ListenerConfig>,
}

/// Handle for controlling and observing the supervisor.
#[derive(Debug, Clone)]
pub struct SupervisorHandle {
    cmd_tx: mpsc::Sender<Command>,
    status_rx: watch::Receiver<Snapshot>,
    events_tx: broadcast::Sender<SupervisorEvent>,
}

/// Events emitted by the supervisor (suitable for IPC fanout).
#[derive(Debug, Clone)]
pub enum SupervisorEvent {
    /// Lifecycle snapshot changed.
    StateChanged(Snapshot),
    /// Bootstrap progress/detail.
    BootstrapProgress {
        /// Percentage when known.
        percent: Option<u8>,
        /// Detail message.
        detail: String,
    },
    /// User-safe error/failure message.
    Failed {
        /// Message (must not contain secrets).
        message: String,
    },
    /// Onion service published its `.onion` address.
    OnionPublished {
        /// Store/service id.
        id: String,
        /// Published onion address.
        onion_address: String,
    },
    /// Onion service runtime error.
    OnionError {
        /// Store/service id.
        id: String,
        /// Safe error message.
        message: String,
    },
}

impl SupervisorHandle {
    /// Request connect/start.
    pub async fn connect(
        &self,
        state_dir: PathBuf,
        cache_dir: PathBuf,
        listeners: ListenerConfig,
    ) -> Result<(), mpsc::error::SendError<Command>> {
        self.cmd_tx
            .send(Command::Connect {
                state_dir,
                cache_dir,
                listeners,
            })
            .await
    }

    /// Request disconnect/stop.
    pub async fn disconnect(&self) -> Result<(), mpsc::error::SendError<Command>> {
        self.cmd_tx.send(Command::Disconnect).await
    }

    /// Request a new identity (new circuits). Only meaningful while connected.
    pub async fn new_identity(&self) -> Result<(), mpsc::error::SendError<Command>> {
        self.cmd_tx.send(Command::NewIdentity).await
    }

    /// Request supervisor shutdown.
    pub async fn shutdown(&self) -> Result<(), mpsc::error::SendError<Command>> {
        self.cmd_tx.send(Command::Shutdown).await
    }

    /// Current snapshot.
    pub fn snapshot(&self) -> Snapshot {
        self.status_rx.borrow().clone()
    }

    /// Subscribe to snapshots.
    #[allow(dead_code)] // M1 API surface for GUI/observers
    pub fn subscribe_status(&self) -> watch::Receiver<Snapshot> {
        self.status_rx.clone()
    }

    /// Subscribe to supervisor events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<SupervisorEvent> {
        self.events_tx.subscribe()
    }
}

/// Spawn the supervisor task and return its handle.
pub fn spawn() -> (SupervisorHandle, tokio::task::JoinHandle<()>) {
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let (status_tx, status_rx) = watch::channel(Snapshot {
        desired: Desired::Stopped,
        state: State::Stopped,
        listeners: None,
    });
    let (events_tx, _events_rx) = broadcast::channel(64);
    let handle = SupervisorHandle {
        cmd_tx,
        status_rx,
        events_tx: events_tx.clone(),
    };
    let join = tokio::spawn(run(cmd_rx, status_tx, events_tx));
    (handle, join)
}

#[derive(Debug)]
enum WorkerMsg {
    Adapter(AdapterEvent),
    Finished(Result<(), String>),
}

struct RunningWorker {
    shutdown_tx: Option<oneshot::Sender<()>>,
    msg_rx: mpsc::UnboundedReceiver<WorkerMsg>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl RunningWorker {
    fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for RunningWorker {
    fn drop(&mut self) {
        self.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn run(
    mut cmd_rx: mpsc::Receiver<Command>,
    status_tx: watch::Sender<Snapshot>,
    events_tx: broadcast::Sender<SupervisorEvent>,
) {
    let mut lifecycle = Lifecycle::new();
    let mut worker: Option<RunningWorker> = None;
    let mut listeners: Option<ListenerConfig> = None;
    let mut last_start: Option<(PathBuf, PathBuf, ListenerConfig)> = None;
    let mut backoff = BACKOFF_INITIAL;
    let mut restart_deadline: Option<tokio::time::Instant> = None;
    let mut intentional_restart = false;

    publish(&lifecycle, listeners.clone(), &status_tx, &events_tx);

    loop {
        let deadline = restart_deadline;
        if let Some(w) = worker.as_mut() {
            tokio::select! {
                biased;
                cmd = cmd_rx.recv() => {
                    if handle_command(
                        cmd, &mut lifecycle, &mut worker, &mut listeners, &mut last_start,
                        &mut backoff, &mut restart_deadline, &mut intentional_restart,
                        &status_tx, &events_tx,
                    ) {
                        return;
                    }
                }
                msg = w.msg_rx.recv() => {
                    handle_worker_msg(
                        msg, &mut lifecycle, &mut worker, &mut listeners, &mut last_start,
                        &mut backoff, &mut restart_deadline, &mut intentional_restart,
                        &status_tx, &events_tx,
                    );
                }
                _ = sleep_until_opt(deadline), if deadline.is_some() => {
                    handle_restart(
                        &mut lifecycle, &mut worker, &mut listeners, &last_start,
                        &mut restart_deadline, &status_tx, &events_tx,
                    );
                }
            }
        } else {
            tokio::select! {
                biased;
                cmd = cmd_rx.recv() => {
                    if handle_command(
                        cmd, &mut lifecycle, &mut worker, &mut listeners, &mut last_start,
                        &mut backoff, &mut restart_deadline, &mut intentional_restart,
                        &status_tx, &events_tx,
                    ) {
                        return;
                    }
                }
                _ = sleep_until_opt(deadline), if deadline.is_some() => {
                    handle_restart(
                        &mut lifecycle, &mut worker, &mut listeners, &last_start,
                        &mut restart_deadline, &status_tx, &events_tx,
                    );
                }
            }
        }
    }
}

async fn sleep_until_opt(deadline: Option<tokio::time::Instant>) {
    if let Some(deadline) = deadline {
        tokio::time::sleep_until(deadline).await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_command(
    cmd: Option<Command>,
    lifecycle: &mut Lifecycle,
    worker: &mut Option<RunningWorker>,
    listeners: &mut Option<ListenerConfig>,
    last_start: &mut Option<(PathBuf, PathBuf, ListenerConfig)>,
    backoff: &mut Duration,
    restart_deadline: &mut Option<tokio::time::Instant>,
    intentional_restart: &mut bool,
    status_tx: &watch::Sender<Snapshot>,
    events_tx: &broadcast::Sender<SupervisorEvent>,
) -> bool {
    match cmd {
        Some(Command::Connect {
            state_dir,
            cache_dir,
            listeners: ls,
        }) => {
            *intentional_restart = false;
            *restart_deadline = None;
            *backoff = BACKOFF_INITIAL;
            *listeners = Some(ls.clone());
            *last_start = Some((state_dir.clone(), cache_dir.clone(), ls.clone()));
            apply(
                lifecycle,
                Event::StartRequested,
                listeners,
                status_tx,
                events_tx,
            );
            if worker.is_none() {
                apply(
                    lifecycle,
                    Event::StartBegun,
                    listeners,
                    status_tx,
                    events_tx,
                );
                *worker = Some(start_worker(state_dir, cache_dir, ls));
            } else if let Some(w) = worker.as_mut() {
                // Stop current worker; completion will trigger restart while desired=Connected.
                apply(lifecycle, Event::StopBegun, listeners, status_tx, events_tx);
                w.stop();
            }
            publish(lifecycle, listeners.clone(), status_tx, events_tx);
            false
        }
        Some(Command::Disconnect) => {
            *intentional_restart = false;
            *restart_deadline = None;
            apply(
                lifecycle,
                Event::StopRequested,
                listeners,
                status_tx,
                events_tx,
            );
            if let Some(w) = worker.as_mut() {
                apply(lifecycle, Event::StopBegun, listeners, status_tx, events_tx);
                w.stop();
            } else {
                apply(lifecycle, Event::Stopped, listeners, status_tx, events_tx);
            }
            publish(lifecycle, listeners.clone(), status_tx, events_tx);
            false
        }
        Some(Command::NewIdentity) => {
            if lifecycle.desired() != Desired::Connected || last_start.is_none() {
                let message = "cannot request new identity: Tor is not connected".to_owned();
                warn!(%message, "new identity rejected");
                let _ = events_tx.send(SupervisorEvent::Failed { message });
                publish(lifecycle, listeners.clone(), status_tx, events_tx);
                return false;
            }
            info!("requesting new identity (restarting Tor client/listeners for new circuits)");
            *intentional_restart = true;
            *restart_deadline = None;
            *backoff = BACKOFF_INITIAL;
            let _ = events_tx.send(SupervisorEvent::BootstrapProgress {
                percent: None,
                detail: "requesting new identity (new circuits)…".to_owned(),
            });
            if let Some(w) = worker.as_mut() {
                apply(lifecycle, Event::StopBegun, listeners, status_tx, events_tx);
                w.stop();
            } else if let Some((state_dir, cache_dir, ls)) = last_start.clone() {
                *listeners = Some(ls.clone());
                apply(
                    lifecycle,
                    Event::StartBegun,
                    listeners,
                    status_tx,
                    events_tx,
                );
                *worker = Some(start_worker(state_dir, cache_dir, ls));
                *intentional_restart = false;
            }
            publish(lifecycle, listeners.clone(), status_tx, events_tx);
            false
        }
        Some(Command::Shutdown) | None => {
            *intentional_restart = false;
            apply(lifecycle, Event::Shutdown, listeners, status_tx, events_tx);
            if let Some(w) = worker.as_mut() {
                apply(lifecycle, Event::StopBegun, listeners, status_tx, events_tx);
                w.stop();
            }
            apply(lifecycle, Event::Stopped, listeners, status_tx, events_tx);
            publish(lifecycle, listeners.clone(), status_tx, events_tx);
            let _ = worker.take();
            info!("supervisor shut down");
            true
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_restart(
    lifecycle: &mut Lifecycle,
    worker: &mut Option<RunningWorker>,
    listeners: &mut Option<ListenerConfig>,
    last_start: &Option<(PathBuf, PathBuf, ListenerConfig)>,
    restart_deadline: &mut Option<tokio::time::Instant>,
    status_tx: &watch::Sender<Snapshot>,
    events_tx: &broadcast::Sender<SupervisorEvent>,
) {
    *restart_deadline = None;
    if lifecycle.desired() == Desired::Connected
        && worker.is_none()
        && let Some((state_dir, cache_dir, ls)) = last_start.clone()
    {
        info!("restarting tor after backoff");
        *listeners = Some(ls.clone());
        apply(
            lifecycle,
            Event::StartBegun,
            listeners,
            status_tx,
            events_tx,
        );
        *worker = Some(start_worker(state_dir, cache_dir, ls));
        publish(lifecycle, listeners.clone(), status_tx, events_tx);
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_worker_msg(
    msg: Option<WorkerMsg>,
    lifecycle: &mut Lifecycle,
    worker: &mut Option<RunningWorker>,
    listeners: &mut Option<ListenerConfig>,
    last_start: &mut Option<(PathBuf, PathBuf, ListenerConfig)>,
    backoff: &mut Duration,
    restart_deadline: &mut Option<tokio::time::Instant>,
    intentional_restart: &mut bool,
    status_tx: &watch::Sender<Snapshot>,
    events_tx: &broadcast::Sender<SupervisorEvent>,
) {
    match msg {
        Some(WorkerMsg::Adapter(event)) => {
            let state_dir = last_start.as_ref().map(|(sd, _, _)| sd.as_path());
            handle_adapter_event(lifecycle, event, listeners, state_dir, status_tx, events_tx);
        }
        Some(WorkerMsg::Finished(result)) => {
            *worker = None;
            match result {
                Ok(()) => {
                    apply(lifecycle, Event::Stopped, listeners, status_tx, events_tx);
                    if *intentional_restart && lifecycle.desired() == Desired::Connected {
                        *intentional_restart = false;
                        *restart_deadline = None;
                        *backoff = BACKOFF_INITIAL;
                        if let Some((state_dir, cache_dir, ls)) = last_start.clone() {
                            info!("restarting Tor for new identity");
                            *listeners = Some(ls.clone());
                            apply(
                                lifecycle,
                                Event::StartBegun,
                                listeners,
                                status_tx,
                                events_tx,
                            );
                            *worker = Some(start_worker(state_dir, cache_dir, ls));
                        } else {
                            let message =
                                "new identity restart failed: missing previous configuration"
                                    .to_owned();
                            apply(
                                lifecycle,
                                Event::Failed {
                                    message: message.clone(),
                                    retryable: false,
                                },
                                listeners,
                                status_tx,
                                events_tx,
                            );
                            let _ = events_tx.send(SupervisorEvent::Failed { message });
                        }
                    } else if lifecycle.desired() == Desired::Connected {
                        let message = "proxy service exited unexpectedly".to_owned();
                        apply(
                            lifecycle,
                            Event::Failed {
                                message: message.clone(),
                                retryable: true,
                            },
                            listeners,
                            status_tx,
                            events_tx,
                        );
                        let _ = events_tx.send(SupervisorEvent::Failed { message });
                        *restart_deadline = Some(tokio::time::Instant::now() + *backoff);
                        *backoff = (*backoff * 2).min(BACKOFF_MAX);
                    }
                }
                Err(message) => {
                    *intentional_restart = false;
                    let retryable = lifecycle.desired() == Desired::Connected;
                    apply(
                        lifecycle,
                        Event::Failed {
                            message: message.clone(),
                            retryable,
                        },
                        listeners,
                        status_tx,
                        events_tx,
                    );
                    let _ = events_tx.send(SupervisorEvent::Failed { message });
                    if retryable {
                        *restart_deadline = Some(tokio::time::Instant::now() + *backoff);
                        *backoff = (*backoff * 2).min(BACKOFF_MAX);
                    }
                }
            }
            publish(lifecycle, listeners.clone(), status_tx, events_tx);
        }
        None => {
            *worker = None;
        }
    }
}

fn handle_adapter_event(
    lifecycle: &mut Lifecycle,
    event: AdapterEvent,
    listeners: &Option<ListenerConfig>,
    state_dir: Option<&std::path::Path>,
    status_tx: &watch::Sender<Snapshot>,
    events_tx: &broadcast::Sender<SupervisorEvent>,
) {
    match event {
        AdapterEvent::Bootstrap(b) => {
            let detail = b.detail.clone();
            let percent = Some(b.percent);
            apply(
                lifecycle,
                Event::BootstrapProgress {
                    percent,
                    detail: detail.clone(),
                    ready: b.ready,
                },
                listeners,
                status_tx,
                events_tx,
            );
            let _ = events_tx.send(SupervisorEvent::BootstrapProgress { percent, detail });
        }
        AdapterEvent::Status(status) => match *status {
            AdapterStatus::Ready { .. } => {
                apply(
                    lifecycle,
                    Event::ListenersReady,
                    listeners,
                    status_tx,
                    events_tx,
                );
            }
            AdapterStatus::Failed { message } => {
                warn!(%message, "adapter reported failure");
            }
            AdapterStatus::Bootstrapping { percent, detail } => {
                apply(
                    lifecycle,
                    Event::BootstrapProgress {
                        percent: Some(percent),
                        detail,
                        ready: false,
                    },
                    listeners,
                    status_tx,
                    events_tx,
                );
            }
            AdapterStatus::Stopped => {
                debug!("adapter reported stopped");
            }
        },
        AdapterEvent::OnionServiceStatus { id, status } => match &status {
            tobro_tor::onion_service::OnionServiceRuntimeStatus::Published { onion_address } => {
                info!(%id, %onion_address, "onion service published");
                let _ = events_tx.send(SupervisorEvent::OnionPublished {
                    id: id.clone(),
                    onion_address: onion_address.clone(),
                });
                if let Some(state_dir) = state_dir {
                    let db_path = state_dir.join(tobro_store::DB_FILE_NAME);
                    let id2 = id.clone();
                    let addr2 = onion_address.clone();
                    tokio::spawn(async move {
                        if let Ok(db) = tobro_store::Db::open(&db_path).await {
                            let patch = tobro_store::OnionServicePatch {
                                name: None,
                                enabled: None,
                                ports: None,
                                onion_address: Some(Some(addr2)),
                            };
                            let _ = db.update_onion_service(&id2, patch).await;
                        }
                    });
                }
            }
            tobro_tor::onion_service::OnionServiceRuntimeStatus::Error { message } => {
                warn!(%id, %message, "onion service error");
                let _ = events_tx.send(SupervisorEvent::OnionError {
                    id: id.clone(),
                    message: message.clone(),
                });
            }
            tobro_tor::onion_service::OnionServiceRuntimeStatus::Starting => {
                debug!(%id, "onion service starting");
            }
            tobro_tor::onion_service::OnionServiceRuntimeStatus::Stopped => {
                debug!(%id, "onion service stopped");
            }
        },
    }
}

fn apply(
    lifecycle: &mut Lifecycle,
    event: Event,
    listeners: &Option<ListenerConfig>,
    status_tx: &watch::Sender<Snapshot>,
    events_tx: &broadcast::Sender<SupervisorEvent>,
) {
    let t = lifecycle.apply(event);
    if t.changed {
        publish(lifecycle, listeners.clone(), status_tx, events_tx);
    }
}

fn publish(
    lifecycle: &Lifecycle,
    listeners: Option<ListenerConfig>,
    status_tx: &watch::Sender<Snapshot>,
    events_tx: &broadcast::Sender<SupervisorEvent>,
) {
    let snapshot = Snapshot {
        desired: lifecycle.desired(),
        state: lifecycle.state().clone(),
        listeners,
    };
    let _ = status_tx.send(snapshot.clone());
    let _ = events_tx.send(SupervisorEvent::StateChanged(snapshot));
}

fn start_worker(
    state_dir: PathBuf,
    cache_dir: PathBuf,
    listeners: ListenerConfig,
) -> RunningWorker {
    let (msg_tx, msg_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let thread = std::thread::Builder::new()
        .name("tobro-tor".to_owned())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = msg_tx.send(WorkerMsg::Finished(Err(format!(
                        "could not start tor runtime: {err}"
                    ))));
                    return;
                }
            };

            rt.block_on(async move {
                let prepared = match bootstrap_and_prepare(state_dir, cache_dir, listeners).await {
                    Ok(p) => p,
                    Err(err) => {
                        let _ = msg_tx.send(WorkerMsg::Finished(Err(format!("{err:#}"))));
                        return;
                    }
                };

                let mut sub = prepared.control.subscribe();
                // Bootstrap progress events were emitted to bootstrap_and_prepare's
                // internal control channel while this worker was awaiting it, so a
                // subscriber created now misses them. Lifecycle reaches Ready only
                // after BootstrapProgress{ready:true} followed by ListenersReady.
                let _ = msg_tx.send(WorkerMsg::Adapter(AdapterEvent::Bootstrap(
                    tobro_tor::BootstrapEvent {
                        percent: 100,
                        ready: true,
                        blocked: None,
                        detail: "bootstrapped".to_owned(),
                    },
                )));
                // Announce ready state.
                let _ = msg_tx.send(WorkerMsg::Adapter(AdapterEvent::Status(Box::new(
                    prepared.control.status(),
                ))));

                let msg_tx_forward = msg_tx.clone();
                let forward = tokio::spawn(async move {
                    loop {
                        match sub.recv().await {
                            Ok(event) => {
                                if msg_tx_forward.send(WorkerMsg::Adapter(event)).is_err() {
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => {}
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });

                let result = prepared
                    .serve(shutdown_rx)
                    .await
                    .map_err(|e| format!("{e:#}"));
                forward.abort();
                let _ = msg_tx.send(WorkerMsg::Finished(result));
            });
        });

    let thread = match thread {
        Ok(t) => Some(t),
        Err(err) => {
            warn!(%err, "could not spawn tor worker thread");
            None
        }
    };

    RunningWorker {
        shutdown_tx: Some(shutdown_tx),
        msg_rx,
        thread,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disconnect_from_stopped_is_stable() {
        let (h, j) = spawn();
        h.disconnect().await.expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let snap = h.snapshot();
        assert_eq!(snap.desired, Desired::Stopped);
        h.shutdown().await.expect("shutdown");
        let _ = tokio::time::timeout(Duration::from_secs(1), j).await;
    }
}
