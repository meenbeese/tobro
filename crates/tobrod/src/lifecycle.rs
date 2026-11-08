//! M1 daemon lifecycle state machine.
//!
//! This module models desired intent and observed daemon state. It is pure
//! (no I/O, no Arti) so transitions can be unit tested exhaustively.
//!
//! Key invariant: [`State::Ready`] is only reachable after bootstrap reports
//! ready; user-facing status must never claim connected before then.

use std::fmt;

/// What the user/operator wants the daemon to be doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Desired {
    /// The daemon should be stopped / not connected.
    Stopped,
    /// The daemon should be connected and serving.
    Connected,
}

/// Observed daemon lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Not running Tor; listeners/daemon may still be alive depending on mode.
    Stopped,
    /// Start requested; preparing config/client.
    Starting,
    /// Arti client created and bootstrap in progress.
    Bootstrapping {
        /// Best-effort bootstrap percentage (0..=100) when known.
        percent: Option<u8>,
        /// Human-readable detail for logs/UI.
        detail: String,
    },
    /// Bootstrapped and local listeners are ready to serve.
    Ready,
    /// Stop requested; tearing down listeners/client.
    Stopping,
    /// A recoverable or terminal failure was observed.
    Failed {
        /// Short, user-safe summary.
        message: String,
        /// Whether supervision may retry automatically.
        retryable: bool,
    },
}

impl State {
    /// Whether the daemon is usable for proxy traffic.
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Whether a start/connect operation can be accepted.
    pub fn can_start(&self) -> bool {
        matches!(
            self,
            Self::Stopped | Self::Failed { .. }
        )
    }

    /// Whether a stop/disconnect operation can be accepted.
    pub fn can_stop(&self) -> bool {
        matches!(
            self,
            Self::Starting | Self::Bootstrapping { .. } | Self::Ready
        )
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => write!(f, "stopped"),
            Self::Starting => write!(f, "starting"),
            Self::Bootstrapping { percent, .. } => match percent {
                Some(p) => write!(f, "bootstrapping ({p}%)"),
                None => write!(f, "bootstrapping"),
            },
            Self::Ready => write!(f, "ready"),
            Self::Stopping => write!(f, "stopping"),
            Self::Failed { retryable, .. } if *retryable => write!(f, "failed (retryable)"),
            Self::Failed { .. } => write!(f, "failed"),
        }
    }
}

/// Inputs that drive the lifecycle state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// User/operator requested connect/start.
    StartRequested,
    /// User/operator requested stop/disconnect.
    StopRequested,
    /// Client/bootstrap preparation began.
    StartBegun,
    /// Bootstrap progress update.
    BootstrapProgress {
        /// Best-effort percentage.
        percent: Option<u8>,
        /// Detail string.
        detail: String,
        /// True only when Arti reports the directory/client is ready.
        ready: bool,
    },
    /// Local listeners are bound and serving after bootstrap.
    ListenersReady,
    /// Stop/teardown began.
    StopBegun,
    /// Teardown completed.
    Stopped,
    /// An operation failed.
    Failed {
        /// User-safe message (must not contain secrets).
        message: String,
        /// Whether supervision may retry.
        retryable: bool,
    },
    /// Process shutdown requested.
    #[cfg_attr(not(test), allow(dead_code))] // M1 skeleton: wired by supervisor.
    Shutdown,
}

/// Result of applying an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    /// State before the event.
    pub from: State,
    /// Event applied.
    pub event: Event,
    /// State after the event.
    pub to: State,
    /// Whether the event caused a state change.
    pub changed: bool,
}

/// Pure lifecycle state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lifecycle {
    desired: Desired,
    state: State,
    /// True after bootstrap is ready but before listeners are confirmed ready.
    bootstrap_ready: bool,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifecycle {
    /// Create a new lifecycle in the stopped state.
    pub fn new() -> Self {
        Self {
            desired: Desired::Stopped,
            state: State::Stopped,
            bootstrap_ready: false,
        }
    }

    /// Current desired intent.
    #[cfg_attr(not(test), allow(dead_code))] // M1 skeleton: used by supervisor/IPC.
    pub fn desired(&self) -> Desired {
        self.desired
    }

    /// Current observed state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Apply an event and return the transition.
    pub fn apply(&mut self, event: Event) -> Transition {
        let from = self.state.clone();
        match &event {
            Event::StartRequested => {
                self.desired = Desired::Connected;
                if self.state.can_start() {
                    self.bootstrap_ready = false;
                    // Stay until StartBegun; the supervisor decides when work begins.
                }
            }
            Event::StopRequested | Event::Shutdown => {
                self.desired = Desired::Stopped;
                self.bootstrap_ready = false;
                if self.state.can_stop() {
                    // StopBegun moves to Stopping.
                }
            }
            Event::StartBegun => {
                if self.desired == Desired::Connected {
                    self.bootstrap_ready = false;
                    self.state = State::Starting;
                }
            }
            Event::BootstrapProgress {
                percent,
                detail,
                ready,
            } => {
                if self.desired == Desired::Connected {
                    if *ready {
                        self.bootstrap_ready = true;
                    }
                    // Never enter Ready here; listeners must be confirmed.
                    if !matches!(self.state, State::Stopping | State::Stopped) {
                        self.state = State::Bootstrapping {
                            percent: *percent,
                            detail: detail.clone(),
                        };
                    }
                }
            }
            Event::ListenersReady => {
                if self.desired == Desired::Connected && self.bootstrap_ready {
                    self.state = State::Ready;
                }
            }
            Event::StopBegun => {
                self.state = State::Stopping;
                self.bootstrap_ready = false;
            }
            Event::Stopped => {
                self.state = State::Stopped;
                self.bootstrap_ready = false;
            }
            Event::Failed { message, retryable } => {
                self.state = State::Failed {
                    message: message.clone(),
                    retryable: *retryable,
                };
                self.bootstrap_ready = false;
            }
        }

        let to = self.state.clone();
        let changed = from != to;
        Transition {
            from,
            event,
            to,
            changed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_reaches_ready_only_after_bootstrap_and_listeners() {
        let mut lc = Lifecycle::new();
        lc.apply(Event::StartRequested);
        lc.apply(Event::StartBegun);
        assert!(matches!(lc.state(), State::Starting));

        lc.apply(Event::BootstrapProgress {
            percent: Some(50),
            detail: "loading".to_owned(),
            ready: false,
        });
        assert!(matches!(lc.state(), State::Bootstrapping { .. }));
        assert!(!lc.state().is_ready());

        lc.apply(Event::BootstrapProgress {
            percent: Some(100),
            detail: "bootstrapped".to_owned(),
            ready: true,
        });
        assert!(matches!(lc.state(), State::Bootstrapping { .. }));
        assert!(!lc.state().is_ready(), "must not be ready before listeners");

        lc.apply(Event::ListenersReady);
        assert!(matches!(lc.state(), State::Ready));
    }

    #[test]
    fn listeners_ready_without_bootstrap_does_not_connect() {
        let mut lc = Lifecycle::new();
        lc.apply(Event::StartRequested);
        lc.apply(Event::StartBegun);
        lc.apply(Event::ListenersReady);
        assert!(!lc.state().is_ready());
    }

    #[test]
    fn stop_request_prevents_ready() {
        let mut lc = Lifecycle::new();
        lc.apply(Event::StartRequested);
        lc.apply(Event::StartBegun);
        lc.apply(Event::BootstrapProgress {
            percent: Some(100),
            detail: "bootstrapped".to_owned(),
            ready: true,
        });
        lc.apply(Event::StopRequested);
        lc.apply(Event::StopBegun);
        lc.apply(Event::ListenersReady);
        assert!(matches!(lc.state(), State::Stopping));
        lc.apply(Event::Stopped);
        assert!(matches!(lc.state(), State::Stopped));
    }

    #[test]
    fn failure_is_recorded() {
        let mut lc = Lifecycle::new();
        lc.apply(Event::StartRequested);
        lc.apply(Event::StartBegun);
        lc.apply(Event::Failed {
            message: "boom".to_owned(),
            retryable: true,
        });
        assert!(matches!(
            lc.state(),
            State::Failed {
                retryable: true,
                ..
            }
        ));
    }
}
