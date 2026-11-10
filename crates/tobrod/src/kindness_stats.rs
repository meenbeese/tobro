//! Kindness statistics (M6): counts of clients the proxy served.
//!
//! The upstream `snowflake-proxy` reports per-connection events only through
//! its log output (`-verbose`): when a client's data channel opens it logs
//! `Data Channel <label>-<id> open`, and when it closes
//! `Data Channel <label>-<id> close` (see upstream `proxy/lib/snowflake.go`,
//! `dc.OnOpen`/`dc.OnClose`). Those lines are the single source of truth for
//! every counter here:
//!
//! - **Served** (weekly and all-time, persisted in `tobro-store`): one client
//!   is counted per `open` line. Counts never include geoip country, client
//!   labels/addresses, or traffic figures from the proxy's periodic summary
//!   lines; summary lines are not parsed at all, so combining live counting
//!   with summary counting can never double count.
//! - **Current connections**: opens minus closes, held in volatile daemon
//!   state. It is not persisted; a daemon (or proxy) restart resets it to 0.
//!
//! Go's `log` package prefixes each line with `YYYY/MM/DD HH:MM:SS `, which
//! the parser strips before matching. The parser deliberately does not
//! interpret anything else the proxy logs (offers, relay URLs, NAT checks);
//! all counters come from the two exact line shapes above.

use std::path::PathBuf;
use std::sync::Arc;

use tobro_store::Db;

use crate::pt_supervisor::{SidecarEvent, SidecarState};

/// One client-serving connection event parsed from the proxy's log output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyLogEvent {
    /// `Data Channel ... open`: a client connected.
    ClientConnected,
    /// `Data Channel ... close`: a served client disconnected.
    ClientDisconnected,
}

/// Strip the Go `log` timestamp prefix (`YYYY/MM/DD HH:MM:SS `) when present.
fn strip_log_prefix(line: &str) -> &str {
    let bytes = line.as_bytes();
    let digit = |i: usize| bytes.get(i).is_some_and(|b| b.is_ascii_digit());
    // SHAPE: 4 digits '/' 2 '/' 2 ' ' 2 ':' 2 ':' 2 ' ' (20 bytes total).
    if bytes.len() > 20
        && digit(0)
        && digit(1)
        && digit(2)
        && digit(3)
        && bytes[4] == b'/'
        && digit(5)
        && digit(6)
        && bytes[7] == b'/'
        && digit(8)
        && digit(9)
        && bytes[10] == b' '
        && digit(11)
        && digit(12)
        && bytes[13] == b':'
        && digit(14)
        && digit(15)
        && bytes[16] == b':'
        && digit(17)
        && digit(18)
        && bytes[19] == b' '
    {
        &line[20..]
    } else {
        line
    }
}

/// Parse a proxy log line into a connection event.
///
/// Only exact report shapes match: the content must start with
/// `Data Channel `, carry a `<label>-<id>` channel identifier (non-empty,
/// containing `-` and ending in a digit), and end with ` open`/` close`.
/// Everything else the proxy logs (including the `Discarded Subsequent Data
/// Channel` and `WebRTC: DataChannel.OnOpen` NAT-check lines) is ignored.
pub(crate) fn parse_log_event(line: &str) -> Option<ProxyLogEvent> {
    let content = strip_log_prefix(line).trim_end_matches(['\r', '\n']);
    if !content.starts_with("Data Channel ") {
        return None;
    }
    let (event, tail) = if content.ends_with(" open") {
        (ProxyLogEvent::ClientConnected, " open")
    } else if content.ends_with(" close") {
        (ProxyLogEvent::ClientDisconnected, " close")
    } else {
        return None;
    };
    let channel = content.get("Data Channel ".len()..content.len() - tail.len());
    // Upstream logs `<label>-<id>`; anything else is chatter with the same
    // words elsewhere in the line.
    match channel {
        Some(channel)
            if channel.len() >= 3
                && channel.contains('-')
                && channel.ends_with(char::is_numeric) =>
        {
            Some(event)
        }
        _ => None,
    }
}

/// UTC date (YYYY-MM-DD) of the Monday of the ISO week containing
/// `unix_day` (days since the Unix epoch).
///
/// The epoch (1970-01-01) was a Thursday, so a Thursday's Monday starts
/// 3 days earlier: `monday = day - (day + 3) % 7`.
fn week_start_for_day(unix_day: i64) -> String {
    let monday = unix_day - (unix_day + 3).rem_euclid(7);
    civil_date(monday)
}

/// Convert days since the Unix epoch to a `YYYY-MM-DD` civil date (UTC).
///
/// Howard Hinnant's `civil_from_days` algorithm; correct for the whole range
/// `i64` can hold and unit-tested against known dates.
fn civil_date(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}")
}

/// Unix days since the epoch for a millisecond timestamp.
fn unix_day(now_ms: i64) -> i64 {
    now_ms.div_euclid(86_400_000)
}

/// Compute UTC now in milliseconds and the ISO week start for it in one call
/// (kept together so both always come from the same clock reading).
fn now_clock() -> (i64, String) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    (now_ms, week_start_for_day(unix_day(now_ms)))
}

/// Live (volatile) statistics observed for `kindness.status`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct StatsLive {
    /// Connections currently open (never below zero; log loss cannot make
    /// the counter negative).
    pub(crate) current: u32,
    /// Whether at least one connection event was observed this daemon
    /// session (mirrors whether the parser has anything to count).
    pub(crate) seen_events: bool,
}

/// Sharable handle to the volatile stats (`kindness.status` reads it).
pub(crate) type StatsShared = Arc<std::sync::RwLock<StatsLive>>;

/// Apply one parsed event to the volatile and persisted counters.
///
/// `current` never underflows: if the proxy's log lost an `open` line, a
/// `close` clamps at zero instead of inventing negative connections. The
/// database is updated only for client connections, and reopen failures are
/// logged rather than breaking the tracker (next events retry).
async fn apply_log_event(db_path: &std::path::Path, shared: &StatsShared, event: ProxyLogEvent) {
    match event {
        ProxyLogEvent::ClientConnected => {
            if let Ok(mut guard) = shared.write() {
                guard.current = guard.current.saturating_add(1);
                guard.seen_events = true;
            }
            let (now_ms, week) = now_clock();
            match Db::open(db_path).await {
                Ok(db) => match db.kindness_stats_record_served(1, &week, now_ms).await {
                    Ok(stats) => {
                        tracing::debug!(
                            sidecar = crate::kindness::SIDECAR_ID,
                            total = stats.total_served,
                            week = stats.week_served,
                            "kindness proxy served a client"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, "could not record the kindness served counter")
                    }
                },
                Err(error) => {
                    tracing::warn!(%error, "could not open the store for kindness stats")
                }
            }
        }
        ProxyLogEvent::ClientDisconnected => {
            if let Ok(mut guard) = shared.write() {
                guard.current = guard.current.saturating_sub(1);
            }
        }
    }
}

/// A proxy exit clears all current connections: every data channel dies with
/// the process, and the counter is not persisted.
fn proxy_exited(shared: &StatsShared) {
    if let Ok(mut guard) = shared.write() {
        guard.current = 0;
    }
}

/// Spawn the stats tracker. It lives as long as the daemon: it consumes the
/// sidecar event stream with its own subscriber (the event logger uses
/// another), counts served clients into the store, and keeps the volatile
/// current-connections count shared with the IPC surface.
pub(crate) fn spawn_tracker(
    mut events: tokio::sync::broadcast::Receiver<SidecarEvent>,
    db_path: PathBuf,
    shared: StatsShared,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let event = match events.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(
                        sidecar = crate::kindness::SIDECAR_ID,
                        skipped,
                        "kindness stats skipped sidecar events"
                    );
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            match &event {
                SidecarEvent::StdoutLine { line, .. } | SidecarEvent::StderrLine { line, .. } => {
                    if let Some(log_event) = parse_log_event(line) {
                        apply_log_event(&db_path, &shared, log_event).await;
                    }
                }
                SidecarEvent::Exited { .. } => proxy_exited(&shared),
                SidecarEvent::State(snapshot)
                    if snapshot.state == SidecarState::Stopped
                        || snapshot.state == SidecarState::Failed =>
                {
                    proxy_exited(&shared)
                }
                _ => {}
            }
        }
    })
}

/// Reset the volatile counters (the `kindness.reset_stats` IPC also clears
/// the persisted totals through the store).
pub(crate) fn reset_live(shared: &StatsShared) {
    if let Ok(mut guard) = shared.write() {
        guard.current = 0;
        guard.seen_events = false;
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const LOG_PREFIX: &str = "2026/11/10 14:05:09 ";

    #[test]
    fn parses_exact_connection_lines() {
        // Real upstream shapes (`dc.Label()` + `dc.ID()`).
        assert_eq!(
            parse_log_event(&format!("{LOG_PREFIX}Data Channel test-1 open\n")),
            Some(ProxyLogEvent::ClientConnected)
        );
        assert_eq!(
            parse_log_event(&format!("{LOG_PREFIX}Data Channel test-1 close\n")),
            Some(ProxyLogEvent::ClientDisconnected)
        );
        assert_eq!(
            parse_log_event("Data Channel 14b6a839f9dab086-1 open\n"),
            Some(ProxyLogEvent::ClientConnected)
        );

        // Without a timestamp prefix (defensive; Go always adds one).
        assert_eq!(
            parse_log_event("Data Channel test-1 open"),
            Some(ProxyLogEvent::ClientConnected)
        );
    }

    #[test]
    fn ignores_everything_else_the_proxy_logs() {
        // Offer stage line must not count as a served client.
        assert_eq!(
            parse_log_event(&format!("{LOG_PREFIX}New Data Channel test-1\n")),
            None
        );
        // "Discarded Subsequent" lines must not increment anything.
        assert_eq!(
            parse_log_event(&format!(
                "{LOG_PREFIX}Discarded Subsequent Data Channel test-2:Ok(()),"
            )),
            None
        );
        // NAT-check data channels use a different shape.
        assert_eq!(
            parse_log_event(&format!("{LOG_PREFIX}WebRTC: DataChannel.OnOpen")),
            None
        );
        // Connection summary lines and other chatter.
        assert_eq!(
            parse_log_event(&format!(
                "{LOG_PREFIX}In the last 1h0m0s, there were 3 completed successful connections."
            )),
            None
        );
        assert_eq!(
            parse_log_event(&format!("{LOG_PREFIX}Connection successful")),
            None
        );
        assert_eq!(
            parse_log_event(&format!(
                "{LOG_PREFIX}Connected to relay: wss://relay.example/"
            )),
            None
        );
        assert_eq!(parse_log_event(""), None);
        assert_eq!(parse_log_event("Data Channel open"), None);
        // A missing/odd channel identifier is chatter, not a client line.
        assert_eq!(
            parse_log_event(&format!("{LOG_PREFIX}Data Channel test open\n")),
            None
        );
        assert_eq!(
            parse_log_event(&format!("{LOG_PREFIX}Data Channel test-1 paused")),
            None
        );
    }

    #[test]
    fn week_start_computation_matches_known_dates() {
        // 1970-01-01 (Thu, day 0) belongs to the week of Mon 1969-12-29.
        assert_eq!(week_start_for_day(0), "1969-12-29");
        // 2026-11-10 (unix day 20767) is a Tuesday; its Monday is 2026-11-09.
        assert_eq!(week_start_for_day(20_767), "2026-11-09");
        // The Monday itself stays its own week start.
        assert_eq!(week_start_for_day(20_766), "2026-11-09");
        // A Sunday (2026-11-15 = 20772) closes the week started on 2026-11-09;
        // the next day starts a new week.
        assert_eq!(week_start_for_day(20_772), "2026-11-09");
        assert_eq!(week_start_for_day(20_773), "2026-11-16");
    }

    #[tokio::test]
    async fn apply_log_event_counts_into_store_and_shared() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let db_path = dir.path().join("tobro.sqlite3");
        let shared: StatsShared = Arc::new(std::sync::RwLock::new(StatsLive::default()));

        apply_log_event(&db_path, &shared, ProxyLogEvent::ClientConnected).await;
        {
            let guard = shared.read().expect("lock");
            assert_eq!(guard.current, 1);
            assert!(guard.seen_events);
        }
        apply_log_event(&db_path, &shared, ProxyLogEvent::ClientConnected).await;
        apply_log_event(&db_path, &shared, ProxyLogEvent::ClientDisconnected).await;
        {
            let guard = shared.read().expect("lock");
            assert_eq!(guard.current, 1);
        }
        // A lost `open` cannot drive the counter below zero.
        apply_log_event(&db_path, &shared, ProxyLogEvent::ClientDisconnected).await;
        apply_log_event(&db_path, &shared, ProxyLogEvent::ClientDisconnected).await;
        {
            let guard = shared.read().expect("lock");
            assert_eq!(guard.current, 0, "current clamps at zero");
        }

        let db = Db::open(&db_path).await?;
        let stats = db.kindness_stats().await?;
        assert_eq!(stats.total_served, 2, "served counted per client");
        assert_eq!(
            stats.week_served, 2,
            "the very first recorded week starts this week"
        );
        Ok(())
    }

    #[tokio::test]
    async fn reset_live_zeroes_current() {
        let shared: StatsShared = Arc::new(std::sync::RwLock::new(StatsLive::default()));
        {
            let mut guard = shared.write().expect("lock");
            guard.current = 4;
            guard.seen_events = true;
        }
        reset_live(&shared);
        assert_eq!(
            *shared.read().expect("lock"),
            StatsLive::default(),
            "reset zeroes current and event marker"
        );
    }

    /// Whole-path test: a fake proxy prints Go-prefixed connection lines on
    /// stdout and stderr; the tracker must count served clients into the
    /// store and keep the volatile current count (then zero it on exit).
    #[cfg(unix)]
    mod behavior {
        use super::*;
        use crate::pt_supervisor::RestartPolicy;

        #[allow(clippy::expect_used, clippy::unwrap_used)]
        #[tokio::test]
        async fn tracker_counts_lines_from_a_fake_proxy() {
            let dir = tempfile::tempdir().expect("tmp");
            let bin = dir.path().join("snowflake-proxy");
            std::fs::write(
                &bin,
                "#!/bin/sh\n\
                 ts=$(date +%Y/%m/%d\\ %H:%M:%S)\n\
                 echo \"$ts Data Channel test-1 open\"\n\
                 echo \"$ts Data Channel test-2 open\" >&2\n\
                 sleep 0.3\n\
                 echo \"$ts Data Channel test-1 close\" >&2\n\
                 while true; do sleep 1; done\n",
            )
            .expect("write fake proxy");
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
            let mut cfg = tobro_config::KindnessConfig::default();
            cfg.proxy_path = Some(bin.to_string_lossy().into_owned());
            let sup = crate::kindness::spawn_supervised_with(
                &cfg,
                dir.path(),
                RestartPolicy {
                    enabled: false,
                    ..RestartPolicy::default()
                },
            )
            .expect("spawn fake proxy");

            let db_path = dir.path().join("tobro.sqlite3");
            let shared: StatsShared = Arc::new(std::sync::RwLock::new(StatsLive::default()));
            let tracker = spawn_tracker(
                sup.control_handle().subscribe_events(),
                db_path.clone(),
                Arc::clone(&shared),
            );

            sup.start().await;

            // Two opens, one close: served 2, current 1.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let guard = shared.read().expect("lock");
                if guard.current == 1 && guard.seen_events {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    panic!("timed out waiting for the proxy lines: {:?}", *guard);
                }
                drop(guard);
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }

            // Give the store write a beat, then verify the persisted totals.
            for _ in 0..40 {
                if let Ok(db) = Db::open(&db_path).await
                    && let Ok(stats) = db.kindness_stats().await
                    && stats.total_served == 2
                {
                    assert_eq!(stats.week_served, 2);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }

            sup.shutdown().await;
            tracker.abort();
        }
    }
}
