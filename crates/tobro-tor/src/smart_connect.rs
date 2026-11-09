//! Smart Connect state machine (M3, F-32).
//!
//! Provides an observable, budgeted, cancellable fallback chain for connecting
//! through censorship: plan ordered attempts, allocate a total time budget,
//! report each attempt (`attempt`, `deadline`/budget, `reason`), and stop on
//! success, cancellation, or exhaustion.
//!
//! Execution of an individual attempt is delegated to the caller (e.g. tobrod
//! supervisor/PT bootstrap), so this module stays testable without a live Tor
//! stack.

use std::future::Future;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::moat::{BridgeSource, ResolvedBridges};
use crate::pt::{BridgeDistribution, import_bridge_lines};

/// Default total Smart Connect budget.
pub const DEFAULT_TOTAL_BUDGET: Duration = Duration::from_secs(30);
/// Minimum budget allocated to any single attempt.
pub const DEFAULT_MIN_ATTEMPT_BUDGET: Duration = Duration::from_secs(5);
/// Maximum attempts to plan (safety cap).
pub const DEFAULT_MAX_ATTEMPTS: usize = 6;
/// Short timeout for the initial direct attempt when Smart Connect/Auto tries direct first.
pub const DEFAULT_DIRECT_BUDGET: Duration = Duration::from_secs(10);

/// High-level transport/method choice for an attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptKind {
    /// Direct Tor connection (no bridges/PTs).
    Direct,
    /// Snowflake.
    Snowflake,
    /// obfs4 (lyrebird).
    Obfs4,
    /// WebTunnel (lyrebird).
    Webtunnel,
    /// meek/meek_lite (lyrebird).
    Meek,
    /// dnstt.
    Dnstt,
    /// User-provided custom bridge lines.
    Custom,
}

impl AttemptKind {
    /// Human-readable label for UI/logs.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Snowflake => "snowflake",
            Self::Obfs4 => "obfs4",
            Self::Webtunnel => "webtunnel",
            Self::Meek => "meek",
            Self::Dnstt => "dnstt",
            Self::Custom => "custom",
        }
    }

    /// Normalized transport id used for bridge matching/config.
    pub fn transport_id(&self) -> Option<&'static str> {
        match self {
            Self::Direct => None,
            Self::Snowflake => Some("snowflake"),
            Self::Obfs4 => Some("obfs4"),
            Self::Webtunnel => Some("webtunnel"),
            Self::Meek => Some("meek_lite"),
            Self::Dnstt => Some("dnstt"),
            Self::Custom => None,
        }
    }
}

/// Policy/configuration for planning Smart Connect attempts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartConnectConfig {
    /// Total time budget for the whole Smart Connect run.
    #[serde(default = "default_total_budget_secs", with = "duration_secs")]
    pub total_budget: Duration,
    /// Minimum budget per attempt.
    #[serde(default = "default_min_attempt_budget_secs", with = "duration_secs")]
    pub min_attempt_budget: Duration,
    /// Maximum number of attempts.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: usize,
    /// User explicitly selected "auto" behavior (eligible for direct-first when no bridges).
    #[serde(default = "default_true")]
    pub auto: bool,
    /// Smart Connect fallback enabled.
    #[serde(default = "default_true")]
    pub smart_connect: bool,
    /// Try direct first when auto and no configured bridges/lines.
    #[serde(default = "default_true")]
    pub try_direct_first: bool,
    /// Preferred country for Moat/built-in bridge selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Explicit transport override (`None` = auto/plan).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_transport: Option<AttemptKind>,
    /// Custom bridge lines (sensitive). Used for `Custom` attempts and as a
    /// direct configured bridge source when present.
    #[serde(default)]
    pub custom_lines: Vec<String>,
    /// Whether custom/configured bridges are already present (affects direct-first).
    #[serde(default)]
    pub has_configured_bridges: bool,
}

fn default_true() -> bool {
    true
}
fn default_max_attempts() -> usize {
    DEFAULT_MAX_ATTEMPTS
}
fn default_total_budget_secs() -> Duration {
    DEFAULT_TOTAL_BUDGET
}
fn default_min_attempt_budget_secs() -> Duration {
    DEFAULT_MIN_ATTEMPT_BUDGET
}

mod duration_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;
    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs().max(1))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs.max(1)))
    }
}

impl Default for SmartConnectConfig {
    fn default() -> Self {
        Self {
            total_budget: DEFAULT_TOTAL_BUDGET,
            min_attempt_budget: DEFAULT_MIN_ATTEMPT_BUDGET,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            auto: true,
            smart_connect: true,
            try_direct_first: true,
            country: None,
            preferred_transport: None,
            custom_lines: Vec::new(),
            has_configured_bridges: false,
        }
    }
}

/// A planned attempt with an allocated budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedAttempt {
    /// 1-based attempt number.
    pub index: usize,
    /// Total attempts in the plan.
    pub total: usize,
    /// Method/transport for this attempt.
    pub kind: AttemptKind,
    /// Human-readable reason/label (safe to display).
    pub reason: String,
    /// Bridge lines to use for this attempt (empty for `Direct`). Sensitive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bridge_lines: Vec<String>,
    /// Source of bridge lines, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_source: Option<BridgeSource>,
    /// Allocated budget for this attempt.
    #[serde(with = "duration_millis")]
    pub budget: Duration,
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;
    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_millis() as u64)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let ms = u64::deserialize(d)?;
        Ok(Duration::from_millis(ms))
    }
}

/// A complete Smart Connect plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartConnectPlan {
    /// Total budget for the run.
    #[serde(with = "duration_millis")]
    pub total_budget: Duration,
    /// Planned attempts in order.
    pub attempts: Vec<PlannedAttempt>,
}

impl SmartConnectPlan {
    /// Build a plan from config and optional resolved bridge sources.
    ///
    /// `resolved` may contain Moat/built-in results keyed by transport id
    /// (e.g. `snowflake`, `obfs4`, `webtunnel`, `meek_lite`, `dnstt`).
    pub fn build(
        config: &SmartConnectConfig,
        resolved: &std::collections::BTreeMap<String, ResolvedBridges>,
        fallback_dist: Option<&BridgeDistribution>,
    ) -> Self {
        let mut kinds: Vec<(AttemptKind, String)> = Vec::new();
        let custom = import_bridge_lines(&config.custom_lines.join("\n"));

        if let Some(pref) = &config.preferred_transport {
            kinds.push((pref.clone(), format!("selected {}", pref.label())));
        } else if config.smart_connect && config.auto {
            if config.try_direct_first && !config.has_configured_bridges && custom.is_empty() {
                kinds.push((
                    AttemptKind::Direct,
                    "try direct connection first".to_owned(),
                ));
            }
            // Plan order per spec: Snowflake → obfs4 → custom.
            // Also include other supported transports if we have/can resolve bridges for them.
            kinds.push((AttemptKind::Snowflake, "try snowflake".to_owned()));
            kinds.push((AttemptKind::Obfs4, "try obfs4".to_owned()));
            if !custom.is_empty() {
                kinds.push((AttemptKind::Custom, "try custom bridges".to_owned()));
            }
        } else if !custom.is_empty() || config.has_configured_bridges {
            kinds.push((AttemptKind::Custom, "use configured bridges".to_owned()));
        } else {
            kinds.push((AttemptKind::Direct, "direct connection".to_owned()));
        }

        // Deduplicate kinds while preserving order.
        let mut seen = std::collections::HashSet::new();
        kinds.retain(|(k, _)| seen.insert(format!("{k:?}")));

        kinds.truncate(config.max_attempts.max(1));

        let budgets = allocate_budgets(config.total_budget, config.min_attempt_budget, kinds.len());
        let total = kinds.len();
        let attempts = kinds
            .into_iter()
            .enumerate()
            .map(|(i, (kind, reason))| {
                let (bridge_lines, bridge_source) = resolve_lines_for_kind(
                    &kind,
                    &custom,
                    resolved,
                    fallback_dist,
                    config.country.as_deref(),
                );
                PlannedAttempt {
                    index: i + 1,
                    total,
                    kind,
                    reason,
                    bridge_lines,
                    bridge_source,
                    budget: budgets.get(i).copied().unwrap_or(config.min_attempt_budget),
                }
            })
            .collect();

        Self {
            total_budget: config.total_budget,
            attempts,
        }
    }
}

fn resolve_lines_for_kind(
    kind: &AttemptKind,
    custom: &[String],
    resolved: &std::collections::BTreeMap<String, ResolvedBridges>,
    fallback_dist: Option<&BridgeDistribution>,
    country: Option<&str>,
) -> (Vec<String>, Option<BridgeSource>) {
    if *kind == AttemptKind::Direct {
        return (Vec::new(), None);
    }
    if *kind == AttemptKind::Custom {
        return (custom.to_vec(), Some(BridgeSource::Custom));
    }
    if let Some(tid) = kind.transport_id() {
        if let Some(r) = resolved.get(tid) {
            if !r.lines.is_empty() {
                return (r.lines.clone(), Some(r.source));
            }
        }
        if let Some(dist) = fallback_dist {
            let lines = dist.lines_for(Some(tid), country);
            if !lines.is_empty() {
                return (lines, Some(BridgeSource::Builtin));
            }
        }
    }
    (Vec::new(), None)
}

/// Allocate `count` attempt budgets from `total`, respecting `min` when possible.
pub fn allocate_budgets(total: Duration, min: Duration, count: usize) -> Vec<Duration> {
    if count == 0 {
        return Vec::new();
    }
    let count_u32 = count as u32;
    let min_total = min.saturating_mul(count_u32);
    if total <= min || total <= min_total {
        // Not enough room for min each; split evenly but keep nonzero.
        let each = (total / count_u32).max(Duration::from_millis(500));
        return vec![each; count];
    }
    // Give direct-like first attempts a slightly smaller/earlier slice is handled by planning;
    // here distribute evenly after reserving mins.
    let extra = total.saturating_sub(min_total);
    let extra_each = extra / count_u32;
    let mut rem = extra.saturating_sub(extra_each.saturating_mul(count_u32));
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let bonus = if rem > Duration::ZERO {
            let b = Duration::from_millis(250).min(rem);
            rem = rem.saturating_sub(b);
            b
        } else {
            Duration::ZERO
        };
        out.push(min + extra_each + bonus);
    }
    out
}

/// Observable Smart Connect events (safe to expose; do not include bridge lines).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum SmartConnectEvent {
    /// Planning completed; attempts are about to run.
    Started {
        /// Total budget in milliseconds.
        total_budget_ms: u64,
        /// Planned attempt count.
        attempts: usize,
    },
    /// An attempt is starting.
    AttemptStarted {
        /// 1-based attempt number.
        attempt: usize,
        /// Total attempts.
        total: usize,
        /// Transport/method label.
        transport: String,
        /// Reason (safe).
        reason: String,
        /// Allocated budget for this attempt (ms).
        budget_ms: u64,
        /// Overall remaining budget at start (ms).
        remaining_ms: u64,
        /// Deadline relative to run start (ms).
        deadline_ms: u64,
        /// Bridge source, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bridge_source: Option<BridgeSource>,
    },
    /// An attempt failed or timed out; Smart Connect may continue.
    AttemptFailed {
        /// 1-based attempt number.
        attempt: usize,
        /// Transport/method label.
        transport: String,
        /// Safe failure reason.
        reason: String,
        /// Elapsed for this attempt (ms).
        elapsed_ms: u64,
        /// Overall remaining budget (ms).
        remaining_ms: u64,
        /// Whether another attempt will be tried.
        will_retry: bool,
    },
    /// An attempt succeeded.
    AttemptSucceeded {
        /// 1-based attempt number.
        attempt: usize,
        /// Transport/method label.
        transport: String,
        /// Elapsed for this attempt (ms).
        elapsed_ms: u64,
    },
    /// All attempts exhausted without success.
    Exhausted {
        /// Safe summary (no secrets).
        reason: String,
    },
    /// Cancelled by caller/user.
    Cancelled {
        /// Safe reason.
        reason: String,
    },
}

/// Result of executing one attempt.
#[derive(Debug, Clone)]
pub struct AttemptResult {
    /// Whether the attempt connected/bootstrapped successfully.
    pub success: bool,
    /// Safe reason/detail (no secrets/bridge material).
    pub reason: String,
}

/// Final Smart Connect outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartConnectOutcome {
    /// Whether Smart Connect connected successfully.
    pub success: bool,
    /// Winning attempt number (1-based), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<usize>,
    /// Winning transport label, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Bridge source for the winner, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_source: Option<BridgeSource>,
    /// Safe diagnostic summary (no secrets).
    pub summary: String,
}

/// Run Smart Connect with a plan.
///
/// - `is_cancelled` is checked before/around attempts (cooperative cancellation).
/// - `observe` receives observable events.
/// - `executor` runs attempt `attempt` and must respect `attempt.budget` (and may
///   also consult `is_cancelled`); it returns an [`AttemptResult`].
///
/// Bridge lines live in `PlannedAttempt::bridge_lines` (sensitive) — observers
/// must not log them; events intentionally omit them.
pub async fn run<F, Fut, C, Obs>(
    plan: SmartConnectPlan,
    mut is_cancelled: C,
    mut observe: Obs,
    mut executor: F,
) -> SmartConnectOutcome
where
    F: FnMut(PlannedAttempt, Duration) -> Fut,
    Fut: Future<Output = AttemptResult>,
    C: FnMut() -> bool,
    Obs: FnMut(SmartConnectEvent),
{
    let start = Instant::now();
    observe(SmartConnectEvent::Started {
        total_budget_ms: plan.total_budget.as_millis() as u64,
        attempts: plan.attempts.len(),
    });

    if plan.attempts.is_empty() {
        let summary = "no Smart Connect attempts planned".to_owned();
        observe(SmartConnectEvent::Exhausted {
            reason: summary.clone(),
        });
        return SmartConnectOutcome {
            success: false,
            attempt: None,
            transport: None,
            bridge_source: None,
            summary,
        };
    }

    for (i, attempt) in plan.attempts.into_iter().enumerate() {
        if is_cancelled() {
            let reason = "cancelled".to_owned();
            observe(SmartConnectEvent::Cancelled {
                reason: reason.clone(),
            });
            return SmartConnectOutcome {
                success: false,
                attempt: None,
                transport: None,
                bridge_source: None,
                summary: reason,
            };
        }

        let elapsed = start.elapsed();
        let remaining_total = plan.total_budget.saturating_sub(elapsed);
        if remaining_total.is_zero() {
            break;
        }
        let budget = attempt.budget.min(remaining_total);
        let deadline_ms = (elapsed + budget).as_millis() as u64;
        observe(SmartConnectEvent::AttemptStarted {
            attempt: attempt.index,
            total: attempt.total,
            transport: attempt.kind.label().to_owned(),
            reason: attempt.reason.clone(),
            budget_ms: budget.as_millis() as u64,
            remaining_ms: remaining_total.as_millis() as u64,
            deadline_ms,
            bridge_source: attempt.bridge_source,
        });

        let attempt_start = Instant::now();
        let kind = attempt.kind.clone();
        let index = attempt.index;
        let total = attempt.total;
        let bridge_source = attempt.bridge_source;
        let result = executor(attempt, budget).await;
        let attempt_elapsed = attempt_start.elapsed();

        if is_cancelled() && !result.success {
            let reason = "cancelled".to_owned();
            observe(SmartConnectEvent::Cancelled {
                reason: reason.clone(),
            });
            return SmartConnectOutcome {
                success: false,
                attempt: None,
                transport: None,
                bridge_source: None,
                summary: reason,
            };
        }

        if result.success {
            observe(SmartConnectEvent::AttemptSucceeded {
                attempt: index,
                transport: kind.label().to_owned(),
                elapsed_ms: attempt_elapsed.as_millis() as u64,
            });
            return SmartConnectOutcome {
                success: true,
                attempt: Some(index),
                transport: Some(kind.label().to_owned()),
                bridge_source,
                summary: format!(
                    "connected via {} (attempt {}/{})",
                    kind.label(),
                    index,
                    total
                ),
            };
        }

        let remaining_ms = plan
            .total_budget
            .saturating_sub(start.elapsed())
            .as_millis() as u64;
        let will_retry = i + 1 < total && remaining_ms > 0;
        observe(SmartConnectEvent::AttemptFailed {
            attempt: index,
            transport: kind.label().to_owned(),
            reason: result.reason,
            elapsed_ms: attempt_elapsed.as_millis() as u64,
            remaining_ms,
            will_retry,
        });
    }

    let summary = "Smart Connect exhausted all attempts without connecting".to_owned();
    observe(SmartConnectEvent::Exhausted {
        reason: summary.clone(),
    });
    SmartConnectOutcome {
        success: false,
        attempt: None,
        transport: None,
        bridge_source: None,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_budgets_across_attempts() {
        let b = allocate_budgets(Duration::from_secs(30), Duration::from_secs(5), 4);
        assert_eq!(b.len(), 4);
        let total: Duration = b.iter().copied().sum();
        assert!(total <= Duration::from_secs(30));
        assert!(b.iter().all(|d| *d >= Duration::from_secs(5)));
    }

    #[test]
    fn plans_auto_direct_then_snowflake_obfs4() {
        let cfg = SmartConnectConfig::default();
        let plan = SmartConnectPlan::build(&cfg, &Default::default(), None);
        let kinds: Vec<_> = plan.attempts.iter().map(|a| a.kind.label()).collect();
        assert_eq!(kinds, vec!["direct", "snowflake", "obfs4"]);
        assert!(plan.attempts.iter().all(|a| !a.budget.is_zero()));
    }

    #[test]
    fn plans_custom_when_lines_present() {
        let mut cfg = SmartConnectConfig::default();
        cfg.has_configured_bridges = true;
        cfg.custom_lines = vec!["obfs4 1.2.3.4:1 AAAA cert=x iat-mode=0".to_owned()];
        let plan = SmartConnectPlan::build(&cfg, &Default::default(), None);
        assert!(plan.attempts.iter().any(|a| a.kind == AttemptKind::Custom));
        // direct should not be first when bridges are configured
        assert_ne!(plan.attempts[0].kind, AttemptKind::Direct);
    }

    #[tokio::test]
    async fn runs_and_reports_observable_attempts_until_success() {
        let cfg = SmartConnectConfig {
            total_budget: Duration::from_secs(20),
            min_attempt_budget: Duration::from_secs(1),
            ..Default::default()
        };
        let plan = SmartConnectPlan::build(&cfg, &Default::default(), None);
        let mut events = Vec::new();
        let mut calls = 0usize;
        let out = run(
            plan,
            || false,
            |e| events.push(e),
            |_attempt, _budget| {
                calls += 1;
                let ok = calls == 2; // fail direct, succeed snowflake
                async move {
                    AttemptResult {
                        success: ok,
                        reason: if ok { "ok".into() } else { "timeout".into() },
                    }
                }
            },
        )
        .await;
        assert!(out.success);
        assert_eq!(out.transport.as_deref(), Some("snowflake"));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SmartConnectEvent::Started { .. }))
        );
        assert!(events.iter().any(|e| matches!(
            e,
            SmartConnectEvent::AttemptFailed {
                attempt: 1,
                will_retry: true,
                ..
            }
        )));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SmartConnectEvent::AttemptSucceeded { attempt: 2, .. }))
        );
    }

    #[tokio::test]
    async fn cancels_cooperatively() {
        let cfg = SmartConnectConfig::default();
        let plan = SmartConnectPlan::build(&cfg, &Default::default(), None);
        let mut events = Vec::new();
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancelled2 = cancelled.clone();
        let out = run(
            plan,
            move || cancelled2.load(std::sync::atomic::Ordering::SeqCst),
            |e| events.push(e),
            |_attempt, _budget| {
                cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
                async move {
                    AttemptResult {
                        success: false,
                        reason: "timeout".into(),
                    }
                }
            },
        )
        .await;
        assert!(!out.success);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SmartConnectEvent::Cancelled { .. }))
                || out.summary.contains("cancel")
        );
    }
}
