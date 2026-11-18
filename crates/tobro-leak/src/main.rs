//! `tobro-leak` — run the TUN leak scenarios against the real helper.
//!
//! Safe scenarios touch only reserved test prefixes and can run on a live
//! workstation (with root). The intrusive tier captures the real default
//! routes and is gated behind `--intrusive` plus
//! `TOBRO_LEAK_ALLOW_INTRUSIVE=1`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use tobro_leak::{HarnessConfig, SCENARIOS, Status, run_all, scenario_info};

#[derive(Debug, Parser)]
#[command(
    name = "tobro-leak",
    about = "End-to-end TUN leak tests for tobro (real helper, real TUN device)",
    version
)]
struct Cli {
    /// List the scenarios and exit.
    #[arg(long)]
    list: bool,
    /// Run only these scenarios (repeatable). Default: the safe tier.
    #[arg(long = "scenario", value_name = "ID")]
    scenarios: Vec<String>,
    /// Include the intrusive tier (also needs TOBRO_LEAK_ALLOW_INTRUSIVE=1).
    #[arg(long)]
    intrusive: bool,
    /// Emit machine-readable JSON instead of the human table.
    #[arg(long)]
    json: bool,
    /// Explicit helper binary (default: discover next to this binary / target).
    #[arg(long, value_name = "PATH")]
    helper: Option<PathBuf>,
    /// Per-operation timeout, in seconds.
    #[arg(long, default_value_t = 5, value_name = "SECS")]
    timeout: u64,
    /// Treat skipped scenarios as failures (use in CI).
    #[arg(long)]
    fail_on_skip: bool,
    /// Print every check, not only failures.
    #[arg(long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("tobro-leak: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    if cli.list {
        for info in SCENARIOS {
            println!(
                "{:<10} {:<26} {}",
                info.tier.label(),
                info.id,
                info.description
            );
        }
        return Ok(ExitCode::SUCCESS);
    }

    let mut ids = cli.scenarios.clone();
    for id in &ids {
        if scenario_info(id).is_none() {
            eprintln!("tobro-leak: unknown scenario {id:?}\n\nAvailable scenarios:");
            for info in SCENARIOS {
                eprintln!("  {:<10} {}", info.tier.label(), info.id);
            }
            return Ok(ExitCode::from(2));
        }
    }
    if ids.is_empty() {
        ids = SCENARIOS
            .iter()
            .filter(|info| {
                info.tier == tobro_leak::Tier::Safe
                    || (cli.intrusive && info.tier == tobro_leak::Tier::Intrusive)
            })
            .map(|info| info.id.to_owned())
            .collect();
    }

    let config = HarnessConfig {
        helper: cli.helper,
        timeout: Duration::from_secs(cli.timeout.max(1)),
        intrusive: cli.intrusive,
    };
    let reports = run_all(&config, &ids).await;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    } else {
        print_human(&reports, cli.verbose);
    }

    let failed = reports
        .iter()
        .any(|report| report.is_failure(cli.fail_on_skip));
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn print_human(reports: &[tobro_leak::ScenarioReport], verbose: bool) {
    for report in reports {
        let (label, summary) = match report.status {
            Status::Passed => ("PASS", format!("{} check(s)", report.checks.len())),
            Status::Skipped => (
                "SKIP",
                report
                    .reason
                    .clone()
                    .unwrap_or_else(|| "skipped".to_owned()),
            ),
            Status::Failed => (
                "FAIL",
                report
                    .checks
                    .last()
                    .map(|check| check.detail.clone())
                    .unwrap_or_else(|| "failed".to_owned()),
            ),
        };
        println!(
            "{label:<4} {:<26} {:>6}ms  {summary}",
            report.scenario, report.duration_ms
        );
        let show_checks = verbose || report.status == Status::Failed;
        if show_checks && report.status != Status::Skipped {
            for check in &report.checks {
                let marker = if check.passed { "ok" } else { "!!" };
                println!("       {marker}  {}: {}", check.name, check.detail);
            }
        }
    }

    let passed = reports
        .iter()
        .filter(|report| report.status == Status::Passed)
        .count();
    let skipped = reports
        .iter()
        .filter(|report| report.status == Status::Skipped)
        .count();
    let failed = reports
        .iter()
        .filter(|report| report.status == Status::Failed)
        .count();
    println!("\n{passed} passed, {failed} failed, {skipped} skipped");
}
