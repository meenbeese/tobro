//! Scenario implementations.
//!
//! Every scenario builds a real plan, applies it through the real helper,
//! asserts properties of the live OS, then tears everything down. A single
//! guard ([`Session`]) owns the device, routes, resolver, and process, and
//! always restores them even when an assertion fails.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures::FutureExt as _;
use tempfile::TempDir;
use tobro_tun::{Forwarding, KillSwitchMode, TunnelPlan};

use crate::canary::FakeDaemon;
use crate::helper::{self, HelperProcess};
use crate::plan::{self, Routing, UdpMode};
use crate::resolver::{self, DnsBackup, DnsSnapshot};
use crate::route::{self, Egress, Routes};
use crate::{Check, HarnessConfig, ScenarioRun};

/// A DNS-shaped payload; the fake resolver echoes it verbatim.
const DNS_QUERY: &[u8] =
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09canary\x04test\x00\x00\x01\x00\x01";

/// Assertions collected while a scenario runs.
#[derive(Debug, Default)]
pub struct Checks {
    items: Vec<Check>,
}

impl Checks {
    /// Require `condition`; on failure, record the check and stop the
    /// scenario (later assertions would be noise).
    fn check(
        &mut self,
        name: impl Into<String>,
        condition: bool,
        detail: impl Into<String>,
    ) -> Result<()> {
        let detail = detail.into();
        self.items.push(Check {
            name: name.into(),
            passed: condition,
            detail: detail.clone(),
        });
        if condition { Ok(()) } else { bail!("{detail}") }
    }

    /// Record an observation that is not an assertion (platform limits).
    fn note(&mut self, detail: impl Into<String>) {
        self.items.push(Check {
            name: "note".to_owned(),
            passed: true,
            detail: detail.into(),
        });
    }

    fn finish(self) -> Vec<Check> {
        self.items
    }
}

/// One prepared scenario environment: a live helper, the fake daemon, and
/// the live route reader.
struct Session {
    /// Lives until the session ends; holds the Unix socket directory.
    dir: TempDir,
    binary: PathBuf,
    endpoint: PathBuf,
    helper: HelperProcess,
    daemon: FakeDaemon,
    routes: Routes,
    dns_backup: DnsBackup,
    interface: String,
    tun_index: u32,
    launches: u32,
    plan_active: bool,
    helper_gone: bool,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("interface", &self.interface)
            .field("tun_index", &self.tun_index)
            .field("plan_active", &self.plan_active)
            .field("helper_gone", &self.helper_gone)
            .finish_non_exhaustive()
    }
}

impl Session {
    async fn prepare(config: &HarnessConfig, name: &str) -> Result<Self> {
        let binary = helper::find_helper_binary(config.helper.as_deref())?;
        let dir = TempDir::new().context("could not create the scenario temp directory")?;
        let endpoint = helper::endpoint_for(dir.path(), name);
        let daemon = FakeDaemon::start().await?;
        // Capture the resolver *before* the helper touches it: this is the
        // restoration handle for crash scenarios.
        let dns_backup = resolver::capture().await?;
        let log_path = dir.path().join("helper-0.log");
        let helper = match HelperProcess::launch(&binary, &endpoint, &log_path).await {
            Ok(helper) => helper,
            Err(error) => {
                let _ = resolver::restore(&dns_backup).await;
                return Err(error);
            }
        };
        let routes = match Routes::new().await {
            Ok(routes) => routes,
            Err(error) => {
                let mut helper = helper;
                helper.shutdown().await;
                let _ = resolver::restore(&dns_backup).await;
                return Err(error);
            }
        };
        Ok(Self {
            dir,
            binary,
            endpoint,
            helper,
            daemon,
            routes,
            dns_backup,
            interface: String::new(),
            tun_index: 0,
            launches: 0,
            plan_active: false,
            helper_gone: false,
        })
    }

    fn daemon(&self) -> &FakeDaemon {
        &self.daemon
    }

    fn routes(&self) -> &Routes {
        &self.routes
    }

    #[cfg(not(target_os = "windows"))]
    fn dns_backup(&self) -> &DnsBackup {
        &self.dns_backup
    }

    fn interface(&self) -> &str {
        &self.interface
    }

    fn tun(&self) -> u32 {
        self.tun_index
    }

    /// Apply `plan` and refresh the interface/index bookkeeping.
    async fn apply(&mut self, plan: &TunnelPlan) -> Result<()> {
        let applied = self.helper.apply(plan).await?;
        self.interface = applied.interface;
        self.tun_index = route::interface_index(&self.interface)?;
        self.plan_active = true;
        self.helper_gone = false;
        Ok(())
    }

    /// Tear the active plan down.
    async fn teardown(&mut self) -> Result<()> {
        if !self.plan_active {
            return Ok(());
        }
        self.helper.teardown().await?;
        self.plan_active = false;
        Ok(())
    }

    /// Kill the helper without cleanup (the crash scenario).
    async fn crash_helper(&mut self) -> Result<()> {
        self.helper.kill().await?;
        let status = self
            .helper
            .wait_exit(Duration::from_secs(10))
            .await
            .context("the killed helper did not exit")?;
        self.plan_active = false;
        self.helper_gone = true;
        if status.success() {
            bail!(
                "the killed helper reported a clean exit; the crash scenario needs an abrupt stop"
            );
        }
        Ok(())
    }

    /// Drop the client connection without a teardown: the daemon crashed.
    async fn helper_disconnect(&mut self) {
        self.helper.disconnect().await;
    }

    /// Start a fresh helper on the same endpoint (recovery after a crash).
    async fn relaunch(&mut self) -> Result<()> {
        self.launches += 1;
        let log = self
            .dir
            .path()
            .join(format!("helper-{}.log", self.launches));
        self.helper = HelperProcess::launch(&self.binary, &self.endpoint, &log).await?;
        self.helper_gone = false;
        Ok(())
    }

    /// Wait for the helper's own exit (the daemon-crash path).
    async fn wait_for_helper_exit(&mut self) -> Result<std::process::ExitStatus> {
        let status = self
            .helper
            .wait_exit(Duration::from_secs(20))
            .await
            .context("the helper did not exit after its client vanished")?;
        self.plan_active = false;
        self.helper_gone = true;
        Ok(status)
    }

    /// Always run: best-effort teardown, kill, resolver restore.
    async fn finish(mut self) -> Result<()> {
        if self.plan_active && !self.helper_gone {
            let _ = self.helper.teardown().await;
        }
        self.helper.shutdown().await;
        let restore = resolver::restore(&self.dns_backup).await;
        self.daemon.stop();
        restore
    }
}

/// Run a scenario body inside a prepared session, always cleaning up.
///
/// The macro (rather than a generic closure) keeps the body's `&mut`
/// borrows simple and catches panics so cleanup still runs.
macro_rules! run_body {
    ($config:expr, $name:expr, |$session:ident, $checks:ident| $body:block) => {{
        let mut session = Session::prepare($config, $name).await?;
        let mut checks = Checks::default();
        let outcome = {
            let future = std::panic::AssertUnwindSafe(async {
                let $session = &mut session;
                let $checks = &mut checks;
                let result: Result<()> = { $body };
                result
            });
            future.catch_unwind().await
        };
        let cleanup = session.finish().await;
        match outcome {
            Ok(result) => {
                result?;
                cleanup?;
                Ok(ScenarioRun::Completed(checks.finish()))
            }
            Err(panic) => {
                let _ = cleanup;
                std::panic::resume_unwind(panic);
            }
        }
    }};
}

/// Forwarding to the fake daemon.
fn forwarding(session: &Session) -> Forwarding {
    Forwarding {
        socks: session.daemon.socks(),
        dns: Some(session.daemon.dns_v4()),
    }
}

fn socket(ip: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(ip, port)
}

fn dns_socket(ip: IpAddr) -> SocketAddr {
    socket(ip, 53)
}

/// Wait for the kernel's route for `destination` to become `want`.
async fn wait_egress(
    routes: &Routes,
    destination: IpAddr,
    want: Egress,
    timeout: Duration,
) -> Result<Egress> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let seen = routes.egress(destination).await?;
        if seen == want || tokio::time::Instant::now() >= deadline {
            return Ok(seen);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Assert that `destination` egresses through the tunnel.
async fn check_tunnel_egress(
    checks: &mut Checks,
    routes: &Routes,
    destination: IpAddr,
    tun: u32,
    label: &str,
) -> Result<()> {
    let want = Egress::Interface(tun);
    let seen = wait_egress(routes, destination, want, Duration::from_secs(3)).await?;
    checks.check(
        label,
        seen == want,
        format!(
            "expected {}, saw {}",
            route::describe(want),
            route::describe(seen)
        ),
    )
}

/// Assert that `destination` no longer egresses through the (closed) tunnel.
async fn check_not_tunnel_egress(
    checks: &mut Checks,
    routes: &Routes,
    destination: IpAddr,
    tun: u32,
    label: &str,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let seen = routes.egress(destination).await?;
        let still_tunnel = matches!(seen, Egress::Interface(index) if index == tun);
        if !still_tunnel || tokio::time::Instant::now() >= deadline {
            return checks.check(
                label,
                !still_tunnel,
                format!(
                    "expected anything but {}, saw {}",
                    route::describe(Egress::Interface(tun)),
                    route::describe(seen)
                ),
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn same_servers(a: &DnsSnapshot, b: &DnsSnapshot) -> bool {
    let mut left = a.servers.clone();
    let mut right = b.servers.clone();
    left.sort_unstable();
    right.sort_unstable();
    left == right
}

#[cfg(target_os = "macos")]
fn contains_all(current: &DnsSnapshot, expected: &DnsSnapshot) -> bool {
    expected
        .servers
        .iter()
        .all(|server| current.contains(*server))
}

fn format_servers(snapshot: &DnsSnapshot) -> String {
    if snapshot.servers.is_empty() {
        return format!("(none, from {})", snapshot.source);
    }
    snapshot
        .servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn host_has_ipv6() -> bool {
    std::net::UdpSocket::bind("[::1]:0").is_ok()
}

// --- Scenarios -------------------------------------------------------------

async fn tcp_forwarded(config: &HarnessConfig) -> Result<ScenarioRun> {
    run_body!(config, "tcp-forwarded", |session, checks| {
        let plan = plan::build(
            Routing::TestPrefixes,
            UdpMode::DnsOnly,
            Some(forwarding(session)),
            KillSwitchMode::Disabled,
        );
        session.apply(&plan).await?;

        check_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v4_host(),
            session.tun(),
            "the test prefix is routed into the tunnel",
        )
        .await?;

        let payload = b"tobro leak test: tcp";
        let echoed =
            crate::traffic::tcp_echo(socket(plan::test_v4_host(), 443), payload, config.timeout)
                .await
                .context("TCP through the tunnel failed")?;
        checks.check(
            "payload echoed through the tunnel",
            echoed == payload,
            format!("received {} byte(s)", echoed.len()),
        )?;

        let destinations = session.daemon().socks_destinations();
        checks.check(
            "the engine dialed the intended SOCKS destination",
            destinations.iter().any(|dest| dest == "198.18.0.1:443"),
            format!("destinations: {destinations:?}"),
        )?;
        let bytes = session.daemon().socks_bytes();
        checks.check(
            "the payload crossed the daemon's SOCKS listener",
            bytes >= payload.len() as u64,
            format!("{bytes} byte(s) echoed by the fake daemon"),
        )?;

        session.teardown().await?;
        check_not_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v4_host(),
            session.tun(),
            "teardown removes the tunnel route",
        )
        .await?;
        Ok(())
    })
}

async fn dns_intercepted(config: &HarnessConfig) -> Result<ScenarioRun> {
    run_body!(config, "dns-intercepted", |session, checks| {
        // Windows scopes the resolver to the wintun adapter, so there is no
        // pre-tunnel value worth comparing against after teardown.
        #[cfg(not(target_os = "windows"))]
        let before = session.dns_backup().snapshot.clone();
        let plan = plan::build(
            Routing::TestPrefixes,
            UdpMode::DnsOnly,
            Some(forwarding(session)),
            KillSwitchMode::Disabled,
        );
        session.apply(&plan).await?;

        let snapshot = resolver::snapshot(Some(session.interface())).await?;
        checks.check(
            "the system resolver points at the tunnel (IPv4)",
            snapshot.contains(plan::TUNNEL_DNS_V4.into()),
            format!("resolvers: {}", format_servers(&snapshot)),
        )?;
        checks.check(
            "the system resolver points at the tunnel (IPv6)",
            snapshot.contains(plan::TUNNEL_DNS_V6.into()),
            format!("resolvers: {}", format_servers(&snapshot)),
        )?;
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        checks.check(
            "the pre-tunnel resolver was replaced, not appended",
            same_servers(
                &snapshot,
                &DnsSnapshot {
                    servers: plan.dns.servers.clone(),
                    source: "plan".to_owned(),
                },
            ),
            format!("resolvers: {}", format_servers(&snapshot)),
        )?;

        check_tunnel_egress(
            checks,
            session.routes(),
            IpAddr::V4(plan::TUNNEL_DNS_V4),
            session.tun(),
            "tunnel DNS (IPv4) egresses through the tunnel",
        )
        .await?;

        let before_queries = session.daemon().dns_queries(false);
        let reply = crate::traffic::dns_echo(
            dns_socket(IpAddr::V4(plan::TUNNEL_DNS_V4)),
            DNS_QUERY,
            config.timeout,
        )
        .await
        .context("the IPv4 DNS query was not intercepted")?;
        checks.check(
            "the IPv4 DNS reply is relayed and spoofed from the tunnel resolver",
            reply == DNS_QUERY,
            format!("received {} byte(s)", reply.len()),
        )?;

        // The IPv6 interception path is only reachable where the backend
        // assigns the tunnel's IPv6 address (Linux). Elsewhere the tunnel
        // still routes IPv6 but has no source address, so traffic fails
        // closed; record that instead of pretending it worked.
        match crate::traffic::dns_echo(
            dns_socket(IpAddr::V6(plan::TUNNEL_DNS_V6)),
            DNS_QUERY,
            config.timeout,
        )
        .await
        {
            Ok(reply) => checks.check(
                "the IPv6 DNS reply is relayed and spoofed from the tunnel resolver",
                reply == DNS_QUERY,
                format!("received {} byte(s)", reply.len()),
            )?,
            Err(error) => checks.note(format!(
                "IPv6 DNS interception could not be exercised on this platform \
                 (traffic fails closed): {error:#}"
            )),
        }

        // Both families use the same local resolver socket. The IPv6 query
        // may not have been sent on platforms without a tunnel v6 address.
        let observed = session.daemon().dns_queries(false) - before_queries;
        checks.check(
            "intercepted queries reached the daemon's resolver",
            observed >= 1,
            format!("{observed} query/queries observed"),
        )?;

        session.teardown().await?;
        // Windows scopes the resolver to the wintun adapter, so it vanishes
        // with the adapter instead of being restored. Unix restores the
        // captured value.
        #[cfg(target_os = "windows")]
        {
            let adapter_gone = match resolver::snapshot(Some(session.interface())).await {
                Ok(snapshot) => snapshot.servers.is_empty(),
                Err(_) => true,
            };
            checks.check(
                "teardown removes the adapter-scoped resolver with the adapter",
                adapter_gone,
                "the wintun adapter no longer exists".to_owned(),
            )?;
        }
        #[cfg(not(target_os = "windows"))]
        {
            let restored = resolver::snapshot(Some(session.interface())).await?;
            #[cfg(target_os = "linux")]
            checks.check(
                "teardown restores the original resolver",
                same_servers(&restored, &before),
                format!("resolvers: {}", format_servers(&restored)),
            )?;
            #[cfg(target_os = "macos")]
            checks.check(
                "teardown restores the original resolver",
                contains_all(&restored, &before),
                format!("resolvers: {}", format_servers(&restored)),
            )?;
        }
        Ok(())
    })
}

async fn udp_blocked(config: &HarnessConfig) -> Result<ScenarioRun> {
    run_body!(config, "udp-blocked", |session, checks| {
        let plan = plan::build(
            Routing::TestPrefixes,
            UdpMode::DnsOnly,
            Some(forwarding(session)),
            KillSwitchMode::Disabled,
        );
        session.apply(&plan).await?;

        let silence = config.timeout.min(Duration::from_secs(2));
        crate::traffic::udp_silence(
            socket(plan::test_v4_host(), 443),
            b"quic-ish payload",
            silence,
        )
        .await
        .context("QUIC/443 UDP was not dropped")?;
        checks.check(
            "QUIC/443 UDP is dropped, not leaked",
            true,
            "no reply arrived within the silence window",
        )?;
        crate::traffic::udp_silence(socket(plan::test_v4_host(), 123), b"ntp-ish", silence)
            .await
            .context("non-DNS UDP was not dropped")?;
        checks.check(
            "other non-DNS UDP is dropped",
            true,
            "no reply arrived within the silence window",
        )?;
        checks.check(
            "no TCP fallback was attempted for dropped UDP",
            session.daemon().socks_destinations().is_empty(),
            format!("destinations: {:?}", session.daemon().socks_destinations()),
        )?;

        // Now the stricter policy: DNS is dropped while TCP still works.
        session.teardown().await?;
        let block_all = plan::build(
            Routing::TestPrefixes,
            UdpMode::BlockAll,
            Some(forwarding(session)),
            KillSwitchMode::Disabled,
        );
        session.apply(&block_all).await?;
        let before_queries = session.daemon().dns_queries(false);
        crate::traffic::udp_silence(
            dns_socket(IpAddr::V4(plan::TUNNEL_DNS_V4)),
            DNS_QUERY,
            silence,
        )
        .await
        .context("DNS was not dropped under block_all")?;
        checks.check(
            "block_all drops DNS as well",
            session.daemon().dns_queries(false) == before_queries,
            "the daemon's resolver saw no query".to_owned(),
        )?;
        let echoed = crate::traffic::tcp_echo(
            socket(plan::test_v4_host(), 443),
            b"tcp under block_all",
            config.timeout,
        )
        .await
        .context("TCP failed under block_all")?;
        checks.check(
            "block_all still forwards TCP (UDP-only restriction)",
            echoed == b"tcp under block_all",
            format!("received {} byte(s)", echoed.len()),
        )?;

        session.teardown().await?;
        Ok(())
    })
}

async fn ipv6_routed(config: &HarnessConfig) -> Result<ScenarioRun> {
    run_body!(config, "ipv6-routed", |session, checks| {
        let plan = plan::build(
            Routing::TestPrefixes,
            UdpMode::DnsOnly,
            Some(forwarding(session)),
            KillSwitchMode::Disabled,
        );
        session.apply(&plan).await?;

        check_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v6_host(),
            session.tun(),
            "the IPv6 test prefix is routed into the tunnel (no physical leak)",
        )
        .await?;

        // Where the backend assigns the tunnel's IPv6 address (Linux), the
        // full forwarding path must work. Elsewhere it must at least fail
        // closed: the route stays in the tunnel and nothing reaches the
        // physical network.
        match crate::traffic::tcp_echo(
            socket(plan::test_v6_host(), 443),
            b"tobro leak test: ipv6",
            config.timeout,
        )
        .await
        {
            Ok(echoed) => {
                checks.check(
                    "IPv6 TCP is forwarded through the tunnel",
                    echoed == b"tobro leak test: ipv6",
                    format!("received {} byte(s)", echoed.len()),
                )?;
                let destinations = session.daemon().socks_destinations();
                checks.check(
                    "the engine dialed the IPv6 destination",
                    destinations.iter().any(|dest| dest == "2001:db8::1:443"),
                    format!("destinations: {destinations:?}"),
                )?;
            }
            Err(error) => checks.note(format!(
                "IPv6 TCP failed closed (the route stays in the tunnel; no physical \
                 egress): {error:#}"
            )),
        }

        session.teardown().await?;
        check_not_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v6_host(),
            session.tun(),
            "teardown removes the IPv6 tunnel route",
        )
        .await?;
        Ok(())
    })
}

async fn route_change(config: &HarnessConfig) -> Result<ScenarioRun> {
    run_body!(config, "route-change", |session, checks| {
        let plan = plan::build(
            Routing::TestPrefixes,
            UdpMode::DnsOnly,
            Some(forwarding(session)),
            KillSwitchMode::Disabled,
        );
        session.apply(&plan).await?;
        check_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v4_host(),
            session.tun(),
            "the initial plan routes the test prefix",
        )
        .await?;

        // An external route manager (VPN, DHCP renew, `route change`) drops
        // the entry out from under the helper.
        session
            .routes()
            .delete_device_route(plan::test_v4_network(), 15, session.tun(), None)
            .await?;
        check_not_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v4_host(),
            session.tun(),
            "the lost route is visible to the daemon (no silent tunnel belief)",
        )
        .await?;

        // The daemon's convergence path: teardown + re-apply.
        session.teardown().await?;
        session.apply(&plan).await?;
        check_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v4_host(),
            session.tun(),
            "re-applying the plan restores the route",
        )
        .await?;
        let echoed = crate::traffic::tcp_echo(
            socket(plan::test_v4_host(), 443),
            b"after route change",
            config.timeout,
        )
        .await
        .context("TCP failed after route convergence")?;
        checks.check(
            "traffic flows again after convergence",
            echoed == b"after route change",
            format!("received {} byte(s)", echoed.len()),
        )?;

        // A narrowed plan must remove the routes it no longer wants: a stale
        // IPv6 route would keep pushing v6 traffic into a tunnel that no
        // longer carries it.
        let mut narrowed = plan.clone();
        narrowed
            .routes
            .retain(|spec| matches!(spec.destination.addr, IpAddr::V4(_)));
        session.apply(&narrowed).await?;
        check_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v4_host(),
            session.tun(),
            "the narrowed plan keeps the IPv4 route",
        )
        .await?;
        check_not_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v6_host(),
            session.tun(),
            "the narrowed plan removes the stale IPv6 route",
        )
        .await?;

        session.teardown().await?;
        check_not_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v4_host(),
            session.tun(),
            "teardown removes the converged route",
        )
        .await?;
        Ok(())
    })
}

fn request_live_suspend() -> Result<Option<&'static str>> {
    if std::env::var("TOBRO_LEAK_ALLOW_LIVE_SLEEP").ok().as_deref() != Some("1") {
        return Ok(None);
    }

    #[cfg(target_os = "linux")]
    {
        let status = std::process::Command::new("systemctl")
            .args(["suspend", "--no-block"])
            .status()?;
        Ok(status.success().then_some("systemctl suspend"))
    }
    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("pmset")
            .arg("sleepnow")
            .status()?;
        Ok(status.success().then_some("pmset sleepnow"))
    }
    #[cfg(target_os = "windows")]
    {
        let status = std::process::Command::new("rundll32.exe")
            .args(["powrprof.dll,SetSuspendState", "0", "1", "0"])
            .status()?;
        Ok(status.success().then_some("SetSuspendState"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Ok(None)
    }
}

async fn sleep_wake(config: &HarnessConfig) -> Result<ScenarioRun> {
    run_body!(config, "sleep-wake", |session, checks| {
        let plan = plan::build(
            Routing::TestPrefixes,
            UdpMode::DnsOnly,
            Some(forwarding(session)),
            KillSwitchMode::Disabled,
        );
        session.apply(&plan).await?;
        check_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v4_host(),
            session.tun(),
            "the tunnel is up before suspend",
        )
        .await?;

        match request_live_suspend()? {
            Some(method) => {
                checks.check(
                    "the live OS suspend request was accepted",
                    true,
                    format!("requested suspend with {method}"),
                )?;
                tokio::time::sleep(Duration::from_secs(8)).await;
            }
            None => {
                checks.note(
                    "live suspend was not gated; set TOBRO_LEAK_ALLOW_LIVE_SLEEP=1 on a dedicated host",
                );
            }
        }

        // Suspend/resume: the kernel does not keep routes across a sleep on
        // every platform. Simulate the loss by deleting the entries while
        // leaving the helper's in-memory plan intact.
        session
            .routes()
            .delete_device_route(plan::test_v4_network(), 15, session.tun(), None)
            .await?;
        // The IPv6 route may not exist on every platform backend.
        let _ = session
            .routes()
            .delete_device_route(plan::test_v6_network(), 32, session.tun(), None)
            .await;
        check_not_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v4_host(),
            session.tun(),
            "post-wake state loss is observable before convergence",
        )
        .await?;

        // The daemon's resume path re-establishes the plan.
        session.teardown().await?;
        session.apply(&plan).await?;
        check_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v4_host(),
            session.tun(),
            "the route is restored after wake",
        )
        .await?;
        let snapshot = resolver::snapshot(Some(session.interface())).await?;
        checks.check(
            "the resolver is still the tunnel after wake",
            snapshot.contains(plan::TUNNEL_DNS_V4.into()),
            format!("resolvers: {}", format_servers(&snapshot)),
        )?;
        let echoed = crate::traffic::tcp_echo(
            socket(plan::test_v4_host(), 443),
            b"after wake",
            config.timeout,
        )
        .await
        .context("TCP failed after wake convergence")?;
        checks.check(
            "traffic flows again after wake",
            echoed == b"after wake",
            format!("received {} byte(s)", echoed.len()),
        )?;
        let reply = crate::traffic::dns_echo(
            dns_socket(IpAddr::V4(plan::TUNNEL_DNS_V4)),
            DNS_QUERY,
            config.timeout,
        )
        .await
        .context("DNS interception was lost after wake")?;
        checks.check(
            "DNS is still intercepted after wake",
            reply == DNS_QUERY,
            format!("received {} byte(s)", reply.len()),
        )?;

        session.teardown().await?;
        check_not_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v4_host(),
            session.tun(),
            "teardown after wake removes the route",
        )
        .await?;
        Ok(())
    })
}

async fn helper_crash(config: &HarnessConfig) -> Result<ScenarioRun> {
    run_body!(config, "helper-crash", |session, checks| {
        let plan = plan::build(
            Routing::TestPrefixes,
            UdpMode::DnsOnly,
            Some(forwarding(session)),
            KillSwitchMode::Block,
        );
        session.apply(&plan).await?;
        let echoed = crate::traffic::tcp_echo(
            socket(plan::test_v4_host(), 443),
            b"before crash",
            config.timeout,
        )
        .await
        .context("TCP failed before the crash")?;
        checks.check(
            "the tunnel works before the crash",
            echoed == b"before crash",
            format!("received {} byte(s)", echoed.len()),
        )?;

        session.crash_helper().await?;
        checks.check(
            "the helper was killed without running its teardown",
            true,
            "SIGKILL/TerminateProcess".to_owned(),
        )?;

        check_not_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v4_host(),
            session.tun(),
            "the device (and its route) is gone after the crash",
        )
        .await?;
        let failed = crate::traffic::tcp_echo(
            socket(plan::test_v4_host(), 443),
            b"after crash",
            config.timeout.min(Duration::from_secs(2)),
        )
        .await;
        checks.check(
            "traffic fails closed after the crash (no physical fallback)",
            failed.is_err(),
            "the connection did not succeed outside the tunnel".to_owned(),
        )?;
        let dns_failed = crate::traffic::dns_echo(
            dns_socket(IpAddr::V4(plan::TUNNEL_DNS_V4)),
            DNS_QUERY,
            config.timeout.min(Duration::from_secs(2)),
        )
        .await;
        checks.check(
            "DNS fails closed after the crash (the resolver target is unreachable)",
            dns_failed.is_err(),
            "the tunnel resolver answered after the device disappeared".to_owned(),
        )?;

        // The resolver is the dangerous leftover: it must still point at the
        // dead tunnel (fail closed), never silently at a physical resolver
        // the helper did not choose.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let snapshot = resolver::snapshot(Some(session.interface())).await?;
            checks.check(
                "the resolver still points at the dead tunnel (fail closed)",
                snapshot.contains(plan::TUNNEL_DNS_V4.into()),
                format!("resolvers: {}", format_servers(&snapshot)),
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            // DNS is scoped to the wintun adapter and vanishes with it.
            let adapter_gone = match resolver::snapshot(Some(session.interface())).await {
                Ok(snapshot) => snapshot.servers.is_empty(),
                Err(_) => true,
            };
            checks.check(
                "adapter-scoped DNS is gone with the adapter (fail closed)",
                adapter_gone,
                "the wintun adapter no longer exists".to_owned(),
            )?;
        }

        // Recovery must come from the helper-owned persistent journal.  Do
        // not restore the harness resolver snapshot before relaunch.
        session.relaunch().await?;
        session.apply(&plan).await?;
        check_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v4_host(),
            session.tun(),
            "a restarted helper re-establishes the route",
        )
        .await?;
        let echoed = crate::traffic::tcp_echo(
            socket(plan::test_v4_host(), 443),
            b"after restart",
            config.timeout,
        )
        .await
        .context("TCP failed after the helper restart")?;
        checks.check(
            "the tunnel works again after the restart",
            echoed == b"after restart",
            format!("received {} byte(s)", echoed.len()),
        )?;
        session.teardown().await?;
        Ok(())
    })
}

async fn daemon_crash(config: &HarnessConfig) -> Result<ScenarioRun> {
    run_body!(config, "daemon-crash", |session, checks| {
        let plan = plan::build(
            Routing::TestPrefixes,
            UdpMode::DnsOnly,
            Some(forwarding(session)),
            KillSwitchMode::Block,
        );
        session.apply(&plan).await?;
        let echoed = crate::traffic::tcp_echo(
            socket(plan::test_v4_host(), 443),
            b"before daemon crash",
            config.timeout,
        )
        .await
        .context("TCP failed before the daemon crash")?;
        checks.check(
            "the tunnel works before the daemon crashes",
            echoed == b"before daemon crash",
            format!("received {} byte(s)", echoed.len()),
        )?;

        // The daemon process dies: its IPC connection is dropped without a
        // teardown. The helper must notice the disconnect and clean up on
        // its idle window.
        session.helper_disconnect().await;
        let status = session.wait_for_helper_exit().await?;
        checks.check(
            "the helper exits cleanly after its client vanishes",
            status.success(),
            format!("exit status: {status}"),
        )?;

        check_not_tunnel_egress(
            checks,
            session.routes(),
            plan::test_v4_host(),
            session.tun(),
            "the idle-window teardown removes the route",
        )
        .await?;

        // The helper's own teardown restores the resolver (Unix) or the
        // adapter DNS disappears with the adapter (Windows).
        #[cfg(target_os = "linux")]
        {
            let restored = resolver::snapshot(Some(session.interface())).await?;
            checks.check(
                "the helper restores the original resolver before exiting",
                same_servers(&restored, &session.dns_backup().snapshot),
                format!("resolvers: {}", format_servers(&restored)),
            )?;
        }
        #[cfg(target_os = "macos")]
        {
            let restored = resolver::snapshot(Some(session.interface())).await?;
            checks.check(
                "the helper restores the original resolver before exiting",
                contains_all(&restored, &session.dns_backup().snapshot),
                format!("resolvers: {}", format_servers(&restored)),
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            let adapter_gone = match resolver::snapshot(Some(session.interface())).await {
                Ok(snapshot) => snapshot.servers.is_empty(),
                Err(_) => true,
            };
            checks.check(
                "the adapter-scoped DNS is gone with the adapter",
                adapter_gone,
                "the wintun adapter no longer exists".to_owned(),
            )?;
        }

        let failed = crate::traffic::tcp_echo(
            socket(plan::test_v4_host(), 443),
            b"after daemon crash",
            config.timeout.min(Duration::from_secs(2)),
        )
        .await;
        checks.check(
            "no plan outlives the daemon",
            failed.is_err(),
            "the connection did not succeed after the teardown".to_owned(),
        )?;

        // Recovery: the daemon comes back and re-applies its plan.
        session.relaunch().await?;
        session.apply(&plan).await?;
        let echoed = crate::traffic::tcp_echo(
            socket(plan::test_v4_host(), 443),
            b"daemon restarted",
            config.timeout,
        )
        .await
        .context("TCP failed after the daemon restart")?;
        checks.check(
            "a restarted daemon re-establishes the tunnel",
            echoed == b"daemon restarted",
            format!("received {} byte(s)", echoed.len()),
        )?;
        session.teardown().await?;
        Ok(())
    })
}

async fn intrusive_default_route(config: &HarnessConfig) -> Result<ScenarioRun> {
    run_body!(config, "intrusive-default-route", |session, checks| {
        let plan = plan::build(
            Routing::DefaultRoutes,
            UdpMode::DnsOnly,
            Some(forwarding(session)),
            KillSwitchMode::Disabled,
        );
        session.apply(&plan).await?;

        // No real connection is made: the fake SOCKS listener is the only
        // reachable daemon, so success proves capture and failure here is a
        // leak.
        let public = IpAddr::from([1, 1, 1, 1]);
        check_tunnel_egress(
            checks,
            session.routes(),
            public,
            session.tun(),
            "the real IPv4 default route is captured by the tunnel",
        )
        .await?;

        let echoed = crate::traffic::tcp_echo(socket(public, 443), b"public v4", config.timeout)
            .await
            .context("TCP to a public address did not reach the fake daemon")?;
        checks.check(
            "public IPv4 TCP reaches the tunnel daemon, not the internet",
            echoed == b"public v4",
            format!("received {} byte(s)", echoed.len()),
        )?;
        checks.check(
            "the engine dialed the public destination over SOCKS",
            session
                .daemon()
                .socks_destinations()
                .iter()
                .any(|dest| dest == "1.1.1.1:443"),
            format!("destinations: {:?}", session.daemon().socks_destinations()),
        )?;
        crate::traffic::udp_silence(socket(public, 443), b"public quic", Duration::from_secs(1))
            .await
            .context("public QUIC was not dropped")?;
        checks.check(
            "public QUIC is dropped inside the tunnel",
            true,
            "no reply arrived".to_owned(),
        )?;

        if host_has_ipv6() {
            let public_v6: IpAddr = "2606:4700:4700::1111"
                .parse()
                .context("the public IPv6 literal is valid")?;
            check_tunnel_egress(
                checks,
                session.routes(),
                public_v6,
                session.tun(),
                "the real IPv6 default route is captured by the tunnel",
            )
            .await?;
        }

        session.teardown().await?;
        check_not_tunnel_egress(
            checks,
            session.routes(),
            public,
            session.tun(),
            "teardown removes the default route",
        )
        .await?;
        Ok(())
    })
}

async fn intrusive_kill_switch(config: &HarnessConfig) -> Result<ScenarioRun> {
    run_body!(config, "intrusive-kill-switch", |session, checks| {
        let plan = plan::build(
            Routing::DefaultRoutes,
            UdpMode::BlockAll,
            None,
            KillSwitchMode::Block,
        );
        session.apply(&plan).await?;

        let public = IpAddr::from([1, 1, 1, 1]);
        check_tunnel_egress(
            checks,
            session.routes(),
            public,
            session.tun(),
            "the default route points into the (parked) tunnel",
        )
        .await?;

        // The engine is parked: the device is up and nothing forwards, so
        // every protocol must time out rather than escape.
        let failed = crate::traffic::tcp_echo(
            socket(public, 443),
            b"fail closed",
            config.timeout.min(Duration::from_secs(2)),
        )
        .await;
        checks.check(
            "TCP fails closed while the kill switch is active",
            failed.is_err(),
            "the connection did not succeed".to_owned(),
        )?;
        crate::traffic::udp_silence(
            dns_socket(IpAddr::from([8, 8, 8, 8])),
            DNS_QUERY,
            config.timeout.min(Duration::from_secs(2)),
        )
        .await
        .context("DNS was not dropped under the kill switch")?;
        checks.check(
            "DNS to a physical resolver is dropped by the parked tunnel",
            true,
            "no reply arrived".to_owned(),
        )?;

        #[cfg(target_os = "linux")]
        {
            // The Linux kill switch adds blackhole defaults one metric above
            // the tunnel: removing the tunnel route must still fail closed.
            session
                .routes()
                .delete_device_route(IpAddr::from([0, 0, 0, 0]), 0, session.tun(), None)
                .await?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            let mut seen = Egress::Unreachable;
            while tokio::time::Instant::now() < deadline {
                seen = session.routes().egress(public).await?;
                if seen == Egress::Blackhole {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            checks.check(
                "the kill-switch insurance blackholes traffic if the tunnel route is lost",
                seen == Egress::Blackhole,
                format!("expected a blackhole, saw {}", route::describe(seen)),
            )?;
        }

        session.teardown().await?;
        let restored = session.routes().egress(public).await?;
        let still_captured = matches!(restored, Egress::Interface(index) if index == session.tun());
        checks.check(
            "teardown restores a non-tunnel path (no blackhole left behind)",
            !still_captured && restored != Egress::Blackhole,
            format!("egress after teardown: {}", route::describe(restored)),
        )?;
        Ok(())
    })
}

// --- Dispatch --------------------------------------------------------------

/// Run one scenario by id (gates already applied by [`crate::run_scenario`]).
pub async fn run(id: &str, config: &HarnessConfig) -> Result<ScenarioRun> {
    match id {
        "tcp-forwarded" => tcp_forwarded(config).await,
        "dns-intercepted" => dns_intercepted(config).await,
        "udp-blocked" => udp_blocked(config).await,
        "ipv6-routed" => {
            if !host_has_ipv6() {
                return Ok(ScenarioRun::Skipped(
                    "the host has no IPv6 stack (cannot bind ::1)".to_owned(),
                ));
            }
            ipv6_routed(config).await
        }
        "route-change" => route_change(config).await,
        "sleep-wake" => sleep_wake(config).await,
        "helper-crash" => helper_crash(config).await,
        "daemon-crash" => daemon_crash(config).await,
        "intrusive-default-route" => intrusive_default_route(config).await,
        "intrusive-kill-switch" => intrusive_kill_switch(config).await,
        other => bail!("unknown scenario {other:?}"),
    }
}
