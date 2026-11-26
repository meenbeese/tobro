# TUN leak tests

`tobro-leak` is the end-to-end leak suite for TUN mode (M7). It drives the
**real privileged helper** on a **real host kernel**: a TUN device is
created, routes and the system resolver change, and traffic is generated
through ordinary host sockets — no mocks, no shortcuts. A fake daemon
(loopback SOCKS5 + DNS listeners) is the only forwarding target, so a packet
that escapes the tunnel is observable instead of silently reaching the
internet.

## What it covers

| Scenario | Leak class it rules out |
| --- | --- |
| `tcp-forwarded` | TCP bypassing the routing engine or the SOCKS forward path |
| `dns-intercepted` | DNS queries bypassing the tunnel resolver; resolver not replaced or not restored |
| `udp-blocked` | QUIC/WebRTC/other UDP escaping; DNS escaping under `udp_policy = "block_all"` |
| `ipv6-routed` | IPv6 traffic ignoring the tunnel policy and leaving over the physical path |
| `route-change` | stale routes after an external route change or a narrowed plan |
| `sleep-wake` | traffic or DNS escaping after the kernel drops state across suspend/resume |
| `helper-crash` | the resolver left pointing at a dead tunnel (fail open) after an unclean helper stop |
| `daemon-crash` | a vanished daemon leaving a half-applied plan behind |
| `intrusive-default-route` | real default routes not capturing IPv4/IPv6 traffic |
| `intrusive-kill-switch` | fail-closed plans letting traffic escape; missing Linux insurance blackholes |

The safe tier routes only the reserved `198.18.0.0/15` (RFC 2544) and
`2001:db8::/32` (RFC 3849) prefixes into the TUN device. If the harness is
killed, the host keeps working: the dangling routes disappear with the
device and nothing real was ever captured.

The intrusive tier captures `0.0.0.0/0` and `::/0` and, for the kill-switch
scenario, blocks all host traffic. It is gated behind **both** `--intrusive`
and `TOBRO_LEAK_ALLOW_INTRUSIVE=1` and must only run on a dedicated host or
inside a network namespace.

## Requirements

- **Privilege:** root on macOS/Linux, an elevated administrator token on
  Windows. The helper refuses to create a TUN device otherwise.
- **TUN support:** `/dev/net/tun` (Linux), utun (macOS), wintun (Windows).
- **Windows:** `wintun.dll` next to `tobro-helper.exe` (packaged builds ship
  it there; `TOBRO_HELPER_BIN` is not enough).
- **Linux:** a regular, writable `/etc/resolv.conf`. The helper refuses a
  symlink managed by systemd-resolved; use the namespace wrapper below.
- The helper binary must be built. The harness searches, in order:
  `--helper`, `TOBRO_HELPER_BIN`, the harness binary's directory,
  `target/{debug,release}`, per-target dirs, then `PATH`.

## Running

Build both binaries first:

```sh
cargo build -p tobro-helper -p tobro-leak
```

List the scenarios:

```sh
./target/debug/tobro-leak --list
```

Run the safe tier (root/administrator required):

```sh
sudo ./target/debug/tobro-leak --fail-on-skip
```

On Windows, from an elevated shell:

```powershell
.\target\debug\tobro-leak.exe --fail-on-skip
```

Select specific scenarios and get machine-readable output:

```sh
sudo ./target/debug/tobro-leak \
  --scenario dns-intercepted --scenario udp-blocked --json
```

Exit codes: `0` success, `1` a scenario failed (or was skipped with
`--fail-on-skip`), `2` invalid command line.

### Linux network namespace (recommended)

`scripts/run-leak-tests.sh` gives the suite its own network and mount
namespaces:

- routes, DNS, and TUN devices cannot touch the host;
- a private copy of `/etc` is bind-mounted, so the helper can manage
  `resolv.conf` (rename) even when the host uses systemd-resolved;
- loopback is up and there is no physical network to leak to, which also
  makes the intrusive tier safe.

```sh
cargo build -p tobro-helper -p tobro-leak  # once
sudo env TOBRO_LEAK_NO_BUILD=1 scripts/run-leak-tests.sh --fail-on-skip

# Intrusive tier inside the namespace:
sudo env TOBRO_LEAK_NO_BUILD=1 TOBRO_LEAK_ALLOW_INTRUSIVE=1 \
  scripts/run-leak-tests.sh --intrusive --fail-on-skip
```

The script builds automatically unless `TOBRO_LEAK_NO_BUILD=1` is set, and
removes its temp directory on exit.

### Dedicated test host

For the intrusive tier outside Linux namespaces (macOS/Windows), use a host
whose network may be interrupted:

```sh
sudo env TOBRO_LEAK_ALLOW_INTRUSIVE=1 \
  ./target/debug/tobro-leak --intrusive --fail-on-skip
```

The intrusive kill-switch scenario parks the TUN device and installs the
platform fail-closed rules (PF on macOS, WFP on Windows, blackhole routes on
Linux). It can temporarily interrupt all host networking; always let the
scenario finish so teardown removes the rules.

## CI

`.github/workflows/leak.yml` runs on `workflow_dispatch` and weekly:

- **Linux:** safe + intrusive tiers inside the namespace wrapper.
- **macOS/Windows:** safe tier on the hosted runner (reserved prefixes,
  options, and resolver always restored by the harness).
- **Windows** additionally downloads `wintun.dll` next to the helper.

Hosted runners are convenient but not a substitute for the dedicated-host
run: kernel/driver differences (utun naming, WFP/PF behavior, wintun
versions) are exactly what the intrusive tier is meant to catch.

## Interpreting results

Each scenario prints `PASS`, `FAIL`, or `SKIP`, its duration, and — for
failures and with `--verbose` — every assertion with the observed value.
`--json` emits the same data:

```json
[
  {
    "scenario": "dns-intercepted",
    "tier": "safe",
    "status": "passed",
    "checks": [
      { "name": "the system resolver points at the tunnel (IPv4)",
        "passed": true,
        "detail": "resolvers: 10.111.222.254, fd6b:626f:6272:6f::2" }
    ],
    "duration_ms": 812
  }
]
```

`SKIP` means the environment cannot run the scenario; the reason is shown
(no privilege, intrusive tier disabled, no IPv6 stack, helper not built).
CI passes `--fail-on-skip` so a skipped scenario cannot silently weaken the
run.

Helper stdout/stderr goes to `helper-N.log` inside the scenario's temp
directory; the path is included in setup failures. The per-scenario
directory is removed after the scenario finishes.

## Cleanup and failure safety

Every scenario owns a guard that always tears the plan down, kills the
helper, and restores the resolver captured *before* the run — including when
an assertion panics. A killed helper (crash scenarios) is expected to leave
state behind; the guard restores it from the pre-run snapshot.

The only state that cannot be restored from the harness is a bypass route or
platform firewall rule installed by a helper that was killed before it could
record it. The intrusive tier should therefore only run on a disposable host
or in a namespace.

## Platform notes

- **Linux**, **macOS**, and **Windows** address the TUN device with both
  families: IPv4 at creation, IPv6 through the platform's privileged API
  (netlink on Linux, `SIOCAIFADDR_IN6` on macOS, `CreateUnicastIpAddressEntry`
  on Windows). IPv6 TCP/DNS interception is therefore asserted end-to-end;
  the suite still fails on any observed physical egress, and on hosts without
  an IPv6 stack it skips the `ipv6-routed` scenario and notes that the IPv6
  DNS check was not exercised.
- **macOS** sets the global `State:/Network/Global/DNS` key; `scutil --dns`
  also lists per-service resolvers, so the suite asserts the tunnel servers
  are present (and restored) rather than that the output is exclusive.
- **Windows** scopes DNS to the wintun adapter; adapter-scoped DNS is
  asserted and disappears with the adapter on teardown/crash.

## Adding a scenario

1. Add a `ScenarioInfo` entry to `SCENARIOS` in `crates/tobro-leak/src/lib.rs`.
2. Implement the body in `crates/tobro-leak/src/scenario.rs` using
   `run_body!` so setup/cleanup stay automatic.
3. Use `plan::build` for the plan, `session.routes()` for kernel ground
   truth, and assert *observed* values in every failure detail.
4. Prefer a reserved prefix in the safe tier; anything that captures
   default routes or blocks traffic belongs in the intrusive tier.
