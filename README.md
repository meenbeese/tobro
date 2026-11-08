# tobro

A desktop-only, ground-up rewrite of Orbot using Rust/Arti and Tauri.

**Status:** M0 complete; M1 in progress. Arti bootstrap/listeners, local IPC
(Unix socket + Windows named pipe), and the minimal Tauri 2 window are
implemented. M1 now includes: `tobro-config` (TOML schema/load/save/validate),
`tobro-store` (embedded local libSQL/Turso-compatible DB + keychain abstraction),
`tobrod` lifecycle/supervisor + `tobro-tor` adapter core, `tobrod run` (loads
config/store, starts IPC, waits for connect), and hardened IPC
(`daemon.hello/status/connect/stop/reload_config` with allowlist, hello-preflight,
no-params validation, Unix peer UID/euid check, idle timeout, event resync).
`tobroctl` supports `status/connect/stop/reload-config/watch` with JSON stdout and
stable exit codes. Remaining M1: React/Tauri shell, logging/redaction + redaction
test, reconfigure application, packaging smoke builds, and exit-gate verification.

- [Read the full plan](TOBRO_PLAN.md) — architecture, technology decisions, Orbot feature-parity matrix, milestones, and risks.

## At a glance

- **Tor engine:** Arti 2.8 (`arti-client` 0.48), embedded in Rust.
- **App:** Tauri 2 + React 19 + TypeScript, with a separate `tobrod` daemon.
- **Platforms:** macOS, Windows, Linux.
- **Scope:** connect/disconnect, bridges and pluggable transports, proxy services, onion services, Kindness Mode, tray/autostart, CLI.
- **Non-goals:** mobile, Tor relay/exit mode, raw `torrc` compatibility, bundled browser.

## Try the M1 daemon

```sh
# terminal 1: start the control plane (loads config/store, idle until connect)
cargo run -p tobrod -- run

# terminal 2
cargo run -p tobroctl -- status         # JSON status (stopped until connected)
cargo run -p tobroctl -- connect        # start Tor/bootstrap + local listeners
cargo run -p tobroctl -- status         # should become serving/connected when ready
cargo run -p tobroctl -- reload-config  # reload/validate config from disk
cargo run -p tobroctl -- stop           # disconnect Tor
cargo run -p tobroctl -- watch          # stream state/bootstrap notifications
```

`tobrod run` starts stopped; use `connect` to start Tor. `tobroctl` prints JSON to
stdout and diagnostics to stderr (exit `0` on success, `1` on error). The IPC
endpoint defaults to `<platform data dir>/tobro/state/tobrod.sock`; pass
`--socket <path>` to both commands when using custom dirs.

## Try the M0 spike

```sh
cargo run -p tobrod -- spike --exit-after-check
```

This bootstraps Arti, prints JSON-line bootstrap events to stdout, fetches a
page through Tor, starts SOCKS/HTTP on `9050` and DNS on `9053`, then fetches a
page through the local SOCKS listener. Drop `--exit-after-check` to keep
serving until Ctrl-C. Use `--state-dir` and `--cache-dir` to keep Arti state
inside the checkout instead of the platform data directory.

## Try the window

```sh
cargo run -p tobro -- --socket /path/to/tobrod.sock   # e.g. from the spike above
```

A minimal Tauri window connects to the same socket (or the default platform
path when run without `--socket`), streams `bootstrap.progress` and
`daemon.state_changed` into the event list, and shows the latest daemon
status. It retries once per second while no daemon is listening.

## License

GPL-3.0-only — see [LICENSE.txt](LICENSE.txt).

