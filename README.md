# tobro

A desktop-only, ground-up rewrite of Orbot using Rust/Arti and Tauri.

**Status:** M0 complete; M1 in progress. Arti bootstrap/listeners, local IPC
(Unix socket + Windows named pipe), and the Tauri 2 desktop shell are
implemented. M1 now includes: `tobro-config` (TOML schema/load/save/validate),
`tobro-store` (embedded local libSQL/Turso-compatible DB + keychain abstraction),
`tobrod` lifecycle/supervisor + `tobro-tor` adapter core, `tobrod run` (loads
config/store, starts IPC, waits for connect), hardened IPC
(`daemon.hello/status/connect/stop/reload_config` with allowlist, hello-preflight,
no-params validation, Unix peer UID/euid check, idle timeout, event resync),
`tobroctl` (`status/connect/stop/reload-config/watch`, JSON stdout, stable exit
codes), and a React 19 + TypeScript + Vite Tauri shell (`apps/desktop/ui`) with
connection/status/bootstrap UI, basic event log, connect/stop controls, tray
icon, and quit-to-tray (the daemon keeps running). Remaining M1:
logging/redaction + redaction test, reconfigure application, packaging smoke
builds, and exit-gate verification.

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

## Try the desktop app

```sh
# install frontend dependencies once
cd apps/desktop/ui && bun install

# run the daemon (terminal 1)
cargo run -p tobrod -- run

# run the Tauri shell (terminal 2, from repo root)
cargo tauri dev --config apps/desktop/tauri.conf.json
# or, if you built the UI and want the Rust side only:
# (cd apps/desktop/ui && bun run build) && cargo run -p tobro
```

The shell connects to `tobrod` over local IPC (default platform state path, or
`--socket <path>`), shows status/bootstrap progress, provides Connect/Stop,
keeps a basic event log, and lives in the tray when the window is closed. Quit
from the tray menu to exit the GUI; the daemon is independent.

## License

GPL-3.0-only — see [LICENSE.txt](LICENSE.txt).

