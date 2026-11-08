# tobro

A desktop-only, ground-up rewrite of Orbot using Rust/Arti and Tauri.

**Status:** M0 complete; M1 wrapped; M2 in progress.

M1 delivered the control plane and desktop shell: Arti bootstrap/listeners,
local IPC (Unix socket + Windows named pipe), `tobro-config`/`tobro-store`,
`tobrod` lifecycle/supervisor + `tobro-tor` adapter core, hardened IPC
(allowlist, hello-preflight, param validation, Unix peer checks, idle timeout,
event resync), `tobroctl`, and a Tauri 2 + React desktop shell with
connect/stop, status/bootstrap UI, tray/quit-to-tray, redaction utilities,
and unsigned packaging smoke builds.

M2 progress so far: CI speedups (safe caching/prebuilt Tauri CLI), configurable
proxy/DNS ports with conflict detection/helpers and honest SOCKS+HTTP listener
semantics, `daemon.new_identity` (new circuits via supervised restart while
preserving guard/state dirs) with tests/CLI/UI, daemon config API
(`config.get`/`config.validate`/`config.apply`, redacted/no secrets, patch-based,
deny-unknown-fields preserved), `tobroctl config get|validate|apply`, desktop
Advanced Settings behind a power-user gate with listener-port editing and config
import/export (no secrets), and a standalone log viewer (filters, copy/save,
wrap, persisted redaction preference) plus daemon/UI redaction hardening.

M2 still open: bind-all-interfaces (opt-in + warnings), DNS/`.onion` wiring
verification/test, exit country/IPv6/`StreamPrefs`, stream isolation, supported
node restrictions/unsupported-knob UX, and runtime/cross-OS verification for M2
exit criteria (new identity behavior, port conflicts).

- [Read the full plan](TOBRO_PLAN.md) — architecture, technology decisions, Orbot feature-parity matrix, milestones, and risks.

## At a glance

- **Tor engine:** Arti 2.8 (`arti-client` 0.48), embedded in Rust.
- **App:** Tauri 2 + React 19 + TypeScript, with a separate `tobrod` daemon.
- **Platforms:** macOS, Windows, Linux.
- **Scope:** connect/disconnect, bridges and pluggable transports, proxy services, onion services, Kindness Mode, tray/autostart, CLI.
- **Non-goals:** mobile, Tor relay/exit mode, raw `torrc` compatibility, bundled browser.

## Try the daemon

```sh
# terminal 1: start the control plane (loads config/store, idle until connect)
cargo run -p tobrod -- run

# terminal 2
cargo run -p tobroctl -- status         # JSON status (stopped until connected)
cargo run -p tobroctl -- connect        # start Tor/bootstrap + local listeners
cargo run -p tobroctl -- status         # should become serving/connected when ready
cargo run -p tobroctl -- new-identity   # request new circuits (preserves guards)
cargo run -p tobroctl -- reload-config  # reload/validate config from disk
cargo run -p tobroctl -- config get     # redacted config (no secrets)
cargo run -p tobroctl -- config validate '{"proxy":{"socks_port":9050}}'
cargo run -p tobroctl -- config apply '{"proxy":{"socks_port":9050}}'
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

# install the Rust Tauri CLI once (provides `cargo tauri`)
cargo install tauri-cli --version "^2.0.0" --locked

# run the Tauri shell from the repo root
cargo tauri dev --config apps/desktop/tauri.conf.json
# alternative (uses @tauri-apps/cli from apps/desktop/ui):
# cd apps/desktop/ui && bun run tauri dev --config ../tauri.conf.json
# or, if you built the UI and want the Rust side only:
# (cd apps/desktop/ui && bun run build) && cargo run -p tobro
```

The GUI tries to start `tobrod` automatically when the daemon is not reachable.
It looks for `tobrod` next to the app binary, via `TOBROD_PATH`, or on `PATH`,
and starts it as `tobrod run --socket <path>`. For development, make sure the
daemon binary is built (for example `cargo build -p tobrod`) so the GUI can find
it. You can still run the daemon manually: `cargo run -p tobrod -- run`.

The shell connects to `tobrod` over local IPC (default platform state path, or
`--socket <path>`), shows status/bootstrap progress, provides Connect/Stop/New
identity, includes an Advanced Settings screen (power-user gated) for
listener-port editing and config import/export (redacted, no secrets), and keeps
an event log viewer (filters/copy/save, redaction controls). If `tobrod` is not
running, the GUI attempts to start it automatically. The window hides to the tray
on close; quit from the tray menu to exit the GUI. The daemon is independent.

## License

GPL-3.0-only — see [LICENSE.txt](LICENSE.txt).

