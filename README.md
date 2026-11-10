# tobro

A desktop-only, ground-up rewrite of Orbot using Rust/Arti and Tauri.

**Status:** M0-M5 complete; M6 in progress.

- [Read the full plan](TOBRO_PLAN.md) — architecture, technology decisions, Orbot feature-parity matrix, milestones, and risks.

## At a glance

- **Tor:** Arti 2.8 (embedded) via `tobrod` daemon + Tauri/React desktop app.
- **Platforms:** macOS, Windows, Linux.
- **Proxy:** local SOCKS5, HTTP CONNECT, and DNS (configurable).
- **Bridges (M3):** `[bridges]` config + **lyrebird** (**obfs4**, **meek_lite**/`meek`, **WebTunnel**) and **snowflake-client** (**snowflake**, AMP/front/broker params supported via bridge lines). Moat/Smart Connect planned.
- **Desktop:** connect/stop/new identity, bootstrap status, tray, autostart, app lock, settings, floating logs.
- **CLI:** `tobroctl` — status/connect/stop/new identity/config/watch.
- **Non-goals:** mobile, relay/exit, `torrc` compatibility, bundled browser.

## Core state machine

```text
        ┌──────────┐   start   ┌───────────┐  bootstrap  ┌───────────────┐
        │ Stopped  ├──────────►│ Starting  ├────────────►│ Bootstrapping │
        └────▲─────┘           └─────┬─────┘             └──────┬────────┘
             │                       │ error                    │ 100%
             │ stop                  ▼                          ▼
        ┌────┴─────┐           ┌───────────┐             ┌────────────┐
        │ Stopping │◄──────────┤  Error    │             │  Connected │
        └──────────┘   stop    └───────────┘             └─────┬──────┘
                                                               │ network loss
                                                               ▼
                                                        ┌─────────────┐
                                                        │ Reconnecting│
                                                        └─────────────┘
```

## System overview

```text
┌──────────────────────────────────────────────────────────────────┐
│                        User session                              │
│                                                                  │
│  ┌────────────────────┐        JSON-RPC 2.0        ┌───────────┐ │
│  │  tobro GUI         │◄──────────────────────────►│  tobrod   │ │
│  │  Tauri 2 + React   │   UDS / named pipe         │  daemon   │ │
│  │  tray, windows     │   events + commands        │           │ │
│  └────────────────────┘                            └─────┬─────┘ │
│                                                          │       │
│  ┌────────────────────┐                                  │       │
│  │  tobroctl CLI      │◄─────────────────────────────────┤       │
│  └────────────────────┘                                  │       │
│                                                          │       │
│                                          ┌───────────────┼───────┐
│                                          │               │       │
│                                    ┌─────▼─────┐   ┌─────▼─────┐ │
│                                    │  Arti     │   │ PT manager│ │
│                                    │  client   │   │ sidecars  │ │
│                                    └─────┬─────┘   └─────┬─────┘ │
│                                          │               │       │
│                                    ┌─────▼───────────────▼─────┐ │
│                                    │  Tor network (bridges)    │ │
│                                    └───────────────────────────┘ │
│                                                                  │
│  ┌─────────────────────────────┐        ┌──────────────────────┐ │
│  │  tobro-helper (privileged)  │◄──────►│  TUN / routes / DNS  │ │
│  │  optional, TUN mode only    │        │  (post-1.0)          │ │
│  └─────────────────────────────┘        └──────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

## Bridges (lyrebird / snowflake, M3)

Enable bridges in `config.toml` and provide bridge lines. tobro resolves PT binaries and configures Arti transports:

- **lyrebird**: `obfs4`, `meek_lite` (`meek` alias), `webtunnel` (`transport_path` / `transport_dir`)
- **snowflake-client**: `snowflake` (`snowflake_path` / `snowflake_dir`); AMP/front/broker/STUN/UTLS settings are passed via bridge-line parameters (including AMP cache rendezvous where supported by the client)

```toml
[bridges]
enabled = true
lines = [
  "obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0",
  "Bridge webtunnel 192.0.2.2:443 FINGERPRINT url=https://example.com/ ver=0.0.1",
  "Bridge snowflake 192.0.2.3:80 FINGERPRINT fingerprint=FINGERPRINT url=https://snowflake-broker.torproject.net/ front=cdn.sstatic.net ampcache=https://cdn.ampproject.org/ utls-imitate=hellorandomizedalpn",
]
# transport_path = "/path/to/lyrebird"           # optional (lyrebird)
# snowflake_path = "/path/to/snowflake-client"   # optional
```

## CLI commands

```sh
# terminal 1: start the control plane (loads config/store, idle until connect)
cargo run -p tobrod -- run

# terminal 2: control the daemon
cargo run -p tobroctl -- status         # JSON status (stopped until connected)
cargo run -p tobroctl -- connect        # start Tor/bootstrap + local listeners
cargo run -p tobroctl -- status         # should become serving/connected when ready
cargo run -p tobroctl -- new-identity   # request new circuits (preserves guards)
cargo run -p tobroctl -- reload-config  # reload/validate config from disk
cargo run -p tobroctl -- config get     # redacted config (no secrets)
cargo run -p tobroctl -- config validate '{"proxy":{"socks_port":9050}}'
cargo run -p tobroctl -- config apply '{"proxy":{"socks_port":9050,"bind_all_interfaces":false}}'
cargo run -p tobroctl -- stop           # disconnect Tor
cargo run -p tobroctl -- watch          # stream state/bootstrap notifications

# M0 spike / runtime checks (boots Tor, serves listeners)
cargo run -p tobrod -- spike --exit-after-check
# opt-in .onion resolution check through the local DNS proxy (UDP; needs live Tor + a reachable target)
cargo run -p tobrod -- spike --exit-after-check --timeout-secs 300 --dns-check-host <v3-onion-hostname>.onion
```

### Desktop app options

```sh
# Start the GUI hidden to the tray (used by autostart/start-minimized)
cargo run -p tobro -- --minimized
# equivalent
cargo run -p tobro -- --hidden
```

`tobrod run` starts stopped; use `connect` to start Tor. `tobroctl` prints JSON to
stdout and diagnostics to stderr (exit `0` on success, `1` on error). The IPC
endpoint defaults to `<platform data dir>/tobro/state/tobrod.sock`; pass
`--socket <path>` to both commands when using custom dirs.

The spike bootstraps Arti, prints JSON-line bootstrap events to stdout, fetches
a page through Tor, starts SOCKS/HTTP on `9050` and DNS on `9053`, then fetches
a page through the local SOCKS listener. Drop `--exit-after-check` to keep
serving until Ctrl-C. Use `--state-dir`/`--cache-dir` for checkout-local Arti
state, and `--dns-check-host` for an explicit DNS/`.onion` resolution check.

## Desktop app

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
identity, settings (listener/config management), and a floating logs window
(filter/redact/copy/save). If `tobrod` is not running, the GUI attempts to start
it automatically. The window hides to the tray on close; quit from the tray menu
to exit the GUI. The daemon is independent.

## License

GPL-3.0-only — see [LICENSE.txt](LICENSE.txt).
