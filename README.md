# tobro

A desktop-only, ground-up rewrite of Orbot using Rust/Arti and Tauri.

**Status:** M0 spike in progress. Arti bootstrap/listeners, the local IPC
socket/client (Unix socket + Windows named pipe), and the minimal Tauri 2
window are implemented; ADRs and benchmarks are next.

- [Read the full plan](TOBRO_PLAN.md) — architecture, technology decisions, Orbot feature-parity matrix, milestones, and risks.

## At a glance

- **Tor engine:** Arti 2.8 (`arti-client` 0.48), embedded in Rust.
- **App:** Tauri 2 + React 19 + TypeScript, with a separate `tobrod` daemon.
- **Platforms:** macOS, Windows, Linux.
- **Scope:** connect/disconnect, bridges and pluggable transports, proxy services, onion services, Kindness Mode, tray/autostart, CLI.
- **Non-goals:** mobile, Tor relay/exit mode, raw `torrc` compatibility, bundled browser.

## Try the M0 spike

```sh
cargo run -p tobrod -- spike --exit-after-check
```

This bootstraps Arti, prints JSON-line bootstrap events to stdout, fetches a
page through Tor, starts SOCKS/HTTP on `9050` and DNS on `9053`, then fetches a
page through the local SOCKS listener. Drop `--exit-after-check` to keep
serving until Ctrl-C. Use `--state-dir` and `--cache-dir` to keep Arti state
inside the checkout instead of the platform data directory.

## Try the IPC endpoint

```sh
# terminal 1: bootstrap, then serve SOCKS/HTTP + DNS and the IPC socket
cargo run -p tobrod -- spike

# terminal 2
cargo run -p tobroctl -- status   # JSON snapshot (handshake + daemon.status)
cargo run -p tobroctl -- watch    # stream bootstrap.progress / state changes
```

The socket defaults to `<platform data dir>/tobro/state/tobrod.sock`. Pass
`--socket <path>` to both commands when using a custom `--state-dir`.

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

