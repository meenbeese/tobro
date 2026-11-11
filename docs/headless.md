# Headless mode: `tobrod` + `tobroctl`

Tobro's Tor engine lives in the **`tobrod` daemon**. The desktop GUI is only a
client: it talks to the daemon over a local, same-user IPC socket (JSON-RPC).
`tobroctl` is the command-line client with the same API, which makes a fully
headless setup possible — a server, SSH session, or a machine that never runs
the GUI.

Everything in this document is JSON on stdout and diagnostics on stderr.
Exit codes: `0` on success, `1` on error.

## Quickstart

```sh
cargo build -p tobrod -p tobroctl

# launch the daemon detached (own process group) and wait until IPC is ready
cargo run -p tobroctl -- start

# bring Tor up, watch it, take it down
cargo run -p tobroctl -- connect
cargo run -p tobroctl -- status
cargo run -p tobroctl -- logs --lines 20
cargo run -p tobroctl -- stop           # stop Tor; daemon keeps running
cargo run -p tobroctl -- shutdown       # disconnect and exit the daemon process
```

`start` uses the `tobrod` binary that sits next to `tobroctl` in the build
output; pass `--daemon /path/to/tobrod` when the binaries live apart. The
daemon writes its log to `<state-dir>/tobrod.log` (override with
`--log-file`), and `--foreground` runs it attached to your terminal instead.

## IPC endpoint

- Default: `<platform data dir>/tobro/state/tobrod.sock`
  (macOS: `~/Library/Application Support/tobro/state/tobrod.sock`).
- Override on both sides with `tobrod run --socket PATH` and
  `tobroctl --socket PATH`.
- Access model: same OS user only. Unix domain socket with `0600` mode in a
  `0700` directory, plus a peer-credential uid check on connect; the named
  pipe on Windows follows the same endpoint convention.

## Command reference

Lifecycle:

| Command | Effect |
|---|---|
| `tobroctl start` | Spawn `tobrod run` detached, wait for IPC, report status. Idempotent: if a daemon is already listening, it reports `already_running: true` and launches nothing. `--connect` also starts Tor; `--wait N` bounds the readiness wait (default 20 s). |
| `tobroctl status` | Daemon state machine snapshot: `state`, bootstrap progress, listener ports, pid, uptime. |
| `tobroctl connect` | Start Tor (bootstrap) and the local SOCKS/HTTP/DNS listeners. |
| `tobroctl stop` | Stop Tor. The daemon keeps running (tray/background-service semantics). |
| `tobroctl new-identity` | New circuits; guard state is preserved. Requires a connected daemon. |
| `tobroctl shutdown` | Ask the daemon to disconnect Tor and exit cleanly (same path as SIGINT). The response is sent before the process exits. |

Observability:

| Command | Effect |
|---|---|
| `tobroctl logs` | Recent daemon log lines from the in-memory ring buffer (`daemon.logs`). `--lines N` (1..=10000, default 200), `--text` for raw lines instead of a JSON envelope. |
| `tobroctl watch` | Stream IPC notifications (`daemon.state_changed`, `bootstrap.progress`, `onion.published`, …) as JSON lines until Ctrl-C. |
| `tobroctl diagnostics export` | Self-contained redacted diagnostics bundle (see below). `--out PATH` writes a `0600` JSON file; default prints it to stdout. |

Configuration and services:

| Command | Effect |
|---|---|
| `tobroctl config get` | Current configuration, redacted (no secrets). |
| `tobroctl config validate PATCH` | Validate a JSON patch (arg, `@file`, or `-` for stdin) without persisting. |
| `tobroctl config apply PATCH` | Validate, persist, and apply a patch; reports whether a restart is required. |
| `tobroctl reload-config` | Reload and validate the config file from disk. |
| `tobroctl onion list/create/update/enable/disable/delete/backup/restore` | Host v3 onion services, with encrypted backup/restore. |
| `tobroctl client-auth …` | Onion service client authorization (`.auth_private`). |
| `tobroctl bridges …` | Bridge line validate/import/export/apply, built-in sets, Moat fetch, transport test. |

## Logs

The daemon keeps three log sinks:

1. **stderr** — always; disable styling via the usual tracing environment
   (`RUST_LOG` / `RUST_LOG_FORMAT` env filtering applies).
2. **Log file** — `tobrod run --log-file PATH` (append). `tobroctl start`
   sets this to `<state-dir>/tobrod.log` by default.
3. **Ring buffer** — the last 1000 lines in memory, served over IPC by
   `daemon.logs` (`tobroctl logs`). Lines are truncated at 4000 characters
   and **redacted at capture time**: bridge credentials, proxy passwords, and
   client-auth key material never enter the buffer, so `tobroctl logs` and the
   diagnostics export are safe to read even from a live, authenticated session.

The file and the ring buffer get the same plain-text (no ANSI) lines as the
ring buffer consumers expect.

## Diagnostics export

`tobroctl diagnostics export` composes a single JSON document:

```json
{
  "format": "tobro-diagnostics",
  "version": 1,
  "generated_at": 1762879200000,
  "tool": { "name": "tobroctl", "version": "0.0.0" },
  "daemon": { "hello": { "…": "versions, platform, pid" },
              "status": { "…": "state, bootstrap, ports" } },
  "config":   { "ok": true, "data": { "…": "redacted configuration" } },
  "onion":    { "ok": true, "data": { "…": "hosted services (addresses, ports)" } },
  "kindness": { "ok": true, "data": { "…": "Kindness Mode summary" } },
  "client_auth": { "ok": true, "data": { "…": "credential metadata, no keys" } },
  "logs":     { "ok": true, "data": { "lines": ["…"], "total_lines": 42 } },
  "notes": ["…"]
}
```

Sections that fail (e.g. Kindness disabled at config level) degrade to
`"ok": false` with an `error` string instead of failing the export. The bundle
never contains private keys, passwords, or raw bridge credentials: the config
comes from the daemon's redacted view and log lines are redacted at capture.
Hosted `.onion` addresses are public by design and included — review the file
before sharing it.

## Running as a service

`start` spawns a daemon that survives its parent, so a service manager only
needs to run `tobrod run` (or `tobroctl start --foreground` if you want the
manager to own the process).

### systemd (user unit)

```ini
# ~/.config/systemd/user/tobrod.service
[Unit]
Description=Tobro Tor daemon
After=network-online.target

[Service]
ExecStart=%h/.cargo/bin/tobrod run
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
```

```sh
systemctl --user enable --now tobrod
journalctl --user -u tobrod -f     # or: tobroctl logs -f
```

### launchd (macOS LaunchAgent)

```xml
<!-- ~/Library/LaunchAgents/app.tobro.daemon.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>app.tobro.daemon</string>
  <key>ProgramArguments</key><array>
    <string>/usr/local/bin/tobrod</string><string>run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
```

```sh
launchctl load ~/Library/LaunchAgents/app.tobro.daemon.plist
```

## Troubleshooting

- **`could not connect to tobrod`** — the daemon is not running. Use
  `tobroctl start`, or run `tobroctl start --foreground` to see why it fails.
- **"another daemon is already listening"** — the IPC socket is live; use
  `tobroctl status` to inspect it instead of starting a second daemon.
- **Port conflicts at connect** — `connect` pre-flights the configured
  listener ports and reports the conflicting port in the error; change them
  with `config apply` or free the ports.
- **Stale socket** — the daemon replaces a stale socket file on start; a
  live socket is never silently taken over.
- **Verbose logs** — set `RUST_LOG=tobro=debug` (per-run; affects stderr and
  the log file).
