# tobro-ipc

Local JSON-RPC protocol shared by `tobrod`, the GUI, and `tobroctl`.

## Wire format

A 4-byte big-endian length prefix followed by a UTF-8 JSON document
(JSON-RPC 2.0). Frames are capped at 1 MiB.

## Transport

Unix domain socket at `<state-dir>/tobrod.sock`, in a `0700` directory with a
`0600` socket. Stale sockets are replaced; a live one is an error.

Windows named pipes are part of the M1 IPC work. On non-Unix targets this crate
exposes the protocol types but not `Client`/`Server`.

## M0 surface

| Kind | Name | Payload |
|---|---|---|
| method | `daemon.hello` | `Hello` (RPC version, daemon/Arti versions, pid) |
| method | `daemon.status` | `DaemonStatus` |
| notification | `bootstrap.progress` | `BootstrapProgress` |
| notification | `daemon.state_changed` | `{ "state": DaemonState }` |

`tobroctl status` and `tobroctl watch` are the reference clients. The Tauri
window will use the same `Client`.
