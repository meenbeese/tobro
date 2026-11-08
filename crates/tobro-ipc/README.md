# tobro-ipc

Local JSON-RPC protocol shared by `tobrod`, the GUI, and `tobroctl`.

## Wire format

A 4-byte big-endian length prefix followed by a UTF-8 JSON document
(JSON-RPC 2.0). Frames are capped at 1 MiB.

## Transport

Unix domain socket at `<state-dir>/tobrod.sock`, in a `0700` directory with a
`0600` socket. Stale sockets are replaced; a live one is an error.

Windows names a pipe `\\.\pipe\tobro-<hash>` from the same path (FNV-1a of the
state path, so both processes agree without a discovery file). A live daemon
holds the first pipe instance, so binding when one is running fails.

## M0 surface

| Kind | Name | Payload |
|---|---|---|
| method | `daemon.hello` | `Hello` (RPC version, daemon/Arti versions, pid) |
| method | `daemon.status` | `DaemonStatus` |
| notification | `bootstrap.progress` | `BootstrapProgress` |
| notification | `daemon.state_changed` | `{ "state": DaemonState }` |

`tobroctl status` and `tobroctl watch` are the reference clients. The Tauri
window will use the same `Client`.
