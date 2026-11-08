# tobro-tor

Arti integration boundary for tobro.

M0 status: bootstraps Arti 2.8, streams bootstrap progress, performs a
connectivity check through Tor, and hosts SOCKS + HTTP CONNECT and DNS
listeners.

## Arti 2.8.0 listener caveat

`StreamProxy::run_proxy` and `DnsProxy::run_dns_proxy` are `pub(crate)` in
Arti 2.8.0, so a library consumer cannot run a listener it bound. The only
supported way to serve SOCKS/HTTP + DNS is `arti::run_proxy`, which owns the
`TorClient` it serves. `tobro-tor` therefore separates observation
(`Tor::bootstrap`, `Tor::check_http`) from serving (`serve`) and drops the
observer before starting the server, because a client holds an exclusive lock
on its state directory.

`run_proxy` also reloads its client configuration from the supplied config
sources at startup. The M0 spike passes empty sources (all defaults), so the
only effect is a benign warning about the custom state/cache directories
("Cannot change storage.* on a running client"). Any non-default client
configuration must be fed through those sources, or it will be reset.

Verified on macOS against Arti 2.8.0 (2026-11-07): SOCKS5 and HTTP CONNECT
both serve on port 9050, and DNS resolves on UDP 9053. The DNS proxy has no
TCP listener, and the first query after startup can take several seconds while
a circuit is built.

See the module docs in `src/lib.rs` for details.

## Pluggable transport API (M0 verification)

`cargo run -p tobro-tor --features pt-client --example pt_api_probe` exercises
the bridge/PT surface of `arti-client` 0.48 without networking. All checks
pass; findings for M3 (plan §5.8, milestone M3):

- `BridgeConfigBuilder` parses C Tor-style `Bridge <transport> <addr:port>
  <id> k=v ...` lines with `FromStr` — Orbot-style bridge lines import
  directly, no custom parser needed at first cut.
- Hand-built bridges work: `.transport(name)`, `.push_setting(k, v)`,
  `.set_addrs(vec![SocketAddr])`, `.set_ids(vec![...])`.
- Transports live in a plain `Vec<TransportConfig>` under
  `bridges.transports` (not an ordered map), each naming its transport name
  protocols, the client binary `path`, and `run_on_startup`.
- Validation happens at `TorClientConfig` build time: a bridge whose
  transport has no matching `TransportConfig` fails with *"all bridges
  unusable due to lack of corresponding pluggable transport"* — only when
  **every** bridge is unusable, so partial bridge sets are tolerated.
- `enabled` is `BoolOrAuto`: auto means "use bridges iff any are
  configured".
- **Process ownership:** `tor-ptmgr` *spawns and supervises the PT client
  binary itself* (that is what `path` means). M3's "PT supervisor"
  therefore is not a process manager for the client PTs arti launches;
  it is (a) locating/verifying binaries and (b) building the
  `TransportConfig`s. Anything arti cannot launch (DNS-based transports
  like dnstt) remains a real sidecar in our supervisor.
