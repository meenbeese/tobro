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
