# tobro — Desktop Tor Client

**A ground-up, desktop-only rewrite of Orbot on Rust/Arti and Tauri.**

| | |
|---|---|
| Document status | Planning draft v1.0 |
| Date | 2026-11-07 |
| Baseline | Orbot `53da58c6ab8831b8a10714ff1480dd774d8c5e0c` (2026-10-25), post-17.9.5 master / tor 0.4.9.11 |
| Target | macOS, Windows, Linux desktop |
| Implementation | None yet — this document is planning only |

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Vision, principles, and scope](#2-vision-principles-and-scope)
3. [Orbot baseline audit](#3-orbot-baseline-audit)
4. [Technology decisions](#4-technology-decisions)
5. [Architecture](#5-architecture)
6. [Feature parity matrix](#6-feature-parity-matrix)
7. [Milestones M0–M9](#7-milestones-m0m9)
8. [Achievements, release gates, and KPIs](#8-achievements-release-gates-and-kpis)
9. [Testing strategy](#9-testing-strategy)
10. [Security and privacy](#10-security-and-privacy)
11. [Packaging, signing, and updates](#11-packaging-signing-and-updates)
12. [Localization and accessibility](#12-localization-and-accessibility)
13. [Performance and resource budgets](#13-performance-and-resource-budgets)
14. [Risks and mitigations](#14-risks-and-mitigations)
15. [Open questions](#15-open-questions)
16. [Decision log](#16-decision-log)
17. [Appendices](#17-appendices)

---

## 1. Executive summary

**tobro** is a desktop-only Tor client that reproduces the useful surface of Orbot — connect/disconnect, bootstrap progress, bridges and pluggable transports, proxy services, onion services, and Kindness Mode — using a modern Rust stack.

The central decision is to **embed Arti directly** instead of shipping the C Tor binary: `arti-client` 0.48.0 (Arti 2.8.0, released 2026-11-04, MSRV Rust 1.92) provides client circuits, SOCKS5, HTTP CONNECT, DNS proxying, onion-service hosting and client authorization, bridges, pluggable transports, and a native RPC system. The desktop shell is **Tauri 2 + React 19 + TypeScript**, which gives a small, native-feeling app with a Rust core and a web UI without Electron's footprint.

The product is split into a long-lived **`tobrod` daemon** and a thin **Tauri GUI**, connected by a local JSON-RPC socket. The daemon owns Tor, proxies, pluggable transports, onion services, and system integration. This preserves Orbot's "background service" behavior, enables a headless CLI (`tobroctl`), keeps the UI crash-isolated from the network stack, and makes the privileged TUN helper a separate, auditable component.

**Parity approach.** Orbot is an Android app, so not every feature has a desktop meaning. Every Orbot feature is classified as **Full**, **Adapted**, **Deferred**, or **Not applicable** in [§6](#6-feature-parity-matrix). Mobile-only features (camo icons, quick-settings tiles, per-app Android VPN routing, battery-optimization prompts) are explicitly not forced into parity.

**Realistic scope.** The work is roughly **9–12 months for 2–3 engineers** across ten milestones. The riskiest items are not the UI; they are Arti's pre-1.0 API churn, pluggable-transport supervision across three operating systems, privileged TUN mode, and the impossibility of matching C Tor's control-port semantics exactly (notably `NEWNYM` and raw `torrc`). These are called out early, and the plan deliberately ships a strong **proxy-mode 1.0** before attempting transparent routing.

**Non-negotiable outcome:** a desktop app that a non-expert can install, connect, and trust, with honest status reporting and no fake parity. If Arti cannot do something, tobro says so rather than simulating it.

---

## 2. Vision, principles, and scope

### 2.1 Product vision

> Tor on the desktop should be as simple as Orbot on a phone: one switch, clear status, and sensible defaults — with the depth power users expect when they open advanced settings.

tobro is for:

- **Everyday users** who want their browser and desktop apps to use Tor without configuring a proxy.
- **Censored users** who need bridges, Snowflake, obfs4, WebTunnel, meek, or DNSTT with automatic fallback.
- **Privacy practitioners** who need stream isolation, onion services, client authorization, and verifiable logs.
- **Operators and researchers** who need a headless daemon and CLI.

### 2.2 Principles

1. **Honest over magical.** Never show "Connected" when only the SOCKS listener is up. Distinguish *daemon running*, *bootstrapped*, *circuits available*, and *system routing active*.
2. **Secure defaults.** Bind proxies to loopback; no telemetry; no plaintext secrets; fail closed for TUN/kill-switch modes.
3. **Local-first.** All configuration, logs, keys, and statistics stay on the machine unless the user explicitly exports them.
4. **Parity with intent, not with pixels.** Reproduce what a feature is *for* on desktop, not the Android mechanism.
5. **One core, many surfaces.** The GUI, tray, CLI, and future integrations all use the same daemon API.
6. **Small blast radius.** Privileged code is separate, minimal, auditable, and optional.
7. **Upstream first.** Prefer Arti's built-in SOCKS/HTTP/DNS/onion-service implementations over reimplementing Tor; contribute fixes upstream.
8. **Accessible and translatable from day one.** No hard-coded strings, keyboard-complete UI, WCAG 2.2 AA target.

### 2.3 In scope (1.0)

- Desktop only: macOS 13+, Windows 10 22H2+, mainstream Linux (Ubuntu 22.04+, Fedora 40+, Arch).
- Embedded Arti client with SOCKS5, HTTP CONNECT, and DNS proxy.
- Direct connections, bridges, pluggable transports, Moat auto-config, Smart Connect fallback.
- Exit-country selection, stream isolation, IPv6 preferences, supported node restrictions.
- New identity (Arti-compatible implementation, clearly labelled).
- System proxy integration, proxy environment variables, and an optional TUN mode after 1.0.
- v3 onion-service hosting, local port forwarding, client authorization, key import/export.
- Kindness Mode (Snowflake proxy) with limits and statistics.
- Tray agent, autostart, notifications, global shortcut, app lock, log viewer.
- Localization, accessibility, signed installers, signed auto-updates.
- Headless daemon and CLI.

### 2.4 Non-goals (1.0)

- Android, iOS, or any mobile target.
- Running a Tor **relay**, bridge, or directory authority. Arti's relay support is still incomplete, and operating an exit relay carries legal/abuse obligations.
- Matching C Tor's control port or accepting arbitrary `torrc`.
- Camouflage icons/app names, Android quick-settings tiles, Android `VpnService`, per-app Android routing, root detection, battery-optimization prompts.
- A built-in browser. tobro routes traffic; it does not harden a browser's fingerprint.
- Guaranteed anonymity for the whole OS by default without TUN; proxy mode is explicitly best-effort for apps that ignore proxy settings.
- A Tor Browser replacement or a "one-click dark web" product.

### 2.5 Terminology

| Term | Meaning in this document |
|---|---|
| **Daemon / `tobrod`** | Long-lived process owning Arti and all network state |
| **GUI** | Tauri/React desktop application |
| **Core** | Rust crates implementing lifecycle, config, Tor, proxies, onion services |
| **PT** | Pluggable transport (obfs4, Snowflake, WebTunnel, meek, DNSTT) |
| **Moat** | Tor Project bridge-distribution API used by Orbot's auto-config |
| **Smart Connect** | Ordered fallback: direct → Snowflake → obfs4 → custom |
| **Proxy mode** | Apps use tobro's SOCKS/HTTP ports; no privileged routing |
| **TUN mode** | A virtual interface captures traffic system-wide; privileged helper required |
| **Full / Adapted / Deferred / N/A** | Parity classifications defined in §6 |

---

## 3. Orbot baseline audit

### 3.1 What Orbot is, technically

Orbot is an Android application (Java/Kotlin, `minSdk 24`, `targetSdk 37`) that bundles the C Tor binary (`tor-android` 0.4.9.11), a Java control-port library (`jtorctl`), and Guardian Project's `IPtProxy` AAR for pluggable transports. It runs Tor inside a foreground `VpnService`/`Service`, builds a `torrc` from Android preferences, and exposes control events (bootstrap %, log lines, port assignments) to the UI through local broadcasts.

Key build facts from the reference checkout:

- `app/build.gradle.kts`: `applicationId org.torproject.android`, `minSdk 24`, `targetSdk 37`, dependencies on `tor-android`, `jtorctl`, `iptproxy`, AndroidX DataStore/Tink (encrypted preferences), Navigation, Biometric, UPnP, Material 3.
- ~102 Kotlin/Java source files under `org.torproject.android`.
- Tor is **not** embedded as a library; it is a separate native process managed through `TorService` and a control port.

### 3.2 Source areas that define the feature baseline

| Area | Reference file(s) | What it tells us |
|---|---|---|
| Service lifecycle | `app/src/main/java/org/torproject/android/service/OrbotService.java` (856 lines) | Start/stop, foreground notification, control events, bootstrap status, new identity, port reporting, VPN coordination, Snowflake lifecycle |
| Tor configuration | `app/src/main/java/org/torproject/android/service/tor/TorConfig.kt` (162 lines) | Exact `torrc` mapping: SOCKSPort/HTTPTunnelPort/TransPort/DNSPort, isolation flags, padding, IPv6, node restrictions, reachable addresses, onion services, client auth, custom torrc |
| Circumvention model | `.../service/circumvention/Transport.kt` (348 lines) | Transport enum (`direct`, `meek`, `obfs4`, `snowflake`, `snowflake_amp`, `snowflake_sqs`, `webtunnel`, `dnstt`, `custom`), bridge injection, PT startup, outbound proxy handling |
| Moat auto-config | `.../circumvention/AutoConf.kt` | Bridge request/response, country selection, fallback behavior |
| Bridge parsing | `.../circumvention/Bridge.kt` | Bridge-line model and serialization (`ip`, `port`, `transport`, `fingerprint`, `cert`, `iat-mode`, `url`, `fronts`, `ice`) |
| Built-in bridges | `.../circumvention/BuiltInBridges.kt` | Bundled bridge sets per transport, DNSTT country data |
| Smart Connect | `.../circumvention/SmartConnect.kt` | Ordered fallback chain and timeout behavior |
| Preferences | `app/src/main/java/org/torproject/android/util/Prefs.kt` (491 lines) | Complete preference inventory, defaults, and semantics |
| Settings UI | `app/src/main/res/xml/preferences.xml`, `safety_prefs.xml` | General, node config, reachable addresses, connectivity, padding, outbound proxy, debug, safety |
| Onion services | `.../service/db/OnionServiceColumns.kt` | `HiddenServiceDir`, `HiddenServiceVersion 3`, `HiddenServicePort onion:local`, domain persistence |
| Client auth | `.../service/db/V3ClientAuthColumns.kt` | `ClientOnionAuthDir`, `.auth_private` format `${domain}:descriptor:x25519:${key}` |
| Kindness Mode | `.../ui/kindness/KindnessFragment.kt`, `SnowflakeProxyService`, `TestTorForSnowflakeProxyService`, `KindnessWatchdogJob` | Snowflake proxy lifecycle, NAT type, UPnP, usage limits, eligibility testing |
| UI surface | `ui/connect`, `ui/settings`, `ui/more`, `ui/v3onionservice`, `ui/kindness`, `ui/quicksettings`, `ui/more/camo` | Main screens and mobile affordances |
| Platform hooks | `app/src/main/AndroidManifest.xml` (302 lines) | Services, VPN, boot receiver, quick-settings tiles, launcher aliases, content providers |
| Recent behavior | `docs/info/CHANGELOG.txt` | Current release priorities and bug history |

### 3.3 Orbot architecture in one paragraph

Orbot's `OrbotService` is both the Tor supervisor and the app's background runtime. It starts `TorService` (the bundled C Tor), waits for the control port, writes a generated `torrc` from `Prefs`, starts `IPtProxy` transports when needed, optionally establishes a `VpnService` with per-app routing, and broadcasts status to activities. The UI is a set of fragments backed by preferences and SQLite content providers. Onion services and client-auth keys are rows in SQLite, materialized into files and `torrc` lines on each start. The Android platform supplies lifecycle, notifications, boot, VPN, and quick-settings integration. **tobro must replace the platform-supplied parts with desktop equivalents, and must replace the C Tor control surface with Arti APIs.**

### 3.4 Complete Orbot preference inventory

From `Prefs.kt` and `preferences.xml`/`safety_prefs.xml`:

| Category | Preferences / behavior |
|---|---|
| General | `pref_default_locale`, `pref_start_boot`, `pref_open_proxy_on_all_interfaces`, `pref_power_user`, `pref_open_battery_opt` (Android), `pref_detect_root` (Android) |
| Kindness | `pref_show_snowflake_proxy_msg`, `pref_be_a_snowflake`, Wi-Fi-only limit, charging-only limit, UPnP ports, last NAT type, last active, served counts (total/weekly), last quality check |
| Node config | `pref_entrance_nodes`, `pref_exit_nodes`, `pref_exclude_nodes`, `pref_strict_nodes` |
| Reachable addresses | `pref_reachable_addresses`, `pref_reachable_addresses_ports` (default `*:80,*:443`) |
| Connectivity | `pref_isolate_dest`, `pref_isolate_port`, `pref_isolate_protocol`, `pref_isolate_keep_alive`, `pref_prefer_ipv6` (default true), `pref_disable_ipv4` |
| Padding | `pref_connection_padding`, `pref_reduced_connection_padding` (default true), `pref_circuit_padding` (default true), `pref_reduced_circuit_padding` (default true) |
| Outbound proxy | `pref_proxy_type` (http/https/socks4/socks5/shadowsocks), `pref_proxy_host`, `pref_proxy_port`, `pref_proxy_username`, `pref_proxy_password`, `pref_proxy_ss` |
| Debug | `pref_socks` (default 9050), `pref_http` (default 8118), `pref_transport`, `pref_dnsport` (default 9053), `pref_custom_torrc`, `pref_enable_logging` |
| Safety | `pref_flag_secure` (screenshot blocking), `pref_require_password`, `pref_auth_no_biometrics` |
| Internal | bridge list/country, connection pathway, Smart Connect toggle/timeout, current version, camo package/name/icon, Orbot service log |

### 3.5 Orbot defaults and ports

| Service | Orbot default | Notes |
|---|---|---|
| SOCKS5 | `9050` | Loopback unless "open proxy on all interfaces" is enabled |
| HTTP CONNECT | `8118` | Loopback by default |
| TransPort | `9040` | Android transparent proxy / VPN path |
| DNSPort | `9053` | Tor DNS resolver |
| Virtual address network | `10.192.0.0/10` | For `.onion` automapping |
| Tor | 0.4.9.11 | Bundled native binary |

### 3.6 What Orbot does that is Android-specific

These are **not** parity requirements; they are replaced or dropped:

| Android mechanism | Why it exists | Desktop replacement |
|---|---|---|
| `VpnService` + per-app routing | Route all device traffic, choose apps | System proxy / proxy env / optional TUN with destination-based split tunneling |
| Foreground service + persistent notification | Keep Tor alive under Android lifecycle | Tray agent + autostart; daemon survives GUI close |
| `BOOT_COMPLETED` receiver | Start on boot | LaunchAgent / Run key / systemd user unit |
| Quick-settings tiles | One-tap start / new identity | Tray menu + global shortcut |
| Camouflage icon/name | Hide the app under a repressive regime | Not applicable (installed app identity is visible; document) |
| Screenshot blocking (`FLAG_SECURE`) | Prevent shoulder-surfing/recents capture | Best-effort OS window-capture protection; not guaranteed |
| Battery-optimization prompts | Prevent OEM killers | Not applicable; optional "keep running" guidance |
| Root detection | Explain root-mode tradeoffs | Not applicable |
| Exact-alarm scheduling | Kindness watchdog | Daemon timer with OS sleep awareness |
| Biometric prompt | Unlock app | OS auth (Touch ID / Windows Hello / polkit/libsecret) plus password fallback |

### 3.7 Baseline gaps and inconsistencies to avoid repeating

- Orbot exposes many C Tor knobs that Arti does not implement (padding, full `EntryNodes`/`ExcludeNodes`, `ReachableAddresses`, raw `torrc`). tobro must **hide or clearly mark** unsupported options instead of writing them into a config Arti ignores.
- Orbot's "New Identity" depends on the C Tor control command `SIGNAL NEWNYM`. Arti has no equivalent control port. tobro needs an explicit, documented strategy (see §4.2.4).
- Orbot's UI conflates service state and Tor state in places (e.g., progress persistence across rotation was a recent bug). tobro should model state explicitly and test it.
- Orbot's Smart Connect behavior is heuristic and timeout-based; tobro should make the chain observable ("trying Snowflake, 12 s left") rather than a spinner.
- Orbot bundles bridge data and PT binaries in the APK. tobro needs a signed sidecar update channel that does not require shipping a full app update for every bridge rotation.

---

## 4. Technology decisions

### 4.1 Decision summary

| Layer | Choice | Version (Nov 2026) | Why |
|---|---|---|---|
| Tor engine | **Arti**, embedded `arti-client` | `arti-client` 0.48.0 / Arti 2.8.0 | Rust-native, no C Tor binary, client SOCKS/HTTP/DNS/onion services/PTs, memory-safe, single toolchain |
| Toolchain | Stable Rust, 2024 edition | MSRV 1.92 | Arti 2.8 requires 1.92; pin in `rust-toolchain.toml` |
| Async runtime | Tokio | 1.54+ | Arti's default runtime; ecosystem standard |
| Desktop shell | **Tauri 2** | 2.x | Small binaries, native WebView, Rust core, tray/updater/autostart plugins, no Chromium bundle |
| UI | **React 19 + TypeScript + Vite** | React 19, Vite 7 | Mature ecosystem, fast iteration, strong typing, easy localization/accessibility |
| Styling | **Tailwind CSS v4** + Radix primitives / shadcn-style components | — | Accessible primitives, consistent design system, no runtime CSS-in-JS |
| UI state | **Zustand** + **TanStack Query** | — | Small, predictable local store; query/cache semantics for daemon state |
| i18n | **i18next + react-i18next** | — | Mature, Weblate-friendly JSON, plurals, RTL |
| Config format | **TOML** + `serde` | — | Human-readable, matches Arti conventions, easy import/export |
| Persistence | **SQLite** via `sqlx` | — | Onion services, client-auth metadata, bridge history, stats; migrations |
| Secrets | **OS keychain** via `keyring` | — | Keychain / Credential Manager / Secret Service; no plaintext passwords |
| Logging | `tracing` + `tracing-subscriber` + rolling files | — | Structured, redactable, per-module levels |
| Errors | `thiserror` (libraries) + `anyhow` (boundaries) | — | Typed core errors, contextual CLI/daemon errors |
| CLI | `clap` + JSON-RPC client | — | Headless control and scripting |
| IPC | **JSON-RPC 2.0 over Unix socket / Windows named pipe** | — | Local-only, debuggable, no TCP exposure, easy CLI |
| HTTP client | `reqwest` (rustls) | — | Moat, bridge data, update metadata; no OpenSSL dependency |
| Pluggable transports | Arti `pt-client` + sidecars: **lyrebird**, **snowflake-client**, **dnstt-client** | — | Reuse Tor Project's maintained PT implementations |
| TUN (post-1.0) | `tun2proxy` / `netstack-smoltcp` + platform TUN | — | Rust userspace TCP/IP stack; no C tor transparent proxy |
| Packaging | Tauri bundler + platform packaging | — | DMG, MSI/NSIS, deb/rpm/AppImage |
| Updates | Tauri updater with signed manifest | — | Signature verification, staged rollout |
| CI | GitHub Actions matrix (macOS/Windows/Linux) | — | Cross-platform build/test/sign |

### 4.2 Tor engine: why Arti

#### 4.2.1 Capabilities we need

Arti 2.8.0 provides, as of this plan:

- Client bootstrapping with `bootstrap_status()` and a `bootstrap_events()` stream.
- SOCKS5 proxy, HTTP CONNECT proxy, and DNS proxy (UDP and TCP).
- `TorClient::connect`, `connect_with_prefs`, `resolve`, `resolve_ptr`.
- `StreamPrefs` for IPv4/IPv6 preference, exit country, isolation groups, optimistic streams, local-address and onion-service toggles.
- `TorClient::with_prefs` to set default stream preferences for a client handle.
- `reconfigure` for live config changes, with documented non-reconfigurable fields.
- `isolated_client()` for unlinkable client handles.
- Onion-service hosting: `create_onion_service`, `launch_onion_service`, `launch_onion_service_with_hsid`, `OnionService` lifecycle.
- Restricted discovery / client authorization: `generate_service_discovery_key`, `insert_service_discovery_key`, `get_service_discovery_key`, `remove_service_discovery_key`, `rotate_service_discovery_key`, plus `KeyMgr` and `HsClientDescEncKey`.
- Bridges and pluggable transports (`pt-client` feature, `BridgesConfig`, `BridgeConfig`, `TransportConfig`).
- Outbound proxy on channels (`ChannelConfig::outbound_proxy`), enabling HTTP/SOCKS upstream proxies; verify exact schemes in M3.
- `arti-rpcserver` for a native RPC interface (not a C Tor control port).
- Vanguards, circuit timing, preemptive circuits, stream timeouts, address filtering, GeoIP.

#### 4.2.2 Capabilities Arti does not yet provide (as of 2.8.0)

These are the parity gaps that shape the plan:

| C Tor / Orbot capability | Arti status | tobro response |
|---|---|---|
| Control port (`SIGNAL NEWNYM`, `GETINFO`, events) | Not implemented; uses RPC | Use Rust APIs and RPC; implement new identity as a client restart (§4.2.4) |
| Raw `torrc` / arbitrary options | Not supported | Typed config; advanced screen only shows supported knobs |
| `EntryNodes` / `ExcludeNodes` fingerprint lists, `StrictNodes` | Limited / not exposed | Surface supported path restrictions only; mark the rest Deferred |
| Connection/circuit padding | Not exposed | Mark Deferred; hide padding settings with an explanation |
| `ReachableAddresses` | Not exposed | Mark Deferred |
| Relay / bridge / directory authority | Incomplete | Explicit non-goal |
| Stable public API | Pre-1.0 | Pin versions, isolate behind `tobro-tor` adapter, track upstream |
| Obsolete consensus handling | Can call `exit(1)` | Supervisor treats unexpected exit as a restartable fault; file upstream issues |
| Exact `NEWNYM` semantics | No equivalent | Restart the client to get new circuits/TLS; document that guard selection may be preserved |

#### 4.2.3 Why not the C Tor binary

- Two runtimes, two security surfaces, and a control-port protocol to maintain.
- Cross-platform binary distribution and notarization are heavier.
- Orbot's control-port code (`jtorctl`) has no direct desktop equivalent worth preserving.
- Arti is the Tor Project's strategic client implementation; embedding it aligns tobro with upstream and avoids reimplementing Tor.
- Trade-off: Arti is younger and pre-1.0. The adapter layer and a conservative release cadence manage that risk.

#### 4.2.4 New identity design

C Tor's `NEWNYM` asks Tor to mark circuits dirty and stop using them for new streams, while keeping guards. Arti has no control port, but it does have `isolated_client()` and the ability to dispose and recreate a `TorClient`. The planned implementation:

1. Stop accepting new streams.
2. Drain or close the SOCKS/HTTP/DNS front-ends.
3. Dispose the current `TorClient` (and its circuits).
4. Recreate a `TorClient` from the same persisted state, with a fresh `IsolationToken`/handle.
5. Restart listeners and update the UI.

This yields new circuits and TLS connections while preserving guard state, which is closer to `NEWNYM` than deleting the guard state (deleting guards would be *worse* for anonymity and is not offered). The UI must say **"New identity (new circuits)"**, not promise exact C Tor behavior. If Arti later exposes a first-class API, swap the implementation behind the same daemon command.

#### 4.2.5 Version and upgrade policy

- Pin `arti-client` exactly (e.g., `=0.48.0`) and upgrade deliberately, one minor at a time.
- Track Arti's release notes monthly; run the full transport and onion-service suite on every bump.
- Keep a compatibility shim (`tobro-tor`) so an Arti API change touches one crate.
- Support the previous two stable releases of tobro with security fixes; publish an Arti version in About/diagnostics.

### 4.3 Desktop shell: why Tauri + React

**Tauri 2** is chosen over Electron, Flutter, and native Rust GUI toolkits because:

- **Rust core + system WebView**: no bundled Chromium (~150 MB saved), low idle memory, native menus/tray/updater/autostart.
- **Strong IPC boundary**: commands/events map cleanly to a daemon API; capabilities/permissions are explicit.
- **Cross-platform packaging** is first-class (DMG, MSI/NSIS, deb/rpm/AppImage).
- **Web UI velocity**: React/TypeScript gives accessible, translatable, testable screens quickly.
- **Security posture**: Tauri's allowlist/capability model is narrower than Electron's Node integration; the daemon is a separate process anyway.

Trade-offs:

- WebView differences (WKWebView vs WebView2 vs WebKitGTK) require a test matrix.
- Linux WebKitGTK can lag on newer CSS/JS features; keep the UI conservative.
- Tauri's updater and tray APIs are younger than Electron's; budget integration time.

**Rejected alternatives:**

| Option | Why rejected |
|---|---|
| **Electron + React** | 100–200 MB installers, high idle memory, larger attack surface, no benefit for a small utility |
| **Flutter desktop** | Strong UI toolkit, but Dart core would duplicate or FFI into Rust; Tor ecosystem is Rust/C; desktop tray/updater maturity is weaker |
| **Go + Wails/Fyne** | Go cannot embed Arti without cgo/FFI; Rust is the natural Arti host |
| **egui / iced / Slint** | Fast and Rust-native, but weaker accessibility, text input, RTL, and design-system support; harder to build a polished, translatable consumer UI |
| **Qt/C++** | Mature, but C++ memory safety and a second toolchain contradict the Rust-first goal; licensing complexity |
| **Web app only** | Cannot own local ports, keychain, system proxy, or TUN; unsuitable for a Tor client |

### 4.4 Data, config, and secrets

#### 4.4.1 Configuration model

- Single `config.toml` in the OS config directory, with a `config_version` and forward-only migrations.
- Atomic writes: write temp file, `fsync`, rename; keep one `.bak`.
- Validation on load and before apply; invalid config never replaces a working one.
- Typed schema split into sections: `general`, `network`, `proxy`, `bridges`, `stream`, `onion_services`, `kindness`, `ui`, `advanced`.
- Unknown keys are preserved on export but ignored on load (forward compatibility).
- Import/export as a single TOML file; **secrets are never included** (passwords and private keys are keychain/file references only).

Example:

```toml
config_version = 1

[general]
language = "system"
start_on_login = true
start_minimized = true
power_user = false

[network]
mode = "direct"            # direct | bridge | custom
exit_country = "auto"      # ISO 3166-1 alpha-2 or "auto"
ipv6 = "prefer"            # prefer | only | disable
new_identity_on_start = false

[proxy]
socks_port = 9050
http_port = 8118
dns_port = 9053
bind_all_interfaces = false
system_proxy = "off"       # off | on | ask

[bridges]
transport = "auto"         # auto | obfs4 | snowflake | webtunnel | meek | dnstt | custom
smart_connect = true
smart_connect_timeout_secs = 30
country = "auto"

[stream]
isolate_destination = false
isolate_port = false
isolate_protocol = false
keep_alive_isolation = false

[onion_services]
enabled = true

[kindness]
enabled = false
limit_charging_only = false
limit_metered_network = true
upnp = true

[advanced]
log_level = "info"
```

#### 4.4.2 Filesystem layout

Use the `directories` crate and platform conventions:

| Data | macOS | Windows | Linux |
|---|---|---|---|
| Config | `~/Library/Application Support/org.tobro.tobro/config.toml` | `%APPDATA%\tobro\config\config.toml` | `$XDG_CONFIG_HOME/tobro/config.toml` |
| Data/state | `~/Library/Application Support/org.tobro.tobro/` | `%LOCALAPPDATA%\tobro\` | `$XDG_DATA_HOME/tobro/` |
| Cache | `~/Library/Caches/org.tobro.tobro/` | `%LOCALAPPDATA%\tobro\cache\` | `$XDG_CACHE_HOME/tobro/` |
| Logs | `~/Library/Logs/tobro/` | `%LOCALAPPDATA%\tobro\logs\` | `$XDG_STATE_HOME/tobro/logs/` |
| Runtime socket | `~/Library/Application Support/org.tobro.tobro/run/tobrod.sock` | `\\.\pipe\tobro-tobrod` | `$XDG_RUNTIME_DIR/tobro/tobrod.sock` |
| Arti state | `<data>/arti/state/` | `<data>\arti\state\` | `<data>/arti/state/` |
| Onion keys | `<data>/onion-services/<id>/` (`0700`) | same | same |
| Client-auth keys | `<data>/onion-auth/` (`0700`, files `0600`) | same | same |
| Database | `<data>/tobro.db` | same | same |

#### 4.4.3 Secrets

- Proxy passwords, bridge credentials, and any future API tokens go to the **OS keychain** via `keyring`:
  - macOS Keychain, Windows Credential Manager, Linux Secret Service (GNOME Keyring/KWallet).
  - If no keychain is available, refuse to persist secrets by default; offer a session-only option and a clearly warned file fallback (`0600`, encrypted with a key derived from an app passphrase via Argon2id).
- Onion-service private keys and client-auth keys are files because Arti needs them; directories `0700`, files `0600`, and a startup permission check (`fs-mistrust`-style).
- Logs never include bridge lines, passwords, private keys, or full `.onion` client-auth secrets. A redaction layer runs before any log sink.
- Clipboard copy of `.onion` addresses or keys is explicit; clear-on-exit is a UI option, not a guarantee.

#### 4.4.4 Database

- SQLite in WAL mode, `sqlx` with migrations embedded in the binary.
- Tables: `onion_service`, `onion_service_port`, `client_auth`, `bridge_history`, `connection_event`, `kindness_stats`, `schema_migrations`.
- Onion service keys remain on disk (not in SQLite) to match Arti's key store and make backup/restore straightforward.
- Database backups are explicit exports; no automatic cloud sync.

### 4.5 Networking services

| Service | Implementation | Default | Notes |
|---|---|---|---|
| SOCKS5 | Arti's built-in SOCKS proxy | `127.0.0.1:9050` | Loopback only by default; optional all-interfaces with warning |
| HTTP CONNECT | Arti's built-in HTTP proxy | `127.0.0.1:8118` | For apps that only speak HTTP proxy |
| DNS | Arti's DNS proxy | `127.0.0.1:9053` | UDP + TCP; `.onion` resolution; optional system DNS later |
| Transparent/TUN | `tun2proxy` + TUN device | off | Post-1.0, privileged helper |
| System proxy | Platform adapter | off | Best-effort; not all apps honor it |
| Proxy env vars | Launch environment / `environment.d` | off | `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` |
| Outbound proxy | Arti `ChannelConfig::outbound_proxy` | none | HTTP CONNECT / SOCKS; Shadowsocks via local `sslocal` sidecar |

**Port policy:** keep Orbot-compatible defaults (`9050`, `8118`, `9053`) for familiarity and tooling compatibility. On startup, if a port is occupied, do **not** silently pick another; show a clear error with the owning process if available and offer "use next free port" (which updates config and dependent app instructions). A future "ephemeral ports" mode can be opt-in.

### 4.6 Pluggable transports

- Arti's `pt-client` feature manages PT processes using the pluggable-transport spec (SOCKS5 endpoint + environment/args), via `tor-ptmgr`.
- Bundle per-platform, per-architecture sidecars:
  - **lyrebird** — obfs4, meek, and WebTunnel.
  - **snowflake-client** — Snowflake, including AMP broker/front configuration where supported.
  - **dnstt-client** — DNSTT.
  - **sslocal** (Shadowsocks Rust) — outbound Shadowsocks proxy.
- Sidecar supervisor responsibilities: locate binary, verify signature/hash, start with a private state dir, parse readiness, capture stderr into redacted logs, restart with backoff, kill on shutdown, prevent orphan processes.
- Bridge data: bundle a signed `bridges.json` with built-in sets; update via app updates and an optional signed bridge-data channel; Moat can fetch fresh bridges on demand.
- Smart Connect: an explicit state machine with per-attempt timeout, cancellation, and a user-visible chain. Order: direct (short timeout) → Snowflake → obfs4 → custom. Remember the last successful transport per profile, not per network by default (network fingerprinting is privacy-sensitive).

### 4.7 System-wide networking

Phase 1 (1.0): **proxy mode**.

- SOCKS/HTTP ports for apps that support proxies.
- System proxy adapter per OS.
- Optional proxy environment variables for newly launched apps.
- Clear UI copy: "Apps that ignore proxy settings will not use Tor."

Phase 2 (post-1.0, opt-in): **TUN mode**.

- A privileged helper (`tobro-helper`) creates a TUN device and configures routes/DNS; the unprivileged daemon speaks a narrow local protocol to it.
- `tun2proxy` (userspace TCP/IP via `netstack-smoltcp`) forwards TCP; UDP handling is scoped (DNS first, QUIC best-effort/blocked with explanation).
- Split tunneling by destination CIDR/domain, not by app (desktop app identity is unreliable). Browser profiles remain the recommended per-app isolation mechanism.
- Kill switch: if the helper or Tor dies, remove routes and block traffic (fail closed) until the user disables the mode.
- Platform privileges:
  - macOS: `SMAppService`-registered LaunchDaemon helper (SMJobBless fallback for older targets), signed with the same Team ID; user approval via the system prompt.
  - Windows: Windows service running as `LocalSystem` or a restricted service account; named-pipe API with ACLs.
  - Linux: systemd system unit + polkit action; or `setcap` on a small helper (preferred: polkit).

### 4.8 Onion services

- Hosting via Arti's onion-service APIs. Persist the service's keys and `.onion` address; expose a stable identity across restarts.
- Model: service (name, onion address, enabled, key path) → ports (onion port → `127.0.0.1:local port`).
- Client authorization: generate/import restricted-discovery keys; export `.auth_private` in the standard `${domain}:descriptor:x25519:${key}` format; import validates and stores `0600`.
- Client-side onion access: through Arti's SOCKS/DNS; no special configuration for `.onion` names.
- Backup/restore: export a service bundle (address + keys + port map) as an encrypted archive; warn that anyone with the keys can impersonate the service.
- Health: show whether the service is published, last descriptor upload, and recent errors (from Arti events/tracing). Do not claim uptime we cannot measure.
- Not in 1.0: vanity address generation (computationally expensive; can be a separate tool later).

### 4.9 Kindness Mode

- Run the **snowflake-proxy** sidecar (not the client) with a dedicated state dir.
- Show NAT type (STUN), whether UPnP succeeded, current connections, and weekly/total served counts parsed from proxy output.
- Limits:
  - "Only on metered networks" — desktop network metering is unreliable; default to a manual toggle plus a warning, and use OS APIs where available.
  - "Only while charging" — use OS power-source APIs; on desktops without a battery, treat as "always plugged in" with a note.
  - Optional daily/weekly connection caps and a bandwidth cap.
- Eligibility test: verify outbound UDP, STUN, and a Tor bootstrap before enabling; explain failures (firewall, symmetric NAT, another VPN).
- Regionalization: reuse Orbot's country logic to disable or warn in heavily censored regions; make it a policy file, not hard-coded UI.
- Privacy: Snowflake proxies relay encrypted traffic and see client IPs at the network layer; link to the Snowflake privacy explanation. No traffic logging.

### 4.10 Rejected or deferred technologies

| Technology | Decision | Reason |
|---|---|---|
| C Tor + control port | Rejected | Contradicts the Arti goal; two runtimes; control-port compatibility burden |
| Electron | Rejected | Size, memory, attack surface |
| Flutter | Rejected | Dart/Rust split; weaker desktop integration for this use case |
| Go (Wails/Fyne) | Rejected | Arti is Rust; FFI complexity |
| egui/iced/Slint | Rejected for primary UI | Accessibility/i18n/design-system maturity |
| Custom Tor implementation | Rejected | Out of scope and unsafe |
| Reimplementing SOCKS/HTTP/DNS | Rejected by default | Use Arti; build a thin front-end only if stream prefs require it |
| Built-in browser | Rejected | Fingerprinting and maintenance; route, don't browse |
| Relay/exit mode | Deferred/N/A | Arti relay incomplete; legal/abuse burden |
| Mobile targets | N/A | Desktop-only mandate |
| Cloud sync of settings/keys | Rejected | Privacy and key-custody risk |
| Telemetry/analytics SDK | Rejected | Violates local-first principle; optional local diagnostics only |

---

## 5. Architecture

### 5.1 System overview

```text
┌──────────────────────────────────────────────────────────────────┐
│                        User session                              │
│                                                                  │
│  ┌────────────────────┐        JSON-RPC 2.0        ┌───────────┐  │
│  │  tobro GUI         │◄──────────────────────────►│  tobrod   │  │
│  │  Tauri 2 + React   │   UDS / named pipe        │  daemon   │  │
│  │  tray, windows     │   events + commands       │           │  │
│  └────────────────────┘                            └─────┬─────┘  │
│                                                          │        │
│  ┌────────────────────┐                                  │        │
│  │  tobroctl CLI      │◄─────────────────────────────────┤        │
│  └────────────────────┘                                  │        │
│                                                          │        │
│                                          ┌───────────────┼────────┐
│                                          │               │        │
│                                    ┌─────▼─────┐   ┌─────▼─────┐  │
│                                    │  Arti     │   │ PT manager│  │
│                                    │  client   │   │ sidecars  │  │
│                                    └─────┬─────┘   └─────┬─────┘  │
│                                          │               │        │
│                                    ┌─────▼───────────────▼─────┐  │
│                                    │  Tor network (bridges)     │  │
│                                    └────────────────────────────┘  │
│                                                                  │
│  ┌─────────────────────────────┐        ┌──────────────────────┐  │
│  │  tobro-helper (privileged)  │◄──────►│  TUN / routes / DNS  │  │
│  │  optional, TUN mode only    │        │  (post-1.0)          │  │
│  └─────────────────────────────┘        └──────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### 5.2 Process and trust boundaries

| Process | Privilege | Owns | Trust boundary |
|---|---|---|---|
| `tobro` GUI | User | WebView UI, tray, notifications, windows | Untrusted-ish UI; no direct Tor/secret access |
| `tobrod` | User | Arti, listeners, config, SQLite, onion keys, PT sidecars | Trusted core; only local IPC |
| `tobroctl` | User | CLI | Same API as GUI |
| PT sidecars | User | obfs4/Snowflake/WebTunnel/meek/DNSTT/Shadowsocks | Untrusted binaries; sandbox where possible, signed, no secrets beyond their config |
| `tobro-helper` | Root/system | TUN device, routes, DNS | Minimal privileged surface; authenticated IPC; audited |

Design rules:

- The GUI never reads private keys directly; it asks the daemon for display-safe metadata.
- The daemon never exposes a TCP control port. IPC is a local socket/pipe with peer credential checks.
- The privileged helper only accepts a fixed set of operations (create/configure/destroy TUN, set routes, set DNS) and validates all addresses.
- PT sidecars run with the minimum environment; no inherited keychain access; state in a per-transport dir.

### 5.3 Why a separate daemon

Alternatives considered:

1. **Everything in the Tauri process** — simplest packaging, but closing the window kills Tor unless tray logic keeps it alive; CLI cannot work without a GUI; a UI crash takes down Tor; privileged helper coupling is awkward.
2. **Tauri sidecar daemon** — good, but Tauri still owns lifecycle; less clean for headless mode.
3. **Independent `tobrod`** — chosen.

Benefits:

- Tor survives GUI close/crash; tray reconnects instantly.
- Headless/SSH/server use via `tobroctl`.
- Crash isolation and cleaner tests (daemon can run in CI without a display).
- Privileged helper talks only to the daemon.
- The GUI can be replaced (or a future native UI added) without touching the core.

Costs:

- Two processes to package, start, and supervise.
- IPC versioning and authentication.
- Slightly more complex first-run/autostart logic.

Those costs are paid once in M1 and are worth it for the product shape.

### 5.4 Repository and crate layout

```text
tobro/
├── Cargo.toml                     # workspace
├── rust-toolchain.toml            # pin 1.92+
├── package.json                   # frontend workspace
├── apps/
│   ├── desktop/                   # Tauri shell binary `tobro`
│   │   ├── src-tauri/
│   │   └── ui/                    # React app (or top-level ui/)
│   └── cli/                       # `tobroctl`
├── crates/
│   ├── tobro-core/                # lifecycle state machine, orchestration
│   ├── tobro-config/              # schema, load/save/migrate/validate
│   ├── tobro-tor/                 # Arti adapter, prefs, reconfigure, new identity
│   ├── tobro-proxy/               # listeners, SOCKS/HTTP/DNS wiring, port policy
│   ├── tobro-pt/                  # sidecar supervisor, bridge parser, Smart Connect
│   ├── tobro-onion/               # onion services, client auth, key bundles
│   ├── tobro-system/              # OS proxy, autostart, power, network state
│   ├── tobro-store/               # SQLite, migrations, keychain wrapper
│   ├── tobro-ipc/                 # JSON-RPC schema, server, client
│   ├── tobro-kindness/            # snowflake-proxy supervisor, stats, limits
│   └── tobro-tun/                 # TUN client + helper protocol (post-1.0)
├── sidecars/                      # pinned binaries + checksums per target
├── packaging/                     # macOS, Windows, Linux assets/scripts
├── docs/                          # user docs, threat model, ADRs
├── tests/                         # integration, network simulation, leak tests
└── .github/workflows/             # CI matrix, signing, release
```

Frontend layout:

```text
ui/
├── src/
│   ├── app/                       # routing, providers, error boundaries
│   ├── features/
│   │   ├── connection/            # connect screen, status, bootstrap
│   │   ├── bridges/               # transport picker, Smart Connect, custom
│   │   ├── proxy/                 # ports, system proxy, TUN
│   │   ├── onion/                 # services, client auth, QR/export
│   │   ├── kindness/              # snowflake proxy UI
│   │   ├── logs/                  # live logs, filters, export
│   │   └── settings/              # general, network, advanced, safety
│   ├── components/                # design system (Radix/shadcn-style)
│   ├── hooks/                     # daemon queries/events
│   ├── lib/                       # ipc client, formatters, validators
│   ├── locales/                   # i18next JSON
│   └── styles/
└── tests/                         # unit + component + e2e
```

### 5.5 Core state machine

```text
        ┌──────────┐   start   ┌───────────┐  bootstrap  ┌────────────┐
        │ Stopped  ├──────────►│ Starting  ├────────────►│ Bootstrapping │
        └────▲─────┘           └─────┬─────┘             └──────┬─────┘
             │                       │ error                    │ 100%
             │ stop                  ▼                          ▼
        ┌────┴─────┐           ┌───────────┐             ┌────────────┐
        │ Stopping │◄──────────┤  Error    │             │  Connected │
        └──────────┘   stop    └───────────┘             └─────┬──────┘
                                                               │ network loss
                                                               ▼
                                                        ┌────────────┐
                                                        │ Reconnecting│
                                                        └────────────┘
```

Rules:

- Every transition is idempotent and cancellation-safe.
- `Connected` means bootstrapped **and** listeners bound; system routing is a separate flag (`routing: proxy | system | tun | off`).
- Desired state (`stopped`/`running`) is persisted so autostart/reconnect can restore intent, but never auto-connects after a user-initiated stop.
- On unexpected Arti exit (including obsolete-consensus `exit(1)`), the supervisor enters `Error`, records the cause, backs off, and retries only if desired state is running. The UI shows a "Restart Tor" action.
- Bootstrap events include a stage label, percent, and a redacted detail line. Never show a frozen 0% spinner: if no events arrive for N seconds, show "waiting for network/directory" with diagnostics.
- Network changes (interface up/down, default route change, sleep/wake) trigger a debounced reconnect check.

### 5.6 IPC design

- **Protocol:** JSON-RPC 2.0 request/response plus server-initiated notifications for events.
- **Transport:** Unix domain socket on macOS/Linux; Windows named pipe. No TCP listener by default (an opt-in localhost TCP port may be added for debugging, off by default and token-protected).
- **Authentication:** socket/pipe permissions (`0700` dir, `0600` socket) plus peer credential checks (`SO_PEERCRED`/`LOCAL_PEERCRED`; named-pipe ACL for the current user). A random per-session token is written to a `0600` file for clients that cannot use peer creds.
- **Versioning:** `rpc_version` in `hello`; daemon rejects incompatible majors with a clear error. Additive fields are allowed.
- **Backpressure:** event subscriptions have bounded queues; slow clients are dropped with a `lagged` notification rather than blocking Tor.

Core methods (indicative):

```text
daemon.hello            -> { version, rpc_version, platform, arti_version }
daemon.status           -> { state, bootstrap, routing, ports, exit_country, ... }
daemon.start            { profile? }
daemon.stop
daemon.restart
daemon.new_identity
config.get              -> redacted config
config.validate         { patch }
config.apply            { patch }
bridges.list            -> built-in sets + metadata
bridges.test            { line } -> result
bridges.moat            { country?, transport? } -> bridge lines
transports.list
transports.select       { transport }
logs.subscribe          { level }
logs.unsubscribe
logs.export             { redact: true }
onion.list
onion.create            { name, ports[] }
onion.update            { id, enabled, ports[] }
onion.delete            { id }
onion.auth.list
onion.auth.import       { domain, key }
onion.auth.export       { id }
kindness.status
kindness.start/stop
system.proxy.get/set
system.autostart.get/set
diagnostics.export
```

Events:

```text
daemon.state_changed
bootstrap.progress
log.line
ports.changed
onion.published
onion.error
transport.attempt
transport.ready
transport.failed
kindness.stats
system.proxy_changed
```

The Tauri layer exposes thin commands that call the same IPC client; the React app uses TanStack Query for request/response and a typed event subscription for pushes. No business logic in the UI beyond presentation and validation.

### 5.7 Configuration and reconfiguration flow

1. UI sends a **patch**, not a whole config.
2. Daemon validates the merged config against the schema and Arti's capabilities.
3. If the change is hot-reconfigurable (e.g., exit country, IPv6 preference, log level), apply via `TorClient::reconfigure` or a new `TorClient::with_prefs` handle.
4. If it requires a restart (e.g., bridge set, ports, onion-service enable), mark `restart_required` and either auto-restart with a progress UI or ask the user.
5. Persist only after successful apply; on failure, keep the previous config and report the field-level error.
6. Secrets are stored via `tobro-store`; the config file contains only a reference.

### 5.8 Bridge and Smart Connect pipeline

```text
User selects Auto / transport
            │
            ▼
  ┌───────────────────┐
  │ Resolve bridge set│  built-in JSON → Moat → custom lines
  └─────────┬─────────┘
            ▼
  ┌───────────────────┐
  │ Validate lines    │  parser + fingerprint/cert checks
  └─────────┬─────────┘
            ▼
  ┌───────────────────┐
  │ Start PT sidecar  │  lyrebird / snowflake-client / dnstt-client
  └─────────┬─────────┘
            ▼
  ┌───────────────────┐
  │ Apply to Arti     │  BridgesConfig + TransportConfig
  └─────────┬─────────┘
            ▼
  ┌───────────────────┐
  │ Bootstrap w/ timer│  success → remember; failure → next attempt
  └───────────────────┘
```

Smart Connect rules:

- Total budget (default 30 s) divided across attempts; each attempt reports `attempt`, `deadline`, `reason`.
- Direct is tried first only if the user chose Auto and no bridges are configured.
- Snowflake before obfs4 (matches Orbot's emphasis on NAT-friendly transports), then custom.
- On success, persist the winning transport **and** the bridge line set (so the next start is fast), but not a network identifier.
- On total failure, keep Tor stopped, show a diagnostic summary, and offer "try again", "use built-in obfs4", or "enter a bridge".

### 5.9 System proxy adapters

| OS | Mechanism | Privilege | Caveats |
|---|---|---|---|
| macOS | `SystemConfiguration` framework or `networksetup` per network service | Usually admin for `networksetup`; helper/authorization may be needed | Per-service; VPN/network changes require reapply; some apps ignore it |
| Windows | `HKCU\...\Internet Settings` + `InternetSetOption` refresh | User | WinINet apps only; WinHTTP and many Electron/Java apps ignore it |
| Linux | GNOME `gsettings`, KDE `kwriteconfig`, fallback env vars | User | No universal standard; browsers often have their own settings |

Adapter interface:

```rust
trait SystemProxy {
    fn snapshot(&self) -> Result<ProxySnapshot>;
    fn apply(&self, proxy: &ProxyConfig) -> Result<()>;
    fn restore(&self, snapshot: &ProxySnapshot) -> Result<()>;
}
```

Rules:

- Always snapshot before applying and restore on stop/crash/uninstall.
- Verify after apply (read back) and report "applied but unverified" if the OS does not expose state.
- Never leave the system pointing at a dead proxy: a watchdog restores the snapshot if the daemon exits unexpectedly.
- The UI explains which apps are covered.

### 5.10 Logging and diagnostics

- `tracing` with per-module targets: `tobro::lifecycle`, `tobro::tor`, `tobro::pt`, `tobro::onion`, `tobro::system`, `tobro::kindness`, `tobro::ipc`.
- Default `info`; `debug`/`trace` are power-user options with a warning.
- Rolling files with size/age caps; in-memory ring buffer for the live viewer.
- Redaction: bridge lines, proxy credentials, onion client-auth keys, authorization headers, and file paths containing user names (where feasible).
- `diagnostics.export` creates a zip with app version, OS, Arti version, redacted config, recent logs, port status, and transport results. It never includes keys or passwords. The user reviews the file before sharing.
- Crash handling: no automatic upload. On restart, show "tobro closed unexpectedly" with a local report option.

### 5.11 Concurrency and shutdown

- A single `Core` actor owns mutable state; commands are messages to it, avoiding lock-order bugs.
- Tor operations are async and cancellable (`CancellationToken`).
- Shutdown order: stop accepting new streams → stop PTs → stop onion services → stop Arti → restore system proxy → close DB → exit.
- A hard shutdown timeout (e.g., 10 s) force-kills sidecars, then restores the system proxy snapshot from a persisted journal.
- Orphan prevention: sidecars are started in their own process group/job object and killed on daemon exit; a stale-PID file is cleaned.

---

## 6. Feature parity matrix

Status legend:

- **Full** — feature exists with equivalent behavior.
- **Adapted** — the intent is preserved through a desktop-appropriate mechanism, with documented differences.
- **Deferred** — planned after 1.0 or blocked on an upstream capability.
- **N/A** — no meaningful desktop equivalent; explicitly out of scope.

### 6.1 Core lifecycle and status

| ID | Orbot feature | Status | tobro implementation | Milestone |
|---|---|---|---|---|
| F-01 | Start/stop Tor | Full | Daemon state machine; UI switch + tray | M1 |
| F-02 | Bootstrap progress and status text | Full | Arti `bootstrap_events`/`bootstrap_status`; stage labels | M1 |
| F-03 | New identity | Adapted | Dispose/recreate `TorClient`; new circuits/TLS; label honestly | M2 |
| F-04 | Autostart on boot/login | Full | LaunchAgent / Run key / systemd user unit | M4 |
| F-05 | Background operation | Full | `tobrod` + tray; closing window does not stop Tor | M1/M4 |
| F-06 | Reconnect on network change | Full | OS network monitor + debounced reconnect | M3 |
| F-07 | Connection diagnostics | Adapted | Port checks, bootstrap trace, transport test, redacted export | M7 |
| F-08 | Headless mode | Added | `tobrod` + `tobroctl` | M6 |

### 6.2 Proxy and routing

| ID | Orbot feature | Status | tobro implementation | Milestone |
|---|---|---|---|---|
| F-09 | SOCKS5 proxy | Full | Arti SOCKS | M1 |
| F-10 | HTTP CONNECT proxy | Full | Arti HTTP proxy | M1 |
| F-11 | DNS proxy | Full | Arti DNS proxy (UDP/TCP) | M2 |
| F-12 | Custom ports | Full | Config + conflict detection | M2 |
| F-13 | Bind proxy on all interfaces | Full | Opt-in with warning + firewall guidance | M2 |
| F-14 | Transparent proxy / VPN | Adapted | TUN mode (post-1.0), opt-in, privileged helper | M7 |
| F-15 | System proxy integration | Adapted | Per-OS adapter; snapshot/restore/verify | M5 |
| F-16 | Proxy environment variables | Full | Launch env / `environment.d` / user guidance | M5 |
| F-17 | Per-app routing | Adapted | Desktop app identity is unreliable; destination-based split tunneling in TUN mode and browser profiles | M7 |
| F-18 | Outbound proxy (HTTP/SOCKS) | Full | Arti `ChannelConfig::outbound_proxy`; verify schemes | M3 |
| F-19 | Shadowsocks outbound | Adapted | `sslocal` sidecar → Arti outbound SOCKS | M3 |
| F-20 | Kill switch | Adapted | TUN mode only; fail-closed routes | M7 |

### 6.3 Circumvention and bridges

| ID | Orbot feature | Status | tobro implementation | Milestone |
|---|---|---|---|---|
| F-21 | Direct connection | Full | Arti default | M1 |
| F-22 | obfs4 | Full | lyrebird sidecar + Arti PT | M3 |
| F-23 | Snowflake | Full | lyrebird/snowflake-client | M3 |
| F-24 | Snowflake AMP | Adapted | Snowflake client AMP broker/front config | M3 |
| F-25 | Snowflake SQS | Deferred | Orbot itself disables it; revisit when stable | — |
| F-26 | WebTunnel | Full | lyrebird | M3 |
| F-27 | meek | Full | lyrebird | M3 |
| F-28 | DNSTT | Adapted | dnstt-client sidecar; country data | M3 |
| F-29 | Custom bridge lines | Full | Parser + validation + UI | M3 |
| F-30 | Built-in bridge sets | Full | Signed bundled JSON + updates | M3 |
| F-31 | Moat auto-config | Full | HTTPS client + country; fallback to built-ins | M3 |
| F-32 | Smart Connect fallback | Full | Observable state machine with budgets | M3 |
| F-33 | Bridge country selection | Adapted | Moat/built-in country filter where data exists | M3 |
| F-34 | Bridge line import/export | Full | Text import, QR (later), redacted export | M3 |
| F-35 | PT binary updates | Adapted | Signed sidecar channel or app updates | M8 |
| F-36 | Transport-specific settings | Adapted | Only expose supported knobs; hide the rest | M3 |

### 6.4 Identity, privacy, and network behavior

| ID | Orbot feature | Status | tobro implementation | Milestone |
|---|---|---|---|---|
| F-37 | Exit node country | Full | `StreamPrefs::exit_country` + default prefs; GeoIP feature | M2 |
| F-38 | Entry nodes | Deferred | Arti does not expose fingerprint-level entry pinning; hide with explanation | — |
| F-39 | Exclude nodes | Deferred | Same as above | — |
| F-40 | StrictNodes | Deferred | Only if Arti exposes strict path rules; currently unavailable | — |
| F-41 | Reachable addresses | Deferred | Arti does not expose; hide with explanation | — |
| F-42 | Stream isolation (destination/port/protocol) | Adapted | `StreamPrefs` isolation groups; thin SOCKS front-end if needed | M2 |
| F-43 | SOCKS auth keep-alive isolation | Adapted | If Arti SOCKS supports it; otherwise document | M2 |
| F-44 | IPv6 preference / IPv4 disable | Full | `StreamPrefs` (prefer/only/disable) via default client prefs | M2 |
| F-45 | Connection padding | Deferred | Arti gap; hide with explanation | — |
| F-46 | Circuit padding | Deferred | Arti gap; hide with explanation | — |
| F-47 | Dormant client timeout | Adapted | `set_dormant` + app idle policy | M2 |
| F-48 | Safe logging | Full | Redaction layer + level control | M2 |
| F-49 | Custom torrc | N/A | Typed advanced config only; raw torrc is deliberately unsupported | M2 |

### 6.5 Onion services

| ID | Orbot feature | Status | tobro implementation | Milestone |
|---|---|---|---|---|
| F-50 | Host v3 onion service | Full | Arti onion-service APIs | M5 |
| F-51 | Enable/disable service | Full | Daemon + persisted state | M5 |
| F-52 | Local port mapping | Full | `onion port → 127.0.0.1:local` | M5 |
| F-53 | Copy/share `.onion` address | Full | Clipboard + QR | M5 |
| F-54 | Client authorization | Full | Restricted discovery keys | M5 |
| F-55 | Import/export `.auth_private` | Full | Standard format + validation | M5 |
| F-56 | Onion service backup/restore | Full | Encrypted bundle export/import | M5 |
| F-57 | Service health/status | Adapted | Publish state + recent errors | M5 |
| F-58 | Access `.onion` sites | Full | Arti SOCKS/DNS | M1/M5 |
| F-59 | Vanity addresses | Deferred | Expensive; separate tool later | — |

### 6.6 Kindness Mode

| ID | Orbot feature | Status | tobro implementation | Milestone |
|---|---|---|---|---|
| F-60 | Run Snowflake proxy | Adapted | `snowflake-proxy` sidecar | M6 |
| F-61 | NAT type detection | Adapted | STUN at startup/periodically | M6 |
| F-62 | UPnP port mapping | Adapted | `portmapper`/`igd-next`; optional | M6 |
| F-63 | Wi-Fi/metered limit | Adapted | OS metering where available; manual toggle + warning | M6 |
| F-64 | Charging-only limit | Adapted | OS power-source API; desktop caveat | M6 |
| F-65 | Weekly/total served stats | Full | Parse proxy stats; local DB | M6 |
| F-66 | Eligibility/quality test | Adapted | UDP/STUN/bootstrap test with clear failures | M6 |
| F-67 | Regional restrictions | Adapted | Policy file derived from Orbot logic | M6 |
| F-68 | Start/stop with Tor | Adapted | Independent toggle + optional coupling | M6 |

### 6.7 UX, settings, and platform

| ID | Orbot feature | Status | tobro implementation | Milestone |
|---|---|---|---|---|
| F-69 | Main connect screen | Full | React connection screen | M1 |
| F-70 | Live log viewer | Full | Ring buffer + filters + export | M2 |
| F-71 | General settings | Full | Language, autostart, power user, bind-all | M4 |
| F-72 | Node config UI | Adapted | Supported subset only | M2 |
| F-73 | Connectivity settings | Adapted | Isolation, IPv6; padding hidden | M2 |
| F-74 | Outbound proxy settings | Full | Type/host/port/auth + Shadowsocks | M3 |
| F-75 | Debug settings | Adapted | Ports, transport, log level; no raw torrc | M2 |
| F-76 | Power-user mode | Full | Gates advanced screens | M4 |
| F-77 | App lock / password | Adapted | OS auth (Touch ID/Windows Hello/polkit) + password fallback | M4 |
| F-78 | Screenshot blocking | Adapted | Best-effort window capture protection; documented limits | M4 |
| F-79 | Notifications | Full | Native notifications for state/errors | M4 |
| F-80 | Tray menu | Full | Connect, new identity, status, quit | M4 |
| F-81 | Global shortcut | Adapted | Toggle connection / new identity | M4 |
| F-82 | Quick-settings tiles | N/A | Tray/shortcut replacement | — |
| F-83 | Camouflage icon/name | N/A | Not applicable; document visibility | — |
| F-84 | Boot receiver | Full | Autostart integration | M4 |
| F-85 | Battery optimization / root detection | N/A | Desktop OSes do not need these | — |
| F-86 | Persistent notification | N/A | Tray status replaces it | — |
| F-87 | First-run onboarding | Adapted | Permissions, proxy explanation, bridge choice | M4 |
| F-88 | Help/About/version | Full | In-app + docs link | M4 |
| F-89 | Localization | Full | i18next + Weblate | M7 |
| F-90 | Themes/accessibility | Full | Light/dark/system, keyboard, screen reader | M4/M7 |
| F-91 | Settings import/export | Full | TOML, secrets excluded | M2 |
| F-92 | Update mechanism | Full | Signed Tauri updater | M8 |

### 6.8 Parity scorecard (target 1.0)

| Category | Full | Adapted | Deferred | N/A | Added | Notes |
|---|---:|---:|---:|---:|---:|---|
| Core lifecycle | 5 | 2 | 0 | 0 | 1 | New identity is adapted by design; headless CLI is an addition |
| Proxy/routing | 7 | 5 | 0 | 0 | 0 | TUN deferred; per-app routing adapted |
| Circumvention | 10 | 5 | 1 | 0 | 0 | SQS deferred (Orbot also disables) |
| Privacy/network | 3 | 3 | 6 | 1 | 0 | Padding, reachable addresses, and node pinning blocked on Arti |
| Onion services | 8 | 1 | 1 | 0 | 0 | Vanity deferred |
| Kindness | 1 | 8 | 0 | 0 | 0 | Desktop limits are inherently adapted |
| UX/platform | 13 | 7 | 0 | 4 | 0 | Mobile-only features dropped |
| **Total** | **47** | **31** | **8** | **5** | **1** | **92 tracked features** |

The deferred items are all upstream-limited or explicitly post-1.0; none blocks the core value proposition.

---

## 7. Milestones M0–M9

Assumptions: 2–3 engineers (Rust + frontend), part-time design/security review, 1-week sprints, a working CI matrix from M0. Durations are elapsed weeks, not person-weeks. They overlap where dependencies allow.

### M0 — Foundations and feasibility spike (2 weeks)

**Goal:** prove the riskiest integration before building product surface.

Deliverables:

- Workspace skeleton, `rust-toolchain.toml` (1.92), lint/format/test CI on macOS/Windows/Linux.
- Spike: headless Rust binary bootstraps Arti 2.8, starts SOCKS/HTTP/DNS, prints bootstrap events, serves a request through Tor.
- Spike: Tauri 2 window talks to the spike daemon over a Unix socket/named pipe.
- Decision record: daemon architecture, IPC format, port policy, license.
- Risk register with owners.
- Benchmark baseline vs C Tor (bootstrap time, throughput, memory) on one machine per OS.

Exit criteria:

- One command starts the daemon and connects through Arti on all three OSes.
- Bootstrap events render in a minimal Tauri window.
- No blocking architectural unknowns remain for M1.

### M1 — Tor core and minimal GUI (4 weeks)

**Goal:** a usable connect/disconnect app with honest status.

Deliverables:

- `tobrod` lifecycle state machine, logging, shutdown, crash supervision.
- `tobro-config` schema/load/save/validate; `tobro-store` SQLite + keychain.
- Arti adapter: bootstrap, SOCKS/HTTP wiring, status, reconfigure basics.
- JSON-RPC server/client, event subscriptions, peer auth, version handshake.
- React shell: connection screen, status, bootstrap stage, logs (basic), tray icon, quit-to-tray.
- Packaging smoke builds (unsigned) for macOS/Windows/Linux.

Exit criteria:

- Connect/stop works repeatedly; 24-hour soak with no leaks or orphan processes.
- Status never claims connected before bootstrap completes.
- GUI close leaves the daemon running; reopen reconnects instantly.
- Logs contain no secrets in a redaction test.

### M2 — Power-user networking (4 weeks)

**Goal:** match Orbot's advanced network controls where Arti supports them.

Deliverables:

- Configurable ports with conflict detection and next-free helper.
- Bind-all-interfaces opt-in with warning and firewall guidance.
- DNS proxy wiring; `.onion` resolution test.
- Exit-country selection; IPv6 prefer/only/disable; default `StreamPrefs`.
- Stream isolation (destination/port/protocol; keep-alive if supported).
- New identity (client restart) with UI copy and tests.
- Supported node restrictions; unsupported options hidden with explanations.
- Log viewer with filters, copy, save; redaction hardening.
- Config import/export (no secrets); advanced settings screen; power-user gate.

Exit criteria:

- Feature tests cover every exposed knob; unsupported knobs are absent, not silently ignored.
- New identity produces new circuits (verified via logs/exit IP change) and preserves guards.
- Port conflicts produce actionable errors on all OSes.

### M3 — Circumvention and bridges (6 weeks)

**Goal:** connect from censored networks with Orbot-grade fallback.

Deliverables:

- PT supervisor: locate/verify/start/stop/restart sidecars; readiness and error parsing.
- lyrebird integration: obfs4, meek, WebTunnel.
- snowflake-client integration (including AMP where supported).
- dnstt-client integration and country data.
- Bridge parser/validator; custom bridge import/export; built-in bridge JSON.
- Moat client with country/transport selection and fallback.
- Smart Connect state machine with budgets, cancellation, and observable attempts.
- Outbound HTTP/SOCKS proxy; Shadowsocks via `sslocal`; auth.
- Transport test UI ("test this bridge") and diagnostics.

Exit criteria:

- A matrix of {obfs4, Snowflake, WebTunnel, meek, DNSTT, custom} × {macOS, Windows, Linux} connects in a controlled test network.
- Smart Connect falls through each step within budget and reports why.
- PT sidecars never survive daemon exit; no orphans after force-kill tests.
- Moat failure falls back to built-in bridges without blocking the UI.

### M4 — Desktop integration and polish (4 weeks)

**Goal:** make tobro feel like a native desktop app.

Deliverables:

- Autostart (LaunchAgent/Run key/systemd user unit) with start-minimized option.
- Tray menu: status, connect/stop, new identity, open window, quit.
- Global shortcut (configurable; default off).
- Native notifications for state changes and errors (rate-limited).
- App lock: OS auth + password fallback; lock on idle/close (configurable).
- Best-effort window capture protection with an honest explanation.
- First-run onboarding: proxy explanation, bridge choice, autostart, diagnostics opt-in.
- Settings polish, About, help links, theme (light/dark/system), keyboard navigation.
- System proxy adapters (start): macOS snapshot/apply/restore, Windows registry, Linux gsettings/KDE.

Exit criteria:

- Autostart and tray behavior verified on all OSes, including reboot/login.
- System proxy applies and restores cleanly; a daemon crash restores the snapshot.
- UI passes keyboard-only and screen-reader smoke tests.
- App lock cannot be bypassed by opening a second window or the CLI (CLI respects lock).

### M5 — Onion services (5 weeks)

**Goal:** full v3 onion-service hosting and client authorization.

Deliverables:

- Onion service model, key storage, create/edit/delete, enable/disable.
- Port mapping UI and validation.
- Arti onion-service launch/publish integration; status and errors.
- Client authorization: generate/import/export `.auth_private`; attach to services.
- Backup/restore encrypted bundle; warning copy.
- Copy address, QR code, open-in-browser guidance.
- Tests: publish reachable service, authorized vs unauthorized client, restart persistence, key loss handling.

Exit criteria:

- A service created in tobro is reachable from Tor Browser.
- Client auth blocks unauthorized clients and admits authorized ones.
- Keys survive restart, upgrade, and backup/restore.
- No private key appears in logs, diagnostics, or the GUI's DOM beyond explicit export.

### M6 — Kindness Mode and headless CLI (4 weeks)

**Goal:** Snowflake proxy parity and automation.

Deliverables:

- `snowflake-proxy` sidecar supervisor; start/stop; crash backoff.
- NAT type detection (STUN), UPnP mapping, eligibility test with actionable errors.
- Limits: metered/charging (best effort), optional connection/bandwidth caps.
- Stats: current connections, weekly/total served; local DB; reset.
- Regional policy file and warnings.
- `tobroctl`: status, start, stop, new-identity, config get/apply, logs, onion list, diagnostics export; JSON output.
- Headless daemon mode (no GUI) and docs.

Exit criteria:

- Snowflake proxy serves a connection in a real network test; stats update.
- Disabling Kindness stops the sidecar and closes UPnP mappings.
- `tobroctl` can fully operate a headless daemon; exit codes and JSON are documented.

### M7 — TUN mode, split tunneling, and diagnostics (6 weeks, post-1.0 candidate)

**Goal:** optional system-wide routing without leaks.

Deliverables:

- Privileged helper per OS with a minimal, audited protocol.
- TUN device creation, route/DNS configuration, teardown.
- `tun2proxy` integration; TCP forwarding; DNS interception; UDP policy.
- Split tunneling by destination CIDR/domain; UI and validation.
- Kill switch with fail-closed behavior and a persistent journal for crash recovery.
- Leak test suite: DNS, IPv6, QUIC/UDP, route changes, sleep/wake, helper crash.
- Installer/uninstaller integration and privilege prompts.

Exit criteria:

- All TCP traffic routes through Tor in TUN mode; DNS leaks are zero in the test suite.
- Killing the daemon/helper restores networking or blocks it per the chosen policy.
- Helper passes a security review; no arbitrary command execution surface.
- Uninstall removes the helper, routes, and DNS settings.

### M8 — Hardening, packaging, and 1.0 release (5 weeks)

**Goal:** shippable, signed, reproducible release.

Deliverables:

- Reproducible builds (`--locked`, pinned toolchains, deterministic bundling where possible).
- macOS: universal2 DMG, hardened runtime, notarization, stapling.
- Windows: MSI/NSIS, Authenticode, SmartScreen guidance.
- Linux: deb/rpm/AppImage; Flathub submission (with sandbox caveats documented).
- Signed updater manifest, staged rollout, rollback, minimum-version policy.
- SBOM, license audit, `cargo deny`/`cargo vet`, dependency review.
- External security review; fix critical/high findings.
- Performance tuning to budgets; accessibility audit; localization freeze.
- User docs, FAQ, troubleshooting, privacy policy, security disclosure policy.
- Release checklist and rollback drill.

Exit criteria:

- Signed installers pass clean-VM install/upgrade/uninstall tests on all OSes.
- Updater verifies signatures and refuses tampered manifests.
- External audit has no open critical/high issues.
- Release checklist signed off by engineering, security, and product.

### M9 — 1.0 maintenance and 1.x (ongoing)

- Monthly Arti/bridge/PT updates; quarterly dependency refresh.
- Crash/error triage; telemetry-free feedback via issue templates and diagnostics exports.
- CVE response with a 7-day critical patch target.
- Onion-service and Kindness reliability improvements.
- Evaluate Arti RPC as a stable control surface; adopt first-class new identity if added.
- Revisit deferred items (padding, reachable addresses, strict node lists, SQS).
- Plan 1.x features: TUN GA, Flatpak hardening, browser-profile helper, vanity addresses.

### 7.1 Timeline summary

| Milestone | Duration | Cumulative | Key dependency |
|---|---:|---:|---|
| M0 | 2 wk | 2 wk | — |
| M1 | 4 wk | 6 wk | M0 |
| M2 | 4 wk | 10 wk | M1 |
| M3 | 6 wk | 16 wk | M1, M2 |
| M4 | 4 wk | 20 wk | M1 |
| M5 | 5 wk | 25 wk | M1, M2 |
| M6 | 4 wk | 29 wk | M3 |
| M7 | 6 wk | 35 wk | M1, M4 |
| M8 | 5 wk | 40 wk | M2–M7 |
| M9 | ongoing | — | M8 |

With 2–3 engineers and normal review/QA overhead, expect **10–12 calendar months** to a signed 1.0. A 1.0 without TUN (M7) is achievable in **8–9 months**; TUN can ship as 1.1.

### 7.2 Critical path

`M0 → M1 → M3 (PTs) → M8` is the critical path. M2, M4, M5, and M6 can run partly in parallel if staffing allows, but M3 is the schedule risk: cross-platform PT packaging and censorship testing are consistently underestimated.

---

## 8. Achievements, release gates, and KPIs

### 8.1 Achievement ladder

| Achievement | Gate | Proof |
|---|---|---|
| **First Light** | M1 | Connect, bootstrap, SOCKS request through Tor, 24 h soak |
| **Power User** | M2 | Ports, exit country, isolation, IPv6, new identity, log export |
| **Censorship Resistant** | M3 | Five transports + Smart Connect + Moat on three OSes |
| **Desktop Native** | M4 | Autostart, tray, notifications, app lock, system proxy |
| **Onion Host** | M5 | Reachable v3 service + client auth + backup/restore |
| **Kindness** | M6 | Snowflake proxy serves traffic with limits and stats |
| **Invisible** | M7 | TUN mode with zero DNS/IPv6 leaks and fail-closed kill switch |
| **1.0** | M8 | Signed, notarized, reproducible, audited, localized |

### 8.2 Release gates (all must pass)

1. **Functional:** all Full/Adapted features in the 1.0 scope pass their acceptance tests.
2. **Security:** external audit has no open critical/high findings; threat model reviewed.
3. **Privacy:** no telemetry; redaction tests pass; diagnostics export reviewed.
4. **Quality:** crash-free sessions ≥ 99.5% in beta; no P1 bugs open.
5. **Performance:** budgets in §13 met on baseline hardware.
6. **Accessibility:** WCAG 2.2 AA audit passed for primary flows.
7. **Localization:** top 10 locales ≥ 95% translated; no truncation in screenshots.
8. **Packaging:** clean install/upgrade/uninstall on all supported OSes; signatures verified.
9. **Docs:** user guide, troubleshooting, privacy policy, security policy published.
10. **Rollback:** a signed previous release can be restored without data loss.

### 8.3 KPIs

| KPI | Target | Measurement |
|---|---|---|
| Direct bootstrap success (broadband) | ≥ 98% | Local diagnostics, opt-in aggregate only |
| Time to connect, p50 / p95 | ≤ 10 s / ≤ 25 s | Daemon metrics, local only |
| Smart Connect success under simulated blocking | ≥ 90% | Test network matrix |
| Crash-free sessions | ≥ 99.5% | Local crash counter, user-shared reports |
| Idle memory (daemon + GUI) | ≤ 180 MB total | CI benchmark |
| Idle CPU | ≤ 2% average | CI benchmark |
| Throughput vs C Tor | ≥ 80% | Benchmark on same host/network |
| Installer size (per platform) | ≤ 60 MB | Release artifact |
| Log secret-leak tests | 0 failures | Automated redaction suite |
| Accessibility | WCAG 2.2 AA | Audit + automated checks |
| Translation coverage (top 10 locales) | ≥ 95% | Weblate |
| Critical CVE patch time | ≤ 7 days | Release records |

### 8.4 Definition of Done (per feature)

- Acceptance criteria written and reviewed.
- Unit + integration tests; failure paths covered.
- Works on macOS, Windows, and Linux (or explicitly platform-scoped).
- Strings externalized; accessibility checked.
- Logs redacted; no secrets in config/DB.
- Docs updated (user + troubleshooting).
- Performance impact measured.
- Security review for anything touching keys, IPC, privileges, or updates.
- Feature flag/rollback path if risky.
- Changelog entry.

---

## 9. Testing strategy

### 9.1 Test pyramid

| Level | Scope | Tools |
|---|---|---|
| Unit | Config schema/validation, bridge parser, state machine, port policy, redaction, key formatting, stats parsing | `cargo test`, `proptest`, `insta` snapshots |
| Component | IPC server/client, PT supervisor with fake binaries, onion service model, system proxy adapters with fakes | `tokio::test`, `tempfile`, mock scripts |
| Integration | Arti bootstrap on a test network, SOCKS/HTTP/DNS end-to-end, onion publish/auth, Moat with a mock server | `arti-testing`/Chutney where practical, `wiremock` |
| E2E | GUI flows, tray, onboarding, settings, logs, onboarding | Tauri WebDriver (`tauri-driver`) on Linux/Windows; Playwright for web UI; manual macOS |
| Network | Censorship simulation, fallback, timeouts, packet loss, DNS failure | `toxiproxy`, `tc`/`netem`, firewall rules, local PT stubs |
| Leak/security | DNS, IPv6, WebRTC (browser guidance), kill switch, IPC auth, privilege boundary | Custom harness + `tcpdump`/Wireshark, `cargo audit`/`deny`/`vet`, fuzzing |
| Performance | Bootstrap, throughput, CPU/memory, startup, sidecar overhead | `criterion`, OS profilers, CI benchmarks |
| Packaging | Install/upgrade/uninstall, signatures, updater tamper tests, permissions | Clean VMs/containers, `codesign`/`signtool` verification |

### 9.2 Test environments

- **CI matrix:** macOS 14/15 (arm64 + x86_64), Windows 11 (x64 + arm64 where feasible), Ubuntu 24.04, Fedora 40, Arch container.
- **Network simulation:** a Linux VM with `tc netem`, `iptables`/`nftables`, and a controllable DNS server; test direct, blocked, and PT-only scenarios.
- **Real-network smoke:** a small manual matrix in at least two countries/network types before release, including a censored network if safely possible.
- **Tor test network:** use Arti's testing facilities/Chutney for deterministic bootstrap; do not depend on the public Tor network for unit tests.
- **Time control:** `tokio::time::pause` for timeouts/backoff; fake clocks for stats windows.

### 9.3 Security testing

- Fuzz: bridge-line parser, JSON-RPC parser, config deserializer, `.auth_private` importer, onion bundle importer.
- Static: `cargo clippy` (deny warnings), `cargo audit`, `cargo deny`, `cargo vet`, secret scanning, SAST in CI.
- Dynamic: IPC peer-credential bypass attempts, symlink attacks on key paths, TOCTOU on config writes, malicious sidecar replacement, updater manifest tampering.
- Privilege: helper protocol fuzzing, argument injection, route/DNS validation, uninstall cleanup.
- Privacy: log scanning for bridge lines/keys, diagnostics export inspection, clipboard behavior.
- External audit before 1.0, focused on IPC, key storage, privileged helper, and update chain.

### 9.4 Release testing

- Clean install → connect → upgrade → connect → uninstall on each OS.
- Downgrade/rollback with existing config/DB.
- Multi-user machine: permissions, per-user daemon, no cross-user socket access.
- Sleep/wake, network switch (Wi-Fi ↔ Ethernet), VPN coexistence, captive portals.
- Long-haul: 72-hour soak with periodic new identity and onion service churn.
- Accessibility: keyboard-only, screen reader (VoiceOver/NVDA/Orca), 200% zoom, high contrast.
- Localization: pseudo-locale, RTL (Arabic/Hebrew), long strings (German), CJK.

---

## 10. Security and privacy

### 10.1 Threat model

| Adversary | Capability | Mitigation |
|---|---|---|
| Network observer / ISP | Block or fingerprint Tor; observe DNS | Bridges/PTs, no plaintext DNS, pluggable transports, traffic padding where supported |
| Censor | Block directory authorities, Moat, PTs | Built-in bridges, Moat fallback, multiple transports, signed bridge updates |
| Local unprivileged attacker | Read files, connect to localhost, inject IPC | `0700` dirs, `0600` files, keychain, socket permissions + peer creds, no TCP control port |
| Malicious local app | Abuse the proxy, read clipboard, screenshot | Loopback binding, optional app lock, clipboard hygiene, capture protection (best effort) |
| Physical attacker | Access disk/keys | OS full-disk encryption guidance, keychain, optional encrypted onion backups, no plaintext secrets |
| Malicious bridge/PT | Traffic manipulation, DoS | Tor's end-to-end crypto; signed PT binaries; bridge validation; timeouts/fallback |
| Compromised update | Arbitrary code | Signed manifests, signature verification, staged rollout, reproducible builds, SBOM |
| Malicious website | Browser fingerprinting, WebRTC leaks | Document that tobro is not a browser; recommend Tor Browser; TUN mode blocks non-Tor egress |
| Insider/build compromise | Supply-chain attack | Reproducible builds, dependency review, `cargo vet`, signed releases, limited CI credentials |

**Out of scope:** a compromised OS/kernel, a compromised Arti/Tor cryptographic primitive, global passive adversaries defeating Tor itself, and users who deliberately disable protections.

### 10.2 Privacy commitments

- **No telemetry, analytics, ads, or unique identifiers.**
- No automatic crash uploads; local reports are opt-in and user-reviewed.
- Bridge lines and onion client-auth keys are treated as sensitive.
- No network fingerprint stored by default (no Wi-Fi SSID history).
- Kindness Mode is opt-in and clearly explains what a Snowflake proxy observes.
- Diagnostics exports are redacted, previewable, and never auto-sent.
- Update checks disclose only the app version/platform, not usage; allow disabling update checks (with a security warning).

### 10.3 Key management

- Proxy/bridge credentials → OS keychain.
- Onion service keys → files `0600` in `0700` dirs; never in SQLite or logs.
- Client-auth keys → same; export only on explicit user action.
- Optional encrypted backup: Argon2id-derived key + AEAD (XChaCha20-Poly1305); passphrase never stored.
- Memory hygiene: `zeroize` for passwords and key material where feasible; avoid long-lived copies in the UI.
- Key rotation: restricted-discovery keys can be rotated via Arti APIs; UI warns that old clients lose access.

### 10.4 IPC and local attack surface

- No TCP control port by default.
- Socket directory `0700`; socket `0600`; peer credentials checked.
- Named pipe ACL restricted to the current user SID.
- Request size limits, schema validation, timeouts, and rate limits.
- Method allowlist; no generic "eval", shell, or file-read methods.
- CLI and GUI share the same authorization; app lock is enforced in the daemon, not just the UI.
- Any future localhost TCP API is opt-in, token-authenticated, and documented as a risk.

### 10.5 Privileged helper (TUN)

- Separate binary, minimal dependencies, no network listeners.
- Fixed command set; all inputs validated (IPs, prefixes, interface names).
- Authenticated local IPC; caller identity verified.
- No shell execution; no arbitrary route tables.
- Runs only while TUN mode is enabled; uninstall removes it.
- Logs to the system log with no packet contents.
- Independent security review before shipping.

### 10.6 Supply chain

- Pin Rust toolchain and dependencies (`Cargo.lock` committed).
- `cargo deny` for licenses/advisories; `cargo vet` for sensitive crates.
- SBOM (CycloneDX) per release.
- Sign sidecars and verify hashes at runtime before execution.
- Reproducible builds where platform tooling allows; publish build instructions and hashes.
- Limit release CI secrets; require review for workflow changes.

### 10.7 Legal and abuse

- tobro is a **client**, not an exit relay; no third-party traffic exits through the user.
- Kindness Mode relays encrypted Snowflake traffic; include the Tor Project's guidance and a clear opt-in.
- Export controls/cryptography: review distribution requirements per jurisdiction; Arti/Tor is widely distributed open source, but confirm with counsel.
- Trademark: "Tor" and "Orbot" are Tor Project/Guardian Project marks; choose branding that does not imply endorsement. Confirm naming before public release.

---

## 11. Packaging, signing, and updates

### 11.1 Platform targets

| OS | Minimum | Architectures | Formats | Notes |
|---|---|---|---|---|
| macOS | 13 Ventura | arm64, x86_64 (universal2) | DMG, zip | Hardened runtime, notarization, LaunchAgent, `SMAppService` helper for TUN |
| Windows | 10 22H2+ | x64, arm64 | MSI (WiX), NSIS | Authenticode, per-user install, named pipe; WebView2 runtime check |
| Linux | Ubuntu 22.04+, Fedora 40+, Arch | x86_64, aarch64 | deb, rpm, AppImage, Flatpak | WebKitGTK 4.1; systemd user unit; polkit helper for TUN |

### 11.2 Build and release pipeline

1. Tag `vX.Y.Z` on a protected branch.
2. CI builds all targets with `--locked` and pinned toolchain.
3. Tests + security scans + SBOM generation.
4. Sign binaries/sidecars; notarize macOS; sign Windows installers.
5. Generate the signed updater manifest (version, platform, URL, sha256, signature, minimum version, rollout %).
6. Publish to a staging channel; run smoke tests on clean VMs.
7. Promote to stable in stages (5% → 25% → 100%) with a kill switch.
8. Publish release notes, hashes, SBOM, and a rollback artifact.

### 11.3 Update strategy

- Tauri updater with Ed25519/minisign-style signatures; public key embedded in the app.
- Manifest fetched over HTTPS; signature verified before download and after.
- Delta updates where supported; full installer fallback.
- Never auto-update while Tor is connected without warning; offer "update and restart".
- Support the previous two minor releases with security fixes; enforce a minimum version only for critical vulnerabilities, with a clear message.
- Linux package managers may own updates; the in-app updater detects and defers to them.

### 11.4 Uninstall and cleanup

- Stop daemon, restore system proxy, remove routes/DNS, stop sidecars, remove helper.
- Offer "keep settings and onion keys" vs "remove everything"; default keep data, explicit wipe.
- Document where data lives and how to securely delete it (OS secure-erase caveats).
- No leftover launch agents/services after uninstall.

### 11.5 Distribution

- Primary: direct download from the project site (signed installers).
- macOS: notarized DMG; consider Homebrew Cask after 1.0.
- Windows: signed MSI; consider winget after 1.0.
- Linux: own apt/rpm repos or distro packages; Flathub after sandbox review; AppImage for portable use.
- Avoid unverified third-party mirrors; publish hashes and signatures.

---

## 12. Localization and accessibility

### 12.1 Localization

- i18next JSON resources; one namespace per feature area; no concatenated sentences.
- ICU-style pluralization and interpolation; avoid gendered/ambiguous strings.
- Locale detection: system → user override; persist choice.
- Weblate integration; translation memory; screenshot context for translators.
- RTL support (Arabic, Hebrew, Persian); logical CSS properties; icon mirroring where meaningful.
- Pseudo-localization in CI to catch truncation and hard-coded strings.
- Date/time/number formatting via `Intl`; avoid hard-coded formats.
- Do not translate technical identifiers (`obfs4`, `.onion`, bridge lines); provide translator notes.
- Target top 10 locales at 1.0; community locales welcome.

### 12.2 Accessibility

- WCAG 2.2 AA target: contrast, focus visible, keyboard operability, labels, error identification.
- Semantic HTML, ARIA only where needed; Radix primitives for dialogs/menus/tabs.
- Full keyboard navigation for connect, settings, onion services, logs.
- Screen-reader announcements for state changes (`aria-live` polite), not every log line.
- Respect `prefers-reduced-motion`, `prefers-color-scheme`, and high-contrast modes.
- Minimum 200% zoom without loss of function; no horizontal scrolling at 320 px width.
- Accessible names for icon-only buttons; visible focus rings; no color-only status.
- Test with VoiceOver (macOS), NVDA (Windows), Orca (Linux).

---

## 13. Performance and resource budgets

| Metric | Budget | Notes |
|---|---|---|
| Daemon idle memory | ≤ 100 MB RSS | Arti + listeners; grows with circuits |
| GUI idle memory | ≤ 120 MB RSS | WebView baseline varies by OS |
| Combined idle CPU | ≤ 2% average | Excluding bootstrap |
| Cold start to window | ≤ 2 s | Signed release build |
| Time to connect, p50 | ≤ 10 s | Broadband, direct |
| Time to connect, p95 | ≤ 25 s | Includes network variance |
| Bootstrap failure recovery | ≤ 3 attempts / 60 s | Then actionable error |
| Throughput | ≥ 80% of C Tor on same host | Single-stream and multi-stream |
| Onion service publish | ≤ 60 s after enable | Network-dependent |
| Log disk usage | ≤ 50 MB default cap | Rotating |
| Installer size | ≤ 60 MB per platform | Includes PT sidecars |
| Update download | ≤ 40 MB delta / ≤ 60 MB full | Platform-dependent |
| Shutdown | ≤ 5 s graceful / ≤ 10 s forced | Restores proxy snapshot |

Measurement: CI benchmarks on fixed runners for regressions; manual baseline on representative hardware (Apple silicon, mid-range x64 laptop, low-end Linux VM). Track p50/p95, not just averages.

---

## 14. Risks and mitigations

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Arti pre-1.0 API churn breaks the adapter | High | Medium | Pin versions; isolate in `tobro-tor`; upgrade monthly with full suite; contribute upstream |
| R2 | Arti lacks a needed C Tor feature (padding, node lists, NEWNYM) | High | Medium | Classify as Deferred/Adapted; hide unsupported UI; document gaps; revisit per release |
| R3 | Arti exits on obsolete consensus or unexpected error | Medium | High | Supervisor restarts with backoff; preserve desired state; surface cause; file upstream |
| R4 | PT sidecar packaging/signing across 3 OSes | High | High | Start in M0/M3; per-platform CI; checksum verification; fallback transports |
| R5 | Censorship testing is hard to reproduce | High | High | Build a netem/firewall lab; use real-network smoke tests; partner with censored users |
| R6 | Smart Connect behaves unpredictably | Medium | Medium | Explicit state machine, budgets, observable attempts, deterministic tests |
| R7 | System proxy is ignored by many apps | Certain | Medium | Clear copy; env vars; TUN mode post-1.0; app compatibility list |
| R8 | TUN helper privilege escalation | Medium | Critical | Minimal audited helper, fixed commands, external review, opt-in, fail-closed |
| R9 | DNS/IPv6/WebRTC leaks | Medium | High | Leak test suite; TUN DNS interception; document browser guidance; block IPv6 in TUN if not supported |
| R10 | macOS notarization/helper signing delays | Medium | Medium | Early signing setup in M0/M4; dedicated Apple account; CI secrets |
| R11 | Windows SmartScreen/AV false positives | Medium | Medium | EV/OV signing, reputation building, submit to Microsoft, clear installer |
| R12 | WebView inconsistencies (especially Linux) | Medium | Low | Conservative UI; test matrix; avoid cutting-edge APIs; fallbacks |
| R13 | Onion key loss or corruption | Low | High | Atomic writes, backups, export warnings, fs checks, recovery docs |
| R14 | Kindness Mode abuse/legal concerns | Low | Medium | Opt-in, limits, regional policy, Tor Project guidance, no exit traffic |
| R15 | Update chain compromise | Low | Critical | Signed manifests, reproducible builds, staged rollout, key rotation plan |
| R16 | Scope creep (relay, mobile, browser) | High | Medium | Explicit non-goals; change control; milestone gates |
| R17 | Localization/accessibility regressions | Medium | Low | CI checks, pseudo-locale, audits, translator context |
| R18 | Performance regression vs C Tor | Medium | Medium | Benchmark in CI; profile; tune Arti config; accept and document gaps |
| R19 | User confusion about "connected" vs "protected" | High | Medium | Distinct states, onboarding, system-routing indicator, honest copy |
| R20 | Single maintainer/bus factor | Medium | High | Documentation, ADRs, CI, release automation, upstream relationships |

### 14.1 Go/no-go triggers

- If Arti cannot reliably bootstrap on two or more target OSes by end of M1, pause feature work and resolve upstream or reconsider the engine.
- If PT sidecars cannot be signed/notarized by M3, ship 1.0 with a reduced transport set and a clear roadmap.
- If TUN helper security review fails, ship 1.0 without TUN (proxy mode only).
- If the external audit finds an unfixable critical issue, delay 1.0 rather than ship.

---

## 15. Open questions

1. **Daemon lifecycle:** should `tobrod` always run, or start on demand from the GUI? (Recommendation: always-on per-user agent once installed, with an idle-exit option.)
2. **Default ports:** keep Orbot's `9050/8118/9053`, or adopt Arti's `9150` convention? (Recommendation: `9050/8118/9053` for compatibility; document conflicts.)
3. **Exit-country scope:** apply globally via default `StreamPrefs`, or per-app/profile? (Recommendation: global default + per-profile override later.)
4. **Stream isolation implementation:** rely on Arti's SOCKS/isolation groups, or build a thin SOCKS front-end for full Orbot semantics? (Recommendation: Arti first; front-end only if tests show gaps.)
5. **TUN in 1.0?** (Recommendation: 1.1; keep 1.0 proxy-mode only.)
6. **Snowflake proxy packaging:** bundle `snowflake-proxy` or build from source per platform? (Recommendation: bundle signed upstream binaries, verify hashes.)
7. **Onion key encryption:** rely on OS permissions/keychain, or encrypt keys at rest with a passphrase? (Recommendation: OS permissions + optional encrypted backup; avoid a second password prompt by default.)
8. **Linux packaging priority:** deb/rpm vs Flatpak vs AppImage? (Recommendation: deb/rpm/AppImage at 1.0; Flathub after sandbox review.)
9. **App lock semantics:** OS auth only, or app password + OS auth? (Recommendation: OS auth preferred, password fallback.)
10. **Update checks:** enabled by default with a privacy notice, or opt-in? (Recommendation: enabled by default, no identifiers, disableable.)
11. **Naming/branding:** does "tobro" conflict with existing marks? (Action: trademark search before public beta.)
12. **Arti upgrade cadence:** monthly minor upgrades vs quarterly? (Recommendation: monthly security patches, quarterly feature upgrades.)
13. **Headless support:** is `tobrod` on a server (no GUI) a supported 1.0 scenario? (Recommendation: yes, best-effort, documented.)
14. **Diagnostics:** local-only export, or optional user-initiated upload to a project endpoint? (Recommendation: local-only at 1.0.)

---

## 16. Decision log

| Date | Decision | Rationale | Status |
|---|---|---|---|
| 2026-11-07 | Desktop only; no mobile | Explicit product mandate; mobile parity would double scope | Accepted |
| 2026-11-07 | Embed Arti, not C Tor | Rust-native, memory-safe, strategic upstream, no control-port bridge | Accepted |
| 2026-11-07 | Tauri 2 + React 19 + TypeScript | Small binaries, native WebView, strong Rust integration, fast UI development | Accepted |
| 2026-11-07 | Separate `tobrod` daemon + thin GUI | Background operation, CLI, crash isolation, privileged-helper boundary | Accepted |
| 2026-11-07 | JSON-RPC over UDS/named pipe | Local-only, debuggable, no TCP exposure, easy CLI | Accepted |
| 2026-11-07 | TOML config + SQLite + OS keychain | Human-readable config, structured state, no plaintext secrets | Accepted |
| 2026-11-07 | Arti built-in SOCKS/HTTP/DNS | Avoid reimplementing Tor; fewer bugs | Accepted |
| 2026-11-07 | lyrebird + snowflake-client + dnstt-client sidecars | Reuse maintained PT implementations; cover Orbot transports | Accepted |
| 2026-11-07 | Proxy mode for 1.0; TUN post-1.0 | Privileged routing is the highest-risk subsystem; ship value sooner | Accepted |
| 2026-11-07 | New identity = client restart | Only viable Arti-compatible approach today; labelled honestly | Accepted |
| 2026-11-07 | Hide unsupported C Tor knobs | Honest UX; avoids silent no-ops | Accepted |
| 2026-11-07 | No telemetry | Privacy-first product principle | Accepted |
| 2026-11-07 | WCAG 2.2 AA + top-10 locales at 1.0 | Accessibility and reach are release criteria | Accepted |
| 2026-11-07 | GPL-3.0-only license | Chosen by project owner; copyleft, matches Orbot's licensing | Accepted |

---

## 17. Appendices

### Appendix A — Orbot → tobro configuration mapping

| Orbot preference | tobro config | Notes |
|---|---|---|
| `pref_socks` | `proxy.socks_port` | Default 9050; conflict detection |
| `pref_http` | `proxy.http_port` | Default 8118 |
| `pref_dnsport` | `proxy.dns_port` | Default 9053 |
| `pref_open_proxy_on_all_interfaces` | `proxy.bind_all_interfaces` | Opt-in + warning |
| `pref_start_boot` | `general.start_on_login` | LaunchAgent/Run key/systemd |
| `pref_power_user` | `general.power_user` | Gates advanced UI |
| `pref_transport` / `pref_connection_pathway` | `bridges.transport` | direct/obfs4/snowflake/webtunnel/meek/dnstt/custom |
| `pref_use_smart_connect` | `bridges.smart_connect` | State machine |
| `pref_smart_connect_timeout` | `bridges.smart_connect_timeout_secs` | Default 30 |
| `pref_bridge_country` | `bridges.country` | Moat/built-in filter |
| `pref_exit_nodes` | `network.exit_country` | Country code via `StreamPrefs` |
| `pref_entrance_nodes` | advanced | Only if Arti exposes; otherwise hidden |
| `pref_exclude_nodes` | advanced | Only if Arti exposes; otherwise hidden |
| `pref_strict_nodes` | advanced | Only if Arti exposes; otherwise hidden |
| `pref_reachable_addresses` | — | Deferred (Arti gap) |
| `pref_isolate_dest/port/protocol/keep_alive` | `stream.*` | Arti isolation groups / SOCKS front-end |
| `pref_prefer_ipv6` / `pref_disable_ipv4` | `network.ipv6` | prefer / only / disable |
| `pref_connection_padding` | — | Deferred (Arti gap) |
| `pref_reduced_connection_padding` | — | Deferred |
| `pref_circuit_padding` | — | Deferred |
| `pref_reduced_circuit_padding` | — | Deferred |
| `pref_proxy_type/host/port/username/password` | `proxy.outbound.*` | Keychain for password |
| `pref_proxy_ss` | `proxy.outbound.shadowsocks` | `sslocal` sidecar |
| `pref_custom_torrc` | — | No raw torrc; typed advanced config |
| `pref_enable_logging` | `advanced.log_level` | debug/trace |
| `pref_default_locale` | `general.language` | i18next |
| `pref_require_password` / `pref_auth_no_biometrics` | `ui.app_lock` | OS auth + password |
| `pref_flag_secure` | `ui.capture_protection` | Best effort |
| `pref_be_a_snowflake` | `kindness.enabled` | Snowflake proxy |
| `pref_be_a_snowflake_limit_wifi` | `kindness.limit_metered_network` | Adapted |
| `pref_be_a_snowflake_limit_charging` | `kindness.limit_charging_only` | Adapted |
| `pref_snowflake_upnp_ports` | `kindness.upnp` | Port mapping |
| `pref_show_snowflake_proxy_msg` | `kindness.show_explainer` | Onboarding |

### Appendix B — Arti API notes and caveats

- **Version:** `arti-client` 0.48.0, Arti 2.8.0, MSRV 1.92. Pin exactly; Arti is pre-1.0.
- **Bootstrap:** `TorClient::create_bootstrapped` blocks until usable; for UI, create unbootstrapped, subscribe to `bootstrap_events`, and call `bootstrap()`. `bootstrap_status()` gives a snapshot.
- **Reconfigure:** `reconfigure(new_config, Reconfigure::AllOrNothing)`; some fields are not hot-reconfigurable and some changes affect only future streams/circuits.
- **Default prefs:** `TorClient::with_prefs` returns a handle with default `StreamPrefs`; use it to apply IPv6 and exit-country defaults to all streams on that handle. Verify SOCKS listener behavior in M2.
- **Isolation:** `StreamPrefs::isolate_every_stream`, `new_isolation_group`, `set_isolation`; `isolated_client()` for unlinkable handles.
- **New identity:** no `NEWNYM`; dispose/recreate the client. Document that guard state may persist.
- **Onion services:** `create_onion_service`, `launch_onion_service`, `launch_onion_service_with_hsid`; restricted discovery via `generate_service_discovery_key`/`insert_service_discovery_key`/`rotate_service_discovery_key`; `KeyMgr` for client keys. APIs are evolving; wrap them.
- **Bridges/PTs:** `BridgesConfig` (bridges, enabled, transports) and `pt-client`; `TransportConfig` describes the sidecar command/args. Verify the exact PT manager API on 0.48 during M0.
- **Outbound proxy:** `ChannelConfig::outbound_proxy` exposes `ProxyProtocol`; confirm supported schemes (HTTP CONNECT/SOCKS) and auth in M3. Shadowsocks via a local SOCKS5 sidecar.
- **DNS:** Arti's DNS proxy supports UDP and TCP; use it for `.onion` and optional DNS routing. Do not claim system-wide DNS protection in proxy mode.
- **Failure mode:** Arti may call `exit(1)` on an obsolete consensus; the daemon must supervise and restart, not assume a clean error.
- **RPC:** `arti-rpcserver` exists but is not a C Tor control port; do not build compatibility shims that imply `GETINFO`/`SIGNAL` support.
- **Relay:** not supported for 1.0; do not expose relay settings.

### Appendix C — Orbot feature source references

| Feature | Source |
|---|---|
| Service lifecycle, ports, new identity | `service/OrbotService.java` |
| Torrc generation | `service/tor/TorConfig.kt` |
| Transports/bridges | `service/circumvention/Transport.kt`, `Bridge.kt`, `BuiltInBridges.kt` |
| Moat auto-config | `service/circumvention/AutoConf.kt` |
| Smart Connect | `service/circumvention/SmartConnect.kt` |
| Preferences/defaults | `util/Prefs.kt` |
| Settings UI | `res/xml/preferences.xml`, `res/xml/safety_prefs.xml` |
| Onion services | `service/db/OnionServiceColumns.kt` |
| Client auth | `service/db/V3ClientAuthColumns.kt` |
| Kindness Mode | `ui/kindness/*`, `ui/kindness/SnowflakeProxyService` |
| Manifest/platform | `app/src/main/AndroidManifest.xml` |
| Recent behavior | `docs/info/CHANGELOG.txt` |
| Build/versions | `app/build.gradle.kts` |

### Appendix D — Glossary

| Term | Definition |
|---|---|
| **Arti** | The Tor Project's Rust implementation of Tor |
| **Bridge** | An unlisted Tor relay used to reach the network when direct connections are blocked |
| **Client authorization** | Restricted discovery: only clients with a private key can connect to an onion service |
| **DNSTT** | A pluggable transport that tunnels through DNS |
| **Moat** | Tor Project's bridge-distribution API |
| **obfs4** | A pluggable transport that makes traffic look random |
| **Onion service** | A service reachable only through the Tor network via a `.onion` address |
| **Pluggable transport (PT)** | A program that transforms Tor traffic to evade blocking |
| **Smart Connect** | Orbot's automatic fallback across connection methods |
| **Snowflake** | A pluggable transport using WebRTC and volunteer proxies |
| **Stream isolation** | Keeping unrelated connections on separate Tor circuits |
| **TUN** | A virtual network interface that captures IP traffic |
| **WebTunnel** | A pluggable transport that looks like HTTPS website traffic |

### Appendix E — Reference links

- Arti repository: <https://gitlab.torproject.org/tpo/core/arti>
- Arti documentation: <https://docs.rs/arti-client>
- Tor Project pluggable transports: <https://support.torproject.org/circumvention/>
- Orbot: <https://orbot.app/>
- Tauri: <https://tauri.app/>
- Snowflake: <https://snowflake.torproject.org/>
- Tor Browser (recommended browsing companion): <https://www.torproject.org/download/>

---

*This document is a plan, not an implementation. It should be revised as Arti evolves and as M0/M1 findings come in. The decision log and open questions are the living parts; update them rather than silently changing scope.*
