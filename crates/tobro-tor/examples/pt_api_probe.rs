//! M0 deliverable: verify the pluggable-transport manager API on
//! `arti-client 0.48` (TOBRO_PLAN Appendix B / risk R4).
//!
//! Compiles and exercises the exact API surface M3's bridge support
//! will use, without networking:
//!
//! 1. C Tor-style `Bridge ...` lines parse via `BridgeConfigBuilder`.
//! 2. Hand-built bridges: `transport()`, `push_setting()`,
//!    `set_addrs()`, `set_ids()`.
//! 3. Transports: `config::pt::TransportConfigBuilder` with
//!    `protocols()`, `path()`, `run_on_startup()`.
//! 4. A bridge naming a transport that has no matching
//!    `TransportConfig` is rejected at `TorClientConfig` build time.
//! 5. A config without any bridges still builds.
//!
//! Run with `cargo run -p tobro-tor --features pt-client --example
//! pt_api_probe`.

#[cfg(feature = "pt-client")]
fn main() -> anyhow::Result<()> {
    use arti_client::TorClientConfig;
    use arti_client::config::pt::TransportConfigBuilder;
    use arti_client::config::{BridgeConfigBuilder, CfgPath};

    // Real-shaped lines from the Tor Project bridge lists.
    const OBFS4_LINE: &str = "Bridge obfs4 192.0.2.55:38114 \
316E643333645F6D79216558614D3931657A5F5F \
cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg \
iat-mode=0";
    const SNOWFLAKE_LINE: &str = "Bridge snowflake 192.0.2.3:80 \
2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
url=https://snowflake-broker.torproject.net.global.prod.fastly.net \
front=cdn.sstatic.net \
ice=stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn";

    // 1. Both lines parse as bridges, like Orbot's imported bridge lines.
    let obfs4_bridge: BridgeConfigBuilder = OBFS4_LINE.parse()?;
    let snowflake_bridge: BridgeConfigBuilder = SNOWFLAKE_LINE.parse()?;
    println!("1. C Tor bridge lines parse via BridgeConfigBuilder ✓");

    // 2. A bridge built by hand with settings, address, and identity.
    let mut hand_built = BridgeConfigBuilder::default();
    hand_built
        .transport("snowflake")
        .push_setting("url", "https://snowflake-broker.torproject.net/")
        .push_setting("front", "www.google.com");
    hand_built.set_addrs(vec!["192.0.2.4:80".parse()?]);
    hand_built.set_ids(vec!["8838024498816A039FCBBAB14E6F40A0843051FA".parse()?]);
    println!("2. Hand-built bridge: transport/settings/addrs/ids ✓");

    // 3. Transport configs naming the client binary arti will spawn.
    let mut obfs4_transport = TransportConfigBuilder::default();
    obfs4_transport
        .protocols(vec!["obfs4".parse()?])
        .path(CfgPath::new("obfs4proxy".into()))
        .run_on_startup(false);
    let mut snowflake_transport = TransportConfigBuilder::default();
    snowflake_transport
        .protocols(vec!["snowflake".parse()?])
        .path(CfgPath::new("snowflake-client".into()))
        .run_on_startup(true);
    println!("3. TransportConfig: protocols/path/run_on_startup ✓");

    // 4. Both bridges with matching transports: the config builds.
    {
        let mut builder = TorClientConfig::builder();
        builder.bridges().bridges().push(obfs4_bridge.clone());
        builder.bridges().bridges().push(snowflake_bridge.clone());
        builder.bridges().bridges().push(hand_built);
        builder.bridges().transports().push(obfs4_transport.clone());
        builder.bridges().transports().push(snowflake_transport);
        let _ = builder.build()?;
        println!("4. Bridges with matching transports build a config ✓");
    }

    // 5. A configured bridge without its transport is rejected.
    {
        let mut builder = TorClientConfig::builder();
        builder.bridges().bridges().push(snowflake_bridge.clone());
        // Obfs4 transport only; the snowflake bridge is orphaned.
        builder.bridges().transports().push(obfs4_transport);
        match builder.build() {
            Err(error) => println!("5. Orphaned bridge rejected at config build ✓ ({error:?})"),
            Ok(_) => anyhow::bail!("orphaned bridge unexpectedly accepted"),
        }
    }

    // 6. No bridges: the default config builds untouched.
    {
        let builder = TorClientConfig::builder();
        let _ = builder.build()?;
        println!("6. Default config without bridges builds ✓");
    }

    println!("pt manager API probe: all checks passed on arti-client 0.48");
    Ok(())
}

#[cfg(not(feature = "pt-client"))]
fn main() {
    eprintln!("this probe needs --features pt-client");
    std::process::exit(1);
}
