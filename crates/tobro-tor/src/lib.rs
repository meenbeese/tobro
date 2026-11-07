//! Arti integration boundary.
//!
//! M0 scaffold: `TorClient` construction, bootstrap events, proxy listeners,
//! and configuration mapping live here next.

/// Crate version from `Cargo.toml`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
