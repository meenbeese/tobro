Tauri `externalBin` sidecars for packaged releases.

`beforeBuildCommand` / CI should place `tobrod` here as:
- `tobrod-<target-triple>` (macOS/Linux)
- `tobrod-<target-triple>.exe` (Windows)

Example:
  cargo build -p tobrod --release --target aarch64-apple-darwin
  cp ../../target/aarch64-apple-darwin/release/tobrod binaries/tobrod-aarch64-apple-darwin

The desktop app also resolves `tobrod` next to the main executable at runtime,
which covers bundles where the sidecar is placed in the same directory.
