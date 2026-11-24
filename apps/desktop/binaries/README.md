Tauri `externalBin` sidecars and driver assets for packaged releases.

`beforeBuildCommand` / CI should place both sidecars here (run
`scripts/prepare-tobrod-sidecar.sh` and `scripts/prepare-tobro-helper-sidecar.sh`):

- `tobrod-<target-triple>` (macOS/Linux), `tobrod-<target-triple>.exe` (Windows)
- `tobro-helper-<target-triple>` (macOS/Linux), `tobro-helper-<target-triple>.exe` (Windows)

Example:
  cargo build -p tobrod --release --target aarch64-apple-darwin
  cp ../../target/aarch64-apple-darwin/release/tobrod binaries/tobrod-aarch64-apple-darwin

The desktop app also resolves `tobrod` and `tobro-helper` next to the main
executable at runtime, which covers bundles where the sidecars are placed in
the same directory.

Windows additionally needs `wintun.dll` next to `tobro-helper.exe`:

- `binaries/wintun.dll` is bundled by `tauri.wintun.conf.json` as a resource
  (pass it to `tauri build` with `--config`, alongside
  `tauri.sidecar.conf.json`) and lands next to the sidecars in the install
  directory.
- `tobro-install` copies it next to the installed helper
  (`%ProgramFiles%\Tobro\helper\wintun.dll`), because the privileged helper
  lives outside the app install directory.
- Fetch it from <https://www.wintun.net/> and stage it with
  `scripts/prepare-tobro-helper-sidecar.sh --wintun <path> --wintun-sha256 <hex>`
  so release builds pin the binary.
