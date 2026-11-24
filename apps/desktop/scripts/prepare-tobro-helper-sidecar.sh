#!/usr/bin/env bash
set -euo pipefail

# Prepare tobro-helper as a Tauri externalBin sidecar for the current/target
# build, together with the Windows wintun driver (`wintun.dll`) that has to sit
# next to the helper binary.
#
# Usage: prepare-tobro-helper-sidecar.sh [--profile debug|release] [--target <triple>]
#                                        [--wintun <path>] [--wintun-sha256 <hex>]
#
# On Windows targets a `wintun.dll` is required. Provide it with --wintun,
# $TOBRO_WINTUN_DLL, or by placing it at apps/desktop/binaries/wintun.dll
# (download: https://www.wintun.net/). When --wintun-sha256 or
# $TOBRO_WINTUN_SHA256 is set, the staged file is verified against that pin.

profile="release"
target="${TAURI_ENV_TARGET_TRIPLE:-${TAURI_ENV_TARGET:-}}"
wintun_src="${TOBRO_WINTUN_DLL:-}"
wintun_sha256="${TOBRO_WINTUN_SHA256:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) profile="$2"; shift 2 ;;
    --target) target="$2"; shift 2 ;;
    --wintun) wintun_src="$2"; shift 2 ;;
    --wintun-sha256) wintun_sha256="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
desktop_dir="$(cd "$script_dir/.." && pwd)"
repo_root="$(cd "$desktop_dir/../.." && pwd)"
binaries_dir="$desktop_dir/binaries"
mkdir -p "$binaries_dir"

if [[ -z "$target" ]]; then
  target="$(rustc -vV | sed -n 's/^host: //p')"
fi

cargo_args=(build -p tobro-helper --manifest-path "$repo_root/Cargo.toml")
if [[ "$profile" == "release" ]]; then
  cargo_args+=(--release)
fi
if [[ -n "$target" ]]; then
  cargo_args+=(--target "$target")
fi

echo "Preparing tobro-helper sidecar: profile=$profile target=$target" >&2
cargo "${cargo_args[@]}"

exe_suffix=""
src_dir="$repo_root/target"
if [[ -n "$target" ]]; then
  src_dir="$src_dir/$target"
fi
src_dir="$src_dir/$profile/tobro-helper"
if [[ "$target" == *windows* ]]; then
  exe_suffix=".exe"
  src_dir="${src_dir}.exe"
fi

dest="$binaries_dir/tobro-helper-$target$exe_suffix"
if [[ ! -f "$src_dir" ]]; then
  echo "tobro-helper binary not found at $src_dir" >&2
  exit 1
fi
cp "$src_dir" "$dest"
chmod +x "$dest" || true
echo "Prepared $dest" >&2

if [[ "$target" != *windows* ]]; then
  exit 0
fi

# Windows: stage wintun.dll next to the helper. The Tauri resource mapping in
# tauri.wintun.conf.json copies it next to the bundled sidecar; the installer
# (tobro-install) copies it into the privileged helper directory, which is a
# different directory from the app bundle.
wintun_dest="$binaries_dir/wintun.dll"
if [[ -z "$wintun_src" && -f "$wintun_dest" ]]; then
  wintun_src="$wintun_dest"
fi
if [[ -z "$wintun_src" ]]; then
  echo "wintun.dll is required for Windows builds: pass --wintun <path>, set TOBRO_WINTUN_DLL, or place it at $wintun_dest (download: https://www.wintun.net/)" >&2
  exit 1
fi
if [[ ! -f "$wintun_src" ]]; then
  echo "wintun.dll not found at $wintun_src" >&2
  exit 1
fi

if [[ -n "$wintun_sha256" ]]; then
  if command -v sha256sum >/dev/null 2>&1; then
    actual_sha256="$(sha256sum "$wintun_src" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual_sha256="$(shasum -a 256 "$wintun_src" | awk '{print $1}')"
  else
    echo "no SHA-256 tool found (sha256sum or shasum); cannot verify the wintun pin" >&2
    exit 1
  fi
  if [[ "$(printf '%s' "$actual_sha256" | tr 'A-F' 'a-f')" != "$(printf '%s' "$wintun_sha256" | tr 'A-F' 'a-f')" ]]; then
    echo "wintun.dll SHA-256 mismatch (expected $wintun_sha256, got $actual_sha256)" >&2
    exit 1
  fi
else
  echo "warning: wintun.dll was staged without a SHA-256 pin (set --wintun-sha256 or TOBRO_WINTUN_SHA256)" >&2
fi

if [[ "$wintun_src" != "$wintun_dest" ]]; then
  cp "$wintun_src" "$wintun_dest"
fi
chmod 0644 "$wintun_dest" || true
echo "Prepared $wintun_dest" >&2
