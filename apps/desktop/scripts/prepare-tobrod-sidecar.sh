#!/usr/bin/env bash
set -euo pipefail

# Prepare tobrod as a Tauri externalBin sidecar for the current/target build.
# Usage: prepare-tobrod-sidecar.sh [--profile debug|release] [--target <triple>]

profile="release"
target="${TAURI_ENV_TARGET_TRIPLE:-${TAURI_ENV_TARGET:-}}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) profile="$2"; shift 2 ;;
    --target) target="$2"; shift 2 ;;
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

cargo_args=(build -p tobrod --manifest-path "$repo_root/Cargo.toml")
if [[ "$profile" == "release" ]]; then
  cargo_args+=(--release)
fi
if [[ -n "$target" ]]; then
  cargo_args+=(--target "$target")
fi

echo "Preparing tobrod sidecar: profile=$profile target=$target" >&2
cargo "${cargo_args[@]}"

exe_suffix=""
src_dir="$repo_root/target"
if [[ -n "$target" ]]; then
  src_dir="$src_dir/$target"
fi
src_dir="$src_dir/$profile/tobrod"
if [[ "$target" == *windows* ]]; then
  exe_suffix=".exe"
  src_dir="${src_dir}.exe"
fi

dest="$binaries_dir/tobrod-$target$exe_suffix"
if [[ ! -f "$src_dir" ]]; then
  echo "tobrod binary not found at $src_dir" >&2
  exit 1
fi
cp "$src_dir" "$dest"
chmod +x "$dest" || true
echo "Prepared $dest" >&2
