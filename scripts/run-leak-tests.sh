#!/usr/bin/env bash
# Run the tobro TUN leak suite inside a private Linux network + mount
# namespace.
#
# Isolation guarantees:
#   - The suite gets its own routing table and interfaces (`unshare --net`),
#     so routes, DNS, and TUN devices never touch the host.
#   - `/etc` is bind-mounted from a private copy (`unshare --mount`), so the
#     helper can replace `/etc/resolv.conf` (rename) without affecting the
#     host, and without hitting the systemd-resolved symlink the helper
#     refuses to manage.
#   - Loopback is brought up; there is no physical network to leak to, which
#     makes the intrusive tier (default routes, kill switch) safe to run.
#
# Usage:
#   sudo scripts/run-leak-tests.sh [tobro-leak arguments...]
#
#   sudo scripts/run-leak-tests.sh --intrusive \
#        --scenario intrusive-default-route
#
# The intrusive tier additionally requires TOBRO_LEAK_ALLOW_INTRUSIVE=1.
# Build first (or let this script build):
#   TOBRO_LEAK_NO_BUILD=1 sudo scripts/run-leak-tests.sh --fail-on-skip
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "run-leak-tests.sh: Linux only (use the workflow or a dedicated host elsewhere)" >&2
    exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
    echo "run-leak-tests.sh: needs root; run it with sudo" >&2
    exit 2
fi
for tool in unshare mount ip mktemp; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "run-leak-tests.sh: required tool '$tool' was not found" >&2
        exit 2
    fi
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="${TOBRO_HELPER_BIN:-$ROOT/target/debug/tobro-helper}"
LEAK_BIN="${TOBRO_LEAK_BIN:-$ROOT/target/debug/tobro-leak}"

if [[ "${TOBRO_LEAK_NO_BUILD:-0}" != "1" ]]; then
    (cd "$ROOT" && cargo build -p tobro-helper -p tobro-leak)
fi
if [[ ! -x "$HELPER" ]]; then
    echo "run-leak-tests.sh: helper binary $HELPER is missing; build it or set TOBRO_HELPER_BIN" >&2
    exit 2
fi
if [[ ! -x "$LEAK_BIN" ]]; then
    echo "run-leak-tests.sh: harness binary $LEAK_BIN is missing; build it or set TOBRO_LEAK_BIN" >&2
    exit 2
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/tobro-leak.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# A writable copy of /etc for the namespace. The original resolv.conf may be
# a symlink to a resolver service the helper refuses to manage; replace it
# with a regular file so apply/restore exercise the real path.
mkdir -p "$WORK/etc"
cp -a /etc/. "$WORK/etc/"
rm -f "$WORK/etc/resolv.conf"
printf 'nameserver 127.0.0.1\n' >"$WORK/etc/resolv.conf"

export WORK_ETC="$WORK/etc"
export TOBRO_HELPER_BIN="$HELPER"
export LEAK_BIN="$LEAK_BIN"

# No `exec`: the trap above must still remove the temp directory once the
# namespace exits.
unshare --net --mount --fork --kill-child \
    bash -c '
        set -euo pipefail
        # Never propagate mounts back to the host namespace.
        mount --make-rprivate /
        # Private, writable /etc (the helper renames a temp file over
        # resolv.conf, so a file bind-mount would not work).
        mount --bind "$WORK_ETC" /etc

        # A fresh netns starts with loopback down.
        ip link set lo up
        if command -v sysctl >/dev/null 2>&1; then
            sysctl -qw net.ipv6.conf.lo.disable_ipv6=0 || true
        fi
        ip -6 addr add ::1/128 dev lo 2>/dev/null || true

        exec "$LEAK_BIN" "$@"
    ' bash "$@"
