#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../ui"

if command -v bun >/dev/null 2>&1; then
  exec bun run build
elif command -v pnpm >/dev/null 2>&1; then
  exec pnpm run build
elif command -v npm >/dev/null 2>&1; then
  exec npm run build
elif command -v node >/dev/null 2>&1 && [ -x ./node_modules/.bin/vite ]; then
  exec node ./node_modules/.bin/vite build
else
  echo "No JS toolchain found (bun/pnpm/npm/node). Install bun or Node.js, then run: cd apps/desktop/ui && npm run build" >&2
  exit 127
fi
