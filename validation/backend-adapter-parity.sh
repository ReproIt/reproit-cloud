#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI_ADAPTER="${REPROIT_CLI_BACKEND_ADAPTER:-$ROOT/../reproit-cli/sdk/reproit-backend-rs/src/lib.rs}"
CLOUD_ADAPTER="$ROOT/experimental/reproit-backend/src/lib.rs"

if [[ ! -f "$CLI_ADAPTER" ]]; then
  echo "CLI adapter not checked out; set REPROIT_CLI_BACKEND_ADAPTER to validate source parity" >&2
  exit 2
fi

diff -u "$CLI_ADAPTER" "$CLOUD_ADAPTER"
echo "Rust backend adapter source parity: ok"
