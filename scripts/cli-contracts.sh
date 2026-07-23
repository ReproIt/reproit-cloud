#!/usr/bin/env bash
set -euo pipefail

# Verifies the vendored CLI contract artifacts against a reproit-cli checkout.
# The check is content-based: a CLI commit that does not touch a contract file
# never breaks it, so there is no repin churn. `.reproit-cli-commit` records
# provenance (CI checks the CLI out at that ref); --sync copies the current
# contents and advances the pin to the checkout's HEAD.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI_ROOT="${REPROIT_CLI_ROOT:-$HERE/../reproit-cli}"
MODE="${1:---check}"
PIN_FILE="$HERE/.reproit-cli-commit"
PIN="$(tr -d '[:space:]' < "$PIN_FILE")"

case "$MODE" in
  --check|--sync) ;;
  *) echo "usage: $0 [--check|--sync]" >&2; exit 2 ;;
esac

test -d "$CLI_ROOT/.git" || {
  echo "CLI source checkout not found: $CLI_ROOT" >&2
  exit 2
}

ACTUAL="$(git -C "$CLI_ROOT" rev-parse HEAD)"

FILES=(
  "crates/reproit-protocol/Cargo.toml|protocol/Cargo.toml"
  "crates/reproit-protocol/fixtures/event-lines-v1.json|protocol/fixtures/event-lines-v1.json"
  "crates/reproit-protocol/src/causal.rs|protocol/src/causal.rs"
  "crates/reproit-protocol/src/environment.rs|protocol/src/environment.rs"
  "crates/reproit-protocol/src/lib.rs|protocol/src/lib.rs"
  "crates/reproit-protocol/src/tests.rs|protocol/src/tests.rs"
  "crates/reproit/oracle-registry.json|tests/golden/fixtures/oracle-registry.json"
  "crates/reproit/tests/golden/fixtures/fixture-spec-v2.json|tests/golden/fixtures/fixture-spec-v2.json"
)

DRIFT=0
for mapping in "${FILES[@]}"; do
  source_path="${mapping%%|*}"
  destination_path="${mapping#*|}"
  if [ "$MODE" = "--sync" ]; then
    cp "$CLI_ROOT/$source_path" "$HERE/$destination_path"
  elif ! cmp -s "$CLI_ROOT/$source_path" "$HERE/$destination_path"; then
    echo "CLI contract drift: $destination_path differs from $source_path at CLI $ACTUAL" >&2
    DRIFT=1
  fi
done

if [ "$MODE" = "--sync" ]; then
  printf '%s\n' "$ACTUAL" > "$PIN_FILE"
  echo "CLI contracts: synced at $ACTUAL"
  exit 0
fi

if [ "$DRIFT" -ne 0 ]; then
  echo "run $0 --sync (from a reviewed CLI checkout) and commit the result" >&2
  exit 1
fi

if [ "$ACTUAL" != "$PIN" ]; then
  echo "note: contract contents match; pin $PIN is behind CLI $ACTUAL (repin via --sync)"
fi
echo "CLI contracts: check ok against CLI $ACTUAL"
