#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI_ROOT="${REPROIT_CLI_ROOT:-$HERE/../reproit-cli}"
MODE="${1:---check}"
PIN="$(tr -d '[:space:]' < "$HERE/.reproit-cli-commit")"

case "$MODE" in
  --check|--sync) ;;
  *) echo "usage: $0 [--check|--sync]" >&2; exit 2 ;;
esac

test -d "$CLI_ROOT/.git" || {
  echo "CLI source checkout not found: $CLI_ROOT" >&2
  exit 2
}

ACTUAL="$(git -C "$CLI_ROOT" rev-parse HEAD)"
test "$ACTUAL" = "$PIN" || {
  echo "CLI checkout is $ACTUAL, expected pinned source-of-truth commit $PIN" >&2
  exit 1
}

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

for mapping in "${FILES[@]}"; do
  source_path="${mapping%%|*}"
  destination_path="${mapping#*|}"
  if [ "$MODE" = "--sync" ]; then
    cp "$CLI_ROOT/$source_path" "$HERE/$destination_path"
  elif ! cmp -s "$CLI_ROOT/$source_path" "$HERE/$destination_path"; then
    echo "CLI contract drift: $destination_path differs from $source_path at $PIN" >&2
    exit 1
  fi
done

echo "CLI contracts: ${MODE#--} at $PIN"
