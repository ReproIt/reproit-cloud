#!/usr/bin/env bash
set -euo pipefail

base_url="${REPROIT_SMOKE_URL:-http://127.0.0.1:8080}"
deadline=$((SECONDS + 90))
until curl --fail --silent --show-error "$base_url/health" >/dev/null; do
  if (( SECONDS >= deadline )); then
    echo "Reproit did not become healthy at $base_url within 90 seconds" >&2
    exit 1
  fi
  sleep 2
done

curl --fail --silent --show-error "$base_url/ready" >/dev/null
curl --fail --silent --show-error "$base_url/login" | rg -q 'Sign in'
echo "self-hosted smoke test passed"
