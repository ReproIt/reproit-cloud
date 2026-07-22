#!/usr/bin/env bash
set -euo pipefail

expect_json_integer() {
  local field="$1"
  local expected="$2"
  local document="$3"
  python3 -c '
import json
import sys

field = sys.argv[1]
expected = int(sys.argv[2])
actual = json.load(sys.stdin)
for segment in field.split("."):
    actual = actual.get(segment) if isinstance(actual, dict) else None
if actual != expected:
    print(f"expected JSON field {field!r} to equal {expected}, got {actual!r}", file=sys.stderr)
    raise SystemExit(1)
' "$field" "$expected" <<<"$document"
}

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
login=$(curl --fail --silent --show-error "$base_url/login")
if ! grep -q 'Sign in' <<<"$login"; then
  echo "Login page did not contain the expected sign-in form" >&2
  exit 1
fi

bootstrap=$(
  docker compose exec -T cloud reproit-cloud init \
    --email smoke@example.com \
    --password smoke-password \
    --project Smoke
)
app_id=$(printf '%s\n' "$bootstrap" | sed -n 's/.*appId: \([^)]*\)).*/\1/p')
api_key=$(printf '%s\n' "$bootstrap" | sed -n 's/.*shown once, store it now): \(sk_live_.*\)/\1/p')
test -n "$app_id"
test -n "$api_key"

run_id="self-host-smoke-$$"
ingest=$(
  curl --fail --silent --show-error \
    -H "authorization: Bearer $api_key" \
    -H 'content-type: application/json' \
    -X POST "$base_url/v1/events" \
    -d '{
      "version": 1,
      "batchId": "'"$run_id"'",
      "appId": "'"$app_id"'",
      "frames": [{
        "runId": "'"$run_id"'",
        "sequence": 1,
        "scope": {"domain": "shared"},
        "event": {
          "kind": "finding",
          "signature": "crash:SelfHostSmoke:probe",
          "message": "self-hosted smoke probe",
          "identity": {
            "oracle": "crash",
            "invariant": "no-uncaught-exception",
            "kind": "exception",
            "message": "smoke probe",
            "frame": "",
            "trigger": "probe"
          },
          "path": [{"signature": "home", "action": "load", "label": null}],
          "context": {
            "build": {"version": "1.0.0-smoke", "commit": "smoke"},
            "platform": "web"
          }
        }
      }],
      "evidence": []
    }'
)
expect_json_integer ingested.errors 1 "$ingest"

bucket_id=$(
  curl --fail --silent --show-error \
    -H "authorization: Bearer $api_key" \
    "$base_url/v1/apps/$app_id/buckets" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["items"][0]["bucketId"])'
)
test -n "$bucket_id"

evidence_file=$(mktemp -t reproit-self-host-smoke.XXXXXX)
cleanup() { rm -f "$evidence_file"; }
trap cleanup EXIT
printf 'reproit self-host evidence smoke\n' > "$evidence_file"
upload=$(
  curl --fail --silent --show-error \
    -H "authorization: Bearer $api_key" \
    -F "file=@$evidence_file;type=text/plain;filename=smoke.txt" \
    "$base_url/v1/apps/$app_id/buckets/$bucket_id/evidence"
)
expect_json_integer stored 1 "$upload"
evidence=$(curl --fail --silent --show-error \
  -H "authorization: Bearer $api_key" \
  "$base_url/v1/apps/$app_id/buckets/$bucket_id/evidence")
expect_json_integer count 1 "$evidence"

echo "self-hosted smoke test passed"
