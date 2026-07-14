#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="reproit-backend-contract-$RANDOM-$$"
WORK="$(mktemp -d)"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

docker run -d --rm --name "$NAME" -P \
  -e POSTGRES_USER=reproit \
  -e POSTGRES_PASSWORD=reproit \
  -e POSTGRES_DB=reproit \
  postgres:16-alpine >/dev/null

PG_PORT="$(docker port "$NAME" 5432/tcp | awk -F: 'END {print $NF}')"
HTTP_PORT="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"

for _ in {1..60}; do
  if docker exec "$NAME" pg_isready -U reproit -d reproit >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$NAME" pg_isready -U reproit -d reproit >/dev/null

cd "$ROOT"
cargo build --locked
DATABASE_URL="postgres://reproit:reproit@127.0.0.1:${PG_PORT}/reproit" \
REPROIT_DEV_OPEN=1 \
REPROIT_ALLOW_LOCAL_BLOBS=1 \
REPROIT_EXPERIMENTAL_BACKEND_CONTRACTS=1 \
  target/debug/reproit-cloud --port "$HTTP_PORT" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!

for _ in {1..90}; do
  if curl -fsS "http://127.0.0.1:${HTTP_PORT}/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    cat "$WORK/server.log" >&2
    exit 1
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${HTTP_PORT}/health" >/dev/null

touch "$WORK/events.ndjson"

append_events() {
  local headers="$1" operation="$2" expected_status="$3" secrets="${4:-}"
  local encoded
  encoded="$(awk 'tolower($1) == "x-reproit-events:" {gsub("\\r", "", $2); print $2}' "$headers")"
  [[ -n "$encoded" ]]
  EVENTS="$encoded" OPERATION="$operation" EXPECTED_STATUS="$expected_status" \
    SECRETS="$secrets" EVENTS_FILE="$WORK/events.ndjson" python3 - <<'PY'
import base64
import json
import os

encoded = os.environ["EVENTS"]
encoded += "=" * (-len(encoded) % 4)
events = json.loads(base64.urlsafe_b64decode(encoded))
assert [event["kind"] for event in events] == ["start", "return"]
assert all(event["operation"] == os.environ["OPERATION"] for event in events)
assert events[1]["status"] == int(os.environ["EXPECTED_STATUS"])
assert events[1]["success"] is True
assert events[1]["effectsComplete"] is False
serialized = json.dumps(events)
for secret in os.environ["SECRETS"].splitlines():
    if secret:
        assert secret not in serialized
with open(os.environ["EVENTS_FILE"], "a", encoding="utf-8") as output:
    for event in events:
        output.write("REPROIT:BACKEND " + json.dumps(event, separators=(",", ":")) + "\n")
PY
}

EMAIL="backend-contract-$RANDOM-$$@example.invalid"
PASSWORD="not-a-real-secret-$RANDOM"
STATUS="$(curl -sS -o "$WORK/signup.body" -D "$WORK/signup.headers" -c "$WORK/cookies" -w '%{http_code}' \
  -H 'content-type: application/json' \
  -H 'x-reproit-trace: cloud-live-signup' \
  -H 'x-reproit-actor: dogfood' \
  -H 'x-reproit-action: 3' \
  --data "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\"}" \
  "http://127.0.0.1:${HTTP_PORT}/auth/signup")"
[[ "$STATUS" == "201" ]]
append_events "$WORK/signup.headers" cloudSignup 201 "$EMAIL
$PASSWORD"

STATUS="$(curl -sS -o "$WORK/project.body" -D "$WORK/project.headers" -b "$WORK/cookies" -w '%{http_code}' \
  -H 'content-type: application/json' \
  -H 'x-reproit-trace: cloud-live-create-project' \
  -H 'x-reproit-actor: dogfood' \
  -H 'x-reproit-action: 4' \
  --data '{"name":"Backend dogfood"}' \
  "http://127.0.0.1:${HTTP_PORT}/account/projects")"
[[ "$STATUS" == "201" ]]
API_KEY="$(jq -er '.apiKey' "$WORK/project.body")"
PUBLISHABLE_KEY="$(jq -er '.publishableKey' "$WORK/project.body")"
APP_ID="$(jq -er '.appId' "$WORK/project.body")"
SECRETS="$EMAIL
$PASSWORD
$API_KEY
$PUBLISHABLE_KEY"
append_events "$WORK/project.headers" cloudCreateProject 201 "$SECRETS"

STATUS="$(curl -sS -o "$WORK/me.body" -D "$WORK/me.headers" -w '%{http_code}' \
  -H "authorization: Bearer $API_KEY" \
  -H 'x-reproit-trace: cloud-live-me' \
  -H 'x-reproit-actor: dogfood' \
  -H 'x-reproit-action: 5' \
  "http://127.0.0.1:${HTTP_PORT}/v1/me")"
[[ "$STATUS" == "200" ]]
append_events "$WORK/me.headers" cloudGetMe 200 "$SECRETS"

STATUS="$(curl -sS -o "$WORK/ingest.body" -D "$WORK/ingest.headers" -w '%{http_code}' \
  -H "authorization: Bearer $API_KEY" \
  -H 'content-type: application/json' \
  -H 'x-reproit-trace: cloud-live-ingest' \
  -H 'x-reproit-actor: dogfood' \
  -H 'x-reproit-action: 6' \
  --data "{\"appId\":\"$APP_ID\",\"batchId\":\"backend-dogfood\",\"events\":[]}" \
  "http://127.0.0.1:${HTTP_PORT}/v1/events")"
[[ "$STATUS" == "200" ]]
append_events "$WORK/ingest.headers" cloudIngestEvents 200 "$SECRETS"

STATUS="$(curl -sS -o "$WORK/replay.body" -D "$WORK/replay.headers" -w '%{http_code}' \
  -H "authorization: Bearer $API_KEY" \
  -H 'content-type: application/json' \
  -H 'x-reproit-trace: cloud-live-replay' \
  -H 'x-reproit-actor: dogfood' \
  -H 'x-reproit-action: 7' \
  --data '{"status":"reproduced","runs":1,"failures":1,"localReproId":"dogfood-repro"}' \
  "http://127.0.0.1:${HTTP_PORT}/v1/apps/${APP_ID}/buckets/backend-dogfood/replay-results")"
[[ "$STATUS" == "200" ]]
append_events "$WORK/replay.headers" cloudRecordReplay 200 "$SECRETS"

EVALUATOR="$ROOT/../reproit-cli/validation/backend/oss/Cargo.toml"
if [[ -f "$EVALUATOR" ]]; then
  cargo run --quiet --manifest-path "$EVALUATOR" -- \
    "$ROOT/contracts/backend-openapi.json" "$WORK/events.ndjson"
else
  echo "CLI evaluator not checked out; captured event shape checks passed, evaluator skipped" >&2
fi

echo "live backend contract capture (5 routes): ok"
