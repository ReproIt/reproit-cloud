#!/usr/bin/env bash
# Reproit worker poll loop (reference implementation).
#
# Shared by Dockerfile.worker (Linux web/android) and the Mac launchd plist
# (mac-worker-setup.sh, web/android/ios). A worker is a PULL client: it dials
# OUT to the control plane and claims shards over HTTP with a bearer WORKER
# token. The control plane never connects to the worker, so workers run behind
# NAT/firewalls with no inbound ports.
#
# Protocol (documented; implemented control-plane side, not here):
#   POST /v1/worker/claim   {capabilities:[...]} -> 200 shard JSON | 204 idle
#   POST /v1/worker/shards/{id}/heartbeat        -> keepalive while running
#   POST /v1/worker/shards/{id}/result  {report} -> finished, report attached
# Auth: every request sends `Authorization: Bearer $REPROIT_WORKER_TOKEN`.
#
# Config (env):
#   REPROIT_CLOUD_URL     base URL of this installation (e.g. https://bugs.example.com)
#   REPROIT_WORKER_TOKEN  bearer token (matches the server's REPROIT_WORKER_TOKEN)
#   REPROIT_CAPABILITIES  comma list this worker can run (e.g. web,android,ios)
#   REPROIT_BIN           path to the reproit binary (default /usr/local/bin/reproit)
#   REPROIT_POLL_BACKOFF  seconds to sleep after a 204 idle (default 5)
#   REPROIT_SHARD_TIMEOUT per-shard wall-clock cap in seconds (default 1800)
set -euo pipefail

CLOUD_URL="${REPROIT_CLOUD_URL:?set REPROIT_CLOUD_URL}"
WORKER_TOKEN="${REPROIT_WORKER_TOKEN:?set REPROIT_WORKER_TOKEN}"
CAPABILITIES="${REPROIT_CAPABILITIES:-web}"
REPROIT_BIN="${REPROIT_BIN:-/usr/local/bin/reproit}"
BACKOFF="${REPROIT_POLL_BACKOFF:-5}"
SHARD_TIMEOUT="${REPROIT_SHARD_TIMEOUT:-1800}"
CLOUD_URL="${CLOUD_URL%/}" # trim trailing slash

# capabilities=web,android,ios -> JSON ["web","android","ios"]
caps_json() {
  printf '%s' "$CAPABILITIES" | jq -R 'split(",") | map(select(length > 0))'
}

auth=(-H "Authorization: Bearer ${WORKER_TOKEN}")
json=(-H "Content-Type: application/json")

echo "reproit-worker: polling ${CLOUD_URL} caps=[${CAPABILITIES}] bin=${REPROIT_BIN}"
command -v jq >/dev/null   || { echo "fatal: jq not found"   >&2; exit 1; }
command -v curl >/dev/null || { echo "fatal: curl not found" >&2; exit 1; }
[ -x "$REPROIT_BIN" ]      || { echo "fatal: ${REPROIT_BIN} not executable" >&2; exit 1; }

# Heartbeat a shard in the background so the control plane knows it's alive and
# can reassign on worker death. Killed when the shard finishes.
start_heartbeat() {
  local sid="$1"
  (
    while true; do
      sleep 20
      curl -fsS -X POST "${auth[@]}" \
        "${CLOUD_URL}/v1/worker/shards/${sid}/heartbeat" >/dev/null 2>&1 || true
    done
  ) >/dev/null 2>&1 &
  # The subshell's fds MUST be redirected away from the caller's pipe: this
  # function is called as `hb_pid="$(start_heartbeat ...)"`, and a backgrounded
  # subshell inherits the command-substitution stdout, so without this redirect
  # `$(...)` never sees EOF and the worker hangs forever right after "claimed".
  echo $!
}

# Per-shard wall-clock cap, portably. GNU `timeout` (Linux/coreutils) or
# `gtimeout` (Homebrew coreutils) when present; else a pure-bash watchdog for
# stock macOS workers (no coreutils). Exits 124 on timeout, matching `timeout`,
# so the rc==124 -> "timeout" status below is preserved on every platform.
if command -v timeout >/dev/null 2>&1; then TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_BIN="gtimeout"
else TIMEOUT_BIN=""; fi

run_with_timeout() {
  local secs="$1"; shift
  if [ -n "$TIMEOUT_BIN" ]; then
    "$TIMEOUT_BIN" "$secs" "$@"
    return $?
  fi
  "$@" &
  local cmd_pid=$!
  ( sleep "$secs"; kill -TERM "$cmd_pid" 2>/dev/null; sleep 5; kill -KILL "$cmd_pid" 2>/dev/null ) >/dev/null 2>&1 &
  local killer_pid=$!
  local rc=0
  wait "$cmd_pid" 2>/dev/null || rc=$?
  kill "$killer_pid" >/dev/null 2>&1 || true
  # A TERM/KILL-signalled run exits 143/137; normalize to 124 like `timeout`.
  if [ "$rc" -eq 143 ] || [ "$rc" -eq 137 ]; then rc=124; fi
  return "$rc"
}

while true; do
  # --- claim ---------------------------------------------------------------
  # -w writes the HTTP status as a trailing line; body is everything before it.
  resp="$(curl -sS -X POST "${auth[@]}" "${json[@]}" \
    -d "$(jq -nc --argjson caps "$(caps_json)" '{capabilities:$caps}')" \
    -w $'\n%{http_code}' \
    "${CLOUD_URL}/v1/worker/claim" || true)"
  code="${resp##*$'\n'}"
  shard="${resp%$'\n'*}"

  if [ "$code" = "204" ]; then
    sleep "$BACKOFF"; continue   # idle: nothing queued
  fi
  if [ "$code" != "200" ]; then
    echo "claim failed: HTTP ${code:-?} ${shard}" >&2
    sleep "$BACKOFF"; continue   # transient: back off and retry
  fi

  shard_id="$(printf '%s' "$shard" | jq -r '.id')"
  app_dir="$(printf '%s' "$shard"  | jq -r '.app_dir // .appDir // empty')"
  seed="$(printf '%s' "$shard"     | jq -r '.seed // 0')"
  budget="$(printf '%s' "$shard"   | jq -r '.budget // 60')"
  config="$(printf '%s' "$shard"   | jq -r '.config // empty')"
  echo "claimed shard ${shard_id} seed=${seed} budget=${budget}"

  hb_pid="$(start_heartbeat "$shard_id")"

  # --- run the EXACT reproit binary against the shard ----------------------
  # One shard = one seed (mirrors the in-process worker in src/worker.rs).
  # An isolated tmp workdir keeps per-shard .reproit state from racing.
  work="$(mktemp -d)"
  cfg_arg=()
  if [ -n "$config" ]; then
    printf '%s' "$config" > "${work}/reproit.yaml"
    cfg_arg=(--config "${work}/reproit.yaml")
  elif [ -n "$app_dir" ]; then
    cfg_arg=(--config "${app_dir}/reproit.yaml")
  fi

  set +e
  run_with_timeout "$SHARD_TIMEOUT" \
    env REPROIT_HEADLESS=1 "$REPROIT_BIN" "${cfg_arg[@]}" \
    fuzz --seed "$seed" --runs 1 --budget "$budget" \
    >"${work}/stdout.log" 2>&1
  rc=$?
  set -e

  kill "$hb_pid" >/dev/null 2>&1 || true

  # --- collect the report --------------------------------------------------
  # reproit writes fuzz.md under the evidence runs dir; fall back to stdout.
  report_file="$(find "$work" -name fuzz.md -type f 2>/dev/null | sort | tail -n1)"
  if [ -n "$report_file" ] && [ -f "$report_file" ]; then
    report="$(cat "$report_file")"
  else
    report="$(cat "${work}/stdout.log" 2>/dev/null || true)"
  fi
  status="clean"
  if grep -q "FINDING" "${work}/stdout.log" 2>/dev/null || [ -n "$report_file" ]; then
    status="finding"
  fi
  [ "$rc" -eq 124 ] && status="timeout"
  [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ] && [ "$status" = "clean" ] && status="error"

  # --- post the result -----------------------------------------------------
  curl -fsS -X POST "${auth[@]}" "${json[@]}" \
    -d "$(jq -nc --arg s "$status" --argjson rc "$rc" --arg r "$report" \
          '{status:$s, exit_code:$rc, report:$r}')" \
    "${CLOUD_URL}/v1/worker/shards/${shard_id}/result" \
    || echo "result post failed for ${shard_id}" >&2

  echo "shard ${shard_id} done: ${status} (rc=${rc})"
  rm -rf "$work"
  # Loop straight back to claim the next shard (no backoff when busy).
done
