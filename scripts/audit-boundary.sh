#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

forbidden='/billing/(checkout|portal|webhook)|/auth/(sso|scim)|REPROIT_TENANT_PROVIDER|cloudRunMinutes|temp-access-credentials'
if rg -n --hidden --glob '!target/**' --glob '!.git/**' --glob '!scripts/audit-boundary.sh' "$forbidden" .; then
  echo "self-hosted boundary violation: hosted provider code or credentials found" >&2
  exit 1
fi

for path in fly.toml src/billing src/mail.rs static/reset.html static/reset.js; do
  if [[ -e "$path" ]]; then
    echo "self-hosted boundary violation: $path must not ship" >&2
    exit 1
  fi
done

auth_files="$(find src/auth -maxdepth 1 -type f -print | LC_ALL=C sort)"
expected_auth=$'src/auth/keys.rs\nsrc/auth/mod.rs\nsrc/auth/password.rs\nsrc/auth/session.rs'
if [[ "$auth_files" != "$expected_auth" ]]; then
  echo "self-hosted boundary violation: unexpected authentication module" >&2
  diff -u <(printf '%s\n' "$expected_auth") <(printf '%s\n' "$auth_files") || true
  exit 1
fi

echo "self-hosted boundary audit passed"
