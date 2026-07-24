#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Hosted-only surfaces that must never ship in the source-available repo:
# billing flows, enterprise SSO/SCIM, and hosted usage metering. The
# multi-tenant DATA PLANE (tenant-provider selection, scoped R2 credential
# minting) is deliberately part of the shared, composable reproit-cloud library
# after the defork: self-host runs it single-tenant with the local provider and
# its own blob store, hosted composes the same code with Neon + R2. So
# REPROIT_TENANT_PROVIDER and the R2 temp-access-credentials minter are NOT
# boundary violations; see docs/architecture/multi-tenancy.md section 7.
forbidden='/billing/(checkout|portal|webhook)|/auth/(sso|scim)|cloudRunMinutes'
if command -v rg >/dev/null 2>&1; then
  boundary_matches="$(rg -n --hidden --glob '!target/**' --glob '!.git/**' --glob '!scripts/audit-boundary.sh' "$forbidden" . || true)"
else
  boundary_matches="$(grep -RInE \
    --exclude-dir=.git \
    --exclude-dir=target \
    --exclude=audit-boundary.sh \
    "$forbidden" . || true)"
fi

if [[ -n "$boundary_matches" ]]; then
  printf '%s\n' "$boundary_matches"
  echo "self-hosted boundary violation: hosted provider code or credentials found" >&2
  exit 1
fi

for path in fly.toml src/billing static/reset.html static/reset.js; do
  if [[ -e "$path" ]]; then
    echo "self-hosted boundary violation: $path must not ship" >&2
    exit 1
  fi
done

auth_files="$(find src/auth -maxdepth 1 -type f -print | LC_ALL=C sort)"
expected_auth=$'src/auth/account.rs\nsrc/auth/invitation_tests.rs\nsrc/auth/keys.rs\nsrc/auth/mod.rs\nsrc/auth/organizations.rs\nsrc/auth/password.rs\nsrc/auth/projects.rs\nsrc/auth/session.rs'
if [[ "$auth_files" != "$expected_auth" ]]; then
  echo "self-hosted boundary violation: unexpected authentication module" >&2
  diff -u <(printf '%s\n' "$expected_auth") <(printf '%s\n' "$auth_files") || true
  exit 1
fi

echo "self-hosted boundary audit passed"
