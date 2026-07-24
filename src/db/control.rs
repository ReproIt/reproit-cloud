//! The CONTROL-PLANE store: the one small shared Postgres that knows about
//! identity and routing metadata, and NEVER holds customer telemetry or videos.
//!
//! Under database-per-org this is the only cross-tenant database. It holds exactly
//! what must be queryable BEFORE a tenant is resolved (you log in, THEN we resolve
//! your org -> tenant) or what is the routing key itself:
//!   - identity: `users`, `sessions`, single-use `email_tokens`
//!   - membership: `orgs` (with a value-free `plan` label), `org_members` (+
//!     seats), `org_invitations`, externally provisioned `directory_users`
//!   - the routing keys: `api_keys` (a CLI/SDK key names its tenant) and the
//!     `tenants` registry (org id -> connection string + blob scope + status)
//!   - tenant maintenance state: `tenant_pending_shards`, `tenant_due_work`,
//!     `org_usage` counters, and the append-only `audit_log`
//!
//! The hosted edition extends `orgs` with billing/SSO columns and adds its own
//! tables through a schema applied AFTER this one (see the deploy repo's
//! `hosted_control.rs`); nothing here names a plan or a vendor.
//!
//! App-scoped data (errors, evidence, triage, jobs, ...) does NOT live here; it
//! lives in the per-tenant database behind `tenants.db_conn`. See
//! `crate::db::tenant::TenantStore`.

use super::{Member, Org, OrgInvitation, OrgSummary, TenantRecord, TenantStatus, User};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

use super::secrets::{decrypt as decrypt_conn, encrypt as encrypt_conn};

/// The control-plane schema. Applied on boot, idempotently. The control DB is a
/// SINGLE shared database whose shape changes rarely; schema-on-boot
/// (`CREATE/ALTER ... IF NOT EXISTS`) is appropriate here, in contrast to the
/// tenant DBs, which get `crate::db::schema::TENANT_SCHEMA` applied the same
/// way at provision time and on boot (pre-launch: no migration ledger).
pub(crate) const CONTROL_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
  id          BIGSERIAL PRIMARY KEY,
  email       TEXT UNIQUE NOT NULL,
  pass_hash   TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;
-- Single-use email flow tokens (signup verification, password reset). Stored
-- HASHED like sessions/API keys; consuming is a DELETE ... RETURNING so a token
-- can never be replayed.
CREATE TABLE IF NOT EXISTS email_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose    TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS email_tokens_user ON email_tokens(user_id);
CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  active_org_id BIGINT,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS active_org_id BIGINT;
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_at
  ON sessions(expires_at) WHERE expires_at IS NOT NULL;
CREATE TABLE IF NOT EXISTS orgs (
  id              BIGSERIAL PRIMARY KEY,
  name            TEXT NOT NULL,
  plan            TEXT NOT NULL DEFAULT 'free',
  personal        BOOLEAN NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS personal BOOLEAN NOT NULL DEFAULT false;
-- The plan label is a value-free string; what any plan MEANS (limits, prices)
-- lives entirely in the hosted overlay. Self-host stays on the default.
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'free';
CREATE TABLE IF NOT EXISTS org_members (
  org_id    BIGINT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role      TEXT NOT NULL DEFAULT 'member',
  seat      BOOLEAN NOT NULL DEFAULT false,
  added_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS org_members_user ON org_members(user_id);
CREATE INDEX IF NOT EXISTS org_members_seated ON org_members(org_id) WHERE seat;
-- Explicit, email-bound organization invitations. A pending seat invitation
-- reserves capacity until it is accepted, revoked, replaced, or expires.
CREATE TABLE IF NOT EXISTS org_invitations (
  id          BIGSERIAL PRIMARY KEY,
  token_hash  TEXT UNIQUE NOT NULL,
  org_id      BIGINT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  email       TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'member',
  seat        BOOLEAN NOT NULL DEFAULT true,
  invited_by  BIGINT REFERENCES users(id) ON DELETE SET NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, email)
);
CREATE INDEX IF NOT EXISTS org_invitations_org ON org_invitations(org_id, id);
CREATE INDEX IF NOT EXISTS org_invitations_expiry ON org_invitations(expires_at);
-- API keys are the CLI/SDK ROUTING KEY: the presented key names its org, which the
-- resolver maps to a tenant database. So the key MUST live in the control plane
-- (it cannot live inside the tenant it routes to). `key` is the SHA-256 hash of
-- the secret; `prefix` a non-secret display hint. `project_id` references a
-- TENANT-db project id (plain BIGINT, no cross-db FK).
CREATE TABLE IF NOT EXISTS api_keys (
  key        TEXT PRIMARY KEY,
  org_id     BIGINT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  project_id BIGINT,
  prefix     TEXT NOT NULL DEFAULT '',
  active     BOOLEAN NOT NULL DEFAULT true,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS api_keys_org ON api_keys(org_id);
-- Short-lived device authorization used by `reproit login`. The CLI holds the
-- device secret; the browser carries the human code. Only hashes are stored and
-- the approved grant can be consumed exactly once to mint an org-scoped key.
CREATE TABLE IF NOT EXISTS cli_authorizations (
  device_hash    TEXT PRIMARY KEY,
  user_code_hash TEXT UNIQUE NOT NULL,
  org_id         BIGINT REFERENCES orgs(id) ON DELETE CASCADE,
  user_id        BIGINT REFERENCES users(id) ON DELETE CASCADE,
  approved       BOOLEAN NOT NULL DEFAULT false,
  consumed       BOOLEAN NOT NULL DEFAULT false,
  expires_at     TIMESTAMPTZ NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS cli_authorizations_expiry ON cli_authorizations(expires_at);
-- Externally provisioned memberships (a directory/SCIM overlay writes here;
-- self-host simply never has rows). Read by list_org_users.
CREATE TABLE IF NOT EXISTS directory_users (
  external_id TEXT PRIMARY KEY,
  org_id      BIGINT NOT NULL REFERENCES orgs(id)  ON DELETE CASCADE,
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  active      BOOLEAN NOT NULL DEFAULT true,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS directory_users_org ON directory_users(org_id);
-- ---- the tenant registry: org id -> its database + blob scope ----------------
-- The heart of database-per-org. One row per org binds it to a Postgres
-- connection string (the tenant database) and a blob scope (bucket/prefix). The
-- resolver reads this on every request (cached) to route to the right tenant DB.
-- `status` tracks the provisioning lifecycle so a half-provisioned tenant is
-- completable, never a dead end. `db_conn` is encrypted at rest with
-- ChaCha20-Poly1305 (AEAD) when REPROIT_CONN_ENC_KEY (32-byte hex key) is set:
-- stored as `enc:v1:<hex(nonce||ciphertext)>` with a fresh random nonce per write.
-- When the key is UNSET (self-host/dev) the value is stored as legacy plaintext,
-- and the read path transparently handles both shapes (the `enc:v1:` prefix is the
-- discriminator). The column name stays `db_conn` either way.
CREATE TABLE IF NOT EXISTS tenants (
  org_id     BIGINT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
  status     TEXT NOT NULL DEFAULT 'provisioning',
  db_conn    TEXT,
  blob_mode  TEXT NOT NULL DEFAULT 'prefix',
  blob_scope TEXT NOT NULL DEFAULT '',
  region     TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tenants_status ON tenants(status);
-- ---- worker-claim routing hint: which tenants have >=1 pending shard ----------
-- A control-plane INDEX of "this tenant has work to claim", so the worker fleet
-- claims by visiting only tenants known to have a pending shard instead of fanning
-- a claim query into EVERY active tenant DB on every 2s poll (finding #3).
--
-- CORRECTNESS INVARIANT: a tenant MUST appear here whenever it has >=1 shard in
-- state='pending' in its tenant DB. This table is a ROUTING HINT, never the source
-- of truth (the per-tenant `shards` table + `FOR UPDATE SKIP LOCKED` is). Therefore:
--   * OVER-inclusion is harmless and self-heals: a stale row just costs one wasted
--     empty claim, after which the clear path (a fresh COUNT==0) removes it.
--   * UNDER-inclusion is a BUG: a missing row starves that tenant's shards forever.
-- So we mark on EVERY transition INTO pending (job submit, requeue-stranded) and
-- clear ONLY when a fresh `COUNT(*) WHERE state='pending'` for the tenant is exactly
-- 0 (never merely because a claim returned None: None can mean "all locked by other
-- workers", and clearing then would strand a later requeue).
CREATE TABLE IF NOT EXISTS tenant_pending_shards (
  org_id     BIGINT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tenant_due_work (
  org_id    BIGINT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  work_kind TEXT NOT NULL,
  due_at    TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (org_id, work_kind)
);
CREATE INDEX IF NOT EXISTS tenant_due_work_claimable
  ON tenant_due_work(work_kind, due_at, org_id);
-- ---- usage metering: monthly occurrence counters per org ---------------------
-- One row per (org, YYYY-MM). Incremented once per ingest batch (by that
-- batch's error-event count) and read by the hard plan cap. Occurrences live
-- in the control plane because the plan is org-level and ingest already
-- touches this DB for key auth. Customer-owned CI execution is not metered.
CREATE TABLE IF NOT EXISTS org_usage (
  org_id      BIGINT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  period      TEXT NOT NULL,
  occurrences BIGINT NOT NULL DEFAULT 0,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, period)
);
-- ---- security audit trail ------------------------------------------------------
-- Who did what, when, to which org. Append-only; written fire-and-forget (an
-- audit failure must never fail the audited request) for: admin-key requests,
-- worker claims/results, auth events, API-key lifecycle, seat/plan changes.
CREATE TABLE IF NOT EXISTS audit_log (
  id      BIGSERIAL PRIMARY KEY,
  actor   TEXT NOT NULL,
  action  TEXT NOT NULL,
  org_id  BIGINT,
  detail  JSONB NOT NULL DEFAULT '{}'::jsonb,
  at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_log_org ON audit_log(org_id, id);
"#;

/// The shared control-plane store. One pool, one database, cross-tenant by design
/// (it is the registry), but free of customer telemetry/videos.
mod credentials;
mod identity;
mod organizations;
mod tenant_registry;

pub struct ControlStore {
    pool: PgPool,
}

/// One row read back from the security audit trail (the ops `audit`
/// subcommand). `detail` is the free-form JSONB the writer recorded.
#[derive(Debug, Clone)]
pub struct AuditRow {
    pub actor: String,
    pub action: String,
    pub detail: serde_json::Value,
    pub at: String,
}

impl ControlStore {
    /// Apply an edition overlay's control schema (idempotent SQL, the same
    /// contract as CONTROL_SCHEMA). Called once at boot via RunConfig.
    #[allow(dead_code)] // The hosted overlay's boot path is the caller.
    pub async fn apply_extra_schema(&self, sql: &str) -> anyhow::Result<()> {
        sqlx::raw_sql(sql).execute(&self.pool).await?;
        Ok(())
    }

    /// The raw pool. The seam for edition overlays (the hosted repo extends
    /// ControlStore through an extension trait over this) and for tests;
    /// shared handlers go through the typed methods, never this.
    #[allow(dead_code)] // The hosted overlay and tests reach it; shared flow must not.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Connect to the control DB and apply its schema. A modest pool: this DB sees
    /// the hot per-request identity/key/tenant lookups (which are tiny and cached),
    /// not the bulk telemetry writes (those go to tenant DBs).
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        // A single explicit connection first: the pool otherwise reports every
        // failure (TLS, auth, DNS) as an opaque "pool timed out", so probe once
        // to surface the real cause in the logs and fail fast.
        {
            use sqlx::Connection;
            // Log the parsed target (host/port/ssl-mode only, never the password) so
            // a URL-parse fallback to localhost is visible instead of an opaque
            // "Connection refused".
            match url.parse::<sqlx::postgres::PgConnectOptions>() {
                Ok(opts) => {
                    let host = sqlx::postgres::PgConnectOptions::get_host(&opts).to_string();
                    let port = sqlx::postgres::PgConnectOptions::get_port(&opts);
                    // Credential-stripped shape of the raw URL: everything up to and
                    // including the last '@' in the authority is replaced with '***@'
                    // so no username/password is ever logged, only the structure.
                    let redacted = {
                        let mut out = String::new();
                        if let Some(sep) = url.find("://") {
                            let (scheme, rest) = url.split_at(sep + 3);
                            let auth_end = rest.find('/').unwrap_or(rest.len());
                            let (auth, tail) = rest.split_at(auth_end);
                            let hostpart = match auth.rfind('@') {
                                Some(at) => &auth[at + 1..],
                                None => auth,
                            };
                            out.push_str(scheme);
                            if auth.contains('@') {
                                out.push_str("***@");
                            }
                            out.push_str(hostpart);
                            out.push_str(tail);
                        } else {
                            out.push_str("<no ://>");
                        }
                        out
                    };
                    tracing::info!(target: "reproit::control", host = %host, port, redacted = %redacted, "control DB connect target");
                }
                Err(e) => {
                    anyhow::bail!("control DB URL parse failed: {e:#}");
                }
            }
            match sqlx::PgConnection::connect(url).await {
                Ok(c) => {
                    let _ = c.close().await;
                }
                Err(e) => {
                    anyhow::bail!("control DB direct connect failed: {e:#}");
                }
            }
        }
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .idle_timeout(std::time::Duration::from_secs(300))
            .max_lifetime(std::time::Duration::from_secs(1800))
            .connect(url)
            .await?;
        sqlx::raw_sql(CONTROL_SCHEMA).execute(&pool).await?;
        Ok(Self { pool })
    }

    /// Liveness/readiness probe.
    pub async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await?;
        Ok(())
    }
}

// Consumed by primary_org (hosted sign-in flow); self-host has no caller yet.
#[allow(dead_code)]
fn row_to_org(r: sqlx::postgres::PgRow) -> Org {
    Org {
        id: r.get::<i64, _>("id"),
        name: r.get::<String, _>("name"),
        plan: r.get::<String, _>("plan"),
        role: r.get::<String, _>("role"),
    }
}

fn row_to_invitation(r: sqlx::postgres::PgRow) -> OrgInvitation {
    OrgInvitation {
        id: r.get::<i64, _>("id"),
        org_name: r.get::<String, _>("org_name"),
        email: r.get::<String, _>("email"),
        role: r.get::<String, _>("role"),
        seat: r.get::<bool, _>("seat"),
        expires_at: r
            .get::<chrono::DateTime<chrono::Utc>, _>("expires_at")
            .to_rfc3339(),
    }
}

fn row_to_tenant(r: sqlx::postgres::PgRow) -> TenantRecord {
    // Decrypt db_conn on read (transparent passthrough for legacy plaintext). A
    // decrypt failure (corrupt data / missing-or-wrong key) degrades to `None`
    // rather than panicking on the request path; the resolver then treats the
    // tenant as having no conn string (and may fall back to deterministic
    // derivation), and the error is logged so it is not silent.
    let db_conn =
        r.get::<Option<String>, _>("db_conn")
            .and_then(|stored| match decrypt_conn(&stored) {
                Ok(plain) => Some(plain),
                Err(e) => {
                    let org_id = r.get::<i64, _>("org_id");
                    tracing::error!("tenant {org_id}: db_conn decrypt failed: {e}");
                    None
                }
            });
    TenantRecord {
        org_id: r.get::<i64, _>("org_id"),
        status: TenantStatus::parse(&r.get::<String, _>("status")),
        db_conn,
        blob_mode: r.get::<String, _>("blob_mode"),
        blob_scope: r.get::<String, _>("blob_scope"),
        region: r.get::<Option<String>, _>("region"),
    }
}

/// LOCAL integration test for the audit-log READ against a REAL Postgres.
/// GATING mirrors auth/tenancy::integration_tests: with no Postgres reachable
/// at `TEST_DATABASE_URL` (default the dev compose :5433) the test SKIPS and
/// passes. A unique throwaway control database is created and dropped.
#[cfg(test)]
mod audit_read_tests {
    use super::*;
    use std::time::Duration;

    fn admin_url() -> String {
        std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://reproit:reproit@localhost:5433/postgres".to_string())
    }

    /// Swap the database segment of a Postgres URL (mirror of the auth/tenancy
    /// integration-test helper, kept local so nothing private leaks).
    fn with_db(url: &str, db: &str) -> String {
        let (base, query) = match url.split_once('?') {
            Some((b, q)) => (b, Some(q)),
            None => (url, None),
        };
        let swapped = match base.rfind('/') {
            Some(idx) if idx > base.find("//").map(|i| i + 1).unwrap_or(0) => {
                format!("{}/{}", &base[..idx], db)
            }
            _ => format!("{base}/{db}"),
        };
        match query {
            Some(q) => format!("{swapped}?{q}"),
            None => swapped,
        }
    }

    async fn admin_pool_or_skip(test: &str) -> Option<sqlx::PgPool> {
        let url = admin_url();
        match PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .connect(&url)
            .await
        {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!(
                    "SKIP {test}: Postgres unreachable at {url} ({e}); set TEST_DATABASE_URL or start the dev :5433 Postgres to run this test"
                );
                None
            }
        }
    }

    async fn drop_db(admin: &sqlx::PgPool, name: &str) {
        let _ = sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1",
        )
        .bind(name)
        .execute(admin)
        .await;
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{name}\""))
            .execute(admin)
            .await;
    }

    #[tokio::test]
    async fn audit_read_returns_the_orgs_rows_newest_first_and_bounded() {
        let Some(admin) = admin_pool_or_skip("audit_read").await else {
            return;
        };
        let db_name = format!("reproit_test_audit_{}", std::process::id());
        drop_db(&admin, &db_name).await;
        sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
            .execute(&admin)
            .await
            .unwrap();

        let store = ControlStore::connect(&with_db(&admin_url(), &db_name))
            .await
            .unwrap();
        let org_a = store.create_org("acme", false).await.unwrap();
        let org_b = store.create_org("globex", false).await.unwrap();

        // Three rows for org A (in write order), one for org B, one org-less
        // row: the read must return ONLY org A's, newest first, capped.
        store
            .audit(
                "ops",
                "org.suspend",
                Some(org_a),
                serde_json::json!({"n": 1}),
            )
            .await;
        store
            .audit(
                "ops",
                "org.resume",
                Some(org_a),
                serde_json::json!({"n": 2}),
            )
            .await;
        store
            .audit(
                "admin-key",
                "admin.request",
                Some(org_a),
                serde_json::json!({"n": 3}),
            )
            .await;
        store
            .audit("ops", "org.plan", Some(org_b), serde_json::json!({}))
            .await;
        store
            .audit("system", "boot", None, serde_json::json!({}))
            .await;

        let rows = store.audit_for_org(org_a, 10).await.unwrap();
        assert_eq!(rows.len(), 3, "only org A's rows");
        // Newest first: the last write comes back first.
        assert_eq!(rows[0].action, "admin.request");
        assert_eq!(rows[0].actor, "admin-key");
        assert_eq!(rows[0].detail, serde_json::json!({"n": 3}));
        assert_eq!(rows[1].action, "org.resume");
        assert_eq!(rows[2].action, "org.suspend");
        // Timestamps parse as RFC 3339 (what the ops CLI prints verbatim).
        assert!(chrono::DateTime::parse_from_rfc3339(&rows[0].at).is_ok());

        // The limit caps the scan and keeps the newest rows.
        let capped = store.audit_for_org(org_a, 2).await.unwrap();
        assert_eq!(capped.len(), 2);
        assert_eq!(capped[0].action, "admin.request");
        assert_eq!(capped[1].action, "org.resume");

        // An org with no rows reads back empty, not an error.
        let none = store.audit_for_org(org_b + 1000, 10).await.unwrap();
        assert!(none.is_empty());

        drop(store);
        drop_db(&admin, &db_name).await;
    }
}

#[cfg(test)]
mod conn_enc_tests {
    use super::*;

    const TEST_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    // `REPROIT_CONN_ENC_KEY` is process-global; keep these env-mutating cases in a
    // single #[test] so they don't race other tests reading the same var.
    #[test]
    fn encrypt_at_rest_roundtrips_and_falls_back_to_plaintext() {
        let conn = "postgres://user:s3cret@db.internal:5432/tenant_42";

        // --- key set: ciphertext is opaque (no secret leaks), and round-trips ---
        std::env::set_var("REPROIT_CONN_ENC_KEY", TEST_KEY_HEX);
        let stored = encrypt_conn(conn).unwrap();
        assert!(
            stored.starts_with(crate::db::secrets::CONN_ENC_PREFIX),
            "must be tagged enc:v1:"
        );
        assert!(
            !stored.contains("s3cret"),
            "secret must not appear in ciphertext"
        );
        assert_eq!(decrypt_conn(&stored).unwrap(), conn, "round-trips");

        // Fresh nonce per write: two encryptions of the same input differ.
        let stored2 = encrypt_conn(conn).unwrap();
        assert_ne!(stored, stored2, "nonce must be random per write");
        assert_eq!(decrypt_conn(&stored2).unwrap(), conn);

        // A legacy plaintext value (no prefix) still reads back verbatim.
        assert_eq!(
            decrypt_conn(conn).unwrap(),
            conn,
            "legacy plaintext passthrough"
        );

        // --- key unset: store plaintext (dev), and read it back unchanged ---
        std::env::remove_var("REPROIT_CONN_ENC_KEY");
        let stored_plain = encrypt_conn(conn).unwrap();
        assert_eq!(stored_plain, conn, "no key => plaintext storage");
        assert_eq!(decrypt_conn(&stored_plain).unwrap(), conn);

        // An encrypted value with the key gone is a decrypt error (not a panic).
        assert!(
            decrypt_conn(&stored).is_err(),
            "encrypted value needs the key"
        );
    }
}
