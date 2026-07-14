//! The CONTROL-PLANE store: the one small shared Postgres that knows about
//! local identity and routing metadata, and NEVER holds customer telemetry or videos.
//!
//! Under database-per-org this is the only cross-tenant database. It holds exactly
//! what must be queryable BEFORE a tenant is resolved (you log in, THEN we resolve
//! your org -> tenant) or what is the routing key itself:
//!   - identity: `users`, `sessions`
//!   - local workspace membership: `orgs`, `org_members`
//!   - the routing keys: `api_keys` (a CLI/SDK key names its tenant) and the
//!     `tenants` registry (org id -> connection string + blob scope + status)
//!
//! App-scoped data (errors, evidence, triage, jobs, ...) does NOT live here; it
//! lives in the per-tenant database behind `tenants.db_conn`. See
//! `crate::db::tenant::TenantStore`.

use super::{Member, Org, TenantRecord, TenantStatus, User};
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
CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS orgs (
  id              BIGSERIAL PRIMARY KEY,
  name            TEXT NOT NULL,
  personal        BOOLEAN NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS personal        BOOLEAN NOT NULL DEFAULT false;
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
    #[cfg(test)]
    pub(crate) fn pool(&self) -> &PgPool {
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

    // ---- tenant registry (the routing table) -------------------------------

    /// Insert (or adopt) a tenant row in `provisioning`. Idempotent on org_id so a
    /// retried signup adopts the in-flight row rather than failing. Returns the
    /// current record after the upsert.
    pub async fn begin_provisioning(&self, org_id: i64) -> anyhow::Result<TenantRecord> {
        sqlx::query(
            "INSERT INTO tenants (org_id, status) VALUES ($1, 'provisioning')
             ON CONFLICT (org_id) DO UPDATE SET updated_at = now()",
        )
        .bind(org_id)
        .execute(&self.pool)
        .await?;
        self.tenant(org_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("tenant row vanished after insert"))
    }

    /// Record the provisioned connection string for a tenant (idempotent overwrite).
    /// The conn string is encrypted at rest before storage (no-op passthrough when
    /// REPROIT_CONN_ENC_KEY is unset; see [`encrypt_conn`]).
    pub async fn set_tenant_conn(&self, org_id: i64, db_conn: &str) -> anyhow::Result<()> {
        let stored = encrypt_conn(db_conn)?;
        sqlx::query("UPDATE tenants SET db_conn = $2, updated_at = now() WHERE org_id = $1")
            .bind(org_id)
            .bind(stored)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Record the blob scope (mode + scope key) for a tenant (idempotent).
    pub async fn set_tenant_blob(
        &self,
        org_id: i64,
        mode: &str,
        scope: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE tenants SET blob_mode = $2, blob_scope = $3, updated_at = now() WHERE org_id = $1",
        )
        .bind(org_id)
        .bind(mode)
        .bind(scope)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Flip a tenant's lifecycle status (provisioning -> active, active ->
    /// suspended, ...). The resolver only serves `active` tenants.
    pub async fn set_tenant_status(&self, org_id: i64, status: TenantStatus) -> anyhow::Result<()> {
        sqlx::query("UPDATE tenants SET status = $2, updated_at = now() WHERE org_id = $1")
            .bind(org_id)
            .bind(status.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The tenant record for an org, or None if the org has no tenant row yet.
    pub async fn tenant(&self, org_id: i64) -> anyhow::Result<Option<TenantRecord>> {
        let row = sqlx::query(
            "SELECT org_id, status, db_conn, blob_mode, blob_scope, region FROM tenants WHERE org_id = $1",
        )
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_tenant))
    }

    /// Every tenant the fleet sweep must visit, ordered for a
    /// stable, resumable sweep. Includes only tenants that have a connection string
    /// (a still-`provisioning` row with no DB yet has nothing to sweep).
    pub async fn all_tenants(&self) -> anyhow::Result<Vec<TenantRecord>> {
        let rows = sqlx::query(
            "SELECT org_id, status, db_conn, blob_mode, blob_scope, region FROM tenants
             WHERE db_conn IS NOT NULL ORDER BY org_id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_tenant).collect())
    }

    // ---- worker-claim routing hint (tenant_pending_shards) -----------------
    // See the table comment in CONTROL_SCHEMA for the correctness invariant: a
    // tenant MUST be present whenever it has >=1 pending shard; over-inclusion is
    // harmless and self-heals, under-inclusion starves shards.

    /// Mark a tenant as having pending work to claim. Called on EVERY transition
    /// INTO pending (job submission, requeue-stranded). Idempotent: a no-op if the
    /// tenant is already marked, so repeated marks are cheap.
    pub async fn mark_tenant_pending(&self, org_id: i64) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO tenant_pending_shards (org_id, updated_at) VALUES ($1, now())
             ON CONFLICT (org_id) DO UPDATE SET updated_at = now()",
        )
        .bind(org_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Clear a tenant from the pending set. The caller MUST have just observed a
    /// fresh `COUNT(*) WHERE state='pending' == 0` for this tenant; clearing on a
    /// mere empty claim (which can mean "all locked by other workers") would strand
    /// a later requeue.
    pub async fn clear_tenant_pending(&self, org_id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM tenant_pending_shards WHERE org_id = $1")
            .bind(org_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The org ids the worker fleet should try to claim from (presence = "has >=1
    /// pending shard"). The claim path resolves each to its tenant store and claims;
    /// a tenant whose fresh pending count is 0 is then cleared by the caller.
    pub async fn tenants_with_pending(&self) -> anyhow::Result<Vec<i64>> {
        let rows = sqlx::query("SELECT org_id FROM tenant_pending_shards ORDER BY org_id")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(|r| r.get::<i64, _>("org_id")).collect())
    }

    /// Offboard: delete the org row; members, API keys, the tenants row, seats,
    /// and usage counters cascade. Audit rows survive (no FK) as the record of
    /// the offboarding itself. Returns whether an org was deleted.
    pub async fn delete_org(&self, org_id: i64) -> anyhow::Result<bool> {
        let r = sqlx::query("DELETE FROM orgs WHERE id = $1")
            .bind(org_id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    // ---- users / sessions --------------------------------------------------

    pub async fn create_user(&self, email: &str, pass_hash: &str) -> anyhow::Result<i64> {
        let row = sqlx::query("INSERT INTO users (email, pass_hash) VALUES ($1,$2) RETURNING id")
            .bind(email)
            .bind(pass_hash)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("id"))
    }

    pub async fn user_auth_by_email(&self, email: &str) -> anyhow::Result<Option<(i64, String)>> {
        let row = sqlx::query("SELECT id, pass_hash FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| (r.get::<i64, _>("id"), r.get::<String, _>("pass_hash"))))
    }

    pub async fn find_user_id_by_email(&self, email: &str) -> anyhow::Result<Option<i64>> {
        let row = sqlx::query("SELECT id FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<i64, _>("id")))
    }

    // Sessions are stored HASHED (same SHA-256 scheme as API keys): a leaked DB
    // dump or backup must not yield live 30-day sessions. The raw token exists
    // only in the user's cookie; every query binds key_hash(token).
    pub async fn create_session(
        &self,
        token: &str,
        user_id: i64,
        ttl_secs: i64,
    ) -> anyhow::Result<()> {
        let expires = chrono::Utc::now() + chrono::Duration::seconds(ttl_secs);
        sqlx::query("INSERT INTO sessions (token, user_id, expires_at) VALUES ($1,$2,$3)")
            .bind(super::key_hash(token))
            .bind(user_id)
            .bind(expires)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn user_for_session(&self, token: &str) -> anyhow::Result<Option<User>> {
        let row = sqlx::query(
            "SELECT u.id, u.email FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token = $1 AND (s.expires_at IS NULL OR s.expires_at > now())",
        )
        .bind(super::key_hash(token))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| User {
            id: r.get::<i64, _>("id"),
            email: r.get::<String, _>("email"),
        }))
    }

    /// Append a security-audit row. Fire-and-forget by design: auditing must
    /// never fail (or slow the tail of) the request being audited, so failures
    /// are logged and swallowed here rather than surfaced to the caller.
    pub async fn audit(
        &self,
        actor: &str,
        action: &str,
        org_id: Option<i64>,
        detail: serde_json::Value,
    ) {
        let r = sqlx::query(
            "INSERT INTO audit_log (actor, action, org_id, detail) VALUES ($1,$2,$3,$4)",
        )
        .bind(actor)
        .bind(action)
        .bind(org_id)
        .bind(detail)
        .execute(&self.pool)
        .await;
        if let Err(e) = r {
            tracing::warn!("audit write failed ({actor} {action}): {e}");
        }
    }

    /// The most recent audit rows for one org, NEWEST FIRST. The table was
    /// write-only until this read; the ops CLI (`audit <org>`) is its first
    /// consumer. One indexed backward scan (`audit_log_org` is (org_id, id)),
    /// bounded by `limit`.
    pub async fn audit_for_org(&self, org_id: i64, limit: i64) -> anyhow::Result<Vec<AuditRow>> {
        let rows = sqlx::query(
            "SELECT actor, action, detail, at FROM audit_log
             WHERE org_id = $1 ORDER BY id DESC LIMIT $2",
        )
        .bind(org_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| AuditRow {
                actor: r.get::<String, _>("actor"),
                action: r.get::<String, _>("action"),
                detail: r.get::<serde_json::Value, _>("detail"),
                at: r.get::<chrono::DateTime<chrono::Utc>, _>("at").to_rfc3339(),
            })
            .collect())
    }

    pub async fn prune_sessions(&self) -> anyhow::Result<u64> {
        let r =
            sqlx::query("DELETE FROM sessions WHERE expires_at IS NOT NULL AND expires_at < now()")
                .execute(&self.pool)
                .await?;
        Ok(r.rows_affected())
    }

    pub async fn delete_session(&self, token: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(super::key_hash(token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---- orgs / membership -------------------------------------------------

    pub async fn create_org(&self, name: &str, personal: bool) -> anyhow::Result<i64> {
        let row = sqlx::query("INSERT INTO orgs (name, personal) VALUES ($1,$2) RETURNING id")
            .bind(name)
            .bind(personal)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("id"))
    }

    pub async fn add_member(&self, org_id: i64, user_id: i64, role: &str) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,$3)
             ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role",
        )
        .bind(org_id)
        .bind(user_id)
        .bind(role)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn primary_org(&self, user_id: i64) -> anyhow::Result<Option<Org>> {
        let row = sqlx::query(
            "SELECT o.id, o.name, m.role
             FROM org_members m JOIN orgs o ON o.id = m.org_id
             WHERE m.user_id = $1
             ORDER BY o.personal DESC, o.id ASC LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_org))
    }

    pub async fn org_role(&self, org_id: i64, user_id: i64) -> anyhow::Result<Option<String>> {
        let row = sqlx::query("SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<String, _>("role")))
    }

    pub async fn count_owners(&self, org_id: i64) -> anyhow::Result<i64> {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM org_members WHERE org_id = $1 AND role = 'owner'",
        )
        .bind(org_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(n)
    }

    pub async fn set_member_role(
        &self,
        org_id: i64,
        user_id: i64,
        role: &str,
    ) -> anyhow::Result<bool> {
        let r = sqlx::query("UPDATE org_members SET role = $3 WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .bind(role)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn list_org_users(&self, org_id: i64) -> anyhow::Result<Vec<Member>> {
        let rows = sqlx::query(
            "WITH scoped AS (
               SELECT user_id FROM org_members WHERE org_id = $1
               UNION
               SELECT user_id FROM directory_users WHERE org_id = $1 AND active
             )
             SELECT u.id AS user_id, u.email, COALESCE(m.role, 'none') AS role,
                    (COALESCE(m.seat, false) OR m.role = 'owner') AS seat
             FROM scoped s
             JOIN users u ON u.id = s.user_id
             LEFT JOIN org_members m ON m.org_id = $1 AND m.user_id = s.user_id
             ORDER BY (m.role='owner') DESC NULLS LAST, (m.role IS NULL) ASC, u.email",
        )
        .bind(org_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Member {
                user_id: r.get::<i64, _>("user_id"),
                email: r.get::<String, _>("email"),
                role: r.get::<String, _>("role"),
                seat: r.get::<bool, _>("seat"),
            })
            .collect())
    }

    pub async fn remove_member(&self, org_id: i64, user_id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn org_name(&self, org_id: i64) -> anyhow::Result<Option<String>> {
        let row = sqlx::query("SELECT name FROM orgs WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<String, _>("name")))
    }

    // ---- per-workspace dashboard access -------------------------------------

    pub async fn has_seat(&self, org_id: i64, user_id: i64) -> anyhow::Result<bool> {
        let row = sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM org_members
             WHERE org_id = $1 AND user_id = $2 AND (seat OR role = 'owner')",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    pub async fn set_seat(&self, org_id: i64, user_id: i64, seat: bool) -> anyhow::Result<bool> {
        let r = sqlx::query("UPDATE org_members SET seat = $3 WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .bind(seat)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    // ---- api keys (the CLI/SDK routing key) --------------------------------

    pub async fn create_api_key(
        &self,
        secret: &str,
        prefix: &str,
        org_id: i64,
        created_by: i64,
        project_id: Option<i64>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO api_keys (key, prefix, org_id, created_by, project_id) VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(super::key_hash(secret))
        .bind(prefix)
        .bind(org_id)
        .bind(created_by)
        .bind(project_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_api_keys(&self, org_id: i64) -> anyhow::Result<Vec<String>> {
        let rows = sqlx::query("SELECT prefix FROM api_keys WHERE org_id = $1 ORDER BY created_at")
            .bind(org_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("prefix"))
            .collect())
    }

    /// (org_id, project_id, created_by) that owns an API key. This is the hot
    /// per-request routing read: the org id it returns is
    /// what the resolver maps to a tenant database. `project_id` is the tenant-db
    /// project the key was minted for (None for org-wide keys); ingest uses it to
    /// pin a publishable key to its own app.
    pub async fn org_for_api_key(
        &self,
        presented: &str,
    ) -> anyhow::Result<Option<(i64, Option<i64>, Option<i64>)>> {
        let row = sqlx::query(
            "SELECT o.id, k.project_id, k.created_by
             FROM api_keys k
             JOIN orgs o ON o.id = k.org_id
             WHERE k.key = $1
               AND k.active
               AND (k.expires_at IS NULL OR k.expires_at > now())",
        )
        .bind(super::key_hash(presented))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            (
                r.get::<i64, _>("id"),
                r.get::<Option<i64>, _>("project_id"),
                r.get::<Option<i64>, _>("created_by"),
            )
        }))
    }

    /// Hard-delete an API key by its secret (compensating cleanup when the second
    /// half of a dual-key mint fails; the key was never returned to anyone).
    pub async fn delete_api_key(&self, secret: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM api_keys WHERE key = $1")
            .bind(super::key_hash(secret))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Revoke earlier browser keys for a project before returning a replacement.
    /// Secret management keys are untouched (`key_prefix` records the pk/sk
    /// family without storing the credential itself).
    pub async fn revoke_publishable_keys_for_project(&self, project_id: i64) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE api_keys SET active = false WHERE project_id = $1 AND key_prefix LIKE 'pk_live_%'",
        )
        .bind(project_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn org_exists(&self, org_id: i64) -> anyhow::Result<bool> {
        let row = sqlx::query_scalar::<_, i32>("SELECT 1 FROM orgs WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }
}

fn row_to_org(r: sqlx::postgres::PgRow) -> Org {
    Org {
        id: r.get::<i64, _>("id"),
        name: r.get::<String, _>("name"),
        role: r.get::<String, _>("role"),
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
