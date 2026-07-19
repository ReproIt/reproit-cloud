//! The TENANT-database schema, declared whole and applied idempotently
//! (`CREATE ... IF NOT EXISTS`), exactly like the control plane's
//! `CONTROL_SCHEMA`: at provision time for a fresh tenant and again on every
//! boot for existing ones, so a schema edit reaches every tenant on the next
//! deploy. PRE-LAUNCH POSTURE: there are no customers, so there is no
//! migration ledger; the schema file IS the truth and changes are edited in
//! place (add `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` alongside the CREATE
//! when reshaping an existing table). A versioned migration system can be
//! reintroduced when there are production tenants to migrate.
//!
//! Under database-per-org the tenant DB IS the org boundary, so app-scoped
//! tables carry NO `org_id`: there is nothing else in the database to leak.
//! `app_id` survives only to distinguish multiple projects/apps WITHIN one
//! org, never as a tenant boundary.

use sqlx::postgres::PgPoolOptions;
use sqlx::types::Json;
use sqlx::{PgPool, Row};

pub const TENANT_SCHEMA: &str = r#"
-- ---- fuzz jobs + shards (the per-tenant work queue) ---------------------------
CREATE TABLE IF NOT EXISTS jobs (
  id              TEXT PRIMARY KEY,
  app_dir         TEXT NOT NULL,
  budget          INT  NOT NULL,
  started_at      TEXT NOT NULL,
  finished_at     TEXT,
  map_states      INT  NOT NULL DEFAULT 0,
  map_transitions INT  NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS shards (
  job_id     TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  seed       INT  NOT NULL,
  state      TEXT NOT NULL,
  report     TEXT,
  duration_s DOUBLE PRECISION NOT NULL DEFAULT 0,
  backend      TEXT NOT NULL DEFAULT 'web',
  claimed_by   TEXT,
  claimed_at   TIMESTAMPTZ,
  heartbeat_at TIMESTAMPTZ,
  attempts     INT NOT NULL DEFAULT 0,
  PRIMARY KEY (job_id, seed)
);
ALTER TABLE shards ADD COLUMN IF NOT EXISTS backend      TEXT NOT NULL DEFAULT 'web';
ALTER TABLE shards ADD COLUMN IF NOT EXISTS claimed_by   TEXT;
ALTER TABLE shards ADD COLUMN IF NOT EXISTS claimed_at   TIMESTAMPTZ;
ALTER TABLE shards ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ;
ALTER TABLE shards ADD COLUMN IF NOT EXISTS attempts     INT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS shards_pending ON shards(state, backend);
-- The requeue-stranded sweep filters state='running' by heartbeat age; this
-- partial index matches that predicate exactly.
CREATE INDEX IF NOT EXISTS shards_running_heartbeat
  ON shards(heartbeat_at) WHERE state='running';

-- ---- production telemetry: edges / errors / evidence --------------------------
CREATE TABLE IF NOT EXISTS edges (
  app_id   TEXT   NOT NULL,
  edge_key TEXT   NOT NULL,
  count    BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (app_id, edge_key)
);
CREATE TABLE IF NOT EXISTS errors (
  id         BIGSERIAL PRIMARY KEY,
  app_id     TEXT  NOT NULL,
  sig        TEXT  NOT NULL,
  message    TEXT  NOT NULL,
  path       JSONB NOT NULL,
  context    JSONB NOT NULL DEFAULT '{}'::jsonb,
  -- The content-addressed bucket id, MATERIALIZED at insert time
  -- (ingest::buckets::bucket_id) so per-bucket reads are one indexed query
  -- instead of a scan-and-regroup of the app's whole history.
  bucket_id  TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE errors ADD COLUMN IF NOT EXISTS bucket_id TEXT;
CREATE INDEX IF NOT EXISTS errors_app ON errors(app_id, id);
CREATE INDEX IF NOT EXISTS errors_bucket ON errors(app_id, bucket_id, id);
-- Retention pruning deletes errors by age.
CREATE INDEX IF NOT EXISTS errors_created ON errors(created_at);
CREATE TABLE IF NOT EXISTS evidence (
  id          BIGSERIAL PRIMARY KEY,
  app_id      TEXT  NOT NULL,
  error_id    BIGINT NOT NULL REFERENCES errors(id) ON DELETE CASCADE,
  kind        TEXT  NOT NULL,
  storage_key TEXT NOT NULL,
  bytes       BIGINT NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS evidence_error ON evidence(error_id, id);

-- ---- ingest idempotency: consumed batch ids ------------------------------------
-- An SDK retry after a network timeout re-POSTs the same batch; the batchId
-- (client-generated, optional) makes the second write a no-op instead of
-- double-counting. Rows are pruned after a short horizon (a retry storm is
-- minutes, not days).
CREATE TABLE IF NOT EXISTS processed_batches (
  app_id     TEXT NOT NULL,
  batch_id   TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, batch_id)
);

-- ---- reproduction attempts + external ticket links ----------------------------
CREATE TABLE IF NOT EXISTS replay_results (
  id             BIGSERIAL PRIMARY KEY,
  app_id         TEXT NOT NULL,
  bucket_id      TEXT NOT NULL,
  status         TEXT NOT NULL,
  runs           INT  NOT NULL DEFAULT 0,
  failures       INT  NOT NULL DEFAULT 0,
  local_repro_id TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS replay_results_bucket ON replay_results(app_id, bucket_id, id);
CREATE TABLE IF NOT EXISTS bucket_tickets (
  app_id       TEXT NOT NULL,
  bucket_id    TEXT NOT NULL,
  provider     TEXT NOT NULL DEFAULT 'github',
  repo         TEXT NOT NULL,
  external_id  TEXT NOT NULL,
  url          TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, bucket_id)
);

-- ---- projects (the org's apps) -------------------------------------------------
-- `created_by` references a control-plane user id, so it is a plain BIGINT here
-- (no cross-database FK); the value is informational.
CREATE TABLE IF NOT EXISTS projects (
  id         BIGSERIAL PRIMARY KEY,
  created_by BIGINT,
  name       TEXT NOT NULL,
  app_id     TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS projects_app ON projects(app_id);

-- ---- human-authored original captures -----------------------------------------
-- A capture is a report, not a confirmed bug. Its immutable local id remains the
-- primary key through browser review, upload, and later derived reproductions.
CREATE TABLE IF NOT EXISTS captures (
  id                TEXT PRIMARY KEY,
  review_token_hash TEXT UNIQUE NOT NULL,
  created_by        BIGINT,
  app_id            TEXT REFERENCES projects(app_id) ON DELETE CASCADE,
  status            TEXT NOT NULL DEFAULT 'pending_review',
  title             TEXT,
  description       TEXT,
  severity          TEXT NOT NULL DEFAULT 'normal',
  visibility        TEXT NOT NULL DEFAULT 'project',
  platform          TEXT NOT NULL,
  target            TEXT NOT NULL,
  source_created_at TEXT NOT NULL,
  manifest          JSONB NOT NULL,
  expires_at        TIMESTAMPTZ NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS captures_app ON captures(app_id, created_at DESC);
CREATE TABLE IF NOT EXISTS capture_files (
  capture_id   TEXT NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
  filename     TEXT NOT NULL,
  storage_key  TEXT NOT NULL,
  bytes        BIGINT NOT NULL,
  sha256       TEXT NOT NULL,
  content_type TEXT NOT NULL,
  uploaded     BOOLEAN NOT NULL DEFAULT false,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (capture_id, filename)
);

-- ---- triage + resolution state --------------------------------------------------
-- `assignee` references a control-plane user id (plain BIGINT, no cross-db FK).
-- Within-tenant assignment validity (assignee is a member of THIS org) is checked
-- in the handler against the control plane, not enforced by an FK here.
CREATE TABLE IF NOT EXISTS bucket_triage (
  app_id         TEXT NOT NULL,
  bucket_id      TEXT NOT NULL,
  status         TEXT NOT NULL DEFAULT 'untriaged',
  assignee       BIGINT,
  fixed_in_build TEXT,
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, bucket_id)
);
CREATE INDEX IF NOT EXISTS bucket_triage_assignee ON bucket_triage(assignee);
CREATE TABLE IF NOT EXISTS bucket_resolution_status (
  app_id     TEXT NOT NULL,
  bucket_id  TEXT NOT NULL,
  status     TEXT NOT NULL,
  build      TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, bucket_id)
);
CREATE TABLE IF NOT EXISTS bucket_resolution_events (
  id          BIGSERIAL PRIMARY KEY,
  app_id      TEXT NOT NULL,
  bucket_id   TEXT NOT NULL,
  from_status TEXT,
  to_status   TEXT NOT NULL,
  build       TEXT,
  at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS bucket_resolution_events_app ON bucket_resolution_events(app_id, id DESC);

-- ---- per-app tracker + reproduction-dispatch configuration --------------------
-- Tokens are encrypted at rest (db::secrets, same key as tenant conn strings).
-- `extra` carries provider-specific knobs (jira project key / transition id,
-- linear team id, shortcut project id, ...) so new providers don't need new
-- columns. `dispatch_repo` + `dispatch_token_enc` bind the app to the customer
-- repo whose CI runs reproduction via repository_dispatch.
CREATE TABLE IF NOT EXISTS project_integrations (
  app_id             TEXT PRIMARY KEY,
  provider           TEXT NOT NULL DEFAULT 'github',
  repo               TEXT,
  base_url           TEXT,
  user_email         TEXT,
  extra              JSONB NOT NULL DEFAULT '{}'::jsonb,
  token_enc          TEXT,
  dispatch_repo      TEXT,
  dispatch_token_enc TEXT,
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---- CI reproduction runs (repository_dispatch ledger) ------------------------
-- One row per dispatch fired into the customer's CI: run status for the
-- dashboard and staleness expiry.
-- reported by the CI run via POST replay-results {runId}.
CREATE TABLE IF NOT EXISTS cloud_runs (
  id            BIGSERIAL PRIMARY KEY,
  app_id        TEXT NOT NULL,
  bucket_id     TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'dispatched',
  requested_by  TEXT NOT NULL DEFAULT '',
  dispatched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS cloud_runs_app ON cloud_runs(app_id, bucket_id, id);
CREATE INDEX IF NOT EXISTS cloud_runs_open ON cloud_runs(dispatched_at) WHERE status='dispatched';
"#;

/// Apply the tenant schema to the database at `conn` (idempotent). Used by the
/// provisioner for fresh tenants and by the boot sweep for existing ones.
pub async fn apply(conn: &str) -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(conn)
        .await?;
    sqlx::raw_sql(TENANT_SCHEMA).execute(&pool).await?;
    backfill_missing_bucket_ids(&pool).await?;
    pool.close().await;
    Ok(())
}

async fn backfill_missing_bucket_ids(pool: &PgPool) -> anyhow::Result<()> {
    let rows = sqlx::query(
        "SELECT id, sig, message, path, context
         FROM errors
         WHERE bucket_id IS NULL
         ORDER BY id",
    )
    .fetch_all(pool)
    .await?;

    for row in rows {
        let id = row.get::<i64, _>("id");
        let Json(path): Json<Vec<crate::ingest::Step>> = row.get("path");
        let Json(context): Json<serde_json::Map<String, serde_json::Value>> = row.get("context");
        let rec = crate::ingest::ErrorRec {
            sig: row.get("sig"),
            message: row.get("message"),
            path,
            context,
        };
        let bucket_id = crate::ingest::buckets::bucket_id(&rec);
        sqlx::query("UPDATE errors SET bucket_id=$1 WHERE id=$2 AND bucket_id IS NULL")
            .bind(bucket_id)
            .bind(id)
            .execute(pool)
            .await?;
    }
    Ok(())
}
