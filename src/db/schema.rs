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
CREATE INDEX IF NOT EXISTS shards_claimable
  ON shards(backend, job_id, seed) WHERE state='pending';
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
CREATE TABLE IF NOT EXISTS bucket_summaries (
  app_id         TEXT NOT NULL,
  bucket_id      TEXT NOT NULL,
  count          BIGINT NOT NULL,
  first_error_id BIGINT NOT NULL,
  last_error_id  BIGINT NOT NULL,
  first_seen     TIMESTAMPTZ NOT NULL,
  last_seen      TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (app_id, bucket_id)
);
CREATE INDEX IF NOT EXISTS bucket_summaries_app_last
  ON bucket_summaries(app_id, last_seen DESC);
CREATE TABLE IF NOT EXISTS bucket_windows (
  app_id       TEXT NOT NULL,
  bucket_id    TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  build        TEXT NOT NULL DEFAULT '',
  count        BIGINT NOT NULL,
  PRIMARY KEY (app_id, bucket_id, window_start, build)
);
CREATE INDEX IF NOT EXISTS bucket_windows_app_bucket
  ON bucket_windows(app_id, bucket_id, window_start);
CREATE TABLE IF NOT EXISTS app_context_counts (
  app_id TEXT NOT NULL,
  key    TEXT NOT NULL,
  value  TEXT NOT NULL,
  count  BIGINT NOT NULL,
  PRIMARY KEY (app_id, key, value)
);
CREATE TABLE IF NOT EXISTS bucket_context_counts (
  app_id    TEXT NOT NULL,
  bucket_id TEXT NOT NULL,
  key       TEXT NOT NULL,
  value     TEXT NOT NULL,
  count     BIGINT NOT NULL,
  PRIMARY KEY (app_id, bucket_id, key, value)
);
CREATE INDEX IF NOT EXISTS bucket_context_counts_bucket
  ON bucket_context_counts(app_id, bucket_id);
CREATE OR REPLACE FUNCTION remove_error_from_read_models() RETURNS TRIGGER AS $$
DECLARE
  dimension RECORD;
BEGIN
  UPDATE bucket_summaries SET count=count-1
  WHERE app_id=OLD.app_id AND bucket_id=OLD.bucket_id;
  DELETE FROM bucket_summaries
  WHERE app_id=OLD.app_id AND bucket_id=OLD.bucket_id AND count <= 0;
  IF EXISTS (
    SELECT 1 FROM bucket_summaries
    WHERE app_id=OLD.app_id AND bucket_id=OLD.bucket_id
      AND (first_error_id=OLD.id OR last_error_id=OLD.id)
  ) THEN
    UPDATE bucket_summaries SET
      first_error_id=remaining.first_id,
      last_error_id=remaining.last_id,
      first_seen=remaining.first_seen,
      last_seen=remaining.last_seen
    FROM (
      SELECT MIN(id) AS first_id, MAX(id) AS last_id,
             MIN(created_at) AS first_seen, MAX(created_at) AS last_seen
      FROM errors WHERE app_id=OLD.app_id AND bucket_id=OLD.bucket_id
    ) remaining
    WHERE app_id=OLD.app_id AND bucket_id=OLD.bucket_id;
  END IF;

  UPDATE bucket_windows SET count=count-1
  WHERE app_id=OLD.app_id AND bucket_id=OLD.bucket_id
    AND window_start=date_trunc('hour', OLD.created_at)
    AND build=COALESCE(OLD.context->'build'->>'commit', OLD.context->'build'->>'version', '');
  DELETE FROM bucket_windows
  WHERE app_id=OLD.app_id AND bucket_id=OLD.bucket_id AND count <= 0;

  FOR dimension IN
    SELECT key,
      CASE
        WHEN jsonb_typeof(value)='string' THEN value #>> '{}'
        WHEN jsonb_typeof(value) IN ('number','boolean') THEN value::TEXT
        WHEN key='build' THEN COALESCE(value->>'version', value->>'commit')
      END AS value
    FROM jsonb_each(OLD.context)
    WHERE key NOT IN ('fingerprint','input','inputs')
      AND (jsonb_typeof(value) IN ('string','number','boolean') OR key='build')
  LOOP
    IF dimension.value IS NOT NULL THEN
      UPDATE app_context_counts SET count=count-1
      WHERE app_id=OLD.app_id AND key=dimension.key AND value=dimension.value;
      DELETE FROM app_context_counts
      WHERE app_id=OLD.app_id AND key=dimension.key AND value=dimension.value AND count <= 0;
      UPDATE bucket_context_counts SET count=count-1
      WHERE app_id=OLD.app_id AND bucket_id=OLD.bucket_id
        AND key=dimension.key AND value=dimension.value;
      DELETE FROM bucket_context_counts
      WHERE app_id=OLD.app_id AND bucket_id=OLD.bucket_id
        AND key=dimension.key AND value=dimension.value AND count <= 0;
    END IF;
  END LOOP;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS error_read_model_delete ON errors;
CREATE TRIGGER error_read_model_delete
AFTER DELETE ON errors
FOR EACH ROW EXECUTE FUNCTION remove_error_from_read_models();
-- Every accepted SDK batch is production traffic, including a clean batch with
-- no errors. Resolution uses this instead of counting unrelated failures as the
-- denominator for "the fixed build has seen enough real use".
CREATE TABLE IF NOT EXISTS build_traffic (
  app_id     TEXT        NOT NULL,
  build      TEXT        NOT NULL,
  count      BIGINT      NOT NULL DEFAULT 0,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, build)
);
CREATE INDEX IF NOT EXISTS build_traffic_app_first
  ON build_traffic(app_id, first_seen);
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
CREATE INDEX IF NOT EXISTS evidence_app_id ON evidence(app_id, id) INCLUDE (bytes);
CREATE TABLE IF NOT EXISTS app_storage_usage (
  app_id TEXT PRIMARY KEY,
  bytes  BIGINT NOT NULL DEFAULT 0 CHECK (bytes >= 0)
);
CREATE OR REPLACE FUNCTION update_app_storage_usage() RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO app_storage_usage (app_id, bytes) VALUES (NEW.app_id, NEW.bytes)
    ON CONFLICT (app_id) DO UPDATE SET bytes=app_storage_usage.bytes + EXCLUDED.bytes;
    RETURN NEW;
  END IF;
  UPDATE app_storage_usage SET bytes=GREATEST(0, bytes - OLD.bytes) WHERE app_id=OLD.app_id;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS evidence_storage_usage ON evidence;
CREATE TRIGGER evidence_storage_usage
AFTER INSERT OR DELETE ON evidence
FOR EACH ROW EXECUTE FUNCTION update_app_storage_usage();
INSERT INTO app_storage_usage (app_id, bytes)
SELECT app_id, COALESCE(SUM(bytes), 0)::BIGINT FROM evidence GROUP BY app_id
ON CONFLICT (app_id) DO UPDATE SET bytes=EXCLUDED.bytes;

-- Immutable evidence graphs. Node ids are hashes of kind, parents, and payload;
-- roots attach a validated graph to a run without copying node content.
CREATE TABLE IF NOT EXISTS artifact_nodes (
  app_id     TEXT  NOT NULL,
  node_id    TEXT  NOT NULL,
  kind       TEXT  NOT NULL,
  parents    JSONB NOT NULL,
  payload    JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, node_id)
);
CREATE TABLE IF NOT EXISTS artifact_roots (
  app_id     TEXT NOT NULL,
  run_id     TEXT NOT NULL,
  root_id    TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, run_id, root_id),
  FOREIGN KEY (app_id, root_id) REFERENCES artifact_nodes(app_id, node_id)
);
CREATE INDEX IF NOT EXISTS artifact_roots_run ON artifact_roots(app_id, run_id);

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
CREATE INDEX IF NOT EXISTS processed_batches_created_at ON processed_batches(created_at);

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
CREATE TABLE IF NOT EXISTS integration_outbox (
  id         BIGSERIAL PRIMARY KEY,
  app_id     TEXT NOT NULL,
  bucket_id  TEXT NOT NULL,
  kind       TEXT NOT NULL,
  attempts   INT NOT NULL DEFAULT 0,
  available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (app_id, bucket_id, kind)
);
CREATE INDEX IF NOT EXISTS integration_outbox_available
  ON integration_outbox(available_at, id);

-- Populate durable read models for databases created before the rollups.
INSERT INTO bucket_summaries
  (app_id, bucket_id, count, first_error_id, last_error_id, first_seen, last_seen)
SELECT app_id, bucket_id, COUNT(*)::BIGINT, MIN(id), MAX(id), MIN(created_at), MAX(created_at)
FROM errors WHERE bucket_id IS NOT NULL GROUP BY app_id, bucket_id
ON CONFLICT (app_id, bucket_id) DO NOTHING;
INSERT INTO build_traffic (app_id, build, count, first_seen, last_seen)
SELECT app_id, COALESCE(context->'build'->>'commit', context->'build'->>'version'),
       COUNT(*)::BIGINT, MIN(created_at), MAX(created_at)
FROM errors
WHERE COALESCE(context->'build'->>'commit', context->'build'->>'version') IS NOT NULL
GROUP BY app_id, COALESCE(context->'build'->>'commit', context->'build'->>'version')
ON CONFLICT (app_id, build) DO NOTHING;
INSERT INTO bucket_windows (app_id, bucket_id, window_start, build, count)
SELECT app_id, bucket_id, date_trunc('hour', created_at),
       COALESCE(context->'build'->>'commit', context->'build'->>'version', ''), COUNT(*)::BIGINT
FROM errors WHERE bucket_id IS NOT NULL
GROUP BY app_id, bucket_id, date_trunc('hour', created_at),
         COALESCE(context->'build'->>'commit', context->'build'->>'version', '')
ON CONFLICT (app_id, bucket_id, window_start, build) DO NOTHING;
INSERT INTO app_context_counts (app_id, key, value, count)
SELECT app_id, key,
       CASE
         WHEN jsonb_typeof(value)='string' THEN value #>> '{}'
         WHEN jsonb_typeof(value) IN ('number','boolean') THEN value::TEXT
         WHEN key='build' THEN COALESCE(value->>'version', value->>'commit')
       END,
       COUNT(*)::BIGINT
FROM errors CROSS JOIN LATERAL jsonb_each(context)
WHERE key NOT IN ('fingerprint','input','inputs')
  AND (jsonb_typeof(value) IN ('string','number','boolean') OR key='build')
  AND (key <> 'build' OR COALESCE(value->>'version', value->>'commit') IS NOT NULL)
GROUP BY app_id, key,
         CASE
           WHEN jsonb_typeof(value)='string' THEN value #>> '{}'
           WHEN jsonb_typeof(value) IN ('number','boolean') THEN value::TEXT
           WHEN key='build' THEN COALESCE(value->>'version', value->>'commit')
         END
ON CONFLICT (app_id, key, value) DO NOTHING;
INSERT INTO bucket_context_counts (app_id, bucket_id, key, value, count)
SELECT app_id, bucket_id, key,
       CASE
         WHEN jsonb_typeof(value)='string' THEN value #>> '{}'
         WHEN jsonb_typeof(value) IN ('number','boolean') THEN value::TEXT
         WHEN key='build' THEN COALESCE(value->>'version', value->>'commit')
       END,
       COUNT(*)::BIGINT
FROM errors CROSS JOIN LATERAL jsonb_each(context)
WHERE bucket_id IS NOT NULL
  AND key NOT IN ('fingerprint','input','inputs')
  AND (jsonb_typeof(value) IN ('string','number','boolean') OR key='build')
  AND (key <> 'build' OR COALESCE(value->>'version', value->>'commit') IS NOT NULL)
GROUP BY app_id, bucket_id, key,
         CASE
           WHEN jsonb_typeof(value)='string' THEN value #>> '{}'
           WHEN jsonb_typeof(value) IN ('number','boolean') THEN value::TEXT
           WHEN key='build' THEN COALESCE(value->>'version', value->>'commit')
         END
ON CONFLICT (app_id, bucket_id, key, value) DO NOTHING;

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

-- ---- hosted reproduction runs (repository_dispatch ledger) --------------------
-- One row per dispatch fired into the customer's CI: run status for the
-- dashboard and staleness expiry. Execution happens in the customer's CI and
-- is deliberately not metered by Reproit.
CREATE TABLE IF NOT EXISTS cloud_runs (
  id            BIGSERIAL PRIMARY KEY,
  app_id        TEXT NOT NULL,
  bucket_id     TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'dispatched',
  requested_by  TEXT NOT NULL DEFAULT '',
  dispatched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at  TIMESTAMPTZ
);
-- Remove the obsolete pre-launch execution-duration field if an early database
-- was initialized with it. No product data depends on this column.
ALTER TABLE cloud_runs DROP COLUMN IF EXISTS minutes;
CREATE INDEX IF NOT EXISTS cloud_runs_app ON cloud_runs(app_id, bucket_id, id);
CREATE INDEX IF NOT EXISTS cloud_runs_open ON cloud_runs(dispatched_at) WHERE status='dispatched';
"#;

// v2 adds the human-authored capture tables to every tenant database.
const TENANT_SCHEMA_VERSION: i64 = 2;

/// Apply all unapplied tenant migrations. Each migration is idempotent, so a
/// process interruption retries the same version safely before recording it.
pub async fn apply(conn: &str) -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(conn)
        .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenant_schema_migrations (
           version BIGINT PRIMARY KEY,
           applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
         )",
    )
    .execute(&pool)
    .await?;
    let applied: Option<i64> =
        sqlx::query_scalar("SELECT MAX(version) FROM tenant_schema_migrations")
            .fetch_one(&pool)
            .await?;
    if applied.unwrap_or(0) < TENANT_SCHEMA_VERSION {
        sqlx::raw_sql(TENANT_SCHEMA).execute(&pool).await?;
        backfill_missing_bucket_ids(&pool).await?;
        // The first pass creates the rollup tables. Re-run the idempotent schema
        // after legacy bucket ids exist so their read models are populated too.
        sqlx::raw_sql(TENANT_SCHEMA).execute(&pool).await?;
        sqlx::query(
            "INSERT INTO tenant_schema_migrations (version) VALUES ($1)
             ON CONFLICT (version) DO NOTHING",
        )
        .bind(TENANT_SCHEMA_VERSION)
        .execute(&pool)
        .await?;
    }
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
