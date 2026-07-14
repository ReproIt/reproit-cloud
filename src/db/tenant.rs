//! The TENANT-bound store: a handle on ONE org's database. Every method here runs
//! plain queries with NO `org_id` filter, because the database IS the org boundary
//! (see `docs/architecture/multi-tenancy.md`). A handler is handed a `TenantStore`
//! already bound to the caller's tenant; a cross-tenant read is physically
//! impossible because there is nothing else in this database to leak.
//!
//! This is the heart of why the self-hosted edition is free: the handlers are
//! single-tenant by construction. The SaaS picks WHICH database per request (the
//! resolver hands the right `TenantStore`); self-hosted always hands the same one.
//!
//! It owns the per-tenant pool but does NOT own its lifetime: pools are created,
//! cached, and idle-evicted by `crate::tenancy::pool::TenantPools` so thousands of
//! tenants never exhaust Postgres backends. A `TenantStore` is therefore cheap to
//! clone (an `Arc<PgPool>` inside) and short-lived per request.

use super::{ClaimedShard, Triage};
use crate::ingest::{ErrorRec, ReplayResult, Step};
use crate::jobs::{Job, ShardState};
use serde_json::{json, Value};
use sqlx::types::Json;
use sqlx::{PgPool, Row};
use std::sync::Arc;

/// A connection handle bound to one tenant's database. Clone is cheap (shares the
/// underlying pool). Handlers receive this, never a global store.
#[derive(Clone)]
pub struct TenantStore {
    pool: Arc<PgPool>,
}

/// A ticket link read back from a tenant DB (was `db::integrations::TicketLink`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct TicketLink {
    pub provider: String,
    pub repo: String,
    #[serde(rename = "externalId")]
    pub external_id: String,
    pub url: String,
}

/// One app's tracker + reproduction-dispatch config (`project_integrations`).
/// Token fields hold the ENCRYPTED (`db::secrets`) value exactly as stored;
/// decryption happens at the point of use, never here.
#[derive(Debug, Clone, Default)]
pub struct IntegrationRow {
    pub provider: String,
    pub repo: Option<String>,
    pub base_url: Option<String>,
    pub user_email: Option<String>,
    pub extra: Value,
    pub token_enc: Option<String>,
    pub dispatch_repo: Option<String>,
    pub dispatch_token_enc: Option<String>,
}

/// A bucket the regression sweep must evaluate (was `db::resolution::AnchoredBucket`).
#[derive(Debug, Clone)]
pub struct AnchoredBucket {
    pub app_id: String,
    pub bucket_id: String,
    pub fixed_in_build: String,
}

/// One persisted resolution-status transition (was `db::resolution::ResolutionEvent`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolutionEvent {
    #[serde(rename = "bucketId")]
    pub bucket_id: String,
    #[serde(rename = "fromStatus")]
    pub from_status: Option<String>,
    #[serde(rename = "toStatus")]
    pub to_status: String,
    pub build: Option<String>,
    pub at: String,
}

impl TenantStore {
    /// Wrap an already-acquired tenant pool. The pool's lifecycle (creation, idle
    /// eviction) is the `TenantPools` manager's job; this just binds queries to it.
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// Liveness probe against the tenant DB. (Available for a per-tenant readiness
    /// check; the top-level `/ready` probes the control plane.)
    #[allow(dead_code)]
    pub async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(self.pool.as_ref())
            .await?;
        Ok(())
    }

    // ---- projects (the org's apps, now in the tenant db) -------------------

    pub async fn create_project(
        &self,
        created_by: i64,
        name: &str,
        app_id: &str,
    ) -> anyhow::Result<i64> {
        let row = sqlx::query(
            "INSERT INTO projects (created_by, name, app_id) VALUES ($1,$2,$3) RETURNING id",
        )
        .bind(created_by)
        .bind(name)
        .bind(app_id)
        .fetch_one(self.pool.as_ref())
        .await?;
        Ok(row.get::<i64, _>("id"))
    }

    pub async fn list_projects(&self) -> anyhow::Result<Vec<(i64, String, String)>> {
        let rows = sqlx::query("SELECT id, name, app_id FROM projects ORDER BY id")
            .fetch_all(self.pool.as_ref())
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<i64, _>("id"),
                    r.get::<String, _>("name"),
                    r.get::<String, _>("app_id"),
                )
            })
            .collect())
    }

    /// Whether this tenant owns a project with `app_id`. Within-tenant only (the
    /// cross-tenant boundary is the database itself). Used to keep one org's user
    /// from naming a sibling project they don't have, never as the tenancy guard.
    pub async fn owns_app(&self, app_id: &str) -> anyhow::Result<bool> {
        let row = sqlx::query_scalar::<_, i32>("SELECT 1 FROM projects WHERE app_id = $1")
            .bind(app_id)
            .fetch_optional(self.pool.as_ref())
            .await?;
        Ok(row.is_some())
    }

    /// The tenant-db project id behind an app id, if any. Ingest uses this to pin
    /// a project-scoped (publishable) key to its own app.
    pub async fn project_id_for_app(&self, app_id: &str) -> anyhow::Result<Option<i64>> {
        let id = sqlx::query_scalar::<_, i64>("SELECT id FROM projects WHERE app_id = $1")
            .bind(app_id)
            .fetch_optional(self.pool.as_ref())
            .await?;
        Ok(id)
    }

    /// Hard-delete a project row (compensating cleanup when key minting fails
    /// right after creation; nothing has referenced the project yet).
    pub async fn delete_project(&self, id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM projects WHERE id = $1")
            .bind(id)
            .execute(self.pool.as_ref())
            .await?;
        Ok(())
    }

    /// How many projects this tenant owns. Used by `GET /v1/me` so `cloud login`
    /// can confirm the key resolved to a tenant without leaking project ids/PII.
    pub async fn count_projects(&self) -> anyhow::Result<i64> {
        let n = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM projects")
            .fetch_one(self.pool.as_ref())
            .await?;
        Ok(n)
    }

    // ---- per-app integration config -----------------------------------------

    pub async fn integration_for(&self, app_id: &str) -> anyhow::Result<Option<IntegrationRow>> {
        let row = sqlx::query(
            "SELECT provider, repo, base_url, user_email, extra, token_enc,
                    dispatch_repo, dispatch_token_enc
             FROM project_integrations WHERE app_id = $1",
        )
        .bind(app_id)
        .fetch_optional(self.pool.as_ref())
        .await?;
        Ok(row.map(|r| IntegrationRow {
            provider: r.get("provider"),
            repo: r.get("repo"),
            base_url: r.get("base_url"),
            user_email: r.get("user_email"),
            extra: r.get::<Value, _>("extra"),
            token_enc: r.get("token_enc"),
            dispatch_repo: r.get("dispatch_repo"),
            dispatch_token_enc: r.get("dispatch_token_enc"),
        }))
    }

    pub async fn set_integration(&self, app_id: &str, row: &IntegrationRow) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO project_integrations
               (app_id, provider, repo, base_url, user_email, extra, token_enc,
                dispatch_repo, dispatch_token_enc, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now())
             ON CONFLICT (app_id) DO UPDATE SET
               provider = EXCLUDED.provider,
               repo = EXCLUDED.repo,
               base_url = EXCLUDED.base_url,
               user_email = EXCLUDED.user_email,
               extra = EXCLUDED.extra,
               token_enc = EXCLUDED.token_enc,
               dispatch_repo = EXCLUDED.dispatch_repo,
               dispatch_token_enc = EXCLUDED.dispatch_token_enc,
               updated_at = now()",
        )
        .bind(app_id)
        .bind(&row.provider)
        .bind(&row.repo)
        .bind(&row.base_url)
        .bind(&row.user_email)
        .bind(&row.extra)
        .bind(&row.token_enc)
        .bind(&row.dispatch_repo)
        .bind(&row.dispatch_token_enc)
        .execute(self.pool.as_ref())
        .await?;
        Ok(())
    }

    // ---- CI reproduction runs (repository_dispatch ledger) -------------------

    pub async fn create_cloud_run(
        &self,
        app_id: &str,
        bucket_id: &str,
        requested_by: &str,
    ) -> anyhow::Result<i64> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO cloud_runs (app_id, bucket_id, requested_by) VALUES ($1,$2,$3) RETURNING id",
        )
        .bind(app_id)
        .bind(bucket_id)
        .bind(requested_by)
        .fetch_one(self.pool.as_ref())
        .await?;
        Ok(id)
    }

    /// Terminal transition for a run. Only an open (dispatched) run moves, so a
    /// duplicate/late report can't flip a completed run, and the row must match
    /// the (app, bucket) the caller is posting against (a run id can't close a
    /// different bucket's run). Returns whether a row transitioned.
    pub async fn complete_cloud_run(
        &self,
        id: i64,
        app_id: &str,
        bucket_id: &str,
        status: &str,
    ) -> anyhow::Result<bool> {
        let r = sqlx::query(
            "UPDATE cloud_runs
             SET status=$4, completed_at=now()
             WHERE id=$1 AND app_id=$2 AND bucket_id=$3 AND status='dispatched'",
        )
        .bind(id)
        .bind(app_id)
        .bind(bucket_id)
        .bind(status)
        .execute(self.pool.as_ref())
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Expire dispatched runs whose CI never reported back within the timeout.
    /// Expiration is operational state only; this edition has no metering.
    pub async fn expire_stale_cloud_runs(&self, older_than_secs: i64) -> anyhow::Result<u64> {
        let r = sqlx::query(
            "UPDATE cloud_runs SET status='expired', completed_at=now()
             WHERE status='dispatched' AND dispatched_at < now() - ($1 || ' seconds')::interval",
        )
        .bind(older_than_secs.to_string())
        .execute(self.pool.as_ref())
        .await?;
        Ok(r.rows_affected())
    }

    pub async fn cloud_runs_for(
        &self,
        app_id: &str,
        bucket_id: &str,
    ) -> anyhow::Result<Vec<Value>> {
        let rows = sqlx::query(
            "SELECT id, status, requested_by, dispatched_at, completed_at
             FROM cloud_runs WHERE app_id=$1 AND bucket_id=$2 ORDER BY id DESC LIMIT 50",
        )
        .bind(app_id)
        .bind(bucket_id)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows
            .iter()
            .map(|r| {
                json!({
                    "runId": r.get::<i64, _>("id"),
                    "status": r.get::<String, _>("status"),
                    "requestedBy": r.get::<String, _>("requested_by"),
                    "dispatchedAt": r.get::<chrono::DateTime<chrono::Utc>, _>("dispatched_at").to_rfc3339(),
                    "completedAt": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("completed_at").map(|t| t.to_rfc3339()),
                })
            })
            .collect())
    }

    /// Total evidence bytes stored for this tenant (the usage panel read).
    pub async fn evidence_bytes_total(&self) -> anyhow::Result<i64> {
        let n: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(bytes), 0)::BIGINT FROM evidence")
            .fetch_one(self.pool.as_ref())
            .await?;
        Ok(n)
    }

    // ---- retention -----------------------------------------------------------

    /// Storage keys of evidence attached to errors older than the retention
    /// window, oldest first. The retention sweep deletes these BLOBS first,
    /// then the rows (`delete_expired_evidence` / `delete_expired_errors`), so
    /// a crash between steps leaves only re-processable rows, never orphaned
    /// customer bytes.
    pub async fn expired_evidence_keys(
        &self,
        days: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<(i64, String)>> {
        let rows = sqlx::query(
            "SELECT e.id, e.storage_key FROM evidence e
             JOIN errors r ON r.id = e.error_id
             WHERE r.created_at < now() - ($1 || ' days')::interval
             ORDER BY e.id LIMIT $2",
        )
        .bind(days.to_string())
        .bind(limit)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows
            .iter()
            .map(|r| (r.get::<i64, _>("id"), r.get::<String, _>("storage_key")))
            .collect())
    }

    pub async fn delete_evidence_rows(&self, ids: &[i64]) -> anyhow::Result<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let r = sqlx::query("DELETE FROM evidence WHERE id = ANY($1)")
            .bind(ids)
            .execute(self.pool.as_ref())
            .await?;
        Ok(r.rows_affected())
    }

    /// Batched delete of errors past the retention window. An error that STILL
    /// has evidence rows is skipped: those rows exist only when their blob
    /// delete failed, and cascading them away here would orphan the customer
    /// bytes in object storage with no ledger row left to retry from. The next
    /// hourly pass retries the blob, then the error becomes deletable.
    pub async fn delete_expired_errors(&self, days: i64, limit: i64) -> anyhow::Result<u64> {
        let r = sqlx::query(
            "DELETE FROM errors WHERE id IN (
               SELECT id FROM errors e
               WHERE e.created_at < now() - ($1 || ' days')::interval
                 AND NOT EXISTS (SELECT 1 FROM evidence ev WHERE ev.error_id = e.id)
               ORDER BY id LIMIT $2)",
        )
        .bind(days.to_string())
        .bind(limit)
        .execute(self.pool.as_ref())
        .await?;
        Ok(r.rows_affected())
    }

    // ---- tenant export (GDPR portability) ----------------------------------

    /// One keyset page of an app's error rows for the export stream, oldest
    /// first (`id > after_id ORDER BY id`, so the caller pages with the last
    /// returned id and never re-reads a row). `within_days` bounds the page to
    /// the retention window when set (hosted: rows past retention are already
    /// queued for deletion, so an export must not resurrect them); None (self-
    /// host owns its retention) exports everything. Returns
    /// `(id, created_at, bucket_id, rec)`.
    pub async fn export_errors_page(
        &self,
        app_id: &str,
        within_days: Option<i64>,
        after_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<(i64, String, Option<String>, ErrorRec)>> {
        let rows = sqlx::query(
            "SELECT id, sig, message, path, context, bucket_id, created_at FROM errors
             WHERE app_id=$1 AND id > $2
               AND ($3::text IS NULL OR created_at >= now() - ($3 || ' days')::interval)
             ORDER BY id LIMIT $4",
        )
        .bind(app_id)
        .bind(after_id)
        .bind(within_days.map(|d| d.to_string()))
        .bind(limit)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<i64, _>("id"),
                    r.get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                        .to_rfc3339(),
                    r.get::<Option<String>, _>("bucket_id"),
                    row_to_error(r),
                )
            })
            .collect())
    }

    /// One keyset page of an app's evidence rows for the export stream: the
    /// blob KEYS and metadata (the bytes themselves stay in object storage and
    /// are fetched per key via `/v1/blob/*key`). Same `id > after_id` paging
    /// contract as `export_errors_page`. Returns
    /// `(id, error_id, kind, storage_key, bytes, created_at)`.
    pub async fn export_evidence_page(
        &self,
        app_id: &str,
        after_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<(i64, i64, String, String, i64, String)>> {
        let rows = sqlx::query(
            "SELECT id, error_id, kind, storage_key, bytes, created_at FROM evidence
             WHERE app_id=$1 AND id > $2 ORDER BY id LIMIT $3",
        )
        .bind(app_id)
        .bind(after_id)
        .bind(limit)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<i64, _>("id"),
                    r.get::<i64, _>("error_id"),
                    r.get::<String, _>("kind"),
                    r.get::<String, _>("storage_key"),
                    r.get::<i64, _>("bytes"),
                    r.get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                        .to_rfc3339(),
                )
            })
            .collect())
    }

    // ---- telemetry: edges / errors / evidence ------------------------------

    /// Single-row edge upsert. Retained for the tenancy integration tests and as
    /// a one-off helper; the hot ingest path uses the batched `ingest_batch`.
    #[allow(dead_code)]
    pub async fn incr_edge(&self, app_id: &str, key: &str) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO edges (app_id, edge_key, count) VALUES ($1,$2,1)
             ON CONFLICT (app_id, edge_key) DO UPDATE SET count = edges.count + 1",
        )
        .bind(app_id)
        .bind(key)
        .execute(self.pool.as_ref())
        .await?;
        Ok(())
    }

    /// Single-row error insert. Retained for the tenancy integration tests and as
    /// a one-off helper; the hot ingest path uses the batched `ingest_batch`.
    #[allow(dead_code)]
    pub async fn add_error(&self, app_id: &str, rec: &ErrorRec) -> anyhow::Result<()> {
        let bucket_id = crate::ingest::buckets::bucket_id(rec);
        sqlx::query(
            "INSERT INTO errors (app_id, sig, message, path, context, bucket_id)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(app_id)
        .bind(&rec.sig)
        .bind(&rec.message)
        .bind(Json(&rec.path))
        .bind(Json(&rec.context))
        .bind(bucket_id)
        .execute(self.pool.as_ref())
        .await?;
        Ok(())
    }

    /// Ingest a whole event batch ATOMICALLY in one transaction and a constant
    /// number of round-trips, instead of one auto-commit statement per event.
    ///
    /// `edges` is `(edge_key, count_delta)` ALREADY pre-aggregated by the caller:
    /// because the `edges` PK is `(app_id, edge_key)`, a single multi-row upsert
    /// cannot touch the same row twice (Postgres rejects "command cannot affect
    /// row a second time"), so duplicate keys within one batch MUST be summed in
    /// memory first and applied as one delta per distinct key. `errors` are
    /// append-only and inserted in one multi-row `UNNEST` statement. Both share
    /// the transaction, so the batch is all-or-nothing: a mid-batch failure rolls
    /// the whole batch back rather than leaving a half-ingested session.
    /// Ingest one batch atomically. `batch_id` (when the SDK sends one) makes
    /// the write idempotent: the id is consumed INSIDE the same transaction as
    /// the data, so a retry of an already-committed batch returns
    /// `Ok(true)` (deduped) and writes nothing, while a retry of a failed
    /// batch (id never committed) writes normally.
    pub async fn ingest_batch(
        &self,
        app_id: &str,
        edges: &[(String, i64)],
        errors: &[ErrorRec],
        batch_id: Option<&str>,
    ) -> anyhow::Result<bool> {
        if edges.is_empty() && errors.is_empty() {
            return Ok(false);
        }
        let mut tx = self.pool.begin().await?;

        if let Some(bid) = batch_id {
            let r = sqlx::query(
                "INSERT INTO processed_batches (app_id, batch_id) VALUES ($1,$2)
                 ON CONFLICT DO NOTHING",
            )
            .bind(app_id)
            .bind(bid)
            .execute(&mut *tx)
            .await?;
            if r.rows_affected() == 0 {
                tx.rollback().await?;
                return Ok(true);
            }
        }

        if !edges.is_empty() {
            // One multi-row upsert: UNNEST the parallel (key, delta) arrays into
            // rows, then apply the SAME ON CONFLICT increment incr_edge uses, with
            // the caller-summed delta so a key repeated in the batch lands once.
            let keys: Vec<&str> = edges.iter().map(|(k, _)| k.as_str()).collect();
            let deltas: Vec<i64> = edges.iter().map(|(_, c)| *c).collect();
            sqlx::query(
                "INSERT INTO edges (app_id, edge_key, count)
                 SELECT $1, k, d
                 FROM UNNEST($2::text[], $3::bigint[]) AS t(k, d)
                 ON CONFLICT (app_id, edge_key)
                   DO UPDATE SET count = edges.count + EXCLUDED.count",
            )
            .bind(app_id)
            .bind(&keys)
            .bind(&deltas)
            .execute(&mut *tx)
            .await?;
        }

        if !errors.is_empty() {
            // One multi-row append: UNNEST the parallel column arrays into rows.
            // No ON CONFLICT (errors are an append-only log keyed by serial id).
            // The bucket id is MATERIALIZED here (same pure fn the read paths
            // trust) so per-bucket reads are indexed, never scan-and-regroup.
            let sigs: Vec<&str> = errors.iter().map(|e| e.sig.as_str()).collect();
            let messages: Vec<&str> = errors.iter().map(|e| e.message.as_str()).collect();
            let paths: Vec<Value> = errors
                .iter()
                .map(|e| serde_json::to_value(&e.path).unwrap_or(Value::Null))
                .collect();
            let contexts: Vec<Value> = errors
                .iter()
                .map(|e| Value::Object(e.context.clone()))
                .collect();
            let bucket_ids: Vec<String> = errors
                .iter()
                .map(crate::ingest::buckets::bucket_id)
                .collect();
            sqlx::query(
                "INSERT INTO errors (app_id, sig, message, path, context, bucket_id)
                 SELECT $1, s, m, p, c, b
                 FROM UNNEST($2::text[], $3::text[], $4::jsonb[], $5::jsonb[], $6::text[])
                   AS t(s, m, p, c, b)",
            )
            .bind(app_id)
            .bind(&sigs)
            .bind(&messages)
            .bind(&paths)
            .bind(&contexts)
            .bind(&bucket_ids)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(false)
    }

    /// Drop consumed batch ids past the retry horizon.
    pub async fn prune_processed_batches(&self, older_than_hours: i64) -> anyhow::Result<u64> {
        let r = sqlx::query(
            "DELETE FROM processed_batches
             WHERE created_at < now() - ($1 || ' hours')::interval",
        )
        .bind(older_than_hours.to_string())
        .execute(self.pool.as_ref())
        .await?;
        Ok(r.rows_affected())
    }

    pub async fn edges(&self, app_id: &str) -> anyhow::Result<Vec<(String, i64)>> {
        let rows =
            sqlx::query("SELECT edge_key, count FROM edges WHERE app_id=$1 ORDER BY edge_key")
                .bind(app_id)
                .fetch_all(self.pool.as_ref())
                .await?;
        Ok(rows
            .iter()
            .map(|r| (r.get::<String, _>("edge_key"), r.get::<i64, _>("count")))
            .collect())
    }

    /// Uncapped full-history read. Retained for the tenancy integration tests;
    /// per-app read/repro/bucket/replay routes use `errors_capped` (bounded scan).
    #[allow(dead_code)]
    pub async fn errors(&self, app_id: &str) -> anyhow::Result<Vec<ErrorRec>> {
        let rows = sqlx::query(
            "SELECT sig, message, path, context FROM errors WHERE app_id=$1 ORDER BY id",
        )
        .bind(app_id)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows.iter().map(row_to_error).collect())
    }

    /// Like `errors`, but with the same HARD CAP as `errors_with_meta_capped`,
    /// for read paths that only need the bare `ErrorRec`s (no id/timestamp) but
    /// must NOT pull a pathological app's entire history into memory. Returns
    /// `(rows, dropped)` where `dropped` is how many rows fell beyond the cap; the
    /// caller LOGS a warning naming the count on cap-hit (never silent truncation).
    /// Keeps the OLDEST rows (`ORDER BY id LIMIT cap`) so first-seen/lineage stays
    /// correct and per-cohort grouping is exact for occurrences inside the window.
    #[allow(dead_code)]
    pub async fn errors_capped(
        &self,
        app_id: &str,
        cap: i64,
    ) -> anyhow::Result<(Vec<ErrorRec>, i64)> {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM errors WHERE app_id=$1")
            .bind(app_id)
            .fetch_one(self.pool.as_ref())
            .await?;
        let rows = sqlx::query(
            "SELECT sig, message, path, context FROM errors WHERE app_id=$1 ORDER BY id LIMIT $2",
        )
        .bind(app_id)
        .bind(cap)
        .fetch_all(self.pool.as_ref())
        .await?;
        let out: Vec<ErrorRec> = rows.iter().map(row_to_error).collect();
        let dropped = (total - out.len() as i64).max(0);
        Ok((out, dropped))
    }

    /// One bucket's occurrences, oldest-first, via the (app_id, bucket_id, id)
    /// index: the materialized read that replaces scan-and-regroup for every
    /// per-bucket endpoint. `cap` bounds a pathological bucket.
    pub async fn errors_for_bucket(
        &self,
        app_id: &str,
        bucket_id: &str,
        cap: i64,
    ) -> anyhow::Result<Vec<(i64, String, ErrorRec)>> {
        let rows = sqlx::query(
            "SELECT id, sig, message, path, context, created_at FROM errors
             WHERE app_id=$1 AND bucket_id=$2 ORDER BY id LIMIT $3",
        )
        .bind(app_id)
        .bind(bucket_id)
        .bind(cap)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows
            .iter()
            .map(|r| {
                let id = r.get::<i64, _>("id");
                let ts = r
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339();
                (id, ts, row_to_error(r))
            })
            .collect())
    }

    /// The newest `limit` occurrences app-wide, returned OLDEST-FIRST: the
    /// bounded sample that stands in for "the whole app history" wherever a
    /// baseline/denominator is needed (discriminators, build ordering, post-fix
    /// traffic). Recency-biased on purpose: that is where the comparison signal
    /// lives.
    pub async fn recent_errors_with_meta(
        &self,
        app_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<(i64, String, ErrorRec)>> {
        let rows = sqlx::query(
            "SELECT id, sig, message, path, context, created_at FROM (
               SELECT * FROM errors WHERE app_id=$1 ORDER BY id DESC LIMIT $2
             ) newest ORDER BY id",
        )
        .bind(app_id)
        .bind(limit)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows
            .iter()
            .map(|r| {
                let id = r.get::<i64, _>("id");
                let ts = r
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339();
                (id, ts, row_to_error(r))
            })
            .collect())
    }

    /// The bounded whole-app grouping scan (the bucket LIST view), with a HARD CAP on how many rows the bucket
    /// grouping path will scan, so a single pathological app cannot pull its
    /// entire (potentially millions) error history into memory on every dashboard
    /// read. We deliberately do NOT silently truncate: when the cap is hit we
    /// return `(rows, dropped)` where `dropped` is how many rows were beyond the
    /// cap, and the caller LOGS a warning naming the count. The scan keeps the
    /// oldest rows (`ORDER BY id LIMIT cap`) so bucket lineage (first-seen) stays
    /// correct for everything within the window; only the newest tail is dropped.
    ///
    /// NOTE: bucket COUNTS for buckets whose occurrences fall entirely inside the
    /// window are still exact. Only when an app exceeds the cap (default 200k) do
    /// the most recent occurrences fall outside it, which is why we warn loudly.
    pub async fn errors_with_meta_capped(
        &self,
        app_id: &str,
        cap: i64,
    ) -> anyhow::Result<(Vec<(i64, String, ErrorRec, Option<String>)>, i64)> {
        // Cheap COUNT first so we can report how many rows we are about to drop.
        // (Index-only on errors_app; far cheaper than materializing every row.)
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM errors WHERE app_id=$1")
            .bind(app_id)
            .fetch_one(self.pool.as_ref())
            .await?;
        let rows = sqlx::query(
            "SELECT id, sig, message, path, context, bucket_id, created_at FROM errors WHERE app_id=$1 ORDER BY id LIMIT $2",
        )
        .bind(app_id)
        .bind(cap)
        .fetch_all(self.pool.as_ref())
        .await?;
        let out: Vec<(i64, String, ErrorRec, Option<String>)> = rows
            .iter()
            .map(|r| {
                let id = r.get::<i64, _>("id");
                let ts = r
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339();
                (
                    id,
                    ts,
                    row_to_error(r),
                    r.get::<Option<String>, _>("bucket_id"),
                )
            })
            .collect();
        let dropped = (total - out.len() as i64).max(0);
        Ok((out, dropped))
    }

    /// A PAGINATED slice of an app's errors for the flat list endpoints (not the
    /// grouping path). `limit`/`offset` give a bounded read with stable id order,
    /// so a list handler never has to materialize the whole table. Returns the
    /// page rows plus the app's total error count for client-side pagination.
    pub async fn errors_paginated(
        &self,
        app_id: &str,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<ErrorRec>, i64)> {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM errors WHERE app_id=$1")
            .bind(app_id)
            .fetch_one(self.pool.as_ref())
            .await?;
        let rows = sqlx::query(
            "SELECT sig, message, path, context FROM errors WHERE app_id=$1 ORDER BY id LIMIT $2 OFFSET $3",
        )
        .bind(app_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok((rows.iter().map(row_to_error).collect(), total))
    }

    pub async fn add_replay_result(
        &self,
        app_id: &str,
        bucket_id: &str,
        status: &str,
        runs: i32,
        failures: i32,
        local_repro_id: Option<&str>,
    ) -> anyhow::Result<i64> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO replay_results (app_id, bucket_id, status, runs, failures, local_repro_id)
             VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
        )
        .bind(app_id)
        .bind(bucket_id)
        .bind(status)
        .bind(runs)
        .bind(failures)
        .bind(local_repro_id)
        .fetch_one(self.pool.as_ref())
        .await?;
        Ok(id)
    }

    pub async fn replay_results_for(
        &self,
        app_id: &str,
        bucket_id: &str,
    ) -> anyhow::Result<Vec<ReplayResult>> {
        let rows = sqlx::query(
            "SELECT status, runs, failures, local_repro_id, created_at
             FROM replay_results WHERE app_id=$1 AND bucket_id=$2 ORDER BY id DESC",
        )
        .bind(app_id)
        .bind(bucket_id)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows
            .iter()
            .map(|r| ReplayResult {
                status: r.get::<String, _>("status"),
                runs: r.get::<i32, _>("runs"),
                failures: r.get::<i32, _>("failures"),
                local_repro_id: r.get::<Option<String>, _>("local_repro_id"),
                created_at: r
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
            })
            .collect())
    }

    /// ALL reproduction attempts for an app, grouped by bucket, newest-first
    /// within each bucket. Folds the per-bucket N+1 (`replay_results_for` in a
    /// loop over every bucket on the list view) into ONE round-trip: the caller
    /// looks each bucket up in the returned map instead of awaiting per bucket.
    /// Buckets with no attempts simply have no map entry (caller treats as empty).
    pub async fn replay_results_by_bucket(
        &self,
        app_id: &str,
    ) -> anyhow::Result<std::collections::HashMap<String, Vec<ReplayResult>>> {
        let rows = sqlx::query(
            "SELECT bucket_id, status, runs, failures, local_repro_id, created_at
             FROM replay_results WHERE app_id=$1 ORDER BY bucket_id, id DESC",
        )
        .bind(app_id)
        .fetch_all(self.pool.as_ref())
        .await?;
        let mut by_bucket: std::collections::HashMap<String, Vec<ReplayResult>> =
            std::collections::HashMap::new();
        for r in &rows {
            by_bucket
                .entry(r.get::<String, _>("bucket_id"))
                .or_default()
                .push(ReplayResult {
                    status: r.get::<String, _>("status"),
                    runs: r.get::<i32, _>("runs"),
                    failures: r.get::<i32, _>("failures"),
                    local_repro_id: r.get::<Option<String>, _>("local_repro_id"),
                    created_at: r
                        .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                        .to_rfc3339(),
                });
        }
        Ok(by_bucket)
    }

    /// ALL triage rows for an app, keyed by bucket id. Folds the per-bucket N+1
    /// (`triage_for_bucket` in a loop over every bucket on the list view) into ONE
    /// round-trip. A bucket with no triage row is absent from the map (the caller
    /// treats absence as the implicit `untriaged` state, exactly like the single-row
    /// helper returning `None`).
    pub async fn triage_all_for_app(
        &self,
        app_id: &str,
    ) -> anyhow::Result<std::collections::HashMap<String, Triage>> {
        let rows = sqlx::query(
            "SELECT bucket_id, status, assignee, updated_at, fixed_in_build
             FROM bucket_triage WHERE app_id = $1",
        )
        .bind(app_id)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<String, _>("bucket_id"),
                    Triage {
                        status: r.get::<String, _>("status"),
                        assignee: r.get::<Option<i64>, _>("assignee"),
                        updated_at: r
                            .get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
                            .to_rfc3339(),
                        fixed_in_build: r.get::<Option<String>, _>("fixed_in_build"),
                    },
                )
            })
            .collect())
    }

    #[allow(dead_code)]
    pub async fn error_id_at(&self, app_id: &str, idx: usize) -> anyhow::Result<Option<i64>> {
        let row =
            sqlx::query("SELECT id FROM errors WHERE app_id=$1 ORDER BY id OFFSET $2 LIMIT 1")
                .bind(app_id)
                .bind(idx as i64)
                .fetch_optional(self.pool.as_ref())
                .await?;
        Ok(row.map(|r| r.get::<i64, _>("id")))
    }

    /// Reserve an evidence row, enforcing the per-app byte quota ATOMICALLY: the
    /// sum-and-check and the insert run in one transaction under a per-app
    /// advisory lock, so concurrent uploads cannot both pass the check and
    /// overshoot. Returns None when the quota would be exceeded. The caller
    /// uploads the blob AFTER reserving and compensates with `remove_evidence`
    /// if the upload fails (the row is the source of truth for usage).
    pub async fn add_evidence_within_quota(
        &self,
        app_id: &str,
        error_id: i64,
        kind: &str,
        storage_key: &str,
        bytes: i64,
        max: Option<i64>,
    ) -> anyhow::Result<Option<i64>> {
        let mut tx = self.pool.begin().await?;
        if let Some(max) = max {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
                .bind(app_id)
                .execute(&mut *tx)
                .await?;
            let used: i64 = sqlx::query_scalar(
                "SELECT COALESCE(SUM(bytes), 0)::BIGINT FROM evidence WHERE app_id=$1",
            )
            .bind(app_id)
            .fetch_one(&mut *tx)
            .await?;
            if !quota_allows(used, bytes, max) {
                tx.rollback().await?;
                return Ok(None);
            }
        }
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO evidence (app_id, error_id, kind, storage_key, bytes)
             VALUES ($1,$2,$3,$4,$5) RETURNING id",
        )
        .bind(app_id)
        .bind(error_id)
        .bind(kind)
        .bind(storage_key)
        .bind(bytes)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(id))
    }

    /// Compensating delete for a reserved evidence row whose blob upload failed.
    pub async fn remove_evidence(&self, id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM evidence WHERE id=$1")
            .bind(id)
            .execute(self.pool.as_ref())
            .await?;
        Ok(())
    }

    pub async fn evidence_for(
        &self,
        error_id: i64,
    ) -> anyhow::Result<Vec<(String, String, i64, String)>> {
        let rows = sqlx::query(
            "SELECT kind, storage_key, bytes, created_at FROM evidence WHERE error_id=$1 ORDER BY id",
        )
        .bind(error_id)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<String, _>("kind"),
                    r.get::<String, _>("storage_key"),
                    r.get::<i64, _>("bytes"),
                    r.get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                        .to_rfc3339(),
                )
            })
            .collect())
    }

    #[allow(dead_code)]
    pub async fn error_at(&self, app_id: &str, idx: usize) -> anyhow::Result<Option<ErrorRec>> {
        let row = sqlx::query(
            "SELECT sig, message, path, context FROM errors WHERE app_id=$1 ORDER BY id OFFSET $2 LIMIT 1",
        )
        .bind(app_id)
        .bind(idx as i64)
        .fetch_optional(self.pool.as_ref())
        .await?;
        Ok(row.as_ref().map(row_to_error))
    }

    // ---- jobs / shards / the durable pull-claim queue ----------------------

    pub async fn insert_job(&self, job: &Job) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO jobs (id, app_dir, budget, started_at, map_states, map_transitions)
             VALUES ($1,$2,$3,$4,0,0)",
        )
        .bind(&job.id)
        .bind(&job.spec_app_dir)
        .bind(job.budget as i32)
        .bind(&job.started_at)
        .execute(&mut *tx)
        .await?;
        for s in &job.shards {
            sqlx::query(
                "INSERT INTO shards (job_id, seed, state, backend, duration_s) VALUES ($1,$2,$3,$4,0)",
            )
            .bind(&job.id)
            .bind(s.seed as i32)
            .bind(s.state.as_str())
            .bind(&job.backend)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Whether a job exists in THIS tenant's db. (Replaces the old cross-tenant
    /// `job_org`: the tenant boundary is the database, so "is this my job?" is just
    /// "does the row exist here?". `get_job` reads via `snapshot`, which already
    /// 404s a missing job, so this is kept for explicit existence checks/ops.)
    #[allow(dead_code)]
    pub async fn job_exists(&self, job_id: &str) -> anyhow::Result<bool> {
        let row = sqlx::query_scalar::<_, i32>("SELECT 1 FROM jobs WHERE id = $1")
            .bind(job_id)
            .fetch_optional(self.pool.as_ref())
            .await?;
        Ok(row.is_some())
    }

    pub async fn claim_shard(
        &self,
        worker_id: &str,
        capabilities: &[String],
    ) -> anyhow::Result<Option<ClaimedShard>> {
        let row = sqlx::query(
            "UPDATE shards SET state='running', claimed_by=$1, claimed_at=now(),
                    heartbeat_at=now(), attempts=attempts+1
             WHERE (job_id, seed) IN (
                 SELECT s.job_id, s.seed FROM shards s
                 WHERE s.state='pending' AND s.backend = ANY($2)
                 ORDER BY s.job_id, s.seed
                 FOR UPDATE SKIP LOCKED
                 LIMIT 1
             )
             RETURNING job_id, seed, claimed_by, backend",
        )
        .bind(worker_id)
        .bind(capabilities)
        .fetch_optional(self.pool.as_ref())
        .await?;
        let Some(row) = row else { return Ok(None) };
        let job_id: String = row.get("job_id");
        let seed: i32 = row.get("seed");
        let claimed_by: String = row.get("claimed_by");
        let backend: String = row.get("backend");
        let job = sqlx::query("SELECT app_dir, budget FROM jobs WHERE id=$1")
            .bind(&job_id)
            .fetch_one(self.pool.as_ref())
            .await?;
        Ok(Some(ClaimedShard {
            job_id,
            seed: seed as u32,
            claimed_by,
            backend,
            app_dir: job.get::<String, _>("app_dir"),
            budget: job.get::<i32, _>("budget") as u32,
        }))
    }

    pub async fn touch_shard(
        &self,
        job_id: &str,
        seed: u32,
        worker_id: &str,
    ) -> anyhow::Result<bool> {
        let r = sqlx::query(
            "UPDATE shards SET heartbeat_at=now()
             WHERE job_id=$1 AND seed=$2 AND claimed_by=$3 AND state='running'",
        )
        .bind(job_id)
        .bind(seed as i32)
        .bind(worker_id)
        .execute(self.pool.as_ref())
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// How many shards are currently in state='pending' in THIS tenant's DB. The
    /// authoritative read behind clearing a tenant from the control-plane
    /// `tenant_pending_shards` routing hint: a tenant is cleared ONLY when this is
    /// exactly 0 (a claim returning None is NOT sufficient, since None can mean "all
    /// pending shards are locked by other workers right now"). Source of truth for
    /// the hint; see `ControlStore::clear_tenant_pending`.
    pub async fn pending_shard_count(&self) -> anyhow::Result<i64> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM shards WHERE state='pending'")
            .fetch_one(self.pool.as_ref())
            .await?;
        Ok(n)
    }

    /// Requeue shards stranded by a dead worker (running, heartbeat older than
    /// `stale_secs`) back to pending. Returns the number moved so the caller can
    /// re-mark the tenant in the control-plane pending set (those shards just
    /// transitioned INTO pending; see the routing-hint invariant).
    pub async fn requeue_stranded(&self, stale_secs: i64) -> anyhow::Result<u64> {
        let r = sqlx::query(
            "UPDATE shards SET state='pending', claimed_by=NULL, claimed_at=NULL, heartbeat_at=NULL
             WHERE state='running'
               AND (heartbeat_at IS NULL OR heartbeat_at < now() - make_interval(secs => $1))",
        )
        .bind(stale_secs as f64)
        .execute(self.pool.as_ref())
        .await?;
        Ok(r.rows_affected())
    }

    pub async fn job_incomplete(&self, job_id: &str) -> anyhow::Result<bool> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM shards WHERE job_id=$1 AND state IN ('pending','running')",
        )
        .bind(job_id)
        .fetch_one(self.pool.as_ref())
        .await?;
        Ok(n > 0)
    }

    pub async fn set_shard(
        &self,
        job_id: &str,
        seed: u32,
        worker_id: &str,
        state: ShardState,
        report: Option<String>,
        duration_s: f64,
    ) -> anyhow::Result<bool> {
        let r = sqlx::query(
            "UPDATE shards SET state=$4, report=$5, duration_s=$6
             WHERE job_id=$1 AND seed=$2 AND claimed_by=$3 AND state='running'",
        )
        .bind(job_id)
        .bind(seed as i32)
        .bind(worker_id)
        .bind(state.as_str())
        .bind(report)
        .bind(duration_s)
        .execute(self.pool.as_ref())
        .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn finalize_job(
        &self,
        job_id: &str,
        states: usize,
        transitions: usize,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE jobs SET finished_at=$2, map_states=$3, map_transitions=$4 WHERE id=$1",
        )
        .bind(job_id)
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(states as i32)
        .bind(transitions as i32)
        .execute(self.pool.as_ref())
        .await?;
        Ok(())
    }

    pub async fn findings_count(&self, job_id: &str) -> anyhow::Result<usize> {
        let n: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM shards WHERE job_id=$1 AND state='finding'")
                .bind(job_id)
                .fetch_one(self.pool.as_ref())
                .await?;
        Ok(n as usize)
    }

    pub async fn list_jobs(&self, limit: i64) -> anyhow::Result<Vec<Value>> {
        let rows = sqlx::query(
            "SELECT
                j.id,
                j.app_dir,
                j.started_at,
                j.finished_at,
                j.map_states,
                j.map_transitions,
                COUNT(s.seed) AS shards,
                COUNT(*) FILTER (WHERE s.state NOT IN ('pending','running')) AS done,
                COUNT(*) FILTER (WHERE s.state = 'finding') AS findings,
                COUNT(*) FILTER (WHERE s.state = 'error') AS errors,
                COUNT(*) FILTER (WHERE s.state = 'running') AS running,
                COUNT(*) FILTER (WHERE s.state = 'clean') AS clean,
                MIN(s.backend) AS backend
             FROM jobs j
             LEFT JOIN shards s ON s.job_id = j.id
             GROUP BY j.id, j.app_dir, j.started_at, j.finished_at, j.map_states, j.map_transitions
             ORDER BY j.started_at DESC
             LIMIT $1",
        )
        .bind(limit.clamp(1, 100))
        .fetch_all(self.pool.as_ref())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let finished_at: Option<String> = r.get("finished_at");
                json!({
                    "id": r.get::<String, _>("id"),
                    "appDir": r.get::<String, _>("app_dir"),
                    "started_at": r.get::<String, _>("started_at"),
                    "finished_at": finished_at,
                    "complete": finished_at.is_some(),
                    "backend": r.get::<Option<String>, _>("backend").unwrap_or_else(|| "web".to_string()),
                    "shards": r.get::<i64, _>("shards"),
                    "done": r.get::<i64, _>("done"),
                    "findings": r.get::<i64, _>("findings"),
                    "errors": r.get::<i64, _>("errors"),
                    "running": r.get::<i64, _>("running"),
                    "clean": r.get::<i64, _>("clean"),
                    "map": {
                        "states": r.get::<i32, _>("map_states"),
                        "transitions": r.get::<i32, _>("map_transitions")
                    },
                })
            })
            .collect())
    }

    pub async fn snapshot(&self, id: &str) -> anyhow::Result<Option<Value>> {
        let job = sqlx::query(
            "SELECT app_dir, started_at, finished_at, map_states, map_transitions FROM jobs WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(self.pool.as_ref())
        .await?;
        let Some(job) = job else { return Ok(None) };
        let rows = sqlx::query(
            "SELECT seed, state, report, duration_s FROM shards WHERE job_id=$1 ORDER BY seed",
        )
        .bind(id)
        .fetch_all(self.pool.as_ref())
        .await?;
        let shards: Vec<Value> = rows
            .iter()
            .map(|r| {
                json!({
                    "seed": r.get::<i32, _>("seed"),
                    "state": r.get::<String, _>("state"),
                    "report": r.get::<Option<String>, _>("report"),
                    "duration_s": r.get::<f64, _>("duration_s"),
                })
            })
            .collect();
        let done = rows
            .iter()
            .filter(|r| {
                let s: String = r.get("state");
                s != "pending" && s != "running"
            })
            .count();
        let findings = rows
            .iter()
            .filter(|r| r.get::<String, _>("state") == "finding")
            .count();
        let finished_at: Option<String> = job.try_get("finished_at")?;
        Ok(Some(json!({
            "id": id,
            "appDir": job.get::<String, _>("app_dir"),
            "shards": rows.len(),
            "done": done,
            "complete": finished_at.is_some(),
            "started_at": job.get::<String, _>("started_at"),
            "finished_at": finished_at,
            "findings": findings,
            "map": { "states": job.get::<i32, _>("map_states"), "transitions": job.get::<i32, _>("map_transitions") },
            "shardDetail": shards,
        })))
    }

    // ---- per-(app,bucket) triage state -------------------------------------

    pub async fn triage_for_bucket(
        &self,
        app_id: &str,
        bucket_id: &str,
    ) -> anyhow::Result<Option<Triage>> {
        let row = sqlx::query(
            "SELECT status, assignee, updated_at, fixed_in_build FROM bucket_triage
             WHERE app_id = $1 AND bucket_id = $2",
        )
        .bind(app_id)
        .bind(bucket_id)
        .fetch_optional(self.pool.as_ref())
        .await?;
        Ok(row.map(|r| Triage {
            status: r.get::<String, _>("status"),
            assignee: r.get::<Option<i64>, _>("assignee"),
            updated_at: r
                .get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
                .to_rfc3339(),
            fixed_in_build: r.get::<Option<String>, _>("fixed_in_build"),
        }))
    }

    pub async fn upsert_triage(
        &self,
        app_id: &str,
        bucket_id: &str,
        status: &str,
        assignee: Option<i64>,
        fixed_in_build: Option<&str>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO bucket_triage (app_id, bucket_id, status, assignee, fixed_in_build, updated_at)
             VALUES ($1,$2,$3,$4,$5, now())
             ON CONFLICT (app_id, bucket_id) DO UPDATE
               SET status = EXCLUDED.status, assignee = EXCLUDED.assignee,
                   fixed_in_build = EXCLUDED.fixed_in_build, updated_at = now()",
        )
        .bind(app_id)
        .bind(bucket_id)
        .bind(status)
        .bind(assignee)
        .bind(fixed_in_build)
        .execute(self.pool.as_ref())
        .await?;
        Ok(())
    }

    pub async fn advance_triage_unless_wontfix(
        &self,
        app_id: &str,
        bucket_id: &str,
        new_status: &str,
        fixed_in_build: Option<&str>,
    ) -> anyhow::Result<bool> {
        let r = sqlx::query(
            "INSERT INTO bucket_triage (app_id, bucket_id, status, fixed_in_build, updated_at)
             VALUES ($1,$2,$3,$4, now())
             ON CONFLICT (app_id, bucket_id) DO UPDATE
               SET status = EXCLUDED.status,
                   fixed_in_build = COALESCE(bucket_triage.fixed_in_build, EXCLUDED.fixed_in_build),
                   updated_at = now()
             WHERE bucket_triage.status <> 'wontfix'",
        )
        .bind(app_id)
        .bind(bucket_id)
        .bind(new_status)
        .bind(fixed_in_build)
        .execute(self.pool.as_ref())
        .await?;
        Ok(r.rows_affected() == 1)
    }

    // ---- bug <-> ticket link -----------------------------------------------

    pub async fn link_ticket(
        &self,
        app_id: &str,
        bucket_id: &str,
        provider: &str,
        repo: &str,
        external_id: &str,
        url: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO bucket_tickets (app_id, bucket_id, provider, repo, external_id, url)
             VALUES ($1,$2,$3,$4,$5,$6)
             ON CONFLICT (app_id, bucket_id) DO UPDATE
               SET provider = EXCLUDED.provider, repo = EXCLUDED.repo,
                   external_id = EXCLUDED.external_id, url = EXCLUDED.url",
        )
        .bind(app_id)
        .bind(bucket_id)
        .bind(provider)
        .bind(repo)
        .bind(external_id)
        .bind(url)
        .execute(self.pool.as_ref())
        .await?;
        Ok(())
    }

    pub async fn ticket_for_bucket(
        &self,
        app_id: &str,
        bucket_id: &str,
    ) -> anyhow::Result<Option<TicketLink>> {
        let row = sqlx::query(
            "SELECT provider, repo, external_id, url FROM bucket_tickets
             WHERE app_id = $1 AND bucket_id = $2",
        )
        .bind(app_id)
        .bind(bucket_id)
        .fetch_optional(self.pool.as_ref())
        .await?;
        Ok(row.map(|r| TicketLink {
            provider: r.get::<String, _>("provider"),
            repo: r.get::<String, _>("repo"),
            external_id: r.get::<String, _>("external_id"),
            url: r.get::<String, _>("url"),
        }))
    }

    // ---- background regression sweep: status + transition log --------------

    pub async fn anchored_buckets(&self) -> anyhow::Result<Vec<AnchoredBucket>> {
        let rows = sqlx::query(
            "SELECT app_id, bucket_id, fixed_in_build FROM bucket_triage
             WHERE fixed_in_build IS NOT NULL AND fixed_in_build <> ''
             ORDER BY app_id, bucket_id",
        )
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows
            .iter()
            .map(|r| AnchoredBucket {
                app_id: r.get::<String, _>("app_id"),
                bucket_id: r.get::<String, _>("bucket_id"),
                fixed_in_build: r.get::<String, _>("fixed_in_build"),
            })
            .collect())
    }

    pub async fn last_resolution_status(
        &self,
        app_id: &str,
        bucket_id: &str,
    ) -> anyhow::Result<Option<String>> {
        let row = sqlx::query(
            "SELECT status FROM bucket_resolution_status WHERE app_id = $1 AND bucket_id = $2",
        )
        .bind(app_id)
        .bind(bucket_id)
        .fetch_optional(self.pool.as_ref())
        .await?;
        Ok(row.map(|r| r.get::<String, _>("status")))
    }

    pub async fn upsert_resolution_status(
        &self,
        app_id: &str,
        bucket_id: &str,
        status: &str,
        build: Option<&str>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO bucket_resolution_status (app_id, bucket_id, status, build, updated_at)
             VALUES ($1,$2,$3,$4, now())
             ON CONFLICT (app_id, bucket_id) DO UPDATE
               SET status = EXCLUDED.status, build = EXCLUDED.build, updated_at = now()",
        )
        .bind(app_id)
        .bind(bucket_id)
        .bind(status)
        .bind(build)
        .execute(self.pool.as_ref())
        .await?;
        Ok(())
    }

    pub async fn record_resolution_event(
        &self,
        app_id: &str,
        bucket_id: &str,
        from_status: Option<&str>,
        to_status: &str,
        build: Option<&str>,
    ) -> anyhow::Result<i64> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO bucket_resolution_events (app_id, bucket_id, from_status, to_status, build)
             VALUES ($1,$2,$3,$4,$5) RETURNING id",
        )
        .bind(app_id)
        .bind(bucket_id)
        .bind(from_status)
        .bind(to_status)
        .bind(build)
        .fetch_one(self.pool.as_ref())
        .await?;
        Ok(id)
    }

    pub async fn recent_resolution_events(
        &self,
        app_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<ResolutionEvent>> {
        let rows = sqlx::query(
            "SELECT bucket_id, from_status, to_status, build, at
             FROM bucket_resolution_events
             WHERE app_id = $1 ORDER BY id DESC LIMIT $2",
        )
        .bind(app_id)
        .bind(limit)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows
            .iter()
            .map(|r| ResolutionEvent {
                bucket_id: r.get::<String, _>("bucket_id"),
                from_status: r.get::<Option<String>, _>("from_status"),
                to_status: r.get::<String, _>("to_status"),
                build: r.get::<Option<String>, _>("build"),
                at: r.get::<chrono::DateTime<chrono::Utc>, _>("at").to_rfc3339(),
            })
            .collect())
    }
}

fn row_to_error(r: &sqlx::postgres::PgRow) -> ErrorRec {
    let Json(path): Json<Vec<Step>> = r.get("path");
    let Json(context): Json<serde_json::Map<String, Value>> = r.get("context");
    ErrorRec {
        sig: r.get("sig"),
        message: r.get("message"),
        path,
        context,
    }
}

/// Overflow-safe quota comparison used by `add_evidence_within_quota`.
fn quota_allows(used: i64, incoming: i64, max: i64) -> bool {
    used.checked_add(incoming).is_some_and(|n| n <= max)
}

#[cfg(test)]
mod tests {
    use super::quota_allows;

    #[test]
    fn quota_comparison_is_inclusive_and_overflow_safe() {
        assert!(quota_allows(80, 20, 100));
        assert!(!quota_allows(80, 21, 100));
        assert!(!quota_allows(i64::MAX, 1, i64::MAX));
    }
}
