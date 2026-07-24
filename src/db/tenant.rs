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

mod ingest;
mod jobs;
mod traffic;
mod triage;

/// A connection handle bound to one tenant's database. Clone is cheap (shares the
/// underlying pool). Handlers receive this, never a global store.
#[derive(Clone)]
pub struct TenantStore {
    pub(super) pool: Arc<PgPool>,
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

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureRow {
    pub id: String,
    pub app_id: Option<String>,
    pub status: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub severity: String,
    pub visibility: String,
    pub platform: String,
    pub target: String,
    pub source_created_at: String,
    pub manifest: Value,
    pub expires_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureFileRow {
    pub filename: String,
    pub storage_key: String,
    pub bytes: i64,
    pub sha256: String,
    pub content_type: String,
}

pub struct NewCapture<'a> {
    pub id: &'a str,
    pub review_token_hash: &'a str,
    pub created_by: Option<i64>,
    pub app_id: Option<&'a str>,
    pub platform: &'a str,
    pub target: &'a str,
    pub source_created_at: &'a str,
    pub manifest: &'a Value,
}

pub struct CaptureApproval<'a> {
    pub review_token_hash: &'a str,
    pub app_id: &'a str,
    pub title: &'a str,
    pub description: &'a str,
    pub severity: &'a str,
    pub visibility: &'a str,
}

pub struct PendingCaptureFile<'a> {
    pub capture_id: &'a str,
    pub filename: &'a str,
    pub storage_key: &'a str,
    pub bytes: i64,
    pub sha256: &'a str,
    pub content_type: &'a str,
    pub quota_bytes: Option<i64>,
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

    pub async fn app_for_project_id(&self, project_id: i64) -> anyhow::Result<Option<String>> {
        Ok(
            sqlx::query_scalar::<_, String>("SELECT app_id FROM projects WHERE id = $1")
                .bind(project_id)
                .fetch_optional(self.pool.as_ref())
                .await?,
        )
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

    /// Return the project name and id for an app id inside this tenant.
    pub async fn project_for_app(&self, app_id: &str) -> anyhow::Result<Option<(i64, String)>> {
        let row = sqlx::query("SELECT id, name FROM projects WHERE app_id = $1")
            .bind(app_id)
            .fetch_optional(self.pool.as_ref())
            .await?;
        Ok(row.map(|r| (r.get("id"), r.get("name"))))
    }

    /// Blob keys owned by one project. Callers delete the blobs before removing
    /// the database ledger so a failed storage delete remains safely retryable.
    pub async fn project_evidence_keys(&self, app_id: &str) -> anyhow::Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT storage_key FROM evidence WHERE app_id = $1
             UNION ALL
             SELECT files.storage_key
             FROM capture_files files
             JOIN captures ON captures.id = files.capture_id
             WHERE captures.app_id = $1",
        )
        .bind(app_id)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows.into_iter().map(|r| r.get("storage_key")).collect())
    }

    /// Delete every tenant-database row owned by an app, then its project row,
    /// in one transaction. Evidence blobs must be removed first by the caller.
    pub async fn delete_project_by_app(&self, app_id: &str) -> anyhow::Result<bool> {
        let mut tx = self.pool.begin().await?;
        for table in [
            "evidence",
            "errors",
            "edges",
            "processed_batches",
            "replay_results",
            "bucket_tickets",
            "bucket_triage",
            "bucket_resolution_status",
            "bucket_resolution_events",
            "project_integrations",
            "cloud_runs",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE app_id = $1"))
                .bind(app_id)
                .execute(&mut *tx)
                .await?;
        }
        let deleted = sqlx::query("DELETE FROM projects WHERE app_id = $1")
            .bind(app_id)
            .execute(&mut *tx)
            .await?
            .rows_affected()
            > 0;
        tx.commit().await?;
        Ok(deleted)
    }

    // ---- human-authored original captures ---------------------------------

    pub async fn create_capture(&self, capture: NewCapture<'_>) -> anyhow::Result<bool> {
        let inserted = sqlx::query(
            "INSERT INTO captures
               (id, review_token_hash, created_by, app_id, platform, target,
                source_created_at, manifest, expires_at)
             SELECT $1,$2,$3,$4,$5,$6,$7,$8,now() + interval '30 minutes'
             WHERE $4::text IS NULL OR EXISTS
               (SELECT 1 FROM projects WHERE app_id = $4)
             ON CONFLICT (id) DO UPDATE
             SET review_token_hash=EXCLUDED.review_token_hash,
                 app_id=EXCLUDED.app_id, expires_at=EXCLUDED.expires_at,
                 updated_at=now()
             WHERE captures.status='pending_review'
               AND captures.manifest=EXCLUDED.manifest",
        )
        .bind(capture.id)
        .bind(capture.review_token_hash)
        .bind(capture.created_by)
        .bind(capture.app_id)
        .bind(capture.platform)
        .bind(capture.target)
        .bind(capture.source_created_at)
        .bind(capture.manifest)
        .execute(self.pool.as_ref())
        .await?
        .rows_affected()
            > 0;
        Ok(inserted)
    }

    pub async fn capture(&self, id: &str) -> anyhow::Result<Option<CaptureRow>> {
        let row = sqlx::query(
            "SELECT id, app_id, status, title, description, severity, visibility,
                    platform, target, source_created_at, manifest,
                    expires_at::text, created_at::text
             FROM captures WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.pool.as_ref())
        .await?;
        Ok(row.map(capture_from_row))
    }

    pub async fn capture_for_review(
        &self,
        review_token_hash: &str,
    ) -> anyhow::Result<Option<CaptureRow>> {
        let row = sqlx::query(
            "SELECT id, app_id, status, title, description, severity, visibility,
                    platform, target, source_created_at, manifest,
                    expires_at::text, created_at::text
             FROM captures
             WHERE review_token_hash = $1 AND expires_at > now()",
        )
        .bind(review_token_hash)
        .fetch_optional(self.pool.as_ref())
        .await?;
        Ok(row.map(capture_from_row))
    }

    pub async fn approve_capture(&self, approval: CaptureApproval<'_>) -> anyhow::Result<bool> {
        let updated = sqlx::query(
            "UPDATE captures
             SET app_id=$2, title=$3, description=$4, severity=$5,
                 visibility=$6, status='approved', updated_at=now()
             WHERE review_token_hash=$1 AND expires_at > now()
               AND status='pending_review'
               AND EXISTS (SELECT 1 FROM projects WHERE app_id=$2)",
        )
        .bind(approval.review_token_hash)
        .bind(approval.app_id)
        .bind(approval.title)
        .bind(approval.description)
        .bind(approval.severity)
        .bind(approval.visibility)
        .execute(self.pool.as_ref())
        .await?
        .rows_affected()
            > 0;
        Ok(updated)
    }

    pub async fn add_capture_file(
        &self,
        file: PendingCaptureFile<'_>,
    ) -> anyhow::Result<Option<bool>> {
        let mut tx = self.pool.begin().await?;
        let app_id = sqlx::query_scalar::<_, String>(
            "SELECT app_id FROM captures
             WHERE id=$1 AND status IN ('approved','uploading')",
        )
        .bind(file.capture_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(app_id) = app_id else {
            tx.rollback().await?;
            return Ok(None);
        };
        if let Some(max) = file.quota_bytes {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
                .bind(&app_id)
                .execute(&mut *tx)
                .await?;
            let used: i64 = sqlx::query_scalar(
                "SELECT
                   (SELECT COALESCE(SUM(bytes),0)::BIGINT
                    FROM evidence WHERE app_id=$1) +
                   (SELECT COALESCE(SUM(files.bytes),0)::BIGINT
                    FROM capture_files files
                    JOIN captures ON captures.id=files.capture_id
                    WHERE captures.app_id=$1
                      AND NOT (files.capture_id=$2 AND files.filename=$3))",
            )
            .bind(&app_id)
            .bind(file.capture_id)
            .bind(file.filename)
            .fetch_one(&mut *tx)
            .await?;
            if !quota_allows(used, file.bytes, max) {
                tx.rollback().await?;
                return Ok(Some(false));
            }
        }
        sqlx::query(
            "INSERT INTO capture_files
               (capture_id, filename, storage_key, bytes, sha256, content_type)
             VALUES ($1,$2,$3,$4,$5,$6)
             ON CONFLICT (capture_id, filename) DO UPDATE
             SET storage_key=EXCLUDED.storage_key, bytes=EXCLUDED.bytes,
                 sha256=EXCLUDED.sha256, content_type=EXCLUDED.content_type,
                 uploaded=false,
                 created_at=now()",
        )
        .bind(file.capture_id)
        .bind(file.filename)
        .bind(file.storage_key)
        .bind(file.bytes)
        .bind(file.sha256)
        .bind(file.content_type)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE captures SET status='uploading', updated_at=now() WHERE id=$1")
            .bind(file.capture_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(true))
    }

    pub async fn remove_capture_file(
        &self,
        capture_id: &str,
        filename: &str,
    ) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM capture_files WHERE capture_id=$1 AND filename=$2")
            .bind(capture_id)
            .bind(filename)
            .execute(self.pool.as_ref())
            .await?;
        Ok(())
    }

    pub async fn mark_capture_file_uploaded(
        &self,
        capture_id: &str,
        filename: &str,
    ) -> anyhow::Result<bool> {
        Ok(sqlx::query(
            "UPDATE capture_files SET uploaded=true
             WHERE capture_id=$1 AND filename=$2",
        )
        .bind(capture_id)
        .bind(filename)
        .execute(self.pool.as_ref())
        .await?
        .rows_affected()
            > 0)
    }

    pub async fn capture_files(&self, capture_id: &str) -> anyhow::Result<Vec<CaptureFileRow>> {
        let rows = sqlx::query(
            "SELECT filename, storage_key, bytes, sha256, content_type
             FROM capture_files
             WHERE capture_id=$1 AND uploaded=true ORDER BY filename",
        )
        .bind(capture_id)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| CaptureFileRow {
                filename: row.get("filename"),
                storage_key: row.get("storage_key"),
                bytes: row.get("bytes"),
                sha256: row.get("sha256"),
                content_type: row.get("content_type"),
            })
            .collect())
    }

    pub async fn captures_for_app(&self, app_id: &str) -> anyhow::Result<Vec<CaptureRow>> {
        let rows = sqlx::query(
            "SELECT id, app_id, status, title, description, severity, visibility,
                    platform, target, source_created_at, manifest,
                    expires_at::text, created_at::text
             FROM captures WHERE app_id=$1 ORDER BY created_at, id",
        )
        .bind(app_id)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows.into_iter().map(capture_from_row).collect())
    }

    pub async fn complete_capture(&self, capture_id: &str) -> anyhow::Result<bool> {
        Ok(sqlx::query(
            "UPDATE captures
             SET status='complete', expires_at=now(), updated_at=now()
             WHERE id=$1 AND status IN ('approved','uploading')",
        )
        .bind(capture_id)
        .execute(self.pool.as_ref())
        .await?
        .rows_affected()
            > 0)
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
}

fn capture_from_row(row: sqlx::postgres::PgRow) -> CaptureRow {
    CaptureRow {
        id: row.get("id"),
        app_id: row.get("app_id"),
        status: row.get("status"),
        title: row.get("title"),
        description: row.get("description"),
        severity: row.get("severity"),
        visibility: row.get("visibility"),
        platform: row.get("platform"),
        target: row.get("target"),
        source_created_at: row.get("source_created_at"),
        manifest: row.get("manifest"),
        expires_at: row.get("expires_at"),
        created_at: row.get("created_at"),
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
