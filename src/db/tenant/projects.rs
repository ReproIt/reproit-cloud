//! Project, integration, cloud-run, retention, and export operations.

use super::*;

impl TenantStore {
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

    /// The app id behind a tenant-db project id. Consumed by the self-host
    /// project routes; the hosted edition carries it unused.
    #[allow(dead_code)]
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
        // Evidence owns object metadata and updates app_storage_usage on delete.
        // Read models must be removed BEFORE errors: the per-error delete trigger
        // otherwise tries to recompute the last bucket summary from an empty error
        // set and violates its non-null first/last-id invariant.
        for table in [
            "evidence",
            "app_storage_usage",
            "artifact_roots",
            "artifact_nodes",
            "bucket_summaries",
            "bucket_windows",
            "app_context_counts",
            "bucket_context_counts",
            "errors",
            "edges",
            "build_traffic",
            "processed_batches",
            "replay_results",
            "bucket_tickets",
            "integration_outbox",
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

    /// How many projects this tenant owns. Consumed by the hosted seat/app
    /// caps; self-host has no cap, so it carries the read unused.
    #[allow(dead_code)]
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

    // ---- hosted reproduction runs (repository_dispatch ledger) ---------------

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
    /// Expiration is operational state only; customer-owned CI is not metered.
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
