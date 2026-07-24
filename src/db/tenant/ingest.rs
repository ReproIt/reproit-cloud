use super::*;

impl TenantStore {
    // ---- telemetry: edges / errors / evidence ------------------------------

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
        evidence: &[reproit_protocol::EvidenceGraph],
        batch_id: &str,
        deployment: Option<&str>,
    ) -> anyhow::Result<bool> {
        if edges.is_empty() && errors.is_empty() && evidence.is_empty() {
            return Ok(false);
        }
        let mut tx = self.pool.begin().await?;

        let r = sqlx::query(
            "INSERT INTO processed_batches (app_id, batch_id) VALUES ($1,$2)
             ON CONFLICT DO NOTHING",
        )
        .bind(app_id)
        .bind(batch_id)
        .execute(&mut *tx)
        .await?;
        if r.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(true);
        }

        if let Some(build) = deployment {
            sqlx::query(
                "INSERT INTO build_traffic (app_id, build, count) VALUES ($1,$2,1)
                 ON CONFLICT (app_id, build) DO UPDATE SET
                   count=build_traffic.count + 1, last_seen=now()",
            )
            .bind(app_id)
            .bind(build)
            .execute(&mut *tx)
            .await?;
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

        crate::db::artifacts::store_graphs(&mut tx, app_id, evidence).await?;

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

    /// Remove verified sample occurrences and, once the bucket is empty, its
    /// derived metadata. The caller supplies only occurrence ids it has already
    /// classified as sample data. A concurrent real occurrence is preserved and
    /// keeps the bucket metadata alive.
    pub async fn delete_sample_bucket_data(
        &self,
        app_id: &str,
        bucket_id: &str,
        error_ids: &[i64],
    ) -> anyhow::Result<(u64, Vec<String>)> {
        if error_ids.is_empty() {
            return Ok((0, Vec::new()));
        }
        let mut tx = self.pool.begin().await?;
        let evidence =
            sqlx::query("SELECT storage_key FROM evidence WHERE app_id=$1 AND error_id = ANY($2)")
                .bind(app_id)
                .bind(error_ids)
                .fetch_all(&mut *tx)
                .await?;
        let keys = evidence
            .iter()
            .map(|row| row.get::<String, _>("storage_key"))
            .collect();
        let deleted =
            sqlx::query("DELETE FROM errors WHERE app_id=$1 AND bucket_id=$2 AND id = ANY($3)")
                .bind(app_id)
                .bind(bucket_id)
                .bind(error_ids)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM errors WHERE app_id=$1 AND bucket_id=$2")
                .bind(app_id)
                .bind(bucket_id)
                .fetch_one(&mut *tx)
                .await?;
        if remaining == 0 {
            sqlx::query("DELETE FROM replay_results WHERE app_id=$1 AND bucket_id=$2")
                .bind(app_id)
                .bind(bucket_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM bucket_tickets WHERE app_id=$1 AND bucket_id=$2")
                .bind(app_id)
                .bind(bucket_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM bucket_triage WHERE app_id=$1 AND bucket_id=$2")
                .bind(app_id)
                .bind(bucket_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM bucket_resolution_status WHERE app_id=$1 AND bucket_id=$2")
                .bind(app_id)
                .bind(bucket_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM bucket_resolution_events WHERE app_id=$1 AND bucket_id=$2")
                .bind(app_id)
                .bind(bucket_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM cloud_runs WHERE app_id=$1 AND bucket_id=$2")
                .bind(app_id)
                .bind(bucket_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok((deleted, keys))
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
}
