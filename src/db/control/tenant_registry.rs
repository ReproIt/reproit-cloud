//! Tenant routing, provisioning, pending-work, and usage operations.

use super::*;

impl ControlStore {
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

    /// Tenants stuck in `provisioning` (a crash-recovery work list for the
    /// reconciler that finishes a half-provisioned tenant).
    pub async fn provisioning_tenants(&self) -> anyhow::Result<Vec<i64>> {
        let rows = sqlx::query("SELECT org_id FROM tenants WHERE status = 'provisioning'")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(|r| r.get::<i64, _>("org_id")).collect())
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

    pub async fn schedule_tenant_work(
        &self,
        org_id: i64,
        work_kind: &str,
        delay_secs: i64,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO tenant_due_work (org_id, work_kind, due_at)
             VALUES ($1,$2,now() + make_interval(secs => $3))
             ON CONFLICT (org_id, work_kind) DO UPDATE SET
               due_at=LEAST(tenant_due_work.due_at, EXCLUDED.due_at)",
        )
        .bind(org_id)
        .bind(work_kind)
        .bind(delay_secs.max(0) as f64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn tenants_due_for(&self, work_kind: &str, limit: i64) -> anyhow::Result<Vec<i64>> {
        let rows = sqlx::query(
            "SELECT org_id FROM tenant_due_work
             WHERE work_kind=$1 AND due_at <= now()
             ORDER BY due_at, org_id LIMIT $2",
        )
        .bind(work_kind)
        .bind(limit.clamp(1, 256))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(|row| row.get("org_id")).collect())
    }

    pub async fn reschedule_tenant_work(
        &self,
        org_id: i64,
        work_kind: &str,
        delay_secs: i64,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE tenant_due_work SET due_at=now() + make_interval(secs => $3)
             WHERE org_id=$1 AND work_kind=$2",
        )
        .bind(org_id)
        .bind(work_kind)
        .bind(delay_secs.max(1) as f64)
        .execute(&self.pool)
        .await?;
        Ok(())
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

    // ---- usage metering ------------------------------------------------------

    /// The org's plan string (orgs.plan), defaulting to free for a missing row.
    // Consumed by the hosted plan policy; self-host meters nothing.
    #[allow(dead_code)]
    pub async fn org_plan(&self, org_id: i64) -> anyhow::Result<String> {
        let row = sqlx::query("SELECT plan FROM orgs WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row
            .map(|r| r.get::<String, _>("plan"))
            .unwrap_or_else(|| "free".to_string()))
    }

    /// Increment this month's occurrence counter by one batch's error count.
    // Consumed by the hosted plan policy; self-host meters nothing.
    #[allow(dead_code)]
    pub async fn add_occurrences(&self, org_id: i64, n: i64) -> anyhow::Result<()> {
        if n <= 0 {
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO org_usage (org_id, period, occurrences)
             VALUES ($1, to_char(now(), 'YYYY-MM'), $2)
             ON CONFLICT (org_id, period)
             DO UPDATE SET occurrences = org_usage.occurrences + EXCLUDED.occurrences,
                           updated_at = now()",
        )
        .bind(org_id)
        .bind(n)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // Consumed by the hosted plan policy; self-host meters nothing.
    #[allow(dead_code)]
    pub async fn occurrences_this_month(&self, org_id: i64) -> anyhow::Result<i64> {
        let row = sqlx::query(
            "SELECT occurrences FROM org_usage
             WHERE org_id = $1 AND period = to_char(now(), 'YYYY-MM')",
        )
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get::<i64, _>("occurrences")).unwrap_or(0))
    }
}
