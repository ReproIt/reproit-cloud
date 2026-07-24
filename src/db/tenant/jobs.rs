//! Durable job and shard queue operations.

use super::*;

impl TenantStore {
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
        let seeds: Vec<i32> = job.shards.iter().map(|shard| shard.seed as i32).collect();
        sqlx::query(
            "INSERT INTO shards (job_id, seed, state, backend, duration_s)
             SELECT $1, seed, 'pending', $2, 0 FROM UNNEST($3::INT[]) AS seed",
        )
        .bind(&job.id)
        .bind(&job.backend)
        .bind(&seeds)
        .execute(&mut *tx)
        .await?;
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
            "WITH claimed AS (
               UPDATE shards SET state='running', claimed_by=$1, claimed_at=now(),
                    heartbeat_at=now(), attempts=attempts+1
               WHERE (job_id, seed) IN (
                 SELECT s.job_id, s.seed FROM shards s
                 WHERE s.state='pending' AND s.backend = ANY($2)
                 ORDER BY s.job_id, s.seed
                 FOR UPDATE SKIP LOCKED
                 LIMIT 1
               )
               RETURNING job_id, seed, claimed_by, backend
             )
             SELECT c.job_id, c.seed, c.claimed_by, c.backend, j.app_dir, j.budget
             FROM claimed c JOIN jobs j ON j.id=c.job_id",
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
        Ok(Some(ClaimedShard {
            job_id,
            seed: seed as u32,
            claimed_by,
            backend,
            app_dir: row.get::<String, _>("app_dir"),
            budget: row.get::<i32, _>("budget") as u32,
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
}
