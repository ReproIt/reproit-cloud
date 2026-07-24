use super::*;

impl TenantStore {
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
