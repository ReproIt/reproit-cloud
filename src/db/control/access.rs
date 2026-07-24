use super::*;

impl ControlStore {
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

    pub async fn create_cli_authorization(
        &self,
        device_code: &str,
        user_code: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM cli_authorizations WHERE consumed OR expires_at <= now()")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT INTO cli_authorizations (device_hash, user_code_hash, expires_at)
             VALUES ($1,$2,now() + ($3 || ' seconds')::interval)",
        )
        .bind(super::key_hash(device_code))
        .bind(super::key_hash(&user_code.to_ascii_uppercase()))
        .bind(ttl_secs.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn approve_cli_authorization(
        &self,
        user_code: &str,
        user_id: i64,
        org_id: i64,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE cli_authorizations SET approved=true, user_id=$2, org_id=$3
             WHERE user_code_hash=$1 AND expires_at > now() AND NOT consumed",
        )
        .bind(super::key_hash(&user_code.to_ascii_uppercase()))
        .bind(user_id)
        .bind(org_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Return `(approved, consumed)` for a live device authorization.
    pub async fn cli_authorization_state(
        &self,
        device_code: &str,
    ) -> anyhow::Result<Option<(bool, bool)>> {
        let row = sqlx::query(
            "SELECT approved, consumed FROM cli_authorizations
             WHERE device_hash=$1 AND expires_at > now()",
        )
        .bind(super::key_hash(device_code))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| (r.get("approved"), r.get("consumed"))))
    }

    /// Atomically consume an approved device grant and mint its account token.
    /// Returns the selected org id, or `None` if the grant was not consumable.
    pub async fn consume_cli_authorization(
        &self,
        device_code: &str,
        secret: &str,
        prefix: &str,
    ) -> anyhow::Result<Option<i64>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT org_id, user_id FROM cli_authorizations
             WHERE device_hash=$1 AND approved AND NOT consumed AND expires_at > now()
             FOR UPDATE",
        )
        .bind(super::key_hash(device_code))
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let org_id: i64 = row.get("org_id");
        let user_id: i64 = row.get("user_id");
        sqlx::query(
            "INSERT INTO api_keys (key, prefix, org_id, created_by, project_id)
             VALUES ($1,$2,$3,$4,NULL)",
        )
        .bind(super::key_hash(secret))
        .bind(prefix)
        .bind(org_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE cli_authorizations SET consumed=true WHERE device_hash=$1")
            .bind(super::key_hash(device_code))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(org_id))
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

    /// (org_id, plan, project_id, created_by) that owns an API key. This is the
    /// hot per-request routing read: the org id it returns is
    /// what the resolver maps to a tenant database. `project_id` is the tenant-db
    /// project the key was minted for (None for org-wide keys); ingest uses it to
    /// pin a publishable key to its own app.
    pub async fn org_for_api_key(
        &self,
        presented: &str,
    ) -> anyhow::Result<Option<(i64, String, Option<i64>, Option<i64>)>> {
        let row = sqlx::query(
            "SELECT o.id, o.plan, k.project_id, k.created_by
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
                r.get::<String, _>("plan"),
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
            "UPDATE api_keys SET active = false WHERE project_id = $1 AND prefix LIKE 'pk_live_%'",
        )
        .bind(project_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Remove every credential scoped to a deleted project. Account-scoped CLI
    /// tokens have project_id NULL and remain valid for the user's other apps.
    pub async fn delete_api_keys_for_project(&self, project_id: i64) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM api_keys WHERE project_id = $1")
            .bind(project_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    pub async fn org_is_personal(&self, org_id: i64) -> anyhow::Result<Option<bool>> {
        sqlx::query_scalar("SELECT personal FROM orgs WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    pub async fn org_exists(&self, org_id: i64) -> anyhow::Result<bool> {
        let row = sqlx::query_scalar::<_, i32>("SELECT 1 FROM orgs WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }
}
