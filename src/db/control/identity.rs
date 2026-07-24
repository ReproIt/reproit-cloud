//! User, email-token, session, and audit operations.

use super::*;

impl ControlStore {
    // ---- users / sessions --------------------------------------------------

    pub async fn create_user(&self, email: &str, pass_hash: &str) -> anyhow::Result<i64> {
        let row = sqlx::query("INSERT INTO users (email, pass_hash) VALUES ($1,$2) RETURNING id")
            .bind(email)
            .bind(pass_hash)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("id"))
    }

    pub async fn user_auth_by_email(&self, email: &str) -> anyhow::Result<Option<(i64, String)>> {
        let row = sqlx::query("SELECT id, pass_hash FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| (r.get::<i64, _>("id"), r.get::<String, _>("pass_hash"))))
    }

    pub async fn find_user_id_by_email(&self, email: &str) -> anyhow::Result<Option<i64>> {
        let row = sqlx::query("SELECT id FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<i64, _>("id")))
    }

    // ---- email flow tokens (verification / password reset) ------------------

    /// Store a single-use email token (hashed at rest, like sessions).
    // Consumed by the hosted verification/reset flow; self-host has no caller yet.
    #[allow(dead_code)]
    pub async fn create_email_token(
        &self,
        token: &str,
        user_id: i64,
        purpose: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<()> {
        let expires = chrono::Utc::now() + chrono::Duration::seconds(ttl_secs);
        sqlx::query(
            "INSERT INTO email_tokens (token_hash, user_id, purpose, expires_at) VALUES ($1,$2,$3,$4)",
        )
        .bind(crate::db::key_hash(token))
        .bind(user_id)
        .bind(purpose)
        .bind(expires)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Consume a token: DELETE ... RETURNING makes it strictly single-use even
    /// under concurrent requests. Returns the user id, or None if the token is
    /// unknown, expired, or for a different purpose.
    // Consumed by the hosted verification/reset flow; self-host has no caller yet.
    #[allow(dead_code)]
    pub async fn consume_email_token(
        &self,
        token: &str,
        purpose: &str,
    ) -> anyhow::Result<Option<i64>> {
        let row = sqlx::query(
            "DELETE FROM email_tokens
             WHERE token_hash = $1 AND purpose = $2 AND expires_at > now()
             RETURNING user_id",
        )
        .bind(crate::db::key_hash(token))
        .bind(purpose)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get::<i64, _>("user_id")))
    }

    // Consumed by the hosted verification/reset flow; self-host has no caller yet.
    #[allow(dead_code)]
    pub async fn prune_email_tokens(&self) -> anyhow::Result<u64> {
        let r = sqlx::query("DELETE FROM email_tokens WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    // Consumed by the hosted verification/reset flow; self-host has no caller yet.
    #[allow(dead_code)]
    pub async fn mark_email_verified(&self, user_id: i64) -> anyhow::Result<()> {
        sqlx::query("UPDATE users SET email_verified_at = now() WHERE id = $1 AND email_verified_at IS NULL")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // Consumed by the hosted verification/reset flow; self-host has no caller yet.
    #[allow(dead_code)]
    pub async fn email_verified(&self, user_id: i64) -> anyhow::Result<bool> {
        let row = sqlx::query("SELECT email_verified_at IS NOT NULL AS v FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<bool, _>("v")).unwrap_or(false))
    }

    /// Password reset: swap the hash and revoke every live session for the user
    /// (a reset must log out whoever holds the old credentials).
    // Consumed by the hosted verification/reset flow; self-host has no caller yet.
    #[allow(dead_code)]
    pub async fn set_password(&self, user_id: i64, pass_hash: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE users SET pass_hash = $2 WHERE id = $1")
            .bind(user_id)
            .bind(pass_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // Consumed by the hosted verification/reset flow; self-host has no caller yet.
    #[allow(dead_code)]
    pub async fn revoke_sessions_for_user(&self, user_id: i64) -> anyhow::Result<u64> {
        let r = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    // Sessions are stored HASHED (same SHA-256 scheme as API keys): a leaked DB
    // dump or backup must not yield live 30-day sessions. The raw token exists
    // only in the user's cookie; every query binds key_hash(token).
    pub async fn create_session(
        &self,
        token: &str,
        user_id: i64,
        ttl_secs: i64,
    ) -> anyhow::Result<()> {
        let expires = chrono::Utc::now() + chrono::Duration::seconds(ttl_secs);
        sqlx::query(
            "INSERT INTO sessions (token, user_id, active_org_id, expires_at)
             VALUES ($1,$2,(
               SELECT o.id FROM org_members m JOIN orgs o ON o.id = m.org_id
               WHERE m.user_id = $2
               ORDER BY o.personal DESC, o.id ASC LIMIT 1
             ),$3)",
        )
        .bind(crate::db::key_hash(token))
        .bind(user_id)
        .bind(expires)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn user_for_session(&self, token: &str) -> anyhow::Result<Option<User>> {
        let row = sqlx::query(
            "SELECT u.id, u.email FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token = $1 AND (s.expires_at IS NULL OR s.expires_at > now())",
        )
        .bind(crate::db::key_hash(token))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| User {
            id: r.get::<i64, _>("id"),
            email: r.get::<String, _>("email"),
        }))
    }

    // Consumed by the hosted verification/reset flow; self-host has no caller yet.
    #[allow(dead_code)]
    pub async fn user_by_id(&self, user_id: i64) -> anyhow::Result<Option<User>> {
        let row = sqlx::query("SELECT id, email FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| User {
            id: r.get::<i64, _>("id"),
            email: r.get::<String, _>("email"),
        }))
    }

    /// Resolve both identity and the organization selected for this session.
    /// If a stale selection no longer belongs to the user, fall back to their
    /// normal first organization without ever crossing a membership boundary.
    pub async fn user_and_org_for_session(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<(User, Org)>> {
        let row = sqlx::query(
            "WITH live AS (
               SELECT user_id, active_org_id FROM sessions
               WHERE token = $1 AND (expires_at IS NULL OR expires_at > now())
             )
             SELECT u.id AS user_id, u.email, o.id, o.name, o.plan, m.role
             FROM live s
             JOIN users u ON u.id = s.user_id
             JOIN org_members m ON m.user_id = s.user_id
             JOIN orgs o ON o.id = m.org_id
             ORDER BY (o.id = s.active_org_id) DESC, o.personal DESC, o.id ASC
             LIMIT 1",
        )
        .bind(crate::db::key_hash(token))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            (
                User {
                    id: r.get::<i64, _>("user_id"),
                    email: r.get::<String, _>("email"),
                },
                Org {
                    id: r.get::<i64, _>("id"),
                    name: r.get::<String, _>("name"),
                    plan: r.get::<String, _>("plan"),
                    role: r.get::<String, _>("role"),
                },
            )
        }))
    }

    pub async fn set_session_org(
        &self,
        token: &str,
        user_id: i64,
        org_id: i64,
    ) -> anyhow::Result<bool> {
        let r = sqlx::query(
            "UPDATE sessions s SET active_org_id = $3
             WHERE s.token = $1 AND s.user_id = $2
               AND (s.expires_at IS NULL OR s.expires_at > now())
               AND EXISTS (
                 SELECT 1 FROM org_members m WHERE m.org_id = $3 AND m.user_id = $2
               )",
        )
        .bind(crate::db::key_hash(token))
        .bind(user_id)
        .bind(org_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Append a security-audit row. Fire-and-forget by design: auditing must
    /// never fail (or slow the tail of) the request being audited, so failures
    /// are logged and swallowed here rather than surfaced to the caller.
    pub async fn audit(
        &self,
        actor: &str,
        action: &str,
        org_id: Option<i64>,
        detail: serde_json::Value,
    ) {
        let r = sqlx::query(
            "INSERT INTO audit_log (actor, action, org_id, detail) VALUES ($1,$2,$3,$4)",
        )
        .bind(actor)
        .bind(action)
        .bind(org_id)
        .bind(detail)
        .execute(&self.pool)
        .await;
        if let Err(e) = r {
            tracing::warn!("audit write failed ({actor} {action}): {e}");
        }
    }

    /// The most recent audit rows for one org, NEWEST FIRST. The table was
    /// write-only until this read; the ops CLI (`audit <org>`) is its first
    /// consumer. One indexed backward scan (`audit_log_org` is (org_id, id)),
    /// bounded by `limit`.
    pub async fn audit_for_org(&self, org_id: i64, limit: i64) -> anyhow::Result<Vec<AuditRow>> {
        let rows = sqlx::query(
            "SELECT actor, action, detail, at FROM audit_log
             WHERE org_id = $1 ORDER BY id DESC LIMIT $2",
        )
        .bind(org_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| AuditRow {
                actor: r.get::<String, _>("actor"),
                action: r.get::<String, _>("action"),
                detail: r.get::<serde_json::Value, _>("detail"),
                at: r.get::<chrono::DateTime<chrono::Utc>, _>("at").to_rfc3339(),
            })
            .collect())
    }

    pub async fn prune_sessions(&self) -> anyhow::Result<u64> {
        let r =
            sqlx::query("DELETE FROM sessions WHERE expires_at IS NOT NULL AND expires_at < now()")
                .execute(&self.pool)
                .await?;
        Ok(r.rows_affected())
    }

    pub async fn delete_session(&self, token: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(crate::db::key_hash(token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
