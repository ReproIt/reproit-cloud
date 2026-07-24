use super::*;

impl ControlStore {
    // ---- orgs / membership -------------------------------------------------

    pub async fn create_org(&self, name: &str, personal: bool) -> anyhow::Result<i64> {
        let row = sqlx::query("INSERT INTO orgs (name, personal) VALUES ($1,$2) RETURNING id")
            .bind(name)
            .bind(personal)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("id"))
    }

    pub async fn add_member(&self, org_id: i64, user_id: i64, role: &str) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,$3)
             ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role",
        )
        .bind(org_id)
        .bind(user_id)
        .bind(role)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_user_orgs(&self, user_id: i64) -> anyhow::Result<Vec<OrgSummary>> {
        let rows = sqlx::query(
            "SELECT o.id, o.name, o.plan, o.personal, m.role
             FROM org_members m JOIN orgs o ON o.id = m.org_id
             WHERE m.user_id = $1 ORDER BY o.personal DESC, lower(o.name), o.id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| OrgSummary {
                id: r.get("id"),
                name: r.get("name"),
                plan: r.get("plan"),
                role: r.get("role"),
                personal: r.get("personal"),
            })
            .collect())
    }

    pub async fn rename_org(&self, org_id: i64, name: &str) -> anyhow::Result<bool> {
        let r = sqlx::query("UPDATE orgs SET name = $2 WHERE id = $1")
            .bind(org_id)
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn org_role(&self, org_id: i64, user_id: i64) -> anyhow::Result<Option<String>> {
        let row = sqlx::query("SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<String, _>("role")))
    }

    pub async fn count_owners(&self, org_id: i64) -> anyhow::Result<i64> {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM org_members WHERE org_id = $1 AND role = 'owner'",
        )
        .bind(org_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(n)
    }

    pub async fn set_member_role(
        &self,
        org_id: i64,
        user_id: i64,
        role: &str,
    ) -> anyhow::Result<bool> {
        let r = sqlx::query("UPDATE org_members SET role = $3 WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .bind(role)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn list_org_users(&self, org_id: i64) -> anyhow::Result<Vec<Member>> {
        let rows = sqlx::query(
            "WITH scoped AS (
               SELECT user_id FROM org_members WHERE org_id = $1
               UNION
               SELECT user_id FROM directory_users WHERE org_id = $1 AND active
             )
             SELECT u.id AS user_id, u.email, COALESCE(m.role, 'none') AS role,
                    (COALESCE(m.seat, false) OR m.role = 'owner') AS seat
             FROM scoped s
             JOIN users u ON u.id = s.user_id
             LEFT JOIN org_members m ON m.org_id = $1 AND m.user_id = s.user_id
             ORDER BY (m.role='owner') DESC NULLS LAST, (m.role IS NULL) ASC, u.email",
        )
        .bind(org_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Member {
                user_id: r.get::<i64, _>("user_id"),
                email: r.get::<String, _>("email"),
                role: r.get::<String, _>("role"),
                seat: r.get::<bool, _>("seat"),
            })
            .collect())
    }

    pub async fn remove_member(&self, org_id: i64, user_id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_org_invitation(
        &self,
        org_id: i64,
        email: &str,
        role: &str,
        seat: bool,
        invited_by: i64,
        raw_token: &str,
        ttl_secs: i64,
        seat_limit: Option<i64>,
    ) -> anyhow::Result<Option<i64>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM orgs WHERE id = $1 FOR UPDATE")
            .bind(org_id)
            .fetch_one(&mut *tx)
            .await?;
        if seat {
            if let Some(limit) = seat_limit {
                let used: i64 = sqlx::query_scalar(
                    "SELECT
                       (SELECT count(*) FROM org_members WHERE org_id = $1 AND (seat OR role = 'owner'))
                       +
                       (SELECT count(*) FROM org_invitations
                        WHERE org_id = $1 AND seat AND expires_at > now() AND email <> $2)",
                ).bind(org_id).bind(email).fetch_one(&mut *tx).await?;
                if used >= limit {
                    tx.rollback().await?;
                    return Ok(None);
                }
            }
        }
        let expires = chrono::Utc::now() + chrono::Duration::seconds(ttl_secs);
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO org_invitations
               (token_hash, org_id, email, role, seat, invited_by, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (org_id, email) DO UPDATE SET
               token_hash=EXCLUDED.token_hash, role=EXCLUDED.role, seat=EXCLUDED.seat,
               invited_by=EXCLUDED.invited_by, expires_at=EXCLUDED.expires_at, updated_at=now()
             RETURNING id",
        )
        .bind(super::key_hash(raw_token))
        .bind(org_id)
        .bind(email)
        .bind(role)
        .bind(seat)
        .bind(invited_by)
        .bind(expires)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(id))
    }

    pub async fn list_org_invitations(&self, org_id: i64) -> anyhow::Result<Vec<OrgInvitation>> {
        let rows = sqlx::query(
            "SELECT i.id, o.name AS org_name, i.email, i.role, i.seat, i.expires_at
             FROM org_invitations i JOIN orgs o ON o.id=i.org_id
             WHERE i.org_id=$1 AND i.expires_at>now() ORDER BY lower(i.email)",
        )
        .bind(org_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_invitation).collect())
    }

    pub async fn org_invitation_by_token(
        &self,
        raw_token: &str,
    ) -> anyhow::Result<Option<OrgInvitation>> {
        let row = sqlx::query(
            "SELECT i.id, o.name AS org_name, i.email, i.role, i.seat, i.expires_at
             FROM org_invitations i JOIN orgs o ON o.id=i.org_id
             WHERE i.token_hash=$1 AND i.expires_at>now()",
        )
        .bind(super::key_hash(raw_token))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_invitation))
    }

    pub async fn refresh_org_invitation(
        &self,
        org_id: i64,
        invitation_id: i64,
        raw_token: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<Option<OrgInvitation>> {
        let expires = chrono::Utc::now() + chrono::Duration::seconds(ttl_secs);
        let row = sqlx::query(
            "UPDATE org_invitations i SET token_hash=$3, expires_at=$4, updated_at=now()
             FROM orgs o WHERE i.id=$2 AND i.org_id=$1 AND o.id=i.org_id
             RETURNING i.id, o.name AS org_name, i.email, i.role, i.seat, i.expires_at",
        )
        .bind(org_id)
        .bind(invitation_id)
        .bind(super::key_hash(raw_token))
        .bind(expires)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_invitation))
    }

    pub async fn revoke_org_invitation(
        &self,
        org_id: i64,
        invitation_id: i64,
    ) -> anyhow::Result<bool> {
        let r = sqlx::query("DELETE FROM org_invitations WHERE org_id=$1 AND id=$2")
            .bind(org_id)
            .bind(invitation_id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn accept_org_invitation(
        &self,
        raw_token: &str,
        user_id: i64,
        verified_email: &str,
    ) -> anyhow::Result<Option<i64>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "DELETE FROM org_invitations
             WHERE token_hash=$1 AND email=$2 AND expires_at>now()
             RETURNING org_id, role, seat",
        )
        .bind(super::key_hash(raw_token))
        .bind(verified_email)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let org_id: i64 = row.get("org_id");
        sqlx::query(
            "INSERT INTO org_members (org_id,user_id,role,seat) VALUES ($1,$2,$3,$4)
             ON CONFLICT (org_id,user_id) DO UPDATE SET role=EXCLUDED.role, seat=org_members.seat OR EXCLUDED.seat",
        ).bind(org_id).bind(user_id).bind(row.get::<String,_>("role")).bind(row.get::<bool,_>("seat"))
            .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(Some(org_id))
    }

    pub async fn prune_org_invitations(&self) -> anyhow::Result<u64> {
        let r = sqlx::query("DELETE FROM org_invitations WHERE expires_at<now()")
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    pub async fn org_name(&self, org_id: i64) -> anyhow::Result<Option<String>> {
        let row = sqlx::query("SELECT name FROM orgs WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<String, _>("name")))
    }

    // ---- per-workspace dashboard access -------------------------------------

    pub async fn has_seat(&self, org_id: i64, user_id: i64) -> anyhow::Result<bool> {
        let row = sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM org_members
             WHERE org_id = $1 AND user_id = $2 AND (seat OR role = 'owner')",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    pub async fn set_seat(&self, org_id: i64, user_id: i64, seat: bool) -> anyhow::Result<bool> {
        let r = sqlx::query("UPDATE org_members SET seat = $3 WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .bind(seat)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() == 1)
    }
}
