//! Human-authored original captures: report intake, review, approval, and
//! bounded file attachment under the evidence quota.

use super::*;

// Consumed by the capture intake handlers; the hosted edition does not mount
// those routes yet, so it carries the methods unused.
#[allow(dead_code)]
impl TenantStore {
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
