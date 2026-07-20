//! Focused telemetry writes and deployment traffic reads.

use super::*;

impl TenantStore {
    #[allow(dead_code)]
    pub async fn incr_edge(&self, app_id: &str, key: &str) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO edges (app_id, edge_key, count) VALUES ($1,$2,1)
             ON CONFLICT (app_id, edge_key) DO UPDATE SET count = edges.count + 1",
        )
        .bind(app_id)
        .bind(key)
        .execute(self.pool.as_ref())
        .await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn add_error(&self, app_id: &str, rec: &ErrorRec) -> anyhow::Result<()> {
        let bucket_id = crate::ingest::buckets::bucket_id(rec);
        sqlx::query(
            "INSERT INTO errors (app_id, sig, message, path, context, bucket_id)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(app_id)
        .bind(&rec.sig)
        .bind(&rec.message)
        .bind(Json(&rec.path))
        .bind(Json(&rec.context))
        .bind(bucket_id)
        .execute(self.pool.as_ref())
        .await?;
        Ok(())
    }

    pub async fn build_traffic(&self, app_id: &str) -> anyhow::Result<Vec<(String, u64, String)>> {
        let rows = sqlx::query(
            "SELECT build, count, first_seen FROM build_traffic
             WHERE app_id=$1 ORDER BY first_seen, build",
        )
        .bind(app_id)
        .fetch_all(self.pool.as_ref())
        .await?;
        Ok(rows
            .iter()
            .map(|row| {
                (
                    row.get("build"),
                    row.get::<i64, _>("count").max(0) as u64,
                    row.get::<chrono::DateTime<chrono::Utc>, _>("first_seen")
                        .to_rfc3339(),
                )
            })
            .collect())
    }
}
