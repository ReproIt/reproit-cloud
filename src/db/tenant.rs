//! The TENANT-bound store: a handle on ONE org's database. Every method here runs
//! plain queries with NO `org_id` filter, because the database IS the org boundary
//! (see `docs/architecture/multi-tenancy.md`). A handler is handed a `TenantStore`
//! already bound to the caller's tenant; a cross-tenant read is physically
//! impossible because there is nothing else in this database to leak.
//!
//! This is the heart of why the self-hosted edition is free: the handlers are
//! single-tenant by construction. The SaaS picks WHICH database per request (the
//! resolver hands the right `TenantStore`); self-hosted always hands the same one.
//!
//! It owns the per-tenant pool but does NOT own its lifetime: pools are created,
//! cached, and idle-evicted by `crate::tenancy::pool::TenantPools` so thousands of
//! tenants never exhaust Postgres backends. A `TenantStore` is therefore cheap to
//! clone (an `Arc<PgPool>` inside) and short-lived per request.

use super::{ClaimedShard, Triage};
use crate::ingest::{ErrorRec, ReplayResult, Step};
use crate::jobs::{Job, ShardState};
use serde_json::{json, Value};
use sqlx::types::Json;
use sqlx::{PgPool, Row};
use std::sync::Arc;

mod captures;
mod jobs;
mod projects;
mod telemetry;
mod triage;

/// A connection handle bound to one tenant's database. Clone is cheap (shares the
/// underlying pool). Handlers receive this, never a global store.
#[derive(Clone)]
pub struct TenantStore {
    pool: Arc<PgPool>,
}

/// A ticket link read back from a tenant DB (was `db::integrations::TicketLink`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct TicketLink {
    pub provider: String,
    pub repo: String,
    #[serde(rename = "externalId")]
    pub external_id: String,
    pub url: String,
}

/// One app's tracker + reproduction-dispatch config (`project_integrations`).
/// Token fields hold the ENCRYPTED (`db::secrets`) value exactly as stored;
/// decryption happens at the point of use, never here.
#[derive(Debug, Clone, Default)]
pub struct IntegrationRow {
    pub provider: String,
    pub repo: Option<String>,
    pub base_url: Option<String>,
    pub user_email: Option<String>,
    pub extra: Value,
    pub token_enc: Option<String>,
    pub dispatch_repo: Option<String>,
    pub dispatch_token_enc: Option<String>,
}

/// A bucket the regression sweep must evaluate (was `db::resolution::AnchoredBucket`).
#[derive(Debug, Clone)]
pub struct AnchoredBucket {
    pub app_id: String,
    pub bucket_id: String,
    pub fixed_in_build: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureRow {
    pub id: String,
    pub app_id: Option<String>,
    pub status: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub severity: String,
    pub visibility: String,
    pub platform: String,
    pub target: String,
    pub source_created_at: String,
    pub manifest: Value,
    pub expires_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureFileRow {
    pub filename: String,
    pub storage_key: String,
    pub bytes: i64,
    pub sha256: String,
    pub content_type: String,
}

// The capture parameter structs and store methods are consumed by the
// capture intake handlers; the hosted edition does not mount those routes
// yet, so it carries them unused.
#[allow(dead_code)]
pub struct NewCapture<'a> {
    pub id: &'a str,
    pub review_token_hash: &'a str,
    pub created_by: Option<i64>,
    pub app_id: Option<&'a str>,
    pub platform: &'a str,
    pub target: &'a str,
    pub source_created_at: &'a str,
    pub manifest: &'a Value,
}

#[allow(dead_code)]
pub struct CaptureApproval<'a> {
    pub review_token_hash: &'a str,
    pub app_id: &'a str,
    pub title: &'a str,
    pub description: &'a str,
    pub severity: &'a str,
    pub visibility: &'a str,
}

#[allow(dead_code)]
pub struct PendingCaptureFile<'a> {
    pub capture_id: &'a str,
    pub filename: &'a str,
    pub storage_key: &'a str,
    pub bytes: i64,
    pub sha256: &'a str,
    pub content_type: &'a str,
    pub quota_bytes: Option<i64>,
}

/// One persisted resolution-status transition (was `db::resolution::ResolutionEvent`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolutionEvent {
    #[serde(rename = "bucketId")]
    pub bucket_id: String,
    #[serde(rename = "fromStatus")]
    pub from_status: Option<String>,
    #[serde(rename = "toStatus")]
    pub to_status: String,
    pub build: Option<String>,
    pub at: String,
}

#[derive(Clone)]
pub struct BucketRollup {
    pub bucket_id: String,
    pub count: u64,
    pub last_seen: String,
    pub oldest: ErrorRec,
    pub newest: ErrorRec,
}

pub struct IntegrationWork {
    pub id: i64,
    pub app_id: String,
    pub bucket_id: String,
}

impl TenantStore {
    pub async fn proof_ledger(
        &self,
        app_id: &str,
        run_id: &str,
    ) -> anyhow::Result<Option<(String, reproit_protocol::ProofLedger)>> {
        let row = sqlx::query(
            "SELECT roots.root_id, nodes.payload
             FROM artifact_roots roots
             JOIN artifact_nodes nodes
               ON nodes.app_id = roots.app_id AND nodes.node_id = roots.root_id
             WHERE roots.app_id = $1 AND roots.run_id = $2 AND nodes.kind = 'proof-ledger'
             ORDER BY roots.created_at DESC, roots.root_id
             LIMIT 1",
        )
        .bind(app_id)
        .bind(run_id)
        .fetch_optional(self.pool.as_ref())
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let root: String = row.try_get("root_id")?;
        let payload: Value = row.try_get("payload")?;
        let ledger: reproit_protocol::ProofLedger = serde_json::from_value(payload)?;
        ledger.validate()?;
        Ok(Some((root, ledger)))
    }

    /// Wrap an already-acquired tenant pool. The pool's lifecycle (creation, idle
    /// eviction) is the `TenantPools` manager's job; this just binds queries to it.
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// Liveness probe against the tenant DB. (Available for a per-tenant readiness
    /// check; the top-level `/ready` probes the control plane.)
    #[allow(dead_code)]
    pub async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(self.pool.as_ref())
            .await?;
        Ok(())
    }
}

fn row_to_error(r: &sqlx::postgres::PgRow) -> ErrorRec {
    let Json(path): Json<Vec<Step>> = r.get("path");
    let Json(context): Json<serde_json::Map<String, Value>> = r.get("context");
    ErrorRec {
        sig: r.get("sig"),
        message: r.get("message"),
        path,
        context,
    }
}

/// Overflow-safe quota comparison used by `add_evidence_within_quota`.
fn quota_allows(used: i64, incoming: i64, max: i64) -> bool {
    used.checked_add(incoming).is_some_and(|n| n <= max)
}

#[cfg(test)]
mod tests {
    use super::quota_allows;

    #[test]
    fn quota_comparison_is_inclusive_and_overflow_safe() {
        assert!(quota_allows(80, 20, 100));
        assert!(!quota_allows(80, 21, 100));
        assert!(!quota_allows(i64::MAX, 1, i64::MAX));
    }
}
