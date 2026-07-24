//! Edition policy: the few points where the hosted SaaS and the self-hosted
//! edition behave differently INSIDE shared flow. Shared files (ingest,
//! evidence, the job worker) call these hooks instead of branching on the
//! edition, so they stay byte-identical across both repositories; each
//! edition installs its own implementation on `App` at construction.
//!
//! Self-host installs `PassivePolicy` (every hook a no-op / unlimited). The
//! hosted overlay implements plan quotas, metering, and tenant maintenance
//! scheduling in its own module. Keep this surface value-free: "may this org
//! ingest N more occurrences" is policy; plans and prices are not named here.
//!
//! Hooks return boxed futures (not `async fn`) so the trait stays
//! object-safe: `App` holds it as `Arc<dyn EditionPolicy>`.

use std::future::Future;
use std::pin::Pin;

/// A boxed hook future; the trait-object-safe shape of `async fn`.
pub type PolicyFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A denied ingest quota: the user-facing message plus the meter values the
/// 429 response surfaces. Contains no user data by construction.
pub struct QuotaDenied {
    pub message: String,
    pub used: i64,
    pub limit: i64,
}

pub trait EditionPolicy: Send + Sync {
    /// May this org ingest `n_errors` more occurrences right now? A denial is
    /// returned to the SDK as 429 with the meter values. An allowing edition
    /// may also use this pre-persist point to schedule tenant maintenance.
    fn check_ingest_quota<'a>(
        &'a self,
        org_id: i64,
        n_errors: u64,
    ) -> PolicyFuture<'a, Result<(), QuotaDenied>>;

    /// Observe an accepted (non-deduped) batch, e.g. to meter usage.
    /// Best-effort: failures must be logged by the implementation, never
    /// surfaced to the SDK.
    fn on_batch_accepted<'a>(&'a self, org_id: i64, n_errors: u64) -> PolicyFuture<'a, ()>;

    /// Observe a job shard claim, e.g. to schedule stranded-shard sweeps.
    fn on_shard_claimed<'a>(&'a self, org_id: i64) -> PolicyFuture<'a, ()>;

    /// The edition's per-app evidence byte cap, or None to defer to the
    /// operator's environment cap.
    fn evidence_cap<'a>(&'a self, org_id: i64) -> PolicyFuture<'a, Option<i64>>;

    /// The edition's data retention window in days, or None when the operator
    /// owns retention (exports then cover everything).
    fn retention_days<'a>(&'a self, org_id: i64) -> PolicyFuture<'a, Option<i64>>;

    /// Observe tenant activity that an edition may follow up on (`kind` is a
    /// static tag such as "resolution" or "cloud-runs"). The hosted edition
    /// schedules the matching maintenance sweep; best-effort, never surfaced.
    fn on_tenant_activity<'a>(&'a self, org_id: i64, kind: &'static str) -> PolicyFuture<'a, ()>;
}

/// The self-hosted edition: no quotas, no metering, no tenant maintenance
/// scheduling. Operators bound evidence through the environment instead.
pub struct PassivePolicy;

impl EditionPolicy for PassivePolicy {
    fn check_ingest_quota<'a>(
        &'a self,
        _org_id: i64,
        _n_errors: u64,
    ) -> PolicyFuture<'a, Result<(), QuotaDenied>> {
        Box::pin(async { Ok(()) })
    }

    fn on_batch_accepted<'a>(&'a self, _org_id: i64, _n_errors: u64) -> PolicyFuture<'a, ()> {
        Box::pin(async {})
    }

    fn on_shard_claimed<'a>(&'a self, _org_id: i64) -> PolicyFuture<'a, ()> {
        Box::pin(async {})
    }

    fn evidence_cap<'a>(&'a self, _org_id: i64) -> PolicyFuture<'a, Option<i64>> {
        Box::pin(async { None })
    }

    fn retention_days<'a>(&'a self, _org_id: i64) -> PolicyFuture<'a, Option<i64>> {
        Box::pin(async { None })
    }

    fn on_tenant_activity<'a>(&'a self, _org_id: i64, _kind: &'static str) -> PolicyFuture<'a, ()> {
        Box::pin(async {})
    }
}
