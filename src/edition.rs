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

    /// The edition's dashboard-seat cap for an org, or None for uncapped.
    /// Checked before granting a seat or reserving one on an invitation.
    fn seat_limit<'a>(&'a self, org_id: i64) -> PolicyFuture<'a, Option<i64>>;

    /// The edition's project/app-count cap for an org, or None for uncapped.
    /// Checked before creating a project.
    fn app_limit<'a>(&'a self, org_id: i64) -> PolicyFuture<'a, Option<i64>>;

    /// Validate a signup's checkout intent. The hosted edition names its
    /// purchasable plans; self-host carries no checkout intent, so the query
    /// parameter is ignored. Sync: a pure filter over the raw string.
    fn valid_checkout_plan(&self, plan: Option<&str>) -> Option<String>;

    /// The edition's account card: plan, limits, billing state, and identity
    /// provider bindings, merged into the `org` object of the `me` response.
    /// `Value::Null` (self-host) leaves the base shape untouched.
    fn account_card<'a>(&'a self, org_id: i64) -> PolicyFuture<'a, serde_json::Value>;

    /// The edition's usage meter: an object whose `plan` and `occurrences`
    /// members extend the usage response. `Value::Null` reports storage only.
    fn usage_meter<'a>(&'a self, org_id: i64) -> PolicyFuture<'a, serde_json::Value>;

    /// The login-method descriptor for `/auth/config` (which provider buttons
    /// the pages render), or None for the password-only default.
    fn auth_methods<'a>(&'a self) -> PolicyFuture<'a, Option<serde_json::Value>>;

    /// Refuse a password login before credentials are checked. Some(message)
    /// becomes a 403; the hosted edition refuses domains whose org enforces
    /// SSO. None never interferes with password login.
    fn login_denied<'a>(&'a self, email: &'a str) -> PolicyFuture<'a, Option<String>>;
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

    fn seat_limit<'a>(&'a self, _org_id: i64) -> PolicyFuture<'a, Option<i64>> {
        Box::pin(async { None })
    }

    fn app_limit<'a>(&'a self, _org_id: i64) -> PolicyFuture<'a, Option<i64>> {
        Box::pin(async { None })
    }

    fn valid_checkout_plan(&self, _plan: Option<&str>) -> Option<String> {
        None
    }

    fn on_tenant_activity<'a>(&'a self, _org_id: i64, _kind: &'static str) -> PolicyFuture<'a, ()> {
        Box::pin(async {})
    }

    fn account_card<'a>(&'a self, _org_id: i64) -> PolicyFuture<'a, serde_json::Value> {
        Box::pin(async { serde_json::Value::Null })
    }

    fn usage_meter<'a>(&'a self, _org_id: i64) -> PolicyFuture<'a, serde_json::Value> {
        Box::pin(async { serde_json::Value::Null })
    }

    fn auth_methods<'a>(&'a self) -> PolicyFuture<'a, Option<serde_json::Value>> {
        Box::pin(async { None })
    }

    fn login_denied<'a>(&'a self, _email: &'a str) -> PolicyFuture<'a, Option<String>> {
        Box::pin(async { None })
    }
}
