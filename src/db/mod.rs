//! Durable persistence on Postgres (via sqlx), split across the TWO PLANES of the
//! database-per-org architecture (`docs/architecture/multi-tenancy.md`):
//!
//!   - [`control::ControlStore`] is the one small SHARED control DB: tenants
//!     registry, identity, API keys, billing, SSO. The only cross-tenant database,
//!     and it holds NO customer telemetry/videos. It is the routing table.
//!   - [`tenant::TenantStore`] is a handle on ONE org's database (telemetry,
//!     errors, evidence, triage, jobs). App-scoped tables carry no `org_id`,
//!     because the database IS the org boundary. A handler is handed a
//!     `TenantStore` already bound to the caller's tenant.
//!
//! Both planes apply their schema idempotently (pre-launch: no migration
//! ledger; [`schema::TENANT_SCHEMA`] is applied at provision and on boot, the
//! control schema on boot). This module holds the shared row types and the
//! key-hash helper both stores use.

mod artifacts;
pub mod control;
pub mod schema;
pub mod secrets;
pub mod tenant;

pub use control::ControlStore;
pub use tenant::{AnchoredBucket, TenantStore};
// `ResolutionEvent` / `TicketLink` are named only through method return types, so
// they need no re-export today; kept available behind the modules for callers that
// want to name them directly.
#[allow(unused_imports)]
pub use tenant::{ResolutionEvent, TicketLink};

/// An authenticated identity (resolved from a session cookie). Lives in the
/// control plane: identity must work BEFORE we know the tenant.
#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub email: String,
}

/// The org context a user is acting in (their org + their role in it).
#[derive(Debug, Clone)]
pub struct Org {
    pub id: i64,
    pub name: String,
    pub role: String,
}

/// A member of an org.
#[derive(Debug, Clone)]
pub struct Member {
    pub user_id: i64,
    pub email: String,
    pub role: String,
    /// Effective dashboard seat (the `seat` flag OR an always-seated owner).
    pub seat: bool,
}

#[derive(Debug, Clone)]
pub struct OrgSummary {
    pub id: i64,
    pub name: String,
    pub plan: String,
    pub role: String,
    pub personal: bool,
}

/// Pending organization invitation. Only a digest of the raw invitation token
/// is persisted; list APIs never expose it.
#[derive(Debug, Clone)]
pub struct OrgInvitation {
    pub id: i64,
    pub org_name: String,
    pub email: String,
    pub role: String,
    pub seat: bool,
    pub expires_at: String,
}

/// A persisted triage row for a bucket (tenant DB).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Triage {
    pub status: String,
    pub assignee: Option<i64>,
    pub updated_at: String,
    #[serde(rename = "fixedInBuild")]
    pub fixed_in_build: Option<String>,
}

/// A shard claimed off a tenant's durable queue: everything a worker needs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClaimedShard {
    pub job_id: String,
    pub seed: u32,
    pub claimed_by: String,
    pub backend: String,
    pub app_dir: String,
    pub budget: u32,
}

/// The lifecycle status of a tenant in the control-plane registry. The resolver
/// only serves `Active` tenants; the others are transient or operational states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantStatus {
    /// Provisioning is in flight (the durable record an attempt started). A crash
    /// here leaves a row a background reconciler can finish.
    Provisioning,
    /// Fully provisioned and serving.
    Active,
    /// Ops-suspended (billing/abuse). Resolver refuses; data is intact.
    Suspended,
    /// Maintenance state (schema being applied / tenant being moved).
    Migrating,
}

impl TenantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TenantStatus::Provisioning => "provisioning",
            TenantStatus::Active => "active",
            TenantStatus::Suspended => "suspended",
            TenantStatus::Migrating => "migrating",
        }
    }
    pub fn parse(s: &str) -> TenantStatus {
        match s {
            "active" => TenantStatus::Active,
            "suspended" => TenantStatus::Suspended,
            "migrating" => TenantStatus::Migrating,
            _ => TenantStatus::Provisioning,
        }
    }
}

/// One tenant's registry record: the org id, its lifecycle status, and the two
/// things the app needs to talk to it, its Postgres connection string and its
/// blob scope. This is the contract the data layer is built on: "a Postgres
/// connection string per tenant" plus a blob scope.
#[derive(Debug, Clone)]
pub struct TenantRecord {
    pub org_id: i64,
    pub status: TenantStatus,
    /// The tenant's Postgres connection string (None while still provisioning).
    pub db_conn: Option<String>,
    /// Blob isolation mode: "prefix" (default) or "bucket".
    pub blob_mode: String,
    /// The bucket name (bucket mode) or key prefix (prefix mode).
    pub blob_scope: String,
    /// Data-residency region (recorded for residency routing; informational today).
    #[allow(dead_code)]
    pub region: Option<String>,
}

/// SHA-256 hex of an API-key secret. We store only this hash; the plaintext is
/// shown once at creation and never persisted or logged. Shared by both stores.
pub fn key_hash(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod schema_guard_tests {
    use super::control::CONTROL_SCHEMA;
    use super::schema::TENANT_SCHEMA;
    use std::collections::BTreeSet;

    /// Every `CREATE TABLE IF NOT EXISTS <name>` declared in a SQL string. The
    /// names are matched off the source SQL (not a live DB), so this guard runs
    /// with no Postgres.
    fn table_names(sql: &str) -> BTreeSet<String> {
        const MARKER: &str = "CREATE TABLE IF NOT EXISTS ";
        let mut names = BTreeSet::new();
        for (idx, _) in sql.match_indices(MARKER) {
            let rest = &sql[idx + MARKER.len()..];
            // The table name is the leading run of identifier chars (\w+).
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                names.insert(name);
            }
        }
        names
    }

    /// The CONTROL schema and the TENANT schema must declare DISJOINT table names.
    /// In the self-hosted edition BOTH run in ONE database, so a name collision
    /// would have the tenant-schema runner silently adopt (or clobber) a control
    /// table, or vice versa. This fails loudly the moment a schema edit reuses a
    /// control table name (or the reverse) so the collision is caught at build time.
    #[test]
    fn control_and_tenant_table_names_are_disjoint() {
        let control = table_names(CONTROL_SCHEMA);
        let tenant = table_names(TENANT_SCHEMA);
        // Sanity: both sets are non-empty (the regex actually matched something),
        // so a green test can never come from extracting zero names.
        assert!(
            control.contains("tenants") && control.contains("api_keys"),
            "control table extraction looks wrong: {control:?}"
        );
        assert!(
            tenant.contains("projects") && tenant.contains("errors"),
            "tenant table extraction looks wrong: {tenant:?}"
        );

        let collisions: Vec<&String> = control.intersection(&tenant).collect();
        assert!(
            collisions.is_empty(),
            "control and tenant schemas share table name(s) {collisions:?}; \
             self-host runs both in one database, so names must be disjoint"
        );
    }
}
