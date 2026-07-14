//! The PROVISIONING flow: the one operation that touches BOTH planes, so the one
//! that needs care (`docs/architecture/multi-tenancy.md` §3).
//!
//! Creating an org under database-per-org ACQUIRES a database. The flow is
//! engineered to be idempotent and crash-recoverable: a half-provisioned tenant
//! must be completable, never a dead-end. The order is deliberate:
//!
//!   1. Write control-plane INTENT (`tenants` row, status=provisioning). The
//!      durable record that an attempt is in flight.
//!   2. Provision the tenant DATABASE via the provider (idempotent on a stable
//!      per-org name, so a retry adopts the existing DB). Store the conn string.
//!   3. Run MIGRATIONS to head against the new DB (the same runner the fleet uses).
//!   4. Create the BLOB scope; record it in the control plane.
//!   5. REGISTER + flip status=active. Until this commit the resolver treats the
//!      tenant as not-yet-ready.
//!
//! Write intent first, do the external side effects (DB, blob) idempotently, flip
//! to active last. A crash at any step leaves a `provisioning` row a reconciler
//! finishes by simply re-running this function (every step is idempotent).
//!
//! Self-hosted: steps 2/4 are config not API calls; 1/5 collapse to "the single
//! tenant". `provision` still runs cleanly (the single-tenant provider returns the
//! one fixed conn, the schema applies to it, the blob scope is the one scope).

use super::provider::ConnectionProvider;
use super::Provider;
use crate::db::{ControlStore, TenantRecord, TenantStatus};

/// Owns the provisioning flow: a connection provider (how a tenant DB is made) and
/// the blob-scope policy. Holds no DB pools itself; it drives the control store +
/// the provider + the schema apply.
pub struct Provisioner {
    provider: Provider,
    /// Default blob isolation mode for new tenants ("prefix" or "bucket").
    blob_mode: String,
}

impl Provisioner {
    pub fn new(provider: Provider) -> Self {
        Self {
            provider,
            // Prefix-per-tenant with prefix-scoped credentials is the design
            // default (matches scale-to-zero economics, avoids bucket sprawl);
            // bucket-per-tenant is reserved for regulated tenants.
            blob_mode: "prefix".to_string(),
        }
    }

    /// The per-tenant blob scope key: the tenant prefix (or bucket name). Stable
    /// and derived from the org id, so it is idempotent across retries.
    fn blob_scope(org_id: i64) -> String {
        format!("t/{org_id}")
    }

    /// Provision (or finish provisioning) a tenant. IDEMPOTENT: safe to re-run on a
    /// half-provisioned org (a crash-recovery reconciler calls exactly this). On
    /// success the tenant is `active` with a connection string, a schema-applied DB to
    /// head, and a registered blob scope. Returns the final tenant record.
    pub async fn provision(
        &self,
        control: &ControlStore,
        org_id: i64,
    ) -> anyhow::Result<TenantRecord> {
        // 1. INTENT: durable "a provisioning attempt is in flight" (idempotent).
        control.begin_provisioning(org_id).await?;

        // 2. DATABASE: idempotent on a stable per-org name (retry adopts existing).
        let conn = self.provider.provision(org_id).await?;
        control.set_tenant_conn(org_id, &conn).await?;

        // 3. SCHEMA: apply the declarative tenant schema (idempotent; a re-run
        //    is a no-op). Pre-launch there is no migration ledger.
        crate::db::schema::apply(&conn).await?;

        // 4. BLOB scope: record the per-tenant prefix/bucket (idempotent overwrite).
        let scope = Self::blob_scope(org_id);
        control
            .set_tenant_blob(org_id, &self.blob_mode, &scope)
            .await?;

        // 5. REGISTER: flip to active LAST. Before this the resolver won't serve it.
        control
            .set_tenant_status(org_id, TenantStatus::Active)
            .await?;

        Ok(TenantRecord {
            org_id,
            status: TenantStatus::Active,
            db_conn: Some(conn),
            blob_mode: self.blob_mode.clone(),
            blob_scope: scope,
            region: None,
        })
    }

    /// Offboard a tenant: drop its database via the provider. The control-plane row
    /// and blobs are handled by the caller (GDPR erasure is its own flow); this is
    /// the data-plane teardown.
    pub async fn deprovision(&self, org_id: i64) -> anyhow::Result<()> {
        self.provider.deprovision(org_id).await
    }
}
