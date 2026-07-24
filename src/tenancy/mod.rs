//! Multi-tenancy: the database-per-org machinery the rest of the app routes
//! through (`docs/architecture/multi-tenancy.md`).
//!
//! The pieces:
//!   - [`blob`]     per-tenant blob isolation (scope + backend trait, local/R2).
//!   - [`provider`] "a Postgres connection string per tenant" behind a trait
//!     (Local schema/db-per-tenant for dev, SingleTenant for self-hosted, Neon
//!     provider for SaaS).
//!   - [`pool`]     the bounded, idle-evicting per-tenant pool LRU (the scaling
//!     answer to "thousands of tenants, bounded backends").
//!   - [`provisioner`] the crash-safe signup flow (intent -> db -> schema ->
//!     blob -> active).
//!   - [`resolver`] identity -> tenant id -> tenant-bound store + blobs.
//!
//! [`Tenancy`] bundles a configured resolver + provisioner behind one type the
//! `App` holds, so handlers say `app.tenancy.resolve(org_id)` and get a `Tenant`.

pub mod blob;
pub mod pool;
pub mod provider;
pub mod provisioner;
pub mod resolver;

#[cfg(test)]
mod integration_tests;

use crate::db::{ControlStore, TenantRecord};
use provider::{ConnectionProvider, LocalProvider, SingleTenantProvider};
use std::sync::Arc;

#[cfg(feature = "neon")]
use provider::NeonProvider;

pub use resolver::{ResolveError, Tenant};

/// A concrete connection provider, chosen at startup. An enum (rather than a `dyn`
/// trait object) because `ConnectionProvider` uses `async fn` in trait, which is
/// not dyn-compatible; the enum keeps the resolver/provisioner non-generic over a
/// boxed trait while still selecting the impl at runtime from config.
pub enum Provider {
    /// Dev/test default: a real database per tenant on one local Postgres.
    Local(LocalProvider),
    /// Self-hosted: one fixed connection string for the single tenant.
    Single(SingleTenantProvider),
    /// SaaS: Neon-provisioned databases backed by the live provider API.
    #[cfg(feature = "neon")]
    Neon(NeonProvider),
}

impl ConnectionProvider for Provider {
    fn provision(
        &self,
        org_id: i64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<String>> + Send + '_>>
    {
        match self {
            Provider::Local(p) => p.provision(org_id),
            Provider::Single(p) => p.provision(org_id),
            #[cfg(feature = "neon")]
            Provider::Neon(p) => p.provision(org_id),
        }
    }
    fn deprovision(
        &self,
        org_id: i64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        match self {
            Provider::Local(p) => p.deprovision(org_id),
            Provider::Single(p) => p.deprovision(org_id),
            #[cfg(feature = "neon")]
            Provider::Neon(p) => p.deprovision(org_id),
        }
    }
    fn derive_conn(&self, org_id: i64) -> Option<String> {
        match self {
            Provider::Local(p) => p.derive_conn(org_id),
            Provider::Single(p) => p.derive_conn(org_id),
            #[cfg(feature = "neon")]
            Provider::Neon(p) => p.derive_conn(org_id),
        }
    }
}

/// The configured tenancy layer the `App` holds: a resolver (org id -> tenant
/// handle) and a provisioner (signup flow). Both wrap the same `Provider`, so one
/// config choice flows through routing AND provisioning.
pub struct Tenancy {
    resolver: resolver::Resolver,
    provisioner: provisioner::Provisioner,
    control: Arc<ControlStore>,
}

impl Tenancy {
    /// Build the tenancy layer from config. `single_tenant_org` is Some in the
    /// self-hosted edition (every request resolves to that one org); None for SaaS.
    pub fn new(
        control: Arc<ControlStore>,
        blobs: blob::Blobs,
        base_tenant_url: &str,
        self_hosted_conn: Option<&str>,
    ) -> Self {
        // Pick the provider. Self-hosted (a fixed conn given) -> single-tenant.
        // Hosted: REPROIT_TENANT_PROVIDER selects `neon` (project-per-org via the
        // Neon API; prod) or `local` (CREATE DATABASE per org on one Postgres;
        // dev/CI, the default). A requested-but-unbuildable provider is a hard
        // startup panic: silently falling back to local in prod would strand
        // tenants on the wrong Postgres.
        let make_provider = || -> Provider {
            match self_hosted_conn {
                Some(conn) => Provider::Single(SingleTenantProvider::new(conn)),
                None => match std::env::var("REPROIT_TENANT_PROVIDER").as_deref() {
                    Ok("neon") => {
                        #[cfg(feature = "neon")]
                        {
                            Provider::Neon(
                                NeonProvider::from_env()
                                    .expect("REPROIT_TENANT_PROVIDER=neon requires NEON_API_KEY"),
                            )
                        }
                        #[cfg(not(feature = "neon"))]
                        panic!(
                            "REPROIT_TENANT_PROVIDER=neon but this binary was built without --features neon"
                        )
                    }
                    Ok("local") | Err(_) => Provider::Local(LocalProvider::new(base_tenant_url)),
                    Ok(other) => panic!("unknown REPROIT_TENANT_PROVIDER {other:?} (neon|local)"),
                },
            }
        };
        let single_tenant_org = self_hosted_conn.map(|_| SELF_HOSTED_ORG_ID);
        let pools = pool::TenantPools::new();
        let resolver = resolver::Resolver::new(
            control.clone(),
            make_provider(),
            pools,
            blobs,
            single_tenant_org,
        );
        let provisioner = provisioner::Provisioner::new(make_provider());
        Self {
            resolver,
            provisioner,
            control,
        }
    }

    /// Resolve an org id to a tenant-bound handle (store + blobs).
    pub async fn resolve(&self, org_id: i64) -> Result<Tenant, ResolveError> {
        self.resolver.resolve(org_id).await
    }

    /// Provision (or finish provisioning) a tenant on signup. Idempotent + crash-
    /// recoverable. Invalidates any stale cached mapping so the new tenant resolves
    /// immediately afterward.
    pub async fn provision(&self, org_id: i64) -> anyhow::Result<TenantRecord> {
        let rec = self.provisioner.provision(&self.control, org_id).await?;
        self.resolver.invalidate(org_id).await;
        Ok(rec)
    }

    /// Offboard a tenant: tear down its database at the provider (idempotent)
    /// and forget any live pool/mapping. Blob + control-plane cleanup is the
    /// caller's job (`main.rs` offboard subcommand), so this stays a pure
    /// data-plane teardown.
    pub async fn deprovision(&self, org_id: i64) -> anyhow::Result<()> {
        self.provisioner.deprovision(org_id).await?;
        self.resolver.invalidate(org_id).await;
        Ok(())
    }

    /// Delete an organization's complete data plane while leaving the control
    /// row for the caller to remove last. Idempotent enough for a retried HTTP
    /// deletion: the registry retains the blob scope until control cleanup.
    // Consumed by the hosted org-deletion route; self-host offboards via ops.
    #[allow(dead_code)]
    pub async fn offboard_data(&self, org_id: i64) -> anyhow::Result<()> {
        if let Some(record) = self.control.tenant(org_id).await? {
            self.resolver.delete_blob_scope(&record.blob_scope).await?;
        }
        self.provisioner.deprovision(org_id).await?;
        self.resolver.invalidate(org_id).await;
        Ok(())
    }

    /// Crash-recovery reconciler for tenants stuck mid-provisioning. Run on startup.
    pub async fn reconcile(&self) -> anyhow::Result<()> {
        self.provisioner.reconcile(&self.control).await
    }

    /// Sweep idle tenant pools (called on a timer). Returns the number evicted.
    pub async fn sweep_idle_pools(&self) -> usize {
        self.resolver.pools().sweep_idle().await
    }

    /// Number of live tenant pools (metrics).
    pub async fn live_pools(&self) -> usize {
        self.resolver.pools().live().await
    }
}

/// The org id the self-hosted single-tenant edition pins every request to. The
/// one tenant is org #1; provisioning targets it once at install.
pub const SELF_HOSTED_ORG_ID: i64 = 1;
