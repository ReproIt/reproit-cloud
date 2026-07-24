//! Single-install tenancy boundary: every request resolves to the operator's
//! one Postgres database and artifact scope.
//!
//! The pieces:
//!   - [`blob`]     per-tenant blob isolation (scope + backend trait, local/R2).
//!   - [`provider`] the fixed Postgres connection provider.
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
use provider::{ConnectionProvider, SingleTenantProvider};
use std::sync::Arc;

pub use resolver::{ResolveError, Tenant};

/// A concrete connection provider, chosen at startup. An enum (rather than a `dyn`
/// trait object) because `ConnectionProvider` uses `async fn` in trait, which is
/// not dyn-compatible; the enum keeps the resolver/provisioner non-generic over a
/// boxed trait while still selecting the impl at runtime from config.
pub enum Provider {
    /// One fixed connection string for this installation.
    Single(SingleTenantProvider),
}

impl ConnectionProvider for Provider {
    fn provision(
        &self,
        org_id: i64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<String>> + Send + '_>>
    {
        match self {
            Provider::Single(p) => p.provision(org_id),
        }
    }
    fn deprovision(
        &self,
        org_id: i64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        match self {
            Provider::Single(p) => p.deprovision(org_id),
        }
    }
    fn derive_conn(&self, org_id: i64) -> Option<String> {
        match self {
            Provider::Single(p) => p.derive_conn(org_id),
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
    /// Build the tenancy layer for the installation's fixed database.
    pub fn new(control: Arc<ControlStore>, blobs: blob::Blobs, conn: &str) -> Self {
        let make_provider = || Provider::Single(SingleTenantProvider::new(conn));
        let pools = pool::TenantPools::new();
        let resolver = resolver::Resolver::new(
            control.clone(),
            make_provider(),
            pools,
            blobs,
            Some(SELF_HOSTED_ORG_ID),
        );
        let provisioner = provisioner::Provisioner::new(make_provider());
        Self {
            resolver,
            provisioner,
            control,
        }
    }

    /// Crash-recovery reconciler for tenants stuck mid-provisioning. Run on startup.
    pub async fn reconcile(&self) -> anyhow::Result<()> {
        self.provisioner.reconcile(&self.control).await
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
