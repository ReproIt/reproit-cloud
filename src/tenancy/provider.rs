//! Fixed-database provider used by a self-hosted installation.

use std::future::Future;
use std::pin::Pin;

/// A boxed, `Send` future, the return shape of the provider's async methods.
type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Hands out the installation's configured Postgres connection.
///
/// The async methods return a BOXED `Send` future rather than `async fn` in trait.
/// This is deliberate: the provider is awaited deep inside the axum handler path
/// (signup -> provision), whose futures must be `Send`, and a bare `async fn` in
/// trait leaks a higher-ranked-lifetime `!Send` bound through the concrete
/// `Provider` enum ("Send is not general enough"). Boxing pins the future as
/// `Send` and sidesteps that, at the cost of one allocation on the cold
/// provisioning path (never the hot request path).
pub trait ConnectionProvider: Send + Sync {
    /// Provision (or adopt) the database for `org_id` and return its connection
    /// string. MUST be idempotent on a stable per-org name: a retried provisioning
    /// adopts the existing database rather than creating a second (the crash-safe
    /// signup flow depends on this).
    fn provision(&self, org_id: i64) -> BoxFut<'_, anyhow::Result<String>>;

    /// Tear down a tenant's database (offboarding / GDPR erasure). Idempotent: a
    /// missing database is a no-op success.
    fn deprovision(&self, org_id: i64) -> BoxFut<'_, anyhow::Result<()>>;

    /// The connection string for an already-provisioned tenant, recomputed from
    /// `org_id` WITHOUT an external call when the provider can (e.g. local derives
    /// it deterministically). Used as a fallback when the control-plane record is
    /// missing its `db_conn`. Returns None if the provider cannot derive it.
    fn derive_conn(&self, org_id: i64) -> Option<String>;
}

/// One fixed connection string for the installation.
pub struct SingleTenantProvider {
    conn: String,
}

impl SingleTenantProvider {
    pub fn new(conn: &str) -> Self {
        Self {
            conn: conn.to_string(),
        }
    }
}

impl ConnectionProvider for SingleTenantProvider {
    fn provision(&self, _org_id: i64) -> BoxFut<'_, anyhow::Result<String>> {
        let conn = self.conn.clone();
        Box::pin(async move { Ok(conn) })
    }
    fn deprovision(&self, _org_id: i64) -> BoxFut<'_, anyhow::Result<()>> {
        // never drop the customer's single database.
        Box::pin(async move { Ok(()) })
    }
    fn derive_conn(&self, _org_id: i64) -> Option<String> {
        Some(self.conn.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_tenant_provider_returns_the_same_conn_for_everyone() {
        let p = SingleTenantProvider::new("postgres://host/db");
        assert_eq!(p.derive_conn(1), p.derive_conn(999));
    }
}
