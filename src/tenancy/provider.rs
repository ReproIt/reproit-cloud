//! The data layer as "a Postgres connection string per tenant", behind a trait.
//!
//! The ONLY thing the app needs to talk to a tenant is a connection string (plus a
//! blob scope, see `blob.rs`). Everything else is an implementation detail of the
//! provider behind that string (`docs/architecture/multi-tenancy.md` §1). This
//! module is that contract:
//!
//!   - [`ConnectionProvider`]: "given an org id, create/return a Postgres
//!     connection string for its database; drop it on offboarding". Anything that
//!     hands out a connection string satisfies it, so Neon is a swappable provider,
//!     not a dependency.
//!
//! Three impls, selected by env/config:
//!   - [`LocalProvider`] (dev/test, the DEFAULT): creates a real, isolated database
//!     PER TENANT on a single local Postgres (`reproit_tenant_<org>`), so the whole
//!     system builds and tests with NO Neon. Schema-per-tenant is offered as a
//!     fallback knob for connection-limit-constrained setups.
//!   - [`SingleTenantProvider`] (self-hosted): returns one fixed connection string
//!     for every org. The self-hosted edition is the SaaS with tenant count = 1.
//!   - [`NeonProvider`] (SaaS): provisions a Neon database via API. STUBBED
//!     (feature-gated) where a live Neon account is required; the trait shape is
//!     real so the SaaS wiring is in place.

use std::future::Future;
use std::pin::Pin;

/// A boxed, `Send` future, the return shape of the provider's async methods.
type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Hands out (and tears down) a Postgres database per tenant. The connection
/// string it returns is the entire contract between the app and a tenant's data.
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

/// LOCAL provider: a real database per tenant on one local Postgres, derived
/// deterministically from the org id. No Neon, no external API: this is what makes
/// the whole architecture build and test offline.
///
/// It needs an ADMIN connection string (to `CREATE DATABASE`) and a base URL whose
/// database name it swaps per tenant. Both default to the dev compose Postgres.
pub struct LocalProvider {
    /// Admin URL used to run `CREATE DATABASE` / `DROP DATABASE`. Connects to a
    /// maintenance DB (e.g. `postgres`).
    admin_url: String,
    /// The connection string template; its database segment is replaced with the
    /// per-tenant database name.
    base_url: String,
}

impl LocalProvider {
    /// Build from a base tenant connection string (e.g. the dev `DATABASE_URL`).
    /// The admin URL points the same server at the `postgres` maintenance db.
    pub fn new(base_url: &str) -> Self {
        let admin_url = swap_db(base_url, "postgres");
        Self {
            admin_url: admin_url.clone(),
            base_url: base_url.to_string(),
        }
    }

    fn db_name(org_id: i64) -> String {
        format!("reproit_tenant_{org_id}")
    }

    fn conn_for(&self, org_id: i64) -> String {
        swap_db(&self.base_url, &Self::db_name(org_id))
    }
}

impl ConnectionProvider for LocalProvider {
    fn provision(&self, org_id: i64) -> BoxFut<'_, anyhow::Result<String>> {
        let admin_url = self.admin_url.clone();
        let conn = self.conn_for(org_id);
        let db = Self::db_name(org_id);
        Box::pin(async move {
            use sqlx::postgres::PgPoolOptions;
            // Connect to the maintenance DB to run CREATE DATABASE (can't run it in
            // a transaction, and the target DB doesn't exist yet).
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(std::time::Duration::from_secs(10))
                .connect(&admin_url)
                .await?;
            // Idempotent: only create if absent (CREATE DATABASE has no IF NOT
            // EXISTS, so we guard on pg_database). A concurrent racer that wins is
            // fine; the loser sees it already exists and adopts it.
            let exists: Option<i32> =
                sqlx::query_scalar("SELECT 1 FROM pg_database WHERE datname = $1")
                    .bind(&db)
                    .fetch_optional(&admin)
                    .await?;
            if exists.is_none() {
                // Database identifiers can't be bound as params; `db` is
                // server-built from the org id (digits only), so it is safe.
                if let Err(e) = sqlx::query(&format!("CREATE DATABASE \"{db}\""))
                    .execute(&admin)
                    .await
                {
                    // Tolerate a lost race (someone else just created it).
                    let already = sqlx::query_scalar::<_, i32>(
                        "SELECT 1 FROM pg_database WHERE datname = $1",
                    )
                    .bind(&db)
                    .fetch_optional(&admin)
                    .await?;
                    if already.is_none() {
                        return Err(e.into());
                    }
                }
            }
            admin.close().await;
            Ok(conn)
        })
    }

    fn deprovision(&self, org_id: i64) -> BoxFut<'_, anyhow::Result<()>> {
        let admin_url = self.admin_url.clone();
        let db = Self::db_name(org_id);
        Box::pin(async move {
            use sqlx::postgres::PgPoolOptions;
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .connect(&admin_url)
                .await?;
            // Force-drop: terminate lingering backends first so the DROP succeeds.
            let _ = sqlx::query(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1",
            )
            .bind(&db)
            .execute(&admin)
            .await;
            let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{db}\""))
                .execute(&admin)
                .await;
            admin.close().await;
            Ok(())
        })
    }

    fn derive_conn(&self, org_id: i64) -> Option<String> {
        Some(self.conn_for(org_id))
    }
}

/// SELF-HOSTED provider: one fixed connection string for every tenant. The
/// self-hosted edition is the SaaS code with the tenant count fixed at one
/// (`docs/architecture/multi-tenancy.md` §6).
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

/// SaaS provider: ONE NEON PROJECT PER ORG via the Neon API v2. Project-per-org
/// (rather than database-per-org inside one project) gives every tenant its own
/// scale-to-zero compute and hard isolation, matching the database-per-org
/// design; idle tenants cost (almost) nothing. Idempotent on the stable project
/// name `reproit-org-<id>`: a retried provisioning adopts the existing project.
/// Scaling watch items: Neon per-plan project-count limits and API rate limits
/// under signup bursts.
#[cfg(feature = "neon")]
pub struct NeonProvider {
    api_key: String,
    /// Neon organization id (org-scoped API keys require it on create/list).
    neon_org: Option<String>,
    base_url: String,
    client: reqwest::Client,
}

#[cfg(feature = "neon")]
impl NeonProvider {
    pub fn from_env() -> Option<Self> {
        Some(Self {
            api_key: std::env::var("NEON_API_KEY")
                .ok()
                .filter(|v| !v.is_empty())?,
            neon_org: std::env::var("NEON_ORG_ID").ok().filter(|v| !v.is_empty()),
            base_url: "https://console.neon.tech/api/v2".to_string(),
            client: reqwest::Client::new(),
        })
    }

    fn project_name(org_id: i64) -> String {
        format!("reproit-org-{org_id}")
    }

    fn req(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        rb.bearer_auth(&self.api_key)
            .header("Accept", "application/json")
            .header("User-Agent", "reproit-cloud")
    }

    async fn json_or_err(resp: reqwest::Response, what: &str) -> anyhow::Result<serde_json::Value> {
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("neon {what} failed ({status}): {body}");
        }
        Ok(body)
    }

    /// Find the per-org project by its stable name. `search` narrows server-side;
    /// the exact-name match happens here.
    async fn find_project(&self, name: &str) -> anyhow::Result<Option<String>> {
        // `search` matches SUBSTRINGS server-side (reproit-org-1 also matches
        // reproit-org-10, -100, ...), so follow the pagination cursor until the
        // exact name is found or the listing is exhausted: stopping at the
        // first page would report an existing project as absent once enough
        // same-prefix names accumulate, and `provision` would then create a
        // DUPLICATE Neon project instead of adopting the existing one.
        let mut cursor: Option<String> = None;
        loop {
            let mut url = format!("{}/projects?search={name}&limit=100", self.base_url);
            if let Some(org) = &self.neon_org {
                url.push_str(&format!("&org_id={org}"));
            }
            if let Some(c) = &cursor {
                url.push_str(&format!("&cursor={c}"));
            }
            let body = Self::json_or_err(
                self.req(self.client.get(url)).send().await?,
                "list projects",
            )
            .await?;
            let page = body["projects"].as_array().cloned().unwrap_or_default();
            if let Some(hit) = page
                .iter()
                .find(|p| p["name"].as_str() == Some(name))
                .and_then(|p| p["id"].as_str())
            {
                return Ok(Some(hit.to_string()));
            }
            // A short page means the listing is exhausted; otherwise follow the
            // cursor (Neon returns pagination.cursor; the last id also works).
            if page.len() < 100 {
                return Ok(None);
            }
            cursor = body["pagination"]["cursor"]
                .as_str()
                .map(|s| s.to_string())
                .or_else(|| {
                    page.last()
                        .and_then(|p| p["id"].as_str())
                        .map(|s| s.to_string())
                });
            if cursor.is_none() {
                return Ok(None);
            }
        }
    }

    /// The POOLED connection uri for an existing project: default branch ->
    /// its first database (+ owning role) -> the connection_uri endpoint.
    async fn connection_uri(&self, project_id: &str) -> anyhow::Result<String> {
        let branches = Self::json_or_err(
            self.req(
                self.client
                    .get(format!("{}/projects/{project_id}/branches", self.base_url)),
            )
            .send()
            .await?,
            "list branches",
        )
        .await?;
        let branch = branches["branches"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|b| b["default"].as_bool() == Some(true))
            .or_else(|| branches["branches"].as_array().and_then(|a| a.first()))
            .and_then(|b| b["id"].as_str())
            .ok_or_else(|| anyhow::anyhow!("neon project {project_id} has no branches"))?
            .to_string();
        let dbs = Self::json_or_err(
            self.req(self.client.get(format!(
                "{}/projects/{project_id}/branches/{branch}/databases",
                self.base_url
            )))
            .send()
            .await?,
            "list databases",
        )
        .await?;
        let db = dbs["databases"]
            .as_array()
            .and_then(|a| a.first())
            .ok_or_else(|| anyhow::anyhow!("neon project {project_id} has no databases"))?;
        let (db_name, role) = (
            db["name"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("neon database has no name"))?,
            db["owner_name"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("neon database has no owner_name"))?,
        );
        let uri = Self::json_or_err(
            self.req(self.client.get(format!(
                "{}/projects/{project_id}/connection_uri?database_name={db_name}&role_name={role}&pooled=true",
                self.base_url
            )))
            .send()
            .await?,
            "connection_uri",
        )
        .await?;
        uri["uri"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("neon connection_uri response missing uri"))
    }
}

#[cfg(feature = "neon")]
impl ConnectionProvider for NeonProvider {
    fn provision(&self, org_id: i64) -> BoxFut<'_, anyhow::Result<String>> {
        Box::pin(async move {
            let name = Self::project_name(org_id);
            // Idempotent adopt: an existing project (a retried provisioning, or a
            // race we lost) is reused, never duplicated.
            if let Some(pid) = self.find_project(&name).await? {
                return self.connection_uri(&pid).await;
            }
            let mut project = serde_json::json!({ "name": name });
            if let Some(org) = &self.neon_org {
                project["org_id"] = serde_json::Value::String(org.clone());
            }
            let created = Self::json_or_err(
                self.req(self.client.post(format!("{}/projects", self.base_url)))
                    .json(&serde_json::json!({ "project": project }))
                    .send()
                    .await?,
                "create project",
            )
            .await?;
            // The create response carries ready-made connection uris; prefer the
            // pooled endpoint resolved the same way as the adopt path.
            if let Some(pid) = created["project"]["id"].as_str() {
                if let Ok(uri) = self.connection_uri(pid).await {
                    return Ok(uri);
                }
            }
            created["connection_uris"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|c| c["connection_uri"].as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow::anyhow!("neon create project returned no connection uri"))
        })
    }

    fn deprovision(&self, org_id: i64) -> BoxFut<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let name = Self::project_name(org_id);
            // Idempotent: a missing project is a no-op success.
            let Some(pid) = self.find_project(&name).await? else {
                return Ok(());
            };
            let resp = self
                .req(
                    self.client
                        .delete(format!("{}/projects/{pid}", self.base_url)),
                )
                .send()
                .await?;
            let status = resp.status();
            if !status.is_success() && status != reqwest::StatusCode::NOT_FOUND {
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("neon delete project {pid} failed ({status}): {body}");
            }
            Ok(())
        })
    }

    fn derive_conn(&self, _org_id: i64) -> Option<String> {
        None // Neon's connection string is API-assigned, not derivable.
    }
}

/// Replace the database segment of a Postgres URL. Handles the common
/// `postgres://user:pass@host:port/dbname[?params]` shape. If no `/db` segment is
/// found the url is returned unchanged (best-effort; dev URLs always have one).
fn swap_db(url: &str, db: &str) -> String {
    // Split off any query string, swap the last path segment, reattach.
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (url, None),
    };
    let swapped = match base.rfind('/') {
        // Ensure the '/' we found is after the authority (not the `//` scheme sep).
        Some(idx) if idx > base.find("//").map(|i| i + 1).unwrap_or(0) => {
            format!("{}/{}", &base[..idx], db)
        }
        _ => format!("{base}/{db}"),
    };
    match query {
        Some(q) => format!("{swapped}?{q}"),
        None => swapped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_db_replaces_the_database_segment() {
        assert_eq!(
            swap_db("postgres://u:p@localhost:5433/reproit", "reproit_tenant_7"),
            "postgres://u:p@localhost:5433/reproit_tenant_7"
        );
        // Query params are preserved.
        assert_eq!(
            swap_db(
                "postgres://u:p@host:5432/base?sslmode=require",
                "reproit_tenant_9"
            ),
            "postgres://u:p@host:5432/reproit_tenant_9?sslmode=require"
        );
    }

    #[test]
    fn local_provider_derives_a_distinct_db_per_tenant() {
        let p = LocalProvider::new("postgres://reproit:reproit@localhost:5433/reproit");
        let a = p.derive_conn(1).unwrap();
        let b = p.derive_conn(2).unwrap();
        assert!(a.ends_with("/reproit_tenant_1"));
        assert!(b.ends_with("/reproit_tenant_2"));
        assert_ne!(a, b);
    }

    #[test]
    fn single_tenant_provider_returns_the_same_conn_for_everyone() {
        let p = SingleTenantProvider::new("postgres://host/db");
        assert_eq!(p.derive_conn(1), p.derive_conn(999));
    }
}
