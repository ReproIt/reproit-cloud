//! The RESOLVER: identity -> tenant id -> a tenant-bound handle carrying its
//! Postgres connection + blob scope (`docs/architecture/multi-tenancy.md` §2).
//!
//! This is where `require_app_access` STOPS being the cross-tenant boundary. After
//! resolution a handler holds a [`Tenant`] bound to exactly one database, so a
//! cross-tenant read is physically impossible, not merely guarded. The middleware
//! (`require_api_key`) resolves the org id from the credential; this resolver maps
//! that org id to a tenant-bound store + blobs:
//!
//!   1. org id -> control-plane `tenants` record (cached; changes only on
//!      provisioning).
//!   2. record.status must be `active` and it must carry a connection string.
//!   3. acquire the tenant's pool from the bounded per-tenant LRU (`TenantPools`).
//!   4. derive the tenant's blob scope from the record.
//!
//! A `TenantResolution` carries the small control-plane mapping cached in-process;
//! a cache miss falls back to a control-plane read. (The cache is deliberately
//! simple, a `Mutex<HashMap>`; it is read on every request and changes rarely.)

use super::blob::{Blobs, TenantBlobs};
use super::pool::TenantPools;
use super::provider::ConnectionProvider;
use super::Provider;
use crate::db::{ControlStore, TenantRecord, TenantStatus, TenantStore};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// How long a resolved tenant mapping stays cached before it is re-read from the
/// control plane. The cache is also INVALIDATED eagerly on provisioning/rotation
/// (see [`Resolver::invalidate`]); the TTL is a backstop so a missed invalidation
/// (or a status flip the resolver didn't drive) self-heals within this window, and
/// so an entry for a now-dormant org eventually expires instead of living forever.
const MAPPING_TTL: Duration = Duration::from_secs(120);

/// Upper bound on cached mappings, so the map can't grow unbounded (one entry per
/// ever-seen org). On insert past the cap we evict expired entries first, and if
/// still full drop the oldest entry, keeping the cache bounded without a full clear.
const MAPPING_CACHE_MAX: usize = 8192;

/// A fully-resolved tenant: the data store + blob handle a handler operates on,
/// both bound to one org's database / blob scope.
#[derive(Clone)]
pub struct Tenant {
    /// The org this handle is bound to (for logging/metrics; the data boundary is
    /// the `store`/`blobs` themselves, not this id).
    #[allow(dead_code)]
    pub org_id: i64,
    pub store: TenantStore,
    pub blobs: TenantBlobs,
}

/// Why a tenant could not be resolved (mapped to an HTTP status by the caller).
#[derive(Debug)]
pub enum ResolveError {
    /// No tenant row for this org (signup never completed) -> treat as 404/not ready.
    NotProvisioned,
    /// Tenant exists but isn't active (provisioning/suspended).
    NotActive(TenantStatus),
    /// An infrastructure error reaching the control plane or the tenant DB.
    Internal(anyhow::Error),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::NotProvisioned => write!(f, "tenant not provisioned"),
            ResolveError::NotActive(s) => write!(f, "tenant not active ({})", s.as_str()),
            ResolveError::Internal(e) => write!(f, "tenant resolve error: {e}"),
        }
    }
}

/// Resolves org ids to tenant-bound handles. Holds the control store, the
/// connection provider (for a derive-fallback when a record lacks its conn), the
/// bounded per-tenant pool cache, the blob store, and a small mapping cache.
///
/// `P` is the connection provider, so the SAME resolver code runs the SaaS (Local
/// or Neon provider) and self-hosted (SingleTenant provider) editions; only the
/// provider differs (the whole point of database-per-org).
pub struct Resolver {
    control: Arc<ControlStore>,
    provider: Provider,
    pools: TenantPools,
    blobs: Blobs,
    /// org id -> (conn, blob_mode, blob_scope), cached in-process. Invalidated on
    /// provisioning/rotation AND expired by a TTL (so a missed invalidation or a
    /// dormant org self-heals; see [`MAPPING_TTL`]). Bounded by [`MAPPING_CACHE_MAX`]
    /// so it can't grow without limit. Avoids a control-plane read on every request.
    cache: Arc<Mutex<HashMap<i64, CachedMapping>>>,
    /// Self-hosted single-tenant mode: every request resolves to this one org id,
    /// no control-plane lookup. None for the multi-tenant SaaS.
    single_tenant: Option<i64>,
}

#[derive(Clone)]
struct CachedMapping {
    conn: String,
    blob_mode: String,
    blob_scope: String,
    /// When this entry was populated; an entry older than [`MAPPING_TTL`] is treated
    /// as a miss and re-read from the control plane.
    inserted_at: Instant,
}

impl Resolver {
    // Consumed by the hosted org-deletion route; self-host offboards via ops.
    #[allow(dead_code)]
    pub(crate) async fn delete_blob_scope(&self, scope: &str) -> anyhow::Result<u64> {
        self.blobs.delete_scope(scope).await
    }

    pub fn new(
        control: Arc<ControlStore>,
        provider: Provider,
        pools: TenantPools,
        blobs: Blobs,
        single_tenant: Option<i64>,
    ) -> Self {
        Self {
            control,
            provider,
            pools,
            blobs,
            cache: Arc::new(Mutex::new(HashMap::new())),
            single_tenant,
        }
    }

    /// Resolve an org id to a tenant-bound [`Tenant`]. The hot path: cache hit ->
    /// pool acquire -> done. A miss reads the control plane, validates the tenant is
    /// active, and populates the cache. In single-tenant mode the control-plane
    /// lookup is skipped entirely (the one fixed conn + scope is used).
    pub async fn resolve(&self, org_id: i64) -> Result<Tenant, ResolveError> {
        // Self-hosted: one tenant, one fixed mapping, no control-plane read.
        if let Some(fixed) = self.single_tenant {
            let conn = self
                .provider
                .derive_conn(fixed)
                .ok_or(ResolveError::NotProvisioned)?;
            let pool = self
                .pools
                .get(fixed, &conn)
                .await
                .map_err(ResolveError::Internal)?;
            return Ok(Tenant {
                org_id: fixed,
                store: TenantStore::new(pool),
                // One scope for the one tenant; the prefix machinery degenerates.
                blobs: self.blobs.for_tenant("prefix", ""),
            });
        }

        let mapping = self.mapping_for(org_id).await?;
        let pool = self
            .pools
            .get(org_id, &mapping.conn)
            .await
            .map_err(ResolveError::Internal)?;
        Ok(Tenant {
            org_id,
            store: TenantStore::new(pool),
            blobs: self
                .blobs
                .for_tenant(&mapping.blob_mode, &mapping.blob_scope),
        })
    }

    /// The cached (or freshly read) connection mapping for an org. A control-plane
    /// read validates the tenant is active and carries a conn; a record missing its
    /// conn falls back to the provider's deterministic derivation (local dev).
    async fn mapping_for(&self, org_id: i64) -> Result<CachedMapping, ResolveError> {
        // Cache hit only if the entry is still within its TTL; an expired entry is a
        // miss so it is re-read (and refreshed) from the control plane.
        if let Some(m) = self.cache.lock().await.get(&org_id).cloned() {
            if m.inserted_at.elapsed() < MAPPING_TTL {
                return Ok(m);
            }
        }
        let record = self
            .control
            .tenant(org_id)
            .await
            .map_err(ResolveError::Internal)?
            .ok_or(ResolveError::NotProvisioned)?;
        if record.status != TenantStatus::Active {
            return Err(ResolveError::NotActive(record.status));
        }
        let conn = self.conn_of(&record)?;
        let mapping = CachedMapping {
            conn,
            blob_mode: record.blob_mode.clone(),
            blob_scope: record.blob_scope.clone(),
            inserted_at: Instant::now(),
        };
        {
            let mut cache = self.cache.lock().await;
            // Bound the map: when at capacity (and inserting a NEW org), first drop
            // expired entries; if still full, evict the single oldest entry. Keeps
            // the cache size bounded without a disruptive full clear.
            if cache.len() >= MAPPING_CACHE_MAX && !cache.contains_key(&org_id) {
                cache.retain(|_, v| v.inserted_at.elapsed() < MAPPING_TTL);
                if cache.len() >= MAPPING_CACHE_MAX {
                    if let Some(oldest) = cache
                        .iter()
                        .min_by_key(|(_, v)| v.inserted_at)
                        .map(|(k, _)| *k)
                    {
                        cache.remove(&oldest);
                    }
                }
            }
            cache.insert(org_id, mapping.clone());
        }
        Ok(mapping)
    }

    /// The connection string for a tenant record: the stored one, or the provider's
    /// deterministic derivation as a fallback (covers a record whose `db_conn` was
    /// not persisted, which the local provider can always reconstruct).
    fn conn_of(&self, record: &TenantRecord) -> Result<String, ResolveError> {
        if let Some(c) = &record.db_conn {
            return Ok(c.clone());
        }
        self.provider
            .derive_conn(record.org_id)
            .ok_or(ResolveError::NotProvisioned)
    }

    /// Drop a tenant's cached mapping + live pool (after provisioning a NEW tenant,
    /// or rotating its connection string), so the next request rebuilds it fresh.
    pub async fn invalidate(&self, org_id: i64) {
        self.cache.lock().await.remove(&org_id);
        self.pools.invalidate(org_id).await;
    }

    /// The bounded pool cache (for the idle-eviction sweep in `main`).
    pub fn pools(&self) -> &TenantPools {
        &self.pools
    }
}
