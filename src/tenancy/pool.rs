//! Bounded connection pooling for the installation database.
//!
//! ## The problem
//! A 20-connection pool PER tenant is impossible at thousands of tenants: it would
//! exhaust Postgres backend limits. But most tenants are idle at any instant.
//!
//! ## The design (implemented here)
//! Keep a bounded LRU of LIVE pools keyed by tenant. Each tenant pool is capped
//! LOW (a few connections), pools are created lazily on first use, and pools idle
//! past a TTL (or evicted when the LRU is full) are closed, so total live
//! connections track active installation work rather than accumulating forever.
//!
//! Operators may also place a transaction-mode pooler in front of Postgres. This
//! module remains the application-side bound and idle-eviction layer.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Per-tenant pool cap. Low on purpose: thousands of tenants * a low cap, bounded
/// by the LRU below, is what keeps total connections sane.
const PER_TENANT_MAX_CONNS: u32 = 4;

/// How many tenant pools we keep live at once. The LRU evicts the
/// least-recently-used pool past this. Founder-tunable via `REPROIT_TENANT_POOL_CAP`.
const DEFAULT_LRU_CAP: usize = 256;

/// Evict a pool not touched within this. Idle tenants release their connections
/// so the backend count tracks active tenants. Tunable via `REPROIT_TENANT_POOL_IDLE_SECS`.
const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(300);

struct Entry {
    pool: Arc<PgPool>,
    last_used: Instant,
}

/// A bounded, idle-evicting cache of per-tenant Postgres pools. Cheap to clone
/// (shared inner). Created once at startup; `get(org_id, conn)` is called per
/// request by the resolver.
#[derive(Clone)]
pub struct TenantPools {
    inner: Arc<Mutex<HashMap<i64, Entry>>>,
    cap: usize,
    idle_ttl: Duration,
}

impl TenantPools {
    pub fn new() -> Self {
        let cap = std::env::var("REPROIT_TENANT_POOL_CAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_LRU_CAP)
            .max(1);
        let idle_ttl = std::env::var("REPROIT_TENANT_POOL_IDLE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_IDLE_TTL);
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            cap,
            idle_ttl,
        }
    }

    /// Get (creating if needed) the pool for a tenant's connection string. Bumps
    /// the tenant's recency, lazily creates a bounded pool on a miss, and evicts
    /// the LRU pool if we are over the cap. Returns a cheap `Arc<PgPool>` clone.
    pub async fn get(&self, org_id: i64, conn: &str) -> anyhow::Result<Arc<PgPool>> {
        {
            // Fast path: an existing live pool. Bump recency and return.
            let mut map = self.inner.lock().await;
            if let Some(e) = map.get_mut(&org_id) {
                e.last_used = Instant::now();
                return Ok(e.pool.clone());
            }
        }
        // Miss: build the pool OUTSIDE the lock (connecting can block), then insert.
        let pool = Arc::new(
            PgPoolOptions::new()
                .max_connections(PER_TENANT_MAX_CONNS)
                .acquire_timeout(Duration::from_secs(10))
                .idle_timeout(Duration::from_secs(60))
                .max_lifetime(Duration::from_secs(900))
                .connect(conn)
                .await?,
        );
        let mut map = self.inner.lock().await;
        // A concurrent racer may have inserted while we connected: adopt theirs and
        // drop ours (the extra pool closes when its Arc drops).
        if let Some(e) = map.get_mut(&org_id) {
            e.last_used = Instant::now();
            return Ok(e.pool.clone());
        }
        map.insert(
            org_id,
            Entry {
                pool: pool.clone(),
                last_used: Instant::now(),
            },
        );
        self.evict_locked(&mut map);
        Ok(pool)
    }

    /// Drop a tenant's pool now (e.g. on suspension / connection-string rotation),
    /// so the next request rebuilds against the fresh string.
    pub async fn invalidate(&self, org_id: i64) {
        self.inner.lock().await.remove(&org_id);
    }

    /// Sweep idle pools: close any not touched within the idle TTL. Called on a
    /// timer from `main`. Returns the number evicted.
    pub async fn sweep_idle(&self) -> usize {
        let now = Instant::now();
        let mut map = self.inner.lock().await;
        let stale: Vec<i64> = map
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_used) > self.idle_ttl)
            .map(|(k, _)| *k)
            .collect();
        for k in &stale {
            map.remove(k);
        }
        stale.len()
    }

    /// Number of live tenant pools (for metrics / tests).
    pub async fn live(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Enforce the LRU cap while holding the lock: evict least-recently-used pools
    /// until we are at or under `cap`. Dropping an `Entry` drops its `Arc<PgPool>`;
    /// the pool closes once no in-flight request still holds a clone.
    fn evict_locked(&self, map: &mut HashMap<i64, Entry>) {
        while map.len() > self.cap {
            let Some(victim) = map.iter().min_by_key(|(_, e)| e.last_used).map(|(k, _)| *k) else {
                break;
            };
            map.remove(&victim);
        }
    }
}

impl Default for TenantPools {
    fn default() -> Self {
        Self::new()
    }
}
