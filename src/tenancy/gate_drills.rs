//! Hosted production-gate drills (ignored; explicitly selected by the deploy
//! repo's `hosted-production-gates` workflow).
//!
//! Two of the five release gates in `docs/architecture/multi-tenancy.md` §8
//! live here, next to the tenancy machinery they exercise:
//!
//!   - `neon_pool_load_gate`: a bounded load run through [`TenantPools`]
//!     against the production Neon pooler (`NEON_POOLER_URL`), measuring
//!     error rate, p95 pool-acquire latency, and peak open connections.
//!   - `control_plane_interruption_drill`: an entirely LOCAL drill against a
//!     disposable Postgres (`TEST_DATABASE_URL`): warm one tenant into the
//!     resolver cache, take the control database away (rename), prove the
//!     cached tenant still resolves while an uncached tenant fails closed,
//!     bring the control database back, and measure recovery.
//!
//! Each passing drill writes its evidence fragment via [`super::gate_evidence`]
//! when `GATE_EVIDENCE_PATH` is set. Unlike the skip-if-unreachable local
//! integration tests, a selected gate with missing prerequisites FAILS.

use super::blob::Blobs;
use super::gate_evidence;
use super::integration_tests::{admin_url, create_db, drop_db, seed_org, with_db};
use super::pool::TenantPools;
use super::Tenancy;
use crate::db::ControlStore;
use sqlx::postgres::PgPoolOptions;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Org-id base for load-gate pool keys (never touches a control plane).
const LOAD_ORG_BASE: i64 = 991_000;
/// Bounds on the env-tunable load shape. The manifest validator accepts a
/// wider range; the harness stays deliberately smaller so one workflow run
/// is bounded in time and provider cost.
const TENANTS_MIN: usize = 2;
const TENANTS_MAX: usize = 256;
const REQUESTS_MIN: usize = 100;
const REQUESTS_MAX: usize = 100_000;
/// Whole-gate wall-clock bound.
const LOAD_GATE_TIMEOUT: Duration = Duration::from_secs(600);
/// The manifest bound the measured error rate must beat (1 percent).
const MAX_ERROR_RATE: f64 = 0.01;

/// Read a bounded usize knob from the env, clamped rather than trusted.
fn bounded_env(name: &str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

/// Gate 2 of §8: bounded active-tenant load against the production Neon
/// pooler. Each simulated tenant is a distinct [`TenantPools`] key over the
/// SAME pooler URL, so the run exercises exactly the application-side pool
/// path a fleet of active tenants exercises, with the per-tenant caps and
/// LRU bounds the resolver uses in production.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the production Neon pooler URL and production-validation credentials"]
async fn neon_pool_load_gate() {
    let url = std::env::var("NEON_POOLER_URL")
        .expect("NEON_POOLER_URL must be set for the explicit Neon pool-load gate");
    let tenants = bounded_env("GATE_TENANTS", 16, TENANTS_MIN, TENANTS_MAX);
    let requests = bounded_env("GATE_REQUESTS", 1_000, REQUESTS_MIN, REQUESTS_MAX);
    let concurrency = tenants.min(32);

    // Peak-open-connection sampler on its own connection: pg_stat_activity for
    // the pooled database, sampled every 250ms for the life of the run.
    let sampler = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&url)
        .await
        .expect("Neon pooler must be reachable for the pool-load gate");
    let max_open = Arc::new(AtomicI64::new(1));
    let done = Arc::new(AtomicUsize::new(0));
    let sampler_task = {
        let (sampler, max_open, done) = (sampler.clone(), max_open.clone(), done.clone());
        tokio::spawn(async move {
            while done.load(Ordering::Relaxed) == 0 {
                let open: Result<i64, _> = sqlx::query_scalar(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()",
                )
                .fetch_one(&sampler)
                .await;
                if let Ok(open) = open {
                    max_open.fetch_max(open, Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
    };

    let pools = TenantPools::new();
    let next = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    let acquire_us = Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(requests)));

    let run = async {
        let mut workers = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let (pools, url) = (pools.clone(), url.clone());
            let (next, errors, acquire_us) = (next.clone(), errors.clone(), acquire_us.clone());
            workers.push(tokio::spawn(async move {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= requests {
                        break;
                    }
                    let org = LOAD_ORG_BASE + (i % tenants) as i64;
                    let started = Instant::now();
                    // The measured section is exactly what a request pays
                    // before its first query: pool lookup/create + acquire.
                    let acquired = match pools.get(org, &url).await {
                        Ok(pool) => pool.acquire().await.map_err(anyhow::Error::from),
                        Err(e) => Err(e),
                    };
                    match acquired {
                        Ok(mut conn) => {
                            let waited = started.elapsed().as_micros() as u64;
                            let ping = sqlx::query("SELECT 1").execute(&mut *conn).await;
                            if ping.is_ok() {
                                acquire_us.lock().await.push(waited);
                            } else {
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }));
        }
        for w in workers {
            w.await.expect("load worker completes");
        }
    };
    tokio::time::timeout(LOAD_GATE_TIMEOUT, run)
        .await
        .expect("pool-load gate exceeded its wall-clock bound");
    done.store(1, Ordering::Relaxed);
    let _ = sampler_task.await;

    let mut samples = acquire_us.lock().await.clone();
    samples.sort_unstable();
    let errors = errors.load(Ordering::Relaxed);
    assert!(
        !samples.is_empty(),
        "pool-load gate completed zero successful requests"
    );
    let error_rate = errors as f64 / requests as f64;
    let p95_index = (samples.len() * 95).div_ceil(100).saturating_sub(1);
    let p95_ms = samples[p95_index] as f64 / 1_000.0;
    let max_open = max_open.load(Ordering::Relaxed).max(1);
    eprintln!(
        "neonPoolLoad: tenants={tenants} requests={requests} errors={errors} \
         errorRate={error_rate:.4} p95PoolAcquireMs={p95_ms:.1} maxOpenConnections={max_open}"
    );
    assert!(
        error_rate <= MAX_ERROR_RATE,
        "error rate {error_rate:.4} exceeds the {MAX_ERROR_RATE} gate bound"
    );
    gate_evidence::write_fragment(
        "neonPoolLoad",
        serde_json::json!({
            "activeTenants": tenants,
            "requests": requests,
            "errorRate": error_rate,
            "p95PoolAcquireMs": p95_ms,
            "maxOpenConnections": max_open,
        }),
    );
}

/// Orgs for the interruption drill (distinct from the 9900xx integration-test
/// ids so concurrent local runs never collide on tenant database names).
const DRILL_ORG_CACHED: i64 = 990_201;
const DRILL_ORG_UNCACHED: i64 = 990_202;
/// Recovery poll bound: 600 * 100ms = 60s, well inside the manifest's 300s cap.
const RECOVERY_POLLS: u32 = 600;
const RECOVERY_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Take the control database away by renaming it out from under its pool
/// (backends terminated first so the rename cannot block). New control-plane
/// reads then fail exactly as they do when a real control plane is down.
async fn rename_db(admin: &sqlx::PgPool, from: &str, to: &str) -> anyhow::Result<()> {
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1")
        .bind(from)
        .execute(admin)
        .await?;
    sqlx::query(&format!("ALTER DATABASE \"{from}\" RENAME TO \"{to}\""))
        .execute(admin)
        .await?;
    Ok(())
}

/// Gate 3 of §8: control-plane interruption, run entirely against a disposable
/// local Postgres (no live providers). Proves the documented posture: a tenant
/// whose mapping and pool are warm keeps working through a control-plane
/// outage, an uncached tenant is DENIED (fail closed, never a guess), and the
/// resolver recovers on its own once the control plane returns.
#[tokio::test]
#[ignore = "control-plane interruption drill; run with a disposable Postgres (TEST_DATABASE_URL)"]
async fn control_plane_interruption_drill() {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&admin_url())
        .await
        .expect("the interruption drill requires a reachable disposable Postgres");

    let control_db = format!("reproit_gate_ctrl_{}", std::process::id());
    let control_db_down = format!("{control_db}_down");
    let tenant_db_a = format!("reproit_tenant_{DRILL_ORG_CACHED}");
    let tenant_db_b = format!("reproit_tenant_{DRILL_ORG_UNCACHED}");

    // Clean leftovers from a crashed prior run (either rename state), then
    // create a fresh control database.
    for db in [&control_db, &control_db_down, &tenant_db_a, &tenant_db_b] {
        drop_db(&admin, db).await;
    }
    create_db(&admin, &control_db)
        .await
        .expect("create drill control db");

    // The drill body answers the measured recovery time on success.
    let result: anyhow::Result<u64> = {
        async {
            let control_url = with_db(&admin_url(), &control_db);
            let control = Arc::new(ControlStore::connect(&control_url).await?);
            let base_tenant_url = with_db(&admin_url(), "reproit");
            let tenancy = Tenancy::new(control, Blobs::from_env(), &base_tenant_url, None);

            seed_org(&control_url, DRILL_ORG_CACHED, "Drill Cached").await?;
            seed_org(&control_url, DRILL_ORG_UNCACHED, "Drill Uncached").await?;
            tenancy.provision(DRILL_ORG_CACHED).await?;
            tenancy.provision(DRILL_ORG_UNCACHED).await?;

            // Warm ONLY the cached tenant: mapping cached + pool live. The
            // uncached tenant's provision-time invalidation leaves it cold.
            tenancy
                .resolve(DRILL_ORG_CACHED)
                .await
                .map_err(|e| anyhow::anyhow!("warm resolve failed: {e}"))?;

            // OUTAGE: the control database disappears mid-flight.
            rename_db(&admin, &control_db, &control_db_down).await?;

            let cached_observed = tenancy.resolve(DRILL_ORG_CACHED).await.is_ok();
            let uncached_denied = tenancy.resolve(DRILL_ORG_UNCACHED).await.is_err();

            // RECOVERY: the control database returns; poll (bounded) until the
            // uncached tenant resolves again.
            let recovery_started = Instant::now();
            rename_db(&admin, &control_db_down, &control_db).await?;
            let mut recovered = false;
            for _ in 0..RECOVERY_POLLS {
                if tenancy.resolve(DRILL_ORG_UNCACHED).await.is_ok() {
                    recovered = true;
                    break;
                }
                tokio::time::sleep(RECOVERY_POLL_INTERVAL).await;
            }
            let recovery_ms = recovery_started.elapsed().as_millis() as u64;

            anyhow::ensure!(cached_observed, "cached tenant did not survive the outage");
            anyhow::ensure!(
                uncached_denied,
                "uncached tenant was not denied during the outage"
            );
            anyhow::ensure!(
                recovered,
                "control plane did not recover within the poll bound"
            );
            anyhow::Ok(recovery_ms)
        }
    }
    .await;

    // Teardown both rename states plus the tenant databases, pass or fail.
    for db in [&control_db, &control_db_down, &tenant_db_a, &tenant_db_b] {
        drop_db(&admin, db).await;
    }
    admin.close().await;
    let recovery_ms = result.expect("control-plane interruption drill body");

    gate_evidence::write_fragment(
        "controlPlaneInterruption",
        serde_json::json!({
            "cachedTenantObserved": true,
            "uncachedTenantDenied": true,
            "recovered": true,
            "recoveryMs": recovery_ms,
        }),
    );
}
