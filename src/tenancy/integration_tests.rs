//! LOCAL integration tests for the tenancy layer against a REAL Postgres.
//!
//! These exercise the database-per-org machinery end to end (`LocalProvider`
//! creating a real `reproit_tenant_<org>` database per org, the schema apply
//! bringing each to head, the resolver handing back a tenant-bound store), which
//! the unit tests cannot reach because the isolation guarantee IS the database.
//!
//! GATING: plain `cargo test` with no database must still pass. Each test reads an
//! admin URL from `TEST_DATABASE_URL` (default the dev compose Postgres on :5433)
//! and, if Postgres is unreachable, SKIPS with an `eprintln!` and returns `Ok`
//! rather than failing. So CI without a database is green; a developer (or CI) with
//! the dev Postgres up gets full coverage.
//!
//! SAFETY: every test uses UNIQUE throwaway database names and HIGH org ids
//! (990001+) so it never clobbers real dev data, and DROPS every database it
//! creates in teardown (control DB + each `reproit_tenant_<org>`), even on the
//! failure paths where feasible.

use super::blob::Blobs;
use super::Tenancy;
use crate::db::{ControlStore, TenantStatus};
use crate::ingest::{buckets, ErrorRec};
use sqlx::postgres::PgPoolOptions;
use sqlx::Connection;
use std::sync::Arc;
use std::time::Duration;

/// The admin (maintenance-DB) URL to create/drop throwaway databases against.
/// (`pub(super)`: the gate drills reuse these throwaway-database helpers.)
pub(super) fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://reproit:reproit@localhost:5433/postgres".to_string())
}

/// Swap the database segment of a Postgres URL (mirror of the provider's helper,
/// kept local to the test so it depends on nothing private).
pub(super) fn with_db(url: &str, db: &str) -> String {
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (url, None),
    };
    let swapped = match base.rfind('/') {
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

/// Try to connect to the admin DB. Returns `None` (and logs a skip) when Postgres
/// is unreachable, so a no-database `cargo test` run passes.
async fn admin_pool_or_skip(test: &str) -> Option<sqlx::PgPool> {
    let url = admin_url();
    match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&url)
        .await
    {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!(
                "SKIP {test}: Postgres unreachable at {url} ({e}); set TEST_DATABASE_URL or start the dev :5433 Postgres to run this test"
            );
            None
        }
    }
}

/// Run `CREATE DATABASE "<name>"` (identifiers can't be bound; names here are
/// test-built from digits/underscores, so this is safe).
pub(super) async fn create_db(admin: &sqlx::PgPool, name: &str) -> anyhow::Result<()> {
    let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(name)
        .fetch_optional(admin)
        .await?;
    if exists.is_none() {
        sqlx::query(&format!("CREATE DATABASE \"{name}\""))
            .execute(admin)
            .await?;
    }
    Ok(())
}

/// Force-drop a database (terminate lingering backends first). Best-effort: errors
/// are swallowed so teardown never masks the test's own assertion failure.
pub(super) async fn drop_db(admin: &sqlx::PgPool, name: &str) {
    let _ =
        sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1")
            .bind(name)
            .execute(admin)
            .await;
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{name}\""))
        .execute(admin)
        .await;
}

/// A minimal error record to write through a tenant store.
fn err_rec(sig: &str, message: &str) -> ErrorRec {
    ErrorRec {
        sig: sig.to_string(),
        message: message.to_string(),
        path: vec![],
        context: serde_json::Map::new(),
    }
}

/// Insert an `orgs` row with an EXPLICIT id (the FK target for `tenants` /
/// `api_keys`). High ids (990000+) so we never collide with real BIGSERIAL orgs.
pub(super) async fn seed_org(control_url: &str, org_id: i64, name: &str) -> anyhow::Result<()> {
    let mut c = sqlx::PgConnection::connect(control_url).await?;
    sqlx::query("INSERT INTO orgs (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
        .bind(org_id)
        .bind(name)
        .execute(&mut c)
        .await?;
    c.close().await?;
    Ok(())
}

/// Insert a control-plane user (the `created_by` FK target for `api_keys`).
/// Returns the new user id.
async fn seed_user(control_url: &str, email: &str) -> anyhow::Result<i64> {
    let mut c = sqlx::PgConnection::connect(control_url).await?;
    let id: i64 =
        sqlx::query_scalar("INSERT INTO users (email, pass_hash) VALUES ($1, 'x') RETURNING id")
            .bind(email)
            .fetch_one(&mut c)
            .await?;
    c.close().await?;
    Ok(id)
}

/// 1. TENANT ISOLATION (security-critical). Provision two orgs through the tenancy
///    layer (each gets its own real `reproit_tenant_<org>` database), write a
///    DISTINCT row into each tenant store, then assert each store reads back ONLY
///    its own row and NEVER the other tenant's. The boundary is the database
///    itself, so a leak here would be a physical cross-database read.
#[tokio::test]
async fn tenant_isolation_two_orgs_never_see_each_other() {
    let Some(admin) = admin_pool_or_skip("tenant_isolation_two_orgs_never_see_each_other").await
    else {
        return;
    };

    // Unique throwaway control DB; high org ids -> reproit_tenant_990001 / _990002.
    let control_db = format!("reproit_it_control_iso_{}", std::process::id());
    let (org_a, org_b) = (990001i64, 990002i64);
    let tenant_db_a = format!("reproit_tenant_{org_a}");
    let tenant_db_b = format!("reproit_tenant_{org_b}");

    // Clean any leftovers from a previous crashed run, then create the control DB.
    drop_db(&admin, &control_db).await;
    drop_db(&admin, &tenant_db_a).await;
    drop_db(&admin, &tenant_db_b).await;
    create_db(&admin, &control_db)
        .await
        .expect("create control db");

    let result = async {
        let control_url = with_db(&admin_url(), &control_db);
        let control = Arc::new(ControlStore::connect(&control_url).await?);
        // The base tenant URL the LocalProvider swaps per org (same server).
        let base_tenant_url = with_db(&admin_url(), "reproit");
        let tenancy = Tenancy::new(control.clone(), Blobs::from_env(), &base_tenant_url, None);

        // Orgs must exist (tenants.org_id REFERENCES orgs(id)).
        seed_org(&control_url, org_a, "Org A").await?;
        seed_org(&control_url, org_b, "Org B").await?;

        // Provision BOTH tenants: each creates its own database + applies the schema.
        tenancy.provision(org_a).await?;
        tenancy.provision(org_b).await?;

        // Resolve each tenant and write a DISTINCT project + error into each.
        let ta = tenancy
            .resolve(org_a)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let tb = tenancy
            .resolve(org_b)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        ta.store.create_project(0, "Alpha", "app-a").await?;
        tb.store.create_project(0, "Bravo", "app-b").await?;
        let err_a = err_rec("sig-a", "boom-a");
        let err_b = err_rec("sig-b", "boom-b");
        let bucket_a = buckets::bucket_id(&err_a);
        let bucket_b = buckets::bucket_id(&err_b);
        ta.store.add_error("app-a", &err_a).await?;
        tb.store.add_error("app-b", &err_b).await?;

        // Each store sees ONLY its own project.
        let a_projects = ta.store.list_projects().await?;
        let b_projects = tb.store.list_projects().await?;
        anyhow::ensure!(
            a_projects.len() == 1 && a_projects[0].2 == "app-a",
            "tenant A should see exactly its own project, saw {a_projects:?}"
        );
        anyhow::ensure!(
            b_projects.len() == 1 && b_projects[0].2 == "app-b",
            "tenant B should see exactly its own project, saw {b_projects:?}"
        );

        // The cross-tenant read is physically impossible: A cannot see B's app_id.
        anyhow::ensure!(
            !ta.store.owns_app("app-b").await?,
            "ISOLATION BREACH: tenant A can see tenant B's app-b"
        );
        anyhow::ensure!(
            !tb.store.owns_app("app-a").await?,
            "ISOLATION BREACH: tenant B can see tenant A's app-a"
        );

        // Errors are likewise isolated: A's app-id has A's error and nothing of B's.
        let a_errors = ta.store.errors("app-a").await?;
        let b_errors = tb.store.errors("app-b").await?;
        anyhow::ensure!(
            a_errors.len() == 1 && a_errors[0].sig == "sig-a",
            "tenant A errors leaked or missing (count {}, first sig {:?})",
            a_errors.len(),
            a_errors.first().map(|e| e.sig.as_str())
        );
        anyhow::ensure!(
            b_errors.len() == 1 && b_errors[0].sig == "sig-b",
            "tenant B errors leaked or missing (count {}, first sig {:?})",
            b_errors.len(),
            b_errors.first().map(|e| e.sig.as_str())
        );
        anyhow::ensure!(
            ta.store
                .errors_for_bucket("app-a", &bucket_a, 10)
                .await?
                .len()
                == 1,
            "tenant A bucket detail read could not find the bucket listed by the error payload"
        );
        anyhow::ensure!(
            tb.store
                .errors_for_bucket("app-b", &bucket_b, 10)
                .await?
                .len()
                == 1,
            "tenant B bucket detail read could not find the bucket listed by the error payload"
        );
        // Querying A's store for B's app-id returns nothing (no shared rows).
        anyhow::ensure!(
            ta.store.errors("app-b").await?.is_empty(),
            "ISOLATION BREACH: tenant A returned rows for tenant B's app-id"
        );

        anyhow::Ok(())
    }
    .await;

    // Teardown: drop every database we created, regardless of pass/fail.
    drop_db(&admin, &tenant_db_a).await;
    drop_db(&admin, &tenant_db_b).await;
    drop_db(&admin, &control_db).await;
    admin.close().await;

    result.expect("tenant isolation test body");
}

/// 2. SCHEMA APPLY. Apply the declarative tenant schema to a FRESH database,
///    assert the expected tables exist, and that a SECOND apply is an
///    idempotent no-op (pre-launch there is no migration ledger; the schema
///    file is the truth and re-applies must always be safe).
#[tokio::test]
async fn schema_apply_creates_tables_and_reapply_is_noop() {
    let Some(admin) = admin_pool_or_skip("schema_apply_creates_tables_and_reapply_is_noop").await
    else {
        return;
    };

    let tenant_db = format!("reproit_it_schema_{}", std::process::id());
    drop_db(&admin, &tenant_db).await;
    create_db(&admin, &tenant_db)
        .await
        .expect("create tenant db");

    let result = async {
        let conn = with_db(&admin_url(), &tenant_db);

        crate::db::schema::apply(&conn).await?;

        let mut c = sqlx::PgConnection::connect(&conn).await?;
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT table_name FROM information_schema.tables
             WHERE table_schema='public' ORDER BY table_name",
        )
        .fetch_all(&mut c)
        .await?;
        for expected in [
            "jobs",
            "shards",
            "edges",
            "errors",
            "evidence",
            "replay_results",
            "bucket_tickets",
            "projects",
            "bucket_triage",
            "bucket_resolution_status",
            "bucket_resolution_events",
            "project_integrations",
            "cloud_runs",
        ] {
            anyhow::ensure!(
                tables.iter().any(|t| t == expected),
                "schema apply should create {expected}; got {tables:?}"
            );
        }
        c.close().await?;

        // Second apply: idempotent (IF NOT EXISTS everywhere), no error.
        crate::db::schema::apply(&conn).await?;

        anyhow::Ok(())
    }
    .await;

    drop_db(&admin, &tenant_db).await;
    admin.close().await;

    result.expect("schema apply test body");
}

/// 3. FULL PATH: a request lifecycle in miniature. Create the org + a user in the
///    control plane -> provision the tenant -> create a project AND an API key
///    (control) -> resolve the org's TenantStore -> write+read one row through it.
#[tokio::test]
async fn full_path_org_to_provision_to_key_to_tenant_row() {
    let Some(admin) = admin_pool_or_skip("full_path_org_to_provision_to_key_to_tenant_row").await
    else {
        return;
    };

    let control_db = format!("reproit_it_control_full_{}", std::process::id());
    let org_id = 990003i64;
    let tenant_db = format!("reproit_tenant_{org_id}");

    drop_db(&admin, &control_db).await;
    drop_db(&admin, &tenant_db).await;
    create_db(&admin, &control_db)
        .await
        .expect("create control db");

    let result = async {
        let control_url = with_db(&admin_url(), &control_db);
        let control = Arc::new(ControlStore::connect(&control_url).await?);
        let base_tenant_url = with_db(&admin_url(), "reproit");
        let tenancy = Tenancy::new(control.clone(), Blobs::from_env(), &base_tenant_url, None);

        // Control plane: org + user, then provision the tenant database.
        seed_org(&control_url, org_id, "Acme").await?;
        let user_id = seed_user(&control_url, "owner@acme.test").await?;
        let rec = tenancy.provision(org_id).await?;
        anyhow::ensure!(
            rec.status == TenantStatus::Active && rec.db_conn.is_some(),
            "provisioned tenant should be active with a conn: {rec:?}"
        );

        // Tenant store: create a project, take its id back.
        let tenant = tenancy
            .resolve(org_id)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let project_id = tenant
            .store
            .create_project(user_id, "Web", "acme-web")
            .await?;
        anyhow::ensure!(project_id > 0, "project id should be assigned");

        // Control plane: mint an API key for the org, scoped to that project. The
        // key is the CLI/SDK routing key (org id -> tenant), so it lives in control.
        control
            .create_api_key(
                "secret-xyz",
                "rk_live_ab",
                org_id,
                user_id,
                Some(project_id),
            )
            .await?;
        let resolved = control.org_for_api_key("secret-xyz").await?;
        anyhow::ensure!(
            resolved == Some((org_id, "free".to_string(), Some(project_id), Some(user_id))),
            "the API key should route to the org and carry its project scope: {resolved:?}"
        );
        let key_hash = crate::db::key_hash("secret-xyz");
        sqlx::query("UPDATE api_keys SET active = false WHERE key = $1")
            .bind(&key_hash)
            .execute(control.pool())
            .await?;
        anyhow::ensure!(
            control.org_for_api_key("secret-xyz").await?.is_none(),
            "inactive API key should not authenticate"
        );
        sqlx::query(
            "UPDATE api_keys SET active = true, expires_at = now() - interval '1 second' WHERE key = $1",
        )
        .bind(&key_hash)
        .execute(control.pool())
        .await?;
        anyhow::ensure!(
            control.org_for_api_key("secret-xyz").await?.is_none(),
            "expired API key should not authenticate"
        );
        sqlx::query(
            "UPDATE api_keys SET expires_at = now() + interval '1 hour' WHERE key = $1",
        )
        .bind(&key_hash)
        .execute(control.pool())
        .await?;
        let resolved = control.org_for_api_key("secret-xyz").await?;
        anyhow::ensure!(
            resolved == Some((org_id, "free".to_string(), Some(project_id), Some(user_id))),
            "future-expiring API key should route to the org: {resolved:?}"
        );

        // Tenant store round-trip: write one telemetry row and read it back.
        tenant.store.incr_edge("acme-web", "s1->s2").await?;
        tenant.store.incr_edge("acme-web", "s1->s2").await?;
        let edges = tenant.store.edges("acme-web").await?;
        anyhow::ensure!(
            edges == vec![("s1->s2".to_string(), 2)],
            "edge row should read back with count 2: {edges:?}"
        );
        let error = ErrorRec {
            sig: "delete-regression".to_string(),
            message: "project cleanup regression".to_string(),
            path: vec![],
            context: serde_json::from_value(serde_json::json!({
                "build": {"version": "delete-test"},
                "locale": "en-US"
            }))?,
        };
        tenant
            .store
            .ingest_batch(
                "acme-web",
                &[],
                &[error.clone(), error],
                &[],
                "delete-regression-batch",
                Some("delete-test"),
            )
            .await?;

        // Project deletion removes raw rows plus derived read models and revokes
        // only this project's keys. Multiple errors in one bucket reproduce the
        // old last-error trigger failure if deletion ordering regresses.
        let project = tenant
            .store
            .project_for_app("acme-web")
            .await?
            .ok_or_else(|| anyhow::anyhow!("project should exist before deletion"))?;
        control.delete_api_keys_for_project(project.0).await?;
        anyhow::ensure!(
            tenant.store.delete_project_by_app("acme-web").await?,
            "project deletion should report a removed project"
        );
        anyhow::ensure!(
            !tenant.store.owns_app("acme-web").await?,
            "deleted project should no longer be owned"
        );
        anyhow::ensure!(
            tenant.store.edges("acme-web").await?.is_empty(),
            "deleted project should leave no edge data"
        );
        anyhow::ensure!(
            control.org_for_api_key("secret-xyz").await?.is_none(),
            "deleted project key should no longer authenticate"
        );

        anyhow::Ok(())
    }
    .await;

    drop_db(&admin, &tenant_db).await;
    drop_db(&admin, &control_db).await;
    admin.close().await;

    result.expect("full path test body");
}

/// 4. NEON (feature `neon`, live-gated). Provision-adopt-deprovision round trip
///    against the real Neon API. The normal suite ignores this external gate;
///    the production-validation workflow selects it explicitly and missing
///    credentials are then a hard failure rather than a silent skip.
#[cfg(feature = "neon")]
#[tokio::test]
#[ignore = "requires a disposable live Neon project and production-validation credentials"]
async fn neon_provision_adopt_deprovision_round_trip() {
    use super::provider::{ConnectionProvider, NeonProvider};
    let p = NeonProvider::from_env()
        .expect("NEON_API_KEY must be set for the explicit production provider gate");
    // A throwaway org id far above anything real (mirrors the Postgres suite).
    let org: i64 = 990_000 + (std::process::id() as i64 % 9_000);
    let result = async {
        let conn = p.provision(org).await?;
        anyhow::ensure!(
            conn.starts_with("postgres://") || conn.starts_with("postgresql://"),
            "neon returned a non-postgres uri: {conn}"
        );
        // Idempotent adopt: a second provision returns a working uri for the
        // SAME project rather than creating a duplicate.
        let again = p.provision(org).await?;
        anyhow::ensure!(
            again.starts_with("postgres://") || again.starts_with("postgresql://"),
            "adopt returned a non-postgres uri: {again}"
        );
        // The schema applies to the fresh Neon database end to end.
        crate::db::schema::apply(&conn).await?;
        anyhow::Ok(())
    }
    .await;
    // Teardown ALWAYS runs (idempotent), then surface the body's verdict.
    let torn_down = p.deprovision(org).await;
    result.expect("neon round-trip body");
    torn_down.expect("neon deprovision");
}
