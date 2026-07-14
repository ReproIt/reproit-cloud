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
use sqlx::postgres::PgPoolOptions;
use sqlx::Connection;
use std::sync::Arc;
use std::time::Duration;

/// The admin (maintenance-DB) URL to create/drop throwaway databases against.
fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://reproit:reproit@localhost:5433/postgres".to_string())
}

/// Swap the database segment of a Postgres URL (mirror of the provider's helper,
/// kept local to the test so it depends on nothing private).
fn with_db(url: &str, db: &str) -> String {
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
async fn create_db(admin: &sqlx::PgPool, name: &str) -> anyhow::Result<()> {
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
async fn drop_db(admin: &sqlx::PgPool, name: &str) {
    let _ =
        sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1")
            .bind(name)
            .execute(admin)
            .await;
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{name}\""))
        .execute(admin)
        .await;
}

/// Insert an `orgs` row with an EXPLICIT id (the FK target for `tenants` /
/// `api_keys`). High ids (990000+) so we never collide with real BIGSERIAL orgs.
async fn seed_org(control_url: &str, org_id: i64, name: &str) -> anyhow::Result<()> {
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
        let base_tenant_url = control_url.clone();
        let tenancy = Tenancy::new(control.clone(), Blobs::from_env(), &base_tenant_url);

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
            resolved == Some((org_id, Some(project_id), Some(user_id))),
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
            resolved == Some((org_id, Some(project_id), Some(user_id))),
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

        anyhow::Ok(())
    }
    .await;

    drop_db(&admin, &tenant_db).await;
    drop_db(&admin, &control_db).await;
    admin.close().await;

    result.expect("full path test body");
}
