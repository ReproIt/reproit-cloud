//! reproit-cloud: the control plane the CLI earns.
//!
//! Core thesis (CLOUD.md): a cloud worker runs the EXACT SAME `reproit`
//! binary against one device/shard. The cloud is orchestration + fleet +
//! storage AROUND the CLI, not a reimplementation. A fuzz job fans out into one
//! shard per seed; shards live in a durable Postgres queue that remote workers
//! (a Mac for ios + android + web, Linux for web/android) CLAIM over HTTP, so a
//! restart never loses work and the worker fleet is provider-agnostic.

mod auth;
mod backend_contract;
mod bootstrap;
mod captures;
mod db;
mod edition;
mod http_security;
mod ingest;
mod integrations;
mod jobs;
mod mail;
mod operations;
mod router;
mod sweep;
mod tenancy;
mod triage;

use axum::http::HeaderMap;
use axum::{
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE, HOST},
        HeaderName, HeaderValue, Method, StatusCode,
    },
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use clap::Parser;
use db::ControlStore;
use http_security::*;
use jobs::{Job, JobSpec};
use operations::*;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tenancy::resolver::Tenant;
use tenancy::{ResolveError, Tenancy};
use tower_governor::{
    errors::GovernorError,
    governor::GovernorConfigBuilder,
    key_extractor::{KeyExtractor, SmartIpKeyExtractor},
    GovernorLayer,
};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// The built-in fallback Postgres url (local dev). Used as the last-resort control
/// connection when no env names one; never invents a tenant DB on its own.
const DEFAULT_DB_URL: &str = "postgres://reproit:reproit@localhost:5433/reproit";

/// Optional public-host boundary. An empty value keeps local and self-hosted
/// installs unrestricted; the hosted deployment sets the two Cloudflare names.
static ALLOWED_HOSTS: OnceLock<HashSet<String>> = OnceLock::new();

#[derive(Parser)]
#[command(
    name = "reproit-cloud",
    version = env!("CARGO_PKG_VERSION"),
    about = "ReproIt cloud control plane"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    #[arg(long, default_value_t = 8080)]
    port: u16,
    /// Embedded worker pool size (local dev: the control plane also claims and
    /// runs shards itself). In production this is 0 and remote workers claim.
    #[arg(long, default_value_t = 0)]
    workers: usize,
    /// Path to the reproit binary the (embedded) workers invoke.
    #[arg(long, default_value = "reproit")]
    reproit_bin: String,
}

/// The one-shot subcommand surface (ops).
#[derive(clap::Subcommand)]
enum Cmd {
    /// Print the experimental route-registry-checked backend contract and exit.
    #[command(hide = true)]
    BackendContract,
    /// Offboard a tenant COMPLETELY (ops/GDPR): tear down its database at the
    /// provider, delete every blob under its scope, and remove the org (members,
    /// keys, tenants row, usage cascade). Refuses to run without --yes.
    Offboard {
        /// The org id to offboard.
        #[arg(long)]
        org: i64,
        /// Confirm the irreversible deletion.
        #[arg(long)]
        yes: bool,
    },
    /// Suspend a tenant (ops: billing/abuse): the resolver stops serving it, so
    /// ingest and the dashboard refuse, but its database and blobs stay intact.
    /// Reversible with `resume`. Refuses to run without --yes.
    Suspend {
        /// The org id to suspend.
        org: i64,
        /// Confirm taking the tenant out of service.
        #[arg(long)]
        yes: bool,
    },
    /// Resume a suspended tenant (status back to active; served again).
    Resume {
        /// The org id to resume.
        org: i64,
    },
    /// List every tenant in the registry as a table: org id, name, status, plan.
    Tenants,
    /// Print an org's most recent audit-log rows, newest first.
    Audit {
        /// The org id to read the audit trail for.
        org: i64,
        /// How many rows to print.
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
    /// Requeue one tenant's stranded shards now (the background sweep does this
    /// every minute; this is the on-demand ops form).
    Requeue {
        /// The org id whose queue to requeue.
        org: i64,
    },
    /// Self-host install bootstrap: create the single org, an admin owner, and a
    /// default project + its first API key (printed once), then exit. Idempotent:
    /// safe to re-run (it never mints a second key). Resolves the single-tenant DB
    /// from DATABASE_URL / REPROIT_SELF_HOSTED_DB exactly like self-host startup.
    Init {
        /// Admin account email (becomes owner of the single org).
        #[arg(long)]
        email: String,
        /// Admin account password (at least 8 characters).
        #[arg(long)]
        password: String,
        /// Name of the default project to create.
        #[arg(long, default_value = "Default")]
        project: String,
    },
}

#[derive(Clone)]
pub(crate) struct App {
    /// The SHARED control plane: tenants registry, identity, keys, billing, SSO.
    pub(crate) control: Arc<ControlStore>,
    /// The database-per-org machinery: resolve an org id to a tenant-bound store +
    /// blob scope; provision a tenant on signup.
    pub(crate) tenancy: Arc<Tenancy>,
    pub(crate) reproit_bin: String,
    /// Raw-path job submission (`POST /jobs`) is for local dev and self-hosted
    /// installs where the caller and worker intentionally share a filesystem.
    /// Managed cloud tenants must not be able to submit arbitrary `app_dir`
    /// paths, even though `jobs::validate_app_dir` confines them defensively.
    pub(crate) allow_raw_jobs: bool,
    /// True for the self-hosted single-tenant edition. Hosted cloud keeps plan
    /// and seat-limit behavior; self-host removes commercial seat caps.
    pub(crate) self_hosted: bool,
    /// Edition policy hooks (quotas, metering, tenant maintenance) called from
    /// shared flow; see `edition.rs`. Self-host installs `PassivePolicy`.
    pub(crate) policy: Arc<dyn edition::EditionPolicy>,
}

impl App {
    /// Resolve an `AuthCtx` to the tenant-bound handle (store + blobs) a handler
    /// operates on. This is where the cross-tenant boundary lives now: the returned
    /// `Tenant` is bound to exactly one database, so a handler physically cannot
    /// read another tenant's rows.
    ///
    /// An `Org` caller resolves to its own tenant. The shared `Admin` key has no
    /// implicit tenant (apps are no longer globally resolvable to an org under
    /// db-per-org); it must name the target via `X-Reproit-Tenant: <org_id>`, a
    /// deliberate ops action, never a silent default.
    pub(crate) async fn tenant_of(
        &self,
        auth: AuthCtx,
        headers: &HeaderMap,
    ) -> Result<Tenant, (StatusCode, Json<serde_json::Value>)> {
        let org_id = match auth {
            AuthCtx::Org(id) => id,
            AuthCtx::Admin => admin_target_result(headers).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": e.message() })),
                )
            })?,
        };
        match self.tenancy.resolve(org_id).await {
            Ok(t) => Ok(t),
            // Not provisioned / not active: 404 (no existence leak), exactly like
            // the old tenancy guard returned for an app the caller couldn't see.
            Err(ResolveError::NotProvisioned) | Err(ResolveError::NotActive(_)) => {
                Err((StatusCode::NOT_FOUND, Json(not_found())))
            }
            Err(ResolveError::Internal(e)) => {
                tracing::error!("tenant resolve failed for org {org_id}: {e}");
                Err((StatusCode::INTERNAL_SERVER_ERROR, Json(server_error())))
            }
        }
    }
}

/// The explicit ops tenant selector for an admin-key request.
fn admin_target(headers: &HeaderMap) -> Option<i64> {
    admin_target_result(headers).ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdminTargetError {
    Missing,
    Invalid,
}

impl AdminTargetError {
    fn message(self) -> &'static str {
        match self {
            AdminTargetError::Missing => {
                "admin API-key requests must include `X-Reproit-Tenant: <org_id>`; use an org-scoped `sk_live_...` key or choose the target tenant org id"
            }
            AdminTargetError::Invalid => {
                "invalid `X-Reproit-Tenant` header: send a numeric tenant org id, for example `X-Reproit-Tenant: 123`"
            }
        }
    }
}

fn admin_target_result(headers: &HeaderMap) -> Result<i64, AdminTargetError> {
    headers
        .get("x-reproit-tenant")
        .ok_or(AdminTargetError::Missing)
        .and_then(|v| {
            v.to_str()
                .ok()
                .and_then(|s| s.trim().parse::<i64>().ok())
                .ok_or(AdminTargetError::Invalid)
        })
}

/// Who is calling a protected route. Inserted into request extensions by
/// `require_api_key`. Under database-per-org the org id here is the ROUTING KEY:
/// `App::tenant_of` maps it to the tenant database the handler operates on. The
/// cross-tenant boundary is that database, not a `WHERE org_id =` clause.
#[derive(Clone, Copy, Debug)]
pub(crate) enum AuthCtx {
    /// The shared admin/ops key: targets a tenant explicitly (X-Reproit-Tenant).
    Admin,
    /// A per-org API key: resolves to this org's tenant database.
    Org(i64),
}

/// Scope of the API-key credential that authenticated the request, inserted into
/// request extensions alongside `AuthCtx`. `project_id` is the tenant-db project
/// the key was minted for (None for org-wide keys and the admin key);
/// `publishable` marks the browser (pk_live_) key. Ingest uses the pair to pin a
/// publishable key to its own app: a pk lifted from one page must not be able to
/// inject telemetry into the org's other projects.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KeyScope {
    pub(crate) project_id: Option<i64>,
    pub(crate) user_id: Option<i64>,
    pub(crate) publishable: bool,
}

impl KeyScope {
    /// The unconstrained scope (admin key, dev-open, org-wide keys).
    pub(crate) const OPEN: KeyScope = KeyScope {
        project_id: None,
        user_id: None,
        publishable: false,
    };
}

/// Run the Reproit Cloud application from parsed process configuration.
pub async fn run() -> anyhow::Result<()> {
    // rustls 0.23 requires a process-wide default crypto provider before any TLS
    // handshake. sqlx (Postgres TLS) and rust-s3 both build rustls configs
    // that rely on this default; without it a TLS-required remote Postgres can
    // fail to connect and the pool silently times out, while a local plaintext
    // Postgres never hits the TLS path. Install `ring` once, at the very top.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    if matches!(cli.cmd, Some(Cmd::BackendContract)) {
        println!(
            "{}",
            serde_json::to_string_pretty(&backend_contract::openapi())?
        );
        return Ok(());
    }

    // This distribution is self-hosted only. There is no hosted/SaaS mode.
    // (single-tenant by definition). This is the mode that maps DATABASE_URL onto
    // BOTH connections and enables the startup env-bootstrap. The legacy
    // `--self-hosted-db` flag also yields a single tenant (see `self_hosted` below),
    // but keeps the old "control defaults to localhost" resolution, so existing
    // invocations are byte-for-byte unchanged.
    let self_hosted = true;
    // Tell the integrations layer which mode we're in: the bare (un-namespaced)
    // tracker env fallback is only legal single-tenant.
    integrations::set_self_hosted(self_hosted);
    // Prometheus metrics: opt-in via REPROIT_METRICS_ADDR (e.g. 127.0.0.1:9090).
    // Served by the exporter's own listener, NEVER on the public router, so the
    // scrape surface needs no auth story of its own. Unset = recorder absent and
    // every metrics:: macro is a no-op.
    if let Ok(addr) = std::env::var("REPROIT_METRICS_ADDR") {
        match addr.parse::<std::net::SocketAddr>() {
            Ok(sock) => {
                if let Err(e) = metrics_exporter_prometheus::PrometheusBuilder::new()
                    .with_http_listener(sock)
                    .install()
                {
                    tracing::error!("metrics exporter failed to start on {sock}: {e}");
                } else {
                    tracing::info!("prometheus metrics on {sock}/metrics");
                }
            }
            Err(_) => {
                tracing::error!("REPROIT_METRICS_ADDR {addr:?} is not host:port; metrics disabled")
            }
        }
    }

    // Dev-open is a local-development convenience that grants Admin to anyone.
    // It is never legitimate on a multi-tenant deployment, so refuse outright
    // rather than trusting REPROIT_PUBLIC_URL to be set correctly.
    if dev_open() && !self_hosted {
        anyhow::bail!(
            "refusing to start with REPROIT_DEV_OPEN on a hosted (multi-tenant) deployment; unset REPROIT_DEV_OPEN or run self-hosted"
        );
    }

    // Compute the EFFECTIVE connection strings, applying the self-host precedence
    // before we connect. The explicit control/tenant urls arrive via clap (each
    // backed by its env), so an unset one is genuinely `None` (not the default);
    // DATABASE_URL has no flag, so it is read raw. Precedence: explicit url >
    // (first-class self-host) DATABASE_URL > the built-in default.
    let database_url = std::env::var("DATABASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let control_url = database_url.unwrap_or_else(|| DEFAULT_DB_URL.to_string());

    // Connect the SHARED control plane (registry + identity + billing). Its schema
    // applies on boot; tenant DBs get the declarative schema at provision/boot.
    let control = Arc::new(ControlStore::connect(&control_url).await?);
    tracing::info!("connected to control-plane postgres, schema ready");

    // Build the tenancy layer: blobs + the connection provider (local-per-tenant
    // for dev/SaaS, single-tenant for self-hosted) behind one resolver/provisioner.
    let blobs = tenancy::blob::Blobs::from_env();
    let blobs_local = blobs.is_local_fs();
    let blobs_ops = blobs.clone();
    let tenancy = Arc::new(Tenancy::new(control.clone(), blobs, &control_url));

    let app = App {
        control: control.clone(),
        tenancy,
        reproit_bin: cli.reproit_bin.clone(),
        allow_raw_jobs: raw_jobs_enabled(self_hosted, dev_open()),
        self_hosted,
        policy: Arc::new(edition::PassivePolicy),
    };

    // One-shot subcommands: run and exit before the server ever binds.
    match &cli.cmd {
        Some(Cmd::Offboard { org, yes }) => {
            return run_offboard(&app, &blobs_ops, *org, *yes).await;
        }
        Some(Cmd::Suspend { org, yes }) => {
            return run_set_tenant_status(&app, *org, db::TenantStatus::Suspended, *yes).await;
        }
        Some(Cmd::Resume { org }) => {
            return run_set_tenant_status(&app, *org, db::TenantStatus::Active, true).await;
        }
        Some(Cmd::Tenants) => {
            return run_list_tenants(&app).await;
        }
        Some(Cmd::Audit { org, limit }) => {
            return run_audit(&app, *org, *limit).await;
        }
        Some(Cmd::Requeue { org }) => {
            return run_requeue(&app, *org).await;
        }
        // Self-host install bootstrap: create org/admin/project + first key, exit.
        Some(Cmd::Init {
            email,
            password,
            project,
        }) => {
            return bootstrap::bootstrap(&app, email, password, project).await;
        }
        Some(Cmd::BackendContract) => unreachable!("handled before database initialization"),
        None => {}
    }

    // Hosted (multi-tenant) evidence must land in a durable object store: the Fly
    // machine's disk is ephemeral, so local-fs blobs silently vanish on stop. A
    // hosted operator who genuinely has a persistent volume can override. Checked
    // AFTER the one-shot subcommands so `init` never depends on blob env.
    if !self_hosted
        && blobs_local
        && std::env::var("REPROIT_ALLOW_LOCAL_BLOBS").ok().as_deref() != Some("1")
    {
        anyhow::bail!(
            "hosted deployment without object storage: configure R2_* (build with --features r2), or set REPROIT_ALLOW_LOCAL_BLOBS=1 only if REPROIT_ARTIFACT_DIR is on a persistent volume"
        );
    }

    // Optional zero-touch bootstrap creates the installation org before the
    // fixed data-plane record. With no bootstrap env, `reproit-cloud init`
    // performs the same idempotent sequence later.
    run_env_bootstrap(&app).await;
    if app
        .control
        .org_exists(tenancy::SELF_HOSTED_ORG_ID)
        .await
        .unwrap_or(false)
    {
        if let Err(e) = app.tenancy.provision(tenancy::SELF_HOSTED_ORG_ID).await {
            tracing::error!("self-hosted data schema initialization failed: {e}");
        }
    }

    spawn_background_sweeps(app.clone());
    // Proactive regression sweep: periodically re-evaluate prod-truth for every
    // anchored bucket and log status TRANSITIONS to the durable alert table. Runs
    // alongside the server; tolerant of an empty DB and never crashes on error.
    sweep::spawn(app.clone());

    // Graceful drain: on SIGTERM/ctrl-c we stop accepting connections (axum) and
    // signal the embedded worker pool to stop claiming and finish in-flight work.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    if cli.workers > 0 {
        jobs::worker::spawn_embedded(app.clone(), cli.workers, shutdown_rx.clone());
    }

    let router = router::build(app);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", cli.port)).await?;
    tracing::info!(
        "reproit-cloud on :{} (embedded workers: {}). /v1/events · /v1/worker/claim",
        cli.port,
        cli.workers
    );
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    })
    .await?;
    Ok(())
}

async fn ready(State(app): State<App>) -> Response {
    match app.control.ping().await {
        Ok(()) => (StatusCode::OK, "ready").into_response(),
        Err(e) => {
            tracing::warn!("readiness check failed: {e}");
            (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
        }
    }
}

/// Optional self-host bootstrap driven by env. Runs only when BOTH
/// `REPROIT_BOOTSTRAP_EMAIL` and `REPROIT_BOOTSTRAP_PASSWORD` are present and
/// non-empty; the project name defaults to "Default". The whole thing is
/// best-effort: a failure is logged, NOT propagated, so a re-deploy with the same
/// envs is safe and the server still comes up (just un-bootstrapped).
async fn run_env_bootstrap(app: &App) {
    let email = std::env::var("REPROIT_BOOTSTRAP_EMAIL")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let password = std::env::var("REPROIT_BOOTSTRAP_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty());
    let (email, password) = match (email, password) {
        (Some(e), Some(p)) => (e, p),
        _ => return,
    };
    let project = std::env::var("REPROIT_BOOTSTRAP_PROJECT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Default".to_string());
    match bootstrap::bootstrap(app, &email, &password, &project).await {
        Ok(()) => tracing::info!("self-host env bootstrap complete"),
        Err(e) => tracing::error!("self-host env bootstrap failed (will retry on next boot): {e}"),
    }
}

/// Background maintenance. Prune expired control-plane sessions, fan the stranded-
/// shard requeue across active tenant DBs (the queue is per-tenant now), and sweep
/// idle tenant pools so total live connections track active tenants.
fn spawn_background_sweeps(app: App) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        let mut ticks: u64 = 0;
        loop {
            tick.tick().await;
            ticks += 1;
            // Retention enforcement + batch-id pruning are hourly (deletes are
            // batched + indexed, but there is no reason to scan every minute).
            let hourly = ticks % 60 == 1;
            if let Err(e) = app.control.prune_sessions().await {
                tracing::warn!("prune_sessions sweep: {e}");
            }
            if let Err(e) = app.control.prune_org_invitations().await {
                tracing::warn!("prune_org_invitations sweep: {e}");
            }
            // Fan the requeue across every active tenant DB (per-tenant queues).
            match app.control.all_tenants().await {
                Ok(tenants) => {
                    for t in tenants {
                        if t.status != db::TenantStatus::Active {
                            continue;
                        }
                        if let Ok(tenant) = app.tenancy.resolve(t.org_id).await {
                            if hourly {
                                if let Err(e) = tenant.store.prune_processed_batches(48).await {
                                    tracing::warn!(
                                        "prune_processed_batches for tenant {}: {e}",
                                        t.org_id
                                    );
                                }
                            }
                            // Hosted runs whose CI never reported back: expire so
                            // the ledger can't hold a run open forever.
                            match tenant
                                .store
                                .expire_stale_cloud_runs(cloud_run_timeout_secs())
                                .await
                            {
                                Ok(n) if n >= 1 => {
                                    tracing::warn!(
                                        "expired {n} stale cloud run(s) for tenant {}",
                                        t.org_id
                                    );
                                    // A hosted run expiring means the customer's CI
                                    // never posted a verdict: the repository_dispatch
                                    // loop is (silently) broken for that app. The
                                    // counter is the reliable Alertmanager signal;
                                    // the webhook is a best-effort page on top.
                                    metrics::counter!("cloud_runs_expired_total").increment(n);
                                    crate::sweep::fire_ops_alert(format!(
                                        "{n} hosted reproduction run(s) for org {} timed out with no verdict from CI: the repository_dispatch loop may be broken (check the app's reproit-repro workflow and its REPROIT_CLOUD_KEY secret)",
                                        t.org_id
                                    ));
                                }
                                Ok(_) => {}
                                Err(e) => tracing::warn!(
                                    "expire_stale_cloud_runs for tenant {}: {e}",
                                    t.org_id
                                ),
                            }
                            match tenant.store.requeue_stranded(120).await {
                                // Any shard moved running->pending is a transition
                                // INTO pending, so re-mark the tenant in the
                                // control-plane routing hint or those requeued shards
                                // would be starved (the claim path only visits marked
                                // tenants; finding #3 invariant).
                                Ok(n) if n >= 1 => {
                                    if let Err(e) = app.control.mark_tenant_pending(t.org_id).await
                                    {
                                        tracing::warn!(
                                            "mark_tenant_pending after requeue for tenant {}: {e}",
                                            t.org_id
                                        );
                                    }
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    tracing::warn!("requeue_stranded for tenant {}: {e}", t.org_id)
                                }
                            }
                        }
                    }
                }
                Err(e) => tracing::warn!("requeue sweep: list tenants failed: {e}"),
            }
            let evicted = app.tenancy.sweep_idle_pools().await;
            if evicted > 0 {
                tracing::debug!(
                    "evicted {evicted} idle tenant pool(s); {} live",
                    app.tenancy.live_pools().await
                );
            }
        }
    });
}

/// How long a dispatched hosted run may stay open before the sweep expires it.
/// A customer CI queue + checkout + replay comfortably fits the 30min default.
pub(crate) fn cloud_run_timeout_secs() -> i64 {
    std::env::var("REPROIT_CLOUD_RUN_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(1800)
}

/// Explicit local-dev escape hatch. NEVER defaults on; production leaves it unset.
fn dev_open() -> bool {
    matches!(
        std::env::var("REPROIT_DEV_OPEN").ok().as_deref(),
        Some("1") | Some("true")
    )
}

fn raw_jobs_enabled(self_hosted: bool, dev_open: bool) -> bool {
    self_hosted || dev_open
}

#[derive(Clone)]
struct BearerKeyExtractor;

impl KeyExtractor for BearerKeyExtractor {
    type Key = String;

    fn extract<T>(&self, req: &axum::http::Request<T>) -> Result<Self::Key, GovernorError> {
        let key = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("missing-bearer");
        Ok(key.to_string())
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    tracing::info!("shutting down (draining)");
}

async fn submit_job(
    State(app): State<App>,
    Extension(auth): Extension<AuthCtx>,
    headers: HeaderMap,
    Json(spec): Json<JobSpec>,
) -> Response {
    if !app.allow_raw_jobs {
        return (StatusCode::NOT_FOUND, Json(not_found())).into_response();
    }
    if let Err(msg) = spec.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response();
    }
    // Confine the submitted app_dir to the allowed jobs root BEFORE doing any
    // work: a caller must not be able to point the worker at an arbitrary absolute
    // path (canonicalize + confine; rejects traversal, symlink escape, and
    // non-existent dirs). The worker re-checks defensively (finding #6).
    if let Err(msg) = jobs::validate_app_dir(&spec.app_dir) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response();
    }

    // Resolve the caller's tenant: the job is inserted into THAT tenant's queue.
    let tenant = match app.tenant_of(auth, &headers).await {
        Ok(t) => t,
        Err((s, j)) => return (s, j).into_response(),
    };
    let job = Job::new(spec);
    let id = job.id.clone();
    let shards = job.shards.len();
    if let Err(e) = tenant.store.insert_job(&job).await {
        tracing::error!("insert_job failed: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "could not enqueue job" })),
        )
            .into_response();
    }
    // The job's shards just transitioned INTO pending, so mark this tenant in the
    // control-plane routing hint (`tenant_pending_shards`) the worker claim path
    // scans (finding #3). A failure here is logged but NOT fatal: the shards are
    // durably enqueued, and the requeue sweep re-marks any tenant whose pending
    // shards it touches, so a missed mark self-heals on the next sweep rather than
    // losing the job.
    if let Err(e) = app.control.mark_tenant_pending(tenant.org_id).await {
        tracing::warn!(
            "mark_tenant_pending for tenant {} after submit failed: {e}",
            tenant.org_id
        );
    }
    // Shards sit in the durable queue; remote (or embedded) workers claim them.
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "id": id,
            "shards": shards,
            "status_url": format!("/jobs/{id}")
        })),
    )
        .into_response()
}

async fn get_job(
    State(app): State<App>,
    Extension(auth): Extension<AuthCtx>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    // The job lives in the caller's tenant DB; a job from another tenant simply
    // doesn't exist here (the database is the boundary), so the snapshot 404s.
    let tenant = match app.tenant_of(auth, &headers).await {
        Ok(t) => t,
        Err((s, j)) => return (s, j).into_response(),
    };
    match tenant.store.snapshot(&id).await {
        Ok(Some(v)) => (StatusCode::OK, Json(v)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(not_found())).into_response(),
        Err(e) => {
            tracing::error!("snapshot failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(server_error())).into_response()
        }
    }
}

pub(crate) async fn account_tenant(app: &App, headers: &HeaderMap) -> Result<Tenant, Response> {
    let (_user, org) = auth::user_and_org(app, headers).await?;
    app.tenancy.resolve(org.id).await.map_err(|e| match e {
        ResolveError::NotProvisioned | ResolveError::NotActive(_) => {
            (StatusCode::NOT_FOUND, Json(not_found())).into_response()
        }
        ResolveError::Internal(e) => {
            tracing::error!("tenant resolve failed for org {}: {e}", org.id);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(server_error())).into_response()
        }
    })
}

async fn account_scans(State(app): State<App>, headers: HeaderMap) -> Response {
    let tenant = match account_tenant(&app, &headers).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    match tenant.store.list_jobs(50).await {
        Ok(items) => (StatusCode::OK, Json(serde_json::json!({ "items": items }))).into_response(),
        Err(e) => {
            tracing::error!("list_jobs failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(server_error())).into_response()
        }
    }
}

async fn account_scan_detail(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let tenant = match account_tenant(&app, &headers).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    match tenant.store.snapshot(&id).await {
        Ok(Some(v)) => (StatusCode::OK, Json(v)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(not_found())).into_response(),
        Err(e) => {
            tracing::error!("scan snapshot failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(server_error())).into_response()
        }
    }
}

pub(crate) fn not_found() -> serde_json::Value {
    serde_json::json!({ "error": "not found" })
}
pub(crate) fn server_error() -> serde_json::Value {
    serde_json::json!({ "error": "internal error" })
}

#[cfg(test)]
mod tests {
    use super::{
        admin_target_result, csrf_origin_allowed, host_is_allowed, normalize_host, origin_of,
        raw_jobs_enabled,
    };
    use axum::http::HeaderMap;
    use std::collections::HashSet;

    #[test]
    fn host_allowlist_is_structural_and_case_insensitive() {
        let allowed = HashSet::from([
            "cloud.reproit.com".to_string(),
            "ingest.reproit.com".to_string(),
        ]);
        assert!(host_is_allowed(Some("cloud.reproit.com"), &allowed));
        assert!(host_is_allowed(Some("INGEST.REPROIT.COM:443"), &allowed));
        assert!(host_is_allowed(Some("cloud.reproit.com."), &allowed));
        assert!(!host_is_allowed(Some("untrusted.example.net"), &allowed));
        assert!(!host_is_allowed(
            Some("cloud.reproit.com.evil.test"),
            &allowed
        ));
        assert!(!host_is_allowed(None, &allowed));
        assert_eq!(
            normalize_host(" Example.COM:8080 ").as_deref(),
            Some("example.com")
        );
        assert!(host_is_allowed(Some("anything.local"), &HashSet::new()));
    }

    #[test]
    fn origin_of_strips_path_and_normalizes() {
        assert_eq!(
            origin_of("https://cloud.reproit.com/app?x=1#h").as_deref(),
            Some("https://cloud.reproit.com")
        );
        assert_eq!(
            origin_of("HTTP://Cloud.Reproit.COM:8080/").as_deref(),
            Some("http://Cloud.Reproit.COM:8080")
        );
        assert_eq!(origin_of("not-a-url"), None);
        assert_eq!(origin_of("https://"), None);
    }

    #[test]
    fn csrf_allowed_origin_passes() {
        let allowed = vec!["https://cloud.reproit.com".to_string()];
        // Bare origin and a full URL both normalize to the allowed origin.
        assert!(csrf_origin_allowed(
            Some("https://cloud.reproit.com"),
            &allowed
        ));
        assert!(csrf_origin_allowed(
            Some("https://cloud.reproit.com/account/seats"),
            &allowed
        ));
    }

    #[test]
    fn csrf_foreign_origin_rejected() {
        let allowed = vec!["https://cloud.reproit.com".to_string()];
        assert!(!csrf_origin_allowed(Some("https://evil.example"), &allowed));
        // Same host, different scheme/port is still foreign.
        assert!(!csrf_origin_allowed(
            Some("http://cloud.reproit.com"),
            &allowed
        ));
        assert!(!csrf_origin_allowed(
            Some("https://cloud.reproit.com:8443"),
            &allowed
        ));
    }

    #[test]
    fn csrf_missing_origin_passes() {
        let allowed = vec!["https://cloud.reproit.com".to_string()];
        // No Origin/Referer (same-origin navigation, native/CLI client) -> allow.
        assert!(csrf_origin_allowed(None, &allowed));
    }

    #[test]
    fn raw_jobs_are_only_enabled_for_dev_or_self_host() {
        assert!(!raw_jobs_enabled(false, false));
        assert!(raw_jobs_enabled(true, false));
        assert!(raw_jobs_enabled(false, true));
    }

    #[test]
    fn dashboard_never_advertises_retired_cli_commands() {
        let surfaces = [
            include_str!("../static/app.js"),
            include_str!("../static/triage.js"),
            include_str!("../docs/ci/reproit-repro.yml"),
            include_str!("../README.md"),
        ];
        for surface in surfaces {
            assert!(!surface.contains("reproit cloud reproduce"));
            assert!(!surface.contains("reproit cloud pull"));
            assert!(!surface.contains("reproit cloud login"));
            assert!(!surface.contains("reproit check ${job.id}"));
            assert!(!surface.contains("reproit run explore"));
            assert!(!surface.contains("reproit record"));
            assert!(!surface.contains("record --upload"));
        }
        assert!(surfaces[0].contains("reproit ${bktArg}"));
        assert!(!surfaces[0].contains("--app ${app}"));
        assert!(surfaces[2].contains("reproit __cloud-internal __replay-dispatch"));
    }

    #[test]
    fn delete_confirmation_shows_the_case_sensitive_name() {
        let dashboard = include_str!("../static/app.js");
        let styles = include_str!("../static/styles.css");

        assert!(dashboard.contains(r#"class="confirmation-value">${esc(project.name)}</span>"#));
        assert!(dashboard.contains("Capitalization and spacing must match."));
        assert!(dashboard.contains("The value does not match. Copy the name exactly as shown."));
        assert!(styles.contains(".confirmation-value{"));
        assert!(styles.contains("text-transform:none"));
    }

    #[test]
    fn project_deletion_selects_a_surviving_project() {
        let dashboard = include_str!("../static/app.js");

        assert!(dashboard.contains("function projectAfterDeletion(projects, deletedAppId)"));
        assert!(dashboard.contains("const nextProject = projectAfterDeletion("));
        assert!(dashboard.contains("Switched to ${nextProject.name}."));
    }

    #[test]
    fn replay_path_exposes_its_overflow_scrollbar() {
        let styles = include_str!("../static/styles.css");

        assert!(styles.contains(".path-card .bd::-webkit-scrollbar-thumb"));
        assert!(styles.contains("overflow-y:auto"));
        assert!(styles.contains("scrollbar-width:thin"));
    }

    #[test]
    fn admin_target_requires_numeric_header() {
        let headers = HeaderMap::new();
        let err = admin_target_result(&headers).unwrap_err();
        assert!(err.message().contains("X-Reproit-Tenant"));

        let mut headers = HeaderMap::new();
        headers.insert("x-reproit-tenant", "abc".parse().unwrap());
        let err = admin_target_result(&headers).unwrap_err();
        assert!(err.message().contains("numeric"));

        let mut headers = HeaderMap::new();
        headers.insert("x-reproit-tenant", "123".parse().unwrap());
        assert_eq!(admin_target_result(&headers).unwrap(), 123);
    }
}
