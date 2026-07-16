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
mod db;
mod ingest;
mod integrations;
mod jobs;
mod mail;
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
use jobs::{Job, JobSpec};
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
#[command(name = "reproit-cloud", about = "ReproIt cloud control plane")]
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    // Rate limiters (in-memory GCRA; Cloudflare edge rules are the gross-abuse
    // first line). Tight on auth (brute-force / argon2 CPU), looser on ingest.
    // IP-keyed limiters MUST use SmartIpKeyExtractor: behind Fly/Cloudflare the
    // socket peer is the proxy, so the default PeerIpKeyExtractor would collapse
    // every client into one global bucket (an attacker could lock out all logins).
    let auth_rl = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(1)
            .burst_size(10)
            .finish()
            .expect("auth rate-limit config"),
    );
    let ingest_rl = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(BearerKeyExtractor)
            .per_second(50)
            .burst_size(200)
            .finish()
            .expect("ingest rate-limit config"),
    );
    // Job submission is far heavier than ingest (it fans out into shards and
    // spawns the reproit binary per shard), so it gets its OWN, tighter limiter
    // rather than riding the loose ingest one. Modest steady rate + small burst.
    let jobs_rl = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(2)
            .burst_size(10)
            .finish()
            .expect("jobs rate-limit config"),
    );
    // Cookie-authenticated account-mutation + billing-checkout surface. These are
    // session-gated (not brute-force-sensitive like signup/login), so they don't
    // need the 1/s auth bound; but they must not be unbounded. A loose per-IP
    // limit that a real dashboard never approaches yet caps scripted abuse.
    let account_rl = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(5)
            .burst_size(30)
            .finish()
            .expect("account rate-limit config"),
    );

    // Job submission (POST /jobs): heavy + rate-limited on its own limiter, behind
    // the same API-key gate as the rest of the protected surface. The handler
    // additionally rejects raw-path submissions unless this process is running in
    // local dev or self-host mode.
    let jobs_submit = Router::new()
        .route("/jobs", post(submit_job))
        .layer(GovernorLayer { config: jobs_rl })
        .route_layer(middleware::from_fn_with_state(app.clone(), require_api_key));

    // Telemetry ingest: the ONLY route a publishable (pk_live_) key may reach, so
    // the browser SDK can append events without carrying a key that can read or
    // export. Secret + admin keys work too (server-side callers). Same loose
    // ingest limiter as the read surface.
    let ingest = Router::new()
        .route(backend_contract::INGEST_EVENTS, post(ingest::post_events))
        .layer(GovernorLayer {
            config: ingest_rl.clone(),
        })
        .route_layer(middleware::from_fn_with_state(
            app.clone(),
            require_ingest_key,
        ));

    // API-key-protected surface: bucket replay packages + reads + export + job
    // status. `require_api_key` fails closed (401) unless a valid SECRET/admin key
    // is present, and rejects publishable keys (403).
    let protected = Router::new()
        .route("/jobs/:id", get(get_job))
        // Minimal auth probe: `reproit login --key ...` hits this to validate a key
        // (resolves the tenant, returns { orgId, projects }), no app id needed.
        .route(backend_contract::GET_ME, get(ingest::get_me))
        .route("/v1/buckets/:bucket", get(ingest::get_bucket_global))
        .route("/v1/graph/:app", get(ingest::get_graph))
        .route("/v1/errors/:app", get(ingest::get_errors))
        .route("/v1/errors/:app/cohorts", get(ingest::get_cohorts))
        // Stable, content-addressed buckets are the public replay package API:
        // indices shift as new errors arrive, bucket ids do not.
        .route("/v1/apps/:app/buckets", get(ingest::get_buckets))
        // Mint/rotate the write-only browser key from an authenticated secret
        // key. This lets account setup obtain SDK credentials without
        // ever putting the management key in application code.
        .route(
            "/v1/apps/:app/publishable-key",
            post(ingest::post_publishable_key),
        )
        // Per-app tracker + dispatch config (tokens write-only, encrypted at rest).
        .route(
            "/v1/apps/:app/integrations",
            get(integrations::get_integration).put(integrations::put_integration),
        )
        .route("/v1/apps/:app/buckets/:bucket", get(ingest::get_bucket))
        .route(
            backend_contract::RECORD_REPLAY,
            post(ingest::post_replay_results).get(ingest::get_replay_results),
        )
        // Hosted reproduction: fire repository_dispatch into the customer's CI
        // (202 + run id); the run history for the bucket.
        .route(
            "/v1/apps/:app/buckets/:bucket/reproduce",
            post(ingest::post_reproduce),
        )
        .route(
            "/v1/apps/:app/buckets/:bucket/runs",
            get(ingest::get_cloud_runs),
        )
        .route(
            "/v1/apps/:app/buckets/:bucket/evidence",
            post(ingest::post_bucket_evidence).get(ingest::get_bucket_evidence),
        )
        // Read the bucket<->ticket link, or set it explicitly (file/relink the
        // issue). Opt-in: POST is a no-op unless the app has a tracker configured.
        .route(
            "/v1/apps/:app/buckets/:bucket/ticket",
            get(ingest::get_ticket).post(ingest::post_ticket),
        )
        // The tenant PORTABILITY export (GDPR article 20; the read counterpart
        // the offboard deletion assumes exists): stream everything the cloud
        // holds for one app as newline-delimited JSON (bucket triage metadata,
        // error rows within retention, evidence blob keys).
        .route("/v1/apps/:app/export", get(ingest::get_export))
        .route("/v1/blob/*key", get(ingest::get_blob))
        .layer(GovernorLayer { config: ingest_rl })
        .route_layer(middleware::from_fn_with_state(app.clone(), require_api_key));

    // Worker fleet surface: remote workers claim shards + report results. Gated
    // by a SEPARATE worker token (REPROIT_WORKER_TOKEN), not user API keys.
    let worker_api = Router::new()
        .route("/v1/worker/claim", post(jobs::worker::claim))
        .route(
            "/v1/worker/shards/:id/heartbeat",
            post(jobs::worker::heartbeat),
        )
        .route("/v1/worker/shards/:id/result", post(jobs::worker::result))
        .route_layer(middleware::from_fn_with_state(
            app.clone(),
            require_worker_token,
        ));

    // === Self-serve account surface, split by protection profile ===

    // (1) Brute-force-sensitive auth: signup/login + the google/sso start+callback.
    // The tight 1/s `auth_rl` limiter is applied as a `route_layer`, so it wraps
    // EVERY route on this sub-router and a future route added here is covered
    // automatically (no fragile "before/after .layer()" ordering to misread).
    let auth_routes = Router::new()
        .route(backend_contract::SIGNUP, post(auth::signup))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/cli/device", post(auth::cli_device))
        .route("/auth/cli/token", post(auth::cli_token))
        .route("/auth/invitations/preview", get(auth::invitation_preview))
        // Email flows: verification (the signup link) + password reset. All
        // token-bearing and unauthenticated, so they belong on the tight limiter.
        .route_layer(GovernorLayer { config: auth_rl });

    // (2) Cookie-authenticated mutation + billing-checkout surface. Cookie-auth'd
    // inside the handlers (unchanged), Json<T> extractors, plus the loose
    // `account_rl` limiter (route_layer = all routes wrapped) AND the Origin/Referer
    // CSRF defense-in-depth middleware. The CSRF check is a no-op when
    // REPROIT_PUBLIC_URL is unset (dev). OAuth GET callbacks live on `auth_routes`
    // above, NOT here, so the CSRF guard never touches them.
    let account_mut = Router::new()
        .route("/account/me", get(auth::me))
        .route("/account/usage", get(auth::usage))
        .route(backend_contract::CREATE_PROJECT, post(auth::create_project))
        .route("/auth/cli/approve", post(auth::cli_approve))
        .route(
            "/account/projects/:app/publishable-key",
            post(auth::rotate_publishable_key),
        )
        .route("/account/orgs/active", post(auth::set_active_org))
        .route("/account/orgs/name", post(auth::rename_org))
        .route("/account/invitations", post(auth::invite_member))
        .route("/account/invitations/accept", post(auth::accept_invitation))
        .route("/account/invitations/resend", post(auth::resend_invitation))
        .route("/account/invitations/revoke", post(auth::revoke_invitation))
        .route("/account/members", post(auth::add_member))
        .route("/account/members/remove", post(auth::remove_member))
        .route("/account/members/role", post(auth::set_member_role))
        .route("/account/seats", post(auth::set_seat))
        .route("/account/scans", get(account_scans))
        .route("/account/scans/:id", get(account_scan_detail))
        // The per-seat triage/management surface (the dashboard, not the engine):
        // cookie-authenticated AND seat-gated inside the handlers (a member without
        // a seat gets 402; the free CLI never reaches these). Triage state on a
        // bucket, plus the "grab a bug" detail read model.
        .route(
            "/v1/apps/:app/buckets/:bucket/triage",
            get(triage::get_triage).post(triage::post_triage),
        )
        .route(
            "/v1/apps/:app/dashboard/buckets",
            get(triage::get_dashboard_buckets),
        )
        .route(
            "/v1/apps/:app/buckets/:bucket/detail",
            get(triage::get_bucket_detail),
        )
        .route(
            "/v1/apps/:app/buckets/:bucket/sample",
            axum::routing::delete(triage::delete_sample_bucket),
        )
        // The per-bucket occurrence time-series (segmented by build) the dashboard
        // graphs, plus the computed prod-evidence resolution.
        .route(
            "/v1/apps/:app/buckets/:bucket/timeline",
            get(triage::get_bucket_timeline),
        )
        // The proactive alert feed: recent prod-truth transitions the background
        // sweep recorded (the "regressed 2h ago" signal). Seat-gated like the rest.
        .route(
            "/v1/apps/:app/resolution-events",
            get(triage::get_resolution_events),
        )
        .route_layer(GovernorLayer { config: account_rl })
        .route_layer(middleware::from_fn(csrf_origin_check));

    // (4) Public, unauthenticated, no-mutation endpoints + static dashboard assets.
    // No limiter needed (static GETs / a redirect / a config read).
    let public_routes = Router::new()
        .route("/", get(|| async { Redirect::to("/app") }))
        .route("/auth/config", get(auth::auth_config))
        .route(
            "/signup",
            get(|| async { Html(include_str!("../static/signup.html")) }),
        )
        .route(
            "/login",
            get(|| async { Html(include_str!("../static/login.html")) }),
        )
        .route(
            "/cli",
            get(|| async { Html(include_str!("../static/cli.html")) }),
        )
        .route(
            "/invite",
            get(|| async { Html(include_str!("../static/invite.html")) }),
        )
        // Auth-page scripts live in files (not inline) so the CSP can stay
        // `script-src 'self'` with no nonces.
        .route(
            "/login.js",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/javascript")],
                    include_str!("../static/login.js"),
                )
            }),
        )
        .route(
            "/cli.js",
            get(|| async {
                (
                    [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
                    include_str!("../static/cli.js"),
                )
            }),
        )
        .route(
            "/signup.js",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/javascript")],
                    include_str!("../static/signup.js"),
                )
            }),
        )
        .route(
            "/invite.js",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/javascript")],
                    include_str!("../static/invite.js"),
                )
            }),
        )
        .route(
            "/app",
            get(|| async { Html(include_str!("../static/app.html")) }),
        )
        // The dashboard's static assets (referenced relatively by app.html, so
        // they resolve to /app.js and /styles.css). Served same-origin so the
        // SPA hits this cloud's /v1 API with no CORS.
        .route(
            "/app.js",
            get(|| async {
                (
                    [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
                    include_str!("../static/app.js"),
                )
            }),
        )
        .route(
            "/selects.js",
            get(|| async {
                (
                    [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
                    include_str!("../static/selects.js"),
                )
            }),
        )
        // The per-seat triage product's view module (bug list + grab-a-bug +
        // triage controls + seat management). Loaded by app.html after app.js.
        .route(
            "/triage.js",
            get(|| async {
                (
                    [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
                    include_str!("../static/triage.js"),
                )
            }),
        )
        .route(
            "/styles.css",
            get(|| async {
                (
                    [(CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../static/styles.css"),
                )
            }),
        )
        .route(
            "/favicon.svg",
            get(|| async {
                (
                    [(CONTENT_TYPE, "image/svg+xml")],
                    include_str!("../static/favicon.svg"),
                )
            }),
        )
        // The bundled NimbusShop sample: a polished storefront with one planted
        // checkout crash and the web SDK wired to THIS cloud. Onboarding opens it with the new
        // project's ?appId=&key= so a first-run user watches a real crash flow
        // into their dashboard before pointing the SDK at their own app. Served
        // same-origin so the SDK's /v1/events POST needs no CORS.
        .route(
            "/demo",
            get(|| async { Html(include_str!("../static/demo/index.html")) }),
        )
        .route(
            "/demo/app.js",
            get(|| async {
                (
                    [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
                    include_str!("../static/demo/app.js"),
                )
            }),
        )
        .route(
            "/demo/reproit-web.js",
            get(|| async {
                (
                    [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
                    include_str!("../static/demo/reproit-web.js"),
                )
            }),
        )
        .route(
            "/demo/styles.css",
            get(|| async {
                (
                    [(CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../static/demo/styles.css"),
                )
            }),
        );

    let router = Router::new()
        // Liveness: process is up. Readiness: Postgres is reachable.
        .route("/health", get(|| async { "ok" }))
        .route("/ready", get(ready))
        .merge(auth_routes)
        .merge(account_mut)
        .merge(public_routes)
        .merge(jobs_submit)
        .merge(ingest)
        .merge(protected)
        .merge(worker_api)
        // Cap request bodies (multipart evidence + JSON) to defang memory-DoS.
        .layer(DefaultBodyLimit::max(32 * 1024 * 1024))
        .layer(cors_layer())
        // Defense-in-depth response headers on every response (outermost).
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(request_metrics))
        // Outermost: reject Fly's automatic hostname before auth, routing, or DB
        // work. Fly health checks explicitly send an allowed Host header.
        .layer(middleware::from_fn(allowed_host))
        .with_state(app);
    let router = if backend_contract::enabled() {
        tracing::warn!("experimental backend contract capture enabled");
        router.layer(middleware::from_fn(backend_contract::capture))
    } else {
        router
    };

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

fn configured_allowed_hosts() -> &'static HashSet<String> {
    ALLOWED_HOSTS.get_or_init(|| {
        std::env::var("REPROIT_ALLOWED_HOSTS")
            .unwrap_or_default()
            .split(',')
            .filter_map(normalize_host)
            .collect()
    })
}

fn normalize_host(value: &str) -> Option<String> {
    let host = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }

    // Host may carry a port. Preserve bracketed IPv6 while stripping its port;
    // hostname allowlists normally contain only DNS names.
    let host = if host.starts_with('[') {
        host.find(']')
            .map(|end| host[..=end].to_string())
            .unwrap_or(host)
    } else {
        host.split_once(':')
            .map(|(name, _)| name.to_string())
            .unwrap_or(host)
    };
    Some(host)
}

fn host_is_allowed(host: Option<&str>, allowed: &HashSet<String>) -> bool {
    allowed.is_empty()
        || host
            .and_then(normalize_host)
            .is_some_and(|host| allowed.contains(&host))
}

async fn allowed_host(request: Request, next: Next) -> Response {
    let host = request.headers().get(HOST).and_then(|v| v.to_str().ok());
    if !host_is_allowed(host, configured_allowed_hosts()) {
        tracing::warn!(
            host = host.unwrap_or("<missing>"),
            "rejected unrecognized host"
        );
        return (
            StatusCode::MISDIRECTED_REQUEST,
            Json(serde_json::json!({ "error": "not found" })),
        )
            .into_response();
    }
    next.run(request).await
}

/// Readiness probe: 200 only when the CONTROL plane answers (the dependency on the
/// critical path of every request: resolve tenant). Tenant DBs are checked lazily
/// on resolve. `/health` stays liveness.
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

/// Constant-time byte compare (length is allowed to leak; token contents aren't).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BearerError {
    Missing,
    Malformed,
}

fn bearer(req: &Request) -> Result<String, BearerError> {
    let Some(raw) = req.headers().get(AUTHORIZATION) else {
        return Err(BearerError::Missing);
    };
    let raw = raw.to_str().map_err(|_| BearerError::Malformed)?;
    let Some(token) = raw.strip_prefix("Bearer ") else {
        return Err(BearerError::Malformed);
    };
    if token.trim().is_empty() {
        return Err(BearerError::Malformed);
    }
    Ok(token.to_string())
}

fn auth_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

fn api_auth_error(bearer: &Result<String, BearerError>) -> Response {
    let msg = match bearer {
        Err(BearerError::Missing) => {
            "missing Authorization header: send `Authorization: Bearer <api key>` using an org API key (`sk_live_...`) or the configured `REPROIT_API_KEY` admin token"
        }
        Err(BearerError::Malformed) => {
            "invalid Authorization header: expected `Authorization: Bearer <api key>`; do not include quotes, prefixes other than Bearer, or redacted tokens"
        }
        Ok(_) => {
            "invalid API key: use an active org API key (`sk_live_...`) or the server's configured `REPROIT_API_KEY` admin token"
        }
    };
    auth_error(StatusCode::UNAUTHORIZED, msg)
}

fn worker_auth_error(server_configured: bool, bearer: &Result<String, BearerError>) -> Response {
    let (status, msg) = if !server_configured {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "worker auth is not configured on this server: set `REPROIT_WORKER_TOKEN` and send it as `Authorization: Bearer <worker token>`",
        )
    } else {
        match bearer {
            Err(BearerError::Missing) => (
                StatusCode::UNAUTHORIZED,
                "missing Authorization header: worker requests must send `Authorization: Bearer <worker token>` matching `REPROIT_WORKER_TOKEN`",
            ),
            Err(BearerError::Malformed) => (
                StatusCode::UNAUTHORIZED,
                "invalid Authorization header: expected `Authorization: Bearer <worker token>` for the worker API",
            ),
            Ok(_) => (
                StatusCode::UNAUTHORIZED,
                "invalid worker token: send the exact `REPROIT_WORKER_TOKEN` value as `Authorization: Bearer <worker token>`",
            ),
        }
    };
    auth_error(status, msg)
}

/// Gate the protected API. FAILS CLOSED: a request with no valid credential is
/// 401, never silently open. A bearer token passes if it is the shared admin key
/// (constant-time compare) OR a valid per-org key; the resolved `AuthCtx` is put
/// in request extensions so handlers scope data to the caller's org. The only
/// way to run open is the explicit `REPROIT_DEV_OPEN=1` (local dev), which grants
/// Admin scope, never a default.
async fn require_api_key(
    State(app): State<App>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    // The powerful surface (reads, export, dispatch, job status): secret keys and
    // the admin key only. Publishable (pk_live_) keys are rejected here.
    resolve_api_auth(app, req, next, false).await
}

/// Ingest gate for `POST /v1/events`: like `require_api_key` but ALSO accepts a
/// publishable (`pk_live_`) key, since that is the browser-safe, write-only key
/// the SDK ships. Secret keys and the admin key work too (server-side callers).
async fn require_ingest_key(
    State(app): State<App>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    resolve_api_auth(app, req, next, true).await
}

/// Shared resolver for the two API gates. Fails closed. A publishable key is
/// accepted only when `allow_publishable` (the ingest route); on every other route
/// it is rejected with 403 BEFORE the `dev_open` fallback, so a browser-shipped
/// key can never read or export the tenant's data even in local-dev-open mode.
async fn resolve_api_auth(
    app: App,
    mut req: Request,
    next: Next,
    allow_publishable: bool,
) -> Result<Response, Response> {
    let shared = std::env::var("REPROIT_API_KEY")
        .ok()
        .filter(|k| !k.is_empty());
    let token = bearer(&req);

    if let (Some(shared), Ok(token)) = (&shared, &token) {
        if ct_eq(shared.as_bytes(), token.as_bytes()) {
            // Admin-key traffic is rare and all-powerful (it can address any
            // tenant via X-Reproit-Tenant), so every request is audited.
            let target = req
                .headers()
                .get("x-reproit-tenant")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<i64>().ok());
            app.control
                .audit(
                    "admin-key",
                    "admin.request",
                    target,
                    serde_json::json!({ "method": req.method().as_str(), "path": req.uri().path() }),
                )
                .await;
            req.extensions_mut().insert(AuthCtx::Admin);
            req.extensions_mut().insert(KeyScope::OPEN);
            return Ok(next.run(req).await);
        }
    }
    if let Ok(token) = &token {
        // Scope gate: a publishable key is write-only. Reject it on every route
        // but ingest, BEFORE the dev_open fallback, so a browser-shipped pk_live_
        // can never read or export tenant data (even locally).
        if !allow_publishable && auth::is_publishable(token) {
            return Err(auth_error(
                StatusCode::FORBIDDEN,
                "publishable keys (pk_live_) may only POST /v1/events; use a secret key (sk_live_) for this endpoint",
            ));
        }
        // API-key revocation and expiry must be enforced at request time. This is
        // a tiny control-plane lookup; if it ever becomes hot enough to cache,
        // the cache needs explicit invalidation on key revoke/rotate.
        match app.control.org_for_api_key(token).await {
            Ok(Some((org_id, project_id, created_by))) => {
                req.extensions_mut().insert(AuthCtx::Org(org_id));
                req.extensions_mut().insert(KeyScope {
                    project_id,
                    user_id: created_by,
                    publishable: auth::is_publishable(token),
                });
                return Ok(next.run(req).await);
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!("api key lookup failed: {e}");
                return Err(auth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not validate API key: check control database connectivity/config (`DATABASE_URL`) and retry",
                ));
            }
        }
    }
    if dev_open() {
        req.extensions_mut().insert(AuthCtx::Admin);
        req.extensions_mut().insert(KeyScope::OPEN);
        return Ok(next.run(req).await);
    }
    Err(api_auth_error(&token))
}

/// Gate the worker fleet API with the shared worker token (constant-time). Fails
/// closed unless `REPROIT_DEV_OPEN=1`. `REPROIT_WORKER_TOKEN` accepts a
/// comma-separated list so a token can rotate with zero downtime: deploy with
/// `old,new`, roll the fleet to `new`, then drop `old`.
async fn require_worker_token(req: Request, next: Next) -> Result<Response, Response> {
    let want: Vec<String> = std::env::var("REPROIT_WORKER_TOKEN")
        .unwrap_or_default()
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    let token = bearer(&req);
    if let Ok(token) = &token {
        // Check every candidate (no early exit) to keep the compare constant-time
        // in the number of configured tokens.
        let mut ok = false;
        for w in &want {
            ok |= ct_eq(w.as_bytes(), token.as_bytes());
        }
        if ok {
            return Ok(next.run(req).await);
        }
    }
    if dev_open() {
        return Ok(next.run(req).await);
    }
    Err(worker_auth_error(!want.is_empty(), &token))
}

/// Offboard one tenant end to end (the Cmd::Offboard body): data plane first
/// (database at the provider, blobs under the scope), control plane last, so a
/// crash mid-way leaves a re-runnable half (the command is idempotent).
async fn run_offboard(
    app: &App,
    blobs: &tenancy::blob::Blobs,
    org_id: i64,
    yes: bool,
) -> anyhow::Result<()> {
    if !yes {
        anyhow::bail!(
            "offboard permanently deletes org {org_id}'s database, blobs, keys and members; re-run with --yes to confirm"
        );
    }
    if app.self_hosted {
        anyhow::bail!(
            "offboard is a hosted (multi-tenant) operation; self-host owns its one database"
        );
    }
    let scope = app
        .control
        .all_tenants()
        .await?
        .into_iter()
        .find(|t| t.org_id == org_id)
        .map(|t| t.blob_scope)
        .unwrap_or_else(|| format!("t/{org_id}"));
    app.tenancy.deprovision(org_id).await?;
    tracing::info!("offboard: org {org_id} database deprovisioned");
    match blobs.delete_scope(&scope).await {
        Ok(n) => tracing::info!("offboard: blob scope {scope} cleared ({n} object(s)/tree)"),
        Err(e) => {
            tracing::warn!("offboard: blob scope {scope} cleanup failed (re-run to retry): {e}")
        }
    }
    let deleted = app.control.delete_org(org_id).await?;
    app.control
        .audit(
            "ops",
            "org.offboard",
            Some(org_id),
            serde_json::json!({ "deleted": deleted }),
        )
        .await;
    tracing::info!("offboard: org {org_id} removed from the control plane (existed: {deleted})");
    Ok(())
}

/// Suspend or resume one tenant (Cmd::Suspend / Cmd::Resume): flip the registry
/// status the resolver serves by. Suspension is reversible (database and blobs
/// intact), but it takes the tenant's ingest and dashboard down, so it demands
/// --yes; resume never does. Audited like every ops action.
async fn run_set_tenant_status(
    app: &App,
    org_id: i64,
    status: db::TenantStatus,
    yes: bool,
) -> anyhow::Result<()> {
    let verb = match status {
        db::TenantStatus::Suspended => "suspend",
        _ => "resume",
    };
    if status == db::TenantStatus::Suspended && !yes {
        anyhow::bail!(
            "suspend takes org {org_id} out of service (ingest + dashboard refuse) until `resume`; re-run with --yes to confirm"
        );
    }
    let Some(current) = app.control.tenant(org_id).await? else {
        anyhow::bail!("org {org_id} has no tenant record; nothing to {verb}");
    };
    if current.status == status {
        tracing::info!("{verb}: org {org_id} is already {}", status.as_str());
        return Ok(());
    }
    app.control.set_tenant_status(org_id, status).await?;
    // The resolver caches mappings briefly (TTL backstop), so the flip takes
    // effect within the cache window on running instances; audit the change.
    app.control
        .audit(
            "ops",
            match status {
                db::TenantStatus::Suspended => "org.suspend",
                _ => "org.resume",
            },
            Some(org_id),
            serde_json::json!({ "from": current.status.as_str(), "to": status.as_str() }),
        )
        .await;
    tracing::info!(
        "{verb}: org {org_id} {} -> {}",
        current.status.as_str(),
        status.as_str()
    );
    Ok(())
}

/// List every tenant in the registry (Cmd::Tenants) as an aligned table: the
/// ops "what is this installation" read. The name lives on `orgs`; a tenant row
/// whose org is gone prints a placeholder rather than erroring the whole list.
async fn run_list_tenants(app: &App) -> anyhow::Result<()> {
    let tenants = app.control.all_tenants().await?;
    let mut rows: Vec<[String; 4]> = Vec::with_capacity(tenants.len());
    for t in &tenants {
        let name = app
            .control
            .org_name(t.org_id)
            .await?
            .unwrap_or_else(|| "<no org row>".to_string());
        rows.push([
            t.org_id.to_string(),
            name,
            t.status.as_str().to_string(),
            "self-hosted".to_string(),
        ]);
    }
    app.control
        .audit(
            "ops",
            "ops.tenants",
            None,
            serde_json::json!({ "count": rows.len() }),
        )
        .await;
    print_table(["ORG", "NAME", "STATUS", "EDITION"], &rows);
    Ok(())
}

/// Print an aligned four-column table (header + rows) for the ops subcommands.
/// Plain spaces-and-padding, no table crate: the output is for a human at a
/// terminal and for `grep`, nothing else.
fn print_table(header: [&str; 4], rows: &[[String; 4]]) {
    let mut w = header.map(str::len);
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            w[i] = w[i].max(cell.len());
        }
    }
    println!(
        "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}",
        header[0],
        header[1],
        header[2],
        header[3],
        w0 = w[0],
        w1 = w[1],
        w2 = w[2],
        w3 = w[3]
    );
    for row in rows {
        println!(
            "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}",
            row[0],
            row[1],
            row[2],
            row[3],
            w0 = w[0],
            w1 = w[1],
            w2 = w[2],
            w3 = w[3]
        );
    }
}

/// Print an org's recent audit rows, newest first (Cmd::Audit). The read query
/// this drives (`audit_for_org`) is the audit table's first reader; until now
/// it was write-only and inspectable only via psql.
async fn run_audit(app: &App, org_id: i64, limit: i64) -> anyhow::Result<()> {
    let rows = app.control.audit_for_org(org_id, limit.max(1)).await?;
    // Reading the trail is itself an admin action worth a trace (matches the
    // admin-key HTTP surface, where even reads are audited).
    app.control
        .audit(
            "ops",
            "org.audit_read",
            Some(org_id),
            serde_json::json!({ "limit": limit, "returned": rows.len() }),
        )
        .await;
    if rows.is_empty() {
        println!("no audit rows for org {org_id}");
        return Ok(());
    }
    for r in &rows {
        println!("{}  {:<12}  {:<24}  {}", r.at, r.actor, r.action, r.detail);
    }
    Ok(())
}

/// Requeue one tenant's stranded shards on demand (Cmd::Requeue): the same
/// logic the minutely background sweep runs (stale threshold included), for
/// when ops shouldn't wait for the next tick. Re-marks the control-plane
/// pending hint exactly like the sweep does, so requeued shards are claimable
/// immediately (the under-inclusion invariant on `tenant_pending_shards`).
async fn run_requeue(app: &App, org_id: i64) -> anyhow::Result<()> {
    let tenant = app
        .tenancy
        .resolve(org_id)
        .await
        .map_err(|e| anyhow::anyhow!("cannot resolve tenant {org_id}: {e}"))?;
    let n = tenant.store.requeue_stranded(120).await?;
    if n >= 1 {
        app.control.mark_tenant_pending(org_id).await?;
    }
    app.control
        .audit(
            "ops",
            "org.requeue",
            Some(org_id),
            serde_json::json!({ "requeued": n }),
        )
        .await;
    tracing::info!("requeue: org {org_id} requeued {n} stranded shard(s)");
    Ok(())
}

/// One tenant's retention pass: delete evidence BLOBS for errors past the
/// plan's retention window, then their rows, then the error rows themselves
/// (evidence-first so a crash can only leave re-processable rows behind, never
/// orphaned customer bytes in object storage). Batched; errors are logged and
/// retried on the next hourly pass.
#[allow(dead_code)] // Enabled when an operator configures a retention policy.
async fn retention_pass(tenant: &tenancy::resolver::Tenant, org_id: i64, days: i64) {
    let mut blobs_deleted = 0u64;
    loop {
        let batch = match tenant.store.expired_evidence_keys(days, 500).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("retention: expired_evidence_keys for tenant {org_id}: {e}");
                return;
            }
        };
        if batch.is_empty() {
            break;
        }
        let n = batch.len();
        let mut deletable = Vec::with_capacity(n);
        for (id, key) in batch {
            match tenant.blobs.delete(&key).await {
                Ok(()) => deletable.push(id),
                // Keep the row so the next pass retries this blob.
                Err(e) => tracing::warn!("retention: blob delete {key} for tenant {org_id}: {e}"),
            }
        }
        blobs_deleted += deletable.len() as u64;
        if let Err(e) = tenant.store.delete_evidence_rows(&deletable).await {
            tracing::warn!("retention: delete_evidence_rows for tenant {org_id}: {e}");
            return;
        }
        if deletable.is_empty() || n < 500 {
            break;
        }
    }
    let mut errors_deleted = 0u64;
    loop {
        match tenant.store.delete_expired_errors(days, 5000).await {
            Ok(n) => {
                errors_deleted += n;
                if n < 5000 {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!("retention: delete_expired_errors for tenant {org_id}: {e}");
                return;
            }
        }
    }
    if blobs_deleted > 0 || errors_deleted > 0 {
        tracing::info!(
            "retention: tenant {org_id} pruned {errors_deleted} error(s), {blobs_deleted} evidence blob(s) past {days}d"
        );
    }
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

/// Defense-in-depth response headers on every response. HSTS forces HTTPS,
/// nosniff stops content-type sniffing (matters for served evidence blobs),
/// frame DENY blocks clickjacking, referrer-policy limits URL leakage. (CSP is
/// intentionally omitted here: the dashboard uses inline scripts, so a strict
/// policy needs nonces + dashboard testing, a follow-up.)
/// Per-request metrics: one counter + one latency histogram, labeled by method
/// and status class. Registered app-wide alongside the security headers.
async fn request_metrics(req: Request, next: Next) -> Response {
    let method = req.method().as_str().to_string();
    let started = std::time::Instant::now();
    let resp = next.run(req).await;
    let status = resp.status().as_u16();
    let class = match status {
        100..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    };
    metrics::counter!("http_requests_total", "method" => method.clone(), "class" => class)
        .increment(1);
    metrics::histogram!("http_request_duration_seconds", "method" => method, "class" => class)
        .record(started.elapsed().as_secs_f64());
    resp
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    h.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    h.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    // Scripts are same-origin files only (the auth pages' former inline blocks
    // now live in /login.js etc., so no nonces needed). Styles allow inline
    // (the pages carry their own <style> blocks) plus Google Fonts; images
    // allow data: (the inline SVG favicons).
    h.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
        ),
    );
    resp
}

/// The set of origins a state-changing cookie-auth request is allowed to come
/// from: the dashboard's own origin (derived from `REPROIT_PUBLIC_URL`) plus any
/// explicitly configured CORS origins (`REPROIT_CORS_ORIGINS`). Returns `None`
/// when `REPROIT_PUBLIC_URL` is unset (dev): the caller then no-ops the check so
/// local development never breaks.
fn csrf_allowed_origins() -> Option<Vec<String>> {
    // Unset (or empty) public URL == dev: don't enforce. (REPROIT_CORS_ORIGINS
    // alone is not enough to turn the check on; the canonical dashboard origin is
    // the anchor and is required.)
    let public = std::env::var("REPROIT_PUBLIC_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())?;
    let mut allowed: Vec<String> = Vec::new();
    if let Some(o) = origin_of(public.trim()) {
        allowed.push(o);
    }
    // Also trust the configured CORS allowlist (already first-party origins the
    // SPA may be served from), normalized to scheme://host[:port].
    if let Ok(list) = std::env::var("REPROIT_CORS_ORIGINS") {
        for raw in list.split(',') {
            if let Some(o) = origin_of(raw.trim()) {
                if !allowed.contains(&o) {
                    allowed.push(o);
                }
            }
        }
    }
    Some(allowed)
}

/// Normalize a URL string to its origin form `scheme://host[:port]` (lowercased
/// scheme+host, no path/query/fragment, no trailing slash) so an `Origin` header
/// can be compared exactly. Returns `None` for input without a recognizable
/// `scheme://host`.
fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() || rest.is_empty() {
        return None;
    }
    // Authority ends at the first '/', '?' or '#'.
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|a| !a.is_empty())?;
    Some(format!("{}://{}", scheme.to_ascii_lowercase(), authority))
}

/// CSRF defense-in-depth for the cookie-auth account/billing mutation surface.
/// `Json<T>` extractors + `SameSite=Lax` cookies + the CORS allowlist already
/// mean a cross-site form POST can't reach these handlers; this adds a cheap
/// Origin/Referer allowlist on top.
///
/// Policy (only for unsafe methods POST/PUT/PATCH/DELETE):
/// - No `Origin`/`Referer` header at all -> PASS (same-origin navigations and
///   native/CLI clients legitimately omit it).
/// - `Origin` (or, if absent, `Referer`) present AND its origin is in the allowed
///   set -> PASS.
/// - Present but foreign -> 403.
///
/// If `REPROIT_PUBLIC_URL` is unset (dev) the check no-ops so local dev (and the
/// same-origin SPA hitting localhost) is never broken. Safe methods always pass.
async fn csrf_origin_check(req: Request, next: Next) -> Result<Response, StatusCode> {
    // Only state-changing methods are CSRF-relevant; GET/HEAD/OPTIONS pass through.
    let unsafe_method = matches!(
        *req.method(),
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );
    if !unsafe_method {
        return Ok(next.run(req).await);
    }
    // Dev (no public URL configured): don't enforce, never break local dev.
    let Some(allowed) = csrf_allowed_origins() else {
        return Ok(next.run(req).await);
    };
    // Prefer Origin; fall back to the Referer's origin. Absent both -> same-origin
    // navigation or a non-browser client -> allow.
    let claimed = req
        .headers()
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            req.headers()
                .get(axum::http::header::REFERER)
                .and_then(|v| v.to_str().ok())
                .and_then(origin_of)
        });
    if csrf_origin_allowed(claimed.as_deref(), &allowed) {
        Ok(next.run(req).await)
    } else {
        tracing::warn!("CSRF: rejecting cookie-auth mutation from foreign origin {claimed:?}");
        Err(StatusCode::FORBIDDEN)
    }
}

/// Pure decision for `csrf_origin_check`: given the request's claimed origin (the
/// `Origin` header, or the `Referer`'s origin) and the allowed-origin set, decide
/// whether to permit the unsafe request. `None` (no Origin/Referer) always passes
/// (same-origin navigation / native client); a present origin must match the set.
fn csrf_origin_allowed(claimed: Option<&str>, allowed: &[String]) -> bool {
    match claimed {
        None => true,
        Some(o) => {
            let normalized = origin_of(o).unwrap_or_else(|| o.to_string());
            allowed.iter().any(|a| a == &normalized)
        }
    }
}

/// CORS for the API. Production REQUIRES an explicit allowlist
/// (`REPROIT_CORS_ORIGINS`, comma-separated); only `REPROIT_DEV_OPEN=1` permits
/// the any-origin fallback. An empty/missing allowlist in prod means "no
/// cross-origin", safer than silently allowing everyone.
fn cors_layer() -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE]);
    let list = std::env::var("REPROIT_CORS_ORIGINS")
        .ok()
        .filter(|s| !s.trim().is_empty());
    match list {
        Some(list) => {
            let origins: Vec<HeaderValue> = list
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .filter_map(|o| match HeaderValue::from_str(o) {
                    Ok(v) => Some(v),
                    Err(_) => {
                        tracing::warn!("ignoring invalid CORS origin: {o:?}");
                        None
                    }
                })
                .collect();
            tracing::info!("CORS allowlist: {} origin(s)", origins.len());
            base.allow_origin(AllowOrigin::list(origins))
        }
        None if dev_open() => {
            tracing::warn!("REPROIT_DEV_OPEN: allowing ANY CORS origin (dev only)");
            base.allow_origin(AllowOrigin::any())
        }
        None => {
            tracing::warn!("REPROIT_CORS_ORIGINS unset: no cross-origin allowed");
            base
        }
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

async fn account_tenant(app: &App, headers: &HeaderMap) -> Result<Tenant, Response> {
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
        ];
        for surface in surfaces {
            assert!(!surface.contains("reproit cloud reproduce"));
            assert!(!surface.contains("reproit cloud pull"));
            assert!(!surface.contains("reproit cloud login"));
            assert!(!surface.contains("reproit check ${job.id}"));
        }
        assert!(surfaces[0].contains("reproit ${bktArg}"));
        assert!(!surfaces[0].contains("--app ${app}"));
        assert!(surfaces[2].contains("reproit __cloud-internal __replay-dispatch"));
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
