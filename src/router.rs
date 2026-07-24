//! HTTP route composition and per-surface protection profiles.

use crate::*;

/// One embedded static asset served verbatim: (route path, content type,
/// body). Editions differ in which pages exist (capture review pages here,
/// a reset page hosted-side), so the whole static surface is data.
pub type StaticAsset = (&'static str, &'static str, &'static str);

/// The self-host edition's static surface: auth pages, the dashboard SPA,
/// capture review pages, and the bundled NimbusShop demo. All embedded at
/// compile time; an overlay edition supplies its own table.
pub const SELF_HOST_ASSETS: &[StaticAsset] = &[
    ("/signup", HTML, include_str!("../static/signup.html")),
    ("/login", HTML, include_str!("../static/login.html")),
    ("/cli", HTML, include_str!("../static/cli.html")),
    (
        "/capture-upload/:token",
        HTML,
        include_str!("../static/capture-upload.html"),
    ),
    (
        "/captures/:id",
        HTML,
        include_str!("../static/capture.html"),
    ),
    ("/invite", HTML, include_str!("../static/invite.html")),
    // Auth-page scripts live in files (not inline) so the CSP can stay
    // `script-src 'self'` with no nonces.
    ("/login.js", JS_PLAIN, include_str!("../static/login.js")),
    ("/cli.js", JS, include_str!("../static/cli.js")),
    (
        "/capture-upload.js",
        JS,
        include_str!("../static/capture-upload.js"),
    ),
    ("/capture.js", JS, include_str!("../static/capture.js")),
    ("/signup.js", JS_PLAIN, include_str!("../static/signup.js")),
    ("/invite.js", JS_PLAIN, include_str!("../static/invite.js")),
    // The dashboard SPA and its assets, served same-origin so it hits this
    // cloud's /v1 API with no CORS.
    ("/app", HTML, include_str!("../static/app.html")),
    ("/app.js", JS, include_str!("../static/app.js")),
    ("/selects.js", JS, include_str!("../static/selects.js")),
    // The per-seat triage product's view module (bug list + grab-a-bug +
    // triage controls + seat management). Loaded by app.html after app.js.
    ("/triage.js", JS, include_str!("../static/triage.js")),
    ("/styles.css", CSS, include_str!("../static/styles.css")),
    (
        "/favicon.svg",
        "image/svg+xml",
        include_str!("../static/favicon.svg"),
    ),
    // The bundled NimbusShop sample: a polished storefront with one planted
    // checkout crash and the web SDK wired to THIS cloud, so a first-run user
    // watches a real crash flow into their dashboard.
    ("/demo", HTML, include_str!("../static/demo/index.html")),
    ("/demo/app.js", JS, include_str!("../static/demo/app.js")),
    (
        "/demo/reproit-web.js",
        JS,
        include_str!("../static/demo/reproit-web.js"),
    ),
    (
        "/demo/styles.css",
        CSS,
        include_str!("../static/demo/styles.css"),
    ),
];

const HTML: &str = "text/html; charset=utf-8";
const JS: &str = "application/javascript; charset=utf-8";
const JS_PLAIN: &str = "application/javascript";
const CSS: &str = "text/css; charset=utf-8";

/// Per-edition route composition inputs; see `RunConfig` for field meaning.
pub struct RouterOptions {
    pub captures: bool,
    pub assets: &'static [StaticAsset],
    pub overlay_open: Option<Router<App>>,
    pub overlay_auth: Option<Router<App>>,
    pub overlay_account: Option<Router<App>>,
}

/// Serve an edition's embedded static assets from its data table.
fn asset_routes(assets: &'static [StaticAsset]) -> Router<App> {
    let mut router = Router::new();
    for (path, content_type, body) in assets {
        router = router.route(
            path,
            get(move || async move {
                (
                    [(CONTENT_TYPE, HeaderValue::from_static(content_type))],
                    *body,
                )
            }),
        );
    }
    router
}

/// Build the complete HTTP surface from explicit application state, plus the
/// edition's routing options. Overlay routers merge into the matching
/// protection profile BEFORE its guards apply, so an overlay route gets the
/// same limiter, CSRF stance, headers, metrics, and host allowlist as every
/// shared route on that profile.
///
/// Keeping route ownership outside process startup makes authentication, rate
/// limits, middleware ordering, and edition drift reviewable as one unit.
pub(crate) fn build(app: App, options: RouterOptions) -> Router {
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
        .route("/v1/apps/:app/runs/:run/proof", get(ingest::get_run_proof))
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
        // Account-token project lifecycle used by automation and disposable
        // release gates. Project keys cannot create siblings or delete any
        // project (enforced inside the handlers).
        .route("/v1/projects", post(auth::create_project_api))
        .route(
            "/v1/projects/:app",
            axum::routing::delete(auth::delete_project_api),
        );
    // The human capture-report API mounts only when the edition serves it.
    let protected = if options.captures {
        protected
            .route("/v1/captures", post(captures::create))
            .route("/v1/captures/:id", get(captures::status))
            .route(
                "/v1/captures/:id/files/:filename",
                axum::routing::put(captures::put_file),
            )
            .route("/v1/captures/:id/complete", post(captures::complete))
    } else {
        protected
    };
    let protected = protected
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
        .route("/auth/verify", get(auth::verify_email))
        .route("/auth/forgot", post(auth::forgot_password))
        .route("/auth/reset", post(auth::reset_password))
        // Overlay identity providers (OAuth/SSO start + callback) share the
        // same brute-force surface, so they ride the same limiter.
        .merge(options.overlay_auth.unwrap_or_default())
        .route_layer(GovernorLayer { config: auth_rl });

    // (2) Cookie-authenticated mutation + billing-checkout surface. Cookie-auth'd
    // inside the handlers (unchanged), Json<T> extractors, plus the loose
    // `account_rl` limiter (route_layer = all routes wrapped) AND the Origin/Referer
    // CSRF defense-in-depth middleware. The CSRF check is a no-op when
    // REPROIT_PUBLIC_URL is unset (dev). OAuth GET callbacks live on `auth_routes`
    // above, NOT here, so the CSRF guard never touches them.
    let account_mut = Router::new()
        .route("/auth/session", get(auth::session_status))
        .route("/account/me", get(auth::me))
        .route("/account/usage", get(auth::usage))
        .route(backend_contract::CREATE_PROJECT, post(auth::create_project))
        .route(
            "/account/projects/:app",
            axum::routing::delete(auth::delete_project),
        )
        .route("/auth/cli/approve", post(auth::cli_approve))
        .route(
            "/account/projects/:app/publishable-key",
            post(auth::rotate_publishable_key),
        )
        .route("/account/orgs", post(auth::create_org))
        .route("/account/orgs/name", post(auth::rename_org))
        .route("/account/orgs/active", post(auth::set_active_org))
        .route(
            "/account/orgs/current",
            axum::routing::delete(auth::delete_org),
        )
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
        );
    // Capture review pages are cookie-authenticated mutations too.
    let account_mut = if options.captures {
        account_mut
            .route(
                "/account/capture-uploads/:token",
                get(captures::review).post(captures::approve),
            )
            .route("/account/captures/:id", get(captures::account_capture))
    } else {
        account_mut
    };
    let account_mut = account_mut
        // Overlay cookie-authenticated mutations (billing checkout/portal,
        // SSO settings) get the same limiter and CSRF stance.
        .merge(options.overlay_account.unwrap_or_default())
        .route_layer(GovernorLayer { config: account_rl })
        .route_layer(middleware::from_fn(csrf_origin_check));

    // (4) Public, unauthenticated, no-mutation endpoints + static dashboard assets.
    // No limiter needed (static GETs / a redirect / a config read).
    let public_routes = Router::new()
        .route("/", get(|| async { Redirect::to("/app") }))
        .route("/auth/config", get(auth::auth_config))
        .merge(asset_routes(options.assets));

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
        .merge(options.overlay_open.unwrap_or_default())
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
    router
}
