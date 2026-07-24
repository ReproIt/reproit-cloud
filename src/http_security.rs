//! HTTP authentication, host, origin, CORS, and response security policy.

use super::*;

pub(super) fn configured_allowed_hosts() -> &'static HashSet<String> {
    ALLOWED_HOSTS.get_or_init(|| {
        std::env::var("REPROIT_ALLOWED_HOSTS")
            .unwrap_or_default()
            .split(',')
            .filter_map(normalize_host)
            .collect()
    })
}

pub(super) fn normalize_host(value: &str) -> Option<String> {
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

pub(super) fn host_is_allowed(host: Option<&str>, allowed: &HashSet<String>) -> bool {
    allowed.is_empty()
        || host
            .and_then(normalize_host)
            .is_some_and(|host| allowed.contains(&host))
}

pub(super) async fn allowed_host(request: Request, next: Next) -> Response {
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

/// Constant-time byte compare (length is allowed to leak; token contents aren't).
pub(super) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
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
pub(super) enum BearerError {
    Missing,
    Malformed,
}

pub(super) fn bearer(req: &Request) -> Result<String, BearerError> {
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

pub(super) fn auth_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

pub(super) fn api_auth_error(bearer: &Result<String, BearerError>) -> Response {
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

pub(super) fn worker_auth_error(
    server_configured: bool,
    bearer: &Result<String, BearerError>,
) -> Response {
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
pub(super) async fn require_api_key(
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
pub(super) async fn require_ingest_key(
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
pub(super) async fn resolve_api_auth(
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
            Ok(Some((org_id, _plan, project_id, created_by))) => {
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
pub(super) async fn require_worker_token(req: Request, next: Next) -> Result<Response, Response> {
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

/// Defense-in-depth response headers on every response. HSTS forces HTTPS,
/// nosniff stops content-type sniffing (matters for served evidence blobs),
/// frame DENY blocks clickjacking, referrer-policy limits URL leakage. (CSP is
/// intentionally omitted here: the dashboard uses inline scripts, so a strict
/// policy needs nonces + dashboard testing, a follow-up.)
/// Per-request metrics: one counter + one latency histogram, labeled by method
/// and status class. Registered app-wide alongside the security headers.
pub(super) async fn request_metrics(req: Request, next: Next) -> Response {
    let method = req.method().as_str().to_string();
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|path| path.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());
    let started = std::time::Instant::now();
    let resp = next.run(req).await;
    let status = resp.status().as_u16();
    let class = match status {
        100..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    };
    let response_bytes = resp
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    metrics::counter!("http_requests_total", "method" => method.clone(), "route" => route.clone(), "class" => class)
        .increment(1);
    metrics::histogram!("http_request_duration_seconds", "method" => method, "route" => route.clone(), "class" => class)
        .record(started.elapsed().as_secs_f64());
    metrics::histogram!("http_response_bytes", "route" => route).record(response_bytes as f64);
    resp
}

pub(super) async fn security_headers(req: Request, next: Next) -> Response {
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
pub(super) fn csrf_allowed_origins() -> Option<Vec<String>> {
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
pub(super) fn origin_of(url: &str) -> Option<String> {
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
pub(super) async fn csrf_origin_check(req: Request, next: Next) -> Result<Response, StatusCode> {
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
pub(super) fn csrf_origin_allowed(claimed: Option<&str>, allowed: &[String]) -> bool {
    match claimed {
        None => true,
        Some(o) => {
            let normalized = origin_of(o).unwrap_or_else(|| o.to_string());
            allowed.iter().any(|a| a == &normalized)
        }
    }
}

/// CORS for the API. Hosted ingest uses `REPROIT_CORS_ORIGINS=*` because browser
/// SDKs run on customer-controlled origins. Authorization remains bearer-key
/// based, and this layer never enables credentialed cookie CORS.
pub(super) fn cors_layer() -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE]);
    let list = std::env::var("REPROIT_CORS_ORIGINS")
        .ok()
        .filter(|s| !s.trim().is_empty());
    match list {
        Some(list) if list.trim() == "*" => {
            tracing::info!("CORS: allowing browser SDK requests from any origin");
            base.allow_origin(AllowOrigin::any())
        }
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
