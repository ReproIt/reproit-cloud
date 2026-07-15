//! The seat product: a developer logs in, sees production bugs, GRABS one, and
//! manages it. This module is the foundation for that surface, in three parts,
//! mirroring how `ingest::buckets` keeps the transforms pure and the DB calls in
//! handlers:
//!
//!   1. **Triage state machine** (`Status` + `apply`): a bucket's lifecycle
//!      `untriaged -> investigating -> fixed | wontfix`, as PURE, unit-tested
//!      transition logic over no DB/HTTP. The verified-fix signal (the SAME one
//!      `integrations::is_verified_fix` uses in the replay-results path) auto-
//!      advances a bucket to `fixed`, UNLESS a human has marked it `wontfix`.
//!   2. **Seat gate** (`seat_decision`): a pure decision over (has_seat) that the
//!      auth layer turns into a 402/403 on the dashboard/triage surface. The
//!      CLI/SDK stays free, seats gate only the cloud dashboard.
//!   3. **"Grab a bug" detail builder** (`bucket_detail`): bundles everything a
//!      dev needs to act, the crash summary, repro status/rate, lineage, replay
//!      actions, the `reproit cloud reproduce --bucket ...` command, the linked
//!      ticket (if any), and the triage state, into one payload.
//!
//! HTTP handlers at the bottom wire these to Postgres; everything above the
//! `---- handlers ----` divider is side-effect-free and directly testable.

pub(crate) mod resolution;

use crate::auth::{ct_eq, current_user};
use crate::db::Triage;
use crate::ingest::buckets;
use crate::App;
use axum::{
    extract::{Path, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

// ---- 1. triage state machine (pure) ----------------------------------------

/// A bucket's triage lifecycle. `untriaged` is the implicit state of a bucket no
/// one has touched yet (no DB row), so a missing row deserializes to
/// `Untriaged`.
/// `Investigating` means someone has picked it up. `Fixed` and `Wontfix` are
/// terminal in the sense that the AUTO verified-fix path won't override
/// `Wontfix` (the human's explicit "won't fix" wins), though a human can still
/// re-open by POSTing any other status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Untriaged,
    Investigating,
    Fixed,
    Wontfix,
}

impl Status {
    /// The wire/DB string for a status (what `bucket_triage.status` stores).
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Untriaged => "untriaged",
            Status::Investigating => "investigating",
            Status::Fixed => "fixed",
            Status::Wontfix => "wontfix",
        }
    }

    /// Parse a status string, or None if it isn't a known state. Used to reject a
    /// bad `status` in a POST body before it ever reaches the DB.
    pub fn parse(s: &str) -> Option<Status> {
        match s {
            "untriaged" => Some(Status::Untriaged),
            "investigating" => Some(Status::Investigating),
            "fixed" => Some(Status::Fixed),
            "wontfix" => Some(Status::Wontfix),
            _ => None,
        }
    }
}

/// PURE human-driven transition: validate moving `from` -> `to`, returning the
/// status to persist.
/// We deliberately allow any move BETWEEN the named states (a dev can re-open a
/// `fixed` bucket, mark an `untriaged` one `wontfix`, etc.), so the rule set is about
/// the simple product state, not a rigid forward-only graph.
///
/// Kept a free function over primitives so it unit-tests with no DB/HTTP, exactly
/// like `integrations::is_verified_fix`.
pub fn apply(_from: Status, to: Status) -> Status {
    to
}

/// PURE verified-fix transition: given the bucket's CURRENT status, what should a
/// verified-fix signal advance it to? This encodes the brief's rule, "when a
/// verified-fix lands, auto-advance to `fixed` UNLESS it's `wontfix`". A `wontfix`
/// bucket is left untouched (returns None: the human's call stands); anything
/// else advances to `Fixed`. Idempotent: a verified fix on an already-`fixed`
/// bucket re-confirms `fixed`. The DB twin (`advance_triage_unless_wontfix`)
/// enforces the same wontfix guard in SQL for the no-row / concurrent case, so
/// at runtime the SQL guard is the one that fires (atomic against a concurrent
/// human POST); this pure twin is the documented, unit-tested decision rule.
#[allow(dead_code)] // the SQL twin enforces this guard atomically at runtime
pub fn on_verified_fix(current: Status) -> Option<Status> {
    match current {
        Status::Wontfix => None,
        _ => Some(Status::Fixed),
    }
}

// ---- 2. seat gate (pure) ---------------------------------------------------

/// The seat-gate verdict for a request hitting the dashboard/triage surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeatVerdict {
    /// Member holds a seat: serve the dashboard surface.
    Allow,
    /// Authenticated org member, but no seat: 402 Payment Required (upgrade /
    /// assign a seat). We pick 402 over 403 because it's an ENTITLEMENT gap, not
    /// an authorization failure, the actionable fix is buying/assigning a seat.
    NoSeat,
    /// Not signed in at all: 401, handled upstream by the cookie check.
    NotSignedIn,
}

/// PURE seat decision over the two facts the DB resolves: is the caller signed in
/// (an org member) and do they hold a seat. No DB/HTTP here so the whole gate is
/// unit-tested; the handler does the lookups and maps the verdict to a status.
/// The CLI/SDK never reaches this, it authenticates on an org API key, so this
/// gates ONLY the per-seat dashboard surface.
pub fn seat_decision(signed_in: bool, has_seat: bool) -> SeatVerdict {
    if !signed_in {
        SeatVerdict::NotSignedIn
    } else if has_seat {
        SeatVerdict::Allow
    } else {
        SeatVerdict::NoSeat
    }
}

// ---- 3. "grab a bug" detail builder (pure) ---------------------------------

/// PURE detail-payload builder: bundle everything a dev needs to GRAB and act on
/// a bucket into one JSON object. Takes the already-fetched pieces (so it stays
/// DB-free and testable) and stitches them together:
///   - identity + crash summary + the repro status/rate (the "is this real?")
///   - the executable replay actions + the local reproduce command
///   - build lineage (regressed-in / no-hits-since)
///   - the linked ticket, if any (reusing `db::integrations::ticket_for_bucket`)
///   - the triage state (defaulting to the implicit `untriaged`)
///
/// The `repro` summary is computed by the same `buckets::repro_status` the bucket
/// list uses, so the seat view and the API agree.
#[allow(clippy::too_many_arguments)]
pub fn bucket_detail(
    app_id: &str,
    bucket_id: &str,
    newest: &crate::ingest::ErrorRec,
    oldest: &crate::ingest::ErrorRec,
    sample: Option<&str>,
    count: usize,
    discriminators: Vec<Value>,
    cohorts: Vec<Value>,
    repro: Value,
    ticket: Option<Value>,
    triage: Option<&Triage>,
    resolution: &resolution::Outcome,
) -> Value {
    // A bucket with no triage row is implicitly `untriaged`, never touched.
    let (status, updated_at) = match triage {
        Some(t) => (t.status.clone(), Value::from(t.updated_at.clone())),
        None => (Status::Untriaged.as_str().to_string(), Value::Null),
    };
    json!({
        "bucketId": bucket_id,
        "bugId": buckets::bug_id(newest),
        "findingIdentity": buckets::finding_identity(newest),
        "sample": sample,
        "appId": app_id,
        "count": count,
        "crashSummary": buckets::crash_summary(newest),
        "crashSig": newest.sig,
        "message": newest.message,
        // The trust signal (status + reproduced/attempts rate), same shape as the
        // bucket list, so "this is real / fixed / data-dependent" reads identically.
        "repro": repro,
        // The executable replay (PII-safe class tokens only) + the one command a
        // dev runs to reproduce locally and post a verdict back.
        "replay": buckets::replay_actions(newest),
        "displayPath": buckets::display_path(newest),
        "reproduceCommand": format!("reproit cloud reproduce --app {app_id} --bucket {bucket_id} --as {bucket_id} --run"),
        "lineage": buckets::lineage(oldest, newest),
        "context": newest.context,
        "cohorts": cohorts,
        "discriminators": discriminators,
        // The linked issue-tracker ticket, or null if the bucket was never filed.
        "ticket": ticket.unwrap_or(Value::Null),
        // The management state the dev acts on: where in the lifecycle.
        // This is the dev's INTENT (the status they clicked).
        "triage": {
            "status": status,
            "updatedAt": updated_at,
            "fixedInBuild": triage.and_then(|t| t.fixed_in_build.clone()),
        },
        // The SYSTEM-computed prod-evidence TRUTH, side by side with the intent
        // above: active/resolving/resolved/regressed, plus the evidence behind it
        // (the fix anchor, the bug's last sighting on a fixed build, and the
        // post-fix recurrence count). The gap between this and `triage.status` is
        // the signal (e.g. dev says `fixed` but resolution says `regressed`).
        "resolution": resolution.to_json(),
    })
}

// ---- handlers --------------------------------------------------------------
//
// Cookie-authenticated (the dashboard surface), then seat-gated: a signed-in org
// member WITHOUT a seat gets 402 here, while the same member's CLI key keeps
// working on /v1/* (which never reaches this gate). Everything above is pure; the
// handlers do the DB lookups and map the pure verdicts to HTTP.

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

/// Compute the prod-evidence resolution for a bucket from the occurrence stream.
/// Pure decision (`resolution::evaluate`) fed by DB reads: the bucket's own
/// occurrences drive recurrence/regression, and the APP-WIDE stream supplies both
/// the build-ordering anchor and the post-fix traffic denominator. On-read
/// evaluation (computed when detail/timeline is fetched) is the foundation; a
/// background sweep is the natural follow-up.
async fn compute_resolution(
    store: &crate::db::TenantStore,
    app_id: &str,
    bucket: &str,
    fixed_in_build: Option<&str>,
) -> resolution::Outcome {
    // App-wide stream (bounded recency sample): drives first-seen build
    // ordering + the post-fix traffic denominator across ALL buckets.
    let app_occ = store
        .recent_errors_with_meta(app_id, crate::ingest::baseline_sample())
        .await
        .unwrap_or_default();
    let app_stream: Vec<resolution::Occurrence> = app_occ
        .iter()
        .map(|(_, at, rec)| resolution::Occurrence {
            at: at.clone(),
            build: buckets::build_version(rec),
        })
        .collect();
    // This bucket's own occurrences (the recurrence signal), via the
    // materialized bucket_id index.
    let bug: Vec<resolution::Occurrence> = store
        .errors_for_bucket(app_id, bucket, crate::ingest::baseline_sample())
        .await
        .unwrap_or_default()
        .iter()
        .map(|(_, at, rec)| resolution::Occurrence {
            at: at.clone(),
            build: buckets::build_version(rec),
        })
        .collect();
    let first_seen = resolution::first_seen_by_build(&app_stream);
    let traffic = fixed_in_build
        .map(|f| resolution::post_fix_traffic(&app_stream, f))
        .unwrap_or(0);
    let now = chrono::Utc::now().to_rfc3339();
    resolution::evaluate(
        &bug,
        &first_seen,
        fixed_in_build,
        traffic,
        &now,
        resolution::Thresholds::default(),
    )
}

/// The bearer-key authorization verdict for an org-scoped DATA request, decided
/// over the two facts the DB resolves from a presented `Authorization: Bearer`
/// token: whether the token is the shared ADMIN key, and (if it's a per-org key)
/// whether that key's org OWNS the requested app. Kept pure so the cross-tenant
/// rule is unit-tested with no DB/HTTP.
#[allow(dead_code)]
// the live path resolves the tenant directly; this pure
// decision + its variants are retained and unit-tested as the
// documented cross-tenant rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerVerdict {
    /// The shared admin/ops key: full access, no org scoping (None org id).
    Admin,
    /// A valid per-org key whose org owns this app: serve, scoped to that org.
    Org(i64),
    /// A bearer token was present but did not authorize this app (unknown key, or
    /// a key whose org does NOT own this app). The caller treats this as "no
    /// bearer authorization", then falls back to the cookie+seat path; a wrong-org
    /// key therefore never leaks across tenants (it gets 404 from the fallback).
    Deny,
}

/// PURE bearer-key decision over the resolved facts: was the token the admin key,
/// and (for a per-org key) the (org_id, owns_app) pair the DB returned. No DB/HTTP
/// here, so the cross-tenant rule (a key whose org does not own the app is denied)
/// is directly unit-tested. The org API key is the org's automation credential, so
/// this path is NOT seat-gated, exactly like `/v1/apps/:app/buckets`.
#[allow(dead_code)] // see BearerVerdict: retained + unit-tested decision rule.
pub fn bearer_decision(is_admin: bool, org_owns: Option<(i64, bool)>) -> BearerVerdict {
    if is_admin {
        return BearerVerdict::Admin;
    }
    match org_owns {
        Some((org_id, true)) => BearerVerdict::Org(org_id),
        _ => BearerVerdict::Deny,
    }
}

/// Read a `Authorization: Bearer <token>` value out of the request headers.
fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|t| t.to_string())
}

/// Authorize an org-scoped DATA request for `app_id` via EITHER credential:
///   (a) a valid ORG API KEY (bearer) whose org owns the app, the machine
///       credential the CLI/MCP agent surface uses, NOT seat-gated (a seat is a
///       per-human dashboard concept; an API key is the org's automation cred).
///       The shared admin key authorizes too (unscoped), mirroring
///       `require_api_key` / `/v1/apps/:app/buckets`.
///   (b) a COOKIE session + a SEAT (the human dashboard), UNCHANGED.
///
/// Returns the org id the request is scoped to on success, or the HTTP response to
/// short-circuit with. The bearer path is tried first; if no bearer authorizes the
/// app (no token, unknown key, or a key whose org does not own the app) we fall
/// through to the cookie+seat gate, so a wrong-org key never leaks across tenants
/// (it simply gets the same 404 the cookie path returns for an app it can't see).
async fn authorize_app(
    app: &App,
    headers: &HeaderMap,
    app_id: &str,
) -> Result<(crate::tenancy::resolver::Tenant, i64), Response> {
    if let Some(token) = bearer(headers) {
        // Mirror `require_api_key`: the shared admin key (constant-time) first.
        let shared = std::env::var("REPROIT_API_KEY")
            .ok()
            .filter(|k| !k.is_empty());
        let is_admin = shared
            .as_deref()
            .is_some_and(|s| ct_eq(s.as_bytes(), token.as_bytes()));
        // Resolve the per-org key to its org id (the routing key under db-per-org).
        let org_for_key = if is_admin {
            None
        } else {
            match app.control.org_for_api_key(&token).await {
                Ok(Some((org_id, _project, _user))) => Some(org_id),
                Ok(None) => None,
                Err(e) => {
                    tracing::error!("org_for_api_key lookup failed: {e}");
                    None
                }
            }
        };
        if is_admin {
            // Admin must NAME the tenant explicitly (apps aren't globally resolvable
            // to an org under db-per-org); resolve it + confirm the app exists there.
            if let Some(org_id) = crate::admin_target(headers) {
                return resolve_owning(app, org_id, app_id).await;
            }
            return Err(err(
                StatusCode::BAD_REQUEST,
                "admin requests must name a tenant via X-Reproit-Tenant",
            ));
        }
        if let Some(org_id) = org_for_key {
            // A per-org key: resolve its tenant and confirm the app exists there.
            // A wrong-org key resolves to ITS OWN tenant where the app is absent, so
            // it 404s, never crossing into another tenant (the DB is the boundary).
            return resolve_owning(app, org_id, app_id).await;
        }
        // Unknown bearer: fall through to the cookie+seat path (no confirm/deny).
    }
    // No bearer authorization: the human dashboard path (cookie + seat).
    seat_gate(app, headers, app_id).await
}

/// Resolve an org's tenant and confirm `app_id` is a project in it (404 otherwise,
/// no existence leak). Shared by the admin + org-key authorization paths.
async fn resolve_owning(
    app: &App,
    org_id: i64,
    app_id: &str,
) -> Result<(crate::tenancy::resolver::Tenant, i64), Response> {
    let tenant = match app.tenancy.resolve(org_id).await {
        Ok(t) => t,
        Err(_) => return Err(err(StatusCode::NOT_FOUND, "not found")),
    };
    match tenant.store.owns_app(app_id).await {
        Ok(true) => Ok((tenant, org_id)),
        Ok(false) => Err(err(StatusCode::NOT_FOUND, "not found")),
        Err(e) => {
            tracing::error!("owns_app check failed for app {app_id}: {e}");
            Err(err(StatusCode::NOT_FOUND, "not found"))
        }
    }
}

/// Resolve the signed-in user, their org, SEAT-GATE the dashboard surface, and
/// resolve the org's TENANT (confirming the app exists there). Returns the
/// (tenant, org_id) on success, or the HTTP response to short-circuit with: 401 if
/// not signed in, 402 if signed in without a seat, 404 if the app isn't the
/// caller's (no existence leak).
async fn seat_gate(
    app: &App,
    headers: &HeaderMap,
    app_id: &str,
) -> Result<(crate::tenancy::resolver::Tenant, i64), Response> {
    let user = current_user(app, headers).await;
    let signed_in = user.is_some();
    let (user_id, org) = match &user {
        Some(u) => {
            let org = crate::auth::user_and_org(app, headers)
                .await
                .ok()
                .map(|(_, org)| org);
            (Some(u.id), org)
        }
        None => (None, None),
    };
    // Resolve the seat fact only when we have an org to check it against.
    let has_seat = match (user_id, &org) {
        (Some(uid), Some(o)) => app.control.has_seat(o.id, uid).await.unwrap_or(false),
        _ => false,
    };
    match seat_decision(signed_in, has_seat) {
        SeatVerdict::NotSignedIn => return Err(err(StatusCode::UNAUTHORIZED, "not signed in")),
        SeatVerdict::NoSeat => {
            return Err(err(
                StatusCode::PAYMENT_REQUIRED,
                "a dashboard seat is required (the CLI stays free); ask an owner to assign you one",
            ))
        }
        SeatVerdict::Allow => {}
    }
    let (Some(_uid), Some(org)) = (user_id, org) else {
        return Err(err(StatusCode::UNAUTHORIZED, "not signed in"));
    };
    // Seated: resolve the org's tenant + confirm the app exists there (404 else).
    resolve_owning(app, org.id, app_id).await
}

/// GET /v1/apps/:app/buckets/:bucket/triage, the bucket's triage state (status +
/// last-touched), or the implicit `untriaged` if it was never touched.
pub async fn get_triage(
    State(app): State<App>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
) -> Response {
    let (tenant, _org_id) = match authorize_app(&app, &headers, &app_id).await {
        Ok(x) => x,
        Err(resp) => return resp,
    };
    let triage = match tenant.store.triage_for_bucket(&app_id, &bucket).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("triage_for_bucket failed for {bucket}: {e}");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    match triage {
        Some(t) => Json(json!({ "bucketId": bucket, "triage": t })).into_response(),
        None => Json(json!({
            "bucketId": bucket,
            "triage": { "status": Status::Untriaged.as_str(), "updatedAt": Value::Null, "fixedInBuild": Value::Null },
        }))
        .into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct TriageUpdate {
    pub status: String,
    /// Optional OVERRIDE for the prod-resolution anchor when moving to `fixed`.
    /// When omitted, the anchor defaults to the newest build seen for this bucket
    /// at fix time (the build the dev was on when they marked it fixed). Ignored
    /// for any non-`fixed` status (the anchor is cleared on re-open).
    #[serde(default, rename = "fixedInBuild")]
    pub fixed_in_build: Option<String>,
}

/// POST /v1/apps/:app/buckets/:bucket/triage, set a bucket's triage state. Body:
/// `{status}`. The status must be a known state.
pub async fn post_triage(
    State(app): State<App>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
    Json(body): Json<TriageUpdate>,
) -> Response {
    let (tenant, _org_id) = match authorize_app(&app, &headers, &app_id).await {
        Ok(x) => x,
        Err(resp) => return resp,
    };
    let Some(to) = Status::parse(&body.status) else {
        return err(
            StatusCode::BAD_REQUEST,
            "status must be one of: untriaged, investigating, fixed, wontfix",
        );
    };
    // The CURRENT status feeds the transition (the implicit `untriaged` if no row yet).
    let current = match tenant.store.triage_for_bucket(&app_id, &bucket).await {
        Ok(Some(t)) => Status::parse(&t.status).unwrap_or(Status::Untriaged),
        Ok(None) => Status::Untriaged,
        Err(e) => {
            tracing::error!("triage_for_bucket failed for {bucket}: {e}");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    let next = apply(current, to);
    // The prod-resolution anchor: set ONLY when moving INTO `fixed` with an
    // explicit fixedInBuild. Cloud cannot infer the real fix build from bug
    // occurrences without creating a false post-fix recurrence.
    let fixed_in_build: Option<String> = if next == Status::Fixed {
        match &body.fixed_in_build {
            Some(b) if !b.trim().is_empty() => Some(b.trim().to_string()),
            _ => None,
        }
    } else {
        None
    };
    if let Err(e) = tenant
        .store
        .upsert_triage(
            &app_id,
            &bucket,
            next.as_str(),
            None,
            fixed_in_build.as_deref(),
        )
        .await
    {
        tracing::error!("upsert_triage failed for {bucket}: {e}");
        return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }
    Json(json!({
        "bucketId": bucket,
        "triage": { "status": next.as_str(), "fixedInBuild": fixed_in_build },
    }))
    .into_response()
}

/// GET /v1/apps/:app/dashboard/buckets, the signed-in dashboard's bucket list.
/// It returns the same ranked payload as the API-key `/v1/apps/:app/buckets`
/// route, but authorizes through the dashboard cookie/seat path (or bearer key
/// when present) so humans do not have to paste a project secret into the UI.
pub async fn get_dashboard_buckets(
    State(app): State<App>,
    headers: HeaderMap,
    Path(app_id): Path<String>,
) -> Response {
    let (tenant, _org_id) = match authorize_app(&app, &headers, &app_id).await {
        Ok(x) => x,
        Err(resp) => return resp,
    };
    match crate::ingest::bucket_list_for_tenant(&tenant, &app_id).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => {
            tracing::error!("dashboard bucket list failed for {app_id}: {e}");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

/// GET /v1/apps/:app/buckets/:bucket/detail, the "GRAB A BUG" read model:
/// everything a dev needs to act on this bucket in one payload (see
/// `bucket_detail`). Seat-gated like the triage endpoints; the CLI's replay
/// package at `/v1/apps/:app/buckets/:bucket` stays ungated for the engine.
pub async fn get_bucket_detail(
    State(app): State<App>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
) -> Response {
    let (tenant, _org_id) = match authorize_app(&app, &headers, &app_id).await {
        Ok(x) => x,
        Err(resp) => return resp,
    };
    let rows = match tenant
        .store
        .errors_for_bucket(&app_id, &bucket, crate::ingest::baseline_sample())
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("errors_for_bucket failed for {app_id}: {e}");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    if rows.is_empty() {
        return err(StatusCode::NOT_FOUND, "not found");
    }
    let oldest = rows.first().unwrap().2.clone();
    let newest = rows.last().unwrap().2.clone();
    let sample = rows
        .iter()
        .all(|(_, _, rec)| crate::ingest::sample_kind(rec) == Some(crate::ingest::NIMBUS_SAMPLE))
        .then_some(crate::ingest::NIMBUS_SAMPLE);
    let count = rows.len();
    let baseline: Vec<serde_json::Map<String, Value>> = tenant
        .store
        .recent_errors_with_meta(&app_id, crate::ingest::baseline_sample())
        .await
        .unwrap_or_default()
        .iter()
        .map(|(_, _, r)| r.context.clone())
        .collect();
    let cohort: Vec<serde_json::Map<String, Value>> =
        rows.iter().map(|(_, _, r)| r.context.clone()).collect();
    let discriminators = crate::ingest::cohorts::discriminators(&cohort, &baseline);
    let cohorts = crate::ingest::cohorts::cohort_breakdowns(&cohort, &baseline);
    // The three side reads the payload bundles: repro rate, linked ticket, triage.
    let results = tenant
        .store
        .replay_results_for(&app_id, &bucket)
        .await
        .unwrap_or_default();
    let repro = buckets::repro_status(&results);
    let ticket = tenant
        .store
        .ticket_for_bucket(&app_id, &bucket)
        .await
        .ok()
        .flatten()
        .map(|t| serde_json::to_value(t).unwrap_or(Value::Null));
    let triage = tenant
        .store
        .triage_for_bucket(&app_id, &bucket)
        .await
        .ok()
        .flatten();
    // Compute the prod-evidence truth against the bucket's claimed fix anchor (if
    // any). On-read evaluation: the resolution is always live, never stale.
    let fixed = triage.as_ref().and_then(|t| t.fixed_in_build.clone());
    let resolution = compute_resolution(&tenant.store, &app_id, &bucket, fixed.as_deref()).await;
    Json(bucket_detail(
        &app_id,
        &bucket,
        &newest,
        &oldest,
        sample,
        count,
        discriminators,
        cohorts,
        repro,
        ticket,
        triage.as_ref(),
        &resolution,
    ))
    .into_response()
}

/// DELETE /v1/apps/:app/buckets/:bucket/sample clears only the bundled
/// NimbusShop onboarding finding. This is intentionally not a generic bug
/// deletion API: every occurrence must carry the sample identity (or match the
/// narrow legacy sample signature), and only an org owner/admin may call it.
pub async fn delete_sample_bucket(
    State(app): State<App>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
) -> Response {
    let (_user, org) = match crate::auth::user_and_org(&app, &headers).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    if !crate::auth::can_manage(&org.role) {
        return err(StatusCode::FORBIDDEN, "owner or admin required");
    }
    let (tenant, _) = match resolve_owning(&app, org.id, &app_id).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    let rows = match tenant
        .store
        .errors_for_bucket(&app_id, &bucket, i64::MAX)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("sample bucket read failed for {app_id}/{bucket}: {e}");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    if rows.is_empty() {
        return err(StatusCode::NOT_FOUND, "not found");
    }
    if rows
        .iter()
        .any(|(_, _, rec)| crate::ingest::sample_kind(rec) != Some(crate::ingest::NIMBUS_SAMPLE))
    {
        return err(
            StatusCode::BAD_REQUEST,
            "only NimbusShop sample data can be cleared here",
        );
    }
    let ids: Vec<i64> = rows.iter().map(|(id, _, _)| *id).collect();
    let (deleted, evidence_keys) = match tenant
        .store
        .delete_sample_bucket_data(&app_id, &bucket, &ids)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("sample bucket delete failed for {app_id}/{bucket}: {e}");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    for key in evidence_keys {
        if let Err(e) = tenant.blobs.delete(&key).await {
            tracing::warn!("sample evidence blob cleanup failed for {app_id}/{bucket}: {e}");
        }
    }
    Json(json!({
        "cleared": true,
        "sample": crate::ingest::NIMBUS_SAMPLE,
        "occurrences": deleted,
    }))
    .into_response()
}

/// GET /v1/apps/:app/buckets/:bucket/timeline, the per-bucket OCCURRENCE
/// TIME-SERIES segmented by build: `{ window, build, count }` cells plus a
/// build-agnostic total series, the data the dashboard graphs. Also surfaces the
/// computed `resolution` (against the bucket's fix anchor) so the graph and the
/// prod-truth verdict are fetched together. Seat-gated like the other dashboard
/// reads. `?window=<secs>` overrides the default hourly grid.
pub async fn get_bucket_timeline(
    State(app): State<App>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
    axum::extract::Query(q): axum::extract::Query<TimelineQuery>,
) -> Response {
    let (tenant, _org_id) = match authorize_app(&app, &headers, &app_id).await {
        Ok(x) => x,
        Err(resp) => return resp,
    };
    let rows = match tenant
        .store
        .errors_for_bucket(&app_id, &bucket, crate::ingest::baseline_sample())
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("errors_for_bucket failed for {app_id}: {e}");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    if rows.is_empty() {
        return err(StatusCode::NOT_FOUND, "not found");
    }
    // (created_at, build_version) pairs for this bucket's occurrences -> the pure
    // shaping fn buckets the time-series and segments it by build.
    let series: Vec<(String, Option<String>)> = rows
        .iter()
        .map(|(_, at, rec)| (at.clone(), buckets::build_version(rec)))
        .collect();
    let window = q.window.unwrap_or(buckets::DEFAULT_TIMELINE_WINDOW_SECS);
    let timeline = buckets::timeline(&series, window);
    // The fix anchor + computed resolution, fetched alongside so the graph and the
    // prod-truth verdict render together.
    let fixed = tenant
        .store
        .triage_for_bucket(&app_id, &bucket)
        .await
        .ok()
        .flatten()
        .and_then(|t| t.fixed_in_build);
    let resolution = compute_resolution(&tenant.store, &app_id, &bucket, fixed.as_deref()).await;
    Json(json!({
        "bucketId": bucket,
        "appId": app_id,
        "windowSecs": window,
        "series": timeline.cells,
        "total": timeline.total,
        "resolution": resolution.to_json(),
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct TimelineQuery {
    /// Time-window size in seconds; defaults to `DEFAULT_TIMELINE_WINDOW_SECS`.
    #[serde(default)]
    pub window: Option<i64>,
}

/// GET /v1/apps/:app/resolution-events, the durable, proactive ALERT FEED: recent
/// prod-truth TRANSITIONS the background sweep recorded (`resolved->regressed`,
/// `resolving->resolved`, ...), newest first. This is what powers "regressed 2h
/// ago" on the dashboard and what a future notification step (email/webhook/Slack)
/// drains. Seat-gated like the other dashboard reads; tolerant of an empty log
/// (returns an empty list, not an error).
pub async fn get_resolution_events(
    State(app): State<App>,
    headers: HeaderMap,
    Path(app_id): Path<String>,
) -> Response {
    let (tenant, _org_id) = match authorize_app(&app, &headers, &app_id).await {
        Ok(x) => x,
        Err(resp) => return resp,
    };
    let events = match tenant
        .store
        .recent_resolution_events(&app_id, crate::sweep::RECENT_EVENTS_LIMIT)
        .await
    {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("recent_resolution_events failed for {app_id}: {e}");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    Json(json!({ "appId": app_id, "count": events.len(), "events": events })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::Step;
    use serde_json::Map;

    fn rec(msg: &str, sig: &str, entry: &str, actions: &[&str]) -> crate::ingest::ErrorRec {
        let mut path = vec![Step {
            sig: entry.to_string(),
            action: "load".to_string(),
            label: None,
        }];
        for a in actions {
            path.push(Step {
                sig: "mid".to_string(),
                action: a.to_string(),
                label: None,
            });
        }
        crate::ingest::ErrorRec {
            sig: sig.to_string(),
            message: msg.to_string(),
            path,
            context: Map::new(),
        }
    }

    // ---- 1. triage state machine ----

    #[test]
    fn status_roundtrips_through_its_wire_string() {
        for s in [
            Status::Untriaged,
            Status::Investigating,
            Status::Fixed,
            Status::Wontfix,
        ] {
            assert_eq!(Status::parse(s.as_str()), Some(s));
        }
        assert_eq!(Status::parse("bogus"), None);
    }

    #[test]
    fn apply_allows_simple_status_changes() {
        assert_eq!(
            apply(Status::Untriaged, Status::Investigating),
            Status::Investigating
        );
        assert_eq!(apply(Status::Investigating, Status::Fixed), Status::Fixed);
        // re-opening a fixed bucket is allowed (coherence, not a forward-only graph).
        assert_eq!(
            apply(Status::Fixed, Status::Investigating),
            Status::Investigating
        );
    }

    #[test]
    fn verified_fix_advances_to_fixed_except_from_wontfix() {
        // From any non-wontfix state a verified fix advances to `fixed`.
        assert_eq!(on_verified_fix(Status::Untriaged), Some(Status::Fixed));
        assert_eq!(on_verified_fix(Status::Investigating), Some(Status::Fixed));
        // Idempotent: an already-fixed bucket re-confirms fixed.
        assert_eq!(on_verified_fix(Status::Fixed), Some(Status::Fixed));
        // THE EXCEPTION: a human's `wontfix` is never overridden by the auto signal.
        assert_eq!(on_verified_fix(Status::Wontfix), None);
    }

    // ---- 2. seat gate ----

    #[test]
    fn seat_decision_gates_only_the_dashboard_surface() {
        // Not signed in: 401 upstream.
        assert_eq!(seat_decision(false, false), SeatVerdict::NotSignedIn);
        assert_eq!(seat_decision(false, true), SeatVerdict::NotSignedIn);
        // Signed in WITHOUT a seat: 402 (entitlement gap), the CLI still works.
        assert_eq!(seat_decision(true, false), SeatVerdict::NoSeat);
        // Signed in WITH a seat: served.
        assert_eq!(seat_decision(true, true), SeatVerdict::Allow);
    }

    // ---- 2b. bearer-key authorization (the agent/CLI org-key path) ----

    #[test]
    fn bearer_decision_authorizes_own_org_and_rejects_cross_tenant() {
        // The shared admin/ops key: full access, no org scoping.
        assert_eq!(bearer_decision(true, None), BearerVerdict::Admin);
        // A per-org key whose org OWNS this app: served, scoped to that org.
        assert_eq!(
            bearer_decision(false, Some((42, true))),
            BearerVerdict::Org(42)
        );
        // CROSS-TENANT: a valid key from a DIFFERENT org (does NOT own this app) is
        // denied here, so the request falls through to cookie+seat (404), never
        // leaking another tenant's data.
        assert_eq!(
            bearer_decision(false, Some((99, false))),
            BearerVerdict::Deny
        );
        // An unknown / non-org key (no org resolved) is denied.
        assert_eq!(bearer_decision(false, None), BearerVerdict::Deny);
        // Admin wins regardless of any org-ownership fact.
        assert_eq!(
            bearer_decision(true, Some((7, false))),
            BearerVerdict::Admin
        );
    }

    #[test]
    fn bearer_reads_authorization_header() {
        let mut h = HeaderMap::new();
        assert_eq!(bearer(&h), None);
        h.insert(AUTHORIZATION, "Bearer sk_live_abc".parse().unwrap());
        assert_eq!(bearer(&h).as_deref(), Some("sk_live_abc"));
        // A non-bearer scheme is not a bearer token.
        let mut h2 = HeaderMap::new();
        h2.insert(AUTHORIZATION, "Basic xyz".parse().unwrap());
        assert_eq!(bearer(&h2), None);
    }

    // ---- 3. "grab a bug" detail builder ----

    #[test]
    fn bucket_detail_bundles_everything_a_dev_needs_to_grab_a_bug() {
        let mut newest = rec(
            "Cannot read property of undefined at line 42",
            "crashX",
            "checkout",
            &["type:key:id:card=long", "tap:key:id:pay"],
        );
        newest
            .context
            .insert("build".into(), serde_json::json!({ "version": "1.4.5" }));
        let oldest = rec(
            "Cannot read property of undefined at line 9001",
            "crashX",
            "checkout",
            &["tap:key:id:pay"],
        );
        let repro = serde_json::json!({ "status": "reproduced", "attempts": 3, "rate": 0.66 });
        let ticket = Some(serde_json::json!({
            "provider": "github", "repo": "acme/web", "externalId": "12",
            "url": "https://github.com/acme/web/issues/12"
        }));
        let triage = Triage {
            status: "investigating".into(),
            assignee: None,
            updated_at: "2026-06-21T00:00:00Z".into(),
            fixed_in_build: None,
        };
        let discs = vec![serde_json::json!({
            "key": "locale",
            "value": "tr",
            "cohortShare": 1.0,
            "baselineShare": 0.3,
            "lift": 3.3
        })];
        let cohorts = vec![serde_json::json!({
            "key": "locale",
            "total": 3,
            "values": [{
                "value": "tr",
                "count": 3,
                "cohortShare": 1.0,
                "baselineShare": 0.3,
                "lift": 3.3
            }]
        })];
        let bid = "bkt_deadbeef0001";
        let res = resolution::Outcome {
            status: resolution::Resolution::Active,
            fixed_in_build: None,
            last_seen_on_fixed_build: None,
            post_fix_occurrences: 0,
        };
        let d = bucket_detail(
            "acme-web",
            bid,
            &newest,
            &oldest,
            None,
            3,
            discs.clone(),
            cohorts.clone(),
            repro.clone(),
            ticket.clone(),
            Some(&triage),
            &res,
        );

        // Identity + the reproduce command a dev runs to grab it.
        assert_eq!(d["bucketId"], bid);
        assert_eq!(d["appId"], "acme-web");
        assert_eq!(d["count"], 3);
        assert_eq!(
            d["reproduceCommand"],
            format!("reproit cloud reproduce --app acme-web --bucket {bid} --as {bid} --run")
        );
        // The executable replay (PII-safe class tokens) is present.
        assert_eq!(
            d["replay"],
            serde_json::json!(["type:key:id:card=long", "tap:key:id:pay"])
        );
        // The repro trust signal + lineage + linked ticket pass through.
        assert_eq!(d["repro"], repro);
        assert_eq!(d["lineage"]["lastSeen"]["version"], "1.4.5");
        assert_eq!(d["discriminators"], serde_json::json!(discs));
        assert_eq!(d["cohorts"], serde_json::json!(cohorts));
        assert_eq!(d["ticket"]["externalId"], "12");
        // The management state a dev acts on (the dev's INTENT).
        assert_eq!(d["triage"]["status"], "investigating");
        // The SYSTEM-computed prod-truth, side by side with the intent.
        assert_eq!(d["resolution"]["status"], "active");
        assert_eq!(d["resolution"]["postFixOccurrences"], 0);
    }

    #[test]
    fn bucket_detail_defaults_to_implicit_untriaged_with_no_triage_or_ticket() {
        let r = rec("boom", "c", "home", &["tap:key:id:save"]);
        let repro = serde_json::json!({ "status": "ready", "attempts": 0 });
        let res = resolution::Outcome {
            status: resolution::Resolution::Active,
            fixed_in_build: None,
            last_seen_on_fixed_build: None,
            post_fix_occurrences: 0,
        };
        let d = bucket_detail(
            "app",
            "bkt_x",
            &r,
            &r,
            None,
            1,
            Vec::new(),
            Vec::new(),
            repro,
            None,
            None,
            &res,
        );
        // A never-touched bucket reads as `untriaged`, no ticket.
        assert_eq!(d["triage"]["status"], "untriaged");
        assert_eq!(d["triage"]["updatedAt"], Value::Null);
        assert_eq!(d["triage"]["fixedInBuild"], Value::Null);
        assert_eq!(d["ticket"], Value::Null);
        // No fix claimed => prod-truth is active.
        assert_eq!(d["resolution"]["status"], "active");
    }
}
