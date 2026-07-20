//! Production telemetry ingestion.
//!
//! Receives strict versioned event batches, merges graph-edge frames into a usage
//! graph in Postgres, persists typed findings, and stores immutable evidence
//! graphs by content hash. The payoff is the
//! bucket package endpoint: it converts a production error bucket into a
//! deterministic replay the runner can execute, turning a prod "cannot
//! reproduce" into a reproducible test.
//!
//! The state signatures here are the SAME ones the runner produces, so this
//! production graph aligns 1:1 with the test app map.

mod aggregation;
mod bucket_api;
pub(crate) mod buckets;
pub(crate) mod cohorts;
mod evidence;
mod export;
pub(crate) mod impact;
mod replay;

use crate::tenancy::resolver::Tenant;
use crate::App;
use axum::body::Bytes;
use axum::extract::{Multipart, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde_json::{json, Map, Value};

// Cohort/discriminator analysis lives in `cohorts`; handlers reach for these two.
// `fixture_spec` is part of the public API, so re-export it at `crate::ingest`.
use aggregation::{aggregate_events, BatchAgg};
pub(crate) use bucket_api::bucket_list_for_tenant;
#[cfg(test)]
use bucket_api::bucket_package;
use bucket_api::{bucket_error_ids, resolve_evidence};
pub use bucket_api::{get_bucket, get_bucket_global, get_buckets, get_ticket, post_ticket};
use cohorts::discriminators;
pub use cohorts::fixture_spec;
#[cfg(test)]
use evidence::evidence_kind;
pub use evidence::{get_blob, get_bucket_evidence, post_bucket_evidence};
pub use export::get_export;
pub use replay::{get_cloud_runs, get_replay_results, post_replay_results, post_reproduce};

/// Per-file cap on a multipart evidence part. field.bytes() buffers the whole
/// part, so an oversize part is rejected with 413 rather than read into memory.
const MAX_EVIDENCE_FIELD_BYTES: usize = 25 * 1024 * 1024;

/// Default aggregate evidence cap per app, including human original captures.
/// This is a product guardrail against one tenant/API key filling shared object
/// storage; self-host can set
/// REPROIT_MAX_EVIDENCE_BYTES_PER_APP=0 to disable it.
const DEFAULT_MAX_EVIDENCE_BYTES_PER_APP: i64 = 10 * 1024 * 1024 * 1024;

/// Hard cap on how many error rows a single grouping read (the bucket list /
/// detail views) will pull into memory, so one pathological app can't load its
/// entire (potentially millions) error history on every dashboard request.
/// Tunable via `REPROIT_MAX_ERROR_SCAN`; defaults high so normal apps are never
/// affected. When the cap IS hit we LOG a warning naming the dropped count, never
/// truncate silently (the most recent occurrences fall outside the window).
const DEFAULT_MAX_ERROR_SCAN: i64 = 200_000;

/// Resolve the error-scan cap from the environment, falling back to the default.
/// A non-positive or unparseable value falls back rather than disabling the cap.
fn max_error_scan() -> i64 {
    std::env::var("REPROIT_MAX_ERROR_SCAN")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_ERROR_SCAN)
}

/// The bounded recency sample that stands in for "the whole app history" in
/// baseline/denominator computations (discriminators, build ordering, post-fix
/// traffic). Tunable via REPROIT_BASELINE_SAMPLE.
pub(crate) fn baseline_sample() -> i64 {
    std::env::var("REPROIT_BASELINE_SAMPLE")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(20_000)
}

pub(crate) fn max_evidence_bytes_per_app() -> Option<i64> {
    std::env::var("REPROIT_MAX_EVIDENCE_BYTES_PER_APP")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .map(|n| (n > 0).then_some(n))
        .unwrap_or(Some(DEFAULT_MAX_EVIDENCE_BYTES_PER_APP))
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ErrorRec {
    pub sig: String,
    pub message: String,
    pub path: Vec<Step>,
    /// PII-safe context dimensions at error time (locale, role, plan, hashed
    /// uid, derived input features, ...). The discriminator for "happens to some
    /// users, not others" lives here, never in the structural signature.
    #[serde(default)]
    pub context: Map<String, Value>,
}

pub(crate) const NIMBUS_SAMPLE: &str = "nimbus-shop";

/// Identify Cloud's bundled NimbusShop checkout sample by its explicit marker.
pub(crate) fn sample_kind(rec: &ErrorRec) -> Option<&'static str> {
    (rec.context.get("reproitSample").and_then(Value::as_str) == Some(NIMBUS_SAMPLE))
        .then_some(NIMBUS_SAMPLE)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Step {
    pub sig: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// A stored piece of repro evidence (mp4/gif/png) attached to a finding. The
/// bytes live in object storage; this is the metadata + storage key recorded in
/// Postgres. `url` is filled in at serialization time (presigned R2 or the
/// cloud-proxied `/v1/blob/<key>` path), never persisted, since it's transient.
#[derive(Clone, serde::Serialize)]
pub struct EvidenceRec {
    pub kind: String,
    pub key: String,
    pub bytes: i64,
    pub ts: String,
    pub url: String,
}

/// One reproduction attempt recorded against a bucket (local CLI or a cloud
/// worker). The trust signal: a bucket that reproduces 8/10 is real; one that
/// is not reproduced in 10/10 attempts needs investigation or fix verification.
#[derive(Clone, serde::Serialize)]
pub struct ReplayResult {
    pub status: String,
    pub runs: i32,
    pub failures: i32,
    pub local_repro_id: Option<String>,
    pub created_at: String,
}

fn visual_evidence_role(kind: &str) -> Option<&'static str> {
    match kind {
        "mp4" | "gif" => Some("clip"),
        "png" | "jpg" | "jpeg" => Some("screenshot"),
        _ => None,
    }
}

fn visual_evidence_refs(evidence: &[EvidenceRec]) -> Value {
    let mut clips = Vec::new();
    let mut screenshots = Vec::new();
    let mut paths = Vec::new();
    let mut items = Vec::new();

    for ev in evidence {
        let Some(role) = visual_evidence_role(&ev.kind) else {
            continue;
        };
        let item = json!({
            "kind": ev.kind.clone(),
            "role": role,
            "key": ev.key.clone(),
            "path": ev.key.clone(),
            "url": ev.url.clone(),
            "bytes": ev.bytes,
            "ts": ev.ts.clone(),
        });
        paths.push(ev.key.clone());
        match role {
            "clip" => clips.push(item.clone()),
            "screenshot" => screenshots.push(item.clone()),
            _ => {}
        }
        items.push(item);
    }

    json!({
        "count": items.len(),
        "items": items,
        "paths": paths,
        "clips": clips,
        "screenshots": screenshots,
    })
}

/// Map an internal error to a 500: log the detail server-side, return a generic
/// message. We never leak raw error strings (DB internals, paths) to clients.
fn err500<E: std::fmt::Display>(e: E) -> (StatusCode, Json<Value>) {
    tracing::error!("ingest internal error: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(crate::server_error()),
    )
}
type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

/// A 404 with no existence leak: same response for "not found" and "not yours",
/// so a cross-tenant probe can't distinguish a missing app from one it can't see.
fn not_found_err() -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(crate::not_found()))
}

/// Resolve the caller's TENANT (the database-per-org boundary) and confirm the
/// app belongs to it. Under database-per-org the cross-tenant boundary is the
/// resolved database, not a `WHERE org_id =` clause: a different tenant's app
/// simply isn't in this database. The within-tenant `owns_app` check stays only to
/// keep one org's user from naming a project that doesn't exist in their org, and
/// returns 404 (never confirming an app the caller can't see).
///
/// Call at the TOP of every app-scoped handler; the returned `Tenant` is what its
/// data reads/writes go through.
pub(crate) async fn tenant_for(
    app: &App,
    auth: crate::AuthCtx,
    headers: &HeaderMap,
    app_id: &str,
) -> Result<Tenant, (StatusCode, Json<Value>)> {
    let tenant = app.tenant_of(auth, headers).await?;
    match tenant.store.owns_app(app_id).await {
        Ok(true) => Ok(tenant),
        Ok(false) => Err(not_found_err()),
        Err(e) => {
            tracing::error!("owns_app check failed for app {app_id}: {e}");
            Err(not_found_err())
        }
    }
}

/// GET /v1/me: a minimal "who am I" probe for `reproit login` to validate a
/// key without naming an app. Resolves the caller's tenant via the existing
/// AuthCtx/`tenant_of` path and returns the projects visible to that credential.
/// An org-level account token sees the org's projects; a project key sees only
/// its own project. A bad key never reaches here because `require_api_key` fails
/// closed with 401.
pub async fn get_me(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    Extension(scope): Extension<crate::KeyScope>,
    headers: HeaderMap,
) -> ApiResult {
    let tenant = app.tenant_of(auth, &headers).await?;
    let mut projects = tenant.store.list_projects().await.map_err(err500)?;
    if let Some(project_id) = scope.project_id {
        projects.retain(|(id, _, _)| *id == project_id);
    }
    Ok(Json(json!({
        "orgId": tenant.org_id,
        "projectCount": projects.len(),
        "projects": projects.into_iter().map(|(id, name, app_id)| json!({
            "id": id, "name": name, "appId": app_id
        })).collect::<Vec<_>>(),
    })))
}

/// POST /v1/apps/:app/publishable-key: mint a fresh browser-safe write-only key
/// using an authenticated secret project key. The full key is returned once and
/// older publishable keys for the project are revoked, giving setup a secure
/// rotation path without ever embedding its management credential in the app.
pub async fn post_publishable_key(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    Extension(scope): Extension<crate::KeyScope>,
    headers: HeaderMap,
    Path(app_id): Path<String>,
) -> ApiResult {
    if scope.publishable {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "a secret key is required to rotate the publishable key" })),
        ));
    }
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    let project_id = tenant
        .store
        .project_id_for_app(&app_id)
        .await
        .map_err(err500)?
        .ok_or_else(not_found_err)?;
    if scope.project_id.is_some() && scope.project_id != Some(project_id) {
        return Err(not_found_err());
    }
    let user_id = scope.user_id.ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "a project secret key is required" })),
        )
    })?;
    let org_id = match auth {
        crate::AuthCtx::Org(id) => id,
        crate::AuthCtx::Admin => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "use a project secret key, not the admin key" })),
            ))
        }
    };
    app.control
        .revoke_publishable_keys_for_project(project_id)
        .await
        .map_err(err500)?;
    let key = crate::auth::new_publishable_key();
    let prefix = crate::auth::api_key_prefix(&key);
    app.control
        .create_api_key(&key, &prefix, org_id, user_id, Some(project_id))
        .await
        .map_err(err500)?;
    app.control
        .audit(
            &format!("user:{user_id}"),
            "apikey.publishable.rotate",
            Some(org_id),
            json!({ "project": project_id, "prefix": prefix }),
        )
        .await;
    Ok(Json(json!({
        "appId": app_id,
        "publishableKey": key,
        "publishableKeyPrefix": prefix,
    })))
}

/// Page size for the export's keyset reads: big enough that a large tenant is
/// a few hundred round-trips, small enough that one page is never a memory
/// event.
/// POST /v1/events, ingest one strict protocol batch.
pub async fn post_events(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    Extension(scope): Extension<crate::KeyScope>,
    headers: HeaderMap,
    Json(batch): Json<reproit_protocol::EventBatch>,
) -> ApiResult {
    batch.validate().map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": error.reason.as_str() })),
        )
    })?;
    let app_id = batch.app_id.clone();
    // Resolve the caller's tenant DB; the app_id is caller-supplied (body), so it
    // must be a project that exists in this tenant.
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    // Publishable keys are project-pinned: a pk_live_ lifted from one page must
    // not inject telemetry into the org's OTHER projects (issue spam, quota
    // burn). The key's minted project id must match the posted app. Org-wide
    // secret keys and the admin key are not restricted.
    if scope.publishable {
        let posted = tenant
            .store
            .project_id_for_app(&app_id)
            .await
            .map_err(|e| {
                tracing::error!("project_id_for_app failed for app {app_id}: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "internal error" })),
                )
            })?;
        if scope.project_id.is_none() || posted != scope.project_id {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "this publishable key is not valid for this appId; use the pk_live_ key minted for this project"
                })),
            ));
        }
    }
    let app_configured = crate::integrations::is_configured_for(&tenant.store, &app_id).await;
    // Collect the whole batch in memory FIRST, then write it in one transaction.
    // Edges are pre-aggregated by key (the `edges` PK is (app_id, edge_key), so a
    // single multi-row upsert can only touch each row once; duplicate keys within
    // the batch must be summed here and applied as one delta). Errors are gathered
    // in arrival order so the in-batch bucket grouping below sees oldest-first.
    let BatchAgg {
        edge_counts,
        error_recs,
    } = aggregate_events(&batch.frames);
    let n_edges = edge_counts.values().map(|c| *c as u64).sum::<u64>();
    let n_errors = error_recs.len() as u64;
    // ONE atomic transaction for the whole batch: a multi-row edge upsert plus a
    // multi-row error insert, all-or-nothing, instead of up to 5000 awaited
    // auto-commit statements. The edge deltas carry the in-batch sums computed
    // above so a key repeated in the batch lands as a single increment.
    let edges: Vec<(String, i64)> = edge_counts.into_iter().collect();
    let deduped = tenant
        .store
        .ingest_batch(
            &app_id,
            &edges,
            &error_recs,
            &batch.evidence,
            &batch.batch_id,
            batch.deployment.as_ref().and_then(|value| value.key()),
        )
        .await
        .map_err(err500)?;
    if deduped {
        metrics::counter!("ingest_batches_deduped_total").increment(1);
        return Ok(Json(json!({ "ok": true, "deduped": true })));
    }
    metrics::counter!("ingest_batches_total").increment(1);
    metrics::counter!("ingest_errors_total").increment(n_errors);
    metrics::counter!("ingest_edges_total").increment(n_edges);
    // file-on-form: for a configured app, file an issue for any bucket this batch
    // touched that doesn't already have a linked ticket. We derive the touched
    // buckets and their oldest/newest occurrence from THIS batch's errors (already
    // in hand), rather than re-reading and re-grouping the app's whole history on
    // every ingest. Best-effort and PII-safe (the hook builds the body from
    // derived bucket data only) and never blocks ingest, a tracker outage is
    // logged and swallowed inside the hook.
    if app_configured && !error_recs.is_empty() {
        maybe_file_new_buckets(&tenant, &app_id, &error_recs).await;
    }
    let captures: Vec<String> = error_recs
        .iter()
        .filter(|record| buckets::is_tester_capture(record))
        .map(buckets::bucket_id)
        .collect();
    let mut body = json!({
        "ok": true,
        "ingested": {
            "edges": n_edges,
            "errors": n_errors,
            "evidenceGraphs": batch.evidence.len(),
        }
    });
    if !captures.is_empty() {
        body["captures"] = json!(captures);
    }
    Ok(Json(body))
}

/// Resolve each bucket TOUCHED BY THIS BATCH to its oldest/newest occurrence and
/// hand it to the file-on-form hook. Bounded by construction: it groups only the
/// errors that just arrived (passed in by the caller), never the app's whole
/// history, so the per-ingest cost is the size of THIS batch, not the lifetime
/// error count. The hook itself is the idempotency guard: it skips any bucket
/// that already has a linked ticket, so a bucket only ever files once even across
/// many batches (and a bucket seen before this batch, but unfiled, still files
/// the first time the integration sees it touched). Operates entirely within ONE
/// tenant's database.
///
/// "Oldest/newest" here are the oldest and newest occurrence WITHIN this batch.
/// The batch arrives in order, so grouping it directly preserves that ordering;
/// the issue body is built from PII-safe derived bucket data either way, so using
/// the batch's own endpoints (rather than re-reading full history for an exact
/// lineage) is correct for the file-once decision.
async fn maybe_file_new_buckets(tenant: &Tenant, app_id: &str, batch_errors: &[ErrorRec]) {
    // Group THIS batch's errors by bucket id, keeping first/last in arrival order.
    let mut by_bucket: std::collections::BTreeMap<String, (ErrorRec, ErrorRec)> =
        std::collections::BTreeMap::new();
    for rec in batch_errors {
        // A tester capture is deliberately not a confirmed bug yet. Filing an
        // issue here would bypass the replay trust gate. It becomes eligible for
        // normal workflows only after a reproduced replay result.
        if buckets::is_tester_capture(rec) {
            continue;
        }
        let bid = buckets::bucket_id(rec);
        by_bucket
            .entry(bid)
            .and_modify(|(_, newest)| *newest = rec.clone())
            .or_insert_with(|| (rec.clone(), rec.clone()));
    }
    for (bid, (oldest, newest)) in by_bucket {
        crate::integrations::file_issue_for_bucket(&tenant.store, app_id, &bid, &oldest, &newest)
            .await;
    }
}

/// GET /v1/graph/:app, the merged production usage graph.
pub async fn get_graph(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path(app_id): Path<String>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    let edges = tenant.store.edges(&app_id).await.map_err(err500)?;
    let mut states = std::collections::BTreeSet::new();
    let edge_list: Vec<Value> = edges
        .iter()
        .map(|(k, c)| {
            let p: Vec<&str> = k.split('|').collect();
            let from = p.first().copied().unwrap_or("");
            let to = p.get(2).copied().unwrap_or("");
            for s in [from, to] {
                if !s.is_empty() && s != "\u{2205}" {
                    states.insert(s.to_string());
                }
            }
            json!({ "from": from, "action": p.get(1).copied().unwrap_or(""), "to": to, "count": c })
        })
        .collect();
    Ok(Json(
        json!({ "appId": app_id, "states": states.len(), "edges": edge_list }),
    ))
}

/// Return the independently validated immutable proof ledger for one run.
pub async fn get_run_proof(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path((app_id, run_id)): Path<(String, String)>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    let Some((root, ledger)) = tenant
        .store
        .proof_ledger(&app_id, &run_id)
        .await
        .map_err(err500)?
    else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "proof ledger not found" })),
        ));
    };
    Ok(Json(json!({
        "appId": app_id,
        "runId": run_id,
        "graphRoot": root,
        "ledger": ledger,
    })))
}

/// Default page size for the flat `/errors` list when the caller doesn't pass an
/// explicit `limit`, and the ceiling we clamp any caller-supplied `limit` to, so
/// this endpoint can never be asked to materialize an unbounded result set.
const ERRORS_PAGE_DEFAULT: i64 = 500;
const ERRORS_PAGE_MAX: i64 = 5000;

/// GET /v1/errors/:app, production errors, each with its graph path. PAGINATED:
/// `?limit=&offset=` give a bounded slice (id order), so this read never loads
/// the whole table. `limit` defaults to `ERRORS_PAGE_DEFAULT` and is clamped to
/// `ERRORS_PAGE_MAX`; the response carries the app's `total` for the client.
pub async fn get_errors(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path(app_id): Path<String>,
    axum::extract::Query(page): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    let limit = page
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(ERRORS_PAGE_DEFAULT)
        .min(ERRORS_PAGE_MAX);
    let offset = page
        .get("offset")
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .unwrap_or(0);
    let (errs, total) = tenant
        .store
        .errors_paginated(&app_id, limit, offset)
        .await
        .map_err(err500)?;
    Ok(Json(
        json!({ "appId": app_id, "count": errs.len(), "total": total, "limit": limit, "offset": offset, "errors": errs }),
    ))
}

/// REAL per-day occurrence counts for the trailing 14 calendar days (UTC),
/// oldest day first, newest day last. Built from `(created_at_rfc3339, build)`
/// pairs via the same pure `buckets::timeline` shaping the seat-gated bucket
/// timeline uses (a one-DAY window), then projected onto a fixed 14-slot grid
/// anchored on today so the array length is stable for the chart. Occurrences
/// older than 14 days fall outside the grid (the chart is "last 14 days"); a
/// timestamp that doesn't parse lands in window 0 and is simply outside the
/// recent grid. No synthesis: an empty cohort yields fourteen zeros, and a
/// cohort whose occurrences all share one day yields a single non-zero slot.
fn daily_counts_last_14(series: &[(String, Option<String>)]) -> Vec<u64> {
    const DAY: i64 = 86_400;
    let tl = buckets::timeline(series, DAY);
    // window_start_epoch -> total count for that day.
    let mut by_day: std::collections::HashMap<i64, u64> = std::collections::HashMap::new();
    for c in &tl.total {
        if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&c.window) {
            let day = t.timestamp().div_euclid(DAY) * DAY;
            *by_day.entry(day).or_default() += c.count;
        }
    }
    // Anchor the 14-slot grid on today's UTC day so the newest slot is "today".
    let today = chrono::Utc::now().timestamp().div_euclid(DAY) * DAY;
    (0..14)
        .map(|i| {
            // i=0 is 13 days ago (oldest), i=13 is today (newest).
            let day = today - (13 - i as i64) * DAY;
            *by_day.get(&day).unwrap_or(&0)
        })
        .collect()
}

/// GET /v1/errors/:app/cohorts, errors grouped by signature, each with its
/// occurrence count, a sample message, and the context DISCRIMINATOR: the
/// dimension(s) over-represented among the users who hit it vs the app baseline.
/// This is the "happens to some users, not others" answer.
pub async fn get_cohorts(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path(app_id): Path<String>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    // Pull occurrences WITH timestamps (errors_with_meta), not the bare errors()
    // form, so the open findings view can carry a REAL per-day occurrence series
    // (the "incidents over time" chart) alongside each cohort. The timestamp is
    // the same created_at the seat-gated bucket timeline buckets by.
    // Bounded grouping scan: cap how many occurrences we materialize. Cap-hit LOGS
    // the dropped count (never silent truncation); the oldest rows are kept so each
    // cohort's grouping/discriminator stays exact for occurrences in the window.
    let (occ, dropped) = tenant
        .store
        .errors_with_meta_capped(&app_id, max_error_scan())
        .await
        .map_err(err500)?;
    if dropped > 0 {
        tracing::warn!(
            "get_cohorts: error scan for {app_id} hit the cap; {dropped} most-recent rows excluded \
             from cohort grouping (raise REPROIT_MAX_ERROR_SCAN to include them)"
        );
    }
    let baseline: Vec<Map<String, Value>> =
        occ.iter().map(|(_, _, r, _)| r.context.clone()).collect();
    // group by signature, carrying (created_at, ErrorRec) so we can both build the
    // discriminator (needs context) and the daily series (needs the timestamp).
    let mut by_sig: std::collections::BTreeMap<String, Vec<(&str, &ErrorRec)>> = Default::default();
    for (_, ts, r, _) in &occ {
        by_sig
            .entry(r.sig.clone())
            .or_default()
            .push((ts.as_str(), r));
    }
    let mut clusters: Vec<Value> = by_sig
        .into_iter()
        .map(|(sig, group)| {
            let cohort: Vec<Map<String, Value>> =
                group.iter().map(|(_, e)| e.context.clone()).collect();
            // REAL per-day occurrence counts for the last 14 days (oldest->newest),
            // derived from this cohort's own occurrence timestamps via the same
            // pure timeline shaping the bucket timeline uses (DAY window). Honest:
            // if every occurrence shares one timestamp the array is a single spike.
            let series: Vec<(String, Option<String>)> =
                group.iter().map(|(ts, _)| (ts.to_string(), None)).collect();
            json!({
                "sig": sig,
                "count": group.len(),
                "message": group.first().map(|(_, e)| e.message.clone()).unwrap_or_default(),
                "discriminators": discriminators(&cohort, &baseline),
                "daily14": daily_counts_last_14(&series),
            })
        })
        .collect();
    clusters.sort_by(|a, b| {
        b["count"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["count"].as_u64().unwrap_or(0))
    });
    Ok(Json(
        json!({ "appId": app_id, "clusters": clusters.len(), "errors": clusters }),
    ))
}

// ---- evidence: store / serve repro artifacts ------------------------------

/// Map a content-type or filename extension to a normalized evidence kind.
/// Unknown types are stored as "blob" rather than rejected, we'd rather keep
/// the artifact than lose a repro because of a missing mime.
#[cfg(test)]
mod tests;
