//! Production telemetry ingestion.
//!
//! Receives the marker-protocol graph the `reproit-web` SDK emits from REAL
//! users, merges it into a usage graph (edges + traversal counts) in Postgres,
//! and stores errors WITH the graph path that produced them. The payoff is the
//! bucket package endpoint: it converts a production error bucket into a
//! deterministic replay the runner can execute, turning a prod "cannot
//! reproduce" into a reproducible test.
//!
//! The state signatures here are the SAME ones the runner produces, so this
//! production graph aligns 1:1 with the test app map.

pub(crate) mod buckets;
pub(crate) mod cohorts;
pub(crate) mod impact;

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
use cohorts::discriminators;
pub use cohorts::fixture_spec;

/// Largest event batch we ingest in one POST /v1/events. Past this we reject
/// before touching the DB: an oversized array is abuse, not a real session.
const MAX_EVENTS_PER_BATCH: usize = 5000;

/// Per-file cap on a multipart evidence part. field.bytes() buffers the whole
/// part, so an oversize part is rejected with 413 rather than read into memory.
const MAX_EVIDENCE_FIELD_BYTES: usize = 25 * 1024 * 1024;

/// Per-field caps inside an ingested event. The 32MB body limit bounds the
/// request, but without these one hostile event could still park megabytes in a
/// single error row (message/context/path) and every later read pays for it.
/// Oversized strings are TRUNCATED (a clipped crash message still buckets and
/// displays); an oversized context is dropped to a marker (a partial context is
/// worse than none for fixture synthesis).
const MAX_ERROR_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_STEP_FIELD_BYTES: usize = 1024;
const MAX_LABEL_BYTES: usize = 256;
const MAX_PATH_STEPS: usize = 256;
const MAX_CONTEXT_BYTES: usize = 64 * 1024;

/// Cap on an accepted oracle id at the ingest gate. Registry ids are short
/// structural tokens (`choice-anomaly`, `blank-screen`); anything longer is not a
/// real category and is dropped rather than allowed to open a bucket.
const MAX_ORACLE_ID_BYTES: usize = 64;

/// Truncate to at most `max` bytes on a char boundary.
fn clipped(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Default aggregate evidence cap per app. This is a product guardrail against
/// one tenant/API key filling shared object storage; self-host can set
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

fn max_evidence_bytes_per_app() -> Option<i64> {
    std::env::var("REPROIT_MAX_EVIDENCE_BYTES_PER_APP")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .map(|n| (n > 0).then_some(n))
        .unwrap_or(Some(DEFAULT_MAX_EVIDENCE_BYTES_PER_APP))
}

fn merge_context(base: &Map<String, Value>, event: &Value) -> Map<String, Value> {
    let mut context = base.clone();
    // `ctx` was the original per-event context spelling. SDKs now put the
    // PII-safe on-error fingerprint under `context.fingerprint`; accept both so
    // older clients keep working and production replay keeps its fixture input.
    for key in ["ctx", "context"] {
        if let Some(ectx) = event.get(key).and_then(|v| v.as_object()) {
            for (k, v) in ectx {
                context.insert(k.clone(), v.clone());
            }
        }
    }
    context
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
/// is clean 10/10 is fixed or data-dependent.
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

/// GET /v1/me: a minimal "who am I" probe for `reproit cloud login` to VALIDATE a
/// key without naming an app. Resolves the caller's tenant via the existing
/// AuthCtx/`tenant_of` path and returns `{ orgId, projects: <count> }` (no PII, no
/// secrets, no project ids). A bad key never reaches here (require_api_key fails
/// closed with 401); a valid key resolves to its org.
pub async fn get_me(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
) -> ApiResult {
    let tenant = app.tenant_of(auth, &headers).await?;
    let projects = tenant.store.count_projects().await.map_err(err500)?;
    Ok(Json(json!({
        "orgId": tenant.org_id,
        "projects": projects,
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
const EXPORT_PAGE: i64 = 1000;

/// GET /v1/apps/:app/export: the tenant PORTABILITY export (GDPR article 20,
/// the read counterpart the offboard deletion assumes exists). Streams
/// everything the cloud holds for one app as newline-delimited JSON, one
/// object per line, in a fixed order:
///
///   1. one `{"kind":"app", ...}` header (org, export time, retention window),
///   2. the bucket triage metadata (`kind":"bucket"`),
///   3. error rows within the retention window, oldest first (`"kind":"error"`),
///   4. evidence blob KEYS (`"kind":"evidence"`; bytes stay in object storage,
///      fetch each via `GET /v1/blob/<key>`).
///
/// The body is produced by a spawned task paging the tenant DB with keyset
/// reads and writing lines into a bounded channel, so an export never
/// materializes a tenant's error history in memory; backpressure from a slow
/// client simply pauses the paging.
pub async fn get_export(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path(app_id): Path<String>,
) -> Response {
    let tenant = match tenant_for(&app, auth, &headers, &app_id).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    // Hosted: bound the export to the plan's retention window; rows past it
    // are already queued for deletion, and an export must not resurrect data
    // the retention contract says is gone. Self-host owns its retention, so it
    // exports everything.
    let days = None;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<String, std::io::Error>>(8);
    tokio::spawn(export_stream(tenant, app_id, days, tx));
    (
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        axum::body::Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx)),
    )
        .into_response()
}

/// The paged producer behind `get_export`: writes NDJSON lines into the body
/// channel. A DB error mid-stream sends an `Err` into the body, which ABORTS
/// the HTTP response (the client sees a broken stream, never a silently
/// truncated export presented as complete), and is logged server-side. A
/// closed channel (client went away) just stops paging.
async fn export_stream(
    tenant: Tenant,
    app_id: String,
    days: Option<i64>,
    tx: tokio::sync::mpsc::Sender<Result<String, std::io::Error>>,
) {
    async fn line(
        tx: &tokio::sync::mpsc::Sender<Result<String, std::io::Error>>,
        v: Value,
    ) -> bool {
        tx.send(Ok(format!("{v}\n"))).await.is_ok()
    }
    async fn abort(
        tx: &tokio::sync::mpsc::Sender<Result<String, std::io::Error>>,
        app_id: &str,
        what: &str,
        e: anyhow::Error,
    ) {
        tracing::error!("export for {app_id}: {what} failed: {e}");
        let _ = tx.send(Err(std::io::Error::other("export aborted"))).await;
    }

    // 1. The header line: what this export is and how it was bounded.
    let head = json!({
        "kind": "app",
        "app": app_id,
        "org": tenant.org_id,
        "exportedAt": chrono::Utc::now().to_rfc3339(),
        "retentionDays": days,
    });
    if !line(&tx, head).await {
        return;
    }

    // 2. Bucket triage metadata (bounded by the app's bucket count; one read).
    //    Sorted by bucket id so the export is deterministic and diffable.
    match tenant.store.triage_all_for_app(&app_id).await {
        Ok(triage) => {
            let mut buckets: Vec<_> = triage.into_iter().collect();
            buckets.sort_by(|a, b| a.0.cmp(&b.0));
            for (bucket, t) in buckets {
                let v = json!({
                    "kind": "bucket",
                    "bucket": bucket,
                    "status": t.status,
                    "assignee": t.assignee,
                    "fixedInBuild": t.fixed_in_build,
                    "updatedAt": t.updated_at,
                });
                if !line(&tx, v).await {
                    return;
                }
            }
        }
        Err(e) => return abort(&tx, &app_id, "triage read", e).await,
    }

    // 3. Error rows within retention, oldest first, keyset-paged.
    let mut after = 0i64;
    loop {
        let page = match tenant
            .store
            .export_errors_page(&app_id, days, after, EXPORT_PAGE)
            .await
        {
            Ok(p) => p,
            Err(e) => return abort(&tx, &app_id, "error page read", e).await,
        };
        let n = page.len() as i64;
        let Some(last) = page.last() else { break };
        after = last.0;
        for (id, at, bucket, rec) in page {
            let v = json!({
                "kind": "error",
                "id": id,
                "at": at,
                "bucket": bucket,
                "sig": rec.sig,
                "message": rec.message,
                "path": rec.path,
                "context": rec.context,
            });
            if !line(&tx, v).await {
                return;
            }
        }
        if n < EXPORT_PAGE {
            break;
        }
    }

    // 4. Evidence blob keys, keyset-paged like the errors.
    let mut after = 0i64;
    loop {
        let page = match tenant
            .store
            .export_evidence_page(&app_id, after, EXPORT_PAGE)
            .await
        {
            Ok(p) => p,
            Err(e) => return abort(&tx, &app_id, "evidence page read", e).await,
        };
        let n = page.len() as i64;
        let Some(last) = page.last() else { break };
        after = last.0;
        for (id, error_id, kind, key, bytes, at) in page {
            let v = json!({
                "kind": "evidence",
                "id": id,
                "errorId": error_id,
                "evidenceKind": kind,
                "key": key,
                "bytes": bytes,
                "at": at,
            });
            if !line(&tx, v).await {
                return;
            }
        }
        if n < EXPORT_PAGE {
            break;
        }
    }
}

/// The oracle gate for POST /v1/events: an error may open a bucket ONLY if it
/// carries a well-formed oracle id. The check is PRESENCE + WELL-FORMEDNESS, NOT
/// registry membership -- a well-formed but unrecognized id can come from a newer
/// CLI/SDK than this cloud build, and the registry contract says consumers must
/// degrade gracefully on an unknown id rather than drop a finding, so it passes.
/// A missing, empty, over-length, or non-token id is rejected. Well-formed is a
/// bounded lowercase token: ascii a-z, 0-9, '-' and '_' (registry ids such as
/// `choice-anomaly` pass; uppercase, spaces, and other punctuation do not).
/// Uncaught crashes reach here as oracle:"crash", so they pass the gate.
fn oracle_well_formed(oracle: &str) -> bool {
    !oracle.is_empty()
        && oracle.len() <= MAX_ORACLE_ID_BYTES
        && oracle
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Retired findings are rejected at ingest so older clients cannot make them
/// resurface in triage. Some old structural checks shared the broad `graph` or
/// `invariant` category, so match those by their precise invariant/message shape
/// and leave unrelated graph, permission-walk, keyboard, and custom invariants
/// intact.
fn retired_oracle(event: &Value, oracle: &str) -> bool {
    if matches!(oracle, "dynamic-type" | "overflow" | "undo-inverse") {
        return true;
    }
    let invariant = event.get("invariant").and_then(Value::as_str).or_else(|| {
        event
            .get("context")
            .and_then(Value::as_object)
            .and_then(|ctx| ctx.get("invariant"))
            .and_then(Value::as_str)
    });
    if matches!(
        invariant,
        Some("no-dead-control" | "no-dead-end" | "no-dynamic-type-clip" | "no-undo-residue")
    ) {
        return true;
    }
    let message = event
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();

    (oracle == "graph"
        && (message.contains("dead control")
            || message.contains("dead end")
            || message.contains("dead-end")))
        || (oracle == "invariant"
            && (message.contains("unlabeled tappable") || message.contains("accessible name")))
}

/// One batch's events reduced to what the write needs: edge deltas summed by key,
/// the accepted error occurrences, and the count of error events the oracle gate
/// dropped (surfaced to the caller so an SDK emitting untagged errors sees it).
struct BatchAgg {
    edge_counts: std::collections::HashMap<String, i64>,
    error_recs: Vec<ErrorRec>,
    dropped_untagged: u64,
}

/// Scan a batch's events into edge deltas and gated error occurrences. Pure over
/// its inputs (no DB), so the oracle gate and in-batch edge summing stay
/// unit-testable without a tenant. Edge keys repeated within the batch are summed
/// here (the `edges` PK is (app_id, edge_key), so a multi-row upsert can touch
/// each row only once). Error events without a well-formed oracle id are gated
/// out before any ErrorRec forms and counted; only tagged findings become
/// buckets. `edge` and every other kind are unaffected by the gate.
fn aggregate_events(events: &[Value], batch_ctx: &Map<String, Value>) -> BatchAgg {
    let mut edge_counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    let mut error_recs: Vec<ErrorRec> = Vec::new();
    let mut dropped_untagged: u64 = 0;
    for ev in events {
        match ev.get("kind").and_then(|v| v.as_str()) {
            Some("edge") => {
                let from = clipped(
                    ev.get("from")
                        .and_then(|v| v.as_str())
                        .unwrap_or("\u{2205}"),
                    MAX_STEP_FIELD_BYTES,
                );
                let action = clipped(
                    ev.get("action").and_then(|v| v.as_str()).unwrap_or("auto"),
                    MAX_STEP_FIELD_BYTES,
                );
                let to = clipped(
                    ev.get("to").and_then(|v| v.as_str()).unwrap_or("?"),
                    MAX_STEP_FIELD_BYTES,
                );
                let key = format!("{from}|{action}|{to}");
                *edge_counts.entry(key).or_insert(0) += 1;
            }
            Some("error") => {
                // Oracle gate: reject before building an ErrorRec so an untagged
                // or malformed finding never opens a bucket. Presence is the
                // `Some(..)` bind; well-formedness is the filter. See
                // oracle_well_formed for why an unknown-but-valid id passes.
                let Some(oracle) = ev
                    .get("oracle")
                    .and_then(|v| v.as_str())
                    .filter(|o| oracle_well_formed(o))
                else {
                    dropped_untagged += 1;
                    continue;
                };
                if retired_oracle(ev, oracle) {
                    dropped_untagged += 1;
                    continue;
                }
                let sig = clipped(
                    ev.get("sig").and_then(|v| v.as_str()).unwrap_or("?"),
                    MAX_STEP_FIELD_BYTES,
                );
                let message = clipped(
                    ev.get("message").and_then(|v| v.as_str()).unwrap_or(""),
                    MAX_ERROR_MESSAGE_BYTES,
                );
                let path: Vec<Step> = ev
                    .get("path")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .take(MAX_PATH_STEPS)
                            .filter_map(|s| {
                                Some(Step {
                                    sig: clipped(s.get("sig")?.as_str()?, MAX_STEP_FIELD_BYTES),
                                    action: clipped(
                                        s.get("action")?.as_str()?,
                                        MAX_STEP_FIELD_BYTES,
                                    ),
                                    label: s
                                        .get("label")
                                        .and_then(|v| v.as_str())
                                        .filter(|s| !s.trim().is_empty())
                                        .map(|s| clipped(s.trim(), MAX_LABEL_BYTES)),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let mut context = merge_context(batch_ctx, ev);
                // The SDK emits the same framework-neutral structural identity
                // the CLI writes beside a prelaunch finding. Preserve only a
                // fully typed, bounded object. Never trust a caller-supplied
                // `bugId`; the service recomputes it from these fields.
                let finding_identity = ev
                    .get("findingIdentity")
                    .cloned()
                    .and_then(|value| {
                        serde_json::from_value::<buckets::FindingIdentity>(value).ok()
                    })
                    .filter(|identity| {
                        [
                            identity.oracle.as_str(),
                            identity.invariant.as_str(),
                            identity.kind.as_str(),
                            identity.message.as_str(),
                            identity.frame.as_str(),
                            identity.trigger.as_str(),
                            identity.boundary.as_deref().unwrap_or(""),
                        ]
                        .iter()
                        .all(|field| field.len() <= MAX_STEP_FIELD_BYTES)
                    });
                // A context past the cap is dropped whole, leaving a marker: any
                // slice of it could mislead fixture synthesis downstream.
                if Value::Object(context.clone()).to_string().len() > MAX_CONTEXT_BYTES {
                    context = Map::new();
                    context.insert("reproitContextDropped".into(), Value::Bool(true));
                }
                if let Some(identity) = finding_identity {
                    context.insert("findingIdentity".into(), json!(identity));
                }
                // The structured oracle category the finding carried (crash /
                // security / blank-screen / ...), preserved for severity classifi-
                // cation on read. Stored AFTER the cap reset so this tiny, load-
                // bearing field always survives. The gate above guarantees it is
                // present and well-formed; clipped() is kept for uniform storage.
                // See impact::severity_for_oracle.
                context.insert(
                    "oracle".into(),
                    Value::String(clipped(oracle, MAX_STEP_FIELD_BYTES)),
                );
                error_recs.push(ErrorRec {
                    sig,
                    message,
                    path,
                    context,
                });
            }
            _ => {}
        }
    }
    BatchAgg {
        edge_counts,
        error_recs,
        dropped_untagged,
    }
}

/// POST /v1/events, ingest a batch from the SDK.
pub async fn post_events(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    Extension(scope): Extension<crate::KeyScope>,
    headers: HeaderMap,
    Json(batch): Json<Value>,
) -> ApiResult {
    let app_id = batch
        .get("appId")
        .and_then(|v| v.as_str())
        .unwrap_or("app")
        .to_string();
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
    let events = batch
        .get("events")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    // Cap the batch before processing: reject an oversized array up front rather
    // than fan it out into thousands of DB writes.
    if events.len() > MAX_EVENTS_PER_BATCH {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "event batch too large" })),
        ));
    }
    // Session-level context applies to every event in the batch; an error may
    // override/extend it with its own `ctx` (context at error time).
    let batch_ctx = batch
        .get("ctx")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let app_configured = crate::integrations::is_configured_for(&tenant.store, &app_id).await;
    // Collect the whole batch in memory FIRST, then write it in one transaction.
    // Edges are pre-aggregated by key (the `edges` PK is (app_id, edge_key), so a
    // single multi-row upsert can only touch each row once; duplicate keys within
    // the batch must be summed here and applied as one delta). Errors are gathered
    // in arrival order so the in-batch bucket grouping below sees oldest-first.
    // The oracle gate lives in aggregate_events: an untagged/malformed error is
    // dropped and counted before any ErrorRec (and thus any bucket) forms.
    let BatchAgg {
        edge_counts,
        error_recs,
        dropped_untagged,
    } = aggregate_events(&events, &batch_ctx);
    let n_edges = edge_counts.values().map(|c| *c as u64).sum::<u64>();
    let n_errors = error_recs.len() as u64;
    // ONE atomic transaction for the whole batch: a multi-row edge upsert plus a
    // multi-row error insert, all-or-nothing, instead of up to 5000 awaited
    // auto-commit statements. The edge deltas carry the in-batch sums computed
    // above so a key repeated in the batch lands as a single increment.
    let edges: Vec<(String, i64)> = edge_counts.into_iter().collect();
    // Optional client idempotency key: body `batchId` or the Idempotency-Key
    // header. Consumed atomically with the write; a retried batch answers 200
    // with deduped=true and counts nothing twice.
    let batch_id = batch
        .get("batchId")
        .and_then(|v| v.as_str())
        .map(|s| clipped(s.trim(), 128))
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("idempotency-key")
                .and_then(|v| v.to_str().ok())
                .map(|s| clipped(s.trim(), 128))
                .filter(|s| !s.is_empty())
        });
    let deduped = tenant
        .store
        .ingest_batch(&app_id, &edges, &error_recs, batch_id.as_deref())
        .await
        .map_err(err500)?;
    if deduped {
        metrics::counter!("ingest_batches_deduped_total").increment(1);
        return Ok(Json(json!({ "ok": true, "deduped": true })));
    }
    metrics::counter!("ingest_batches_total").increment(1);
    metrics::counter!("ingest_errors_total").increment(n_errors);
    metrics::counter!("ingest_edges_total").increment(n_edges);
    metrics::counter!("ingest_dropped_untagged_total").increment(dropped_untagged);
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
    // Surface the gate's drop count only when it fired, so a normal batch's
    // response shape is unchanged; a client shipping untagged errors sees them
    // rejected here rather than silently vanishing.
    let mut body = json!({ "ok": true, "ingested": { "edges": n_edges, "errors": n_errors } });
    if dropped_untagged > 0 {
        body["droppedUntagged"] = json!(dropped_untagged);
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

// ---- buckets: stable, content-addressed error identity --------------------

/// Group capped-scan rows by their STORED bucket id (materialized at insert).
/// Rows written before materialization carry NULL and fall back to recomputing
/// with the same pure fn, so the two can never disagree. Preserves first-seen
/// order like `buckets::group`.
fn group_stored(occ: &[(i64, String, ErrorRec, Option<String>)]) -> Vec<(String, Vec<usize>)> {
    let mut order: Vec<String> = Vec::new();
    let mut by_bucket: std::collections::HashMap<String, Vec<usize>> = Default::default();
    for (i, (_, _, rec, stored)) in occ.iter().enumerate() {
        let bid = stored.clone().unwrap_or_else(|| buckets::bucket_id(rec));
        let entry = by_bucket.entry(bid.clone()).or_default();
        if entry.is_empty() {
            order.push(bid);
        }
        entry.push(i);
    }
    order
        .into_iter()
        .map(|bid| {
            let idxs = by_bucket.remove(&bid).unwrap_or_default();
            (bid, idxs)
        })
        .collect()
}

/// Resolve stored evidence rows for a set of error ids into serializable records
/// with fetch urls. Used by bucket evidence/package reads.
async fn resolve_evidence(tenant: &Tenant, error_ids: &[i64]) -> anyhow::Result<Vec<EvidenceRec>> {
    let mut out = Vec::new();
    for &id in error_ids {
        for (kind, key, bytes, ts) in tenant.store.evidence_for(id).await? {
            let url = tenant.blobs.url_for(&key).await?;
            out.push(EvidenceRec {
                kind,
                key,
                bytes,
                ts,
                url,
            });
        }
    }
    Ok(out)
}

async fn bucket_error_ids(
    tenant: &Tenant,
    app_id: &str,
    bucket: &str,
    _log_scope: &str,
) -> Result<Vec<i64>, (StatusCode, Json<Value>)> {
    let rows = tenant
        .store
        .errors_for_bucket(app_id, bucket, max_error_scan())
        .await
        .map_err(err500)?;
    if rows.is_empty() {
        return Err(not_found_err());
    }
    Ok(rows.iter().map(|(id, _, _)| *id).collect())
}

/// GET /v1/apps/:app/buckets, the production bug list keyed by STABLE bucket id
/// (not a shifting index), DEFAULT-SORTED BY IMPACT: the "what do I fix first?"
/// order. Each item carries its count, lineage (first/last seen build),
/// k-anonymized discriminators, reproduction status, the SYSTEM-computed
/// resolution truth, and the deterministic, explainable `impact` score (+ `why`).
/// The list is sorted by impact score descending, ties broken on the stable
/// bucket id, so the order is reproducible.
pub async fn get_buckets(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path(app_id): Path<String>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    bucket_list_for_tenant(&tenant, &app_id)
        .await
        .map(Json)
        .map_err(err500)
}

/// Build the ranked production-bucket list for an already-authorized tenant.
/// The API-key replay surface and the signed-in dashboard surface intentionally
/// share this one implementation so bucket ranking, repro trust, and prod-truth
/// resolution cannot drift.
pub(crate) async fn bucket_list_for_tenant(tenant: &Tenant, app_id: &str) -> anyhow::Result<Value> {
    use crate::triage::resolution;
    // Bounded grouping scan: cap how many error rows we materialize. When the cap
    // is hit we LOG how many rows were dropped (never silent truncation); bucket
    // COUNTS stay exact for every occurrence inside the window, only the newest
    // tail beyond the cap is excluded.
    let (occ, dropped) = tenant
        .store
        .errors_with_meta_capped(app_id, max_error_scan())
        .await?;
    if dropped > 0 {
        tracing::warn!(
            "get_buckets: error scan for {app_id} hit the cap; {dropped} most-recent rows excluded \
             from bucket grouping (raise REPROIT_MAX_ERROR_SCAN to include them)"
        );
    }
    let baseline: Vec<Map<String, Value>> =
        occ.iter().map(|(_, _, r, _)| r.context.clone()).collect();
    let groups = group_stored(&occ);

    // Batch the two per-bucket reads (folds the N+1): ALL replay results and ALL
    // triage rows for this app in ONE round-trip each, then look each bucket up in
    // the returned maps in the loop instead of awaiting once per bucket.
    let results_by_bucket = tenant.store.replay_results_by_bucket(app_id).await?;
    let triage_by_bucket = tenant.store.triage_all_for_app(app_id).await?;

    // App-wide first-seen-by-build map: the build-ordering anchor the resolution
    // engine segments against. Computed ONCE over the whole stream and reused for
    // every bucket (the regressed/resolved boost feeds the impact actionability).
    let app_stream: Vec<resolution::Occurrence> = occ
        .iter()
        .map(|(_, at, rec, _)| resolution::Occurrence {
            at: at.clone(),
            build: buckets::build_version(rec),
        })
        .collect();
    let first_seen = resolution::first_seen_by_build(&app_stream);
    let now = chrono::Utc::now().to_rfc3339();

    let mut items: Vec<(f64, String, Value)> = Vec::with_capacity(groups.len());
    for (bid, idxs) in &groups {
        let oldest = &occ[idxs[0]].2;
        let newest = &occ[*idxs.last().unwrap()].2;
        let cohort: Vec<Map<String, Value>> =
            idxs.iter().map(|&i| occ[i].2.context.clone()).collect();
        let results = results_by_bucket.get(bid).cloned().unwrap_or_default();

        // This bucket's claimed fix anchor (if any) drives its resolution truth.
        let triage = triage_by_bucket.get(bid).cloned();
        let fixed = triage.as_ref().and_then(|t| t.fixed_in_build.clone());
        // The SAME pure engine the on-read detail path uses (no logic fork). The
        // bug's own occurrence stream is this bucket's; the anchor + traffic come
        // from the app-wide stream.
        let bug: Vec<resolution::Occurrence> = idxs
            .iter()
            .map(|&i| resolution::Occurrence {
                at: occ[i].1.clone(),
                build: buckets::build_version(&occ[i].2),
            })
            .collect();
        let traffic = fixed
            .as_deref()
            .map(|f| resolution::post_fix_traffic(&app_stream, f))
            .unwrap_or(0);
        let outcome = resolution::evaluate(
            &bug,
            &first_seen,
            fixed.as_deref(),
            traffic,
            &now,
            resolution::Thresholds::default(),
        );

        // The occurrence time-series (for trend/velocity + frequency) + last-seen.
        let series: Vec<(String, Option<String>)> = idxs
            .iter()
            .map(|&i| (occ[i].1.clone(), buckets::build_version(&occ[i].2)))
            .collect();
        let timeline = buckets::timeline(&series, buckets::DEFAULT_TIMELINE_WINDOW_SECS);
        let last_seen = idxs.last().map(|&i| occ[i].1.clone());

        // Actionability for the impact boost: UNTRIAGED = never touched (no row);
        // REGRESSED = prod contradicts the claimed fix.
        let action = impact::Actionability {
            is_new: triage.is_none(),
            is_regressed: outcome.status == resolution::Resolution::Regressed,
        };
        let signals = impact::BucketSignals {
            // The structured oracle id, if the finding carried one (stored into the
            // occurrence context at ingest). Absent -> impact_score falls back to
            // keyword inference, so this is purely additive.
            oracle: newest.context.get("oracle").and_then(|v| v.as_str()),
            crash_sig: &newest.sig,
            message: &newest.message,
            count: idxs.len() as u64,
            timeline: &timeline,
            last_seen: last_seen.as_deref(),
            action,
        };
        let scored = impact::impact_score(&signals, &now);

        let item = json!({
            "bucketId": bid,
            "bugId": buckets::bug_id(newest),
            "findingIdentity": buckets::finding_identity(newest),
            "count": idxs.len(),
            "message": newest.message,
            "crashSig": newest.sig,
            "startSig": newest.path.first().map(|s| s.sig.clone()),
            "replayLen": buckets::replay_actions(newest).len(),
            "lineage": buckets::lineage(oldest, newest),
            "discriminators": discriminators(&cohort, &baseline),
            "triage": triage
                .as_ref()
                .map(|t| json!({ "status": t.status, "updatedAt": t.updated_at, "fixedInBuild": t.fixed_in_build }))
                .unwrap_or_else(|| json!({ "status": "untriaged", "updatedAt": Value::Null, "fixedInBuild": Value::Null })),
            "repro": buckets::repro_status(&results),
            // The system-computed prod-truth (active/resolving/resolved/regressed).
            "resolution": outcome.to_json(),
            // The ranking key + its explanation: severity class, score, and the
            // per-factor `why` breakdown so the order is trustable.
            "impact": {
                "score": scored.score,
                "severity": scored.severity.as_str(),
                "why": scored.why,
            },
        });
        items.push((scored.score, bid.clone(), item));
    }

    // Sort by impact DESC, ties broken on the stable bucket id ASC: deterministic
    // and reproducible (`total_cmp` orders the f64 score without NaN surprises).
    items.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let items: Vec<Value> = items.into_iter().map(|(_, _, v)| v).collect();
    Ok(json!({ "appId": app_id, "buckets": items.len(), "items": items }))
}

/// GET /v1/apps/:app/buckets/:bucket, the money endpoint: a portable REPLAY
/// PACKAGE for one bucket. Everything a local `reproit cloud reproduce` needs to
/// turn a real-user failure into a deterministic local test: the executable
/// replay, the property-matched fixture spec (from the PII-safe fingerprint),
/// the discriminators, build lineage, evidence, and the reproduction rate.
#[allow(clippy::too_many_arguments)]
fn bucket_package(
    bucket: &str,
    newest: &ErrorRec,
    oldest: &ErrorRec,
    count: usize,
    discriminators: &[Value],
    evidence: Vec<EvidenceRec>,
    results: Vec<ReplayResult>,
) -> Value {
    let actions = buckets::replay_actions(newest);
    let display_path = buckets::display_path(newest);
    let fixture = fixture_spec(&newest.context, discriminators);
    let visual_evidence = visual_evidence_refs(&evidence);
    json!({
        "bucketId": bucket,
        "bugId": buckets::bug_id(newest),
        "findingIdentity": buckets::finding_identity(newest),
        "summary": buckets::crash_summary(newest),
        "message": newest.message,
        "expectedError": newest.message,
        "crashSig": newest.sig,
        "startSig": newest.path.first().map(|s| s.sig.clone()),
        "count": count,
        "replay": actions.clone(),
        "actions": actions,
        "displayPath": display_path,
        "context": newest.context,
        "discriminators": discriminators,
        "fixture": fixture.clone(),
        "fixtureSpec": fixture,
        "lineage": buckets::lineage(oldest, newest),
        "evidence": evidence,
        "visualEvidence": visual_evidence,
        "repro": buckets::repro_status(&results),
        "results": results.clone(),
        "replayResults": results,
        "howto": "reproit cloud reproduce --app <app> --bucket <bucketId> --as <name> --run: downloads this package, synthesizes the fixture, replays the actions, then POSTs the result to replay-results",
    })
}

pub async fn get_bucket(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    // Indexed per-bucket read (materialized bucket_id), plus a bounded recency
    // sample of the app stream as the discriminator baseline.
    let rows = tenant
        .store
        .errors_for_bucket(&app_id, &bucket, max_error_scan())
        .await
        .map_err(err500)?;
    if rows.is_empty() {
        return Err(not_found_err());
    }
    let base_occ = tenant
        .store
        .recent_errors_with_meta(&app_id, baseline_sample())
        .await
        .map_err(err500)?;
    let baseline: Vec<Map<String, Value>> =
        base_occ.iter().map(|(_, _, r)| r.context.clone()).collect();
    let oldest = &rows.first().unwrap().2;
    let newest = &rows.last().unwrap().2;
    let cohort: Vec<Map<String, Value>> = rows.iter().map(|(_, _, r)| r.context.clone()).collect();
    let discs = discriminators(&cohort, &baseline);
    let error_ids: Vec<i64> = rows.iter().map(|(id, _, _)| *id).collect();
    let evidence = resolve_evidence(&tenant, &error_ids)
        .await
        .map_err(err500)?;
    let results = tenant
        .store
        .replay_results_for(&app_id, &bucket)
        .await
        .map_err(err500)?;
    Ok(Json(bucket_package(
        &bucket,
        newest,
        oldest,
        rows.len(),
        &discs,
        evidence,
        results,
    )))
}

/// Reproduction verdicts a client may report for a bucket.
const REPLAY_STATUSES: &[&str] = &["reproduced", "clean", "data_dependent", "stale", "flaky"];

/// POST /v1/apps/:app/buckets/:bucket/replay-results, record one reproduction
/// attempt (the trust loop). Body: `{status, runs?, failures?, localReproId?}`.
pub async fn post_replay_results(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    let status = body.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if !REPLAY_STATUSES.contains(&status) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("status must be one of {REPLAY_STATUSES:?}") })),
        ));
    }
    let runs = body.get("runs").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let failures = body.get("failures").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let local = body.get("localReproId").and_then(|v| v.as_str());
    let id = tenant
        .store
        .add_replay_result(&app_id, &bucket, status, runs, failures, local)
        .await
        .map_err(err500)?;
    // Verified-fix => triage advances to `fixed`. The SAME signal the ticket-close
    // path keys on (`is_verified_fix`) auto-advances the bucket's triage status,
    // UNLESS a human marked it `wontfix` (the DB twin enforces that guard in SQL,
    // and inserts a fresh `fixed` row if the bucket was never touched). Triage is
    // independent of the tracker integration, so this fires whether or not the app
    // has a tracker configured. Best-effort: a triage write failure must not fail
    // the replay-result POST (the result itself is already durably recorded).
    if crate::integrations::is_verified_fix(status, runs, failures) {
        let anchor = body
            .get("fixedInBuild")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        match tenant
            .store
            .advance_triage_unless_wontfix(
                &app_id,
                &bucket,
                crate::triage::Status::Fixed.as_str(),
                anchor,
            )
            .await
        {
            Ok(true) => tracing::info!("triage auto-advanced bucket {bucket} to fixed"),
            Ok(false) => {} // wontfix: the human's call stands.
            Err(e) => tracing::warn!("triage auto-advance failed for {bucket}: {e}"),
        }
    }
    // Verified-fix close: if this result is the signal that the bug no longer
    // reproduces, comment + close the linked ticket with proof. Opt-in and
    // best-effort, the hook short-circuits when the app has no tracker or the
    // bucket has no linked ticket, and NEVER fails the request on a tracker
    // outage (it logs and swallows). If the client knows the actual fixed build
    // it may pass `fixedInBuild`; cloud does not infer it from bug occurrences.
    if crate::integrations::is_verified_fix(status, runs, failures)
        && crate::integrations::is_configured_for(&tenant.store, &app_id).await
    {
        let build = body
            .get("fixedInBuild")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        crate::integrations::close_ticket_on_fix(&tenant.store, &app_id, &bucket, build).await;
    }
    // CI-run loop closure: a run dispatched via POST .../reproduce passes
    // its `runId` back here, which completes the cloud_runs ledger row. The row
    // must belong to this (app, bucket). Best-effort: an
    // unknown or already-terminal run id is ignored (the result itself stands).
    if let Some(run_id) = body.get("runId").and_then(|v| v.as_i64()) {
        match tenant
            .store
            .complete_cloud_run(run_id, &app_id, &bucket, "completed")
            .await
        {
            Ok(true) => {}
            Ok(false) => tracing::warn!("replay-result named unknown/closed cloud run {run_id}"),
            Err(e) => tracing::warn!("complete_cloud_run({run_id}) failed: {e}"),
        }
    }
    Ok(Json(json!({ "ok": true, "id": id })))
}

/// POST /v1/apps/:app/buckets/:bucket/reproduce, the CI reproduction
/// trigger. Fires a `repository_dispatch` into the app's bound customer repo
/// (project_integrations.dispatch_repo) so reproduction runs in THEIR CI; the
/// cloud never holds source or simulators. 202 with the run id; the CI
/// workflow's `reproit cloud reproduce ... --run` posts the verdict back to
/// replay-results with this id, completing the ledger row.
pub async fn post_reproduce(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    let row = tenant
        .store
        .integration_for(&app_id)
        .await
        .map_err(err500)?;
    let (repo, token_enc) = match row.and_then(|r| Some((r.dispatch_repo?, r.dispatch_token_enc?)))
    {
        Some(x) => x,
        None => {
            return Err((
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "no dispatch repo configured for this app; PUT /v1/apps/:app/integrations with dispatchRepo + dispatchToken first"
                })),
            ))
        }
    };
    let token = crate::db::secrets::decrypt(&token_enc).map_err(err500)?;
    let requested_by = match auth {
        crate::AuthCtx::Admin => "admin".to_string(),
        crate::AuthCtx::Org(org) => format!("org:{org}"),
    };
    let run_id = tenant
        .store
        .create_cloud_run(&app_id, &bucket, &requested_by)
        .await
        .map_err(err500)?;
    let payload = json!({ "app": app_id, "bucket": bucket, "runId": run_id });
    if let Err(e) = crate::integrations::dispatch::repository_dispatch(&repo, &token, payload).await
    {
        tracing::error!("repository_dispatch for {app_id}/{bucket} failed: {e}");
        let _ = tenant
            .store
            .complete_cloud_run(run_id, &app_id, &bucket, "failed")
            .await;
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(
                json!({ "error": "repository_dispatch failed; check the dispatch repo/token", "runId": run_id }),
            ),
        ));
    }
    metrics::counter!("cloud_runs_dispatched_total").increment(1);
    app.control
        .audit(
            &requested_by,
            "run.dispatch",
            None,
            json!({ "app": app_id, "bucket": bucket, "runId": run_id, "repo": repo }),
        )
        .await;
    Ok(Json(
        json!({ "ok": true, "runId": run_id, "status": "dispatched" }),
    ))
}

/// GET /v1/apps/:app/buckets/:bucket/runs, the hosted-run history for a bucket.
pub async fn get_cloud_runs(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    let runs = tenant
        .store
        .cloud_runs_for(&app_id, &bucket)
        .await
        .map_err(err500)?;
    Ok(Json(json!({ "bucketId": bucket, "runs": runs })))
}

/// GET /v1/apps/:app/buckets/:bucket/replay-results, the attempt history + the
/// reproduction-rate summary.
pub async fn get_replay_results(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    let results = tenant
        .store
        .replay_results_for(&app_id, &bucket)
        .await
        .map_err(err500)?;
    Ok(Json(json!({
        "bucketId": bucket,
        "repro": buckets::repro_status(&results),
        "results": results,
    })))
}

// ---- bug <-> ticket link: read / set the external issue for a bucket -------

/// GET /v1/apps/:app/buckets/:bucket/ticket, the bucket's linked external ticket
/// (provider/repo/externalId/url), or `{linked:false}` if none. PII-safe: the
/// link carries no user data.
pub async fn get_ticket(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    match tenant
        .store
        .ticket_for_bucket(&app_id, &bucket)
        .await
        .map_err(err500)?
    {
        Some(link) => Ok(Json(json!({
            "bucketId": bucket,
            "linked": true,
            "ticket": link,
        }))),
        None => Ok(Json(json!({
            "bucketId": bucket,
            "linked": false,
            // Whether filing is even possible (the app has a tracker configured).
            "configured": crate::integrations::is_configured_for(&tenant.store, &app_id).await,
        }))),
    }
}

/// POST /v1/apps/:app/buckets/:bucket/ticket, explicitly file (or re-file) the
/// issue for a bucket and persist the link. Opt-in: if the app has no tracker
/// configured this is a 400 ("not configured"), never a silent success. If the
/// bucket already has a ticket, returns the existing link unchanged (idempotent,
/// a bucket maps to exactly one ticket). The bucket must exist (have at least one
/// occurrence) so we have a real repro package to file.
pub async fn post_ticket(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    if !crate::integrations::is_configured_for(&tenant.store, &app_id).await {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "no issue tracker configured for this app" })),
        ));
    }
    // Already linked: return it as-is (1:1 mapping, no duplicate file).
    if let Some(link) = tenant
        .store
        .ticket_for_bucket(&app_id, &bucket)
        .await
        .map_err(err500)?
    {
        return Ok(Json(
            json!({ "bucketId": bucket, "linked": true, "ticket": link }),
        ));
    }
    // Resolve the bucket's oldest/newest occurrence for the PII-safe body via
    // the materialized bucket_id index.
    let rows = tenant
        .store
        .errors_for_bucket(&app_id, &bucket, max_error_scan())
        .await
        .map_err(err500)?;
    if rows.is_empty() {
        return Err(not_found_err());
    }
    let oldest = rows.first().unwrap().2.clone();
    let newest = rows.last().unwrap().2.clone();
    match crate::integrations::file_issue_for_bucket(
        &tenant.store,
        &app_id,
        &bucket,
        &oldest,
        &newest,
    )
    .await
    {
        Some(url) => Ok(Json(
            json!({ "bucketId": bucket, "linked": true, "url": url }),
        )),
        None => Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": "could not file issue with the tracker" })),
        )),
    }
}

// ---- evidence: store / serve repro artifacts ------------------------------

/// Map a content-type or filename extension to a normalized evidence kind.
/// Unknown types are stored as "blob" rather than rejected, we'd rather keep
/// the artifact than lose a repro because of a missing mime.
fn evidence_kind(content_type: Option<&str>, filename: Option<&str>) -> String {
    let from_ct = content_type.and_then(|ct| match ct.split(';').next().unwrap_or("").trim() {
        "video/mp4" => Some("mp4"),
        "image/gif" => Some("gif"),
        "image/png" => Some("png"),
        "image/jpeg" => Some("jpg"),
        _ => None,
    });
    if let Some(k) = from_ct {
        return k.to_string();
    }
    let ext = filename
        .and_then(|f| f.rsplit('.').next())
        .map(|e| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("mp4") => "mp4",
        Some("gif") => "gif",
        Some("png") => "png",
        Some("jpg") | Some("jpeg") => "jpg",
        _ => "blob",
    }
    .to_string()
}

/// File extension to give a stored key for a given kind.
fn kind_ext(kind: &str) -> &str {
    match kind {
        "mp4" => "mp4",
        "gif" => "gif",
        "png" => "png",
        "jpg" => "jpg",
        _ => "bin",
    }
}

/// Optional operator-defined evidence cap. Zero/unset disables it.
async fn evidence_cap(_app: &App, _tenant: &Tenant) -> Option<i64> {
    max_evidence_bytes_per_app()
}

async fn store_evidence_for_error(
    tenant: &Tenant,
    app_id: &str,
    error_id: i64,
    mut multipart: Multipart,
    cap: Option<i64>,
) -> ApiResult {
    let mut stored: Vec<EvidenceRec> = Vec::new();
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": e.to_string() })),
                ))
            }
        };
        let content_type = field.content_type().map(|s| s.to_string());
        let filename = field.file_name().map(|s| s.to_string());
        let data = field.bytes().await.map_err(|e| {
            tracing::error!("multipart field read failed: {e}");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "could not read multipart field" })),
            )
        })?;
        // Per-file cap: reject an oversize part with 413 rather than store it.
        if data.len() > MAX_EVIDENCE_FIELD_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({ "error": "evidence file too large" })),
            ));
        }
        if data.is_empty() {
            continue;
        }
        let kind = evidence_kind(content_type.as_deref(), filename.as_deref());
        let bytes = data.len() as i64;
        // Server-generated, traversal-free key: app/error/uuid.ext.
        let key = format!(
            "{app_id}/{error_id}/{}.{}",
            uuid::Uuid::new_v4(),
            kind_ext(&kind)
        );
        // Reserve the row FIRST (quota check + insert are one transaction under a
        // per-app advisory lock, so concurrent uploads cannot overshoot), then
        // upload; a failed upload compensates by removing the reservation.
        let evidence_id = tenant
            .store
            .add_evidence_within_quota(app_id, error_id, &kind, &key, bytes, cap)
            .await
            .map_err(err500)?;
        let Some(evidence_id) = evidence_id else {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({ "error": "app evidence quota exceeded" })),
            ));
        };
        if let Err(e) = tenant.blobs.put(&key, &data).await {
            let _ = tenant.store.remove_evidence(evidence_id).await;
            return Err(err500(e));
        }
        let url = tenant.blobs.url_for(&key).await.map_err(err500)?;
        stored.push(EvidenceRec {
            kind,
            key,
            bytes,
            ts: chrono::Utc::now().to_rfc3339(),
            url,
        });
    }
    if stored.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "no file parts in multipart body" })),
        ));
    }
    Ok(Json(
        json!({ "ok": true, "stored": stored.len(), "evidence": stored }),
    ))
}

/// POST /v1/apps/:app/buckets/:bucket/evidence, attach proof artifacts to a
/// stable bucket. Evidence is stored on the newest occurrence in the bucket; the
/// bucket package lists evidence across all occurrences, so the artifact is
/// immediately visible from `GET /v1/apps/:app/buckets/:bucket`.
pub async fn post_bucket_evidence(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
    multipart: Multipart,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    let ids = bucket_error_ids(&tenant, &app_id, &bucket, "post_bucket_evidence").await?;
    let Some(error_id) = ids.last().copied() else {
        return Err(not_found_err());
    };
    store_evidence_for_error(
        &tenant,
        &app_id,
        error_id,
        multipart,
        evidence_cap(&app, &tenant).await,
    )
    .await
}

/// GET /v1/apps/:app/buckets/:bucket/evidence, list all proof artifacts attached
/// to every occurrence currently grouped into the stable bucket id.
pub async fn get_bucket_evidence(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    let ids = bucket_error_ids(&tenant, &app_id, &bucket, "get_bucket_evidence").await?;
    let evidence = resolve_evidence(&tenant, &ids).await.map_err(err500)?;
    let visual_evidence = visual_evidence_refs(&evidence);
    Ok(Json(json!({
        "appId": app_id,
        "bucketId": bucket,
        "count": evidence.len(),
        "evidence": evidence,
        "visualEvidence": visual_evidence,
    })))
}

/// GET /v1/blob/*key, proxy bytes for the local-fs backend. R2 deployments hand
/// out presigned urls instead and never hit this. Auth-protected like the rest.
pub async fn get_blob(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    if !crate::tenancy::blob::is_safe_key(&key) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid key" })),
        ));
    }
    // The key is TENANT-RELATIVE (`app_id/error_id/uuid.ext`). We resolve the
    // caller's tenant and serve through `tenant.blobs`, which re-roots the key at
    // the tenant's blob scope: a key cannot be edited to point at another tenant's
    // bytes because the scoped handle has no authority outside this tenant's scope.
    // We still confirm the leading app segment is a project in this tenant (404
    // otherwise), keeping the no-existence-leak behavior.
    let key_app = key.split('/').next().unwrap_or("");
    let tenant = tenant_for(&app, auth, &headers, key_app).await?;
    let bytes = tenant.blobs.get(&key).await.map_err(|e| {
        // Log the detail, return a generic 404 (don't echo the storage error).
        tracing::error!("blob fetch failed for key {key}: {e}");
        not_found_err()
    })?;
    let ext = key.rsplit('.').next().unwrap_or("");
    let mime = match ext {
        "mp4" => "video/mp4",
        "gif" => "image/gif",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        _ => "application/octet-stream",
    };
    Ok(([(header::CONTENT_TYPE, mime)], Bytes::from(bytes)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(msg: &str, sig: &str, entry: &str, actions: &[&str]) -> ErrorRec {
        let mut path = vec![Step {
            sig: entry.to_string(),
            action: "load".to_string(),
            label: None,
        }];
        for action in actions {
            path.push(Step {
                sig: "mid".to_string(),
                action: action.to_string(),
                label: None,
            });
        }
        ErrorRec {
            sig: sig.to_string(),
            message: msg.to_string(),
            path,
            context: Map::new(),
        }
    }

    #[test]
    fn evidence_kind_from_content_type_then_extension() {
        // content-type wins when present
        assert_eq!(evidence_kind(Some("video/mp4"), Some("x.gif")), "mp4");
        assert_eq!(evidence_kind(Some("image/gif; q=1"), None), "gif");
        // falls back to filename extension
        assert_eq!(evidence_kind(None, Some("repro.MP4")), "mp4");
        assert_eq!(
            evidence_kind(Some("application/x"), Some("shot.png")),
            "png"
        );
        assert_eq!(evidence_kind(Some("image/jpeg"), None), "jpg");
        // unknown is kept as a generic blob, never rejected
        assert_eq!(evidence_kind(None, Some("weird.xyz")), "blob");
        assert_eq!(evidence_kind(None, None), "blob");
    }

    #[test]
    fn safe_key_rejects_traversal_and_absolute() {
        use crate::tenancy::blob::is_safe_key;
        assert!(is_safe_key("app/42/abc.mp4"));
        assert!(!is_safe_key("/etc/passwd"));
        assert!(!is_safe_key("app/../../etc/passwd"));
        assert!(!is_safe_key("app/./x"));
        assert!(!is_safe_key(""));
        assert!(!is_safe_key("app//x"));
    }

    #[test]
    fn error_context_accepts_context_and_ctx_spellings() {
        let mut batch = Map::new();
        batch.insert("locale".into(), json!("en-US"));
        batch.insert("plan".into(), json!("free"));
        let ev = json!({
            "ctx": { "plan": "pro", "route": "/checkout" },
            "context": {
                "fingerprint": [{ "field": "name", "len": 18, "charset": "unicode" }],
                "fpVersion": 2
            }
        });
        let merged = merge_context(&batch, &ev);
        assert_eq!(merged["locale"], json!("en-US"));
        assert_eq!(merged["plan"], json!("pro"));
        assert_eq!(merged["route"], json!("/checkout"));
        assert_eq!(merged["fpVersion"], json!(2));
        assert_eq!(merged["fingerprint"][0]["field"], json!("name"));
    }

    #[test]
    fn event_context_fingerprint_feeds_fixture_spec() {
        let ev = json!({
            "context": {
                "fingerprint": [{
                    "field": "name",
                    "len": 18,
                    "bytes": 90,
                    "graphemes": 12,
                    "charset": "unicode",
                    "scripts": ["Latin", "Arabic"],
                    "hasNewline": true
                }]
            }
        });
        let merged = merge_context(&Map::new(), &ev);
        let spec = fixture_spec(&merged, &[]);
        let generate = &spec["inputs"][0]["generate"];
        assert_eq!(generate["minLen"], json!(18));
        assert_eq!(generate["minBytes"], json!(90));
        assert_eq!(generate["minGraphemes"], json!(12));
        assert_eq!(generate["scripts"], json!(["Latin", "Arabic"]));
        assert_eq!(generate["newline"], json!(true));
    }

    #[test]
    fn bucket_package_exposes_bucket_first_replay_shape() {
        let mut newest = rec(
            "Cannot read property at line 42",
            "crashA",
            "checkout",
            &["type:key:id:card=long", "tap:key:id:pay"],
        );
        newest
            .context
            .insert("build".into(), json!({ "version": "1.2.3" }));
        newest.context.insert(
            "fingerprint".into(),
            json!([{ "field": "card", "len": 64, "charset": "numeric" }]),
        );
        let oldest = rec(
            "Cannot read property at line 1",
            "crashA",
            "checkout",
            &["tap:key:id:pay"],
        );
        let discriminators = vec![json!({
            "key": "locale",
            "value": "tr",
            "cohortShare": 1.0,
            "baselineShare": 0.2,
            "lift": 5.0,
        })];
        let evidence = vec![EvidenceRec {
            kind: "mp4".into(),
            key: "app/1/repro.mp4".into(),
            bytes: 10,
            ts: "2026-06-27T00:00:00Z".into(),
            url: "/v1/blob/app/1/repro.mp4".into(),
        }];
        let results = vec![ReplayResult {
            status: "reproduced".into(),
            runs: 1,
            failures: 1,
            local_repro_id: Some("local-1".into()),
            created_at: "2026-06-27T00:00:00Z".into(),
        }];

        let pkg = bucket_package(
            "bkt_deadbeef0001",
            &newest,
            &oldest,
            2,
            &discriminators,
            evidence,
            results,
        );

        assert_eq!(pkg["bucketId"], "bkt_deadbeef0001");
        assert_eq!(pkg["message"], "Cannot read property at line 42");
        assert_eq!(pkg["summary"], "Cannot read property at line N (crashA)");
        assert_eq!(pkg["actions"], pkg["replay"]);
        assert_eq!(
            pkg["actions"],
            json!(["type:key:id:card=long", "tap:key:id:pay"])
        );
        assert_eq!(pkg["displayPath"][1]["action"], "type:key:id:card=long");
        assert_eq!(pkg["fixture"], pkg["fixtureSpec"]);
        assert_eq!(pkg["fixture"]["locale"], "tr");
        assert_eq!(pkg["fixture"]["inputs"][0]["field"], "card");
        assert_eq!(pkg["discriminators"][0]["key"], "locale");
        assert_eq!(pkg["lineage"]["lastSeen"]["version"], "1.2.3");
        assert_eq!(pkg["evidence"][0]["kind"], "mp4");
        assert_eq!(pkg["visualEvidence"]["count"], 1);
        assert_eq!(pkg["visualEvidence"]["paths"], json!(["app/1/repro.mp4"]));
        assert_eq!(pkg["visualEvidence"]["clips"][0]["role"], "clip");
        assert_eq!(pkg["visualEvidence"]["clips"][0]["path"], "app/1/repro.mp4");
        assert_eq!(pkg["visualEvidence"]["screenshots"], json!([]));
        assert_eq!(pkg["results"], pkg["replayResults"]);
        assert_eq!(pkg["repro"]["status"], "reproduced");
    }

    #[test]
    fn oracle_gate_admits_tagged_error_and_forms_bucket() {
        // A crash is an oracle bug (SDKs tag uncaught crashes oracle:"crash"), so
        // it passes the gate, becomes an occurrence, and opens a bucket.
        let events = vec![json!({
            "kind": "error",
            "sig": "crashA",
            "message": "boom",
            "oracle": "crash",
        })];
        let agg = aggregate_events(&events, &Map::new());
        assert_eq!(agg.error_recs.len(), 1);
        assert_eq!(agg.dropped_untagged, 0);
        assert_eq!(agg.error_recs[0].context["oracle"], json!("crash"));
        // A bucket id is derivable for the accepted occurrence.
        assert!(!buckets::bucket_id(&agg.error_recs[0]).is_empty());
    }

    #[test]
    fn ingest_preserves_bounded_structural_identity_and_recomputes_bug_id() {
        let identity = json!({
            "oracle": "crash",
            "invariant": "no-exception",
            "kind": "exception",
            "message": "boom at #",
            "frame": "",
            "trigger": ""
        });
        let events = vec![json!({
            "kind": "error",
            "sig": "screen",
            "message": "boom at 42",
            "oracle": "crash",
            "findingIdentity": identity,
            "bugId": "bug_attacker_controlled"
        })];
        let agg = aggregate_events(&events, &Map::new());
        let rec = &agg.error_recs[0];
        assert_eq!(rec.context["findingIdentity"], identity);
        assert_ne!(buckets::bug_id(rec), "bug_attacker_controlled");
        assert_eq!(
            buckets::bucket_id(rec).trim_start_matches("bkt_"),
            buckets::bug_id(rec).trim_start_matches("bug_")
        );
    }

    #[test]
    fn oracle_gate_drops_untagged_error_and_forms_no_bucket() {
        // A general error report with no oracle tag is not a product finding: it
        // is dropped before any ErrorRec forms and counted for the response.
        let events = vec![json!({
            "kind": "error",
            "sig": "crashA",
            "message": "boom",
        })];
        let agg = aggregate_events(&events, &Map::new());
        assert!(agg.error_recs.is_empty());
        assert_eq!(agg.dropped_untagged, 1);
    }

    #[test]
    fn oracle_gate_rejects_malformed_ids() {
        // Uppercase, spaces, punctuation, empty, and over-length are all malformed.
        assert!(!oracle_well_formed("Crash"));
        assert!(!oracle_well_formed("blank screen"));
        assert!(!oracle_well_formed("sql;drop"));
        assert!(!oracle_well_formed("crash!"));
        assert!(!oracle_well_formed(""));
        assert!(!oracle_well_formed(&"x".repeat(MAX_ORACLE_ID_BYTES + 1)));
        // Exactly at the cap is still a token.
        assert!(oracle_well_formed(&"x".repeat(MAX_ORACLE_ID_BYTES)));
        // Every canonical registry id passes the gate (choice-anomaly et al).
        for (id, _) in impact::KNOWN_ORACLES {
            assert!(oracle_well_formed(id), "registry id must pass gate: {id}");
        }
        // Through the loop, each malformed error is dropped, none bucketed.
        let events = vec![
            json!({ "kind": "error", "sig": "s", "oracle": "UPPER" }),
            json!({ "kind": "error", "sig": "s", "oracle": "has space" }),
            json!({ "kind": "error", "sig": "s", "oracle": "x".repeat(MAX_ORACLE_ID_BYTES + 1) }),
        ];
        let agg = aggregate_events(&events, &Map::new());
        assert!(agg.error_recs.is_empty());
        assert_eq!(agg.dropped_untagged, 3);
    }

    #[test]
    fn oracle_gate_admits_wellformed_unknown_id() {
        // An id this cloud build does not recognize (from a newer CLI/SDK) still
        // passes: the gate is presence + well-formedness, not registry membership.
        let unknown = "time-travel-9000";
        assert!(!impact::KNOWN_ORACLES.iter().any(|(k, _)| *k == unknown));
        assert!(oracle_well_formed(unknown));
        let events = vec![json!({
            "kind": "error", "sig": "s", "message": "m", "oracle": unknown,
        })];
        let agg = aggregate_events(&events, &Map::new());
        assert_eq!(agg.error_recs.len(), 1);
        assert_eq!(agg.dropped_untagged, 0);
        assert_eq!(agg.error_recs[0].context["oracle"], json!(unknown));
    }

    #[test]
    fn oracle_gate_tombstones_retired_finding_families_only() {
        for event in [
            json!({
                "kind": "error", "sig": "s", "oracle": "graph",
                "invariant": "no-dead-control", "message": "legacy"
            }),
            json!({
                "kind": "error", "sig": "s", "oracle": "graph",
                "message": "state abc has a dead control: tap:Save"
            }),
            json!({
                "kind": "error", "sig": "s", "oracle": "graph",
                "context": {"invariant": "no-dead-control"}
            }),
            json!({
                "kind": "error", "sig": "s", "oracle": "graph",
                "invariant": "no-dead-end", "message": "state abc is a dead end"
            }),
            json!({
                "kind": "error", "sig": "s", "oracle": "dynamic-type"
            }),
            json!({
                "kind": "error", "sig": "s", "oracle": "overflow"
            }),
            json!({
                "kind": "error", "sig": "s", "oracle": "undo-inverse"
            }),
            json!({
                "kind": "error", "sig": "s", "oracle": "invariant",
                "message": "3 unlabeled tappables exceed max 0"
            }),
            json!({
                "kind": "error", "sig": "s", "oracle": "invariant",
                "message": "button has no accessible name"
            }),
        ] {
            let agg = aggregate_events(&[event], &Map::new());
            assert!(agg.error_recs.is_empty());
            assert_eq!(agg.dropped_untagged, 1);
        }

        let legacy_graph = aggregate_events(
            &[json!({
                "kind": "error", "sig": "s", "oracle": "graph",
                "invariant": "no-occluded-control", "message": "covered button"
            })],
            &Map::new(),
        );
        assert_eq!(
            legacy_graph.error_recs.len(),
            1,
            "well-formed legacy graph events remain compatible"
        );
        assert_eq!(legacy_graph.dropped_untagged, 0);
        assert_eq!(
            impact::severity_for_oracle(
                legacy_graph.error_recs[0].context["oracle"]
                    .as_str()
                    .expect("stored oracle")
            ),
            impact::Severity::Unknown,
            "generic graph must not be promoted to occlusion"
        );

        for event in [
            json!({"kind":"error", "sig":"s", "oracle":"occlusion"}),
            json!({"kind":"error", "sig":"s", "oracle":"choice-anomaly"}),
            json!({"kind":"error", "sig":"s", "oracle":"stuck-keyboard"}),
            json!({
                "kind":"error", "sig":"s", "oracle":"permission-walk",
                "invariant":"no-permission-dead-end"
            }),
        ] {
            let agg = aggregate_events(&[event], &Map::new());
            assert_eq!(agg.error_recs.len(), 1);
            assert_eq!(agg.dropped_untagged, 0);
        }
    }

    #[test]
    fn oracle_gate_leaves_edges_and_other_kinds_untouched() {
        // The gate touches only the error kind: edges still sum by key and an
        // unrelated kind is ignored, exactly as before.
        let events = vec![
            json!({ "kind": "edge", "from": "a", "action": "tap", "to": "b" }),
            json!({ "kind": "edge", "from": "a", "action": "tap", "to": "b" }),
            json!({ "kind": "error", "sig": "s" }),
            json!({ "kind": "screenshot" }),
        ];
        let agg = aggregate_events(&events, &Map::new());
        assert_eq!(agg.edge_counts.get("a|tap|b"), Some(&2));
        assert!(agg.error_recs.is_empty());
        assert_eq!(agg.dropped_untagged, 1);
    }
}
