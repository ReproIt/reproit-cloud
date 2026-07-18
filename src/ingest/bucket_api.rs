//! Production bucket ranking, packaging, and ticket endpoints.

use super::*;

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
pub(super) async fn resolve_evidence(
    tenant: &Tenant,
    error_ids: &[i64],
) -> anyhow::Result<Vec<EvidenceRec>> {
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

pub(super) async fn bucket_error_ids(
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
    let mut pending_captures: Vec<(f64, String, Value)> = Vec::new();
    for (bid, idxs) in &groups {
        let oldest = &occ[idxs[0]].2;
        let newest = &occ[*idxs.last().unwrap()].2;
        let cohort: Vec<Map<String, Value>> =
            idxs.iter().map(|&i| occ[i].2.context.clone()).collect();
        let results = results_by_bucket.get(bid).cloned().unwrap_or_default();
        let tester_capture = buckets::is_tester_capture(newest);
        let capture_confirmed = buckets::tester_capture_confirmed(&results);

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
            count: idxs.len() as u64,
            timeline: &timeline,
            last_seen: last_seen.as_deref(),
            action,
        };
        let scored = impact::impact_score(&signals, &now);

        let sample = idxs
            .iter()
            .all(|&i| sample_kind(&occ[i].2) == Some(NIMBUS_SAMPLE))
            .then_some(NIMBUS_SAMPLE);
        let item = json!({
            "bucketId": bid,
            "bugId": buckets::bug_id(newest),
            "findingIdentity": buckets::finding_identity(newest),
            "sample": sample,
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
            "capture": tester_capture.then(|| json!({
                "source": "tester",
                "status": if capture_confirmed { "confirmed" } else { "pending" },
            })),
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
        if tester_capture && !capture_confirmed {
            pending_captures.push((scored.score, bid.clone(), item));
        } else {
            items.push((scored.score, bid.clone(), item));
        }
    }

    // Sort by impact DESC, ties broken on the stable bucket id ASC: deterministic
    // and reproducible (`total_cmp` orders the f64 score without NaN surprises).
    items.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let items: Vec<Value> = items.into_iter().map(|(_, _, v)| v).collect();
    pending_captures.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let pending_captures: Vec<Value> = pending_captures
        .into_iter()
        .map(|(_, _, value)| value)
        .collect();
    Ok(json!({
        "appId": app_id,
        "buckets": items.len(),
        "items": items,
        "pendingCaptures": pending_captures,
    }))
}

/// GET /v1/apps/:app/buckets/:bucket, the money endpoint: a portable REPLAY
/// PACKAGE for one bucket. Everything a direct `reproit bkt_...` needs to
/// turn a real-user failure into a deterministic local test: the executable
/// replay, the property-matched fixture spec (from the PII-safe fingerprint),
/// the discriminators, build lineage, evidence, and the reproduction rate.
#[allow(clippy::too_many_arguments)]
pub(super) fn bucket_package(
    app_id: &str,
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
        "appId": app_id,
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
        "howto": "reproit <bucketId>: downloads this package, saves it locally, synthesizes the fixture, replays the actions, then reports the verdict to Cloud",
    })
}

async fn bucket_package_for_tenant(
    tenant: &Tenant,
    app_id: &str,
    bucket: &str,
) -> anyhow::Result<Option<Value>> {
    let rows = tenant
        .store
        .errors_for_bucket(app_id, bucket, max_error_scan())
        .await?;
    if rows.is_empty() {
        return Ok(None);
    }
    let base_occ = tenant
        .store
        .recent_errors_with_meta(app_id, baseline_sample())
        .await?;
    let baseline: Vec<Map<String, Value>> =
        base_occ.iter().map(|(_, _, r)| r.context.clone()).collect();
    let oldest = &rows.first().unwrap().2;
    let newest = &rows.last().unwrap().2;
    let cohort: Vec<Map<String, Value>> = rows.iter().map(|(_, _, r)| r.context.clone()).collect();
    let discs = discriminators(&cohort, &baseline);
    let error_ids: Vec<i64> = rows.iter().map(|(id, _, _)| *id).collect();
    let evidence = resolve_evidence(tenant, &error_ids).await?;
    let results = tenant.store.replay_results_for(app_id, bucket).await?;
    Ok(Some(bucket_package(
        app_id,
        bucket,
        newest,
        oldest,
        rows.len(),
        &discs,
        evidence,
        results,
    )))
}

pub async fn get_bucket_global(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    Extension(scope): Extension<crate::KeyScope>,
    headers: HeaderMap,
    Path(bucket): Path<String>,
) -> ApiResult {
    let tenant = app.tenant_of(auth, &headers).await?;
    let mut projects = tenant.store.list_projects().await.map_err(err500)?;
    if let Some(project_id) = scope.project_id {
        projects.retain(|(id, _, _)| *id == project_id);
    }
    let mut found = Vec::new();
    for (_, _, app_id) in projects {
        if let Some(package) = bucket_package_for_tenant(&tenant, &app_id, &bucket)
            .await
            .map_err(err500)?
        {
            found.push((app_id, package));
        }
    }
    match found.len() {
        0 => Err(not_found_err()),
        1 => Ok(Json(found.pop().unwrap().1)),
        _ => Err((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "bucket exists in more than one accessible project",
                "bucketId": bucket,
                "projects": found.into_iter().map(|(app_id, _)| app_id).collect::<Vec<_>>(),
            })),
        )),
    }
}

pub async fn get_bucket(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    bucket_package_for_tenant(&tenant, &app_id, &bucket)
        .await
        .map_err(err500)?
        .map(Json)
        .ok_or_else(not_found_err)
}

/// Reproduction verdicts a client may report for a bucket.
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
