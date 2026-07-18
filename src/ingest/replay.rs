//! Production-to-local replay status and hosted reproduction dispatch.

use super::*;

const REPLAY_STATUSES: &[&str] = &["reproduced", "not_reproduced", "stale", "flaky"];

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
    // Explicit tester reports become normal workflow items only after replay
    // confirmation. File the integration ticket here, not at ingest time.
    if status == "reproduced" {
        match tenant
            .store
            .errors_for_bucket(&app_id, &bucket, max_error_scan())
            .await
        {
            Ok(rows) if !rows.is_empty() && buckets::is_tester_capture(&rows.last().unwrap().2) => {
                let oldest = &rows.first().unwrap().2;
                let newest = &rows.last().unwrap().2;
                crate::integrations::file_issue_for_bucket(
                    &tenant.store,
                    &app_id,
                    &bucket,
                    oldest,
                    newest,
                )
                .await;
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!("could not load confirmed tester capture {bucket}: {error}")
            }
        }
    }
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
/// workflow's private replay dispatch command posts the verdict back to
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
