//! Worker fleet: shards live in a durable Postgres queue that REMOTE workers
//! (a Mac for ios + android + web, a Linux box for web/android) CLAIM over HTTP.
//! A worker is a PULL client: it dials out, claims a shard, runs the EXACT same
//! `reproit` binary in an ISOLATED working dir (so per-run .reproit/ state and
//! the fuzz config never race), heartbeats while running, and posts the report.
//! Same binary, same markers, same evidence as the local CLI.
//!
//! This module exposes the control-plane side of that protocol:
//!   * `claim`     POST /v1/worker/claim          -> 200 shard JSON | 204 idle
//!   * `heartbeat` POST /v1/worker/shards/:id/...  -> keepalive while running
//!   * `result`    POST /v1/worker/shards/:id/...  -> finished, report attached
//!
//! It also exposes an OPTIONAL `spawn_embedded` pool so local dev can claim and
//! run shards in-process (the control plane is also a worker), with a graceful
//! drain on shutdown.

use crate::db::TenantStore;
use crate::jobs::ShardState;
use crate::App;
use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// Wall-clock cap on a single shard's reproit child (embedded pool). A hung run
/// maps to ShardState::Error so it can't wedge a worker forever (audit #15).
const SHARD_TIMEOUT: Duration = Duration::from_secs(300);
/// How often an embedded worker heartbeats a shard it is running, so the sweeps
/// (`requeue_stranded`) never reclaim a shard that is still making progress.
const HEARTBEAT_EVERY: Duration = Duration::from_secs(20);
/// Idle backoff: how long an embedded worker sleeps after a 204-equivalent
/// (no shard available) before polling the queue again.
const IDLE_BACKOFF: Duration = Duration::from_secs(2);

// ---- HTTP worker API (remote fleet) ---------------------------------------

/// Claim request body. `capabilities` is the set of backends this worker can
/// serve (web | android | ios); empty defaults to ["web"]. `worker_id` is an
/// optional stable identity (we mint one if absent, since the fleet is trusted
/// via REPROIT_WORKER_TOKEN and heartbeats/results address shards by id).
#[derive(Debug, Deserialize)]
pub struct ClaimReq {
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub worker_id: Option<String>,
}

/// Result body a worker posts when a shard finishes. `duration_s` is optional
/// (the shell reference client doesn't send it); `exit_code` is informational.
#[derive(Debug, Deserialize)]
pub struct ResultReq {
    pub status: String,
    #[serde(default)]
    #[allow(dead_code)] // part of the documented protocol body; informational
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub report: Option<String>,
    #[serde(default)]
    pub duration_s: Option<f64>,
}

/// POST /v1/worker/claim: atomically claim the next pending shard whose backend
/// this worker can serve. Under database-per-org the queue is PER-TENANT (shards
/// live in tenant DBs), so a claim FANS across active tenants and grabs the first
/// available shard. The returned id is "<org>:<job>:<seed>:<worker>" so
/// heartbeat/result route back to the right tenant DB and are bound to the
/// claimant. 200 with the work to do, or 204 when nothing's queued anywhere.
///
/// NOTE: fan-then-claim is the simple, correct answer for a modest tenant count.
/// Global fairness / a cross-tenant claim view is design Open Question 4 (a
/// control-plane queue index), deliberately deferred.
pub async fn claim(State(app): State<App>, Json(req): Json<ClaimReq>) -> Response {
    let mut caps = req.capabilities;
    if caps.is_empty() {
        caps.push("web".to_string());
    }
    let worker_id = sanitize_worker_id(
        req.worker_id
            .unwrap_or_else(|| format!("w-{}", uuid::Uuid::new_v4())),
    );

    match claim_across_tenants(&app, &worker_id, &caps).await {
        Some((org_id, shard)) => {
            // Successful claims are audited (the worker fleet can address any
            // tenant); the empty-poll path stays out of the audit trail.
            metrics::counter!("worker_claims_total").increment(1);
            app.control
                .audit(
                    &format!("worker:{worker_id}"),
                    "worker.claim",
                    Some(org_id),
                    serde_json::json!({ "job": shard.job_id, "seed": shard.seed }),
                )
                .await;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "id": format!("{}:{}:{}:{}", org_id, shard.job_id, shard.seed, shard.claimed_by),
                    "appDir": shard.app_dir,
                    "seed": shard.seed,
                    "budget": shard.budget,
                    "backend": shard.backend,
                })),
            )
                .into_response()
        }
        // Nothing claimable for this worker's capabilities in any tenant: idle.
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

fn sanitize_worker_id(id: String) -> String {
    let clean: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .take(96)
        .collect();
    if clean.is_empty() {
        format!("w-{}", uuid::Uuid::new_v4())
    } else {
        clean
    }
}

/// Resolve the tenant store for an org id (worker routing). The worker fleet is
/// trusted via REPROIT_WORKER_TOKEN, so it may address any tenant by id.
async fn tenant_store(app: &App, org_id: i64) -> Option<TenantStore> {
    app.tenancy.resolve(org_id).await.ok().map(|t| t.store)
}

/// Claim the first available shard, visiting ONLY tenants the control-plane routing
/// hint (`tenant_pending_shards`) says have pending work, instead of fanning a claim
/// query into EVERY active tenant DB on every poll (finding #3). Returns the owning
/// org id alongside the claimed shard so the worker can route follow-ups.
///
/// The hint is allowed to over-include (a stale row just costs one wasted empty
/// claim here); it must never under-include (that would starve a tenant). So after
/// scanning a tenant whose claim came back empty, we read the AUTHORITATIVE pending
/// count and clear the hint ONLY when it is exactly 0. A None claim with a non-zero
/// pending count means "all pending shards are locked by other workers" -> keep the
/// hint so a later poll retries.
async fn claim_across_tenants(
    app: &App,
    worker_id: &str,
    caps: &[String],
) -> Option<(i64, crate::db::ClaimedShard)> {
    let org_ids = app.control.tenants_with_pending().await.ok()?;
    for org_id in org_ids {
        let Some(store) = tenant_store(app, org_id).await else {
            continue;
        };
        match store.claim_shard(worker_id, caps).await {
            Ok(Some(shard)) => {
                app.policy.on_shard_claimed(org_id).await;
                return Some((org_id, shard));
            }
            Ok(None) => {
                // No shard claimable for our caps. Self-heal the hint, but ONLY if
                // the tenant genuinely has zero pending shards (a fresh COUNT): a
                // None can also mean "all pending shards locked by other workers" or
                // "pending but a backend we don't serve", in which cases we must NOT
                // clear or we'd strand them.
                match store.pending_shard_count().await {
                    Ok(0) => {
                        if let Err(e) = app.control.clear_tenant_pending(org_id).await {
                            tracing::warn!("clear_tenant_pending {org_id} failed: {e}");
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("pending_shard_count for tenant {org_id} failed: {e}"),
                }
                continue;
            }
            Err(e) => {
                tracing::warn!("claim_shard for tenant {} failed: {e}", org_id);
                continue;
            }
        }
    }
    None
}

/// POST /v1/worker/shards/:id/heartbeat where id is "<org>:<job>:<seed>:<worker>".
/// Keeps a claimed shard alive in its tenant DB. 200 if it touched a running
/// shard owned by that worker, 410 Gone if it's no longer running or was
/// reclaimed, 400 on a malformed id.
pub async fn heartbeat(State(app): State<App>, Path(id): Path<String>) -> StatusCode {
    let Some((org_id, job_id, seed, worker_id)) = parse_shard_id(&id) else {
        return StatusCode::BAD_REQUEST;
    };
    let Some(store) = tenant_store(&app, org_id).await else {
        return StatusCode::GONE;
    };
    match store.touch_shard(&job_id, seed, &worker_id).await {
        Ok(true) => StatusCode::OK,
        Ok(false) => StatusCode::GONE,
        Err(e) => {
            tracing::error!("touch_shard {id} failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// POST /v1/worker/shards/:id/result where id is "<org>:<job>:<seed>:<worker>".
/// Records the shard's terminal state + report in its tenant DB, then finalizes
/// the job once no shard is still pending/running. 200 on success, 410 if the
/// claimant is stale, 400 on a bad id or status.
pub async fn result(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(res): Json<ResultReq>,
) -> StatusCode {
    let Some((org_id, job_id, seed, worker_id)) = parse_shard_id(&id) else {
        return StatusCode::BAD_REQUEST;
    };
    let Some(state) = map_status(&res.status) else {
        tracing::warn!("result {id}: unknown status {:?}", res.status);
        return StatusCode::BAD_REQUEST;
    };
    let Some(store) = tenant_store(&app, org_id).await else {
        return StatusCode::GONE;
    };

    let duration = res.duration_s.unwrap_or(0.0);
    match store
        .set_shard(&job_id, seed, &worker_id, state, res.report, duration)
        .await
    {
        Ok(true) => {
            app.control
                .audit(
                    &format!("worker:{worker_id}"),
                    "worker.result",
                    Some(org_id),
                    serde_json::json!({ "job": job_id, "seed": seed, "status": res.status }),
                )
                .await;
        }
        Ok(false) => return StatusCode::GONE,
        Err(e) => {
            tracing::error!("set_shard {id} failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }

    if let Err(e) = maybe_finalize(&store, &job_id).await {
        tracing::error!("finalize after {id} failed: {e}");
        // The shard result is durably recorded; finalize is recoverable on the
        // next completing shard, so the worker's POST still succeeded.
    }
    StatusCode::OK
}

/// Map the worker's status string to a terminal shard state. "timeout" maps to
/// Error (a hung shard is a failed shard, not a clean one). Returns None for an
/// unrecognized status so the handler can 400 a malformed body.
fn map_status(status: &str) -> Option<ShardState> {
    match status {
        "clean" => Some(ShardState::Clean),
        "finding" => Some(ShardState::Finding),
        "timeout" => Some(ShardState::Error),
        "error" => Some(ShardState::Error),
        _ => None,
    }
}

/// Parse a "<org>:<job_id>:<seed>:<worker>" shard id. The org id is digits,
/// worker ids are sanitized to avoid `:`, and the job id is everything between
/// the leading org and trailing seed.
fn parse_shard_id(id: &str) -> Option<(i64, String, u32, String)> {
    let (org, rest) = id.split_once(':')?;
    let org_id: i64 = org.parse().ok()?;
    let (rest, worker_id) = rest.rsplit_once(':')?;
    if worker_id.is_empty() {
        return None;
    }
    let (job, seed) = rest.rsplit_once(':')?;
    if job.is_empty() {
        return None;
    }
    let seed: u32 = seed.parse().ok()?;
    Some((org_id, job.to_string(), seed, worker_id.to_string()))
}

/// Finalize the job if every shard is terminal, within ONE tenant's DB. Map
/// aggregation across remote workers is out of scope here (each keeps its own
/// .reproit state), so we record the job finished with a 0/0 map summary; findings
/// are derived on read from the shard states.
async fn maybe_finalize(store: &TenantStore, job_id: &str) -> anyhow::Result<()> {
    if store.job_incomplete(job_id).await? {
        return Ok(());
    }
    store.finalize_job(job_id, 0, 0).await?;
    let findings = store.findings_count(job_id).await.unwrap_or(0);
    tracing::info!("job {job_id}: complete. {findings} finding(s)");
    Ok(())
}

// ---- embedded worker pool (local dev) -------------------------------------

/// Spawn `n` in-process workers that claim + run shards locally (local dev: the
/// control plane is also a worker). Each worker loops: claim a shard, run it,
/// post the result, repeat; on `shutdown` it stops claiming and drains (the
/// in-flight shard finishes, then the task exits). A panic in one worker's
/// run can't take down the pool, since each shard runs under a guard task.
pub fn spawn_embedded(app: App, n: usize, shutdown: tokio::sync::watch::Receiver<bool>) {
    // Bound concurrency to `n` even if a future change spawns more pollers.
    let sem = Arc::new(Semaphore::new(n.max(1)));
    let caps: Vec<String> = vec!["web".into(), "android".into(), "ios".into()];
    for i in 0..n.max(1) {
        let app = app.clone();
        let caps = caps.clone();
        let sem = sem.clone();
        let mut shutdown = shutdown.clone();
        let worker_id = format!("embedded-{i}");
        tokio::spawn(async move {
            tracing::info!("embedded worker {worker_id} up (caps {caps:?})");
            loop {
                // Graceful drain: stop claiming new work once asked to shut down.
                if *shutdown.borrow() {
                    break;
                }
                // Acquire a permit before claiming so at most `n` shards run at
                // once (audit #16: never .unwrap() the acquire, the semaphore is
                // never closed here but treat a closed sem as "stop claiming").
                let permit = match sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };

                match claim_across_tenants(&app, &worker_id, &caps).await {
                    Some((org_id, shard)) => {
                        let task_app = app.clone();
                        let task_worker = worker_id.clone();
                        // Run the shard under its own task so a panic in the run
                        // is isolated (the join error is logged, the pool lives).
                        let handle = tokio::spawn(async move {
                            run_embedded_shard(&task_app, &task_worker, org_id, shard).await;
                        });
                        if let Err(e) = handle.await {
                            tracing::error!(
                                "embedded worker {worker_id}: shard task panicked: {e}"
                            );
                        }
                        drop(permit);
                    }
                    None => {
                        // Idle: release the permit and back off, but wake early
                        // on shutdown so drain doesn't wait out the full sleep.
                        drop(permit);
                        tokio::select! {
                            _ = tokio::time::sleep(IDLE_BACKOFF) => {}
                            _ = shutdown.changed() => {}
                        }
                    }
                }
            }
            tracing::info!("embedded worker {worker_id} drained, exiting");
        });
    }
}

/// Run one claimed shard in-process: record Running, run the reproit binary in
/// an isolated dir with a periodic heartbeat, then record the terminal state +
/// report and finalize the job if it's the last shard.
async fn run_embedded_shard(
    app: &App,
    worker_id: &str,
    org_id: i64,
    shard: crate::db::ClaimedShard,
) {
    let crate::db::ClaimedShard {
        job_id,
        seed,
        app_dir,
        budget,
        claimed_by,
        ..
    } = shard;

    // Bind to the owning tenant's DB for the whole run (claim already targeted it).
    let Some(store) = tenant_store(app, org_id).await else {
        tracing::warn!("embedded worker {worker_id}: tenant {org_id} unresolved, dropping shard");
        return;
    };

    let _ = store
        .set_shard(&job_id, seed, &claimed_by, ShardState::Running, None, 0.0)
        .await;

    // Heartbeat in the background so the requeue sweep never steals a shard that
    // is still running locally. Killed when the run finishes (guard drop).
    let hb = {
        let store = store.clone();
        let job_id = job_id.clone();
        let claimed_by = claimed_by.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(HEARTBEAT_EVERY);
            loop {
                tick.tick().await;
                match store.touch_shard(&job_id, seed, &claimed_by).await {
                    // Shard no longer running for us (finished/requeued): stop.
                    Ok(false) => break,
                    Ok(true) => {}
                    Err(e) => tracing::warn!("heartbeat {job_id}:{seed} failed: {e}"),
                }
            }
        })
    };

    let (state, report, elapsed) =
        run_shard(&app_dir, &job_id, seed, budget, &app.reproit_bin).await;
    hb.abort();

    match store
        .set_shard(&job_id, seed, &claimed_by, state.clone(), report, elapsed)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(
                "embedded worker {worker_id}: shard {job_id}:{seed} was reclaimed before result"
            );
            return;
        }
        Err(e) => {
            tracing::error!("embedded worker {worker_id}: set_shard {job_id}:{seed} failed: {e}");
            return;
        }
    }
    if let Err(e) = maybe_finalize(&store, &job_id).await {
        tracing::error!("embedded worker {worker_id}: finalize {job_id} failed: {e}");
    }
}

/// Run the reproit binary against a shard in an ISOLATED working dir and return
/// `(terminal state, report, elapsed_seconds)`. Sandboxed (audit #15): the
/// app_dir must exist and be a directory; all work happens inside the per-shard
/// temp dir; the child is killed if it exceeds SHARD_TIMEOUT (a hung run maps to
/// Error, never Clean). Adapted from the original in-process worker logic.
async fn run_shard(
    app_dir: &str,
    job_id: &str,
    seed: u32,
    budget: u32,
    reproit_bin: &str,
) -> (ShardState, Option<String>, f64) {
    let t0 = Instant::now();

    // Validate the app dir up front so a bad job can't make us touch arbitrary
    // paths; all writes below live under `work` (a child of the app dir). This is
    // a DEFENSIVE re-check of the same confinement the submit handler applies
    // (canonicalize + confine under the jobs root): a shard that reaches the
    // worker with an out-of-root path (stale queue row, future submit path) is
    // refused here too (finding #6).
    if let Err(msg) = super::validate_app_dir(app_dir) {
        tracing::error!("shard {job_id}:{seed}: {msg}");
        return (ShardState::Error, Some(msg), t0.elapsed().as_secs_f64());
    }

    let work = match isolate(app_dir, job_id, seed) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("shard {job_id}:{seed}: isolate failed: {e}");
            return (
                ShardState::Error,
                Some(format!("isolate: {e}")),
                t0.elapsed().as_secs_f64(),
            );
        }
    };

    let mut cmd = tokio::process::Command::new(reproit_bin);
    cmd.arg("--config")
        .arg(work.join("reproit.yaml"))
        .args(["fuzz", "--seed"])
        .arg(seed.to_string())
        .args(["--runs", "1", "--budget"])
        .arg(budget.to_string())
        .env("REPROIT_HEADLESS", "1");

    // Wall-clock cap on the child: on timeout, kill it and report Error so a
    // hung run can't wedge the worker (audit #15).
    let out = match tokio::time::timeout(SHARD_TIMEOUT, cmd.output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            tracing::error!("shard {job_id}:{seed}: spawn failed: {e}");
            return (
                ShardState::Error,
                Some(e.to_string()),
                t0.elapsed().as_secs_f64(),
            );
        }
        Err(_) => {
            tracing::warn!(
                "shard {job_id}:{seed}: timed out after {}s, marking error",
                SHARD_TIMEOUT.as_secs()
            );
            return (
                ShardState::Error,
                Some(format!("timeout after {}s", SHARD_TIMEOUT.as_secs())),
                t0.elapsed().as_secs_f64(),
            );
        }
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    let found = stdout.contains("FINDING");
    let report = find_report(&work);
    let state = if found || report.is_some() {
        ShardState::Finding
    } else {
        ShardState::Clean
    };
    (state, report, t0.elapsed().as_secs_f64())
}

/// Build an isolated work dir for a shard: its own reproit.yaml with a per-shard
/// evidence outDir, sharing the app build/URL of the original. Parallel shards
/// never share .reproit/runs or the fuzz config. All paths stay under the app
/// dir's `.reproit-cloud/<job>/<seed>` subtree.
fn isolate(app_dir: &str, job_id: &str, seed: u32) -> anyhow::Result<PathBuf> {
    let app = PathBuf::from(app_dir);
    let cfg = std::fs::read_to_string(app.join("reproit.yaml"))?;
    let work = app.join(format!(".reproit-cloud/{job_id}/{seed}"));
    std::fs::create_dir_all(&work)?;

    // Rewrite evidence.outDir to the shard's dir (absolute), so parallel shards
    // never share .reproit/runs or the fuzz config.
    let shard_out = work.join("runs");
    let mut rewritten = String::new();
    let mut in_evidence = false;
    for line in cfg.lines() {
        if line.trim_start().starts_with("evidence:") {
            in_evidence = true;
            rewritten.push_str(line);
            rewritten.push('\n');
            continue;
        }
        if in_evidence && line.trim_start().starts_with("outDir:") {
            let indent = &line[..line.len() - line.trim_start().len()];
            rewritten.push_str(&format!("{indent}outDir: {}\n", shard_out.display()));
            continue;
        }
        // web-runner / projectDir are relative to the original app dir; rewrite
        // the common relative ones to absolute so the shard config resolves them
        // from anywhere.
        if let Some(rest) = line.trim_start().strip_prefix("webRunnerDir:") {
            let indent = &line[..line.len() - line.trim_start().len()];
            let abs = app
                .join(rest.trim())
                .canonicalize()
                .unwrap_or_else(|_| app.join(rest.trim()));
            rewritten.push_str(&format!("{indent}webRunnerDir: {}\n", abs.display()));
            continue;
        }
        rewritten.push_str(line);
        rewritten.push('\n');
    }
    std::fs::write(work.join("reproit.yaml"), rewritten)?;
    Ok(work)
}

/// Extract the most recent fuzz.md report under the shard's runs dir, if any.
fn find_report(work: &std::path::Path) -> Option<String> {
    let runs = work.join("runs");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&runs)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for d in dirs.iter().rev() {
        let f = d.join("fuzz.md");
        if f.exists() {
            match std::fs::read_to_string(&f) {
                Ok(s) => return Some(s),
                Err(e) => tracing::warn!("read {}: {e}", f.display()),
            }
        }
    }
    None
}
