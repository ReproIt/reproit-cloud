//! The background REGRESSION SWEEP: a periodic task that turns the on-read
//! resolution engine into a PROACTIVE, durable alert signal.
//!
//! On-read evaluation (the bucket detail/timeline path) is honest but reactive:
//! the prod-truth is only computed when someone LOOKS. A bug can regress at 2am
//! and nobody knows until they open the dashboard. This sweep closes that gap: on
//! a fixed interval it re-runs the SAME pure `triage::resolution::evaluate` for
//! every bucket with a `fixed_in_build` anchor (NO logic fork, the read path and
//! the sweep agree by construction), persists the current status so reads stay
//! fast, and, when the status CHANGES, appends a row to the durable
//! `bucket_resolution_events` log, the queryable, alertable "regressed 2h ago".
//!
//! The transition DECISION is a pure function (`transition`), unit-tested hard:
//! a change yields exactly one event, no change yields none. The orchestration
//! (`sweep_once`) does the DB I/O around it and is engineered to NEVER crash the
//! server: every error is logged and the sweep continues to the next bucket.

use crate::db::TenantStore;
use crate::ingest::buckets;
use crate::triage::resolution;
use crate::App;
use std::time::Duration;

/// How often the sweep runs. Five minutes balances "alert promptly" against "don't
/// hammer the DB"; founder-tunable, and env-overridable via `REPROIT_SWEEP_SECS`
/// (set 0 to DISABLE the sweep entirely, e.g. on a read replica or in a test).
pub const DEFAULT_SWEEP_INTERVAL_SECS: u64 = 5 * 60;

/// The cap on how many recent transitions the `/resolution-events` endpoint
/// returns. Founder-tunable; the dashboard pages if it needs more history.
pub const RECENT_EVENTS_LIMIT: i64 = 100;

/// Resolve the sweep interval from the environment, falling back to the default.
/// `REPROIT_SWEEP_SECS=0` disables the sweep (returns None). An unparseable value
/// falls back to the default rather than failing startup.
pub fn interval_secs() -> Option<u64> {
    match std::env::var("REPROIT_SWEEP_SECS").ok().as_deref() {
        Some("0") => None,
        Some(v) => Some(v.parse().unwrap_or(DEFAULT_SWEEP_INTERVAL_SECS)),
        None => Some(DEFAULT_SWEEP_INTERVAL_SECS),
    }
}

/// The outbound alert webhook URL (`REPROIT_ALERT_WEBHOOK`): a Slack/Discord/
/// generic incoming-webhook endpoint that gets ONE JSON POST per alertable
/// transition. Read once and cached for the process lifetime (the sweep is a
/// hot loop; re-reading env every bucket buys nothing). Unset/empty means no
/// alerts, silently (the self-host default: alerting is opt-in).
static ALERT_WEBHOOK: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

fn alert_webhook_url() -> Option<&'static str> {
    ALERT_WEBHOOK
        .get_or_init(|| {
            std::env::var("REPROIT_ALERT_WEBHOOK")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .as_deref()
}

/// PURE alert decision: given a transition the sweep just recorded, build the
/// webhook payload, or None when the transition isn't alert-worthy. Only a
/// transition INTO `regressed` (a shipped fix came back, the headline page) or
/// INTO `resolved` (the fix confirmed by prod traffic) alerts; the intermediate
/// states (`active`, `resolving`) are dashboard signal, not pager signal.
///
/// The payload is one flat JSON object (`app`, `bucket`, `from`, `to`, `org`)
/// plus a human-readable `text` field, which Slack (and Discord in
/// Slack-compat mode) renders directly, so one URL shape serves Slack, Discord
/// and any generic webhook receiver.
pub(crate) fn alert_payload(
    app_id: &str,
    bucket_id: &str,
    from: Option<&str>,
    to: &str,
    org_id: i64,
) -> Option<serde_json::Value> {
    if to != "regressed" && to != "resolved" {
        return None;
    }
    let from_s = from.unwrap_or("?");
    let text = format!("Reproit: bucket {bucket_id} in {app_id} is now {to} (was {from_s})");
    Some(serde_json::json!({
        "app": app_id,
        "bucket": bucket_id,
        "from": from,
        "to": to,
        "org": org_id,
        "text": text,
    }))
}

/// POST one alert payload to the configured webhook (same tiny reqwest shape as
/// `mail::send`: one client, one POST, status check). The CALLER decides what a
/// failure means; for the sweep it is log-and-continue, never a sweep failure.
async fn post_alert(url: &str, payload: &serde_json::Value) -> anyhow::Result<()> {
    let resp = reqwest::Client::new()
        .post(url)
        .json(payload)
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("alert webhook failed ({status}): {body}");
    }
    Ok(())
}

/// Fire a best-effort OPERATIONAL alert (a broken hosted loop, not a customer
/// bucket transition), reusing the same `REPROIT_ALERT_WEBHOOK`. Fire-and-forget
/// on its own task so a slow/down endpoint never stalls the caller; a delivery
/// failure is only warn-logged. The DURABLE signal is the Prometheus counter the
/// caller increments alongside this, matching the transition-alert design where
/// the metric is guaranteed and the webhook is convenience. No-op unconfigured.
pub(crate) fn fire_ops_alert(text: String) {
    let Some(url) = alert_webhook_url() else {
        return;
    };
    let payload = serde_json::json!({ "kind": "ops", "text": format!("Reproit ops: {text}") });
    tokio::spawn(async move {
        if let Err(e) = post_alert(url, &payload).await {
            tracing::warn!("ops alert webhook failed: {e}");
        }
    });
}

/// PURE transition decision: given the bucket's PREVIOUSLY-persisted status (None
/// if never swept) and the freshly-computed `current` status, decide whether a
/// transition event should be recorded. Returns the `from` status to log (Some on
/// a change, where `from` is the prior status; the first-ever observation is NOT
/// logged as a transition, see below), or None when nothing changed.
///
/// Rules:
///   - SAME status (including a repeat first-sweep `active`) => None: no event.
///   - First observation (prev = None) => None: there's no PRIOR truth to have
///     transitioned FROM, so the first sweep just seeds the baseline. A bucket's
///     genuine "it regressed" event fires on the NEXT sweep when it actually
///     flips. (This keeps the log to real changes, not a backfill flood the first
///     time the sweep runs over an existing DB.)
///   - CHANGE (prev = Some(x), current y, x != y) => Some(x): record `x -> y`.
///
/// `Some(None)` is impossible by construction (a change always has a prior). The
/// double Option encodes "record an event?" (outer) and "what `from`?" (inner is
/// always `Some` here, kept as Option to match the nullable column).
pub fn transition(prev: Option<&str>, current: &str) -> Option<Option<String>> {
    match prev {
        // First time we've ever seen this bucket: seed the baseline, no event.
        None => None,
        // Unchanged: no event.
        Some(p) if p == current => None,
        // A real flip: record from -> to.
        Some(p) => Some(Some(p.to_string())),
    }
}

/// Spawn the background sweep loop on a tokio interval. A no-op (logs and returns)
/// when the sweep is disabled via `REPROIT_SWEEP_SECS=0`. The loop NEVER
/// propagates an error: `sweep_once` swallows + logs per-bucket failures, so a DB
/// hiccup can't take down the server. Started from `main` alongside the other
/// background sweeps.
pub fn spawn(app: App) {
    let Some(secs) = interval_secs() else {
        tracing::info!("resolution sweep disabled (REPROIT_SWEEP_SECS=0)");
        return;
    };
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(secs.max(1)));
        // Skip missed ticks rather than burst-catch-up if the sweep ran long.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!("resolution sweep every {secs}s");
        loop {
            tick.tick().await;
            sweep_once(&app).await;
        }
    });
}

/// Run one bounded pass over tenants whose anchored buckets are due.
pub async fn sweep_once(app: &App) {
    // Self-host has no edition policy feeding the due-work queue, so each pass
    // schedules every registered tenant due NOW first. That preserves the
    // historical sweep-everything-each-interval behavior through the same
    // queue-driven loop the hosted edition runs.
    if app.self_hosted {
        match app.control.all_tenants().await {
            Ok(tenants) => {
                for t in tenants {
                    if t.status != crate::db::TenantStatus::Active {
                        continue;
                    }
                    if let Err(e) = app
                        .control
                        .schedule_tenant_work(t.org_id, "resolution", 0)
                        .await
                    {
                        tracing::warn!(
                            "resolution sweep: self-host enqueue for {} failed: {e}",
                            t.org_id
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!("resolution sweep: list tenants failed: {e}");
                return;
            }
        }
    }
    let org_ids = match app.control.tenants_due_for("resolution", 128).await {
        Ok(ids) => ids,
        Err(e) => {
            tracing::warn!("resolution sweep: due-work read failed: {e}");
            return;
        }
    };
    let now = chrono::Utc::now().to_rfc3339();
    let mut changes = 0u64;
    for org_id in org_ids {
        let Ok(tenant) = app.tenancy.resolve(org_id).await else {
            continue;
        };
        changes += sweep_tenant(&tenant.store, org_id, &now).await;
        if let Err(error) = app
            .control
            .reschedule_tenant_work(org_id, "resolution", interval_secs().unwrap_or(300) as i64)
            .await
        {
            tracing::warn!("resolution sweep reschedule for tenant {org_id} failed: {error}");
        }
    }
    if changes > 0 {
        tracing::info!("resolution sweep: {changes} status change(s) recorded");
    }
}

/// Sweep every anchored bucket in ONE tenant's database. Tolerant of an empty db
/// (no anchored buckets) and crash-proof per bucket. Returns the change count.
async fn sweep_tenant(store: &TenantStore, org_id: i64, now: &str) -> u64 {
    let anchored = match store.anchored_buckets().await {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!("resolution sweep: anchored_buckets for tenant {org_id} failed: {e}");
            return 0;
        }
    };
    let mut changes = 0u64;
    for b in &anchored {
        match sweep_bucket(store, b, org_id, now).await {
            Ok(n) => changes += n,
            // One bad bucket must not abort the pass: log and move on.
            Err(e) => tracing::warn!(
                "resolution sweep: tenant {org_id} bucket {}/{} failed: {e}",
                b.app_id,
                b.bucket_id
            ),
        }
    }
    changes
}

/// Evaluate ONE anchored bucket and, on a status change, persist + log it. Returns
/// the number of events recorded (0 or 1). Reuses the on-read resolution wiring
/// (`compute_for_bucket`) so the sweep and the dashboard can never disagree.
///
/// The status is persisted on EVERY pass (so `updated_at` and the fast-read cache
/// stay current), but an EVENT is appended only on a real change, exactly once.
async fn sweep_bucket(
    store: &TenantStore,
    b: &crate::db::AnchoredBucket,
    org_id: i64,
    now: &str,
) -> anyhow::Result<u64> {
    let (outcome, regression_build) =
        compute_for_bucket(store, &b.app_id, &b.bucket_id, &b.fixed_in_build, now).await?;
    let current = outcome.status.as_str();
    let prev = store
        .last_resolution_status(&b.app_id, &b.bucket_id)
        .await?;

    let mut recorded = 0u64;
    if let Some(from) = transition(prev.as_deref(), current) {
        store
            .record_resolution_event(
                &b.app_id,
                &b.bucket_id,
                from.as_deref(),
                current,
                Some(&b.fixed_in_build),
            )
            .await?;
        recorded = 1;
        // One counter per recorded transition, labeled by the destination
        // status, so Prometheus/Alertmanager can page on
        // `resolution_transitions_total{to="regressed"}` independently of the
        // webhook below (belt and braces: metrics survive a webhook outage).
        metrics::counter!("resolution_transitions_total", "to" => current.to_string()).increment(1);
        tracing::info!(
            "resolution sweep: {}/{} {} -> {}",
            b.app_id,
            b.bucket_id,
            from.as_deref().unwrap_or("?"),
            current
        );
        // Best-effort outbound alert on the transitions a human should hear
        // about (into regressed / into resolved). Fired on a spawned task so a
        // slow or down webhook endpoint can never stall the sweep, and a
        // failure is a warn-log, never a sweep error (the durable event row
        // above is the source of truth; the webhook is a courtesy ping).
        if let Some(url) = alert_webhook_url() {
            if let Some(payload) =
                alert_payload(&b.app_id, &b.bucket_id, from.as_deref(), current, org_id)
            {
                let (app_id, bucket_id) = (b.app_id.clone(), b.bucket_id.clone());
                tokio::spawn(async move {
                    if let Err(e) = post_alert(url, &payload).await {
                        tracing::warn!(
                            "resolution sweep: alert webhook for {app_id}/{bucket_id} failed: {e}"
                        );
                    }
                });
            }
        }
        if current == "resolved" {
            crate::integrations::close_ticket_on_fix(
                store,
                &b.app_id,
                &b.bucket_id,
                Some(&b.fixed_in_build),
            )
            .await;
        } else if current == "regressed" {
            crate::integrations::reopen_ticket_on_regression(
                store,
                &b.app_id,
                &b.bucket_id,
                regression_build.as_deref(),
            )
            .await;
        }
    }
    // Persist the current status last (the baseline the NEXT pass diffs against),
    // so a failure recording the event doesn't advance the baseline past it.
    store
        .upsert_resolution_status(&b.app_id, &b.bucket_id, current, Some(&b.fixed_in_build))
        .await?;
    Ok(recorded)
}

/// Compute the prod-evidence resolution for ONE bucket the way the on-read path
/// does: the app-wide stream anchors build-ordering + supplies the post-fix
/// traffic denominator; the bucket's own stream drives recurrence. The SAME pure
/// `resolution::evaluate` the detail endpoint calls (no logic fork).
async fn compute_for_bucket(
    store: &TenantStore,
    app_id: &str,
    bucket: &str,
    fixed_in_build: &str,
    now: &str,
) -> anyhow::Result<(resolution::Outcome, Option<String>)> {
    let traffic_rows = store.build_traffic(app_id).await?;
    let weighted_traffic: Vec<(resolution::Occurrence, u64)> = traffic_rows
        .iter()
        .map(|(build, count, at)| {
            (
                resolution::Occurrence {
                    at: at.clone(),
                    build: Some(build.clone()),
                },
                *count,
            )
        })
        .collect();
    let app_stream: Vec<resolution::Occurrence> = if weighted_traffic.is_empty() {
        store
            .recent_errors_with_meta(app_id, crate::ingest::baseline_sample())
            .await?
            .iter()
            .map(|(_, at, rec)| resolution::Occurrence {
                at: at.clone(),
                build: buckets::build_version(rec),
            })
            .collect()
    } else {
        weighted_traffic
            .iter()
            .map(|(occ, _)| occ.clone())
            .collect()
    };
    let bug: Vec<resolution::Occurrence> = store
        .errors_for_bucket(app_id, bucket, crate::ingest::baseline_sample())
        .await?
        .iter()
        .map(|(_, at, rec)| resolution::Occurrence {
            at: at.clone(),
            build: buckets::build_version(rec),
        })
        .collect();
    let first_seen = resolution::first_seen_by_build(&app_stream);
    let traffic = if weighted_traffic.is_empty() {
        resolution::post_fix_traffic(&app_stream, fixed_in_build)
    } else {
        resolution::post_fix_build_traffic(&weighted_traffic, fixed_in_build)
    };
    let outcome = resolution::evaluate(
        &bug,
        &first_seen,
        Some(fixed_in_build),
        traffic,
        now,
        resolution::Thresholds::configured(),
    );
    let regression_build = latest_post_fix_build(&bug, &first_seen, fixed_in_build);
    Ok((outcome, regression_build))
}

fn latest_post_fix_build(
    bug: &[resolution::Occurrence],
    first_seen: &std::collections::BTreeMap<String, i64>,
    fixed_in_build: &str,
) -> Option<String> {
    let fix_epoch = *first_seen.get(fixed_in_build)?;
    bug.iter()
        .filter_map(|occurrence| {
            let build = occurrence.build.as_deref()?;
            let epoch = chrono::DateTime::parse_from_rfc3339(&occurrence.at)
                .ok()?
                .timestamp();
            let build_epoch = *first_seen.get(build)?;
            (epoch >= fix_epoch && (build == fixed_in_build || build_epoch >= fix_epoch))
                .then_some((epoch, build.to_string()))
        })
        .max_by_key(|(epoch, _)| *epoch)
        .map(|(_, build)| build)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regression_notification_names_the_actual_recurring_build() {
        let bug = vec![
            resolution::Occurrence {
                at: "2026-07-16T20:00:00Z".into(),
                build: Some("fixed".into()),
            },
            resolution::Occurrence {
                at: "2026-07-16T21:00:00Z".into(),
                build: Some("regressed".into()),
            },
        ];
        let first_seen = resolution::first_seen_by_build(&bug);
        assert_eq!(
            latest_post_fix_build(&bug, &first_seen, "fixed").as_deref(),
            Some("regressed")
        );
    }

    #[test]
    fn first_observation_seeds_the_baseline_without_an_event() {
        // No prior status: the first sweep just records the baseline, no event.
        assert_eq!(transition(None, "active"), None);
        assert_eq!(transition(None, "regressed"), None);
    }

    #[test]
    fn no_change_produces_no_event() {
        // Same status across two sweeps: nothing to alert on.
        assert_eq!(transition(Some("resolved"), "resolved"), None);
        assert_eq!(transition(Some("regressed"), "regressed"), None);
        assert_eq!(transition(Some("resolving"), "resolving"), None);
    }

    #[test]
    fn a_change_produces_exactly_one_event_with_the_prior_status() {
        // resolved -> regressed (the headline alert): one event, from = resolved.
        assert_eq!(
            transition(Some("resolved"), "regressed"),
            Some(Some("resolved".to_string()))
        );
        // resolving -> resolved: the fix confirmed.
        assert_eq!(
            transition(Some("resolving"), "resolved"),
            Some(Some("resolving".to_string()))
        );
        // active -> resolving: a fix just got claimed and is now validating.
        assert_eq!(
            transition(Some("active"), "resolving"),
            Some(Some("active".to_string()))
        );
    }

    #[test]
    fn only_regressed_and_resolved_transitions_alert() {
        // The headline page: a shipped fix came back.
        let p = alert_payload("shop", "b-1", Some("resolved"), "regressed", 42).unwrap();
        assert_eq!(p["app"], "shop");
        assert_eq!(p["bucket"], "b-1");
        assert_eq!(p["from"], "resolved");
        assert_eq!(p["to"], "regressed");
        assert_eq!(p["org"], 42);
        // The `text` field is what Slack renders; it must name the essentials.
        let text = p["text"].as_str().unwrap();
        assert!(text.contains("b-1") && text.contains("shop") && text.contains("regressed"));

        // The fix confirmed: also alert-worthy.
        let p = alert_payload("shop", "b-1", Some("resolving"), "resolved", 42).unwrap();
        assert_eq!(p["to"], "resolved");

        // Intermediate states are dashboard signal, not pager signal.
        assert!(alert_payload("shop", "b-1", Some("active"), "resolving", 42).is_none());
        assert!(alert_payload("shop", "b-1", Some("resolved"), "active", 42).is_none());
    }

    #[test]
    fn alert_payload_tolerates_a_missing_from() {
        // `from` is nullable in the event log; the payload carries null and the
        // text degrades to "?" rather than panicking or dropping the alert.
        let p = alert_payload("shop", "b-9", None, "regressed", 7).unwrap();
        assert_eq!(p["from"], serde_json::Value::Null);
        assert!(p["text"].as_str().unwrap().contains("was ?"));
    }

    #[test]
    fn interval_env_override_and_disable() {
        // Default when unset.
        std::env::remove_var("REPROIT_SWEEP_SECS");
        assert_eq!(interval_secs(), Some(DEFAULT_SWEEP_INTERVAL_SECS));
        // Explicit value.
        std::env::set_var("REPROIT_SWEEP_SECS", "30");
        assert_eq!(interval_secs(), Some(30));
        // Zero disables.
        std::env::set_var("REPROIT_SWEEP_SECS", "0");
        assert_eq!(interval_secs(), None);
        // Garbage falls back to the default (never fails startup).
        std::env::set_var("REPROIT_SWEEP_SECS", "not-a-number");
        assert_eq!(interval_secs(), Some(DEFAULT_SWEEP_INTERVAL_SECS));
        std::env::remove_var("REPROIT_SWEEP_SECS");
    }
}

/// Webhook POST tests against a LOCAL mock receiver (the same mock-server shape
/// the tracker and R2 scoped-creds tests use). No real Slack/Discord endpoint
/// is ever called; `post_alert` is tested directly with the mock's URL, so the
/// process-global `REPROIT_ALERT_WEBHOOK` env is never touched.
#[cfg(test)]
mod webhook_tests {
    use super::*;
    use axum::{extract::State, routing::post, Json, Router};
    use std::sync::{Arc, Mutex};

    type Shared = Arc<Mutex<Vec<serde_json::Value>>>;

    /// Spin up a local webhook receiver on an ephemeral port, recording every
    /// JSON body. `ok=false` answers 500 to every POST (a down/misconfigured
    /// endpoint).
    async fn mock_webhook(ok: bool) -> (String, Shared) {
        let rec: Shared = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route(
                "/hook",
                post(
                    move |State(rec): State<Shared>, Json(b): Json<serde_json::Value>| async move {
                        rec.lock().unwrap().push(b);
                        if ok {
                            axum::http::StatusCode::OK
                        } else {
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR
                        }
                    },
                ),
            )
            .with_state(rec.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (url, rec)
    }

    #[tokio::test]
    async fn alert_posts_one_json_object_with_the_slack_text_field() {
        let (url, rec) = mock_webhook(true).await;
        let payload = alert_payload("shop", "b-1", Some("resolved"), "regressed", 42).unwrap();
        post_alert(&url, &payload).await.unwrap();

        let bodies = rec.lock().unwrap();
        assert_eq!(bodies.len(), 1, "exactly one POST per transition");
        let b = &bodies[0];
        assert_eq!(b["app"], "shop");
        assert_eq!(b["bucket"], "b-1");
        assert_eq!(b["from"], "resolved");
        assert_eq!(b["to"], "regressed");
        assert_eq!(b["org"], 42);
        assert!(b["text"].as_str().unwrap().contains("regressed"));
    }

    #[tokio::test]
    async fn a_failing_endpoint_is_an_error_the_sweep_only_logs() {
        let (url, rec) = mock_webhook(false).await;
        let payload = alert_payload("shop", "b-1", Some("resolved"), "regressed", 42).unwrap();
        let err = post_alert(&url, &payload).await.unwrap_err().to_string();
        assert!(err.contains("500"), "unexpected error: {err}");
        // The POST did reach the endpoint; only the status made it a failure.
        assert_eq!(rec.lock().unwrap().len(), 1);
    }
}
