//! Bug <-> ticket integration: a content-addressed bucket maps 1:1 to an
//! external issue-tracker ticket.
//!
//! Two flows, both OPT-IN per app (no config => no-op, zero overhead) and
//! PII-safe by construction (only ever the bucket's derived, value-free data):
//!
//!   - **file-on-form**: when a NEW bucket appears for a configured app, file an
//!     issue carrying the PII-safe repro package (bucket id, crash signature,
//!     normalized message, replay action list, lineage, and the local
//!     direct `reproit bkt_...` command), and persist the link.
//!   - **close-on-fix**: when a replay-result flips a bucket to FIXED (a posted
//!     result whose verdict says the bug no longer reproduces), auto-comment +
//!     close the linked ticket with proof.
//!
//! The provider behind a link is a small `Tracker` trait (create_issue /
//! comment / close), so GitHub/Jira/Linear/Shortcut plug into the same
//! buckets/replay-results flow. The DB link
//! (`bucket_tickets(app, bucket_id, provider, repo, external_id, url)`) lives in
//! `db::integrations`; the GitHub REST client in `github`. Everything here is
//! deterministic, side-effect-free logic (the trigger decision + the issue-body
//! builder) plus the thin orchestration that wires it to the handlers, mirroring
//! how `ingest::buckets` keeps transforms pure and the DB calls in handlers.

pub mod dispatch;
pub mod github;
pub mod jira;
pub mod linear;
pub mod shortcut;

use crate::ingest::{buckets, ErrorRec};
use github::GithubTracker;
use jira::JiraTracker;
use linear::LinearTracker;
use shortcut::ShortcutTracker;

/// The provider-agnostic issue-tracker surface a bucket links against. Three
/// operations cover the whole bug<->ticket lifecycle, so a provider is a single
/// impl, no change to the buckets/replay-results flow:
///   - `create_issue` files a new ticket from a PII-safe body, returns its
///     provider-native id + url (what we persist into `bucket_tickets`).
///   - `comment` posts the verified-fix proof onto the linked ticket.
///   - `close` transitions it to the provider's terminal/closed state.
///
/// Async-trait-free (returns boxed futures via `async fn` in trait, stabilized
/// since Rust 1.75) to match the codebase's plain-`async fn` style.
#[allow(async_fn_in_trait)]
pub trait Tracker {
    /// Provider tag persisted in `bucket_tickets.provider`.
    fn provider(&self) -> &'static str;
    /// The repo/project identifier persisted in `bucket_tickets.repo`.
    fn repo(&self) -> &str;
    /// File a new issue; returns (external_id, html_url).
    async fn create_issue(&self, title: &str, body: &str) -> anyhow::Result<(String, String)>;
    /// Comment on an existing issue (the verified-fix proof).
    async fn comment(&self, external_id: &str, body: &str) -> anyhow::Result<()>;
    /// Close an existing issue (transition to the provider's closed state).
    async fn close(&self, external_id: &str) -> anyhow::Result<()>;
}

pub enum ConfiguredTracker {
    Github(GithubTracker),
    Jira(JiraTracker),
    Linear(LinearTracker),
    Shortcut(ShortcutTracker),
}

impl ConfiguredTracker {
    fn provider(&self) -> &'static str {
        match self {
            Self::Github(t) => t.provider(),
            Self::Jira(t) => t.provider(),
            Self::Linear(t) => t.provider(),
            Self::Shortcut(t) => t.provider(),
        }
    }

    fn repo(&self) -> &str {
        match self {
            Self::Github(t) => t.repo(),
            Self::Jira(t) => t.repo(),
            Self::Linear(t) => t.repo(),
            Self::Shortcut(t) => t.repo(),
        }
    }

    async fn create_issue(&self, title: &str, body: &str) -> anyhow::Result<(String, String)> {
        match self {
            Self::Github(t) => t.create_issue(title, body).await,
            Self::Jira(t) => t.create_issue(title, body).await,
            Self::Linear(t) => t.create_issue(title, body).await,
            Self::Shortcut(t) => t.create_issue(title, body).await,
        }
    }

    async fn comment(&self, external_id: &str, body: &str) -> anyhow::Result<()> {
        match self {
            Self::Github(t) => t.comment(external_id, body).await,
            Self::Jira(t) => t.comment(external_id, body).await,
            Self::Linear(t) => t.comment(external_id, body).await,
            Self::Shortcut(t) => t.comment(external_id, body).await,
        }
    }

    async fn close(&self, external_id: &str) -> anyhow::Result<()> {
        match self {
            Self::Github(t) => t.close(external_id).await,
            Self::Jira(t) => t.close(external_id).await,
            Self::Linear(t) => t.close(external_id).await,
            Self::Shortcut(t) => t.close(external_id).await,
        }
    }
}

/// Resolve the configured tracker for an app, or `None` if unconfigured (the
/// opt-in gate: no env/config => no integration, both flows short-circuit).
///
/// Config is per-app via env, namespaced by app id so one cloud can serve many
/// apps with distinct tracker projects/tokens, matching how billing/SSO read env lazily:
///   REPROIT_TRACKER_PROVIDER__<APP> github|jira|linear|shortcut
///
/// GitHub:
///   REPROIT_GH_REPO__<APP>   owner/repo   (the target repository)
///   REPROIT_GH_TOKEN__<APP>  ghp_…/PAT    (a token with `issues:write`)
///
/// Jira:
///   REPROIT_JIRA_BASE_URL__<APP>       https://example.atlassian.net
///   REPROIT_JIRA_EMAIL__<APP>          bot@example.com
///   REPROIT_JIRA_API_TOKEN__<APP>      Atlassian API token
///   REPROIT_JIRA_PROJECT_KEY__<APP>    ENG
///   REPROIT_JIRA_DONE_TRANSITION_ID__<APP>  optional close transition id
///
/// Linear:
///   REPROIT_LINEAR_TOKEN__<APP>         Linear API key
///   REPROIT_LINEAR_TEAM_ID__<APP>       team UUID
///   REPROIT_LINEAR_DONE_STATE_ID__<APP> optional done state UUID
///
/// Shortcut:
///   REPROIT_SHORTCUT_TOKEN__<APP>          Shortcut API token
///   REPROIT_SHORTCUT_PROJECT_ID__<APP>     numeric project id
///   REPROIT_SHORTCUT_DONE_STATE_ID__<APP>  optional workflow state id
///
/// Resolve the tracker for an app: the tenant's `project_integrations` row
/// first (the hosted self-serve path), then env config (`resolve`). The row
/// wins when it names a provider AND yields a working config; a broken row
/// (undecryptable token, missing fields) logs and falls through to env so a
/// half-saved config can't silently disable an env-configured integration.
pub async fn resolve_for(
    store: &crate::db::TenantStore,
    app_id: &str,
) -> Option<ConfiguredTracker> {
    match store.integration_for(app_id).await {
        Ok(Some(row)) => match from_config(&row) {
            Some(t) => return Some(t),
            None => {
                if row.token_enc.is_some() {
                    tracing::warn!("project_integrations row for {app_id} is incomplete/undecryptable; falling back to env");
                }
            }
        },
        Ok(None) => {}
        Err(e) => tracing::warn!("integration_for({app_id}) failed: {e}"),
    }
    resolve(app_id)
}

/// Build a tracker from a per-tenant config row. Provider-specific knobs ride
/// in `extra` (camelCase keys, matching the PUT body).
fn from_config(row: &crate::db::tenant::IntegrationRow) -> Option<ConfiguredTracker> {
    let token = crate::db::secrets::decrypt(row.token_enc.as_deref()?).ok()?;
    let xs = |k: &str| {
        row.extra
            .get(k)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    };
    match row.provider.as_str() {
        "github" | "gh" => Some(ConfiguredTracker::Github(GithubTracker::new(
            row.repo.clone().filter(|r| !r.is_empty())?,
            token,
        ))),
        "jira" => Some(ConfiguredTracker::Jira(JiraTracker::from_parts(
            row.base_url.clone().filter(|s| !s.is_empty())?,
            row.user_email.clone().filter(|s| !s.is_empty())?,
            token,
            xs("projectKey")?,
            xs("issueType"),
            xs("doneTransitionId"),
        ))),
        "linear" => Some(ConfiguredTracker::Linear(LinearTracker::from_parts(
            token,
            xs("teamId")?,
            xs("doneStateId"),
            row.base_url.clone().filter(|s| !s.is_empty()),
        ))),
        "shortcut" | "clubhouse" => Some(ConfiguredTracker::Shortcut(ShortcutTracker::from_parts(
            token,
            xs("projectId")?.parse().ok()?,
            xs("doneStateId").and_then(|v| v.parse().ok()),
            row.base_url.clone().filter(|s| !s.is_empty()),
        ))),
        _ => None,
    }
}

/// A global fallback (no `__<APP>` suffix) lets a single-app deploy skip the
/// suffix, but ONLY under self-host: on a hosted multi-tenant deploy a bare
/// `REPROIT_GH_TOKEN`/`REPROIT_GH_REPO` would apply to EVERY tenant's apps and
/// file one tenant's crash buckets into another tenant's repo. `<APP>` is the
/// app id upper-cased with non-alnum mapped to `_`, so an app id like
/// `acme-web` reads `REPROIT_GH_REPO__ACME_WEB`.
pub fn resolve(app_id: &str) -> Option<ConfiguredTracker> {
    let key = env_key(app_id);
    let provider = env_for("REPROIT_TRACKER_PROVIDER", &key)
        .or_else(|| env_for("REPROIT_ISSUE_PROVIDER", &key))
        .unwrap_or_else(|| "github".to_string())
        .to_ascii_lowercase();
    match provider.as_str() {
        "github" | "gh" => {
            let repo = env_for("REPROIT_GH_REPO", &key)?;
            let token = env_for("REPROIT_GH_TOKEN", &key)?;
            Some(ConfiguredTracker::Github(GithubTracker::new(repo, token)))
        }
        "jira" => Some(ConfiguredTracker::Jira(JiraTracker::from_env(&key)?)),
        "linear" => Some(ConfiguredTracker::Linear(LinearTracker::from_env(&key)?)),
        "shortcut" | "clubhouse" => Some(ConfiguredTracker::Shortcut(ShortcutTracker::from_env(
            &key,
        )?)),
        _ => None,
    }
}

/// Whether `app_id` has ANY tracker configured (the tenant's
/// `project_integrations` row or env). The cheap opt-in probe used to skip work
/// entirely on the hot ingest path before doing any bucket grouping; the row
/// lookup is one indexed PK read.
pub async fn is_configured_for(store: &crate::db::TenantStore, app_id: &str) -> bool {
    resolve_for(store, app_id).await.is_some()
}

/// Process-wide deployment mode, set once at startup from main's `self_hosted`.
/// Defaults to HOSTED (false) so a missed initialization fails safe: the bare-env
/// fallback below stays closed rather than leaking one tenant's tracker config
/// onto every app the process serves.
static SELF_HOSTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_self_hosted(v: bool) {
    SELF_HOSTED.store(v, std::sync::atomic::Ordering::Relaxed);
}

fn self_hosted() -> bool {
    SELF_HOSTED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Read `<base>__<APP>` first, then bare `<base>` as a single-app fallback.
/// The bare fallback is SELF-HOST ONLY (see `resolve` docs: on hosted it would
/// cross tenants). Empty values are treated as unset (same convention as
/// billing's `env`).
pub(crate) fn env_for(base: &str, app_key: &str) -> Option<String> {
    let scoped = format!("{base}__{app_key}");
    std::env::var(scoped)
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| {
            if self_hosted() {
                std::env::var(base).ok().filter(|v| !v.is_empty())
            } else {
                None
            }
        })
}

/// Normalize an app id into an env-var-safe suffix: upper-cased, every
/// non-alphanumeric byte mapped to `_`. Deterministic so config is predictable.
fn env_key(app_id: &str) -> String {
    app_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// PURE TRIGGER DECISION: does this freshly-posted replay-result mean the bucket
/// is verified fixed (and so its ticket should be commented + closed)?
///
/// The verified-fix signal is a result whose verdict says the bug no longer
/// reproduces: multiple `clean` runs (actual replays that did NOT crash) with
/// zero failures. We deliberately do NOT treat `data_dependent`,
/// `stale`, or `flaky` as fixed (those are "couldn't pin it down", not "gone"),
/// and a `clean` with `runs == 0` is a non-result, not a verification. Kept a
/// free function over primitives so it's unit-testable with no DB/HTTP.
pub fn is_verified_fix(status: &str, runs: i32, failures: i32) -> bool {
    status == "clean" && runs >= 3 && failures == 0
}

/// PII-safe title + body for the issue filed when a bucket forms. The body
/// carries ONLY derived, value-free bucket data: the stable bucket id, crash
/// signature, normalized (digit-collapsed) message, the executable replay action
/// list (already PII-filtered by `buckets::replay_actions`), build lineage, and
/// the local reproduce command. It never embeds `rec.context` or any raw user
/// value, so by construction no PII can leak into a ticket.
pub fn issue_body(
    app_id: &str,
    bucket_id: &str,
    oldest: &ErrorRec,
    newest: &ErrorRec,
) -> (String, String) {
    let title = format!("[reproit] {bucket_id}: {}", buckets::crash_summary(newest));
    let replay = buckets::replay_actions(newest);
    let replay_md = if replay.is_empty() {
        "_(no executable replay steps; reproduces on load)_".to_string()
    } else {
        replay
            .iter()
            .enumerate()
            .map(|(i, a)| format!("{}. `{a}`", i + 1))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let lineage = buckets::lineage(oldest, newest);
    let first = build_str(&lineage, "firstSeen");
    let last = build_str(&lineage, "lastSeen");
    let body = format!(
        "Auto-filed by **reproit** for production bug bucket `{bucket_id}` in app `{app_id}`.\n\
         \n\
         This is a PII-safe repro package: derived signatures and an executable replay only, \
         never user values.\n\
         \n\
         **Crash signature:** `{crash}`\n\
         **Normalized message:** {msg}\n\
         **First seen:** {first}\n\
         **Last seen:** {last}\n\
         \n\
         **Replay actions:**\n{replay_md}\n\
         \n\
         **Reproduce locally:**\n\
         ```sh\n\
         reproit {bucket_id} --app {app_id}\n\
         ```\n\
         reproit will download the replay package, synthesize a PII-safe fixture, replay the \
         actions deterministically, and post the verdict back. When it confirms the bug no \
         longer reproduces, reproit will comment the proof here and close this issue.",
        crash = newest.sig,
        msg = buckets::normalized_message(newest),
    );
    (title, body)
}

/// PII-safe comment posted onto the linked ticket when a bucket is verified
/// fixed. References only the bucket id and the build it was confirmed on (no
/// user data), matching the brief's "reproit confirmed bucket <id> no longer
/// reproduces as of <build>".
pub fn fix_comment(bucket_id: &str, build: Option<&str>) -> String {
    match build {
        Some(b) => format!(
            "reproit confirmed bucket `{bucket_id}` no longer reproduces as of `{b}`. \
             Closing automatically."
        ),
        None => format!(
            "reproit confirmed bucket `{bucket_id}` no longer reproduces. Closing automatically."
        ),
    }
}

/// Pull a human-readable `version[@commit]` out of a lineage side, or "unknown".
fn build_str(lineage: &serde_json::Value, side: &str) -> String {
    let b = &lineage[side];
    let v = b.get("version").and_then(|v| v.as_str());
    let c = b.get("commit").and_then(|v| v.as_str());
    match (v, c) {
        (Some(v), Some(c)) => format!("{v} ({c})"),
        (Some(v), None) => v.to_string(),
        (None, Some(c)) => c.to_string(),
        (None, None) => "unknown".to_string(),
    }
}

// ---- orchestration hooks: thin wiring from the handlers --------------------
//
// These do the DB-link read/write + HTTP via the trait. They NEVER fail the
// request that triggered them: a tracker outage must not block ingest or a
// replay-result POST, so they log and swallow. Both short-circuit instantly when
// the app is unconfigured (the opt-in zero-overhead path).

/// file-on-form hook: file an issue for a newly-formed bucket and persist the
/// link, unless the app is unconfigured or the bucket already has a ticket.
/// Returns the linked issue url on a fresh file (for the caller's response), or
/// None when nothing was filed (unconfigured / already linked / tracker error).
pub async fn file_issue_for_bucket(
    store: &crate::db::TenantStore,
    app_id: &str,
    bucket_id: &str,
    oldest: &ErrorRec,
    newest: &ErrorRec,
) -> Option<String> {
    let tracker = resolve_for(store, app_id).await?;
    // Idempotency: never file twice for the same bucket (the bucket<->ticket
    // mapping is 1:1). A pre-existing link wins.
    match store.ticket_for_bucket(app_id, bucket_id).await {
        Ok(Some(_)) => return None,
        Ok(None) => {}
        Err(e) => {
            tracing::warn!("ticket_for_bucket lookup failed for {bucket_id}: {e}");
            return None;
        }
    }
    let (title, body) = issue_body(app_id, bucket_id, oldest, newest);
    let (external_id, url) = match tracker.create_issue(&title, &body).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("create_issue failed for bucket {bucket_id}: {e}");
            return None;
        }
    };
    if let Err(e) = store
        .link_ticket(
            app_id,
            bucket_id,
            tracker.provider(),
            tracker.repo(),
            &external_id,
            &url,
        )
        .await
    {
        tracing::warn!("link_ticket persist failed for bucket {bucket_id}: {e}");
        return None;
    }
    tracing::info!(
        "filed {} issue {external_id} for bucket {bucket_id}",
        tracker.provider()
    );
    Some(url)
}

/// close-on-fix hook: comment the verified-fix proof onto the linked ticket and
/// close it. No-op if the app is unconfigured or the bucket has no linked ticket
/// (nothing to close). `build` is the build the fix was confirmed on, for proof.
pub async fn close_ticket_on_fix(
    store: &crate::db::TenantStore,
    app_id: &str,
    bucket_id: &str,
    build: Option<&str>,
) {
    let Some(tracker) = resolve_for(store, app_id).await else {
        return; // unconfigured: opt-in zero-overhead path.
    };
    let link = match store.ticket_for_bucket(app_id, bucket_id).await {
        Ok(Some(l)) => l,
        Ok(None) => return, // bucket never filed a ticket: nothing to close.
        Err(e) => {
            tracing::warn!("ticket_for_bucket lookup failed for {bucket_id}: {e}");
            return;
        }
    };
    let comment = fix_comment(bucket_id, build);
    if let Err(e) = tracker.comment(&link.external_id, &comment).await {
        tracing::warn!(
            "verified-fix comment failed on issue {}: {e}",
            link.external_id
        );
        return; // don't close without the proof comment landing.
    }
    if let Err(e) = tracker.close(&link.external_id).await {
        tracing::warn!("close failed on issue {}: {e}", link.external_id);
        return;
    }
    tracing::info!(
        "closed {} issue {} for verified-fixed bucket {bucket_id}",
        tracker.provider(),
        link.external_id
    );
}

// ---- self-serve config surface: GET/PUT /v1/apps/:app/integrations ----------

/// GET: the app's integration config, tokens redacted to a `tokenSet` boolean
/// (secrets are write-only; there is no way to read one back out).
pub async fn get_integration(
    axum::extract::State(app): axum::extract::State<crate::App>,
    axum::Extension(auth): axum::Extension<crate::AuthCtx>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(app_id): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let tenant = match crate::ingest::tenant_for(&app, auth, &headers, &app_id).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let row = match tenant.store.integration_for(&app_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("integration_for({app_id}) failed: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({ "error": "internal error" })),
            )
                .into_response();
        }
    };
    let body = match row {
        Some(r) => serde_json::json!({
            "provider": r.provider,
            "repo": r.repo,
            "baseUrl": r.base_url,
            "userEmail": r.user_email,
            "extra": r.extra,
            "tokenSet": r.token_enc.is_some(),
            "dispatchRepo": r.dispatch_repo,
            "dispatchTokenSet": r.dispatch_token_enc.is_some(),
        }),
        None => {
            serde_json::json!({ "provider": serde_json::Value::Null, "tokenSet": false, "dispatchTokenSet": false })
        }
    };
    axum::Json(body).into_response()
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutIntegration {
    pub provider: Option<String>,
    pub repo: Option<String>,
    pub base_url: Option<String>,
    pub user_email: Option<String>,
    #[serde(default)]
    pub extra: Option<serde_json::Value>,
    /// Absent = keep the stored token; empty string = clear; value = replace.
    pub token: Option<String>,
    pub dispatch_repo: Option<String>,
    /// Same keep/clear/replace semantics as `token`.
    pub dispatch_token: Option<String>,
}

/// PUT: upsert the app's integration config. Tokens are encrypted at rest with
/// the same key as tenant conn strings and never echoed back.
pub async fn put_integration(
    axum::extract::State(app): axum::extract::State<crate::App>,
    axum::Extension(auth): axum::Extension<crate::AuthCtx>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(app_id): axum::extract::Path<String>,
    axum::Json(put): axum::Json<PutIntegration>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let err500 = || {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({ "error": "internal error" })),
        )
            .into_response()
    };
    let tenant = match crate::ingest::tenant_for(&app, auth, &headers, &app_id).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let prev = tenant
        .store
        .integration_for(&app_id)
        .await
        .unwrap_or_default()
        .unwrap_or_default();
    // keep (absent) / clear ("") / replace (value) for each secret.
    let merge_secret = |incoming: Option<String>, stored: Option<String>| match incoming {
        None => Ok(stored),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => crate::db::secrets::encrypt(&s).map(Some),
    };
    let token_enc = match merge_secret(put.token, prev.token_enc) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("token encryption failed for {app_id}: {e}");
            return err500();
        }
    };
    let dispatch_token_enc = match merge_secret(put.dispatch_token, prev.dispatch_token_enc) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("dispatch token encryption failed for {app_id}: {e}");
            return err500();
        }
    };
    let row = crate::db::tenant::IntegrationRow {
        provider: put
            .provider
            .filter(|p| !p.is_empty())
            .unwrap_or(if prev.provider.is_empty() {
                "github".to_string()
            } else {
                prev.provider
            }),
        repo: put.repo.or(prev.repo).filter(|s| !s.is_empty()),
        base_url: put.base_url.or(prev.base_url).filter(|s| !s.is_empty()),
        user_email: put.user_email.or(prev.user_email).filter(|s| !s.is_empty()),
        extra: put
            .extra
            .filter(|v| v.is_object())
            .unwrap_or(if prev.extra.is_object() {
                prev.extra
            } else {
                serde_json::json!({})
            }),
        token_enc,
        dispatch_repo: put
            .dispatch_repo
            .or(prev.dispatch_repo)
            .filter(|s| !s.is_empty()),
        dispatch_token_enc,
    };
    if let Err(e) = tenant.store.set_integration(&app_id, &row).await {
        tracing::error!("set_integration({app_id}) failed: {e}");
        return err500();
    }
    app.control
        .audit(
            "org-key",
            "integration.set",
            None,
            serde_json::json!({ "app": app_id, "provider": row.provider }),
        )
        .await;
    axum::Json(serde_json::json!({ "ok": true, "provider": row.provider })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_builds_each_provider_and_rejects_incomplete_rows() {
        use crate::db::tenant::IntegrationRow;
        // No REPROIT_CONN_ENC_KEY in tests => decrypt is plaintext passthrough.
        let gh = IntegrationRow {
            provider: "github".into(),
            repo: Some("acme/web".into()),
            token_enc: Some("tok".into()),
            extra: serde_json::json!({}),
            ..Default::default()
        };
        assert!(matches!(
            from_config(&gh),
            Some(ConfiguredTracker::Github(_))
        ));
        // Missing repo => not configured, never a half-built tracker.
        assert!(from_config(&IntegrationRow {
            provider: "github".into(),
            token_enc: Some("tok".into()),
            extra: serde_json::json!({}),
            ..Default::default()
        })
        .is_none());
        // Missing token => not configured.
        assert!(from_config(&IntegrationRow {
            provider: "github".into(),
            repo: Some("acme/web".into()),
            extra: serde_json::json!({}),
            ..Default::default()
        })
        .is_none());
        let jira = IntegrationRow {
            provider: "jira".into(),
            base_url: Some("https://x.atlassian.net".into()),
            user_email: Some("bot@x.com".into()),
            token_enc: Some("tok".into()),
            extra: serde_json::json!({ "projectKey": "ENG" }),
            ..Default::default()
        };
        assert!(matches!(
            from_config(&jira),
            Some(ConfiguredTracker::Jira(_))
        ));
        let linear = IntegrationRow {
            provider: "linear".into(),
            token_enc: Some("tok".into()),
            extra: serde_json::json!({ "teamId": "team-uuid" }),
            ..Default::default()
        };
        assert!(matches!(
            from_config(&linear),
            Some(ConfiguredTracker::Linear(_))
        ));
        let shortcut = IntegrationRow {
            provider: "shortcut".into(),
            token_enc: Some("tok".into()),
            extra: serde_json::json!({ "projectId": "42" }),
            ..Default::default()
        };
        assert!(matches!(
            from_config(&shortcut),
            Some(ConfiguredTracker::Shortcut(_))
        ));
        assert!(from_config(&IntegrationRow {
            provider: "unknown".into(),
            token_enc: Some("tok".into()),
            extra: serde_json::json!({}),
            ..Default::default()
        })
        .is_none());
    }
    use crate::ingest::Step;
    use serde_json::{json, Map};

    fn rec(msg: &str, sig: &str, entry: &str, actions: &[&str]) -> ErrorRec {
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
        ErrorRec {
            sig: sig.to_string(),
            message: msg.to_string(),
            path,
            context: Map::new(),
        }
    }

    #[test]
    fn verified_fix_only_on_clean_run_with_no_failures() {
        // The fix signal: repeated clean replays, zero failures.
        assert!(is_verified_fix("clean", 5, 0));
        assert!(is_verified_fix("clean", 3, 0));
        assert!(!is_verified_fix("clean", 1, 0));
        assert!(!is_verified_fix("clean", 2, 0));
        // Still reproducing: not fixed.
        assert!(!is_verified_fix("reproduced", 5, 5));
        assert!(!is_verified_fix("clean", 5, 1));
        // A clean verdict with no runs is a non-result, not a verification.
        assert!(!is_verified_fix("clean", 0, 0));
        // "Couldn't pin it down" verdicts are NOT a verified fix.
        assert!(!is_verified_fix("data_dependent", 5, 0));
        assert!(!is_verified_fix("stale", 5, 0));
        assert!(!is_verified_fix("flaky", 5, 0));
    }

    #[test]
    fn issue_body_carries_bucket_id_and_reproduce_command_but_no_raw_values() {
        // A data-dependent crash whose typed step is a PII-safe CLASS token, plus
        // build lineage. The user's actual values would be capitals/spaces/@ etc.
        let mut oldest = rec(
            "Cannot read property of undefined at line 42",
            "crashX",
            "checkout",
            &["type:key:id:card=long", "tap:key:id:pay"],
        );
        oldest.context.insert(
            "build".into(),
            json!({ "version": "1.4.2", "commit": "abc123" }),
        );
        // PII guard: a raw value buried in context must never surface in the body.
        oldest
            .context
            .insert("email".into(), json!("jane@example.com"));
        let mut newest = rec(
            "Cannot read property of undefined at line 9001",
            "crashX",
            "checkout",
            &["type:key:id:card=long", "tap:key:id:pay"],
        );
        newest
            .context
            .insert("build".into(), json!({ "version": "1.4.5" }));

        let bid = "bkt_deadbeef0001";
        let (title, body) = issue_body("acme-web", bid, &oldest, &newest);

        // Contains the stable bucket id and the local reproduce command.
        assert!(title.contains(bid), "title has bucket id: {title}");
        assert!(body.contains(bid), "body has bucket id");
        assert!(
            body.contains(&format!(
                "reproit {bid} --app acme-web"
            )),
            "body has the reproduce command"
        );
        // Carries the PII-safe replay (class tokens) + lineage.
        assert!(body.contains("type:key:id:card=long"));
        assert!(body.contains("tap:key:id:pay"));
        assert!(body.contains("1.4.2"));
        assert!(body.contains("1.4.5"));
        // Normalized message (digits collapsed to N), not the raw line number.
        assert!(body.contains("line N"), "message is normalized");

        // PII GUARD: no raw user value (the email in context) can appear anywhere.
        assert!(!title.contains("jane@example.com"));
        assert!(!body.contains("jane@example.com"));
        assert!(!body.contains("@example.com"));
    }

    #[test]
    fn issue_body_with_raw_typed_step_drops_the_value() {
        // A typed step carrying RAW user text must be filtered out of the body's
        // replay list (replay_actions already drops it), so it can't leak.
        let r = rec(
            "boom",
            "c",
            "home",
            &["type:key:id:name=John Doe", "tap:key:id:save"],
        );
        let (_t, body) = issue_body("app", "bkt_x", &r, &r);
        assert!(
            !body.contains("John Doe"),
            "raw typed value dropped from body"
        );
        assert!(body.contains("tap:key:id:save"));
    }

    #[test]
    fn fix_comment_states_bucket_and_build_no_user_data() {
        let with = fix_comment("bkt_abc", Some("1.4.5"));
        assert!(with.contains("bkt_abc"));
        assert!(with.contains("1.4.5"));
        assert!(with.contains("no longer reproduces"));
        let without = fix_comment("bkt_abc", None);
        assert!(without.contains("bkt_abc"));
        assert!(without.contains("no longer reproduces"));
    }

    #[test]
    fn env_key_normalizes_app_id_to_var_suffix() {
        assert_eq!(env_key("acme-web"), "ACME_WEB");
        assert_eq!(env_key("App.123"), "APP_123");
        assert_eq!(env_key("plain"), "PLAIN");
    }
}
