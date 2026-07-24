//! Self-serve accounts: signup / login / logout + session cookies and per-user
//! API keys. Passwords are argon2id-hashed; sessions are opaque random tokens
//! stored server-side (a `sessions` row) and carried in an HttpOnly cookie.
//!
//! This is the auth layer the dashboard and the `/account/*` endpoints sit on.
//! API keys minted here authenticate the CLI/SDK (see `user_for_api_key`).
//!
//! The mechanics live in focused submodules; this file keeps the HTTP handlers
//! and re-exports the pieces external callers (main.rs) and the SSO overlay
//! (sso.rs, via `crate::auth::X`) depend on:
//!   - `session`: session token, cookies, `ct_eq`, `cookie_value`, env helpers
//!   - `password`: argon2id hashing + the federated "unusable password" sentinel
//!   - `keys`: `sk_live_*` API key minting + display prefix
//!   - `google`: the Google OAuth start/callback flow (hosted feature)

use crate::db::User;
use crate::App;
use axum::{
    extract::{Path, Query, State},
    http::{header::CACHE_CONTROL, header::COOKIE, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

/// Email-token lifetimes: 48h to click a signup verification, 30 minutes for a
/// password reset (short + single-use, standard practice).
const VERIFY_TTL_SECS: i64 = 48 * 60 * 60;
const RESET_TTL_SECS: i64 = 30 * 60;

/// Enterprise SSO + SCIM (WorkOS overlay). Lives under `auth` since it is an
/// identity concern; reuses this module's session + cookie helpers.
#[cfg(feature = "hosted")]
pub mod sso;

#[cfg(feature = "hosted")]
mod google;
mod keys;
mod password;
mod session;

#[cfg(all(test, feature = "hosted"))]
mod integration_tests;
#[cfg(test)]
mod invitation_tests;
#[cfg(all(test, feature = "hosted"))]
mod onboarding_tests;

// Re-exports preserving the public API. The SSO overlay (sso.rs) reaches these
// as `crate::auth::X`, so they stay crate-visible here; main.rs sees the Google
// handlers as `auth::google_*` and `new_api_key` as `auth::new_api_key`.
#[cfg(feature = "hosted")]
pub use google::{google_callback, google_start};
pub use keys::new_api_key;
pub(crate) use keys::{api_key_prefix, is_publishable, new_publishable_key};
// The self-host bootstrap (src/bootstrap.rs) mints the admin user + first key, so
// it needs the same argon2id hasher and key-prefix derivation the handlers use,
// rather than duplicating the crypto. Re-exported crate-visible under distinct
// names so the local `use` of these in this module doesn't collide.
pub(crate) use keys::api_key_prefix as api_key_prefix_pub;
pub(crate) use password::hash_password as hash_password_pub;
#[cfg(feature = "hosted")]
pub(crate) use password::oauth_sentinel_hash;
#[cfg(feature = "hosted")]
pub(crate) use session::{cleared_oauth_state_cookie, oauth_state_cookie, OAUTH_STATE_COOKIE};
pub(crate) use session::{
    cookie_value, ct_eq, new_session_token, session_cookie, SESSION_TTL_SECS,
};

use password::{hash_password, verify_password};
use session::{cleared_cookie, with_cookie, COOKIE_NAME};

#[derive(Deserialize)]
pub struct Creds {
    pub email: String,
    pub password: String,
    /// Optional checkout intent from /signup?plan=... . Carried through the
    /// email-verification hop so the plan the visitor clicked on the site
    /// survives to the dashboard's checkout.
    #[serde(default)]
    pub plan: Option<String>,
    /// Optional organization invitation carried through signup verification.
    /// Tokens are opaque hex and are accepted only after the verified mailbox
    /// matches the invitation email.
    #[serde(default)]
    pub invite: Option<String>,
    /// Browser-local last workspace preference. The server still verifies that
    /// this user is a member before selecting it for the new session.
    #[serde(default, rename = "orgId")]
    pub org_id: Option<i64>,
}

/// The checkout intent a signup may carry: the edition policy names the
/// purchasable plans (hosted); self-host always resolves None.
fn valid_plan(app: &App, plan: Option<&str>) -> Option<String> {
    app.policy.valid_checkout_plan(plan)
}

const INVITE_TTL_SECS: i64 = 7 * 24 * 60 * 60;

// ---- helpers ---------------------------------------------------------------

pub(crate) fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

/// Read the session cookie and resolve the current user, if any.
pub async fn current_user(app: &App, headers: &HeaderMap) -> Option<User> {
    let token = cookie_value(headers, COOKIE_NAME)?;
    app.control.user_for_session(token).await.ok().flatten()
}

/// Lightweight session probe for anonymous-only pages.
pub async fn session_status(State(app): State<App>, headers: HeaderMap) -> Response {
    let status = if current_user(&app, &headers).await.is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::UNAUTHORIZED
    };
    ([(CACHE_CONTROL, "no-store")], status).into_response()
}

// ---- handlers --------------------------------------------------------------

/// Resolve the signed-in user AND their primary org, or an error response.
/// Shared with the SSO overlay (sso.rs) for the org-level SSO settings handler.
pub(crate) async fn user_and_org(
    app: &App,
    headers: &HeaderMap,
) -> Result<(crate::db::User, crate::db::Org), Response> {
    let token = cookie_value(headers, COOKIE_NAME)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "not signed in"))?;
    let (user, org) = app
        .control
        .user_and_org_for_session(token)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "no org for account"))?;
    Ok((user, org))
}

pub(crate) fn can_manage(role: &str) -> bool {
    role == "owner" || role == "admin"
}

const CLI_AUTH_TTL_SECS: i64 = 10 * 60;

#[derive(Deserialize)]
pub struct CliDeviceReq {
    #[serde(default)]
    pub client: Option<String>,
}

pub async fn cli_device(State(app): State<App>, Json(req): Json<CliDeviceReq>) -> Response {
    let device_code = new_session_token();
    let raw = Uuid::new_v4().simple().to_string().to_ascii_uppercase();
    let user_code = format!("{}-{}", &raw[..4], &raw[4..8]);
    if let Err(e) = app
        .control
        .create_cli_authorization(&device_code, &user_code, CLI_AUTH_TTL_SECS)
        .await
    {
        tracing::error!("could not create CLI authorization: {e}");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not start CLI login",
        );
    }
    app.control
        .audit(
            "anonymous",
            "cli.login.start",
            None,
            json!({ "client": req.client.unwrap_or_else(|| "reproit".into()) }),
        )
        .await;
    let verification_uri = format!("{}/cli", crate::mail::public_base());
    Json(json!({
        "deviceCode": device_code, "userCode": user_code,
        "verificationUri": verification_uri,
        "verificationUriComplete": format!("{verification_uri}?code={user_code}"),
        "expiresIn": CLI_AUTH_TTL_SECS, "interval": 2,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct CliCodeReq {
    pub code: String,
}

pub async fn cli_approve(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<CliCodeReq>,
) -> Response {
    let (user, org) = match user_and_org(&app, &headers).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    match app
        .control
        .approve_cli_authorization(req.code.trim(), user.id, org.id)
        .await
    {
        Ok(true) => {
            app.control
                .audit(
                    &format!("user:{}", user.id),
                    "cli.login.approve",
                    Some(org.id),
                    json!({}),
                )
                .await;
            Json(json!({ "approved": true, "organization": org.name })).into_response()
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "code is invalid or expired"),
        Err(e) => {
            tracing::error!("could not approve CLI authorization: {e}");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not approve CLI login",
            )
        }
    }
}

pub async fn cli_token(State(app): State<App>, Json(req): Json<CliCodeReq>) -> Response {
    let device_code = req.code.trim();
    match app.control.cli_authorization_state(device_code).await {
        Ok(Some((false, false))) => {
            return (StatusCode::ACCEPTED, Json(json!({ "status": "pending" }))).into_response()
        }
        Ok(Some((_, true))) | Ok(None) => {
            return err(StatusCode::GONE, "authorization is expired or already used")
        }
        Ok(Some((true, false))) => {}
        Err(e) => {
            tracing::error!("could not read CLI authorization: {e}");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not finish CLI login",
            );
        }
    }
    let token = new_api_key();
    let prefix = api_key_prefix(&token);
    let org_id = match app
        .control
        .consume_cli_authorization(device_code, &token, &prefix)
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => return err(StatusCode::GONE, "authorization is expired or already used"),
        Err(e) => {
            tracing::error!("could not consume CLI authorization: {e}");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not finish CLI login",
            );
        }
    };
    let projects = match app.tenancy.resolve(org_id).await {
        Ok(tenant) => tenant.store.list_projects().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    Json(json!({
        "token": token, "orgId": org_id,
        "projects": projects.into_iter().map(|(id, name, app_id)| json!({ "id": id, "name": name, "appId": app_id })).collect::<Vec<_>>(),
    })).into_response()
}

pub async fn rotate_publishable_key(
    State(app): State<App>,
    headers: HeaderMap,
    axum::extract::Path(app_id): axum::extract::Path<String>,
) -> Response {
    let (user, org) = match user_and_org(&app, &headers).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    if !can_manage(&org.role) {
        return err(StatusCode::FORBIDDEN, "owner or admin required");
    }
    let tenant = match app.tenancy.resolve(org.id).await {
        Ok(tenant) => tenant,
        Err(_) => return err(StatusCode::NOT_FOUND, "project not found"),
    };
    let project_id = match tenant.store.project_id_for_app(&app_id).await {
        Ok(Some(id)) => id,
        _ => return err(StatusCode::NOT_FOUND, "project not found"),
    };
    if let Err(e) = app
        .control
        .revoke_publishable_keys_for_project(project_id)
        .await
    {
        tracing::error!("could not revoke publishable keys: {e}");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not rotate publishable key",
        );
    }
    let key = new_publishable_key();
    let prefix = api_key_prefix(&key);
    if let Err(e) = app
        .control
        .create_api_key(&key, &prefix, org.id, user.id, Some(project_id))
        .await
    {
        tracing::error!("could not create publishable key: {e}");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not rotate publishable key",
        );
    }
    app.control
        .audit(
            &format!("user:{}", user.id),
            "apikey.publishable.rotate",
            Some(org.id),
            json!({ "project": project_id, "prefix": prefix }),
        )
        .await;
    Json(json!({ "appId": app_id, "publishableKey": key, "publishableKeyPrefix": prefix }))
        .into_response()
}

pub async fn signup(State(app): State<App>, Json(c): Json<Creds>) -> Response {
    let email = c.email.trim().to_lowercase();
    if !email.contains('@') || email.len() > 254 {
        return err(StatusCode::BAD_REQUEST, "enter a valid email");
    }
    if c.password.len() < 8 || c.password.trim().is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "password must be at least 8 characters",
        );
    }
    let hash = match hash_password(&c.password) {
        Ok(h) => h,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "could not hash password"),
    };
    let user_id = match app.control.create_user(&email, &hash).await {
        Ok(id) => id,
        Err(_) => return err(StatusCode::CONFLICT, "that email is already registered"),
    };
    app.control
        .audit(&format!("user:{user_id}"), "auth.signup", None, json!({}))
        .await;
    // Hosted signups verify their email BEFORE anything is provisioned: an
    // unverified signup is just a users row, so a bot burst cannot make us run
    // CREATE DATABASE per request. Self-host keeps the immediate flow (single
    // tenant, no mail dependency).
    if !app.self_hosted {
        let plan = valid_plan(&app, c.plan.as_deref());
        send_verification(&app, user_id, &email, plan.as_deref(), c.invite.as_deref()).await;
        return (
            StatusCode::CREATED,
            Json(json!({ "email": email, "verifyEmail": true })),
        )
            .into_response();
    }
    let joins_existing_org = match c.invite.as_deref() {
        Some(invite) => app
            .control
            .org_invitation_by_token(invite)
            .await
            .ok()
            .flatten()
            .is_some_and(|i| i.email == email),
        None => false,
    };
    if !joins_existing_org {
        if let Some(r) = provision_personal_org(&app, user_id).await {
            return r;
        }
    }
    let _ = app.control.mark_email_verified(user_id).await;
    let token = new_session_token();
    if app
        .control
        .create_session(&token, user_id, SESSION_TTL_SECS)
        .await
        .is_err()
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "could not start session");
    }
    if let Some(org_id) = c.org_id {
        let _ = app.control.set_session_org(&token, user_id, org_id).await;
    }
    with_cookie(
        session_cookie(&token),
        StatusCode::CREATED,
        json!({ "email": email, "plan": "free" }),
    )
}

/// Every new user gets a personal org and is its owner. Under database-per-org,
/// creating the org ACQUIRES a database: provision the tenant (intent -> DB ->
/// schema -> blob -> active). The flow is idempotent + crash-recoverable, so a
/// failure here leaves a `provisioning` row the startup reconciler finishes.
/// Returns Some(error response) on failure, None on success.
async fn provision_personal_org(app: &App, user_id: i64) -> Option<Response> {
    match app.control.create_org("Personal", true).await {
        Ok(org_id) => {
            let _ = app.control.add_member(org_id, user_id, "owner").await;
            if let Err(e) = app.tenancy.provision(org_id).await {
                tracing::error!("signup: tenant provisioning failed for org {org_id}: {e}");
                return Some(err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not provision your workspace (retry shortly)",
                ));
            }
            None
        }
        Err(_) => Some(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not create org",
        )),
    }
}

/// Mint a 48h single-use verification token and mail the link. Send failures
/// are logged, never surfaced: the next login attempt re-sends.
async fn send_verification(
    app: &App,
    user_id: i64,
    email: &str,
    plan: Option<&str>,
    invite: Option<&str>,
) {
    let token = new_session_token();
    if let Err(e) = app
        .control
        .create_email_token(&token, user_id, "verify", VERIFY_TTL_SECS)
        .await
    {
        tracing::error!("could not store verification token for user {user_id}: {e}");
        return;
    }
    let plan_q = plan.map(|p| format!("&plan={p}")).unwrap_or_default();
    let invite_q = invite
        .filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|t| format!("&invite={t}"))
        .unwrap_or_default();
    let link = format!(
        "{}/auth/verify?token={token}{plan_q}{invite_q}",
        crate::mail::public_base()
    );
    let (subject, body) = crate::mail::verification_email(&link);
    if let Err(e) = crate::mail::send(email, &subject, &body).await {
        tracing::error!("verification email to user {user_id} failed: {e}");
    }
}

/// GET /auth/verify?token=...: the emailed link. Consumes the token, marks the
/// email verified, provisions the personal org (exactly once: skipped if the
/// user already has one), signs the user in, and lands on /app. A bad/expired
/// token bounces to /login where a fresh login re-sends the link.
pub async fn verify_email(State(app): State<App>, Query(q): Query<TokenQuery>) -> Response {
    let uid = match app.control.consume_email_token(&q.token, "verify").await {
        Ok(Some(uid)) => uid,
        _ => return Redirect::to("/login?verify=failed").into_response(),
    };
    let _ = app.control.mark_email_verified(uid).await;
    let verified_email = app
        .control
        .user_by_id(uid)
        .await
        .ok()
        .flatten()
        .map(|u| u.email);
    let valid_invite = match (q.invite.as_deref(), verified_email.as_deref()) {
        (Some(token), Some(email)) => app
            .control
            .org_invitation_by_token(token)
            .await
            .ok()
            .flatten()
            .is_some_and(|i| i.email == email),
        _ => false,
    };
    if !valid_invite && app.control.primary_org(uid).await.ok().flatten().is_none() {
        if let Some(r) = provision_personal_org(&app, uid).await {
            return r;
        }
    }
    app.control
        .audit(&format!("user:{uid}"), "auth.verify", None, json!({}))
        .await;
    let token = new_session_token();
    if app
        .control
        .create_session(&token, uid, SESSION_TTL_SECS)
        .await
        .is_err()
    {
        return Redirect::to("/login").into_response();
    }
    // Land on the dashboard; a carried plan deep-links the account section,
    // where the same checkout hop login.js uses takes over.
    let dest = match (
        valid_invite,
        q.invite.as_deref(),
        valid_plan(&app, q.plan.as_deref()),
    ) {
        (true, Some(invite), _) => format!("/invite?token={invite}"),
        (_, _, Some(p)) => format!("/app?plan={p}#account"),
        _ => "/app".to_string(),
    };
    let mut resp = Redirect::to(&dest).into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&session_cookie(&token)) {
        resp.headers_mut().insert(axum::http::header::SET_COOKIE, v);
    }
    resp
}

#[derive(Deserialize)]
pub struct TokenQuery {
    pub token: String,
    /// Checkout intent carried through the verification link.
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub invite: Option<String>,
}

#[derive(Deserialize)]
pub struct ForgotReq {
    pub email: String,
}

/// POST /auth/forgot: always 200 with the same body (no account-existence
/// oracle). When the account exists, mails a 30-minute single-use reset link.
pub async fn forgot_password(State(app): State<App>, Json(f): Json<ForgotReq>) -> Response {
    let email = f.email.trim().to_lowercase();
    if let Ok(Some(uid)) = app.control.find_user_id_by_email(&email).await {
        let token = new_session_token();
        if app
            .control
            .create_email_token(&token, uid, "reset", RESET_TTL_SECS)
            .await
            .is_ok()
        {
            // Fire the send off-request: awaiting the mail API only on the
            // account-exists branch would make response latency an existence
            // oracle for the uniform {ok:true} body.
            let link = format!("{}/reset?token={token}", crate::mail::public_base());
            let to = email.clone();
            tokio::spawn(async move {
                let (subject, body) = crate::mail::reset_email(&link);
                if let Err(e) = crate::mail::send(&to, &subject, &body).await {
                    tracing::error!("reset email to user {uid} failed: {e}");
                }
            });
            app.control
                .audit(&format!("user:{uid}"), "auth.forgot", None, json!({}))
                .await;
        }
    }
    Json(json!({ "ok": true })).into_response()
}

#[derive(Deserialize)]
pub struct ResetReq {
    pub token: String,
    pub password: String,
}

/// POST /auth/reset: consume the reset token, swap the password hash, and
/// revoke every live session (whoever held the old credentials is logged out).
pub async fn reset_password(State(app): State<App>, Json(r): Json<ResetReq>) -> Response {
    if r.password.len() < 8 || r.password.trim().is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "password must be at least 8 characters",
        );
    }
    let uid = match app.control.consume_email_token(&r.token, "reset").await {
        Ok(Some(uid)) => uid,
        _ => return err(StatusCode::BAD_REQUEST, "invalid or expired reset link"),
    };
    let hash = match hash_password(&r.password) {
        Ok(h) => h,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "could not hash password"),
    };
    if app.control.set_password(uid, &hash).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "could not set password");
    }
    let _ = app.control.revoke_sessions_for_user(uid).await;
    // A proven mailbox interaction also proves the email: mark verified so a
    // pre-verification user who resets isn't stuck.
    let _ = app.control.mark_email_verified(uid).await;
    app.control
        .audit(
            &format!("user:{uid}"),
            "auth.password_reset",
            None,
            json!({}),
        )
        .await;
    Json(json!({ "ok": true })).into_response()
}

/// SSO enforcement (Enterprise overlay): if this email's domain maps to an org
/// that enforces SSO, password login is refused outright. One guarded lookup;
/// it only fires when an org has set sso_enforced, so normal password login is
/// never affected. Dormant when WorkOS isn't configured (no org will enforce).
#[cfg(feature = "hosted")]
async fn sso_enforced_refusal(app: &App, email: &str) -> Option<Response> {
    let domain = email.rsplit('@').next().filter(|d| !d.is_empty())?;
    if app
        .control
        .domain_enforces_sso(domain)
        .await
        .unwrap_or(false)
    {
        return Some(err(
            StatusCode::FORBIDDEN,
            "this organization requires SSO; sign in at /auth/sso/start",
        ));
    }
    None
}

/// Self-host has no SSO overlay; password login is never refused for it.
#[cfg(not(feature = "hosted"))]
async fn sso_enforced_refusal(_app: &App, _email: &str) -> Option<Response> {
    None
}

pub async fn login(State(app): State<App>, Json(c): Json<Creds>) -> Response {
    let email = c.email.trim().to_lowercase();
    if let Some(refusal) = sso_enforced_refusal(&app, &email).await {
        return refusal;
    }
    let row = app.control.user_auth_by_email(&email).await.ok().flatten();
    let (user_id, hash) = match row {
        Some(t) => t,
        None => return err(StatusCode::UNAUTHORIZED, "wrong email or password"),
    };
    if !verify_password(&c.password, &hash) {
        // Audited with the user id only (the account exists; the password was
        // wrong): a burst of these is the brute-force signal.
        app.control
            .audit(
                &format!("user:{user_id}"),
                "auth.login_failed",
                None,
                json!({}),
            )
            .await;
        return err(StatusCode::UNAUTHORIZED, "wrong email or password");
    }
    // Hosted accounts must have verified their email before getting a session
    // (verification is what gates workspace provisioning). Re-send on every
    // attempt: the auth limiter bounds the rate, and a lost link would
    // otherwise dead-end the account.
    if !app.self_hosted && !app.control.email_verified(user_id).await.unwrap_or(false) {
        let plan = valid_plan(&app, c.plan.as_deref());
        send_verification(&app, user_id, &email, plan.as_deref(), c.invite.as_deref()).await;
        return err(
            StatusCode::FORBIDDEN,
            "verify your email first; we just sent you a fresh link",
        );
    }
    app.control
        .audit(&format!("user:{user_id}"), "auth.login", None, json!({}))
        .await;
    // Self-heal: a verified user with no org means the verify link burned its
    // token but provisioning failed mid-way (or the process died). Provisioning
    // is idempotent-at-worst-once here because this only fires when NO org
    // exists for the user.
    if !app.self_hosted
        && app
            .control
            .primary_org(user_id)
            .await
            .ok()
            .flatten()
            .is_none()
    {
        if let Some(r) = provision_personal_org(&app, user_id).await {
            return r;
        }
    }
    let token = new_session_token();
    if app
        .control
        .create_session(&token, user_id, SESSION_TTL_SECS)
        .await
        .is_err()
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "could not start session");
    }
    if let Some(org_id) = c.org_id {
        let _ = app.control.set_session_org(&token, user_id, org_id).await;
    }
    let plan = app
        .control
        .primary_org(user_id)
        .await
        .ok()
        .flatten()
        .map(|o| o.plan)
        .unwrap_or_else(|| "free".into());
    with_cookie(
        session_cookie(&token),
        StatusCode::OK,
        json!({ "email": email, "plan": plan }),
    )
}

pub async fn logout(State(app): State<App>, headers: HeaderMap) -> Response {
    if let Some(raw) = headers.get(COOKIE).and_then(|v| v.to_str().ok()) {
        if let Some(token) = raw
            .split(';')
            .find_map(|c| c.trim().strip_prefix(&format!("{COOKIE_NAME}=")))
        {
            let _ = app.control.delete_session(token).await;
        }
    }
    with_cookie(cleared_cookie(), StatusCode::OK, json!({ "ok": true }))
}

mod account;
mod organizations;
mod projects;

pub use account::*;
pub use organizations::*;
pub use projects::*;
