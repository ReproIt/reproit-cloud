//! Self-serve accounts: signup / login / logout + session cookies and per-user
//! API keys. Passwords are argon2id-hashed; sessions are opaque random tokens
//! stored server-side (a `sessions` row) and carried in an HttpOnly cookie.
//!
//! This is the auth layer the dashboard and the `/account/*` endpoints sit on.
//! API keys minted here authenticate the CLI/SDK (see `user_for_api_key`).
//!
//! The mechanics live in focused submodules; this file keeps the HTTP handlers
//! and re-exports the pieces used by the rest of the application:
//!   - `session`: session token, cookies, `ct_eq`, `cookie_value`, env helpers
//!   - `password`: argon2id password hashing
//!   - `keys`: `sk_live_*` API key minting + display prefix

use crate::db::User;
use crate::App;
use axum::{
    extract::{Path, State},
    http::{header::COOKIE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

#[cfg(test)]
mod invitation_tests;
mod invitations;
mod keys;
mod members;
mod organizations;
mod password;
mod projects;
mod session;

pub use invitations::*;
pub use members::*;
pub use organizations::*;
pub use projects::*;

// Re-exports preserving the crate API used by startup and tests.
pub use keys::new_api_key;
pub(crate) use keys::{api_key_prefix, is_publishable, new_publishable_key};
// The self-host bootstrap (src/bootstrap.rs) mints the admin user + first key, so
// it needs the same argon2id hasher and key-prefix derivation the handlers use,
// rather than duplicating the crypto. Re-exported crate-visible under distinct
// names so the local `use` of these in this module doesn't collide.
pub(crate) use keys::api_key_prefix as api_key_prefix_pub;
pub(crate) use password::hash_password as hash_password_pub;
pub(crate) use session::{
    cookie_value, ct_eq, new_session_token, session_cookie, SESSION_TTL_SECS,
};

use password::{hash_password, verify_password};
use session::{cleared_cookie, with_cookie, COOKIE_NAME};

#[derive(Deserialize)]
pub struct Creds {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub invite: Option<String>,
    #[serde(default, rename = "orgId")]
    pub org_id: Option<i64>,
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
        "deviceCode": device_code,
        "userCode": user_code,
        "verificationUri": verification_uri,
        "verificationUriComplete": format!("{verification_uri}?code={user_code}"),
        "expiresIn": CLI_AUTH_TTL_SECS,
        "interval": 2,
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
        "token": token,
        "orgId": org_id,
        "projects": projects.into_iter().map(|(id, name, app_id)| json!({
            "id": id, "name": name, "appId": app_id
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// Rotate the browser-safe SDK key from the signed-in dashboard. Full key
/// material is returned once; only its hash remains after the response.
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
        json!({ "email": email }),
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

pub async fn login(State(app): State<App>, Json(c): Json<Creds>) -> Response {
    let email = c.email.trim().to_lowercase();
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
    app.control
        .audit(&format!("user:{user_id}"), "auth.login", None, json!({}))
        .await;
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
        StatusCode::OK,
        json!({ "email": email }),
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

/// Current account: org, role, projects, keys, and members (dashboard bootstrap).
pub async fn me(State(app): State<App>, headers: HeaderMap) -> Response {
    let (user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    // Projects live in the TENANT db now; the API keys + members are control-plane.
    let projects = match app.tenancy.resolve(org.id).await {
        Ok(t) => t.store.list_projects().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let keys = app.control.list_api_keys(org.id).await.unwrap_or_default();
    let members = app.control.list_org_users(org.id).await.unwrap_or_default();
    let organizations = app
        .control
        .list_user_orgs(user.id)
        .await
        .unwrap_or_default();
    let invitations = if can_manage(&org.role) {
        app.control
            .list_org_invitations(org.id)
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    Json(json!({
        "email": user.email,
        "organizations": organizations.iter().map(|o| json!({
            "id":o.id,"name":o.name,"plan":o.plan,"role":o.role,
            "personal":o.personal,"active":o.id==org.id
        })).collect::<Vec<_>>(),
        "org": {
            "id": org.id,
            "name": org.name,
            "role": org.role,
            "selfHosted": true
        },
        "projects": projects.iter().map(|(id, name, app_id)| json!({
            "id": id, "name": name, "appId": app_id
        })).collect::<Vec<_>>(),
        "apiKeys": keys,
        "members": members.iter().map(|m| json!({
            "userId": m.user_id, "email": m.email, "role": m.role, "seat": m.seat
        })).collect::<Vec<_>>(),
        "invitations": invitations.iter().map(|i| json!({
            "id":i.id,"email":i.email,"role":i.role,"seat":i.seat,"expiresAt":i.expires_at
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// GET /account/usage: operational storage consumption for this installation.
pub async fn usage(State(app): State<App>, headers: HeaderMap) -> Response {
    let (_user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let evidence_bytes = match app.tenancy.resolve(org.id).await {
        Ok(t) => t.store.evidence_bytes_total().await.unwrap_or(0),
        Err(_) => 0,
    };
    Json(json!({
        "used": {
            "evidenceBytes": evidence_bytes
        },
    }))
    .into_response()
}

/// GET /auth/config: the self-hosted edition uses local password auth only.
pub async fn auth_config() -> Response {
    Json(json!({
        "google": false,
        "sso": false,
    }))
    .into_response()
}
