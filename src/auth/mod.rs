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
mod keys;
mod password;
mod session;

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

#[derive(Deserialize)]
pub struct NewProject {
    pub name: String,
}

#[derive(Deserialize)]
pub struct DeleteConfirm {
    pub confirm: String,
}

/// Create a project (org-owned) and mint its first API key. Owner/admin only.
pub async fn create_project(
    State(app): State<App>,
    headers: HeaderMap,
    Json(p): Json<NewProject>,
) -> Response {
    let (user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !can_manage(&org.role) {
        return err(
            StatusCode::FORBIDDEN,
            "only owners/admins can create projects",
        );
    }
    let name = p.name.trim();
    if name.is_empty() || name.len() > 80 {
        return err(StatusCode::BAD_REQUEST, "project name required");
    }
    let slug: String = name
        .to_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect();
    let app_id = format!(
        "{}-{}",
        slug.trim_matches('-'),
        &Uuid::new_v4().simple().to_string()[..6]
    );
    // The project is written into the org's TENANT database (no org_id: the
    // database is the org). Resolve the tenant first; a not-yet-provisioned org
    // can't create projects.
    let tenant = match app.tenancy.resolve(org.id).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(
                "create_project: tenant resolve failed for org {}: {e}",
                org.id
            );
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not create project",
            );
        }
    };
    let project_id = match tenant.store.create_project(user.id, name, &app_id).await {
        Ok(id) => id,
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not create project",
            )
        }
    };
    // Mint a fresh SECRET (sk_live_) for the CLI / server / dashboard reads, and a
    // PUBLISHABLE (pk_live_) write-only key for the browser SDK. Both store only a
    // hash + a non-secret prefix; the full values are returned ONCE below and can
    // never be retrieved again. Never logged. The publishable key is the one that
    // ships in client-side JS, so a page-source scrape can only append telemetry.
    let key = new_api_key();
    let prefix = api_key_prefix(&key);
    let pub_key = new_publishable_key();
    let pub_prefix = api_key_prefix(&pub_key);
    // The project row and the two key inserts span two databases (tenant +
    // control), so they cannot share a transaction. Compensate instead: if any
    // insert fails, undo the earlier writes so a retry never sees a project
    // without its keys or an orphaned secret. Cleanup is best-effort (logged);
    // nothing has been returned to the caller yet, so a leftover is inert.
    if app
        .control
        .create_api_key(&key, &prefix, org.id, user.id, Some(project_id))
        .await
        .is_err()
    {
        if let Err(e) = tenant.store.delete_project(project_id).await {
            tracing::error!("create_project cleanup: delete_project {project_id} failed: {e}");
        }
        return err(StatusCode::INTERNAL_SERVER_ERROR, "could not mint API key");
    }
    if app
        .control
        .create_api_key(&pub_key, &pub_prefix, org.id, user.id, Some(project_id))
        .await
        .is_err()
    {
        if let Err(e) = app.control.delete_api_key(&key).await {
            tracing::error!("create_project cleanup: delete_api_key failed: {e}");
        }
        if let Err(e) = tenant.store.delete_project(project_id).await {
            tracing::error!("create_project cleanup: delete_project {project_id} failed: {e}");
        }
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not mint publishable key",
        );
    }
    app.control
        .audit(
            &format!("user:{}", user.id),
            "apikey.create",
            Some(org.id),
            json!({ "prefix": prefix, "publishablePrefix": pub_prefix, "project": project_id }),
        )
        .await;
    (
        StatusCode::CREATED,
        Json(json!({
            "id": project_id,
            "name": name,
            "appId": app_id,
            // Shown exactly once: copy them now, they are never retrievable again.
            "apiKey": key,
            "apiKeyPrefix": prefix,
            // The browser-safe key for the SDK snippet + the wired demo.
            "publishableKey": pub_key,
            "publishableKeyPrefix": pub_prefix,
        })),
    )
        .into_response()
}

/// Permanently delete one project and all of its telemetry, evidence, keys,
/// integrations, and triage state. Owner/admin only with exact-name confirmation.
pub async fn delete_project(
    State(app): State<App>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<DeleteConfirm>,
) -> Response {
    let (user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !can_manage(&org.role) {
        return err(
            StatusCode::FORBIDDEN,
            "only owners/admins can delete projects",
        );
    }
    let tenant = match app.tenancy.resolve(org.id).await {
        Ok(t) => t,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "could not open project"),
    };
    let (project_id, project_name) = match tenant.store.project_for_app(&app_id).await {
        Ok(Some(project)) => project,
        Ok(None) => return err(StatusCode::NOT_FOUND, "project not found"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "could not open project"),
    };
    if req.confirm != project_name {
        return err(
            StatusCode::BAD_REQUEST,
            "type the exact project name to confirm deletion",
        );
    }
    let keys = match tenant.store.project_evidence_keys(&app_id).await {
        Ok(keys) => keys,
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not enumerate project evidence",
            )
        }
    };
    for key in &keys {
        if let Err(error) = tenant.blobs.delete(key).await {
            tracing::error!("delete_project: blob {key} failed for {app_id}: {error}");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not delete project evidence; nothing else was removed",
            );
        }
    }
    if app
        .control
        .delete_api_keys_for_project(project_id)
        .await
        .is_err()
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not revoke project keys",
        );
    }
    match tenant.store.delete_project_by_app(&app_id).await {
        Ok(true) => {}
        Ok(false) => return err(StatusCode::NOT_FOUND, "project not found"),
        Err(error) => {
            tracing::error!("delete_project: database cleanup failed for {app_id}: {error}");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not delete project data",
            );
        }
    }
    app.control
        .audit(
            &format!("user:{}", user.id),
            "project.delete",
            Some(org.id),
            json!({"appId":app_id,"project":project_id,"name":project_name,"evidenceObjects":keys.len()}),
        )
        .await;
    Json(json!({"ok":true,"appId":app_id})).into_response()
}

#[derive(Deserialize)]
pub struct ActiveOrgReq {
    #[serde(rename = "orgId")]
    pub org_id: i64,
}

pub async fn set_active_org(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<ActiveOrgReq>,
) -> Response {
    let user = match current_user(&app, &headers).await {
        Some(u) => u,
        None => return err(StatusCode::UNAUTHORIZED, "not signed in"),
    };
    let Some(token) = cookie_value(&headers, COOKIE_NAME) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    match app
        .control
        .set_session_org(token, user.id, req.org_id)
        .await
    {
        Ok(true) => Json(json!({"ok":true,"orgId":req.org_id})).into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, "organization not found"),
        Err(_) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not switch organization",
        ),
    }
}

#[derive(Deserialize)]
pub struct OrgNameReq {
    pub name: String,
}

pub async fn rename_org(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<OrgNameReq>,
) -> Response {
    let (user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !can_manage(&org.role) {
        return err(
            StatusCode::FORBIDDEN,
            "only owners/admins can rename the organization",
        );
    }
    let name = req.name.trim();
    if name.is_empty() || name.len() > 80 {
        return err(StatusCode::BAD_REQUEST, "organization name required");
    }
    if app.control.rename_org(org.id, name).await.ok() != Some(true) {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not rename organization",
        );
    }
    app.control
        .audit(
            &format!("user:{}", user.id),
            "org.rename",
            Some(org.id),
            json!({"name":name}),
        )
        .await;
    Json(json!({"ok":true,"name":name})).into_response()
}

/// Hosted organization deletion uses the same full offboarding pipeline as the
/// operator command. Personal workspaces and self-hosted installations have
/// separate account/deployment lifecycles and cannot be deleted here.
pub async fn delete_org(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<DeleteConfirm>,
) -> Response {
    let (user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if org.role != "owner" {
        return err(
            StatusCode::FORBIDDEN,
            "only the organization owner can delete it",
        );
    }
    if req.confirm != org.name {
        return err(
            StatusCode::BAD_REQUEST,
            "type the exact organization name to confirm deletion",
        );
    }
    if app.self_hosted {
        return err(
            StatusCode::BAD_REQUEST,
            "self-hosted workspace deletion is managed by the deployment owner",
        );
    }
    if app.control.org_is_personal(org.id).await.ok().flatten() != Some(false) {
        return err(
            StatusCode::BAD_REQUEST,
            "the personal workspace is deleted through account deletion",
        );
    }
    // Hosted builds add the billing guard and full provider teardown. This
    // source-available build deliberately refuses rather than partially delete.
    let _ = user;
    err(
        StatusCode::NOT_IMPLEMENTED,
        "organization deletion requires the hosted offboarding service",
    )
}

#[derive(Deserialize)]
pub struct InviteReq {
    pub email: String,
    pub role: Option<String>,
}
#[derive(Deserialize)]
pub struct InvitationIdReq {
    #[serde(rename = "invitationId")]
    pub invitation_id: i64,
}
#[derive(Deserialize)]
pub struct InviteTokenReq {
    pub token: String,
}

fn invite_role(role: Option<&str>) -> &'static str {
    if role == Some("admin") {
        "admin"
    } else {
        "member"
    }
}
async fn deliver_invitation(i: &crate::db::OrgInvitation, token: &str) -> anyhow::Result<()> {
    let link = format!("{}/invite?token={token}", crate::mail::public_base());
    let (subject, body) = crate::mail::invitation_email(&i.org_name, &link);
    crate::mail::send(&i.email, &subject, &body).await
}

pub async fn invite_member(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<InviteReq>,
) -> Response {
    let (user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !can_manage(&org.role) {
        return err(
            StatusCode::FORBIDDEN,
            "only owners/admins can invite members",
        );
    }
    let email = req.email.trim().to_lowercase();
    if !email.contains('@') || email.len() > 254 {
        return err(StatusCode::BAD_REQUEST, "enter a valid email");
    }
    if let Ok(Some(uid)) = app.control.find_user_id_by_email(&email).await {
        if app
            .control
            .org_role(org.id, uid)
            .await
            .ok()
            .flatten()
            .is_some()
        {
            return err(StatusCode::CONFLICT, "that person is already a member");
        }
    }
    let token = new_session_token();
    let role = invite_role(req.role.as_deref());
    let id = match app
        .control
        .upsert_org_invitation(
            org.id,
            &email,
            role,
            true,
            user.id,
            &token,
            INVITE_TTL_SECS,
            None,
        )
        .await
    {
        Ok(Some(id)) => id,
        _ => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not create invitation",
            )
        }
    };
    let invitation = match app
        .control
        .org_invitation_by_token(&token)
        .await
        .ok()
        .flatten()
    {
        Some(i) => i,
        None => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not create invitation",
            )
        }
    };
    if deliver_invitation(&invitation, &token).await.is_err() {
        return err(
            StatusCode::BAD_GATEWAY,
            "invitation saved, but the email could not be sent",
        );
    }
    app.control
        .audit(
            &format!("user:{}", user.id),
            "member.invite",
            Some(org.id),
            json!({"invitationId":id,"email":email,"role":role}),
        )
        .await;
    (StatusCode::CREATED,Json(json!({"id":id,"email":invitation.email,"role":invitation.role,"seat":invitation.seat,"expiresAt":invitation.expires_at}))).into_response()
}

pub async fn resend_invitation(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<InvitationIdReq>,
) -> Response {
    let (user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !can_manage(&org.role) {
        return err(
            StatusCode::FORBIDDEN,
            "only owners/admins can resend invitations",
        );
    }
    let token = new_session_token();
    let i = match app
        .control
        .refresh_org_invitation(org.id, req.invitation_id, &token, INVITE_TTL_SECS)
        .await
    {
        Ok(Some(i)) => i,
        Ok(None) => return err(StatusCode::NOT_FOUND, "invitation not found"),
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not refresh invitation",
            )
        }
    };
    if deliver_invitation(&i, &token).await.is_err() {
        return err(
            StatusCode::BAD_GATEWAY,
            "invitation refreshed, but the email could not be sent",
        );
    }
    app.control
        .audit(
            &format!("user:{}", user.id),
            "member.invite_resend",
            Some(org.id),
            json!({"invitationId":i.id}),
        )
        .await;
    Json(json!({"ok":true,"expiresAt":i.expires_at})).into_response()
}

pub async fn revoke_invitation(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<InvitationIdReq>,
) -> Response {
    let (user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !can_manage(&org.role) {
        return err(
            StatusCode::FORBIDDEN,
            "only owners/admins can revoke invitations",
        );
    }
    match app
        .control
        .revoke_org_invitation(org.id, req.invitation_id)
        .await
    {
        Ok(true) => {
            app.control
                .audit(
                    &format!("user:{}", user.id),
                    "member.invite_revoke",
                    Some(org.id),
                    json!({"invitationId":req.invitation_id}),
                )
                .await;
            Json(json!({"ok":true})).into_response()
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "invitation not found"),
        Err(_) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not revoke invitation",
        ),
    }
}

pub async fn invitation_preview(
    State(app): State<App>,
    axum::extract::Query(req): axum::extract::Query<InviteTokenReq>,
) -> Response {
    match app.control.org_invitation_by_token(&req.token).await{
        Ok(Some(i))=>Json(json!({"organization":i.org_name,"email":i.email,"role":i.role,"expiresAt":i.expires_at})).into_response(),
        _=>err(StatusCode::NOT_FOUND,"invitation is invalid or expired")}
}

pub async fn accept_invitation(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<InviteTokenReq>,
) -> Response {
    let user = match current_user(&app, &headers).await {
        Some(u) => u,
        None => {
            return err(
                StatusCode::UNAUTHORIZED,
                "sign in to accept this invitation",
            )
        }
    };
    let Some(session) = cookie_value(&headers, COOKIE_NAME) else {
        return err(
            StatusCode::UNAUTHORIZED,
            "sign in to accept this invitation",
        );
    };
    let org_id = match app
        .control
        .accept_org_invitation(&req.token, user.id, &user.email)
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return err(
                StatusCode::BAD_REQUEST,
                "invitation is invalid, expired, or belongs to another email",
            )
        }
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not accept invitation",
            )
        }
    };
    if app
        .control
        .set_session_org(session, user.id, org_id)
        .await
        .ok()
        != Some(true)
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not open organization",
        );
    }
    app.control
        .audit(
            &format!("user:{}", user.id),
            "member.invite_accept",
            Some(org_id),
            json!({}),
        )
        .await;
    Json(json!({"ok":true,"orgId":org_id})).into_response()
}

#[derive(Deserialize)]
pub struct AddMember {
    pub email: String,
    pub role: Option<String>,
}

/// Add an existing user to your org by email. Owner/admin only.
pub async fn add_member(
    State(app): State<App>,
    headers: HeaderMap,
    Json(m): Json<AddMember>,
) -> Response {
    let (_user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !can_manage(&org.role) {
        return err(StatusCode::FORBIDDEN, "only owners/admins can add members");
    }
    let email = m.email.trim().to_lowercase();
    let role = match m.role.as_deref() {
        Some("admin") => "admin",
        _ => "member",
    };
    let target = match app
        .control
        .find_user_id_by_email(&email)
        .await
        .ok()
        .flatten()
    {
        Some(id) => id,
        None => {
            return err(
                StatusCode::NOT_FOUND,
                "no Repro It account with that email (they must sign up first)",
            )
        }
    };
    if app.control.add_member(org.id, target, role).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "could not add member");
    }
    Json(json!({ "email": email, "role": role })).into_response()
}

#[derive(Deserialize)]
pub struct RemoveMember {
    #[serde(rename = "userId")]
    pub user_id: i64,
}

#[derive(Deserialize)]
pub struct SetMemberRole {
    #[serde(rename = "userId")]
    pub user_id: i64,
    pub role: String,
}

/// Change a member's org role. Owner/admin only; admins cannot mint owners, and
/// the last owner cannot be demoted.
pub async fn set_member_role(
    State(app): State<App>,
    headers: HeaderMap,
    Json(m): Json<SetMemberRole>,
) -> Response {
    let (_user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !can_manage(&org.role) {
        return err(StatusCode::FORBIDDEN, "only owners/admins can manage roles");
    }
    let role = match m.role.as_str() {
        "none" | "no_access" | "no-access" => "none",
        "owner" => {
            if org.role != "owner" {
                return err(StatusCode::FORBIDDEN, "only owners can grant owner");
            }
            "owner"
        }
        "admin" => "admin",
        "member" => "member",
        _ => {
            return err(
                StatusCode::BAD_REQUEST,
                "role must be none, owner, admin, or member",
            )
        }
    };
    let current = app.control.org_role(org.id, m.user_id).await.ok().flatten();
    let current_role = current.as_deref();
    if current_role.is_none() && role == "none" {
        return Json(json!({ "userId": m.user_id, "role": role })).into_response();
    }
    if current_role == Some("owner") && org.role != "owner" {
        return err(StatusCode::FORBIDDEN, "only owners can change owner roles");
    }
    if current_role == Some("owner") && role != "owner" {
        let owners = app.control.count_owners(org.id).await.unwrap_or(1);
        if owners <= 1 {
            return err(StatusCode::BAD_REQUEST, "cannot demote the last owner");
        }
    }
    if role == "none" {
        if app.control.remove_member(org.id, m.user_id).await.is_err() {
            return err(StatusCode::INTERNAL_SERVER_ERROR, "could not update role");
        }
    } else if current_role.is_none() {
        if app
            .control
            .add_member(org.id, m.user_id, role)
            .await
            .is_err()
        {
            return err(StatusCode::INTERNAL_SERVER_ERROR, "could not update role");
        }
    } else if app
        .control
        .set_member_role(org.id, m.user_id, role)
        .await
        .map(|matched| !matched)
        .unwrap_or(true)
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "could not update role");
    }
    Json(json!({ "userId": m.user_id, "role": role })).into_response()
}

/// Remove a member from your org (offboarding). Owner/admin only; cannot remove
/// an owner (prevents lockout). Data and CI keys stay with the org.
pub async fn remove_member(
    State(app): State<App>,
    headers: HeaderMap,
    Json(m): Json<RemoveMember>,
) -> Response {
    let (_user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !can_manage(&org.role) {
        return err(
            StatusCode::FORBIDDEN,
            "only owners/admins can remove members",
        );
    }
    if app
        .control
        .org_role(org.id, m.user_id)
        .await
        .ok()
        .flatten()
        .as_deref()
        == Some("owner")
    {
        return err(StatusCode::BAD_REQUEST, "cannot remove an owner");
    }
    if app.control.remove_member(org.id, m.user_id).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "could not remove member");
    }
    Json(json!({ "ok": true })).into_response()
}

#[derive(Deserialize)]
pub struct SetSeat {
    #[serde(rename = "userId")]
    pub user_id: i64,
    /// Grant (true) or revoke (false) the member's dashboard seat.
    pub seat: bool,
}

/// POST /account/seats: grant or revoke dashboard access. Self-hosted installs
/// are uncapped; this is an authorization flag, not a commercial entitlement.
/// Owners are always seated, so this is for granting NON-owner members.
pub async fn set_seat(
    State(app): State<App>,
    headers: HeaderMap,
    Json(s): Json<SetSeat>,
) -> Response {
    let (user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !can_manage(&org.role) {
        return err(StatusCode::FORBIDDEN, "only owners/admins can assign seats");
    }
    // The target must be a member of this org (a seat is a per-membership flag).
    if app
        .control
        .org_role(org.id, s.user_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return err(StatusCode::NOT_FOUND, "no such member in this org");
    }
    if app
        .control
        .set_seat(org.id, s.user_id, s.seat)
        .await
        .map(|matched| !matched)
        .unwrap_or(true)
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "could not update seat");
    }
    app.control
        .audit(
            &format!("user:{}", user.id),
            "seat.set",
            Some(org.id),
            json!({ "target": s.user_id, "seat": s.seat }),
        )
        .await;
    Json(json!({ "userId": s.user_id, "seat": s.seat })).into_response()
}

/// GET /auth/config: the self-hosted edition uses local password auth only.
pub async fn auth_config() -> Response {
    Json(json!({
        "google": false,
        "sso": false,
    }))
    .into_response()
}
