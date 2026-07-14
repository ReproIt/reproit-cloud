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
    extract::State,
    http::{header::COOKIE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

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
}

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
    let user = current_user(app, headers)
        .await
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "not signed in"))?;
    let org = app
        .control
        .primary_org(user.id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "no org for account"))?;
    Ok((user, org))
}

pub(crate) fn can_manage(role: &str) -> bool {
    role == "owner" || role == "admin"
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
    if let Some(r) = provision_personal_org(&app, user_id).await {
        return r;
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
    Json(json!({
        "email": user.email,
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
