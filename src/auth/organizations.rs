//! Organization, invitation, membership, and seat handlers.

use super::*;

#[derive(Deserialize)]
pub struct ActiveOrgReq {
    #[serde(rename = "orgId")]
    pub org_id: i64,
}

/// Switch only this browser session into another organization the user belongs
/// to. The membership predicate is inside the UPDATE, so a forged org id can
/// never become active even briefly.
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
        Ok(true) => {
            app.control
                .audit(
                    &format!("user:{}", user.id),
                    "org.switch",
                    Some(req.org_id),
                    json!({}),
                )
                .await;
            Json(json!({ "ok": true, "orgId": req.org_id })).into_response()
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "organization not found"),
        Err(_) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not switch organization",
        ),
    }
}

#[derive(Deserialize)]
pub struct NewOrgReq {
    pub name: String,
}

pub async fn create_org(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<NewOrgReq>,
) -> Response {
    if app.self_hosted {
        return err(
            StatusCode::BAD_REQUEST,
            "self-hosted ReproIt uses one organization",
        );
    }
    let user = match current_user(&app, &headers).await {
        Some(u) => u,
        None => return err(StatusCode::UNAUTHORIZED, "not signed in"),
    };
    let name = req.name.trim();
    if name.is_empty() || name.len() > 80 {
        return err(StatusCode::BAD_REQUEST, "organization name required");
    }
    let org_id = match app.control.create_org(name, false).await {
        Ok(id) => id,
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not create organization",
            )
        }
    };
    if app
        .control
        .add_member(org_id, user.id, "owner")
        .await
        .is_err()
    {
        let _ = app.control.delete_org(org_id).await;
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not create organization",
        );
    }
    if let Err(e) = app.tenancy.provision(org_id).await {
        tracing::error!("create_org: tenant provisioning failed for org {org_id}: {e}");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not provision organization (retry shortly)",
        );
    }
    if let Some(token) = cookie_value(&headers, COOKIE_NAME) {
        let _ = app.control.set_session_org(token, user.id, org_id).await;
    }
    app.control
        .audit(
            &format!("user:{}", user.id),
            "org.create",
            Some(org_id),
            json!({ "name": name }),
        )
        .await;
    (
        StatusCode::CREATED,
        Json(json!({ "id": org_id, "name": name })),
    )
        .into_response()
}

pub async fn rename_org(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<NewOrgReq>,
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
            json!({ "name": name }),
        )
        .await;
    Json(json!({ "ok": true, "name": name })).into_response()
}

/// Permanently offboard a non-personal hosted organization. Only its owner may
/// do this, after billing has reached the free state and the exact name matches.
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
    if org.plan != "free" {
        return err(
            StatusCode::CONFLICT,
            "cancel the active subscription and wait for the plan to become free",
        );
    }
    let session = cookie_value(&headers, COOKIE_NAME).map(str::to_string);
    if let Err(error) = app.tenancy.offboard_data(org.id).await {
        tracing::error!(
            "delete_org: data-plane cleanup failed for {}: {error}",
            org.id
        );
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not delete organization data",
        );
    }
    match app.control.delete_org(org.id).await {
        Ok(true) => {}
        Ok(false) => return err(StatusCode::NOT_FOUND, "organization not found"),
        Err(error) => {
            tracing::error!("delete_org: control cleanup failed for {}: {error}", org.id);
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not finish organization deletion; retry",
            );
        }
    }
    let next_org = app
        .control
        .list_user_orgs(user.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .next()
        .map(|item| item.id);
    if let (Some(token), Some(next_id)) = (session.as_deref(), next_org) {
        let _ = app.control.set_session_org(token, user.id, next_id).await;
    }
    app.control
        .audit(
            &format!("user:{}", user.id),
            "org.delete",
            Some(org.id),
            json!({"name":org.name,"nextOrgId":next_org}),
        )
        .await;
    Json(json!({"ok":true,"orgId":next_org})).into_response()
}

#[derive(Deserialize)]
pub struct InviteReq {
    pub email: String,
    pub role: Option<String>,
}

fn invite_role(role: Option<&str>) -> &'static str {
    match role {
        Some("admin") => "admin",
        _ => "member",
    }
}

async fn deliver_invitation(
    invite: &crate::db::OrgInvitation,
    raw_token: &str,
) -> anyhow::Result<()> {
    let link = format!("{}/invite?token={raw_token}", crate::mail::public_base());
    let (subject, body) = crate::mail::invitation_email(&invite.org_name, &link);
    crate::mail::send(&invite.email, &subject, &body).await
}

/// Create or replace an invitation. The invitation, not an unverified email
/// address, is the authority to join. A seat is reserved now so acceptance can
/// never surprise the recipient with a plan-cap failure.
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
    if let Ok(Some(target)) = app.control.find_user_id_by_email(&email).await {
        if app
            .control
            .org_role(org.id, target)
            .await
            .ok()
            .flatten()
            .is_some()
        {
            return err(StatusCode::CONFLICT, "that person is already a member");
        }
    }
    let raw_token = new_session_token();
    let role = invite_role(req.role.as_deref());
    let limit = app.policy.seat_limit(org.id).await;
    let invitation_id = match app
        .control
        .upsert_org_invitation(
            org.id,
            &email,
            role,
            true,
            user.id,
            &raw_token,
            INVITE_TTL_SECS,
            limit,
        )
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return err(
                StatusCode::PAYMENT_REQUIRED,
                "seat limit reached for this plan; upgrade to invite another member",
            )
        }
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not create invitation",
            )
        }
    };
    let invitation = match app
        .control
        .org_invitation_by_token(&raw_token)
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
    if let Err(e) = deliver_invitation(&invitation, &raw_token).await {
        tracing::error!("invitation email {} failed: {e}", invitation.id);
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
            json!({ "invitationId": invitation_id, "email": email, "role": role }),
        )
        .await;
    (
        StatusCode::CREATED,
        Json(json!({
            "id": invitation.id, "email": invitation.email, "role": invitation.role,
            "seat": invitation.seat, "expiresAt": invitation.expires_at
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct InvitationIdReq {
    #[serde(rename = "invitationId")]
    pub invitation_id: i64,
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
    let raw_token = new_session_token();
    let invitation = match app
        .control
        .refresh_org_invitation(org.id, req.invitation_id, &raw_token, INVITE_TTL_SECS)
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
    if let Err(e) = deliver_invitation(&invitation, &raw_token).await {
        tracing::error!("invitation resend {} failed: {e}", invitation.id);
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
            json!({ "invitationId": invitation.id }),
        )
        .await;
    Json(json!({ "ok": true, "expiresAt": invitation.expires_at })).into_response()
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
                    json!({ "invitationId": req.invitation_id }),
                )
                .await;
            Json(json!({ "ok": true })).into_response()
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "invitation not found"),
        Err(_) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not revoke invitation",
        ),
    }
}

#[derive(Deserialize)]
pub struct InviteTokenReq {
    pub token: String,
}

pub async fn invitation_preview(
    State(app): State<App>,
    Query(req): Query<InviteTokenReq>,
) -> Response {
    match app.control.org_invitation_by_token(&req.token).await {
        Ok(Some(i)) => Json(json!({
            "organization": i.org_name, "email": i.email, "role": i.role,
            "expiresAt": i.expires_at
        }))
        .into_response(),
        _ => err(StatusCode::NOT_FOUND, "invitation is invalid or expired"),
    }
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
    let Some(session_token) = cookie_value(&headers, COOKIE_NAME) else {
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
        .set_session_org(session_token, user.id, org_id)
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
    Json(json!({ "ok": true, "orgId": org_id })).into_response()
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

/// POST /account/seats: grant or revoke a member's dashboard SEAT. Owner/admin
/// only. A SEAT is what gates the per-seat cloud surface (the triage dashboard);
/// the CLI/SDK stays free and is never gated by this. Granting enforces the
/// edition's seat limit (the edition policy), so a hosted org can't seat
/// more members than its plan allows, and the buyer upgrades to seat more.
/// Self-hosted installs are uncapped. Revoking always succeeds (freeing a seat).
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
    if let (true, Some(limit)) = (s.seat, app.policy.seat_limit(org.id).await) {
        // Enforce the edition's seat limit BEFORE granting. count_seats already
        // counts the consumed seats (seated members + always-seated owners);
        // if the target is currently unseated, granting adds one, so we compare
        // the current count against the limit. A re-grant of an already-seated
        // member is idempotent and never over-counts (the write is a no-op delta).
        let used = app.control.count_seats(org.id).await.unwrap_or(0);
        let already = app
            .control
            .has_seat(org.id, s.user_id)
            .await
            .unwrap_or(false);
        if !already && used >= limit {
            return err(
                StatusCode::PAYMENT_REQUIRED,
                "hosted seat limit reached for this plan; upgrade to add more seats",
            );
        }
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

/// GET /auth/config: which login providers are enabled, so the pages can show
/// the right buttons. Google appears only once both OAuth env vars are present.
pub async fn auth_config(State(app): State<App>) -> Response {
    // The edition's provider descriptor; password-only when the policy has no
    // federated providers to offer.
    let methods = app.policy.auth_methods().await.unwrap_or_else(|| {
        json!({
            "google": false,
            "sso": false,
        })
    });
    Json(methods).into_response()
}
