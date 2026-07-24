use super::*;

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
