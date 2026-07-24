use super::*;

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
