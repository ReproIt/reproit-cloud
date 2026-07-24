use super::*;

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
