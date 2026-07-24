//! The signed-in account read surface: the dashboard bootstrap (`me`) and the
//! usage meter. The edition policy contributes the plan/billing/identity card
//! and the metered usage members; the base shapes are edition-agnostic.

use super::*;
use serde_json::Value;

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
    let mut org_json = json!({
        "id": org.id,
        "name": org.name,
        "role": org.role,
        "selfHosted": app.self_hosted,
    });
    // The edition's account card (plan, limits, billing, identity providers)
    // extends the org object; Null (self-host) leaves the base shape as is.
    if let Value::Object(card) = app.policy.account_card(org.id).await {
        org_json
            .as_object_mut()
            .expect("org body is an object")
            .extend(card);
    }
    Json(json!({
        "email": user.email,
        "organizations": organizations.iter().map(|o| json!({
            "id": o.id, "name": o.name, "plan": o.plan, "role": o.role,
            "personal": o.personal, "active": o.id == org.id
        })).collect::<Vec<_>>(),
        "org": org_json,
        "projects": projects.iter().map(|(id, name, app_id)| json!({
            "id": id, "name": name, "appId": app_id
        })).collect::<Vec<_>>(),
        "apiKeys": keys,
        "members": members.iter().map(|m| json!({
            "userId": m.user_id, "email": m.email, "role": m.role, "seat": m.seat
        })).collect::<Vec<_>>(),
        "invitations": invitations.iter().map(|i| json!({
            "id": i.id, "email": i.email, "role": i.role, "seat": i.seat,
            "expiresAt": i.expires_at
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// GET /account/usage: retained evidence bytes for every edition, plus the
/// edition meter (plan limits and occurrences this month) when the policy
/// provides one. Customer-owned CI is not metered.
pub async fn usage(State(app): State<App>, headers: HeaderMap) -> Response {
    let (_user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let evidence_bytes = match app.tenancy.resolve(org.id).await {
        Ok(t) => t.store.evidence_bytes_total().await.unwrap_or(0),
        Err(_) => 0,
    };
    let mut body = json!({
        "used": {
            "evidenceBytes": evidence_bytes,
        },
    });
    if let Value::Object(meter) = app.policy.usage_meter(org.id).await {
        if let Some(plan) = meter.get("plan") {
            body["plan"] = plan.clone();
        }
        if let Some(occurrences) = meter.get("occurrences") {
            body["used"]["occurrences"] = occurrences.clone();
        }
    }
    Json(body).into_response()
}
