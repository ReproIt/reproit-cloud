//! The signed-in account read surface: the dashboard bootstrap (`me`) and the
//! usage meter, with hosted and self-host response shapes selected per build.

use super::*;

/// Current account: org, role, projects, keys, and members (dashboard bootstrap).
#[cfg(feature = "hosted")]
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
    let plan_limits = crate::billing::plan_limits(&org.plan).to_json();
    let has_billing_customer = app
        .control
        .org_stripe_customer(org.id)
        .await
        .ok()
        .flatten()
        .is_some();
    // The SSO overlay's org-level binding, for the dashboard's SSO card:
    // `available` is the plan gate (self-host is never plan-gated), `provider`
    // whether the WorkOS overlay is live on this deployment at all.
    let (workos_org_id, sso_domain, sso_enforced) = app
        .control
        .org_sso(org.id)
        .await
        .ok()
        .flatten()
        .unwrap_or((None, None, false));
    Json(json!({
        "email": user.email,
        "organizations": organizations.iter().map(|o| json!({
            "id": o.id, "name": o.name, "plan": o.plan, "role": o.role,
            "personal": o.personal, "active": o.id == org.id
        })).collect::<Vec<_>>(),
        "org": {
            "id": org.id,
            "name": org.name,
            "plan": org.plan,
            "planLimits": plan_limits,
            "role": org.role,
            "selfHosted": app.self_hosted,
            "hasBillingCustomer": has_billing_customer,
            "sso": {
                "available": app.self_hosted || crate::billing::plan_limits(&org.plan).sso,
                "provider": self::sso::workos_config().is_some(),
                "workosOrgId": workos_org_id,
                "domain": sso_domain,
                "enforced": sso_enforced
            }
        },
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

/// Current account: org, role, projects, keys, and members (dashboard bootstrap).
#[cfg(not(feature = "hosted"))]
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

/// GET /account/usage: the org's plan limits + live consumption (occurrences
/// this month and retained evidence bytes). Customer-owned CI is not metered.
#[cfg(feature = "hosted")]
pub async fn usage(State(app): State<App>, headers: HeaderMap) -> Response {
    let (_user, org) = match user_and_org(&app, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let limits = crate::billing::plan_limits(&org.plan);
    let occurrences = app
        .control
        .occurrences_this_month(org.id)
        .await
        .unwrap_or(0);
    let evidence_bytes = match app.tenancy.resolve(org.id).await {
        Ok(t) => t.store.evidence_bytes_total().await.unwrap_or(0),
        Err(_) => 0,
    };
    Json(json!({
        "plan": limits.to_json(),
        "used": {
            "occurrences": occurrences,
            "evidenceBytes": evidence_bytes,
        },
    }))
    .into_response()
}
/// GET /account/usage: operational storage consumption for this installation.
#[cfg(not(feature = "hosted"))]
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
