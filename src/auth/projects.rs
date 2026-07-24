use super::*;

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
