//! Human-authored original capture review, upload, and read surfaces.

use crate::*;
use axum::body::Body;
use axum::extract::Path as AxumPath;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;

const MAX_CAPTURE_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateCaptureRequest {
    id: String,
    manifest: Value,
    app_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApproveCaptureRequest {
    app_id: String,
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_severity")]
    severity: String,
    #[serde(default = "default_visibility")]
    visibility: String,
}

fn default_severity() -> String {
    "normal".into()
}

fn default_visibility() -> String {
    "project".into()
}

pub(crate) async fn create(
    State(app): State<App>,
    Extension(auth): Extension<AuthCtx>,
    Extension(scope): Extension<KeyScope>,
    headers: HeaderMap,
    Json(request): Json<CreateCaptureRequest>,
) -> Response {
    if !valid_capture_id(&request.id) {
        return auth::err(StatusCode::BAD_REQUEST, "invalid capture id");
    }
    if request.manifest.get("id").and_then(Value::as_str) != Some(request.id.as_str())
        || request
            .manifest
            .get("immutableOriginal")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return auth::err(
            StatusCode::BAD_REQUEST,
            "manifest does not describe this capture",
        );
    }
    if !valid_manifest_files(&request.manifest) {
        return auth::err(
            StatusCode::BAD_REQUEST,
            "manifest file hashes are missing or invalid",
        );
    }
    let platform = request
        .manifest
        .get("platform")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let target = request
        .manifest
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let created = request
        .manifest
        .get("created")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let tenant = match app.tenant_of(auth, &headers).await {
        Ok(tenant) => tenant,
        Err((status, body)) => return (status, body).into_response(),
    };
    let scoped_app = match scope.project_id {
        Some(project_id) => match tenant.store.app_for_project_id(project_id).await {
            Ok(Some(app_id)) => Some(app_id),
            Ok(None) => return auth::err(StatusCode::FORBIDDEN, "project key is no longer valid"),
            Err(error) => {
                tracing::error!("capture key scope lookup failed: {error}");
                return auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error");
            }
        },
        None => None,
    };
    if scoped_app.as_deref().is_some_and(|app_id| {
        request
            .app_id
            .as_deref()
            .is_some_and(|requested| requested != app_id)
    }) {
        return auth::err(
            StatusCode::FORBIDDEN,
            "project key cannot upload to that project",
        );
    }
    let app_id = scoped_app.as_deref().or(request.app_id.as_deref());
    if let Some(app_id) = app_id {
        match tenant.store.owns_app(app_id).await {
            Ok(true) => {}
            Ok(false) => return auth::err(StatusCode::BAD_REQUEST, "unknown project"),
            Err(error) => {
                tracing::error!("capture project lookup failed: {error}");
                return auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error");
            }
        }
    }
    let review_token = format!("{}_{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let review_hash = token_hash(&review_token);
    let inserted = tenant
        .store
        .create_capture(
            &request.id,
            &review_hash,
            scope.user_id,
            app_id,
            platform,
            target,
            created,
            &request.manifest,
        )
        .await;
    match inserted {
        Ok(true) => {
            let review_url = public_url(&format!("/capture-upload/{review_token}"));
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": request.id,
                    "status": "pending_review",
                    "reviewUrl": review_url,
                    "statusUrl": format!("/v1/captures/{}", request.id),
                })),
            )
                .into_response()
        }
        Ok(false) => auth::err(
            StatusCode::CONFLICT,
            "capture already exists or project is invalid",
        ),
        Err(error) => {
            tracing::error!("capture create failed: {error}");
            auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error")
        }
    }
}

pub(crate) async fn status(
    State(app): State<App>,
    Extension(auth): Extension<AuthCtx>,
    Extension(scope): Extension<KeyScope>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let tenant = match app.tenant_of(auth, &headers).await {
        Ok(tenant) => tenant,
        Err((status, body)) => return (status, body).into_response(),
    };
    capture_status_for_key(&tenant, &id, scope).await
}

pub(crate) async fn put_file(
    State(app): State<App>,
    Extension(auth): Extension<AuthCtx>,
    Extension(scope): Extension<KeyScope>,
    headers: HeaderMap,
    AxumPath((id, filename)): AxumPath<(String, String)>,
    body: Body,
) -> Response {
    let tenant = match app.tenant_of(auth, &headers).await {
        Ok(tenant) => tenant,
        Err((status, body)) => return (status, body).into_response(),
    };
    let capture = match tenant.store.capture(&id).await {
        Ok(Some(capture)) if matches!(capture.status.as_str(), "approved" | "uploading") => capture,
        Ok(Some(_)) => return auth::err(StatusCode::CONFLICT, "capture is not ready for upload"),
        Ok(None) => return auth::err(StatusCode::NOT_FOUND, "capture not found"),
        Err(error) => {
            tracing::error!("capture read failed: {error}");
            return auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error");
        }
    };
    if !key_can_access(&tenant, &capture, scope).await {
        return auth::err(StatusCode::NOT_FOUND, "capture not found");
    }
    let expected = expected_files(&capture.manifest);
    if filename != "manifest.json" && !expected.contains_key(&filename) {
        return auth::err(
            StatusCode::BAD_REQUEST,
            "file is not declared by the manifest",
        );
    }
    if !safe_filename(&filename) {
        return auth::err(StatusCode::BAD_REQUEST, "invalid capture filename");
    }
    let claimed = headers
        .get("x-reproit-sha256")
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_sha256(value));
    if claimed.is_none() {
        return auth::err(StatusCode::BAD_REQUEST, "x-reproit-sha256 is required");
    }
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let temp_path = std::env::temp_dir().join(format!(
        "reproit-capture-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let written = stream_to_file(body, &temp_path).await;
    let (bytes, actual) = match written {
        Ok(result) => result,
        Err(response) => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return response;
        }
    };
    if claimed != Some(actual.as_str())
        || expected
            .get(&filename)
            .is_some_and(|expected| expected != &actual)
    {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return auth::err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "capture file hash mismatch",
        );
    }
    let storage_key = format!("captures/{id}/{filename}");
    match tenant
        .store
        .add_capture_file(
            &id,
            &filename,
            &storage_key,
            bytes as i64,
            &actual,
            &content_type,
            ingest::max_evidence_bytes_per_app(),
        )
        .await
    {
        Ok(Some(true)) => {}
        Ok(Some(false)) => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return auth::err(
                StatusCode::PAYLOAD_TOO_LARGE,
                "project evidence quota exceeded",
            );
        }
        Ok(None) => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return auth::err(StatusCode::CONFLICT, "capture is not ready for upload");
        }
        Err(error) => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            tracing::error!("capture file reservation failed: {error}");
            return auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error");
        }
    }
    if let Err(error) = tenant
        .blobs
        .put_path(&storage_key, &temp_path, &content_type)
        .await
    {
        let _ = tenant.store.remove_capture_file(&id, &filename).await;
        let _ = tokio::fs::remove_file(&temp_path).await;
        tracing::error!("capture blob upload failed: {error}");
        return auth::err(StatusCode::INTERNAL_SERVER_ERROR, "upload failed");
    }
    let _ = tokio::fs::remove_file(&temp_path).await;
    match tenant
        .store
        .mark_capture_file_uploaded(&id, &filename)
        .await
    {
        Ok(true) => {}
        Ok(false) => return auth::err(StatusCode::CONFLICT, "capture upload was interrupted"),
        Err(error) => {
            tracing::error!("capture file completion failed: {error}");
            return auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error");
        }
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "sha256": actual })),
    )
        .into_response()
}

pub(crate) async fn complete(
    State(app): State<App>,
    Extension(auth): Extension<AuthCtx>,
    Extension(scope): Extension<KeyScope>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let tenant = match app.tenant_of(auth, &headers).await {
        Ok(tenant) => tenant,
        Err((status, body)) => return (status, body).into_response(),
    };
    let capture = match tenant.store.capture(&id).await {
        Ok(Some(capture)) => capture,
        Ok(None) => return auth::err(StatusCode::NOT_FOUND, "capture not found"),
        Err(error) => {
            tracing::error!("capture read failed: {error}");
            return auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error");
        }
    };
    if !key_can_access(&tenant, &capture, scope).await {
        return auth::err(StatusCode::NOT_FOUND, "capture not found");
    }
    let files = match tenant.store.capture_files(&id).await {
        Ok(files) => files,
        Err(error) => {
            tracing::error!("capture file read failed: {error}");
            return auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error");
        }
    };
    let uploaded: BTreeMap<_, _> = files
        .iter()
        .map(|file| (file.filename.as_str(), file.sha256.as_str()))
        .collect();
    let expected = expected_files(&capture.manifest);
    let complete = uploaded.contains_key("manifest.json")
        && expected
            .iter()
            .all(|(name, hash)| uploaded.get(name.as_str()) == Some(&hash.as_str()));
    if !complete {
        return auth::err(
            StatusCode::CONFLICT,
            "not all manifest files have been uploaded",
        );
    }
    match tenant.store.complete_capture(&id).await {
        Ok(true) => capture_status(&tenant, &id, None).await,
        Ok(false) => auth::err(StatusCode::CONFLICT, "capture cannot be completed"),
        Err(error) => {
            tracing::error!("capture completion failed: {error}");
            auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error")
        }
    }
}

pub(crate) async fn review(
    State(app): State<App>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
) -> Response {
    let tenant = match account_tenant(&app, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let hash = token_hash(&token);
    let capture = match tenant.store.capture_for_review(&hash).await {
        Ok(Some(capture)) => capture,
        Ok(None) => return auth::err(StatusCode::NOT_FOUND, "review link is invalid or expired"),
        Err(error) => {
            tracing::error!("capture review read failed: {error}");
            return auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error");
        }
    };
    let projects = match tenant.store.list_projects().await {
        Ok(projects) => projects
            .into_iter()
            .map(|(_, name, app_id)| json!({ "name": name, "appId": app_id }))
            .collect::<Vec<_>>(),
        Err(error) => {
            tracing::error!("capture project list failed: {error}");
            return auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error");
        }
    };
    (
        StatusCode::OK,
        Json(json!({ "capture": capture, "projects": projects })),
    )
        .into_response()
}

pub(crate) async fn approve(
    State(app): State<App>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
    Json(request): Json<ApproveCaptureRequest>,
) -> Response {
    let tenant = match account_tenant(&app, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let title = request.title.trim();
    if title.is_empty() || title.len() > 200 || request.description.len() > 10_000 {
        return auth::err(StatusCode::BAD_REQUEST, "invalid capture details");
    }
    if !matches!(
        request.severity.as_str(),
        "low" | "normal" | "high" | "critical"
    ) || !matches!(request.visibility.as_str(), "project" | "organization")
    {
        return auth::err(StatusCode::BAD_REQUEST, "invalid severity or visibility");
    }
    match tenant
        .store
        .approve_capture(
            &token_hash(&token),
            &request.app_id,
            title,
            request.description.trim(),
            &request.severity,
            &request.visibility,
        )
        .await
    {
        Ok(true) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Ok(false) => auth::err(StatusCode::CONFLICT, "capture cannot be approved"),
        Err(error) => {
            tracing::error!("capture approval failed: {error}");
            auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error")
        }
    }
}

pub(crate) async fn account_capture(
    State(app): State<App>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let tenant = match account_tenant(&app, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    capture_status(&tenant, &id, None).await
}

async fn capture_status(tenant: &Tenant, id: &str, review_url: Option<String>) -> Response {
    let capture = match tenant.store.capture(id).await {
        Ok(Some(capture)) => capture,
        Ok(None) => return auth::err(StatusCode::NOT_FOUND, "capture not found"),
        Err(error) => {
            tracing::error!("capture status failed: {error}");
            return auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error");
        }
    };
    let files = match tenant.store.capture_files(id).await {
        Ok(files) => files,
        Err(error) => {
            tracing::error!("capture file status failed: {error}");
            return auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error");
        }
    };
    let capture_url =
        (capture.status == "complete").then(|| public_url(&format!("/captures/{}", capture.id)));
    (
        StatusCode::OK,
        Json(json!({
            "capture": capture,
            "uploadReady": matches!(capture.status.as_str(), "approved" | "uploading"),
            "reviewUrl": review_url,
            "captureUrl": capture_url,
            "files": files,
        })),
    )
        .into_response()
}

async fn capture_status_for_key(tenant: &Tenant, id: &str, scope: KeyScope) -> Response {
    let capture = match tenant.store.capture(id).await {
        Ok(Some(capture)) => capture,
        Ok(None) => return auth::err(StatusCode::NOT_FOUND, "capture not found"),
        Err(error) => {
            tracing::error!("capture status failed: {error}");
            return auth::err(StatusCode::INTERNAL_SERVER_ERROR, "server error");
        }
    };
    if !key_can_access(tenant, &capture, scope).await {
        return auth::err(StatusCode::NOT_FOUND, "capture not found");
    }
    capture_status(tenant, id, None).await
}

async fn key_can_access(
    tenant: &Tenant,
    capture: &crate::db::tenant::CaptureRow,
    scope: KeyScope,
) -> bool {
    let Some(project_id) = scope.project_id else {
        return true;
    };
    match tenant.store.app_for_project_id(project_id).await {
        Ok(Some(app_id)) => capture.app_id.as_deref() == Some(app_id.as_str()),
        Ok(None) => false,
        Err(error) => {
            tracing::error!("capture key access lookup failed: {error}");
            false
        }
    }
}

async fn stream_to_file(body: Body, path: &std::path::Path) -> Result<(u64, String), Response> {
    let mut file = tokio::fs::File::create(path).await.map_err(|error| {
        tracing::error!("capture temp file create failed: {error}");
        auth::err(StatusCode::INTERNAL_SERVER_ERROR, "upload failed")
    })?;
    let mut stream = body.into_data_stream();
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| auth::err(StatusCode::BAD_REQUEST, "invalid upload body"))?;
        bytes = bytes.saturating_add(chunk.len() as u64);
        if bytes > MAX_CAPTURE_FILE_BYTES {
            let _ = tokio::fs::remove_file(path).await;
            return Err(auth::err(
                StatusCode::PAYLOAD_TOO_LARGE,
                "capture file is too large",
            ));
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(|error| {
            tracing::error!("capture temp file write failed: {error}");
            auth::err(StatusCode::INTERNAL_SERVER_ERROR, "upload failed")
        })?;
    }
    file.flush().await.map_err(|error| {
        tracing::error!("capture temp file flush failed: {error}");
        auth::err(StatusCode::INTERNAL_SERVER_ERROR, "upload failed")
    })?;
    Ok((bytes, hex::encode(hasher.finalize())))
}

fn expected_files(manifest: &Value) -> BTreeMap<String, String> {
    manifest
        .get("fileSha256")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|values| values.iter())
        .filter_map(|(name, hash)| hash.as_str().map(|hash| (name.clone(), hash.to_string())))
        .filter(|(name, hash)| safe_filename(name) && valid_sha256(hash))
        .collect()
}

fn valid_manifest_files(manifest: &Value) -> bool {
    let Some(files) = manifest.get("fileSha256").and_then(Value::as_object) else {
        return false;
    };
    !files.is_empty()
        && files
            .iter()
            .all(|(name, hash)| safe_filename(name) && hash.as_str().is_some_and(valid_sha256))
}

fn valid_capture_id(value: &str) -> bool {
    value.strip_prefix("cap_").is_some_and(|suffix| {
        suffix.len() == 16 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn safe_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn public_url(path: &str) -> String {
    std::env::var("REPROIT_PUBLIC_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|base| format!("{}{}", base.trim_end_matches('/'), path))
        .unwrap_or_else(|| path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_capture_ids_and_filenames() {
        assert!(valid_capture_id("cap_0123456789abcdef"));
        assert!(!valid_capture_id("cap_0123"));
        assert!(safe_filename("original.mov"));
        assert!(!safe_filename("../secret"));
        assert!(!safe_filename("nested/file"));
    }

    #[test]
    fn expected_files_ignores_unsafe_or_invalid_entries() {
        let manifest = json!({
            "fileSha256": {
                "original.mov": "a".repeat(64),
                "../secret": "b".repeat(64),
                "bad.mov": "short"
            }
        });
        let files = expected_files(&manifest);
        assert_eq!(files.len(), 1);
        assert!(files.contains_key("original.mov"));
        assert!(!valid_manifest_files(&manifest));
    }
}
