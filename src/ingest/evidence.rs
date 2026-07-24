//! Bounded evidence upload, retrieval, and blob delivery.

use super::*;

pub(super) fn evidence_kind(content_type: Option<&str>, filename: Option<&str>) -> String {
    let from_ct = content_type.and_then(|ct| match ct.split(';').next().unwrap_or("").trim() {
        "video/mp4" => Some("mp4"),
        "image/gif" => Some("gif"),
        "image/png" => Some("png"),
        "image/jpeg" => Some("jpg"),
        _ => None,
    });
    if let Some(k) = from_ct {
        return k.to_string();
    }
    let ext = filename
        .and_then(|f| f.rsplit('.').next())
        .map(|e| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("mp4") => "mp4",
        Some("gif") => "gif",
        Some("png") => "png",
        Some("jpg") | Some("jpeg") => "jpg",
        _ => "blob",
    }
    .to_string()
}

/// File extension to give a stored key for a given kind.
fn kind_ext(kind: &str) -> &str {
    match kind {
        "mp4" => "mp4",
        "gif" => "gif",
        "png" => "png",
        "jpg" => "jpg",
        _ => "bin",
    }
}

/// The per-app evidence byte cap: the edition policy decides first (the
/// hosted overlay derives it from the org's plan); when it abstains, the
/// operator's environment cap applies (REPROIT_MAX_EVIDENCE_BYTES_PER_APP,
/// zero/unset disables).
async fn evidence_cap(app: &App, tenant: &Tenant) -> Option<i64> {
    if let Some(cap) = app.policy.evidence_cap(tenant.org_id).await {
        return Some(cap);
    }
    max_evidence_bytes_per_app()
}

async fn store_evidence_for_error(
    tenant: &Tenant,
    app_id: &str,
    error_id: i64,
    mut multipart: Multipart,
    cap: Option<i64>,
) -> ApiResult {
    let mut stored: Vec<EvidenceRec> = Vec::new();
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": e.to_string() })),
                ))
            }
        };
        let content_type = field.content_type().map(|s| s.to_string());
        let filename = field.file_name().map(|s| s.to_string());
        let data = field.bytes().await.map_err(|e| {
            tracing::error!("multipart field read failed: {e}");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "could not read multipart field" })),
            )
        })?;
        // Per-file cap: reject an oversize part with 413 rather than store it.
        if data.len() > MAX_EVIDENCE_FIELD_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({ "error": "evidence file too large" })),
            ));
        }
        if data.is_empty() {
            continue;
        }
        let kind = evidence_kind(content_type.as_deref(), filename.as_deref());
        let bytes = data.len() as i64;
        // Server-generated, traversal-free key: app/error/uuid.ext.
        let key = format!(
            "{app_id}/{error_id}/{}.{}",
            uuid::Uuid::new_v4(),
            kind_ext(&kind)
        );
        // Reserve the row FIRST (quota check + insert are one transaction under a
        // per-app advisory lock, so concurrent uploads cannot overshoot), then
        // upload; a failed upload compensates by removing the reservation.
        let evidence_id = tenant
            .store
            .add_evidence_within_quota(app_id, error_id, &kind, &key, bytes, cap)
            .await
            .map_err(err500)?;
        let Some(evidence_id) = evidence_id else {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({ "error": "app evidence quota exceeded" })),
            ));
        };
        if let Err(e) = tenant.blobs.put(&key, &data).await {
            let _ = tenant.store.remove_evidence(evidence_id).await;
            return Err(err500(e));
        }
        let url = tenant.blobs.url_for(&key).await.map_err(err500)?;
        stored.push(EvidenceRec {
            kind,
            key,
            bytes,
            ts: chrono::Utc::now().to_rfc3339(),
            url,
        });
    }
    if stored.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "no file parts in multipart body" })),
        ));
    }
    Ok(Json(
        json!({ "ok": true, "stored": stored.len(), "evidence": stored }),
    ))
}

/// POST /v1/apps/:app/buckets/:bucket/evidence, attach proof artifacts to a
/// stable bucket. Evidence is stored on the newest occurrence in the bucket; the
/// bucket package lists evidence across all occurrences, so the artifact is
/// immediately visible from `GET /v1/apps/:app/buckets/:bucket`.
pub async fn post_bucket_evidence(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
    multipart: Multipart,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    let ids = bucket_error_ids(&tenant, &app_id, &bucket, "post_bucket_evidence").await?;
    let Some(error_id) = ids.last().copied() else {
        return Err(not_found_err());
    };
    store_evidence_for_error(
        &tenant,
        &app_id,
        error_id,
        multipart,
        evidence_cap(&app, &tenant).await,
    )
    .await
}

/// GET /v1/apps/:app/buckets/:bucket/evidence, list all proof artifacts attached
/// to every occurrence currently grouped into the stable bucket id.
pub async fn get_bucket_evidence(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path((app_id, bucket)): Path<(String, String)>,
) -> ApiResult {
    let tenant = tenant_for(&app, auth, &headers, &app_id).await?;
    let ids = bucket_error_ids(&tenant, &app_id, &bucket, "get_bucket_evidence").await?;
    let evidence = resolve_evidence(&tenant, &ids).await.map_err(err500)?;
    let visual_evidence = visual_evidence_refs(&evidence);
    Ok(Json(json!({
        "appId": app_id,
        "bucketId": bucket,
        "count": evidence.len(),
        "evidence": evidence,
        "visualEvidence": visual_evidence,
    })))
}

/// GET /v1/blob/*key, proxy bytes for the local-fs backend. R2 deployments hand
/// out presigned urls instead and never hit this. Auth-protected like the rest.
pub async fn get_blob(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    if !crate::tenancy::blob::is_safe_key(&key) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid key" })),
        ));
    }
    // The key is TENANT-RELATIVE (`app_id/error_id/uuid.ext`). We resolve the
    // caller's tenant and serve through `tenant.blobs`, which re-roots the key at
    // the tenant's blob scope: a key cannot be edited to point at another tenant's
    // bytes because the scoped handle has no authority outside this tenant's scope.
    // We still confirm the leading app segment is a project in this tenant (404
    // otherwise), keeping the no-existence-leak behavior.
    let key_app = key.split('/').next().unwrap_or("");
    let tenant = tenant_for(&app, auth, &headers, key_app).await?;
    let bytes = tenant.blobs.get(&key).await.map_err(|e| {
        // Log the detail, return a generic 404 (don't echo the storage error).
        tracing::error!("blob fetch failed for key {key}: {e}");
        not_found_err()
    })?;
    let ext = key.rsplit('.').next().unwrap_or("");
    let mime = match ext {
        "mp4" => "video/mp4",
        "gif" => "image/gif",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        _ => "application/octet-stream",
    };
    Ok(([(header::CONTENT_TYPE, mime)], Bytes::from(bytes)).into_response())
}
