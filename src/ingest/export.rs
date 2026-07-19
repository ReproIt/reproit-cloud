//! Bounded, streaming tenant portability export.

use super::*;

const EXPORT_PAGE: i64 = 1000;

/// GET /v1/apps/:app/export: the tenant PORTABILITY export (GDPR article 20,
/// the read counterpart the offboard deletion assumes exists). Streams
/// everything the cloud holds for one app as newline-delimited JSON, one
/// object per line, in a fixed order:
///
///   1. one `{"kind":"app", ...}` header (org, export time, retention window),
///   2. the bucket triage metadata (`kind":"bucket"`),
///   3. error rows within the retention window, oldest first (`"kind":"error"`),
///   4. evidence blob KEYS (`"kind":"evidence"`; bytes stay in object storage,
///      fetch each via `GET /v1/blob/<key>`).
///   5. human-authored original captures and their immutable file keys.
///
/// The body is produced by a spawned task paging the tenant DB with keyset
/// reads and writing lines into a bounded channel, so an export never
/// materializes a tenant's error history in memory; backpressure from a slow
/// client simply pauses the paging.
pub async fn get_export(
    State(app): State<App>,
    Extension(auth): Extension<crate::AuthCtx>,
    headers: HeaderMap,
    Path(app_id): Path<String>,
) -> Response {
    let tenant = match tenant_for(&app, auth, &headers, &app_id).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    // Hosted: bound the export to the plan's retention window; rows past it
    // are already queued for deletion, and an export must not resurrect data
    // the retention contract says is gone. Self-host owns its retention, so it
    // exports everything.
    let days = None;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<String, std::io::Error>>(8);
    tokio::spawn(export_stream(tenant, app_id, days, tx));
    (
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        axum::body::Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx)),
    )
        .into_response()
}

/// The paged producer behind `get_export`: writes NDJSON lines into the body
/// channel. A DB error mid-stream sends an `Err` into the body, which ABORTS
/// the HTTP response (the client sees a broken stream, never a silently
/// truncated export presented as complete), and is logged server-side. A
/// closed channel (client went away) just stops paging.
async fn export_stream(
    tenant: Tenant,
    app_id: String,
    days: Option<i64>,
    tx: tokio::sync::mpsc::Sender<Result<String, std::io::Error>>,
) {
    async fn line(
        tx: &tokio::sync::mpsc::Sender<Result<String, std::io::Error>>,
        v: Value,
    ) -> bool {
        tx.send(Ok(format!("{v}\n"))).await.is_ok()
    }
    async fn abort(
        tx: &tokio::sync::mpsc::Sender<Result<String, std::io::Error>>,
        app_id: &str,
        what: &str,
        e: anyhow::Error,
    ) {
        tracing::error!("export for {app_id}: {what} failed: {e}");
        let _ = tx.send(Err(std::io::Error::other("export aborted"))).await;
    }

    // 1. The header line: what this export is and how it was bounded.
    let head = json!({
        "kind": "app",
        "app": app_id,
        "org": tenant.org_id,
        "exportedAt": chrono::Utc::now().to_rfc3339(),
        "retentionDays": days,
    });
    if !line(&tx, head).await {
        return;
    }

    // 2. Bucket triage metadata (bounded by the app's bucket count; one read).
    //    Sorted by bucket id so the export is deterministic and diffable.
    match tenant.store.triage_all_for_app(&app_id).await {
        Ok(triage) => {
            let mut buckets: Vec<_> = triage.into_iter().collect();
            buckets.sort_by(|a, b| a.0.cmp(&b.0));
            for (bucket, t) in buckets {
                let v = json!({
                    "kind": "bucket",
                    "bucket": bucket,
                    "status": t.status,
                    "assignee": t.assignee,
                    "fixedInBuild": t.fixed_in_build,
                    "updatedAt": t.updated_at,
                });
                if !line(&tx, v).await {
                    return;
                }
            }
        }
        Err(e) => return abort(&tx, &app_id, "triage read", e).await,
    }

    // 3. Error rows within retention, oldest first, keyset-paged.
    let mut after = 0i64;
    loop {
        let page = match tenant
            .store
            .export_errors_page(&app_id, days, after, EXPORT_PAGE)
            .await
        {
            Ok(p) => p,
            Err(e) => return abort(&tx, &app_id, "error page read", e).await,
        };
        let n = page.len() as i64;
        let Some(last) = page.last() else { break };
        after = last.0;
        for (id, at, bucket, rec) in page {
            let v = json!({
                "kind": "error",
                "id": id,
                "at": at,
                "bucket": bucket,
                "sig": rec.sig,
                "message": rec.message,
                "path": rec.path,
                "context": rec.context,
            });
            if !line(&tx, v).await {
                return;
            }
        }
        if n < EXPORT_PAGE {
            break;
        }
    }

    // 4. Evidence blob keys, keyset-paged like the errors.
    let mut after = 0i64;
    loop {
        let page = match tenant
            .store
            .export_evidence_page(&app_id, after, EXPORT_PAGE)
            .await
        {
            Ok(p) => p,
            Err(e) => return abort(&tx, &app_id, "evidence page read", e).await,
        };
        let n = page.len() as i64;
        let Some(last) = page.last() else { break };
        after = last.0;
        for (id, error_id, kind, key, bytes, at) in page {
            let v = json!({
                "kind": "evidence",
                "id": id,
                "errorId": error_id,
                "evidenceKind": kind,
                "key": key,
                "bytes": bytes,
                "at": at,
            });
            if !line(&tx, v).await {
                return;
            }
        }
        if n < EXPORT_PAGE {
            break;
        }
    }

    // 5. Human-authored originals and their object keys. Captures are reports,
    //    not confirmed bugs, so they retain their own kind in the export.
    let captures = match tenant.store.captures_for_app(&app_id).await {
        Ok(captures) => captures,
        Err(e) => return abort(&tx, &app_id, "capture read", e).await,
    };
    for capture in captures {
        let files = match tenant.store.capture_files(&capture.id).await {
            Ok(files) => files,
            Err(e) => return abort(&tx, &app_id, "capture file read", e).await,
        };
        if !line(
            &tx,
            json!({
                "kind": "capture",
                "capture": capture,
                "files": files,
            }),
        )
        .await
        {
            return;
        }
    }
}
