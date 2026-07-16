//! The hosted reproduction trigger: fire a GitHub `repository_dispatch` into
//! the CUSTOMER's repo so reproduction runs in THEIR CI, never on our compute.
//! This is the code-blind constraint made concrete (multi-tenancy design,
//! "reproduction and video recording happen in the customer's own CI"): the
//! cloud holds only the app's `dispatch_repo` binding + a repo-scoped token,
//! sends `{app, bucket, runId}`, and the workflow closes the loop by running
//! ReproIt's private CI callback, which POSTs the verdict back to
//! `/v1/apps/:app/buckets/:bucket/replay-results` with the run id.

use serde_json::Value;

/// The dispatch event type customer workflows subscribe to
/// (`on: repository_dispatch: types: [reproit-repro]`).
pub const EVENT_TYPE: &str = "reproit-repro";

/// POST /repos/{owner}/{repo}/dispatches. GitHub answers 204 with no body.
/// The token needs Contents read/write on that one repo (fine-grained PAT).
pub async fn repository_dispatch(
    repo: &str,
    token: &str,
    client_payload: Value,
) -> anyhow::Result<()> {
    dispatch_at("https://api.github.com", repo, token, client_payload).await
}

async fn dispatch_at(
    base: &str,
    repo: &str,
    token: &str,
    client_payload: Value,
) -> anyhow::Result<()> {
    let resp = reqwest::Client::new()
        .post(format!("{base}/repos/{repo}/dispatches"))
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "reproit-cloud")
        .json(&serde_json::json!({
            "event_type": EVENT_TYPE,
            "client_payload": client_payload,
        }))
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("repository_dispatch to {repo} failed ({status}): {body}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Router};
    use std::sync::{Arc, Mutex};

    /// Round-trip against a local mock GitHub: asserts the path, the bearer
    /// token, the event type, and the client payload shape the CI receives.
    #[tokio::test]
    async fn dispatch_posts_event_type_and_payload() {
        let seen: Arc<Mutex<Option<(String, String, Value)>>> = Arc::new(Mutex::new(None));
        let seen2 = seen.clone();
        let app = Router::new().route(
            "/repos/:owner/:repo/dispatches",
            post(
                move |axum::extract::Path((owner, repo)): axum::extract::Path<(String, String)>,
                      headers: axum::http::HeaderMap,
                      axum::Json(body): axum::Json<Value>| {
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    *seen2.lock().unwrap() = Some((format!("{owner}/{repo}"), auth, body));
                    async { axum::http::StatusCode::NO_CONTENT }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        dispatch_at(
            &format!("http://{addr}"),
            "acme/web",
            "github_pat_x",
            serde_json::json!({ "app": "a", "bucket": "bkt_1", "runId": 7 }),
        )
        .await
        .unwrap();

        let (repo, auth, body) = seen.lock().unwrap().clone().unwrap();
        assert_eq!(repo, "acme/web");
        assert_eq!(auth, "Bearer github_pat_x");
        assert_eq!(body["event_type"], EVENT_TYPE);
        assert_eq!(body["client_payload"]["bucket"], "bkt_1");
        assert_eq!(body["client_payload"]["runId"], 7);
    }
}
