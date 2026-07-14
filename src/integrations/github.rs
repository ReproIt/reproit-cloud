//! GitHub Issues implementation of the `Tracker` trait. Three REST calls cover
//! the whole bug<->ticket lifecycle:
//!   - create_issue: POST   /repos/{owner}/{repo}/issues
//!   - comment:      POST   /repos/{owner}/{repo}/issues/{n}/comments
//!   - close:        PATCH  /repos/{owner}/{repo}/issues/{n}   {state: closed}
//!
//! Auth is a token (PAT / GitHub App installation token) with `issues:write`,
//! sent as `Authorization: Bearer <token>` per GitHub's REST v3 contract. The
//! base URL is injectable
//! (`with_base_url`) so tests point it at a local mock server and make ZERO real
//! external calls; production leaves it at the api.github.com default.
//!
//! Nothing here ever sees a user value: the body is built by the PII-safe
//! `integrations::issue_body`, this layer just ships the bytes.

use super::Tracker;
use serde_json::{json, Value};

/// GitHub's REST API base. Overridable in tests via `with_base_url`.
const GITHUB_API: &str = "https://api.github.com";

/// A GitHub Issues client bound to one `owner/repo` and a write token.
pub struct GithubTracker {
    repo: String,
    token: String,
    base_url: String,
    client: reqwest::Client,
}

impl GithubTracker {
    /// Bind to `owner/repo` with a write token, against the public GitHub API.
    pub fn new(repo: String, token: String) -> Self {
        Self {
            repo,
            token,
            base_url: GITHUB_API.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Point the client at a different base url (a local mock in tests). Returns
    /// self for chaining. Only ever used to redirect to a test server; the
    /// default is the real api.github.com.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_base_url(mut self, base: String) -> Self {
        self.base_url = base;
        self
    }

    /// `{base}/repos/{owner}/{repo}/issues{suffix}`. `suffix` is "" for the
    /// collection or "/{n}" / "/{n}/comments" for a single issue.
    fn issues_url(&self, suffix: &str) -> String {
        format!("{}/repos/{}/issues{suffix}", self.base_url, self.repo)
    }

    /// Shared header set: bearer token, the REST v3 accept header, and a
    /// User-Agent (GitHub rejects requests without one). `api_version` pins the
    /// REST contract this client was written against.
    fn req(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        rb.bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "reproit-cloud")
    }
}

impl Tracker for GithubTracker {
    fn provider(&self) -> &'static str {
        "github"
    }

    fn repo(&self) -> &str {
        &self.repo
    }

    async fn create_issue(&self, title: &str, body: &str) -> anyhow::Result<(String, String)> {
        let resp = self
            .req(self.client.post(self.issues_url("")))
            .json(&json!({ "title": title, "body": body }))
            .send()
            .await?;
        let status = resp.status();
        let v: Value = resp.json().await?;
        if !status.is_success() {
            anyhow::bail!("github create_issue {status}: {}", message_of(&v));
        }
        let number = v
            .get("number")
            .and_then(|n| n.as_i64())
            .ok_or_else(|| anyhow::anyhow!("github create_issue: no issue number in response"))?;
        // `html_url` is the human-clickable issue link we persist + return.
        let url = v
            .get("html_url")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();
        Ok((number.to_string(), url))
    }

    async fn comment(&self, issue_number: &str, body: &str) -> anyhow::Result<()> {
        let resp = self
            .req(
                self.client
                    .post(self.issues_url(&format!("/{issue_number}/comments"))),
            )
            .json(&json!({ "body": body }))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let v: Value = resp.json().await.unwrap_or_else(|_| json!({}));
            anyhow::bail!("github comment {status}: {}", message_of(&v));
        }
        Ok(())
    }

    async fn close(&self, issue_number: &str) -> anyhow::Result<()> {
        let resp = self
            .req(
                self.client
                    .patch(self.issues_url(&format!("/{issue_number}"))),
            )
            .json(&json!({ "state": "closed" }))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let v: Value = resp.json().await.unwrap_or_else(|_| json!({}));
            anyhow::bail!("github close {status}: {}", message_of(&v));
        }
        Ok(())
    }
}

/// Pull GitHub's `message` field out of an error response for the log/anyhow
/// chain (e.g. "Bad credentials"), or a generic note if absent.
fn message_of(v: &Value) -> String {
    v.get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("unexpected response")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{Path, State},
        routing::{patch, post},
        Json, Router,
    };
    use std::sync::{Arc, Mutex};

    /// What the mock GitHub server recorded, so a test can assert on exactly the
    /// requests the client made (path, method, the PII-safe JSON body).
    #[derive(Default)]
    struct Recorded {
        created_title: Option<String>,
        created_body: Option<String>,
        comment_issue: Option<i64>,
        comment_body: Option<String>,
        closed_issue: Option<i64>,
        closed_state: Option<String>,
    }

    type Shared = Arc<Mutex<Recorded>>;

    /// Spin up a LOCAL mock of the three GitHub endpoints on an ephemeral port,
    /// returning (base_url, recorder). No real api.github.com call is ever made.
    async fn mock_github() -> (String, Shared) {
        let rec: Shared = Arc::new(Mutex::new(Recorded::default()));
        let app = Router::new()
            .route(
                "/repos/:owner/:repo/issues",
                post(
                    |State(rec): State<Shared>, Json(b): Json<Value>| async move {
                        let mut r = rec.lock().unwrap();
                        r.created_title =
                            b.get("title").and_then(|v| v.as_str()).map(str::to_string);
                        r.created_body = b.get("body").and_then(|v| v.as_str()).map(str::to_string);
                        Json(json!({ "number": 7, "html_url": "https://github.com/o/r/issues/7" }))
                    },
                ),
            )
            .route(
                "/repos/:owner/:repo/issues/:n/comments",
                post(
                    |Path((_o, _r, n)): Path<(String, String, i64)>,
                     State(rec): State<Shared>,
                     Json(b): Json<Value>| async move {
                        let mut r = rec.lock().unwrap();
                        r.comment_issue = Some(n);
                        r.comment_body = b.get("body").and_then(|v| v.as_str()).map(str::to_string);
                        Json(json!({ "id": 1 }))
                    },
                ),
            )
            .route(
                "/repos/:owner/:repo/issues/:n",
                patch(
                    |Path((_o, _r, n)): Path<(String, String, i64)>,
                     State(rec): State<Shared>,
                     Json(b): Json<Value>| async move {
                        let mut r = rec.lock().unwrap();
                        r.closed_issue = Some(n);
                        r.closed_state =
                            b.get("state").and_then(|v| v.as_str()).map(str::to_string);
                        Json(json!({ "number": n, "state": "closed" }))
                    },
                ),
            )
            .with_state(rec.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (base, rec)
    }

    #[tokio::test]
    async fn create_comment_close_against_mock_github() {
        let (base, rec) = mock_github().await;
        let gh = GithubTracker::new("octo/repo".into(), "tok".into()).with_base_url(base);

        // create_issue parses number + html_url out of the response.
        let (number, url) = gh
            .create_issue("[reproit] bkt_x", "body for bkt_x")
            .await
            .unwrap();
        assert_eq!(number, "7");
        assert_eq!(url, "https://github.com/o/r/issues/7");

        gh.comment("7", "reproit confirmed bkt_x no longer reproduces")
            .await
            .unwrap();
        gh.close("7").await.unwrap();

        let r = rec.lock().unwrap();
        assert_eq!(r.created_title.as_deref(), Some("[reproit] bkt_x"));
        assert_eq!(r.created_body.as_deref(), Some("body for bkt_x"));
        assert_eq!(r.comment_issue, Some(7));
        assert!(r
            .comment_body
            .as_deref()
            .unwrap()
            .contains("no longer reproduces"));
        assert_eq!(r.closed_issue, Some(7));
        // close transitions to GitHub's terminal state.
        assert_eq!(r.closed_state.as_deref(), Some("closed"));
    }

    #[test]
    fn issues_url_targets_the_repo_issues_collection_and_items() {
        let gh = GithubTracker::new("octo/repo".into(), "t".into())
            .with_base_url("https://example.test".into());
        assert_eq!(
            gh.issues_url(""),
            "https://example.test/repos/octo/repo/issues"
        );
        assert_eq!(
            gh.issues_url("/7/comments"),
            "https://example.test/repos/octo/repo/issues/7/comments"
        );
    }
}
