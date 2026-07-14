//! Jira Cloud issue integration.
//!
//! Required env, scoped with `__<APP>` or global:
//!   REPROIT_JIRA_BASE_URL      https://example.atlassian.net
//!   REPROIT_JIRA_EMAIL         bot@example.com
//!   REPROIT_JIRA_API_TOKEN     Atlassian API token
//!   REPROIT_JIRA_PROJECT_KEY   ENG
//! Optional:
//!   REPROIT_JIRA_ISSUE_TYPE    Bug
//!   REPROIT_JIRA_DONE_TRANSITION_ID

use super::{env_for, Tracker};
use serde_json::{json, Value};

pub struct JiraTracker {
    base_url: String,
    email: String,
    api_token: String,
    project_key: String,
    issue_type: String,
    done_transition_id: Option<String>,
    client: reqwest::Client,
}

impl JiraTracker {
    pub fn from_env(app_key: &str) -> Option<Self> {
        Some(Self::from_parts(
            env_for("REPROIT_JIRA_BASE_URL", app_key)?,
            env_for("REPROIT_JIRA_EMAIL", app_key)?,
            env_for("REPROIT_JIRA_API_TOKEN", app_key)?,
            env_for("REPROIT_JIRA_PROJECT_KEY", app_key)?,
            env_for("REPROIT_JIRA_ISSUE_TYPE", app_key),
            env_for("REPROIT_JIRA_DONE_TRANSITION_ID", app_key),
        ))
    }

    /// Construct from explicit config (the per-tenant `project_integrations`
    /// row); `from_env` is a thin wrapper over this.
    pub fn from_parts(
        base_url: String,
        email: String,
        api_token: String,
        project_key: String,
        issue_type: Option<String>,
        done_transition_id: Option<String>,
    ) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            email,
            api_token,
            project_key,
            issue_type: issue_type.unwrap_or_else(|| "Bug".to_string()),
            done_transition_id,
            client: reqwest::Client::new(),
        }
    }

    fn api(&self, path: &str) -> String {
        format!("{}/rest/api/3{}", self.base_url, path)
    }

    fn req(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        rb.basic_auth(&self.email, Some(&self.api_token))
            .header("Accept", "application/json")
    }
}

impl Tracker for JiraTracker {
    fn provider(&self) -> &'static str {
        "jira"
    }

    fn repo(&self) -> &str {
        &self.project_key
    }

    async fn create_issue(&self, title: &str, body: &str) -> anyhow::Result<(String, String)> {
        let resp = self
            .req(self.client.post(self.api("/issue")))
            .json(&json!({
                "fields": {
                    "project": { "key": self.project_key },
                    "issuetype": { "name": self.issue_type },
                    "summary": title,
                    "description": adf_doc(body)
                }
            }))
            .send()
            .await?;
        let status = resp.status();
        let v: Value = resp.json().await?;
        if !status.is_success() {
            anyhow::bail!("jira create_issue {status}: {}", message_of(&v));
        }
        let key = v
            .get("key")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow::anyhow!("jira create_issue: no issue key in response"))?
            .to_string();
        let url = format!("{}/browse/{}", self.base_url, key);
        Ok((key, url))
    }

    async fn comment(&self, external_id: &str, body: &str) -> anyhow::Result<()> {
        let resp = self
            .req(
                self.client
                    .post(self.api(&format!("/issue/{external_id}/comment"))),
            )
            .json(&json!({ "body": adf_doc(body) }))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let v: Value = resp.json().await.unwrap_or_else(|_| json!({}));
            anyhow::bail!("jira comment {status}: {}", message_of(&v));
        }
        Ok(())
    }

    async fn close(&self, external_id: &str) -> anyhow::Result<()> {
        let Some(id) = &self.done_transition_id else {
            return Ok(());
        };
        let resp = self
            .req(
                self.client
                    .post(self.api(&format!("/issue/{external_id}/transitions"))),
            )
            .json(&json!({ "transition": { "id": id } }))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let v: Value = resp.json().await.unwrap_or_else(|_| json!({}));
            anyhow::bail!("jira transition {status}: {}", message_of(&v));
        }
        Ok(())
    }
}

fn adf_doc(text: &str) -> Value {
    json!({
        "type": "doc",
        "version": 1,
        "content": [{
            "type": "paragraph",
            "content": [{ "type": "text", "text": text }]
        }]
    })
}

fn message_of(v: &Value) -> String {
    v.get("errorMessages")
        .and_then(|x| x.as_array())
        .and_then(|xs| xs.first())
        .and_then(|x| x.as_str())
        .or_else(|| v.get("message").and_then(|x| x.as_str()))
        .unwrap_or("unexpected response")
        .to_string()
}
