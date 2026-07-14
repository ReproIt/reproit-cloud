//! Shortcut story integration.

use super::{env_for, Tracker};
use serde_json::{json, Value};

pub struct ShortcutTracker {
    token: String,
    project_id: i64,
    done_state_id: Option<i64>,
    base_url: String,
    client: reqwest::Client,
}

impl ShortcutTracker {
    pub fn from_env(app_key: &str) -> Option<Self> {
        Some(Self::from_parts(
            env_for("REPROIT_SHORTCUT_TOKEN", app_key)?,
            env_for("REPROIT_SHORTCUT_PROJECT_ID", app_key)?
                .parse()
                .ok()?,
            env_for("REPROIT_SHORTCUT_DONE_STATE_ID", app_key).and_then(|v| v.parse().ok()),
            env_for("REPROIT_SHORTCUT_BASE_URL", app_key),
        ))
    }

    /// Construct from explicit config (the per-tenant `project_integrations`
    /// row); `from_env` is a thin wrapper over this.
    pub fn from_parts(
        token: String,
        project_id: i64,
        done_state_id: Option<i64>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            token,
            project_id,
            done_state_id,
            base_url: base_url.unwrap_or_else(|| "https://api.app.shortcut.com/api/v3".to_string()),
            client: reqwest::Client::new(),
        }
    }

    fn api(&self, path: &str) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), path)
    }

    fn req(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        rb.header("Shortcut-Token", &self.token)
            .header("Content-Type", "application/json")
    }
}

impl Tracker for ShortcutTracker {
    fn provider(&self) -> &'static str {
        "shortcut"
    }

    fn repo(&self) -> &str {
        "shortcut"
    }

    async fn create_issue(&self, title: &str, body: &str) -> anyhow::Result<(String, String)> {
        let resp = self
            .req(self.client.post(self.api("/stories")))
            .json(&json!({
                "name": title,
                "description": body,
                "story_type": "bug",
                "project_id": self.project_id
            }))
            .send()
            .await?;
        let status = resp.status();
        let v: Value = resp.json().await?;
        if !status.is_success() {
            anyhow::bail!("shortcut create story {status}: {}", message_of(&v));
        }
        let id = v
            .get("id")
            .and_then(|x| x.as_i64())
            .ok_or_else(|| anyhow::anyhow!("shortcut create story: no id"))?;
        let url = v
            .get("app_url")
            .or_else(|| v.get("url"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        Ok((id.to_string(), url))
    }

    async fn comment(&self, external_id: &str, body: &str) -> anyhow::Result<()> {
        let resp = self
            .req(
                self.client
                    .post(self.api(&format!("/stories/{external_id}/comments"))),
            )
            .json(&json!({ "text": body }))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let v: Value = resp.json().await.unwrap_or_else(|_| json!({}));
            anyhow::bail!("shortcut comment {status}: {}", message_of(&v));
        }
        Ok(())
    }

    async fn close(&self, external_id: &str) -> anyhow::Result<()> {
        let Some(done_state_id) = self.done_state_id else {
            return Ok(());
        };
        let resp = self
            .req(
                self.client
                    .put(self.api(&format!("/stories/{external_id}"))),
            )
            .json(&json!({ "workflow_state_id": done_state_id }))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let v: Value = resp.json().await.unwrap_or_else(|_| json!({}));
            anyhow::bail!("shortcut close {status}: {}", message_of(&v));
        }
        Ok(())
    }
}

fn message_of(v: &Value) -> String {
    v.get("message")
        .or_else(|| v.get("error"))
        .and_then(|x| x.as_str())
        .unwrap_or("unexpected response")
        .to_string()
}
