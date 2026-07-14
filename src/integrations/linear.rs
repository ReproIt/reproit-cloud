//! Linear issue integration.

use super::{env_for, Tracker};
use serde_json::{json, Value};

pub struct LinearTracker {
    token: String,
    team_id: String,
    done_state_id: Option<String>,
    base_url: String,
    client: reqwest::Client,
}

impl LinearTracker {
    pub fn from_env(app_key: &str) -> Option<Self> {
        Some(Self::from_parts(
            env_for("REPROIT_LINEAR_TOKEN", app_key)?,
            env_for("REPROIT_LINEAR_TEAM_ID", app_key)?,
            env_for("REPROIT_LINEAR_DONE_STATE_ID", app_key),
            env_for("REPROIT_LINEAR_BASE_URL", app_key),
        ))
    }

    /// Construct from explicit config (the per-tenant `project_integrations`
    /// row); `from_env` is a thin wrapper over this.
    pub fn from_parts(
        token: String,
        team_id: String,
        done_state_id: Option<String>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            token,
            team_id,
            done_state_id,
            base_url: base_url.unwrap_or_else(|| "https://api.linear.app/graphql".to_string()),
            client: reqwest::Client::new(),
        }
    }

    async fn gql(&self, query: &str, variables: Value) -> anyhow::Result<Value> {
        let resp = self
            .client
            .post(&self.base_url)
            .bearer_auth(&self.token)
            .json(&json!({ "query": query, "variables": variables }))
            .send()
            .await?;
        let status = resp.status();
        let v: Value = resp.json().await?;
        if !status.is_success() || v.get("errors").is_some() {
            anyhow::bail!("linear graphql {status}: {}", message_of(&v));
        }
        Ok(v)
    }
}

impl Tracker for LinearTracker {
    fn provider(&self) -> &'static str {
        "linear"
    }

    fn repo(&self) -> &str {
        &self.team_id
    }

    async fn create_issue(&self, title: &str, body: &str) -> anyhow::Result<(String, String)> {
        let v = self
            .gql(
                "mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url } } }",
                json!({ "input": { "teamId": self.team_id, "title": title, "description": body } }),
            )
            .await?;
        let issue = &v["data"]["issueCreate"]["issue"];
        let id = issue
            .get("id")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow::anyhow!("linear issueCreate: no issue id"))?
            .to_string();
        let url = issue
            .get("url")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        Ok((id, url))
    }

    async fn comment(&self, external_id: &str, body: &str) -> anyhow::Result<()> {
        self.gql(
            "mutation($input: CommentCreateInput!) { commentCreate(input: $input) { success } }",
            json!({ "input": { "issueId": external_id, "body": body } }),
        )
        .await?;
        Ok(())
    }

    async fn close(&self, external_id: &str) -> anyhow::Result<()> {
        let Some(state_id) = &self.done_state_id else {
            return Ok(());
        };
        self.gql(
            "mutation($id: String!, $input: IssueUpdateInput!) { issueUpdate(id: $id, input: $input) { success } }",
            json!({ "id": external_id, "input": { "stateId": state_id } }),
        )
        .await?;
        Ok(())
    }
}

fn message_of(v: &Value) -> String {
    v.get("errors")
        .and_then(|x| x.as_array())
        .and_then(|xs| xs.first())
        .and_then(|x| x.get("message"))
        .and_then(|x| x.as_str())
        .unwrap_or("unexpected response")
        .to_string()
}
