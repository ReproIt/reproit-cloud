//! Optional transactional email for self-hosted invitations. When Resend is
//! not configured, the invitation is logged so a local operator can copy it.

use serde_json::json;

const RESEND_API: &str = "https://api.resend.com/emails";

pub fn public_base() -> String {
    std::env::var("REPROIT_PUBLIC_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.trim_end_matches('/').to_string())
        .unwrap_or_else(|| "http://localhost:8080".to_string())
}

pub async fn send(to: &str, subject: &str, text: &str) -> anyhow::Result<()> {
    let from = std::env::var("REPROIT_MAIL_FROM")
        .ok()
        .filter(|v| !v.is_empty());
    let key = std::env::var("RESEND_API_KEY")
        .ok()
        .filter(|v| !v.is_empty());
    let (Some(from), Some(key)) = (from, key) else {
        tracing::info!("mail (unconfigured, logging instead) to={to} subject={subject:?}\n{text}");
        return Ok(());
    };
    let resp = reqwest::Client::new()
        .post(RESEND_API)
        .bearer_auth(key)
        .json(&json!({"from":from,"to":[to],"subject":subject,"text":text}))
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("mail provider rejected invitation");
    }
    Ok(())
}

pub fn invitation_email(org_name: &str, link: &str) -> (String, String) {
    (format!("Join {org_name} on ReproIt"), format!(
        "You have been invited to join {org_name} on ReproIt:\n\n{link}\n\nThe invitation expires in 7 days and works once. If you were not expecting it, ignore this email."
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn invitation_names_org_link_and_expiry() {
        let (subject, body) = super::invitation_email("Acme", "https://x/invite?token=t");
        assert!(subject.contains("Acme"));
        assert!(body.contains("https://x/invite?token=t"));
        assert!(body.contains("7 days"));
    }
}
