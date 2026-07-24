//! Outbound transactional email via Resend (signup verification, password
//! reset). Deliberately tiny: plain-text bodies, one POST, no template system.
//!
//! Config: `RESEND_API_KEY` + `REPROIT_MAIL_FROM` (e.g. `Reproit <no-reply@reproit.com>`).
//! When UNCONFIGURED (self-host/dev), `send` logs the body instead of failing so
//! the verification/reset links remain usable from the server log.

use serde_json::json;

const RESEND_API: &str = "https://api.resend.com/emails";

fn from_addr() -> Option<String> {
    std::env::var("REPROIT_MAIL_FROM")
        .ok()
        .filter(|v| !v.is_empty())
}

/// True when both mail env vars are set, so `send` will actually deliver rather
/// than log. The boot path uses this to refuse a hosted start with no mail.
// Consumed by the hosted signup/reset flow; self-host has no caller yet.
#[allow(dead_code)]
pub fn is_configured() -> bool {
    from_addr().is_some()
        && std::env::var("RESEND_API_KEY")
            .ok()
            .is_some_and(|v| !v.is_empty())
}

/// Send a plain-text email. Errors are returned (callers decide whether the
/// request fails); unconfigured installs log the body and succeed, so the
/// self-host flow works with zero mail setup.
pub async fn send(to: &str, subject: &str, text: &str) -> anyhow::Result<()> {
    let (Some(from), Ok(key)) = (from_addr(), std::env::var("RESEND_API_KEY")) else {
        // Hosted boot refuses this state (see main), so reaching here means a
        // self-host/dev install with no mail provider: log the link so it stays
        // usable from the server log.
        tracing::info!("mail (unconfigured, logging instead) to={to} subject={subject:?}\n{text}");
        return Ok(());
    };
    let resp = reqwest::Client::new()
        .post(RESEND_API)
        .bearer_auth(key)
        .json(&json!({ "from": from, "to": [to], "subject": subject, "text": text }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("resend send failed ({status}): {body}");
    }
    Ok(())
}

/// The public base url links are built on. Hosted deploys set
/// REPROIT_PUBLIC_URL; the localhost fallback keeps dev links clickable.
pub fn public_base() -> String {
    std::env::var("REPROIT_PUBLIC_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.trim_end_matches('/').to_string())
        .unwrap_or_else(|| "http://localhost:8080".to_string())
}

// Consumed by the hosted signup/reset flow; self-host has no caller yet.
#[allow(dead_code)]
pub fn verification_email(link: &str) -> (String, String) {
    (
        "Verify your ReproIt email".to_string(),
        format!(
            "Confirm your email to finish creating your ReproIt workspace:\n\n{link}\n\nThe link expires in 48 hours. If you didn't sign up, ignore this email."
        ),
    )
}

// Consumed by the hosted signup/reset flow; self-host has no caller yet.
#[allow(dead_code)]
pub fn reset_email(link: &str) -> (String, String) {
    (
        "Reset your ReproIt password".to_string(),
        format!(
            "Reset your ReproIt password:\n\n{link}\n\nThe link expires in 30 minutes and works once. If you didn't request this, ignore this email; your password is unchanged."
        ),
    )
}

pub fn invitation_email(org_name: &str, link: &str) -> (String, String) {
    (
        format!("Join {org_name} on ReproIt"),
        format!(
            "You have been invited to join {org_name} on ReproIt:\n\n{link}\n\nThe invitation expires in 7 days and works once. If you were not expecting it, ignore this email."
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_embed_the_link_and_name_the_expiry() {
        let (subj, body) = verification_email("https://x/auth/verify?token=t");
        assert!(subj.contains("Verify"));
        assert!(body.contains("https://x/auth/verify?token=t"));
        assert!(body.contains("48 hours"));
        let (subj, body) = reset_email("https://x/reset?token=t");
        assert!(subj.contains("Reset"));
        assert!(body.contains("https://x/reset?token=t"));
        assert!(body.contains("once"));
        let (subj, body) = invitation_email("Acme", "https://x/invite?token=t");
        assert!(subj.contains("Acme"));
        assert!(body.contains("https://x/invite?token=t"));
        assert!(body.contains("7 days"));
    }
}
