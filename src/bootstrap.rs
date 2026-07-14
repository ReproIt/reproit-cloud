//! Self-host bootstrap: turn a fresh single-tenant database into a usable install.
//!
//! Self-host runs the SAME SaaS code with the tenant count fixed at one (org
//! `SELF_HOSTED_ORG_ID`). A fresh SaaS database has no org, no admin user, and no
//! API key, so there is nothing to sign in with and nothing for the CLI/SDK to
//! present. This routine creates exactly those three things, idempotently:
//!   1. the single org (org #1),
//!   2. an admin user that owns it,
//!   3. a default project + its first `sk_live_*` key (printed once to stdout).
//!
//! Every step is safe to re-run: a redeploy with the same bootstrap envs (or a
//! second `init`) reuses what exists and never mints a second key. It is invoked
//! by the `init` subcommand and, on normal startup, by the
//! `REPROIT_BOOTSTRAP_EMAIL`/`REPROIT_BOOTSTRAP_PASSWORD` env pair.

use crate::auth::{api_key_prefix_pub, hash_password_pub, new_api_key};
use crate::tenancy::SELF_HOSTED_ORG_ID;
use crate::App;
use uuid::Uuid;

/// Bring a self-host install to a ready state. Idempotent end to end; see the
/// module docs for the steps. Prints the freshly minted API key to stdout exactly
/// once (only on the first run that mints it); never logs the secret.
pub(crate) async fn bootstrap(
    app: &App,
    email: &str,
    password: &str,
    project_name: &str,
) -> anyhow::Result<()> {
    let email = email.trim().to_lowercase();
    if !email.contains('@') {
        anyhow::bail!("bootstrap email must be a valid email address");
    }
    if password.len() < 8 {
        anyhow::bail!("bootstrap password must be at least 8 characters");
    }

    // 1. Ensure org #1. On a FRESH database `create_org` (BIGSERIAL) returns id 1.
    // If org #1 already exists we reuse it; if creation hands back any other id the
    // database was not fresh (it already had orgs), which self-host can't pin to a
    // fixed tenant, so we bail with a clear message rather than corrupt routing.
    if !app.control.org_exists(SELF_HOSTED_ORG_ID).await? {
        let id = app.control.create_org(project_name, false).await?;
        if id != SELF_HOSTED_ORG_ID {
            anyhow::bail!(
                "self-host bootstrap expects a fresh database; found existing org(s) \
                 (new org got id {id}, expected {SELF_HOSTED_ORG_ID})"
            );
        }
    }

    // 2. Ensure the admin user exists and owns org #1. Reuse an existing account by
    // email (re-bootstrap), only hashing/creating when absent. `add_member` upserts
    // the owner role, so it is safe whether or not the membership already exists.
    let user_id = match app.control.find_user_id_by_email(&email).await? {
        Some(id) => id,
        None => {
            let hash = hash_password_pub(password)
                .map_err(|e| anyhow::anyhow!("could not hash bootstrap password: {e}"))?;
            app.control.create_user(&email, &hash).await?
        }
    };
    app.control
        .add_member(SELF_HOSTED_ORG_ID, user_id, "owner")
        .await?;

    // 3. Provision the single tenant DB (idempotent: intent -> db -> schema ->
    // blob -> active, resumable on a half-finished prior run).
    app.tenancy.provision(SELF_HOSTED_ORG_ID).await?;

    // 4. Default project + first key. If the org already has any key we are
    // re-running on an installed system: don't mint another (the secret is shown
    // only once, so a second mint would silently strand a key). Report and stop.
    let existing = app.control.list_api_keys(SELF_HOSTED_ORG_ID).await?;
    if !existing.is_empty() {
        tracing::info!(
            "self-host already bootstrapped ({} key(s)); not minting another",
            existing.len()
        );
        return Ok(());
    }

    // Same slug + short-uuid app id the dashboard's create_project handler builds.
    let slug: String = project_name
        .to_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect();
    let app_id = format!(
        "{}-{}",
        slug.trim_matches('-'),
        &Uuid::new_v4().simple().to_string()[..6]
    );

    let tenant = app
        .tenancy
        .resolve(SELF_HOSTED_ORG_ID)
        .await
        .map_err(|e| anyhow::anyhow!("could not resolve the self-host tenant: {e}"))?;
    let project_id = tenant
        .store
        .create_project(user_id, project_name, &app_id)
        .await?;

    // Mint the SDK/CLI key. Only the hash + a display prefix are stored; the full
    // secret is shown once here and is never retrievable again. Never logged.
    let key = new_api_key();
    let prefix = api_key_prefix_pub(&key);
    app.control
        .create_api_key(&key, &prefix, SELF_HOSTED_ORG_ID, user_id, Some(project_id))
        .await?;

    // The one place the secret is surfaced: stdout, in an obvious copy-now block.
    println!("\n  ReproIt self-host bootstrap complete.");
    println!("  Project: {project_name}  (appId: {app_id})");
    println!("  API key (shown once, store it now): {key}\n");

    Ok(())
}
