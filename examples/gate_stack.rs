//! Credential-free MULTI-TENANT boot for local dev and the hosted production
//! gates (specifically `two-tenant-negative`).
//!
//! The shipped `reproit-cloud` binary defaults to the SINGLE-tenant self-hosted
//! edition (`RunConfig::default().default_self_hosted == true`), and no env var
//! turns that off. The two-tenant negative cases need TWO real tenants
//! (database-per-org), so this example is the one seam that composes the
//! multi-tenant control plane WITHOUT the hosted overlay's external providers.
//!
//! `default_self_hosted: false` gives database-per-org: the LocalProvider derives
//! `reproit_tenant_<org>` on the base Postgres (`REPROIT_TENANT_PROVIDER` unset or
//! `local`). `require_mail: false` boots with no Resend key, so verification links
//! are logged instead of mailed (see `mail::send`) and a provisioning script can
//! drive signup end to end from one Postgres. Blobs stay local-fs
//! (`REPROIT_ALLOW_LOCAL_BLOBS=1` + `REPROIT_ARTIFACT_DIR`), so the whole stack
//! runs on one Postgres with no live providers.
//!
//! Because `run_with` also dispatches the one-shot ops subcommands, invoking this
//! example as `gate_stack -- suspend <org> --yes` / `-- offboard --org <org>
//! --yes` runs those ops with the SAME multi-tenant wiring (the default binary is
//! self-hosted and refuses `offboard`).
//!
//! This is NOT a production artifact: the hosted deployment composes its own
//! overlay (policy, SSO, dashboard assets). This is the local/gate stack only.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    reproit_cloud::run_with(reproit_cloud::RunConfig {
        default_self_hosted: false,
        require_mail: false,
        ..reproit_cloud::RunConfig::default()
    })
    .await
}
