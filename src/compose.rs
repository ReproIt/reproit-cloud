//! The public composition surface an overlay edition drives: the policy
//! factory, the preflight, and `RunConfig`, the one bundle of seams
//! `run_with` accepts. Split from lib.rs so process wiring stays under the
//! file cap.

use crate::db::ControlStore;
use crate::{edition, router, App};
use axum::Router;
use std::sync::Arc;

/// Builds the edition policy once the control store exists. The resolved
/// self-hosted flag comes first so an overlay binary can still honor an
/// operator's explicit self-host mode.
pub type PolicyFactory =
    Box<dyn FnOnce(bool, Arc<ControlStore>) -> Arc<dyn edition::EditionPolicy> + Send>;

/// Edition preflight, called with the resolved self-hosted flag before any
/// database work, so an overlay can refuse a misconfigured deployment early.
pub type PreflightFn = Box<dyn FnOnce(bool) -> anyhow::Result<()> + Send>;

/// Composition inputs for `run_with`: the seams a hosted overlay drives.
/// `Default` is the self-hosted edition exactly as `run()` ships it.
pub struct RunConfig {
    /// The self-hosted flag's value when neither `--self-hosted`, the env,
    /// nor an implying flag decides. The self-host distribution defaults to
    /// true; an overlay deployment passes false and stays multi-tenant.
    pub default_self_hosted: bool,
    /// Edition security preflight; receives the resolved self-hosted flag.
    pub preflight: Option<PreflightFn>,
    /// Edition policy hooks (quotas, metering, account card, login gate);
    /// None installs `PassivePolicy`.
    pub policy: Option<PolicyFactory>,
    /// Extra routes merged into the shared router BEFORE the security layers
    /// wrap it, with NO shared rate limiter (signature-gated webhooks).
    pub overlay_routes: Option<Router<App>>,
    /// Extra routes merged under the tight brute-force auth limiter
    /// (identity-provider start/callback endpoints).
    pub overlay_auth: Option<Router<App>>,
    /// Extra routes merged under the account limiter + CSRF origin guard
    /// (cookie-authenticated mutations such as billing checkout).
    pub overlay_account: Option<Router<App>>,
    /// Overlay control-plane schema applied right after the shared schema
    /// (idempotent SQL, same contract as CONTROL_SCHEMA).
    pub extra_control_schema: Option<&'static str>,
    /// Refuse a hosted (multi-tenant) boot without a configured mail
    /// provider. Hosted signup depends on verification email; self-host
    /// logs the links instead and is never gated.
    pub require_mail: bool,
    /// Mount the human capture-report surface (API + review pages).
    pub captures: bool,
    /// The embedded static assets this edition serves: (path, content type,
    /// body). Defaults to the self-host dashboard baked into this crate.
    pub assets: &'static [router::StaticAsset],
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            default_self_hosted: true,
            preflight: None,
            policy: None,
            overlay_routes: None,
            overlay_auth: None,
            overlay_account: None,
            extra_control_schema: None,
            require_mail: false,
            captures: true,
            assets: router::SELF_HOST_ASSETS,
        }
    }
}
