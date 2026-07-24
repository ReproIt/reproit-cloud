//! Session + cookie plumbing: the opaque session token, the `rid_session` and
//! `rid_oauth_state` cookies (with their `Secure`/`Max-Age` rules), and the
//! small helpers (`ct_eq`, `cookie_value`, `with_cookie`) shared by the
//! handlers here and by the SSO overlay (sso.rs, hosted feature).

use axum::{
    http::{header::COOKIE, header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::Value;
use uuid::Uuid;

#[cfg(feature = "hosted")]
pub(crate) fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}
#[cfg(feature = "hosted")]
pub(crate) fn public_base() -> String {
    env("REPROIT_PUBLIC_URL").unwrap_or_else(|| "http://cloud.reproit.localhost".into())
}

pub(crate) const COOKIE_NAME: &str = "rid_session";
/// Session lifetime: 30 days, kept in lockstep with the server-side `expires_at`
/// (passed to `create_session`) and the cookie's `Max-Age`.
pub(crate) const SESSION_TTL_SECS: i64 = 2_592_000;
/// Transient cookie carrying the OAuth `state` between `*_start` and the
/// callback. Short-lived (10 min) so a dangling value can't be replayed later.
/// Reused by the SSO overlay (sso.rs) so its flow matches Google's exactly.
#[cfg(feature = "hosted")]
pub(crate) const OAUTH_STATE_COOKIE: &str = "rid_oauth_state";
#[cfg(feature = "hosted")]
pub(crate) const OAUTH_STATE_TTL_SECS: i64 = 600;

/// Opaque 64-hex session token (two v4 UUIDs). Also used to mint the OAuth/SSO
/// `state` nonce (CSPRNG via uuid v4), shared with the SSO overlay (sso.rs).
pub(crate) fn new_session_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// Constant-time byte compare (length may leak; contents must not). Used to
/// match the OAuth `state` so a mismatch can't be probed via response timing.
/// Shared with the SSO overlay (sso.rs) for `state` + webhook signature checks.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `; Secure` unless we're in the explicit local-dev escape hatch. Production is
/// always HTTPS, so this is on by default; only `REPROIT_DEV_OPEN=1` (plain http
/// localhost) drops it so the cookie still rides over http during dev.
pub(crate) fn secure_attr() -> &'static str {
    let dev = matches!(
        std::env::var("REPROIT_DEV_OPEN").ok().as_deref(),
        Some("1") | Some("true")
    );
    if dev {
        ""
    } else {
        "; Secure"
    }
}

pub(crate) fn session_cookie(token: &str) -> String {
    // 30-day session, Max-Age in lockstep with the server-side expiry. HttpOnly
    // keeps it out of JS; SameSite=Lax + Secure defend against CSRF / sniffing.
    format!(
        "{COOKIE_NAME}={token}; HttpOnly; SameSite=Lax{}; Path=/; Max-Age={SESSION_TTL_SECS}",
        secure_attr()
    )
}

pub(crate) fn cleared_cookie() -> String {
    format!(
        "{COOKIE_NAME}=; HttpOnly; SameSite=Lax{}; Path=/; Max-Age=0",
        secure_attr()
    )
}

/// Set the short-lived OAuth `state` cookie (CSRF / session-fixation defense).
#[cfg(feature = "hosted")]
pub(crate) fn oauth_state_cookie(state: &str) -> String {
    format!(
        "{OAUTH_STATE_COOKIE}={state}; HttpOnly; SameSite=Lax{}; Path=/; Max-Age={OAUTH_STATE_TTL_SECS}",
        secure_attr()
    )
}

/// Clear the OAuth `state` cookie once the callback has consumed it.
#[cfg(feature = "hosted")]
pub(crate) fn cleared_oauth_state_cookie() -> String {
    format!(
        "{OAUTH_STATE_COOKIE}=; HttpOnly; SameSite=Lax{}; Path=/; Max-Age=0",
        secure_attr()
    )
}

/// Pull a named cookie value out of a Cookie header.
pub(crate) fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|c| {
        let c = c.trim();
        c.strip_prefix(name).and_then(|rest| rest.strip_prefix('='))
    })
}

pub(crate) fn with_cookie(cookie: String, status: StatusCode, body: Value) -> Response {
    let mut resp = (status, Json(body)).into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(SET_COOKIE, v);
    }
    resp
}
