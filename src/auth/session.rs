//! Session and cookie plumbing for local password authentication.

use axum::{
    http::{header::COOKIE, header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::Value;
use uuid::Uuid;

pub(crate) const COOKIE_NAME: &str = "rid_session";
/// Session lifetime: 30 days, kept in lockstep with the server-side `expires_at`
/// (passed to `create_session`) and the cookie's `Max-Age`.
pub(crate) const SESSION_TTL_SECS: i64 = 2_592_000;
/// Opaque 64-hex session token (two CSPRNG UUIDs).
pub(crate) fn new_session_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// Constant-time byte compare (length may leak; contents must not). Used to
/// compare bearer credentials without leaking their contents through timing.
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
