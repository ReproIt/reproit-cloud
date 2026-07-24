//! Password hashing (argon2id) and the federated-account "unusable password"
//! sentinel. Google / SSO accounts get a random sentinel hash no password can
//! ever verify against, so they exist for membership but only sign in via the
//! IdP. Shared with the SSO overlay so JIT-provisioned users match exactly.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use uuid::Uuid;

pub(crate) fn hash_password(pw: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub(crate) fn verify_password(pw: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(pw.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// An "unusable password" sentinel hash for federated accounts (Google / SSO):
/// a random argon2id hash that no password can ever verify against, so the
/// account exists for membership but can only sign in via the IdP. Shared with
/// the SSO overlay so JIT-provisioned users match the Google path exactly.
// Consumed by the SSO overlay; self-host has no federated sign-in yet.
#[allow(dead_code)]
pub(crate) fn oauth_sentinel_hash() -> String {
    hash_password(&Uuid::new_v4().to_string()).unwrap_or_else(|_| Uuid::new_v4().to_string())
}
