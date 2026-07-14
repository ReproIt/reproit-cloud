//! At-rest encryption for control/tenant secrets (tenant DB connection
//! strings, per-app integration tokens): ChaCha20-Poly1305 AEAD keyed by
//! `REPROIT_CONN_ENC_KEY` (32-byte hex), stored as `enc:v1:<hex(nonce||ct)>`
//! with a fresh random nonce per write. Unset key => plaintext passthrough
//! (self-host/dev), with a one-time warning. Extracted from `control.rs` so
//! every secret column uses the same scheme + key.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

/// Version prefix on an encrypted secret. A value WITHOUT this prefix is legacy
/// plaintext (self-host/dev, or rows written before encryption was enabled) and is
/// read back verbatim, so existing rows keep working.
pub(crate) const CONN_ENC_PREFIX: &str = "enc:v1:";

/// The 32-byte AEAD key from `REPROIT_CONN_ENC_KEY` (hex), or `None` if unset.
/// When unset we fall back to plaintext storage (preserving self-host/dev), with a
/// one-time warning so the operator knows tenant conn strings are not encrypted.
fn conn_enc_key() -> Option<[u8; 32]> {
    use std::sync::OnceLock;
    static WARNED: OnceLock<()> = OnceLock::new();
    let hex_key = match std::env::var("REPROIT_CONN_ENC_KEY") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            WARNED.get_or_init(|| {
                tracing::warn!(
                    "REPROIT_CONN_ENC_KEY unset: tenant DB connection strings are stored \
                     UNENCRYPTED (set a 32-byte hex key to encrypt them at rest)"
                );
            });
            return None;
        }
    };
    match hex::decode(hex_key.trim()) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Some(key)
        }
        _ => {
            // Misconfigured key is a hard error in spirit, but we must not panic on
            // the request path; treat as "no key" and warn loudly every time so it
            // is impossible to miss in logs (this should never happen in prod).
            tracing::error!(
                "REPROIT_CONN_ENC_KEY is set but is not 32 bytes of hex; \
                 storing tenant conn strings UNENCRYPTED"
            );
            None
        }
    }
}

/// Encrypt a tenant connection string for at-rest storage. With a key configured,
/// returns `enc:v1:<hex(nonce||ciphertext)>` (fresh random 12-byte nonce per call);
/// without a key, returns the plaintext unchanged (legacy/dev behavior).
pub(crate) fn encrypt(plaintext: &str) -> anyhow::Result<String> {
    let key = match conn_enc_key() {
        Some(k) => k,
        None => return Ok(plaintext.to_string()),
    };
    use rand::RngCore;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
        .map_err(|_| anyhow::anyhow!("secret encryption failed"))?;
    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    Ok(format!("{CONN_ENC_PREFIX}{}", hex::encode(blob)))
}

/// Decrypt a stored tenant connection string. An `enc:v1:`-prefixed value is
/// decrypted with the configured key; any other value is treated as legacy
/// plaintext and returned as-is (so existing rows and dev keep working).
pub(crate) fn decrypt(stored: &str) -> anyhow::Result<String> {
    let Some(rest) = stored.strip_prefix(CONN_ENC_PREFIX) else {
        return Ok(stored.to_string()); // legacy plaintext
    };
    let key = conn_enc_key().ok_or_else(|| {
        anyhow::anyhow!("encrypted secret present but REPROIT_CONN_ENC_KEY unset")
    })?;
    let blob = hex::decode(rest).map_err(|_| anyhow::anyhow!("secret ciphertext not valid hex"))?;
    if blob.len() < 12 {
        anyhow::bail!("secret ciphertext too short");
    }
    let (nonce_bytes, ct) = blob.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| anyhow::anyhow!("secret decryption failed (wrong key or corrupt data)"))?;
    Ok(String::from_utf8(pt)?)
}
