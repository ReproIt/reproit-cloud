//! Per-user API keys: minting a `sk_live_*` secret (returned once) and deriving
//! the non-secret display prefix that's safe to store and list in plaintext.

/// A user-facing API key secret: `sk_live_<48 hex chars>` drawn from the OS
/// CSPRNG. The full secret is returned to the user exactly once (at creation);
/// only its hash is stored, so it can never be retrieved again.
pub fn new_api_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("sk_live_{}", hex::encode(bytes))
}

/// A PUBLISHABLE key: `pk_live_<48 hex chars>`, minted alongside the secret when
/// a project is created. It is write-only (see `is_publishable` + the ingest-only
/// route gate) so it is SAFE to ship in client-side browser JS. The SDK snippet
/// carries this, never the secret. A visitor who lifts it from page source can
/// only append telemetry, never read or export the org's bug data.
pub fn new_publishable_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("pk_live_{}", hex::encode(bytes))
}

/// True for a publishable (`pk_live_`) key. Publishable keys are accepted ONLY on
/// `POST /v1/events`; every read/export/manage route rejects them, so a key that
/// must live in a browser can never read the tenant's data. The distinction rides
/// in the token string itself (its prefix), so no per-key scope column is needed.
pub(crate) fn is_publishable(token: &str) -> bool {
    token.starts_with("pk_")
}

/// A non-secret display hint for a key (e.g. "sk_live_ab..." / "pk_live_ab..."):
/// the literal `xk_live_` prefix plus only the first 2 secret hex chars,
/// Safe to store and list in plaintext. Deliberately reveals at most
/// ~1 secret byte (down from 4) so the hint can never be used to narrow a brute
/// force of the key.
pub(crate) fn api_key_prefix(secret: &str) -> String {
    // `sk_live_`/`pk_live_` is 8 chars; take 2 more (one secret byte), then mark.
    let shown: String = secret.chars().take(8 + 2).collect();
    format!("{shown}...")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_and_publishable_have_distinct_prefixes_and_scope() {
        let sk = new_api_key();
        let pk = new_publishable_key();
        assert!(sk.starts_with("sk_live_"));
        assert!(pk.starts_with("pk_live_"));
        // The scope gate keys off the prefix: only pk is publishable, and a secret
        // key must never be treated as write-only (it would lose read access).
        assert!(is_publishable(&pk));
        assert!(!is_publishable(&sk));
        // Full length: 8-char prefix + 48 hex chars.
        assert_eq!(sk.len(), 8 + 48);
        assert_eq!(pk.len(), 8 + 48);
        // The display hint reveals at most one secret byte and marks truncation.
        assert_eq!(api_key_prefix(&pk).len(), 10 + 3);
        assert!(api_key_prefix(&pk).ends_with("..."));
    }
}
