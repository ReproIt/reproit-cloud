//! Per-tenant blob / object isolation: the videos are the crown jewels, so blob
//! isolation matters as much as DB isolation (`docs/architecture/multi-tenancy.md`
//! §5). The model:
//!
//!   - A tenant's bytes live under a per-tenant SCOPE: a prefix in a shared bucket
//!     (default) or a dedicated bucket (enterprise). The control-plane
//!     `tenants.blob_scope` records which.
//!   - A request is handed a [`TenantBlobs`] handle ALREADY pinned to the resolved
//!     tenant's scope. Every key it forms is rooted at that scope, so a handler
//!     bug cannot address another tenant's bytes: the handle has no authority
//!     outside the scope.
//!   - Signed/served URLs name a key inside the scope and cannot be edited to
//!     point across tenants.
//!
//! The backend is a [`BlobBackend`] trait with two impls:
//!   - [`LocalBackend`]: filesystem, the default, needs no credentials, so the
//!     whole cloud is testable offline. Serves via the cloud's `/v1/blob/*key`
//!     proxy (which keeps its own safety check).
//!   - [`R2Backend`] (feature `r2`): a Cloudflare R2 bucket with short-lived
//!     presigned GET urls. With `R2_CREDS_API_TOKEN` set, every tenant operation
//!     runs under a PER-TENANT temporary credential minted from Cloudflare's
//!     temp-access-credentials API, bound to the tenant's key prefix and cached
//!     with TTL-aware refresh, so even a key-forming bug cannot cross a tenant
//!     boundary at the STORAGE layer. Without it the one process credential is
//!     used and isolation is convention-only (logged once at startup).
//!
//! Self-hosted degenerates to one scope for the one tenant; same code.

use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;

/// The provider-agnostic blob backend. Operations take the tenant's SCOPE (the
/// isolation boundary; a backend that binds storage-layer credentials uses it,
/// the local backend ignores it) plus a FULLY-SCOPED key (the tenant prefix is
/// already prepended by `TenantBlobs`), so a backend never sees an unscoped key
/// and cannot be tricked into crossing a tenant boundary.
#[allow(async_fn_in_trait)]
pub trait BlobBackend: Send + Sync {
    async fn put(&self, scope: &str, key: &str, bytes: &[u8]) -> anyhow::Result<String>;
    // Consumed by the capture upload flow; hosted mounts no capture routes yet.
    #[allow(dead_code)]
    async fn put_path(
        &self,
        scope: &str,
        key: &str,
        path: &std::path::Path,
        content_type: &str,
    ) -> anyhow::Result<String>;
    async fn get(&self, scope: &str, key: &str) -> anyhow::Result<Vec<u8>>;
    /// A url a client can fetch `key` from: a cloud-proxied path (local) or a
    /// short-lived presigned GET (R2).
    async fn url_for(&self, scope: &str, key: &str) -> anyhow::Result<String>;
    /// Remove the object. Deleting a key that no longer exists is NOT an error
    /// (retention retries must be idempotent).
    async fn delete(&self, scope: &str, key: &str) -> anyhow::Result<()>;
    /// Remove every object under `prefix` (tenant offboarding). Returns the
    /// number of objects removed; a missing prefix is 0, not an error.
    async fn delete_prefix(&self, prefix: &str) -> anyhow::Result<u64>;
}

/// The process-wide blob store, before tenant scoping. Built once at startup from
/// env; `for_tenant` derives the per-request scoped handle.
#[derive(Clone)]
pub struct Blobs {
    backend: Arc<Backend>,
}

/// Concrete backend selection. (An enum rather than `Box<dyn>` so the local/r2
/// split stays monomorphized and the `r2` feature gates cleanly.)
enum Backend {
    Local(LocalBackend),
    // Boxed: the R2 backend now carries the credential minter + cache, which
    // would otherwise dominate the enum's size for the local-fs default too.
    #[cfg(feature = "r2")]
    R2(Box<R2Backend>),
}

impl Blobs {
    /// R2 when R2_* env vars are present (and the `r2` feature is built), else the
    /// local filesystem under REPROIT_ARTIFACT_DIR.
    pub fn from_env() -> Self {
        #[cfg(feature = "r2")]
        {
            if let Some(b) = R2Backend::from_env() {
                if b.mints_scoped_credentials() {
                    tracing::info!(
                        "blobs: R2 backend, per-tenant prefix-scoped credentials (minted via the Cloudflare API)"
                    );
                } else {
                    tracing::warn!(
                        "blobs: R2 backend without credential minting: blob isolation is convention-only (key prefixes); set R2_CREDS_API_TOKEN (with R2_ACCOUNT_ID) for per-tenant prefix-scoped credentials"
                    );
                }
                return Self {
                    backend: Arc::new(Backend::R2(Box::new(b))),
                };
            }
        }
        let root = std::env::var("REPROIT_ARTIFACT_DIR")
            .unwrap_or_else(|_| "/tmp/reproit-artifacts".into());
        tracing::info!(
            "blobs: local-fs backend (dir={root}); blob isolation is convention-only (key prefixes behind the blob proxy's safety check)"
        );
        Self {
            backend: Arc::new(Backend::Local(LocalBackend {
                root: PathBuf::from(root),
            })),
        }
    }

    /// Whether blobs land on the local filesystem (vs a durable object store).
    /// Hosted deployments use this at startup to refuse ephemeral evidence storage.
    pub fn is_local_fs(&self) -> bool {
        matches!(&*self.backend, Backend::Local(_))
    }

    /// Delete EVERYTHING under a tenant's blob scope (offboarding/GDPR).
    /// Idempotent; an empty scope is refused (it would name the whole store).
    pub async fn delete_scope(&self, scope: &str) -> anyhow::Result<u64> {
        let scope = scope.trim_matches('/');
        if scope.is_empty() {
            anyhow::bail!("refusing to delete an empty blob scope");
        }
        self.backend.delete_prefix(scope).await
    }

    /// Derive a handle pinned to one tenant's blob scope (`tenants.blob_scope`).
    /// Every key is rooted at `<scope>/...` regardless of `_mode`: "bucket" mode
    /// (a dedicated bucket + credential per tenant) is designed but not
    /// implemented at the backend, and honoring it as "no prefix" would collapse
    /// tenants into one namespace on the single configured bucket. Prefix
    /// scoping is the safe floor until per-tenant buckets exist.
    pub fn for_tenant(&self, _mode: &str, scope: &str) -> TenantBlobs {
        TenantBlobs {
            backend: self.backend.clone(),
            scope: scope.to_string(),
        }
    }
}

/// A blob handle pinned to one tenant's scope. Handlers get this from the resolver
/// and can only address bytes inside the tenant's scope.
#[derive(Clone)]
pub struct TenantBlobs {
    backend: Arc<Backend>,
    scope: String,
}

impl TenantBlobs {
    /// Root a tenant-relative key at this tenant's scope. In prefix mode the scope
    /// becomes a leading path segment (`<scope>/<key>`); in bucket mode the bucket
    /// itself is the boundary so the key is unchanged. Either way the result CANNOT
    /// escape the tenant: a `..` in `key` is rejected by the backend's safety check.
    pub fn scoped(&self, key: &str) -> String {
        // ALWAYS prefix-scope when a scope exists. "bucket" mode (a dedicated
        // bucket per tenant with its own credential) is designed but not
        // implemented at the backend, so treating it as unscoped here would
        // silently collapse every tenant into one namespace on the one
        // configured bucket; prefix scoping is the safe floor either way.
        if self.scope.is_empty() {
            key.to_string()
        } else {
            format!("{}/{}", self.scope.trim_matches('/'), key)
        }
    }

    /// Construct the final scoped key and REJECT it if it isn't a safe relative
    /// key (no traversal, no absolute path, no empty segments). Validating the
    /// FINAL key (after `scoped`) at this boundary means a future caller cannot
    /// accidentally introduce traversal even if the handler-level check is missed:
    /// the storage handle itself refuses to address anything outside the scope.
    fn safe_scoped(&self, key: &str) -> anyhow::Result<String> {
        let scoped = self.scoped(key);
        if !is_safe_key(&scoped) {
            anyhow::bail!("unsafe blob key rejected: {scoped:?}");
        }
        Ok(scoped)
    }

    pub async fn put(&self, key: &str, bytes: &[u8]) -> anyhow::Result<String> {
        self.backend
            .put(&self.scope, &self.safe_scoped(key)?, bytes)
            .await
    }

    // Consumed by the capture upload flow; hosted mounts no capture routes yet.
    #[allow(dead_code)]
    pub async fn put_path(
        &self,
        key: &str,
        path: &std::path::Path,
        content_type: &str,
    ) -> anyhow::Result<String> {
        self.backend
            .put_path(&self.scope, &self.safe_scoped(key)?, path, content_type)
            .await
    }

    pub async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        self.backend.get(&self.scope, &self.safe_scoped(key)?).await
    }

    pub async fn url_for(&self, key: &str) -> anyhow::Result<String> {
        self.backend
            .url_for(&self.scope, &self.safe_scoped(key)?)
            .await
    }

    pub async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.backend
            .delete(&self.scope, &self.safe_scoped(key)?)
            .await
    }
}

impl Backend {
    async fn put(&self, scope: &str, key: &str, bytes: &[u8]) -> anyhow::Result<String> {
        match self {
            Backend::Local(b) => b.put(scope, key, bytes).await,
            #[cfg(feature = "r2")]
            Backend::R2(b) => b.put(scope, key, bytes).await,
        }
    }
    // Consumed by the capture upload flow; hosted mounts no capture routes yet.
    #[allow(dead_code)]
    async fn put_path(
        &self,
        scope: &str,
        key: &str,
        path: &std::path::Path,
        content_type: &str,
    ) -> anyhow::Result<String> {
        match self {
            Backend::Local(b) => b.put_path(scope, key, path, content_type).await,
            #[cfg(feature = "r2")]
            Backend::R2(b) => b.put_path(scope, key, path, content_type).await,
        }
    }
    async fn get(&self, scope: &str, key: &str) -> anyhow::Result<Vec<u8>> {
        match self {
            Backend::Local(b) => b.get(scope, key).await,
            #[cfg(feature = "r2")]
            Backend::R2(b) => b.get(scope, key).await,
        }
    }
    async fn url_for(&self, scope: &str, key: &str) -> anyhow::Result<String> {
        match self {
            Backend::Local(b) => b.url_for(scope, key).await,
            #[cfg(feature = "r2")]
            Backend::R2(b) => b.url_for(scope, key).await,
        }
    }
    async fn delete(&self, scope: &str, key: &str) -> anyhow::Result<()> {
        match self {
            Backend::Local(b) => b.delete(scope, key).await,
            #[cfg(feature = "r2")]
            Backend::R2(b) => b.delete(scope, key).await,
        }
    }
    async fn delete_prefix(&self, prefix: &str) -> anyhow::Result<u64> {
        match self {
            Backend::Local(b) => b.delete_prefix(prefix).await,
            #[cfg(feature = "r2")]
            Backend::R2(b) => b.delete_prefix(prefix).await,
        }
    }
}

/// Local filesystem backend: writes under a root dir, serves via the cloud proxy.
pub struct LocalBackend {
    root: PathBuf,
}

impl BlobBackend for LocalBackend {
    // The scope is unused here: local isolation is the scoped key path itself
    // plus the blob proxy's safety check (there is no credential to bind).
    async fn put(&self, _scope: &str, key: &str, bytes: &[u8]) -> anyhow::Result<String> {
        let path = self.root.join(safe_key(key));
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).await?;
        }
        fs::write(&path, bytes).await?;
        Ok(format!("file://{}", path.display()))
    }
    // Consumed by the capture upload flow; hosted mounts no capture routes yet.
    #[allow(dead_code)]
    async fn put_path(
        &self,
        _scope: &str,
        key: &str,
        source: &std::path::Path,
        _content_type: &str,
    ) -> anyhow::Result<String> {
        let path = self.root.join(safe_key(key));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::copy(source, &path).await?;
        Ok(format!("file://{}", path.display()))
    }
    async fn get(&self, _scope: &str, key: &str) -> anyhow::Result<Vec<u8>> {
        Ok(fs::read(self.root.join(safe_key(key))).await?)
    }
    async fn url_for(&self, _scope: &str, key: &str) -> anyhow::Result<String> {
        Ok(format!("/v1/blob/{key}"))
    }
    async fn delete(&self, _scope: &str, key: &str) -> anyhow::Result<()> {
        match fs::remove_file(self.root.join(safe_key(key))).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    async fn delete_prefix(&self, prefix: &str) -> anyhow::Result<u64> {
        let dir = self.root.join(safe_key(prefix));
        match fs::remove_dir_all(&dir).await {
            // Cheap approximation: the local backend doesn't count files; 1
            // signals "something was removed", 0 "nothing existed".
            Ok(()) => Ok(1),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(feature = "r2")]
mod r2;
#[cfg(feature = "r2")]
pub use r2::R2Backend;

/// Trim a leading slash before a key touches the filesystem.
fn safe_key(key: &str) -> &str {
    key.trim_start_matches('/')
}

/// True when `key` is a safe relative key (no traversal, no absolute paths). Used
/// by the blob-proxy route to reject malicious keys.
pub fn is_safe_key(key: &str) -> bool {
    !key.is_empty()
        && !key.starts_with('/')
        && !key
            .split('/')
            .any(|seg| seg == ".." || seg == "." || seg.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_key_rejects_traversal_and_absolute() {
        assert!(is_safe_key("t/app/42/abc.mp4"));
        assert!(!is_safe_key("/etc/passwd"));
        assert!(!is_safe_key("app/../../etc/passwd"));
        assert!(!is_safe_key("app/./x"));
        assert!(!is_safe_key(""));
        assert!(!is_safe_key("app//x"));
    }

    #[test]
    fn prefix_scope_roots_keys_at_the_tenant_and_cannot_escape() {
        let blobs = Blobs {
            backend: Arc::new(Backend::Local(LocalBackend {
                root: PathBuf::from("/tmp/x"),
            })),
        };
        let t = blobs.for_tenant("prefix", "org-7");
        // A tenant-relative key is rooted at the tenant prefix.
        assert_eq!(t.scoped("acme/42/v.mp4"), "org-7/acme/42/v.mp4");
        // The other tenant gets a DIFFERENT prefix: the two key spaces are disjoint.
        let u = blobs.for_tenant("prefix", "org-9");
        assert_eq!(u.scoped("acme/42/v.mp4"), "org-9/acme/42/v.mp4");
        assert_ne!(t.scoped("k"), u.scoped("k"));
    }

    #[tokio::test]
    async fn put_get_url_for_reject_traversal_keys() {
        let dir = std::env::temp_dir().join(format!("reproit-blob-test-{}", std::process::id()));
        let blobs = Blobs {
            backend: Arc::new(Backend::Local(LocalBackend { root: dir })),
        };
        let t = blobs.for_tenant("prefix", "org-7");
        // A `..` segment escapes the scope: every op must refuse it, never touch
        // the backend, and surface the rejected final key.
        for bad in ["../../etc/passwd", "a/../../etc/passwd", "/abs", "a/./b"] {
            let put = t.put(bad, b"x").await;
            assert!(put.is_err(), "put accepted unsafe key {bad:?}");
            assert!(t.get(bad).await.is_err(), "get accepted unsafe key {bad:?}");
            assert!(
                t.url_for(bad).await.is_err(),
                "url_for accepted unsafe key {bad:?}"
            );
        }
        // A safe key still resolves through scoping (control: not over-rejecting).
        assert!(t.url_for("acme/42/v.mp4").await.is_ok());
    }

    #[test]
    fn bucket_mode_still_prefix_scopes_until_per_tenant_buckets_exist() {
        // "bucket" mode used to leave keys unscoped while the backend had only
        // ONE configured bucket, silently collapsing tenants into a shared
        // namespace. Until per-tenant buckets are real, every mode prefixes.
        let blobs = Blobs {
            backend: Arc::new(Backend::Local(LocalBackend {
                root: PathBuf::from("/tmp/x"),
            })),
        };
        let t = blobs.for_tenant("bucket", "tenant-bucket-7");
        assert_eq!(t.scoped("acme/42/v.mp4"), "tenant-bucket-7/acme/42/v.mp4");
    }
}
