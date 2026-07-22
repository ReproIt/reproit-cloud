//! Blob storage for one self-hosted installation.
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
//!   - [`R2Backend`] (feature `r2`): any S3-compatible bucket with short-lived
//!     presigned GET URLs and static installation credentials.

use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;

/// How long a presigned R2 GET url stays valid (1 hour).
#[cfg(feature = "r2")]
const PRESIGN_EXPIRY_SECS: u32 = 3600;

/// The provider-agnostic blob backend. Operations take the tenant's SCOPE (the
/// isolation boundary; a backend that binds storage-layer credentials uses it,
/// the local backend ignores it) plus a FULLY-SCOPED key (the tenant prefix is
/// already prepended by `TenantBlobs`), so a backend never sees an unscoped key
/// and cannot be tricked into crossing a tenant boundary.
#[allow(async_fn_in_trait)]
pub trait BlobBackend: Send + Sync {
    async fn put(&self, scope: &str, key: &str, bytes: &[u8]) -> anyhow::Result<String>;
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
    // Boxed to keep the local-fs default compact.
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
                tracing::info!("blobs: S3-compatible object storage backend");
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

/// S3-compatible object-storage backend (feature `r2`).
///
/// The historical `R2_*` variable names remain wire-compatible, but any
/// S3-compatible service can be selected with `R2_ENDPOINT`. This edition has
/// one installation namespace and never calls a provider control-plane API.
#[cfg(feature = "r2")]
pub struct R2Backend {
    store: object_store::aws::AmazonS3,
}

#[cfg(feature = "r2")]
const MAX_DELETE_PREFIX_OBJECTS: u64 = 100_000;

#[cfg(feature = "r2")]
impl R2Backend {
    /// Build from static S3-compatible credentials. `R2_ENDPOINT` selects a
    /// custom path-style service such as MinIO; without it, `R2_ACCOUNT_ID`
    /// selects Cloudflare R2.
    ///
    ///   - UNSET (the default, Cloudflare R2): the endpoint is derived from
    ///     `R2_ACCOUNT_ID` (required) as `https://{account}.r2.cloudflarestorage.com`
    ///     and virtual-host addressing is used, R2's native style.
    ///   - SET (a local MinIO or other R2-compatible store): `R2_ENDPOINT` is used
    ///     verbatim as the custom endpoint, `R2_ACCOUNT_ID` becomes OPTIONAL (MinIO
    ///     has none), and PATH-STYLE addressing is enabled (MinIO requires it, and
    ///     it points the same code at a local object store for dev/prod parity).
    ///
    /// `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, and `R2_BUCKET` are required in
    /// both shapes.
    ///
    fn from_env() -> Option<Self> {
        let (key, secret, bucket) = (
            std::env::var("R2_ACCESS_KEY_ID").ok()?,
            std::env::var("R2_SECRET_ACCESS_KEY").ok()?,
            std::env::var("R2_BUCKET").ok()?,
        );
        let (endpoint, virtual_hosted_style) = match std::env::var("R2_ENDPOINT").ok() {
            // Custom endpoint (local MinIO / any R2-compatible store): account id is
            // optional, path-style addressing is required.
            Some(endpoint) => (endpoint, false),
            // Default Cloudflare R2: derive the endpoint from the account id
            // (required) and use virtual-host addressing.
            None => {
                let account = std::env::var("R2_ACCOUNT_ID").ok()?;
                (format!("https://{account}.r2.cloudflarestorage.com"), true)
            }
        };
        let allow_http = endpoint.starts_with("http://");
        let store = object_store::aws::AmazonS3Builder::new()
            .with_region("auto")
            .with_bucket_name(bucket)
            .with_access_key_id(key)
            .with_secret_access_key(secret)
            .with_endpoint(endpoint)
            .with_virtual_hosted_style_request(virtual_hosted_style)
            .with_allow_http(allow_http)
            .build()
            .ok()?;
        Some(Self { store })
    }
}

#[cfg(feature = "r2")]
impl BlobBackend for R2Backend {
    async fn put(&self, _scope: &str, key: &str, bytes: &[u8]) -> anyhow::Result<String> {
        use object_store::ObjectStoreExt;
        let location = object_store::path::Path::from(key);
        self.store.put(&location, bytes.to_vec().into()).await?;
        Ok(format!("r2://{key}"))
    }
    async fn put_path(
        &self,
        _scope: &str,
        key: &str,
        path: &std::path::Path,
        content_type: &str,
    ) -> anyhow::Result<String> {
        use object_store::{Attribute, Attributes, ObjectStore};
        use tokio::io::AsyncWriteExt;
        let location = object_store::path::Path::from(key);
        let store: Arc<dyn ObjectStore> = Arc::new(self.store.clone());
        let attributes: Attributes = [(
            Attribute::ContentType,
            object_store::AttributeValue::from(content_type.to_string()),
        )]
        .into_iter()
        .collect();
        let mut writer =
            object_store::buffered::BufWriter::new(store, location).with_attributes(attributes);
        let mut source = fs::File::open(path).await?;
        tokio::io::copy(&mut source, &mut writer).await?;
        writer.shutdown().await?;
        Ok(format!("r2://{key}"))
    }
    async fn get(&self, _scope: &str, key: &str) -> anyhow::Result<Vec<u8>> {
        use object_store::ObjectStoreExt;
        let location = object_store::path::Path::from(key);
        Ok(self.store.get(&location).await?.bytes().await?.to_vec())
    }
    async fn url_for(&self, _scope: &str, key: &str) -> anyhow::Result<String> {
        use object_store::signer::Signer;
        let location = object_store::path::Path::from(key);
        Ok(self
            .store
            .signed_url(
                axum::http::Method::GET,
                &location,
                std::time::Duration::from_secs(PRESIGN_EXPIRY_SECS.into()),
            )
            .await?
            .to_string())
    }
    async fn delete(&self, _scope: &str, key: &str) -> anyhow::Result<()> {
        use object_store::ObjectStoreExt;
        // S3/R2 DELETE is idempotent: deleting a missing key answers 204.
        self.store
            .delete(&object_store::path::Path::from(key))
            .await?;
        Ok(())
    }
    async fn delete_prefix(&self, prefix: &str) -> anyhow::Result<u64> {
        use futures_util::StreamExt;
        use object_store::{ObjectStore, ObjectStoreExt};
        let mut removed = 0u64;
        let location = object_store::path::Path::from(format!("{prefix}/"));
        let mut objects = self.store.list(Some(&location));
        while let Some(object) = objects.next().await {
            if removed >= MAX_DELETE_PREFIX_OBJECTS {
                anyhow::bail!("object deletion exceeded {MAX_DELETE_PREFIX_OBJECTS} keys");
            }
            self.store.delete(&object?.location).await?;
            removed += 1;
        }
        Ok(removed)
    }
}

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
