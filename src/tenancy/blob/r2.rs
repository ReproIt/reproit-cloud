//! Cloudflare R2 / S3-compatible blob backend (feature `r2`), including the
//! per-tenant scoped-credential minter. Split from `blob.rs` so the shared
//! scoping/trait layer stays under the file-size cap; see that file's header
//! for the isolation model.

use super::BlobBackend;
use std::sync::Arc;
use tokio::fs;

/// Expiry for presigned GET urls handed to browsers.
const PRESIGN_EXPIRY_SECS: u32 = 3600;

/// Cloudflare R2 backend (feature `r2`).
///
/// Two isolation postures, selected by env at startup:
///   - MINTING (`R2_CREDS_API_TOKEN` set): every tenant operation runs under a
///     short-lived credential minted from Cloudflare's temp-access-credentials
///     API and bound to the tenant's key prefix. A minting failure FAILS the
///     operation; it never falls back to the parent credential, because a
///     deployment configured for scoped isolation must not silently degrade
///     to convention-only.
///   - CONVENTION-ONLY (minting env absent: self-host, MinIO): the one parent
///     credential is used for everything and isolation rests on the
///     `TenantBlobs` key scoping alone (warned once at startup).
pub struct R2Backend {
    /// The PARENT bucket handle carrying the process-wide credential. Every
    /// operation in convention-only mode uses it; in minting mode only
    /// `delete_prefix` (offboarding) does, an operator action rather than a
    /// tenant-request operation.
    store: object_store::aws::AmazonS3,
    bucket: String,
    endpoint: String,
    virtual_hosted_style: bool,
    /// Per-tenant scoped-credential minting + cache. None = convention-only.
    scoped: Option<ScopedCreds>,
}

/// How long a minted per-tenant credential lives at Cloudflare (2 hours)...
const SCOPED_CRED_TTL_SECS: u64 = 7200;

/// ...and the remaining life below which it is re-minted instead of reused. The
/// margin exceeds [`PRESIGN_EXPIRY_SECS`] (plus clock-skew slack) because a
/// presigned URL dies with the credential that signed it: no URL may be handed
/// out whose signing credential expires before the URL does.
const SCOPED_CRED_REFRESH_MARGIN_SECS: u64 = PRESIGN_EXPIRY_SECS as u64 + 300;

/// Upper bound on cached per-tenant credentials, mirroring the resolver's
/// mapping-cache bound (an entry is a key pair + session token per tenant).
const SCOPED_CRED_CACHE_MAX: usize = 8192;

const MAX_DELETE_PREFIX_OBJECTS: u64 = 100_000;

/// Cloudflare's REST API base. The minting endpoint lives HERE (the account
/// API), not on the R2-compatible object endpoint. Tests inject a local mock.
const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4";

/// One minted temporary credential, cached per tenant scope.
#[derive(Clone)]
struct MintedCred {
    access_key_id: String,
    secret_access_key: String,
    /// Rides as `X-Amz-Security-Token` on every request signed with this
    /// credential (a temporary credential is invalid without it).
    session_token: String,
    /// When Cloudflare expires this credential, measured locally from BEFORE
    /// the mint call so the local estimate never outlives R2's.
    expires_at: std::time::Instant,
}

impl MintedCred {
    /// Still safely reusable: enough life left that a presigned URL signed now
    /// outlives its own expiry (see [`SCOPED_CRED_REFRESH_MARGIN_SECS`]).
    fn is_fresh(&self) -> bool {
        self.expires_at
            .checked_duration_since(std::time::Instant::now())
            .is_some_and(|left| left.as_secs() > SCOPED_CRED_REFRESH_MARGIN_SECS)
    }
}

/// Mints per-tenant temporary R2 credentials via Cloudflare's
/// `POST /accounts/{id}/r2/temp-access-credentials`: an account-level API token
/// exchanges the parent access key for a short-lived S3-style credential bound
/// to a bucket + key prefix + TTL.
struct R2CredentialMinter {
    /// [`CLOUDFLARE_API`] in production; a local mock server in tests.
    api_base: String,
    account_id: String,
    /// The Cloudflare account API token authorized to mint R2 temporary access
    /// credentials (`R2_CREDS_API_TOKEN`). A Cloudflare API bearer token, NOT
    /// an S3-style key pair.
    api_token: String,
    /// The R2 access key id the temporary credential is derived from
    /// (`R2_ACCESS_KEY_ID`, the same parent key the bucket handle signs with).
    parent_access_key_id: String,
    bucket: String,
    client: reqwest::Client,
}

impl R2CredentialMinter {
    /// Mint one credential bound to `prefix` (empty = the whole bucket, the
    /// self-hosted single-tenant degenerate case). The caller owns caching and
    /// NEVER falls back to the parent credential on failure (fail closed).
    async fn mint(&self, prefix: &str) -> anyhow::Result<MintedCred> {
        // Timestamp BEFORE the call: the local expiry estimate must err early.
        let minted_at = std::time::Instant::now();
        let mut body = serde_json::json!({
            "bucket": self.bucket,
            "parentAccessKeyId": self.parent_access_key_id,
            "permission": "object-read-write",
            "ttlSeconds": SCOPED_CRED_TTL_SECS,
        });
        if !prefix.is_empty() {
            // Trailing slash: bind the credential to the tenant's SEGMENT, not
            // a string prefix ("t/4" must not also cover "t/42/...").
            body["prefixes"] = serde_json::json!([format!("{}/", prefix.trim_matches('/'))]);
        }
        let resp = self
            .client
            .post(format!(
                "{}/accounts/{}/r2/temp-access-credentials",
                self.api_base, self.account_id
            ))
            .bearer_auth(&self.api_token)
            .header("User-Agent", "reproit-cloud")
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        let v: serde_json::Value = resp.json().await.unwrap_or_default();
        if !status.is_success() || v["success"] != serde_json::Value::Bool(true) {
            anyhow::bail!(
                "r2 temp-credential mint for prefix {prefix:?} failed ({status}): {}",
                v["errors"]
            );
        }
        let field = |name: &str| -> anyhow::Result<String> {
            v["result"][name]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow::anyhow!("r2 temp-credential response missing {name}"))
        };
        Ok(MintedCred {
            access_key_id: field("accessKeyId")?,
            secret_access_key: field("secretAccessKey")?,
            session_token: field("sessionToken")?,
            expires_at: minted_at + std::time::Duration::from_secs(SCOPED_CRED_TTL_SECS),
        })
    }
}

/// The minter plus a TTL-aware per-scope cache: one minted credential serves a
/// tenant's operations until it nears expiry, so the Cloudflare API is called
/// about once per tenant per cache window, not per request.
struct ScopedCreds {
    minter: R2CredentialMinter,
    /// tenant scope -> live minted credential. The lock is NOT held across the
    /// mint call: two racing refreshes for one scope both succeed and the last
    /// write wins (both credentials are valid), which beats serializing every
    /// tenant's blob i/o behind one HTTP round trip.
    cache: tokio::sync::Mutex<std::collections::HashMap<String, MintedCred>>,
}

impl ScopedCreds {
    /// Built when `R2_CREDS_API_TOKEN` is set. Requested-but-unbuildable is a
    /// hard startup panic (same posture as REPROIT_TENANT_PROVIDER): running
    /// convention-only when the operator asked for scoped credentials would
    /// fake the isolation.
    fn from_env(bucket: &str, parent_access_key_id: &str) -> Option<Self> {
        let api_token = std::env::var("R2_CREDS_API_TOKEN")
            .ok()
            .filter(|v| !v.is_empty())?;
        let account_id = std::env::var("R2_ACCOUNT_ID")
            .ok()
            .filter(|v| !v.is_empty())
            .expect("R2_CREDS_API_TOKEN is set but R2_ACCOUNT_ID is not; minting scoped credentials needs the account id");
        Some(Self {
            minter: R2CredentialMinter {
                api_base: CLOUDFLARE_API.to_string(),
                account_id,
                api_token,
                parent_access_key_id: parent_access_key_id.to_string(),
                bucket: bucket.to_string(),
                client: reqwest::Client::new(),
            },
            cache: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// The live credential for a tenant scope: cached while fresh, re-minted
    /// inside the refresh margin. A mint failure is the caller's failure (fail
    /// closed); a stale cached entry is never reused in its place.
    async fn credentials_for(&self, scope: &str) -> anyhow::Result<MintedCred> {
        let scope = scope.trim_matches('/');
        if let Some(c) = self.cache.lock().await.get(scope) {
            if c.is_fresh() {
                return Ok(c.clone());
            }
        }
        let fresh = self.minter.mint(scope).await?;
        let mut cache = self.cache.lock().await;
        // Bound the map the way the resolver bounds its mapping cache: drop
        // stale entries first, then the soonest-expiring one if still full.
        if cache.len() >= SCOPED_CRED_CACHE_MAX && !cache.contains_key(scope) {
            cache.retain(|_, c| c.is_fresh());
            if cache.len() >= SCOPED_CRED_CACHE_MAX {
                if let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, c)| c.expires_at)
                    .map(|(k, _)| k.clone())
                {
                    cache.remove(&oldest);
                }
            }
        }
        cache.insert(scope.to_string(), fresh.clone());
        Ok(fresh)
    }
}

impl R2Backend {
    /// Build from env. Two shapes, selected by whether `R2_ENDPOINT` is set:
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
    /// Additionally, `R2_CREDS_API_TOKEN` (with `R2_ACCOUNT_ID`) enables
    /// per-tenant scoped-credential minting; without it isolation is
    /// convention-only (`Blobs::from_env` logs which).
    pub(super) fn from_env() -> Option<Self> {
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
        let scoped = ScopedCreds::from_env(&bucket, &key);
        let store = Self::store(
            &key,
            &secret,
            None,
            &bucket,
            &endpoint,
            virtual_hosted_style,
        )
        .expect("validated R2 object-store configuration must build");
        Some(Self {
            store,
            bucket,
            endpoint,
            virtual_hosted_style,
            scoped,
        })
    }

    fn store(
        access_key_id: &str,
        secret_access_key: &str,
        session_token: Option<&str>,
        bucket: &str,
        endpoint: &str,
        virtual_hosted_style: bool,
    ) -> anyhow::Result<object_store::aws::AmazonS3> {
        let mut builder = object_store::aws::AmazonS3Builder::new()
            .with_region("auto")
            .with_bucket_name(bucket)
            .with_access_key_id(access_key_id)
            .with_secret_access_key(secret_access_key)
            .with_endpoint(endpoint)
            .with_virtual_hosted_style_request(virtual_hosted_style)
            .with_allow_http(endpoint.starts_with("http://"));
        if let Some(token) = session_token {
            builder = builder.with_token(token);
        }
        Ok(builder.build()?)
    }

    /// Whether tenant operations run under minted per-tenant credentials (used
    /// by `Blobs::from_env` to log the isolation posture once at startup).
    pub(super) fn mints_scoped_credentials(&self) -> bool {
        self.scoped.is_some()
    }

    /// The bucket handle one tenant operation runs under. Convention-only mode
    /// answers the parent handle; minting mode builds a handle carrying the
    /// tenant's minted prefix-bound credential (cached, TTL-refreshed). A mint
    /// failure fails the operation and NEVER falls back to the parent
    /// credential: a deployment configured for scoped isolation must not
    /// silently degrade to convention-only.
    async fn store_for(&self, scope: &str) -> anyhow::Result<object_store::aws::AmazonS3> {
        let Some(scoped) = &self.scoped else {
            return Ok(self.store.clone());
        };
        let minted = scoped.credentials_for(scope).await?;
        Self::store(
            &minted.access_key_id,
            &minted.secret_access_key,
            Some(&minted.session_token),
            &self.bucket,
            &self.endpoint,
            self.virtual_hosted_style,
        )
    }
}

impl BlobBackend for R2Backend {
    async fn put(&self, scope: &str, key: &str, bytes: &[u8]) -> anyhow::Result<String> {
        use object_store::ObjectStoreExt;
        let store = self.store_for(scope).await?;
        store
            .put(&object_store::path::Path::from(key), bytes.to_vec().into())
            .await?;
        Ok(format!("r2://{key}"))
    }
    async fn put_path(
        &self,
        scope: &str,
        key: &str,
        path: &std::path::Path,
        content_type: &str,
    ) -> anyhow::Result<String> {
        use object_store::{Attribute, Attributes, ObjectStore};
        use tokio::io::AsyncWriteExt;
        let store = self.store_for(scope).await?;
        let location = object_store::path::Path::from(key);
        let attributes: Attributes = [(
            Attribute::ContentType,
            object_store::AttributeValue::from(content_type.to_string()),
        )]
        .into_iter()
        .collect();
        let store: Arc<dyn ObjectStore> = Arc::new(store);
        let mut writer =
            object_store::buffered::BufWriter::new(store, location).with_attributes(attributes);
        let mut source = fs::File::open(path).await?;
        tokio::io::copy(&mut source, &mut writer).await?;
        writer.shutdown().await?;
        Ok(format!("r2://{key}"))
    }
    async fn get(&self, scope: &str, key: &str) -> anyhow::Result<Vec<u8>> {
        use object_store::ObjectStoreExt;
        let store = self.store_for(scope).await?;
        Ok(store
            .get(&object_store::path::Path::from(key))
            .await?
            .bytes()
            .await?
            .to_vec())
    }
    async fn url_for(&self, scope: &str, key: &str) -> anyhow::Result<String> {
        // Signed with the tenant's scoped credential when minting is on: the
        // URL then carries the session token and cannot be edited to name a
        // key outside the tenant prefix (the credential has no authority there).
        use object_store::signer::Signer;
        let store = self.store_for(scope).await?;
        Ok(store
            .signed_url(
                axum::http::Method::GET,
                &object_store::path::Path::from(key),
                std::time::Duration::from_secs(PRESIGN_EXPIRY_SECS.into()),
            )
            .await?
            .to_string())
    }
    async fn delete(&self, scope: &str, key: &str) -> anyhow::Result<()> {
        use object_store::ObjectStoreExt;
        // S3/R2 DELETE is idempotent: deleting a missing key answers 204.
        self.store_for(scope)
            .await?
            .delete(&object_store::path::Path::from(key))
            .await?;
        Ok(())
    }
    async fn delete_prefix(&self, prefix: &str) -> anyhow::Result<u64> {
        use futures_util::StreamExt;
        use object_store::{ObjectStore, ObjectStoreExt};
        // Offboarding is an OPERATOR action on the whole scope, not a
        // tenant-request operation, so it runs under the parent credential
        // (whose bucket-wide authority is exactly what deleting a scope needs).
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

/// Scoped-credential minting/caching tests against a LOCAL mock of Cloudflare's
/// temp-access-credentials endpoint (the same mock-server shape the GitHub
/// tracker tests use). No real Cloudflare call is ever made.
#[cfg(test)]
mod r2_scoped_creds_tests {
    use super::*;
    use axum::{
        extract::{Path, State},
        routing::post,
        Json, Router,
    };
    use std::sync::{Arc, Mutex};

    /// Everything the mock Cloudflare API recorded, so tests assert on exactly
    /// the requests that would hit the real minting endpoint.
    #[derive(Default)]
    struct Recorded {
        accounts: Vec<String>,
        auths: Vec<String>,
        bodies: Vec<serde_json::Value>,
    }

    type Shared = Arc<Mutex<Recorded>>;

    /// Spin up a local mock of `POST /accounts/{id}/r2/temp-access-credentials`
    /// on an ephemeral port. Each successful mint answers a DISTINCT
    /// `accessKeyId` ("minted-<n>") so a re-mint is observable; `ok=false`
    /// makes every call fail Cloudflare-style (`success: false`).
    async fn mock_cloudflare(ok: bool) -> (String, Shared) {
        let rec: Shared = Arc::new(Mutex::new(Recorded::default()));
        let app = Router::new()
            .route(
                "/accounts/:account/r2/temp-access-credentials",
                post(
                    move |Path(account): Path<String>,
                          State(rec): State<Shared>,
                          headers: axum::http::HeaderMap,
                          Json(b): Json<serde_json::Value>| async move {
                        let mut r = rec.lock().unwrap();
                        r.accounts.push(account);
                        r.auths.push(
                            headers
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string(),
                        );
                        r.bodies.push(b);
                        let n = r.bodies.len();
                        if ok {
                            Json(serde_json::json!({
                                "success": true,
                                "result": {
                                    "accessKeyId": format!("minted-{n}"),
                                    "secretAccessKey": "sk-temp",
                                    "sessionToken": "tok-temp"
                                }
                            }))
                        } else {
                            Json(serde_json::json!({
                                "success": false,
                                "errors": [{ "code": 10000, "message": "denied" }]
                            }))
                        }
                    },
                ),
            )
            .with_state(rec.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (base, rec)
    }

    /// A `ScopedCreds` pointed at the mock, with the field values the env would
    /// normally supply.
    fn scoped_creds(api_base: String) -> ScopedCreds {
        ScopedCreds {
            minter: R2CredentialMinter {
                api_base,
                account_id: "acct-1".into(),
                api_token: "cf-token".into(),
                parent_access_key_id: "parent-key".into(),
                bucket: "reproit-evidence".into(),
                client: reqwest::Client::new(),
            },
            cache: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    #[tokio::test]
    async fn mint_binds_the_tenant_prefix_and_parses_the_credential() {
        let (base, rec) = mock_cloudflare(true).await;
        let sc = scoped_creds(base);
        let cred = sc.credentials_for("t/42").await.unwrap();
        assert_eq!(cred.access_key_id, "minted-1");
        assert_eq!(cred.secret_access_key, "sk-temp");
        assert_eq!(cred.session_token, "tok-temp");
        assert!(cred.is_fresh(), "a just-minted credential must be fresh");

        let r = rec.lock().unwrap();
        // Routed to the configured account with the Cloudflare bearer token.
        assert_eq!(r.accounts, vec!["acct-1"]);
        assert_eq!(r.auths, vec!["Bearer cf-token"]);
        // The body carries the exact minting contract: parent key, object-level
        // permission, the TTL, and the tenant prefix WITH its trailing slash
        // ("t/4" must never also cover "t/42/...").
        let b = &r.bodies[0];
        assert_eq!(b["bucket"], "reproit-evidence");
        assert_eq!(b["parentAccessKeyId"], "parent-key");
        assert_eq!(b["permission"], "object-read-write");
        assert_eq!(b["ttlSeconds"], SCOPED_CRED_TTL_SECS);
        assert_eq!(b["prefixes"], serde_json::json!(["t/42/"]));
    }

    #[tokio::test]
    async fn empty_scope_mints_a_bucket_wide_credential() {
        // Self-hosted single tenant: the scope is "" and the bucket itself is
        // the boundary, so the mint carries NO prefixes restriction.
        let (base, rec) = mock_cloudflare(true).await;
        let sc = scoped_creds(base);
        sc.credentials_for("").await.unwrap();
        let r = rec.lock().unwrap();
        assert!(r.bodies[0].get("prefixes").is_none());
    }

    #[tokio::test]
    async fn cache_serves_repeats_and_refreshes_inside_the_margin() {
        let (base, rec) = mock_cloudflare(true).await;
        let sc = scoped_creds(base);

        // Repeat ops for one tenant reuse the cached credential: one mint call.
        let a = sc.credentials_for("t/7").await.unwrap();
        let b = sc.credentials_for("t/7").await.unwrap();
        assert_eq!(a.access_key_id, b.access_key_id);
        assert_eq!(rec.lock().unwrap().bodies.len(), 1);

        // A different tenant is a different cache entry AND a different
        // credential (the whole point of scoping).
        let c = sc.credentials_for("t/8").await.unwrap();
        assert_ne!(c.access_key_id, a.access_key_id);
        assert_eq!(rec.lock().unwrap().bodies.len(), 2);

        // Age t/7's entry into the refresh margin: the next call re-mints
        // instead of handing out a credential a presigned URL could outlive.
        sc.cache.lock().await.get_mut("t/7").unwrap().expires_at = std::time::Instant::now();
        let d = sc.credentials_for("t/7").await.unwrap();
        assert_ne!(d.access_key_id, a.access_key_id);
        assert_eq!(rec.lock().unwrap().bodies.len(), 3);
    }

    #[tokio::test]
    async fn mint_failure_fails_closed() {
        let (base, _rec) = mock_cloudflare(false).await;
        let sc = scoped_creds(base);

        // A failed mint is the operation's failure... (`MintedCred` is
        // deliberately not Debug, so no unwrap_err: a credential must never
        // have a debug-printable path into logs.)
        let err = match sc.credentials_for("t/9").await {
            Ok(_) => panic!("mint against a denying API must fail closed"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("failed"), "unexpected error: {err}");
        // ...and nothing bogus lands in the cache.
        assert!(sc.cache.lock().await.is_empty());

        // Even with a STALE cached entry present, a failed refresh is an error,
        // never a silent reuse of a credential that a presigned URL (or the
        // request itself) could outlive.
        sc.cache.lock().await.insert(
            "t/9".to_string(),
            MintedCred {
                access_key_id: "stale".into(),
                secret_access_key: "stale".into(),
                session_token: "stale".into(),
                expires_at: std::time::Instant::now(),
            },
        );
        assert!(sc.credentials_for("t/9").await.is_err());
    }

    #[tokio::test]
    #[ignore = "requires a disposable live R2 bucket and production-validation credentials"]
    async fn live_r2_credentials_enforce_two_tenant_isolation() {
        use object_store::ObjectStoreExt;

        let backend = R2Backend::from_env()
            .expect("R2 credentials must be set for the explicit production provider gate");
        assert!(
            backend.mints_scoped_credentials(),
            "R2_CREDS_API_TOKEN must enable prefix-scoped credentials"
        );

        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let scope_a = format!("t/release-gate-{nonce}-a");
        let scope_b = format!("t/release-gate-{nonce}-b");
        let key_a = object_store::path::Path::from(format!("{scope_a}/probe"));
        let key_b = object_store::path::Path::from(format!("{scope_b}/probe"));
        let store_a = backend.store_for(&scope_a).await.unwrap();
        let store_b = backend.store_for(&scope_b).await.unwrap();

        let result = async {
            store_a.put(&key_a, b"tenant-a".to_vec().into()).await?;
            store_b.put(&key_b, b"tenant-b".to_vec().into()).await?;
            anyhow::ensure!(
                store_a.get(&key_b).await.is_err(),
                "tenant A credential read tenant B's object"
            );
            anyhow::ensure!(
                store_b.get(&key_a).await.is_err(),
                "tenant B credential read tenant A's object"
            );
            anyhow::ensure!(
                store_a
                    .put(&key_b, b"escape".to_vec().into())
                    .await
                    .is_err(),
                "tenant A credential wrote into tenant B's prefix"
            );
            anyhow::ensure!(
                store_b
                    .put(&key_a, b"escape".to_vec().into())
                    .await
                    .is_err(),
                "tenant B credential wrote into tenant A's prefix"
            );
            anyhow::Ok(())
        }
        .await;

        let cleanup_a = backend.store.delete(&key_a).await;
        let cleanup_b = backend.store.delete(&key_b).await;
        result.expect("live R2 isolation checks");
        cleanup_a.expect("remove tenant A gate object");
        cleanup_b.expect("remove tenant B gate object");
    }
}
