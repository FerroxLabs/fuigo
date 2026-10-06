//! Shared upload utilities for session persistence and agent telemetry.
//!
//! This module provides a unified interface for uploading bytes to cloud storage,
//! supporting direct upload (via service account), proxy upload (via cli-chat-proxy),
//! and S3-compatible backends.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;

use crate::UploadMethod;
use fuigo_auth::{AuthCredentialProvider, StaticAuthCredentialProvider};

use crate::storage_client::{Auth401AttributionCallback, StaticFuigoAuth, StorageClient};

/// Threshold for switching to multipart upload (50 MB).
///
/// Files larger than this use `StorageClient::upload_multipart()` (signed URLs,
/// parts uploaded directly to cloud storage) instead of streaming through the proxy.
pub const MULTIPART_UPLOAD_THRESHOLD: u64 = 50 * 1024 * 1024;

/// Construct a `StorageClient` for proxy-mode uploads. Uses the caller-provided
/// refresh-aware credentials when present, otherwise falls back to a
/// `StaticFuigoAuth` carrying the inline user / deployment keys from
/// `UploadMethod::Proxy`. The optional `http_client` lets the caller pass a
/// shell-tuned client (HTTP/2 keep-alive, conn pool tuning); when `None` we
/// fall back to the shared TLS/redirect-policy builder.
fn build_proxy_client_with_fallback(
    proxy_base_url: &str,
    user_token: &str,
    deployment_key: Option<String>,
    credentials: Option<Arc<dyn AuthCredentialProvider>>,
    attribution: Option<Arc<dyn Auth401AttributionCallback>>,
    http_client: Option<reqwest::Client>,
) -> StorageClient {
    let provider = credentials.unwrap_or_else(|| {
        let mut creds = StaticFuigoAuth::new(Some(user_token.to_owned()));
        creds.deployment_key = deployment_key;
        let bearer = creds.wire_bearer();
        let destination = creds.bearer_destination(proxy_base_url);
        Arc::new(StaticAuthCredentialProvider::new(
            Box::new(creds),
            bearer,
            destination,
        ))
    });
    let http_client = http_client.unwrap_or_else(|| {
        fuigo_extra_ca::build_reqwest_client(|builder| builder)
            .expect("failed to build storage HTTP client")
    });
    let mut client = StorageClient::with_provider(proxy_base_url, http_client, provider);
    if let Some(cb) = attribution {
        client = client.with_attribution(cb);
    }
    client
}

/// Implement `StorageConfig` for `TraceExportConfig`. Lives here (alongside the
/// trait + upload helpers) so callers can use the shared upload helpers without
/// a foreign-trait impl. Refresh-aware callers still get credential /
/// attribution wiring via `TraceExportConfigWithAuth` (in shell).
impl StorageConfig for crate::TraceExportConfig {
    fn bucket_url(&self) -> &str {
        // For proxy mode, bucket_url may be None (proxy determines it from ACLs).
        // Return a placeholder that won't be used.
        self.bucket_url.as_deref().unwrap_or("gs://placeholder")
    }

    fn upload_method(&self) -> &UploadMethod {
        &self.upload_method
    }
}

/// A trait for storage configuration that provides bucket URL and upload method.
/// This allows different config types (TraceExportConfig, etc.) to share upload logic.
pub trait StorageConfig {
    fn bucket_url(&self) -> &str;
    fn upload_method(&self) -> &UploadMethod;
    /// Optional refresh-aware credentials for proxy-mode uploads. When
    /// `Some(_)`, `upload_*_via_proxy` helpers construct a `StorageClient`
    /// via `StorageClient::with_provider(...)` so 401 retries can request
    /// a token refresh. Default `None` for configs that ship a static
    /// user-token only.
    fn proxy_credentials(&self) -> Option<Arc<dyn AuthCredentialProvider>> {
        None
    }
    /// Optional 401-attribution callback. When `Some(_)`, the constructed
    /// `StorageClient` also calls `with_attribution(...)` so the embedding
    /// application records auth-attribution telemetry for proxy 401s.
    fn proxy_attribution(&self) -> Option<Arc<dyn Auth401AttributionCallback>> {
        None
    }
    /// Optional HTTP client for proxy-mode uploads. `None` falls back to
    /// the shared TLS/redirect-policy builder (used by bins/tests). Production callers
    /// should return shell's tuned `shared_upload_client()` -- HTTP/2
    /// keep-alive + aggressive connection pool eviction. The trace upload
    /// queue, feedback uploads, share uploads, and subagent metadata
    /// uploads all rely on this tuning to avoid stale-connection retries
    /// during backoff loops.
    fn proxy_http_client(&self) -> Option<reqwest::Client> {
        None
    }
}

/// Uploads bytes to cloud storage at the specified path.
/// Returns the full storage URL on success.
/// Dispatches to direct, proxy, or S3 backend based on config.
pub async fn upload_bytes<C: StorageConfig>(
    config: &C,
    object_path: &str,
    content: &[u8],
    content_type: &str,
) -> anyhow::Result<String> {
    // P149: text leaves the machine through the process's upload filter (see `payload_filter`).
    let filtered = crate::payload_filter::apply(content, content_type);
    let content: &[u8] = &filtered;
    match config.upload_method() {
        UploadMethod::Direct {
            service_account_key,
        } => {
            // Parse the bucket URL to extract bucket name (required for direct mode)
            let url = url::Url::parse(config.bucket_url())
                .with_context(|| format!("Invalid GCS URL: {}", config.bucket_url()))?;

            if url.scheme() != "gs" {
                anyhow::bail!(
                    "Invalid GCS URL scheme: expected 'gs', got '{}'",
                    url.scheme()
                );
            }

            let bucket = url
                .host_str()
                .context("GCS URL must have a bucket name")?
                .to_string();

            upload_bytes_direct(
                &bucket,
                object_path,
                content,
                content_type,
                service_account_key.as_deref(),
            )
            .await
        }
        UploadMethod::Proxy {
            proxy_base_url,
            user_token,
            deployment_key,
            alpha_test_key: _,
        } => {
            // For proxy mode, bucket is determined by proxy from user ACLs
            tracing::debug!(
                proxy_base_url = %proxy_base_url,
                object_path = %object_path,
                "Uploading bytes to GCS via proxy (bucket determined by proxy from ACLs)"
            );
            upload_bytes_via_proxy(
                proxy_base_url,
                user_token,
                deployment_key.as_deref(),
                object_path,
                content,
                content_type,
                config.proxy_credentials(),
                config.proxy_attribution(),
                config.proxy_http_client(),
            )
            .await
        }
        UploadMethod::S3 {
            bucket,
            region,
            credentials_file,
            credentials_content,
            endpoint_url,
        } => {
            crate::s3::upload_bytes(
                bucket,
                object_path,
                content,
                content_type,
                region,
                credentials_content.as_deref(),
                credentials_file.as_deref(),
                endpoint_url.as_deref(),
            )
            .await
        }
    }
}

/// Like [`upload_bytes`], but in proxy mode uses a pre-signed PUT URL
/// so the data goes directly to storage instead of through the proxy.
///
/// This avoids the nginx `proxy-body-size: 4m` limit on the HTTP ingress and
/// the Cloudflare 100 MB limit, making it safe for arbitrarily large payloads
/// (e.g. session share data).
///
/// In direct mode this is identical to `upload_bytes` (the service
/// account already talks to storage directly).
pub async fn upload_bytes_signed<C: StorageConfig>(
    config: &C,
    object_path: &str,
    content: &[u8],
    content_type: &str,
) -> anyhow::Result<String> {
    // P149: text leaves the machine through the process's upload filter (see `payload_filter`).
    let filtered = crate::payload_filter::apply(content, content_type);
    let content: &[u8] = &filtered;
    match config.upload_method() {
        UploadMethod::Direct { .. } => {
            // Direct mode already bypasses the proxy — reuse the existing path.
            upload_bytes(config, object_path, content, content_type).await
        }
        UploadMethod::Proxy {
            proxy_base_url,
            user_token,
            deployment_key,
            alpha_test_key: _,
        } => {
            tracing::debug!(
                proxy_base_url = %proxy_base_url,
                object_path = %object_path,
                bytes = content.len(),
                "Uploading bytes to GCS via signed URL (bypasses proxy body limits)"
            );
            upload_bytes_via_signed_url(
                proxy_base_url,
                user_token,
                deployment_key.as_deref(),
                object_path,
                content,
                content_type,
                config.proxy_credentials(),
                config.proxy_attribution(),
                config.proxy_http_client(),
            )
            .await
        }
        UploadMethod::S3 { .. } => upload_bytes(config, object_path, content, content_type).await,
    }
}

/// Uploads a file to cloud storage by streaming from disk.
///
/// Preferred over `upload_bytes` for the background upload queue because:
/// - Never loads the full file into memory (critical for multi-GB dedup blobs)
/// - For Proxy mode with large files (>50 MB), uses signed-URL multipart upload
///   so data travels directly to storage, bypassing the proxy's body size limits
/// - For Proxy mode with small files, uses `StorageClient::upload_file()` (streaming)
/// - For Direct mode, streams via the gcloud-storage crate
pub async fn upload_file<C: StorageConfig>(
    config: &C,
    object_path: &str,
    file_path: &Path,
    content_type: &str,
) -> anyhow::Result<String> {
    // P149: a text file the process's upload filter changes is sent as a filtered copy (same routing: multipart
    // above the threshold); the file itself is untouched.
    let copy = crate::payload_filter::filtered_copy(file_path, content_type)
        .with_context(|| format!("read {} for upload", file_path.display()))?;
    let file_path = copy.as_ref().map_or(file_path, |c| c.path());
    match config.upload_method() {
        UploadMethod::Direct {
            service_account_key,
        } => {
            let bucket_url = config.bucket_url();
            let url = url::Url::parse(bucket_url)
                .with_context(|| format!("Invalid GCS URL: {}", bucket_url))?;
            if url.scheme() != "gs" {
                anyhow::bail!(
                    "Invalid GCS URL scheme: expected 'gs', got '{}'",
                    url.scheme()
                );
            }
            let bucket = url
                .host_str()
                .context("GCS URL must have a bucket name")?
                .to_string();
            upload_file_direct(
                &bucket,
                object_path,
                file_path,
                content_type,
                service_account_key.as_deref(),
            )
            .await
        }
        UploadMethod::Proxy {
            proxy_base_url,
            user_token,
            deployment_key,
            alpha_test_key: _,
        } => {
            upload_file_via_proxy(
                proxy_base_url,
                user_token,
                deployment_key.as_deref(),
                object_path,
                file_path,
                content_type,
                config.proxy_credentials(),
                config.proxy_attribution(),
                config.proxy_http_client(),
            )
            .await
        }
        UploadMethod::S3 {
            bucket,
            region,
            credentials_file,
            credentials_content,
            endpoint_url,
        } => {
            crate::s3::upload_file(
                bucket,
                object_path,
                file_path,
                content_type,
                region,
                credentials_content.as_deref(),
                credentials_file.as_deref(),
                endpoint_url.as_deref(),
            )
            .await
        }
    }
}

/// Uploads an async reader to cloud storage, dispatching to the appropriate backend.
///
/// Used for streaming compressed uploads where the reader is consumed once per attempt.
/// Callers handle retries by recreating the reader.
pub async fn upload_stream<C: StorageConfig, R>(
    config: &C,
    object_path: &str,
    reader: R,
    content_type: &str,
) -> anyhow::Result<String>
where
    R: tokio::io::AsyncRead + Send + Sync + 'static,
{
    match config.upload_method() {
        UploadMethod::Direct {
            service_account_key,
        } => {
            let bucket_url = config.bucket_url();
            let url = url::Url::parse(bucket_url)
                .with_context(|| format!("Invalid GCS URL: {}", bucket_url))?;
            if url.scheme() != "gs" {
                anyhow::bail!(
                    "Invalid GCS URL scheme: expected 'gs', got '{}'",
                    url.scheme()
                );
            }
            let bucket = url
                .host_str()
                .context("GCS URL must have a bucket name")?
                .to_string();
            upload_stream_direct(
                &bucket,
                object_path,
                reader,
                content_type,
                service_account_key.as_deref(),
            )
            .await
        }
        UploadMethod::Proxy {
            proxy_base_url,
            user_token,
            deployment_key,
            alpha_test_key: _,
        } => {
            let storage_client = build_proxy_client_with_fallback(
                proxy_base_url,
                user_token,
                deployment_key.as_deref().map(|s| s.to_owned()),
                config.proxy_credentials(),
                config.proxy_attribution(),
                config.proxy_http_client(),
            );
            let response = storage_client
                .upload_stream(object_path, reader, content_type)
                .await
                .with_context(|| format!("Streaming upload failed for {}", object_path))?;
            Ok(format!("gs://{}/{}", response.bucket, response.path))
        }
        UploadMethod::S3 {
            bucket,
            region,
            credentials_file,
            credentials_content,
            endpoint_url,
        } => {
            crate::s3::upload_stream(
                bucket,
                object_path,
                reader,
                content_type,
                region,
                credentials_content.as_deref(),
                credentials_file.as_deref(),
                endpoint_url.as_deref(),
            )
            .await
        }
    }
}

/// Stream an async reader directly to GCS via the gcloud-storage client.
async fn upload_stream_direct<R: tokio::io::AsyncRead + Send + Sync + 'static>(
    bucket: &str,
    object_path: &str,
    reader: R,
    content_type: &str,
    service_account_key: Option<&str>,
) -> anyhow::Result<String> {
    use gcloud_storage::http::objects::upload::{Media, UploadObjectRequest, UploadType};
    use tokio_util::io::ReaderStream;

    let client = build_gcs_client(service_account_key).await?;
    let stream = ReaderStream::new(reader);

    let mut media = Media::new(object_path.to_string());
    media.content_type = content_type.to_owned().into();
    let upload_type = UploadType::Simple(media);
    let request = UploadObjectRequest {
        bucket: bucket.to_string(),
        ..Default::default()
    };
    client
        .upload_streamed_object(&request, stream, &upload_type)
        .await
        .with_context(|| format!("Failed to upload to gs://{}/{}", bucket, object_path))?;

    Ok(format!("gs://{}/{}", bucket, object_path))
}

/// Upload a file through the cli-chat-proxy, choosing multipart vs streaming based on size.
///
/// Files > `MULTIPART_UPLOAD_THRESHOLD` use signed-URL multipart upload (parts go
/// directly to cloud storage, not through the proxy HTTP body). This avoids the proxy's request
/// body size limit and the timeout issues that cause 55% of upload failures for large
/// dedup blobs.
async fn upload_file_via_proxy(
    proxy_base_url: &str,
    user_token: &str,
    deployment_key: Option<&str>,
    object_path: &str,
    file_path: &Path,
    content_type: &str,
    credentials: Option<Arc<dyn AuthCredentialProvider>>,
    attribution: Option<Arc<dyn Auth401AttributionCallback>>,
    http_client: Option<reqwest::Client>,
) -> anyhow::Result<String> {
    use crate::storage_client::{MultipartUploadOptions, RetryConfig};

    let storage_client = build_proxy_client_with_fallback(
        proxy_base_url,
        user_token,
        deployment_key.map(|s| s.to_owned()),
        credentials,
        attribution,
        http_client,
    )
    .with_retry_config(RetryConfig::conservative());

    let file_size = tokio::fs::metadata(file_path)
        .await
        .with_context(|| format!("Failed to get file metadata: {}", file_path.display()))?
        .len();

    if file_size > MULTIPART_UPLOAD_THRESHOLD {
        // Large file: upload directly to cloud storage via signed URLs (bypasses proxy body)
        tracing::info!(
            file_size,
            threshold = MULTIPART_UPLOAD_THRESHOLD,
            upload_method = "multipart",
            path = %file_path.display(),
            "Upload queue: using multipart for large file"
        );
        let options = MultipartUploadOptions::new().with_max_concurrent(4);
        let response = storage_client
            .upload_multipart(object_path, file_path, content_type, Some(options))
            .await
            .with_context(|| format!("Multipart upload failed for {}", object_path))?;
        Ok(response.gcs_url)
    } else {
        // Small file: stream through proxy (no memory copy)
        tracing::debug!(
            file_size,
            upload_method = "streaming",
            path = %file_path.display(),
            "Upload queue: using streaming for small file"
        );
        let response = storage_client
            .upload_file(object_path, file_path, content_type)
            .await
            .with_context(|| format!("Streaming upload failed for {}", object_path))?;
        Ok(format!("gs://{}/{}", response.bucket, response.path))
    }
}

/// Build a GCS client with optional service account key, or default ADC.
async fn build_gcs_client(
    service_account_key: Option<&str>,
) -> anyhow::Result<gcloud_storage::client::Client> {
    use gcloud_storage::client::{Client as GcsClient, ClientConfig as GcsClientConfig};

    crate::gcs_http_policy::install_auth_policy()?;

    // Protect storage/IAM requests. gcloud-auth's separate token-source HTTP
    // clients are not controlled by this field and require a separate adapter.
    let config = GcsClientConfig {
        http: Some(crate::gcs_http_policy::client()?),
        ..GcsClientConfig::default()
    };

    let gcs_config = if let Some(key_json) = service_account_key {
        config
            .with_credentials(
                gcloud_storage::client::google_cloud_auth::credentials::CredentialsFile::new_from_str(key_json)
                    .await
                    .context("Failed to parse service account key")?,
            )
            .await
            .context("Failed to configure GCS client with service account")?
    } else {
        config
            .with_auth()
            .await
            .context("Failed to authenticate GCS client")?
    };

    Ok(GcsClient::new(gcs_config))
}

/// Upload a file directly to GCS by streaming from disk.
async fn upload_file_direct(
    bucket: &str,
    object_path: &str,
    file_path: &Path,
    content_type: &str,
    service_account_key: Option<&str>,
) -> anyhow::Result<String> {
    use gcloud_storage::http::objects::upload::{Media, UploadObjectRequest, UploadType};
    use tokio::fs::File as TokioFile;
    use tokio_util::io::ReaderStream;

    let client = build_gcs_client(service_account_key).await?;

    let file = TokioFile::open(file_path)
        .await
        .with_context(|| format!("Failed to open file: {}", file_path.display()))?;
    // ReaderStream<TokioFile> yields io::Result<Bytes>; io::Error satisfies
    // upload_streamed_object's S::Error: Into<Box<dyn Error + Send + Sync>> bound directly.
    let stream = ReaderStream::new(file);

    let mut media = Media::new(object_path.to_string());
    media.content_type = content_type.to_owned().into();
    let upload_type = UploadType::Simple(media);
    let request = UploadObjectRequest {
        bucket: bucket.to_string(),
        ..Default::default()
    };
    client
        .upload_streamed_object(&request, stream, &upload_type)
        .await
        .with_context(|| format!("Failed to upload to gs://{}/{}", bucket, object_path))?;

    Ok(format!("gs://{}/{}", bucket, object_path))
}

/// Uploads bytes directly to GCS using the gcloud-storage client.
async fn upload_bytes_direct(
    bucket: &str,
    object_path: &str,
    content: &[u8],
    content_type: &str,
    service_account_key: Option<&str>,
) -> anyhow::Result<String> {
    use gcloud_storage::http::objects::upload::{Media, UploadObjectRequest, UploadType};

    let client = build_gcs_client(service_account_key).await?;

    let mut media = Media::new(object_path.to_string());
    media.content_type = content_type.to_owned().into();
    let upload_type = UploadType::Simple(media);
    let request = UploadObjectRequest {
        bucket: bucket.to_string(),
        ..Default::default()
    };

    client
        .upload_object(&request, content.to_vec(), &upload_type)
        .await
        .with_context(|| format!("Failed to upload to gs://{}/{}", bucket, object_path))?;

    // Return the full GCS URL
    Ok(format!("gs://{}/{}", bucket, object_path))
}

/// Uploads bytes via the cli-chat-proxy storage proxy API.
/// The bucket is determined by the proxy based on the user's ACLs.
async fn upload_bytes_via_proxy(
    proxy_base_url: &str,
    user_token: &str,
    deployment_key: Option<&str>,
    object_path: &str,
    content: &[u8],
    content_type: &str,
    credentials: Option<Arc<dyn AuthCredentialProvider>>,
    attribution: Option<Arc<dyn Auth401AttributionCallback>>,
    http_client: Option<reqwest::Client>,
) -> anyhow::Result<String> {
    use crate::storage_client::RetryConfig;

    // Conservative retry config handles storage-backend 429 errors during autoscaling.
    let storage_client = build_proxy_client_with_fallback(
        proxy_base_url,
        user_token,
        deployment_key.map(|s| s.to_owned()),
        credentials,
        attribution,
        http_client,
    )
    .with_retry_config(RetryConfig::conservative());

    let response = storage_client
        .upload(object_path, content, content_type)
        .await
        .with_context(|| {
            // P149 (S12): the proxy by location only; a base URL can carry a password or a query secret.
            format!(
                "Failed to upload to storage proxy: {} (path: {})",
                fuigo_auth::redact_url(proxy_base_url),
                object_path
            )
        })?;

    // Return the full GCS URL
    Ok(format!("gs://{}/{}", response.bucket, response.path))
}

/// Uploads bytes to cloud storage via a pre-signed PUT URL obtained from the proxy.
///
/// This completely bypasses the proxy for the data transfer, avoiding
/// nginx / Cloudflare body-size limits.  The proxy is only contacted
/// once (to generate the signed URL), after which the bytes go straight
/// to cloud storage.
///
/// Use this when the payload may exceed 4 MB (the nginx `proxy-body-size`
/// on the HTTP ingress) — e.g. session share data.
pub async fn upload_bytes_via_signed_url(
    proxy_base_url: &str,
    user_token: &str,
    deployment_key: Option<&str>,
    object_path: &str,
    content: &[u8],
    content_type: &str,
    credentials: Option<Arc<dyn AuthCredentialProvider>>,
    attribution: Option<Arc<dyn Auth401AttributionCallback>>,
    http_client: Option<reqwest::Client>,
) -> anyhow::Result<String> {
    let storage_client = build_proxy_client_with_fallback(
        proxy_base_url,
        user_token,
        deployment_key.map(|s| s.to_owned()),
        credentials,
        attribution,
        http_client,
    );

    let signed = storage_client
        .upload_bytes_signed(object_path, content, content_type)
        .await
        .with_context(|| {
            format!(
                "Failed to upload via signed URL: {} (path: {})",
                proxy_base_url, object_path
            )
        })?;

    Ok(format!("gs://{}/{}", signed.bucket, signed.path))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TraceExportConfig, UploadMethod};

    #[tokio::test]
    async fn proxy_fallback_rejects_cross_origin_redirect() {
        use axum::{Router, routing::get};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let received = Arc::new(AtomicUsize::new(0));
        let sink = received.clone();
        let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = format!(
            "http://{}/storage/limits",
            destination.local_addr().unwrap()
        );
        let destination_task = tokio::spawn(async move {
            axum::serve(
                destination,
                Router::new().route(
                    "/storage/limits",
                    get(move || {
                        let sink = sink.clone();
                        async move {
                            sink.fetch_add(1, Ordering::SeqCst);
                            "{}"
                        }
                    }),
                ),
            )
            .await
            .unwrap();
        });
        let source = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", source.local_addr().unwrap());
        let source_hits = Arc::new(AtomicUsize::new(0));
        let source_seen = source_hits.clone();
        let source_task = tokio::spawn(async move {
            axum::serve(
                source,
                Router::new().route(
                    "/storage/limits",
                    get(move || {
                        let target = target.clone();
                        source_seen.fetch_add(1, Ordering::SeqCst);
                        async move {
                            (
                                axum::http::StatusCode::TEMPORARY_REDIRECT,
                                [("location", target)],
                            )
                        }
                    }),
                ),
            )
            .await
            .unwrap();
        });
        // P47: a deployment key (exempt: its own rules) so the request really reaches the loopback source and the
        // redirect is what gets refused; a session `user_token` would be refused before any request (pinned in
        // `p47_static_session_upload_never_reaches_a_loopback_proxy`).
        let client = build_proxy_client_with_fallback(
            &base,
            "",
            Some("fake-deployment-key".into()),
            None,
            None,
            None,
        );
        let result = client.get_upload_limits().await;
        source_task.abort();
        destination_task.abort();
        assert!(result.is_err());
        assert_eq!(
            received.load(Ordering::SeqCst),
            0,
            "fallback client followed cross-origin redirect"
        );
        assert_eq!(
            source_hits.load(Ordering::SeqCst),
            1,
            "the source must have received the request (the redirect is what is under test)"
        );
        let err = format!("{:#}", result.unwrap_err());
        assert!(!err.contains("The request was not made"), "not a P47 refusal: {err}");
    }

    fn proxy_config() -> TraceExportConfig {
        proxy_config_with_url("https://proxy.example.com/v1".to_string())
    }

    fn proxy_config_with_url(base_url: String) -> TraceExportConfig {
        TraceExportConfig {
            bucket_url: None,
            service_account_key: None,
            upload_method: UploadMethod::Proxy {
                proxy_base_url: base_url,
                user_token: "tok".to_string(),
                deployment_key: None,
                alpha_test_key: None,
            },
            prefix_dir: None,
            gcs_prefix: None,
            absolute_paths: false,
            archive_name_override: None,
        }
    }

    /// P47: the proxy config with a NON-session static key, for tests of upload dispatch (a session `user_token`
    /// on the static path may never reach these loopback mocks; see `p47_static_session_upload_never_reaches_a_loopback_proxy`).
    struct StaticKeyProxy(TraceExportConfig);
    impl StorageConfig for StaticKeyProxy {
        fn bucket_url(&self) -> &str {
            self.0.bucket_url()
        }
        fn upload_method(&self) -> &UploadMethod {
            self.0.upload_method()
        }
        fn proxy_credentials(&self) -> Option<Arc<dyn AuthCredentialProvider>> {
            Some(Arc::new(StaticAuthCredentialProvider::new(
                Box::new(StaticFuigoAuth::new(Some("tok".into()))),
                Some("tok".into()),
                fuigo_auth::BearerDestination::Unrestricted,
            )))
        }
    }

    /// P47: the static fallback treats `user_token` as the session token it is: a cleartext loopback proxy never
    /// receives any request (with or without the token) and the upload fails with the refusal. Positive control: the
    /// same server, reached with a non-session static key, receives the upload.
    #[tokio::test]
    async fn p47_static_session_upload_never_reaches_a_loopback_proxy() {
        let (addr, state) = start_dispatch_test_server().await;
        let config = proxy_config_with_url(format!("http://{}/v1", addr));
        let temp = tempfile::TempDir::new().unwrap();
        let small_file = temp.path().join("small.bin");
        std::fs::write(&small_file, vec![0u8; 1024]).unwrap();
        let err = upload_file(&config, "s/turn_0/small.bin", &small_file, "application/octet-stream")
            .await
            .unwrap_err();
        assert!(
            fuigo_auth::find_bearer_refusal(err.as_ref()).is_some(),
            "the refusal must survive typed: {err:#}"
        );
        assert!(!state.storage_called.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!state.multipart_called.load(std::sync::atomic::Ordering::SeqCst));
        let _ = upload_file(
            &StaticKeyProxy(config),
            "s/turn_0/small.bin",
            &small_file,
            "application/octet-stream",
        )
        .await;
        assert!(state.storage_called.load(std::sync::atomic::Ordering::SeqCst));
    }

    fn direct_config() -> TraceExportConfig {
        TraceExportConfig {
            bucket_url: Some("gs://test-bucket".to_string()),
            service_account_key: None,
            upload_method: UploadMethod::Direct {
                service_account_key: None,
            },
            prefix_dir: None,
            gcs_prefix: None,
            absolute_paths: false,
            archive_name_override: None,
        }
    }

    #[test]
    fn multipart_threshold_is_50mb() {
        assert_eq!(
            MULTIPART_UPLOAD_THRESHOLD,
            50 * 1024 * 1024,
            "Multipart threshold must be 50 MB to match the plan and repo_changes.rs"
        );
    }

    #[tokio::test]
    async fn upload_file_proxy_missing_file_returns_error() {
        // upload_file_via_proxy checks metadata before connecting — should fail
        // fast with a descriptive error if the temp file was deleted mid-flight.
        let config = proxy_config();
        let result = upload_file(
            &config,
            "session/turn_0/test.bin",
            std::path::Path::new("/tmp/nonexistent_upload_queue_test_file"),
            "application/octet-stream",
        )
        .await;
        assert!(result.is_err(), "Should error for missing file");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("metadata") || err.contains("No such file"),
            "Error should mention file metadata: {}",
            err
        );
    }

    #[tokio::test]
    async fn upload_file_direct_missing_file_returns_error() {
        // Direct mode tries to authenticate first — bucket URL parse should succeed,
        // but the file open will fail later. We only care it returns an error, not panics.
        let config = direct_config();
        let result = upload_file(
            &config,
            "session/turn_0/test.bin",
            std::path::Path::new("/tmp/nonexistent_upload_queue_test_file"),
            "application/octet-stream",
        )
        .await;
        assert!(result.is_err(), "Should error for missing file");
    }

    #[tokio::test]
    async fn upload_file_direct_invalid_scheme_returns_error() {
        // Verify that a non-gs:// URL is rejected before any I/O.
        let config = TraceExportConfig {
            bucket_url: Some("https://not-a-gcs-url.example.com".to_string()),
            service_account_key: None,
            upload_method: UploadMethod::Direct {
                service_account_key: None,
            },
            prefix_dir: None,
            gcs_prefix: None,
            absolute_paths: false,
            archive_name_override: None,
        };
        let result = upload_file(
            &config,
            "path/test.bin",
            std::path::Path::new("/tmp/file"),
            "application/octet-stream",
        )
        .await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("gs"),
            "Error should mention expected scheme"
        );
    }

    /// Shared state for the dispatch test server, tracking which endpoints were hit.
    #[derive(Clone, Default)]
    struct DispatchState {
        multipart_called: std::sync::Arc<std::sync::atomic::AtomicBool>,
        storage_called: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    /// Start a minimal axum server (with proper State extractors) that records
    /// which upload routes were hit. Uses the same State extractor pattern as
    /// storage_client_tests.rs to ensure reliable flag updates in Bazel CI.
    ///
    /// Returns (addr, state) where state.multipart_called / state.storage_called
    /// are set to true when the respective route is hit.
    async fn start_dispatch_test_server() -> (std::net::SocketAddr, DispatchState) {
        use axum::{
            Router, body::Body, extract::State, http::StatusCode, response::IntoResponse,
            routing::post,
        };
        use std::sync::atomic::Ordering;
        use tokio::net::TcpListener;

        let state = DispatchState::default();

        async fn multipart_handler(
            State(s): State<DispatchState>,
            _body: Body,
        ) -> impl IntoResponse {
            s.multipart_called.store(true, Ordering::SeqCst);
            // 400 = non-retryable: client fails fast without backoff delays
            (StatusCode::BAD_REQUEST, r#"{"error":"test"}"#)
        }

        async fn storage_handler(State(s): State<DispatchState>, _body: Body) -> impl IntoResponse {
            s.storage_called.store(true, Ordering::SeqCst);
            (StatusCode::BAD_REQUEST, r#"{"error":"test"}"#)
        }

        let app = Router::new()
            .route("/v1/storage/multipart/init", post(multipart_handler))
            .route("/v1/storage", post(storage_handler))
            .with_state(state.clone());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        // Give the server 50ms to bind and accept — more headroom for Bazel CI sandboxing.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        (addr, state)
    }

    #[tokio::test]
    async fn upload_file_via_proxy_uses_multipart_for_large_files() {
        // Large file (just over 50 MB threshold) should hit the multipart init endpoint.
        // Uses set_len() to create a sparse file — no actual disk write.
        let (addr, state) = start_dispatch_test_server().await;
        let config = proxy_config_with_url(format!("http://{}/v1", addr));

        let temp = tempfile::TempDir::new().unwrap();
        let large_file = temp.path().join("large.bin");
        let f = std::fs::File::create(&large_file).unwrap();
        f.set_len(MULTIPART_UPLOAD_THRESHOLD + 1).unwrap(); // sparse file, no actual disk write

        let _ = upload_file(
            &StaticKeyProxy(config),
            "session/turn_0/large.bin",
            &large_file,
            "application/octet-stream",
        )
        .await;

        assert!(
            state
                .multipart_called
                .load(std::sync::atomic::Ordering::SeqCst),
            "File > 50MB should use multipart upload"
        );
        assert!(
            !state
                .storage_called
                .load(std::sync::atomic::Ordering::SeqCst),
            "File > 50MB should NOT use the simple storage endpoint"
        );
    }

    #[tokio::test]
    async fn upload_file_via_proxy_uses_streaming_for_small_files() {
        // Small file (1 KB) should hit the simple storage endpoint, not multipart.
        let (addr, state) = start_dispatch_test_server().await;
        let config = proxy_config_with_url(format!("http://{}/v1", addr));

        let temp = tempfile::TempDir::new().unwrap();
        let small_file = temp.path().join("small.bin");
        std::fs::write(&small_file, vec![0u8; 1024]).unwrap();

        let _ = upload_file(
            &StaticKeyProxy(config),
            "session/turn_0/small.bin",
            &small_file,
            "application/octet-stream",
        )
        .await;

        assert!(
            !state
                .multipart_called
                .load(std::sync::atomic::Ordering::SeqCst),
            "File < 50MB should NOT use multipart upload"
        );
        assert!(
            state
                .storage_called
                .load(std::sync::atomic::Ordering::SeqCst),
            "File < 50MB should use the simple storage endpoint"
        );
    }
}

/// P71 wire-level tests: the destination gate, reached through each dispatcher and through each
/// content-moving method of the storage client itself (where the gate lives). Assertions are on what a
/// recording mock endpoint RECEIVED, never on a return value alone.
#[cfg(test)]
mod p71_gate_tests {
    use super::*;
    use crate::destination_gate::{WITHHELD_NOTICE, is_withheld, withheld_notices};
    use crate::gate_testkit::RecordingEndpoint;
    use crate::{TraceExportConfig, UploadMethod};

    const CONTENT: &[u8] = b"P71-ARCHIVE-BYTES: account user-123 /home/rowan/work team-456";

    /// A proxy config whose credential is a deployment key (no session token to protect), so the only
    /// thing standing between the bytes and a loopback mock is the destination gate.
    fn config_for(method: UploadMethod) -> TraceExportConfig {
        TraceExportConfig {
            bucket_url: Some("gs://operator-bucket".to_string()),
            service_account_key: None,
            upload_method: method,
            prefix_dir: None,
            gcs_prefix: None,
            absolute_paths: false,
            archive_name_override: None,
        }
    }

    fn proxy(base: &str) -> TraceExportConfig {
        config_for(UploadMethod::Proxy {
            proxy_base_url: base.to_string(),
            user_token: String::new(),
            deployment_key: Some("deployment-key".to_string()),
            alpha_test_key: None,
        })
    }

    fn s3(endpoint: &str) -> TraceExportConfig {
        config_for(UploadMethod::S3 {
            bucket: "operator-bucket".to_string(),
            region: "us-east-1".to_string(),
            credentials_file: None,
            credentials_content: Some(
                r#"{"aws_access_key_id":"test","aws_secret_access_key":"test"}"#.to_string(),
            ),
            endpoint_url: Some(endpoint.to_string()),
        })
    }

    /// Run every dispatcher against `config`, returning each outcome.
    async fn run_all(config: &TraceExportConfig) -> Vec<(&'static str, anyhow::Result<String>)> {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("archive.bin");
        std::fs::write(&file, CONTENT).unwrap();
        vec![
            ("upload_bytes", upload_bytes(config, "s/a.bin", CONTENT, "application/gzip").await),
            ("upload_bytes_signed", upload_bytes_signed(config, "s/b.bin", CONTENT, "application/gzip").await),
            ("upload_file", upload_file(config, "s/c.bin", &file, "application/gzip").await),
            (
                "upload_stream",
                upload_stream(config, "s/d.bin", std::io::Cursor::new(CONTENT.to_vec()), "application/gzip").await,
            ),
        ]
    }

    /// Class 3, every dispatcher: the mock receives no connection and no byte.
    #[tokio::test]
    async fn third_party_proxy_receives_nothing_from_any_dispatcher() {
        let mock = RecordingEndpoint::third_party().await;
        let config = proxy(&mock.proxy_base_url());
        for (name, outcome) in run_all(&config).await {
            let err = outcome.expect_err(name);
            assert!(is_withheld(&err), "{name}: {err:#}");
        }
        mock.settle(std::time::Duration::from_millis(300)).await;
        assert_eq!(mock.connections(), 0, "a connection reached the third-party proxy");
        assert!(mock.received().is_empty());
        assert!(!mock.received_contains(b"P71-ARCHIVE"));
    }

    /// The gate is in the storage client, so a caller that holds a client and skips the dispatchers is
    /// refused all the same: every public method that moves content, or names an object to the proxy for
    /// upload, sends nothing to a third-party proxy. (The signed-URL flow has one public entry,
    /// `upload_bytes_signed`: the PUT to a URL is private, so it only ever gets the URL a gated proxy returned.)
    #[tokio::test]
    async fn a_storage_client_sends_nothing_to_a_third_party_proxy_through_any_method() {
        let mock = RecordingEndpoint::third_party().await;
        let client = StorageClient::with_static_key(&mock.proxy_base_url(), "deployment-key");
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("archive.bin");
        std::fs::write(&file, CONTENT).unwrap();
        let files = || vec![("s/a.bin".to_string(), CONTENT.to_vec(), "application/gzip".to_string())];

        let withheld: Vec<(&str, bool)> = vec![
            ("upload", client.upload("s/a.bin", CONTENT, "application/gzip").await.is_err_and(|e| is_withheld(&e))),
            ("upload_file", client.upload_file("s/b.bin", &file, "application/gzip").await.is_err_and(|e| is_withheld(&e))),
            (
                "upload_stream",
                client
                    .upload_stream("s/c.bin", std::io::Cursor::new(CONTENT.to_vec()), "application/gzip")
                    .await
                    .is_err_and(|e| is_withheld(&e)),
            ),
            (
                "upload_multipart",
                client.upload_multipart("s/d.bin", &file, "application/gzip", None).await.is_err_and(|e| is_withheld(&e)),
            ),
            (
                "upload_bytes_signed",
                client.upload_bytes_signed("s/f.bin", CONTENT, "application/gzip").await.is_err_and(|e| is_withheld(&e)),
            ),
            ("batch_upload", client.batch_upload(files()).await.is_none()),
            ("batch_upload_json", client.batch_upload_json(files()).await.is_none()),
        ];
        for (name, refused) in &withheld {
            assert!(refused, "{name}: not refused as withheld");
        }
        mock.settle(std::time::Duration::from_millis(300)).await;
        assert_eq!(mock.connections(), 0, "a storage client reached the third-party proxy");
        assert!(mock.received().is_empty());
    }

    /// The notice is printed once per process and says what was withheld and the remedy.
    #[tokio::test]
    async fn withheld_upload_prints_the_notice_exactly_once() {
        let mock = RecordingEndpoint::third_party().await;
        let config = proxy(&mock.proxy_base_url());
        let _ = run_all(&config).await;
        let _ = run_all(&config).await;
        let notices = withheld_notices();
        assert_eq!(notices.iter().filter(|n| n.as_str() == WITHHELD_NOTICE).count(), 1);
        assert!(WITHHELD_NOTICE.contains("NOT uploaded") && WITHHELD_NOTICE.contains("trace_upload_bucket"));
    }

    /// Fail closed: a proxy that cannot be classified is class 3.
    #[tokio::test]
    async fn unclassifiable_destination_receives_nothing() {
        for base in ["not a url", "", "ftp://127.0.0.1/v1", "http://api.fluxrouter.ai.evil.example/v1"] {
            let config = proxy(base);
            for (name, outcome) in run_all(&config).await {
                let err = outcome.expect_err(name);
                assert!(is_withheld(&err), "{base} {name}: {err:#}");
            }
        }
    }

    /// Class 1 (positive control for the mocks): a FluxRouter-class loopback proxy receives the bytes
    /// unchanged through every byte-carrying dispatcher.
    #[tokio::test]
    async fn fluxrouter_class_proxy_receives_bytes_unchanged() {
        for name in ["upload_bytes", "upload_file", "upload_stream"] {
            let mock = RecordingEndpoint::fluxrouter_class().await;
            let config = proxy(&mock.proxy_base_url());
            let dir = tempfile::TempDir::new().unwrap();
            let file = dir.path().join("archive.bin");
            std::fs::write(&file, CONTENT).unwrap();
            let outcome = match name {
                "upload_bytes" => upload_bytes(&config, "s/a.bin", CONTENT, "application/gzip").await,
                "upload_file" => upload_file(&config, "s/c.bin", &file, "application/gzip").await,
                _ => upload_stream(&config, "s/d.bin", std::io::Cursor::new(CONTENT.to_vec()), "application/gzip").await,
            };
            if let Err(err) = &outcome {
                assert!(!is_withheld(err), "{name}: {err:#}");
            }
            assert!(mock.requests() >= 1, "{name}: no request reached the class 1 mock");
            assert!(mock.received_contains(CONTENT), "{name}: bytes not received unchanged");
        }
        // The signed-URL flow asks the proxy for a URL, then PUTs the payload to it (the mock answers with
        // a URL on itself): both requests arrive, and the payload arrives unchanged.
        let mock = RecordingEndpoint::fluxrouter_class().await;
        let outcome =
            upload_bytes_signed(&proxy(&mock.proxy_base_url()), "s/b.bin", CONTENT, "application/gzip").await;
        outcome.expect("the signed-URL upload to a class 1 mock completes");
        assert!(mock.received_contains(b"/storage/signed-upload-url"), "no signed-URL request reached the mock");
        assert!(
            mock.received_contains(format!("PUT {}", crate::gate_testkit::SIGNED_PUT_PATH).as_bytes()),
            "upload_bytes_signed never PUT its payload"
        );
        assert!(mock.received_contains(CONTENT), "upload_bytes_signed: bytes not received unchanged");
    }

    /// Class 2: the operator's own S3 bucket receives the bytes unchanged, through each dispatcher that
    /// carries them (one mock per dispatcher, so neither can satisfy the other's assertion).
    #[tokio::test]
    async fn operator_s3_bucket_receives_bytes_unchanged() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("archive.bin");
        std::fs::write(&file, CONTENT).unwrap();
        for name in ["upload_bytes", "upload_file", "upload_stream"] {
            let mock = RecordingEndpoint::third_party().await;
            let config = s3(&mock.endpoint_url());
            let key = format!("s/{name}.bin");
            let outcome = match name {
                "upload_bytes" => upload_bytes(&config, &key, CONTENT, "application/gzip").await,
                "upload_file" => upload_file(&config, &key, &file, "application/gzip").await,
                _ => upload_stream(&config, &key, std::io::Cursor::new(CONTENT.to_vec()), "application/gzip").await,
            };
            if let Err(err) = &outcome {
                assert!(!is_withheld(err), "{name}: {err:#}");
            }
            assert!(mock.received_contains(key.as_bytes()), "{name}: the S3 bucket saw no request for {key}");
            assert!(mock.received_contains(CONTENT), "{name}: the S3 bucket did not receive the bytes unchanged");
        }
    }

    /// Class 2, Direct GCS: classified as the operator's bucket, so the gate lets it through. (No
    /// mock stands in for GCS; the gate decision is what is asserted.)
    #[test]
    fn direct_gcs_is_the_operators_bucket() {
        let method = UploadMethod::Direct { service_account_key: None };
        assert!(crate::destination_gate::gate_upload(&method, "s/a.bin").is_ok());
    }
}
