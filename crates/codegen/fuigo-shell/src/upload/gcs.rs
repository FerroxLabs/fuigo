//! Shell-side adapter that threads the live `AuthManager` through to the `StorageClient` constructed inside `fuigo_file_utils::gcs::*` helpers.
//!
//! Background: the data-collector helpers (`upload_bytes`, `upload_file`, `upload_stream`, `upload_bytes_signed`) build a `StorageClient` per call.
//! Without a `StorageConfig` impl that provides `proxy_credentials` / `proxy_attribution`, that client falls back to a static `user_token` snapshot.
//! The snapshot is baked into `TraceExportConfig` at construction time, and no attribution event is emitted on 401.
//! That snapshot becomes stale on rotation and is empty during the 5-minute pre-refresh buffer window in `AuthManager`.
//! Both show up as `POST /v1/storage` 401s at the proxy.
//!
//! [`TraceExportConfigWithAuth`] wraps a bare `TraceExportConfig` plus an optional `Arc<AuthManager>` and implements `StorageConfig`.
//! When the manager is present, the constructed `StorageClient` gets:
//!
//!   1. A refresh-aware `ShellAuthCredentialProvider`.
//!      It serves the live token from `auth_manager.current()` and falls back to `expired_auth()` so the buffer window is covered.
//!   2. A `StorageClientAttributionBridge` that emits the `auth_401_attribution` event on 401 with the right consumer tag.
//!
//! Use [`WithAuth::with_auth`] at every shell-side upload call site that has an `AuthManager` in scope.
//! Call it immediately before passing the config to an `fuigo_file_utils::gcs::*` helper.
use crate::auth::AuthManager;
use crate::auth::credential_provider::{
    ShellAuthCredentialProvider, StorageClientAttributionBridge,
};
use fuigo_auth::AuthCredentialProvider;
use fuigo_file_utils::gcs::StorageConfig;
use fuigo_file_utils::storage_client::Auth401AttributionCallback;
use fuigo_file_utils::{TraceExportConfig, UploadMethod};
use std::sync::Arc;
/// P47: a proxy upload whose credential KIND is known, for callers with a resolved `FuigoAuth` and no
/// `AuthManager` (the `fuigo trace` command). `UploadMethod::Proxy.user_token` cannot say what it carries, so the
/// static fallback in `fuigo-file-utils` treats it as a session token. This wrapper supplies the credential as a
/// static provider instead, with the right rule: a static `AuthMode::ApiKey` credential is
/// `BearerDestination::Unrestricted` (its own rules), a session credential is checked by the service-endpoint trust
/// class against the proxy base. A deployment key, or no credential, leaves the fallback in charge.
pub struct ClassifiedProxyUpload {
    inner: TraceExportConfig,
    credentials: Option<Arc<dyn AuthCredentialProvider>>,
}
impl ClassifiedProxyUpload {
    pub fn new(inner: TraceExportConfig, auth: Option<&crate::auth::FuigoAuth>) -> Self {
        let credentials = match (&inner.upload_method, auth) {
            (
                UploadMethod::Proxy {
                    proxy_base_url,
                    deployment_key: None,
                    ..
                },
                Some(auth),
            ) => {
                let destination = if crate::auth::session_delivery::is_session_credential(auth) {
                    crate::auth::session_delivery::service_bearer_destination(
                        Some(proxy_base_url.clone()),
                        "trace_cmd_upload",
                    )
                } else {
                    fuigo_auth::BearerDestination::Unrestricted
                };
                let creds =
                    crate::util::fuigo_auth_credentials::FuigoAuthCredentials::new(Some(auth.key.clone()));
                Some(Arc::new(fuigo_auth::StaticAuthCredentialProvider::new(
                    Box::new(creds),
                    Some(auth.key.clone()),
                    destination,
                )) as Arc<dyn AuthCredentialProvider>)
            }
            _ => None,
        };
        Self { inner, credentials }
    }
}
/// P47 / P71: whether `error` is a refused destination (nothing was sent; no retry can change it): the bearer may not
/// go there (P47), or the destination may not receive file content at all (P71, `destination_gate`).
pub fn is_destination_refusal(error: &anyhow::Error) -> bool {
    fuigo_auth::find_bearer_refusal(error.as_ref()).is_some()
        || fuigo_file_utils::destination_gate::is_withheld(error)
}
impl StorageConfig for ClassifiedProxyUpload {
    fn bucket_url(&self) -> &str {
        self.inner.bucket_url()
    }
    fn upload_method(&self) -> &UploadMethod {
        self.inner.upload_method()
    }
    fn proxy_credentials(&self) -> Option<Arc<dyn AuthCredentialProvider>> {
        self.credentials.clone()
    }
}
/// See the module docs for why this exists.
///
/// `auth_manager == None` is supported (for tests, direct-mode upload, and a few sites without an `AuthManager` in scope).
/// It degrades to the pre-existing snapshot-based behavior.
#[derive(Clone)]
pub(crate) struct TraceExportConfigWithAuth {
    inner: TraceExportConfig,
    auth_manager: Option<Arc<AuthManager>>,
}
impl TraceExportConfigWithAuth {
    pub(crate) fn new(inner: TraceExportConfig, auth_manager: Option<Arc<AuthManager>>) -> Self {
        Self {
            inner,
            auth_manager,
        }
    }
}
impl StorageConfig for TraceExportConfigWithAuth {
    fn bucket_url(&self) -> &str {
        self.inner.bucket_url()
    }
    fn upload_method(&self) -> &UploadMethod {
        self.inner.upload_method()
    }
    fn proxy_credentials(&self) -> Option<Arc<dyn AuthCredentialProvider>> {
        let am = self.auth_manager.as_ref()?;
        let UploadMethod::Proxy {
            proxy_base_url,
            deployment_key,
            alpha_test_key,
            ..
        } = &self.inner.upload_method
        else {
            return None;
        };
        Some(Arc::new(ShellAuthCredentialProvider::new(
            am.clone(),
            deployment_key.clone(),
            alpha_test_key.clone(),
            Some(proxy_base_url.clone()),
            "trace_upload",
        )))
    }
    fn proxy_attribution(&self) -> Option<Arc<dyn Auth401AttributionCallback>> {
        let am = self.auth_manager.as_ref()?;
        if !matches!(self.inner.upload_method, UploadMethod::Proxy { .. }) {
            return None;
        }
        Some(Arc::new(StorageClientAttributionBridge::new(
            am.clone(),
            None,
        )))
    }
    fn proxy_http_client(&self) -> Option<reqwest::Client> {
        Some(crate::http::shared_upload_client())
    }
}
/// Convenience trait for wrapping a `TraceExportConfig` at upload call sites. Pattern:
///
/// ```ignore
/// fuigo_file_utils::gcs::upload_bytes(
///     &gcs_config.with_auth(Some(auth_manager.clone())),
///     ...,
/// ).await
/// ```
///
/// At sites without an `AuthManager` in scope, pass `None` (degrades to snapshot behavior; same as calling the helper with the bare config).
pub(crate) trait WithAuth {
    fn with_auth(&self, auth_manager: Option<Arc<AuthManager>>) -> TraceExportConfigWithAuth;
}
impl WithAuth for TraceExportConfig {
    fn with_auth(&self, auth_manager: Option<Arc<AuthManager>>) -> TraceExportConfigWithAuth {
        TraceExportConfigWithAuth::new(self.clone(), auth_manager)
    }
}
/// Override at runtime with `FUIGO_TELEMETRY_GCS_BUCKET`; `None` disables trace uploads until a bucket is configured.
pub(crate) const SESSION_TRACES_BUCKET: Option<&str> =
    option_env!("FUIGO_SESSION_TRACES_BUCKET_DEFAULT");
/// Upload bytes to the `auth-diagnostics/{version}/{user_id}/{ts}.jsonl` path for easy aggregation across users.
/// Used by both the auth refresh failure uploader and the 401/404 error trace uploader.
pub(crate) async fn upload_to_auth_diagnostics(
    log_bytes: &[u8],
    user_id: &str,
    upload_method: &crate::session::repo_changes::UploadMethod,
    auth_manager: Arc<crate::auth::AuthManager>,
) {
    let user_id = user_id.replace('/', "_");
    let ts = chrono::Utc::now().timestamp_millis();
    let version = fuigo_version::VERSION;
    let object_path = format!("auth-diagnostics/{version}/{user_id}/{ts}.jsonl");
    let config = crate::session::repo_changes::TraceExportConfig {
        bucket_url: None,
        service_account_key: None,
        upload_method: upload_method.clone(),
        prefix_dir: None,
        gcs_prefix: None,
        absolute_paths: false,
        archive_name_override: None,
    };
    // P149 (S14/K16): the diagnostic log leaves the machine, so it gets the trace-upload scrub.
    let log_bytes = super::trace::scrub_upload_payload(log_bytes, "application/x-ndjson");
    match fuigo_file_utils::gcs::upload_bytes(
        &config.with_auth(Some(auth_manager)),
        &object_path,
        &log_bytes,
        "application/x-ndjson",
    )
    .await
    {
        Ok(_) => {
            tracing::info!(
                version = version,
                "uploaded diagnostic log to auth-diagnostics"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to upload diagnostic log to auth-diagnostics");
        }
    }
}
