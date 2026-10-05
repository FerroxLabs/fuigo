use crate::auth::backend::{ActiveAuthBackend, AuthBackend};
use crate::auth::{FuigoAuth, FuigoComConfig};
use crate::session::export::{ExportedMessage, ExportedMetadata, ExportedSession};
use indexmap::IndexMap;
use prod_mc_cli_chat_proxy_types::SubagentBundle;
use serde::{Deserialize, Serialize};
use std::time::Duration;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Env var naming the session-history ("code") backend this client talks to.
///
/// There is **no compiled default**. Upstream this fell back to the vendor's
/// `https://code.grok.com`; Fuigo runs no such backend, so an unset var means
/// the features built on it (share links, session writeback, fork sync,
/// remote delete) are not available, and every request says so instead of
/// dialling a host the user never configured.
pub const FUIGO_CODE_BACKEND_URL_ENV: &str = "FUIGO_CODE_BACKEND_URL";
/// Env var naming the web origin that renders shared sessions.
///
/// No compiled default either (upstream: `https://grok.com`). Without it there
/// is no share URL to show, so [`share_url`] returns `None`.
pub const FUIGO_CODE_WEB_URL_ENV: &str = "FUIGO_CODE_WEB_URL";
/// An env value, with empty treated as unset (the convention the sibling
/// `remote/*_client.rs` resolvers already use). Set values pass through verbatim.
pub(crate) fn nonempty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}
/// The configured share-link origin, or `None` when `FUIGO_CODE_WEB_URL` is unset.
pub(crate) fn code_web_url() -> Option<String> {
    nonempty_env(FUIGO_CODE_WEB_URL_ENV)
}
/// The share URL for a permission id, or `None` when no web origin is configured.
///
/// Never invents a destination: with `FUIGO_CODE_WEB_URL` unset there is no
/// page that can render the share, so there is no URL.
pub fn share_url(permission_id: &str) -> Option<String> {
    code_web_url().map(|web_url| share_url_on(&web_url, permission_id))
}
/// `<web_url>/build/share/<permission_id>` on an origin the caller has already resolved.
fn share_url_on(web_url: &str, permission_id: &str) -> String {
    format!("{web_url}/build/share/{permission_id}")
}
fn add_cli_chat_proxy_headers_blocking(
    builder: reqwest::blocking::RequestBuilder,
    auth: &FuigoAuth,
    alpha_test_key: Option<&str>,
    url: &str,
) -> reqwest::blocking::RequestBuilder {
    let _ = alpha_test_key;
    // P43: identity only to a FluxRouter-operated destination.
    let identity = super::account_identity_headers(url, &auth.user_id, auth.email.as_deref());
    builder
        .header("Authorization", format!("Bearer {}", &auth.key))
        .header("X-XAI-Token-Auth", FuigoComConfig::default().token_header)
        .headers(identity)
        .header(
            crate::http::CLIENT_MODE_HEADER,
            crate::http::process_client_mode(),
        )
}
async fn parse_json_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, BackendError> {
    let bytes = response.bytes().await?;
    serde_json::from_slice(&bytes).map_err(BackendError::from)
}
async fn add_bundle_fetch_headers(
    builder: reqwest::RequestBuilder,
    auth_manager: Option<&std::sync::Arc<crate::auth::AuthManager>>,
    deployment_key: Option<&str>,
    alpha_test_key: Option<&str>,
    url: &str,
    service_base: &str,
) -> Result<reqwest::RequestBuilder, BackendError> {
    let resolved_auth = match auth_manager {
        Some(am) if ActiveAuthBackend::default().is_fuigo_authority() => am.auth().await.ok(),
        _ => None,
    };
    // P47: a session credential is attached only where the service-endpoint trust class admits the URL; the
    // caller's base is the configured cli-chat-proxy base. A deployment key keeps its own rules.
    if deployment_key.is_none()
        && let Some(auth) = &resolved_auth
    {
        crate::auth::session_delivery::service_session_gate(auth, url, Some(service_base), "bundle_fetch")
            .map_err(|refused| BackendError::SessionDestinationRefused(refused.to_string()))?;
    }
    let mut credentials = crate::util::fuigo_auth_credentials::FuigoAuthCredentials::new(
        resolved_auth.as_ref().map(|auth| auth.key.clone()),
    );
    credentials.deployment_key = deployment_key.map(str::to_owned);
    credentials.alpha_test_key = alpha_test_key.map(str::to_owned);
    // P43: identity only to a FluxRouter-operated destination.
    let identity = fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_destination(url);
    let client_identifier = crate::http::process_client_identifier();
    let mut pairs = vec![
        ("x-fuigo-client-version", fuigo_version::VERSION),
        ("x-fuigo-client-identifier", client_identifier.as_str()),
    ];
    if deployment_key.is_none()
        && let Some(auth) = &resolved_auth
    {
        pairs.push(("x-userid", auth.user_id.as_str()));
        if let Some(email) = &auth.email {
            pairs.push(("x-email", email.as_str()));
        }
    }
    let mut builder = credentials
        .apply(builder, url)
        .headers(identity.header_map(pairs));
    builder = builder
        .header(
            crate::http::CLIENT_MODE_HEADER,
            crate::http::process_client_mode(),
        );
    Ok(fuigo_file_utils::trace_context::inject_trace_context_into_request(builder))
}
/// Fetch the bundled subagent cache payload from cli-chat-proxy `GET /v1/subagents/bundle`.
///
/// Uses the shell's standard auth for proxy requests: a configured deployment key takes precedence; otherwise the user-session token is used.
pub async fn fetch_subagent_bundle(
    cli_chat_proxy_base_url: &str,
    auth_manager: Option<&std::sync::Arc<crate::auth::AuthManager>>,
    deployment_key: Option<&str>,
    alpha_test_key: Option<&str>,
) -> Result<SubagentBundle, BackendError> {
    let url = format!("{}/subagents/bundle", cli_chat_proxy_base_url);
    let response = fuigo_extra_ca::dispatch::send(
        add_bundle_fetch_headers(
            crate::http::shared_client()
                .get(&url)
                .timeout(std::time::Duration::from_secs(10)),
            auth_manager,
            deployment_key,
            alpha_test_key,
            &url,
            cli_chat_proxy_base_url,
        )
        .await?,
    )
    .await?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        return Err(BackendError::RequestFailed { status, body });
    }
    let bundle: SubagentBundle = parse_json_response(response).await?;
    tracing::debug!(
        version = %bundle.version,
        personas = bundle.personas.len(),
        roles = bundle.roles.len(),
        agents = bundle.agents.len(),
        "Fetched subagent bundle from cli-chat-proxy"
    );
    Ok(bundle)
}
/// The result of fetching a bundle: either raw tar.gz bytes from the new archive endpoint, or a parsed JSON bundle from the legacy endpoint.
#[derive(Debug)]
pub enum FetchedBundle {
    Archive(Vec<u8>),
    Legacy(SubagentBundle),
}
/// Fetch a bundle, trying the archive endpoint first and falling back to legacy JSON on any non-success HTTP status.
pub async fn fetch_bundle(
    cli_chat_proxy_base_url: &str,
    auth_manager: Option<&std::sync::Arc<crate::auth::AuthManager>>,
    deployment_key: Option<&str>,
    alpha_test_key: Option<&str>,
) -> Result<FetchedBundle, BackendError> {
    fetch_bundle_inner(
        cli_chat_proxy_base_url,
        auth_manager,
        deployment_key,
        alpha_test_key,
    )
    .await
}
async fn fetch_bundle_inner(
    cli_chat_proxy_base_url: &str,
    auth_manager: Option<&std::sync::Arc<crate::auth::AuthManager>>,
    deployment_key: Option<&str>,
    alpha_test_key: Option<&str>,
) -> Result<FetchedBundle, BackendError> {
    let archive_url = format!("{}/bundle/archive", cli_chat_proxy_base_url);
    let raw_client = crate::http::shared_client();
    let client: reqwest_middleware::ClientWithMiddleware = if let Some(am) = auth_manager {
        let provider: std::sync::Arc<dyn fuigo_auth::AuthCredentialProvider> = std::sync::Arc::new(
            crate::auth::credential_provider::ShellAuthCredentialProvider::new(
                am.clone(),
                deployment_key.map(str::to_owned),
                alpha_test_key.map(str::to_owned),
                Some(cli_chat_proxy_base_url.to_owned()),
                "bundle_archive",
            ),
        );
        crate::http::with_auth_retry(raw_client, provider)
    } else {
        reqwest_middleware::ClientBuilder::new(raw_client)
            .with(fuigo_auth::EgressMiddleware)
            .build()
    };
    // P43: identity only to a FluxRouter-operated destination.
    let identity = fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_destination(&archive_url);
    let current_auth = if deployment_key.is_none() {
        auth_manager.and_then(|am| am.current())
    } else {
        None
    };
    let mut pairs = vec![("x-fuigo-client-version", fuigo_version::VERSION)];
    if let Some(auth) = &current_auth {
        pairs.push(("x-userid", auth.user_id.as_str()));
        if let Some(email) = &auth.email {
            pairs.push(("x-email", email.as_str()));
        }
    }
    let request = client
        .get(&archive_url)
        .timeout(std::time::Duration::from_secs(30))
        .headers(identity.header_map(pairs))
        .header(
            crate::http::CLIENT_MODE_HEADER,
            crate::http::process_client_mode(),
        );
    let archive_response = request.send().await.map_err(|e| match e {
        reqwest_middleware::Error::Reqwest(e) => BackendError::Network(e),
        reqwest_middleware::Error::Middleware(e) => middleware_error(e),
    })?;
    if archive_response.status().is_success() {
        let bytes = archive_response.bytes().await?;
        return Ok(FetchedBundle::Archive(bytes.to_vec()));
    }
    if archive_response.status() == reqwest::StatusCode::UNAUTHORIZED {
        let body = archive_response.text().await.unwrap_or_default();
        return Err(BackendError::RequestFailed { status: 401, body });
    }
    tracing::debug!(
        status = %archive_response.status(),
        "archive endpoint unavailable, falling back to legacy JSON"
    );
    let bundle = fetch_subagent_bundle(
        cli_chat_proxy_base_url,
        auth_manager,
        deployment_key,
        alpha_test_key,
    )
    .await?;
    Ok(FetchedBundle::Legacy(bundle))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ShareResponse {
    pub permission_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoadDataResponse {
    pub messages: Option<Vec<LoadedMessage>>,
    pub session: Option<SessionInfo>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoadedMessage {
    pub id: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub session_id: String,
    pub title: Option<String>,
    pub cwd: Option<String>,
    pub status: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SaveDataRequest {
    pub messages: Vec<ExportedMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpsertSessionRequest {
    pub session: SessionUpdate,
    pub agent_id: String,
}
/// The upsert body actually sent to `url` (P54). Every session-backend write that names the
/// machine (history sync, share, fork, worktree resume) reaches the wire through
/// [`BackendClient::upsert_session`], so this is the one place `agent_id` (the persisted machine
/// id, a cross-destination identifier) is decided. A FluxRouter-operated backend receives it
/// unchanged; any other backend (`FUIGO_CODE_BACKEND_URL` is operator-configured and is not
/// FluxRouter by default) receives `IdentityDisclosure::body_key_for(url, agent_id)`, a pseudonym
/// stable at that origin, so the backend can still group a machine's sessions. The field is
/// required by the wire type, so it is substituted, never omitted.
pub(crate) fn upsert_session_request(
    url: &str,
    metadata: &ExportedMetadata,
    agent_id: &str,
) -> UpsertSessionRequest {
    UpsertSessionRequest {
        session: SessionUpdate {
            title: metadata.title.clone(),
            cwd: Some(metadata.cwd.clone()),
            status: Some("active".to_string()),
            metadata: serde_json::to_value(metadata).ok(),
        },
        agent_id: fuigo_extra_ca::fluxrouter::IdentityDisclosure::body_key_for(url, agent_id),
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Request blocked by egress policy: {0}")]
    Policy(&'static str),
    #[error("Request failed: {status} - {body}")]
    RequestFailed { status: u16, body: String },
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Session not found: {session_id}")]
    SessionNotFound { session_id: String },
    #[error("Hydration I/O error at {path}: {source}")]
    Hydration {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("Auth error: {0}")]
    Auth(String),
    /// P47: the destination may not receive the session token, so the request was not made.
    #[error("{0}")]
    SessionDestinationRefused(String),
    /// The feature depends on a service Fuigo does not run by default and the
    /// operator has not pointed it anywhere. The message names the env var.
    #[error("{0}")]
    NotConfigured(String),
}

/// A middleware failure: P47's refused destination keeps its own variant (its text is the remedy), anything else
/// is an auth failure as before.
fn middleware_error(e: anyhow::Error) -> BackendError {
    match fuigo_auth::find_bearer_refusal(e.as_ref()) {
        Some(refused) => BackendError::SessionDestinationRefused(refused.0.clone()),
        None => BackendError::Auth(e.to_string()),
    }
}

impl From<fuigo_extra_ca::dispatch::DispatchError> for BackendError {
    fn from(error: fuigo_extra_ca::dispatch::DispatchError) -> Self {
        match error {
            fuigo_extra_ca::dispatch::DispatchError::Denied(reason) => Self::Policy(reason),
            fuigo_extra_ca::dispatch::DispatchError::Transport(error) => Self::Network(error),
        }
    }
}
pub struct BackendClient {
    reqwest_client: reqwest::Client,
    client: reqwest_middleware::ClientWithMiddleware,
    /// `None` when `FUIGO_CODE_BACKEND_URL` is unset: every request fails
    /// closed with [`BackendError::NotConfigured`].
    base_url: Option<String>,
    pub(crate) auth_manager: Option<std::sync::Arc<crate::auth::AuthManager>>,
}
impl Default for BackendClient {
    fn default() -> Self {
        Self::new()
    }
}
/// Set once a backend has refused a save carrying compaction checkpoints and accepted it without them: later saves in
/// this process leave the checkpoints out instead of failing twice.
static CHECKPOINTS_REFUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// A 4xx that can mean "this backend does not take that message". Auth (401, 403) and transient (408, 429) failures
/// are not refusals.
fn is_checkpoint_refusal(status: u16) -> bool {
    (400..500).contains(&status) && !matches!(status, 401 | 403 | 408 | 429)
}
impl BackendClient {
    fn build_default_client() -> reqwest::Client {
        fuigo_extra_ca::build_reqwest_client(|builder| {
                builder.connect_timeout(Duration::from_secs(10)).timeout(DEFAULT_TIMEOUT)
            })
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "failed to build backend HTTP client; falling back to shared client");
                crate::http::shared_client()
            })
    }
    pub fn new() -> Self {
        let reqwest_client = Self::build_default_client();
        Self {
            client: reqwest_middleware::ClientBuilder::new(reqwest_client.clone())
                .with(fuigo_auth::EgressMiddleware)
                .build(),
            reqwest_client,
            base_url: nonempty_env(FUIGO_CODE_BACKEND_URL_ENV),
            auth_manager: None,
        }
    }
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        let reqwest_client = Self::build_default_client();
        Self {
            client: reqwest_middleware::ClientBuilder::new(reqwest_client.clone())
                .with(fuigo_auth::EgressMiddleware)
                .build(),
            reqwest_client,
            base_url: Some(base_url.into()),
            auth_manager: None,
        }
    }
    /// The configured backend origin, or the fail-closed error every request returns without one.
    fn base(&self) -> Result<&str, BackendError> {
        self.base_url.as_deref().ok_or_else(|| {
            BackendError::NotConfigured(format!(
                "session sharing and history sync need {FUIGO_CODE_BACKEND_URL_ENV} to be configured; \
                 they are not available otherwise"
            ))
        })
    }
    /// Attach a live `AuthManager` so every request resolves a fresh token instead of requiring the caller to pass `&FuigoAuth`.
    pub(crate) fn with_auth_manager(
        mut self,
        manager: std::sync::Arc<crate::auth::AuthManager>,
    ) -> Self {
        let credentials: std::sync::Arc<dyn fuigo_auth::AuthCredentialProvider> =
            std::sync::Arc::new(
                crate::auth::credential_provider::ShellAuthCredentialProvider::new(
                    manager.clone(),
                    None,
                    None,
                    self.base_url.clone(),
                    "code_backend",
                ),
            );
        self.client = crate::http::with_auth_retry(self.reqwest_client.clone(), credentials);
        self.auth_manager = Some(manager);
        self
    }
    async fn resolve_auth(&self) -> Result<FuigoAuth, BackendError> {
        let manager = self
            .auth_manager
            .as_ref()
            .ok_or_else(|| BackendError::Auth("No AuthManager configured".into()))?;
        manager
            .auth()
            .await
            .map_err(|e| BackendError::Auth(format!("{e}")))
    }
    /// The configured backend origin, or `None` when `FUIGO_CODE_BACKEND_URL` is unset.
    pub fn base_url(&self) -> Option<&str> {
        self.base_url.as_deref()
    }
    /// Everything a share needs before any byte is uploaded: a backend to store
    /// the session and a web origin to view it on. Returns the origin.
    pub(crate) fn share_link_origin(&self) -> Result<String, BackendError> {
        self.base()?;
        code_web_url().ok_or_else(|| {
            BackendError::NotConfigured(format!(
                "session share links need {FUIGO_CODE_WEB_URL_ENV} to be configured; \
                 sharing is not available otherwise"
            ))
        })
    }
    /// The session data (`save_session_data`) is sent inline to the backend.
    /// If the backend responds with 413 (payload too large), the error is logged as a warning and the share continues.
    /// The caller is expected to have already uploaded the data to GCS via a signed URL as a fallback.
    pub async fn share_session(
        &self,
        session: &ExportedSession,
        agent_id: &str,
    ) -> Result<String, BackendError> {
        // Fail closed BEFORE uploading anything: a share with no page to view
        // it on is not a share, and no host is ever invented for the link.
        let web_url = self.share_link_origin()?;
        self.upsert_session(&session.session_id, &session.metadata, agent_id)
            .await?;
        match self
            .save_session_data(
                &session.session_id,
                &session.messages,
                Some(&session.metadata),
            )
            .await
        {
            Ok(()) => {}
            Err(BackendError::RequestFailed { status: 413, .. }) => {
                tracing::warn!(
                    session_id = %session.session_id,
                    "Backend returned 413 for save_session_data; \
                     session data should already be in GCS via signed URL"
                );
            }
            Err(e) => return Err(e),
        }
        let share_response = self.create_share_link(&session.session_id).await?;
        Ok(share_url_on(&web_url, &share_response.permission_id))
    }
    /// Must include X-XAI-Token-Auth so nginx auth subrequest routes to OAuth.
    /// See: crates/codegen/fuigo-shell/src/agent/app.rs:run_headless
    async fn auth_header_map(&self) -> Result<reqwest::header::HeaderMap, BackendError> {
        use reqwest::header::{HeaderMap, HeaderValue};
        let auth = self.resolve_auth().await?;
        let mut headers = HeaderMap::new();
        let required = |value: &str, name: &str| -> Result<HeaderValue, BackendError> {
            HeaderValue::from_str(value)
                .map_err(|e| BackendError::Auth(format!("invalid {name} header: {e}")))
        };
        headers.insert(
            "X-XAI-Token-Auth",
            required(&FuigoComConfig::default().token_header, "X-XAI-Token-Auth")?,
        );
        headers.insert("x-userid", required(&auth.user_id, "x-userid")?);
        if let Some(email) = &auth.email
            && let Ok(v) = HeaderValue::from_str(email)
        {
            headers.insert("x-email", v);
        }
        if let Ok(v) = HeaderValue::from_str(&crate::http::process_client_identifier()) {
            headers.insert("x-fuigo-client-identifier", v);
        }
        headers.insert(
            crate::http::CLIENT_MODE_HEADER,
            HeaderValue::from_static(crate::http::process_client_mode()),
        );
        headers.insert(
            "x-fuigo-client-version",
            HeaderValue::from_static(fuigo_version::VERSION),
        );
        Ok(headers)
    }
    /// The request `send_with_auth` sends. P43: the auth header map carries identity
    /// (`x-userid`, `x-email`, client labels); the destination is final only once the request
    /// is built, so the withholding happens here, on the request that goes on the wire.
    async fn authed_request(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::Request, BackendError> {
        let headers = self.auth_header_map().await?;
        let builder = fuigo_file_utils::trace_context::inject_trace_context_into_request(
            builder.timeout(DEFAULT_TIMEOUT).headers(headers),
        );
        let mut request = builder.build()?;
        fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_destination(request.url().as_str())
            .withhold_from_header_map(request.headers_mut());
        Ok(request)
    }
    async fn send_with_auth(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, BackendError> {
        let request = self.authed_request(builder).await?;
        self.client.execute(request).await.map_err(|e| match e {
            reqwest_middleware::Error::Reqwest(e) => BackendError::Network(e),
            reqwest_middleware::Error::Middleware(e) => middleware_error(e),
        })
    }
    pub async fn upsert_session(
        &self,
        session_id: &str,
        metadata: &ExportedMetadata,
        agent_id: &str,
    ) -> Result<(), BackendError> {
        let url = format!("{}/sessions/{}", self.base()?, session_id);
        let request = upsert_session_request(&url, metadata, agent_id);
        let response = self
            .send_with_auth(self.reqwest_client.put(&url).json(&request))
            .await?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(BackendError::RequestFailed { status, body });
        }
        Ok(())
    }
    /// Uploads a session's messages. Compaction checkpoints ride along as `_fuigo/compaction_checkpoint` messages; if
    /// the backend refuses the save with a client error (an unknown method, a larger body), the save is retried once
    /// without them, so a backend that predates them still stores every normal message. 401, 403, 408 and 429 are
    /// auth or transient failures, not refusals, and are returned as before.
    pub(crate) async fn save_session_data(
        &self,
        session_id: &str,
        messages: &[ExportedMessage],
        metadata: Option<&ExportedMetadata>,
    ) -> Result<(), BackendError> {
        let has_checkpoints = messages.iter().any(ExportedMessage::is_compaction_checkpoint);
        if !has_checkpoints {
            return self.post_session_data(session_id, messages, metadata).await;
        }
        let only_checkpoints = messages.iter().all(ExportedMessage::is_compaction_checkpoint);
        if CHECKPOINTS_REFUSED.load(std::sync::atomic::Ordering::Relaxed) {
            if only_checkpoints {
                // Nothing but checkpoints is left once they are filtered out: there is nothing to send.
                return Ok(());
            }
            return self.post_without_checkpoints(session_id, messages, metadata).await;
        }
        match self.post_session_data(session_id, messages, metadata).await {
            Err(BackendError::RequestFailed { status, .. }) if is_checkpoint_refusal(status) => {
                // A batch of only checkpoints has no retry to prove anything with: a 4xx on it is the refusal, and
                // the checkpoint is dropped from the pending set instead of being posted again on every flush.
                if !only_checkpoints {
                    self.post_without_checkpoints(session_id, messages, metadata).await?;
                }
                // Remember only once the retry proved the checkpoints were the problem.
                // A 413 may mean only this one was too large, so it does not disable later (smaller) checkpoints.
                let first = status == 413
                    || !CHECKPOINTS_REFUSED.swap(true, std::sync::atomic::Ordering::Relaxed);
                if first {
                    tracing::warn!(
                        status,
                        "backend refused compaction checkpoints; the compaction summary is not stored remotely \
                         (a session pulled from remote storage will resume without it)"
                    );
                }
                Ok(())
            }
            other => other,
        }
    }
    async fn post_without_checkpoints(
        &self,
        session_id: &str,
        messages: &[ExportedMessage],
        metadata: Option<&ExportedMetadata>,
    ) -> Result<(), BackendError> {
        let kept: Vec<ExportedMessage> = messages
            .iter()
            .filter(|m| !m.is_compaction_checkpoint())
            .cloned()
            .collect();
        self.post_session_data(session_id, &kept, metadata).await
    }
    async fn post_session_data(
        &self,
        session_id: &str,
        messages: &[ExportedMessage],
        metadata: Option<&ExportedMetadata>,
    ) -> Result<(), BackendError> {
        let url = format!("{}/sessions/{}/data", self.base()?, session_id);
        let request = SaveDataRequest {
            messages: messages.to_vec(),
            metadata: metadata.and_then(|m| serde_json::to_value(m).ok()),
        };
        let response = self
            .send_with_auth(self.reqwest_client.post(&url).json(&request))
            .await?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(BackendError::RequestFailed { status, body });
        }
        Ok(())
    }
    pub async fn list_sessions(&self) -> Result<Vec<SessionInfo>, BackendError> {
        let url = format!("{}/sessions", self.base()?);
        let response = self.send_with_auth(self.reqwest_client.get(&url)).await?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(BackendError::RequestFailed { status, body });
        }
        #[derive(Deserialize)]
        struct ListResponse {
            sessions: Vec<SessionInfo>,
        }
        let data: ListResponse = response.json().await?;
        Ok(data.sessions)
    }
    pub(crate) async fn load_session_data(
        &self,
        session_id: &str,
    ) -> Result<LoadDataResponse, BackendError> {
        let url = format!("{}/sessions/{}/data", self.base()?, session_id);
        let response = self.send_with_auth(self.reqwest_client.get(&url)).await?;
        if response.status().as_u16() == 404 {
            return Err(BackendError::SessionNotFound {
                session_id: session_id.to_string(),
            });
        }
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(BackendError::RequestFailed { status, body });
        }
        let data: LoadDataResponse = response.json().await?;
        Ok(data)
    }
    pub(crate) async fn create_share_link(
        &self,
        session_id: &str,
    ) -> Result<ShareResponse, BackendError> {
        let url = format!("{}/sessions/{}/share", self.base()?, session_id);
        let response = self.send_with_auth(self.reqwest_client.post(&url)).await?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(BackendError::RequestFailed { status, body });
        }
        let share_response: ShareResponse = response.json().await?;
        Ok(share_response)
    }
    pub(crate) async fn delete_session_data(&self, session_id: &str) -> Result<(), BackendError> {
        let url = format!("{}/sessions/{}/data", self.base()?, session_id);
        let response = self
            .send_with_auth(self.reqwest_client.delete(&url))
            .await?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(BackendError::RequestFailed { status, body });
        }
        Ok(())
    }
}
/// Distinguishes the three cases the external-OTEL gate cares about (see [`crate::agent::mvp_agent`]).
#[derive(Debug, Clone)]
#[must_use]
#[non_exhaustive]
pub enum SettingsFetch {
    /// Settings fetched and parsed; carries the policy that resolves the gate.
    /// Boxed because `RemoteSettings` is large and the other variants are unit-sized.
    Fetched(Box<crate::util::config::RemoteSettings>),
    /// Credential unambiguously rejected (401): the remote policy will never reach this leader, so the gate may open without waiting.
    Rejected,
    /// Transient/ambiguous (network, 5xx exhausted, 403/429/other 4xx, unparseable 2xx): outcome unknown.
    /// Leave the gate closed (fail-closed), retry later.
    Retry,
    /// P47: the settings URL may not receive the session token, so nothing was sent. Terminal like `Rejected` (no
    /// remote policy can reach this leader) but NOT a credential rejection: no auth recovery, no re-fetch. Carries
    /// the refusal text (origin and remedy).
    DestinationRefused(String),
}
impl SettingsFetch {
    /// For callers that only want the settings and treat every failure alike.
    pub fn into_option(self) -> Option<crate::util::config::RemoteSettings> {
        match self {
            SettingsFetch::Fetched(s) => Some(*s),
            SettingsFetch::Rejected | SettingsFetch::Retry | SettingsFetch::DestinationRefused(_) => {
                None
            }
        }
    }
}
/// Makes up to [`crate::http::SETTINGS_FETCH_MAX_ATTEMPTS`] attempts on transient failures.
pub fn fetch_settings_blocking(
    cli_chat_proxy_base_url: &str,
    auth: &FuigoAuth,
    alpha_test_key: Option<&str>,
) -> SettingsFetch {
    fetch_settings_blocking_with_attempts(
        cli_chat_proxy_base_url,
        auth,
        alpha_test_key,
        crate::http::SETTINGS_FETCH_MAX_ATTEMPTS,
    )
}
/// Private so the attempt count stays out of the public API; tests use it to skip retry backoff on the transient-failure paths.
fn fetch_settings_blocking_with_attempts(
    cli_chat_proxy_base_url: &str,
    auth: &FuigoAuth,
    alpha_test_key: Option<&str>,
    max_attempts: u32,
) -> SettingsFetch {
    let client = crate::http::shared_startup_blocking_client();
    let url = format!("{cli_chat_proxy_base_url}/settings");
    // P47: the session token goes only where the service-endpoint trust class admits `/settings`. A refused
    // destination is terminal (no retry can change it) and distinct from a 401: the request is not made, the
    // refusal is logged with its remedy, and no auth recovery runs.
    if let Err(refused) = crate::auth::session_delivery::service_session_gate(
        auth,
        &url,
        Some(cli_chat_proxy_base_url),
        "remote_settings",
    ) {
        return SettingsFetch::DestinationRefused(refused.to_string());
    }
    let max_attempts = max_attempts.max(1);
    for attempt in 0u32..max_attempts {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(500 * u64::from(attempt)));
        }
        let request =
            add_cli_chat_proxy_headers_blocking(client.get(&url), auth, alpha_test_key, &url);
        match fuigo_extra_ca::dispatch::send_blocking(request) {
            Ok(resp) if resp.status().is_success() => match resp.json() {
                Ok(settings) => {
                    tracing::debug!("Fetched remote settings from cli-chat-proxy");
                    return SettingsFetch::Fetched(Box::new(settings));
                }
                Err(e) => {
                    tracing::warn!(attempt, "Failed to parse settings response: {e}");
                    return SettingsFetch::Retry;
                }
            },
            Ok(resp) if resp.status().is_server_error() => {
                tracing::warn!(
                    attempt,
                    status = resp.status().as_u16(),
                    "Settings fetch server error, retrying"
                );
                continue;
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::UNAUTHORIZED => {
                tracing::warn!(
                    status = resp.status().as_u16(),
                    "Settings fetch rejected (401)"
                );
                return SettingsFetch::Rejected;
            }
            Ok(resp) => {
                tracing::warn!(
                    status = resp.status().as_u16(),
                    "Settings fetch failed (non-2xx)"
                );
                return SettingsFetch::Retry;
            }
            Err(fuigo_extra_ca::dispatch::DispatchError::Denied(reason)) => {
                tracing::warn!("Settings fetch blocked by egress policy: {reason}");
                // Keep existing cached settings; policy denial is not a 401.
                return SettingsFetch::Retry;
            }
            Err(fuigo_extra_ca::dispatch::DispatchError::Transport(e)) => {
                tracing::warn!(attempt, "Settings fetch network error: {e}");
                continue;
            }
        }
    }
    tracing::error!(max_attempts, "Settings fetch failed");
    SettingsFetch::Retry
}
#[derive(Deserialize)]
struct LoginConfigResponse {
    /// Tri-state: `Some` forces a transport; `None` or an absent flag keeps the client default.
    #[serde(default)]
    device_flow: Option<bool>,
}
/// The `GET /login-config` request. P43: the persisted machine id (`x-fuigo-agent-id`), the
/// client version and the client identifier go only to a FluxRouter-operated destination.
fn login_config_request(
    client: &reqwest::Client,
    url: &str,
    agent_id: &str,
) -> reqwest::RequestBuilder {
    let identity = fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_destination(url);
    let client_identifier = crate::http::process_client_identifier();
    client
        .get(url)
        .timeout(std::time::Duration::from_millis(1500))
        .headers(identity.header_map([
            ("x-fuigo-agent-id", agent_id),
            ("x-fuigo-client-version", fuigo_version::VERSION),
            ("x-fuigo-client-identifier", client_identifier.as_str()),
        ]))
        .header(
            crate::http::CLIENT_MODE_HEADER,
            crate::http::process_client_mode(),
        )
}
/// Fetch `fuigo_build_login_device_flow` from cli-chat-proxy `GET /v1/login-config`.
///
/// Unauthenticated (pre-login); `x-fuigo-agent-id` is the per-install bucketing key.
/// Best-effort: any error or unset flag returns `None` so the caller keeps the loopback default.
/// Caps at 1.5s with no retries since it's on the login path.
pub async fn fetch_login_device_flow(cli_chat_proxy_base_url: &str) -> Option<bool> {
    let agent_id = tokio::task::spawn_blocking(fuigo_telemetry::id::agent_id)
        .await
        .ok()?;
    let url = format!("{}/login-config", cli_chat_proxy_base_url);
    let response = fuigo_extra_ca::dispatch::send(login_config_request(
        &crate::http::shared_client(),
        &url,
        &agent_id,
    ))
    .await;
    let resp = match response {
        Ok(resp) if resp.status().is_success() => resp,
        Ok(resp) => {
            tracing::debug!(status = resp.status().as_u16(), "login-config fetch failed");
            return None;
        }
        Err(e) => {
            tracing::debug!("login-config fetch error: {e}");
            return None;
        }
    };
    match resp.json::<LoginConfigResponse>().await {
        Ok(cfg) => {
            tracing::debug!(device_flow = ?cfg.device_flow, "Fetched remote login-config");
            cfg.device_flow
        }
        Err(e) => {
            tracing::debug!("Failed to parse login-config response: {e}");
            None
        }
    }
}
/// Default context window when the remote endpoint doesn't provide one.
pub(crate) const DEFAULT_CONTEXT_WINDOW: u64 = 256_000;
pub struct FetchModelsResult {
    pub models: Vec<crate::agent::config::ModelEntryConfig>,
    pub etag: Option<String>,
}
/// Parse a single model entry from the /models-v2 response.
/// Used by both initial model fetch and session-resume metadata refresh.
pub(crate) fn parse_remote_model_value(
    value: &serde_json::Value,
    default_base_url: &str,
) -> Option<crate::agent::config::ModelEntryConfig> {
    let obj = value.as_object()?;
    let meta = obj.get("_meta").and_then(|v| v.as_object());
    let id = get_string(obj, "id");
    let model = get_string(obj, "model")
        .or_else(|| get_string(obj, "modelId"))
        .or_else(|| id.clone())
        .or_else(|| meta.and_then(|m| get_string(m, "model")))
        .or_else(|| meta.and_then(|m| get_string(m, "modelId")))?;
    let model_family = get_string(obj, "modelFamily")
        .or_else(|| get_string(obj, "model_family"))
        .or_else(|| meta.and_then(|m| get_string(m, "modelFamily")))
        .or_else(|| meta.and_then(|m| get_string(m, "model_family")));
    let base_url = get_string(obj, "baseUrl")
        .or_else(|| get_string(obj, "base_url"))
        .unwrap_or_else(|| default_base_url.to_owned());
    let name = get_string(obj, "name").or_else(|| Some(model.clone()));
    let context_window = get_u64(obj, "contextWindow")
        .or_else(|| get_u64(obj, "context_window"))
        .or_else(|| meta.and_then(|m| get_u64(m, "contextWindow")))
        .or_else(|| meta.and_then(|m| get_u64(m, "totalContextTokens")))
        .unwrap_or(DEFAULT_CONTEXT_WINDOW);
    let context_window = std::num::NonZeroU64::new(context_window)?;
    let agent_type = get_string(obj, "systemPromptType")
        .or_else(|| get_string(obj, "system_prompt_type"))
        .or_else(|| get_string(obj, "agent_type"))
        .or_else(|| get_string(obj, "agentType"))
        .or_else(|| meta.and_then(|m| get_string(m, "agentType")))
        .or_else(|| meta.and_then(|m| get_string(m, "agent_type")))
        .unwrap_or_else(crate::agent::config::default_agent_type);
    let api_backend = get_string(obj, "apiBackend")
        .or_else(|| get_string(obj, "api_backend"))
        .and_then(|s| match s.as_str() {
            "responses" => Some(crate::sampling::ApiBackend::Responses),
            "chat_completions" => Some(crate::sampling::ApiBackend::ChatCompletions),
            "messages" => Some(crate::sampling::ApiBackend::Messages),
            _ => None,
        })
        .unwrap_or_default();
    Some(crate::agent::config::ModelEntryConfig {
        id,
        model,
        model_family,
        base_url,
        name,
        description: get_string(obj, "description"),
        max_completion_tokens: get_u64(obj, "maxCompletionTokens")
            .or_else(|| get_u64(obj, "max_completion_tokens"))
            .and_then(|v| u32::try_from(v).ok()),
        temperature: get_f64(obj, "temperature").map(|v| v as f32),
        top_p: get_f64(obj, "topP").or_else(|| get_f64(obj, "top_p")).map(|v| v as f32),
        api_key: get_string(obj, "apiKey").or_else(|| get_string(obj, "api_key")),
        env_key: get_env_keys(obj, "envKey").or_else(|| get_env_keys(obj, "env_key")),
        api_backend,
        context_window,
        auto_compact_threshold_percent: get_u64(obj, "autoCompactThresholdPercent")
            .or_else(|| get_u64(obj, "auto_compact_threshold_percent"))
            .and_then(|v| u8::try_from(v).ok()),
        system_prompt_label: get_string(obj, "systemPromptLabel")
            .or_else(|| get_string(obj, "system_prompt_label"))
            .filter(|s| !s.trim().is_empty()),
        extra_headers: get_string_map(obj, "extraHeaders"),
        api_base_url: get_string(obj, "apiBaseUrl")
            .or_else(|| get_string(obj, "api_base_url")),
        use_concise: obj
            .get("useConcise")
            .or_else(|| obj.get("use_concise"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        agent_type,
        inference_idle_timeout_secs: get_u64(obj, "inferenceIdleTimeoutSecs")
            .or_else(|| get_u64(obj, "inference_idle_timeout_secs")),
        max_retries: get_u64(obj, "maxRetries")
            .or_else(|| get_u64(obj, "max_retries"))
            .and_then(|v| u32::try_from(v).ok()),
        subagent_rate_limit_max_attempts: get_u64(obj, "subagentRateLimitMaxAttempts")
            .or_else(|| get_u64(obj, "subagent_rate_limit_max_attempts"))
            .and_then(|v| u32::try_from(v).ok()),
        hidden: obj
            .get("hidden")
            .or_else(|| meta.and_then(|m| m.get("hidden")))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        supported_in_api: obj
            .get("supportedInApi")
            .or_else(|| obj.get("supported_in_api"))
            .or_else(|| meta.and_then(|m| m.get("supportedInApi")))
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        auth_scheme: None,
        reasoning_effort: get_string(obj, "reasoningEffort")
            .or_else(|| get_string(obj, "reasoning_effort"))
            .or_else(|| meta.and_then(|m| get_string(m, "reasoningEffort")))
            .and_then(|s| s.parse().ok()),
        supports_reasoning_effort: obj
            .get("supportsReasoningEffort")
            .or_else(|| obj.get("supports_reasoning_effort"))
            .or_else(|| meta.and_then(|m| m.get("supportsReasoningEffort")))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        reasoning_efforts: obj
            .get("reasoningEfforts")
            .or_else(|| obj.get("reasoning_efforts"))
            .or_else(|| meta.and_then(|m| m.get("reasoningEfforts")))
            .and_then(|v| v.as_array())
            .map(|arr| fuigo_sampling_types::parse_reasoning_effort_options(arr))
            .unwrap_or_default(),
        variants: obj
            .get("variants")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr
                    .iter()
                    .filter_map(|value| match serde_json::from_value(value.clone()) {
                        Ok(variant) => Some(variant),
                        Err(e) => {
                            tracing::warn!("Dropping a model variant this build cannot read: {e}");
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default(),
        supports_backend_search: obj
            .get("supportsBackendSearch")
            .or_else(|| obj.get("supports_backend_search"))
            .or_else(|| meta.and_then(|m| m.get("supportsBackendSearch")))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        programmatic_tool_calling: obj
            .get("programmaticToolCalling")
            .or_else(|| obj.get("programmatic_tool_calling"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        compactions_remaining: obj
            .get("compactionsRemaining")
            .or_else(|| obj.get("compactions_remaining"))
            .or_else(|| meta.and_then(|m| m.get("compactionsRemaining")))
            .and_then(parse_compactions_remaining)
            .or_else(|| {
                obj
                    .get("sendCompactionsRemaining")
                    .or_else(|| obj.get("send_compactions_remaining"))
                    .or_else(|| meta.and_then(|m| m.get("sendCompactionsRemaining")))
                    .and_then(|v| v.as_bool())
                    .map(fuigo_sampling_types::CompactionsRemaining::Dynamic)
            }),
        compaction_at_tokens: obj
            .get("compactionAtTokens")
            .or_else(|| obj.get("compaction_at_tokens"))
            .or_else(|| meta.and_then(|m| m.get("compactionAtTokens")))
            .and_then(parse_compaction_at_tokens),
        show_model_fingerprint: obj
            .get("showModelFingerprint")
            .or_else(|| obj.get("show_model_fingerprint"))
            .or_else(|| meta.and_then(|m| m.get("showModelFingerprint")))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        stream_tool_calls: obj
            .get("streamToolCalls")
            .or_else(|| obj.get("stream_tool_calls"))
            .and_then(|v| v.as_bool()),
        laziness_detector: get_object(obj, "lazinessDetector")
            .or_else(|| get_object(obj, "laziness_detector"))
            .or_else(|| meta.and_then(|m| get_object(m, "lazinessDetector")))
            .and_then(|v| match serde_json::from_value::<
                crate::agent::config::LazinessDetectorPerModelConfig,
            >(v.clone()) {
                Ok(cfg) => Some(cfg),
                Err(e) => {
                    tracing::warn!(
                            error = %e,
                            "Failed to deserialize laziness_detector block from remote model; falling back to default"
                        );
                    None
                }
            })
            .unwrap_or_default(),
        rate_limit_retry_threshold: None,
        reasoning_summary: None,
    })
}
fn get_string(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    obj.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}
/// Parse `env_key` / `envKey` as a single string or a string array.
fn get_env_keys(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<crate::agent::config::EnvKeys> {
    let v = obj.get(key)?;
    if let Some(s) = v.as_str() {
        return Some(crate::agent::config::EnvKeys::single(s));
    }
    if let Some(arr) = v.as_array() {
        let mut names = Vec::with_capacity(arr.len());
        for item in arr {
            let Some(s) = item.as_str() else {
                tracing::warn!(
                    key,
                    "env_key array has a non-string element; ignoring env_key"
                );
                return None;
            };
            if !s.is_empty() {
                names.push(s.to_owned());
            }
        }
        if names.is_empty() {
            return None;
        }
        return Some(crate::agent::config::EnvKeys::new(names));
    }
    None
}
fn parse_compaction_at_tokens(
    v: &serde_json::Value,
) -> Option<fuigo_sampling_types::CompactionAtTokens> {
    use fuigo_sampling_types::CompactionAtTokens;
    v.as_bool()
        .map(CompactionAtTokens::Enabled)
        .or_else(|| v.as_u64().map(CompactionAtTokens::Fixed))
}
fn parse_compactions_remaining(
    v: &serde_json::Value,
) -> Option<fuigo_sampling_types::CompactionsRemaining> {
    use fuigo_sampling_types::CompactionsRemaining;
    v.as_bool().map(CompactionsRemaining::Dynamic).or_else(|| {
        v.as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .map(CompactionsRemaining::Fixed)
    })
}
fn get_u64(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u64> {
    obj.get(key).and_then(|v| v.as_u64())
}
fn get_f64(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<f64> {
    obj.get(key).and_then(|v| v.as_f64())
}
fn get_object<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a serde_json::Value> {
    obj.get(key).filter(|v| v.is_object())
}
fn get_string_map(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> IndexMap<String, String> {
    obj.get(key)
        .and_then(|v| v.as_object())
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}
#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;

#[cfg(test)]
mod egress_policy_tests {
    use super::*;
    #[test]
    fn egress_policy_denial_preserves_its_category() {
        let error = BackendError::from(fuigo_extra_ca::dispatch::DispatchError::Denied("blocked"));
        assert!(matches!(error, BackendError::Policy("blocked")));
    }
}
