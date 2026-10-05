//! HTTP client for managing sandbox sessions and environments via the cli-chat-proxy REST API.

use fuigo_extra_ca::dispatch::AsyncRequestBuilderExt as _;
use std::sync::Arc;

use crate::auth::{AuthManager, FuigoComConfig};
use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;

// Re-export sandbox API types from cli-chat-proxy-types for convenience.
// Sorted alphabetically; see sandbox_types.rs for logical grouping.
pub use prod_mc_cli_chat_proxy_types::{
    SandboxCreateEnvironmentRequest, SandboxEnvironment, SandboxEnvironmentResponse,
    SandboxEnvironmentVariable, SandboxEnvironmentWithMetadata, SandboxForkRequest,
    SandboxForkResponse, SandboxForkedSession, SandboxHibernateResponse,
    SandboxListEnvironmentsRequest, SandboxListEnvironmentsResponse,
    SandboxListPreinstalledPackagesResponse, SandboxLogsExitCodes, SandboxLogsResponse,
    SandboxMode, SandboxPreinstalledPackage, SandboxRestoreRequest, SandboxRestoreResponse,
    SandboxSecretInput, SandboxStartRequest, SandboxStartResponse, SandboxStatusResponse,
    SandboxTerminateRequest, SandboxUpdateEnvironmentRequest,
};

// ============================================================================
// Sandbox Client
// ============================================================================

/// HTTP client for interacting with the sandbox API via cli-chat-proxy.
///
/// Path parameters (`session_id`, `environment_id`) are interpolated directly into URLs without percent-encoding.
/// This is safe because these IDs are UUIDs in practice.
/// If ID formats ever change to include URL-unsafe characters, the `format!()` calls should be updated to use percent-encoding.
pub struct SandboxClient {
    client: reqwest::Client,
    base_url: String,
    auth_manager: Arc<AuthManager>,
}

impl SandboxClient {
    pub fn new(base_url: impl Into<String>, auth_manager: Arc<AuthManager>) -> Self {
        Self {
            client: crate::http::shared_client(),
            base_url: base_url.into(),
            auth_manager,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    // Do not set Content-Type: callers use .json() and reqwest .header() appends
    /// P47: the session token goes only where the service-endpoint trust class admits `url` (with the
    /// configured cli-chat-proxy base this client was built with); otherwise the request is not made.
    async fn auth_headers(
        &self,
        builder: reqwest::RequestBuilder,
        url: &str,
    ) -> Result<reqwest::RequestBuilder> {
        let auth = self
            .auth_manager
            .auth()
            .await
            .context("failed to resolve sandbox auth")?;
        crate::auth::session_delivery::service_session_gate(
            &auth,
            url,
            Some(&self.base_url),
            "sandbox",
        )?;
        // P43: identity only to a FluxRouter-operated destination.
        let identity = super::account_identity_headers(&self.base_url, &auth.user_id, auth.email.as_deref());
        let builder = builder
            .header("Authorization", format!("Bearer {}", &auth.key))
            .header("X-XAI-Token-Auth", FuigoComConfig::default().token_header)
            .headers(identity)
            .header(
                crate::http::CLIENT_MODE_HEADER,
                crate::http::process_client_mode(),
            );

        Ok(fuigo_file_utils::trace_context::inject_trace_context_into_request(builder))
    }

    /// Check an HTTP response for errors, then deserialize the JSON body.
    async fn parse_response<T: DeserializeOwned>(
        response: reqwest::Response,
        operation: &str,
    ) -> Result<T> {
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            bail!("{operation} failed: {status} - {body}");
        }
        response
            .json()
            .await
            .with_context(|| format!("failed to parse {operation} response"))
    }

    /// Check an HTTP response for errors, discarding the body.
    async fn check_response(response: reqwest::Response, operation: &str) -> Result<()> {
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            bail!("{operation} failed: {status} - {body}");
        }
        Ok(())
    }

    pub async fn fork_session(&self, request: &SandboxForkRequest) -> Result<SandboxForkResponse> {
        let url = format!("{}/sandbox/sessions/fork", self.base_url);
        let response = self
            .auth_headers(self.client.post(&url), &url)
            .await?
            .json(request)
            .send_checked()
            .await
            .context("failed to send fork session request")?;
        Self::parse_response(response, "fork session").await
    }

    pub(crate) async fn terminate_session(
        &self,
        session_id: &str,
        request: &SandboxTerminateRequest,
    ) -> Result<()> {
        let mut url = format!("{}/sandbox/sessions/{}", self.base_url, session_id);
        if let Some(env_id) = &request.environment_id {
            url = format!("{}?environmentId={}", url, env_id);
        }

        let response = self
            .auth_headers(self.client.delete(&url), &url)
            .await?
            .send_checked()
            .await
            .context("failed to send terminate session request")?;

        if response.status().as_u16() == 404 {
            bail!("session not found: {session_id}");
        }
        Self::check_response(response, "terminate session").await
    }

    // ========================================================================
    // Session Lifecycle
    // ========================================================================

    // ========================================================================
    // Environment CRUD
    // ========================================================================

    pub async fn list_environments(
        &self,
        request: &SandboxListEnvironmentsRequest,
    ) -> Result<SandboxListEnvironmentsResponse> {
        let url = format!("{}/sandbox/environments", self.base_url);
        let mut builder = self.auth_headers(self.client.get(&url), &url).await?;
        if let Some(page) = request.page {
            builder = builder.query(&[("page", page)]);
        }
        if let Some(page_size) = request.page_size {
            builder = builder.query(&[("pageSize", page_size)]);
        }
        let response = builder
            .send_checked()
            .await
            .context("failed to send list environments request")?;
        Self::parse_response(response, "list environments").await
    }

    pub(crate) async fn create_environment(
        &self,
        request: &SandboxCreateEnvironmentRequest,
    ) -> Result<SandboxEnvironmentResponse> {
        let url = format!("{}/sandbox/environments", self.base_url);
        let response = self
            .auth_headers(self.client.post(&url), &url)
            .await?
            .json(request)
            .send_checked()
            .await
            .context("failed to send create environment request")?;
        Self::parse_response(response, "create environment").await
    }

    pub(crate) async fn update_environment(
        &self,
        environment_id: &str,
        request: &SandboxUpdateEnvironmentRequest,
    ) -> Result<SandboxEnvironmentResponse> {
        let url = format!("{}/sandbox/environments/{}", self.base_url, environment_id);
        let response = self
            .auth_headers(self.client.put(&url), &url)
            .await?
            .json(request)
            .send_checked()
            .await
            .context("failed to send update environment request")?;
        Self::parse_response(response, "update environment").await
    }

    pub(crate) async fn delete_environment(&self, environment_id: &str) -> Result<()> {
        let url = format!("{}/sandbox/environments/{}", self.base_url, environment_id);
        let response = self
            .auth_headers(self.client.delete(&url), &url)
            .await?
            .send_checked()
            .await
            .context("failed to send delete environment request")?;
        Self::check_response(response, "delete environment").await
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    /// P43 hostile: a sandbox host that is not FluxRouter-operated gets no identity.
    #[tokio::test(flavor = "current_thread")]
    async fn sandbox_requests_send_no_identity_to_a_non_fluxrouter_host() {
        let Some(front) = crate::test_support::session_wire::fronted_child(
            "remote::agent::identity_tests::sandbox_requests_send_no_identity_to_a_non_fluxrouter_host",
        ) else {
            return;
        };
        // Alone in its process: install the issuer no other test happened to install here.
        crate::auth::set_test_oauth2_issuer(crate::auth::GROK_OAUTH2_ISSUER);
        let (base, seen, handle) =
            crate::remote::identity_tests::spawn_recording_mock("{}").await;
            let base = front.front_service(&base);
        let client = SandboxClient::new(base, crate::remote::skills_client::tests::test_auth_manager());
        let _ = client
            .list_environments(&SandboxListEnvironmentsRequest::default())
            .await;
        handle.abort();
        crate::remote::identity_tests::assert_no_identity(&seen, "sandbox");
    }
}
