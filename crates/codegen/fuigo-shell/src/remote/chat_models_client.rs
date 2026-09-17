//! The grok.com chat model catalog (`POST /rest/modes`): the models fuigo-web's chat picker shows, distinct from the CLI `/v1/models` build catalog.
//! Transport only; the cache and the ACP mapping live in [`crate::agent::chat_modes`].

use fuigo_extra_ca::dispatch::AsyncRequestBuilderExt as _;
use std::sync::Arc;

use serde::Deserialize;

use crate::auth::AuthManager;

/// Env vars that can name the chat-models host, in precedence order.
///
/// No compiled default (upstream: the vendor's web origin). With none set the
/// chat model catalog is not available and [`ChatModelsError::NotConfigured`] says so.
pub(crate) const MODES_BASE_URL_ENV_CHAIN: [&str; 3] = [
    "FUIGO_MODES_BASE_URL",
    "FUIGO_CONVERSATIONS_BASE_URL",
    "FUIGO_CODE_WEB_URL",
];

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mode {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub badge_text: Option<String>,
    #[serde(default)]
    pub availability: ModeAvailability,
    #[serde(default)]
    pub icon_hint: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Mode {
    pub fn is_available(&self) -> bool {
        self.availability.available.is_some()
    }
}

/// proto3-JSON oneof: exactly one field is present.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModeAvailability {
    #[serde(default)]
    pub available: Option<serde_json::Value>,
    #[serde(default)]
    pub unavailable: Option<serde_json::Value>,
    #[serde(default)]
    pub requires_upgrade: Option<serde_json::Value>,
    #[serde(default)]
    pub coming_soon: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListModesResponse {
    #[serde(default)]
    pub modes: Vec<Mode>,
    #[serde(default)]
    pub default_mode_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ChatModelsError {
    #[error("no Fuigo credentials")]
    NoAuth,
    /// No chat-models host is configured; the catalog is unavailable rather than pointed at a vendor.
    #[error(
        "the chat model catalog needs FUIGO_MODES_BASE_URL (or FUIGO_CODE_WEB_URL) to be configured; it is not available otherwise"
    )]
    NotConfigured,
    #[error("request timed out")]
    Timeout,
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("request blocked by egress policy: {0}")]
    Policy(&'static str),
    #[error("request failed: {status}")]
    Http { status: u16 },
    #[error("parse error: {0}")]
    Parse(#[from] serde_json::Error),
}

impl From<fuigo_extra_ca::dispatch::DispatchError> for ChatModelsError {
    fn from(error: fuigo_extra_ca::dispatch::DispatchError) -> Self {
        match error {
            fuigo_extra_ca::dispatch::DispatchError::Denied(reason) => Self::Policy(reason),
            fuigo_extra_ca::dispatch::DispatchError::Transport(error) => Self::Network(error),
        }
    }
}

/// Stateless transport for `POST /rest/modes`; caching lives in [`crate::agent::chat_modes::ChatModesManager`].
pub struct ChatModelsClient {
    http: reqwest::Client,
    /// `None` when no env var in [`MODES_BASE_URL_ENV_CHAIN`] is set: every
    /// request fails closed with [`ChatModelsError::NotConfigured`].
    base_url: Option<String>,
    auth: Arc<AuthManager>,
}

impl ChatModelsClient {
    pub fn new(auth: Arc<AuthManager>) -> Self {
        Self {
            http: crate::http::shared_client(),
            base_url: super::skills_client::first_nonempty_env(&MODES_BASE_URL_ENV_CHAIN),
            auth,
        }
    }

    /// The configured host, or the fail-closed error every request returns without one.
    fn base(&self) -> Result<&str, ChatModelsError> {
        self.base_url.as_deref().ok_or(ChatModelsError::NotConfigured)
    }

    /// Gated only on a valid grok.com bearer, not `is_fuigo_auth()` like workspaces/conversations.
    /// `/rest/modes` is the public chat endpoint, and that gate would exclude API-key and cached-token chat users.
    pub(crate) async fn list_modes(
        &self,
        locale: &str,
    ) -> Result<ListModesResponse, ChatModelsError> {
        let auth = self
            .auth
            .auth()
            .await
            .map_err(|_| ChatModelsError::NoAuth)?;
        let base = self.base()?;

        let url = format!("{}/rest/modes", base);
        let body = serde_json::json!({ "locale": locale });
        let mut builder = self
            .http
            .post(&url)
            .json(&body)
            .header("Authorization", format!("Bearer {}", auth.key))
            .header(
                "X-XAI-Token-Auth",
                self.auth.fuigo_com_config().token_header.clone(),
            )
            .header("x-userid", &auth.user_id)
            .header("x-fuigo-client-version", fuigo_version::VERSION)
            .header(
                "x-fuigo-client-identifier",
                crate::http::process_client_identifier(),
            )
            .header(
                crate::http::CLIENT_MODE_HEADER,
                crate::http::process_client_mode(),
            )
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(email) = &auth.email {
            builder = builder.header("x-email", email);
        }
        let builder = fuigo_file_utils::trace_context::inject_trace_context_into_request(builder);

        let response = builder.send_checked().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(ChatModelsError::Http {
                status: status.as_u16(),
            });
        }

        let bytes = response.bytes().await?;
        let resp: ListModesResponse = serde_json::from_slice(&bytes)?;
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_parse_camelcase_wire() {
        let json = serde_json::json!({
            "modes": [{
                "id": "auto",
                "title": "Auto",
                "description": "Picks the best model",
                "badgeText": "New",
                "availability": { "available": {} },
                "iconHint": "rocket",
                "tags": ["TAG_PRIMARY"]
            }, {
                "id": "heavy",
                "title": "Heavy",
                "availability": { "requiresUpgrade": { "message": "Upgrade" } }
            }],
            "defaultModeId": "auto"
        });
        let resp: ListModesResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.modes.len(), 2);
        assert_eq!(resp.default_mode_id, "auto");
        let auto = &resp.modes[0];
        assert_eq!(auto.id, "auto");
        assert_eq!(auto.title, "Auto");
        assert_eq!(auto.badge_text.as_deref(), Some("New"));
        assert_eq!(auto.icon_hint, "rocket");
        assert_eq!(auto.tags, vec!["TAG_PRIMARY".to_string()]);
        assert!(auto.is_available());
        assert!(!resp.modes[1].is_available());
    }

    #[test]
    fn missing_fields_default_gracefully() {
        let json = serde_json::json!({ "modes": [{ "id": "m1" }] });
        let resp: ListModesResponse = serde_json::from_value(json).unwrap();
        let m = &resp.modes[0];
        assert_eq!(m.id, "m1");
        assert!(m.title.is_empty());
        assert!(m.description.is_empty());
        assert!(m.badge_text.is_none());
        // With no availability field on the wire, the mode is not selectable
        assert!(!m.is_available());
        assert!(resp.default_mode_id.is_empty());
    }

    // ===== No vendor host as a default (1.0.20, REM-1 / REM-3) =====

    /// Row 4: with none of the env vars set the client resolves NO host.
    /// Upstream fell back to its vendor's web origin here.
    /// (Inspects `Debug` output only, so it compiles against the pre-fix `String` too.)
    #[test]
    #[serial_test::serial]
    fn chat_models_client_without_env_names_no_vendor_host() {
        let _a = fuigo_test_support::EnvGuard::unset("FUIGO_MODES_BASE_URL");
        let _b = fuigo_test_support::EnvGuard::unset("FUIGO_CONVERSATIONS_BASE_URL");
        let _c = fuigo_test_support::EnvGuard::unset("FUIGO_CODE_WEB_URL");
        let client =
            ChatModelsClient::new(crate::remote::skills_client::tests::test_auth_manager());
        let rendered = format!("{:?}", client.base_url);
        assert!(
            !rendered.contains("grok.com"),
            "chat models base fell back to a vendor host: {rendered}"
        );
    }

    /// Row 4, typed: unset means `None` and `list_modes` fails closed naming the variable.
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn chat_models_client_without_env_fails_closed_with_a_true_message() {
        let _a = fuigo_test_support::EnvGuard::unset("FUIGO_MODES_BASE_URL");
        let _b = fuigo_test_support::EnvGuard::unset("FUIGO_CONVERSATIONS_BASE_URL");
        let _c = fuigo_test_support::EnvGuard::unset("FUIGO_CODE_WEB_URL");
        let client =
            ChatModelsClient::new(crate::remote::skills_client::tests::test_auth_manager());
        assert_eq!(client.base_url, None);
        let err = client.list_modes("en").await.expect_err("no host, no request");
        let shown = err.to_string();
        assert!(matches!(err, ChatModelsError::NotConfigured), "{shown}");
        assert!(shown.contains("FUIGO_MODES_BASE_URL"), "{shown}");
        assert!(!shown.contains("grok.com"), "{shown}");
    }

    /// Row 4, set: precedence `FUIGO_MODES_BASE_URL` > `FUIGO_CONVERSATIONS_BASE_URL` > `FUIGO_CODE_WEB_URL`, verbatim.
    #[test]
    #[serial_test::serial]
    fn chat_models_client_env_chain_precedence_is_unchanged() {
        let am = crate::remote::skills_client::tests::test_auth_manager;
        let _web = fuigo_test_support::EnvGuard::set("FUIGO_CODE_WEB_URL", "https://web.example.test");
        assert_eq!(ChatModelsClient::new(am()).base_url.as_deref(), Some("https://web.example.test"));
        let _conv =
            fuigo_test_support::EnvGuard::set("FUIGO_CONVERSATIONS_BASE_URL", "https://conv.example.test");
        assert_eq!(ChatModelsClient::new(am()).base_url.as_deref(), Some("https://conv.example.test"));
        let _modes = fuigo_test_support::EnvGuard::set("FUIGO_MODES_BASE_URL", "https://modes.example.test");
        assert_eq!(ChatModelsClient::new(am()).base_url.as_deref(), Some("https://modes.example.test"));
    }
}

#[cfg(test)]
mod egress_policy_tests {
    use super::*;
    #[test]
    fn egress_policy_denial_preserves_its_category() {
        let error =
            ChatModelsError::from(fuigo_extra_ca::dispatch::DispatchError::Denied("blocked"));
        assert!(matches!(error, ChatModelsError::Policy("blocked")));
    }
}
