use fuigo_extra_ca::dispatch::AsyncRequestBuilderExt as _;
use std::sync::Arc;

use serde::Deserialize;

use crate::auth::AuthManager;

/// Env vars that can name the workspaces host, in precedence order.
///
/// No compiled default (upstream: the vendor's web origin). With none set the
/// workspaces list is not available and [`WsError::NotConfigured`] says so.
pub(crate) const WORKSPACES_BASE_URL_ENV_CHAIN: [&str; 3] = [
    "FUIGO_WORKSPACES_BASE_URL",
    "FUIGO_CONVERSATIONS_BASE_URL",
    "FUIGO_CODE_WEB_URL",
];

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    #[serde(default)]
    pub workspace_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub create_time: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct WsQuery {
    pub page_size: i64,
    pub page_token: Option<String>,
    pub query: Option<String>,
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ListWorkspacesPage {
    pub workspaces: Vec<Workspace>,
    pub next_page_token: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum WsError {
    #[error("no OAuth credentials for workspaces:read")]
    NoOauth,
    /// No workspaces host is configured; the feature is unavailable rather than pointed at a vendor.
    #[error(
        "the workspaces list needs FUIGO_WORKSPACES_BASE_URL (or FUIGO_CODE_WEB_URL) to be configured; it is not available otherwise"
    )]
    NotConfigured,
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("request blocked by egress policy: {0}")]
    Policy(&'static str),
    #[error("request failed: {status}")]
    Http { status: u16 },
    #[error("parse error: {0}")]
    Parse(#[from] serde_json::Error),
}

impl From<fuigo_extra_ca::dispatch::DispatchError> for WsError {
    fn from(error: fuigo_extra_ca::dispatch::DispatchError) -> Self {
        match error {
            fuigo_extra_ca::dispatch::DispatchError::Denied(reason) => Self::Policy(reason),
            fuigo_extra_ca::dispatch::DispatchError::Transport(error) => Self::Network(error),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListWorkspacesResponseWire {
    #[serde(default)]
    workspaces: Vec<Workspace>,
    #[serde(default)]
    next_page_token: Option<String>,
}

pub struct WorkspacesClient {
    http: reqwest::Client,
    /// `None` when no env var in [`WORKSPACES_BASE_URL_ENV_CHAIN`] is set: every
    /// request fails closed with [`WsError::NotConfigured`].
    base_url: Option<String>,
    auth: Arc<AuthManager>,
}

impl WorkspacesClient {
    pub fn new(auth: Arc<AuthManager>) -> Self {
        Self {
            http: crate::http::shared_client(),
            base_url: first_nonempty_env(&WORKSPACES_BASE_URL_ENV_CHAIN),
            auth,
        }
    }

    /// The configured host, or the fail-closed error every request returns without one.
    fn base(&self) -> Result<&str, WsError> {
        self.base_url.as_deref().ok_or(WsError::NotConfigured)
    }

    pub(crate) async fn list_workspaces(&self, q: &WsQuery) -> Result<ListWorkspacesPage, WsError> {
        let auth = self.auth.auth().await.map_err(|_| WsError::NoOauth)?;
        if !auth.is_fuigo_auth() {
            return Err(WsError::NoOauth);
        }
        let base = self.base()?;

        let url = format!("{}/rest/workspaces", base);
        let mut query: Vec<(&str, String)> = vec![("pageSize", q.page_size.to_string())];
        if let Some(token) = q.page_token.as_deref().filter(|s| !s.is_empty()) {
            query.push(("pageToken", token.to_owned()));
        }
        if let Some(search) = q.query.as_deref().filter(|s| !s.is_empty()) {
            query.push(("query", search.to_owned()));
        }
        if let Some(kind) = q.kind.as_deref().filter(|s| !s.is_empty()) {
            query.push(("kind", kind.to_owned()));
        }

        let mut builder = self
            .http
            .get(&url)
            .query(&query)
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
            return Err(WsError::Http {
                status: status.as_u16(),
            });
        }

        let bytes = response.bytes().await?;
        let wire: ListWorkspacesResponseWire = serde_json::from_slice(&bytes)?;

        Ok(ListWorkspacesPage {
            workspaces: wire.workspaces,
            next_page_token: wire.next_page_token.filter(|t| !t.is_empty()),
        })
    }
}

pub(crate) use super::skills_client::first_nonempty_env;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_parses_camelcase_wire() {
        let json = serde_json::json!({
            "workspaces": [{
                "workspaceId": "ws_9f3a",
                "name": "GPU vendor research",
                "createTime": "2026-06-18T17:30:00Z",
                "kind": "WORKSPACE_KIND_IMAGINE"
            }],
            "nextPageToken": "tok2"
        });
        let wire: ListWorkspacesResponseWire = serde_json::from_value(json).unwrap();
        assert_eq!(wire.workspaces.len(), 1);
        let w = &wire.workspaces[0];
        assert_eq!(w.workspace_id, "ws_9f3a");
        assert_eq!(w.name, "GPU vendor research");
        assert_eq!(w.create_time.as_deref(), Some("2026-06-18T17:30:00Z"));
        assert_eq!(w.kind.as_deref(), Some("WORKSPACE_KIND_IMAGINE"));
        assert_eq!(wire.next_page_token.as_deref(), Some("tok2"));
    }

    #[test]
    fn missing_fields_default_gracefully() {
        let json = serde_json::json!({ "workspaces": [{ "workspaceId": "w1" }] });
        let wire: ListWorkspacesResponseWire = serde_json::from_value(json).unwrap();
        let w = &wire.workspaces[0];
        assert_eq!(w.workspace_id, "w1");
        assert!(w.name.is_empty());
        assert!(w.create_time.is_none());
        assert!(w.kind.is_none());
        assert!(wire.next_page_token.is_none());
    }

    // ===== No vendor host as a default (1.0.20, REM-1 / REM-3) =====

    /// Row 5: with none of the env vars set the client resolves NO host.
    /// Upstream fell back to its vendor's web origin here.
    /// (Inspects `Debug` output only, so it compiles against the pre-fix `String` too.)
    #[test]
    #[serial_test::serial]
    fn workspaces_client_without_env_names_no_vendor_host() {
        let _a = fuigo_test_support::EnvGuard::unset("FUIGO_WORKSPACES_BASE_URL");
        let _b = fuigo_test_support::EnvGuard::unset("FUIGO_CONVERSATIONS_BASE_URL");
        let _c = fuigo_test_support::EnvGuard::unset("FUIGO_CODE_WEB_URL");
        let client =
            WorkspacesClient::new(crate::remote::skills_client::tests::test_auth_manager());
        let rendered = format!("{:?}", client.base_url);
        assert!(
            !rendered.contains("grok.com"),
            "workspaces base fell back to a vendor host: {rendered}"
        );
    }

    /// Row 5, typed: unset means `None` and `list_workspaces` fails closed naming the variable
    /// (after the auth gate, so a no-OAuth caller still sees `NoOauth` as before).
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn workspaces_client_without_env_fails_closed_with_a_true_message() {
        let _a = fuigo_test_support::EnvGuard::unset("FUIGO_WORKSPACES_BASE_URL");
        let _b = fuigo_test_support::EnvGuard::unset("FUIGO_CONVERSATIONS_BASE_URL");
        let _c = fuigo_test_support::EnvGuard::unset("FUIGO_CODE_WEB_URL");
        let client =
            WorkspacesClient::new(crate::remote::skills_client::tests::test_auth_manager());
        assert_eq!(client.base_url, None);
        let err = client
            .list_workspaces(&WsQuery {
                page_size: 10,
                ..WsQuery::default()
            })
            .await
            .expect_err("no host, no request");
        let shown = err.to_string();
        assert!(matches!(err, WsError::NotConfigured), "{shown}");
        assert!(shown.contains("FUIGO_WORKSPACES_BASE_URL"), "{shown}");
        assert!(!shown.contains("grok.com"), "{shown}");
    }

    /// Row 5, set: precedence `FUIGO_WORKSPACES_BASE_URL` > `FUIGO_CONVERSATIONS_BASE_URL` > `FUIGO_CODE_WEB_URL`, verbatim.
    #[test]
    #[serial_test::serial]
    fn workspaces_client_env_chain_precedence_is_unchanged() {
        let am = crate::remote::skills_client::tests::test_auth_manager;
        let _web = fuigo_test_support::EnvGuard::set("FUIGO_CODE_WEB_URL", "https://web.example.test");
        assert_eq!(WorkspacesClient::new(am()).base_url.as_deref(), Some("https://web.example.test"));
        let _conv =
            fuigo_test_support::EnvGuard::set("FUIGO_CONVERSATIONS_BASE_URL", "https://conv.example.test");
        assert_eq!(WorkspacesClient::new(am()).base_url.as_deref(), Some("https://conv.example.test"));
        let _ws = fuigo_test_support::EnvGuard::set("FUIGO_WORKSPACES_BASE_URL", "https://ws.example.test");
        assert_eq!(WorkspacesClient::new(am()).base_url.as_deref(), Some("https://ws.example.test"));
    }
}

#[cfg(test)]
mod egress_policy_tests {
    use super::*;
    #[test]
    fn egress_policy_denial_preserves_its_category() {
        let error = WsError::from(fuigo_extra_ca::dispatch::DispatchError::Denied("blocked"));
        assert!(matches!(error, WsError::Policy("blocked")));
    }
}
