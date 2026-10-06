//! The host's TOML parsing (`McpServerConfig::oauth_config`) builds these types; [`crate::oauth`] consumes them.

use std::collections::HashMap;

/// Travels alongside `acp::McpServer` (which can't be extended since it's an external crate type).
#[derive(Clone, Default)]
pub struct McpOAuthConfig {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub callback_port: Option<u16>,
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for McpOAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            client_id,
            client_secret,
            scopes,
            callback_port,
        } = self;
        f.debug_struct("McpOAuthConfig")
            .field("client_id", client_id)
            .field("client_secret", &client_secret.as_ref().map(|_| "<redacted>"))
            .field("scopes", scopes)
            .field("callback_port", callback_port)
            .finish()
    }
}

impl McpOAuthConfig {
    pub fn is_configured(&self) -> bool {
        self.client_id.is_some()
    }
}

/// Per-server OAuth configuration map, keyed by MCP server name.
pub type McpOAuthConfigMap = HashMap<String, McpOAuthConfig>;

#[cfg(test)]
mod p70_redacted_debug {
    use super::*;

    /// `{x:?}` and `{x:#?}` hold `<redacted>` (control) and no fragment of any secret.
    fn assert_redacted(debug: &dyn std::fmt::Debug, secrets: &[&str]) {
        for out in [format!("{debug:?}"), format!("{debug:#?}")] {
            assert!(out.contains("<redacted>"), "control: the secret field is printed as redacted: {out}");
            for secret in secrets {
                let chars: Vec<char> = secret.chars().collect();
                for w in chars.windows(6) {
                    let frag: String = w.iter().collect();
                    assert!(!out.contains(&frag), "Debug output holds {frag:?} of a secret: {out}");
                }
            }
        }
    }

    #[test]
    fn mcp_oauth_config_and_observed_token_debug_redact() {
        let cfg = McpOAuthConfig {
            client_id: Some("p70-client".into()),
            client_secret: Some("p70cs-FAKE-3c4d5e6f".into()),
            ..McpOAuthConfig::default()
        };
        assert_redacted(&cfg, &["p70cs-FAKE-3c4d5e6f"]);
        let observed = crate::credentials::ObservedAccessToken::default();
        observed.record(Some("p70ot-FAKE-8e9f0a1b".into()));
        assert_redacted(&observed, &["p70ot-FAKE-8e9f0a1b"]);
    }
}
