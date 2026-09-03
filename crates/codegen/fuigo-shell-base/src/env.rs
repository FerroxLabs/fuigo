//! FuigoBuildEnvironment configuration for the shell crate family.
//!
//! The environment presets (per-environment endpoint URLs, the staging trust check, `EnvVarGuard`) live in the [`fuigo_env`] leaf crate.
//! Sibling crates (telemetry, tools, workspace) share them without depending on this crate.
//! This module re-exports them and hosts the shell-specific gateway-bridge env vars.
//!
//! # Gateway-bridge mode (env-only)
//! - `FUIGO_GATEWAY_URL` — when set to a valid URL, `MvpAgent` spawns a
//!   per-session gateway bridge actor and routes prompts through it.
//!   When unset, sessions created in gateway mode fall back to [`FuigoBuildEnvironment::gateway_ws_url`] and everything else stays in local mode.
pub use fuigo_env::{
    FuigoBuildEnvironment, PROD_ASSET_SERVER_URL, PROD_CLI_CHAT_PROXY_BASE_URL,
    PROD_GATEWAY_WS_URL, PROD_RELAY_WS_URL, PROD_WS_ORIGIN,
};
/// Computer Hub WebSocket URL used by the local-workspace supervisor when
/// `agent_config.hub.url` is unset. **Empty: Fuigo operates no Computer Hub.**
///
/// This used to default to `wss://computer-hub.grok.com/v1/tools`, so a plain
/// `fuigo workspace start` opened a websocket to xAI infrastructure. It escaped
/// the sweep that emptied every other production endpoint in `fuigo_env`
/// (whose own comment names this exact failure mode: "a default-on websocket to
/// a host we do not control is the worst kind of leftover: it never appears in
/// an HTTP client audit") — and it escaped it for that reason. The
/// `fuigo-extra-ca` egress blocklist does NOT cover it: that guard is a reqwest
/// DNS resolver, and this connection is raw tungstenite.
///
/// Empty means the feature is off until an operator sets `agent_config.hub.url`
/// or passes `--hub-url`. Do not repoint it at FluxRouter: that is an inference
/// gateway, not a tool hub.
pub const PROD_COMPUTER_HUB_WS_URL: &str = "";
#[cfg(any(test, feature = "test-support"))]
pub use fuigo_env::EnvVarGuard;
/// Env var that opts a process into gateway-bridge mode.
/// When set to a parseable URL, `session/new` / `session/load` spawns a per-session `gateway_bridge` actor in the shell.
/// When unset the process stays in local mode.
pub const FUIGO_GATEWAY_URL_ENV: &str = "FUIGO_GATEWAY_URL";
/// Client kill switch for the gateway-bridge custom-method passthrough.
/// Set to `1` / `true` to force every `custom_method` call back onto agent-local dispatch regardless of the routing table or negotiated capability.
/// That gives an instant revert without a redeploy if the channel misbehaves.
/// Unset, `0`, or `false` keeps normal routing.
pub const FUIGO_DISABLE_CUSTOM_BRIDGE_ENV: &str = "FUIGO_DISABLE_CUSTOM_BRIDGE";
/// `true` when the custom-method bridge passthrough is force-disabled via [`FUIGO_DISABLE_CUSTOM_BRIDGE_ENV`].
/// Accepts `1`/`true` (case-insensitive).
pub fn custom_bridge_disabled() -> bool {
    std::env::var(FUIGO_DISABLE_CUSTOM_BRIDGE_ENV)
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}
/// Parse `FUIGO_GATEWAY_URL` into a [`url::Url`].
///
/// This build ignores the variable and stays in local mode (warns if set).
pub fn parse_gateway_url() -> Option<url::Url> {
    let raw = std::env::var(FUIGO_GATEWAY_URL_ENV).ok()?;
    if raw.is_empty() {
        return None;
    }
    tracing::warn!(
        env = FUIGO_GATEWAY_URL_ENV,
        "FUIGO_GATEWAY_URL is set but this build does not support gateway-bridge mode; staying in local mode"
    );
    None
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_gateway_url_returns_none_when_unset() {
        let _env = EnvVarGuard::remove(FUIGO_GATEWAY_URL_ENV);
        assert!(parse_gateway_url().is_none());
    }
    #[test]
    fn parse_gateway_url_returns_none_when_empty() {
        let _env = EnvVarGuard::set(FUIGO_GATEWAY_URL_ENV, "");
        assert!(parse_gateway_url().is_none());
    }
    #[test]
    fn parse_gateway_url_hard_off_without_gateway_bridge() {
        let _env = EnvVarGuard::set(FUIGO_GATEWAY_URL_ENV, "wss://gateway.example.com/ws");
        assert!(
            parse_gateway_url().is_none(),
            "valid URL must still be ignored in this build"
        );
    }
    #[test]
    fn custom_bridge_disabled_defaults_false_when_unset() {
        let _env = EnvVarGuard::remove(FUIGO_DISABLE_CUSTOM_BRIDGE_ENV);
        assert!(!custom_bridge_disabled());
    }
    #[test]
    fn custom_bridge_disabled_true_for_one_and_true() {
        for v in ["1", "true", "TRUE", " true "] {
            let _env = EnvVarGuard::set(FUIGO_DISABLE_CUSTOM_BRIDGE_ENV, v);
            assert!(
                custom_bridge_disabled(),
                "{v:?} must disable the custom bridge"
            );
        }
    }
    #[test]
    fn custom_bridge_disabled_false_for_zero_and_garbage() {
        for v in ["0", "false", "", "no"] {
            let _env = EnvVarGuard::set(FUIGO_DISABLE_CUSTOM_BRIDGE_ENV, v);
            assert!(
                !custom_bridge_disabled(),
                "{v:?} must leave the custom bridge enabled"
            );
        }
    }
}
