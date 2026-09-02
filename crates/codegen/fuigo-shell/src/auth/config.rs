use super::model::TEAM_PRINCIPAL_TYPE;
use crate::env::{PROD_RELAY_WS_URL, PROD_WS_ORIGIN};
use serde::{Deserialize, Serialize};
fn default_oidc_scopes() -> Vec<String> {
    vec![
        "openid".into(),
        "profile".into(),
        "email".into(),
        "offline_access".into(),
        "api:access".into(),
    ]
}
/// Default scopes for the Ferrox Labs OAuth2 provider. `grok-cli:access` authorizes the token for API proxy requests.
fn default_oauth2_scopes() -> Vec<String> {
    vec![
        "openid".into(),
        "profile".into(),
        "email".into(),
        "offline_access".into(),
        "grok-cli:access".into(),
        "api:access".into(),
        "conversations:read".into(),
        "conversations:write".into(),
        "workspaces:read".into(),
        "workspaces:write".into(),
    ]
}
fn default_team_oauth2_scopes() -> Vec<String> {
    vec![
        "profile".into(),
        "offline_access".into(),
        "grok-cli:access".into(),
        "api:access".into(),
        "team:read".into(),
        "conversations:read".into(),
        "conversations:write".into(),
        "workspaces:read".into(),
        "workspaces:write".into(),
    ]
}
/// Pins automatic auth to one method via `[auth] preferred_method`.
/// When the pinned method is unavailable, auth fails rather than falling back; unset keeps the multi-method fallback.
/// Only the config file can set this, not remote settings or env.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreferredAuthMethod {
    /// `FUIGO_API_KEY` / auth.json `fuigo::api_key` / per-model BYOK (`fuigo.api_key`).
    ApiKey,
    /// OIDC / OAuth2 session (`cached_token`, interactive `grok.com` / `oidc`, including devbox-minted OIDC).
    Oidc,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FuigoComConfig {
    pub fuigo_ws_origin: String,
    pub fuigo_ws_url: String,
    pub token_header: String,
    /// OIDC config for customer-provided IdPs. See [`OidcAuthConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<OidcAuthConfig>,
    /// OAuth2 provider config. When set, it is preferred over the legacy relay flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2: Option<OAuth2ProviderConfig>,
    /// External auth provider command; stdout carries the token, stderr the user-facing output, and exit 0 means success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_provider_command: Option<String>,
    /// Login button label (env: `FUIGO_AUTH_PROVIDER_LABEL`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_provider_label: Option<String>,
    /// Token TTL in seconds for external auth providers that output bare tokens without `expires_in`.
    /// Synthesizes `expires_at` so proactive refresh works. Env: `FUIGO_AUTH_TOKEN_TTL`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token_ttl: Option<u64>,
    /// Admin kill switch: when `Some(true)`, the `fuigo.api_key` auth method is neither advertised nor accepted.
    /// `FUIGO_API_KEY` and per-model credentials then can't bypass the deployment's IdP login. Env: `FUIGO_DISABLE_API_KEY_AUTH`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_api_key_auth: Option<bool>,
    /// Restricts login to a specific team: the login token's team principal must equal this.
    /// Also settable via `FUIGO_FORCE_LOGIN_TEAM_ID`; see `resolve_force_login_team` for how the tiers resolve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_login_team_uuid: Option<ForceLoginTeam>,
    /// See [`PreferredAuthMethod`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_method: Option<PreferredAuthMethod>,
}
/// Team login restriction. TOML string or array; an empty array fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ForceLoginTeam {
    /// The only allowed team.
    Single(String),
    /// Allowed teams; an empty list fails closed.
    AnyOf(Vec<String>),
}
/// Customer OIDC Identity Provider configuration (`[fuigo_com_config.oidc]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcAuthConfig {
    pub issuer: String,
    pub client_id: String,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
}
/// OAuth2 provider configuration (`FUIGO_OAUTH2_ISSUER` / `FUIGO_OAUTH2_CLIENT_ID`).
///
/// Uses the standard OAuth 2.1 authorization code flow with PKCE via [`OidcAuthConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2ProviderConfig {
    pub issuer: String,
    pub client_id: String,
    #[serde(default = "default_oauth2_scopes")]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    /// Client-supplied referrer so analytics can attribute OAuth usage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrer: Option<String>,
}
/// xAI's OAuth2 issuer. **Not a default.** Fuigo ships with no issuer at all.
///
/// Kept as a named constant because Grok OAuth is a supported *opt-in*: a user
/// who wants it sets `FUIGO_OAUTH2_ISSUER` to this value together with
/// `FUIGO_OAUTH2_CLIENT_ID` and the `grok-cli:access` scope. Naming it here
/// documents the value and gives the tests something to seed.
///
/// It used to be the silent fallback, so `fuigo login` dialled xAI out of the
/// box in a product that is not xAI's.
pub const GROK_OAUTH2_ISSUER: &str = "https://auth.x.ai";
/// A separate const so the frozen contract test pins the production allowlist even when the non-production feature adds staging and local origins.
const PROD_ACCOUNTS_APP_ORIGINS: &[&str] = &["https://accounts.x.ai"];
/// Production build: accepts only the production accounts app.
pub(crate) fn allowed_accounts_app_origins() -> Vec<String> {
    PROD_ACCOUNTS_APP_ORIGINS
        .iter()
        .map(|o| o.to_string())
        .collect()
}
/// Builds a CORS layer accepting requests from the deployments in [`allowed_accounts_app_origins`] for the given HTTP method.
pub(crate) fn accounts_app_cors_layer(method: axum::http::Method) -> tower_http::cors::CorsLayer {
    tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::list(
            allowed_accounts_app_origins()
                .iter()
                .filter_map(|origin| match origin.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        tracing::warn!(origin, "skipping malformed accounts-app CORS origin");
                        None
                    }
                }),
        ))
        .allow_methods([method])
}
/// Local-dev OAuth2 issuer (accounts-app running on localhost).
const FUIGO_OAUTH2_LOCAL_ISSUER: &str = "http://localhost:22255";
/// Returns `true` when `FUIGO_LOCAL_AUTH=1` is set, indicating the local accounts-app should be used as the OAuth2 issuer.
pub(crate) fn use_local_auth() -> bool {
    std::env::var("FUIGO_LOCAL_AUTH")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false)
}
/// The configured OAuth2 issuer, or `""` when none is configured.
///
/// There is **no compiled default**. This returned `https://auth.x.ai`
/// unconditionally, so `fuigo login` dialled xAI in a product that is not
/// xAI's, and a doc comment described that as "the Ferrox Labs issuer".
///
/// An issuer is now something the user chooses, exactly like every other
/// endpoint: set `FUIGO_OAUTH2_ISSUER` (with `FUIGO_OAUTH2_CLIENT_ID`).
/// `FUIGO_LOCAL_AUTH=1` still selects the local-dev accounts app.
pub fn fuigo_oauth2_issuer() -> String {
    #[cfg(test)]
    if let Some(issuer) = TEST_ISSUER_OVERRIDE.get() {
        return issuer.clone();
    }
    if use_local_auth() {
        return FUIGO_OAUTH2_LOCAL_ISSUER.to_owned();
    }
    std::env::var("FUIGO_OAUTH2_ISSUER").unwrap_or_default()
}

/// Test-only configured issuer.
///
/// Tests that exercise issuer *matching* need an installation that has one.
/// A `OnceLock` rather than `std::env::set_var`, which is `unsafe` in edition
/// 2024 and races with every other test in the binary. Every caller installs
/// the same value, so first-write-wins is deterministic.
#[cfg(test)]
static TEST_ISSUER_OVERRIDE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// A `FuigoComConfig` with an OAuth2 provider installed, for tests that
/// exercise login behaviour.
///
/// `FuigoComConfig::default()` no longer carries a provider — Fuigo ships
/// without one — so tests about *how* login behaves must state that this
/// installation is configured, rather than relying on a compiled-in vendor.
#[cfg(test)]
pub(crate) fn test_config_with_oauth2() -> FuigoComConfig {
    set_test_oauth2_issuer(GROK_OAUTH2_ISSUER);
    let mut cfg = FuigoComConfig::default();
    cfg.oauth2 = Some(OAuth2ProviderConfig {
        issuer: GROK_OAUTH2_ISSUER.to_owned(),
        client_id: "test-client-id".to_owned(),
        scopes: default_oauth2_scopes(),
        principal_type: None,
        principal_id: None,
        referrer: None,
    });
    cfg.oidc = None;
    cfg
}

/// Install the configured issuer for tests. Idempotent; first write wins.
#[cfg(test)]
pub(crate) fn set_test_oauth2_issuer(issuer: &str) {
    let _ = TEST_ISSUER_OVERRIDE.set(issuer.to_owned());
}

/// Whether `issuer` is the issuer this installation is configured to trust.
///
/// Decides whether a stored token counts as a first-party account. With no
/// issuer configured this is `false` for everything, which is the safe
/// direction: an unknown token is not promoted to first-party.
pub fn is_fuigo_oauth2_issuer(issuer: &str) -> bool {
    if issuer.is_empty() {
        return false;
    }
    issuer == FUIGO_OAUTH2_LOCAL_ISSUER || issuer == fuigo_oauth2_issuer()
}
/// auth.json scope key used by the pre-OIDC `fuigo login --legacy` flow.
/// Matches the key format produced by the original `accounts.x.ai` relay auth.
pub(crate) const LEGACY_AUTH_SCOPE: &str = "https://accounts.x.ai/sign-in";
impl FuigoComConfig {
    /// Pinning a team (`force_login_team_uuid`) disables `fuigo.api_key` auth: team membership can't be verified from a bare API key.
    /// The `FUIGO_DISABLE_API_KEY_AUTH` env lockdown is read at call time and OR-ed in, so a lower-trust user `config.toml` cannot turn it back off.
    /// `requirements.toml` already wins by layer precedence.
    pub(crate) fn api_key_auth_disabled(&self) -> bool {
        self.disable_api_key_auth == Some(true)
            || self.force_login_team_uuid.is_some()
            || env_lockdown_forced()
    }
    /// When `preferred_method = api_key`, automatic OIDC paths (devbox mint, interactive browser login, external auth provider) must not run.
    /// The pin is fail-closed; explicit `fuigo login --devbox` and `--api-key` bypass it.
    pub(crate) fn blocks_automatic_oidc(&self) -> bool {
        matches!(self.preferred_method, Some(PreferredAuthMethod::ApiKey))
    }
    /// The auth.json scope key for this config.
    pub fn auth_scope(&self) -> String {
        if let Some(ref oidc) = self.oidc {
            format!("{}::{}", oidc.issuer.trim_end_matches('/'), oidc.client_id)
        } else if let Some(ref oauth2) = self.oauth2 {
            oauth2.auth_scope()
        } else {
            // Fuigo ships with no OAuth provider, so this is a normal state,
            // not an impossible one. It used to be `unreachable!`, which held
            // only because a vendor issuer and client id were compiled in as a
            // fallback; removing that turned the invariant into a panic on a
            // fresh install.
            //
            // Returning a distinct sentinel keeps the 18 call sites working
            // and is safe by construction: a real scope is `issuer::client_id`
            // and no issuer is spelled `unconfigured`, so a lookup under this
            // key cannot collide with a stored credential and simply misses.
            // Nothing stores under it either -- `run_cli_login` refuses before
            // it gets that far when no issuer is configured.
            UNCONFIGURED_AUTH_SCOPE.to_owned()
        }
    }
}
/// Scope key used when no OAuth provider is configured. Cannot collide with a
/// real `issuer::client_id` scope. See [`FuigoComConfig::auth_scope`].
pub const UNCONFIGURED_AUTH_SCOPE: &str = "unconfigured::no-oauth-provider";

impl OAuth2ProviderConfig {
    pub fn is_team_principal(&self) -> bool {
        self.principal_type.as_deref() == Some(TEAM_PRINCIPAL_TYPE)
    }
    pub fn from_env() -> Option<Self> {
        let issuer = std::env::var("FUIGO_OAUTH2_ISSUER").ok()?;
        let client_id = std::env::var("FUIGO_OAUTH2_CLIENT_ID").ok()?;
        let principal_type = std::env::var("FUIGO_OAUTH2_PRINCIPAL_TYPE").ok();
        let principal_id = std::env::var("FUIGO_OAUTH2_PRINCIPAL_ID").ok();
        let default_scopes = match principal_type.as_deref() {
            Some(TEAM_PRINCIPAL_TYPE) => default_team_oauth2_scopes(),
            _ => default_oauth2_scopes(),
        };
        Some(Self {
            issuer,
            client_id,
            scopes: std::env::var("FUIGO_OAUTH2_SCOPES")
                .map(|s| s.split(',').map(|s| s.trim().to_owned()).collect())
                .unwrap_or(default_scopes),
            principal_type,
            principal_id,
            // Opt-in only. Its own field comment says it exists "so analytics
            // can attribute OAuth usage" -- that is a tracking parameter for
            // whoever operates the issuer, and it defaulted to "fuigo-build".
            referrer: std::env::var("FUIGO_OAUTH2_REFERRER").ok(),
        })
    }
    /// Convert to [`OidcAuthConfig`] to reuse the OIDC login flow.
    pub(crate) fn as_oidc(&self) -> OidcAuthConfig {
        OidcAuthConfig {
            issuer: self.issuer.clone(),
            client_id: self.client_id.clone(),
            scopes: self.scopes.clone(),
            audience: None,
        }
    }
    pub(crate) fn base_auth_scope(&self) -> String {
        format!("{}::{}", self.issuer.trim_end_matches('/'), self.client_id)
    }
    pub fn auth_scope(&self) -> String {
        self.base_auth_scope()
    }
}
impl Default for FuigoComConfig {
    fn default() -> Self {
        let oidc = OidcAuthConfig::from_env();
        // No fallback provider. This previously defaulted to xAI's issuer and
        // an obfuscated xAI OAuth client id compiled into the binary, so a
        // fresh install had a working login to a vendor the user never chose.
        //
        // `None` here means `fuigo login` refuses until an issuer is
        // configured -- enterprise OIDC, or FUIGO_OAUTH2_ISSUER +
        // FUIGO_OAUTH2_CLIENT_ID. Grok OAuth is reached that way, as an
        // opt-in: see [`GROK_OAUTH2_ISSUER`].
        let oauth2 = if oidc.is_some() {
            None
        } else {
            OAuth2ProviderConfig::from_env()
        };
        Self {
            fuigo_ws_origin: std::env::var("FUIGO_WS_ORIGIN")
                .unwrap_or_else(|_| PROD_WS_ORIGIN.to_owned()),
            fuigo_ws_url: std::env::var("FUIGO_WS_URL")
                .unwrap_or_else(|_| PROD_RELAY_WS_URL.to_owned()),
            token_header: "xai-grok-cli".to_owned(),
            oidc,
            oauth2,
            auth_provider_command: std::env::var("FUIGO_AUTH_PROVIDER_COMMAND").ok(),
            auth_provider_label: std::env::var("FUIGO_AUTH_PROVIDER_LABEL").ok(),
            auth_token_ttl: std::env::var("FUIGO_AUTH_TOKEN_TTL")
                .ok()
                .and_then(|v| v.parse().ok()),
            disable_api_key_auth: std::env::var("FUIGO_DISABLE_API_KEY_AUTH")
                .ok()
                .map(|v| env_flag_enabled(&v)),
            force_login_team_uuid: None,
            preferred_method: None,
        }
    }
}
/// Parses a boolean env-var value for fuigo's on/off flags.
/// Bare presence enables the flag, but falsy spellings (`0`, `false`, `off`, `no`, empty) count as disabled.
/// `FUIGO_DISABLE_API_KEY_AUTH=false` therefore does NOT enable the flag.
fn env_flag_enabled(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "off" | "no"
    )
}
/// True when the admin has set `FUIGO_DISABLE_API_KEY_AUTH` to a truthy value in the process environment.
/// It is read at call time and OR-ed into `api_key_auth_disabled()`, so a user-layer `config.toml` cannot override the lockdown.
fn env_lockdown_forced() -> bool {
    std::env::var("FUIGO_DISABLE_API_KEY_AUTH")
        .ok()
        .is_some_and(|v| env_flag_enabled(&v))
}
/// Env var for the login-team pin.
/// It is named `..._TEAM_ID` (the user-facing "team id") while the config key stays `force_login_team_uuid` for backward compatibility.
/// The two intentionally differ, so do not rename either.
const FORCE_LOGIN_TEAM_ID_ENV: &str = "FUIGO_FORCE_LOGIN_TEAM_ID";
/// The `FUIGO_FORCE_LOGIN_TEAM_ID` env override; the env tier in [`resolve_force_login_team`].
pub(crate) fn force_login_team_from_env() -> Option<ForceLoginTeam> {
    let raw = std::env::var(FORCE_LOGIN_TEAM_ID_ENV).ok()?;
    parse_force_login_team(&raw)
}
/// The `force_login_team_uuid` pin from the merged `requirements.toml` / MDM layers; the non-overridable tier in [`resolve_force_login_team`].
/// It is read at call time so the clamp holds on config-load paths that build `FuigoComConfig` without a separate `apply_requirements` pass.
pub(crate) fn force_login_team_from_requirements() -> Option<ForceLoginTeam> {
    force_login_team_from_requirements_value(&crate::config::load_merged_requirements()?)
}
/// Extracts the `force_login_team_uuid` pin from a merged requirements value, reading the `[fuigo_com_config]` key and its `[auth]` alias.
/// A present but unparseable value fails closed (an empty any-of, which blocks login).
/// A malformed pin on the highest-trust tier therefore cannot silently drop the restriction.
fn force_login_team_from_requirements_value(requirements: &toml::Value) -> Option<ForceLoginTeam> {
    let value = requirements
        .get("fuigo_com_config")
        .and_then(|section| section.get("force_login_team_uuid"))
        .or_else(|| {
            requirements
                .get("auth")
                .and_then(|section| section.get("force_login_team_uuid"))
        })?;
    match value.clone().try_into() {
        Ok(team) => Some(team),
        Err(_) => {
            tracing::warn!(
                "force_login_team_uuid in requirements.toml is malformed; failing closed"
            );
            Some(ForceLoginTeam::AnyOf(vec![]))
        }
    }
}
/// Resolves the effective login-team pin by tier: `requirements` beats `env` beats `config`.
/// `requirements` is the non-overridable `requirements.toml` / MDM pin.
/// `env` (`FUIGO_FORCE_LOGIN_TEAM_ID`) wins over the merged user/managed `config.toml`.
pub(crate) fn resolve_force_login_team(
    requirements: Option<ForceLoginTeam>,
    env: Option<ForceLoginTeam>,
    config: Option<ForceLoginTeam>,
) -> Option<ForceLoginTeam> {
    requirements.or(env).or(config)
}
/// Parses a `FUIGO_FORCE_LOGIN_TEAM_ID` value into a [`ForceLoginTeam`].
/// A bare value is a single team, a JSON array is an any-of set (each element trimmed), and an empty or whitespace-only value yields `None`.
/// A value that looks like a JSON array but does not parse fails closed (an empty any-of, which blocks login).
/// A typo in the array therefore cannot silently drop the restriction.
fn parse_force_login_team(raw: &str) -> Option<ForceLoginTeam> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with('[') {
        match serde_json::from_str::<Vec<String>>(trimmed) {
            Ok(teams) => Some(ForceLoginTeam::AnyOf(
                teams.into_iter().map(|t| t.trim().to_owned()).collect(),
            )),
            Err(_) => {
                tracing::warn!(
                    "FUIGO_FORCE_LOGIN_TEAM_ID is not a valid JSON array; failing closed"
                );
                Some(ForceLoginTeam::AnyOf(vec![]))
            }
        }
    } else {
        Some(ForceLoginTeam::Single(trimmed.to_owned()))
    }
}
impl OidcAuthConfig {
    pub fn from_env() -> Option<Self> {
        let issuer = std::env::var("FUIGO_OIDC_ISSUER").ok()?;
        let client_id = std::env::var("FUIGO_OIDC_CLIENT_ID").ok()?;
        Some(Self {
            issuer,
            client_id,
            scopes: std::env::var("FUIGO_OIDC_SCOPES")
                .map(|s| s.split(',').map(|s| s.trim().to_owned()).collect())
                .unwrap_or_else(|_| default_oidc_scopes()),
            audience: std::env::var("FUIGO_OIDC_AUDIENCE").ok(),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn team_auth_scope_is_base_scope() {
        let cfg = OAuth2ProviderConfig {
            issuer: "https://auth.x.ai".into(),
            client_id: "client-123".into(),
            scopes: default_team_oauth2_scopes(),
            principal_type: Some("Team".into()),
            principal_id: Some("team-abc".into()),
            referrer: Some("fuigo-build".into()),
        };
        assert_eq!(cfg.auth_scope(), "https://auth.x.ai::client-123");
    }
    #[test]
    fn env_flag_enabled_treats_falsy_spellings_as_off() {
        for off in ["", " ", "0", "false", "FALSE", "off", "No", "  false  "] {
            assert!(!env_flag_enabled(off), "{off:?} should be off");
        }
        for on in ["1", "true", "yes", "on", "enabled"] {
            assert!(env_flag_enabled(on), "{on:?} should be on");
        }
    }
    #[test]
    fn personal_auth_scope_is_base_scope() {
        let cfg = OAuth2ProviderConfig {
            issuer: "https://auth.x.ai".into(),
            client_id: "client-123".into(),
            scopes: default_oauth2_scopes(),
            principal_type: None,
            principal_id: None,
            referrer: Some("fuigo-build".into()),
        };
        assert_eq!(cfg.auth_scope(), "https://auth.x.ai::client-123");
    }
    /// FROZEN loopback contract: the accounts-app origins the CLI's loopback callback server accepts cross-origin requests from.
    /// The consent page (served from accounts.x.ai) delivers the code via `fetch(..., cors)`.
    /// Removing an origin therefore breaks loopback delivery for already-installed CLIs.
    /// Keep in sync with the oauth2-provider / accounts-app deployments.
    /// Non-production / local-dev origins are opt-in only.
    #[test]
    fn allowed_accounts_app_origins_are_frozen() {
        assert_eq!(PROD_ACCOUNTS_APP_ORIGINS, &["https://accounts.x.ai"]);
        assert_eq!(allowed_accounts_app_origins(), PROD_ACCOUNTS_APP_ORIGINS);
    }
    /// FROZEN client contract: the 10 scopes the Ferrox Labs OAuth2 client requests.
    /// The server must keep accepting all of them; existing tokens carry exactly this set.
    #[test]
    fn default_oauth2_scopes_are_frozen() {
        let scopes = default_oauth2_scopes();
        let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
        assert_eq!(
            scopes,
            [
                "openid",
                "profile",
                "email",
                "offline_access",
                "grok-cli:access",
                "api:access",
                "conversations:read",
                "conversations:write",
                "workspaces:read",
                "workspaces:write",
            ]
        );
    }
    #[test]
    fn preferred_method_deserializes_from_toml() {
        let cfg: FuigoComConfig = toml::from_str(
            r#"
            preferred_method = "api_key"
            "#,
        )
        .expect("parse");
        assert_eq!(cfg.preferred_method, Some(PreferredAuthMethod::ApiKey));
        let cfg: FuigoComConfig = toml::from_str(
            r#"
            preferred_method = "oidc"
            "#,
        )
        .expect("parse");
        assert_eq!(cfg.preferred_method, Some(PreferredAuthMethod::Oidc));
        let cfg: FuigoComConfig = toml::from_str("").expect("parse empty");
        assert_eq!(cfg.preferred_method, None);
    }
    /// Every `FUIGO_FORCE_LOGIN_TEAM_ID` shape: bare value, arrays, empty-array, malformed, and empty/whitespace.
    #[test]
    fn parse_force_login_team_handles_all_shapes() {
        assert_eq!(
            parse_force_login_team("  team-abc  "),
            Some(ForceLoginTeam::Single("team-abc".into())),
        );
        assert_eq!(
            parse_force_login_team(r#"["  team-a "]"#),
            Some(ForceLoginTeam::AnyOf(vec!["team-a".into()])),
        );
        assert_eq!(
            parse_force_login_team(r#"["team-a", " team-b "]"#),
            Some(ForceLoginTeam::AnyOf(vec![
                "team-a".into(),
                "team-b".into()
            ])),
        );
        assert_eq!(
            parse_force_login_team("[]"),
            Some(ForceLoginTeam::AnyOf(vec![])),
        );
        assert_eq!(
            parse_force_login_team(r#"["team-a", "team-b"#),
            Some(ForceLoginTeam::AnyOf(vec![])),
        );
        assert_eq!(parse_force_login_team(""), None);
        assert_eq!(parse_force_login_team("   "), None);
    }
    /// Precedence by tier: requirements wins over env, which wins over user/managed config.
    #[test]
    fn resolve_force_login_team_precedence() {
        let req = || Some(ForceLoginTeam::Single("req-team".into()));
        let env = || Some(ForceLoginTeam::Single("env-team".into()));
        let cfg = || Some(ForceLoginTeam::Single("cfg-team".into()));
        assert_eq!(resolve_force_login_team(req(), env(), cfg()), req());
        assert_eq!(resolve_force_login_team(req(), None, cfg()), req());
        assert_eq!(resolve_force_login_team(req(), env(), None), req());
        assert_eq!(resolve_force_login_team(None, env(), cfg()), env());
        assert_eq!(resolve_force_login_team(None, env(), None), env());
        assert_eq!(resolve_force_login_team(None, None, cfg()), cfg());
        assert_eq!(resolve_force_login_team(None, None, None), None);
    }
    /// Extraction from the `[fuigo_com_config]` key and its `[auth]` alias.
    /// A present but malformed value fails closed (empty any-of), never `None`; an absent field is `None`.
    #[test]
    fn force_login_team_from_requirements_value_extracts_and_fails_closed() {
        fn pin(toml_str: &str) -> Option<ForceLoginTeam> {
            force_login_team_from_requirements_value(&toml::from_str(toml_str).expect("parse"))
        }
        assert_eq!(
            pin("[fuigo_com_config]\nforce_login_team_uuid = \"team-a\"\n"),
            Some(ForceLoginTeam::Single("team-a".into())),
        );
        assert_eq!(
            pin("[auth]\nforce_login_team_uuid = [\"team-a\", \"team-b\"]\n"),
            Some(ForceLoginTeam::AnyOf(vec![
                "team-a".into(),
                "team-b".into()
            ])),
        );
        assert_eq!(
            pin("[fuigo_com_config]\nforce_login_team_uuid = 123\n"),
            Some(ForceLoginTeam::AnyOf(vec![])),
        );
        assert_eq!(pin("[fuigo_com_config]\n"), None);
        assert_eq!(pin(""), None);
    }
}
