//! Pure OIDC protocol mechanics: PKCE, discovery, token exchange, refresh_tokens, JWT validation, principal extraction.
//!
//! No `AuthManager` mutation here.
//! The login orchestration is in [`super::login`]; refresh primitives are in [`super::refresh`].
use super::super::config::{ForceLoginTeam, FuigoComConfig, OAuth2ProviderConfig, OidcAuthConfig};
use super::super::{AuthMode, FuigoAuth};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use fuigo_extra_ca::dispatch::AsyncRequestBuilderExt as _;
use parking_lot::RwLock;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration as StdDuration, Instant};
#[derive(Debug, Clone, thiserror::Error)]
pub(super) enum OidcError {
    #[error("OIDC not configured")]
    NotConfigured,
    #[error("failed to bind OIDC loopback server: {0}")]
    BindLoopback(String),
    #[error("failed to save OIDC auth: {0}")]
    SaveAuth(String),
    #[error("OIDC discovery failed: HTTP {status} from {url}")]
    DiscoveryHttp { status: u16, url: String },
    /// Keep the "10 minutes" text in sync with `AUTH_CALLBACK_TIMEOUT` in `login.rs`.
    #[error("Login timed out after 10 minutes. Please try again.")]
    CallbackTimeout,
    #[error("OIDC callback channel closed unexpectedly")]
    CallbackChannelClosed,
    #[error("OIDC authentication failed: {0}")]
    CallbackAuthFailed(String),
    #[error("failed to parse pasted input: {0}")]
    InvalidPastedInput(String),
    #[error("OIDC token exchange failed: HTTP {status} — {body}")]
    TokenExchangeHttp { status: u16, body: String },
    #[error("OIDC token refresh failed: HTTP {status} — {body}")]
    TokenRefreshHttp { status: u16, body: String },
    /// Local policy refused the token endpoint (P99): discovery named one this client will not send a credential
    /// to (decided before any request), or the admitted endpoint answered with a redirect that is not followed
    /// (the credential stayed on the admitted origin). Neither says anything about the credential, which is kept.
    #[error("{0}")]
    TokenEndpointRefused(String),
    #[error("OIDC authentication failed: state mismatch")]
    StateMismatch,
    #[error("OIDC id_token uses unsupported algorithm: {0}")]
    UnsupportedAlg(String),
    #[error("OIDC id_token alg {alg} is not in discovery supported list")]
    AlgNotInDiscoverySupportedList { alg: String },
    #[error("OIDC id_token missing kid header")]
    IdTokenMissingKid,
    #[error("OIDC discovery missing jwks_uri")]
    DiscoveryMissingJwksUri,
    #[error("OIDC JWK not found for kid={kid}")]
    JwkNotFound { kid: String },
    #[error("OIDC id_token issuer mismatch")]
    IssuerMismatch,
    #[error("OIDC id_token audience mismatch")]
    AudienceMismatch,
    #[error("OIDC id_token nonce mismatch")]
    NonceMismatch,
    #[error("OIDC token response missing id_token")]
    MissingIdToken,
    #[error("OIDC id_token validation failed: {0}")]
    IdTokenValidationFailed(String),
    #[error(
        "This deployment requires logging into {expected}; your login returned {}",
        actual.as_deref().unwrap_or("no team principal")
    )]
    PinnedPrincipalMismatch {
        /// Pre-formatted requirement, e.g. `team <id>` or `one of teams: a, b`.
        expected: String,
        actual: Option<String>,
    },
    #[error(
        "Login is blocked by your administrator: force_login_team_uuid is an empty \
         list, so no team is permitted to sign in"
    )]
    ForceLoginNoPrincipalsAllowed,
}
const ALLOWED_ID_TOKEN_ALGS: &[jsonwebtoken::Algorithm] = &[
    jsonwebtoken::Algorithm::RS256,
    jsonwebtoken::Algorithm::RS384,
    jsonwebtoken::Algorithm::RS512,
    jsonwebtoken::Algorithm::PS256,
    jsonwebtoken::Algorithm::PS384,
    jsonwebtoken::Algorithm::PS512,
    jsonwebtoken::Algorithm::ES256,
    jsonwebtoken::Algorithm::ES384,
    jsonwebtoken::Algorithm::EdDSA,
];
/// Optionally attach an extra access header when the optional non-production feature is enabled and the request targets a matching first-party host.
pub(crate) fn with_alpha_test_key(
    builder: reqwest::RequestBuilder,
    url: &str,
) -> reqwest::RequestBuilder {
    let _ = url;
    builder
}
pub(crate) fn is_configured(config: &FuigoComConfig) -> bool {
    config.oidc.is_some()
}
/// Peek at the unverified access token JWT to extract the `principal_type` and `principal_id` chosen during the consent screen.
///
/// When the user picks "Team" on the consent screen, the server strips user-only scopes (`openid`, `email`).
/// It then issues the token with `principal_type=Team`.
/// The shell's config doesn't know which principal the user picked, so we peek at the token to find out.
///
/// Returns `(principal_type, principal_id)` or `None` if the token is not a JWT or the claims can't be extracted.
pub(crate) fn peek_access_token_principal(
    access_token: &str,
) -> Option<(String, String, Option<String>)> {
    #[derive(serde::Deserialize)]
    struct MinimalClaims {
        #[serde(default, alias = "principalType")]
        principal_type: Option<String>,
        #[serde(default, alias = "principalId")]
        principal_id: Option<String>,
        #[serde(default)]
        team_id: Option<String>,
    }
    crate::auth::jwt::ensure_jwt_crypto_provider();
    let token_data =
        jsonwebtoken::dangerous::insecure_decode::<MinimalClaims>(access_token).ok()?;
    let pt = token_data.claims.principal_type?;
    let pid = token_data.claims.principal_id?;
    if pt.is_empty() || pid.is_empty() {
        return None;
    }
    let tid = token_data.claims.team_id.filter(|s| !s.is_empty());
    Some((pt, pid, tid))
}
/// Extract just the `principal_id` claim for `force_login_team_uuid` matching, regardless of whether `principal_type` is present.
/// A token can carry the team id in `principal_id` without a `principal_type`; the pin must still match it.
/// Matching the id alone is safe: a user id never collides with a team uuid (distinct id spaces).
/// The server re-validates the signed token anyway.
/// Returns `None` only when no non-empty `principal_id` is present (which `enforce_login_principal` treats as fail-closed).
pub(crate) fn peek_access_token_principal_id(access_token: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct PrincipalIdClaim {
        #[serde(default, alias = "principalId")]
        principal_id: Option<String>,
    }
    crate::auth::jwt::ensure_jwt_crypto_provider();
    jsonwebtoken::dangerous::insecure_decode::<PrincipalIdClaim>(access_token)
        .ok()?
        .claims
        .principal_id
        .filter(|s| !s.is_empty())
}
/// Resolved allowed-team set from the dedicated `force_login_team_uuid` lockdown knob, or `None` (unrestricted).
/// The legacy `oauth2.principal_id` is intentionally NOT an enforcement gate; it only pre-selects the team on the consent page.
/// Deployments that set it for pre-selection therefore keep letting users pick a team (no surprise login failures on upgrade).
/// This function is pure for testing.
pub(crate) fn resolve_login_principal_policy(
    force_login_team_uuid: Option<&ForceLoginTeam>,
) -> Option<ForceLoginTeam> {
    force_login_team_uuid.cloned()
}
pub(crate) fn login_principal_policy(cfg: &FuigoComConfig) -> Option<ForceLoginTeam> {
    resolve_login_principal_policy(cfg.force_login_team_uuid.as_ref())
}
/// Reject a token whose principal isn't allowed, BEFORE persisting (no partial state).
/// A restriction also rejects a token with no principal (else picking "personal" on the consent page defeats it); an empty `AnyOf` fails closed.
///
/// The `actual` principal comes from the access-token claim (`peek_access_token_principal`, an unverified `insecure_decode`).
/// This client-side check is fail-fast UX and defense-in-depth, NOT the security boundary.
/// The server re-validates the signed token on every API call and is authoritative, so a locally tampered token still cannot reach the API.
pub(crate) fn enforce_login_principal(
    policy: Option<&ForceLoginTeam>,
    actual: Option<&str>,
) -> anyhow::Result<()> {
    let allowed: &[String] = match policy {
        None => return Ok(()),
        Some(ForceLoginTeam::Single(id)) => std::slice::from_ref(id),
        Some(ForceLoginTeam::AnyOf(ids)) if ids.is_empty() => {
            tracing::warn!("OIDC: force_login_team_uuid is an empty list; failing closed");
            return Err(anyhow::Error::new(OidcError::ForceLoginNoPrincipalsAllowed));
        }
        Some(ForceLoginTeam::AnyOf(ids)) => ids,
    };
    if let Some(actual) = actual
        && allowed.iter().any(|a| a == actual)
    {
        return Ok(());
    }
    let expected = if allowed.len() == 1 {
        format!("team {}", allowed[0])
    } else {
        format!("one of teams: {}", allowed.join(", "))
    };
    tracing::warn!(
        expected = %expected,
        actual = ?actual,
        "OIDC: login principal does not satisfy required policy; rejecting"
    );
    Err(anyhow::Error::new(OidcError::PinnedPrincipalMismatch {
        expected,
        actual: actual.map(str::to_owned),
    }))
}
#[derive(Debug)]
pub(super) struct OidcUserInfo {
    pub(super) user_id: String,
    pub(super) email: Option<String>,
    pub(super) first_name: Option<String>,
    pub(super) last_name: Option<String>,
    pub(super) profile_image_asset_id: Option<String>,
    pub(super) principal_type: Option<String>,
    pub(super) principal_id: Option<String>,
    pub(super) team_id: Option<String>,
    pub(super) team_name: Option<String>,
    pub(super) team_role: Option<String>,
    pub(super) organization_id: Option<String>,
    pub(super) organization_name: Option<String>,
    pub(super) organization_role: Option<String>,
    pub(super) user_blocked_reason: Option<String>,
    pub(super) team_blocked_reasons: Vec<String>,
    pub(super) coding_data_retention_opt_out: bool,
}
pub(super) fn build_fuigo_auth(
    tokens: TokenResponse,
    user_info: OidcUserInfo,
    issuer: &str,
    client_id: &str,
) -> FuigoAuth {
    let now = Utc::now();
    FuigoAuth {
        key: tokens.access_token,
        auth_mode: AuthMode::Oidc,
        create_time: now,
        user_id: user_info.user_id,
        email: user_info.email,
        first_name: user_info.first_name,
        last_name: user_info.last_name,
        profile_image_asset_id: user_info.profile_image_asset_id,
        principal_type: user_info.principal_type,
        principal_id: user_info.principal_id,
        team_id: user_info.team_id,
        team_name: user_info.team_name,
        team_role: user_info.team_role,
        organization_id: user_info.organization_id,
        organization_name: user_info.organization_name,
        organization_role: user_info.organization_role,
        user_blocked_reason: user_info.user_blocked_reason,
        team_blocked_reasons: user_info.team_blocked_reasons,
        coding_data_retention_opt_out: user_info.coding_data_retention_opt_out,
        has_fuigo_code_access: None,
        refresh_token: tokens.refresh_token,
        expires_at: tokens.expires_in.map(|s| now + Duration::seconds(s as i64)),
        oidc_issuer: Some(issuer.to_owned()),
        oidc_client_id: Some(client_id.to_owned()),
    }
}
#[derive(Debug, Clone, Deserialize)]
pub(super) struct Discovery {
    pub(super) authorization_endpoint: String,
    pub(super) token_endpoint: String,
    #[serde(default)]
    pub(super) jwks_uri: Option<String>,
    #[serde(default)]
    pub(super) id_token_signing_alg_values_supported: Option<Vec<String>>,
}
/// RFC 8414 says discovery clients SHOULD cache.
/// 1h is short enough that an endpoint move propagates within an agent session.
/// It is long enough that a discovery-endpoint outage no longer blocks token refresh once the doc is cached.
const DISCOVERY_CACHE_TTL: StdDuration = StdDuration::from_secs(3600);
/// Per-issuer cache of `(Discovery, fetched_at)`.
/// Process-global because the discovery doc is identity-free; multiple AuthManagers pointed at the same IdP share one entry.
static DISCOVERY_CACHE: LazyLock<RwLock<HashMap<String, (Discovery, Instant)>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
pub(super) async fn discover(issuer: &str) -> anyhow::Result<Discovery> {
    let issuer_key = issuer.trim_end_matches('/').to_owned();
    if let Some((doc, at)) = DISCOVERY_CACHE.read().get(&issuer_key)
        && at.elapsed() < DISCOVERY_CACHE_TTL
    {
        return Ok(doc.clone());
    }
    use backon::Retryable;
    let key = issuer_key.clone();
    let doc = (|| {
        let key = key.clone();
        async move { discover_once(&key).await }
    })
    .retry(discovery_retry_policy())
    .when(|error: &anyhow::Error| !is_egress_policy_denial(error))
    .await?;
    DISCOVERY_CACHE
        .write()
        .insert(issuer_key, (doc.clone(), Instant::now()));
    Ok(doc)
}
fn discovery_retry_policy() -> backon::ExponentialBuilder {
    backon::ExponentialBuilder::default()
        .with_max_times(2)
        .with_min_delay(StdDuration::from_millis(500))
        .with_max_delay(StdDuration::from_secs(2))
        .with_jitter()
}
async fn discover_once(issuer_key: &str) -> anyhow::Result<Discovery> {
    let url = format!("{issuer_key}/.well-known/openid-configuration");
    tracing::debug!(url = %url, "OIDC: fetching discovery document");
    let resp = with_alpha_test_key(
        crate::http::shared_client()
            .get(&url)
            .timeout(StdDuration::from_secs(10)),
        &url,
    )
    .send_checked()
    .await
    .map_err(fuigo_extra_ca::dispatch::DispatchError::without_url)?;
    if !resp.status().is_success() {
        return Err(anyhow::Error::new(OidcError::DiscoveryHttp {
            status: resp.status().as_u16(),
            url,
        }));
    }
    let doc: Discovery = resp.json().await.map_err(reqwest::Error::without_url)?;
    // The document is data from the network: log origin and path only, never userinfo or a query.
    tracing::debug!(
        authorization_endpoint = %redacted_for_log(&doc.authorization_endpoint),
        token_endpoint = %redacted_for_log(&doc.token_endpoint),
        jwks_uri = ?doc.jwks_uri.as_deref().map(redacted_for_log),
        id_token_algs = ?doc.id_token_signing_alg_values_supported,
        "OIDC: discovery complete"
    );
    Ok(doc)
}
/// Origin and path of a discovery-named URL, for logs: no userinfo, no query, no fragment.
/// Only http and https URLs are rendered: any other scheme (a `blob:` URL carries a whole URL in its path)
/// is replaced by a fixed placeholder.
fn redacted_for_log(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => {
            format!("{}{}", url.origin().ascii_serialization(), url.path())
        }
        Ok(_) => "<not an http(s) URL>".to_owned(),
        Err(_) => "<not a URL>".to_owned(),
    }
}
/// The only way a credential (authorization code, PKCE verifier, refresh token) reaches a discovery-named token endpoint (P99).
///
/// Discovery is fetched from the issuer, but the document is data: it can name any URL.
/// The endpoint must be https on the issuer's own origin with no userinfo, or the one built-in split-host pair
/// (`fuigo_computer_hub_sdk::check_token_endpoint`, the same rule the workspace hub applies).
/// The shared client then keeps every redirect on that origin (`fuigo_extra_ca` credential redirect policy).
/// A refusal is [`OidcError::TokenEndpointRefused`]: nothing is sent and nothing stored is touched.
pub(super) fn checked_token_endpoint(
    issuer: &str,
    token_endpoint: &str,
) -> anyhow::Result<reqwest::Url> {
    let refused = |reason: String| anyhow::Error::new(OidcError::TokenEndpointRefused(reason));
    let url = reqwest::Url::parse(token_endpoint)
        .map_err(|_| refused("OIDC token_endpoint is not a valid URL; nothing was sent".into()))?;
    let allow_loopback_http = allow_loopback_http(
        cfg!(test),
        super::super::config::is_local_dev_issuer(issuer),
    );
    fuigo_computer_hub_sdk::check_token_endpoint(issuer, &url, allow_loopback_http)
        .map_err(refused)?;
    Ok(url)
}
/// Plain http to a loopback token endpoint (still on the issuer's own origin) is for in-process mock issuers in
/// test builds, and for the local-dev accounts app that `FUIGO_LOCAL_AUTH` selects, when it is the issuer.
/// It is never true for any other issuer in a shipped build.
fn allow_loopback_http(test_build: bool, local_dev_issuer: bool) -> bool {
    test_build || local_dev_issuer
}
/// A redirect the shared client refused to follow (another origin, or more hops than its limit on the same
/// origin) is a refusal of the token endpoint, not a transport blip: the credential never left the admitted
/// origin, so the caller must not retry it or count it against the credential.
/// Every other transport error is passed on with its URL removed (a token endpoint URL may carry a query).
fn refused_redirect(error: fuigo_extra_ca::dispatch::DispatchError) -> anyhow::Error {
    match error {
        fuigo_extra_ca::dispatch::DispatchError::Transport(error) if error.is_redirect() => {
            // The policy's own static text (`fuigo_extra_ca` redirect policy) tells a loop from a refusal.
            let too_many = std::error::Error::source(&error)
                .is_some_and(|cause| cause.to_string().contains("redirect limit"));
            let reason = if too_many {
                "OIDC token_endpoint redirected too many times; \
                 the credential was not sent outside the token endpoint's origin"
            } else {
                "OIDC token_endpoint answered with a redirect that Fuigo does not follow; \
                 the credential was not sent outside the token endpoint's origin"
            };
            anyhow::Error::new(OidcError::TokenEndpointRefused(reason.into()))
        }
        other => anyhow::Error::new(other.without_url()),
    }
}
#[cfg(test)]
pub(super) fn clear_discovery_cache() {
    DISCOVERY_CACHE.write().clear();
}
pub(in crate::auth) struct Pkce {
    pub(in crate::auth) code_verifier: String,
    pub(in crate::auth) code_challenge: String,
}
pub(in crate::auth) fn generate_pkce() -> Pkce {
    let random_bytes: [u8; 32] = rand::random();
    let code_verifier = URL_SAFE_NO_PAD.encode(random_bytes);
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    Pkce {
        code_verifier,
        code_challenge,
    }
}
pub(super) fn build_authorize_url(
    config: &OidcAuthConfig,
    oauth2: Option<&OAuth2ProviderConfig>,
    discovery: &Discovery,
    redirect_uri: &str,
    pkce: &Pkce,
    state: &str,
    nonce: &str,
) -> String {
    let scopes = config.scopes.join(" ");
    let mut url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}\
         &code_challenge={}&code_challenge_method=S256&state={}&nonce={}",
        discovery.authorization_endpoint,
        urlencoding::encode(&config.client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(&scopes),
        urlencoding::encode(&pkce.code_challenge),
        urlencoding::encode(state),
        urlencoding::encode(nonce),
    );
    if let Some(ref audience) = config.audience {
        url.push_str(&format!("&audience={}", urlencoding::encode(audience)));
    }
    if let Some(oauth2) = oauth2 {
        if let Some(ref principal_type) = oauth2.principal_type {
            url.push_str(&format!(
                "&principal_type={}",
                urlencoding::encode(principal_type)
            ));
        }
        if let Some(ref principal_id) = oauth2.principal_id {
            url.push_str(&format!(
                "&principal_id={}",
                urlencoding::encode(principal_id)
            ));
        }
    }
    let referrer = oauth2
        .and_then(|o| o.referrer.as_deref())
        .filter(|r| !r.is_empty())
        .unwrap_or("fuigo-build");
    url.push_str(&format!("&referrer={}", urlencoding::encode(referrer)));
    url
}
#[derive(Deserialize)]
pub(super) struct TokenResponse {
    pub(super) access_token: String,
    #[serde(default)]
    pub(super) refresh_token: Option<String>,
    #[serde(default)]
    pub(super) id_token: Option<String>,
    #[serde(default)]
    pub(super) expires_in: Option<u64>,
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            access_token: _,
            refresh_token,
            id_token,
            expires_in,
        } = self;
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &refresh_token.as_ref().map(|_| "<redacted>"))
            .field("id_token", &id_token.as_ref().map(|_| "<redacted>"))
            .field("expires_in", expires_in)
            .finish()
    }
}
pub(super) async fn exchange_code(
    issuer: &str,
    token_endpoint: &str,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    code_verifier: &str,
) -> anyhow::Result<TokenResponse> {
    // P99: the code and PKCE verifier go only to a token endpoint bound to the issuer.
    // Logged after the check, so a refused URL (which may carry userinfo) is never written out.
    let token_url = checked_token_endpoint(issuer, token_endpoint)?;
    tracing::debug!(token_endpoint = %redacted_for_log(token_url.as_str()), "OIDC: exchanging code for tokens");
    let resp = with_alpha_test_key(
        crate::http::shared_client()
            .post(token_url)
            // P43: identity-class header, FluxRouter-operated destinations only.
            .headers(
                fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_destination(token_endpoint)
                    .header_map([("x-fuigo-client-version", fuigo_version::VERSION)]),
            )
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("client_id", client_id),
                ("code_verifier", code_verifier),
            ])
            .timeout(std::time::Duration::from_secs(15)),
        token_endpoint,
    )
    .send_checked()
    .await
    .map_err(refused_redirect)?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::Error::new(OidcError::TokenExchangeHttp {
            status,
            body,
        }));
    }
    Ok(resp.json().await.map_err(reqwest::Error::without_url)?)
}
/// Retry gate for `refresh_tokens`.
/// Defers to `classify_terminal` (the single source of truth): only a recognized terminal code (`invalid_grant`, `invalid_client`) stops retries.
/// Everything else (5xx, 429, bare 4xx, or an unrecognized/RFC-transient code) is retried.
fn is_egress_policy_denial(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<fuigo_extra_ca::dispatch::DispatchError>(),
            Some(fuigo_extra_ca::dispatch::DispatchError::Denied(_))
        )
    })
}

fn is_transient_refresh_error(err: &anyhow::Error) -> bool {
    if is_egress_policy_denial(err) {
        return false;
    }
    if matches!(
        err.downcast_ref::<OidcError>(),
        Some(OidcError::TokenEndpointRefused(_))
    ) {
        return false;
    }
    let Some(OidcError::TokenRefreshHttp { status, body }) = err.downcast_ref::<OidcError>() else {
        return true;
    };
    if *status >= 500 || *status == 429 {
        return true;
    }
    let error_code = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error")?.as_str().map(str::to_owned));
    error_code
        .as_deref()
        .and_then(super::refresh::classify_terminal)
        .is_none()
}
/// Up to 3 attempts (1 + 2 retries), 200ms-2s jittered exponential backoff.
/// Bounded so a hard outage still surfaces to the user promptly via the existing `RefreshOutcome::TransientFailure` path.
fn refresh_retry_policy() -> backon::ExponentialBuilder {
    backon::ExponentialBuilder::default()
        .with_max_times(2)
        .with_min_delay(StdDuration::from_millis(200))
        .with_max_delay(StdDuration::from_secs(2))
        .with_jitter()
}
pub(super) async fn refresh_tokens(
    issuer: &str,
    token_endpoint: &str,
    refresh_token: &str,
    client_id: &str,
    principal_type: Option<&str>,
    principal_id: Option<&str>,
) -> anyhow::Result<TokenResponse> {
    use backon::Retryable;
    // P99: the refresh token goes only to a token endpoint bound to the issuer. Checked once, before
    // the retry loop and before logging, so a refused URL (which may carry userinfo) is never written out.
    let token_url = checked_token_endpoint(issuer, token_endpoint)?;
    let token_url = &token_url;
    tracing::debug!(
        token_endpoint = %redacted_for_log(token_url.as_str()),
        principal_type = ?principal_type,
        principal_id = ?principal_id,
        "OIDC: refreshing token"
    );
    let probe = super::refresh::SuspendProbe::start();
    (|| {
        refresh_tokens_once(
            token_url,
            refresh_token,
            client_id,
            principal_type,
            principal_id,
        )
    })
    .retry(refresh_retry_policy())
    .when(move |err: &anyhow::Error| {
        if !is_transient_refresh_error(err) {
            return false;
        }
        if probe.straddled_past_grace() {
            crate::unified_log::warn(
                "auth.refresh.retry_suppressed_suspend",
                None,
                Some(serde_json::json!({
                    "suspended_ms": probe.suspended_ms(),
                    "error": err.to_string(),
                })),
            );
            return false;
        }
        true
    })
    .await
}
/// One unretried POST to a token endpoint that [`checked_token_endpoint`] admitted (P99): the only caller is
/// [`refresh_tokens`], which hands over the checked URL.
/// Errors carry the typed `OidcError::TokenRefreshHttp` so the retry classifier can read the status code and OAuth2 `error` field without re-parsing.
async fn refresh_tokens_once(
    token_url: &reqwest::Url,
    refresh_token: &str,
    client_id: &str,
    principal_type: Option<&str>,
    principal_id: Option<&str>,
) -> anyhow::Result<TokenResponse> {
    // P70b: an IdP's `error_description` can echo the refresh token and is logged; record it for the log sinks.
    fuigo_telemetry::sent_credentials::record(refresh_token);
    let mut params = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(pt) = principal_type {
        params.push(("principal_type", pt));
    }
    if let Some(pid) = principal_id {
        params.push(("principal_id", pid));
    }
    let resp = with_alpha_test_key(
        crate::http::shared_client()
            .post(token_url.clone())
            .form(&params)
            .timeout(StdDuration::from_secs(15)),
        token_url.as_str(),
    )
    .send_checked()
    .await
    .map_err(refused_redirect)?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let error_code = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error")?.as_str().map(str::to_owned));
        tracing::warn!(
            http_status = status,
            oauth2_error = ?error_code,
            rt_prefix = %fuigo_auth::bearer_fingerprint(refresh_token),
            client_id = %client_id,
            principal_type = ?principal_type,
            "OIDC: token refresh HTTP error"
        );
        return Err(anyhow::Error::new(OidcError::TokenRefreshHttp {
            status,
            body,
        }));
    }
    Ok(resp.json().await.map_err(reqwest::Error::without_url)?)
}
#[derive(Debug, Deserialize)]
pub(super) struct IdTokenClaims {
    #[serde(default)]
    pub(super) sub: Option<String>,
    #[serde(default)]
    pub(super) email: Option<String>,
    #[serde(default)]
    pub(super) iss: Option<String>,
    #[serde(default)]
    pub(super) aud: Option<serde_json::Value>,
    #[serde(default)]
    pub(super) nonce: Option<String>,
    #[serde(default, alias = "given_name")]
    pub(super) first_name: Option<String>,
    #[serde(default, alias = "family_name")]
    pub(super) last_name: Option<String>,
    #[serde(default)]
    pub(super) picture: Option<String>,
}
pub(super) fn aud_matches(aud: &serde_json::Value, expected: &str) -> bool {
    match aud {
        serde_json::Value::String(s) => s == expected,
        serde_json::Value::Array(values) => values
            .iter()
            .any(|v| matches!(v, serde_json::Value::String(s) if s == expected)),
        _ => false,
    }
}
pub(super) fn validate_state(expected: &str, received: &str) -> anyhow::Result<()> {
    if received != expected {
        tracing::warn!(expected = %expected, received = %received, "OIDC: state mismatch");
        return Err(anyhow::Error::new(OidcError::StateMismatch));
    }
    Ok(())
}
/// Explicit JWA name mapping, so nothing couples to `jsonwebtoken::Algorithm`'s `Debug` repr.
pub(super) fn alg_to_jwa_name(alg: jsonwebtoken::Algorithm) -> &'static str {
    match alg {
        jsonwebtoken::Algorithm::RS256 => "RS256",
        jsonwebtoken::Algorithm::RS384 => "RS384",
        jsonwebtoken::Algorithm::RS512 => "RS512",
        jsonwebtoken::Algorithm::PS256 => "PS256",
        jsonwebtoken::Algorithm::PS384 => "PS384",
        jsonwebtoken::Algorithm::PS512 => "PS512",
        jsonwebtoken::Algorithm::ES256 => "ES256",
        jsonwebtoken::Algorithm::ES384 => "ES384",
        jsonwebtoken::Algorithm::EdDSA => "EdDSA",
        other => match other {
            jsonwebtoken::Algorithm::HS256 => "HS256",
            jsonwebtoken::Algorithm::HS384 => "HS384",
            jsonwebtoken::Algorithm::HS512 => "HS512",
            _ => "unknown",
        },
    }
}
pub(super) fn ensure_alg_allowed(
    alg: jsonwebtoken::Algorithm,
    discovery_supported_algs: Option<&[String]>,
) -> anyhow::Result<()> {
    let alg_name = alg_to_jwa_name(alg);
    if !ALLOWED_ID_TOKEN_ALGS.contains(&alg) {
        return Err(anyhow::Error::new(OidcError::UnsupportedAlg(
            alg_name.to_owned(),
        )));
    }
    if let Some(supported) = discovery_supported_algs
        && !supported.iter().any(|a| a == alg_name)
    {
        return Err(anyhow::Error::new(
            OidcError::AlgNotInDiscoverySupportedList {
                alg: alg_name.to_owned(),
            },
        ));
    }
    Ok(())
}
pub(super) async fn validate_and_extract_user_info(
    token: &str,
    discovery: &Discovery,
    expected_issuer: &str,
    expected_client_id: &str,
    expected_nonce: &str,
) -> anyhow::Result<OidcUserInfo> {
    crate::auth::jwt::ensure_jwt_crypto_provider();
    let header = jsonwebtoken::decode_header(token)?;
    let kid = header
        .kid
        .ok_or_else(|| anyhow::Error::new(OidcError::IdTokenMissingKid))?;
    let jwks_uri = discovery
        .jwks_uri
        .as_ref()
        .ok_or_else(|| anyhow::Error::new(OidcError::DiscoveryMissingJwksUri))?;
    let jwks: jsonwebtoken::jwk::JwkSet = with_alpha_test_key(
        crate::http::shared_client()
            .get(jwks_uri)
            .timeout(std::time::Duration::from_secs(10)),
        jwks_uri,
    )
    .send_checked()
    .await?
    .error_for_status()?
    .json()
    .await?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| anyhow::Error::new(OidcError::JwkNotFound { kid: kid.clone() }))?;
    let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk)?;
    let alg = header.alg;
    ensure_alg_allowed(
        alg,
        discovery.id_token_signing_alg_values_supported.as_deref(),
    )?;
    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.set_issuer(&[expected_issuer]);
    validation.set_audience(&[expected_client_id]);
    validation.validate_exp = true;
    validation.validate_aud = true;
    validation.required_spec_claims = ["sub", "iss", "aud", "exp"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    let token_data = jsonwebtoken::decode::<IdTokenClaims>(token, &decoding_key, &validation)?;
    if token_data.claims.iss.as_deref() != Some(expected_issuer) {
        return Err(anyhow::Error::new(OidcError::IssuerMismatch));
    }
    if let Some(ref aud) = token_data.claims.aud
        && !aud_matches(aud, expected_client_id)
    {
        return Err(anyhow::Error::new(OidcError::AudienceMismatch));
    }
    if token_data.claims.nonce.as_deref() != Some(expected_nonce) {
        return Err(anyhow::Error::new(OidcError::NonceMismatch));
    }
    Ok(OidcUserInfo {
        user_id: token_data
            .claims
            .sub
            .unwrap_or_else(|| "unknown".to_string()),
        email: token_data.claims.email,
        first_name: token_data.claims.first_name,
        last_name: token_data.claims.last_name,
        profile_image_asset_id: token_data.claims.picture,
        principal_type: None,
        principal_id: None,
        team_id: None,
        team_name: None,
        team_role: None,
        organization_id: None,
        organization_name: None,
        organization_role: None,
        user_blocked_reason: None,
        team_blocked_reasons: vec![],
        coding_data_retention_opt_out: crate::auth::default_coding_data_retention_opt_out(),
    })
}
pub(super) async fn extract_user_info(
    id_token: Option<&str>,
    discovery: &Discovery,
    expected_issuer: &str,
    expected_client_id: &str,
    expected_nonce: &str,
    principal_type: Option<&str>,
    principal_id: Option<&str>,
    fallback_team_id: Option<String>,
) -> anyhow::Result<OidcUserInfo> {
    if principal_type == Some(crate::auth::model::TEAM_PRINCIPAL_TYPE) {
        let team_user_id = principal_id.unwrap_or("unknown").to_owned();
        return Ok(OidcUserInfo {
            user_id: team_user_id,
            email: None,
            first_name: None,
            last_name: None,
            profile_image_asset_id: None,
            principal_type: Some(crate::auth::model::TEAM_PRINCIPAL_TYPE.to_string()),
            principal_id: principal_id.map(ToOwned::to_owned),
            team_id: principal_id.map(ToOwned::to_owned).or(fallback_team_id),
            team_name: None,
            team_role: None,
            organization_id: None,
            organization_name: None,
            organization_role: None,
            user_blocked_reason: None,
            team_blocked_reasons: vec![],
            coding_data_retention_opt_out: crate::auth::default_coding_data_retention_opt_out(),
        });
    }
    let token = id_token.ok_or_else(|| anyhow::Error::new(OidcError::MissingIdToken))?;
    validate_and_extract_user_info(
        token,
        discovery,
        expected_issuer,
        expected_client_id,
        expected_nonce,
    )
    .await
    .map(|mut user_info| {
        user_info.principal_type = principal_type.map(ToOwned::to_owned);
        user_info.principal_id = principal_id.map(ToOwned::to_owned);
        if user_info.team_id.is_none() {
            user_info.team_id = fallback_team_id;
        }
        user_info
    })
    .map_err(|e| anyhow::Error::new(OidcError::IdTokenValidationFailed(e.to_string())))
}
#[cfg(test)]
mod tests {
    use super::super::test_helpers::*;
    use super::*;
    /// P43 hostile: a token endpoint that is not FluxRouter-operated gets no client version.
    #[tokio::test(flavor = "current_thread")]
    async fn code_exchange_sends_no_identity_to_a_non_fluxrouter_issuer() {
        let (base, seen, handle) = crate::remote::identity_tests::spawn_recording_mock("{}").await;
        let _ = exchange_code(&base, &format!("{base}/token"), "code", "http://127.0.0.1/cb", "id", "v").await;
        handle.abort();
        crate::remote::identity_tests::assert_no_identity_headers(&seen, "oidc_exchange_code");
    }
    #[test]
    fn pkce_s256_challenge_matches_verifier() {
        let pkce = generate_pkce();
        assert_eq!(pkce.code_verifier.len(), 43);
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce.code_verifier.as_bytes()));
        assert_eq!(pkce.code_challenge, expected);
    }
    #[test]
    fn authorize_url_includes_required_oidc_params() {
        let config = OidcAuthConfig {
            issuer: "https://example.okta.com".into(),
            client_id: TEST_CLIENT_ID.into(),
            scopes: vec!["openid".into(), "profile".into()],
            audience: Some("api://fuigo".into()),
        };
        let discovery = Discovery {
            authorization_endpoint: "https://example.okta.com/authorize".into(),
            token_endpoint: "https://example.okta.com/token".into(),
            jwks_uri: None,
            id_token_signing_alg_values_supported: None,
        };
        let pkce = Pkce {
            code_verifier: "v".into(),
            code_challenge: "c".into(),
        };
        let nonce = test_nonce();
        let nonce_q = format!("nonce={nonce}");
        let url = build_authorize_url(
            &config,
            None,
            &discovery,
            "http://127.0.0.1:9999/callback",
            &pkce,
            "state123",
            &nonce,
        );
        for required in [
            "response_type=code",
            "client_id=test-client-id",
            "code_challenge=c",
            "code_challenge_method=S256",
            "state=state123",
            nonce_q.as_str(),
            "scope=openid",
            "audience=api",
            "referrer=fuigo-build",
        ] {
            assert!(url.contains(required), "missing param: {required}");
        }
        assert_eq!(
            url.matches("referrer=").count(),
            1,
            "expected exactly one referrer param, got: {url}"
        );
    }
    #[test]
    fn authorize_url_includes_team_principal_params() {
        let config = OidcAuthConfig {
            issuer: "https://auth.x.ai".into(),
            client_id: TEST_CLIENT_ID.into(),
            scopes: vec!["offline_access".into(), "grok-cli:access".into()],
            audience: None,
        };
        let oauth2 = OAuth2ProviderConfig {
            issuer: "https://auth.x.ai".into(),
            client_id: TEST_CLIENT_ID.into(),
            scopes: vec!["offline_access".into(), "grok-cli:access".into()],
            principal_type: Some("Team".into()),
            principal_id: Some("team-123".into()),
            referrer: Some("fuigo-build".into()),
        };
        let discovery = Discovery {
            authorization_endpoint: "https://auth.x.ai/authorize".into(),
            token_endpoint: "https://auth.x.ai/token".into(),
            jwks_uri: None,
            id_token_signing_alg_values_supported: None,
        };
        let pkce = Pkce {
            code_verifier: "v".into(),
            code_challenge: "c".into(),
        };
        let url = build_authorize_url(
            &config,
            Some(&oauth2),
            &discovery,
            "http://127.0.0.1:9999/callback",
            &pkce,
            "state123",
            &test_nonce(),
        );
        assert!(url.contains("principal_type=Team"));
        assert!(url.contains("principal_id=team-123"));
        assert!(url.contains("referrer=fuigo-build"));
        assert_eq!(
            url.matches("referrer=").count(),
            1,
            "expected exactly one referrer param, got: {url}"
        );
    }
    #[test]
    fn authorize_url_uses_oauth2_referrer_override_once() {
        let config = OidcAuthConfig {
            issuer: "https://auth.x.ai".into(),
            client_id: TEST_CLIENT_ID.into(),
            scopes: vec!["offline_access".into(), "grok-cli:access".into()],
            audience: None,
        };
        let oauth2 = OAuth2ProviderConfig {
            issuer: "https://auth.x.ai".into(),
            client_id: TEST_CLIENT_ID.into(),
            scopes: vec!["offline_access".into(), "grok-cli:access".into()],
            principal_type: None,
            principal_id: None,
            referrer: Some("fuigo-desktop".into()),
        };
        let discovery = Discovery {
            authorization_endpoint: "https://auth.x.ai/authorize".into(),
            token_endpoint: "https://auth.x.ai/token".into(),
            jwks_uri: None,
            id_token_signing_alg_values_supported: None,
        };
        let pkce = Pkce {
            code_verifier: "v".into(),
            code_challenge: "c".into(),
        };
        let url = build_authorize_url(
            &config,
            Some(&oauth2),
            &discovery,
            "http://127.0.0.1:9999/callback",
            &pkce,
            "state123",
            &test_nonce(),
        );
        assert!(url.contains("referrer=fuigo-desktop"));
        assert!(!url.contains("referrer=fuigo-build"));
        assert_eq!(
            url.matches("referrer=").count(),
            1,
            "expected exactly one referrer param, got: {url}"
        );
    }
    #[tokio::test]
    async fn extract_user_info_allows_team_without_id_token() {
        let discovery = Discovery {
            authorization_endpoint: "https://example.okta.com/authorize".into(),
            token_endpoint: "https://example.okta.com/token".into(),
            jwks_uri: Some("https://example.okta.com/jwks".into()),
            id_token_signing_alg_values_supported: Some(vec!["RS256".into()]),
        };
        let user_info = extract_user_info(
            None,
            &discovery,
            "https://example.okta.com",
            "test-client",
            &test_nonce(),
            Some("Team"),
            Some("team-123"),
            None,
        )
        .await
        .expect("team login should not require id_token");
        assert_eq!(
            user_info.user_id, "team-123",
            "team user_id should be the principal_id"
        );
        assert_eq!(user_info.principal_type.as_deref(), Some("Team"));
        assert_eq!(user_info.principal_id.as_deref(), Some("team-123"));
        assert_eq!(user_info.team_id.as_deref(), Some("team-123"));
        assert!(user_info.email.is_none());
    }
    #[test]
    fn validate_state_rejects_mismatch() {
        let err = validate_state("expected-state", "wrong-state").unwrap_err();
        assert!(
            err.to_string().contains("state mismatch"),
            "unexpected error: {err}"
        );
    }
    #[tokio::test]
    async fn id_token_validation_fails_on_nonce_mismatch() {
        ensure_crypto_provider();
        let (issuer, id_token, discovery, handle) = mock_idp_token().await;
        let err = extract_user_info(
            Some(&id_token),
            &discovery,
            &issuer,
            TEST_CLIENT_ID,
            "wrong-nonce",
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("nonce mismatch"),
            "unexpected error: {err}"
        );
        handle.abort();
    }
    #[test]
    fn rejects_unsupported_id_token_alg() {
        let err = ensure_alg_allowed(jsonwebtoken::Algorithm::HS256, Some(&["RS256".to_string()]))
            .unwrap_err();
        assert!(
            err.to_string().contains("unsupported algorithm"),
            "unexpected error: {err}"
        );
    }
    #[tokio::test]
    async fn id_token_validation_fails_on_audience_mismatch() {
        ensure_crypto_provider();
        let (issuer, id_token, discovery, handle) = mock_idp_token().await;
        let err = extract_user_info(
            Some(&id_token),
            &discovery,
            &issuer,
            "wrong-client",
            &test_nonce(),
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("audience mismatch")
                || err.to_string().contains("InvalidAudience"),
            "unexpected error: {err}"
        );
        handle.abort();
    }
    /// JWT principal-extraction matrix:
    ///   - team JWT: extracts (Team, team_id, None)
    ///   - non-JWT garbage / empty: returns None
    ///   - JWT without principal_type/_id: returns None
    #[test]
    fn peek_access_token_principal_matrix() {
        ensure_crypto_provider();
        fn make_jwt(claims: serde_json::Value) -> String {
            let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
            crate::auth::jwt::ensure_jwt_crypto_provider();
            jsonwebtoken::encode(
                &header,
                &claims,
                &jsonwebtoken::EncodingKey::from_secret(b"test-secret"),
            )
            .unwrap()
        }
        let team_jwt = make_jwt(serde_json::json!({
            "sub": "user-42",
            "iss": "https://auth.x.ai",
            "aud": "test-client",
            "exp": 9999999999u64,
            "iat": 1000000000u64,
            "scope": "offline_access grok-cli:access api:access",
            "principal_type": "Team",
            "principal_id": "team-abc-123",
            "client_id": "test-client",
            "jti": "token-1",
        }));
        let (pt, pid, tid) = peek_access_token_principal(&team_jwt).expect("team principal");
        assert_eq!(pt, "Team");
        assert_eq!(pid, "team-abc-123");
        assert_eq!(tid, None);
        assert!(peek_access_token_principal("not-a-jwt-token").is_none());
        assert!(peek_access_token_principal("").is_none());
        let no_principal = make_jwt(serde_json::json!({
            "sub": "user-42",
            "iss": "https://auth.x.ai",
            "aud": "test-client",
            "exp": 9999999999u64,
            "iat": 1000000000u64,
        }));
        assert!(peek_access_token_principal(&no_principal).is_none());
    }
    /// `peek_access_token_principal_id` extracts the id even when `principal_type` is absent.
    /// The stricter `peek_access_token_principal` returns `None` there.
    #[test]
    fn peek_access_token_principal_id_does_not_require_type() {
        ensure_crypto_provider();
        fn make_jwt(claims: serde_json::Value) -> String {
            crate::auth::jwt::ensure_jwt_crypto_provider();
            jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
                &claims,
                &jsonwebtoken::EncodingKey::from_secret(b"test-secret"),
            )
            .unwrap()
        }
        let id_only = make_jwt(serde_json::json!({ "principal_id": "team-abc", "sub": "u" }));
        assert_eq!(
            peek_access_token_principal_id(&id_only).as_deref(),
            Some("team-abc"),
        );
        assert!(
            peek_access_token_principal(&id_only).is_none(),
            "the strict peek still needs principal_type",
        );
        let none = make_jwt(serde_json::json!({ "sub": "u" }));
        assert!(peek_access_token_principal_id(&none).is_none());
        assert!(peek_access_token_principal_id("not-a-jwt").is_none());
    }
    /// Enforcement matrix: None passes; Single/AnyOf require a match (and reject a no-principal token); empty AnyOf fails closed.
    #[test]
    fn enforce_login_principal_matrix() {
        assert!(enforce_login_principal(None, None).is_ok());
        assert!(enforce_login_principal(None, Some("team-abc")).is_ok());
        let single = ForceLoginTeam::Single("team-abc".into());
        assert!(enforce_login_principal(Some(&single), Some("team-abc")).is_ok());
        let err = enforce_login_principal(Some(&single), Some("team-other")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "This deployment requires logging into team team-abc; \
             your login returned team-other",
        );
        let err = enforce_login_principal(Some(&single), None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "This deployment requires logging into team team-abc; \
             your login returned no team principal",
        );
        let any_of = ForceLoginTeam::AnyOf(vec!["team-a".into(), "team-b".into()]);
        assert!(enforce_login_principal(Some(&any_of), Some("team-b")).is_ok());
        let err = enforce_login_principal(Some(&any_of), Some("team-c")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "This deployment requires logging into one of teams: team-a, team-b; \
             your login returned team-c",
        );
        let err = enforce_login_principal(Some(&ForceLoginTeam::AnyOf(vec![])), Some("team-a"))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Login is blocked by your administrator: force_login_team_uuid is an empty \
             list, so no team is permitted to sign in",
        );
    }
    /// Only the dedicated `force_login_team_uuid` knob produces an enforcement policy.
    /// The legacy `oauth2.principal_id` is pre-select-only and never an enforcement gate.
    #[test]
    fn resolve_login_principal_policy_uses_force_login_team_only() {
        assert_eq!(resolve_login_principal_policy(None), None);
        assert_eq!(
            resolve_login_principal_policy(Some(&ForceLoginTeam::Single("team-locked".into()))),
            Some(ForceLoginTeam::Single("team-locked".into())),
        );
        assert_eq!(
            resolve_login_principal_policy(Some(&ForceLoginTeam::AnyOf(vec![
                "a".into(),
                "b".into()
            ]))),
            Some(ForceLoginTeam::AnyOf(vec!["a".into(), "b".into()])),
        );
    }
    /// Discovery is cached for `DISCOVERY_CACHE_TTL`.
    /// The second call to `discover()` for the same issuer hits the cache and does not fetch over HTTP.
    /// Without the cache, every refresh pays a discovery round-trip and a discovery-endpoint blip blocks token refresh.
    #[tokio::test]
    async fn discover_uses_cache_within_ttl() {
        use std::sync::atomic::{AtomicU32, Ordering};
        clear_discovery_cache();
        let hits = std::sync::Arc::new(AtomicU32::new(0));
        let hits_for_handler = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let issuer_for_handler = issuer.clone();
        let app = axum::Router::new().route(
            "/.well-known/openid-configuration",
            axum::routing::get(move || {
                let b = issuer_for_handler.clone();
                let counter = hits_for_handler.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({
                        "authorization_endpoint": format!("{b}/authorize"),
                        "token_endpoint": format!("{b}/token"),
                    }))
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let _ = discover(&issuer).await.unwrap();
        let _ = discover(&issuer).await.unwrap();
        let _ = discover(&issuer).await.unwrap();
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "discover() must hit the network exactly once across 3 calls (cache TTL = 1h)"
        );
        server.abort();
    }
    /// `refresh_tokens` retries on a transient 503 and succeeds on the next attempt.
    /// Without backon, a single IdP blip during refresh surfaces to the user as a chat failure.
    #[tokio::test]
    async fn refresh_tokens_retries_on_transient_5xx() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let hits = std::sync::Arc::new(AtomicU32::new(0));
        let hits_for_handler = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new().route(
            "/token",
            axum::routing::post(move || {
                let counter = hits_for_handler.clone();
                async move {
                    let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    if n == 1 {
                        (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            "upstream busy".to_string(),
                        )
                    } else {
                        (
                            axum::http::StatusCode::OK,
                            r#"{"access_token":"new-at","expires_in":3600}"#.to_string(),
                        )
                    }
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let issuer = format!("http://127.0.0.1:{port}");
        let token_endpoint = format!("{issuer}/token");
        let resp = refresh_tokens(&issuer, &token_endpoint, "rt", "client", None, None)
            .await
            .expect("transient 5xx must be retried until success");
        assert_eq!(resp.access_token, "new-at");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "first attempt fails 503, second succeeds — exactly 2 hits"
        );
        server.abort();
    }
    /// Terminal OAuth2 errors (`invalid_grant`, `invalid_client`) MUST NOT be retried.
    /// Retrying a revoked grant just wastes time and risks rate-limit.
    /// Verifies `is_transient_refresh_error` correctly classifies typed 4xx as terminal.
    #[tokio::test]
    async fn refresh_tokens_does_not_retry_terminal_invalid_grant() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let hits = std::sync::Arc::new(AtomicU32::new(0));
        let hits_for_handler = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new().route(
            "/token",
            axum::routing::post(move || {
                let counter = hits_for_handler.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        r#"{"error":"invalid_grant","error_description":"refresh token revoked"}"#
                            .to_string(),
                    )
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let issuer = format!("http://127.0.0.1:{port}");
        let token_endpoint = format!("{issuer}/token");
        let err = refresh_tokens(&issuer, &token_endpoint, "rt", "client", None, None)
            .await
            .expect_err("invalid_grant is terminal");
        assert!(
            err.to_string().contains("400") || err.to_string().contains("invalid_grant"),
            "error must surface the IdP rejection, got: {err}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "terminal OAuth2 error must NOT be retried (exactly 1 hit)"
        );
        server.abort();
    }
    /// A 4xx carrying an OAuth2 code that is NOT a recognized terminal one (e.g. RFC 6749 `temporarily_unavailable`) must be retried.
    /// The retry gate defers to `classify_terminal`, so only the recognized terminal codes stop retries; everything else is transient.
    #[tokio::test]
    async fn refresh_tokens_retries_on_coded_transient_error() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let hits = std::sync::Arc::new(AtomicU32::new(0));
        let hits_for_handler = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new().route(
            "/token",
            axum::routing::post(move || {
                let counter = hits_for_handler.clone();
                async move {
                    let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    if n == 1 {
                        (
                            axum::http::StatusCode::BAD_REQUEST,
                            r#"{"error":"temporarily_unavailable"}"#.to_string(),
                        )
                    } else {
                        (
                            axum::http::StatusCode::OK,
                            r#"{"access_token":"new-at","expires_in":3600}"#.to_string(),
                        )
                    }
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let issuer = format!("http://127.0.0.1:{port}");
        let token_endpoint = format!("{issuer}/token");
        let resp = refresh_tokens(&issuer, &token_endpoint, "rt", "client", None, None)
            .await
            .expect("a non-terminal coded 4xx must be retried until success");
        assert_eq!(resp.access_token, "new-at");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "temporarily_unavailable must be retried (1 fail + 1 success = 2 hits)"
        );
        server.abort();
    }
    #[test]
    fn callback_timeout_error_is_user_friendly() {
        let err: anyhow::Error = OidcError::CallbackTimeout.into();
        let msg = err.to_string();
        assert!(
            msg.contains("Login timed out after 10 minutes"),
            "expected friendly timeout message, got: {msg}"
        );
        assert!(
            msg.contains("Please try again"),
            "expected 'Please try again' call to action, got: {msg}"
        );
        assert!(
            !msg.contains("OIDC"),
            "should not leak internal 'OIDC' terminology to users, got: {msg}"
        );
        assert!(
            !msg.contains("300s"),
            "should not mention raw seconds, got: {msg}"
        );
    }
}

/// P99: credentials reach a discovery-named token endpoint only when it is bound to the issuer.
#[cfg(test)]
mod token_endpoint_binding_tests {
    use super::*;
    use std::sync::Arc;

    type Bodies = Arc<parking_lot::Mutex<Vec<String>>>;

    /// Records every request body and answers like a token endpoint, so a credential that
    /// reaches it is both accepted and recorded.
    async fn spawn_recorder() -> (String, Bodies, tokio::task::JoinHandle<()>) {
        let bodies = Bodies::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().fallback({
            let bodies = bodies.clone();
            move |body: String| {
                bodies.lock().push(body);
                async {
                    axum::Json(serde_json::json!({
                        "access_token": "recorder-access",
                        "refresh_token": "recorder-refresh",
                        "expires_in": 3600,
                    }))
                }
            }
        });
        let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (base, bodies, handle)
    }

    fn refusal(error: &anyhow::Error) -> &str {
        match error.downcast_ref::<OidcError>() {
            Some(OidcError::TokenEndpointRefused(reason)) => reason,
            other => panic!("expected TokenEndpointRefused, got {other:?} / {error:#}"),
        }
    }

    /// The shell's rule is the shared one: the issuer's own origin, or the one built-in pair.
    #[test]
    fn checked_token_endpoint_applies_the_shared_rule() {
        for (issuer, endpoint) in [
            ("https://acme.okta.com", "https://acme.okta.com/oauth2/v1/token"),
            ("https://acme.okta.com/", "https://acme.okta.com:443/token"),
            ("https://accounts.google.com", "https://oauth2.googleapis.com/token"),
            // In-process mock issuers (test builds only).
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080/token"),
        ] {
            let url = checked_token_endpoint(issuer, endpoint)
                .unwrap_or_else(|error| panic!("{issuer} -> {endpoint}: {error:#}"));
            assert_eq!(url, reqwest::Url::parse(endpoint).unwrap());
        }
        for (issuer, endpoint, why) in [
            ("https://acme.okta.com", "https://evil.example/token", "issuer's origin"),
            ("https://acme.okta.com", "https://acme.okta.com.evil.example/token", "issuer's origin"),
            ("https://acme.okta.com", "https://acme.okta.com:8443/token", "issuer's origin"),
            ("https://acme.okta.com", "http://acme.okta.com/token", "not https"),
            ("https://acme.okta.com", "https://user:pw@acme.okta.com/token", "userinfo"),
            ("https://acme.okta.com", "https://oauth2.googleapis.com/token", "issuer's origin"),
            ("https://accounts.google.com", "https://evil.oauth2.googleapis.com/token", "issuer's origin"),
            ("http://127.0.0.1:8080", "http://127.0.0.1:9090/token", "issuer's origin"),
            ("https://acme.okta.com", "not a url", "not a valid URL"),
            ("https://acme.okta.com", "/oauth2/token", "not a valid URL"),
        ] {
            let error = checked_token_endpoint(issuer, endpoint)
                .expect_err(&format!("{issuer} -> {endpoint} must be refused"));
            let reason = refusal(&error);
            assert!(reason.contains(why), "{issuer} -> {endpoint}: {reason}");
            assert!(reason.contains("nothing was sent"), "{reason}");
        }
    }

    /// What reaches a log from a discovery-named URL: origin and path, never userinfo or a query.
    #[test]
    fn discovery_named_urls_are_redacted_for_logs() {
        for (url, logged) in [
            ("https://idp.example/oauth2/token", "https://idp.example/oauth2/token"),
            ("https://user:secret@idp.example/token", "https://idp.example/token"),
            ("https://idp.example:8443/token?key=secret#frag", "https://idp.example:8443/token"),
            ("not a url", "<not a URL>"),
            ("blob:https://user:secret@idp.example/token", "<not an http(s) URL>"),
            ("ftp://user:secret@idp.example/token", "<not an http(s) URL>"),
            ("data:text/plain,secret", "<not an http(s) URL>"),
        ] {
            let rendered = redacted_for_log(url);
            assert_eq!(rendered, logged, "{url}");
            assert!(!rendered.contains("secret"), "{url}: {rendered}");
        }
    }

    /// A transport error from an admitted token endpoint does not carry the endpoint's URL (it may
    /// hold a query) into the error text that the refresh path writes to its logs.
    #[tokio::test]
    async fn transport_errors_from_the_token_endpoint_do_not_carry_its_url() {
        // A loopback port with nothing listening: the connection is refused.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let issuer = format!("http://127.0.0.1:{port}");
        let endpoint = format!("{issuer}/token?tenant_key=query-secret");
        let refresh = refresh_tokens(&issuer, &endpoint, "the-refresh-token", "client", None, None)
            .await
            .expect_err("nothing is listening");
        let exchange = exchange_code(&issuer, &endpoint, "the-code", "http://127.0.0.1/cb", "client", "v")
            .await
            .expect_err("nothing is listening");
        for error in [refresh, exchange] {
            assert!(
                error.downcast_ref::<OidcError>().is_none(),
                "a refused connection is a transport error, not a refusal: {error:#}"
            );
            for text in [error.to_string(), format!("{error:#}"), format!("{error:?}")] {
                assert!(!text.contains("query-secret"), "{text}");
                assert!(!text.contains("tenant_key"), "{text}");
                assert!(!text.contains("the-refresh-token"), "{text}");
            }
        }
    }

    /// The local-dev exemption needs BOTH the variable and the exact local issuer; any other
    /// issuer never gets it, whatever the environment says, and the local issuer does not get it
    /// without the variable.
    #[test]
    fn local_dev_http_exemption_is_only_for_the_local_dev_issuer() {
        use crate::auth::config::{is_local_dev_issuer, is_local_dev_issuer_when};
        for issuer in ["http://localhost:22255", "http://localhost:22255/"] {
            assert!(is_local_dev_issuer_when(true, issuer), "{issuer}");
            assert!(!is_local_dev_issuer_when(false, issuer), "{issuer}");
        }
        for issuer in [
            "https://acme.okta.com",
            "http://acme.okta.com",
            "http://localhost:8080",
            "http://127.0.0.1:22255",
            "https://localhost:22255",
            "http://localhost:22255.evil.example",
            "http://evil.example/localhost:22255",
        ] {
            for local_auth in [false, true] {
                assert!(!is_local_dev_issuer_when(local_auth, issuer), "{issuer}");
            }
            assert!(!is_local_dev_issuer(issuer), "{issuer}");
        }
    }

    /// What a shipped build passes as `allow_loopback_http`: nothing but the local-dev issuer.
    #[test]
    fn a_shipped_build_admits_loopback_http_only_for_the_local_dev_issuer() {
        assert!(!allow_loopback_http(false, false));
        assert!(allow_loopback_http(false, true));
        assert!(allow_loopback_http(true, false));
        // The rule a shipped build then applies to any other issuer: http is refused, loopback or not.
        for (issuer, endpoint) in [
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080/token"),
            ("http://localhost:8080", "http://localhost:8080/token"),
            ("http://idp.example", "http://idp.example/token"),
        ] {
            let url = reqwest::Url::parse(endpoint).unwrap();
            let shipped = allow_loopback_http(
                false,
                crate::auth::config::is_local_dev_issuer_when(true, issuer),
            );
            let error = fuigo_computer_hub_sdk::check_token_endpoint(issuer, &url, shipped)
                .expect_err(endpoint);
            assert!(error.contains("not https"), "{endpoint}: {error}");
        }
        // The local-dev issuer with the variable set: its own loopback origin only.
        let local = "http://localhost:22255";
        let shipped = allow_loopback_http(
            false,
            crate::auth::config::is_local_dev_issuer_when(true, local),
        );
        let url = |s: &str| reqwest::Url::parse(s).unwrap();
        assert_eq!(
            fuigo_computer_hub_sdk::check_token_endpoint(
                local,
                &url("http://localhost:22255/oauth2/token"),
                shipped
            ),
            Ok(())
        );
        for endpoint in [
            "http://localhost:9999/token",
            "http://127.0.0.1:22255/token",
            "http://evil.example/token",
            "https://evil.example/token",
        ] {
            assert!(
                fuigo_computer_hub_sdk::check_token_endpoint(local, &url(endpoint), shipped)
                    .is_err(),
                "{endpoint}"
            );
        }
    }

    /// The authorization code and PKCE verifier are not sent to a token endpoint off the
    /// issuer's origin, and the same call with the endpoint on the issuer's origin is sent.
    #[tokio::test]
    async fn exchange_code_sends_the_code_only_to_the_issuer_origin() {
        let (issuer, own, own_server) = spawn_recorder().await;
        let (foreign, foreign_bodies, foreign_server) = spawn_recorder().await;
        let error = exchange_code(
            &issuer,
            &format!("{foreign}/token"),
            "the-code",
            "http://127.0.0.1/callback",
            "client",
            "the-verifier",
        )
        .await
        .expect_err("a foreign token endpoint must be refused");
        assert!(refusal(&error).contains("issuer's origin"), "{error:#}");
        assert!(foreign_bodies.lock().is_empty(), "{:?}", foreign_bodies.lock());
        assert!(own.lock().is_empty(), "a refusal sends nothing anywhere");

        let tokens = exchange_code(
            &issuer,
            &format!("{issuer}/token"),
            "the-code",
            "http://127.0.0.1/callback",
            "client",
            "the-verifier",
        )
        .await
        .expect("the issuer's own token endpoint is used");
        assert_eq!(tokens.access_token, "recorder-access");
        let own = own.lock().clone();
        assert_eq!(own.len(), 1, "{own:?}");
        assert!(own[0].contains("code=the-code"), "{own:?}");
        assert!(own[0].contains("code_verifier=the-verifier"), "{own:?}");
        assert!(foreign_bodies.lock().is_empty());
        own_server.abort();
        foreign_server.abort();
    }

    /// The refresh token is not sent to a token endpoint off the issuer's origin: refused once,
    /// with no retries, and the same call with the endpoint on the issuer's origin is sent.
    #[tokio::test]
    async fn refresh_tokens_sends_the_refresh_token_only_to_the_issuer_origin() {
        let (issuer, own, own_server) = spawn_recorder().await;
        let (foreign, foreign_bodies, foreign_server) = spawn_recorder().await;
        let error = refresh_tokens(
            &issuer,
            &format!("{foreign}/token"),
            "the-refresh-token",
            "client",
            None,
            None,
        )
        .await
        .expect_err("a foreign token endpoint must be refused");
        assert!(refusal(&error).contains("issuer's origin"), "{error:#}");
        assert!(!is_transient_refresh_error(&error), "a refusal is not retried");
        assert!(foreign_bodies.lock().is_empty(), "{:?}", foreign_bodies.lock());
        assert!(own.lock().is_empty(), "a refusal sends nothing anywhere");

        let tokens = refresh_tokens(
            &issuer,
            &format!("{issuer}/token"),
            "the-refresh-token",
            "client",
            None,
            None,
        )
        .await
        .expect("the issuer's own token endpoint is used");
        assert_eq!(tokens.access_token, "recorder-access");
        let own = own.lock().clone();
        assert_eq!(own.len(), 1, "{own:?}");
        assert!(own[0].contains("refresh_token=the-refresh-token"), "{own:?}");
        assert!(foreign_bodies.lock().is_empty());
        own_server.abort();
        foreign_server.abort();
    }
}
#[cfg(test)]
mod egress_policy_tests {
    use super::*;
    #[test]
    fn egress_policy_denial_is_not_transient_oauth_failure() {
        let error = anyhow::Error::new(fuigo_extra_ca::dispatch::DispatchError::Denied("blocked"))
            .context("refresh request");
        assert!(is_egress_policy_denial(&error));
        assert!(!is_transient_refresh_error(&error));
    }
}

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
    fn token_response_debug_redacts_every_token() {
        let response: TokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "p70ac-FAKE-1a2b3c4d",
            "refresh_token": "p70rf-FAKE-5e6f7a8b",
            "id_token": "p70id-FAKE-9c0d1e2f",
            "expires_in": 60,
        }))
        .expect("token response");
        assert_redacted(&response, &["p70ac-FAKE-1a2b3c4d", "p70rf-FAKE-5e6f7a8b", "p70id-FAKE-9c0d1e2f"]);
    }
}
