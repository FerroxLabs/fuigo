//! [`AuthProvider`] that refreshes OIDC tokens before they expire.
//!
//! `current()` checks token expiry and, if needed, performs OIDC
//! discovery + token exchange before returning the credential.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;

use crate::auth::{AuthCredential, AuthIdentity, AuthProvider};

pub type OnRefreshCallback = Arc<dyn Fn(&RefreshEvent) + Send + Sync>;

#[derive(Clone)]
pub struct RefreshEvent {
    pub access_token: String,
    pub new_refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for RefreshEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            access_token: _,
            new_refresh_token,
            expires_at,
        } = self;
        f.debug_struct("RefreshEvent")
            .field("access_token", &"<redacted>")
            .field("new_refresh_token", &new_refresh_token.as_ref().map(|_| "<redacted>"))
            .field("expires_at", expires_at)
            .finish()
    }
}

struct TokenState {
    access_token: String,
    refresh_token: String,
    expires_at: Option<DateTime<Utc>>,
}

type UrlPolicy = Arc<dyn Fn(&reqwest::Url) -> Result<(), String> + Send + Sync>;

struct HttpTransport {
    client: reqwest::Client,
    check_url: UrlPolicy,
}

pub struct OidcAuthProvider {
    state: Mutex<TokenState>,
    issuer: String,
    client_id: String,
    user_id: Option<String>,
    principal_type: Option<String>,
    principal_id: Option<String>,
    on_refresh: Option<OnRefreshCallback>,
    http_transport: Option<HttpTransport>,
}

const REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// The one built-in split-host identity provider (P99). Google's issuer is
/// `https://accounts.google.com` and its discovery document names a token endpoint on
/// `https://oauth2.googleapis.com`. This is a single exact, directed pair of https
/// origins on the default port, compiled in. It is not a list and it is not configurable.
const SPLIT_HOST_ISSUER_HOST: &str = "accounts.google.com";
const SPLIT_HOST_TOKEN_HOST: &str = "oauth2.googleapis.com";

/// True only for the issuer origin `https://accounts.google.com` paired with the token
/// endpoint origin `https://oauth2.googleapis.com`. Host comparison is exact (the URL
/// parser has already lowercased it): no subdomain, no suffix, no trailing dot. The
/// caller has already refused userinfo on the token endpoint.
fn is_builtin_split_host_pair(issuer: &reqwest::Url, token_endpoint: &reqwest::Url) -> bool {
    let https_origin = |url: &reqwest::Url, host: &str| {
        url.scheme() == "https"
            && url.host_str() == Some(host)
            && url.port_or_known_default() == Some(443)
    };
    issuer.username().is_empty()
        && issuer.password().is_none()
        && https_origin(issuer, SPLIT_HOST_ISSUER_HOST)
        && https_origin(token_endpoint, SPLIT_HOST_TOKEN_HOST)
}

/// A credential (refresh token, authorization code) may go only to an https
/// `token_endpoint` on the issuer's own origin (scheme, host and port), with no userinfo
/// (P87, audit CB-3). A discovery document naming any other recipient is refused before
/// anything is sent: a hostile or compromised discovery response must not be able to
/// collect the credential. Used by the hub refresh (this SDK, `fuigo-workspace`) and by
/// the shell's own OIDC login and refresh (P99).
///
/// One exception, built in: the exact pair in [`is_builtin_split_host_pair`]. Every other
/// issuer whose token endpoint lives on another host is refused: the request is not sent
/// and the stored token is kept.
///
/// `allow_loopback_http` admits a plain-http endpoint on a loopback host, still on
/// the issuer's origin. It exists for in-process mock issuers: the hub callers pass
/// `cfg!(test)`, which is never true in a shipped build. The shell passes `true` in a
/// shipped build in one case only, its developer-only local accounts app
/// (`FUIGO_LOCAL_AUTH`, issuer `http://localhost:22255`).
///
/// This binds the first hop only; the client that sends the credential must also refuse
/// cross-origin redirects.
pub fn check_token_endpoint(
    issuer: &str,
    token_endpoint: &reqwest::Url,
    allow_loopback_http: bool,
) -> Result<(), String> {
    let issuer = reqwest::Url::parse(issuer.trim_end_matches('/'))
        .map_err(|_| "OIDC issuer is not a valid URL; nothing was sent".to_string())?;
    if !token_endpoint.username().is_empty() || token_endpoint.password().is_some() {
        return Err("OIDC token_endpoint carries userinfo; nothing was sent".into());
    }
    let loopback = token_endpoint.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    let scheme_ok = token_endpoint.scheme() == "https"
        || (allow_loopback_http && loopback && token_endpoint.scheme() == "http");
    if !scheme_ok {
        return Err("OIDC token_endpoint is not https; nothing was sent".into());
    }
    if token_endpoint.origin() != issuer.origin()
        && !is_builtin_split_host_pair(&issuer, token_endpoint)
    {
        return Err("OIDC token_endpoint is not on the issuer's origin; nothing was sent".into());
    }
    Ok(())
}

/// Redirects for the SDK's default client: at most 10, each to the origin of the
/// request that was redirected. An injected client (`http_transport`) brings its own
/// policy and must be at least this strict; Fuigo injects its same-origin policy.
fn same_origin_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let same_origin = attempt
            .previous()
            .last()
            .is_some_and(|previous| previous.origin() == attempt.url().origin());
        if attempt.previous().len() >= 10 || !same_origin {
            attempt.stop()
        } else {
            attempt.follow()
        }
    })
}

impl std::fmt::Debug for OidcAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcAuthProvider")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

pub struct OidcAuthProviderBuilder {
    access_token: String,
    refresh_token: String,
    issuer: String,
    client_id: String,
    expires_at: Option<DateTime<Utc>>,
    user_id: Option<String>,
    principal_type: Option<String>,
    principal_id: Option<String>,
    on_refresh: Option<OnRefreshCallback>,
    http_transport: Option<HttpTransport>,
}

impl OidcAuthProviderBuilder {
    pub fn new(
        access_token: impl Into<String>,
        refresh_token: impl Into<String>,
        issuer: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Self {
        Self {
            access_token: access_token.into(),
            refresh_token: refresh_token.into(),
            issuer: issuer.into(),
            client_id: client_id.into(),
            expires_at: None,
            user_id: None,
            principal_type: None,
            principal_id: None,
            on_refresh: None,
            http_transport: None,
        }
    }

    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Owner user id parsed from the auth source, surfaced via
    /// [`AuthProvider::identity`].
    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    pub fn principal_type(mut self, pt: impl Into<String>) -> Self {
        self.principal_type = Some(pt.into());
        self
    }

    pub fn principal_id(mut self, pid: impl Into<String>) -> Self {
        self.principal_id = Some(pid.into());
        self
    }

    pub fn on_refresh(mut self, cb: OnRefreshCallback) -> Self {
        self.on_refresh = Some(cb);
        self
    }

    /// Inject the application's TLS/redirect client and initial-recipient check.
    /// The callback checks discovery and token requests; the injected client must
    /// also enforce the application's policy on any automatically followed hop.
    pub fn http_transport(
        mut self,
        client: reqwest::Client,
        check_url: impl Fn(&reqwest::Url) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        self.http_transport = Some(HttpTransport {
            client,
            check_url: Arc::new(check_url),
        });
        self
    }

    pub fn build(self) -> OidcAuthProvider {
        OidcAuthProvider {
            state: Mutex::new(TokenState {
                access_token: self.access_token,
                refresh_token: self.refresh_token,
                expires_at: self.expires_at,
            }),
            issuer: self.issuer,
            client_id: self.client_id,
            user_id: self.user_id,
            principal_type: self.principal_type,
            principal_id: self.principal_id,
            on_refresh: self.on_refresh,
            http_transport: self.http_transport,
        }
    }
}

impl AuthProvider for OidcAuthProvider {
    fn current(&self) -> AuthCredential {
        let expired = {
            let s = self.state.lock();
            s.expires_at.is_some_and(|exp| {
                Utc::now() + chrono::Duration::from_std(REFRESH_MARGIN).unwrap() >= exp
            })
        };
        if !expired {
            crate::metrics::oidc_refresh_observe(
                crate::metrics::OidcRefreshOutcome::SkippedNotExpired,
                None,
            );
        } else {
            use crate::metrics::{OidcRefreshOutcome, oidc_refresh_observe};
            let started = std::time::Instant::now();
            match self.try_refresh() {
                Ok(()) => {
                    let secs = started.elapsed().as_secs_f64();
                    oidc_refresh_observe(OidcRefreshOutcome::Ok, Some(secs));
                    tracing::info!(duration_secs = secs, outcome = "ok", "OIDC token refreshed");
                }
                Err(e) => {
                    let secs = started.elapsed().as_secs_f64();
                    oidc_refresh_observe(OidcRefreshOutcome::FailedUsedStale, Some(secs));
                    tracing::warn!(
                        error = %e,
                        duration_secs = secs,
                        outcome = "failed_used_stale",
                        "OIDC refresh failed, using stale token"
                    );
                }
            }
        }
        let s = self.state.lock();
        AuthCredential::bearer(&s.access_token)
    }

    /// Stable issuer/client/user pool key; does not call [`Self::current`].
    fn principal_key(&self) -> crate::auth::PrincipalKey {
        let mut fingerprint = format!("oidc:{}:{}", self.issuer, self.client_id);
        if let Some(uid) = self.user_id.as_deref() {
            fingerprint.push(':');
            fingerprint.push_str(uid);
        }
        crate::auth::PrincipalKey::opaque(fingerprint)
    }

    /// Surface the principal fields parsed from the auth source. `None` only
    /// when no `user_id` was supplied (nothing to attribute).
    fn identity(&self) -> Option<AuthIdentity> {
        let user_id = self.user_id.clone()?;
        Some(AuthIdentity {
            user_id,
            principal_type: self.principal_type.clone(),
            principal_id: self.principal_id.clone(),
        })
    }
}

impl OidcAuthProvider {
    fn try_refresh(&self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!(issuer = %self.issuer, "refreshing OIDC token");
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            tokio::task::block_in_place(|| handle.block_on(self.do_refresh()))
        } else {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(self.do_refresh())
        }
    }

    async fn do_refresh(&self) -> Result<(), Box<dyn std::error::Error>> {
        let refresh_token = self.state.lock().refresh_token.clone();
        let issuer = self.issuer.trim_end_matches('/');
        // A common-layer crate cannot use the codegen TLS policy crate; build
        // fallibly so a broken OS certificate store surfaces as Err, not a panic.
        #[allow(clippy::disallowed_methods)]
        // common-layer crate; the fuigo TLS policy helper is out of reach
        let client = match &self.http_transport {
            Some(transport) => transport.client.clone(),
            // CB-3: the token-endpoint check binds the FIRST hop only, so the default client must
            // not follow a redirect off that origin (a 307/308 replays the refresh-token form).
            None => reqwest::Client::builder()
                .redirect(same_origin_redirects())
                .build()?,
        };

        #[derive(serde::Deserialize)]
        struct Discovery {
            token_endpoint: String,
        }

        let discovery_url =
            reqwest::Url::parse(&format!("{issuer}/.well-known/openid-configuration"))?;
        if let Some(transport) = &self.http_transport {
            (transport.check_url)(&discovery_url)?;
        }
        // Common SDK adapter: Fuigo hub_auth injects the policy-built client and
        // check_url above; standalone SDK users retain their own transport policy.
        #[allow(clippy::disallowed_methods)]
        let disc: Discovery = client
            .get(discovery_url)
            .timeout(Duration::from_secs(10))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let mut params = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", self.client_id.as_str()),
        ];
        let pt = self.principal_type.clone();
        let pid = self.principal_id.clone();
        if let Some(ref v) = pt {
            params.push(("principal_type", v));
        }
        if let Some(ref v) = pid {
            params.push(("principal_id", v));
        }

        #[derive(serde::Deserialize)]
        struct Tokens {
            access_token: String,
            #[serde(default)]
            refresh_token: Option<String>,
            #[serde(default)]
            expires_in: Option<u64>,
        }

        let token_url = reqwest::Url::parse(&disc.token_endpoint)?;
        check_token_endpoint(&self.issuer, &token_url, cfg!(test))?;
        if let Some(transport) = &self.http_transport {
            (transport.check_url)(&token_url)?;
        }
        // Same adapter boundary: token_url is checked above before attaching the
        // refresh-token form; the injected client also enforces redirect policy.
        #[allow(clippy::disallowed_methods)]
        let tokens: Tokens = client
            .post(token_url)
            .form(&params)
            .timeout(Duration::from_secs(15))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let expires_at = tokens
            .expires_in
            .map(|s| Utc::now() + chrono::Duration::seconds(s as i64));

        if let Some(ref cb) = self.on_refresh {
            cb(&RefreshEvent {
                access_token: tokens.access_token.clone(),
                new_refresh_token: tokens.refresh_token.clone(),
                expires_at,
            });
        }

        let mut s = self.state.lock();
        s.access_token = tokens.access_token;
        if let Some(rt) = tokens.refresh_token {
            s.refresh_token = rt;
        }
        s.expires_at = expires_at;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CB-3: https on the issuer's exact origin, or nothing.
    #[test]
    fn token_endpoint_must_be_https_on_the_issuer_origin() {
        let url = |s: &str| reqwest::Url::parse(s).unwrap();
        let issuer = "https://auth.example.com/";
        for ok in [
            "https://auth.example.com/oauth2/token",
            "https://auth.example.com:443/token",
            "https://AUTH.example.com/token",
        ] {
            assert_eq!(
                check_token_endpoint(issuer, &url(ok), false),
                Ok(()),
                "{ok}"
            );
        }
        for (bad, why) in [
            ("http://auth.example.com/token", "not https"),
            ("https://evil.example/token", "issuer's origin"),
            (
                "https://auth.example.com.evil.example/token",
                "issuer's origin",
            ),
            ("https://token.example.com/token", "issuer's origin"),
            ("https://auth.example.com:8443/token", "issuer's origin"),
            ("https://user:pw@auth.example.com/token", "userinfo"),
        ] {
            let error = check_token_endpoint(issuer, &url(bad), true).unwrap_err();
            assert!(error.contains(why), "{bad}: {error}");
            assert!(
                !error.contains("example"),
                "the error must not echo the URL: {error}"
            );
        }
        // Loopback http only when the caller allows it (test builds), still same-origin.
        let local = "http://127.0.0.1:8080";
        assert!(check_token_endpoint(local, &url("http://127.0.0.1:8080/token"), true).is_ok());
        assert!(check_token_endpoint(local, &url("http://127.0.0.1:8080/token"), false).is_err());
        assert!(check_token_endpoint(local, &url("http://127.0.0.1:9090/token"), true).is_err());
        assert!(
            check_token_endpoint("http://idp.example", &url("http://idp.example/token"), true)
                .is_err()
        );
        assert!(check_token_endpoint("not a url", &url("https://a.example/token"), false).is_err());
    }

    /// P99: the one built-in split-host pair. Google's issuer is `https://accounts.google.com`
    /// and its discovery document names `https://oauth2.googleapis.com/token`.
    #[test]
    fn the_builtin_split_host_pair_is_admitted() {
        let url = |s: &str| reqwest::Url::parse(s).unwrap();
        for issuer in [
            "https://accounts.google.com",
            "https://accounts.google.com/",
            "https://ACCOUNTS.google.com:443",
        ] {
            for endpoint in [
                "https://oauth2.googleapis.com/token",
                "https://oauth2.googleapis.com:443/token",
                "https://OAUTH2.googleapis.com/token",
            ] {
                for allow_loopback_http in [false, true] {
                    assert_eq!(
                        check_token_endpoint(issuer, &url(endpoint), allow_loopback_http),
                        Ok(()),
                        "{issuer} -> {endpoint}"
                    );
                }
            }
        }
        // The issuer's own origin stays admitted next to the exception.
        assert_eq!(
            check_token_endpoint(
                "https://accounts.google.com",
                &url("https://accounts.google.com/o/oauth2/token"),
                false
            ),
            Ok(())
        );
    }

    /// P99: the exception is one exact, directed pair. Every look-alike is refused.
    #[test]
    fn look_alikes_of_the_builtin_split_host_pair_are_refused() {
        let url = |s: &str| reqwest::Url::parse(s).unwrap();
        let google_issuer = "https://accounts.google.com";
        let google_token = "https://oauth2.googleapis.com/token";
        for (issuer, endpoint, why) in [
            // Another issuer naming the Google token host.
            ("https://auth.example.com", google_token, "issuer's origin"),
            (
                "https://oauth2.googleapis.com.evil.example",
                google_token,
                "issuer's origin",
            ),
            // The pair reversed.
            (
                "https://oauth2.googleapis.com",
                "https://accounts.google.com/token",
                "issuer's origin",
            ),
            // The Google issuer naming another host.
            (
                google_issuer,
                "https://evil.example/token",
                "issuer's origin",
            ),
            (
                google_issuer,
                "https://www.googleapis.com/oauth2/v4/token",
                "issuer's origin",
            ),
            (
                google_issuer,
                "https://googleapis.com/token",
                "issuer's origin",
            ),
            // Subdomain and suffix tricks, on either side.
            (
                google_issuer,
                "https://evil.oauth2.googleapis.com/token",
                "issuer's origin",
            ),
            (
                google_issuer,
                "https://oauth2.googleapis.com.evil.example/token",
                "issuer's origin",
            ),
            (
                google_issuer,
                "https://oauth2.googleapis.com./token",
                "issuer's origin",
            ),
            (
                google_issuer,
                "https://xoauth2.googleapis.com/token",
                "issuer's origin",
            ),
            (
                "https://evil.accounts.google.com",
                google_token,
                "issuer's origin",
            ),
            (
                "https://accounts.google.com.evil.example",
                google_token,
                "issuer's origin",
            ),
            (
                "https://accounts.google.com.",
                google_token,
                "issuer's origin",
            ),
            (
                "https://xaccounts.google.com",
                google_token,
                "issuer's origin",
            ),
            // Plain http, on either side, including http on the https port.
            (
                google_issuer,
                "http://oauth2.googleapis.com/token",
                "not https",
            ),
            (
                google_issuer,
                "http://oauth2.googleapis.com:443/token",
                "not https",
            ),
            (
                "http://accounts.google.com",
                google_token,
                "issuer's origin",
            ),
            (
                "http://accounts.google.com:443",
                google_token,
                "issuer's origin",
            ),
            // Another port, on either side.
            (
                google_issuer,
                "https://oauth2.googleapis.com:8443/token",
                "issuer's origin",
            ),
            (
                "https://accounts.google.com:8443",
                google_token,
                "issuer's origin",
            ),
            // Userinfo, on either side.
            (
                google_issuer,
                "https://user:pw@oauth2.googleapis.com/token",
                "userinfo",
            ),
            (
                google_issuer,
                "https://accounts.google.com@oauth2.googleapis.com/token",
                "userinfo",
            ),
            (
                "https://user@accounts.google.com",
                google_token,
                "issuer's origin",
            ),
            (
                "https://oauth2.googleapis.com@accounts.google.com",
                google_token,
                "issuer's origin",
            ),
        ] {
            for allow_loopback_http in [false, true] {
                let error = check_token_endpoint(issuer, &url(endpoint), allow_loopback_http)
                    .expect_err(&format!("{issuer} -> {endpoint} must be refused"));
                assert!(error.contains(why), "{issuer} -> {endpoint}: {error}");
                assert!(
                    !error.contains("google"),
                    "the error must not echo the URL: {error}"
                );
            }
        }
    }

    /// CB-3, behavioural: a discovery document naming a token endpoint on another
    /// origin gets no refresh token. The other origin is never contacted, no callback
    /// fires and the stored tokens are untouched.
    #[allow(clippy::disallowed_methods)] // injected client only targets local test observers
    #[tokio::test]
    async fn discovered_token_endpoint_on_another_origin_never_receives_the_refresh_token() {
        use axum::{Router, routing::get};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let collector = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        collector.set_nonblocking(true).unwrap();
        let foreign = format!("http://{}/token", collector.local_addr().unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().route(
            "/.well-known/openid-configuration",
            get(move || {
                let foreign = foreign.clone();
                async move { axum::Json(serde_json::json!({"token_endpoint": foreign})) }
            }),
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let callbacks = Arc::new(AtomicUsize::new(0));
        let seen = callbacks.clone();
        for injected in [false, true] {
            let mut builder =
                OidcAuthProviderBuilder::new("old-access", "old-refresh", base.clone(), "client")
                    .on_refresh(Arc::new({
                        let seen = seen.clone();
                        move |_| {
                            seen.fetch_add(1, Ordering::SeqCst);
                        }
                    }));
            if injected {
                let client = reqwest::Client::builder().no_proxy().build().unwrap();
                builder = builder.http_transport(client, |_| Ok(()));
            }
            let provider = builder.build();
            let error = provider.do_refresh().await.unwrap_err().to_string();
            assert!(error.contains("issuer's origin"), "{error}");
            assert_eq!(provider.state.lock().access_token, "old-access");
            assert_eq!(provider.state.lock().refresh_token, "old-refresh");
        }
        task.abort();
        assert_eq!(callbacks.load(Ordering::SeqCst), 0);
        assert_eq!(
            collector.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "the foreign token endpoint was contacted"
        );
    }

    /// CB-3 (Astra r1): an allowed token endpoint that answers 307/308 to another origin
    /// must not get the refresh-token form replayed there by the SDK's default client.
    #[tokio::test]
    async fn default_client_never_follows_the_token_endpoint_off_its_origin() {
        use axum::{
            Router,
            routing::{get, post},
        };
        for status in [
            axum::http::StatusCode::TEMPORARY_REDIRECT,
            axum::http::StatusCode::PERMANENT_REDIRECT,
        ] {
            let collector = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            collector.set_nonblocking(true).unwrap();
            let foreign = format!("http://{}/collect", collector.local_addr().unwrap());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let token_url = format!("{base}/token");
            // Proves the token endpoint WAS reached with the token, so a refresh that failed
            // earlier (discovery, an environment proxy) cannot pass for a refused redirect.
            let posted = Arc::new(Mutex::new(Vec::<String>::new()));
            let app = Router::new()
                .route(
                    "/.well-known/openid-configuration",
                    get(move || {
                        let token_url = token_url.clone();
                        async move { axum::Json(serde_json::json!({"token_endpoint": token_url})) }
                    }),
                )
                .route(
                    "/token",
                    post({
                        let posted = posted.clone();
                        move |body: String| {
                            let foreign = foreign.clone();
                            posted.lock().push(body);
                            async move { (status, [(axum::http::header::LOCATION, foreign)]) }
                        }
                    }),
                );
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let provider =
                OidcAuthProviderBuilder::new("old-access", "old-refresh", base, "client").build();
            let result = provider.do_refresh().await;
            task.abort();
            assert!(
                result.is_err(),
                "{status}: a redirect is not a token response"
            );
            let posted = posted.lock().clone();
            assert_eq!(posted.len(), 1, "{status}: {posted:?}");
            assert!(
                posted[0].contains("refresh_token=old-refresh"),
                "{status}: {posted:?}"
            );
            assert_eq!(
                collector.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "{status}: the refresh token was replayed to another origin"
            );
            assert_eq!(provider.state.lock().refresh_token, "old-refresh");
        }
    }

    #[allow(clippy::disallowed_methods)] // injected client only targets local test observers
    #[tokio::test]
    async fn injected_transport_denies_discovery_before_contact() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let provider = OidcAuthProviderBuilder::new("old-access", "old-refresh", base, "client")
            .http_transport(client, |_| Err("policy denied".to_string()))
            .build();
        assert!(
            provider
                .do_refresh()
                .await
                .unwrap_err()
                .to_string()
                .contains("policy denied")
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(provider.state.lock().access_token, "old-access");
    }

    #[allow(clippy::disallowed_methods)] // injected client only targets local test observers
    #[tokio::test]
    async fn injected_transport_checks_discovered_recipient_before_refresh_or_callback() {
        use axum::{
            Router,
            routing::{get, post},
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        for deny_token in [true, false] {
            let token_calls = Arc::new(AtomicUsize::new(0));
            let callbacks = Arc::new(AtomicUsize::new(0));
            let sink = token_calls.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let token_url = format!("{base}/token");
            let app = Router::new()
                .route("/.well-known/openid-configuration", get(move || {
                    let token_url = token_url.clone();
                    async move { axum::Json(serde_json::json!({"token_endpoint": token_url})) }
                }))
                .route("/token", post(move || {
                    let sink = sink.clone();
                    async move {
                        sink.fetch_add(1, Ordering::SeqCst);
                        axum::Json(serde_json::json!({"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600}))
                    }
                }));
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let seen = callbacks.clone();
            let provider =
                OidcAuthProviderBuilder::new("old-access", "old-refresh", base, "client")
                    .on_refresh(Arc::new(move |_| {
                        seen.fetch_add(1, Ordering::SeqCst);
                    }))
                    .http_transport(client, move |url| {
                        if deny_token && url.path() == "/token" {
                            Err("token recipient denied".to_string())
                        } else {
                            Ok(())
                        }
                    })
                    .build();
            let result = provider.do_refresh().await;
            task.abort();
            if deny_token {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("token recipient denied")
                );
                assert_eq!(token_calls.load(Ordering::SeqCst), 0);
                assert_eq!(callbacks.load(Ordering::SeqCst), 0);
                assert_eq!(provider.state.lock().access_token, "old-access");
                assert_eq!(provider.state.lock().refresh_token, "old-refresh");
            } else {
                result.unwrap();
                assert_eq!(token_calls.load(Ordering::SeqCst), 1);
                assert_eq!(callbacks.load(Ordering::SeqCst), 1);
                assert_eq!(provider.state.lock().access_token, "new-access");
                assert_eq!(provider.state.lock().refresh_token, "new-refresh");
            }
        }
    }

    #[test]
    fn current_returns_token_when_not_expired() {
        #[cfg(feature = "metrics")]
        let _guard = crate::metrics::lock_oidc_metrics_test();
        let provider = OidcAuthProviderBuilder::new(
            "access-tok",
            "refresh-tok",
            "https://auth.example.com",
            "client1",
        )
        .expires_at(Utc::now() + chrono::Duration::hours(1))
        .build();

        let cred = provider.current();
        match cred {
            AuthCredential::Bearer { token } => {
                assert_eq!(token, "access-tok");
            }
            _ => panic!("expected Bearer"),
        }
    }

    #[test]
    fn current_returns_token_when_no_expiry() {
        #[cfg(feature = "metrics")]
        let _guard = crate::metrics::lock_oidc_metrics_test();
        let provider = OidcAuthProviderBuilder::new(
            "no-expiry-tok",
            "refresh-tok",
            "https://auth.example.com",
            "client1",
        )
        .build();

        let cred = provider.current();
        match cred {
            AuthCredential::Bearer { token } => assert_eq!(token, "no-expiry-tok"),
            _ => panic!("expected Bearer"),
        }
    }

    #[test]
    fn current_returns_stale_token_when_refresh_fails() {
        #[cfg(feature = "metrics")]
        let _guard = crate::metrics::lock_oidc_metrics_test();
        // Expired token, but issuer is unreachable — should return stale
        let provider = OidcAuthProviderBuilder::new(
            "stale-tok",
            "refresh-tok",
            "https://localhost:1", // unreachable
            "client1",
        )
        .expires_at(Utc::now() - chrono::Duration::hours(1))
        .build();

        let cred = provider.current();
        match cred {
            AuthCredential::Bearer { token } => assert_eq!(token, "stale-tok"),
            _ => panic!("expected Bearer"),
        }
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn current_records_skipped_and_failed_refresh_outcomes() {
        let _guard = crate::metrics::lock_oidc_metrics_test();
        use crate::metrics::OidcRefreshOutcome;
        let skipped_before =
            crate::metrics::oidc_refresh_count(OidcRefreshOutcome::SkippedNotExpired);
        let failed_before = crate::metrics::oidc_refresh_count(OidcRefreshOutcome::FailedUsedStale);
        let duration_before = crate::metrics::oidc_refresh_duration_sample_count();

        let fresh = OidcAuthProviderBuilder::new(
            "access-tok",
            "refresh-tok",
            "https://auth.example.com",
            "client1",
        )
        .expires_at(Utc::now() + chrono::Duration::hours(1))
        .build();
        let _ = fresh.current();
        assert_eq!(
            crate::metrics::oidc_refresh_count(OidcRefreshOutcome::SkippedNotExpired),
            skipped_before + 1
        );
        assert_eq!(
            crate::metrics::oidc_refresh_duration_sample_count(),
            duration_before,
            "skipped path must not observe refresh duration"
        );

        let stale = OidcAuthProviderBuilder::new(
            "stale-tok",
            "refresh-tok",
            "https://localhost:1",
            "client1",
        )
        .expires_at(Utc::now() - chrono::Duration::hours(1))
        .build();
        let _ = stale.current();
        assert_eq!(
            crate::metrics::oidc_refresh_count(OidcRefreshOutcome::FailedUsedStale),
            failed_before + 1
        );
        assert_eq!(
            crate::metrics::oidc_refresh_duration_sample_count(),
            duration_before + 1,
            "failed refresh must observe exactly one duration sample"
        );
        assert_eq!(
            crate::metrics::oidc_refresh_count(OidcRefreshOutcome::SkippedNotExpired),
            skipped_before + 1,
            "failed refresh must not also count as skipped"
        );
    }

    #[test]
    fn principal_key_is_stable_and_does_not_call_current() {
        #[cfg(feature = "metrics")]
        let _guard = crate::metrics::lock_oidc_metrics_test();
        #[cfg(feature = "metrics")]
        let skipped_before = crate::metrics::oidc_refresh_count(
            crate::metrics::OidcRefreshOutcome::SkippedNotExpired,
        );

        let provider = OidcAuthProviderBuilder::new(
            "access-tok",
            "refresh-tok",
            "https://auth.example.com",
            "client1",
        )
        .user_id("user-9")
        .expires_at(Utc::now() + chrono::Duration::hours(1))
        .build();

        let k1 = provider.principal_key();
        let k2 = provider.principal_key();
        assert_eq!(k1, k2);

        #[cfg(feature = "metrics")]
        assert_eq!(
            crate::metrics::oidc_refresh_count(
                crate::metrics::OidcRefreshOutcome::SkippedNotExpired
            ),
            skipped_before,
            "principal_key must not call current()"
        );

        let token_key = AuthCredential::bearer("access-tok").principal_key();
        assert_ne!(k1, token_key);
    }

    #[cfg(feature = "metrics")]
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn current_records_ok_refresh_outcome_against_mock_idp() {
        use crate::metrics::OidcRefreshOutcome;
        use axum::Router;
        use axum::routing::{get, post};

        let _guard = crate::metrics::lock_oidc_metrics_test();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let token_endpoint = format!("{base}/token");
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let token_endpoint = token_endpoint.clone();
                    async move {
                        axum::Json(serde_json::json!({
                            "token_endpoint": token_endpoint
                        }))
                    }
                }),
            )
            .route(
                "/token",
                post(|| async {
                    axum::Json(serde_json::json!({
                        "access_token": "fresh-access",
                        "refresh_token": "fresh-refresh",
                        "expires_in": 3600
                    }))
                }),
            );
        let _server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        tokio::task::yield_now().await;

        let ok_before = crate::metrics::oidc_refresh_count(OidcRefreshOutcome::Ok);
        let duration_before = crate::metrics::oidc_refresh_duration_sample_count();

        let provider = OidcAuthProviderBuilder::new("stale-access", "refresh-tok", base, "client1")
            .expires_at(Utc::now() - chrono::Duration::hours(1))
            .build();

        // try_refresh uses block_in_place; needs multi-thread runtime.
        let cred = tokio::task::spawn_blocking(move || provider.current())
            .await
            .expect("join");
        match cred {
            AuthCredential::Bearer { token } => assert_eq!(token, "fresh-access"),
            _ => panic!("expected Bearer"),
        }
        assert_eq!(
            crate::metrics::oidc_refresh_count(OidcRefreshOutcome::Ok),
            ok_before + 1
        );
        assert_eq!(
            crate::metrics::oidc_refresh_duration_sample_count(),
            duration_before + 1
        );
    }

    #[test]
    fn identity_surfaces_principal_fields() {
        let provider = OidcAuthProviderBuilder::new("tok", "rt", "https://auth.example.com", "c1")
            .user_id("user-1")
            .principal_type("Team")
            .principal_id("team-9")
            .build();
        let id = provider.identity().expect("identity present");
        assert_eq!(id.user_id, "user-1");
        assert_eq!(id.principal_type.as_deref(), Some("Team"));
        assert_eq!(id.principal_id.as_deref(), Some("team-9"));
    }

    #[test]
    fn identity_none_without_user_id() {
        let provider =
            OidcAuthProviderBuilder::new("tok", "rt", "https://auth.example.com", "c1").build();
        assert!(provider.identity().is_none());
    }

    #[test]
    fn debug_does_not_leak_tokens() {
        let provider = OidcAuthProviderBuilder::new(
            "secret-access-token",
            "secret-refresh-token",
            "https://auth.example.com",
            "client1",
        )
        .build();

        let debug = format!("{provider:?}");
        assert!(!debug.contains("secret-access-token"));
        assert!(!debug.contains("secret-refresh-token"));
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
    fn refresh_event_debug_redacts_tokens() {
        let event = RefreshEvent {
            access_token: "p70ac-FAKE-0d1e2f3a".into(),
            new_refresh_token: Some("p70nr-FAKE-4b5c6d7e".into()),
            expires_at: None,
        };
        assert_redacted(&event, &["p70ac-FAKE-0d1e2f3a", "p70nr-FAKE-4b5c6d7e"]);
    }
}
