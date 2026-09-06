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

#[derive(Debug, Clone)]
pub struct RefreshEvent {
    pub access_token: String,
    pub new_refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
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
            None => reqwest::Client::builder().build()?,
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
