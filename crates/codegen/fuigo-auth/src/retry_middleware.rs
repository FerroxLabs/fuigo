//! `reqwest-middleware` layer: stamps auth headers and retries on 401.
//! Gated behind the `middleware` cargo feature.

use std::sync::Arc;

use reqwest::{Request, Response, StatusCode, header::HeaderValue};
use reqwest_middleware::{Error, Middleware, Next};

use crate::AuthCredentialProvider;
use crate::bearer_fragment::BearerFingerprint;

/// Fingerprint of the bearer this middleware stamped, recorded into the request's `http::Extensions` at stamp time.
/// 401-attribution sites read it back via [`execute_with_stamp`]; re-resolving at record time races with the refresh the 401 itself triggers.
/// Absent means nothing was stamped; a retry overwrites it, so it always describes the attempt whose response the caller holds.
/// Only the [`BearerFingerprint`] is stored, never the bearer or any fragment of it, so sinks may log it.
#[derive(Clone, Debug)]
pub struct StampedBearerFingerprint(pub BearerFingerprint);

/// Initial-request policy for middleware clients, including unauthenticated
/// clients. Redirect hops are additionally checked by the shared TLS builder.
pub struct EgressMiddleware;

#[async_trait::async_trait]
impl Middleware for EgressMiddleware {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> Result<Response, Error> {
        fuigo_extra_ca::dispatch::check_url(req.url())
            .map_err(|error| Error::Middleware(error.into()))?;
        next.run(req, extensions).await
    }
}

/// Execute `req` on a middleware-wrapped client and return the response plus the [`StampedBearerFingerprint`] the auth middleware recorded, if any.
/// This is how 401-attribution call sites learn what was actually sent on the wire.
pub async fn execute_with_stamp(
    client: &reqwest_middleware::ClientWithMiddleware,
    req: Request,
) -> reqwest_middleware::Result<(Response, Option<StampedBearerFingerprint>)> {
    let mut ext = http::Extensions::new();
    let resp = client.execute_with_extensions(req, &mut ext).await?;
    Ok((resp, ext.get::<StampedBearerFingerprint>().cloned()))
}

pub struct AuthRetryMiddleware {
    credentials: Arc<dyn AuthCredentialProvider>,
    max_retries: u32,
}

impl AuthRetryMiddleware {
    pub fn new(credentials: Arc<dyn AuthCredentialProvider>, max_retries: u32) -> Self {
        Self {
            credentials,
            max_retries,
        }
    }
}

fn apply_auth_header(req: &mut Request, token: &str, extensions: &mut http::Extensions) {
    match HeaderValue::from_str(&format!("Bearer {token}")) {
        Ok(val) => {
            req.headers_mut()
                .insert(reqwest::header::AUTHORIZATION, val);
            extensions.insert(StampedBearerFingerprint(BearerFingerprint::of(token)));
        }
        Err(e) => {
            tracing::warn!(error = %e, "auth retry: failed to build Authorization header");
        }
    }
}

/// P47: the [`crate::BearerDestinationRefused`] somewhere in `error`'s chain, looking through
/// `reqwest_middleware::Error::Middleware` (whose `#[error(transparent)]` hides the inner error from `source()`).
pub fn find_bearer_refusal<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a crate::BearerDestinationRefused> {
    let mut next = Some(error);
    while let Some(e) = next {
        if let Some(refused) = e.downcast_ref::<crate::BearerDestinationRefused>() {
            return Some(refused);
        }
        if let Some(Error::Middleware(inner)) = e.downcast_ref::<Error>() {
            let inner: &(dyn std::error::Error + 'static) = inner.as_ref();
            if let Some(refused) = find_bearer_refusal(inner) {
                return Some(refused);
            }
        }
        next = e.source();
    }
    None
}

/// The destination as the caller wrote it. reqwest strips URL userinfo when it builds the request and turns it
/// into a `Basic` `Authorization` header, so `req.url()` alone can no longer show it. A request that carries
/// `Basic` credentials is reported to the rule with a userinfo marker, so the rule's userinfo refusal (P47) still
/// applies.
fn destination_as_written(req: &Request) -> reqwest::Url {
    let mut url = req.url().clone();
    let basic = req
        .headers()
        .get(reqwest::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.len() >= 6 && v[..6].eq_ignore_ascii_case("basic "));
    if basic {
        let _ = url.set_username("userinfo");
    }
    url
}

/// P47: a refused destination is an error and the request is NOT sent (neither with the bearer nor
/// without it). The error is the provider's [`crate::BearerDestinationRefused`], so callers can surface
/// its text, which names the refused origin and the remedy.
fn refuse_unless_bearer_may_reach(
    credentials: &dyn AuthCredentialProvider,
    destination: &reqwest::Url,
    bearer: &str,
) -> Result<(), Error> {
    credentials.bearer_may_reach(destination, bearer).map_err(|refused| {
        tracing::warn!(reason = %refused, "auth: request not sent, the bearer may not go to this destination");
        Error::Middleware(refused.into())
    })
}

#[async_trait::async_trait]
impl Middleware for AuthRetryMiddleware {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> Result<Response, Error> {
        fuigo_extra_ca::dispatch::check_url(req.url())
            .map_err(|error| Error::Middleware(error.into()))?;
        // The destination as written, captured BEFORE the first stamp replaces a userinfo `Basic` header: every
        // stamp (the first and each post-refresh retry) is checked against it.
        let destination = destination_as_written(&req);
        if let Some(ref token) = self.credentials.snapshot().token {
            refuse_unless_bearer_may_reach(self.credentials.as_ref(), &destination, token)?;
            apply_auth_header(&mut req, token, extensions);
        }

        let backup = req.try_clone();
        let resp = next.clone().run(req, extensions).await?;

        if resp.status() != StatusCode::UNAUTHORIZED || self.max_retries == 0 {
            return Ok(resp);
        }
        let Some(backup) = backup else {
            return Ok(resp);
        };

        let mut last_resp = resp;
        for _ in 0..self.max_retries {
            if !self.credentials.refresh_after_unauthorized().await {
                break;
            }
            let Some(ref token) = self.credentials.snapshot().token else {
                break;
            };
            let Some(mut retry) = backup.try_clone() else {
                break;
            };
            refuse_unless_bearer_may_reach(self.credentials.as_ref(), &destination, token)?;
            apply_auth_header(&mut retry, token, extensions);
            last_resp = next.clone().run(retry, extensions).await?;
            if last_resp.status() != StatusCode::UNAUTHORIZED {
                return Ok(last_resp);
            }
        }

        Ok(last_resp)
    }
}

#[allow(clippy::disallowed_methods)] // test clients hit localhost mocks
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CredentialSnapshot, HttpAuth};
    use reqwest_middleware::ClientBuilder;
    use std::sync::Mutex;

    struct MockProvider {
        token: Mutex<Option<String>>,
        refresh_result: bool,
        refresh_count: Mutex<u32>,
        /// P47: a host whose requests the provider's destination rule refuses.
        refuse_host: Option<String>,
    }

    impl MockProvider {
        fn new(token: Option<&str>, refresh_result: bool) -> Self {
            Self {
                token: Mutex::new(token.map(|s| s.to_owned())),
                refresh_result,
                refresh_count: Mutex::new(0),
                refuse_host: None,
            }
        }

        fn refusing(token: Option<&str>, host: &str) -> Self {
            Self {
                refuse_host: Some(host.to_owned()),
                ..Self::new(token, true)
            }
        }

        fn refresh_count(&self) -> u32 {
            *self.refresh_count.lock().unwrap()
        }
    }

    impl HttpAuth for MockProvider {
        fn apply(&self, b: reqwest::RequestBuilder, _: &str) -> reqwest::RequestBuilder {
            b
        }
    }

    #[async_trait::async_trait]
    impl AuthCredentialProvider for MockProvider {
        fn snapshot(&self) -> CredentialSnapshot {
            CredentialSnapshot {
                token: self.token.lock().unwrap().clone(),
                ..Default::default()
            }
        }

        async fn refresh_after_unauthorized(&self) -> bool {
            *self.refresh_count.lock().unwrap() += 1;
            self.refresh_result
        }

        fn bearer_may_reach(
            &self,
            url: &reqwest::Url,
            _bearer: &str,
        ) -> Result<(), crate::BearerDestinationRefused> {
            match &self.refuse_host {
                Some(host) if url.host_str() == Some(host.as_str()) => {
                    Err(crate::BearerDestinationRefused(format!("refused {host}")))
                }
                _ => Ok(()),
            }
        }
    }

    async fn build_client(
        provider: Arc<dyn AuthCredentialProvider>,
        max_retries: u32,
    ) -> reqwest_middleware::ClientWithMiddleware {
        ClientBuilder::new(reqwest::Client::new())
            .with(AuthRetryMiddleware::new(provider, max_retries))
            .build()
    }

    #[tokio::test]
    async fn test_401_no_refresh_returns_401() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", "/")
            .with_status(401)
            .expect(1)
            .create_async()
            .await;

        let p = Arc::new(MockProvider::new(Some("tok"), false));
        let client = build_client(p.clone(), 1).await;

        let resp = client.get(server.url()).send().await.unwrap();
        assert_eq!(resp.status(), 401);
        assert_eq!(p.refresh_count(), 1);
        m.assert_async().await;
    }

    #[tokio::test]
    async fn middleware_paths_reject_before_proxy_connection_or_auth_refresh() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        for with_auth in [false, true] {
            let raw = fuigo_extra_ca::build_reqwest_client(|builder| {
                builder
                    .no_proxy()
                    .proxy(reqwest::Proxy::all(&proxy).unwrap())
                    .timeout(std::time::Duration::from_millis(500))
            })
            .unwrap();
            let provider = Arc::new(MockProvider::new(Some("fake-key"), true));
            let builder = ClientBuilder::new(raw);
            let client = if with_auth {
                // AuthRetryMiddleware also enforces policy when used on its own.
                builder
                    .with(AuthRetryMiddleware::new(provider.clone(), 1))
                    .build()
            } else {
                builder.with(EgressMiddleware).build()
            };
            for url in ["http://api.x.ai/v1", "https://api.x.ai/v1"] {
                let error = client.get(url).send().await.unwrap_err();
                assert!(matches!(error, Error::Middleware(_)));
                assert!(
                    error
                        .to_string()
                        .contains("refuses to contact upstream vendor host")
                );
            }
            assert_eq!(provider.refresh_count(), 0);
        }
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    /// Simulates a real auth manager: starts with a stale token, and a refresh swaps in the fresh one.
    struct SimulatedAuthManager {
        token: Mutex<Option<String>>,
        fresh_token: String,
        refresh_count: Mutex<u32>,
    }

    impl SimulatedAuthManager {
        fn simulated(stale: &str, fresh: &str) -> Self {
            Self {
                token: Mutex::new(Some(stale.to_owned())),
                fresh_token: fresh.to_owned(),
                refresh_count: Mutex::new(0),
            }
        }
    }

    impl HttpAuth for SimulatedAuthManager {
        fn apply(&self, b: reqwest::RequestBuilder, _: &str) -> reqwest::RequestBuilder {
            b
        }
    }

    #[async_trait::async_trait]
    impl AuthCredentialProvider for SimulatedAuthManager {
        fn snapshot(&self) -> CredentialSnapshot {
            CredentialSnapshot {
                token: self.token.lock().unwrap().clone(),
                ..Default::default()
            }
        }

        async fn refresh_after_unauthorized(&self) -> bool {
            *self.refresh_count.lock().unwrap() += 1;
            *self.token.lock().unwrap() = Some(self.fresh_token.clone());
            true
        }

        fn bearer_may_reach(&self, _: &reqwest::Url, _: &str) -> Result<(), crate::BearerDestinationRefused> {
            Ok(())
        }
    }

    /// P47: a destination the provider's rule refuses gets NO request at all (the bearer is not stamped and the
    /// request is not sent unauthenticated either), the error carries the refusal text, and no refresh runs.
    /// Positive control: the same provider and client stamp the bearer for an admitted host.
    #[tokio::test]
    async fn p47_a_refused_destination_is_never_contacted() {
        let mut server = mockito::Server::new_async().await;
        let admitted = server
            .mock("GET", "/ok")
            .match_header("authorization", "Bearer p47-session")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;
        let refused = server.mock("GET", "/no").expect(0).create_async().await;
        // mockito listens on 127.0.0.1; `localhost` reaches the same server under another host name.
        let p = Arc::new(MockProvider::refusing(Some("p47-session"), "localhost"));
        let client = build_client(p.clone(), 1).await;
        let port = server.socket_address().port();

        let error = client
            .get(format!("http://localhost:{port}/no"))
            .send()
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Middleware(_)), "{error}");
        assert!(error.to_string().contains("refused localhost"), "{error}");
        let resp = client
            .get(format!("http://127.0.0.1:{port}/ok"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(p.refresh_count(), 0);
        refused.assert_async().await;
        admitted.assert_async().await;
    }

    /// P47 (audit R2): reqwest strips URL userinfo into a `Basic` header before the middleware runs; the rule must
    /// still see it. A rule that refuses userinfo blocks `http://u:p@host/` and admits the same host without it.
    #[tokio::test]
    async fn p47_url_userinfo_reaches_the_rule() {
        let mut server = mockito::Server::new_async().await;
        let admitted = server.mock("GET", "/x").expect(1).create_async().await;
        let provider = Arc::new(crate::StaticAuthCredentialProvider::new(
            Box::new(MockProvider::new(None, false)),
            Some("p47-session".into()),
            crate::BearerDestination::Checked(Arc::new(|url: &reqwest::Url| {
                if url.username().is_empty() {
                    Ok(())
                } else {
                    Err(crate::BearerDestinationRefused("userinfo refused".into()))
                }
            })),
        ));
        let client = build_client(provider, 1).await;
        let port = server.socket_address().port();
        let error = client
            .get(format!("http://u:p@127.0.0.1:{port}/x"))
            .send()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("userinfo refused"), "{error}");
        client
            .get(format!("http://127.0.0.1:{port}/x"))
            .send()
            .await
            .unwrap();
        admitted.assert_async().await;
    }

    /// P47 (audit R3): the userinfo marker survives into the retry check. An exempt key goes to `http://u:p@host/`,
    /// is answered 401, recovery yields a session bearer, and the retry is refused: one request, none carrying the
    /// session bearer.
    #[tokio::test]
    async fn p47_userinfo_marker_survives_into_the_retry_check() {
        struct KeyThenSession {
            token: Mutex<String>,
        }
        impl HttpAuth for KeyThenSession {
            fn apply(&self, b: reqwest::RequestBuilder, _: &str) -> reqwest::RequestBuilder {
                b
            }
        }
        #[async_trait::async_trait]
        impl AuthCredentialProvider for KeyThenSession {
            fn snapshot(&self) -> CredentialSnapshot {
                CredentialSnapshot {
                    token: Some(self.token.lock().unwrap().clone()),
                    ..Default::default()
                }
            }
            async fn refresh_after_unauthorized(&self) -> bool {
                *self.token.lock().unwrap() = "p47-session".into();
                true
            }
            fn bearer_may_reach(
                &self,
                url: &reqwest::Url,
                bearer: &str,
            ) -> Result<(), crate::BearerDestinationRefused> {
                if bearer == "p47-api-key" || url.username().is_empty() {
                    Ok(())
                } else {
                    Err(crate::BearerDestinationRefused("userinfo refused for the session".into()))
                }
            }
        }
        let mut server = mockito::Server::new_async().await;
        let first = server
            .mock("GET", "/x")
            .match_header("authorization", "Bearer p47-api-key")
            .with_status(401)
            .expect(1)
            .create_async()
            .await;
        let session = server
            .mock("GET", "/x")
            .match_header("authorization", "Bearer p47-session")
            .expect(0)
            .create_async()
            .await;
        let provider = Arc::new(KeyThenSession {
            token: Mutex::new("p47-api-key".into()),
        });
        let client = build_client(provider, 1).await;
        let port = server.socket_address().port();
        let error = client
            .get(format!("http://u:p@127.0.0.1:{port}/x"))
            .send()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("userinfo refused"), "{error}");
        first.assert_async().await;
        session.assert_async().await;
    }

    /// P47: the rule is re-applied before a post-refresh retry stamps the new bearer.
    #[tokio::test]
    async fn p47_the_retry_stamp_is_checked_too() {
        struct FlipAfterRefresh {
            inner: SimulatedAuthManager,
            refreshed: std::sync::atomic::AtomicBool,
        }
        impl HttpAuth for FlipAfterRefresh {
            fn apply(&self, b: reqwest::RequestBuilder, _: &str) -> reqwest::RequestBuilder {
                b
            }
        }
        #[async_trait::async_trait]
        impl AuthCredentialProvider for FlipAfterRefresh {
            fn snapshot(&self) -> CredentialSnapshot {
                self.inner.snapshot()
            }
            async fn refresh_after_unauthorized(&self) -> bool {
                self.refreshed.store(true, std::sync::atomic::Ordering::SeqCst);
                self.inner.refresh_after_unauthorized().await
            }
            fn bearer_may_reach(&self, _: &reqwest::Url, _: &str) -> Result<(), crate::BearerDestinationRefused> {
                if self.refreshed.load(std::sync::atomic::Ordering::SeqCst) {
                    Err(crate::BearerDestinationRefused("refused after refresh".into()))
                } else {
                    Ok(())
                }
            }
        }
        let mut server = mockito::Server::new_async().await;
        let first = server
            .mock("GET", "/api")
            .match_header("authorization", "Bearer stale")
            .with_status(401)
            .expect(1)
            .create_async()
            .await;
        let retried = server
            .mock("GET", "/api")
            .match_header("authorization", "Bearer fresh")
            .expect(0)
            .create_async()
            .await;
        let p = Arc::new(FlipAfterRefresh {
            inner: SimulatedAuthManager::simulated("stale", "fresh"),
            refreshed: std::sync::atomic::AtomicBool::new(false),
        });
        let client = build_client(p, 1).await;
        let error = client
            .get(format!("{}/api", server.url()))
            .send()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("refused after refresh"), "{error}");
        first.assert_async().await;
        retried.assert_async().await;
    }

    #[tokio::test]
    async fn test_e2e_stale_token_refreshed_and_retried() {
        let mut server = mockito::Server::new_async().await;

        let m401 = server
            .mock("GET", "/api")
            .match_header("authorization", "Bearer stale-token")
            .with_status(401)
            .create_async()
            .await;
        let m200 = server
            .mock("GET", "/api")
            .match_header("authorization", "Bearer fresh-token")
            .with_status(200)
            .with_body(r#"{"ok":true}"#)
            .create_async()
            .await;

        let p = Arc::new(SimulatedAuthManager::simulated(
            "stale-token",
            "fresh-token",
        ));
        let client = build_client(p.clone(), 1).await;

        let resp = client
            .get(format!("{}/api", server.url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(*p.refresh_count.lock().unwrap(), 1);
        m401.assert_async().await;
        m200.assert_async().await;
    }

    #[tokio::test]
    async fn test_e2e_auth_header_stamped_automatically() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/api")
            .match_header("authorization", "Bearer my-token")
            .with_status(200)
            .create_async()
            .await;

        let p = Arc::new(MockProvider::new(Some("my-token"), false));
        let client = build_client(p.clone(), 1).await;

        let resp = client
            .get(format!("{}/api", server.url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(p.refresh_count(), 0);
        mock.assert_async().await;
    }

    /// The stamp must describe the bearer of the attempt whose response the caller holds.
    /// After a 401, a refresh, and a retry, that is the fresh token, not the stale one stamped on the first attempt.
    #[tokio::test]
    async fn execute_with_stamp_reports_last_stamped_bearer() {
        let mut server = mockito::Server::new_async().await;
        let m401 = server
            .mock("GET", "/api")
            .match_header("authorization", "Bearer stale-token")
            .with_status(401)
            .create_async()
            .await;
        let m200 = server
            .mock("GET", "/api")
            .match_header("authorization", "Bearer fresh-token")
            .with_status(200)
            .create_async()
            .await;

        let p = Arc::new(SimulatedAuthManager::simulated(
            "stale-token",
            "fresh-token",
        ));
        let client = build_client(p, 1).await;

        let req = client.get(format!("{}/api", server.url())).build().unwrap();
        let (resp, stamp) = execute_with_stamp(&client, req).await.unwrap();
        assert_eq!(resp.status(), 200);
        // A token of 12 chars or fewer is its own suffix
        assert_eq!(stamp.expect("bearer was stamped").0, crate::BearerFingerprint::of("fresh-token"));
        m401.assert_async().await;
        m200.assert_async().await;
    }

    /// No credential means no stamp: attribution must see "nothing was sent", not an empty string or a stale record.
    #[tokio::test]
    async fn execute_with_stamp_is_none_when_nothing_stamped() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", "/")
            .with_status(401)
            .create_async()
            .await;

        let p = Arc::new(MockProvider::new(None, false));
        let client = build_client(p, 0).await;

        let req = client.get(server.url()).build().unwrap();
        let (resp, stamp) = execute_with_stamp(&client, req).await.unwrap();
        assert_eq!(resp.status(), 401);
        assert!(stamp.is_none(), "no credential must mean no stamp");
        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_max_retries_bounds_attempts() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", "/")
            .with_status(401)
            .expect(4)
            .create_async()
            .await;

        let p = Arc::new(MockProvider::new(Some("tok"), true));
        let client = build_client(p.clone(), 3).await;

        let resp = client.get(server.url()).send().await.unwrap();
        assert_eq!(resp.status(), 401);
        assert_eq!(p.refresh_count(), 3);
        m.assert_async().await;
    }
}
