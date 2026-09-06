//! MCP reqwest 0.13 policy and rmcp OAuth dispatch adapter.
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use rmcp::transport::auth::{
    AuthError, AuthorizationManager, OAuthHttpClient, OAuthHttpClientError, OAuthHttpClientFuture,
    OAuthHttpRedirectPolicy, OAuthHttpRequest,
};

pub(crate) fn check_url(url: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(url).map_err(|_| "invalid MCP request URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("MCP HTTP and consent URLs require HTTP or HTTPS".to_string());
    }
    fuigo_extra_ca::dispatch::check_url(&url).map_err(|error| error.to_string())
}

fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > 10 {
            return attempt.error("Fuigo MCP redirect limit exceeded");
        }
        let next = attempt.url();
        let same_origin = attempt.previous().first().is_some_and(|original| {
            original.origin() == next.origin()
                && original.username().is_empty()
                && original.password().is_none()
                && next.username().is_empty()
                && next.password().is_none()
                && matches!(next.scheme(), "http" | "https")
        });
        if !same_origin {
            return attempt.error("Fuigo refuses a cross-origin MCP credential redirect");
        }
        if let Err(error) = check_url(next.as_str()) {
            return attempt.error(error);
        }
        attempt.follow()
    })
}

pub(crate) fn configure(mut builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    fuigo_extra_ca::ensure_default_crypto_provider();
    builder = builder.tls_backend_rustls().redirect(redirect_policy());
    for der in fuigo_extra_ca::extra_root_ders() {
        match reqwest::Certificate::from_der(der) {
            Ok(cert) => builder = builder.add_root_certificate(cert),
            Err(error) => tracing::warn!(%error, "extra CA rejected by MCP HTTP client; skipping"),
        }
    }
    builder
}

struct CheckedOAuthClient {
    follow: reqwest::Client,
    stop: reqwest::Client,
}

impl CheckedOAuthClient {
    #[allow(clippy::disallowed_methods)] // approved MCP 0.13 TLS and redirect construction
    fn new() -> Result<Self, AuthError> {
        let build = |policy| {
            configure(reqwest::Client::builder())
                .timeout(Duration::from_secs(30))
                .redirect(policy)
                .build()
                .map_err(|error| AuthError::InternalError(error.to_string()))
        };
        Ok(Self {
            follow: build(redirect_policy())?,
            stop: build(reqwest::redirect::Policy::none())?,
        })
    }

    async fn execute_request(
        &self,
        mut request: reqwest::Request,
        policy: OAuthHttpRedirectPolicy,
        timeout: Option<Duration>,
    ) -> Result<http::Response<Vec<u8>>, OAuthHttpClientError> {
        check_url(request.url().as_str()).map_err(OAuthHttpClientError::new)?;
        if let Some(timeout) = timeout {
            *request.timeout_mut() = Some(timeout);
        }
        let client = match policy {
            OAuthHttpRedirectPolicy::Follow => &self.follow,
            OAuthHttpRedirectPolicy::Stop => &self.stop,
            _ => {
                return Err(OAuthHttpClientError::new(
                    "unsupported OAuth redirect policy",
                ));
            }
        };
        let response = client
            .execute(request)
            .await
            .map_err(|error| OAuthHttpClientError::new(error.without_url().to_string()))?;
        let mut builder = http::Response::builder()
            .status(response.status())
            .version(response.version());
        for (name, value) in response.headers() {
            builder = builder.header(name, value);
        }
        // Match rmcp 2.1's bounded buffered OAuth-response contract.
        const MAX_BODY: usize = 1024 * 1024;
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .map_err(|error| OAuthHttpClientError::new(error.without_url().to_string()))?;
            if chunk.len() > MAX_BODY - body.len() {
                return Err(OAuthHttpClientError::new("OAuth response exceeds 1 MiB"));
            }
            body.extend_from_slice(&chunk);
        }
        builder
            .body(body)
            .map_err(|error| OAuthHttpClientError::new(error.to_string()))
    }
}

impl OAuthHttpClient for CheckedOAuthClient {
    fn execute(&self, operation: OAuthHttpRequest) -> OAuthHttpClientFuture<'_> {
        Box::pin(async move {
            let request = reqwest::Request::try_from(operation.request)
                .map_err(|error| OAuthHttpClientError::new(error.without_url().to_string()))?;
            self.execute_request(request, operation.redirect_policy, operation.timeout)
                .await
        })
    }
}

pub(crate) async fn auth_manager(url: &str) -> Result<AuthorizationManager, AuthError> {
    check_url(url).map_err(AuthError::InternalError)?;
    AuthorizationManager::new_with_oauth_http_client(url, Arc::new(CheckedOAuthClient::new()?))
        .await
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // clients target local non-forwarding observers
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Bytes,
        http::{HeaderMap, StatusCode},
        routing::post,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn consent_and_http_policy_reject_non_http_schemes() {
        for url in [
            "file:///tmp/example",
            "javascript:void(0)",
            "custom-app://example",
            "https://api.x.ai/authorize",
        ] {
            assert!(check_url(url).is_err());
        }
        assert!(check_url("https://login.example/authorize").is_ok());
    }

    #[tokio::test]
    async fn oauth_same_origin_follow_preserves_body_and_headers() {
        let received = Arc::new(AtomicUsize::new(0));
        let sink = received.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/start", listener.local_addr().unwrap());
        let app = Router::new()
            .route(
                "/start",
                post(|| async { (StatusCode::TEMPORARY_REDIRECT, [("location", "/done")]) }),
            )
            .route(
                "/done",
                post(move |headers: HeaderMap, body: Bytes| {
                    let sink = sink.clone();
                    async move {
                        assert_eq!(headers.get("x-api-key").unwrap(), "fake-key");
                        assert_eq!(body.as_ref(), b"private-body");
                        sink.fetch_add(1, Ordering::SeqCst);
                        ([("x-test-result", "preserved")], "ok")
                    }
                }),
            );
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = CheckedOAuthClient::new().unwrap();
        let request = client
            .follow
            .post(url)
            .header("x-api-key", "fake-key")
            .body("private-body")
            .build()
            .unwrap();
        let response = client
            .execute_request(request, OAuthHttpRedirectPolicy::Follow, None)
            .await
            .unwrap();
        task.abort();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers().get("x-test-result").unwrap(),
            "preserved"
        );
        assert_eq!(response.body(), b"ok");
        assert_eq!(received.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn oauth_response_body_remains_bounded() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let app = Router::new().route("/token", post(|| async { vec![b'x'; 1024 * 1024 + 1] }));
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = CheckedOAuthClient::new().unwrap();
        let request = client.stop.post(url).build().unwrap();
        let error = client
            .execute_request(request, OAuthHttpRedirectPolicy::Stop, None)
            .await
            .unwrap_err();
        task.abort();
        assert!(error.to_string().contains("exceeds 1 MiB"));
    }

    #[tokio::test]
    async fn oauth_egress_policy_rejects_before_proxy_contact() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let client = configure(
            reqwest::Client::builder()
                .no_proxy()
                .proxy(reqwest::Proxy::all(proxy).unwrap()),
        )
        .build()
        .unwrap();
        let checked = CheckedOAuthClient {
            follow: client.clone(),
            stop: client.clone(),
        };
        for url in ["http://api.x.ai/token", "https://api.x.ai/token"] {
            let request = client.post(url).body("fake-secret").build().unwrap();
            let error = checked
                .execute_request(
                    request,
                    OAuthHttpRedirectPolicy::Stop,
                    Some(Duration::from_secs(2)),
                )
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("refuses to contact upstream vendor host")
            );
        }
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn oauth_redirect_policy_prevents_cross_origin_body_and_header_replay() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sink = calls.clone();
        let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_url = format!("http://{}/token", destination.local_addr().unwrap());
        let destination_task = tokio::spawn(async move {
            axum::serve(
                destination,
                Router::new().route(
                    "/token",
                    post(move || {
                        let sink = sink.clone();
                        async move {
                            sink.fetch_add(1, Ordering::SeqCst);
                            "ok"
                        }
                    }),
                ),
            )
            .await
            .unwrap();
        });
        for status in [
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
        ] {
            let source = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let source_url = format!("http://{}/token", source.local_addr().unwrap());
            let location = destination_url.clone();
            let source_task = tokio::spawn(async move {
                axum::serve(
                    source,
                    Router::new().route(
                        "/token",
                        post(move |headers: HeaderMap, body: Bytes| {
                            let location = location.clone();
                            async move {
                                assert_eq!(headers.get("x-api-key").unwrap(), "fake-key");
                                assert_eq!(body.as_ref(), b"private-body");
                                (status, [("location", location)], "redirect")
                            }
                        }),
                    ),
                )
                .await
                .unwrap();
            });
            let checked = CheckedOAuthClient::new().unwrap();
            let build = || {
                checked
                    .follow
                    .post(&source_url)
                    .header("x-api-key", "fake-key")
                    .body("private-body")
                    .build()
                    .unwrap()
            };
            assert!(
                checked
                    .execute_request(
                        build(),
                        OAuthHttpRedirectPolicy::Follow,
                        Some(Duration::from_secs(2))
                    )
                    .await
                    .is_err()
            );
            let stopped = checked
                .execute_request(
                    build(),
                    OAuthHttpRedirectPolicy::Stop,
                    Some(Duration::from_secs(2)),
                )
                .await
                .unwrap();
            assert_eq!(stopped.status(), status);
            source_task.abort();
        }
        destination_task.abort();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn real_oauth_manager_checks_discovered_registration_recipient() {
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        proxy.set_nonblocking(true).unwrap();
        let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", server.local_addr().unwrap());
        let issuer = base.clone();
        let discoveries = Arc::new(AtomicUsize::new(0));
        let observed = discoveries.clone();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let issuer = issuer.clone();
            let observed = observed.clone();
            async move {
                use axum::response::IntoResponse;
                if uri.path().contains("oauth-authorization-server")
                    || uri.path().contains("openid-configuration")
                {
                    observed.fetch_add(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({
                        "issuer": issuer,
                        "authorization_endpoint": format!("{issuer}/authorize"),
                        "token_endpoint": "https://api.x.ai/token",
                        "registration_endpoint": "https://api.x.ai/register",
                        "code_challenge_methods_supported": ["S256"]
                    }))
                    .into_response()
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            }
        });
        let task = tokio::spawn(async move {
            axum::serve(server, app).await.unwrap();
        });
        // Even a regression can only contact this non-forwarding proxy for x.ai.
        let client = configure(reqwest::Client::builder().no_proxy().proxy(
            reqwest::Proxy::custom(move |url| {
                url.host_str()
                    .filter(|host| fuigo_extra_ca::egress::is_blocked_host(host))
                    .map(|_| proxy_url.clone())
            }),
        ))
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
        let checked = CheckedOAuthClient {
            follow: client.clone(),
            stop: client,
        };
        let mut manager = AuthorizationManager::new_with_oauth_http_client(
            format!("{base}/mcp"),
            Arc::new(checked),
        )
        .await
        .unwrap();
        let metadata = manager.discover_metadata().await.unwrap();
        assert!(discoveries.load(Ordering::SeqCst) > 0);
        manager.set_metadata(metadata);
        let error = manager
            .register_client("fake-client", "http://localhost/callback", &[])
            .await
            .unwrap_err();
        task.abort();
        assert!(
            error
                .to_string()
                .contains("refuses to contact upstream vendor host"),
            "{error}"
        );
        assert_eq!(
            proxy.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
