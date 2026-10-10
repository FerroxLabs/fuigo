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

/// How many token endpoints one manager remembers; more than a handful means a hostile or broken server.
const MAX_TRACKED_TOKEN_ENDPOINTS: usize = 32;

/// What this manager has learned about token endpoints from the authorization-server metadata documents it fetched.
#[derive(Default)]
struct TokenEndpointBindings {
    /// Token endpoints named by a metadata document that passed [`judge_token_endpoint`].
    allowed: std::collections::HashSet<String>,
    /// Set when a server named more endpoints than [`MAX_TRACKED_TOKEN_ENDPOINTS`]: nothing is admitted any more.
    saturated: bool,
    /// Token endpoints named only by a document that failed it, with the reason, so a refusal can say why.
    refused: std::collections::HashMap<String, String>,
}

fn origin_label(url: &reqwest::Url) -> String {
    url.origin().ascii_serialization()
}

/// A URL without credentials, query or fragment, for error messages and map keys.
fn endpoint_key(url: &reqwest::Url) -> String {
    let mut url = url.clone();
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

/// Binding for one authorization-server metadata document. RFC 8414 section 3.3 requires the issuer to match the
/// origin the document was fetched from; requiring the token endpoint on that origin too is Fuigo policy on top.
///
/// `served_from` is the URL the document was fetched from. The authorization server is the origin that served it, so:
/// the `issuer` it declares (when it declares one) must be on that origin, and the `token_endpoint` must be on that
/// origin too. A token endpoint on any other scheme, host or port is not something the authorization server controls,
/// and the authorization code, PKCE verifier, client secret and refresh token must never be sent there.
/// Returns `None` when the document names no token endpoint at all (a protected-resource document, for example),
/// else the endpoint key and the verdict. Loopback `http` development servers pass because their origin matches.
fn judge_token_endpoint(
    served_from: &reqwest::Url,
    document: &serde_json::Value,
) -> Option<(String, Result<(), String>)> {
    let named = document.get("token_endpoint")?.as_str()?;
    // A protected-resource document (RFC 9728: it carries `resource`, and AS metadata never does) may hold extension
    // fields; a stray token_endpoint there is neither authorization-server metadata nor evidence against one.
    if document.get("resource").is_some() && document.get("issuer").is_none() {
        return None;
    }
    let served_origin = origin_label(served_from);
    let endpoint = match reqwest::Url::parse(named) {
        Ok(url) if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() => url,
        _ => {
            return Some((
                named.chars().take(200).collect(),
                Err(format!(
                    "refused: the authorization server metadata served from {served_origin} names a token_endpoint that is not an absolute http(s) URL"
                )),
            ));
        }
    };
    let key = endpoint_key(&endpoint);
    if let Some(issuer) = document.get("issuer").and_then(|v| v.as_str()) {
        let issuer_origin = reqwest::Url::parse(issuer)
            .ok()
            .filter(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
            .map(|url| origin_label(&url));
        if issuer_origin.as_deref() != Some(served_origin.as_str()) {
            return Some((
                key,
                Err(format!(
                    "refused: the authorization server metadata served from {served_origin} declares issuer {}, which is not on the origin that served it (RFC 8414 section 3.3 requires the issuer to match), so its token_endpoint cannot be trusted",
                    issuer_origin.as_deref().unwrap_or("(not an http(s) URL)")
                )),
            ));
        }
    }
    // The one binding rule, shared with the shell's OIDC login and the hub refresh: the token endpoint is https (or
    // http on loopback) on the issuer's origin, or the built-in Google pair. The issuer was just required to be on the
    // serving origin, so "issuer origin" and "served origin" are the same origin here; with no declared issuer the
    // serving origin stands in for it. Never looser than the shell: it also refuses userinfo and plain http off loopback.
    let issuer_for_rule = document
        .get("issuer")
        .and_then(|v| v.as_str())
        .map_or_else(|| served_origin.clone(), str::to_string);
    if let Err(rule) = fuigo_computer_hub_sdk::check_token_endpoint(&issuer_for_rule, &endpoint, true) {
        let detail = if origin_label(&endpoint) != served_origin {
            format!("which is on a different origin ({})", origin_label(&endpoint))
        } else {
            format!("which the shared token endpoint rule refuses ({rule})")
        };
        return Some((
            key.clone(),
            Err(format!(
                "refused: the authorization server metadata served from {served_origin} names token_endpoint {key}, {detail}. Authorization codes, refresh tokens and client secrets are only sent to a token endpoint on the authorization server's own origin"
            )),
        ));
    }
    Some((key, Ok(())))
}

/// Does this request carry a code, a refresh token or a client secret? OAuth token requests are form-encoded.
fn is_credential_bearing(request: &reqwest::Request) -> bool {
    if request.method() != reqwest::Method::POST {
        return false;
    }
    let Some(body) = request.body() else {
        return false;
    };
    // OAuth token requests are form-encoded. A body that declares another content type (the JSON registration
    // request, whose scope string may legally contain '&' and '=') is not parsed as a form.
    let declared = request
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_ascii_lowercase());
    if declared
        .as_deref()
        .is_some_and(|value| !value.starts_with("application/x-www-form-urlencoded"))
    {
        return false;
    }
    // A streaming body cannot be inspected; treat it as credential-bearing so it must target a bound endpoint.
    let Some(bytes) = body.as_bytes() else {
        return true;
    };
    if declared.is_none() && matches!(bytes.first(), Some(b'{' | b'[')) {
        return false;
    }
    let text = String::from_utf8_lossy(bytes);
    text.split('&').any(|pair| {
        let name = pair.split('=').next().unwrap_or_default();
        matches!(
            name,
            "grant_type" | "code" | "refresh_token" | "client_secret" | "code_verifier" | "client_assertion"
        )
    })
}

tokio::task_local! {
    /// Where the adapter leaves the reason for a refused token request. rmcp turns the adapter's error into the opaque
    /// text "Request failed", so a caller that wants to tell the user why wraps its call in [`capture_refusal`].
    static REFUSAL: std::cell::RefCell<Option<String>>;
}

/// Run `operation` and return what it produced plus the reason a token request inside it was refused, if one was.
pub(crate) async fn capture_refusal<F: std::future::Future>(operation: F) -> (F::Output, Option<String>) {
    REFUSAL
        .scope(std::cell::RefCell::new(None), async {
            let output = operation.await;
            let refusal = REFUSAL.with(|slot| slot.borrow_mut().take());
            (output, refusal)
        })
        .await
}

tokio::task_local! {
    /// A refusal Fuigo itself generated while running a sign-in, built only from endpoint keys (no query, no userinfo)
    /// and origins. It travels beside the error, never inside it, so provider text can never be mistaken for it
    /// (Astra r2). Callers that show a reason to a client wrap the flow in [`capture_trusted_refusal`].
    static TRUSTED_REFUSAL: std::cell::RefCell<Option<String>>;
}

/// Run `operation` and return what it produced plus the client-safe refusal Fuigo recorded inside it, if any.
pub(crate) async fn capture_trusted_refusal<F: std::future::Future>(operation: F) -> (F::Output, Option<String>) {
    TRUSTED_REFUSAL
        .scope(std::cell::RefCell::new(None), async {
            let output = operation.await;
            let refusal = TRUSTED_REFUSAL.with(|slot| slot.borrow_mut().take());
            (output, refusal)
        })
        .await
}

/// Record a refusal for both the log-oriented [`capture_refusal`] and the client-facing [`capture_trusted_refusal`].
/// `message` must be built only from endpoint keys and origins.
fn record_refusal(message: &str) {
    let _ = REFUSAL.try_with(|slot| *slot.borrow_mut() = Some(message.to_string()));
    let _ = TRUSTED_REFUSAL.try_with(|slot| *slot.borrow_mut() = Some(message.to_string()));
}

/// How many MCP server URLs the process remembers a refusal for; a flood of distinct servers cannot grow it without bound.
const MAX_REMEMBERED_REFUSALS: usize = 64;
/// The longest refusal text kept; the texts are built from endpoint keys and fixed wording, so this is only a bound.
const MAX_REMEMBERED_REFUSAL_CHARS: usize = 600;

/// The latest refusal of a credential-bearing token request, per MCP server URL (K7).
/// rmcp refreshes an expired token on its own, outside any [`capture_refusal`] scope, and shows only "Request failed".
/// The adapter sees every such request, so it leaves the reason here for `/mcps` to show beside the server.
/// Texts are built only from endpoint keys (no query, no userinfo), origins and fixed wording.
static REMEMBERED_REFUSALS: std::sync::LazyLock<
    parking_lot::Mutex<std::collections::HashMap<String, String>>,
> = std::sync::LazyLock::new(Default::default);

fn refusal_key(server_url: &str) -> String {
    reqwest::Url::parse(server_url)
        .map(|url| endpoint_key(&url))
        .unwrap_or_else(|_| server_url.to_string())
}

/// The reason the last credential-bearing token request for the MCP server at `server_url` was refused, if one was
/// and no later one succeeded.
pub fn auth_refusal_for_url(server_url: &str) -> Option<String> {
    REMEMBERED_REFUSALS.lock().get(&refusal_key(server_url)).cloned()
}

fn remember_refusal(server_url: &str, message: &str) {
    if server_url.is_empty() {
        return;
    }
    let key = refusal_key(server_url);
    let text: String = message.chars().take(MAX_REMEMBERED_REFUSAL_CHARS).collect();
    let mut table = REMEMBERED_REFUSALS.lock();
    if !table.contains_key(&key) && table.len() >= MAX_REMEMBERED_REFUSALS {
        table.clear();
    }
    table.insert(key, text);
}

fn forget_refusal(server_url: &str) {
    if !server_url.is_empty() {
        REMEMBERED_REFUSALS.lock().remove(&refusal_key(server_url));
    }
}

/// The text a user should see: the specific refusal when there was one, else rmcp's own error.
pub(crate) fn explain_token_error(error: &dyn std::fmt::Display, refusal: Option<&str>) -> String {
    refusal.map_or_else(|| error.to_string(), str::to_string)
}

/// `refresh_token()` for callers that only need a verdict: a refused token endpoint is logged with its reason.
pub(crate) async fn refresh_logged(manager: &AuthorizationManager, server: &str) -> bool {
    let (outcome, refusal) = capture_refusal(manager.refresh_token()).await;
    match outcome {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(server, error = %explain_token_error(&error, refusal.as_deref()), "OAuth token refresh failed");
            false
        }
    }
}

struct CheckedOAuthClient {
    follow: reqwest::Client,
    stop: reqwest::Client,
    bindings: parking_lot::Mutex<TokenEndpointBindings>,
    /// The MCP server URL this client serves; refusals are remembered against it (empty: not remembered).
    resource: String,
}

impl CheckedOAuthClient {
    #[cfg(test)]
    fn new() -> Result<Self, AuthError> {
        Self::for_resource("")
    }

    #[allow(clippy::disallowed_methods)] // approved MCP 0.13 TLS and redirect construction
    fn for_resource(resource: &str) -> Result<Self, AuthError> {
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
            bindings: parking_lot::Mutex::new(TokenEndpointBindings::default()),
            resource: resource.to_string(),
        })
    }

    /// Record a refusal for the task that is running the request and for `/mcps`.
    /// `message` must be built only from endpoint keys and origins.
    fn refuse(&self, message: &str) {
        record_refusal(message);
        remember_refusal(&self.resource, message);
    }

    /// A token endpoint that redirected a credential-bearing request is refused for the rest of this manager's life:
    /// the next automatic refresh is refused before it sends anything, instead of posting the refresh token again.
    fn refuse_endpoint_for_good(&self, key: &str, why: &str) {
        let mut bindings = self.bindings.lock();
        bindings.allowed.remove(key);
        bindings.refused.entry(key.to_string()).or_insert_with(|| why.to_string());
    }

    /// Refuse to send a credential-bearing request to a token endpoint no validated metadata document named.
    fn check_token_recipient(&self, request: &reqwest::Request) -> Result<(), OAuthHttpClientError> {
        if !is_credential_bearing(request) {
            return Ok(());
        }
        let key = endpoint_key(request.url());
        let bindings = self.bindings.lock();
        if bindings.allowed.contains(&key) && !bindings.saturated {
            return Ok(());
        }
        let why = bindings.refused.get(&key).cloned().unwrap_or_else(|| {
            if bindings.saturated {
                return format!(
                    "refused: the server named more than {MAX_TRACKED_TOKEN_ENDPOINTS} distinct token endpoints, so none can be trusted"
                );
            }
            format!(
                "refused: {key} is not a token endpoint named by authorization server metadata served from its own origin"
            )
        });
        let message = format!(
            "refusing to send OAuth credentials (authorization code, refresh token or client secret) to {key}: {why}"
        );
        tracing::warn!(endpoint = %key, "{message}");
        self.refuse(&message);
        Err(OAuthHttpClientError::from(message))
    }

    /// Learn from an authorization-server metadata response which token endpoints the server legitimately controls.
    fn learn_token_endpoint(&self, served_from: &reqwest::Url, body: &[u8]) {
        let Ok(document) = serde_json::from_slice::<serde_json::Value>(body) else {
            return;
        };
        let Some((key, verdict)) = judge_token_endpoint(served_from, &document) else {
            return;
        };
        let mut bindings = self.bindings.lock();
        let known = bindings.allowed.contains(&key) || bindings.refused.contains_key(&key);
        if !known && bindings.allowed.len() + bindings.refused.len() >= MAX_TRACKED_TOKEN_ENDPOINTS {
            // Never drop a verdict silently: a full table fails closed, and refusals of known endpoints still apply.
            bindings.saturated = true;
            bindings.allowed.clear();
            return;
        }
        match verdict {
            // A refusal is sticky: one document that put this endpoint off its authorization server's origin means
            // no later document can admit it for this manager.
            Ok(()) if !bindings.refused.contains_key(&key) && !bindings.saturated => {
                bindings.allowed.insert(key);
            }
            Ok(()) => {}
            Err(reason) => {
                bindings.allowed.remove(&key);
                bindings.refused.entry(key).or_insert(reason);
            }
        }
    }

    #[allow(clippy::disallowed_methods)] // reqwest 0.13 adapter: check_url precedes execution; clients enforce redirect policy.
    async fn execute_request(
        &self,
        mut request: reqwest::Request,
        policy: OAuthHttpRedirectPolicy,
        timeout: Option<Duration>,
    ) -> Result<http::Response<Vec<u8>>, OAuthHttpClientError> {
        self.check_token_recipient(&request)?;
        if let Err(message) = check_url(request.url().as_str()) {
            if is_credential_bearing(&request) {
                let _ = REFUSAL.try_with(|slot| *slot.borrow_mut() = Some(message.clone()));
                let _ = TRUSTED_REFUSAL.try_with(|slot| {
                    *slot.borrow_mut() = Some(format!(
                        "refusing to send OAuth credentials to {}: the network policy blocks this address",
                        endpoint_key(request.url())
                    ))
                });
                remember_refusal(
                    &self.resource,
                    &format!(
                        "refusing to send OAuth credentials to {}: the network policy blocks this address",
                        endpoint_key(request.url())
                    ),
                );
            }
            return Err(OAuthHttpClientError::from(message));
        }
        let discovery_url = (request.method() == reqwest::Method::GET).then(|| request.url().clone());
        // A credential-bearing request whose redirect the policy stops is a refusal the caller can show (P151).
        let refused_redirect_key = is_credential_bearing(&request).then(|| endpoint_key(request.url()));
        if let Some(timeout) = timeout {
            *request.timeout_mut() = Some(timeout);
        }
        let client = match policy {
            OAuthHttpRedirectPolicy::Follow => &self.follow,
            OAuthHttpRedirectPolicy::Stop => &self.stop,
            _ => {
                return Err(OAuthHttpClientError::from(
                    "unsupported OAuth redirect policy",
                ));
            }
        };
        let response = match client.execute(request).await {
            Ok(response) => response,
            Err(error) if error.is_redirect() && refused_redirect_key.is_some() => {
                let key = refused_redirect_key.unwrap_or_default();
                let why = "refused: the token endpoint redirected the request to another origin, to an address the network policy blocks, or too many times";
                let message = format!(
                    "refusing to send OAuth credentials (authorization code, refresh token or client secret) through a redirect from {key}: {why}"
                );
                tracing::warn!(endpoint = %key, "{message}");
                self.refuse_endpoint_for_good(&key, why);
                self.refuse(&message);
                return Err(OAuthHttpClientError::from(message));
            }
            Err(error) => return Err(OAuthHttpClientError::from(error.without_url().to_string())),
        };
        // rmcp sends token requests with the Stop policy, so a redirect comes back as a response; rmcp would read
        // it as an empty error. Credentials are never resent to a redirect target: refuse with the reason (P151).
        if let Some(key) = refused_redirect_key.as_deref()
            && response.status().is_redirection()
        {
            let target = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|location| response.url().join(location).ok());
            let same_origin = target
                .as_ref()
                .is_some_and(|target| target.origin() == response.url().origin());
            let place = if same_origin { "another address on the same origin" } else { "another origin" };
            let why = format!(
                "refused: the token endpoint answered HTTP {} redirecting the request to {place}; credentials are only sent to the token endpoint the metadata names",
                response.status().as_u16()
            );
            let message = format!(
                "refusing to send OAuth credentials (authorization code, refresh token or client secret) through a redirect from {key}: {why}"
            );
            tracing::warn!(endpoint = %key, "{message}");
            self.refuse_endpoint_for_good(key, &why);
            self.refuse(&message);
            return Err(OAuthHttpClientError::from(message));
        }
        let succeeded = response.status().is_success();
        if succeeded && refused_redirect_key.is_some() {
            // A credential-bearing request went through: whatever was refused before no longer describes this server.
            forget_refusal(&self.resource);
        }
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
                .map_err(|error| OAuthHttpClientError::from(error.without_url().to_string()))?;
            if chunk.len() > MAX_BODY - body.len() {
                return Err(OAuthHttpClientError::from("OAuth response exceeds 1 MiB"));
            }
            body.extend_from_slice(&chunk);
        }
        if let Some(discovery_url) = discovery_url
            && succeeded
        {
            self.learn_token_endpoint(&discovery_url, &body);
        }
        builder
            .body(body)
            .map_err(|error| OAuthHttpClientError::from(error.to_string()))
    }
}

impl OAuthHttpClient for CheckedOAuthClient {
    fn execute(&self, operation: OAuthHttpRequest) -> OAuthHttpClientFuture<'_> {
        Box::pin(async move {
            let request = reqwest::Request::try_from(operation.request)
                .map_err(|error| OAuthHttpClientError::from(error.without_url().to_string()))?;
            self.execute_request(request, operation.redirect_policy, operation.timeout)
                .await
        })
    }
}

pub(crate) async fn auth_manager(url: &str) -> Result<AuthorizationManager, AuthError> {
    check_url(url).map_err(AuthError::InternalError)?;
    AuthorizationManager::new_with_oauth_http_client(
        url,
        Arc::new(CheckedOAuthClient::for_resource(url)?),
    )
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
            bindings: Default::default(),
            resource: String::new(),
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

    fn doc(issuer: Option<&str>, token_endpoint: &str) -> serde_json::Value {
        let mut doc = serde_json::json!({
            "authorization_endpoint": "https://as.example.com/authorize",
            "token_endpoint": token_endpoint
        });
        if let Some(issuer) = issuer {
            doc["issuer"] = issuer.into();
        }
        doc
    }

    fn judge(served_from: &str, document: serde_json::Value) -> Result<(), String> {
        let served_from = reqwest::Url::parse(served_from).unwrap();
        judge_token_endpoint(&served_from, &document)
            .expect("document names a token endpoint")
            .1
    }

    #[test]
    fn token_endpoint_on_the_issuer_origin_is_admitted() {
        let served = "https://as.example.com/.well-known/oauth-authorization-server";
        for token in [
            "https://as.example.com/token",
            "https://as.example.com:443/oauth2/token",
            "https://AS.EXAMPLE.COM/t?x=1",
        ] {
            judge(served, doc(Some("https://as.example.com"), token)).unwrap();
        }
        // no issuer declared (legacy server): the serving origin alone is the anchor
        judge(served, doc(None, "https://as.example.com/token")).unwrap();
        // loopback http development servers keep working because their origin matches
        judge(
            "http://127.0.0.1:4000/.well-known/oauth-authorization-server",
            doc(Some("http://127.0.0.1:4000"), "http://127.0.0.1:4000/token"),
        )
        .unwrap();
    }

    #[test]
    fn token_endpoint_off_the_issuer_origin_is_refused_with_the_reason() {
        let served = "https://as.example.com/.well-known/oauth-authorization-server";
        for token in [
            "https://evil.test/token",
            "https://as.example.com.evil.test/token",
            "https://as.example.com@evil.test/token",
            "https://as.example.com:8443/token",
            "http://as.example.com/token",
            "https://token.as.example.com/token",
        ] {
            let error = judge(served, doc(Some("https://as.example.com"), token))
                .expect_err(token);
            assert!(error.starts_with("refused:"), "{error}");
            assert!(error.contains("different origin"), "{error}");
            assert!(error.contains("https://as.example.com"), "{error}");
        }
        for token in ["/token", "ftp://as.example.com/token", "javascript:alert(1)", ""] {
            let error = judge(served, doc(None, token)).expect_err(token);
            assert!(error.contains("not an absolute http(s) URL"), "{error}");
        }
    }

    #[test]
    fn google_split_host_pair_is_admitted_like_the_shell() {
        let served = "https://accounts.google.com/.well-known/openid-configuration";
        judge(
            served,
            doc(Some("https://accounts.google.com"), "https://oauth2.googleapis.com/token"),
        )
        .unwrap();
        // look-alikes stay refused
        for token in [
            "https://oauth2.googleapis.com.evil.example/token",
            "http://oauth2.googleapis.com/token",
            "https://oauth2.googleapis.com:8443/token",
            "https://evil.oauth2.googleapis.com/token",
            "https://oauth2.googleapis.com@evil.example/token",
            "https://www.googleapis.com/token",
        ] {
            judge(served, doc(Some("https://accounts.google.com"), token)).expect_err(token);
        }
        // the pair is directed and exact: another issuer does not inherit it
        judge(
            "https://login.example.com/.well-known/openid-configuration",
            doc(Some("https://login.example.com"), "https://oauth2.googleapis.com/token"),
        )
        .expect_err("other issuer");
        // Cognito-style split hosts remain refused, as in the shell
        judge(
            "https://cognito-idp.eu-west-1.amazonaws.com/pool/.well-known/openid-configuration",
            doc(Some("https://cognito-idp.eu-west-1.amazonaws.com/pool"), "https://x.auth.eu-west-1.amazoncognito.com/oauth2/token"),
        )
        .expect_err("cognito");
    }

    #[test]
    fn google_pair_admits_exchange_and_refresh() {
        let checked = client_with_no_proxy();
        let served = reqwest::Url::parse("https://accounts.google.com/.well-known/openid-configuration").unwrap();
        checked.learn_token_endpoint(
            &served,
            br#"{"issuer":"https://accounts.google.com","authorization_endpoint":"https://accounts.google.com/o/oauth2/v2/auth","token_endpoint":"https://oauth2.googleapis.com/token"}"#,
        );
        for body in [
            "grant_type=authorization_code&code=c&code_verifier=v&client_secret=s",
            "grant_type=refresh_token&refresh_token=rt",
        ] {
            checked
                .check_token_recipient(&credential_post("https://oauth2.googleapis.com/token", body))
                .unwrap();
            checked
                .check_token_recipient(&credential_post("https://oauth2.googleapis.com.evil.example/token", body))
                .unwrap_err();
        }
    }

    #[test]
    fn issuer_off_the_serving_origin_is_refused() {
        let served = "https://as.example.com/.well-known/oauth-authorization-server";
        for issuer in ["https://evil.test", "https://evil.test/", "not a url", "http://as.example.com"] {
            let error = judge(served, doc(Some(issuer), "https://as.example.com/token"))
                .expect_err(issuer);
            assert!(error.contains("RFC 8414"), "{error}");
        }
        // a non-string issuer is treated as absent only if absent; a declared string must match
        assert!(judge_token_endpoint(
            &reqwest::Url::parse(served).unwrap(),
            &serde_json::json!({ "issuer": "https://as.example.com/tenant1", "authorization_endpoint": "https://as.example.com/a", "token_endpoint": "https://as.example.com/token" })
        )
        .unwrap()
        .1
        .is_ok());
    }

    #[test]
    fn a_document_without_a_token_endpoint_teaches_nothing() {
        let served = reqwest::Url::parse("https://rs.example.com/.well-known/oauth-protected-resource").unwrap();
        assert!(judge_token_endpoint(&served, &serde_json::json!({ "resource": "https://rs.example.com" })).is_none());
        assert!(judge_token_endpoint(&served, &serde_json::json!({ "token_endpoint": 7 })).is_none());
    }

    fn client_with_no_proxy() -> CheckedOAuthClient {
        let client = reqwest::Client::new();
        CheckedOAuthClient {
            follow: client.clone(),
            stop: client,
            bindings: Default::default(),
            resource: String::new(),
        }
    }

    fn credential_post(url: &str, body: &'static str) -> reqwest::Request {
        reqwest::Client::new().post(url).body(body).build().unwrap()
    }

    #[test]
    fn credential_requests_need_a_validated_token_endpoint() {
        let checked = client_with_no_proxy();
        let served = reqwest::Url::parse("https://as.example.com/.well-known/oauth-authorization-server").unwrap();
        let refresh = "grant_type=refresh_token&refresh_token=rt-secret&client_id=c";

        // nothing learned yet: fail closed, and say what was refused and why
        let error = checked
            .check_token_recipient(&credential_post("https://as.example.com/token", refresh))
            .unwrap_err()
            .to_string();
        assert!(error.contains("refusing to send OAuth credentials"), "{error}");
        assert!(error.contains("https://as.example.com/token"), "{error}");
        assert!(!error.contains("rt-secret"), "{error}");

        // a legitimate document admits its own endpoint
        checked.learn_token_endpoint(
            &served,
            br#"{"issuer":"https://as.example.com","authorization_endpoint":"https://as.example.com/a","token_endpoint":"https://as.example.com/token"}"#,
        );
        checked
            .check_token_recipient(&credential_post("https://as.example.com/token", refresh))
            .unwrap();
        checked
            .check_token_recipient(&credential_post(
                "https://as.example.com/token",
                "grant_type=authorization_code&code=c&code_verifier=v",
            ))
            .unwrap();
        checked
            .check_token_recipient(&credential_post("https://as.example.com/token", "client_secret=s"))
            .unwrap();

        // a hostile document is remembered with its reason and its endpoint stays refused
        checked.learn_token_endpoint(
            &served,
            br#"{"issuer":"https://as.example.com","authorization_endpoint":"https://as.example.com/a","token_endpoint":"https://evil.test/token"}"#,
        );
        let error = checked
            .check_token_recipient(&credential_post("https://evil.test/token", refresh))
            .unwrap_err()
            .to_string();
        assert!(error.contains("https://evil.test/token"), "{error}");
        assert!(error.contains("different origin (https://evil.test)"), "{error}");
        assert!(error.contains("https://as.example.com"), "{error}");

        // a path on the same origin that no document named is still refused
        assert!(
            checked
                .check_token_recipient(&credential_post("https://as.example.com/other", refresh))
                .is_err()
        );
    }

    #[test]
    fn requests_that_carry_no_credential_are_not_gated() {
        let checked = client_with_no_proxy();
        let json = reqwest::Client::new()
            .post("https://as.example.com/register")
            .header("content-type", "application/json")
            .body(r#"{"client_name":"Fuigo","grant_types":["authorization_code","refresh_token"]}"#)
            .build()
            .unwrap();
        checked.check_token_recipient(&json).unwrap();
        let get = reqwest::Client::new().get("https://as.example.com/x").build().unwrap();
        checked.check_token_recipient(&get).unwrap();
        // the gate cannot be bypassed by hiding the grant among other form fields
        assert!(
            checked
                .check_token_recipient(&credential_post("https://evil.test/t", "a=b&refresh_token=rt"))
                .is_err()
        );
    }

    #[test]
    fn a_refused_refresh_is_never_classified_as_a_transient_network_failure() {
        use crate::rmcp::transport::auth::AuthError;
        let opaque = AuthError::TokenRefreshFailed("Request failed".to_string());
        assert!(crate::servers::mcp_refresh_failure_is_transient_unless_refused(&opaque, None));
        assert!(!crate::servers::mcp_refresh_failure_is_transient_unless_refused(
            &opaque,
            Some("refusing to send OAuth credentials")
        ));
    }

    #[test]
    fn a_resource_document_cannot_admit_a_token_endpoint_for_rejected_as_metadata() {
        // Astra r1 HIGH: R's protected-resource document carries a stray token_endpoint, and a later "custom" document
        // served from R declares A as issuer and names R/token. Neither may admit R/token.
        let checked = client_with_no_proxy();
        let resource = reqwest::Url::parse("https://r.example.com/.well-known/oauth-protected-resource").unwrap();
        checked.learn_token_endpoint(
            &resource,
            br#"{"resource":"https://r.example.com","authorization_endpoint":"https://r.example.com/a","token_endpoint":"https://r.example.com/token"}"#,
        );
        let custom = reqwest::Url::parse("https://r.example.com/custom-as-metadata").unwrap();
        checked.learn_token_endpoint(
            &custom,
            br#"{"issuer":"https://a.example.com","authorization_endpoint":"https://a.example.com/authorize","token_endpoint":"https://r.example.com/token"}"#,
        );
        let error = checked
            .check_token_recipient(&credential_post(
                "https://r.example.com/token",
                "grant_type=refresh_token&refresh_token=rt",
            ))
            .unwrap_err()
            .to_string();
        assert!(error.contains("https://r.example.com/token"), "{error}");
        // and a refusal is sticky: a later admitting document from another origin context cannot undo it
        checked.learn_token_endpoint(
            &reqwest::Url::parse("https://r.example.com/.well-known/oauth-authorization-server").unwrap(),
            br#"{"issuer":"https://r.example.com","authorization_endpoint":"https://r.example.com/a","token_endpoint":"https://r.example.com/token"}"#,
        );
        assert!(
            checked
                .check_token_recipient(&credential_post(
                    "https://r.example.com/token",
                    "grant_type=refresh_token&refresh_token=rt"
                ))
                .is_err()
        );
    }

    #[test]
    fn a_document_on_a_resource_looking_path_cannot_launder_an_endpoint_for_another_issuer() {
        // Astra r2 HIGH: the stray endpoint is admitted from a path under /mcp, the AS document that names it for
        // issuer A sits on a path containing "oauth-protected-resource"; both are judged, so the refusal wins.
        let checked = client_with_no_proxy();
        checked.learn_token_endpoint(
            &reqwest::Url::parse("https://r.example.com/mcp").unwrap(),
            br#"{"issuer":"https://r.example.com","authorization_endpoint":"https://r.example.com/authorize","token_endpoint":"https://r.example.com/token"}"#,
        );
        checked.learn_token_endpoint(
            &reqwest::Url::parse("https://r.example.com/.well-known/oauth-protected-resource-as").unwrap(),
            br#"{"issuer":"https://a.example.com","authorization_endpoint":"https://a.example.com/authorize","token_endpoint":"https://r.example.com/token"}"#,
        );
        assert!(
            checked
                .check_token_recipient(&credential_post(
                    "https://r.example.com/token",
                    "grant_type=authorization_code&code=c&client_secret=s"
                ))
                .is_err()
        );
    }

    #[test]
    fn a_tenant_path_containing_a_well_known_word_is_not_a_false_refusal() {
        // Astra r2 MEDIUM: legitimate AS metadata must be admitted whatever its path says.
        let checked = client_with_no_proxy();
        checked.learn_token_endpoint(
            &reqwest::Url::parse("https://a.example/.well-known/oauth-authorization-server/tenants/oauth-protected-resource-demo").unwrap(),
            br#"{"issuer":"https://a.example/tenants/oauth-protected-resource-demo","authorization_endpoint":"https://a.example/authorize","token_endpoint":"https://a.example/token"}"#,
        );
        checked
            .check_token_recipient(&credential_post("https://a.example/token", "grant_type=refresh_token&refresh_token=rt"))
            .unwrap();
    }

    #[test]
    fn a_full_table_fails_closed_and_never_suppresses_a_refusal() {
        // Astra r2 HIGH: after saturation a refusal of an already admitted endpoint was dropped.
        let checked = client_with_no_proxy();
        let served = reqwest::Url::parse("https://as.example.com/.well-known/oauth-authorization-server").unwrap();
        let named = |token: &str| {
            format!(r#"{{"issuer":"https://as.example.com","authorization_endpoint":"https://as.example.com/a","token_endpoint":"{token}"}}"#)
        };
        checked.learn_token_endpoint(&served, named("https://as.example.com/token").as_bytes());
        for i in 0..MAX_TRACKED_TOKEN_ENDPOINTS + 4 {
            checked.learn_token_endpoint(&served, named(&format!("https://as.example.com/t{i}")).as_bytes());
        }
        // the endpoint admitted earlier is no longer trusted once the table overflowed
        assert!(
            checked
                .check_token_recipient(&credential_post("https://as.example.com/token", "grant_type=refresh_token&refresh_token=rt"))
                .is_err()
        );
        // and a refusal for a known endpoint is still recorded
        let other = reqwest::Url::parse("https://evil.test/.well-known/oauth-authorization-server").unwrap();
        checked.learn_token_endpoint(&other, named("https://as.example.com/token").as_bytes());
        let error = checked
            .check_token_recipient(&credential_post("https://as.example.com/token", "grant_type=refresh_token&refresh_token=rt"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("refus"), "{error}");
    }

    #[test]
    fn a_protected_resource_document_with_a_stray_token_endpoint_neither_admits_nor_poisons() {
        // Astra r3 MEDIUM: R's resource metadata (RFC 9728 allows extension fields) names AS A and carries a stray
        // token_endpoint on A; it must be ignored, not recorded as a refusal that blocks A's real metadata later.
        let checked = client_with_no_proxy();
        checked.learn_token_endpoint(
            &reqwest::Url::parse("https://r.example/.well-known/oauth-protected-resource/mcp").unwrap(),
            br#"{"resource":"https://r.example/mcp","authorization_servers":["https://a.example"],"token_endpoint":"https://a.example/token"}"#,
        );
        assert!(
            checked
                .check_token_recipient(&credential_post("https://a.example/token", "grant_type=refresh_token&refresh_token=rt"))
                .is_err(),
            "a resource document admits nothing"
        );
        checked.learn_token_endpoint(
            &reqwest::Url::parse("https://a.example/.well-known/oauth-authorization-server").unwrap(),
            br#"{"issuer":"https://a.example","authorization_endpoint":"https://a.example/authorize","token_endpoint":"https://a.example/token"}"#,
        );
        checked
            .check_token_recipient(&credential_post("https://a.example/token", "grant_type=refresh_token&refresh_token=rt"))
            .unwrap();
    }

    #[test]
    fn dynamic_registration_json_is_not_mistaken_for_a_credential_request() {
        // Astra r1 MEDIUM: a scope containing '&' and '=' is legal and lands inside the JSON registration body.
        let checked = client_with_no_proxy();
        let register = reqwest::Client::new()
            .post("https://as.example.com/register")
            .header("content-type", "application/json")
            .body(r#"{"client_name":"Fuigo","scope":"api&code=read&refresh_token=x"}"#)
            .build()
            .unwrap();
        checked.check_token_recipient(&register).unwrap();
        // a form body is still judged even with a charset parameter on the content type
        let form = reqwest::Client::new()
            .post("https://evil.test/token")
            .header("content-type", "application/x-www-form-urlencoded; charset=UTF-8")
            .body("grant_type=refresh_token&refresh_token=rt")
            .build()
            .unwrap();
        assert!(checked.check_token_recipient(&form).is_err());
    }

    #[tokio::test]
    async fn a_denylisted_token_endpoint_still_reports_the_reason() {
        // Astra r1 MEDIUM: check_url used to return before the refusal reason was recorded.
        let checked = CheckedOAuthClient::new().unwrap();
        let request = checked
            .follow
            .post("https://api.x.ai/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body("grant_type=refresh_token&refresh_token=rt-secret")
            .build()
            .unwrap();
        let (outcome, refusal) = capture_refusal(checked.execute_request(
            request,
            OAuthHttpRedirectPolicy::Stop,
            Some(Duration::from_secs(2)),
        ))
        .await;
        assert!(outcome.is_err());
        let refusal = refusal.expect("the refusal reason is captured for policy rejections too");
        assert!(!refusal.contains("rt-secret"), "{refusal}");
    }

    #[tokio::test]
    async fn gated_request_never_reaches_the_foreign_endpoint() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sink = calls.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/token",
                    post(move || {
                        let sink = sink.clone();
                        async move {
                            sink.fetch_add(1, Ordering::SeqCst);
                            "{}"
                        }
                    }),
                ),
            )
            .await
            .unwrap();
        });
        let checked = CheckedOAuthClient::new().unwrap();
        let request = checked
            .follow
            .post(&url)
            .body("grant_type=refresh_token&refresh_token=rt-secret")
            .build()
            .unwrap();
        let (outcome, refusal) = capture_refusal(checked.execute_request(
            request,
            OAuthHttpRedirectPolicy::Follow,
            Some(Duration::from_secs(2)),
        ))
        .await;
        let error = outcome.unwrap_err().to_string();
        task.abort();
        assert!(error.contains("refusing to send OAuth credentials"), "{error}");
        let refusal = refusal.expect("the refusal reaches the caller past rmcp's opaque error");
        assert_eq!(explain_token_error(&"Request failed", Some(&refusal)), refusal);
        assert_eq!(explain_token_error(&"Request failed", None), "Request failed");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn real_oauth_manager_checks_discovered_registration_recipient() {
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        proxy.set_nonblocking(true).unwrap();
        let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", server.local_addr().unwrap());
        // Discovery for the /mcp issuer must advertise that exact issuer under
        // rmcp 3.x validation, so registration reaches the recipient policy.
        let issuer = format!("{base}/mcp");
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
            bindings: Default::default(),
            resource: String::new(),
        };
        let mut manager = AuthorizationManager::new_with_oauth_http_client(
            format!("{base}/mcp"),
            Arc::new(checked),
        )
        .await
        .unwrap();
        let metadata = crate::oauth::discover_metadata_bounded(&manager)
            .await
            .unwrap();
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

    /// P151 (C1b login_redirect): a token endpoint that redirects the credentials to another origin is refused, and the
    /// refusal is what the caller can show (it was "server returned empty error response"). Nothing reaches the target.
    #[tokio::test]
    async fn a_refused_cross_origin_token_redirect_is_reported_as_a_refusal() {
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
        let source = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source_base = format!("http://{}", source.local_addr().unwrap());
        let location = destination_url.clone();
        let source_task = tokio::spawn(async move {
            axum::serve(
                source,
                Router::new().route(
                    "/token-redir",
                    post(move || {
                        let location = location.clone();
                        async move { (StatusCode::TEMPORARY_REDIRECT, [("location", location)], "redirect") }
                    }),
                ),
            )
            .await
            .unwrap();
        });
        let checked = CheckedOAuthClient::new().unwrap();
        // Metadata from the source's own origin names the redirecting endpoint, so the recipient check admits it.
        let served = reqwest::Url::parse(&format!("{source_base}/.well-known/oauth-authorization-server")).unwrap();
        checked.learn_token_endpoint(
            &served,
            format!(r#"{{"issuer":"{source_base}","authorization_endpoint":"{source_base}/authorize","token_endpoint":"{source_base}/token-redir"}}"#)
                .as_bytes(),
        );
        let request = checked
            .follow
            .post(format!("{source_base}/token-redir"))
            .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("grant_type=refresh_token&refresh_token=p151-SYNRT")
            .build()
            .unwrap();
        let (result, refusal) = capture_refusal(checked.execute_request(
            request,
            OAuthHttpRedirectPolicy::Follow,
            Some(Duration::from_secs(5)),
        ))
        .await;
        // rmcp sends token requests with the Stop policy (C1b live): the 307 then comes back as a response, which
        // rmcp reported as "server returned empty error response". It must be a refusal with a reason too.
        // A redirect now refuses that endpoint for good (K7), so the stop-policy path needs a client of its own.
        let checked_stop = CheckedOAuthClient::new().unwrap();
        checked_stop.learn_token_endpoint(
            &served,
            format!(r#"{{"issuer":"{source_base}","authorization_endpoint":"{source_base}/authorize","token_endpoint":"{source_base}/token-redir"}}"#)
                .as_bytes(),
        );
        let stop_request = checked_stop
            .stop
            .post(format!("{source_base}/token-redir"))
            .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("grant_type=authorization_code&code=p151-SYNCODE")
            .build()
            .unwrap();
        let (stop_result, stop_refusal) = capture_refusal(checked_stop.execute_request(
            stop_request,
            OAuthHttpRedirectPolicy::Stop,
            Some(Duration::from_secs(5)),
        ))
        .await;
        assert!(stop_result.is_err(), "a redirected token request is a failure, not a response to parse");
        let stop_refusal = stop_refusal.expect("the stopped redirect must be recorded as a refusal");
        assert!(stop_refusal.contains("redirect") && stop_refusal.contains("another origin"), "{stop_refusal}");
        assert!(!stop_refusal.contains("p151-SYNCODE"), "{stop_refusal}");
        source_task.abort();
        destination_task.abort();
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing may reach the other origin");
        let refusal = refusal.expect("the redirect refusal must be recorded for the caller to show");
        assert!(refusal.contains("redirect"), "{refusal}");
        assert!(refusal.contains("another origin"), "{refusal}");
        assert!(!refusal.contains("p151-SYNRT"), "the refusal must not carry the credential: {refusal}");
    }

    /// A same-origin redirecting token endpoint with a stop-policy client, counting the POSTs that reach it.
    async fn redirecting_token_endpoint() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let posts = Arc::new(AtomicUsize::new(0));
        let sink = posts.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let location = format!("{base}/token-moved");
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/token-redir",
                    post(move || {
                        let sink = sink.clone();
                        let location = location.clone();
                        async move {
                            sink.fetch_add(1, Ordering::SeqCst);
                            (StatusCode::TEMPORARY_REDIRECT, [("location", location)], "redirect")
                        }
                    }),
                ),
            )
            .await
            .unwrap();
        });
        (base, posts, task)
    }

    fn admit_token_endpoint(checked: &CheckedOAuthClient, base: &str, path: &str) {
        let served = reqwest::Url::parse(&format!("{base}/.well-known/oauth-authorization-server")).unwrap();
        checked.learn_token_endpoint(
            &served,
            format!(r#"{{"issuer":"{base}","authorization_endpoint":"{base}/authorize","token_endpoint":"{base}{path}"}}"#)
                .as_bytes(),
        );
    }

    /// K7: rmcp refreshes on every 401 and every handshake retry. A token endpoint that redirects the refresh to
    /// another address of its own origin used to receive the refresh token each time (5 POSTs per session in the RC
    /// retest). After the first refusal the endpoint is refused for good, so nothing is sent again.
    #[tokio::test]
    async fn p193_a_redirecting_token_endpoint_is_posted_to_once_per_manager() {
        let (base, posts, task) = redirecting_token_endpoint().await;
        let checked = CheckedOAuthClient::for_resource(&format!("{base}/mcp")).unwrap();
        admit_token_endpoint(&checked, &base, "/token-redir");
        let mut reasons = Vec::new();
        for attempt in 0..5 {
            let request = checked
                .stop
                .post(format!("{base}/token-redir"))
                .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(format!("grant_type=refresh_token&refresh_token=p193-RT-{attempt}"))
                .build()
                .unwrap();
            let (result, refusal) = capture_refusal(checked.execute_request(
                request,
                OAuthHttpRedirectPolicy::Stop,
                Some(Duration::from_secs(5)),
            ))
            .await;
            assert!(result.is_err(), "attempt {attempt} must be refused");
            reasons.push(refusal.expect("every attempt carries its reason"));
        }
        task.abort();
        assert_eq!(posts.load(Ordering::SeqCst), 1, "only the first attempt may reach the endpoint");
        for reason in &reasons {
            assert!(reason.contains("redirect"), "{reason}");
            assert!(!reason.contains("p193-RT"), "the reason must not carry the credential: {reason}");
        }
    }

    /// K7: the reason for a refused automatic refresh is kept per MCP server URL for `/mcps`, and a request that gets
    /// through clears it, so a recovered server stops showing a stale refusal.
    #[tokio::test]
    async fn p193_a_refused_refresh_is_remembered_for_the_server_until_a_request_succeeds() {
        let (base, _posts, task) = redirecting_token_endpoint().await;
        let ok_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ok_base = format!("http://{}", ok_listener.local_addr().unwrap());
        let ok_task = tokio::spawn(async move {
            axum::serve(
                ok_listener,
                Router::new().route(
                    "/token",
                    post(|| async { axum::Json(serde_json::json!({"access_token": "t", "token_type": "Bearer"})) }),
                ),
            )
            .await
            .unwrap();
        });
        let refused_url = format!("{base}/p193-remembered/mcp");
        let ok_url = format!("{ok_base}/p193-remembered/mcp");
        assert_eq!(auth_refusal_for_url(&refused_url), None);

        let checked = CheckedOAuthClient::for_resource(&refused_url).unwrap();
        admit_token_endpoint(&checked, &base, "/token-redir");
        let request = checked
            .stop
            .post(format!("{base}/token-redir"))
            .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("grant_type=refresh_token&refresh_token=p193-RT")
            .build()
            .unwrap();
        let result = checked
            .execute_request(request, OAuthHttpRedirectPolicy::Stop, Some(Duration::from_secs(5)))
            .await;
        assert!(result.is_err());
        let remembered = auth_refusal_for_url(&refused_url).expect("the refusal is remembered for the server");
        assert!(remembered.contains("redirect"), "{remembered}");
        assert!(!remembered.contains("p193-RT"), "{remembered}");
        assert_eq!(auth_refusal_for_url(&ok_url), None, "another server is unaffected");

        // A later credential-bearing request that succeeds clears what was remembered for that server.
        let healthy = CheckedOAuthClient::for_resource(&ok_url).unwrap();
        remember_refusal(&ok_url, "refusing to send OAuth credentials: stale");
        admit_token_endpoint(&healthy, &ok_base, "/token");
        let request = healthy
            .stop
            .post(format!("{ok_base}/token"))
            .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("grant_type=refresh_token&refresh_token=p193-RT2")
            .build()
            .unwrap();
        healthy
            .execute_request(request, OAuthHttpRedirectPolicy::Stop, Some(Duration::from_secs(5)))
            .await
            .expect("the healthy endpoint answers");
        task.abort();
        ok_task.abort();
        assert_eq!(auth_refusal_for_url(&ok_url), None, "a success clears the remembered refusal");
    }
}
