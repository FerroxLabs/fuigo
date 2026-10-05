use super::*;
use fuigo_extra_ca::subscription::{Recipient, SubscriptionClient};
use std::ffi::OsString;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub(super) struct TokenClient {
    provider: SubscriptionProvider,
    client: SubscriptionClient,
    #[cfg(test)]
    endpoint: Option<String>,
    /// Test-only stand-in for the process-wide CA bundle selection, which is read once per
    /// process and may be set by any other test in the binary.
    #[cfg(test)]
    ca_bundle: Option<Option<(&'static str, OsString)>>,
}
impl TokenClient {
    pub(super) fn new(provider: SubscriptionProvider) -> Result<Self> {
        let recipient = match provider {
            SubscriptionProvider::Chatgpt => Recipient::ChatGptAuth,
            SubscriptionProvider::Xai => Recipient::XaiAuth,
        };
        Ok(Self {
            provider,
            client: subscription_client(recipient)?,
            #[cfg(test)]
            endpoint: None,
            #[cfg(test)]
            ca_bundle: None,
        })
    }
    #[cfg(test)]
    pub(super) fn with_ca_bundle(mut self, bundle: Option<(&'static str, OsString)>) -> Self {
        self.ca_bundle = Some(bundle);
        self
    }
    fn ca_bundle(&self) -> Option<(&'static str, OsString)> {
        #[cfg(test)]
        if let Some(bundle) = &self.ca_bundle {
            return bundle.clone();
        }
        configured_ca_bundle()
    }
    #[cfg(test)]
    pub(super) fn local(provider: SubscriptionProvider, endpoint: String) -> Self {
        assert!(url::Url::parse(&endpoint).unwrap().host_str() == Some("127.0.0.1"));
        Self {
            endpoint: Some(endpoint),
            ..Self::new(provider).unwrap()
        }
    }
    async fn post(&self, form: &[(&str, &str)]) -> Result<serde_json::Value> {
        tokio::time::timeout(Duration::from_secs(25), async {
            #[cfg(test)]
            if let Some(endpoint) = &self.endpoint {
                use fuigo_extra_ca::dispatch::AsyncRequestBuilderExt;
                let client = or_local_tls(
                    fuigo_extra_ca::build_reqwest_client(|b| {
                        b.redirect(reqwest::redirect::Policy::none())
                    }),
                    self.ca_bundle(),
                )?;
                let response = client
                    .post(endpoint)
                    .form(form)
                    .send_checked()
                    .await
                    .map_err(|error| exchange_send_error(&error, self.ca_bundle()))?;
                return read_response(response).await;
            }
            let request = self
                .client
                .request(reqwest::Method::POST, self.provider.token_url())
                .header("originator", "fuigo")
                .form(form)
                .build()
                .map_err(|_| SubscriptionError::Network)?;
            let response = self
                .client
                .execute(request)
                .await
                .map_err(|error| exchange_send_error(&error, self.ca_bundle()))?;
            read_response(response).await
        })
        .await
        // The deadline can elapse after the provider received the request, so this is
        // ambiguous, not a send failure.
        .map_err(|_| SubscriptionError::AmbiguousExchange)?
    }
    async fn exchange(&self, code: &str, verifier: &str, redirect: &str) -> Result<Credential> {
        let body = self
            .post(&[
                ("grant_type", "authorization_code"),
                ("client_id", self.provider.client_id()),
                ("code", code),
                ("code_verifier", verifier),
                ("redirect_uri", redirect),
            ])
            .await?;
        parse_credential(self.provider, body)
    }
    pub(super) async fn refresh(&self, refresh: &str) -> Result<Credential> {
        let mut form = vec![
            ("grant_type", "refresh_token"),
            ("client_id", self.provider.client_id()),
            ("refresh_token", refresh),
        ];
        if self.provider == SubscriptionProvider::Xai {
            form.push(("scope", self.provider.scope()));
        }
        parse_credential(self.provider, self.post(&form).await?)
    }
}
/// The subscription HTTPS client. Building it touches nothing but local TLS state (crypto
/// provider, OS roots, the opt-in extra CA bundle), so its failure is a local configuration
/// fault: reporting it as a network error would invite endless retries of something only
/// the user can fix.
pub(super) fn subscription_client(recipient: Recipient) -> Result<SubscriptionClient> {
    or_local_tls(SubscriptionClient::new(recipient), configured_ca_bundle())
}
/// A send failure. A TLS handshake that rejected the provider's certificate while an extra
/// CA bundle is configured is the usual face of a broken bundle: the loader skips an
/// unreadable or certificate-free file (logging it), so the client builds and the failure
/// only shows up here. That is a local configuration fault, reported as such with the file
/// named. With no bundle configured a rejected certificate stays `Network`: telling the
/// user to trust a different CA could be advice to trust an interceptor. Either way the
/// handshake failed before any request bytes were sent.
pub(super) fn transport_error(
    error: &(dyn std::error::Error + 'static),
    bundle: Option<(&str, OsString)>,
) -> SubscriptionError {
    match bundle {
        Some(bundle) if certificate_rejected(error) => local_tls(
            Some(bundle),
            "the provider's TLS certificate did not verify",
        ),
        _ => SubscriptionError::Network,
    }
}
/// A token-exchange send failure. Only a failure before the request left this host (egress
/// denial, DNS, TCP connect, TLS handshake) proves the provider issued nothing. Any other
/// transport failure (the connection dropped after the request was written, before the
/// response headers arrived) may follow a rotation the provider already performed, so it is
/// ambiguous and the refresh latch must hold.
pub(super) fn exchange_send_error(
    error: &fuigo_extra_ca::dispatch::DispatchError,
    bundle: Option<(&str, OsString)>,
) -> SubscriptionError {
    use fuigo_extra_ca::dispatch::DispatchError;
    let never_sent = error.is_connect() || matches!(error, DispatchError::Denied(_));
    match transport_error(error, bundle) {
        SubscriptionError::Network if !never_sent => SubscriptionError::AmbiguousExchange,
        other => other,
    }
}
/// Whether a rustls certificate-verification failure is anywhere in the error chain.
/// `io::Error::source` skips the error it wraps, so wrapped errors are opened explicitly.
fn certificate_rejected(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut pending = vec![error];
    let mut seen = 0;
    while let Some(error) = pending.pop() {
        seen += 1;
        if seen > 64 {
            return false;
        }
        if let Some(rustls::Error::InvalidCertificate(_)) = error.downcast_ref::<rustls::Error>() {
            return true;
        }
        if let Some(inner) = error
            .downcast_ref::<std::io::Error>()
            .and_then(|io| io.get_ref())
        {
            pending.push(inner);
        }
        if let Some(source) = error.source() {
            pending.push(source);
        }
    }
    false
}
/// The CA bundle variable fuigo-extra-ca selected, and the path it names.
pub(super) fn configured_ca_bundle() -> Option<(&'static str, OsString)> {
    let variable = fuigo_extra_ca::configured_bundle_env()?;
    Some((variable, std::env::var_os(variable).unwrap_or_default()))
}
/// Maps a client-construction failure to [`SubscriptionError::LocalTls`], naming the file.
pub(super) fn or_local_tls<T, E>(
    built: std::result::Result<T, E>,
    bundle: Option<(&str, OsString)>,
) -> Result<T> {
    built.map_err(|_| local_tls(bundle, "the HTTPS client could not be built"))
}
fn local_tls(bundle: Option<(&str, OsString)>, what: &str) -> SubscriptionError {
    // `{:?}` quotes and escapes the path so it cannot inject terminal controls.
    let detail = match bundle {
        Some((variable, path)) => format!(
            "{what}; check the CA bundle file {:?} set by {variable}",
            Path::new(&path)
        ),
        None => format!("{what}; no extra CA bundle is configured; check the system trust store"),
    };
    tracing::warn!(%detail, "subscription local TLS/CA configuration error");
    SubscriptionError::LocalTls(detail)
}
/// Token-exchange responses only. The success status is already in hand here, so the one
/// `Network` this can produce is a body read that failed *after* the provider answered:
/// a rotated single-use refresh token is then gone along with the reply we lost. Report
/// that as ambiguous so the refresh path latches instead of treating it as a send failure.
pub(super) async fn read_response(response: reqwest::Response) -> Result<serde_json::Value> {
    read_json_response(response, 65536)
        .await
        .map_err(|error| match error {
            SubscriptionError::Network => SubscriptionError::AmbiguousExchange,
            other => other,
        })
}
pub(super) async fn read_json_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<serde_json::Value> {
    if !response.status().is_success() {
        return Err(SubscriptionError::Http(response.status().as_u16()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| SubscriptionError::Network)?
    {
        if body.len() + chunk.len() > max_bytes {
            return Err(SubscriptionError::InvalidCredentials);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| SubscriptionError::InvalidCredentials)
}
fn parse_credential(provider: SubscriptionProvider, body: serde_json::Value) -> Result<Credential> {
    let access = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or(SubscriptionError::InvalidCredentials)?;
    if !body
        .get("token_type")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("bearer"))
    {
        return Err(SubscriptionError::InvalidCredentials);
    }
    // Claims are metadata from the pinned TLS token response, never a local JWT authentication bypass.
    let access_claims = claims(access);
    let id_claims = body
        .get("id_token")
        .and_then(|v| v.as_str())
        .and_then(claims);
    for claim in [&access_claims, &id_claims].into_iter().flatten() {
        if let Some(issuer) = claim.get("iss").and_then(|v| v.as_str()) {
            if issuer.trim_end_matches('/') != provider.issuer() {
                return Err(SubscriptionError::InvalidCredentials);
            }
        }
    }
    let get_account = |claim: &serde_json::Value| -> Option<String> {
        let value = match provider {
            SubscriptionProvider::Chatgpt => claim
                .get("https://api.openai.com/auth")?
                .get("chatgpt_account_id"),
            SubscriptionProvider::Xai => claim.get("principal_id").or_else(|| claim.get("sub")),
        };
        value?.as_str().filter(|s| !s.is_empty()).map(str::to_owned)
    };
    let access_account = access_claims.as_ref().and_then(get_account);
    let id_account = id_claims.as_ref().and_then(get_account);
    if access_account.is_some() && id_account.is_some() && access_account != id_account {
        return Err(SubscriptionError::InvalidCredentials);
    }
    let account = access_account
        .or(id_account)
        .ok_or(SubscriptionError::InvalidCredentials)?;
    let relative_expiry = body
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .and_then(|n| now().checked_add(n));
    let jwt_expiry = access_claims
        .as_ref()
        .and_then(|v| v.get("exp"))
        .and_then(|v| v.as_u64());
    let expires_at = match (relative_expiry, jwt_expiry) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) | (None, Some(a)) => a,
        _ => return Err(SubscriptionError::InvalidCredentials),
    };
    let record = Credential {
        provider,
        issuer: provider.issuer().into(),
        client_id: provider.client_id().into(),
        account,
        access_token: access.into(),
        refresh_token: body
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        expires_at,
        refresh_pending: false,
    };
    record.access()?;
    Ok(record)
}

/// The loopback callback listener. Under test it reports its own drop, so a test can prove
/// the socket was released without re-binding the port, which races every other test on
/// the host for ephemeral ports.
struct CallbackListener {
    inner: TcpListener,
    ipv6: Option<TcpListener>,
    #[cfg(test)]
    dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Callback connections read at once. Each is bounded by [`CALLBACK_READ_TIMEOUT`], so a
/// connection that never sends a request line holds one slot for at most that long and
/// never blocks the real callback; past this many, new connections wait in the kernel
/// backlog until a slot frees. Ignored requests are never counted: only the attempt's
/// overall deadline ends a login that is never completed.
const MAX_PENDING_CALLBACKS: usize = 32;
const CALLBACK_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// `EAFNOSUPPORT`: the host has no IPv6 at all (kernel booted without it, some containers).
#[cfg(unix)]
pub(super) const EAFNOSUPPORT: i32 = libc::EAFNOSUPPORT;
#[cfg(windows)]
pub(super) const EAFNOSUPPORT: i32 = 10047; // WSAEAFNOSUPPORT
#[cfg(not(any(unix, windows)))]
pub(super) const EAFNOSUPPORT: i32 = i32::MIN;

/// Whether an IPv6 loopback bind failed because the host has no IPv6 loopback, as opposed
/// to someone else holding the address. Only these let ChatGPT sign-in continue on IPv4
/// alone: with no `[::1]` on the host, nothing can listen there and receive the redirect.
pub(super) fn ipv6_loopback_unavailable(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::AddrNotAvailable
        || error.raw_os_error() == Some(EAFNOSUPPORT)
}

fn listener_error(address: std::net::SocketAddr, error: &std::io::Error) -> SubscriptionError {
    fuigo_tty_utils::cli_eprintln!(
        "Cannot bind subscription callback listener at {address}: {error}. Release this address before signing in."
    );
    SubscriptionError::Listener
}

/// Binds the callback listeners: `127.0.0.1:port`, and for ChatGPT (whose registered
/// redirect host is `localhost`, which a browser may resolve to `::1` first) `[::1]` on the
/// same port, so no other local process can take the IPv6 side of the redirect. A host
/// without IPv6 loopback continues on IPv4 alone; any other IPv6 failure (the address is
/// held by someone else, or an unknown error) aborts, as does any IPv4 failure.
/// `bind` is the socket seam: production passes `TcpListener::bind`.
async fn bind_callback_listeners<F, Fut>(
    provider: SubscriptionProvider,
    port: u16,
    bind: F,
) -> Result<(TcpListener, Option<TcpListener>)>
where
    F: Fn(std::net::SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<TcpListener>>,
{
    let ipv4_address: std::net::SocketAddr = (std::net::Ipv4Addr::LOCALHOST, port).into();
    let ipv4 = bind(ipv4_address)
        .await
        .map_err(|error| listener_error(ipv4_address, &error))?;
    if provider != SubscriptionProvider::Chatgpt {
        return Ok((ipv4, None));
    }
    let port = ipv4
        .local_addr()
        .map_err(|_| SubscriptionError::Listener)?
        .port();
    let ipv6_address: std::net::SocketAddr = (std::net::Ipv6Addr::LOCALHOST, port).into();
    match bind(ipv6_address).await {
        Ok(ipv6) => Ok((ipv4, Some(ipv6))),
        Err(error) if ipv6_loopback_unavailable(&error) => {
            tracing::info!(%error, "no IPv6 loopback on this host; subscription callback listens on IPv4 only");
            Ok((ipv4, None))
        }
        Err(error) => Err(listener_error(ipv6_address, &error)),
    }
}

/// What one callback connection amounted to.
enum CallbackRequest {
    /// Not this attempt's callback (wrong, missing or duplicate state, another path, a
    /// malformed or unfinished request): answered, if possible, and ignored.
    Ignored,
    /// This attempt's state with the authorization code.
    Code(String),
    /// This attempt's state without a usable code (for example the user declined): final.
    Rejected,
}

/// The target of a well-formed `GET <origin-form target> HTTP/1.x` request head (CRLF line
/// endings, every header line `name: value`). `None` for anything else, so a malformed request
/// is ignored even when it carries this attempt's state.
fn parse_request_target(head: &str) -> Option<&str> {
    let head = head.strip_suffix("\r\n\r\n")?;
    let mut lines = head.split("\r\n");
    let mut parts = lines.next()?.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    let well_formed = parts.next().is_none()
        && method == "GET"
        && (version == "HTTP/1.1" || version == "HTTP/1.0")
        && target.starts_with('/')
        && !target.starts_with("//")
        // RFC 9112 3.2.1 origin-form is path and optional query only, so no fragment ('#').
        // Rejects exactly what a browser always percent-encodes in a path or query (WHATWG URL:
        // controls, space, non-ASCII, '"', '#', '<', '>'), so a real callback is never refused
        // for a character a browser legitimately leaves raw (such as '|' or '{').
        && target
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"\"#<>".contains(&b));
    // RFC 9110 5.1 / 5.5: a field name is a token; a field value has no control character
    // other than horizontal tab.
    let token = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
    let headers_ok = lines.all(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            !name.is_empty()
                && name.bytes().all(token)
                && value.bytes().all(|b| b == b'\t' || !(b.is_ascii_control()))
        })
    });
    (well_formed && headers_ok).then_some(target)
}

/// Reads and answers one callback connection. Never fails: anything that is not this
/// attempt's callback is [`CallbackRequest::Ignored`], so no other page or local process
/// can end the login by sending junk to the port.
async fn read_callback(
    mut stream: tokio::net::TcpStream,
    expected_path: &str,
    state: &str,
) -> CallbackRequest {
    const NOT_FOUND: &[u8] =
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nFuigo rejected this callback.";
    const RECEIVED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nFuigo received authorization. Return to your terminal for the result.";
    let mut bytes = Vec::new();
    let read = tokio::time::timeout(CALLBACK_READ_TIMEOUT, async {
        loop {
            bytes.push(stream.read_u8().await.ok()?);
            if bytes.ends_with(b"\r\n\r\n") {
                return Some(());
            }
            if bytes.len() >= 8192 {
                return None;
            }
        }
    })
    .await;
    if !matches!(read, Ok(Some(()))) {
        // Unfinished (closed early, too long, or too slow): answered, best effort, and ignored.
        let _ = stream.write_all(BAD_REQUEST).await;
        return CallbackRequest::Ignored;
    }
    let target = std::str::from_utf8(&bytes)
        .ok()
        .and_then(parse_request_target)
        .and_then(|target| url::Url::parse(&format!("http://localhost{target}")).ok());
    let Some(url) = target else {
        let _ = stream.write_all(BAD_REQUEST).await;
        return CallbackRequest::Ignored;
    };
    if url.path() != expected_path {
        let _ = stream.write_all(NOT_FOUND).await;
        return CallbackRequest::Ignored;
    }
    let fields: Vec<_> = url.query_pairs().collect();
    let states: Vec<_> = fields.iter().filter(|(k, _)| k == "state").collect();
    let codes: Vec<_> = fields.iter().filter(|(k, _)| k == "code").collect();
    if !(states.len() == 1 && states[0].1 == state) {
        let _ = stream.write_all(BAD_REQUEST).await;
        return CallbackRequest::Ignored;
    }
    if codes.len() == 1 && !codes[0].1.is_empty() && !fields.iter().any(|(k, _)| k == "error") {
        let _ = stream.write_all(RECEIVED).await;
        CallbackRequest::Code(codes[0].1.to_string())
    } else {
        let _ = stream.write_all(BAD_REQUEST).await;
        CallbackRequest::Rejected
    }
}
#[cfg(test)]
impl Drop for CallbackListener {
    fn drop(&mut self) {
        // `inner` is closed by the drop glue immediately after this, in the same call.
        self.dropped
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Owns the listener and one attempt's PKCE material. Dropping cancels the listener.
/// No spawned callback task, external session imports, or secret Debug output.
pub struct LoginAttempt {
    provider: SubscriptionProvider,
    listener: CallbackListener,
    redirect: String,
    state: String,
    verifier: String,
    authorize: String,
    client: TokenClient,
}
impl LoginAttempt {
    pub async fn start(provider: SubscriptionProvider) -> Result<Self> {
        let port = if provider == SubscriptionProvider::Chatgpt {
            1455
        } else {
            0
        };
        Self::bind(provider, port).await
    }
    pub(super) async fn bind(provider: SubscriptionProvider, port: u16) -> Result<Self> {
        Self::bind_with(provider, port, TcpListener::bind).await
    }
    pub(super) async fn bind_with<F, Fut>(
        provider: SubscriptionProvider,
        port: u16,
        bind: F,
    ) -> Result<Self>
    where
        F: Fn(std::net::SocketAddr) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<TcpListener>>,
    {
        let (listener, ipv6) = bind_callback_listeners(provider, port, bind).await?;
        let port = listener
            .local_addr()
            .map_err(|_| SubscriptionError::Listener)?
            .port();
        let (host, path) = match provider {
            SubscriptionProvider::Chatgpt => ("localhost", "/auth/callback"),
            SubscriptionProvider::Xai => ("127.0.0.1", "/callback"),
        };
        let redirect = format!("http://{host}:{port}{path}");
        let pkce = crate::auth::oidc::protocol::generate_pkce();
        let state = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let mut authorize =
            url::Url::parse(provider.authorize_url()).map_err(|_| SubscriptionError::Callback)?;
        authorize.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", provider.client_id()),
            ("scope", provider.scope()),
            ("redirect_uri", &redirect),
            ("code_challenge", &pkce.code_challenge),
            ("code_challenge_method", "S256"),
            ("state", &state),
        ]);
        if provider == SubscriptionProvider::Chatgpt {
            authorize.query_pairs_mut().extend_pairs([
                ("id_token_add_organizations", "true"),
                ("codex_cli_simplified_flow", "true"),
                ("originator", "fuigo"),
            ]);
        }
        Ok(Self {
            provider,
            listener: CallbackListener {
                inner: listener,
                ipv6,
                #[cfg(test)]
                dropped: Default::default(),
            },
            redirect,
            state,
            verifier: pkce.code_verifier,
            authorize: authorize.into(),
            client: TokenClient::new(provider)?,
        })
    }
    /// Whether this attempt also listens on `[::1]`.
    #[cfg(test)]
    pub(super) fn listens_on_ipv6(&self) -> bool {
        self.listener.ipv6.is_some()
    }
    /// Becomes `true` once this attempt's callback listener has been dropped.
    #[cfg(test)]
    pub(super) fn listener_drop_probe(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.listener.dropped.clone()
    }
    #[cfg(test)]
    pub(super) fn with_endpoint(mut self, endpoint: String) -> Self {
        self.client = TokenClient::local(self.provider, endpoint);
        self
    }
    pub fn authorization_url(&self) -> &str {
        &self.authorize
    }
    pub async fn finish(self, store: &SubscriptionStore, cancel: CancellationToken) -> Result<()> {
        self.finish_with_timeout(store, cancel, Duration::from_secs(600))
            .await
    }
    pub(super) async fn finish_with_timeout(
        self,
        store: &SubscriptionStore,
        cancel: CancellationToken,
        duration: Duration,
    ) -> Result<()> {
        self.finish_with_code_input(store, cancel, duration, std::future::pending())
            .await
    }
    pub(super) async fn finish_with_code_input(
        self,
        store: &SubscriptionStore,
        cancel: CancellationToken,
        duration: Duration,
        input: impl std::future::Future<Output = Result<String>>,
    ) -> Result<()> {
        let authorization = async {
            tokio::select! {
                callback = self.callback() => callback,
                code = input => code,
            }
        };
        let code = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(SubscriptionError::Cancelled),
            result = tokio::time::timeout(duration, authorization) => result.map_err(|_| SubscriptionError::Timeout)??,
        };
        // Once the exchange begins, complete its bounded exchange/persistence even if the caller cancels.
        let store = store.clone();
        drop(self.listener);
        tokio::spawn(async move {
            let credential = self
                .client
                .exchange(&code, &self.verifier, &self.redirect)
                .await?;
            store.save(credential).await
        })
        .await
        .map_err(|_| SubscriptionError::Network)?
    }
    /// Serves the callback port until this attempt's own callback arrives. Connections are
    /// read concurrently (see [`MAX_PENDING_CALLBACKS`]), so an idle or slow connection
    /// cannot hold up the real one; requests that are not this attempt's callback are
    /// answered and ignored, never fatal. The caller's deadline bounds the whole wait.
    async fn callback(&self) -> Result<String> {
        use futures::StreamExt;
        let expected = url::Url::parse(&self.redirect).map_err(|_| SubscriptionError::Callback)?;
        let expected_path = expected.path();
        let mut pending = futures::stream::FuturesUnordered::new();
        loop {
            let accept = async {
                match &self.listener.ipv6 {
                    Some(ipv6) => tokio::select! {
                        accepted = self.listener.inner.accept() => accepted,
                        accepted = ipv6.accept() => accepted,
                    },
                    None => self.listener.inner.accept().await,
                }
            };
            tokio::select! {
                accepted = accept, if pending.len() < MAX_PENDING_CALLBACKS => match accepted {
                    Ok((stream, _)) => pending.push(read_callback(stream, expected_path, &self.state)),
                    // A peer that connected and reset before the accept is its own failure,
                    // not the listener's; any peer could otherwise end the login this way.
                    Err(error) if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                    Err(_) => return Err(SubscriptionError::Listener),
                },
                Some(request) = pending.next() => match request {
                    CallbackRequest::Ignored => {}
                    CallbackRequest::Code(code) => return Ok(code),
                    CallbackRequest::Rejected => return Err(SubscriptionError::Callback),
                },
            }
        }
    }
}

pub async fn cli_login(provider: SubscriptionProvider) -> Result<()> {
    let store = default_store()?;
    let attempt = LoginAttempt::start(provider).await?;
    fuigo_tty_utils::cli_eprintln!(
        "Sign in to {} for Fuigo. Credentials will be stored only by Fuigo.\n{}",
        provider.name(),
        attempt.authorization_url()
    );
    if webbrowser::open(attempt.authorization_url()).is_err() {
        fuigo_tty_utils::cli_eprintln!("Open the URL above in your browser.");
    }
    let cancel = CancellationToken::new();
    let finish = attempt.finish_with_code_input(
        &store,
        cancel.clone(),
        Duration::from_secs(600),
        super::manual::code(provider),
    );
    tokio::pin!(finish);
    tokio::select! {
        result = &mut finish => result?,
        _ = tokio::signal::ctrl_c() => { cancel.cancel(); finish.await?; },
    }
    fuigo_tty_utils::cli_eprintln!("{} subscription login saved by Fuigo.", provider.name());
    Ok(())
}
