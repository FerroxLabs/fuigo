//! Exact-recipient capability for explicitly selected subscription providers.
//!
//! Three properties keep a subscription bearer on its provider's own endpoint:
//! - [`SubscriptionClient::execute`] refuses any URL but the recipient's exact
//!   https endpoints (no userinfo, fragment or other port; no query except
//!   the single validated `client_version` on the ChatGPT model catalog);
//! - redirects are never followed, so a provider response cannot move the
//!   request (and its `Authorization` header or token form) anywhere else;
//! - the egress guard ([`crate::egress`]) is installed like on every other
//!   client, with ONE exact-host exception: the recipient's own host. For the
//!   xAI subscription that admits `auth.x.ai` (token client) or `api.x.ai`
//!   (inference client) and refuses every other blocked name, telemetry hosts
//!   included. `FUIGO_ALLOW_UPSTREAM_HOSTS` is not needed for subscriptions.
//!
//! Requests are built with [`SubscriptionClient::request`], whose builder has
//! no `send`: the only dispatch is `execute`, after the recipient check.
use crate::dispatch::DispatchError;
use reqwest::{Client, ClientBuilder, Method, Request, RequestBuilder, Response, Url};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    ChatGptAuth,
    ChatGptInference,
    XaiAuth,
    XaiInference,
}

impl Recipient {
    /// The one host this recipient's endpoints live on, and the one blocked
    /// name its client's egress guard admits.
    fn host(self) -> &'static str {
        match self {
            Self::ChatGptAuth => "auth.openai.com",
            Self::ChatGptInference => "chatgpt.com",
            Self::XaiAuth => "auth.x.ai",
            Self::XaiInference => "api.x.ai",
        }
    }

    fn accepts(self, url: &Url) -> bool {
        if url.scheme() != "https"
            || url.port_or_known_default() != Some(443)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return false;
        }
        let paths: &[&str] = match self {
            Self::ChatGptAuth => &["/oauth/token"],
            Self::ChatGptInference => {
                &["/backend-api/codex/responses", "/backend-api/codex/models"]
            }
            Self::XaiAuth => &["/oauth2/token"],
            Self::XaiInference => &["/v1/responses", "/v1/chat/completions", "/v1/models"],
        };
        if url.host_str() != Some(self.host()) || !paths.contains(&url.path()) {
            return false;
        }
        if self == Self::ChatGptInference && url.path() == "/backend-api/codex/models" {
            let params: Vec<_> = url.query_pairs().collect();
            return params.len() == 1
                && params[0].0 == "client_version"
                && !params[0].1.is_empty()
                && params[0].1.len() <= 64
                && params[0]
                    .1
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-_+".contains(&c));
        }
        url.query().is_none()
    }
}

/// The raw client is private and never handed out: [`Self::request`] returns a
/// [`SubscriptionRequestBuilder`], which cannot dispatch, so every request reaches
/// the wire through [`Self::execute`] and its recipient check.
#[derive(Clone)]
pub struct SubscriptionClient {
    client: Client,
    recipient: Recipient,
}

impl SubscriptionClient {
    pub fn new(recipient: Recipient) -> reqwest::Result<Self> {
        Self::build(recipient, |builder| builder)
    }

    /// The production construction. `extend` is the identity outside this
    /// module's tests, where it only adds loopback routes and a test root; it
    /// runs last, so the policy below is exactly what the tests exercise.
    #[allow(clippy::disallowed_methods)] // Approved scoped TLS/egress boundary.
    fn build(
        recipient: Recipient,
        extend: impl FnOnce(ClientBuilder) -> ClientBuilder,
    ) -> reqwest::Result<Self> {
        crate::ensure_default_crypto_provider();
        let mut builder = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(20))
            .user_agent("Fuigo/subscription")
            .use_rustls_tls()
            .tls_built_in_native_certs(false)
            .tls_built_in_webpki_certs(true)
            .dns_resolver(crate::egress::resolver_allowing_exactly(recipient.host()));
        for cert in crate::shared_reqwest_roots() {
            builder = builder.add_root_certificate(cert);
        }
        Ok(Self {
            client: extend(builder).build()?,
            recipient,
        })
    }

    /// reqwest moves URL userinfo into an `Authorization: Basic` header before
    /// `execute` could see it, so a URL carrying userinfo is refused here instead.
    pub fn request(&self, method: Method, url: &str) -> SubscriptionRequestBuilder {
        let userinfo =
            Url::parse(url).is_ok_and(|url| !url.username().is_empty() || url.password().is_some());
        SubscriptionRequestBuilder {
            inner: self.client.request(method, url),
            userinfo,
        }
    }

    #[allow(clippy::disallowed_methods)] // Exact URL check before proxy/DNS dispatch; redirects disabled.
    pub async fn execute(&self, request: Request) -> Result<Response, DispatchError> {
        if !self.recipient.accepts(request.url()) {
            return Err(DispatchError::Denied("subscription recipient rejected"));
        }
        self.client
            .execute(request)
            .await
            .map_err(|e| DispatchError::Transport(e.without_url()))
    }
}

/// A subscription request under construction. Deliberately has no `send`: the
/// inner reqwest builder holds the raw client, and it never leaves this type.
/// Finish with [`Self::build`] and dispatch with [`SubscriptionClient::execute`].
#[derive(Debug)]
#[must_use = "build() the request and pass it to SubscriptionClient::execute"]
pub struct SubscriptionRequestBuilder {
    inner: RequestBuilder,
    /// The URL given to `request` carried userinfo; `build` refuses it.
    userinfo: bool,
}

impl SubscriptionRequestBuilder {
    pub fn header(self, name: &str, value: &str) -> Self {
        Self {
            inner: self.inner.header(name, value),
            ..self
        }
    }

    pub fn bearer_auth(self, token: &str) -> Self {
        Self {
            inner: self.inner.bearer_auth(token),
            ..self
        }
    }

    pub fn query(self, pairs: &[(&str, &str)]) -> Self {
        Self {
            inner: self.inner.query(pairs),
            ..self
        }
    }

    pub fn form(self, pairs: &[(&str, &str)]) -> Self {
        Self {
            inner: self.inner.form(pairs),
            ..self
        }
    }

    pub fn build(self) -> Result<Request, DispatchError> {
        if self.userinfo {
            return Err(DispatchError::Denied("subscription recipient rejected"));
        }
        self.inner.build().map_err(DispatchError::Transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subscription_catalog_allows_only_required_client_version() {
        let recipient = Recipient::ChatGptInference;
        assert!(
            recipient.accepts(
                &Url::parse("https://chatgpt.com/backend-api/codex/models?client_version=1.0.5")
                    .unwrap()
            )
        );
        for url in [
            "https://chatgpt.com/backend-api/codex/models",
            "https://chatgpt.com/backend-api/codex/models?client_version=",
            "https://chatgpt.com/backend-api/codex/models?client_version=1.0.5&redirect_uri=https://evil.test",
            "https://chatgpt.com/backend-api/codex/models?client_version=1.0.5&client_version=2.0.0",
            "https://chatgpt.com/backend-api/codex/responses?client_version=1.0.5",
            "https://chatgpt.com.evil.test/backend-api/codex/models?client_version=1.0.5",
        ] {
            assert!(!recipient.accepts(&Url::parse(url).unwrap()), "{url}");
        }
    }
    #[test]
    fn subscription_recipients_are_exact() {
        for (recipient, allowed) in [
            (
                Recipient::ChatGptAuth,
                "https://auth.openai.com/oauth/token",
            ),
            (
                Recipient::ChatGptInference,
                "https://chatgpt.com/backend-api/codex/responses",
            ),
            (Recipient::XaiAuth, "https://auth.x.ai/oauth2/token"),
            (Recipient::XaiInference, "https://api.x.ai/v1/responses"),
        ] {
            assert!(recipient.accepts(&Url::parse(allowed).unwrap()));
            for denied in [
                allowed.replace("https:", "http:"),
                format!("{allowed}?leak=1"),
                format!("{allowed}#fragment"),
                allowed.replace("https://", "https://user@"),
                allowed
                    .replace(".com/", ".com.evil.test/")
                    .replace(".ai/", ".ai.evil.test/"),
                "https://api.fluxrouter.ai/v1/responses".into(),
                "https://api.x.ai/v1/files".into(),
            ] {
                assert!(
                    !recipient.accepts(&Url::parse(&denied).unwrap()),
                    "{denied}"
                );
            }
        }
        assert!(crate::egress::is_blocked_host("api.x.ai"));
    }

    /// The guard is INSTALLED on the production client (P87, audit F1): a blocked
    /// name other than the recipient's own host is refused at resolution, before any
    /// socket opens. The raw client is used on purpose: it is the only way to put such
    /// a name in front of the resolver, since `execute` refuses it earlier.
    #[tokio::test]
    async fn production_client_carries_the_egress_guard_with_only_its_own_host_exempt() {
        assert!(
            crate::egress::guard_enabled(),
            "FUIGO_ALLOW_UPSTREAM_HOSTS lifts the guard this test pins; unset it"
        );
        for (recipient, refused) in [
            (Recipient::XaiAuth, "https://api.mixpanel.com/track"),
            (Recipient::XaiAuth, "https://api.x.ai/v1/models"),
            (
                Recipient::XaiAuth,
                "https://cli-chat-proxy.grok.com/v1/settings",
            ),
            (Recipient::XaiInference, "https://auth.x.ai/oauth2/token"),
            (Recipient::ChatGptAuth, "https://auth.x.ai/oauth2/token"),
            (
                Recipient::ChatGptInference,
                "https://api.mixpanel.com/track",
            ),
        ] {
            // no_proxy: an environment proxy would take the name away from the resolver.
            let client = SubscriptionClient::build(recipient, |b| b.no_proxy()).unwrap();
            let request = Request::new(Method::GET, Url::parse(refused).unwrap());
            #[allow(clippy::disallowed_methods)] // deliberately below execute's recipient check
            let error = client.client.execute(request).await.expect_err(refused);
            assert!(
                format!("{error:?}").contains("refuses to contact upstream vendor host"),
                "{recipient:?} -> {refused}: expected the egress guard's refusal, got {error:?}"
            );
        }
        // The exemption is exactly the recipient's host (the name `accepts` binds to).
        for recipient in [Recipient::XaiAuth, Recipient::XaiInference] {
            assert!(crate::egress::is_blocked_host(recipient.host()));
        }
    }

    /// The exception is wired to the recipient (Astra r1): the PRODUCTION client for each
    /// recipient gets past the guard for exactly its own host. The test hook stops the
    /// lookup at the guard, so nothing is resolved or contacted. Kills a constructor that
    /// installs the plain guard (xAI subscriptions refused) or no guard at all.
    #[tokio::test(flavor = "current_thread")]
    async fn production_client_guard_admits_its_own_host() {
        assert!(
            crate::egress::guard_enabled(),
            "FUIGO_ALLOW_UPSTREAM_HOSTS lifts the guard this test pins; unset it"
        );
        for (recipient, url) in [
            (Recipient::XaiAuth, "https://auth.x.ai/oauth2/token"),
            (Recipient::XaiInference, "https://api.x.ai/v1/responses"),
            (
                Recipient::ChatGptAuth,
                "https://auth.openai.com/oauth/token",
            ),
            (
                Recipient::ChatGptInference,
                "https://chatgpt.com/backend-api/codex/responses",
            ),
        ] {
            // no_proxy: an environment proxy would take the name away from the resolver.
            let client = SubscriptionClient::build(recipient, |b| b.no_proxy()).unwrap();
            let request = client.request(Method::POST, url).build().unwrap();
            crate::egress::test_hook::arm();
            let error = client.execute(request).await.expect_err(url);
            let admitted = crate::egress::test_hook::take();
            let rendered = format!("{error:?}");
            assert!(
                rendered.contains(crate::egress::test_hook::ADMITTED_SENTINEL),
                "{recipient:?}: the guard did not admit its own host: {rendered}"
            );
            assert_eq!(admitted, vec![recipient.host().to_owned()], "{recipient:?}");
        }
    }

    /// Astra r2: userinfo in the URL is refused at build, before reqwest can turn it
    /// into a Basic `Authorization` header that `execute` would no longer see.
    #[test]
    fn userinfo_in_the_request_url_is_refused() {
        let client = SubscriptionClient::new(Recipient::XaiAuth).unwrap();
        for url in [
            "https://alice:secret@auth.x.ai/oauth2/token",
            "https://alice@auth.x.ai/oauth2/token",
        ] {
            let error = client.request(Method::POST, url).build().expect_err(url);
            assert!(
                matches!(
                    error,
                    DispatchError::Denied("subscription recipient rejected")
                ),
                "{url}: {error:?}"
            );
        }
        assert!(
            client
                .request(Method::POST, "https://auth.x.ai/oauth2/token")
                .build()
                .is_ok()
        );
    }

    mod wire {
        //! The PRODUCTION client against loopback TLS servers (P87, audit test gap):
        //! `SubscriptionClient::build` with loopback routes, a test root and `no_proxy`
        //! appended (the routes bypass the resolver; the guard is pinned separately).
        //! These are the tests that kill "redirects on" (M2) and "recipient check off" (M3).
        use super::*;
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        use std::io::{Read, Write};
        use std::net::{SocketAddr, TcpListener};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        const NAMES: [&str; 4] = ["auth.x.ai", "api.x.ai", "auth.openai.com", "evil.test"];

        struct Pki {
            root: reqwest::Certificate,
            server: Arc<rustls::ServerConfig>,
        }

        fn pki() -> Pki {
            let ca_key = KeyPair::generate().unwrap();
            let mut ca = CertificateParams::new(vec![]).unwrap();
            ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let ca = ca.self_signed(&ca_key).unwrap();
            let leaf_key = KeyPair::generate().unwrap();
            let leaf =
                CertificateParams::new(NAMES.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                    .unwrap()
                    .signed_by(&leaf_key, &ca, &ca_key)
                    .unwrap();
            let server = rustls::ServerConfig::builder_with_provider(
                rustls::crypto::aws_lc_rs::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
            )
            .unwrap();
            Pki {
                root: reqwest::Certificate::from_der(ca.der()).unwrap(),
                server: Arc::new(server),
            }
        }

        /// A loopback HTTPS server that counts TCP accepts and records every request
        /// head it receives, answering each with `response` and closing.
        struct Observer {
            addr: SocketAddr,
            accepts: Arc<AtomicUsize>,
            heads: Arc<Mutex<Vec<String>>>,
        }

        impl Observer {
            fn start(config: Arc<rustls::ServerConfig>, response: &'static str) -> Self {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let addr = listener.local_addr().unwrap();
                let accepts = Arc::new(AtomicUsize::new(0));
                let heads = Arc::new(Mutex::new(Vec::new()));
                let (count, seen) = (accepts.clone(), heads.clone());
                std::thread::spawn(move || {
                    for socket in listener.incoming() {
                        let Ok(mut socket) = socket else { return };
                        count.fetch_add(1, Ordering::SeqCst);
                        let (config, seen) = (config.clone(), seen.clone());
                        std::thread::spawn(move || {
                            let _ =
                                socket.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                            let Ok(mut conn) = rustls::ServerConnection::new(config) else {
                                return;
                            };
                            let mut tls = rustls::Stream::new(&mut conn, &mut socket);
                            let (mut head, mut buf) = (Vec::new(), [0u8; 4096]);
                            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                                match tls.read(&mut buf) {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => head.extend_from_slice(&buf[..n]),
                                }
                            }
                            if head.is_empty() {
                                return;
                            }
                            seen.lock()
                                .unwrap()
                                .push(String::from_utf8_lossy(&head).into_owned());
                            let _ = tls.write_all(response.as_bytes());
                            let _ = tls.flush();
                        });
                    }
                });
                Self {
                    addr,
                    accepts,
                    heads,
                }
            }

            fn accepts(&self) -> usize {
                self.accepts.load(Ordering::SeqCst)
            }

            fn heads(&self) -> Vec<String> {
                self.heads.lock().unwrap().clone()
            }
        }

        /// The production client, with `routes` (host -> loopback server) and the test root.
        fn routed(
            recipient: Recipient,
            pki: &Pki,
            routes: &[(&str, &Observer)],
        ) -> SubscriptionClient {
            SubscriptionClient::build(recipient, |mut builder| {
                for (host, observer) in routes {
                    builder = builder.resolve_to_addrs(host, &[observer.addr]);
                }
                builder.add_root_certificate(pki.root.clone()).no_proxy()
            })
            .expect("production client builds")
        }

        fn token_request(client: &SubscriptionClient, url: &str) -> Request {
            client
                .request(Method::POST, url)
                .bearer_auth("fixture-subscription-bearer")
                .form(&[("refresh_token", "fixture-refresh-token")])
                .build()
                .unwrap()
        }

        const OK: &str = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";

        /// The bearer reaches the exact endpoint, once, and nothing is refused that should not be.
        #[tokio::test(flavor = "multi_thread")]
        async fn token_goes_only_to_the_exact_endpoint() {
            let pki = pki();
            let endpoint = Observer::start(pki.server.clone(), OK);
            let client = routed(Recipient::XaiAuth, &pki, &[("auth.x.ai", &endpoint)]);
            let response = client
                .execute(token_request(&client, "https://auth.x.ai/oauth2/token"))
                .await
                .expect("the exact endpoint is reachable");
            assert_eq!(response.status(), 200);
            let heads = endpoint.heads();
            assert_eq!(heads.len(), 1, "{heads:?}");
            assert!(
                heads[0].starts_with("POST /oauth2/token HTTP/1.1\r\n"),
                "{}",
                heads[0]
            );
            assert!(
                heads[0]
                    .to_ascii_lowercase()
                    .contains("authorization: bearer fixture-subscription-bearer"),
                "{}",
                heads[0]
            );
        }

        /// A wrong recipient is refused BEFORE any contact: no TCP accept anywhere, and the
        /// error is the recipient denial, not a transport failure. Kills M3.
        #[tokio::test(flavor = "multi_thread")]
        async fn wrong_recipient_is_refused_before_any_contact() {
            let pki = pki();
            let endpoint = Observer::start(pki.server.clone(), OK);
            let decoy = Observer::start(pki.server.clone(), OK);
            let client = routed(
                Recipient::XaiAuth,
                &pki,
                &[
                    ("auth.x.ai", &endpoint),
                    ("api.x.ai", &decoy),
                    ("evil.test", &decoy),
                    ("auth.openai.com", &decoy),
                ],
            );
            for url in [
                "https://evil.test/oauth2/token",
                "https://api.x.ai/oauth2/token",
                "https://api.x.ai/v1/responses",
                "https://auth.openai.com/oauth/token",
                "https://auth.x.ai/oauth2/authorize",
                "https://auth.x.ai/oauth2/token?redirect_uri=https://evil.test",
            ] {
                let error = client
                    .execute(token_request(&client, url))
                    .await
                    .expect_err(url);
                assert!(
                    matches!(
                        error,
                        DispatchError::Denied("subscription recipient rejected")
                    ),
                    "{url}: {error:?}"
                );
            }
            assert_eq!(
                decoy.accepts(),
                0,
                "a refused recipient was contacted: {:?}",
                decoy.heads()
            );
            assert_eq!(
                endpoint.accepts(),
                0,
                "a refused path was contacted: {:?}",
                endpoint.heads()
            );
        }

        /// No redirect is followed: the 3xx comes back to the caller as-is, the endpoint
        /// sees one request, and neither a same-origin (307 replays body and bearer) nor a
        /// cross-origin target is contacted. Kills M2.
        #[tokio::test(flavor = "multi_thread")]
        async fn redirects_are_never_followed() {
            for (status, location) in [
                (
                    "307 Temporary Redirect",
                    "https://auth.x.ai/oauth2/elsewhere",
                ),
                ("308 Permanent Redirect", "https://auth.x.ai/oauth2/token"),
                ("302 Found", "https://evil.test/collect"),
                ("307 Temporary Redirect", "https://evil.test/collect"),
            ] {
                let pki = pki();
                let response: &'static str = Box::leak(
                    format!(
                        "HTTP/1.1 {status}\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    )
                    .into_boxed_str(),
                );
                let endpoint = Observer::start(pki.server.clone(), response);
                let elsewhere = Observer::start(pki.server.clone(), OK);
                let client = routed(
                    Recipient::XaiAuth,
                    &pki,
                    &[("auth.x.ai", &endpoint), ("evil.test", &elsewhere)],
                );
                let response = client
                    .execute(token_request(&client, "https://auth.x.ai/oauth2/token"))
                    .await
                    .expect("the 3xx itself is returned");
                assert!(
                    response.status().is_redirection(),
                    "{status} -> {location}: {}",
                    response.status()
                );
                assert_eq!(
                    endpoint.heads().len(),
                    1,
                    "{status} -> {location}: {:?}",
                    endpoint.heads()
                );
                assert_eq!(
                    elsewhere.accepts(),
                    0,
                    "{status} -> {location}: {:?}",
                    elsewhere.heads()
                );
            }
        }
    }
}
