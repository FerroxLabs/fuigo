use super::*;
use fuigo_extra_ca::subscription::{Recipient, SubscriptionClient};
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
}
impl TokenClient {
    pub(super) fn new(provider: SubscriptionProvider) -> Result<Self> {
        let recipient = match provider {
            SubscriptionProvider::Chatgpt => Recipient::ChatGptAuth,
            SubscriptionProvider::Xai => Recipient::XaiAuth,
        };
        Ok(Self {
            provider,
            client: SubscriptionClient::new(recipient).map_err(|_| SubscriptionError::Network)?,
            #[cfg(test)]
            endpoint: None,
        })
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
                let client = fuigo_extra_ca::build_reqwest_client(|b| {
                    b.redirect(reqwest::redirect::Policy::none())
                })
                .map_err(|_| SubscriptionError::Network)?;
                let response = client
                    .post(endpoint)
                    .form(form)
                    .send_checked()
                    .await
                    .map_err(|_| SubscriptionError::Network)?;
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
                .map_err(|_| SubscriptionError::Network)?;
            read_response(response).await
        })
        .await
        .map_err(|_| SubscriptionError::Network)?
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
pub(super) async fn read_response(response: reqwest::Response) -> Result<serde_json::Value> {
    read_json_response(response, 65536).await
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

/// Owns the listener and one attempt's PKCE material. Dropping cancels the listener.
/// No spawned callback task, external session imports, or secret Debug output.
pub struct LoginAttempt {
    provider: SubscriptionProvider,
    listener: TcpListener,
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
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(|_| SubscriptionError::Listener)?;
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
            listener,
            redirect,
            state,
            verifier: pkce.code_verifier,
            authorize: authorize.into(),
            client: TokenClient::new(provider)?,
        })
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
    async fn callback(&self) -> Result<String> {
        loop {
            let (mut stream, _) = self
                .listener
                .accept()
                .await
                .map_err(|_| SubscriptionError::Listener)?;
            let mut bytes = Vec::new();
            let read = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let byte = stream
                        .read_u8()
                        .await
                        .map_err(|_| SubscriptionError::Callback)?;
                    bytes.push(byte);
                    if bytes.ends_with(b"\r\n\r\n") {
                        return Ok(());
                    }
                    if bytes.len() >= 8192 {
                        return Err(SubscriptionError::Callback);
                    }
                }
            })
            .await;
            if !matches!(read, Ok(Ok(()))) {
                continue;
            }
            let line = std::str::from_utf8(&bytes)
                .map_err(|_| SubscriptionError::Callback)?
                .lines()
                .next()
                .ok_or(SubscriptionError::Callback)?;
            let mut parts = line.split_whitespace();
            if parts.next() != Some("GET") {
                continue;
            }
            let target = parts.next().ok_or(SubscriptionError::Callback)?;
            if !target.starts_with('/') || target.starts_with("//") {
                return Err(SubscriptionError::Callback);
            }
            let url = url::Url::parse(&format!("http://localhost{target}"))
                .map_err(|_| SubscriptionError::Callback)?;
            let expected =
                url::Url::parse(&self.redirect).map_err(|_| SubscriptionError::Callback)?;
            if url.path() != expected.path() {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                continue;
            }
            let fields: Vec<_> = url.query_pairs().collect();
            let states: Vec<_> = fields.iter().filter(|(k, _)| k == "state").collect();
            let codes: Vec<_> = fields.iter().filter(|(k, _)| k == "code").collect();
            let valid = states.len() == 1
                && states[0].1 == self.state
                && codes.len() == 1
                && !codes[0].1.is_empty()
                && !fields.iter().any(|(k, _)| k == "error");
            let reply: &[u8] = if valid {
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nFuigo received authorization. Return to your terminal for the result."
            } else {
                b"HTTP/1.1 400 Bad Request\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nFuigo rejected this callback."
            };
            let _ = stream.write_all(reply).await;
            if !valid {
                return Err(SubscriptionError::Callback);
            }
            return Ok(codes[0].1.to_string());
        }
    }
}

pub async fn cli_login(provider: SubscriptionProvider) -> Result<()> {
    let store = default_store()?;
    let attempt = LoginAttempt::start(provider).await?;
    eprintln!(
        "Sign in to {} for Fuigo. Credentials will be stored only by Fuigo.\n{}",
        provider.name(),
        attempt.authorization_url()
    );
    if webbrowser::open(attempt.authorization_url()).is_err() {
        eprintln!("Open the URL above in your browser.");
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
    eprintln!("{} subscription login saved by Fuigo.", provider.name());
    Ok(())
}
