//! Exact-recipient capability for explicitly selected subscription providers.
//! General clients still refuse the upstream vendor estate. No redirects here.
use crate::dispatch::DispatchError;
use reqwest::{Client, Method, Request, RequestBuilder, Response, Url};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    ChatGptAuth,
    ChatGptInference,
    XaiAuth,
    XaiInference,
}

impl Recipient {
    fn accepts(self, url: &Url) -> bool {
        if url.scheme() != "https"
            || url.port_or_known_default() != Some(443)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return false;
        }
        let (host, paths): (&str, &[&str]) = match self {
            Self::ChatGptAuth => ("auth.openai.com", &["/oauth/token"]),
            Self::ChatGptInference => (
                "chatgpt.com",
                &["/backend-api/codex/responses", "/backend-api/codex/models"],
            ),
            Self::XaiAuth => ("auth.x.ai", &["/oauth2/token"]),
            Self::XaiInference => (
                "api.x.ai",
                &["/v1/responses", "/v1/chat/completions", "/v1/models"],
            ),
        };
        if url.host_str() != Some(host) || !paths.contains(&url.path()) {
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

/// The raw client is private so every dispatch must pass the recipient check.
#[derive(Clone)]
pub struct SubscriptionClient {
    client: Client,
    recipient: Recipient,
}

impl SubscriptionClient {
    #[allow(clippy::disallowed_methods)] // Approved scoped TLS/egress boundary.
    pub fn new(recipient: Recipient) -> reqwest::Result<Self> {
        crate::ensure_default_crypto_provider();
        let mut builder = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(20))
            .user_agent("Fuigo/subscription")
            .use_rustls_tls()
            .tls_built_in_native_certs(false)
            .tls_built_in_webpki_certs(true);
        for cert in crate::shared_reqwest_roots() {
            builder = builder.add_root_certificate(cert);
        }
        Ok(Self {
            client: builder.build()?,
            recipient,
        })
    }

    pub fn request(&self, method: Method, url: &str) -> RequestBuilder {
        self.client.request(method, url)
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
}
