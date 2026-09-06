use google_cloud_metadata::transport::RequestPolicyExt;
use async_trait::async_trait;

use crate::credentials;
use crate::error::Error;
use crate::misc::{UnwrapOrEmpty, EMPTY};
use crate::token::{Token, TOKEN_URL};
use crate::token_source::TokenSource;
use crate::token_source::{default_http_client, InternalToken};

#[allow(dead_code)]
#[derive(Debug)]
pub struct UserAccountTokenSource {
    client_id: String,
    client_secret: String,
    token_url: String,
    redirect_url: String,
    refresh_token: String,

    client: reqwest::Client,
}

impl UserAccountTokenSource {
    pub(crate) fn new(cred: &credentials::CredentialsFile) -> Result<UserAccountTokenSource, Error> {
        if cred.refresh_token.is_none() {
            return Err(Error::RefreshTokenIsRequired);
        }

        let ts = UserAccountTokenSource {
            client_id: cred.client_id.unwrap_or_empty(),
            client_secret: cred.client_secret.unwrap_or_empty(),
            token_url: match &cred.token_uri {
                None => TOKEN_URL.to_string(),
                Some(s) => s.to_string(),
            },
            redirect_url: EMPTY.to_string(),
            refresh_token: cred.refresh_token.unwrap_or_empty(),
            client: default_http_client()?,
        };
        Ok(ts)
    }
}

#[derive(serde::Serialize)]
struct RequestBody<'a> {
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub grant_type: &'a str,
    pub refresh_token: &'a str,
}

#[async_trait]
impl TokenSource for UserAccountTokenSource {
    async fn token(&self) -> Result<Token, Error> {
        let data = RequestBody {
            client_id: &self.client_id,
            client_secret: &self.client_secret,
            grant_type: "refresh_token",
            refresh_token: &self.refresh_token,
        };

        let it = self
            .client
            .post(self.token_url.to_string())
            .json(&data)
            .send_guarded()
            .await?
            .json::<InternalToken>()
            .await?;

        return Ok(it.to_token(time::OffsetDateTime::now_utc()));
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;

    #[tokio::test]
    async fn refresh_policy_is_checked_on_every_attempt() {
        use google_cloud_metadata::transport::{self, Policy};
        transport::install(Policy {
            configure: |b| b,
            check_url: |url| if url.host_str() == Some("127.0.0.1") { Ok(()) } else { Err("denied".into()) },
        }).unwrap();
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        proxy.set_nonblocking(true).unwrap();
        let credentials: credentials::CredentialsFile = serde_json::from_value(serde_json::json!({
            "type": "authorized_user", "client_id": "fake-client",
            "client_secret": "fake-client-secret", "refresh_token": "fake-refresh",
            "token_uri": "http://blocked.invalid/token"
        })).unwrap();
        let mut source = UserAccountTokenSource::new(&credentials).unwrap();
        source.client = reqwest::Client::builder().no_proxy()
            .proxy(reqwest::Proxy::all(format!("http://{}", proxy.local_addr().unwrap())).unwrap())
            .build().unwrap();
        for _ in 0..2 {
            let error = source.token().await.unwrap_err();
            assert!(matches!(error, Error::TransportPolicy(transport::Error::Denied)));
            assert!(!error.to_string().contains("fake-refresh"));
        }
        assert_eq!(proxy.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }
}
