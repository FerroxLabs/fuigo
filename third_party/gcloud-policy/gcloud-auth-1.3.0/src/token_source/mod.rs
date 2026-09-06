use std::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;
use jsonwebtoken;
use serde::Deserialize;

use crate::error::Error;
use crate::token::Token;

pub mod authorized_user_token_source;
pub mod compute_identity_source;
pub mod compute_token_source;
pub mod impersonate_token_source;
pub mod reuse_token_source;
pub mod service_account_token_source;

#[cfg(feature = "external-account")]
pub mod external_account_source;

#[async_trait]
pub trait TokenSource: Send + Sync + Debug {
    async fn token(&self) -> Result<Token, Error>;
}

pub(crate) fn default_http_client() -> Result<reqwest::Client, reqwest::Error> {
    google_cloud_metadata::transport::client(Duration::from_secs(3))
}

#[derive(Clone, Deserialize)]
struct InternalToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<i64>,
}

impl InternalToken {
    fn to_token(&self, now: time::OffsetDateTime) -> Token {
        Token {
            access_token: self.access_token.clone(),
            token_type: self.token_type.clone(),
            expiry: self.expires_in.map(|s| now + time::Duration::seconds(s)),
        }
    }
}

#[derive(Clone, Deserialize)]
struct InternalIdToken {
    pub id_token: String,
}

#[derive(Deserialize)]
struct ExpClaim {
    exp: i64,
}

impl InternalIdToken {
    fn to_token(&self, audience: &str) -> Result<Token, Error> {
        Ok(Token {
            access_token: self.id_token.clone(),
            token_type: "Bearer".into(),
            expiry: time::OffsetDateTime::from_unix_timestamp(self.get_exp(audience)?).ok(),
        })
    }

    fn get_exp(&self, _audience: &str) -> Result<i64, Error> {
        //skips all checks, so audience has to be manually checked if necessary
        let token = jsonwebtoken::dangerous::insecure_decode::<ExpClaim>(self.id_token.as_bytes())?;
        Ok(token.claims.exp)
    }
}

#[cfg(test)]
mod tests {
    use crate::credentials::CredentialsFile;
    use crate::error::Error;
    use crate::token_source::service_account_token_source::{
        OAuth2ServiceAccountTokenSource, ServiceAccountTokenSource,
    };
    use crate::token_source::TokenSource;

    fn fixture_credentials(token_uri: &str) -> CredentialsFile {
        // Ephemeral test-only key; never reads ambient Google credentials.
        let output = std::process::Command::new("openssl")
            .args(["genrsa", "2048"]).output().expect("openssl test-key generator");
        assert!(output.status.success());
        serde_json::from_value(serde_json::json!({
            "type": "service_account", "project_id": "local-test",
            "private_key_id": "test-key", "private_key": String::from_utf8(output.stdout).unwrap(),
            "client_email": "test@local.invalid", "client_id": "test-client",
            "token_uri": token_uri
        })).unwrap()
    }

    #[tokio::test]
    async fn test_jwt_token_source() -> Result<(), Error> {
        let credentials = fixture_credentials("http://127.0.0.1:1/unused");
        let audience = "https://spanner.googleapis.com/";
        let ts = ServiceAccountTokenSource::new(&credentials, audience)?;
        let token = ts.token().await?;
        assert_eq!("Bearer", token.token_type);
        assert!(token.expiry.unwrap().unix_timestamp() > 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_oauth2_token_source() -> Result<(), Error> {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(std::time::Duration::from_secs(3))).unwrap();
                        let mut bytes = Vec::new();
                        let mut buffer = [0; 4096];
                        loop {
                            let n = stream.read(&mut buffer).unwrap();
                            assert!(n > 0);
                            bytes.extend_from_slice(&buffer[..n]);
                            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                                let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                                let length: usize = headers.lines().find_map(|l| l.strip_prefix("content-length:")).unwrap().trim().parse().unwrap();
                                if bytes.len() >= end + 4 + length { break; }
                            }
                        }
                        let request = String::from_utf8_lossy(&bytes);
                        assert!(request.starts_with("POST /token "));
                        assert!(request.contains("assertion="));
                        let body = r#"{"access_token":"local-access","token_type":"Bearer","expires_in":3600}"#;
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline);
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(e) => panic!("local token receiver: {e}"),
                }
            }
        });
        let credentials = fixture_credentials(&format!("http://{addr}/token"));
        let scope = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/spanner.data";
        let sub = None;
        let mut ts = OAuth2ServiceAccountTokenSource::new(&credentials, scope, sub)?;
        ts.client = reqwest::Client::builder().no_proxy().build()?;
        let result = ts.token().await;
        server.join().unwrap();
        let token = result?;
        assert_eq!("Bearer", token.token_type);
        assert!(token.expiry.unwrap().unix_timestamp() > 0);
        Ok(())
    }
}
