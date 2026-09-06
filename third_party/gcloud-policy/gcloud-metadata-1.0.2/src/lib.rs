use std::string;
use std::time::Duration;

use reqwest::header::{HeaderValue, USER_AGENT};
use tokio::net::lookup_host;
use tokio::sync::OnceCell;
pub mod transport;
use transport::RequestPolicyExt;

pub const METADATA_IP: &str = "169.254.169.254";
pub const METADATA_HOST_ENV: &str = "GCE_METADATA_HOST";
pub const METADATA_GOOGLE_HOST: &str = "metadata.google.internal:80";
pub const METADATA_FLAVOR_KEY: &str = "Metadata-Flavor";
pub const METADATA_GOOGLE: &str = "Google";

static ON_GCE: OnceCell<bool> = OnceCell::const_new();

static PROJECT_ID: OnceCell<String> = OnceCell::const_new();

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    TransportPolicy(#[from] transport::Error),
    #[error("invalid response code: {0}")]
    InvalidResponse(u16),
    #[error(transparent)]
    FromUTF8Error(#[from] string::FromUtf8Error),
    #[error(transparent)]
    HttpError(#[from] reqwest::Error),
}

pub async fn on_gce() -> bool {
    match ON_GCE.get_or_try_init(test_on_gce).await {
        Ok(s) => *s,
        Err(_err) => false,
    }
}

async fn test_on_gce() -> Result<bool, Error> {
    // The user explicitly said they're on GCE, so trust them.
    if std::env::var(METADATA_HOST_ENV).is_ok() {
        return Ok(true);
    }

    let client = transport::client(Duration::from_secs(3))?;
    let url = format!("http://{METADATA_IP}");

    let response = client.get(&url).send_guarded().await;
    if let Ok(response) = response {
        if response.status().is_success() {
            let on_gce = match response.headers().get(METADATA_FLAVOR_KEY) {
                None => false,
                Some(s) => s == METADATA_GOOGLE,
            };

            if on_gce {
                return Ok(true);
            }
        }
    }

    match lookup_host(METADATA_GOOGLE_HOST).await {
        Ok(s) => {
            for ip in s {
                if ip.ip().to_string() == METADATA_IP {
                    return Ok(true);
                }
            }
        }
        Err(_e) => return Ok(false),
    };

    Ok(false)
}

pub async fn project_id() -> String {
    match PROJECT_ID
        .get_or_try_init(|| get_etag_with_trim("project/project-id"))
        .await
    {
        Ok(s) => s.to_string(),
        Err(_err) => "".to_string(),
    }
}

pub async fn email(service_account: &str) -> Result<String, Error> {
    get_etag_with_trim(&format!("instance/service-accounts/{service_account}/email")).await
}

async fn get_etag_with_trim(suffix: &str) -> Result<String, Error> {
    let result = get_etag(suffix).await?;
    Ok(result.trim().to_string())
}

async fn get_etag(suffix: &str) -> Result<String, Error> {
    let host = std::env::var(METADATA_HOST_ENV).unwrap_or_else(|_| METADATA_GOOGLE_HOST.to_string());
    let url = format!("http://{host}/computeMetadata/v1/{suffix}");
    let client = transport::client(Duration::from_secs(3))?;
    let response = client
        .get(url)
        .header(METADATA_FLAVOR_KEY, HeaderValue::from_str(METADATA_GOOGLE).unwrap())
        .header(USER_AGENT, HeaderValue::from_str("gcloud-rust/0.1").unwrap())
        .send_guarded()
        .await?;

    if response.status().is_success() {
        return Ok(response.text().await?);
    }
    Err(Error::InvalidResponse(response.status().as_u16()))
}

#[cfg(test)]
mod policy_tests {
    #[tokio::test]
    async fn metadata_override_cannot_bypass_policy() {
        const CASE: &str = "FUIGO_METADATA_POLICY_CHILD";
        if std::env::var_os(CASE).is_none() {
            let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            proxy.set_nonblocking(true).unwrap();
            let url = format!("http://{}", proxy.local_addr().unwrap());
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "policy_tests::metadata_override_cannot_bypass_policy", "--nocapture"])
                .env(CASE, "1").env(super::METADATA_HOST_ENV, "blocked.invalid")
                .env("HTTP_PROXY", &url).env("http_proxy", &url)
                .env("ALL_PROXY", &url).env("all_proxy", &url)
                .env_remove("NO_PROXY").env_remove("no_proxy")
                .status().unwrap();
            assert!(status.success());
            assert_eq!(proxy.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            return;
        }
        super::transport::install(super::transport::Policy {
            configure: |b| b,
            check_url: |_| Err("denied".into()),
        }).unwrap();
        let error = super::email("default").await.unwrap_err();
        assert!(matches!(error, super::Error::TransportPolicy(super::transport::Error::Denied)));
    }
}
