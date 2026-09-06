//! Header-credential-free downloads with reviewed cross-origin redirects.
//!
//! No raw client/request builder escapes this API: callers can request GET,
//! HEAD or a numeric byte range, but cannot attach auth, cookies or a body.
//! Signed URLs remain explicit URL authority; they are not copied to Referer.

use std::fmt;
use std::time::Duration;

use reqwest::{Method, Url};

#[derive(Debug)]
pub enum DownloadError {
    InvalidUrl,
    Policy(&'static str),
    Request(reqwest::Error),
}

impl fmt::Display for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl => f.write_str("invalid download URL"),
            Self::Policy(reason) => f.write_str(reason),
            Self::Request(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DownloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            _ => None,
        }
    }
}

fn validate(url: &Url) -> Result<(), DownloadError> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(DownloadError::Policy("download URL userinfo is forbidden"));
    }
    let loopback = url.host_str().is_some_and(|host| {
        host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(DownloadError::Policy(
            "downloads require HTTPS or loopback HTTP",
        ));
    }
    if crate::egress::guard_enabled() && url.host_str().is_some_and(crate::egress::is_blocked_host)
    {
        return Err(DownloadError::Policy(
            "fuigo refuses to contact upstream vendor host",
        ));
    }
    Ok(())
}

fn parsed(url: &str) -> Result<Url, DownloadError> {
    let url = Url::parse(url).map_err(|_| DownloadError::InvalidUrl)?;
    validate(&url)?;
    Ok(url)
}

fn policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > 10 {
            return attempt.error("fuigo download redirect limit exceeded");
        }
        if let Err(error) = validate(attempt.url()) {
            return attempt.error(error);
        }
        if attempt.previous().iter().any(|u| u.scheme() == "https")
            && attempt.url().scheme() != "https"
        {
            return attempt.error("fuigo refuses an HTTPS download downgrade");
        }
        attempt.follow()
    })
}

/// A pooled download client with no credential/header/body configuration API.
#[derive(Clone, Debug)]
pub struct PublicDownloadClient(reqwest::Client);

impl PublicDownloadClient {
    pub fn new(timeout: Duration) -> reqwest::Result<Self> {
        crate::build_reqwest_client(|b| b.timeout(timeout).referer(false).redirect(policy()))
            .map(Self)
    }

    pub async fn get(&self, url: &str) -> Result<reqwest::Response, DownloadError> {
        self.request(Method::GET, url, None).await
    }

    pub async fn head(&self, url: &str) -> Result<reqwest::Response, DownloadError> {
        self.request(Method::HEAD, url, None).await
    }

    pub async fn get_range(
        &self,
        url: &str,
        start: u64,
        end: u64,
    ) -> Result<reqwest::Response, DownloadError> {
        if start > end {
            return Err(DownloadError::Policy("invalid download byte range"));
        }
        self.request(Method::GET, url, Some((start, end))).await
    }

    #[allow(clippy::disallowed_methods)] // Restricted methods/headers; parsed URL and redirect policy enforce admission.
    async fn request(
        &self,
        method: Method,
        url: &str,
        range: Option<(u64, u64)>,
    ) -> Result<reqwest::Response, DownloadError> {
        let mut request = self.0.request(method, parsed(url)?);
        if let Some((start, end)) = range {
            request = request.header(reqwest::header::RANGE, format!("bytes={start}-{end}"));
        }
        request
            .send()
            .await
            .map_err(|error| DownloadError::Request(error.without_url()))
    }
}

/// Blocking equivalent for boot-time public changelog fetching.
#[derive(Clone, Debug)]
pub struct BlockingPublicDownloadClient(reqwest::blocking::Client);

impl BlockingPublicDownloadClient {
    pub fn new(timeout: Duration) -> reqwest::Result<Self> {
        crate::build_blocking_reqwest_client(|b| {
            b.timeout(timeout).referer(false).redirect(policy())
        })
        .map(Self)
    }

    #[allow(clippy::disallowed_methods)] // parsed URL and redirect policy enforce public-download admission.
    pub fn get(&self, url: &str) -> Result<reqwest::blocking::Response, DownloadError> {
        self.0
            .get(parsed(url)?)
            .send()
            .map_err(|error| DownloadError::Request(error.without_url()))
    }
}
