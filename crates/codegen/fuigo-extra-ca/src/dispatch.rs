//! Validate the built destination before reqwest can contact an explicit or
//! environment proxy. DNS denial alone cannot prevent HTTP CONNECT dispatch.
//!
//! Use clients built by this crate: their redirect policy additionally checks
//! every followed hop. This initial-request boundary does not wrap external
//! middleware/SDK sends automatically; those callers need their own integration.

use std::fmt;

#[derive(Debug)]
pub enum DispatchError {
    Denied(&'static str),
    Transport(reqwest::Error),
}

impl DispatchError {
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Transport(error) if error.is_timeout())
    }

    pub fn is_connect(&self) -> bool {
        matches!(self, Self::Transport(error) if error.is_connect())
    }

    pub fn without_url(self) -> Self {
        match self {
            Self::Transport(error) => Self::Transport(error.without_url()),
            denied => denied,
        }
    }
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(reason) => f.write_str(reason),
            Self::Transport(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DispatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Denied(_) => None,
        }
    }
}

impl From<reqwest::Error> for DispatchError {
    fn from(error: reqwest::Error) -> Self {
        Self::Transport(error)
    }
}

/// Does not log the URL, whose path/query may contain credentials.
pub fn check_url(url: &reqwest::Url) -> Result<(), DispatchError> {
    if crate::egress::guard_enabled() && url.host_str().is_some_and(crate::egress::is_blocked_host)
    {
        return Err(DispatchError::Denied(
            "fuigo refuses to contact upstream vendor host",
        ));
    }
    Ok(())
}

pub async fn send(builder: reqwest::RequestBuilder) -> Result<reqwest::Response, DispatchError> {
    let (client, request) = builder.build_split();
    execute(&client, request?).await
}

/// Chain-friendly checked dispatch without changing request construction APIs.
pub trait AsyncRequestBuilderExt {
    fn send_checked(
        self,
    ) -> impl std::future::Future<Output = Result<reqwest::Response, DispatchError>> + Send;
}

impl AsyncRequestBuilderExt for reqwest::RequestBuilder {
    fn send_checked(
        self,
    ) -> impl std::future::Future<Output = Result<reqwest::Response, DispatchError>> + Send {
        send(self)
    }
}

pub trait BlockingRequestBuilderExt {
    fn send_checked(self) -> Result<reqwest::blocking::Response, DispatchError>;
}

impl BlockingRequestBuilderExt for reqwest::blocking::RequestBuilder {
    fn send_checked(self) -> Result<reqwest::blocking::Response, DispatchError> {
        send_blocking(self)
    }
}

pub async fn execute(
    client: &reqwest::Client,
    request: reqwest::Request,
) -> Result<reqwest::Response, DispatchError> {
    check_url(request.url())?;
    client
        .execute(request)
        .await
        .map_err(DispatchError::Transport)
}

pub fn send_blocking(
    builder: reqwest::blocking::RequestBuilder,
) -> Result<reqwest::blocking::Response, DispatchError> {
    let (client, request) = builder.build_split();
    execute_blocking(&client, request?)
}

pub fn execute_blocking(
    client: &reqwest::blocking::Client,
    request: reqwest::blocking::Request,
) -> Result<reqwest::blocking::Response, DispatchError> {
    check_url(request.url())?;
    client.execute(request).map_err(DispatchError::Transport)
}
