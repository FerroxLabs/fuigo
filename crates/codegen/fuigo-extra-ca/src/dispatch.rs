//! Validate the built destination before reqwest can contact an explicit or
//! environment proxy. DNS denial alone cannot prevent HTTP CONNECT dispatch.
//!
//! # What "checked" means here — and what it does NOT
//!
//! [`check_url`], [`execute`], [`send`] and the `send_checked` extension
//! methods apply exactly one rule: the upstream-vendor egress denylist of
//! [`crate::egress`] (refuse `x.ai`, `grok.com`, `mixpanel.com` unless
//! `FUIGO_ALLOW_UPSTREAM_HOSTS` lifts it). That is the WHOLE check.
//!
//! It is NOT a credential-to-destination binding (audit CB-5). A request that
//! carries a token, key or session cookie passes it to any destination that is
//! not on the vendor denylist. Binding a credential to its recipient takes
//! TWO things, and `send_checked` provides neither:
//! - an initial-recipient check, per credential, before the request is sent:
//!   the exact-recipient [`crate::subscription::SubscriptionClient`],
//!   `credential_recipient_matches` and the per-call-site origin checks in the
//!   callers, `fuigo_computer_hub_sdk::check_token_endpoint` for hub OIDC
//!   refresh and for the shell's own OIDC login and refresh;
//! - redirect handling that cannot carry the credential off that origin: the
//!   same-origin policy of [`crate::build_reqwest_client`], or no redirects.
//!
//! The redirect policy alone binds nothing: it keeps a credential on the
//! origin of the FIRST request, whatever that origin is.
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

/// The vendor egress denylist only (see the module docs): `Ok` says nothing
/// about whether a credential on this request belongs at this destination.
/// Does not log the URL, whose path/query may contain credentials.
pub fn check_url(url: &reqwest::Url) -> Result<(), DispatchError> {
    if url.host_str().is_some_and(crate::egress::is_refused_host)
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

/// Chain-friendly dispatch through [`check_url`] without changing request
/// construction APIs. "Checked" means the vendor egress denylist only; it does
/// not bind any credential on the request to its destination.
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

/// Blocking twin of [`AsyncRequestBuilderExt`]; the same denylist-only check.
pub trait BlockingRequestBuilderExt {
    fn send_checked(self) -> Result<reqwest::blocking::Response, DispatchError>;
}

impl BlockingRequestBuilderExt for reqwest::blocking::RequestBuilder {
    fn send_checked(self) -> Result<reqwest::blocking::Response, DispatchError> {
        send_blocking(self)
    }
}

#[allow(clippy::disallowed_methods)] // Approved boundary: check_url precedes raw dispatch.
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

#[allow(clippy::disallowed_methods)] // Approved boundary: check_url precedes raw dispatch.
pub fn execute_blocking(
    client: &reqwest::blocking::Client,
    request: reqwest::blocking::Request,
) -> Result<reqwest::blocking::Response, DispatchError> {
    check_url(request.url())?;
    client.execute(request).map_err(DispatchError::Transport)
}
