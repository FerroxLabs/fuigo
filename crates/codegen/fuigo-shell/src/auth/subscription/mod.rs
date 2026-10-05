//! Fuigo-owned subscription sessions. No external credential imports.
//! Protocol constants adapted from Ferrox Labs Wayland Core oauth/chatgpt.rs,
//! oauth/xai.rs and Wayland xaiOAuthCore.ts (Apache-2.0, Copyright 2026 Ferrox Labs).
// CLI printer: stdout goes through `fuigo_tty_utils::cli_println!` (a raw `println!` aborts the
// process when stdout's reader is gone, R060).
#![deny(clippy::print_stdout)]
mod flow;
pub(crate) mod inference;
mod manual;
mod storage;
#[cfg(test)]
mod tests;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
pub use flow::{LoginAttempt, cli_login};
pub use inference::cli_models;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
pub use storage::SubscriptionStore;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionProvider {
    Chatgpt,
    #[value(alias = "grok")]
    Xai,
}

impl SubscriptionProvider {
    pub fn name(self) -> &'static str {
        match self {
            Self::Chatgpt => "chatgpt",
            Self::Xai => "xai",
        }
    }
    fn issuer(self) -> &'static str {
        match self {
            Self::Chatgpt => "https://auth.openai.com",
            Self::Xai => "https://auth.x.ai",
        }
    }
    fn client_id(self) -> &'static str {
        match self {
            Self::Chatgpt => "app_EMoamEEZ73f0CkXaXp7hrann",
            Self::Xai => "b1a00492-073a-47ea-816f-4c329264a828",
        }
    }
    fn scope(self) -> &'static str {
        match self {
            Self::Chatgpt => "openid profile email offline_access",
            Self::Xai => "openid profile email offline_access grok-cli:access api:access",
        }
    }
    fn token_url(self) -> &'static str {
        match self {
            Self::Chatgpt => "https://auth.openai.com/oauth/token",
            Self::Xai => "https://auth.x.ai/oauth2/token",
        }
    }
    fn authorize_url(self) -> &'static str {
        match self {
            Self::Chatgpt => "https://auth.openai.com/oauth/authorize",
            Self::Xai => "https://auth.x.ai/oauth2/authorize",
        }
    }
}

/// Deliberately contains no underlying HTTP, JSON, URL or token error text.
#[derive(Debug, thiserror::Error)]
pub enum SubscriptionError {
    #[error("subscription credential storage failed; no successful persistence can be claimed")]
    Storage,
    #[error("subscription credential lock timed out")]
    LockTimeout,
    #[error("subscription login required for the selected provider/account")]
    LoginRequired,
    #[error("subscription response has invalid credentials or changed account binding")]
    InvalidCredentials,
    #[error("subscription token request failed (HTTP {0}); no provider fallback was attempted")]
    Http(u16),
    #[error("subscription token request was not sent to the provider")]
    Network,
    /// This machine's TLS configuration stopped the request before any bytes were sent:
    /// the HTTPS client could not be built, or the provider's certificate did not verify
    /// against a configured extra CA bundle. Retrying cannot help until the named file (or
    /// trust store) is fixed. The detail names a local file path only, never response or
    /// token content.
    #[error(
        "subscription local TLS/CA configuration error: {0}; no request was sent, and \
         retrying will not help until it is fixed"
    )]
    LocalTls(String),
    /// The provider accepted the request but its outcome was lost (the response body
    /// failed mid-read after a success status, or the bounded exchange timed out).
    /// A rotated single-use refresh token may already have been consumed.
    #[error("subscription token exchange outcome is unknown; the token may already be rotated")]
    AmbiguousExchange,
    #[error("subscription callback rejected")]
    Callback,
    #[error("subscription login cancelled")]
    Cancelled,
    #[error("subscription login timed out")]
    Timeout,
    #[error("subscription callback listener unavailable")]
    Listener,
    #[error("subscription terminal input unavailable")]
    Terminal,
}
pub type Result<T> = std::result::Result<T, SubscriptionError>;

impl SubscriptionError {
    /// Whether a failed token exchange may have left the provider holding a rotated
    /// (therefore consumed) refresh token. `true` means the durable `refresh_pending`
    /// marker must stay set and only a fresh login can recover; `false` means the
    /// provider issued nothing, so the marker must be cleared or a transient failure
    /// would permanently sign the user out.
    ///
    /// Only meaningful for errors returned by the refresh exchange itself.
    pub(super) fn may_have_consumed_refresh_token(&self) -> bool {
        match self {
            // A non-success status is returned by `read_json_response` before the body is
            // read: the provider refused outright. 4xx other than 429 means it rejected the
            // token itself, so a re-login is genuinely required; 429, 5xx and any other
            // non-success status mean it never processed the token.
            Self::Http(code) => (400..500).contains(code) && *code != 429,
            // The request never left this host: egress denial, DNS, connect or TLS
            // handshake failure (`flow::exchange_send_error` reports anything later as
            // `AmbiguousExchange`).
            Self::Network => false,
            // No client existed, or the handshake failed before the request was written.
            Self::LocalTls(_) => false,
            // Raised around persistence, not around the exchange.
            Self::Storage | Self::LockTimeout => false,
            // The provider answered, or may have answered, and we lost the reply.
            Self::AmbiguousExchange => true,
            // A malformed or mis-bound token response: the provider did issue something.
            Self::InvalidCredentials => true,
            // Not produced by the exchange; fail closed rather than guess.
            Self::LoginRequired
            | Self::Callback
            | Self::Cancelled
            | Self::Timeout
            | Self::Listener
            | Self::Terminal => true,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Credential {
    provider: SubscriptionProvider,
    issuer: String,
    client_id: String,
    account: String,
    access_token: String,
    refresh_token: Option<String>,
    expires_at: u64,
    #[serde(default)]
    refresh_pending: bool,
}
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubscriptionCredential([REDACTED])")
    }
}

#[derive(Debug, Serialize)]
pub struct SubscriptionStatus {
    pub provider: SubscriptionProvider,
    pub account: String,
    pub selected: bool,
    pub expires_at: u64,
    pub login_required: bool,
}

/// Bearer is never included in Debug/Display. Only selected inference may use it.
#[derive(Clone)]
pub struct SubscriptionAccess {
    pub provider: SubscriptionProvider,
    pub account: String,
    pub expires_at: u64,
    token: String,
    unpersisted: bool,
}
impl std::fmt::Debug for SubscriptionAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubscriptionAccess([REDACTED])")
    }
}
impl SubscriptionAccess {
    pub fn bearer(&self) -> Result<&str> {
        if self.expires_at <= now() {
            return Err(SubscriptionError::LoginRequired);
        }
        Ok(&self.token)
    }
    /// True when this credential came from a successful refresh the store could not save.
    /// It works for this process only; the user should fix the disk before restarting.
    pub fn is_unpersisted(&self) -> bool {
        self.unpersisted
    }
    fn unpersisted(mut self) -> Self {
        self.unpersisted = true;
        self
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn claims(token: &str) -> Option<serde_json::Value> {
    let mut parts = token.split('.');
    parts.next()?;
    let body = parts.next()?;
    if parts.next().is_none() || parts.next().is_some() {
        return None;
    }
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).ok()?).ok()
}

impl Credential {
    fn validate(&self, provider: SubscriptionProvider, account: &str) -> Result<()> {
        if self.provider != provider
            || self.issuer != provider.issuer()
            || self.client_id != provider.client_id()
            || self.account != account
            || account.is_empty()
            || self.access_token.is_empty()
        {
            return Err(SubscriptionError::InvalidCredentials);
        }
        Ok(())
    }
    fn access(&self) -> Result<SubscriptionAccess> {
        if self.refresh_pending || self.expires_at <= now() {
            return Err(SubscriptionError::LoginRequired);
        }
        Ok(SubscriptionAccess {
            provider: self.provider,
            account: self.account.clone(),
            expires_at: self.expires_at,
            token: self.access_token.clone(),
            unpersisted: false,
        })
    }
}

pub async fn cli_status(provider: SubscriptionProvider) -> Result<()> {
    let store = default_store()?;
    let statuses = store.status(provider).await?;
    if statuses.is_empty() {
        fuigo_tty_utils::cli_println!("{}: signed out", provider.name());
    }
    for status in statuses {
        // JSON escaping prevents account metadata from injecting terminal controls.
        fuigo_tty_utils::cli_println!(
            "{}",
            serde_json::to_string(&status).map_err(|_| SubscriptionError::Storage)?
        );
    }
    Ok(())
}
pub fn default_store() -> Result<SubscriptionStore> {
    let home = fuigo_dirs::resolve_fuigo_home().ok_or(SubscriptionError::Storage)?;
    Ok(SubscriptionStore::new(Path::new(&home)))
}
