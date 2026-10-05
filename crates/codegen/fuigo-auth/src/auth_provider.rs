//! Credentials for outbound HTTP made by the data-collector.
//! Shell installs `ShellAuthCredentialProvider` wrapping `AuthManager` + `TokenRefresher`.
//! Data-collector code holds an `Arc<dyn AuthCredentialProvider>`.

use reqwest::RequestBuilder;

use crate::visibility::HttpAuth;

/// Snapshot of the currently effective credentials.
/// Used by callers that build their own header maps (the OTel OTLP exporter) or that need the bearer prefix for 401-attribution telemetry.
#[derive(Clone, Default)]
pub struct CredentialSnapshot {
    /// Bearer token. `None` when no auth is configured (CI / `--api-key` headless).
    pub token: Option<String>,
    /// User identifier matching the bearer token's owner.
    /// `None` when no auth is configured or when the underlying provider has no concept of user identity (`StaticAuthCredentialProvider`).
    /// Read by the OTel layer to populate the `user.id` resource attribute.
    pub user_id: Option<String>,
    /// Team identifier from OAuth. `None` for personal accounts or when no auth is configured.
    pub team_id: Option<String>,
    /// `uuidv5(NAMESPACE_OID, deployment_key)`, set only for deployment-key auth.
    pub deployment_id: Option<String>,
    /// `uuidv5(NAMESPACE_OID, api_key)`, set only for `AuthMode::ApiKey`.
    pub api_key_id: Option<String>,
    /// Org id from the OIDC `organizationId` claim; `None` for personal / deployment-key auth.
    pub organization_id: Option<String>,
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for CredentialSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            token,
            user_id,
            team_id,
            deployment_id,
            api_key_id,
            organization_id,
        } = self;
        f.debug_struct("CredentialSnapshot")
            .field("token", &token.as_ref().map(|_| "<redacted>"))
            .field("user_id", user_id)
            .field("team_id", team_id)
            .field("deployment_id", deployment_id)
            .field("api_key_id", api_key_id)
            .field("organization_id", organization_id)
            .finish()
    }
}

/// Source of truth for outbound auth on data-collector requests.
///
/// Supertrait of `HttpAuth` so a single impl satisfies both this trait (refresh-aware snapshot + 401 recovery) and `HttpAuth` (header construction).
/// Callers add headers via `HttpAuth::apply`.
#[async_trait::async_trait]
pub trait AuthCredentialProvider: HttpAuth + Send + Sync + 'static {
    /// Implementations should issue a cheap disk re-read (`AuthManager::refresh`) before snapshotting.
    /// This lets callers see updates from sibling processes (`fuigo-desktop`, `fuigo login`).
    /// The `token` field MUST mirror the bearer that `HttpAuth::apply` would send on the wire so 401-attribution prefixes match the actual request.
    fn snapshot(&self) -> CredentialSnapshot;

    /// Attempt to obtain a fresh token.
    /// Returns `true` if a different token was obtained; the caller should retry the failed request once.
    /// Returns `false` if no refresher is configured or refresh failed.
    async fn refresh_after_unauthorized(&self) -> bool;

    /// Whether `X-XAI-Token-Auth` should be sent with the bearer token.
    /// `false` for deployment keys (bare Bearer), `true` for user/OAuth tokens.
    /// See `FuigoAuthCredentials::apply()` for the wire format contract.
    fn needs_token_auth_header(&self) -> bool {
        true
    }

    /// Whether the provider holds a credential worth a real outbound attempt: an unexpired token (in memory or on disk), or a static key.
    /// The default `true` always attempts.
    fn has_usable_credential(&self) -> bool {
        true
    }

    /// P47: may `bearer` — the exact value the caller took from [`Self::snapshot`] and is about to attach — go to a
    /// request for `url`? The decision is about that value, never a re-read of the provider's state, so a credential
    /// switch between the snapshot and the check cannot exempt one credential and send another.
    ///
    /// Required, with no default, so every provider states its rule. A provider whose bearer can be a
    /// session token answers with the service-endpoint trust class (`fuigo_extra_ca::service_trust`);
    /// one holding only a non-session key (API key, BYOK key, deployment key) answers `Ok`.
    /// [`crate::AuthRetryMiddleware`] consults it before every stamp and, on `Err`, does not send the
    /// request at all; callers that build their own headers (the OTLP exporter) must consult it too.
    fn bearer_may_reach(
        &self,
        url: &reqwest::Url,
        bearer: &str,
    ) -> Result<(), BearerDestinationRefused>;
}

/// P47: the bearer may not go to this destination, so the request was not sent. The text is user-facing:
/// it names the refused origin and the remedy, never a path or the token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BearerDestinationRefused(pub String);

impl std::fmt::Display for BearerDestinationRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BearerDestinationRefused {}

/// The destination rule a [`StaticAuthCredentialProvider`] applies to its bearer.
#[derive(Clone)]
pub enum BearerDestination {
    /// The bearer is not a session token (API key, BYOK key, deployment key, or none); the rules that
    /// resolved it already decided where it may go.
    Unrestricted,
    /// The bearer is (or may be) a session token: every destination is checked by this rule.
    Checked(BearerRule),
}

/// A destination rule for [`BearerDestination::Checked`]: `Err` refuses `url` for the provider's bearer.
pub type BearerRule =
    std::sync::Arc<dyn Fn(&reqwest::Url) -> Result<(), BearerDestinationRefused> + Send + Sync>;

impl BearerDestination {
    /// Apply the rule to `url`.
    pub fn check(&self, url: &reqwest::Url) -> Result<(), BearerDestinationRefused> {
        match self {
            Self::Unrestricted => Ok(()),
            Self::Checked(rule) => rule(url),
        }
    }
}

impl std::fmt::Debug for BearerDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unrestricted => "Unrestricted",
            Self::Checked(_) => "Checked",
        })
    }
}

/// Static credential provider. Used by tests and by callers that pass a raw `&str` token with no `AuthManager` available.
///
/// `bearer` is the wire bearer the inner `HttpAuth` will send in the `Authorization` header.
/// Stored alongside the inner so `snapshot().token` returns the same prefix that goes out on the wire (used by 401-attribution telemetry).
/// `None` when no bearer is configured.
pub struct StaticAuthCredentialProvider {
    inner: Box<dyn HttpAuth>,
    bearer: Option<String>,
    destination: BearerDestination,
}

impl StaticAuthCredentialProvider {
    /// Wrap `inner` so callers see it as an `AuthCredentialProvider`.
    /// Pass the bearer token that `inner.apply()` will send in the `Authorization` header so `snapshot().token` reflects the wire bearer truthfully.
    /// `destination` is the P47 rule for that bearer: [`BearerDestination::Checked`] whenever it can be a session token.
    pub fn new(
        inner: Box<dyn HttpAuth>,
        bearer: Option<String>,
        destination: BearerDestination,
    ) -> Self {
        Self {
            inner,
            bearer,
            destination,
        }
    }
}

impl std::fmt::Debug for StaticAuthCredentialProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticAuthCredentialProvider")
            .field("has_bearer", &self.bearer.is_some())
            .field("destination", &self.destination)
            .finish()
    }
}

impl HttpAuth for StaticAuthCredentialProvider {
    fn apply(&self, builder: RequestBuilder, base_url: &str) -> RequestBuilder {
        self.inner.apply(builder, base_url)
    }
}

#[async_trait::async_trait]
impl AuthCredentialProvider for StaticAuthCredentialProvider {
    fn snapshot(&self) -> CredentialSnapshot {
        CredentialSnapshot {
            token: self.bearer.clone(),
            ..Default::default()
        }
    }

    async fn refresh_after_unauthorized(&self) -> bool {
        false
    }

    fn bearer_may_reach(
        &self,
        url: &reqwest::Url,
        _bearer: &str,
    ) -> Result<(), BearerDestinationRefused> {
        self.destination.check(url)
    }
}

#[cfg(test)]
mod p70_redacted_debug {
    use super::*;

    /// `{x:?}` and `{x:#?}` hold `<redacted>` (control) and no fragment of any secret.
    fn assert_redacted(debug: &dyn std::fmt::Debug, secrets: &[&str]) {
        for out in [format!("{debug:?}"), format!("{debug:#?}")] {
            assert!(out.contains("<redacted>"), "control: the secret field is printed as redacted: {out}");
            for secret in secrets {
                let chars: Vec<char> = secret.chars().collect();
                for w in chars.windows(6) {
                    let frag: String = w.iter().collect();
                    assert!(!out.contains(&frag), "Debug output holds {frag:?} of a secret: {out}");
                }
            }
        }
    }

    #[test]
    fn credential_snapshot_debug_redacts_the_token() {
        let snap = CredentialSnapshot {
            token: Some("p70tok-FAKE-0f1e2d3c".into()),
            user_id: Some("p70-user".into()),
            ..CredentialSnapshot::default()
        };
        assert_redacted(&snap, &["p70tok-FAKE-0f1e2d3c"]);
        assert!(format!("{snap:?}").contains("p70-user"));
    }
}
