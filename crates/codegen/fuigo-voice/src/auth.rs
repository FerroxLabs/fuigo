//! Bearer resolution for voice STT requests.
//!
//! The voice clients are long-lived: a single voice session opens many STT connections over its lifetime.
//! An OAuth/session bearer rotates (~15 min), so capturing a token once at startup would 401 mid-session.
//! Instead of a static `String`, the clients hold a [`SharedVoiceAuth`] and resolve a bearer per request.
//!
//! Batch resolves twice, and deliberately: once when the session opens, as a
//! permission check on the endpoint, and again immediately before the upload.
//! A recording can run for five minutes and upload for two more, which is long
//! enough for a token fetched at press time to expire before it is used -- and
//! a POST carrying audio is not retried, so a 401 there costs the whole
//! utterance.
//!
//! # The credential is scoped to a destination
//!
//! [`VoiceAuthProvider::bearer_for`] takes the absolute URL the credential
//! would be sent to, and may answer `None`.
//!
//! This used to be a bare `bearer()` with no destination, which meant voice
//! handed the session bearer to whatever `[voice].api_base` named — bypassing
//! `is_fuigo_api_bearer_url`, the predicate that exists to decide exactly this.
//! Batch transcription makes the stakes plainer, because the request body is
//! the recording, but the hole applied to the streaming transport too.
//!
//! The check itself is not made here. This crate is dependency-light and has
//! no access to the shell's configured trust registry, so the *provider*
//! decides and this crate only guarantees that it is asked. The method is
//! named `bearer_for` rather than gaining a defaulted URL parameter so that
//! every implementor had to be updated rather than silently keeping the old
//! behaviour.

use std::future::{Future, ready};
use std::pin::Pin;
use std::sync::Arc;

#[cfg(feature = "audio")]
use crate::error::VoiceError;

pub trait VoiceAuthProvider: std::fmt::Debug + Send + Sync + 'static {
    /// Resolve a bearer for `endpoint`, the absolute URL the credential will be
    /// attached to.
    ///
    /// `None` means "not for that destination" and must be treated as a
    /// refusal, never as a transient failure to retry.
    fn bearer_for(
        &self,
        endpoint: &str,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>>;
}

/// Shared provider handed to the voice pipeline.
pub type SharedVoiceAuth = Arc<dyn VoiceAuthProvider>;

/// Resolve the bearer for `endpoint`, turning a refusal into a legible error.
///
/// The message names the endpoint, because the most likely cause of a refusal
/// is a `[voice].api_base` pointing somewhere the session credential is not
/// allowed to go — and an unattributed "not signed in" would send the user to
/// re-authenticate, which cannot fix it.
#[cfg(feature = "audio")]
pub(crate) async fn require_bearer(
    auth: &SharedVoiceAuth,
    endpoint: &str,
) -> Result<String, VoiceError> {
    auth.bearer_for(endpoint).await.ok_or_else(|| {
        VoiceError::Auth(format!(
            "no credential available for the voice endpoint {endpoint}. \
             Either you are not signed in (run `fuigo login`, set FUIGO_API_KEY, \
             or set a model api_key/env_key), or `[voice].api_base` names a host \
             this session's credential is not permitted to be sent to."
        ))
    })
}

/// A fixed bearer that never refreshes, and is **not scoped to a destination**.
///
/// Used by the standalone `voice-probe` binary and by tests, where there is no
/// `AuthManager` — only a raw key the operator passed on the same command line
/// as the endpoint. Choosing both together is the authorisation, so there is
/// nothing further for this type to check.
///
/// It is therefore not suitable for the pager, where the credential is a
/// session bearer the user never typed and the endpoint comes from a config
/// file. That path uses a provider that consults the configured trust registry.
pub struct StaticVoiceAuth(pub String);

impl std::fmt::Debug for StaticVoiceAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("StaticVoiceAuth")
            .field(&"<redacted>")
            .finish()
    }
}

impl VoiceAuthProvider for StaticVoiceAuth {
    fn bearer_for(
        &self,
        _endpoint: &str,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        Box::pin(ready(Some(self.0.clone())))
    }
}

impl StaticVoiceAuth {
    /// Build a [`SharedVoiceAuth`] from a static key, trimming whitespace and rejecting an empty value.
    pub fn shared(key: impl Into<String>) -> Option<SharedVoiceAuth> {
        let key = key.into().trim().to_string();
        if key.is_empty() {
            return None;
        }
        Some(Arc::new(Self(key)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_provider_resolves() {
        let provider = StaticVoiceAuth::shared("  sk-test  ").unwrap();
        assert_eq!(
            provider
                .bearer_for("https://api.example.com/v1")
                .await
                .as_deref(),
            Some("sk-test")
        );
    }

    /// Stated, not accidental: this provider is unscoped, and that is why it is
    /// confined to the probe binary and tests.
    #[tokio::test]
    async fn static_provider_is_not_endpoint_scoped() {
        let provider = StaticVoiceAuth::shared("sk-test").unwrap();
        assert!(
            provider
                .bearer_for("https://somewhere.else.example/v1")
                .await
                .is_some(),
            "StaticVoiceAuth answers for any endpoint by design"
        );
    }

    #[test]
    fn static_provider_rejects_empty() {
        assert!(StaticVoiceAuth::shared("   ").is_none());
    }

    /// A provider that declines must surface as an auth error naming the
    /// endpoint, not as a silent `None` the caller can mistake for "retry".
    #[cfg(feature = "audio")]
    #[tokio::test]
    async fn a_refusal_becomes_an_error_that_names_the_endpoint() {
        #[derive(Debug)]
        struct Refuses;
        impl VoiceAuthProvider for Refuses {
            fn bearer_for(
                &self,
                _endpoint: &str,
            ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
                Box::pin(ready(None))
            }
        }
        let auth: SharedVoiceAuth = Arc::new(Refuses);
        let err = require_bearer(&auth, "https://evil.example/v1/audio/transcriptions")
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("evil.example"), "{text}");
        assert!(text.contains("api_base"), "{text}");
    }
}
