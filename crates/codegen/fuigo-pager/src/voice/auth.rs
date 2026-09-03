//! Bridge the shell's `AuthManager` onto the voice crate's bearer provider.
//!
//! The voice channel reuses the same bearer the agent uses for chat, so there
//! is no separate env var. It is resolved per request: the agent's refreshing
//! manager in direct-spawn mode; in leader mode, a non-refreshing one adopts
//! the agent's rotated `auth.json` token under the file lock (see
//! [`crate::acp`]).
//!
//! # This is where the voice credential is scoped to a destination
//!
//! `VoiceAuthProvider::bearer_for` is asked about a specific URL, and this
//! implementation answers only for endpoints that pass
//! [`fuigo_shell::util::is_fuigo_api_bearer_url`] — the same predicate that
//! decides where a session bearer may be attached for chat.
//!
//! Before this check existed, voice resolved a bearer with no destination at
//! all, so `[voice].api_base` could name any HTTPS host and the session token
//! went there. With the batch transport the request body is the recording, so
//! the microphone audio went with it, but the credential leak applied to the
//! streaming transport just as much.
//!
//! The predicate is very nearly config-derived. Alongside the configured
//! `[endpoints]` origins it has one arm that consults no configuration at all:
//! `is_trusted_cli_chat_proxy_url`, the compiled-in production cli-chat-proxy
//! base. That base is `fuigo_env::PROD_CLI_CHAT_PROXY_BASE_URL`, which is the
//! empty string in this tree, and an empty base never parses as a URL, so the
//! arm matches nothing here. What is left does fail closed: until
//! `set_trusted_api_origins` has run, nothing is trusted and voice refuses
//! rather than guessing. In the ordinary case `[voice].api_base` is either
//! unset (and inherits `[endpoints].fuigo_api_base_url`, which is one of the
//! installed origins) or set to that same host, so this changes nothing for a
//! user who has not pointed voice somewhere else.

use std::future::{Future, ready};
use std::pin::Pin;
use std::sync::Arc;

use fuigo_tools::types::SharedApiKeyProvider;
use fuigo_voice::{SharedVoiceAuth, VoiceAuthProvider};

/// Adapts the shell's `ApiKeyProvider` onto [`VoiceAuthProvider`].
///
/// Resolves a token per request (never a static snapshot), so a long session follows the `AuthManager` instead of pinning a token that 401s.
struct AuthManagerVoiceAuth(SharedApiKeyProvider);

impl std::fmt::Debug for AuthManagerVoiceAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthManagerVoiceAuth")
    }
}

impl VoiceAuthProvider for AuthManagerVoiceAuth {
    fn bearer_for(
        &self,
        endpoint: &str,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        if !endpoint_may_receive_the_session_bearer(endpoint) {
            // Refused before the manager is even consulted, so a token is never
            // materialised for a destination it may not be sent to.
            tracing::warn!(
                endpoint = %endpoint,
                "refusing to send the session credential to a voice endpoint that is not a configured first-party origin"
            );
            return Box::pin(ready(None));
        }
        let provider = self.0.clone();
        Box::pin(async move { provider.current_api_key_async().await })
    }
}

/// Whether the session bearer may be attached to `endpoint`.
///
/// A thin named wrapper so the policy has one place, one name, and a test.
fn endpoint_may_receive_the_session_bearer(endpoint: &str) -> bool {
    fuigo_shell::util::is_fuigo_api_bearer_url(endpoint)
}

/// Build the voice bearer provider from the connection's `AuthManager`.
///
/// Works for every auth method: OAuth / grok.com / OIDC session tokens and `FUIGO_API_KEY` / per-model BYOK keys.
pub fn build_voice_auth(auth_manager: Arc<fuigo_shell::auth::AuthManager>) -> SharedVoiceAuth {
    Arc::new(AuthManagerVoiceAuth(
        fuigo_shell::auth::shared_api_key_provider(auth_manager),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fail-closed property — that nothing is trusted before
    /// `set_trusted_api_origins` runs — is NOT assertable here. The registry is
    /// a process-wide `OnceLock` and other tests in this binary install
    /// origins, so what is trusted depends on test ordering. It is pinned in
    /// its own single-purpose process instead:
    /// `fuigo-shell-base/tests/trust_fails_closed.rs`.
    ///
    /// What IS assertable here are the properties that hold whatever the trust
    /// set contains.
    #[test]
    fn plaintext_is_refused_even_for_a_host_that_may_be_trusted_over_https() {
        // Scheme matters independently of host: `is_trusted_fuigo_https_url`
        // rejects anything that is not `https` before it looks at the origin.
        assert!(!endpoint_may_receive_the_session_bearer(
            "http://api.fluxrouter.ai/v1/audio/transcriptions"
        ));
        assert!(!endpoint_may_receive_the_session_bearer(
            "ws://api.fluxrouter.ai/v1/stt"
        ));
    }

    /// Loopback is never a first-party origin: a co-located process could read
    /// a token sent to `http://localhost`, and the https spelling is refused
    /// too so a local proxy cannot become a credential sink.
    #[test]
    fn loopback_is_refused() {
        for endpoint in [
            "https://localhost:8443/v1/audio/transcriptions",
            "https://127.0.0.1:9000/v1/audio/transcriptions",
            "https://[::1]:9000/v1/audio/transcriptions",
            "http://localhost:8443/v1/audio/transcriptions",
        ] {
            assert!(
                !endpoint_may_receive_the_session_bearer(endpoint),
                "{endpoint} must not receive the session bearer"
            );
        }
    }

    /// A string that is not a URL cannot be an origin, so it cannot match one.
    #[test]
    fn unparseable_endpoints_are_refused() {
        for endpoint in ["", "   ", "not a url", "api.fluxrouter.ai"] {
            assert!(
                !endpoint_may_receive_the_session_bearer(endpoint),
                "{endpoint:?} must not receive the session bearer"
            );
        }
    }
}
