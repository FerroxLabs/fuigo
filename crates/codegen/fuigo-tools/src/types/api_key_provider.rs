use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Auxiliary operation whose credential is being resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialPurpose {
    Voice,
    WebSearch,
    ImageGeneration,
    ImageEdit,
    VideoGeneration,
    VideoPoll,
}

/// Purpose and destination for one live credential decision.
#[derive(Debug, Clone, Copy)]
pub struct CredentialRequest<'a> {
    pub purpose: CredentialPurpose,
    pub recipient: &'a str,
    /// Model identity is meaningful only for model-backed tools such as web
    /// search. It lets a host preserve the model/provider credential pairing.
    pub model: Option<&'a str>,
}

/// Result of resolving a credential for a particular operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialResolution {
    Resolved(String),
    /// The provider does not own this route. A deliberately configured static
    /// credential/recipient pair may be used instead.
    UseConfigured,
    /// The provider owns or refuses this route, but has no admissible live
    /// credential. Callers must fail before dispatch and must not fall back.
    Denied,
}

/// Resolves the current API key for tool HTTP requests.
pub trait ApiKeyProvider: Send + Sync + 'static {
    /// Sync cached read (no refresh). Override point for static providers.
    fn current_api_key(&self) -> Option<String>;

    /// Per-request resolve. `AuthManager` overrides this to drive the
    /// refresh chain; default delegates to the sync method.
    fn current_api_key_async(&self) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        Box::pin(std::future::ready(self.current_api_key()))
    }

    /// Resolve a credential for a concrete auxiliary operation. Existing
    /// static providers retain their previous behavior: a present key wins,
    /// while `None` leaves an explicitly paired configured key available.
    /// Security-aware hosts override this to return [`CredentialResolution::Denied`]
    /// when a live credential is missing or the recipient is refused.
    fn credential_for(
        &self,
        _request: CredentialRequest<'_>,
    ) -> Pin<Box<dyn Future<Output = CredentialResolution> + Send + '_>> {
        Box::pin(async move {
            self.current_api_key_async()
                .await
                .map(CredentialResolution::Resolved)
                .unwrap_or(CredentialResolution::UseConfigured)
        })
    }
}

/// Shared provider used across tool clients.
pub type SharedApiKeyProvider = Arc<dyn ApiKeyProvider>;

/// Resolve the bearer for the next request. A security-aware provider's denial
/// is authoritative; only an absent provider or `UseConfigured` may use the
/// explicitly paired static credential.
pub(crate) async fn resolve_bearer(
    provider: Option<&SharedApiKeyProvider>,
    request: CredentialRequest<'_>,
    configured: Option<&str>,
) -> Option<String> {
    let configured = || {
        configured
            .map(str::trim)
            .filter(|key| !key.is_empty())
            .map(str::to_owned)
    };
    match provider {
        Some(provider) => match provider.credential_for(request).await {
            CredentialResolution::Resolved(key) => {
                let key = key.trim();
                (!key.is_empty()).then(|| key.to_owned())
            }
            CredentialResolution::UseConfigured => configured(),
            CredentialResolution::Denied => None,
        },
        None => configured(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MissingProvider;

    impl ApiKeyProvider for MissingProvider {
        fn current_api_key(&self) -> Option<String> {
            None
        }
    }

    #[tokio::test]
    async fn t04_static_provider_contract_preserves_explicit_configured_pair() {
        let provider: SharedApiKeyProvider = Arc::new(MissingProvider);
        let resolved = resolve_bearer(
            Some(&provider),
            CredentialRequest {
                purpose: CredentialPurpose::WebSearch,
                recipient: "https://search.example/v1/responses",
                model: Some("search-model"),
            },
            Some(" paired-key "),
        )
        .await;
        assert_eq!(resolved.as_deref(), Some("paired-key"));
    }
}
