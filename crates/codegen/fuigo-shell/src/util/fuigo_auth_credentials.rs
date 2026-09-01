use reqwest::RequestBuilder;
use std::sync::Arc;
/// Deployment key (enterprise) sends bare `Bearer`, routed to management key auth.
/// User token (Ferrox Labs users) sends `Bearer` and `X-XAI-Token-Auth: xai-grok-cli`.
/// Deployment key takes precedence when both are present.
#[derive(Clone)]
pub struct FuigoAuthCredentials {
    pub user_token: Option<String>,
    pub deployment_key: Option<String>,
    pub alpha_test_key: Option<String>,
    auth_manager: Option<Arc<crate::auth::AuthManager>>,
}
impl std::fmt::Debug for FuigoAuthCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuigoAuthCredentials")
            .field(
                "user_token",
                &self.user_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "deployment_key",
                &self.deployment_key.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "mode",
                &if self.auth_manager.is_some() {
                    "live"
                } else {
                    "static"
                },
            )
            .finish()
    }
}
impl FuigoAuthCredentials {
    /// Static credentials from a snapshot token. No refresh capability.
    pub fn new(user_token: Option<String>) -> Self {
        Self {
            user_token,
            deployment_key: None,
            alpha_test_key: None,
            auth_manager: None,
        }
    }
    /// Live credentials backed by an `AuthManager`.
    /// `resolve_async()` refreshes from memory, then disk, then OIDC; `resolve()` reads the in-memory cache for sync contexts.
    pub fn with_auth_manager(mut self, am: Arc<crate::auth::AuthManager>) -> Self {
        self.auth_manager = Some(am);
        self
    }
    pub fn auth_manager(&self) -> Option<&Arc<crate::auth::AuthManager>> {
        self.auth_manager.as_ref()
    }
    /// Error hint for 401 responses.
    pub fn auth_error_hint(&self) -> &'static str {
        if self.deployment_key.is_some() {
            "Your FUIGO_DEPLOYMENT_KEY is invalid or expired. Please contact a team admin."
        } else if self.user_token.is_some() {
            "Your auth token is invalid or expired. Run `fuigo login` to re-authenticate."
        } else {
            "Not authenticated."
        }
    }
    /// Return a snapshot with the live token from the internal `AuthManager` if available, falling back to the static `user_token`.
    ///
    /// Uses `current_or_expired()` instead of `current()` so a token in the early-invalidation refresh window is still returned.
    /// Such a token is expired for proactive refresh but still accepted by the server.
    pub fn resolve(&self) -> FuigoAuthCredentials {
        if let Some(ref am) = self.auth_manager
            && let Some(auth) = am.current_or_expired()
        {
            let mut creds = self.clone();
            creds.user_token = Some(auth.key);
            creds
        } else {
            self.clone()
        }
    }
    /// Async resolve via the internal `AuthManager::get_valid_token()` (memory, then disk, then an active OIDC refresh).
    /// Falls back to sync `resolve()` on error so transient refresh failures don't drop the bearer.
    pub async fn resolve_async(&self) -> FuigoAuthCredentials {
        let Some(ref am) = self.auth_manager else {
            return self.clone();
        };
        match am.get_valid_token().await {
            Ok(key) => {
                let mut creds = self.clone();
                creds.user_token = Some(key);
                creds
            }
            Err(e) => {
                tracing::warn!(error = %e, "resolve_credentials_async: active resolve failed, using cached");
                self.resolve()
            }
        }
    }
    pub fn apply(&self, builder: RequestBuilder, base_url: &str) -> RequestBuilder {
        let builder = if let Some(ref key) = self.deployment_key {
            builder.header("Authorization", format!("Bearer {}", key))
        } else if let Some(ref token) = self.user_token {
            builder
                .header("Authorization", format!("Bearer {}", token))
                .header(
                    obfstr::obfstr!("X-XAI-Token-Auth"),
                    obfstr::obfstr!("xai-grok-cli"),
                )
        } else {
            builder
        };
        let _ = base_url;
        builder
    }
}
impl fuigo_auth::HttpAuth for FuigoAuthCredentials {
    fn apply(&self, builder: RequestBuilder, base_url: &str) -> RequestBuilder {
        FuigoAuthCredentials::apply(self, builder, base_url)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthManager, AuthMode, FuigoAuth, FuigoComConfig};
    use chrono::{Duration, Utc};
    use std::sync::Arc;
    fn make_manager_with_token(
        expires_at: chrono::DateTime<Utc>,
    ) -> (Arc<AuthManager>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mgr = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
        let auth = FuigoAuth {
            key: "test-bearer-token".into(),
            auth_mode: AuthMode::External,
            expires_at: Some(expires_at),
            create_time: Utc::now(),
            ..FuigoAuth::test_default()
        };
        mgr.hot_swap(auth);
        (mgr, dir)
    }
    #[test]
    fn resolve_returns_token_when_not_expired() {
        let (mgr, _dir) = make_manager_with_token(Utc::now() + Duration::hours(1));
        let creds = FuigoAuthCredentials::new(None).with_auth_manager(mgr);
        let resolved = creds.resolve();
        assert_eq!(resolved.user_token.as_deref(), Some("test-bearer-token"));
    }
    #[test]
    fn resolve_returns_token_during_early_invalidation_window() {
        let (mgr, _dir) = make_manager_with_token(Utc::now() + Duration::minutes(3));
        let creds = FuigoAuthCredentials::new(None).with_auth_manager(mgr.clone());
        assert!(mgr.current().is_none());
        assert!(mgr.current_or_expired().is_some());
        assert_eq!(
            creds.resolve().user_token.as_deref(),
            Some("test-bearer-token")
        );
    }
    #[test]
    fn resolve_returns_static_token_when_no_auth_manager() {
        let creds = FuigoAuthCredentials::new(Some("static-token".into()));
        assert_eq!(creds.resolve().user_token.as_deref(), Some("static-token"));
    }
    #[test]
    fn resolve_returns_none_when_no_token_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
        let creds = FuigoAuthCredentials::new(None).with_auth_manager(mgr);
        assert!(creds.resolve().user_token.is_none());
    }
}
