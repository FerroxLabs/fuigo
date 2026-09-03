//! The Fuigo backend: Ferrox Labs OAuth2, enterprise OIDC, the operator's auth binary, or a devbox.

use std::sync::Arc;

use super::{AuthBackend, LoginRequest};
use crate::auth::refresh::{
    AuthSnapshot, DiagnosticUploader, ExternalBinaryRefresher, ExternalCommandRunner,
    OidcRefresher, TokenRefresher,
};
use crate::auth::{AuthManager, FuigoAuth, FuigoComConfig};

#[derive(Default)]
pub(crate) struct FuigoAuthBackend;

#[async_trait::async_trait(?Send)]
impl AuthBackend for FuigoAuthBackend {
    fn scope_key(&self, config: &FuigoComConfig) -> String {
        config.auth_scope()
    }

    /// Devbox auth files from before the OIDC flow wrote this key, and only this backend ever minted credentials into it.
    fn inherited_scopes(&self) -> &'static [&'static str] {
        &[crate::auth::model::LEGACY_SCOPE]
    }

    /// An Ferrox Labs login can come from OAuth2, a customer's own login provider, the auth binary, or a devbox, so there is no one issuer to check for.
    /// Saying yes to all of them is safe: a credential minted elsewhere still gets sent to Ferrox Labs, which rejects it.
    fn owns(&self, _auth: &FuigoAuth) -> bool {
        true
    }

    /// The session bearer goes only to a configured first-party origin.
    ///
    /// This used to return `true` for every URL, with the reasoning that "some
    /// customers run their own gateway and sign in there with the session we
    /// issued them, so a list of allowed hosts would lock them out". That was
    /// written when the trust set was the compiled-in vendor domain, and it no
    /// longer holds: `set_trusted_api_origins` seeds the set from the user's
    /// own `[endpoints]`, so a customer gateway is trusted *because they
    /// configured it*. The objection is answered without the hole.
    ///
    /// The hole was real. `resolve_credentials` reaches this arm for any model
    /// with no `api_key`/`env_key` and no `auth_provider`, which is every model
    /// that came from the remote catalogue. Those never pass through the
    /// `[model.*]` fail-closed guard in `resolve_model_list` (a prefetched map
    /// replaces `resolved` wholesale), so this predicate was the only thing
    /// standing between a third-party `base_url` and the session token — and it
    /// was not looking.
    ///
    /// `is_fuigo_api_bearer_url` is the strict form: https only, loopback
    /// refused. It is not purely configuration-derived, though: besides the
    /// configured `[endpoints]` origins it has a second arm,
    /// `is_trusted_cli_chat_proxy_url`, which trusts the compiled-in
    /// production cli-chat-proxy base regardless of what the user configured.
    /// That base is `fuigo_env::PROD_CLI_CHAT_PROXY_BASE_URL`, which is the
    /// empty string in this tree, and an empty base never parses as a URL, so
    /// the arm matches nothing here — with no `[endpoints]` installed the
    /// predicate is false for every URL and this fails closed. BYOK is
    /// unaffected — a model with its own credential never reaches this arm.
    fn may_receive_session(&self, url: &str) -> bool {
        crate::util::is_fuigo_api_bearer_url(url)
    }

    fn login_host(&self, config: &FuigoComConfig) -> String {
        super::host_of(&config.fuigo_ws_origin)
    }

    fn is_fuigo_authority(&self) -> bool {
        true
    }

    async fn login(&self, req: LoginRequest<'_>) -> anyhow::Result<(FuigoAuth, bool)> {
        crate::auth::flow::run_auth_flow_steps(
            req.auth_manager,
            req.fuigo_com_config,
            req.reauth,
            req.force_interactive,
            req.on_stderr,
            req.url_tx,
            req.code_rx,
            req.login_override,
        )
        .await
    }

    fn refresher(
        &self,
        manager: Arc<AuthManager>,
        auth_provider_command: Option<String>,
        diagnostic_uploader: Option<DiagnosticUploader>,
    ) -> Arc<dyn TokenRefresher> {
        match auth_provider_command {
            Some(cmd) => {
                let runner: Arc<dyn ExternalCommandRunner> = manager;
                Arc::new(ExternalBinaryRefresher::new(runner, cmd))
            }
            None => {
                let snapshot: Arc<dyn AuthSnapshot> = manager;
                let refresher = OidcRefresher::new(snapshot);
                match diagnostic_uploader {
                    Some(uploader) => Arc::new(refresher.with_diagnostic_upload(uploader)),
                    None => Arc::new(refresher),
                }
            }
        }
    }
}
