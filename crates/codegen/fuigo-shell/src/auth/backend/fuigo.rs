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

    /// Some customers run their own gateway and sign in there with the session Ferrox Labs issued them, so a list of allowed hosts would lock them out.
    /// The models cache stops one backend's models from being used by another: it remembers the URL each entry came from and ignores the rest.
    fn may_receive_session(&self, _url: &str) -> bool {
        true
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
