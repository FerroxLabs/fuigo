use agent_client_protocol as acp;

use crate::auth::{AuthManager, FuigoAuth};

/// Require Ferrox Labs auth from a sync context: with no `.await` to refresh, a token inside the client's early-invalidation buffer still counts.
pub(crate) fn require_fuigo_auth(
    auth_manager: &AuthManager,
    missing_message: &'static str,
    non_fuigo_message: &'static str,
) -> Result<FuigoAuth, acp::Error> {
    let auth = auth_manager
        .current_or_expired()
        .ok_or_else(|| crate::acp_error::auth_required(missing_message))?;
    if !auth.is_fuigo_auth() {
        return Err(crate::acp_error::auth_required(non_fuigo_message));
    }
    Ok(auth)
}
