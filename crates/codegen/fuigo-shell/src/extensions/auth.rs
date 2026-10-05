//! `fuigo/auth/*` and legacy `fuigo/{get,set}ApiKey` extension handlers.
//!
//! These methods let the client read/write the API key via the agent and drive the OAuth login flow.
//! The agent is the single source of truth for `auth.json`.

use agent_client_protocol as acp;
use serde::{Deserialize, Serialize};

use super::{ExtResult, parse_params, to_raw_response};
use crate::agent::MvpAgent;
use crate::session::ExtMethodResult;

#[tracing::instrument(skip_all, fields(method = %args.method))]
pub async fn handle(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    match args.method.as_ref() {
        "fuigo/auth/getBearerToken" => handle_get_bearer_token(agent).await,
        "fuigo/getApiKey" => handle_get_api_key(),
        "fuigo/setApiKey" => handle_set_api_key(agent, args).await,
        "fuigo/auth/submit_code" => handle_submit_code(agent, args),
        "fuigo/auth/get_url" => handle_get_url(agent).await,
        "fuigo/auth/cancel" => handle_cancel(agent, args),
        "fuigo/auth/logout" => handle_logout(agent, args).await,
        "fuigo/auth/info" => handle_info(agent),
        "fuigo/auth/check_subscription" => handle_check_subscription(agent).await,
        _ => Err(crate::acp_error::unknown_ext_method(&args.method)),
    }
}

/// Stop an in-flight interactive login (device poll or loopback wait).
/// Calling it when nothing is waiting does nothing.
/// When `request_seq` is present, only that attempt is cancelled, so a delayed cancel cannot cancel a newer login that already replaced it.
fn handle_cancel(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    #[derive(Deserialize)]
    struct CancelParams {
        #[serde(default)]
        request_seq: Option<u64>,
    }
    let params: CancelParams =
        serde_json::from_str(args.params.get()).unwrap_or(CancelParams { request_seq: None });
    match params.request_seq {
        Some(seq) => agent.interactive_auth.cancel_for_client_seq(seq),
        None => agent.interactive_auth.cancel(),
    }
    to_raw_response(&serde_json::json!({ "cancelled": true }))
}

async fn handle_get_bearer_token(agent: &MvpAgent) -> ExtResult {
    // Fail closed for session tokens: desktop resume treats non-null as success.
    // Never return a hard-expired access token
    // Still return wire-valid session tokens and static user-supplied keys (process model key, env, or disk api_key)
    // That keeps non-session sessions working when AuthManager has no OIDC entry
    let token = match agent.auth_manager.get_valid_token().await {
        Ok(token) => Some(token),
        Err(_) => agent
            .auth_manager
            .current_wire_valid()
            .map(|a| a.key)
            .or_else(|| agent.auth_manager.static_api_key_for_export()),
    }
    // A key a client supplied in `authenticate` (P08) is never handed back over the wire, whichever branch found it.
    .filter(|key| !crate::agent::auth_method::is_runtime_api_key(key));
    ExtMethodResult::success(serde_json::json!({ "token": token }))
        .to_ext_response()
        .map_err(|e| crate::acp_error::internal_error(e.to_string()))
}

fn handle_get_api_key() -> ExtResult {
    // The environment or saved key only: a runtime key a client supplied in `authenticate` is never echoed back (P08).
    let key = crate::agent::auth_method::read_fuigo_api_key_echoable().ok();
    ExtMethodResult::success(serde_json::json!({ "key": key }))
        .to_ext_response()
        .map_err(|e| crate::acp_error::internal_error(e.to_string()))
}

async fn handle_set_api_key(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    let params: serde_json::Value = parse_params(args)?;
    let key = params.get("key").and_then(|v| v.as_str());
    let fuigo_home = crate::util::fuigo_home::fuigo_home();
    if let Some(k) = key {
        if k.is_empty() {
            crate::auth::clear_api_key_async(&fuigo_home)
                .await
                .map_err(|e| crate::acp_error::internal_error(e.to_string()))?;
            crate::agent::auth_method::apply_set_api_key(None);
        } else {
            crate::auth::store_api_key_async(&fuigo_home, k)
                .await
                .map_err(|e| crate::acp_error::internal_error(e.to_string()))?;
            // P70: held in memory, ahead of the env key exactly as the `set_var` it replaces overwrote it, but never
            // in the agent's environment, so no child process inherits it.
            crate::agent::auth_method::apply_set_api_key(Some(k));
        }
    } else {
        crate::auth::clear_api_key_async(&fuigo_home)
            .await
            .map_err(|e| crate::acp_error::internal_error(e.to_string()))?;
        crate::agent::auth_method::apply_set_api_key(None);
    }
    // P08: only once the write succeeded (a failed set keeps the working credential), and with no await between the
    // two steps: an explicit set or clear supersedes a runtime key from `authenticate`, which would otherwise shadow
    // it, and drops the agent's copy of that key so the next `authenticate` re-resolves from the current sources.
    if let Some(previous) = crate::agent::auth_method::set_runtime_api_key(None) {
        let mut sampling_config = agent.sampling_config.borrow_mut();
        if sampling_config.api_key.as_deref() == Some(previous.as_str()) {
            sampling_config.api_key = None;
        }
        drop(sampling_config);
        // The AuthManager's process static key may hold the same key through a model `env_key = "FUIGO_API_KEY"`
        // mapping; re-derive it from the now-current sources so `getBearerToken` cannot hand the cleared key out.
        agent.sync_process_static_api_key(None);
    }
    ExtMethodResult::success(serde_json::json!({ "ok": true }))
        .to_ext_response()
        .map_err(|e| crate::acp_error::internal_error(e.to_string()))
}

/// Handles an auth code submitted from the TUI.
fn handle_submit_code(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    #[derive(Deserialize)]
    struct SubmitCodeParams {
        code: String,
    }

    let params: SubmitCodeParams = serde_json::from_str(args.params.get())
        .map_err(|e| crate::acp_error::invalid_params(format!("invalid params: {e}")))?;

    match agent.interactive_auth.submit_code(params.code) {
        Ok(()) => to_raw_response(&serde_json::json!({ "submitted": true })),
        Err(crate::auth::single_flight::SubmitCodeError::SendFailed(e)) => Err(
            crate::acp_error::internal_error(format!("failed to submit auth code: {e}")),
        ),
        Err(crate::auth::single_flight::SubmitCodeError::NoPendingAttempt) => {
            Err(crate::acp_error::invalid_params("no pending auth session"))
        }
    }
}

/// Awaits the auth URL from the oneshot channel (blocks until ready).
async fn handle_get_url(agent: &MvpAgent) -> ExtResult {
    let rx = agent.interactive_auth.take_url_rx();
    // `None` when no URL was sent (cached credentials, early error, second poll): report mode as `null` rather than mislabeling it `loopback`
    let (auth_url, mode) = match rx {
        Some(rx) => match rx.await {
            Ok(info) => (Some(info.url), Some(info.mode)),
            Err(_) => (None, None),
        },
        None => (None, None),
    };
    to_raw_response(&serde_json::json!({
        "auth_url": auth_url,
        // `external_provider` kept for older clients; `mode` is authoritative.
        "external_provider": mode.is_some_and(|m| m.is_external_provider()),
        "mode": mode.map(|m| m.as_wire_str()),
    }))
}

async fn handle_logout(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    #[derive(Deserialize)]
    struct LogoutParams {
        scope: Option<String>,
    }

    let params: LogoutParams = serde_json::from_str(args.params.get())
        .map_err(|e| crate::acp_error::invalid_params(format!("invalid params: {e}")))?;

    // Stop any in-flight login so it cannot write credentials back after logout.
    agent.interactive_auth.cancel();

    let result = crate::auth::perform_logout(&agent.auth_manager, params.scope.as_deref())
        .map_err(|e| crate::acp_error::internal_error(format!("failed to logout: {e}")))?;
    // `auth.lifecycle` (not `auth`) avoids colliding with the pre-existing per-request `AuthManager::auth()` `#[instrument]` span
    tracing::info_span!("auth.lifecycle", action = "logout", success = true).in_scope(|| {});

    agent.models_manager.on_auth_changed().await;

    to_raw_response(&serde_json::json!({
        "ok": true,
        "was_logged_in": result.was_logged_in,
        "email": result.email,
        "api_key_still_set": result.api_key_still_set,
    }))
}

/// Re-checks the subscription once, for the retry button on the paywall screen.
/// Returns the updated auth response with gate info so the pager can refresh the gate state.
async fn handle_check_subscription(agent: &MvpAgent) -> ExtResult {
    agent.retry_subscription_check().await;
    let response = agent.auth_response_with_meta();
    to_raw_response(&serde_json::json!({
        "authenticated": response.meta.is_some(),
        "meta": response.meta,
    }))
}

/// Returns current auth method ID, user profile fields, and team/principal metadata.
fn handle_info(agent: &MvpAgent) -> ExtResult {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AuthInfoResponse {
        method_id: Option<String>,
        email: Option<String>,
        first_name: Option<String>,
        last_name: Option<String>,
        /// `fuigo-asset://` URL resolved by the Electron protocol handler, or a full `http(s)://` URL passed through unchanged.
        profile_image_url: Option<String>,
        team_id: Option<String>,
        team_name: Option<String>,
        team_role: Option<String>,
        organization_id: Option<String>,
        organization_name: Option<String>,
        organization_role: Option<String>,
        principal_type: Option<String>,
        principal_id: Option<String>,
        user_blocked_reason: Option<String>,
        team_blocked_reasons: Vec<String>,
        coding_data_retention_opt_out: bool,
    }

    let method_id = agent
        .auth_method_id
        .load()
        .as_ref()
        .map(|m| m.0.to_string());
    let auth = agent.auth_manager.current_or_expired();
    let raw_asset_id = auth.as_ref().and_then(|a| a.profile_image_asset_id.clone());

    // Return a fuigo-asset:// URL that the Electron renderer resolves at display time via a custom protocol handler
    // The handler proxies through cli-chat-proxy's /asset endpoint; Electron's HTTP cache handles reuse
    // Nothing here touches a disk cache or the network
    let profile_image_url = match raw_asset_id.as_deref().filter(|k| !k.is_empty()) {
        Some(key) if key.starts_with("http://") || key.starts_with("https://") => {
            Some(key.to_owned())
        }
        Some(key) => Some(format!("fuigo-asset:///{key}")),
        None => None,
    };
    to_raw_response(&AuthInfoResponse {
        method_id,
        email: auth.as_ref().and_then(|a| a.email.clone()),
        first_name: auth.as_ref().and_then(|a| a.first_name.clone()),
        last_name: auth.as_ref().and_then(|a| a.last_name.clone()),
        profile_image_url,
        team_id: auth.as_ref().and_then(|a| a.team_id.clone()),
        team_name: auth.as_ref().and_then(|a| a.team_name.clone()),
        team_role: auth.as_ref().and_then(|a| a.team_role.clone()),
        organization_id: auth.as_ref().and_then(|a| a.organization_id.clone()),
        organization_name: auth.as_ref().and_then(|a| a.organization_name.clone()),
        organization_role: auth.as_ref().and_then(|a| a.organization_role.clone()),
        principal_type: auth.as_ref().and_then(|a| a.principal_type.clone()),
        principal_id: auth.as_ref().and_then(|a| a.principal_id.clone()),
        user_blocked_reason: auth.as_ref().and_then(|a| a.user_blocked_reason.clone()),
        team_blocked_reasons: auth
            .as_ref()
            .map(|a| a.team_blocked_reasons.clone())
            .unwrap_or_default(),
        // With no credential the privacy state is unknown, so report opted-out (fail closed)
        // This matches `AuthManager::allows_data_collection` and the FuigoAuth Default
        coding_data_retention_opt_out: auth
            .as_ref()
            .map(|a| a.coding_data_retention_opt_out)
            .unwrap_or_else(crate::auth::default_coding_data_retention_opt_out),
    })
}
