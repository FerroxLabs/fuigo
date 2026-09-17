//! `fuigo/share_session` extension handler.
//!
//! Loads a local session, exports it, uploads the message payload to cloud storage via a signed URL, and asks the backend for a public share URL.
//! The signed URL lets large sessions bypass the proxy/backend body-size limits.
//! Best-effort metadata upload is fire-and-forget on the spawned task.

use agent_client_protocol as acp;

use super::{ExtResult, parse_params, to_raw_response};
use crate::agent::MvpAgent;
use crate::remote::client::BackendClient;
use crate::session::export::{ExportedMessage, ExportedSession};
use crate::session::info::Info as SessionInfo;
use crate::session::persistence::list_summaries;
use crate::session::share::{ShareSessionRequest, ShareSessionResponse};
use crate::upload::trace::{SessionMetadataType, upload_session_metadata};
use fuigo_telemetry::id::agent_id;

#[tracing::instrument(skip_all, fields(method = %args.method))]
pub async fn handle(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    match args.method.as_ref() {
        "fuigo/share_session" => {
            tracing::info!("handling share session request");
            handle_share_session(agent, args).await
        }
        _ => Err(crate::acp_error::unknown_ext_method(&args.method)),
    }
}

async fn handle_share_session(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    let request: ShareSessionRequest = parse_params(args)?;

    let auth = require_fuigo_auth_for_share(&agent.auth_manager)?;

    // Remote settings / feature-flag gate: sharing_enabled defaults to false and is only enabled for eligible accounts
    let sharing_enabled = agent
        .cfg
        .borrow()
        .remote_settings
        .as_ref()
        .and_then(|rs| rs.sharing_enabled)
        .unwrap_or(false);
    if !sharing_enabled {
        return Err(crate::acp_error::invalid_params(
            "Session sharing is not available for your account.",
        ));
    }

    // Only block for ZDR teams (hard data-retention policy), not for coding-data-retention opt-out; sharing is user-initiated
    if auth.is_zdr_team() {
        return Err(crate::acp_error::invalid_params(
            "Session sharing is disabled for your team's data retention policy",
        ));
    }

    // Find session info by searching through summaries
    let summaries = list_summaries(None)
        .await
        .map_err(|e| crate::acp_error::internal_error(format!("Failed to list sessions: {}", e)))?;

    let summary = summaries
        .iter()
        .find(|s| s.info.id.0.as_ref() == request.session_id.as_str())
        .ok_or_else(|| crate::acp_error::resource_not_found("Session not found"))?;

    // Get turn number from the summary we already loaded
    let current_turn = summary.next_trace_turn.saturating_sub(1);

    let info = SessionInfo {
        id: acp::SessionId::new(request.session_id.clone()),
        cwd: summary.info.cwd.clone(),
    };

    let exported = ExportedSession::from_local_session(&info)
        .await
        .map_err(|e| crate::acp_error::internal_error(format!("Failed to load session: {}", e)))?;

    if exported.messages.is_empty() {
        return Err(crate::acp_error::invalid_params("No messages to share yet"));
    }

    let client = BackendClient::new().with_auth_manager(agent.auth_manager.clone());

    // Obtain trace context once; used for the signed URL upload and then moved into the spawned metadata task
    let trace_context = agent.get_trace_context(&info, current_turn).await;

    // Upload session data to cloud storage via signed URL so large sessions don't hit the 413
    // body-size limit on the backend API -- but only once the share destination is known.
    // The ordering is the combinator's, not this block's, so it cannot be reordered away.
    upload_only_after_destination_resolves(client.share_link_origin(), || async {
        if let Some(ref ctx) = trace_context {
            upload_share_data_to_gcs(
                &request.session_id,
                &exported.messages,
                &ctx.gcs_config,
                Some(agent.auth_manager.clone()),
            )
            .await;
        }
    })
    .await?;

    // Upload to backend and get share URL.
    // The `save_session_data` call may fail with 413 for very large sessions; that is acceptable because the data is already in cloud storage
    let agent_id = agent_id();
    let share_url = client
        .share_session(&exported, &agent_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to share session with backend");
            crate::acp_error::internal_error(format!("Failed to share session: {}", e))
        })?;

    // Upload share metadata to cloud storage (best-effort, fire-and-forget).
    if let Some(mut ctx) = trace_context {
        ctx.gcs_config.gcs_prefix = None;
        tokio::spawn(async move {
            upload_session_metadata(&ctx, SessionMetadataType::Share).await;
        });
    }

    let response = ShareSessionResponse { share_url };
    to_raw_response(&response)
}

/// Fail closed BEFORE any upload: with no share backend or web origin configured there is
/// nothing to share to and nowhere to view it, so nothing may leave the machine, and the error
/// names the variable to set.
///
/// The ordering lives here rather than in statement order at the call site: `upload` is this
/// function's argument, so it is not expressible to run it before `destination` is resolved.
/// `share_upload_gate_tests` pins both directions.
async fn upload_only_after_destination_resolves<Fut>(
    destination: Result<String, crate::remote::client::BackendError>,
    upload: impl FnOnce() -> Fut,
) -> Result<String, acp::Error>
where
    Fut: std::future::Future<Output = ()>,
{
    let destination = destination.map_err(|e| {
        tracing::warn!(error = %e, "share unavailable: not configured");
        crate::acp_error::invalid_request(e.to_string())
    })?;
    upload().await;
    Ok(destination)
}

/// Upload session messages to cloud storage via signed URL (best-effort).
///
/// Serialises the messages to JSON and uploads them under `share/{session_id}_{timestamp}_data.json`.
/// On failure the error is logged as a warning; the caller is expected to fall back to the backend API.
async fn upload_share_data_to_gcs(
    session_id: &str,
    messages: &[ExportedMessage],
    gcs_config: &crate::session::repo_changes::TraceExportConfig,
    auth_manager: Option<std::sync::Arc<crate::auth::AuthManager>>,
) {
    let data_json = match serde_json::to_vec(messages) {
        Ok(json) => json,
        Err(e) => {
            tracing::warn!(
                session_id = %session_id,
                error = %e,
                "Failed to serialise share data"
            );
            return;
        }
    };

    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let gcs_path = format!("share/{}_{}_data.json", session_id, timestamp);

    use crate::upload::gcs::WithAuth as _;
    if let Err(e) = fuigo_file_utils::gcs::upload_bytes_signed(
        &gcs_config.with_auth(auth_manager),
        &gcs_path,
        &data_json,
        "application/json",
    )
    .await
    {
        tracing::warn!(
            session_id = %session_id,
            error = %e,
            "Failed to upload share data via signed URL, \
             falling back to backend API"
        );
    }
}

fn require_fuigo_auth_for_share(
    auth_manager: &crate::auth::AuthManager,
) -> Result<crate::auth::FuigoAuth, acp::Error> {
    super::auth_gate::require_fuigo_auth(
        auth_manager,
        "Authentication required to share session",
        "Share session is disabled. Run `fuigo login` to authenticate.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::FuigoComConfig;
    use crate::auth::{AuthMode, FuigoAuth};
    use chrono::{Duration, Utc};
    use std::sync::Arc;
    use tempfile::tempdir;

    fn make_auth_manager_with_token_expiring_in(
        ttl: Duration,
    ) -> (Arc<crate::auth::AuthManager>, tempfile::TempDir) {
        let dir = tempdir().expect("tempdir for share auth test");
        let mgr = Arc::new(crate::auth::AuthManager::new(
            dir.path(),
            FuigoComConfig::default(),
        ));

        let expires_at = Utc::now() + ttl;

        // We must explicitly set oidc_issuer to a first-party Ferrox Labs issuer.
        // Only OIDC tokens against https://auth.x.ai (or the local-dev equivalent) return true from is_fuigo_auth()
        // The share tests need that to exercise the happy path through require_fuigo_auth_for_share
        let auth = FuigoAuth {
            auth_mode: AuthMode::Oidc,
            oidc_issuer: Some("https://auth.x.ai".to_string()),
            key: "test-key".into(),
            expires_at: Some(expires_at),
            create_time: Utc::now() - Duration::hours(1),
            ..Default::default()
        };
        mgr.hot_swap(auth);
        (mgr, dir)
    }

    #[test]
    fn share_works_outside_the_5m_early_invalidation_window() {
        let (mgr, _dir) = make_auth_manager_with_token_expiring_in(Duration::minutes(10));
        assert!(mgr.current().is_some());
        assert!(require_fuigo_auth_for_share(&mgr).is_ok());
    }

    #[test]
    fn share_succeeds_inside_the_5m_early_invalidation_window() {
        let (mgr, _dir) = make_auth_manager_with_token_expiring_in(Duration::seconds(1));
        // The regression state: the token sits inside the early-invalidation buffer
        assert!(
            mgr.current().is_none(),
            "current() drops the token inside the buffer"
        );
        assert!(mgr.expired_auth().is_some());

        // require_fuigo_auth_for_share reads current_or_expired(), so this passes
        let res = require_fuigo_auth_for_share(&mgr);
        assert!(
            res.is_ok(),
            "require_fuigo_auth_for_share must succeed for a still-valid buffered Ferrox Labs token"
        );
    }

    #[test]
    fn share_fails_with_no_auth_at_all() {
        let dir = tempdir().expect("tempdir");
        let mgr = Arc::new(crate::auth::AuthManager::new(
            dir.path(),
            FuigoComConfig::default(),
        ));
        assert!(require_fuigo_auth_for_share(&mgr).is_err());
    }

    #[test]
    fn share_rejects_non_fuigo_auth_with_actionable_fuigo_login_message() {
        let dir = tempdir().expect("tempdir");
        let mgr = Arc::new(crate::auth::AuthManager::new(
            dir.path(),
            FuigoComConfig::default(),
        ));

        // API key is the simplest non-Ferrox Labs credential (External and enterprise OIDC are also rejected the same way)
        let non_fuigo = FuigoAuth {
            auth_mode: AuthMode::ApiKey,
            key: "fuigo-test-key".into(),
            create_time: Utc::now(),
            ..Default::default()
        };
        mgr.hot_swap(non_fuigo);

        let err = require_fuigo_auth_for_share(&mgr).expect_err(
            "non-Ferrox Labs accounts (API key, External, enterprise IdP) must be rejected",
        );

        // Test the *exact* actionable data message for the non-Ferrox Labs path (distinct from the generic "Authentication required to share session" path)
        let serialized =
            serde_json::to_value(&err).expect("acp::Error serializes to JSON-RPC shape");
        let data_obj = serialized
            .get("data")
            .expect("auth_required error carries data");
        assert_eq!(
            data_obj.get("error_kind").and_then(|v| v.as_str()),
            Some("auth")
        );
        let data = data_obj
            .get("message")
            .and_then(|v| v.as_str())
            .expect("typed data carries the message");

        assert_eq!(
            data,
            "Share session is disabled. Run `fuigo login` to authenticate."
        );
    }
}

/// The share handler's pre-upload ordering, pinned in both directions.
///
/// Statement order alone would not catch a reordering, so the ordering lives in
/// [`upload_only_after_destination_resolves`] and these tests watch the effect run (or not).
#[cfg(test)]
mod share_upload_gate_tests {
    use super::*;
    use crate::remote::client::BackendError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Not configured: the handler fails with a message naming the variable, and NOTHING is
    /// uploaded. This is the one that a reordering (guard after the upload) would break.
    #[tokio::test(flavor = "current_thread")]
    async fn share_uploads_nothing_when_the_destination_is_not_configured() {
        let uploads = AtomicUsize::new(0);
        let err = upload_only_after_destination_resolves(
            Err(BackendError::NotConfigured(
                "session share links need FUIGO_CODE_WEB_URL to be configured".to_string(),
            )),
            || async {
                uploads.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await
        .expect_err("an unconfigured share must fail");
        assert_eq!(
            uploads.load(Ordering::SeqCst),
            0,
            "session data must not leave the machine before the share destination is known"
        );
        let shown = format!("{err:?}");
        assert!(shown.contains("FUIGO_CODE_WEB_URL"), "{shown}");
        assert!(!shown.contains("grok.com"), "{shown}");
    }

    /// Configured: the upload runs exactly once, after the destination resolved, and the
    /// destination is handed back for the share URL.
    #[tokio::test(flavor = "current_thread")]
    async fn share_uploads_once_after_the_destination_resolves() {
        let uploads = AtomicUsize::new(0);
        let origin = upload_only_after_destination_resolves(
            Ok("https://share.example.test".to_string()),
            || async {
                uploads.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await
        .expect("a configured share must proceed");
        assert_eq!(uploads.load(Ordering::SeqCst), 1);
        assert_eq!(origin, "https://share.example.test");
    }
}
