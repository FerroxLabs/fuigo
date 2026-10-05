//! `fuigo/feedback`, `fuigo/feedback/dismiss`, `fuigo/btw`, and `fuigo/review/*` extension handlers.
//!
//! - `feedback` and `feedback/dismiss`: persist user ratings and text locally and forward to cli-chat-proxy.
//! - `btw`: routed to [`super::btw`] (side question with optional attached images).
//! - `review/comment` and `review/comment/delete`: record inline code review events to cloud storage.
use super::{ExtResult, parse_params};
use crate::agent::MvpAgent;
use crate::session::persistence::{LocalFeedbackEntry, UserFeedbackEntry};
use crate::session::{
    ClientFeedbackInput, CommentDeleteRequest, CommentDeleteResponse, CommentRequest,
    CommentResponse, FeedbackRequestDismiss, FeedbackResponse, SessionCommand,
};
use crate::upload::gcs::WithAuth as _;
use agent_client_protocol as acp;
use fuigo_file_utils::gcs::upload_bytes;
use fuigo_telemetry::id::agent_id;
use std::sync::Arc;
#[tracing::instrument(skip_all, fields(method = %args.method))]
pub async fn handle(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    match args.method.as_ref() {
        "fuigo/btw" => {
            tracing::info!("handling /btw side question");
            super::btw::handle_btw(agent, args).await
        }
        "fuigo/feedback" | "fuigo/feedback/dismiss" => {
            tracing::info!("handling user feedback");
            handle_feedback(agent, args).await
        }
        "fuigo/feedback/upload-trace" => handle_upload_trace(agent, args).await,
        m if m.starts_with("fuigo/review") => {
            tracing::info!("handling review comment");
            handle_review(agent, args).await
        }
        _ => Err(crate::acp_error::unknown_ext_method(&args.method)),
    }
}
async fn handle_feedback(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    if !agent.cfg.borrow().is_feedback_enabled() {
        return Err(crate::acp_error::internal_error(
            "Feedback is disabled. To enable, set FUIGO_FEEDBACK_ENABLED=true or \
             [features] feedback = true in config.toml.",
        ));
    }
    match args.method.as_ref() {
        "fuigo/feedback" => {
            let mut feedback_input: ClientFeedbackInput =
                match serde_json::from_str::<ClientFeedbackInput>(args.params.get()) {
                    Ok(input) => input,
                    Err(_) => {
                        let simple: crate::session::FeedbackRequest = parse_params(args)?;
                        ClientFeedbackInput {
                            session_id: simple.session_id,
                            client_type:
                                prod_mc_cli_chat_proxy_types::feedback_types::ClientType::Tui,
                            rating_type: None,
                            rating_value: None,
                            feedback_text: Some(simple.feedback_text),
                            images: vec![],
                            feedback_categories: vec![],
                            context_type: None,
                            turn_number: None,
                            request_id: None,
                            client_version: None,
                            metadata: None,
                            terminal_info: None,
                        }
                    }
                };
            if let Err(e) = prod_mc_cli_chat_proxy_types::feedback_types::validate_feedback_images(
                &feedback_input.images,
            ) {
                return Err(crate::acp_error::invalid_params(format!(
                    "feedback images: {e}"
                )));
            }
            let session_id = acp::SessionId::new(feedback_input.session_id.clone());
            let session_handle = agent.resident_handle(&session_id);
            let (model_id, model_metadata) = if let Some(ref session) = session_handle {
                let (tx1, rx1) = tokio::sync::oneshot::channel();
                let _ = session
                    .cmd_tx
                    .send(SessionCommand::GetCurrentModel { responds_to: tx1 });
                let model_id = rx1.await.ok();
                let model_metadata = session.get_model_metadata().await;
                (model_id, model_metadata)
            } else {
                let sampling_config = agent.sampling_config.borrow().clone();
                (Some(sampling_config.model.clone()), Default::default())
            };
            let turn_number = feedback_input.turn_number.or_else(|| {
                agent
                    .session_turn_number(&session_id)
                    .map(|t| t.saturating_sub(1) as i64)
            });
            let mut submission = feedback_input.take_submission(
                model_id.clone(),
                model_metadata.resolved_model_id,
                model_metadata.model_fingerprint,
                turn_number,
            );
            let turn_number = submission.turn_number;
            if let Some(ref session_handle) = session_handle {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let _ = session_handle
                    .cmd_tx
                    .send(SessionCommand::GetFeedbackContext {
                        turn_number,
                        responds_to: tx,
                    });
                if let Ok(ctx) = rx.await {
                    submission.tool_outcomes = ctx.tool_outcomes;
                    submission.session_cwd = Some(ctx.session_cwd);
                    submission.compaction_count = Some(ctx.compaction_count);
                    submission.context_window_usage = Some(ctx.context_window_usage);
                    submission.context_tokens_used = Some(ctx.context_tokens_used);
                    submission.context_window_tokens = Some(ctx.context_window_tokens);
                }
            }
            if let (Some(session_handle), Some(rating_value)) =
                (&session_handle, feedback_input.rating_value)
            {
                use prod_mc_cli_chat_proxy_types::feedback_types::RatingType;
                let (is_positive, is_negative) = match feedback_input.rating_type {
                    Some(RatingType::Thumbs) | None => (rating_value > 0, rating_value < 0),
                    Some(RatingType::Stars) => (rating_value >= 4, rating_value <= 2),
                    Some(RatingType::Nps) => (rating_value >= 9, rating_value <= 6),
                };
                if is_positive {
                    session_handle.signals_handle.record_positive_rating();
                } else if is_negative {
                    session_handle.signals_handle.record_negative_rating();
                }
            }
            if feedback_input.is_solicited() {
                tracing::info!(
                    session_id = %feedback_input.session_id,
                    request_id = ?feedback_input.request_id(),
                    turn_number = ?turn_number,
                    "Solicited feedback received (response to feedback request)"
                );
            } else {
                tracing::info!(
                    session_id = %feedback_input.session_id,
                    turn_number = ?turn_number,
                    "Spontaneous user feedback received"
                );
            }
            let telemetry_enabled = {
                let cfg = agent.cfg.borrow();
                cfg.is_telemetry_enabled()
                    && !agent
                        .auth_manager
                        .current_or_expired()
                        .is_some_and(|a| a.is_zdr_team())
            };
            let client = agent.feedback_client();
            if client.is_none() {
                tracing::warn!(
                    "no feedback client available (missing proxy credentials); feedback saved locally only"
                );
            }
            let user_cfg = agent.cfg.borrow().feedback.user.clone();
            let author_identity =
                crate::util::user_identity::cached_identity(user_cfg.as_ref()).await;
            let outcome = crate::session::feedback_manager::submit_feedback_workflow(
                &mut submission,
                client.as_ref(),
                session_handle.as_ref().map(|h| &h.persistence_tx),
                crate::session::feedback_manager::SubmitFeedbackOptions {
                    solicited: feedback_input.is_solicited(),
                    telemetry_enabled,
                    author_identity,
                },
            )
            .await;
            match &outcome {
                crate::session::feedback_manager::SubmitOutcome::Submitted => {
                    tracing::info!("feedback submitted to proxy successfully");
                }
                crate::session::feedback_manager::SubmitOutcome::LocalOnly => {
                    tracing::warn!("feedback saved locally only (no proxy client)");
                }
                crate::session::feedback_manager::SubmitOutcome::Failed(e) => {
                    tracing::error!(error = %e, "feedback submission to proxy failed");
                    return Err(crate::acp_error::internal_error(format!(
                        "Feedback submission failed: {e}"
                    )));
                }
            }
            let value = serde_json::to_value(FeedbackResponse { success: true })
                .map(|value| serde_json::value::to_raw_value(&value).map(Arc::from))
                .expect("to work")
                .expect("to work");
            Ok(acp::ExtResponse::new(value))
        }
        "fuigo/feedback/dismiss" => {
            let dismiss_input: FeedbackRequestDismiss = parse_params(args)?;
            tracing::info!(
                session_id = %dismiss_input.session_id,
                request_id = %dismiss_input.request_id,
                "Feedback request dismissed by user"
            );
            let telemetry_enabled = {
                let cfg = agent.cfg.borrow();
                cfg.is_telemetry_enabled()
                    && !agent
                        .auth_manager
                        .current_or_expired()
                        .is_some_and(|a| a.is_zdr_team())
            };
            if telemetry_enabled {
                tracing::info_span!(
                    "feedback.survey",
                    survey_type = "session",
                    event_type = "dismissed",
                    appearance_id = %dismiss_input.request_id,
                    has_feedback_text = false,
                    is_solicited = true,
                )
                .in_scope(|| {});
            }
            {
                let session_id = acp::SessionId::new(dismiss_input.session_id.clone());
                if let Some(session_handle) = agent.resident_handle(&session_id) {
                    session_handle.persist_feedback(LocalFeedbackEntry::UserFeedback(
                        UserFeedbackEntry {
                            submitted_at: chrono::Utc::now(),
                            session_id: dismiss_input.session_id.clone(),
                            turn_number: None,
                            solicited: true,
                            request_id: Some(dismiss_input.request_id.clone()),
                            dismissed: true,
                            submission: None,
                        },
                    ));
                }
            }
            let request_id = dismiss_input.request_id.clone();
            let client = agent
                .feedback_client()
                .ok_or_else(|| crate::acp_error::internal_error("No credentials for feedback"))?;
            let feedback_base_url = agent.cfg.borrow().endpoints.resolve_feedback_base_url();
            match client.dismiss_request(&request_id).await {
                Ok(response) => {
                    tracing::info!(
                        request_id = %response.request_id,
                        status = %response.status,
                        feedback_url = %feedback_base_url,
                        "Feedback request dismissed"
                    );
                    let value = serde_json::to_value(&response)
                        .map(|value| serde_json::value::to_raw_value(&value).map(Arc::from))
                        .expect("to work")
                        .expect("to work");
                    Ok(acp::ExtResponse::new(value))
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        request_id = %request_id,
                        feedback_url = %feedback_base_url,
                        "Failed to dismiss feedback request"
                    );
                    Err(crate::acp_error::internal_error(format!(
                        "Failed to dismiss feedback request: {e}"
                    )))
                }
            }
        }
        _ => Err(crate::acp_error::unknown_ext_method(&args.method)),
    }
}
/// Bounds the one-shot GCS upload so a stalled connection can't hang the ACP handler; sized for the 50 MiB archive cap on a slow uplink.
const FEEDBACK_TRACE_UPLOAD_TIMEOUT_SECS: u64 = 120;
async fn handle_upload_trace(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct UploadTraceRequest {
        session_id: String,
    }
    let req: UploadTraceRequest = parse_params(args)?;
    if !agent.cfg.borrow().is_feedback_enabled()
        || agent
            .auth_manager
            .current_or_expired()
            .is_some_and(|a| a.is_zdr_team())
        || agent.team_blocks_one_shot_trace_upload()
    {
        return Err(crate::acp_error::internal_error(
            "trace upload is not available",
        ));
    }
    if !agent.feedback_trace_offer() && !agent.cfg.borrow().is_trace_upload_enabled() {
        return Err(crate::acp_error::internal_error(
            "trace upload is not available",
        ));
    }
    let sid: acp::SessionId = req.session_id.clone().into();
    if agent.resident_handle(&sid).is_none() {
        return Err(crate::acp_error::invalid_params(format!(
            "session not found: {}",
            req.session_id
        )));
    }
    let Some(session_dir) = crate::session::persistence::find_session_dir_by_id(&req.session_id)
    else {
        return Err(crate::acp_error::invalid_params(
            "session directory not found",
        ));
    };
    // Resolve the destination first: identity in the packed files follows it (P54).
    let Some(gcs_config) = agent
        .one_shot_feedback_gcs_config(req.session_id.clone())
        .await
    else {
        return Err(crate::acp_error::internal_error(
            "trace upload is not available",
        ));
    };
    send_feedback_archive(
        session_dir,
        req.session_id.clone(),
        gcs_config,
        Some(agent.auth_manager.clone()),
    )
    .await
}

/// Pack `session_dir` and upload it as the one-shot feedback archive.
///
/// The handler resolves the session and the destination; everything that moves bytes is here, so a
/// test can drive it against a mock storage endpoint.
pub(crate) async fn send_feedback_archive(
    session_dir: std::path::PathBuf,
    session_id_owned: String,
    gcs_config: crate::session::repo_changes::TraceExportConfig,
    auth_manager: Option<std::sync::Arc<crate::auth::AuthManager>>,
) -> ExtResult {
    // P71: a destination that may not receive file content gets nothing, so do not read or pack the
    // session directory for it. (`upload_bytes` below enforces the same rule for every caller.)
    fuigo_file_utils::destination_gate::gate_upload_as(
        fuigo_file_utils::destination_gate::WithheldKind::FeedbackArchive,
        &gcs_config.upload_method,
        &format!("{}/feedback_trace.tar.gz", session_id_owned),
    )
    .map_err(|e| crate::acp_error::internal_error(format!("trace upload withheld: {e:#}")))?;
    let destination = archive_destination(&gcs_config.upload_method);
    let session_id = session_id_owned.clone();
    let archive = tokio::task::spawn_blocking({
        let session_dir = session_dir.clone();
        move || {
            crate::upload::feedback_archive::build_session_archive(
                &session_dir,
                &session_id,
                &destination,
            )
        }
    })
    .await
    .map_err(|e| crate::acp_error::internal_error(format!("couldn't build session archive: {e}")))?
    .map_err(|e| {
        crate::acp_error::internal_error(format!("couldn't build session archive: {e}"))
    })?;
    let object_path = format!("{}/feedback_trace.tar.gz", session_id_owned);
    use crate::upload::gcs::WithAuth as _;
    match tokio::time::timeout(
        std::time::Duration::from_secs(FEEDBACK_TRACE_UPLOAD_TIMEOUT_SECS),
        fuigo_file_utils::gcs::upload_bytes(
            &gcs_config.with_auth(auth_manager),
            &object_path,
            &archive,
            "application/gzip",
        ),
    )
    .await
    {
        Ok(Ok(_)) => super::to_ext_response(Ok(serde_json::json!({
            "uploaded": true,
            "objectPath": object_path,
        }))),
        Ok(Err(e)) => Err(crate::acp_error::internal_error(format!(
            "trace upload failed: {e:#}"
        ))),
        Err(_) => Err(crate::acp_error::internal_error("trace upload timed out")),
    }
}
/// Record inline code review events.
///
/// P54: the URL a one-shot feedback archive's identity is decided on: the storage proxy it is
/// uploaded through. `one_shot_feedback_gcs_config` refuses every other method today; if one is
/// ever returned, the empty destination withholds identity (fails closed).
fn archive_destination(upload_method: &fuigo_file_utils::upload_config::UploadMethod) -> String {
    use fuigo_file_utils::upload_config::UploadMethod;
    match upload_method {
        UploadMethod::Proxy { proxy_base_url, .. } => proxy_base_url.clone(),
        UploadMethod::Direct { .. } | UploadMethod::S3 { .. } => String::new(),
    }
}

/// P54: add `agentId` (the persisted machine id) to a review-comment record only where the
/// record's destination may receive it.
///
/// * `Direct` (GCS with a configured service-account key) and `S3` (configured bucket and
///   credentials) are the operator's own storage, configured for exactly this trace data: kept.
/// * `Proxy` uploads through the operator-configured storage proxy, the auxiliary-service class
///   P43 gates: the id goes as is only when that proxy is FluxRouter-operated. Any other proxy
///   receives `IdentityDisclosure::body_key_for(proxy, id)`, the SAME origin-scoped pseudonym the
///   session's `hunk_records.jsonl` carries to that proxy in a feedback archive
///   (`upload::feedback_archive::withhold_loc_identity`), so a create record, its delete
///   tombstone and the LOC records of one session keep one stable machine key there (P54-K:
///   P54 omitted the field, which broke any consumer joining or requiring it). Where a session's
///   archive is also uploaded the proxy already holds this key; a deployment-key configuration
///   uploads comments but never one-shot archives (`one_shot_feedback_gcs_config`), so there this
///   is a new, pseudonymous, origin-scoped machine key — within the P54 policy ("nothing or a
///   per-origin pseudonym"), and the operator's own proxy.
pub(crate) fn stamp_review_agent_id(
    record: &mut serde_json::Value,
    upload_method: &fuigo_file_utils::upload_config::UploadMethod,
    agent_id: &str,
) {
    use fuigo_file_utils::upload_config::UploadMethod;
    let kept = match upload_method {
        UploadMethod::Direct { .. } | UploadMethod::S3 { .. } => agent_id.to_owned(),
        UploadMethod::Proxy { proxy_base_url, .. } => {
            fuigo_extra_ca::fluxrouter::IdentityDisclosure::body_key_for(proxy_base_url, agent_id)
        }
    };
    if let Some(map) = record.as_object_mut() {
        map.insert("agentId".into(), serde_json::Value::String(kept));
    }
}

/// Upload one `fuigo/review/*` record (`event` is `"create"` for a comment, `"delete"` for the tombstone of a
/// deleted one) to cloud storage. Best-effort: a failure is logged, never surfaced.
///
/// Both review handlers send through here, so a test can drive the upload against a mock storage endpoint
/// (P71: a storage proxy that is not FluxRouter-operated receives nothing; `upload_bytes` enforces it).
pub(crate) async fn upload_review_record(
    gcs_config: crate::session::repo_changes::TraceExportConfig,
    auth_manager: Option<Arc<crate::auth::AuthManager>>,
    gcs_path: String,
    json_bytes: Vec<u8>,
    event: &'static str,
) {
    match upload_bytes(
        &gcs_config.with_auth(auth_manager),
        &gcs_path,
        &json_bytes,
        "application/json",
    )
    .await
    {
        Ok(gcs_url) => {
            tracing::info!(gcs_url = %gcs_url, event, "Review comment record uploaded to GCS");
        }
        Err(e) => {
            tracing::warn!(error = %e, gcs_path, event, "Failed to upload review comment record to GCS");
        }
    }
}

/// Methods:
/// - `fuigo/review/comment`: record a new inline code comment to cloud storage
/// - `fuigo/review/comment/delete`: record a tombstone event for a deleted comment
async fn handle_review(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    match args.method.as_ref() {
        "fuigo/review/comment" => {
            let request: CommentRequest = parse_params(args)?;
            let comment_id = uuid::Uuid::now_v7().to_string();
            tracing::info!(
                comment_id = %comment_id,
                session_id = %request.session_id,
                prompt_index = request.prompt_index,
                path = %request.citation.path,
                lines = %format!("{}-{}", request.citation.start_line, request.citation.end_line),
                "Comment received"
            );
            if let Some(gcs_config) = agent
                .build_gcs_config(format!("{}/comments", request.session_id))
                .await
            {
                let mut record = serde_json::json!({
                    "event": "create",
                    "commentId": comment_id,
                    "sessionId": request.session_id,
                    "promptIndex": request.prompt_index,
                    "comment": null,
                    "citation": request.citation,
                    "clientType": format!("{:?}", agent.client_type()),
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });
                stamp_review_agent_id(&mut record, &gcs_config.upload_method, &agent_id());
                let json_bytes = serde_json::to_vec_pretty(&record)
                    .map_err(|e| crate::acp_error::internal_error(e.to_string()))?;
                let gcs_path = format!(
                    "{}/{}.json",
                    gcs_config.gcs_prefix.as_deref().unwrap_or("comments"),
                    comment_id
                );
                tokio::spawn(upload_review_record(
                    gcs_config,
                    Some(agent.auth_manager.clone()),
                    gcs_path,
                    json_bytes,
                    "create",
                ));
            }
            let value = serde_json::to_value(CommentResponse {
                comment_id,
                recorded: true,
            })
            .map(|value| serde_json::value::to_raw_value(&value).map(Arc::from))
            .expect("to work")
            .expect("to work");
            Ok(acp::ExtResponse::new(value))
        }
        "fuigo/review/comment/delete" => {
            let request: CommentDeleteRequest = parse_params(args)?;
            tracing::info!(
                comment_id = %request.comment_id,
                session_id = %request.session_id,
                "Comment delete received"
            );
            if let Some(gcs_config) = agent
                .build_gcs_config(format!("{}/comments", request.session_id))
                .await
            {
                let mut record = serde_json::json!({
                    "event": "delete",
                    "commentId": request.comment_id,
                    "sessionId": request.session_id,
                    "clientType": format!("{:?}", agent.client_type()),
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });
                stamp_review_agent_id(&mut record, &gcs_config.upload_method, &agent_id());
                let json_bytes = serde_json::to_vec_pretty(&record)
                    .map_err(|e| crate::acp_error::internal_error(e.to_string()))?;
                let event_id = uuid::Uuid::now_v7().to_string();
                let gcs_path = format!(
                    "{}/{}.json",
                    gcs_config.gcs_prefix.as_deref().unwrap_or("comments"),
                    event_id
                );
                tokio::spawn(upload_review_record(
                    gcs_config,
                    Some(agent.auth_manager.clone()),
                    gcs_path,
                    json_bytes,
                    "delete",
                ));
            }
            let value = serde_json::to_value(CommentDeleteResponse {
                comment_id: request.comment_id,
                deleted: true,
            })
            .map(|value| serde_json::value::to_raw_value(&value).map(Arc::from))
            .expect("to work")
            .expect("to work");
            Ok(acp::ExtResponse::new(value))
        }
        _ => Err(crate::acp_error::unknown_ext_method(&args.method)),
    }
}


#[cfg(test)]
mod review_identity_tests {
    use super::stamp_review_agent_id;
    use fuigo_file_utils::upload_config::UploadMethod;

    const MACHINE_ID: &str = "5d1f0c2a-7a7a-4b4b-8c8c-0123456789ab";

    fn proxy(url: &str) -> UploadMethod {
        UploadMethod::Proxy {
            proxy_base_url: url.into(),
            user_token: "tok".into(),
            deployment_key: None,
            alpha_test_key: None,
        }
    }

    fn stamped(method: &UploadMethod) -> serde_json::Value {
        let mut record = serde_json::json!({"event": "create", "commentId": "c1", "sessionId": "s1"});
        stamp_review_agent_id(&mut record, method, MACHINE_ID);
        record
    }

    /// P54 hostile: a review-comment record uploaded through a storage proxy that is not
    /// FluxRouter-operated never carries the machine id itself; through FluxRouter, or into the
    /// operator's own configured bucket (Direct GCS, S3), it still does.
    ///
    /// P54-K: at a non-FluxRouter proxy the record carries the proxy-origin pseudonym — the key
    /// `hunk_records.jsonl` already carries to that proxy for the same session — not nothing, so a
    /// create record and its tombstone stay joinable and a consumer that requires the field keeps
    /// working. Pinned as equality with the archive's transformation of the same id.
    #[test]
    fn review_comment_records_carry_the_machine_id_only_to_permitted_storage() {
        for url in [
            "https://cli-proxy.example/v1",
            "http://127.0.0.1:9/v1",
            "http://api.fluxrouter.ai/v1",
        ] {
            let record = stamped(&proxy(url));
            assert!(!record.to_string().contains(MACHINE_ID), "{url}: {record}");
            let key = record["agentId"].as_str().unwrap_or_else(|| panic!("{url}: no agentId: {record}"));
            assert_eq!(
                key,
                fuigo_extra_ca::fluxrouter::destination_pseudonym(url, MACHINE_ID),
                "{url}: not the origin pseudonym"
            );
            let archived = crate::upload::feedback_archive::withhold_loc_identity(
                url,
                format!("{{\"agentId\":\"{MACHINE_ID}\",\"authorType\":\"agent\"}}\n").into_bytes(),
            );
            let archived: serde_json::Value =
                serde_json::from_slice(&archived).expect("one transformed LOC record");
            assert_eq!(archived["agentId"], key, "{url}: comment and LOC keys differ");
            assert_eq!(record["commentId"], "c1");
        }
        assert_eq!(stamped(&proxy("https://api.fluxrouter.ai/v1"))["agentId"], MACHINE_ID);
        assert_eq!(
            stamped(&UploadMethod::Direct { service_account_key: Some("{}".into()) })["agentId"],
            MACHINE_ID
        );
        let s3 = UploadMethod::S3 {
            bucket: "b".into(),
            region: "r".into(),
            credentials_file: None,
            credentials_content: None,
            endpoint_url: None,
        };
        assert_eq!(stamped(&s3)["agentId"], MACHINE_ID);
    }
}
