use super::*;
use pretty_assertions::assert_eq;

#[test]
fn headless_ack_signal_classifies_messages() {
    let sid = acp::SessionId::new("sess-1");
    let ext = |method: &str, params: serde_json::Value| {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        AcpClientMessageBox::ExtNotification(fuigo_acp_lib::AcpArgsBox {
            request: Box::new(acp::ExtNotification::new(
                method,
                serde_json::value::to_raw_value(&params)
                    .expect("serialize")
                    .into(),
            )),
            response_tx: tx,
        })
    };
    let queue_changed = ext(
        fuigo_shell::session::prompt_queue::QUEUE_CHANGED_METHOD,
        serde_json::json!({ "sessionId": "sess-1", "entries": [], "runningPromptId": "p1" }),
    );
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let update = AcpClientMessageBox::SessionNotification(fuigo_acp_lib::AcpArgsBox {
        request: Box::new(
            acp::SessionNotification::new(
                sid.clone(),
                acp::SessionUpdate::AgentMessageChunk(acp::ContentChunk::new(
                    acp::ContentBlock::Text(acp::TextContent::new("hi")),
                )),
            )
            .meta(serde_json::json!({ "promptId": "p1" }).as_object().cloned()),
        ),
        response_tx: tx,
    });
    let unrelated = ext("fuigo/models/update", serde_json::json!({}));
    assert_eq!(
        [
            Some(AckSignal::QueueChanged),
            Some(AckSignal::SessionUpdate),
            None
        ],
        [&queue_changed, &update, &unrelated].map(|msg| headless_ack_signal(msg, &sid, "p1"))
    );
}

/// The ack-timeout record must reach `unified.jsonl` without the pager's buffered forwarder: this
/// path runs exactly when the shell has stopped answering, so nothing may ever flush that buffer.
#[tokio::test]
async fn ack_timeout_is_written_to_the_unified_log_directly() {
    fuigo_telemetry::unified_log::redirect_to_temp_for_tests();
    let (acp_tx, _agent_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpAgentMessage>();
    let session_id = acp::SessionId::new("sess-ack-timeout-direct-log");
    let deadlines = PromptAckDeadlines {
        soft: Duration::from_millis(50),
        hard: Duration::from_millis(200),
    };

    let _ = abort_unacknowledged_prompt(
        &acp_tx,
        &session_id,
        "p-direct-log",
        Duration::from_millis(250),
        &deadlines,
    )
    .await;

    let log = fuigo_telemetry::unified_log::snapshot_session_log(session_id.0.as_ref())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    assert!(
        log.contains("\"prompt.ack_timeout\"") && log.contains("\"p-direct-log\""),
        "the ack-timeout entry must be written straight to the unified log, not left buffered; log: {log:?}"
    );
}
