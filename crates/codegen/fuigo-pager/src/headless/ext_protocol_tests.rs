use super::*;
use crate::headless::reducer::StreamEvent;
use pretty_assertions::assert_eq;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl CapturedLogs {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapturedLogs {
    type Writer = CapturedLogs;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn capture_logs(f: impl FnOnce()) -> String {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    logs.text()
}

fn make_ext_notif(
    method: &str,
    update: serde_json::Value,
) -> fuigo_acp_lib::AcpArgsBox<acp::ExtNotification> {
    make_raw_ext_notif(
        method,
        serde_json::json!({
            "sessionId": "sess-1",
            "update": update,
        }),
    )
}

fn make_raw_ext_notif(
    method: &str,
    params: serde_json::Value,
) -> fuigo_acp_lib::AcpArgsBox<acp::ExtNotification> {
    let raw = serde_json::value::to_raw_value(&params).unwrap();
    let (tx, _rx) = tokio::sync::oneshot::channel();
    fuigo_acp_lib::AcpArgs {
        request: acp::ExtNotification::new(method, raw.into()),
        response_tx: tx,
    }
    .boxed()
}

#[test]
fn headless_task_backgrounded_parses_task_id() {
    let notif = make_ext_notif(
        "fuigo/task_backgrounded",
        serde_json::json!({
            "sessionUpdate": "task_backgrounded",
            "task_id": "task-abc",
        }),
    );
    assert!(matches!(
        handle_ext_notification(&notif),
        ExtEvent::TaskBackgrounded { task_id, is_monitor: false } if task_id == "task-abc"
    ));
}

#[test]
fn headless_task_backgrounded_numeric_task_id_is_coerced() {
    let notif = make_ext_notif(
        "fuigo/task_backgrounded",
        serde_json::json!({
            "sessionUpdate": "task_backgrounded",
            "task_id": 4242,
        }),
    );
    assert!(matches!(
        handle_ext_notification(&notif),
        ExtEvent::TaskBackgrounded { task_id, is_monitor: false } if task_id == "4242"
    ));
}

#[test]
fn headless_task_completed_numeric_task_id_is_coerced() {
    let notif = make_ext_notif(
        "fuigo/task_completed",
        serde_json::json!({
            "sessionUpdate": "task_completed",
            "task_snapshot": { "task_id": 4242 }
        }),
    );
    assert!(matches!(
        handle_ext_notification(&notif),
        ExtEvent::TaskCompleted { task_id } if task_id == "4242"
    ));
}

#[test]
fn headless_task_backgrounded_with_monitor_description_is_monitor() {
    let notif = make_ext_notif(
        "fuigo/task_backgrounded",
        serde_json::json!({
            "sessionUpdate": "task_backgrounded",
            "task_id": "mon-1",
            "monitor_description": "watching logs",
        }),
    );
    assert!(matches!(
        handle_ext_notification(&notif),
        ExtEvent::TaskBackgrounded { task_id, is_monitor: true } if task_id == "mon-1"
    ));
}

#[test]
fn headless_task_completed_parses_task_id() {
    let notif = make_ext_notif(
        "fuigo/task_completed",
        serde_json::json!({
            "sessionUpdate": "task_completed",
            "task_snapshot": { "task_id": "task-abc" }
        }),
    );
    assert!(matches!(
        handle_ext_notification(&notif),
        ExtEvent::TaskCompleted { task_id } if task_id == "task-abc"
    ));
}

#[test]
fn headless_subagent_spawned_and_finished_parse() {
    let spawned = make_ext_notif(
        "fuigo/session_notification",
        serde_json::json!({
            "sessionUpdate": "subagent_spawned",
            "subagent_id": "sub-1",
            "parent_session_id": "p",
            "child_session_id": "c",
            "subagent_type": "explore",
            "description": "test"
        }),
    );
    assert!(matches!(
        handle_ext_notification(&spawned),
        ExtEvent::SubagentSpawned { subagent_id } if subagent_id == "sub-1"
    ));
    let finished = make_ext_notif(
        "fuigo/session_notification",
        serde_json::json!({
            "sessionUpdate": "subagent_finished",
            "subagent_id": "sub-1",
            "child_session_id": "c",
            "status": "completed",
            "tool_calls": 0,
            "turns": 1,
            "duration_ms": 5
        }),
    );
    assert!(matches!(
        handle_ext_notification(&finished),
        ExtEvent::SubagentFinished { subagent_id } if subagent_id == "sub-1"
    ));
}

#[test]
fn headless_response_completed_parses_per_response_fields() {
    let notif = make_ext_notif(
        "fuigo/session_notification",
        serde_json::json!({
            "sessionUpdate": "response_completed",
            "message_id": "msg_01",
            "stop_reason": "tool_use",
            "usage": {
                "input_tokens": 10,
                "output_tokens": 4,
                "cache_read_input_tokens": 2,
                "cache_creation_input_tokens": 0,
            },
            "signature": "sig-xyz",
            "stop_sequence": "<END>",
        }),
    );
    let ExtEvent::Stream(event) = handle_ext_notification(&notif) else {
        panic!("expected Stream event");
    };
    let StreamEvent::ResponseCompleted {
        message_id,
        stop_reason,
        usage,
        signature,
        stop_sequence,
    } = *event
    else {
        panic!("expected ResponseCompleted");
    };
    assert_eq!(message_id.as_deref(), Some("msg_01"));
    assert_eq!(stop_reason.as_deref(), Some("tool_use"));
    assert_eq!(signature.as_deref(), Some("sig-xyz"));
    assert_eq!(stop_sequence.as_deref(), Some("<END>"));
    let usage = usage.expect("usage present");
    assert_eq!(usage.input_tokens, 10);
    assert_eq!(usage.cache_read_input_tokens, 2);
}

#[test]
fn headless_response_started_parses_per_response_fields() {
    let notif = make_ext_notif(
        "fuigo/session_notification",
        serde_json::json!({
            "sessionUpdate": "response_started",
            "message_id": "msg_01",
            "model": "grok-4",
            "input_tokens": 42,
            "cache_read_input_tokens": 7,
            "cache_creation_input_tokens": 3,
        }),
    );
    let ExtEvent::Stream(event) = handle_ext_notification(&notif) else {
        panic!("expected Stream event");
    };
    let StreamEvent::ResponseStarted {
        message_id,
        model,
        input_tokens,
        cache_read_input_tokens,
        cache_creation_input_tokens,
    } = *event
    else {
        panic!("expected ResponseStarted");
    };
    assert_eq!(message_id.as_deref(), Some("msg_01"));
    assert_eq!(model.as_deref(), Some("grok-4"));
    assert_eq!(input_tokens, 42);
    assert_eq!(cache_read_input_tokens, 7);
    assert_eq!(cache_creation_input_tokens, 3);
}

#[test]
fn headless_reasoning_completed_parses_signature() {
    let notif = make_ext_notif(
        "fuigo/session_notification",
        serde_json::json!({
            "sessionUpdate": "reasoning_completed",
            "signature": "sig-xyz",
        }),
    );
    let ExtEvent::Stream(event) = handle_ext_notification(&notif) else {
        panic!("expected Stream event");
    };
    let StreamEvent::ReasoningCompleted { signature } = *event else {
        panic!("expected ReasoningCompleted");
    };
    assert_eq!(signature.as_deref(), Some("sig-xyz"));
}

/// P195 (U17): a `redacted_thinking` block reaches the reducer as its own event, carrying the opaque blob.
#[test]
fn headless_redacted_thinking_parses_data() {
    let notif = make_ext_notif(
        "fuigo/session_notification",
        serde_json::json!({
            "sessionUpdate": "redacted_thinking",
            "data": "opaque-blob",
        }),
    );
    let ExtEvent::Stream(event) = handle_ext_notification(&notif) else {
        panic!("expected Stream event");
    };
    let StreamEvent::RedactedThinking { data } = *event else {
        panic!("expected RedactedThinking");
    };
    assert_eq!(data, "opaque-blob");
}

#[test]
fn headless_undecodable_known_background_task_errors_not_silent() {
    let notif = make_ext_notif(
        "fuigo/task_backgrounded",
        serde_json::json!({
            "sessionUpdate": "task_backgrounded",
            "task_id": { "nested": "object" },
        }),
    );
    let mut is_none = false;
    let logs = capture_logs(|| {
        is_none = matches!(handle_ext_notification(&notif), ExtEvent::None);
    });
    assert!(is_none, "undecodable known method degrades to None");
    assert!(
        logs.contains("task_backgrounded"),
        "log names the method: {logs}"
    );
    assert!(logs.contains("ERROR"), "logged at error level: {logs}");
}

#[test]
fn headless_task_backgrounded_mismatched_tag_errors_not_silent() {
    let notif = make_ext_notif(
        "fuigo/task_backgrounded",
        serde_json::json!({
            "sessionUpdate": "task_completed",
            "task_id": "task-abc",
        }),
    );
    let mut is_none = false;
    let logs = capture_logs(|| {
        is_none = matches!(handle_ext_notification(&notif), ExtEvent::None);
    });
    assert!(is_none, "mismatched-tag known method degrades to None");
    assert!(
        logs.contains("task_backgrounded"),
        "log names the method: {logs}"
    );
    assert!(logs.contains("ERROR"), "logged at error level: {logs}");
}

#[test]
fn headless_task_completed_mismatched_tag_errors_not_silent() {
    let notif = make_ext_notif(
        "fuigo/task_completed",
        serde_json::json!({
            "sessionUpdate": "task_backgrounded",
            "task_snapshot": { "task_id": "task-abc" },
        }),
    );
    let mut is_none = false;
    let logs = capture_logs(|| {
        is_none = matches!(handle_ext_notification(&notif), ExtEvent::None);
    });
    assert!(is_none, "mismatched-tag known method degrades to None");
    assert!(
        logs.contains("task_completed"),
        "log names the method: {logs}"
    );
    assert!(logs.contains("ERROR"), "logged at error level: {logs}");
}

#[test]
fn headless_malformed_known_response_boundary_warns_not_silent() {
    let notif = make_ext_notif(
        "fuigo/session_notification",
        serde_json::json!({
            "sessionUpdate": "response_completed",
            "usage": "not-an-object",
        }),
    );
    let mut is_none = false;
    let logs = capture_logs(|| {
        is_none = matches!(handle_ext_notification(&notif), ExtEvent::None);
    });
    assert!(is_none, "malformed known notification degrades to None");
    assert!(
        logs.contains("session notification"),
        "warning describes the malformed session notification: {logs}"
    );
    assert!(logs.contains("WARN"), "logged at warn level: {logs}");
}

#[test]
fn headless_session_update_unknown_method_is_none() {
    let payload = serde_json::json!({
        "sessionId": "sess-1",
        "update": {
            "sessionUpdate": "subagent_spawned",
            "subagent_id": "sub-1"
        }
    });
    let raw = serde_json::value::to_raw_value(&payload).unwrap();
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let notif = fuigo_acp_lib::AcpArgs {
        request: acp::ExtNotification::new("fuigo/other", raw.into()),
        response_tx: tx,
    }
    .boxed();
    assert!(matches!(handle_ext_notification(&notif), ExtEvent::None));
}

#[test]
fn headless_session_notification_task_tag_errors_not_silent() {
    for tag in ["task_backgrounded", "task_completed"] {
        let notif = make_ext_notif(
            "fuigo/session_notification",
            serde_json::json!({
                "sessionUpdate": tag,
                "task_id": "task-abc",
            }),
        );
        let mut is_none = false;
        let logs = capture_logs(|| {
            is_none = matches!(handle_ext_notification(&notif), ExtEvent::None);
        });
        assert!(is_none, "misrouted lifecycle tag degrades to None ({tag})");
        assert!(logs.contains(tag), "log names the tag {tag}: {logs}");
        assert!(
            logs.contains("ERROR"),
            "logged at error level ({tag}): {logs}"
        );
    }
}

#[test]
fn headless_version_mismatch_logs_warn_with_both_versions() {
    let notif = make_raw_ext_notif(
        "fuigo/leader/version_mismatch",
        serde_json::json!({
            "clientVersion": "0.1.157",
            "leaderVersion": "0.1.150",
            "message": "Client version 0.1.157 differs from leader version 0.1.150.",
        }),
    );
    let mut is_none = false;
    let logs = capture_logs(|| {
        is_none = matches!(handle_ext_notification(&notif), ExtEvent::None);
    });
    assert!(is_none, "version mismatch is log-only in headless");
    assert!(logs.contains("WARN"), "logged at warn level: {logs}");
    assert!(
        logs.contains("version_mismatch"),
        "log names the method: {logs}"
    );
    let banner = crate::glyphs::sanitize_toast_message(
        "⚠ Version mismatch: client 0.1.157, leader 0.1.150. Restart fuigo to match",
    );
    assert!(
        logs.contains(banner.as_ref()),
        "log carries the exact banner: {logs}"
    );
}

#[test]
fn headless_version_mismatch_without_message_still_warns() {
    let notif = make_raw_ext_notif(
        "fuigo/leader/version_mismatch",
        serde_json::json!({
            "clientVersion": "0.1.157",
            "leaderVersion": "0.1.150",
        }),
    );
    let mut is_none = false;
    let logs = capture_logs(|| {
        is_none = matches!(handle_ext_notification(&notif), ExtEvent::None);
    });
    assert!(is_none);
    assert!(logs.contains("WARN"), "logged at warn level: {logs}");
    let banner = crate::glyphs::sanitize_toast_message(
        "⚠ Version mismatch: client 0.1.157, leader 0.1.150. Restart fuigo to match",
    );
    assert!(
        logs.contains(banner.as_ref()),
        "missing message must still log both versions: {logs}"
    );
}

#[test]
fn headless_version_mismatch_malformed_warns_distinctly() {
    for params in [
        serde_json::json!({}),
        serde_json::json!({ "message": "only a message" }),
        serde_json::Value::String("not-an-object".into()),
    ] {
        let desc = params.to_string();
        let notif = make_raw_ext_notif("fuigo/leader/version_mismatch", params);
        let logs = capture_logs(|| {
            assert!(
                matches!(handle_ext_notification(&notif), ExtEvent::None),
                "malformed params must not crash: {desc}"
            );
        });
        assert!(logs.contains("WARN"), "parse failure must warn: {logs}");
        assert!(
            logs.contains("version_mismatch"),
            "parse failure must name the method: {logs}"
        );
        assert!(
            !logs.contains("⚠ Version mismatch: client"),
            "malformed payload must not emit the success banner: {logs}"
        );
    }
}

#[test]
fn headless_unknown_leader_method_is_silent_none() {
    let notif = make_raw_ext_notif(
        "fuigo/leader/not_a_method",
        serde_json::json!({
            "clientVersion": "0.1.157",
            "leaderVersion": "0.1.150",
        }),
    );
    let mut is_none = false;
    let logs = capture_logs(|| {
        is_none = matches!(handle_ext_notification(&notif), ExtEvent::None);
    });
    assert!(is_none);
    assert!(
        !logs.contains("WARN"),
        "unknown method must stay a clean ignore: {logs}"
    );
}

#[test]
fn headless_session_notification_unknown_tag_is_clean_ignore() {
    let notif = make_ext_notif(
        "fuigo/session_notification",
        serde_json::json!({ "sessionUpdate": "totally_unknown_display_tag" }),
    );
    let mut is_none = false;
    let logs = capture_logs(|| {
        is_none = matches!(handle_ext_notification(&notif), ExtEvent::None);
    });
    assert!(is_none, "unknown display tag degrades to None");
    assert!(
        !logs.contains("ERROR"),
        "an unknown display tag is a clean ignore, not an error: {logs}"
    );
}

/// Call `reply_headless_ext_method` and return what landed on the oneshot.
fn ext_method_reply(
    method: &str,
    params: serde_json::Value,
) -> fuigo_acp_lib::AcpResult<acp::ExtResponse> {
    let raw = serde_json::value::to_raw_value(&params).unwrap();
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    reply_headless_ext_method(
        fuigo_acp_lib::AcpArgs {
            request: acp::ExtRequest::new(method, raw.into()),
            response_tx: tx,
        }
        .boxed(),
    );
    rx.try_recv()
        .expect("ext_method must be answered, never dropped")
}

/// `fuigo/ask_user_question` gets a typed `cancelled` reply on the wire;
/// malformed params are still answered (known methods do not parse params).
#[test]
fn mcp_elicit_replies_cancelled() {
    use fuigo_tools::mcp_elicitation::McpElicitExtResponse;
    let raw = ext_method_reply("fuigo/mcp/elicit", serde_json::json!({}))
        .expect("policy reply, not an error");
    let typed: McpElicitExtResponse = serde_json::from_str(raw.0.get()).expect("typed cancel");
    assert!(matches!(typed, McpElicitExtResponse::Cancel));
}

#[test]
fn ask_user_question_replies_cancelled() {
    use fuigo_tools::implementations::fuigo_build::ask_user_question::AskUserQuestionExtResponse;
    for params in [
        serde_json::json!({
            "sessionId": "s", "toolCallId": "t", "questions": [], "mode": "default",
        }),
        serde_json::json!("not-an-object"),
    ] {
        let resp = ext_method_reply("fuigo/ask_user_question", params)
            .expect("policy reply, not an error");
        let parsed: AskUserQuestionExtResponse = serde_json::from_str(resp.0.get())
            .expect("wire reply must deserialize as the typed response");
        assert!(matches!(parsed, AskUserQuestionExtResponse::Cancelled));
    }
}

/// `fuigo/exit_plan_mode` is approved (no feedback) so the shell executes the exit and the model proceeds to implement.
#[test]
fn exit_plan_mode_replies_approved() {
    use fuigo_tools::implementations::fuigo_build::exit_plan_mode::ExitPlanModeExtResponse;
    let resp = ext_method_reply(
        "fuigo/exit_plan_mode",
        serde_json::json!({"sessionId": "s", "toolCallId": "t"}),
    )
    .expect("policy reply, not an error");
    let parsed: ExitPlanModeExtResponse = serde_json::from_str(resp.0.get())
        .expect("wire reply must deserialize as the typed response");
    assert_eq!(parsed.outcome, "approved");
    assert!(parsed.feedback.is_none());
}

/// Unknown methods (including lookalikes of the known ones) get a MethodNotFound error carrying the method name, never a dropped channel.
#[test]
fn unknown_ext_method_replies_method_not_found() {
    for method in [
        "fuigo/some_future_method",
        "fuigo/ask_user_questions",
        "fuigo/exit_plan_mode2",
        "ask_user_question",
    ] {
        let err = ext_method_reply(method, serde_json::json!({}))
            .expect_err("unknown method must be an error reply");
        assert_eq!(i32::from(err.code), -32601, "method={method}");
        assert!(
            err.message.contains(method),
            "error must carry the method name: {method} -> {}",
            err.message
        );
    }
}

/// A receiver dropped before the reply must not panic the responder.
#[test]
fn dropped_receiver_does_not_panic() {
    let raw = serde_json::value::to_raw_value(&serde_json::json!({})).unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    drop(rx);
    reply_headless_ext_method(
        fuigo_acp_lib::AcpArgs {
            request: acp::ExtRequest::new("fuigo/ask_user_question", raw.into()),
            response_tx: tx,
        }
        .boxed(),
    );
}

#[test]
fn headless_memory_flush_notifications_decode() {
    use crate::headless::reducer::Lifecycle;

    let started = make_ext_notif(
        "fuigo/session/update",
        serde_json::json!({ "sessionUpdate": "memory_flush_started" }),
    );
    assert!(matches!(
        handle_ext_notification(&started),
        ExtEvent::Lifecycle(Lifecycle::MemoryFlushStarted)
    ));

    let completed = make_ext_notif(
        "fuigo/session/update",
        serde_json::json!({
            "sessionUpdate": "memory_flush_completed",
            "result": "written",
            "path": "/tmp/memory/sessions/log.md"
        }),
    );
    match handle_ext_notification(&completed) {
        ExtEvent::Lifecycle(Lifecycle::MemoryFlushCompleted { result, path }) => {
            assert_eq!(result, "written");
            assert_eq!(path.as_deref(), Some("/tmp/memory/sessions/log.md"));
        }
        _ => panic!("expected MemoryFlushCompleted"),
    }
}

/// Real leader bytes through the real ACP decode path into the headless handler: the warn log must appear.
#[cfg(unix)]
#[tokio::test]
async fn real_leader_version_mismatch_reaches_headless_handler() {
    let mut leader =
        crate::acp::leader_bridge::real_leader_harness::bridge_to_real_leader("0.1.157", "0.1.150")
            .await;
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), leader.bridge.channel.rx.recv())
        .await
        .expect("version-mismatch notice never reached the headless pager: the ACP decoder rejected the wire method")
        .expect("bridge channel closed");
    let fuigo_acp_lib::AcpClientMessageBox::ExtNotification(notif) = msg.boxed() else {
        panic!("expected an ExtNotification");
    };
    let mut is_none = false;
    let logs = capture_logs(|| {
        is_none = matches!(handle_ext_notification(&notif), ExtEvent::None);
    });
    assert!(is_none, "version mismatch is log-only in headless");
    let banner = crate::glyphs::sanitize_toast_message(
        "⚠ Version mismatch: client 0.1.157, leader 0.1.150. Restart fuigo to match",
    );
    assert!(
        logs.contains(banner.as_ref()),
        "log carries the exact banner: {logs}"
    );
}

#[test]
fn headless_version_mismatch_accepts_prefixed_method() {
    let notif = make_raw_ext_notif(
        "_fuigo/leader/version_mismatch",
        serde_json::json!({ "clientVersion": "0.1.157", "leaderVersion": "0.1.150" }),
    );
    let logs = capture_logs(|| {
        assert!(matches!(handle_ext_notification(&notif), ExtEvent::None));
    });
    let banner = crate::glyphs::sanitize_toast_message(
        "⚠ Version mismatch: client 0.1.157, leader 0.1.150. Restart fuigo to match",
    );
    assert!(logs.contains(banner.as_ref()), "{logs}");
}

/// P133: a refused reference to the saved API key reaches headless output, as a notice line on stderr for `plain` and a
/// typed line for `streaming-json`; it used to reach only the log.
#[test]
fn headless_config_notice_decodes_and_is_worded_as_a_warning() {
    use crate::headless::reducer::Lifecycle;

    let notice = make_ext_notif(
        "fuigo/session/update",
        serde_json::json!({
            "sessionUpdate": "config_notice",
            "message": "/w/repo/.fuigo/config.toml: `mcp_servers.s.env.T` names FUIGO_API_KEY, the saved API key, and was ignored."
        }),
    );
    match handle_ext_notification(&notice) {
        ExtEvent::Lifecycle(l @ Lifecycle::ConfigNotice { .. }) => {
            let line = l.plain_message();
            assert!(
                line.starts_with("warning: /w/repo/.fuigo/config.toml"),
                "{line}"
            );
            assert!(line.contains("FUIGO_API_KEY"), "{line}");
        }
        _ => panic!("expected ConfigNotice"),
    }
}

/// P188: the shell's own `retry_state` serialization decodes to a discard only when `discardEmitted` is set.
#[test]
fn p188_retry_state_with_discard_decodes_to_response_discarded() {
    use fuigo_shell::extensions::notification::{RetryState, SessionUpdate};
    let wire = |discard_emitted: bool| {
        serde_json::to_value(SessionUpdate::RetryState(RetryState::Retrying {
            attempt: 1,
            max_retries: 15,
            reason: "stream ended early".into(),
            error_type: Some("api".into()),
            verdicts: None,
            discard_emitted,
            message_id: discard_emitted.then(|| "msg_1".to_string()),
            stream_start_ms: discard_emitted.then_some(9),
        }))
        .unwrap()
    };
    let on = wire(true);
    assert_eq!(
        on["discardEmitted"], true,
        "the wire name Murage reads: {on}"
    );
    assert_eq!(on["messageId"], "msg_1", "{on}");
    assert!(matches!(
        handle_ext_notification(&make_ext_notif("fuigo/session_notification", on)),
        ExtEvent::Stream(event) if matches!(*event, StreamEvent::ResponseDiscarded { ref message_id, stream_start_ms: Some(9) } if message_id.as_deref() == Some("msg_1"))
    ));
    let off = wire(false);
    assert!(
        off.get("discardEmitted").is_none(),
        "absent when false, as on older shells: {off}"
    );
    assert!(matches!(
        handle_ext_notification(&make_ext_notif("fuigo/session_notification", off)),
        ExtEvent::None
    ));
}

/// P181 (Astra round 1): a compaction error is untrusted text printed to the terminal, so hidden characters go.
#[test]
fn headless_compact_failed_line_drops_hidden_characters() {
    use crate::headless::reducer::Lifecycle;

    let failed = Lifecycle::CompactFailed {
        error: "bad\u{e0041} \u{00ad}thing\u{2028}\x1b[31m happened".to_string(),
    };
    assert_eq!(
        failed.plain_message(),
        "Auto-compact failed - bad thing [31m happened"
    );
}

/// P181 (Grok round): a config key from a project file is untrusted text; an OSC 0 title in it must not reach stderr.
#[test]
fn headless_config_notice_scrubs_a_key_carrying_an_osc_title() {
    use crate::headless::reducer::Lifecycle;

    let notice = Lifecycle::ConfigNotice {
        message: "/w/repo/.mcp.json: `mcp_servers.x.env.\u{1b}]0;owned\u{7}\u{2028}k` names FUIGO_API_KEY, the saved API key, and was ignored."
            .to_string(),
    };
    let line = notice.plain_message();
    assert_eq!(
        line,
        "warning: /w/repo/.mcp.json: `mcp_servers.x.env. ]0;owned  k` names FUIGO_API_KEY, the saved API key, and was ignored."
    );
}

/// P181 (Grok round): a memory flush that failed carries the API error message and a path, both untrusted.
#[test]
fn headless_memory_flush_line_scrubs_the_error_and_path() {
    use crate::headless::reducer::Lifecycle;

    let failed = Lifecycle::MemoryFlushCompleted {
        result: "skipped: API error (status 400): \u{1b}]0;owned\u{7}\u{e0041}.".to_string(),
        path: Some("/w/\u{1b}]0;x\u{7}a\u{2029}b".to_string()),
    };
    assert_eq!(
        failed.plain_message(),
        "Memory flush skipped: API error (status 400):  ]0;owned .: /w/ ]0;x a b"
    );
    let no_path = Lifecycle::MemoryFlushCompleted {
        result: "skipped: \u{1b}[31mred\u{202e}".to_string(),
        path: None,
    };
    assert_eq!(no_path.plain_message(), "Memory flush skipped:  [31mred.");
}

fn mcp_status_kind(
    name: &str,
    status: &str,
    reason: &str,
    detail: Option<&str>,
    kind: Option<serde_json::Value>,
) -> ExtEvent {
    let mut params = serde_json::json!({
        "sessionId": "s1", "name": name, "source": "local",
        "status": status, "reason": reason, "tools": null,
    });
    if let Some(d) = detail {
        params["detail"] = d.into();
    }
    if let Some(k) = kind {
        params["failureKind"] = k;
    }
    handle_ext_notification(&make_raw_ext_notif("fuigo/mcp/server_status", params))
}

fn mcp_status(name: &str, status: &str, reason: &str, detail: Option<&str>) -> ExtEvent {
    mcp_status_kind(name, status, reason, detail, None)
}

/// A failed start with a closed failure kind reaches headless; healthy, restarting or closed servers do not, and a push
/// with no kind (an older sender) is left out. The event carries the name and the kind only, never the raw detail.
#[test]
fn headless_mcp_server_status_reports_only_a_failed_start() {
    use fuigo_shell::extensions::mcp::McpFailureKind as K;
    let kind = |k: &str| Some(serde_json::json!(k));
    assert!(matches!(
        mcp_status_kind("dead", "unavailable", "handshake_failed", Some("boom"), kind("exited_before_answer")),
        ExtEvent::McpStartFailed { name, kind: K::ExitedBeforeAnswer } if name == "dead"
    ));
    assert!(matches!(
        mcp_status_kind(
            "t",
            "unavailable",
            "handshake_failed",
            None,
            Some(serde_json::json!({"timeout": {"secs": 5}}))
        ),
        ExtEvent::McpStartFailed {
            kind: K::Timeout { secs: 5 },
            ..
        }
    ));
    assert!(matches!(
        mcp_status("old", "unavailable", "handshake_failed", Some("boom")),
        ExtEvent::None
    ));
    for (status, reason) in [
        ("ready", "initialized"),
        ("initializing", "config_added"),
        ("unavailable", "transport_closed"),
        ("unavailable", "restart_failed"),
        ("needs_auth", "auth_expired"),
    ] {
        assert!(
            matches!(
                mcp_status_kind("s", status, reason, None, kind("other")),
                ExtEvent::None
            ),
            "{status}/{reason}"
        );
    }
}

/// A `failureKind` this build does not know must not drop the push: it decodes and prints the handshake-failed line.
#[test]
fn headless_mcp_unknown_failure_kind_still_reports_handshake_failed() {
    use fuigo_shell::extensions::mcp::McpFailureKind as K;
    for k in [
        serde_json::json!("from_the_future"),
        serde_json::json!({"future": {"n": 1}}),
    ] {
        let ev = mcp_status_kind(
            "dead",
            "unavailable",
            "handshake_failed",
            Some("boom"),
            Some(k),
        );
        let ExtEvent::McpStartFailed { name, kind } = ev else {
            panic!("an unknown kind must still be reported");
        };
        assert_eq!((name.as_str(), kind), ("dead", K::Unknown));
        let (_, notice) = crate::headless::reducer::Lifecycle::mcp_start_failed(&name, kind);
        assert!(
            notice
                .plain_message()
                .contains("failed to start: the start-up handshake failed.")
        );
    }
}

/// Servers that need sign-in stay silent: a 401 during the handshake and a needs-OAuth server both carry `needs_auth`
/// (from the error type, decided in the shell and the dispatcher), whatever the raw detail says.
#[test]
fn headless_mcp_server_status_keeps_sign_in_servers_silent() {
    let kind = Some(serde_json::json!("needs_auth"));
    for detail in [
        "MCP server 'gh' handshake failed: HTTP 401 Unauthorized",
        "MCP server 'x': Auth required (non-interactive session)",
    ] {
        assert!(matches!(
            mcp_status_kind(
                "gh",
                "unavailable",
                "handshake_failed",
                Some(detail),
                kind.clone()
            ),
            ExtEvent::None
        ));
    }
}

/// The fixed reason for each failure kind; no raw text anywhere in the line.
#[test]
fn headless_mcp_start_failed_line_names_server_fixed_reason_and_doctor() {
    use fuigo_shell::extensions::mcp::McpFailureKind as K;
    for (kind, reason) in [
        (K::CommandNotStarted, "the command could not be started"),
        (
            K::ExitedBeforeAnswer,
            "the server exited before it answered",
        ),
        (
            K::Timeout { secs: 5 },
            "the server did not answer within 5 s",
        ),
        (K::Unreachable, "the server could not be reached"),
        (K::Other, "the start-up handshake failed"),
        (
            K::ServerRejected,
            "the server rejected the connection (it may need sign-in)",
        ),
        (K::Unknown, "the start-up handshake failed"),
    ] {
        let (_, notice) = crate::headless::reducer::Lifecycle::mcp_start_failed("srv", kind);
        let line = notice.plain_message();
        assert_eq!(
            line,
            format!(
                "warning: MCP server \"srv\" failed to start: {reason}. Run `fuigo mcp doctor`."
            )
        );
    }
}

/// The name is outside text: escape sequences and newlines become inert, quotes are softened, the name is capped at 80
/// characters.
#[test]
fn headless_mcp_start_failed_name_is_inert_and_capped() {
    use fuigo_shell::extensions::mcp::McpFailureKind as K;
    let (printed, notice) = crate::headless::reducer::Lifecycle::mcp_start_failed(
        "ev\u{1b}]0;owned\u{7}\nil\"x",
        K::Other,
    );
    let line = notice.plain_message();
    assert!(
        !line.contains('\u{1b}') && !line.contains('\u{7}') && !line.contains('\n'),
        "{line:?}"
    );
    assert_eq!(printed, "ev ]0;owned  il'x");
    assert!(line.contains("\"ev ]0;owned  il'x\""), "{line}");

    let (printed, _) =
        crate::headless::reducer::Lifecycle::mcp_start_failed(&"n".repeat(500), K::Other);
    assert_eq!(printed.chars().count(), 80);
    assert!(printed.ends_with("..."));
    let (printed, _) =
        crate::headless::reducer::Lifecycle::mcp_start_failed(&"n".repeat(80), K::Other);
    assert_eq!(printed, "n".repeat(80), "an 80-character name is not cut");
}

#[test]
fn goal_updated_decodes_to_a_goal_status() {
    for (status, active) in [
        ("active", true),
        ("user_paused", false),
        ("back_off_paused", false),
        ("no_progress_paused", false),
        ("infra_paused", false),
        ("blocked", false),
        ("budget_limited", false),
        ("complete", false),
        ("cleared", false),
    ] {
        let notif = make_ext_notif(
            "fuigo/session/update",
            serde_json::json!({
                "sessionUpdate": "goal_updated",
                "goal_id": "g1",
                "objective": "ship it",
                "status": status,
                "phase": "executing",
                "elapsed_ms": 5,
                "total_deliverables": 0,
                "completed_deliverables": 0,
                "total_worker_rounds": 0,
                "total_verify_rounds": 0,
            }),
        );
        assert!(
            matches!(
                handle_ext_notification(&notif),
                ExtEvent::GoalStatus { goal_id, active: got, status: wire } if goal_id == "g1" && got == active && wire == status
            ),
            "status {status}"
        );
    }
}

#[test]
fn turn_completed_decodes_to_the_end_of_turn_event() {
    let notif = make_ext_notif(
        "fuigo/session/update",
        serde_json::json!({
            "sessionUpdate": "turn_completed",
            "prompt_id": "p1",
            "stop_reason": "end_turn",
        }),
    );
    assert!(matches!(handle_ext_notification(&notif), ExtEvent::TurnCompleted));
}
