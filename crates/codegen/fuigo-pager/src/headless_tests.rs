use pretty_assertions::assert_eq;

#[test]
fn lifecycle_tracking_is_independent_of_wait_flag() {
    let mut pending = std::collections::HashSet::new();
    let mut completed = std::collections::HashSet::new();
    super::track_background_lifecycle(
        super::ExtEvent::TaskBackgrounded {
            task_id: "t1".into(),
            is_monitor: false,
        },
        &mut pending,
        &mut completed,
    );
    super::track_background_lifecycle(
        super::ExtEvent::SubagentSpawned {
            subagent_id: "s1".into(),
        },
        &mut pending,
        &mut completed,
    );
    assert!(pending.contains(&super::BackgroundWork::Task("t1".into())));
    assert!(pending.contains(&super::BackgroundWork::Subagent("s1".into())));

    super::track_background_lifecycle(
        super::ExtEvent::TaskCompleted {
            task_id: "t1".into(),
        },
        &mut pending,
        &mut completed,
    );
    super::track_background_lifecycle(
        super::ExtEvent::SubagentFinished {
            subagent_id: "s1".into(),
        },
        &mut pending,
        &mut completed,
    );
    assert!(pending.is_empty());
}

#[test]
fn completion_before_backgrounded_never_rearms_pending() {
    let mut pending = std::collections::HashSet::new();
    let mut completed = std::collections::HashSet::new();
    super::track_background_lifecycle(
        super::ExtEvent::TaskCompleted {
            task_id: "t1".into(),
        },
        &mut pending,
        &mut completed,
    );
    super::track_background_lifecycle(
        super::ExtEvent::TaskBackgrounded {
            task_id: "t1".into(),
            is_monitor: false,
        },
        &mut pending,
        &mut completed,
    );
    assert!(pending.is_empty());
}

/// A late/duplicate `task_backgrounded` must not resurrect a completed task.
#[test]
fn duplicate_backgrounded_after_completion_stays_dead() {
    let mut pending = std::collections::HashSet::new();
    let mut completed = std::collections::HashSet::new();
    let bg = || super::ExtEvent::TaskBackgrounded {
        task_id: "t1".into(),
        is_monitor: false,
    };
    super::track_background_lifecycle(bg(), &mut pending, &mut completed);
    assert!(pending.contains(&super::BackgroundWork::Task("t1".into())));
    super::track_background_lifecycle(
        super::ExtEvent::TaskCompleted {
            task_id: "t1".into(),
        },
        &mut pending,
        &mut completed,
    );
    assert!(pending.is_empty());
    super::track_background_lifecycle(bg(), &mut pending, &mut completed);
    assert!(
        pending.is_empty(),
        "a backgrounded for an already-completed id must not re-arm pending"
    );
}

/// The same tombstone dedup applies to background subagents.
#[test]
fn duplicate_subagent_spawn_after_finish_stays_dead() {
    let mut pending = std::collections::HashSet::new();
    let mut completed = std::collections::HashSet::new();
    let spawn = || super::ExtEvent::SubagentSpawned {
        subagent_id: "s1".into(),
    };
    super::track_background_lifecycle(spawn(), &mut pending, &mut completed);
    super::track_background_lifecycle(
        super::ExtEvent::SubagentFinished {
            subagent_id: "s1".into(),
        },
        &mut pending,
        &mut completed,
    );
    assert!(pending.is_empty());
    super::track_background_lifecycle(spawn(), &mut pending, &mut completed);
    assert!(
        pending.is_empty(),
        "a spawn for an already-finished subagent id must not re-arm pending"
    );
}

#[test]
fn reap_request_for_task_kills_with_session_scope() {
    let session_id = acp::SessionId::new("sess-1");
    let work = super::BackgroundWork::Task("task-42".into());
    let request = super::reap_request_for_work(&work, &session_id).unwrap();
    assert_eq!(request.method.as_ref(), "fuigo/task/kill");
    let params: serde_json::Value = serde_json::from_str(request.params.get()).unwrap();
    assert_eq!(params["sessionId"], "sess-1");
    assert_eq!(params["taskId"], "task-42");
    assert_eq!(params["source"], "teardown");
}

/// A numeric `task_id` is coerced to its string form, tracked, and reaped on exit.
#[test]
fn numeric_task_id_is_decoded_tracked_and_reaped() {
    let payload = serde_json::json!({
        "sessionId": "sess-1",
        "update": { "sessionUpdate": "task_backgrounded", "task_id": 4242 },
    });
    let raw = serde_json::value::to_raw_value(&payload).unwrap();
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let notif = fuigo_acp_lib::AcpArgs {
        request: acp::ExtNotification::new("fuigo/task_backgrounded", raw.into()),
        response_tx: tx,
    }
    .boxed();
    let event = super::handle_ext_notification(&notif);
    let mut pending = std::collections::HashSet::new();
    let mut completed = std::collections::HashSet::new();
    super::track_background_lifecycle(event, &mut pending, &mut completed);
    let work = super::BackgroundWork::Task("4242".into());
    assert!(
        pending.contains(&work),
        "numeric task_id tracked as the coerced string id"
    );
    let session_id = acp::SessionId::new("sess-1");
    let request = super::reap_request_for_work(&work, &session_id).unwrap();
    assert_eq!(request.method.as_ref(), "fuigo/task/kill");
    let params: serde_json::Value = serde_json::from_str(request.params.get()).unwrap();
    assert_eq!(params["taskId"], "4242");
    assert_eq!(params["sessionId"], "sess-1");
    assert_eq!(params["source"], "teardown");
}

#[test]
fn reap_request_for_subagent_cancels_with_typed_id() {
    let session_id = acp::SessionId::new("sess-1");
    let work = super::BackgroundWork::Subagent("sub-7".into());
    let request = super::reap_request_for_work(&work, &session_id).unwrap();
    assert_eq!(request.method.as_ref(), "fuigo/subagent/cancel");
    let params: serde_json::Value = serde_json::from_str(request.params.get()).unwrap();
    assert_eq!(params["subagentId"], "sub-7");
}

/// A `task_backgrounded` delivered right at prompt completion is still recorded by the drain.
#[test]
fn drain_records_task_backgrounded_delivered_at_exit() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let payload = serde_json::json!({
        "sessionId": "sess-1",
        "update": { "sessionUpdate": "task_backgrounded", "task_id": "late-1" },
    });
    let raw = serde_json::value::to_raw_value(&payload).unwrap();
    let (resp_tx, _resp_rx) = tokio::sync::oneshot::channel();
    tx.send(fuigo_acp_lib::AcpClientMessage::ExtNotification(
        fuigo_acp_lib::AcpArgs {
            request: acp::ExtNotification::new("fuigo/task_backgrounded", raw.into()),
            response_tx: resp_tx,
        },
    ))
    .unwrap();

    let mut emitter = HeadlessEmitter::new(OutputFormat::Json, false);
    let mut pending = std::collections::HashSet::new();
    let mut completed = std::collections::HashSet::new();
    let mut ttf_logged = false;
    super::drain_pending_acp_messages(
        &mut rx,
        &mut emitter,
        std::time::Instant::now(),
        &mut ttf_logged,
        false,
        &mut pending,
        &mut completed,
    );
    assert!(
        pending.contains(&super::BackgroundWork::Task("late-1".into())),
        "drain-to-empty records a task_backgrounded buffered at exit"
    );
}

/// `begin_session` runs before the model and effort are applied, so a post-open error carries the real context.
#[test]
fn post_open_error_carries_real_session_context() {
    let mut pre = reducer_for(OutputFormat::StreamingMessagesJson).unwrap();
    let pre_lines = pre.error("boom", None, 0, None);
    let pre_result = pre_lines
        .iter()
        .find(|l| l["type"] == "result")
        .expect("result line");
    assert_eq!(
        pre_result["session_id"], "",
        "pre-session error keeps the startup-error fallback"
    );

    let mut post = reducer_for(OutputFormat::StreamingMessagesJson).unwrap();
    post.begin(SessionContext {
        session_id: "sess-real".into(),
        model: Some("grok-4".into()),
        cwd: "/work/dir".into(),
        permission_mode: None,
        mcp_servers: Vec::new(),
        include_partial_messages: false,
        api_key_auth: true,
        context_window: None,
    });
    let post_lines = post.error("boom", None, 0, None);
    let post_result = post_lines
        .iter()
        .find(|l| l["type"] == "result")
        .expect("result line");
    assert_eq!(
        post_result["session_id"], "sess-real",
        "post-open error carries the real session id"
    );
    let init = post_lines
        .iter()
        .find(|l| l["type"] == "system" && l["subtype"] == "init")
        .expect("system/init line");
    assert_eq!(init["session_id"], "sess-real");
    assert_eq!(init["cwd"], "/work/dir");
}

use super::*;
use fuigo_workspace::permission::types::{RuleAction, ToolFilter};

fn s(v: &str) -> String {
    v.to_owned()
}

/// Headless materialization is never chat and carries the pre-sandbox pin flag through.
#[test]
fn headless_materialize_ctx_stays_non_chat() {
    use crate::app::session_startup::TitleResolution;
    for pinned in [false, true] {
        for restore_code in [false, true] {
            let ctx = headless_materialize_ctx(pinned, restore_code);
            assert!(!ctx.chat_mode);
            assert!(
                !ctx.has_worktree,
                "headless must not defer remote miss to a worktree it never creates"
            );
            assert_eq!(ctx.restore_code, restore_code);
            assert_eq!(
                ctx.title_resolution,
                if pinned {
                    TitleResolution::PinnedPreSandbox
                } else {
                    TitleResolution::Allowed
                }
            );
        }
    }
}

#[test]
fn headless_remote_miss_restores_conversation_instead_of_deferring_worktree() {
    use crate::app::session_startup::{RemoteMissPlan, plan_remote_miss};
    for restore_code in [false, true] {
        let ctx = headless_materialize_ctx(false, restore_code);
        assert!(!matches!(
            plan_remote_miss(ctx, true),
            RemoteMissPlan::DeferToWorktree { .. }
        ));
    }
    let mut conv = headless_materialize_ctx(false, false);
    conv.allow_remote_restore = true;
    assert_eq!(
        plan_remote_miss(conv, true),
        RemoteMissPlan::RestoreConversation
    );
    let mut code = headless_materialize_ctx(false, true);
    code.allow_remote_restore = true;
    assert_eq!(
        plan_remote_miss(code, true),
        RemoteMissPlan::RejectInPlaceCodeRestore {
            title_miss_hint: false,
        }
    );
}

#[test]
fn strict_valid_rules_parse_deny_before_allow() {
    let allow = vec![s("Bash(npm*)")];
    let deny = vec![s("Bash(rm*)"), s("Edit(/etc/**)")];
    let rules = parse_permission_rules_strict(&allow, &deny).unwrap();
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[0].action, RuleAction::Deny);
    assert!(matches!(rules[0].tool, ToolFilter::Bash));
    assert_eq!(rules[1].action, RuleAction::Deny);
    assert!(matches!(rules[1].tool, ToolFilter::Edit));
    assert_eq!(rules[2].action, RuleAction::Allow);
    assert!(matches!(rules[2].tool, ToolFilter::Bash));
}

#[test]
fn strict_invalid_rule_errors() {
    let result = parse_permission_rules_strict(&[], &[s("EnterWorktree(foo)")]);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("--deny"));
    assert!(msg.contains("EnterWorktree"));
}

#[test]
fn strict_reports_all_invalid_rules() {
    let result = parse_permission_rules_strict(
        &[s("BadTool(x)")],
        &[s("EnterWorktree(foo)"), s("Bash(rm*)")],
    );
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("EnterWorktree"),
        "should mention first bad deny"
    );
    assert!(msg.contains("BadTool"), "should mention bad allow");
}

#[test]
fn lenient_skips_invalid_keeps_valid() {
    let allow = vec![s("Bash(npm*)")];
    let deny = vec![s("EnterWorktree(foo)"), s("Bash(rm*)")];
    let rules = parse_permission_rules_lenient(&allow, &deny);
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].action, RuleAction::Deny);
    assert_eq!(rules[0].pattern.as_deref(), Some("rm*"));
    assert_eq!(rules[1].action, RuleAction::Allow);
    assert_eq!(rules[1].pattern.as_deref(), Some("npm*"));
}

#[test]
fn empty_inputs_produce_empty_rules() {
    let rules = parse_permission_rules_strict(&[], &[]).unwrap();
    assert!(rules.is_empty());
    let rules = parse_permission_rules_lenient(&[], &[]);
    assert!(rules.is_empty());
}

#[test]
fn domain_mode_web_fetch() {
    let rules = parse_permission_rules_strict(&[], &[s("WebFetch(domain:evil.com)")]).unwrap();
    assert_eq!(rules.len(), 1);
    assert!(matches!(rules[0].tool, ToolFilter::WebFetch));
    assert_eq!(
        rules[0].pattern_mode,
        fuigo_workspace::permission::types::PatternMode::Domain
    );
    assert_eq!(rules[0].pattern.as_deref(), Some("evil.com"));
}

#[test]
fn bash_colon_wildcard_deny_translates_to_prefix() {
    let rules = parse_permission_rules_strict(&[], &[s("Bash(sed:*)")]).unwrap();
    assert_eq!(rules.len(), 1);
    assert!(matches!(rules[0].tool, ToolFilter::Bash));
    assert_eq!(rules[0].pattern.as_deref(), Some("sed"));
}

#[test]
fn structured_output_without_meta_errors_never_parses_text() {
    let mut emitter = HeadlessEmitter::new(OutputFormat::Json, true);
    emitter.text_buffer = r#"{"name":"alice","age":30}"#.into();
    emitter.set_structured_output_from_meta(serde_json::json!({}).as_object());
    let result = emitter.build_json_result("EndTurn", "sess-1", "req-1");
    assert!(result["structuredOutput"].is_null());
    assert_eq!(
        result["structuredOutputError"],
        "model did not produce structured output"
    );
}

#[test]
fn structured_output_from_meta_wins_over_text_buffer() {
    let mut emitter = HeadlessEmitter::new(OutputFormat::Json, true);
    emitter.text_buffer = "thinking out loud...".into();
    emitter.set_structured_output_from_meta(
        serde_json::json!({"structuredOutput": {"name": "carol"}}).as_object(),
    );
    let result = emitter.build_json_result("EndTurn", "sess-1", "req-1");
    assert_eq!(result["structuredOutput"]["name"], "carol");
    assert!(result.get("structuredOutputError").is_none());

    let mut emitter = HeadlessEmitter::new(OutputFormat::Json, true);
    emitter.set_structured_output_from_meta(
        serde_json::json!({
            "structuredOutputError": "output does not match the required schema"
        })
        .as_object(),
    );
    let result = emitter.build_json_result("EndTurn", "sess-1", "req-1");
    assert!(result["structuredOutput"].is_null());
    assert_eq!(
        result["structuredOutputError"],
        "output does not match the required schema"
    );
}

#[test]
fn streaming_json_structured_output_emits_from_meta() {
    let mut emitter = HeadlessEmitter::new(OutputFormat::StreamingJson, true);
    emitter.on_text_chunk(r#"{"name":"#);
    emitter.on_text_chunk(r#""bob"}"#);
    assert!(emitter.text_buffer.is_empty());

    emitter.set_structured_output_from_meta(
        serde_json::json!({"structuredOutput": {"name": "bob"}}).as_object(),
    );
    let mut target = serde_json::json!({});
    emitter.attach_structured_output(&mut target);
    assert_eq!(target["structuredOutput"]["name"], "bob");
    assert!(target.get("structuredOutputError").is_none());
}

#[test]
fn broken_pipe_write_is_a_clean_latched_stop() {
    let mut emitter = HeadlessEmitter::new(OutputFormat::StreamingMessagesJson, false);
    let result = emitter.record_write_result(Err(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "pipe",
    )));
    assert!(result.is_ok(), "broken pipe is a clean stop");
    assert!(emitter.output_closed);
    assert!(emitter.take_output_error().is_none());
}

#[test]
fn hard_write_error_is_latched_and_surfaced_once() {
    let mut emitter = HeadlessEmitter::new(OutputFormat::StreamingMessagesJson, false);
    let result = emitter.record_write_result(Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "denied",
    )));
    assert!(result.is_err(), "hard error is surfaced to the caller");
    assert!(emitter.output_closed);
    let latched = emitter.take_output_error().expect("hard error latched");
    assert_eq!(latched.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        emitter.take_output_error().is_none(),
        "taken once, then cleared"
    );
}

#[test]
fn first_hard_write_error_wins_the_latch() {
    let mut emitter = HeadlessEmitter::new(OutputFormat::Json, false);
    let _ = emitter.record_write_result(Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "first",
    )));
    let _ = emitter.record_write_result(Err(std::io::Error::other("second")));
    assert_eq!(
        emitter.take_output_error().map(|e| e.kind()),
        Some(std::io::ErrorKind::PermissionDenied)
    );
}

#[test]
fn successful_write_leaves_no_latched_error() {
    let mut emitter = HeadlessEmitter::new(OutputFormat::Plain, false);
    assert!(emitter.record_write_result(Ok(())).is_ok());
    assert!(!emitter.output_closed);
    assert!(emitter.take_output_error().is_none());
}

#[test]
fn parse_json_schema_rejects_non_objects_and_invalid_json() {
    assert!(super::parse_json_schema(r#"{"type":"object"}"#).is_ok());
    assert!(
        super::parse_json_schema(r#"[1,2,3]"#)
            .unwrap_err()
            .to_string()
            .contains("must be a JSON object")
    );
    assert!(
        super::parse_json_schema(r#"{not json"#)
            .unwrap_err()
            .to_string()
            .contains("invalid JSON")
    );
}

#[test]
fn handler_answers_ext_method_instead_of_dropping() {
    use agent_client_protocol as acp;
    use fuigo_tools::implementations::fuigo_build::ask_user_question::AskUserQuestionExtResponse;
    let raw = serde_json::value::to_raw_value(&serde_json::json!({})).unwrap();
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    let msg = fuigo_acp_lib::AcpClientMessage::ExtMethod(fuigo_acp_lib::AcpArgs {
        request: acp::ExtRequest::new("fuigo/ask_user_question", raw.into()),
        response_tx: tx,
    });
    let mut emitter = super::HeadlessEmitter::new(super::OutputFormat::Json, false);
    let mut pending = std::collections::HashSet::new();
    let mut completed = std::collections::HashSet::new();
    let mut ttf_logged = false;
    super::handle_headless_acp_message(
        msg.boxed(),
        &mut emitter,
        std::time::Instant::now(),
        &mut ttf_logged,
        false,
        &mut pending,
        &mut completed,
    );
    let resp = rx
        .try_recv()
        .expect("ExtMethod must be answered, never dropped")
        .expect("policy reply, not an error");
    let parsed: AskUserQuestionExtResponse =
        serde_json::from_str(resp.0.get()).expect("typed wire reply");
    assert!(matches!(parsed, AskUserQuestionExtResponse::Cancelled));
}

// ── Headless turn hard timeout (`--timeout` / `FUIGO_HEADLESS_TIMEOUT_SECS`) ────────────

fn timeout_test_options(total_timeout: Option<std::time::Duration>) -> super::HeadlessOptions {
    super::HeadlessOptions {
        session_id: None,
        resume: None,
        resume_title_pinned: false,
        cwd: None,
        yolo: false,
        trust: false,
        output_format: super::OutputFormat::Json,
        include_partial_messages: false,
        json_schema: None,
        model: None,
        rules: None,
        system_prompt_override: None,
        continue_last_session: false,
        fork_session: false,
        worktree: None,
        restore_code: false,
        agent: None,
        agents_json: None,
        cli_tools: None,
        cli_disallowed_tools: None,
        disable_web_search: false,
        allow_rules: Vec::new(),
        deny_rules: Vec::new(),
        max_turns: None,
        permission_mode_flag: None,
        reasoning_effort: None,
        wait_for_background: true,
        background_wait_timeout: std::time::Duration::from_secs(600),
        total_timeout,
        memory_flush: false,
        memory_enabled_override: None,
    }
}

/// Drive a turn whose agent never answers and never streams, with the supplied hard cap.
async fn drive_silent_turn(total_timeout: Option<std::time::Duration>) -> super::TurnDriveOutcome {
    // Senders/receivers are held so neither channel ever closes: every `select!` arm stays pending.
    let (_client_tx, mut acp_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (acp_tx, _agent_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpAgentMessage>();
    let session_id = acp::SessionId::new("sess-1");
    let mut emitter = super::HeadlessEmitter::new(super::OutputFormat::Json, false);
    let options = timeout_test_options(total_timeout);
    let mut ttf_logged = false;
    let prompt_fut = std::future::pending::<Result<acp::PromptResponse, acp::Error>>();
    super::drive_prompt_turn(
        prompt_fut,
        &mut acp_rx,
        &acp_tx,
        &session_id,
        &mut emitter,
        &options,
        super::RunDeadline::start(total_timeout),
        std::time::Instant::now(),
        &mut ttf_logged,
    )
    .await
}

/// The bug: with no end event the prompt future, the ACP stream and the (gated-off) background
/// sleep arm are all pending forever, so `fuigo -p` never returns. The hard cap must break it.
#[tokio::test]
async fn turn_gives_up_when_the_agent_never_responds() {
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        drive_silent_turn(Some(std::time::Duration::from_millis(200))),
    )
    .await
    .expect("headless turn hung past its --timeout instead of giving up");
    assert!(
        outcome.timed_out,
        "the turn must report the hard timeout so the caller exits non-zero"
    );
    assert!(
        outcome.prompt_result.is_none(),
        "a timed-out turn has no prompt result"
    );
    assert!(!outcome.connection_closed, "the channel never closed");
}

/// Default-off: with no `--timeout` a silent turn keeps waiting exactly as it does today.
#[tokio::test]
async fn turn_without_timeout_keeps_waiting() {
    let waited = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        drive_silent_turn(None),
    )
    .await;
    assert!(
        waited.is_err(),
        "without --timeout the turn must not acquire a deadline of its own"
    );
}

/// `acp_send` awaits a bare oneshot; a bounded send must not inherit that unbounded wait.
#[tokio::test]
async fn lifecycle_send_fails_instead_of_blocking_forever() {
    let never = std::future::pending::<Result<(), String>>();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        super::with_send_deadline(
            "initialize",
            Some(std::time::Duration::from_millis(200)),
            never,
        ),
    )
    .await
    .expect("with_send_deadline blocked past its own limit");
    let err = result.expect_err("a send that is never answered must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("timed out") && msg.contains("initialize"),
        "error must name the timeout and the lifecycle step, got: {msg}"
    );
}

/// The bound wrapper is transparent otherwise: successes and real errors pass straight through.
#[tokio::test]
async fn lifecycle_send_passes_results_through() {
    let ok = super::with_send_deadline(
        "initialize",
        Some(std::time::Duration::from_secs(5)),
        std::future::ready(Ok::<u8, String>(7)),
    )
    .await
    .unwrap();
    assert_eq!(ok, 7);
    let err = super::with_send_deadline(
        "authenticate",
        Some(std::time::Duration::from_secs(5)),
        std::future::ready(Err::<u8, String>("no credentials".to_string())),
    )
    .await
    .unwrap_err();
    assert_eq!(err.to_string(), "no credentials");
}

/// `--timeout` is documented as a cap on the whole run, but `session/new` is a bare `acp_send`
/// awaiting a oneshot. An agent that accepts the request and then goes silent — precisely the
/// slow-skills-scan shape — used to hang `fuigo -p` forever despite the flag.
#[tokio::test]
async fn session_new_is_bounded_by_the_run_deadline() {
    // `_agent_rx` is held so the send succeeds and the reply oneshot is simply never answered.
    let (acp_tx, _agent_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpAgentMessage>();
    let tmp = tempfile::tempdir().expect("tmp cwd");
    let deadline = super::RunDeadline::start(Some(std::time::Duration::from_millis(200)));
    let err = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        super::open_session(&acp_tx, tmp.path(), None, None, deadline),
    )
    .await
    .expect("session/new ignored the run deadline and blocked forever")
    .err()
    .expect("an unanswered session/new must fail, not hang");
    let msg = err.to_string();
    assert!(
        msg.contains("timed out") && msg.contains("session/new"),
        "the error must name the deadline and the step, got: {msg}"
    );
}

/// Without `--timeout` those sends keep their historical unbounded shape.
#[tokio::test]
async fn session_new_without_a_run_deadline_still_waits() {
    let (acp_tx, _agent_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpAgentMessage>();
    let tmp = tempfile::tempdir().expect("tmp cwd");
    let waited = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        super::open_session(
            &acp_tx,
            tmp.path(),
            None,
            None,
            super::RunDeadline::start(None),
        ),
    )
    .await;
    assert!(
        waited.is_err(),
        "with no --timeout, session/new must not acquire a deadline of its own"
    );
}

/// The run budget is shared: one send cannot be given more time than the whole run has left,
/// and a cap of its own still applies when it is the sooner of the two.
#[test]
fn the_run_budget_is_the_sooner_of_the_cap_and_the_run_deadline() {
    let uncapped = super::RunDeadline::start(None);
    assert_eq!(uncapped.remaining(), None);
    assert_eq!(uncapped.budget(None), None);
    assert_eq!(
        uncapped.budget(Some(std::time::Duration::from_secs(120))),
        Some(std::time::Duration::from_secs(120))
    );
    let capped = super::RunDeadline::start(Some(std::time::Duration::from_secs(30)));
    let left = capped.remaining().expect("a cap leaves a remainder");
    assert!(left <= std::time::Duration::from_secs(30));
    assert!(
        capped.budget(Some(std::time::Duration::from_secs(120))) <= Some(left),
        "a 120s send cap must not outlive a 30s run"
    );
    assert_eq!(
        capped.budget(Some(std::time::Duration::from_millis(1))),
        Some(std::time::Duration::from_millis(1)),
        "the sooner cap still wins"
    );
    let elapsed = super::RunDeadline::start(Some(std::time::Duration::ZERO));
    assert_eq!(
        elapsed.budget(None),
        Some(std::time::Duration::ZERO),
        "a spent run gives later sends no budget at all"
    );
}

fn completed_prompt_response() -> acp::PromptResponse {
    let mut meta = acp::Meta::new();
    meta.insert(
        "usage".to_string(),
        serde_json::json!({"input_tokens": 1234, "output_tokens": 7}),
    );
    meta.insert(
        "structuredOutput".to_string(),
        serde_json::json!({"answer": "42"}),
    );
    meta.insert(
        "sessionId".to_string(),
        serde_json::Value::String("sess-1".into()),
    );
    meta.insert(
        "requestId".to_string(),
        serde_json::Value::String("req-1".into()),
    );
    acp::PromptResponse::new(acp::StopReason::EndTurn).meta(Some(meta))
}

/// The cap can fire while a turn that already answered is still waiting on background work (a
/// persistent monitor never completes and always waits out `--background-wait-timeout`). The
/// answer, its usage and its structured output are real work that must not be discarded: for a
/// product benchmarked on cost per task, throwing away the spend record of a completed turn is a
/// silent loss.
#[test]
fn the_hard_cap_still_reports_a_turn_that_already_completed() {
    let mut emitter = super::HeadlessEmitter::new(super::OutputFormat::Json, true);
    let err = super::finish_turn(
        &mut emitter,
        Some(Ok(completed_prompt_response())),
        true,
        Some(std::time::Duration::from_secs(300)),
        &acp::SessionId::new("sess-1"),
        false,
    )
    .expect_err("a capped run must still exit non-zero");
    assert!(
        err.to_string().contains("Timed out after 300s"),
        "the timeout must still be reported, got: {err}"
    );
    assert_eq!(
        emitter.usage,
        Some(serde_json::json!({"input_tokens": 1234, "output_tokens": 7})),
        "a completed turn's usage must survive the cap"
    );
    assert!(
        matches!(emitter.structured_output, Some(Ok(ref v)) if *v == serde_json::json!({"answer": "42"})),
        "a completed turn's structured output must survive the cap, got: {:?}",
        emitter.structured_output
    );
}

/// A cap that fires with no completed turn behind it reports only the timeout.
#[test]
fn the_hard_cap_reports_a_turn_that_never_completed() {
    let mut emitter = super::HeadlessEmitter::new(super::OutputFormat::Json, true);
    let err = super::finish_turn(
        &mut emitter,
        None,
        true,
        Some(std::time::Duration::from_secs(300)),
        &acp::SessionId::new("sess-1"),
        false,
    )
    .expect_err("a capped run must exit non-zero");
    assert!(err.to_string().contains("Timed out after 300s"));
    assert!(
        emitter.usage.is_none() && emitter.structured_output.is_none(),
        "nothing completed, so there is nothing to report"
    );
}

/// `fuigo -p --memory-flush --timeout N` must not wait forever if the backend wedges during the
/// flush: `flush_fut` is a bare `acp_send` and the ACP arm alone never ends a wedged flush.
#[tokio::test]
async fn the_memory_flush_is_bounded_by_the_run_deadline() {
    let (_client_tx, mut acp_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (acp_tx, _agent_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpAgentMessage>();
    let mut emitter = super::HeadlessEmitter::new(super::OutputFormat::Json, false);
    let err = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        super::run_headless_memory_flush(
            &acp_tx,
            &mut acp_rx,
            &acp::SessionId::new("sess-1"),
            &mut emitter,
            false,
            super::RunDeadline::start(Some(std::time::Duration::from_millis(200))),
        ),
    )
    .await
    .expect("the memory flush ignored the run deadline and blocked forever")
    .expect_err("an unanswered flush must fail, not hang");
    assert!(
        err.to_string().contains("memory flush"),
        "the error must name the step, got: {err}"
    );
}

/// A stdout seam so a test can assert on the bytes a machine consumer actually reads.
#[derive(Clone, Default)]
struct CapturedOut(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedOut {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("capture lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CapturedOut {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("capture lock").clone()).expect("utf8 output")
    }
}

/// A failed turn whose `error.data` is the shell's typed object reports its `message`, never the object as JSON.
#[test]
fn a_typed_prompt_error_reports_its_message_not_raw_json() {
    let captured = CapturedOut::default();
    let mut emitter = super::HeadlessEmitter::with_writer(
        super::OutputFormat::Json,
        true,
        Box::new(captured.clone()),
    );
    let wire_error = acp::Error::internal_error().data(serde_json::json!({
        "message": "empty response from model (reasoning_only)",
        "error_kind": "empty_response",
    }));
    let err = super::finish_turn(
        &mut emitter,
        Some(Err(wire_error)),
        false,
        None,
        &acp::SessionId::new("sess-1"),
        false,
    )
    .expect_err("a failed turn exits non-zero");
    assert_eq!(
        err.to_string(),
        "Internal error: empty response from model (reasoning_only)"
    );
    let out = captured.text();
    let doc: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("stdout must be one JSON document ({e}): {out}"));
    assert_eq!(doc["type"], "error");
    assert_eq!(
        doc["message"],
        "Internal error: empty response from model (reasoning_only)"
    );
}

/// Drive `finish_turn` through the hard cap with a turn that already answered, capturing stdout.
fn capped_run_output(format: super::OutputFormat) -> String {
    let captured = CapturedOut::default();
    let mut emitter = super::HeadlessEmitter::with_writer(format, true, Box::new(captured.clone()));
    emitter.on_text_chunk("the answer");
    let err = super::finish_turn(
        &mut emitter,
        Some(Ok(completed_prompt_response())),
        true,
        Some(std::time::Duration::from_secs(300)),
        &acp::SessionId::new("sess-1"),
        false,
    )
    .expect_err("a capped run must still exit non-zero");
    assert!(
        err.to_string().contains("Timed out after 300s"),
        "the timeout must still be reported, got: {err}"
    );
    captured.text()
}

/// `--output-format json` must stay ONE parseable document. Reporting the cap as a second
/// document after the completed turn's result breaks `json.loads` / `JSON.parse` outright ("Extra
/// data"), in the mode `--timeout` is documented for.
#[test]
fn the_hard_cap_emits_one_json_document_carrying_both_the_result_and_the_timeout() {
    let out = capped_run_output(super::OutputFormat::Json);
    let doc: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("stdout must parse as exactly one JSON document ({e}): {out}"));
    assert_eq!(
        doc["stopReason"], "cancelled",
        "the cap must be visible on the one terminal document: {doc}"
    );
    assert_eq!(
        doc["error"], "Timed out after 300s waiting for the turn to end",
        "the timeout message must ride on that document: {doc}"
    );
    assert_eq!(
        doc["text"], "the answer",
        "the completed turn's answer must survive: {doc}"
    );
    assert!(
        doc["usage"].is_object(),
        "the completed turn's spend record must ride on the same document: {doc}"
    );
    assert_eq!(
        doc["structuredOutput"],
        serde_json::json!({"answer": "42"}),
        "the completed turn's structured output must survive: {doc}"
    );
}

/// `--output-format stream-json` must carry exactly one `result` line: a consumer that stops at the
/// first terminal line would otherwise report SUCCESS for a run that timed out and exited 1, and
/// one that reads to EOF would double-count `usage`.
#[test]
fn the_hard_cap_emits_one_stream_json_result_line() {
    let out = capped_run_output(super::OutputFormat::StreamingMessagesJson);
    let results: Vec<serde_json::Value> = out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("each line is JSON"))
        .filter(|v| v["type"] == "result")
        .collect();
    assert_eq!(
        results.len(),
        1,
        "exactly one terminal result line, got {}: {out}",
        results.len()
    );
    let result = &results[0];
    assert_eq!(result["is_error"], true, "the run failed: {result}");
    assert_eq!(
        result["errors"],
        serde_json::json!(["Timed out after 300s waiting for the turn to end"]),
        "the one result line must name the cap: {result}"
    );
    assert_eq!(
        result["result"], "the answer",
        "the answer the turn already paid for must ride on it: {result}"
    );
    assert_eq!(
        result["structured_output"],
        serde_json::json!({"answer": "42"}),
        "so must its structured output: {result}"
    );
}

/// Same contract for the native `streaming-json` reducer: one terminal line, not `end` then `error`.
#[test]
fn the_hard_cap_emits_one_streaming_json_terminal_line() {
    let out = capped_run_output(super::OutputFormat::StreamingJson);
    let terminal: Vec<serde_json::Value> = out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("each line is JSON"))
        .filter(|v| v["type"] == "end" || v["type"] == "error")
        .collect();
    assert_eq!(
        terminal.len(),
        1,
        "exactly one terminal line, got {}: {out}",
        terminal.len()
    );
    assert_eq!(terminal[0]["type"], "end");
    assert_eq!(terminal[0]["stopReason"], "cancelled");
    assert_eq!(
        terminal[0]["error"],
        "Timed out after 300s waiting for the turn to end"
    );
    assert_eq!(
        terminal[0]["structuredOutput"],
        serde_json::json!({"answer": "42"}),
        "the completed turn's structured output must ride on it: {}",
        terminal[0]
    );
}

/// A turn that completed with no cap in play keeps its normal single success document.
#[test]
fn a_normal_turn_still_emits_one_success_document() {
    let captured = CapturedOut::default();
    let mut emitter = super::HeadlessEmitter::with_writer(
        super::OutputFormat::Json,
        true,
        Box::new(captured.clone()),
    );
    super::finish_turn(
        &mut emitter,
        Some(Ok(completed_prompt_response())),
        false,
        None,
        &acp::SessionId::new("sess-1"),
        false,
    )
    .expect("an uncapped completed turn succeeds");
    let doc: serde_json::Value = serde_json::from_str(&captured.text()).expect("one JSON document");
    assert_eq!(doc["stopReason"], "end_turn");
    assert!(
        doc.get("error").is_none(),
        "no cap fired, so no error field: {doc}"
    );
}

/// A `session/load` that runs out of run budget must say so. Reporting "Session does not exist"
/// sends the operator to the wrong remedy — re-running without `--resume`, losing the conversation.
#[tokio::test]
async fn a_session_load_that_hits_the_run_cap_reports_the_timeout() {
    let (acp_tx, _agent_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpAgentMessage>();
    let tmp = tempfile::tempdir().expect("tmp cwd");
    let msg = match super::open_session(
        &acp_tx,
        tmp.path(),
        Some("sess-resume-1"),
        None,
        super::RunDeadline::start(Some(std::time::Duration::from_millis(50))),
    )
    .await
    {
        Ok(_) => panic!("an unanswered session/load must fail"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("timed out") && msg.contains("session/load"),
        "a run-cap timeout must be reported as one, got: {msg}"
    );
    assert!(
        !msg.contains("Session does not exist"),
        "a timeout is not a missing session, got: {msg}"
    );
}

/// The 120s lifecycle cap applies even to runs that asked for no `--timeout`, so it needs a way out:
/// a cold `FUIGO_HOME` on a network mount can legitimately take longer to answer `initialize`, and
/// that run worked in 1.0.16. `0` disables it; anything malformed keeps the default.
#[test]
fn the_lifecycle_cap_has_an_escape_hatch() {
    assert_eq!(
        super::parse_lifecycle_timeout_env(None),
        Some(super::DEFAULT_LIFECYCLE_SEND_TIMEOUT),
        "unset keeps the default cap"
    );
    assert_eq!(
        super::parse_lifecycle_timeout_env(Some("  ")),
        Some(super::DEFAULT_LIFECYCLE_SEND_TIMEOUT),
        "empty keeps the default cap"
    );
    assert_eq!(
        super::parse_lifecycle_timeout_env(Some("soon")),
        Some(super::DEFAULT_LIFECYCLE_SEND_TIMEOUT),
        "garbage keeps the default cap rather than breaking startup"
    );
    assert_eq!(
        super::parse_lifecycle_timeout_env(Some("600")),
        Some(std::time::Duration::from_secs(600)),
        "a slow host can raise it"
    );
    assert_eq!(
        super::parse_lifecycle_timeout_env(Some("0")),
        None,
        "0 restores the unbounded 1.0.16 startup sends"
    );
    assert_eq!(
        super::RunDeadline::start(None).budget(super::parse_lifecycle_timeout_env(Some("0"))),
        None,
        "with the hatch open and no --timeout, the startup sends are unbounded again"
    );
}
