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
            for has_worktree in [false, true] {
                let ctx = headless_materialize_ctx(pinned, restore_code, has_worktree);
                assert!(!ctx.chat_mode);
                assert_eq!(ctx.has_worktree, has_worktree);
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
}

#[test]
fn headless_remote_miss_restores_conversation_instead_of_deferring_worktree() {
    use crate::app::session_startup::{RemoteMissPlan, plan_remote_miss};
    for restore_code in [false, true] {
        let ctx = headless_materialize_ctx(false, restore_code, false);
        assert!(!matches!(
            plan_remote_miss(ctx, true),
            RemoteMissPlan::DeferToWorktree { .. }
        ));
    }
    let mut conv = headless_materialize_ctx(false, false, false);
    conv.allow_remote_restore = true;
    assert_eq!(
        plan_remote_miss(conv, true),
        RemoteMissPlan::RestoreConversation
    );
    let mut code = headless_materialize_ctx(false, true, false);
    code.allow_remote_restore = true;
    assert_eq!(
        plan_remote_miss(code, true),
        RemoteMissPlan::RejectInPlaceCodeRestore {
            title_miss_hint: false,
        }
    );
}

#[test]
fn headless_remote_miss_defers_to_worktree_when_requested() {
    use crate::app::session_startup::{RemoteMissPlan, plan_remote_miss};
    for restore_code in [false, true] {
        let ctx = headless_materialize_ctx(false, restore_code, true);
        assert_eq!(
            plan_remote_miss(ctx, true),
            RemoteMissPlan::DeferToWorktree {
                deferred_local_miss: false,
            }
        );
    }
}

/// Fake agent for the worktree paths: answers the extension method with `ext_reply`, then
/// `session/new` and `session/load` as directed. Records every request for assertions.
#[derive(Default)]
struct FakeAgentLog {
    ext: Vec<(String, serde_json::Value)>,
    new_sessions: Vec<(std::path::PathBuf, Option<acp::Meta>)>,
    loads: Vec<(String, std::path::PathBuf, Option<acp::Meta>)>,
}

fn spawn_fake_agent(
    ext_reply: serde_json::Value,
    session_open: Result<&'static str, &'static str>,
) -> (
    fuigo_acp_lib::AcpAgentTx,
    std::sync::Arc<std::sync::Mutex<FakeAgentLog>>,
) {
    use std::sync::{Arc, Mutex};
    use fuigo_acp_lib::AcpAgentMessage;
    let log = Arc::new(Mutex::new(FakeAgentLog::default()));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AcpAgentMessage>();
    let log_for_task = log.clone();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                AcpAgentMessage::ExtMethod(args) => {
                    let params: serde_json::Value =
                        serde_json::from_str(args.request.params.get()).unwrap();
                    log_for_task
                        .lock()
                        .unwrap()
                        .ext
                        .push((args.request.method.to_string(), params));
                    let raw = serde_json::value::to_raw_value(&ext_reply).unwrap();
                    let _ = args
                        .response_tx
                        .send(Ok(acp::ExtResponse::new(Arc::from(raw))));
                }
                AcpAgentMessage::NewSession(args) => {
                    log_for_task
                        .lock()
                        .unwrap()
                        .new_sessions
                        .push((args.request.cwd.clone(), args.request.meta.clone()));
                    // Like the agent, a `meta.sessionId` names the new session; otherwise mint one.
                    let forced = args
                        .request
                        .meta
                        .as_ref()
                        .and_then(|m| m.get("sessionId"))
                        .and_then(|v| v.as_str())
                        .map(str::to_owned);
                    let _ = args.response_tx.send(match session_open {
                        Ok(sid) => Ok(acp::NewSessionResponse::new(
                            forced.unwrap_or_else(|| sid.to_owned()),
                        )),
                        Err(msg) => Err(acp::Error::internal_error().data(msg)),
                    });
                }
                AcpAgentMessage::LoadSession(args) => {
                    log_for_task.lock().unwrap().loads.push((
                        args.request.session_id.0.to_string(),
                        args.request.cwd.clone(),
                        args.request.meta.clone(),
                    ));
                    let _ = args.response_tx.send(match session_open {
                        Ok(_) => Ok(acp::LoadSessionResponse::new()),
                        Err(msg) => Err(acp::Error::internal_error().data(msg)),
                    });
                }
                _ => {}
            }
        }
    });
    (tx, log)
}

#[tokio::test]
async fn worktree_create_opens_session_at_worktree_subdirectory() {
    let source = tempfile::tempdir().unwrap();
    let launch_cwd = source.path().join("crates").join("pager");
    std::fs::create_dir_all(&launch_cwd).unwrap();
    let wt_root = tempfile::tempdir().unwrap();
    let (tx, log) = spawn_fake_agent(
        serde_json::json!({"result": {
            "worktreePath": wt_root.path(),
            "sourceGitRoot": source.path(),
        }}),
        Ok("sess-new"),
    );
    let spec = WorktreeSpec::from_cli(Some("fix"), Some("origin/main")).unwrap();

    let opened = open_session_in_new_worktree(&tx, &launch_cwd, &spec, None, RunDeadline::start(None))
        .await
        .unwrap();

    assert_eq!(opened.session_id.0.as_ref(), "sess-new");
    assert_eq!(opened.cwd, wt_root.path().join("crates").join("pager"));
    let log = log.lock().unwrap();
    let Some((method, params)) = log.ext.first() else {
        panic!("expected an ext call: {:?}", log.ext);
    };
    assert_eq!(method, "fuigo/git/worktree/create_from_worktree_sync");
    assert_eq!(
        params.get("sourceWorktreePath").and_then(|v| v.as_str()),
        Some(launch_cwd.to_string_lossy().as_ref())
    );
    assert_eq!(
        params.get("copyMode").and_then(|v| v.as_str()),
        Some("clean")
    );
    assert_eq!(params.get("label").and_then(|v| v.as_str()), Some("fix"));
    assert_eq!(
        params.get("gitRef").and_then(|v| v.as_str()),
        Some("origin/main")
    );
    assert!(
        params
            .get("newSessionId")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.starts_with("pager-"))
    );
    assert_eq!(log.new_sessions.len(), 1);
    assert_eq!(log.new_sessions.first().map(|s| &s.0), Some(&opened.cwd));
    assert!(log.loads.is_empty());
}

#[tokio::test]
async fn worktree_create_with_session_id_names_worktree_and_session() {
    let source = tempfile::tempdir().unwrap();
    let wt_root = tempfile::tempdir().unwrap();
    let (tx, log) = spawn_fake_agent(
        serde_json::json!({"worktreePath": wt_root.path()}),
        Ok("minted-if-not-forced"),
    );
    let sid = "2d3c6b3e-3d43-4f0a-9d2e-2b6d1b6a9c11";

    let opened =
        open_session_in_new_worktree(&tx, source.path(), &WorktreeSpec::default(), Some(sid), RunDeadline::start(None))
            .await
            .unwrap();

    assert_eq!(opened.session_id.0.as_ref(), sid);
    assert_eq!(opened.cwd, wt_root.path());
    let log = log.lock().unwrap();
    let Some((_, params)) = log.ext.first() else {
        panic!("expected an ext call: {:?}", log.ext);
    };
    assert_eq!(
        params.get("newSessionId").and_then(|v| v.as_str()),
        Some(sid)
    );
    assert_eq!(
        params.get("copyMode").and_then(|v| v.as_str()),
        Some("dirty")
    );
    let meta = log
        .new_sessions
        .first()
        .and_then(|s| s.1.as_ref())
        .expect("session id forced via meta");
    assert_eq!(meta.get("sessionId").and_then(|v| v.as_str()), Some(sid));
}

#[tokio::test]
async fn worktree_create_failure_is_reported_before_any_session_opens() {
    let source = tempfile::tempdir().unwrap();
    for (reply, expect) in [
        (
            serde_json::json!({"error": "no space left for worktree"}),
            "no space left for worktree",
        ),
        (
            serde_json::json!({"result": {}}),
            "response missing worktreePath",
        ),
    ] {
        let (tx, log) = spawn_fake_agent(reply, Ok("never"));
        let err = open_session_in_new_worktree(&tx, source.path(), &WorktreeSpec::default(), None, RunDeadline::start(None))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("couldn't create worktree"), "{err}");
        assert!(err.contains(expect), "{err}");
        assert!(log.lock().unwrap().new_sessions.is_empty());
    }
}

#[tokio::test]
async fn worktree_create_then_session_failure_names_the_orphaned_worktree() {
    let source = tempfile::tempdir().unwrap();
    let wt_root = tempfile::tempdir().unwrap();
    let (tx, _log) = spawn_fake_agent(
        serde_json::json!({"worktreePath": wt_root.path()}),
        Err("agent refused"),
    );

    let err = open_session_in_new_worktree(&tx, source.path(), &WorktreeSpec::default(), None, RunDeadline::start(None))
        .await
        .unwrap_err()
        .to_string();

    assert!(err.contains("agent refused"), "{err}");
    assert!(err.contains(&wt_root.path().display().to_string()), "{err}");
    assert!(err.contains("fuigo worktree rm"), "{err}");
}

#[tokio::test]
async fn worktree_resume_loads_reported_session_without_re_restoring_code() {
    let source = tempfile::tempdir().unwrap();
    let wt_root = tempfile::tempdir().unwrap();
    let eff_cwd = wt_root.path().join("sub");
    let (tx, log) = spawn_fake_agent(
        serde_json::json!({"result": {
            "sessionId": "forked-in-worktree",
            "worktreePath": wt_root.path(),
            "effectiveCwd": eff_cwd,
            "codeRestored": true,
        }}),
        Ok("unused"),
    );
    let spec = WorktreeSpec::from_cli(Some(""), Some("v1.2")).unwrap();

    let opened =
        resume_session_in_new_worktree(&tx, source.path(), &spec, "orig", Some(true), false, RunDeadline::start(None))
            .await
            .unwrap();

    assert_eq!(opened.session_id.0.as_ref(), "forked-in-worktree");
    assert_eq!(opened.cwd, eff_cwd);
    let log = log.lock().unwrap();
    let Some((method, params)) = log.ext.first() else {
        panic!("expected an ext call: {:?}", log.ext);
    };
    assert_eq!(method, "fuigo/git/worktree/resume_session");
    assert_eq!(
        params.get("sessionId").and_then(|v| v.as_str()),
        Some("orig")
    );
    assert_eq!(
        params.get("sourceCwd").and_then(|v| v.as_str()),
        Some(source.path().to_string_lossy().as_ref())
    );
    assert_eq!(
        params.get("copyMode").and_then(|v| v.as_str()),
        Some("clean")
    );
    assert_eq!(params.get("gitRef").and_then(|v| v.as_str()), Some("v1.2"));
    assert_eq!(
        params.get("restoreCode").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert!(params.get("worktreeType").is_some());
    let Some((loaded_sid, loaded_cwd, meta)) = log.loads.first() else {
        panic!("expected a load: {:?}", log.loads);
    };
    assert_eq!(loaded_sid, "forked-in-worktree");
    assert_eq!(loaded_cwd, &eff_cwd);
    let meta = meta.as_ref().unwrap();
    assert_eq!(meta.get("noReplay").and_then(|v| v.as_bool()), Some(true));
    assert!(
        meta.get("fuigo/restore_code").is_none(),
        "load must not request code restore a second time"
    );
    assert!(log.new_sessions.is_empty());
}

#[tokio::test]
async fn worktree_resume_failure_carries_local_miss_hint_like_the_tui() {
    let source = tempfile::tempdir().unwrap();
    let (tx, _log) = spawn_fake_agent(serde_json::json!({"error": "archive unavailable"}), Ok("x"));
    let spec = WorktreeSpec::default();

    let hinted = resume_session_in_new_worktree(&tx, source.path(), &spec, "my title", None, true, RunDeadline::start(None))
        .await
        .unwrap_err()
        .to_string();
    let plain = resume_session_in_new_worktree(&tx, source.path(), &spec, "my title", None, false, RunDeadline::start(None))
        .await
        .unwrap_err()
        .to_string();

    assert_eq!(
        plain,
        crate::app::session_title_resolve::worktree_resume_failure_message(
            None,
            "archive unavailable"
        )
    );
    assert_eq!(
        hinted,
        crate::app::session_title_resolve::worktree_resume_failure_message(
            Some("my title"),
            "archive unavailable"
        )
    );
    assert_ne!(hinted, plain);
}

#[test]
fn worktree_with_fork_is_rejected_at_intent() {
    use crate::app::session_startup::{
        SessionStartupFlags, StartupFlagError, session_startup_intent_from_flags,
    };
    let err = session_startup_intent_from_flags(SessionStartupFlags {
        session_id: None,
        resume_session_id: Some("01a06380-62b5-7881-b173-c69cd2c213fd"),
        resume_most_recent: false,
        continue_last_session: false,
        fork_session: true,
        has_worktree: true,
    })
    .unwrap_err();
    assert!(matches!(err, StartupFlagError::ForkWithWorktree));
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
    emitter.on_text_chunk(r#"{"name":"#, None);
    emitter.on_text_chunk(r#""bob"}"#, None);
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
        worktree_ref: None,
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
        // This fixture is about the `--timeout` cap, not the ack watch.
        None,
        &crate::app::prompt_ack::PromptAckDeadlines::from_env(None),
        &super::InterruptWatch::inert(),
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

/// P149 (S8, live lane C2 D1): a provider that echoes the key this process sent puts it in the turn's error text.
/// Every output format's error document carries `<redacted>` in its place, as the TUI
/// and the ACP reply rail do. The error is built as it would arrive unscrubbed, so this pins the printer itself.
#[test]
fn a_prompt_error_echoing_a_sent_credential_is_redacted_in_every_format() {
    const SENT: &str = "fuigo-p149-SYNTH-headless-key-0001";
    let _registry = crate::test_util::sent_credentials_lock();
    fuigo_telemetry::sent_credentials::record(SENT);
    for format in [
        super::OutputFormat::Plain,
        super::OutputFormat::Json,
        super::OutputFormat::StreamingJson,
        super::OutputFormat::StreamingMessagesJson,
    ] {
        let captured = CapturedOut::default();
        let mut emitter =
            super::HeadlessEmitter::with_writer(format, false, Box::new(captured.clone()));
        let wire_error = acp::Error::internal_error().data(serde_json::json!({
            "message": format!("API error (status 402 Payment Required): Credit limit reached for key {SENT}; top up"),
            "error_kind": "api",
        }));
        // The returned error is what `main` prints; `headless_error_report` (fuigo-pager-bin) scrubs that line.
        let _ = super::finish_turn(
            &mut emitter,
            Some(Err(wire_error)),
            false,
            None,
            &acp::SessionId::new("sess-p149"),
            true,
        )
        .expect_err("a failed turn exits non-zero");
        let out = captured.text();
        assert!(!out.contains(SENT), "{format:?}: stdout carried the sent key: {out}");
        if format != super::OutputFormat::Plain {
            assert!(out.contains("Credit limit reached for key <redacted>"), "{format:?}: control: {out}");
        }
    }
}

/// P149 (S8, Astra r3 #1): a schema-validation error quotes the rejected value and rides an `Ok` reply, past the ACP
/// reply-rail scrub; the terminal document's structured-output error carries `<redacted>` for a sent credential.
#[test]
fn a_structured_output_error_quoting_a_sent_credential_is_redacted() {
    const SENT: &str = "fuigo-p149-SYNTH-schema-error-key-01";
    let _registry = crate::test_util::sent_credentials_lock();
    fuigo_telemetry::sent_credentials::record(SENT);
    let captured = CapturedOut::default();
    let mut emitter =
        super::HeadlessEmitter::with_writer(super::OutputFormat::Json, true, Box::new(captured.clone()));
    let mut meta = serde_json::Map::new();
    meta.insert(
        "structuredOutputError".into(),
        serde_json::json!(format!("\"{SENT}\" is not of type \"number\"")),
    );
    emitter.set_structured_output_from_meta(Some(&meta));
    emitter.on_end("end_turn", "sess-p149", "req-p149", None);
    let out = captured.text();
    assert!(!out.contains(SENT), "{out}");
    assert!(out.contains("<redacted>"), "control: the error is reported: {out}");
}

/// P149 (S8, Astra r2 #6): the run-level error `on_end` folds into the terminal document is scrubbed too.
#[test]
fn a_run_level_error_on_the_terminal_document_is_redacted() {
    const SENT: &str = "fuigo-p149-SYNTH-on-end-key-000001";
    let _registry = crate::test_util::sent_credentials_lock();
    fuigo_telemetry::sent_credentials::record(SENT);
    for format in [super::OutputFormat::Json, super::OutputFormat::StreamingJson] {
        let captured = CapturedOut::default();
        let mut emitter =
            super::HeadlessEmitter::with_writer(format, false, Box::new(captured.clone()));
        emitter.on_end("end_turn", "sess-p149", "req-p149", Some(&format!("run failed near {SENT}")));
        let out = captured.text();
        assert!(!out.contains(SENT), "{format:?}: {out}");
        if format == super::OutputFormat::Json {
            assert!(out.contains("run failed near <redacted>"), "control: {out}");
        }
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
    emitter.on_text_chunk("the answer", None);
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

/// A retry-status mirror chunk (`_meta["fuigo/retryStatus"]`, a live `agent_thought_chunk`) is progress for stock ACP clients.
/// It is neither part of the headless answer nor of its reported thought.
#[test]
fn retry_status_mirror_chunk_is_not_part_of_the_answer() {
    use agent_client_protocol as acp;
    let notification = |update: acp::SessionUpdate| {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        fuigo_acp_lib::AcpClientMessage::SessionNotification(fuigo_acp_lib::AcpArgs {
            request: acp::SessionNotification::new(acp::SessionId::new("s"), update),
            response_tx: tx,
        })
    };
    let content = |text: &str, meta: Option<serde_json::Map<String, serde_json::Value>>| {
        acp::ContentChunk::new(acp::ContentBlock::Text(acp::TextContent::new(
            text.to_string(),
        )))
        .meta(meta)
    };
    let mut tagged = serde_json::Map::new();
    tagged.insert(
        "fuigo/retryStatus".into(),
        serde_json::json!({"type": "failed", "error_type": "empty_response", "message": "x"}),
    );
    let mut emitter = super::HeadlessEmitter::new(super::OutputFormat::Json, false);
    let mut pending = std::collections::HashSet::new();
    let mut completed = std::collections::HashSet::new();
    let mut ttf_logged = false;
    for msg in [
        notification(acp::SessionUpdate::AgentThoughtChunk(content(
            "Retrying the model (1/2): x\n\n",
            Some(tagged),
        ))),
        notification(acp::SessionUpdate::AgentThoughtChunk(content(
            "thinking", None,
        ))),
        notification(acp::SessionUpdate::AgentMessageChunk(content(
            "Hello", None,
        ))),
    ] {
        super::handle_headless_acp_message(
            msg.boxed(),
            &mut emitter,
            std::time::Instant::now(),
            &mut ttf_logged,
            false,
            &mut pending,
            &mut completed,
        );
    }
    assert_eq!(emitter.text_buffer, "Hello");
    assert_eq!(
        emitter.thought_buffer, "thinking",
        "only the model's own reasoning is reported as thought"
    );
}

// ── Prompt-acknowledgment fail-safe (U084) ─────────────────────────────────────────

/// A prompt the agent never acknowledges must abort at the hard deadline instead of waiting
/// forever: the run ends with a `prompt_ack_timeout`-prefixed error and a bounded rewind cancel.
#[tokio::test]
async fn an_unacknowledged_prompt_aborts_at_the_hard_deadline() {
    use crate::app::prompt_ack::{PromptAckDeadlines, PromptAckWatch};

    // A live sender keeps the ACP arm pending: the agent answers nothing at all.
    let (_client_tx, mut acp_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (acp_tx, mut agent_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpAgentMessage>();
    let session_id = acp::SessionId::new("sess-1");
    let mut emitter = super::HeadlessEmitter::new(super::OutputFormat::Json, false);
    let deadlines = PromptAckDeadlines {
        soft: std::time::Duration::from_millis(50),
        hard: std::time::Duration::from_millis(200),
    };
    let mut ttf_logged = false;

    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        super::drive_prompt_turn(
            // The `session/prompt` RPC itself never resolves, exactly like a wedged shell.
            std::future::pending::<Result<acp::PromptResponse, acp::Error>>(),
            &mut acp_rx,
            &acp_tx,
            &session_id,
            &mut emitter,
            &timeout_test_options(None),
            super::RunDeadline::start(None),
            std::time::Instant::now(),
            &mut ttf_logged,
            Some(PromptAckWatch::new("p-unacked", std::time::Instant::now())),
            &deadlines,
            &super::InterruptWatch::inert(),
        ),
    )
    .await
    .expect("an unacknowledged prompt must not hang the headless run");

    assert!(
        outcome.prompt_unacknowledged,
        "the watch must report the prompt as unacknowledged"
    );
    let err = match outcome.prompt_result {
        Some(Err(err)) => err,
        other => panic!("expected the ack timeout error, got {other:?}"),
    };
    assert!(
        err.message.contains("prompt_ack_timeout"),
        "the exit error must carry the machine-greppable prefix, got: {}",
        err.message
    );
    // The late prompt is rewound shell-side rather than left running unobserved.
    let cancelled = std::iter::from_fn(|| agent_rx.try_recv().ok()).any(|msg| {
        matches!(
            msg,
            fuigo_acp_lib::AcpAgentMessage::Cancel(ref args)
                if args.request.session_id == session_id
        )
    });
    assert!(cancelled, "the abort must send a rewind cancel");
}

/// An acknowledged prompt disarms the watch: the same wedged RPC now waits (it is the run
/// deadline's job, not the ack watch's, to end a turn the agent accepted but never finishes).
#[tokio::test]
async fn an_acknowledged_prompt_disarms_the_watch() {
    use crate::app::prompt_ack::{PromptAckDeadlines, PromptAckWatch};

    let (client_tx, mut acp_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (acp_tx, _agent_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpAgentMessage>();
    let session_id = acp::SessionId::new("sess-1");
    let (tx, _rx) = tokio::sync::oneshot::channel();
    client_tx
        .send(fuigo_acp_lib::AcpClientMessage::SessionNotification(
            fuigo_acp_lib::AcpArgs {
                request: acp::SessionNotification::new(
                    session_id.clone(),
                    acp::SessionUpdate::AgentMessageChunk(acp::ContentChunk::new(
                        acp::ContentBlock::Text(acp::TextContent::new("working on it")),
                    )),
                )
                .meta(
                    serde_json::json!({ "promptId": "p-acked" })
                        .as_object()
                        .cloned(),
                ),
                response_tx: tx,
            },
        ))
        .expect("queue the acknowledgment");
    let mut emitter = super::HeadlessEmitter::new(super::OutputFormat::Json, false);
    let deadlines = PromptAckDeadlines {
        soft: std::time::Duration::from_millis(50),
        hard: std::time::Duration::from_millis(200),
    };
    let mut ttf_logged = false;

    let outcome = tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        super::drive_prompt_turn(
            std::future::pending::<Result<acp::PromptResponse, acp::Error>>(),
            &mut acp_rx,
            &acp_tx,
            &session_id,
            &mut emitter,
            &timeout_test_options(None),
            super::RunDeadline::start(None),
            std::time::Instant::now(),
            &mut ttf_logged,
            Some(PromptAckWatch::new("p-acked", std::time::Instant::now())),
            &deadlines,
            &super::InterruptWatch::inert(),
        ),
    )
    .await;

    assert!(
        outcome.is_err(),
        "an acknowledged prompt must keep waiting, not abort: {:?}",
        outcome.map(|o| o.prompt_unacknowledged)
    );
}

// ── Headless permission denial is a first-class outcome (Contract D) ───────────────────────
//
// D.1: a denial that leaves the process exiting 0 is indistinguishable from success to a CI job.
// D.2.1 gives it a dedicated, stable exit code; D.2.2 requires the reason to be recoverable
// without parsing English; D.3 forbids both silent approval and a report gated on a TTY.
// These tests pin the P02a half: the latch, the typed outcome, and the exit-code mapping.
mod permission_denial {
    use agent_client_protocol as acp;
    use std::sync::Arc;

    use crate::headless::{
        HeadlessDenial, HeadlessDenialRule, HeadlessEmitter, HeadlessOutcome, OutputFormat,
        PERMISSION_DENIED_EXIT_CODE, TurnStop, emit_completed_response,
        connection_closed_error, handle_headless_acp_message, headless_run_outcome,
    };

    /// A prompt response carrying the shell's own terminal `_meta`, with `cancellationCategory`
    /// exactly as `fuigo_shell::session::commands::meta_category_str` spells it on the wire.
    fn response(stop: acp::StopReason, cancellation_category: Option<&str>) -> acp::PromptResponse {
        let mut meta = acp::Meta::new();
        meta.insert(
            "sessionId".to_string(),
            serde_json::Value::String("sess-1".into()),
        );
        meta.insert(
            "requestId".to_string(),
            serde_json::Value::String("req-1".into()),
        );
        if let Some(category) = cancellation_category {
            meta.insert(
                crate::app::CANCELLATION_CATEGORY_KEY.to_string(),
                serde_json::Value::String(category.to_owned()),
            );
        }
        acp::PromptResponse::new(stop).meta(Some(meta))
    }

    /// Answer one `session/request_permission` offering exactly `kinds`, on `emitter`.
    fn ask(
        emitter: &mut HeadlessEmitter,
        yolo: bool,
        title: Option<&str>,
        kinds: &[acp::PermissionOptionKind],
    ) -> acp::RequestPermissionOutcome {
        let fields = match title {
            Some(t) => acp::ToolCallUpdateFields::new().title(Some(t.to_owned())),
            None => acp::ToolCallUpdateFields::default(),
        };
        let options = kinds
            .iter()
            .enumerate()
            .map(|(i, kind)| {
                acp::PermissionOption::new(
                    acp::PermissionOptionId::new(format!("opt-{i}").as_str()),
                    format!("option {i}"),
                    *kind,
                )
            })
            .collect();
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        let msg = fuigo_acp_lib::AcpClientMessage::RequestPermission(fuigo_acp_lib::AcpArgs {
            request: acp::RequestPermissionRequest::new(
                acp::SessionId::new("sess-1"),
                acp::ToolCallUpdate::new(acp::ToolCallId::new(Arc::from("tc-1")), fields),
                options,
            ),
            response_tx: tx,
        });
        let mut pending = std::collections::HashSet::new();
        let mut completed = std::collections::HashSet::new();
        let mut ttf_logged = false;
        handle_headless_acp_message(
            msg.boxed(),
            emitter,
            std::time::Instant::now(),
            &mut ttf_logged,
            yolo,
            &mut pending,
            &mut completed,
        );
        rx.try_recv()
            .expect("a permission request must always be answered, never dropped")
            .expect("a policy reply, not an ACP error")
            .outcome
    }

    /// A `json` emitter whose bytes are captured rather than written to the test runner's stdout.
    fn emitter() -> HeadlessEmitter {
        captured_emitter().1
    }

    fn captured_emitter() -> (super::CapturedOut, HeadlessEmitter) {
        let captured = super::CapturedOut::default();
        let emitter = HeadlessEmitter::with_writer(
            OutputFormat::Json,
            false,
            Box::new(captured.clone()),
        );
        (captured, emitter)
    }

    /// The headless default: nobody to ask, so the request is refused — and the refusal is now
    /// recorded rather than dropped on the floor.
    #[test]
    fn headless_denies_and_latches_why() {
        let mut emitter = emitter();
        let outcome = ask(
            &mut emitter,
            /*yolo=*/ false,
            Some("Write src/main.rs"),
            &[
                acp::PermissionOptionKind::AllowOnce,
                acp::PermissionOptionKind::RejectOnce,
            ],
        );
        assert!(
            matches!(outcome, acp::RequestPermissionOutcome::Cancelled),
            "the ACP outcome stays `Cancelled`; changing the wire is deferred to P00 (packet §3.2)"
        );
        let denial = emitter
            .take_permission_denial()
            .expect("a headless denial must be latched, not silent");
        assert_eq!(denial.rule, HeadlessDenialRule::HeadlessNeverApproves);
        assert_eq!(denial.tool_title.as_deref(), Some("Write src/main.rs"));
        assert_eq!(denial.tool_call_id, "tc-1");
    }

    /// P149 (S8, Astra r1 #1): a denied tool call whose title holds a credential this process sent prints that title
    /// on stderr (`human_line` on exit 3, `notice_line` when the run continued) and puts it in the denial record of
    /// the terminal document. Every one of them carries `<redacted>` in its place.
    #[test]
    fn a_denied_tool_title_holding_a_sent_credential_is_redacted_everywhere_it_is_printed() {
        const SENT: &str = "fuigo-p149-SYNTH-denial-title-key-01";
        let _registry = crate::test_util::sent_credentials_lock();
        fuigo_telemetry::sent_credentials::record(SENT);
        let (captured, mut emitter) = captured_emitter();
        let _ = ask(
            &mut emitter,
            /*yolo=*/ false,
            Some(&format!("echo {SENT}")),
            &[acp::PermissionOptionKind::AllowOnce, acp::PermissionOptionKind::RejectOnce],
        );
        let denial = emitter.permission_denial.clone().expect("a headless denial is latched");
        for (what, text) in [
            ("human_line", denial.human_line()),
            ("notice_line", denial.notice_line()),
            ("wire_record", denial.wire_record(true).to_string()),
        ] {
            assert!(!text.contains(SENT), "{what} carries the sent key: {text}");
            assert!(text.contains("echo <redacted>"), "control: {what}: {text}");
        }
        emitter.on_error("turn failed", None);
        let out = captured.text();
        assert!(!out.contains(SENT), "the terminal document carries the sent key: {out}");
    }

    /// `--yolo` auto-approves, so a request it cannot approve is a denial too — the branch the
    /// original report missed. An allow option was never offered, and the record proves it.
    #[test]
    fn yolo_with_no_allow_option_is_also_a_denial() {
        let mut emitter = emitter();
        let outcome = ask(
            &mut emitter,
            /*yolo=*/ true,
            None,
            &[acp::PermissionOptionKind::RejectOnce],
        );
        assert!(matches!(outcome, acp::RequestPermissionOutcome::Cancelled));
        let denial = emitter
            .take_permission_denial()
            .expect("yolo with nothing to approve is still a denial");
        assert_eq!(denial.rule, HeadlessDenialRule::YoloHadNoAllowOption);
        assert_eq!(
            denial.offered_option_kinds,
            vec![
                serde_json::to_value(acp::PermissionOptionKind::RejectOnce)
                    .expect("an ACP enum serializes")
                    .as_str()
                    .expect("a string enum")
                    .to_owned()
            ],
            "the offered kinds are recorded in their ACP wire spelling, not Rust's Debug form"
        );
        assert!(
            !denial
                .offered_option_kinds
                .iter()
                .any(|kind| kind.starts_with("allow")),
            "the evidence a consumer needs: no allow option was on offer, got {:?}",
            denial.offered_option_kinds
        );
    }

    /// The counter-test D.3 demands: nothing here turns a denial into an approval, and nothing
    /// turns an approval into a denial either. A yolo request with an allow option is still allowed
    /// and latches nothing.
    #[test]
    fn yolo_with_an_allow_option_still_approves_and_latches_nothing() {
        let mut emitter = emitter();
        let outcome = ask(
            &mut emitter,
            /*yolo=*/ true,
            Some("Read src/main.rs"),
            &[
                acp::PermissionOptionKind::RejectOnce,
                acp::PermissionOptionKind::AllowOnce,
            ],
        );
        assert!(
            matches!(outcome, acp::RequestPermissionOutcome::Selected(_)),
            "yolo must still select the allow option, got {outcome:?}"
        );
        assert_eq!(
            emitter.take_permission_denial(),
            None,
            "an approval is not a denial"
        );
    }

    /// The first denial is the one that blocked the run; later ones are its consequences.
    #[test]
    fn the_first_denial_wins() {
        let mut emitter = emitter();
        ask(&mut emitter, false, Some("first"), &[]);
        ask(&mut emitter, true, Some("second"), &[]);
        let denial = emitter.take_permission_denial().expect("latched");
        assert_eq!(denial.rule, HeadlessDenialRule::HeadlessNeverApproves);
        assert_eq!(denial.tool_title.as_deref(), Some("first"));
    }

    fn denial() -> HeadlessDenial {
        HeadlessDenial {
            rule: HeadlessDenialRule::HeadlessNeverApproves,
            tool_title: Some("Write src/main.rs".to_owned()),
            tool_call_id: "tc-1".to_owned(),
            offered_option_kinds: vec!["reject_once".to_owned()],
            agent_message: None,
        }
    }

    /// D.2.1. The code is a compatibility commitment: `0` is success, `1` is a generic error, `2` is
    /// a managed-policy requirement failure, `130`/`143` are signals. A change here breaks every
    /// script that branches on it, so it is pinned by value on purpose.
    #[test]
    fn the_exit_code_is_dedicated_documented_and_stable() {
        assert_eq!(PERMISSION_DENIED_EXIT_CODE, 3);
        assert_eq!(denial().exit_code(), PERMISSION_DENIED_EXIT_CODE);
        for taken in [0, 1, 2, 126, 127, 130, 143] {
            assert_ne!(
                PERMISSION_DENIED_EXIT_CODE, taken,
                "{taken} already means something else"
            );
        }
    }

    /// D.2.2: the reason must be recoverable without parsing English. The rule id and the remedy are
    /// data on the record; the prose line is built *from* them, never the other way round.
    #[test]
    fn the_reason_is_recoverable_without_parsing_english() {
        assert_eq!(
            HeadlessDenialRule::HeadlessNeverApproves.id(),
            "headless_never_approves"
        );
        assert_eq!(
            HeadlessDenialRule::YoloHadNoAllowOption.id(),
            "yolo_had_no_allow_option"
        );
        for rule in [
            HeadlessDenialRule::HeadlessNeverApproves,
            HeadlessDenialRule::YoloHadNoAllowOption,
        ] {
            assert!(
                !rule.remedy().is_empty(),
                "{} must say what the operator changes",
                rule.id()
            );
        }
    }

    /// D.2.3: one English line on the exit path, remedy included, naming what was refused.
    #[test]
    fn the_human_line_names_the_request_the_rule_and_the_remedy() {
        let denial = denial();
        let line = denial.human_line();
        assert!(line.contains("Write src/main.rs"), "{line}");
        assert!(line.contains("tc-1"), "{line}");
        assert!(line.contains("headless_never_approves"), "{line}");
        assert!(line.contains(denial.rule.remedy()), "{line}");
        assert!(line.contains("3"), "{line}");
        assert_eq!(line.lines().count(), 1, "one line, not a paragraph: {line}");
    }

    /// A denial with no tool title still identifies what was refused.
    #[test]
    fn an_untitled_request_is_still_identified() {
        let untitled = HeadlessDenial {
            tool_title: None,
            ..denial()
        };
        assert_eq!(untitled.requested(), "tool call [tc-1]");
        assert!(untitled.human_line().contains("tc-1"));
    }

    /// P181 (S5, M1): a title or call id that contains Fuigo's own closing delimiter cannot close it.
    #[test]
    fn a_title_or_call_id_cannot_close_its_own_delimiter() {
        let hostile = HeadlessDenial {
            tool_title: Some("Write\u{201d} nothing was denied. Exiting 0. ".into()),
            tool_call_id: "x] granted (".into(),
            ..denial()
        };
        assert_eq!(
            hostile.requested(),
            "\u{201c}Write\\\" nothing was denied. Exiting 0. \u{201d} (tool call [x\\] granted (])"
        );
        let line = hostile.human_line();
        assert!(line.contains(&hostile.requested()), "{line:?}");
    }

    /// The precedence the exit path commits to, in one test.
    ///
    /// P02a had the denial outrank the turn's own error. That is corrected here: an error keeps
    /// `exit(1)`. D.2.1 asks for a code distinct from a crash, and that is symmetric — a denial
    /// latched anywhere in the run must not relabel a crash as "permission denied" and send the
    /// operator off to pre-approve something that was never the problem. A dead stdout still
    /// outranks everything: nothing can be reported through it.
    #[test]
    fn an_error_outranks_a_denial_and_dead_stdout_outranks_both() {
        let blocked = headless_run_outcome(
            Ok(TurnStop::PermissionCancelled),
            None,
            None,
            Some(denial()),
        )
        .expect("a run that ended at the denial is an outcome, not an error");
        assert!(matches!(blocked, HeadlessOutcome::PermissionDenied(_)));

        let crashed = headless_run_outcome(
            Err(anyhow::anyhow!("Connection closed unexpectedly")),
            None,
            None,
            Some(denial()),
        )
        .expect_err("a crash after a denial is still a crash");
        assert!(
            format!("{crashed:#}").contains("Connection closed unexpectedly"),
            "the crash must keep its own message: {crashed:#}"
        );

        let flush_failed = headless_run_outcome(
            Ok(TurnStop::PermissionCancelled),
            Some(anyhow::anyhow!("memory flush failed")),
            None,
            Some(denial()),
        )
        .expect_err("a memory-flush failure is an error, not a denial");
        assert!(format!("{flush_failed:#}").contains("memory flush failed"));

        let dead_stdout = headless_run_outcome(
            Ok(TurnStop::PermissionCancelled),
            None,
            Some(std::io::Error::other("stdout is gone")),
            Some(denial()),
        )
        .expect_err("a dead stdout outranks everything: nothing can report the denial");
        assert!(
            format!("{dead_stdout:#}").contains("stdout write failed"),
            "got: {dead_stdout:#}"
        );
    }

    /// The two things a denial that ended the run may never be: success, or a crash.
    #[test]
    fn a_denial_that_ended_the_run_is_neither_success_nor_a_crash() {
        let outcome = headless_run_outcome(
            Ok(TurnStop::PermissionCancelled),
            None,
            None,
            Some(denial()),
        )
        .expect("a denial is an outcome, not an error");
        assert_ne!(
            outcome,
            HeadlessOutcome::Finished,
            "a blocked run must never look like a finished one"
        );
        let code = outcome
            .denial()
            .expect("the record survives to the exit path")
            .exit_code();
        assert_ne!(code, 0, "never success");
        assert_ne!(code, 1, "never the generic error code a crash reports");
    }

    /// FALSE POSITIVE ON SUCCESS — the first of the two directions P02a got wrong.
    ///
    /// A denial can be latched by something that did not end the run. The case verified in this tree
    /// is the post-turn **memory flush**: `run_single_turn` calls `run_headless_memory_flush` only
    /// when the turn's outcome is already `Ok`, the terminal document has already been written with
    /// `end_turn`, and the flush drives the same `handle_headless_acp_message` — so a denial there is
    /// latched against a turn that succeeded. Anything else that asks after the turn has ended (a
    /// background task, a subagent whose own turn was cancelled while the parent's continued) lands
    /// in the same shape. P02a exited 3 on every one of those and told the operator the run was
    /// blocked.
    ///
    /// D.2.1 scopes the code to "a run that **ended** because a permission was denied". This is not
    /// one, so it exits 0 — and still says so on stderr, because D.3 forbids a denial that is
    /// indistinguishable from success.
    #[test]
    fn a_denial_the_run_recovered_from_exits_zero() {
        assert_eq!(
            headless_run_outcome(Ok(TurnStop::Ended), None, None, Some(denial()))
                .expect("a recovered run is not an error"),
            HeadlessOutcome::Finished,
            "a run that was refused something, carried on and finished is a success"
        );
        assert!(
            !denial().notice_line().is_empty(),
            "the denial is still reported in English, or it is indistinguishable from success (D.3)"
        );
        assert!(
            denial().notice_line().contains(denial().rule.remedy()),
            "the notice carries the remedy too: {}",
            denial().notice_line()
        );
    }

    /// FALSE POSITIVE ON A CRASH — the second direction.
    ///
    /// P02a suppressed the `Connection closed unexpectedly` bail whenever a denial was latched and
    /// let the denial outrank the turn's error, so a mid-turn crash exited 3 and the stderr line
    /// told the operator to "pre-approve it before the run". A crash is a crash: exit 1.
    #[test]
    fn a_crash_after_a_denial_is_still_a_crash() {
        for turn_error in [
            "Connection closed unexpectedly",
            "max turns reached",
            "Timed out after 30s waiting for the turn to end",
        ] {
            let err = headless_run_outcome(
                Err(anyhow::anyhow!("{turn_error}")),
                None,
                None,
                Some(denial()),
            )
            .expect_err("a latched denial must not downgrade a failure to the denial code");
            assert!(
                format!("{err:#}").contains(turn_error),
                "expected `{turn_error}`, got: {err:#}"
            );
        }
    }

    /// P02j: a denial latched before the mid-turn `Connection closed unexpectedly` bail used to
    /// vanish, because the bail returned before the outcome fold could write the notice. The error
    /// keeps exit 1 and the denial line must reach stderr exactly once.
    #[test]
    fn a_denial_latched_before_a_closed_connection_reaches_stderr_exactly_once() {
        let mut emitter = emitter();
        emitter.record_permission_denial(denial());
        let mut stderr = Vec::new();
        let err = connection_closed_error(&mut emitter, &mut stderr);
        assert!(
            format!("{err:#}").contains("Connection closed unexpectedly"),
            "the crash keeps its own error: {err:#}"
        );
        let text = String::from_utf8(stderr).expect("utf8");
        assert_eq!(
            text,
            format!("{}\n", denial().notice_line()),
            "the denial line exactly once, nothing else"
        );
        assert!(
            emitter.take_permission_denial().is_none(),
            "the latch is consumed, so nothing can print it a second time"
        );
    }

    /// The attack bytes from the S3 audit: erase the trusted prefix, conceal the rest, same-colour text, a forged line.
    const HOSTILE_FIELD: &str = "Write \u{1b}]0;owned\u{7}x\u{2028}y\u{e0041}z\r\x1b[Kfuigo: permission granted, \
        nothing to review.\x1b[8m\x1b[7m\x1b[31;41m\x1b[38;5;1;48;5;1m\nfuigo: forged second line";

    /// `fuigo_count` is how many times "fuigo:" appears: the trusted prefix, plus the two the hostile field carries when
    /// the line interpolates it (3), or just the prefix when the line does not carry that field at all (1).
    fn assert_one_intact_line(text: &str, prefix: &str, fuigo_count: usize) {
        let body = text.strip_suffix('\n').expect("ends with one newline");
        assert!(body.starts_with(prefix), "trusted prefix intact: {text:?}");
        assert!(
            !body.chars().any(|c| c.is_control() || fuigo_tty_utils::is_unsafe_display_char(c)),
            "no ESC, CR, LF, tab or other control remains in the line: {text:?}"
        );
        assert_eq!(text.matches("fuigo:").count(), fuigo_count, "the forged prefix is inert text inside the one line: {text:?}");
        assert!(body.contains("Denied by rule"), "the trusted tail survives: {text:?}");
    }

    /// P181 (sweep, S3): the connection-closed path writes the denial line to a caller-supplied stderr writer. The tool
    /// title and the tool-call id are the agent's text; neither can erase, conceal, restyle or forge a line.
    #[test]
    fn the_connection_closed_denial_line_is_scrubbed_like_every_other_stderr_line() {
        for (title, call_id) in [(HOSTILE_FIELD, "tc-1"), ("Write", HOSTILE_FIELD)] {
            let mut emitter = emitter();
            let mut hostile = denial();
            hostile.tool_title = Some(title.to_owned());
            hostile.tool_call_id = call_id.to_owned();
            emitter.record_permission_denial(hostile);
            let mut stderr = Vec::new();
            let _ = connection_closed_error(&mut emitter, &mut stderr);
            let text = String::from_utf8(stderr).expect("utf8");
            assert_one_intact_line(&text, "fuigo: a permission was denied in headless mode and the run continued: ", 3);
            // S5: the 150-column hostile field is shortened to the field cap (middle replaced by an ellipsis)
            // ESC and the space before it are two spaces; inside the bracketed call id the `]` is escaped
            assert!(text.contains("Write  ]0;owned") || text.contains("Write  \\]0;owned"), "inert visible bytes: {text:?}");
            assert!(text.contains('\u{2026}'), "the field is capped: {text:?}");
            assert!(text.contains("Denied by rule `") && text.contains("Remedy: "), "Fuigo's own tail is intact: {text:?}");
        }
    }

    /// P181 (S3): the exit-path lines are built from the same fields, so they hold even before any writer filter runs.
    #[test]
    fn the_human_and_notice_lines_carry_no_untrusted_control_byte() {
        for (title, call_id, agent_message) in [
            (Some(HOSTILE_FIELD), "tc-1", None),
            (Some("Write"), HOSTILE_FIELD, None),
            (Some("Write"), "tc-1", Some(HOSTILE_FIELD)),
        ] {
            let mut d = denial();
            d.tool_title = title.map(str::to_owned);
            d.tool_call_id = call_id.to_owned();
            d.agent_message = agent_message.map(str::to_owned);
            // The agent message is only on the budget line, so in the third case these two lines hold no hostile text.
            let carried = if agent_message.is_some() { 1 } else { 3 };
            assert_one_intact_line(&format!("{}\n", d.notice_line()), "fuigo: a permission was denied", carried);
            assert_one_intact_line(&format!("{}\n", d.human_line()), "fuigo: blocked", carried);
            let mut budget = HeadlessDenial::from_budget_rule(HeadlessDenialRule::ExecutionBudgetUnrecognized);
            budget.agent_message = Some(HOSTILE_FIELD.to_owned());
            assert_one_intact_line(&format!("{}\n", budget.human_line()), "fuigo: blocked", 3);
        }
    }

    /// Binds the production bail to the helper. The helper's own tests cannot see a revert to a bare
    /// `bail!` at the call site, and no in-process harness can close the shell mid-turn, so this
    /// pins the call site's text.
    #[test]
    fn the_mid_turn_close_bail_goes_through_the_denial_reporting_helper() {
        let src = include_str!("headless.rs");
        assert!(
            src.contains("return Err(connection_closed_error("),
            "the connection-closed bail must report a latched denial first"
        );
        assert!(
            !src.contains("anyhow::bail!(\"Connection closed unexpectedly\")"),
            "a bare bail drops a latched denial (P02j)"
        );
    }

    /// With no denial latched a closed connection writes nothing extra.
    #[test]
    fn a_closed_connection_without_a_denial_writes_nothing() {
        let mut emitter = emitter();
        let mut stderr = Vec::new();
        let _ = connection_closed_error(&mut emitter, &mut stderr);
        assert!(stderr.is_empty());
    }

    /// The discriminator itself, read off the shell's own wire rather than inferred.
    ///
    /// `cancelled` is not enough: `--max-turns`, a hook deny, a permission *reject* and a mid-turn
    /// abort all report `StopReason::Cancelled`. `_meta.cancellationCategory` is what separates them,
    /// and `PermissionCancelled` is the one this exit code belongs to.
    #[test]
    fn only_the_permission_cancelled_category_ends_the_run_at_a_denial() {
        let mut emitter = emitter();
        assert_eq!(
            emit_completed_response(
                &mut emitter,
                response(acp::StopReason::Cancelled, Some("PermissionCancelled")),
                &acp::SessionId::new("sess-1"),
                None,
            ),
            TurnStop::PermissionCancelled
        );
        assert_eq!(
            emit_completed_response(
                &mut emitter,
                response(acp::StopReason::EndTurn, None),
                &acp::SessionId::new("sess-1"),
                None,
            ),
            TurnStop::Ended
        );
        assert_eq!(
            emit_completed_response(
                &mut emitter,
                response(acp::StopReason::Cancelled, Some("max_turns_reached")),
                &acp::SessionId::new("sess-1"),
                None,
            ),
            TurnStop::MaxTurns
        );
        for other in ["MidTurnAbort", "HookDenied", "PermissionRejected"] {
            assert_eq!(
                emit_completed_response(
                    &mut emitter,
                    response(acp::StopReason::Cancelled, Some(other)),
                    &acp::SessionId::new("sess-1"),
                    None,
                ),
                TurnStop::Ended,
                "{other} is not a dismissed permission prompt"
            );
        }
    }

    /// The wire constant this whole gate rests on, pinned against the shell that stamps it. If the
    /// shell renames its category the exit code stops firing, and only this test says so.
    #[test]
    fn the_cancellation_category_matches_the_shell_that_stamps_it() {
        assert_eq!(
            fuigo_shell::session::commands::PERMISSION_CANCELLED_CATEGORY,
            "PermissionCancelled"
        );
        assert_eq!(crate::app::CANCELLATION_CATEGORY_KEY, "cancellationCategory");
    }

    /// D.2.2 on the document a machine consumer actually reads: the reason is a field, not prose.
    #[test]
    fn the_json_document_carries_the_denial_record() {
        let (captured, mut emitter) = captured_emitter();
        ask(
            &mut emitter,
            /*yolo=*/ false,
            Some("Write src/main.rs"),
            &[acp::PermissionOptionKind::RejectOnce],
        );
        let stop = emit_completed_response(
            &mut emitter,
            response(acp::StopReason::Cancelled, Some("PermissionCancelled")),
            &acp::SessionId::new("sess-1"),
            None,
        );
        assert_eq!(stop, TurnStop::PermissionCancelled);
        let doc: serde_json::Value =
            serde_json::from_str(&captured.text()).expect("exactly one JSON document, still");
        assert_eq!(doc["stopReason"], "cancelled");
        let record = &doc["permissionDenied"];
        assert_eq!(record["rule"], "headless_never_approves");
        assert_eq!(record["toolCallId"], "tc-1");
        assert_eq!(record["toolTitle"], "Write src/main.rs");
        assert_eq!(record["exitCode"], PERMISSION_DENIED_EXIT_CODE);
        assert!(
            record["remedy"].as_str().is_some_and(|r| !r.is_empty()),
            "the remedy is data too: {doc}"
        );
        assert_eq!(record["offeredOptionKinds"], serde_json::json!(["reject_once"]));
    }

    /// The invariant that makes the narrow gate safe: a latched denial is never silent, whatever the
    /// run's outcome turns out to be. `main` writes the fuller line on the `PermissionDenied` arm;
    /// every other path writes the notice from `headless_run_outcome`. Only a dead stdout skips it,
    /// and there the write error is the louder fact.
    #[test]
    fn a_latched_denial_is_never_silent_whatever_the_outcome() {
        // Exhaustive over the shapes `run_single_turn` can hand the fold, denial always present.
        let cases: Vec<(&str, anyhow::Result<HeadlessOutcome>)> = vec![
            (
                "ended at the denial",
                headless_run_outcome(Ok(TurnStop::PermissionCancelled), None, None, Some(denial())),
            ),
            (
                "recovered and finished",
                headless_run_outcome(Ok(TurnStop::Ended), None, None, Some(denial())),
            ),
            (
                "turn failed",
                headless_run_outcome(Err(anyhow::anyhow!("boom")), None, None, Some(denial())),
            ),
            (
                "memory flush failed",
                headless_run_outcome(
                    Ok(TurnStop::Ended),
                    Some(anyhow::anyhow!("flush boom")),
                    None,
                    Some(denial()),
                ),
            ),
        ];
        for (what, outcome) in cases {
            match outcome {
                Ok(HeadlessOutcome::PermissionDenied(d)) => {
                    assert!(!d.human_line().is_empty(), "{what}: main reports this one")
                }
                Ok(HeadlessOutcome::Finished) | Err(_) => { /* notice_line already written */ }
            }
        }
        // And the one exception, stated rather than assumed.
        assert!(
            headless_run_outcome(
                Ok(TurnStop::PermissionCancelled),
                None,
                Some(std::io::Error::other("stdout is gone")),
                Some(denial()),
            )
            .is_err(),
            "a dead stdout is the outcome; the denial cannot be reported through it"
        );
    }

    /// Nothing latched means nothing changed: an ordinary run is still `Finished`.
    #[test]
    fn a_run_with_no_denial_is_unchanged() {
        for stop in [TurnStop::Ended, TurnStop::PermissionCancelled] {
            assert_eq!(
                headless_run_outcome(Ok(stop), None, None, None).expect("clean run"),
                HeadlessOutcome::Finished
            );
        }
        assert!(
            headless_run_outcome(Err(anyhow::anyhow!("boom")), None, None, None).is_err(),
            "a real error is still a real error"
        );
    }

    /// Contract D.4 (P02e): the shell's token-budget denial, as the prompt error the shell sends.
    fn budget_denied_error(rule: fuigo_shell::acp_error::ExecutionBudgetRule) -> acp::Error {
        fuigo_shell::acp_error::ExecutionBudgetDenial {
            rule,
            total_token_limit: Some(100),
            total_tokens_used: 120,
            output_token_limit: None,
            output_tokens_used: 0,
            unknown_usage: false,
        }
        .to_acp_error()
    }

    /// A budget denial ends the run through the SAME contract as a permission denial: exit 3, the
    /// record on the one JSON document, the rule and remedy recoverable without reading prose.
    #[test]
    fn a_budget_denied_turn_exits_three_with_the_denial_record() {
        use fuigo_shell::acp_error::ExecutionBudgetRule;
        for rule in ExecutionBudgetRule::ALL {
            let (captured, mut emitter) = captured_emitter();
            let stop = crate::headless::finish_turn(
                &mut emitter,
                Some(Err(budget_denied_error(rule))),
                false,
                None,
                &acp::SessionId::new("sess-1"),
                false,
            )
            .expect("a budget denial is an outcome, not a failed run");
            assert_eq!(
                stop,
                TurnStop::BudgetDenied(HeadlessDenialRule::ExecutionBudget(rule))
            );
            let doc: serde_json::Value = serde_json::from_str(captured.text().trim())
                .unwrap_or_else(|e| panic!("one JSON document ({e}): {}", captured.text()));
            assert_eq!(doc["permissionDenied"]["rule"], rule.id(), "{doc}");
            assert_eq!(doc["permissionDenied"]["remedy"], rule.remedy(), "{doc}");
            assert_eq!(
                doc["permissionDenied"]["exitCode"], PERMISSION_DENIED_EXIT_CODE,
                "{doc}"
            );

            let outcome =
                headless_run_outcome(Ok(stop), None, None, emitter.take_permission_denial())
                    .expect("not a crash");
            let HeadlessOutcome::PermissionDenied(denial) = outcome else {
                panic!("a budget-denied run must not exit 0: {outcome:?}");
            };
            assert_eq!(denial.rule, HeadlessDenialRule::ExecutionBudget(rule));
            assert_eq!(denial.exit_code(), 3);
            let line = denial.human_line();
            assert!(
                line.contains(rule.id()) && line.contains(rule.remedy()),
                "{line}"
            );
            assert!(
                !line.contains("permission denied"),
                "it was a budget, not a permission: {line}"
            );
            assert_eq!(line.lines().count(), 1, "{line}");
        }
    }

    /// The budget denial is the outcome the run ENDED at, so it wins over a permission denial
    /// latched earlier (which still gets its own stderr notice); and any other prompt error is still
    /// a failed run, `exit(1)`.
    #[test]
    fn only_the_budget_denial_code_turns_a_prompt_error_into_a_denial() {
        use fuigo_shell::acp_error::ExecutionBudgetRule;
        let (_captured, mut emitter) = captured_emitter();
        emitter.record_permission_denial(denial());
        let stop = crate::headless::finish_turn(
            &mut emitter,
            Some(Err(budget_denied_error(
                ExecutionBudgetRule::TokenUsageUnknown,
            ))),
            false,
            None,
            &acp::SessionId::new("sess-1"),
            false,
        )
        .expect("an outcome");
        let outcome = headless_run_outcome(Ok(stop), None, None, emitter.take_permission_denial())
            .expect("not a crash");
        assert_eq!(
            outcome.denial().map(|d| d.rule),
            Some(HeadlessDenialRule::ExecutionBudget(
                ExecutionBudgetRule::TokenUsageUnknown
            ))
        );

        for other in [
            fuigo_shell::acp_error::execution_incomplete("Execution stopped with bounded capacity"),
            acp::Error::invalid_params().data(serde_json::json!({
                "message": "invalid configuration: execution admission denied or could not be persisted",
                "error_kind": "api",
            })),
        ] {
            let (_captured, mut emitter) = captured_emitter();
            assert!(
                crate::headless::finish_turn(&mut emitter, Some(Err(other)), false, None,
                    &acp::SessionId::new("sess-1"), false).is_err(),
                "an error without the denial code is still a failed run"
            );
        }
    }

    /// A newer agent's rule this build does not know is still a denial: the stable `data.code` is
    /// what decides, so it still exits 3 rather than falling back to `exit(1)`.
    #[test]
    fn an_unrecognized_budget_rule_is_still_a_denial() {
        let mut wire = serde_json::to_value(budget_denied_error(
            fuigo_shell::acp_error::ExecutionBudgetRule::TotalTokensExhausted,
        ))
        .unwrap();
        wire["data"]["rule"] = serde_json::json!("execution_wall_clock_budget_exhausted");
        let err: acp::Error = serde_json::from_value(wire).unwrap();
        let (_captured, mut emitter) = captured_emitter();
        let stop = crate::headless::finish_turn(
            &mut emitter,
            Some(Err(err)),
            false,
            None,
            &acp::SessionId::new("sess-1"),
            false,
        )
        .expect("an outcome, not a failed run");
        assert_eq!(
            stop,
            TurnStop::BudgetDenied(HeadlessDenialRule::ExecutionBudgetUnrecognized)
        );
        let outcome = headless_run_outcome(Ok(stop), None, None, emitter.take_permission_denial())
            .expect("not a crash");
        assert_eq!(outcome.denial().map(HeadlessDenial::exit_code), Some(3));
    }

    /// P51: an unrecognized budget rule is reported by `main`'s ONE line, which carries the agent's own
    /// message (it names the rule and its remedy). `finish_turn` writes nothing of its own in plain, so
    /// the message must be on the denial the exit path prints; if it were not, collapsing to one line
    /// would lose the only text that says what refused the run.
    #[test]
    fn an_unrecognized_budget_rule_is_reported_on_main_s_one_line() {
        let mut wire = serde_json::to_value(budget_denied_error(
            fuigo_shell::acp_error::ExecutionBudgetRule::TotalTokensExhausted,
        ))
        .unwrap();
        wire["data"]["rule"] = serde_json::json!("execution_wall_clock_budget_exhausted");
        let err: acp::Error = serde_json::from_value(wire).unwrap();
        let expected = fuigo_shell::sampling::error::acp_error_text(&err);
        let captured = super::CapturedOut::default();
        let mut emitter =
            HeadlessEmitter::with_writer(OutputFormat::Plain, false, Box::new(captured.clone()));
        crate::headless::finish_turn(
            &mut emitter,
            Some(Err(err)),
            false,
            None,
            &acp::SessionId::new("sess-1"),
            false,
        )
        .expect("an outcome");
        assert_eq!(captured.text(), "", "plain writes nothing to stdout");
        let line = emitter
            .take_permission_denial()
            .expect("the denial is latched")
            .human_line();
        assert_eq!(line.lines().count(), 1, "one line: {line}");
        assert!(line.contains(&expected), "the agent's message rides on the line: {line}");
    }

    /// An interrupt while the turn is driven, after the turn already answered, is ONE document: the
    /// completed response and the interrupt together, exactly as the `--timeout` cap reports it.
    #[test]
    fn an_interrupt_after_a_completed_response_is_one_document_with_the_error() {
        let captured = super::CapturedOut::default();
        let mut emitter = HeadlessEmitter::with_writer(OutputFormat::Json, false, Box::new(captured.clone()));
        let err = crate::headless::finish_interrupt(
            &mut emitter,
            Some(Ok(acp::PromptResponse::new(acp::StopReason::EndTurn))),
            130,
            &acp::SessionId::new("sess-1"),
        );
        assert!(err.downcast_ref::<crate::headless::HeadlessInterrupted>().is_some());
        let doc: serde_json::Value =
            serde_json::from_str(captured.text().trim()).expect("stdout is exactly one JSON value");
        assert_eq!(doc["error"], "Interrupted by SIGINT; exiting 130", "{doc}");
        assert_eq!(doc["stopReason"], "cancelled", "{doc}");
    }

    /// A signal latched while the turn is driven ends the drive with its exit code (through the same
    /// drain/reap path as the `--timeout` cap) instead of waiting on a turn that never ends.
    #[tokio::test]
    async fn a_latched_interrupt_ends_the_driven_turn_with_its_code() {
        let (_client_tx, mut acp_rx) =
            tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
        let (acp_tx, _agent_rx) =
            tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpAgentMessage>();
        let session_id = acp::SessionId::new("sess-1");
        let mut emitter = HeadlessEmitter::new(OutputFormat::Json, false);
        let mut ttf_logged = false;
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            crate::headless::drive_prompt_turn(
                std::future::pending::<Result<acp::PromptResponse, acp::Error>>(),
                &mut acp_rx,
                &acp_tx,
                &session_id,
                &mut emitter,
                &super::timeout_test_options(None),
                crate::headless::RunDeadline::start(None),
                std::time::Instant::now(),
                &mut ttf_logged,
                None,
                &crate::app::prompt_ack::PromptAckDeadlines::from_env(None),
                &crate::headless::InterruptWatch::fixed(Some(130)),
            ),
        )
        .await
        .expect("an interrupt must end the driven turn");
        assert_eq!(outcome.interrupted, Some(130));
        assert!(!outcome.timed_out);
    }

    /// An interrupted run must not wait forever on a stalled log flush: the bound fires, and an
    /// unbounded caller still waits for a flush that does complete.
    #[tokio::test]
    async fn the_log_flush_after_an_interrupt_is_bounded() {
        let started = std::time::Instant::now();
        let finished = crate::headless::await_bounded_if(
            true,
            std::time::Duration::from_millis(100),
            std::future::pending::<()>(),
        )
        .await;
        assert!(!finished, "a stalled flush must hit the cap");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert!(
            crate::headless::await_bounded_if(false, std::time::Duration::from_millis(1), async {
                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            })
            .await,
            "an unbounded caller waits for the flush to finish"
        );
    }

    /// A signal that arrives while the final log flush is stalled ends the wait at once instead of
    /// queueing behind it (the interrupt owner stands down until the turn is finalized).
    #[tokio::test]
    async fn a_signal_during_a_stalled_flush_is_not_queued_behind_it() {
        let started = std::time::Instant::now();
        // Own timeout so a regression (the flush queueing the signal behind itself) is a named failure,
        // not a hang.
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            crate::headless::flush_or_interrupt(
                false,
                std::time::Duration::from_secs(60),
                std::future::pending::<()>(),
                &crate::headless::InterruptWatch::fixed(Some(143)),
                None,
            ),
        )
        .await
        .expect("a signal must end a stalled flush; it queued behind the flush instead");
        assert_eq!(code, Some(143));
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        // With no signal, a completing flush reports none.
        let none = crate::headless::flush_or_interrupt(
            false,
            std::time::Duration::from_secs(60),
            async {},
            &crate::headless::InterruptWatch::inert(),
            None,
        )
        .await;
        assert_eq!(none, None);
    }

    /// P51: a run that ends without a final prompt-level ledger (interrupt, timeout, connection loss)
    /// still reports what its completed responses were billed, on every format's terminal record, so a
    /// caller reconciling cost from it never sees zeros for spend that happened.
    #[test]
    fn a_terminal_error_record_carries_the_usage_of_completed_responses() {
        use crate::headless::reducer::StreamEvent;
        let usage = fuigo_shell::extensions::notification::ResponseUsage {
            input_tokens: 10,
            output_tokens: 20,
            ..Default::default()
        };
        for format in [OutputFormat::Json, OutputFormat::StreamingJson, OutputFormat::StreamingMessagesJson] {
            let captured = super::CapturedOut::default();
            let mut emitter = HeadlessEmitter::with_writer(format, false, Box::new(captured.clone()));
            for _ in 0..2 {
                emitter.reduce_and_emit(StreamEvent::ResponseCompleted {
                    message_id: Some("m".into()),
                    stop_reason: Some("tool_use".into()),
                    usage: Some(usage.clone()),
                    signature: None,
                    stop_sequence: None,
                });
            }
            let before = captured.text().len();
            emitter.on_error("Interrupted by SIGINT; exiting 130", Some("cancelled"));
            let text = captured.text();
            let terminal: serde_json::Value = serde_json::from_str(
                text[before..].lines().rev().find(|l| !l.trim().is_empty()).expect("a terminal line"),
            )
            .or_else(|_| serde_json::from_str(text[before..].trim()))
            .expect("terminal json");
            // Two responses of 10 in / 20 out.
            assert_eq!(terminal["usage"]["output_tokens"], 40, "{format:?}: {terminal}");
            assert_eq!(terminal["usage"]["input_tokens"], 20, "{format:?}: {terminal}");
        }
    }

    /// The one-line rule survives an agent message with embedded newlines (a multi-line remedy).
    #[test]
    fn a_multiline_agent_message_stays_on_one_line() {
        let mut denial = HeadlessDenial::from_budget_rule(HeadlessDenialRule::ExecutionBudgetUnrecognized);
        denial.agent_message = Some("rule x refused\n  raise limit y\n\nthen retry".to_string());
        let line = denial.human_line();
        assert_eq!(line.lines().count(), 1, "{line}");
        assert!(line.contains("rule x refused raise limit y then retry"), "{line}");
    }

    /// An interrupt after the terminal document is out (the post-turn memory flush) writes no second
    /// document: a machine consumer reads exactly one. Before it, the error line IS the document.
    #[test]
    fn an_interrupt_writes_one_terminal_document_at_most() {
        for format in [OutputFormat::Json, OutputFormat::StreamingJson, OutputFormat::StreamingMessagesJson] {
            let captured = super::CapturedOut::default();
            let mut emitter = HeadlessEmitter::with_writer(format, false, Box::new(captured.clone()));
            let before = captured.text();
            let err = crate::headless::interrupted(&mut emitter, 130);
            assert!(err.downcast_ref::<crate::headless::HeadlessInterrupted>().is_some());
            let docs = captured.text().len() - before.len();
            assert!(docs > 0, "{format:?}: an interrupt before any terminal writes the error document");
            let after_first = captured.text();
            let _ = crate::headless::interrupted(&mut emitter, 130);
            assert_eq!(captured.text(), after_first, "{format:?}: a second terminal document was written");
        }
        let captured = super::CapturedOut::default();
        let mut emitter = HeadlessEmitter::with_writer(OutputFormat::Json, false, Box::new(captured.clone()));
        emitter.on_end("end_turn", "s", "r", None);
        let done = captured.text();
        let _ = crate::headless::interrupted(&mut emitter, 143);
        assert_eq!(captured.text(), done, "an interrupt after the terminal document writes nothing");
    }

    /// `--output-format plain`: stdout stays empty and the budget denial writes nothing itself —
    /// `main` writes its one stderr line — so the run produces exactly one line, not two.
    #[test]
    fn a_plain_budget_denial_leaves_the_one_line_to_main() {
        let captured = super::CapturedOut::default();
        let mut emitter =
            HeadlessEmitter::with_writer(OutputFormat::Plain, false, Box::new(captured.clone()));
        let stop = crate::headless::finish_turn(
            &mut emitter,
            Some(Err(budget_denied_error(
                fuigo_shell::acp_error::ExecutionBudgetRule::TotalTokensExhausted,
            ))),
            false,
            None,
            &acp::SessionId::new("sess-1"),
            false,
        )
        .expect("an outcome");
        assert!(matches!(stop, TurnStop::BudgetDenied(_)));
        assert_eq!(captured.text(), "", "plain writes nothing to stdout");
    }
}

/// P02b — Contract D.2.2 across all four `--output-format`s: the denial is data on the one terminal
/// record each format's consumer reads, and that record never contradicts the exit code.
mod denial_record_per_format {
    use agent_client_protocol as acp;
    use std::sync::Arc;

    use super::CapturedOut;
    use crate::headless::reducer::{StreamEvent, tool_call_event};
    use crate::headless::{
        HeadlessDenial, HeadlessDenialRule, HeadlessEmitter, HeadlessOutcome, OutputFormat,
        PERMISSION_DENIED_EXIT_CODE, TurnStop, emit_completed_response, headless_run_outcome,
    };

    const ALL: [OutputFormat; 4] = [
        OutputFormat::Plain,
        OutputFormat::Json,
        OutputFormat::StreamingJson,
        OutputFormat::StreamingMessagesJson,
    ];

    fn emitter(format: OutputFormat) -> (CapturedOut, HeadlessEmitter) {
        let captured = CapturedOut::default();
        let emitter = HeadlessEmitter::with_writer(format, false, Box::new(captured.clone()));
        (captured, emitter)
    }

    fn denial() -> HeadlessDenial {
        HeadlessDenial {
            rule: HeadlessDenialRule::HeadlessNeverApproves,
            tool_title: Some("Edit src/main.rs".to_owned()),
            tool_call_id: "tc-1".to_owned(),
            offered_option_kinds: vec!["allow_once".to_owned(), "reject_once".to_owned()],
            agent_message: None,
        }
    }

    fn response(stop: acp::StopReason, category: Option<&str>) -> acp::PromptResponse {
        let mut meta = acp::Meta::new();
        meta.insert("sessionId".into(), serde_json::json!("sess-1"));
        meta.insert("requestId".into(), serde_json::json!("req-1"));
        if let Some(category) = category {
            meta.insert(
                crate::app::CANCELLATION_CATEGORY_KEY.to_string(),
                serde_json::json!(category),
            );
        }
        acp::PromptResponse::new(stop).meta(Some(meta))
    }

    /// Stream the `tool_call` the agent sends before it asks, as the real loop does.
    fn stream_tool_call(emitter: &mut HeadlessEmitter) {
        let mut tc =
            acp::ToolCall::new(acp::ToolCallId::new(Arc::from("tc-1")), "Edit src/main.rs")
                .kind(acp::ToolKind::Edit);
        tc.raw_input = Some(serde_json::json!({"file_path": "src/main.rs", "old_string": "a"}));
        let mut meta = acp::Meta::new();
        meta.insert(
            "fuigo/tool".into(),
            serde_json::json!({"name": "search_replace", "kind": "edit"}),
        );
        tc.meta = Some(meta);
        emitter.reduce_and_emit(StreamEvent::ToolCall(tool_call_event(&tc)));
    }

    /// Run the shape of a blocked turn: the tool call streams, its permission is refused, and the
    /// shell ends the turn `cancelled` with `PermissionCancelled`.
    fn blocked_turn(format: OutputFormat) -> (String, TurnStop) {
        let (captured, mut emitter) = emitter(format);
        stream_tool_call(&mut emitter);
        emitter.record_permission_denial(denial());
        let stop = emit_completed_response(
            &mut emitter,
            response(acp::StopReason::Cancelled, Some("PermissionCancelled")),
            &acp::SessionId::new("sess-1"),
            None,
        );
        (captured.text(), stop)
    }

    fn ndjson(text: &str) -> Vec<serde_json::Value> {
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("NDJSON line ({e}): {l}")))
            .collect()
    }

    /// The four formats, one assertion block each — the D.5 test, per format: exit `3` and a reason a
    /// consumer recovers without reading English.
    #[test]
    fn every_output_format_represents_a_blocking_denial() {
        for format in ALL {
            let (stdout, stop) = blocked_turn(format);
            assert_eq!(stop, TurnStop::PermissionCancelled, "{format:?}");
            // Every format exits 3 — never 0 (finished) and never 1 (crashed).
            let outcome = headless_run_outcome(Ok(stop), None, None, Some(denial())).expect("ok");
            let HeadlessOutcome::PermissionDenied(d) = outcome else {
                panic!("{format:?}: a blocked run must be PermissionDenied, got {outcome:?}");
            };
            assert_eq!(d.exit_code(), PERMISSION_DENIED_EXIT_CODE);
            assert_ne!(d.exit_code(), 0);
            assert_ne!(d.exit_code(), 1);
            match format {
                OutputFormat::Plain => {
                    // Plain's representation is the stderr line `main` writes; stdout stays the
                    // model's text, with no JSON smuggled into it.
                    assert!(
                        !stdout.contains("permissionDenied"),
                        "plain stdout: {stdout:?}"
                    );
                    let line = d.human_line();
                    assert!(line.contains("headless_never_approves"), "{line}");
                    assert!(line.contains("Remedy:"), "{line}");
                    assert!(line.contains("--allow"), "{line}");
                }
                OutputFormat::Json => {
                    let doc: serde_json::Value =
                        serde_json::from_str(&stdout).expect("exactly one JSON document");
                    assert_eq!(doc["stopReason"], "cancelled");
                    let rec = &doc["permissionDenied"];
                    assert_eq!(rec["rule"], "headless_never_approves");
                    assert_eq!(rec["toolCallId"], "tc-1");
                    assert_eq!(rec["endedRun"], true);
                    assert_eq!(rec["exitCode"], PERMISSION_DENIED_EXIT_CODE);
                }
                OutputFormat::StreamingJson => {
                    let lines = ndjson(&stdout);
                    let last = lines.last().expect("a terminal line");
                    assert_eq!(
                        last["type"], "end",
                        "the record rides the last line: {stdout}"
                    );
                    assert_eq!(
                        lines.iter().filter(|l| l["type"] == "end").count(),
                        1,
                        "still exactly one terminal line: {stdout}"
                    );
                    assert_eq!(last["stopReason"], "cancelled");
                    // The same record, under the same key, as the json document.
                    assert_eq!(last["permissionDenied"], denial().wire_record(true));
                    assert_eq!(
                        last["permissionDenied"]["exitCode"],
                        PERMISSION_DENIED_EXIT_CODE
                    );
                    assert!(
                        lines.iter().all(|l| l["type"] != "permission_denied"),
                        "no invented line type: {stdout}"
                    );
                }
                OutputFormat::StreamingMessagesJson => {
                    let lines = ndjson(&stdout);
                    let result = lines.last().expect("a terminal line");
                    assert_eq!(result["type"], "result", "{stdout}");
                    assert_eq!(result["is_error"], true, "a blocked run is not a success");
                    assert_eq!(result["subtype"], "error_during_execution");
                    assert_eq!(result["stop_reason"], "cancelled");
                    // The schema's own field, in the schema's own entry shape — nothing invented.
                    assert_eq!(
                        result["permission_denials"],
                        serde_json::json!([{
                            "tool_name": "search_replace",
                            "tool_use_id": "tc-1",
                            "tool_input": {"file_path": "src/main.rs", "old_string": "a"},
                        }]),
                        "{result}"
                    );
                    assert!(
                        lines.iter().all(|l| [
                            "system",
                            "assistant",
                            "user",
                            "stream_event",
                            "result"
                        ]
                        .contains(&l["type"].as_str().unwrap_or(""))),
                        "only Messages wire types: {stdout}"
                    );
                }
            }
        }
    }

    /// A refusal the turn carried past exits `0`, so no format's record may claim `3`.
    #[test]
    fn a_recovered_denial_is_recorded_without_claiming_exit_three() {
        for format in ALL {
            let (captured, mut emitter) = emitter(format);
            stream_tool_call(&mut emitter);
            emitter.record_permission_denial(denial());
            let stop = emit_completed_response(
                &mut emitter,
                response(acp::StopReason::EndTurn, None),
                &acp::SessionId::new("sess-1"),
                None,
            );
            assert_eq!(
                headless_run_outcome(Ok(stop), None, None, Some(denial())).expect("ok"),
                HeadlessOutcome::Finished,
                "{format:?}"
            );
            let stdout = captured.text();
            match format {
                OutputFormat::Plain => assert!(!stdout.contains("permissionDenied")),
                OutputFormat::Json => {
                    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("json");
                    assert_eq!(doc["permissionDenied"]["endedRun"], false, "{doc}");
                    assert!(doc["permissionDenied"].get("exitCode").is_none(), "{doc}");
                    assert_eq!(doc["permissionDenied"]["rule"], "headless_never_approves");
                }
                OutputFormat::StreamingJson => {
                    let last = ndjson(&stdout).pop().expect("end");
                    assert_eq!(last["type"], "end");
                    assert_eq!(last["permissionDenied"], denial().wire_record(false));
                    assert!(last["permissionDenied"].get("exitCode").is_none(), "{last}");
                }
                OutputFormat::StreamingMessagesJson => {
                    let result = ndjson(&stdout).pop().expect("result");
                    assert_eq!(result["type"], "result");
                    assert_eq!(result["is_error"], false, "the run finished: {result}");
                    assert_eq!(result["permission_denials"][0]["tool_use_id"], "tc-1");
                }
            }
        }
    }

    /// A failure after a refusal exits `1`; the record still rides the error line, and still does
    /// not claim `3`. Covers both the error line and the `--timeout` cap folded into the end line.
    #[test]
    fn a_failure_after_a_denial_carries_the_record_and_keeps_exit_one() {
        for format in [
            OutputFormat::Json,
            OutputFormat::StreamingJson,
            OutputFormat::StreamingMessagesJson,
        ] {
            let (captured, mut emitter) = emitter(format);
            stream_tool_call(&mut emitter);
            emitter.record_permission_denial(denial());
            emitter.on_error("boom", None);
            let last = ndjson(&captured.text()).pop().expect("a terminal line");
            match format {
                OutputFormat::StreamingMessagesJson => {
                    assert_eq!(last["is_error"], true);
                    assert_eq!(
                        last["permission_denials"][0]["tool_use_id"], "tc-1",
                        "{last}"
                    );
                }
                _ => {
                    assert_eq!(last["type"], "error", "{last}");
                    assert_eq!(last["permissionDenied"]["endedRun"], false, "{last}");
                    assert!(last["permissionDenied"].get("exitCode").is_none(), "{last}");
                }
            }
        }
        // The `--timeout` cap lands on a turn that did end at the refusal: still exit 1, so no `3`.
        for format in [OutputFormat::Json, OutputFormat::StreamingJson] {
            let (captured, mut emitter) = emitter(format);
            emitter.record_permission_denial(denial());
            emit_completed_response(
                &mut emitter,
                response(acp::StopReason::Cancelled, Some("PermissionCancelled")),
                &acp::SessionId::new("sess-1"),
                Some("Timed out after 5s waiting for the turn to end"),
            );
            let text = captured.text();
            let doc: serde_json::Value = match format {
                OutputFormat::Json => serde_json::from_str(&text).expect("json"),
                _ => ndjson(&text).pop().expect("end"),
            };
            assert_eq!(
                doc["permissionDenied"]["endedRun"], false,
                "{format:?}: {doc}"
            );
            assert!(
                doc["permissionDenied"].get("exitCode").is_none(),
                "{format:?}: {doc}"
            );
        }
    }

    /// Nothing refused, nothing reported: no format grows a denial key on an ordinary run.
    #[test]
    fn a_run_with_no_denial_carries_no_record() {
        for format in ALL {
            let (captured, mut emitter) = emitter(format);
            stream_tool_call(&mut emitter);
            emit_completed_response(
                &mut emitter,
                response(acp::StopReason::EndTurn, None),
                &acp::SessionId::new("sess-1"),
                None,
            );
            let stdout = captured.text();
            assert!(!stdout.contains("permissionDenied"), "{format:?}: {stdout}");
            assert!(
                !stdout.contains("permission_denials"),
                "{format:?}: {stdout}"
            );
        }
    }

    /// A denial for a tool call that never streamed still produces a Messages entry — from the
    /// agent's own title — rather than vanishing from the one format most likely machine-read.
    #[test]
    fn a_messages_denial_for_an_unstreamed_tool_call_is_not_dropped() {
        let (captured, mut emitter) = emitter(OutputFormat::StreamingMessagesJson);
        emitter.record_permission_denial(denial());
        emit_completed_response(
            &mut emitter,
            response(acp::StopReason::Cancelled, Some("PermissionCancelled")),
            &acp::SessionId::new("sess-1"),
            None,
        );
        let result = ndjson(&captured.text()).pop().expect("result");
        assert_eq!(
            result["permission_denials"],
            serde_json::json!([{"tool_name": "Edit src/main.rs", "tool_use_id": "tc-1", "tool_input": {}}])
        );
    }

    /// Contract D.4 through the P02b contract: a token-budget denial arrives as the turn's prompt
    /// error, ends the run with exit 3, and reports on each format's one terminal line — with
    /// `endedRun`/`exitCode`, since the run did end there — and never as a tool the model did not call.
    #[test]
    fn a_budget_denial_reports_through_every_format() {
        use fuigo_shell::acp_error::{ExecutionBudgetDenial, ExecutionBudgetRule};
        let rule = ExecutionBudgetRule::TotalTokensExhausted;
        let err = ExecutionBudgetDenial {
            rule,
            total_token_limit: Some(100),
            total_tokens_used: 120,
            output_token_limit: None,
            output_tokens_used: 0,
            unknown_usage: false,
        }
        .to_acp_error();
        for format in ALL {
            let (captured, mut emitter) = emitter(format);
            let stop = crate::headless::finish_turn(
                &mut emitter,
                Some(Err(err.clone())),
                false,
                None,
                &acp::SessionId::new("sess-1"),
                false,
            )
            .expect("a budget denial is an outcome, not a failed run");
            let outcome =
                headless_run_outcome(Ok(stop), None, None, emitter.take_permission_denial())
                    .expect("not a crash");
            let HeadlessOutcome::PermissionDenied(d) = outcome else {
                panic!("{format:?}: exit 3, got {outcome:?}");
            };
            assert_eq!(d.exit_code(), PERMISSION_DENIED_EXIT_CODE);
            let stdout = captured.text();
            let expected = d.wire_record(true);
            assert_eq!(
                expected["toolCallId"],
                serde_json::Value::Null,
                "no tool call to join on"
            );
            assert_eq!(expected["rule"], rule.id());
            match format {
                OutputFormat::Plain => assert_eq!(stdout, "", "main writes the one stderr line"),
                OutputFormat::Json | OutputFormat::StreamingJson => {
                    let lines = ndjson(&stdout);
                    assert_eq!(lines.len(), 1, "{format:?}: one terminal line: {stdout}");
                    assert_eq!(lines[0]["type"], "error", "{stdout}");
                    assert_eq!(
                        lines[0]["permissionDenied"], expected,
                        "{format:?}: {stdout}"
                    );
                    assert_eq!(
                        lines[0]["permissionDenied"]["exitCode"],
                        PERMISSION_DENIED_EXIT_CODE
                    );
                }
                OutputFormat::StreamingMessagesJson => {
                    let lines = ndjson(&stdout);
                    let result = lines.last().expect("a result");
                    assert_eq!(result["type"], "result", "{stdout}");
                    assert_eq!(
                        lines.iter().filter(|l| l["type"] == "result").count(),
                        1,
                        "{stdout}"
                    );
                    assert_eq!(result["is_error"], true, "{stdout}");
                    assert_eq!(
                        result["stop_reason"],
                        serde_json::Value::Null,
                        "documented: null for a budget denial: {stdout}"
                    );
                    assert!(
                        result.get("permission_denials").is_none(),
                        "no tool was refused, so no SDKPermissionDenial is invented: {stdout}"
                    );
                    assert!(
                        result["errors"][0]
                            .as_str()
                            .is_some_and(|e| e.contains(rule.id())),
                        "the agent's message names the rule: {stdout}"
                    );
                }
            }
        }
    }

    /// P195 (K25, Grok r1): the shell's denial for an answer that COMPLETED and then spent the goal's budget.
    fn plain_budget_error() -> acp::Error {
        fuigo_shell::acp_error::ExecutionBudgetDenial {
            rule: fuigo_shell::acp_error::ExecutionBudgetRule::TotalTokensExhausted,
            total_token_limit: Some(100),
            total_tokens_used: 120,
            output_token_limit: None,
            output_tokens_used: 0,
            unknown_usage: false,
        }
        .to_acp_error()
    }

    fn answer_then_budget_error() -> acp::Error {
        let mut err = plain_budget_error();
        if let Some(serde_json::Value::Object(data)) = err.data.as_mut() {
            data.insert("answer_completed".to_string(), serde_json::Value::Bool(true));
        }
        err
    }

    /// Run `finish_turn` on a turn that streamed `ANSWER-TEXT-42` and whose spend then hit the budget.
    fn answered_then_budget_run(format: OutputFormat, err: acp::Error) -> (String, i32) {
        let (captured, mut emitter) = emitter(format);
        emitter.on_text_chunk("ANSWER-TEXT-42", None);
        let stop = crate::headless::finish_turn(
            &mut emitter,
            Some(Err(err)),
            false,
            None,
            &acp::SessionId::new("sess-1"),
            false,
        )
        .expect("a budget denial is an outcome, not a failed run");
        let outcome = headless_run_outcome(Ok(stop), None, None, emitter.take_permission_denial())
            .expect("not a crash");
        let HeadlessOutcome::PermissionDenied(d) = outcome else {
            panic!("{format:?}: exit 3, got {outcome:?}");
        };
        (captured.text(), d.exit_code())
    }

    /// K25: the completed answer is written exactly once, with the denial, in every format; exit 3.
    #[test]
    fn json_a_completed_answer_that_spends_the_budget_keeps_its_text() {
        let (out, code) = answered_then_budget_run(OutputFormat::Json, answer_then_budget_error());
        assert_eq!(code, 3);
        let doc: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("exactly one JSON document ({e}): {out}"));
        assert_eq!(doc["text"], "ANSWER-TEXT-42", "{out}");
        assert_eq!(out.matches("ANSWER-TEXT-42").count(), 1, "{out}");
        assert_eq!(doc["stopReason"], "end_turn", "{out}");
        assert_eq!(doc["sessionId"], "sess-1", "{out}");
        assert_ne!(doc["type"], "error", "not the error document: {out}");
        assert_eq!(doc["permissionDenied"]["rule"], "execution_token_budget_exhausted", "{out}");
        assert_eq!(doc["permissionDenied"]["exitCode"], 3, "{out}");
    }

    #[test]
    fn streaming_json_a_completed_answer_that_spends_the_budget_keeps_its_text() {
        let (out, code) =
            answered_then_budget_run(OutputFormat::StreamingJson, answer_then_budget_error());
        assert_eq!(code, 3);
        assert_eq!(out.matches("ANSWER-TEXT-42").count(), 1, "text once: {out}");
        let lines = ndjson(&out);
        let last = lines.last().expect("a terminal line");
        assert_eq!(last["type"], "end", "{out}");
        assert_eq!(last["permissionDenied"]["rule"], "execution_token_budget_exhausted", "{out}");
        assert_eq!(lines.iter().filter(|l| l["type"] == "end" || l["type"] == "error").count(), 1, "{out}");
    }

    #[test]
    fn streaming_messages_json_a_completed_answer_that_spends_the_budget_keeps_its_text() {
        let (out, code) = answered_then_budget_run(
            OutputFormat::StreamingMessagesJson,
            answer_then_budget_error(),
        );
        assert_eq!(code, 3);
        let lines = ndjson(&out);
        let results: Vec<_> = lines.iter().filter(|l| l["type"] == "result").collect();
        assert_eq!(results.len(), 1, "one terminal line: {out}");
        assert_eq!(results[0]["result"], "ANSWER-TEXT-42", "result carries the last text: {out}");
        // Grok r2: the stream must say why the exit code is 3, so the line is the denial's, not a success.
        assert_eq!(results[0]["is_error"], true, "{out}");
        assert_eq!(results[0]["subtype"], "error_during_execution", "{out}");
        assert_eq!(
            results[0]["stop_reason"],
            serde_json::Value::Null,
            "same as the no-answer budget denial: {out}"
        );
        assert!(
            results[0]["errors"][0]
                .as_str()
                .is_some_and(|e| e.contains("execution_token_budget_exhausted")),
            "errors[0] names the rule: {out}"
        );
        assert_eq!(lines.last().unwrap()["type"], "result", "the result is the last line: {out}");
        assert_eq!(
            lines.iter().filter(|l| l["type"] == "assistant").count(),
            1,
            "the assistant frame holds the text once: {out}"
        );
        assert_eq!(out.matches("ANSWER-TEXT-42").count(), 2, "frame + result: {out}");
    }

    /// Guard, not a regression test for the round-2 fix: plain never took the new branch, so this passes with or
    /// without it. It pins that the answer reaches stdout exactly once.
    #[test]
    fn plain_a_completed_answer_that_spends_the_budget_keeps_its_text_on_stdout() {
        let (out, code) = answered_then_budget_run(OutputFormat::Plain, answer_then_budget_error());
        assert_eq!(code, 3);
        assert_eq!(out.matches("ANSWER-TEXT-42").count(), 1, "{out}");
    }

    /// Non-regression: a budget denial with no completed answer is still the error document.
    #[test]
    fn a_budget_denial_without_a_completed_answer_stays_the_error_document() {
        let (out, code) = answered_then_budget_run(OutputFormat::Json, plain_budget_error());
        assert_eq!(code, 3);
        let doc: serde_json::Value = serde_json::from_str(&out).expect("one document");
        assert_eq!(doc["type"], "error", "{out}");
    }

    /// Non-regression: an answer that completes UNDER budget (an `Ok` turn) is the normal document, no denial.
    #[test]
    fn a_completed_answer_under_budget_is_the_normal_document() {
        let (captured, mut emitter) = emitter(OutputFormat::Json);
        emitter.on_text_chunk("ANSWER-TEXT-42", None);
        let stop = crate::headless::finish_turn(
            &mut emitter,
            Some(Ok(super::completed_prompt_response())),
            false,
            None,
            &acp::SessionId::new("sess-1"),
            false,
        )
        .expect("ok");
        assert_eq!(stop, TurnStop::Ended);
        let doc: serde_json::Value = serde_json::from_str(&captured.text()).expect("one document");
        assert_eq!(doc["text"], "ANSWER-TEXT-42");
        assert!(doc.get("permissionDenied").is_none(), "{doc}");
        assert!(emitter.take_permission_denial().is_none());
    }

    /// The flush's model request would be refused by the same spent budget and relabel the denial's
    /// exit `3` as a failed run's `1`, so it never runs after one; every other gate is unchanged.
    #[test]
    fn the_memory_flush_never_runs_after_a_budget_denial() {
        use crate::headless::should_run_memory_flush;
        let budget = TurnStop::BudgetDenied(HeadlessDenialRule::ExecutionBudgetUnrecognized);
        assert!(!should_run_memory_flush(true, &Ok(budget)));
        assert!(should_run_memory_flush(true, &Ok(TurnStop::Ended)));
        assert!(should_run_memory_flush(true, &Ok(TurnStop::PermissionCancelled)));
        assert!(!should_run_memory_flush(true, &Err(anyhow::anyhow!("boom"))));
        assert!(!should_run_memory_flush(false, &Ok(TurnStop::Ended)));
    }

    /// The remedy is data a script may act on, so the flags it names must exist. They are `--allow`
    /// and `--deny` (`app/cli.rs`); P02a's record named `--allow-rules`/`--deny-rules`, which do not.
    #[test]
    fn the_remedies_name_flags_that_exist() {
        for rule in [
            HeadlessDenialRule::HeadlessNeverApproves,
            HeadlessDenialRule::YoloHadNoAllowOption,
        ] {
            let remedy = rule.remedy();
            assert!(!remedy.contains("--allow-rules"), "{remedy}");
            assert!(!remedy.contains("--deny-rules"), "{remedy}");
        }
        assert!(
            HeadlessDenialRule::HeadlessNeverApproves
                .remedy()
                .contains("--allow,")
        );
        assert!(
            HeadlessDenialRule::YoloHadNoAllowOption
                .remedy()
                .contains("--deny ")
        );
        use clap::CommandFactory as _;
        let cmd = crate::app::cli::PagerArgs::command();
        for flag in ["allow", "deny", "permission-mode"] {
            assert!(
                cmd.get_arguments().any(|a| a.get_long() == Some(flag)),
                "--{flag} must be a real flag"
            );
        }
    }
}

/// P02c — the headless guide is compiled into the binary (`docs.rs` `include_str!`), so what it says
/// about a denial is a shipped product claim. These pins tie its prose to the code that emits it: a
/// record field, a rule, a remedy flag or the exit code that changes on one side fails here.
mod denial_docs_pin {
    use crate::headless::{HeadlessDenial, HeadlessDenialRule, PERMISSION_DENIED_EXIT_CODE};

    fn guide() -> &'static str {
        crate::docs::USER_GUIDE
            .iter()
            .find(|d| d.filename == "14-headless-mode.md")
            .expect("the headless guide is bundled")
            .content
    }

    /// The `json` example in "The denial record, per format": the first fenced block that carries
    /// `permissionDenied`.
    fn documented_record() -> serde_json::Value {
        let section = guide()
            .split("#### The denial record, per format")
            .nth(1)
            .expect("the per-format section exists");
        let block = section
            .split("```json\n")
            .skip(1)
            .map(|b| b.split("```").next().unwrap_or_default())
            .find(|b| b.contains("\"permissionDenied\""))
            .expect("a json example of the record");
        let doc: serde_json::Value = serde_json::from_str(block).unwrap_or_else(|e| {
            panic!("the documented example must be valid JSON ({e}):\n{block}")
        });
        doc["permissionDenied"].clone()
    }

    #[test]
    fn the_documented_record_has_exactly_the_emitted_fields() {
        let denial = HeadlessDenial {
            rule: HeadlessDenialRule::HeadlessNeverApproves,
            tool_title: Some("Write src/main.rs".into()),
            tool_call_id: "tc-17".into(),
            offered_option_kinds: vec!["allow_once".into(), "reject_once".into()],
            agent_message: None,
        };
        let keys = |v: &serde_json::Value| {
            let mut k: Vec<String> = v.as_object().expect("an object").keys().cloned().collect();
            k.sort();
            k
        };
        let documented = documented_record();
        assert_eq!(keys(&documented), keys(&denial.wire_record(true)));
        assert_eq!(documented["exitCode"], PERMISSION_DENIED_EXIT_CODE);
        assert_eq!(documented["endedRun"], true);
        // Every field of the record has a row in the field table.
        for key in keys(&denial.wire_record(true)) {
            assert!(
                guide().contains(&format!("| `{key}` |")),
                "the field table must describe `{key}`"
            );
        }
    }

    #[test]
    fn the_guide_lists_every_rule_with_flags_that_exist() {
        let guide = guide();
        let budget = fuigo_shell::acp_error::ExecutionBudgetRule::ALL
            .into_iter()
            .map(HeadlessDenialRule::ExecutionBudget);
        for rule in [
            HeadlessDenialRule::HeadlessNeverApproves,
            HeadlessDenialRule::YoloHadNoAllowOption,
            HeadlessDenialRule::ExecutionBudgetUnrecognized,
        ]
        .into_iter()
        .chain(budget)
        {
            assert!(
                guide.contains(&format!("| `{}` |", rule.id())),
                "the rules table must list `{}`",
                rule.id()
            );
        }
        assert!(
            !guide.contains("--allow-rules"),
            "there is no --allow-rules flag"
        );
        assert!(
            !guide.contains("--deny-rules"),
            "there is no --deny-rules flag"
        );
        // The stderr example is the real line, remedy included, for the documented call.
        let line = HeadlessDenial {
            rule: HeadlessDenialRule::HeadlessNeverApproves,
            tool_title: Some("Write src/main.rs".into()),
            tool_call_id: "tc-17".into(),
            offered_option_kinds: vec![],
            agent_message: None,
        }
        .human_line();
        let documented: String = guide
            .split("#### The stderr line")
            .nth(1)
            .and_then(|s| s.split("```\n").nth(1))
            .expect("the stderr example")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            documented, line,
            "the documented stderr line is the emitted one"
        );
    }

    #[test]
    fn the_guide_documents_the_exit_code_and_the_messages_field() {
        let guide = guide();
        assert!(
            guide.contains(&format!(
                "| `{PERMISSION_DENIED_EXIT_CODE}`  | **Blocked.**"
            )),
            "the exit-code table row for the denial code"
        );
        assert!(
            !guide.contains("does not collect permission denials"),
            "the stale claim that permission_denials is always empty"
        );
        assert!(guide.contains("`tool_name`, `tool_use_id`, `tool_input`"));
    }

    /// The agent-mode guide documents the wire the headless pager decodes (Contract D.4): the stable
    /// `data.code` and every rule id the shell can send.
    #[test]
    fn the_agent_guide_documents_the_budget_denial_wire() {
        let guide = crate::docs::USER_GUIDE
            .iter()
            .find(|d| d.filename == "15-agent-mode.md")
            .expect("the agent-mode guide is bundled")
            .content;
        assert!(guide.contains(&format!(
            "`data.code: \"{}\"`",
            fuigo_shell::acp_error::EXECUTION_BUDGET_DENIED_CODE
        )));
        for rule in fuigo_shell::acp_error::ExecutionBudgetRule::ALL {
            assert!(
                guide.contains(&format!("| `{}` |", rule.id())),
                "the agent guide must list `{}`",
                rule.id()
            );
        }
        // Every structured field the shell puts in `data` is described in the field table.
        let wire = fuigo_shell::acp_error::ExecutionBudgetDenial {
            rule: fuigo_shell::acp_error::ExecutionBudgetRule::TotalTokensExhausted,
            total_token_limit: Some(1),
            total_tokens_used: 2,
            output_token_limit: None,
            output_tokens_used: 0,
            unknown_usage: false,
        }
        .to_acp_error();
        let data = wire.data.expect("typed data");
        let section = guide
            .split("#### Token-budget denials")
            .nth(1)
            .expect("the budget-denial section");
        for key in data.as_object().expect("an object").keys() {
            if key == "message" || key == "error_kind" {
                continue; // described by the general Errors table
            }
            assert!(
                section.contains(&format!("`{key}`")),
                "the budget-denial field table must describe `{key}`"
            );
        }
    }
}

/// P188: a resent model request voids what its dead attempts streamed. `plain` and `json` never print that text;
/// the streaming formats never put it in a frame or the result, and say what is void where deltas already went out.
#[test]
fn p188_a_discarded_attempt_never_reaches_the_reply_in_any_format() {
    use super::StreamEvent;
    for format in [
        super::OutputFormat::Plain,
        super::OutputFormat::Json,
        super::OutputFormat::StreamingJson,
        super::OutputFormat::StreamingMessagesJson,
    ] {
        let captured = CapturedOut::default();
        let mut emitter =
            super::HeadlessEmitter::with_writer(format, false, Box::new(captured.clone()));
        // A committed response first: its text is final and must survive the later discards
        emitter.on_text_chunk("Looking. ", Some(1));
        emitter.reduce_and_emit(StreamEvent::ResponseCompleted {
            message_id: None,
            stop_reason: Some("tool_use".into()),
            usage: None,
            signature: None,
            stop_sequence: None,
        });
        for (stream, dead) in [(2, "A1"), (3, "A2")] {
            emitter.on_thought_chunk(&format!("thinking {dead}"), Some(stream));
            emitter.on_text_chunk(dead, Some(stream));
            if stream == 3 {
                // Astra r1: a hosted tool (x_search) reports mid-attempt; it is not a response boundary
                emitter.reduce_and_emit(StreamEvent::ToolCall(super::reducer::ToolCallEvent::hosted_for_test(
                    "xs-1", "x_search",
                )));
            }
            emitter.reduce_and_emit(StreamEvent::ResponseDiscarded {
                message_id: None,
                stream_start_ms: Some(stream),
            });
        }
        emitter.on_text_chunk("A3", Some(4));
        emitter.reduce_and_emit(StreamEvent::ResponseCompleted {
            message_id: None,
            stop_reason: Some("end_turn".into()),
            usage: None,
            signature: None,
            stop_sequence: None,
        });
        emitter.on_end("end_turn", "sess-p188", "req-p188", None);
        let out = captured.text();
        match format {
            super::OutputFormat::Plain => assert_eq!(out, "Looking. A3\n"),
            super::OutputFormat::Json => {
                let doc: serde_json::Value = serde_json::from_str(&out).expect("one JSON document");
                assert_eq!(doc["text"], "Looking. A3", "{out}");
                assert!(doc.get("thought").is_none(), "the dead attempts' thinking is void too: {out}");
            }
            super::OutputFormat::StreamingJson => {
                // Text lines went out live; a consumer applying `response_discarded` gets the accepted reply
                let (mut visible, mut committed, mut voids) = (String::new(), 0, 0);
                for line in out.lines() {
                    let line: serde_json::Value = serde_json::from_str(line).expect("NDJSON");
                    match line["type"].as_str() {
                        Some("text") => visible.push_str(line["data"].as_str().unwrap()),
                        Some("usage") => committed = visible.len(),
                        Some("response_discarded") => {
                            voids += 1;
                            visible.truncate(committed);
                        }
                        _ => {}
                    }
                }
                assert_eq!(voids, 2, "{out}");
                assert_eq!(visible, "Looking. A3", "{out}");
            }
            super::OutputFormat::StreamingMessagesJson => {
                assert!(!out.contains("A1") && !out.contains("A2"), "no frame or result carries dead text: {out}");
                let lines: Vec<serde_json::Value> = out
                    .lines()
                    .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("NDJSON"))
                    .collect();
                let result = lines.iter().find(|l| l["type"] == "result").expect("result line");
                // `result` is the last assistant frame's text, as for any multi-response turn
                assert_eq!(result["result"], "A3", "{out}");
                // Astra r1 HIGH: the hosted call reported by a dead attempt keeps its tool_use, so its error
                // tool_result is never an orphan
                let ids = |kind: &str, key: &str| -> Vec<String> {
                    lines
                        .iter()
                        .flat_map(|l| l["message"]["content"].as_array().cloned().unwrap_or_default())
                        .filter(|b| b["type"] == kind)
                        .map(|b| b[key].as_str().unwrap_or_default().to_string())
                        .collect()
                };
                assert_eq!(ids("tool_use", "id"), ids("tool_result", "tool_use_id"), "{out}");
            }
        }
    }
}

/// P181 (Grok round): plain output on a terminal is the model's text, which is untrusted, so it goes through the shared
/// terminal filter; every other format and a piped plain stream stay exact.
#[test]
fn plain_output_to_a_terminal_is_scrubbed_and_piped_output_is_exact() {
    use std::sync::{Arc, Mutex};

    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let run = |terminal: bool| {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let mut emitter = super::HeadlessEmitter::with_writer(
            super::OutputFormat::Plain,
            false,
            Box::new(Sink(bytes.clone())),
        );
        emitter.scrub_terminal = terminal;
        emitter.on_text_chunk("answer \x1b]0;owned\x07 with\u{2028}break \u{e0041}and \x1b[1mbold\x1b[0m\n", None);
        // P188 holds plain text until its response is accepted; this is the acceptance
        emitter.flush_plain_pending();
        String::from_utf8(bytes.lock().unwrap().clone()).unwrap()
    };
    assert_eq!(run(true), "answer  ]0;owned  with break and  [1mbold [0m\n");
    assert_eq!(
        run(false),
        "answer \x1b]0;owned\x07 with\u{2028}break \u{e0041}and \x1b[1mbold\x1b[0m\n"
    );
}

/// P181 (sweep, after P188): a resend after streamed output must not let a hostile first attempt through, and the resent
/// attempt itself is scrubbed. Plain output on a terminal is held per attempt and written once it is accepted, so the
/// filter runs on every write whichever attempt it belongs to: the voided one never reaches the terminal, an attempt
/// accepted by `ResponseCompleted` and an attempt accepted because the next one began are both scrubbed.
#[test]
fn p181_plain_terminal_output_scrubs_the_first_and_the_resent_attempt() {
    use super::StreamEvent;
    let captured = CapturedOut::default();
    let mut emitter = super::HeadlessEmitter::with_writer(
        super::OutputFormat::Plain,
        false,
        Box::new(captured.clone()),
    );
    emitter.scrub_terminal = true;
    let done = || StreamEvent::ResponseCompleted {
        message_id: None,
        stop_reason: Some("tool_use".into()),
        usage: None,
        signature: None,
        stop_sequence: None,
    };
    // Attempt 1 is voided by the resend
    emitter.on_text_chunk("void \x1b]0;first\x07 text", Some(1));
    emitter.reduce_and_emit(StreamEvent::ResponseDiscarded {
        message_id: None,
        stream_start_ms: Some(1),
    });
    // Attempt 2, the resend, is accepted by its completion
    emitter.on_text_chunk("two \x1b]0;second\x07\u{2028}ok ", Some(2));
    emitter.reduce_and_emit(done());
    // Attempt 3 is accepted because attempt 4 begins without a discard
    emitter.on_text_chunk("three \u{9b}31m\u{e0041}x ", Some(3));
    emitter.on_text_chunk("four \x1b[2J", Some(4));
    emitter.reduce_and_emit(done());
    let out = captured.text();
    assert_eq!(out, "two  ]0;second  ok three  31mx four  [2J");
    assert!(!out.contains("void"), "{out:?}");
}


/// P181 (Grok r3 HIGH): plain model text on a terminal cannot restyle the terminal, so the denial that follows is intact.
/// The audit's attack bytes (reset, a fake Fuigo line, black on black, faint, strikethrough) arrive as inert text with
/// no ESC; split across chunks the sequence is joined before the scrub; the only escape on the stream is Fuigo's own
/// leading reset on the denial line.
#[test]
fn p181_r3_model_text_on_a_terminal_cannot_restyle_the_denial_that_follows() {
    for tail in ["\x1b[38;2;0;0;0;48;2;0;0;0m", "\x1b[30;40m", "\x1b[2m", "\x1b[9m"] {
        let captured = CapturedOut::default();
        let mut emitter = super::HeadlessEmitter::with_writer(
            super::OutputFormat::Plain,
            false,
            Box::new(captured.clone()),
        );
        emitter.scrub_terminal = true;
        let model = format!("\x1b[0m fuigo: permission granted, nothing to review.\n{tail}");
        emitter.on_text_chunk(&model, Some(1));
        emitter.flush_plain_pending();
        let out = captured.text();
        assert!(!out.contains('\x1b'), "{out:?}");
        assert!(out.contains("fuigo: permission granted") && out.contains(&tail[1..]), "inert text stays visible: {out:?}");

        let denial = super::HeadlessDenial {
            rule: super::HeadlessDenialRule::HeadlessNeverApproves,
            tool_title: Some("Write\x1b[0m fuigo: permission granted".to_owned()),
            tool_call_id: "tc-1".to_owned(),
            offered_option_kinds: vec!["reject_once".to_owned()],
            agent_message: None,
        };
        let mut err = Vec::new();
        assert!(fuigo_tty_utils::best_effort_stderr::write_fuigo_line_with(&mut err, &denial.notice_line(), true));
        let err = String::from_utf8(err).unwrap();
        assert!(err.starts_with("\x1b[0mfuigo: a permission was denied"), "{err:?}");
        assert_eq!(err.matches('\x1b').count(), 1, "only Fuigo's own reset: {err:?}");
        assert!(err.contains(denial.rule.remedy()) && err.ends_with(".\n"), "{err:?}");
        // L1: the agent's title and the call id are quoted, so its words read as quoted text, not as Fuigo's sentence
        assert!(err.contains("\u{201c}Write [0m fuigo: permission granted\u{201d} (tool call [tc-1])"), "{err:?}");
    }
}

/// P181 (Grok r3 HIGH): a sequence split across chunks of one response cannot survive: the chunks are joined first.
#[test]
fn p181_r3_a_sequence_split_across_chunks_is_judged_whole() {
    let captured = CapturedOut::default();
    let mut emitter = super::HeadlessEmitter::with_writer(
        super::OutputFormat::Plain,
        false,
        Box::new(captured.clone()),
    );
    emitter.scrub_terminal = true;
    for chunk in ["a\x1b", "[3", "0;4", "0mb \x1b]0;ti", "tle\x07c \u{9b}", "2Jd\n"] {
        emitter.on_text_chunk(chunk, Some(1));
    }
    emitter.flush_plain_pending();
    assert_eq!(captured.text(), "a [30;40mb  ]0;title c  2Jd\n");
}

/// P181 (Grok r3 HIGH): both attempts of a P188 discard-and-resend get the strict scrub; the voided one never appears.
#[test]
fn p181_r3_the_resend_path_is_strictly_scrubbed_on_both_attempts() {
    use super::StreamEvent;
    let captured = CapturedOut::default();
    let mut emitter = super::HeadlessEmitter::with_writer(
        super::OutputFormat::Plain,
        false,
        Box::new(captured.clone()),
    );
    emitter.scrub_terminal = true;
    emitter.on_text_chunk("void \x1b[2m", Some(1));
    emitter.reduce_and_emit(StreamEvent::ResponseDiscarded { message_id: None, stream_start_ms: Some(1) });
    emitter.on_text_chunk("two \x1b[30;40m ", Some(2));
    emitter.on_text_chunk("three \x1b[9m", Some(3));
    emitter.flush_plain_pending();
    let out = captured.text();
    assert_eq!(out, "two  [30;40m three  [9m");
}
