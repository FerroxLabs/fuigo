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
        ),
    )
    .await;

    assert!(
        outcome.is_err(),
        "an acknowledged prompt must keep waiting, not abort: {:?}",
        outcome.map(|o| o.prompt_unacknowledged)
    );
}
