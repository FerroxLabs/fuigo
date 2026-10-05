//! P07a: where plugin hooks fire is gated by folder trust on every path P07a touches, and a
//! mid-session trust change reaches the subagents spawned after it.
//!
//! The workdir is an untrusted git repo (release build simulated, so the gate is live) carrying
//! three match-all `PreToolUse` loggers, each writing its stdin (the hook envelope) to its own log:
//!
//! - `project`: a repo hook file, `.fuigo/hooks/probe.json`;
//! - `projplug`: a PROJECT-scope plugin's inline manifest hooks, `.fuigo/plugins/projplug`;
//! - `userplug`: a USER-scope plugin's `hooks/hooks.json`, `$FUIGO_HOME/plugins/userplug`;
//! - `cfgplug`: a plugin the REPO's own `.fuigo/config.toml` names in `[plugins].paths` (config-path
//!   scope, auto-trusted because it sits under `$HOME`), so only the folder gate keeps it out.
//!
//! Three phases, each a parent turn that spawns a foreground child; child and parent each `read_file` a probe file
//! whose name marks the call in the hook envelope:
//!
//! - **A, untrusted (session-start load, subagent inheritance, agent-hooks override):** only
//!   `userplug` fires, in parent and child, and in a second session whose agent definition carries
//!   inline hooks (the `spawn_and_register_session` override). The repo's hooks stay dark.
//! - **B, after `/hooks-trust` (`fuigo/hooks/action` `trust`):** the child spawned AFTER the grant
//!   fires `project` and `projplug`. Red before P07a: a subagent copied its parent's registry from
//!   a `SessionHandle` field written once at spawn, so the reload the grant triggered never reached
//!   it - and the `/hooks-trust` path never rebuilt the plugin view, so `projplug` stayed out even
//!   in the parent.
//! - **C, after `/hooks-untrust`:** none of `project`, `projplug`, `cfgplug` fires again, in parent
//!   or child. The plugins are the stale-snapshot case: the session's stored plugin registry does not
//!   follow a trust change, so the hook reload must rediscover the plugins on the current verdict
//!   (`cfgplug` is not `Project`-scoped, so no scope filter alone catches it).
//! - **D:** a sibling session opened while trusted untrusts the already-revoked folder: the verdict
//!   does not change, but its own registry must still drop the repo's hooks.
//! - **E:** the typed `/hooks-trust` / `/hooks-untrust` slash commands reconcile hooks like the modal.
#![cfg(unix)]

#[allow(dead_code)]
mod acp_harness;

use std::path::{Path, PathBuf};

use acp_harness::{
    AutoApproveClient, RPC_TIMEOUT, connect_client, ext_method, new_session, run_agent_test,
    spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::sse::{
    chat_completion_script_exact, chat_completions_reasoning_then_tool_call_events,
};
use fuigo_test_support::{
    InferenceEndpoint, InferenceExpectation, InferenceRequestMatcher, MockInferenceServer,
    ScriptedResponse,
};
use serde_json::{Value, json};

const TAGS: [&str; 4] = ["project", "projplug", "cfgplug", "userplug"];
const REPO_TAGS: [&str; 3] = ["project", "projplug", "cfgplug"];

fn tool_call(call_id: &str, name: &str, arguments: &str) -> ScriptedResponse {
    ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
        "probe",
        call_id,
        name,
        arguments,
        "test-model",
    ))
}

/// A `read_file` call on `cwd/<file>`; the file name is what marks the call in the hook envelope.
fn read_call(call_id: &str, cwd: &Path, file: &str) -> ScriptedResponse {
    let path = cwd.join(file);
    std::fs::write(&path, "probe\n").expect("probe file");
    tool_call(
        call_id,
        "read_file",
        &json!({"target_file": path}).to_string(),
    )
}

fn probe_file(phase: &str, who: &str) -> String {
    format!("p07-{phase}-{who}.txt")
}

fn text(answer: &str) -> ScriptedResponse {
    ScriptedResponse::sse(chat_completion_script_exact(answer, "test-model"))
}

fn logger_hooks(log: &Path) -> Value {
    json!({
        "PreToolUse": [{
            "hooks": [{
                "type": "command",
                "command": format!("cat >> {0}; echo >> {0}", log.display()),
                "timeout": 30
            }]
        }]
    })
}

fn log_path(dir: &Path, tag: &str) -> PathBuf {
    dir.join(format!("{tag}.jsonl"))
}

/// The hook envelopes `tag` logged, one JSON object per line.
fn envelopes(dir: &Path, tag: &str) -> Vec<Value> {
    std::fs::read_to_string(log_path(dir, tag))
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad envelope {l:?}: {e}")))
        .collect()
}

fn session_of(envelope: &Value) -> String {
    envelope
        .get("sessionId")
        .or_else(|| envelope.get("session_id"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// `(parent runs, child runs)` of phase `phase`'s probe reads that `tag` logged.
fn probe_runs(dir: &Path, tag: &str, phase: &str, parent: &str) -> (usize, usize) {
    let runs = envelopes(dir, tag);
    let parent_file = probe_file(phase, "parent");
    let child_file = probe_file(phase, "child");
    let in_parent = runs
        .iter()
        .filter(|e| session_of(e) == parent && e.to_string().contains(&parent_file))
        .count();
    let in_child = runs
        .iter()
        .filter(|e| session_of(e) != parent && e.to_string().contains(&child_file))
        .count();
    (in_parent, in_child)
}

/// Runs `tag` logged for `session` reading `p07-<label>.txt`.
fn tagged_runs(dir: &Path, tag: &str, session: &str, label: &str) -> usize {
    let file = format!("p07-{label}.txt");
    envelopes(dir, tag)
        .iter()
        .filter(|e| session_of(e) == session && e.to_string().contains(&file))
        .count()
}

/// A session whose agent definition carries inline hooks (an `agentinline` logger), so it is built by the agent-hooks spawn override.
async fn new_hooked_session(
    conn: &acp::ClientSideConnection,
    cwd: &Path,
    logs: &Path,
) -> acp::SessionId {
    let meta = json!({
        "modelId": "test-model",
        "agentProfile": {
            "name": "hooked-agent",
            "description": "an agent with inline hooks",
            "hooks": logger_hooks(&log_path(logs, "agentinline"))
        }
    });
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.new_session(
            acp::NewSessionRequest::new(cwd.to_path_buf()).meta(meta.as_object().cloned()),
        ),
    )
    .await
    .expect("session/new timed out")
    .expect("session/new failed")
    .session_id
}

/// One turn in `session`: read `p07-<label>.txt`, then answer.
async fn run_single_read(
    conn: &acp::ClientSideConnection,
    mock: &MockInferenceServer,
    session: &acp::SessionId,
    cwd: &Path,
    label: &str,
) {
    let fg = || InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions);
    let steps = [
        mock.expect_response(
            format!("{label}-read"),
            fg(),
            read_call(&format!("call_{label}"), cwd, &format!("p07-{label}.txt")),
        ),
        mock.expect_response(format!("{label}-done"), fg(), text("done")),
    ];
    let response = tokio::time::timeout(
        RPC_TIMEOUT,
        conn.prompt(acp::PromptRequest::new(
            session.clone(),
            vec![acp::ContentBlock::Text(acp::TextContent::new(
                "Read one file.",
            ))],
        )),
    )
    .await
    .unwrap_or_else(|_| panic!("{label} prompt timed out"))
    .unwrap_or_else(|e| {
        panic!(
            "{label} prompt failed: {e:?}\n{}",
            mock.request_log_summary()
        )
    });
    assert_eq!(response.stop_reason, acp::StopReason::EndTurn, "{label}");
    for step in &steps {
        step.assert_satisfied();
    }
}

fn clear_logs(dir: &Path) {
    for tag in TAGS {
        let _ = std::fs::remove_file(log_path(dir, tag));
    }
}

/// One phase: parent spawns a foreground child; child reads its probe file and ends; parent reads its probe file and ends.
async fn run_phase(
    conn: &acp::ClientSideConnection,
    mock: &MockInferenceServer,
    session: &acp::SessionId,
    cwd: &Path,
    phase: &str,
) {
    let fg = || InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions);
    let spawn_args = json!({
        "description": format!("phase {phase} child"),
        "prompt": format!("Read one file, then stop (phase {phase} child)."),
        "subagent_type": "general-purpose",
    });
    let steps: Vec<InferenceExpectation> = vec![
        mock.expect_response(
            format!("{phase}-parent-spawn"),
            fg(),
            tool_call(
                &format!("call_{phase}_spawn"),
                "spawn_subagent",
                &spawn_args.to_string(),
            ),
        ),
        mock.expect_response(
            format!("{phase}-child-read"),
            fg(),
            read_call(
                &format!("call_{phase}_child"),
                cwd,
                &probe_file(phase, "child"),
            ),
        ),
        mock.expect_response(format!("{phase}-child-done"), fg(), text("child done")),
        mock.expect_response(
            format!("{phase}-parent-read"),
            fg(),
            read_call(
                &format!("call_{phase}_parent"),
                cwd,
                &probe_file(phase, "parent"),
            ),
        ),
        mock.expect_response(format!("{phase}-parent-done"), fg(), text("parent done")),
    ];
    let response = tokio::time::timeout(
        RPC_TIMEOUT,
        conn.prompt(acp::PromptRequest::new(
            session.clone(),
            vec![acp::ContentBlock::Text(acp::TextContent::new(format!(
                "Phase {phase}: spawn one foreground child, then read a file."
            )))],
        )),
    )
    .await
    .unwrap_or_else(|_| panic!("phase {phase} prompt timed out"))
    .unwrap_or_else(|e| {
        panic!(
            "phase {phase} prompt failed: {e:?}\n{}",
            mock.request_log_summary()
        )
    });
    assert_eq!(
        response.stop_reason,
        acp::StopReason::EndTurn,
        "phase {phase}\n{}",
        mock.request_log_summary()
    );
    for step in &steps {
        step.assert_satisfied();
    }
}

async fn hooks_action(conn: &acp::ClientSideConnection, session: &acp::SessionId, action: &str) {
    hooks_action_expect(conn, session, action, "success").await;
}

async fn hooks_action_expect(
    conn: &acp::ClientSideConnection,
    session: &acp::SessionId,
    action: &str,
    status: &str,
) {
    let outcome = ext_method(
        conn,
        "fuigo/hooks/action",
        json!({"sessionId": session.0.to_string(), "action": {"type": action}}),
    )
    .await;
    assert_eq!(
        outcome["result"]["status"]
            .as_str()
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some(status),
        "hooks action {action}: {outcome}"
    );
}

/// A builtin slash command typed as a prompt (`/hooks-trust`, `/hooks-untrust`); it ends the turn without the model.
async fn slash(conn: &acp::ClientSideConnection, session: &acp::SessionId, command: &str) {
    let response = tokio::time::timeout(
        RPC_TIMEOUT,
        conn.prompt(acp::PromptRequest::new(
            session.clone(),
            vec![acp::ContentBlock::Text(acp::TextContent::new(command))],
        )),
    )
    .await
    .unwrap_or_else(|_| panic!("{command} timed out"))
    .unwrap_or_else(|e| panic!("{command} failed: {e:?}"));
    assert_eq!(response.stop_reason, acp::StopReason::EndTurn, "{command}");
}

/// Assert `session`'s read of `p07-<label>.txt` fired `userplug` once and each repo source `repo` times.
fn assert_single_read(logs: &Path, session: &acp::SessionId, label: &str, repo: usize, why: &str) {
    let id = session.0.to_string();
    for tag in TAGS {
        let want = if tag == "userplug" { 1 } else { repo };
        assert_eq!(
            tagged_runs(logs, tag, &id, label),
            want,
            "{why}: `{tag}` must fire {want} time(s)"
        );
    }
}

#[test]
fn plugin_hooks_follow_folder_trust_in_sessions_and_their_subagents() {
    // SAFETY: set before the harness starts any runtime; one #[test] per binary.
    // A pinned FUIGO_TEST_VERSION simulates a release build, the only build the folder-trust gate is live in.
    unsafe {
        std::env::set_var("FUIGO_TEST_VERSION", "0.0.0-p07-sim");
        std::env::remove_var("FUIGO_FOLDER_TRUST");
    }
    run_agent_test(|cwd, mock| async move {
        let fuigo_home = PathBuf::from(std::env::var("FUIGO_HOME").expect("FUIGO_HOME"));
        let logs = fuigo_home.join("hook-logs");
        std::fs::create_dir_all(&logs).expect("log dir");

        git2::Repository::init(&cwd).expect("git init the workdir");
        let repo_hooks = cwd.join(".fuigo").join("hooks");
        std::fs::create_dir_all(&repo_hooks).expect("repo hooks dir");
        std::fs::write(
            repo_hooks.join("probe.json"),
            json!({"hooks": logger_hooks(&log_path(&logs, "project"))}).to_string(),
        )
        .expect("repo hook file");
        let projplug = cwd.join(".fuigo").join("plugins").join("projplug");
        std::fs::create_dir_all(&projplug).expect("project plugin dir");
        std::fs::write(
            projplug.join("plugin.json"),
            json!({"name": "projplug", "hooks": {"hooks": logger_hooks(&log_path(&logs, "projplug"))}})
                .to_string(),
        )
        .expect("project plugin manifest");
        let userplug = fuigo_home.join("plugins").join("userplug");
        std::fs::create_dir_all(userplug.join("hooks")).expect("user plugin dir");
        std::fs::write(userplug.join("plugin.json"), r#"{"name":"userplug"}"#).expect("manifest");
        std::fs::write(
            userplug.join("hooks").join("hooks.json"),
            json!({"hooks": logger_hooks(&log_path(&logs, "userplug"))}).to_string(),
        )
        .expect("user plugin hooks.json");
        let home = PathBuf::from(std::env::var("HOME").expect("HOME"));
        let cfgplug = home.join("cfgplug");
        std::fs::create_dir_all(cfgplug.join("hooks")).expect("config-path plugin dir");
        std::fs::write(cfgplug.join("plugin.json"), r#"{"name":"cfgplug"}"#).expect("manifest");
        std::fs::write(
            cfgplug.join("hooks").join("hooks.json"),
            json!({"hooks": logger_hooks(&log_path(&logs, "cfgplug"))}).to_string(),
        )
        .expect("config-path plugin hooks.json");
        // The repo's own config names it; project config is read only while the folder is trusted
        std::fs::write(
            cwd.join(".fuigo").join("config.toml"),
            format!("[plugins]\npaths = [{:?}]\n", cfgplug.display().to_string()),
        )
        .expect("repo config.toml");
        // Every scope defaults to disabled until named in `[plugins].enabled`; enabling isolates the TRUST gate
        std::fs::write(
            fuigo_home.join("config.toml"),
            "[plugins]\nenabled = [\"userplug\", \"projplug\", \"cfgplug\"]\n",
        )
        .expect("config.toml");

        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let (conn, _) = connect_client(
            AutoApproveClient,
            "plugin-hooks-trust",
            spawn_agent_local_with_config(config),
        )
        .await;
        let session = new_session(&conn, &cwd).await;
        let parent = session.0.to_string();

        // A: untrusted
        run_phase(&conn, &mock, &session, &cwd, "a").await;
        assert_eq!(
            probe_runs(&logs, "userplug", "a", &parent),
            (1, 1),
            "A: a user plugin's hook fires from the first turn, in parent and child"
        );
        for tag in REPO_TAGS {
            assert_eq!(
                probe_runs(&logs, tag, "a", &parent),
                (0, 0),
                "A: untrusted folder: `{tag}` must not fire in parent or child"
            );
        }
        // A session whose agent carries inline hooks is built by the spawn override, the other load site
        let hooked = new_hooked_session(&conn, &cwd, &logs).await;
        run_single_read(&conn, &mock, &hooked, &cwd, "a-hooked").await;
        let hooked_id = hooked.0.to_string();
        assert_eq!(
            tagged_runs(&logs, "agentinline", &hooked_id, "a-hooked"),
            1,
            "A: the agent's own (built-in scope) hook fires"
        );
        for tag in TAGS {
            let want = usize::from(tag == "userplug");
            assert_eq!(
                tagged_runs(&logs, tag, &hooked_id, "a-hooked"),
                want,
                "A: agent-hooks session in an untrusted folder: `{tag}` must fire {want} time(s)"
            );
        }

        // B: trust granted mid-session; the child is spawned after the grant
        hooks_action(&conn, &session, "trust").await;
        clear_logs(&logs);
        run_phase(&conn, &mock, &session, &cwd, "b").await;
        for tag in TAGS {
            assert_eq!(
                probe_runs(&logs, tag, "b", &parent),
                (1, 1),
                "B: after /hooks-trust `{tag}` must fire in the parent AND in the subagent spawned after the grant"
            );
        }

        // A sibling session opened while trusted loads the repo's hooks at start
        let sibling = new_session(&conn, &cwd).await;
        run_single_read(&conn, &mock, &sibling, &cwd, "b-sibling").await;
        assert_single_read(
            &logs,
            &sibling,
            "b-sibling",
            1,
            "B: sibling opened while trusted",
        );

        // C: trust revoked mid-session
        hooks_action(&conn, &session, "untrust").await;
        clear_logs(&logs);
        run_phase(&conn, &mock, &session, &cwd, "c").await;
        assert_eq!(
            probe_runs(&logs, "userplug", "c", &parent),
            (1, 1),
            "C: a user plugin is not folder-gated and keeps firing"
        );
        for tag in REPO_TAGS {
            assert_eq!(
                probe_runs(&logs, tag, "c", &parent),
                (0, 0),
                "C: after /hooks-untrust `{tag}` must not fire in parent or child"
            );
        }

        // D: the sibling untrusts a folder another session already revoked: the verdict is unchanged ("not found"),
        // but the sibling's own registry, loaded while trusted, must still drop the repo's hooks
        hooks_action_expect(&conn, &sibling, "untrust", "not_found").await;
        run_single_read(&conn, &mock, &sibling, &cwd, "d-sibling").await;
        assert_single_read(
            &logs,
            &sibling,
            "d-sibling",
            0,
            "D: sibling after its own untrust",
        );

        // E: the literal slash commands reconcile hooks the same way as the `/hooks` modal
        slash(&conn, &session, "/hooks-trust").await;
        run_single_read(&conn, &mock, &session, &cwd, "e-trusted").await;
        assert_single_read(
            &logs,
            &session,
            "e-trusted",
            1,
            "E: after a typed /hooks-trust",
        );
        slash(&conn, &session, "/hooks-untrust").await;
        run_single_read(&conn, &mock, &session, &cwd, "e-untrusted").await;
        assert_single_read(
            &logs,
            &session,
            "e-untrusted",
            0,
            "E: after a typed /hooks-untrust",
        );
        // A reload rebuilds the whole registry; the agent's own admitted hook must survive it
        slash(&conn, &hooked, "/hooks-untrust").await;
        run_single_read(&conn, &mock, &hooked, &cwd, "e-hooked").await;
        assert_single_read(
            &logs,
            &hooked,
            "e-hooked",
            0,
            "E: agent-hooks session after a reload",
        );
        assert_eq!(
            tagged_runs(&logs, "agentinline", &hooked_id, "e-hooked"),
            1,
            "E: the agent's own hook survives the reload"
        );

        tokio::time::timeout(
            RPC_TIMEOUT,
            conn.close_session(acp::CloseSessionRequest::new(session)),
        )
        .await
        .expect("close_session timed out")
        .expect("close_session");
    });
}
