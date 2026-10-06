//! P146 (S17/K2 follow-up): a compaction checkpoint is read only from a regular file inside the session folder.
//!
//! S17 refuses a checkpoint marker whose path leaves the session folder, but the check was on the text of the path
//! only. A `compaction_checkpoints/<id>.json` that is a SYMLINK to a file outside the session was followed: that file's
//! content became the session's summary on load and was copied into its forks. Now such a checkpoint reads as missing
//! (the same as a refused path): the outside file is never read, and the session still loads and answers.
//!
//! Real path: a session compacted by an agent over ACP, damaged on disk once that agent is gone, then loaded cold
//! (`session/load`) and forked by a fresh agent. One `#[test]` per binary (the harness env is process-global).
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{
    AutoApproveClient, RPC_TIMEOUT, connect_client, ext_method, new_session, prompt_turn, run_agent_test,
    spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_shell::session::info::Info;
use fuigo_test_support::sse::chat_completion_script_exact;
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, ScriptedResponse};
use serde_json::json;
use std::path::{Path, PathBuf};

const MODEL: &str = "test-model";
const SUMMARY_PREAMBLE: &str = "This session is being continued from a previous conversation";
const SENTINEL: &str = "P146-OUTSIDE-SENTINEL";

fn agent_config() -> fuigo_shell::agent::config::Config {
    let mut config = fuigo_shell::agent::config::Config::default();
    // A local title keeps title generation off the mock, so no auxiliary request races the scripted turns.
    config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
    config
}

async fn connect(label: &str) -> acp::ClientSideConnection {
    connect_client(AutoApproveClient, label, spawn_agent_local_with_config(agent_config()))
        .await
        .0
}

fn session_dir(session: &acp::SessionId, cwd: &Path) -> PathBuf {
    fuigo_shell::session::persistence::session_dir(&Info {
        id: session.clone(),
        cwd: cwd.to_string_lossy().into_owned(),
    })
}

/// A prompt answered with `answer`; returns the body of its first foreground request.
async fn turn(
    conn: &acp::ClientSideConnection,
    mock: &MockInferenceServer,
    session: &acp::SessionId,
    prompt: &str,
    answer: &str,
) -> String {
    let step = mock.expect_response(
        format!("{prompt}-answer"),
        InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
        ScriptedResponse::sse(chat_completion_script_exact(answer, MODEL)),
    );
    let before = mock.requests().len();
    prompt_turn(conn, session, prompt).await;
    step.assert_satisfied();
    mock.requests()[before..]
        .iter()
        .filter(|r| r.path == "/v1/chat/completions" && r.header("x-fuigo-turn-idx").is_some())
        .filter_map(|r| r.body.clone())
        .next()
        .expect("the turn made a foreground request")["messages"]
        .to_string()
}

/// Every file under `dir`, recursively, as text (lossy), for "was the outside content copied here?" checks.
fn tree_text(dir: &Path) -> String {
    let mut text = String::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path).expect("stat");
        if meta.is_dir() {
            text.push_str(&tree_text(&path));
        } else if meta.is_file() {
            text.push_str(&String::from_utf8_lossy(&std::fs::read(&path).unwrap_or_default()));
        }
    }
    text
}

#[cfg(unix)]
#[test]
fn a_symlinked_compaction_checkpoint_is_never_followed() {
    run_agent_test(|cwd, mock| async move {
        let outside = tempfile::TempDir::new().expect("outside dir");

        // ── Agent A: a session with one turn, a compaction and one more turn. ──
        let a = connect("p146-build").await;
        let session = new_session(&a, &cwd).await;
        turn(&a, &mock, &session, "First prompt.", "First answer.").await;
        ext_method(
            &a,
            "fuigo/compact_conversation",
            json!({"session_id": session.to_string(), "user_context": "Keep the answers."}),
        )
        .await;
        let live = turn(&a, &mock, &session, "Second prompt.", "Second answer.").await;
        assert!(live.contains(SUMMARY_PREAMBLE), "fixture: the compacted session's request carries the summary: {live}");
        drop(a);

        // ── Damage: the checkpoint becomes a symlink to a copy outside the session that carries the sentinel, and
        // chat_history.jsonl is gone, so the load rebuilds the history from the transcript and that checkpoint. ──
        let dir = session_dir(&session, &cwd);
        let checkpoints: Vec<PathBuf> = std::fs::read_dir(dir.join("compaction_checkpoints"))
            .expect("checkpoint dir")
            .map(|e| e.expect("entry").path())
            .collect();
        assert_eq!(checkpoints.len(), 1, "fixture: one compaction, one checkpoint");
        let checkpoint = &checkpoints[0];
        let original = std::fs::read_to_string(checkpoint).expect("read checkpoint");
        assert!(original.contains(SUMMARY_PREAMBLE), "fixture: the checkpoint holds the summary");
        let planted = outside.path().join("sentinel.json");
        std::fs::write(&planted, original.replace(SUMMARY_PREAMBLE, &format!("{SENTINEL} {SUMMARY_PREAMBLE}")))
            .expect("write outside file");
        let planted_before = std::fs::read(&planted).expect("read outside file");
        std::fs::remove_file(checkpoint).expect("remove checkpoint");
        std::os::unix::fs::symlink(&planted, checkpoint).expect("plant symlink");
        std::fs::remove_file(dir.join("chat_history.jsonl")).expect("remove chat history");

        // ── Agent B: cold load, a turn, then a whole fork. ──
        let b = connect("p146-load").await;
        let mut failures = Vec::new();
        match tokio::time::timeout(
            RPC_TIMEOUT,
            b.load_session(acp::LoadSessionRequest::new(session.clone(), cwd.to_path_buf())),
        )
        .await
        {
            Ok(Ok(_)) => {
                let messages = turn(&b, &mock, &session, "Third prompt.", "Third answer.").await;
                if messages.contains(SENTINEL) {
                    failures.push(format!("the loaded session's request carries the outside file's content: {messages}"));
                }
                if !messages.contains("Second prompt.") {
                    failures.push(format!("the loaded session lost its post-compaction turn: {messages}"));
                }
            }
            Ok(Err(e)) => failures.push(format!("session/load failed: {e}")),
            Err(_) => failures.push("session/load timed out".into()),
        }
        let fork = ext_method(
            &b,
            "fuigo/session/fork",
            json!({
                "sourceSessionId": session.to_string(),
                "sourceCwd": cwd.to_string_lossy(),
                "newCwd": cwd.to_string_lossy(),
            }),
        )
        .await;
        let fork = acp::SessionId::new(fork["newSessionId"].as_str().expect("fork returns its session id").to_string());
        let fork_text = tree_text(&session_dir(&fork, &cwd));
        if fork_text.contains(SENTINEL) {
            failures.push("the fork copied the outside file's content".into());
        }
        if tree_text(&dir).contains(SENTINEL) {
            failures.push("the session's own files now carry the outside file's content".into());
        }
        if std::fs::read(&planted).expect("read outside file") != planted_before {
            failures.push("the outside file was changed".into());
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    });
}
