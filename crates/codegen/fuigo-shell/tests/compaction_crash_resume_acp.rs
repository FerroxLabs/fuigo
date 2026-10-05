//! P111 (DI-03): a process stopped after a compaction committed, but before its rewrite of `chat_history.jsonl`
//! landed, must resume with the compacted history.
//!
//! The compaction commit writes the checkpoint and appends the activation marker to `updates.jsonl` (the commit point);
//! the rewrite of `chat_history.jsonl` with the compacted projection follows as a separate, unacknowledged message.
//! Since P88 a resume trusts `chat_history.jsonl`, so a crash in between resumed with the pre-compaction history while
//! the transcript recorded the compaction.
//!
//! The crash is reproduced from its on-disk result: a real agent compacts the session through `fuigo/compact_conversation`
//! (the production commit), then `chat_history.jsonl` is put back to the bytes it had when the compaction started, which
//! is exactly what a crash between the marker and the rewrite leaves. A fresh agent then loads the session through the
//! real `session/load`, and the model's next request must equal that of a twin that compacted without a crash.
//! A third agent loads it again after one more turn, so the recovered history is shown to be durable.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{
    AutoApproveClient, RPC_TIMEOUT, connect_client, ext_method, new_session, prompt_turn,
    run_agent_test, spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_shell::session::info::Info;
use fuigo_test_support::sse::chat_completion_script_exact;
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, ScriptedResponse};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const MODEL: &str = "test-model";
const SUMMARY_PREAMBLE: &str = "This session is being continued from a previous conversation";

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

fn foreground() -> InferenceRequestMatcher {
    InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions)
}

async fn turn(conn: &acp::ClientSideConnection, mock: &MockInferenceServer, session: &acp::SessionId, text: &str, answer: &str) {
    let step = mock.expect_response(
        format!("answer-{answer}"),
        foreground(),
        ScriptedResponse::sse(chat_completion_script_exact(answer, MODEL)),
    );
    prompt_turn(conn, session, text).await;
    step.assert_satisfied();
}

/// Sends `text` and returns the `messages` of that turn's first foreground request.
async fn turn_messages(
    conn: &acp::ClientSideConnection,
    mock: &MockInferenceServer,
    session: &acp::SessionId,
    text: &str,
    answer: &str,
) -> Value {
    let before = mock.requests().len();
    turn(conn, mock, session, text, answer).await;
    mock.requests()[before..]
        .iter()
        .filter(|r| r.path == "/v1/chat/completions" && r.header("x-fuigo-turn-idx").is_some())
        .filter_map(|r| r.body.clone())
        .next()
        .expect("the turn made a foreground request")["messages"]
        .clone()
}

async fn compact(conn: &acp::ClientSideConnection, session: &acp::SessionId) {
    ext_method(
        conn,
        "fuigo/compact_conversation",
        json!({"session_id": session.to_string(), "user_context": "Keep the facts."}),
    )
    .await;
}

async fn load(conn: &acp::ClientSideConnection, session: &acp::SessionId, cwd: &Path) -> Result<(), String> {
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.load_session(acp::LoadSessionRequest::new(session.clone(), cwd.to_path_buf())),
    )
    .await
    .map_err(|_| "session/load timed out".to_string())?
    .map(|_| ())
    .map_err(|e| format!("session/load failed: {e}"))
}

fn session_dir(session: &acp::SessionId, cwd: &Path) -> PathBuf {
    fuigo_shell::session::persistence::session_dir(&Info {
        id: session.clone(),
        cwd: cwd.to_string_lossy().into_owned(),
    })
}

/// The compaction summary names the session's own transcript directory; replace the id so twins compare equal.
fn without_session_id(messages: &Value, id: &acp::SessionId) -> Value {
    serde_json::from_str(&messages.to_string().replace(id.0.as_ref(), "<session>")).expect("json")
}

fn texts(messages: &Value) -> Vec<String> {
    messages
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| format!("{}: {}", m["role"].as_str().unwrap_or("?"), m["content"].as_str().unwrap_or_default()))
        .collect()
}

/// Two turns, so the pre-compaction history differs visibly from the compacted one.
async fn script(conn: &acp::ClientSideConnection, mock: &MockInferenceServer, session: &acp::SessionId) {
    turn(conn, mock, session, "Remember the colour teal.", "Noted teal.").await;
    turn(conn, mock, session, "Remember the number 42.", "Noted 42.").await;
}

#[test]
fn a_crash_between_the_compaction_commit_and_the_history_rewrite_resumes_compacted() {
    run_agent_test(|cwd, mock| async move {
        let a = connect("p111-live").await;
        let live = new_session(&a, &cwd).await;
        script(&a, &mock, &live).await;
        compact(&a, &live).await;
        let expected = without_session_id(
            &turn_messages(&a, &mock, &live, "What do you remember?", "Teal and 42.").await,
            &live,
        );
        assert!(
            expected.to_string().contains(SUMMARY_PREAMBLE),
            "fixture: the live compacted request carries the summary: {:?}",
            texts(&expected)
        );

        let crashed = new_session(&a, &cwd).await;
        script(&a, &mock, &crashed).await;
        let chat_path = session_dir(&crashed, &cwd).join("chat_history.jsonl");
        let before_compaction = std::fs::read(&chat_path).expect("chat history before the compaction");
        compact(&a, &crashed).await;
        // The rewrite is a separate message that follows the acknowledged commit, so it can land after `compact`
        // returns (that gap is the crash window). Wait for it, so that putting the old bytes back below is exactly
        // what a crash in the window leaves, and nothing still in flight overwrites them.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::fs::read(&chat_path).expect("chat history after the compaction") == before_compaction {
            assert!(std::time::Instant::now() < deadline, "fixture: the compaction never rewrote chat_history.jsonl");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        drop(a);
        // What a crash between the activation marker and the chat_history.jsonl rewrite leaves on disk.
        std::fs::write(&chat_path, &before_compaction).expect("restore the pre-compaction chat history");

        let b = connect("p111-resume").await;
        load(&b, &crashed, &cwd).await.expect("the crashed session loads");
        let got = without_session_id(
            &turn_messages(&b, &mock, &crashed, "What do you remember?", "Teal and 42.").await,
            &crashed,
        );
        drop(b);
        assert_eq!(
            got,
            expected,
            "after the crash the model must resume with the compacted history\n  expected: {:?}\n  resumed:  {:?}",
            texts(&expected),
            texts(&got)
        );

        // The recovered history was persisted: a later load keeps it and the turn made on top of it.
        let c = connect("p111-resume-again").await;
        load(&c, &crashed, &cwd).await.expect("the session loads again");
        let again = turn_messages(&c, &mock, &crashed, "Anything else?", "No.").await;
        let again_text = again.to_string();
        assert!(
            again_text.contains(SUMMARY_PREAMBLE) && again_text.contains("Teal and 42."),
            "the second resume keeps the compacted history and the turn after it: {:?}",
            texts(&again)
        );
    });
}
