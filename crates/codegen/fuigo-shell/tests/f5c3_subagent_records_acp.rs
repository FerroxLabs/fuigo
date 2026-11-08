//! F5-C3 (design F5 §5.5, Fable M3; §6.1): a subagent's records in its parent's folder (`subagents/<id>/meta.json`)
//! are written as the parent's own writer, carried on the spawn envelope, and that clone never outlives the run.
//! Closing the parent answers "closed" and frees its writer inside the close budget (8 s, 8.5 s worst case), with the
//! child still running and after it finished. A clone kept past the run would make close wait the whole budget and
//! leave the writer held.
#[allow(dead_code)]
mod acp_harness;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use acp_harness::{
    AutoApproveClient, RPC_TIMEOUT, connect_client, ext_method, new_session, run_agent_test,
    spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_session_writer::SessionWriter;
use fuigo_test_support::sse::{chat_completion_script_exact, chat_completions_reasoning_then_tool_call_events};
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, ScriptedResponse};
use serde_json::{Value, json};

const CLOSE_BUDGET: Duration = Duration::from_millis(8_500);

fn foreground() -> InferenceRequestMatcher {
    InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions)
}

fn spawn_child(task_id: &str) -> ScriptedResponse {
    let args = json!({
        "description": "f5c3 records child",
        "prompt": format!("Reply with the word done ({task_id})."),
        "subagent_type": "general-purpose",
        "task_id": task_id,
    });
    ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
        "spawn",
        &format!("call_{task_id}"),
        "spawn_subagent",
        &args.to_string(),
        "test-model",
    ))
}

fn text(reply: &str) -> ScriptedResponse {
    ScriptedResponse::sse(chat_completion_script_exact(reply, "test-model"))
}

fn config() -> fuigo_shell::agent::config::Config {
    let mut config = fuigo_shell::agent::config::Config::default();
    config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
    config
}

fn prompt(session: &acp::SessionId, text: &str) -> acp::PromptRequest {
    acp::PromptRequest::new(session.clone(), vec![acp::ContentBlock::Text(acp::TextContent::new(text))])
}

/// `<FUIGO_HOME>/.../<parent>/subagents/<task_id>/meta.json`, wherever the cwd encoding put the parent's folder.
fn find_meta(parent: &str, task_id: &str) -> Option<PathBuf> {
    fn walk(dir: &Path, parent: &str, task_id: &str, depth: usize) -> Option<PathBuf> {
        let candidate = dir.join(parent).join("subagents").join(task_id).join("meta.json");
        if candidate.is_file() {
            return Some(candidate);
        }
        if depth == 0 {
            return None;
        }
        std::fs::read_dir(dir).ok()?.flatten().filter(|e| e.path().is_dir()).find_map(|e| walk(&e.path(), parent, task_id, depth - 1))
    }
    walk(Path::new(&std::env::var_os("FUIGO_HOME")?), parent, task_id, 4)
}

fn tree() -> String {
    fn walk(dir: &Path, out: &mut String, depth: usize) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            out.push_str(&format!("{}\n", e.path().display()));
            if depth > 0 && e.path().is_dir() {
                walk(&e.path(), out, depth - 1);
            }
        }
    }
    let mut out = String::new();
    match std::env::var_os("FUIGO_HOME") {
        Some(home) => walk(&Path::new(&home).join("sessions"), &mut out, 4),
        None => out.push_str("FUIGO_HOME unset"),
    }
    out
}

/// Close `session` and say what it answered, how long it took, and whether its writer was free when it answered.
async fn close(conn: &acp::ClientSideConnection, session: &acp::SessionId) -> (Value, Duration, bool) {
    let started = Instant::now();
    let answer = ext_method(conn, "fuigo/session/close", json!({ "sessionId": session.to_string() })).await;
    (answer, started.elapsed(), SessionWriter::is_free(&session.0))
}

fn assert_closed_in_budget(case: &str, (answer, elapsed, free): &(Value, Duration, bool), mock: &MockInferenceServer) {
    assert!(answer.to_string().contains("closed"), "{case}: close answered {answer}\n{}", mock.request_log_summary());
    assert!(*elapsed < CLOSE_BUDGET, "{case}: close took {elapsed:?}, over the {CLOSE_BUDGET:?} budget");
    assert!(*free, "{case}: the parent's writer was still held when close answered ({elapsed:?}): a clone outlived the run");
}

/// One test (the harness's `FUIGO_HOME` is process-wide): the child finished, then the child still running.
#[test]
fn f5c3_closing_the_parent_frees_its_writer_after_and_while_a_child_runs() {
    run_agent_test(|cwd, mock| async move {
        let (conn, _) = connect_client(AutoApproveClient, "f5c3-records", spawn_agent_local_with_config(config())).await;

        // (1) After the child finished: the records landed through the parent's writer; close frees it in budget.
        let steps = [
            mock.expect_response("parent-spawns", foreground(), spawn_child("c3-done")),
            mock.expect_response("child-replies", foreground(), text("done")),
            mock.expect_response("parent-ends", foreground(), text("parent done")),
        ];
        let session = new_session(&conn, &cwd).await;
        tokio::time::timeout(RPC_TIMEOUT, conn.prompt(prompt(&session, "Spawn one child, then stop.")))
            .await
            .unwrap_or_else(|_| panic!("prompt timed out\n{}\n{}", mock.request_log_summary(), tree()))
            .unwrap_or_else(|e| panic!("prompt failed: {e:?}\n{}", mock.request_log_summary()));
        for step in &steps {
            step.assert_satisfied();
        }
        let meta = find_meta(&session.0, "c3-done")
            .unwrap_or_else(|| panic!("the child's meta.json is not in the parent's folder\n{}", tree()));
        let meta: Value = serde_json::from_slice(&std::fs::read(meta).unwrap()).unwrap();
        assert_eq!(meta["status"], "completed", "the completion record landed: {meta}");
        assert!(!SessionWriter::is_free(&session.0), "a live parent holds its writer");
        let closed = close(&conn, &session).await;
        assert_closed_in_budget("after finish", &closed, &mock);

        // (2) While the child runs: close cancels it, its records are written, and the clone is gone in budget.
        let _spawn = mock.expect_response("parent-spawns-2", foreground(), spawn_child("c3-running"));
        let mut child = mock.expect_response_blocked("child-held", foreground(), text("done"));
        let session = new_session(&conn, &cwd).await;
        let turn = tokio::time::timeout(RPC_TIMEOUT, conn.prompt(prompt(&session, "Spawn one child and wait for it.")));
        let closer = async {
            tokio::time::timeout(RPC_TIMEOUT, child.wait_blocked())
                .await
                .unwrap_or_else(|_| panic!("the child never started streaming\n{}", mock.request_log_summary()));
            assert!(find_meta(&session.0, "c3-running").is_some(), "the spawn record is not in the parent's folder\n{}", tree());
            let closed = close(&conn, &session).await;
            child.release();
            closed
        };
        let (turn, closed) = tokio::join!(turn, closer);
        let _ = turn.expect("the parent turn never ended after close");
        assert_closed_in_budget("while running", &closed, &mock);
    });
}
