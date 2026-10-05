//! P146 (K19/P140 follow-up): a rewind whose `rewind_points.jsonl` rewrite cannot run is not reported as done.
//!
//! Every forced rewind ends by rewriting `rewind_points.jsonl` (the saved file versions of the prompts it undoes), under
//! the rewrite lock another Fuigo process may hold (P140). Before P146 the rewrite was sent off without a reply: with
//! the lock held past the wait, `fuigo/rewind/execute` answered `success: true` while the rewrite was dropped (only a
//! log warning), so the file kept the undone prompts. Now the rewind takes that lock before it changes anything; a
//! holder that keeps it refuses the rewind with nothing changed, and the same rewind works once the lock is free.
//!
//! Real path: an agent over ACP, a real session on disk, the lock held by another open file (as another process would).
//! One `#[test]` per binary (the harness env is process-global).
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{
    AutoApproveClient, RPC_TIMEOUT, connect_client, new_session, prompt_turn, run_agent_test,
    spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_shell::session::info::Info;
use fuigo_test_support::sse::chat_completion_script_exact;
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher, ScriptedResponse};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const MODEL: &str = "test-model";

fn agent_config() -> fuigo_shell::agent::config::Config {
    let mut config = fuigo_shell::agent::config::Config::default();
    // A local title keeps title generation off the mock, so no auxiliary request races the scripted turns.
    config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
    config
}

fn session_dir(session: &acp::SessionId, cwd: &Path) -> PathBuf {
    fuigo_shell::session::persistence::session_dir(&Info {
        id: session.clone(),
        cwd: cwd.to_string_lossy().into_owned(),
    })
}

/// The `prompt_index` of every row of `rewind_points.jsonl`, in file order.
fn point_indices(path: &Path) -> Vec<u64> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|row| row["prompt_index"].as_u64())
        .collect()
}

/// `fuigo/rewind/execute`; an error response is returned as `Err` instead of failing the test.
async fn rewind(conn: &acp::ClientSideConnection, session: &acp::SessionId, target: usize) -> Result<Value, String> {
    let params = json!({ "sessionId": session.to_string(), "targetPromptIndex": target, "force": true, "mode": "all" });
    let raw = serde_json::value::RawValue::from_string(params.to_string()).expect("serialize ext params");
    match tokio::time::timeout(
        RPC_TIMEOUT,
        conn.ext_method(acp::ExtRequest::new("fuigo/rewind/execute", std::sync::Arc::from(raw))),
    )
    .await
    {
        Err(_) => Err("fuigo/rewind/execute timed out".into()),
        Ok(Err(e)) => Err(format!("{e}")),
        Ok(Ok(resp)) => serde_json::from_str(resp.0.get()).map_err(|e| format!("bad response: {e}")),
    }
}

#[test]
fn a_rewind_whose_rewind_points_cannot_be_rewritten_is_refused_with_nothing_changed() {
    run_agent_test(|cwd, mock| async move {
        let conn = connect_client(AutoApproveClient, "p146-lock", spawn_agent_local_with_config(agent_config()))
            .await
            .0;
        let session = new_session(&conn, &cwd).await;
        for i in 0..3 {
            let step = mock.expect_response(
                format!("answer-{i}"),
                InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
                ScriptedResponse::sse(chat_completion_script_exact(&format!("Answer {i}."), MODEL)),
            );
            prompt_turn(&conn, &session, &format!("Prompt {i}.")).await;
            step.assert_satisfied();
        }
        let dir = session_dir(&session, &cwd);
        let points_path = dir.join("rewind_points.jsonl");
        let chat_path = dir.join("chat_history.jsonl");
        assert_eq!(point_indices(&points_path), vec![0, 1, 2], "fixture: one rewind point per prompt");

        // Another Fuigo process is stuck inside its rewrite: it holds the rewrite lock past the rewind's wait (10 s).
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join("rewind_points.jsonl.rewrite.lock"))
            .expect("open the rewrite lock");
        fs2::FileExt::try_lock_exclusive(&holder).expect("hold the rewrite lock");
        let points_before = std::fs::read(&points_path).expect("read rewind points");
        let chat_before = std::fs::read(&chat_path).expect("read chat history");

        let refused = rewind(&conn, &session, 1).await.expect("rewind/execute answers");
        let points_after_refusal = std::fs::read(&points_path).expect("read rewind points");
        let chat_after_refusal = std::fs::read(&chat_path).expect("read chat history");
        fs2::FileExt::unlock(&holder).expect("release the rewrite lock");
        drop(holder);

        let mut failures = Vec::new();
        if refused["success"] != false {
            failures.push(format!("the rewind was reported done although rewind_points.jsonl could not be rewritten: {refused}"));
        }
        let error = refused["error"].as_str().unwrap_or_default();
        if !(error.contains("Nothing was changed") && error.contains("rewind_points.jsonl")) {
            failures.push(format!("the refusal does not say what happened: {refused}"));
        }
        if points_after_refusal != points_before {
            failures.push("the refused rewind changed rewind_points.jsonl".into());
        }
        if chat_after_refusal != chat_before {
            failures.push("the refused rewind changed chat_history.jsonl".into());
        }

        // The rewrite lock is free but the append lock stays held (another process stuck inside an append): the
        // rewrite could not run, so the rewind is refused up front with nothing changed, and it says so.
        let appender = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join("rewind_points.jsonl.lock"))
            .expect("open the append lock");
        fs2::FileExt::try_lock_exclusive(&appender).expect("hold the append lock");
        let late = rewind(&conn, &session, 1).await.expect("rewind/execute answers");
        let points_after_late = std::fs::read(&points_path).expect("read rewind points");
        let chat_after_late = std::fs::read(&chat_path).expect("read chat history");
        fs2::FileExt::unlock(&appender).expect("release the append lock");
        drop(appender);
        let error = late["error"].as_str().unwrap_or_default();
        if late["success"] != false || !error.contains("Nothing was changed") {
            failures.push(format!("a rewind whose rewrite could not run was not refused: {late}"));
        }
        if points_after_late != points_before || chat_after_late != chat_before {
            failures.push("a rewind whose rewrite could not run changed rewind_points.jsonl or chat_history.jsonl".into());
        }

        // The locks are free again: the same rewind goes through, and its rewrite has landed when it answers.
        let retried = rewind(&conn, &session, 1).await.expect("rewind/execute answers");
        if retried["success"] != true {
            failures.push(format!("the retried rewind failed: {retried}"));
        }
        let left = point_indices(&points_path);
        if left != vec![0] {
            failures.push(format!("after the retried rewind rewind_points.jsonl holds prompts {left:?}, expected [0]"));
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    });
}
