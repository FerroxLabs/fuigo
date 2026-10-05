//! P88: resuming a session hands the model exactly the history it had before the resume, tool calls and results included.
//!
//! Before P88, every `session/load` of a session compacted by 1.0.10 or later replaced `chat_history.jsonl` (the model's
//! own record) with a text-only rebuild from `updates.jsonl`. That rebuild skips tool calls and tool results and merges
//! the assistant text on either side of them, so the resumed model lost the record of the commands it ran and the files
//! it edited. A missing or unreadable checkpoint file also made the whole load fail.
//!
//! Every scenario runs one twin session per case. The *live* twin continues in the agent that built it. The *resumed*
//! twin runs the identical script, then is loaded cold by a fresh agent (the real `session/load` -> `load_light` path,
//! from the files on disk). Both then get the same next prompt, and the `messages` of the first foreground request of
//! that turn must be identical: what the model sees after a resume is what it would have seen had the process lived.
//!
//! One `#[test]` per binary (the harness env is process-global); every scenario is checked and the failures are
//! reported together, so a red run names each broken case.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{
    AutoApproveClient, RPC_TIMEOUT, connect_client, ext_method, new_session, prompt_turn,
    run_agent_test, spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_shell::session::info::Info;
use fuigo_test_support::sse::chat_completion_script_exact;
use fuigo_test_support::{
    InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, ScriptedResponse, SseEvent,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const MODEL: &str = "test-model";

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

/// One streamed assistant message that says `text` and then calls `read_file` on `path` as `call_id`.
fn text_then_read_file(text: &str, call_id: &str, path: &Path) -> ScriptedResponse {
    let chunk = |delta: Value, finish: Value| {
        SseEvent::data(
            json!({
                "id": "chatcmpl-p88", "object": "chat.completion.chunk", "created": 0, "model": MODEL,
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            })
            .to_string(),
        )
    };
    let arguments = json!({ "target_file": path }).to_string();
    ScriptedResponse::sse(vec![
        chunk(json!({"role": "assistant", "content": text}), Value::Null),
        chunk(
            json!({"tool_calls": [{
                "index": 0, "id": call_id, "type": "function",
                "function": {"name": "read_file", "arguments": arguments},
            }]}),
            Value::Null,
        ),
        SseEvent::data(
            json!({
                "id": "chatcmpl-p88", "object": "chat.completion.chunk", "created": 0, "model": MODEL,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
            })
            .to_string(),
        ),
        SseEvent::data("[DONE]"),
    ])
}

fn foreground() -> InferenceRequestMatcher {
    InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions)
}

/// Bodies of the foreground (agent-turn) chat requests logged at or after `from`.
fn foreground_bodies(mock: &MockInferenceServer, from: usize) -> Vec<Value> {
    mock.requests()[from..]
        .iter()
        .filter(|r| r.path == "/v1/chat/completions" && r.header("x-fuigo-turn-idx").is_some())
        .filter_map(|r| r.body.clone())
        .collect()
}

/// A turn in which the model says something, reads `file` (a real `read_file` call, executed), then answers.
/// The text on both sides of the call is what the pre-P88 rebuild merged into one message.
async fn tool_turn(
    conn: &acp::ClientSideConnection,
    mock: &MockInferenceServer,
    session: &acp::SessionId,
    label: &str,
    file: &Path,
) {
    let steps = [
        mock.expect_response(
            format!("{label}-call"),
            foreground(),
            text_then_read_file(&format!("Reading {label}. "), &format!("call-{label}"), file),
        ),
        mock.expect_response(
            format!("{label}-answer"),
            foreground(),
            ScriptedResponse::sse(chat_completion_script_exact(&format!("Read {label}."), MODEL)),
        ),
    ];
    prompt_turn(conn, session, &format!("Please read {label}.")).await;
    for step in &steps {
        step.assert_satisfied();
    }
}

async fn compact(conn: &acp::ClientSideConnection, session: &acp::SessionId) {
    ext_method(
        conn,
        "fuigo/compact_conversation",
        json!({"session_id": session.to_string(), "user_context": "Keep the file names."}),
    )
    .await;
}

/// The shared script: one tool turn, then `compactions` rounds of (compact, tool turn).
async fn run_script(
    conn: &acp::ClientSideConnection,
    mock: &MockInferenceServer,
    session: &acp::SessionId,
    files: &[PathBuf],
    compactions: usize,
) {
    tool_turn(conn, mock, session, "file-0", &files[0]).await;
    for (round, file) in files.iter().enumerate().skip(1).take(compactions) {
        compact(conn, session).await;
        tool_turn(conn, mock, session, &format!("file-{round}"), file).await;
    }
}

/// Sends the shared next prompt and returns the `messages` of that turn's first foreground request.
async fn next_turn_messages(
    conn: &acp::ClientSideConnection,
    mock: &MockInferenceServer,
    session: &acp::SessionId,
) -> Value {
    let step = mock.expect_response(
        "next-answer",
        foreground(),
        ScriptedResponse::sse(chat_completion_script_exact("Next done.", MODEL)),
    );
    let before = mock.requests().len();
    prompt_turn(conn, session, "What did you do so far?").await;
    step.assert_satisfied();
    foreground_bodies(mock, before)
        .into_iter()
        .next()
        .expect("the next turn made a foreground request")["messages"]
        .clone()
}

/// `session/load` on a fresh agent. `Err` carries the load error (pre-P88, a damaged checkpoint failed here).
async fn load(
    conn: &acp::ClientSideConnection,
    session: &acp::SessionId,
    cwd: &Path,
) -> Result<(), String> {
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

fn checkpoint_files(session: &acp::SessionId, cwd: &Path) -> Vec<PathBuf> {
    let dir = session_dir(session, cwd).join("compaction_checkpoints");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        // A session that never compacted has no checkpoint directory.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => panic!("{}: {e}", dir.display()),
    };
    let mut files: Vec<PathBuf> = entries
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    files.sort();
    files
}

/// Ids of every tool call and tool result in a request's `messages`.
fn tool_ids(messages: &Value) -> Vec<String> {
    let mut ids = Vec::new();
    for message in messages.as_array().into_iter().flatten() {
        for call in message["tool_calls"].as_array().into_iter().flatten() {
            ids.push(format!("call:{}", call["id"].as_str().unwrap_or_default()));
        }
        if let Some(id) = message["tool_call_id"].as_str() {
            ids.push(format!("result:{id}"));
        }
    }
    ids
}

/// The compaction summary names the session's own transcript directory, so twins differ in that id and nothing else.
/// Replace `id` with a placeholder so the comparison is about history, not about which twin it is.
fn without_session_id(messages: &Value, id: &acp::SessionId) -> Value {
    serde_json::from_str(&messages.to_string().replace(id.0.as_ref(), "<session>")).expect("json")
}

const SUMMARY_PREAMBLE: &str = "This session is being continued from a previous conversation";

/// `role: first 60 chars` per message, for failure reports.
fn roles(messages: &Value) -> String {
    messages
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| {
            let content = m["content"].as_str().unwrap_or_default();
            let end = content.char_indices().nth(60).map_or(content.len(), |(i, _)| i);
            format!("[{}{} {:?}]", m["role"].as_str().unwrap_or("?"), if m["tool_calls"].is_array() { "+tools" } else { "" }, &content[..end])
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `None` when equal; otherwise a short account of the first difference.
fn first_difference(expected: &Value, actual: &Value) -> Option<String> {
    if expected == actual {
        return None;
    }
    let (e, a) = (
        expected.as_array().cloned().unwrap_or_default(),
        actual.as_array().cloned().unwrap_or_default(),
    );
    let at = (0..e.len().max(a.len()))
        .find(|&i| e.get(i) != a.get(i))
        .unwrap_or(0);
    Some(format!(
        "{} expected vs {} resumed messages; first difference at [{at}]\n  expected: {}\n  resumed:  {}\n  expected tool ids: {:?}\n  resumed tool ids:  {:?}",
        e.len(),
        a.len(),
        e.get(at).map(Value::to_string).unwrap_or_else(|| "<none>".into()),
        a.get(at).map(Value::to_string).unwrap_or_else(|| "<none>".into()),
        tool_ids(expected),
        tool_ids(actual),
    ))
}

#[test]
fn a_resumed_session_sends_the_model_the_history_it_had() {
    run_agent_test(|cwd, mock| async move {
        let files: Vec<PathBuf> = (0..3)
            .map(|i| {
                let path = cwd.join(format!("file-{i}.txt"));
                std::fs::write(&path, format!("contents of file {i}: {}\n", "observation; ".repeat(40)))
                    .expect("fixture file");
                path
            })
            .collect();
        let mut failures: Vec<String> = Vec::new();

        // ── Agent A: build every twin, and record the live twins' next request (the expected history). ──
        let a = connect("p88-live").await;
        let mut expected = Vec::new();
        let mut resumed = Vec::new();
        for compactions in 0..=2 {
            let live = new_session(&a, &cwd).await;
            run_script(&a, &mock, &live, &files, compactions).await;
            let twin = new_session(&a, &cwd).await;
            run_script(&a, &mock, &twin, &files, compactions).await;
            expected.push(without_session_id(&next_turn_messages(&a, &mock, &live).await, &live));
            resumed.push(twin);
        }
        let names = ["never compacted", "compacted once", "compacted twice"];
        // Fixture check: each live request carries its script's last tool call (made after any compaction) and its result.
        for (round, (name, messages)) in names.iter().zip(&expected).enumerate() {
            let ids = tool_ids(messages);
            for id in [format!("call:call-file-{round}"), format!("result:call-file-{round}")] {
                assert!(ids.contains(&id), "fixture ({name}): live request lacks {id}: {ids:?}");
            }
        }
        // Compacted once, then: forked; checkpoint file deleted; checkpoint file truncated; already resumed by 1.0.17;
        // chat_history.jsonl lost (rebuilt from updates.jsonl at load).
        let mut once_twins = Vec::new();
        for _ in 0..5 {
            let twin = new_session(&a, &cwd).await;
            run_script(&a, &mock, &twin, &files, 1).await;
            once_twins.push(twin);
        }
        // Compacted twice, then forked at its first prompt (before both compactions).
        let point_fork_source = new_session(&a, &cwd).await;
        run_script(&a, &mock, &point_fork_source, &files, 2).await;
        drop(a);
        let [fork_source, missing_checkpoint, corrupt_checkpoint, resumed_by_1017, chat_missing] =
            <[acp::SessionId; 5]>::try_from(once_twins).expect("five twins");

        // Every session loaded below is byte-for-byte what 1.0.17 writes: same files, and the checkpoint's prefix under
        // 1.0.17's key (this version writes `resolved_prefix_len`; 1.0.10-1.0.19 wrote `inherited_prefix_len`).
        let loaded: Vec<&acp::SessionId> = resumed
            .iter()
            .chain([&fork_source, &missing_checkpoint, &corrupt_checkpoint, &resumed_by_1017, &chat_missing, &point_fork_source])
            .collect();
        for session in loaded {
            for path in checkpoint_files(session, &cwd) {
                let mut file: Value =
                    serde_json::from_slice(&std::fs::read(&path).expect("read checkpoint")).expect("checkpoint json");
                let object = file.as_object_mut().expect("checkpoint object");
                // (A pre-P88 build already writes the old key; the test runs there too, to show the defect.)
                if let Some(prefix) = object.remove("resolved_prefix_len") {
                    object.insert("inherited_prefix_len".into(), prefix);
                }
                assert!(object.contains_key("inherited_prefix_len"), "fixture: checkpoint carries its prefix: {}", path.display());
                std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).expect("write checkpoint");
            }
        }
        std::fs::remove_file(session_dir(&chat_missing, &cwd).join("chat_history.jsonl")).expect("remove chat history");

        // L-1 fixtures: the session's only checkpoint file is gone, or cut short mid-write.
        assert_eq!(checkpoint_files(&missing_checkpoint, &cwd).len(), 1, "fixture: one compaction, one checkpoint");
        assert_eq!(checkpoint_files(&corrupt_checkpoint, &cwd).len(), 1, "fixture: one compaction, one checkpoint");
        for path in checkpoint_files(&missing_checkpoint, &cwd) {
            std::fs::remove_file(path).expect("remove checkpoint");
        }
        for path in checkpoint_files(&corrupt_checkpoint, &cwd) {
            let bytes = std::fs::read(&path).expect("read checkpoint");
            std::fs::write(&path, &bytes[..bytes.len() / 2]).expect("truncate checkpoint");
        }
        // A session 1.0.17 already resumed once: its load rewrote chat_history.jsonl with the text-only rebuild.
        {
            let dir = session_dir(&resumed_by_1017, &cwd);
            let rebuilt = fuigo_shell::session::helpers::replay::replay_to_prompt(
                &dir.join("updates.jsonl"),
                &dir,
                usize::MAX,
            )
            .expect("1.0.17 rebuild");
            let mut lines = String::new();
            for item in &rebuilt.conversation {
                lines.push_str(&serde_json::to_string(item).expect("item"));
                lines.push('\n');
            }
            std::fs::write(dir.join("chat_history.jsonl"), lines).expect("1.0.17 chat_history");
        }

        // ── Agent B: cold loads through `load_light`. ──
        let b = connect("p88-resume").await;
        for ((name, twin), want) in names.iter().zip(&resumed).zip(&expected) {
            match load(&b, twin, &cwd).await {
                Ok(()) => {
                    let got = without_session_id(&next_turn_messages(&b, &mock, twin).await, twin);
                    if let Some(diff) = first_difference(want, &got) {
                        failures.push(format!("{name}: {diff}"));
                    }
                }
                Err(e) => failures.push(format!("{name}: {e}")),
            }
        }
        let fork = ext_method(
            &b,
            "fuigo/session/fork",
            json!({
                "sourceSessionId": fork_source.to_string(),
                "sourceCwd": cwd.to_string_lossy(),
                "newCwd": cwd.to_string_lossy(),
            }),
        )
        .await;
        let fork = acp::SessionId::new(
            fork["newSessionId"].as_str().expect("fork returns its session id").to_string(),
        );
        // A fork copies its source's chat history verbatim, so its summary names the source's transcript directory.
        for (name, twin, named) in [
            ("compacted once, then forked", &fork, &fork_source),
            ("compacted once, checkpoint file missing", &missing_checkpoint, &missing_checkpoint),
            ("compacted once, checkpoint file truncated", &corrupt_checkpoint, &corrupt_checkpoint),
        ] {
            match load(&b, twin, &cwd).await {
                Ok(()) => {
                    let got = without_session_id(&next_turn_messages(&b, &mock, twin).await, named);
                    if let Some(diff) = first_difference(&expected[1], &got) {
                        failures.push(format!("{name}: {diff}"));
                    }
                }
                Err(e) => failures.push(format!("{name}: {e}")),
            }
        }
        // chat_history.jsonl lost: load rebuilds it from updates.jsonl. That rebuild reconstructs tool calls from the
        // transcript (not byte-identical to what the model saw), but it must start from the checkpoint's projection:
        // the compaction summary and the post-compaction tool call and result must all be there.
        match load(&b, &chat_missing, &cwd).await {
            Ok(()) => {
                let got = without_session_id(&next_turn_messages(&b, &mock, &chat_missing).await, &chat_missing);
                if let Some(diff) = first_difference(&expected[1], &got) {
                    eprintln!("chat_history.jsonl lost (informational, not asserted): {diff}");
                }
                let summary = expected[1]
                    .as_array()
                    .and_then(|m| m.iter().find(|m| m["content"].as_str().is_some_and(|c| c.starts_with(SUMMARY_PREAMBLE))))
                    .expect("fixture: the live compacted request carries the summary")
                    .clone();
                if !got.as_array().is_some_and(|m| m.contains(&summary)) {
                    failures.push("compacted once, chat_history.jsonl lost: the rebuilt history lacks the compaction summary".into());
                }
                if tool_ids(&got) != tool_ids(&expected[1]) {
                    failures.push(format!(
                        "compacted once, chat_history.jsonl lost: tool ids {:?}, expected {:?}",
                        tool_ids(&got),
                        tool_ids(&expected[1])
                    ));
                }
            }
            Err(e) => failures.push(format!("compacted once, chat_history.jsonl lost: {e}")),
        }
        // A point-in-time fork before a compaction must not inherit that compaction's summary of later turns.
        let point_fork = ext_method(
            &b,
            "fuigo/session/fork",
            json!({
                "sourceSessionId": point_fork_source.to_string(),
                "sourceCwd": cwd.to_string_lossy(),
                "newCwd": cwd.to_string_lossy(),
                "targetPromptIndex": 0,
            }),
        )
        .await;
        let point_fork = acp::SessionId::new(
            point_fork["newSessionId"].as_str().expect("fork returns its session id").to_string(),
        );
        match load(&b, &point_fork, &cwd).await {
            Ok(()) => {
                let got = next_turn_messages(&b, &mock, &point_fork).await;
                let text = got.to_string();
                eprintln!("point-in-time fork messages: {}", roles(&got));
                for later in ["file-1", "file-2", "call-file-1", "call-file-2"] {
                    if text.contains(later) {
                        failures.push(format!("compacted twice, forked at prompt 0: history mentions {later}, from after the fork point: {}", roles(&got)));
                    }
                }
                if !text.contains(SUMMARY_PREAMBLE) {
                    failures.push(format!("compacted twice, forked at prompt 0: the first compaction's summary is missing: {}", roles(&got)));
                }
            }
            Err(e) => failures.push(format!("compacted twice, forked at prompt 0: {e}")),
        }
        // The 1.0.17-resumed session: what that rebuild dropped is gone, but nothing done after it may be lost again.
        let mut resumed_1017_ok = false;
        match load(&b, &resumed_by_1017, &cwd).await {
            Ok(()) => {
                tool_turn(&b, &mock, &resumed_by_1017, "after-1017", &files[2]).await;
                resumed_1017_ok = true;
            }
            Err(e) => failures.push(format!("resumed by 1.0.17: {e}")),
        }
        drop(b);

        // ── Agent C: load the 1.0.17-resumed session again. ──
        if resumed_1017_ok {
            let c = connect("p88-resume-again").await;
            match load(&c, &resumed_by_1017, &cwd).await {
                Ok(()) => {
                    let got = next_turn_messages(&c, &mock, &resumed_by_1017).await;
                    let ids = tool_ids(&got);
                    for id in ["call:call-after-1017", "result:call-after-1017"] {
                        if !ids.iter().any(|i| i == id) {
                            failures.push(format!(
                                "resumed by 1.0.17, then resumed again: {id} (made after the 1.0.17 resume) was dropped; tool ids sent: {ids:?}"
                            ));
                        }
                    }
                }
                Err(e) => failures.push(format!("resumed by 1.0.17, then resumed again: {e}")),
            }
        }

        assert!(
            failures.is_empty(),
            "{} resume scenario(s) changed what the model sees:\n\n{}",
            failures.len(),
            failures.join("\n\n")
        );
    });
}
