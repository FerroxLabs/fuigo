//! P96: a session whose `chat_history.jsonl` has a torn line is repaired when it is loaded.
//!
//! The loader skips a line it cannot parse. When that line was the assistant message carrying a tool call, the tool
//! result that followed it is left without its call, and strict providers answer every later request with HTTP 400.
//! Before P96 the only way out was to run `fuigo/session/repair` by hand.
//!
//! Every scenario builds a real session (one executed `read_file` turn), damages its files once the building agent is
//! gone, loads it cold in a fresh agent (the real `session/load` -> `load_light` path) and sends one more prompt.
//!
//! One `#[test]` per binary (the harness env is process-global); every scenario is checked and the failures are
//! reported together, so a red run names each broken case.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{
    RPC_TIMEOUT, connect_client, ext_method, new_session, prompt_turn, run_agent_test,
    spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_shell::session::info::Info;
use fuigo_test_support::sse::chat_completion_script_exact;
use fuigo_test_support::{
    InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, ScriptedResponse, SseEvent,
};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

const MODEL: &str = "test-model";
const CALL_ID: &str = "call-p96";
const BACKUP_NAME: &str = "chat_history.jsonl.pre-repair";
/// The raw file the lenient reader keeps the first time it skips a line.
const CORRUPT_NAME: &str = "chat_history.jsonl.corrupt";

/// Records the raw params of every ext notification the agent sends (the user-visible notes travel on these).
#[derive(Clone, Default)]
struct Recorder(Rc<RefCell<Vec<String>>>);

#[async_trait::async_trait(?Send)]
impl acp::Client for Recorder {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        Ok(acp::RequestPermissionResponse::new(
            acp_harness::allow_once(&args),
        ))
    }
    async fn session_notification(&self, _: acp::SessionNotification) -> acp::Result<()> {
        Ok(())
    }
    async fn ext_notification(&self, args: acp::ExtNotification) -> acp::Result<()> {
        self.0.borrow_mut().push(args.params.get().to_owned());
        Ok(())
    }
}

impl Recorder {
    /// The updates of kind `kind` (the wire name of the variant) sent for `session`.
    fn updates_of_kind(&self, session: &acp::SessionId, kind: &str) -> Vec<Value> {
        self.0
            .borrow()
            .iter()
            .filter_map(|raw| serde_json::from_str::<Value>(raw).ok())
            .filter(|v| v["sessionId"] == session.0.as_ref())
            .map(|v| v["update"].clone())
            .filter(|update| update["sessionUpdate"] == kind)
            .collect()
    }

    /// The repair notices sent for `session`, as their text. They travel as `history_repaired` updates.
    fn repair_notices(&self, session: &acp::SessionId) -> Vec<String> {
        self.updates_of_kind(session, "history_repaired")
            .iter()
            .filter_map(|update| update["message"].as_str().map(str::to_owned))
            .collect()
    }
}

fn agent_config() -> fuigo_shell::agent::config::Config {
    let mut config = fuigo_shell::agent::config::Config::default();
    // A local title keeps title generation off the mock, so no auxiliary request races the scripted turns.
    config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
    config
}

async fn connect(label: &str, recorder: Recorder) -> acp::ClientSideConnection {
    connect_client(
        recorder,
        label,
        spawn_agent_local_with_config(agent_config()),
    )
    .await
    .0
}

/// One streamed assistant message that says something and then calls `read_file` on `path` as [`CALL_ID`].
fn text_then_read_file(path: &Path) -> ScriptedResponse {
    let chunk = |delta: Value, finish: Value| {
        SseEvent::data(
            json!({
                "id": "chatcmpl-p96", "object": "chat.completion.chunk", "created": 0, "model": MODEL,
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            })
            .to_string(),
        )
    };
    let arguments = json!({ "target_file": path }).to_string();
    ScriptedResponse::sse(vec![
        chunk(
            json!({"role": "assistant", "content": "Reading the file. "}),
            Value::Null,
        ),
        chunk(
            json!({"tool_calls": [{
                "index": 0, "id": CALL_ID, "type": "function",
                "function": {"name": "read_file", "arguments": arguments},
            }]}),
            Value::Null,
        ),
        SseEvent::data(
            json!({
                "id": "chatcmpl-p96", "object": "chat.completion.chunk", "created": 0, "model": MODEL,
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

/// A new session with one turn in which the model reads `file` (a real, executed `read_file` call) and answers.
async fn session_with_tool_turn(
    conn: &acp::ClientSideConnection,
    mock: &MockInferenceServer,
    cwd: &Path,
    file: &Path,
) -> acp::SessionId {
    let session = new_session(conn, cwd).await;
    let steps = [
        mock.expect_response("p96-call", foreground(), text_then_read_file(file)),
        mock.expect_response(
            "p96-answer",
            foreground(),
            ScriptedResponse::sse(chat_completion_script_exact("FINAL-ANSWER-P96", MODEL)),
        ),
    ];
    prompt_turn(conn, &session, "Please read the file.").await;
    for step in &steps {
        step.assert_satisfied();
    }
    session
}

/// Sends the next prompt and returns the `messages` of that turn's first foreground request.
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
    mock.requests()[before..]
        .iter()
        .filter(|r| r.path == "/v1/chat/completions" && r.header("x-fuigo-turn-idx").is_some())
        .filter_map(|r| r.body.clone())
        .next()
        .expect("the next turn made a foreground request")["messages"]
        .clone()
}

async fn load(
    conn: &acp::ClientSideConnection,
    session: &acp::SessionId,
    cwd: &Path,
) -> Result<(), String> {
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.load_session(acp::LoadSessionRequest::new(
            session.clone(),
            cwd.to_path_buf(),
        )),
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

fn chat_path(session: &acp::SessionId, cwd: &Path) -> PathBuf {
    session_dir(session, cwd).join("chat_history.jsonl")
}

/// Ends `session` in the agent that built it and waits until its actor is gone.
///
/// A dropped connection leaves the agent's session actors running in this process, each holding the session's shared
/// turn-owner lock, and load never repairs a session a live actor holds. The crashed process whose torn write this
/// test stands for holds nothing, so the builder's actors have to be gone before the cold load.
async fn close_and_release(conn: &acp::ClientSideConnection, session: &acp::SessionId, cwd: &Path) {
    ext_method(conn, "fuigo/session/close", json!({ "sessionId": session.to_string() })).await;
    let lock_path = session_dir(session, cwd).join("turn_owner.lock");
    let deadline = tokio::time::Instant::now() + RPC_TIMEOUT;
    loop {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open turn owner lock");
        if fs2::FileExt::try_lock_exclusive(&file).is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the builder's actor for {} never released the session",
            session.0
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// Index of the first line of `bytes` that contains `needle`, with the lines themselves (newlines stripped).
fn line_with<'a>(bytes: &'a [u8], needle: &str) -> (usize, Vec<&'a [u8]>) {
    let lines: Vec<&[u8]> = bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    let at = lines
        .iter()
        .position(|l| String::from_utf8_lossy(l).contains(needle))
        .unwrap_or_else(|| panic!("fixture: no chat history line contains {needle}"));
    (at, lines)
}

/// Cuts the first line containing `needle` in half, as a crash in the middle of an append leaves it.
/// Returns the damaged file's bytes.
fn tear_line(path: &Path, needle: &str) -> Vec<u8> {
    let bytes = std::fs::read(path).expect("read chat history");
    let (at, lines) = line_with(&bytes, needle);
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        out.extend_from_slice(if i == at {
            &line[..line.len() / 2]
        } else {
            line
        });
        out.push(b'\n');
    }
    std::fs::write(path, &out).expect("write torn chat history");
    out
}

/// Removes the first line containing `needle` altogether. Every remaining line still parses.
fn drop_line(path: &Path, needle: &str) -> Vec<u8> {
    let bytes = std::fs::read(path).expect("read chat history");
    let (at, lines) = line_with(&bytes, needle);
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if i != at {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
    }
    std::fs::write(path, &out).expect("write chat history");
    out
}

/// Tool results in `messages` that do not follow an assistant message declaring their call.
fn orphaned_results(messages: &Value) -> Vec<String> {
    let mut declared: Vec<String> = Vec::new();
    let mut orphans = Vec::new();
    for message in messages.as_array().into_iter().flatten() {
        for call in message["tool_calls"].as_array().into_iter().flatten() {
            declared.push(call["id"].as_str().unwrap_or_default().to_owned());
        }
        if let Some(id) = message["tool_call_id"].as_str()
            && !declared.iter().any(|d| d == id)
        {
            orphans.push(id.to_owned());
        }
    }
    orphans
}

/// Like `ext_method`, but an error response is returned instead of failing the test.
async fn try_ext_method(
    conn: &acp::ClientSideConnection,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    let raw = serde_json::value::RawValue::from_string(params.to_string()).expect("serialize ext params");
    match tokio::time::timeout(
        RPC_TIMEOUT,
        conn.ext_method(acp::ExtRequest::new(method, std::sync::Arc::from(raw))),
    )
    .await
    {
        Err(_) => Err(format!("{method} timed out")),
        Ok(Err(e)) => Err(format!("{e} {}", e.data.as_ref().map(|d| d.to_string()).unwrap_or_default())),
        Ok(Ok(resp)) => serde_json::from_str(resp.0.get()).map_err(|e| format!("{method}: bad response: {e}")),
    }
}

/// How often `needle` occurs in the text of the user messages of `messages`.
fn user_messages_with(messages: &Value, needle: &str) -> usize {
    messages
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["role"] == "user" && m["content"].to_string().contains(needle))
        .count()
}

/// Scenario 3b, on a session loaded while its file cannot be backed up (so it must not be rewritten): a rewind and a
/// compaction would rewrite the file. They must be refused with an error that says why, and leave the history in
/// memory, the transcript (`updates.jsonl`) and `chat_history.jsonl` as they were, so all three still agree.
async fn destructive_rewrites_are_refused(
    conn: &acp::ClientSideConnection,
    mock: &MockInferenceServer,
    session: &acp::SessionId,
    cwd: &Path,
    original: &[u8],
) -> Vec<String> {
    let mut failures = Vec::new();
    let updates_path = session_dir(session, cwd).join("updates.jsonl");
    let transcript_before = std::fs::read(&updates_path).expect("read updates.jsonl");
    let chat_before = std::fs::read(chat_path(session, cwd)).expect("read chat history");
    // The turn before this one asked "What did you do so far?"; a rewind to prompt 1 would drop it.
    let rewind = try_ext_method(
        conn,
        "fuigo/rewind/execute",
        json!({ "sessionId": session.to_string(), "targetPromptIndex": 1, "force": true, "mode": "conversation_only" }),
    )
    .await;
    match &rewind {
        Ok(response) if response["success"] == false => {
            let error = response["error"].as_str().unwrap_or_default();
            if !error.contains("could not be backed up") {
                failures.push(format!("backup failed: the refused rewind does not say why: {response}"));
            }
        }
        other => failures.push(format!("backup failed: a rewind was not refused: {other:?}")),
    }
    let requests_before = mock.requests().len();
    let compact = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        try_ext_method(conn, "fuigo/compact_conversation", json!({ "sessionId": session.to_string() })),
    )
    .await
    .unwrap_or_else(|_| Err("fuigo/compact_conversation did not answer".into()));
    match &compact {
        Err(error) if error.contains("could not be backed up") => {}
        other => failures.push(format!("backup failed: a compaction was not refused with the reason: {other:?}")),
    }
    let made = mock.requests().len() - requests_before;
    if made != 0 {
        failures.push(format!("backup failed: the refused compaction still sent {made} request(s)"));
    }
    let transcript_after = std::fs::read(&updates_path).expect("read updates.jsonl");
    if String::from_utf8_lossy(&transcript_after).contains("rewind_marker") {
        failures.push("backup failed: the transcript records a rewind the file does not have".into());
    }
    let added = String::from_utf8_lossy(&transcript_after[transcript_before.len().min(transcript_after.len())..])
        .into_owned();
    if added.contains("compaction") {
        failures.push(format!("backup failed: the transcript records a compaction the file does not have: {added}"));
    }
    if std::fs::read(chat_path(session, cwd)).expect("read chat history") != chat_before {
        failures.push("backup failed: a refused rewind or compaction changed chat_history.jsonl".into());
    }
    // Memory: the next request still carries the turn the rewind would have dropped (it asks the same question again).
    let messages = next_turn_messages(conn, mock, session).await;
    let asked = user_messages_with(&messages, "What did you do so far?");
    if asked != 2 {
        failures.push(format!(
            "backup failed: after the refused rewind the next request carries {asked} copies of the earlier question, not 2"
        ));
    }
    let after_turn = std::fs::read(chat_path(session, cwd)).expect("read chat history");
    if !after_turn.starts_with(original) {
        failures.push("backup failed: the original bytes are gone from disk after the refused rewrites".into());
    }
    failures
}

#[test]
fn a_torn_chat_history_line_is_repaired_at_load() {
    run_agent_test(|cwd, mock| async move {
        let file = cwd.join("notes.txt");
        std::fs::write(&file, "contents of the file\n").expect("fixture file");
        let mut failures: Vec<String> = Vec::new();

        // ── Agent A: build the sessions. ──
        let a = connect("p96-build", Recorder::default()).await;
        let torn = session_with_tool_turn(&a, &mock, &cwd, &file).await;
        let clean = session_with_tool_turn(&a, &mock, &cwd, &file).await;
        let no_backup = session_with_tool_turn(&a, &mock, &cwd, &file).await;
        let harmless_tear = session_with_tool_turn(&a, &mock, &cwd, &file).await;
        let orphan_no_tear = session_with_tool_turn(&a, &mock, &cwd, &file).await;
        let live = session_with_tool_turn(&a, &mock, &cwd, &file).await;
        let broken_earlier = session_with_tool_turn(&a, &mock, &cwd, &file).await;
        let corrupt_copy_only = session_with_tool_turn(&a, &mock, &cwd, &file).await;
        for session in [
            &torn,
            &clean,
            &no_backup,
            &harmless_tear,
            &orphan_no_tear,
            &live,
            &broken_earlier,
            &corrupt_copy_only,
        ] {
            close_and_release(&a, session, &cwd).await;
        }
        drop(a);

        // Fixture check: the assistant line with the call comes first, its result on a later line.
        {
            let bytes = std::fs::read(chat_path(&torn, &cwd)).expect("read chat history");
            let (call_at, lines) = line_with(&bytes, CALL_ID);
            assert!(
                String::from_utf8_lossy(lines[call_at]).contains("read_file"),
                "fixture: the first line naming {CALL_ID} is the assistant's tool call"
            );
            assert!(
                lines[call_at + 1..]
                    .iter()
                    .any(|l| String::from_utf8_lossy(l).contains(CALL_ID)),
                "fixture: the tool result for {CALL_ID} is on a later line"
            );
        }

        // Torn assistant line: its tool result is left without a call.
        let torn_original = tear_line(&chat_path(&torn, &cwd), CALL_ID);
        // The same damage, with the backup made impossible.
        let no_backup_original = tear_line(&chat_path(&no_backup, &cwd), CALL_ID);
        // A directory where the backup belongs: nothing can be published there, and a directory is not a backup.
        std::fs::create_dir(session_dir(&no_backup, &cwd).join(BACKUP_NAME)).expect("block the backup");
        // A torn line whose loss leaves the history valid (the final answer): nothing to repair.
        tear_line(&chat_path(&harmless_tear, &cwd), "FINAL-ANSWER-P96");
        // An orphaned result with no unreadable line: the loader skipped nothing, so load must not touch it.
        drop_line(&chat_path(&orphan_no_tear, &cwd), CALL_ID);
        let clean_original = std::fs::read(chat_path(&clean, &cwd)).expect("read chat history");
        // A session that broke before this release: its first load after the tear kept the raw file as `.corrupt`
        // and rewrote the history without the torn line. Every line parses now; the orphaned result is still there.
        let broken_earlier_intact = std::fs::read(chat_path(&broken_earlier, &cwd)).expect("read chat history");
        let broken_earlier_corrupt = tear_line(&chat_path(&broken_earlier, &cwd), CALL_ID);
        std::fs::write(session_dir(&broken_earlier, &cwd).join(CORRUPT_NAME), &broken_earlier_corrupt)
            .expect("write the .corrupt copy");
        // The same line is then gone altogether (dropped from the intact file, so the right line is removed).
        std::fs::write(chat_path(&broken_earlier, &cwd), &broken_earlier_intact).expect("restore chat history");
        let broken_earlier_original = drop_line(&chat_path(&broken_earlier, &cwd), CALL_ID);
        // A `.corrupt` copy next to a history that needs no repair.
        let corrupt_copy_only_original =
            std::fs::read(chat_path(&corrupt_copy_only, &cwd)).expect("read chat history");
        std::fs::write(session_dir(&corrupt_copy_only, &cwd).join(CORRUPT_NAME), b"{\"torn\n")
            .expect("write the .corrupt copy");

        // ── Agent B: cold loads. ──
        let recorder = Recorder::default();
        let b = connect("p96-resume", recorder.clone()).await;

        // 1. Torn line: the next request is well formed, the backup holds the original bytes, the user is told.
        match load(&b, &torn, &cwd).await {
            Ok(()) => {
                let messages = next_turn_messages(&b, &mock, &torn).await;
                let orphans = orphaned_results(&messages);
                if !orphans.is_empty() {
                    failures.push(format!(
                        "torn line: the next request carries tool results without a call: {orphans:?}"
                    ));
                }
                let backup = session_dir(&torn, &cwd).join(BACKUP_NAME);
                match std::fs::read(&backup) {
                    Ok(bytes) if bytes == torn_original => {}
                    Ok(bytes) => failures.push(format!(
                        "torn line: the backup holds {} bytes that are not the original {} bytes",
                        bytes.len(),
                        torn_original.len()
                    )),
                    Err(e) => failures.push(format!("torn line: no backup at {}: {e}", backup.display())),
                }
                let on_disk = std::fs::read(chat_path(&torn, &cwd)).expect("read chat history");
                let unparseable = on_disk
                    .split(|b| *b == b'\n')
                    .filter(|l| !l.is_empty())
                    .filter(|l| serde_json::from_slice::<Value>(l).is_err())
                    .count();
                if unparseable != 0 {
                    failures.push(format!("torn line: {unparseable} unreadable line(s) are still on disk"));
                }
                let notices = recorder.repair_notices(&torn);
                match notices.as_slice() {
                    [notice] => {
                        if !notice.starts_with("Session history repaired: removed 1 tool result") {
                            failures.push(format!("torn line: the notice does not name the repair first: {notice}"));
                        }
                        for want in ["1 unreadable line", "1 tool result", &backup.display().to_string()] {
                            if !notice.contains(want) {
                                failures.push(format!("torn line: the notice lacks {want:?}: {notice}"));
                            }
                        }
                    }
                    other => failures.push(format!("torn line: expected one repair notice, got {other:?}")),
                }
                // The note has its own kind; it must not arrive labelled as an image drop.
                let as_image_drop = recorder.updates_of_kind(&torn, "image_dropped");
                if !as_image_drop.is_empty() {
                    failures.push(format!("torn line: an image-drop note was sent: {as_image_drop:?}"));
                }
                let transcript =
                    std::fs::read_to_string(session_dir(&torn, &cwd).join("updates.jsonl")).unwrap_or_default();
                if !transcript.contains(BACKUP_NAME) {
                    failures.push("torn line: the notice is not in the saved transcript".into());
                }
            }
            Err(e) => failures.push(format!("torn line: {e}")),
        }

        // 2. Clean session: load leaves the file byte-identical, makes no backup, says nothing.
        match load(&b, &clean, &cwd).await {
            Ok(()) => {
                let after = std::fs::read(chat_path(&clean, &cwd)).expect("read chat history");
                if after != clean_original {
                    failures.push(format!(
                        "clean session: load rewrote chat_history.jsonl ({} bytes before, {} after)",
                        clean_original.len(),
                        after.len()
                    ));
                }
                let messages = next_turn_messages(&b, &mock, &clean).await;
                if !orphaned_results(&messages).is_empty() {
                    failures.push("clean session (fixture): its own request carries an orphaned result".into());
                }
                if session_dir(&clean, &cwd).join(BACKUP_NAME).exists() {
                    failures.push("clean session: a backup was created".into());
                }
                if !recorder.repair_notices(&clean).is_empty() {
                    failures.push(format!("clean session: a repair notice was sent: {:?}", recorder.repair_notices(&clean)));
                }
            }
            Err(e) => failures.push(format!("clean session: {e}")),
        }

        // 3. Backup impossible: the file on disk is not rewritten; the request is still well formed (repaired in memory).
        match load(&b, &no_backup, &cwd).await {
            Ok(()) => {
                let after_load = std::fs::read(chat_path(&no_backup, &cwd)).expect("read chat history");
                if after_load != no_backup_original {
                    failures.push(format!(
                        "backup failed: load rewrote chat_history.jsonl without a backup ({} bytes before, {} after)",
                        no_backup_original.len(),
                        after_load.len()
                    ));
                }
                let messages = next_turn_messages(&b, &mock, &no_backup).await;
                let orphans = orphaned_results(&messages);
                if !orphans.is_empty() {
                    failures.push(format!(
                        "backup failed: the next request carries tool results without a call: {orphans:?}"
                    ));
                }
                // The turn appends its own messages; the original bytes must still be there, in place.
                let after_turn = std::fs::read(chat_path(&no_backup, &cwd)).expect("read chat history");
                if !after_turn.starts_with(&no_backup_original) {
                    failures.push("backup failed: the original bytes are gone from disk after the next turn".into());
                }
                if !session_dir(&no_backup, &cwd).join(BACKUP_NAME).is_dir() {
                    failures.push("backup failed (fixture): the directory blocking the backup is gone".into());
                }
                let notices = recorder.repair_notices(&no_backup);
                if !notices.iter().any(|n| n.contains("could not be backed up")) {
                    failures.push(format!("backup failed: no notice says the backup failed: {notices:?}"));
                }
                // 3b. While the file cannot be rewritten, a rewind and a compaction are refused with a clear error
                //     and change nothing: not the history in memory, not the transcript, not the file.
                failures.extend(
                    destructive_rewrites_are_refused(&b, &mock, &no_backup, &cwd, &no_backup_original).await,
                );
            }
            Err(e) => failures.push(format!("backup failed: {e}")),
        }

        // 4. A torn line that orphans nothing: no repair, so no backup and no notice.
        match load(&b, &harmless_tear, &cwd).await {
            Ok(()) => {
                next_turn_messages(&b, &mock, &harmless_tear).await;
                if session_dir(&harmless_tear, &cwd).join(BACKUP_NAME).exists() {
                    failures.push("harmless tear: a repair backup was created although nothing needed repair".into());
                }
                if !recorder.repair_notices(&harmless_tear).is_empty() {
                    failures.push("harmless tear: a repair notice was sent although nothing was repaired".into());
                }
            }
            Err(e) => failures.push(format!("harmless tear: {e}")),
        }

        // 5. An orphan the loader did not cause (no skipped line): load does not repair it.
        match load(&b, &orphan_no_tear, &cwd).await {
            Ok(()) => {
                // The mock accepts the malformed request; the turn only lets any notice arrive before the checks.
                next_turn_messages(&b, &mock, &orphan_no_tear).await;
                if session_dir(&orphan_no_tear, &cwd).join(CORRUPT_NAME).exists() {
                    failures.push("orphan without a torn line (fixture): a .corrupt copy exists".into());
                }
                if session_dir(&orphan_no_tear, &cwd).join(BACKUP_NAME).exists() {
                    failures.push("orphan without a torn line: load made a repair backup".into());
                }
                if !recorder.repair_notices(&orphan_no_tear).is_empty() {
                    failures.push("orphan without a torn line: load sent a repair notice".into());
                }
            }
            Err(e) => failures.push(format!("orphan without a torn line: {e}")),
        }

        // 6. A session that is live in this agent: a second `session/load` (a reconnect) reads the file while the live
        //    actor owns it, and a line caught mid-append looks torn. That load must not repair or rewrite anything.
        match load(&b, &live, &cwd).await {
            Ok(()) => {
                // A full turn first: the actor writes its startup snapshot of the history asynchronously, and that
                // write landing after the tear below would undo the damage and blame the reconnect for it. A finished
                // turn is behind that snapshot in the same persistence queue.
                next_turn_messages(&b, &mock, &live).await;
                let torn_under_live = tear_line(&chat_path(&live, &cwd), CALL_ID);
                match load(&b, &live, &cwd).await {
                    Ok(()) => {
                        let after = std::fs::read(chat_path(&live, &cwd)).expect("read chat history");
                        if after != torn_under_live {
                            failures.push("live session: a reconnect rewrote the live session's chat_history.jsonl".into());
                        }
                        if session_dir(&live, &cwd).join(BACKUP_NAME).exists() {
                            failures.push("live session: a reconnect made a repair backup".into());
                        }
                        // The live actor's own history is intact, so its next request is well formed.
                        let messages = next_turn_messages(&b, &mock, &live).await;
                        if !orphaned_results(&messages).is_empty() {
                            failures.push("live session: the live history lost a tool call".into());
                        }
                        if !recorder.repair_notices(&live).is_empty() {
                            failures.push("live session: a repair notice was sent".into());
                        }
                    }
                    Err(e) => failures.push(format!("live session, reconnect: {e}")),
                }
            }
            Err(e) => failures.push(format!("live session: {e}")),
        }

        // 7. Broken before this release (a `.corrupt` copy, an orphaned result, no unreadable line): repaired at load.
        match load(&b, &broken_earlier, &cwd).await {
            Ok(()) => {
                let messages = next_turn_messages(&b, &mock, &broken_earlier).await;
                let orphans = orphaned_results(&messages);
                if !orphans.is_empty() {
                    failures.push(format!(
                        "broken earlier: the next request carries tool results without a call: {orphans:?}"
                    ));
                }
                let backup = session_dir(&broken_earlier, &cwd).join(BACKUP_NAME);
                match std::fs::read(&backup) {
                    Ok(bytes) if bytes == broken_earlier_original => {}
                    Ok(_) => failures.push("broken earlier: the backup is not the file as found".into()),
                    Err(e) => failures.push(format!("broken earlier: no backup at {}: {e}", backup.display())),
                }
                let corrupt = session_dir(&broken_earlier, &cwd).join(CORRUPT_NAME);
                if std::fs::read(&corrupt).ok().as_deref() != Some(broken_earlier_corrupt.as_slice()) {
                    failures.push("broken earlier: the .corrupt copy was changed or removed".into());
                }
                let notices = recorder.repair_notices(&broken_earlier);
                match notices.as_slice() {
                    [notice] => {
                        for want in [
                            "Session history repaired: removed 1 tool result",
                            &corrupt.display().to_string(),
                            &backup.display().to_string(),
                        ] {
                            if !notice.contains(want) {
                                failures.push(format!("broken earlier: the notice lacks {want:?}: {notice}"));
                            }
                        }
                    }
                    other => failures.push(format!("broken earlier: expected one repair notice, got {other:?}")),
                }

                // 7b. A second cold load after the repair does nothing more.
                close_and_release(&b, &broken_earlier, &cwd).await;
                match load(&b, &broken_earlier, &cwd).await {
                    Ok(()) => {
                        let messages = next_turn_messages(&b, &mock, &broken_earlier).await;
                        if !orphaned_results(&messages).is_empty() {
                            failures.push("broken earlier, second load: the request carries an orphaned result".into());
                        }
                        // The transcript keeps the note as the record of what was generated, and `session/load` does
                        // not replay it (P123): the user saw it when the repair was made, so the client has received
                        // it exactly once across the two loads. A new repair would save a second note, with different
                        // words (the backup is already there).
                        let saved = std::fs::read_to_string(session_dir(&broken_earlier, &cwd).join("updates.jsonl"))
                            .unwrap_or_default();
                        let saved_notes = saved.lines().filter(|l| l.contains("\"history_repaired\"")).count();
                        if saved_notes != 1 {
                            failures.push(format!(
                                "broken earlier, second load: the transcript holds {saved_notes} repair notes, expected 1"
                            ));
                        }
                        let notices = recorder.repair_notices(&broken_earlier);
                        if notices.len() != 1 {
                            failures.push(format!(
                                "broken earlier, second load: the client received {} repair notes across the two loads, expected 1 (the second load must not replay it): {notices:?}",
                                notices.len()
                            ));
                        }
                        let on_disk = std::fs::read(chat_path(&broken_earlier, &cwd)).expect("read chat history");
                        if String::from_utf8_lossy(&on_disk).matches(CALL_ID).count() != 0 {
                            failures.push("broken earlier, second load: the orphaned result is back on disk".into());
                        }
                        if std::fs::read(&backup).ok().as_deref() != Some(broken_earlier_original.as_slice()) {
                            failures.push("broken earlier, second load: the backup changed".into());
                        }
                        if std::fs::read(&corrupt).ok().as_deref() != Some(broken_earlier_corrupt.as_slice()) {
                            failures.push("broken earlier, second load: the .corrupt copy changed".into());
                        }
                    }
                    Err(e) => failures.push(format!("broken earlier, second load: {e}")),
                }
            }
            Err(e) => failures.push(format!("broken earlier: {e}")),
        }

        // 8. A `.corrupt` copy next to a history that needs no repair: file byte-identical, no backup, no notice.
        match load(&b, &corrupt_copy_only, &cwd).await {
            Ok(()) => {
                let after = std::fs::read(chat_path(&corrupt_copy_only, &cwd)).expect("read chat history");
                if after != corrupt_copy_only_original {
                    failures.push(format!(
                        ".corrupt copy only: load rewrote chat_history.jsonl ({} bytes before, {} after)",
                        corrupt_copy_only_original.len(),
                        after.len()
                    ));
                }
                next_turn_messages(&b, &mock, &corrupt_copy_only).await;
                if session_dir(&corrupt_copy_only, &cwd).join(BACKUP_NAME).exists() {
                    failures.push(".corrupt copy only: a repair backup was created".into());
                }
                if !recorder.repair_notices(&corrupt_copy_only).is_empty() {
                    failures.push(".corrupt copy only: a repair notice was sent".into());
                }
                let corrupt = std::fs::read(session_dir(&corrupt_copy_only, &cwd).join(CORRUPT_NAME)).ok();
                if corrupt.as_deref() != Some(b"{\"torn\n".as_slice()) {
                    failures.push(".corrupt copy only: the .corrupt copy was changed or removed".into());
                }
            }
            Err(e) => failures.push(format!(".corrupt copy only: {e}")),
        }
        drop(b);

        assert!(
            failures.is_empty(),
            "{} load-repair scenario(s) failed:\n\n{}",
            failures.len(),
            failures.join("\n\n")
        );
    });
}
