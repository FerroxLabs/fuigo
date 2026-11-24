//! 1.0.47 S2 (SL-06), design §7 tests 5 and 7 through the real agent (Fable code review #4): a recorded secret reaches
//! a tool result, a subagent, an MCP server (its stderr and a large result), a forced compaction and a fork. Afterwards
//! no file under `$FUIGO_HOME` or `$HOME` may hold it, except the verbatim stores (`/rewind` copies, permission grants).
//! Then the session is resumed cold (test 5): every stored line still parses, tool calls and results still pair, and a
//! second turn completes. Synthetic values only.
//!
//! One `#[test]` per binary (the harness env is process-global).
#![cfg(unix)]
#[allow(dead_code)]
mod acp_harness;

use std::path::{Path, PathBuf};

use acp_harness::{
    AutoApproveClient, RPC_TIMEOUT, close_and_release, connect_client, ext_method, new_session,
    prompt_turn, run_agent_test, spawn_agent_local_with_config,
};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::sse::chat_completion_script_exact;
use fuigo_test_support::{
    InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, ScriptedResponse, SseEvent,
};
use serde_json::{Value, json};

const MODEL: &str = "test-model";
// Split so the literal is not a token-shaped string in the source.
const TOKEN: &str = concat!("dpl_", "live_C4n4ryAcp7Rq2Vx9");

/// A minimal MCP stdio server: prints the token on stderr at start and on every call, lists one tool, and answers a
/// call with a large result that repeats the token. The token comes in two halves, so neither the script nor
/// `config.toml` holds it.
const MCP_SERVER: &str = r#"import json, sys
token = sys.argv[1] + sys.argv[2]
sys.stderr.write("canary mcp starting, DEPLOY_TOKEN=" + token + "\n"); sys.stderr.flush()
for line in sys.stdin:
    try:
        m = json.loads(line)
    except Exception:
        continue
    if "id" not in m:
        continue
    method = m.get("method")
    if method == "initialize":
        r = {"protocolVersion": m.get("params", {}).get("protocolVersion", "2024-11-05"),
             "capabilities": {"tools": {}}, "serverInfo": {"name": "canary", "version": "0"}}
    elif method == "tools/list":
        r = {"tools": [{"name": "fetch_report", "description": "Fetch the deploy report.",
                        "inputSchema": {"type": "object", "properties": {}}}]}
    elif method == "tools/call":
        sys.stderr.write("tools/call, DEPLOY_TOKEN=" + token + "\n"); sys.stderr.flush()
        with open(sys.argv[3], "a") as f:
            f.write("called\n")
        r = {"content": [{"type": "text", "text": ("report line with " + token + "\n") * 6000}]}
    else:
        r = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}) + "\n")
    sys.stdout.flush()
"#;

fn agent_config() -> fuigo_shell::agent::config::Config {
    let mut config = fuigo_shell::agent::config::Config::default();
    config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
    config
}

async fn connect(label: &str) -> acp::ClientSideConnection {
    connect_client(
        AutoApproveClient,
        label,
        spawn_agent_local_with_config(agent_config()),
    )
    .await
    .0
}

fn foreground() -> InferenceRequestMatcher {
    InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions)
}

/// One streamed assistant message that calls `name` with `arguments` as `call_id`.
fn tool_call(call_id: &str, name: &str, arguments: Value) -> ScriptedResponse {
    let chunk = |delta: Value, finish: Value| {
        SseEvent::data(
            json!({
                "id": "chatcmpl-s2", "object": "chat.completion.chunk", "created": 0, "model": MODEL,
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            })
            .to_string(),
        )
    };
    ScriptedResponse::sse(vec![
        chunk(
            json!({"role": "assistant", "content": null, "tool_calls": [{
                "index": 0, "id": call_id, "type": "function",
                "function": {"name": name, "arguments": arguments.to_string()},
            }]}),
            Value::Null,
        ),
        SseEvent::data(
            json!({
                "id": "chatcmpl-s2", "object": "chat.completion.chunk", "created": 0, "model": MODEL,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
            })
            .to_string(),
        ),
        SseEvent::data("[DONE]"),
    ])
}

/// A turn whose first foreground response calls `name`; everything after it (the answer, a subagent's own requests)
/// gets the mock's default response, which also holds the token.
async fn tool_turn(
    conn: &acp::ClientSideConnection,
    mock: &MockInferenceServer,
    session: &acp::SessionId,
    label: &str,
    name: &str,
    arguments: Value,
) {
    let step = mock.expect_response(
        format!("{label}-call"),
        foreground(),
        tool_call(&format!("call-{label}"), name, arguments),
    );
    prompt_turn(
        conn,
        session,
        &format!("Step {label}; the token is {TOKEN}."),
    )
    .await;
    step.assert_satisfied();
}

/// Every regular file under `dir`, recursively (symlinks are not followed). An entry that cannot be read fails the
/// test: a sweep that skips evidence proves nothing (Astra code review Medium 5).
fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => panic!("read_dir {}: {e}", dir.display()),
    };
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("entry in {}: {e}", dir.display()));
        let kind = entry
            .file_type()
            .unwrap_or_else(|e| panic!("file_type {}: {e}", entry.path().display()));
        if kind.is_dir() {
            files_under(&entry.path(), out);
        } else if kind.is_file() {
            out.push(entry.path());
        }
    }
}

/// The verbatim stores (design §2.4): `/rewind` copies and permission grants keep their exact bytes.
fn is_verbatim_store(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    name.starts_with("rewind_points.jsonl")
        || name.starts_with("permission")
        || name.contains("grants")
}

/// Ids of every tool call and tool result in a request's `messages`, as (calls, results).
fn tool_ids(messages: &Value) -> (Vec<String>, Vec<String>) {
    let (mut calls, mut results) = (Vec::new(), Vec::new());
    for message in messages.as_array().into_iter().flatten() {
        for call in message["tool_calls"].as_array().into_iter().flatten() {
            calls.push(call["id"].as_str().unwrap_or_default().to_owned());
        }
        if let Some(id) = message["tool_call_id"].as_str() {
            results.push(id.to_owned());
        }
    }
    calls.sort();
    results.sort();
    (calls, results)
}

fn session_dir(session: &acp::SessionId, cwd: &Path) -> PathBuf {
    fuigo_shell::session::persistence::session_dir(&fuigo_shell::session::info::Info {
        id: session.clone(),
        cwd: cwd.to_string_lossy().into_owned(),
    })
}

/// Non-empty lines of `path`; each must be JSON and none the withheld marker (no skipped line on load).
fn json_lines(path: &Path) -> usize {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut count = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        serde_json::from_str::<Value>(line)
            .unwrap_or_else(|e| panic!("{}: a line does not parse ({e}): {line}", path.display()));
        assert_ne!(
            line.trim(),
            fuigo_secrets::at_rest::WITHHELD_MARKER,
            "{}: a record was withheld",
            path.display()
        );
        count += 1;
    }
    count
}

#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there"
)]
#[test]
fn a_recorded_secret_is_never_written_at_rest_through_the_agent() {
    run_agent_test(|cwd, mock| async move {
        // What `capture_env` records from a secret-named variable at process start.
        fuigo_secrets::at_rest::record(TOKEN);
        let fuigo_home = PathBuf::from(std::env::var_os("FUIGO_HOME").expect("FUIGO_HOME"));
        let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
        let script = cwd.join("canary_mcp.py");
        let called = cwd.join("mcp_called");
        std::fs::write(&script, MCP_SERVER).unwrap();
        let (head, tail) = TOKEN.split_at(8);
        std::fs::write(
            fuigo_home.join("config.toml"),
            format!(
                "[mcp_servers.canary]\ncommand = \"/usr/bin/python3\"\nargs = [\"{}\", \"{head}\", \"{tail}\", \"{}\"]\nstartup_timeout_sec = 20\n",
                script.display(),
                called.display()
            ),
        )
        .unwrap();
        let env_file = cwd.join("deploy.env");
        std::fs::write(&env_file, format!("DEPLOY_TOKEN={TOKEN}\n")).unwrap();
        // Compaction summaries, subagent turns and answers all get this, so each of them holds the token.
        // Long enough that a compaction summary is not rejected as degenerate.
        mock.set_response(format!(
            "Noted: the deploy token is {TOKEN}. {}",
            "The session read the deploy settings and checked them step by step. ".repeat(40)
        ));

        let conn = connect("s2-canary").await;
        let session = new_session(&conn, &cwd).await;
        tool_turn(
            &conn,
            &mock,
            &session,
            "read",
            "read_file",
            json!({"target_file": env_file}),
        )
        .await;
        tool_turn(
            &conn,
            &mock,
            &session,
            "subagent",
            "spawn_subagent",
            json!({
                "description": "check the token",
                "prompt": format!("Repeat the deploy token {TOKEN}."),
                "subagent_type": "general-purpose",
            }),
        )
        .await;
        tool_turn(
            &conn,
            &mock,
            &session,
            "mcp",
            "use_tool",
            json!({"tool_name": "canary__fetch_report", "tool_input": {}}),
        )
        .await;
        ext_method(
            &conn,
            "fuigo/compact_conversation",
            json!({"session_id": session.to_string(), "user_context": "Keep the token."}),
        )
        .await;
        // Forked from a closed source, as a later window would (a live source's post-compaction writes race the copy's
        // coherence check, which then refuses it as retryable).
        close_and_release(&conn, &[&session]).await;
        drop(conn);
        let conn = connect("s2-canary-fork").await;
        let fork = ext_method(
            &conn,
            "fuigo/session/fork",
            json!({
                "sourceSessionId": session.to_string(),
                "sourceCwd": cwd.to_string_lossy(),
                "newCwd": cwd.to_string_lossy(),
            }),
        )
        .await;
        let fork = acp::SessionId::new(
            fork["newSessionId"]
                .as_str()
                .expect("fork returns its session id")
                .to_string(),
        );
        close_and_release(&conn, &[&fork]).await;
        drop(conn);

        // The paths the sweep must cover all ran.
        assert!(
            std::fs::read_to_string(&called).is_ok_and(|t| t.contains("called")),
            "fixture: the MCP tool was called"
        );
        let dir = session_dir(&session, &cwd);
        assert!(
            session_dir(&fork, &cwd)
                .join("chat_history.jsonl")
                .is_file(),
            "fixture: the fork was written"
        );
        assert!(
            dir.join("compaction_checkpoints").is_dir(),
            "fixture: the compaction ran"
        );

        let mut files = Vec::new();
        files_under(&fuigo_home, &mut files);
        files_under(&home, &mut files);
        files.sort();
        files.dedup();
        // Protect the edge (Astra code review Medium 5): inside the live session the model saw the raw tool result.
        assert!(
            mock.requests().iter().any(|r| r
                .body
                .as_ref()
                .is_some_and(|b| b.to_string().contains(&format!("DEPLOY_TOKEN={TOKEN}")))),
            "the sampler received the raw read_file result"
        );
        // Astra code review item 6: the MCP server printed the value on stderr at start and on the call; its log holds
        // those lines with the placeholder, so the stderr path ran through the layer.
        let stderr_logs: Vec<&PathBuf> = files
            .iter()
            .filter(|f| {
                f.to_string_lossy().contains("logs/mcp/")
                    && f.to_string_lossy().ends_with(".stderr.log")
            })
            .collect();
        assert!(
            !stderr_logs.is_empty(),
            "fixture: the MCP server's stderr was logged"
        );
        let stderr_text: String = stderr_logs
            .iter()
            .map(|f| std::fs::read_to_string(f).unwrap())
            .collect();
        assert!(
            stderr_text.contains("canary mcp starting, DEPLOY_TOKEN=<redacted>")
                && stderr_text.contains("tools/call, DEPLOY_TOKEN=<redacted>"),
            "{stderr_text}"
        );
        let leaks: Vec<String> = files
            .iter()
            .filter(|f| !is_verbatim_store(f))
            .filter(|f| {
                let bytes =
                    std::fs::read(f).unwrap_or_else(|e| panic!("read {}: {e}", f.display()));
                bytes.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes())
            })
            .map(|f| f.display().to_string())
            .collect();
        assert!(
            leaks.is_empty(),
            "the canary was written at rest in:\n{}",
            leaks.join("\n")
        );

        // Test 5: a cold resume of the scrubbed session.
        let chat = dir.join("chat_history.jsonl");
        let items = json_lines(&chat);
        json_lines(&dir.join("updates.jsonl"));
        let resumed = connect("s2-canary-resume").await;
        tokio::time::timeout(
            RPC_TIMEOUT,
            resumed.load_session(acp::LoadSessionRequest::new(session.clone(), cwd.clone())),
        )
        .await
        .expect("session/load timed out")
        .expect("session/load");
        assert_eq!(json_lines(&chat), items, "the load kept every stored item");
        assert!(
            !dir.join("chat_history.jsonl.corrupt").exists(),
            "no line was quarantined"
        );
        let step = mock.expect_response(
            "resumed-answer",
            foreground(),
            ScriptedResponse::sse(chat_completion_script_exact("Resumed.", MODEL)),
        );
        let before = mock.requests().len();
        prompt_turn(&resumed, &session, "And now?").await;
        step.assert_satisfied();
        let request = mock.requests()[before..]
            .iter()
            .filter(|r| r.path == "/v1/chat/completions" && r.header("x-fuigo-turn-idx").is_some())
            .find_map(|r| r.body.clone())
            .expect("the resumed turn made a foreground request");
        let (calls, results) = tool_ids(&request["messages"]);
        assert_eq!(calls, results, "every tool call still has its result");
        close_and_release(&resumed, &[&session]).await;
    });
}
