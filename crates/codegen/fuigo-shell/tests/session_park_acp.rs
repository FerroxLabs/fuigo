//! P189: `_fuigo/session/park` / `_fuigo/session/unpark` against the REAL `fuigo` binary, driven the way
//! Murage drives it (`--permission-mode bypassPermissions --no-memory agent --no-leader -m <model> stdio`).
//! Only the inference endpoint is mocked (`MockInferenceServer`); every request it receives is timestamped.
//!
//! The scenario is Murage's measured one (`FUIGO-LIVE-EVIDENCE.md`): a turn starts background work and
//! ends; the background work finishes after `end_turn`. Without a park Fuigo then starts a NEW turn on its
//! own and calls the model again. With a park: no model call and no frame after the park
//! acknowledgement, the background command still completes, and unpark releases the held frames and runs
//! the deferred wake turn.
// Test, bench or example code: its prints reach a harness or a developer, never a user, so the
// workspace print deny (R077) is waived here.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::time::{Duration, SystemTime};

use fuigo_test_support::scripted::ScriptedResponse;
use fuigo_test_support::sse::chat_completions_reasoning_then_tool_call_events;
use fuigo_test_support::{
    AgentSpawnSpec, InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer,
    MockModelEntry, RawReply, RawStdioClient, TestSandbox, scaled,
};
use serde_json::{Value, json};

const RPC: Duration = Duration::from_secs(30);
const MODEL: &str = "p189-model";
const GLOBAL_BYPASS: &[&str] = &["--permission-mode", "bypassPermissions", "--no-memory"];
const AGENT_ARGS: &[&str] = &["--no-leader", "-m", MODEL];
/// The background command and the monitor both finish this long after they start.
const BG_SECS: u64 = 3;

fn refuse(_: &Value) -> Option<Value> {
    None
}

fn method_of(msg: &Value) -> Option<&str> {
    msg.get("method").and_then(Value::as_str)
}

struct Agent {
    client: RawStdioClient,
    server: MockInferenceServer,
    workspace: std::path::PathBuf,
    next_id: u32,
}

impl Agent {
    async fn spawn() -> Self {
        Self::spawn_with_models(vec![MockModelEntry::new(MODEL)]).await
    }

    async fn spawn_with_models(models: Vec<MockModelEntry>) -> Self {
        let server = MockInferenceServer::start_with_models(models)
            .await
            .expect("start mock server");
        server.set_response("done");
        let sandbox = TestSandbox::new();
        let workspace = sandbox.workspace().to_path_buf();
        let spec = AgentSpawnSpec {
            leading_args: GLOBAL_BYPASS,
            agent_args: AGENT_ARGS,
            ..AgentSpawnSpec::default()
        };
        let client = RawStdioClient::spawn_with_spec(&server, &workspace, sandbox, &spec).await;
        Self {
            client,
            server,
            workspace,
            next_id: 0,
        }
    }

    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = format!("p189-{}", self.next_id);
        self.client
            .request(&id, method, params, RPC, refuse)
            .await
    }

    async fn call_answering(
        &mut self,
        method: &str,
        params: Value,
        answer: impl FnMut(&Value) -> fuigo_test_support::acp_client::RawReply,
    ) -> Value {
        self.next_id += 1;
        let id = format!("p189-{}", self.next_id);
        self.client.request(&id, method, params, RPC, answer).await
    }

    async fn connect(&mut self) -> String {
        self.connect_with(json!({ "fs": { "readTextFile": false, "writeTextFile": false } }))
            .await
    }

    async fn connect_with(&mut self, client_capabilities: Value) -> String {
        let init = self
            .call(
                "initialize",
                json!({
                    "protocolVersion": 1,
                    "clientCapabilities": client_capabilities
                }),
            )
            .await;
        assert!(init.get("result").is_some(), "initialize failed: {init}");
        let auth = self
            .call("authenticate", json!({ "methodId": "fuigo.api_key" }))
            .await;
        assert_eq!(auth.get("result"), Some(&json!({})), "authenticate: {auth}");
        let ws = self.workspace.clone();
        let new = self
            .call("session/new", json!({ "cwd": ws, "mcpServers": [] }))
            .await;
        new["result"]["sessionId"]
            .as_str()
            .unwrap_or_else(|| panic!("session/new returned no sessionId: {new}"))
            .to_owned()
    }

    async fn prompt(&mut self, session_id: &str, text: &str) -> Value {
        self.call(
            "session/prompt",
            json!({ "sessionId": session_id, "prompt": [{ "type": "text", "text": text }] }),
        )
        .await
    }

    /// Chat-completions requests that reached the mock after `since`.
    fn chat_requests_after(&self, since: SystemTime) -> Vec<fuigo_test_support::mock_server::LogEntry> {
        self.server
            .requests()
            .into_iter()
            .filter(|r| r.path == "/v1/chat/completions" && r.at > since)
            .collect()
    }

    /// Wait (bounded) until a chat-completions request arrives after `since`; reads stdout meanwhile so
    /// the agent never blocks on a full pipe.
    async fn wait_chat_request_after(&mut self, since: SystemTime, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + scaled(within);
        while tokio::time::Instant::now() < deadline {
            if !self.chat_requests_after(since).is_empty() {
                return true;
            }
            let _ = self
                .client
                .wait_for_message("drain", Duration::from_millis(200), |_| false, refuse)
                .await;
        }
        !self.chat_requests_after(since).is_empty()
    }

    fn stderr(&self) -> String {
        self.client.stderr()
    }
}

fn script_tool_call(
    server: &MockInferenceServer,
    call_id: &str,
    tool: &str,
    args: Value,
) -> fuigo_test_support::InferenceExpectation {
    server.expect_response(
        call_id,
        InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
        ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
            "",
            call_id,
            tool,
            &args.to_string(),
            MODEL,
        )),
    )
}

/// Turn 1 starts a background command and a monitor that both finish `BG_SECS` later, then ends.
fn script_background_turn(server: &MockInferenceServer) -> Vec<fuigo_test_support::InferenceExpectation> {
    vec![
        script_tool_call(
            server,
            "call_bg",
            "run_terminal_command",
            json!({
                "command": format!("sleep {BG_SECS} && touch p189-bg-done"),
                "description": "p189 background command",
                "background": true,
            }),
        ),
        script_tool_call(
            server,
            "call_monitor",
            "monitor",
            json!({
                "command": format!("sleep {BG_SECS}; touch p189-monitor-done; echo P189-MONITOR-DONE"),
                "description": "p189 monitor",
            }),
        ),
    ]
}

async fn run_background_turn(agent: &mut Agent) -> String {
    let scripted = script_background_turn(&agent.server);
    let session = agent.connect().await;
    let reply = agent.prompt(&session, "start the background work").await;
    assert_eq!(
        reply["result"]["stopReason"], "end_turn",
        "turn 1 did not end: {reply}\n{}",
        agent.stderr()
    );
    for expectation in &scripted {
        expectation.assert_satisfied();
    }
    session
}

/// Today's behaviour, and the reason for P189: background work that finishes after `end_turn` makes Fuigo
/// start a new turn by itself and call the model again.
#[tokio::test(flavor = "current_thread")]
async fn background_work_finishing_after_end_turn_starts_a_self_started_model_call() {
    let mut agent = Agent::spawn().await;
    let _session = run_background_turn(&mut agent).await;
    let ended = SystemTime::now();
    assert!(
        agent
            .wait_chat_request_after(ended, Duration::from_secs(BG_SECS + 20))
            .await,
        "no self-started model call after the background work finished\n{}",
        agent.stderr()
    );
}

/// The P189 contract: park after `end_turn`; while parked the background command still finishes, but no
/// model call and no frame of any kind follows the park acknowledgement. Unpark writes the held frames
/// before its reply and then runs the deferred wake turn.
#[tokio::test(flavor = "current_thread")]
async fn park_holds_background_wakes_and_frames_until_unpark() {
    let mut agent = Agent::spawn().await;
    let session = run_background_turn(&mut agent).await;

    let park = agent
        .call("_fuigo/session/park", json!({ "sessionId": session }))
        .await;
    let parked_at = SystemTime::now();
    assert_eq!(
        park["result"]["parked"], true,
        "park failed: {park}\n{}",
        agent.stderr()
    );
    assert_eq!(park["result"]["mode"], "hold");
    let lines_at_ack = agent.client.transcript().len();

    // Quiet while parked: the background command and the monitor finish (BG_SECS), and nothing follows.
    let stray = agent
        .client
        .wait_for_message(
            "parked: no frame may follow the park ack",
            Duration::from_secs(BG_SECS + 6),
            |_| true,
            |_: &Value| RawReply::Refuse,
        )
        .await;
    assert!(
        stray.is_none(),
        "a frame arrived after the park acknowledgement: {stray:?}"
    );
    assert_eq!(agent.client.transcript().len(), lines_at_ack);
    assert!(
        agent.workspace.join("p189-bg-done").exists(),
        "hold mode lets the background command finish"
    );
    assert!(
        agent.workspace.join("p189-monitor-done").exists(),
        "hold mode lets the monitor command finish"
    );
    let calls_while_parked = agent.chat_requests_after(parked_at);
    assert!(
        calls_while_parked.is_empty(),
        "{} model call(s) while parked",
        calls_while_parked.len()
    );

    // A second park reports the park that holds.
    let again = agent
        .call("_fuigo/session/park", json!({ "sessionId": session }))
        .await;
    assert_eq!(again["result"]["alreadyParked"], true, "{again}");
    assert_eq!(agent.client.transcript().len(), lines_at_ack + 1, "only the reply was written");

    let unparked_at = SystemTime::now();
    let unpark = agent
        .call("_fuigo/session/unpark", json!({ "sessionId": session }))
        .await;
    assert_eq!(unpark["result"]["resumed"], true, "{unpark}");
    assert_eq!(unpark["result"]["wasParked"], true, "{unpark}");
    let released = unpark["result"]["released"]["frames"].as_u64().unwrap_or(0);
    assert!(released >= 1, "the completions' frames were held: {unpark}");
    let written_before_reply: Vec<Value> = agent.client.transcript()[lines_at_ack + 1..]
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|m| m.get("method").is_some())
        .collect();
    assert_eq!(
        written_before_reply.len() as u64,
        released + 1,
        "every released frame, then the unparked marker, is written before the unpark reply"
    );
    let (frames, marker) = written_before_reply.split_at(released as usize);
    for frame in frames {
        assert_eq!(
            frame["params"]["_meta"]["fuigo/released"], true,
            "a released frame is not marked: {frame}"
        );
    }
    assert_unparked_marker(&marker[0], &session, released);
    assert!(
        agent
            .wait_chat_request_after(unparked_at, Duration::from_secs(20))
            .await,
        "the deferred wake turn never ran after unpark\n{}",
        agent.stderr()
    );
}

fn assert_unparked_marker(msg: &Value, session: &str, frames: u64) {
    assert_eq!(method_of(msg), Some("_fuigo/session_notification"), "not the marker: {msg}");
    assert_eq!(msg["params"]["sessionId"], session, "{msg}");
    assert_eq!(msg["params"]["update"]["sessionUpdate"], "unparked", "{msg}");
    assert_eq!(msg["params"]["update"]["released"]["frames"], frames, "{msg}");
}

/// Clean-park latency: nothing running, the park reply time is printed (`P189-CLEAN-PARK-MS`) and must be
/// far inside Murage's 5 s bound.
#[tokio::test(flavor = "current_thread")]
async fn clean_park_is_fast() {
    let mut agent = Agent::spawn().await;
    let session = agent.connect().await;
    let first = agent.prompt(&session, "hello").await;
    assert_eq!(first["result"]["stopReason"], "end_turn", "{first}");
    let mut samples = Vec::new();
    for mode in ["hold"] {
        let started = std::time::Instant::now();
        let park = agent
            .call("_fuigo/session/park", json!({ "sessionId": session, "mode": mode }))
            .await;
        let ms = started.elapsed().as_millis();
        assert_eq!(park["result"]["parked"], true, "{park}");
        samples.push((mode, ms));
        let resume = agent.prompt(&session, "next").await;
        assert_eq!(resume["result"]["stopReason"], "end_turn", "{resume}");
    }
    for (mode, ms) in &samples {
        println!("P189-CLEAN-PARK-MS mode={mode} ms={ms}");
        assert!(*ms < 1000, "a clean {mode} park took {ms} ms");
    }
}

/// The methods (notifications and requests) written since transcript line `from`.
fn frames_since(agent: &Agent, from: usize) -> Vec<Value> {
    agent.client.transcript()[from..]
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|m| m.get("method").is_some())
        .collect()
}

/// A minimal stdio MCP server (POSIX sh): `initialize`, `tools/list` (one tool), `ping`.
#[cfg(unix)]
fn stub_mcp_script() -> &'static str {
    r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"p189","version":"0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"p189_echo","description":"p189 echo","inputSchema":{"type":"object","properties":{}}}]}}\n' "$id" ;;
    *'"method":"ping"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id" ;;
  esac
done
"#
}

/// `session/load` on a parked session does not unpark it and writes nothing but its own reply (noReplay):
/// the session is still parked afterwards, and the next prompt is the implicit unpark (released frames
/// marked, then the `unparked` marker).
#[tokio::test(flavor = "current_thread")]
async fn load_on_a_parked_session_writes_only_its_reply_and_stays_parked() {
    let mut agent = Agent::spawn().await;
    let session = agent.connect().await;
    let first = agent.prompt(&session, "hello").await;
    assert_eq!(first["result"]["stopReason"], "end_turn", "{first}");
    let park = agent
        .call("_fuigo/session/park", json!({ "sessionId": session, "mode": "hold" }))
        .await;
    assert_eq!(park["result"]["parked"], true, "{park}");
    let at_ack = agent.client.transcript().len();
    let ws = agent.workspace.clone();
    let load = agent
        .call(
            "session/load",
            json!({ "sessionId": session, "cwd": ws, "mcpServers": [], "_meta": { "noReplay": true } }),
        )
        .await;
    assert!(load.get("result").is_some(), "load failed: {load}\n{}", agent.stderr());
    assert!(
        load["result"]["_meta"]["fuigo/mcpReady"]["servers"].is_array(),
        "a parked load reply carries the MCP readiness: {load}"
    );
    let quiet = agent
        .client
        .wait_for_message("after a parked load", Duration::from_secs(2), |_| true, |_: &Value| RawReply::Refuse)
        .await;
    assert!(quiet.is_none(), "a frame followed the parked load reply: {quiet:?}");
    assert_eq!(
        frames_since(&agent, at_ack),
        Vec::<Value>::new(),
        "a parked load wrote something besides its reply"
    );
    let again = agent
        .call("_fuigo/session/park", json!({ "sessionId": session, "mode": "hold" }))
        .await;
    assert_eq!(again["result"]["alreadyParked"], true, "load must not unpark: {again}");
    let before_prompt = agent.client.transcript().len();
    let next = agent.prompt(&session, "next").await;
    assert_eq!(next["result"]["stopReason"], "end_turn", "{next}");
    let after = frames_since(&agent, before_prompt);
    let marker_at = after
        .iter()
        .position(|m| m["params"]["update"]["sessionUpdate"] == "unparked")
        .expect("the prompt writes the unparked marker");
    let released = after[marker_at]["params"]["update"]["released"]["frames"].as_u64().unwrap_or(0);
    assert_eq!(marker_at as u64, released, "only released frames precede the marker: {after:?}");
    for frame in &after[..marker_at] {
        assert_eq!(frame["params"]["_meta"]["fuigo/released"], true, "{frame}");
    }
}

/// A parked load with fresh MCP servers (one good, one that cannot start) replies only once both settled,
/// listing each one's status, and writes nothing else (no `_fuigo/mcp_initialized`).
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn parked_load_reply_carries_mcp_readiness() {
    let mut agent = Agent::spawn().await;
    let script = agent.client.sandbox().temp_dir().join("p189-mcp.sh");
    std::fs::write(&script, stub_mcp_script()).expect("write MCP stub");
    let session = agent.connect().await;
    let first = agent.prompt(&session, "hello").await;
    assert_eq!(first["result"]["stopReason"], "end_turn", "{first}");
    let park = agent
        .call("_fuigo/session/park", json!({ "sessionId": session, "mode": "hold" }))
        .await;
    assert_eq!(park["result"]["parked"], true, "{park}");
    let at_ack = agent.client.transcript().len();
    let ws = agent.workspace.clone();
    let load = agent
        .call(
            "session/load",
            json!({
                "sessionId": session,
                "cwd": ws,
                "mcpServers": [
                    { "name": "p189good", "command": "/bin/sh", "args": [script], "env": [] },
                    { "name": "p189bad", "command": "/nonexistent/p189-mcp", "args": [], "env": [] }
                ],
                "_meta": { "noReplay": true }
            }),
        )
        .await;
    assert!(load.get("result").is_some(), "load failed: {load}\n{}", agent.stderr());
    let servers = load["result"]["_meta"]["fuigo/mcpReady"]["servers"]
        .as_array()
        .unwrap_or_else(|| panic!("no fuigo/mcpReady in the parked load reply: {load}"))
        .clone();
    let status_of = |name: &str| {
        servers
            .iter()
            .find(|s| s["name"] == name)
            .map(|s| s["status"].clone())
            .unwrap_or_else(|| panic!("{name} missing from {servers:?}"))
    };
    assert_eq!(status_of("p189good"), "ready", "{servers:?}");
    assert_eq!(status_of("p189bad"), "failed", "{servers:?}");
    let quiet = agent
        .client
        .wait_for_message("after a parked load", Duration::from_secs(2), |_| true, |_: &Value| RawReply::Refuse)
        .await;
    assert!(quiet.is_none(), "a frame followed the parked load reply: {quiet:?}");
    assert_eq!(frames_since(&agent, at_ack), Vec::<Value>::new(), "nothing but the reply may be written");
}

/// `session/prompt` on a parked session unparks it implicitly and runs the prompt.
#[tokio::test(flavor = "current_thread")]
async fn prompt_on_a_parked_session_unparks_it() {
    let mut agent = Agent::spawn().await;
    let session = agent.connect().await;
    let first = agent.prompt(&session, "hello").await;
    assert_eq!(first["result"]["stopReason"], "end_turn", "{first}");
    let park = agent
        .call("_fuigo/session/park", json!({ "sessionId": session }))
        .await;
    assert_eq!(park["result"]["parked"], true, "{park}");
    let lines_at_ack = agent.client.transcript().len();
    let second = agent.prompt(&session, "again").await;
    assert_eq!(
        second["result"]["stopReason"], "end_turn",
        "a prompt on a parked session must run: {second}\n{}",
        agent.stderr()
    );
    let after: Vec<Value> = agent.client.transcript()[lines_at_ack..]
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|m| m.get("method").is_some())
        .collect();
    let marker_at = after
        .iter()
        .position(|m| m["params"]["update"]["sessionUpdate"] == "unparked")
        .expect("the implicit unpark writes the unparked marker");
    let first_update = after
        .iter()
        .position(|m| method_of(m) == Some("session/update") && m["params"]["_meta"]["fuigo/released"] != true);
    assert!(
        first_update.is_none_or(|i| i > marker_at),
        "the marker precedes the new turn's first frame: {after:?}"
    );
    let unpark = agent
        .call("_fuigo/session/unpark", json!({ "sessionId": session }))
        .await;
    assert_eq!(unpark["result"]["wasParked"], false, "the prompt already unparked: {unpark}");
}

/// Wire errors: an unknown mode and an unknown session are `-32602`; `initialize` advertises the method.
#[tokio::test(flavor = "current_thread")]
async fn park_wire_errors_and_capability() {
    let mut agent = Agent::spawn().await;
    let init = agent
        .call(
            "initialize",
            json!({ "protocolVersion": 1, "clientCapabilities": {} }),
        )
        .await;
    let cap = &init["result"]["agentCapabilities"]["_meta"]["fuigo/capabilities"]["sessionPark"];
    assert_eq!(cap["version"], 1, "{init}");
    assert_eq!(cap["defaultMode"], "hold");
    assert_eq!(cap["modes"], json!(["hold"]), "{init}");
    assert_eq!(cap["promptWhileParked"], "implicitUnpark");
    assert_eq!(
        cap["methods"],
        json!(["_fuigo/session/park", "_fuigo/session/unpark"])
    );
    let auth = agent
        .call("authenticate", json!({ "methodId": "fuigo.api_key" }))
        .await;
    assert!(auth.get("result").is_some(), "{auth}");
    let ws = agent.workspace.clone();
    let new = agent
        .call("session/new", json!({ "cwd": ws, "mcpServers": [] }))
        .await;
    let session = new["result"]["sessionId"].as_str().expect("session id").to_owned();
    let bad_mode = agent
        .call("_fuigo/session/park", json!({ "sessionId": session, "mode": "freeze" }))
        .await;
    assert_eq!(bad_mode["error"]["code"], -32602, "{bad_mode}");
    let unknown = agent
        .call("_fuigo/session/park", json!({ "sessionId": "no-such-session" }))
        .await;
    assert_eq!(unknown["error"]["code"], -32602, "{unknown}");
    assert!(
        agent.client.transcript().iter().all(|l| {
            serde_json::from_str::<Value>(l)
                .ok()
                .is_none_or(|m| method_of(&m) != Some("_fuigo/session/park"))
        }),
        "the agent never sends park itself"
    );
}

/// No timer fires while parked: a scheduler task that comes due while parked does not call the model,
/// spawn a loop, or write a frame. The next prompt (implicit unpark) folds it into its turn as a reminder.
/// The scheduler's minimum interval is one minute, so this waits it (the 1 s case is a scheduler unit test).
#[tokio::test(flavor = "current_thread")]
async fn park_folds_a_scheduler_fire_into_the_next_prompt() {
    let mut agent = Agent::spawn().await;
    let scheduled = script_tool_call(
        &agent.server,
        "call_sched",
        "scheduler_create",
        json!({ "interval": "1m", "prompt": "Reply with the word p189loop." }),
    );
    let session = agent.connect().await;
    let created_at = std::time::Instant::now();
    let reply = agent.prompt(&session, "schedule the loop").await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}\n{}", agent.stderr());
    scheduled.assert_satisfied();
    let park = agent
        .call("_fuigo/session/park", json!({ "sessionId": session }))
        .await;
    let parked_at = SystemTime::now();
    assert_eq!(park["result"]["parked"], true, "{park}");
    let lines_at_ack = agent.client.transcript().len();

    // Stay parked well past the first fire (one minute after creation).
    let quiet_for = Duration::from_secs(75).saturating_sub(created_at.elapsed());
    let stray = agent
        .client
        .wait_for_message(
            "parked through a scheduler fire",
            quiet_for,
            |_| true,
            |_: &Value| RawReply::Refuse,
        )
        .await;
    assert!(stray.is_none(), "a frame arrived while parked: {stray:?}");
    assert_eq!(agent.client.transcript().len(), lines_at_ack);
    assert!(
        agent.chat_requests_after(parked_at).is_empty(),
        "the scheduler fire called the model while parked"
    );

    // Murage's path: the next prompt unparks implicitly; the fire that came due is folded into its turn as
    // a reminder instead of running as its own loop.
    let prompted_at = SystemTime::now();
    let reply = agent.prompt(&session, "what happened?").await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}\n{}", agent.stderr());
    let requests = agent.chat_requests_after(prompted_at);
    let folded = requests.iter().any(|r| {
        r.body
            .as_ref()
            .is_some_and(|b| b.to_string().contains("came due"))
    });
    assert!(folded, "the user's turn must carry the folded scheduler fire");
    assert!(
        !requests.iter().any(|r| r
            .body
            .as_ref()
            .is_some_and(|b| b.to_string().contains("p189loop") && !b.to_string().contains("came due"))),
        "the folded fire must not also run as a loop"
    );
}

/// A client terminal (`clientCapabilities.terminal`): `terminal/create` gets an id, `terminal/output` reports
/// a still-running command, `terminal/wait_for_exit` stays unanswered (the command runs on), the rest succeed.
fn client_terminal(msg: &Value) -> fuigo_test_support::acp_client::RawReply {
    use fuigo_test_support::acp_client::RawReply;
    match method_of(msg) {
        Some("terminal/create") => RawReply::Result(json!({ "terminalId": "p189-term-1" })),
        Some("terminal/output") => RawReply::Result(json!({ "output": "", "truncated": false })),
        Some("terminal/wait_for_exit") => RawReply::Defer,
        Some("terminal/kill" | "terminal/release") => RawReply::Result(json!({})),
        _ => RawReply::Refuse,
    }
}

/// Astra r1 #3/#10 (circular wait): with a client terminal running a background command, a park must not
/// wait on its own hold. Counting the running tasks asks the client (`terminal/output`); asked after the park
/// completed, that request is held until the unpark and the park never replies. A second park reports the
/// count recorded at the ack without asking again.
#[tokio::test(flavor = "current_thread")]
async fn park_with_a_client_terminal_task_replies() {
    let mut agent = Agent::spawn().await;
    let scripted = script_tool_call(
        &agent.server,
        "call_client_term",
        "run_terminal_command",
        json!({ "command": "sleep 300", "description": "p189 client terminal", "background": true }),
    );
    let session = agent
        .connect_with(json!({ "fs": { "readTextFile": false, "writeTextFile": false }, "terminal": true }))
        .await;
    let reply = agent
        .call_answering(
            "session/prompt",
            json!({ "sessionId": session, "prompt": [{ "type": "text", "text": "start" }] }),
            client_terminal,
        )
        .await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}\n{}", agent.stderr());
    scripted.assert_satisfied();
    let started = std::time::Instant::now();
    let park = tokio::time::timeout(
        scaled(Duration::from_secs(20)),
        agent.call_answering(
            "_fuigo/session/park",
            json!({ "sessionId": session, "mode": "hold", "timeoutMs": 5000 }),
            client_terminal,
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("the park never replied (circular wait on its own hold)\n{}", agent.stderr()));
    assert_eq!(park["result"]["parked"], true, "{park}\n{}", agent.stderr());
    assert!(started.elapsed() < Duration::from_secs(10), "park took {:?}", started.elapsed());
    let running = park["result"]["running"]["backgroundTasks"].clone();
    let again = tokio::time::timeout(
        scaled(Duration::from_secs(10)),
        agent.call_answering(
            "_fuigo/session/park",
            json!({ "sessionId": session, "mode": "hold" }),
            client_terminal,
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("the idempotent park never replied\n{}", agent.stderr()));
    assert_eq!(again["result"]["alreadyParked"], true, "{again}");
    assert_eq!(again["result"]["running"]["backgroundTasks"], running, "{again}");
    let unpark = agent
        .call_answering("_fuigo/session/unpark", json!({ "sessionId": session }), client_terminal)
        .await;
    assert_eq!(unpark["result"]["wasParked"], true, "{unpark}");
}

/// Murage's per-turn sequence on a parked session: `session/load` -> `session/set_model` -> `session/prompt`.
/// `set_model` is allowed while parked and does not unpark: only the two replies are written, and the frames
/// `set_model` emits (model changed, config options, ...) are held and released, marked, at the prompt.
#[tokio::test(flavor = "current_thread")]
async fn set_model_on_a_parked_session_is_held_and_does_not_unpark() {
    const OTHER: &str = "p189-model-b";
    let mut agent =
        Agent::spawn_with_models(vec![MockModelEntry::new(MODEL), MockModelEntry::new(OTHER)]).await;
    let session = agent.connect().await;
    let first = agent.prompt(&session, "hello").await;
    assert_eq!(first["result"]["stopReason"], "end_turn", "{first}");
    let park = agent
        .call("_fuigo/session/park", json!({ "sessionId": session, "mode": "hold" }))
        .await;
    assert_eq!(park["result"]["parked"], true, "{park}");
    let at_ack = agent.client.transcript().len();
    let ws = agent.workspace.clone();
    let load = agent
        .call(
            "session/load",
            json!({ "sessionId": session, "cwd": ws, "mcpServers": [], "_meta": { "noReplay": true } }),
        )
        .await;
    assert!(load.get("result").is_some(), "load failed: {load}\n{}", agent.stderr());
    let set = agent
        .call("session/set_model", json!({ "sessionId": session, "modelId": OTHER }))
        .await;
    assert!(set.get("result").is_some(), "set_model failed while parked: {set}\n{}", agent.stderr());
    let quiet = agent
        .client
        .wait_for_message("after a parked set_model", Duration::from_secs(2), |_| true, |_: &Value| RawReply::Refuse)
        .await;
    assert!(quiet.is_none(), "a frame followed the parked set_model reply: {quiet:?}");
    assert_eq!(
        frames_since(&agent, at_ack),
        Vec::<Value>::new(),
        "a parked load + set_model wrote something besides their replies"
    );
    let again = agent
        .call("_fuigo/session/park", json!({ "sessionId": session, "mode": "hold" }))
        .await;
    assert_eq!(again["result"]["alreadyParked"], true, "set_model must not unpark: {again}");
    let before_prompt = agent.client.transcript().len();
    let next = agent.prompt(&session, "next").await;
    assert_eq!(next["result"]["stopReason"], "end_turn", "{next}\n{}", agent.stderr());
    let after = frames_since(&agent, before_prompt);
    let marker_at = after
        .iter()
        .position(|m| m["params"]["update"]["sessionUpdate"] == "unparked")
        .expect("the prompt writes the unparked marker");
    let released = after[marker_at]["params"]["update"]["released"]["frames"].as_u64().unwrap_or(0);
    assert_eq!(marker_at as u64, released, "only released frames precede the marker: {after:?}");
    assert!(released >= 1, "set_model's frames were not held for the prompt: {after:?}");
    for frame in &after[..marker_at] {
        assert_eq!(frame["params"]["_meta"]["fuigo/released"], true, "{frame}");
    }
    println!("P189-SET-MODEL-RELEASED frames={released}");
}

// ---- round 3 group A ----

// ---- round 3 group C ----

/// NEW-1: `set_model` to a model of a DIFFERENT family on a parked session with model-minted history used to run
/// the family-switch compaction inline, which waits for an unpark that only a prompt can give: deadlock. Now the
/// compaction is owed: `set_model` replies at once, no model call is made while parked, and the prompt's
/// implicit unpark runs the compaction before the prompt's own turn.
#[tokio::test(flavor = "current_thread")]
async fn family_switch_set_model_on_a_parked_session_is_owed_until_the_prompt() {
    const OTHER: &str = "p189-model-fam-b";
    let mut agent = Agent::spawn_with_models(vec![
        MockModelEntry::new(MODEL).with_model_family("p189-fam-a"),
        MockModelEntry::new(OTHER).with_model_family("p189-fam-b"),
    ])
    .await;
    let session = agent.connect().await;
    let first = agent.prompt(&session, "hello").await;
    assert_eq!(first["result"]["stopReason"], "end_turn", "{first}");
    let park = agent
        .call("_fuigo/session/park", json!({ "sessionId": session, "mode": "hold" }))
        .await;
    assert_eq!(park["result"]["parked"], true, "{park}");
    let since = SystemTime::now();
    let ws = agent.workspace.clone();
    let load = agent
        .call(
            "session/load",
            json!({ "sessionId": session, "cwd": ws, "mcpServers": [], "_meta": { "noReplay": true } }),
        )
        .await;
    assert!(load.get("result").is_some(), "load failed: {load}\n{}", agent.stderr());
    let set = tokio::time::timeout(
        scaled(Duration::from_secs(10)),
        agent.call("session/set_model", json!({ "sessionId": session, "modelId": OTHER })),
    )
    .await
    .unwrap_or_else(|_| panic!("set_model did not reply while parked (deadlock)\n{}", agent.stderr()));
    assert!(set.get("result").is_some(), "set_model failed while parked: {set}\n{}", agent.stderr());
    let _ = agent
        .client
        .wait_for_message("quiet after set_model", Duration::from_secs(2), |_| false, refuse)
        .await;
    assert_eq!(
        agent.chat_requests_after(since).len(),
        0,
        "a model call was made while parked\n{}",
        agent.stderr()
    );
    let next = agent.prompt(&session, "next").await;
    assert_eq!(next["result"]["stopReason"], "end_turn", "{next}\n{}", agent.stderr());
    let calls = agent.chat_requests_after(since).len();
    assert!(calls >= 2, "the prompt ran no owed family-switch compaction (model calls: {calls})");
}

/// P189 M3, end to end through the real binary: the PRODUCTION model dispatch gate. A background subagent's first
/// model call fails with a retryable 503 (`retry-after: RETRY_AFTER_SECS`); the root is hold-parked during that
/// backoff. The subagent's RETRY comes due while parked: it is past execution admission, so only the dispatch gate
/// (`ParkGate::wait_open`) can hold it. It must not reach the endpoint while parked and must go out after unpark.
///
/// Script, in the order the mock hands out foreground replies: parent round 1 spawns the background subagent,
/// parent round 2 ends the turn, child round 1 answers 503; the retry is unscripted (echo).
#[tokio::test(flavor = "current_thread")]
async fn model_dispatch_gate_holds_a_background_subagents_retry_while_parked() {
    const RETRY_AFTER_SECS: u64 = 10;
    let mut agent = Agent::spawn().await;
    let server = &agent.server;
    let spawn = script_tool_call(
        server,
        "call_spawn",
        "spawn_subagent",
        json!({
            "description": "p189 gate child",
            "prompt": "say hello",
            "subagent_type": "general-purpose",
            "background": true,
        }),
    );
    let parent_end = server.expect_response(
        "parent-round-2-ends",
        InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
        ScriptedResponse::sse(fuigo_test_support::sse::chat_completion_script_exact("spawned", MODEL)),
    );
    let mut unavailable = ScriptedResponse::json(503, json!({ "error": { "message": "p189 overloaded" } }));
    unavailable.headers.push(("retry-after".to_owned(), RETRY_AFTER_SECS.to_string()));
    let child_503 = server.expect_response(
        "child-round-1-503",
        InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
        unavailable,
    );
    let session = agent.connect().await;
    let reply = agent.prompt(&session, "start the background subagent").await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "turn 1 did not end: {reply}\n{}", agent.stderr());
    spawn.assert_satisfied();
    parent_end.assert_satisfied();
    // The child's first call (the 503) must have been served before the park, so the retry is in its backoff.
    let deadline = tokio::time::Instant::now() + scaled(Duration::from_secs(30));
    while !child_503.is_satisfied() && tokio::time::Instant::now() < deadline {
        let _ = agent
            .client
            .wait_for_message("drain", Duration::from_millis(200), |_| false, refuse)
            .await;
    }
    assert!(child_503.is_satisfied(), "the child never made its first call\n{}", agent.stderr());

    let park = agent.call("_fuigo/session/park", json!({ "sessionId": session })).await;
    let parked_at = SystemTime::now();
    assert_eq!(park["result"]["parked"], true, "park failed: {park}\n{}", agent.stderr());

    // The backoff ends while parked; the retry is due and must be held.
    let _ = agent
        .client
        .wait_for_message(
            "parked: quiet",
            Duration::from_secs(RETRY_AFTER_SECS + 5),
            |_| true,
            |_: &Value| RawReply::Refuse,
        )
        .await;
    let held = agent.chat_requests_after(parked_at);
    assert!(held.is_empty(), "{} model call(s) reached the endpoint while parked", held.len());

    let unparked_at = SystemTime::now();
    let unpark = agent.call("_fuigo/session/unpark", json!({ "sessionId": session })).await;
    assert_eq!(unpark["result"]["wasParked"], true, "{unpark}");
    assert!(
        agent.wait_chat_request_after(unparked_at, Duration::from_secs(20)).await,
        "no model call after unpark: the gate never released\n{}",
        agent.stderr()
    );
}

/// P189 A1: `stop` is not available on any OS. The capability lists only `hold`; a `stop` request is `-32602`
/// naming the advertised modes and leaves the session unparked (a prompt still runs, with no unparked marker).
#[tokio::test(flavor = "current_thread")]
async fn park_stop_is_unadvertised_everywhere() {
    let mut agent = Agent::spawn().await;
    let init = agent
        .call("initialize", json!({ "protocolVersion": 1, "clientCapabilities": {} }))
        .await;
    let cap = &init["result"]["agentCapabilities"]["_meta"]["fuigo/capabilities"]["sessionPark"];
    assert_eq!(cap["modes"], json!(["hold"]), "{init}");
    let auth = agent
        .call("authenticate", json!({ "methodId": "fuigo.api_key" }))
        .await;
    assert!(auth.get("result").is_some(), "{auth}");
    let ws = agent.workspace.clone();
    let new = agent
        .call("session/new", json!({ "cwd": ws, "mcpServers": [] }))
        .await;
    let session = new["result"]["sessionId"].as_str().expect("session id").to_owned();
    let stop = agent
        .call("_fuigo/session/park", json!({ "sessionId": session, "mode": "stop" }))
        .await;
    assert_eq!(stop["error"]["code"], -32602, "{stop}");
    let message = stop["error"]["data"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("hold") && !message.contains("\"stop\""), "{stop}");
    let unpark = agent
        .call("_fuigo/session/unpark", json!({ "sessionId": session }))
        .await;
    assert_eq!(unpark["result"]["wasParked"], false, "a refused stop parked the session: {unpark}");
    let prompt = agent.prompt(&session, "hello").await;
    assert_eq!(prompt["result"]["stopReason"], "end_turn", "{prompt}");
}
