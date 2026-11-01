//! 1.0.38: a folder-trust grant reaches project instructions.
//!
//! Each test drives the REAL binary over raw ACP against `MockInferenceServer`: a client that advertises
//! `fuigo/folderTrust.v2`, answers `fuigo/folder_trust/request` and reads what the model endpoint and `chat_history`
//! actually received. The version stamp is set, otherwise folder trust is inert and "untrusted" proves nothing.
#![cfg(unix)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use fuigo_test_support::acp_client::{AgentSpawnSpec, RawReply, RawStdioClient};
use fuigo_test_support::sse::chat_completions_reasoning_then_tool_call_events;
use fuigo_test_support::{
    InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, MockModelEntry, ScriptedResponse, SseEvent,
    TestSandbox,
};
use serde_json::{Value, json};

const CANARY: &str = "MARMALADE-38-CANARY";
const USER_CANARY: &str = "QUINCE-38-USER-CANARY";
const LATE_CANARY: &str = "DAMSON-38-LATE-CANARY";
const RPC: Duration = Duration::from_secs(60);
const PLAN_MODEL: &str = "u38-plan";
/// `fuigo-build` and the plan agent are compatible harnesses, so a switch between them keeps the agent. Only a strict
/// harness rebuilds, and this one keeps its rules in a reminder.
const HARNESS_MODEL: &str = "u38-harness";
const DEFAULT_MODEL: &str = "test-model";
/// A model's `agent_type` chooses only a strict harness, and with no profile every session is the plan agent. So the
/// reminder agent under test is asked for by name, as a client does; the tests read the history tag to prove which ran.
const REMINDER_TAG: &str = r#""synthetic_reason":"project_instructions""#;
const TRUST: &[(&str, &str)] = &[("FUIGO_TEST_VERSION", "1.0.38-u38"), ("FUIGO_FOLDER_TRUST", "1")];

fn profile(model: &str) -> &'static str {
    match model {
        PLAN_MODEL => "fuigo-build-plan",
        HARNESS_MODEL => "fuigo-build-orchestrator",
        _ => "fuigo-build",
    }
}

fn local<F: std::future::Future>(f: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("rt");
    let set = tokio::task::LocalSet::new();
    rt.block_on(set.run_until(f))
}

async fn server() -> MockInferenceServer {
    let server = MockInferenceServer::start_with_models(vec![
        MockModelEntry::with_agent_type(DEFAULT_MODEL, "fuigo-build"),
        MockModelEntry::with_agent_type(PLAN_MODEL, "fuigo-build-plan"),
        MockModelEntry::with_agent_type(HARNESS_MODEL, "fuigo-build-orchestrator"),
    ])
    .await
    .expect("mock");
    server.preset_allow_access();
    server
}

fn sandbox(server: &MockInferenceServer) -> TestSandbox {
    let sandbox = TestSandbox::builder().mock_url(server.url()).git().build();
    std::fs::write(
        sandbox.workspace().join("AGENTS.md"),
        format!("# Project instructions\n\nCodeword: {CANARY}\n"),
    )
    .expect("AGENTS.md");
    sandbox
}

fn plant_user_file(sandbox: &TestSandbox) {
    std::fs::write(
        sandbox.fuigo_home().join("AGENTS.md"),
        format!("# User instructions\n\n{USER_CANARY}\n"),
    )
    .expect("user AGENTS.md");
}

/// What the client answers to `fuigo/folder_trust/request`.
#[derive(Clone, Copy, PartialEq)]
enum Reply {
    Trust,
    TrustForProcess,
    Hold,
}

const GRANT: fn() -> Value = || json!({ "outcome": "trust", "scope": "configAndCommands" });

fn answer(reply: Reply, held: Rc<RefCell<Option<Value>>>) -> impl FnMut(&Value) -> RawReply {
    move |msg: &Value| {
        if msg.get("method").and_then(Value::as_str) == Some("fuigo/folder_trust/request")
            || msg.get("method").and_then(Value::as_str) == Some("_fuigo/folder_trust/request")
        {
            return match reply {
                Reply::Trust => RawReply::Result(GRANT()),
                Reply::TrustForProcess => RawReply::Result(
                    json!({ "outcome": "trust", "scope": "configAndCommands", "duration": "process" }),
                ),
                Reply::Hold => {
                    *held.borrow_mut() = msg.get("id").cloned();
                    RawReply::Defer
                }
            };
        }
        if msg.get("method").and_then(Value::as_str) == Some("session/request_permission") {
            let option = msg["params"]["options"]
                .as_array()
                .and_then(|options| options.iter().find(|o| o["kind"] == "allow_once").or(options.first()))
                .map(|o| o["optionId"].clone())
                .unwrap_or(Value::Null);
            return RawReply::Result(json!({ "outcome": { "outcome": "selected", "optionId": option } }));
        }
        RawReply::Refuse
    }
}

struct Peer {
    client: RawStdioClient,
    next: u64,
    reply: Reply,
    held: Rc<RefCell<Option<Value>>>,
    cwd: PathBuf,
    display_cwd: Option<&'static str>,
}

impl Peer {
    async fn start(server: &MockInferenceServer, sandbox: TestSandbox, reply: Reply) -> Self {
        let cwd = sandbox.workspace().to_path_buf();
        let spec = AgentSpawnSpec {
            leading_args: &["--permission-mode", "default", "--no-memory"],
            agent_args: &["--no-leader"],
            extra_env: TRUST,
            ..AgentSpawnSpec::default()
        };
        let client = RawStdioClient::spawn_with_spec(server, &cwd, sandbox, &spec).await;
        let mut peer = Self::adopt(client, cwd).await;
        peer.reply = reply;
        peer
    }

    /// Initialize and authenticate an agent spawned by the caller.
    async fn adopt(client: RawStdioClient, cwd: PathBuf) -> Self {
        let mut peer = Self { client, next: 0, reply: Reply::Hold, held: Rc::default(), cwd, display_cwd: None };
        let init = peer
            .call(
                "initialize",
                json!({
                    "protocolVersion": 1,
                    "clientCapabilities": {
                        "fs": { "readTextFile": false, "writeTextFile": false },
                        "terminal": false,
                        "_meta": { "fuigo/folderTrust": { "v2": true } }
                    },
                    "_meta": { "startupHints": { "nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true } }
                }),
            )
            .await;
        assert!(init.get("result").is_some(), "initialize: {init}");
        let auth = peer
            .call("authenticate", json!({ "methodId": "fuigo.api_key", "_meta": { "headless": true } }))
            .await;
        assert!(auth.get("result").is_some(), "authenticate: {auth}");
        peer
    }

    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = format!("u38-{}", self.next);
        let reply = answer(self.reply, self.held.clone());
        self.client.request(&id, method, params, RPC, reply).await
    }

    async fn new_session(&mut self, model: &str) -> String {
        let cwd = self.cwd.clone();
        let new = self
            .call(
                "session/new",
                json!({
                    "cwd": cwd, "mcpServers": [],
                    "_meta": { "modelId": model, "agentProfile": profile(model) }
                }),
            )
            .await;
        new["result"]["sessionId"].as_str().unwrap_or_else(|| panic!("session/new: {new}")).to_owned()
    }

    async fn load(&mut self, model: &str, session: &str) {
        let cwd = self.cwd.clone();
        let load = self
            .call(
                "session/load",
                json!({
                    "sessionId": session, "cwd": cwd, "mcpServers": [],
                    "_meta": { "agentProfile": profile(model), "fuigo/display_cwd": self.display_cwd }
                }),
            )
            .await;
        assert!(load.get("result").is_some(), "session/load: {load}\nstderr: {}", self.client.stderr());
    }

    async fn prompt(&mut self, session: &str, text: &str) {
        let done = self
            .call(
                "session/prompt",
                json!({ "sessionId": session, "prompt": [{ "type": "text", "text": text }] }),
            )
            .await;
        assert!(done.get("result").is_some(), "session/prompt: {done}\nstderr: {}", self.client.stderr());
    }

    /// Let the detached grant task finish. Reads the agent's stdout meanwhile, so it never blocks on a full pipe.
    async fn settle(&mut self, secs: u64) {
        let _ = self
            .client
            .wait_for_message("settle", Duration::from_secs(secs), |_| false, answer(self.reply, self.held.clone()))
            .await;
    }

    /// Answer the held trust request with a grant, from here on granting at once.
    async fn release(&mut self) {
        if self.held.borrow().is_none() {
            self.settle(2).await;
        }
        let id = self.held.borrow_mut().take().expect("premise: a trust request is held");
        self.client.respond(&id, GRANT(), RPC).await;
        self.reply = Reply::Trust;
        self.settle(1).await;
        assert!(self.granted(), "premise: the held grant is stored");
    }

    /// Send a prompt, answer the held request `after` later, and return once the turn is done.
    async fn prompt_releasing_after(&mut self, session: &str, text: &str, after: Duration) {
        self.next += 1;
        let id = format!("u38-{}", self.next);
        let line = json!({
            "jsonrpc": "2.0", "id": id, "method": "session/prompt",
            "params": { "sessionId": session, "prompt": [{ "type": "text", "text": text }] }
        });
        self.client.send_line(&line.to_string()).await;
        let reply = answer(self.reply, self.held.clone());
        let _ = self.client.wait_for_message("hold", after, |_| false, reply).await;
        let held = self.held.borrow_mut().take().expect("premise: a trust request is held");
        self.client.respond(&held, GRANT(), RPC).await;
        self.reply = Reply::Trust;
        let reply = answer(self.reply, self.held.clone());
        let done = self.client.response_for_id_answering(&id, "session/prompt", RPC, reply).await;
        assert!(done.get("result").is_some(), "session/prompt: {done}");
    }

    /// Send a prompt, answer the held trust request with `reply` shortly after, and return how long the turn then took.
    async fn prompt_answering_held(&mut self, session: &str, text: &str, reply: Value) -> Duration {
        self.settle(1).await;
        let held = self.held.borrow_mut().take().expect("premise: a trust request is held");
        self.next += 1;
        let id = format!("u38-{}", self.next);
        let line = json!({
            "jsonrpc": "2.0", "id": id, "method": "session/prompt",
            "params": { "sessionId": session, "prompt": [{ "type": "text", "text": text }] }
        });
        self.client.send_line(&line.to_string()).await;
        let answer_fn = answer(self.reply, self.held.clone());
        let _ = self.client.wait_for_message("hold", Duration::from_millis(300), |_| false, answer_fn).await;
        let mut line = reply;
        line["jsonrpc"] = json!("2.0");
        line["id"] = held;
        self.client.send_line(&line.to_string()).await;
        let answered = std::time::Instant::now();
        let answer_fn = answer(self.reply, self.held.clone());
        let done = self.client.response_for_id_answering(&id, "session/prompt", RPC, answer_fn).await;
        assert!(done.get("result").is_some(), "session/prompt: {done}");
        answered.elapsed()
    }

    async fn set_model(&mut self, session: &str, model: &str) {
        let set = self.call("session/set_model", json!({ "sessionId": session, "modelId": model })).await;
        assert!(set.get("result").is_some(), "set_model {model}: {set}");
    }

    async fn compact(&mut self, session: &str) {
        let done = self
            .call("_fuigo/compact_conversation", json!({ "session_id": session, "user_context": "keep it" }))
            .await;
        assert!(done.get("result").is_some(), "compact: {done}");
    }

    /// The grant reached the durable store.
    fn granted(&self) -> bool {
        let store = self.client.sandbox().fuigo_home().join("trusted_folders.toml");
        std::fs::read_to_string(store).is_ok_and(|text| text.contains(&*self.cwd.to_string_lossy()))
    }

    async fn stop(mut self) -> TestSandbox {
        let _ = self.client.close().await;
        self.client.take_sandbox()
    }
}

fn hits(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// Every persisted `chat_history*` line of `session` under the sandbox.
fn history(sandbox: &TestSandbox, session: &str) -> String {
    let mut out = String::new();
    let mut stack = vec![sandbox.fuigo_home().to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n.to_string_lossy().starts_with("chat_history"))
                && path.to_string_lossy().contains(session)
            {
                out.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
            }
        }
    }
    assert!(!out.is_empty(), "no chat_history for {session}");
    out
}

/// `session`'s own directory under the sandbox.
fn session_dir(sandbox: &TestSandbox, session: &str) -> PathBuf {
    let mut stack = vec![sandbox.fuigo_home().to_path_buf()];
    while let Some(dir) = stack.pop() {
        if dir.file_name().is_some_and(|n| n.to_string_lossy() == session) && dir.join("chat_history.jsonl").exists() {
            return dir;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        stack.extend(entries.flatten().map(|e| e.path()).filter(|p| p.is_dir()));
    }
    panic!("no session directory for {session}");
}

/// Every session under the sandbox that records itself as a fork.
fn forks(sandbox: &TestSandbox) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![sandbox.fuigo_home().to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for path in entries.flatten().map(|e| e.path()) {
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n == "summary.json")
                && std::fs::read_to_string(&path).is_ok_and(|text| text.contains("subagent_fork"))
                && let Some(id) = dir.file_name().map(|n| n.to_string_lossy().into_owned())
            {
                found.push(id);
            }
        }
    }
    found
}

/// The stored history of the one session, other than `parent`, holding `marker`.
fn user_history_holding(sandbox: &TestSandbox, parent: &str, marker: &str) -> String {
    let mut found = Vec::new();
    let mut stack = vec![sandbox.fuigo_home().to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for path in entries.flatten().map(|e| e.path()) {
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n == "chat_history.jsonl")
                && !dir.to_string_lossy().contains(parent)
                && let Ok(text) = std::fs::read_to_string(&path)
                && text.contains(marker)
            {
                found.push(text);
            }
        }
    }
    assert_eq!(found.len(), 1, "sessions holding {marker}");
    found.pop().expect("one session")
}

/// How the fork was made, as the child's session records it.
fn fork_kind(sandbox: &TestSandbox, child: &str) -> String {
    let dir = session_dir(sandbox, child);
    let names = ["forked_verbatim", "forked_summarized"];
    for entry in std::fs::read_dir(&dir).expect("child dir").flatten() {
        let text = std::fs::read_to_string(entry.path()).unwrap_or_default();
        if entry.file_name() != "chat_history.jsonl"
            && let Some(kind) = names.iter().find(|kind| text.contains(**kind))
        {
            return (*kind).to_owned();
        }
    }
    panic!("no fork marker in {}", dir.display());
}

/// A child's first request: a subagent's system prompt, with the task as its last message. A parent holds the task only
/// in its tool call, and the title request ends on the task but has its own system prompt.
fn child_body(server: &MockInferenceServer, task: &str) -> String {
    server
        .request_bodies()
        .iter()
        .find(|body| {
            let Some(messages) = body["messages"].as_array() else { return false };
            messages.first().is_some_and(|m| m.to_string().contains("subagent"))
                && messages.last().is_some_and(|m| m.to_string().contains(task))
        })
        .map(Value::to_string)
        .unwrap_or_else(|| panic!("no child request for {task}"))
}

/// Every request carrying `marker` holds the project file `copies` times.
fn every_request(server: &MockInferenceServer, marker: &str, copies: usize, what: &str) {
    let bodies: Vec<String> =
        server.request_bodies().iter().map(Value::to_string).filter(|body| body.contains(marker)).collect();
    assert!(!bodies.is_empty(), "{what}: no request carried {marker}");
    for body in bodies {
        assert_eq!(hits(&body, CANARY), copies, "{what}");
        assert!(!body.contains("project_files_withheld"), "{what}: the bit reached the wire");
    }
}

/// Red on 1.0.37. Grant while the session is open: the next turn sees the project file, and so does a new process.
async fn grant_reaches_next_turn_and_load(model: &str) {
    let server = server().await;
    let sandbox = sandbox(&server);
    let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
    let session = peer.new_session(model).await;
    peer.settle(4).await;
    assert!(peer.granted(), "premise: the client's grant is stored");
    peer.prompt(&session, "turn-first").await;
    let live = turn_body(&server, "turn-first");
    assert_eq!(hits(&live, CANARY), 1, "the grant must reach the next turn once ({model})");
    let sandbox = peer.stop().await;

    let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
    peer.load(model, &session).await;
    peer.prompt(&session, "turn-second").await;
    let loaded = turn_body(&server, "turn-second");
    assert_eq!(hits(&loaded, CANARY), 1, "the file must survive a new-process load once ({model})");
    let sandbox = peer.stop().await;
    let saved = history(&sandbox, &session);
    assert!(saved.contains(CANARY), "chat_history must hold the file ({model})");
    assert_eq!(saved.contains(REMINDER_TAG), model != PLAN_MODEL, "premise: the {model} branch ran");
}

fn turn_body(server: &MockInferenceServer, marker: &str) -> String {
    server
        .request_bodies()
        .iter()
        .map(Value::to_string)
        .filter(|b| b.contains(marker))
        .max_by_key(String::len)
        .unwrap_or_else(|| panic!("no request carried {marker}"))
}

fn once(server: &MockInferenceServer, marker: &str, what: &str) {
    let body = turn_body(server, marker);
    assert_eq!(hits(&body, CANARY), 1, "{what}");
    assert!(!body.contains("project_files_withheld"), "{what}: the bit reached the wire");
}

/// A new session in the same folder stores the grant, as another client would.
async fn grant_elsewhere(server: &MockInferenceServer, sandbox: TestSandbox) -> TestSandbox {
    let mut peer = Peer::start(server, sandbox, Reply::Trust).await;
    let _ = peer.new_session(DEFAULT_MODEL).await;
    peer.settle(3).await;
    assert!(peer.granted(), "premise: the grant is stored");
    peer.stop().await
}

#[test]
fn user_level_and_project_file_add_only_the_project_file_once() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            let server = server().await;
            let sandbox = sandbox(&server);
            plant_user_file(&sandbox);
            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            let session = peer.new_session(model).await;
            peer.settle(1).await;
            peer.release().await;
            peer.prompt(&session, "turn-one").await;
            let body = turn_body(&server, "turn-one");
            assert_eq!(hits(&body, CANARY), 1, "{model}: project file");
            assert_eq!(hits(&body, USER_CANARY), 1, "{model}: user file");
            peer.stop().await;
        }
    });
}

#[test]
fn load_then_grant_then_prompt_and_a_repeat_load_stay_at_one_copy() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            let server = server().await;
            let sandbox = sandbox(&server);
            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            let session = peer.new_session(model).await;
            peer.prompt(&session, "turn-one").await;
            assert_eq!(hits(&turn_body(&server, "turn-one"), CANARY), 0, "premise: withheld");
            let sandbox = peer.stop().await;
            assert!(history(&sandbox, &session).contains("project_files_withheld"), "the bit is on disk");

            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            peer.load(model, &session).await;
            peer.release().await;
            peer.prompt(&session, "turn-two").await;
            once(&server, "turn-two", "load, grant, prompt");
            let sandbox = peer.stop().await;

            let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
            peer.load(model, &session).await;
            peer.prompt(&session, "turn-three").await;
            once(&server, "turn-three", "repeat load");
            let sandbox = peer.stop().await;
            assert!(!history(&sandbox, &session).contains("project_files_withheld"));
        }
    });
}

#[test]
fn a_grant_at_turn_three_reaches_turn_three() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            let server = server().await;
            let sandbox = sandbox(&server);
            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            let session = peer.new_session(model).await;
            peer.prompt(&session, "turn-one").await;
            peer.prompt(&session, "turn-two").await;
            peer.release().await;
            peer.prompt(&session, "turn-three").await;
            once(&server, "turn-three", "grant at turn 3");
            peer.prompt(&session, "turn-four").await;
            once(&server, "turn-four", "and it stays once");
            peer.stop().await;
        }
    });
}

#[test]
fn a_grant_after_compaction_and_a_compacted_load_stay_at_one_copy() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            let server = server().await;
            let sandbox = sandbox(&server);
            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            let session = peer.new_session(model).await;
            peer.prompt(&session, "turn-one").await;
            peer.compact(&session).await;
            peer.release().await;
            peer.prompt(&session, "turn-two").await;
            once(&server, "turn-two", "grant after compaction");
            let sandbox = peer.stop().await;

            let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
            peer.load(model, &session).await;
            peer.prompt(&session, "turn-three").await;
            once(&server, "turn-three", "load of a compacted session");
            peer.compact(&session).await;
            peer.prompt(&session, "turn-four").await;
            once(&server, "turn-four", "compacted again, trusted");
            peer.stop().await;
        }
    });
}

#[test]
fn a_zero_turn_switch_there_and_back_delivers_once() {
    local(async {
        let server = server().await;
        let sandbox = sandbox(&server);
        plant_user_file(&sandbox);
        let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
        let session = peer.new_session(HARNESS_MODEL).await;
        peer.set_model(&session, PLAN_MODEL).await;
        peer.set_model(&session, HARNESS_MODEL).await;
        peer.release().await;
        peer.prompt(&session, "turn-one").await;
        once(&server, "turn-one", "reminder, plan, reminder, grant");
        assert_eq!(hits(&turn_body(&server, "turn-one"), USER_CANARY), 1);
        let saved = peer.stop().await;
        assert!(history(&saved, &session).contains(REMINDER_TAG), "premise: back on the reminder agent");

        let sandbox = self::sandbox(&server);
        plant_user_file(&sandbox);
        let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
        let session = peer.new_session(HARNESS_MODEL).await;
        peer.release().await;
        peer.set_model(&session, PLAN_MODEL).await;
        peer.prompt(&session, "turn-one-b").await;
        once(&server, "turn-one-b", "granted, then switched to plan");
        let saved = peer.stop().await;
        assert!(!history(&saved, &session).contains(REMINDER_TAG), "premise: the rebuild reached the plan agent");
    });
}

/// F5. A process grant delivers and clears the bit, so after a restart, which is untrusted again, a later grant delivers
/// nothing. Both orders: the prompt may come before or after the second grant.
#[test]
fn a_process_grant_a_restart_and_a_second_grant_keep_one_copy() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            for prompt_first in [false, true] {
                let server = server().await;
                let sandbox = sandbox(&server);
                let mut peer = Peer::start(&server, sandbox, Reply::TrustForProcess).await;
                let session = peer.new_session(model).await;
                peer.settle(3).await;
                peer.prompt(&session, "turn-one").await;
                once(&server, "turn-one", "process grant");
                assert!(!peer.granted(), "premise: a process grant saves nothing");
                let sandbox = peer.stop().await;

                let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
                peer.load(model, &session).await;
                if prompt_first {
                    peer.prompt(&session, "turn-two").await;
                    once(&server, "turn-two", "restart, untrusted");
                }
                peer.release().await;
                peer.prompt(&session, "turn-three").await;
                once(&server, "turn-three", "restart, second grant");
                let sandbox = peer.stop().await;
                let saved = history(&sandbox, &session);
                assert_eq!(hits(&saved, CANARY), 1, "one copy in history");
                assert!(!saved.contains("project_files_withheld"));
            }
        }
    });
}

#[test]
fn a_durable_grant_elsewhere_delivers_on_a_trusted_load_once() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            let server = server().await;
            let sandbox = sandbox(&server);
            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            let session = peer.new_session(model).await;
            peer.prompt(&session, "turn-one").await;
            let sandbox = peer.stop().await;
            let sandbox = grant_elsewhere(&server, sandbox).await;

            let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
            peer.load(model, &session).await;
            peer.prompt(&session, "turn-two").await;
            once(&server, "turn-two", "trusted load");
            let sandbox = peer.stop().await;
            assert_eq!(hits(&history(&sandbox, &session), CANARY), 1, "one copy in history");
        }
    });
}

#[test]
fn an_empty_set_then_a_user_file_inserts_the_reminder_once() {
    local(async {
        let server = server().await;
        let sandbox = sandbox(&server);
        std::fs::remove_file(sandbox.workspace().join("AGENTS.md")).expect("no project file");
        let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
        let session = peer.new_session(DEFAULT_MODEL).await;
        peer.prompt(&session, "turn-one").await;
        let sandbox = peer.stop().await;
        plant_user_file(&sandbox);
        let sandbox = grant_elsewhere(&server, sandbox).await;

        let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
        peer.load(DEFAULT_MODEL, &session).await;
        peer.prompt(&session, "turn-two").await;
        assert_eq!(hits(&turn_body(&server, "turn-two"), USER_CANARY), 1);
        let sandbox = peer.stop().await;
        let saved = history(&sandbox, &session);
        assert_eq!(hits(&saved, USER_CANARY), 1, "the reminder is stored once");
        assert!(saved.contains(REMINDER_TAG), "premise: the reminder agent ran");
        assert!(saved.contains("project_files_withheld"), "the bit waits for a project file");
    });
}

/// A plan agent keeps its rules in the first message and a load never rebuilds that message, so a user file added later
/// waits for a new session. The untrusted head behaves as a trusted one does: nothing here depends on a grant.
#[test]
fn a_plan_head_leaves_a_later_user_file_to_a_new_session() {
    local(async {
        let server = server().await;
        let sandbox = sandbox(&server);
        std::fs::remove_file(sandbox.workspace().join("AGENTS.md")).expect("no project file");
        let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
        let session = peer.new_session(PLAN_MODEL).await;
        peer.prompt(&session, "turn-one").await;
        let sandbox = peer.stop().await;
        plant_user_file(&sandbox);
        let sandbox = grant_elsewhere(&server, sandbox).await;

        let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
        peer.load(PLAN_MODEL, &session).await;
        peer.prompt(&session, "turn-two").await;
        assert_eq!(hits(&turn_body(&server, "turn-two"), USER_CANARY), 0);
        let sandbox = peer.stop().await;
        assert!(history(&sandbox, &session).contains("project_files_withheld"), "the bit waits for a project file");
    });
}

/// The same load with a head built trusted, so it runs on 1.0.37 too: the behaviour above is not new.
#[test]
fn a_trusted_plan_head_leaves_a_later_user_file_to_a_new_session() {
    local(async {
        let server = server().await;
        let sandbox = sandbox(&server);
        let cwd = sandbox.workspace().to_path_buf();
        let client = RawStdioClient::spawn_with_spec(&server, &cwd, sandbox, &trusted_spec()).await;
        let mut peer = Peer::adopt(client, cwd.clone()).await;
        let session = peer.new_session(PLAN_MODEL).await;
        peer.prompt(&session, "turn-one").await;
        let sandbox = peer.stop().await;
        plant_user_file(&sandbox);

        let client = RawStdioClient::spawn_with_spec(&server, &cwd, sandbox, &trusted_spec()).await;
        let mut peer = Peer::adopt(client, cwd).await;
        peer.load(PLAN_MODEL, &session).await;
        peer.prompt(&session, "turn-two").await;
        assert_eq!(hits(&turn_body(&server, "turn-two"), USER_CANARY), 0);
        peer.stop().await;
    });
}

#[test]
fn untrusted_keeps_the_bit_and_it_never_reaches_a_request() {
    local(async {
        let server = server().await;
        let sandbox = sandbox(&server);
        let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
        let session = peer.new_session(DEFAULT_MODEL).await;
        peer.prompt(&session, "turn-one").await;
        peer.prompt(&session, "turn-two").await;
        let body = turn_body(&server, "turn-two");
        assert_eq!(hits(&body, CANARY), 0);
        assert!(!body.contains("project_files_withheld"));
        let sandbox = peer.stop().await;
        let saved = history(&sandbox, &session);
        assert!(saved.contains("project_files_withheld"));
        assert!(!saved.contains(CANARY));
    });
}

fn trusted_spec() -> AgentSpawnSpec<'static> {
    AgentSpawnSpec {
        leading_args: &["--permission-mode", "default", "--no-memory", "--trust"],
        agent_args: &["--no-leader"],
        extra_env: TRUST,
        ..AgentSpawnSpec::default()
    }
}

/// With `U38_DUMP` set, writes the trusted sessions' bodies so a run on each build can be compared.
#[test]
fn a_trusted_session_is_unchanged_with_no_bit_and_no_late_file() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            let server = server().await;
            let sandbox = sandbox(&server);
            let cwd = sandbox.workspace().to_path_buf();
            let client = RawStdioClient::spawn_with_spec(&server, &cwd, sandbox, &trusted_spec()).await;
            let mut peer = Peer::adopt(client, cwd.clone()).await;
            let session = peer.new_session(model).await;
            peer.prompt(&session, "turn-one").await;
            let sandbox = peer.stop().await;
            std::fs::write(cwd.join("CLAUDE.md"), format!("{LATE_CANARY}\n")).expect("late file");

            let client = RawStdioClient::spawn_with_spec(&server, &cwd, sandbox, &trusted_spec()).await;
            let mut peer = Peer::adopt(client, cwd.clone()).await;
            peer.load(model, &session).await;
            peer.prompt(&session, "turn-two").await;
            once(&server, "turn-two", "trusted load");
            assert_eq!(hits(&turn_body(&server, "turn-two"), LATE_CANARY), 0, "{model}: no history, no delivery");
            let sandbox = peer.stop().await;
            let context = std::fs::read_to_string(session_dir(&sandbox, &session).join("prompt_context.json"));
            assert!(context.expect("prompt context").contains("CLAUDE.md"), "{model}: premise: a recognized file");
            let saved = history(&sandbox, &session);
            assert!(!saved.contains("project_files_withheld"));
            assert_eq!(hits(&saved, LATE_CANARY), 0, "{model}");
            assert_eq!(saved.contains(REMINDER_TAG), model != PLAN_MODEL, "premise: the {model} branch ran");
            if let Ok(path) = std::env::var("U38_DUMP") {
                let bodies: Vec<String> = server.request_bodies().iter().map(Value::to_string).collect();
                std::fs::write(format!("{path}.{model}"), bodies.join("\n")).expect("dump");
            }
        }
    });
}

#[test]
fn a_sibling_session_applies_at_its_own_next_turn() {
    local(async {
        let server = server().await;
        let sandbox = sandbox(&server);
        let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
        let first = peer.new_session(DEFAULT_MODEL).await;
        let second = peer.new_session(DEFAULT_MODEL).await;
        peer.prompt(&first, "first-one").await;
        peer.prompt(&second, "second-one").await;
        peer.release().await;
        peer.prompt(&first, "first-two").await;
        once(&server, "first-two", "the prompting session");
        peer.prompt(&second, "second-two").await;
        once(&server, "second-two", "its sibling");
        peer.stop().await;
    });
}

#[test]
fn a_grant_before_the_first_prompt_and_a_second_after_reach_the_first_request() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            let server = server().await;
            let sandbox = sandbox(&server);
            let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
            let session = peer.new_session(model).await;
            peer.prompt(&session, "turn-one").await;
            once(&server, "turn-one", "grant before the first prompt");
            peer.stop().await;

            let sandbox = self::sandbox(&server);
            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            let session = peer.new_session(model).await;
            peer.prompt_releasing_after(&session, "turn-one-late", Duration::from_secs(1)).await;
            once(&server, "turn-one-late", "grant a second after the first prompt");
            peer.stop().await;
        }
    });
}

fn expect_spawn(
    server: &MockInferenceServer,
    model: &str,
    call: &str,
    task: &str,
) -> fuigo_test_support::InferenceExpectation {
    let args = json!({ "description": "u38 child", "prompt": task, "subagent_type": "general-purpose" });
    server.expect_response(
        call,
        InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
        ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
            "",
            call,
            "spawn_subagent",
            &args.to_string(),
            model,
        )),
    )
}

/// The model's spawn tool has no fork: its child is new and reads the folder's verdict for itself.
#[test]
fn a_new_child_follows_the_folder_and_carries_the_file_once() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            let server = server().await;
            let sandbox = sandbox(&server);
            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            let session = peer.new_session(model).await;
            peer.prompt(&session, "turn-one").await;
            let _a = expect_spawn(&server, model, "call_a", "child-untrusted");
            peer.prompt(&session, "turn-two").await;
            assert_eq!(hits(&child_body(&server, "child-untrusted"), CANARY), 0, "{model}: an untrusted child");

            peer.release().await;
            let _b = expect_spawn(&server, model, "call_b", "child-trusted");
            peer.prompt(&session, "turn-three").await;
            assert_eq!(hits(&child_body(&server, "child-trusted"), CANARY), 1, "{model}: fork after delivery");
            peer.stop().await;
        }
    });
}

#[test]
fn a_trusted_parents_new_child_has_one_copy() {
    local(async {
        let server = server().await;
        let sandbox = sandbox(&server);
        let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
        let session = peer.new_session(PLAN_MODEL).await;
        peer.settle(3).await;
        peer.prompt(&session, "turn-one").await;
        let _a = expect_spawn(&server, PLAN_MODEL, "call_a", "child-of-trusted");
        peer.prompt(&session, "turn-two").await;
        assert_eq!(hits(&child_body(&server, "child-of-trusted"), CANARY), 1, "trusted plan parent");
        peer.stop().await;
    });
}

fn expect_resume(
    server: &MockInferenceServer,
    model: &str,
    call: &str,
    child: &str,
    task: &str,
) -> fuigo_test_support::InferenceExpectation {
    let args = json!({
        "description": "u38 child", "prompt": task, "subagent_type": "general-purpose", "resume_from": child,
    });
    server.expect_response(
        call,
        InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
        ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
            "",
            call,
            "spawn_subagent",
            &args.to_string(),
            model,
        )),
    )
}

/// What a parent has behind it when it forks. `/goal` is the only fork a client can drive and it runs between turns, where
/// even a failed turn leaves a complete tail, so these are mirror forks: the summarized route (an incomplete tail or a
/// parent over 80% of the window) and the disk fallback have unit tests. A parent holding nothing but a compaction summary
/// has nothing to inherit and opens a new child, so `Compacted` has the tool call after the compaction.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Tail {
    Compacted,
    ToolCall,
}

const TAILS: [Tail; 2] = [Tail::Compacted, Tail::ToolCall];
const GOAL: &str = "/goal u38 objective marker";
const OBJECTIVE: &str = "u38 objective marker";

impl Peer {
    async fn leave_tail(&mut self, server: &MockInferenceServer, session: &str, model: &str, tail: Tail) {
        if tail == Tail::Compacted {
            self.compact(session).await;
        }
        let _call = expect_spawn(server, model, "call_tail", "tail-child");
        let _refused = server.expect_response(
            "refused",
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::json(400, json!({ "error": { "message": "u38 refused" } })),
        );
        let params = json!({ "sessionId": session, "prompt": [{ "type": "text", "text": "turn-tail" }] });
        let _ = self.call("session/prompt", params).await;
    }

    /// The fork `/goal` made, checked to be the route under test.
    fn forked_child(&self, kind: &str, what: &str) -> String {
        let children = forks(self.client.sandbox());
        assert_eq!(children.len(), 1, "{what}: {children:?}");
        let child = children.into_iter().next().expect("one child");
        assert_eq!(fork_kind(self.client.sandbox(), &child), kind, "{what}");
        child
    }
}

/// The grant lands after the fork of an untrusted parent. The child kept the bit, so its next open delivers once.
#[test]
fn a_grant_after_a_fork_reaches_the_child_once() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            for tail in TAILS {
                let what = format!("{model}, {tail:?}");
                let server = server().await;
                let sandbox = sandbox(&server);
                let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
                let session = peer.new_session(model).await;
                peer.prompt(&session, "turn-one").await;
                peer.leave_tail(&server, &session, model, tail).await;
                peer.prompt(&session, GOAL).await;
                let child = peer.forked_child("forked_verbatim", &what);
                let inherited = history(peer.client.sandbox(), &child);
                assert!(inherited.contains("project_files_withheld"), "{what}: the child's bit");
                assert_eq!(hits(&inherited, CANARY), 0, "{what}");
                every_request(&server, OBJECTIVE, 0, &what);

                peer.release().await;
                let _resume = expect_resume(&server, model, "call_b", &child, "child-after");
                peer.prompt(&session, "turn-three").await;
                assert_eq!(hits(&child_body(&server, "child-after"), CANARY), 1, "{what}: the child after the grant");
                once(&server, "turn-three", "and the parent");
                let sandbox = peer.stop().await;
                // A resume copies the child into a session of its own, whose user turn is the task.
                let resumed = user_history_holding(&sandbox, &session, "child-after");
                assert!(!resumed.contains("project_files_withheld") && hits(&resumed, CANARY) == 1, "{what}: delivered");
            }
        }
    });
}

/// Forked after delivery: the child has the file and no bit, as a trusted parent's does.
#[test]
fn a_fork_after_delivery_carries_the_file_once() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            for tail in TAILS {
                let what = format!("{model}, {tail:?}");
                let server = server().await;
                let sandbox = sandbox(&server);
                let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
                let session = peer.new_session(model).await;
                peer.prompt(&session, "turn-one").await;
                peer.release().await;
                peer.prompt(&session, "turn-two").await;
                peer.leave_tail(&server, &session, model, tail).await;
                peer.prompt(&session, GOAL).await;
                let child = peer.forked_child("forked_verbatim", &what);
                every_request(&server, OBJECTIVE, 1, &what);
                let sandbox = peer.stop().await;
                assert!(!history(&sandbox, &child).contains("project_files_withheld"), "{what}: no bit");
            }
        }
    });
}

#[test]
fn a_trusted_plan_parents_fork_has_one_copy_and_no_bit() {
    local(async {
        for tail in TAILS {
            let what = format!("{tail:?}");
            let server = server().await;
            let sandbox = sandbox(&server);
            let cwd = sandbox.workspace().to_path_buf();
            let client = RawStdioClient::spawn_with_spec(&server, &cwd, sandbox, &trusted_spec()).await;
            let mut peer = Peer::adopt(client, cwd).await;
            let session = peer.new_session(PLAN_MODEL).await;
            peer.prompt(&session, "turn-one").await;
            peer.leave_tail(&server, &session, PLAN_MODEL, tail).await;
            peer.prompt(&session, GOAL).await;
            let child = peer.forked_child("forked_verbatim", &what);
            every_request(&server, OBJECTIVE, 1, &what);
            let sandbox = peer.stop().await;
            assert!(!history(&sandbox, &child).contains("project_files_withheld"), "{what}: no bit");
        }
    });
}

/// `/goal` forks between turns, the one caller whose parent tail is complete, so its planner is a verbatim mirror.
#[test]
fn a_mirror_fork_carries_the_file_once_and_an_untrusted_one_keeps_the_bit() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            for delivered_first in [true, false] {
                let what = format!("{model}, delivered first {delivered_first}");
                let server = server().await;
                let sandbox = sandbox(&server);
                let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
                let session = peer.new_session(model).await;
                peer.prompt(&session, "turn-one").await;
                if delivered_first {
                    peer.release().await;
                    peer.prompt(&session, "turn-two").await;
                }
                peer.prompt(&session, GOAL).await;
                let child = peer.forked_child("forked_verbatim", &what);
                let inherited = history(peer.client.sandbox(), &child);
                assert_eq!(hits(&inherited, CANARY), usize::from(delivered_first), "{what}: the child's history");
                assert_eq!(inherited.contains("project_files_withheld"), !delivered_first, "{what}: the child's bit");
                every_request(&server, OBJECTIVE, usize::from(delivered_first), &what);

                if !delivered_first {
                    peer.release().await;
                    peer.prompt(&session, "turn-three").await;
                    once(&server, "turn-three", "the parent after the grant");
                }
                peer.stop().await;
            }
        }
    });
}

/// A client sets the display cwd on `session/load`; `session/new` has no such option. Both delivery routes: a live grant
/// after the load, and a load that opens trusted.
#[test]
fn a_grant_under_a_display_cwd_delivers_one_copy_and_survives_a_load() {
    const DISPLAY: &str = "/u38/display/repo";
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            for live in [true, false] {
                let what = format!("{model}, live {live}");
                let server = server().await;
                let sandbox = sandbox(&server);
                plant_user_file(&sandbox);
                let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
                let session = peer.new_session(model).await;
                peer.prompt(&session, "turn-one").await;
                let sandbox = peer.stop().await;
                let sandbox = if live { sandbox } else { grant_elsewhere(&server, sandbox).await };

                let reply = if live { Reply::Hold } else { Reply::Trust };
                let mut peer = Peer::start(&server, sandbox, reply).await;
                peer.display_cwd = Some(DISPLAY);
                peer.load(model, &session).await;
                if live {
                    peer.release().await;
                }
                peer.prompt(&session, "turn-two").await;
                once(&server, "turn-two", &what);
                let body = turn_body(&server, "turn-two");
                assert!(body.contains(&format!("{DISPLAY}/AGENTS.md")), "{what}: the display path");
                assert_eq!(hits(&body, USER_CANARY), 1, "{what}: the user file stays apart from the project set");
                let sandbox = peer.stop().await;

                let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
                peer.display_cwd = Some(DISPLAY);
                peer.load(model, &session).await;
                peer.prompt(&session, "turn-three").await;
                once(&server, "turn-three", "display cwd, loaded again");
                peer.stop().await;
            }
        }
    });
}

fn append_only(path: &std::path::Path, on: bool) -> bool {
    std::process::Command::new("chattr")
        .arg(if on { "+a" } else { "-a" })
        .arg(path)
        .status()
        .is_ok_and(|status| status.success())
}

#[ignore = "needs root and chattr to inject the write failure; the release gate runs it with --ignored"]
/// The load's history writes fail. A load writes twice, by two routes, and both replace the file, so the fault is a file
/// that takes appends and refuses replacement: memory has the delivery, the bit stays on disk, the next load delivers once.
/// Needs a filesystem and a user that can set append-only, and fails loudly on any other: it proves nothing without the fault.
#[test]
fn a_failed_history_write_on_load_delivers_once_on_the_next_load() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            let server = server().await;
            let sandbox = sandbox(&server);
            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            let session = peer.new_session(model).await;
            peer.prompt(&session, "turn-one").await;
            let sandbox = peer.stop().await;
            let sandbox = grant_elsewhere(&server, sandbox).await;
            let chat = session_dir(&sandbox, &session).join("chat_history.jsonl");
            assert!(
                append_only(&chat, true),
                "the fault can't be set: this test needs `chattr +a`, so a root user on ext4 or similar"
            );

            let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
            peer.load(model, &session).await;
            peer.prompt(&session, "turn-two").await;
            once(&server, "turn-two", "delivered in memory");
            let sandbox = peer.stop().await;
            assert!(append_only(&chat, false), "clear the fault");
            assert!(history(&sandbox, &session).contains("project_files_withheld"), "premise: the write failed");

            let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
            peer.load(model, &session).await;
            peer.prompt(&session, "turn-three").await;
            once(&server, "turn-three", "the next load delivers once");
            let sandbox = peer.stop().await;
            let saved = history(&sandbox, &session);
            assert_eq!(hits(&saved, CANARY), 1, "{model}: one stored copy");
            assert!(!saved.contains("project_files_withheld"), "{model}: bit cleared with the delivery");
        }
    });
}

/// The live grant's history write fails: the conversation stays as stored, and the next start delivers once.
#[test]
fn a_failed_history_write_on_a_live_grant_delivers_at_the_next_start() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
          for compact_first in [false, true] {
            let server = server().await;
            let sandbox = sandbox(&server);
            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            let session = peer.new_session(model).await;
            peer.prompt(&session, "turn-one").await;
            peer.settle(1).await;
            let chat = session_dir(peer.client.sandbox(), &session).join("chat_history.jsonl");
            let stored = std::fs::read(&chat).expect("stored history");
            std::fs::remove_file(&chat).expect("take the path");
            std::fs::create_dir(&chat).expect("a rename can't land on this");
            std::fs::write(chat.join("full"), "x").expect("non-empty");

            peer.release().await;
            peer.prompt(&session, "turn-two").await;
            assert_eq!(hits(&turn_body(&server, "turn-two"), CANARY), 0, "{model}: the refused write left the head as stored");

            std::fs::remove_dir_all(&chat).expect("clear the fault");
            std::fs::write(&chat, stored).expect("restore");
            if compact_first {
                peer.compact(&session).await;
            }
            peer.prompt(&session, "turn-three").await;
            once(&server, "turn-three", "the next start delivers once");
            peer.prompt(&session, "turn-four").await;
            once(&server, "turn-four", "and stays once");
            peer.stop().await;
          }
        }
    });
}

/// A reply ends the first turn's 2 s wait through the real request task, about 1.7 s early here. The wait only moves on
/// when that task ends, so a turn that beats the limit by this much proves the reply did it.
const WAIT_ENDED_EARLY: Duration = Duration::from_millis(1200);

#[test]
fn a_reject_ends_the_first_turns_wait_and_stays_gated() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            let server = server().await;
            let sandbox = sandbox(&server);
            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            let session = peer.new_session(model).await;
            let reply = json!({ "result": { "outcome": "reject" } });
            let took = peer.prompt_answering_held(&session, "turn-one", reply).await;
            assert!(took < WAIT_ENDED_EARLY, "{model}: {took:?}");
            assert_eq!(hits(&turn_body(&server, "turn-one"), CANARY), 0, "{model}: a reject stays gated");
            assert!(!peer.granted(), "{model}");
            peer.stop().await;
        }
    });
}

/// The branch a disconnect takes: the request itself fails, with no decision.
#[test]
fn a_failed_trust_request_ends_the_first_turns_wait_and_stays_gated() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            let server = server().await;
            let sandbox = sandbox(&server);
            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            let session = peer.new_session(model).await;
            let reply = json!({ "error": { "code": -32000, "message": "client gone" } });
            let took = peer.prompt_answering_held(&session, "turn-one", reply).await;
            assert!(took < WAIT_ENDED_EARLY, "{model}: {took:?}");
            assert_eq!(hits(&turn_body(&server, "turn-one"), CANARY), 0, "{model}: no decision stays gated");
            assert!(!peer.granted(), "{model}");
            peer.stop().await;
        }
    });
}

#[test]
fn red_default_agent_grant_reaches_turn_then_load() {
    local(grant_reaches_next_turn_and_load(DEFAULT_MODEL));
}

#[test]
fn red_plan_agent_grant_reaches_turn_then_load() {
    local(grant_reaches_next_turn_and_load(PLAN_MODEL));
}

/// How a project file fails at the grant. `AGENTS.md` as a directory is a read that fails, for any user: root ignores a
/// `chmod 000`, so that fault proves nothing on a root lane.
#[derive(Clone, Copy, Debug)]
enum Fault {
    Absent,
    ReadFails,
}

fn break_file(file: &std::path::Path, fault: Fault) {
    let away = file.with_extension("away");
    std::fs::rename(file, away).expect("move the file away");
    if matches!(fault, Fault::ReadFails) {
        std::fs::create_dir(file).expect("a read of this fails");
    }
}

fn restore_file(file: &std::path::Path, fault: Fault) {
    if matches!(fault, Fault::ReadFails) {
        std::fs::remove_dir(file).expect("clear the fault");
    }
    std::fs::rename(file.with_extension("away"), file).expect("put the file back");
}

/// The grant finds nothing: the list stays incomplete, the bit stays, and the next start rediscovers. A compaction in
/// between keeps the bit on the rebuilt head, so the next prompt and a later load both carry the file once.
#[test]
fn a_file_missing_at_the_grant_survives_a_compaction_and_reaches_the_next_prompt_and_a_load() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            for fault in [Fault::Absent, Fault::ReadFails] {
                let what = format!("{model}, {fault:?}");
                let server = server().await;
                let sandbox = sandbox(&server);
                let file = sandbox.workspace().join("AGENTS.md");
                let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
                let session = peer.new_session(model).await;
                peer.prompt(&session, "turn-one").await;
                break_file(&file, fault);
                peer.release().await;
                peer.prompt(&session, "turn-two").await;
                assert_eq!(hits(&turn_body(&server, "turn-two"), CANARY), 0, "{what}: premise");
                restore_file(&file, fault);
                peer.compact(&session).await;
                peer.prompt(&session, "turn-three").await;
                once(&server, "turn-three", &format!("{what}: next prompt"));
                let sandbox = peer.stop().await;

                let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
                peer.load(model, &session).await;
                peer.prompt(&session, "turn-four").await;
                once(&server, "turn-four", &format!("{what}: later load"));
                let sandbox = peer.stop().await;
                let saved = history(&sandbox, &session);
                assert_eq!(hits(&saved, CANARY), 1, "{what}: one stored copy");
                assert!(!saved.contains("project_files_withheld"), "{what}: delivered");
            }
        }
    });
}

/// Fix 3. A zero-turn harness rebuild with no project file to render keeps the obligation: the file restored afterwards
/// reaches the first prompt and a later load once, on either kind of agent.
#[test]
fn a_zero_turn_rebuild_from_an_empty_set_keeps_the_obligation() {
    local(async {
        for (from, to) in [(HARNESS_MODEL, PLAN_MODEL), (PLAN_MODEL, HARNESS_MODEL)] {
            for fault in [Fault::Absent, Fault::ReadFails] {
                let what = format!("{from} to {to}, {fault:?}");
                let server = server().await;
                let sandbox = sandbox(&server);
                let file = sandbox.workspace().join("AGENTS.md");
                let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
                let session = peer.new_session(from).await;
                break_file(&file, fault);
                peer.release().await;
                peer.set_model(&session, to).await;
                restore_file(&file, fault);
                peer.prompt(&session, "turn-one").await;
                once(&server, "turn-one", &format!("{what}: first prompt"));
                let sandbox = peer.stop().await;
                assert_eq!(history(&sandbox, &session).contains(REMINDER_TAG), to == HARNESS_MODEL, "{what}: premise");

                let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
                peer.load(to, &session).await;
                peer.prompt(&session, "turn-two").await;
                once(&server, "turn-two", &format!("{what}: later load"));
                let sandbox = peer.stop().await;
                let saved = history(&sandbox, &session);
                assert_eq!(hits(&saved, CANARY), 1, "{what}: one stored copy");
                assert!(!saved.contains("project_files_withheld"), "{what}: delivered");
            }
        }
    });
}

/// As above, with the load itself finding nothing: the rule at the open-with-history path.
#[test]
fn a_file_missing_at_a_trusted_load_survives_a_compaction() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            let server = server().await;
            let sandbox = sandbox(&server);
            let file = sandbox.workspace().join("AGENTS.md");
            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            let session = peer.new_session(model).await;
            peer.prompt(&session, "turn-one").await;
            let sandbox = peer.stop().await;
            let sandbox = grant_elsewhere(&server, sandbox).await;

            break_file(&file, Fault::Absent);
            let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
            peer.load(model, &session).await;
            peer.prompt(&session, "turn-two").await;
            assert_eq!(hits(&turn_body(&server, "turn-two"), CANARY), 0, "{model}: premise");
            restore_file(&file, Fault::Absent);
            peer.compact(&session).await;
            peer.prompt(&session, "turn-three").await;
            once(&server, "turn-three", "next prompt");
            peer.stop().await;
        }
    });
}

/// A tool call whose response reports a context far over any window, so the turn compacts inline before it continues.
fn over_the_window(model: &str, call: &str, path: &str) -> ScriptedResponse {
    let chunk = |delta: Value, finish: Value, usage: Value| {
        SseEvent::data(
            json!({
                "id": "chatcmpl-u38", "object": "chat.completion.chunk", "created": 0, "model": model,
                "choices": [{ "index": 0, "delta": delta, "finish_reason": finish }],
                "usage": usage,
            })
            .to_string(),
        )
    };
    let arguments = json!({ "target_file": path, "path": path, "file_path": path }).to_string();
    ScriptedResponse::sse(vec![
        chunk(json!({ "role": "assistant" }), Value::Null, Value::Null),
        chunk(
            json!({ "tool_calls": [{
                "index": 0, "id": call, "type": "function",
                "function": { "name": "read_file", "arguments": arguments },
            }]}),
            Value::Null,
            Value::Null,
        ),
        chunk(
            json!({}),
            json!("tool_calls"),
            json!({ "prompt_tokens": 50_000_000, "completion_tokens": 20, "total_tokens": 50_000_020 }),
        ),
        SseEvent::data("[DONE]"),
    ])
}

fn checkpoints(sandbox: &TestSandbox, session: &str) -> usize {
    std::fs::read_dir(session_dir(sandbox, session).join("compaction_checkpoints")).map_or(0, Iterator::count)
}

/// A process grant delivers, the restart is untrusted, and the load's history has no bit. A second grant must still
/// refresh the list at the next start, or an inline compaction in that very turn rebuilds a head without the file.
#[test]
fn a_second_process_grant_carries_the_file_through_an_inline_compaction() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            let server = server().await;
            let sandbox = sandbox(&server);
            std::fs::write(sandbox.workspace().join("note.txt"), "note").expect("note");
            let mut peer = Peer::start(&server, sandbox, Reply::TrustForProcess).await;
            let session = peer.new_session(model).await;
            peer.settle(3).await;
            peer.prompt(&session, "turn-one").await;
            once(&server, "turn-one", "process grant");
            let sandbox = peer.stop().await;

            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            peer.load(model, &session).await;
            peer.release().await;
            let _call = server.expect_response(
                "over the window",
                InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
                over_the_window(model, "call_big", "note.txt"),
            );
            peer.prompt(&session, "turn-two").await;
            assert_eq!(checkpoints(peer.client.sandbox(), &session), 1, "{model}: premise: the turn compacted inline");
            let last = server.request_bodies().last().map(Value::to_string).expect("a request");
            assert_eq!(hits(&last, CANARY), 1, "{model}: the continuation after the inline compaction");
            peer.stop().await;
        }
    });
}

impl Peer {
    async fn rewind(&mut self, session: &str, target: usize) {
        let params = json!({ "sessionId": session, "targetPromptIndex": target, "force": true, "mode": "all" });
        let done = self.call("_fuigo/rewind/execute", params).await;
        assert_eq!(done["result"]["success"], json!(true), "rewind {target}: {done}");
    }
}

/// A rewind across a compaction brings back a head from before the grant. The checkpoint recorded that the head held
/// the bit: the raw route (target before the compaction) re-marks it, the checkpoint route (target after it) stored it.
/// Either way the next prompt and a later load carry the file once.
#[test]
fn a_rewind_across_a_compaction_keeps_the_grants_repair() {
    local(async {
        for model in [DEFAULT_MODEL, PLAN_MODEL] {
            for target in [1, 2] {
                let what = format!("{model}, rewind to {target}");
                let server = server().await;
                let sandbox = sandbox(&server);
                let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
                let session = peer.new_session(model).await;
                peer.prompt(&session, "turn-one").await;
                peer.prompt(&session, "turn-two").await;
                peer.compact(&session).await;
                peer.release().await;
                peer.prompt(&session, "turn-three").await;
                once(&server, "turn-three", &format!("{what}: delivered"));
                peer.rewind(&session, target).await;
                peer.prompt(&session, "turn-four").await;
                once(&server, "turn-four", &format!("{what}: next prompt"));
                let sandbox = peer.stop().await;

                let mut peer = Peer::start(&server, sandbox, Reply::Trust).await;
                peer.load(model, &session).await;
                peer.prompt(&session, "turn-five").await;
                once(&server, "turn-five", &format!("{what}: later load"));
                let sandbox = peer.stop().await;
                assert!(!history(&sandbox, &session).contains("project_files_withheld"), "{what}: delivered");
            }
        }
    });
}

/// A rewind in a session that was trusted from the start leaves its checkpoint and head as they were: no new key.
#[test]
fn a_trusted_rewind_writes_no_checkpoint_key() {
    local(async {
        let server = server().await;
        let sandbox = sandbox(&server);
        let cwd = sandbox.workspace().to_path_buf();
        let client = RawStdioClient::spawn_with_spec(&server, &cwd, sandbox, &trusted_spec()).await;
        let mut peer = Peer::adopt(client, cwd).await;
        let session = peer.new_session(PLAN_MODEL).await;
        peer.prompt(&session, "turn-one").await;
        peer.prompt(&session, "turn-two").await;
        peer.compact(&session).await;
        peer.rewind(&session, 1).await;
        peer.prompt(&session, "turn-three").await;
        once(&server, "turn-three", "trusted rewind");
        let sandbox = peer.stop().await;
        assert!(!history(&sandbox, &session).contains("project_files_withheld"));
        let dir = session_dir(&sandbox, &session).join("compaction_checkpoints");
        for checkpoint in std::fs::read_dir(dir).expect("a checkpoint").flatten() {
            let text = std::fs::read_to_string(checkpoint.path()).expect("checkpoint");
            assert!(!text.contains("withheld"), "a trusted checkpoint is byte-identical: {text}");
        }
    });
}

/// A new child has no prefix. Built untrusted, it waits for the outstanding request at its first start; a grant in that
/// wait reaches its first request once, with or without a user-level file.
#[test]
fn a_grant_in_a_new_childs_first_wait_reaches_its_first_request() {
    local(async {
        for user_level in [false, true] {
            let server = server().await;
            let sandbox = sandbox(&server);
            if user_level {
                plant_user_file(&sandbox);
            }
            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            let session = peer.new_session(DEFAULT_MODEL).await;
            peer.prompt(&session, "turn-one").await;
            let _a = expect_spawn(&server, DEFAULT_MODEL, "call_a", "child-in-wait");
            peer.prompt_releasing_after(&session, "turn-two", Duration::from_millis(1200)).await;
            assert_eq!(hits(&child_body(&server, "child-in-wait"), CANARY), 1, "user level: {user_level}");
            peer.stop().await;
        }
    });
}

/// The session id of the one child holding `marker`.
fn child_holding(sandbox: &TestSandbox, parent: &str, marker: &str) -> String {
    let mut stack = vec![sandbox.fuigo_home().to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for path in entries.flatten().map(|e| e.path()) {
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n == "chat_history.jsonl")
                && !dir.to_string_lossy().contains(parent)
                && std::fs::read_to_string(&path).is_ok_and(|text| text.contains(marker))
            {
                return dir.file_name().expect("session dir").to_string_lossy().into_owned();
            }
        }
    }
    panic!("no child holds {marker}");
}

/// Built untrusted with no grant in sight: the child's first User item holds the bit, so a grant at any later turn delivers.
#[test]
fn a_new_child_built_untrusted_has_a_holder_for_a_later_grant() {
    local(async {
        for user_level in [false, true] {
            let what = format!("user level: {user_level}");
            let server = server().await;
            let sandbox = sandbox(&server);
            if user_level {
                plant_user_file(&sandbox);
            }
            let mut peer = Peer::start(&server, sandbox, Reply::Hold).await;
            let session = peer.new_session(DEFAULT_MODEL).await;
            peer.prompt(&session, "turn-one").await;
            let _a = expect_spawn(&server, DEFAULT_MODEL, "call_a", "child-first");
            peer.prompt(&session, "turn-two").await;
            assert_eq!(hits(&child_body(&server, "child-first"), CANARY), 0, "{what}: premise");
            let child = child_holding(peer.client.sandbox(), &session, "child-first");
            let stored = history(peer.client.sandbox(), &child);
            assert!(stored.contains("project_files_withheld"), "{what}: the child's bit");

            peer.release().await;
            let _b = expect_resume(&server, DEFAULT_MODEL, "call_b", &child, "child-later");
            peer.prompt(&session, "turn-three").await;
            assert_eq!(hits(&child_body(&server, "child-later"), CANARY), 1, "{what}: a later turn");
            peer.stop().await;
        }
    });
}

