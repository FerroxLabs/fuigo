//! Contract E conformance: Fuigo as Murage embeds it.
//!
//! Murage ships a Fuigo binary and drives it as an ACP agent over stdio. Every test here spawns the
//! REAL `fuigo` binary (`FUIGO_BINARY`) with Murage's argv and speaks to it the way Murage does, so a
//! change that would silently break the shipping embedder fails here first. Nothing of the thing under
//! test is mocked: only the inference/models endpoint is (`MockInferenceServer`).
//!
//! Wire assertions read raw newline-delimited JSON-RPC (`RawStdioClient`). The typed ACP client hides
//! both the leading `_` that ACP 0.10.4 adds to every extension method at send time and the exact key
//! spellings (`_meta` vs `meta`), and those are the facts Contract E.5a / E.7 turn on.
//!
//! Hermeticity: each test owns a `TestSandbox` (own `HOME`, `FUIGO_HOME`, `TMPDIR`, cleared env) and
//! asserts that the child actually used it. No test calls `std::env::set_var`, so the tests in this
//! binary may run in parallel: the child env is set per spawn, never on the parent.
//!
//! Clause map (Contract E, `docs/strike/contracts/E-downstream-embedder-compatibility.md`):
//! E.1 argv: `murage_exact_argv_is_accepted`, `murage_argv_flags_still_exist_with_their_spellings`,
//!   `permission_mode_flag_governs_tool_approval`, `model_and_reasoning_effort_flags_reach_inference`,
//!   `no_leader_flag_keeps_the_agent_standalone_when_config_enables_leader`, `no_memory_flag_withholds_memory_tools`.
//! E.2 credential injection: `injected_fuigo_api_key_authenticates`, `injected_env_key_still_authenticates_and_is_not_persisted`.
//! E.2 / P08 runtime key (`authenticate` `_meta["fuigo/apiKey"]`): `runtime_api_key_authenticates_with_no_env_or_config_key`,
//!   `runtime_api_key_leaves_an_existing_auth_json_byte_identical`, `runtime_api_key_is_persisted_when_the_client_opts_in`,
//!   `runtime_api_key_is_invisible_to_child_processes`, `runtime_api_key_never_reaches_errors_logs_or_disk`,
//!   `runtime_api_key_survives_debug_logging_on_the_success_path`, `set_api_key_clear_drops_the_runtime_key`,
//!   `malformed_wire_lines_carrying_the_key_reach_no_log`, `set_api_key_clear_with_a_mapped_model_hands_out_nothing`,
//!   `p08_auth_wire_matches_golden`.
//! E.2 / P70 saved key (`auth.json`, held in memory, never in the agent's env): `auth_json_key_authenticates_and_reaches_no_tool_child`,
//!   `injected_env_key_outranks_the_auth_json_key`, `set_api_key_key_authenticates_and_reaches_no_tool_child`,
//!   `client_terminal_child_does_not_inherit_the_saved_key` (the one that fails if the key is put back into the env),
//!   `session_new_mcp_header_and_env_secrets_reach_no_log`.
//! E.3 auth negotiation: `initialize_advertises_fuigo_api_key_and_names_it_default`,
//!   `no_credential_yields_empty_auth_methods_and_minus_32000`.
//! E.4 protocol version: `protocol_version_one_is_accepted`.
//! E.5 / E.5a folder trust: `folder_trust_round_trip_without_trust_flag`, `trust_flag_suppresses_the_round_trip`.
//! E.6 / E.5a MCP ready and the other `_fuigo/*` names Murage binds: `mcp_ready_notification_wire_name_is_pinned`,
//!   `murage_mcp_server_elicit_and_ready_wire_names`, `ask_user_question_round_trip_wire_name_is_pinned`,
//!   `ask_user_question_waits_for_murage_past_the_non_interactive_cap` (P04 consult).
//! E.7 model state: `meta_model_state_matches_golden`.
//! E.8 wire path: `murage_wire_path_fields_round_trip`.
// Test, bench or example code: its prints reach a harness or a developer, never a user, so the
// workspace print deny (R077) is waived here.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::Path;
use std::time::Duration;

use agent_client_protocol as acp;
use fuigo_test_support::scripted::ScriptedResponse;
use fuigo_test_support::sse::chat_completions_reasoning_then_tool_call_events;
use fuigo_test_support::{
    AgentSpawnSpec, FuigoStdioClient, InferenceEndpoint, InferenceRequestMatcher,
    MockInferenceServer, MockModelEntry, RawReply, RawStdioClient, TestProcess, TestProcessConfig, TestSandbox,
    TestStdin, fuigo_binary, scaled,
};
#[cfg(unix)]
use fuigo_test_support::{PidLiveness, pid_liveness, sigkill};
use serde_json::{Value, json};

/// Per-request budget; `RawStdioClient` scales it with `FUIGO_TEST_TIMEOUT_SCALE`.
const RPC: Duration = Duration::from_secs(30);
/// The default model of the catalog below (first entry) and its catalog-default effort.
const MODEL_A: &str = "murage-model-a";
/// A second model, so `-m` has something to change.
const MODEL_B: &str = "murage-model-b";
/// The key Murage injects. Distinct from the sandbox's `test-key-for-ci` so the bearer proves which key was used.
const INJECTED_KEY: &str = "murage-injected-key-p00";
/// A release-version stamp at runtime: without it folder trust is inert on an unstamped build and the
/// trust tests would pass vacuously (`fuigo-workspace/src/folder_trust.rs` `is_local_build`).
const TEST_VERSION: (&str, &str) = ("FUIGO_TEST_VERSION", "1.0.21-p00");
/// The project-scoped MCP server the trust tests plant; its appearance in `_fuigo/mcp/servers_updated`
/// is the observable proof that project config was applied.
const PROJECT_SERVER: &str = "murage-p00-project";

const GLOBAL_DEFAULT: &[&str] = &["--permission-mode", "default", "--no-memory"];
const GLOBAL_BYPASS: &[&str] = &["--permission-mode", "bypassPermissions", "--no-memory"];
const GLOBAL_DEFAULT_TRUST: &[&str] = &["--permission-mode", "default", "--trust", "--no-memory"];
/// Murage's agent half: `--no-leader [-m <model>] [--reasoning-effort <effort>] stdio`.
const AGENT_MURAGE: &[&str] = &["--no-leader", "-m", MODEL_B, "--reasoning-effort", "high"];

fn catalog() -> Vec<MockModelEntry> {
    vec![
        MockModelEntry::new(MODEL_A)
            .with_supports_reasoning_effort(true)
            .with_reasoning_efforts(vec![json!("low"), json!("high")]),
        MockModelEntry::new(MODEL_B),
    ]
}

/// Murage's `initialize` params, verbatim in shape (`server/drivers/acp/core.ts`, the `initialize` request):
/// `protocolVersion: 1`, no `clientInfo`, and the folder-trust capability under `clientCapabilities._meta`.
fn murage_initialize_params() -> Value {
    json!({
        "protocolVersion": 1,
        "clientCapabilities": {
            "fs": { "readTextFile": false, "writeTextFile": false },
            "elicitation": { "form": {}, "url": {} },
            "_meta": { "fuigo/folderTrust": { "interactive": true } }
        }
    })
}

/// Never answer an agent-to-client request (the client refuses with -32601).
fn refuse(_: &Value) -> Option<Value> {
    None
}

fn method_of(msg: &Value) -> Option<&str> {
    msg.get("method").and_then(Value::as_str)
}

fn object_keys(v: &Value) -> Vec<String> {
    let mut keys: Vec<String> = v
        .as_object()
        .unwrap_or_else(|| panic!("expected a JSON object, got {v}"))
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

fn sorted(keys: &[&str]) -> Vec<String> {
    let mut keys: Vec<String> = keys.iter().map(|k| (*k).to_owned()).collect();
    keys.sort();
    keys
}

/// The child really ran inside the sandbox. On Linux the child's OWN environment is read back from
/// `/proc/<pid>/environ` (observed, not the sandbox's intent); elsewhere the sandbox's applied env is the
/// best available evidence. The child must also have created its `agent_id` in the sandbox `FUIGO_HOME`.
/// Residual: this proves where the child was pointed and where it wrote, not that it read nothing else.
fn assert_hermetic(sandbox: &TestSandbox, child_pid: Option<u32>) {
    let expected = [
        ("HOME", sandbox.home()),
        ("USERPROFILE", sandbox.home()),
        ("FUIGO_HOME", sandbox.fuigo_home()),
        ("TMPDIR", sandbox.temp_dir()),
    ];
    #[cfg(target_os = "linux")]
    let observed: Vec<(String, String)> = {
        let pid = child_pid.expect("the agent must still be running when hermeticity is checked");
        std::fs::read(format!("/proc/{pid}/environ"))
            .unwrap_or_else(|e| panic!("read /proc/{pid}/environ: {e}"))
            .split(|b| *b == 0)
            .filter_map(|kv| {
                let kv = String::from_utf8_lossy(kv);
                kv.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned()))
            })
            .collect()
    };
    #[cfg(not(target_os = "linux"))]
    let observed: Vec<(String, String)> = {
        let _ = child_pid;
        sandbox
            .env()
            .into_iter()
            .map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned()))
            .collect()
    };
    for (key, path) in expected {
        let got = observed.iter().find(|(k, _)| k == key).map(|(_, v)| Path::new(v.as_str()));
        assert_eq!(got, Some(path), "the child's own {key} is not the sandbox's");
    }
    assert!(
        sandbox.fuigo_home().join("agent_id").is_file(),
        "the child never created agent_id in the sandbox FUIGO_HOME {}: it ran against some other home",
        sandbox.fuigo_home().display()
    );
}

/// Record, once per test binary, which `fuigo` binary is under test. `fuigo_binary()` falls back to a
/// `target/debug` build when `FUIGO_BINARY` is unset; the gate always sets it, and this line makes a run
/// that did not traceable in its log.
fn log_binary_identity() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let bin = fuigo_binary();
        let meta = std::fs::metadata(&bin).ok();
        eprintln!(
            "[p00] FUIGO_BINARY={:?} resolved={} bytes={:?} modified={:?}",
            std::env::var_os("FUIGO_BINARY"),
            bin.display(),
            meta.as_ref().map(|m| m.len()),
            meta.and_then(|m| m.modified().ok()),
        );
    });
}

/// One spawned Murage-shaped agent plus its mock endpoint.
struct Murage {
    client: RawStdioClient,
    server: MockInferenceServer,
    workspace: std::path::PathBuf,
    next_id: u32,
}

impl Murage {
    async fn spawn(spec: AgentSpawnSpec<'_>, prepare: impl FnOnce(&TestSandbox)) -> Self {
        let server = MockInferenceServer::start_with_models(catalog())
            .await
            .expect("start mock server");
        log_binary_identity();
        let sandbox = TestSandbox::new();
        prepare(&sandbox);
        let workspace = sandbox.workspace().to_path_buf();
        let client = RawStdioClient::spawn_with_spec(&server, &workspace, sandbox, &spec).await;
        Self {
            client,
            server,
            workspace,
            next_id: 0,
        }
    }

    async fn call<R: Into<RawReply>>(
        &mut self,
        method: &str,
        params: Value,
        answer: impl FnMut(&Value) -> R,
    ) -> Value {
        self.next_id += 1;
        let id = format!("murage-{}", self.next_id);
        let reply = self.client.request(&id, method, params, RPC, answer).await;
        assert_eq!(reply["jsonrpc"], "2.0", "{method}: not a JSON-RPC 2.0 reply: {reply}");
        reply
    }

    /// `initialize` with Murage's params; returns the whole reply.
    async fn initialize(&mut self) -> Value {
        self.call("initialize", murage_initialize_params(), refuse).await
    }

    /// Murage's sequence: `initialize`, `authenticate {methodId: "fuigo.api_key"}`, `session/new`. Returns the session id.
    async fn connect<R: Into<RawReply>>(&mut self, answer: impl FnMut(&Value) -> R) -> String {
        self.connect_with(answer, json!([])).await
    }

    /// [`Self::connect`] with Murage's `mcpServers` on `session/new`.
    async fn connect_with<R: Into<RawReply>>(
        &mut self,
        answer: impl FnMut(&Value) -> R,
        mcp_servers: Value,
    ) -> String {
        let init = self.initialize().await;
        assert!(init.get("result").is_some(), "initialize failed: {init}");
        let auth = self
            .call("authenticate", json!({ "methodId": "fuigo.api_key" }), refuse)
            .await;
        assert_eq!(auth.get("result"), Some(&json!({})), "authenticate: {auth}");
        let ws = self.workspace.clone();
        let new = self
            .call("session/new", json!({ "cwd": ws, "mcpServers": mcp_servers }), answer)
            .await;
        new["result"]["sessionId"]
            .as_str()
            .unwrap_or_else(|| panic!("session/new returned no sessionId: {new}"))
            .to_owned()
    }

    async fn prompt<R: Into<RawReply>>(
        &mut self,
        session_id: &str,
        text: &str,
        answer: impl FnMut(&Value) -> R,
    ) -> Value {
        self.call(
            "session/prompt",
            json!({ "sessionId": session_id, "prompt": [{ "type": "text", "text": text }] }),
            answer,
        )
        .await
    }

    fn sandbox(&self) -> &TestSandbox {
        self.client.sandbox()
    }

    fn child_pid(&self) -> Option<u32> {
        self.client.child_pid()
    }

    /// The first message matching `matches`, whether it ALREADY arrived (for example while `session/new`
    /// was in flight, which is when the agent starts its asynchronous trust prompt and MCP setup) or
    /// arrives before `timeout`. Non-matching agent-to-client requests are answered by `answer`.
    async fn seen_or_wait<R: Into<RawReply>>(
        &mut self,
        what: &str,
        timeout: Duration,
        matches: impl Fn(&Value) -> bool,
        answer: impl FnMut(&Value) -> R,
    ) -> Option<Value> {
        if let Some(found) = self.messages().into_iter().find(|m| matches(m)) {
            return Some(found);
        }
        self.client.wait_for_message(what, timeout, &matches, answer).await
    }

    fn methods_seen(&self) -> Vec<String> {
        self.messages()
            .iter()
            .filter_map(|x| method_of(x).map(str::to_owned))
            .collect()
    }

    /// Every message the agent wrote so far, parsed.
    fn messages(&self) -> Vec<Value> {
        self.client
            .transcript()
            .iter()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    fn messages_named(&self, method: &str) -> Vec<Value> {
        self.messages()
            .into_iter()
            .filter(|m| method_of(m) == Some(method))
            .collect()
    }

    /// Foreground chat-completions requests the agent made, in order.
    fn chat_requests(&self) -> Vec<fuigo_test_support::mock_server::LogEntry> {
        self.server
            .requests()
            .into_iter()
            .filter(|r| r.path == "/v1/chat/completions")
            .collect()
    }

    fn stderr(&self) -> String {
        self.client.stderr()
    }
}

/// Plant a trust-gated project config: a project `.mcp.json` declaring one stdio server.
fn plant_project_mcp(sandbox: &TestSandbox) {
    std::fs::write(
        sandbox.workspace().join(".mcp.json"),
        json!({ "mcpServers": { PROJECT_SERVER: { "command": "/nonexistent/murage-p00-project", "args": [] } } })
            .to_string(),
    )
    .expect("write project .mcp.json");
}

fn lists_project_server(msg: &Value) -> bool {
    method_of(msg) == Some("_fuigo/mcp/servers_updated")
        && msg["params"]["mcpServers"]
            .as_array()
            .is_some_and(|s| s.iter().any(|e| e["name"] == PROJECT_SERVER))
}

// ---------------------------------------------------------------------------------------------
// E.1 — process spawn surface
// ---------------------------------------------------------------------------------------------

/// E.1: the verbatim Murage argv is accepted and a full turn runs, for both permission modes and with
/// `--trust`. Driven through the typed `FuigoStdioClient`, which authenticates with `fuigo.api_key`.
#[tokio::test(flavor = "current_thread")]
async fn murage_exact_argv_is_accepted() {
    for global in [GLOBAL_DEFAULT, GLOBAL_BYPASS, GLOBAL_DEFAULT_TRUST] {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let server = MockInferenceServer::start_with_models(catalog())
                    .await
                    .expect("start mock server");
                let sandbox = TestSandbox::new();
                let workspace = sandbox.workspace().to_path_buf();
                let spec = AgentSpawnSpec {
                    leading_args: global,
                    agent_args: AGENT_MURAGE,
                    ..AgentSpawnSpec::default()
                };
                let argv = spec.argv();
                let mut client =
                    FuigoStdioClient::spawn_with_spec(&server, &workspace, sandbox, &spec).await;
                let init = client.initialize_with_timeout().await;
                assert_eq!(init.protocol_version, acp::ProtocolVersion::V1, "{argv:?}");
                let session = client.create_session_with_timeout(&workspace).await;
                let response = client
                    .prompt_with_timeout(&session, "hello murage")
                    .await
                    .unwrap_or_else(|e| panic!("{argv:?}: prompt failed: {e:?}\n{}", client.stderr()));
                assert_eq!(response.stop_reason, acp::StopReason::EndTurn, "{argv:?}");
                assert!(
                    client.captured_text().contains("hello murage"),
                    "{argv:?}: the turn produced no echoed text: {:?}",
                    client.captured_text()
                );
                assert_hermetic(client.sandbox(), client.child_pid());
                let _ = client.close().await;
            })
            .await;
    }
}

/// Outcome of one short-lived CLI invocation.
struct CliRun {
    code: Option<i32>,
    killed: bool,
    stdout: String,
    stderr: String,
}

/// Run the real binary with `args` in a fresh sandbox, stdin closed; kill it if it outlives the deadline.
/// Used for clap-level probes: a rejected argv exits 2 with a message naming the flag. An argv that parses
/// starts the agent, which ends on stdin EOF. The child is owned by the shared `TestProcess` (process-tree
/// teardown), driven on a private current-thread runtime so callers stay synchronous.
fn run_cli(args: &[&str]) -> CliRun {
    let mut sandbox = TestSandbox::new();
    // An argv that parses starts the agent: point every endpoint at a closed loopback port so it can
    // never reach a real host.
    sandbox.set_mock_url("http://127.0.0.1:9/v1");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("probe runtime");
    runtime.block_on(async {
        let mut cmd = tokio::process::Command::new(fuigo_binary());
        cmd.args(args).current_dir(sandbox.workspace());
        let mut process = TestProcess::spawn(
            cmd,
            &sandbox,
            TestProcessConfig::new()
                .label("fuigo cli probe")
                .stdin(TestStdin::Null)
                .tail_bytes(256 * 1024),
        )
        .expect("spawn fuigo");
        let status = process
            .wait_with_deadline(scaled(Duration::from_secs(20)))
            .await
            .expect("wait for fuigo");
        let killed = status.is_none();
        if killed {
            let _ = process.kill().await;
        }
        CliRun {
            code: status.and_then(|s| s.code()),
            killed,
            stdout: process.stdout_tail().text,
            stderr: process.stderr_tail().text,
        }
    })
}

/// Whether clap refused the argv: exit 2 with clap's `error: ...` report, which ends in a `Usage:` line
/// (unknown argument, conflict, missing value) or `For more information, try '--help'.` (invalid value).
fn clap_rejected(run: &CliRun) -> bool {
    run.code == Some(2)
        && run.stderr.contains("error:")
        && (run.stderr.contains("Usage:") || run.stderr.contains("For more information, try '--help'"))
}

/// The argv parses AND the agent it starts runs cleanly: with stdin closed a healthy `agent stdio` ends on
/// EOF with exit 0. Probed WITHOUT `--help`, because clap does not validate values (e.g.
/// `--permission-mode`) when `--help` is present. A crash, a signal or a hang past the deadline fails.
fn assert_accepted(args: &[&str]) {
    let run = run_cli(args);
    assert!(
        run.code == Some(0) && !run.killed,
        "Murage's argv {args:?} must parse and start cleanly (exit 0 on stdin EOF); got code {:?} killed={} clap_rejected={}\nstderr:\n{}",
        run.code,
        run.killed,
        clap_rejected(&run),
        run.stderr
    );
}

fn assert_rejected_naming(args: &[&str], must_mention: &[&str]) {
    let run = run_cli(args);
    assert!(
        clap_rejected(&run),
        "{args:?} must be rejected at parse time; got code {:?} killed={}\nstderr:\n{}",
        run.code,
        run.killed,
        run.stderr
    );
    for needle in must_mention {
        assert!(
            run.stderr.contains(needle),
            "{args:?}: the parse error must mention {needle:?}; stderr:\n{}",
            run.stderr
        );
    }
}

/// E.1 at the parser: every flag Murage passes exists under exactly that spelling, in that position,
/// and is a real argument rather than something silently ignored. A spawn-only test passes when a flag
/// is ignored; here each flag is shown to be (a) accepted where Murage puts it and (b) wired: its value
/// is validated, or it takes part in a declared conflict, so a rename or removal changes the parse.
#[test]
fn murage_argv_flags_still_exist_with_their_spellings() {
    // The full argv, as Murage builds it, parses (both modes; with and without --trust).
    assert_accepted(&[
        "--permission-mode", "default", "--no-memory", "agent", "--no-leader", "-m", MODEL_B,
        "--reasoning-effort", "high", "stdio",
    ]);
    assert_accepted(&[
        "--permission-mode", "bypassPermissions", "--trust", "--no-memory", "agent", "--no-leader",
        "-m", MODEL_B, "--reasoning-effort", "high", "stdio",
    ]);
    // Aliases Murage or its users may rely on.
    assert_accepted(&["--trust-folder", "--no-memory", "agent", "--no-leader", "stdio"]);
    assert_accepted(&["--no-memory", "agent", "--no-leader", "--model", MODEL_B, "--effort", "high", "stdio"]);

    // Positive control for this probe itself: a misspelled flag in Murage's position is rejected, so
    // the accepts above mean the spellings exist rather than that anything parses.
    assert_rejected_naming(&["--no-memroy", "agent", "--no-leader", "stdio"], &["--no-memroy"]);
    assert_rejected_naming(&["--no-memory", "agent", "--no-leaderr", "stdio"], &["--no-leaderr"]);
    // `--permission-mode` validates its value against a fixed set that still contains both Murage values.
    assert_rejected_naming(
        &["--permission-mode", "not-a-mode", "agent", "--no-leader", "stdio"],
        &["--permission-mode", "default", "bypassPermissions"],
    );
    // `--no-memory` is the real flag: it conflicts with its opposite.
    assert_rejected_naming(
        &["--no-memory", "--experimental-memory", "agent", "--no-leader", "stdio"],
        &["--no-memory"],
    );
    // `--no-leader` is the real flag: it conflicts with `--leader`.
    assert_rejected_naming(&["agent", "--leader", "--no-leader", "stdio"], &["--no-leader"]);
    // `-m` and `--reasoning-effort` take a value: without one they are a parse error.
    assert_rejected_naming(&["agent", "--no-leader", "-m"], &["--model"]);
    assert_rejected_naming(&["agent", "--no-leader", "--reasoning-effort"], &["--reasoning-effort"]);

    // The `agent` help still documents the agent half of the argv and the `stdio` mode.
    let help = run_cli(&["agent", "--help"]);
    assert_eq!(help.code, Some(0), "agent --help: {}", help.stderr);
    for needle in ["--no-leader", "-m, --model", "--reasoning-effort", "effort", "stdio"] {
        assert!(help.stdout.contains(needle), "`fuigo agent --help` lost {needle:?}:\n{}", help.stdout);
    }
}

/// Script one foreground turn that calls `run_terminal_command` with `command`, then answers with text.
fn script_terminal_call(
    server: &MockInferenceServer,
    call_id: &str,
    command: &str,
) -> fuigo_test_support::InferenceExpectation {
    server.expect_response(
        call_id,
        InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
        ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
            "",
            call_id,
            "run_terminal_command",
            &json!({ "command": command, "description": "p00 conformance" }).to_string(),
            MODEL_B,
        )),
    )
}

/// E.1 semantics of the security-critical `--permission-mode`: under `default` a side-effecting tool call
/// asks the client (`session/request_permission`) and a rejection stops it; under `bypassPermissions` the
/// same call runs with no question asked.
#[tokio::test(flavor = "current_thread")]
async fn permission_mode_flag_governs_tool_approval() {
    for (global, expect_question) in [(GLOBAL_DEFAULT, true), (GLOBAL_BYPASS, false)] {
        let mut m = Murage::spawn(
            AgentSpawnSpec {
                leading_args: global,
                agent_args: AGENT_MURAGE,
                ..AgentSpawnSpec::default()
            },
            |sandbox| {
                std::fs::write(sandbox.workspace().join("p00-victim"), "x").expect("plant victim");
            },
        )
        .await;
        // `rm` is never on the safe auto-allow list (`touch`/`mkdir` are), so `default` must ask.
        let scripted = script_terminal_call(&m.server, "call_perm", "rm -f p00-victim");
        let session = m.connect(refuse).await;
        let mut questions = Vec::new();
        let reply = m
            .prompt(&session, "delete the victim", |req| {
                if method_of(req) != Some("session/request_permission") {
                    return None;
                }
                questions.push(req.clone());
                let reject = req["params"]["options"]
                    .as_array()
                    .and_then(|o| o.iter().find(|o| o["kind"] == "reject_once"))
                    .unwrap_or_else(|| panic!("no reject_once option offered: {req}"));
                Some(json!({ "outcome": { "outcome": "selected", "optionId": reject["optionId"] } }))
            })
            .await;
        assert!(reply.get("result").is_some(), "{global:?}: prompt failed: {reply}\n{}", m.stderr());
        scripted.assert_satisfied();
        let deleted = !m.workspace.join("p00-victim").exists();
        if expect_question {
            assert_eq!(
                questions.len(),
                1,
                "{global:?}: a side-effecting command must ask the client exactly once; asked {questions:?}"
            );
            assert!(!deleted, "{global:?}: the rejected command ran anyway");
        } else {
            assert!(
                questions.is_empty(),
                "{global:?}: bypassPermissions must not ask the client; asked {questions:?}"
            );
            assert!(deleted, "{global:?}: the command did not run\n{}", m.stderr());
        }
        assert_hermetic(m.sandbox(), m.child_pid());
    }
}

/// E.1 semantics of `-m` and `--reasoning-effort` (and the `--effort` alias): both reach the inference
/// request. The catalog default is `murage-model-a` at effort `low`, so an ignored flag shows up here.
#[tokio::test(flavor = "current_thread")]
async fn model_and_reasoning_effort_flags_reach_inference() {
    let cases: [(&[&str], &str, Option<&str>); 3] = [
        (&["--no-leader", "-m", MODEL_B], MODEL_B, None),
        (&["--no-leader", "-m", MODEL_A, "--reasoning-effort", "high"], MODEL_A, Some("high")),
        (&["--no-leader", "-m", MODEL_A, "--effort", "high"], MODEL_A, Some("high")),
    ];
    for (agent_args, model, effort) in cases {
        let mut m = Murage::spawn(
            AgentSpawnSpec {
                leading_args: GLOBAL_DEFAULT,
                agent_args,
                ..AgentSpawnSpec::default()
            },
            |_| {},
        )
        .await;
        let init = m.initialize().await;
        assert_eq!(
            init["result"]["_meta"]["modelState"]["currentModelId"], model,
            "{agent_args:?}: -m must select the model reported at initialize"
        );
        let _ = m
            .call("authenticate", json!({ "methodId": "fuigo.api_key" }), refuse)
            .await;
        let ws = m.workspace.clone();
        let new = m
            .call("session/new", json!({ "cwd": ws, "mcpServers": [] }), refuse)
            .await;
        let session = new["result"]["sessionId"].as_str().expect("sessionId").to_owned();
        let reply = m.prompt(&session, "hello murage", refuse).await;
        assert!(reply.get("result").is_some(), "{agent_args:?}: {reply}");
        let requests = m.chat_requests();
        let body = requests
            .last()
            .and_then(|r| r.body.clone())
            .unwrap_or_else(|| panic!("{agent_args:?}: no chat request reached the mock"));
        assert_eq!(body["model"], model, "{agent_args:?}: model on the wire");
        if let Some(effort) = effort {
            assert_eq!(body["reasoning_effort"], effort, "{agent_args:?}: effort on the wire");
        }
    }
}

/// E.1 semantics of `--no-leader`: with `[cli] use_leader = true` in the user config, `agent stdio` would
/// attach to (or start) a shared leader. Murage's `--no-leader` must keep the process standalone.
#[tokio::test(flavor = "current_thread")]
async fn no_leader_flag_keeps_the_agent_standalone_when_config_enables_leader() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            ..AgentSpawnSpec::default()
        },
        |sandbox| {
            std::fs::write(sandbox.fuigo_home().join("config.toml"), "[cli]\nuse_leader = true\n")
                .expect("write config.toml");
        },
    )
    .await;
    // Declared after `m`, so it drops first, including during a panic unwind, while the sandbox (and its
    // `leader.lock`) still exists.
    let _leader_guard = LeaderReaper {
        fuigo_home: m.sandbox().fuigo_home().to_path_buf(),
        follower_pid: m.child_pid(),
    };
    let session = m.connect(refuse).await;
    let reply = m.prompt(&session, "hello murage", refuse).await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    let leader_files: Vec<String> = walk_names(m.sandbox().root())
        .into_iter()
        .filter(|n| n.contains("leader"))
        .collect();
    assert!(
        leader_files.is_empty(),
        "--no-leader must not create or attach to a leader; found {leader_files:?}"
    );
    assert_hermetic(m.sandbox(), m.child_pid());
}

/// On drop, kills every process this test left behind and waits until none is left. A leader started by a
/// `--no-leader` regression detaches (`--no-exit-on-disconnect`, its own process group), so no
/// test-process teardown reaches it, and the follower (`agent stdio`) spawns and respawns leaders. So:
/// 1. SIGKILL the follower's process group and confirm the follower is dead (gone or a zombie). From then
///    on no process of this test can fork again.
/// 2. On Linux, kill every process whose OWN environment carries this sandbox's `FUIGO_HOME`, until a scan
///    finds none. That identity covers a leader at any stage, including a forked child that has left the
///    follower's group but not yet exec'd (it inherits the follower's environment), and it does not depend
///    on the leader having published its PID. Elsewhere the PID in `leader.lock` is used (residual).
/// Runs on every exit path, including unwinding.
struct LeaderReaper {
    fuigo_home: std::path::PathBuf,
    follower_pid: Option<u32>,
}

impl LeaderReaper {
    /// Live processes that belong to this sandbox.
    fn strays(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = std::fs::read_to_string(self.fuigo_home.join("leader.lock"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .into_iter()
            .collect();
        #[cfg(target_os = "linux")]
        {
            let want = format!("FUIGO_HOME={}", self.fuigo_home.display());
            let me = std::process::id();
            for entry in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
                let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                    continue;
                };
                if pid == me || pids.contains(&pid) {
                    continue;
                }
                let environ = std::fs::read(entry.path().join("environ")).unwrap_or_default();
                if environ.split(|b| *b == 0).any(|kv| kv == want.as_bytes()) {
                    pids.push(pid);
                }
            }
        }
        pids
    }

    /// Whether `pid` can no longer run, so can no longer fork. On Linux a zombie counts as finished (its owner,
    /// `TestProcess`, dropped after this guard, reaps it later). Elsewhere only a definite ESRCH from
    /// `kill(pid, 0)` does; `EPERM` and any other answer count as alive. Every probe is a direct syscall,
    /// so nothing here can block.
    #[cfg(unix)]
    fn finished(pid: u32) -> bool {
        #[cfg(target_os = "linux")]
        {
            match std::fs::read(format!("/proc/{pid}/stat")) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => pid_liveness(pid) == PidLiveness::Gone,
                // Field 3, after the parenthesised command name (which may hold any bytes), is the state.
                Ok(stat) => stat
                    .iter()
                    .rposition(|b| *b == b')')
                    .and_then(|close| {
                        stat[close + 1..]
                            .split(|b| b.is_ascii_whitespace())
                            .find(|f| !f.is_empty())
                    })
                    .is_some_and(|state| state == b"Z" || state == b"X"),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            pid_liveness(pid) == PidLiveness::Gone
        }
    }
}

impl Drop for LeaderReaper {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            if let Some(follower) = self.follower_pid {
                // TestProcess puts the child in its own session, so its PID is its process group.
                let _ = sigkill(follower, true);
                // Linux only: there `finished` sees a zombie as finished. Off Linux a zombie looks alive
                // until its owner reaps it (after this guard), so waiting would only burn the deadline.
                #[cfg(target_os = "linux")]
                while !Self::finished(follower) && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            loop {
                let alive: Vec<u32> = self
                    .strays()
                    .into_iter()
                    .filter(|pid| !Self::finished(*pid))
                    .collect();
                if alive.is_empty() {
                    break;
                }
                for pid in &alive {
                    let _ = sigkill(*pid, false);
                }
                if std::time::Instant::now() >= deadline {
                    eprintln!("[p00] WARNING: process(es) {alive:?} of this sandbox still alive 10s after SIGKILL");
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        #[cfg(not(unix))]
        for pid in self.strays() {
            let _ = std::process::Command::new("taskkill")
                .args(["/F", "/T", "/PID", &pid.to_string()])
                .status();
        }
    }
}

/// File names under `root`, recursively (best effort; unreadable directories are skipped).
fn walk_names(root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            names.push(entry.file_name().to_string_lossy().into_owned());
            if path.is_dir() && !path.is_symlink() {
                stack.push(path);
            }
        }
    }
    names
}

// ---------------------------------------------------------------------------------------------
// E.2 / E.3 / E.4 — credentials, auth negotiation, protocol version
// ---------------------------------------------------------------------------------------------

/// E.2: a `FUIGO_API_KEY` present only in the CHILD's environment authenticates the session, and it is
/// that key — not some other credential — that the agent bills inference to.
#[tokio::test(flavor = "current_thread")]
async fn injected_fuigo_api_key_authenticates() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            extra_env: &[("FUIGO_API_KEY", INJECTED_KEY)],
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    assert!(
        m.sandbox()
            .env()
            .iter()
            .any(|(k, v)| k == "FUIGO_API_KEY" && v == INJECTED_KEY),
        "precondition: the injected key is in the child env"
    );
    let init = m.initialize().await;
    let methods = &init["result"]["authMethods"];
    assert!(
        methods.as_array().is_some_and(|a| a.iter().any(|x| x["id"] == "fuigo.api_key")),
        "fuigo.api_key not advertised with an injected key: {methods}"
    );
    let auth = m
        .call("authenticate", json!({ "methodId": "fuigo.api_key" }), refuse)
        .await;
    assert_eq!(auth.get("result"), Some(&json!({})), "authenticate must return {{}}: {auth}");
    let ws = m.workspace.clone();
    let new = m
        .call("session/new", json!({ "cwd": ws, "mcpServers": [] }), refuse)
        .await;
    let session = new["result"]["sessionId"].as_str().expect("sessionId").to_owned();
    let reply = m.prompt(&session, "hello murage", refuse).await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    let chats = m.chat_requests();
    assert!(!chats.is_empty(), "no inference request was made");
    for r in &chats {
        assert_eq!(
            r.authorization.as_deref(),
            Some(format!("Bearer {INJECTED_KEY}").as_str()),
            "inference must bill to the injected key"
        );
    }
    assert_hermetic(m.sandbox(), m.child_pid());
}

/// E.3: `fuigo.api_key` is advertised, is FIRST (Murage falls back to `ids[0]`), and is the
/// `_meta.defaultAuthMethodId`.
#[tokio::test(flavor = "current_thread")]
async fn initialize_advertises_fuigo_api_key_and_names_it_default() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            extra_env: &[("FUIGO_API_KEY", INJECTED_KEY)],
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let init = m.initialize().await;
    let result = &init["result"];
    assert_eq!(
        result["authMethods"][0]["id"], "fuigo.api_key",
        "fuigo.api_key must be authMethods.first(): {}",
        result["authMethods"]
    );
    assert_eq!(
        result["_meta"]["defaultAuthMethodId"], "fuigo.api_key",
        "_meta.defaultAuthMethodId must name the method that honours the injected key"
    );
    assert!(result.get("meta").is_none(), "`meta` (no underscore) on the wire: {result}");
}

/// E.3: with no credential reachable at all, `authMethods` is empty and both `session/new` (Murage's
/// path when it has no method to pick) and `authenticate` fail `-32000 "Authentication required"`.
/// The message is pinned byte-for-byte: Murage's `classifyError` matches on it. The reason lives in
/// `data.message` and is deliberately not pinned.
#[tokio::test(flavor = "current_thread")]
async fn no_credential_yields_empty_auth_methods_and_minus_32000() {
    let mut fuigo_home_was_empty = false;
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            remove_env: &["FUIGO_API_KEY", "FUIGO_CODE_API_KEY"],
            ..AgentSpawnSpec::default()
        },
        |sandbox| {
            fuigo_home_was_empty = std::fs::read_dir(sandbox.fuigo_home())
                .expect("read FUIGO_HOME")
                .next()
                .is_none();
        },
    )
    .await;
    // Every credential source is absent: no env key (either name), no auth.json / cached token and no
    // config.toml api_key (FUIGO_HOME starts empty), and the mock catalog carries no per-model keys.
    assert!(fuigo_home_was_empty, "precondition: the sandbox FUIGO_HOME starts empty");
    for key in ["FUIGO_API_KEY", "FUIGO_CODE_API_KEY"] {
        assert!(
            !m.sandbox().env().iter().any(|(k, _)| k == key),
            "precondition: {key} must be absent from the child env"
        );
    }

    let init = m.initialize().await;
    assert_eq!(init["result"]["authMethods"], json!([]), "authMethods must be empty: {init}");
    assert_eq!(init["result"]["_meta"]["defaultAuthMethodId"], Value::Null, "{init}");

    let ws = m.workspace.clone();
    let new = m
        .call("session/new", json!({ "cwd": ws, "mcpServers": [] }), refuse)
        .await;
    assert_eq!(new["error"]["code"], -32000, "session/new without a credential: {new}");
    assert_eq!(new["error"]["message"], "Authentication required", "{new}");

    let auth = m
        .call("authenticate", json!({ "methodId": "fuigo.api_key" }), refuse)
        .await;
    assert_eq!(auth["error"]["code"], -32000, "authenticate without a credential: {auth}");
    assert_eq!(auth["error"]["message"], "Authentication required", "{auth}");

    assert!(
        !m.sandbox().fuigo_home().join("auth.json").exists(),
        "a credential file appeared during the run"
    );
    assert!(m.chat_requests().is_empty(), "inference ran without a credential");
    assert_hermetic(m.sandbox(), m.child_pid());
}

/// E.4: `protocolVersion: 1` (Murage's only literal) is accepted and echoed.
#[tokio::test(flavor = "current_thread")]
async fn protocol_version_one_is_accepted() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let init = m.initialize().await;
    assert!(init.get("error").is_none(), "initialize rejected protocolVersion 1: {init}");
    assert_eq!(init["result"]["protocolVersion"], 1, "{init}");
}

// ---------------------------------------------------------------------------------------------
// E.5 / E.5a — folder trust; E.6 — MCP ready
// ---------------------------------------------------------------------------------------------

/// E.5 / E.5a: without `--trust`, a workspace with project config produces the agent-to-client request
/// whose WIRE name is exactly `_fuigo/folder_trust/request`, with params `{sessionId, cwd, workspace,
/// configKinds}`; answering `{"outcome":"trust"}` persists the grant and applies the project config.
#[tokio::test(flavor = "current_thread")]
async fn folder_trust_round_trip_without_trust_flag() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            extra_env: &[TEST_VERSION],
            ..AgentSpawnSpec::default()
        },
        plant_project_mcp,
    )
    .await;
    // The agent starts the trust prompt while `session/new` is being answered, so the request may arrive
    // before or after the `session/new` response. `hold` DEFERS it whenever it arrives: the decision stays
    // pending while the test checks that the project config is still gated, and only then is it granted.
    let is_trust = |x: &Value| method_of(x) == Some("_fuigo/folder_trust/request");
    let hold = |req: &Value| {
        if is_trust(req) {
            RawReply::Defer
        } else {
            RawReply::Refuse
        }
    };
    let session = m.connect(&hold).await;
    let request = m
        .seen_or_wait("folder trust request", RPC, is_trust, &hold)
        .await
        .unwrap_or_else(|| {
            panic!(
                "no `_fuigo/folder_trust/request` within {RPC:?}; methods seen: {:?}\nstderr:\n{}",
                m.methods_seen(),
                m.stderr()
            )
        });
    let params = &request["params"];
    assert_eq!(
        object_keys(params),
        sorted(&["sessionId", "cwd", "workspace", "configKinds"]),
        "folder trust params: {params}"
    );
    assert_eq!(params["sessionId"], session.as_str());
    let ws = m.workspace.to_string_lossy().into_owned();
    let ws_canon = dunce_canon(&m.workspace);
    assert!(params["cwd"] == ws.as_str() || params["cwd"] == ws_canon.as_str(), "cwd: {params}");
    assert!(
        params["workspace"] == ws.as_str() || params["workspace"] == ws_canon.as_str(),
        "workspace: {params}"
    );
    assert_eq!(params["configKinds"], json!(["mcp"]), "{params}");

    // Decision pending. The session's MCP setup finishes regardless (with project servers gated), so its
    // `_fuigo/mcp_initialized` marks a point by which an ungated apply would already be visible; a quiet
    // window after it widens the net. Nothing may apply the project server in that time.
    let sid = session.clone();
    m.seen_or_wait(
        "mcp ready while the trust decision is pending",
        RPC,
        move |x| method_of(x) == Some("_fuigo/mcp_initialized") && x["params"]["sessionId"] == sid.as_str(),
        &hold,
    )
    .await
    .unwrap_or_else(|| panic!("no `_fuigo/mcp_initialized` while the decision was pending; methods seen: {:?}", m.methods_seen()));
    let premature = m
        .client
        .wait_for_message("premature apply", Duration::from_secs(2), lists_project_server, &hold)
        .await;
    assert!(
        premature.is_none() && !m.messages().iter().any(lists_project_server),
        "the project config was applied while the trust decision was still pending"
    );
    assert!(
        !m.sandbox().fuigo_home().join("trusted_folders.toml").exists(),
        "a trust grant was persisted before the client decided"
    );
    assert_eq!(
        m.messages().iter().filter(|x| is_trust(x)).count(),
        1,
        "the trust request was sent more than once while pending"
    );

    // Murage's grant. Only now may the project config apply.
    m.client
        .respond(&request["id"], json!({ "outcome": "trust" }), RPC)
        .await;
    let applied = m
        .seen_or_wait("project config applied", RPC, lists_project_server, &hold)
        .await;
    assert!(
        applied.is_some(),
        "after a trust grant the project server never reached `_fuigo/mcp/servers_updated`\nstderr:\n{}",
        m.stderr()
    );
    let store = std::fs::read_to_string(m.sandbox().fuigo_home().join("trusted_folders.toml"))
        .expect("the grant must persist to FUIGO_HOME/trusted_folders.toml");
    assert!(
        (store.contains(&ws) || store.contains(&ws_canon)) && store.contains("trusted = true"),
        "trust store does not record the grant:\n{store}"
    );
    assert!(
        m.messages_named("fuigo/folder_trust/request").is_empty(),
        "the un-prefixed source spelling leaked onto the wire"
    );
    assert_hermetic(m.sandbox(), m.child_pid());
}

fn dunce_canon(p: &Path) -> String {
    dunce::canonicalize(p)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_else(|_| p.to_string_lossy().into_owned())
}

/// E.5: the same workspace with `--trust`: no trust request is ever sent, the project config applies
/// directly, and the grant is recorded in the sandbox trust store. The round-trip test above is the
/// control that proves this setup does prompt without the flag.
#[tokio::test(flavor = "current_thread")]
async fn trust_flag_suppresses_the_round_trip() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT_TRUST,
            agent_args: AGENT_MURAGE,
            extra_env: &[TEST_VERSION],
            ..AgentSpawnSpec::default()
        },
        plant_project_mcp,
    )
    .await;
    let mut trust_requests = Vec::new();
    let mut record = |req: &Value| {
        if method_of(req).is_some_and(|n| n.contains("folder_trust")) {
            trust_requests.push(req.clone());
        }
        None
    };
    let session = m.connect(&mut record).await;
    let reply = m.prompt(&session, "hello murage", &mut record).await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    // The trust prompt is spawned right after session/new; a whole turn plus this window is far longer
    // than the round-trip test needs to see it.
    let late = m
        .client
        .wait_for_message(
            "late folder trust request",
            Duration::from_secs(3),
            |msg| method_of(msg).is_some_and(|n| n.contains("folder_trust")),
            refuse,
        )
        .await;
    assert!(late.is_none(), "--trust must suppress the round-trip; got {late:?}");
    assert!(trust_requests.is_empty(), "--trust must suppress the round-trip; got {trust_requests:?}");
    let any_trust = m
        .methods_seen()
        .into_iter()
        .filter(|n| n.contains("folder_trust"))
        .collect::<Vec<_>>();
    assert!(any_trust.is_empty(), "--trust must suppress the round-trip; the wire carried {any_trust:?}");
    assert!(
        m.messages().iter().any(lists_project_server),
        "with --trust the project config must apply without a prompt"
    );
    let ws = m.workspace.to_string_lossy().into_owned();
    let ws_canon = dunce_canon(&m.workspace);
    let store = std::fs::read_to_string(m.sandbox().fuigo_home().join("trusted_folders.toml"))
        .expect("--trust must record the grant in FUIGO_HOME/trusted_folders.toml");
    assert!(
        (store.contains(&ws) || store.contains(&ws_canon)) && store.contains("trusted = true"),
        "trust store does not record the --trust grant:\n{store}"
    );
    assert_hermetic(m.sandbox(), m.child_pid());
}

/// E.6 / E.5a: MCP readiness is signalled by the notification whose WIRE name is exactly
/// `_fuigo/mcp_initialized` (source spelling `fuigo/mcp_initialized`), for this session.
#[tokio::test(flavor = "current_thread")]
async fn mcp_ready_notification_wire_name_is_pinned() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let session = m.connect(refuse).await;
    let sid = session.clone();
    let ready = m
        .seen_or_wait(
            "mcp ready",
            RPC,
            move |msg| {
                method_of(msg) == Some("_fuigo/mcp_initialized") && msg["params"]["sessionId"] == sid.as_str()
            },
            refuse,
        )
        .await
        .unwrap_or_else(|| {
            panic!(
                "no `_fuigo/mcp_initialized` for this session within {RPC:?}; methods seen: {:?}",
                m.methods_seen()
            )
        });
    assert!(ready.get("id").is_none(), "must be a notification: {ready}");
    assert_eq!(
        object_keys(&ready["params"]),
        sorted(&["sessionId", "mcpToolCount", "elapsedMs"]),
        "{ready}"
    );
    assert_eq!(ready["params"]["sessionId"], session.as_str());
    assert!(
        m.messages_named("fuigo/mcp_initialized").is_empty(),
        "the un-prefixed source spelling leaked onto the wire"
    );
}

#[cfg(unix)]
/// A minimal stdio MCP server (POSIX sh): answers `initialize`, `tools/list` (one tool) and `ping`, and
/// right after `notifications/initialized` asks the client a form elicitation. The client's answer to
/// that elicitation is appended verbatim to `log`.
fn mcp_server_script(log: &Path) -> String {
    format!(
        r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*) printf '{{"jsonrpc":"2.0","id":%s,"result":{{"protocolVersion":"2025-06-18","capabilities":{{"tools":{{}}}},"serverInfo":{{"name":"p00","version":"0"}}}}}}\n' "$id" ;;
    *'"method":"notifications/initialized"'*) printf '{{"jsonrpc":"2.0","id":"p00-elicit","method":"elicitation/create","params":{{"message":"p00 asks","requestedSchema":{{"type":"object","properties":{{"ok":{{"type":"boolean"}}}}}}}}}}\n' ;;
    *'"method":"tools/list"'*) printf '{{"jsonrpc":"2.0","id":%s,"result":{{"tools":[{{"name":"p00_echo","description":"p00 echo","inputSchema":{{"type":"object","properties":{{}}}}}}]}}}}\n' "$id" ;;
    *'"method":"ping"'*) printf '{{"jsonrpc":"2.0","id":%s,"result":{{}}}}\n' "$id" ;;
    *'"id":"p00-elicit"'*) printf '%s\n' "$line" >> '{log}' ;;
  esac
done
"#,
        log = log.display()
    )
}

/// E.5a / E.6 on the path Murage actually uses: Murage passes its MCP servers in `session/new`. Over a
/// real MCP handshake (1) the server's elicitation reaches the client as `_fuigo/mcp/elicit` with the
/// params Murage reads, and Murage's `{"outcome":"accept","content":…}` reply reaches the server as MCP
/// `{"action":"accept","content":…}`; (2) readiness is `_fuigo/mcp_initialized` with the server's tool
/// counted (the background-handshake send site, not the no-server shortcut).
/// Unix only: the fixture server is a POSIX `sh` script (Murage's own platforms run the same Fuigo path).
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn murage_mcp_server_elicit_and_ready_wire_names() {
    let script = std::cell::RefCell::new(None::<(std::path::PathBuf, std::path::PathBuf)>);
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            ..AgentSpawnSpec::default()
        },
        |sandbox| {
            let log = sandbox.temp_dir().join("p00-elicit.log");
            let path = sandbox.temp_dir().join("p00-mcp.sh");
            std::fs::write(&path, mcp_server_script(&log)).expect("write MCP server script");
            *script.borrow_mut() = Some((path, log));
        },
    )
    .await;
    let (script_path, elicit_log) = script.take().expect("script written");
    let elicits = std::cell::RefCell::new(Vec::<Value>::new());
    let accept = |req: &Value| {
        if method_of(req) == Some("_fuigo/mcp/elicit") {
            elicits.borrow_mut().push(req.clone());
            return Some(json!({ "outcome": "accept", "content": { "ok": true } }));
        }
        None
    };
    let session = m
        .connect_with(
            &accept,
            json!([{ "name": "p00mcp", "command": "/bin/sh", "args": [script_path], "env": [] }]),
        )
        .await;
    let sid = session.clone();
    let ready = m
        .seen_or_wait(
            "mcp ready after the handshake",
            RPC,
            move |msg| {
                method_of(msg) == Some("_fuigo/mcp_initialized")
                    && msg["params"]["sessionId"] == sid.as_str()
                    && msg["params"]["mcpToolCount"].as_u64().is_some_and(|n| n >= 1)
            },
            &accept,
        )
        .await
        .unwrap_or_else(|| {
            panic!(
                "no `_fuigo/mcp_initialized` counting the server's tool within {RPC:?}; methods seen: {:?}\nstderr:\n{}",
                m.methods_seen(),
                m.stderr()
            )
        });
    assert!(ready.get("id").is_none(), "MCP readiness must be a notification, not a request: {ready}");
    assert_eq!(
        object_keys(&ready["params"]),
        sorted(&["sessionId", "mcpToolCount", "elapsedMs"]),
        "{ready}"
    );
    if elicits.borrow().is_empty() {
        // Not answered during the waits above: wait for it, and answer it the way Murage does.
        if let Some(req) = m
            .seen_or_wait("mcp elicit", RPC, |x| method_of(x) == Some("_fuigo/mcp/elicit"), &accept)
            .await
            && let Some(result) = accept(&req)
        {
            m.client.respond(&req["id"], result, RPC).await;
        }
    }
    let elicits = elicits.borrow().clone();
    assert_eq!(elicits.len(), 1, "expected one `_fuigo/mcp/elicit`; methods seen: {:?}", m.methods_seen());
    let params = &elicits[0]["params"];
    assert_eq!(
        object_keys(params),
        sorted(&["sessionId", "toolCallId", "serverName", "message", "mode", "requestedSchema"]),
        "_fuigo/mcp/elicit params: {params}"
    );
    assert_eq!(params["sessionId"], session.as_str());
    assert_eq!(params["serverName"], "p00mcp");
    assert_eq!(params["message"], "p00 asks");
    assert_eq!(params["mode"], "form");
    assert_eq!(params["requestedSchema"]["properties"]["ok"]["type"], "boolean");
    // The answer travels back to the MCP server asynchronously; bound the wait for the server's log.
    let deadline = std::time::Instant::now() + scaled(Duration::from_secs(10));
    let answered = loop {
        let text = std::fs::read_to_string(&elicit_log).unwrap_or_default();
        if !text.trim().is_empty() || std::time::Instant::now() >= deadline {
            break text;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let answered: Value = serde_json::from_str(answered.trim())
        .unwrap_or_else(|e| panic!("the MCP server never received the elicitation answer ({e}): {answered:?}"));
    assert_eq!(
        answered["result"],
        json!({ "action": "accept", "content": { "ok": true } }),
        "Murage's accept must reach the MCP server as an MCP accept: {answered}"
    );
    for unprefixed in ["fuigo/mcp/elicit", "fuigo/mcp_initialized"] {
        assert!(m.messages_named(unprefixed).is_empty(), "{unprefixed} leaked onto the wire un-prefixed");
    }
    assert_hermetic(m.sandbox(), m.child_pid());
}

/// E.5a: the model's `ask_user_question` reaches the client as `_fuigo/ask_user_question` with the params
/// Murage parses, and Murage's accepted reply (`toFuigoAnswers`: answers keyed by question text) is what
/// the model is told.
#[tokio::test(flavor = "current_thread")]
async fn ask_user_question_round_trip_wire_name_is_pinned() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let scripted = m.server.expect_response(
        "call_ask",
        InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
        ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
            "",
            "call_ask",
            "ask_user_question",
            &json!({ "questions": [{ "question": "Pick one?", "options": [
                { "label": "Alpha", "description": "first" },
                { "label": "Beta", "description": "second" }
            ] }] })
            .to_string(),
            MODEL_B,
        )),
    );
    let session = m.connect(refuse).await;
    let mut asks = Vec::new();
    let reply = m
        .prompt(&session, "ask me", |req| {
            if method_of(req) != Some("_fuigo/ask_user_question") {
                return None;
            }
            asks.push(req.clone());
            Some(json!({ "outcome": "accepted", "answers": { "Pick one?": ["Beta"] } }))
        })
        .await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    scripted.assert_satisfied();
    assert_eq!(asks.len(), 1, "expected one `_fuigo/ask_user_question`; methods seen: {:?}", m.methods_seen());
    let params = &asks[0]["params"];
    assert_eq!(
        object_keys(params),
        sorted(&["sessionId", "toolCallId", "questions", "mode"]),
        "_fuigo/ask_user_question params: {params}"
    );
    assert_eq!(params["sessionId"], session.as_str());
    assert_eq!(params["toolCallId"], "call_ask");
    assert_eq!(params["questions"][0]["question"], "Pick one?");
    assert_eq!(params["questions"][0]["options"][1]["label"], "Beta");
    let told: Vec<String> = m
        .chat_requests()
        .iter()
        .filter_map(|r| r.body.as_ref().and_then(|b| b["messages"].as_array()).cloned())
        .flatten()
        .filter(|msg| msg["role"] == "tool" && msg["tool_call_id"] == "call_ask")
        .filter_map(|msg| msg["content"].as_str().map(str::to_owned))
        .collect();
    assert!(
        told.iter().any(|t| t.contains("Beta")),
        "the model was not told the answer Murage sent; tool results: {told:?}"
    );
    assert!(m.messages_named("fuigo/ask_user_question").is_empty(), "un-prefixed name leaked onto the wire");
}

/// Contract E consult on P04 (`8d250586`): Fuigo caps `ask_user_question` at 30 s and answers "no operator"
/// only for a client that declares `startupHints.nonInteractive` (`session/acp_session_impl/spawn.rs`).
/// Murage declares no startup hints, and its owner answers through a UI that waits up to 30 minutes. With
/// Murage's exact payloads, a question held open well past 30 s must stay open, and Murage's late answer must
/// reach the model.
#[tokio::test(flavor = "current_thread")]
async fn ask_user_question_waits_for_murage_past_the_non_interactive_cap() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let scripted = m.server.expect_response(
        "call_ask_late",
        InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
        ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
            "",
            "call_ask_late",
            "ask_user_question",
            &json!({ "questions": [{ "question": "Pick one?", "options": [
                { "label": "Alpha", "description": "first" },
                { "label": "Beta", "description": "second" }
            ] }] })
            .to_string(),
            MODEL_B,
        )),
    );
    let session = m.connect(refuse).await;
    m.client
        .send_line(
            &json!({ "jsonrpc": "2.0", "id": "murage-late-prompt", "method": "session/prompt",
                "params": { "sessionId": session, "prompt": [{ "type": "text", "text": "ask me" }] } })
            .to_string(),
        )
        .await;
    let ask = m
        .client
        .wait_for_message(
            "ask_user_question",
            RPC,
            |x| method_of(x) == Some("_fuigo/ask_user_question"),
            refuse,
        )
        .await
        .unwrap_or_else(|| panic!("no `_fuigo/ask_user_question`; methods seen: {:?}", m.methods_seen()));
    // Hold the owner's answer past P04's 30 s non-interactive cap. If Fuigo resolved the question on its own
    // (no-operator text, or any terminal status), the tool call would finish here.
    let resolved_early = |x: &Value| {
        method_of(x) == Some("session/update")
            && x["params"]["update"]["sessionUpdate"] == "tool_call_update"
            && x["params"]["update"]["toolCallId"] == "call_ask_late"
            && (x["params"]["update"]["status"] == "completed" || x["params"]["update"]["status"] == "failed")
    };
    let early = m
        .client
        .wait_for_message("question held past the cap", Duration::from_secs(40), resolved_early, refuse)
        .await;
    assert!(
        early.is_none(),
        "Fuigo resolved the question before Murage answered (Murage would be cut off): {early:?}"
    );
    m.client
        .respond(&ask["id"], json!({ "outcome": "accepted", "answers": { "Pick one?": ["Beta"] } }), RPC)
        .await;
    let reply = m
        .client
        .response_for_id_answering("murage-late-prompt", "late prompt", RPC, refuse)
        .await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    scripted.assert_satisfied();
    let told: Vec<String> = m
        .chat_requests()
        .iter()
        .filter_map(|r| r.body.as_ref().and_then(|b| b["messages"].as_array()).cloned())
        .flatten()
        .filter(|msg| msg["role"] == "tool" && msg["tool_call_id"] == "call_ask_late")
        .filter_map(|msg| msg["content"].as_str().map(str::to_owned))
        .collect();
    assert!(
        told.iter().any(|t| t.contains("Beta")),
        "the model was not told Murage's late answer; tool results: {told:?}"
    );
}

/// E.1 semantics of `--no-memory`: Murage owns persistent memory, so Fuigo must not offer its own. With
/// the flag, the inference request carries no `memory_*` tool; without it (the control, same argv minus
/// the flag) `memory_search` is offered, so a flag that stopped working would show here.
#[tokio::test(flavor = "current_thread")]
async fn no_memory_flag_withholds_memory_tools() {
    let mut offered = Vec::new();
    for global in [GLOBAL_DEFAULT, &["--permission-mode", "default"][..]] {
        let mut m = Murage::spawn(
            AgentSpawnSpec {
                leading_args: global,
                agent_args: AGENT_MURAGE,
                ..AgentSpawnSpec::default()
            },
            |_| {},
        )
        .await;
        let session = m.connect(refuse).await;
        let reply = m.prompt(&session, "hello murage", refuse).await;
        assert_eq!(reply["result"]["stopReason"], "end_turn", "{global:?}: {reply}");
        let tools: Vec<String> = m
            .chat_requests()
            .iter()
            .filter_map(|r| r.body.as_ref().and_then(|b| b["tools"].as_array()).cloned())
            .flatten()
            .filter_map(|t| t["function"]["name"].as_str().map(str::to_owned))
            .collect();
        assert!(!tools.is_empty(), "{global:?}: no tools reached the mock");
        offered.push(tools);
    }
    let memory = |tools: &[String]| tools.iter().filter(|t| t.starts_with("memory_")).cloned().collect::<Vec<_>>();
    assert!(
        memory(&offered[0]).is_empty(),
        "--no-memory must withhold memory tools; offered {:?}",
        memory(&offered[0])
    );
    assert!(
        offered[1].iter().any(|t| t == "memory_search"),
        "control: without --no-memory the agent offers memory_search (else this test cannot see the flag); offered {:?}",
        offered[1]
    );
}

// ---------------------------------------------------------------------------------------------
// E.7 — model state golden; E.8 — wire path
// ---------------------------------------------------------------------------------------------

/// E.7: `initialize`'s `_meta.modelState` (wire key `_meta`, never `meta`) equals the golden captured
/// from the live wire, as a `serde_json::Value`. This pins `currentModelId` and every
/// `availableModels[].modelId` at their paths, and flags any other drift in the shape.
#[tokio::test(flavor = "current_thread")]
async fn meta_model_state_matches_golden() {
    let golden: Value =
        serde_json::from_str(include_str!("fixtures/murage_model_state_golden.json")).expect("golden");
    let golden = &golden["modelState"];
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let init = m.initialize().await;
    let result = &init["result"];
    assert!(result.get("meta").is_none(), "`meta` (no underscore) on the wire: {result}");
    let live = result
        .get("_meta")
        .and_then(|meta| meta.get("modelState"))
        .unwrap_or_else(|| panic!("no `_meta.modelState` on the initialize response: {result}"));
    // The two paths Murage reads, asserted on their own so a failure names them.
    assert_eq!(live["currentModelId"], golden["currentModelId"], "_meta.modelState.currentModelId");
    let ids = |v: &Value| -> Vec<Value> {
        v["availableModels"]
            .as_array()
            .map(|a| a.iter().map(|m| m["modelId"].clone()).collect())
            .unwrap_or_default()
    };
    assert_eq!(ids(live), ids(golden), "_meta.modelState.availableModels[].modelId");
    assert_eq!(
        live, golden,
        "_meta.modelState drifted from the golden captured off the 1.0.20-line wire.\nlive:   {live}\ngolden: {golden}"
    );
}

/// E.8: one real turn with a tool call, observed on the wire. The `sessionUpdate` tags and the fields
/// Murage reads (`core.ts` session/update switch) keep their spellings; `stopReason` serializes as today.
#[tokio::test(flavor = "current_thread")]
async fn murage_wire_path_fields_round_trip() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_BYPASS,
            agent_args: AGENT_MURAGE,
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let scripted = script_terminal_call(&m.server, "call_wire", "printf p00-wire");
    let session = m.connect(refuse).await;
    let reply = m.prompt(&session, "run the command", refuse).await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    scripted.assert_satisfied();

    let updates: Vec<Value> = m
        .messages_named("session/update")
        .into_iter()
        .filter(|u| u["params"]["sessionId"] == session.as_str())
        .map(|u| u["params"]["update"].clone())
        .collect();
    let of_kind = |kind: &str| -> Vec<&Value> {
        updates.iter().filter(|u| u["sessionUpdate"] == kind).collect()
    };

    let call = of_kind("tool_call")
        .into_iter()
        .find(|u| u["toolCallId"] == "call_wire")
        .unwrap_or_else(|| panic!("no tool_call for call_wire; updates: {updates:?}"));
    assert!(call["title"].is_string(), "tool_call.title: {call}");
    // Observed at the parent: the optional top-level `kind` / `status` are omitted on this update and the
    // kind rides `_meta["fuigo/tool"]`, which Murage reads as its tool stamp. Murage guards `kind` with
    // `typeof === "string"`, so if they appear they must be strings.
    for optional in ["kind", "status"] {
        if let Some(v) = call.get(optional) {
            assert!(v.is_string(), "tool_call.{optional} must be a string when present: {call}");
        }
    }
    // Murage accepts the stamp as its tool identity only with `version === 1` and a string `namespace`.
    let stamp = &call["_meta"]["fuigo/tool"];
    assert_eq!(stamp["version"], 1, "tool_call._meta[\"fuigo/tool\"].version: {call}");
    assert_eq!(stamp["name"], "run_terminal_command", "tool_call._meta[\"fuigo/tool\"]: {call}");
    assert!(stamp["namespace"].is_string(), "tool_call._meta[\"fuigo/tool\"].namespace: {call}");
    assert!(stamp["kind"].is_string(), "tool_call._meta[\"fuigo/tool\"].kind: {call}");
    assert_eq!(call["rawInput"]["command"], "printf p00-wire", "tool_call.rawInput: {call}");
    assert!(call.get("tool_call_id").is_none() && call.get("raw_input").is_none(), "{call}");

    let done = of_kind("tool_call_update")
        .into_iter()
        .find(|u| u["toolCallId"] == "call_wire" && (u["status"] == "completed" || u["status"] == "failed"))
        .unwrap_or_else(|| panic!("no terminal tool_call_update for call_wire; updates: {updates:?}"));
    assert_eq!(done["status"], "completed", "{done}");

    let chunks = of_kind("agent_message_chunk");
    assert!(!chunks.is_empty(), "no agent_message_chunk; updates: {updates:?}");
    for chunk in chunks {
        assert_eq!(chunk["content"]["type"], "text", "{chunk}");
        assert!(chunk["content"]["text"].is_string(), "{chunk}");
    }
    let commands = of_kind("available_commands_update");
    assert!(!commands.is_empty(), "no available_commands_update; updates: {updates:?}");
    for update in commands {
        let list = update["availableCommands"]
            .as_array()
            .unwrap_or_else(|| panic!("available_commands_update without availableCommands: {update}"));
        assert!(!list.is_empty(), "empty availableCommands: {update}");
        assert!(list.iter().all(|c| c["name"].is_string()), "availableCommands[].name: {update}");
    }
    assert!(
        updates.iter().all(|u| u["sessionUpdate"].as_str().is_some_and(|t| t
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '_'))),
        "every sessionUpdate tag stays snake_case: {updates:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// E.2 / P08 — the runtime API-key channel (`authenticate` `_meta["fuigo/apiKey"]`)
// ---------------------------------------------------------------------------------------------

/// The key a P08 client supplies over the wire. Obviously fake, and distinct from `INJECTED_KEY`, the
/// sandbox's `test-key-for-ci` and `DISK_KEY`, so every bearer and every scan names its source.
const RUNTIME_KEY: &str = "p08rk-FAKE-7c1e0b9d4a2f-q8m3x6v1n5z0";
/// A key already on disk in `auth.json` before the agent starts.
const DISK_KEY: &str = "p08-disk-key-FAKE-not-a-secret";
/// The `authenticate` `_meta` key that carries the runtime credential.
const API_KEY_META: &str = "fuigo/apiKey";
/// Neither env name: a P08 client has no key in the agent's environment.
const NO_ENV_KEY: &[&str] = &["FUIGO_API_KEY", "FUIGO_CODE_API_KEY"];

fn authenticate_with_runtime_key(key: &str, persist: Option<bool>) -> Value {
    let mut carrier = json!({ "key": key });
    if let Some(persist) = persist {
        carrier["persist"] = json!(persist);
    }
    json!({ "methodId": "fuigo.api_key", "_meta": { API_KEY_META: carrier } })
}

/// Every file under `root` whose bytes contain `needle` (symlinks are not followed).
fn files_containing(root: &Path, needle: &str) -> Vec<std::path::PathBuf> {
    let mut hits = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file()
                && std::fs::read(&path)
                    .is_ok_and(|bytes| bytes.windows(needle.len()).any(|w| w == needle.as_bytes()))
            {
                hits.push(path);
            }
        }
    }
    hits
}

/// The secret appears in no file of the sandbox (FUIGO_HOME, HOME, TMPDIR and the workspace: logs,
/// session state, `auth.json`), in no line the agent wrote to the client, and in the agent's stderr. Partial
/// disclosure counts: its first and last 8 characters are searched too (the codebase's log fragments are 12-20
/// characters, so any of them contains one of these). `RUNTIME_KEY`'s fragments are unique to it.
fn assert_key_nowhere(m: &Murage, key: &str) {
    let chars: Vec<char> = key.chars().collect();
    let head: String = chars[..8].iter().collect();
    let tail: String = chars[chars.len() - 8..].iter().collect();
    for needle in [key, head.as_str(), tail.as_str()] {
        let files = files_containing(m.sandbox().root(), needle);
        assert!(files.is_empty(), "the runtime key (or its fragment {needle:?}) reached disk: {files:?}");
        let lines: Vec<&String> = m.client.transcript().iter().filter(|l| l.contains(needle)).collect();
        assert!(lines.is_empty(), "the runtime key (or {needle:?}) went back over the wire: {lines:?}");
        assert!(!m.stderr().contains(needle), "the runtime key (or {needle:?}) reached the agent's stderr");
    }
}

/// The capability that tells a client, before it authenticates, that `authenticate` accepts a key.
fn runtime_key_advert(init: &Value) -> Value {
    init["result"]["agentCapabilities"]["_meta"]["fuigo/capabilities"]["authenticateApiKey"].clone()
}

/// P08 acceptance 1 + 2: with NO env key and NO config or disk key, a client authenticates with a key it
/// supplies in `authenticate`, inference bills that key, and nothing is written to disk. Contract E.3 is
/// untouched: `authMethods` is still empty for a credential-less start; the channel is discovered from
/// `agentCapabilities._meta["fuigo/capabilities"].authenticateApiKey`.
#[tokio::test(flavor = "current_thread")]
async fn runtime_api_key_authenticates_with_no_env_or_config_key() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            remove_env: NO_ENV_KEY,
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let auth_json = m.sandbox().fuigo_home().join("auth.json");
    assert!(!auth_json.exists(), "precondition: no auth.json");
    let init = m.initialize().await;
    assert_eq!(init["result"]["authMethods"], json!([]), "E.3: no credential, no advert: {init}");
    assert_eq!(
        runtime_key_advert(&init)["metaKey"],
        API_KEY_META,
        "the runtime-key channel must be advertised: {init}"
    );
    let auth = m
        .call("authenticate", authenticate_with_runtime_key(RUNTIME_KEY, None), refuse)
        .await;
    assert_eq!(auth["result"]["_meta"][API_KEY_META]["persisted"], false, "authenticate: {auth}");
    let ws = m.workspace.clone();
    let new = m
        .call("session/new", json!({ "cwd": ws, "mcpServers": [] }), refuse)
        .await;
    let session = new["result"]["sessionId"]
        .as_str()
        .unwrap_or_else(|| panic!("session/new after a runtime-key authenticate: {new}\n{}", m.stderr()))
        .to_owned();
    let reply = m.prompt(&session, "hello p08", refuse).await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    let chats = m.chat_requests();
    assert!(!chats.is_empty(), "no inference request was made");
    for r in &chats {
        assert_eq!(
            r.authorization.as_deref(),
            Some(format!("Bearer {RUNTIME_KEY}").as_str()),
            "inference must bill the key the client supplied"
        );
    }
    assert!(!auth_json.exists(), "a session-only authenticate wrote auth.json");
    // The credential readers a client can call never hand the runtime key back (checked by the transcript scan).
    for method in ["_fuigo/getApiKey", "_fuigo/auth/getBearerToken"] {
        let read = m.call(method, json!({}), refuse).await;
        assert!(read.get("result").is_some(), "{method}: {read}");
    }
    assert_key_nowhere(&m, RUNTIME_KEY);
    assert_hermetic(m.sandbox(), m.child_pid());
}

/// P08 acceptance 2, strong form: an `auth.json` that already exists (holding another key) is byte-for-byte
/// unchanged by a session-only `authenticate`, and the key the client supplied, not the one on disk (which
/// the agent loads at `initialize`), is the one inference bills.
#[tokio::test(flavor = "current_thread")]
async fn runtime_api_key_leaves_an_existing_auth_json_byte_identical() {
    let seeded = json!({
        "fuigo::api_key": {
            "key": DISK_KEY,
            "auth_mode": "api_key",
            "create_time": "2026-01-01T00:00:00Z",
            "user_id": "",
            "email": null
        }
    })
    .to_string();
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            remove_env: NO_ENV_KEY,
            ..AgentSpawnSpec::default()
        },
        |sandbox| {
            std::fs::write(sandbox.fuigo_home().join("auth.json"), &seeded).expect("seed auth.json");
        },
    )
    .await;
    let auth_json = m.sandbox().fuigo_home().join("auth.json");
    let before = std::fs::read(&auth_json).expect("read seeded auth.json");
    let _ = m.initialize().await;
    let auth = m
        .call("authenticate", authenticate_with_runtime_key(RUNTIME_KEY, Some(false)), refuse)
        .await;
    assert!(auth.get("result").is_some(), "authenticate: {auth}");
    let ws = m.workspace.clone();
    let new = m
        .call("session/new", json!({ "cwd": ws, "mcpServers": [] }), refuse)
        .await;
    let session = new["result"]["sessionId"].as_str().expect("sessionId").to_owned();
    let reply = m.prompt(&session, "hello p08", refuse).await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    let chats = m.chat_requests();
    assert!(!chats.is_empty(), "no inference request was made");
    for r in &chats {
        assert_eq!(
            r.authorization.as_deref(),
            Some(format!("Bearer {RUNTIME_KEY}").as_str()),
            "the client's key must win over the key on disk"
        );
    }
    let after = std::fs::read(&auth_json).expect("auth.json still exists");
    assert!(before == after, "a session-only authenticate changed auth.json");
    assert_key_nowhere(&m, RUNTIME_KEY);
}

/// P08 acceptance 3: persistence still works when the client asks for it (`persist: true`), so the old
/// "authenticate saves the key" flow is an explicit choice rather than lost.
#[tokio::test(flavor = "current_thread")]
async fn runtime_api_key_is_persisted_when_the_client_opts_in() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            remove_env: NO_ENV_KEY,
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let _ = m.initialize().await;
    let auth = m
        .call("authenticate", authenticate_with_runtime_key(RUNTIME_KEY, Some(true)), refuse)
        .await;
    assert_eq!(auth["result"]["_meta"][API_KEY_META]["persisted"], true, "authenticate: {auth}");
    let stored: Value = serde_json::from_slice(
        &std::fs::read(m.sandbox().fuigo_home().join("auth.json")).expect("persist: true writes auth.json"),
    )
    .expect("auth.json is JSON");
    assert_eq!(stored["fuigo::api_key"]["key"], RUNTIME_KEY, "the persisted key");
    // Opting in to disk is not opting in to the wire or the logs.
    let lines: Vec<&String> = m.client.transcript().iter().filter(|l| l.contains(RUNTIME_KEY)).collect();
    assert!(lines.is_empty(), "the runtime key went back over the wire: {lines:?}");
    assert!(!m.stderr().contains(RUNTIME_KEY), "the runtime key reached the agent's stderr");
}

/// P08 acceptance 4: a runtime-store credential is not visible to a child the agent spawns. The child's
/// whole environment is dumped and searched for the key's VALUE, so a leak under any variable name fails
/// (the existing `shell_env_policy` tests cover the twelve provider names only). Positive control: the
/// dump holds the child's `HOME`.
#[tokio::test(flavor = "current_thread")]
async fn runtime_api_key_is_invisible_to_child_processes() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_BYPASS,
            agent_args: AGENT_MURAGE,
            remove_env: NO_ENV_KEY,
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let scripted = script_terminal_call(&m.server, "call_env", "env > p08-child-env.txt");
    let _ = m.initialize().await;
    let auth = m
        .call("authenticate", authenticate_with_runtime_key(RUNTIME_KEY, None), refuse)
        .await;
    assert!(auth.get("result").is_some(), "authenticate: {auth}");
    let ws = m.workspace.clone();
    let new = m
        .call("session/new", json!({ "cwd": ws, "mcpServers": [] }), refuse)
        .await;
    let session = new["result"]["sessionId"].as_str().expect("sessionId").to_owned();
    let reply = m.prompt(&session, "dump the environment", refuse).await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    scripted.assert_satisfied();
    let dump = std::fs::read_to_string(m.workspace.join("p08-child-env.txt")).expect("the child ran");
    assert!(dump.lines().any(|l| l.starts_with("HOME=")), "control: the dump is the child's env:\n{dump}");
    assert!(!dump.contains(RUNTIME_KEY), "a child saw the runtime key");
    for name in NO_ENV_KEY {
        assert!(!dump.lines().any(|l| l.starts_with(&format!("{name}="))), "a child got {name}");
    }
    // The bearer proves the key was live in the agent while the child ran.
    assert!(
        m.chat_requests()
            .iter()
            .all(|r| r.authorization.as_deref() == Some(format!("Bearer {RUNTIME_KEY}").as_str())),
        "inference must bill the runtime key"
    );
}

/// P08 acceptance 5 (and build item 4): every failure path keeps the key out of the error `data`, the
/// wire, stderr and every file; and the no-credential failure tells an ACP client what to send.
#[tokio::test(flavor = "current_thread")]
async fn runtime_api_key_never_reaches_errors_logs_or_disk() {
    // (a) Malformed carrier: a wrong-typed `persist` beside a real key is refused, and the refusal does not
    //     quote the request back. (b) No credential at all: the -32000 names the `_meta` key to send.
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            remove_env: NO_ENV_KEY,
            extra_env: &[("RUST_LOG", "trace")],
        },
        |_| {},
    )
    .await;
    let _ = m.initialize().await;
    let bad = m
        .call(
            "authenticate",
            json!({ "methodId": "fuigo.api_key", "_meta": { API_KEY_META: { "key": RUNTIME_KEY, "persist": "yes" } } }),
            refuse,
        )
        .await;
    assert_eq!(bad["error"]["code"], -32602, "a malformed carrier is invalid params: {bad}");
    assert!(!bad.to_string().contains(RUNTIME_KEY), "the error echoed the key: {bad}");
    let none = m
        .call("authenticate", json!({ "methodId": "fuigo.api_key" }), refuse)
        .await;
    assert_eq!(none["error"]["code"], -32000, "{none}");
    assert_eq!(none["error"]["message"], "Authentication required", "E.3 pins the message: {none}");
    assert_eq!(
        none["error"]["data"]["metaKey"], API_KEY_META,
        "the failure must tell the client where to put a key: {none}"
    );
    let text = none["error"]["data"]["message"].as_str().unwrap_or_default();
    assert!(text.contains(API_KEY_META), "data.message must name the _meta key: {none}");
    assert!(!text.contains("config.toml"), "data.message is addressed to a human: {none}");
    assert_key_nowhere(&m, RUNTIME_KEY);
    assert!(!m.sandbox().fuigo_home().join("auth.json").exists());

    // (c) Admin kill switch: a supplied key is refused and is not stored, logged or echoed.
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            remove_env: NO_ENV_KEY,
            extra_env: &[("RUST_LOG", "trace"), ("FUIGO_DISABLE_API_KEY_AUTH", "1")],
        },
        |_| {},
    )
    .await;
    let _ = m.initialize().await;
    let refused = m
        .call("authenticate", authenticate_with_runtime_key(RUNTIME_KEY, Some(true)), refuse)
        .await;
    assert_eq!(refused["error"]["code"], -32000, "the kill switch refuses a runtime key: {refused}");
    let ws = m.workspace.clone();
    let new = m
        .call("session/new", json!({ "cwd": ws, "mcpServers": [] }), refuse)
        .await;
    assert!(new.get("error").is_some(), "a refused key must not authenticate a session: {new}");
    assert!(m.chat_requests().is_empty(), "inference ran on a refused key");
    assert_key_nowhere(&m, RUNTIME_KEY);
    assert!(!m.sandbox().fuigo_home().join("auth.json").exists(), "a refused key was persisted");
}

/// Contract E.2 under P08: the key Murage injects through the CHILD's environment still authenticates
/// with Murage's plain `authenticate` (no `_meta`), bills inference, and is no longer copied into
/// `auth.json` as a side effect (persistence is opt-in; release note in R065).
#[tokio::test(flavor = "current_thread")]
async fn injected_env_key_still_authenticates_and_is_not_persisted() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            extra_env: &[("FUIGO_API_KEY", INJECTED_KEY)],
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let session = m.connect(refuse).await;
    let reply = m.prompt(&session, "hello murage", refuse).await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    let chats = m.chat_requests();
    assert!(!chats.is_empty(), "no inference request was made");
    for r in &chats {
        assert_eq!(
            r.authorization.as_deref(),
            Some(format!("Bearer {INJECTED_KEY}").as_str()),
            "E.2: inference bills the injected key"
        );
    }
    assert!(
        !m.sandbox().fuigo_home().join("auth.json").exists(),
        "the injected key was written to auth.json without the client asking"
    );
}

/// The P08 auth surface as two real agents put it on the wire: the `authMethods` advert with an injected
/// key, the `authenticateApiKey` capability, the exact `authenticate` request a P08 client sends (key
/// replaced by a placeholder) and the reply it got, and the no-credential `-32000` error.
async fn p08_auth_wire() -> Value {
    let mut with_env = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            extra_env: &[("FUIGO_API_KEY", INJECTED_KEY)],
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let init = with_env.initialize().await;
    let mut bare = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            remove_env: NO_ENV_KEY,
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let bare_init = bare.initialize().await;
    let no_credential = bare
        .call("authenticate", json!({ "methodId": "fuigo.api_key" }), refuse)
        .await;
    let request = authenticate_with_runtime_key(RUNTIME_KEY, Some(false));
    let reply = bare.call("authenticate", request.clone(), refuse).await;
    let mut request_shape = request;
    request_shape["_meta"][API_KEY_META]["key"] = json!("<api key>");
    json!({
        "authMethodsWithInjectedKey": init["result"]["authMethods"],
        "authMethodsWithoutCredential": bare_init["result"]["authMethods"],
        "authenticateApiKeyCapability": runtime_key_advert(&bare_init),
        "authenticateRequest": request_shape,
        "authenticateReply": reply["result"],
        "noCredentialError": no_credential["error"],
    })
}

/// Capture helper for `fixtures/p08_auth_wire_golden.json` (Contract E.7a: goldens come off the wire).
/// Run with `--ignored --nocapture` against the candidate binary and paste the `P08-GOLDEN` line.
#[tokio::test(flavor = "current_thread")]
#[ignore = "capture helper for the P08 golden, run by hand"]
async fn p08_auth_wire_capture() {
    println!("P08-GOLDEN {}", p08_auth_wire().await);
}

/// P08 acceptance 6: `authMethods`, the `authenticateApiKey` capability, the accepted `authenticate`
/// request shape and its reply, and the no-credential error equal the golden captured off the live wire.
#[tokio::test(flavor = "current_thread")]
async fn p08_auth_wire_matches_golden() {
    let golden: Value =
        serde_json::from_str(include_str!("fixtures/p08_auth_wire_golden.json")).expect("golden");
    let live = p08_auth_wire().await;
    assert_eq!(live, golden["wire"], "P08 auth surface drifted from the golden.\nlive:   {live}\ngolden: {}", golden["wire"]);
}

/// P08 acceptance 5 on the SUCCESS path with every log turned up: `RUST_LOG=trace` on stderr and the
/// `FUIGO_DEBUG_LOG` firehose on disk, through authenticate, `session/new` and a turn. Covers the ACP SDK's
/// raw-wire trace (capped by `acp_raw_wire_cap`) and the session-setup config dump (removed).
#[tokio::test(flavor = "current_thread")]
async fn runtime_api_key_survives_debug_logging_on_the_success_path() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            remove_env: NO_ENV_KEY,
            extra_env: &[("RUST_LOG", "trace"), ("FUIGO_DEBUG_LOG", "1")],
        },
        |_| {},
    )
    .await;
    let _ = m.initialize().await;
    let auth = m
        .call("authenticate", authenticate_with_runtime_key(RUNTIME_KEY, None), refuse)
        .await;
    assert!(auth.get("result").is_some(), "authenticate: {auth}");
    let ws = m.workspace.clone();
    let new = m
        .call("session/new", json!({ "cwd": ws, "mcpServers": [] }), refuse)
        .await;
    let session = new["result"]["sessionId"].as_str().expect("sessionId").to_owned();
    let reply = m.prompt(&session, "hello p08", refuse).await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    // Control: the logs really were on (trace reached stderr; the firehose wrote under FUIGO_HOME/debug).
    assert!(m.stderr().contains("TRACE"), "control: RUST_LOG=trace produced no trace output");
    assert!(
        !files_containing(&m.sandbox().fuigo_home().join("debug"), "session").is_empty(),
        "control: FUIGO_DEBUG_LOG wrote no session log"
    );
    assert_key_nowhere(&m, RUNTIME_KEY);
}

/// Astra r2 F3/F5: `fuigo/setApiKey {"key": ""}` after a runtime-key authenticate drops the runtime key AND
/// the agent's copy of it, so a later plain `authenticate` with no other credential fails `-32000` instead
/// of reporting success on a key that was cleared.
#[tokio::test(flavor = "current_thread")]
async fn set_api_key_clear_drops_the_runtime_key() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            remove_env: NO_ENV_KEY,
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let _ = m.initialize().await;
    let auth = m
        .call("authenticate", authenticate_with_runtime_key(RUNTIME_KEY, None), refuse)
        .await;
    assert!(auth.get("result").is_some(), "authenticate: {auth}");
    let cleared = m.call("_fuigo/setApiKey", json!({ "key": "" }), refuse).await;
    assert!(cleared.get("result").is_some(), "setApiKey clear: {cleared}");
    let again = m
        .call("authenticate", json!({ "methodId": "fuigo.api_key" }), refuse)
        .await;
    assert_eq!(again["error"]["code"], -32000, "authenticate after clearing the only key: {again}");
    assert_eq!(again["error"]["message"], "Authentication required", "{again}");
    let bearer = m.call("_fuigo/auth/getBearerToken", json!({}), refuse).await;
    assert!(bearer.get("result").is_some(), "getBearerToken after clear: {bearer}");
    assert_key_nowhere(&m, RUNTIME_KEY);
}

/// Astra r3: a client message the ACP SDK cannot dispatch is logged by the SDK itself, verbatim, at ERROR
/// (a malformed line; a notification it rejects). Neither may carry the key into any log, even at trace.
#[tokio::test(flavor = "current_thread")]
async fn malformed_wire_lines_carrying_the_key_reach_no_log() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            remove_env: NO_ENV_KEY,
            extra_env: &[("RUST_LOG", "trace"), ("FUIGO_DEBUG_LOG", "1")],
        },
        |_| {},
    )
    .await;
    let _ = m.initialize().await;
    // Not JSON at all, the key inside.
    m.client
        .send_line(&format!("{{\"jsonrpc\":\"2.0\",\"id\":\"bad\",\"method\":\"authenticate\",\"params\":{{\"key\":\"{RUNTIME_KEY}\""))
        .await;
    // A notification (no id) the agent does not accept, the key inside.
    m.client
        .send_line(
            &json!({ "jsonrpc": "2.0", "method": "authenticate", "params": authenticate_with_runtime_key(RUNTIME_KEY, None) })
                .to_string(),
        )
        .await;
    // Barrier: a later request is answered, so both lines were read and handled first.
    let barrier = m
        .call("authenticate", json!({ "methodId": "fuigo.api_key" }), refuse)
        .await;
    assert_eq!(barrier["error"]["code"], -32000, "the malformed lines must not authenticate: {barrier}");
    assert!(m.stderr().contains("TRACE"), "control: RUST_LOG=trace produced no trace output");
    assert_key_nowhere(&m, RUNTIME_KEY);
}

/// Astra r4: with a model whose `env_key` names `FUIGO_API_KEY`, a runtime key also reaches the AuthManager's
/// process static key (via `sync_process_static_api_key`). Clearing through `fuigo/setApiKey` must re-derive that
/// copy too, or `getBearerToken` hands the cleared key out (the transcript scan in `assert_key_nowhere` sees it).
#[tokio::test(flavor = "current_thread")]
async fn set_api_key_clear_with_a_mapped_model_hands_out_nothing() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            remove_env: NO_ENV_KEY,
            ..AgentSpawnSpec::default()
        },
        |sandbox| {
            std::fs::write(
                sandbox.fuigo_home().join("config.toml"),
                format!("[model.\"{MODEL_B}\"]\nmodel = \"{MODEL_B}\"\nenv_key = \"FUIGO_API_KEY\"\n"),
            )
            .expect("write config.toml");
        },
    )
    .await;
    let _ = m.initialize().await;
    let auth = m
        .call("authenticate", authenticate_with_runtime_key(RUNTIME_KEY, None), refuse)
        .await;
    assert!(auth.get("result").is_some(), "authenticate: {auth}");
    let cleared = m.call("_fuigo/setApiKey", json!({ "key": "" }), refuse).await;
    assert!(cleared.get("result").is_some(), "setApiKey clear: {cleared}");
    let bearer = m.call("_fuigo/auth/getBearerToken", json!({}), refuse).await;
    assert!(bearer.get("result").is_some(), "getBearerToken after clear: {bearer}");
    assert_key_nowhere(&m, RUNTIME_KEY);
}

// ---------------------------------------------------------------------------------------------
// E.2 / P70 — a key saved in `auth.json` authenticates without entering the agent's environment
// ---------------------------------------------------------------------------------------------

/// A key saved in `auth.json` (and nowhere else). Obviously fake and distinct from every other key here.
const P70_DISK_KEY: &str = "p70-disk-key-FAKE-4e9a1c7d2b";
/// An innocuous variable in the agent's environment: the control that the child really inherits the agent's env.
const P70_CANARY: (&str, &str) = ("P70_INHERITED_CANARY", "p70-canary-present");

fn seed_auth_json(sandbox: &TestSandbox, key: &str) {
    let seeded = json!({
        "fuigo::api_key": {
            "key": key,
            "auth_mode": "api_key",
            "create_time": "2026-01-01T00:00:00Z",
            "user_id": "",
            "email": null
        }
    });
    std::fs::write(sandbox.fuigo_home().join("auth.json"), seeded.to_string()).expect("seed auth.json");
}

/// P70 (P08 proposal 4): `initialize` used to copy a key saved in `auth.json` into `FUIGO_API_KEY`, the agent's own
/// environment, where every child spawned without a name-based strip (`!` bash mode, client terminals, external
/// auth commands, git, gh) inherited it. The key is now held in memory.
///
/// What THIS test pins is Contract E.2 with the saved key: Murage's plain `authenticate` still authenticates with
/// it, inference bills it, `fuigo/getApiKey` still returns it, and a model-tool child under a permissive user
/// `[shell_environment_policy]` holds the key's value under no name. It does NOT tell whether the agent's own
/// environment holds the key: the shell tool strips `FUIGO_API_KEY` by name whatever the policy says, so this test
/// passes with the old `set_var` too (Astra r1). `client_terminal_child_does_not_inherit_the_saved_key` below and
/// `auth_method`'s unit tests are the ones that fail when the key is put back into the environment.
/// Controls: the dump holds the child's `HOME` and the canary the agent was given.
#[tokio::test(flavor = "current_thread")]
async fn auth_json_key_authenticates_and_reaches_no_tool_child() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_BYPASS,
            agent_args: AGENT_MURAGE,
            extra_env: &[P70_CANARY],
            remove_env: NO_ENV_KEY,
        },
        |sandbox| {
            seed_auth_json(sandbox, P70_DISK_KEY);
            std::fs::write(
                sandbox.fuigo_home().join("config.toml"),
                "[shell_environment_policy]\nexclude = [\"P70_UNRELATED_NAME\"]\n",
            )
            .expect("write config.toml");
        },
    )
    .await;
    let scripted = script_terminal_call(&m.server, "call_env", "env > p70-child-env.txt");
    let init = m.initialize().await;
    assert!(
        init["result"]["authMethods"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x["id"] == "fuigo.api_key")),
        "the saved key must still be advertised: {init}"
    );
    let auth = m
        .call("authenticate", json!({ "methodId": "fuigo.api_key" }), refuse)
        .await;
    assert_eq!(auth.get("result"), Some(&json!({})), "Murage's plain authenticate: {auth}");
    let ws = m.workspace.clone();
    let new = m
        .call("session/new", json!({ "cwd": ws, "mcpServers": [] }), refuse)
        .await;
    let session = new["result"]["sessionId"]
        .as_str()
        .unwrap_or_else(|| panic!("session/new: {new}\n{}", m.stderr()))
        .to_owned();
    let reply = m.prompt(&session, "dump the environment", refuse).await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    scripted.assert_satisfied();
    let dump = std::fs::read_to_string(m.workspace.join("p70-child-env.txt")).expect("the child ran");
    assert!(dump.lines().any(|l| l.starts_with("HOME=")), "control: the dump is the child's env:\n{dump}");
    assert!(
        dump.lines().any(|l| l == format!("{}={}", P70_CANARY.0, P70_CANARY.1)),
        "control: the permissive policy passes the agent's environment through:\n{dump}"
    );
    assert!(!dump.contains(P70_DISK_KEY), "a child inherited the auth.json key from the agent's environment");
    for name in NO_ENV_KEY {
        assert!(!dump.lines().any(|l| l.starts_with(&format!("{name}="))), "a child got {name}");
    }
    let chats = m.chat_requests();
    assert!(!chats.is_empty(), "no inference request was made");
    for r in &chats {
        assert_eq!(
            r.authorization.as_deref(),
            Some(format!("Bearer {P70_DISK_KEY}").as_str()),
            "inference must bill the saved key"
        );
    }
    let read = m.call("_fuigo/getApiKey", json!({}), refuse).await;
    assert_eq!(read["result"]["result"]["key"], P70_DISK_KEY, "getApiKey still returns the user's saved key: {read}");
}

/// P70 / Contract E.2: a key Murage injects into the agent's environment still outranks a key saved in
/// `auth.json`, exactly as when the saved key was copied into the environment only if it was empty. A pin of the
/// precedence only: it passes with the old env copy too (an injected key prevented the copy), as Astra r2 noted.
#[tokio::test(flavor = "current_thread")]
async fn injected_env_key_outranks_the_auth_json_key() {
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            extra_env: &[("FUIGO_API_KEY", INJECTED_KEY)],
            ..AgentSpawnSpec::default()
        },
        |sandbox| seed_auth_json(sandbox, P70_DISK_KEY),
    )
    .await;
    let session = m.connect(refuse).await;
    let reply = m.prompt(&session, "hello p70", refuse).await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    let chats = m.chat_requests();
    assert!(!chats.is_empty(), "no inference request was made");
    for r in &chats {
        assert_eq!(
            r.authorization.as_deref(),
            Some(format!("Bearer {INJECTED_KEY}").as_str()),
            "the injected key must win over the saved one"
        );
    }
}

/// P70: `fuigo/setApiKey` saves the key to `auth.json` and used to `set_var("FUIGO_API_KEY")` as well. The key is now
/// held in memory, ahead of any env key exactly as the `set_var` overwrote it. What THIS test pins, end to end: a
/// later plain `authenticate` bills the key, and a model-tool child under a permissive `[shell_environment_policy]`
/// holds its value under no name. Like the test above it passes with the old `set_var` too (the shell tool strips the
/// name unconditionally); `client_terminal_child_does_not_inherit_the_saved_key` and `auth_method`'s unit tests are
/// the ones that fail when the key is put back into the environment.
#[tokio::test(flavor = "current_thread")]
async fn set_api_key_key_authenticates_and_reaches_no_tool_child() {
    const SET_KEY: &str = "p70-setapikey-FAKE-8c3f0e1a6d";
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_BYPASS,
            agent_args: AGENT_MURAGE,
            extra_env: &[P70_CANARY],
            remove_env: NO_ENV_KEY,
        },
        |sandbox| {
            std::fs::write(
                sandbox.fuigo_home().join("config.toml"),
                "[shell_environment_policy]\nexclude = [\"P70_UNRELATED_NAME\"]\n",
            )
            .expect("write config.toml");
        },
    )
    .await;
    let scripted = script_terminal_call(&m.server, "call_env", "env > p70-child-env.txt");
    let _ = m.initialize().await;
    let set = m.call("_fuigo/setApiKey", json!({ "key": SET_KEY }), refuse).await;
    assert_eq!(set["result"]["result"]["ok"], true, "setApiKey: {set}");
    let auth = m
        .call("authenticate", json!({ "methodId": "fuigo.api_key" }), refuse)
        .await;
    assert_eq!(auth.get("result"), Some(&json!({})), "authenticate after setApiKey: {auth}");
    let ws = m.workspace.clone();
    let new = m
        .call("session/new", json!({ "cwd": ws, "mcpServers": [] }), refuse)
        .await;
    let session = new["result"]["sessionId"]
        .as_str()
        .unwrap_or_else(|| panic!("session/new: {new}\n{}", m.stderr()))
        .to_owned();
    let reply = m.prompt(&session, "dump the environment", refuse).await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    scripted.assert_satisfied();
    let dump = std::fs::read_to_string(m.workspace.join("p70-child-env.txt")).expect("the child ran");
    assert!(
        dump.lines().any(|l| l == format!("{}={}", P70_CANARY.0, P70_CANARY.1)),
        "control: the permissive policy passes the agent's environment through:\n{dump}"
    );
    assert!(!dump.contains(SET_KEY), "a child inherited the setApiKey key from the agent's environment");
    let chats = m.chat_requests();
    assert!(!chats.is_empty(), "no inference request was made");
    for r in &chats {
        assert_eq!(
            r.authorization.as_deref(),
            Some(format!("Bearer {SET_KEY}").as_str()),
            "inference must bill the key setApiKey saved"
        );
    }
}

/// P70a: the child boundary on a path with NO name-based strip. The model's shell tool removes `FUIGO_API_KEY`
/// by name whatever the user's policy says (`fuigo_tools::util::shell_env_policy::is_provider_credential`), so the
/// two `…_reaches_no_tool_child` tests above pin Contract E.2 and the value-under-any-name rule but cannot tell
/// whether the AGENT's environment holds the saved key. A terminal the client opens with `fuigo/terminal/create` inherits the agent's
/// environment exactly as it is (as do `!` bash mode, PTY terminals, external auth commands, git and gh). With the
/// key saved in `auth.json` (first pass) or handed to `fuigo/setApiKey` (second pass), such a child's environment
/// holds no `FUIGO_API_KEY` and the key's value under no name. Controls: the child has `HOME` and the canary the
/// agent was started with, so the dump is the inherited environment; inference still bills the saved key.
#[tokio::test(flavor = "current_thread")]
async fn client_terminal_child_does_not_inherit_the_saved_key() {
    const SET_KEY: &str = "p70a-setapikey-FAKE-5b2d9e7c1f";
    for via_set_api_key in [false, true] {
        let key = if via_set_api_key { SET_KEY } else { P70_DISK_KEY };
        let mut m = Murage::spawn(
            AgentSpawnSpec {
                leading_args: GLOBAL_BYPASS,
                agent_args: AGENT_MURAGE,
                extra_env: &[P70_CANARY],
                remove_env: NO_ENV_KEY,
            },
            |sandbox| {
                if !via_set_api_key {
                    seed_auth_json(sandbox, P70_DISK_KEY);
                }
            },
        )
        .await;
        let _ = m.initialize().await;
        if via_set_api_key {
            let set = m.call("_fuigo/setApiKey", json!({ "key": SET_KEY }), refuse).await;
            assert_eq!(set["result"]["result"]["ok"], true, "setApiKey: {set}");
        }
        let auth = m
            .call("authenticate", json!({ "methodId": "fuigo.api_key" }), refuse)
            .await;
        assert_eq!(auth.get("result"), Some(&json!({})), "authenticate: {auth}");
        let ws = m.workspace.clone();
        let new = m
            .call("session/new", json!({ "cwd": ws, "mcpServers": [] }), refuse)
            .await;
        let session = new["result"]["sessionId"]
            .as_str()
            .unwrap_or_else(|| panic!("session/new: {new}\n{}", m.stderr()))
            .to_owned();
        let created = m
            .call(
                "_fuigo/terminal/create",
                json!({
                    "sessionId": session,
                    "command": "/bin/sh",
                    "args": ["-c", "env > p70a-client-env.txt"],
                    "cwd": ws,
                }),
                refuse,
            )
            .await;
        let terminal = created["result"]["result"]["terminalId"]
            .as_str()
            .unwrap_or_else(|| panic!("terminal/create: {created}\n{}", m.stderr()))
            .to_owned();
        let exited = m
            .call(
                "_fuigo/terminal/wait_for_exit",
                json!({ "sessionId": session, "terminalId": terminal }),
                refuse,
            )
            .await;
        assert!(exited.get("result").is_some(), "terminal/wait_for_exit: {exited}");
        let dump = std::fs::read_to_string(m.workspace.join("p70a-client-env.txt")).expect("the child ran");
        assert!(dump.lines().any(|l| l.starts_with("HOME=")), "control: the dump is the child's env:\n{dump}");
        assert!(
            dump.lines().any(|l| l == format!("{}={}", P70_CANARY.0, P70_CANARY.1)),
            "control: this child inherits the agent's environment unfiltered:\n{dump}"
        );
        assert!(!dump.contains(key), "a client terminal inherited the saved key (setApiKey: {via_set_api_key})");
        for name in NO_ENV_KEY {
            assert!(
                !dump.lines().any(|l| l.starts_with(&format!("{name}="))),
                "a client terminal got {name} (setApiKey: {via_set_api_key})"
            );
        }
        let reply = m.prompt(&session, "hello p70a", refuse).await;
        assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
        let chats = m.chat_requests();
        assert!(!chats.is_empty(), "no inference request was made");
        for r in &chats {
            assert_eq!(
                r.authorization.as_deref(),
                Some(format!("Bearer {key}").as_str()),
                "inference must bill the saved key (setApiKey: {via_set_api_key})"
            );
        }
    }
}

/// P70 (Astra r1/r2): `session/new` used to log the whole ACP request with `{:?}`, and the SDK's derived `Debug` prints
/// every MCP server's header and env VALUES. With trace logging written in full to a file (`FUIGO_LOG_FILE`: the
/// stderr capture keeps only a 64 KiB tail, so it cannot prove absence), a `session/new` carrying an HTTP MCP server
/// with an `Authorization` header and a stdio server with a secret env value leaves neither secret, nor an
/// eight-character fragment of either, in that log, in any file under `FUIGO_HOME`'s log dirs, or in the stderr tail.
/// Control: the log holds the very event that used to leak (`Received new session request`) and trace-level output.
#[tokio::test(flavor = "current_thread")]
async fn session_new_mcp_header_and_env_secrets_reach_no_log() {
    const HDR_SECRET: &str = "p70mcphdr-FAKE-6d1f0a9c3e";
    const ENV_SECRET: &str = "p70mcpenv-FAKE-2b7e5c8a4f";
    let log_dir = tempfile::tempdir().expect("log dir");
    let log_file = log_dir.path().join("p70-trace.log");
    let log_path = log_file.to_string_lossy().into_owned();
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_DEFAULT,
            agent_args: AGENT_MURAGE,
            extra_env: &[("RUST_LOG", "trace"), ("FUIGO_LOG_FILE", log_path.as_str())],
            ..AgentSpawnSpec::default()
        },
        |_| {},
    )
    .await;
    let session = m
        .connect_with(
            refuse,
            json!([
                {
                    "type": "http",
                    "name": "p70http",
                    "url": "http://127.0.0.1:9/mcp",
                    "headers": [{ "name": "Authorization", "value": format!("Bearer {HDR_SECRET}") }]
                },
                {
                    "name": "p70stdio",
                    "command": "/bin/sh",
                    "args": ["-c", "exit 0"],
                    "env": [{ "name": "P70_MCP_TOKEN", "value": ENV_SECRET }]
                }
            ]),
        )
        .await;
    let reply = m.prompt(&session, "hello p70", refuse).await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    let log = std::fs::read_to_string(&log_file).expect("FUIGO_LOG_FILE was written");
    assert!(log.contains("Received new session request"), "control: the full log holds the session/new event");
    assert!(log.contains("TRACE"), "control: RUST_LOG=trace reached the log file");
    let home = m.sandbox().fuigo_home().to_path_buf();
    for secret in [HDR_SECRET, ENV_SECRET] {
        let chars: Vec<char> = secret.chars().collect();
        let head: String = chars[..8].iter().collect();
        let tail: String = chars[chars.len() - 8..].iter().collect();
        for needle in [secret, head.as_str(), tail.as_str()] {
            assert!(!log.contains(needle), "an MCP secret (or {needle:?}) reached the trace log");
            assert!(!m.stderr().contains(needle), "an MCP secret (or {needle:?}) reached the agent's stderr");
            for dir in [home.join("debug"), home.join("logs")] {
                let files = files_containing(&dir, needle);
                assert!(files.is_empty(), "an MCP secret (or {needle:?}) reached a log file: {files:?}");
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// P70a follow-up (Sean, 2026-10-03): explicit `${FUIGO_API_KEY}` references in config keep working.
// ---------------------------------------------------------------------------------------------

/// A minimal stdio MCP server (POSIX sh) that first writes the environment it was started with to `dump` and its
/// arguments, one per line, to `args`, then answers `initialize`, `tools/list` (one tool) and `ping`.
#[cfg(unix)]
fn env_dumping_mcp_server_script(dump: &Path, args: &Path) -> String {
    format!(
        r#"#!/bin/sh
env > '{dump}'
printf '%s\n' "$@" > '{args}'
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*) printf '{{"jsonrpc":"2.0","id":%s,"result":{{"protocolVersion":"2025-06-18","capabilities":{{"tools":{{}}}},"serverInfo":{{"name":"p70a","version":"0"}}}}}}\n' "$id" ;;
    *'"method":"tools/list"'*) printf '{{"jsonrpc":"2.0","id":%s,"result":{{"tools":[{{"name":"p70a_echo","description":"p70a echo","inputSchema":{{"type":"object","properties":{{}}}}}}]}}}}\n' "$id" ;;
    *'"method":"ping"'*) printf '{{"jsonrpc":"2.0","id":%s,"result":{{}}}}\n' "$id" ;;
  esac
done
"#,
        dump = dump.display(),
        args = args.display()
    )
}

/// A loopback HTTP listener that records the head of every request it receives and answers each with a 404. Dropping
/// it stops and joins its thread (Astra f4 #2).
struct RecordingHttpListener {
    url: String,
    heads: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    addr: std::net::SocketAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for RecordingHttpListener {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        // Wake the blocking accept so the thread sees `stop`.
        let _ = std::net::TcpStream::connect_timeout(&self.addr, Duration::from_secs(5));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn recording_http_listener() -> RecordingHttpListener {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let heads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (recorded, stopping) = (heads.clone(), stop.clone());
    let thread = std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stopping.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            let Ok(mut stream) = stream else { break };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut head = Vec::new();
            let mut chunk = [0u8; 4096];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&chunk[..n]),
                }
            }
            recorded.lock().unwrap().push(String::from_utf8_lossy(&head).into_owned());
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    RecordingHttpListener { url: format!("http://{addr}/mcp"), heads, addr, stop, thread: Some(thread) }
}

/// Poll `read` until it returns `Some` or `timeout` (scaled) passes.
async fn poll_for<T>(timeout: Duration, mut read: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = std::time::Instant::now() + scaled(timeout);
    loop {
        if let Some(found) = read() {
            return Some(found);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// P70a follow-up, end to end through the real agent binary: the user's API key is saved in `auth.json` only (no
/// `FUIGO_API_KEY` in the agent's environment), and `config.toml` names it explicitly in four places. Each gets the
/// saved key, at the place the reference was written and nowhere else:
/// - a stdio MCP server's `env = { FUIGO_API_KEY = "${FUIGO_API_KEY}" }`: the server's environment holds it;
/// - an HTTP MCP server's `headers = { Authorization = "Bearer ${FUIGO_API_KEY}" }`: the request carries it;
/// - a `UserPromptSubmit` hook whose `command` uses `$FUIGO_API_KEY`: the hook sees it;
/// - a hook whose `env` map says `P70A_TOKEN = "${FUIGO_API_KEY}"`: the hook sees it under that name.
///
/// And it reaches no child that does not name it: a hook running a script that reads `$FUIGO_API_KEY` from its
/// inherited environment, a `!` (bash mode) command and a client terminal (`fuigo/terminal/create`) see no
/// `FUIGO_API_KEY` and the key under no name. The last two inherit the agent's live environment unfiltered (the
/// canary is the control), so they also show the key never entered the agent's own environment.
/// `/proc/<agent>/environ` (Linux) is checked too; it shows the environment the agent was STARTED with, so it is a
/// control on the launch, not a detector of a later `set_var`.
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn explicit_key_references_in_config_reach_only_their_own_destination() {
    let http = recording_http_listener();
    let (http_url, http_heads) = (http.url.clone(), http.heads.clone());
    let mut m = Murage::spawn(
        AgentSpawnSpec {
            leading_args: GLOBAL_BYPASS,
            agent_args: AGENT_MURAGE,
            extra_env: &[P70_CANARY],
            remove_env: NO_ENV_KEY,
        },
        |sandbox| {
            seed_auth_json(sandbox, P70_DISK_KEY);
            let ws = sandbox.workspace();
            let tmp = sandbox.temp_dir();
            let mcp_script = tmp.join("p70a-mcp.sh");
            std::fs::write(
                &mcp_script,
                env_dumping_mcp_server_script(&ws.join("p70a-mcp-env.txt"), &ws.join("p70a-mcp-args.txt")),
            )
                .expect("write MCP server script");
            let hook_script = tmp.join("p70a-hook-inherited.sh");
            std::fs::write(
                &hook_script,
                format!(
                    "printf '%s' \"${{FUIGO_API_KEY-unset}}\" > '{}'\nenv > '{}'\n",
                    ws.join("p70a-hook-inherited.txt").display(),
                    ws.join("p70a-hook-inherited-env.txt").display()
                ),
            )
            .expect("write hook script");
            let config = format!(
                r#"
[mcp_servers.p70astdio]
command = "/bin/sh"
args = ["{mcp_script}", "--key", "${{FUIGO_API_KEY}}"]
env = {{ FUIGO_API_KEY = "${{FUIGO_API_KEY}}", P70A_PLAIN = "p70a-plain", P70A_ESCAPED = "$${{FUIGO_API_KEY}}" }}

[mcp_servers.p70ahttp]
url = "{http_url}?ref=${{FUIGO_API_KEY}}"
headers = {{ Authorization = "Bearer ${{FUIGO_API_KEY}}" }}

[[hooks.UserPromptSubmit]]
[[hooks.UserPromptSubmit.hooks]]
type = "command"
command = "printf '%s' \"$FUIGO_API_KEY\" > '{explicit}'"

[[hooks.UserPromptSubmit.hooks]]
type = "command"
command = "printf '%s' \"$P70A_TOKEN\" > '{via_env}'"
env = {{ P70A_TOKEN = "${{FUIGO_API_KEY}}" }}

[[hooks.UserPromptSubmit.hooks]]
type = "command"
command = "/bin/sh '{hook_script}'"
"#,
                mcp_script = mcp_script.display(),
                explicit = ws.join("p70a-hook-explicit.txt").display(),
                via_env = ws.join("p70a-hook-via-env.txt").display(),
                hook_script = hook_script.display(),
            );
            std::fs::write(sandbox.fuigo_home().join("config.toml"), config).expect("write config.toml");
        },
    )
    .await;
    let session = m.connect(refuse).await;
    let ws = m.workspace.clone();
    let read = |name: &str| std::fs::read_to_string(ws.join(name)).ok().filter(|s| !s.is_empty());

    // The stdio MCP server's own environment.
    let mcp_env = poll_for(RPC, || read("p70a-mcp-env.txt"))
        .await
        .unwrap_or_else(|| panic!("the stdio MCP server never started; methods: {:?}\n{}", m.methods_seen(), m.stderr()));
    assert!(mcp_env.lines().any(|l| l == "P70A_PLAIN=p70a-plain"), "control: the server got its configured env:\n{mcp_env}");
    assert!(
        mcp_env.lines().any(|l| l == format!("FUIGO_API_KEY={P70_DISK_KEY}")),
        "an MCP server env naming ${{FUIGO_API_KEY}} did not get the saved key"
    );
    // Astra f4 #1, f7: an escaped `$${FUIGO_API_KEY}` is text: kept through both expansion passes MCP strings get, then
    // read as an escape at spawn, so the server receives the text `${FUIGO_API_KEY}` (as before P70a), not the key.
    assert!(
        mcp_env.lines().any(|l| l == "P70A_ESCAPED=${FUIGO_API_KEY}"),
        "an escaped reference was resolved or rewritten:\n{}",
        mcp_env.lines().filter(|l| l.starts_with("P70A_ESCAPED=")).collect::<Vec<_>>().join("\n")
    );

    let mcp_args = poll_for(RPC, || read("p70a-mcp-args.txt")).await.expect("the MCP server wrote its args");
    assert_eq!(mcp_args.lines().collect::<Vec<_>>(), ["--key", P70_DISK_KEY], "MCP args naming ${{FUIGO_API_KEY}}");

    // The HTTP MCP server's request.
    let head = poll_for(RPC, || {
        http_heads.lock().unwrap().iter().find(|h| h.to_ascii_lowercase().contains("authorization:")).cloned()
    })
    .await
    .unwrap_or_else(|| panic!("no request with an Authorization header reached the HTTP MCP server; {} request(s)", http_heads.lock().unwrap().len()));
    assert!(
        head.lines().any(|l| l.to_ascii_lowercase().starts_with("authorization:")
            && l.split_once(':').is_some_and(|(_, v)| v.trim() == format!("Bearer {P70_DISK_KEY}"))),
        "an MCP header naming ${{FUIGO_API_KEY}} did not carry the saved key"
    );
    // An MCP URL is an identifier (logged, persisted, listed): an unexported reference in it is deliberately NOT
    // resolved from the saved key (put the key in a header).
    assert!(
        head.lines().next().is_some_and(|l| l.contains("/mcp?ref=") && !l.contains(P70_DISK_KEY)),
        "an MCP URL reference was resolved: {head:?}"
    );

    // Hooks run on the prompt.
    let reply = m.prompt(&session, "hello p70a", refuse).await;
    assert_eq!(reply["result"]["stopReason"], "end_turn", "{reply}");
    let explicit = poll_for(RPC, || read("p70a-hook-explicit.txt")).await;
    assert_eq!(explicit.as_deref(), Some(P70_DISK_KEY), "a hook command naming $FUIGO_API_KEY did not get the saved key\n{}", m.stderr());
    let via_env = poll_for(RPC, || read("p70a-hook-via-env.txt")).await;
    assert_eq!(via_env.as_deref(), Some(P70_DISK_KEY), "a hook env value naming ${{FUIGO_API_KEY}} did not get the saved key");
    let inherited = poll_for(RPC, || read("p70a-hook-inherited.txt")).await;
    assert_eq!(inherited.as_deref(), Some("unset"), "a hook script without an explicit reference got FUIGO_API_KEY");
    let inherited_env = read("p70a-hook-inherited-env.txt").expect("the inherited-env hook dumped its env");
    assert!(!inherited_env.contains(P70_DISK_KEY), "a hook without an explicit reference holds the key under some name");

    // A `!` (bash mode) command.
    let bang = m
        .call(
            "session/prompt",
            json!({
                "sessionId": session,
                "prompt": [{
                    "type": "text",
                    "text": "!env > p70a-bang-env.txt",
                    "_meta": { "bash_command": "env > p70a-bang-env.txt" }
                }]
            }),
            refuse,
        )
        .await;
    assert!(bang.get("result").is_some(), "bash-mode prompt: {bang}");
    let bang_env = poll_for(RPC, || read("p70a-bang-env.txt")).await.expect("the ! command ran");
    // A client terminal.
    let created = m
        .call(
            "_fuigo/terminal/create",
            json!({ "sessionId": session, "command": "/bin/sh", "args": ["-c", "env > p70a-term-env.txt"], "cwd": ws }),
            refuse,
        )
        .await;
    let terminal = created["result"]["result"]["terminalId"]
        .as_str()
        .unwrap_or_else(|| panic!("terminal/create: {created}\n{}", m.stderr()))
        .to_owned();
    let exited = m
        .call("_fuigo/terminal/wait_for_exit", json!({ "sessionId": session, "terminalId": terminal }), refuse)
        .await;
    assert!(exited.get("result").is_some(), "terminal/wait_for_exit: {exited}");
    let term_env = read("p70a-term-env.txt").expect("the client terminal ran");
    for (what, dump) in [("a ! command", &bang_env), ("a client terminal", &term_env)] {
        assert!(dump.lines().any(|l| l.starts_with("HOME=")), "control: {what}'s dump is its env:\n{dump}");
        assert!(
            dump.lines().any(|l| l == format!("{}={}", P70_CANARY.0, P70_CANARY.1)),
            "control: {what} inherits the agent's environment:\n{dump}"
        );
        assert!(!dump.contains(P70_DISK_KEY), "{what} inherited the saved key");
        for name in NO_ENV_KEY {
            assert!(!dump.lines().any(|l| l.starts_with(&format!("{name}="))), "{what} got {name}");
        }
    }
    #[cfg(target_os = "linux")]
    if let Some(pid) = m.child_pid() {
        let environ = std::fs::read(format!("/proc/{pid}/environ")).expect("the agent's /proc environ");
        assert!(
            !String::from_utf8_lossy(&environ).contains(P70_DISK_KEY),
            "the agent was started with the saved key in its environment"
        );
    }

    // Control: inference bills the saved key.
    let chats = m.chat_requests();
    assert!(!chats.is_empty(), "no inference request was made");
    for r in &chats {
        assert_eq!(r.authorization.as_deref(), Some(format!("Bearer {P70_DISK_KEY}").as_str()));
    }

    // The MCP catalog a client reads (Astra f2 #1): `servers_updated` was pushed already; ask for `mcp/list` too.
    let listed = m.call("_fuigo/mcp/list", json!({ "sessionId": session }), refuse).await;
    assert!(listed.get("result").is_some(), "mcp/list: {listed}");
    assert!(listed.to_string().contains("${FUIGO_API_KEY}"), "control: the catalog shows the reference: {listed}");

    // The key went where the config named it and into no record of it (Astra f1 #1, f2): no file under FUIGO_HOME
    // other than `auth.json` (session events, logs, MCP state), no line the agent wrote to the client, not its stderr.
    let home = m.sandbox().fuigo_home().to_path_buf();
    let on_disk: Vec<_> = files_containing(&home, P70_DISK_KEY)
        .into_iter()
        .filter(|p| p.file_name().is_none_or(|n| n != "auth.json"))
        .collect();
    assert!(on_disk.is_empty(), "the saved key reached a file under FUIGO_HOME: {on_disk:?}");
    let wire: Vec<&String> = m.client.transcript().iter().filter(|l| l.contains(P70_DISK_KEY)).collect();
    assert!(wire.is_empty(), "the saved key went to the client: {wire:?}");
    assert!(!m.stderr().contains(P70_DISK_KEY), "the saved key reached the agent's stderr");
}
