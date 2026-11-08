//! F5-C2 (design F5 §5.5, §6.1): a direct `fuigo agent --no-leader stdio` process that gets stdin EOF exits, and its
//! session writer (the in-process slot and the OS hold) goes with it, so the next process loads the session at once:
//! never `still closing`, never `HELD_ELSEWHERE`.
//!
//! Against the REAL binary; only the inference endpoint is mocked.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::time::{Duration, Instant};

use fuigo_test_support::{AgentSpawnSpec, MockInferenceServer, MockModelEntry, RawStdioClient, TestSandbox};
use serde_json::{Value, json};

const RPC: Duration = Duration::from_secs(30);
const MODEL: &str = "f5c2-model";
const AGENT_ARGS: &[&str] = &["--no-leader", "-m", MODEL];
/// A process that ends on EOF ends inside the close budget (§6.1, 8.5 s worst case) plus process teardown.
const EXIT_BUDGET: Duration = Duration::from_secs(15);

fn refuse(_: &Value) -> Option<Value> {
    None
}

async fn call(client: &mut RawStdioClient, n: &mut u32, method: &str, params: Value) -> Value {
    *n += 1;
    client.request(&format!("f5c2-{n}"), method, params, RPC, refuse).await
}

async fn handshake(client: &mut RawStdioClient, n: &mut u32) {
    let init = call(
        client,
        n,
        "initialize",
        json!({ "protocolVersion": 1, "clientCapabilities": { "fs": { "readTextFile": false, "writeTextFile": false } } }),
    )
    .await;
    assert!(init.get("result").is_some(), "initialize failed: {init}");
    let auth = call(client, n, "authenticate", json!({ "methodId": "fuigo.api_key" })).await;
    assert_eq!(auth.get("result"), Some(&json!({})), "authenticate: {auth}");
}

async fn prompt_ok(client: &mut RawStdioClient, n: &mut u32, sid: &str) {
    let r = call(
        client,
        n,
        "session/prompt",
        json!({ "sessionId": sid, "prompt": [{ "type": "text", "text": "hello" }] }),
    )
    .await;
    assert_eq!(r["result"]["stopReason"].as_str(), Some("end_turn"), "prompt: {r}");
}

#[tokio::test(flavor = "current_thread")]
async fn f5c2_stdio_eof_exit_releases_the_writer_for_the_next_process() {
    let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new(MODEL)])
        .await
        .expect("start mock server");
    server.set_response("done");
    let sandbox = TestSandbox::new();
    let workspace = sandbox.workspace().to_path_buf();
    let spec = AgentSpawnSpec { agent_args: AGENT_ARGS, ..AgentSpawnSpec::default() };

    let mut first = RawStdioClient::spawn_with_spec(&server, &workspace, sandbox, &spec).await;
    let mut n = 0;
    handshake(&mut first, &mut n).await;
    let new = call(&mut first, &mut n, "session/new", json!({ "cwd": workspace, "mcpServers": [] })).await;
    let sid = new["result"]["sessionId"].as_str().unwrap_or_else(|| panic!("session/new: {new}")).to_owned();
    prompt_ok(&mut first, &mut n, &sid).await;

    // The client quits: stdin EOF, nothing else. The process must end by itself.
    let started = Instant::now();
    let status = first.close_stdin_and_wait(EXIT_BUDGET).await.expect("wait for exit");
    let exited_in = started.elapsed();
    assert!(
        status.is_some(),
        "the agent was still running {EXIT_BUDGET:?} after stdin EOF\nstderr:\n{}",
        first.stderr()
    );
    println!("[f5c2-stdio] EOF exit: {status:?} after {exited_in:?}");
    let sandbox = first.take_sandbox();
    let _ = first.close().await;

    // The next process on the same FUIGO_HOME loads the session at once and runs a turn.
    let mut second = RawStdioClient::spawn_with_spec(&server, &workspace, sandbox, &spec).await;
    let mut n = 0;
    handshake(&mut second, &mut n).await;
    let started = Instant::now();
    let load = call(
        &mut second,
        &mut n,
        "session/load",
        json!({ "sessionId": sid, "cwd": workspace, "mcpServers": [] }),
    )
    .await;
    let took = started.elapsed();
    assert!(
        load.get("error").is_none() && load.get("result").is_some(),
        "the next process's session/load was refused after {took:?}: {load}\nstderr:\n{}",
        second.stderr()
    );
    println!("[f5c2-stdio] next-process load: ok in {took:?}");
    prompt_ok(&mut second, &mut n, &sid).await;
    let _ = second.close().await;
}
