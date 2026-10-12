//! Windows evidence for peer messaging between TWO REAL Fuigo processes (Fuigo 1.0.25 packet 15d).
//!
//! NOT RUN BY ORDINARY LANES. The test is `#[ignore]`: it starts real processes and real named pipes. Run it on a Windows
//! machine from an INTERACTIVE or BATCH logon (never ssh: a network logon is refused by design) with:
//!
//! ```text
//! cargo test --locked -p fuigo-shell --features test-support --test win_peer_two_process -- --ignored --nocapture --test-threads=1
//! ```
//!
//! What it starts: the helper `p15d-stdio-agent` (`src/bin/p15d-stdio-agent.rs`), which runs the real `run_stdio_agent` loop on
//! stdin/stdout, TWICE (A and B), plus a third copy (C) at the end. This test is the ACP client of each. All share ONE fresh
//! Fuigo home (a directory this test creates under the current user's temp directory, so the owner and ancestor checks pass),
//! `FUIGO_PEER_MESSAGING=1`, and each has its own mock model endpoint on 127.0.0.1 with a fake key. Nothing leaves the machine.
//! Each child is killed by its own handle in a drop guard. Output lines: `P15D-EVIDENCE <step> PASS|FAIL <detail>`.
#![cfg(windows)]
#[allow(dead_code)]
mod acp_harness;

use std::cell::RefCell;
use std::path::PathBuf;
use std::process::Stdio;
use std::rc::Rc;
use std::time::{Duration, Instant};

use acp_harness::{RPC_TIMEOUT, allow_once, ext_method, new_session, prompt_turn};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_acp_lib::LineBufferedRead;
use fuigo_test_support::sse::{chat_completion_script_exact, chat_completions_reasoning_then_tool_call_events};
use fuigo_test_support::{InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, ScriptedResponse};
use serde_json::{Value, json};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

const OVERALL: Duration = Duration::from_secs(15 * 60);

fn report(step: &str, ok: bool, detail: &str) {
    println!("P15D-EVIDENCE {step} {} {detail}", if ok { "PASS" } else { "FAIL" });
    assert!(ok, "P15D-EVIDENCE {step} FAIL {detail}");
}

/// Every notification the agent sends, as text.
#[derive(Clone, Default)]
struct Recorder(Rc<RefCell<Vec<String>>>);

#[async_trait::async_trait(?Send)]
impl acp::Client for Recorder {
    async fn request_permission(&self, args: acp::RequestPermissionRequest) -> acp::Result<acp::RequestPermissionResponse> {
        Ok(acp::RequestPermissionResponse::new(allow_once(&args)))
    }
    async fn session_notification(&self, args: acp::SessionNotification) -> acp::Result<()> {
        self.0.borrow_mut().push(serde_json::to_string(&args).unwrap_or_default());
        Ok(())
    }
    async fn ext_notification(&self, args: acp::ExtNotification) -> acp::Result<()> {
        self.0.borrow_mut().push(format!("{} {}", args.method, args.params.get()));
        Ok(())
    }
}

/// A child process killed by its own handle when dropped. If the test is failing, its stderr tail is printed.
struct ChildGuard {
    name: &'static str,
    child: Option<tokio::process::Child>,
    stderr: PathBuf,
}

impl ChildGuard {
    fn kill(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill();
        if std::thread::panicking() {
            let text = std::fs::read_to_string(&self.stderr).unwrap_or_default();
            let tail: String = text.chars().rev().take(1500).collect::<Vec<_>>().into_iter().rev().collect();
            println!("P15D-EVIDENCE stderr-tail {} {tail}", self.name);
        }
    }
}

struct Peer {
    name: &'static str,
    guard: ChildGuard,
    conn: acp::ClientSideConnection,
    events: Recorder,
    mock: Rc<MockInferenceServer>,
    session: acp::SessionId,
}

struct Dirs {
    root: PathBuf,
    fuigo_home: PathBuf,
    work: PathBuf,
}

fn spawn_peer(name: &'static str, dirs: &Dirs, mock: &MockInferenceServer) -> (ChildGuard, tokio::process::ChildStdin, tokio::process::ChildStdout) {
    let profile = dirs.root.join(format!("profile-{name}"));
    std::fs::create_dir_all(&profile).expect("profile dir");
    let stderr = dirs.root.join(format!("stderr-{name}.txt"));
    let url = mock.url();
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_p15d-stdio-agent"));
    cmd.env("HOME", &profile)
        .env("USERPROFILE", &profile)
        .env("FUIGO_HOME", &dirs.fuigo_home)
        .env("FUIGO_PEER_MESSAGING", "1")
        .env("FUIGO_CLI_CHAT_PROXY_BASE_URL", &url)
        .env("FUIGO_API_BASE_URL", &url)
        .env("FUIGO_API_KEY", "test-key-for-ci")
        .env("FUIGO_TELEMETRY_ENABLED", "false")
        .env("FUIGO_FEEDBACK_ENABLED", "false")
        .env("FUIGO_TRACE_UPLOAD", "false")
        .env("FUIGO_TURN_SUMMARY", "false")
        .current_dir(&dirs.work)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(std::fs::File::create(&stderr).expect("stderr file")))
        .kill_on_drop(true);
    let mut child = cmd.spawn().expect("spawn the helper agent");
    let stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    (ChildGuard { name, child: Some(child), stderr }, stdin, stdout)
}

async fn start_peer(name: &'static str, dirs: &Dirs, mock: Rc<MockInferenceServer>) -> Peer {
    let (guard, stdin, stdout) = spawn_peer(name, dirs, &mock);
    let events = Recorder::default();
    let incoming = LineBufferedRead::spawn_local(stdout.compat());
    let (conn, io) = acp::ClientSideConnection::new(events.clone(), stdin.compat_write(), incoming, |fut| {
        tokio::task::spawn_local(fut);
    });
    tokio::task::spawn_local(io);
    let init = tokio::time::timeout(
        RPC_TIMEOUT,
        conn.initialize(
            acp::InitializeRequest::new(acp::ProtocolVersion::V1)
                .client_capabilities(acp::ClientCapabilities::new().fs(acp::FileSystemCapabilities::new()).terminal(false))
                .meta(
                    json!({
                        "startupHints": {"nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true},
                        "clientType": "p15d-two-process", "clientVersion": "0.0-test",
                    })
                    .as_object()
                    .cloned(),
                ),
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("{name}: initialize timed out"))
    .unwrap_or_else(|e| panic!("{name}: initialize failed: {e:?}"));
    let method = init
        .auth_methods
        .iter()
        .find(|m| &*m.id().0 == "fuigo.api_key")
        .unwrap_or_else(|| panic!("{name}: no fuigo.api_key auth method"));
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.authenticate(acp::AuthenticateRequest::new(method.id().clone()).meta(json!({ "headless": true }).as_object().cloned())),
    )
    .await
    .unwrap_or_else(|_| panic!("{name}: authenticate timed out"))
    .unwrap_or_else(|e| panic!("{name}: authenticate failed: {e:?}"));
    let session = new_session(&conn, &dirs.work).await;
    Peer { name, guard, conn, events, mock, session }
}

impl Peer {
    async fn call(&self, method: &str, mut params: Value) -> Value {
        params["sessionId"] = json!(self.session.0.to_string());
        ext_method(&self.conn, method, params).await
    }

    fn bodies_with(&self, needle: &str) -> usize {
        self.mock.request_bodies().iter().filter(|b| b.to_string().contains(needle)).count()
    }

    fn saw_event(&self, needle: &str) -> bool {
        self.events.0.borrow().iter().any(|e| e.contains(needle))
    }

    /// Wait until no new model request has arrived for `quiet` (a turn started by a notice or message has finished).
    async fn settle(&self, quiet: Duration) {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut last = self.mock.request_count();
        let mut since = Instant::now();
        while Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let now = self.mock.request_count();
            if now != last {
                last = now;
                since = Instant::now();
            } else if since.elapsed() >= quiet {
                return;
            }
        }
    }
}

async fn wait_until<F: FnMut() -> bool>(bound: Duration, mut f: F) -> bool {
    let end = Instant::now() + bound;
    while Instant::now() < end {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    f()
}

fn host_of(address: &str) -> String {
    address.trim_start_matches("fuigo-peer:").split('/').next().unwrap_or("").to_owned()
}

fn fg() -> InferenceRequestMatcher {
    InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions)
}

/// Script one turn of `p`'s model: call `send_message` to `to` with `marker`, then end with a line of text.
fn script_send(p: &Peer, call_id: &str, to: &str, marker: &str) {
    let args = json!({"to": to, "message": marker, "summary": "p15d"}).to_string();
    let _ = p.mock.expect_response(
        format!("send-{call_id}"),
        fg(),
        ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events("send", call_id, "send_message", &args, "test-model")),
    );
    let _ = p.mock.expect_response(
        format!("done-{call_id}"),
        fg(),
        ScriptedResponse::sse(chat_completion_script_exact("sent", "test-model")),
    );
}

/// The text of the tool result for `call_id` in the model requests `p`'s mock saw.
fn tool_result(p: &Peer, call_id: &str) -> Option<String> {
    p.mock.request_bodies().iter().find_map(|b| {
        b["messages"].as_array()?.iter().find_map(|m| {
            (m["role"] == "tool" && m["tool_call_id"] == call_id).then(|| m["content"].to_string())
        })
    })
}

fn locator_text(dirs: &Dirs) -> String {
    std::fs::read_to_string(dirs.fuigo_home.join("peers").join("hosts.json")).unwrap_or_default()
}

async fn list_rows(p: &Peer) -> Vec<String> {
    let v = p.call("fuigo/peer/list", json!({})).await;
    v["rows"].as_array().map(|r| r.iter().filter_map(|x| x["address"].as_str().map(str::to_owned)).collect()).unwrap_or_default()
}

async fn list_until(p: &Peer, want_host: &str, present: bool, bound: Duration) -> Vec<String> {
    let end = Instant::now() + bound;
    loop {
        let rows = list_rows(p).await;
        if rows.iter().any(|a| host_of(a) == want_host) == present || Instant::now() >= end {
            return rows;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn scenario(dirs: Dirs, mock_a: Rc<MockInferenceServer>, mock_b: Rc<MockInferenceServer>) {
    println!("P15D-EVIDENCE setup INFO fuigo_home={} (a fresh directory under the user's temp)", dirs.fuigo_home.display());
    let a = start_peer("A", &dirs, mock_a).await;
    let mut b = start_peer("B", &dirs, mock_b).await;

    // 1. opt in, list each other, two different host ids.
    for p in [&a, &b] {
        let r = p.call("fuigo/peer/configure", json!({"optIn": true, "operator": "attended"})).await;
        report("1-configure", r["optIn"] == json!(true), &format!("{} -> {r}", p.name));
    }
    let who_b = b.call("fuigo/peer/list", json!({})).await["self"]["address"].as_str().unwrap_or("").to_owned();
    let who_a = a.call("fuigo/peer/list", json!({})).await["self"]["address"].as_str().unwrap_or("").to_owned();
    let (host_a, host_b) = (host_of(&who_a), host_of(&who_b));
    report("1-two-hosts", !host_a.is_empty() && !host_b.is_empty() && host_a != host_b, &format!("A={host_a} B={host_b}"));
    let a_sees = list_until(&a, &host_b, true, Duration::from_secs(30)).await;
    let b_sees = list_until(&b, &host_a, true, Duration::from_secs(30)).await;
    let addr_b = a_sees.iter().find(|x| host_of(x) == host_b).cloned().unwrap_or_default();
    report("1-a-lists-b", !addr_b.is_empty(), &format!("A lists {a_sees:?}"));
    report("1-b-lists-a", b_sees.iter().any(|x| host_of(x) == host_a), &format!("B lists {b_sees:?}"));
    let loc = locator_text(&dirs);
    report("1-hosts-json", loc.contains(&host_a) && loc.contains(&host_b), &format!("hosts.json has both rows: {}", loc.contains(&host_a) && loc.contains(&host_b)));

    // 2. SEND delivered (same permission mode).
    let (m1, m2, m3) = ("P15D-MARK-ONE-7f3a", "P15D-MARK-TWO-91c4", "P15D-MARK-THREE-b2e8");
    script_send(&a, "call_one", &addr_b, m1);
    prompt_turn(&a.conn, &a.session, "send the first message").await;
    let res = tool_result(&a, "call_one").unwrap_or_default();
    report("2-send-delivered", res.contains("Delivered"), &format!("A tool result: {res}"));
    let got = wait_until(Duration::from_secs(40), || b.bodies_with(m1) > 0 && b.bodies_with("cross-session-message") > 0).await;
    report("2-b-model-saw-marker", got, &format!("B model requests with the marker: {}", b.bodies_with(m1)));
    b.settle(Duration::from_secs(4)).await;
    a.settle(Duration::from_secs(4)).await;

    // 3. HELD: B in a different permission mode (yolo; A stays default).
    // `session/set_mode` plan only goes pending until the next turn; the permission base is what the peer check compares, and the
    // client signal for it is the yolo notification (as the terminal sends it).
    let raw = serde_json::value::RawValue::from_string(json!({"yolo_mode": true}).to_string()).expect("raw");
    tokio::time::timeout(RPC_TIMEOUT, b.conn.ext_notification(acp::ExtNotification::new("fuigo/yolo_mode_changed", std::sync::Arc::from(raw))))
        .await
        .expect("yolo notification timed out")
        .expect("yolo notification failed");
    tokio::time::sleep(Duration::from_secs(2)).await;
    b.settle(Duration::from_secs(2)).await;
    script_send(&a, "call_two", &addr_b, m2);
    prompt_turn(&a.conn, &a.session, "send the second message").await;
    let res = tool_result(&a, "call_two").unwrap_or_default();
    report("3-send-held", res.contains("Held for the receiver"), &format!("A tool result: {res}"));
    let ev = wait_until(Duration::from_secs(20), || b.saw_event("peer_held")).await;
    report("3-peer-held-event", ev, "B received a peer_held event");
    let held = b.call("fuigo/peer/list_held", json!({})).await;
    let rows = held["held"].as_array().cloned().unwrap_or_default();
    report("3-list-held", rows.len() == 1 && rows[0]["token"].is_string(), &format!("B list_held: {} row(s)", rows.len()));
    report("3-not-delivered-yet", b.bodies_with(m2) == 0, "B's model has not seen the second marker");

    // 4. RELEASE.
    let (id, token) = (rows[0]["heldId"].clone(), rows[0]["token"].clone());
    let r = b.call("fuigo/peer/release", json!({"heldId": id, "token": token, "action": "release"})).await;
    report("4-release-result", r["result"] == json!("delivered"), &format!("release -> {r}"));
    let got = wait_until(Duration::from_secs(40), || b.bodies_with(m2) > 0).await;
    report("4-b-model-saw-marker", got, &format!("B model requests with the second marker: {}", b.bodies_with(m2)));
    b.settle(Duration::from_secs(4)).await;
    a.settle(Duration::from_secs(4)).await;

    // 5. REFUSE.
    script_send(&a, "call_three", &addr_b, m3);
    prompt_turn(&a.conn, &a.session, "send the third message").await;
    let res = tool_result(&a, "call_three").unwrap_or_default();
    report("5-send-held", res.contains("Held for the receiver"), &format!("A tool result: {res}"));
    let held = b.call("fuigo/peer/list_held", json!({})).await;
    let rows = held["held"].as_array().cloned().unwrap_or_default();
    report("5-list-held", rows.len() == 1, &format!("B list_held: {} row(s)", rows.len()));
    let r = b.call("fuigo/peer/release", json!({"heldId": rows[0]["heldId"], "token": rows[0]["token"], "action": "refuse"})).await;
    report("5-refuse-result", r["result"] == json!("refused"), &format!("refuse -> {r}"));
    tokio::time::sleep(Duration::from_secs(6)).await;
    report("5-never-seen", b.bodies_with(m3) == 0, "B's model never saw the third marker");
    let told = |a: &Peer| a.bodies_with("was held and then refused") > 0;
    let mut ok = wait_until(Duration::from_secs(20), || told(&a)).await;
    if !ok {
        // The notice reaches the sender's model with its next turn.
        a.settle(Duration::from_secs(3)).await;
        let _ = a.mock.expect_response("after-refuse", fg(), ScriptedResponse::sse(chat_completion_script_exact("ok", "test-model")));
        prompt_turn(&a.conn, &a.session, "any news?").await;
        ok = wait_until(Duration::from_secs(20), || told(&a)).await;
    }
    report("5-sender-told", ok, "A's model was shown the notice that the message was refused");

    // 6. B exits; A stops listing it; the row goes at the next reap (a start-time reap, by a third process).
    b.guard.kill();
    let rows = list_until(&a, &host_b, false, Duration::from_secs(30)).await;
    report("6-a-no-longer-lists-b", !rows.iter().any(|x| host_of(x) == host_b), &format!("A lists {rows:?}"));
    let still = locator_text(&dirs).contains(&host_b);
    println!("P15D-EVIDENCE 6-row-before-reap INFO B's row still in hosts.json after the kill (nothing reaps between starts): {still}");
    let mock_c = b.mock.clone();
    drop(b);
    let c = start_peer("C", &dirs, mock_c).await;
    let r = c.call("fuigo/peer/configure", json!({"optIn": true, "operator": "attended"})).await;
    report("6-c-configure", r["optIn"] == json!(true), &format!("C -> {r}"));
    let gone = wait_until(Duration::from_secs(30), || !locator_text(&dirs).contains(&host_b)).await;
    report("6-b-row-reaped", gone, "B's row is gone from hosts.json after C's start-time reap (two tries)");
    let loc = locator_text(&dirs);
    report("6-a-row-kept", loc.contains(&host_a), "A's row is still in hosts.json");
}

#[test]
#[ignore = "real processes and named pipes: run on the Windows test box under a batch logon"]
fn two_real_processes_list_send_hold_release_refuse() {
    fuigo_extra_ca::ensure_default_crypto_provider();
    let mock_rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().expect("mock runtime");
    let start = |rt: &tokio::runtime::Runtime| Rc::new(rt.block_on(MockInferenceServer::start()).expect("mock server"));
    let (mock_a, mock_b) = (start(&mock_rt), start(&mock_rt));
    // Fresh directories under the current user's temp directory (owner: this user; the inherited access is the user, SYSTEM
    // and Administrators only). The Fuigo home itself is created by this test, empty.
    let tmp = tempfile::Builder::new().prefix("p15d-").tempdir().expect("temp root");
    let root = tmp.path().to_path_buf();
    let fuigo_home = root.join("fuigo-home");
    let work = root.join("work");
    for d in [&fuigo_home, &work] {
        std::fs::create_dir(d).expect("create dir");
    }
    let dirs = Dirs { root, fuigo_home, work };
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("test runtime");
    let local = tokio::task::LocalSet::new();
    let outcome = rt.block_on(local.run_until(async {
        tokio::time::timeout(OVERALL, scenario(dirs, mock_a, mock_b)).await
    }));
    assert!(outcome.is_ok(), "P15D-EVIDENCE overall FAIL the test did not finish within {OVERALL:?}");
}
