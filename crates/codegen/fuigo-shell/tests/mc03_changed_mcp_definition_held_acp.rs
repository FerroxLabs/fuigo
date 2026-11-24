//! MC-03 (1.0.47 S3): an MCP server definition that changed since the user approved it is held, not spawned, until
//! re-approved, in every permission mode (bypass included). Before the fix an edited `config.toml` command ran in the
//! next session (and in the open one, through hot reload) with no prompt.
//!
//! Real path: the real binary over stdio, a user `config.toml` stdio MCP server that records its version tag when it
//! starts. Session 1 sees v1 first (recorded silently). The definition is then edited to v2 on disk and a second
//! session opens in bypass mode: v2 must never start.
#![cfg(unix)]

use std::path::Path;
use std::time::{Duration, Instant};

use fuigo_test_support::acp_client::{AgentSpawnSpec, RawReply, RawStdioClient};
use fuigo_test_support::{MockInferenceServer, TestSandbox};
use serde_json::{Value, json};

const RPC: Duration = Duration::from_secs(60);

/// A minimal MCP stdio server: appends its first argument to the marker file, then answers `initialize` and
/// `tools/list` (no tools) and acknowledges any other request.
const SERVER: &str = r#"import json, sys
with open(sys.argv[2], "a") as f:
    f.write(sys.argv[1] + "\n")
for line in sys.stdin:
    try:
        m = json.loads(line)
    except Exception:
        continue
    if "id" not in m:
        continue
    if m.get("method") == "initialize":
        r = {"protocolVersion": m.get("params", {}).get("protocolVersion", "2024-11-05"),
             "capabilities": {"tools": {}}, "serverInfo": {"name": "mc03", "version": "0"}}
    elif m.get("method") == "tools/list":
        r = {"tools": []}
    else:
        r = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}) + "\n")
    sys.stdout.flush()
"#;

#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there"
)]
fn write_config(fuigo_home: &Path, script: &Path, marker: &Path, tag: &str) {
    std::fs::write(
        fuigo_home.join("config.toml"),
        format!(
            "[mcp_servers.mc03srv]\ncommand = \"/usr/bin/python3\"\nargs = [\"{}\", \"{tag}\", \"{}\"]\nstartup_timeout_sec = 10\n",
            script.display(),
            marker.display()
        ),
    )
    .expect("config.toml");
}

fn tags(marker: &Path) -> Vec<String> {
    std::fs::read_to_string(marker)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn refuse(_: &Value) -> RawReply {
    RawReply::Refuse
}

#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there"
)]
#[tokio::test(flavor = "current_thread")]
async fn a_changed_mcp_definition_is_held_even_in_bypass_mode() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let server = MockInferenceServer::start().await.expect("mock server");
            let sandbox = TestSandbox::new();
            let fuigo_home = sandbox.fuigo_home().to_path_buf();
            let workspace = sandbox.workspace().to_path_buf();
            let script = fuigo_home.join("mc03_mcp.py");
            let marker = fuigo_home.join("mc03_marker.txt");
            std::fs::write(&script, SERVER).expect("server script");
            write_config(&fuigo_home, &script, &marker, "v1");

            let spec = AgentSpawnSpec {
                agent_args: &["--no-leader"],
                ..AgentSpawnSpec::default()
            };
            let mut client = RawStdioClient::spawn_with_spec(&server, &workspace, sandbox, &spec).await;
            let init = client
                .request(
                    "mc03-1",
                    "initialize",
                    json!({
                        "protocolVersion": 1,
                        "clientCapabilities": { "fs": { "readTextFile": false, "writeTextFile": false }, "terminal": false },
                        "_meta": { "startupHints": { "nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true } }
                    }),
                    RPC,
                    refuse,
                )
                .await;
            assert!(init.get("result").is_some(), "initialize: {init}");
            let auth = client
                .request("mc03-2", "authenticate", json!({ "methodId": "fuigo.api_key" }), RPC, refuse)
                .await;
            assert!(auth.get("result").is_some(), "authenticate: {auth}");
            let new = client
                .request("mc03-3", "session/new", json!({ "cwd": workspace, "mcpServers": [] }), RPC, refuse)
                .await;
            assert!(new["result"]["sessionId"].is_string(), "session/new: {new}");

            // Drain the agent's stdout while waiting for `tag` to appear in the marker (or `secs` to pass).
            async fn seen_within(client: &mut RawStdioClient, marker: &Path, tag: &str, secs: u64) -> bool {
                let deadline = Instant::now() + Duration::from_secs(secs);
                while Instant::now() < deadline {
                    if tags(marker).iter().any(|t| t == tag) {
                        return true;
                    }
                    let _ = client
                        .wait_for_message("drain", Duration::from_millis(500), |_| false, refuse)
                        .await;
                }
                tags(marker).iter().any(|t| t == tag)
            }
            assert!(
                seen_within(&mut client, &marker, "v1", 30).await,
                "premise: the first-seen server starts silently; tags {:?}\nstderr:\n{}",
                tags(&marker),
                client.stderr()
            );

            // The definition changes on disk; a bypass-mode session opens.
            write_config(&fuigo_home, &script, &marker, "v2");
            let second = client
                .request(
                    "mc03-4",
                    "session/new",
                    json!({ "cwd": workspace, "mcpServers": [], "_meta": { "yoloMode": true } }),
                    RPC,
                    refuse,
                )
                .await;
            assert!(second["result"]["sessionId"].is_string(), "session/new (bypass): {second}");
            assert!(
                !seen_within(&mut client, &marker, "v2", 20).await,
                "a changed definition must be held until approved, even in bypass mode; tags {:?}\nstderr:\n{}",
                tags(&marker),
                client.stderr()
            );
            // The user is told (a client config notice), never silently skipped.
            assert!(
                client
                    .transcript()
                    .iter()
                    .any(|l| l.contains("mc03srv") && l.contains("changed since you approved it")),
                "the held server sends a notice; transcript:\n{}",
                client.transcript().join("\n")
            );
            let approvals = std::fs::read_to_string(fuigo_home.join("mcp_approved_definitions.json"))
                .expect("the approvals file records the first-seen definition");
            assert!(approvals.contains("mcpdef.v1:"), "approvals file: {approvals}");
        })
        .await;
}

/// Requests an HTTP MCP endpoint received, as their lowercased header blocks. The endpoint answers every request with
/// 503: only whether Fuigo connected (and with which header) matters.
async fn count_requests(
    listener: tokio::net::TcpListener,
    seen: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let seen = seen.clone();
        tokio::task::spawn_local(async move {
            let mut buf = vec![0u8; 16 * 1024];
            let mut len = 0;
            while len < buf.len() {
                match sock.read(&mut buf[len..]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => len += n,
                }
                if buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            seen.borrow_mut()
                .push(String::from_utf8_lossy(&buf[..len]).to_lowercase());
            let _ = sock
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await;
        });
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there"
)]
fn write_http_config(fuigo_home: &Path, port: u16, tag: &str, oauth: bool) {
    let oauth = if oauth {
        "[mcp_servers.mc03http.oauth]\nclientId = \"mc03-client\"\ncallbackPort = 4319\n"
    } else {
        ""
    };
    std::fs::write(
        fuigo_home.join("config.toml"),
        format!(
            "[mcp_servers.mc03http]\nurl = \"http://127.0.0.1:{port}/mcp\"\nstartup_timeout_sec = 10\n[mcp_servers.mc03http.headers]\nX-Mc03-Tag = \"{tag}\"\n{oauth}"
        ),
    )
    .expect("config.toml");
}

/// Review Fable M5/M6 (design test 5 at the connect layer): a changed HTTP header and a changed OAuth setting each hold
/// the server, and a held server makes zero connections.
#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there"
)]
#[tokio::test(flavor = "current_thread")]
async fn a_changed_http_header_or_oauth_setting_is_held_with_zero_connections() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let server = MockInferenceServer::start().await.expect("mock server");
            let sandbox = TestSandbox::new();
            let fuigo_home = sandbox.fuigo_home().to_path_buf();
            let workspace = sandbox.workspace().to_path_buf();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let port = listener.local_addr().unwrap().port();
            let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
            tokio::task::spawn_local(count_requests(listener, seen.clone()));
            let with_tag = |tag: &str| {
                let needle = format!("x-mc03-tag: {tag}");
                seen.borrow().iter().filter(|r| r.contains(&needle)).count()
            };
            write_http_config(&fuigo_home, port, "t1", false);

            let spec = AgentSpawnSpec {
                agent_args: &["--no-leader"],
                ..AgentSpawnSpec::default()
            };
            let mut client = RawStdioClient::spawn_with_spec(&server, &workspace, sandbox, &spec).await;
            let init = client
                .request(
                    "h-1",
                    "initialize",
                    json!({
                        "protocolVersion": 1,
                        "clientCapabilities": { "fs": { "readTextFile": false, "writeTextFile": false }, "terminal": false },
                        "_meta": { "startupHints": { "nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true } }
                    }),
                    RPC,
                    refuse,
                )
                .await;
            assert!(init.get("result").is_some(), "initialize: {init}");
            let auth = client
                .request("h-2", "authenticate", json!({ "methodId": "fuigo.api_key" }), RPC, refuse)
                .await;
            assert!(auth.get("result").is_some(), "authenticate: {auth}");

            async fn drain(client: &mut RawStdioClient, secs: u64, mut done: impl FnMut() -> bool) -> bool {
                let deadline = Instant::now() + Duration::from_secs(secs);
                while Instant::now() < deadline {
                    if done() {
                        return true;
                    }
                    let _ = client
                        .wait_for_message("drain", Duration::from_millis(500), |_| false, refuse)
                        .await;
                }
                done()
            }
            async fn new_session(client: &mut RawStdioClient, id: &str, workspace: &Path) {
                let r = client
                    .request(id, "session/new", json!({ "cwd": workspace, "mcpServers": [] }), RPC, refuse)
                    .await;
                assert!(r["result"]["sessionId"].is_string(), "session/new: {r}");
            }

            new_session(&mut client, "h-3", &workspace).await;
            assert!(
                drain(&mut client, 30, || with_tag("t1") > 0).await,
                "premise: the first-seen HTTP server connects; stderr:\n{}",
                client.stderr()
            );

            // Header value changed: held, never connects with it (the open session's hot reload included).
            write_http_config(&fuigo_home, port, "t2", false);
            new_session(&mut client, "h-4", &workspace).await;
            drain(&mut client, 15, || false).await;
            assert_eq!(with_tag("t2"), 0, "a changed header must be held; stderr:\n{}", client.stderr());

            // OAuth setting added to the approved header: held, zero connections of any kind after the change settles.
            write_http_config(&fuigo_home, port, "t1", true);
            drain(&mut client, 5, || false).await;
            let before = seen.borrow().len();
            new_session(&mut client, "h-5", &workspace).await;
            drain(&mut client, 15, || false).await;
            assert_eq!(
                seen.borrow().len(),
                before,
                "a changed OAuth setting must be held: {:?}\nstderr:\n{}",
                &seen.borrow()[before..],
                client.stderr()
            );
            let notices = client
                .transcript()
                .iter()
                .filter(|l| l.contains("mc03http") && l.contains("changed since you approved it"))
                .count();
            assert!(notices >= 2, "each held start sends the notice; transcript:\n{}", client.transcript().join("\n"));
        })
        .await;
}

/// Opens a session on v1, then edits the definition to v2 so the open session's hot reload holds it. With
/// `corrupt_store`, the approvals file is made unreadable first, so the hold is a store-unavailable one.
#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there"
)]
async fn a_session_holding_v2(
    corrupt_store: bool,
) -> (
    MockInferenceServer,
    RawStdioClient,
    String,
    std::path::PathBuf,
) {
    let server = MockInferenceServer::start().await.expect("mock server");
    let sandbox = TestSandbox::new();
    let fuigo_home = sandbox.fuigo_home().to_path_buf();
    let workspace = sandbox.workspace().to_path_buf();
    let script = fuigo_home.join("mc03_mcp.py");
    let marker = fuigo_home.join("mc03_marker.txt");
    std::fs::write(&script, SERVER).expect("server script");
    write_config(&fuigo_home, &script, &marker, "v1");
    let spec = AgentSpawnSpec {
        agent_args: &["--no-leader"],
        ..AgentSpawnSpec::default()
    };
    let mut client = RawStdioClient::spawn_with_spec(&server, &workspace, sandbox, &spec).await;
    let init = client
        .request(
            "h-1",
            "initialize",
            json!({
                "protocolVersion": 1,
                "clientCapabilities": { "fs": { "readTextFile": false, "writeTextFile": false }, "terminal": false },
                "_meta": { "startupHints": { "nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true } }
            }),
            RPC,
            refuse,
        )
        .await;
    assert!(init.get("result").is_some(), "initialize: {init}");
    let auth = client
        .request(
            "h-2",
            "authenticate",
            json!({ "methodId": "fuigo.api_key" }),
            RPC,
            refuse,
        )
        .await;
    assert!(auth.get("result").is_some(), "authenticate: {auth}");
    let new = client
        .request(
            "h-3",
            "session/new",
            json!({ "cwd": workspace, "mcpServers": [] }),
            RPC,
            refuse,
        )
        .await;
    let sid = new["result"]["sessionId"]
        .as_str()
        .expect("session id")
        .to_owned();
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline && !tags(&marker).iter().any(|t| t == "v1") {
        let _ = client
            .wait_for_message("drain", Duration::from_millis(500), |_| false, refuse)
            .await;
    }
    assert!(
        tags(&marker).iter().any(|t| t == "v1"),
        "premise: v1 starts; tags {:?}",
        tags(&marker)
    );
    if corrupt_store {
        std::fs::write(fuigo_home.join("mcp_approved_definitions.json"), "not json")
            .expect("corrupt store");
    }
    write_config(&fuigo_home, &script, &marker, "v2");
    // The watcher picks the edit up; keep stdout drained meanwhile.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let _ = client
            .wait_for_message("drain", Duration::from_millis(500), |_| false, refuse)
            .await;
    }
    assert!(
        !tags(&marker).iter().any(|t| t == "v2"),
        "premise: v2 is held; tags {:?}",
        tags(&marker)
    );
    (server, client, sid, fuigo_home)
}

async fn listed(client: &mut RawStdioClient, id: &str, sid: &str) -> Value {
    let list = client
        .request(
            id,
            "_fuigo/mcp/list",
            json!({ "sessionId": sid }),
            RPC,
            refuse,
        )
        .await;
    // The ext response wraps the method result once more (`result.result`).
    list["result"]["result"]["servers"]
        .as_array()
        .and_then(|s| s.iter().find(|e| e["name"] == "mc03srv").cloned())
        .unwrap_or_else(|| panic!("mc03srv listed: {list}"))
}

async fn toggle_on(client: &mut RawStdioClient, id: &str, sid: &str) -> Value {
    client
        .request(
            id,
            "_fuigo/mcp/toggle",
            json!({ "session_id": sid, "server_name": "mc03srv", "enabled": true }),
            RPC,
            refuse,
        )
        .await
}

/// Coordinator (ACP hosts such as Murage): `mcp/list` says which servers are held, so a host never has to parse
/// notice text; approving through `_fuigo/mcp/toggle` clears it.
#[tokio::test(flavor = "current_thread")]
async fn acp_mcp_list_marks_a_held_server_until_the_toggle_approves_it() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_server, mut client, sid, _home) = a_session_holding_v2(false).await;
            let entry = listed(&mut client, "h-4", &sid).await;
            assert_eq!(entry["held"], true, "{entry}");
            assert!(
                entry["heldReason"]
                    .as_str()
                    .is_some_and(|r| r.contains("changed since you approved it")),
                "{entry}"
            );
            assert!(
                entry["heldDigest"]
                    .as_str()
                    .is_some_and(|d| d.starts_with("mcpdef.v1:")),
                "{entry}"
            );
            let toggled = toggle_on(&mut client, "h-5", &sid).await;
            assert!(toggled.get("result").is_some(), "mcp/toggle: {toggled}");
            let entry = listed(&mut client, "h-6", &sid).await;
            assert_eq!(entry["held"], false, "{entry}");
            assert!(
                entry.get("heldReason").is_none() && entry.get("heldDigest").is_none(),
                "{entry}"
            );
        })
        .await;
}

/// Coordinator: while the approvals file is unreadable, the toggle cannot approve, so it fails with an error naming the
/// file and the reset command instead of reporting ok.
#[tokio::test(flavor = "current_thread")]
async fn acp_mcp_toggle_errors_while_the_approvals_file_is_unreadable() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_server, mut client, sid, home) = a_session_holding_v2(true).await;
            let entry = listed(&mut client, "h-4", &sid).await;
            assert_eq!(entry["held"], true, "{entry}");
            assert!(
                entry["heldReason"]
                    .as_str()
                    .is_some_and(|r| r.contains("could not be read")),
                "{entry}"
            );
            let toggled = toggle_on(&mut client, "h-5", &sid).await;
            let message = toggled.to_string();
            assert!(
                toggled.get("error").is_some() && !message.contains("\"ok\":true"),
                "must not report ok: {toggled}"
            );
            assert!(
                message.contains("mcp_approved_definitions.json")
                    && message.contains("fuigo mcp approvals reset"),
                "{toggled}"
            );
            assert!(home.join("mcp_approved_definitions.json").exists());
        })
        .await;
}

async fn toggle_on_shown(client: &mut RawStdioClient, id: &str, sid: &str, digest: &str) -> Value {
    client
        .request(
            id,
            "_fuigo/mcp/toggle",
            json!({ "session_id": sid, "server_name": "mc03srv", "enabled": true, "digest": digest }),
            RPC,
            refuse,
        )
        .await
}

/// Review Astra confirm H1 (Sean: approve exactly what is shown): v2 is shown as held, the file changes to v3 and the
/// hot reload holds v3; approving with v2's digest is refused, approves nothing, and v3 stays held and never starts.
#[tokio::test(flavor = "current_thread")]
async fn acp_mcp_toggle_with_a_shown_digest_never_approves_a_later_definition() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_server, mut client, sid, home) = a_session_holding_v2(false).await;
            let shown = listed(&mut client, "h-4", &sid).await["heldDigest"]
                .as_str()
                .expect("v2 digest shown")
                .to_owned();
            let (script, marker) = (home.join("mc03_mcp.py"), home.join("mc03_marker.txt"));
            write_config(&home, &script, &marker, "v3");
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut now_held = shown.clone();
            while Instant::now() < deadline && now_held == shown {
                let _ = client
                    .wait_for_message("drain", Duration::from_millis(500), |_| false, refuse)
                    .await;
                now_held = listed(&mut client, "h-5", &sid).await["heldDigest"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
            }
            assert_ne!(now_held, shown, "premise: the hot reload holds v3");
            let toggled = toggle_on_shown(&mut client, "h-6", &sid, &shown).await;
            let message = toggled.to_string();
            assert!(
                toggled.get("error").is_some() && !message.contains("\"ok\":true"),
                "must not report ok: {toggled}"
            );
            assert!(
                message.contains("changed again since it was shown"),
                "{toggled}"
            );
            let entry = listed(&mut client, "h-7", &sid).await;
            assert_eq!(entry["held"], true, "{entry}");
            assert_eq!(entry["heldDigest"], now_held.as_str(), "{entry}");
            let store =
                std::fs::read_to_string(home.join("mcp_approved_definitions.json")).unwrap();
            assert!(
                !store.contains(&shown) && !store.contains(&now_held),
                "nothing approved: {store}"
            );
            assert!(
                !tags(&marker).iter().any(|t| t == "v3"),
                "{:?}",
                tags(&marker)
            );
        })
        .await;
}

/// Review Astra confirm H1: approving with the digest that is shown and still held starts it.
#[tokio::test(flavor = "current_thread")]
async fn acp_mcp_toggle_with_the_shown_digest_starts_the_shown_definition() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_server, mut client, sid, home) = a_session_holding_v2(false).await;
            let shown = listed(&mut client, "h-4", &sid).await["heldDigest"]
                .as_str()
                .expect("v2 digest shown")
                .to_owned();
            let toggled = toggle_on_shown(&mut client, "h-5", &sid, &shown).await;
            assert!(toggled.get("result").is_some(), "mcp/toggle: {toggled}");
            let marker = home.join("mc03_marker.txt");
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline && !tags(&marker).iter().any(|t| t == "v2") {
                let _ = client
                    .wait_for_message("drain", Duration::from_millis(500), |_| false, refuse)
                    .await;
            }
            assert!(
                tags(&marker).iter().any(|t| t == "v2"),
                "{:?}",
                tags(&marker)
            );
            assert_eq!(listed(&mut client, "h-6", &sid).await["held"], false);
        })
        .await;
}
