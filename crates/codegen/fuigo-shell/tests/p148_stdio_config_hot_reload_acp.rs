//! P148 item 3 (e2e C1, P141): `fuigo agent --no-leader stdio` follows MCP server edits in the user's config while a
//! session is open, as leader mode always did. Before the fix only leader mode ran the config watcher, so a dedicated
//! stdio process kept the old definition until `/plugins reload` or a restart (1.0.20 behaved the same; the user
//! guide promises config hot-reload without naming a mode).
//!
//! Real path: the real binary over stdio, a user `config.toml` stdio MCP server that records its version tag when it
//! starts, an edit of that tag on disk with the session open.
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
             "capabilities": {"tools": {}}, "serverInfo": {"name": "p148", "version": "0"}}
    elif m.get("method") == "tools/list":
        r = {"tools": []}
    else:
        r = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}) + "\n")
    sys.stdout.flush()
"#;

fn write_config(fuigo_home: &Path, script: &Path, marker: &Path, tag: &str) {
    std::fs::write(
        fuigo_home.join("config.toml"),
        format!(
            "[mcp_servers.p148reload]\ncommand = \"/usr/bin/python3\"\nargs = [\"{}\", \"{tag}\", \"{}\"]\nstartup_timeout_sec = 10\n",
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

#[tokio::test(flavor = "current_thread")]
async fn a_no_leader_stdio_agent_follows_user_mcp_config_edits() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let server = MockInferenceServer::start().await.expect("mock server");
            let sandbox = TestSandbox::new();
            let fuigo_home = sandbox.fuigo_home().to_path_buf();
            let workspace = sandbox.workspace().to_path_buf();
            let script = fuigo_home.join("p148_mcp.py");
            let marker = fuigo_home.join("p148_marker.txt");
            std::fs::write(&script, SERVER).expect("server script");
            write_config(&fuigo_home, &script, &marker, "v1");

            let spec = AgentSpawnSpec {
                agent_args: &["--no-leader"],
                ..AgentSpawnSpec::default()
            };
            let mut client = RawStdioClient::spawn_with_spec(&server, &workspace, sandbox, &spec).await;
            let init = client
                .request(
                    "p148-1",
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
                .request("p148-2", "authenticate", json!({ "methodId": "fuigo.api_key" }), RPC, refuse)
                .await;
            assert!(auth.get("result").is_some(), "authenticate: {auth}");
            let new = client
                .request("p148-3", "session/new", json!({ "cwd": workspace, "mcpServers": [] }), RPC, refuse)
                .await;
            assert!(new["result"]["sessionId"].is_string(), "session/new: {new}");

            let wait_for = |tag: &'static str, secs: u64| {
                let marker = marker.clone();
                async move {
                    let deadline = Instant::now() + Duration::from_secs(secs);
                    while Instant::now() < deadline {
                        if tags(&marker).iter().any(|t| t == tag) {
                            return true;
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                    false
                }
            };
            assert!(wait_for("v1", 30).await, "premise: the server starts with the session; tags {:?}", tags(&marker));

            // Edit the definition on disk with the session open. Keep the agent's stdout drained meanwhile.
            write_config(&fuigo_home, &script, &marker, "v2");
            let followed = {
                let deadline = Instant::now() + Duration::from_secs(30);
                let mut seen = false;
                while Instant::now() < deadline {
                    if tags(&marker).iter().any(|t| t == "v2") {
                        seen = true;
                        break;
                    }
                    let _ = client
                        .wait_for_message("drain", Duration::from_millis(500), |_| false, refuse)
                        .await;
                }
                seen
            };
            assert!(
                followed,
                "the open session must restart the edited server from disk without a restart; tags {:?}\nstderr:\n{}",
                tags(&marker),
                client.stderr()
            );
        })
        .await;
}
