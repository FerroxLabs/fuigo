//! A subagent that inherits its parent's connected MCP pool - and declares no MCP
//! server of its own - must still be handed `search_tool` / `use_tool`, because that
//! pair is the only route from a session to any MCP server (`McpState` is not handed
//! to `AgentBuilder`; `fuigo-agent/src/builder.rs` drops the pair whenever the spawn
//! site reports no reachable server).
//!
//! `a1da364` replaced the inline gate in `spawn_session_actor`
//! (`session/acp_session_impl/spawn.rs`) with `mcp_meta_tools_reachable`, which counts
//! the inherited pool as a third source. Its four unit tests pin only that pure
//! function; the defect lived at the CALL SITE, whose old boolean
//! `!mcp_servers.is_empty() || !acp_mcp_servers.is_empty() || mode == "adaptive"` never
//! looked at `parent_mcp_pool`. That exact regression leaves every unit test green, so
//! this binary drives the real path instead:
//!
//! 1. a streamable-HTTP MCP server on loopback (`initialize`, `notifications/initialized`,
//!    `tools/list`, a standing GET), declared in the parent's `config.toml` - the parent
//!    connects to it before its first turn (`run_loop` awaits `wait_for_mcp_initialized`
//!    for non-subagents), so the pool snapshot `spawn_subagent` takes
//!    (`SessionCommand::SnapshotMcpPool`) holds one live client;
//! 2. the scripted parent turn spawns one `general-purpose` child, whose builtin
//!    definition has no `mcpServers` and the default `mcpInheritance: all`, so
//!    `subagent::handle_request` hands it the parent pool and nothing else - the
//!    inherited pool is the child's ONLY MCP source;
//! 3. the child's inference request, taken off the mock, must advertise both meta-tools.
//!
//! Presentation is pinned to `full`: the `adaptive` term of the gate keeps the pair on its
//! own and would mask a call site that stopped counting the pool.
#[allow(dead_code)]
mod acp_harness;
#[path = "perf_harness/mod.rs"]
mod perf_harness;
#[path = "subagent_sweep_support/mod.rs"]
mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Value, json};

/// `run_burst`'s opening prompt to the parent (`"Spawn {n} latency probe subagents."`).
const PARENT_PROMPT_TAIL: &str = "latency probe subagents.";
/// The tail of the probe prompt the scripted parent turn gives its one child
/// (`burst_tool_calls_sse`: `"Reply with the word done and nothing else (000)."`).
const CHILD_PROMPT_TAIL: &str = "nothing else (000).";

/// How long the fixture stalls every `tools/list` after the parent's.
/// Far longer than the child's spawn-to-first-turn path, so a child that does not wait for the registration misses the server notice,
/// and well inside the 10 s bound `await_inherited_mcp_registration` waits for it.
const CHILD_TOOLS_LIST_DELAY_MS: u64 = 3000;

#[derive(Clone)]
struct FixtureMcp {
    initializes: Arc<AtomicUsize>,
    tool_lists: Arc<AtomicUsize>,
}

/// Minimal streamable-HTTP MCP server: enough of the protocol for `McpClient` to
/// handshake and register one tool, and nothing that could reach the assertions.
async fn handle_post(State(state): State<FixtureMcp>, Json(req): Json<Value>) -> Response {
    match req["method"].as_str() {
        Some("initialize") => {
            state.initializes.fetch_add(1, Ordering::SeqCst);
            let result = json!({
                "jsonrpc": "2.0",
                "id": req["id"],
                "result": {
                    "protocolVersion": req["params"]["protocolVersion"],
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "parent-pool-fixture", "version": "0.0.0"},
                },
            });
            ([("mcp-session-id", "parent-pool-fixture-session")], Json(result)).into_response()
        }
        Some("tools/list") => {
            // The first call is the parent's own registration. Every later call is a child registering the
            // inherited client's tools, and a slow one is what exposed the "was the child told" race.
            if state.tool_lists.fetch_add(1, Ordering::SeqCst) >= 1 {
                tokio::time::sleep(std::time::Duration::from_millis(CHILD_TOOLS_LIST_DELAY_MS)).await;
            }
            Json(json!({
                "jsonrpc": "2.0",
                "id": req["id"],
                "result": {"tools": [{
                    "name": "echo",
                    "description": "echo the input",
                    "inputSchema": {"type": "object", "properties": {}},
                }]},
            }))
            .into_response()
        }
        // `notifications/initialized`, the anonymous-access probe (`{}`) and anything else.
        _ => StatusCode::ACCEPTED.into_response(),
    }
}

async fn handle_get() -> Response {
    let body = Body::from_stream(futures::stream::pending::<Result<String, std::io::Error>>());
    ([(header::CONTENT_TYPE, "text/event-stream")], body).into_response()
}

async fn start_fixture_mcp(state: FixtureMcp) -> String {
    let app = axum::Router::new()
        .route("/mcp", get(handle_get).post(handle_post))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture MCP server");
    let addr = listener.local_addr().expect("fixture MCP addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}/mcp")
}

fn tool_names(body: &Value) -> Vec<String> {
    body["tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|t| t["function"]["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Every user-role message of a request, as JSON text.
///
/// Not just the last one: a turn's prompt is not always its last message. Under load the child's inherited MCP pool
/// reports "MCP server connected" before the child builds its first request, and that `<system-reminder>` is appended
/// as a trailing user message after the probe prompt. Matching on the LAST user message then missed the child's
/// main-turn request entirely (measured: request `turn_idx=1`, `[system, probe prompt, reminder]`, advertising
/// `search_tool`/`use_tool`), and the test failed with "no main-turn inference request from the child".
fn user_messages(body: &Value) -> Vec<String> {
    body["messages"]
        .as_array()
        .map(|messages| {
            messages
                .iter()
                .filter(|m| m["role"] == "user")
                .map(|m| m["content"].to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn has_user_message(body: &Value, tail: &str) -> bool {
    user_messages(body).iter().any(|c| c.contains(tail))
}

#[test]
fn inherited_parent_pool_keeps_the_mcp_meta_tools_reachable_from_the_child() {
    // One test per binary; set before any agent or mock thread exists.
    unsafe {
        std::env::set_var("FUIGO_TOOL_PRESENTATION", "full");
        std::env::set_var("FUIGO_MAX_MODEL_CALLS", "20");
        std::env::set_var("FUIGO_SWEEP_DEADLINE_S", "60");
        std::env::set_var("FUIGO_TURN_SUMMARY", "false");
    }
    let env = support::sweep_env_init();

    let fixture = FixtureMcp {
        initializes: Arc::new(AtomicUsize::new(0)),
        tool_lists: Arc::new(AtomicUsize::new(0)),
    };
    let mcp_url = env.mock_rt.block_on(start_fixture_mcp(fixture.clone()));

    // The parent's one MCP server. `sweep_env_init` has already pointed `FUIGO_HOME`
    // and `HOME` at empty temp dirs, so this declaration is the parent's only MCP
    // source and the child's only inheritable one.
    let fuigo_home = std::path::PathBuf::from(
        std::env::var_os("FUIGO_HOME").expect("sweep_env_init sets FUIGO_HOME"),
    );
    std::fs::create_dir_all(&fuigo_home).expect("fuigo home");
    std::fs::write(
        fuigo_home.join("config.toml"),
        format!("[mcp_servers.parent-pool-fixture]\nurl = \"{mcp_url}\"\n"),
    )
    .expect("write parent MCP declaration");

    let server = env
        .mock_rt
        .block_on(fuigo_test_support::MockInferenceServer::start())
        .expect("mock server");
    unsafe {
        std::env::set_var("FUIGO_CLI_CHAT_PROXY_BASE_URL", server.url());
        std::env::set_var("FUIGO_API_BASE_URL", server.url());
    }

    let outcome = support::run_burst(&server, 1, "none", env.deadline);
    assert_eq!(outcome.rows.len(), 1, "one real native child must be observed");
    assert_eq!(outcome.failures, 0, "the native child did not complete");

    // The pool the child inherits is `SharedMcpPool::from_state`, which holds only
    // clients that finished their handshake. Without this the test could pass or
    // fail for a reason other than the call site.
    assert!(
        fixture.initializes.load(Ordering::SeqCst) >= 1
            && fixture.tool_lists.load(Ordering::SeqCst) >= 1,
        "the parent never connected to the fixture MCP server (initialize={}, tools/list={}); \
         the inherited pool would be empty and this test would measure nothing",
        fixture.initializes.load(Ordering::SeqCst),
        fixture.tool_lists.load(Ordering::SeqCst),
    );

    // Main-turn requests only: they carry `x-fuigo-turn-idx` (`fuigo-sampler/src/client.rs`),
    // side calls do not. A session-title side call repeats the session's prompt as its last
    // user message and advertises only `session_title`, so matching on the prompt alone would
    // fail on that side call whatever the call site under test does.
    let bodies: Vec<Value> = server
        .requests()
        .iter()
        .filter(|r| r.path == "/v1/chat/completions" && r.header("x-fuigo-turn-idx").is_some())
        .filter_map(|r| r.body.as_ref().and_then(|b| serde_json::from_str(&b.to_string()).ok()))
        .collect();

    // Control: the parent declared the server itself, so its own-servers term keeps
    // the pair regardless of the call site under test. Its turn is the first one that
    // carries `run_burst`'s opening prompt.
    let parent = bodies
        .iter()
        .find(|b| has_user_message(b, PARENT_PROMPT_TAIL))
        .expect("the parent's main-turn inference request");
    for required in ["search_tool", "use_tool"] {
        assert!(
            tool_names(parent).iter().any(|n| n == required),
            "the parent, which declared the MCP server, lost {required}: {:?}",
            tool_names(parent)
        );
    }

    // The child's turn: it carries, as a user message, the probe prompt the parent's
    // scripted `spawn_subagent` call gave it, and never the parent's prompt (the parent's
    // own requests hold the probe text only inside its tool-call arguments).
    let child_requests: Vec<&Value> = bodies
        .iter()
        .filter(|b| has_user_message(b, CHILD_PROMPT_TAIL) && !has_user_message(b, PARENT_PROMPT_TAIL))
        .collect();
    assert!(
        !child_requests.is_empty(),
        "no main-turn inference request from the child was observed\n{}",
        server.request_log_summary()
    );
    let first_child = child_requests[0];
    for child in child_requests {
        let offered = tool_names(child);
        for required in ["search_tool", "use_tool"] {
            assert!(
                offered.iter().any(|n| n == required),
                "a child with no MCP server of its own inherited its parent's connected pool \
                 but was not handed {required}, so it holds a live MCP client it cannot call; \
                 advertised: {offered:?}"
            );
        }
    }

    // P-6: the child must be told about the inherited server deterministically, in its FIRST request, exactly once.
    // Before the fix the notice depended on whether the child's tool registration beat the turn's reminder injection.
    let notice_count = first_child["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .filter(|m| m["content"].to_string().contains("MCP server connected:"))
        .filter(|m| m["content"].to_string().contains("parent-pool-fixture"))
        .count();
    assert_eq!(
        notice_count, 1,
        "the child's first request must carry exactly one 'MCP server connected' notice naming the inherited server \
         (got {notice_count}); a missing notice means the turn started before the inherited tools registered"
    );
}
