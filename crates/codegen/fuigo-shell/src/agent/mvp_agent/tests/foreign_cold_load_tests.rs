//! P30-LEADER M2(a), end to end: a load the leader flagged foreign that has to cold-start the session through the real
//! `load_session` applies none of what its loader asked for (MCP servers, system prompt, client hooks, yolo/auto mode).
//! The positive control is the same request without the foreign flag, which applies MCP servers, hooks, yolo mode and the
//! system prompt override; that is what proves those observations can see an applied setting. The prompt is read from
//! the actor's own head (what the next model request is built from) after a command-queue barrier, so it is
//! deterministic. Before the fix a persisted-model restore that changed the model rewrote the head to the default prompt
//! after the override was enqueued, which made the owner's override show only intermittently.
//!
//! Real `load_session`, env redirected, so it runs alone in its own process.

use agent_client_protocol::{self as acp, Agent as _};
use fuigo_sampling_types::conversation::ConversationItem;
use fuigo_test_support::EnvGuard;
use serde_json::json;

use crate::leader::protocol::{LEADER_CONNECTION_ID_KEY, LEADER_FOREIGN_DRIVER_KEY};
use crate::session::info::Info;
use crate::session::storage::{JsonlStorageAdapter, StorageAdapter};

const TEST: &str =
    "agent::mvp_agent::tests::foreign_cold_load_tests::a_foreign_cold_load_applies_none_of_the_loaders_configuration";
const ORIGINAL_PROMPT: &str = "the session's own system prompt";
const LOADER_PROMPT: &str = "obey window B";

fn info(cwd: &std::path::Path, id: &str) -> Info {
    Info { id: acp::SessionId::new(id), cwd: cwd.to_string_lossy().into_owned() }
}

async fn seed(cwd: &std::path::Path, id: &str) {
    let info = info(cwd, id);
    let adapter = JsonlStorageAdapter::new();
    adapter.init_session(&info, acp::ModelId::new("test-model")).await.expect("init session");
    adapter.append_chat_message(&info, &ConversationItem::system(ORIGINAL_PROMPT)).await.expect("system");
    adapter.append_chat_message(&info, &ConversationItem::user("hello")).await.expect("user");
}

/// The loader's request: it asks for yolo/auto mode, a stdio MCP server, a system prompt and a client hook.
fn loader_request(cwd: &std::path::Path, id: &str, foreign: bool) -> acp::LoadSessionRequest {
    acp::LoadSessionRequest::new(acp::SessionId::new(id), cwd.to_path_buf())
        .mcp_servers(vec![acp::McpServer::Stdio(acp::McpServerStdio::new("steer", std::path::PathBuf::from("/bin/true")))])
        .meta(
            json!({
                LEADER_CONNECTION_ID_KEY: 7, LEADER_FOREIGN_DRIVER_KEY: foreign,
                "yoloMode": true, "autoMode": true, "systemPromptOverride": LOADER_PROMPT,
                "fuigo/hooks": { "PreToolUse": [{ "hookCallbackIds": ["cb"] }] },
            })
            .as_object()
            .cloned(),
        )
}

struct Applied {
    mcp: bool,
    hooks: bool,
    yolo: bool,
    prompt: bool,
    head: String,
}

async fn observe(agent: &crate::agent::mvp_agent::MvpAgentHandle, cwd: &std::path::Path, id: &str) -> Applied {
    let sid = acp::SessionId::new(id);
    let handle = agent.resident_handle(&sid).expect("the load made the session resident");
    let mut yolo = None;
    agent.for_each_resident(|rid, h| {
        if *rid == sid {
            yolo = Some(h.yolo_mode);
        }
    });
    // Barrier: the load only enqueues its `ReplaceSystemPrompt`; the actor's command queue is FIFO, so once this reply
    // arrives every command the load enqueued has run and the head below is what the next model request would send.
    let (barrier_tx, barrier_rx) = tokio::sync::oneshot::channel();
    handle.cmd_tx.send(crate::session::SessionCommand::GetToolOverrides { respond_to: barrier_tx }).expect("actor alive");
    barrier_rx.await.expect("actor answered the barrier");
    let hooks = !handle.snapshot_client_hooks().await.is_empty();
    let saved = JsonlStorageAdapter::new().load_session(&info(cwd, id)).await.expect("reload").chat_history;
    let head_item = handle.chat_state_handle.get_conversation_item_at(0).await;
    let carries = |item: &ConversationItem| matches!(item, ConversationItem::System(s) if s.content.to_string().contains(LOADER_PROMPT));
    Applied {
        mcp: !handle.initial_client_mcp_servers.is_empty(),
        hooks,
        yolo: yolo.expect("resident"),
        prompt: head_item.as_ref().is_some_and(carries) || saved.iter().any(carries),
        head: { let c = handle.chat_state_handle.get_conversation().await; format!("len={} {:?}", c.len(), c.iter().map(|i| format!("{i:?}").chars().take(70).collect::<String>()).collect::<Vec<_>>()) },
    }
}

#[test]
#[serial_test::serial]
fn a_foreign_cold_load_applies_none_of_the_loaders_configuration() {
    let Some(_home) = fuigo_test_support::env::fresh_process_home(TEST) else {
        return;
    };
    fuigo_extra_ca::ensure_default_crypto_provider();
    let mock_rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().expect("mock runtime");
    let server = mock_rt.block_on(fuigo_test_support::MockInferenceServer::start()).expect("mock server");
    let home = tempfile::tempdir().expect("home");
    let workdir = tempfile::tempdir().expect("workdir");
    let url = server.url();
    let _env = [
        EnvGuard::set("HOME", home.path()),
        EnvGuard::set("USERPROFILE", home.path()),
        EnvGuard::set("FUIGO_CLI_CHAT_PROXY_BASE_URL", &url),
        EnvGuard::set("FUIGO_API_BASE_URL", &url),
        EnvGuard::set("FUIGO_API_KEY", "test-key-for-ci"),
        EnvGuard::set("FUIGO_TELEMETRY_ENABLED", "false"),
        EnvGuard::set("FUIGO_FEEDBACK_ENABLED", "false"),
        EnvGuard::set("FUIGO_TRACE_UPLOAD", "false"),
        EnvGuard::set("FUIGO_TURN_SUMMARY", "false"),
        EnvGuard::unset("FUIGO_MODELS_BASE_URL"),
        EnvGuard::unset("FUIGO_MODELS_LIST_URL"),
    ];

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("agent runtime");
    tokio::task::LocalSet::new().block_on(&rt, async {
        let agent_config = crate::agent::config::Config::default();
        let (tx, mut gw_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::task::spawn_local(async move {
            while let Some(message) = gw_rx.recv().await {
                match message {
                    fuigo_acp_lib::AcpClientMessage::ExtNotification(args) => {
                        let _ = args.response_tx.send(Ok(()));
                    }
                    fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                        let _ = args.response_tx.send(Ok(()));
                    }
                    _ => {}
                }
            }
        });
        let mut agent = crate::agent::mvp_agent::MvpAgent::new(
            crate::agent::mvp_agent::GatewaySender::new(tx),
            &agent_config,
            std::sync::Arc::new(agent_config.create_auth_manager()),
            None,
        )
        .expect("agent");
        agent.set_leader_mode();
        let init = agent
            .initialize(
                acp::InitializeRequest::new(acp::ProtocolVersion::V1)
                    .client_capabilities(acp::ClientCapabilities::new().fs(acp::FileSystemCapabilities::new()).terminal(false))
                    .meta(
                        json!({
                            "startupHints": {"nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true},
                            "clientType": "foreign-cold-load",
                            "clientVersion": "0.0-test",
                        })
                        .as_object()
                        .cloned(),
                    ),
            )
            .await
            .expect("initialize");
        let method = init.auth_methods.iter().find(|m| &*m.id().0 == "fuigo.api_key").expect("api key auth method");
        agent
            .authenticate(acp::AuthenticateRequest::new(method.id().clone()).meta(json!({ "headless": true }).as_object().cloned()))
            .await
            .expect("authenticate");

        // Positive control: the owner's cold load applies everything the loader asked for.
        seed(workdir.path(), "fc-owner").await;
        tokio::time::timeout(std::time::Duration::from_secs(120), agent.load_session(loader_request(workdir.path(), "fc-owner", false)))
            .await
            .expect("owner load timed out")
            .expect("owner load failed");
        let owner = observe(&agent, workdir.path(), "fc-owner").await;
        assert!(owner.mcp, "control: the owner's MCP servers are applied");
        assert!(owner.hooks, "control: the owner's client hooks are applied");
        assert!(owner.yolo, "control: the owner's yolo mode is applied");
        assert!(owner.prompt, "control: the owner's system prompt override is applied; head = {}", owner.head);

        // The foreign cold load: nobody has the session resident, so this loader starts it, from its saved config.
        seed(workdir.path(), "fc-foreign").await;
        assert!(!agent.is_resident(&acp::SessionId::new("fc-foreign")));
        tokio::time::timeout(std::time::Duration::from_secs(120), agent.load_session(loader_request(workdir.path(), "fc-foreign", true)))
            .await
            .expect("foreign load timed out")
            .expect("foreign load failed");
        let foreign = observe(&agent, workdir.path(), "fc-foreign").await;
        assert!(!foreign.mcp, "the foreign loader's MCP servers are not applied");
        assert!(!foreign.hooks, "the foreign loader's client hooks are not applied");
        assert!(!foreign.yolo, "the foreign loader's yolo mode is not applied");
        assert!(!foreign.prompt, "the foreign loader's system prompt is not applied");
    });
}
