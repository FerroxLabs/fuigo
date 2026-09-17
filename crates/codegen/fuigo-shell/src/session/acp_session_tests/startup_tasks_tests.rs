//! The run loop must start serving commands before MCP servers finish (or even start) their
//! handshakes: MCP init, the running-task promotion and the session-context snapshot are owned
//! background tasks, not inline awaits ahead of the command loop.
use super::support::*;
use super::*;
use fuigo_test_support::sse::responses_api_script_exact;
use fuigo_test_support::{MockInferenceServer, ScriptedResponse};
use std::time::Duration;

/// Leaves one stdio MCP server's handshake in flight forever, the state a slow or hung server
/// leaves the actor in right after `session/new`.
async fn leave_mcp_init_in_flight(actor: &SessionActor) {
    let mut state = actor.mcp_state.lock().await;
    state.configs = vec![acp::McpServer::Stdio(
        acp::McpServerStdio::new("slow".to_string(), "sh")
            .args(vec!["-c".to_string(), "sleep 30".to_string()])
            .env(vec![]),
    )];
    state.cancel_init();
    assert!(state.try_start_init());
    state.mark_servers_initializing(vec!["slow".into()]);
}

/// The chat-state sender is returned so the caller keeps its channel open for the loop's lifetime.
fn spawn_run_session(
    actor: Arc<SessionActor>,
    event_rx: tokio::sync::mpsc::UnboundedReceiver<SessionEvent>,
) -> (
    tokio::sync::mpsc::UnboundedSender<SessionCommand>,
    tokio::sync::mpsc::UnboundedSender<fuigo_chat_state::ChatStateEvent>,
) {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<SessionCommand>();
    let (chat_tx, chat_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::task::spawn_local(super::run_session(
        actor,
        cmd_rx,
        chat_rx,
        event_rx,
        None,
        Arc::new(parking_lot::Mutex::new(
            fuigo_workspace::file_system::CodebaseIndexManager::new(),
        )),
        std::path::PathBuf::from("/tmp"),
        crate::session::fs_watch::FsWatchCapabilities::none(),
    ));
    (cmd_tx, chat_tx)
}

/// `session/new` reads its `toolOverrides` echo from the actor; with the loop parked behind
/// `wait_for_mcp_initialized` that read blocked for the whole echo budget.
#[tokio::test(flavor = "current_thread")]
async fn run_session_serves_commands_while_mcp_init_is_in_flight() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
            let (persistence_tx, _persistence_rx) = tokio::sync::mpsc::unbounded_channel();
            let (actor, event_rx) =
                create_test_actor_ex(0, 256_000, 85, gateway_tx, persistence_tx).await;
            leave_mcp_init_in_flight(&actor).await;
            let actor = Arc::new(actor);
            let (cmd_tx, _chat_tx) = spawn_run_session(actor.clone(), event_rx);

            let (tx, rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(SessionCommand::GetToolOverrides { respond_to: tx })
                .expect("run_session must be receiving commands");
            let echo = tokio::time::timeout(Duration::from_secs(2), rx)
                .await
                .expect("the command loop must answer while the MCP handshake is still in flight")
                .expect("the actor answers GetToolOverrides");
            assert!(echo.is_none(), "no overrides were applied on this actor");
            assert!(
                !actor.mcp_state.lock().await.is_initialized(),
                "the handshake is still in flight: the loop did not wait for it"
            );
        })
        .await;
}

/// A prompt sent right after `session/new` runs while the MCP servers are still connecting.
#[tokio::test(flavor = "current_thread")]
async fn prompt_turn_completes_while_mcp_init_is_in_flight() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let server = MockInferenceServer::start()
                .await
                .expect("mock inference server");
            server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::sse(responses_api_script_exact("hello", "test")),
            );
            let sampling_config = fuigo_sampler::SamplerConfig {
                api_key: Some("test-key".into()),
                base_url: server.url(),
                model: "test".into(),
                api_backend: fuigo_sampler::ApiBackend::Responses,
                context_window: 256_000,
                max_retries: Some(0),
                idle_timeout_secs: Some(30),
                ..Default::default()
            };
            let (sampler_event_tx, mut sampler_event_rx) = tokio::sync::mpsc::unbounded_channel();
            let sampler_handle = fuigo_sampler::SamplerActor::spawn(
                sampling_config,
                fuigo_sampler::RetryPolicy {
                    max_retries: 0,
                    rate_limit_retry_threshold: 0,
                    ..Default::default()
                },
                sampler_event_tx,
            );
            let (gateway_tx, mut gateway_rx) = tokio::sync::mpsc::unbounded_channel();
            tokio::task::spawn_local(async move {
                while let Some(message) = gateway_rx.recv().await {
                    if let fuigo_acp_lib::AcpClientMessage::SessionNotification(args) = message {
                        let _ = args.response_tx.send(Ok(()));
                    }
                }
            });
            let (persistence_tx, persistence_rx) = tokio::sync::mpsc::unbounded_channel();
            super::disk_full_tests::spawn_persistence_stub(persistence_rx, || Ok(()));
            let (mut actor, event_rx) =
                create_test_actor_ex(0, 256_000, 85, gateway_tx, persistence_tx).await;
            actor.sampler_handle = sampler_handle;
            actor.compaction.verbatim_input = false;
            // Progressive: the prompt itself never waits for MCP; only the run loop's startup did.
            actor.mcp_strategy.set(McpInitStrategy::Progressive);
            let mut config = actor
                .chat_state_handle
                .get_sampling_config()
                .await
                .expect("test actor sampling config");
            config.base_url = server.url();
            config.api_backend = fuigo_sampling_types::ApiBackend::Responses;
            actor.chat_state_handle.update_sampling_config(config);
            let mut credentials = actor.chat_state_handle.get_credentials().await;
            credentials.api_key = Some("test-key".into());
            actor.chat_state_handle.update_credentials(credentials);
            leave_mcp_init_in_flight(&actor).await;
            let actor = Arc::new(actor);
            let event_actor = actor.clone();
            tokio::task::spawn_local(async move {
                while let Some(event) = sampler_event_rx.recv().await {
                    event_actor.handle_sampling_event(event).await;
                }
            });
            let (cmd_tx, _chat_tx) = spawn_run_session(actor.clone(), event_rx);

            let (respond_to, result_rx) = tokio::sync::oneshot::channel();
            cmd_tx
                .send(SessionCommand::Prompt {
                    prompt_id: "first-prompt".into(),
                    prompt_blocks: vec![acp::ContentBlock::Text(acp::TextContent::new("hi"))],
                    prompt_mode: PromptMode::Agent,
                    artifact_upload_ctx: None,
                    client_identifier: None,
                    screen_mode: None,
                    verbatim: true,
                    traceparent: None,
                    json_schema: None,
                    send_now: false,
                    admission: None,
                    tool_overrides_update: None,
                    respond_to,
                    prompt_admitted: None,
                    persist_ack: None,
                    parsed_prompt_tx: None,
                })
                .expect("run_session must be receiving commands");
            let result = tokio::time::timeout(Duration::from_secs(20), result_rx)
                .await
                .expect("the first prompt must run while the MCP handshake is still in flight")
                .expect("the actor answers the prompt");
            assert!(result.is_ok(), "the turn must complete: {result:?}");
            assert!(
                !actor.mcp_state.lock().await.is_initialized(),
                "the handshake is still in flight: the turn did not wait for it"
            );
        })
        .await;
}
