//! The session's own agent definition declares `mcpServers` (agent.md). They win over the disk/client merge by name
//! and a plugin reload, which re-merges disk and client servers, must not lose them. Red first.

use agent_client_protocol as acp;
use fuigo_agent::config::{AgentDefinition, AgentScope, McpServerRef};
use fuigo_agent::plugins::SharedPluginRegistryHandle;

fn url_of(servers: &[acp::McpServer], name: &str) -> Option<String> {
    servers.iter().find_map(|s| match s {
        acp::McpServer::Http(s) if s.name == name => Some(s.url.clone()),
        _ => None,
    })
}

fn seat_with(servers: Vec<McpServerRef>) -> AgentDefinition {
    let mut definition = AgentDefinition::default_fuigo_build();
    definition.name = "seat".to_owned();
    definition.scope = AgentScope::User;
    definition.mcp_servers = servers;
    definition
}

fn inline(name: &str, url: &str) -> McpServerRef {
    McpServerRef::Inline {
        name: name.to_owned(),
        config: serde_json::json!({"type": "http", "url": url, "headers": []}),
    }
}

/// `~/.cursor/mcp.json` defines `adder` (a disk source); the seat's agent.md defines `adder` too, plus `extra`.
/// After the plugin reload the agent definition's `adder` is the one running, and `extra` is still there.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_plugin_reload_keeps_the_agent_definitions_mcp_servers_over_the_disk_merge() {
    // Writes FUIGO_HOME / HOME, which every test in this binary reads: run in a process of its own
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    use fuigo_test_support::env::EnvGuard;
    let fuigo_home = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let _fh = EnvGuard::set("FUIGO_HOME", fuigo_home.path());
    let _h = EnvGuard::set("HOME", home.path());
    let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let _key = EnvGuard::unset("FUIGO_API_KEY");
    std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
    std::fs::write(
        home.path().join(".cursor/mcp.json"),
        r#"{"mcpServers":{"adder":{"url":"https://disk.example/mcp"}}}"#,
    )
    .unwrap();
    let repo = tempfile::tempdir().unwrap();
    git2::Repository::init(repo.path()).unwrap();
    crate::agent::folder_trust::record_for_test(repo.path(), true);
    let handle = SharedPluginRegistryHandle::new(None, vec![]);
    let registry = handle.build_for_cwd(
        repo.path(),
        &fuigo_agent::plugins::discovery::DiscoveryConfig::default(),
        &[],
        true,
    );

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
            let (persistence_tx, _persistence_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut actor = crate::session::acp_session::support::create_test_actor(
                0,
                256_000,
                85,
                gateway_tx,
                persistence_tx,
            )
            .await;
            actor.session_info.cwd = repo.path().display().to_string();
            actor.plugin_registry_handle = Some(handle.clone());
            *actor.agent.borrow_mut() =
                crate::session::acp_session::support::test_agent_from_config(
                    fuigo_tools::registry::types::ToolServerConfig {
                        tools: vec![],
                        behavior_preset: None,
                    },
                    seat_with(vec![
                        inline("adder", "https://agent.example/mcp"),
                        inline("extra", "https://extra.example/mcp"),
                    ]),
                    std::sync::Arc::new(fuigo_tools::computer::local::LocalTerminalBackend::new()),
                )
                .await;
            let actor = std::sync::Arc::new(actor);
            let _ = actor.apply_plugin_registry_snapshot(registry).await;
            let configs = actor.mcp_state.lock().await.configs.clone();
            assert_eq!(
                url_of(&configs, "adder").as_deref(),
                Some("https://agent.example/mcp"),
                "the disk merge replaced the agent definition's server on reload: {configs:?}"
            );
            assert_eq!(
                url_of(&configs, "extra").as_deref(),
                Some("https://extra.example/mcp"),
                "the agent definition's server was lost on reload: {configs:?}"
            );
        })
        .await;
}
