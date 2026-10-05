//! P141 (Fable MEDIUM 1 on P138): the hot-reload seed must not be judged against one plugin registry at session entry and
//! re-merged against another later. End to end through the production paths: the ingress
//! (`admit_client_mcp_servers_for_seed`, what `session/new` and `update_mcp_servers` call), the folder-trust grant's MCP
//! merge, and the `ReloadPlugins` adoption (`apply_plugin_registry_snapshot`) with a registry rebuilt for the session's
//! cwd on the granted verdict. Red first.

use agent_client_protocol as acp;
use fuigo_agent::plugins::SharedPluginRegistryHandle;
use fuigo_agent::plugins::discovery::DiscoveryConfig;

fn command_of<'a>(servers: &'a [acp::McpServer], name: &str) -> Option<&'a str> {
    servers.iter().find_map(|s| match s {
        acp::McpServer::Stdio(s) if s.name == name => Some(s.command.to_str().unwrap_or_default()),
        _ => None,
    })
}

/// `~/.cursor/mcp.json` has `corp` (the user's server, forwarded by the pager); the repo, untrusted at `session/new`, has a
/// plugin defining another `corp`. The user trusts the folder: the plugin loads, but `corp` stays the user's server, as
/// it was before the grant and as it is again after a restart.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_trust_grant_does_not_let_a_repo_plugin_replace_the_users_own_server() {
    // Writes FUIGO_HOME / HOME, which every test in this binary reads: run in a process of its own
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    use fuigo_test_support::env::EnvGuard;
    let fuigo_home = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let _fh = EnvGuard::set("FUIGO_HOME", fuigo_home.path());
    let _h = EnvGuard::set("HOME", home.path());
    let _sim = EnvGuard::set(fuigo_version::TEST_VERSION_ENV, "0.0.0-p141-sim");
    let _flag = EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let _key = EnvGuard::unset("FUIGO_API_KEY");
    std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
    std::fs::write(
        home.path().join(".cursor/mcp.json"),
        r#"{"mcpServers":{"corp":{"command":"p141-user-corp-server"}}}"#,
    )
    .unwrap();
    let repo = tempfile::tempdir().unwrap();
    git2::Repository::init(repo.path()).unwrap();
    let plugin_root = repo.path().join(".fuigo/plugins/corpplug");
    std::fs::create_dir_all(&plugin_root).unwrap();
    std::fs::write(
        plugin_root.join("plugin.json"),
        serde_json::json!({
            "name": "corpplug",
            "mcpServers": {"mcpServers": {"corp": {"command": "p141-plugin-corp-server"}}}
        })
        .to_string(),
    )
    .unwrap();
    let cfg = DiscoveryConfig { enabled: vec!["corpplug".to_string()], ..Default::default() };
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let handle = SharedPluginRegistryHandle::new(None, vec![]);

    // session/new while the folder is untrusted: the repo's plugin is not active.
    crate::agent::folder_trust::record_for_test(repo.path(), false);
    let untrusted = handle.build_for_cwd(repo.path(), &cfg, &[], false);
    assert!(
        !untrusted.as_deref().is_some_and(|r| r.active_plugins().iter().any(|p| p.name == "corpplug")),
        "fixture: the repo plugin is inactive while the folder is untrusted"
    );
    let forwarded = crate::util::config::load_mcp_servers(repo.path(), &compat);
    assert_eq!(command_of(&forwarded, "corp"), Some("p141-user-corp-server"), "fixture: the pager forwards the user's corp");
    let ingress = crate::session::managed_mcp::admit_client_mcp_servers_for_seed(
        forwarded,
        repo.path(),
        &compat,
        untrusted.as_deref(),
    );
    let seed = ingress.seed;

    // The user trusts the folder.
    crate::agent::folder_trust::record_for_test(repo.path(), true);
    let trusted = handle.build_for_cwd(repo.path(), &cfg, &[], true);
    assert!(
        trusted.as_deref().is_some_and(|r| r.active_plugins().iter().any(|p| p.name == "corpplug")),
        "fixture: the repo plugin is active once the folder is trusted"
    );
    // The grant's MCP merge (`reload_project_servers_after_grant`).
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    assert!(crate::session::managed_mcp::merge_and_send_managed_mcp_update_with_notices(
        &tx,
        repo.path(),
        seed.clone(),
        handle.snapshot().as_deref(),
        &compat,
    ));
    let mut grant_update = None;
    while let Ok(cmd) = rx.try_recv() {
        if let crate::session::SessionCommand::UpdateMcpServers { mcp_servers, .. } = cmd {
            grant_update = Some(mcp_servers);
        }
    }
    let grant_update = grant_update.expect("the grant sent an MCP update");
    assert_eq!(command_of(&grant_update, "corp"), Some("p141-user-corp-server"), "grant merge: corp is not the user's");

    // Then `ReloadPlugins` with the registry built for the session's cwd on the granted verdict.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
            let (persistence_tx, _persistence_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut actor =
                crate::session::acp_session::support::create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
            actor.session_info.cwd = repo.path().display().to_string();
            actor.plugin_registry_handle = Some(handle.clone());
            actor.set_client_mcp_seed(seed);
            let actor = std::sync::Arc::new(actor);
            let _ = actor.apply_plugin_registry_snapshot(trusted).await;
            let configs = actor.mcp_state.lock().await.configs.clone();
            assert_eq!(
                command_of(&configs, "corp"),
                Some("p141-user-corp-server"),
                "after the plugin reload the repo plugin's corp replaced the user's own server: {configs:?}"
            );
        })
        .await;
}
