//! P118 (backlog row P103): a plugin's MCP servers may not name the saved API key. Red first.

use super::*;

#[test]
fn a_plugin_mcp_server_cannot_name_the_saved_key() {
    let root = serde_json::json!({
        "mcpServers": {
            "p118-plugin-stdio": {
                "command": "x",
                "args": ["--key=${FUIGO_API_KEY}"],
                "env": { "TOKEN": "${FUIGO_API_KEY}", "OTHER": "ok" }
            },
            "p118-plugin-http": {
                "url": "https://p.p118.invalid/mcp",
                "headers": { "Authorization": "Bearer ${FUIGO_API_KEY}" }
            }
        }
    });
    let (servers, _oauth) = load_plugin_mcp_servers_from_value(&root, "acme", "/plugins/acme", "/data/acme");
    assert_eq!(servers.len(), 2, "both servers still load; only the references are refused");
    for server in &servers {
        match server {
            acp::McpServer::Stdio(s) => {
                assert!(s.args.iter().all(|a| !a.contains("FUIGO_API_KEY")), "{:?}", s.args);
                let token = s.env.iter().find(|e| e.name == "TOKEN").expect("TOKEN");
                assert_eq!(token.value, "");
                assert!(s.env.iter().any(|e| e.name == "OTHER" && e.value == "ok"));
            }
            acp::McpServer::Http(h) => {
                let auth = h.headers.iter().find(|x| x.name == "Authorization").expect("Authorization");
                assert_eq!(auth.value, "Bearer ");
            }
            _ => {}
        }
    }
    let notes = fuigo_config::key_naming::refusal_notes();
    assert!(
        notes.iter().any(|n| n.contains("plugin:acme") && n.contains("mcpServers.p118-plugin-stdio.env.TOKEN") && n.contains("FUIGO_API_KEY")),
        "no note naming the plugin and the key: {notes:?}"
    );
}

/// Astra r1 #6: a plugin's MCP file is refused wherever the plugin sits, even under `$FUIGO_HOME` (`--plugin-dir`).
#[test]
fn a_plugin_mcp_file_under_the_user_home_is_still_refused() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let dir = fuigo_config::fuigo_home().join("dev").join("acme");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(".mcp.json");
    std::fs::write(
        &path,
        r#"{"mcpServers":{"p118-dev":{"command":"x","env":{"TOKEN":"${FUIGO_API_KEY}","OTHER":"ok"}}}}"#,
    )
    .unwrap();
    let (servers, _) = load_plugin_mcp_servers(&path, "acme", "/plugins/acme", "/data/acme");
    let acp::McpServer::Stdio(s) = &servers[0] else { panic!("stdio") };
    assert_eq!(s.env.iter().find(|e| e.name == "TOKEN").unwrap().value, "");
}

/// Astra r3 R2-7: the refusal note for an inline plugin manifest names the manifest FILE.
#[test]
fn an_inline_plugin_refusal_names_the_manifest_path() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join(".claude-plugin").join("plugin.json");
    std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    std::fs::write(&manifest, "{}").unwrap();
    let label = plugin_manifest_label(dir.path(), "acme7");
    assert_eq!(label, manifest.display().to_string());
    let root = serde_json::json!({"mcpServers": {"p118-r27": {"command": "x", "env": {"TOKEN": "${FUIGO_API_KEY}"}}}});
    let _ = load_plugin_mcp_servers_from_value_labelled(&root, &label, "acme7", "/plugins/acme7", "/data/acme7");
    let notes = fuigo_config::key_naming::refusal_notes();
    assert!(
        notes.iter().any(|n| n.starts_with(&label) && n.contains("mcpServers.p118-r27.env.TOKEN")),
        "no note naming {label}: {notes:?}"
    );
}
