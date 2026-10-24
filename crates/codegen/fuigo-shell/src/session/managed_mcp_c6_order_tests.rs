//! The order MCP sources are merged in, pinned end to end through the production merge (`merge_managed_mcp_servers`):
//! the nearest project `config.toml`, then the user `config.toml`, then plugins, `~/.claude.json`, the Cursor project
//! `mcp.json`, the Cursor user `mcp.json`, and the project `.mcp.json` last. A server a `config.toml` marks
//! `enabled = false` still hides its name from every later source.

use super::*;

fn url_of(servers: &[acp::McpServer], name: &str) -> Option<String> {
    servers
        .iter()
        .find(|s| mcp_server_name(s) == name)
        .and_then(|s| match s {
            acp::McpServer::Http(h) => Some(h.url.clone()),
            _ => None,
        })
}

fn write(path: &std::path::Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn json_server(url: &str) -> String {
    format!(r#"{{"mcpServers":{{"dup":{{"type":"http","url":"{url}"}}}}}}"#)
}

fn toml_server(url: &str, enabled: bool) -> String {
    format!("[mcp_servers.dup]\nurl = \"{url}\"\nenabled = {enabled}\n")
}

#[test]
fn a_name_defined_in_every_source_resolves_in_the_documented_order() {
    // Writes FUIGO_HOME and HOME, which every test in this binary reads: run in a process of its own
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let fuigo_home = fuigo_test_support::FuigoHome::new();
    let home = tempfile::tempdir().unwrap();
    let _home = fuigo_test_support::EnvGuard::set("HOME", home.path());
    let repo = tempfile::tempdir().unwrap();
    git2::Repository::init(repo.path()).unwrap();
    crate::agent::folder_trust::record_for_test(repo.path(), true);
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let merged_url = || {
        let merged = merge_managed_mcp_servers(vec![], repo.path(), None, &compat);
        url_of(&merged, "dup")
    };
    let user_toml = fuigo_home.path().join("config.toml");
    let project_toml = repo.path().join(".fuigo/config.toml");
    let claude_json = home.path().join(".claude.json");
    let cursor_project = repo.path().join(".cursor/mcp.json");
    let cursor_user = home.path().join(".cursor/mcp.json");
    let mcp_json = repo.path().join(".mcp.json");

    write(&user_toml, &toml_server("https://user.example/mcp", true));
    write(
        &project_toml,
        &toml_server("https://project.example/mcp", true),
    );
    write(&claude_json, &json_server("https://claude.example/mcp"));
    write(
        &cursor_project,
        &json_server("https://cursor-project.example/mcp"),
    );
    write(
        &cursor_user,
        &json_server("https://cursor-user.example/mcp"),
    );
    write(&mcp_json, &json_server("https://mcp-json.example/mcp"));

    assert_eq!(
        merged_url().as_deref(),
        Some("https://project.example/mcp"),
        "the nearest project config.toml wins"
    );
    std::fs::remove_file(&project_toml).unwrap();
    assert_eq!(
        merged_url().as_deref(),
        Some("https://user.example/mcp"),
        "then the user config.toml"
    );
    std::fs::remove_file(&user_toml).unwrap();
    assert_eq!(
        merged_url().as_deref(),
        Some("https://claude.example/mcp"),
        "then ~/.claude.json"
    );
    std::fs::remove_file(&claude_json).unwrap();
    assert_eq!(
        merged_url().as_deref(),
        Some("https://cursor-project.example/mcp"),
        "then the Cursor project mcp.json"
    );
    std::fs::remove_file(&cursor_project).unwrap();
    assert_eq!(
        merged_url().as_deref(),
        Some("https://cursor-user.example/mcp"),
        "then the Cursor user mcp.json"
    );
    std::fs::remove_file(&cursor_user).unwrap();
    assert_eq!(
        merged_url().as_deref(),
        Some("https://mcp-json.example/mcp"),
        "the project .mcp.json comes last"
    );

    // `enabled = false` in a config.toml hides the name from every later source.
    write(&user_toml, &toml_server("https://user.example/mcp", false));
    write(&claude_json, &json_server("https://claude.example/mcp"));
    write(
        &cursor_user,
        &json_server("https://cursor-user.example/mcp"),
    );
    assert_eq!(
        merged_url(),
        None,
        "a disabled config.toml server must not hand its name to a later source"
    );
}
