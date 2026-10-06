//! P113 (E2): the variables an MCP server's config names as holding its credential (`bearer_token_env_var`,
//! `oauth_client_secret_env_var`, `[oauth] client_secret_env_var`) are denied to every child process, like a model's
//! `env_key` (P86): server A's token must not reach the model's bash tool, server B, a hook or a language server.
//! The denylist is process-wide and only grows, so every test uses names no other test registers.

use super::*;
use fuigo_tools::util::shell_env_policy::is_provider_credential;

/// At config parse: the `[mcp_servers.*]` loader registers the names before any server is built or spawned, so a
/// stdio server started earlier than the HTTP server that names the token (or one that never connects) cannot
/// inherit it. Also the hot-reload path, which parses the new file before it restarts servers.
#[test]
fn p113_mcp_credential_variables_are_denied_at_config_parse() {
    let names = [
        "P113_PARSE_BEARER",
        "P113_PARSE_OAUTH_SECRET",
        "P113_PARSE_OAUTH_BLOCK_SECRET",
        "P113_RELOAD_BEARER",
    ];
    for name in names {
        assert!(!is_provider_credential(name), "precondition: {name} is not denied yet");
    }
    let raw: TomlValue = toml::from_str(
        r#"
[mcp_servers.tracker]
url = "https://mcp.p113.invalid/mcp"
bearer_token_env_var = "P113_PARSE_BEARER"
oauth_client_id = "client"
oauth_client_secret_env_var = "P113_PARSE_OAUTH_SECRET"

[mcp_servers.disabled_one]
url = "https://mcp2.p113.invalid/mcp"
enabled = false

[mcp_servers.disabled_one.oauth]
clientId = "client2"
clientSecretEnvVar = "P113_PARSE_OAUTH_BLOCK_SECRET"
"#,
    )
    .unwrap();
    let parsed = parse_mcp_servers_from_toml(&raw);
    assert_eq!(parsed.len(), 2, "control: both servers parse");
    for name in &names[..3] {
        assert!(is_provider_credential(name), "{name}, named by an MCP server's config, reaches child processes");
    }

    let reloaded: TomlValue = toml::from_str(
        r#"
[mcp_servers.added_on_reload]
url = "https://mcp3.p113.invalid/mcp"
bearer_token_env_var = "P113_RELOAD_BEARER"
"#,
    )
    .unwrap();
    crate::agent::config::deny_credentials_named_in(&reloaded);
    assert!(is_provider_credential("P113_RELOAD_BEARER"), "the hot-reload pre-pass leaves the new token inheritable");
}

/// At resolution: a server config that never went through the TOML loader (`.mcp.json`, an import, a plugin) has
/// its names registered where `fuigo-config-types` reads the token and the client secret.
#[test]
fn p113_mcp_credential_variables_are_denied_at_resolution() {
    let config: McpServerConfig = serde_json::from_value(serde_json::json!({
        "url": "https://mcp4.p113.invalid/mcp",
        "bearer_token_env_var": "P113_RESOLVE_BEARER",
        "oauth_client_id": "client",
        "oauth_client_secret_env_var": "P113_RESOLVE_OAUTH_SECRET",
    }))
    .unwrap();
    let block: McpServerConfig = serde_json::from_value(serde_json::json!({
        "url": "https://mcp5.p113.invalid/mcp",
        "oauth": {"clientId": "client", "clientSecretEnvVar": "P113_RESOLVE_OAUTH_BLOCK_SECRET"},
    }))
    .unwrap();
    for name in ["P113_RESOLVE_BEARER", "P113_RESOLVE_OAUTH_SECRET", "P113_RESOLVE_OAUTH_BLOCK_SECRET"] {
        assert!(!is_provider_credential(name), "precondition: {name} is not denied yet");
    }
    assert!(config.to_acp_mcp_server("a").is_some(), "control: the server converts");
    assert!(is_provider_credential("P113_RESOLVE_BEARER"));
    assert!(config.oauth_config().is_some(), "control: the OAuth config resolves");
    assert!(is_provider_credential("P113_RESOLVE_OAUTH_SECRET"));
    assert!(block.oauth_config().is_some(), "control: the [oauth] block resolves");
    assert!(is_provider_credential("P113_RESOLVE_OAUTH_BLOCK_SECRET"));
}

/// Astra r1 #4: a `.mcp.json` / `~/.claude.json` server still awaiting its setup choice is skipped by the loader
/// before it is built, so its token variable is registered when the JSON is parsed and again before the setup gate.
#[test]
fn p113_mcp_credential_variables_of_a_server_awaiting_setup_are_denied() {
    let pending = |bearer: &str| {
        serde_json::json!({
            "url": "https://mcp6.p113.invalid/mcp",
            "bearer_token_env_var": bearer,
            "setup": {"fields": [{"id": "site", "label": "Site", "type": "select", "options": [{"label": "A", "value": "a"}]}]},
        })
    };
    for name in ["P113_SETUP_JSON_BEARER", "P113_SETUP_LOADER_BEARER"] {
        assert!(!is_provider_credential(name), "precondition: {name} is not denied yet");
    }
    // A server name no preferences file holds a setup choice for (Astra r2 #7), so the server really awaits setup.
    const SERVER: &str = "p113-awaiting-setup-7c41e9";
    let parsed = mcp_config_from_json_value(&serde_json::json!({"mcpServers": serde_json::Map::from_iter([(SERVER.to_string(), pending("P113_SETUP_JSON_BEARER"))])}));
    assert_eq!(parsed.mcp_servers.len(), 1, "control: the entry parses");
    assert!(is_provider_credential("P113_SETUP_JSON_BEARER"), "a .mcp.json server awaiting setup leaves its token inheritable");

    let built: McpServerConfig = serde_json::from_value(pending("P113_SETUP_LOADER_BEARER")).unwrap();
    assert!(!load_mcp_preferences().file().servers.contains_key(SERVER), "precondition: no setup choice saved");
    let config = McpConfig { mcp_servers: IndexMap::from([(SERVER.to_string(), built)]) };
    let (servers, _) = parse_mcp_config_with_oauth(&config, "p113", &|s: &str| s.to_string());
    assert!(servers.is_empty(), "control: the server awaits setup and is not built");
    assert!(is_provider_credential("P113_SETUP_LOADER_BEARER"), "the loader skipped the server before registering its token");
}
