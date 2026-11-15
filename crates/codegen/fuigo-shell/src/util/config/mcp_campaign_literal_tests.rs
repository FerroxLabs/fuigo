//! A campaign-added MCP server's `url`, `args`, `command` and `cwd` are literals at use: `${PATH}` (set in every test
//! environment) is not expanded, while the user's own server expands exactly as before.

use super::*;

fn effective_with_campaign() -> TomlValue {
    let mut user: TomlValue = toml::from_str(
        "[mcp_servers.own]\ncommand = \"own-srv\"\nargs = [\"--p=${PATH}\"]\n",
    )
    .unwrap();
    fuigo_config::expand_env_vars_in_toml(&mut user);
    let patch: toml::Table = toml::from_str(
        "[mcp_servers.fresh]\ncommand = \"${PATH}/srv\"\nargs = [\"--k=${PATH}\"]\n\
         [mcp_servers.web]\nurl = \"https://h.invalid/mcp?k=${PATH}\"\n\
         [mcp_servers.tilde]\ncommand = \"~/bin/srv\"\nargs = [\"~/data\"]\n",
    )
    .unwrap();
    let entries = vec![fuigo_config::campaigns::CampaignEntry { id: "c".into(), patch }];
    fuigo_config::campaigns::apply_active_campaign_patches(&mut user, &entries);
    user
}

fn materialize(root: &TomlValue, name: &str) -> acp::McpServer {
    let config = parse_mcp_servers_from_toml(root).get(name).unwrap_or_else(|| panic!("no server {name}")).clone();
    materialize_mcp_config(
        name,
        config,
        &load_mcp_preferences().file(),
        &crate::config::expand_env_vars_in_string,
        McpEnabledFilter::Respect,
    )
    .unwrap_or_else(|| panic!("server {name} does not materialize"))
}

#[test]
fn campaign_added_server_strings_are_not_environment_expanded_at_use() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let root = effective_with_campaign();
    match materialize(&root, "fresh") {
        acp::McpServer::Stdio(s) => {
            assert_eq!(s.args, vec!["--k=${PATH}".to_owned()]);
            assert_eq!(s.command, std::path::PathBuf::from("${PATH}/srv"));
        }
        other => panic!("not stdio: {other:?}"),
    }
    match materialize(&root, "web") {
        acp::McpServer::Http(h) => assert_eq!(h.url, "https://h.invalid/mcp?k=${PATH}"),
        other => panic!("not http: {other:?}"),
    }
    // A leading `~` is the user's home, no secret: it still expands for a campaign's stdio server.
    match materialize(&root, "tilde") {
        acp::McpServer::Stdio(s) => {
            assert!(!s.command.to_string_lossy().starts_with('~') && s.command.ends_with("bin/srv"), "{:?}", s.command);
            assert!(!s.args[0].starts_with('~') && s.args[0].ends_with("data"), "{:?}", s.args);
        }
        other => panic!("not stdio: {other:?}"),
    }
    match materialize(&root, "own") {
        acp::McpServer::Stdio(s) => assert!(!s.args[0].contains("${PATH}"), "the user's own server expands: {:?}", s.args),
        other => panic!("not stdio: {other:?}"),
    }
}
