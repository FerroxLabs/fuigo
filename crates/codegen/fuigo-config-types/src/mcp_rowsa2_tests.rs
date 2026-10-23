//! ROWS-A2 (1.0.32) 53.11: a stdio MCP server's `~` is the user's home, as in a shell, because the server is started
//! without one.

use super::*;

#[test]
fn a_stdio_server_expands_a_leading_tilde_in_command_args_and_cwd() {
    let home = fuigo_config::mcp_bearer_file::home_dir().expect("a home directory for the test");
    let home = home.to_string_lossy().into_owned();
    let mut cfg: McpServerConfig = serde_json::from_value(serde_json::json!({
        "command": "~/bin/server", "args": ["~/data", "--root=~/not-expanded", "plain", "~user/x"], "cwd": "~/work",
        "env": { "K": "~/not-expanded-either" }
    }))
    .unwrap();
    cfg.expand_strings(&|s: &str| s.to_owned());
    let McpServerTransportConfig::Stdio { command, args, env, cwd } = &cfg.transport else { panic!("stdio") };
    assert_eq!(command, &format!("{home}/bin/server"));
    assert_eq!(cwd.as_deref(), Some(format!("{home}/work").as_str()));
    assert_eq!(args[0], format!("{home}/data"));
    assert_eq!(args[1], "--root=~/not-expanded", "only a word that starts with ~ is a home path");
    assert_eq!(args[2], "plain");
    assert_eq!(args[3], "~user/x", "another user's home is not guessed");
    assert_eq!(env.as_ref().unwrap()["K"], "~/not-expanded-either");
}

#[test]
fn a_bare_tilde_is_the_home_directory_and_a_url_is_untouched() {
    let home = fuigo_config::mcp_bearer_file::home_dir().expect("a home directory for the test");
    let mut cfg: McpServerConfig =
        serde_json::from_value(serde_json::json!({ "command": "srv", "cwd": "~" })).unwrap();
    cfg.expand_strings(&|s: &str| s.to_owned());
    let McpServerTransportConfig::Stdio { cwd, .. } = &cfg.transport else { panic!("stdio") };
    assert_eq!(cwd.as_deref(), Some(home.to_string_lossy().as_ref()));

    let mut http: McpServerConfig =
        serde_json::from_value(serde_json::json!({ "url": "https://x.invalid/~me/mcp" })).unwrap();
    http.expand_strings(&|s: &str| s.to_owned());
    let McpServerTransportConfig::StreamableHttp { url, .. } = &http.transport else { panic!("http") };
    assert_eq!(url, "https://x.invalid/~me/mcp");
}
