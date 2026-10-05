//! P118 (backlog row P103): a project's `.mcp.json` may not name the saved API key `FUIGO_API_KEY`. Red first.

use super::*;

const MCP_JSON: &str = r#"{
  "mcpServers": {
    "p118-stdio": {
      "command": "x",
      "args": ["--key=${FUIGO_API_KEY}", "--plain"],
      "env": { "TOKEN": "${FUIGO_API_KEY}", "KEPT": "$${FUIGO_API_KEY}", "OTHER": "ok" }
    },
    "p118-http": {
      "url": "https://m.p118.invalid/mcp",
      "headers": { "Authorization": "Bearer ${FUIGO_API_KEY}" },
      "bearer_token_env_var": "FUIGO_API_KEY"
    }
  }
}"#;

#[test]
fn a_project_mcp_json_cannot_name_the_saved_key() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".mcp.json");
    std::fs::write(&path, MCP_JSON).unwrap();
    let config = read_mcp_json(&path).expect("parses");
    match &config.mcp_servers["p118-stdio"].transport {
        McpServerTransportConfig::Stdio { args, env, .. } => {
            assert_eq!(args, &["--key=".to_owned(), "--plain".to_owned()]);
            let env = env.as_ref().unwrap();
            assert_eq!(env["TOKEN"], "");
            assert_eq!(env["KEPT"], "$${FUIGO_API_KEY}", "an escaped reference is text and stays");
            assert_eq!(env["OTHER"], "ok");
        }
        other => panic!("not stdio: {other:?}"),
    }
    match &config.mcp_servers["p118-http"].transport {
        McpServerTransportConfig::StreamableHttp { headers, bearer_token_env_var, .. } => {
            assert_eq!(headers.as_ref().unwrap()["Authorization"], "Bearer ");
            assert_eq!(bearer_token_env_var, &None, "a bearer name pointing at the saved key is removed");
        }
        other => panic!("not http: {other:?}"),
    }
    let notes = fuigo_config::key_naming::refusal_notes();
    assert!(
        notes.iter().any(|n| n.contains(&path.display().to_string()) && n.contains("mcpServers.p118-stdio.env.TOKEN")),
        "no note naming the file and the key: {notes:?}"
    );
    // The materialized server, as the session would spawn it, holds no reference either.
    let servers = load_mcp_json_file(&path);
    let stdio = servers
        .iter()
        .find_map(|s| match s {
            acp::McpServer::Stdio(s) if s.name == "p118-stdio" => Some(s),
            _ => None,
        })
        .expect("stdio server");
    assert!(stdio.env.iter().all(|e| e.name != "TOKEN" || e.value.is_empty()));
    assert!(stdio.args.iter().all(|a| !a.contains("FUIGO_API_KEY") || a.starts_with("$$")));
}

/// The control: the user's own `~/.claude.json` / `~/.cursor/mcp.json` are user-level and keep working.
#[test]
fn a_user_level_mcp_json_may_still_name_the_saved_key() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let home = fuigo_dirs::home_dir().expect("home dir");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".mcp.json");
    std::fs::write(&path, MCP_JSON).unwrap();
    // A project file in a private dir is refused (above); a trusted path is judged by the shared rule.
    assert!(!fuigo_config::key_naming::source_may_name_saved_key(&path));
    assert!(fuigo_config::key_naming::source_may_name_saved_key(&home.join(".claude.json")));
    assert!(fuigo_config::key_naming::source_may_name_saved_key(&home.join(".cursor").join("mcp.json")));
    assert!(fuigo_config::key_naming::source_may_name_saved_key(&fuigo_config::fuigo_home().join("config.toml")));
    assert!(!fuigo_config::key_naming::source_may_name_saved_key(&fuigo_config::fuigo_home().join("plugins").join("a").join(".mcp.json")));
}

fn project_config(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    let project = dir.join(".fuigo");
    std::fs::create_dir_all(&project).unwrap();
    let path = project.join("config.toml");
    std::fs::write(&path, body).unwrap();
    path
}

fn materialize_loaded(root: &TomlValue, name: &str) -> acp::McpServer {
    let configs = parse_mcp_servers_from_toml(root);
    let config = configs.get(name).unwrap_or_else(|| panic!("no server {name}: {root:?}")).clone();
    materialize_mcp_config(
        name,
        config,
        &load_mcp_preferences().file(),
        &crate::config::expand_env_vars_in_string,
        McpEnabledFilter::Respect,
    )
    .unwrap_or_else(|| panic!("server {name} does not materialize"))
}

fn stdio_env(server: &acp::McpServer, var: &str) -> Option<String> {
    match server {
        acp::McpServer::Stdio(s) => s.env.iter().find(|e| e.name == var).map(|e| e.value.clone()),
        other => panic!("not stdio: {other:?}"),
    }
}

/// Astra r3 N2: a server a project config introduces through `[[version_overrides]]`, with a value that expansion turns
/// into a key reference only AFTER load, never reaches the spawn holding the reference.
#[test]
fn a_version_override_server_cannot_rebuild_a_key_reference_after_load() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let dir = tempfile::tempdir().unwrap();
    let path = project_config(
        dir.path(),
        "[[version_overrides]]\nminimum_version = \"0.0.0\"\n[version_overrides.mcp_servers.p118_late]\ncommand = \"./mcp-child\"\nenv = { TOKEN = \"$${P118_UNSET_LATE:-$}{FUIGO_API_KEY}\", PLAIN = \"ok\" }\n",
    );
    let root = fuigo_config::load_config_file(&path).unwrap();
    let server = materialize_loaded(&root, "p118_late");
    let token = stdio_env(&server, "TOKEN").unwrap_or_default();
    assert!(!token.contains("FUIGO_API_KEY"), "the spawn would bind the saved key into TOKEN: {token:?}");
    assert_eq!(stdio_env(&server, "PLAIN").as_deref(), Some("ok"));
}

/// Astra r3 N1: a project `.mcp.json` server NAMED `env` cannot select the saved key as its bearer token.
#[test]
fn a_project_server_named_env_cannot_select_the_saved_key_as_its_bearer() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    fn resolver(name: &str) -> Option<String> {
        (name == fuigo_config::FIRST_PARTY_KEY_ENV_VAR).then(|| "p118-n1-FAKE-saved-key".to_owned())
    }
    fuigo_config::install_credential_env_resolver(resolver);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".mcp.json");
    std::fs::write(
        &path,
        r#"{"mcpServers":{"env":{"url":"https://e.p118.invalid/mcp","bearer_token_env_var":"FUIGO_API_KEY"}}}"#,
    )
    .unwrap();
    let servers = load_mcp_json_file(&path);
    assert_eq!(servers.len(), 1);
    let acp::McpServer::Http(h) = &servers[0] else { panic!("http") };
    assert!(h.headers.iter().all(|x| x.name != "Authorization"), "{:?}", h.headers);
}

/// Astra r3 N4: a project definition does not poison the same name at user level, before or after it is removed. The
/// mark belongs to the definition.
#[test]
fn a_project_definition_does_not_poison_a_user_level_server_of_the_same_name() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let dir = tempfile::tempdir().unwrap();
    let body = "[mcp_servers.acme]\ncommand = \"x\"\nenv = { TOKEN = \"${FUIGO_API_KEY}\" }\n";
    let project = project_config(dir.path(), body);
    let loaded = fuigo_config::load_config_file(&project).unwrap();
    let from_project = materialize_loaded(&loaded, "acme");
    assert!(!stdio_env(&from_project, "TOKEN").unwrap_or_default().contains("FUIGO_API_KEY"));
    // The same name at user level, loaded afterwards in the same process, still names the key.
    let user = home.path().join("config.toml");
    std::fs::write(&user, body).unwrap();
    let loaded = fuigo_config::load_config_file(&user).unwrap();
    let from_user = materialize_loaded(&loaded, "acme");
    assert_eq!(stdio_env(&from_user, "TOKEN").as_deref(), Some("${FUIGO_API_KEY}"), "late-bound at spawn");
}

/// Astra r3 N5: refusal adds no expansion pass; `$$` keeps its v1.0.20 meaning for text unrelated to the key.
#[test]
fn escaped_dollars_in_a_project_mcp_json_keep_their_v1_0_20_meaning() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    // SAFETY: own process (rerun_in_own_process); removed below.
    unsafe { std::env::set_var("P118_N5_VAR", "expanded-value") };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".mcp.json");
    std::fs::write(
        &path,
        r#"{"mcpServers":{"s":{"command":"x","env":{"LITERAL":"$$P118_N5_VAR","PLAIN":"$P118_N5_VAR"}}}}"#,
    )
    .unwrap();
    let servers = load_mcp_json_file(&path);
    unsafe { std::env::remove_var("P118_N5_VAR") };
    assert_eq!(stdio_env(&servers[0], "LITERAL").as_deref(), Some("$P118_N5_VAR"));
    assert_eq!(stdio_env(&servers[0], "PLAIN").as_deref(), Some("expanded-value"));
}

/// Legitimate user-level config keeps working: a `~/.fuigo` that is a symlink, a reference to the saved key, and `$$`
/// escapes behave as in v1.0.20; and no worktree under it inherits that.
#[cfg(unix)]
#[test]
fn a_symlinked_user_home_config_may_name_the_key_and_keeps_dollar_escapes() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("dotfiles-fuigo");
    std::fs::create_dir_all(real.join("worktrees/w/.fuigo")).unwrap();
    let link = tmp.path().join(".fuigo");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let _env = fuigo_test_support::env::EnvGuard::set("FUIGO_HOME", &link);
    std::fs::write(
        link.join("config.toml"),
        "[mcp_servers.u]\ncommand = \"x\"\nenv = { TOKEN = \"${FUIGO_API_KEY}\", ESC = \"$$P118_NOT_A_VAR\" }\n",
    )
    .unwrap();
    let body = "[mcp_servers.w]\ncommand = \"x\"\nenv = { TOKEN = \"${FUIGO_API_KEY}\" }\n";
    std::fs::write(link.join("worktrees/w/.fuigo/config.toml"), body).unwrap();
    let user = fuigo_config::load_config_file(&link.join("config.toml")).unwrap();
    let env = &user["mcp_servers"]["u"]["env"];
    assert_eq!(env["TOKEN"].as_str(), Some("${FUIGO_API_KEY}"));
    assert_eq!(env["ESC"].as_str(), Some("$P118_NOT_A_VAR"));
    assert!(user["mcp_servers"]["u"].get(fuigo_config::key_naming::UNTRUSTED_SOURCE_MARKER).is_none());
    // A project worktree under the same home is an ordinary project.
    let wt = fuigo_config::load_config_file(&link.join("worktrees/w/.fuigo/config.toml")).unwrap();
    assert_eq!(wt["mcp_servers"]["w"]["env"]["TOKEN"].as_str(), Some(""));
}
