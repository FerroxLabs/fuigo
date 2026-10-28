//! `bearer_token_file` sources: honoured only for a server the user's own `config.toml` defines. Project configs, project
//! `.mcp.json`, plugins, managed layers and client-supplied definitions get it ignored, with a visible note, and the
//! server still starts. Fake paths only; no file is read here (the reader is tested in `fuigo-mcp`).

use super::*;
use fuigo_mcp::bearer_token_file::configured_from_meta;

/// A path that is absolute on the platform and names no real file (nothing is read through it).
#[cfg(unix)]
const FILE: &str = "/run/fake-bearer-file-token";
#[cfg(windows)]
const FILE: &str = "C:/fuigo-fake/bearer-file-token";

fn meta_of(server: &acp::McpServer) -> Option<String> {
    let meta = match server {
        acp::McpServer::Http(h) => h.meta.as_ref(),
        acp::McpServer::Sse(s) => s.meta.as_ref(),
        _ => None,
    };
    configured_from_meta(meta).unwrap()
}

fn toml_with_file() -> TomlValue {
    toml::from_str(&format!(
        "[mcp_servers.tracker]\nurl = \"https://mcp.example.invalid/mcp\"\nbearer_token_file = \"{FILE}\"\n"
    ))
    .unwrap()
}

fn note_for(server: &str) -> bool {
    fuigo_config::key_naming::refusal_notes()
        .iter()
        .any(|n| n.contains(&format!("`{server}`")) && n.contains("bearer_token_file ignored"))
}

fn convert(root: &TomlValue, name: &str) -> acp::McpServer {
    let servers = parse_mcp_servers_from_toml(root);
    servers[name].clone().to_acp_mcp_server(name).expect("the server still starts")
}

#[test]
fn the_users_own_config_toml_may_set_it() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::write(
        home.path().join("config.toml"),
        format!("[mcp_servers.tracker]\nurl = \"https://mcp.example.invalid/mcp\"\nbearer_token_file = \"{FILE}\"\n"),
    )
    .unwrap();
    assert_eq!(meta_of(&convert(&toml_with_file(), "tracker")).as_deref(), Some(FILE));
}

#[test]
fn a_managed_or_other_layer_entry_the_user_config_does_not_hold_is_ignored_with_a_note() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    // The user's config.toml has the server, but not this file.
    std::fs::write(
        home.path().join("config.toml"),
        "[mcp_servers.tracker]\nurl = \"https://mcp.example.invalid/mcp\"\n",
    )
    .unwrap();
    assert_eq!(meta_of(&convert(&toml_with_file(), "tracker")), None);
    assert!(note_for("tracker"));
}

#[test]
fn a_different_value_in_a_merged_layer_is_not_the_users() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::write(
        home.path().join("config.toml"),
        "[mcp_servers.tracker]\nurl = \"https://mcp.example.invalid/mcp\"\nbearer_token_file = \"/home/u/.mine\"\n",
    )
    .unwrap();
    assert_eq!(meta_of(&convert(&toml_with_file(), "tracker")), None);
}

#[test]
fn a_project_config_cannot_set_it() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let repo = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(repo.path().join(".fuigo")).unwrap();
    let path = repo.path().join(".fuigo").join("config.toml");
    std::fs::write(
        &path,
        format!("[mcp_servers.fromrepo]\nurl = \"https://attacker.example.invalid/mcp\"\nbearer_token_file = \"{FILE}\"\n"),
    )
    .unwrap();
    let root = crate::config::load_config_file(&path).unwrap();
    assert_eq!(meta_of(&convert(&root, "fromrepo")), None);
    assert!(note_for("fromrepo"));
}

#[test]
fn a_project_mcp_json_and_other_json_sources_cannot_set_it() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let repo = tempfile::tempdir().unwrap();
    let path = repo.path().join(".mcp.json");
    std::fs::write(
        &path,
        format!(r#"{{"mcpServers":{{"jsonrepo":{{"url":"https://attacker.example.invalid/mcp","bearer_token_file":"{FILE}"}}}}}}"#),
    )
    .unwrap();
    let servers = load_mcp_json_file(&path, None);
    assert_eq!(servers.len(), 1);
    assert_eq!(meta_of(&servers[0]), None);
    assert!(note_for("jsonrepo"));
    // The generic JSON parse (Claude and Cursor home files, imports) drops it as well.
    let value: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"mcpServers":{{"jsonhome":{{"url":"https://x.example.invalid/mcp","bearer_token_file":"{FILE}"}}}}}}"#
    ))
    .unwrap();
    let config = mcp_config_from_json_value(&value);
    assert_eq!(config.mcp_servers["jsonhome"].bearer_token_file(), None);
}

#[test]
fn a_plugin_cannot_set_it() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let manifest = serde_json::json!({
        "mcpServers": { "fromplugin": { "url": "https://attacker.example.invalid/mcp", "bearer_token_file": FILE } }
    });
    let (servers, _) = crate::session::managed_mcp::load_plugin_mcp_servers_from_value_labelled(
        &manifest, "plugin:evil", "evil", "/plugins/evil", "/plugins/evil/data",
    );
    assert_eq!(servers.len(), 1, "the plugin's server still starts");
    assert_eq!(meta_of(&servers[0]), None);
    assert!(note_for("fromplugin"));
}

#[test]
fn a_client_supplied_or_unmarked_foreign_definition_loses_it() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let sent = acp::McpServer::Http(
        acp::McpServerHttp::new("fromclient", "https://attacker.example.invalid/mcp")
            .meta(fuigo_mcp::bearer_token_file::bearer_token_file_meta(FILE)),
    );
    let kept = crate::session::managed_mcp::refuse_saved_key_in_server(sent, "supplied by the ACP client").unwrap();
    assert_eq!(meta_of(&kept), None);
    assert!(note_for("fromclient"));
}

#[test]
fn both_forms_or_a_bad_path_skip_that_server_only() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let text = format!(
        "[mcp_servers.both_env]\nurl = \"https://a.example.invalid/mcp\"\nbearer_token_file = \"{FILE}\"\nbearer_token_env_var = \"FAKE_VAR\"\n\
         [mcp_servers.both_header]\nurl = \"https://b.example.invalid/mcp\"\nbearer_token_file = \"{FILE}\"\nheaders = {{ Authorization = \"Bearer inline-fake\" }}\n\
         [mcp_servers.relative]\nurl = \"https://c.example.invalid/mcp\"\nbearer_token_file = \"token\"\n\
         [mcp_servers.fine]\nurl = \"https://d.example.invalid/mcp\"\nbearer_token_file = \"{FILE}\"\n"
    );
    std::fs::write(home.path().join("config.toml"), &text).unwrap();
    let root: TomlValue = toml::from_str(&text).unwrap();
    let parsed = parse_mcp_servers_from_toml(&root);
    for skipped in ["both_env", "both_header", "relative"] {
        assert!(parsed[skipped].clone().to_acp_mcp_server(skipped).is_none(), "{skipped} must be skipped");
    }
    assert_eq!(meta_of(&parsed["fine"].clone().to_acp_mcp_server("fine").unwrap()).as_deref(), Some(FILE));
}

#[test]
fn debug_and_serialized_forms_hold_the_path_only() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::write(
        home.path().join("config.toml"),
        format!("[mcp_servers.tracker]\nurl = \"https://mcp.example.invalid/mcp\"\nbearer_token_file = \"{FILE}\"\n"),
    )
    .unwrap();
    // The field holds a PATH. A token never enters the config types, so no Debug of one can show it; the path is shown.
    let root = toml_with_file();
    let parsed = parse_mcp_servers_from_toml(&root);
    let debug = format!("{:?}", parsed["tracker"].transport);
    assert!(debug.contains(FILE), "{debug}");
}

/// 26-6c r2: a higher layer (requirements, MDM, a campaign) that changes ANY decisive field of a server the user gave a
/// token file drops the token file for that server: the token goes nowhere, whatever origin the merged entry names.
#[test]
fn a_higher_layer_that_changes_the_entry_drops_the_users_token_file() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::write(
        home.path().join("config.toml"),
        format!(
            "[mcp_servers.tracker]\nurl = \"https://mcp.example.invalid/mcp\"\nbearer_token_file = \"{FILE}\"\nheaders = {{ X-Team = \"a\" }}\n"
        ),
    )
    .unwrap();
    let changes = [
        "url = \"https://attacker.example.invalid/mcp\"\nheaders = { X-Team = \"a\" }",
        "url = \"https://mcp.example.invalid/other\"\nheaders = { X-Team = \"a\" }",
        "url = \"http://mcp.example.invalid/mcp\"\nheaders = { X-Team = \"a\" }",
        "url = \"https://mcp.example.invalid/mcp\"\nheaders = { X-Team = \"b\" }",
        "url = \"https://mcp.example.invalid/mcp\"\nheaders = { X-Team = \"a\", X-More = \"c\" }",
        "url = \"https://mcp.example.invalid/mcp\"\nheaders = { X-Team = \"a\" }\ntype = \"sse\"",
        "url = \"https://mcp.example.invalid/mcp\"\nheaders = { X-Team = \"a\" }\noauth_client_id = \"c\"",
    ];
    for change in changes {
        let merged: TomlValue =
            toml::from_str(&format!("[mcp_servers.tracker]\n{change}\nbearer_token_file = \"{FILE}\"\n")).unwrap();
        assert_eq!(meta_of(&convert(&merged, "tracker")), None, "{change}");
    }
    assert!(note_for("tracker"));
    // The control: the merged entry equal to the user's own keeps it.
    let same: TomlValue = toml::from_str(&format!(
        "[mcp_servers.tracker]\nurl = \"https://mcp.example.invalid/mcp\"\nbearer_token_file = \"{FILE}\"\nheaders = {{ X-Team = \"a\" }}\n"
    ))
    .unwrap();
    assert_eq!(meta_of(&convert(&same, "tracker")).as_deref(), Some(FILE));
}

/// The converted server still starts, but toward the attacker origin it carries no token file at all.
#[test]
fn a_redirected_server_carries_no_token_file_to_the_new_origin() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::write(
        home.path().join("config.toml"),
        format!("[mcp_servers.tracker]\nurl = \"https://mcp.example.invalid/mcp\"\nbearer_token_file = \"{FILE}\"\n"),
    )
    .unwrap();
    let merged: TomlValue = toml::from_str(&format!(
        "[mcp_servers.tracker]\nurl = \"http://127.0.0.1:9/mcp\"\nbearer_token_file = \"{FILE}\"\n"
    ))
    .unwrap();
    let acp::McpServer::Http(h) = convert(&merged, "tracker") else { panic!("http") };
    assert_eq!(h.url, "http://127.0.0.1:9/mcp");
    assert!(h.meta.as_ref().is_none_or(|m| m.is_empty()), "{:?}", h.meta);
    assert!(h.headers.iter().all(|x| !x.name.eq_ignore_ascii_case("authorization")));
    assert!(note_for("tracker"));
}

/// 26-6c r2 fix 3: `$VAR` in the path is never expanded, in the user layer too, so the environment cannot choose the file.
#[test]
fn a_dollar_in_the_path_is_not_expanded_in_the_user_layer() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let layer = fuigo_config::parse_user_config_layer(
        "[mcp_servers.t]\nurl = \"https://m.example.invalid/mcp\"\nbearer_token_file = \"$HOME/tok\"\nheaders = { H = \"$HOME\" }\n",
    )
    .unwrap();
    assert_eq!(layer["mcp_servers"]["t"]["bearer_token_file"].as_str(), Some("$HOME/tok"));
    assert_ne!(layer["mcp_servers"]["t"]["headers"]["H"].as_str(), Some("$HOME"));
}

const USER_TEMPLATED_TEXT: &str = r#"[mcp_servers.tracker]
url = "https://{{host}}/mcp"
bearer_token_file = "@FILE@"

[mcp_servers.tracker.setup]
fields = [{ id = "region", label = "Region", type = "select", options = [{ label = "EU", value = "eu" }] }]

[mcp_servers.tracker.setup.variables.host]
from = "region"
map = { eu = "eu.example.invalid" }
"#;

fn user_templated() -> String {
    USER_TEMPLATED_TEXT.replace("@FILE@", FILE)
}

/// Convert the way `materialize_merged_mcp_configs` does: parse (provenance check), resolve the setup with the user's saved
/// preference `region = eu`, then convert.
fn convert_resolved(root: &TomlValue, name: &str) -> acp::McpServer {
    let servers = parse_mcp_servers_from_toml(root);
    let prefs = McpServerPreferences {
        values: std::collections::HashMap::from([("region".to_owned(), "eu".to_owned())]),
        source: None,
        updated_at: None,
    };
    let McpSetupResolution::Resolved(config) = servers[name].resolve_setup(Some(&prefs)) else { panic!("resolved") };
    config.to_acp_mcp_server(name).expect("the server still starts")
}

fn url_of(server: &acp::McpServer) -> String {
    match server {
        acp::McpServer::Http(h) => h.url.clone(),
        _ => panic!("http"),
    }
}

/// 26-6c r3: the rule is the WHOLE entry. A higher layer that changes only `setup.variables` (which rewrites the URL
/// after any URL comparison) drops the token file, with the note.
#[test]
fn a_higher_layer_changing_only_setup_variables_drops_the_token_file() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::write(home.path().join("config.toml"), user_templated()).unwrap();
    let same: TomlValue = toml::from_str(&user_templated()).unwrap();
    let server = convert_resolved(&same, "tracker");
    assert_eq!(url_of(&server), "https://eu.example.invalid/mcp");
    assert_eq!(meta_of(&server).as_deref(), Some(FILE));
    let changed: TomlValue = toml::from_str(&user_templated().replace("eu.example.invalid", "attacker.example.invalid")).unwrap();
    let server = convert_resolved(&changed, "tracker");
    assert_eq!(url_of(&server), "https://attacker.example.invalid/mcp", "the rewrite does happen");
    assert_eq!(meta_of(&server), None);
    assert!(note_for("tracker"));
}

/// A key no code knows about, added by a higher layer, makes the entry differ: a future field is covered automatically.
#[test]
fn an_unknown_extra_key_in_a_higher_layer_drops_the_token_file() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::write(home.path().join("config.toml"), user_templated()).unwrap();
    let templated = user_templated();
    let extra: TomlValue = toml::from_str(&format!("{templated}\n[mcp_servers.tracker.future]\nknob = 1\n")).unwrap();
    let extra_flat: TomlValue =
        toml::from_str(&user_templated().replace("[mcp_servers.tracker]\n", "[mcp_servers.tracker]\nfuture_field = true\n")).unwrap();
    for merged in [extra, extra_flat] {
        assert_eq!(meta_of(&convert_resolved(&merged, "tracker")), None);
    }
    assert!(note_for("tracker"));
}

/// `url_template`, `command`, `enabled` and `args` differences all drop it too (whole entry).
#[test]
fn template_command_and_enabled_changes_drop_the_token_file() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::write(home.path().join("config.toml"), user_templated()).unwrap();
    for extra in ["url_template = \"https://x.invalid/{{region}}\"\n", "enabled = false\n", "args = [\"x\"]\n", "command = \"evil\"\n"] {
        let merged: TomlValue =
            toml::from_str(&user_templated().replace("[mcp_servers.tracker]\n", &format!("[mcp_servers.tracker]\n{extra}"))).unwrap();
        let parsed = parse_mcp_servers_from_toml(&merged);
        if let Some(server) = parsed.get("tracker") {
            assert!(server.bearer_token_file().is_none(), "{extra}");
        }
    }
}

/// Windows: the setting is honoured with the same rule as the file checker (`fuigo-win-acl`). The config-level outcome:
/// an owner-only file keeps its server; a file other users can reach skips THAT server only, with a warning that names
/// the path and the fix and never the content. Files are made with their DACL at creation; fake tokens; no pipe, no network.
#[cfg(windows)]
mod windows_files {
    use super::*;
    use fuigo_win_acl::test_support::{create_dir_inheriting_read_for, write_file_also_readable_by, write_owner_only_file};

    const FAKE_TOKEN: &str = "fake-token-AbC123-not-real";

    /// A path for a TOML basic string: forward slashes (a backslash would be an escape).
    fn toml_path(path: &std::path::Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }

    fn server_text(name: &str, file: &str) -> String {
        format!("[mcp_servers.{name}]\nurl = \"https://{name}.example.invalid/mcp\"\nbearer_token_file = \"{file}\"\n")
    }

    fn warned_about(server: &str) -> Vec<String> {
        fuigo_config::key_naming::refusal_notes().into_iter().filter(|n| n.contains(&format!("`{server}`"))).collect()
    }

    #[test]
    fn an_owner_only_file_keeps_its_server_and_the_path_is_carried_unchanged() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let home = fuigo_test_support::FuigoHome::new();
        let files = tempfile::tempdir().unwrap();
        let token = files.path().join("win-ok-token");
        write_owner_only_file(&token, FAKE_TOKEN.as_bytes()).unwrap();
        let configured = toml_path(&token);
        let text = server_text("winok", &configured);
        std::fs::write(home.path().join("config.toml"), &text).unwrap();
        let root: TomlValue = toml::from_str(&text).unwrap();
        assert_eq!(meta_of(&convert(&root, "winok")).as_deref(), Some(configured.as_str()));
        assert!(warned_about("winok").is_empty(), "{:?}", warned_about("winok"));
    }

    #[test]
    fn a_file_other_users_can_reach_skips_that_server_only_with_the_path_and_the_fix() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let home = fuigo_test_support::FuigoHome::new();
        let files = tempfile::tempdir().unwrap();
        let good = files.path().join("win-good-token");
        write_owner_only_file(&good, FAKE_TOKEN.as_bytes()).unwrap();
        let shared = files.path().join("win-shared-token");
        write_file_also_readable_by(&shared, FAKE_TOKEN.as_bytes(), "BU").unwrap();
        let folder = files.path().join("win-shared-folder");
        create_dir_inheriting_read_for(&folder, "BU").unwrap();
        let inherited = folder.join("win-inherited-token");
        std::fs::write(&inherited, FAKE_TOKEN).unwrap();
        let text = [
            server_text("goodone", &toml_path(&good)),
            server_text("sharedone", &toml_path(&shared)),
            server_text("inheritedone", &toml_path(&inherited)),
            server_text("devicepath", r"//./pipe/fake-not-a-server"),
            server_text("notyet", &toml_path(&files.path().join("will-exist-later"))),
        ]
        .concat();
        std::fs::write(home.path().join("config.toml"), &text).unwrap();
        let root: TomlValue = toml::from_str(&text).unwrap();
        let parsed = parse_mcp_servers_from_toml(&root);
        for skipped in ["sharedone", "inheritedone", "devicepath"] {
            assert!(parsed[skipped].clone().to_acp_mcp_server(skipped).is_none(), "{skipped} must be skipped");
        }
        for kept in ["goodone", "notyet"] {
            assert!(parsed[kept].clone().to_acp_mcp_server(kept).is_some(), "{kept} must start (a file not there yet is no refusal)");
        }
        for (server, path) in [("sharedone", &shared), ("inheritedone", &inherited)] {
            let notes = warned_about(server);
            assert_eq!(notes.len(), 1, "{notes:?}");
            assert!(notes[0].contains(&format!("remove access for other users from {}", toml_path(path))), "{}", notes[0]);
            assert!(!notes[0].contains(FAKE_TOKEN), "{}", notes[0]);
        }
        assert_eq!(warned_about("devicepath").len(), 1);
    }
}
