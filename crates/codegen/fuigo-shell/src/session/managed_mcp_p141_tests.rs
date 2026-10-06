//! P141 (Fable LOW 3 on P138): a forwarded copy that stays in the hot-reload seed (one the ingress renamed, or one that
//! shadows a same-named plugin server) follows the disk on every reload: an edit takes effect, a delete takes effect.
//! Through the production ingress (`admit_client_mcp_servers_for_seed`) and the reload merge. Red first.

use super::*;

fn names(servers: &[acp::McpServer]) -> Vec<String> {
    servers.iter().map(|s| mcp_server_name(s).to_owned()).collect()
}

fn find<'a>(servers: &'a [acp::McpServer], name: &str) -> Option<&'a acp::McpServer> {
    servers.iter().find(|s| mcp_server_name(s) == name)
}

fn url_of(servers: &[acp::McpServer], name: &str) -> Option<String> {
    find(servers, name).and_then(|s| match s {
        acp::McpServer::Http(h) => Some(h.url.clone()),
        _ => None,
    })
}

fn auth_of(servers: &[acp::McpServer], name: &str) -> Option<String> {
    find(servers, name).and_then(|s| match s {
        acp::McpServer::Http(h) => h.headers.iter().find(|x| x.name == "Authorization").map(|x| x.value.clone()),
        _ => None,
    })
}

fn command_of(servers: &[acp::McpServer], name: &str) -> Option<String> {
    find(servers, name).and_then(|s| match s {
        acp::McpServer::Stdio(s) => Some(s.command.display().to_string()),
        _ => None,
    })
}

fn dotted(url: &str) -> String {
    format!("[mcp_servers.\"com.p141\"]\nurl = \"{url}\"\nheaders = {{ Authorization = \"Bearer ${{FUIGO_API_KEY}}\" }}\n")
}

/// A RENAMED copy (`com.p141` arrives as `com-p141`) stays in the seed; an edit of it on disk is picked up by the next
/// reload, and a delete removes it (it does not keep running, scrubbed, until restart).
#[test]
fn a_kept_renamed_copy_follows_an_edit_and_a_delete() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let home = fuigo_test_support::FuigoHome::new();
    let config = home.path().join("config.toml");
    std::fs::write(&config, dotted("https://d.p141.invalid/mcp")).unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let forwarded = crate::util::config::load_mcp_servers(cwd.path(), &compat);
    let seed = admit_client_mcp_servers_for_seed(forwarded, cwd.path(), &compat, None).seed;

    let unchanged = merge_managed_mcp_servers(seed.clone(), cwd.path(), None, &compat);
    assert_eq!(auth_of(&unchanged, "com-p141").as_deref(), Some("Bearer ${FUIGO_API_KEY}"), "{:?}", names(&unchanged));

    std::fs::write(&config, dotted("https://edited.p141.invalid/mcp")).unwrap();
    let edited = merge_managed_mcp_servers(seed.clone(), cwd.path(), None, &compat);
    assert_eq!(url_of(&edited, "com-p141").as_deref(), Some("https://edited.p141.invalid/mcp"), "the edit was not picked up");
    assert_eq!(auth_of(&edited, "com-p141").as_deref(), Some("Bearer ${FUIGO_API_KEY}"), "the user's key reference was lost");

    std::fs::write(&config, "").unwrap();
    let deleted = merge_managed_mcp_servers(seed, cwd.path(), None, &compat);
    assert!(find(&deleted, "com-p141").is_none(), "a deleted renamed server lingers: {:?}", names(&deleted));
}

/// The user's `~/.cursor/mcp.json` `corp` shadows an active plugin's `corp` (Astra P138 r1 #2): the user's server keeps
/// winning on every reload while it is on disk, an edit of it is picked up, and once the user deletes it the plugin's
/// `corp` runs (the deleted copy does not keep running until restart).
#[test]
#[serial_test::serial]
fn a_kept_plugin_shadowing_copy_follows_an_edit_and_a_delete() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    use fuigo_test_support::env::EnvGuard;
    let fuigo_home = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let _fh = EnvGuard::set("FUIGO_HOME", fuigo_home.path());
    let _h = EnvGuard::set("HOME", home.path());
    let _key = EnvGuard::unset("FUIGO_API_KEY");
    let cursor = home.path().join(".cursor/mcp.json");
    std::fs::create_dir_all(cursor.parent().unwrap()).unwrap();
    let write_user = |command: &str| {
        std::fs::write(&cursor, format!(r#"{{"mcpServers":{{"corp":{{"command":"{command}"}}}}}}"#)).unwrap();
    };
    write_user("p141-user-corp");
    let plugins = tempfile::tempdir().unwrap();
    let plugin_root = plugins.path().join("corpplug");
    std::fs::create_dir_all(&plugin_root).unwrap();
    std::fs::write(
        plugin_root.join("plugin.json"),
        serde_json::json!({
            "name": "corpplug",
            "mcpServers": {"mcpServers": {"corp": {"command": "p141-plugin-corp"}}}
        })
        .to_string(),
    )
    .unwrap();
    let cfg = fuigo_agent::plugins::discovery::DiscoveryConfig {
        enabled: vec!["corpplug".to_string()],
        ..Default::default()
    };
    let cwd = tempfile::tempdir().unwrap();
    let registry = fuigo_agent::plugins::SharedPluginRegistryHandle::new(None, vec![])
        .build_for_cwd(cwd.path(), &cfg, std::slice::from_ref(&plugin_root), true);
    assert!(
        registry.as_deref().is_some_and(|r| r.active_plugins().iter().any(|p| p.name == "corpplug")),
        "fixture: the plugin is active"
    );
    let registry = registry.as_deref();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let forwarded = crate::util::config::load_mcp_servers(cwd.path(), &compat);
    assert_eq!(command_of(&forwarded, "corp").as_deref(), Some("p141-user-corp"), "fixture: the pager forwards the user's corp");
    let seed = admit_client_mcp_servers_for_seed(forwarded, cwd.path(), &compat, registry).seed;

    let unchanged = merge_managed_mcp_servers(seed.clone(), cwd.path(), registry, &compat);
    assert_eq!(command_of(&unchanged, "corp").as_deref(), Some("p141-user-corp"), "the plugin replaced the user's server");

    write_user("p141-user-corp-edited");
    let edited = merge_managed_mcp_servers(seed.clone(), cwd.path(), registry, &compat);
    assert_eq!(command_of(&edited, "corp").as_deref(), Some("p141-user-corp-edited"), "the edit was not picked up");

    std::fs::write(&cursor, r#"{"mcpServers":{}}"#).unwrap();
    let deleted = merge_managed_mcp_servers(seed, cwd.path(), registry, &compat);
    assert_eq!(
        command_of(&deleted, "corp").as_deref(),
        Some("p141-plugin-corp"),
        "the user deleted corp, yet the stale copy still shadows the plugin's"
    );
}

/// A kept copy is still subject to the vendor `mcps` kill switch on every merge (by URL, as a client server is): the
/// user turns Cursor's switch off while a Cursor entry shares the copy's URL, and the next reload drops the copy.
#[test]
fn a_kept_copy_is_still_subject_to_the_vendor_kill_switch() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::write(home.path().join("config.toml"), "[mcp_servers.\"com.p141k\"]\nurl = \"https://k.p141.invalid/mcp\"\n").unwrap();
    let cwd = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(cwd.path().join(".cursor")).unwrap();
    std::fs::write(
        cwd.path().join(".cursor/mcp.json"),
        r#"{"mcpServers":{"p141-cur":{"url":"https://k.p141.invalid/mcp"}}}"#,
    )
    .unwrap();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let forwarded = crate::util::config::load_mcp_servers(cwd.path(), &compat);
    let seed = admit_client_mcp_servers_for_seed(forwarded, cwd.path(), &compat, None).seed;
    assert!(seed.disk_copy_names().contains(&"com-p141k".to_owned()), "fixture: the renamed copy is in the seed");
    let on = merge_managed_mcp_servers(seed.clone(), cwd.path(), None, &compat);
    assert!(find(&on, "com-p141k").is_some(), "fixture: the copy runs while Cursor's switch is on");
    let mut off = compat;
    off.cursor.mcps = false;
    let merged = merge_managed_mcp_servers(seed, cwd.path(), None, &off);
    assert!(find(&merged, "com-p141k").is_none(), "a copy blocked by the kill switch was re-admitted: {:?}", names(&merged));
}

/// The kill switch judges what will RUN: the user edits a kept (renamed) copy's URL to one a disabled vendor's config
/// names, and the next reload drops it (the stored, pre-edit URL is not what is checked). Astra P141 r1.
#[test]
fn a_kept_copy_edited_onto_a_blocked_url_is_dropped() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let home = fuigo_test_support::FuigoHome::new();
    let config = home.path().join("config.toml");
    let server = |url: &str| format!("[mcp_servers.\"com.p141e\"]\nurl = \"{url}\"\n");
    std::fs::write(&config, server("https://e1.p141.invalid/mcp")).unwrap();
    let cwd = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(cwd.path().join(".cursor")).unwrap();
    std::fs::write(
        cwd.path().join(".cursor/mcp.json"),
        r#"{"mcpServers":{"p141-cur-e":{"url":"https://e2.p141.invalid/mcp"}}}"#,
    )
    .unwrap();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let forwarded = crate::util::config::load_mcp_servers(cwd.path(), &compat);
    let seed = admit_client_mcp_servers_for_seed(forwarded, cwd.path(), &compat, None).seed;
    let mut off = compat;
    off.cursor.mcps = false;
    let before = merge_managed_mcp_servers(seed.clone(), cwd.path(), None, &off);
    assert_eq!(url_of(&before, "com-p141e").as_deref(), Some("https://e1.p141.invalid/mcp"), "fixture: not blocked yet");
    std::fs::write(&config, server("https://e2.p141.invalid/mcp")).unwrap();
    let after = merge_managed_mcp_servers(seed, cwd.path(), None, &off);
    assert!(find(&after, "com-p141e").is_none(), "an edit onto a blocked URL bypassed the kill switch: {:?}", names(&after));
}

/// A trusted folder whose project `.mcp.json` defines `com.p141x` (an untrusted source); the user's config defines
/// `com-p141x` with the saved key. The client forwards only the project's server, which the ingress renames onto the
/// user's name: the user's definition still runs under it, at the first merge and at every reload (Astra P141 r1 HIGH).
#[test]
fn a_renamed_copy_never_replaces_a_trusted_definition_of_its_new_name() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::write(
        home.path().join("config.toml"),
        "[mcp_servers.com-p141x]\nurl = \"https://u.p141.invalid/mcp\"\nheaders = { Authorization = \"Bearer ${FUIGO_API_KEY}\" }\n",
    )
    .unwrap();
    let cwd = tempfile::tempdir().unwrap();
    git2::Repository::init(cwd.path()).unwrap();
    crate::agent::folder_trust::record_for_test(cwd.path(), true);
    std::fs::write(
        cwd.path().join(".mcp.json"),
        r#"{"mcpServers":{"com.p141x":{"type":"http","url":"https://p.p141.invalid/mcp"}}}"#,
    )
    .unwrap();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let forwarded: Vec<acp::McpServer> = crate::util::config::load_mcp_servers(cwd.path(), &compat)
        .into_iter()
        .filter(|s| mcp_server_name(s) == "com.p141x")
        .collect();
    assert_eq!(forwarded.len(), 1, "fixture: the project's server is on disk and forwarded");
    let AdmittedClientServers { seed, merged } = admit_client_mcp_servers_for_seed(forwarded, cwd.path(), &compat, None);
    assert_eq!(seed.disk_copy_names(), ["com-p141x"], "fixture: the renamed copy is marked");
    for (when, servers) in [("first merge", merged), ("reload", merge_managed_mcp_servers(seed, cwd.path(), None, &compat))] {
        assert_eq!(url_of(&servers, "com-p141x").as_deref(), Some("https://u.p141.invalid/mcp"), "{when}: the user's server was replaced");
        assert_eq!(auth_of(&servers, "com-p141x").as_deref(), Some("Bearer ${FUIGO_API_KEY}"), "{when}");
    }
}

/// Two client servers of one name, one a forwarded copy: the LAST one wins, as before P141 (copies are not merged
/// ahead of the client's own servers). Astra P141 r1.
#[test]
fn the_last_of_two_same_named_client_servers_wins() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let _home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    git2::Repository::init(cwd.path()).unwrap();
    crate::agent::folder_trust::record_for_test(cwd.path(), true);
    std::fs::write(
        cwd.path().join(".mcp.json"),
        r#"{"mcpServers":{"p141-dup":{"type":"http","url":"https://a.p141.invalid/mcp"}}}"#,
    )
    .unwrap();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let copy = crate::util::config::load_mcp_servers(cwd.path(), &compat)
        .into_iter()
        .find(|s| mcp_server_name(s) == "p141-dup")
        .expect("fixture: the project's server is on disk");
    let own = acp::McpServer::Http(acp::McpServerHttp::new("p141-dup", "https://b.p141.invalid/mcp").headers(vec![]));
    for (client, expected) in [
        (vec![own.clone(), copy.clone()], "https://a.p141.invalid/mcp"),
        (vec![copy, own], "https://b.p141.invalid/mcp"),
    ] {
        let AdmittedClientServers { seed, merged } = admit_client_mcp_servers_for_seed(client, cwd.path(), &compat, None);
        assert_eq!(url_of(&merged, "p141-dup").as_deref(), Some(expected), "first merge");
        let reloaded = merge_managed_mcp_servers(seed, cwd.path(), None, &compat);
        assert_eq!(url_of(&reloaded, "p141-dup").as_deref(), Some(expected), "reload");
    }
}

/// The kill switch judges the definition that is finally inserted: a renamed copy of a project server is replaced by
/// the user's trusted definition of that name, whose URL a disabled vendor's config names; that definition is not
/// inserted under the alias (Astra P141 r2).
#[test]
fn the_kill_switch_judges_the_substituted_user_definition() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::write(home.path().join("config.toml"), "[mcp_servers.\"com.p141b\"]\nurl = \"https://blocked.p141.invalid/mcp\"\n").unwrap();
    let cwd = tempfile::tempdir().unwrap();
    git2::Repository::init(cwd.path()).unwrap();
    crate::agent::folder_trust::record_for_test(cwd.path(), true);
    std::fs::write(
        cwd.path().join(".mcp.json"),
        r#"{"mcpServers":{"com/p141b":{"type":"http","url":"https://a.p141.invalid/mcp"}}}"#,
    )
    .unwrap();
    std::fs::create_dir_all(cwd.path().join(".cursor")).unwrap();
    std::fs::write(
        cwd.path().join(".cursor/mcp.json"),
        r#"{"mcpServers":{"p141-cur-b":{"url":"https://blocked.p141.invalid/mcp"}}}"#,
    )
    .unwrap();
    let mut off = fuigo_tools::types::compat::CompatConfig::default();
    off.cursor.mcps = false;
    let forwarded: Vec<acp::McpServer> = crate::util::config::load_mcp_servers(cwd.path(), &off)
        .into_iter()
        .filter(|s| mcp_server_name(s) == "com/p141b")
        .collect();
    assert_eq!(forwarded.len(), 1, "fixture: the project's server is on disk and forwarded");
    let AdmittedClientServers { seed, merged } = admit_client_mcp_servers_for_seed(forwarded, cwd.path(), &off, None);
    assert_eq!(seed.disk_copy_names(), ["com-p141b"], "fixture: the copy is renamed onto the user's name");
    for (when, servers) in [("first merge", merged), ("reload", merge_managed_mcp_servers(seed, cwd.path(), None, &off))] {
        assert_ne!(
            url_of(&servers, "com-p141b").as_deref(),
            Some("https://blocked.p141.invalid/mcp"),
            "{when}: a blocked URL was inserted under the alias"
        );
    }
}
