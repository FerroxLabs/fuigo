//! P138 (Fable findings on P133/P136): the trust-grant reload tells its session, a forwarded copy of a disk definition in
//! the hot-reload seed does not outlive a delete (P141: it is kept, marked, and resolved against the disk at every
//! merge), a pager without a credential resolver is not "different", the ACP scrub removes the key's value too.

use super::*;

const KEY: &str = "p138-FAKE-saved-key";

fn resolver(name: &str) -> Option<String> {
    (name == fuigo_config::FIRST_PARTY_KEY_ENV_VAR).then(|| KEY.to_owned())
}

fn header(s: &acp::McpServer, name: &str) -> Option<String> {
    match s {
        acp::McpServer::Http(h) => h.headers.iter().find(|x| x.name == name).map(|x| x.value.clone()),
        acp::McpServer::Sse(h) => h.headers.iter().find(|x| x.name == name).map(|x| x.value.clone()),
        _ => None,
    }
}

fn names(servers: &[acp::McpServer]) -> Vec<String> {
    servers.iter().map(|s| mcp_server_name(s).to_owned()).collect()
}

const USER_TOML: &str = r#"
[mcp_servers.p138-http]
url = "https://m.p138.invalid/mcp"
headers = { Authorization = "Bearer ${FUIGO_API_KEY}", X-A = "a" }
"#;

/// c-3: the user deletes a server from config; the session's hot-reload seed (the copy the pager forwarded) must not keep
/// it running. A server the client supplied itself is still kept.
#[test]
fn a_server_deleted_from_config_does_not_linger_through_the_hot_reload_seed() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let home = fuigo_test_support::FuigoHome::new();
    let config = home.path().join("config.toml");
    std::fs::write(&config, USER_TOML).unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let mut client = crate::util::config::load_mcp_servers(cwd.path(), &compat);
    assert_eq!(names(&client), ["p138-http"], "precondition: the pager forwards the user's server");
    client.push(acp::McpServer::Http(acp::McpServerHttp::new("p138-editor", "https://e.p138.invalid/mcp").headers(vec![])));

    let AdmittedClientServers { merged, seed } = admit_client_mcp_servers_for_seed(client, cwd.path(), &compat, None);
    assert!(names(&merged).contains(&"p138-http".to_owned()), "what runs now still has the user's server");
    // P141: the seed keeps the forwarded copy, marked as one (the merge resolves it against the disk).
    assert_eq!(seed.disk_copy_names(), ["p138-http"], "the forwarded copy is marked as a disk copy");
    let now = merge_managed_mcp_servers(seed.clone(), cwd.path(), None, &compat);
    assert_eq!(header(find(&now, "p138-http"), "Authorization").as_deref(), Some("Bearer ${FUIGO_API_KEY}"));

    // The user deletes it; the session re-merges its seed.
    std::fs::write(&config, "").unwrap();
    let after = merge_managed_mcp_servers(seed, cwd.path(), None, &compat);
    assert!(!names(&after).contains(&"p138-http".to_owned()), "a deleted server lingers: {:?}", names(&after));
    assert!(names(&after).contains(&"p138-editor".to_owned()), "the editor's own server is kept");
}

fn find<'a>(servers: &'a [acp::McpServer], name: &str) -> &'a acp::McpServer {
    servers.iter().find(|s| mcp_server_name(s) == name).unwrap_or_else(|| panic!("{name} missing"))
}

/// c-1: the pager has no credential resolver, the shell has one. A server that reads the saved key by name
/// (`bearer_token_env_var`) is forwarded without its `Authorization` header; it is still the user's definition: used as
/// such, no refusal, no "differs" report.
#[test]
fn a_pager_copy_without_the_resolved_bearer_header_is_still_the_users_definition() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::write(
        home.path().join("config.toml"),
        "[mcp_servers.p138-bearer]\nurl = \"https://b.p138.invalid/mcp\"\nbearer_token_env_var = \"FUIGO_API_KEY\"\n",
    )
    .unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    // The pager: no resolver, the key is not exported.
    let forwarded = crate::util::config::load_mcp_servers(cwd.path(), &compat);
    assert_eq!(header(find(&forwarded, "p138-bearer"), "Authorization"), None, "precondition: the pager has no key");
    // The shell.
    fuigo_config::install_credential_env_resolver(resolver);
    let scope = fuigo_config::key_naming::NoticeScope::new();
    let admitted = scope.run(|| admit_client_mcp_servers_for_seed(forwarded, cwd.path(), &compat, None));
    assert!(scope.notes().is_empty(), "a refusal was recorded against the user's own server");
    assert_eq!(
        header(find(&admitted.merged, "p138-bearer"), "Authorization").as_deref(),
        Some(format!("Bearer {KEY}").as_str()),
        "the copy was not recognised as the user's definition"
    );
    assert_eq!(admitted.seed.disk_copy_names(), ["p138-bearer"], "the copy is not marked as the user's definition");
    // And not a different definition: nothing for the merge to report.
    let users = find(&admitted.merged, "p138-bearer").clone();
    assert!(same_definition_modulo_unresolved_bearer(&users, &http_without_auth(&users)));
    // A copy that differs in anything else is still different.
    let mut other = http_without_auth(&users);
    if let acp::McpServer::Http(h) = &mut other {
        h.url = "https://evil.p138.invalid/mcp".to_owned();
    }
    assert!(!same_definition_modulo_unresolved_bearer(&users, &other));
    // And a client copy that HAS another Authorization is not the user's.
    let mut with_other_auth = http_without_auth(&users);
    if let acp::McpServer::Http(h) = &mut with_other_auth {
        h.headers.push(acp::HttpHeader::new("Authorization", "Bearer other"));
    }
    assert!(!same_definition_modulo_unresolved_bearer(&users, &with_other_auth));
}

fn http_without_auth(server: &acp::McpServer) -> acp::McpServer {
    let mut s = server.clone();
    if let acp::McpServer::Http(h) = &mut s {
        h.headers.retain(|x| !x.name.eq_ignore_ascii_case("authorization"));
    }
    s
}

/// c-2: a differing client copy is reported once, not on every reload that re-merges the same seed.
#[test]
fn a_differing_client_server_is_reported_once() {
    let a = acp::McpServer::Http(acp::McpServerHttp::new("p138-once", "https://o.p138.invalid/mcp").headers(vec![]));
    let b = acp::McpServer::Http(acp::McpServerHttp::new("p138-once", "https://o2.p138.invalid/mcp").headers(vec![]));
    assert!(first_report_of_differing_server(&a));
    assert!(!first_report_of_differing_server(&a), "reported again");
    assert!(!first_report_of_differing_server(&a.clone()), "reported again");
    assert!(first_report_of_differing_server(&b), "a different definition is a different report");
}

/// d-1: the folder-trust grant reloads through the notice-sending merge: a refusal the merge records reaches the session.
#[test]
fn the_trust_grant_reload_tells_the_session_what_it_refused() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let _home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let seed = vec![acp::McpServer::Http(
        acp::McpServerHttp::new("p138-grant", "https://g.p138.invalid/mcp")
            .headers(vec![acp::HttpHeader::new("Authorization", "Bearer ${FUIGO_API_KEY}")]),
    )];
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    assert!(merge_and_send_managed_mcp_update_with_notices(&tx, cwd.path(), seed, None, &compat));
    let (mut notices, mut updates) = (Vec::new(), 0);
    while let Ok(cmd) = rx.try_recv() {
        match cmd {
            crate::session::SessionCommand::NotifyConfigNoticeIfNew { notice } => notices.push(notice),
            crate::session::SessionCommand::UpdateMcpServers { mcp_servers, .. } => {
                updates += 1;
                assert_eq!(header(find(&mcp_servers, "p138-grant"), "Authorization").as_deref(), Some("Bearer "));
            }
            _ => {}
        }
    }
    assert_eq!(updates, 1);
    assert!(
        notices.iter().any(|n| n.contains("p138-grant") && n.contains("FUIGO_API_KEY")),
        "the session was told nothing: {notices:?}"
    );
}

/// b-1: a client server that carries the key's VALUE (not a reference) loses it, and the note never holds it.
#[test]
fn a_client_server_holding_the_saved_keys_value_loses_it() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let _key = fuigo_test_support::EnvGuard::set("FUIGO_API_KEY", KEY);
    let cwd = tempfile::tempdir().unwrap();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let client = vec![
        acp::McpServer::Http(
            acp::McpServerHttp::new("p138-lit", "https://l.p138.invalid/mcp")
                .headers(vec![acp::HttpHeader::new("Authorization", format!("Bearer {KEY}")), acp::HttpHeader::new("X-Ok", "ok")]),
        ),
        acp::McpServer::Stdio(
            acp::McpServerStdio::new("p138-lit-stdio", "p138-server")
                .args(vec![format!("--key={KEY}")])
                .env(vec![acp::EnvVariable::new("TOKEN", KEY)]),
        ),
    ];
    let scope = fuigo_config::key_naming::NoticeScope::new();
    let admitted = scope.run(|| admit_client_mcp_servers(client, cwd.path(), &compat));
    let text = serde_json::to_string(&admitted).unwrap();
    assert!(!text.contains(KEY), "the key's value survived the scrub: {text}");
    assert_eq!(header(find(&admitted, "p138-lit"), "X-Ok").as_deref(), Some("ok"), "other text is kept");
    let notes = scope.notes();
    assert!(!notes.is_empty(), "no note");
    assert!(notes.iter().all(|n| !n.contains(KEY)), "a note holds the key: {notes:?}");
}

/// Astra P138 r1 #1 (HIGH): a forwarded copy the ingress RENAMED (`com.p138` -> `com-p138`; the disk only has the raw
/// name) stays in the seed, so a later reload still runs it.
#[test]
fn a_renamed_forwarded_copy_stays_in_the_seed() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let home = fuigo_test_support::FuigoHome::new();
    let dotted = "[mcp_servers.\"com.p138\"]\nurl = \"https://d.p138.invalid/mcp\"\nheaders = { Authorization = \"Bearer ${FUIGO_API_KEY}\" }\n";
    std::fs::write(home.path().join("config.toml"), format!("{USER_TOML}\n{dotted}")).unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let forwarded = crate::util::config::load_mcp_servers(cwd.path(), &compat);
    let AdmittedClientServers { seed, .. } = admit_client_mcp_servers_for_seed(forwarded, cwd.path(), &compat, None);
    let mut copies = seed.disk_copy_names();
    copies.sort();
    assert_eq!(copies, ["com-p138", "p138-http"], "both forwarded copies stay in the seed, marked");
    // The next reload (disk unchanged) still runs both, the renamed one with its key reference.
    let reloaded = merge_managed_mcp_servers(seed, cwd.path(), None, &compat);
    assert_eq!(header(find(&reloaded, "com-p138"), "Authorization").as_deref(), Some("Bearer ${FUIGO_API_KEY}"));
    assert!(names(&reloaded).contains(&"p138-http".to_owned()));
}

// Astra P138 r1 #2 (a copy shadowing a same-named plugin server stays and wins every reload) is now tested through a
// real plugin registry and the production reload paths: `managed_mcp_p141_tests.rs` and `hooks_plugins_p141_tests.rs`.
