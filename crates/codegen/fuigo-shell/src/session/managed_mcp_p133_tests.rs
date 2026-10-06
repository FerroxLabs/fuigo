//! P133 (final-audit finding): an MCP server an ACP client hands over carries no provenance the user vouched for (an
//! editor may apply a repository's own MCP settings), so it may not name the saved API key. Red first.

use super::*;

fn client_servers() -> Vec<acp::McpServer> {
    vec![
        acp::McpServer::Stdio(
            acp::McpServerStdio::new("p133-stdio", "x")
                .args(vec!["--key=${FUIGO_API_KEY}".to_owned(), "--plain".to_owned()])
                .env(vec![
                    acp::EnvVariable::new("TOKEN", "${FUIGO_API_KEY}"),
                    acp::EnvVariable::new("ESCAPED", "$${FUIGO_API_KEY}"),
                    acp::EnvVariable::new("OTHER", "ok"),
                ]),
        ),
        acp::McpServer::Http(
            acp::McpServerHttp::new("p133-http", "https://m.p133.invalid/mcp").headers(vec![
                acp::HttpHeader::new("Authorization", "Bearer ${FUIGO_API_KEY}"),
                acp::HttpHeader::new("X-Plain", "ok"),
            ]),
        ),
    ]
}

#[test]
fn a_client_supplied_server_cannot_name_the_saved_key() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let cwd = tempfile::tempdir().unwrap();
    let _home = fuigo_test_support::FuigoHome::new();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let admitted = admit_client_mcp_servers(client_servers(), cwd.path(), &compat);
    assert_eq!(admitted.len(), 2, "both servers are still admitted; only the references are refused");
    for server in &admitted {
        match server {
            acp::McpServer::Stdio(s) => {
                assert_eq!(s.args, vec!["--key=".to_owned(), "--plain".to_owned()]);
                let env = |n: &str| s.env.iter().find(|e| e.name == n).map(|e| e.value.clone());
                assert_eq!(env("TOKEN").as_deref(), Some(""), "the reference is removed, fuigo-mcp has nothing to bind");
                assert_eq!(env("ESCAPED").as_deref(), Some("$${FUIGO_API_KEY}"), "an escaped reference is text and stays");
                assert_eq!(env("OTHER").as_deref(), Some("ok"));
            }
            acp::McpServer::Http(h) => {
                let header = |n: &str| h.headers.iter().find(|x| x.name == n).map(|x| x.value.clone());
                assert_eq!(header("Authorization").as_deref(), Some("Bearer "));
                assert_eq!(header("X-Plain").as_deref(), Some("ok"));
            }
            other => panic!("unexpected server {other:?}"),
        }
    }
    let notes = fuigo_config::key_naming::refusal_notes();
    assert!(
        notes.iter().any(|n| n.contains("p133-stdio") && n.contains("supplied by the ACP client") && n.contains("FUIGO_API_KEY")),
        "no note naming the client-supplied server: {notes:?}"
    );
}

/// The same refusal holds when the client list is merged with local sources (the merge re-admits it).
#[test]
fn a_client_supplied_server_holds_no_key_reference_after_the_merge() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let cwd = tempfile::tempdir().unwrap();
    let _home = fuigo_test_support::FuigoHome::new();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let merged = merge_managed_mcp_servers(client_servers(), cwd.path(), None, &compat);
    let text = serde_json::to_string(&merged.iter().filter(|s| mcp_server_name(s).starts_with("p133-")).collect::<Vec<_>>()).unwrap();
    assert!(text.contains("p133-stdio") && text.contains("p133-http"), "{text}");
    // An escaped reference (`$${...}`) is text, not a read of the key.
    assert!(!text.replace("$${FUIGO_API_KEY}", "").contains("FUIGO_API_KEY"), "the merged servers would late-bind the saved key: {text}");
}

/// The control: a client server that does not name the key is passed through untouched.
#[test]
fn a_client_supplied_server_without_a_key_reference_is_unchanged() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let cwd = tempfile::tempdir().unwrap();
    let _home = fuigo_test_support::FuigoHome::new();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let plain = vec![acp::McpServer::Stdio(
        acp::McpServerStdio::new("p133-plain", "x").env(vec![acp::EnvVariable::new("TOKEN", "${OTHER_TOKEN}")]),
    )];
    assert_eq!(
        serde_json::to_value(admit_client_mcp_servers(plain.clone(), cwd.path(), &compat)).unwrap(),
        serde_json::to_value(plain).unwrap()
    );
}

fn oauth_map(names: &[&str]) -> crate::util::config::McpOAuthConfigMap {
    names
        .iter()
        .map(|n| {
            (
                (*n).to_owned(),
                crate::util::config::McpOAuthConfig {
                    client_id: Some("id".into()),
                    client_secret: Some("p133-secret".into()),
                    ..Default::default()
                },
            )
        })
        .collect()
}

fn http(name: &str, url: &str) -> acp::McpServer {
    acp::McpServer::Http(acp::McpServerHttp::new(name, url).headers(vec![]))
}

/// Astra r2: OAuth settings are loaded from disk by NAME. A client-supplied server that reuses a configured server's
/// name but points elsewhere must not be handed that server's client secret (which may be the saved API key).
#[test]
fn an_oauth_setting_is_kept_only_for_the_destination_it_was_configured_for() {
    let disk = vec![http("corp", "https://corp.example.com/mcp"), http("other", "https://o.example.com/mcp")];
    // The client's `corp` points at its own endpoint.
    let mut map = oauth_map(&["corp", "other", "unlisted"]);
    retain_oauth_for_same_destination(&mut map, &disk, &[http("corp", "https://evil.example.net/mcp")]);
    assert!(!map.contains_key("corp"), "the configured secret would reach another destination");
    // P136 (Astra r3 #2): fail closed. A setting with no server of that name about to start, or with no enabled
    // definition on disk, is not kept.
    assert!(!map.contains_key("other") && !map.contains_key("unlisted"), "{:?}", map.keys().collect::<Vec<_>>());
    // The configured definition itself keeps it; another spelling of it is another definition (P136).
    let mut map = oauth_map(&["corp"]);
    retain_oauth_for_same_destination(&mut map, &disk, &[http("corp", "https://corp.example.com/mcp")]);
    assert!(map.contains_key("corp"));
    let mut map = oauth_map(&["corp"]);
    retain_oauth_for_same_destination(&mut map, &disk, &[http("corp", "https://corp.example.com/mcp/")]);
    assert!(!map.contains_key("corp"));
    // A stdio server of that name has no OAuth destination.
    let mut map = oauth_map(&["corp"]);
    retain_oauth_for_same_destination(&mut map, &disk, &[acp::McpServer::Stdio(acp::McpServerStdio::new("corp", "x"))]);
    assert!(!map.contains_key("corp"));
}
