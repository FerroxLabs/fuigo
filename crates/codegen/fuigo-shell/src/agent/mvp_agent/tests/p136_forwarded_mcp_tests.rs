//! P136 (Astra r3 #3, a P133 regression): the pager forwards the user's own MCP servers in `session/new` and
//! `session/load`; both go through `resolve_mcp_servers` (admit, then merge). A user config that names the saved key
//! must come out of it unchanged, as in v1.0.20.

use agent_client_protocol as acp;

use super::build_minimal_agent_for_tests;

#[tokio::test(flavor = "current_thread")]
async fn the_session_entry_keeps_a_forwarded_user_server_s_key_reference() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::write(
        home.path().join("config.toml"),
        "[mcp_servers.p136-agent]\nurl = \"https://a.p136.invalid/mcp\"\nheaders = { Authorization = \"Bearer ${FUIGO_API_KEY}\", X-A = \"a\", X-B = \"b\" }\n",
    )
    .unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let forwarded =
        crate::util::config::load_mcp_servers(cwd.path(), &fuigo_tools::types::compat::CompatConfig::default());
    let agent = build_minimal_agent_for_tests();
    let (seed, merged) = agent.resolve_mcp_servers(forwarded, cwd.path()).await;
    // P141: the hot-reload seed keeps the forwarded copy, marked as the user's disk definition (every merge resolves it
    // against the current disk, so it neither goes stale nor outlives a delete).
    assert_eq!(seed.disk_copy_names(), ["p136-agent"], "the forwarded copy is not marked as the user's definition: {seed:?}");
    let auth = merged
        .iter()
        .find_map(|s| match s {
            acp::McpServer::Http(h) if h.name == "p136-agent" => {
                h.headers.iter().find(|x| x.name == "Authorization").map(|x| x.value.clone())
            }
            _ => None,
        })
        .expect("merged: p136-agent missing");
    assert_eq!(auth, "Bearer ${FUIGO_API_KEY}", "merged: the user's own key reference was scrubbed");
}
