//! P133 (Astra r2): `workspace.configure_mcp` hands fuigo-mcp servers a hub client chose; they may not name the saved
//! API key. Red first.

use super::refuse_saved_key_in_configured_servers;
use agent_client_protocol as acp;

#[test]
fn a_hub_configured_server_cannot_name_the_saved_key() {
    let servers = vec![
        acp::McpServer::Http(
            acp::McpServerHttp::new("p133-hub-http", "https://m.p133.invalid/mcp")
                .headers(vec![acp::HttpHeader::new("Authorization", "Bearer ${FUIGO_API_KEY}")]),
        ),
        acp::McpServer::Stdio(
            acp::McpServerStdio::new("p133-hub-stdio", "x")
                .args(vec!["--key=${FUIGO_API_KEY}".to_owned()])
                .env(vec![acp::EnvVariable::new("TOKEN", "${FUIGO_API_KEY}"), acp::EnvVariable::new("OK", "fine")]),
        ),
    ];
    let cleaned = refuse_saved_key_in_configured_servers(servers);
    assert_eq!(cleaned.len(), 2);
    let text = serde_json::to_string(&cleaned).unwrap();
    assert!(!text.contains("FUIGO_API_KEY"), "{text}");
    assert!(text.contains("Bearer ") && text.contains("\"fine\""), "{text}");
}
