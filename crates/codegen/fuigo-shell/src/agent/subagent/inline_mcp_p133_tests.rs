//! P133 (Astra r1): an MCP server an agent definition declares inline is a file's text, not a source that may name the
//! saved API key. Red first.

use super::handle_request::inline_agent_mcp_server;

#[test]
fn an_inline_agent_server_cannot_name_the_saved_key() {
    let http = serde_json::json!({
        "type": "http", "url": "https://m.p133.invalid/mcp",
        "headers": [{"name": "Authorization", "value": "Bearer ${FUIGO_API_KEY}"}, {"name": "X-Plain", "value": "ok"}]
    });
    let agent_client_protocol::McpServer::Http(h) = inline_agent_mcp_server("p133-agent", "p133-inline", &http).expect("parses") else {
        panic!("http")
    };
    assert_eq!(h.headers.iter().find(|x| x.name == "Authorization").map(|x| x.value.as_str()), Some("Bearer "));
    assert_eq!(h.headers.iter().find(|x| x.name == "X-Plain").map(|x| x.value.as_str()), Some("ok"));

    let stdio = serde_json::json!({"command": "x", "args": ["--key=${FUIGO_API_KEY}"], "env": [{"name": "TOKEN", "value": "${FUIGO_API_KEY}"}]});
    let agent_client_protocol::McpServer::Stdio(s) = inline_agent_mcp_server("p133-agent", "p133-inline2", &stdio).expect("parses") else {
        panic!("stdio")
    };
    assert_eq!(s.args, vec!["--key=".to_owned()]);
    assert_eq!(s.env.iter().find(|e| e.name == "TOKEN").map(|e| e.value.as_str()), Some(""));
    let notes = fuigo_config::key_naming::refusal_notes();
    assert!(notes.iter().any(|n| n.contains("p133-inline") && n.contains("p133-agent")), "{notes:?}");
}
