//! P91 R5 + audit mutant M4: the agent-id header (the bound session id) is never
//! taken from config, and is sent only to a first-party server on loopback.
use super::*;

fn headers_with_forgery() -> Vec<(String, String)> {
    vec![
        ("x-grok-agent-id".to_owned(), "forged".to_owned()),
        ("Authorization".to_owned(), "Bearer keep".to_owned()),
        ("X-GROK-AGENT-ID".to_owned(), "forged-upper".to_owned()),
    ]
}

fn agent_ids(headers: &[(String, String)]) -> Vec<&str> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(GROK_AGENT_ID_HEADER))
        .map(|(_, value)| value.as_str())
        .collect()
}

/// M4: a config-supplied `X-Grok-Agent-ID` (any case) never reaches any server.
#[test]
fn config_supplied_agent_id_header_is_always_stripped() {
    let writer = fuigo_session_events::EventWriter::noop();
    let plain = McpSpawnCtx::for_session("sess-1", &writer, OauthInteractivity::Interactive, None);
    let first_party =
        McpSpawnCtx::for_session("sess-1", &writer, OauthInteractivity::Interactive, None)
            .with_grok_agent_id_header();
    for (ctx, url, expect_local, expect_ids) in [
        (&plain, "https://mcp.example.com/mcp", false, vec![]),
        (&plain, "http://127.0.0.1:9/mcp", false, vec![]),
        (&first_party, "https://mcp.example.com/mcp", false, vec![]),
        (&first_party, "http://127.0.0.1:9/mcp", true, vec!["sess-1"]),
    ] {
        let mut headers = headers_with_forgery();
        let local = apply_agent_id_header(&mut headers, "srv", url, ctx).unwrap();
        assert_eq!(local, expect_local, "{url}");
        assert_eq!(agent_ids(&headers), expect_ids, "{url}: {headers:?}");
        assert!(headers.iter().any(|(n, v)| n == "Authorization" && v == "Bearer keep"));
    }
}

/// R5: a first-party NAME alone is not enough; the server must be on this machine.
#[test]
fn first_party_posture_requires_a_loopback_url() {
    for url in [
        "http://127.0.0.1:8080/mcp",
        "http://127.5.6.7/mcp",
        "http://[::1]:3000/mcp",
        "http://localhost:3000/mcp",
        "https://LOCALHOST/mcp",
    ] {
        assert!(is_loopback_http_url(url), "{url}");
    }
    for url in [
        "https://app.example.com/mcp",
        "http://localhost.evil.example/mcp",
        "http://127.0.0.1.evil.example/mcp",
        "http://10.0.0.1/mcp",
        "http://0.0.0.0:8080/mcp",
        "http://[::ffff:8.8.8.8]/mcp",
        "ws://127.0.0.1/mcp",
        "file:///tmp/sock",
        "not a url",
    ] {
        assert!(!is_loopback_http_url(url), "{url}");
    }
}
