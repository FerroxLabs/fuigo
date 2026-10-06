//! P136 (Astra round 3 on P133, #1): provenance is honoured at every credential extraction point. A definition marked
//! `untrusted_source` never resolves the saved API key, through `bearer_token_env_var` or through either OAuth
//! client-secret variable, by name or by an alias that holds the key. Red first.

use super::*;

pub(super) const SAVED_KEY: &str = "p136-FAKE-saved-key";

fn install() {
    install_credential_env_resolver(super::p70_redacted_debug::p70a_resolver);
}

fn untrusted(json: serde_json::Value) -> McpServerConfig {
    let mut cfg: McpServerConfig = serde_json::from_value(json).expect("a server definition");
    cfg.untrusted_source = true;
    cfg
}

#[test]
fn an_untrusted_definition_never_gets_the_saved_key_as_its_oauth_secret() {
    install();
    for var in ["FUIGO_API_KEY", "P136_ALIAS_OF_THE_KEY", "P136_HOLDS_THE_KEY", "P136_LITERAL_REFERENCE"] {
        for json in [
            serde_json::json!({ "url": "https://o.p136.invalid/mcp", "oauth_client_id": "c", "oauth_client_secret_env_var": var }),
            serde_json::json!({ "url": "https://o.p136.invalid/mcp", "oauth": { "clientId": "c", "clientSecretEnvVar": var } }),
        ] {
            let oauth = untrusted(json.clone()).oauth_config().expect("the client id still applies");
            assert_eq!(oauth.client_id.as_deref(), Some("c"), "{json}");
            assert_ne!(oauth.client_secret.as_deref(), Some(SAVED_KEY), "{json}: the saved key became the OAuth secret");
        }
    }
}

#[test]
fn an_untrusted_definition_never_gets_the_saved_key_as_its_bearer_token() {
    install();
    // Astra P136 r1 #2: a variable whose value is the TEXT `${FUIGO_API_KEY}` would put a reference the HTTP spawn
    // resolves to the key into the header, after the final scrub ran.
    for var in ["FUIGO_API_KEY", "P136_ALIAS_OF_THE_KEY", "P136_HOLDS_THE_KEY", "P136_LITERAL_REFERENCE"] {
        let cfg = untrusted(serde_json::json!({ "url": "https://b.p136.invalid/mcp", "bearer_token_env_var": var }));
        let Some(acp::McpServer::Http(h)) = cfg.to_acp_mcp_server("p136-bearer") else { panic!("http") };
        assert!(
            h.headers.iter().all(|x| !x.value.contains(SAVED_KEY) && !x.value.contains("FUIGO_API_KEY")),
            "{var}: the bearer token is or names the saved key: {:?}",
            h.headers.iter().map(|x| &x.name).collect::<Vec<_>>()
        );
    }
}

/// Astra P136 r1 #3: an untrusted definition whose text became the key's VALUE on expansion (no reference left) is
/// still refused at the final gate.
#[test]
fn an_untrusted_definition_holding_the_saved_key_value_is_refused_at_the_final_gate() {
    install();
    let cfg = untrusted(serde_json::json!({
        "url": "https://v.p136.invalid/mcp",
        "headers": { "Authorization": format!("Bearer {SAVED_KEY}"), "X-Plain": "ok" }
    }));
    let Some(acp::McpServer::Http(h)) = cfg.to_acp_mcp_server("p136-value") else { panic!("http") };
    assert!(h.headers.iter().all(|x| !x.value.contains(SAVED_KEY)), "the key value reached the header");
    assert!(h.headers.iter().any(|x| x.name == "X-Plain" && x.value == "ok"));
    let stdio = untrusted(serde_json::json!({ "command": "x", "args": [format!("--k={SAVED_KEY}")], "env": { "T": SAVED_KEY } }));
    let Some(acp::McpServer::Stdio(s)) = stdio.to_acp_mcp_server("p136-value-stdio") else { panic!("stdio") };
    assert!(s.args.iter().all(|a| !a.contains(SAVED_KEY)) && s.env.iter().all(|e| !e.value.contains(SAVED_KEY)));
}

/// The control: the user's own (trusted) definition keeps both, and another variable keeps working when untrusted.
#[test]
fn a_trusted_definition_keeps_the_saved_key_and_others_keep_their_secrets() {
    install();
    let mut trusted = untrusted(serde_json::json!({
        "url": "https://o.p136.invalid/mcp", "oauth_client_id": "c", "oauth_client_secret_env_var": "FUIGO_API_KEY"
    }));
    trusted.untrusted_source = false;
    assert_eq!(trusted.oauth_config().and_then(|o| o.client_secret).as_deref(), Some(SAVED_KEY));
    let other = untrusted(serde_json::json!({
        "url": "https://o.p136.invalid/mcp", "oauth_client_id": "c", "oauth_client_secret_env_var": "P70A_MCP_BEARER_TEST_VAR"
    }));
    assert_eq!(other.oauth_config().and_then(|o| o.client_secret).as_deref(), Some("p70a-FAKE-resolved-bearer"));
}

/// P147 (Astra r1 #4): a JSON source's (`~/.claude.json`) `${FUIGO_API_KEY:-default}` in `command`, `cwd` or `url` (which
/// never receive the saved key) is its default after loading, as without a key in 1.0.20; in `args`, `env` and
/// `headers` it is kept for the spawn to resolve.
#[test]
fn a_defaulted_reference_is_its_default_where_the_key_is_never_filled() {
    assert!(std::env::var_os("FUIGO_API_KEY").is_none(), "this test needs FUIGO_API_KEY unexported");
    let sub = &fuigo_config::expand_env_vars_in_string;
    let mut stdio: McpServerConfig = serde_json::from_value(serde_json::json!({
        "command": "${FUIGO_API_KEY:-npx}", "args": ["${FUIGO_API_KEY:-a}"], "cwd": "/w/${FUIGO_API_KEY:-c}",
        "env": { "T": "${FUIGO_API_KEY:-e}" }
    }))
    .unwrap();
    stdio.expand_strings(sub);
    let McpServerTransportConfig::Stdio { command, args, env, cwd } = &stdio.transport else { panic!("stdio") };
    assert_eq!(command, "npx");
    assert_eq!(cwd.as_deref(), Some("/w/c"));
    assert_eq!(args[0], "${FUIGO_API_KEY:-a}");
    assert_eq!(env.as_ref().unwrap()["T"], "${FUIGO_API_KEY:-e}");
    let mut http: McpServerConfig = serde_json::from_value(serde_json::json!({
        "url": "https://x.invalid/${FUIGO_API_KEY:-v1}/mcp", "headers": { "X": "${FUIGO_API_KEY:-h}" }
    }))
    .unwrap();
    http.expand_strings(sub);
    let McpServerTransportConfig::StreamableHttp { url, headers, .. } = &http.transport else { panic!("http") };
    assert_eq!(url, "https://x.invalid/v1/mcp");
    assert_eq!(headers.as_ref().unwrap()["X"], "${FUIGO_API_KEY:-h}");
}
