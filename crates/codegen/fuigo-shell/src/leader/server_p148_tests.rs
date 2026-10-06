//! P148 (B19, Astra r2): on a shared leader each client's own `initialize` `startupHints` reach its session requests.
//! The agent keeps only the first `initialize` it saw, so without this an app that embeds Fuigo non-interactively and
//! sends its hints only on `initialize` ran its sessions under the first (interactive) client's policy.

use super::*;
use serde_json::json;

fn initialize(hints: serde_json::Value) -> serde_json::Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": AGENT_METHOD_NAMES.initialize,
           "params": {"protocolVersion": 1, "_meta": {"startupHints": hints}}})
}

#[test]
fn a_clients_initialize_hints_are_read_from_its_initialize_only() {
    let hints = json!({"nonInteractive": true});
    assert_eq!(initialize_startup_hints(&initialize(hints.clone())), Some(hints));
    assert_eq!(initialize_startup_hints(&initialize(json!("not an object"))), None);
    let new = json!({"jsonrpc": "2.0", "id": 2, "method": AGENT_METHOD_NAMES.session_new,
                     "params": {"cwd": "/w", "_meta": {"startupHints": {"nonInteractive": true}}}});
    assert_eq!(initialize_startup_hints(&new), None, "only an initialize sets a client's hints");
}

#[test]
fn a_session_request_without_hints_carries_its_clients_initialize_hints() {
    let hints = json!({"nonInteractive": true, "skipGitStatus": true});
    for method in [
        AGENT_METHOD_NAMES.session_new,
        AGENT_METHOD_NAMES.session_load,
        AGENT_METHOD_NAMES.session_resume,
    ] {
        let mut request = json!({"jsonrpc": "2.0", "id": 3, "method": method, "params": {"cwd": "/w"}});
        assert!(inject_client_startup_hints(&mut request, Some(&hints)), "{method}");
        assert_eq!(request["params"]["_meta"]["startupHints"], hints, "{method}");
    }
}

#[test]
fn hints_a_session_request_names_itself_are_kept_and_nothing_else_is_touched() {
    let hints = json!({"nonInteractive": true});
    let own = json!({"nonInteractive": false});
    let mut request = json!({"jsonrpc": "2.0", "id": 4, "method": AGENT_METHOD_NAMES.session_new,
                             "params": {"cwd": "/w", "_meta": {"startupHints": own.clone()}}});
    assert!(!inject_client_startup_hints(&mut request, Some(&hints)));
    assert_eq!(request["params"]["_meta"]["startupHints"], own);

    let mut prompt = json!({"jsonrpc": "2.0", "id": 5, "method": AGENT_METHOD_NAMES.session_prompt,
                            "params": {"sessionId": "s"}});
    let before = prompt.clone();
    assert!(!inject_client_startup_hints(&mut prompt, Some(&hints)));
    assert_eq!(prompt, before);

    let mut no_hints = json!({"jsonrpc": "2.0", "id": 6, "method": AGENT_METHOD_NAMES.session_new,
                              "params": {"cwd": "/w"}});
    let before = no_hints.clone();
    assert!(!inject_client_startup_hints(&mut no_hints, None), "a client that sent no hints adds none");
    assert_eq!(no_hints, before);
}
