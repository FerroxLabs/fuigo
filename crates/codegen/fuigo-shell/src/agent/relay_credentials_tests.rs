//! P82 tests: the request gate and the response backstop on their own, then through the real relay socket session.
use super::*;
use crate::agent::relay::{RelayBodyIdentity, SessionEndReason, relay_outbound_frame, run_websocket_session};
use agent_client_protocol as acp;
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes, protocol::Role};
use tokio_util::sync::CancellationToken;

/// A session bearer and an API key as the producers would hand them out; no frame a relay that is not
/// FluxRouter-operated receives may contain either.
const BEARER: &str = "p82-bearer-eyJhbGciOiJSUzI1NiJ9.c2Vzc2lvbg.c2ln";
const API_KEY: &str = "xai-p82-api-key-0123456789abcdef";
const ENV_SECRET: &str = "p82-env-secret-hunter2";
const MCP_SECRET: &str = "ghp_p82mcpsecret0123456789";
const HOOK_SECRET: &str = "p82-hook-secret-0123";

const FLUXROUTER_RELAYS: [&str; 2] = ["wss://api.fluxrouter.ai/ws/relay", "WSS://API.FluxRouter.AI:443/other"];
const OTHER_RELAYS: [&str; 5] = [
    "wss://relay.example/ws",
    "ws://api.fluxrouter.ai/ws/relay",
    "https://api.fluxrouter.ai/ws/relay",
    "wss://api.fluxrouter.ai.evil.example/ws",
    "",
];

fn machine_id() -> String {
    "5d1f0c2a-7a7a-4b4b-8c8c-0123456789ab".to_owned()
}
fn decision(relay: &str) -> RelayBodyIdentity {
    RelayBodyIdentity::for_relay(relay, machine_id)
}
fn disclosure(relay: &str) -> IdentityDisclosure {
    IdentityDisclosure::for_websocket_destination(relay)
}
/// `text` with every `~u` turned into a JSON unicode escape's introducer (a backslash and `u`), so that a fixture can
/// spell an escaped key or value without the escape being resolved anywhere before the code under test reads it.
fn esc(text: &str) -> String {
    text.replace("~u", "\\u")
}
fn parse(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {text}"))
}
/// The refusal `gate_relay_message` must answer `id` / `method` with.
fn assert_refusal(answer: &str, id: &Value, method: &str) {
    let answer = parse(answer);
    assert_eq!(answer["jsonrpc"], "2.0", "{answer}");
    assert_eq!(&answer["id"], id, "{answer}");
    assert_eq!(answer["error"]["code"], -32600, "{answer}");
    let message = answer["error"]["message"].as_str().unwrap();
    assert!(message.contains(method) && message.contains("FluxRouter-operated relay"), "{answer}");
    assert_eq!(answer["error"]["data"]["error_kind"], "invalid_request", "{answer}");
    assert_eq!(answer["error"]["data"]["message"], message, "{answer}");
    assert!(answer.get("result").is_none(), "{answer}");
}

// ===== request side =====

/// P82 hostile, request side: every credential method a relay that is not FluxRouter-operated asks for is refused
/// with an error carrying its own id, whatever the id; a notification for one is dropped; the agent never sees either.
#[test]
fn p82_gate_refuses_every_credential_method() {
    assert_eq!(CREDENTIAL_METHODS, ["fuigo/auth/getBearerToken", "fuigo/getApiKey"]);
    for method in CREDENTIAL_METHODS {
        let wire = format!("_{method}");
        for id in [json!(7), json!("3|1"), json!(null), json!(-1.5), json!({ "nested": [1] })] {
            let request = json!({ "jsonrpc": "2.0", "id": id, "method": wire, "params": {} });
            match gate_relay_message(&request) {
                RelayMessage::Refuse(answer) => assert_refusal(&answer, &id, &wire),
                other => panic!("{request}: {other:?}"),
            }
        }
        // Without params, without `jsonrpc`, without the `_` (the agent's reader would not route that name, but it
        // is refused all the same), with several.
        for spelling in [wire.clone(), method.to_owned(), format!("__{method}"), format!("___{method}")] {
            let request = json!({ "id": 1, "method": spelling });
            assert!(matches!(gate_relay_message(&request), RelayMessage::Refuse(_)), "{request}");
        }
        // A notification: nothing to answer, nothing handed to the agent.
        for sibling in [json!({ "result": {} }), json!({ "error": { "code": 1, "message": "m" } })] {
            let mut request = json!({ "jsonrpc": "2.0", "id": 9, "method": wire });
            request.as_object_mut().unwrap().extend(sibling.as_object().unwrap().clone());
            assert!(matches!(gate_relay_message(&request), RelayMessage::Refuse(_)), "{request}");
        }
        let notification = json!({ "jsonrpc": "2.0", "method": wire, "params": {} });
        assert_eq!(gate_relay_message(&notification), RelayMessage::Drop, "{notification}");
    }
}

/// P82, request side: the agent reads exactly the message the gate decided on. The relay reader parses the text
/// (escapes decoded; of duplicate keys the last one); a credential method hidden by escapes or by a duplicate key is
/// still refused, and what is forwarded is that value's own one-line serialisation, never the relay's bytes.
#[test]
fn p82_gate_decides_on_the_parsed_message_and_forwards_only_that() {
    // Escapes in the method, and in the key.
    for text in [
        r#"{"jsonrpc":"2.0","id":1,"method":"_fuigo/auth/getB~u0065arerToken"}"#,
        r#"{"jsonrpc":"2.0","id":1,"m~u0065thod":"_fuigo/getApiKey"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"~u005ffuigo\/getApiKey"}"#,
    ] {
        let text = esc(text);
        assert!(text.contains("\\u0"), "positive control: an escape: {text}");
        assert!(matches!(gate_relay_message(&parse(&text)), RelayMessage::Refuse(_)), "{text}");
    }
    for text in [
        // Duplicate keys: the reader keeps the last, and so would the agent's (it rejects a duplicate field, so it
        // never sees two).
        r#"{"jsonrpc":"2.0","id":1,"method":"_fuigo/session/list","method":"_fuigo/getApiKey"}"#,
        // A raw newline inside the message: the agent's reader would split the relay's bytes there.
        "{\"jsonrpc\":\"2.0\",\n\"id\":1,\n\"method\":\"_fuigo/getApiKey\"}",
    ] {
        assert!(matches!(gate_relay_message(&parse(text)), RelayMessage::Refuse(_)), "{text}");
    }
    // The other order: the last method wins, and the forwarded line names ONLY it.
    let text = r#"{"jsonrpc":"2.0","id":1,"method":"_fuigo/getApiKey","method":"_fuigo/session/list"}"#;
    let RelayMessage::Forward(line) = gate_relay_message(&parse(text)) else { panic!("{text}") };
    assert_eq!(line, r#"{"jsonrpc":"2.0","id":1,"method":"_fuigo/session/list"}"#);
    // A message split over lines, or carrying escapes, reaches the agent as one line without them; key order and
    // every value are kept.
    let text = "{\"jsonrpc\":\"2.0\",\n \"id\":2,\n \"method\":\"session/prompt\",\"params\":{\"prompt\":[{\"type\":\"text\",\"text\":\"caf\\u00e9 \\n x\"}],\"n\":1.5}}";
    let RelayMessage::Forward(line) = gate_relay_message(&parse(text)) else { panic!("{text}") };
    assert_eq!(
        line,
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"session/prompt\",\"params\":{\"prompt\":[{\"type\":\"text\",\"text\":\"café \\n x\"}],\"n\":1.5}}"
    );
    assert!(!line.contains('\n'));
    // Near misses are not credential methods (the agent answers them with an unknown-method error or its own data).
    for method in [
        "_fuigo/auth/getBearerTokens",
        "_fuigo/auth/getbearertoken",
        "_fuigo/getApiKeyX",
        "_fuigo/setApiKey",
        "_fuigo/auth/info",
        "_fuigo/auth/get_url",
        "_fuigo/getapikey",
        "_fuigo/getApiKey_",
        "_fuigo/auth/getBearerToken__",
        "_ fuigo/getApiKey",
        "initialize",
    ] {
        let request = json!({ "jsonrpc": "2.0", "id": 3, "method": method, "params": { "fuigo/getApiKey": true } });
        assert_eq!(gate_relay_message(&request), RelayMessage::Forward(request.to_string()), "{method}");
    }
    // Responses and errors the relay sends the agent (answers to the agent's own requests) are forwarded.
    for message in [
        json!({ "jsonrpc": "2.0", "id": 4, "result": { "outcome": "allow" } }),
        json!({ "id": 5, "result": null }),
        json!({ "jsonrpc": "2.0", "id": 6, "error": { "code": -32603, "message": "client failed" } }),
        json!({ "jsonrpc": "2.0", "id": 7, "error": { "code": -32000, "message": "x" }, "method": "session/cancel" }),
    ] {
        assert_eq!(gate_relay_message(&message), RelayMessage::Forward(message.to_string()), "{message}");
    }
    // Not a JSON object: never handed to the agent. Its reader takes a positional array as a request.
    for message in [
        json!([1, "_fuigo/getApiKey", {}, null, null]),
        json!([{ "jsonrpc": "2.0", "id": 1, "method": "_fuigo/getApiKey" }]),
        json!([{ "jsonrpc": "2.0", "id": 1, "method": "session/list" }]),
        json!([]),
        json!("_fuigo/getApiKey"),
        json!(1),
        json!(null),
    ] {
        assert_eq!(gate_relay_message(&message), RelayMessage::Drop, "{message}");
    }
}

// ===== response side =====

/// The answers of the credential producers, built as they build them, in a leader-namespaced response.
fn credential_responses() -> Vec<(&'static str, String, String)> {
    use crate::session::ExtMethodResult;
    let frame = |id: &str, result: String| format!(r#"{{"jsonrpc":"2.0","id":"{id}","result":{result}}}"#);
    // `extensions/auth.rs`: `ExtMethodResult::success(json!({ "token": token }))`, `json!({ "key": key })`.
    let bearer = serde_json::to_string(&ExtMethodResult::success(json!({ "token": BEARER }))).unwrap();
    let api_key = serde_json::to_string(&ExtMethodResult::success(json!({ "key": API_KEY }))).unwrap();
    let none = serde_json::to_string(&ExtMethodResult::success(json!({ "token": null }))).unwrap();
    let no_key = serde_json::to_string(&ExtMethodResult::success(json!({ "key": null }))).unwrap();
    vec![
        ("getBearerToken", frame("3|1", bearer), frame("3|1", r#"{"result":{}}"#.to_owned())),
        ("getApiKey", frame("3|2", api_key), frame("3|2", r#"{"result":{}}"#.to_owned())),
        ("getBearerToken, no token", frame("3|3", none), frame("3|3", r#"{"result":{}}"#.to_owned())),
        ("getApiKey, no key", frame("3|4", no_key), frame("3|4", r#"{"result":{}}"#.to_owned())),
    ]
}

/// The cloud-environment responses from the REAL wire types, as `acp_agent.rs` builds them, and what a relay that is
/// not FluxRouter-operated receives from the credential filter: every secret's and variable's value, and the scripts,
/// withheld; the names and everything else kept.
fn environment_responses() -> Vec<(&'static str, String, String)> {
    use crate::remote::{SandboxEnvironment, SandboxEnvironmentVariable, SandboxEnvironmentWithMetadata};
    let variable = |key: &str, value: Option<&str>| SandboxEnvironmentVariable {
        key: Some(key.to_owned()),
        value: value.map(str::to_owned),
    };
    let environment = |id: &str| SandboxEnvironmentWithMetadata {
        environment: Some(SandboxEnvironment {
            environment_id: Some(id.to_owned()),
            name: Some("build box".to_owned()),
            setup_script: Some(format!("curl -H 'Authorization: Bearer {ENV_SECRET}' https://x")),
            maintenance_script: Some("./maintain.sh".to_owned()),
            ..Default::default()
        }),
        environment_variables: vec![variable("NODE_ENV", Some("production")), variable("API_KEY", Some(ENV_SECRET))],
        secrets: vec![variable("DB_PASSWORD", Some(ENV_SECRET)), variable("EMPTY", None), variable("TOKEN", Some("v2"))],
        user_role: Some("OWNER".to_owned()),
    };
    let rows = vec![
        environment("env-1"),
        SandboxEnvironmentWithMetadata { secrets: Vec::new(), environment: None, ..environment("env-2") },
        environment("env-3"),
    ];
    let list = format!(r#"{{"jsonrpc":"2.0","id":7,"result":{}}}"#, json!({ "environments": rows }));
    let one = format!(r#"{{"jsonrpc":"2.0","id":8,"result":{}}}"#, json!({ "environment": rows[0] }));
    let withhold = |row: &mut Value| {
        for list in ["secrets", "environmentVariables"] {
            for entry in row[list].as_array_mut().unwrap() {
                entry.as_object_mut().unwrap().shift_remove("value");
            }
        }
        if let Some(environment) = row["environment"].as_object_mut() {
            assert!(environment.shift_remove("setupScript").is_some() && environment.shift_remove("maintenanceScript").is_some());
        }
    };
    let mut list_withheld = parse(&list);
    for row in list_withheld["result"]["environments"].as_array_mut().unwrap() {
        withhold(row);
    }
    let mut one_withheld = parse(&one);
    withhold(&mut one_withheld["result"]["environment"]);
    assert_eq!(parse(&list).to_string(), list, "positive control: the frame round-trips byte for byte");
    vec![("env list", list, list_withheld.to_string()), ("env create / update", one, one_withheld.to_string())]
}

/// The MCP catalog from the REAL producer (`build_mcp_catalog`), as `fuigo/mcp/list` answers it
/// (`to_ext_response(Ok(McpListResponse { servers }))`) and as `fuigo/mcp/servers_updated` pushes it. Three servers, the
/// last with the credentials in its third variable, its arguments and (HTTP) its URL.
fn mcp_frames() -> Vec<(&'static str, String, String)> {
    use crate::extensions::mcp::{McpServersUpdated, build_mcp_catalog};
    let servers = [
        acp::McpServer::Stdio(acp::McpServerStdio::new("plain", "/usr/bin/plain")),
        acp::McpServer::Http(acp::McpServerHttp::new("remote", format!("https://mcp.example/sse?api_key={MCP_SECRET}"))),
        acp::McpServer::Stdio(
            acp::McpServerStdio::new("github", "/usr/bin/github-mcp")
                .args(vec!["--stdio".to_owned(), format!("--token={MCP_SECRET}")])
                .env(vec![
                    acp::EnvVariable::new("LOG", "debug"),
                    acp::EnvVariable::new("REGION", "eu"),
                    acp::EnvVariable::new("GITHUB_TOKEN", MCP_SECRET),
                ]),
        ),
    ];
    let catalog = build_mcp_catalog(&servers);
    let list = format!(
        r#"{{"jsonrpc":"2.0","id":9,"result":{}}}"#,
        serde_json::to_string(&crate::session::ExtMethodResult::success(json!({ "servers": catalog }))).unwrap()
    );
    let updated = format!(
        r#"{{"jsonrpc":"2.0","method":"_fuigo/mcp/servers_updated","params":{}}}"#,
        serde_json::to_string(&McpServersUpdated { mcp_servers: catalog }).unwrap()
    );
    let withheld = |frame: &str| {
        frame
            .replace(r#","command":"/usr/bin/plain""#, "")
            .replace(r#","command":"/usr/bin/github-mcp""#, "")
            .replace(&format!(r#","url":"https://mcp.example/sse?api_key={MCP_SECRET}""#), "")
            .replace(&format!(r#","args":["--stdio","--token={MCP_SECRET}"]"#), "")
            .replace(r#"{"name":"LOG","value":"debug"}"#, r#"{"name":"LOG"}"#)
            .replace(r#"{"name":"REGION","value":"eu"}"#, r#"{"name":"REGION"}"#)
            .replace(&format!(r#"{{"name":"GITHUB_TOKEN","value":"{MCP_SECRET}"}}"#), r#"{"name":"GITHUB_TOKEN"}"#)
    };
    vec![("mcp/list", list.clone(), withheld(&list)), ("mcp/servers_updated", updated.clone(), withheld(&updated))]
}

/// The hooks from the REAL wire types, as `fuigo/hooks/list` answers them (`to_ext_response(Ok(HooksListResponse))`)
/// and as the `hooks_changed` session notification pushes them. Three hooks, the third with a literal token in its URL
/// and the second in its command.
fn hook_frames() -> Vec<(&'static str, String, String)> {
    use crate::extensions::notification::{SessionNotification, SessionUpdate};
    use fuigo_hooks_plugins_types::{HookEvent, HookHandlerType, HookInfo, HooksListResponse};
    let hook = |name: &str, command: Option<String>, url: Option<String>| HookInfo {
        name: name.to_owned(),
        event: HookEvent::PreToolUse,
        handler_type: if url.is_some() { HookHandlerType::Http } else { HookHandlerType::Command },
        matcher: Some("Bash".to_owned()),
        command,
        url,
        timeout_ms: 5000,
        source_dir: "/home/u/.fuigo/hooks".to_owned(),
        disabled: false,
        pinned: false,
        removable: true,
    };
    let hooks = vec![
        hook("global/fmt:pre_tool_use[0].hooks[0]", Some("./fmt.sh".to_owned()), None),
        hook("global/notify:pre_tool_use[0].hooks[1]", Some(format!("curl -H 'Authorization: Bearer {HOOK_SECRET}' x")), None),
        hook("global/audit:pre_tool_use[0].hooks[2]", None, Some(format!("https://hooks.example/run?token={HOOK_SECRET}"))),
    ];
    let list = format!(
        r#"{{"jsonrpc":"2.0","id":10,"result":{}}}"#,
        serde_json::to_string(&crate::session::ExtMethodResult::success(HooksListResponse {
            hooks: hooks.clone(),
            project_trusted: true,
            load_errors: Vec::new(),
        }))
        .unwrap()
    );
    let changed = format!(
        r#"{{"jsonrpc":"2.0","method":"_fuigo/session_notification","params":{}}}"#,
        serde_json::to_string(&SessionNotification {
            session_id: acp::SessionId::new("s-1"),
            update: SessionUpdate::HooksChanged { hooks, project_trusted: true, load_errors: Vec::new() },
            meta: None,
        })
        .unwrap()
    );
    let withheld = |frame: &str| {
        frame
            .replace(r#""command":"./fmt.sh","url":null,"#, "")
            .replace(&format!(r#""command":"curl -H 'Authorization: Bearer {HOOK_SECRET}' x","url":null,"#), "")
            .replace(&format!(r#""command":null,"url":"https://hooks.example/run?token={HOOK_SECRET}","#), "")
    };
    vec![("hooks/list", list.clone(), withheld(&list)), ("hooks_changed", changed.clone(), withheld(&changed))]
}

/// The agent's own `terminal/create` request to its client (`fuigo-shell-terminal`: `acp::CreateTerminalRequest` with
/// the session's environment), as a relay receives it in leader mode, and without its `env`.
fn terminal_frames() -> Vec<(&'static str, String, String)> {
    let request = acp::CreateTerminalRequest::new(acp::SessionId::new("s-1"), "pwd")
        .args(vec![])
        .env(vec![acp::EnvVariable::new("LANG", "C"), acp::EnvVariable::new("GITHUB_TOKEN", MCP_SECRET)])
        .cwd(Some(std::path::PathBuf::from("/work")))
        .output_byte_limit(Some(4096));
    let frame = format!(
        r#"{{"jsonrpc":"2.0","id":"t-1","method":"terminal/create","params":{}}}"#,
        serde_json::to_string(&request).unwrap()
    );
    let mut withheld: Value = parse(&frame);
    assert!(withheld["params"].as_object_mut().unwrap().shift_remove("env").is_some(), "positive control: {frame}");
    vec![("terminal/create", frame, withheld.to_string())]
}

fn all_credential_frames() -> Vec<(&'static str, String, String)> {
    let mut frames = credential_responses();
    frames.extend(environment_responses());
    frames.extend(mcp_frames());
    frames.extend(hook_frames());
    frames.extend(terminal_frames());
    frames
}

/// P82 hostile and first-party, response side: a relay that is not FluxRouter-operated never receives a credential
/// field, from the producers' own shapes; a FluxRouter relay receives every frame byte for byte; the rest of each
/// frame is unchanged.
#[test]
fn p82_withhold_credentials_from_every_producer() {
    for (name, frame, withheld) in all_credential_frames() {
        assert_ne!(frame, withheld, "{name}: positive control, the fields are where the replace looks: {frame}");
        for relay in FLUXROUTER_RELAYS {
            assert_eq!(withhold_credentials(disclosure(relay), frame.clone()), frame, "{name} {relay}");
            assert_eq!(relay_outbound_frame(&decision(relay), frame.clone()), frame, "{name} {relay}");
        }
        for relay in OTHER_RELAYS {
            let sent = withhold_credentials(disclosure(relay), frame.clone());
            assert_eq!(sent, withheld, "{name} {relay}");
            // The socket writer's whole filter: P81's identity filter on the frame without its credentials (the
            // environment fixtures' owner ids are null, and P81 withholds them whatever their value).
            let written = relay_outbound_frame(&decision(relay), frame.clone());
            assert_eq!(written, relay_outbound_frame(&decision(relay), withheld.clone()), "{name} {relay}");
            if !name.starts_with("env") {
                assert_eq!(written, withheld, "{name} {relay}");
            }
            for secret in [BEARER, API_KEY, ENV_SECRET, MCP_SECRET, HOOK_SECRET, "\"v2\"", "\"debug\"", "./fmt.sh", "production", "maintain.sh"] {
                assert!(!written.contains(secret), "{name} {relay}: {secret} in {written}");
                assert!(!sent.contains(secret), "{name} {relay}: {secret} in {sent}");
            }
        }
    }
    // The kept parts, stated once.
    let (_, _, env_list) = &environment_responses()[0];
    for kept in [r#""key":"NODE_ENV""#, r#""key":"API_KEY""#, r#""key":"DB_PASSWORD""#, r#""userRole":"OWNER""#, "env-3", r#""name":"build box""#] {
        assert!(env_list.contains(kept), "{kept}: {env_list}");
    }
    let (_, _, mcp_list) = &mcp_frames()[0];
    for kept in [r#""name":"GITHUB_TOKEN""#, r#""type":"stdio""#, r#""name":"plain""#, r#""type":"http""#, r#""name":"REGION""#] {
        assert!(mcp_list.contains(kept), "{kept}: {mcp_list}");
    }
    for gone in ["\"args\":", "\"url\":", "\"command\":"] {
        assert!(!mcp_list.contains(gone), "{gone}: {mcp_list}");
    }
    for (_, _, hooks) in hook_frames() {
        for kept in ["global/audit:pre_tool_use[0].hooks[2]", r#""matcher":"Bash""#, r#""handlerType":"http""#, r#""removable":true"#] {
            assert!(hooks.contains(kept), "{kept}: {hooks}");
        }
        assert!(!hooks.contains("\"command\":") && !hooks.contains("\"url\":"), "{hooks}");
    }
    // Every field on its own, whatever its value, and next to unrelated data that stays byte for byte (raw text).
    for (frame, withheld) in [
        (
            r#"{"id":1,"result":{"result":{"a":1.50,"token":{"x":[1]},"b":"~u00e9","c":"é"}}}"#,
            r#"{"id":1,"result":{"result":{"a":1.50,"b":"~u00e9","c":"é"}}}"#,
        ),
        (r#"{"id":1,"result":{"result":{"key":7}},"x":[ 1 ]}"#, r#"{"id":1,"result":{"result":{}},"x":[ 1 ]}"#),
        (r#"{"id":1,"result":{"result":{"token":"t","key":"k","c":3}}}"#, r#"{"id":1,"result":{"result":{"c":3}}}"#),
        (
            r#"{"id":1,"result":{"environments":[{"secrets":[{"key":"A","value":true},3,{"value":[]}]},null,"s"]}}"#,
            r#"{"id":1,"result":{"environments":[{"secrets":[{"key":"A"},3,{}]},null,"s"]}}"#,
        ),
        (r#"{"id":1,"result":{"environment":{"secrets":[{"value":"v"}]}}}"#, r#"{"id":1,"result":{"environment":{"secrets":[{}]}}}"#),
        (
            r#"{"id":1,"result":{"result":{"servers":[{"env":[{"name":"A","value":"v"}]},{"type":"http"}]}}}"#,
            r#"{"id":1,"result":{"result":{"servers":[{"env":[{"name":"A"}]},{"type":"http"}]}}}"#,
        ),
        (
            r#"{"id":1,"result":{"result":{"servers":[{"args":["a"],"n":1},{"url":"u","n":2},{"url":null,"args":[],"env":[]}]}}}"#,
            r#"{"id":1,"result":{"result":{"servers":[{"n":1},{"n":2},{"env":[]}]}}}"#,
        ),
        (
            r#"{"id":1,"result":{"result":{"servers":[{"name":"a","setup":{"variables":{"AUTH":{"map":{"prod":"literal-key"}}}},"setupValues":{"AUTH":"prod"},"command":"${KEY}"}]}}}"#,
            r#"{"id":1,"result":{"result":{"servers":[{"name":"a"}]}}}"#,
        ),
        (
            r#"{"id":1,"result":{"result":{"status":"setup_required","setup":{"fields":[{"options":[{"value":"literal-key"}]}]},"error":null}}}"#,
            r#"{"id":1,"result":{"result":{"status":"setup_required","error":null}}}"#,
        ),
        (
            r#"{"id":"t","method":"terminal/create","params":{"sessionId":"s","command":"pwd","env":[{"name":"A","value":"v"}],"cwd":"/w"}}"#,
            r#"{"id":"t","method":"terminal/create","params":{"sessionId":"s","command":"pwd","cwd":"/w"}}"#,
        ),
        (
            r#"{"id":"t","method":"terminal\/create","params":{"env":7}}"#,
            r#"{"id":"t","method":"terminal\/create","params":{}}"#,
        ),
        // A terminal/create frame that also carries the other places: each is withheld, the env too.
        (
            r#"{"id":"t","method":"terminal/create","result":{"result":{"token":"t"},"environment":{"secrets":[{"value":1}]}},"params":{"env":[{"name":"A","value":"v"}],"mcpServers":[{"args":[0]}],"update":{"hooks":[{"url":0}]}}}"#,
            r#"{"id":"t","method":"terminal/create","result":{"result":{},"environment":{"secrets":[{}]}},"params":{"mcpServers":[{}],"update":{"hooks":[{}]}}}"#,
        ),
        // Cloud environments whose only pre-check key is `environment` / `environments` (no secrets list, no variables).
        (
            r#"{"id":1,"result":{"environment":{"environment":{"setupScript":"s","name":"n"}}}}"#,
            r#"{"id":1,"result":{"environment":{"environment":{"name":"n"}}}}"#,
        ),
        (
            r#"{"id":1,"result":{"environments":[{"environment":{"maintenanceScript":"m","name":"n"}}]}}"#,
            r#"{"id":1,"result":{"environments":[{"environment":{"name":"n"}}]}}"#,
        ),
        (
            r#"{"id":1,"result":{"environments":[{"environmentVariables":[{"value":"v"}]}]}}"#,
            r#"{"id":1,"result":{"environments":[{"environmentVariables":[{}]}]}}"#,
        ),
        // A catalog push with HTTP servers only: `mcpServers` is the one key that tells the pre-check to read it.
        (
            r#"{"jsonrpc":"2.0","method":"_fuigo/mcp/servers_updated","params":{"mcpServers":[{"name":"r","type":"http","url":"https://m.example/?k=v"}]}}"#,
            r#"{"jsonrpc":"2.0","method":"_fuigo/mcp/servers_updated","params":{"mcpServers":[{"name":"r","type":"http"}]}}"#,
        ),
        // A setup-only MCP entry as the list handler builds it (an HTTP placeholder with no command).
        (
            r#"{"id":1,"result":{"result":{"servers":[{"name":"a","source":"local","setup":{"variables":{"AUTH":{"map":{"p":"k"}}}},"setupValues":{"AUTH":"p"},"type":"http","url":""}]}}}"#,
            r#"{"id":1,"result":{"result":{"servers":[{"name":"a","source":"local","type":"http"}]}}}"#,
        ),
        // A terminal/create method spelled with an escape; a longer method of the same prefix is not terminal/create.
        (
            r#"{"id":"t","method":"terminal/~u0063reate","params":{"env":[{"name":"A","value":"v"}]}}"#,
            r#"{"id":"t","method":"terminal/~u0063reate","params":{}}"#,
        ),
        // Cloud environment scripts and variables, each on its own.
        (
            r#"{"id":1,"result":{"environment":{"environment":{"setupScript":"s","name":"n","maintenanceScript":null},"environmentVariables":[{"key":"K","value":"v"}]}}}"#,
            r#"{"id":1,"result":{"environment":{"environment":{"name":"n"},"environmentVariables":[{"key":"K"}]}}}"#,
        ),
        // Rows that are not changed keep their own bytes, beside a row that is.
        (
            r#"{"id":1,"result":{"result":{"servers":[{ "n" : 1 },{"args":[0]},{ "m":[ 2 ] }]}}}"#,
            r#"{"id":1,"result":{"result":{"servers":[{ "n" : 1 },{},{ "m":[ 2 ] }]}}}"#,
        ),
        (
            r#"{"id":1,"result":{"result":{"hooks":[{"name":"a","command":"c"},{"url":"u","name":"b"},{"command":1,"url":[2]}],"projectTrusted":true}}}"#,
            r#"{"id":1,"result":{"result":{"hooks":[{"name":"a"},{"name":"b"},{}],"projectTrusted":true}}}"#,
        ),
        (
            r#"{"method":"_fuigo/session_notification","params":{"sessionId":"s","update":{"sessionUpdate":"hooks_changed","hooks":[{"name":"a","command":"c","url":"u"}]}}}"#,
            r#"{"method":"_fuigo/session_notification","params":{"sessionId":"s","update":{"sessionUpdate":"hooks_changed","hooks":[{"name":"a"}]}}}"#,
        ),
        (
            r#"{"method":"_fuigo/mcp/servers_updated","params":{"mcpServers":[{"env":[{"name":"A","value":"v"}]}]}}"#,
            r#"{"method":"_fuigo/mcp/servers_updated","params":{"mcpServers":[{"env":[{"name":"A"}]}]}}"#,
        ),
        // Every place in one frame, each list with five entries and the last entry of each holding a credential: no
        // place hides another, no entry hides the next.
        (
            r#"{"id":1,"result":{"result":{"token":"t","key":"k","servers":[{"n":1},{"n":2},{"n":3},{"n":4},{"args":[0],"url":0,"env":[{"n":1},{"n":2},{"n":3},{"n":4},{"value":3}]}],"hooks":[{"n":1},{"n":2},{"n":3},{"n":4},{"command":0,"url":0}]},"environments":[{"n":1},{"n":2},{"n":3},{"n":4},{"secrets":[{"n":1},{"n":2},{"n":3},{"n":4},{"value":6}]}],"environment":{"secrets":[{"n":1},{"n":2},{"n":3},{"n":4},{"value":8}]}},"params":{"mcpServers":[{"n":1},{"n":2},{"n":3},{"n":4},{"args":[0],"url":0,"env":[{"n":1},{"n":2},{"n":3},{"n":4},{"value":9}]}],"update":{"hooks":[{"n":1},{"n":2},{"n":3},{"n":4},{"command":0,"url":0}]}}}"#,
            r#"{"id":1,"result":{"result":{"servers":[{"n":1},{"n":2},{"n":3},{"n":4},{"env":[{"n":1},{"n":2},{"n":3},{"n":4},{}]}],"hooks":[{"n":1},{"n":2},{"n":3},{"n":4},{}]},"environments":[{"n":1},{"n":2},{"n":3},{"n":4},{"secrets":[{"n":1},{"n":2},{"n":3},{"n":4},{}]}],"environment":{"secrets":[{"n":1},{"n":2},{"n":3},{"n":4},{}]}},"params":{"mcpServers":[{"n":1},{"n":2},{"n":3},{"n":4},{"env":[{"n":1},{"n":2},{"n":3},{"n":4},{}]}],"update":{"hooks":[{"n":1},{"n":2},{"n":3},{"n":4},{}]}}}"#,
        ),
    ] {
        for relay in OTHER_RELAYS {
            assert_eq!(withhold_credentials(disclosure(relay), esc(frame)), esc(withheld), "{relay}: {frame}");
        }
    }
}

/// P82, response side: every row of a list is read, however long (here the credential is in the 64th entry of each).
#[test]
fn p82_withhold_credentials_reads_every_row() {
    let filler: Vec<Value> = (0..63).map(|n| json!({ "n": n })).collect();
    let with = |last: Value| {
        let mut rows = filler.clone();
        rows.push(last);
        Value::Array(rows)
    };
    let frame = json!({
        "id": 1,
        "result": {
            "result": { "servers": with(json!({ "env": with(json!({ "value": "SECRET" })), "url": "SECRET" })), "hooks": with(json!({ "url": "SECRET" })) },
            "environments": with(json!({ "secrets": with(json!({ "value": "SECRET" })) })),
        },
        "params": { "mcpServers": with(json!({ "args": ["SECRET"] })), "update": { "hooks": with(json!({ "command": "SECRET" })) } },
    })
    .to_string();
    assert_eq!(frame.matches("SECRET").count(), 6, "positive control");
    for relay in OTHER_RELAYS {
        let sent = withhold_credentials(disclosure(relay), frame.clone());
        assert!(!sent.is_empty() && !sent.contains("SECRET"), "{relay}: {sent}");
        assert_eq!(sent.matches("\"n\":62").count(), 7, "{relay}: every filler row kept");
    }
}

/// P82, response side, P81's declared LOW closed for this class: a key spelled with escapes is seen, and a duplicate
/// key on the path to a credential field, which leaves the value a reader takes up to the reader, makes the frame
/// undecidable, so it is not sent. So is a frame that names a credential key and is not a JSON object.
#[test]
fn p82_withhold_credentials_sees_through_escapes_and_fails_closed() {
    // Each escaped spelling contains none of the quoted keys the pre-check looks for: it is read because of the
    // escape, and the field is withheld.
    for (frame, withheld) in [
        (r#"{"id":1,"result":{"result":{"t~u006fken":"SECRET"}}}"#, r#"{"id":1,"result":{"result":{}}}"#),
        (r#"{"id":1,"result":{"result":{"~u006bey":"SECRET"}}}"#, r#"{"id":1,"result":{"result":{}}}"#),
        (r#"{"id":1,"r~u0065sult":{"result":{"t~u006fken":"SECRET"}}}"#, r#"{"id":1,"result":{"result":{}}}"#),
        (r#"{"id":1,"result":{"r~u0065sult":{"~u006bey":"SECRET"}}}"#, r#"{"id":1,"result":{"result":{}}}"#),
        (
            r#"{"id":1,"result":{"envir~u006fnments":[{"s~u0065crets":[{"v~u0061lue":"SECRET"}]}]}}"#,
            r#"{"id":1,"result":{"environments":[{"secrets":[{}]}]}}"#,
        ),
        (r#"{"id":1,"result":{"envir~u006fnment":{"~u0073ecrets":[{"value":"SECRET"}]}}}"#, r#"{"id":1,"result":{"environment":{"secrets":[{}]}}}"#),
        (r#"{"params":{"mcpServ~u0065rs":[{"~u0065nv":[{"value":"SECRET"}]}]}}"#, r#"{"params":{"mcpServers":[{"env":[{}]}]}}"#),
        (r#"{"id":1,"result":{"result":{"s~u0065rvers":[{"e~u006ev":[{"value":"SECRET"}]}]}}}"#, r#"{"id":1,"result":{"result":{"servers":[{"env":[{}]}]}}}"#),
        (r#"{"id":1,"result":{"result":{"h~u006foks":[{"~u0075rl":"SECRET"}]}}}"#, r#"{"id":1,"result":{"result":{"hooks":[{}]}}}"#),
        (r#"{"params":{"upd~u0061te":{"~u0068ooks":[{"comm~u0061nd":"SECRET"}]}}}"#, r#"{"params":{"update":{"hooks":[{}]}}}"#),
    ] {
        let frame = esc(frame);
        assert!(frame.contains("\\u00"), "positive control: an escape: {frame}");
        assert!(!CREDENTIAL_KEYS.iter().any(|key| frame.contains(key)), "positive control: only the escape: {frame}");
        for relay in OTHER_RELAYS {
            let sent = withhold_credentials(disclosure(relay), frame.clone());
            assert_eq!(sent, withheld, "{relay}: {frame}");
            assert!(!sent.contains("SECRET"), "{relay}: {sent}");
        }
        for relay in FLUXROUTER_RELAYS {
            assert_eq!(withhold_credentials(disclosure(relay), frame.clone()), frame, "{relay}");
        }
    }
    for undecidable in [
        // Duplicate keys at every level on the paths (one spelled with an escape: the same key once read).
        r#"{"id":1,"result":{"result":{"token":"SECRET"}},"result":{}}"#,
        r#"{"id":1,"result":{},"result":{"result":{"token":"SECRET"}}}"#,
        r#"{"id":1,"result":{"result":{"token":"SECRET"},"result":{}}}"#,
        r#"{"id":1,"result":{"result":{"token":"SECRET","token":null}}}"#,
        r#"{"id":1,"result":{"result":{"key":"SECRET","~u006bey":null}}}"#,
        r#"{"id":1,"result":{"result":{"t~u006fken":"SECRET","t~u006fken":null}}}"#,
        r#"{"id":1,"result":{"environments":[{"secrets":[{"value":"SECRET","value":null}]}]}}"#,
        r#"{"id":1,"result":{"environments":[{"secrets":[]},{"secrets":[{"value":"SECRET"}],"secrets":[]}]}}"#,
        r#"{"id":1,"result":{"environment":{"secrets":[{"value":"SECRET"}]},"environment":{}}}"#,
        r#"{"params":{"mcpServers":[{"env":[{"value":"SECRET"}]}],"mcpServers":[]}}"#,
        r#"{"params":{"mcpServers":[{"env":[{"value":"SECRET"}],"env":[]}]}}"#,
        r#"{"params":{"mcpServers":[{"env":[{"value":"SECRET","value":""}]}]}}"#,
        r#"{"params":{"mcpServers":[{"env":[{"value":"SECRET"}]}]},"params":{}}"#,
        r#"{"id":1,"result":{"result":{"servers":[{"env":[{"value":"SECRET"}]}],"servers":[]}}}"#,
        r#"{"id":1,"result":{"result":{"servers":[{"args":["SECRET"],"args":[]}]}}}"#,
        r#"{"id":1,"result":{"environments":[{"secrets":[{"value":"SECRET"}]}],"environments":[]}}"#,
        r#"{"id":1,"result":{"result":{"hooks":[{"url":"SECRET"}],"hooks":[]}}}"#,
        r#"{"id":1,"result":{"result":{"hooks":[{"command":"SECRET","command":null}]}}}"#,
        r#"{"params":{"update":{"hooks":[{"url":"SECRET"}]},"update":{}}}"#,
        r#"{"params":{"update":{"hooks":[{"url":"SECRET"}],"hooks":[]}}}"#,
        r#"{"id":1,"result":{"result":{"hooks":[{"url":"SECRET","url":null}]}}}"#,
        r#"{"id":1,"result":{"result":{"servers":[{"url":"SECRET","url":null}]}}}"#,
        r#"{"id":1,"result":{"result":{"servers":[{"setup":"SECRET","setup":null}]}}}"#,
        r#"{"id":1,"result":{"result":{"setup":"SECRET","setup":null}}}"#,
        r#"{"id":1,"result":{"result":{"servers":[{"setupValues":"SECRET","setupValues":null}]}}}"#,
        r#"{"id":1,"result":{"environments":[{"environment":{"setupScript":"SECRET","setupScript":null}}]}}"#,
        r#"{"id":"t","method":"terminal/create","params":{"env":[{"value":"SECRET"}],"env":[]}}"#,
        r#"{"id":"t","method":"terminal/create","method":"terminal/output","params":{"env":[{"value":"SECRET"}]}}"#,
        // Not a JSON object, or not JSON.
        r#"[{"id":1,"result":{"result":{"token":"SECRET"}}}]"#,
        r#"{"id":1,"result":{"result":{"token":"SECRET"}}"#,
        r#"not json "token" SECRET"#,
        r#""~u0074oken SECRET""#,
        r#"{"id":1,"result":{"result":{"t~u006fken":"SECRET"}}"#,
    ] {
        let undecidable = esc(undecidable);
        for relay in OTHER_RELAYS {
            assert_eq!(withhold_credentials(disclosure(relay), undecidable.clone()), "", "{relay}: {undecidable}");
            assert_eq!(relay_outbound_frame(&decision(relay), undecidable.clone()), "", "{relay}: {undecidable}");
        }
        for relay in FLUXROUTER_RELAYS {
            assert_eq!(relay_outbound_frame(&decision(relay), undecidable.clone()), undecidable, "{relay}");
        }
    }
}

/// P82, response side: everything that is not one of those fields at one of those places goes to every relay byte
/// for byte (the same key elsewhere is application data), including frames the pre-check reads.
#[test]
fn p82_withhold_credentials_leaves_everything_else_alone() {
    for untouched in [
        // Credential-named keys at other places, or similar keys.
        r#"{"jsonrpc":"2.0","id":1,"result":{"token":"t","key":"k","secrets":[{"value":"v"}],"env":[{"value":"v"}]}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"result":{"tokens":3,"keys":["k"],"apiKey":null,"result":{"token":"t"}}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"result":{"servers":[{"env":{"value":"v"}},{"envs":[{"value":"v"}]}]}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"environments":{"secrets":[{"value":"v"}]},"environment":[{"secrets":[{"value":"v"}]}]}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"environments":[{"secrets":"none","environmentVariables":{"key":"K","value":"v"},"environment":[{"setupScript":"s"}]}]}}"#,
        // Requests, notifications other than the MCP catalog's place, errors.
        r#"{"jsonrpc":"2.0","method":"session/update","params":{"update":{"content":{"text":"\"token\": ~u001b[31m"}},"key":"k"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"session/request_permission","params":{"toolCall":{"rawInput":{"env":[{"value":"v"}]}}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"terminal/output","params":{"env":[{"name":"A","value":"v"}]}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"terminal/createExtra","params":{"env":[{"name":"A","value":"v"}]}}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":{"env":[{"name":"A","value":"v"}],"setup":{"x":1},"result":{"status":"ok"}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"error":{"code":-1,"message":"no","data":{"result":{"token":"t"}}}}"#,
        // Duplicate keys away from the paths are not this backstop's to decide.
        r#"{"jsonrpc":"2.0","id":4,"result":{"result":{"other":{"token":1,"token":2}}}}"#,
        // A frame without the keys or an escape is not read at all.
        r#"{"jsonrpc":"2.0","id":5,"result":{"result":{"a":1}},"result":{}}"#,
        "not json",
    ] {
        let untouched = esc(untouched);
        for relay in OTHER_RELAYS.iter().chain(FLUXROUTER_RELAYS.iter()) {
            assert_eq!(withhold_credentials(disclosure(relay), untouched.clone()), untouched, "{relay}: {untouched}");
        }
    }
}

// ===== through the real relay socket session =====

/// An in-memory WebSocket pair (no network, no handshake).
async fn ws_pair() -> (
    tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
    tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
) {
    let (client, server) = tokio::io::duplex(256 * 1024);
    let client_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    let server_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(server, Role::Server, None).await;
    (client_ws, server_ws)
}

/// What the relay sends in [`p82_ws_session_relay_messages_by_relay_operator`]: credential requests in text and
/// binary frames, hidden by escapes, a duplicate key, a raw newline and a positional array, between ordinary
/// messages.
fn p82_relay_frames() -> Vec<Message> {
    let text = |s: &str| Message::Text(Utf8Bytes::from(esc(s)));
    vec![
        text(r#"{"jsonrpc":"2.0","id":1,"method":"_fuigo/auth/getBearerToken","params":{}}"#),
        text(r#"{"jsonrpc":"2.0","id":2,"method":"_fuigo/getApiKey","params":{}}"#),
        text(r#"{"jsonrpc":"2.0","id":3,"method":"_fuigo/auth/info","params":{}}"#),
        text(r#"{"jsonrpc":"2.0","id":4,"method":"_fuigo/auth/getB~u0065arerToken"}"#),
        text(r#"{"jsonrpc":"2.0","id":5,"method":"_fuigo/session/list","method":"_fuigo/getApiKey"}"#),
        text("[0,\n{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"_fuigo/getApiKey\"}\n]"),
        text(r#"[7,"_fuigo/auth/getBearerToken",{},null,null]"#),
        Message::Binary(
            "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"_fuigo/getApiKey\"}\n{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"_fuigo/session/list\",\"params\":{}}\r\n[10,\"_fuigo/getApiKey\",{},null,null]\nnot json\n"
                .as_bytes()
                .to_vec()
                .into(),
        ),
        text(r#"{"jsonrpc":"2.0","method":"_fuigo/getApiKey"}"#),
        // One JSON object whose raw newlines put a credential request on a line of its own: the agent's line reader
        // would read that line as a request if it were handed the relay's bytes.
        text("{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"_fuigo/session/list\",\"params\":{\"a\":\n{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"_fuigo/getApiKey\"}\n}}"),
        text(r#"{"jsonrpc":"2.0","id":11,"method":"session/prompt","params":{"sessionId":"s"}}"#),
    ]
}

/// Run one relay session: the relay side sends `frames`, the agent side emits `agent_frames`. Returns every line the
/// agent was handed (the last relay frame is an ordinary request with id 11, so once it is handed every earlier frame
/// has been read) and every text frame the relay side received, in order, until it has `answers` of them.
async fn p82_session(relay: &str, frames: Vec<Message>, agent_frames: Vec<String>, answers: usize) -> (Vec<String>, Vec<String>) {
    let (client_ws, server_ws) = ws_pair().await;
    let (mut server_tx, mut server_rx) = server_ws.split();
    let (to_agent_tx, mut to_agent_rx) = mpsc::unbounded_channel::<String>();
    let (agent_out_tx, mut agent_out_rx) = mpsc::unbounded_channel::<String>();
    let cancel = CancellationToken::new();
    let identity = decision(relay);
    let session = run_websocket_session(client_ws, &to_agent_tx, &mut agent_out_rx, &cancel, &identity);
    let mut handed = Vec::new();
    let relay_side = async {
        for frame in frames {
            server_tx.send(frame).await.expect("relay sends");
        }
        for frame in agent_frames {
            agent_out_tx.send(frame).unwrap();
        }
        while !handed.last().is_some_and(|line: &String| line.contains(r#""id":11"#)) {
            let line = tokio::time::timeout(Duration::from_secs(5), to_agent_rx.recv())
                .await
                .unwrap_or_else(|_| panic!("{relay}: the last relay request never reached the agent: {handed:?}"))
                .expect("the reader is running");
            handed.push(line);
        }
        let mut got = Vec::new();
        while got.len() < answers {
            match tokio::time::timeout(Duration::from_secs(5), server_rx.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => got.push(text.to_string()),
                Ok(Some(Ok(_))) => continue,
                other => panic!("{relay}: the relay side saw {other:?} after {got:?}"),
            }
        }
        // Nothing else arrives (a refusal or a frame too many would be here by now).
        if let Ok(Some(Ok(Message::Text(extra)))) = tokio::time::timeout(Duration::from_millis(300), server_rx.next()).await {
            panic!("{relay}: an extra frame reached the relay: {extra}");
        }
        cancel.cancel();
        got
    };
    let (ended, got) = tokio::time::timeout(Duration::from_secs(20), async { tokio::join!(session, relay_side) })
        .await
        .expect("test timed out");
    assert_eq!(ended.expect("session ends cleanly on cancel"), SessionEndReason::Normal, "{relay}");
    assert!(to_agent_rx.try_recv().is_err(), "{relay}: nothing after the last request");
    (handed, got)
}

/// P82 hostile, through the real socket session (reader and writer): a relay that is not FluxRouter-operated gets an
/// error for every credential request, however it is sent, and the agent is handed none of them, only the ordinary
/// messages, each as one line; the bytes written to the relay socket carry no credential, also for the agent's
/// answers to a LOCAL client's credential request (leader mode). A FluxRouter relay: unchanged, byte for byte.
#[tokio::test]
async fn p82_ws_session_relay_messages_by_relay_operator() {
    let local_answers: Vec<String> = all_credential_frames().into_iter().map(|(_, frame, _)| frame).collect();
    let withheld_answers: Vec<String> = all_credential_frames().into_iter().map(|(_, _, withheld)| withheld).collect();
    for relay in ["wss://relay.example/ws", "ws://api.fluxrouter.ai/ws/relay", ""] {
        let (handed, got) = p82_session(relay, p82_relay_frames(), local_answers.clone(), 5 + local_answers.len()).await;
        assert_eq!(
            handed,
            [
                r#"{"jsonrpc":"2.0","id":3,"method":"_fuigo/auth/info","params":{}}"#,
                r#"{"jsonrpc":"2.0","id":9,"method":"_fuigo/session/list","params":{}}"#,
                r#"{"jsonrpc":"2.0","id":10,"method":"_fuigo/session/list","params":{"a":{"jsonrpc":"2.0","id":12,"method":"_fuigo/getApiKey"}}}"#,
                r#"{"jsonrpc":"2.0","id":11,"method":"session/prompt","params":{"sessionId":"s"}}"#,
            ],
            "{relay}: only the ordinary messages reach the agent, each as the one line that was decided on"
        );
        assert!(handed.iter().all(|line| !line.contains('\n')), "{relay}: {handed:?}");
        let (refusals, answers): (Vec<String>, Vec<String>) = got.into_iter().partition(|frame| frame.contains("\"error\""));
        // The refusals arrive in the order the relay sent the requests (id 5's last `method` is the credential one;
        // ids 6, 7 and 10 are arrays and are dropped unanswered, as is the notification).
        let refused: Vec<(Value, &str)> = vec![
            (json!(1), "_fuigo/auth/getBearerToken"),
            (json!(2), "_fuigo/getApiKey"),
            (json!(4), "_fuigo/auth/getBearerToken"),
            (json!(5), "_fuigo/getApiKey"),
            (json!(8), "_fuigo/getApiKey"),
        ];
        assert_eq!(refusals.len(), refused.len(), "{relay}: {refusals:?}");
        for (answer, (id, method)) in refusals.iter().zip(&refused) {
            assert_refusal(answer, id, method);
        }
        let expected: Vec<String> = withheld_answers.iter().map(|w| relay_outbound_frame(&decision(relay), w.clone())).collect();
        assert_eq!(answers, expected, "{relay}: the local answers, without their credentials");
        for frame in refusals.iter().chain(&answers) {
            for secret in [BEARER, API_KEY, ENV_SECRET, MCP_SECRET] {
                assert!(!frame.contains(secret), "{relay}: {secret} reached the relay: {frame}");
            }
        }
    }
    for relay in FLUXROUTER_RELAYS {
        let (handed, got) = p82_session(relay, p82_relay_frames(), local_answers.clone(), local_answers.len()).await;
        // Every text frame byte for byte, every binary frame as one message, in order; no refusal.
        let mut expected: Vec<String> = Vec::new();
        for frame in p82_relay_frames() {
            match frame {
                Message::Text(text) => expected.push(text.to_string()),
                Message::Binary(bin) => expected.push(String::from_utf8(bin.to_vec()).unwrap().trim_end_matches(['\r', '\n']).to_owned()),
                _ => unreachable!(),
            }
        }
        assert_eq!(handed, expected, "{relay}");
        assert_eq!(got, local_answers, "{relay}: every answer byte for byte");
    }
}

/// P82: when the agent side is gone, a binary frame ends the session, for every relay, as a text frame does: the reader
/// stops instead of waiting for the next frame.
#[tokio::test]
async fn p82_ws_session_ends_when_the_agent_is_gone_after_a_binary_frame() {
    for relay in ["wss://relay.example/ws", FLUXROUTER_RELAYS[0]] {
        let (client_ws, server_ws) = ws_pair().await;
        let (mut server_tx, _server_rx) = server_ws.split();
        let (to_agent_tx, to_agent_rx) = mpsc::unbounded_channel::<String>();
        drop(to_agent_rx);
        let (_agent_out_tx, mut agent_out_rx) = mpsc::unbounded_channel::<String>();
        let cancel = CancellationToken::new();
        let identity = decision(relay);
        let frame = br#"{"jsonrpc":"2.0","id":1,"method":"_fuigo/session/list","params":{}}"#.to_vec();
        server_tx.send(Message::Binary(frame.into())).await.expect("relay sends");
        let ended = tokio::time::timeout(
            Duration::from_secs(5),
            run_websocket_session(client_ws, &to_agent_tx, &mut agent_out_rx, &cancel, &identity),
        )
        .await
        .unwrap_or_else(|_| panic!("{relay}: the reader kept waiting after the agent was gone"));
        assert_eq!(ended.expect("no error"), SessionEndReason::Normal, "{relay}");
    }
}

/// P82 source pins: the relay reader gates every message of a relay that is not FluxRouter-operated (text and
/// binary) and keeps a FluxRouter relay's bytes; the writer sends the refusals through the socket's one text writer,
/// after the filter; the filter withholds credentials before anything else.
#[test]
fn p82_relay_reader_and_writer_are_gated() {
    let src = include_str!("relay.rs");
    let prod = src.split("\n#[cfg(test)]").next().unwrap();
    let flat = prod.split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(flat.matches("relay_credentials::gate_relay_message(&json)").count(), 2, "text and binary");
    assert_eq!(flat.matches("ws_outbound.send(Message::Text(").count(), 1, "one text writer");
    assert_eq!(flat.matches("to_agent_tx.send(").count(), 3, "text, binary gated, binary as before");
    for pinned in [
        "let relay_is_fluxrouter = identity.disclosure.is_permitted();",
        "let outbound = if relay_is_fluxrouter { if declare_relay_client_capabilities(&mut json) { json.to_string() } \
         else { trimmed_end.to_string() } } else {",
        "declare_relay_client_capabilities(&mut json); match super::relay_credentials::gate_relay_message(&json) { \
         super::relay_credentials::RelayMessage::Forward(line) => line, super::relay_credentials::RelayMessage::Refuse(answer) \
         => { let _ = refusal_tx.send(answer); continue; } super::relay_credentials::RelayMessage::Drop => continue, } };",
        "if !relay_is_fluxrouter { // P82: the agent reads this frame line by line;",
        "let mut agent_gone = false; for line in s.split('\\n') { let Ok(json) = \
         serde_json::from_str::<serde_json::Value>(line) else { continue; };",
        "Some(refused) = refusal_rx.recv() => refused,",
        "let msg = relay_outbound_frame(identity, msg); if !msg.is_empty() && let Err(e) = \
         ws_outbound.send(Message::Text(Utf8Bytes::from(msg))).await",
        "pub(crate) fn relay_outbound_frame(identity: &RelayBodyIdentity, msg: String) -> String { let msg = \
         super::relay_credentials::withhold_credentials(identity.disclosure, msg); if identity.disclosure.is_permitted()",
    ] {
        assert!(flat.contains(pinned), "{pinned}");
    }
    // The gate's own first statements.
    let own = include_str!("relay_credentials.rs");
    let own = own.split("\n#[cfg(test)]").next().unwrap().split_whitespace().collect::<Vec<_>>().join(" ");
    for pinned in [
        "if disclosure.is_permitted() || !(CREDENTIAL_KEYS.iter().any(|key| msg.contains(key)) || msg.contains(\"\\\\u\")) { return msg; }",
        "let Some(object) = message.as_object() else {",
        "Ok(None) => msg, Err(error) => {",
    ] {
        assert!(own.contains(pinned), "{pinned}");
    }
}
