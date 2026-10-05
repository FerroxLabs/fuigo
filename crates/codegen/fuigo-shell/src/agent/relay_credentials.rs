//! P82: a relay that is not FluxRouter-operated is never handed a credential over the bridge.
//!
//! When a relay is bridged to the agent (`agent/app.rs`: headless-relay mode, and leader mode, where the relay also
//! receives the answers to the local IPC clients' requests), a message the relay sends reaches the agent as an ACP
//! message, and every line the agent writes goes to the relay socket. Before P82 a relay could ask the agent for the
//! session bearer (`fuigo/auth/getBearerToken`) or the environment's `FUIGO_API_KEY` (`fuigo/getApiKey`), and the
//! cloud-environment responses, the MCP catalog, the hook list and the agent's own `terminal/create` requests carried
//! secret values to it.
//!
//! Who may receive a credential is decided on the URL the relay socket is opened to, by the rule the handshake and
//! P77 / P81 use (`IdentityDisclosure::for_websocket_destination`: `wss` to the FluxRouter API host). A
//! FluxRouter-operated relay is unchanged, byte for byte. Any other relay:
//!
//! * **request side** ([`gate_relay_message`]): a request for a credential is answered with a JSON-RPC error on the
//!   relay socket and never reaches the agent, so the credential is never produced for it. A message that is not a
//!   JSON object is not handed to the agent (the agent's ACP reader also accepts a positional array as a request).
//!   Every other message is handed to the agent as the serialisation of the value this gate decided on (one line, no
//!   duplicate keys, no escapes), never as the relay's own bytes, so the agent cannot read it differently;
//! * **response side** ([`withhold_credentials`], a backstop in the socket writer): a frame never carries a
//!   credential field to such a relay, whoever asked (in leader mode, a local client's `getBearerToken` answer is
//!   copied to the relay). The frame is read strictly: when its credential fields cannot be decided (not a JSON
//!   object, or a duplicate key on the path to them) it is not sent at all.
//!
//! The local stdio / IPC clients never pass through this module: the IPC copy of a line is taken before the relay
//! writer (`agent/app.rs`), and relay sync (`relay/sync.rs`) answers the relay itself and forwards nothing to an agent.
use fuigo_extra_ca::fluxrouter::IdentityDisclosure;
use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, Visitor};
use serde_json::value::RawValue;
use tracing::warn;

/// The ACP extension methods whose answer IS a credential, as the agent's routers name them: the wire name without
/// the ACP `_` prefix (`agent-client-protocol` strips it before the agent's `ext_method` sees the name).
///
/// * `fuigo/auth/getBearerToken` (`extensions/auth.rs`): the session bearer, or a static key the user supplied;
/// * `fuigo/getApiKey` (`extensions/auth.rs`): the environment's `FUIGO_API_KEY`.
pub(crate) const CREDENTIAL_METHODS: [&str; 2] = ["fuigo/auth/getBearerToken", "fuigo/getApiKey"];

/// The JSON-RPC error code a refused credential request is answered with: `-32600` (invalid request), as
/// `acp_error::invalid_request`, with the same typed `data`.
const REFUSED_CODE: i64 = -32600;

/// What one message a relay that is not FluxRouter-operated sent becomes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RelayMessage {
    /// Hand this line to the agent.
    Forward(String),
    /// Not handed to the agent; this JSON-RPC error goes back to the relay.
    Refuse(String),
    /// Not handed to the agent, and nothing to answer.
    Drop,
}

/// Whether `method` names a credential method, with the ACP `_` prefix or without it (or with several: refusing a
/// name the agent would not route anyway costs nothing).
fn is_credential_method(method: &str) -> bool {
    CREDENTIAL_METHODS.contains(&method.trim_start_matches('_'))
}

/// The error a refused request is answered with, carrying the request's own `id`.
fn refusal(id: &serde_json::Value, method: &str) -> String {
    let message = format!(
        "{method} is not available through this relay: credentials are handed only to a FluxRouter-operated relay"
    );
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": REFUSED_CODE,
            "message": message,
            "data": crate::acp_error::error_data(crate::acp_error::AcpErrorKind::InvalidRequest, message.clone()),
        },
    })
    .to_string()
}

/// P82, request side: what one message from a relay that is NOT FluxRouter-operated becomes. `message` is the value
/// the relay reader parsed (escapes decoded; of duplicate keys, the last, which is then the only one forwarded).
///
/// * Not a JSON object: dropped. Batches are not served by the agent, and its reader would take a positional array
///   (`[id, method, params, …]`) as a request, which no check on object keys would see.
/// * A request for a credential method: refused with a JSON-RPC error carrying its `id`; a notification for one
///   (no `id`) is dropped.
/// * Anything else: forwarded as `message`'s own serialisation, so the agent reads exactly what was decided on.
///
/// A FluxRouter-operated relay never reaches this function: `relay.rs` hands its bytes to the agent as they are.
pub(crate) fn gate_relay_message(message: &serde_json::Value) -> RelayMessage {
    let Some(object) = message.as_object() else {
        warn!("relay: a message that is not a JSON object was not handed to the agent");
        return RelayMessage::Drop;
    };
    let Some(method) = object
        .get("method")
        .and_then(|method| method.as_str())
        .filter(|method| is_credential_method(method))
    else {
        return RelayMessage::Forward(message.to_string());
    };
    warn!(method, "relay: a request for a credential from a relay that is not FluxRouter-operated was refused");
    match object.get("id") {
        Some(id) => RelayMessage::Refuse(refusal(id, method)),
        None => RelayMessage::Drop,
    }
}

/// The quoted keys at which the backstop reads a frame: the credential fields themselves, and the lists that hold
/// the others. A key spelled with escapes can only be spelled with `\u` (none of these keys, nor the keys on the path
/// to them, has a character with a shorter escape), and a frame with `\u` anywhere is read too.
const CREDENTIAL_KEYS: [&str; 10] = [
    "\"token\"",
    "\"key\"",
    "\"secrets\"",
    "\"servers\"",
    "\"mcpServers\"",
    "\"hooks\"",
    "\"setup\"",
    "\"env\"",
    "\"environments\"",
    "\"environment\"",
];
/// The fields of an extension method's result envelope (`ExtMethodResult`: `result.result`) that hold a credential:
/// `getBearerToken`'s `token`, `getApiKey`'s `key`.
const CREDENTIAL_RESULT_KEYS: [&str; 2] = ["token", "key"];
/// The fields of an MCP catalog entry (`McpServerEntry`) that can carry a credential: a stdio server's command and
/// arguments and an HTTP server's URL, all with `${VAR}` already expanded (a relay that may write a server's
/// configuration could otherwise read any variable back through them), and the setup schema with the values saved for
/// it (a variable's `map` holds the literal value each choice selects). `env[]` values are withheld one by one, keeping
/// the names.
const MCP_SERVER_KEYS: [&str; 5] = ["command", "args", "url", "setup", "setupValues"];
/// The setup schema `fuigo/mcp/auth_trigger` answers with when a server still needs setup (`result.result.setup`).
const MCP_SETUP_RESULT_KEYS: [&str; 1] = ["setup"];
/// The fields of a hook (`HookInfo`) that can carry a credential: the command line and the URL it runs, as written in
/// the hook's configuration (a literal token in either is sent as it is).
const HOOK_KEYS: [&str; 2] = ["command", "url"];

/// P82, response side: what the relay socket writer sends for one outbound frame. A FluxRouter-operated relay gets
/// `msg` itself. Any other relay gets it without these fields (whatever their value):
///
/// * `result.result.token`, `result.result.key`: the result envelope of `fuigo/auth/getBearerToken` and
///   `fuigo/getApiKey`. A relay's own request for them is refused by [`gate_relay_message`]; these are the answers to
///   a LOCAL client's request, which leader mode copies to the relay;
/// * of every cloud environment in `result.environments[]` (`fuigo/cloud/env/list`) and `result.environment`
///   (`create`, `update`): the `value` of every `secrets[]` and `environmentVariables[]` entry (the names stay; the
///   backend calls the latter non-secret, but nothing enforces that), and the `setupScript` / `maintenanceScript` of
///   its `environment` (scripts the user wrote, which can hold a literal token);
/// * of every MCP server in `result.result.servers[]` (`fuigo/mcp/list`) and `params.mcpServers[]` (the
///   `fuigo/mcp/servers_updated` notification): the `value` of every `env[]` entry (a stdio server's environment,
///   expanded, which is where a server's API key lives; the variable's name stays), and [`MCP_SERVER_KEYS`];
///   `result.result.setup` (`fuigo/mcp/auth_trigger`);
/// * `params.env` of the agent's own `terminal/create` requests (the session's environment, from settings and a trusted
///   `.envrc`; in leader mode a local client's terminal request is copied to the relay). The whole list goes: an entry
///   without its value is not a valid `EnvVariable`, so a relay that runs the terminal runs it without them;
/// * of every hook in `result.result.hooks[]` (`fuigo/hooks/list`) and `params.update.hooks[]` (the `hooks_changed`
///   session notification): `command` and `url`. The hook's name, event, type, matcher and state stay.
///
/// A frame is read only if it contains one of [`CREDENTIAL_KEYS`] or an escape (`\u`), and then strictly: when it is
/// not a JSON object, or has a duplicate key at a level on those paths, which value a reader takes is the reader's
/// choice, so it is not sent (an empty string). Everything not on those paths is carried as raw text.
pub(crate) fn withhold_credentials(disclosure: IdentityDisclosure, msg: String) -> String {
    if disclosure.is_permitted() || !(CREDENTIAL_KEYS.iter().any(|key| msg.contains(key)) || msg.contains("\\u")) {
        return msg;
    }
    match withhold_frame_credentials(&msg) {
        Ok(Some(rewritten)) => rewritten,
        Ok(None) => msg,
        Err(error) => {
            warn!(%error, "relay: an outbound frame whose credential fields cannot be decided was not sent to this relay");
            String::new()
        }
    }
}

/// A JSON object read ONE level deep (keys in order, values as raw text) that refuses a duplicate key.
struct StrictObject(indexmap::IndexMap<String, Box<RawValue>>);

impl<'de> Deserialize<'de> for StrictObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictObject;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object without duplicate keys")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<StrictObject, A::Error> {
                let mut object = indexmap::IndexMap::new();
                while let Some((key, value)) = map.next_entry::<String, Box<RawValue>>()? {
                    if object.contains_key(&key) {
                        return Err(A::Error::custom(format!("duplicate key {key:?}")));
                    }
                    object.insert(key, value);
                }
                Ok(StrictObject(object))
            }
        }
        deserializer.deserialize_map(StrictVisitor)
    }
}

/// `raw` read as a [`StrictObject`]; `Ok(None)` when it is a JSON value of another kind (nothing on a path there).
fn strict_object(raw: &RawValue) -> serde_json::Result<Option<StrictObject>> {
    if !raw.get().starts_with('{') {
        return Ok(None);
    }
    serde_json::from_str(raw.get()).map(Some)
}

/// Apply `edit` to the object at `parent[key]`; write it back if `edit` changed it.
fn edit_in(
    parent: &mut StrictObject,
    key: &str,
    edit: impl FnOnce(&mut StrictObject) -> serde_json::Result<bool>,
) -> serde_json::Result<bool> {
    let Some(raw) = parent.0.get(key) else {
        return Ok(false);
    };
    let Some(mut child) = strict_object(raw)? else {
        return Ok(false);
    };
    if !edit(&mut child)? {
        return Ok(false);
    }
    parent.0.insert(key.to_owned(), serde_json::value::to_raw_value(&child.0)?);
    Ok(true)
}

/// Apply `edit` to every object in the array at `parent[key]`; write the array back if `edit` changed one.
fn edit_rows(
    parent: &mut StrictObject,
    key: &str,
    mut edit: impl FnMut(&mut StrictObject) -> serde_json::Result<bool>,
) -> serde_json::Result<bool> {
    let Some(raw) = parent.0.get(key) else {
        return Ok(false);
    };
    if !raw.get().starts_with('[') {
        return Ok(false);
    }
    let mut rows: Vec<Box<RawValue>> = serde_json::from_str(raw.get())?;
    let mut changed = false;
    for row in &mut rows {
        if let Some(mut object) = strict_object(row)?
            && edit(&mut object)?
        {
            *row = serde_json::value::to_raw_value(&object.0)?;
            changed = true;
        }
    }
    if changed {
        parent.0.insert(key.to_owned(), serde_json::value::to_raw_value(&rows)?);
    }
    Ok(changed)
}

/// Remove `value` from every object in `parent[list]` (a secret's or an environment variable's value; its name stays).
fn withhold_values(parent: &mut StrictObject, list: &str) -> serde_json::Result<bool> {
    edit_rows(parent, list, |entry| Ok(entry.0.shift_remove("value").is_some()))
}

/// The scripts of a cloud environment (`SandboxEnvironment`, camel case).
const ENVIRONMENT_SCRIPT_KEYS: [&str; 2] = ["setupScript", "maintenanceScript"];

/// Remove what can carry a credential from a `SandboxEnvironmentWithMetadata`: the values of its secrets and its
/// variables, and its environment's scripts.
fn withhold_environment_secrets(with_metadata: &mut StrictObject) -> serde_json::Result<bool> {
    let secrets = withhold_values(with_metadata, "secrets")?;
    let variables = withhold_values(with_metadata, "environmentVariables")?;
    let scripts = edit_in(with_metadata, "environment", |environment| {
        Ok(withhold_keys(environment, &ENVIRONMENT_SCRIPT_KEYS))
    })?;
    Ok(secrets | variables | scripts)
}

/// Remove every one of `keys` from `object`, whatever its value.
fn withhold_keys(object: &mut StrictObject, keys: &[&str]) -> bool {
    let mut withheld = false;
    for key in keys {
        withheld |= object.0.shift_remove(*key).is_some();
    }
    withheld
}

/// Remove what can carry a credential from every MCP server in `parent[list]`.
fn withhold_mcp_servers(parent: &mut StrictObject, list: &str) -> serde_json::Result<bool> {
    edit_rows(parent, list, |server| {
        let withheld = withhold_keys(server, &MCP_SERVER_KEYS);
        Ok(withhold_values(server, "env")? | withheld)
    })
}

/// Remove what can carry a credential from every hook in `parent[list]`.
fn withhold_hooks(parent: &mut StrictObject, list: &str) -> serde_json::Result<bool> {
    edit_rows(parent, list, |hook| Ok(withhold_keys(hook, &HOOK_KEYS)))
}

/// `frame` without its credential fields; `None` when it has none (the frame is sent as it is).
fn withhold_frame_credentials(frame: &str) -> serde_json::Result<Option<String>> {
    let mut frame: StrictObject = serde_json::from_str(frame)?;
    let mut withheld = edit_in(&mut frame, "result", |result| {
        let mut withheld = edit_in(result, "result", |envelope| {
            // `getBearerToken`, `getApiKey`; `fuigo/mcp/auth_trigger`.
            let mut withheld = withhold_keys(envelope, &CREDENTIAL_RESULT_KEYS);
            withheld |= withhold_keys(envelope, &MCP_SETUP_RESULT_KEYS);
            // `fuigo/mcp/list`, `fuigo/hooks/list`.
            withheld |= withhold_mcp_servers(envelope, "servers")?;
            withheld |= withhold_hooks(envelope, "hooks")?;
            Ok(withheld)
        })?;
        // `fuigo/cloud/env/list`: every row; `create`, `update`: the one environment.
        withheld |= edit_rows(result, "environments", withhold_environment_secrets)?;
        withheld |= edit_in(result, "environment", withhold_environment_secrets)?;
        Ok(withheld)
    })?;
    // The agent's `terminal/create` requests to the client.
    let terminal_create = frame
        .0
        .get("method")
        .is_some_and(|method| serde_json::from_str::<String>(method.get()).is_ok_and(|method| method == "terminal/create"));
    if terminal_create {
        withheld |= edit_in(&mut frame, "params", |params| Ok(params.0.shift_remove("env").is_some()))?;
    }
    // `fuigo/mcp/servers_updated`; the `hooks_changed` session notification.
    withheld |= edit_in(&mut frame, "params", |params| {
        let withheld = withhold_mcp_servers(params, "mcpServers")?;
        Ok(edit_in(params, "update", |update| withhold_hooks(update, "hooks"))? | withheld)
    })?;
    if !withheld {
        return Ok(None);
    }
    serde_json::to_string(&frame.0).map(Some)
}

#[cfg(test)]
#[path = "relay_credentials_tests.rs"]
mod tests;
