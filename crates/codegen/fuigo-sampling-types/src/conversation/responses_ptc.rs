//! OpenAI Responses "Programmatic Tool Calling" (PTC) support for the conversation layer.
//!
//! Wire contract: `docs/ptc-contract.md`.
//!
//! The vendored `async-openai` `rs::OutputItem` / `rs::Item` enums are `#[serde(tag = "type")]` with no catch-all, so the
//! PTC item types (`program`, `program_output`) cannot pass through them.
//! They ride a *typed carrier* instead: an `rs::CustomToolCall` whose `name` is one of the reserved
//! [`PROGRAM_CARRIER_NAME`] / [`PROGRAM_OUTPUT_CARRIER_NAME`] values and whose `input` is the JSON of the real item.
//! The sampler transcodes wire items into carriers as the SSE frames arrive (`fuigo_sampler::stream::responses_ptc`),
//! this module turns carriers into [`BackendToolKind::Program`] / [`BackendToolKind::ProgramOutput`] conversation items
//! and back, and [`patch_request_body`] rewrites the carriers into real wire items on the serialized request.
//!
//! Everything here is inert when no PTC item or tool is present: [`patch_request_body`] is a byte-for-byte no-op.

use serde::{Deserialize, Serialize};

use crate::rs;

use super::BackendToolKind;

/// Wire `type` of the hosted PTC tool entry and the name reported for program progress events.
pub const PTC_TOOL_TYPE: &str = "programmatic_tool_calling";

/// Reserved `custom_tool_call.name` of the carrier for a `program` item.
pub const PROGRAM_CARRIER_NAME: &str = "__fuigo_ptc_program";
/// Reserved `custom_tool_call.name` of the carrier for a `program_output` item.
pub const PROGRAM_OUTPUT_CARRIER_NAME: &str = "__fuigo_ptc_program_output";

/// The `allowed_callers` value stamped on every client function tool when PTC is on: the model may call it directly or from a program.
pub const ALLOWED_CALLERS_BOTH: [&str; 2] = ["direct", "programmatic"];

/// A `program` output item: the JavaScript the model wrote for the hosted runtime.
///
/// `call_ids` is Fuigo-only bookkeeping (not a wire field): the `call_id`s of the client `function_call`s this program produced,
/// read off their `caller.caller_id` when the response arrived.
/// Replay uses it to re-attach `caller` to those calls and to their `function_call_output`s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramItem {
    pub id: String,
    pub call_id: String,
    pub code: String,
    /// Opaque replay fingerprint; the API requires it back verbatim.
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_ids: Vec<String>,
}

/// A `program_output` output item: the terminal result of a program run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramOutputItem {
    pub id: String,
    pub call_id: String,
    pub result: String,
    /// `completed` or `incomplete`.
    pub status: String,
}

impl ProgramOutputItem {
    pub fn is_completed(&self) -> bool {
        self.status == "completed"
    }
}

/// The raw-JSON hosted tool entry that enables the runtime.
pub fn tool_entry() -> serde_json::Value {
    serde_json::json!({ "type": PTC_TOOL_TYPE })
}

/// The carrier payload for a `program` item (what goes into `custom_tool_call.input`).
fn program_payload(p: &ProgramItem) -> serde_json::Value {
    serde_json::json!({ "code": p.code, "fingerprint": p.fingerprint, "call_ids": p.call_ids })
}

/// The carrier payload for a `program_output` item.
fn program_output_payload(o: &ProgramOutputItem) -> serde_json::Value {
    serde_json::json!({ "result": o.result, "status": o.status })
}

/// A carrier item as raw JSON: the shape both the SSE transcoder emits and [`patch_request_body`] recognizes.
pub fn carrier_json(
    id: &str,
    call_id: &str,
    name: &str,
    payload: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "type": "custom_tool_call",
        "id": id,
        "call_id": call_id,
        "name": name,
        "input": payload.to_string(),
    })
}

/// Builds the carrier JSON for a wire `program` item, attaching the `call_ids` it produced.
/// `None` when the item lacks a required field.
pub fn program_wire_to_carrier(
    item: &serde_json::Value,
    call_ids: &[String],
) -> Option<serde_json::Value> {
    let p = ProgramItem {
        id: item.get("id")?.as_str()?.to_owned(),
        call_id: item.get("call_id")?.as_str()?.to_owned(),
        code: item
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned(),
        fingerprint: item
            .get("fingerprint")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned(),
        call_ids: call_ids.to_vec(),
    };
    Some(carrier_json(
        &p.id,
        &p.call_id,
        PROGRAM_CARRIER_NAME,
        &program_payload(&p),
    ))
}

/// Builds the carrier JSON for a wire `program_output` item.
pub fn program_output_wire_to_carrier(item: &serde_json::Value) -> Option<serde_json::Value> {
    let o = ProgramOutputItem {
        id: item.get("id")?.as_str()?.to_owned(),
        call_id: item.get("call_id")?.as_str()?.to_owned(),
        result: item
            .get("result")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned(),
        status: item
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("completed")
            .to_owned(),
    };
    Some(carrier_json(
        &o.id,
        &o.call_id,
        PROGRAM_OUTPUT_CARRIER_NAME,
        &program_output_payload(&o),
    ))
}

/// Whether a typed custom tool call is a PTC carrier.
pub fn is_carrier(ct: &rs::CustomToolCall) -> bool {
    ct.name == PROGRAM_CARRIER_NAME || ct.name == PROGRAM_OUTPUT_CARRIER_NAME
}

/// The conversation item a carrier stands for; `None` for a real custom tool call.
pub fn carrier_to_backend_kind(ct: &rs::CustomToolCall) -> Option<BackendToolKind> {
    let payload: serde_json::Value = serde_json::from_str(&ct.input).ok()?;
    match ct.name.as_str() {
        PROGRAM_CARRIER_NAME => Some(BackendToolKind::Program(ProgramItem {
            id: ct.id.clone(),
            call_id: ct.call_id.clone(),
            code: payload
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
            fingerprint: payload
                .get("fingerprint")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
            call_ids: payload
                .get("call_ids")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
        })),
        PROGRAM_OUTPUT_CARRIER_NAME => Some(BackendToolKind::ProgramOutput(ProgramOutputItem {
            id: ct.id.clone(),
            call_id: ct.call_id.clone(),
            result: payload
                .get("result")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
            status: payload
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("completed")
                .to_owned(),
        })),
        _ => None,
    }
}

/// The structured payload reported on the `BackendToolCallCompleted` event for a carrier.
/// `status` is present on program output so the ACP layer can mark an `incomplete` run as failed.
pub fn carrier_result_payload(kind: &BackendToolKind) -> Option<serde_json::Value> {
    match kind {
        BackendToolKind::Program(p) => Some(serde_json::json!({
            "type": "program",
            "id": p.id,
            "call_id": p.call_id,
            "code": p.code,
        })),
        BackendToolKind::ProgramOutput(o) => Some(serde_json::json!({
            "type": "program_output",
            "id": o.id,
            "call_id": o.call_id,
            "result": o.result,
            "status": if o.is_completed() { "completed" } else { "failed" },
        })),
        _ => None,
    }
}

/// The typed input items that replay a program item: one carrier, which [`patch_request_body`] rewrites into the wire `program`.
pub fn program_input_items(p: &ProgramItem) -> Vec<rs::InputItem> {
    carrier_input_item(carrier_json(
        &p.id,
        &p.call_id,
        PROGRAM_CARRIER_NAME,
        &program_payload(p),
    ))
}

/// The typed input items that replay a program output item.
pub fn program_output_input_items(o: &ProgramOutputItem) -> Vec<rs::InputItem> {
    carrier_input_item(carrier_json(
        &o.id,
        &o.call_id,
        PROGRAM_OUTPUT_CARRIER_NAME,
        &program_output_payload(o),
    ))
}

/// `rs::CustomToolCall` is `#[non_exhaustive]`, so the carrier is built through serde rather than a struct literal.
fn carrier_input_item(json: serde_json::Value) -> Vec<rs::InputItem> {
    match serde_json::from_value::<rs::CustomToolCall>(json) {
        Ok(ct) => vec![rs::InputItem::Item(rs::Item::CustomToolCall(ct))],
        Err(err) => {
            tracing::error!(error = %err, "PTC carrier failed to build; the program item is dropped from the replay");
            Vec::new()
        }
    }
}

/// Human-readable summary for token estimation and text extraction.
pub fn text_summary(kind: &BackendToolKind) -> Option<String> {
    fn preview(s: &str) -> String {
        let mut end = s.len().min(100);
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        if end < s.len() {
            format!("{}...", &s[..end])
        } else {
            s.to_owned()
        }
    }
    match kind {
        BackendToolKind::Program(p) => {
            Some(format!("[backend {PTC_TOOL_TYPE}] {}", preview(&p.code)))
        }
        BackendToolKind::ProgramOutput(o) => Some(format!(
            "[backend {PTC_TOOL_TYPE} output ({})] {}",
            o.status,
            preview(&o.result)
        )),
        _ => None,
    }
}

/// Rewrites a serialized Responses request body for PTC. Byte-for-byte no-op when nothing PTC is present.
///
/// 1. Carrier `custom_tool_call` items in `input` become wire `program` / `program_output` items.
/// 2. `function_call` / `function_call_output` items whose `call_id` a program produced get
///    `caller: {type: "program", caller_id}` so the server can resume the paused program.
/// 3. When the `programmatic_tool_calling` tool is present, every `function` / `custom` tool without an explicit
///    `allowed_callers` is stamped with `["direct", "programmatic"]`.
pub fn patch_request_body(body: &mut serde_json::Value) {
    patch_input_items(body);
    patch_allowed_callers(body);
}

fn patch_input_items(body: &mut serde_json::Value) {
    let Some(input) = body.get_mut("input").and_then(|v| v.as_array_mut()) else {
        return;
    };
    // call_id -> program call_id
    let mut producers: Vec<(String, String)> = Vec::new();
    for item in input.iter_mut() {
        let is_carrier = item.get("type").and_then(|t| t.as_str()) == Some("custom_tool_call")
            && matches!(
                item.get("name").and_then(|n| n.as_str()),
                Some(PROGRAM_CARRIER_NAME) | Some(PROGRAM_OUTPUT_CARRIER_NAME)
            );
        if !is_carrier {
            continue;
        }
        let Ok(ct) = serde_json::from_value::<rs::CustomToolCall>(item.clone()) else {
            continue;
        };
        match carrier_to_backend_kind(&ct) {
            Some(BackendToolKind::Program(p)) => {
                for call_id in &p.call_ids {
                    producers.push((call_id.clone(), p.call_id.clone()));
                }
                *item = serde_json::json!({
                    "type": "program",
                    "id": p.id,
                    "call_id": p.call_id,
                    "code": p.code,
                    "fingerprint": p.fingerprint,
                });
            }
            Some(BackendToolKind::ProgramOutput(o)) => {
                *item = serde_json::json!({
                    "type": "program_output",
                    "id": o.id,
                    "call_id": o.call_id,
                    "result": o.result,
                    "status": o.status,
                });
            }
            _ => {}
        }
    }
    if producers.is_empty() {
        return;
    }
    for item in input.iter_mut() {
        let Some(kind) = item.get("type").and_then(|t| t.as_str()) else {
            continue;
        };
        if kind != "function_call" && kind != "function_call_output" {
            continue;
        }
        if item.get("caller").is_some() {
            continue;
        }
        let Some(call_id) = item.get("call_id").and_then(|c| c.as_str()) else {
            continue;
        };
        let Some((_, program_call_id)) = producers.iter().find(|(c, _)| c == call_id) else {
            continue;
        };
        let caller = serde_json::json!({ "type": "program", "caller_id": program_call_id });
        if let Some(obj) = item.as_object_mut() {
            obj.insert("caller".to_owned(), caller);
        }
    }
}

fn patch_allowed_callers(body: &mut serde_json::Value) {
    let Some(tools) = body.get_mut("tools").and_then(|v| v.as_array_mut()) else {
        return;
    };
    let ptc_on = tools
        .iter()
        .any(|t| t.get("type").and_then(|v| v.as_str()) == Some(PTC_TOOL_TYPE));
    if !ptc_on {
        return;
    }
    for tool in tools.iter_mut() {
        let eligible = matches!(
            tool.get("type").and_then(|v| v.as_str()),
            Some("function") | Some("custom")
        );
        if !eligible || tool.get("allowed_callers").is_some() {
            continue;
        }
        if let Some(obj) = tool.as_object_mut() {
            obj.insert(
                "allowed_callers".to_owned(),
                serde_json::json!(ALLOWED_CALLERS_BOTH),
            );
        }
    }
}
