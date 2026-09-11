//! Programmatic tool calling (PTC) at the Responses SSE boundary.
//!
//! The vendored `async-openai` `OutputItem` enum has no catch-all variant, so a `program` or `program_output` item
//! would fail typed deserialization of the frame that carries it (`response.output_item.*`, `response.completed`).
//! [`transcode_sse`] rewrites those items into the typed carrier defined in
//! `fuigo_sampling_types::responses_ptc` before the frame is parsed; the two `*_event` helpers turn carriers into the
//! backend-tool progress events the shell already renders.
//!
//! Wire contract: `docs/ptc-contract.md`.

use std::collections::BTreeMap;

use fuigo_sampling_types::responses_ptc::{
    PTC_TOOL_TYPE, carrier_result_payload, carrier_to_backend_kind, is_carrier,
    program_output_wire_to_carrier, program_wire_to_carrier,
};
use fuigo_sampling_types::rs;

use crate::events::SamplingEvent;
use crate::types::RequestId;

/// Cheap pre-filter: a frame that never mentions a program item is returned untouched without JSON parsing.
fn may_carry_program(data: &str) -> bool {
    data.contains("\"program\"") || data.contains("\"program_output\"")
}

/// Rewrite the PTC items in one SSE `data:` payload into typed carriers.
/// `None` when the frame needs no change (the common case).
pub fn transcode_sse(data: &str) -> Option<String> {
    if !may_carry_program(data) {
        return None;
    }
    let mut value: serde_json::Value = serde_json::from_str(data).ok()?;
    let event_type = value.get("type")?.as_str()?.to_owned();
    let changed = match event_type.as_str() {
        "response.output_item.added" | "response.output_item.done" => {
            let item = value.get_mut("item")?;
            transcode_item(item, &BTreeMap::new())
        }
        _ => {
            let output = value
                .get_mut("response")
                .and_then(|r| r.get_mut("output"))
                .and_then(|o| o.as_array_mut())?;
            transcode_output(output)
        }
    };
    changed.then(|| value.to_string())
}

/// Rewrite every program item of a full `output` array, attaching to each program the `call_id`s of the
/// `function_call` items it produced (their `caller.caller_id` names the program's `call_id`).
fn transcode_output(output: &mut [serde_json::Value]) -> bool {
    let mut produced: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for item in output.iter() {
        if item.get("type").and_then(|t| t.as_str()) != Some("function_call") {
            continue;
        }
        let Some(caller) = item.get("caller") else {
            continue;
        };
        if caller.get("type").and_then(|t| t.as_str()) != Some("program") {
            continue;
        }
        if let (Some(program), Some(call_id)) = (
            caller.get("caller_id").and_then(|c| c.as_str()),
            item.get("call_id").and_then(|c| c.as_str()),
        ) {
            produced
                .entry(program.to_owned())
                .or_default()
                .push(call_id.to_owned());
        }
    }
    let mut changed = false;
    for item in output.iter_mut() {
        changed |= transcode_item(item, &produced);
    }
    changed
}

fn transcode_item(item: &mut serde_json::Value, produced: &BTreeMap<String, Vec<String>>) -> bool {
    let carrier = match item.get("type").and_then(|t| t.as_str()) {
        Some("program") => {
            let call_ids = item
                .get("call_id")
                .and_then(|c| c.as_str())
                .and_then(|c| produced.get(c))
                .cloned()
                .unwrap_or_default();
            program_wire_to_carrier(item, &call_ids)
        }
        Some("program_output") => program_output_wire_to_carrier(item),
        _ => None,
    };
    match carrier {
        Some(carrier) => {
            *item = carrier;
            true
        }
        None => false,
    }
}

/// The progress event for a carrier that just started streaming; `None` for a real custom tool call.
pub(crate) fn started_event(
    request_id: &RequestId,
    ct: &rs::CustomToolCall,
) -> Option<SamplingEvent> {
    if !is_carrier(ct) {
        return None;
    }
    Some(SamplingEvent::BackendToolCallStarted {
        request_id: request_id.clone(),
        call_id: ct.id.clone(),
        name: PTC_TOOL_TYPE.to_string(),
    })
}

/// The completion event for a finished carrier item; `None` for a real custom tool call.
pub(crate) fn completed_event(
    request_id: &RequestId,
    ct: &rs::CustomToolCall,
) -> Option<SamplingEvent> {
    if !is_carrier(ct) {
        return None;
    }
    let kind = carrier_to_backend_kind(ct)?;
    Some(SamplingEvent::BackendToolCallCompleted {
        request_id: request_id.clone(),
        call_id: ct.id.clone(),
        name: PTC_TOOL_TYPE.to_string(),
        result: carrier_result_payload(&kind),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use super::*;
    use fuigo_sampling_types::responses_ptc::{PROGRAM_CARRIER_NAME, PROGRAM_OUTPUT_CARRIER_NAME};

    const PROGRAM: &str = r#"{"type":"program","id":"prog_item_1","call_id":"prog_1","code":"text('x')","fingerprint":"fp"}"#;

    #[test]
    fn frames_without_program_items_pass_through_untouched() {
        assert!(transcode_sse(r#"{"type":"response.output_text.delta","delta":"hi"}"#).is_none());
        // Mentions the word but carries no program item
        assert!(
            transcode_sse(
                r#"{"type":"response.output_item.done","item":{"type":"message","id":"m","role":"assistant","status":"completed","content":[{"type":"output_text","text":"a \"program\"","annotations":[]}]}}"#
            )
            .is_none()
        );
    }

    #[test]
    fn output_item_added_with_program_becomes_a_typed_carrier() {
        let frame = format!(
            r#"{{"type":"response.output_item.added","output_index":1,"sequence_number":3,"item":{PROGRAM}}}"#
        );
        let out = transcode_sse(&frame).expect("rewritten");
        let event: rs::ResponseStreamEvent =
            serde_json::from_str(&out).expect("typed frame parses");
        let rs::ResponseStreamEvent::ResponseOutputItemAdded(added) = event else {
            panic!("unexpected event");
        };
        let rs::OutputItem::CustomToolCall(ct) = added.item else {
            panic!("expected carrier");
        };
        assert_eq!(ct.name, PROGRAM_CARRIER_NAME);
        assert_eq!(ct.id, "prog_item_1");
        assert_eq!(ct.call_id, "prog_1");
        assert!(started_event(&RequestId::from("r"), &ct).is_some());
    }

    #[test]
    fn terminal_response_attaches_produced_call_ids_to_the_program() {
        let frame = format!(
            r#"{{"type":"response.completed","sequence_number":9,"response":{{"id":"resp_1","object":"response","created_at":0,"status":"completed","model":"gpt-5.6","parallel_tool_calls":true,"output":[
                {{"type":"reasoning","id":"rs_1","summary":[]}},
                {PROGRAM},
                {{"type":"function_call","id":"fc_a","call_id":"call_a","name":"read_file","arguments":"{{}}","status":"completed","caller":{{"type":"program","caller_id":"prog_1"}}}},
                {{"type":"function_call","id":"fc_b","call_id":"call_b","name":"read_file","arguments":"{{}}","status":"completed","caller":{{"type":"program","caller_id":"prog_1"}}}},
                {{"type":"function_call","id":"fc_c","call_id":"call_c","name":"read_file","arguments":"{{}}","status":"completed","caller":{{"type":"direct"}}}}
            ]}}}}"#
        );
        let out = transcode_sse(&frame).expect("rewritten");
        let event: rs::ResponseStreamEvent =
            serde_json::from_str(&out).expect("typed frame parses");
        let rs::ResponseStreamEvent::ResponseCompleted(done) = event else {
            panic!("unexpected event");
        };
        assert_eq!(done.response.output.len(), 5);
        let rs::OutputItem::CustomToolCall(ct) = &done.response.output[1] else {
            panic!("expected carrier at index 1");
        };
        let payload: serde_json::Value = serde_json::from_str(&ct.input).unwrap();
        assert_eq!(payload["call_ids"], serde_json::json!(["call_a", "call_b"]));
        assert_eq!(payload["fingerprint"], "fp");
        assert!(matches!(
            done.response.output[2],
            rs::OutputItem::FunctionCall(_)
        ));
    }

    #[test]
    fn program_output_completion_event_carries_status() {
        let frame = r#"{"type":"response.output_item.done","output_index":0,"sequence_number":1,"item":{"type":"program_output","id":"po_1","call_id":"prog_1","result":"AB","status":"completed"}}"#;
        let out = transcode_sse(frame).expect("rewritten");
        let event: rs::ResponseStreamEvent =
            serde_json::from_str(&out).expect("typed frame parses");
        let rs::ResponseStreamEvent::ResponseOutputItemDone(done) = event else {
            panic!("unexpected event");
        };
        let rs::OutputItem::CustomToolCall(ct) = &done.item else {
            panic!("expected carrier");
        };
        assert_eq!(ct.name, PROGRAM_OUTPUT_CARRIER_NAME);
        let Some(SamplingEvent::BackendToolCallCompleted { name, result, .. }) =
            completed_event(&RequestId::from("r"), ct)
        else {
            panic!("expected completed event");
        };
        assert_eq!(name, PTC_TOOL_TYPE);
        let result = result.expect("payload");
        assert_eq!(result["result"], "AB");
        assert_eq!(result["status"], "completed");
    }

    /// End to end through the layer-2 transform: carrier frames become backend-tool progress events and the
    /// completed conversation carries the program item ahead of the assistant's (program-originated) tool calls.
    #[tokio::test]
    async fn stream_responses_surfaces_program_items_and_events() {
        use crate::stream::responses::stream_responses;
        use fuigo_sampling_types::{BackendToolKind, ConversationItem, StopReason};
        use futures_util::StreamExt;
        use std::pin::pin;
        use std::time::Duration;

        let added = transcode_sse(&format!(
            r#"{{"type":"response.output_item.added","output_index":0,"sequence_number":1,"item":{PROGRAM}}}"#
        ))
        .unwrap();
        let done = transcode_sse(&format!(
            r#"{{"type":"response.output_item.done","output_index":0,"sequence_number":2,"item":{PROGRAM}}}"#
        ))
        .unwrap();
        let completed = transcode_sse(&format!(
            r#"{{"type":"response.completed","sequence_number":5,"response":{{"id":"resp_1","object":"response","created_at":0,"status":"completed","model":"gpt-5.6","parallel_tool_calls":true,"output":[
                {PROGRAM},
                {{"type":"function_call","id":"fc_a","call_id":"call_a","name":"read_file","arguments":"{{\"path\":\"a\"}}","status":"completed","caller":{{"type":"program","caller_id":"prog_1"}}}},
                {{"type":"function_call","id":"fc_b","call_id":"call_b","name":"read_file","arguments":"{{\"path\":\"b\"}}","status":"completed","caller":{{"type":"program","caller_id":"prog_1"}}}}
            ]}}}}"#
        ))
        .unwrap();
        let frames: Vec<Result<rs::ResponseStreamEvent, fuigo_sampling_types::SamplingError>> =
            [added, done, completed]
                .iter()
                .map(|f| Ok(serde_json::from_str(f).expect("typed frame")))
                .collect();
        let raw = futures_util::stream::iter(frames).boxed();
        let mut events = Vec::new();
        let mut s = pin!(stream_responses(
            raw,
            None,
            RequestId::from("ptc"),
            Duration::from_secs(60),
            None,
            HashSet::new(),
        ));
        while let Some(ev) = s.next().await {
            events.push(ev);
        }

        assert!(events.iter().any(|e| matches!(
            e,
            SamplingEvent::BackendToolCallStarted { name, call_id, .. }
                if name == PTC_TOOL_TYPE && call_id == "prog_item_1"
        )));
        assert!(events.iter().any(|e| matches!(
            e,
            SamplingEvent::BackendToolCallCompleted { name, result: Some(r), .. }
                if name == PTC_TOOL_TYPE && r["code"] == "text('x')"
        )));
        let Some(SamplingEvent::Completed { response, .. }) = events.last() else {
            panic!("expected Completed, got {:?}", events.last());
        };
        assert_eq!(response.stop_reason, Some(StopReason::ToolCalls));
        let ConversationItem::BackendToolCall(b) = &response.items[0] else {
            panic!("expected program item first: {:?}", response.items);
        };
        let BackendToolKind::Program(p) = &b.kind else {
            panic!("expected program kind: {:?}", b.kind);
        };
        assert_eq!(p.fingerprint, "fp");
        assert_eq!(p.call_ids, vec!["call_a".to_string(), "call_b".to_string()]);
        let ConversationItem::Assistant(a) = &response.items[1] else {
            panic!("expected assistant: {:?}", response.items);
        };
        assert_eq!(a.tool_calls.len(), 2);
    }

    #[test]
    fn a_real_custom_tool_call_is_left_alone() {
        let ct: rs::CustomToolCall = serde_json::from_value(serde_json::json!({
            "type": "custom_tool_call", "id": "x1", "call_id": "c1", "name": "x_keyword_search", "input": "{}"
        }))
        .unwrap();
        assert!(started_event(&RequestId::from("r"), &ct).is_none());
        assert!(completed_event(&RequestId::from("r"), &ct).is_none());
    }
}
