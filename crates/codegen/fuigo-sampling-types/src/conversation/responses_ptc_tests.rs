use super::responses_ptc::*;
use super::*;

fn read_file_tool() -> ToolSpec {
    ToolSpec {
        name: "read_file".to_string(),
        description: Some("Read a file".to_string()),
        parameters: serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}}),
    }
}

fn program() -> ProgramItem {
    ProgramItem {
        id: "prog_item_1".into(),
        call_id: "prog_1".into(),
        code: "const a = await tools.read_file({path: 'a.txt'}); text(a);".into(),
        fingerprint: "fp-opaque".into(),
        call_ids: vec!["call_a".into(), "call_b".into()],
    }
}

/// Serialize a request the way the sampler does: typed body, then the PTC pass.
fn serialized(req: &ConversationRequest) -> serde_json::Value {
    let responses_req: rs::CreateResponse = req.into();
    let mut body = serde_json::to_value(&responses_req).expect("serializable");
    if let Some(tools) = body.get_mut("tools").and_then(|v| v.as_array_mut()) {
        tools.extend(extra_tool_entries(&req.hosted_tools));
    } else {
        let extra = extra_tool_entries(&req.hosted_tools);
        if !extra.is_empty() {
            body["tools"] = serde_json::Value::Array(extra);
        }
    }
    patch_request_body(&mut body);
    body
}

#[test]
fn flag_off_request_is_byte_identical_and_carries_no_ptc_keys() {
    let req = ConversationRequest::from_items(vec![
        ConversationItem::system("sys"),
        ConversationItem::user("hi"),
        ConversationItem::assistant_tool_calls(vec![ToolCall {
            id: "call_direct".into(),
            name: "read_file".to_string(),
            arguments: r#"{"path":"a.txt"}"#.into(),
        }]),
        ConversationItem::tool_result("call_direct", "hello"),
    ])
    .with_model("gpt-5.6")
    .with_tools(vec![read_file_tool()]);

    let responses_req: rs::CreateResponse = (&req).into();
    let before = serde_json::to_string(&responses_req).expect("serializable");
    let mut body: serde_json::Value = serde_json::from_str(&before).expect("json");
    patch_request_body(&mut body);
    let after = serde_json::to_string(&body).expect("serializable");
    let before_norm =
        serde_json::to_string(&serde_json::from_str::<serde_json::Value>(&before).unwrap())
            .unwrap();
    assert_eq!(
        before_norm, after,
        "the PTC pass must be a no-op when the flag is off"
    );
    assert!(!after.contains("allowed_callers"));
    assert!(!after.contains("programmatic"));
    assert!(!after.contains("\"caller\""));
}

#[test]
fn flag_on_adds_tool_entry_and_allowed_callers() {
    let mut req = ConversationRequest::from_items(vec![ConversationItem::user("hi")])
        .with_model("gpt-5.6")
        .with_tools(vec![read_file_tool()]);
    req.hosted_tools = vec![HostedTool::ProgrammaticToolCalling];

    let body = serialized(&req);
    let tools = body["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0]["type"], "function");
    assert_eq!(tools[0]["name"], "read_file");
    assert_eq!(
        tools[0]["allowed_callers"],
        serde_json::json!(["direct", "programmatic"])
    );
    assert_eq!(
        tools[1],
        serde_json::json!({"type": "programmatic_tool_calling"})
    );
}

#[test]
fn allowed_callers_are_not_stamped_without_the_ptc_tool() {
    let mut body = serde_json::json!({
        "tools": [{"type": "function", "name": "read_file"}, {"type": "web_search"}]
    });
    let before = body.clone();
    patch_request_body(&mut body);
    assert_eq!(body, before);
}

#[test]
fn explicit_allowed_callers_are_preserved() {
    let mut body = serde_json::json!({
        "tools": [
            {"type": "function", "name": "ask_user", "allowed_callers": ["direct"]},
            {"type": "function", "name": "read_file"},
            {"type": "programmatic_tool_calling"}
        ]
    });
    patch_request_body(&mut body);
    assert_eq!(
        body["tools"][0]["allowed_callers"],
        serde_json::json!(["direct"])
    );
    assert_eq!(
        body["tools"][1]["allowed_callers"],
        serde_json::json!(["direct", "programmatic"])
    );
    assert!(body["tools"][2].get("allowed_callers").is_none());
}

#[test]
fn program_items_replay_as_wire_items_with_callers() {
    let mut req = ConversationRequest::from_items(vec![
        ConversationItem::user("read a and b"),
        ConversationItem::BackendToolCall(BackendToolCallItem {
            kind: BackendToolKind::Program(program()),
        }),
        ConversationItem::assistant_tool_calls(vec![
            ToolCall {
                id: "call_a".into(),
                name: "read_file".to_string(),
                arguments: r#"{"path":"a.txt"}"#.into(),
            },
            ToolCall {
                id: "call_b".into(),
                name: "read_file".to_string(),
                arguments: r#"{"path":"b.txt"}"#.into(),
            },
            // A direct call in the same turn keeps no caller
            ToolCall {
                id: "call_direct".into(),
                name: "read_file".to_string(),
                arguments: r#"{"path":"c.txt"}"#.into(),
            },
        ]),
        ConversationItem::tool_result("call_a", "A"),
        ConversationItem::tool_result("call_b", "B"),
        ConversationItem::tool_result("call_direct", "C"),
        ConversationItem::BackendToolCall(BackendToolCallItem {
            kind: BackendToolKind::ProgramOutput(ProgramOutputItem {
                id: "po_item_1".into(),
                call_id: "prog_1".into(),
                result: "AB".into(),
                status: "completed".into(),
            }),
        }),
        ConversationItem::assistant("done"),
    ])
    .with_model("gpt-5.6")
    .with_tools(vec![read_file_tool()]);
    req.hosted_tools = vec![HostedTool::ProgrammaticToolCalling];

    let body = serialized(&req);
    let input = body["input"].as_array().expect("input");
    let kinds: Vec<&str> = input
        .iter()
        .map(|i| i.get("type").and_then(|t| t.as_str()).unwrap_or("message"))
        .collect();
    assert_eq!(
        kinds,
        vec![
            "message",
            "program",
            "function_call",
            "function_call",
            "function_call",
            "function_call_output",
            "function_call_output",
            "function_call_output",
            "program_output",
            "message",
        ]
    );
    assert_eq!(
        input[1],
        serde_json::json!({
            "type": "program",
            "id": "prog_item_1",
            "call_id": "prog_1",
            "code": program().code,
            "fingerprint": "fp-opaque",
        })
    );
    let caller = serde_json::json!({"type": "program", "caller_id": "prog_1"});
    assert_eq!(input[2]["caller"], caller);
    assert_eq!(input[3]["caller"], caller);
    assert!(
        input[4].get("caller").is_none(),
        "direct call must not get a caller"
    );
    assert_eq!(input[5]["caller"], caller);
    assert_eq!(input[5]["output"], "A");
    assert_eq!(input[6]["caller"], caller);
    assert!(input[7].get("caller").is_none());
    assert_eq!(
        input[8],
        serde_json::json!({
            "type": "program_output",
            "id": "po_item_1",
            "call_id": "prog_1",
            "result": "AB",
            "status": "completed",
        })
    );
    assert!(
        !serde_json::to_string(&body)
            .unwrap()
            .contains("__fuigo_ptc")
    );
}

#[test]
fn carrier_round_trips_through_conversation_items() {
    let carrier = program_wire_to_carrier(
        &serde_json::json!({
            "type": "program", "id": "prog_item_1", "call_id": "prog_1",
            "code": "text('x')", "fingerprint": "fp"
        }),
        &["call_a".to_string()],
    )
    .expect("carrier");
    let ct: rs::CustomToolCall = serde_json::from_value(carrier).expect("typed carrier");
    assert!(is_carrier(&ct));
    let kind = carrier_to_backend_kind(&ct).expect("program");
    let BackendToolKind::Program(p) = &kind else {
        panic!("expected program, got {kind:?}");
    };
    assert_eq!(p.call_ids, vec!["call_a".to_string()]);
    assert_eq!(p.fingerprint, "fp");

    let item = BackendToolCallItem { kind };
    assert_eq!(item.id(), "prog_item_1");
    assert!(
        item.text_summary()
            .starts_with("[backend programmatic_tool_calling]")
    );

    // Persisted form keeps the bookkeeping and the tag
    let persisted = serde_json::to_value(&item).unwrap();
    assert_eq!(persisted["kind"]["tool_type"], "program");
    assert_eq!(persisted["kind"]["call_ids"], serde_json::json!(["call_a"]));
    let back: BackendToolCallItem = serde_json::from_value(persisted).unwrap();
    assert_eq!(back.id(), "prog_item_1");
}

#[test]
fn program_output_carrier_reports_incomplete_as_failed() {
    let carrier = program_output_wire_to_carrier(&serde_json::json!({
        "type": "program_output", "id": "po_1", "call_id": "prog_1",
        "result": "boom", "status": "incomplete"
    }))
    .expect("carrier");
    let ct: rs::CustomToolCall = serde_json::from_value(carrier).expect("typed carrier");
    let kind = carrier_to_backend_kind(&ct).expect("program output");
    let payload = carrier_result_payload(&kind).expect("payload");
    assert_eq!(payload["status"], "failed");
    assert_eq!(payload["result"], "boom");
}

#[test]
fn response_with_program_carrier_maps_to_conversation_items() {
    let carrier = program_wire_to_carrier(
        &serde_json::json!({"type": "program", "id": "prog_item_1", "call_id": "prog_1", "code": "c", "fingerprint": "f"}),
        &["call_a".to_string()],
    )
    .unwrap();
    let response: rs::Response = serde_json::from_value(serde_json::json!({
        "id": "resp_1", "object": "response", "created_at": 0, "status": "completed", "model": "gpt-5.6",
        "output": [
            carrier,
            {"type": "function_call", "id": "fc_a", "call_id": "call_a", "name": "read_file", "arguments": "{}", "status": "completed"}
        ],
        "parallel_tool_calls": true
    }))
    .expect("typed response");
    let items = response_to_conversation_items(response);
    assert_eq!(items.len(), 2);
    let ConversationItem::BackendToolCall(b) = &items[0] else {
        panic!("expected program item first, got {:?}", items[0]);
    };
    assert!(matches!(b.kind, BackendToolKind::Program(_)));
    let ConversationItem::Assistant(a) = &items[1] else {
        panic!("expected assistant, got {:?}", items[1]);
    };
    assert_eq!(a.tool_calls.len(), 1);
    assert_eq!(a.tool_calls[0].id.as_ref(), "call_a");
}

#[test]
fn hosted_tool_wire_name_and_overrides() {
    let mut tools = vec![HostedTool::ProgrammaticToolCalling];
    assert_eq!(tools[0].wire_name(), "programmatic_tool_calling");
    let applied = apply_tool_overrides(&mut tools, None);
    assert_eq!(applied, ToolOverrides::default());
    assert_eq!(
        extra_tool_entries(&tools),
        vec![serde_json::json!({"type": "programmatic_tool_calling"})]
    );
}
