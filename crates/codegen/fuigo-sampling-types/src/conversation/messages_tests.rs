use super::test_support::*;
use super::*;

fn messages_test_request(reasoning_effort: Option<crate::ReasoningEffort>) -> ConversationRequest {
    ConversationRequest {
        items: vec![ConversationItem::user("Hello")],
        model: Some("test-model".to_string()),
        reasoning_effort,
        ..Default::default()
    }
}

#[test]
fn json_schema_and_reasoning_effort_are_orthogonal_in_output_config() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": { "x": { "type": "string" } },
        "required": ["x"]
    });
    let mut req = ConversationRequest::from_items(vec![ConversationItem::user("go")])
        .with_json_schema(schema);
    req.reasoning_effort = Some(crate::ReasoningEffort::High);

    let msgs = build_messages_request(&req);
    let oc = msgs.output_config.expect("output_config present");
    assert_eq!(oc.effort.as_deref(), Some("high"));
    assert!(oc.format.is_some());
    assert!(
        msgs.thinking.is_some(),
        "thinking set when effort is present"
    );
}

#[test]
fn test_messages_request_wire_format_for_supported_variants() {
    for (variant, expected) in [
        (crate::ReasoningEffort::Low, "low"),
        (crate::ReasoningEffort::Medium, "medium"),
        (crate::ReasoningEffort::High, "high"),
        (crate::ReasoningEffort::Xhigh, "xhigh"),
        (crate::ReasoningEffort::Max, "max"),
    ] {
        let req = messages_test_request(Some(variant));
        let msgs = build_messages_request(&req);
        let json = serde_json::to_value(&msgs).unwrap();
        assert_eq!(
            json.pointer("/output_config/effort")
                .and_then(|v| v.as_str()),
            Some(expected),
            "{variant:?} should map to output_config.effort={expected:?}; got: {json:#}",
        );
        assert_eq!(
            json.pointer("/thinking/type").and_then(|v| v.as_str()),
            Some("adaptive"),
            "{variant:?} should auto-pair thinking.type=adaptive; got: {json:#}",
        );
    }
}

#[test]
fn test_messages_request_omits_output_config_when_no_supported_effort() {
    let none_or_unsupported = [
        None,
        Some(crate::ReasoningEffort::None),
        Some(crate::ReasoningEffort::Minimal),
    ];
    for input in none_or_unsupported {
        let req = messages_test_request(input);
        let msgs = build_messages_request(&req);
        assert!(
            msgs.output_config.is_none(),
            "input {input:?} must not produce output_config",
        );
        assert!(
            msgs.thinking.is_none(),
            "input {input:?} must not auto-pair thinking",
        );
    }
}

#[test]
fn test_messages_request_thinking_carries_summarized_display() {
    let req = ConversationRequest {
        reasoning_effort: Some(crate::ReasoningEffort::High),
        ..ConversationRequest::from_items(vec![ConversationItem::user("hi")])
            .with_model("messages-compatible-model")
    };
    let msg = build_messages_request(&req);
    let json = serde_json::to_value(&msg).unwrap();
    assert_eq!(
        json.pointer("/thinking/type").and_then(|v| v.as_str()),
        Some("adaptive"),
        "thinking.type should be 'adaptive'; got: {json:#}",
    );
    assert_eq!(
        json.pointer("/thinking/display").and_then(|v| v.as_str()),
        Some("summarized"),
        "thinking.display must be 'summarized' so 4.7+ surfaces thinking content; got: {json:#}",
    );
}

#[test]
fn test_messages_request_omits_thinking_when_effort_unset() {
    let req = ConversationRequest::from_items(vec![ConversationItem::user("hi")])
        .with_model("messages-compatible-model");
    let msg = build_messages_request(&req);
    let json = serde_json::to_value(&msg).unwrap();
    assert!(
        json.get("thinking").is_none()
            || json
                .pointer("/thinking")
                .map(|v| v.is_null())
                .unwrap_or(false),
        "thinking must be absent when reasoning_effort is unset; got: {json:#}",
    );
    assert!(
        json.get("output_config").is_none()
            || json
                .pointer("/output_config")
                .map(|v| v.is_null())
                .unwrap_or(false),
        "output_config must be absent when reasoning_effort is unset; got: {json:#}",
    );
}

#[test]
fn test_messages_request_previous_tip_skips_a_trailing_user_run() {
    let mut items = vec![
        ConversationItem::system("You are a helpful assistant."),
        ConversationItem::user("Fix the bug"),
    ];
    items.extend(agent_turn(0));
    items.extend(agent_turn(1));
    // The shape after a parallel batch: tool results, then followups.
    items.push(ConversationItem::user("[Image content]"));
    items.push(ConversationItem::user("<system-reminder>"));

    let json = serde_json::to_value(build_messages_request(
        &ConversationRequest::from_items(items).with_model("messages-compatible-model"),
    ))
    .unwrap();
    let messages = json["messages"].as_array().unwrap();

    let marked: Vec<usize> = (0..messages.len())
        .filter(|&i| marker_on_last_block(&messages[i]).is_some())
        .collect();
    let last_assistant = messages
        .iter()
        .rposition(|m| m["role"] == "assistant")
        .unwrap();
    assert_eq!(marked.len(), 2, "tip and previous tip only: {json:#}");
    assert_eq!(marked[1], messages.len() - 1, "tip: {json:#}");
    assert!(
        marked[0] < last_assistant,
        "the previous tip must sit before the last assistant turn, not inside \
             the trailing user run; got {marked:?} in {json:#}",
    );
}

#[test]
fn test_messages_request_cache_breakpoint_marks_an_image_tip() {
    let req = ConversationRequest::from_items(vec![
        ConversationItem::system("You are a helpful assistant."),
        ConversationItem::User(UserItem {
            content: vec![
                ContentPart::Text {
                    text: "what is in this screenshot".into(),
                },
                ContentPart::Image {
                    url: "data:image/png;base64,iVBOR".into(),
                },
            ],
            ..Default::default()
        }),
    ])
    .with_model("messages-compatible-model");

    let json = serde_json::to_value(build_messages_request(&req)).unwrap();
    let blocks = json["messages"][0]["content"].as_array().unwrap();

    assert_eq!(blocks.last().unwrap()["type"].as_str(), Some("image"));
    assert_eq!(
        marker_on_last_block(&json["messages"][0]),
        Some("ephemeral"),
        "{json:#}",
    );
    assert!(blocks[0].get("cache_control").is_none(), "{json:#}");
}

#[test]
fn test_messages_request_cache_breakpoint_skips_thinking() {
    let req = ConversationRequest::from_items(vec![
        ConversationItem::user("Fix the bug"),
        ConversationItem::Reasoning(synthesized_reasoning_item("weighing options")),
        ConversationItem::assistant("Fixed it."),
    ])
    .with_model("messages-compatible-model");

    let json = serde_json::to_value(build_messages_request(&req)).unwrap();
    let blocks = json["messages"][1]["content"].as_array().unwrap();

    let thinking = blocks
        .iter()
        .find(|b| b["type"] == "thinking")
        .expect("reasoning should emit a thinking block");
    assert!(thinking.get("cache_control").is_none(), "{json:#}");
    assert_eq!(
        marker_on_last_block(&json["messages"][1]),
        Some("ephemeral"),
        "{json:#}",
    );
}

#[test]
fn test_btw_cross_api_messages_no_regressions() {
    let items = btw_prepare_items(btw_mid_turn_conversation());
    let req = ConversationRequest::from_items(items);
    let msg = build_messages_request(&req);
    let json = serde_json::to_value(&msg).unwrap();

    let messages = json.get("messages").unwrap().as_array().unwrap();

    // No thinking blocks anywhere.
    for (i, m) in messages.iter().enumerate() {
        if let Some(content) = m.get("content").and_then(|c| c.as_array()) {
            for block in content {
                assert_ne!(
                    block.get("type").and_then(|t| t.as_str()),
                    Some("thinking"),
                    "messages[{i}] must not contain thinking blocks",
                );
            }
        }
    }

    // Last assistant message must not have unanswered tool_use.
    let last_assistant = messages
        .iter()
        .rev()
        .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("assistant"))
        .expect("should have an assistant message");
    if let Some(content) = last_assistant.get("content").and_then(|c| c.as_array()) {
        for block in content {
            assert_ne!(
                block.get("type").and_then(|t| t.as_str()),
                Some("tool_use"),
                "last assistant in btw request must not have unanswered tool_use",
            );
        }
    }

    // Top-level thinking must be absent (no reasoning_effort set).
    assert!(
        json.get("thinking").is_none() || json.pointer("/thinking").is_some_and(|v| v.is_null()),
        "top-level thinking must be absent; got: {json:#}",
    );

    assert!(
        json.get("temperature").is_none()
            || json.pointer("/temperature").is_some_and(|v| v.is_null()),
        "temperature must be absent so proxy defaults can apply; got: {json:#}",
    );

    // The completed tool pair (call_1) must survive.
    let has_tool_use_call_1 = messages.iter().any(|m| {
        m.get("content")
            .and_then(|c| c.as_array())
            .is_some_and(|blocks| {
                blocks.iter().any(|b| {
                    b.get("type").and_then(|t| t.as_str()) == Some("tool_use")
                        && b.get("id").and_then(|id| id.as_str()) == Some("call_1")
                })
            })
    });
    assert!(
        has_tool_use_call_1,
        "completed tool_use call_1 must survive"
    );

    let has_tool_result_call_1 = messages.iter().any(|m| {
        m.get("content")
            .and_then(|c| c.as_array())
            .is_some_and(|blocks| {
                blocks.iter().any(|b| {
                    b.get("type").and_then(|t| t.as_str()) == Some("tool_result")
                        && b.get("tool_use_id").and_then(|id| id.as_str()) == Some("call_1")
                })
            })
    });
    assert!(
        has_tool_result_call_1,
        "completed tool_result for call_1 must survive"
    );
}

#[test]
fn test_tool_result_with_images_to_anthropic() {
    let req = ConversationRequest::from_items(vec![
        ConversationItem::user("Read this"),
        ConversationItem::Assistant(AssistantItem {
            content: String::new().into(),
            tool_calls: vec![ToolCall {
                id: "call_1".into(),
                name: "read_file".to_string(),
                arguments: "{}".into(),
            }],
            model_id: None,
            model_fingerprint: None,
            reasoning_effort: None,
            output_order: None,
        }),
        ConversationItem::tool_result_with_images(
            "call_1",
            "Read image file: photo.png",
            vec![ContentPart::Image {
                url: "data:image/png;base64,iVBOR".into(),
            }],
        ),
    ]);

    let messages_req = build_messages_request(&req);

    // Find the user message that contains the tool result (the Messages API wraps tool results in user messages)
    let tool_result_msg = messages_req
        .messages
        .iter()
        .find(|m| {
            if let crate::messages::MessageContent::Blocks(blocks) = &m.content {
                blocks
                    .iter()
                    .any(|b| matches!(b, crate::messages::ContentBlock::ToolResult { .. }))
            } else {
                false
            }
        })
        .expect("Expected a message with ToolResult block");

    let crate::messages::MessageContent::Blocks(blocks) = &tool_result_msg.content else {
        panic!("Expected Blocks");
    };
    let tool_result_block = blocks
        .iter()
        .find_map(|b| {
            if let crate::messages::ContentBlock::ToolResult { content, .. } = b {
                Some(content)
            } else {
                None
            }
        })
        .unwrap();

    let crate::messages::ToolResultContent::Blocks(inner) = tool_result_block else {
        panic!("Expected ToolResultContent::Blocks, got Text");
    };
    assert_eq!(inner.len(), 2);
    assert!(
        matches!(&inner[0], crate::messages::ContentBlock::Text { text, .. } if text == "Read image file: photo.png")
    );
    assert!(
        matches!(&inner[1], crate::messages::ContentBlock::Image { source: crate::messages::ImageSource::Base64 { media_type, data }, .. } if media_type == "image/png" && data == "iVBOR")
    );
}

#[test]
fn upgrade_legacy_reasoning_singular_anthropic_no_id() {
    // Messages streaming sets id = "" (see stream/messages.rs:340).
    // The upgrader must still emit a sibling carrying text and signature
    let raw = serde_json::json!({
        "type": "assistant",
        "content": "answer",
        "reasoning": {
            "text": "Let me think about this...",
            "encrypted": "signature-bytes-here",
            "id": ""
        },
        "model_id": "messages-compatible-model"
    });
    let mut seen = std::collections::HashSet::new();
    let siblings = upgrade_legacy_reasoning(&raw, &mut seen);
    assert_eq!(siblings.len(), 1);
    let ConversationItem::Reasoning(r) = &siblings[0] else {
        panic!("expected Reasoning sibling");
    };
    assert_eq!(r.id, "");
    assert_eq!(r.encrypted_content.as_deref(), Some("signature-bytes-here"));
}

fn reasoning_with_signature(text: &str, signature: &str) -> rs::ReasoningItem {
    let mut r = synthesized_reasoning_item(text);
    r.encrypted_content = Some(signature.to_owned());
    r
}

/// Every reasoning sibling replays as its own block, in order, each with its own signature; a redacted
/// item replays as `redacted_thinking` carrying its opaque data and no `thinking` / `signature` fields.
#[test]
fn replay_emits_every_thinking_and_redacted_block_in_order() {
    let req = ConversationRequest::from_items(vec![
        ConversationItem::user("go"),
        ConversationItem::Reasoning(reasoning_with_signature("first", "sig-1")),
        ConversationItem::Reasoning(redacted_thinking_item("opaque-blob")),
        ConversationItem::Reasoning(reasoning_with_signature("second", "sig-2")),
        ConversationItem::assistant("done"),
    ])
    .with_model("messages-compatible-model");

    let json = serde_json::to_value(build_messages_request(&req)).unwrap();
    let blocks = json["messages"][1]["content"].as_array().unwrap();
    let kinds: Vec<&str> = blocks.iter().map(|b| b["type"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        vec!["thinking", "redacted_thinking", "thinking", "text"],
        "{json:#}"
    );
    assert_eq!(blocks[0]["thinking"], "first");
    assert_eq!(blocks[0]["signature"], "sig-1");
    assert_eq!(blocks[1]["data"], "opaque-blob");
    assert!(blocks[1].get("signature").is_none(), "{json:#}");
    assert_eq!(blocks[2]["thinking"], "second");
    assert_eq!(blocks[2]["signature"], "sig-2");
}

/// A redacted item is Anthropic-only: the Responses input must not carry it to another protocol.
#[test]
fn responses_input_skips_redacted_thinking_items() {
    let req = ConversationRequest::from_items(vec![
        ConversationItem::user("go"),
        ConversationItem::Reasoning(redacted_thinking_item("opaque-blob")),
        ConversationItem::assistant("done"),
    ])
    .with_model("m");
    let responses_req: rs::CreateResponse = (&req).into();
    let rs::InputParam::Items(items) = responses_req.input else {
        panic!("Expected Items input");
    };
    let json = serde_json::to_string(&items).unwrap();
    assert!(!json.contains("opaque-blob"), "{json}");
    assert!(!json.contains(REDACTED_THINKING_ITEM_ID), "{json}");
}

fn wire_response(content: serde_json::Value) -> crate::messages::MessagesResponse {
    serde_json::from_value(serde_json::json!({
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "content": content,
        "model": "messages-compatible-model",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }))
    .unwrap()
}

/// The non-streaming path keeps every thinking / redacted_thinking block as a sibling `Reasoning`, in wire order,
/// ahead of the `Assistant`, so replaying its history does not lose reasoning.
#[test]
fn non_streaming_response_keeps_every_thinking_block() {
    let resp = wire_response(serde_json::json!([
        {"type": "thinking", "thinking": "first", "signature": "sig-1"},
        {"type": "redacted_thinking", "data": "opaque-blob"},
        {"type": "text", "text": "hello"},
        {"type": "thinking", "thinking": "second", "signature": "sig-2"},
    ]));
    let items = messages_response_to_items(resp);
    assert_eq!(items.len(), 4, "{items:#?}");
    let ConversationItem::Reasoning(a) = &items[0] else {
        panic!("item 0 must be Reasoning: {items:#?}")
    };
    assert_eq!(reasoning_item_text(a), "first");
    assert_eq!(a.encrypted_content.as_deref(), Some("sig-1"));
    let ConversationItem::Reasoning(b) = &items[1] else {
        panic!("item 1 must be Reasoning: {items:#?}")
    };
    assert!(is_redacted_thinking_item(b));
    assert_eq!(b.encrypted_content.as_deref(), Some("opaque-blob"));
    let ConversationItem::Reasoning(c) = &items[2] else {
        panic!("item 2 must be Reasoning: {items:#?}")
    };
    assert_eq!(c.encrypted_content.as_deref(), Some("sig-2"));
    assert!(matches!(&items[3], ConversationItem::Assistant(a) if a.content.as_ref() == "hello"));
}

/// History persistence is plain serde on `ConversationItem`: a reload must hand back every block unchanged.
#[test]
fn reasoning_items_survive_a_serde_round_trip_for_resume() {
    let items = vec![
        ConversationItem::Reasoning(reasoning_with_signature("first", "sig-1")),
        ConversationItem::Reasoning(redacted_thinking_item("opaque-blob")),
        ConversationItem::Reasoning(reasoning_with_signature("second", "sig-2")),
        ConversationItem::assistant("done"),
    ];
    let wire: Vec<String> = items
        .iter()
        .map(|i| serde_json::to_string(i).unwrap())
        .collect();
    let back: Vec<ConversationItem> = wire
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let req_before = serde_json::to_value(build_messages_request(
        &ConversationRequest::from_items(
            std::iter::once(ConversationItem::user("go"))
                .chain(items)
                .collect(),
        )
        .with_model("m"),
    ))
    .unwrap();
    let req_after = serde_json::to_value(build_messages_request(
        &ConversationRequest::from_items(
            std::iter::once(ConversationItem::user("go"))
                .chain(back)
                .collect(),
        )
        .with_model("m"),
    ))
    .unwrap();
    assert_eq!(req_before, req_after);
    assert_eq!(req_after["messages"][1]["content"][1]["type"], "redacted_thinking");
}

/// The response-completed update reports the last thinking block's signature.
#[test]
fn last_reasoning_signature_is_the_last_block() {
    let resp = ConversationResponse {
        items: vec![
            ConversationItem::Reasoning(reasoning_with_signature("a", "sig-1")),
            ConversationItem::Reasoning(reasoning_with_signature("b", "sig-2")),
            ConversationItem::assistant("x"),
        ],
        stop_reason: None,
        usage: None,
        cost_usd_ticks: None,
        message_chunks_emitted: 0,
        doom_loop_signals: Vec::new(),
        stop_message: None,
        message_id: None,
        raw_stop_reason: None,
        stop_sequence: None,
    };
    assert_eq!(resp.last_reasoning_signature(), Some("sig-2"));
}
