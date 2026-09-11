use super::*;

/// Flatten `response.output` into `ConversationItem`s, preserving emission order.
/// Replaying that order byte for byte on the next turn is what keeps the server-side prefix cache hot.
///
/// `is_client_tool` names the function/freeform tools this request advertised.
/// A `custom_tool_call` naming one of them is a client tool call (freeform input, executed locally);
/// any other `custom_tool_call` is a backend-executed hosted tool (x_search) and is kept for replay only.
pub fn response_to_conversation_items(
    response: rs::Response,
    is_client_tool: impl Fn(&str) -> bool,
) -> Vec<ConversationItem> {
    let model_id = response.model.clone();
    let model_fingerprint = response
        .metadata
        .as_ref()
        .and_then(|m| m.get("system_fingerprint"))
        .cloned()
        .filter(|s| !s.is_empty());
    let reasoning_effort = response
        .reasoning
        .as_ref()
        .and_then(|r| r.effort.clone())
        .map(crate::ReasoningEffort::from_responses_api);

    let mut items: Vec<ConversationItem> = Vec::with_capacity(response.output.len() + 1);
    let mut content = String::new();
    let mut tool_calls: Vec<ToolCall> = Vec::new();
    let mut order: Vec<OutputSlot> = Vec::with_capacity(response.output.len());
    let mut backend_tool_count: usize = 0;

    for item in response.output {
        match item {
            rs::OutputItem::Message(msg) => {
                let mut text = String::new();
                for content_part in msg.content {
                    if let rs::OutputMessageContent::OutputText(text_content) = content_part {
                        if !text.is_empty() {
                            text.push('\n');
                        }
                        text.push_str(&text_content.text);
                    }
                }
                if !content.is_empty() {
                    content.push('\n');
                }
                content.push_str(&text);
                order.push(OutputSlot::Message {
                    text: Arc::<str>::from(text),
                });
            }
            rs::OutputItem::FunctionCall(fc) => {
                // Tied to the assistant turn: a ToolResult must follow each one in conversation order, so they are not siblings
                order.push(OutputSlot::FunctionCall {
                    call_id: fc.call_id.clone(),
                });
                tool_calls.push(ToolCall {
                    id: Arc::<str>::from(fc.call_id),
                    name: fc.name,
                    arguments: Arc::<str>::from(fc.arguments),
                });
            }
            rs::OutputItem::Reasoning(r) => {
                order.push(OutputSlot::Reasoning { id: r.id.clone() });
                items.push(ConversationItem::Reasoning(r));
            }
            // These calls already ran server-side; they are kept so later turns replay the same context
            rs::OutputItem::WebSearchCall(ws) => {
                backend_tool_count += 1;
                order.push(OutputSlot::BackendToolCall { id: ws.id.clone() });
                items.push(ConversationItem::BackendToolCall(BackendToolCallItem {
                    kind: BackendToolKind::WebSearch(ws),
                }));
            }
            // A freeform client tool (`custom` tool, e.g. apply_patch) arrives as a custom_tool_call whose input is the raw text
            rs::OutputItem::CustomToolCall(ct) if is_client_tool(&ct.name) => {
                order.push(OutputSlot::CustomToolCall {
                    call_id: ct.call_id.clone(),
                    id: ct.id.clone(),
                });
                tool_calls.push(ToolCall {
                    id: Arc::<str>::from(ct.call_id),
                    name: ct.name,
                    arguments: Arc::<str>::from(ct.input),
                });
            }
            rs::OutputItem::CustomToolCall(ct) => {
                backend_tool_count += 1;
                order.push(OutputSlot::BackendToolCall { id: ct.id.clone() });
                items.push(ConversationItem::BackendToolCall(BackendToolCallItem {
                    kind: BackendToolKind::XSearch(ct),
                }));
            }
            rs::OutputItem::CodeInterpreterCall(ci) => {
                backend_tool_count += 1;
                order.push(OutputSlot::BackendToolCall { id: ci.id.clone() });
                items.push(ConversationItem::BackendToolCall(BackendToolCallItem {
                    kind: BackendToolKind::CodeInterpreter(ci),
                }));
            }
            rs::OutputItem::McpCall(_) => {
                backend_tool_count += 1;
            }
            _ => {}
        }
    }

    if backend_tool_count > 0 {
        tracing::info!(
            backend_tool_count,
            "response contained backend-executed tool calls"
        );
    }

    // The legacy layout (siblings, message, function calls) already replays most turns verbatim; only record the
    // order when it differs, so text-only turns stay byte-identical on disk.
    let output_order = (!legacy_order_equivalent(&order)).then_some(order);

    tracing::info!(model_id = %model_id, ?model_fingerprint, ?reasoning_effort, "response_to_conversation_items setting model metadata on AssistantItem");
    items.push(ConversationItem::Assistant(AssistantItem {
        content: Arc::<str>::from(content),
        tool_calls,
        model_id: Some(model_id),
        model_fingerprint,
        reasoning_effort,
        output_order,
    }));

    items
}

/// Whether replaying `[siblings..., message?, function_calls...]` reproduces `order` exactly.
fn legacy_order_equivalent(order: &[OutputSlot]) -> bool {
    let mut phase = 0u8; // 0 siblings, 1 message seen, 2 function calls
    for slot in order {
        match slot {
            OutputSlot::Reasoning { .. } | OutputSlot::BackendToolCall { .. } if phase == 0 => {}
            OutputSlot::Message { .. } if phase == 0 => phase = 1,
            OutputSlot::FunctionCall { .. } => phase = 2,
            _ => return false,
        }
    }
    true
}

impl From<&ConversationRequest> for rs::CreateResponse {
    fn from(req: &ConversationRequest) -> Self {
        let input = build_responses_input(req);
        let tools = build_responses_tools(req);

        let tool_choice = req.tool_choice.as_ref().map(|tc| match tc {
            ConversationToolChoice::Auto => rs::ToolChoiceParam::Mode(rs::ToolChoiceOptions::Auto),
            ConversationToolChoice::None => rs::ToolChoiceParam::Mode(rs::ToolChoiceOptions::None),
            ConversationToolChoice::Required => {
                rs::ToolChoiceParam::Mode(rs::ToolChoiceOptions::Required)
            }
            ConversationToolChoice::Function(name) => {
                rs::ToolChoiceParam::Function(rs::ToolChoiceFunction { name: name.clone() })
            }
        });

        let verbosity = req.text_verbosity.map(|v| v.to_responses_api());
        let text = match (&req.json_schema, verbosity) {
            (None, None) => None,
            (schema, verbosity) => Some(rs::ResponseTextParam {
                format: match schema {
                    Some(schema) => rs::TextResponseFormatConfiguration::JsonSchema(
                        rs::ResponseFormatJsonSchema {
                            description: None,
                            name: STRUCTURED_OUTPUT_SCHEMA_NAME.to_string(),
                            schema: Some(schema.clone()),
                            strict: Some(true),
                        },
                    ),
                    None => rs::TextResponseFormatConfiguration::Text,
                },
                verbosity,
            }),
        };

        rs::CreateResponse {
            background: None,
            conversation: None,
            include: None,
            input,
            instructions: None,
            max_output_tokens: req.max_output_tokens,
            max_tool_calls: None,
            metadata: None,
            model: req.model.clone(),
            // Explicit and constant: it is part of the cached prefix, and the model may batch independent calls
            parallel_tool_calls: Some(true),
            previous_response_id: None,
            prompt: None,
            prompt_cache_key: req
                .prompt_cache_key
                .clone()
                .or_else(|| req.x_fuigo_conv_id.clone()),
            prompt_cache_retention: None,
            reasoning: Some(rs::Reasoning {
                effort: req.reasoning_effort.map(|e| e.to_responses_api()),
                // A summary is display-only; a non-interactive session never shows it
                summary: (!req.suppress_reasoning_summary).then_some(rs::ReasoningSummary::Concise),
            }),
            safety_identifier: None,
            service_tier: None,
            store: None,
            stream: None,
            stream_options: None,
            temperature: req.temperature,
            text,
            tool_choice,
            tools: if tools.is_empty() { None } else { Some(tools) },
            top_logprobs: None,
            top_p: req.top_p,
            truncation: None,
        }
    }
}

/// Reasoning items stay top-level siblings rather than folding into the assistant, so the input replays the model's original order.
///
/// A run of `Reasoning` / `BackendToolCall` siblings is held back until the assistant item that follows it: when that
/// item recorded an [`AssistantItem::output_order`], the siblings, the message text and the tool calls are emitted in
/// exactly that order (a reasoning item must directly precede the item it produced). Without a recorded order the
/// legacy layout applies: siblings, then the message, then the calls.
/// `function_call_output` / `custom_tool_call_output` items always follow their calls.
pub(super) fn build_responses_input(req: &ConversationRequest) -> rs::InputParam {
    let mut items: Vec<rs::InputItem> = Vec::with_capacity(req.items.len());
    let mut pending: Vec<&ConversationItem> = Vec::new();
    // Call ids replayed as `custom_tool_call`; their results go back as `custom_tool_call_output`
    let mut custom_call_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    for item in &req.items {
        match item {
            ConversationItem::Reasoning(_) | ConversationItem::BackendToolCall(_) => {
                pending.push(item);
            }
            ConversationItem::Assistant(a) => {
                assistant_to_input_items(a, req, &mut pending, &mut custom_call_ids, &mut items);
            }
            ConversationItem::ToolResult(t) => {
                flush_pending(&mut pending, &mut items);
                items.push(tool_result_to_input_item(
                    t,
                    custom_call_ids.contains(&t.tool_call_id),
                ));
            }
            other => {
                flush_pending(&mut pending, &mut items);
                items.extend(conversation_item_to_input_items(other));
            }
        }
    }
    flush_pending(&mut pending, &mut items);
    rs::InputParam::Items(items)
}

fn flush_pending(pending: &mut Vec<&ConversationItem>, out: &mut Vec<rs::InputItem>) {
    out.extend(pending.drain(..).flat_map(conversation_item_to_input_items));
}

/// How a stored tool call goes back on the wire.
enum CallWire {
    Function,
    /// `custom_tool_call`; `id` is the recorded wire item id, empty when the call was stored as a function call
    Custom { id: String },
}

/// The wire form of a tool call follows the tool's *current* declaration: a name the `tools` list declares as a
/// `custom` tool always replays as `custom_tool_call` (a JSON-era apply_patch call is unwrapped to its text), and a
/// name declared as a function always replays as `function_call` (a freeform-era call is wrapped under its input
/// key). The prefix therefore never mixes item kinds for one tool name. An undeclared name keeps its recorded kind.
fn call_wire(req: &ConversationRequest, tc: &ToolCall, recorded: CallWire) -> CallWire {
    match req.tools.iter().find(|t| t.name == tc.name) {
        Some(spec) if spec.is_freeform() => CallWire::Custom {
            id: match recorded {
                CallWire::Custom { id } => id,
                CallWire::Function => String::new(),
            },
        },
        Some(_) => CallWire::Function,
        None => recorded,
    }
}

/// The input key freeform text is wrapped under for a tool (the schema's single required string property, `patch`).
fn input_key(req: &ConversationRequest, name: &str) -> String {
    req.tools
        .iter()
        .find(|t| t.name == name)
        .map(ToolSpec::freeform_input_key)
        .unwrap_or_else(|| "raw".to_owned())
}

fn tool_call_input_item(
    req: &ConversationRequest,
    tc: &ToolCall,
    recorded: CallWire,
    custom_call_ids: &mut std::collections::HashSet<String>,
) -> rs::InputItem {
    let from_freeform = matches!(recorded, CallWire::Custom { .. });
    match call_wire(req, tc, recorded) {
        CallWire::Function => function_call_input_item(req, tc, from_freeform),
        CallWire::Custom { id } => {
            custom_call_ids.insert(tc.id.as_ref().to_owned());
            custom_tool_call_input_item(req, tc, &id)
        }
    }
}

/// Emit one assistant turn: the held-back siblings, the message text and the tool calls, in recorded emission order.
fn assistant_to_input_items(
    a: &AssistantItem,
    req: &ConversationRequest,
    pending: &mut Vec<&ConversationItem>,
    custom_call_ids: &mut std::collections::HashSet<String>,
    out: &mut Vec<rs::InputItem>,
) {
    let Some(order) = a.output_order.as_deref() else {
        flush_pending(pending, out);
        if !a.content.is_empty() {
            out.push(assistant_message_input_item(&a.content));
        }
        out.extend(
            a.tool_calls
                .iter()
                .map(|tc| tool_call_input_item(req, tc, CallWire::Function, custom_call_ids)),
        );
        return;
    };

    let mut sibling_used = vec![false; pending.len()];
    let mut call_used = vec![false; a.tool_calls.len()];
    let message_slots = order
        .iter()
        .filter(|s| matches!(s, OutputSlot::Message { .. }))
        .count();
    let mut message_placed = false;
    let mut ordered: Vec<rs::InputItem> = Vec::with_capacity(order.len());
    for slot in order {
        match slot {
            OutputSlot::Reasoning { id } => {
                let found = pending.iter().enumerate().position(|(i, p)| {
                    !sibling_used[i] && matches!(p, ConversationItem::Reasoning(r) if r.id == *id)
                });
                if let Some(i) = found {
                    sibling_used[i] = true;
                    ordered.extend(conversation_item_to_input_items(pending[i]));
                }
            }
            OutputSlot::BackendToolCall { id } => {
                let found = pending.iter().enumerate().position(|(i, p)| {
                    !sibling_used[i]
                        && matches!(p, ConversationItem::BackendToolCall(b) if b.id() == id)
                });
                if let Some(i) = found {
                    sibling_used[i] = true;
                    ordered.extend(conversation_item_to_input_items(pending[i]));
                }
            }
            OutputSlot::Message { text } => {
                // A single message replays the (possibly rewritten) assistant content; several keep their own text
                let text: &str = if message_slots == 1 { &a.content } else { text };
                message_placed = true;
                if !text.is_empty() {
                    ordered.push(assistant_message_input_item(text));
                }
            }
            OutputSlot::FunctionCall { call_id } => {
                if let Some(tc) = take_tool_call(a, &mut call_used, call_id) {
                    ordered.push(tool_call_input_item(req, tc, CallWire::Function, custom_call_ids));
                }
            }
            OutputSlot::CustomToolCall { call_id, id } => {
                if let Some(tc) = take_tool_call(a, &mut call_used, call_id) {
                    ordered.push(tool_call_input_item(
                        req,
                        tc,
                        CallWire::Custom { id: id.clone() },
                        custom_call_ids,
                    ));
                }
            }
        }
    }

    // Anything the recorded order does not account for keeps the legacy layout around the ordered block:
    // unmatched siblings first, an unplaced message next, unmatched calls last.
    for (i, p) in pending.iter().enumerate() {
        if !sibling_used[i] {
            out.extend(conversation_item_to_input_items(p));
        }
    }
    pending.clear();
    if !message_placed && !a.content.is_empty() {
        out.push(assistant_message_input_item(&a.content));
    }
    out.extend(ordered);
    for (i, tc) in a.tool_calls.iter().enumerate() {
        if !call_used[i] {
            out.push(tool_call_input_item(req, tc, CallWire::Function, custom_call_ids));
        }
    }
}

fn take_tool_call<'a>(
    a: &'a AssistantItem,
    call_used: &mut [bool],
    call_id: &str,
) -> Option<&'a ToolCall> {
    let i = a
        .tool_calls
        .iter()
        .enumerate()
        .position(|(i, tc)| !call_used[i] && tc.id.as_ref() == call_id)?;
    call_used[i] = true;
    Some(&a.tool_calls[i])
}

fn assistant_message_input_item(text: &str) -> rs::InputItem {
    rs::InputItem::EasyMessage(rs::EasyInputMessage {
        r#type: rs::MessageType::Message,
        role: rs::Role::Assistant,
        content: rs::EasyInputContent::Text(text.to_owned()),
    })
}

/// A function call's JSON arguments. A call recorded in the freeform form (`from_freeform`) carries raw text, which
/// is wrapped under the tool's input key; anything else that is not JSON is sanitized to `{}` as before.
fn function_call_input_item(req: &ConversationRequest, tc: &ToolCall, from_freeform: bool) -> rs::InputItem {
    let arguments = if from_freeform
        && serde_json::from_str::<serde::de::IgnoredAny>(&tc.arguments).is_err()
    {
        let key = input_key(req, &tc.name);
        Arc::<str>::from(serde_json::json!({ key: tc.arguments.as_ref() }).to_string())
    } else {
        sanitize_tool_arguments(&tc.id, &tc.name, tc.arguments.clone())
    };
    rs::InputItem::Item(rs::Item::FunctionCall(rs::FunctionToolCall {
        call_id: tc.id.as_ref().to_owned(),
        name: tc.name.clone(),
        arguments: arguments.as_ref().to_owned(),
        id: None,
        status: None,
    }))
}

/// A freeform tool call replays verbatim: the input is the raw text the model produced, never JSON-wrapped.
/// A call stored in the JSON function form (`{"patch": text}`, or the `input` / `raw` envelopes) is unwrapped to its text.
fn custom_tool_call_input_item(req: &ConversationRequest, tc: &ToolCall, id: &str) -> rs::InputItem {
    let text = freeform_text(&tc.arguments, &input_key(req, &tc.name));
    rs::InputItem::Item(rs::Item::CustomToolCall(custom_tool_call(
        &tc.id, &tc.name, &text, id,
    )))
}

/// The freeform text behind stored arguments: the string under `key` (or `patch` / `input` / `raw`) of a JSON
/// object, else the arguments themselves.
fn freeform_text(arguments: &str, key: &str) -> String {
    if let Ok(serde_json::Value::Object(obj)) = serde_json::from_str::<serde_json::Value>(arguments) {
        for k in [key, "patch", "input", "raw"] {
            if let Some(serde_json::Value::String(text)) = obj.get(k) {
                return text.clone();
            }
        }
    }
    arguments.to_owned()
}

/// Build an `rs::CustomToolCall` (a `custom_tool_call` item).
/// The type is `#[non_exhaustive]` with no builder, so deserializing its four wire fields is the only constructor.
pub fn custom_tool_call(call_id: &str, name: &str, input: &str, id: &str) -> rs::CustomToolCall {
    serde_json::from_value(serde_json::json!({
        "call_id": call_id,
        "name": name,
        "input": input,
        "id": id,
    }))
    .expect("custom_tool_call has exactly these four fields")
}

fn tool_result_content_parts(t: &ToolResultItem) -> Vec<rs::InputContent> {
    let mut parts: Vec<rs::InputContent> = vec![rs::InputContent::InputText(rs::InputTextContent {
        text: t.content.as_ref().to_owned(),
    })];
    for img in &t.images {
        if let ContentPart::Image { url } = img {
            parts.push(rs::InputContent::InputImage(rs::InputImageContent {
                detail: rs::ImageDetail::Auto,
                file_id: None,
                image_url: Some(url.as_ref().to_owned()),
            }));
        }
    }
    parts
}

fn tool_result_to_input_item(t: &ToolResultItem, custom: bool) -> rs::InputItem {
    if custom {
        let output = if t.images.is_empty() {
            rs::CustomToolCallOutputOutput::Text(t.content.as_ref().to_owned())
        } else {
            rs::CustomToolCallOutputOutput::List(tool_result_content_parts(t))
        };
        return rs::InputItem::Item(rs::Item::CustomToolCallOutput(rs::CustomToolCallOutput {
            call_id: t.tool_call_id.clone(),
            output,
            id: None,
        }));
    }
    let output = if t.images.is_empty() {
        rs::FunctionCallOutput::Text(t.content.as_ref().to_owned())
    } else {
        rs::FunctionCallOutput::Content(tool_result_content_parts(t))
    };
    rs::InputItem::Item(rs::Item::FunctionCallOutput(
        rs::FunctionCallOutputItemParam {
            call_id: t.tool_call_id.clone(),
            output,
            id: None,
            status: None,
        },
    ))
}

/// Wire fixups `async-openai`'s input types cannot express:
/// - inject the `type: "reasoning_text"` discriminator the API requires (`ReasoningTextContent` has no `type` field,
///   so it serializes to `{"text": ...}` and the API answers 400);
/// - drop an empty `id` from a `custom_tool_call` (the field is mandatory on the struct but optional on input; it is
///   empty when a JSON-era call replays in the custom form).
/// Delete the first once upstream grows the field.
pub fn patch_reasoning_text_types(body: &mut serde_json::Value) {
    let Some(input) = body.get_mut("input").and_then(|v| v.as_array_mut()) else {
        return;
    };
    for item in input.iter_mut() {
        if item.get("type").and_then(|t| t.as_str()) == Some("custom_tool_call")
            && item.get("id").and_then(|i| i.as_str()) == Some("")
            && let Some(obj) = item.as_object_mut()
        {
            obj.remove("id");
            continue;
        }
        if item.get("type").and_then(|t| t.as_str()) != Some("reasoning") {
            continue;
        }
        let Some(content) = item.get_mut("content").and_then(|c| c.as_array_mut()) else {
            continue;
        };
        for c in content.iter_mut() {
            if let Some(obj) = c.as_object_mut() {
                obj.entry("type")
                    .or_insert_with(|| serde_json::Value::String("reasoning_text".into()));
            }
        }
    }
}

/// Strip what the API does not want back on a reasoning item.
/// `status` is output-only. With `store: false` the `encrypted_content` blob is the reasoning; plaintext `content`
/// beside it would only be the same reasoning twice (GPT-5.x omits it anyway), so it is dropped whenever the
/// encrypted blob is present. The `summary` stays: the API accepts it and it is what a display-only fallback carries.
pub(super) fn reasoning_item_for_input(r: &rs::ReasoningItem) -> rs::ReasoningItem {
    let mut r = r.clone();
    r.status = None;
    if r.encrypted_content.is_some() {
        r.content = None;
    }
    r
}

fn conversation_item_to_input_items(item: &ConversationItem) -> Vec<rs::InputItem> {
    match item {
        ConversationItem::System(s) => {
            vec![rs::InputItem::EasyMessage(rs::EasyInputMessage {
                r#type: rs::MessageType::Message,
                role: rs::Role::System,
                content: rs::EasyInputContent::Text(s.content.as_ref().to_owned()),
            })]
        }
        ConversationItem::User(u) => {
            let content = content_parts_to_easy_input_content(&u.content);
            vec![rs::InputItem::EasyMessage(rs::EasyInputMessage {
                r#type: rs::MessageType::Message,
                role: rs::Role::User,
                content,
            })]
        }
        ConversationItem::Reasoning(r) => {
            vec![rs::InputItem::Item(rs::Item::Reasoning(
                reasoning_item_for_input(r),
            ))]
        }
        ConversationItem::Assistant(a) => {
            let mut items = Vec::new();
            if !a.content.is_empty() {
                items.push(assistant_message_input_item(&a.content));
            }
            items.extend(a.tool_calls.iter().map(|tc| {
                let arguments = sanitize_tool_arguments(&tc.id, &tc.name, tc.arguments.clone());
                rs::InputItem::Item(rs::Item::FunctionCall(rs::FunctionToolCall {
                    call_id: tc.id.as_ref().to_owned(),
                    name: tc.name.clone(),
                    arguments: arguments.as_ref().to_owned(),
                    id: None,
                    status: None,
                }))
            }));
            items
        }
        ConversationItem::ToolResult(t) => vec![tool_result_to_input_item(t, false)],
        ConversationItem::BackendToolCall(b) => {
            vec![match &b.kind {
                BackendToolKind::WebSearch(ws) => {
                    rs::InputItem::Item(rs::Item::WebSearchCall(ws.clone()))
                }
                BackendToolKind::XSearch(ct) => {
                    rs::InputItem::Item(rs::Item::CustomToolCall(ct.clone()))
                }
                BackendToolKind::CodeInterpreter(ci) => {
                    rs::InputItem::Item(rs::Item::CodeInterpreterCall(ci.clone()))
                }
            }]
        }
    }
}

fn content_parts_to_easy_input_content(parts: &[ContentPart]) -> rs::EasyInputContent {
    if parts.len() == 1
        && let ContentPart::Text { text } = &parts[0]
    {
        return rs::EasyInputContent::Text(text.as_ref().to_owned());
    }

    let items: Vec<rs::InputContent> = parts
        .iter()
        .map(|part| match part {
            ContentPart::Text { text } => rs::InputContent::InputText(rs::InputTextContent {
                text: text.as_ref().to_owned(),
            }),
            ContentPart::Image { url } => rs::InputContent::InputImage(rs::InputImageContent {
                image_url: Some(url.as_ref().to_owned()),
                file_id: None,
                detail: rs::ImageDetail::default(),
            }),
        })
        .collect();

    rs::EasyInputContent::ContentList(items)
}

/// The request's client tools: JSON function tools, or `custom` (grammar-constrained freeform) tools for specs that carry a
/// [`FreeformFormat`].
/// A tool whose name collides with a backend-hosted tool is dropped: sending both is rejected as a duplicate, so the hosted tool wins.
///
/// No hosted tool is emitted here.
/// Both ride the raw-JSON [`extra_tool_entries`] channel instead.
fn build_responses_tools(req: &ConversationRequest) -> Vec<rs::Tool> {
    let tools: Vec<rs::Tool> = req
        .tools
        .iter()
        .filter(|t| {
            let collides = req.hosted_tools.iter().any(|h| h.wire_name() == t.name);
            if collides {
                tracing::warn!(
                    tool = %t.name,
                    "dropping function tool that collides with a backend-hosted tool"
                );
            }
            !collides
        })
        .map(|t| match &t.freeform {
            Some(format) => rs::Tool::Custom(rs::CustomToolParam {
                name: t.name.clone(),
                description: t.description.clone(),
                format: rs::CustomToolParamFormat::Grammar(rs::CustomGrammarFormatParam {
                    definition: format.definition.clone(),
                    syntax: match format.syntax {
                        FreeformSyntax::Lark => rs::GrammarSyntax::Lark,
                        FreeformSyntax::Regex => rs::GrammarSyntax::Regex,
                    },
                }),
            }),
            None => rs::Tool::Function(rs::FunctionTool {
                name: t.name.clone(),
                description: t.description.clone(),
                parameters: Some(t.parameters.clone()),
                strict: None,
            }),
        })
        .collect();

    tools
}

/// Every hosted tool as a raw JSON entry, which the sampler client splices into the serialized `tools` array.
/// `x_search` rides this channel because it has no `rs::Tool` variant.
/// `web_search` rides it because async_openai's `rs::WebSearchToolFilters` models only `allowed_domains` and cannot carry `excluded_domains`.
/// Emitting either as a typed `rs::Tool` as well would send it twice, which the API rejects as a duplicate.
/// The JSON built here is byte-identical to the native `rs::Tool::WebSearch` for the no-filter and allowlist-only cases.
pub fn extra_tool_entries(hosted_tools: &[HostedTool]) -> Vec<serde_json::Value> {
    let mut entries = Vec::new();
    for tool in hosted_tools {
        match tool {
            HostedTool::WebSearch { options } => {
                entries.push(match options {
                    Some(o) => o.to_tool_entry(),
                    None => WebSearchOptions::default().to_tool_entry(),
                });
            }
            HostedTool::XSearch { options } => {
                entries.push(match options {
                    Some(o) => o.to_tool_entry(),
                    None => XSearchOptions::default().to_tool_entry(),
                });
            }
        }
    }
    entries
}
