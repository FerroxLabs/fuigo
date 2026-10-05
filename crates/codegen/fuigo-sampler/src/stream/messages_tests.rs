//! These tests live outside `messages.rs` so the implementation reads top-to-bottom.
//! `#[path = "messages_tests.rs"] mod tests;` in messages.rs wires them in.

use super::*;
use futures_util::stream;
use std::pin::pin;
use fuigo_sampling_types::messages::{
    ContentBlock, MessageDeltaBody, MessageDeltaUsage, MessagesResponse, MessagesUsage,
    StreamDelta, StreamError,
};
use fuigo_sampling_types::serde_helpers::Open;

fn rid() -> RequestId {
    RequestId::from("msg-test")
}

fn message_start() -> MessageStreamEvent {
    MessageStreamEvent::MessageStart {
        message: MessagesResponse {
            id: "msg_1".into(),
            r#type: "message".into(),
            role: "assistant".into(),
            content: vec![],
            model: "messages-compatible-model".into(),
            stop_reason: None,
            usage: MessagesUsage {
                input_tokens: 10,
                output_tokens: 0,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            },
        },
    }
}

fn text_block_start(index: u32) -> MessageStreamEvent {
    MessageStreamEvent::ContentBlockStart {
        index,
        content_block: Open::Known(ContentBlock::Text {
            text: String::new(),
            cache_control: None,
        }),
    }
}

fn text_delta(index: u32, text: &str) -> MessageStreamEvent {
    MessageStreamEvent::ContentBlockDelta {
        index,
        delta: Open::Known(StreamDelta::TextDelta { text: text.into() }),
    }
}

fn block_stop(index: u32) -> MessageStreamEvent {
    MessageStreamEvent::ContentBlockStop { index }
}

fn message_delta_with_stop(stop: messages::StopReason) -> MessageStreamEvent {
    MessageStreamEvent::MessageDelta {
        delta: MessageDeltaBody {
            stop_reason: Some(stop),
            stop_sequence: None,
            stop_details: None,
        },
        usage: MessageDeltaUsage {
            output_tokens: 5,
            input_tokens: Some(10),
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
        },
    }
}

/// A refusal `message_delta` carrying a provider `stop_details.explanation`, mirroring the Anthropic Messages API ToS auto-refusal wire shape.
fn message_delta_refusal_with_explanation(explanation: &str) -> MessageStreamEvent {
    MessageStreamEvent::MessageDelta {
        delta: MessageDeltaBody {
            stop_reason: Some(messages::StopReason::Refusal),
            stop_sequence: None,
            stop_details: Some(messages::StopDetails {
                r#type: Some("refusal".to_string()),
                category: Some("frontier_llm".to_string()),
                explanation: Some(explanation.to_string()),
            }),
        },
        usage: MessageDeltaUsage {
            output_tokens: 0,
            input_tokens: Some(10),
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
        },
    }
}

async fn collect(s: impl Stream<Item = SamplingEvent>) -> Vec<SamplingEvent> {
    let mut out = Vec::new();
    let mut s = pin!(s);
    while let Some(ev) = s.next().await {
        out.push(ev);
    }
    out
}

#[tokio::test]
async fn empty_stream_yields_started_then_completed() {
    let raw = stream::iter(Vec::<Result<MessageStreamEvent, SamplingError>>::new()).boxed();
    let events = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], SamplingEvent::StreamStarted { .. }));
    assert!(matches!(events[1], SamplingEvent::Completed { .. }));
}

#[tokio::test]
async fn text_block_assembles_into_completed_response() {
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(text_block_start(0)),
        Ok(text_delta(0, "Hello, ")),
        Ok(text_delta(0, "world!")),
        Ok(block_stop(0)),
        Ok(message_delta_with_stop(messages::StopReason::EndTurn)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    let text_tokens: Vec<&str> = evs
        .iter()
        .filter_map(|e| match e {
            SamplingEvent::ChannelToken {
                channel: SamplingChannel::Text,
                text,
                ..
            } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(text_tokens, vec!["Hello, ", "world!"]);

    match evs.last().unwrap() {
        SamplingEvent::Completed { response, .. } => {
            let a = response.assistant().expect("assistant item present");
            assert_eq!(a.content.as_ref(), "Hello, world!");
            assert_eq!(a.model_id.as_deref(), Some("messages-compatible-model"));
            assert_eq!(response.stop_reason, Some(StopReason::Stop));
            // Provider message id and the verbatim wire stop reason survive onto the response (collapsed `stop_reason` loses the string)
            assert_eq!(response.message_id.as_deref(), Some("msg_1"));
            assert_eq!(response.raw_stop_reason.as_deref(), Some("end_turn"));
            let u = response.usage.as_ref().expect("usage extracted");
            assert_eq!(u.prompt_tokens, 10);
            assert_eq!(u.completion_tokens, 5);
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

#[tokio::test]
async fn thinking_block_emits_reasoning_channel_and_preserved_in_response() {
    let thinking_start = MessageStreamEvent::ContentBlockStart {
        index: 0,
        content_block: Open::Known(ContentBlock::Thinking {
            thinking: String::new(),
            signature: String::new(),
        }),
    };
    let thinking_delta = MessageStreamEvent::ContentBlockDelta {
        index: 0,
        delta: Open::Known(StreamDelta::ThinkingDelta {
            thinking: "let me think...".into(),
        }),
    };
    let sig_delta = MessageStreamEvent::ContentBlockDelta {
        index: 0,
        delta: Open::Known(StreamDelta::SignatureDelta {
            signature: "abc123".into(),
        }),
    };
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(thinking_start),
        Ok(thinking_delta),
        Ok(sig_delta),
        Ok(block_stop(0)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    let reasoning_tokens: Vec<&str> = evs
        .iter()
        .filter_map(|e| match e {
            SamplingEvent::ChannelToken {
                channel: SamplingChannel::Reasoning,
                text,
                ..
            } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(reasoning_tokens, vec!["let me think..."]);

    match evs.last().unwrap() {
        SamplingEvent::Completed { response, .. } => {
            let r = response
                .reasoning_items()
                .next()
                .expect("reasoning sibling preserved");
            let rs::SummaryPart::SummaryText(t) = &r.summary[0];
            assert_eq!(t.text, "let me think...");
            assert_eq!(r.encrypted_content.as_deref(), Some("abc123"));
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

/// `thinking(sig1) → text → thinking(sig2)` must emit each thinking block's own signature, in order, on its own `ReasoningCompleted`.
/// The event fires at the block's stop, so per-index signatures reach the headless reducer instead of collapsing to one.
#[tokio::test]
async fn multiple_thinking_blocks_emit_per_block_signatures_in_order() {
    let thinking_block = |index: u32, text: &str, sig: &str| {
        vec![
            Ok(MessageStreamEvent::ContentBlockStart {
                index,
                content_block: Open::Known(ContentBlock::Thinking {
                    thinking: String::new(),
                    signature: String::new(),
                }),
            }),
            Ok(MessageStreamEvent::ContentBlockDelta {
                index,
                delta: Open::Known(StreamDelta::ThinkingDelta {
                    thinking: text.into(),
                }),
            }),
            Ok(MessageStreamEvent::ContentBlockDelta {
                index,
                delta: Open::Known(StreamDelta::SignatureDelta {
                    signature: sig.into(),
                }),
            }),
            Ok(block_stop(index)),
        ]
    };
    let mut events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![Ok(message_start())];
    events.extend(thinking_block(0, "first", "sig-1"));
    events.push(Ok(text_block_start(1)));
    events.push(Ok(text_delta(1, "interlude")));
    events.push(Ok(block_stop(1)));
    events.extend(thinking_block(2, "second", "sig-2"));
    events.push(Ok(MessageStreamEvent::MessageStop));

    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    let sigs: Vec<&str> = evs
        .iter()
        .filter_map(|e| match e {
            SamplingEvent::ReasoningCompleted { signature, .. } => Some(signature.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        sigs,
        vec!["sig-1", "sig-2"],
        "each thinking block emits its own signature in order"
    );
}

#[tokio::test]
async fn tool_use_block_assembles_into_tool_call() {
    let tool_start = MessageStreamEvent::ContentBlockStart {
        index: 0,
        content_block: Open::Known(ContentBlock::ToolUse {
            id: "call_xyz".into(),
            name: "do_thing".into(),
            input: serde_json::json!({}),
            // Set: a parser matching only the absent case must fail here.
            cache_control: Some(fuigo_sampling_types::messages::CacheControl::ephemeral()),
        }),
    };
    let arg_delta_1 = MessageStreamEvent::ContentBlockDelta {
        index: 0,
        delta: Open::Known(StreamDelta::InputJsonDelta {
            partial_json: "{\"x\":".into(),
        }),
    };
    let arg_delta_2 = MessageStreamEvent::ContentBlockDelta {
        index: 0,
        delta: Open::Known(StreamDelta::InputJsonDelta {
            partial_json: "1}".into(),
        }),
    };
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(tool_start),
        Ok(arg_delta_1),
        Ok(arg_delta_2),
        Ok(block_stop(0)),
        Ok(message_delta_with_stop(messages::StopReason::ToolUse)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    let deltas: Vec<_> = evs
        .iter()
        .filter_map(|e| match e {
            SamplingEvent::ToolCallDelta {
                tool_index,
                id,
                name,
                arguments_delta,
                ..
            } => Some((
                *tool_index,
                id.clone(),
                name.clone(),
                arguments_delta.clone(),
            )),
            _ => None,
        })
        .collect();
    assert_eq!(deltas.len(), 3);
    assert_eq!(deltas[0].0, 0);
    assert_eq!(deltas[0].1.as_deref(), Some("call_xyz"));
    assert_eq!(deltas[0].2.as_deref(), Some("do_thing"));
    assert_eq!(deltas[0].3, None);
    assert_eq!(deltas[1].3.as_deref(), Some("{\"x\":"));
    assert_eq!(deltas[2].3.as_deref(), Some("1}"));

    match evs.last().unwrap() {
        SamplingEvent::Completed { response, .. } => {
            let calls = response.tool_calls();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].id.as_ref(), "call_xyz");
            assert_eq!(calls[0].name, "do_thing");
            assert_eq!(calls[0].arguments.as_ref(), "{\"x\":1}");
            assert_eq!(response.stop_reason, Some(StopReason::ToolCalls));
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

/// Regression: a stream whose terminal `message_delta` carries `stop_reason: "refusal"` must complete cleanly.
/// Erroring out would discard the already-streamed response.
#[tokio::test]
async fn refusal_stop_reason_completes_stream() {
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(text_block_start(0)),
        Ok(text_delta(0, "I can't help with that.")),
        Ok(block_stop(0)),
        Ok(message_delta_with_stop(messages::StopReason::Refusal)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    assert!(
        !evs.iter()
            .any(|e| matches!(e, SamplingEvent::Failed { .. })),
        "refusal stream must not yield Failed: {evs:?}"
    );
    match evs.last().unwrap() {
        SamplingEvent::Completed { response, .. } => {
            let a = response.assistant().expect("assistant item present");
            assert_eq!(a.content.as_ref(), "I can't help with that.");
            assert_eq!(response.stop_reason, Some(StopReason::ContentFilter));
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

/// A refusal `stop_details.explanation` on the terminal delta must land on the completed `ConversationResponse.stop_message`.
/// The agent loop shows the provider's reason from there; otherwise the turn ends empty and silent.
#[tokio::test]
async fn refusal_stop_message_flows_to_response() {
    let explanation = "This request was blocked by the provider's content policy.";
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(message_delta_refusal_with_explanation(explanation)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    match evs.last().unwrap() {
        SamplingEvent::Completed { response, .. } => {
            assert_eq!(response.stop_reason, Some(StopReason::ContentFilter));
            assert_eq!(
                response.stop_message.as_deref(),
                Some(explanation),
                "provider explanation normalized onto stop_message"
            );
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

#[tokio::test]
async fn pause_turn_and_unknown_stop_reasons_complete_as_stop() {
    for stop in [
        messages::StopReason::PauseTurn,
        messages::StopReason::Unknown("mystery_reason".to_string()),
    ] {
        let label = format!("{stop:?}");
        let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
            Ok(message_start()),
            Ok(text_block_start(0)),
            Ok(text_delta(0, "partial answer")),
            Ok(block_stop(0)),
            Ok(message_delta_with_stop(stop)),
            Ok(MessageStreamEvent::MessageStop),
        ];
        let raw = stream::iter(events).boxed();
        let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;
        match evs.last().unwrap() {
            SamplingEvent::Completed { response, .. } => {
                assert_eq!(
                    response.stop_reason,
                    Some(StopReason::Stop),
                    "{label} must end the turn like stop"
                );
            }
            other => panic!("{label}: expected Completed, got {other:?}"),
        }
    }
}

/// A plain `max_tokens` stop with only text completes with `stop_reason=Length` and keeps the partial text.
#[tokio::test]
async fn max_tokens_text_only_completes_with_length_stop() {
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(text_block_start(0)),
        Ok(text_delta(0, "cut answ")),
        Ok(block_stop(0)),
        Ok(message_delta_with_stop(messages::StopReason::MaxTokens)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    match evs.last().unwrap() {
        SamplingEvent::Completed { response, .. } => {
            assert_eq!(response.stop_reason, Some(StopReason::Length));
            assert_eq!(response.assistant_text(), "cut answ");
        }
        other => panic!("expected Completed(Length), got {other:?}"),
    }
}

/// A max_tokens stop carrying a completed tool_use block keeps `stop_reason=Length`.
/// The ToolCalls override must not mask the truncation: the block's arguments may be a silently-truncated prefix.
#[tokio::test]
async fn max_tokens_with_tool_use_keeps_length_stop() {
    let tool_start = MessageStreamEvent::ContentBlockStart {
        index: 0,
        content_block: Open::Known(ContentBlock::ToolUse {
            id: "call_cut".into(),
            name: "do_thing".into(),
            input: serde_json::json!({}),
            cache_control: None,
        }),
    };
    let arg_delta = MessageStreamEvent::ContentBlockDelta {
        index: 0,
        delta: Open::Known(StreamDelta::InputJsonDelta {
            partial_json: "{\"x\": \"trunc".into(),
        }),
    };
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(tool_start),
        Ok(arg_delta),
        Ok(block_stop(0)),
        Ok(message_delta_with_stop(messages::StopReason::MaxTokens)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    match evs.last().unwrap() {
        SamplingEvent::Completed { response, .. } => {
            assert_eq!(response.stop_reason, Some(StopReason::Length));
            assert_eq!(response.tool_calls().len(), 1, "tool call still carried");
        }
        other => panic!("expected Completed(Length), got {other:?}"),
    }
}

/// A tool_use block closed with zero argument deltas collects as an empty-arguments tool call.
/// That is the shape `LengthPolicy::verdict` salvages.
#[tokio::test]
async fn max_tokens_tool_use_without_arg_deltas_collects_empty_arguments() {
    let tool_start = MessageStreamEvent::ContentBlockStart {
        index: 0,
        content_block: Open::Known(ContentBlock::ToolUse {
            id: "call_no_args".into(),
            name: "do_thing".into(),
            input: serde_json::json!({}),
            cache_control: None,
        }),
    };
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(tool_start),
        Ok(block_stop(0)),
        Ok(message_delta_with_stop(messages::StopReason::MaxTokens)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    match evs.last().unwrap() {
        SamplingEvent::Completed { response, .. } => {
            assert_eq!(response.stop_reason, Some(StopReason::Length));
            assert_eq!(response.tool_calls().len(), 1);
            assert_eq!(response.tool_calls()[0].arguments.as_ref(), "");
        }
        other => panic!("expected Completed(Length), got {other:?}"),
    }
}

/// Pins the model_context_window_exceeded decision: it maps to the Length stop class and COMPLETES with the partial preserved.
/// Fail-vs-salvage belongs to `drive_l2`, not this transform.
#[tokio::test]
async fn model_context_window_exceeded_completes_with_length_stop() {
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(text_block_start(0)),
        Ok(text_delta(0, "truncated answ")),
        Ok(block_stop(0)),
        Ok(message_delta_with_stop(
            messages::StopReason::ModelContextWindowExceeded,
        )),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    match evs.last().unwrap() {
        SamplingEvent::Completed { response, .. } => {
            assert_eq!(response.stop_reason, Some(StopReason::Length));
            assert_eq!(
                response.assistant_text(),
                "truncated answ",
                "partial content must be preserved"
            );
        }
        other => panic!("expected Completed(Length), got {other:?}"),
    }
}

/// Pins the override: completed tool_use blocks beat a terminal Refusal, so the agent loop still resolves the calls.
#[tokio::test]
async fn refusal_after_tool_use_blocks_keeps_tool_calls_stop_reason() {
    let tool_start = MessageStreamEvent::ContentBlockStart {
        index: 0,
        content_block: Open::Known(ContentBlock::ToolUse {
            id: "call_refused".into(),
            name: "do_thing".into(),
            input: serde_json::json!({}),
            cache_control: None,
        }),
    };
    let arg_delta = MessageStreamEvent::ContentBlockDelta {
        index: 0,
        delta: Open::Known(StreamDelta::InputJsonDelta {
            partial_json: "{}".into(),
        }),
    };
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(tool_start),
        Ok(arg_delta),
        Ok(block_stop(0)),
        Ok(message_delta_with_stop(messages::StopReason::Refusal)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    match evs.last().unwrap() {
        SamplingEvent::Completed { response, .. } => {
            assert_eq!(response.tool_calls().len(), 1);
            assert_eq!(
                response.stop_reason,
                Some(StopReason::ToolCalls),
                "tool_use blocks must win over the refusal stop_reason"
            );
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

#[tokio::test]
async fn server_error_event_yields_failed_500() {
    let err_event = MessageStreamEvent::Error {
        error: StreamError {
            r#type: "overloaded_error".into(),
            message: "rate limit hit".into(),
        },
    };
    let raw = stream::iter(vec![Ok(message_start()), Ok(err_event)]).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    match evs.last().unwrap() {
        SamplingEvent::Failed { error, .. } => {
            assert_eq!(error.kind, crate::events::SamplingErrorKind::Api);
            assert_eq!(error.status_code, Some(500));
            assert!(error.message.contains("overloaded_error"));
            // Messages error events have no code slot; a code appearing here would make typed events eligible for a destructive image strip
            assert_eq!(error.error_code, None);
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[tokio::test]
async fn mid_stream_transport_error_yields_failed() {
    let raw = stream::iter(vec![
        Ok(message_start()),
        Err(SamplingError::EventStreamError("conn reset".into())),
    ])
    .boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;
    assert!(
        evs.iter()
            .any(|e| matches!(e, SamplingEvent::Failed { .. }))
    );
    assert!(
        !evs.iter()
            .any(|e| matches!(e, SamplingEvent::Completed { .. }))
    );
}

#[tokio::test(start_paused = true)]
async fn idle_timeout_when_stream_stalls() {
    let raw = stream::iter(vec![Ok(message_start())])
        .chain(stream::pending())
        .boxed();
    let evs = collect(stream_messages(
        raw,
        None,
        rid(),
        Duration::from_millis(100),
    ))
    .await;

    match evs.last().unwrap() {
        SamplingEvent::Failed { error, .. } => {
            assert_eq!(error.kind, crate::events::SamplingErrorKind::IdleTimeout);
        }
        other => panic!("expected Failed(IdleTimeout), got {other:?}"),
    }
}

#[tokio::test]
async fn model_metadata_yielded_after_stream_started() {
    let raw = stream::iter(vec![Ok(MessageStreamEvent::MessageStop)]).boxed();
    let metadata = ResponseModelMetadata {
        context_window: Some(200_000),
        ..Default::default()
    };
    let evs = collect(stream_messages(
        raw,
        Some(metadata),
        rid(),
        Duration::from_secs(60),
    ))
    .await;

    assert!(matches!(evs[0], SamplingEvent::StreamStarted { .. }));
    assert!(matches!(evs[1], SamplingEvent::ModelMetadata { .. }));
}

#[test]
fn meaningful_content_classifier_treats_ping_as_keepalive() {
    assert!(!messages_event_has_meaningful_content(
        &MessageStreamEvent::Ping
    ));
    assert!(messages_event_has_meaningful_content(
        &MessageStreamEvent::MessageStop
    ));
}

// ── Token usage: Anthropic Messages API cache-bucket accounting ────────────

fn message_start_with_cache(
    input: u32,
    cache_read: u32,
    cache_creation: u32,
) -> MessageStreamEvent {
    MessageStreamEvent::MessageStart {
        message: MessagesResponse {
            id: "msg_cache".into(),
            r#type: "message".into(),
            role: "assistant".into(),
            content: vec![],
            model: "messages-compatible-model".into(),
            stop_reason: None,
            usage: MessagesUsage {
                input_tokens: input,
                output_tokens: 0,
                cache_creation_input_tokens: cache_creation,
                cache_read_input_tokens: cache_read,
            },
        },
    }
}

fn message_delta_with_cache(
    output: u32,
    input: Option<u32>,
    cache_read: Option<u32>,
    cache_creation: Option<u32>,
) -> MessageStreamEvent {
    MessageStreamEvent::MessageDelta {
        delta: MessageDeltaBody {
            stop_reason: Some(messages::StopReason::EndTurn),
            stop_sequence: None,
            stop_details: None,
        },
        usage: MessageDeltaUsage {
            output_tokens: output,
            input_tokens: input,
            cache_read_input_tokens: cache_read,
            cache_creation_input_tokens: cache_creation,
        },
    }
}

/// Drive a minimal stream with the supplied usage events and pluck the `TokenUsage` out of the terminal `Completed` event.
async fn usage_from_stream(events: Vec<MessageStreamEvent>) -> TokenUsage {
    let raw = stream::iter(
        events
            .into_iter()
            .map(Ok::<_, SamplingError>)
            .collect::<Vec<_>>(),
    )
    .boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;
    match evs.last().expect("at least one event") {
        SamplingEvent::Completed { response, .. } => response
            .usage
            .clone()
            .expect("usage should be emitted when prompt or output tokens > 0"),
        other => panic!("expected Completed, got {other:?}"),
    }
}

#[tokio::test]
async fn prompt_tokens_sums_all_three_anthropic_buckets() {
    // cached_prompt_tokens counts cache_read only (writes aren't a hit)
    let usage = usage_from_stream(vec![
        message_start_with_cache(100, 5000, 200),
        text_block_start(0),
        text_delta(0, "ok"),
        block_stop(0),
        message_delta_with_cache(7, None, None, None),
        MessageStreamEvent::MessageStop,
    ])
    .await;

    assert_eq!(usage.prompt_tokens, 100 + 5000 + 200);
    assert_eq!(usage.cached_prompt_tokens, 5000);
    assert_eq!(usage.cache_creation_prompt_tokens, 200);
    assert_eq!(usage.completion_tokens, 7);
    assert_eq!(usage.total_tokens, 100 + 5000 + 200 + 7);
}

#[tokio::test]
async fn message_delta_cache_fields_override_message_start() {
    // Providers can report zero cache at message_start and emit the real values on the final delta; honor the delta when present
    let usage = usage_from_stream(vec![
        message_start_with_cache(10, 0, 0),
        message_delta_with_cache(4, Some(10), Some(900), Some(50)),
        MessageStreamEvent::MessageStop,
    ])
    .await;

    assert_eq!(usage.prompt_tokens, 10 + 900 + 50);
    assert_eq!(usage.cached_prompt_tokens, 900);
    assert_eq!(usage.cache_creation_prompt_tokens, 50);
    assert_eq!(usage.completion_tokens, 4);
}

#[tokio::test]
async fn pure_cache_hit_with_zero_uncached_still_emits_usage() {
    // 100% cache hit: Anthropic Messages API reports input_tokens=0 with cache_read>0.
    // Usage must still be emitted so callers see the cached cost
    let usage = usage_from_stream(vec![
        message_start_with_cache(0, 2500, 0),
        message_delta_with_cache(1, None, None, None),
        MessageStreamEvent::MessageStop,
    ])
    .await;

    assert_eq!(usage.prompt_tokens, 2500);
    assert_eq!(usage.cached_prompt_tokens, 2500);
    assert_eq!(usage.total_tokens, 2501);
}

/// Tolerating an unmodelled content block must not hand a stalled turn an unlimited extension:
/// an unknown block is never "meaningful content", so the content clock still runs down on it.
/// This is the trap a forward-compatibility fix creates -- the naive version appends the new
/// variant to the `=> true` list and a provider streaming junk then holds the turn open forever.
#[test]
fn unmodelled_content_blocks_are_never_meaningful_content() {
    let unknown_block = MessageStreamEvent::ContentBlockStart {
        index: 0,
        content_block: Open::Unknown(serde_json::json!({"type":"server_tool_use","id":"s1"})),
    };
    let unknown_delta = MessageStreamEvent::ContentBlockDelta {
        index: 0,
        delta: Open::Unknown(serde_json::json!({"type":"citations_delta","citation":{}})),
    };
    assert!(!messages_event_has_meaningful_content(&unknown_block));
    assert!(!messages_event_has_meaningful_content(&unknown_delta));
    // …while the modelled forms still are.
    assert!(messages_event_has_meaningful_content(&text_block_start(0)));
    assert!(messages_event_has_meaningful_content(&text_delta(0, "hi")));
    // And `ping`, the real heartbeat, remains non-content.
    assert!(!messages_event_has_meaningful_content(
        &MessageStreamEvent::Ping
    ));
}

/// THE regression this packet was reopened for.
///
/// An unmodelled `content_block_delta` is dropped instead of failing the parse -- but the block it
/// belongs to stays open, so `content_block_stop` used to finalize a `ToolCall` out of whatever
/// fragments survived, and the turn reported `StopReason::ToolCalls`: success.
///
/// The dangerous position is the MIDDLE of the argument sequence, not the tail. A tail drop leaves
/// invalid JSON, which is loud at the tool boundary. A middle drop concatenates
/// `{"a":1,` + <dropped> + `"c":3}` into `{"a":1,"c":3}` -- syntactically valid, one parameter gone.
/// Substitute a real tool and it is an `Edit` that lost `old_string`, or a `Write` that lost part of
/// `content`, executing with arguments the model never sent while everything reports fine.
///
/// So: the turn must FAIL. This asserts both halves -- that it fails, and that no tool call with
/// altered arguments ever reaches a consumer.
#[tokio::test]
async fn mid_sequence_unmodelled_delta_on_a_tool_use_block_fails_the_turn() {
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(MessageStreamEvent::ContentBlockStart {
            index: 0,
            content_block: Open::Known(ContentBlock::ToolUse {
                id: "call_edit".into(),
                name: "Edit".into(),
                input: serde_json::json!({}),
                cache_control: None,
            }),
        }),
        Ok(MessageStreamEvent::ContentBlockDelta {
            index: 0,
            delta: Open::Known(StreamDelta::InputJsonDelta {
                partial_json: "{\"a\":1,".into(),
            }),
        }),
        // The provider ships a delta type this client does not model, in the middle of the
        // arguments. Whatever it carried is now unrecoverable.
        Ok(MessageStreamEvent::ContentBlockDelta {
            index: 0,
            delta: Open::Unknown(serde_json::json!({
                "type": "input_json_patch_delta",
                "patch": [{"op": "add", "path": "/b", "value": 2}],
            })),
        }),
        Ok(MessageStreamEvent::ContentBlockDelta {
            index: 0,
            delta: Open::Known(StreamDelta::InputJsonDelta {
                partial_json: "\"c\":3}".into(),
            }),
        }),
        Ok(block_stop(0)),
        Ok(message_delta_with_stop(messages::StopReason::ToolUse)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    // No completed turn, and above all no tool call built from the mutilated arguments.
    for ev in &evs {
        if let SamplingEvent::Completed { response, .. } = ev {
            panic!(
                "the turn completed with tool_calls {:?} after a delta was silently dropped from \
                 the middle of its arguments; `{{\"a\":1,\"c\":3}}` is valid JSON missing a \
                 parameter the model sent, and executing it is the whole defect",
                response.tool_calls()
            );
        }
    }

    match evs.last().expect("at least one event") {
        SamplingEvent::Failed { error, .. } => {
            // Same classification the pre-packet abort had: a parse-level failure, never retried.
            assert_eq!(error.kind, crate::events::SamplingErrorKind::Serialization);
            assert!(!error.is_retryable, "resending cannot un-drop the delta");
            // The diagnostic must name the unmodelled type and the tool, or the next incident is
            // unreadable -- "no diagnostic at all" is what the design note calls strictly worse.
            assert!(
                error.message.contains("input_json_patch_delta"),
                "the failure must name the unmodelled delta type, got: {}",
                error.message
            );
            assert!(
                error.message.contains("Edit"),
                "the failure must name the tool whose arguments were lost, got: {}",
                error.message
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// The same guard must not depend on WHERE the drop landed. A trailing drop happens to leave
/// invalid JSON, so the tool boundary would have caught it -- but correctness cannot rest on the
/// provider's chunk boundaries, so this fails for the same reason and by the same path.
#[tokio::test]
async fn trailing_unmodelled_delta_on_a_tool_use_block_also_fails_the_turn() {
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(MessageStreamEvent::ContentBlockStart {
            index: 0,
            content_block: Open::Known(ContentBlock::ToolUse {
                id: "call_write".into(),
                name: "Write".into(),
                input: serde_json::json!({}),
                cache_control: None,
            }),
        }),
        Ok(MessageStreamEvent::ContentBlockDelta {
            index: 0,
            delta: Open::Known(StreamDelta::InputJsonDelta {
                partial_json: "{\"path\":\"/tmp/x\"".into(),
            }),
        }),
        Ok(MessageStreamEvent::ContentBlockDelta {
            index: 0,
            delta: Open::Unknown(serde_json::json!({"type": "future_delta"})),
        }),
        Ok(block_stop(0)),
        Ok(message_delta_with_stop(messages::StopReason::ToolUse)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    assert!(
        !evs.iter()
            .any(|e| matches!(e, SamplingEvent::Completed { .. })),
        "a tool_use block that lost a delta must never complete the turn"
    );
    assert!(matches!(evs.last(), Some(SamplingEvent::Failed { .. })));
}

/// The asymmetry, asserted rather than assumed: a dropped delta on a TEXT block is tolerated.
///
/// Nothing executes prose. The gap is visible to the reader and warned about in the log, and failing
/// the turn over it would discard a complete, already-billed response -- the exact harm this packet
/// exists to prevent. Only arguments that a program will act on are worth a dead turn. If this test
/// ever has to change, the cost is a whole class of turns dying over cosmetic drift.
#[tokio::test]
async fn unmodelled_delta_on_a_text_block_is_tolerated_and_the_turn_completes() {
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(text_block_start(0)),
        Ok(text_delta(0, "first ")),
        Ok(MessageStreamEvent::ContentBlockDelta {
            index: 0,
            delta: Open::Unknown(serde_json::json!({"type": "citations_delta", "citation": {}})),
        }),
        Ok(text_delta(0, "second")),
        Ok(block_stop(0)),
        Ok(message_delta_with_stop(messages::StopReason::EndTurn)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    match evs.last().expect("at least one event") {
        SamplingEvent::Completed { response, .. } => {
            let a = response.assistant().expect("assistant item present");
            assert_eq!(a.content.as_ref(), "first second");
            assert_eq!(response.stop_reason, Some(StopReason::Stop));
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

/// A tool_use block is judged on ITS OWN dropped delta, not another block's. A text block losing a
/// delta earlier in the same turn must not poison a well-formed tool call that follows -- the guard
/// is per-block state, and a whole-stream flag would over-fire and kill good turns.
#[tokio::test]
async fn a_dropped_delta_on_one_block_does_not_fail_another_blocks_tool_call() {
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(text_block_start(0)),
        Ok(MessageStreamEvent::ContentBlockDelta {
            index: 0,
            delta: Open::Unknown(serde_json::json!({"type": "citations_delta"})),
        }),
        Ok(text_delta(0, "hi")),
        Ok(block_stop(0)),
        Ok(MessageStreamEvent::ContentBlockStart {
            index: 1,
            content_block: Open::Known(ContentBlock::ToolUse {
                id: "call_ok".into(),
                name: "Read".into(),
                input: serde_json::json!({}),
                cache_control: None,
            }),
        }),
        Ok(MessageStreamEvent::ContentBlockDelta {
            index: 1,
            delta: Open::Known(StreamDelta::InputJsonDelta {
                partial_json: "{\"path\":\"/tmp/y\"}".into(),
            }),
        }),
        Ok(block_stop(1)),
        Ok(message_delta_with_stop(messages::StopReason::ToolUse)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    match evs.last().expect("at least one event") {
        SamplingEvent::Completed { response, .. } => {
            let calls = response.tool_calls();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].arguments.as_ref(), "{\"path\":\"/tmp/y\"}");
            assert_eq!(response.stop_reason, Some(StopReason::ToolCalls));
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

/// An unmodelled delta addressed to an index with no open block is still harmless: no block state
/// exists, so nothing can be finalized from it and no later block inherits the drop.
#[tokio::test]
async fn unmodelled_delta_for_an_unopened_block_does_not_fail_the_turn() {
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        // An unmodelled content BLOCK opens no state, by design.
        Ok(MessageStreamEvent::ContentBlockStart {
            index: 0,
            content_block: Open::Unknown(
                serde_json::json!({"type": "server_tool_use", "id": "s1"}),
            ),
        }),
        Ok(MessageStreamEvent::ContentBlockDelta {
            index: 0,
            delta: Open::Unknown(serde_json::json!({"type": "server_tool_use_delta"})),
        }),
        Ok(block_stop(0)),
        Ok(text_block_start(1)),
        Ok(text_delta(1, "ok")),
        Ok(block_stop(1)),
        Ok(message_delta_with_stop(messages::StopReason::EndTurn)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    match evs.last().expect("at least one event") {
        SamplingEvent::Completed { response, .. } => {
            let a = response.assistant().expect("assistant item present");
            assert_eq!(a.content.as_ref(), "ok");
            assert!(response.tool_calls().is_empty());
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

/// An unmodelled `stop_reason` that names a token limit maps to `Length`, not `Stop`.
///
/// The Messages backend's `StopReason::Unknown` arm predates this packet (it is in the `2eb306e`
/// baseline), so this is a pre-existing silent-wrong rather than a P12b regression -- but it is the
/// identical defect: a gateway fronting this backend spells the same stop `MAX_TOKENS` or `length`,
/// and `Length` is what drives truncation handling and compaction.
#[tokio::test]
async fn unmodelled_token_limit_stop_reason_maps_to_length() {
    for wire in ["MAX_TOKENS", "max_tokens", "length", "length_limit"] {
        let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
            Ok(message_start()),
            Ok(text_block_start(0)),
            Ok(text_delta(0, "truncated tai")),
            Ok(block_stop(0)),
            Ok(message_delta_with_stop(messages::StopReason::Unknown(
                wire.to_owned(),
            ))),
            Ok(MessageStreamEvent::MessageStop),
        ];
        let raw = stream::iter(events).boxed();
        let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;
        match evs.last().expect("at least one event") {
            SamplingEvent::Completed { response, .. } => assert_eq!(
                response.stop_reason,
                Some(StopReason::Length),
                "`{wire}` names a token limit; reporting Stop presents a truncated tail as the \
                 model's final answer"
            ),
            other => panic!("expected Completed for `{wire}`, got {other:?}"),
        }
    }
}

/// The guard keys on "this delta is not modelled", not on "a tag could be read off it".
///
/// `Open::deserialize` only ever produces `Unknown` for a payload that HAS a string `type`, so this
/// shape cannot arrive from the wire today. It can arrive from a refactor: anything that constructs
/// `Open::Unknown` by hand, or a future `Open` that tolerates a tagless variant, would otherwise
/// find the one path where a dropped delta is not recorded and a tool call is finalized from
/// mutilated arguments again. Keyed on `known().is_none()`, there is no such path.
#[tokio::test]
async fn an_untagged_unknown_delta_on_a_tool_use_block_still_fails_the_turn() {
    let events: Vec<Result<MessageStreamEvent, SamplingError>> = vec![
        Ok(message_start()),
        Ok(MessageStreamEvent::ContentBlockStart {
            index: 0,
            content_block: Open::Known(ContentBlock::ToolUse {
                id: "call_bash".into(),
                name: "Bash".into(),
                input: serde_json::json!({}),
                cache_control: None,
            }),
        }),
        Ok(MessageStreamEvent::ContentBlockDelta {
            index: 0,
            delta: Open::Known(StreamDelta::InputJsonDelta {
                partial_json: "{\"command\":\"ls\",".into(),
            }),
        }),
        // No `type` at all -- still a delta this client did not model and did not apply.
        Ok(MessageStreamEvent::ContentBlockDelta {
            index: 0,
            delta: Open::Unknown(serde_json::json!({"patch": []})),
        }),
        Ok(MessageStreamEvent::ContentBlockDelta {
            index: 0,
            delta: Open::Known(StreamDelta::InputJsonDelta {
                partial_json: "\"timeout\":5}".into(),
            }),
        }),
        Ok(block_stop(0)),
        Ok(message_delta_with_stop(messages::StopReason::ToolUse)),
        Ok(MessageStreamEvent::MessageStop),
    ];
    let raw = stream::iter(events).boxed();
    let evs = collect(stream_messages(raw, None, rid(), Duration::from_secs(60))).await;

    assert!(
        !evs.iter()
            .any(|e| matches!(e, SamplingEvent::Completed { .. })),
        "an unrecorded drop is the whole defect; a tagless unknown delta must not be the exception"
    );
    match evs.last().expect("at least one event") {
        SamplingEvent::Failed { error, .. } => {
            assert_eq!(error.kind, crate::events::SamplingErrorKind::Serialization);
            assert!(
                error.message.contains("<untagged>"),
                "the diagnostic must say the delta carried no type, got: {}",
                error.message
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}
