//! Layer-2 stream transform for the Anthropic Messages API.
//!
//! Consumes a raw `MessageStreamEvent` stream and produces [`SamplingEvent`]s.
//! Pure: no I/O, no shell coupling.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use futures_util::stream::{BoxStream, Stream};

use fuigo_sampling_types::messages::{self, MessageStreamEvent};
use fuigo_sampling_types::{
    AssistantItem, ConversationItem, ConversationResponse, ResponseModelMetadata, SamplingError,
    StopReason, TokenUsage, ToolCall, rs,
};

use crate::events::{SamplingChannel, SamplingErrorInfo, SamplingEvent};
use crate::metrics::InferenceLatencyStats;
use crate::types::RequestId;

/// Returns whether a Messages API event reflects real model progress rather than a liveness-only heartbeat (Ping).
pub(crate) fn messages_event_has_meaningful_content(event: &MessageStreamEvent) -> bool {
    match event {
        MessageStreamEvent::Ping => false,
        // A block whose type this client does not model is NOT progress, however often it
        // arrives: counting it would let a provider streaming an unmodelled block refresh the
        // content clock forever while producing nothing the user can see. Tolerating an unknown
        // variant must never buy a stalled turn an unlimited extension.
        MessageStreamEvent::ContentBlockStart { content_block, .. } => content_block.known().is_some(),
        MessageStreamEvent::ContentBlockDelta { delta, .. } => delta.known().is_some(),
        MessageStreamEvent::MessageStart { .. }
        | MessageStreamEvent::MessageDelta { .. }
        | MessageStreamEvent::MessageStop
        | MessageStreamEvent::ContentBlockStop { .. }
        | MessageStreamEvent::Error { .. } => true,
    }
}

/// The Anthropic Messages API reports content as a sequence of indexed blocks (text / thinking / tool_use), each with start / delta / stop events.
/// We accumulate per-index and finalize each block on `ContentBlockStop`.
struct BlockState {
    block_type: BlockType,
    text_acc: String,
    tool_name: String,
    tool_id: String,
    args_acc: String,
    thinking_acc: String,
    signature: String,
    /// The first `SignatureDelta` replaces a start-seeded signature (no doubling); later deltas append.
    signature_delta_seen: bool,
    /// The wire `type` of the first delta on THIS block that this client does not model, if any.
    ///
    /// An unmodelled delta is dropped rather than fatal, so the block's accumulators have a hole in
    /// them while the block state itself survives to be finalized. Whether that hole is tolerable
    /// depends entirely on what the block becomes, so the drop is recorded here and
    /// `ContentBlockStop` decides. See the `BlockType::ToolUse` arm.
    dropped_unknown_delta: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockType {
    Text,
    ToolUse,
    Thinking,
    /// A `redacted_thinking` block: the opaque `data` blob is held in `BlockState::signature`.
    RedactedThinking,
}

/// Transform a raw Anthropic Messages API stream into a stream of [`SamplingEvent`]s.
///
/// Yields exactly one terminal event ([`SamplingEvent::Completed`] or [`SamplingEvent::Failed`]) per request.
/// Server-side `Error` events translate to `SamplingError::Api { status: 500, .. }`.
/// The actor's retry loop treats them as retryable transport-level errors.
pub fn stream_messages<'a>(
    raw_stream: BoxStream<'a, Result<MessageStreamEvent, SamplingError>>,
    model_metadata: Option<ResponseModelMetadata>,
    request_id: RequestId,
    idle_timeout: Duration,
) -> impl Stream<Item = SamplingEvent> + Send + 'a {
    async_stream::stream! {
        use messages::{ContentBlock, StreamDelta};

        let stream_start = Instant::now();
        let mut chunk_timestamps: Vec<Instant> = Vec::new();

        yield SamplingEvent::StreamStarted {
            request_id: request_id.clone(),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        };

        if let Some(metadata) = model_metadata {
            yield SamplingEvent::ModelMetadata {
                request_id: request_id.clone(),
                metadata,
            };
        }

        // Per-block accumulators keyed by content block index.
        let mut blocks: BTreeMap<u32, BlockState> = BTreeMap::new();

        // Final-message-level accumulators
        let mut final_model: Option<String> = None;
        // Anthropic Messages API `input_tokens` is the uncached portion
        // Cache hits and writes are reported in separate buckets and must be summed for the true total prompt size
        let mut final_input_tokens: u32 = 0;
        let mut final_cache_read_input_tokens: u32 = 0;
        let mut final_cache_creation_input_tokens: u32 = 0;
        let mut final_output_tokens: u32 = 0;
        let mut final_stop_reason: Option<StopReason> = None;
        let mut final_stop_message: Option<String> = None;
        let mut final_message_id: Option<String> = None;
        let mut final_raw_stop_reason: Option<String> = None;
        // The provider sends the matched stop sequence in `message_delta.stop_sequence` on a `stop_sequence`-terminated turn
        // It is carried through so the headless `streaming-messages-json` consumer can echo it
        let mut final_stop_sequence: Option<String> = None;

        // Assistant-response accumulators (built up as ContentBlockStop events fire)
        // Each thinking (and redacted_thinking) block becomes its own `rs::ReasoningItem`, in wire order
        // They are emitted as sibling `ConversationItem::Reasoning`s before the trailing Assistant
        // Keeping every block matters: the API requires prior thinking blocks back unmodified, each with its own signature
        let mut assistant_text = String::new();
        let mut assistant_tool_calls: Vec<ToolCall> = Vec::new();
        let mut assistant_reasoning: Vec<rs::ReasoningItem> = Vec::new();

        // Index counters
        let mut chunk_index: u64 = 0;
        let mut message_chunk_count: u64 = 0;
        let mut first_token_emitted = false;
        let mut last_content_chunk_at = Instant::now();

        // Tool-call index counter for per-tool deltas (separate from the block index, which can be interleaved with text/thinking blocks)
        let mut next_tool_index: u32 = 0;
        let mut block_to_tool_index: BTreeMap<u32, u32> = BTreeMap::new();

        let mut stream = raw_stream;
        loop {
            let event_result = match tokio::time::timeout(idle_timeout, stream.next()).await {
                Ok(Some(event_result)) => event_result,
                Ok(None) => break,
                Err(_elapsed) => {
                    let err = SamplingError::IdleTimeout {
                        elapsed_secs: idle_timeout.as_secs(),
                    };
                    yield SamplingEvent::Failed {
                        request_id: request_id.clone(),
                        error: SamplingErrorInfo::from(&err),
                    };
                    return;
                }
            };

            let event = match event_result {
                Ok(event) => event,
                Err(err) => {
                    yield SamplingEvent::Failed {
                        request_id: request_id.clone(),
                        error: SamplingErrorInfo::from(&err),
                    };
                    return;
                }
            };

            let event_has_content = messages_event_has_meaningful_content(&event);

            match event {
                MessageStreamEvent::MessageStart { message } => {
                    final_message_id = Some(message.id.clone());
                    final_model = Some(message.model.clone());
                    final_input_tokens = message.usage.input_tokens;
                    final_cache_read_input_tokens = message.usage.cache_read_input_tokens;
                    final_cache_creation_input_tokens = message.usage.cache_creation_input_tokens;
                    // Yield the real id, model, and input usage before any content
                    // Partial-mode framing then emits them on the real `message_start` instead of a synthesized placeholder
                    yield SamplingEvent::ResponseStarted {
                        request_id: request_id.clone(),
                        message_id: message.id,
                        model: message.model,
                        input_tokens: u64::from(message.usage.input_tokens),
                        cache_read_input_tokens: u64::from(
                            message.usage.cache_read_input_tokens,
                        ),
                        cache_creation_input_tokens: u64::from(
                            message.usage.cache_creation_input_tokens,
                        ),
                    };
                }

                // `content_block` is `Open`: a block type this client does not model is skipped
                // and the turn survives, while a modelled type with a malformed body has already
                // failed the parse upstream
                MessageStreamEvent::ContentBlockStart {
                    index,
                    content_block,
                } => match content_block.into_known() {
                    Some(ContentBlock::Thinking {
                        thinking,
                        signature,
                    }) => {
                        blocks.insert(
                            index,
                            BlockState {
                                block_type: BlockType::Thinking,
                                text_acc: String::new(),
                                tool_name: String::new(),
                                tool_id: String::new(),
                                args_acc: String::new(),
                                thinking_acc: thinking.clone(),
                                signature: signature.clone(),
                                signature_delta_seen: false,
                                dropped_unknown_delta: None,
                            },
                        );
                        if !first_token_emitted {
                            first_token_emitted = true;
                            yield SamplingEvent::FirstToken {
                                request_id: request_id.clone(),
                            };
                        }
                    }
                    Some(ContentBlock::Text { text, .. }) => {
                        blocks.insert(
                            index,
                            BlockState {
                                block_type: BlockType::Text,
                                text_acc: text.clone(),
                                tool_name: String::new(),
                                tool_id: String::new(),
                                args_acc: String::new(),
                                thinking_acc: String::new(),
                                signature: String::new(),
                                signature_delta_seen: false,
                                dropped_unknown_delta: None,
                            },
                        );
                        if !first_token_emitted {
                            first_token_emitted = true;
                            yield SamplingEvent::FirstToken {
                                request_id: request_id.clone(),
                            };
                        }
                    }
                    Some(ContentBlock::ToolUse { id, name, .. }) => {
                        let tool_index = next_tool_index;
                        next_tool_index += 1;
                        block_to_tool_index.insert(index, tool_index);

                        blocks.insert(
                            index,
                            BlockState {
                                block_type: BlockType::ToolUse,
                                text_acc: String::new(),
                                tool_name: name.clone(),
                                tool_id: id.clone(),
                                // Anthropic Messages API streams arguments via InputJsonDelta events
                                // Starting from "{}" then appending fragments would produce invalid JSON
                                args_acc: String::new(),
                                thinking_acc: String::new(),
                                signature: String::new(),
                                signature_delta_seen: false,
                                dropped_unknown_delta: None,
                            },
                        );

                        // Emit the initial id and name so subscribers can pre-allocate UI for the tool call before arguments stream in
                        yield SamplingEvent::ToolCallDelta {
                            request_id: request_id.clone(),
                            tool_index,
                            id: Some(id),
                            name: Some(name),
                            arguments_delta: None,
                        };
                    }
                    // Encrypted reasoning the model chose to redact
                    // The opaque `data` blob is kept (in the `signature` slot) and finalized at the block's stop as a sentinel-tagged reasoning item
                    // Replaying it unchanged is what the API requires; it is also forwarded as a `SamplingEvent::RedactedThinking` at the block's stop
                    Some(ContentBlock::RedactedThinking { data }) => {
                        blocks.insert(
                            index,
                            BlockState {
                                block_type: BlockType::RedactedThinking,
                                text_acc: String::new(),
                                tool_name: String::new(),
                                tool_id: String::new(),
                                args_acc: String::new(),
                                thinking_acc: String::new(),
                                signature: data,
                                signature_delta_seen: false,
                                dropped_unknown_delta: None,
                            },
                        );
                    }
                    // Image / ToolResult are not expected in assistant streams.
                    Some(_) => {}
                    // A content-block type this client does not model: no block state is opened,
                    // so its deltas are ignored too, and the rest of the turn proceeds
                    None => {}
                },

                // `delta` is `Open`: an unmodelled delta type is dropped rather than failing the
                // parse. But dropping one is DATA LOSS on a block that stays open, so the drop is
                // recorded against that block before it is discarded. `ContentBlockStop` is where
                // the loss is judged -- a hole in streamed text is a visible gap, a hole in
                // streamed tool arguments is a silently altered tool call.
                MessageStreamEvent::ContentBlockDelta { index, delta } => {
                    // Keyed on "this delta is not modelled", NOT on "a tag could be read off it":
                    // an `Open::Unknown` that somehow carries no string `type` is still a dropped
                    // delta, and it must not be the one case that slips through unrecorded.
                    if delta.known().is_none() {
                        let tag = delta.unknown_tag().unwrap_or("<untagged>");
                        tracing::warn!(
                            block_index = index,
                            unknown_delta_type = %tag,
                            "Dropping a content-block delta this client does not model"
                        );
                        // Keep the FIRST tag: it is the one that names where the hole started, and
                        // a block with several holes is no more acceptable than a block with one.
                        if let Some(state) = blocks.get_mut(&index)
                            && state.dropped_unknown_delta.is_none()
                        {
                            state.dropped_unknown_delta = Some(tag.to_owned());
                        }
                    }
                    if let Some(state) = blocks.get_mut(&index)
                        && let Some(delta) = delta.into_known()
                    {
                        match delta {
                            StreamDelta::ThinkingDelta { thinking } => {
                                if !thinking.is_empty() {
                                    state.thinking_acc.push_str(&thinking);
                                    if !first_token_emitted {
                                        first_token_emitted = true;
                                        yield SamplingEvent::FirstToken {
                                            request_id: request_id.clone(),
                                        };
                                    }
                                    chunk_index += 1;
                                    yield SamplingEvent::ChannelToken {
                                        request_id: request_id.clone(),
                                        channel: SamplingChannel::Reasoning,
                                        text: thinking,
                                        chunk_index,
                                    };
                                }
                            }
                            StreamDelta::SignatureDelta { signature } => {
                                // The first delta replaces any start-seeded signature so a gateway sending both never doubles it
                                // Later deltas append: a signature split across deltas must survive whole
                                if !state.signature_delta_seen {
                                    state.signature_delta_seen = true;
                                    state.signature.clear();
                                }
                                state.signature.push_str(&signature);
                            }
                            StreamDelta::TextDelta { text } => {
                                if !text.is_empty() {
                                    state.text_acc.push_str(&text);
                                    if !first_token_emitted {
                                        first_token_emitted = true;
                                        yield SamplingEvent::FirstToken {
                                            request_id: request_id.clone(),
                                        };
                                    }
                                    chunk_timestamps.push(Instant::now());
                                    chunk_index += 1;
                                    message_chunk_count += 1;
                                    yield SamplingEvent::ChannelToken {
                                        request_id: request_id.clone(),
                                        channel: SamplingChannel::Text,
                                        text,
                                        chunk_index,
                                    };
                                }
                            }
                            StreamDelta::InputJsonDelta { partial_json } => {
                                state.args_acc.push_str(&partial_json);
                                if let Some(&tool_index) = block_to_tool_index.get(&index) {
                                    yield SamplingEvent::ToolCallDelta {
                                        request_id: request_id.clone(),
                                        tool_index,
                                        id: None,
                                        name: None,
                                        arguments_delta: Some(partial_json),
                                    };
                                }
                            }
                        }
                    }
                }

                MessageStreamEvent::ContentBlockStop { index } => {
                    if let Some(state) = blocks.remove(&index) {
                        match state.block_type {
                            // Text and Thinking deliberately TOLERATE a dropped delta where ToolUse
                            // refuses one. The asymmetry is the point: a hole in streamed text is a
                            // visible gap in prose a human reads, already warned about in the log,
                            // and nothing executes it -- failing the turn over it would throw away
                            // a complete billed response for a cosmetic defect, which is the exact
                            // harm this packet was written to stop. A hole in streamed tool
                            // arguments changes what a program DOES, invisibly. Only the second one
                            // is worth a dead turn.
                            BlockType::Text => {
                                if !state.text_acc.is_empty() {
                                    if !assistant_text.is_empty() {
                                        assistant_text.push('\n');
                                    }
                                    assistant_text.push_str(&state.text_acc);
                                }
                            }
                            BlockType::Thinking => {
                                // Yield the encrypted signature at the thinking block's stop
                                // Partial-mode framing can then emit `signature_delta` before its `content_block_stop`
                                if !state.signature.is_empty() {
                                    yield SamplingEvent::ReasoningCompleted {
                                        request_id: request_id.clone(),
                                        signature: state.signature.clone(),
                                    };
                                }
                                if !state.thinking_acc.is_empty() || !state.signature.is_empty() {
                                    // Anthropic Messages API `Thinking` blocks uniquely carry an encrypted `signature` distinct from the text
                                    // Either field may be empty
                                    // Build directly rather than via `synthesized_reasoning_item` since the helper assumes a non-empty summary
                                    let summary = if state.thinking_acc.is_empty() {
                                        vec![]
                                    } else {
                                        vec![rs::SummaryPart::SummaryText(
                                            rs::SummaryTextContent {
                                                text: state.thinking_acc,
                                            },
                                        )]
                                    };
                                    let encrypted_content = if state.signature.is_empty() {
                                        None
                                    } else {
                                        Some(state.signature)
                                    };
                                    assistant_reasoning.push(rs::ReasoningItem {
                                        id: String::new(),
                                        summary,
                                        content: None,
                                        encrypted_content,
                                        status: None,
                                    });
                                }
                            }
                            BlockType::RedactedThinking => {
                                if !state.signature.is_empty() {
                                    // Forward the block in wire order, so the headless reducer keeps it where the model put it
                                    yield SamplingEvent::RedactedThinking {
                                        request_id: request_id.clone(),
                                        data: state.signature.clone(),
                                    };
                                    assistant_reasoning.push(
                                        fuigo_sampling_types::redacted_thinking_item(state.signature),
                                    );
                                }
                            }
                            BlockType::ToolUse => {
                                // A tool call is EXECUTED, and `args_acc` is a plain concatenation
                                // of streamed fragments. A delta dropped from the MIDDLE of that
                                // sequence therefore does not produce a detectable error: with
                                // `{"a":1,` + <dropped `"b":2,`> + `"c":3}` the concatenation is
                                // `{"a":1,"c":3}`, syntactically valid JSON with one parameter
                                // silently absent. An `Edit` that loses `old_string`, or a `Write`
                                // that loses part of `content`, would then run with arguments the
                                // model never sent and the turn would report success. (A drop from
                                // the TAIL is the harmless case -- it yields invalid JSON, which is
                                // loud at the tool boundary. Correctness cannot rest on which.)
                                //
                                // Forward compatibility exists to keep a paid-for turn alive
                                // through a variant we do not model. It must never buy a turn that
                                // ACTS on altered arguments: that is a strictly worse outcome than
                                // the loud abort this replaced. `serde_helpers`' own design note
                                // forbids exactly this for a corrupt modelled `tool_use` block;
                                // this extends it to a dropped delta ON a well-formed one, which is
                                // the case that note did not reach.
                                let dropped = state.dropped_unknown_delta.as_ref().map(|tag| {
                                    SamplingErrorInfo::from(&SamplingError::serialization_message(
                                        format!(
                                            "tool_use block {index} (`{name}`) dropped an unmodelled \
                                             `{tag}` content-block delta, so its streamed arguments \
                                             are incomplete; refusing to report a tool call whose \
                                             arguments may differ from what the model sent",
                                            name = state.tool_name,
                                        ),
                                    ))
                                });
                                if let Some(error) = dropped {
                                    yield SamplingEvent::Failed {
                                        request_id: request_id.clone(),
                                        error,
                                    };
                                    return;
                                }
                                assistant_tool_calls.push(ToolCall {
                                    id: std::sync::Arc::<str>::from(state.tool_id),
                                    name: state.tool_name,
                                    arguments: std::sync::Arc::<str>::from(state.args_acc),
                                });
                            }
                        }
                    }
                }

                MessageStreamEvent::MessageDelta { delta, usage } => {
                    // Normalize the provider's stop detail to a plain message; the shell logs it when it shows a refusal
                    if let Some(details) = delta.stop_details {
                        final_stop_message = details.explanation;
                    }
                    // Keep the exact wire string so consumers can echo it.
                    final_raw_stop_reason = delta
                        .stop_reason
                        .as_ref()
                        .map(messages::StopReason::wire_str);
                    // The matched stop sequence arrives on the same terminal delta (present only on a `stop_sequence` stop); carry it verbatim
                    if delta.stop_sequence.is_some() {
                        final_stop_sequence = delta.stop_sequence.clone();
                    }
                    final_stop_reason = delta.stop_reason.map(|sr| match sr {
                        messages::StopReason::EndTurn => StopReason::Stop,
                        messages::StopReason::MaxTokens => StopReason::Length,
                        messages::StopReason::StopSequence => StopReason::Stop,
                        messages::StopReason::ToolUse => StopReason::ToolCalls,
                        // The model declined to continue; whatever streamed is the complete response, so end the turn cleanly
                        messages::StopReason::Refusal => StopReason::ContentFilter,
                        messages::StopReason::PauseTurn => {
                            // Anthropic Messages API expects the client to resend to continue; we end the turn instead
                            tracing::warn!(
                                wire_stop_reason = "pause_turn",
                                "pause_turn ended the turn like stop (no auto-continue)"
                            );
                            StopReason::Stop
                        }
                        messages::StopReason::ModelContextWindowExceeded => {
                            // Output-side overflow on a successful stream maps to the Length stop class
                            // Compact-on-error recovery needs an Api error carrying model metadata and a prompt-side overflow; neither exists here
                            tracing::warn!(
                                wire_stop_reason = "model_context_window_exceeded",
                                "context window hit mid-generation; mapping to the Length stop class"
                            );
                            StopReason::Length
                        }
                        // An unmodelled stop_reason that NAMES A TOKEN LIMIT is a length stop, not a
                        // clean completion. `Length` is what drives truncation handling and
                        // compaction, and a gateway fronting this backend spells the same stop
                        // `MAX_TOKENS`, `length` or `length_limit`; reading any of those as `Stop`
                        // presents a truncated tail as the model's final answer.
                        messages::StopReason::Unknown(wire)
                            if fuigo_sampling_types::types::is_length_stop_alias(&wire) =>
                        {
                            tracing::warn!(
                                wire_stop_reason = %wire,
                                "unrecognized stop_reason names a token limit; mapping to the Length stop class"
                            );
                            StopReason::Length
                        }
                        messages::StopReason::Unknown(wire) => {
                            tracing::warn!(
                                wire_stop_reason = %wire,
                                "unrecognized stop_reason in messages stream; treating as stop"
                            );
                            StopReason::Stop
                        }
                    });
                    final_output_tokens = usage.output_tokens;
                    // Optional on the delta; preserve message_start values when omitted.
                    if let Some(input) = usage.input_tokens {
                        final_input_tokens = input;
                    }
                    if let Some(cache_read) = usage.cache_read_input_tokens {
                        final_cache_read_input_tokens = cache_read;
                    }
                    if let Some(cache_creation) = usage.cache_creation_input_tokens {
                        final_cache_creation_input_tokens = cache_creation;
                    }
                }

                MessageStreamEvent::MessageStop => {
                    // Final message complete; the loop exits naturally when the underlying stream ends
                }

                MessageStreamEvent::Ping => {
                    // Liveness only, no action; the inner timeout was already reset above by the successful `next()`
                }

                MessageStreamEvent::Error { error } => {
                    let error_message = format!("{}: {}", error.r#type, error.message);
                    let err = SamplingError::Api {
                        status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                        message: error_message,
                        model_metadata: None,
                        retry_after_secs: None,
                        should_retry: None,
                        // Messages-style error events carry no code slot.
                        error_code: None,
                    };
                    yield SamplingEvent::Failed {
                        request_id: request_id.clone(),
                        error: SamplingErrorInfo::from(&err),
                    };
                    return;
                }
            }

            if event_has_content {
                last_content_chunk_at = Instant::now();
            } else if last_content_chunk_at.elapsed() > idle_timeout {
                let err = SamplingError::IdleTimeout {
                    elapsed_secs: idle_timeout.as_secs(),
                };
                yield SamplingEvent::Failed {
                    request_id: request_id.clone(),
                    error: SamplingErrorInfo::from(&err),
                };
                return;
            }
        }

        // A `Length` stop is NOT failed here
        // The transform completes with `stop_reason=Length` and `drive_l2` decides fail-vs-salvage per the request's `LengthPolicy`

        // ── Build the final response ─────────────────────────────────
        let model_id = final_model.unwrap_or_default();
        // Match the OAI Responses convention: prompt_tokens holds the full prompt, cached_prompt_tokens counts cache hits only
        let total_prompt_tokens = final_input_tokens
            .saturating_add(final_cache_read_input_tokens)
            .saturating_add(final_cache_creation_input_tokens);
        let usage = if total_prompt_tokens > 0 || final_output_tokens > 0 {
            Some(TokenUsage {
                prompt_tokens: total_prompt_tokens,
                completion_tokens: final_output_tokens,
                total_tokens: total_prompt_tokens.saturating_add(final_output_tokens),
                reasoning_tokens: 0,
                cached_prompt_tokens: final_cache_read_input_tokens,
                cache_creation_prompt_tokens: final_cache_creation_input_tokens,
            })
        } else {
            None
        };

        let stop_reason = if final_stop_reason == Some(StopReason::Length) {
            // Length wins even over completed tool_use blocks
            // The provider closes a block it cut mid-stream, so the trailing call's arguments may be silently truncated
            // Fail-vs-salvage belongs to the `LengthPolicy` gate
            final_stop_reason
        } else if !assistant_tool_calls.is_empty() {
            // Completed tool_use blocks win even over Refusal: the calls are real model output the agent loop must resolve
            Some(StopReason::ToolCalls)
        } else {
            final_stop_reason
        };

        let assistant_item = ConversationItem::Assistant(AssistantItem {
            content: std::sync::Arc::<str>::from(assistant_text),
            tool_calls: assistant_tool_calls,
            model_id: Some(model_id),
            model_fingerprint: None,
            // The Messages API does not echo the applied reasoning effort.
            reasoning_effort: None,
            output_order: None,
        });

        let mut items: Vec<ConversationItem> = Vec::new();
        items.extend(assistant_reasoning.into_iter().map(ConversationItem::Reasoning));
        items.push(assistant_item);

        let stream_end = Instant::now();
        let metrics =
            InferenceLatencyStats::from_timestamps(stream_start, &chunk_timestamps, stream_end);

        let response = ConversationResponse {
            items,
            stop_reason,
            usage,
            // Anthropic Messages API carries no cost on the wire.
            cost_usd_ticks: None,
            message_chunks_emitted: message_chunk_count,
            doom_loop_signals: Vec::new(),
            stop_message: final_stop_message,
            message_id: final_message_id,
            raw_stop_reason: final_raw_stop_reason,
            stop_sequence: final_stop_sequence,
        };

        yield SamplingEvent::Completed {
            request_id: request_id.clone(),
            response: Box::new(response),
            metrics,
        };
    }
}

#[cfg(test)]
#[path = "messages_tests.rs"]
mod tests;
