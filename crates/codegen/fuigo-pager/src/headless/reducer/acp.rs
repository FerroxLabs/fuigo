//! The `streaming-json` reducer: native ACP session updates, one JSON object per line.
//! It defines its own line shapes: [`AcpLine`], [`AcpUsageLine`], [`AcpEndLine`].

use serde::Serialize;
use serde_json::Value;

use crate::headless::{HeadlessDenial, attach_result_usage};
use fuigo_shell::extensions::notification::ResponseUsage;

use super::{
    Lifecycle, Reducer, StreamEvent, TurnEnd, attach_structured_output, to_line,
    tool_call_status_wire,
};

/// `streaming-json` per-response `usage` line (camelCase keys).
#[derive(Serialize)]
struct AcpUsageLine {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(rename = "messageId", skip_serializing_if = "Option::is_none")]
    message_id: Option<String>,
    #[serde(rename = "stopReason", skip_serializing_if = "Option::is_none")]
    stop_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<ResponseUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
}

/// `streaming-json` line shapes: an Ferrox Labs `type`-tagged envelope derived from ACP updates.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AcpLine {
    Text {
        data: String,
    },
    Thought {
        data: String,
    },
    ToolCall {
        #[serde(rename = "toolCallId")]
        tool_call_id: String,
        title: String,
        kind: Option<String>,
        status: Option<String>,
        #[serde(rename = "toolName")]
        tool_name: String,
        #[serde(rename = "rawInput")]
        raw_input: Value,
        content: Value,
        locations: Value,
    },
    ToolCallUpdate {
        #[serde(rename = "toolCallId")]
        tool_call_id: String,
        status: Option<String>,
        content: Value,
        #[serde(rename = "rawOutput")]
        raw_output: Value,
        locations: Value,
    },
    Plan {
        entries: Value,
    },
    AvailableCommands {
        tools: Vec<String>,
        commands: Vec<String>,
    },
    MaxTurnsReached,
    /// P188: the `text`/`thought` lines since the current response began (the later of the prompt, the last `usage`
    /// line and the last `response_discarded`) came from a model request that failed and is being resent; drop them,
    /// the resend streams the reply again. A `tool_call` line is not a boundary: a hosted search reports mid-response.
    ResponseDiscarded {
        #[serde(rename = "messageId", skip_serializing_if = "Option::is_none")]
        message_id: Option<String>,
        #[serde(rename = "streamStartMs", skip_serializing_if = "Option::is_none")]
        stream_start_ms: Option<i64>,
    },
    Error {
        message: String,
    },
    AutoCompactStarted {
        percentage: u8,
    },
    AutoCompactCompleted,
    AutoCompactFailed {
        error: String,
    },
    AutoCompactCancelled,
    AutoContinueCompleted {
        total_tokens: u64,
    },
    ImageCompressed {
        message: String,
    },
    ConfigNotice {
        message: String,
    },
    MemoryFlushStarted,
    MemoryFlushCompleted {
        result: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
}

/// `streaming-json` terminal `end` line (spend fields merged in by the caller).
#[derive(Serialize)]
struct AcpEndLine<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(rename = "stopReason")]
    stop_reason: &'a str,
    #[serde(rename = "sessionId")]
    session_id: &'a str,
    #[serde(rename = "requestId")]
    request_id: &'a str,
}

/// `streaming-json`: native ACP session updates, one object per line.
#[derive(Default)]
pub(crate) struct AcpReducer {
    /// The denial record (`HeadlessDenial::wire_record`) for the terminal line, when one was latched.
    permission_denied: Option<Value>,
}

impl AcpReducer {
    /// Stamp `permissionDenied` on a terminal line — the same record, under the same key, as the
    /// `json` document, so one consumer handles both formats. Added to the existing `end`/`error`
    /// line rather than emitted as a line of its own: `end` is documented as the last event and a
    /// consumer reads exactly one terminal record.
    fn attach_permission_denied(&self, line: &mut Value) {
        if let Some(record) = &self.permission_denied
            && let Some(obj) = line.as_object_mut()
        {
            obj.insert("permissionDenied".to_string(), record.clone());
        }
    }
}

impl Reducer for AcpReducer {
    fn reduce(&mut self, event: StreamEvent) -> Vec<Value> {
        let line = match event {
            StreamEvent::AgentMessage(data) => AcpLine::Text { data },
            StreamEvent::AgentThought(data) => AcpLine::Thought { data },
            StreamEvent::ToolCall(tc) => AcpLine::ToolCall {
                tool_call_id: tc.tool_call_id,
                title: tc.title,
                kind: tc.tool_kind,
                status: tc.status.and_then(tool_call_status_wire),
                tool_name: tc.tool_name,
                raw_input: tc.raw_input,
                content: tc.content,
                locations: tc.locations,
            },
            StreamEvent::ToolCallUpdate(u) => AcpLine::ToolCallUpdate {
                tool_call_id: u.tool_call_id,
                status: u.status.and_then(tool_call_status_wire),
                content: u.content,
                raw_output: u.raw_output,
                locations: u.locations,
            },
            StreamEvent::Plan(entries) => AcpLine::Plan { entries },
            StreamEvent::AvailableCommands {
                tools,
                commands,
                skills: _,
            } => AcpLine::AvailableCommands { tools, commands },
            StreamEvent::Lifecycle(l) => return vec![to_line(&acp_lifecycle_line(l))],
            StreamEvent::ResponseDiscarded {
                message_id,
                stream_start_ms,
            } => AcpLine::ResponseDiscarded {
                message_id,
                stream_start_ms,
            },
            // Only the Messages reducer consumes these, for its `--include-partial-messages` framing
            StreamEvent::ResponseStarted { .. } | StreamEvent::ReasoningCompleted { .. } => {
                return vec![];
            }
            StreamEvent::ResponseCompleted {
                message_id,
                stop_reason,
                usage,
                signature,
                stop_sequence: _,
            } => {
                return vec![to_line(&AcpUsageLine {
                    kind: "usage",
                    message_id,
                    stop_reason,
                    usage,
                    signature,
                })];
            }
        };
        vec![to_line(&line)]
    }

    fn max_turns(&mut self) -> Vec<Value> {
        vec![to_line(&AcpLine::MaxTurnsReached)]
    }

    fn finish(&mut self, end: &TurnEnd<'_>) -> Vec<Value> {
        let mut line = to_line(&AcpEndLine {
            kind: "end",
            stop_reason: end.stop_reason,
            session_id: end.session_id,
            request_id: end.request_id,
        });
        if let Some(usage) = end.usage {
            attach_result_usage(&mut line, usage);
        }
        attach_structured_output(&mut line, end.structured_output.clone());
        // A run-level failure rides on this line instead of a second terminal `error` line.
        if let Some(error) = end.error
            && let Some(obj) = line.as_object_mut()
        {
            obj.insert("error".to_string(), Value::String(error.to_string()));
        }
        self.attach_permission_denied(&mut line);
        vec![line]
    }

    fn permission_denied(&mut self, denial: &HeadlessDenial, ended_run: bool) {
        self.permission_denied = Some(denial.wire_record(ended_run));
    }

    fn error(
        &mut self,
        message: &str,
        usage: Option<&Value>,
        _duration_ms: u64,
        _stop_reason: Option<&str>,
    ) -> Vec<Value> {
        let mut line = to_line(&AcpLine::Error {
            message: message.to_string(),
        });
        if let Some(usage) = usage {
            attach_result_usage(&mut line, usage);
        }
        self.attach_permission_denied(&mut line);
        vec![line]
    }
}

fn acp_lifecycle_line(l: Lifecycle) -> AcpLine {
    match l {
        Lifecycle::CompactStarted { percentage } => AcpLine::AutoCompactStarted { percentage },
        Lifecycle::CompactCompleted { .. } => AcpLine::AutoCompactCompleted,
        Lifecycle::CompactFailed { error } => AcpLine::AutoCompactFailed { error },
        Lifecycle::CompactCancelled => AcpLine::AutoCompactCancelled,
        Lifecycle::AutoContinue { total_tokens } => AcpLine::AutoContinueCompleted { total_tokens },
        Lifecycle::ImageCompressed { message } => AcpLine::ImageCompressed { message },
        Lifecycle::ConfigNotice { message } => AcpLine::ConfigNotice { message },
        Lifecycle::MemoryFlushStarted => AcpLine::MemoryFlushStarted,
        Lifecycle::MemoryFlushCompleted { result, path } => {
            AcpLine::MemoryFlushCompleted { result, path }
        }
    }
}

#[cfg(test)]
mod p188_tests {
    use super::*;

    /// P188: the native stream mirrors the ACP contract: a `response_discarded` line voids the `text`/`thought`
    /// lines since the current response began.
    #[test]
    fn a_discard_becomes_a_response_discarded_line() {
        let mut r = AcpReducer::default();
        assert_eq!(
            r.reduce(StreamEvent::ResponseDiscarded {
                message_id: Some("msg_1".into()),
                stream_start_ms: Some(7),
            }),
            vec![serde_json::json!({"type": "response_discarded", "messageId": "msg_1", "streamStartMs": 7})]
        );
        assert_eq!(
            r.reduce(StreamEvent::ResponseDiscarded {
                message_id: None,
                stream_start_ms: None
            }),
            vec![serde_json::json!({"type": "response_discarded"})]
        );
    }
}
