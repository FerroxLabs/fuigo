//! `send_subagent_message` — send an active message to an owned subagent.

use crate::implementations::fuigo_build::task::backend::SubagentBackendResource;
use crate::implementations::fuigo_build::task::types::{
    ActiveAgentMessageOperation, ActiveAgentMessageOutcome, ActiveAgentMessageRequest,
    SubagentDepthCounter,
};
use crate::types::tool::{ToolKind, ToolNamespace};

pub const SEND_SUBAGENT_MESSAGE_TOOL_NAME: &str = "send_subagent_message";

/// How the SENDER meant the message. This engine lands all three the same way
/// (see [`SendSubagentMessageTool::description_template`]); the class is
/// recorded and named on the message's row, and does not route the delivery.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SendSubagentMessageDelivery {
    /// Meant as a correction to the turn already in flight.
    Steer,
    /// Meant as a later instruction (the class of every send before this field existed).
    Queue,
    /// Meant as urgent.
    Interject,
}

impl From<SendSubagentMessageDelivery> for ActiveAgentMessageOperation {
    fn from(delivery: SendSubagentMessageDelivery) -> Self {
        match delivery {
            SendSubagentMessageDelivery::Steer => ActiveAgentMessageOperation::Steer,
            SendSubagentMessageDelivery::Queue => ActiveAgentMessageOperation::Queue,
            SendSubagentMessageDelivery::Interject => ActiveAgentMessageOperation::Interject,
        }
    }
}

/// The one place an omitted `delivery` becomes an operation: `queue`, the
/// class every send carried before the field existed.
pub fn resolve_delivery(delivery: Option<SendSubagentMessageDelivery>) -> ActiveAgentMessageOperation {
    match delivery {
        Some(delivery) => ActiveAgentMessageOperation::from(delivery),
        None => ActiveAgentMessageOperation::Queue,
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct SendSubagentMessageInput {
    /// ID of the subagent that should receive the message (active, or completed and eligible to resume).
    pub subagent_id: String,
    /// Text to send to the subagent.
    pub text: String,
    /// How you mean the message; omitted means `queue`. Recorded and shown on
    /// the message's row — it does not change how the message lands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<SendSubagentMessageDelivery>,
}

impl SendSubagentMessageInput {
    pub fn operation(&self) -> ActiveAgentMessageOperation {
        resolve_delivery(self.delivery)
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[non_exhaustive]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SendSubagentMessageOutput {
    Accepted {
        message_id: String,
    },
    NotFoundOrNotOwned,
    NotActiveOrFinalizing,
    Saturated {
        max_in_flight: usize,
    },
    AdmissionUncertain,
    NotAcceptedBeforeDeadline,
    Unsupported,
    Limit {
        max_bytes: usize,
        observed_bytes: usize,
    },
    ChannelClosed,
}

/// Delivery classification shared by tool hosts and presentations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendSubagentMessageDisposition {
    /// Admission was confirmed.
    Accepted,
    /// Admission was definitely rejected.
    Rejected,
    /// Admission or delivery could not be confirmed.
    Unconfirmed,
}

impl SendSubagentMessageOutput {
    /// Classify this output without collapsing uncertainty into failure.
    pub fn disposition(&self) -> SendSubagentMessageDisposition {
        match self {
            Self::Accepted { .. } => SendSubagentMessageDisposition::Accepted,
            Self::AdmissionUncertain => SendSubagentMessageDisposition::Unconfirmed,
            Self::NotFoundOrNotOwned
            | Self::NotActiveOrFinalizing
            | Self::Saturated { .. }
            | Self::NotAcceptedBeforeDeadline
            | Self::Unsupported
            | Self::Limit { .. }
            | Self::ChannelClosed => SendSubagentMessageDisposition::Rejected,
        }
    }
}

impl From<ActiveAgentMessageOutcome> for SendSubagentMessageOutput {
    fn from(outcome: ActiveAgentMessageOutcome) -> Self {
        match outcome {
            ActiveAgentMessageOutcome::Accepted { message_id } => Self::Accepted { message_id },
            ActiveAgentMessageOutcome::NotFoundOrNotOwned => Self::NotFoundOrNotOwned,
            ActiveAgentMessageOutcome::NotActiveOrFinalizing => Self::NotActiveOrFinalizing,
            ActiveAgentMessageOutcome::Saturated { max_in_flight } => {
                Self::Saturated { max_in_flight }
            }
            ActiveAgentMessageOutcome::AdmissionUncertain => Self::AdmissionUncertain,
            ActiveAgentMessageOutcome::NotAcceptedBeforeDeadline => Self::NotAcceptedBeforeDeadline,
            ActiveAgentMessageOutcome::Unsupported => Self::Unsupported,
            ActiveAgentMessageOutcome::Limit {
                max_bytes,
                observed_bytes,
            } => Self::Limit {
                max_bytes,
                observed_bytes,
            },
            ActiveAgentMessageOutcome::ChannelClosed => Self::ChannelClosed,
        }
    }
}

impl std::fmt::Display for SendSubagentMessageOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accepted { message_id } => {
                write!(f, "Message accepted (message_id: {message_id}).")
            }
            Self::NotFoundOrNotOwned => {
                f.write_str("Subagent not found or not owned by this session.")
            }
            Self::NotActiveOrFinalizing => f.write_str("Subagent is not active or is finalizing."),
            Self::Saturated { max_in_flight } => write!(
                f,
                "Message admission is saturated (maximum {max_in_flight} in flight)."
            ),
            Self::AdmissionUncertain => f.write_str(
                "Message admission could not be confirmed; the message may or may not have been accepted.",
            ),
            Self::NotAcceptedBeforeDeadline => {
                f.write_str("Message was not accepted before the delivery deadline.")
            }
            Self::Unsupported => {
                f.write_str("Active agent messages are unsupported in this context.")
            }
            Self::Limit {
                max_bytes,
                observed_bytes,
            } => write!(
                f,
                "Message size is invalid: observed {observed_bytes} bytes; maximum is {max_bytes} bytes."
            ),
            Self::ChannelClosed => {
                f.write_str("Message was not accepted because the subagent channel closed.")
            }
        }
    }
}

impl fuigo_tool_runtime::ToolOutput for SendSubagentMessageOutput {}

#[derive(Debug, Default)]
pub struct SendSubagentMessageTool;

impl crate::types::tool_metadata::ToolMetadata for SendSubagentMessageTool {
    fn kind(&self) -> ToolKind {
        ToolKind::ActiveAgentMessage
    }

    fn tool_namespace(&self) -> ToolNamespace {
        ToolNamespace::FuigoBuild
    }

    /// INVARIANT: this text may promise the model only what the engine
    /// implements. Fuigo has ONE delivery for all three classes. The class is
    /// carried as far as authorization (`fuigo-shell`
    /// `session/message_delivery.rs` and `agent/subagent/child_runtime.rs`
    /// are the only readers of `ActiveAgentMessageOperation`) and is never
    /// routed on: `admit_parent_agent_message`
    /// (`session/acp_session_impl/parent_message.rs`) commits every class
    /// through `commit_queued_delivery`, `promote_parent_agent_messages`
    /// then lifts every parent-agent row into the running turn at the next
    /// safe point, and the commit raises `ParentMessageSignal`, which
    /// interrupts an in-flight `get_task_output` wait. Upstream's
    /// `ParentInterjectSignal` / `order_for_delivery` ordering is not ported.
    /// If the classes are ever made to differ, rewrite this text in the same
    /// commit: `tool_description_promises_only_the_delivery_the_engine_implements`
    /// pins the pair.
    fn description_template(&self) -> &str {
        "Send a follow-up message to a subagent owned by this session. An active subagent receives it as a message; an eligible completed subagent (not cancelled, not workflow-owned, and one whose completion reports to this session) resumes with the same identity and runs the text as its next turn, reporting like a background completion. `delivery` (`queue` by default, `steer`, `interject`) records how you mean the message and is named on its row in the transcript; it does not change how the message lands. Every class lands the same way here: an active subagent's message joins the turn it is running at that turn's next safe point, interrupting it if it is blocked waiting on background work, and starts a turn of its own if the subagent is idle. Do not pick a class expecting a different arrival order or a different priority."
    }
}

impl fuigo_tool_runtime::Tool for SendSubagentMessageTool {
    type Args = SendSubagentMessageInput;
    type Output = SendSubagentMessageOutput;

    fn id(&self) -> fuigo_tool_protocol::ToolId {
        fuigo_tool_protocol::ToolId::new(SEND_SUBAGENT_MESSAGE_TOOL_NAME).expect("valid tool id")
    }

    fn description(
        &self,
        _ctx: &fuigo_tool_runtime::ListToolsContext,
    ) -> fuigo_tool_types::ToolDescription {
        fuigo_tool_types::ToolDescription::new(
            SEND_SUBAGENT_MESSAGE_TOOL_NAME,
            crate::types::tool_metadata::ToolMetadata::sanitized_description_template(self),
        )
    }

    fn capabilities(&self) -> fuigo_tool_protocol::ToolCapabilities {
        fuigo_tool_protocol::ToolCapabilities {
            is_read_only: false,
            tool_scope: Some(fuigo_tool_protocol::ToolScope::Write),
            ..Default::default()
        }
    }

    #[tracing::instrument(
        name = "tool.send_subagent_message",
        skip_all,
        fields(subagent_id = %input.subagent_id)
    )]
    async fn run(
        &self,
        ctx: fuigo_tool_runtime::ToolCallContext,
        input: SendSubagentMessageInput,
    ) -> Result<SendSubagentMessageOutput, fuigo_tool_runtime::ToolError> {
        let resources = crate::types::tool_metadata::shared_resources(&ctx)?;
        let (depth, backend) = {
            let res = resources.lock().await;
            (
                res.get::<SubagentDepthCounter>().map(|value| value.0),
                res.get::<SubagentBackendResource>().cloned(),
            )
        };

        let (Some(0), Some(backend)) = (depth, backend) else {
            return Ok(SendSubagentMessageOutput::Unsupported);
        };
        let operation = input.operation();
        let request = match ActiveAgentMessageRequest::try_new_with_operation(
            input.subagent_id,
            input.text,
            operation,
        ) {
            Ok(request) => request,
            Err(outcome) => return Ok(outcome.into()),
        };

        Ok(backend.backend().send_active_message(request).await.into())
    }
}

#[cfg(test)]
#[path = "send_subagent_message_tests.rs"]
mod tests;
