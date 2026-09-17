//! Recognizes `send_subagent_message` tool calls and maps them to scrollback blocks.
//!
//! The block takes the subagent id and text straight from the deserialized input, with no re-validation.
//! A rejected send therefore still shows the exact destination and text that was attempted.

use agent_client_protocol as acp;
use fuigo_tools::implementations::fuigo_build::send_subagent_message::{
    SEND_SUBAGENT_MESSAGE_TOOL_NAME, SendSubagentMessageDisposition, SendSubagentMessageOutput,
};
use fuigo_tools::tool_taxonomy::{CanonicalToolMeta, TOOL_META_KEY, TOOL_META_VERSION};
use fuigo_tools::types::output::ToolOutput;
use fuigo_tools::types::tool::ToolKind;
use serde::Deserialize;

use crate::scrollback::block::RenderBlock;
use crate::scrollback::blocks::tool::{
    SentMessageDelivery, SentMessagePresentation, SentMessageToolCallBlock, ToolCallBlock,
};

/// Unknown fields are ignored, so the direct input and the `variant`-tagged `ToolInput`
/// envelope both parse.
#[derive(Deserialize)]
struct SentMessageWireInput {
    subagent_id: String,
    text: String,
    /// Kept raw: a newer shell may send a delivery this pager does not know.
    #[serde(default)]
    delivery: Option<serde_json::Value>,
}

impl SentMessageWireInput {
    /// `None` ONLY when the wire named a delivery this pager does not know.
    ///
    /// An absent `delivery` is `queue`, not "no class": that is what the tool
    /// does with it (`send_subagent_message::resolve_delivery`, and the shipped
    /// description says "`queue` by default"). Resolving it here is what keeps
    /// an omitted `delivery` and an explicit `"queue"` — the same operation —
    /// from rendering two different verbs.
    fn recognized_delivery(&self) -> Option<SentMessageDelivery> {
        let Some(delivery) = self.delivery.as_ref() else {
            return Some(SentMessageDelivery::Queue);
        };
        match delivery.as_str()? {
            "steer" => Some(SentMessageDelivery::Steer),
            "queue" => Some(SentMessageDelivery::Queue),
            "interject" => Some(SentMessageDelivery::Interject),
            _ => None,
        }
    }
}

pub(super) fn is_tool(tool_call: &acp::ToolCall) -> bool {
    match tool_call
        .meta
        .as_ref()
        .and_then(|meta| meta.get(TOOL_META_KEY))
    {
        Some(meta) => serde_json::from_value::<CanonicalToolMeta>(meta.clone()).is_ok_and(|meta| {
            meta.version == TOOL_META_VERSION && meta.kind == ToolKind::ActiveAgentMessage
        }),
        None => tool_call.title == SEND_SUBAGENT_MESSAGE_TOOL_NAME,
    }
}

pub(super) fn to_block(tool_call: &acp::ToolCall) -> RenderBlock {
    let input = tool_call
        .raw_input
        .as_ref()
        .and_then(|input| SentMessageWireInput::deserialize(input).ok());
    let output =
        tool_call
            .raw_output
            .clone()
            .and_then(
                |output| match serde_json::from_value::<ToolOutput>(output).ok()? {
                    ToolOutput::SendSubagentMessage(output) => Some(output),
                    _ => None,
                },
            );
    let presentation = presentation(tool_call, output);
    let (subagent_id, text, delivery) = input.map_or((None, None, None), |input| {
        let delivery = input.recognized_delivery();
        (Some(input.subagent_id), Some(input.text), delivery)
    });

    RenderBlock::ToolCall(ToolCallBlock::SentMessage(
        SentMessageToolCallBlock::new(presentation, subagent_id, text).with_delivery(delivery),
    ))
}

fn presentation(
    tool_call: &acp::ToolCall,
    output: Option<SendSubagentMessageOutput>,
) -> SentMessagePresentation {
    if !is_terminal(tool_call.status) {
        return SentMessagePresentation::Sending;
    }
    match output {
        Some(output) => match output.disposition() {
            SendSubagentMessageDisposition::Accepted => SentMessagePresentation::Sent,
            SendSubagentMessageDisposition::Rejected => SentMessagePresentation::Rejected {
                reason: output.to_string(),
            },
            SendSubagentMessageDisposition::Unconfirmed => SentMessagePresentation::Unconfirmed {
                reason: output.to_string(),
            },
        },
        None => SentMessagePresentation::Rejected {
            reason: content_text(tool_call).unwrap_or_else(|| {
                "Message was not accepted or delivery details are unavailable.".to_owned()
            }),
        },
    }
}

fn is_terminal(status: acp::ToolCallStatus) -> bool {
    matches!(
        status,
        acp::ToolCallStatus::Completed | acp::ToolCallStatus::Failed
    )
}

fn content_text(tool_call: &acp::ToolCall) -> Option<String> {
    let text = tool_call
        .content
        .iter()
        .filter_map(|content| match content {
            acp::ToolCallContent::Content(acp::Content {
                content: acp::ContentBlock::Text(text),
                ..
            }) => Some(text.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
#[path = "subagent_message_tests.rs"]
mod tests;
