//! Argument types for the model-facing tools. Types only: nothing here is registered with the model.
//! Unknown fields are rejected, and there is no field for `from`, name, mode, hop or denials (S2.5).
//! Deserializing runs the caps (`validate`); `Debug` prints lengths only.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::bounds::{BoundsError, max_bytes};
use crate::limits::*;

pub const LIST_AGENTS_TOOL: &str = "list_agents";
pub const SEND_MESSAGE_TOOL: &str = "send_message";
pub const REFUSE_PEER_MESSAGE_TOOL: &str = "refuse_peer_message";

/// `list_agents` takes no arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListAgentsArgs {}

/// `send_message {to, message?, notify_when_idle?, summary?}` (section 2, row 3a).
/// `summary` never leaves the sender.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SendMessageArgsRaw")]
pub struct SendMessageArgs {
    pub to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_when_idle: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendMessageArgsRaw {
    to: String,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    notify_when_idle: Option<bool>,
    #[serde(default)]
    summary: Option<String>,
}

impl TryFrom<SendMessageArgsRaw> for SendMessageArgs {
    type Error = BoundsError;

    fn try_from(r: SendMessageArgsRaw) -> Result<Self, BoundsError> {
        let a = Self {
            to: r.to,
            message: r.message,
            notify_when_idle: r.notify_when_idle,
            summary: r.summary,
        };
        a.validate()?;
        Ok(a)
    }
}

impl SendMessageArgs {
    /// Body, summary and `to` caps. Name validity is the resolver's job (`resolve_target`).
    pub fn validate(&self) -> Result<(), BoundsError> {
        max_bytes("to", &self.to, MAX_TO_BYTES)?;
        if let Some(m) = &self.message {
            max_bytes("message", m, MAX_BODY_BYTES)?;
        }
        if let Some(s) = &self.summary {
            max_bytes("summary", s, MAX_SUMMARY_BYTES)?;
        }
        Ok(())
    }
}

impl fmt::Debug for SendMessageArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendMessageArgs")
            .field("to_len", &self.to.len())
            .field("message_len", &self.message.as_ref().map(String::len))
            .field("notify_when_idle", &self.notify_when_idle)
            .field("summary_len", &self.summary.as_ref().map(String::len))
            .finish()
    }
}

/// `refuse_peer_message {message_id, reason}` (S7.4).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RefusePeerMessageArgsRaw")]
pub struct RefusePeerMessageArgs {
    pub message_id: String,
    pub reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusePeerMessageArgsRaw {
    message_id: String,
    reason: String,
}

impl TryFrom<RefusePeerMessageArgsRaw> for RefusePeerMessageArgs {
    type Error = BoundsError;

    fn try_from(r: RefusePeerMessageArgsRaw) -> Result<Self, BoundsError> {
        let a = Self { message_id: r.message_id, reason: r.reason };
        a.validate()?;
        Ok(a)
    }
}

impl RefusePeerMessageArgs {
    pub fn validate(&self) -> Result<(), BoundsError> {
        max_bytes("message_id", &self.message_id, MAX_ID_BYTES)?;
        max_bytes("reason", &self.reason, MAX_REFUSE_REASON_BYTES)
    }
}

impl fmt::Debug for RefusePeerMessageArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefusePeerMessageArgs")
            .field("message_id_len", &self.message_id.len())
            .field("reason_len", &self.reason.len())
            .finish()
    }
}
