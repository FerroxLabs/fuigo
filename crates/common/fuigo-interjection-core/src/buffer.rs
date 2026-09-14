use serde::{Deserialize, Serialize};

use crate::events::EventQueue;
use crate::format::{format_interjection, format_parent_agent_interjection};

/// Who authored a buffered interjection.
///
/// The two are framed and resolved differently by the host: a human
/// interjection is the user speaking mid-turn; a parent-agent message is
/// model-authored, untrusted text from an owning agent. Collapsing them would
/// let a parent agent speak with user authority.
///
/// The parent variant carries the message's identity because a buffered entry
/// is not always drained into the running turn: a turn abort, a chat-state
/// failure, or a turn-end strand sends it back out as a queued prompt turn, and
/// the host has to rebuild the original model-authored origin from what the
/// entry itself carries.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterjectionAuthority {
    #[default]
    User,
    ParentAgent {
        message_id: String,
        sender_session_id: String,
    },
}

/// A buffered mid-turn interjection awaiting the next safe drain point.
/// `Attachment` is host-defined (inline images, asset IDs); core never reads it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingInterjection<Attachment> {
    pub text: String,
    pub attachments: Vec<Attachment>,
    /// Defaults to [`InterjectionAuthority::User`], which is what every
    /// pre-existing entry (and every persisted one) is.
    #[serde(default)]
    pub authority: InterjectionAuthority,
}

/// Hand-written so `..Default::default()` works for any `Attachment`, including
/// host attachment types that are not themselves `Default`.
impl<Attachment> Default for PendingInterjection<Attachment> {
    fn default() -> Self {
        Self {
            text: String::new(),
            attachments: Vec::new(),
            authority: InterjectionAuthority::User,
        }
    }
}

/// A drained entry, wrapped and ready to emit as a synthetic user message.
#[derive(Debug, Clone, PartialEq)]
pub struct FormattedInterjection<Attachment> {
    pub text: String,
    pub attachments: Vec<Attachment>,
}

/// A queue of pending interjections — just an [`EventQueue`] of
/// [`PendingInterjection`]. Use [`drain_formatted`] to drain + frame them as
/// synthetic user messages.
pub type InterjectionBuffer<Attachment> = EventQueue<PendingInterjection<Attachment>>;

/// Drain `buffer`, framing each entry as a synthetic user message (FIFO, one
/// message per entry, never merged). `sanitize_text` runs on the raw text first
/// (hosts strip artifacts like image placeholder paths; pass
/// `std::convert::identity` if none).
pub fn drain_formatted<Attachment>(
    buffer: &InterjectionBuffer<Attachment>,
    sanitize_text: impl Fn(String) -> String,
) -> Vec<FormattedInterjection<Attachment>> {
    buffer
        .drain_all()
        .into_iter()
        .map(|entry| FormattedInterjection {
            text: match entry.authority {
                InterjectionAuthority::User => format_interjection(sanitize_text(entry.text)),
                InterjectionAuthority::ParentAgent { .. } => {
                    format_parent_agent_interjection(sanitize_text(entry.text))
                }
            },
            attachments: entry.attachments,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_formatted_sanitizes_wraps_and_preserves_order() {
        let buf: InterjectionBuffer<()> = InterjectionBuffer::new();
        buf.push(PendingInterjection {
            text: "look at [SECRET] one".into(),
            ..Default::default()
        });
        buf.push(PendingInterjection {
            text: "two".into(),
            ..Default::default()
        });

        let out = drain_formatted(&buf, |t| t.replace("[SECRET] ", ""));
        assert!(buf.is_empty());
        assert_eq!(out.len(), 2, "one message per entry, never merged");
        assert!(
            out[0]
                .text
                .contains("<user_query>\nlook at one\n</user_query>")
        );
        assert!(out[1].text.contains("<user_query>\ntwo\n</user_query>"));
        assert!(
            out[0]
                .text
                .starts_with("The user sent a message while you were working:")
        );
    }

    #[test]
    fn drain_formatted_frames_a_parent_agent_entry_as_the_agent() {
        let buf: InterjectionBuffer<()> = InterjectionBuffer::new();
        buf.push(PendingInterjection {
            text: "stop and do X instead".into(),
            authority: InterjectionAuthority::ParentAgent {
                message_id: "m1".into(),
                sender_session_id: "root-session".into(),
            },
            ..Default::default()
        });

        let out = drain_formatted(&buf, std::convert::identity);
        assert!(
            out[0].text.starts_with(crate::format::PARENT_AGENT_NOTE),
            "got: {}",
            out[0].text
        );
        assert!(
            !out[0].text.contains("<user_query>"),
            "got: {}",
            out[0].text
        );
    }
}
