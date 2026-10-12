//! The message envelope the sending host stamps (S2.5, S5.6, S7.2). Every field except the body is
//! a claim by a cooperative same-user process (S3.7); only the mode-equality hold relies on them.

use serde::{Deserialize, Serialize};

use std::fmt;

use crate::address::{Address, is_valid_display_name};
use crate::bounds::{BoundsError, max_bytes};
use crate::limits::*;
use crate::mode::PeerMode;

/// Who answers permission requests (S4.4, S4.5). Paired with the mode for the hold rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorKind {
    Human,
    Auto,
    None,
}

/// One recent permission denial (S7.1): the tool kind and a hash of the normalised target.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenialStamp {
    pub tool_kind: String,
    pub target_hash: String,
}

impl fmt::Debug for DenialStamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DenialStamp")
            .field("tool_kind_len", &self.tool_kind.len())
            .field("target_hash_len", &self.target_hash.len())
            .finish()
    }
}

/// What travels between hosts. The model's tool has no field for any of these but the body (S2.5).
///
/// Deserializing runs [`Envelope::validate`] (the bounds), so bytes never become an `Envelope` without
/// passing the caps. `PartialEq` only: a [`PeerMode::Unknown`] sender mode makes an envelope unequal to itself.
/// `Debug` prints lengths only, never the body or names.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "RawEnvelope")]
pub struct Envelope {
    pub message_id: String,
    /// Per sender-receiver pair, so arrival order is send order (section 2, row 3b).
    pub seq: u64,
    pub from: Address,
    /// Manual title only, cut to 64 characters; empty when the title is automatic (S1.7).
    pub from_name: String,
    /// The sender's auto-title, kept apart from `from_name` (S1.7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_auto_title: Option<String>,
    pub from_ref: String,
    pub from_mode: PeerMode,
    pub from_operator: OperatorKind,
    pub conversation_id: String,
    pub hop: u32,
    /// Recent denials, newest last; empty when none in the last 30 minutes (S7.2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_recently: Vec<DenialStamp>,
    pub body: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvelope {
    message_id: String,
    seq: u64,
    from: Address,
    from_name: String,
    #[serde(default)]
    from_auto_title: Option<String>,
    from_ref: String,
    from_mode: PeerMode,
    from_operator: OperatorKind,
    conversation_id: String,
    hop: u32,
    #[serde(default)]
    denied_recently: Vec<DenialStamp>,
    body: String,
}

impl TryFrom<RawEnvelope> for Envelope {
    type Error = BoundsError;

    fn try_from(r: RawEnvelope) -> Result<Self, BoundsError> {
        let e = Envelope {
            message_id: r.message_id,
            seq: r.seq,
            from: r.from,
            from_name: r.from_name,
            from_auto_title: r.from_auto_title,
            from_ref: r.from_ref,
            from_mode: r.from_mode,
            from_operator: r.from_operator,
            conversation_id: r.conversation_id,
            hop: r.hop,
            denied_recently: r.denied_recently,
            body: r.body,
        };
        e.validate()?;
        Ok(e)
    }
}

impl Envelope {
    /// Enforce the body, name, id and denial caps. Every deserialize path calls this, so it is the only way to
    /// get an `Envelope` from bytes.
    pub fn validate(&self) -> Result<(), BoundsError> {
        max_bytes("body", &self.body, MAX_BODY_BYTES)?;
        max_bytes("message_id", &self.message_id, MAX_ID_BYTES)?;
        max_bytes("conversation_id", &self.conversation_id, MAX_ID_BYTES)?;
        max_bytes("from_ref", &self.from_ref, MAX_ID_BYTES)?;
        if !is_valid_display_name(&self.from_name) {
            return Err(BoundsError::BadName { field: "from_name" });
        }
        if let Some(t) = &self.from_auto_title
            && !is_valid_display_name(t)
        {
            return Err(BoundsError::BadName { field: "from_auto_title" });
        }
        if self.denied_recently.len() > MAX_DENIAL_STAMPS {
            return Err(BoundsError::TooMany {
                field: "denied_recently",
                max: MAX_DENIAL_STAMPS,
                got: self.denied_recently.len(),
            });
        }
        for d in &self.denied_recently {
            max_bytes("denied_recently.tool_kind", &d.tool_kind, MAX_DENIAL_FIELD_BYTES)?;
            max_bytes("denied_recently.target_hash", &d.target_hash, MAX_DENIAL_FIELD_BYTES)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("message_id_len", &self.message_id.len())
            .field("seq", &self.seq)
            .field("from", &self.from)
            .field("from_name_len", &self.from_name.len())
            .field("from_auto_title_len", &self.from_auto_title.as_ref().map(String::len))
            .field("from_ref_len", &self.from_ref.len())
            .field("from_mode", &self.from_mode)
            .field("from_operator", &self.from_operator)
            .field("conversation_id_len", &self.conversation_id.len())
            .field("hop", &self.hop)
            .field("denied_recently_count", &self.denied_recently.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}
