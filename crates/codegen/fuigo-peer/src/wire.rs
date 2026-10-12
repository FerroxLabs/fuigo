//! Wire contracts for the unix inbox (Fuigo 1.0.25, packet 8a): types only, inert.
//!
//! One connection carries one [`Hello`] each way and then exactly one [`Op`] and its [`Reply`] (S3.2). The
//! op set is closed: `list`, `send`, `notice`. Anything else is a decode error (a watch is the `watch` field of `send`, packet 11). No op and
//! no field can express a human origin, an authority, a mode override or a tool approval (S2.6): a received
//! `Send` carries the same [`Envelope`] a local send does, and the receiver decides everything from its own
//! state. Serialization is serde JSON; a frame is at most [`MAX_FRAME_BYTES`]. This module does no IO and
//! no JSON itself (the crate has no JSON dependency outside tests): [`check_wire_frame`] and the `validate`
//! methods are the checks a transport runs around its own decode.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::address::{Address, HOST_ID_LEN, is_valid_display_name};
use crate::bounds::{BoundsError, max_bytes};
use crate::envelope::Envelope;
use crate::limits::{LIST_PAGE_ROWS, MAX_FRAME_BYTES, MAX_ID_BYTES, MAX_LIST_ROWS};
use crate::outcome::DeliveryOutcome;

/// The one protocol version this build speaks. A different version is answered with
/// [`Reply::Unavailable`] and never reaps a locator row (S3.6).
pub const WIRE_VERSION: u32 = 1;
/// Longest `reason` on an `unavailable` reply, in bytes.
pub const MAX_REASON_BYTES: usize = 256;
/// Pages a `list` can address (`MAX_LIST_ROWS / LIST_PAGE_ROWS`).
pub const MAX_LIST_PAGES: u32 = (MAX_LIST_ROWS / LIST_PAGE_ROWS) as u32;

/// Why a frame or a value was refused. Sizes and field names only, never peer bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The frame is over [`MAX_FRAME_BYTES`].
    FrameTooLarge { len: usize },
    /// A bounded field is over its cap or holds a disallowed character.
    Bounds(BoundsError),
    /// A value outside its closed range (named by field).
    OutOfRange { field: &'static str },
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { len } => write!(f, "frame is {len} bytes, the cap is {MAX_FRAME_BYTES}"),
            Self::Bounds(e) => e.fmt(f),
            Self::OutOfRange { field } => write!(f, "`{field}` is out of range"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<BoundsError> for WireError {
    fn from(e: BoundsError) -> Self {
        Self::Bounds(e)
    }
}

/// The frame-size check, run on the 4-byte length before any allocation (S3.2).
pub const fn check_wire_frame(len: usize) -> Result<(), WireError> {
    if len <= MAX_FRAME_BYTES { Ok(()) } else { Err(WireError::FrameTooLarge { len }) }
}

/// A host id: exactly 32 lower-case hex characters. It can never hold `/`, `.` or anything but hex, so it is
/// safe as a file name (S3.5). The only constructors check; deserializing checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct HostId(String);

impl HostId {
    pub fn new(text: &str) -> Result<Self, WireError> {
        if text.len() != HOST_ID_LEN || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(WireError::OutOfRange { field: "host_id" });
        }
        Ok(Self(text.to_owned()))
    }

    /// The host id of an address (already checked when the address was built).
    pub fn of(address: &Address) -> Self {
        Self(address.host_id().to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for HostId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::new(&text).map_err(serde::de::Error::custom)
    }
}

/// An id that is non-empty and at most [`MAX_ID_BYTES`] bytes (a message id in a notice).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct BoundedId(String);

impl BoundedId {
    pub fn new(text: &str) -> Result<Self, WireError> {
        if text.is_empty() {
            return Err(WireError::OutOfRange { field: "id" });
        }
        max_bytes("id", text, MAX_ID_BYTES)?;
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for BoundedId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::new(&text).map_err(serde::de::Error::custom)
    }
}

/// A short human-readable reason, at most [`MAX_REASON_BYTES`] bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ReasonText(String);

impl ReasonText {
    pub fn new(text: &str) -> Result<Self, WireError> {
        max_bytes("reason", text, MAX_REASON_BYTES)?;
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ReasonText {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::new(&text).map_err(serde::de::Error::custom)
    }
}

/// The first frame each way. The version is one exact integer; any other value is a mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub version: u32,
    pub host_id: HostId,
}

impl Hello {
    pub fn new(host_id: HostId) -> Self {
        Self { version: WIRE_VERSION, host_id }
    }

    /// True only for exactly [`WIRE_VERSION`]. No range, no "newer is fine".
    pub fn version_matches(&self) -> bool {
        self.version == WIRE_VERSION
    }
}

/// Why a notice was sent (S9.3). The kinds are exactly the design's list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeKind {
    Released,
    Expired,
    Refused,
    Denied,
    Idle,
    Exited,
    Unavailable,
}

/// The one operation after the hello. Closed set (S2.6). Unit-like payloads are written `{}` variants so that
/// `deny_unknown_fields` applies (see `DeliveryOutcome`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant, reason = "one short-lived value per connection; boxing would change the public shape for nothing")]
pub enum Op {
    /// One page of the host's sessions, 0-based.
    List { page: u32 },
    /// Deliver an envelope to `to`. The envelope validates itself on decode. `watch` (S9.1) asks the receiver to send ONE
    /// `idle` notice when the turn that consumes the message ends; with an EMPTY body it is a watch only (nothing is
    /// delivered to the model). Absent on the wire when false, so a send without a watch has the bytes it always had, and an
    /// older peer (which rejects the unknown field) makes the sender report `unavailable`.
    Send {
        to: Address,
        envelope: Envelope,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        watch: bool,
    },
    /// A delivery notice for a message id the receiver has an outstanding record for (S9.3).
    Notice { message_id: BoundedId, kind: NoticeKind },
}

impl Op {
    /// Checks beyond what decoding already enforces (the page range).
    pub fn validate(&self) -> Result<(), WireError> {
        match self {
            Self::List { page } if *page >= MAX_LIST_PAGES => Err(WireError::OutOfRange { field: "page" }),
            Self::Send { envelope, .. } => Ok(envelope.validate()?),
            _ => Ok(()),
        }
    }
}

/// One listed session. A display claim; the address is what routes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRow {
    pub address: Address,
    /// Manual title or empty.
    pub name: String,
    pub session_ref: String,
}

/// The one reply after the op.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    List { rows: Vec<SessionRow>, more: bool },
    Send { outcome: DeliveryOutcome },
    /// Acknowledges a notice. Carries nothing.
    Notice {},
    /// The host cannot serve this (feature off, version mismatch, sandbox, stale incarnation).
    Unavailable { reason: ReasonText },
}

impl Reply {
    /// Row count and name checks that decoding alone does not do.
    pub fn validate(&self) -> Result<(), WireError> {
        if let Self::List { rows, .. } = self {
            if rows.len() > LIST_PAGE_ROWS {
                return Err(BoundsError::TooMany { field: "rows", max: LIST_PAGE_ROWS, got: rows.len() }.into());
            }
            for r in rows {
                if !is_valid_display_name(&r.name) {
                    return Err(BoundsError::BadName { field: "rows.name" }.into());
                }
                max_bytes("rows.session_ref", &r.session_ref, MAX_ID_BYTES)?;
            }
        }
        Ok(())
    }
}
