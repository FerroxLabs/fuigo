//! Delivery outcomes (section 2, row 3a). `unknown` is the sender's own result after one retry.

use serde::{Deserialize, Serialize};

/// Why a message is held for the receiver's human (S4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReason {
    ModeMismatch,
    LoopGuard,
    SenderDenied,
    Integrity,
    /// Receiver policy is `hold` (S4.2): held although the modes match.
    PolicyHold,
}

/// Why a message was refused outright. The names come from the design text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    Unavailable,
    NoOperator,
    Saturated,
    RateLimited,
    StaleAddress,
    Ambiguous,
    /// Receiver policy is `refuse` (S4.2).
    PolicyRefused,
    /// Body or frame over the cap (S5.1).
    TooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
/// The unit outcomes are written `{}` variants: serde ignores `deny_unknown_fields` on a unit variant
/// of an internally tagged enum, and an outcome with stray fields must not parse.
pub enum DeliveryOutcome {
    Delivered {},
    Held {
        reason: HoldReason,
        /// Unix seconds.
        expires_at: u64,
    },
    Watching {},
    Rejected {
        reason: RejectReason,
    },
    Unknown {},
}
