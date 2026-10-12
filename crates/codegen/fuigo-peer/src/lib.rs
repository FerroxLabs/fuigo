//! Contracts for peer messaging (Fuigo 1.0.25, packet 1): types only.
//!
//! Nothing here opens a socket, registers a tool or touches a session. Later packets
//! build the transport, admission and tools on these definitions.

pub mod address;
pub mod bounds;
pub mod envelope;
pub mod host;
pub mod ingress;
pub mod limits;
pub mod locator_row;
pub mod mode;
pub mod outcome;
pub mod tools;
pub mod wire;

pub use address::{
    BIDI_CONTROLS,
    Address, AddressError, NameRef, Target, is_valid_display_name, parse_name_ref, resolve_target,
};
pub use bounds::BoundsError;
pub use ingress::{
    HostLedger, HostSaturated, IngressConfig, IngressSizes, IngressVerdict, PeerIngress, PeerTurnBudget, Ticket, TurnOrigin,
    check_body, check_frame, frame_within_limit, hop_exhausted, next_hop,
};
pub use envelope::{DenialStamp, Envelope, OperatorKind};
pub use locator_row::{
    DirChoice, DirUnavailable, HostDir, HostRow, Reap, RowsError, TryResult, choose_dir, parse_rows, reap_decision, runtime_home_dir, runtime_peers_dir, socket_path,
};
pub use mode::{KnownPeerMode, PeerBase, PeerMode};
pub use outcome::{DeliveryOutcome, HoldReason, RejectReason};
pub use wire::{
    BoundedId, Hello, HostId, NoticeKind, Op, ReasonText, Reply, SessionRow, WIRE_VERSION, WireError, check_wire_frame,
};

#[cfg(test)]
mod ingress_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wire_tests;
