//! The sender's mode as it travels in the envelope. It carries every value of the workspace's effective report
//! (base mode, plan flag, session edit grant) losslessly, so two sessions compare equal only when they behave
//! the same. The wire form is one string: `<base>[+plan][+grant]`, e.g. `yolo+plan` or `auto+grant`.
//! Anything else deserializes to [`PeerMode::Unknown`], which is unequal to every value including itself.

use serde::{Deserialize, Serialize};

/// The base permission modes (the report minus the plan flag and the edit grant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerBase {
    Default,
    AcceptEdits,
    Auto,
    DontAsk,
    BypassPermissions,
    /// A user, project or CLI catch-all `Allow Any` rule.
    AllowAnyRule,
    Yolo,
    AllowAll,
    AlwaysAllow,
}

impl PeerBase {
    pub const ALL: [PeerBase; 9] = [
        Self::Default,
        Self::AcceptEdits,
        Self::Auto,
        Self::DontAsk,
        Self::BypassPermissions,
        Self::AllowAnyRule,
        Self::Yolo,
        Self::AllowAll,
        Self::AlwaysAllow,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::AcceptEdits => "acceptEdits",
            Self::Auto => "auto",
            Self::DontAsk => "dontAsk",
            Self::BypassPermissions => "bypassPermissions",
            Self::AllowAnyRule => "allowAnyRule",
            Self::Yolo => "yolo",
            Self::AllowAll => "allowAll",
            Self::AlwaysAllow => "alwaysAllow",
        }
    }

    fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|b| b.as_str() == s)
    }
}

/// A mode this build understands: all three dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KnownPeerMode {
    pub plan_active: bool,
    pub base: PeerBase,
    pub session_edit_grant: bool,
}

/// The envelope's sender mode. `Unknown` carries nothing and equals nothing, itself included, so a mode
/// this build cannot read can never satisfy a mode-equality check.
#[derive(Debug, Clone, Copy)]
pub enum PeerMode {
    Known(KnownPeerMode),
    Unknown,
}

impl PartialEq for PeerMode {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Known(a), Self::Known(b)) => a == b,
            _ => false,
        }
    }
}

impl PeerMode {
    pub fn new(plan_active: bool, base: PeerBase, session_edit_grant: bool) -> Self {
        Self::Known(KnownPeerMode { plan_active, base, session_edit_grant })
    }

    pub fn known(&self) -> Option<KnownPeerMode> {
        match self {
            Self::Known(k) => Some(*k),
            Self::Unknown => None,
        }
    }

    /// Every known value: 9 bases x plan x grant = 36.
    pub fn all_known() -> impl Iterator<Item = PeerMode> {
        PeerBase::ALL.into_iter().flat_map(|base| {
            [false, true].into_iter().flat_map(move |plan| {
                [false, true].into_iter().map(move |grant| PeerMode::new(plan, base, grant))
            })
        })
    }

    pub fn to_wire(&self) -> String {
        match self {
            Self::Unknown => "unknown".to_owned(),
            Self::Known(k) => {
                let mut s = k.base.as_str().to_owned();
                if k.plan_active {
                    s.push_str("+plan");
                }
                if k.session_edit_grant {
                    s.push_str("+grant");
                }
                s
            }
        }
    }

    /// Strict, canonical parse; every other string is [`PeerMode::Unknown`].
    pub fn from_wire(s: &str) -> Self {
        let mut parts = s.split('+');
        let Some(base) = parts.next().and_then(PeerBase::from_name) else {
            return Self::Unknown;
        };
        let rest: Vec<&str> = parts.collect();
        let (plan_active, session_edit_grant) = match rest.as_slice() {
            [] => (false, false),
            ["plan"] => (true, false),
            ["grant"] => (false, true),
            ["plan", "grant"] => (true, true),
            _ => return Self::Unknown,
        };
        Self::new(plan_active, base, session_edit_grant)
    }
}

impl Serialize for PeerMode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_wire())
    }
}

impl<'de> Deserialize<'de> for PeerMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from_wire(&String::deserialize(d)?))
    }
}
