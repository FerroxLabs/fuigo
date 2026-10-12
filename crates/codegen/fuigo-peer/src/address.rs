//! The opaque session address and the `name [ref]` form (section 1; section 2 rows 1, 3e, 7).
//!
//! An address is `fuigo-peer:<host-id>/<session-id>/<incarnation>`. The host id is 32 lowercase hex
//! characters (S3.5). The incarnation counts how many times that session was loaded into that host,
//! so an address held across a restart or reload is stale and cannot reach a new session.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::limits::{MAX_ADDRESS_SESSION_ID_CHARS, MAX_NAME_CHARS};

/// Scheme prefix. A `to` that starts with it is parsed strictly as an address and never as a name.
pub const ADDRESS_PREFIX: &str = "fuigo-peer:";
/// Characters in a host id (128 random bits as hex).
pub const HOST_ID_LEN: usize = 32;
/// Shortest and longest `[ref]` (8 characters of session id, plus 4 of host id on a collision).
pub const REF_LEN_RANGE: std::ops::RangeInclusive<usize> = 8..=12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    MissingPrefix,
    BadHostId,
    BadSessionId,
    BadIncarnation,
    WrongPartCount,
    /// A name that is not a valid display name (see [`is_valid_display_name`]).
    InvalidName,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingPrefix => "address must start with `fuigo-peer:`",
            Self::BadHostId => "host id must be 32 lowercase hex characters",
            Self::BadSessionId => "session id is empty, too long, or has a disallowed character",
            Self::BadIncarnation => "incarnation must be a decimal number",
            Self::WrongPartCount => "address must be `fuigo-peer:<host-id>/<session-id>/<incarnation>`",
            Self::InvalidName => "name is not a valid display name",
        })
    }
}

impl std::error::Error for AddressError {}

/// A parsed peer address. Compare whole values; never redirect an old incarnation to a new one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    host_id: String,
    session_id: String,
    incarnation: u64,
}

fn valid_session_id(s: &str) -> bool {
    !s.is_empty()
        && s.chars().count() <= MAX_ADDRESS_SESSION_ID_CHARS
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl Address {
    pub fn new(host_id: &str, session_id: &str, incarnation: u64) -> Result<Self, AddressError> {
        if host_id.len() != HOST_ID_LEN
            || !host_id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(AddressError::BadHostId);
        }
        if !valid_session_id(session_id) {
            return Err(AddressError::BadSessionId);
        }
        Ok(Self {
            host_id: host_id.to_owned(),
            session_id: session_id.to_owned(),
            incarnation,
        })
    }

    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn incarnation(&self) -> u64 {
        self.incarnation
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{ADDRESS_PREFIX}{}/{}/{}", self.host_id, self.session_id, self.incarnation)
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s.strip_prefix(ADDRESS_PREFIX).ok_or(AddressError::MissingPrefix)?;
        let parts: Vec<&str> = rest.split('/').collect();
        let [host, session, incarnation] = parts.as_slice() else {
            return Err(AddressError::WrongPartCount);
        };
        // Digits only: no sign, no whitespace, no leading `+` that `u64::from_str` would accept.
        if incarnation.is_empty() || !incarnation.bytes().all(|b| b.is_ascii_digit()) {
            return Err(AddressError::BadIncarnation);
        }
        let incarnation = incarnation.parse::<u64>().map_err(|_| AddressError::BadIncarnation)?;
        let addr = Self::new(host, session, incarnation)?;
        // Canonical form only, so one session has one spelling (`007` is refused).
        if addr.to_string() != s {
            return Err(AddressError::BadIncarnation);
        }
        Ok(addr)
    }
}

impl Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Bidirectional-control characters that can reorder displayed text: ALM, LRM, RLM, LRE..RLO, LRI..PDI.
pub const BIDI_CONTROLS: &[char] = &[
    '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
];

/// True when `s` begins with the address scheme in any letter case.
fn has_address_prefix_any_case(s: &str) -> bool {
    s.as_bytes()
        .get(..ADDRESS_PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(ADDRESS_PREFIX.as_bytes()))
}

/// Whether `name` may be shown and routed as a display name. It must not parse as an address, must not begin
/// with `fuigo-peer:` in any letter case, must hold no control character (C0, DEL, C1), no U+2028 / U+2029 and
/// no bidi control, and must be at most [`MAX_NAME_CHARS`] characters. The empty string passes (it means "no
/// manual title"); a caller that needs a non-empty name checks that itself.
pub fn is_valid_display_name(name: &str) -> bool {
    name.chars().count() <= MAX_NAME_CHARS
        && !has_address_prefix_any_case(name)
        && name.parse::<Address>().is_err()
        && !name
            .chars()
            .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}' || BIDI_CONTROLS.contains(&c))
}

/// `Name [ref]`: the form `list_agents` shows. Only a trailing `[ref]` counts; brackets anywhere
/// else in the name belong to the name.
#[derive(Clone, PartialEq, Eq)]
pub struct NameRef<'a> {
    pub name: &'a str,
    pub reference: &'a str,
}

impl fmt::Debug for NameRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NameRef")
            .field("name_len", &self.name.len())
            .field("reference_len", &self.reference.len())
            .finish()
    }
}

/// Split a trailing ` [ref]` off `s`. The ref is 8 to 12 ASCII alphanumeric or `-` characters and
/// must be preceded by a space; the name before it must be non-empty. `None` means "all name".
pub fn parse_name_ref(s: &str) -> Option<NameRef<'_>> {
    let inner = s.strip_suffix(']')?;
    let open = inner.rfind('[')?;
    let reference = &inner[open + 1..];
    let name = inner[..open].strip_suffix(' ')?;
    let ok_ref = REF_LEN_RANGE.contains(&reference.len())
        && reference.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if name.trim().is_empty() || !ok_ref {
        return None;
    }
    Some(NameRef { name, reference })
}

/// What a model-supplied `to` means (section 2, row 7). Resolution against live rows is a later packet.
#[derive(Clone, PartialEq, Eq)]
pub enum Target<'a> {
    Address(Address),
    NameRef(NameRef<'a>),
    Name(&'a str),
}

impl fmt::Debug for Target<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(a) => f.debug_tuple("Address").field(a).finish(),
            Self::NameRef(n) => f.debug_tuple("NameRef").field(n).finish(),
            Self::Name(n) => f.debug_struct("Name").field("len", &n.len()).finish(),
        }
    }
}

/// A `to` starting with `fuigo-peer:` (any letter case) is an address or an error, never a name (section 2,
/// row 3e). A string that fails [`is_valid_display_name`] is never routed as a name: it is an error.
pub fn resolve_target(to: &str) -> Result<Target<'_>, AddressError> {
    if has_address_prefix_any_case(to) {
        // `parse` is case-sensitive, so `FUIGO-PEER:...` is an error here, not a name.
        return to.parse().map(Target::Address);
    }
    Ok(match parse_name_ref(to) {
        Some(nr) => {
            if !is_valid_display_name(nr.name) {
                return Err(AddressError::InvalidName);
            }
            Target::NameRef(nr)
        }
        None => {
            if !is_valid_display_name(to) {
                return Err(AddressError::InvalidName);
            }
            Target::Name(to)
        }
    })
}
