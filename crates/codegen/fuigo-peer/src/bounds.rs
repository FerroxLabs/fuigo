//! Bounds checks shared by the wire types. A value that fails one is never usable.

use std::fmt;

/// Why a wire value was refused. Carries the field name and sizes only, never the offending text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundsError {
    /// `field` holds `got` units (bytes or characters, see `unit`) against a cap of `max`.
    TooLong { field: &'static str, unit: &'static str, max: usize, got: usize },
    /// A list holds more entries than allowed.
    TooMany { field: &'static str, max: usize, got: usize },
    /// A name that is not a valid display name (address-shaped, control or bidi characters, over the cap).
    BadName { field: &'static str },
}

impl fmt::Display for BoundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { field, unit, max, got } => {
                write!(f, "`{field}` is {got} {unit}, the cap is {max}")
            }
            Self::TooMany { field, max, got } => write!(f, "`{field}` has {got} entries, the cap is {max}"),
            Self::BadName { field } => write!(f, "`{field}` is not a valid display name"),
        }
    }
}

impl std::error::Error for BoundsError {}

pub(crate) fn max_bytes(field: &'static str, value: &str, max: usize) -> Result<(), BoundsError> {
    if value.len() > max {
        return Err(BoundsError::TooLong { field, unit: "bytes", max, got: value.len() });
    }
    Ok(())
}
