//! The Windows file rule for a file we are about to trust, judged on the OPEN HANDLE: not a reparse point, not a
//! directory, exactly one link, owner is us (or BUILTIN\\Administrators when our token is elevated), and every ACE of the
//! DACL is a plain allow for us, SYSTEM or BUILTIN\\Administrators.
//!
//! One checker for every caller (the peer locator in `fuigo-shell`, the bearer token file in `fuigo-mcp`). The pure policy
//! ([`policy`]) compiles and is tested on every OS; the OS-calling part ([`sys`]) is Windows only.

pub mod policy;
#[cfg(windows)]
pub mod sys;

#[cfg(all(windows, feature = "test-support"))]
pub mod test_support;

pub use policy::*;
#[cfg(windows)]
pub use sys::{FileAclRefusal, check_owner_only_file, check_owner_only_file_capped, drive_is_remote, our_sid, owner_and_dacl, read_owner_dacl, token_elevated};
