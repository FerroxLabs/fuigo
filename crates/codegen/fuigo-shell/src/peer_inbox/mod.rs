//! Hardened locator files for the peer inbox (packet 8b; DESIGN S3.3, S3.4).
//!
//! Directory and file helpers only: no socket, no listener, no caller outside tests until packet 8d.
//! Locator content is opaque bytes here. Every function is SYNCHRONOUS and does blocking file I/O
//! (`update_locator` may also block on an `flock`): async callers must go through `spawn_blocking`.
//! Every failure is a typed [`Disabled`] value; nothing here builds a string from file content or logs it.
// Inert until packet 8d (inbox and dialer) calls these helpers; only the tests use them now.
#![cfg_attr(not(test), allow(dead_code))]

mod conn;
#[cfg(test)]
mod conn_tests;
#[cfg(unix)]
mod dial;
mod directory;
mod dirs;
pub(crate) mod driver;
pub(crate) mod host;
#[cfg(unix)]
mod inbox;
#[cfg(all(test, unix))]
mod inbox_tests;
mod locator;
#[cfg(test)]
mod locator_tests;
#[cfg(all(test, unix))]
mod host_tests;
#[cfg(all(test, unix))]
mod hardening_tests;
#[cfg(unix)]
mod reap;
mod rows;
mod watch;
#[cfg(all(test, unix))]
mod watch_tests;
pub(crate) mod tool_host;
#[cfg(test)]
mod tool_host_tests;
#[cfg(all(test, unix))]
mod uid_tests;
#[cfg(windows)]
mod win_dirs;
#[cfg(windows)]
mod win_inbox;
mod win_logic;
#[cfg(windows)]
mod win_watch;
#[cfg(windows)]
mod win_locator;
#[cfg(windows)]
mod win_pipe;
mod win_policy;
#[cfg(windows)]
#[doc(hidden)]
pub mod win_evidence;

#[cfg(unix)]
pub(crate) use inbox::{PeerInbox, StartOptions};
#[cfg(windows)]
pub(crate) use win_inbox::{PeerInbox, StartOptions};
/// Neither unix nor windows: there is no listener and no dialer; `start` only reports why. The type has no value, so the
/// methods below exist only to let host code compile.
#[cfg(not(any(unix, windows)))]
pub(crate) struct PeerInbox(std::convert::Infallible);
#[cfg(not(any(unix, windows)))]
impl PeerInbox {
    pub(crate) async fn start(_home: &std::path::Path) -> Result<PeerInbox, Disabled> {
        Err(Disabled::UnsupportedPlatform)
    }
    pub(crate) fn host_id(&self) -> &fuigo_peer::HostId {
        match self.0 {}
    }
    pub(crate) fn directory(&self) -> &std::sync::Arc<directory::PeerDirectory> {
        match self.0 {}
    }
    pub(crate) async fn shutdown(&self) {
        match self.0 {}
    }
}

pub(crate) use dirs::CheckedDir;
pub(crate) use locator::{read_locator, update_locator, update_locator_rewriting};

/// Why a single file failed its S3.4 checks. A file that fails is never parsed and never followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reject {
    Symlink,
    NotRegular,
    WrongOwner,
    WrongMode,
    HardLinked,
    TooLarge,
}

/// Why peer messaging is disabled (or one locator operation refused). Typed, never built from file content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disabled {
    UnsupportedPlatform,
    /// `features.peer_messaging` is off: returned before any file system call (8d).
    FeatureOff,
    /// The home path is too long for a socket and there is no usable runtime directory (S3.5) (8d).
    SocketDirUnavailable,
    /// Something already exists at the socket path we are about to bind: fail closed (8d).
    SocketPathExists,
    /// The socket we bound is not a socket owned by us with mode 0600 (8d).
    SocketCheckFailed,
    HomeNotAbsolute,
    HomePathNotNormal,
    HomeMissing,
    SymlinkedHome,
    HomeNotDirectory,
    HomeWrongOwner,
    HomeWritableByOthers,
    AncestorMissing,
    AncestorSymlink,
    AncestorNotDirectory,
    AncestorWrongOwner,
    AncestorWritableByOthers,
    PeersMissing,
    PeersSymlink,
    PeersNotDirectory,
    PeersWrongOwner,
    PeersWrongMode,
    /// The locator name is empty, has a separator or NUL, is `.`/`..`, or collides with the lock/temp names.
    InvalidName,
    /// The locator file failed its checks (a read reports this; `update_locator` refuses on it).
    Rejected(Reject),
    /// The lock file failed its checks (for example it is a symlink).
    LockRejected(Reject),
    /// The bytes `f` produced exceed the 64 KiB cap.
    OutputTooLarge,
    /// Our row could not be published because the locator already holds the maximum number of rows. Not terminal:
    /// the next session registration may retry, at most once a minute.
    LocatorFull,
    /// The start task panicked; the inbox is off for this process.
    StartPanicked,
    /// Another process held the directory lock for the whole 2 s bound (8d round 2).
    LockBusy,
    /// `XDG_RUNTIME_DIR` is not absolute, not ours, or writable by others: no runtime branch (8d round 2).
    RuntimeDirUnavailable,
    /// An OS error with its errno (no text).
    Io(i32),
    /// Windows: our own account could not be read.
    IdentityUnreadable,
    /// Windows: the inbox pipe name already exists (a pre-created pipe).
    PipeNameInUse,
    /// Windows: the inbox pipe could not be created.
    PipeCreateFailed,
    /// Windows: the inbox pipe failed its owner / DACL read-back.
    PipeCheckFailed,
    /// Windows: the checked `peers` directory is no longer the directory that was opened (identity mismatch).
    PeersMoved,
    /// Windows: this process runs in a network (remote) logon session (decision 56).
    NetworkLogon,
    /// S4.1: a remote / relay client is connected to this leader process; none of its sessions can message peers.
    RemoteClientAttached,
}

/// Maximum locator file size: 64 KiB.
pub(crate) const MAX_LOCATOR_BYTES: u64 = 64 * 1024;

impl Disabled {
    /// A short FIXED human text for this reason (never built from file content). Later packets (8d/8e) show it
    /// in `/peers` and `list_agents`. Disabling only makes the peer inbox unavailable; nothing else depends on it.
    pub(crate) fn reason_text(&self) -> &'static str {
        match self {
            Disabled::SymlinkedHome => {
                "peer messaging is unavailable: the Fuigo home is a symbolic link"
            }
            Disabled::UnsupportedPlatform => "peer messaging is unavailable: unsupported platform",
            Disabled::FeatureOff => "peer messaging is unavailable: the feature is off",
            Disabled::RemoteClientAttached => "peer messaging is unavailable: a remote client is connected to this Fuigo",
            Disabled::SocketDirUnavailable => {
                "peer messaging is unavailable: no usable directory for the inbox socket"
            }
            Disabled::SocketPathExists | Disabled::SocketCheckFailed => {
                "peer messaging is unavailable: the inbox socket path failed its safety checks"
            }
            Disabled::HomeNotAbsolute | Disabled::HomePathNotNormal => {
                "peer messaging is unavailable: the Fuigo home path is not a plain absolute path"
            }
            Disabled::HomeMissing | Disabled::HomeNotDirectory => {
                "peer messaging is unavailable: the Fuigo home is missing or not a directory"
            }
            Disabled::HomeWrongOwner | Disabled::HomeWritableByOthers => {
                "peer messaging is unavailable: the Fuigo home is not private to this user"
            }
            Disabled::AncestorMissing
            | Disabled::AncestorSymlink
            | Disabled::AncestorNotDirectory
            | Disabled::AncestorWrongOwner
            | Disabled::AncestorWritableByOthers => {
                "peer messaging is unavailable: a parent directory of the Fuigo home is not trusted"
            }
            Disabled::PeersMissing
            | Disabled::PeersSymlink
            | Disabled::PeersNotDirectory
            | Disabled::PeersWrongOwner
            | Disabled::PeersWrongMode => {
                "peer messaging is unavailable: the peers directory failed its safety checks"
            }
            Disabled::InvalidName => "peer messaging is unavailable: invalid locator name",
            Disabled::Rejected(_) | Disabled::LockRejected(_) => {
                "peer messaging is unavailable: a locator file failed its safety checks"
            }
            Disabled::LockBusy => "peer messaging is unavailable: the locator lock is busy",
            Disabled::RuntimeDirUnavailable => {
                "peer messaging is unavailable: the runtime directory is not private to this user"
            }
            Disabled::StartPanicked => "peer messaging is unavailable: the inbox failed to start",
            Disabled::LocatorFull => "peer messaging is unavailable: the host list is full of other hosts",
            Disabled::OutputTooLarge => "peer messaging is unavailable: locator data too large",
            Disabled::IdentityUnreadable => "peer messaging is unavailable: this user account could not be read",
            Disabled::PipeNameInUse => "peer messaging is unavailable: the inbox pipe name is already in use",
            Disabled::PipeCreateFailed => "peer messaging is unavailable: the inbox pipe could not be created",
            Disabled::PipeCheckFailed => "peer messaging is unavailable: the inbox pipe failed its safety checks",
            Disabled::PeersMoved => "peer messaging is unavailable: the peers directory changed while Fuigo was running",
            Disabled::NetworkLogon => "peer messaging is unavailable in a remote (network) logon session",
            Disabled::Io(_) => "peer messaging is unavailable: a file system error occurred",
        }
    }
}
