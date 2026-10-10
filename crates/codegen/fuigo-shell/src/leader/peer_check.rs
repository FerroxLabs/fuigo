//! Who is on the other end of the local leader socket (unix).
//!
//! The leader socket is private to one user account: it is bound mode 0600 with no wider moment ([`bind_private`]),
//! and BOTH sides compare the peer's uid with their own effective uid before they exchange a byte
//! ([`server_accepts`], [`client_accepts`]). Anything but a positive match is refused, including a failed query
//! (fail closed). On Windows these functions accept everything: the named pipe has its own packet.
//!
//! The OS call (`SO_PEERCRED` on Linux, `getpeereid` on macOS/BSD, both behind tokio's `peer_cred`) is one tiny
//! function; its result feeds the pure [`peer_is_same_user`], which is what the unit tests pin.
#![cfg_attr(not(unix), allow(unused))]

use super::transport::{LeaderListener, LeaderStream};
use std::path::Path;

/// The decision for one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PeerVerdict {
    Accept,
    Refuse,
}

/// Same account, and only then. `Err` (could not learn the peer) refuses.
pub(super) fn peer_is_same_user<E>(our_uid: u32, peer: Result<u32, E>) -> PeerVerdict {
    match peer {
        Ok(uid) if uid == our_uid => PeerVerdict::Accept,
        _ => PeerVerdict::Refuse,
    }
}

#[cfg(unix)]
fn os_peer_uid(stream: &LeaderStream) -> std::io::Result<u32> {
    stream.peer_cred().map(|cred| cred.uid())
}

#[cfg(unix)]
fn our_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Which side of the connection is asking (test seam keys).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Side {
    Client,
    Server,
}

#[cfg(unix)]
fn verdict_for(side: Side, stream: &LeaderStream, socket_path: &Path) -> PeerVerdict {
    let ours = our_uid();
    #[cfg(test)]
    let peer = seam::query(side, socket_path, ours).unwrap_or_else(|| os_peer_uid(stream));
    #[cfg(not(test))]
    let peer = os_peer_uid(stream);
    let verdict = peer_is_same_user(ours, peer.as_ref().map(|uid| *uid));
    if verdict == PeerVerdict::Refuse {
        match &peer {
            Ok(uid) => tracing::debug!(?side, peer_uid = *uid, "Refusing a peer of another user account"),
            Err(e) => tracing::debug!(?side, error = %e, "Refusing a peer whose account could not be determined"),
        }
    }
    verdict
}

/// Server side: may this accepted connection be read from? Call before reading anything.
pub(super) fn server_accepts(stream: &LeaderStream, socket_path: &Path) -> bool {
    #[cfg(unix)]
    {
        verdict_for(Side::Server, stream, socket_path) == PeerVerdict::Accept
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Client side: may we send anything to the process we just connected to? Call before the first write.
pub(super) fn client_accepts(stream: &LeaderStream, socket_path: &Path) -> bool {
    #[cfg(unix)]
    {
        verdict_for(Side::Client, stream, socket_path) == PeerVerdict::Accept
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Bind the leader listener at `path`, mode 0600 from the first moment it is visible at `path`.
///
/// The socket is bound inside a fresh directory created 0700 next to `path`, chmod-ed 0600 there, and only then
/// renamed into place (the rename replaces a stale socket atomically and keeps the socket connectable on Linux and
/// macOS). Nobody but the owner can reach it before the rename, so there is no wider-mode window, and unlike
/// `umask` (process-wide) no other thread's file creation is affected.
#[cfg(unix)]
pub(super) fn bind_private(path: &Path) -> std::io::Result<LeaderListener> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let pid = std::process::id();
    let mut dir = None;
    for attempt in 0u32..16 {
        // Short on purpose: `<parent>/.lXXXX/s` is never longer than `leader.sock` in the same directory
        // (the `sun_path` limit is ~104 bytes).
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let tag = (pid ^ nanos ^ attempt.wrapping_mul(0x9e37)) & 0xffff;
        let candidate = parent.join(format!(".l{tag:04x}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => {
                dir = Some(candidate);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let dir = dir.ok_or_else(|| std::io::Error::other("could not create a private bind directory"))?;
    let result = (|| {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let temp_sock = dir.join("s");
        let listener = LeaderListener::bind(&temp_sock)?;
        std::fs::set_permissions(&temp_sock, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&temp_sock, path)?;
        Ok(listener)
    })();
    let _ = std::fs::remove_file(dir.join("s"));
    let _ = std::fs::remove_dir(&dir);
    result
}

#[cfg(not(unix))]
pub(super) fn bind_private(path: &Path) -> std::io::Result<LeaderListener> {
    LeaderListener::bind(path)
}

/// Test-only injection of the credential query result, keyed by side and socket path so parallel tests never see
/// each other's setting.
#[cfg(test)]
pub(super) mod seam {
    use super::Side;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    #[derive(Clone, Copy)]
    pub(in crate::leader) enum Inject {
        /// Report a peer whose uid is ours plus one.
        ForeignUid,
        /// The credential query itself fails.
        QueryError,
    }

    static SEAMS: Mutex<Vec<(Side, PathBuf, Inject)>> = Mutex::new(Vec::new());

    pub(in crate::leader) fn set(side: Side, path: &Path, inject: Inject) {
        SEAMS.lock().unwrap().push((side, path.to_path_buf(), inject));
    }

    pub(super) fn query(side: Side, path: &Path, ours: u32) -> Option<std::io::Result<u32>> {
        let seams = SEAMS.lock().unwrap();
        let (_, _, inject) = seams.iter().find(|(s, p, _)| *s == side && p == path)?;
        Some(match inject {
            Inject::ForeignUid => Ok(ours.wrapping_add(1)),
            Inject::QueryError => Err(std::io::Error::other("injected credential failure")),
        })
    }
}

// unix only: the tests bind unix sockets (the Windows build has only the accepting stubs to test)
#[cfg(all(test, unix))]
#[path = "peer_check_tests.rs"]
mod tests;
