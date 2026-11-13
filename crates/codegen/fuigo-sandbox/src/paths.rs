//! Filesystem path tables for sandbox profiles.

use std::path::{Path, PathBuf};

// ── Fuigo state directory ────────────────────────────────────────────────────

/// Fuigo state directory (`$FUIGO_HOME` or `~/.fuigo`).
pub(crate) fn fuigo_home() -> PathBuf {
    fuigo_config::fuigo_home()
}

/// The sessions root used by sandbox grants, diagnostics, and the root audit log.
/// This names the root; writes within individual session folders use SessionWriter.
pub(crate) fn sessions_root() -> PathBuf {
    fuigo_home().join("sessions")
}

/// On-disk JSONL audit log under the sessions directory.
///
/// Strict writes it via the sessions directory grant (not a file grant on the fuigo home parent, which would follow a planted symlink).
pub(crate) fn sandbox_events_log_path() -> PathBuf {
    sessions_root().join("sandbox-events.jsonl")
}

// ── Device files & directories ──────────────────────────────────────────────

/// Device files that need write access for normal tool operation.
///
/// These are individual files (use `allow_file`, not `allow_path`).
/// Directory nodes under `/dev` belong in [`DEVICE_DIRS`].
#[cfg(all(feature = "enforce", unix))]
pub(crate) const DEVICE_FILES: &[&str] = &[
    "/dev/null",    // output sink — used by virtually every CLI tool
    "/dev/zero",    // zero source — used by memory allocators
    "/dev/random",  // entropy — used by crypto/TLS
    "/dev/urandom", // entropy — used by crypto/TLS
    "/dev/tty",     // controlling terminal — used by git, ssh, gpg
    "/dev/ptmx",    // PTY allocation — used by terminal spawning
];

/// Device directories that need write access (use `allow_path`, not `allow_file`).
#[cfg(all(feature = "enforce", unix))]
pub(crate) const DEVICE_DIRS: &[&str] = &[
    "/dev/pts", // PTY slaves (Linux)
    "/dev/fd",  // fd table (symlink to /proc/self/fd on Linux; a directory)
];

// ── Temporary directories ───────────────────────────────────────────────────

/// Temporary directories that need write access.
///
/// On macOS, programs use both `/tmp` (symlink to `/private/tmp`) and `/private/var/folders/` (the real `TMPDIR` / `NSTemporaryDirectory()`).
pub(crate) fn temp_writable_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];

    // macOS: /tmp is a symlink to /private/tmp, but the real TMPDIR is under /private/var/folders
    // Also include /private/tmp since Seatbelt may resolve the symlink.
    if cfg!(target_os = "macos") {
        for p in ["/private/tmp", "/private/var/tmp", "/private/var/folders"] {
            let pb = PathBuf::from(p);
            if pb.exists() && pb.is_dir() {
                paths.push(pb);
            }
        }
    }

    // Respect $TMPDIR if it points somewhere else (e.g. custom Linux setups).
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        let pb = PathBuf::from(&tmpdir);
        if pb.exists() && pb.is_dir() && !paths.contains(&pb) {
            paths.push(pb);
        }
    }

    paths
}

// ── Essential writable paths ────────────────────────────────────────────────

/// Writable directory paths for the workspace profile (full `fuigo_home()` and temp).
/// Device files are handled separately via `allow_file` in `to_capability_set_with_config`.
pub(crate) fn essential_writable_paths(workspace: &Path) -> Vec<PathBuf> {
    let mut paths = vec![workspace.to_path_buf(), fuigo_home()];
    paths.extend(temp_writable_paths());
    paths
}

/// Writable directory paths for the strict profile (workspace, sessions, and temp).
///
/// Strict may read `fuigo_home()` but must not write the parent.
/// Events JSONL lives under `sessions/`.
///
/// With session persistence off (F12, `--no-session-persistence`) the session tree is not granted: applying a grant
/// creates a missing directory, and a run that persists nothing must not make `<fuigo_home>/sessions` (review r2).
pub(crate) fn essential_writable_paths_strict(workspace: &Path) -> Vec<PathBuf> {
    strict_writable_paths(workspace, fuigo_config::session_persistence_disabled())
}

fn strict_writable_paths(workspace: &Path, persistence_off: bool) -> Vec<PathBuf> {
    let mut paths = vec![workspace.to_path_buf()];
    if !persistence_off {
        paths.push(sessions_root());
    }
    paths.extend(temp_writable_paths());
    paths
}

/// Writable directory paths for the read-only profile (minimal: just ~/.fuigo + temp).
/// Device files are handled separately via `allow_file` in `to_capability_set_with_config`.
pub(crate) fn essential_writable_paths_minimal() -> Vec<PathBuf> {
    let mut paths = vec![fuigo_home()];
    paths.extend(temp_writable_paths());
    paths
}

#[cfg(test)]
mod r2_tests {
    use super::*;

    /// Review r2 (F12): the strict profile's read_write grants name the session tree only while persistence is on.
    #[test]
    fn r2f12_strict_profile_grants_the_session_tree_only_with_persistence_on() {
        let workspace = Path::new("/work/space");
        let sessions = fuigo_home().join("sessions");
        assert!(strict_writable_paths(workspace, false).contains(&sessions));
        let off = strict_writable_paths(workspace, true);
        assert!(!off.iter().any(|p| p.starts_with(&sessions)), "{off:?}");
        assert!(
            off.contains(&workspace.to_path_buf()),
            "the workspace stays writable: {off:?}"
        );
    }
}
