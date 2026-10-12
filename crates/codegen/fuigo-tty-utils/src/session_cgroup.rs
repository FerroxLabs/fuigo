//! Per-session cgroup v2 for "session park" `stop` (P189 packet B).
//!
//! Standalone: nothing in the product calls this yet. Linux has the real
//! implementation; every other OS gets stubs whose [`probe`] answers
//! [`Unavailable::NotLinux`] (macOS/Windows paths are compile-checked only by
//! the cross builds, not run).
//!
//! # Layout
//!
//! `<own>/fuigo-park-<uuid>/<session-uuid>/`, where `<own>` is this process's
//! own cgroup (the `0::<path>` line of `/proc/self/cgroup`). Fuigo does not
//! move itself, enables no controllers and writes nothing to
//! `cgroup.subtree_control`. The process directory `fuigo-park-<uuid>` is
//! protected by an `flock` on a lock file held for the life of the process.
//! The lock file lives in the *runtime dir*: `$XDG_RUNTIME_DIR/fuigo/` when
//! that is set and is a directory, else `/tmp/fuigo-run-<euid>/` (mode 0700).
//! It is deliberately NOT under `$HOME`/`$FUIGO_HOME`: two processes with
//! different homes share one cgroup, and the sweep must see each other's locks.
//!
//! # Rules this module keeps
//!
//! * No pid, process group, session id or marker is ever used to pick a victim.
//!   Membership comes only from the child's own `write(cgroup.procs, "0")`
//!   before exec and from fork inheritance. The only pid comparison is the
//!   guard that refuses to kill when *we* are listed in the cgroup.
//! * Every failure is a typed reason; any error or panic in the probe means
//!   unavailable. Release builds are `panic = "abort"`, so "panic means
//!   unavailable" holds ONLY in test and debug builds; in release a panic
//!   would abort, and the probe is written to have no panic path.
//! * The cached [`probe`] answer is cached only as the answer of the process
//!   that computed it (a fork gets [`Unavailable::InheritedProbe`]). A failure
//!   is cached too: that is fail-closed, never a path from "no" to "yes".
//! * Launch children with `ProcessScope::spawn_placed{,_std}` only (the only
//!   public way to place; `SessionCgroup::spawn` is crate-private). It
//!   registers the placement first, holds the lease through `spawn()` and
//!   latches `breached` under it for every command that starts unplaced.
//! * Teardown and the stale sweep never kill and never remove a populated
//!   directory (the kernel's `rmdir` refuses with `EBUSY`).

use std::fmt;
use std::time::Duration;

/// Errno a placement `pre_exec` closure returns when its `write` failed.
/// Seen by the parent as the `spawn()` error; see
/// [`SessionCgroup::record_spawn_error`]. `ENOTRECOVERABLE` (the value differs
/// per architecture, so it is not hard-coded on unix).
#[cfg(unix)]
pub const PLACE_SENTINEL_ERRNO: i32 = libc::ENOTRECOVERABLE;
/// Never produced off unix; kept so the constant exists everywhere.
#[cfg(not(unix))]
pub const PLACE_SENTINEL_ERRNO: i32 = 131;

/// Why `stop` cannot be offered. Every probe branch has its own variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    NotLinux,
    /// `/sys/fs/cgroup` is not a cgroup2 mount (v1 or hybrid, or absent).
    NotCgroup2(String),
    OwnCgroupUnreadable,
    OwnCgroupMissing(String),
    /// The `0::` path has a `..`, or our pid is not in its `cgroup.procs`
    /// (e.g. a cgroup namespace over a host mount).
    OwnCgroupInvalid(String),
    /// The cached probe belongs to another process (we are a fork).
    InheritedProbe,
    /// `cgroup.type` was something other than `domain` (e.g. `threaded`).
    OwnCgroupNotDomain(String),
    /// No place for the lock file.
    LockDir(String),
    /// `mkdir` of the process or probe directory failed (`errno` as returned).
    MkdirRefused { path: String, errno: i32 },
    /// No `cgroup.kill` (kernel before 5.14).
    NoCgroupKill,
    ProcsNotWritable(String),
    /// The live spawn/kill/`populated` round trip failed.
    RoundTrip(String),
    Panicked,
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLinux => write!(f, "not_linux"),
            Self::NotCgroup2(p) => write!(f, "not_cgroup2 ({p})"),
            Self::OwnCgroupUnreadable => write!(f, "own_cgroup_unreadable"),
            Self::OwnCgroupMissing(p) => write!(f, "own_cgroup_missing ({p})"),
            Self::OwnCgroupInvalid(e) => write!(f, "own_cgroup_invalid ({e})"),
            Self::InheritedProbe => write!(f, "inherited_probe"),
            Self::OwnCgroupNotDomain(t) => write!(f, "own_cgroup_not_domain (type {t})"),
            Self::LockDir(e) => write!(f, "lock_dir ({e})"),
            Self::MkdirRefused { path, errno } => {
                let name = match *errno {
                    13 => "EACCES",
                    30 => "EROFS",
                    1 => "EPERM",
                    _ => "errno",
                };
                write!(f, "mkdir_refused {name} {errno} ({path})")
            }
            Self::NoCgroupKill => write!(f, "no_cgroup_kill"),
            Self::ProcsNotWritable(e) => write!(f, "procs_not_writable ({e})"),
            Self::RoundTrip(e) => write!(f, "round_trip_failed ({e})"),
            Self::Panicked => write!(f, "probe_panicked"),
        }
    }
}

/// Why [`SessionCgroup::place`] refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaceError {
    /// [`SessionCgroup::close`] ran (the stop gate is shut).
    Closed,
    /// A stop is in progress or done and not reopened: the spawn is refused.
    Stopping,
    Unavailable,
}

/// Name of the opt-in environment variable (owner decision 39).
pub const PARK_STOP_ENV: &str = "FUIGO_SESSION_PARK_STOP";

/// The one placement decision: `value` is the variable's value and must be
/// exactly `on`; only then is `probe_usable` called (once). Any other value, or
/// none, answers `false` without probing: no cgroup, no directory, no lock file.
pub fn decide_placement(value: Option<&str>, probe_usable: impl FnOnce() -> bool) -> bool {
    value == Some("on") && probe_usable()
}

/// Process-wide "placement enabled", read once: [`PARK_STOP_ENV`] is `on` AND
/// [`probe`] is usable. Evaluated lazily at the first session's scope
/// creation, which is after the process's start-up (any bwrap re-exec and
/// sandbox apply happen in `main` before a session exists). Packet D will use
/// this for the advertised modes.
pub fn placement_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        let value = std::env::var(PARK_STOP_ENV).ok();
        decide_placement(value.as_deref(), || match probe() {
            Ok(_) => true,
            Err(why) => {
                tracing::info!(reason = %why, "session park stop unavailable; commands run unplaced");
                false
            }
        })
    })
}

/// Why `SessionCgroup::spawn` failed.
#[derive(Debug)]
pub enum SpawnError {
    /// The stop gate is shut (or a stop is in progress): nothing was started.
    Closed,
    /// A stop is in progress ([`SessionCgroup::begin_stop`]): nothing was started.
    Stopping,
    /// The placement write failed; `breached` is latched. Nothing was started.
    Placement(std::io::Error),
    /// Any other `spawn()` failure (e.g. exec). Nothing was started.
    Spawn(std::io::Error),
}

/// Why [`SessionCgroup::kill_and_wait`] did not kill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefuseReason {
    /// A placement write failed earlier: some child may have escaped.
    Breached,
    /// Our own pid, or our own cgroup, is in the session's subtree.
    SelfInCgroup,
    /// Spawn leases were still outstanding at the deadline (the gate could not be taken).
    GateOpen,
    /// Failed before `cgroup.kill` was written: nothing was killed.
    Io(String),
    Unavailable,
}

/// Result of [`SessionCgroup::kill_and_wait`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillOutcome {
    /// `populated 0` was read.
    Emptied { waited: Duration },
    /// `cgroup.kill` was written but the cgroup was still populated at the deadline.
    NotEmptied { waited: Duration },
    /// `cgroup.kill` was written but `cgroup.events` could not be read: the
    /// outcome is unknown (do not report "nothing was killed").
    KilledUnverified(String),
    /// Nothing was killed.
    Refused(RefuseReason),
}

/// Result of [`SessionCgroup::teardown`] and the sweep's per-directory verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeardownOutcome {
    Removed,
    /// Still populated (or has a populated child): left in place, not killed.
    LeftPopulated,
    Failed(String),
}

/// What [`ParkHost::sweep_stale`] did. Names only; no pids.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub removed: Vec<String>,
    /// `(directory name, reason)` for directories left in place.
    pub kept: Vec<(String, String)>,
}

#[cfg(target_os = "linux")]
mod imp;
#[cfg(target_os = "linux")]
pub use imp::{ParkHost, PlaceLease, ProbeEnv, SessionCgroup, probe, probe_with};

#[cfg(not(target_os = "linux"))]
mod stub {
    use super::{KillOutcome, RefuseReason, SpawnError, SweepReport, TeardownOutcome, Unavailable};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    /// Same fields as the Linux probe environment (the test-only ones aside).
    #[derive(Clone)]
    pub struct ProbeEnv {
        pub cgroup_root: PathBuf,
        pub own_cgroup: Option<String>,
        pub lock_dir: PathBuf,
        pub require_cgroup2: bool,
    }
    impl ProbeEnv {
        pub fn system() -> Self {
            Self { cgroup_root: PathBuf::new(), own_cgroup: None, lock_dir: PathBuf::new(), require_cgroup2: true }
        }
    }

    /// Never constructed off Linux.
    pub struct ParkHost(());
    /// Never constructed off Linux.
    pub struct SessionCgroup(());
    /// Never constructed off Linux.
    pub struct PlaceLease<'a>(std::marker::PhantomData<&'a ()>);
    impl PlaceLease<'_> {
        pub(crate) fn placed(&self) -> bool {
            false
        }
    }

    static NOT_LINUX: Unavailable = Unavailable::NotLinux;

    pub fn probe() -> Result<&'static ParkHost, &'static Unavailable> {
        Err(&NOT_LINUX)
    }
    pub fn probe_with(_env: &ProbeEnv) -> Result<ParkHost, Unavailable> {
        Err(Unavailable::NotLinux)
    }
    impl ParkHost {
        pub fn process_dir(&self) -> &Path {
            Path::new("")
        }
        pub fn create_session(&self) -> Result<SessionCgroup, Unavailable> {
            Err(Unavailable::NotLinux)
        }
        pub fn sweep_stale(&self) -> SweepReport {
            SweepReport::default()
        }
    }
    impl SessionCgroup {
        pub fn dir(&self) -> &Path {
            Path::new("")
        }
        #[allow(dead_code)]
        pub(crate) fn spawn(&self, _cmd: &mut std::process::Command) -> Result<std::process::Child, SpawnError> {
            Err(SpawnError::Closed)
        }
        pub(crate) fn place(&self, _cmd: &mut std::process::Command) -> Result<PlaceLease<'_>, super::PlaceError> {
            Err(super::PlaceError::Unavailable)
        }
        pub(crate) fn place_or_latch(&self, _cmd: &mut std::process::Command) -> Result<PlaceLease<'_>, super::PlaceError> {
            Err(super::PlaceError::Unavailable)
        }
        pub(crate) fn latch_breached(&self) {}
        pub(crate) fn fallback_point(&self) {}
        pub fn begin_stop(&self) {}
        pub fn record_spawn_error(&self, _err: &std::io::Error) -> bool {
            false
        }
        pub fn close(&self) {}
        pub fn reopen(&self) {}
        pub fn is_breached(&self) -> bool {
            false
        }
        pub fn kill_and_wait(&self, _deadline: Duration) -> KillOutcome {
            KillOutcome::Refused(RefuseReason::Unavailable)
        }
        pub fn teardown(&self) -> TeardownOutcome {
            TeardownOutcome::Failed("not linux".into())
        }
    }
}
#[cfg(not(target_os = "linux"))]
pub use stub::{ParkHost, PlaceLease, ProbeEnv, SessionCgroup, probe, probe_with};

#[cfg(all(test, target_os = "linux"))]
mod tests;
