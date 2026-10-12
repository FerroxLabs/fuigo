//! Linux implementation of [`super`]. See the parent module docs for the rules.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, PoisonError, RwLock, RwLockReadGuard, TryLockError};
use std::time::{Duration, Instant};
#[cfg(test)]
use std::sync::Mutex;

use super::{
    KillOutcome, PLACE_SENTINEL_ERRNO, PlaceError, RefuseReason, SpawnError, SweepReport,
    TeardownOutcome, Unavailable,
};

const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
const PARK_PREFIX: &str = "fuigo-park-";
const ROUND_TRIP_STEP: Duration = Duration::from_secs(2);
const KILL_CAP: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(10);

/// Where the probe looks. [`ProbeEnv::system`] is production; tests point
/// `cgroup_root`/`own_cgroup`/`lock_dir` at a fake tree.
#[derive(Clone)]
pub struct ProbeEnv {
    /// Normally `/sys/fs/cgroup`.
    pub cgroup_root: PathBuf,
    /// The `0::` path of `/proc/self/cgroup` (leading `/`), `None` if unreadable.
    pub own_cgroup: Option<String>,
    pub lock_dir: PathBuf,
    /// Check that `cgroup_root` is a cgroup2 mount (always true in production).
    pub require_cgroup2: bool,
    #[cfg(test)]
    pub(super) populate: Option<fn(&Path)>,
    #[cfg(test)]
    pub(super) mkdir_errno: Option<i32>,
    #[cfg(test)]
    pub(super) panic_in_probe: bool,
    /// Fake trees: succeed after the file checks, skipping the live round trip.
    #[cfg(test)]
    pub(super) skip_round_trip: bool,
}

impl ProbeEnv {
    pub fn system() -> Self {
        let own = fs::read_to_string("/proc/self/cgroup").ok().and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("0::").map(|p| p.trim().to_string()))
        });
        Self {
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            own_cgroup: own,
            lock_dir: system_lock_dir(),
            require_cgroup2: true,
            #[cfg(test)]
            populate: None,
            #[cfg(test)]
            mkdir_errno: None,
            #[cfg(test)]
            panic_in_probe: false,
            #[cfg(test)]
            skip_round_trip: false,
        }
    }

    fn own_dir(&self, rel: &str) -> PathBuf {
        self.cgroup_root.join(rel.trim_start_matches('/'))
    }

    fn make_dir(&self, path: &Path) -> io::Result<()> {
        #[cfg(test)]
        if let Some(e) = self.mkdir_errno {
            return Err(io::Error::from_raw_os_error(e));
        }
        fs::DirBuilder::new().mode(0o755).create(path)?;
        #[cfg(test)]
        if let Some(p) = self.populate {
            p(path);
        }
        Ok(())
    }

    /// `rmdir` bottom-up; the kernel refuses (`EBUSY`) on a populated cgroup.
    fn remove_tree(&self, dir: &Path) -> TeardownOutcome {
        let outcome = remove_tree_if_empty(dir);
        #[cfg(test)]
        if self.populate.is_some() && outcome != TeardownOutcome::Removed {
            // Fake trees hold plain files in place of the kernel's control
            // files; nested `fuigo-park-*` directories are still left alone.
            return fake_remove(dir);
        }
        outcome
    }
}

fn system_lock_dir() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
        let p = PathBuf::from(x);
        if p.is_absolute() && p.is_dir() {
            return p.join("fuigo");
        }
    }
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    PathBuf::from(format!("/tmp/fuigo-run-{uid}"))
}

fn new_uuid() -> io::Result<String> {
    let s = fs::read_to_string("/proc/sys/kernel/random/uuid")?;
    let s = s.trim().to_string();
    if is_uuid(&s) { Ok(s) } else { Err(io::Error::other("malformed kernel uuid")) }
}

pub(super) fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit() && !b.is_ascii_uppercase(),
        })
}

fn is_park_dir_name(name: &str) -> bool {
    name.strip_prefix(PARK_PREFIX).is_some_and(is_uuid)
}

fn errno_of(e: &io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

/// `open(path, O_PATH|O_DIRECTORY)`: the directory handle kill and events go through.
fn open_dirfd(path: &Path) -> io::Result<File> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::other("nul in path"))?;
    // SAFETY: `c` is NUL-terminated; the fd is wrapped immediately.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh fd we own.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn openat(dirfd: &File, name: &str, flags: i32) -> io::Result<File> {
    let c = std::ffi::CString::new(name).map_err(|_| io::Error::other("nul in name"))?;
    // SAFETY: valid dirfd, NUL-terminated name; the fd is wrapped immediately.
    let fd = unsafe { libc::openat(dirfd.as_raw_fd(), c.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh fd we own.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn write_kill(dirfd: &File) -> io::Result<()> {
    use std::io::Write;
    let mut f = openat(dirfd, "cgroup.kill", libc::O_WRONLY)?;
    f.write_all(b"1")
}

fn events_populated(dirfd: &File) -> io::Result<bool> {
    use std::io::Read;
    let mut ev = String::new();
    openat(dirfd, "cgroup.events", libc::O_RDONLY)?.read_to_string(&mut ev)?;
    for l in ev.lines() {
        if let Some(v) = l.strip_prefix("populated ") {
            return Ok(v.trim() == "1");
        }
    }
    Err(io::Error::other("no populated line in cgroup.events"))
}

/// Poll `populated` until it equals `want` or `within` passes.
fn wait_populated(dirfd: &File, want: bool, within: Duration, mut tick: impl FnMut()) -> io::Result<bool> {
    let start = Instant::now();
    loop {
        tick();
        if events_populated(dirfd)? == want {
            return Ok(true);
        }
        if start.elapsed() >= within {
            return Ok(false);
        }
        std::thread::sleep(POLL);
    }
}

/// `rmdir` bottom-up. `dir` is the root of the removal (exempt from the
/// name rule). A `fuigo-park-*` directory anywhere below the root belongs to a
/// nested Fuigo (started by a tool inside the session): it is never entered or
/// removed, and the root is reported [`TeardownOutcome::LeftPopulated`].
fn remove_tree_if_empty(dir: &Path) -> TeardownOutcome {
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return TeardownOutcome::Removed,
        Err(e) => return TeardownOutcome::Failed(e.to_string()),
    };
    for ent in rd.flatten() {
        if ent.file_type().is_ok_and(|t| t.is_dir()) {
            if is_park_dir_name(&ent.file_name().to_string_lossy()) {
                return TeardownOutcome::LeftPopulated;
            }
            match remove_tree_if_empty(&ent.path()) {
                TeardownOutcome::Removed => {}
                other => return other,
            }
        }
    }
    match fs::remove_dir(dir) {
        Ok(()) => TeardownOutcome::Removed,
        Err(e) if e.kind() == io::ErrorKind::NotFound => TeardownOutcome::Removed,
        // EBUSY: populated. ENOTEMPTY: a populated child or stray entries.
        Err(e) if matches!(errno_of(&e), libc::EBUSY | libc::ENOTEMPTY) => TeardownOutcome::LeftPopulated,
        Err(e) => TeardownOutcome::Failed(e.to_string()),
    }
}

/// Fake-tree removal (plain files stand in for control files); same nested rule.
#[cfg(test)]
fn fake_remove(dir: &Path) -> TeardownOutcome {
    let mut left = false;
    if let Ok(rd) = fs::read_dir(dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if ent.file_type().is_ok_and(|t| t.is_dir()) {
                if is_park_dir_name(&ent.file_name().to_string_lossy())
                    || fake_remove(&p) != TeardownOutcome::Removed
                {
                    left = true;
                }
            } else {
                let _ = fs::remove_file(&p);
            }
        }
    }
    if left {
        return TeardownOutcome::LeftPopulated;
    }
    match fs::remove_dir(dir) {
        Ok(()) => TeardownOutcome::Removed,
        Err(e) if e.kind() == io::ErrorKind::NotFound => TeardownOutcome::Removed,
        Err(e) => TeardownOutcome::Failed(e.to_string()),
    }
}

/// Remove, retrying while the kernel still reports the cgroup populated (a
/// just-killed child takes a moment to leave).
fn remove_tree_retry(env: &ProbeEnv, dir: &Path, within: Duration) -> TeardownOutcome {
    let start = Instant::now();
    loop {
        let r = env.remove_tree(dir);
        if r != TeardownOutcome::LeftPopulated || start.elapsed() >= within {
            return r;
        }
        std::thread::sleep(POLL);
    }
}

/// Every pid in the subtree. An unreadable `cgroup.procs` is an error: the
/// own-pid guard must fail closed.
fn list_pids(dir: &Path, out: &mut Vec<u32>) -> io::Result<()> {
    let s = fs::read_to_string(dir.join("cgroup.procs"))?;
    out.extend(s.lines().filter_map(|l| l.trim().parse::<u32>().ok()));
    for ent in fs::read_dir(dir)?.flatten() {
        if ent.file_type().is_ok_and(|t| t.is_dir()) {
            list_pids(&ent.path(), out)?;
        }
    }
    Ok(())
}

fn try_flock(f: &File) -> io::Result<bool> {
    // SAFETY: valid fd owned by `f`.
    let r = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if r == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) { Ok(false) } else { Err(e) }
}

/// Never follows a symlink at the final component.
pub(super) fn open_lock(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// The lock directory must be a real directory we own with no group/other bits.
pub(super) fn check_lock_dir(p: &Path, euid: u32) -> Result<(), Unavailable> {
    let m = fs::symlink_metadata(p).map_err(|e| Unavailable::LockDir(format!("lstat: {e}")))?;
    if !m.file_type().is_dir() {
        return Err(Unavailable::LockDir("lock dir is not a real directory".into()));
    }
    if m.uid() != euid {
        return Err(Unavailable::LockDir(format!("lock dir owned by uid {}", m.uid())));
    }
    if m.mode() & 0o077 != 0 {
        return Err(Unavailable::LockDir(format!("lock dir mode {:o} has group/other bits", m.mode() & 0o7777)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Host (the per-process directory) and probe
// ---------------------------------------------------------------------------

/// The per-process cgroup `<own>/fuigo-park-<uuid>/` plus the lock that
/// protects it from the stale sweep. Dropping it removes the directory if
/// empty (never kills).
pub struct ParkHost {
    env: ProbeEnv,
    own_rel: String,
    own_dir: PathBuf,
    process_dir: PathBuf,
    lock_path: PathBuf,
    _lock: File,
}

/// `(pid that probed, result)`. Only a definite answer for THIS process is
/// served from the cache. A failure is cached too: that is fail-closed (stop
/// stays unavailable until restart), never a way to turn "no" into "yes".
static PROBE: OnceLock<(u32, Result<ParkHost, Unavailable>)> = OnceLock::new();
static INHERITED: Unavailable = Unavailable::InheritedProbe;

/// The cached production probe. Any error or panic is [`Unavailable`].
pub fn probe() -> Result<&'static ParkHost, &'static Unavailable> {
    probe_for_pid(std::process::id())
}

/// [`probe`] as seen from process `pid`: a cache filled by another process
/// (this one is a fork that inherited the static) is not an answer for us.
pub(super) fn probe_for_pid(pid: u32) -> Result<&'static ParkHost, &'static Unavailable> {
    let (owner, res) = PROBE.get_or_init(|| (std::process::id(), probe_with(&ProbeEnv::system())));
    if *owner != pid {
        return Err(&INHERITED);
    }
    res.as_ref()
}

/// Uncached probe against `env`. Runs the stale sweep, then every step of the
/// plan's "Detection at start"; leaves a usable process directory on success
/// and nothing behind on failure.
pub fn probe_with(env: &ProbeEnv) -> Result<ParkHost, Unavailable> {
    let env = env.clone();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| probe_inner(&env)))
        .unwrap_or(Err(Unavailable::Panicked))
}

fn probe_inner(env: &ProbeEnv) -> Result<ParkHost, Unavailable> {
    #[cfg(test)]
    if env.panic_in_probe {
        std::panic::panic_any("injected probe panic");
    }
    // 2. cgroup2 unified mount.
    if env.require_cgroup2 {
        let c = std::ffi::CString::new(env.cgroup_root.as_os_str().as_encoded_bytes())
            .map_err(|_| Unavailable::NotCgroup2("nul in path".into()))?;
        // SAFETY: zeroed statfs is a valid out-parameter; `c` is NUL-terminated.
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::statfs(c.as_ptr(), &mut st) };
        if r != 0 {
            return Err(Unavailable::NotCgroup2(format!("statfs: {}", io::Error::last_os_error())));
        }
        #[allow(clippy::unnecessary_cast)] // f_type is i32 on some targets, i64 here
        let f_type = st.f_type as i64;
        if f_type != CGROUP2_SUPER_MAGIC {
            return Err(Unavailable::NotCgroup2(format!("f_type {f_type:#x}")));
        }
    }
    // 3. Own cgroup visible, sane, ours, and a domain cgroup (or the root).
    let own_rel = env.own_cgroup.clone().ok_or(Unavailable::OwnCgroupUnreadable)?;
    if Path::new(&own_rel).components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(Unavailable::OwnCgroupInvalid(format!("`..` in {own_rel}")));
    }
    let own_dir = env.own_dir(&own_rel);
    if !own_dir.is_dir() {
        return Err(Unavailable::OwnCgroupMissing(own_rel));
    }
    match fs::read_to_string(own_dir.join("cgroup.procs")) {
        Ok(p) if p.lines().any(|l| l.trim().parse::<u32>().ok() == Some(std::process::id())) => {}
        Ok(_) => return Err(Unavailable::OwnCgroupInvalid("our pid is not in its cgroup.procs".into())),
        Err(e) => return Err(Unavailable::OwnCgroupInvalid(format!("cgroup.procs: {e}"))),
    }
    match fs::read_to_string(own_dir.join("cgroup.type")) {
        Ok(t) if t.trim() != "domain" => return Err(Unavailable::OwnCgroupNotDomain(t.trim().to_string())),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(Unavailable::OwnCgroupMissing(format!("cgroup.type: {e}"))),
    }
    // Lock first (so a concurrent sweep never sees our directory unprotected),
    // then sweep stale directories of dead processes, then create ours.
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&env.lock_dir)
        .map_err(|e| Unavailable::LockDir(e.to_string()))?;
    // SAFETY: geteuid has no preconditions.
    check_lock_dir(&env.lock_dir, unsafe { libc::geteuid() })?;
    let name = format!("{PARK_PREFIX}{}", new_uuid().map_err(|e| Unavailable::LockDir(e.to_string()))?);
    let lock_path = env.lock_dir.join(format!("{name}.lock"));
    let lock = open_lock(&lock_path).map_err(|e| Unavailable::LockDir(e.to_string()))?;
    match try_flock(&lock) {
        Ok(true) => {}
        Ok(false) => return Err(Unavailable::LockDir("fresh lock file is held".into())),
        Err(e) => return Err(Unavailable::LockDir(e.to_string())),
    }
    let process_dir = own_dir.join(&name);
    let host = ParkHost {
        env: env.clone(),
        own_rel,
        own_dir,
        process_dir: process_dir.clone(),
        lock_path,
        _lock: lock,
    };
    host.sweep_stale();
    // 4. mkdir of the process directory. From here `host`'s Drop cleans up on failure.
    env.make_dir(&process_dir).map_err(|e| mkdir_err(&process_dir, &e))?;
    let probe_dir = process_dir.join("probe");
    env.make_dir(&probe_dir).map_err(|e| mkdir_err(&probe_dir, &e))?;
    let result = probe_checks(env, &probe_dir);
    remove_tree_retry(env, &probe_dir, Duration::from_secs(1));
    result?;
    Ok(host)
}

fn mkdir_err(path: &Path, e: &io::Error) -> Unavailable {
    Unavailable::MkdirRefused { path: path.display().to_string(), errno: errno_of(e) }
}

fn probe_checks(env: &ProbeEnv, probe_dir: &Path) -> Result<(), Unavailable> {
    // 5. cgroup.kill exists, cgroup.procs opens for write.
    if !probe_dir.join("cgroup.kill").exists() {
        return Err(Unavailable::NoCgroupKill);
    }
    let procs = open_procs(probe_dir).map_err(|e| Unavailable::ProcsNotWritable(e.to_string()))?;
    let cg = SessionCgroup::from_parts(env.clone(), probe_dir.to_path_buf(), String::new(), procs)
        .map_err(|e| Unavailable::ProcsNotWritable(format!("dirfd: {e}")))?;
    #[cfg(test)]
    if env.skip_round_trip {
        return Ok(());
    }
    // 6. Live round trip through the real placement path.
    let rt = |m: &str| Unavailable::RoundTrip(m.to_string());
    let mut cmd = std::process::Command::new("/bin/sh");
    // `exec`: the child IS sleep, so killing it can never orphan a second process.
    cmd.args(["-c", "exec sleep 30"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = match cg.spawn(&mut cmd) {
        Ok(c) => c,
        Err(SpawnError::Closed | SpawnError::Stopping) => return Err(rt("place refused")),
        Err(SpawnError::Placement(e) | SpawnError::Spawn(e)) => {
            return Err(Unavailable::RoundTrip(format!("spawn/place failed: {e}")));
        }
    };
    let res = round_trip(&mut child, &cg.dirfd);
    if res.is_err() {
        // Cleanup through the cgroup this probe created, then the handle we own.
        let _ = write_kill(&cg.dirfd);
    }
    let _ = child.kill();
    let _ = child.wait();
    res.map_err(|m| rt(&m))
}

fn round_trip(child: &mut std::process::Child, dirfd: &File) -> Result<(), String> {
    let up = wait_populated(dirfd, true, ROUND_TRIP_STEP, || {}).map_err(|e| format!("events: {e}"))?;
    if !up {
        return Err("never saw populated 1".into());
    }
    write_kill(dirfd).map_err(|e| format!("cgroup.kill write: {e}"))?;
    // Reap while polling: the answer must not depend on zombie accounting.
    let mut status = None;
    let down = wait_populated(dirfd, false, ROUND_TRIP_STEP, || {
        if status.is_none() {
            status = child.try_wait().ok().flatten();
        }
    })
    .map_err(|e| format!("events: {e}"))?;
    if !down {
        return Err("populated never returned to 0 within 2s".into());
    }
    let start = Instant::now();
    while status.is_none() && start.elapsed() < ROUND_TRIP_STEP {
        status = child.try_wait().ok().flatten();
        std::thread::sleep(POLL);
    }
    use std::os::unix::process::ExitStatusExt;
    match status.and_then(|s| s.signal()) {
        Some(9) => {}
        other => return Err(format!("child not killed by SIGKILL ({other:?})")),
    }
    Ok(())
}

pub(super) fn open_procs(dir: &Path) -> io::Result<File> {
    let f = OpenOptions::new().write(true).custom_flags(libc::O_CLOEXEC).open(dir.join("cgroup.procs"))?;
    // The fd must not sit in 0..=2: a child's stdio dup2 would overwrite it
    // before our pre_exec runs.
    if f.as_raw_fd() < 3 {
        // SAFETY: valid fd; F_DUPFD_CLOEXEC returns a new owned fd >= 3.
        let n = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `n` is a fresh fd we own.
        return Ok(unsafe { File::from_raw_fd(n) });
    }
    Ok(f)
}

fn fstat_ids(fd: RawFd) -> io::Result<(libc::dev_t, libc::ino_t)> {
    // SAFETY: zeroed stat is a valid out-parameter; fstat only writes it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: plain syscall on a caller-owned fd.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((st.st_dev, st.st_ino))
}

impl ParkHost {
    pub fn process_dir(&self) -> &Path {
        &self.process_dir
    }

    /// Create `<process dir>/<session-uuid>/` and open its `cgroup.procs`.
    pub fn create_session(&self) -> Result<SessionCgroup, Unavailable> {
        let id = new_uuid().map_err(|e| Unavailable::LockDir(e.to_string()))?;
        let dir = self.process_dir.join(id);
        self.env.make_dir(&dir).map_err(|e| mkdir_err(&dir, &e))?;
        let made = open_procs(&dir).and_then(|f| {
            let rel = format!("{}/{}", self.own_rel.trim_end_matches('/'), rel_tail(&self.own_dir, &dir));
            SessionCgroup::from_parts(self.env.clone(), dir.clone(), rel, f)
        });
        made.map_err(|e| {
            self.env.remove_tree(&dir);
            Unavailable::ProcsNotWritable(e.to_string())
        })
    }

    /// Remove `<own>/fuigo-park-*` directories that are empty and whose
    /// owner's lock file EXISTS and is free. A directory whose lock file cannot
    /// be found is kept (its owner may use a different lock directory). Never
    /// kills, never removes a populated directory, never touches this process's
    /// own directory, never enters a `fuigo-park-*` directory below a session.
    pub fn sweep_stale(&self) -> SweepReport {
        let mut rep = SweepReport::default();
        let Ok(rd) = fs::read_dir(&self.own_dir) else { return rep };
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            if !is_park_dir_name(&name) || !ent.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            if ent.path() == self.process_dir {
                continue;
            }
            let lock_path = self.env.lock_dir.join(format!("{name}.lock"));
            // Hold the lock for the whole removal.
            let held = match open_lock_existing(&lock_path) {
                Ok(Some(f)) => match try_flock(&f) {
                    Ok(true) => f,
                    Ok(false) => {
                        rep.kept.push((name, "owner lock held".into()));
                        continue;
                    }
                    Err(e) => {
                        rep.kept.push((name, format!("lock: {e}")));
                        continue;
                    }
                },
                Ok(None) => {
                    rep.kept.push((name, "no lock file".into()));
                    continue;
                }
                Err(e) => {
                    rep.kept.push((name, format!("lock open: {e}")));
                    continue;
                }
            };
            match self.env.remove_tree(&ent.path()) {
                TeardownOutcome::Removed => {
                    let _ = fs::remove_file(&lock_path);
                    rep.removed.push(name);
                }
                TeardownOutcome::LeftPopulated => rep.kept.push((name, "populated".into())),
                TeardownOutcome::Failed(e) => rep.kept.push((name, e)),
            }
            drop(held);
        }
        self.sweep_orphan_locks();
        rep
    }

    /// Remove lock files of dead owners whose directory is gone (a lock is free
    /// exactly when its owner has exited). Files younger than a minute are left:
    /// an owner may have created its file but not yet taken the lock.
    fn sweep_orphan_locks(&self) {
        let Ok(rd) = fs::read_dir(&self.env.lock_dir) else { return };
        for ent in rd.flatten() {
            let fname = ent.file_name().to_string_lossy().into_owned();
            let Some(stem) = fname.strip_suffix(".lock") else { continue };
            if !is_park_dir_name(stem) || ent.path() == self.lock_path {
                continue;
            }
            let old = ent
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age >= Duration::from_secs(60));
            if !old || self.own_dir.join(stem).exists() {
                continue;
            }
            if let Ok(Some(f)) = open_lock_existing(&ent.path())
                && try_flock(&f).unwrap_or(false)
            {
                let _ = fs::remove_file(ent.path());
            }
        }
    }
}

fn open_lock_existing(path: &Path) -> io::Result<Option<File>> {
    match OpenOptions::new().write(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path) {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn rel_tail(base: &Path, dir: &Path) -> String {
    dir.strip_prefix(base).map(|p| p.display().to_string()).unwrap_or_default()
}

impl Drop for ParkHost {
    fn drop(&mut self) {
        // Never kills. A populated directory stays; the next sweep handles it.
        if self.env.remove_tree(&self.process_dir) == TeardownOutcome::Removed {
            let _ = fs::remove_file(&self.lock_path);
        }
    }
}

// ---------------------------------------------------------------------------
// Session cgroup
// ---------------------------------------------------------------------------

/// A test-only callback that pauses a spawn at a named point while it holds the gate lease.
#[cfg(test)]
type TestPauseHook = Arc<dyn Fn(&'static str) + Send + Sync>;

/// One root session's cgroup. `Send + Sync`.
///
/// Entry points for launching a process into it: `ProcessScope::spawn_placed{,_std}`.
pub struct SessionCgroup {
    env: ProbeEnv,
    dir: PathBuf,
    /// Path as `/proc/<pid>/cgroup` would show it (empty for the probe cgroup).
    rel: String,
    /// `O_PATH` handle on `dir`: kill and events go through it, not the path.
    dirfd: File,
    /// Shared with every placement closure so the fd lives as long as any
    /// `Command` that registered one.
    procs: Arc<File>,
    /// `st_dev`/`st_ino` of `cgroup.procs` captured at open.
    procs_id: (libc::dev_t, libc::ino_t),
    /// Open / Closed (session end) / Stopping. Spawns hold the read side until `spawn()` returns.
    pub(super) gate: RwLock<Gate>,
    breached: AtomicBool,
    /// Test-only pause point: called with a stage name while the gate is held
    /// (`placed`/`unplaced`/`fallback` with the read lease, `kill` with the write side).
    #[cfg(test)]
    pub(super) hook: Mutex<Option<TestPauseHook>>,
}

/// Held from `place` until `spawn()` has returned (the gate's read side).
#[must_use = "hold the lease until spawn() returns"]
pub struct PlaceLease<'a> {
    _guard: RwLockReadGuard<'a, Gate>,
    placed: bool,
}

impl PlaceLease<'_> {
    /// True when the placement `pre_exec` was registered; false for an unplaced
    /// start (session end), for which `breached` is already latched.
    pub(crate) fn placed(&self) -> bool {
        self.placed
    }
}

// THE LOCKING RULE (P189 packet C, round 3). The gate is a `RwLock<Gate>`.
//   1. Every spawn decision (placed, unplaced-with-latch, or refused) is made
//      and RECORDED while holding the gate's READ side. The `breached` latch for
//      an unplaced start is set while the read lease is held, BEFORE that
//      command starts, and the lease is held until its `spawn()` has returned,
//      exactly as for a placed spawn (this includes the unplaced fallback after
//      a failed placement write).
//   2. `kill_and_wait` takes the WRITE side (so no spawn decision is in flight),
//      sets `Stopping`, and only then reads `breached` and the own-pid guards,
//      writes `cgroup.kill` and reads `populated`, holding the write side
//      throughout. By rule 1, `breached` read under the write side is final for
//      everything that started before it.
//   3. A spawn that cannot take the read side because the write side is held
//      (try-lock failed, or the lock is poisoned) is REFUSED
//      (`SpawnPlacedError::Stopping`): nothing runs. `kill_and_wait` leaves the
//      state `Stopping` after it returns, until `reopen()` (a failed stop) or
//      session end. The ONLY state allowing an unplaced start is `Closed`, set by
//      `close()` at session end, where no kill follows.
//   4. A spawn never blocks behind a kill: the read side is only try-locked.
// Hence: if `kill_and_wait` returns `Emptied`, no process of this session
// started outside the cgroup before that result, and none can start during or
// after it until the gate is reopened. `breached` is never cleared (not even by
// `reopen()`): after a failed stop the session continues, and a later stop must
// still report incomplete.
/// The stop gate. `Closed` (session end only): a spawn through
/// [`SessionCgroup::place_or_latch`] runs unplaced with `breached` latched.
/// `Stopping` (a stop is in progress or done, until `reopen`): a spawn is
/// REFUSED and nothing runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gate {
    Open,
    Closed,
    Stopping,
}

impl SessionCgroup {
    pub(super) fn from_parts(env: ProbeEnv, dir: PathBuf, rel: String, procs: File) -> io::Result<Self> {
        let dirfd = open_dirfd(&dir)?;
        let procs_id = fstat_ids(procs.as_raw_fd())?;
        Ok(Self {
            env,
            dir,
            rel,
            dirfd,
            procs: Arc::new(procs),
            procs_id,
            gate: RwLock::new(Gate::Open),
            breached: AtomicBool::new(false),
            #[cfg(test)]
            hook: Mutex::new(None),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    #[cfg(test)]
    pub(super) fn procs_fd_for_test(&self) -> RawFd {
        self.procs.as_raw_fd()
    }

    /// Std entry used by the probe round trip and tests (crate-private: the one
    /// public placement entries are `ProcessScope::spawn_placed{,_std}`). Same
    /// locking rule: the read lease is held through `spawn()` and `breached` is
    /// latched before it is dropped. A closed gate refuses ([`SpawnError::Closed`]).
    pub(crate) fn spawn(&self, cmd: &mut std::process::Command) -> Result<std::process::Child, SpawnError> {
        let lease = self.place(cmd).map_err(|e| match e {
            PlaceError::Stopping => SpawnError::Stopping,
            _ => SpawnError::Closed,
        })?;
        // reason: the single sanctioned spawn of a session child; placement is
        // inside the gate and the failure is recorded below, under the lease.
        #[allow(clippy::disallowed_methods)]
        let spawned = cmd.spawn();
        let out = spawned.map_err(|e| if self.record_spawn_error(&e) { SpawnError::Placement(e) } else { SpawnError::Spawn(e) });
        drop(lease);
        out
    }

    #[cfg(test)]
    fn test_pause(&self, stage: &'static str) {
        let h = self.hook.lock().unwrap_or_else(PoisonError::into_inner).clone();
        if let Some(h) = h {
            h(stage);
        }
    }
    #[cfg(not(test))]
    fn test_pause(&self, _stage: &'static str) {}

    /// Register the placement `pre_exec` on `cmd` and take a read lease; a
    /// closed gate ([`PlaceError::Closed`]) or a stop ([`PlaceError::Stopping`])
    /// refuses and nothing is latched.
    pub(crate) fn place(&self, cmd: &mut std::process::Command) -> Result<PlaceLease<'_>, PlaceError> {
        self.place_inner(cmd, false)
    }

    /// As [`place`](Self::place), except that a gate closed by session end hands
    /// back an UNPLACED lease with `breached` already latched under it (the
    /// command still runs, outside the cgroup). A stop in progress, or a gate
    /// whose write side is held or poisoned, is [`PlaceError::Stopping`].
    pub(crate) fn place_or_latch(&self, cmd: &mut std::process::Command) -> Result<PlaceLease<'_>, PlaceError> {
        self.place_inner(cmd, true)
    }

    /// The closure owns an `Arc` of the `cgroup.procs` file, `fstat`s the fd and
    /// compares `st_dev`/`st_ino` with the values captured at open, then does
    /// exactly one `write(fd, "0")`. On any mismatch or short write it returns
    /// [`PLACE_SENTINEL_ERRNO`]. It allocates nothing, takes no locks and logs
    /// nothing: it runs between fork and exec (`fstat` and `write` are
    /// async-signal-safe). See THE LOCKING RULE above.
    fn place_inner(&self, cmd: &mut std::process::Command, unplaced_ok: bool) -> Result<PlaceLease<'_>, PlaceError> {
        // Rule 3/4: never wait behind a kill; contention or poison is a refusal.
        let guard = match self.gate.try_read() {
            Ok(g) => g,
            Err(_) => return Err(PlaceError::Stopping),
        };
        match *guard {
            Gate::Open => {}
            Gate::Stopping => return Err(PlaceError::Stopping),
            Gate::Closed => {
                if !unplaced_ok {
                    return Err(PlaceError::Closed);
                }
                // Rule 1: latched under the read lease, before the command starts.
                self.breached.store(true, Ordering::SeqCst);
                self.test_pause("unplaced");
                return Ok(PlaceLease { _guard: guard, placed: false });
            }
        }
        let file = Arc::clone(&self.procs);
        let (dev, ino) = self.procs_id;
        // SAFETY: the closure only calls fstat(2) and write(2) on a captured fd
        // with stack/static buffers, and builds an errno-only io::Error; no
        // allocation, locks, formatting or panics.
        unsafe {
            cmd.pre_exec(move || {
                let fd = file.as_raw_fd();
                let mut st: libc::stat = std::mem::zeroed();
                if libc::fstat(fd, &mut st) != 0 || st.st_dev != dev || st.st_ino != ino {
                    return Err(io::Error::from_raw_os_error(PLACE_SENTINEL_ERRNO));
                }
                if libc::write(fd, b"0".as_ptr().cast(), 1) == 1 {
                    Ok(())
                } else {
                    Err(io::Error::from_raw_os_error(PLACE_SENTINEL_ERRNO))
                }
            });
        }
        self.test_pause("placed");
        Ok(PlaceLease { _guard: guard, placed: true })
    }

    /// Latch `breached` if `err` is the placement sentinel. Returns whether it was.
    /// Call it while still holding the lease (it latches under it).
    pub fn record_spawn_error(&self, err: &io::Error) -> bool {
        let hit = err.raw_os_error() == Some(PLACE_SENTINEL_ERRNO);
        if hit {
            self.breached.store(true, Ordering::SeqCst);
        }
        hit
    }

    /// Latch `breached`: a command of this session started (or is about to
    /// start) outside the cgroup, so a later stop must not report a clean result.
    pub(crate) fn latch_breached(&self) {
        self.breached.store(true, Ordering::SeqCst);
    }

    /// Hold the fallback pause point (test hook) with the lease still held.
    pub(crate) fn fallback_point(&self) {
        self.test_pause("fallback");
    }

    pub fn is_breached(&self) -> bool {
        self.breached.load(Ordering::SeqCst)
    }

    /// Take the write side (waits for every outstanding lease, no timeout) and
    /// shut the gate: later spawns get [`SpawnError::Closed`]. Do not call on a
    /// thread that holds a lease.
    pub fn close(&self) {
        let mut g = self.gate.write().unwrap_or_else(PoisonError::into_inner);
        if *g == Gate::Open {
            *g = Gate::Closed;
        }
    }

    /// A stop begins (optional early call: `kill_and_wait` itself sets
    /// `Stopping` under the write side): takes the
    /// write side (waits for every outstanding lease) and sets the gate to
    /// `Stopping`, so a spawn attempted from now on is REFUSED
    /// (`SpawnPlacedError::Stopping`) and nothing runs. [`reopen`](Self::reopen)
    /// undoes it. Nothing calls this yet. Do not call on a thread that holds a lease.
    pub fn begin_stop(&self) {
        *self.gate.write().unwrap_or_else(PoisonError::into_inner) = Gate::Stopping;
    }

    /// Open the gate again (a stop that failed leaves the session usable).
    /// Never clears `breached`: a later stop must still report incomplete.
    pub fn reopen(&self) {
        *self.gate.write().unwrap_or_else(PoisonError::into_inner) = Gate::Open;
    }

    /// Stop: set `Stopping`, write `1` to `cgroup.kill`, then wait for `populated 0`
    /// for `min(5 s, deadline)`. The gate's write side is taken here and held
    /// through the `populated` read, so a spawn can neither slip in nor be
    /// mid-flight: if outstanding leases are not gone within the deadline the
    /// answer is `Refused(GateOpen)`. Also refuses, without killing, when
    /// `breached` or when we are inside the cgroup. Whatever the outcome the
    /// gate stays `Stopping` (spawns are refused) until [`reopen`](Self::reopen)
    /// (a failed stop; the session continues) or session end; `GateOpen` (the
    /// write side was never taken) leaves it untouched.
    pub fn kill_and_wait(&self, deadline: Duration) -> KillOutcome {
        let own = std::fs::read_to_string("/proc/self/cgroup").ok().and_then(|s| {
            s.lines().find_map(|l| l.strip_prefix("0::").map(|p| p.trim().to_string()))
        });
        self.kill_and_wait_as(deadline, std::process::id(), own.as_deref())
    }

    /// [`kill_and_wait`](Self::kill_and_wait) with the identity of "us" given
    /// (tests substitute a child's pid so the test process is never moved).
    pub(super) fn kill_and_wait_as(&self, deadline: Duration, self_pid: u32, self_cgroup: Option<&str>) -> KillOutcome {
        let start = Instant::now();
        let limit = deadline.min(KILL_CAP);
        let mut guard = loop {
            match self.gate.try_write() {
                Ok(g) => break g,
                Err(TryLockError::Poisoned(p)) => break p.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    if start.elapsed() >= limit {
                        return KillOutcome::Refused(RefuseReason::GateOpen);
                    }
                    std::thread::sleep(POLL);
                }
            }
        };
        // Rule 2/3: Stopping under the write side, and it STAYS (even after a
        // refusal) until `reopen()` or session end.
        *guard = Gate::Stopping;
        self.test_pause("kill");
        self.kill_gated(limit, self_pid, self_cgroup)
    }

    /// The kill itself; the caller holds the gate's write side.
    fn kill_gated(&self, limit: Duration, self_pid: u32, self_cgroup: Option<&str>) -> KillOutcome {
        if self.is_breached() {
            return KillOutcome::Refused(RefuseReason::Breached);
        }
        if let Some(c) = self_cgroup
            && !self.rel.is_empty()
            && (c == self.rel || c.starts_with(&format!("{}/", self.rel)))
        {
            return KillOutcome::Refused(RefuseReason::SelfInCgroup);
        }
        let mut pids = Vec::new();
        if let Err(e) = list_pids(&self.dir, &mut pids) {
            return KillOutcome::Refused(RefuseReason::Io(format!("cgroup.procs: {e}")));
        }
        if pids.contains(&self_pid) {
            return KillOutcome::Refused(RefuseReason::SelfInCgroup);
        }
        let start = Instant::now();
        if let Err(e) = write_kill(&self.dirfd) {
            return KillOutcome::Refused(RefuseReason::Io(format!("cgroup.kill: {e}")));
        }
        // From here the kill was written: never report "nothing was killed".
        match wait_populated(&self.dirfd, false, limit, || {}) {
            Ok(true) => KillOutcome::Emptied { waited: start.elapsed() },
            Ok(false) => KillOutcome::NotEmptied { waited: start.elapsed() },
            Err(e) => KillOutcome::KilledUnverified(format!("cgroup.events: {e}")),
        }
    }

    /// Close the gate and `rmdir` bottom-up if empty. Never kills; a populated
    /// directory is left in place and reported, and so is one holding a nested
    /// Fuigo's `fuigo-park-*` directory.
    pub fn teardown(&self) -> TeardownOutcome {
        self.close();
        self.env.remove_tree(&self.dir)
    }
}

impl Drop for SessionCgroup {
    fn drop(&mut self) {
        let _ = self.env.remove_tree(&self.dir);
    }
}
