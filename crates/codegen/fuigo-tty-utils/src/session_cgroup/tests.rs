//! Fake-tree tests run anywhere on Linux; the real-cgroup tests use the
//! production probe and skip (or fail under `FUIGO_TEST_REQUIRE_CGROUP=1`).
#![allow(clippy::disallowed_methods)] // tests spawn and reap their own placed children
#![allow(clippy::print_stdout)] // the receipt lines (P189-CGROUP-RAN/SKIP) are test output

use super::imp::{check_lock_dir, is_uuid, open_lock, probe_for_pid, ProbeEnv};
use super::*;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static N: AtomicUsize = AtomicUsize::new(0);

fn tmp(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "p189b-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A fake cgroup root with one own cgroup `/own`.
fn fake(tag: &str) -> (ProbeEnv, PathBuf) {
    let root = tmp(tag);
    std::fs::create_dir_all(root.join("own")).unwrap();
    // The probe requires our own pid to be listed in our cgroup's procs.
    std::fs::write(root.join("own/cgroup.procs"), format!("{}\n", std::process::id())).unwrap();
    let mut env = ProbeEnv::system();
    env.cgroup_root = root.clone();
    env.own_cgroup = Some("/own".into());
    env.lock_dir = root.join("locks");
    env.require_cgroup2 = false;
    (env, root)
}

fn no_leftovers(root: &Path) {
    let left: Vec<_> = std::fs::read_dir(root.join("own"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .collect();
    assert!(left.is_empty(), "leftover dirs: {left:?}");
}

fn full_files(dir: &Path) {
    std::fs::write(dir.join("cgroup.kill"), "").unwrap();
    std::fs::write(dir.join("cgroup.procs"), "").unwrap();
    std::fs::write(dir.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
}

#[test]
fn fake_not_cgroup2() {
    let (mut env, root) = fake("notv2");
    env.require_cgroup2 = true; // a tmp dir is not cgroup2fs
    assert!(matches!(probe_with(&env), Err(Unavailable::NotCgroup2(_))));
    no_leftovers(&root);
}

#[test]
fn fake_own_cgroup_missing_and_unreadable() {
    let (mut env, _r) = fake("own");
    env.own_cgroup = Some("/nope".into());
    assert!(matches!(probe_with(&env), Err(Unavailable::OwnCgroupMissing(_))));
    env.own_cgroup = None;
    assert_eq!(probe_with(&env).err(), Some(Unavailable::OwnCgroupUnreadable));
}

#[test]
fn fake_cgroup_type_threaded() {
    let (env, root) = fake("thr");
    std::fs::write(root.join("own/cgroup.type"), "threaded\n").unwrap();
    assert_eq!(probe_with(&env).err(), Some(Unavailable::OwnCgroupNotDomain("threaded".into())));
    // `domain` passes this step (and proceeds to the next failure).
    std::fs::write(root.join("own/cgroup.type"), "domain\n").unwrap();
    let mut env = env;
    env.mkdir_errno = Some(libc::EACCES);
    assert!(matches!(probe_with(&env), Err(Unavailable::MkdirRefused { .. })));
}

#[test]
fn fake_mkdir_refused_eacces_erofs() {
    for (e, name) in [(libc::EACCES, "EACCES"), (libc::EROFS, "EROFS")] {
        let (mut env, root) = fake("mk");
        env.mkdir_errno = Some(e);
        let err = probe_with(&env).err().unwrap();
        assert!(matches!(err, Unavailable::MkdirRefused { errno, .. } if errno == e), "{err}");
        assert!(err.to_string().contains(name), "{err}");
        no_leftovers(&root);
    }
}

#[test]
fn fake_no_cgroup_kill() {
    let (mut env, root) = fake("nokill");
    env.populate = Some(|d| std::fs::write(d.join("cgroup.procs"), "").unwrap());
    assert_eq!(probe_with(&env).err(), Some(Unavailable::NoCgroupKill));
    no_leftovers(&root);
}

#[test]
fn fake_procs_not_writable() {
    let (mut env, root) = fake("noprocs");
    env.populate = Some(|d| {
        std::fs::write(d.join("cgroup.kill"), "").unwrap();
        std::fs::create_dir(d.join("cgroup.procs")).unwrap(); // open for write: EISDIR
    });
    assert!(matches!(probe_with(&env), Err(Unavailable::ProcsNotWritable(_))));
    no_leftovers(&root);
}

#[test]
fn fake_round_trip_never_empties() {
    let (mut env, root) = fake("rt");
    env.populate = Some(full_files); // events stays "populated 1" after the kill
    let t = Instant::now();
    let err = probe_with(&env).err().unwrap();
    assert!(matches!(&err, Unavailable::RoundTrip(m) if m.contains("never returned to 0")), "{err}");
    assert!(t.elapsed() < Duration::from_secs(6));
    no_leftovers(&root);
}

#[test]
fn fake_probe_panic_is_unavailable() {
    let (mut env, _r) = fake("panic");
    env.panic_in_probe = true;
    assert_eq!(probe_with(&env).err(), Some(Unavailable::Panicked));
}

#[test]
fn fake_sweep_removes_only_empty_unlocked_valid_names() {
    let (env, root) = fake("sweep");
    let own = root.join("own");
    std::os::unix::fs::DirBuilderExt::mode(std::fs::DirBuilder::new().recursive(true), 0o700).create(&env.lock_dir).unwrap();
    let mk = |n: &str| {
        let p = own.join(n);
        std::fs::create_dir_all(p.join("child")).unwrap();
        p
    };
    let u = |c: char| format!("fuigo-park-{}", c.to_string().repeat(8) + "-1111-2222-3333-444444444444");
    let stale = mk(&u('a'));
    std::fs::File::create(env.lock_dir.join(format!("{}.lock", u('a')))).unwrap(); // free lock = dead owner
    let locked = mk(&u('b'));
    let populated = mk(&u('c'));
    std::fs::write(populated.join("child/stray"), "x").unwrap(); // rmdir must refuse
    let badname = mk("fuigo-park-not-a-uuid");
    let other = mk("someone-else");
    // The lock of `locked` is held by a second open file description.
    let lp = env.lock_dir.join(format!("{}.lock", u('b')));
    let held = std::fs::File::create(&lp).unwrap();
    assert_eq!(unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&held), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    // Orphan lock files: an old free one goes, a young one stays.
    let old_lock = env.lock_dir.join(format!("{}.lock", u('7')));
    let young_lock = env.lock_dir.join(format!("{}.lock", u('8')));
    let f = std::fs::File::create(&old_lock).unwrap();
    f.set_modified(std::time::SystemTime::now() - Duration::from_secs(3600)).unwrap();
    std::fs::File::create(&young_lock).unwrap();
    // Our own host: this also runs the sweep. (Real kernel files are absent, so
    // use a probe that fails after the sweep: the sweep ran before mkdir.)
    let mut env2 = env.clone();
    env2.mkdir_errno = Some(libc::EACCES);
    let _ = probe_with(&env2);
    assert!(!stale.exists());
    assert!(!old_lock.exists() && young_lock.exists());
    assert!(locked.exists() && populated.exists() && badname.exists() && other.exists());
    drop(held);
}

// ---------------------------------------------------------------------------
// Real cgroup
// ---------------------------------------------------------------------------

static RAN: AtomicUsize = AtomicUsize::new(0);

/// `None` = skipped (printed); panics if `FUIGO_TEST_REQUIRE_CGROUP=1`.
struct Real {
    host: ParkHost,
    _serial: std::sync::MutexGuard<'static, ()>,
}
impl std::ops::Deref for Real {
    type Target = ParkHost;
    fn deref(&self) -> &ParkHost {
        &self.host
    }
}
/// Real-cgroup tests run one at a time: the sweep test creates unlocked stale
/// directories that a parallel test's probe sweep would otherwise remove.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn real(name: &str) -> Option<Real> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    match probe_with(&ProbeEnv::system()) {
        Ok(host) => {
            let h = Real { host, _serial: g };
            let n = RAN.fetch_add(1, Ordering::SeqCst) + 1;
            let own = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
            let own_dir = ProbeEnv::system().cgroup_root.join(own.trim().trim_start_matches("0::").trim_start_matches('/'));
            let members = std::fs::read_to_string(own_dir.join("cgroup.procs")).map(|s| s.lines().count()).unwrap_or(0);
            println!("P189-CGROUP-RAN {n} {name} own_cgroup={} own_cgroup_procs={members}", own.trim());
            Some(h)
        }
        Err(r) => {
            println!("P189-CGROUP-SKIP {r} ({name})");
            assert!(
                std::env::var("FUIGO_TEST_REQUIRE_CGROUP").as_deref() != Ok("1"),
                "cgroup required but unavailable: {r}"
            );
            None
        }
    }
}

fn placed(cg: &SessionCgroup, script: &str) -> Child {
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", script]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    cg.spawn(&mut cmd).expect("spawn placed")
}

/// Not dead: alive and not a zombie.
fn alive(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => !s.rsplit(')').next().unwrap_or("").trim_start().starts_with('Z'),
        Err(_) => false,
    }
}

fn wait_file_pid(f: &Path) -> u32 {
    for _ in 0..300 {
        if let Ok(s) = std::fs::read_to_string(f) && let Ok(p) = s.trim().parse() {
            return p;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("no pid file {f:?}");
}

fn cgroup_of(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default()
}

fn pids_gone(pids: &[u32]) -> bool {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(3) {
        if pids.iter().all(|p| !alive(*p)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

#[test]
fn real_setsid_double_fork_daemon_dies_and_sibling_survives() {
    let Some(host) = real("daemon_and_sibling") else { return };
    let a = host.create_session().unwrap();
    let b = host.create_session().unwrap();
    let t = tmp("daemon");
    let pidf = t.join("pid");
    let script = format!(
        "(setsid sh -c 'sleep 300 </dev/null >/dev/null 2>&1 & echo $! > {}; exit') ; sleep 300",
        pidf.display()
    );
    let mut ca = placed(&a, &script);
    let mut cb = placed(&b, "sleep 300");
    let daemon = wait_file_pid(&pidf);
    assert!(alive(daemon));
    assert!(cgroup_of(daemon).contains(a.dir().file_name().unwrap().to_str().unwrap()));
    a.close();
    let out = a.kill_and_wait(Duration::from_secs(5));
    assert!(matches!(out, KillOutcome::Emptied { .. }), "{out:?}");
    let _ = ca.wait();
    assert!(pids_gone(&[daemon, ca.id()]), "daemon survived");
    // Sibling session in the same process directory is untouched.
    assert!(alive(cb.id()), "sibling killed");
    b.close();
    assert!(matches!(b.kill_and_wait(Duration::from_secs(5)), KillOutcome::Emptied { .. }));
    assert_eq!(cb.wait().unwrap().signal(), Some(9));
    assert_eq!(a.teardown(), TeardownOutcome::Removed);
    assert_eq!(b.teardown(), TeardownOutcome::Removed);
    let _ = std::fs::remove_dir_all(t);
}

#[test]
fn real_place_after_close_refused() {
    let Some(host) = real("closed") else { return };
    let cg = host.create_session().unwrap();
    cg.close();
    let mut cmd = Command::new("/bin/true");
    assert_eq!(cg.place(&mut cmd).err(), Some(PlaceError::Closed));
    cg.reopen();
    let mut c = placed(&cg, "exit 0");
    assert!(c.wait().unwrap().success());
}

#[test]
fn real_failed_placement_latches_breach_and_blocks_kill() {
    let Some(host) = real("breach") else { return };
    let cg = host.create_session().unwrap();
    let mut live = placed(&cg, "sleep 300");
    // Test-only sabotage: point the session's procs fd at a read-only file so
    // the next placement write fails with EBADF.
    let ro = std::fs::File::open("/dev/null").unwrap();
    let fd = cg.procs_fd_for_test();
    assert!(unsafe { libc::dup2(std::os::fd::AsRawFd::as_raw_fd(&ro), fd) } >= 0);
    let mut cmd = Command::new("/bin/true");
    let err = cg.spawn(&mut cmd).expect_err("placement must fail");
    assert!(matches!(err, SpawnError::Placement(_)), "{err:?}");
    assert!(cg.is_breached());
    assert_eq!(cg.kill_and_wait(Duration::from_secs(1)), KillOutcome::Refused(RefuseReason::Breached));
    assert!(alive(live.id()), "refused kill must not kill");
    // Cleanup: this test created the cgroup, so it may write its kill file.
    std::fs::write(cg.dir().join("cgroup.kill"), "1").unwrap();
    let _ = live.wait();
}

#[test]
fn real_own_pid_in_cgroup_refuses_kill() {
    let Some(host) = real("selfpid") else { return };
    let cg = host.create_session().unwrap();
    let mut c = placed(&cg, "sleep 300");
    // Pose the child as "us": the test process itself is never moved.
    let out = cg.kill_and_wait_as(Duration::from_secs(1), c.id(), None);
    assert_eq!(out, KillOutcome::Refused(RefuseReason::SelfInCgroup));
    assert!(alive(c.id()));
    let rel = cgroup_of(c.id()).trim().trim_start_matches("0::").to_string();
    let out = cg.kill_and_wait_as(Duration::from_secs(1), 1, Some(&rel));
    assert_eq!(out, KillOutcome::Refused(RefuseReason::SelfInCgroup));
    assert!(alive(c.id()));
    assert!(matches!(cg.kill_and_wait(Duration::from_secs(5)), KillOutcome::Emptied { .. }));
    let _ = c.wait();
}

#[test]
fn real_teardown_leaves_populated_removes_empty() {
    let Some(host) = real("teardown") else { return };
    let empty = host.create_session().unwrap();
    assert_eq!(empty.teardown(), TeardownOutcome::Removed);
    assert!(!empty.dir().exists());
    let busy = host.create_session().unwrap();
    let mut c = placed(&busy, "sleep 300");
    assert_eq!(busy.teardown(), TeardownOutcome::LeftPopulated);
    assert!(busy.dir().exists() && alive(c.id()), "teardown must not kill");
    assert!(matches!(busy.kill_and_wait(Duration::from_secs(5)), KillOutcome::Emptied { .. }));
    let _ = c.wait();
    assert_eq!(busy.teardown(), TeardownOutcome::Removed);
}

#[test]
fn real_sweep_removes_only_empty_unlocked() {
    let Some(host) = real("sweep") else { return };
    let own = host.process_dir().parent().unwrap().to_path_buf();
    let tail = std::fs::read_to_string("/proc/sys/kernel/random/uuid").unwrap().trim()[8..].to_string();
    let u = |c: char| format!("fuigo-park-{}{tail}", c.to_string().repeat(8));
    let (stale, locked, busy) = (own.join(u('d')), own.join(u('e')), own.join(u('f')));
    std::fs::create_dir(&stale).unwrap();
    std::fs::create_dir(stale.join("s1")).unwrap();
    std::fs::create_dir(&locked).unwrap();
    std::fs::create_dir(&busy).unwrap();
    let env = ProbeEnv::system();
    std::fs::create_dir_all(&env.lock_dir).unwrap();
    let lp = env.lock_dir.join(format!("{}.lock", u('e')));
    // `stale` and `busy` have free lock files (dead owners); a missing lock would keep them.
    let (lock_stale, lock_busy) = (env.lock_dir.join(format!("{}.lock", u('d'))), env.lock_dir.join(format!("{}.lock", u('f'))));
    std::fs::File::create(&lock_stale).unwrap();
    std::fs::File::create(&lock_busy).unwrap();
    let held = std::fs::File::create(&lp).unwrap();
    assert_eq!(unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&held), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    // A populated stale directory: a placed sleep inside `busy/s1`.
    let busy_host_dir = busy.join("s1");
    std::fs::create_dir(&busy_host_dir).unwrap();
    let procs = std::fs::OpenOptions::new().write(true).open(busy_host_dir.join("cgroup.procs")).unwrap();
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "sleep 300"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    let fd = std::os::fd::AsRawFd::as_raw_fd(&procs);
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut cmd, move || {
            if libc::write(fd, b"0".as_ptr().cast(), 1) == 1 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
        });
    }
    let mut c = cmd.spawn().unwrap();
    let rep = host.sweep_stale();
    assert!(!stale.exists(), "empty unlocked dir must go: {rep:?}");
    assert!(locked.exists(), "locked dir must stay");
    // `busy` has a free lock (owner "dead"), but is populated: kept.
    assert!(busy.exists() && alive(c.id()), "populated dir must stay and nothing is killed");
    // Cleanup of exactly what this test made.
    // Kill via the cgroup this test created (never via a pid).
    std::fs::write(busy_host_dir.join("cgroup.kill"), "1").unwrap();
    let _ = c.wait();
    drop(held);
    let _ = std::fs::remove_file(&lp);
    let _ = std::fs::remove_file(&lock_stale);
    let _ = std::fs::remove_file(&lock_busy);
    let t = Instant::now();
    while std::fs::remove_dir(&busy_host_dir).is_err() && t.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = std::fs::remove_dir(&busy);
    let _ = std::fs::remove_dir(&locked);
}

#[test]
fn real_zombie_and_populated() {
    let Some(host) = real("zombie") else { return };
    let cg = host.create_session().unwrap();
    let c = placed(&cg, "sleep 300");
    let pid = c.id();
    cg.close();
    // Do NOT reap `c`: after the kill it is a zombie until wait().
    let out = cg.kill_and_wait(Duration::from_secs(5));
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let state = stat.rsplit(')').next().unwrap_or("").trim().chars().next().unwrap_or('?');
    let listed = std::fs::read_to_string(cg.dir().join("cgroup.procs")).unwrap_or_default().contains(&pid.to_string());
    println!("P189-ZOMBIE outcome={out:?} state_after={state} zombie_listed_in_cgroup_procs={listed}");
    // Verified on the build box: a zombie does not keep `populated` at 1.
    assert!(matches!(out, KillOutcome::Emptied { .. }), "{out:?}");
    assert_eq!(state, 'Z', "child should be an unreaped zombie");
    let mut c = c;
    let _ = c.wait();
}

#[test]
fn real_cached_probe_agrees() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let a = probe().map(|h| h.process_dir().to_path_buf()).map_err(|e| e.clone());
    let b = probe().map(|h| h.process_dir().to_path_buf()).map_err(|e| e.clone());
    assert_eq!(a, b);
    println!("P189-PROBE {}", a.map(|p| format!("usable {}", p.display())).unwrap_or_else(|e| format!("unavailable: {e}")));
}

#[test]
fn uuid_shape() {
    assert!(is_uuid("12345678-1234-1234-1234-123456789abc"));
    assert!(!is_uuid("12345678-1234-1234-1234-123456789ABC"));
    assert!(!is_uuid("nope"));
}

// ---------------------------------------------------------------------------
// Round 2: fake-tree tests of the rules (run on any Linux, probe or not)
// ---------------------------------------------------------------------------

fn ok_files(dir: &Path) {
    std::fs::write(dir.join("cgroup.kill"), "").unwrap();
    std::fs::write(dir.join("cgroup.procs"), "").unwrap();
    std::fs::write(dir.join("cgroup.events"), "populated 0\n").unwrap();
}

/// `cgroup.procs` is `/dev/full`: it opens for write, every write fails.
fn full_procs_files(dir: &Path) {
    ok_files(dir);
    std::fs::remove_file(dir.join("cgroup.procs")).unwrap();
    std::os::unix::fs::symlink("/dev/full", dir.join("cgroup.procs")).unwrap();
}

/// A successful fake probe (no live round trip): a real `ParkHost` on a plain-file tree.
fn fake_host(tag: &str, populate: fn(&Path)) -> (ParkHost, ProbeEnv, PathBuf) {
    let (mut env, root) = fake(tag);
    env.populate = Some(populate);
    env.skip_round_trip = true;
    let host = probe_with(&env).expect("fake probe");
    (host, env, root)
}

const UA: &str = "fuigo-park-aaaaaaaa-1111-2222-3333-444444444444";
const UB: &str = "fuigo-park-bbbbbbbb-1111-2222-3333-444444444444";

#[test]
fn fake_sweep_keeps_directory_when_lock_file_not_found() {
    // Two "processes" that disagree on the lock directory.
    let (host, env, root) = fake_host("nolock", ok_files);
    let theirs = root.join("their-locks");
    std::fs::create_dir_all(&theirs).unwrap();
    std::fs::create_dir_all(root.join("own").join(UA).join("sess")).unwrap();
    std::fs::File::create(theirs.join(format!("{UA}.lock"))).unwrap(); // free, but in THEIR dir
    let rep = host.sweep_stale();
    assert!(root.join("own").join(UA).exists(), "must keep: {rep:?}");
    assert!(rep.kept.contains(&(UA.to_string(), "no lock file".to_string())), "{rep:?}");
    // The same directory with its lock visible and free goes.
    std::fs::File::create(env.lock_dir.join(format!("{UA}.lock"))).unwrap();
    let rep = host.sweep_stale();
    assert!(!root.join("own").join(UA).exists() && rep.removed == vec![UA.to_string()], "{rep:?}");
    drop(host);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn fake_nested_fuigo_directories_are_never_removed() {
    let (host, env, root) = fake_host("nested", ok_files);
    let own = root.join("own");
    // Sweep: a stale park dir whose session holds a nested Fuigo's park dir.
    let nested = own.join(UA).join("sess").join(UB).join("inner-sess");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::File::create(env.lock_dir.join(format!("{UA}.lock"))).unwrap();
    let rep = host.sweep_stale();
    assert!(nested.exists(), "nested tree touched: {rep:?}");
    assert!(rep.kept.iter().any(|(n, why)| n == UA && why == "populated"), "{rep:?}");
    // Session teardown and Drop leave the nested directory too.
    let s = host.create_session().unwrap();
    let nested2 = s.dir().join(UB).join("inner");
    std::fs::create_dir_all(&nested2).unwrap();
    assert_eq!(s.teardown(), TeardownOutcome::LeftPopulated);
    drop(s);
    assert!(nested2.exists());
    drop(host);
    assert!(nested2.exists() && nested.exists());
    let _ = std::fs::remove_dir_all(root);
}

fn fake_session(tag: &str, populate: fn(&Path)) -> (ParkHost, SessionCgroup, PathBuf) {
    let (host, _env, root) = fake_host(tag, populate);
    let s = host.create_session().unwrap();
    (host, s, root)
}

#[test]
fn fake_spawn_places_and_runs() {
    let (_h, s, root) = fake_session("spawn", ok_files);
    let mut cmd = Command::new("/bin/true");
    let mut c = s.spawn(&mut cmd).unwrap();
    assert!(c.wait().unwrap().success());
    assert_eq!(std::fs::read_to_string(s.dir().join("cgroup.procs")).unwrap(), "0");
    assert!(!s.is_breached());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn fake_placement_failure_latches_breach_and_blocks_kill() {
    let (_h, s, root) = fake_session("fullprocs", full_procs_files);
    let mut cmd = Command::new("/bin/true");
    let err = s.spawn(&mut cmd).unwrap_err();
    assert!(matches!(&err, SpawnError::Placement(e) if e.raw_os_error() == Some(PLACE_SENTINEL_ERRNO)), "{err:?}");
    assert!(s.is_breached());
    assert_eq!(s.kill_and_wait(Duration::from_secs(1)), KillOutcome::Refused(RefuseReason::Breached));
    // Round 3: even a refusal leaves the gate Stopping until reopen(); breached survives it.
    assert!(matches!(s.spawn(&mut Command::new("/bin/true")), Err(SpawnError::Stopping)));
    s.reopen();
    assert!(s.is_breached(), "reopen() never clears breached");
    assert!(matches!(s.spawn(&mut Command::new("/bin/true")), Err(SpawnError::Placement(_))));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn fake_clobbered_fd_gives_sentinel_and_child_never_starts() {
    let (_h, s, root) = fake_session("clobber", ok_files);
    let marker = root.join("started");
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", &format!("touch {}", marker.display())]);
    let devnull = std::fs::File::open("/dev/null").unwrap();
    let (src, dst) = (std::os::fd::AsRawFd::as_raw_fd(&devnull), s.procs_fd_for_test());
    // An EARLIER hook that dup2s onto our fd number: the write would "succeed" on /dev/null.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut cmd, move || {
            if libc::dup2(src, dst) < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
        });
    }
    // /dev/null swallows the write, so only the st_dev/st_ino check can catch it.
    let err = s.spawn(&mut cmd).unwrap_err();
    assert!(matches!(err, SpawnError::Placement(_)), "{err:?}");
    assert!(s.is_breached());
    std::thread::sleep(Duration::from_millis(100));
    assert!(!marker.exists(), "child must not start");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn fake_respawn_after_cgroup_dropped_keeps_its_fd_and_touches_no_bystander() {
    let (_h, s, root) = fake_session("respawn", ok_files);
    let mut cmd = Command::new("/bin/true");
    drop(s.place(&mut cmd).unwrap());
    let fd = s.procs_fd_for_test();
    drop(s);
    // The Command still owns the fd, so nothing else can be handed that number.
    let by_path = root.join("bystander");
    let by = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(&by_path).unwrap();
    assert_ne!(std::os::fd::AsRawFd::as_raw_fd(&by), fd);
    let _ = cmd.spawn().map(|mut c| c.wait());
    assert_eq!(std::fs::read_to_string(&by_path).unwrap(), "", "bystander written");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn fake_kill_without_close_takes_the_gate_and_closes_it() {
    let (_h, s, root) = fake_session("nocloseA", ok_files);
    // No close() call: kill_and_wait must hold the gate itself.
    assert!(matches!(s.kill_and_wait(Duration::from_secs(1)), KillOutcome::Emptied { .. }));
    assert!(matches!(s.spawn(&mut Command::new("/bin/true")), Err(SpawnError::Stopping)));
    s.reopen();
    assert!(s.spawn(&mut Command::new("/bin/true")).unwrap().wait().unwrap().success());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn fake_outstanding_lease_refuses_then_delays_the_kill() {
    let (_h, s, root) = fake_session("lease", ok_files);
    let mut cmd = Command::new("/bin/true");
    let lease = s.place(&mut cmd).unwrap();
    assert_eq!(s.kill_and_wait(Duration::from_millis(150)), KillOutcome::Refused(RefuseReason::GateOpen));
    drop(lease);
    // A lease that ends mid-wait delays the kill instead of refusing it.
    let s = &s;
    let finished = std::sync::atomic::AtomicBool::new(false);
    let finished = &finished;
    std::thread::scope(|sc| {
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        sc.spawn(move || {
            let mut c = Command::new("/bin/true");
            let l = s.place(&mut c).unwrap();
            held_tx.send(()).unwrap();
            // Released by the main thread, never by a timer: no scheduling delay can end the lease early.
            release_rx.recv().unwrap();
            drop(l);
        });
        held_rx.recv().unwrap();
        let killer = sc.spawn(move || {
            let out = s.kill_and_wait(Duration::from_secs(30));
            finished.store(true, Ordering::SeqCst);
            out
        });
        // A late killer can only make this pass vacuously, never fail it.
        std::thread::sleep(Duration::from_millis(300));
        assert!(!finished.load(Ordering::SeqCst), "kill_and_wait returned with a lease out");
        release_tx.send(()).unwrap();
        let out = killer.join().unwrap();
        assert!(matches!(out, KillOutcome::Emptied { .. }), "{out:?}");
    });
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn fake_close_waits_for_outstanding_lease() {
    // Fails if the RwLock is replaced by a bare flag.
    let (_h, s, root) = fake_session("closewait", ok_files);
    let s = &s;
    let closed = std::sync::atomic::AtomicBool::new(false);
    let closed = &closed;
    std::thread::scope(|sc| {
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        sc.spawn(move || {
            let mut c = Command::new("/bin/true");
            let l = s.place(&mut c).unwrap();
            held_tx.send(()).unwrap();
            // Released by the main thread, never by a timer: no scheduling delay can end the lease early.
            release_rx.recv().unwrap();
            drop(l);
        });
        held_rx.recv().unwrap();
        let closer = sc.spawn(move || {
            s.close();
            closed.store(true, Ordering::SeqCst);
        });
        // A late closer can only make this pass vacuously, never fail it.
        std::thread::sleep(Duration::from_millis(300));
        assert!(!closed.load(Ordering::SeqCst), "close() returned with a lease out");
        release_tx.send(()).unwrap();
        closer.join().unwrap();
        assert!(closed.load(Ordering::SeqCst));
    });
    assert_eq!(s.place(&mut Command::new("/bin/true")).err(), Some(PlaceError::Closed));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn fake_spawn_during_kill_is_refused() {
    let (_h, s, root) = fake_session("duringkill", ok_files);
    std::fs::write(s.dir().join("cgroup.events"), "populated 1\n").unwrap(); // never empties
    // Learn that the kill holds the write side from the kill itself, not from a timer.
    let (in_kill_tx, in_kill_rx) = std::sync::mpsc::channel();
    let in_kill_tx = std::sync::Mutex::new(in_kill_tx);
    *s.hook.lock().unwrap() = Some(std::sync::Arc::new(move |stage: &'static str| {
        if stage == "kill" {
            let _ = in_kill_tx.lock().unwrap().send(());
        }
    }));
    std::thread::scope(|sc| {
        let k = sc.spawn(|| s.kill_and_wait(Duration::from_millis(600)));
        in_kill_rx.recv_timeout(Duration::from_secs(30)).expect("kill never started");
        assert!(matches!(s.spawn(&mut Command::new("/bin/true")), Err(SpawnError::Stopping)));
        assert!(matches!(k.join().unwrap(), KillOutcome::NotEmptied { .. }));
    });
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn fake_events_unreadable_after_kill_is_killed_unverified() {
    let (_h, s, root) = fake_session("unverified", ok_files);
    std::fs::remove_file(s.dir().join("cgroup.events")).unwrap();
    let out = s.kill_and_wait(Duration::from_secs(1));
    assert!(matches!(out, KillOutcome::KilledUnverified(_)), "{out:?}");
    assert_eq!(std::fs::read_to_string(s.dir().join("cgroup.kill")).unwrap(), "1", "kill was written");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn fake_unreadable_procs_refuses_the_kill() {
    let (_h, s, root) = fake_session("noprocs2", ok_files);
    std::fs::remove_file(s.dir().join("cgroup.procs")).unwrap();
    let out = s.kill_and_wait(Duration::from_secs(1));
    assert!(matches!(out, KillOutcome::Refused(RefuseReason::Io(_))), "{out:?}");
    assert_eq!(std::fs::read_to_string(s.dir().join("cgroup.kill")).unwrap(), "", "nothing written");
    let _ = std::fs::remove_dir_all(root);
}

// Probe branches.

#[test]
fn fake_lock_dir_branches() {
    let (mut env, root) = fake("lockdir");
    // Not creatable (parent is a file).
    std::fs::write(root.join("afile"), "x").unwrap();
    env.lock_dir = root.join("afile/locks");
    assert!(matches!(probe_with(&env), Err(Unavailable::LockDir(_))));
    // Pre-created with group/other bits.
    let wide = root.join("wide");
    std::fs::create_dir(&wide).unwrap();
    std::fs::set_permissions(&wide, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    env.lock_dir = wide;
    let e = probe_with(&env).err().unwrap();
    assert!(matches!(&e, Unavailable::LockDir(m) if m.contains("group/other")), "{e}");
    // A symlink to a good directory.
    let good = root.join("good");
    std::fs::create_dir(&good).unwrap();
    std::fs::set_permissions(&good, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let link = root.join("link");
    std::os::unix::fs::symlink(&good, &link).unwrap();
    env.lock_dir = link;
    let e = probe_with(&env).err().unwrap();
    assert!(matches!(&e, Unavailable::LockDir(m) if m.contains("not a real directory")), "{e}");
    // Wrong owner (as seen by the checker) and the happy case.
    assert!(check_lock_dir(&good, 0xFFFF_FFF0).is_err());
    assert!(check_lock_dir(&good, unsafe { libc::geteuid() }).is_ok());
    no_leftovers(&root);
    // A lock file that is a symlink is never followed.
    let target = root.join("target");
    std::fs::write(&target, "").unwrap();
    let ll = good.join("x.lock");
    std::os::unix::fs::symlink(&target, &ll).unwrap();
    assert!(open_lock(&ll).is_err());
}

#[test]
fn fake_own_cgroup_validation() {
    let (mut env, root) = fake("ownvalid");
    env.own_cgroup = Some("/own/../own".into());
    assert!(matches!(probe_with(&env), Err(Unavailable::OwnCgroupInvalid(_))));
    env.own_cgroup = Some("/own".into());
    std::fs::write(root.join("own/cgroup.procs"), "1\n").unwrap(); // not us
    assert!(matches!(probe_with(&env), Err(Unavailable::OwnCgroupInvalid(_))));
    std::fs::remove_file(root.join("own/cgroup.procs")).unwrap();
    assert!(matches!(probe_with(&env), Err(Unavailable::OwnCgroupInvalid(_))));
}

#[test]
fn fake_statfs_error_and_cgroup_type_read_error() {
    let (mut env, root) = fake("statfs");
    env.require_cgroup2 = true;
    env.cgroup_root = root.join("does-not-exist");
    let e = probe_with(&env).err().unwrap();
    assert!(matches!(&e, Unavailable::NotCgroup2(m) if m.starts_with("statfs:")), "{e}");
    let (env, root) = fake("typeerr");
    std::fs::create_dir(root.join("own/cgroup.type")).unwrap(); // read: EISDIR
    let e = probe_with(&env).err().unwrap();
    assert!(matches!(&e, Unavailable::OwnCgroupMissing(m) if m.contains("cgroup.type")), "{e}");
}

#[test]
fn fake_round_trip_never_saw_populated() {
    let (mut env, root) = fake("neversaw");
    env.populate = Some(ok_files); // events stays "populated 0"
    let e = probe_with(&env).err().unwrap();
    assert!(matches!(&e, Unavailable::RoundTrip(m) if m.contains("never saw populated 1")), "{e}");
    no_leftovers(&root);
}

#[test]
fn fake_round_trip_spawn_place_failed() {
    let (mut env, root) = fake("placefail");
    env.populate = Some(full_procs_files);
    let e = probe_with(&env).err().unwrap();
    assert!(matches!(&e, Unavailable::RoundTrip(m) if m.contains("spawn/place failed")), "{e}");
    no_leftovers(&root);
}

fn pretend_kernel(dir: &Path) {
    // Events say populated 1; once something writes cgroup.kill they say 0,
    // but nobody sends the child a signal.
    std::fs::write(dir.join("cgroup.kill"), "").unwrap();
    std::fs::write(dir.join("cgroup.procs"), "").unwrap();
    std::fs::write(dir.join("cgroup.events"), "populated 1\n").unwrap();
    let d = dir.to_path_buf();
    std::thread::spawn(move || {
        for _ in 0..800 {
            if std::fs::read_to_string(d.join("cgroup.kill")).is_ok_and(|s| s == "1") {
                let _ = std::fs::write(d.join("cgroup.events"), "populated 0\n");
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
}

#[test]
fn fake_round_trip_child_not_killed_by_sigkill() {
    let (mut env, root) = fake("nosig");
    env.populate = Some(pretend_kernel);
    let e = probe_with(&env).err().unwrap();
    assert!(matches!(&e, Unavailable::RoundTrip(m) if m.contains("not killed by SIGKILL")), "{e}");
    no_leftovers(&root);
}

#[test]
fn fake_cached_probe_is_not_an_answer_for_a_forked_process() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let other = std::process::id().wrapping_add(1);
    assert_eq!(probe_for_pid(other).err(), Some(&Unavailable::InheritedProbe));
}

// The always-running contract test (finding 7).

/// Landing lanes (the build box) MUST export `FUIGO_TEST_REQUIRE_CGROUP=1`.
/// Then an unavailable probe fails this test (and every `real_*` test) instead
/// of printing `P189-CGROUP-SKIP` and passing.
#[test]
fn require_cgroup_contract() {
    let required = std::env::var("FUIGO_TEST_REQUIRE_CGROUP").as_deref() == Ok("1");
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let r = probe_with(&ProbeEnv::system());
    println!("P189-CGROUP-CONTRACT required={required} probe={}", r.as_ref().map(|_| "usable".to_string()).unwrap_or_else(|e| e.to_string()));
    if required {
        assert!(r.is_ok(), "FUIGO_TEST_REQUIRE_CGROUP=1 but the probe is unavailable: {:?}", r.err());
    }
}

// Real cgroup, round 2.

#[test]
fn real_nested_park_directory_is_left_in_place() {
    let Some(host) = real("nested") else { return };
    let cg = host.create_session().unwrap();
    let uuid = std::fs::read_to_string("/proc/sys/kernel/random/uuid").unwrap();
    let nested = cg.dir().join(format!("fuigo-park-{}", uuid.trim()));
    let inner = nested.join("inner");
    std::fs::create_dir(&nested).unwrap();
    std::fs::create_dir(&inner).unwrap();
    assert_eq!(cg.teardown(), TeardownOutcome::LeftPopulated);
    assert!(inner.exists() && nested.exists(), "nested Fuigo's directories must stay");
    // This test made them, so it removes them.
    std::fs::remove_dir(&inner).unwrap();
    std::fs::remove_dir(&nested).unwrap();
    assert_eq!(cg.teardown(), TeardownOutcome::Removed);
}

#[test]
fn real_respawn_after_cgroup_removed_fails_closed() {
    let Some(host) = real("respawn") else { return };
    let cg = host.create_session().unwrap();
    let mut cmd = Command::new("/bin/true");
    drop(cg.place(&mut cmd).unwrap());
    drop(cg); // removes the (empty) cgroup; the Command still owns the fd
    let err = cmd.spawn().expect_err("write into a removed cgroup must fail");
    assert_eq!(err.raw_os_error(), Some(PLACE_SENTINEL_ERRNO), "{err}");
}

// ---------------------------------------------------------------------------
// Packet C: ProcessScope wiring (tokio spawn sites go through spawn_placed)
// ---------------------------------------------------------------------------

mod scope_wiring {
    use super::*;
    use crate::ProcessScope;
    use std::sync::atomic::AtomicUsize;

    fn new_sh() -> tokio::process::Command {
        tokio::process::Command::new("/bin/sh")
    }

    fn cfg(script: &str) -> impl FnMut(&mut tokio::process::Command, &crate::PlaceHook) -> Result<(), ()> + '_ {
        move |cmd, _hook| {
            cmd.args(["-c", script]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
            Ok(())
        }
    }

    fn place_sh(scope: Option<&ProcessScope>, script: &str) -> Result<tokio::process::Child, crate::SpawnPlacedError<()>> {
        ProcessScope::spawn_placed(scope, new_sh, cfg(script))
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    #[test]
    fn unset_or_not_on_never_probes_or_creates() {
        for value in [None, Some(""), Some("off"), Some("1"), Some("ON"), Some("true")] {
            let probes = AtomicUsize::new(0);
            assert!(!decide_placement(value, || {
                probes.fetch_add(1, Ordering::SeqCst);
                true
            }));
            let created = AtomicUsize::new(0);
            let scope = ProcessScope::new_session_with(value, || {
                created.fetch_add(1, Ordering::SeqCst);
                None
            });
            assert_eq!(probes.load(Ordering::SeqCst), 0, "{value:?}");
            assert_eq!(created.load(Ordering::SeqCst), 0, "{value:?}");
            assert!(scope.session_cgroup().is_none());
        }
        assert!(decide_placement(Some("on"), || true));
        assert!(!decide_placement(Some("on"), || false));
    }

    #[test]
    fn no_cgroup_spawns_once_and_unchanged() {
        let scope = ProcessScope::new();
        let built = AtomicUsize::new(0);
        let mut child = rt().block_on(async {
            ProcessScope::spawn_placed(
                Some(&scope),
                new_sh,
                |cmd, hook| {
                    assert!(!hook.retry_may_follow());
                    built.fetch_add(1, Ordering::SeqCst);
                    cfg("exit 0")(cmd, hook)
                },
            )
            .unwrap()
        });
        assert_eq!(built.load(Ordering::SeqCst), 1);
        assert!(rt().block_on(child.wait()).unwrap().success());
        // No scope at all: same.
        let mut child = rt().block_on(async { place_sh(None, "exit 0").unwrap() });
        assert!(rt().block_on(child.wait()).unwrap().success());
    }

    #[test]
    fn fake_failed_placement_latches_breached_and_the_command_still_runs() {
        let (_h, s, root) = fake_session("scope-fullprocs", full_procs_files);
        let scope = ProcessScope::with_session_cgroup(s);
        let built = AtomicUsize::new(0);
        let marker = root.join("ran");
        let script = format!("echo ran > {}", marker.display());
        let mut child = rt().block_on(async {
            ProcessScope::spawn_placed(Some(&scope), new_sh, |cmd, hook| {
                built.fetch_add(1, Ordering::SeqCst);
                cfg(&script)(cmd, hook)
            })
            .unwrap()
        });
        assert!(rt().block_on(child.wait()).unwrap().success());
        assert_eq!(built.load(Ordering::SeqCst), 2, "placed attempt then unplaced retry");
        assert!(scope.session_cgroup().unwrap().is_breached());
        assert!(marker.exists(), "the command must still have run");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn fake_placement_writes_zero_and_does_not_breach() {
        let (_h, s, root) = fake_session("scope-ok", ok_files);
        let scope = ProcessScope::with_session_cgroup(s);
        let mut child = rt().block_on(async { place_sh(Some(&scope), "exit 0").unwrap() });
        assert!(rt().block_on(child.wait()).unwrap().success());
        let cg = scope.session_cgroup().unwrap();
        assert_eq!(std::fs::read_to_string(cg.dir().join("cgroup.procs")).unwrap(), "0");
        assert!(!cg.is_breached());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn real_placed_setsid_grandchild_in_cgroup_enrolled_child_not_and_nohup_survives_release() {
        let Some(host) = real("scope-wiring") else { return };
        let scope = ProcessScope::with_session_cgroup(host.create_session().unwrap());
        let cg_rel = |pid: u32| cgroup_of(pid);
        let dir = scope.session_cgroup().unwrap().dir().to_path_buf();
        let want = dir.strip_prefix("/sys/fs/cgroup").unwrap().to_string_lossy().to_string();
        let tmpd = tmp("scope-real");
        let (fg, gc, nh) = (tmpd.join("fg"), tmpd.join("gc"), tmpd.join("nh"));
        // placed: leader, setsid grandchild, nohup child
        let script = format!(
            "echo $$ > {fg}; setsid sh -c 'echo $$ > {gc}; sleep 60' & nohup sh -c 'echo $$ > {nh}; sleep 60' >/dev/null 2>&1 & sleep 60",
            fg = fg.display(), gc = gc.display(), nh = nh.display()
        );
        let mut child = rt().block_on(async { place_sh(Some(&scope), &script).unwrap() });
        let (fg_pid, gc_pid, nh_pid) = (wait_file_pid(&fg), wait_file_pid(&gc), wait_file_pid(&nh));
        for pid in [fg_pid, gc_pid, nh_pid] {
            assert!(cg_rel(pid).contains(&want), "{pid} not in session cgroup: {}", cg_rel(pid));
        }
        // An enrolled-but-unplaced child (the MCP/LSP path: ProcessScope::spawn) is not.
        let mut other = tokio::process::Command::new("/bin/sh");
        // : dash forks for a lone , so killing the shell
        // would orphan the sleep (it outlived the whole test run).
        other.args(["-c", "exec sleep 60"]).stdin(Stdio::null());
        let (mut other_child, _group) = rt().block_on(async { scope.spawn(other).unwrap() });
        let other_pid = other_child.id().unwrap();
        assert!(!cg_rel(other_pid).contains(&want), "unplaced child landed in the session cgroup");
        // Release while populated: nothing is killed and the directory stays.
        scope.release_session_cgroup();
        assert!(dir.exists(), "populated directory must stay");
        assert!(alive(nh_pid) && alive(gc_pid), "release must never kill");
        // Cleanup: this test created the cgroup, so it may kill it.
        std::fs::write(dir.join("cgroup.kill"), "1").unwrap();
        assert!(pids_gone(&[fg_pid, gc_pid, nh_pid]));
        let _ = child.start_kill();
        let _ = other_child.start_kill();
        let _ = rt().block_on(child.wait());
        let _ = rt().block_on(other_child.wait());
        // The killed grandchildren are reparented and reaped by init, not by us; a zombie still
        // populates the cgroup (rmdir would be EBUSY), so wait for the kernel to say it is empty.
        let t = Instant::now();
        while !std::fs::read_to_string(dir.join("cgroup.events")).is_ok_and(|e| e.contains("populated 0"))
            && t.elapsed() < Duration::from_secs(30)
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        scope.release_session_cgroup();
        assert!(!dir.exists(), "an empty directory is removed");
        let _ = std::fs::remove_dir_all(tmpd);
    }

    #[test]
    fn real_two_sessions_two_cgroups() {
        let Some(host) = real("scope-two") else { return };
        let a = ProcessScope::with_session_cgroup(host.create_session().unwrap());
        let b = ProcessScope::with_session_cgroup(host.create_session().unwrap());
        assert_ne!(a.session_cgroup().unwrap().dir(), b.session_cgroup().unwrap().dir());
        // A scope clone (what a subagent holds) shares the root's cgroup.
        assert_eq!(a.clone().session_cgroup().unwrap().dir(), a.session_cgroup().unwrap().dir());
    }

    // ---- Round 2 -------------------------------------------------------

    #[test]
    fn closed_gate_runs_unplaced_and_latches_breached() {
        let (_h, s, root) = fake_session("scope-closed", ok_files);
        let scope = ProcessScope::with_session_cgroup(s);
        let cg = scope.session_cgroup().unwrap();
        cg.close();
        assert!(!cg.is_breached());
        let marker = root.join("ran-closed");
        let script = format!("echo ran > {}", marker.display());
        let mut child = rt().block_on(async { place_sh(Some(&scope), &script).unwrap() });
        assert!(rt().block_on(child.wait()).unwrap().success());
        assert!(marker.exists(), "a closed gate must not stop the command");
        assert!(cg.is_breached(), "an unplaced start must latch breached");
        assert_eq!(std::fs::read_to_string(cg.dir().join("cgroup.procs")).unwrap(), "", "it was not placed");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn write_locked_gate_refuses_the_spawn_and_nothing_runs() {
        let (_h, s, root) = fake_session("scope-wlocked", ok_files);
        let scope = ProcessScope::with_session_cgroup(s);
        let cg = scope.session_cgroup().unwrap();
        // kill_and_wait holds the write side; emulate that with a raw write guard.
        let guard = cg.gate.write().unwrap();
        let marker = root.join("ran-wlocked");
        let script = format!("echo ran > {}", marker.display());
        assert!(matches!(place_sh(Some(&scope), &script), Err(crate::SpawnPlacedError::Stopping)));
        drop(guard);
        assert!(!marker.exists(), "nothing may start while the write side is held");
        assert!(!cg.is_breached());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stopping_gate_refuses_the_spawn_and_nothing_runs() {
        let (_h, s, root) = fake_session("scope-stopping", ok_files);
        let scope = ProcessScope::with_session_cgroup(s);
        let cg = scope.session_cgroup().unwrap();
        cg.begin_stop();
        let marker = root.join("ran-stopping");
        let script = format!("echo ran > {}", marker.display());
        let built = AtomicUsize::new(0);
        let r = ProcessScope::spawn_placed(Some(&scope), new_sh, |cmd, hook| {
            built.fetch_add(1, Ordering::SeqCst);
            cfg(&script)(cmd, hook)
        });
        assert!(matches!(r, Err(crate::SpawnPlacedError::Stopping)));
        assert_eq!(built.load(Ordering::SeqCst), 0, "configure must not even run");
        assert!(!marker.exists(), "nothing may run during a stop");
        assert!(!cg.is_breached(), "a refused spawn escaped nothing");
        assert!(matches!(cg.spawn(&mut Command::new("/bin/true")), Err(SpawnError::Stopping)));
        // close() does not downgrade Stopping; reopen() opens the gate again.
        cg.close();
        assert!(matches!(place_sh(Some(&scope), &script), Err(crate::SpawnPlacedError::Stopping)));
        cg.reopen();
        let mut child = rt().block_on(async { place_sh(Some(&scope), &script).unwrap() });
        assert!(rt().block_on(child.wait()).unwrap().success());
        assert!(marker.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn failed_configure_on_the_placed_attempt_falls_back_to_the_base_spawn() {
        // e.g. an fd mapping that cannot be duplicated: the command must still run unplaced.
        let (_h, s, root) = fake_session("scope-cfgfail", ok_files);
        let scope = ProcessScope::with_session_cgroup(s);
        let cg = scope.session_cgroup().unwrap();
        let marker = root.join("ran-cfg");
        let script = format!("echo ran > {}", marker.display());
        let calls = AtomicUsize::new(0);
        let mut child = rt().block_on(async {
            ProcessScope::spawn_placed(Some(&scope), new_sh, |cmd, hook| {
                calls.fetch_add(1, Ordering::SeqCst);
                if hook.retry_may_follow() {
                    return Err(());
                }
                cfg(&script)(cmd, hook)
            })
            .unwrap()
        });
        assert!(rt().block_on(child.wait()).unwrap().success());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(marker.exists());
        assert!(cg.is_breached());
        // A configure that fails on the unplaced attempt too is a Build error.
        let r = ProcessScope::spawn_placed(Some(&scope), new_sh, |_c, _h| Err::<(), _>(7));
        assert!(matches!(r, Err(crate::SpawnPlacedError::Build(7))));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn std_command_entry_places_and_falls_back() {
        let (_h, s, root) = fake_session("scope-std-ok", ok_files);
        let scope = ProcessScope::with_session_cgroup(s);
        let mut c = ProcessScope::spawn_placed_std(Some(&scope), || Command::new("/bin/true"), |_c, _h| Ok::<(), ()>(())).unwrap();
        assert!(c.wait().unwrap().success());
        let cg = scope.session_cgroup().unwrap();
        assert_eq!(std::fs::read_to_string(cg.dir().join("cgroup.procs")).unwrap(), "0");
        assert!(!cg.is_breached());
        let _ = std::fs::remove_dir_all(root);

        let (_h, s, root) = fake_session("scope-std-full", full_procs_files);
        let scope = ProcessScope::with_session_cgroup(s);
        let mut c = ProcessScope::spawn_placed_std(Some(&scope), || Command::new("/bin/true"), |_c, _h| Ok::<(), ()>(())).unwrap();
        assert!(c.wait().unwrap().success());
        assert!(scope.session_cgroup().unwrap().is_breached());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn placement_is_the_first_pre_exec_even_if_configure_registers_one() {
        // configure registers its own pre_exec that must run AFTER the placement
        // write: it reads cgroup.procs (the fake file) and records what it saw.
        let (_h, s, root) = fake_session("scope-order", ok_files);
        let scope = ProcessScope::with_session_cgroup(s);
        let procs = scope.session_cgroup().unwrap().dir().join("cgroup.procs");
        let seen = root.join("seen");
        let (procs_c, seen_c) = (procs.clone(), seen.clone());
        let mut child = rt().block_on(async {
            ProcessScope::spawn_placed(Some(&scope), new_sh, move |cmd, hook| {
                use std::os::unix::process::CommandExt as _;
                let p = std::ffi::CString::new(procs_c.to_str().unwrap()).unwrap();
                let o = std::ffi::CString::new(seen_c.to_str().unwrap()).unwrap();
                // Allocation-free (open/read/write on stack buffers), like any pre_exec.
                unsafe {
                    cmd.as_std_mut().pre_exec(move || {
                        let mut buf = [0u8; 8];
                        let fd = libc::open(p.as_ptr(), libc::O_RDONLY);
                        let n = if fd >= 0 { libc::read(fd, buf.as_mut_ptr().cast(), 8) } else { -1 };
                        if fd >= 0 {
                            libc::close(fd);
                        }
                        let ofd = libc::open(o.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644);
                        if ofd >= 0 {
                            if n > 0 {
                                libc::write(ofd, buf.as_ptr().cast(), n as usize);
                            }
                            libc::close(ofd);
                        }
                        Ok(())
                    });
                }
                cfg("exit 0")(cmd, hook)
            })
            .unwrap()
        });
        assert!(rt().block_on(child.wait()).unwrap().success());
        assert_eq!(std::fs::read_to_string(&seen).unwrap(), "0", "the placement write ran before the caller's pre_exec");
        let _ = std::fs::remove_dir_all(root);
    }

    // ---- Round 3: the placement-gate race -------------------------------------

    type Pause = (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>);

    /// Pause `stage` inside the entry (lease or write side held): returns the
    /// receiver that fires when a thread is parked there and the sender that releases it.
    fn pause_at(cg: &SessionCgroup, at: &'static str) -> Pause {
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let (reached_tx, go_rx) = (std::sync::Mutex::new(reached_tx), std::sync::Mutex::new(go_rx));
        *cg.hook.lock().unwrap() = Some(Arc::new(move |stage: &'static str| {
            if stage == at {
                let _ = reached_tx.lock().unwrap().send(());
                let _ = go_rx.lock().unwrap().recv();
            }
        }));
        (reached_rx, go_tx)
    }

    use std::sync::Arc;

    /// An unplaced start parked inside the entry with its lease held: a
    /// concurrent kill must not return until the start finished, and then must
    /// refuse (breached), never report Emptied.
    fn kill_waits_for_parked_unplaced_spawn(tag: &str, populate: fn(&Path), at: &'static str, close_first: bool) {
        let (_h, s, root) = fake_session(tag, populate);
        let scope = ProcessScope::with_session_cgroup(s);
        let cg = scope.session_cgroup().unwrap();
        if close_first {
            cg.close();
        }
        let (reached, go) = pause_at(cg, at);
        let marker = root.join("ran-parked");
        let script = format!("echo ran > {}", marker.display());
        std::thread::scope(|sc| {
            let sp = sc.spawn(|| {
                let mut c = ProcessScope::spawn_placed_std(
                    Some(&scope),
                    || Command::new("/bin/sh"),
                    |cmd, _h| {
                        cmd.args(["-c", &script]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
                        Ok::<(), ()>(())
                    },
                )
                .unwrap();
                c.wait().unwrap().success()
            });
            reached.recv_timeout(Duration::from_secs(10)).expect("spawn never reached the pause point");
            assert!(cg.is_breached(), "the latch is set under the lease, before the unplaced start");
            let k = sc.spawn(|| cg.kill_and_wait(Duration::from_secs(5)));
            std::thread::sleep(Duration::from_millis(300));
            assert!(!k.is_finished(), "kill_and_wait returned while an unplaced spawn was in flight");
            go.send(()).unwrap();
            assert!(sp.join().unwrap());
            assert_eq!(k.join().unwrap(), KillOutcome::Refused(RefuseReason::Breached));
        });
        assert!(marker.exists(), "the unplaced command still ran");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn kill_waits_for_a_parked_unplaced_spawn_at_session_end() {
        kill_waits_for_parked_unplaced_spawn("race-closed", ok_files, "unplaced", true);
    }

    #[test]
    fn kill_waits_for_a_parked_unplaced_fallback_after_a_failed_placement_write() {
        kill_waits_for_parked_unplaced_spawn("race-fallback", full_procs_files, "fallback", false);
    }

    #[test]
    fn spawn_while_kill_holds_the_write_side_is_refused_and_after_it_until_reopen() {
        let (_h, s, root) = fake_session("race-kill-held", ok_files);
        let scope = ProcessScope::with_session_cgroup(s);
        let cg = scope.session_cgroup().unwrap();
        let (reached, go) = pause_at(cg, "kill");
        let marker = root.join("ran-during-kill");
        let script = format!("echo ran > {}", marker.display());
        let mk = |scope: &ProcessScope| {
            let script = script.clone();
            ProcessScope::spawn_placed_std(
                Some(scope),
                || Command::new("/bin/sh"),
                move |cmd, _h| {
                    cmd.args(["-c", &script]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
                    Ok::<(), ()>(())
                },
            )
        };
        std::thread::scope(|sc| {
            let k = sc.spawn(|| cg.kill_and_wait(Duration::from_secs(5)));
            reached.recv_timeout(Duration::from_secs(10)).expect("kill never reached the pause point");
            assert!(matches!(mk(&scope), Err(crate::SpawnPlacedError::Stopping)));
            assert!(matches!(rt().block_on(async { place_sh(Some(&scope), &script) }), Err(crate::SpawnPlacedError::Stopping)));
            go.send(()).unwrap();
            assert!(matches!(k.join().unwrap(), KillOutcome::Emptied { .. }));
        });
        assert!(!marker.exists(), "nothing may start during a stop");
        assert!(!cg.is_breached());
        // After the kill returned: still refused until reopen().
        assert!(matches!(mk(&scope), Err(crate::SpawnPlacedError::Stopping)));
        assert!(!marker.exists());
        cg.reopen();
        assert!(mk(&scope).unwrap().wait().unwrap().success());
        assert!(marker.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reopen_never_clears_breached_so_a_later_stop_still_reports_incomplete() {
        let (_h, s, root) = fake_session("race-reopen", ok_files);
        let scope = ProcessScope::with_session_cgroup(s);
        let cg = scope.session_cgroup().unwrap();
        cg.close();
        let mut c0 = rt().block_on(async { place_sh(Some(&scope), "exit 0").unwrap() });
        assert!(rt().block_on(c0.wait()).unwrap().success());
        assert!(cg.is_breached());
        assert_eq!(cg.kill_and_wait(Duration::from_secs(1)), KillOutcome::Refused(RefuseReason::Breached));
        cg.reopen();
        assert!(cg.is_breached(), "reopen() must not clear the latch");
        let mut c = rt().block_on(async { place_sh(Some(&scope), "exit 0").unwrap() });
        assert!(rt().block_on(c.wait()).unwrap().success());
        assert_eq!(cg.kill_and_wait(Duration::from_secs(1)), KillOutcome::Refused(RefuseReason::Breached));
        let _ = std::fs::remove_dir_all(root);
    }
}
