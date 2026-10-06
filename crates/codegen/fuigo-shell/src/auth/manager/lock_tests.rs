use super::*;
use tempfile::TempDir;

fn auth_json_path(dir: &TempDir) -> std::path::PathBuf {
    dir.path().join("auth.json")
}

#[cfg(unix)]
fn inode_of(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).expect("lock file must exist").ino()
}

#[test]
fn parse_holder_info_accepts_pid_ts_and_rejects_garbage() {
    assert_eq!(
        parse_holder_info("12345:1700000000"),
        Some((12345, 1700000000))
    );
    assert_eq!(
        parse_holder_info("  12345:1700000000  "),
        Some((12345, 1700000000))
    );
    assert!(parse_holder_info("").is_none());
    assert!(parse_holder_info("no-colon").is_none());
    assert!(parse_holder_info("abc:123").is_none());
    assert!(parse_holder_info("123:abc").is_none());
}

#[test]
fn unparseable_holder_classifies_alive_when_fresh_and_stuck_when_old() {
    let dir = TempDir::new().unwrap();
    let lock_path = dir.path().join("test.lock");
    std::fs::write(&lock_path, b"").unwrap();

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();

    assert_eq!(
        read_holder(&mut file).state,
        HolderState::Alive,
        "fresh empty lock must be assumed alive"
    );

    let old = filetime::FileTime::from_unix_time(
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64)
            - (STALE_LOCK_TIMEOUT_SECS as i64 + 30),
        /*nanos*/ 0,
    );
    filetime::set_file_mtime(&lock_path, old).unwrap();

    let holder = read_holder(&mut file);
    assert_eq!(
        (holder.state, holder.pid),
        (HolderState::StuckLive, None),
        "empty lock older than the stale threshold must classify stale, with no pid"
    );
}

#[test]
fn nonblocking_acquire_writes_holder_info() {
    let dir = TempDir::new().unwrap();
    let path = auth_json_path(&dir);
    let lock_path = path.with_file_name("auth.json.lock");

    let _lock = try_lock_auth_file_nonblocking(&path).expect("uncontended non-blocking acquire");

    let content = std::fs::read_to_string(&lock_path).unwrap();
    let (pid, _ts) =
        parse_holder_info(&content).expect("non-blocking acquire must write parseable info");
    assert_eq!(pid, std::process::id());
}

#[test]
fn nonblocking_acquire_returns_none_while_held() {
    let dir = TempDir::new().unwrap();
    let path = auth_json_path(&dir);

    let _lock1 = try_lock_auth_file_nonblocking(&path).expect("first acquire");
    let lock2 = try_lock_auth_file_nonblocking(&path);
    assert!(lock2.is_none(), "must return None when the lock is held");
}

#[cfg(unix)]
#[test]
fn is_process_alive_accepts_own_pid_and_rejects_invalid_pids() {
    assert!(is_process_alive(std::process::id()));
    assert!(!is_process_alive(0));
    assert!(!is_process_alive(u32::MAX));
    assert!(!is_process_alive(i32::MAX as u32));
}

#[cfg(unix)]
#[test]
fn dead_holder_pid_classifies_dead() {
    let dir = TempDir::new().unwrap();
    let lock_path = dir.path().join("test.lock");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)
        .unwrap();

    let dead_pid: u32 = i32::MAX as u32;
    write!(file, "{dead_pid}:9999999999").unwrap();
    file.sync_all().unwrap();

    assert_eq!(
        read_holder(&mut file),
        LockHolder {
            state: HolderState::Dead,
            pid: Some(dead_pid),
            age_secs: Some(0),
        },
        "dead recorded PID classifies Dead (telemetry only), naming the pid"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn stuck_live_holder_is_never_broken() {
    let dir = TempDir::new().unwrap();
    let path = auth_json_path(&dir);
    let lock_path = path.with_file_name("auth.json.lock");

    let _holder = super::test_support::hold_backdated_stale_lock(&lock_path);
    let inode_before = inode_of(&lock_path);

    assert!(
        matches!(try_acquire_once(&lock_path), LockAttempt::Busy),
        "live-but-stale holder must classify Busy"
    );
    assert_eq!(
        inode_of(&lock_path),
        inode_before,
        "instant attempt must not touch the lock file"
    );

    let got = try_lock_auth_file_async(&path, StdDuration::from_millis(300), Heartbeat::Skip).await;
    let LockAcquire::TimedOut { holder } = got else {
        panic!("waiter must time out rather than break a live-but-stale holder");
    };
    let holder = holder.expect("deadline snapshot must read the holder");
    assert_eq!(
        (holder.state, holder.pid),
        (HolderState::StuckLive, Some(std::process::id())),
        "timeout snapshot must classify and name the live-but-stale holder"
    );
    assert!(
        holder
            .age_secs
            .is_some_and(|age| age > STALE_LOCK_TIMEOUT_SECS),
        "timeout snapshot must carry the holder age, got {:?}",
        holder.age_secs
    );
    assert_eq!(
        inode_of(&lock_path),
        inode_before,
        "a timed-out waiter must leave the live inode in place"
    );
}

#[cfg(unix)]
#[test]
fn heartbeat_refreshes_holder_info() {
    let dir = TempDir::new().unwrap();
    let lock_path = dir.path().join("auth.json.lock");
    let mut file = super::test_support::hold_backdated_stale_lock(&lock_path);
    assert_eq!(read_holder(&mut file).state, HolderState::StuckLive);

    let hb = LockHeartbeat::spawn(file.try_clone().unwrap(), StdDuration::from_millis(20));

    let deadline = std::time::Instant::now() + StdDuration::from_secs(5);
    loop {
        if read_holder(&mut file).state == HolderState::Alive {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "heartbeat never re-dated the holder info"
        );
        std::thread::sleep(StdDuration::from_millis(10));
    }
    drop(hb);
}

#[cfg(unix)]
#[test]
fn inodes_do_not_match_after_unlink_and_recreate() {
    let dir = TempDir::new().unwrap();
    let lock_path = dir.path().join("test.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)
        .unwrap();

    std::fs::remove_file(&lock_path).unwrap();
    let _new_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)
        .unwrap();

    assert!(!inodes_match(&file, &lock_path).unwrap());
}

#[cfg(unix)]
#[test]
fn held_guard_reports_not_live_after_out_of_band_unlink_and_recreate() {
    let dir = TempDir::new().unwrap();
    let path = auth_json_path(&dir);

    let lock = try_lock_auth_file_nonblocking(&path).expect("acquire");
    assert!(lock.still_live(&path), "freshly acquired lock must be live");

    let lock_path = path.with_file_name("auth.json.lock");
    std::fs::remove_file(&lock_path).unwrap();
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();

    assert!(
        !lock.still_live(&path),
        "after unlink+recreate the held guard must report not-live"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn total_wait_stays_within_timeout_budget() {
    let dir = TempDir::new().unwrap();
    let path = auth_json_path(&dir);
    let _holder =
        super::test_support::hold_backdated_stale_lock(&path.with_file_name("auth.json.lock"));

    let timeout = StdDuration::from_millis(900);
    let start = tokio::time::Instant::now();
    let lock = try_lock_auth_file_async(&path, timeout, Heartbeat::Skip).await;
    let elapsed = start.elapsed();
    assert!(
        lock.into_guard().is_none(),
        "a live-but-stale holder is never broken; the waiter must time out"
    );
    assert!(
        elapsed < timeout + StdDuration::from_secs(1),
        "total wait must stay within the caller's budget, took {elapsed:?}"
    );
}

#[tokio::test]
async fn acquire_release_and_reacquire_succeed() {
    let dir = TempDir::new().unwrap();
    let path = auth_json_path(&dir);

    let lock = try_lock_auth_file_async(&path, StdDuration::from_secs(1), Heartbeat::Skip)
        .await
        .into_guard();
    assert!(lock.is_some(), "should acquire lock");

    let lock_path = path.with_file_name("auth.json.lock");
    let content = std::fs::read_to_string(&lock_path).unwrap();
    let (pid, _ts) = parse_holder_info(&content).unwrap();
    assert_eq!(pid, std::process::id());

    drop(lock);

    let lock2 = try_lock_auth_file_async(&path, StdDuration::from_secs(1), Heartbeat::Skip)
        .await
        .into_guard();
    assert!(lock2.is_some(), "should re-acquire after release");
}

#[cfg(unix)]
#[tokio::test]
async fn acquire_succeeds_over_leftover_lock_file_of_dead_process() {
    let dir = TempDir::new().unwrap();
    let path = auth_json_path(&dir);
    let lock_path = path.with_file_name("auth.json.lock");

    let dead_pid: u32 = i32::MAX as u32;
    std::fs::write(&lock_path, format!("{dead_pid}:9999999999")).unwrap();

    let lock = try_lock_auth_file_async(&path, StdDuration::from_secs(1), Heartbeat::Skip)
        .await
        .into_guard();
    assert!(lock.is_some(), "should acquire over leftover dead-PID file");

    let content = std::fs::read_to_string(&lock_path).unwrap();
    let (pid, _ts) = parse_holder_info(&content).unwrap();
    assert_eq!(pid, std::process::id());
}

/// Line printed to stdout once the subprocess holds the flock.
#[cfg(unix)]
const LOCK_HOLDER_READY: &str = "__FUIGO_LOCK_HOLDER_READY__";

/// Inert unless `FUIGO_TEST_LOCK_HOLDER` holds `"<lock_path>|<pid|dead_pid|empty>|<age_secs>"`:
/// flocks with backdated info (or a dead recorded PID, or an empty file), prints ready, then blocks on stdin.
#[cfg(unix)]
#[test]
#[ignore = "spawned as a subprocess by the cross-process lock tests"]
fn subprocess_lock_holder() {
    let Ok(spec) = std::env::var("FUIGO_TEST_LOCK_HOLDER") else {
        return;
    };
    let mut parts = spec.splitn(3, '|');
    let lock_path = parts.next().expect("spec lock_path");
    let mode = parts.next().expect("spec mode");
    let age_secs: u64 = parts.next().expect("spec age").parse().expect("age parse");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .expect("open lock file");
    file.lock_exclusive().expect("flock");

    match mode {
        "dead_pid" => {
            file.set_len(0).unwrap();
            file.seek(io::SeekFrom::Start(0)).unwrap();
            write!(file, "{}:{}", i32::MAX as u32, now - age_secs).unwrap();
            file.sync_all().unwrap();
        }
        "pid" => {
            file.set_len(0).unwrap();
            file.seek(io::SeekFrom::Start(0)).unwrap();
            write!(file, "{}:{}", std::process::id(), now - age_secs).unwrap();
            file.sync_all().unwrap();
        }
        "empty" => {
            file.set_len(0).unwrap();
            file.sync_all().unwrap();
            if age_secs > 0 {
                let old =
                    filetime::FileTime::from_unix_time((now - age_secs) as i64, /*nanos*/ 0);
                filetime::set_file_mtime(lock_path, old).unwrap();
            }
        }
        other => panic!("unknown lock-holder mode: {other:?}"),
    }

    println!("{LOCK_HOLDER_READY}");
    io::stdout().flush().unwrap();

    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
}

/// Re-executes this test binary as a lock holder; returns once it holds the flock.
#[cfg(unix)]
fn spawn_lock_holder_subprocess(
    lock_path: &std::path::Path,
    mode: &str,
    age_secs: u64,
) -> std::process::Child {
    use std::io::BufRead;

    let exe = std::env::current_exe().expect("current_exe");
    let spec = format!("{}|{mode}|{age_secs}", lock_path.to_str().unwrap());
    #[allow(clippy::disallowed_methods)] // test fixture; the test kills it
    let mut child = std::process::Command::new(exe)
        .env("FUIGO_TEST_LOCK_HOLDER", spec)
        .args([
            "--ignored",
            "--exact",
            "--nocapture",
            "auth::manager::lock::tests::subprocess_lock_holder",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn lock-holder subprocess");

    {
        let stdout = child.stdout.as_mut().expect("child stdout");
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line).expect("read child stdout");
            assert!(n > 0, "child exited before signaling ready");
            if line.trim() == LOCK_HOLDER_READY {
                break;
            }
        }
    }
    child
}

#[cfg(unix)]
#[tokio::test]
async fn unopenable_lock_path_fails_fast_without_burning_the_budget() {
    let dir = TempDir::new().unwrap();
    let path = auth_json_path(&dir);
    std::fs::create_dir(path.with_file_name("auth.json.lock")).unwrap();

    let started = tokio::time::Instant::now();
    let got = try_lock_auth_file_async(&path, StdDuration::from_secs(5), Heartbeat::Skip).await;

    let LockAcquire::Failed { .. } = got else {
        panic!("a directory at the lock path must fail the acquire, not time it out");
    };
    assert!(
        started.elapsed() < StdDuration::from_millis(500),
        "an unopenable lock path must fail fast, took {:?}",
        started.elapsed()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn dead_recorded_pid_with_live_flock_is_never_broken() {
    let dir = TempDir::new().unwrap();
    let path = auth_json_path(&dir);
    let lock_path = path.with_file_name("auth.json.lock");

    let mut child = spawn_lock_holder_subprocess(&lock_path, "dead_pid", /*age_secs*/ 0);
    let inode_before = inode_of(&lock_path);

    let got = try_lock_auth_file_async(&path, StdDuration::from_millis(500), Heartbeat::Skip).await;
    let LockAcquire::TimedOut { holder } = got else {
        panic!("a live flock must never be broken, even with a dead recorded PID");
    };
    assert_eq!(
        holder.map(|h| (h.state, h.pid)),
        Some((HolderState::Dead, Some(i32::MAX as u32))),
        "the snapshot must classify the dead recorded PID (telemetry only)"
    );
    assert_eq!(
        inode_of(&lock_path),
        inode_before,
        "the lock file must not be unlinked"
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
#[test]
fn dropping_the_guard_silences_the_heartbeat_before_anyone_else_can_hold_the_lock() {
    let dir = TempDir::new().unwrap();
    let lock_path = dir.path().join("auth.json.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)
        .unwrap();
    file.try_lock_exclusive().unwrap();
    let heartbeat = LockHeartbeat::spawn(file.try_clone().unwrap(), StdDuration::from_millis(1));
    drop(AuthFileLock {
        heartbeat: Some(heartbeat),
        file,
    });

    let mut second = lock_once_released(&lock_path, RELEASE_DEADLINE);
    second.set_len(0).unwrap();
    write!(second, "sentinel").unwrap();
    second.sync_all().unwrap();
    std::thread::sleep(StdDuration::from_millis(30));
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        "sentinel",
        "a heartbeat surviving the guard drop would stamp the re-acquired lock"
    );
}

/// A guard that was dropped must release its lock; how long another thread waits for that.
/// A release that never comes fails with a named diagnosis rather than blocking forever.
#[cfg(unix)]
const RELEASE_DEADLINE: StdDuration = StdDuration::from_secs(10);

/// Take the exclusive lock on `path` once every holder of its open file description is gone.
///
/// Not a retry loop and not a wider timeout: `flock` locks belong to the open file
/// *description*, and any concurrent `fork` in this test process (every test that spawns a
/// subprocess) hands the child a copy of every open descriptor until its `exec`. So for that
/// window a lock whose guard was dropped is still held, and a non-blocking `try_lock_exclusive`
/// fails with `WouldBlock` although nothing is wrong (see
/// `a_forked_child_transiently_keeps_a_dropped_lock_held`). A blocking acquire waits for exactly
/// that copy to close, and still fails, loudly, if the guard's own release is the bug.
#[cfg(unix)]
fn lock_once_released(path: &Path, deadline: StdDuration) -> File {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("lock-once-released".into())
        .spawn(move || {
            let acquired = file.lock_exclusive().map(|()| file);
            let _ = tx.send(acquired);
        })
        .unwrap();
    match rx.recv_timeout(deadline) {
        Ok(Ok(file)) => file,
        Ok(Err(e)) => panic!("blocking exclusive lock on {} failed: {e}", path.display()),
        Err(_) => panic!(
            "the lock on {} was still held {deadline:?} after its guard was dropped: the guard \
             did not release it (a concurrent fork's transient descriptor copy lasts \
             microseconds, not seconds)",
            path.display()
        ),
    }
}

/// A child parked between `fork` and `exec`, holding a copy of every descriptor this process has
/// open: what any concurrent `Command::spawn` is for a few microseconds. `pre_exec` runs in
/// exactly that window. No timing is involved: the child announces it is parked over one pipe
/// and stays parked until told to go over another. `Command::spawn` only returns once the child
/// has exec'd, so it runs on its own thread.
#[cfg(unix)]
struct ParkedForkChild {
    release: libc::c_int,
    spawned: std::thread::JoinHandle<std::process::Child>,
}

#[cfg(unix)]
impl ParkedForkChild {
    /// Returns once the child is parked in the fork-to-exec window.
    fn park() -> Self {
        use std::os::unix::process::CommandExt;
        fn pipe() -> (libc::c_int, libc::c_int) {
            let mut fds = [0 as libc::c_int; 2];
            // SAFETY: `fds` is a valid two-element buffer.
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            (fds[0], fds[1])
        }
        let (ready_rx, ready_tx) = pipe();
        let (go_rx, go_tx) = pipe();
        let spawned = std::thread::spawn(move || {
            let mut command = std::process::Command::new("true");
            // SAFETY: the closure only calls `write` and `read`, which are async-signal-safe.
            unsafe {
                command.pre_exec(move || {
                    let byte = 1u8;
                    libc::write(ready_tx, (&raw const byte).cast(), 1);
                    let mut go = 0u8;
                    libc::read(go_rx, (&raw mut go).cast(), 1);
                    Ok(())
                });
            }
            #[allow(clippy::disallowed_methods)] // test fixture; reaped by `let_go_and_reap`
            let child = command.spawn().unwrap();
            // SAFETY: these are this thread's own pipe ends, closed exactly once.
            unsafe {
                libc::close(ready_tx);
                libc::close(go_rx);
            }
            child
        });
        let mut byte = 0u8;
        // SAFETY: valid one-byte buffer; blocks until the child is parked.
        assert_eq!(
            unsafe { libc::read(ready_rx, (&raw mut byte).cast(), 1) },
            1
        );
        // SAFETY: closed exactly once.
        unsafe { libc::close(ready_rx) };
        Self {
            release: go_tx,
            spawned,
        }
    }

    /// Let the child exec (closing its descriptor copies) and reap it.
    fn let_go_and_reap(self) {
        let byte = 1u8;
        // SAFETY: a valid one-byte buffer, then the pipe end is closed exactly once.
        unsafe {
            libc::write(self.release, (&raw const byte).cast(), 1);
            libc::close(self.release);
        }
        let mut child = self.spawned.join().unwrap();
        assert!(child.wait().unwrap().success());
    }
}

#[cfg(unix)]
#[test]
fn a_forked_child_transiently_keeps_a_dropped_lock_held() {
    let dir = TempDir::new().unwrap();
    let lock_path = dir.path().join("auth.json.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)
        .unwrap();
    file.try_lock_exclusive().unwrap();

    let child = ParkedForkChild::park();
    drop(file);

    // The guard is gone, yet the lock is held by the parked child's inherited copy: this is the
    // spurious WouldBlock that made the dropped-guard test fail once per few full runs.
    let probe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    let err = probe
        .try_lock_exclusive()
        .expect_err("the forked child's descriptor copy must still hold the lock");
    assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    drop(probe);

    // Once the child execs its copy closes, and the blocking acquire gets the lock.
    child.let_go_and_reap();
    drop(lock_once_released(&lock_path, RELEASE_DEADLINE));
}

#[cfg(unix)]
#[tokio::test]
async fn wedged_live_holder_in_other_process_is_never_broken() {
    let dir = TempDir::new().unwrap();
    let path = auth_json_path(&dir);
    let lock_path = path.with_file_name("auth.json.lock");

    let mut child = spawn_lock_holder_subprocess(&lock_path, "pid", /*age_secs*/ 120);
    let child_pid = child.id();

    assert!(is_process_alive(child_pid));
    let inode_before = inode_of(&lock_path);

    let LockAcquire::TimedOut { holder } =
        try_lock_auth_file_async(&path, StdDuration::from_millis(500), Heartbeat::Skip).await
    else {
        panic!("a live-but-stale holder must never be broken");
    };
    assert_eq!(
        holder.map(|h| (h.state, h.pid)),
        Some((HolderState::StuckLive, Some(child_pid))),
        "timeout snapshot must name the wedged holder"
    );
    assert_eq!(
        inode_of(&lock_path),
        inode_before,
        "the failed acquire must leave the live inode in place"
    );

    child.kill().unwrap();
    child.wait().unwrap();
    let lock = try_lock_auth_file_async(&path, StdDuration::from_secs(2), Heartbeat::Skip)
        .await
        .into_guard();
    assert!(lock.is_some(), "flock must be free once the holder dies");
    assert_eq!(
        inode_of(&lock_path),
        inode_before,
        "recovery-by-death must reuse the live inode"
    );
    let content = std::fs::read_to_string(&lock_path).unwrap();
    let (pid, _) = parse_holder_info(&content).unwrap();
    assert_eq!(pid, std::process::id());
}

#[cfg(unix)]
#[tokio::test]
async fn old_empty_lock_held_by_live_process_is_never_broken() {
    let dir = TempDir::new().unwrap();
    let path = auth_json_path(&dir);
    let lock_path = path.with_file_name("auth.json.lock");

    let mut child = spawn_lock_holder_subprocess(&lock_path, "empty", STALE_LOCK_TIMEOUT_SECS + 30);
    assert!(is_process_alive(child.id()));

    let lock = try_lock_auth_file_async(&path, StdDuration::from_millis(500), Heartbeat::Skip)
        .await
        .into_guard();
    assert!(
        lock.is_none(),
        "an old empty lock held by a live holder must not be broken"
    );
    assert!(lock_path.exists(), "lock file must not be unlinked");

    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
#[tokio::test]
async fn waiter_survives_sibling_recovery_on_live_inode() {
    let dir = TempDir::new().unwrap();
    let path = auth_json_path(&dir);
    let lock_path = path.with_file_name("auth.json.lock");

    let mut child = spawn_lock_holder_subprocess(&lock_path, "pid", /*age_secs*/ 120);
    let inode_before = inode_of(&lock_path);

    let waiter_path = path.clone();
    let waiter = tokio::spawn(async move {
        try_lock_auth_file_async(&waiter_path, StdDuration::from_secs(10), Heartbeat::Skip)
            .await
            .into_guard()
    });
    tokio::time::sleep(StdDuration::from_millis(300)).await;

    let recovery =
        try_lock_auth_file_async(&path, StdDuration::from_secs(1), Heartbeat::Skip).await;
    assert!(
        recovery.into_guard().is_none(),
        "recovery must not steal the lock from a live holder"
    );
    assert_eq!(
        inode_of(&lock_path),
        inode_before,
        "recovery must never unlink/recreate the lock file"
    );

    let released_at = tokio::time::Instant::now();
    child.stdin.take().unwrap().write_all(b"release\n").unwrap();
    let lock = tokio::time::timeout(StdDuration::from_secs(5), waiter)
        .await
        .expect("waiter must not stall after the holder releases")
        .expect("waiter task must not panic")
        .expect("waiter must acquire the lock");
    assert!(
        released_at.elapsed() < StdDuration::from_secs(3),
        "waiter must wake promptly on release, not burn its budget on a dead inode"
    );
    assert!(
        lock.still_live(&path),
        "the waiter's guard must hold the LIVE inode"
    );
    assert_eq!(inode_of(&lock_path), inode_before);

    let _ = child.wait();
}

#[cfg(unix)]
#[test]
fn blocking_acquire_succeeds_when_uncontended() {
    let dir = TempDir::new().unwrap();
    let lock_path = dir.path().join("auth.json.lock");

    let _file = blocking_acquire(&lock_path).expect("uncontended blocking acquire should succeed");
    let content = std::fs::read_to_string(&lock_path).unwrap();
    let (pid, _ts) = parse_holder_info(&content).unwrap();
    assert_eq!(pid, std::process::id());
}

#[cfg(unix)]
#[tokio::test]
async fn blocking_wait_wakes_promptly_when_holder_releases() {
    let dir = TempDir::new().unwrap();
    let path = auth_json_path(&dir);
    let lock_path = path.with_file_name("auth.json.lock");

    let mut child = spawn_lock_holder_subprocess(&lock_path, "pid", /*age_secs*/ 0);

    let mut stdin = child.stdin.take().unwrap();
    let release_handle = std::thread::spawn(move || {
        std::thread::sleep(StdDuration::from_secs(1));
        let _ = stdin.write_all(b"release\n");
    });

    let start = tokio::time::Instant::now();
    let lock = try_lock_auth_file_async(&path, StdDuration::from_secs(10), Heartbeat::Skip)
        .await
        .into_guard();
    let elapsed = start.elapsed();

    assert!(lock.is_some(), "should acquire via blocking flock");
    assert!(
        elapsed >= StdDuration::from_millis(800),
        "should have waited for child, took {elapsed:?}"
    );
    assert!(
        elapsed < StdDuration::from_secs(4),
        "blocking flock should wake promptly, took {elapsed:?}"
    );

    release_handle.join().unwrap();
    let _ = child.wait();
}

/// P150 (D6): `auth.json.lock` sits beside `auth.json` and is created owner-only by every acquire path, and one an
/// older version left 0644 is tightened when it is next taken.
#[cfg(unix)]
#[test]
fn p150_auth_lock_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let dir = TempDir::new().unwrap();
    let path = auth_json_path(&dir);
    let lock_path = path.with_file_name(LOCK_FILE_NAME);

    drop(try_lock_auth_file_nonblocking(&path).expect("uncontended non-blocking acquire"));
    assert_eq!(mode(&lock_path), 0o600, "non-blocking acquire must create it owner-only");

    std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    match lock_auth_file_blocking(&path, StdDuration::from_secs(5)) {
        LockAcquire::Acquired(lock) => drop(lock),
        _ => panic!("uncontended blocking acquire"),
    }
    assert_eq!(mode(&lock_path), 0o600, "a looser auth.json.lock is tightened");

    std::fs::remove_file(&lock_path).unwrap();
    match lock_auth_file_blocking(&path, StdDuration::from_secs(5)) {
        LockAcquire::Acquired(lock) => drop(lock),
        _ => panic!("uncontended blocking acquire"),
    }
    assert_eq!(mode(&lock_path), 0o600, "blocking acquire must create it owner-only");
}
