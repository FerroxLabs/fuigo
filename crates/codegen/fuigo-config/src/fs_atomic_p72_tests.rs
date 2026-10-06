//! P72: the lock's wait gives up only when nothing ahead of it moves, and
//! waiters in different processes are served in arrival order (the
//! cross-process ticket queue, `xq`). Child roles re-run this test binary.

use super::*;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Every entry name in `dir`, sorted (empty for a missing directory).
fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Re-run this test binary as a child in `role` (see [`p72_child_role`]).
fn spawn_role(role: &str) -> std::process::Child {
    #[allow(clippy::disallowed_methods)] // test fixture; waited for by the caller
    std::process::Command::new(std::env::current_exe().unwrap())
        .env("FUIGO_P72_ROLE", role)
        .args([
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads",
            "1",
            "fs_atomic::p72_tests::p72_child_role",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap()
}

fn wait_ok(child: std::process::Child, what: &str) -> String {
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success(), "{what} failed:\n{stdout}");
    stdout
}

/// The trace a lock writes when `<lock>.trace` exists: `(event, pid)` in order.
fn trace_of(lock: &Path) -> Vec<(String, u32)> {
    let mut path = lock.as_os_str().to_owned();
    path.push(".trace");
    std::fs::read_to_string(PathBuf::from(path))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let (what, pid) = l.split_once(' ')?;
            Some((what.to_owned(), pid.parse().ok()?))
        })
        .collect()
}

/// The file whose creation starts the contending children.
fn go_file(lock: &Path) -> PathBuf {
    let mut path = lock.as_os_str().to_owned();
    path.push(".go");
    PathBuf::from(path)
}

fn enable_trace(lock: &Path) {
    let mut path = lock.as_os_str().to_owned();
    path.push(".trace");
    std::fs::write(PathBuf::from(path), "").unwrap();
}

fn spin_until(what: &str, limit: Duration, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// For every `Q p` .. next `G p` window, how many grants each OTHER process
/// got inside it. FIFO admits at most one per other process (it was already
/// ahead, or raced p's registration once); a process overtaking p twice means
/// it re-queued and was served ahead of p again.
fn worst_overtakes(trace: &[(String, u32)]) -> (usize, String) {
    let mut worst = (0, String::new());
    for (i, (what, pid)) in trace.iter().enumerate() {
        if what != "Q" {
            continue;
        }
        let mut grants: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
        for (w, p) in &trace[i + 1..] {
            if w == "G" && p == pid {
                break;
            }
            if w == "G" {
                *grants.entry(*p).or_default() += 1;
            }
        }
        if let Some((other, n)) = grants.iter().max_by_key(|(_, n)| **n)
            && *n > worst.0
        {
            worst = (*n, format!("pid {other} granted {n}x while pid {pid} waited (trace line {i})"));
        }
    }
    worst
}

/// THE CONTENTION TEST (P72 F3). Six processes take one lock 20 times each,
/// back to back, holding it a little each time and re-requesting at once --
/// the pattern that starved a waiter of an unordered `flock`. With the default
/// wait (no retries anywhere) none is refused, the exclusion holds (an unlocked
/// read-append-write inside the lock loses nothing), and the trace shows FIFO
/// service: while a process waits, no other process is granted the lock twice.
#[test]
fn n_processes_contending_are_served_in_turn_and_never_refused() {
    let _alone = HEAVY_IO
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    const PROCS: usize = 6;
    const EACH: usize = 20;
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("locks/contended.lock");
    let data = dir.path().join("data");
    std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
    enable_trace(&lock);
    let children: Vec<_> = (0..PROCS)
        .map(|p| {
            spawn_role(&format!(
                "contend|{}|{}|p{p}|{EACH}",
                lock.display(),
                data.display()
            ))
        })
        .collect();
    // All start together (no child gets a head start of its whole run).
    std::fs::write(go_file(&lock), "").unwrap();
    let mut stats = Vec::new();
    for (p, mut c) in children.into_iter().enumerate() {
        drop(c.stdin.take());
        let out = wait_ok(c, &format!("contender p{p}"));
        stats.extend(
            out.lines()
                .filter_map(|l| l.find("P72_WAIT").map(|at| l[at..].to_owned())),
        );
    }
    // Exclusion: every append landed.
    let mut got: Vec<String> = std::fs::read_to_string(&data)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    got.sort();
    let mut want: Vec<String> = (0..PROCS)
        .flat_map(|p| (0..EACH).map(move |i| format!("p{p}-{i}")))
        .collect();
    want.sort();
    assert_eq!(got, want);
    // Fairness: FIFO across processes.
    let trace = trace_of(&lock);
    assert_eq!(
        trace.iter().filter(|(w, _)| w == "G").count(),
        PROCS * EACH,
        "one grant per acquisition"
    );
    // Every acquisition queued (Q) before it was granted (G), one at a time
    // per process.
    let mut per_pid: std::collections::HashMap<u32, Vec<&str>> = std::collections::HashMap::new();
    for (w, p) in &trace {
        per_pid.entry(*p).or_default().push(w.as_str());
    }
    assert_eq!(per_pid.len(), PROCS, "{per_pid:?}");
    for (p, events) in &per_pid {
        let want: Vec<&str> = (0..EACH).flat_map(|_| ["Q", "G"]).collect();
        assert_eq!(events, &want, "pid {p}: every grant must follow its own queueing");
    }
    // ...and there WAS contention: most acquisitions waited behind another
    // process's grant (else this proves nothing about the order).
    let waited_behind = trace
        .iter()
        .enumerate()
        .filter(|(_, (w, _))| w == "Q")
        .filter(|(i, (_, pid))| {
            trace[i + 1..]
                .iter()
                .take_while(|(w, p)| !(w == "G" && p == pid))
                .any(|(w, _)| w == "G")
        })
        .count();
    let (worst, detail) = worst_overtakes(&trace);
    println!("P72_CONTENTION worst_overtakes={worst} waited_behind={waited_behind}/{} {detail}", PROCS * EACH);
    assert!(
        waited_behind * 2 >= PROCS * EACH,
        "only {waited_behind} of {} acquisitions met contention",
        PROCS * EACH
    );
    for s in &stats {
        println!("{s}");
    }
    assert!(worst <= 1, "not FIFO: {detail}");
    // Every ticket is gone again, and the idle queue's directory with them.
    let queue = xq::dir_for(&lock);
    assert!(!queue.exists(), "{:?}", names_in(&queue));
}

/// A waiter behind other PROCESSES whose holds add up to far more than its
/// stall limit, but each well inside it, is served, not refused -- and so is a
/// second thread of the same process queued behind the first (it counts the
/// cross-process queue's progress as its own).
#[test]
fn waiters_behind_moving_holders_in_other_processes_are_not_refused() {
    let _alone = HEAVY_IO
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    const HOLDERS: usize = 4;
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("moving.lock");
    enable_trace(&lock);
    // Each holder takes the lock 3 times for 150 ms: about 1.8 s of holding in
    // all, against a 600 ms stall limit below.
    let children: Vec<_> = (0..HOLDERS)
        .map(|_| spawn_role(&format!("hold|{}|150|3", lock.display())))
        .collect();
    spin_until("every holder to queue", Duration::from_secs(30), || {
        trace_of(&lock).iter().filter(|(w, _)| w == "Q").count() >= HOLDERS
    });
    let stall = Duration::from_millis(600);
    let started = Instant::now();
    let (first, second) = std::thread::scope(|s| {
        let a = s.spawn(|| lock_at_within(&lock, stall).map(|l| (l, started.elapsed())));
        // The second thread queues behind the first, in this process.
        spin_until("first thread to take its turn", Duration::from_secs(10), || {
            turn::outstanding(&turn::key_for(&lock)) >= 1
        });
        let b = s.spawn(|| lock_at_within(&lock, stall).map(|l| (l, started.elapsed())));
        let first = a.join().unwrap().map(|(l, t)| {
            drop(l);
            t
        });
        let second = b.join().unwrap().map(|(l, t)| {
            drop(l);
            t
        });
        (first, second)
    });
    for c in children {
        wait_ok(c, "holder");
    }
    let first = first.expect("the first waiter must not be refused while the queue moves");
    let second = second.expect("the second waiter must not be refused while the queue moves");
    println!("P72_MOVING first={first:?} second={second:?} stall={stall:?}");
    assert!(
        second > stall,
        "the queue ahead held for longer than the stall limit ({second:?}); this test proves nothing"
    );
}

/// A writer that holds the lock and never lets go (wedged, stopped) still
/// gets every waiter refused after the stall limit, not hung.
#[test]
fn a_wedged_holder_in_another_process_is_refused_after_the_stall_limit() {
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("wedged.lock");
    enable_trace(&lock);
    let mut holder = spawn_role(&format!("wedge|{}", lock.display()));
    spin_until("the holder to be granted", Duration::from_secs(30), || {
        trace_of(&lock).iter().any(|(w, _)| w == "G")
    });
    let stall = Duration::from_millis(300);
    let started = Instant::now();
    let err = lock_at_within(&lock, stall).expect_err("the lock is held for good");
    let waited = started.elapsed();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert!(waited >= stall, "gave up early: {waited:?}");
    assert!(waited < stall * 20, "gave up late: {waited:?}");
    drop(holder.stdin.take());
    wait_ok(holder, "wedged holder");
    drop(lock_at_within(&lock, stall).expect("free again once the holder exits"));
}

/// A ticket left by a writer that died (its file is not locked) is skipped
/// and removed; a live one ahead is waited for, and its going away lets the
/// waiter in.
#[test]
fn a_dead_writers_ticket_is_skipped_and_a_live_one_is_waited_for() {
    use fs2::FileExt as _;
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("q.lock");
    let queue = xq::dir_for(&lock);
    std::fs::create_dir_all(&queue).unwrap();
    // Sorts before any real ticket.
    let dead = queue.join(format!("{:032}.{:010}.{:020}.t", 1, 1, 1));
    std::fs::write(&dead, "").unwrap();
    let started = Instant::now();
    drop(lock_at_within(&lock, Duration::from_secs(5)).expect("a dead ticket is not waited on"));
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    assert!(!dead.exists(), "the dead ticket must be removed");

    // A live ticket: locked through its own open file description (as another
    // process's would be).
    assert!(!queue.exists(), "an idle queue's directory is removed");
    std::fs::create_dir_all(&queue).unwrap();
    let live = queue.join(format!("{:032}.{:010}.{:020}.t", 2, 2, 2));
    let owner = std::fs::File::create(&live).unwrap();
    owner.lock_exclusive().unwrap();
    let err = lock_at_within(&lock, Duration::from_millis(200)).expect_err("a live ticket is ahead");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert!(live.exists(), "a live ticket must never be removed");
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        // As a writer's drop does: the name goes, then the lock.
        std::fs::remove_file(&live).unwrap();
        drop(owner);
    });
    drop(lock_at_within(&lock, Duration::from_secs(5)).expect("served once the ticket ahead goes"));
    releaser.join().unwrap();
    assert!(!queue.exists(), "{:?}", names_in(&queue));
}

/// A ticket stamped LATER than the clock reads now (as after the clock is
/// stepped back) is still ahead of a newcomer: arrival order never goes
/// backwards with the clock.
#[test]
fn a_ticket_stamped_in_the_future_stays_ahead_of_a_newcomer() {
    use fs2::FileExt as _;
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("clock.lock");
    let queue = xq::dir_for(&lock);
    std::fs::create_dir_all(&queue).unwrap();
    let future = queue.join(format!("{:032}.{:010}.{:020}.t", 10u128.pow(31), 3, 3));
    let owner = std::fs::File::create(&future).unwrap();
    owner.lock_exclusive().unwrap();
    let err = lock_at_within(&lock, Duration::from_millis(300))
        .expect_err("the waiting (future-stamped) ticket is ahead");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    std::fs::remove_file(&future).unwrap();
    drop(owner);
    drop(lock_at_within(&lock, Duration::from_secs(5)).expect("free once it goes"));
}

/// The LAST writer ahead in the cross-process queue leaving counts as
/// progress for this process's threads queued behind the one that was
/// waiting on it: here the thread behind would otherwise give up while the
/// thread ahead of it, granted just now, still holds well inside the limit.
#[test]
fn the_last_holder_ahead_leaving_restarts_the_wait_of_threads_behind() {
    let _alone = HEAVY_IO
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("handoff.lock");
    enable_trace(&lock);
    let holder = spawn_role(&format!("hold|{}|800|1", lock.display()));
    spin_until("the other process to hold the lock", Duration::from_secs(30), || {
        trace_of(&lock).iter().any(|(w, _)| w == "G")
    });
    let stall = Duration::from_secs(1);
    let key = turn::key_for(&lock);
    let (a, b) = std::thread::scope(|s| {
        let a = s.spawn(|| {
            let l = lock_at_within(&lock, Duration::from_secs(30))?;
            std::thread::sleep(Duration::from_millis(400));
            drop(l);
            Ok::<_, std::io::Error>(())
        });
        spin_until("the first thread to take its turn", Duration::from_secs(10), || {
            turn::outstanding(&key) >= 1
        });
        let b = s.spawn(|| lock_at_within(&lock, stall).map(drop));
        (a.join().unwrap(), b.join().unwrap())
    });
    wait_ok(holder, "holder");
    a.expect("first thread");
    b.expect("the thread behind must not give up: the queue ahead of it moved");
}

/// Threads of ONE process behind holders that each hold well inside the stall
/// limit, but much longer than it in all, are served, not refused.
#[test]
fn a_thread_behind_moving_holders_in_this_process_is_not_refused() {
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("threads.lock");
    let key = turn::key_for(&lock);
    let stall = Duration::from_millis(500);
    let first = lock_at_within(&lock, stall).unwrap();
    let holders: Vec<_> = (0..8)
        .map(|_| {
            let lock = lock.clone();
            std::thread::spawn(move || {
                let l = lock_at_within(&lock, Duration::from_secs(30)).expect("holder");
                std::thread::sleep(Duration::from_millis(120));
                drop(l);
            })
        })
        .collect();
    spin_until("holders to queue", Duration::from_secs(10), || turn::outstanding(&key) == 9);
    let started = Instant::now();
    let waiter = {
        let lock = lock.clone();
        std::thread::spawn(move || lock_at_within(&lock, stall).map(drop))
    };
    spin_until("waiter to queue", Duration::from_secs(10), || turn::outstanding(&key) == 10);
    drop(first);
    for h in holders {
        h.join().unwrap();
    }
    waiter
        .join()
        .unwrap()
        .expect("the waiter must not be refused while the queue moves");
    let waited = started.elapsed();
    assert!(waited > stall, "held {waited:?} in all; this test proves nothing");
}

/// The state-file lock sits under `<fuigo home>/locks/`, one per file
/// identity, and nothing is created beside the file.
#[test]
fn a_state_file_is_locked_out_of_its_directory_by_identity() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir_all(&real).unwrap();
    let a = state_lock_path(&real.join("f.json")).unwrap();
    let b = state_lock_path(&real.join("../real/./f.json")).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, state_lock_path(&real.join("g.json")).unwrap());
    // (`<fuigo home>/locks`; in this test binary a private directory.)
    assert_eq!(a.parent().unwrap(), state_locks_dir());
    // These writers write through a symlink: a link (also a chain, also a
    // relative one, also before the target exists) locks as the file it ends at.
    #[cfg(unix)]
    {
        let links = dir.path().join("links");
        std::fs::create_dir_all(&links).unwrap();
        std::os::unix::fs::symlink(real.join("f.json"), links.join("link1")).unwrap();
        std::os::unix::fs::symlink("link1", links.join("link2")).unwrap();
        std::os::unix::fs::symlink("../real/./f.json", links.join("rel")).unwrap();
        for link in [links.join("link1"), links.join("link2"), links.join("rel")] {
            assert_eq!(state_lock_path(&link).unwrap(), a, "{}", link.display());
        }
    }
    let path = real.join("f.json");
    edit_state_file(
        &path,
        |bytes| stage_atomically(&path, bytes, None),
        |_| Ok::<_, std::io::Error>(Edit::Replace { contents: b"x".to_vec(), value: () }),
    )
    .unwrap();
    assert_eq!(names_in(&real), ["f.json"]);
}

/// Child-process roles for the tests above; does nothing unless
/// `FUIGO_P72_ROLE` is set (so a plain `--ignored` run is harmless).
#[test]
#[ignore = "child-process role for the P72 lock tests"]
fn p72_child_role() {
    let Ok(role) = std::env::var("FUIGO_P72_ROLE") else {
        return;
    };
    let parts: Vec<&str> = role.split('|').collect();
    match parts.as_slice() {
        ["contend", lock, data, prefix, n] => {
            use std::io::Write as _;
            let (lock, data) = (Path::new(lock), Path::new(data));
            let mut worst = Duration::ZERO;
            let mut total = Duration::ZERO;
            let n: usize = n.parse().unwrap();
            let go = go_file(lock);
            let started = Instant::now();
            while !go.exists() {
                assert!(started.elapsed() < Duration::from_secs(120), "never told to go");
                std::thread::sleep(Duration::from_millis(1));
            }
            for i in 0..n {
                let asked = Instant::now();
                // No retry: a refusal fails the test.
                let held = lock_file_for_write(lock)
                    .unwrap_or_else(|e| panic!("{prefix}-{i} refused: {e}"));
                let waited = asked.elapsed();
                worst = worst.max(waited);
                total += waited;
                // An unlocked read-append-write: only the lock keeps it whole.
                let mut s = std::fs::read_to_string(data).unwrap_or_default();
                s.push_str(&format!("{prefix}-{i}\n"));
                std::thread::sleep(Duration::from_millis(3));
                let mut f = std::fs::File::create(data).unwrap();
                f.write_all(s.as_bytes()).unwrap();
                drop(f);
                drop(held); // ...and straight back in
            }
            println!("P72_WAIT {prefix} worst={worst:?} mean={:?}", total / n as u32);
        }
        ["hold", lock, ms, times] => {
            let lock = Path::new(lock);
            for _ in 0..times.parse::<usize>().unwrap() {
                let held = lock_file_for_write(lock).expect("holder");
                std::thread::sleep(Duration::from_millis(ms.parse().unwrap()));
                drop(held);
            }
        }
        ["wedge", lock] => {
            use std::io::BufRead as _;
            let held = lock_file_for_write(Path::new(lock)).expect("holder");
            let mut line = String::new();
            let _ = std::io::stdin().lock().read_line(&mut line);
            drop(held);
        }
        _ => panic!("unknown role {role}"),
    }
}
