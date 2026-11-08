//! Deterministic tests of the writer (design §9.1, CT-W1-CT-W8 as far as they live in this crate). CT-W3b
//! (`ResourcesPersistence`), CT-W3c's `EventWriter` half, CT-W5 (close) and CT-W6 on the real session thread need the
//! converted crates and land with F5-X / F5-T.

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

use crate::lock::SESSION_WRITER_LOCK_FILE;
use crate::{ClaimError, Refusal, SessionWriter, refusal, seams};

const SEAM: Duration = Duration::from_secs(10);

fn unique_id(tag: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    format!("{tag}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed))
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("runtime")
}

/// Another holder, as the lock tests make it: a second open of the lock file excludes this process's own open exactly as
/// another process's would (the OS lock belongs to the open file).
fn foreign_could_take(dir: &Path) -> bool {
    let Ok(file) = std::fs::OpenOptions::new().read(true).write(true).open(dir.join(SESSION_WRITER_LOCK_FILE)) else {
        return true;
    };
    match file.try_lock() {
        Ok(()) => {
            file.unlock().expect("unlock");
            true
        }
        Err(std::fs::TryLockError::WouldBlock) => false,
        Err(std::fs::TryLockError::Error(e)) => panic!("{e}"),
    }
}

/// Wait out a dropped hold that a concurrently forking test's child still shares until it execs (see the lock tests).
fn eventually(mut done: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !done() {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

/// Every file under `dir` with its bytes, for byte-identical checks.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("read_dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let bytes = std::fs::read(&path).expect("read");
                out.push((path.strip_prefix(dir).expect("prefix").to_path_buf(), bytes));
            }
        }
    }
    out.sort();
    out
}

// ---- child processes ---------------------------------------------------------------------------------------------

const PROBE: &str = "writer_tests::probe_process";
const PROBE_DIR: &str = "FUIGO_F5W_PROBE_DIR";
const HOLDER: &str = "lock::tests::holder_process";
const HOLDER_DIR: &str = "FUIGO_P30_DIRECT_HOLDER_DIR";

/// Child of CT-W4: answers each `probe` line on stdin with `nofile`, `held` or `free` for the session's OS lock, using
/// its own open of the lock file (never creating it).
#[test]
#[ignore = "helper process for ct_w4"]
fn probe_process() {
    let Some(dir) = std::env::var_os(PROBE_DIR) else { return };
    let path = Path::new(&dir).join(SESSION_WRITER_LOCK_FILE);
    println!("PROBE_READY");
    for line in std::io::stdin().lock().lines() {
        if line.expect("line") != "probe" {
            break;
        }
        let answer = match std::fs::OpenOptions::new().read(true).write(true).open(&path) {
            Err(_) => "nofile",
            Ok(file) => match file.try_lock() {
                Ok(()) => {
                    let _ = file.unlock();
                    "free"
                }
                Err(std::fs::TryLockError::WouldBlock) => "held",
                Err(std::fs::TryLockError::Error(_)) => "error",
            },
        };
        println!("{answer}");
    }
}

fn spawn_test_child(name: &str, env: (&str, &Path), stdin: bool) -> Child {
    // Not enrolled in a process scope: the test kills and reaps it itself.
    #[allow(clippy::disallowed_methods)]
    std::process::Command::new(std::env::current_exe().expect("test exe"))
        .args(["--exact", name, "--ignored", "--nocapture", "--test-threads=1"])
        .env(env.0, env.1)
        .stdin(if stdin { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child")
}

fn wait_line(out: &mut BufReader<ChildStdout>, want: &str) {
    let mut line = String::new();
    loop {
        line.clear();
        assert!(out.read_line(&mut line).expect("read") > 0, "child exited before {want}");
        // libtest prints `test <name> ... ` without a newline before the child's own output.
        if line.contains(want) {
            return;
        }
    }
}

struct Probe {
    child: Child,
    stdin: ChildStdin,
    out: BufReader<ChildStdout>,
}

impl Probe {
    fn start(dir: &Path) -> Self {
        let mut child = spawn_test_child(PROBE, (PROBE_DIR, dir), true);
        let stdin = child.stdin.take().expect("stdin");
        let mut out = BufReader::new(child.stdout.take().expect("stdout"));
        wait_line(&mut out, "PROBE_READY");
        Self { child, stdin, out }
    }

    fn ask(&mut self) -> String {
        writeln!(self.stdin, "probe").expect("ask");
        self.stdin.flush().expect("flush");
        loop {
            let mut line = String::new();
            assert!(self.out.read_line(&mut line).expect("read") > 0, "probe exited");
            let last = line.split_whitespace().last().unwrap_or("").to_owned();
            if matches!(last.as_str(), "nofile" | "held" | "free" | "error") {
                return last;
            }
        }
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn foreign_process_hold(dir: &Path) -> Child {
    let mut child = spawn_test_child(HOLDER, (HOLDER_DIR, dir), false);
    let mut out = BufReader::new(child.stdout.take().expect("stdout"));
    wait_line(&mut out, "HOLDER_READY");
    child
}

// ---- CT-W1: the counted slot ---------------------------------------------------------------------------------------

/// CT-W1: a second `try_claim` of one id is `Busy`; after the first writer's LAST clone drops, the waiter wakes and
/// claims.
#[test]
fn ct_w1_second_claim_is_busy_until_the_last_clone_drops() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("w1");
    let first = SessionWriter::try_claim(&id, dir.path().join("s")).expect("first");
    let clone = first.clone();
    let busy = SessionWriter::try_claim(&id, dir.path().join("s")).expect_err("second must be busy");
    let rt = rt();
    let waiter = rt.spawn(async move { busy.freed_by(Instant::now() + Duration::from_secs(10)).await });
    drop(first);
    std::thread::sleep(Duration::from_millis(50));
    assert!(!waiter.is_finished(), "woke while a clone still holds the slot");
    assert!(SessionWriter::try_claim(&id, dir.path().join("s")).is_err(), "slot freed while a clone lives");
    drop(clone);
    assert!(rt.block_on(waiter).expect("join"), "waiter not woken by the last drop");
    let again = SessionWriter::try_claim(&id, dir.path().join("s")).expect("claims after free");
    assert!(again.generation() > 0);
    assert_eq!(crate::debug_live_writers(&id), 1);
    drop(again);
    assert_eq!(crate::debug_live_writers(&id), 0);
    assert!(SessionWriter::is_free(&id));
}

/// `claim` waits on the same deadline and reports "still closing" when the holder outlives it.
#[test]
fn claim_waits_for_the_holder_then_reports_still_closing() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("claim");
    let rt = rt();
    let held = SessionWriter::try_claim(&id, dir.path().join("s")).expect("held");
    let short = rt.block_on(SessionWriter::claim(&id, dir.path().join("s"), Instant::now() + Duration::from_millis(80)));
    assert_eq!(short.expect_err("must time out"), ClaimError::StillClosing);
    assert!(!rt.block_on(SessionWriter::wait_free(&id, Instant::now() + Duration::from_millis(50))));
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        drop(held);
    });
    let got = rt.block_on(SessionWriter::claim(&id, dir.path().join("s"), Instant::now() + Duration::from_secs(10)));
    release.join().expect("join");
    let got = got.expect("claims once the holder drops");
    drop(got);
    assert!(rt.block_on(SessionWriter::wait_free(&id, Instant::now() + Duration::from_secs(1))));
}

// ---- CT-W2: the drop window ----------------------------------------------------------------------------------------

/// CT-W2: paused inside `Inner::drop` (OS hold released, slot not yet), a `try_claim` is `Busy`; and a stale drop whose
/// entry was replaced by a newer generation leaves the newer entry alone (the `gen` check).
#[test]
fn ct_w2_drop_window_is_busy_and_a_stale_drop_is_harmless() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("w2");
    let old = SessionWriter::try_claim(&id, dir.path().join("s")).expect("old");
    old.append_sync("f", b"x").expect("attach");
    let gate = seams::arm(&format!("drop:{id}"));
    let dropper = std::thread::spawn(move || drop(old));
    assert!(gate.wait_reached(SEAM), "drop never reached the seam");
    // The OS hold is already released, the slot is not.
    assert!(eventually(|| foreign_could_take(&dir.path().join("s"))));
    assert!(SessionWriter::try_claim(&id, dir.path().join("s")).is_err(), "slot free inside the drop window");
    // Simulate a newer generation owning the id while the old drop is still in flight.
    let newer_gen = 1 << 60;
    {
        let (tx, _rx) = tokio::sync::watch::channel(());
        crate::writer::test_replace_slot(&id, newer_gen, tx);
    }
    gate.open();
    dropper.join().expect("join");
    assert!(!SessionWriter::is_free(&id), "a stale drop removed the newer generation's slot");
    crate::writer::test_remove_slot(&id);
}

// ---- CT-W3: a write outlives its awaiting future, never its writer -----------------------------------------------------

/// CT-W3: `replace_atomic` paused before its rename; the awaiting future is dropped and the caller's writer too;
/// `wait_free` stays false until the rename lands.
#[test]
fn ct_w3_wait_free_waits_for_an_abandoned_replace_atomic() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("w3");
    let session = dir.path().join("s");
    let rt = rt();
    let writer = SessionWriter::try_claim(&id, &session).expect("claim");
    writer.replace_atomic_sync("state.json", b"old").expect("first write");
    let gate = seams::arm(&format!("rename:{id}"));
    // Open the gate even if an assertion below fails, so the runtime's drop does not wait on the parked write.
    struct OpenOnDrop(Arc<seams::Gate>);
    impl Drop for OpenOnDrop {
        fn drop(&mut self) {
            self.0.open();
        }
    }
    let _open_on_unwind = OpenOnDrop(gate.clone());
    let task = rt.spawn({
        let writer = writer.clone();
        async move { writer.replace_atomic("state.json", b"new".to_vec()).await }
    });
    assert!(gate.wait_reached(SEAM), "never reached the rename");
    task.abort();
    drop(writer);
    assert!(!rt.block_on(SessionWriter::wait_free(&id, Instant::now() + Duration::from_millis(150))));
    assert_eq!(std::fs::read(session.join("state.json")).expect("read"), b"old");
    gate.open();
    assert!(rt.block_on(SessionWriter::wait_free(&id, Instant::now() + Duration::from_secs(10))));
    assert_eq!(std::fs::read(session.join("state.json")).expect("read"), b"new", "the write landed before free");
}

/// CT-W3c (`SessionAppend` half): a recorder task that owns a `SessionAppend` keeps the writer until it drops.
#[test]
fn ct_w3c_a_held_append_handle_keeps_the_writer() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("w3c");
    let rt = rt();
    let writer = SessionWriter::try_claim(&id, dir.path().join("s")).expect("claim");
    let log = writer.open_append("terminal/t1.log").expect("open");
    drop(writer);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let recorder = rt.spawn(async move {
        log.write_all_async(b"line 1\n".to_vec()).await.expect("write");
        let _ = stop_rx.await;
        log.write_all(b"line 2\n").expect("write");
    });
    assert!(!rt.block_on(SessionWriter::wait_free(&id, Instant::now() + Duration::from_millis(150))));
    let _ = stop_tx.send(());
    rt.block_on(recorder).expect("join");
    assert!(rt.block_on(SessionWriter::wait_free(&id, Instant::now() + Duration::from_secs(10))));
    assert_eq!(std::fs::read(dir.path().join("s/terminal/t1.log")).expect("read"), b"line 1\nline 2\n");
}

// ---- CT-W4: the OS hold from the first byte -------------------------------------------------------------------------

/// CT-W4: missing folder; `claim`, then the first `append_sync` from a plain thread. A child process sees the OS lock
/// held at the moment the first byte is about to be written (paused at the syscall), and until the last clone drops.
#[test]
fn ct_w4_a_new_session_holds_the_os_lock_from_its_first_byte() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("w4");
    let session = dir.path().join("cwd-bucket").join(&id);
    let rt = rt();
    let writer = rt
        .block_on(SessionWriter::claim(&id, &session, Instant::now() + Duration::from_secs(5)))
        .expect("claim");
    assert!(!session.exists(), "claim must not create the folder");
    let mut probe = Probe::start(&session);
    assert_eq!(probe.ask(), "nofile");
    let gate = seams::arm(&format!("op:{id}"));
    let first = std::thread::spawn({
        let writer = writer.clone();
        move || writer.append_sync("updates.jsonl", b"{}\n")
    });
    assert!(gate.wait_reached(SEAM), "first write never reached its syscall");
    assert!(!session.join("updates.jsonl").exists(), "paused before the first byte");
    assert_eq!(probe.ask(), "held", "OS lock not held before the first byte");
    gate.open();
    first.join().expect("join").expect("first write");
    let clone = writer.clone();
    drop(writer);
    assert_eq!(probe.ask(), "held", "released while a clone lives");
    drop(clone);
    assert!(eventually(|| probe.ask() == "free"), "not released after the last clone");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(&session).expect("meta").permissions().mode() & 0o777, 0o700);
        let mode = std::fs::metadata(session.join("updates.jsonl")).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

/// CT-W4b: an existing folder held by a child process. `try_claim` succeeds in this process, but the first `copy_in`
/// and `create_new` return `HeldElsewhere`, and the folder is byte-identical afterwards. An eager `claim` is refused.
#[test]
fn ct_w4b_a_folder_held_by_another_process_is_never_written() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("w4b");
    let session = dir.path().join(&id);
    std::fs::create_dir_all(&session).expect("mkdir");
    std::fs::write(session.join("updates.jsonl"), b"{\"a\":1}\n").expect("seed");
    let src = dir.path().join("src.jsonl");
    std::fs::write(&src, b"copied").expect("src");
    let mut holder = foreign_process_hold(&session);
    let before = snapshot(&session);
    let writer = SessionWriter::try_claim(&id, &session).expect("in-process slot is free");
    let error = writer.copy_in_sync(&src, "chat_history.jsonl").expect_err("copy_in must be refused");
    assert_eq!(refusal(&error), Some(Refusal::HeldElsewhere), "{error}");
    let error = writer.create_new_sync("mcp/dump.txt", b"x").expect_err("create_new must be refused");
    assert_eq!(refusal(&error), Some(Refusal::HeldElsewhere), "{error}");
    let error = writer.append_sync("updates.jsonl", b"more").expect_err("append must be refused");
    assert_eq!(refusal(&error), Some(Refusal::HeldElsewhere));
    // F5-C8: the methods that never create the folder attach the hold too (a rename or a remove by a writer that
    // skipped the hold would change a folder another process owns).
    let error = writer.rename_sync("updates.jsonl", "moved/updates.jsonl").expect_err("rename must be refused");
    assert_eq!(refusal(&error), Some(Refusal::HeldElsewhere), "{error}");
    let error = writer.remove_sync("updates.jsonl").expect_err("remove must be refused");
    assert_eq!(refusal(&error), Some(Refusal::HeldElsewhere), "{error}");
    assert_eq!(snapshot(&session), before, "the folder changed");
    assert!(!session.join("moved").exists());
    assert!(!session.join("mcp").exists());
    drop(writer);
    let rt = rt();
    let refused = rt.block_on(SessionWriter::claim(&id, &session, Instant::now() + Duration::from_secs(5)));
    assert_eq!(refused.expect_err("eager attach refuses"), ClaimError::HeldElsewhere);
    assert!(SessionWriter::is_free(&id), "a refused claim keeps the slot");
    holder.kill().expect("kill");
    holder.wait().expect("reap");
    let writer = rt
        .block_on(SessionWriter::claim(&id, &session, Instant::now() + Duration::from_secs(5)))
        .expect("free after the holder dies");
    writer.copy_in_sync(&src, "chat_history.jsonl").expect("now writes");
}

/// F5-C8: `ensure_folder_owner_only_sync` makes a folder that already existed with a wider mode (an earlier, failed
/// import) owner-only again, not only a folder it creates.
#[cfg(unix)]
#[test]
fn c8_ensure_folder_owner_only_retightens_an_existing_folder() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("c8-0700");
    let session = dir.path().join(&id);
    std::fs::create_dir_all(&session).expect("mkdir");
    std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let writer = SessionWriter::try_claim(&id, &session).expect("claim");
    writer.ensure_folder_owner_only_sync().expect("ensure");
    assert_eq!(std::fs::metadata(&session).expect("meta").permissions().mode() & 0o777, 0o700, "not re-tightened");
}

/// A reader's writer does not retry a contended lock: it is refused at once, not after 300 ms (Fable round-2 L6).
#[test]
fn a_reader_writer_never_waits_for_a_contended_lock() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("reader");
    let session = dir.path().join(&id);
    std::fs::create_dir_all(&session).expect("mkdir");
    let other = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(session.join(SESSION_WRITER_LOCK_FILE))
        .expect("open");
    other.try_lock().expect("foreign hold");
    let reader = SessionWriter::try_claim_reader(&id, &session).expect("slot");
    let started = std::time::Instant::now();
    let error = reader.replace_atomic_sync("chat_history.jsonl", b"x").expect_err("refused");
    assert_eq!(refusal(&error), Some(Refusal::HeldElsewhere));
    assert!(started.elapsed() < Duration::from_millis(200), "a reader waited {:?}", started.elapsed());
    let owner = SessionWriter::try_claim(format!("{id}-owner"), &session).expect("slot");
    let started = std::time::Instant::now();
    assert!(owner.append_sync("x", b"x").is_err());
    assert!(started.elapsed() >= Duration::from_millis(290), "an owner rides out a momentary hold");
}

// ---- CT-W6 (crate half): unwind frees the writer --------------------------------------------------------------------

/// A thread that panics while holding the writer frees it on unwind, after its last write.
#[test]
fn ct_w6_unwind_frees_the_writer() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("w6");
    let writer = SessionWriter::try_claim(&id, dir.path().join("s")).expect("claim");
    let thread = std::thread::spawn(move || {
        writer.append_sync("updates.jsonl", b"tail\n").expect("tail");
        panic!("session thread dies");
    });
    assert!(thread.join().is_err());
    assert!(SessionWriter::is_free(&id));
    assert!(eventually(|| foreign_could_take(&dir.path().join("s"))));
    assert_eq!(std::fs::read(dir.path().join("s/updates.jsonl")).expect("read"), b"tail\n");
}

// ---- CT-W7: delete --------------------------------------------------------------------------------------------------

/// CT-W7: `delete_tree` renames while holding the OS hold, then releases, then wipes; afterwards a mutating call on a
/// surviving clone returns `Gone` and writes nothing, and the slot stays held until the last clone drops.
#[test]
fn ct_w7_delete_tree_order_and_gone_after() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("w7");
    let session = dir.path().join(&id);
    let rt = rt();
    std::fs::create_dir_all(&session).expect("mkdir");
    std::fs::write(session.join("updates.jsonl"), b"{}\n").expect("seed");
    let writer =
        rt.block_on(SessionWriter::claim(&id, &session, Instant::now() + Duration::from_secs(5))).expect("claim");
    assert!(!foreign_could_take(&session), "eager attach holds the lock");
    let survivor = writer.clone();
    let log: Arc<Mutex<Vec<String>>> = Arc::default();
    let tombstone = dir.path().join(format!("{}{id}-{}", crate::DELETING_PREFIX, std::process::id()));
    let (log2, session2, tomb2) = (log.clone(), session.clone(), tombstone.clone());
    crate::delete_observer::set(Some(Box::new(move |step| {
        // Only this test's steps: the observer is process-wide.
        let state = match step {
            "local_rename" => format!("{step}:orig={}:tomb={}:held={}", session2.exists(), tomb2.exists(), !foreign_could_take(&tomb2)),
            _ => step.to_owned(),
        };
        log2.lock().expect("log").push(state);
    })));
    writer.delete_tree_sync().expect("delete");
    crate::delete_observer::set(None);
    assert_eq!(
        *log.lock().expect("log"),
        vec!["local_rename:orig=false:tomb=true:held=true".to_owned(), "hold_released".into(), "local_wipe".into()]
    );
    assert!(!session.exists() && !tombstone.exists());
    let error = survivor.append_sync("updates.jsonl", b"late").expect_err("Gone");
    assert_eq!(refusal(&error), Some(Refusal::Gone));
    assert_eq!(refusal(&survivor.delete_tree_sync().expect_err("Gone")), Some(Refusal::Gone));
    assert!(!session.exists(), "a late write recreated the folder");
    assert!(!SessionWriter::is_free(&id), "the slot is held until the last clone drops");
    drop((writer, survivor));
    assert!(SessionWriter::is_free(&id));
}

// ---- CT-W8: paths stay inside the folder ------------------------------------------------------------------------------

/// CT-W8: a `rel` with `..`, a root or `.` is refused; subdirectory creation never leaves the folder, and a folder
/// removed underneath is not recreated by a subdirectory write.
#[test]
fn ct_w8_relative_paths_only_and_nothing_above_the_folder() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("w8");
    let session = dir.path().join("bucket").join(&id);
    let writer = SessionWriter::try_claim(&id, &session).expect("claim");
    for bad in ["../escape", "a/../../escape", "/abs/path", "./x", ""] {
        let error = writer.append_sync(bad, b"x").expect_err(bad);
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{bad}");
    }
    assert!(!session.exists(), "a refused path created the folder");
    assert!(!dir.path().join("escape").exists());
    writer.create_new_sync("subagents/c1/meta.json", b"{}").expect("nested");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for sub in ["subagents", "subagents/c1"] {
            let mode = std::fs::metadata(session.join(sub)).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{sub}");
        }
    }
    std::fs::remove_dir_all(&session).expect("removed underneath");
    let error = writer.create_new_sync("images/1.png", b"png").expect_err("must not recreate the folder");
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert!(!session.exists());
    assert_eq!(std::fs::read_dir(dir.path().join("bucket")).expect("bucket").count(), 0);
}

// ---- the rest of the write API ----------------------------------------------------------------------------------------

#[test]
fn write_api_round_trip() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("api");
    let session = dir.path().join(&id);
    let rt = rt();
    let w = SessionWriter::try_claim(&id, &session).expect("claim");
    rt.block_on(w.append("updates.jsonl", b"a\n".to_vec())).expect("append");
    w.append_sync("updates.jsonl", b"b").expect("append torn");
    w.append_line_checked_sync("updates.jsonl", b"c\n").expect("checked");
    assert_eq!(std::fs::read(session.join("updates.jsonl")).expect("read"), b"a\nb\nc\n");
    rt.block_on(w.replace_atomic("summary.json", b"{}".to_vec())).expect("replace");
    assert!(
        std::fs::read_dir(&session).expect("ls").all(|e| !e.expect("e").file_name().to_string_lossy().ends_with(".tmp")),
        "temporary sibling left behind"
    );
    let error = w.create_new_sync("summary.json", b"x").expect_err("exists");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    rt.block_on(w.create_new("mcp/c1.txt", b"dump".to_vec())).expect("create_new");
    rt.block_on(w.rename("mcp/c1.txt", "mcp/c1.corrupt")).expect("rename");
    rt.block_on(w.copy_in(session.join("summary.json"), "fork/summary.json")).expect("copy_in");
    rt.block_on(w.remove("mcp/c1.corrupt")).expect("remove");
    let lock = w.open_lock("turn_owner.lock").expect("lock sidecar");
    lock.try_lock().expect("lock it");
    let seen = w.summary(|summary, lock| Ok((summary.to_path_buf(), lock.to_path_buf()))).expect("summary");
    assert_eq!(seen, (session.join("summary.json"), session.join("summary.json.lock")));
    let other = SessionWriter::try_claim(unique_id("api-missing"), dir.path().join("missing")).expect("claim");
    let error = other.summary(|_, _| Ok(())).expect_err("summary never creates the folder");
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(other.remove_sync("x").expect_err("nor does remove").kind(), std::io::ErrorKind::NotFound);
    assert!(!dir.path().join("missing").exists());
}

// ---- trace marks --------------------------------------------------------------------------------------------------

#[test]
fn trace_marks_bracket_every_mutation_and_wait_for_directory_acks() {
    let home = tempfile::tempdir().expect("home");
    let marks = home.path().join("f5-marks");
    let acks = home.path().join("f5-acks");
    std::fs::create_dir_all(&acks).expect("acks");
    // The harness: acknowledge every `d.<gen>.<seq>.<hash>` mark.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let acker = std::thread::spawn({
        let (marks, acks, stop) = (marks.clone(), acks.clone(), stop.clone());
        move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(entries) = std::fs::read_dir(&marks) {
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if let Some(rest) = name.strip_prefix("d.") {
                            let ack: Vec<&str> = rest.splitn(3, '.').take(2).collect();
                            let _ = std::fs::File::create(acks.join(format!("d.{}", ack.join("."))));
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    });
    crate::trace::set_test_trace_dir(Some(marks.clone()));
    let id = unique_id("trace");
    let session = home.path().join("sessions").join(&id);
    let w = SessionWriter::try_claim(&id, &session).expect("claim");
    let generation = w.generation();
    w.append_sync("terminal/t.log", b"x").expect("append");
    w.replace_atomic_sync("summary.json", b"{}").expect("replace");
    drop(w);
    crate::trace::set_test_trace_dir(None);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    acker.join().expect("acker");
    let names: Vec<String> =
        std::fs::read_dir(&marks).expect("marks").map(|e| e.expect("e").file_name().to_string_lossy().into_owned()).collect();
    let has = |prefix: &str| names.iter().any(|n| n.starts_with(prefix));
    assert!(has(&format!("claim.{id}.{generation}")) && has(&format!("free.{id}.{generation}")), "{names:?}");
    let log_hash = crate::trace::path_hash(&session.join("terminal/t.log"));
    let summary_hash = crate::trace::path_hash(&session.join("summary.json"));
    for hash in [&log_hash, &summary_hash] {
        assert!(names.iter().any(|n| n.starts_with(&format!("b.{generation}.")) && n.ends_with(hash.as_str())), "{names:?}");
        assert!(names.iter().any(|n| n.starts_with(&format!("e.{generation}.")) && n.ends_with(hash.as_str())), "{names:?}");
    }
    for created in [session.clone(), session.join("terminal")] {
        let hash = crate::trace::path_hash(&created);
        assert!(names.iter().any(|n| n.starts_with(&format!("d.{generation}.")) && n.ends_with(&hash)), "{names:?}");
    }
    assert!(!has("dto.") && !has("x."), "{names:?}");
}

/// The independent detector (§9.4): a write that bypasses the writer between its `b` mark and its own syscall makes an
/// `x` mark.
#[test]
fn trace_detects_a_same_path_write_inside_the_window() {
    let home = tempfile::tempdir().expect("home");
    let marks = home.path().join("f5-marks");
    std::fs::create_dir_all(home.path().join("f5-acks")).expect("acks");
    let id = unique_id("x");
    let session = home.path().join(&id);
    std::fs::create_dir_all(&session).expect("mkdir");
    std::fs::write(session.join("updates.jsonl"), b"a\n").expect("seed");
    let hash = crate::trace::path_hash(&session.join("updates.jsonl"));
    let gate = seams::arm(&format!("trace-b:{hash}"));
    let writer = SessionWriter::try_claim(&id, &session).expect("claim");
    let generation = writer.generation();
    let thread = std::thread::spawn({
        let marks = marks.clone();
        move || {
            crate::trace::set_test_trace_dir(Some(marks));
            writer.append_sync("updates.jsonl", b"b\n").expect("append");
        }
    });
    assert!(gate.wait_reached(SEAM));
    std::fs::OpenOptions::new().append(true).open(session.join("updates.jsonl")).expect("bypass").write_all(b"bypass\n").expect("w");
    gate.open();
    thread.join().expect("join");
    let names: Vec<String> =
        std::fs::read_dir(&marks).expect("marks").map(|e| e.expect("e").file_name().to_string_lossy().into_owned()).collect();
    assert!(names.iter().any(|n| n.starts_with(&format!("x.{generation}."))), "{names:?}");
}

// ---- F5-C3: move_in, hard_link_in_no_replace ------------------------------------------------------------------------

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).expect("meta").permissions().mode() & 0o777
}

fn no_tmp_left(dir: &Path) -> bool {
    std::fs::read_dir(dir).expect("ls").all(|e| !e.expect("e").file_name().to_string_lossy().ends_with(".tmp"))
}

#[test]
fn c3_move_in_renames_a_staged_file_into_the_folder_replacing_the_target() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("mv");
    let session = dir.path().join("sessions").join(&id);
    let staged = dir.path().join("staging").join("updates.jsonl");
    std::fs::create_dir_all(staged.parent().expect("p")).expect("staging");
    std::fs::write(&staged, b"staged\n").expect("stage");
    let w = SessionWriter::try_claim(&id, &session).expect("claim");
    w.append_sync("updates.jsonl", b"old\n").expect("seed through the writer");
    w.move_in_sync(&staged, "updates.jsonl").expect("move_in");
    assert_eq!(std::fs::read(session.join("updates.jsonl")).expect("read"), b"staged\n");
    assert!(!staged.exists(), "a rename leaves nothing staged");
    rt().block_on(w.move_in(dir.path().join("missing"), "x")).expect_err("a missing source is an error");
    assert!(!session.join("x").exists());
    assert!(no_tmp_left(&session));
    let error = w.move_in_sync(&staged, "../escape").expect_err("relative inside only");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn c3_move_in_across_filesystems_copies_owner_only_then_removes_the_source() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("mvx");
    let session = dir.path().join(&id);
    let staged = dir.path().join("staged.jsonl");
    std::fs::write(&staged, b"cross\n").expect("stage");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    }
    let w = SessionWriter::try_claim(&id, &session).expect("claim");
    crate::writer::FORCE_EXDEV.with(|f| f.set(true));
    let moved = w.move_in_sync(&staged, "sub/updates.jsonl");
    crate::writer::FORCE_EXDEV.with(|f| f.set(false));
    moved.expect("the EXDEV fallback");
    assert_eq!(std::fs::read(session.join("sub/updates.jsonl")).expect("read"), b"cross\n");
    assert!(!staged.exists(), "the fallback removes the staged original once the copy landed");
    assert!(no_tmp_left(&session.join("sub")));
    #[cfg(unix)]
    assert_eq!(mode_of(&session.join("sub/updates.jsonl")), 0o600, "owner-only whatever the source's mode");
}

#[test]
fn c3_hard_link_in_no_replace_publishes_once_and_never_replaces() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("ln");
    let session = dir.path().join(&id);
    let w = SessionWriter::try_claim(&id, &session).expect("claim");
    w.create_new_sync("chat.a.tmp", b"first").expect("stage a");
    w.create_new_sync("chat.b.tmp", b"second").expect("stage b");
    w.hard_link_in_no_replace_sync("chat.a.tmp", "chat.pre-repair").expect("first publisher wins");
    let error = w.hard_link_in_no_replace_sync("chat.b.tmp", "chat.pre-repair").expect_err("never replaces");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(session.join("chat.pre-repair")).expect("read"), b"first");
    w.remove_sync("chat.a.tmp").expect("unstage");
    assert_eq!(std::fs::read(session.join("chat.pre-repair")).expect("read"), b"first", "a link, not a name");
    let other = SessionWriter::try_claim(unique_id("ln-missing"), dir.path().join("missing")).expect("claim");
    let error = other.hard_link_in_no_replace_sync("a", "b").expect_err("never creates the folder");
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert!(!dir.path().join("missing").exists());
    let error = w.hard_link_in_no_replace_sync("chat.b.tmp", "/abs").expect_err("relative only");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn c3_move_in_and_hard_link_refuse_a_folder_held_by_another_process() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("c3held");
    let session = dir.path().join(&id);
    std::fs::create_dir_all(&session).expect("mkdir");
    std::fs::write(session.join("chat.tmp"), b"x").expect("seed");
    let staged = dir.path().join("staged");
    std::fs::write(&staged, b"staged").expect("stage");
    let mut holder = foreign_process_hold(&session);
    let before = snapshot(&session);
    let writer = SessionWriter::try_claim(&id, &session).expect("in-process slot is free");
    let error = writer.move_in_sync(&staged, "updates.jsonl").expect_err("move_in must be refused");
    assert_eq!(refusal(&error), Some(Refusal::HeldElsewhere), "{error}");
    let error = writer.hard_link_in_no_replace_sync("chat.tmp", "chat.pre-repair").expect_err("link must be refused");
    assert_eq!(refusal(&error), Some(Refusal::HeldElsewhere), "{error}");
    assert_eq!(snapshot(&session), before, "the folder changed");
    assert!(staged.exists(), "a refused move keeps the staged file");
    drop(writer);
    holder.kill().expect("kill");
    holder.wait().expect("reap");
}

#[test]
fn c3_trace_marks_bracket_move_in_and_hard_link() {
    let home = tempfile::tempdir().expect("home");
    let marks = home.path().join("f5-marks");
    std::fs::create_dir_all(home.path().join("f5-acks")).expect("acks");
    let id = unique_id("c3trace");
    let session = home.path().join(&id);
    // The folder exists, so no directory is created and no acknowledgement is awaited.
    std::fs::create_dir_all(&session).expect("mkdir");
    let staged = home.path().join("staged");
    std::fs::write(&staged, b"s").expect("stage");
    crate::trace::set_test_trace_dir(Some(marks.clone()));
    let w = SessionWriter::try_claim(&id, &session).expect("claim");
    let generation = w.generation();
    w.move_in_sync(&staged, "updates.jsonl").expect("move_in");
    w.hard_link_in_no_replace_sync("updates.jsonl", "updates.link").expect("link");
    drop(w);
    crate::trace::set_test_trace_dir(None);
    let names: Vec<String> =
        std::fs::read_dir(&marks).expect("marks").map(|e| e.expect("e").file_name().to_string_lossy().into_owned()).collect();
    for rel in ["updates.jsonl", "updates.link"] {
        let hash = crate::trace::path_hash(&session.join(rel));
        for kind in ["b", "e"] {
            assert!(
                names.iter().any(|n| n.starts_with(&format!("{kind}.{generation}.")) && n.ends_with(hash.as_str())),
                "{kind} mark for {rel}: {names:?}"
            );
        }
    }
    assert!(!names.iter().any(|n| n.starts_with("x.") || n.starts_with("dto.")), "{names:?}");
}

// ---- F5-B5 (box B4): a freed writer leaves no handle open ----------------------------------------------------------

/// The open descriptors of this process that point at one of `paths`.
#[cfg(target_os = "linux")]
fn open_fds_to(paths: &[PathBuf]) -> Vec<PathBuf> {
    let wanted: Vec<PathBuf> = paths.iter().map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone())).collect();
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| {
            entries.flatten().filter_map(|entry| std::fs::read_link(entry.path()).ok()).filter(|t| wanted.contains(t)).collect()
        })
        .unwrap_or_default()
}

/// Design §6.1 (box B4): an append handle that holds the writer's last clone has closed its file when the writer is
/// freed (paused at the free, `/proc/self/fd` has no descriptor of it). Before B5 the handle dropped its writer clone
/// first and closed `events.jsonl` after the free.
#[cfg(target_os = "linux")]
#[test]
fn f5b5_an_append_handle_closes_its_file_before_the_writer_is_free() {
    let dir = tempfile::tempdir().expect("dir");
    let id = unique_id("b5-append");
    let writer = SessionWriter::try_claim(&id, dir.path().join("s")).expect("claim");
    let append = writer.open_append("events.jsonl").expect("open");
    append.write_all(b"{}\n").expect("append");
    drop(writer);
    let events = dir.path().join("s").join("events.jsonl");
    assert_eq!(open_fds_to(std::slice::from_ref(&events)).len(), 1, "fixture: the handle holds events.jsonl open");
    let gate = seams::arm(&format!("drop:{id}"));
    let dropper = std::thread::spawn(move || drop(append));
    assert!(gate.wait_reached(SEAM), "the writer was never freed");
    let open = open_fds_to(std::slice::from_ref(&events));
    gate.open();
    dropper.join().expect("join");
    assert!(open.is_empty(), "events.jsonl was still open when its writer was freed: {open:?}");
    assert!(SessionWriter::is_free(&id));
}

/// Review r1 H2: a fork in another process opens a held session's lock sidecars read-only and never creates one, so
/// they must exist as soon as the session is held: at the first write of a cold folder, and at a claim of an existing one.
#[tokio::test]
async fn r1h2_the_lock_sidecars_exist_once_the_hold_attaches() {
    const SIDECARS: [&str; 3] = ["snapshot.lock", "chat_history.jsonl.lock", "updates.jsonl.lock"];
    let root = tempfile::tempdir().unwrap();
    let cold = root.path().join("r1h2-cold");
    let first = SessionWriter::try_claim("r1h2-cold", &cold).unwrap();
    first.append_sync("events.jsonl", b"x\n").unwrap();
    let warm = root.path().join("r1h2-warm");
    std::fs::create_dir_all(&warm).unwrap();
    let claimed = SessionWriter::claim("r1h2-warm", &warm, Instant::now() + Duration::from_secs(5)).await.unwrap();
    for (dir, what) in [(&cold, "first write of a cold folder"), (&warm, "claim of an existing folder")] {
        for name in SIDECARS {
            assert!(dir.join(name).is_file(), "{name} missing after the {what}");
        }
    }
    drop((first, claimed));
}
