use super::*;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime")
}

/// Another process's hold, as the test makes it: a second open of the lock file excludes this process's own open exactly
/// as another process's would (the OS lock belongs to the open file).
fn foreign_hold(dir: &Path) -> std::fs::File {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(SESSION_WRITER_LOCK_FILE))
        .expect("open");
    file.try_lock().expect("foreign hold");
    file
}

fn foreign_could_take(dir: &Path) -> bool {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(SESSION_WRITER_LOCK_FILE))
        .expect("open");
    match file.try_lock() {
        Ok(()) => {
            file.unlock().expect("unlock");
            true
        }
        Err(std::fs::TryLockError::WouldBlock) => false,
        Err(std::fs::TryLockError::Error(e)) => panic!("{e}"),
    }
}

#[test]
fn a_session_held_elsewhere_is_refused_and_free_once_released() {
    let dir = tempfile::tempdir().expect("dir");
    let other = foreign_hold(dir.path());
    assert!(dir_open_elsewhere(dir.path()));
    let refused = rt().block_on(acquire(dir.path()));
    assert!(matches!(refused, Err(HeldElsewhere)), "{refused:?}");
    let error = HeldElsewhere.into_acp_error();
    assert!(format!("{error:?}").contains(HELD_ELSEWHERE), "{error:?}");
    drop(other);
    assert!(!dir_open_elsewhere(dir.path()));
    let lock = rt().block_on(acquire(dir.path())).expect("free").expect("locked");
    assert!(!foreign_could_take(dir.path()));
    // This process's own hold is not "elsewhere".
    assert!(!dir_open_elsewhere(dir.path()));
    drop(lock);
    assert!(foreign_could_take(dir.path()));
}

#[test]
fn holds_in_one_process_are_counted_and_the_last_one_releases() {
    let dir = tempfile::tempdir().expect("dir");
    let first = rt().block_on(acquire(dir.path())).expect("first").expect("locked");
    let second = rt().block_on(acquire(dir.path())).expect("re-entrant").expect("locked");
    assert!(!foreign_could_take(dir.path()));
    drop(first);
    assert!(!foreign_could_take(dir.path()), "released while another hold in this process is live");
    drop(second);
    assert!(foreign_could_take(dir.path()));
    let again = rt().block_on(acquire(dir.path())).expect("again").expect("locked");
    drop(again);
}

#[test]
fn nothing_is_locked_or_created_without_a_session_folder() {
    let dir = tempfile::tempdir().expect("dir");
    let missing = dir.path().join("no-such-session");
    assert!(rt().block_on(acquire(&missing)).expect("no folder").is_none());
    assert!(!missing.exists());
    assert!(!dir_open_elsewhere(&missing));
    // The early check never creates the lock file.
    assert!(!dir_open_elsewhere(dir.path()));
    assert!(!dir.path().join(SESSION_WRITER_LOCK_FILE).exists());
}

const HOLDER: &str = "session::session_writer_lock::tests::holder_process";
const HOLDER_DIR: &str = "FUIGO_P30_DIRECT_HOLDER_DIR";

/// Child of [`a_crashed_holder_releases_the_session`]: holds the session and waits to be killed.
#[test]
#[ignore = "helper process for a_crashed_holder_releases_the_session"]
fn holder_process() {
    let Some(dir) = std::env::var_os(HOLDER_DIR) else { return };
    let lock = rt().block_on(acquire(Path::new(&dir))).expect("holder").expect("locked");
    println!("HOLDER_READY");
    std::thread::sleep(Duration::from_secs(120));
    drop(lock);
}

/// A real second process holds the session; killing it (no cleanup runs) frees the session at once.
#[test]
fn a_crashed_holder_releases_the_session() {
    use std::io::BufRead as _;
    let dir = tempfile::tempdir().expect("dir");
    // Not enrolled in a process scope: this test kills and reaps it itself.
    #[allow(clippy::disallowed_methods)]
    let mut child = std::process::Command::new(std::env::current_exe().expect("test exe"))
        .args(["--exact", HOLDER, "--ignored", "--nocapture", "--test-threads=1"])
        .env(HOLDER_DIR, dir.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn holder");
    let mut ready = false;
    for line in std::io::BufReader::new(child.stdout.take().expect("stdout")).lines() {
        if line.expect("line").contains("HOLDER_READY") {
            ready = true;
            break;
        }
    }
    assert!(ready, "holder process never took the session");
    assert!(dir_open_elsewhere(dir.path()), "the other process's hold is not seen");
    assert!(matches!(rt().block_on(acquire(dir.path())), Err(HeldElsewhere)));
    child.kill().expect("kill holder");
    child.wait().expect("reap holder");
    let lock = rt().block_on(acquire(dir.path())).expect("released by the crash").expect("locked");
    drop(lock);
}
