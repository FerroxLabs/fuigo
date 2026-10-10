use super::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn collects_top_level_files_with_flat_names() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("chat_history.jsonl"), b"line1\nline2").unwrap();
    fs::write(dir.path().join("summary.json"), b"{}").unwrap();

    let mut files = Vec::new();
    collect_session_files_recursive(dir.path(), dir.path(), &mut files);

    files.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, "chat_history.jsonl");
    assert_eq!(files[0].data, b"line1\nline2");
    assert_eq!(files[1].name, "summary.json");
    assert_eq!(files[1].data, b"{}");
}

#[test]
fn collects_subdirectory_files_with_relative_paths() {
    let dir = TempDir::new().unwrap();
    let prompts_dir = dir.path().join("prompts");
    fs::create_dir(&prompts_dir).unwrap();
    fs::write(prompts_dir.join("prompt_0.txt"), b"long prompt content").unwrap();
    fs::write(prompts_dir.join("prompt_1.txt"), b"another long prompt").unwrap();
    fs::write(dir.path().join("summary.json"), b"{}").unwrap();

    let mut files = Vec::new();
    collect_session_files_recursive(dir.path(), dir.path(), &mut files);

    files.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(files.len(), 3);
    assert_eq!(files[0].name, "prompts/prompt_0.txt");
    assert_eq!(files[0].data, b"long prompt content");
    assert_eq!(files[1].name, "prompts/prompt_1.txt");
    assert_eq!(files[2].name, "summary.json");
}

#[test]
fn collects_nested_subdirectories() {
    let dir = TempDir::new().unwrap();
    let deep = dir.path().join("a").join("b");
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("deep.txt"), b"deep").unwrap();
    fs::write(dir.path().join("top.txt"), b"top").unwrap();

    let mut files = Vec::new();
    collect_session_files_recursive(dir.path(), dir.path(), &mut files);

    files.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, "a/b/deep.txt");
    assert_eq!(files[1].name, "top.txt");
}

#[test]
fn nonexistent_directory_returns_empty() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("does_not_exist");

    let mut files = Vec::new();
    collect_session_files_recursive(&missing, &missing, &mut files);

    assert!(files.is_empty());
}

#[test]
fn empty_directory_returns_empty() {
    let dir = TempDir::new().unwrap();

    let mut files = Vec::new();
    collect_session_files_recursive(dir.path(), dir.path(), &mut files);

    assert!(files.is_empty());
}

#[test]
fn skips_empty_subdirectories() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("empty_subdir")).unwrap();
    fs::write(dir.path().join("file.txt"), b"data").unwrap();

    let mut files = Vec::new();
    collect_session_files_recursive(dir.path(), dir.path(), &mut files);

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "file.txt");
}

// P194 (U13): terminal and MCP logs are bounded at every turn end.

#[test]
fn trims_oversized_terminal_logs_to_both_ends_but_never_caps_other_files() {
    let dir = TempDir::new().unwrap();
    let cap = archive_logs::MAX_ARCHIVED_LOG_BYTES as usize;
    fs::create_dir(dir.path().join("terminal")).unwrap();
    fs::create_dir(dir.path().join("images")).unwrap();
    let big_log = [vec![b'h'; cap], vec![b't'; cap]].concat();
    fs::write(dir.path().join("terminal/big.log"), &big_log).unwrap();
    fs::write(dir.path().join("terminal/small.log"), b"ok").unwrap();
    for name in ["images/big.png", "chat_history.jsonl"] {
        fs::File::create(dir.path().join(name))
            .unwrap()
            .set_len(cap as u64 + 1)
            .unwrap();
    }

    let mut files = Vec::new();
    collect_session_files_recursive(dir.path(), dir.path(), &mut files);
    files.sort_by(|a, b| a.name.cmp(&b.name));

    let sizes: Vec<_> = files
        .iter()
        .map(|f| (f.name.as_str(), f.data.len()))
        .collect();
    assert_eq!(
        sizes,
        [
            ("chat_history.jsonl", cap + 1),
            ("images/big.png", cap + 1),
            ("terminal/big.log", cap + archive_logs::TRIM_MARKER.len()),
            ("terminal/small.log", 2),
        ]
    );
    let trimmed = &files[2].data;
    assert!(trimmed.starts_with(&vec![b'h'; cap / 2]));
    assert!(trimmed.ends_with(&vec![b't'; cap / 2]));
}

#[test]
fn admits_newest_terminal_logs_until_the_copy_budget_is_spent() {
    use std::time::{Duration, SystemTime};

    let dir = TempDir::new().unwrap();
    let terminal = dir.path().join("terminal");
    fs::create_dir(&terminal).unwrap();
    let per_log = archive_logs::MAX_ARCHIVED_LOG_BYTES;
    let fits = (archive_logs::MAX_ARCHIVED_TERMINAL_BYTES / per_log) as usize;
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    for i in 0..=fits {
        let log = fs::File::create(terminal.join(format!("{i:02}.log"))).unwrap();
        log.set_len(per_log).unwrap();
        log.set_modified(t0 + Duration::from_secs(i as u64))
            .unwrap();
    }

    let mut files = Vec::new();
    collect_session_files_recursive(dir.path(), dir.path(), &mut files);

    let mut names: Vec<_> = files.iter().map(|f| f.name.clone()).collect();
    names.sort_unstable();
    let newest: Vec<_> = (1..=fits).map(|i| format!("terminal/{i:02}.log")).collect();
    assert_eq!(names, newest, "the oldest log is the one left out");
}

/// P146 stays: a symlinked `terminal/` directory, or a symlinked log inside it, copies nothing from outside the session.
#[cfg(unix)]
#[test]
fn terminal_logs_never_follow_a_symlink() {
    let dir = TempDir::new().unwrap();
    let elsewhere = TempDir::new().unwrap();
    fs::write(elsewhere.path().join("outside.log"), b"not session data").unwrap();
    fs::write(dir.path().join("summary.json"), b"{}").unwrap();

    std::os::unix::fs::symlink(elsewhere.path(), dir.path().join("terminal")).unwrap();
    let mut files = Vec::new();
    collect_session_files_recursive(dir.path(), dir.path(), &mut files);
    let names: Vec<_> = files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["summary.json"], "a symlinked terminal/ directory");

    fs::remove_file(dir.path().join("terminal")).unwrap();
    fs::create_dir(dir.path().join("terminal")).unwrap();
    fs::write(dir.path().join("terminal/real.log"), b"real").unwrap();
    std::os::unix::fs::symlink(
        elsewhere.path().join("outside.log"),
        dir.path().join("terminal/link.log"),
    )
    .unwrap();
    let mut files = Vec::new();
    collect_session_files_recursive(dir.path(), dir.path(), &mut files);
    files.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        ["summary.json", "terminal/real.log"],
        "a symlinked log"
    );
}

#[test]
fn a_log_that_fits_is_read_whole_and_one_that_does_not_keeps_both_ends() {
    let dir = TempDir::new().unwrap();
    let cap = archive_logs::MAX_ARCHIVED_LOG_BYTES as usize;
    let small = dir.path().join("small.log");
    fs::write(&small, b"whole").unwrap();
    assert_eq!(
        archive_logs::read_log_for_archive(fs::File::open(&small).unwrap()).unwrap(),
        b"whole"
    );
    let big = dir.path().join("big.log");
    fs::write(&big, [vec![b'a'; cap], vec![b'z'; cap]].concat()).unwrap();
    let data = archive_logs::read_log_for_archive(fs::File::open(&big).unwrap()).unwrap();
    assert_eq!(data.len(), cap + archive_logs::TRIM_MARKER.len());
    assert!(data.starts_with(&vec![b'a'; cap / 2]));
    assert!(data.ends_with(&vec![b'z'; cap / 2]));
}

#[test]
#[serial_test::serial]
fn mcp_stderr_logs_in_the_archive_keep_both_ends_of_an_oversized_log() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = TempDir::new().unwrap();
    let _env = fuigo_test_support::EnvGuard::set("FUIGO_HOME", home.path());
    let cap = archive_logs::MAX_ARCHIVED_LOG_BYTES as usize;
    let logs = home.path().join("logs").join("mcp");
    fs::create_dir_all(&logs).unwrap();
    fs::write(logs.join("big.log"), [vec![b'h'; cap], vec![b't'; cap]].concat()).unwrap();
    fs::write(logs.join("small.log"), b"ok").unwrap();

    let mut files = Vec::new();
    collect_mcp_stderr_logs(&mut files);
    files.sort_by(|a, b| a.name.cmp(&b.name));

    let sizes: Vec<_> = files
        .iter()
        .map(|f| (f.name.as_str(), f.data.len()))
        .collect();
    assert_eq!(
        sizes,
        [
            ("mcp_stderr/big.log", cap + archive_logs::TRIM_MARKER.len()),
            ("mcp_stderr/small.log", 2),
        ]
    );
    assert!(files[0].data.starts_with(&vec![b'h'; cap / 2]));
    assert!(files[0].data.ends_with(&vec![b't'; cap / 2]));
}

// ---- Round 2 (Grok r1, U13) ----

/// A log that is over the cap at `stat` and shrinks before the tail seek is kept (capped), never dropped.
/// The race is controlled by `read_log_with_hook`, which runs between the head read and the tail seek: the
/// test truncates the same file there through a second handle.
#[test]
fn a_log_that_shrinks_between_the_size_check_and_the_tail_read_is_not_dropped() {
    let dir = TempDir::new().unwrap();
    let cap = archive_logs::MAX_ARCHIVED_LOG_BYTES as usize;
    let path = dir.path().join("rotating.log");
    fs::write(&path, vec![b'x'; cap * 2]).unwrap();
    let file = fs::File::open(&path).unwrap();
    let data = archive_logs::read_log_with_hook(file, || {
        fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(100).unwrap();
    })
    .expect("a shrunk log is still read");
    assert_eq!(data, vec![b'x'; 100]);
}

#[test]
fn a_log_that_shrinks_to_just_under_the_cap_is_not_kept_twice() {
    let dir = TempDir::new().unwrap();
    let cap = archive_logs::MAX_ARCHIVED_LOG_BYTES as usize;
    let path = dir.path().join("rotating.log");
    fs::write(&path, vec![b'x'; cap * 2]).unwrap();
    let file = fs::File::open(&path).unwrap();
    let data = archive_logs::read_log_with_hook(file, || {
        fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(cap as u64 - 10).unwrap();
    })
    .unwrap();
    assert_eq!(data.len(), cap - 10, "the current content once, no marker");
}

#[cfg(unix)]
#[test]
#[serial_test::serial]
fn mcp_stderr_logs_never_follow_a_symlink_or_wait_on_a_fifo() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = TempDir::new().unwrap();
    let _env = fuigo_test_support::EnvGuard::set("FUIGO_HOME", home.path());
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("secret.txt"), b"not an mcp log").unwrap();
    let logs = home.path().join("logs").join("mcp");
    fs::create_dir_all(&logs).unwrap();
    fs::write(logs.join("real.log"), b"real").unwrap();
    std::os::unix::fs::symlink(outside.path().join("secret.txt"), logs.join("evil.log")).unwrap();
    let fifo = std::ffi::CString::new(logs.join("pipe.log").to_str().unwrap()).unwrap();
    // SAFETY: mkfifo(2) on a NUL-terminated path in a temp dir.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut files = Vec::new();
        collect_mcp_stderr_logs(&mut files);
        let _ = tx.send(files);
    });
    let files = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("a FIFO in logs/mcp must not hang the archive");
    let names: Vec<_> = files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["mcp_stderr/real.log"]);
}

#[test]
fn a_trim_never_splits_a_utf8_codepoint() {
    let dir = TempDir::new().unwrap();
    let cap = archive_logs::MAX_ARCHIVED_LOG_BYTES as usize;
    // 3-byte codepoints: the half (512 KiB) is not a multiple of 3, so both cuts land inside one.
    let text = "€".repeat(cap * 2 / 3 + 10);
    let path = dir.path().join("utf8.log");
    fs::write(&path, &text).unwrap();
    let data = archive_logs::read_log_for_archive(fs::File::open(&path).unwrap()).unwrap();
    assert!(std::str::from_utf8(&data).is_ok(), "the archived log is still valid UTF-8");
    assert!(data.len() <= cap + archive_logs::TRIM_MARKER.len());
}

#[test]
fn a_trim_leaves_a_non_utf8_log_as_bytes() {
    let dir = TempDir::new().unwrap();
    let cap = archive_logs::MAX_ARCHIVED_LOG_BYTES as usize;
    let path = dir.path().join("binary.log");
    fs::write(&path, [vec![0xFF_u8; cap], vec![0x80_u8; cap]].concat()).unwrap();
    let data = archive_logs::read_log_for_archive(fs::File::open(&path).unwrap()).unwrap();
    assert_eq!(data.len(), cap + archive_logs::TRIM_MARKER.len());
}

#[test]
fn logs_with_equal_mtimes_are_admitted_in_a_stable_order() {
    let dir = TempDir::new().unwrap();
    let term = dir.path().join("terminal");
    fs::create_dir(&term).unwrap();
    let cap = archive_logs::MAX_ARCHIVED_LOG_BYTES as usize;
    let when = std::time::SystemTime::now();
    // 17 full logs, one more than the 16 MiB budget holds, all with the same mtime.
    for i in 0..17 {
        let f = fs::File::create(term.join(format!("{i:02}.log"))).unwrap();
        f.set_len(cap as u64).unwrap();
        f.set_modified(when).unwrap();
    }
    let kept = || {
        let mut files = Vec::new();
        archive_logs::collect_terminal_logs(dir.path(), &mut files);
        let mut names: Vec<_> = files.into_iter().map(|f| f.name).collect();
        names.sort();
        names
    };
    let first = kept();
    assert_eq!(first.len(), 16);
    for _ in 0..5 {
        assert_eq!(kept(), first, "the same logs are left out every time");
    }
    assert!(!first.contains(&"terminal/16.log".to_string()), "ties go by name: the last name is left out");
}

#[test]
fn a_nested_file_is_recorded_with_forward_slashes() {
    let dir = TempDir::new().unwrap();
    let deep = dir.path().join("a").join("b");
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("deep.txt"), b"x").unwrap();

    let mut files = Vec::new();
    collect_session_files_recursive(dir.path(), dir.path(), &mut files);

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "a/b/deep.txt");
}
