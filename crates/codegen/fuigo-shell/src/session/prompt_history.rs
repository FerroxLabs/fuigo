//! Per-working-directory prompt history for fast reverse search.
//!
//! Stores prompts in a separate JSONL file per CWD for instant loading, independent of session storage.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;

const MAX_PROMPT_HISTORY_ENTRIES: usize = 10_000;
const PROMPT_HISTORY_FILE: &str = "prompt_history.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptEntry {
    pub timestamp: DateTime<Utc>,
    pub session_id: String,
    pub prompt: String,
    /// Whether this prompt was a direct bash command (vs. an AI prompt).
    /// Defaults to `false` for backward compatibility: entries written before this field existed are treated as non-bash.
    /// Shell history files (`~/.bash_history` etc.) compensate for this gap.
    #[serde(default)]
    pub is_bash: bool,
}

pub(crate) fn prompt_history_path(cwd: &str) -> PathBuf {
    crate::util::fuigo_home::sessions_cwd_dir(cwd).join(PROMPT_HISTORY_FILE)
}

/// Append a prompt to the history file (synchronous, fast append-only).
/// Creates parent directories if they don't exist.
///
/// Holds the file's state lock (`fuigo_config::fs_atomic::lock_state_file`)
/// for the append (P72), the lock [`truncate_if_needed`] rewrites the file
/// under: an append that landed between the truncation's read and its rename
/// went into the replaced file and was lost.
pub(crate) fn append_prompt(cwd: &str, entry: &PromptEntry) -> io::Result<()> {
    let path = prompt_history_path(cwd);
    crate::util::fuigo_home::ensure_sessions_cwd_dir(cwd)?;
    // The file exists before the lock is taken (P79): a state lock covers the
    // file's inode as well as its name, and a file created under a lock taken
    // for a missing one would be covered by name only (a hard link made to it
    // while this append is still writing would not wait). An empty history
    // is harmless to every reader.
    // Every prompt typed in this project: owner-only like the session files beside it (P150, S14). Created 0600, and a
    // file an older version left looser is tightened (best effort; the truncation's rewrite keeps the mode).
    if !path.exists() {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(&path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if std::fs::metadata(&path).is_ok_and(|m| m.permissions().mode() & 0o777 != 0o600) {
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
    let _lock = fuigo_config::fs_atomic::lock_state_file(&path)?;
    #[cfg(test)]
    under_lock_seam::run(under_lock_seam::Site::Append);

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    let mut line =
        serde_json::to_vec(entry).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    line.push(b'\n');
    file.write_all(&line)?;
    Ok(())
}

/// Returns prompts in reverse chronological order (most recent first).
pub(crate) fn load_prompts(cwd: &str) -> io::Result<Vec<String>> {
    load_prompts_filtered(cwd, |_| true)
}

/// Returns prompts in reverse chronological order (most recent first), matching `load_prompts` ordering.
/// The pager's up-arrow / Ctrl+R history overlay uses this when it wants only the current session's prompts.
pub(crate) fn load_prompts_for_session(cwd: &str, session_id: &str) -> io::Result<Vec<String>> {
    load_prompts_filtered(cwd, |e| e.session_id == session_id)
}

/// Truncate the history file to MAX_PROMPT_HISTORY_ENTRIES if it exceeds the limit.
///
/// The shared read-modify-write (`fuigo_config::fs_atomic::edit_state_file`,
/// P72), on the lock every [`append_prompt`] holds: the replacement is renamed
/// in only if the file is still the version that was cut down, so a prompt
/// appended meanwhile (by any session, in any process) is never dropped. The
/// temp name is unique (two sessions truncating at once shared the fixed
/// `prompt_history.jsonl.tmp`), and the file keeps its mode.
pub(crate) fn truncate_if_needed(cwd: &str) -> io::Result<()> {
    truncate_file_if_needed(&prompt_history_path(cwd), MAX_PROMPT_HISTORY_ENTRIES)
}

/// [`truncate_if_needed`] of the file at `path`, keeping at most `max` entries.
fn truncate_file_if_needed(path: &std::path::Path, max: usize) -> io::Result<()> {
    use fuigo_config::fs_atomic::Edit;
    if !path.exists() {
        return Ok(());
    }
    fuigo_config::fs_atomic::edit_state_file(
        path,
        |bytes| {
            fuigo_config::write_through::stage_file_atomically_with(
                path,
                bytes,
                fuigo_config::write_through::NewFileMode::Default,
            )
        },
        |current| {
            let bytes = match current {
                Ok(Some(bytes)) => bytes,
                Ok(None) => return Ok(Edit::Keep(())),
                Err(e) => return Err(io::Error::new(e.kind(), e.to_string())),
            };
            #[cfg(test)]
            under_lock_seam::run(under_lock_seam::Site::Truncate);
            let entries: Vec<PromptEntry> = BufReader::new(bytes)
                .lines()
                .map_while(Result::ok)
                .filter(|line| !line.trim().is_empty())
                .filter_map(|line| serde_json::from_str(&line).ok())
                .collect();
            if entries.len() <= max {
                return Ok(Edit::Keep(()));
            }
            // Keep the most recent entries
            let mut contents = Vec::new();
            for entry in &entries[entries.len() - max..] {
                serde_json::to_writer(&mut contents, entry)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                contents.push(b'\n');
            }
            Ok(Edit::Replace { contents, value: () })
        },
    )
    .map_err(io::Error::from)
}

/// Test seam (P79): a hook run on the writing thread while it holds the
/// history's state lock -- in the truncation once the edit has read the file
/// (in its locked pass; before the replacement is staged), in the append
/// right after the lock is taken. It is what lets a test act inside the
/// window the lock exists for.
#[cfg(test)]
mod under_lock_seam {
    use std::cell::RefCell;

    type Hook = Option<Box<dyn FnMut()>>;

    #[derive(Clone, Copy)]
    pub(super) enum Site {
        Truncate,
        Append,
    }

    thread_local! {
        static HOOKS: RefCell<[Hook; 2]> = const { RefCell::new([None, None]) };
    }

    pub(super) fn set(site: Site, hook: Hook) {
        HOOKS.with(|h| h.borrow_mut()[site as usize] = hook);
    }

    pub(super) fn run(site: Site) {
        // Taken out for the call: a hook may write the history itself.
        let hook = HOOKS.with(|h| h.borrow_mut()[site as usize].take());
        if let Some(mut hook) = hook {
            hook();
            HOOKS.with(|h| {
                h.borrow_mut()[site as usize].get_or_insert(hook);
            });
        }
    }
}

/// Async wrapper for append_prompt (fire-and-forget via spawn_blocking)
pub(crate) async fn append_prompt_async(cwd: String, entry: PromptEntry) {
    let _ = tokio::task::spawn_blocking(move || {
        if let Err(e) = append_prompt(&cwd, &entry) {
            tracing::warn!(?e, "failed to append prompt to history");
        }
    })
    .await;
}

/// Returns prompts in reverse chronological order (most recent first).
pub(crate) fn load_bash_prompts(cwd: &str) -> io::Result<Vec<String>> {
    load_prompts_filtered(cwd, |e| e.is_bash)
}

fn load_prompts_filtered(
    cwd: &str,
    filter: impl Fn(&PromptEntry) -> bool,
) -> io::Result<Vec<String>> {
    let path = prompt_history_path(cwd);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = std::fs::File::open(&path)?;
    let reader = BufReader::new(file);

    let mut prompts = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<PromptEntry>(&line)
            && filter(&entry)
        {
            prompts.push(entry.prompt);
        }
    }

    prompts.dedup();
    prompts.reverse();

    Ok(prompts)
}

pub(crate) async fn load_prompts_async(cwd: String) -> io::Result<Vec<String>> {
    tokio::task::spawn_blocking(move || load_prompts(&cwd))
        .await
        .map_err(io::Error::other)?
}

pub(crate) async fn load_prompts_for_session_async(
    cwd: String,
    session_id: String,
) -> io::Result<Vec<String>> {
    tokio::task::spawn_blocking(move || load_prompts_for_session(&cwd, &session_id))
        .await
        .map_err(io::Error::other)?
}

pub(crate) async fn load_bash_prompts_async(cwd: String) -> io::Result<Vec<String>> {
    tokio::task::spawn_blocking(move || load_bash_prompts(&cwd))
        .await
        .map_err(io::Error::other)?
}

/// Async wrapper for truncate_if_needed (background maintenance)
pub(crate) async fn truncate_if_needed_async(cwd: String) {
    let _ = tokio::task::spawn_blocking(move || {
        if let Err(e) = truncate_if_needed(&cwd) {
            tracing::warn!(?e, "failed to truncate prompt history");
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_cwd() -> (TempDir, String) {
        let tmp = TempDir::new().unwrap();
        let cwd = tmp
            .path()
            .join("test_project")
            .to_string_lossy()
            .to_string();
        (tmp, cwd)
    }

    #[test]
    fn test_append_and_load() {
        let (_tmp, cwd) = test_cwd();

        let entry1 = PromptEntry {
            timestamp: Utc::now(),
            session_id: "s1".into(),
            prompt: "first prompt".into(),
            is_bash: false,
        };
        let entry2 = PromptEntry {
            timestamp: Utc::now(),
            session_id: "s1".into(),
            prompt: "second prompt".into(),
            is_bash: false,
        };

        append_prompt(&cwd, &entry1).unwrap();
        append_prompt(&cwd, &entry2).unwrap();

        let prompts = load_prompts(&cwd).unwrap();
        assert_eq!(prompts.len(), 2);
        // Most recent first
        assert_eq!(prompts[0], "second prompt");
        assert_eq!(prompts[1], "first prompt");
    }

    /// P150 (S14; live e2e lane M): `prompt_history.jsonl` (every prompt typed in the project) is created 0600, and
    /// one an older version left 0644 is tightened by the next append.
    #[cfg(unix)]
    #[test]
    fn p150_prompt_history_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_tmp, cwd) = test_cwd();
        let entry = PromptEntry {
            timestamp: Utc::now(),
            session_id: "s1".into(),
            prompt: "p150".into(),
            is_bash: false,
        };
        append_prompt(&cwd, &entry).unwrap();
        let path = prompt_history_path(&cwd);
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "a new prompt history must be owner-only");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        append_prompt(&cwd, &entry).unwrap();
        assert_eq!(mode(&path), 0o600, "a looser prompt history is tightened");
    }

    #[test]
    fn test_deduplication() {
        let (_tmp, cwd) = test_cwd();

        // Add consecutive identical prompts
        for _ in 0..3 {
            let entry = PromptEntry {
                timestamp: Utc::now(),
                session_id: "s1".into(),
                prompt: "same prompt".into(),
                is_bash: false,
            };
            append_prompt(&cwd, &entry).unwrap();
        }

        let prompts = load_prompts(&cwd).unwrap();
        // Consecutive identical prompts collapse to one entry
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0], "same prompt");
    }

    #[test]
    fn test_empty_file() {
        let (_tmp, cwd) = test_cwd();
        let prompts = load_prompts(&cwd).unwrap();
        assert!(prompts.is_empty());
    }

    #[test]
    fn test_path_encoding() {
        let cwd = "/path/with spaces/and@special#chars";
        let path = prompt_history_path(cwd);
        assert!(path.to_string_lossy().contains("prompt_history.jsonl"));
        // Encoding the CWD removes the spaces
        assert!(!path.to_string_lossy().contains(" "));
    }

    #[test]
    fn test_load_bash_prompts_filters_correctly() {
        let (_tmp, cwd) = test_cwd();

        let bash_entry = PromptEntry {
            timestamp: Utc::now(),
            session_id: "s1".into(),
            prompt: "git status".into(),
            is_bash: true,
        };
        let ai_entry = PromptEntry {
            timestamp: Utc::now(),
            session_id: "s1".into(),
            prompt: "explain this code".into(),
            is_bash: false,
        };
        let bash_entry2 = PromptEntry {
            timestamp: Utc::now(),
            session_id: "s1".into(),
            prompt: "ls -la".into(),
            is_bash: true,
        };

        append_prompt(&cwd, &bash_entry).unwrap();
        append_prompt(&cwd, &ai_entry).unwrap();
        append_prompt(&cwd, &bash_entry2).unwrap();

        let bash_prompts = load_bash_prompts(&cwd).unwrap();
        assert_eq!(bash_prompts.len(), 2);
        assert_eq!(bash_prompts[0], "ls -la");
        assert_eq!(bash_prompts[1], "git status");

        // load_prompts still returns all
        let all_prompts = load_prompts(&cwd).unwrap();
        assert_eq!(all_prompts.len(), 3);
    }

    #[test]
    fn test_backward_compat_missing_is_bash() {
        let (_tmp, cwd) = test_cwd();
        let path = prompt_history_path(&cwd);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        // Write an entry WITHOUT the is_bash field (simulating old format)
        let old_json =
            r#"{"timestamp":"2024-01-01T00:00:00Z","session_id":"s1","prompt":"old command"}"#;
        std::fs::write(&path, format!("{old_json}\n")).unwrap();

        // The old entry deserializes with is_bash defaulting to false
        let all = load_prompts(&cwd).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], "old command");

        // The old entry does not appear in bash-filtered results
        let bash = load_bash_prompts(&cwd).unwrap();
        assert!(bash.is_empty());
    }

    #[test]
    fn test_load_bash_prompts_deduplicates() {
        let (_tmp, cwd) = test_cwd();

        for _ in 0..3 {
            let entry = PromptEntry {
                timestamp: Utc::now(),
                session_id: "s1".into(),
                prompt: "git status".into(),
                is_bash: true,
            };
            append_prompt(&cwd, &entry).unwrap();
        }

        let bash = load_bash_prompts(&cwd).unwrap();
        assert_eq!(bash.len(), 1);
        assert_eq!(bash[0], "git status");
    }

    #[test]
    fn test_load_bash_prompts_empty_file() {
        let (_tmp, cwd) = test_cwd();
        let bash = load_bash_prompts(&cwd).unwrap();
        assert!(bash.is_empty());
    }

    #[test]
    fn test_load_prompts_for_session_filters_by_session_id() {
        let (_tmp, cwd) = test_cwd();

        let mk = |session_id: &str, prompt: &str| PromptEntry {
            timestamp: Utc::now(),
            session_id: session_id.into(),
            prompt: prompt.into(),
            is_bash: false,
        };

        // Interleave prompts from two sessions in the shared per-CWD file.
        append_prompt(&cwd, &mk("s1", "s1 first")).unwrap();
        append_prompt(&cwd, &mk("s2", "s2 first")).unwrap();
        append_prompt(&cwd, &mk("s1", "s1 second")).unwrap();
        append_prompt(&cwd, &mk("s2", "s2 second")).unwrap();

        // Only s1's prompts, most-recent-first (same ordering as load_prompts).
        let s1 = load_prompts_for_session(&cwd, "s1").unwrap();
        assert_eq!(s1, vec!["s1 second".to_string(), "s1 first".to_string()]);

        let s2 = load_prompts_for_session(&cwd, "s2").unwrap();
        assert_eq!(s2, vec!["s2 second".to_string(), "s2 first".to_string()]);

        assert!(load_prompts_for_session(&cwd, "nope").unwrap().is_empty());

        assert_eq!(load_prompts(&cwd).unwrap().len(), 4);
    }

    /// P72: a truncation running while prompts are appended (other sessions,
    /// other processes) drops only the oldest entries, never an append that
    /// landed between its read and its rename; and leaves no temp.
    #[test]
    #[serial_test::serial] // the state lock lives under the (env-derived) fuigo home
    fn truncation_alongside_appends_loses_no_new_prompt() {
        let (_tmp, cwd) = test_cwd();
        let path = prompt_history_path(&cwd);
        crate::util::fuigo_home::ensure_sessions_cwd_dir(&cwd).unwrap();
        let entry = |prompt: String| PromptEntry {
            timestamp: Utc::now(),
            session_id: "s".into(),
            prompt,
            is_bash: false,
        };
        let mut seed = Vec::new();
        for i in 0..210 {
            serde_json::to_writer(&mut seed, &entry(format!("old-{i}"))).unwrap();
            seed.push(b'\n');
        }
        std::fs::write(&path, seed).unwrap();
        const MAX: usize = 200;
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let truncator = {
            let (path, done) = (path.clone(), done.clone());
            std::thread::spawn(move || {
                let mut runs = 0;
                while !done.load(std::sync::atomic::Ordering::SeqCst) || runs == 0 {
                    truncate_file_if_needed(&path, MAX).unwrap();
                    runs += 1;
                }
                runs
            })
        };
        for i in 0..150 {
            append_prompt(&cwd, &entry(format!("new-{i}"))).unwrap();
        }
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(truncator.join().unwrap() > 0);
        truncate_file_if_needed(&path, MAX).unwrap();
        let mut got = load_prompts(&cwd).unwrap();
        got.reverse();
        let want: Vec<String> = (160..210)
            .map(|i| format!("old-{i}"))
            .chain((0..150).map(|i| format!("new-{i}")))
            .collect();
        assert_eq!(got, want);
        let temps: Vec<String> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(temps.is_empty(), "{temps:?}");
    }

    /// P79 (kills P72's mutant M13): in the truncation's LOCKED pass (read,
    /// fsync, rename under the lock; the pass an optimistic commit's refusal
    /// falls back to) an append must wait for the lock. Without the append
    /// lock it lands in the file being replaced and is lost. Here the
    /// truncation is forced into the locked pass (the path runs through a
    /// symlink on unix, and there is no optimistic pass on Windows) and, from
    /// inside it, a thread appends. The truncation goes on only once that
    /// thread is seen queued on the lock (no sleep: an append that takes no
    /// lock never queues, it just finishes, and the test fails on that), and
    /// the prompt must be in the file afterwards.
    #[test]
    #[serial_test::serial] // the state lock lives under the (env-derived) fuigo home
    fn an_append_waits_for_the_lock_the_locked_truncation_pass_holds() {
        let (tmp, cwd) = test_cwd();
        let path = prompt_history_path(&cwd);
        crate::util::fuigo_home::ensure_sessions_cwd_dir(&cwd).unwrap();
        let entry = |prompt: String| PromptEntry {
            timestamp: Utc::now(),
            session_id: "s".into(),
            prompt,
            is_bash: false,
        };
        let mut seed = Vec::new();
        for i in 0..210 {
            serde_json::to_writer(&mut seed, &entry(format!("old-{i}"))).unwrap();
            seed.push(b'\n');
        }
        std::fs::write(&path, seed).unwrap();
        #[cfg(unix)]
        let through = {
            let link = tmp.path().join("via-link");
            std::os::unix::fs::symlink(path.parent().unwrap(), &link).unwrap();
            link.join(PROMPT_HISTORY_FILE)
        };
        #[cfg(not(unix))]
        let through = {
            let _ = &tmp;
            path.clone()
        };

        let appender: std::rc::Rc<std::cell::RefCell<Option<std::thread::JoinHandle<()>>>> =
            std::rc::Rc::default();
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_ran = std::rc::Rc::new(std::cell::Cell::new(0u32));
        {
            let (appender, finished, hook_ran, cwd) = (
                appender.clone(),
                finished.clone(),
                hook_ran.clone(),
                cwd.clone(),
            );
            under_lock_seam::set(
                under_lock_seam::Site::Truncate,
                Some(Box::new(move || {
                    hook_ran.set(hook_ran.get() + 1);
                    if appender.borrow().is_some() {
                        return;
                    }
                    let (done, cwd, e) = (finished.clone(), cwd.clone(), entry("during".into()));
                    let thread = std::thread::spawn(move || {
                        append_prompt(&cwd, &e).unwrap();
                        done.store(true, std::sync::atomic::Ordering::SeqCst);
                    });
                    let id = thread.thread().id();
                    *appender.borrow_mut() = Some(thread);
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
                    while !fuigo_config::fs_atomic::thread_is_queued_for_a_lock(id) {
                        assert!(
                            !finished.load(std::sync::atomic::Ordering::SeqCst),
                            "an append completed while the truncation held the state lock"
                        );
                        assert!(
                            std::time::Instant::now() < deadline,
                            "the append never queued on the state lock"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    assert!(
                        !finished.load(std::sync::atomic::Ordering::SeqCst),
                        "an append completed while the truncation held the state lock"
                    );
                })),
            );
        }
        let truncated = truncate_file_if_needed(&through, 200);
        under_lock_seam::set(under_lock_seam::Site::Truncate, None);
        truncated.unwrap();
        assert!(
            hook_ran.get() >= 1,
            "the truncation never ran its edit (no locked pass)"
        );
        appender
            .borrow_mut()
            .take()
            .expect("the hook appended")
            .join()
            .unwrap();

        let mut got = load_prompts(&cwd).unwrap();
        got.reverse();
        let want: Vec<String> = (10..210)
            .map(|i| format!("old-{i}"))
            .chain(std::iter::once("during".to_string()))
            .collect();
        assert_eq!(
            got, want,
            "the append must land after the replacement, not in it"
        );
    }

    /// P79: the first append creates the history. Its lock must cover the
    /// file it creates by inode too, not only by name: a writer that reaches
    /// the new file through a hard link made while the append still holds
    /// the lock has to wait for it.
    #[test]
    #[serial_test::serial] // the state lock lives under the (env-derived) fuigo home
    fn the_first_append_excludes_a_writer_through_a_hard_link_to_the_new_file() {
        let (_tmp, cwd) = test_cwd();
        let path = prompt_history_path(&cwd);
        assert!(!path.exists());
        let alias = path.with_file_name("alias-of-history.jsonl");
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let other: std::rc::Rc<std::cell::RefCell<Option<std::thread::JoinHandle<()>>>> =
            std::rc::Rc::default();
        {
            let (path, alias, finished, other) =
                (path.clone(), alias.clone(), finished.clone(), other.clone());
            under_lock_seam::set(
                under_lock_seam::Site::Append,
                Some(Box::new(move || {
                    std::fs::hard_link(&path, &alias).unwrap();
                    let (alias, done) = (alias.clone(), finished.clone());
                    let thread = std::thread::spawn(move || {
                        drop(fuigo_config::fs_atomic::lock_state_file(&alias).unwrap());
                        done.store(true, std::sync::atomic::Ordering::SeqCst);
                    });
                    let id = thread.thread().id();
                    *other.borrow_mut() = Some(thread);
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
                    while !fuigo_config::fs_atomic::thread_is_queued_for_a_lock(id) {
                        assert!(
                            !finished.load(std::sync::atomic::Ordering::SeqCst),
                            "a writer through the hard link locked the file during the append"
                        );
                        assert!(
                            std::time::Instant::now() < deadline,
                            "the writer through the hard link never queued"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    assert!(!finished.load(std::sync::atomic::Ordering::SeqCst));
                })),
            );
        }
        let appended = append_prompt(
            &cwd,
            &PromptEntry {
                timestamp: Utc::now(),
                session_id: "s".into(),
                prompt: "first".into(),
                is_bash: false,
            },
        );
        under_lock_seam::set(under_lock_seam::Site::Append, None);
        appended.unwrap();
        other
            .borrow_mut()
            .take()
            .expect("the hook ran")
            .join()
            .unwrap();
        assert_eq!(load_prompts(&cwd).unwrap(), ["first"]);
    }

    #[tokio::test]
    async fn test_append_prompt_async_round_trips_for_session() {
        let (_tmp, cwd) = test_cwd();

        let entry = PromptEntry {
            timestamp: Utc::now(),
            session_id: "s1".into(),
            prompt: "durable prompt".into(),
            is_bash: false,
        };

        // Mirrors the submit path: awaiting the wrapper makes the append immediately loadable.
        append_prompt_async(cwd.clone(), entry).await;

        let prompts = load_prompts_for_session_async(cwd, "s1".into())
            .await
            .unwrap();
        assert_eq!(prompts, vec!["durable prompt".to_string()]);
    }
}
