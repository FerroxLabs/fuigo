//! Tracks open TUI sessions in `~/.fuigo/active_sessions.json` for crash recovery.
//! A clean exit removes the entry; a crash leaves it behind.
//! On next launch, [`collect_crashed`] finds orphaned entries (dead PIDs).

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

use agent_client_protocol as acp;
use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveSession {
    pub session_id: acp::SessionId,
    pub pid: u32,
    pub cwd: String,
    pub opened_at: DateTime<Utc>,
}

const DATA_FILENAME: &str = "active_sessions.json";
const LOCK_FILENAME: &str = "active_sessions.lock";
const TMP_FILENAME: &str = "active_sessions.json.tmp";

// -- Public API (delegates to `_in` variants with default fuigo home) --------

/// Register a session as active (idempotent by session_id).
pub fn register(session: ActiveSession) -> io::Result<()> {
    register_in(&fuigo_config::fuigo_home(), session)
}

/// Non-blocking unregister for signal handlers.
/// Returns `Ok(false)` on lock contention; the orphan is cleaned up by `collect_crashed` next launch.
pub fn try_unregister(session_id: &acp::SessionId) -> io::Result<bool> {
    try_unregister_in(&fuigo_config::fuigo_home(), session_id)
}

/// Remove entries with dead PIDs and return them.
pub fn collect_crashed() -> io::Result<Vec<ActiveSession>> {
    collect_crashed_in(&fuigo_config::fuigo_home())
}

// -- Injectable-root variants (`_in`) for testing ---------------------------

pub fn register_in(root: &Path, session: ActiveSession) -> io::Result<()> {
    with_locked_state(root, |sessions| {
        sessions.retain(|s| s.session_id != session.session_id);
        sessions.push(session);
    })
}

pub fn unregister_in(root: &Path, session_id: &acp::SessionId) -> io::Result<()> {
    with_locked_state(root, |sessions| {
        sessions.retain(|s| s.session_id != *session_id);
    })
}

pub fn try_unregister_in(root: &Path, session_id: &acp::SessionId) -> io::Result<bool> {
    try_with_locked_state(root, |sessions| {
        sessions.retain(|s| s.session_id != *session_id);
    })
    .map(|opt| opt.is_some())
}

pub fn collect_crashed_in(root: &Path) -> io::Result<Vec<ActiveSession>> {
    with_locked_state(root, |sessions| {
        let (alive, dead): (Vec<_>, Vec<_>) = sessions.drain(..).partition(|s| is_pid_alive(s.pid));
        *sessions = alive;
        dead
    })
}

pub fn list_in(root: &Path) -> io::Result<Vec<ActiveSession>> {
    let data_path = root.join(DATA_FILENAME);
    read_data_file(&data_path)
}

// -- Internal: locked read-modify-write -------------------------------------

fn with_locked_state<F, R>(root: &Path, mutate: F) -> io::Result<R>
where
    F: FnOnce(&mut Vec<ActiveSession>) -> R,
{
    let lock_path = root.join(LOCK_FILENAME);
    let data_path = root.join(DATA_FILENAME);
    let tmp_path = root.join(TMP_FILENAME);

    fs::create_dir_all(root)?;
    let lock_file = open_lock_file(&lock_path)?;
    lock_file.lock_exclusive()?;

    let result = locked_mutate(&data_path, &tmp_path, mutate);

    let _ = lock_file.unlock();
    result
}

/// Not `WouldBlock`: Windows surfaces contention (ERROR_LOCK_VIOLATION) as `Uncategorized`.
fn lock_is_contended(e: &std::io::Error) -> bool {
    let contended = fs2::lock_contended_error();
    e.kind() == contended.kind() && e.raw_os_error() == contended.raw_os_error()
}

/// Non-blocking variant for signal handlers.
fn try_with_locked_state<F, R>(root: &Path, mutate: F) -> io::Result<Option<R>>
where
    F: FnOnce(&mut Vec<ActiveSession>) -> R,
{
    let lock_path = root.join(LOCK_FILENAME);
    let data_path = root.join(DATA_FILENAME);
    let tmp_path = root.join(TMP_FILENAME);

    fs::create_dir_all(root)?;
    let lock_file = open_lock_file(&lock_path)?;

    match lock_file.try_lock_exclusive() {
        Ok(()) => {
            let result = locked_mutate(&data_path, &tmp_path, mutate);
            let _ = lock_file.unlock();
            result.map(Some)
        }
        Err(e) if lock_is_contended(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

fn locked_mutate<F, R>(data_path: &Path, tmp_path: &Path, mutate: F) -> io::Result<R>
where
    F: FnOnce(&mut Vec<ActiveSession>) -> R,
{
    let mut sessions = read_data_file(data_path)?;
    let result = mutate(&mut sessions);
    write_data_file_atomic(tmp_path, data_path, &sessions)?;
    Ok(result)
}

fn open_lock_file(path: &Path) -> io::Result<File> {
    let file = fuigo_config::owner_only_file_options(
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false),
    )
    .open(path)?;
    fuigo_config::tighten_own_regular_file_owner_only(&file, path);
    Ok(file)
}

fn read_data_file(path: &Path) -> io::Result<Vec<ActiveSession>> {
    match fs::read(path) {
        Ok(bytes) if bytes.is_empty() => Ok(Vec::new()),
        Ok(bytes) => match serde_json::from_slice::<Vec<ActiveSession>>(&bytes) {
            Ok(sessions) => Ok(sessions),
            Err(e) => Ok(recover_corrupt(path, &bytes, &e)),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// How many backups of corrupt files are kept beside the data file.
const MAX_CORRUPT_BACKUPS: usize = 5;

/// A file that does not parse: keep a copy of it, salvage the entries that are still readable, and say so.
/// The next write replaces the broken file with the recovered list, so the copy is the only record of the original.
fn recover_corrupt(path: &Path, bytes: &[u8], error: &serde_json::Error) -> Vec<ActiveSession> {
    let recovered = salvage_entries(bytes);
    let backup = backup_corrupt_file(path, bytes);
    tracing::warn!(
        path = %path.display(),
        error = %error,
        recovered = recovered.len(),
        backup = ?backup.as_ref().ok(),
        backup_error = ?backup.as_ref().err().map(ToString::to_string),
        "active_sessions.json is corrupted; kept a backup and recovered the readable entries"
    );
    recovered
}

/// Entries of a damaged list that still decode: every readable element of an intact array, or the complete
/// objects found in a truncated or otherwise broken one.
fn salvage_entries(bytes: &[u8]) -> Vec<ActiveSession> {
    if let Ok(serde_json::Value::Array(items)) = serde_json::from_slice::<serde_json::Value>(bytes) {
        return items
            .into_iter()
            .filter_map(|item| serde_json::from_value(item).ok())
            .collect();
    }
    let mut found = Vec::new();
    let (mut depth, mut start) = (0i32, None);
    let (mut in_string, mut escaped) = (false, false);
    for (i, &b) in bytes.iter().enumerate() {
        if in_string {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' => depth += 1,
            b'{' => {
                depth += 1;
                if depth == 2 {
                    start = Some(i);
                }
            }
            b'}' => {
                if depth == 2
                    && let Some(s) = start.take()
                    && let Ok(entry) = serde_json::from_slice::<ActiveSession>(&bytes[s..=i])
                {
                    found.push(entry);
                }
                depth -= 1;
            }
            b']' => depth -= 1,
            _ => {}
        }
        depth = depth.max(0);
    }
    found
}

/// Copy the corrupt file to `active_sessions.json.corrupt-<hash of its bytes>` (owner-only), once per distinct content,
/// and drop the oldest copies beyond [`MAX_CORRUPT_BACKUPS`].
fn backup_corrupt_file(path: &Path, bytes: &[u8]) -> io::Result<std::path::PathBuf> {
    use std::hash::{Hash, Hasher};
    use io::Write as _;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    let target = dir.join(format!("{DATA_FILENAME}.corrupt-{:016x}", hasher.finish()));
    match fuigo_config::owner_only_file_options(OpenOptions::new().write(true).create_new(true))
        .open(&target)
    {
        Ok(mut file) => file.write_all(bytes)?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(target),
        Err(e) => return Err(e),
    }
    prune_corrupt_backups(dir);
    Ok(target)
}

fn prune_corrupt_backups(dir: &Path) {
    let prefix = format!("{DATA_FILENAME}.corrupt-");
    let Ok(entries) = fs::read_dir(dir) else { return };
    let mut backups: Vec<_> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    if backups.len() <= MAX_CORRUPT_BACKUPS {
        return;
    }
    backups.sort();
    for (_, old) in backups.iter().take(backups.len() - MAX_CORRUPT_BACKUPS) {
        let _ = fs::remove_file(old);
    }
}

fn write_data_file_atomic(
    tmp_path: &Path,
    data_path: &Path,
    sessions: &[ActiveSession],
) -> io::Result<()> {
    let json = serde_json::to_string_pretty(sessions)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    // Fresh 0600 temp (create_new: a stale or planted file is removed first, never reused or followed), then the
    // rename replaces `active_sessions.json` with it, so an older wider-mode json is healed on its next write.
    match fs::remove_file(tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    {
        use io::Write as _;
        let mut tmp = fuigo_config::owner_only_file_options(
            OpenOptions::new().write(true).create_new(true),
        )
        .open(tmp_path)?;
        tmp.write_all(json.as_bytes())?;
    }
    fs::rename(tmp_path, data_path).inspect_err(|_| {
        let _ = fs::remove_file(tmp_path);
    })
}

fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let pid_i = match i32::try_from(pid) {
            Ok(p) if p > 0 => p,
            _ => return false,
        };
        let ret = unsafe { libc::kill(pid_i as libc::pid_t, 0) };
        if ret == 0 {
            return true;
        }
        io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
        match handle {
            Ok(h) => {
                let _ = unsafe { CloseHandle(h) };
                true
            }
            Err(_) => false,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        // Conservative: assume alive if we can't check.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn a_held_lock_makes_the_non_blocking_mutation_report_busy_not_an_error() {
        let dir = TempDir::new().unwrap();
        let holder = open_lock_file(&dir.path().join(LOCK_FILENAME)).unwrap();
        holder.lock_exclusive().unwrap();
        let out = try_with_locked_state(dir.path(), |_| ());
        assert!(matches!(out, Ok(None)), "expected Ok(None) while another handle holds the lock, got {out:?}");
    }

    fn make_session(id: &str, pid: u32) -> ActiveSession {
        ActiveSession {
            session_id: acp::SessionId::new(id),
            pid,
            cwd: "/tmp/test".into(),
            opened_at: Utc::now(),
        }
    }

    #[test]
    fn register_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let s = make_session("s1", std::process::id());
        register_in(dir.path(), s.clone()).unwrap();
        register_in(dir.path(), s).unwrap();
        assert_eq!(list_in(dir.path()).unwrap().len(), 1);
    }

    #[test]
    fn collect_crashed_partitions_by_pid_liveness() {
        let dir = TempDir::new().unwrap();
        register_in(dir.path(), make_session("alive", std::process::id())).unwrap();
        register_in(dir.path(), make_session("dead", 2_000_000_000)).unwrap();

        let crashed = collect_crashed_in(dir.path()).unwrap();
        assert_eq!(crashed.len(), 1);
        assert_eq!(&*crashed[0].session_id.0, "dead");
        assert_eq!(&*list_in(dir.path()).unwrap()[0].session_id.0, "alive");
    }

    #[test]
    fn concurrent_registers_no_corruption() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        std::thread::scope(|s| {
            for i in 0..10 {
                let p = path.clone();
                s.spawn(move || {
                    register_in(&p, make_session(&format!("s{i}"), std::process::id())).unwrap()
                });
            }
        });
        assert_eq!(list_in(dir.path()).unwrap().len(), 10);
    }

    #[test]
    fn try_unregister_skips_if_locked() {
        let dir = TempDir::new().unwrap();
        let s = make_session("s1", std::process::id());
        register_in(dir.path(), s.clone()).unwrap();

        let lock_file = open_lock_file(&dir.path().join(LOCK_FILENAME)).unwrap();
        lock_file.lock_exclusive().unwrap();
        assert!(!try_unregister_in(dir.path(), &s.session_id).unwrap());
        lock_file.unlock().unwrap();
        assert_eq!(list_in(dir.path()).unwrap().len(), 1);
    }

    #[test]
    fn corrupt_file_recovers() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(DATA_FILENAME), "garbage{{{").unwrap();
        assert!(list_in(dir.path()).unwrap().is_empty());
        register_in(dir.path(), make_session("s1", std::process::id())).unwrap();
        assert_eq!(list_in(dir.path()).unwrap().len(), 1);
    }

    #[cfg(unix)]
    mod modes {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};

        fn mode(p: &Path) -> u32 {
            fs::metadata(p).unwrap().permissions().mode() & 0o777
        }
        fn set(p: &Path, m: u32) {
            fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
        }

        #[test]
        fn new_lock_and_json_are_owner_only() {
            let dir = TempDir::new().unwrap();
            register_in(dir.path(), make_session("a", 1)).unwrap();
            assert_eq!(mode(&dir.path().join(LOCK_FILENAME)) & 0o077, 0, "lock");
            assert_eq!(mode(&dir.path().join(DATA_FILENAME)) & 0o077, 0, "json");
        }

        #[test]
        fn existing_wide_lock_and_json_are_tightened() {
            let dir = TempDir::new().unwrap();
            let lock = dir.path().join(LOCK_FILENAME);
            let data = dir.path().join(DATA_FILENAME);
            fs::write(&lock, b"").unwrap();
            fs::write(&data, b"[]").unwrap();
            set(&lock, 0o644);
            set(&data, 0o644);
            register_in(dir.path(), make_session("a", 1)).unwrap();
            assert_eq!(mode(&lock), 0o600, "old lock");
            assert_eq!(mode(&data), 0o600, "old json");
        }

        #[test]
        fn stale_wide_tmp_file_does_not_leak_into_json() {
            let dir = TempDir::new().unwrap();
            let tmp = dir.path().join(TMP_FILENAME);
            fs::write(&tmp, b"stale").unwrap();
            set(&tmp, 0o644);
            register_in(dir.path(), make_session("fu2-new-session", std::process::id())).unwrap();
            let data = dir.path().join(DATA_FILENAME);
            assert_eq!(mode(&data), 0o600);
            let body = fs::read_to_string(&data).unwrap();
            assert!(body.contains("fu2-new-session"), "new session id missing: {body}");
            assert!(!body.contains("stale"), "stale temp content survived: {body}");
        }

        #[test]
        fn lock_symlink_target_mode_is_not_changed() {
            let dir = TempDir::new().unwrap();
            let other = TempDir::new().unwrap();
            let target = other.path().join("target");
            fs::write(&target, b"").unwrap();
            set(&target, 0o644);
            symlink(&target, dir.path().join(LOCK_FILENAME)).unwrap();
            register_in(dir.path(), make_session("a", 1)).unwrap();
            assert_eq!(mode(&target), 0o644, "symlink target must be untouched");
        }
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use tempfile::TempDir;

    fn session(id: &str) -> ActiveSession {
        ActiveSession {
            session_id: acp::SessionId::new(id),
            pid: std::process::id(),
            cwd: "/tmp/test".into(),
            opened_at: Utc::now(),
        }
    }

    fn json(s: &ActiveSession) -> String {
        serde_json::to_string(s).unwrap()
    }

    fn backups(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut found: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("active_sessions.json.corrupt"))
            })
            .collect();
        found.sort();
        found
    }

    fn ids(dir: &Path) -> Vec<String> {
        list_in(dir)
            .unwrap()
            .into_iter()
            .map(|s| s.session_id.to_string())
            .collect()
    }

    #[test]
    fn a_malformed_entry_keeps_the_readable_ones_and_a_backup() {
        let dir = TempDir::new().unwrap();
        let text = format!(
            "[{}, {{\"session_id\": 42, \"pid\": \"x\"}}, {}]",
            json(&session("keep-1")),
            json(&session("keep-2"))
        );
        fs::write(dir.path().join(DATA_FILENAME), &text).unwrap();
        assert_eq!(ids(dir.path()), ["keep-1", "keep-2"]);
        let saved = backups(dir.path());
        assert_eq!(saved.len(), 1, "exactly one backup of the corrupt file: {saved:?}");
        assert_eq!(fs::read_to_string(&saved[0]).unwrap(), text, "the backup is the original bytes");
    }

    #[test]
    fn a_truncated_file_recovers_the_complete_entries() {
        let dir = TempDir::new().unwrap();
        let second = json(&session("cut"));
        let text = format!("[{}, {}", json(&session("whole")), &second[..second.len() / 2]);
        fs::write(dir.path().join(DATA_FILENAME), &text).unwrap();
        assert_eq!(ids(dir.path()), ["whole"]);
        assert_eq!(backups(dir.path()).len(), 1);
    }

    #[test]
    fn unrecoverable_garbage_yields_an_empty_list_and_a_backup() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(DATA_FILENAME), "not json at all \u{0}\u{1}").unwrap();
        assert!(ids(dir.path()).is_empty());
        assert_eq!(backups(dir.path()).len(), 1);
    }

    #[test]
    fn a_healthy_file_is_never_backed_up() {
        let dir = TempDir::new().unwrap();
        register_in(dir.path(), session("ok")).unwrap();
        assert_eq!(ids(dir.path()), ["ok"]);
        assert!(backups(dir.path()).is_empty());
    }

    #[test]
    fn the_next_write_keeps_the_recovered_entries() {
        let dir = TempDir::new().unwrap();
        let text = format!("[{}, {{\"bad\": true}}]", json(&session("old")));
        fs::write(dir.path().join(DATA_FILENAME), &text).unwrap();
        register_in(dir.path(), session("new")).unwrap();
        assert_eq!(ids(dir.path()), ["old", "new"]);
        assert_eq!(backups(dir.path()).len(), 1);
    }
}
