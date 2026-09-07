//! OS-backed consolidation exclusion and a separate durable success marker.
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::SystemTime,
};

pub struct DreamLock {
    path: PathBuf,
    marker: PathBuf,
}
pub struct DreamGuard {
    _file: fs::File,
    marker: PathBuf,
}
impl DreamLock {
    pub fn new(workspace_dir: &Path) -> Self {
        Self {
            path: workspace_dir.join(".dream-mutex"),
            marker: workspace_dir.join(".dream-consolidated"),
        }
    }
    pub fn last_consolidated_at(&self) -> io::Result<Option<SystemTime>> {
        match fs::metadata(&self.marker) {
            Ok(meta) => Ok(Some(meta.modified()?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    /// The OS releases this stable lock on drop or process exit. Never steal a live lock by age.
    pub fn acquire(&self, _stale_secs: u64) -> io::Result<Option<DreamGuard>> {
        fs::create_dir_all(self.path.parent().unwrap())?;
        let mut opts = fs::OpenOptions::new();
        opts.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = opts.open(&self.path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(DreamGuard {
                _file: file,
                marker: self.marker.clone(),
            })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }
}
impl DreamGuard {
    /// Stamp only after the complete operation succeeds; cancellation never changes this marker.
    pub fn commit(self) -> bool {
        self.commit_sources(&[])
    }
    pub fn commit_sources(self, snapshots: &[(String, String)]) -> bool {
        super::storage::update_file(&self.marker, |old| {
            let mut processed: std::collections::BTreeMap<String, String> =
                serde_json::from_str(old).unwrap_or_default();
            for (stem, content) in snapshots {
                processed.insert(
                    stem.clone(),
                    blake3::hash(content.as_bytes()).to_hex().to_string(),
                );
            }
            serde_json::to_string(&processed).expect("string map serialization")
        })
        .is_ok()
    }
}

/// Returns sorted file stems of `.md` files in `sessions_dir` modified after `since`, excluding the current session (`exclude_sid8`).
pub fn sessions_since(
    sessions_dir: &Path,
    since: SystemTime,
    exclude_sid8: Option<&str>,
) -> io::Result<Vec<String>> {
    let entries = match fs::read_dir(sessions_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let marker = sessions_dir.parent().map(|p| p.join(".dream-consolidated"));
    let processed: std::collections::BTreeMap<String, String> = marker
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let mut result = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("md") || !entry.file_type()?.is_file()
        {
            continue;
        }

        if let Some(exclude) = exclude_sid8
            && path
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(|stem| stem.ends_with(exclude))
        {
            continue;
        }

        if let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            && let Some(prior) = processed.get(stem)
            && let Ok(content) = fs::read(&path)
            && *prior == blake3::hash(&content).to_hex().to_string()
        {
            continue;
        }
        if entry.metadata()?.modified()? > since
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            result.push(stem.to_owned());
        }
    }

    result.sort();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use filetime::FileTime;
    use std::time::Duration;
    use tempfile::TempDir;
    #[test]
    fn exclusion_and_cancellation_preserve_success() {
        let dir = tempfile::tempdir().unwrap();
        let lock = DreamLock::new(dir.path());
        let guard = lock.acquire(0).unwrap().unwrap();
        assert!(lock.acquire(0).unwrap().is_none());
        assert!(lock.last_consolidated_at().unwrap().is_none());
        drop(guard);
        let guard = lock.acquire(0).unwrap().unwrap();
        assert!(guard.commit());
        let success = lock.last_consolidated_at().unwrap();
        drop(lock.acquire(0).unwrap().unwrap());
        assert_eq!(lock.last_consolidated_at().unwrap(), success);
        assert!(lock.acquire(0).unwrap().is_some());
    }
    #[test]
    fn marker_failure_keeps_retry_open() {
        let dir = tempfile::tempdir().unwrap();
        let lock = DreamLock::new(dir.path());
        fs::create_dir(&lock.marker).unwrap();
        assert!(!lock.acquire(0).unwrap().unwrap().commit());
        assert!(lock.acquire(0).unwrap().is_some());
    }
    #[test]
    fn receipts_keep_changed_and_unprocessed_sources_eligible() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir(&sessions).unwrap();
        fs::write(sessions.join("processed.md"), "original").unwrap();
        fs::write(sessions.join("pending.md"), "pending").unwrap();
        let lock = DreamLock::new(dir.path());
        assert!(
            lock.acquire(0)
                .unwrap()
                .unwrap()
                .commit_sources(&[("processed".into(), "original".into())])
        );
        assert_eq!(
            sessions_since(&sessions, SystemTime::UNIX_EPOCH, None).unwrap(),
            vec!["pending"]
        );
        fs::write(sessions.join("processed.md"), "external edit").unwrap();
        assert_eq!(
            sessions_since(&sessions, SystemTime::UNIX_EPOCH, None).unwrap(),
            vec!["pending", "processed"]
        );
    }

    #[test]
    #[ignore = "helper launched by cross_process_lock_released_after_exit"]
    fn lock_process_child() {
        let dir = std::path::PathBuf::from(std::env::var_os("FUIGO_DREAM_TEST_DIR").unwrap());
        let lock = DreamLock::new(&dir);
        let _guard = lock.acquire(0).unwrap().unwrap();
        fs::write(dir.join("ready"), "ready").unwrap();
        loop {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    #[test]
    fn cross_process_lock_released_after_exit() {
        let dir = TempDir::new().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "dream_lock::tests::lock_process_child",
                "--ignored",
            ])
            .env("FUIGO_DREAM_TEST_DIR", dir.path())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !dir.path().join("ready").exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let ready = dir.path().join("ready").exists();
        let lock = DreamLock::new(dir.path());
        let excluded = lock.acquire(0).unwrap().is_none();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            ready,
            "child must reach the OS lock before contention is tested"
        );
        assert!(excluded);
        assert!(lock.acquire(0).unwrap().is_some());
        assert!(lock.last_consolidated_at().unwrap().is_none());
    }

    // --- sessions_since tests ---

    fn write_session(dir: &Path, name: &str, age_secs: u64) {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join(format!("{name}.md"));
        fs::write(&path, "test").unwrap();
        let t = SystemTime::now() - Duration::from_secs(age_secs);
        filetime::set_file_mtime(&path, FileTime::from_system_time(t)).unwrap();
    }

    #[test]
    fn filters_by_mtime() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        let cutoff = SystemTime::now() - Duration::from_secs(3600);

        write_session(&sessions, "2026-01-01-proj-aaa11111", 1800); // 30min ago, after cutoff
        write_session(&sessions, "2025-12-31-proj-bbb22222", 7200); // 2h ago, before cutoff

        let result = sessions_since(&sessions, cutoff, None).unwrap();
        assert_eq!(result, vec!["2026-01-01-proj-aaa11111"]);
    }

    #[test]
    fn mtime_at_exact_cutoff_is_excluded() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        let cutoff = SystemTime::now() - Duration::from_secs(3600);

        // Set mtime to the exact cutoff value (not strictly after)
        fs::create_dir_all(&sessions).unwrap();
        let path = sessions.join("2026-01-01-proj-exact000.md");
        fs::write(&path, "test").unwrap();
        filetime::set_file_mtime(&path, FileTime::from_system_time(cutoff)).unwrap();

        let result = sessions_since(&sessions, cutoff, None).unwrap();
        assert!(
            result.is_empty(),
            "mtime == cutoff should be excluded (strict >)"
        );
    }

    #[test]
    fn excludes_current_session() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        let cutoff = SystemTime::now() - Duration::from_secs(86400);

        write_session(&sessions, "2026-01-01-proj-aaa11111", 100);
        write_session(&sessions, "2026-01-01-proj-bbb22222", 100);

        let result = sessions_since(&sessions, cutoff, Some("bbb22222")).unwrap();
        assert_eq!(result, vec!["2026-01-01-proj-aaa11111"]);
    }

    #[test]
    fn empty_dir_returns_empty_vec() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let result = sessions_since(&sessions, SystemTime::UNIX_EPOCH, None).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn nonexistent_dir_returns_empty_vec() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("nonexistent");

        let result = sessions_since(&sessions, SystemTime::UNIX_EPOCH, None).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn ignores_non_md_files() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        write_session(&sessions, "2026-01-01-proj-aaa11111", 0);
        fs::write(sessions.join("notes.txt"), "not a session").unwrap();
        fs::write(sessions.join("data.json"), "{}").unwrap();

        let result = sessions_since(&sessions, SystemTime::UNIX_EPOCH, None).unwrap();
        assert_eq!(result, vec!["2026-01-01-proj-aaa11111"]);
    }

    #[test]
    fn returns_sorted_stems() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");

        write_session(&sessions, "zzz-session", 0);
        write_session(&sessions, "aaa-session", 0);
        write_session(&sessions, "mmm-session", 0);

        let result = sessions_since(&sessions, SystemTime::UNIX_EPOCH, None).unwrap();
        assert_eq!(result, vec!["aaa-session", "mmm-session", "zzz-session"]);
    }
}
