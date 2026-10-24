//! Point-in-time candidate view of local session storage.
//!
//! Resolves session directories under the sessions root (`<encoded-cwd>/<session-id>/` buckets).
//! The journaled relocation transaction this module was named for never ran in production and was deleted.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub(crate) enum RelocationError {
    #[error("invalid relocation {field}: {value:?}")]
    InvalidComponent { field: &'static str, value: String },
    #[error("{operation} {path}: {source}", path = path.display())]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("decode {path}: {source}", path = path.display())]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

pub(crate) type Result<T> = std::result::Result<T, RelocationError>;

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> RelocationError {
    RelocationError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn validate_component(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.contains('/')
        || value.contains('\\')
    {
        return Err(RelocationError::InvalidComponent {
            field,
            value: value.to_owned(),
        });
    }
    Ok(())
}

type SessionCandidates = HashMap<String, Vec<PathBuf>>;

pub(crate) struct RelocationView {
    sessions_root: PathBuf,
    all_candidates: SessionCandidates,
    persisted_candidates: SessionCandidates,
}

impl RelocationView {
    pub(crate) fn load(fuigo_home: &Path) -> Result<Self> {
        Self::load_for_sessions_root(&fuigo_home.join("sessions"))
    }

    pub(crate) fn load_for_sessions_root(sessions_root: &Path) -> Result<Self> {
        let (all_candidates, persisted_candidates) = load_candidates(sessions_root)?;
        Ok(Self {
            sessions_root: sessions_root.into(),
            all_candidates,
            persisted_candidates,
        })
    }

    /// Session directories with a persisted `summary.json`, optionally restricted to `cwd`.
    /// A session id present under multiple cwd buckets is ambiguous and skipped.
    pub(crate) fn session_dirs(&self, cwd: Option<&str>) -> Result<Vec<PathBuf>> {
        let cwd_parent = cwd.map(|cwd| {
            self.sessions_root
                .join(fuigo_config::encode_cwd_dirname(cwd))
        });
        Ok(self
            .persisted_candidates
            .values()
            .filter(|paths| {
                cwd_parent
                    .as_deref()
                    .is_none_or(|parent| paths.iter().any(|path| path.parent() == Some(parent)))
            })
            .filter_map(|paths| select(paths, cwd_parent.as_deref()))
            .collect())
    }

    pub(crate) fn find_persisted_session_dir(&self, session_id: &str) -> Result<Option<PathBuf>> {
        self.find_session_dir(session_id, &self.persisted_candidates)
    }

    pub(crate) fn find_any_session_dir(&self, session_id: &str) -> Result<Option<PathBuf>> {
        self.find_session_dir(session_id, &self.all_candidates)
    }

    fn find_session_dir(
        &self,
        session_id: &str,
        candidates: &SessionCandidates,
    ) -> Result<Option<PathBuf>> {
        validate_component("session id", session_id)?;
        let paths = candidates.get(session_id).map(Vec::as_slice).unwrap_or(&[]);
        Ok(select(paths, None))
    }
}

/// A candidate is unambiguous only when exactly one path carries the id.
fn select(paths: &[PathBuf], cwd_parent: Option<&Path>) -> Option<PathBuf> {
    let selected = (paths.len() == 1).then(|| paths[0].clone());
    selected.filter(|path| cwd_parent.is_none_or(|parent| path.parent() == Some(parent)))
}

fn load_candidates(sessions_root: &Path) -> Result<(SessionCandidates, SessionCandidates)> {
    let entries = match fs::read_dir(sessions_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((HashMap::new(), HashMap::new()));
        }
        Err(error) => return Err(io_error("read", sessions_root, error)),
    };
    let mut all = SessionCandidates::new();
    let mut persisted = SessionCandidates::new();
    // One folder that cannot be read (permissions, a vanished mount, a damaged entry) must not take the whole listing
    // with it: the session list and `/resume` show everything else and the log names what was skipped.
    for cwd_entry in entries {
        let cwd_entry = match cwd_entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(root = %sessions_root.display(), %error, "skipping an unreadable entry of the sessions folder");
                continue;
            }
        };
        let cwd_path = cwd_entry.path();
        let cwd_type = match cwd_entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                tracing::warn!(path = %cwd_path.display(), %error, "skipping a sessions folder that cannot be inspected");
                continue;
            }
        };
        if !cwd_type.is_dir() || cwd_type.is_symlink() {
            continue;
        }
        let session_entries = match fs::read_dir(&cwd_path) {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(path = %cwd_path.display(), %error, "skipping an unreadable sessions folder");
                continue;
            }
        };
        for session_entry in session_entries {
            let session_entry = match session_entry {
                Ok(entry) => entry,
                Err(error) => {
                    tracing::warn!(path = %cwd_path.display(), %error, "skipping an unreadable session entry");
                    continue;
                }
            };
            let path = session_entry.path();
            let file_type = match session_entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "skipping a session that cannot be inspected");
                    continue;
                }
            };
            let Some(id) = session_entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !file_type.is_dir() || file_type.is_symlink() || id.starts_with('.') {
                continue;
            }
            let summary = path.join(super::SUMMARY_FILE);
            match fs::symlink_metadata(&summary) {
                Ok(metadata)
                    if metadata.file_type().is_file() && !metadata.file_type().is_symlink() =>
                {
                    all.entry(id.clone()).or_default().push(path.clone());
                    persisted.entry(id).or_default().push(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    all.entry(id).or_default().push(path);
                }
                Err(error) => {
                    tracing::warn!(path = %summary.display(), %error, "skipping a session whose summary cannot be inspected");
                }
                Ok(_) => {
                    all.entry(id).or_default().push(path);
                }
            }
        }
    }
    Ok((all, persisted))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Run `f` with this thread's filesystem identity dropped to an unprivileged user, so permission checks apply
    /// even when the suite runs as root. Only the calling thread is affected and it is restored before returning.
    fn as_unprivileged<R: Send>(f: impl FnOnce() -> R + Send) -> R {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    // SAFETY: setfsuid changes only the calling thread's filesystem uid; it is undone below.
                    let previous = unsafe { libc::setfsuid(65534) };
                    let out = f();
                    // SAFETY: as above.
                    unsafe { libc::setfsuid(previous as libc::uid_t) };
                    out
                })
                .join()
                .unwrap()
        })
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn make_session(root: &Path, bucket: &str, id: &str) {
        let dir = root.join(bucket).join(id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(super::super::SUMMARY_FILE), "{}").unwrap();
        set_mode(&root.join(bucket), 0o755);
        set_mode(&dir, 0o755);
    }

    #[test]
    fn an_unreadable_workspace_folder_does_not_hide_the_other_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        set_mode(tmp.path(), 0o755);
        let root = tmp.path().join("sessions");
        fs::create_dir_all(&root).unwrap();
        set_mode(&root, 0o755);
        make_session(&root, "readable-cwd", "session-a");
        make_session(&root, "locked-cwd", "session-b");
        set_mode(&root.join("locked-cwd"), 0o000);

        let view = as_unprivileged(|| RelocationView::load_for_sessions_root(&root));
        set_mode(&root.join("locked-cwd"), 0o755);

        let view = view.expect("a folder that cannot be read must be skipped, not fail the whole listing");
        assert_eq!(
            view.session_dirs(None).unwrap(),
            vec![root.join("readable-cwd").join("session-a")],
        );
    }

    #[test]
    fn an_unreadable_sessions_root_is_still_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        set_mode(tmp.path(), 0o755);
        let root = tmp.path().join("sessions");
        fs::create_dir_all(&root).unwrap();
        set_mode(&root, 0o000);
        let view = as_unprivileged(|| RelocationView::load_for_sessions_root(&root));
        set_mode(&root, 0o755);
        assert!(view.is_err(), "nothing can be listed from an unreadable root");
    }
}
