use std::path::{Path, PathBuf};

// Project-hook trust is no longer stored here: the shell's folder-trust store
// (`~/.fuigo/trusted_folders.toml`) is the single authority for whether a repo's
// project hooks run (the same gate as repo-local MCP/LSP). The helpers below
// exist only to migrate prior grants out of the legacy file.

/// Path to the legacy project-hook trust file (`<user_fuigo_home>/trusted-hook-projects`), or `None` when no user fuigo home resolves.
/// It is retained only for the one-time migration into folder-trust.
pub fn legacy_trust_file_path() -> Option<PathBuf> {
    Some(fuigo_config::user_fuigo_home()?.join(fuigo_config::TRUSTED_HOOK_PROJECTS_FILENAME))
}

/// The legacy format is one canonical absolute path per line; blank and `#`-comment lines are skipped.
/// A missing file yields `Ok(empty)` (nothing to migrate).
/// Any other read error is returned as `Err` so the caller does not mistake an unreadable file for an empty one and consume it.
/// The one-time migration that seeds folder-trust from prior grants consumes this list.
pub fn list_trusted_projects_with_file(trust_file: &Path) -> std::io::Result<Vec<PathBuf>> {
    let content = match std::fs::read_to_string(trust_file) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(PathBuf::from)
        .collect())
}

// ── Hook enable/disable ─────────────────────────────────────────────────

/// Disabled hooks are listed in `$FUIGO_HOME/disabled-hooks`, one hook name per line.
pub fn is_hook_disabled(hook_name: &str) -> bool {
    match disabled_hooks_file_path() {
        Some(file) => is_hook_disabled_with_file(hook_name, &file),
        None => false,
    }
}

/// What the hooks modal and status reports show as disabled; managed-policy hooks never do, since dispatch ignores their disable state.
/// Keep this in lockstep with `dispatcher::eligible_or_record_skip` or the modal lies about what runs.
pub fn hook_disabled_for_display(spec: &crate::config::HookSpec) -> bool {
    hook_disabled_for_display_with(spec, &DisabledHooks::load())
}

/// The same rule as [`hook_disabled_for_display`], evaluated against a pre-loaded snapshot (bulk display passes and tests).
pub fn hook_disabled_for_display_with(
    spec: &crate::config::HookSpec,
    disabled: &DisabledHooks,
) -> bool {
    !spec.is_managed_policy() && (!spec.enabled || disabled.contains(&spec.name))
}

/// One-shot snapshot of the disabled-hooks file, for callers that evaluate many specs per pass (dispatch loops, the stop-gate guard).
/// One `load()` replaces a file read per spec.
pub struct DisabledHooks(std::collections::HashSet<String>);

impl DisabledHooks {
    /// Build from explicit names (tests; no filesystem or env dependence).
    pub fn from_names<I: IntoIterator<Item = String>>(names: I) -> Self {
        Self(names.into_iter().collect())
    }

    pub fn load() -> Self {
        let names = disabled_hooks_file_path()
            .and_then(|file| std::fs::read_to_string(file).ok())
            .map(|content| {
                content
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        Self(names)
    }

    pub fn contains(&self, hook_name: &str) -> bool {
        self.0.contains(hook_name)
    }
}

fn is_hook_disabled_with_file(hook_name: &str, file: &Path) -> bool {
    let content = match std::fs::read_to_string(file) {
        Ok(c) => c,
        Err(_) => return false,
    };
    content
        .lines()
        .any(|l| !l.trim().is_empty() && !l.trim().starts_with('#') && l.trim() == hook_name)
}

/// Disable a hook by name (append to `$FUIGO_HOME/disabled-hooks`).
pub fn disable_hook(hook_name: &str) -> Result<(), String> {
    let file = disabled_hooks_file_path()
        .ok_or_else(|| "no user fuigo home (set $FUIGO_HOME or $HOME)".to_string())?;
    disable_hook_with_file(hook_name, &file)
}

fn disable_hook_with_file(hook_name: &str, file: &Path) -> Result<(), String> {
    use fuigo_config::fs_atomic::Edit;
    edit_disabled_hooks(file, |current| {
        let content = match current {
            Ok(bytes) => String::from_utf8(bytes.unwrap_or_default().to_vec()).map_err(|_| {
                "failed to open disabled-hooks file: stream did not contain valid UTF-8".to_owned()
            })?,
            // Unreadable: it was treated as "not disabled" and appended to; a
            // replacement built from nothing would drop every line, so refuse.
            Err(e) => return Err(format!("failed to open disabled-hooks file: {e}")),
        };
        if content
            .lines()
            .any(|l| !l.trim().is_empty() && !l.trim().starts_with('#') && l.trim() == hook_name)
        {
            return Ok(Edit::Keep(()));
        }
        let mut updated = content;
        if !updated.is_empty() && !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(hook_name);
        updated.push('\n');
        Ok(Edit::Replace {
            contents: updated.into_bytes(),
            value: (),
        })
    })
}

/// Read-modify-write `disabled-hooks` through the shared helper
/// (`fuigo_config::fs_atomic::edit_locked`, on `disabled-hooks.lock`): a
/// disable and an enable in two processes cannot lose each other's change, and
/// the file is replaced (written through a symlink, its mode kept; a new file
/// gets `0o666 & !umask` as the old append created it), never truncated in
/// place, so a reader never sees it empty and runs a hook the user disabled.
fn edit_disabled_hooks<T>(
    file: &Path,
    edit: impl FnMut(fuigo_config::fs_atomic::Current<'_>) -> Result<fuigo_config::fs_atomic::Edit<T>, String>,
) -> Result<T, String> {
    use fuigo_config::fs_atomic::EditError;
    use fuigo_config::write_through::{NewFileMode, stage_file_atomically_with};
    fuigo_config::fs_atomic::edit_locked(
        file,
        |bytes| stage_file_atomically_with(file, bytes, NewFileMode::Default),
        edit,
    )
    .map_err(|e| match e {
        EditError::Edit(e) => e,
        EditError::Lock(e) => format!("failed to lock disabled-hooks file: {e}"),
        EditError::Write(e) => format!("failed to write disabled-hooks file: {e}"),
    })
}

/// Enable a hook by name (remove from `$FUIGO_HOME/disabled-hooks`).
pub fn enable_hook(hook_name: &str) -> Result<bool, String> {
    match disabled_hooks_file_path() {
        Some(file) => enable_hook_with_file(hook_name, &file),
        None => Ok(false),
    }
}

fn enable_hook_with_file(hook_name: &str, file: &Path) -> Result<bool, String> {
    use fuigo_config::fs_atomic::Edit;
    // Nothing to enable in a missing file; take no lock for it.
    if matches!(std::fs::metadata(file), Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(false);
    }
    edit_disabled_hooks(file, |current| {
        let content = match current {
            Ok(None) => return Ok(Edit::Keep(false)),
            Ok(Some(bytes)) => std::str::from_utf8(bytes)
                .map_err(|_| "failed to read disabled-hooks file: stream did not contain valid UTF-8".to_owned())?,
            Err(e) => return Err(format!("failed to read disabled-hooks file: {e}")),
        };
        let mut found = false;
        let new_lines: Vec<&str> = content
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') && trimmed == hook_name {
                    found = true;
                    false
                } else {
                    true
                }
            })
            .collect();
        if !found {
            return Ok(Edit::Keep(false));
        }
        let mut updated = String::new();
        for line in new_lines {
            updated.push_str(line);
            updated.push('\n');
        }
        Ok(Edit::Replace {
            contents: updated.into_bytes(),
            value: true,
        })
    })
}

/// Returns the path to `$FUIGO_HOME/disabled-hooks`, or `None` when no user fuigo home resolves.
fn disabled_hooks_file_path() -> Option<PathBuf> {
    Some(fuigo_config::user_fuigo_home()?.join("disabled-hooks"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test creates its own legacy file in its own temp dir, so no state is shared.
    fn trust_file_in(dir: &Path) -> PathBuf {
        let fuigo_dir = dir.join(".fuigo");
        std::fs::create_dir_all(&fuigo_dir).unwrap();
        fuigo_dir.join("trusted-hook-projects")
    }

    #[test]
    fn list_trusted_projects_parses_paths_skipping_comments_and_blanks() {
        let home = tempfile::tempdir().unwrap();
        let trust_file = trust_file_in(home.path());
        std::fs::write(
            &trust_file,
            "# comment\n\n/abs/project/one\n  /abs/project/two  \n# trailing\n",
        )
        .unwrap();

        let projects = list_trusted_projects_with_file(&trust_file).unwrap();
        assert_eq!(
            projects,
            vec![
                PathBuf::from("/abs/project/one"),
                PathBuf::from("/abs/project/two"),
            ]
        );
    }

    #[test]
    fn list_trusted_projects_missing_file_is_empty() {
        // The migration treats a missing file as "nothing to migrate", not as an unreadable file
        let projects =
            list_trusted_projects_with_file(Path::new("/nonexistent/trusted-hook-projects"))
                .expect("missing file resolves to Ok(empty)");
        assert!(projects.is_empty());
    }
}

#[cfg(test)]
#[path = "trust_p61_tests.rs"]
mod p61_tests;
