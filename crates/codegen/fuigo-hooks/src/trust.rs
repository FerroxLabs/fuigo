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
/// Under `allow_managed_hooks_only` every other hook shows disabled (P169).
/// Keep this in lockstep with `dispatcher::eligible_or_record_skip` or the modal lies about what runs.
pub fn hook_disabled_for_display(spec: &crate::config::HookSpec) -> bool {
    hook_disabled_for_display_with(spec, &DisabledHooks::load())
}

/// The same rule as [`hook_disabled_for_display`], evaluated against a pre-loaded snapshot (bulk display passes and tests).
pub fn hook_disabled_for_display_with(
    spec: &crate::config::HookSpec,
    disabled: &DisabledHooks,
) -> bool {
    disabled.blocks(spec)
}

/// Why a hook is skipped at dispatch and shown disabled in the modal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookSkipReason {
    /// Its `enabled` flag is off or its name is in `$FUIGO_HOME/disabled-hooks`.
    UserDisabled,
    /// `allow_managed_hooks_only` is pinned by managed policy and the hook is not managed policy.
    ManagedOnly,
}

/// The note shown when a hook is refused because `FUIGO_MANAGED_HOOKS_ONLY` is on for this process.
pub const MANAGED_HOOKS_ONLY_ENV_NOTE: &str = "Only managed hooks run (FUIGO_MANAGED_HOOKS_ONLY): the app running \
     Fuigo turns off user, project and plugin hooks.";

/// The note shown when a hook is refused under `allow_managed_hooks_only` (P169).
pub const MANAGED_HOOKS_ONLY_NOTE: &str = "Only managed hooks run: your organization's policy \
     (allow_managed_hooks_only) turns off user, project and plugin hooks.";

/// One-shot snapshot of the per-spec skip inputs: the disabled-hooks file and the `allow_managed_hooks_only` pin.
/// [`Self::skip_reason`] is the one rule the dispatcher, the stop-gate guard and the modal apply, so they cannot
/// disagree about what runs. One `load()` replaces a file read per spec.
#[derive(Debug, Default)]
pub struct DisabledHooks {
    names: std::collections::HashSet<String>,
    managed_only: bool,
    /// The managed-only pin is on because of `FUIGO_MANAGED_HOOKS_ONLY` (no policy file pins it).
    managed_only_by_env: bool,
    /// The disabled-hooks file exists but could not be read. Which hooks the user disabled is then unknown, so every
    /// non-managed hook is skipped rather than running one the user turned off.
    unreadable: bool,
}

impl DisabledHooks {
    /// Build from explicit names with no managed-only pin (tests; no filesystem or env dependence).
    pub fn from_names<I: IntoIterator<Item = String>>(names: I) -> Self {
        Self::new(names, false)
    }

    /// Build from explicit names and pin (tests).
    pub fn new<I: IntoIterator<Item = String>>(names: I, managed_only: bool) -> Self {
        Self {
            names: names.into_iter().collect(),
            managed_only,
            managed_only_by_env: false,
            unreadable: false,
        }
    }

    /// Build from the disabled-hooks file at `file` (no managed-only pin). A missing file disables nothing; a file
    /// that exists but cannot be read marks the set unreadable, which skips every non-managed hook.
    pub fn from_file(file: &Path, managed_only: bool) -> Self {
        let (names, unreadable) = read_disabled_names(file);
        let mut loaded = Self::new(names, managed_only);
        loaded.unreadable = unreadable;
        loaded
    }

    /// Read the disabled-hooks file and the `allow_managed_hooks_only` pin (every managed-config and requirements
    /// layer plus the Claude managed-settings file; an unreadable policy layer engages it).
    pub fn load() -> Self {
        let pin = fuigo_config::policy_sources::managed_hooks_only_pin();
        let mut loaded = match disabled_hooks_file_path() {
            Some(file) => Self::from_file(&file, pin.is_disabled()),
            None => Self::new(Vec::new(), pin.is_disabled()),
        };
        loaded.managed_only_by_env = pin.is_from_env();
        loaded
    }

    /// Mark the managed-only pin as engaged by `FUIGO_MANAGED_HOOKS_ONLY` (tests and `load`).
    pub fn with_managed_only_by_env(mut self) -> Self {
        self.managed_only = true;
        self.managed_only_by_env = true;
        self
    }

    /// The pin is on because of `FUIGO_MANAGED_HOOKS_ONLY`, not a policy file.
    pub fn managed_only_by_env(&self) -> bool {
        self.managed_only_by_env
    }

    /// The note for a hook refused under the managed-only pin, naming the env var when that is why.
    pub fn managed_only_note(&self) -> &'static str {
        if self.managed_only_by_env {
            MANAGED_HOOKS_ONLY_ENV_NOTE
        } else {
            MANAGED_HOOKS_ONLY_NOTE
        }
    }

    pub fn contains(&self, hook_name: &str) -> bool {
        self.names.contains(hook_name)
    }

    /// `allow_managed_hooks_only` is pinned.
    pub fn managed_only(&self) -> bool {
        self.managed_only
    }

    /// Managed-policy hooks are never skipped; the managed-only pin outranks a user disable as the reported reason.
    pub fn skip_reason(&self, spec: &crate::config::HookSpec) -> Option<HookSkipReason> {
        if spec.is_managed_policy() {
            return None;
        }
        if self.managed_only {
            return Some(HookSkipReason::ManagedOnly);
        }
        (!spec.enabled || self.unreadable || self.names_disable(spec)).then_some(HookSkipReason::UserDisabled)
    }

    /// The file disables `spec`: its own per-repo line, or (project hooks only) a legacy bare `project/<name>` line,
    /// which keeps applying to every repo exactly as it did before hooks were keyed by repo, so no disable is lost.
    fn names_disable(&self, spec: &crate::config::HookSpec) -> bool {
        let key = disable_key(spec);
        self.names.contains(&key) || (key != spec.name && self.names.contains(&spec.name))
    }

    /// Whether dispatch skips `spec`; also what the modal shows as disabled.
    pub fn blocks(&self, spec: &crate::config::HookSpec) -> bool {
        self.skip_reason(spec).is_some()
    }
}

/// Names listed in the disabled-hooks file, and whether the file exists but could not be read.
/// Bytes that are not UTF-8 are replaced, so the lines around them still count; a missing file is simply empty.
fn read_disabled_names(file: &Path) -> (Vec<String>, bool) {
    let bytes = match std::fs::read(file) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Vec::new(), false),
        Err(e) => {
            tracing::warn!(path = %file.display(), error = %e, "disabled-hooks file is unreadable; skipping every hook");
            return (Vec::new(), true);
        }
    };
    let names = String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    (names, false)
}

fn is_hook_disabled_with_file(hook_name: &str, file: &Path) -> bool {
    let (names, unreadable) = read_disabled_names(file);
    unreadable || names.iter().any(|n| n == hook_name)
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
        // Enabling a project hook in a repo also drops the legacy bare `project/<name>` line (see `disable_key`).
        let bare = hook_name
            .split_once('\t')
            .map(|(name, _)| name)
            .filter(|name| name.starts_with(crate::config::PROJECT_HOOK_PREFIX));
        let mut found = false;
        let new_lines: Vec<&str> = content
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                if !trimmed.is_empty()
                    && !trimmed.starts_with('#')
                    && (trimmed == hook_name || bare == Some(trimmed))
                {
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

// ── Per-repo keys for project hooks (75.B18) ───────────────────────────

/// Directory names that mark a project hook source (`<repo>/.claude/settings.json`, `<repo>/.fuigo/hooks`, `<repo>/.cursor/hooks.json`).
const PROJECT_SOURCE_DIRS: [&str; 3] = [".claude", ".fuigo", ".cursor"];

/// The folder a project hook belongs to: the parent of the `.claude` / `.fuigo` / `.cursor` directory its source lives in,
/// canonicalised when it resolves. `None` for any hook that is not a project-file hook.
fn project_scope(spec: &crate::config::HookSpec) -> Option<PathBuf> {
    if crate::config::hook_origin(spec) != crate::config::HookOrigin::ProjectFile {
        return None;
    }
    let owner = spec
        .source_dir
        .ancestors()
        .find(|a| {
            a.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| PROJECT_SOURCE_DIRS.contains(&n))
        })
        .and_then(Path::parent)
        .unwrap_or(&spec.source_dir);
    Some(dunce::canonicalize(owner).unwrap_or_else(|_| owner.to_path_buf()))
}

/// Encode a repo path so two different paths never give the same entry and the reader's `trim` cannot change it.
/// `%`, tab, newline and carriage return are always percent-escaped; so is any whitespace at either end of the path
/// (`/repos/app ` stays distinct from `/repos/app`); bytes that are not UTF-8 are escaped byte by byte, never replaced.
/// Everything else is written as is, so an entry written by an earlier build still reads the same.
fn escape_scope(path: &Path) -> String {
    enum Unit {
        Ch(char),
        Raw(u8),
    }
    let mut units: Vec<Unit> = Vec::new();
    for chunk in path.as_os_str().as_encoded_bytes().utf8_chunks() {
        units.extend(chunk.valid().chars().map(Unit::Ch));
        units.extend(chunk.invalid().iter().copied().map(Unit::Raw));
    }
    let solid = |u: &Unit| !matches!(u, Unit::Ch(c) if c.is_whitespace());
    let first = units.iter().position(solid).unwrap_or(units.len());
    let last = units.iter().rposition(solid).map_or(0, |i| i + 1);
    let mut out = String::new();
    for (i, unit) in units.iter().enumerate() {
        match unit {
            Unit::Raw(b) => out.push_str(&format!("%{b:02X}")),
            Unit::Ch(c) if matches!(c, '%' | '\t' | '\n' | '\r') || i < first || i >= last => {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
            Unit::Ch(c) => out.push(*c),
        }
    }
    out
}

/// The line `$FUIGO_HOME/disabled-hooks` holds for `spec`. A user, global, plugin or managed hook is its bare name.
/// A project hook is `<name>\t<repo folder>`, so disabling it in one repo does not switch off a same-named hook
/// (for instance a guard hook) in another.
///
/// Legacy rule (75.B18): a bare `project/<name>` line, written before project hooks were keyed by repo, is never
/// rewritten or guessed at. It keeps applying to every repo, exactly as it did, so no disable is lost. New disables
/// are written per repo. Enabling a project hook removes its per-repo line and that bare line (the user said the
/// hook should run); disabling it writes the per-repo line and leaves the bare one for the repos not yet touched.
pub fn disable_key(spec: &crate::config::HookSpec) -> String {
    match project_scope(spec) {
        Some(scope) => format!("{}\t{}", spec.name, escape_scope(&scope)),
        None => spec.name.clone(),
    }
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

    #[test]
    fn disabled_names_survive_invalid_utf8_elsewhere_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("disabled-hooks");
        let mut bytes = b"evil-hook\n".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe, b'\n']);
        bytes.extend_from_slice(b"other-hook\n");
        std::fs::write(&file, bytes).unwrap();
        assert!(is_hook_disabled_with_file("evil-hook", &file));
        assert!(is_hook_disabled_with_file("other-hook", &file));
        assert!(!is_hook_disabled_with_file("fine-hook", &file));
    }

    #[test]
    fn unreadable_disabled_file_keeps_every_hook_disabled() {
        // A directory where the file belongs: the read fails even for root.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("disabled-hooks");
        std::fs::create_dir(&file).unwrap();
        assert!(is_hook_disabled_with_file("any-hook", &file));
    }

    #[test]
    fn missing_disabled_file_disables_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_hook_disabled_with_file("any-hook", &dir.path().join("disabled-hooks")));
    }
}

#[cfg(test)]
#[path = "trust_p61_tests.rs"]
mod p61_tests;

#[cfg(test)]
#[path = "trust_u41_tests.rs"]
mod u41_tests;
