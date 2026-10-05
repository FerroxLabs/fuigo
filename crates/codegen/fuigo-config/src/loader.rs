//! TOML loading, layered merging, and `$VAR` expansion.
//!
//! The merged result is the **default** config; requirements layers sit on top via [`crate::validation`].

use std::path::Path;

use crate::paths::{system_config_dir, user_fuigo_home};
use crate::version_overrides::{self, apply_version_overrides};

/// Read and parse a TOML file WITHOUT `$VAR` expansion (empty table if absent).
/// Shared core of [`load_toml_file`] and the hook-layer read.
fn read_toml_file(path: &Path) -> std::io::Result<toml::Value> {
    read_toml_file_as(path, BlankRead::Accept)
}

/// What [`read_toml_file_as`] does with a file that reads blank.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BlankRead {
    /// A blank file is an empty table, at once.
    Accept,
    /// Re-check before believing it (the user layer; see [`confirm_blank`]).
    ConfirmStable,
}

/// How long a blank user layer is given to fill before it is re-read.
const BLANK_RECHECK_DELAY: std::time::Duration = std::time::Duration::from_millis(15);

/// Re-reads of a blank user layer whose identity keeps changing, before the
/// blank is accepted anyway.
const BLANK_RECHECKS: usize = 3;

fn read_toml_file_as(path: &Path, blank: BlankRead) -> std::io::Result<toml::Value> {
    let read = match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() && blank == BlankRead::ConfirmStable => confirm_blank(path),
        other => other,
    };
    match read {
        Ok(s) if s.trim().is_empty() => Ok(toml::Value::Table(toml::map::Map::new())),
        Ok(s) => match toml::from_str::<toml::Value>(&s) {
            Ok(v) => Ok(v),
            Err(e) => {
                // The detail is built from the span, never from Display: Display echoes the offending source line, which may carry a secret
                // Safe to log and to return to a client
                let detail = toml_error_detail(&s, &e);
                tracing::error!(file = %path.display(), "config toml has syntax errors: {detail}");
                Err(std::io::Error::other(detail))
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(toml::Value::Table(toml::map::Map::new()))
        }
        Err(e) => {
            tracing::error!(file = %path.display(), "config file unreadable: {e}");
            Err(e)
        }
    }
}

/// A blank user `config.toml` is either a deliberate reset (the user emptied
/// it, which must be honoured: no settings, no trusted origins) or a file
/// caught between an in-place writer's truncate and its write (an editor
/// saving in place), which must not be read as "no settings" (R013 §1.5).
/// Content cannot tell them apart; time can. So the blank is re-read after
/// [`BLANK_RECHECK_DELAY`]:
///
/// - it now has content: that content is used;
/// - it is still blank and its identity (inode, size, times) did not move
///   across the wait: the blank is stable, and accepted;
/// - it is still blank but did move: a writer is active, so wait again, at
///   most [`BLANK_RECHECKS`] times; if it never holds still, the read FAILS
///   (`ResourceBusy`) rather than load "no settings" from a file that is
///   being rewritten. Callers treat that like any unreadable config (the
///   reloader keeps the last good layers);
/// - it is gone: absent is empty, as always.
///
/// Costs one short wait only when the user layer is blank. Atomic writers
/// (every Fuigo writer since P17-F1) never expose a blank file at all.
fn confirm_blank(path: &Path) -> std::io::Result<String> {
    for _ in 0..BLANK_RECHECKS {
        let before = FileStamp::of(path);
        blank_recheck_wait();
        match std::fs::read_to_string(path) {
            Ok(again) if !again.trim().is_empty() => return Ok(again),
            Ok(again) => {
                let after = FileStamp::of(path);
                if before.is_some() && before == after {
                    return Ok(again);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::ResourceBusy,
        format!(
            "{} read blank and kept changing across {BLANK_RECHECKS} re-reads; \
             not treating a file that is being rewritten as empty",
            path.display()
        ),
    ))
}

/// The identity [`confirm_blank`] compares across its wait.
#[derive(PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    ino_ctime: (u64, i64, i64),
    // Windows: which file this is. Size and modified time cannot tell a blank
    // file from the blank file that replaced it within one tick of the clock
    // that stamps files (about a millisecond, up to ~16 ms).
    #[cfg(windows)]
    file: crate::managed_text::FileIdentity,
}

impl FileStamp {
    /// `None` when the file cannot be examined, which is never a stable
    /// blank: on Windows that includes a file whose identity cannot be read
    /// (two unreadable identities must not pass for "the same file").
    fn of(path: &Path) -> Option<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;
        let md = std::fs::metadata(path).ok()?;
        Some(Self {
            len: md.len(),
            modified: md.modified().ok(),
            #[cfg(unix)]
            ino_ctime: (md.ino(), md.ctime(), md.ctime_nsec()),
            #[cfg(windows)]
            file: crate::managed_text::FileIdentity::of_file(path).ok()?,
        })
    }
}

#[cfg(not(test))]
fn blank_recheck_wait() {
    std::thread::sleep(BLANK_RECHECK_DELAY);
}

/// Tests replace the wait with a hook that plays the concurrent writer.
#[cfg(test)]
fn blank_recheck_wait() {
    let _ = BLANK_RECHECK_DELAY;
    blank_hook::fire();
}

#[cfg(test)]
pub(crate) mod blank_hook {
    thread_local! {
        static HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
            const { std::cell::RefCell::new(None) };
        static FIRED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Install `hook` (run in place of the wait) and reset the count.
    pub(crate) fn set(hook: Option<Box<dyn FnMut()>>) {
        HOOK.with(|h| *h.borrow_mut() = hook);
        FIRED.with(|f| f.set(0));
    }

    /// Waits taken on this thread since the last [`set`].
    pub(crate) fn fired() -> usize {
        FIRED.with(std::cell::Cell::get)
    }

    pub(super) fn fire() {
        FIRED.with(|f| f.set(f.get() + 1));
        HOOK.with(|h| {
            if let Some(hook) = h.borrow_mut().as_mut() {
                hook();
            }
        });
    }
}

/// Load and parse a TOML file, expanding `$VAR` references. Empty table if absent.
pub fn load_toml_file(path: &Path) -> std::io::Result<toml::Value> {
    let mut v = read_toml_file(path)?;
    expand_env_vars_in_toml(&mut v);
    Ok(v)
}

/// A snippet-free description of a TOML parse error: `"TOML parse error at line L, column C: <what>"` (or just the message when there's no span).
/// Never includes the offending source line (`Display` echoes it and it may carry a secret), so this is safe to log or return to a client.
/// Shared with the trace `config_files` artifact so the redaction rule lives in one place.
pub fn toml_error_detail(src: &str, e: &toml::de::Error) -> String {
    match e.span() {
        Some(span) => {
            let (line, col) = line_col(src, span.start);
            format!(
                "TOML parse error at line {line}, column {col}: {}",
                e.message()
            )
        }
        None => e.message().to_owned(),
    }
}

/// 1-based (line, column) of a byte offset within `src`.
fn line_col(src: &str, byte: usize) -> (usize, usize) {
    let mut line = 1;
    let mut col = 1;
    for (i, ch) in src.char_indices() {
        if i >= byte {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// [`load_toml_file`] plus that layer's `[[version_overrides]]`.
/// Use for fuigo config files; use [`load_toml_file`] directly for unrelated TOML.
///
/// P118: a file outside the user-level and managed locations (a project's `.fuigo/config.toml`, a plugin's) may not
/// name the saved API key `FUIGO_API_KEY`; see [`crate::key_naming`]. Its references are refused before `$VAR`
/// expansion.
pub fn load_config_file(path: &Path) -> std::io::Result<toml::Value> {
    load_config_file_with_key_naming(path, crate::key_naming::source_may_name_saved_key(path))
}

/// [`load_config_file`] with the tier decided by the caller (`may_name_saved_key`).
pub fn load_config_file_with_key_naming(path: &Path, may_name_saved_key: bool) -> std::io::Result<toml::Value> {
    let mut v = read_toml_file(path)?;
    let label = path.display().to_string();
    if !may_name_saved_key {
        // Refuse, and mark every server this file defines (also inside its `version_overrides`) so the mark travels
        // with the definition to the spawn, where the final strings are refused once more (Astra r3 N2, N4).
        let refused = crate::key_naming::refuse_toml_source(&mut v, &label);
        crate::key_naming::report_refusals(&refused);
    }
    expand_env_vars_in_toml(&mut v);
    if !may_name_saved_key {
        // Expansion can build a reference out of text that held none (`${D}FUIGO_API_KEY` with `D = "$"`, a default
        // `${X:-FUIGO_API_KEY}` in a field that names a variable): refuse again on the expanded values.
        let refused = crate::key_naming::refuse_key_references_in_toml(&mut v, &label);
        crate::key_naming::report_refusals(&refused);
    }
    apply_version_overrides_with_registered(&mut v)?;
    if !may_name_saved_key {
        // And once more on the layered result: an override is the last thing that can change what a server holds.
        let refused = crate::key_naming::refuse_key_references_in_toml(&mut v, &label);
        crate::key_naming::report_refusals(&refused);
    }
    Ok(v)
}

/// The user `config.toml` layer parsed from `src` exactly as [`load_from_disk`]
/// parses the file's contents: blank is an empty table, `$VAR`s are expanded,
/// `[[version_overrides]]` applied. For a writer that already holds the bytes
/// it is about to rewrite (the shell's settings save decides from the bytes
/// `fs_atomic::edit_locked` hands it, P72). A blank `src` is believed as it
/// is: the caller's own snapshot check, not a re-read, catches a file caught
/// mid-write.
///
/// # Errors
///
/// A TOML syntax error (described without the offending line, as
/// [`toml_error_detail`]), or a version-override failure.
pub fn parse_user_config_layer(src: &str) -> std::io::Result<toml::Value> {
    let mut v = if src.trim().is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        toml::from_str::<toml::Value>(src)
            .map_err(|e| std::io::Error::other(toml_error_detail(src, &e)))?
    };
    expand_env_vars_in_toml(&mut v);
    apply_version_overrides_with_registered(&mut v)?;
    Ok(v)
}

pub fn load_from_disk() -> std::io::Result<toml::Value> {
    load_user_config_layer(user_fuigo_home().as_deref(), USER_CONFIG_FILENAME)
}

/// User config filename (`$FUIGO_HOME/config.toml`), shared by the loaders here.
pub const USER_CONFIG_FILENAME: &str = "config.toml";

/// Managed config filename, shared by the loaders in this module.
pub const MANAGED_CONFIG_FILENAME: &str = "managed_config.toml";

/// Requirements (cloud-cache) filename, synced from the server alongside the managed config.
pub const REQUIREMENTS_FILENAME: &str = "requirements.toml";

/// Unsigned folder-trust store (`$FUIGO_HOME/trusted_folders.toml`).
pub const TRUSTED_FOLDERS_FILENAME: &str = "trusted_folders.toml";

/// User-global sandbox profile definitions (`$FUIGO_HOME/sandbox.toml`).
pub const SANDBOX_CONFIG_FILENAME: &str = "sandbox.toml";

/// Legacy project-hook trust list (`$FUIGO_HOME/trusted-hook-projects`).
/// Migrated into [`TRUSTED_FOLDERS_FILENAME`] on the next unsandboxed start.
pub const TRUSTED_HOOK_PROJECTS_FILENAME: &str = "trusted-hook-projects";

/// Plugin trust list (`$FUIGO_HOME/trusted-plugins`).
pub const TRUSTED_PLUGINS_FILENAME: &str = "trusted-plugins";

pub fn load_managed_config() -> std::io::Result<toml::Value> {
    load_user_config_layer(user_fuigo_home().as_deref(), MANAGED_CONFIG_FILENAME)
}

/// Load a user-tier config layer from `<home>/<filename>`.
/// With no resolvable user home, returns an empty table rather than reading a cwd-relative `.fuigo/<filename>`.
/// The cwd fallback would silently promote an untrusted project `.fuigo` to the user tier.
///
/// A blank file is re-checked before it is believed (see [`confirm_blank`]).
fn load_user_config_layer(home: Option<&Path>, filename: &str) -> std::io::Result<toml::Value> {
    match home {
        Some(g) => {
            let mut v = read_toml_file_as(&g.join(filename), BlankRead::ConfirmStable)?;
            expand_env_vars_in_toml(&mut v);
            apply_version_overrides_with_registered(&mut v)?;
            Ok(v)
        }
        None => Ok(toml::Value::Table(toml::map::Map::new())),
    }
}

pub fn load_system_managed_config() -> std::io::Result<toml::Value> {
    let mut v = match system_config_dir() {
        Some(dir) => load_toml_file(&dir.join(MANAGED_CONFIG_FILENAME))?,
        None => toml::Value::Table(toml::map::Map::new()),
    };
    apply_version_overrides_with_registered(&mut v)?;
    Ok(v)
}

/// One managed-config layer: the parsed TOML and the file it came from.
#[derive(Debug, Clone)]
pub struct ManagedConfigLayer {
    pub value: toml::Value,
    pub path: std::path::PathBuf,
    /// `true` for the root-owned system layer (`/etc/fuigo`), derived from the load directory.
    pub is_system: bool,
}

/// All `managed_config.toml` layers in apply order (system first, user last).
/// Absent layers are skipped; unparsable layers are skipped with a warning.
/// One bad layer never drops the others.
pub fn managed_config_layers() -> Vec<ManagedConfigLayer> {
    managed_config_layers_at(system_config_dir().as_deref(), user_fuigo_home().as_deref())
}

/// [`managed_config_layers`] with explicit directories.
pub fn managed_config_layers_at(
    system_dir: Option<&Path>,
    user_home: Option<&Path>,
) -> Vec<ManagedConfigLayer> {
    let mut layers = Vec::new();
    for (dir, is_system) in [(system_dir, true), (user_home, false)] {
        let Some(path) = dir.map(|d| d.join(MANAGED_CONFIG_FILENAME)) else {
            continue;
        };
        if !path.is_file() {
            continue;
        }
        match load_config_file_with_key_naming(&path, true) {
            Ok(value) => layers.push(ManagedConfigLayer {
                value,
                path,
                is_system,
            }),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping managed_config.toml layer that failed to load or parse")
            }
        }
    }
    layers
}

/// A hook's origin (held by `fuigo_hooks::HookSpec::layer`).
/// Defined here, not in `fuigo-hooks`, since the dep direction is `fuigo-hooks -> fuigo-config`.
/// This crate sets the config tiers; `File`/`Plugin` are set downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookProvenance {
    /// `/etc/fuigo/managed_config.toml` (root-owned).
    SystemManaged,
    /// `$FUIGO_HOME/managed_config.toml` (server-synced, user-writable).
    Managed,
    /// System-tier `requirements.toml` (root-owned, e.g. `/etc/fuigo`).
    Requirements,
    /// `$FUIGO_HOME/requirements.toml` (user-writable).
    UserRequirements,
    /// `$FUIGO_HOME/config.toml`.
    User,
    /// A JSON hook file (the hooks directory, a vendor settings file, or a configured hooks path).
    File,
    /// A plugin-contributed hook.
    Plugin,
    /// A tier this build doesn't recognize (e.g. a newer peer's provenance over the wire).
    /// Forward-tolerant so an unknown value degrades to a conservative origin instead of failing the whole `HookRegistry` decode.
    #[serde(other)]
    Unknown,
}

/// Defaults to `File` so wire records written before provenance existed decode as the most conservative origin.
impl Default for HookProvenance {
    fn default() -> Self {
        Self::File
    }
}

impl HookProvenance {
    /// Root-owned admin policy tiers; the user cannot disable or skip their hooks.
    /// Every disable path must consult this predicate rather than re-derive the rule from names or paths.
    /// `$FUIGO_HOME` tiers (`Managed`, `UserRequirements`) never qualify: the user owns that directory and can rewrite or repoint it.
    /// Exempting them would let any file the user edits grant itself the exemption.
    pub fn is_managed_policy(self) -> bool {
        matches!(self, Self::SystemManaged | Self::Requirements)
    }

    /// Authority rank for duplicate resolution: when byte-identical hooks arrive from several tiers, the highest-ranked copy keeps its provenance.
    /// The provenance carries the no-disable rule and the pinned timeout/env; root-owned tiers outrank `$FUIGO_HOME` tiers.
    /// Deliberately NOT the config-merge precedence (where user overrides managed).
    /// Merge precedence answers "whose VALUE wins"; this answers "whose copy of one identical hook is authoritative": ownership, not recency.
    pub fn authority_rank(self) -> u8 {
        match self {
            Self::SystemManaged => 6,
            Self::Requirements => 5,
            Self::Managed => 4,
            Self::UserRequirements => 3,
            Self::User => 2,
            Self::File | Self::Plugin => 1,
            Self::Unknown => 0,
        }
    }

    /// The snake_case wire string (matches the derived serde representation).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SystemManaged => "system_managed",
            Self::Managed => "managed",
            Self::Requirements => "requirements",
            Self::UserRequirements => "user_requirements",
            Self::User => "user",
            Self::File => "file",
            Self::Plugin => "plugin",
            Self::Unknown => "unknown",
        }
    }
}

impl std::str::FromStr for HookProvenance {
    type Err = std::convert::Infallible;

    /// Inverse of [`HookProvenance::as_str`].
    /// Unrecognized strings map to [`HookProvenance::Unknown`] (forward-tolerant), so this never fails.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "system_managed" => Self::SystemManaged,
            "managed" => Self::Managed,
            "requirements" => Self::Requirements,
            "user_requirements" => Self::UserRequirements,
            "user" => Self::User,
            "file" => Self::File,
            "plugin" => Self::Plugin,
            _ => Self::Unknown,
        })
    }
}

/// One config layer's `hooks` subtree (read without `$VAR` expansion) plus its provenance.
#[derive(Debug, Clone)]
pub struct HookConfigLayer {
    provenance: HookProvenance,
    source_name: String,
    path: std::path::PathBuf,
    hooks: toml::Value,
}

impl HookConfigLayer {
    /// Construct a layer directly (in-memory config and tests); the synthesized `path` mirrors `source_name`.
    /// Real layers come from [`hook_config_layers`].
    pub fn new(
        provenance: HookProvenance,
        source_name: impl Into<String>,
        hooks: toml::Value,
    ) -> Self {
        let source_name = source_name.into();
        let path = std::path::PathBuf::from(&source_name);
        Self {
            provenance,
            source_name,
            path,
            hooks,
        }
    }

    pub fn provenance(&self) -> HookProvenance {
        self.provenance
    }

    /// A stable label for this layer (e.g. `"managed"`, `"requirements/user"`), used to prefix hook names for display and dedup.
    pub fn source_name(&self) -> &str {
        &self.source_name
    }

    /// The layer's backing file, so parse errors can cite a real path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// The raw `hooks` table, unexpanded so a literal `${VAR}` reaches the runner.
    pub fn hooks(&self) -> &toml::Value {
        &self.hooks
    }
}

/// All config-layer `hooks` blocks, highest authority first (matching [`effective_config_base`]).
/// Read WITHOUT env-expansion and never merged (hooks combine additively downstream).
/// Absent or unparsable layers are skipped with a warning so one bad layer can't drop the others.
/// macOS MDM is excluded (not a TOML file).
pub fn hook_config_layers() -> Vec<HookConfigLayer> {
    hook_config_layers_at(system_config_dir().as_deref(), user_fuigo_home().as_deref())
}

/// Warn when a policy-tier hooks file is a symlink or not root-owned; the no-disable exemption assumes admin ownership of the system dir.
#[cfg(unix)]
fn warn_unless_root_owned(path: &Path) {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => tracing::warn!(
            path = %path.display(),
            "policy-tier hooks file is a symlink; its hooks cannot be disabled — ensure the target is admin-controlled"
        ),
        Ok(meta) if meta.uid() != 0 => tracing::warn!(
            path = %path.display(),
            uid = meta.uid(),
            "policy-tier hooks file is not root-owned; its hooks cannot be disabled — enforcement assumes admin ownership"
        ),
        // Root-owned but group/world-writable is the sneakier misconfig: any local user can edit the "non-disableable" policy
        Ok(meta) if meta.mode() & 0o022 != 0 => tracing::warn!(
            path = %path.display(),
            mode = format!("{:o}", meta.mode() & 0o777),
            "policy-tier hooks file is group- or world-writable; its hooks cannot be disabled — restrict write access to root"
        ),
        _ => {}
    }
}

#[cfg(not(unix))]
fn warn_unless_root_owned(_path: &Path) {}

/// [`hook_config_layers`] with explicit directories, for tests.
pub fn hook_config_layers_at(
    system_dir: Option<&Path>,
    user_home: Option<&Path>,
) -> Vec<HookConfigLayer> {
    /// One candidate config-hook layer: which directory and filename to read, and the provenance/label to stamp on hooks found there.
    struct LayerSpec<'a> {
        dir: Option<&'a Path>,
        filename: &'a str,
        provenance: HookProvenance,
        source_name: &'a str,
    }

    // Highest config authority first, matching `effective_config_base` precedence (requirements > user > managed > system_managed)
    // User overrides managed in this model
    // Byte-identical duplicates resolve by `HookProvenance::authority_rank` regardless of this order; every distinct hook runs regardless
    let specs = [
        LayerSpec {
            dir: system_dir,
            filename: REQUIREMENTS_FILENAME,
            provenance: HookProvenance::Requirements,
            source_name: "requirements/system",
        },
        LayerSpec {
            dir: user_home,
            filename: REQUIREMENTS_FILENAME,
            provenance: HookProvenance::UserRequirements,
            source_name: "requirements/user",
        },
        LayerSpec {
            dir: user_home,
            filename: USER_CONFIG_FILENAME,
            provenance: HookProvenance::User,
            source_name: "user",
        },
        LayerSpec {
            dir: user_home,
            filename: MANAGED_CONFIG_FILENAME,
            provenance: HookProvenance::Managed,
            source_name: "managed",
        },
        LayerSpec {
            dir: system_dir,
            filename: MANAGED_CONFIG_FILENAME,
            provenance: HookProvenance::SystemManaged,
            source_name: "system_managed",
        },
    ];

    let mut layers = Vec::new();
    for LayerSpec {
        dir,
        filename,
        provenance,
        source_name,
    } in specs
    {
        let Some(path) = dir.map(|d| d.join(filename)) else {
            continue;
        };
        if !path.is_file() {
            continue;
        }
        // The no-disable exemption rests on OS ownership; a misconfigured system dir would silently create non-disableable hooks, so make it loud
        // Classification is unchanged (a root-owned deployment is the documented requirement, not something we can verify portably)
        if provenance.is_managed_policy() {
            warn_unless_root_owned(&path);
        }
        // No `$VAR` expansion: a literal `${VAR}` must reach the hook runner, which does the single expansion (expanding here would double-expand)
        let mut value = match read_toml_file(&path) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping config layer whose hooks could not be read");
                continue;
            }
        };
        // Apply `[[version_overrides]]` (parity with `load_config_file`); deep-merge only, no `$VAR` expansion, so the layer stays unexpanded
        if let Err(e) = apply_version_overrides_with_registered(&mut value) {
            tracing::warn!(path = %path.display(), error = %e, "skipping config layer whose version_overrides failed to apply");
            continue;
        }
        let Some(hooks) = value.get("hooks") else {
            continue;
        };
        if !hooks.is_table() {
            tracing::warn!(path = %path.display(), "ignoring non-table `hooks` value in config layer");
            continue;
        }
        layers.push(HookConfigLayer {
            provenance,
            source_name: source_name.to_string(),
            path: path.clone(),
            hooks: hooks.clone(),
        });
    }
    layers
}

/// Applies matching `[[version_overrides]]` patches against the running CLI version; strips the section either way.
/// If the installed version can't be parsed (broken `FUIGO_TEST_VERSION` in dev), it silently strips without applying, keeping the CLI usable.
pub fn apply_version_overrides_with_registered(value: &mut toml::Value) -> std::io::Result<()> {
    match fuigo_version::installed_semver() {
        Ok(version) => apply_version_overrides(value, &version)
            .map_err(|e| std::io::Error::other(e.redacted())),
        Err(_) => {
            if let Some(table) = value.as_table_mut() {
                table.remove(version_overrides::VERSION_OVERRIDES_KEY);
            }
            Ok(())
        }
    }
}

/// Normalize a single config layer in place, before it is merged with the others.
///
/// Currently: couple `[toolset.web_search]`'s mutually-exclusive `allowed_domains` and `excluded_domains`.
/// If exactly one is set (non-empty), clear the other to `[]`, so the two keys travel together.
/// `deep_merge_toml` then replaces the whole policy from the winning layer instead of mixing keys across layers.
/// Both-set (a user error) and both-unset are left alone; the both-set case is handled downstream where the section is read.
///
/// This runs on every input of the merge, not only the disk layers.
/// Campaign and version-override patches overlay *after* the layer merge, so they are normalized too, in `apply_patches`.
pub(crate) fn normalize_config_layer(layer: &mut toml::Value) {
    let Some(web_search) = layer
        .as_table_mut()
        .and_then(|t| t.get_mut("toolset"))
        .and_then(|t| t.as_table_mut())
        .and_then(|t| t.get_mut("web_search"))
        .and_then(|v| v.as_table_mut())
    else {
        return;
    };
    let non_empty = |table: &toml::value::Table, key: &str| {
        table
            .get(key)
            .and_then(toml::Value::as_array)
            .is_some_and(|a| !a.is_empty())
    };
    let allowed = non_empty(web_search, "allowed_domains");
    let excluded = non_empty(web_search, "excluded_domains");
    if allowed && !excluded {
        web_search.insert(
            "excluded_domains".to_string(),
            toml::Value::Array(Vec::new()),
        );
    } else if excluded && !allowed {
        web_search.insert(
            "allowed_domains".to_string(),
            toml::Value::Array(Vec::new()),
        );
    }
}

/// Recursively merge `overrides` into `base`. Values in `overrides` win.
pub fn deep_merge_toml(base: &mut toml::Value, overrides: &toml::Value) {
    if let toml::Value::Table(overrides_table) = overrides
        && let toml::Value::Table(base_table) = base
    {
        for (key, value) in overrides_table {
            if let Some(existing) = base_table.get_mut(key) {
                deep_merge_toml(existing, value);
            } else {
                base_table.insert(key.clone(), value.clone());
            }
        }
    } else {
        *base = overrides.clone();
    }
}

/// Expand `$VAR` / `${VAR}` in all string values.
///
/// P147: a `${FUIGO_API_KEY:-default}` is kept for the destination only where the saved key is resolved when the value
/// is used (an MCP server's `env`, `args` and `headers`, a model's `api_key`); everywhere else it is its default, as
/// without a key in 1.0.20 (those places never receive the saved key).
pub fn expand_env_vars_in_toml(value: &mut toml::Value) {
    expand_env_vars_in_toml_at(value, &mut Vec::new());
}

fn expand_env_vars_in_toml_at(value: &mut toml::Value, path: &mut Vec<String>) {
    match value {
        toml::Value::String(s) => {
            let expanded = expand_env_vars_in_string_keeping(s, key_default_resolves_at(path));
            if expanded != *s {
                *s = expanded;
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                expand_env_vars_in_toml_at(item, path);
            }
        }
        toml::Value::Table(table) => {
            for (key, item) in table.iter_mut() {
                path.push(key.clone());
                expand_env_vars_in_toml_at(item, path);
                path.pop();
            }
        }
        _ => {}
    }
}

/// Whether a config value at `path` is resolved against the saved key where it is used (see
/// [`expand_env_vars_in_toml`]).
fn key_default_resolves_at(path: &[String]) -> bool {
    let in_server_values = path
        .iter()
        .position(|seg| seg == "mcp_servers")
        .and_then(|i| path.get(i + 2))
        .is_some_and(|field| matches!(field.as_str(), "env" | "args" | "headers"));
    // A model's or a provider's own `api_key` (`[model.<name>]`, `[models.<name>]`, `[model_providers.<name>]`), not a
    // map entry that happens to be named `api_key` (`query_params`, `extra_headers`, `[models.extra_headers]`: Astra
    // r2 N1, r3 #1, #2).
    let model_api_key = path.len() >= 3
        && path[path.len() - 1] == "api_key"
        && matches!(path[path.len() - 3].as_str(), "model" | "models" | "model_providers")
        && !matches!(
            path[path.len() - 2].as_str(),
            "extra_headers" | "query_params" | "env_http_headers" | "http_headers" | "headers"
        );
    in_server_values || model_api_key
}

/// Expand `$VAR` / `${VAR}` in a single string, from the process environment.
///
/// P70a: an unexported `${FUIGO_API_KEY}` stays literal here even when the user saved a key; the places that use the
/// value resolve it late (`crate::credential_env::resolve_first_party_key_references`), so no record of config holds
/// the key. P147: so does an unexported `${FUIGO_API_KEY:-default}` (its default expanded); a place that never receives
/// the key takes the default with [`crate::credential_env::apply_first_party_key_defaults`].
pub fn expand_env_vars_in_string(input: &str) -> String {
    expand_env_vars_in_string_keeping(input, true)
}

fn expand_env_vars_in_string_keeping(input: &str, key_default_resolves: bool) -> String {
    // P70a (Astra f4 #1, f6): a `$`-run before the first-party name (`$${FUIGO_API_KEY}`, any form) is kept as
    // written, so the `$$` escape cannot produce a plain reference that a destination would resolve to the saved key.
    // P147: an exported key is expanded here, as before.
    let keep_defaulted =
        key_default_resolves && std::env::var_os(crate::credential_env::FIRST_PARTY_KEY_ENV_VAR).is_none();
    crate::credential_env::expand_keeping_first_party_references(input, keep_defaulted, |text| {
        let context = |name: &str| std::env::var(name).ok();
        shellexpand::env_with_context_no_errors(text, context).into_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, contents: &str) {
        std::fs::write(dir.join(name), contents).unwrap();
    }

    #[test]
    fn hook_config_layers_reads_each_layer_unmerged_with_provenance() {
        let sys = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        write(
            home.path(),
            "config.toml",
            "[[hooks.PreToolUse]]\nmatcher = \"Bash\"\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"${HOME}/u.sh\"\n",
        );
        write(
            home.path(),
            MANAGED_CONFIG_FILENAME,
            "[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"/m.sh\"\n",
        );
        write(
            sys.path(),
            REQUIREMENTS_FILENAME,
            "[[hooks.PostToolUse]]\n[[hooks.PostToolUse.hooks]]\ntype = \"command\"\ncommand = \"/r.sh\"\n",
        );

        let layers = hook_config_layers_at(Some(sys.path()), Some(home.path()));

        // Highest authority first, each layer keeping its own provenance.
        let names: Vec<_> = layers.iter().map(|l| l.source_name().to_string()).collect();
        assert_eq!(names, vec!["requirements/system", "user", "managed"]);
        assert_eq!(layers[1].provenance(), HookProvenance::User);
        // Unmerged, and `${HOME}` stays literal (the runner expands, not the loader).
        let cmd = layers[1].hooks()["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        assert_eq!(cmd, "${HOME}/u.sh");
    }

    /// The user-writable `$FUIGO_HOME/requirements.toml` stamps `UserRequirements`, never the exempt `Requirements`.
    /// A file the user owns cannot grant itself the no-disable exemption.
    #[test]
    fn user_requirements_layer_is_not_managed_policy() {
        let user_home = tempfile::tempdir().unwrap();
        std::fs::write(
            user_home.path().join("requirements.toml"),
            "[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"x.sh\"\n",
        )
        .unwrap();
        let layers = hook_config_layers_at(None, Some(user_home.path()));
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].provenance(), HookProvenance::UserRequirements);
        assert_eq!(layers[0].source_name(), "requirements/user");
        assert!(!layers[0].provenance().is_managed_policy());
    }

    #[test]
    fn hook_config_layers_bad_user_layer_does_not_drop_managed() {
        let home = tempfile::tempdir().unwrap();
        write(home.path(), "config.toml", "this is = = not valid toml");
        write(
            home.path(),
            MANAGED_CONFIG_FILENAME,
            "[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"/m.sh\"\n",
        );
        let layers = hook_config_layers_at(None, Some(home.path()));
        let names: Vec<_> = layers.iter().map(|l| l.source_name().to_string()).collect();
        assert_eq!(names, vec!["managed"]);
    }

    /// Direct contract for `deep_merge_toml`: nested tables merge (siblings preserved), arrays replace (not concatenate), missing keys insert.
    #[test]
    fn deep_merge_toml_table_merge_array_replace_and_insert() {
        let mut base: toml::Value = toml::from_str(
            r#"
            [features.telemetry]
            enabled = false
            sample_rate = 0.0

            [server]
            allowed = ["a", "b"]
            "#,
        )
        .unwrap();
        let overrides: toml::Value = toml::from_str(
            r#"
            [features.telemetry]
            enabled = true

            [server]
            allowed = ["c"]

            [brand_new]
            x = 1
            "#,
        )
        .unwrap();

        deep_merge_toml(&mut base, &overrides);

        assert_eq!(
            base["features"]["telemetry"]["enabled"].as_bool(),
            Some(true)
        );
        assert_eq!(
            base["features"]["telemetry"]["sample_rate"].as_float(),
            Some(0.0)
        );
        let arr: Vec<_> = base["server"]["allowed"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(arr, vec!["c"]);
        assert_eq!(base["brand_new"]["x"].as_integer(), Some(1));
    }

    fn ws_layer(body: &str) -> toml::Value {
        toml::from_str(&format!("[toolset.web_search]\n{body}\n")).unwrap()
    }

    fn ws_array(v: &toml::Value, key: &str) -> Option<Vec<String>> {
        v.get("toolset")?
            .get("web_search")?
            .get(key)?
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|d| d.as_str().map(str::to_owned))
                    .collect()
            })
    }

    #[test]
    fn normalize_sets_the_absent_sibling_to_empty() {
        let mut allow = ws_layer(r#"allowed_domains = ["a.com"]"#);
        normalize_config_layer(&mut allow);
        assert_eq!(
            ws_array(&allow, "allowed_domains"),
            Some(vec!["a.com".into()])
        );
        assert_eq!(ws_array(&allow, "excluded_domains"), Some(vec![]));

        let mut block = ws_layer(r#"excluded_domains = ["b.com"]"#);
        normalize_config_layer(&mut block);
        assert_eq!(
            ws_array(&block, "excluded_domains"),
            Some(vec!["b.com".into()])
        );
        assert_eq!(ws_array(&block, "allowed_domains"), Some(vec![]));
    }

    #[test]
    fn normalize_leaves_both_set_and_both_unset_untouched() {
        let mut both = ws_layer("allowed_domains = [\"a.com\"]\nexcluded_domains = [\"b.com\"]");
        normalize_config_layer(&mut both);
        assert_eq!(
            ws_array(&both, "allowed_domains"),
            Some(vec!["a.com".into()])
        );
        assert_eq!(
            ws_array(&both, "excluded_domains"),
            Some(vec!["b.com".into()])
        );

        let mut none: toml::Value = toml::from_str("[toolset.web_search]\n").unwrap();
        normalize_config_layer(&mut none);
        assert_eq!(ws_array(&none, "allowed_domains"), None);
        assert_eq!(ws_array(&none, "excluded_domains"), None);
    }

    /// After per-layer normalization, a plain `deep_merge_toml` lets a higher layer's blocklist beat a lower layer's allowlist atomically.
    #[test]
    fn normalized_layers_deep_merge_atomically() {
        let mut lower = ws_layer(r#"allowed_domains = ["github.com"]"#);
        let mut higher = ws_layer(r#"excluded_domains = ["evil.com"]"#);
        normalize_config_layer(&mut lower);
        normalize_config_layer(&mut higher);

        // higher wins in a deep merge
        let mut merged = lower;
        deep_merge_toml(&mut merged, &higher);

        assert_eq!(
            ws_array(&merged, "excluded_domains"),
            Some(vec!["evil.com".into()])
        );
        assert_eq!(
            ws_array(&merged, "allowed_domains"),
            Some(vec![]),
            "lower layer's allowlist must be cleared, not merged in"
        );
    }

    /// Campaign and version-override patches overlay after the layer merge, so they need the same normalization.
    /// A campaign that flips an allowlist to a blocklist must replace the policy, not leave both keys set.
    #[test]
    fn overlay_patches_are_normalized_before_merge() {
        let mut merged = ws_layer(r#"allowed_domains = ["github.com"]"#);
        normalize_config_layer(&mut merged);

        let patch: toml::Table =
            toml::from_str("[toolset.web_search]\nexcluded_domains = [\"evil.com\"]\n").unwrap();
        crate::config_override::apply_patches(
            &mut merged,
            std::iter::once(patch),
            crate::config_override::PATCH_STRIP_KEYS,
        );

        assert_eq!(
            ws_array(&merged, "excluded_domains"),
            Some(vec!["evil.com".into()])
        );
        assert_eq!(
            ws_array(&merged, "allowed_domains"),
            Some(vec![]),
            "the campaign's blocklist must replace the underlying allowlist"
        );
    }

    #[test]
    fn user_version_overrides_dont_escape_their_layer() {
        let cli_version = semver::Version::parse("1.8.0").unwrap();
        let mut user: toml::Value = toml::from_str(
            r#"
            [[version_overrides]]
            minimum_version = "1.0.0"
            [version_overrides.telemetry]
            mode = "enabled"
            "#,
        )
        .unwrap();
        apply_version_overrides(&mut user, &cli_version).unwrap();
        assert_eq!(user["telemetry"]["mode"].as_str(), Some("enabled"));

        let requirements: toml::Value = toml::from_str(
            r#"
            [telemetry]
            mode = "disabled"
            "#,
        )
        .unwrap();

        let mut merged = user;
        deep_merge_toml(&mut merged, &requirements);
        assert_eq!(merged["telemetry"]["mode"].as_str(), Some("disabled"));
    }

    #[test]
    fn load_user_config_layer_is_empty_without_user_home() {
        // No resolvable user home: no user layer, and no cwd-relative .fuigo read
        let v = load_user_config_layer(None, "config.toml").unwrap();
        assert_eq!(v.as_table().map(|t| t.is_empty()), Some(true));
    }

    #[test]
    fn load_user_config_layer_treats_empty_file_as_empty_table() {
        let dir = std::env::temp_dir().join(format!("fuigo-load-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.toml"), b"").unwrap();
        let v = load_user_config_layer(Some(&dir), "config.toml").unwrap();
        assert_eq!(v.as_table().map(|t| t.is_empty()), Some(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R013 §1.5 loader half: a user layer caught blank mid-rewrite (an
    /// in-place writer between its truncate and its write) is re-read, and
    /// the written content is what loads, not "no settings".
    #[test]
    fn a_user_layer_caught_blank_mid_write_loads_the_written_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, b"").unwrap();
        let writer = path.clone();
        blank_hook::set(Some(Box::new(move || {
            std::fs::write(&writer, "[telemetry]\nmode = \"kept\"\n").unwrap();
        })));
        let v = load_user_config_layer(Some(dir.path()), "config.toml");
        let fired = blank_hook::fired();
        blank_hook::set(None);
        assert_eq!(v.unwrap()["telemetry"]["mode"].as_str(), Some("kept"));
        assert_eq!(fired, 1);
    }

    /// A blank that stays blank and unchanged is a deliberate reset: honoured
    /// after one re-check.
    #[test]
    fn a_stable_blank_user_layer_is_accepted_after_one_recheck() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), b"  \n").unwrap();
        blank_hook::set(None);
        let v = load_user_config_layer(Some(dir.path()), "config.toml").unwrap();
        let fired = blank_hook::fired();
        assert_eq!(v.as_table().map(toml::map::Map::is_empty), Some(true));
        assert_eq!(fired, 1);
    }

    /// A blank whose identity keeps moving is waited on a bounded number of
    /// times, then refused: it is being rewritten, not deliberately empty.
    #[test]
    fn a_blank_that_keeps_changing_is_refused_after_bounded_rechecks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, b"").unwrap();
        let writer = path.clone();
        let mut n = 0u8;
        blank_hook::set(Some(Box::new(move || {
            // A new blank inode each time: replaced, still empty.
            n += 1;
            let tmp = writer.with_extension(format!("t{n}"));
            std::fs::write(&tmp, b"").unwrap();
            std::fs::rename(&tmp, &writer).unwrap();
        })));
        let err = load_user_config_layer(Some(dir.path()), "config.toml").unwrap_err();
        let fired = blank_hook::fired();
        blank_hook::set(None);
        assert_eq!(err.kind(), std::io::ErrorKind::ResourceBusy, "{err}");
        assert_eq!(fired, BLANK_RECHECKS);
    }

    /// Deleted during the re-check: an absent user layer is empty, as always.
    #[test]
    fn a_blank_user_layer_deleted_during_the_recheck_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, b"").unwrap();
        let gone = path.clone();
        blank_hook::set(Some(Box::new(move || std::fs::remove_file(&gone).unwrap())));
        let v = load_user_config_layer(Some(dir.path()), "config.toml").unwrap();
        blank_hook::set(None);
        assert_eq!(v.as_table().map(toml::map::Map::is_empty), Some(true));
    }

    /// Only the user layer pays for the re-check: other blank TOML loads as
    /// empty at once.
    #[test]
    fn other_blank_toml_is_not_rechecked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("other.toml");
        std::fs::write(&path, b"").unwrap();
        blank_hook::set(None);
        let v = load_toml_file(&path).unwrap();
        assert_eq!(v.as_table().map(toml::map::Map::is_empty), Some(true));
        assert_eq!(blank_hook::fired(), 0);
    }

    /// Non-blank user layers are read once, with no wait.
    #[test]
    fn a_non_blank_user_layer_is_not_rechecked() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), "a = 1\n").unwrap();
        blank_hook::set(None);
        let v = load_user_config_layer(Some(dir.path()), "config.toml").unwrap();
        assert_eq!(v["a"].as_integer(), Some(1));
        assert_eq!(blank_hook::fired(), 0);
    }

    #[test]
    fn load_user_config_layer_reads_file_when_home_present() {
        use std::io::Write;

        let dir = std::env::temp_dir().join(format!("fuigo-load-layer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut f = std::fs::File::create(dir.join("config.toml")).unwrap();
        writeln!(f, "[telemetry]\nmode = \"from_file\"\n").unwrap();

        let v = load_user_config_layer(Some(&dir), "config.toml").unwrap();
        assert_eq!(v["telemetry"]["mode"].as_str(), Some("from_file"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The returned error keeps the parser's kind and location but never the source snippet, which can carry a secret and would reach clients.
    #[test]
    fn parse_error_keeps_kind_but_not_snippet() {
        let dir = std::env::temp_dir().join(format!("fuigo-toml-leak-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.toml");
        // Duplicate key: the message names the key; the secret-bearing source line is only in Display.
        std::fs::write(
            &path,
            "api_key = \"fuigo-secretmustnotleak\"\napi_key = \"fuigo-secretmustnotleak2\"\n",
        )
        .unwrap();

        let msg = load_toml_file(&path).unwrap_err().to_string();
        assert!(
            msg.contains("TOML parse error at line 2"),
            "want location: {msg}"
        );
        assert!(msg.contains("duplicate key"), "want parser kind: {msg}");
        assert!(
            !msg.contains("fuigo-secretmustnotleak"),
            "leaked the secret value: {msg}"
        );
        assert!(
            !msg.contains('|') && !msg.contains('^'),
            "leaked the source snippet/caret: {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
