use super::load::load_config_from_toml;
use super::mcp::{Config, user_config_path};
use anyhow::Result;
use fuigo_agent::prompt::skills::SkillsConfig;
use toml::Value as TomlValue;
use toml::map::Map as TomlMap;
/// Process-LOCAL write lock for `~/.fuigo/config.toml`.
/// Serializes the read-modify-write in [`update_config`] so two rapid settings toggles in THIS process can't interleave and clobber each other.
/// It does nothing across processes — the pager and the shell are separate processes — so every writer also takes
/// `fuigo_config::fs_atomic::lock_config_for_write`'s file lock (through `edit_locked`), which every config writer contends on; see [`update_config`].
static SAVE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// Blank (first-run 0-byte file) is an empty table; other unparseable TOML is an error so a silent fallback cannot drop unmodeled sections.
pub(crate) fn parse_existing_config_toml(s: &str) -> Result<TomlValue, toml::de::Error> {
    if s.trim().is_empty() {
        return Ok(TomlValue::Table(TomlMap::new()));
    }
    toml::from_str(s)
}
/// The user config file `root` with `config`'s modeled sections merged in:
/// what a settings save writes over a file holding `root`. Unmodeled keys and
/// sections are kept (see [`merge_section`]).
fn render_settings(mut root: TomlValue, config: &Config) -> TomlValue {
    if !matches!(root, TomlValue::Table(_)) {
        root = TomlValue::Table(TomlMap::new());
    }
    let table = root.as_table_mut().expect("root must be a table");
    merge_section(table, "cli", &config.cli);
    merge_section(table, "models", &config.models);
    merge_section(table, "ui", &config.ui);
    merge_section(table, "harness", &config.harness);
    merge_section(table, "session", &config.session);
    merge_ask_user_question_section(table, &config.ask_user_question);
    if config.privacy == super::mcp::PrivacyConfig::default() {
        table.remove("privacy");
    } else {
        merge_section(table, "privacy", &config.privacy);
    }
    if config.consent == super::consent::ConsentConfig::default() {
        table.remove("consent");
    } else {
        if let Some(TomlValue::Table(section)) = table.get_mut("consent") {
            section.remove("answers");
        }
        merge_section(table, "consent", &config.consent);
    }
    if config.skills == SkillsConfig::default() {
        table.remove("skills");
    } else {
        merge_section(table, "skills", &config.skills);
    }
    merge_section(table, "telemetry", &config.telemetry);
    merge_section(table, "features", &config.features);
    root
}

/// The raw table and the loaded settings of one version of the user config
/// file, or why a settings save must not rewrite it. `current` is what
/// `fs_atomic::edit_locked` read; the loader's view is
/// `fuigo_config::parse_user_config_layer` of the same bytes (what
/// `load_from_disk` gives for a file holding them).
fn settings_view(
    path: &std::path::Path,
    current: fuigo_config::fs_atomic::Current<'_>,
) -> Result<(TomlValue, Config)> {
    // Only a missing file is an empty config. A hard read error (EACCES,
    // EIO) treated as empty would let the write replace a file this process
    // could not read, erasing every setting in it.
    let text = current_str(current).map_err(|e| {
        anyhow::anyhow!("refusing to overwrite {}: it could not be read ({e})", path.display())
    })?;
    let text = text.unwrap_or_default();
    let root = parse_existing_config_toml(text).map_err(|parse_err| {
        anyhow::anyhow!(
            "refusing to overwrite unparseable {}: {}; save a backup \
                 and fix the syntax error before retrying",
            path.display(),
            parse_err,
        )
    })?;
    // A loader failure is not an empty config. Defaulting here meant a file
    // that parses as TOML but fails semantic validation (bad version
    // overrides, say) was rewritten from defaults, silently discarding every
    // modeled field the user had set.
    let loaded = fuigo_config::parse_user_config_layer(text).map_err(|e| {
        anyhow::anyhow!("refusing to rewrite config.toml: it could not be loaded ({e})")
    })?;
    Ok((root, load_config_from_toml(&loaded)))
}

/// Acquire the process-local [`SAVE_LOCK`] used by [`update_config`].
/// Callers that mutate the file directly (marketplace add/remove) hold it so they can't interleave with a settings save in THIS process.
/// It says nothing about other processes: those callers also take `fuigo_config::fs_atomic::lock_config_for_write` on the file itself.
pub(crate) async fn lock_config_writes() -> tokio::sync::MutexGuard<'static, ()> {
    SAVE_LOCK.lock().await
}
/// Read a file, treating only `NotFound` as empty.
/// Hard read errors (EACCES, EIO) propagate so callers don't clobber an unreadable file on the next write.
pub(crate) fn read_to_string_or_empty(path: &std::path::Path) -> std::io::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e),
    }
}
/// The lock file a read-modify-write of `path` takes: `<path>.lock` beside the
/// user's `config.toml` (the lock every writer of that file has always taken),
/// and for any other file -- a project's `.fuigo/config.toml`, which sits in
/// the user's repository -- a lock under `~/.fuigo/locks/` named by a hash of
/// the file's absolute path, so no lock file is dropped into the repository.
/// Every writer of one file gets the same lock file from this function.
pub(crate) fn rmw_lock_path(path: &std::path::Path) -> std::path::PathBuf {
    if path == user_config_path().as_path() {
        return fuigo_config::fs_atomic::config_lock_path(path);
    }
    // The identity rules (the directory resolved component by component, so
    // a symlinked project directory and the real path agree, and the identity
    // does not change when the first writer creates a missing `.fuigo`) live in
    // `fuigo_config::fs_atomic::lock_path_in` since P72, shared with the other
    // crates' state-file writers; the lock names are unchanged.
    fuigo_config::fs_atomic::lock_path_in(
        &crate::util::fuigo_home::fuigo_home().join("locks"),
        "config",
        path,
    )
}

/// Read-modify-write the config file `path` through the shared helper
/// (`fuigo_config::fs_atomic::edit_locked_with_lock`): under [`SAVE_LOCK`] and
/// the cross-process lock [`rmw_lock_path`] names, with the temp filled and
/// synced outside the file lock, renamed only if the file is still the version
/// `edit` was given, and removed on every failure. The replacement keeps the
/// file's mode exactly (a new file is `0600`) and replaces a symlink at
/// `path`, as these writers always did.
///
/// `edit` decides from the bytes it is given (it may run more than once, so it
/// must have no side effects). Write failures read `failed to write <path>: …`.
pub(crate) async fn edit_config_file<T: Send + 'static>(
    path: &std::path::Path,
    edit: impl FnMut(fuigo_config::fs_atomic::Current<'_>) -> Result<fuigo_config::fs_atomic::Edit<T>>
    + Send
    + 'static,
) -> Result<T> {
    edit_config_file_with(path, fuigo_config::fs_atomic::stage_atomically_keeping_mode, edit).await
}

/// How a writer turns new contents into a staged temp beside `path`.
pub(crate) type StageFn =
    fn(&std::path::Path, &[u8]) -> std::io::Result<fuigo_config::fs_atomic::StagedReplacement>;

/// [`edit_config_file`] with the writer's own staging policy (mode, links).
pub(crate) async fn edit_config_file_with<T: Send + 'static>(
    path: &std::path::Path,
    stage: StageFn,
    edit: impl FnMut(fuigo_config::fs_atomic::Current<'_>) -> Result<fuigo_config::fs_atomic::Edit<T>>
    + Send
    + 'static,
) -> Result<T> {
    let guard = SAVE_LOCK.lock().await;
    let path = path.to_path_buf();
    // `flock` and the fsync block, so they never run on the reactor. The
    // process-local lock moves into the worker with the file lock it takes, so
    // a cancelled caller cannot release it while the commit is still running.
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        edit_config_file_blocking_with(&path, stage, edit)
    })
        .await
        .map_err(|e| anyhow::anyhow!("config write task failed: {e}"))?
}

/// [`edit_config_file`] for a caller already on a blocking thread. Takes the
/// cross-process lock only (not [`SAVE_LOCK`], which an async caller holds).
pub(crate) fn edit_config_file_blocking<T>(
    path: &std::path::Path,
    edit: impl FnMut(fuigo_config::fs_atomic::Current<'_>) -> Result<fuigo_config::fs_atomic::Edit<T>>,
) -> Result<T> {
    edit_config_file_blocking_with(path, fuigo_config::fs_atomic::stage_atomically_keeping_mode, edit)
}

/// [`edit_config_file_blocking`] with the writer's own staging policy.
pub(crate) fn edit_config_file_blocking_with<T>(
    path: &std::path::Path,
    stage: StageFn,
    edit: impl FnMut(fuigo_config::fs_atomic::Current<'_>) -> Result<fuigo_config::fs_atomic::Edit<T>>,
) -> Result<T> {
    use fuigo_config::fs_atomic::EditError;
    edit_config_file_raw(path, stage, edit).map_err(|e| match e {
        EditError::Edit(e) => e,
        EditError::Lock(e) => anyhow::Error::from(e),
        EditError::Write(e) => anyhow::anyhow!("failed to write {}: {e}", path.display()),
    })
}

/// [`edit_config_file_blocking_with`] with the helper's error kept apart (lock,
/// write, or the edit's own), for a caller that words each one itself.
pub(crate) fn edit_config_file_raw<T>(
    path: &std::path::Path,
    stage: StageFn,
    edit: impl FnMut(fuigo_config::fs_atomic::Current<'_>) -> Result<fuigo_config::fs_atomic::Edit<T>>,
) -> Result<T, fuigo_config::fs_atomic::EditError<anyhow::Error>> {
    fuigo_config::fs_atomic::edit_locked_with_lock(
        path,
        &rmw_lock_path(path),
        |bytes| stage(path, bytes),
        edit,
    )
}

/// The text an edit was handed: `None` for a missing file; the read error, or
/// `InvalidData` for bytes that are not UTF-8 (what `read_to_string` gave).
pub(crate) fn current_str(
    current: fuigo_config::fs_atomic::Current<'_>,
) -> std::io::Result<Option<&str>> {
    match current {
        Ok(None) => Ok(None),
        Ok(Some(bytes)) => std::str::from_utf8(bytes).map(Some).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "stream did not contain valid UTF-8",
            )
        }),
        Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
    }
}
/// Merge `[toolset.ask_user_question]` into the root table.
/// `[toolset]` is deliberately NOT merged wholesale, so only this settings-writable sub-table round-trips.
/// It carries runtime-only structs (`web_search` sampler etc.) whose serialized defaults must never land in the user file.
fn merge_ask_user_question_section(
    table: &mut TomlMap<String, TomlValue>,
    ask: &crate::tools::config::AskUserQuestionToolConfig,
) {
    if ask.timeout_enabled.is_none() && ask.timeout_secs.is_none() {
        return;
    }
    let toolset = table
        .entry("toolset".to_string())
        .or_insert_with(|| TomlValue::Table(TomlMap::new()));
    if !matches!(toolset, TomlValue::Table(_)) {
        *toolset = TomlValue::Table(TomlMap::new());
    }
    if let TomlValue::Table(toolset_table) = toolset {
        merge_section(toolset_table, "ask_user_question", ask);
    }
}
/// Merge serialized fields of `value` into `table[key]`, preserving any existing keys not present in the serialized output.
/// This prevents `save_config_locked` round-trips from silently dropping unmodeled fields (e.g. pager-written `show_timestamps`, `auto_dark_theme`).
/// Deep-merge `incoming` into `existing`: nested tables recurse; scalars replace.
fn merge_toml_tables(
    existing: &mut TomlMap<String, TomlValue>,
    incoming: TomlMap<String, TomlValue>,
) {
    for (field_key, field_val) in incoming {
        match (existing.get_mut(&field_key), field_val) {
            (Some(TomlValue::Table(dst)), TomlValue::Table(src)) => {
                merge_toml_tables(dst, src);
            }
            (_, v) => {
                existing.insert(field_key, v);
            }
        }
    }
}
fn merge_section<T: serde::Serialize>(
    table: &mut TomlMap<String, TomlValue>,
    key: &str,
    value: &T,
) {
    match TomlValue::try_from(value) {
        Ok(TomlValue::Table(new_fields)) if !new_fields.is_empty() => {
            let section = table
                .entry(key.to_string())
                .or_insert_with(|| TomlValue::Table(TomlMap::new()));
            if let TomlValue::Table(existing) = section {
                merge_toml_tables(existing, new_fields);
            } else {
                *section = TomlValue::Table(new_fields);
            }
        }
        Ok(TomlValue::Table(_)) => {}
        Ok(_) | Err(_) => {
            table.remove(key);
        }
    }
}
/// Update settings with a read-modify-write, preserving unrelated fields.
///
/// The shared optimistic read-modify-write (P72; `fuigo_config::fs_atomic`'s
/// `Snapshot` and `commit_if_unchanged`, the steps of `edit_locked`): `f` is run on the
/// settings loaded from the file's current version, the result is rendered
/// over that version, the replacement is filled and synced with NO lock held,
/// and it is renamed under `config.toml.lock` only if the file is still that
/// version. Otherwise `f` runs again on the newer version (after two such
/// passes, the whole cycle runs under the lock). So `f` always decides from
/// exactly the version its result replaces -- a read-dependent change (bump a
/// version, append to a list) sees every other writer's change, as under the
/// old fully locked save -- while the `fsync` no longer runs under the lock
/// every other `config.toml` writer contends on.
///
/// `f` may therefore run more than once; it must only change the `Config` it
/// is given (no other side effects), which is why it is `FnMut`. It runs on
/// the caller's task (it may borrow from the caller); every read, the staging
/// and the commit run on the blocking pool.
///
/// [`SAVE_LOCK`] still orders this process's settings saves and marketplace
/// writers. If this future is cancelled while a commit runs, an optimistic
/// commit still renames only over the version `f` decided from; the locked
/// cycle's locks move into the task that commits.
///
/// # Errors
///
/// A file that cannot be read, parsed or loaded is refused, never rewritten
/// from defaults. A lock wait that makes no progress for
/// `fuigo_config::fs_atomic::CONFIG_LOCK_MAX_WAIT` surfaces as a `TimedOut`
/// I/O error rather than a hang.
pub async fn update_config<F>(mut f: F) -> Result<()>
where
    F: FnMut(&mut Config),
{
    use fuigo_config::fs_atomic::{EditError, Snapshot, StagedReplacement};
    let guard = SAVE_LOCK.lock().await;
    let path = user_config_path();
    let lock_path = fuigo_config::fs_atomic::config_lock_path(&path);
    let write_err = |e: EditError<std::convert::Infallible>, path: &std::path::Path| match e {
        EditError::Lock(e) => anyhow::Error::from(e),
        EditError::Write(e) => anyhow::anyhow!("failed to write {}: {e}", path.display()),
        EditError::Edit(never) => match never {},
    };
    // `f` decides on this (async) side, as it borrows from the caller; every
    // read, the staging (`fsync`) and the commit run on the blocking pool.
    // An existing file keeps its mode minus any group/world bits: this file
    // can hold credentials (the Claude import writes environment values into
    // it), and a config created under a permissive umask would otherwise stay
    // world-readable forever because each rewrite restored it. A new file is
    // `0600`.
    for _ in 0..OPTIMISTIC_SETTINGS_PASSES {
        let snapshot = {
            let path = path.clone();
            tokio::task::spawn_blocking(move || {
                fuigo_config::fs_atomic::sweep_stale_temps_once(&path);
                Snapshot::take(&path)
            })
            .await
            .map_err(|e| anyhow::anyhow!("config read task failed: {e}"))?
        };
        let snapshot = match snapshot {
            Ok(Some(snapshot)) => snapshot,
            // A path through a symlink, or Windows: the locked cycle below.
            Ok(None) => break,
            // Written while read: try again.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // Unreadable: the locked cycle meets (and reports) the error.
            Err(_) => break,
        };
        let (root, mut cfg) = settings_view(&path, snapshot.current())?;
        f(&mut cfg);
        let contents = toml::to_string_pretty(&render_settings(root, &cfg))?.into_bytes();
        let committed = {
            let (path, lock_path) = (path.clone(), lock_path.clone());
            tokio::task::spawn_blocking(move || {
                // Staged (and synced) with no lock held; the commit takes the
                // lock and renames only if the file is still `snapshot`, so a
                // commit that outlives a cancelled caller can never overwrite
                // a newer version.
                let staged = fuigo_config::fs_atomic::stage_atomically_from_existing(
                    &path, &contents, 0o600,
                )
                .map_err(EditError::Write)?;
                fuigo_config::fs_atomic::commit_if_unchanged(&path, &lock_path, &snapshot, staged)
            })
            .await
            .map_err(|e| anyhow::anyhow!("config write task failed: {e}"))?
        };
        match committed {
            Ok(true) => return Ok(()),
            // Overtaken by another writer: decide again from its version.
            Ok(false) => {}
            Err(e) => return Err(write_err(e, &path)),
        }
    }
    // Overtaken every time (sustained contention), or no optimistic pass
    // possible: the whole cycle under the lock, so the save always makes
    // progress. The lock moves into the task that commits, and is released
    // only after the rename, also if this future is cancelled meanwhile.
    let (lock, read) = {
        let (path, lock_path) = (path.clone(), lock_path.clone());
        tokio::task::spawn_blocking(move || {
            let lock = fuigo_config::fs_atomic::lock_file_for_write(&lock_path)?;
            Ok::<_, std::io::Error>((lock, std::fs::read(&path)))
        })
        .await
        .map_err(|e| anyhow::anyhow!("config read task failed: {e}"))??
    };
    let current = match &read {
        Ok(bytes) => Ok(Some(bytes.as_slice())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    };
    let (root, mut cfg) = settings_view(&path, current)?;
    f(&mut cfg);
    let contents = toml::to_string_pretty(&render_settings(root, &cfg))?.into_bytes();
    tokio::task::spawn_blocking(move || {
        let _locks = (lock, guard);
        fuigo_config::fs_atomic::stage_atomically_from_existing(&path, &contents, 0o600)
            .and_then(StagedReplacement::commit)
            .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", path.display()))
    })
    .await
    .map_err(|e| anyhow::anyhow!("config write task failed: {e}"))?
}

/// Optimistic passes [`update_config`] makes before its locked cycle (as
/// `fuigo_config::fs_atomic::edit_locked`).
const OPTIMISTIC_SETTINGS_PASSES: usize = 2;
#[cfg(test)]
#[path = "persist_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "p61_cross_process_tests.rs"]
mod p61_cross_process_tests;
#[cfg(test)]
#[path = "p72_tests.rs"]
mod p72_tests;
