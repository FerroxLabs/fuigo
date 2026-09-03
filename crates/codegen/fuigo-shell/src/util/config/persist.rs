use super::load::load_config_from_toml;
use super::mcp::{Config, user_config_path};
use anyhow::Result;
use fuigo_agent::prompt::skills::SkillsConfig;
use toml::Value as TomlValue;
use toml::map::Map as TomlMap;
/// Process-LOCAL write lock for `~/.fuigo/config.toml`.
/// Serializes the read-modify-write in [`update_config`] so two rapid settings toggles in THIS process can't interleave and clobber each other.
/// It does nothing across processes — the pager and the shell are separate processes — so callers also take
/// `fuigo_config::fs_atomic::lock_config_for_write`, the file lock every config writer contends on; see [`update_config`].
static SAVE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// Blank (first-run 0-byte file) is an empty table; other unparseable TOML is an error so a silent fallback cannot drop unmodeled sections.
pub(crate) fn parse_existing_config_toml(s: &str) -> Result<TomlValue, toml::de::Error> {
    if s.trim().is_empty() {
        return Ok(TomlValue::Table(TomlMap::new()));
    }
    toml::from_str(s)
}
/// [`update_config`] body; caller must hold BOTH [`SAVE_LOCK`] and the
/// `config.toml` file lock (`fuigo_config::fs_atomic::lock_config_for_write`).
/// This function does not take either, and its read already happened in the caller.
async fn save_config_locked(config: &Config) -> Result<()> {
    let path = user_config_path();
    let mut root: TomlValue = match tokio::fs::read_to_string(&path).await {
        Ok(s) => match parse_existing_config_toml(&s) {
            Ok(v) => v,
            Err(parse_err) => {
                return Err(anyhow::anyhow!(
                    "refusing to overwrite unparseable {}: {}; save a backup \
                         and fix the syntax error before retrying",
                    path.display(),
                    parse_err,
                ));
            }
        },
        // Only a missing file is an empty config. A hard read error (EACCES,
        // EIO) treated as empty would let the atomic write below replace a file
        // this process could not read, erasing every setting in it.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => TomlValue::Table(TomlMap::new()),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "refusing to overwrite {}: it could not be read ({e})",
                path.display()
            ));
        }
    };
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
    let toml_str = toml::to_string_pretty(&root)?;
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    #[cfg(unix)]
    let prior_mode: Option<u32> = match tokio::fs::metadata(&path).await {
        Ok(m) => {
            use std::os::unix::fs::PermissionsExt;
            Some(m.permissions().mode())
        }
        Err(_) => None,
    };
    #[cfg(not(unix))]
    let prior_mode: Option<u32> = None;
    let suffix = {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("toml.tmp.{}.{}", std::process::id(), nanos)
    };
    let tmp = path.with_extension(suffix);
    tokio::fs::write(&tmp, toml_str).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // An existing file keeps its mode, minus any group/world bits: this file
        // can hold credentials (the Claude import writes environment values into
        // it), and a config that was created under a permissive umask would
        // otherwise stay world-readable forever because each rewrite faithfully
        // restored it. A new file is created 0600 rather than inheriting the
        // umask for the same reason.
        let mode = prior_mode.map_or(0o600, |m| m & 0o700);
        let _ = tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).await;
    }
    let _ = prior_mode;
    tokio::fs::rename(&tmp, &path).await?;
    Ok(())
}
/// Acquire the process-local [`SAVE_LOCK`] used by [`update_config`].
/// Callers that mutate the file directly (marketplace add/remove) hold it so they can't interleave with a settings save in THIS process.
/// It says nothing about other processes: those callers also take `fuigo_config::fs_atomic::lock_config_for_write` on the file itself.
pub(crate) async fn lock_config_writes() -> tokio::sync::MutexGuard<'static, ()> {
    SAVE_LOCK.lock().await
}
/// Both locks a user-config read-modify-write needs: the process-local
/// [`SAVE_LOCK`] and the cross-process file lock every other writer takes.
///
/// `SAVE_LOCK` alone is not enough. It orders this process's own writers and
/// says nothing about the CLI or a second pager editing the same file, which is
/// the case that loses updates. Returned as a pair so both live exactly as long
/// as the caller's read-modify-write.
///
/// Acquired in the same order everywhere: `SAVE_LOCK`, then the file lock.
pub(crate) async fn lock_user_config_writes(
    path: &std::path::Path,
) -> anyhow::Result<(
    tokio::sync::MutexGuard<'static, ()>,
    fuigo_config::fs_atomic::ConfigWriteLock,
)> {
    let guard = SAVE_LOCK.lock().await;
    let path = path.to_path_buf();
    // `flock` blocks, so it never runs on the reactor.
    let file_lock =
        tokio::task::spawn_blocking(move || fuigo_config::fs_atomic::lock_config_for_write(&path))
            .await??;
    Ok((guard, file_lock))
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
/// Atomic write via temp file then `rename` (mirrors [`save_config_locked`]) so a crash mid-write can't truncate `config.toml`.
/// Does NOT take the `config.toml` file lock: callers that use it for a read-modify-write must hold
/// `fuigo_config::fs_atomic::lock_config_for_write` across both halves themselves.
/// Preserves the dest mode on unix.
pub(crate) fn atomic_write_string(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    #[cfg(unix)]
    let prior_mode: Option<u32> = match std::fs::metadata(path) {
        Ok(m) => {
            use std::os::unix::fs::PermissionsExt;
            Some(m.permissions().mode())
        }
        Err(_) => None,
    };
    #[cfg(not(unix))]
    let prior_mode: Option<u32> = None;
    let suffix = {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("toml.tmp.{}.{}", std::process::id(), nanos)
    };
    let tmp = path.with_extension(suffix);
    std::fs::write(&tmp, content)?;
    #[cfg(unix)]
    if let Some(mode) = prior_mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode));
    }
    let _ = prior_mode;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
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
/// Two locks, because they cover different things. [`SAVE_LOCK`] serializes
/// concurrent tasks inside this process. `config.toml.lock` is an advisory file
/// lock, so it also serializes this against writers in OTHER processes — the
/// pager writes the same file — and it is held across the read AND the rename,
/// which is what stops a concurrent writer reading the same original and
/// renaming its own document over this one.
///
/// The file lock only constrains writers that take it; its own docs list which
/// ones do and which known writer still does not.
///
/// # Errors
///
/// Adds one failure mode to the write itself: the config lock being held past
/// `fuigo_config::fs_atomic::CONFIG_LOCK_MAX_WAIT`, which surfaces as a
/// `TimedOut` I/O error rather than a hang.
pub async fn update_config<F>(f: F) -> Result<()>
where
    F: FnOnce(&mut Config),
{
    // Both locks, in the one order the workspace uses. Held for the whole
    // read-modify-write below.
    let _locks = lock_user_config_writes(&user_config_path()).await?;
    // A loader failure is not an empty config. Defaulting here meant a file that
    // parses as TOML but fails semantic validation (bad version overrides, say)
    // was rewritten from defaults, silently discarding every modeled field the
    // user had set. The loader already treats a missing file as empty.
    let root: TomlValue = crate::config::load_from_disk().map_err(|e| {
        anyhow::anyhow!("refusing to rewrite config.toml: it could not be loaded ({e})")
    })?;
    let mut cfg = load_config_from_toml(&root);
    f(&mut cfg);
    save_config_locked(&cfg).await
}
#[cfg(test)]
#[path = "persist_tests.rs"]
mod tests;
