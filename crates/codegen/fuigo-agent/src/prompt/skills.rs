//! Skill and command discovery for system prompt injection.
//!
//! Discovers skills in priority order across local, repo, optional workspace-user, user, bundled, config-path, and plugin sources.
//! Parsing primitives live in `fuigo_tools::implementations::skills::discovery`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::plugins::discovery::PluginScope;
use fuigo_tools::implementations::skills::types::skill_name_from_path;
pub use fuigo_tools::implementations::skills::types::{SkillInfo, SkillScope};
/// Re-export so agent-side discovery (and the shell) can name the resolved vendor-compat config without reaching into `fuigo_tools` directly.
pub use fuigo_tools::types::compat::CompatConfig;

use fuigo_tools::implementations::skills::discovery::{
    COMMAND_SUBDIR, MAX_SKILL_WALK_DEPTH, SKILL_SUBDIRS, find_command_paths, find_skill_md_paths,
    find_skill_paths, is_valid_skill_name, normalize_skill_name, parse_skill_files, scan_md_files,
    walk_for_skill_md,
};

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct SkillsConfig {
    /// Disable implicit workspace/home discovery; explicit and injected paths remain.
    #[serde(default)]
    pub auto_discover: Option<bool>,
    /// Additional skill locations to load.
    /// Each entry is a `SKILL.md` file or a directory walked recursively.
    /// Supports `~` expansion.
    #[serde(default)]
    pub paths: Vec<String>,

    /// Path prefixes to exclude.
    /// Any skill whose resolved path starts with one of these entries is filtered out.
    /// Supports `~` expansion.
    #[serde(default)]
    pub ignore: Vec<String>,

    /// Skill names that are disabled.
    /// Disabled skills remain in the list (unlike `ignore` which hides them entirely).
    /// They are excluded from the system prompt and skill tool invocation.
    #[serde(default)]
    pub disabled: Vec<String>,

    /// Skill dirs the launcher injects after syncing from the server (tagged `Server` scope).
    #[serde(default)]
    pub server_skill_dirs: Vec<String>,

    /// Skill dirs the launcher injects for skills bundled with the platform (tagged `Bundled` scope).
    #[serde(default)]
    pub bundled_skill_dirs: Vec<String>,
}

/// List all discovered skills with their metadata.
///
/// Priority order: Local (cwd/.fuigo/skills, cwd/.agents/skills, cwd/.claude/skills) → Intermediate dirs →
/// Repo (repo_root/.fuigo/skills, repo_root/.agents/skills, repo_root/.claude/skills) → User (~/.fuigo/skills, ~/.agents/skills, ~/.claude/skills)
/// → additional paths from `config.paths`
/// → Server (injected `config.server_skill_dirs`)
/// → Bundled (injected `config.bundled_skill_dirs` + `~/.fuigo/bundled`; lowest precedence).
///
/// `config.ignore` globs are applied across all sources after collection.
/// Skills with the same name from higher-priority sources override lower-priority ones.
///
/// When `working_directory` is `None`, only User-scoped skills are returned.
///
/// `compat` gates which vendor (`.agents`/`.claude`/`.cursor`) dirs are scanned.
/// Pass `CompatConfig::default()` to preserve the historical all-vendors behavior.
/// `project_trusted` is the folder-trust verdict for `working_directory`; when false, the project chain and the workspace-user overlay are omitted.
pub async fn list_skills(
    working_directory: Option<&str>,
    config: &SkillsConfig,
    compat: CompatConfig,
    project_trusted: bool,
) -> Vec<SkillInfo> {
    list_skills_with_plugins(working_directory, config, None, compat, project_trusted).await
}

/// Whether any project skill or command root exists on the supplied roots.
/// Empty discovery roots still require trust. All vendors count regardless of runtime compat settings.
pub fn has_project_skill_dirs_in<'a>(chain_dirs: impl IntoIterator<Item = &'a Path>) -> bool {
    let config_dirs = CompatConfig::default().skill_config_dirs();
    chain_dirs.into_iter().any(|dir| {
        config_dirs.iter().any(|config_dir| {
            let config_dir = dir.join(config_dir);
            SKILL_SUBDIRS
                .iter()
                .copied()
                .chain(std::iter::once(COMMAND_SUBDIR))
                .any(|subdir| config_dir.join(subdir).is_dir())
        })
    })
}

/// List all discovered skills including plugin-provided skills.
///
/// When `plugins` is `Some`, skills from enabled plugins are appended with `plugin_name: Some(...)`.
/// Their `scope` is the plugin's origin (e.g. `Repo` for `.fuigo/plugins/`).
/// Native skills always win bare-name resolution, but qualified plugin entries (`my-plugin:hello`) are preserved even on collision.
/// Untrusted projects skip project roots and the workspace-user overlay; user, config-path, injected, and plugin sources are unaffected.
pub async fn list_skills_with_plugins(
    working_directory: Option<&str>,
    config: &SkillsConfig,
    plugins: Option<&crate::plugins::PluginRegistry>,
    compat: CompatConfig,
    project_trusted: bool,
) -> Vec<SkillInfo> {
    let _skill_discovery_timer = crate::timing::timer("skill_discovery");
    let cwd = working_directory.map(str::to_owned);
    let scan_config = config.clone();
    let scanned = run_scan_blocking(move || {
        scan_filesystem_skills(cwd.as_deref(), &scan_config, compat, project_trusted)
    })
    .await;
    finish_skills(scanned, config, plugins)
}

/// The filesystem half of discovery: the recursive `read_dir` walk, a `canonicalize` per candidate,
/// a frontmatter parse per `SKILL.md`, and a libgit2 repo discovery for `[skills].paths`.
///
/// All of it is blocking work. It is deliberately a plain `fn` so callers must hand it to the
/// blocking pool: run inline on a tokio worker, a slow or network-mounted skills directory pins
/// that worker and no timeout around the call can fire.
fn scan_filesystem_skills(
    working_directory: Option<&str>,
    config: &SkillsConfig,
    compat: CompatConfig,
    project_trusted: bool,
) -> Vec<SkillInfo> {
    #[cfg(test)]
    {
        *SKILL_DISCOVERY_SCANS
            .lock()
            .expect("scan tally")
            .entry(working_directory.map(str::to_owned))
            .or_insert(0) += 1;
        test_hooks::delay_for(working_directory);
    }
    let workspace_user_dir = crate::prompt::workspace_user::optional_workspace_user_dir();
    let (discovery_cwd, discovery_user_dir) = if project_trusted {
        (working_directory, workspace_user_dir.as_deref())
    } else {
        (None, None)
    };

    let mut skills = if config.auto_discover == Some(false) {
        Vec::new()
    } else {
        list_skills_with_options_blocking(
            discovery_cwd,
            discovery_user_dir,
            &fuigo_tools::util::fuigo_home::fuigo_home(),
            compat,
        )
    };

    let git_root = working_directory.and_then(|wd| {
        git2::Repository::discover(wd)
            .ok()
            .and_then(|repo| repo.workdir().map(|p| p.to_path_buf()))
    });
    skills.extend(collect_config_skills(&config.paths, git_root.as_deref()));

    skills.extend(collect_injected_skills(
        &config.server_skill_dirs,
        SkillScope::Server,
    ));
    skills.extend(collect_injected_skills(
        &config.bundled_skill_dirs,
        SkillScope::Bundled,
    ));
    skills
}

/// Run one scan closure on the blocking pool, degrading to an empty list if the task is lost.
async fn run_scan_blocking<F>(scan: F) -> Vec<SkillInfo>
where
    F: FnOnce() -> Vec<SkillInfo> + Send + 'static,
{
    match tokio::task::spawn_blocking(scan).await {
        Ok(skills) => skills,
        Err(e) => {
            tracing::warn!(error = %e, "skill discovery task failed; continuing without discovered skills");
            Vec::new()
        }
    }
}

/// Everything after the filesystem walk: ignore filtering, scope ordering, plugin merge, disable marking.
/// In-memory only, so it is re-run per session even when the scan itself came from the cache.
fn finish_skills(
    scanned: Vec<SkillInfo>,
    config: &SkillsConfig,
    plugins: Option<&crate::plugins::PluginRegistry>,
) -> Vec<SkillInfo> {
    let mut skills = filter_skills(scanned, &config.ignore);
    skills.sort_by_key(|s| s.scope);

    let plugin_skills = if let Some(registry) = plugins {
        collect_plugin_skills(registry)
    } else {
        vec![]
    };

    let mut merged = merge_skills_with_plugins(skills, plugin_skills);

    // Mark disabled skills
    // Disabled skills remain in the list (unlike `ignore` which hides them) but are excluded from the system prompt and skill tool invocation
    if !config.disabled.is_empty() {
        let disabled_set: HashSet<&str> = config.disabled.iter().map(|s| s.as_str()).collect();
        for skill in &mut merged {
            if disabled_set.contains(skill.name.as_str()) {
                skill.enabled = false;
            }
        }
    }

    merged
}

// ── Session-start skill discovery: bounded, off-worker, and cached ──────────────────────
//
// `session/new` rebuilds the agent, and the rebuild discovers skills. That walk is unbounded
// filesystem work paid once per session; embedded hosts open many sessions against one FUIGO_HOME.
// The `/skills` reload path has always wrapped the identical work in a timeout; session start now
// does the same, on the blocking pool, with a process-lifetime cache in front of it.

/// Real filesystem scans performed per working directory. Test-only: cache hits must be
/// observable without timing, and a per-cwd tally stays exact under a parallel test run.
#[cfg(test)]
static SKILL_DISCOVERY_SCANS: std::sync::LazyLock<std::sync::Mutex<HashMap<Option<String>, u64>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Real filesystem scans performed for `cwd` so far; cache hits do not count.
#[cfg(test)]
pub(crate) fn skill_discovery_scan_count(cwd: Option<&str>) -> u64 {
    SKILL_DISCOVERY_SCANS
        .lock()
        .expect("scan tally")
        .get(&cwd.map(str::to_owned))
        .copied()
        .unwrap_or(0)
}

/// Cap on one skills scan. Matches the cap the `/skills` reload path has always used.
pub const DEFAULT_SKILL_DISCOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Env override for [`DEFAULT_SKILL_DISCOVERY_TIMEOUT`], in milliseconds.
pub const SKILL_DISCOVERY_TIMEOUT_ENV: &str = "FUIGO_SKILLS_DISCOVERY_TIMEOUT_MS";

/// The configured scan cap: `FUIGO_SKILLS_DISCOVERY_TIMEOUT_MS` if set and parsable, else the default.
pub fn skill_discovery_timeout() -> std::time::Duration {
    parse_skill_discovery_timeout(std::env::var(SKILL_DISCOVERY_TIMEOUT_ENV).ok().as_deref())
}

/// An unset, empty or unparsable override keeps the default rather than disabling discovery.
fn parse_skill_discovery_timeout(raw: Option<&str>) -> std::time::Duration {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return DEFAULT_SKILL_DISCOVERY_TIMEOUT;
    };
    match raw.parse::<u64>() {
        Ok(ms) => std::time::Duration::from_millis(ms),
        Err(_) => {
            tracing::warn!(
                value = raw,
                "{SKILL_DISCOVERY_TIMEOUT_ENV} is not a number of milliseconds; using the default"
            );
            DEFAULT_SKILL_DISCOVERY_TIMEOUT
        }
    }
}

/// Identity of one discovery result. Anything that changes which files are read belongs here.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct SkillDiscoveryKey {
    cwd: Option<String>,
    fuigo_home: PathBuf,
    /// Serialized `SkillsConfig`: it derives `Serialize` but not `Hash`.
    config: String,
    /// Debug form of the resolved vendor-compat config, for the same reason.
    compat: String,
    project_trusted: bool,
}

impl SkillDiscoveryKey {
    fn new(
        working_directory: Option<&str>,
        config: &SkillsConfig,
        compat: CompatConfig,
        project_trusted: bool,
    ) -> Self {
        Self {
            cwd: working_directory.map(str::to_owned),
            fuigo_home: fuigo_tools::util::fuigo_home::fuigo_home(),
            config: serde_json::to_string(config).unwrap_or_else(|_| format!("{config:?}")),
            compat: format!("{compat:?}"),
            project_trusted,
        }
    }
}

/// Stamp of one path the scan reads: its modification time and, for a file, its length.
///
/// The length is carried because mtime resolution is filesystem-dependent (HFS+ and some network
/// mounts are second-granular), and an in-place `SKILL.md` edit inside the same second must still
/// invalidate.
type PathStamp = Option<(std::time::SystemTime, u64)>;

/// Stamps of everything [`scan_filesystem_skills`] reads: every directory the walk descends into
/// and every `SKILL.md`/command `.md` it parses, under every root.
///
/// This must cover what the walk covers, not a prefix of it. Stamping only each root plus its
/// `skills`/`commands` children missed skills nested below the first level (the walk recurses
/// [`MAX_SKILL_WALK_DEPTH`]), the injected `server_skill_dirs`/`bundled_skill_dirs`, and every
/// in-place edit — so a skill added under `~/.fuigo/skills/<group>/<new>/`, or a bundled tree
/// synced by an embedded host, was never picked up again for the life of the process.
type RootsFingerprint = Vec<(PathBuf, PathStamp)>;

#[derive(Clone)]
struct CachedDiscovery {
    fingerprint: RootsFingerprint,
    skills: Vec<SkillInfo>,
}

static SKILL_DISCOVERY_CACHE: std::sync::LazyLock<
    std::sync::Mutex<HashMap<SkillDiscoveryKey, CachedDiscovery>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Drop every cached scan. The `/skills` reload path calls this so an explicit reload is always
/// authoritative for later `session/new` calls in the same process.
pub fn invalidate_skill_discovery_cache() {
    if let Ok(mut cache) = SKILL_DISCOVERY_CACHE.lock() {
        cache.clear();
    }
}

/// Stamp one path: `None` when it does not exist, so an appearing or vanishing root differs.
fn stamp_of(path: &Path) -> PathStamp {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    Some((modified, if meta.is_file() { meta.len() } else { 0 }))
}

/// Stamp `dir` and, recursively, the subdirectories and markdown files under it, mirroring
/// `walk_for_skill_md`'s depth limit so the fingerprint sees exactly what the walk sees.
fn stamp_tree(dir: &Path, depth: usize, out: &mut RootsFingerprint) {
    out.push((dir.to_path_buf(), stamp_of(dir)));
    if depth > MAX_SKILL_WALK_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut children: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    children.sort();
    for child in children {
        if child.is_dir() {
            stamp_tree(&child, depth + 1, out);
        } else if child.extension().and_then(|e| e.to_str()) == Some("md") {
            out.push((child.clone(), stamp_of(&child)));
        }
    }
}

/// Every directory tree [`scan_filesystem_skills`] walks, in the order it reads them.
///
/// Kept beside the scan deliberately: a source the scan reads but this does not is a skill change
/// the cache can never see.
fn skill_walk_roots(
    working_directory: Option<&str>,
    config: &SkillsConfig,
    compat: CompatConfig,
    project_trusted: bool,
) -> Vec<PathBuf> {
    let workspace_user_dir = crate::prompt::workspace_user::optional_workspace_user_dir();
    let (cwd, user_dir) = if project_trusted {
        (working_directory, workspace_user_dir.as_deref())
    } else {
        (None, None)
    };
    let fuigo_home = fuigo_tools::util::fuigo_home::fuigo_home();
    // `&[]`, not `&config.paths`: the vendor roots contribute only their `skills`/`commands`
    // children (`~/.fuigo` itself holds sessions and logs, which churn and are never scanned),
    // while a `[skills].paths` entry IS the skill dir and gets walked whole, below.
    let config_dirs =
        collect_skill_config_dirs(cwd.map(Path::new), user_dir, &fuigo_home, &[], compat);
    let mut roots = Vec::new();
    for dir in config_dirs {
        for subdir in SKILL_SUBDIRS.iter().copied().chain([COMMAND_SUBDIR]) {
            roots.push(dir.join(subdir));
        }
    }
    // `list_skills_with_options_blocking` also reads `<fuigo_home>/bundled`.
    for subdir in SKILL_SUBDIRS {
        roots.push(fuigo_home.join("bundled").join(subdir));
    }
    roots.extend(config.paths.iter().map(|raw| expand_tilde(raw)));
    roots.extend(config.server_skill_dirs.iter().map(|raw| expand_tilde(raw)));
    roots.extend(
        config
            .bundled_skill_dirs
            .iter()
            .map(|raw| expand_tilde(raw)),
    );
    roots
}

fn roots_fingerprint(
    working_directory: Option<&str>,
    config: &SkillsConfig,
    compat: CompatConfig,
    project_trusted: bool,
) -> RootsFingerprint {
    let roots = skill_walk_roots(working_directory, config, compat, project_trusted);
    let mut fingerprint = Vec::with_capacity(roots.len() * 4);
    for root in roots {
        stamp_tree(&root, 0, &mut fingerprint);
    }
    fingerprint
}

/// Scans running right now, keyed the same way as the cache.
///
/// `spawn_blocking` tasks cannot be aborted, so a scan that overran its cap keeps running on a
/// blocking thread. Without this, every later `session/new` on a slow filesystem spawned another
/// full scan that also outlived its cap — the one case the cache exists for was the one case it
/// could not help, and the live threads accumulated toward tokio's blocking-pool limit.
static SKILL_DISCOVERY_INFLIGHT: std::sync::LazyLock<
    std::sync::Mutex<HashMap<SkillDiscoveryKey, tokio::sync::watch::Receiver<bool>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Clears the in-flight marker when the scan ends, panic included, so one failed scan cannot
/// wedge every later session into waiting for a scan that is not running.
struct InFlightGuard(SkillDiscoveryKey);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if let Ok(mut inflight) = SKILL_DISCOVERY_INFLIGHT.lock() {
            inflight.remove(&self.0);
        }
    }
}

/// Either this call owns the scan, or another call is already running it.
enum ScanRole {
    Owner(tokio::sync::watch::Sender<bool>),
    Waiter(tokio::sync::watch::Receiver<bool>),
}

fn claim_scan(key: &SkillDiscoveryKey) -> ScanRole {
    let Ok(mut inflight) = SKILL_DISCOVERY_INFLIGHT.lock() else {
        // A poisoned registry must not stop discovery; just scan without deduplication.
        return ScanRole::Owner(tokio::sync::watch::channel(false).0);
    };
    match inflight.get(key) {
        Some(rx) => ScanRole::Waiter(rx.clone()),
        None => {
            let (tx, rx) = tokio::sync::watch::channel(false);
            inflight.insert(key.clone(), rx);
            ScanRole::Owner(tx)
        }
    }
}

fn cached_skills(key: &SkillDiscoveryKey) -> Option<CachedDiscovery> {
    SKILL_DISCOVERY_CACHE
        .lock()
        .ok()
        .and_then(|cache| cache.get(key).cloned())
}

/// [`list_skills_with_plugins`] for session start: off the tokio workers, time-capped, and cached
/// for the life of the process, with an explicit cap so callers (and tests) can bound it themselves.
///
/// A scan that overruns its cap does not block the session. It keeps running (a blocking task
/// cannot be cancelled) and caches its result when it lands, so the next session is served from
/// the cache instead of starting a second scan; meanwhile this session builds with whatever was
/// already cached, or with nothing, and `reload_skills_from_disk` plus the skills watcher backfill.
pub async fn list_skills_with_plugins_within(
    limit: std::time::Duration,
    working_directory: Option<&str>,
    config: &SkillsConfig,
    plugins: Option<&crate::plugins::PluginRegistry>,
    compat: CompatConfig,
    project_trusted: bool,
) -> Vec<SkillInfo> {
    let _skill_discovery_timer = crate::timing::timer("skill_discovery");
    let key = SkillDiscoveryKey::new(working_directory, config, compat, project_trusted);
    let cached = cached_skills(&key);

    let scanned = match claim_scan(&key) {
        ScanRole::Waiter(mut rx) => {
            // Another session is already scanning these roots: wait for it instead of starting a
            // second walk of the same slow tree.
            let _ = tokio::time::timeout(limit, rx.changed()).await;
            cached_skills(&key)
                .or(cached)
                .map(|c| c.skills)
                .unwrap_or_default()
        }
        ScanRole::Owner(done) => {
            let cwd = working_directory.map(str::to_owned);
            let scan_config = config.clone();
            let cache_key = key.clone();
            let cached_for_scan = cached.clone();
            // The fingerprint stats the roots, so it is filesystem work too: it rides the same
            // blocking task, and the cache write happens inside it so a scan that outlived its cap
            // still pays off for the next session.
            let job = tokio::task::spawn_blocking(move || {
                let _guard = InFlightGuard(cache_key.clone());
                let fingerprint =
                    roots_fingerprint(cwd.as_deref(), &scan_config, compat, project_trusted);
                let skills = match cached_for_scan {
                    Some(cached) if cached.fingerprint == fingerprint => cached.skills,
                    _ => {
                        let skills = scan_filesystem_skills(
                            cwd.as_deref(),
                            &scan_config,
                            compat,
                            project_trusted,
                        );
                        if let Ok(mut cache) = SKILL_DISCOVERY_CACHE.lock() {
                            cache.insert(
                                cache_key,
                                CachedDiscovery {
                                    fingerprint,
                                    skills: skills.clone(),
                                },
                            );
                        }
                        skills
                    }
                };
                let _ = done.send(true);
                skills
            });

            match tokio::time::timeout(limit, job).await {
                Ok(Ok(skills)) => skills,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "skill discovery task failed; continuing without discovered skills");
                    Vec::new()
                }
                Err(_) => {
                    tracing::warn!(
                        timeout_ms = limit.as_millis() as u64,
                        "skill discovery timed out at session start; continuing without discovered skills"
                    );
                    // A previously discovered list beats nothing: the scan that overran is still
                    // running and will refresh the cache for the next session.
                    cached.map(|c| c.skills).unwrap_or_default()
                }
            }
        }
    };
    finish_skills(scanned, config, plugins)
}

/// Per-directory scan delays, so a test can simulate a slow filesystem without touching globals
/// that a parallel test also reads.
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};
    use std::time::Duration;

    static DELAYS: LazyLock<Mutex<HashMap<String, Duration>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    /// Make every scan rooted at `cwd` take `delay`.
    pub(crate) fn set_delay(cwd: &str, delay: Duration) {
        DELAYS
            .lock()
            .expect("scan delay registry")
            .insert(cwd.to_string(), delay);
    }

    pub(crate) fn delay_for(cwd: Option<&str>) {
        let Some(cwd) = cwd else { return };
        let delay = DELAYS
            .lock()
            .expect("scan delay registry")
            .get(cwd)
            .copied();
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
    }
}

/// Canonical source of all config directories that may contain skills.
///
/// Both skill discovery and the file watcher call this function so they agree on which directories matter.
pub fn collect_skill_config_dirs(
    cwd: Option<&Path>,
    workspace_user_dir: Option<&Path>,
    global_dir: &Path,
    config_paths: &[String],
    compat: CompatConfig,
) -> Vec<PathBuf> {
    let project_sources = cwd.map(|cwd| {
        crate::repo::StartupProjectSources::with_workspace_user(
            cwd,
            workspace_user_dir.map(Path::to_path_buf),
        )
    });
    collect_skill_config_dirs_from_sources(
        project_sources.as_ref(),
        global_dir,
        config_paths,
        compat,
    )
}

/// [`collect_skill_config_dirs`] over an already-resolved project chain, so discovery and the folder-trust detector walk the same roots.
fn collect_skill_config_dirs_from_sources(
    project_sources: Option<&crate::repo::StartupProjectSources>,
    global_dir: &Path,
    config_paths: &[String],
    compat: CompatConfig,
) -> Vec<PathBuf> {
    let fuigo_home = global_dir.to_path_buf();

    let mut dirs = Vec::new();
    let mut seen = HashSet::new();

    // Helper: add if the directory exists and hasn't been seen yet.
    let mut try_add = |dir: PathBuf| {
        if !dir.is_dir() {
            return;
        }
        let canonical = dunce::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
        if seen.insert(canonical) {
            dirs.push(dir);
        }
    };

    // `.agents`/`.claude`/`.cursor` are gated by the resolved compat config; `.fuigo` is always present
    // When all cells are on, this list equals the historical `[".fuigo", ".agents", ".claude", ".cursor"]`
    let config_dir_names = compat.skill_config_dirs();

    // Priority 1, 2 & 2.5: the cwd-to-git-root chain (cwd first), then the optional workspace user dir
    if let Some(project_sources) = project_sources {
        for dir in project_sources.skill_dirs() {
            for name in &config_dir_names {
                try_add(dir.join(name));
            }
        }
    }

    // Priority 3: Global user dirs. `.fuigo` comes from `fuigo_home` (which may be overridden), so it's handled separately.
    // `.agents`/`.claude`/`.cursor` are gated by their skills compat cells
    try_add(fuigo_home);
    if let Some(home) = fuigo_dirs::home_dir() {
        if compat.agents.skills {
            try_add(home.join(".agents"));
        }
        if compat.claude.skills {
            try_add(home.join(".claude"));
        }
        if compat.cursor.skills {
            try_add(home.join(".cursor"));
        }
    }

    // Priority 4: Config paths (skills.paths entries).
    for raw in config_paths {
        let expanded = expand_tilde(raw);
        if expanded.is_dir() {
            try_add(expanded);
        } else if expanded.is_file()
            && let Some(parent) = expanded.parent()
        {
            try_add(parent.to_path_buf());
        }
    }

    dirs
}

/// Determine the skill scope for a config directory based on its location relative to `cwd`, `git_root`, and the user's home directory.
fn scope_for_config_dir(dir: &Path, cwd: Option<&Path>, git_root: Option<&Path>) -> SkillScope {
    // Home-level dirs (e.g. ~/.fuigo/, ~/.agents/, ~/.claude/) are User scope.
    if let Some(home) = fuigo_dirs::home_dir()
        && dir.parent() == Some(home.as_path())
    {
        return SkillScope::User;
    }

    // Dir whose parent is cwd is Local scope.
    if let Some(cwd) = cwd
        && dir.parent() == Some(cwd)
    {
        return SkillScope::Local;
    }

    // Dir under git root is Repo scope.
    if let Some(root) = git_root
        && dir.starts_with(root)
    {
        return SkillScope::Repo;
    }

    SkillScope::User
}

/// Collect paths into `out`, deduplicating by canonical path.
///
/// Skill/command discovery does **not** consult `.gitignore`.
/// Auto-discovery only visits known config roots (`.fuigo`, `.agents`, `.claude`, `.cursor`), which teams often gitignore but still expect to load.
/// Hiding a skill uses `[skills] ignore` in config, not repo ignore rules.
/// AGENTS.md discovery still honors gitignore: that is content, not skill roots.
fn collect_discovered_paths(
    paths: impl IntoIterator<Item = PathBuf>,
    scope: SkillScope,
    seen: &mut HashSet<PathBuf>,
    out: &mut Vec<(PathBuf, SkillScope)>,
) {
    for path in paths {
        let canonical = dunce::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if seen.insert(canonical) {
            out.push((path, scope));
        }
    }
}

/// Discover skills and commands from config dirs, workspace, and bundled paths.
/// Skills are collected before commands so they win name collisions via first-seen-wins dedup.
/// Returns only global skills when `working_directory` is `None`.
#[cfg(test)]
async fn list_skills_with_options(
    working_directory: Option<&str>,
    workspace_user_dir: Option<&Path>,
    global_dir: &Path,
    compat: CompatConfig,
) -> Vec<SkillInfo> {
    list_skills_with_options_blocking(working_directory, workspace_user_dir, global_dir, compat)
}

/// The blocking walk behind [`list_skills_with_options`]; never call it from a tokio worker directly.
fn list_skills_with_options_blocking(
    working_directory: Option<&str>,
    workspace_user_dir: Option<&Path>,
    global_dir: &Path,
    compat: CompatConfig,
) -> Vec<SkillInfo> {
    let cwd = working_directory.map(PathBuf::from);
    let project_sources = cwd.as_ref().map(|cwd| {
        crate::repo::StartupProjectSources::with_workspace_user(
            cwd,
            workspace_user_dir.map(Path::to_path_buf),
        )
    });
    let git_root = project_sources
        .as_ref()
        .and_then(|sources| sources.chain.git_root.as_deref());

    let config_dirs =
        collect_skill_config_dirs_from_sources(project_sources.as_ref(), global_dir, &[], compat);

    let mut skill_files: Vec<(PathBuf, SkillScope)> = Vec::new();
    let mut seen_canonical_paths = HashSet::new();

    for config_dir in &config_dirs {
        let scope = scope_for_config_dir(config_dir, cwd.as_deref(), git_root);

        // Skills before commands: skills win name collisions.
        collect_discovered_paths(
            find_skill_paths(config_dir),
            scope,
            &mut seen_canonical_paths,
            &mut skill_files,
        );
        collect_discovered_paths(
            find_command_paths(config_dir),
            scope,
            &mut seen_canonical_paths,
            &mut skill_files,
        );
    }

    let bundled_dir = global_dir.join("bundled");
    collect_discovered_paths(
        find_skill_paths(&bundled_dir),
        SkillScope::Bundled,
        &mut seen_canonical_paths,
        &mut skill_files,
    );

    parse_skill_files(skill_files)
}

/// Expand a `~`-prefixed path string to an absolute `PathBuf`.
fn expand_tilde(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/")
        && let Some(home) = fuigo_dirs::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(raw)
}

/// Collect and parse skills from `SkillsConfig.paths` entries.
///
/// Each entry is either a direct SKILL.md file or a directory to walk recursively.
/// `~` is expanded.
/// Scope is `Repo` if the resolved path falls inside `git_root`, otherwise `User`.
fn collect_config_skills(config_paths: &[String], git_root: Option<&Path>) -> Vec<SkillInfo> {
    let mut skill_files: Vec<(PathBuf, SkillScope)> = Vec::new();
    let mut seen = HashSet::new();

    for raw in config_paths {
        let expanded = expand_tilde(raw);
        let scope = match git_root {
            Some(root) if expanded.starts_with(root) => SkillScope::Repo,
            _ => SkillScope::User,
        };

        if expanded.is_file() && expanded.file_name().is_some_and(|n| n == "SKILL.md") {
            collect_discovered_paths(
                std::iter::once(expanded),
                scope,
                &mut seen,
                &mut skill_files,
            );
        } else if expanded.is_dir() {
            let dir_paths = find_skill_md_paths(&expanded);
            collect_discovered_paths(dir_paths, scope, &mut seen, &mut skill_files);
        } else {
            tracing::warn!(
                path = %expanded.display(),
                "config path does not exist or is not a SKILL.md file/directory"
            );
        }
    }

    let mut skills = parse_skill_files(skill_files);
    // Provenance metadata only (scope still drives precedence): lets inspect and UIs tell `[skills].paths` entries from plain user/repo skills
    for skill in &mut skills {
        skill.config_source = Some(
            fuigo_tools::types::config_source::ConfigSource::ConfigToml {
                path: PathBuf::from(&skill.path),
            },
        );
    }
    skills
}

fn collect_injected_skills(dirs: &[String], scope: SkillScope) -> Vec<SkillInfo> {
    let mut skill_files: Vec<(PathBuf, SkillScope)> = Vec::new();
    let mut seen = HashSet::new();

    for raw in dirs {
        let expanded = expand_tilde(raw);
        if !expanded.is_dir() {
            continue;
        }
        let mut dir_paths = Vec::new();
        walk_for_skill_md(&expanded, &mut dir_paths, 0);
        collect_discovered_paths(dir_paths, scope, &mut seen, &mut skill_files);
    }

    parse_skill_files(skill_files)
}

/// Deduplicate skills while preserving first-seen priority order.
///
/// Dedupes in two passes at once:
/// - By canonical path (same file discovered via multiple sources; the kept entry inherits a dropped duplicate's `config_source` stamp)
/// - By skill name (a higher-priority source wins)
///
/// [`rekey_to_dir_basename`] re-keys a same-scope name loser to its directory basename when that differs from the contested name and is free.
/// `stamp_plugin_fields` applies the same recovery to plugin siblings.
/// A loser whose basename equals the contested name or is already claimed stays shadowed.
/// A frontmatter owner evicts a claimant that only holds its name via an earlier re-key.
/// Cross-scope shadowing (a higher-priority source claiming a name) is an intentional override and is preserved as-is.
fn dedupe_skills(skills: Vec<SkillInfo>) -> Vec<SkillInfo> {
    let mut seen_paths: HashMap<PathBuf, usize> = HashMap::new();
    // Maps a contested name to its claiming scope and the claimant's index in `deduped`
    let mut seen_names: HashMap<String, (SkillScope, usize)> = HashMap::new();

    let mut deduped: Vec<SkillInfo> = Vec::with_capacity(skills.len());
    for mut skill in skills {
        let canonical_path =
            dunce::canonicalize(&skill.path).unwrap_or_else(|_| PathBuf::from(&skill.path));

        if let Some(&kept_idx) = seen_paths.get(&canonical_path) {
            // A file reached via both auto-discovery and `[skills].paths` is genuinely both
            // Carry the provenance stamp onto the kept entry so the label doesn't depend on source order
            // Scope is untouched
            let kept = &mut deduped[kept_idx];
            if kept.config_source.is_none() && skill.config_source.is_some() {
                kept.config_source = skill.config_source;
            }
            continue;
        }
        if let Some(&(winner_scope, winner_idx)) = seen_names.get(&skill.name) {
            if winner_scope == skill.scope
                && !matches!(skill.scope, SkillScope::Server | SkillScope::Bundled)
            {
                // Same-scope siblings sharing a frontmatter name keep both: re-key the challenger to its dir basename
                // When the challenger IS the basename owner, re-key the earlier claimant instead and hand the name back
                // A challenger whose rekey failed for other reasons (dir taken/invalid) has no claim and falls through to be shadowed below
                if rekey_to_dir_basename(&mut skill, &mut seen_names, deduped.len()) {
                    seen_paths.insert(canonical_path, deduped.len());
                    deduped.push(skill);
                    continue;
                }
                let challenger_owns_basename = skill_name_from_path(&skill.path)
                    .map(normalize_skill_name)
                    .is_some_and(|dir| dir == skill.name);
                if challenger_owns_basename {
                    if rekey_to_dir_basename(&mut deduped[winner_idx], &mut seen_names, winner_idx)
                    {
                        seen_names.insert(skill.name.clone(), (skill.scope, deduped.len()));
                        seen_paths.insert(canonical_path, deduped.len());
                        deduped.push(skill);
                        continue;
                    }
                    if deduped[winner_idx].display_name.is_some() {
                        // The incumbent holds this name only via an earlier re-key and cannot move again, so the frontmatter owner evicts it
                        // A stale copy must not shadow the skill genuinely named after its own directory
                        let evicted = &deduped[winner_idx];
                        let evicted_path = dunce::canonicalize(&evicted.path)
                            .unwrap_or_else(|_| PathBuf::from(&evicted.path));
                        seen_paths.remove(&evicted_path);
                        seen_paths.insert(canonical_path, winner_idx);
                        deduped[winner_idx] = skill;
                        continue;
                    }
                }
            }
            // Server/Bundled are shadowed by design.
            if !matches!(skill.scope, SkillScope::Server | SkillScope::Bundled) {
                tracing::debug!(
                    skill = %skill.name,
                    path = %skill.path,
                    "skill name shadowed by an earlier skill with the same name; rename to avoid the collision"
                );
            }
            continue;
        }
        seen_names.insert(skill.name.clone(), (skill.scope, deduped.len()));

        seen_paths.insert(canonical_path, deduped.len());
        deduped.push(skill);
    }

    deduped
}

/// Re-identify a name-collision party under its directory basename, keeping the frontmatter name as the display label.
/// This covers a copied skill dir (`cp -r japandi japandi2` with `name: japandi` left in both files).
///
/// Returns `false` when the basename is missing/invalid, equals the skill's current name (a true duplicate), or is itself already claimed.
/// A `false` return leaves the collision to the caller's shadowing path.
fn rekey_to_dir_basename(
    skill: &mut SkillInfo,
    seen_names: &mut HashMap<String, (SkillScope, usize)>,
    idx: usize,
) -> bool {
    let Some(dir) = skill_name_from_path(&skill.path) else {
        return false;
    };
    let dir = normalize_skill_name(dir);
    if !is_valid_skill_name(&dir) || dir == skill.name || seen_names.contains_key(&dir) {
        return false;
    }
    tracing::debug!(
        skill = %skill.name,
        rekeyed = %dir,
        path = %skill.path,
        "skill name collides with a same-scope skill; re-identified by directory name"
    );
    seen_names.insert(dir.clone(), (skill.scope, idx));
    skill.display_name = Some(std::mem::replace(&mut skill.name, dir));
    true
}

/// Stamp plugin metadata onto skills parsed by `parse_skill_files`.
fn stamp_plugin_fields(skills: &mut [SkillInfo], plugin: &crate::plugins::LoadedPlugin) {
    let scope = match plugin.scope {
        PluginScope::CliOverride => SkillScope::Local,
        PluginScope::Project => SkillScope::Repo,
        PluginScope::User => SkillScope::User,
        PluginScope::ConfigPath => SkillScope::Plugin,
    };
    for skill in skills.iter_mut() {
        skill.scope = scope;
        skill.plugin_name = Some(plugin.name.clone());
        skill.plugin_version = plugin.version.clone();
        skill.plugin_root = Some(plugin.root_str());
        skill.plugin_data = Some(plugin.data_dir_str());
        // Identity is the directory basename (`plugin:<dir>`), keeping sibling skills collision-free; frontmatter `name` becomes the display label
        // Normalize the basename so the slash name is a valid slug, matching how frontmatter/fallback names are slugged at parse time
        if let Some(dir) = skill_name_from_path(&skill.path) {
            let dir = normalize_skill_name(dir);
            if !dir.is_empty() && dir != skill.name {
                skill.display_name = Some(std::mem::replace(&mut skill.name, dir));
            }
        }
        skill.config_source = Some(fuigo_tools::types::config_source::ConfigSource::Plugin {
            plugin_name: plugin.name.clone(),
            path: PathBuf::from(&skill.path),
        });
    }
}

fn collect_plugin_skills(registry: &crate::plugins::PluginRegistry) -> Vec<SkillInfo> {
    let mut skills = Vec::new();

    for plugin in registry.enabled_plugins() {
        let mut paths: Vec<(PathBuf, SkillScope)> = Vec::new();

        // Skills: shared discovery primitive (see `find_skill_md_paths`).
        for skill_dir in &plugin.skill_dirs {
            if !skill_dir.is_dir() {
                continue;
            }
            paths.extend(
                find_skill_md_paths(skill_dir)
                    .into_iter()
                    .map(|p| (p, SkillScope::Repo)),
            );
        }

        // Commands (.md files in command directories)
        for cmd_dir in &plugin.command_dirs {
            paths.extend(
                scan_md_files(cmd_dir)
                    .into_iter()
                    .map(|p| (p, SkillScope::Repo)),
            );
        }

        let mut parsed = parse_skill_files(paths);
        stamp_plugin_fields(&mut parsed, plugin);
        skills.extend(parsed);
    }

    skills
}

/// Plugin-aware skill merge (native first, then plugin skills appended with qualified-name dedup).
fn merge_skills_with_plugins(
    native_skills: Vec<SkillInfo>,
    plugin_skills: Vec<SkillInfo>,
) -> Vec<SkillInfo> {
    let mut deduped = dedupe_skills(native_skills);
    let native_names: HashSet<String> = deduped.iter().map(|s| s.name.clone()).collect();

    let mut seen_plugin_qualified: HashSet<String> = HashSet::new();
    for skill in plugin_skills {
        if !seen_plugin_qualified.insert(skill.dedup_key()) {
            continue;
        }
        if native_names.contains(&skill.name) {
            tracing::debug!(
                skill_name = %skill.name,
                plugin = ?skill.plugin_name,
                "plugin skill bare name collides with native; qualified form still available"
            );
        }
        deduped.push(skill);
    }

    deduped
}
/// Filter a list of skills, removing any whose canonical path matches or is within the ignore paths
pub fn filter_skills(skills: Vec<SkillInfo>, ignore_paths: &[String]) -> Vec<SkillInfo> {
    if ignore_paths.is_empty() {
        return skills;
    }
    let expanded: Vec<PathBuf> = ignore_paths
        .iter()
        .map(|p| {
            let path = expand_tilde(p);
            dunce::canonicalize(&path).unwrap_or(path)
        })
        .collect();
    skills
        .into_iter()
        .filter(|skill| {
            let canonical =
                dunce::canonicalize(&skill.path).unwrap_or_else(|_| PathBuf::from(&skill.path));
            // >MAX_PATH caveat (see workspace clippy.toml); fail-open here: over-long ignored skills stay included
            !expanded.iter().any(|ignore| canonical.starts_with(ignore))
        })
        .collect()
}

/// Format a skill for prompt injection (if body is populated).
/// Injects plain markdown body — no XML envelope.
pub(crate) fn format_skill_for_injection(skill: &SkillInfo) -> Option<String> {
    skill.body.as_ref().filter(|b| !b.is_empty()).map(|body| {
        fuigo_tools::implementations::skills::skill::build_skill_message(skill, body)
    })
}

/// Format multiple skills for prompt injection.
/// Returns plain markdown skill bodies, no XML wrapper.
pub(crate) fn format_skills_for_injection(skills: &[SkillInfo]) -> String {
    let parts: Vec<String> = skills
        .iter()
        .filter_map(format_skill_for_injection)
        .collect();
    if parts.is_empty() {
        return String::new();
    }
    // Trailing blank line separates the last skill envelope from the agent's own prompt body, so `</skill>` doesn't run into the body
    format!("\n\n{}\n\n", parts.join("\n\n"))
}

/// Resolve agent definition `skills:` names to SkillInfo with body populated.
pub(crate) async fn resolve_preloaded_skills(
    names: &[String],
    discovered: &[SkillInfo],
) -> Vec<SkillInfo> {
    let mut result = Vec::new();

    for name in names {
        let skill = discovered.iter().find(|s| {
            s.name.eq_ignore_ascii_case(name)
                || fuigo_tools::implementations::skills::skill::format_skill_name(s)
                    .eq_ignore_ascii_case(name)
        });

        let Some(skill) = skill else {
            tracing::warn!(
                skill_name = %name,
                "Skill declared in agent definition not found in discovered skills"
            );
            continue;
        };

        match fuigo_tools::implementations::skills::skill::load_skill_with_body(skill).await {
            Ok(loaded) => result.push(loaded),
            Err(e) => {
                tracing::warn!(
                    skill_name = %name,
                    path = %skill.path,
                    error = %e,
                    "Failed to load skill body for preloading"
                );
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use fuigo_tools::implementations::skills::discovery::{
        MAX_BODY_PEEK_BYTES, SkillParseError, extract_first_paragraph, is_valid_skill_name,
        normalize_skill_name, parse_skill_frontmatter,
    };

    fn write_skill_md(dir: &Path, name: &str) {
        fs::create_dir_all(dir).unwrap();
        let content = format!(
            "---\nname: {name}\ndescription: A test skill called {name}\n---\n\nSkill body here.\n"
        );
        fs::write(dir.join("SKILL.md"), content).unwrap();
    }

    #[tokio::test]
    async fn explicit_discovery_excludes_ambient_skills_and_keeps_admitted_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        fs::create_dir_all(&project).unwrap();
        init_git_repo(&project);
        write_skill_md(&project.join(".agents/skills/ambient"), "ambient");
        let explicit = tmp.path().join("explicit");
        write_skill_md(&explicit.join("admitted"), "admitted");
        let injected = tmp.path().join("injected");
        write_skill_md(&injected.join("host-skill"), "host-skill");
        let config = SkillsConfig {
            auto_discover: Some(false),
            paths: vec![explicit.to_string_lossy().into_owned()],
            server_skill_dirs: vec![injected.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let skills = list_skills(
            Some(project.to_str().unwrap()),
            &config,
            CompatConfig::default(),
            /*project_trusted*/ true,
        )
        .await;
        let names: HashSet<_> = skills.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, HashSet::from(["admitted", "host-skill"]));
    }

    // ── Server-synced skills (injected server_skill_dirs) ────────────────

    #[tokio::test]
    async fn server_skills_discovered_and_shadowed_by_local() {
        let server = tempfile::tempdir().unwrap();
        write_skill_md(&server.path().join("server-only"), "server-only");
        write_skill_md(&server.path().join("dup"), "dup");

        let cwd = tempfile::tempdir().unwrap();
        write_skill_md(&cwd.path().join(".fuigo").join("skills").join("dup"), "dup");

        let config = SkillsConfig {
            server_skill_dirs: vec![server.path().to_string_lossy().into_owned()],
            ..Default::default()
        };
        let skills = list_skills_with_plugins(
            Some(&cwd.path().to_string_lossy()),
            &config,
            None,
            CompatConfig::default(),
            /*project_trusted*/ true,
        )
        .await;

        let server_only = skills
            .iter()
            .find(|s| s.name == "server-only")
            .expect("server-only skill should be discovered");
        assert_eq!(server_only.scope, SkillScope::Server);

        let dups: Vec<_> = skills.iter().filter(|s| s.name == "dup").collect();
        assert_eq!(dups.len(), 1, "dup should appear once");
        assert_eq!(
            dups[0].scope,
            SkillScope::Local,
            "local skill must shadow the server-synced one"
        );
    }

    #[tokio::test]
    async fn bundled_skills_injected_and_shadowed_by_local() {
        let bundled = tempfile::tempdir().unwrap();
        write_skill_md(&bundled.path().join("bundled__helper"), "helper");
        write_skill_md(&bundled.path().join("dup"), "dup");

        let cwd = tempfile::tempdir().unwrap();
        write_skill_md(&cwd.path().join(".fuigo").join("skills").join("dup"), "dup");

        let config = SkillsConfig {
            bundled_skill_dirs: vec![bundled.path().to_string_lossy().into_owned()],
            ..Default::default()
        };
        let skills = list_skills_with_plugins(
            Some(&cwd.path().to_string_lossy()),
            &config,
            None,
            CompatConfig::default(),
            /*project_trusted*/ true,
        )
        .await;

        let helper = skills
            .iter()
            .find(|s| s.name == "helper")
            .expect("bundled helper skill should be discovered");
        assert_eq!(helper.scope, SkillScope::Bundled);

        let dups: Vec<_> = skills.iter().filter(|s| s.name == "dup").collect();
        assert_eq!(dups.len(), 1, "dup should appear once");
        assert_eq!(dups[0].scope, SkillScope::Local);
    }

    #[tokio::test]
    async fn server_skill_beats_bundled() {
        let server = tempfile::tempdir().unwrap();
        write_skill_md(&server.path().join("shared"), "shared");
        let bundled = tempfile::tempdir().unwrap();
        write_skill_md(&bundled.path().join("shared"), "shared");

        let cwd = tempfile::tempdir().unwrap();
        let config = SkillsConfig {
            server_skill_dirs: vec![server.path().to_string_lossy().into_owned()],
            bundled_skill_dirs: vec![bundled.path().to_string_lossy().into_owned()],
            ..Default::default()
        };
        let skills = list_skills_with_plugins(
            Some(&cwd.path().to_string_lossy()),
            &config,
            None,
            CompatConfig::default(),
            /*project_trusted*/ true,
        )
        .await;

        let shared: Vec<_> = skills.iter().filter(|s| s.name == "shared").collect();
        assert_eq!(shared.len(), 1, "shared should appear once");
        assert_eq!(
            shared[0].scope,
            SkillScope::Server,
            "server skill must shadow the bundled one"
        );
    }

    // ── Feature 3: Recursive skill reading ──────────────────────────────

    #[test]
    fn find_skill_paths_flat_layout() {
        // Traditional flat layout: skills/<name>/SKILL.md
        let tmp = tempfile::tempdir().unwrap();
        let fuigo_dir = tmp.path().join(".fuigo");

        write_skill_md(&fuigo_dir.join("skills").join("alpha"), "alpha");
        write_skill_md(&fuigo_dir.join("skills").join("beta"), "beta");

        let paths = find_skill_paths(&fuigo_dir);
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().all(|p| p.file_name().unwrap() == "SKILL.md"));
    }

    #[test]
    fn find_skill_paths_nested_layout() {
        // Nested: skills/team/infra/SKILL.md, skills/team/training/SKILL.md
        let tmp = tempfile::tempdir().unwrap();
        let fuigo_dir = tmp.path().join(".fuigo");
        let skills = fuigo_dir.join("skills");

        write_skill_md(&skills.join("team").join("infra"), "infra");
        write_skill_md(&skills.join("team").join("training"), "training");

        let paths = find_skill_paths(&fuigo_dir);
        assert_eq!(paths.len(), 2);

        let path_strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        assert!(path_strs.iter().any(|p| p.contains("infra")));
        assert!(path_strs.iter().any(|p| p.contains("training")));
    }

    #[test]
    fn find_skill_paths_mixed_flat_and_nested() {
        let tmp = tempfile::tempdir().unwrap();
        let fuigo_dir = tmp.path().join(".fuigo");
        let skills = fuigo_dir.join("skills");

        // Flat
        write_skill_md(&skills.join("top-level"), "top-level");
        // Nested 1 level
        write_skill_md(&skills.join("team").join("nested-one"), "nested-one");
        // Nested 2 levels
        write_skill_md(&skills.join("org").join("team").join("deep"), "deep");

        let paths = find_skill_paths(&fuigo_dir);
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn find_skill_paths_dir_without_skill_md_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let fuigo_dir = tmp.path().join(".fuigo");
        let skills = fuigo_dir.join("skills");

        write_skill_md(&skills.join("valid"), "valid");
        fs::create_dir_all(skills.join("empty-dir")).unwrap();
        // Create a dir with a random file but no SKILL.md
        let other = skills.join("other");
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join("README.md"), "not a skill").unwrap();

        let paths = find_skill_paths(&fuigo_dir);
        assert_eq!(paths.len(), 1);
        assert!(paths[0].display().to_string().contains("valid"));
    }

    #[test]
    fn find_skill_paths_no_skills_dir() {
        // .fuigo exists but no skills/ subdirectory
        let tmp = tempfile::tempdir().unwrap();
        let fuigo_dir = tmp.path().join(".fuigo");
        fs::create_dir_all(&fuigo_dir).unwrap();

        let paths = find_skill_paths(&fuigo_dir);
        assert!(paths.is_empty());
    }

    #[test]
    fn find_skill_paths_nonexistent_dir() {
        let paths = find_skill_paths(Path::new("/nonexistent/path"));
        assert!(paths.is_empty());
    }

    #[test]
    fn walk_for_skill_md_respects_depth_limit() {
        // Create a directory tree deeper than MAX_SKILL_WALK_DEPTH
        let tmp = tempfile::tempdir().unwrap();
        let skills_dir = tmp.path().join("skills");

        // Build a chain: skills/d0/d1/d2/d3/d4/d5/d6/deep-skill/SKILL.md
        // d5 sits at the depth limit and d6 is one past it
        let mut current = skills_dir.clone();
        for i in 0..=MAX_SKILL_WALK_DEPTH + 1 {
            current = current.join(format!("d{i}"));
        }
        write_skill_md(&current.join("deep-skill"), "deep-skill");

        // Also put one at an accessible depth
        write_skill_md(&skills_dir.join("shallow"), "shallow");

        let mut paths = Vec::new();
        walk_for_skill_md(&skills_dir, &mut paths, 0);

        assert_eq!(paths.len(), 1);
        assert!(paths[0].display().to_string().contains("shallow"));
    }

    #[test]
    fn find_skill_paths_parent_and_child_both_have_skill_md() {
        let tmp = tempfile::tempdir().unwrap();
        let fuigo_dir = tmp.path().join(".fuigo");
        let skills = fuigo_dir.join("skills");

        // Parent skill
        write_skill_md(&skills.join("parent"), "parent-skill");
        // Child skill inside parent
        write_skill_md(&skills.join("parent").join("child"), "child-skill");

        let paths = find_skill_paths(&fuigo_dir);
        assert_eq!(paths.len(), 2);

        let path_strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        assert!(path_strs.iter().any(|p| p.contains("parent/SKILL.md")));
        assert!(path_strs.iter().any(|p| p.contains("child/SKILL.md")));
    }

    // ── extract_first_paragraph ──────────────────────────────────────

    #[test]
    fn first_paragraph_simple() {
        let body = "This is the first paragraph.\n\nThis is the second.";
        assert_eq!(
            extract_first_paragraph(body).unwrap(),
            "This is the first paragraph."
        );
    }

    #[test]
    fn first_paragraph_skips_headings() {
        let body = "# Git Commit Skill\n\nReview staged changes and create a commit.\n\n## Steps";
        assert_eq!(
            extract_first_paragraph(body).unwrap(),
            "Review staged changes and create a commit."
        );
    }

    #[test]
    fn first_paragraph_multiline() {
        let body =
            "# Skill\n\nFirst line of paragraph.\nSecond line of paragraph.\n\nAnother paragraph.";
        assert_eq!(
            extract_first_paragraph(body).unwrap(),
            "First line of paragraph. Second line of paragraph."
        );
    }

    #[test]
    fn first_paragraph_empty_body() {
        assert!(extract_first_paragraph("").is_none());
    }

    #[test]
    fn first_paragraph_headings_only() {
        let body = "# Title\n\n## Section\n\n### Subsection";
        assert!(extract_first_paragraph(body).is_none());
    }

    // ── UTF-8 safe body truncation ──────────────────────────────────

    #[test]
    fn description_fallback_end_to_end_with_multibyte_skill_file() {
        // End-to-end: a SKILL.md with no description in frontmatter falls back to body parsing
        // The body contains multibyte text that would cross the MAX_BODY_PEEK_BYTES boundary
        let tmp = tempfile::tempdir().unwrap();
        let skill_dir = tmp.path().join("skills").join("emoji-skill");
        fs::create_dir_all(&skill_dir).unwrap();

        // Body (after frontmatter): a heading and a paragraph with multibyte chars exceeding 2048 bytes
        let long_paragraph = "\u{00E9}".repeat(MAX_BODY_PEEK_BYTES); // 2-byte chars
        let content = format!("---\nname: emoji-skill\n---\n# Test\n\n{long_paragraph}\n");
        fs::write(skill_dir.join("SKILL.md"), &content).unwrap();

        let skills = parse_skill_files(vec![(skill_dir.join("SKILL.md"), SkillScope::Local)]);

        // Must not panic
        assert_eq!(skills.len(), 1);
        assert!(
            !skills[0].description.is_empty(),
            "description should be filled from body"
        );
    }

    // ── Frontmatter parsing (existing coverage + regression) ─────────

    #[test]
    fn parse_valid_frontmatter() {
        let content = "---\nname: my-skill\ndescription: A skill\n---\n\nBody.\n";
        let parsed = parse_skill_frontmatter(content, None).unwrap();
        assert_eq!(parsed.name, "my-skill");
        assert_eq!(parsed.description, "A skill");
    }

    #[test]
    fn parse_allowed_tools_comma_string() {
        let content = "---\nname: my-skill\ndescription: test\nallowed-tools: \"bash, read_file, grep\"\n---\n";
        let parsed = parse_skill_frontmatter(content, None).unwrap();
        assert_eq!(
            parsed.allowed_tools.as_deref(),
            Some(
                [
                    "bash".to_string(),
                    "read_file".to_string(),
                    "grep".to_string()
                ]
                .as_slice()
            )
        );
    }

    #[test]
    fn parse_allowed_tools_yaml_list() {
        let content = "---\nname: my-skill\ndescription: test\nallowed-tools:\n  - bash\n  - read_file\n  - grep\n---\n";
        let parsed = parse_skill_frontmatter(content, None).unwrap();
        assert_eq!(
            parsed.allowed_tools.as_deref(),
            Some(
                [
                    "bash".to_string(),
                    "read_file".to_string(),
                    "grep".to_string()
                ]
                .as_slice()
            )
        );
    }

    #[test]
    fn parse_allowed_tools_omitted() {
        let content = "---\nname: my-skill\ndescription: test\n---\n";
        let parsed = parse_skill_frontmatter(content, None).unwrap();
        assert!(parsed.allowed_tools.is_none());
    }

    #[test]
    fn parse_model_and_effort() {
        let content = "---\nname: my-skill\ndescription: test\nmodel: grok-3\neffort: high\n---\n";
        let parsed = parse_skill_frontmatter(content, None).unwrap();
        assert_eq!(parsed.model.as_deref(), Some("grok-3"));
        assert_eq!(parsed.effort.as_deref(), Some("high"));
    }

    #[test]
    fn parse_model_and_effort_omitted() {
        let content = "---\nname: my-skill\ndescription: test\n---\n";
        let parsed = parse_skill_frontmatter(content, None).unwrap();
        assert!(parsed.model.is_none());
        assert!(parsed.effort.is_none());
    }

    // ── agentskills.io spec parity ────────────────────────────────

    #[test]
    fn parse_license_and_compatibility() {
        let content = "---\nname: my-skill\ndescription: test\nlicense: Apache-2.0\ncompatibility: Requires git and docker\n---\n";
        let parsed = parse_skill_frontmatter(content, None).unwrap();
        assert_eq!(parsed.license.as_deref(), Some("Apache-2.0"));
        assert_eq!(
            parsed.compatibility.as_deref(),
            Some("Requires git and docker")
        );
    }

    #[test]
    fn parse_license_and_compatibility_omitted() {
        let content = "---\nname: my-skill\ndescription: test\n---\n";
        let parsed = parse_skill_frontmatter(content, None).unwrap();
        assert!(parsed.license.is_none());
        assert!(parsed.compatibility.is_none());
    }

    #[test]
    fn parse_metadata_arbitrary_keys() {
        let content = "---\nname: my-skill\ndescription: test\nmetadata:\n  author: example-org\n  version: \"1.0\"\n  short-description: Short desc\n---\n";
        let parsed = parse_skill_frontmatter(content, None).unwrap();
        assert_eq!(parsed.short_description.as_deref(), Some("Short desc"));
        assert_eq!(parsed.author.as_deref(), Some("example-org"));
        let meta = parsed.metadata.unwrap();
        assert_eq!(meta.get("version").unwrap(), "1.0");
        // short-description and author are extracted to top-level fields and not in the generic map
        assert!(!meta.contains_key("short-description"));
        assert!(!meta.contains_key("author"));
    }

    #[test]
    fn parse_metadata_omitted() {
        let content = "---\nname: my-skill\ndescription: test\n---\n";
        let parsed = parse_skill_frontmatter(content, None).unwrap();
        assert!(parsed.short_description.is_none());
        assert!(parsed.metadata.is_none());
    }

    #[test]
    fn name_validation_rejects_leading_hyphen() {
        assert!(!is_valid_skill_name("-pdf"));
    }

    #[test]
    fn name_validation_rejects_trailing_hyphen() {
        assert!(!is_valid_skill_name("pdf-"));
    }

    #[test]
    fn name_validation_rejects_consecutive_hyphens() {
        assert!(!is_valid_skill_name("pdf--tool"));
    }

    #[test]
    fn name_validation_accepts_valid_names() {
        assert!(is_valid_skill_name("pdf-processing"));
        assert!(is_valid_skill_name("data-analysis"));
        assert!(is_valid_skill_name("a"));
        assert!(is_valid_skill_name("a-b-c"));
        assert!(is_valid_skill_name("tool123"));
    }

    #[test]
    fn normalize_replaces_spaces_with_hyphens() {
        assert_eq!(normalize_skill_name("my cool skill"), "my-cool-skill");
    }

    #[test]
    fn normalize_lowercases_and_collapses_hyphens() {
        assert_eq!(normalize_skill_name("My  Cool  Skill"), "my-cool-skill");
    }

    #[test]
    fn normalize_trims_leading_trailing() {
        assert_eq!(normalize_skill_name(" -my-skill- "), "my-skill");
    }

    #[test]
    fn parse_frontmatter_normalizes_spaced_name() {
        let content = "---\nname: my cool skill\ndescription: A skill\n---\n";
        let parsed = parse_skill_frontmatter(content, None).unwrap();
        assert_eq!(parsed.name, "my-cool-skill");
    }

    #[test]
    fn parse_skill_files_no_frontmatter_uses_dir_name() {
        let tmp = tempfile::tempdir().unwrap();
        let skill_dir = tmp.path().join("skills").join("my-skill");
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(
            skill_dir.join("SKILL.md"),
            "Just body content, no frontmatter.",
        )
        .unwrap();

        let skills = parse_skill_files(vec![(skill_dir.join("SKILL.md"), SkillScope::Local)]);
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].name, "my-skill");
        assert!(
            skills[0].user_invocable,
            "no-frontmatter skills must be user-invocable"
        );
    }

    #[test]
    fn parse_allowed_tools_space_delimited() {
        // agentskills.io format: space-delimited with tool patterns
        let content = "---\nname: my-skill\ndescription: test\nallowed-tools: \"Bash(git:*) Read Write\"\n---\n";
        let parsed = parse_skill_frontmatter(content, None).unwrap();
        assert_eq!(
            parsed.allowed_tools.as_deref(),
            Some(
                [
                    "Bash(git:*)".to_string(),
                    "Read".to_string(),
                    "Write".to_string()
                ]
                .as_slice()
            )
        );
    }

    #[test]
    fn parse_full_spec_plus_extensions() {
        // Mixed agentskills.io spec fields and our extensions; all must parse
        let content = "---\nname: my-skill\ndescription: A full skill\nlicense: MIT\ncompatibility: Python 3.12+\nmetadata:\n  author: test-org\n  version: \"2.0\"\nallowed-tools:\n  - bash\n  - read_file\nargument-hint: file path\nmodel: grok-3\neffort: high\nuser-invocable: true\ndisable-model-invocation: false\n---\nBody content.\n";
        let parsed = parse_skill_frontmatter(content, None).unwrap();
        assert_eq!(parsed.name, "my-skill");
        assert_eq!(parsed.description, "A full skill");
        assert_eq!(parsed.license.as_deref(), Some("MIT"));
        assert_eq!(parsed.compatibility.as_deref(), Some("Python 3.12+"));
        assert_eq!(parsed.author.as_deref(), Some("test-org"));
        assert_eq!(
            parsed.allowed_tools.as_deref(),
            Some(["bash".to_string(), "read_file".to_string()].as_slice())
        );
        assert_eq!(parsed.argument_hint.as_deref(), Some("file path"));
        assert_eq!(parsed.model.as_deref(), Some("grok-3"));
        assert_eq!(parsed.effort.as_deref(), Some("high"));
        assert!(parsed.user_invocable);
        assert!(!parsed.disable_model_invocation);
    }

    #[test]
    fn parse_frontmatter_recovers_colon_in_value() {
        let content = "---\nname: my-skill\ndescription: lorem ipsum: dolor sit amet\n---\n";
        let parsed = parse_skill_frontmatter(content, None).unwrap();
        assert_eq!(parsed.name, "my-skill");
        assert_eq!(parsed.description, "lorem ipsum: dolor sit amet");
    }

    #[test]
    fn parse_frontmatter_special_chars_normalized() {
        // Non-slug chars (e.g. `@`, `!`, `.`) normalize to hyphens so the skill is kept and slash-usable, rather than dropped.
        let parsed =
            parse_skill_frontmatter("---\nname: inv@lid!name\ndescription: A\n---\n", None)
                .unwrap();
        assert_eq!(parsed.name, "inv-lid-name");
    }

    #[test]
    fn parse_frontmatter_all_symbol_name_rejected() {
        // A name that normalizes to empty has nothing usable, so it is still rejected
        assert!(matches!(
            parse_skill_frontmatter("---\nname: \"@!#\"\ndescription: A\n---\n", None),
            Err(SkillParseError::InvalidName(_))
        ));
    }

    // ── Feature 1: Workspace user skills via list_skills ─────────────

    /// Helper: initialize a bare git repo at `path` so git2::Repository::discover works.
    fn init_git_repo(path: &Path) {
        git2::Repository::init(path).unwrap();
    }

    #[tokio::test]
    async fn list_skills_includes_workspace_user_skills() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        init_git_repo(&repo_root);

        // Create workspace user dir with a skill
        let user_dir = repo_root.join("x").join("testuser");
        write_skill_md(
            &user_dir.join(".fuigo").join("skills").join("my-tool"),
            "my-tool",
        );

        // cwd is the repo root (not inside the user dir, so the walk won't find it)
        let skills = list_skills_with_options(
            Some(repo_root.to_str().unwrap()),
            Some(&user_dir),
            tmp.path(),
            CompatConfig::default(),
        )
        .await;

        let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"my-tool"),
            "Expected 'my-tool' in skills, got: {names:?}"
        );
    }

    #[tokio::test]
    async fn list_skills_workspace_user_dedup_when_cwd_inside_user_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        init_git_repo(&repo_root);

        // User dir with a skill
        let user_dir = repo_root.join("x").join("testuser");
        write_skill_md(
            &user_dir.join(".fuigo").join("skills").join("dedup-skill"),
            "dedup-skill",
        );

        // cwd is inside the user dir; the upward walk will already find it
        let skills = list_skills_with_options(
            Some(user_dir.to_str().unwrap()),
            Some(&user_dir),
            tmp.path(),
            CompatConfig::default(),
        )
        .await;

        let count = skills.iter().filter(|s| s.name == "dedup-skill").count();
        assert_eq!(count, 1, "Skill should appear exactly once, got {count}");
    }

    #[tokio::test]
    async fn list_skills_no_workspace_user_dir_no_extra_skills() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        init_git_repo(&repo_root);

        // Create a skill that would only be found via workspace user path
        let user_dir = repo_root.join("x").join("ghost");
        write_skill_md(
            &user_dir.join(".fuigo").join("skills").join("ghost-skill"),
            "ghost-skill",
        );

        // Pass None; simulates env vars not set
        let skills = list_skills_with_options(
            Some(repo_root.to_str().unwrap()),
            None,
            tmp.path(),
            CompatConfig::default(),
        )
        .await;

        let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
        assert!(
            !names.contains(&"ghost-skill"),
            "Without workspace user dir, ghost-skill should not be found"
        );
    }

    #[tokio::test]
    async fn list_skills_workspace_user_dir_with_recursive_skills() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        init_git_repo(&repo_root);

        // User dir with nested skills
        let user_dir = repo_root.join("x").join("nested-user");
        let skills_base = user_dir.join(".fuigo").join("skills");
        write_skill_md(&skills_base.join("flat-skill"), "flat-skill");
        write_skill_md(&skills_base.join("team").join("deep-skill"), "deep-skill");

        let skills = list_skills_with_options(
            Some(repo_root.to_str().unwrap()),
            Some(&user_dir),
            tmp.path(),
            CompatConfig::default(),
        )
        .await;

        let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"flat-skill"),
            "flat-skill not found: {names:?}"
        );
        assert!(
            names.contains(&"deep-skill"),
            "deep-skill not found: {names:?}"
        );
    }

    // ── collect_config_skills ────────────────────────────────────────

    #[test]
    fn collect_config_skills_from_directory() {
        let tmp = tempfile::tempdir().unwrap();
        write_skill_md(&tmp.path().join("alpha"), "alpha");
        write_skill_md(&tmp.path().join("beta"), "beta");

        let paths = vec![tmp.path().to_str().unwrap().to_string()];
        let skills = collect_config_skills(&paths, None);

        let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"alpha"), "alpha not found: {names:?}");
        assert!(names.contains(&"beta"), "beta not found: {names:?}");
    }

    #[test]
    fn collect_config_skills_direct_skill_md_file() {
        let tmp = tempfile::tempdir().unwrap();
        let skill_dir = tmp.path().join("my-skill");
        write_skill_md(&skill_dir, "my-skill");

        let paths = vec![skill_dir.join("SKILL.md").to_str().unwrap().to_string()];
        let skills = collect_config_skills(&paths, None);

        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].name, "my-skill");
    }

    #[test]
    fn collect_config_skills_scope_user_outside_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&repo).unwrap();
        write_skill_md(&outside.join("ext-skill"), "ext-skill");

        let paths = vec![outside.to_str().unwrap().to_string()];
        let skills = collect_config_skills(&paths, Some(&repo));

        assert_eq!(skills[0].scope, SkillScope::User);
    }

    #[test]
    fn collect_config_skills_scope_repo_inside_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let inside = repo.join("tools");
        write_skill_md(&inside.join("repo-skill"), "repo-skill");

        let paths = vec![inside.to_str().unwrap().to_string()];
        let skills = collect_config_skills(&paths, Some(&repo));

        assert_eq!(skills[0].scope, SkillScope::Repo);
    }

    #[test]
    fn collect_config_skills_skill_md_at_root_of_config_path() {
        // When the config path itself is a skill directory (contains SKILL.md), it is discovered even though walk_for_skill_md only walks children
        let tmp = tempfile::tempdir().unwrap();
        write_skill_md(tmp.path(), "root-skill");

        let paths = vec![tmp.path().to_str().unwrap().to_string()];
        let skills = collect_config_skills(&paths, None);

        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].name, "root-skill");
    }

    #[test]
    fn collect_config_skills_nonexistent_path_is_skipped() {
        let paths = vec!["/nonexistent/path/to/skills".to_string()];
        let skills = collect_config_skills(&paths, None);
        assert!(skills.is_empty());
    }

    #[test]
    fn collect_config_skills_deduplicates_same_file() {
        let tmp = tempfile::tempdir().unwrap();
        write_skill_md(&tmp.path().join("dup-skill"), "dup-skill");

        // Same directory listed twice
        let dir = tmp.path().to_str().unwrap().to_string();
        let paths = vec![dir.clone(), dir];
        let skills = collect_config_skills(&paths, None);

        assert_eq!(skills.len(), 1, "Same file should not appear twice");
    }

    #[test]
    fn collect_config_skills_stamps_config_toml_source() {
        let tmp = tempfile::tempdir().unwrap();
        write_skill_md(&tmp.path().join("cfg-skill"), "cfg-skill");

        let paths = vec![tmp.path().to_str().unwrap().to_string()];
        let skills = collect_config_skills(&paths, None);

        assert_eq!(skills.len(), 1);
        match &skills[0].config_source {
            Some(fuigo_tools::types::config_source::ConfigSource::ConfigToml { path }) => {
                assert_eq!(path, Path::new(&skills[0].path));
            }
            other => panic!("expected ConfigToml source, got {other:?}"),
        }
    }

    // ── filter_skills ────────────────────────────────────────────────

    fn make_skill(name: &str, path: &str) -> SkillInfo {
        SkillInfo {
            name: name.to_string(),
            display_name: None,
            description: format!("desc for {name}"),
            when_to_use: None,
            short_description: None,
            author: None,
            argument_hint: None,
            path: path.to_string(),
            scope: SkillScope::User,
            config_source: None,
            plugin_name: None,
            plugin_version: None,
            plugin_root: None,
            plugin_data: None,
            allowed_tools: None,
            license: None,
            compatibility: None,
            metadata: None,
            model: None,
            effort: None,
            user_invocable: true,
            disable_model_invocation: false,
            has_user_specified_description: false,
            paths: None,
            enabled: true,
            body: None,
        }
    }

    #[test]
    fn stamp_plugin_fields_sets_root_and_data() {
        use crate::plugins::discovery::PluginId;
        use crate::plugins::registry::LoadedPlugin;

        let root = PathBuf::from("/tmp/plugin-dev");
        let plugin = LoadedPlugin {
            name: "plugin-dev".to_string(),
            id: PluginId::new(PluginScope::User, &root, "plugin-dev"),
            root: root.clone(),
            canonical_root: root.clone(),
            scope: PluginScope::User,
            origin: crate::plugins::PluginOrigin::UserFuigo,
            trusted: true,
            enabled: true,
            version: Some("1.0.0".to_string()),
            description: None,
            skill_dirs: vec![],
            command_dirs: vec![],
            agent_dirs: vec![],
            hooks_path: None,
            mcp_config_path: None,
            lsp_config_path: None,
            skill_count: 0,
            agent_count: 0,
            skill_names: vec![],
            agent_names: vec![],
            has_hooks: false,
            hook_count: 0,
            has_inline_hooks_only: false,
            mcp_server_count: 0,
            has_inline_mcp_only: false,
            lsp_server_count: 0,
            has_inline_lsp_only: false,
            inline_hooks: None,
            inline_mcp_servers: None,
            inline_lsp_servers: None,
            conflict: None,
        };

        let mut skills = vec![make_skill(
            "indexer",
            "/tmp/plugin-dev/skills/indexer/SKILL.md",
        )];
        stamp_plugin_fields(&mut skills, &plugin);

        let expected_root = plugin.root_str();
        let expected_data = plugin.data_dir_str();
        assert_eq!(
            skills[0].plugin_root.as_deref(),
            Some(expected_root.as_str())
        );
        assert_eq!(
            skills[0].plugin_data.as_deref(),
            Some(expected_data.as_str())
        );
        assert_eq!(skills[0].plugin_name.as_deref(), Some("plugin-dev"));
    }

    // ── Manifest `skills` entries pointing directly at skill dirs ──

    fn make_registry_with_skill_dirs(
        name: &str,
        root: &Path,
        skill_dirs: Vec<PathBuf>,
    ) -> crate::plugins::PluginRegistry {
        use crate::plugins::discovery::{DiscoveredPlugin, PluginId};
        use crate::plugins::manifest::PluginManifest;

        let dp = DiscoveredPlugin {
            manifest: PluginManifest {
                name: name.to_string(),
                version: Some("0.1.0".to_string()),
                description: None,
                author: None,
                homepage: None,
                repository: None,
                license: None,
                keywords: vec![],
                skills: None,
                commands: None,
                agents: None,
                hooks: None,
                mcp_servers: None,
                lsp_servers: None,
            },
            id: PluginId::new(PluginScope::User, root, name),
            root: root.to_path_buf(),
            canonical_root: root.to_path_buf(),
            scope: PluginScope::User,
            origin: crate::plugins::PluginOrigin::UserFuigo,
            trusted: true,
            skill_dirs,
            command_dirs: vec![],
            agent_dirs: vec![],
            hooks_path: None,
            mcp_config_path: None,
            lsp_config_path: None,
            conflict: None,
        };
        crate::plugins::PluginRegistry::from_discovered(vec![dp], &[], &[name.to_string()])
    }

    #[test]
    fn collect_plugin_skills_finds_root_level_skill_md() {
        // Manifest style: "skills": ["skills/one", "skills/two"]; each entry IS a skill directory with SKILL.md at its root
        let tmp = tempfile::tempdir().unwrap();
        let one = tmp.path().join("skills").join("one");
        let two = tmp.path().join("skills").join("two");
        write_skill_md(&one, "one");
        write_skill_md(&two, "two");

        let registry =
            make_registry_with_skill_dirs("listed", tmp.path(), vec![one.clone(), two.clone()]);
        let skills = collect_plugin_skills(&registry);

        assert_eq!(skills.len(), 2, "root-level SKILL.md dirs must load");
        let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"one") && names.contains(&"two"),
            "{names:?}"
        );
        assert!(
            skills
                .iter()
                .all(|s| s.plugin_name.as_deref() == Some("listed"))
        );
    }

    #[test]
    fn collect_plugin_skills_parent_dir_unchanged_and_no_double_count() {
        // Convention style (parent dir) still works, and listing both the parent and a child dir does not yield duplicates after merge
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("skills");
        let child = parent.join("one");
        write_skill_md(&child, "one");

        let registry =
            make_registry_with_skill_dirs("mixed", tmp.path(), vec![parent.clone(), child.clone()]);
        let merged = merge_skills_with_plugins(vec![], collect_plugin_skills(&registry));

        let ones: Vec<_> = merged.iter().filter(|s| s.name == "one").collect();
        assert_eq!(ones.len(), 1, "skill must appear exactly once: {merged:?}");
    }

    #[tokio::test]
    async fn untrusted_project_skills_are_omitted() {
        for config_dir in [".fuigo", ".agents", ".claude", ".cursor"] {
            let tmp = tempfile::tempdir().unwrap();
            let repo = tmp.path().join("repo");
            let config_root = repo.join(config_dir);
            write_skill_md(
                &config_root.join("skills").join("trust-gate-proj"),
                "trust-gate-proj",
            );
            let commands = config_root.join("commands");
            std::fs::create_dir_all(&commands).unwrap();
            std::fs::write(commands.join("trust-gate-command.md"), "# deploy\n").unwrap();
            init_git_repo(&repo);
            std::fs::write(repo.join(".gitignore"), format!("{config_dir}/\n")).unwrap();
            let subdir = repo.join("crates").join("inner");
            std::fs::create_dir_all(&subdir).unwrap();
            let chain = crate::repo::RepoDirChain::resolve(&subdir);
            assert!(has_project_skill_dirs_in(
                chain.dirs.iter().map(PathBuf::as_path)
            ));

            let trusted = list_skills(
                Some(subdir.to_str().unwrap()),
                &SkillsConfig::default(),
                CompatConfig::default(),
                /*project_trusted*/ true,
            )
            .await;
            let untrusted = list_skills(
                Some(subdir.to_str().unwrap()),
                &SkillsConfig::default(),
                CompatConfig::default(),
                /*project_trusted*/ false,
            )
            .await;
            for name in ["trust-gate-proj", "trust-gate-command"] {
                assert!(
                    trusted.iter().any(|skill| skill.name == name),
                    "trusted folder must load {config_dir} skill {name}"
                );
                assert!(
                    !untrusted.iter().any(|skill| skill.name == name),
                    "untrusted folder must omit {config_dir} skill {name}"
                );
            }
        }
    }

    #[test]
    fn filter_skills_empty_ignore_returns_all() {
        let skills = vec![
            make_skill("a", "/some/path/a/SKILL.md"),
            make_skill("b", "/some/path/b/SKILL.md"),
        ];
        let result = filter_skills(skills.clone(), &[]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn filter_skills_removes_exact_path_match() {
        let tmp = tempfile::tempdir().unwrap();
        let skill_dir = tmp.path().join("bad-skill");
        write_skill_md(&skill_dir, "bad-skill");
        let skill_path = skill_dir.join("SKILL.md");

        let skills = vec![
            make_skill("good-skill", "/other/SKILL.md"),
            make_skill("bad-skill", skill_path.to_str().unwrap()),
        ];
        let ignore = vec![skill_path.to_str().unwrap().to_string()];
        let result = filter_skills(skills, &ignore);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "good-skill");
    }

    #[test]
    fn filter_skills_removes_directory_prefix_match() {
        let tmp = tempfile::tempdir().unwrap();
        let ignored_dir = tmp.path().join("ignored");
        write_skill_md(&ignored_dir.join("skill-a"), "skill-a");
        write_skill_md(&ignored_dir.join("skill-b"), "skill-b");

        let skills = vec![
            make_skill(
                "skill-a",
                ignored_dir
                    .join("skill-a")
                    .join("SKILL.md")
                    .to_str()
                    .unwrap(),
            ),
            make_skill(
                "skill-b",
                ignored_dir
                    .join("skill-b")
                    .join("SKILL.md")
                    .to_str()
                    .unwrap(),
            ),
            make_skill("keeper", "/other/keeper/SKILL.md"),
        ];
        let ignore = vec![ignored_dir.to_str().unwrap().to_string()];
        let result = filter_skills(skills, &ignore);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "keeper");
    }

    #[tokio::test]
    async fn list_skills_loads_custom_path_from_config() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        init_git_repo(&repo_root);

        // A skill in a custom directory outside the repo
        let custom_dir = tmp.path().join("custom-skills");
        write_skill_md(&custom_dir.join("custom-skill"), "custom-skill");

        let config = SkillsConfig {
            auto_discover: None,
            paths: vec![custom_dir.to_str().unwrap().to_string()],
            ignore: vec![],
            disabled: vec![],
            server_skill_dirs: vec![],
            bundled_skill_dirs: vec![],
        };

        let skills = list_skills(
            Some(repo_root.to_str().unwrap()),
            &config,
            CompatConfig::default(),
            /*project_trusted*/ true,
        )
        .await;
        let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"custom-skill"),
            "custom-skill not found: {names:?}"
        );
    }

    #[tokio::test]
    async fn list_skills_ignore_filters_custom_path_skill() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        init_git_repo(&repo_root);

        let custom_dir = tmp.path().join("custom-skills");
        write_skill_md(&custom_dir.join("wanted"), "wanted");
        write_skill_md(&custom_dir.join("unwanted"), "unwanted");
        let unwanted_path = custom_dir.join("unwanted");

        let config = SkillsConfig {
            auto_discover: None,
            paths: vec![custom_dir.to_str().unwrap().to_string()],
            ignore: vec![unwanted_path.to_str().unwrap().to_string()],
            disabled: vec![],
            server_skill_dirs: vec![],
            bundled_skill_dirs: vec![],
        };

        let skills = list_skills(
            Some(repo_root.to_str().unwrap()),
            &config,
            CompatConfig::default(),
            /*project_trusted*/ true,
        )
        .await;
        let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"wanted"), "wanted not found: {names:?}");
        assert!(
            !names.contains(&"unwanted"),
            "unwanted should be filtered: {names:?}"
        );
    }

    #[tokio::test]
    async fn list_skills_deduplicates_auto_and_config_overlap() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        init_git_repo(&repo_root);

        let auto_dir = repo_root.join(".fuigo").join("skills").join("dup-skill");
        write_skill_md(&auto_dir, "dup-skill");

        // Add the same auto-discovered skills root as a config path.
        let config = SkillsConfig {
            auto_discover: None,
            paths: vec![
                repo_root
                    .join(".fuigo")
                    .join("skills")
                    .to_str()
                    .unwrap()
                    .to_string(),
            ],
            ignore: vec![],
            disabled: vec![],
            server_skill_dirs: vec![],
            bundled_skill_dirs: vec![],
        };

        let skills = list_skills(
            Some(repo_root.to_str().unwrap()),
            &config,
            CompatConfig::default(),
            /*project_trusted*/ true,
        )
        .await;
        let count = skills.iter().filter(|s| s.name == "dup-skill").count();

        assert_eq!(count, 1, "dup-skill should only be loaded once");
    }

    /// A skill reachable via auto-discovery AND `[skills].paths` is genuinely both.
    /// The auto-discovered copy wins (scope unchanged) but inherits the ConfigToml stamp, so the label doesn't depend on source order.
    #[tokio::test]
    async fn list_skills_auto_and_config_overlap_keeps_config_toml_source() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        init_git_repo(&repo_root);

        let auto_dir = repo_root.join(".fuigo").join("skills").join("overlap-skill");
        write_skill_md(&auto_dir, "overlap-skill");

        let config = SkillsConfig {
            paths: vec![
                repo_root
                    .join(".fuigo")
                    .join("skills")
                    .to_str()
                    .unwrap()
                    .to_string(),
            ],
            ..Default::default()
        };

        let skills = list_skills(
            Some(repo_root.to_str().unwrap()),
            &config,
            CompatConfig::default(),
            /*project_trusted*/ true,
        )
        .await;

        let overlaps: Vec<&SkillInfo> = skills
            .iter()
            .filter(|s| s.name == "overlap-skill")
            .collect();
        assert_eq!(
            overlaps.len(),
            1,
            "overlap-skill should only be loaded once"
        );
        assert_eq!(
            overlaps[0].scope,
            SkillScope::Local,
            "auto-discovered scope must win"
        );
        assert!(
            matches!(
                overlaps[0].config_source,
                Some(fuigo_tools::types::config_source::ConfigSource::ConfigToml { .. })
            ),
            "ConfigToml stamp should survive path-dedupe: {:?}",
            overlaps[0].config_source
        );
    }

    /// Name-dedupe drops a *different* file that shares a name; its stamp must not leak onto the winner (they are genuinely different skills).
    #[test]
    fn dedupe_skills_name_collision_does_not_propagate_config_source() {
        let winner = make_skill("same-name", "/some/path/a/SKILL.md");
        let mut loser = make_skill("same-name", "/some/path/b/SKILL.md");
        loser.config_source = Some(
            fuigo_tools::types::config_source::ConfigSource::ConfigToml {
                path: PathBuf::from("/some/path/b/SKILL.md"),
            },
        );

        let deduped = dedupe_skills(vec![winner, loser]);

        // Same-scope siblings both survive (the collision loser is re-keyed to its dir basename); provenance must stay with its own file
        assert_eq!(deduped.len(), 2);
        assert!(
            deduped[0].config_source.is_none(),
            "name-dedupe must not propagate provenance across different files"
        );
        assert_eq!(deduped[1].name, "b");
        assert!(
            deduped[1].config_source.is_some(),
            "re-keyed sibling keeps its own provenance"
        );
    }

    #[tokio::test]
    async fn list_skills_ignore_allows_lower_priority_same_name_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().join("repo");
        let cwd = repo_root.join("work").join("nested");
        fs::create_dir_all(&cwd).unwrap();
        init_git_repo(&repo_root);

        // Same skill name in local (higher-priority) and repo (lower-priority) sources.
        write_skill_md(&cwd.join(".fuigo").join("skills").join("same"), "same");
        let repo_skill_dir = repo_root.join(".fuigo").join("skills").join("same");
        write_skill_md(&repo_skill_dir, "same");

        // Ignore the local skill path. Repo fallback should remain visible.
        let config = SkillsConfig {
            auto_discover: None,
            paths: vec![],
            ignore: vec![
                cwd.join(".fuigo")
                    .join("skills")
                    .to_str()
                    .unwrap()
                    .to_string(),
            ],
            disabled: vec![],
            server_skill_dirs: vec![],
            bundled_skill_dirs: vec![],
        };

        let skills = list_skills(
            Some(cwd.to_str().unwrap()),
            &config,
            CompatConfig::default(),
            /*project_trusted*/ true,
        )
        .await;
        let same_skills: Vec<&SkillInfo> = skills.iter().filter(|s| s.name == "same").collect();

        assert_eq!(
            same_skills.len(),
            1,
            "Expected repo fallback skill after local ignore"
        );
        assert!(
            same_skills[0]
                .path
                .starts_with(repo_skill_dir.to_str().unwrap()),
            "Expected fallback from repo path, got: {}",
            same_skills[0].path
        );
    }

    // ── Disabled skills marking ─────────────────────────────────────

    #[tokio::test]
    async fn disabled_config_marks_skill_enabled_false() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        init_git_repo(&repo_root);

        write_skill_md(
            &repo_root.join(".fuigo").join("skills").join("commit"),
            "commit",
        );
        write_skill_md(
            &repo_root.join(".fuigo").join("skills").join("review"),
            "review",
        );

        let config = SkillsConfig {
            auto_discover: None,
            paths: vec![],
            ignore: vec![],
            disabled: vec!["commit".to_string()],
            server_skill_dirs: vec![],
            bundled_skill_dirs: vec![],
        };
        let skills = list_skills(
            Some(repo_root.to_str().unwrap()),
            &config,
            CompatConfig::default(),
            /*project_trusted*/ true,
        )
        .await;

        let commit = skills.iter().find(|s| s.name == "commit");
        let review = skills.iter().find(|s| s.name == "review");

        assert!(
            commit.is_some(),
            "disabled skill should still appear in list"
        );
        assert!(
            !commit.unwrap().enabled,
            "disabled skill should have enabled=false"
        );
        assert!(review.is_some());
        assert!(
            review.unwrap().enabled,
            "non-disabled skill should have enabled=true"
        );
    }

    #[tokio::test]
    async fn disabled_config_empty_leaves_all_enabled() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        init_git_repo(&repo_root);

        write_skill_md(
            &repo_root.join(".fuigo").join("skills").join("deploy"),
            "deploy",
        );

        let config = SkillsConfig {
            auto_discover: None,
            paths: vec![],
            ignore: vec![],
            disabled: vec![],
            server_skill_dirs: vec![],
            bundled_skill_dirs: vec![],
        };
        let skills = list_skills(
            Some(repo_root.to_str().unwrap()),
            &config,
            CompatConfig::default(),
            /*project_trusted*/ true,
        )
        .await;
        assert!(
            skills.iter().all(|s| s.enabled),
            "all skills should be enabled when disabled list is empty"
        );
    }

    // ── Bundled skills discovery ─────────────────────────────────────

    #[tokio::test]
    async fn bundled_skills_are_discovered() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        init_git_repo(&repo_root);

        write_skill_md(
            &home.join("bundled").join("skills").join("commit"),
            "commit",
        );

        let skills = list_skills_with_options(
            Some(repo_root.to_str().unwrap()),
            None,
            &home,
            CompatConfig::default(),
        )
        .await;
        let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"commit"),
            "Expected bundled 'commit' skill, got: {names:?}"
        );
    }

    #[tokio::test]
    async fn user_skills_shadow_bundled_skills() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        init_git_repo(&repo_root);

        // User skill at <home>/skills/commit/SKILL.md
        write_skill_md(&home.join("skills").join("commit"), "commit");

        // Bundled skill at <home>/bundled/skills/commit/SKILL.md (different body)
        let bundled_skill_dir = home.join("bundled").join("skills").join("commit");
        fs::create_dir_all(&bundled_skill_dir).unwrap();
        fs::write(
            bundled_skill_dir.join("SKILL.md"),
            "---\nname: commit\ndescription: bundled version\n---\nBundled body.\n",
        )
        .unwrap();

        let raw = list_skills_with_options(
            Some(repo_root.to_str().unwrap()),
            None,
            &home,
            CompatConfig::default(),
        )
        .await;

        // Both are discovered at the list_skills_with_options level (different canonical paths)
        assert_eq!(
            raw.iter().filter(|s| s.name == "commit").count(),
            2,
            "Expected exactly 2 'commit' skills before dedup (user + bundled)"
        );
        // User skill appears before bundled (first-seen-wins ordering)
        let first_commit = raw.iter().find(|s| s.name == "commit").unwrap();
        assert!(
            !first_commit.path.contains("/bundled/"),
            "User skill should appear before bundled: {}",
            first_commit.path
        );

        // After name-based dedup (as list_skills_with_plugins does), only user version survives
        let deduped = dedupe_skills(raw);
        let commit_skills: Vec<&SkillInfo> =
            deduped.iter().filter(|s| s.name == "commit").collect();
        assert_eq!(
            commit_skills.len(),
            1,
            "Expected exactly one 'commit' after dedup, got {}",
            commit_skills.len()
        );
        assert!(
            !commit_skills[0].path.contains("/bundled/"),
            "User skill should win over bundled: {}",
            commit_skills[0].path
        );
    }

    // ── Command file discovery ────────────────────────────────────────

    /// Regression: project `.claude/commands` often sits under a full `.claude/**` gitignore with only `!.claude/skills/**` re-included.
    /// User-scoped `~/.claude/commands` still loaded; project commands did not, so `/frontend` never appeared for the large multi-package repo.
    #[tokio::test]
    async fn project_claude_commands_load_even_when_gitignored() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).expect("create repo dir");
        init_git_repo(&repo_root);

        // Mirror the ignore a large multi-package repo uses: ignore all of .claude, re-include skills only
        fs::write(
            repo_root.join(".gitignore"),
            "**/.claude\n**/.claude/**\n!.claude/\n!.claude/skills/\n!.claude/skills/**\n",
        )
        .expect("write gitignore");

        let commands = repo_root.join(".claude").join("commands");
        fs::create_dir_all(&commands).expect("create commands dir");
        fs::write(
            commands.join("frontend.md"),
            "---\nname: frontend\ndescription: Acme Design System Frontend Skill\n---\nUse the design system.\n",
        )
        .expect("write frontend.md");

        // Skill under the force-included path must still load too.
        write_skill_md(
            &repo_root.join(".claude").join("skills").join("bp-deltas"),
            "bp-deltas",
        );

        let repo_str = repo_root.to_str().unwrap_or_default();
        let skills =
            list_skills_with_options(Some(repo_str), None, tmp.path(), CompatConfig::default())
                .await;
        let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();

        assert!(
            names.contains(&"frontend"),
            "gitignored project .claude/commands/frontend.md must load as a slash skill, got: {names:?}"
        );
        assert!(
            names.contains(&"bp-deltas"),
            "project .claude/skills still loads, got: {names:?}"
        );

        let frontend = skills
            .iter()
            .find(|s| s.name == "frontend")
            .expect("frontend skill");
        assert!(
            frontend.path.contains("commands"),
            "frontend should come from commands/, path={}",
            frontend.path
        );
    }

    #[test]
    fn command_file_name_derivation_with_and_without_frontmatter() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let commands = tmp.path().join("commands");
        fs::create_dir_all(&commands).expect("create commands dir");

        fs::write(
            commands.join("deploy.md"),
            "---\nname: deploy\ndescription: Ship it\n---\nBody.\n",
        )
        .expect("write deploy.md");
        fs::write(commands.join("rollback.md"), "Just rollback instructions.")
            .expect("write rollback.md");

        let files = vec![
            (commands.join("deploy.md"), SkillScope::Repo),
            (commands.join("rollback.md"), SkillScope::Repo),
        ];
        let skills = parse_skill_files(files);

        assert_eq!(skills.len(), 2);
        let deploy = skills
            .iter()
            .find(|s| s.name == "deploy")
            .expect("deploy skill not found");
        assert_eq!(deploy.description, "Ship it");

        let rollback = skills
            .iter()
            .find(|s| s.name == "rollback")
            .expect("rollback skill not found");
        assert_eq!(rollback.description, "Just rollback instructions.");
    }

    #[tokio::test]
    async fn skills_shadow_commands_with_same_name() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).expect("create repo dir");
        init_git_repo(&repo_root);

        let claude_dir = repo_root.join(".claude");
        write_skill_md(&claude_dir.join("skills").join("deploy"), "deploy");
        let commands = claude_dir.join("commands");
        fs::create_dir_all(&commands).expect("create commands dir");
        fs::write(
            commands.join("deploy.md"),
            "---\nname: deploy\ndescription: command version\n---\n",
        )
        .expect("write deploy.md command");

        let repo_str = repo_root.to_str().unwrap_or_default();
        let raw =
            list_skills_with_options(Some(repo_str), None, tmp.path(), CompatConfig::default())
                .await;

        let deploy_entries: Vec<_> = raw.iter().filter(|s| s.name == "deploy").collect();
        assert_eq!(deploy_entries.len(), 2);
        assert!(
            deploy_entries[0].path.contains("SKILL.md"),
            "skill should appear before command"
        );

        let deduped = dedupe_skills(raw);
        let deploy = deduped
            .iter()
            .filter(|s| s.name == "deploy")
            .collect::<Vec<_>>();
        assert_eq!(deploy.len(), 1);
        assert!(deploy[0].path.contains("SKILL.md"));
    }

    // ── Plugin skill identity ─────────────────────────────

    fn min_plugin(name: &str) -> crate::plugins::LoadedPlugin {
        use crate::plugins::discovery::PluginId;
        let root = PathBuf::from(format!("/tmp/{name}"));
        crate::plugins::LoadedPlugin {
            name: name.to_string(),
            id: PluginId::new(PluginScope::Project, &root, name),
            root: root.clone(),
            canonical_root: root,
            scope: PluginScope::Project,
            origin: crate::plugins::PluginOrigin::ProjectFuigo,
            trusted: true,
            enabled: true,
            version: Some("1.0.0".to_string()),
            description: None,
            skill_dirs: vec![],
            command_dirs: vec![],
            agent_dirs: vec![],
            hooks_path: None,
            mcp_config_path: None,
            lsp_config_path: None,
            skill_count: 0,
            agent_count: 0,
            skill_names: vec![],
            agent_names: vec![],
            has_hooks: false,
            hook_count: 0,
            has_inline_hooks_only: false,
            mcp_server_count: 0,
            has_inline_mcp_only: false,
            lsp_server_count: 0,
            has_inline_lsp_only: false,
            inline_hooks: None,
            inline_mcp_servers: None,
            inline_lsp_servers: None,
            conflict: None,
        }
    }

    #[test]
    fn stamp_plugin_fields_uses_dir_basename_as_identity() {
        // Siblings sharing the frontmatter name `deploy` must not collide.
        let mut skills = vec![
            SkillInfo {
                name: "deploy".to_owned(),
                path: "/p/skills/deploy-prod/SKILL.md".to_owned(),
                ..SkillInfo::default()
            },
            SkillInfo {
                name: "deploy".to_owned(),
                path: "/p/skills/deploy-staging/SKILL.md".to_owned(),
                ..SkillInfo::default()
            },
        ];
        stamp_plugin_fields(&mut skills, &min_plugin("infra"));

        assert_eq!(skills[0].name, "deploy-prod");
        assert_eq!(skills[0].display_name.as_deref(), Some("deploy"));
        assert_eq!(skills[0].dedup_key(), "infra:deploy-prod");
        assert_ne!(skills[0].dedup_key(), skills[1].dedup_key());
    }

    #[test]
    fn stamp_plugin_fields_normalizes_dir_basename() {
        let mut skills = vec![SkillInfo {
            name: "deploy".to_owned(),
            path: "/p/skills/Deploy_Prod/SKILL.md".to_owned(),
            ..SkillInfo::default()
        }];
        stamp_plugin_fields(&mut skills, &min_plugin("infra"));
        assert_eq!(skills[0].name, "deploy-prod");
        assert_eq!(skills[0].display_name.as_deref(), Some("deploy"));
    }

    #[test]
    fn stamp_plugin_fields_keeps_name_when_dir_matches() {
        let mut skills = vec![SkillInfo {
            name: "deploy".to_owned(),
            path: "/p/skills/deploy/SKILL.md".to_owned(),
            ..SkillInfo::default()
        }];
        stamp_plugin_fields(&mut skills, &min_plugin("infra"));

        assert_eq!(skills[0].name, "deploy");
        assert_eq!(skills[0].display_name, None);
        assert_eq!(skills[0].label(), "deploy");
    }

    #[tokio::test]
    async fn empty_bundled_dir_produces_no_bundled_skills() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        init_git_repo(&repo_root);

        // Create <home>/bundled/ but no skills/ subdirectory
        fs::create_dir_all(home.join("bundled")).unwrap();

        let skills = list_skills_with_options(
            Some(repo_root.to_str().unwrap()),
            None,
            &home,
            CompatConfig::default(),
        )
        .await;
        let bundled: Vec<_> = skills
            .iter()
            .filter(|s| s.path.contains("/bundled/"))
            .collect();
        assert!(
            bundled.is_empty(),
            "Expected no bundled skills from empty bundled dir, got: {:?}",
            bundled.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
    }

    // ── collect_skill_config_dirs vendor gating ────────────

    #[test]
    fn collect_skill_config_dirs_gates_vendor_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        // Not a git repo, so it falls to the cwd-only branch (no upward walk)
        for name in [".fuigo", ".agents", ".claude", ".cursor"] {
            fs::create_dir_all(cwd.join(name)).unwrap();
        }

        let ends_with = |dirs: &[PathBuf], suffix: &str| dirs.iter().any(|d| d.ends_with(suffix));

        // With all cells on, both vendor dirs are present (byte-for-byte legacy behavior)
        let all =
            collect_skill_config_dirs(Some(cwd), None, tmp.path(), &[], CompatConfig::default());
        assert!(ends_with(&all, ".claude"), "claude missing: {all:?}");
        assert!(ends_with(&all, ".cursor"), "cursor missing: {all:?}");

        // With cursor.skills off, .cursor is dropped and .claude kept
        let mut compat = CompatConfig::default();
        compat.cursor.skills = false;
        let dirs = collect_skill_config_dirs(Some(cwd), None, tmp.path(), &[], compat);
        assert!(
            !ends_with(&dirs, ".cursor"),
            "cursor must be gated off: {dirs:?}"
        );
        assert!(ends_with(&dirs, ".claude"), "claude must remain: {dirs:?}");
        assert!(ends_with(&dirs, ".fuigo"), "fuigo must remain: {dirs:?}");
    }

    /// RAII guard: set an env var, restore the prior value (or unset) on drop.
    struct EnvVarGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn collect_skill_config_dirs_gates_home_agents_dir() {
        // Pin both HOME and USERPROFILE so Windows home_dir() sees the tempdir too
        let home = tempfile::tempdir().unwrap();
        let _home_guard = EnvVarGuard::set("HOME", home.path());
        let _userprofile_guard = EnvVarGuard::set("USERPROFILE", home.path());
        let home_agents = home.path().join(".agents");
        fs::create_dir_all(home_agents.join("skills")).unwrap();
        let fuigo_home = tempfile::tempdir().unwrap();

        let canon = |p: &Path| dunce::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        let has_home_agents =
            |dirs: &[PathBuf]| dirs.iter().any(|d| canon(d) == canon(&home_agents));

        // Default ON: `~/.agents` is scanned (historical CLI behavior)
        let dirs =
            collect_skill_config_dirs(None, None, fuigo_home.path(), &[], CompatConfig::default());
        assert!(
            has_home_agents(&dirs),
            "~/.agents must be scanned by default: {dirs:?}"
        );

        // `agents.skills = false` (FUIGO_AGENTS_SKILLS_ENABLED=0): `~/.agents` is not scanned
        let mut compat = CompatConfig::default();
        compat.agents.skills = false;
        let dirs = collect_skill_config_dirs(None, None, fuigo_home.path(), &[], compat);
        assert!(
            !has_home_agents(&dirs),
            "~/.agents must be gated off: {dirs:?}"
        );
    }

    // ── Same-scope frontmatter-name collisions (copied skill dirs) ──────

    fn named_skill(name: &str, path: &str, scope: SkillScope) -> SkillInfo {
        SkillInfo {
            name: name.to_owned(),
            path: path.to_owned(),
            scope,
            ..SkillInfo::default()
        }
    }

    #[test]
    fn dedupe_rekeys_same_scope_name_collision_to_dir_basename() {
        // `cp -r japandi japandi2` with `name: japandi` left in both files.
        let out = dedupe_skills(vec![
            named_skill("japandi", "/u/skills/japandi/SKILL.md", SkillScope::User),
            named_skill("japandi", "/u/skills/japandi2/SKILL.md", SkillScope::User),
        ]);
        let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["japandi", "japandi2"], "both siblings must survive");
        assert_eq!(out[0].display_name, None);
        assert_eq!(
            out[1].display_name.as_deref(),
            Some("japandi"),
            "frontmatter name becomes the display label"
        );
    }

    #[test]
    fn dedupe_hands_name_back_to_basename_owner() {
        // The copy sorts before the original (`backup-japandi/`): the original keeps the bare name; the earlier claimant is re-keyed instead
        let out = dedupe_skills(vec![
            named_skill(
                "japandi",
                "/u/skills/backup-japandi/SKILL.md",
                SkillScope::User,
            ),
            named_skill("japandi", "/u/skills/japandi/SKILL.md", SkillScope::User),
        ]);
        let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["backup-japandi", "japandi"]);
        assert_eq!(out[0].display_name.as_deref(), Some("japandi"));
        assert_eq!(out[1].display_name, None);
    }

    #[test]
    fn dedupe_rekeys_every_same_scope_claimant() {
        let out = dedupe_skills(vec![
            named_skill("japandi", "/u/skills/japandi-a/SKILL.md", SkillScope::User),
            named_skill("japandi", "/u/skills/japandi-b/SKILL.md", SkillScope::User),
            named_skill("japandi", "/u/skills/japandi/SKILL.md", SkillScope::User),
        ]);
        let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["japandi-a", "japandi-b", "japandi"]);
    }

    #[test]
    fn dedupe_challenger_without_basename_claim_is_still_shadowed() {
        // The contested basename is already claimed cross-scope: the challenger has no dir identity to fall back to
        // It has no claim to steal the bare name, so first-seen keeps it
        let out = dedupe_skills(vec![
            named_skill("japandi2", "/l/skills/japandi2/SKILL.md", SkillScope::Local),
            named_skill(
                "japandi",
                "/u/skills/original-japandi/SKILL.md",
                SkillScope::User,
            ),
            named_skill("japandi", "/u/skills/japandi2/SKILL.md", SkillScope::User),
        ]);
        let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["japandi2", "japandi"]);
        assert_eq!(
            out[1].path, "/u/skills/original-japandi/SKILL.md",
            "first-seen claimant keeps the bare name"
        );
    }

    #[test]
    fn dedupe_rekeyed_name_shadows_lower_scope_claimant() {
        // The re-keyed user copy owns `japandi2` before the server skill is seen: scope priority applies to re-keyed names too
        let out = dedupe_skills(vec![
            named_skill("japandi", "/u/skills/japandi/SKILL.md", SkillScope::User),
            named_skill("japandi", "/u/skills/japandi2/SKILL.md", SkillScope::User),
            named_skill(
                "japandi2",
                "/srv/skills/japandi2/SKILL.md",
                SkillScope::Server,
            ),
        ]);
        let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["japandi", "japandi2"]);
        assert_eq!(out[1].scope, SkillScope::User);
    }

    #[test]
    fn dedupe_same_scope_cross_harness_loser_resurfaces() {
        // A `.claude` skill claiming a `.fuigo`-owned name (both User scope) re-keys to its dir basename instead of being silently hidden
        let out = dedupe_skills(vec![
            named_skill(
                "review",
                "/u/.fuigo/skills/review/SKILL.md",
                SkillScope::User,
            ),
            named_skill(
                "review",
                "/u/.claude/skills/my-review/SKILL.md",
                SkillScope::User,
            ),
        ]);
        let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["review", "my-review"]);
    }

    #[test]
    fn dedupe_frontmatter_owner_evicts_rekeyed_squatter() {
        // A stale copy re-keyed to `japandi2` must not shadow the skill whose frontmatter genuinely says `japandi2`; the owner evicts it
        let out = dedupe_skills(vec![
            named_skill(
                "japandi",
                "/u/.fuigo/skills/japandi/SKILL.md",
                SkillScope::User,
            ),
            named_skill(
                "japandi",
                "/u/.fuigo/skills/japandi2/SKILL.md",
                SkillScope::User,
            ),
            named_skill(
                "japandi2",
                "/u/.claude/skills/japandi2/SKILL.md",
                SkillScope::User,
            ),
        ]);
        let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["japandi", "japandi2"]);
        let owner = &out[1];
        assert_eq!(owner.path, "/u/.claude/skills/japandi2/SKILL.md");
        assert_eq!(owner.display_name, None, "genuine owner, not a re-key");
    }

    #[test]
    fn dedupe_cross_scope_shadowing_unchanged() {
        // Cross-scope same-name is the documented override mechanism: the lower-priority skill stays hidden even when its dir basename differs
        let out = dedupe_skills(vec![
            named_skill(
                "japandi",
                "/repo/.fuigo/skills/japandi/SKILL.md",
                SkillScope::Repo,
            ),
            named_skill("japandi", "/u/skills/japandi2/SKILL.md", SkillScope::User),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].scope, SkillScope::Repo);
    }

    #[test]
    fn dedupe_same_scope_same_basename_still_drops() {
        // Same name AND same dir basename across two same-scope roots
        // (e.g. ~/.fuigo/skills and ~/.agents/skills): first-seen wins.
        let out = dedupe_skills(vec![
            named_skill(
                "japandi",
                "/u/.fuigo/skills/japandi/SKILL.md",
                SkillScope::User,
            ),
            named_skill(
                "japandi",
                "/u/.agents/skills/japandi/SKILL.md",
                SkillScope::User,
            ),
        ]);
        assert_eq!(out.len(), 1);
        assert!(out[0].path.contains(".fuigo"));
    }

    #[tokio::test]
    async fn copied_skill_dir_with_stale_frontmatter_name_surfaces_both() {
        // Name-dedup runs in `list_skills` (via `merge_skills_with_plugins`), not in `list_skills_with_options`
        // Names are prefixed to be collision-proof against real user-scope skills (`list_skills` scans fuigo_home)
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        init_git_repo(&repo_root);

        let skills_dir = repo_root.join(".fuigo").join("skills");
        write_skill_md(&skills_dir.join("zz-copyfix-japandi"), "zz-copyfix-japandi");
        // The copy keeps the original's frontmatter name.
        write_skill_md(
            &skills_dir.join("zz-copyfix-japandi2"),
            "zz-copyfix-japandi",
        );

        let skills = list_skills(
            Some(repo_root.to_str().unwrap()),
            &SkillsConfig::default(),
            CompatConfig::default(),
            /*project_trusted*/ true,
        )
        .await;
        let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"zz-copyfix-japandi"),
            "missing original in {names:?}"
        );
        assert!(
            names.contains(&"zz-copyfix-japandi2"),
            "missing rekeyed copy in {names:?}"
        );
        let rekeyed = skills
            .iter()
            .find(|s| s.name == "zz-copyfix-japandi2")
            .unwrap();
        assert_eq!(rekeyed.display_name.as_deref(), Some("zz-copyfix-japandi"));
        assert!(rekeyed.path.ends_with("zz-copyfix-japandi2/SKILL.md"));
    }
}

/// Session-start discovery must be bounded, must not pin a tokio worker, and must not be repaid
/// by every later session in the same process.
#[cfg(test)]
mod discovery_budget_tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn write_skill_md(dir: &Path, name: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: A test skill called {name}\n---\n\nBody.\n"),
        )
        .unwrap();
    }

    /// A tempdir project holding one skill, plus the cwd string discovery is keyed on.
    fn project_with_skill(name: &str) -> (tempfile::TempDir, String) {
        let tmp = tempfile::tempdir().unwrap();
        write_skill_md(&tmp.path().join(".fuigo").join("skills").join(name), name);
        let cwd = tmp.path().to_str().unwrap().to_string();
        (tmp, cwd)
    }

    async fn discover(limit: Duration, cwd: &str) -> Vec<SkillInfo> {
        list_skills_with_plugins_within(
            limit,
            Some(cwd),
            &SkillsConfig::default(),
            None,
            CompatConfig::default(),
            /*project_trusted*/ true,
        )
        .await
    }

    fn has(skills: &[SkillInfo], name: &str) -> bool {
        skills.iter().any(|s| s.name == name)
    }

    #[test]
    fn timeout_override_parses_and_falls_back() {
        assert_eq!(
            parse_skill_discovery_timeout(None),
            DEFAULT_SKILL_DISCOVERY_TIMEOUT
        );
        assert_eq!(
            parse_skill_discovery_timeout(Some("  ")),
            DEFAULT_SKILL_DISCOVERY_TIMEOUT
        );
        assert_eq!(
            parse_skill_discovery_timeout(Some("nonsense")),
            DEFAULT_SKILL_DISCOVERY_TIMEOUT
        );
        assert_eq!(
            parse_skill_discovery_timeout(Some("250")),
            Duration::from_millis(250)
        );
    }

    /// The bug: the scan is async in name only. Run inline on a single-threaded runtime a slow
    /// filesystem pins the worker, so no timeout around it can ever fire and `session/new` waits
    /// out the whole walk.
    #[tokio::test(flavor = "current_thread")]
    async fn slow_scan_neither_pins_the_runtime_nor_outlives_its_timeout() {
        let (_tmp, cwd) = project_with_skill("slow-skill");
        test_hooks::set_delay(&cwd, Duration::from_secs(5));
        let started = Instant::now();
        let skills = discover(Duration::from_millis(200), &cwd).await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "discovery blocked for {elapsed:?}; the cap must fire while the scan runs off-worker"
        );
        assert!(
            !has(&skills, "slow-skill"),
            "a scan that overran its cap yields nothing; the reload path backfills"
        );
    }

    /// A capped-out scan must never be cached *as empty*: the next session still gets the skills.
    #[tokio::test]
    async fn a_scan_that_overran_is_not_cached_as_empty() {
        let (_tmp, cwd) = project_with_skill("retry-skill");
        test_hooks::set_delay(&cwd, Duration::from_millis(600));
        assert!(!has(
            &discover(Duration::from_millis(100), &cwd).await,
            "retry-skill"
        ));
        test_hooks::set_delay(&cwd, Duration::ZERO);
        assert!(
            has(
                &discover(Duration::from_secs(30), &cwd).await,
                "retry-skill"
            ),
            "the next session must not inherit the empty result"
        );
    }

    /// `spawn_blocking` cannot be cancelled, so the scan that overran its cap runs to completion
    /// anyway. Throwing its result away made the slow-filesystem case — the one the cache exists
    /// for — the one case that never cached: every session paid another full scan, and every one
    /// of those scans outlived its cap on a live blocking thread.
    #[tokio::test]
    async fn an_overrun_scan_still_populates_the_cache_for_the_next_session() {
        let (_tmp, cwd) = project_with_skill("slow-cached-skill");
        test_hooks::set_delay(&cwd, Duration::from_millis(600));
        let before = skill_discovery_scan_count(Some(&cwd));
        assert!(!has(
            &discover(Duration::from_millis(100), &cwd).await,
            "slow-cached-skill"
        ));
        // Let the scan that overran land.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(
            skill_discovery_scan_count(Some(&cwd)),
            before + 1,
            "exactly one real scan so far"
        );
        let second = discover(Duration::from_secs(30), &cwd).await;
        assert!(
            has(&second, "slow-cached-skill"),
            "the overrun scan's result must serve the next session"
        );
        assert_eq!(
            skill_discovery_scan_count(Some(&cwd)),
            before + 1,
            "the next session must be served from the cache, not rescan the slow tree"
        );
    }

    /// Sessions that start while a scan is already running must join it, not launch their own walk
    /// of the same slow tree.
    #[tokio::test]
    async fn concurrent_session_starts_share_one_scan() {
        let (_tmp, cwd) = project_with_skill("shared-skill");
        test_hooks::set_delay(&cwd, Duration::from_millis(400));
        let before = skill_discovery_scan_count(Some(&cwd));
        let (a, b, c) = tokio::join!(
            discover(Duration::from_secs(30), &cwd),
            discover(Duration::from_secs(30), &cwd),
            discover(Duration::from_secs(30), &cwd),
        );
        assert_eq!(
            skill_discovery_scan_count(Some(&cwd)),
            before + 1,
            "three concurrent session starts must share one filesystem scan"
        );
        for skills in [&a, &b, &c] {
            assert!(
                has(skills, "shared-skill"),
                "every waiter must still get the discovered skills"
            );
        }
    }

    /// The mtime fingerprint has to cover what the walk covers. `walk_for_skill_md` recurses
    /// `MAX_SKILL_WALK_DEPTH` levels, so a skill added below the first level changed no stamped
    /// directory and was never picked up again for the life of the process.
    #[tokio::test]
    async fn a_skill_nested_below_the_first_level_invalidates_the_cache() {
        let (tmp, cwd) = project_with_skill("top-skill");
        let group = tmp
            .path()
            .join(".fuigo")
            .join("skills")
            .join("group")
            .join("sub");
        write_skill_md(&group.join("nested-a"), "nested-a");
        assert!(has(
            &discover(Duration::from_secs(30), &cwd).await,
            "nested-a"
        ));
        write_skill_md(&group.join("nested-b"), "nested-b");
        assert!(
            has(&discover(Duration::from_secs(30), &cwd).await, "nested-b"),
            "a skill added three levels down must still force a rescan"
        );
    }

    /// Editing a description in place changes no directory: the stamp carries the file's mtime and
    /// length so an in-place edit is seen too.
    #[tokio::test]
    async fn an_edited_skill_description_invalidates_the_cache() {
        let (tmp, cwd) = project_with_skill("edited-skill");
        let dir = tmp
            .path()
            .join(".fuigo")
            .join("skills")
            .join("edited-skill");
        let first = discover(Duration::from_secs(30), &cwd).await;
        assert!(
            first
                .iter()
                .any(|s| s.name == "edited-skill" && s.description.contains("A test skill")),
            "baseline description"
        );
        std::fs::write(
            dir.join("SKILL.md"),
            "---\nname: edited-skill\ndescription: Rewritten description for the edited skill\n---\n\nBody.\n",
        )
        .unwrap();
        let second = discover(Duration::from_secs(30), &cwd).await;
        assert!(
            second
                .iter()
                .any(|s| s.name == "edited-skill" && s.description.contains("Rewritten")),
            "an in-place SKILL.md edit must invalidate the cache, got: {:?}",
            second
                .iter()
                .map(|s| (&s.name, &s.description))
                .collect::<Vec<_>>()
        );
    }

    /// `server_skill_dirs`/`bundled_skill_dirs` are scanned but were never fingerprinted, so an
    /// embedded host that syncs new bundled skills to disk was served the pre-sync list forever.
    #[tokio::test]
    async fn injected_server_and_bundled_dirs_are_fingerprinted() {
        for (label, pick) in [
            (
                "server",
                (|c: &mut SkillsConfig, p: String| c.server_skill_dirs.push(p))
                    as fn(&mut SkillsConfig, String),
            ),
            ("bundled", |c: &mut SkillsConfig, p: String| {
                c.bundled_skill_dirs.push(p)
            }),
        ] {
            let (_project, cwd) = project_with_skill(&format!("{label}-anchor"));
            let injected = tempfile::tempdir().unwrap();
            let mut config = SkillsConfig::default();
            pick(&mut config, injected.path().to_str().unwrap().to_string());
            let discover_injected = |config: SkillsConfig, cwd: String| async move {
                list_skills_with_plugins_within(
                    Duration::from_secs(30),
                    Some(&cwd),
                    &config,
                    None,
                    CompatConfig::default(),
                    /*project_trusted*/ true,
                )
                .await
            };
            write_skill_md(&injected.path().join("one"), &format!("{label}-one"));
            let first = discover_injected(config.clone(), cwd.clone()).await;
            assert!(
                has(&first, &format!("{label}-one")),
                "{label}: injected skill must be discovered"
            );
            write_skill_md(&injected.path().join("two"), &format!("{label}-two"));
            let second = discover_injected(config.clone(), cwd.clone()).await;
            assert!(
                has(&second, &format!("{label}-two")),
                "{label}: a skill added to an injected dir must force a rescan"
            );
        }
    }

    /// A previously discovered list beats nothing: when the cap fires on a cached key, serve what
    /// the last scan found rather than telling the session it has no skills.
    #[tokio::test]
    async fn an_overrun_refresh_falls_back_to_the_cached_list() {
        let (_tmp, cwd) = project_with_skill("sticky-skill");
        assert!(has(
            &discover(Duration::from_secs(30), &cwd).await,
            "sticky-skill"
        ));
        test_hooks::set_delay(&cwd, Duration::from_millis(600));
        // Force the cached fingerprint to miss so the slow scan is re-entered.
        write_skill_md(
            &_tmp.path().join(".fuigo").join("skills").join("late-skill"),
            "late-skill",
        );
        let capped = discover(Duration::from_millis(100), &cwd).await;
        assert!(
            has(&capped, "sticky-skill"),
            "an overrun refresh must fall back to the cached list, not an empty one"
        );
        test_hooks::set_delay(&cwd, Duration::ZERO);
    }

    /// The second `session/new` in one process pays nothing: same roots, same answer, no rescan.
    #[tokio::test]
    async fn second_session_start_hits_the_cache() {
        let (_tmp, cwd) = project_with_skill("cached-skill");
        let before = skill_discovery_scan_count(Some(&cwd));
        let first = discover(Duration::from_secs(30), &cwd).await;
        assert_eq!(
            skill_discovery_scan_count(Some(&cwd)),
            before + 1,
            "the first session scans the filesystem"
        );
        let second = discover(Duration::from_secs(30), &cwd).await;
        assert_eq!(
            skill_discovery_scan_count(Some(&cwd)),
            before + 1,
            "the second session must be served from the process cache"
        );
        assert!(has(&first, "cached-skill") && has(&second, "cached-skill"));
        assert_eq!(first.len(), second.len());
    }

    /// The cache is not sticky: adding a skill changes a root's mtime and forces a rescan.
    #[tokio::test]
    async fn a_new_skill_invalidates_the_cache() {
        let (tmp, cwd) = project_with_skill("first-skill");
        let before = skill_discovery_scan_count(Some(&cwd));
        assert!(has(
            &discover(Duration::from_secs(30), &cwd).await,
            "first-skill"
        ));
        write_skill_md(
            &tmp.path()
                .join(".fuigo")
                .join("skills")
                .join("second-skill"),
            "second-skill",
        );
        let after = discover(Duration::from_secs(30), &cwd).await;
        assert_eq!(
            skill_discovery_scan_count(Some(&cwd)),
            before + 2,
            "a changed skills root must force a rescan"
        );
        assert!(
            has(&after, "second-skill"),
            "the rescan must pick the new skill up"
        );
    }
}
