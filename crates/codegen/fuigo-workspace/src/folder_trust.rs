//! Folder trust: one decision per folder for its settings AND its shell commands (u35 t1, design d2).
//!
//! **Trusting a folder** means its project config (hooks, `.envrc`, project MCP/LSP servers, project permission
//! rules, instructions, skills) loads and its shell commands carry the user's authority, as upstream and the peers do
//! it. An **untrusted** folder loads no executable project config, every shell command there that no user grant covers
//! asks (or is refused when nothing can ask), and Fuigo itself starts no `git`, `jj` or `direnv` there.
//!
//! ## Precedence ([`decide`])
//! 1. No trust key ([`crate::trust::trust_key`]: canonicalize failed, non-UTF-8, `$HOME`, `/`) → Untrusted.
//! 2. The user's own `[folder_trust] enabled = false` (absolute user home or managed config) or
//!    `FUIGO_FOLDER_TRUST=0` → Trusted, with a loud warning. A local/dev build (no release stamp) → Trusted (inert).
//!    The remote kill switch is ignored.
//! 3. A relative `FUIGO_HOME`, no home, or an unreadable store → Untrusted.
//! 4. A "no" from this process ([`decline_folder_trust_key`], `/untrust`) → Untrusted, whatever the store says.
//! 5. A stored "no" covering the key → Untrusted (it beats the config list, so `/untrust` always revokes).
//! 6. `[folder_trust] trusted_folders` in the user's own config (or managed config) covering the key → Trusted.
//! 7. A stored "yes" at the current consent ([`crate::trust::CONSENT_V`]) → Trusted.
//! 8. A stored "yes" from before 1.0.35 (Legacy) → asked once more (`Prompt(Upgrade)`), else Untrusted; no record →
//!    `Prompt(New)`, else Untrusted. While a question is pending the folder is Untrusted.
//!
//! [`dir_trust`] caches the command-side verdict per canonical directory, validated by a fingerprint of the trust
//! inputs (store, user and managed config, worktree registry, the switch, this process's declines); errors and
//! pending questions are never cached.

use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use parking_lot::Mutex;

use toml::Value as TomlValue;
use fuigo_config_types::BoolFlag;

pub use crate::trust::{CONSENT_V, Coverage, KeyError};
use crate::trust::{TrustStore, trust_key};

/// Why a folder is not trusted for commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UntrustedReason {
    /// The folder has no trust key (canonicalize failed, non-UTF-8, home or filesystem root).
    Key(KeyError),
    /// The user declined this folder (stored, or in this process).
    Declined(PathBuf),
    /// Trusted before 1.0.35 (settings only); asked once more before it covers commands.
    Legacy(PathBuf),
    /// Never decided.
    Undecided(PathBuf),
    /// The trust inputs could not be read (relative `FUIGO_HOME`, no home, unreadable store).
    Inputs,
}

impl UntrustedReason {
    /// The folder's trust key, when it has one.
    pub fn key(&self) -> Option<&Path> {
        match self {
            Self::Declined(k) | Self::Legacy(k) | Self::Undecided(k) => Some(k),
            Self::Key(_) | Self::Inputs => None,
        }
    }

    /// Whether the folder is the user's home or the filesystem root (or otherwise can never be trusted).
    pub fn unrecordable(&self) -> bool {
        matches!(self, Self::Key(KeyError::Unrecordable))
    }
}

/// u35 t1 (design d2 §5.4): what a session that cannot ask says when a shell command was not run because its folder
/// is not trusted (headless, `dontAsk`).
pub fn untrusted_command_refusal(reason: &UntrustedReason) -> String {
    if reason.unrecordable() {
        return "Not run: home and root folders can't be trusted; run Fuigo from a project folder, or pass an allow \
                rule such as --allow 'Bash(cargo test *)'."
            .to_owned();
    }
    let folder = reason.key().map_or_else(|| "this folder".to_owned(), |key| key.display().to_string());
    format!(
        "Not run: {folder} is not a trusted folder and this session can't ask. Run \"fuigo --trust\" there once, or \
         add to ~/.fuigo/config.toml: [folder_trust] trusted_folders = [\"{folder}\"] (a project's own config can't \
         set this). An allow rule such as --allow 'Bash(cargo test *)' also works."
    )
}

/// u35 t1 (design d2 §5.4): what a session that cannot ask says once at start in a folder that is not trusted.
pub fn untrusted_session_notice(reason: &UntrustedReason) -> String {
    let refusal = untrusted_command_refusal(reason);
    let rest = refusal.strip_prefix("Not run: ").unwrap_or(&refusal);
    format!("shell commands without an allow rule will not run: {rest}")
}

/// Why the folder-trust question is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptReason {
    /// Never decided.
    New,
    /// Trusted before 1.0.35 for its settings only: asked once more, because trust now also covers commands.
    Upgrade,
}

/// The folder-trust decision for a folder ([`decide`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    Trusted,
    Untrusted(UntrustedReason),
    /// Interactive: ask the user. The folder is Untrusted until answered.
    Prompt(PromptReason),
}

impl TrustDecision {
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }
}

/// The command-side trust verdict for a directory or a command's directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandTrust {
    Trusted,
    Untrusted(UntrustedReason),
}

impl CommandTrust {
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }
}

/// Whether the whole folder-trust system is inert (auto-trusts everything) for this binary: true on a local/dev build (no `FUIGO_VERSION` stamp).
/// Every trust auto-grant site calls this; when true fuigo never prompts, never gates, and does no `trusted_folders.toml` I/O.
pub fn folder_trust_inert() -> bool {
    is_local_build()
}

/// Whether this binary was built without a release version stamp (`FUIGO_VERSION` unset at compile time), i.e. a local/dev build.
/// Kept local rather than in `fuigo-version`: adding a symbol to that near-universal crate widens the rebuild/test fan-out for unrelated targets.
/// `option_env!` resolves the same in any crate. Cross-crate callers use [`folder_trust_inert`].
fn is_local_build() -> bool {
    // Runtime escape hatch: a pinned FUIGO_TEST_VERSION simulates a release build
    // Tests/CI run unstamped, so they look like local builds; this lets them exercise the gate
    if std::env::var(fuigo_version::TEST_VERSION_ENV).is_ok() {
        return false;
    }
    option_env!("FUIGO_VERSION").is_none()
}

/// The warning shown once when the user switched folder trust off (owner decision D2).
pub const DISABLED_WARNING: &str =
    "Folder trust is off: every folder's config and commands run with your authority";

// ── Trust inputs (store, config list, switch), cached by fingerprint ─────────────────────────────

/// One file's identity for the fingerprint: absent, or (length, mtime, inode-ish, permissions, status-change time).
/// u35 t2 (Astra 3): the permissions and the status-change time are in it, so a `chmod` (a store made unreadable)
/// invalidates every verdict cached before it, though the length, mtime and inode stay the same.
type FileStamp = Option<(u64, Option<std::time::SystemTime>, u64, u32, (i64, i64))>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    home: Option<PathBuf>,
    files: Vec<FileStamp>,
    switch: Option<std::ffi::OsString>,
    test_version: bool,
    declines: u64,
}

fn file_stamp(path: &Path) -> FileStamp {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    let ino = {
        use std::os::unix::fs::MetadataExt;
        meta.ino() ^ meta.dev().rotate_left(32)
    };
    #[cfg(not(unix))]
    let ino = 0;
    #[cfg(unix)]
    let (mode, changed) = {
        use std::os::unix::fs::MetadataExt;
        (meta.mode(), (meta.ctime(), meta.ctime_nsec()))
    };
    #[cfg(not(unix))]
    let (mode, changed) = (u32::from(meta.permissions().readonly()), (0, 0));
    Some((meta.len(), meta.modified().ok(), ino, mode, changed))
}

/// The worktree registry file the read-write open would use under `home` (per host on network mounts), resolved once
/// per home (it runs a statfs and a hostname lookup).
fn worktree_db_path(home: &Path) -> PathBuf {
    static CACHE: LazyLock<Mutex<HashMap<PathBuf, PathBuf>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
    if let Some(path) = CACHE.lock().get(home) {
        return path.clone();
    }
    let path = fuigo_fast_worktree::WorktreeDb::resolve_db_path(home);
    CACHE.lock().insert(home.to_path_buf(), path.clone());
    path
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

/// u35 t1 (design d2 §2.3, Grok d2 H3, Astra d2 M5): the files whose content decides folder trust: the store, the user
/// and managed config, and the worktree registry Fuigo actually opens (`WorktreeDb::resolve_db_path`, per-host on a
/// network mount) with its `-wal`/`-shm`/`-journal` sidecars. Empty when no absolute user home resolves (then nothing
/// is read from it either). The protected-edit floor compares these by physical path AND by file identity, so a
/// symlink, a hard link or a renamed path cannot be used to write them.
pub fn trust_input_paths() -> Vec<PathBuf> {
    let Some(home) = fuigo_config::user_fuigo_home() else {
        return Vec::new();
    };
    let db = worktree_db_path(&home);
    let mut paths = vec![
        home.join(crate::trust::TRUST_FILE_NAME),
        home.join(fuigo_config::USER_CONFIG_FILENAME),
        home.join(fuigo_config::MANAGED_CONFIG_FILENAME),
        db.clone(),
    ];
    paths.extend(["-wal", "-shm", "-journal"].map(|s| with_suffix(&db, s)));
    paths
}

/// Whether the physical `path` IS one of the [`trust_input_paths`]: the same resolved path, or the same file (device
/// and inode on Unix, file index on Windows) reached through a hard link or another name.
pub fn is_trust_input(path: &Path) -> bool {
    let inputs = trust_input_paths();
    if inputs.is_empty() {
        return false;
    }
    let target = same_file::Handle::from_path(path).ok();
    inputs.iter().any(|input| {
        let physical = dunce::canonicalize(input).unwrap_or_else(|_| input.clone());
        physical == path
            || target
                .as_ref()
                .is_some_and(|t| same_file::Handle::from_path(&physical).ok().as_ref() == Some(t))
    })
}

fn fingerprint() -> Fingerprint {
    let home = fuigo_config::user_fuigo_home();
    // Every trust input, the registry's `-shm`/`-journal` sidecars included (empty when no absolute home resolves).
    let files = trust_input_paths().iter().map(|p| file_stamp(p)).collect();
    Fingerprint {
        home,
        files,
        switch: std::env::var_os("FUIGO_FOLDER_TRUST"),
        test_version: std::env::var_os(fuigo_version::TEST_VERSION_ENV).is_some(),
        declines: DECLINE_GENERATION.load(Ordering::Acquire),
    }
}

/// The trust inputs read from the user's absolute home: the store, the switch, and the `trusted_folders` keys.
#[derive(Debug)]
struct TrustInputs {
    /// `None`: no absolute user home (relative `FUIGO_HOME` or none): nothing is trusted.
    store: Option<TrustStore>,
    /// The user's own `[folder_trust] enabled = false` or `FUIGO_FOLDER_TRUST=0`.
    disabled: bool,
    /// `[folder_trust] trusted_folders`, each resolved to its trust key.
    config_keys: Vec<PathBuf>,
    /// u35 t2 (Astra 6): the user or managed config could not be read or parsed. The decision still uses what did
    /// load (a store grant counts; a malformed config does not untrust every folder), but neither these inputs nor a
    /// verdict derived from them is cached: the next use reads and decides again.
    load_failed: bool,
}

fn folder_trust_table(value: Option<&TomlValue>) -> Option<&toml::map::Map<String, TomlValue>> {
    value?.get("folder_trust")?.as_table()
}

fn load_inputs() -> TrustInputs {
    let home = fuigo_config::user_fuigo_home();
    // The user and managed config are read only from an absolute user home (`user_fuigo_home` is `None` otherwise).
    let mut load_failed = false;
    let mut loaded = |layer: &str, result: Result<TomlValue, _>| match result {
        Ok(value) => Some(value),
        Err(error) => {
            load_failed = true;
            tracing::warn!(layer, %error, "folder trust: could not read the config; its folder-trust settings are ignored until it loads");
            None
        }
    };
    let user = home.as_ref().and_then(|_| loaded("user", fuigo_config::load_from_disk()));
    let managed = home.as_ref().and_then(|_| loaded("managed", fuigo_config::load_managed_config()));
    let enabled_of = |v: Option<&TomlValue>| folder_trust_table(v)?.get("enabled")?.as_bool();
    let enabled = BoolFlag::env("FUIGO_FOLDER_TRUST")
        .config(enabled_of(user.as_ref()))
        .managed(enabled_of(managed.as_ref()))
        .default(true)
        .resolve()
        .value;
    let mut config_keys = Vec::new();
    for layer in [managed.as_ref(), user.as_ref()] {
        let Some(list) = folder_trust_table(layer).and_then(|t| t.get("trusted_folders")).and_then(TomlValue::as_array)
        else {
            continue;
        };
        for entry in list.iter().filter_map(TomlValue::as_str) {
            let path = match entry.strip_prefix("~/") {
                Some(rest) => match fuigo_dirs::home_dir() {
                    Some(h) => h.join(rest),
                    None => continue,
                },
                None => PathBuf::from(entry),
            };
            if !path.is_absolute() {
                tracing::warn!(entry, "[folder_trust] trusted_folders: ignoring a relative path");
                continue;
            }
            match trust_key(&path) {
                Ok(key) => config_keys.push(key),
                Err(KeyError::Unrecordable) => {
                    tracing::warn!(entry, "[folder_trust] trusted_folders: home and root folders can't be trusted; ignored");
                }
                Err(KeyError::Canonicalize) => {
                    tracing::debug!(entry, "[folder_trust] trusted_folders: folder not found; ignored");
                }
            }
        }
    }
    let store = crate::trust::TrustStore::default_path().map(TrustStore::load_from);
    TrustInputs { store, disabled: !enabled, config_keys, load_failed }
}

/// The trust inputs last read, with the fingerprint they were read at.
type CachedInputs = Option<(Fingerprint, Arc<TrustInputs>)>;

static INPUTS: LazyLock<Mutex<CachedInputs>> = LazyLock::new(|| Mutex::new(None));

fn inputs_for(fp: &Fingerprint) -> Arc<TrustInputs> {
    if let Some((cached_fp, inputs)) = INPUTS.lock().as_ref()
        && cached_fp == fp
    {
        return inputs.clone();
    }
    let inputs = Arc::new(load_inputs());
    if !inputs.load_failed {
        *INPUTS.lock() = Some((fp.clone(), inputs.clone()));
    }
    inputs
}

/// Whether the user switched folder trust off (their own config or `FUIGO_FOLDER_TRUST=0`); the TUI and headless
/// startup show [`DISABLED_WARNING`] when it is.
pub fn folder_trust_disabled() -> bool {
    !folder_trust_inert() && inputs_for(&fingerprint()).disabled
}

fn warn_disabled_once() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| tracing::warn!("{DISABLED_WARNING}"));
}

// ── This process's declines ───────────────────────────────────────────────────────────────────────

/// Keys the user declined in this process (`n`, `/untrust`). A decline beats the store and the config list for this
/// process even when it could not be saved (Grok d2 M6). There is no process-local grant: a "yes" that could not be
/// saved leaves the folder untrusted.
static PROCESS_DECLINES: LazyLock<Mutex<HashSet<PathBuf>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
static DECLINE_GENERATION: AtomicU64 = AtomicU64::new(0);

fn set_process_decline(key: &Path, declined: bool) {
    let changed = if declined {
        PROCESS_DECLINES.lock().insert(key.to_path_buf())
    } else {
        PROCESS_DECLINES.lock().remove(key)
    };
    if changed {
        DECLINE_GENERATION.fetch_add(1, Ordering::AcqRel);
    }
}

/// A trust change this process made (or saw): every cached verdict is re-derived on its next use.
pub fn note_trust_changed() {
    DECLINE_GENERATION.fetch_add(1, Ordering::AcqRel);
}

/// The current trust-input fingerprint generation, for callers that cache something derived from trust (the
/// permission manager's compiled project policy): changes whenever any trust input or this process's declines change.
pub fn trust_generation() -> u64 {
    use std::hash::{Hash, Hasher};
    let fp = fingerprint();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    fp.home.hash(&mut h);
    fp.files.hash(&mut h);
    fp.switch.hash(&mut h);
    fp.test_version.hash(&mut h);
    fp.declines.hash(&mut h);
    h.finish()
}

// ── The decision ─────────────────────────────────────────────────────────────────────────────────

/// The folder-trust decision for `cwd` (see the module docs for the precedence). `interactive`: whether the caller can
/// ask the user now (the TUI question, an ACP v2 client); otherwise an undecided or Legacy folder is Untrusted.
pub fn decide(cwd: &Path, interactive: bool) -> TrustDecision {
    if folder_trust_inert() {
        return TrustDecision::Trusted;
    }
    decide_in(cwd, interactive, &inputs_for(&fingerprint()))
}

/// [`decide`] over trust inputs already read.
fn decide_in(cwd: &Path, interactive: bool, inputs: &TrustInputs) -> TrustDecision {
    let Ok(physical) = dunce::canonicalize(cwd) else {
        return TrustDecision::Untrusted(UntrustedReason::Key(KeyError::Canonicalize));
    };
    match trust_key(&physical) {
        Ok(key) => decide_with(&physical, &key, interactive, inputs),
        Err(e) => TrustDecision::Untrusted(UntrustedReason::Key(e)),
    }
}

/// [`decide`] for an already-resolved trust key.
pub fn decide_key(key: &Path, interactive: bool) -> TrustDecision {
    if folder_trust_inert() {
        return TrustDecision::Trusted;
    }
    let inputs = inputs_for(&fingerprint());
    decide_with(key, key, interactive, &inputs)
}

/// The precedence for the physical folder `path` whose trust key is `key` (a record for a subfolder of the repository
/// counts for that subfolder: the most specific "no" wins).
fn decide_with(path: &Path, key: &Path, interactive: bool, inputs: &TrustInputs) -> TrustDecision {
    let key_buf = || key.to_path_buf();
    if inputs.disabled {
        warn_disabled_once();
        return TrustDecision::Trusted;
    }
    let Some(store) = inputs.store.as_ref().filter(|s| s.disk_readable()) else {
        return TrustDecision::Untrusted(UntrustedReason::Inputs);
    };
    if PROCESS_DECLINES.lock().contains(key) {
        return TrustDecision::Untrusted(UntrustedReason::Declined(key_buf()));
    }
    let coverage = store.coverage(path, key);
    if coverage == Coverage::Declined {
        return TrustDecision::Untrusted(UntrustedReason::Declined(key_buf()));
    }
    if inputs.config_keys.iter().any(|k| k == key) {
        return TrustDecision::Trusted;
    }
    match coverage {
        Coverage::Trusted { consent } if consent >= CONSENT_V => TrustDecision::Trusted,
        Coverage::Trusted { .. } if interactive => TrustDecision::Prompt(PromptReason::Upgrade),
        Coverage::Trusted { .. } => TrustDecision::Untrusted(UntrustedReason::Legacy(key_buf())),
        Coverage::None | Coverage::Declined if interactive => TrustDecision::Prompt(PromptReason::New),
        Coverage::None | Coverage::Declined => TrustDecision::Untrusted(UntrustedReason::Undecided(key_buf())),
    }
}

/// Per canonical directory: the fingerprint it was derived under and the verdict.
static DIR_CACHE: LazyLock<Mutex<HashMap<PathBuf, (Fingerprint, CommandTrust)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The command-side verdict for one directory: Trusted only when [`decide`] (not interactive) is Trusted. Spawns
/// nothing. Cached per canonical directory under the trust-input fingerprint; key errors and undecided/Legacy folders
/// (a question may be pending) are never cached.
pub fn dir_trust(dir: &Path) -> CommandTrust {
    #[cfg(test)]
    if let Some(forced) = test_folder_trust(dir) {
        return forced;
    }
    if folder_trust_inert() {
        return CommandTrust::Trusted;
    }
    let Ok(canonical) = dunce::canonicalize(dir) else {
        return CommandTrust::Untrusted(UntrustedReason::Key(KeyError::Canonicalize));
    };
    let fp = fingerprint();
    if let Some((cached_fp, verdict)) = DIR_CACHE.lock().get(&canonical)
        && *cached_fp == fp
    {
        return verdict.clone();
    }
    let inputs = inputs_for(&fp);
    let verdict = match decide_in(&canonical, false, &inputs) {
        TrustDecision::Trusted => CommandTrust::Trusted,
        TrustDecision::Untrusted(reason) => CommandTrust::Untrusted(reason),
        TrustDecision::Prompt(_) => CommandTrust::Untrusted(UntrustedReason::Undecided(canonical.clone())),
    };
    let cacheable = !inputs.load_failed
        && matches!(
            verdict,
            CommandTrust::Trusted | CommandTrust::Untrusted(UntrustedReason::Declined(_) | UntrustedReason::Inputs)
        );
    if cacheable {
        DIR_CACHE.lock().insert(canonical, (fp, verdict.clone()));
    }
    verdict
}

/// Trusted iff every directory is ([`dir_trust`]); the first untrusted directory's reason otherwise.
pub fn command_trust<'a>(dirs: impl IntoIterator<Item = &'a Path>) -> CommandTrust {
    for dir in dirs {
        if let CommandTrust::Untrusted(reason) = dir_trust(dir) {
            return CommandTrust::Untrusted(reason);
        }
    }
    CommandTrust::Trusted
}

/// Install this process's folder-trust judges: the repository-tool gate (`fuigo_tty_utils::repo_exec`) and the shell
/// runner's backstop. Every binary entry calls it once at start, before anything can spawn.
pub fn install_process_judges() {
    fuigo_tty_utils::install_repo_exec_judge(|dir| dir_trust(dir).is_trusted());
    crate::permission::install_runner_trust_judge();
}

#[cfg(test)]
thread_local! {
    static TEST_FOLDER_TRUST: std::cell::RefCell<TestTrustMode> = const { std::cell::RefCell::new(TestTrustMode::Default) };
}

#[cfg(test)]
#[derive(Debug, Clone)]
enum TestTrustMode {
    /// Tests that do not choose: every folder Trusted (existing suites keep r14 behaviour).
    Default,
    Fixed(CommandTrust),
    /// Trusted only under these folders (as given and canonical); every other folder Undecided.
    Only(Vec<PathBuf>),
    /// The real decision (store, config, keys).
    Real,
}

#[cfg(test)]
fn test_folder_trust(dir: &Path) -> Option<CommandTrust> {
    TEST_FOLDER_TRUST.with(|m| match &*m.borrow() {
        TestTrustMode::Default => Some(CommandTrust::Trusted),
        TestTrustMode::Fixed(t) => Some(t.clone()),
        TestTrustMode::Only(roots) => {
            // u35 t2 (Astra 7): physical containment only, as the real decision (a symlink inside a trusted folder
            // that points elsewhere is the folder it points to; a folder that does not resolve is not trusted).
            let Ok(canonical) = dunce::canonicalize(dir) else {
                return Some(CommandTrust::Untrusted(UntrustedReason::Key(KeyError::Canonicalize)));
            };
            Some(if roots.iter().any(|root| canonical.starts_with(root)) {
                CommandTrust::Trusted
            } else {
                CommandTrust::Untrusted(UntrustedReason::Undecided(canonical))
            })
        }
        TestTrustMode::Real => None,
    })
}

/// Test-only: until dropped, [`dir_trust`] on this thread returns `trust` (or the real decision with
/// [`TestFolderTrust::real`]). Without one, every folder is Trusted in this crate's tests.
#[cfg(test)]
pub(crate) struct TestFolderTrust(TestTrustMode);

#[cfg(test)]
impl TestFolderTrust {
    pub(crate) fn set(trust: CommandTrust) -> Self {
        Self(TEST_FOLDER_TRUST.with(|m| m.replace(TestTrustMode::Fixed(trust))))
    }
    pub(crate) fn untrusted() -> Self {
        Self::set(CommandTrust::Untrusted(UntrustedReason::Undecided(PathBuf::from("/untrusted-test-folder"))))
    }
    /// Trusted only physically under `roots` (each by its canonical path).
    pub(crate) fn only(roots: &[&Path]) -> Self {
        let all = roots.iter().map(|root| dunce::canonicalize(root).unwrap_or_else(|_| root.to_path_buf())).collect();
        Self(TEST_FOLDER_TRUST.with(|m| m.replace(TestTrustMode::Only(all))))
    }
    pub(crate) fn real() -> Self {
        Self(TEST_FOLDER_TRUST.with(|m| m.replace(TestTrustMode::Real)))
    }
}

#[cfg(test)]
impl Drop for TestFolderTrust {
    fn drop(&mut self) {
        let prev = std::mem::replace(&mut self.0, TestTrustMode::Default);
        TEST_FOLDER_TRUST.with(|m| *m.borrow_mut() = prev);
    }
}

// ── Grants, declines, revocation ────────────────────────────────────────────────────────────────

/// Why a grant was refused before anything was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRefuse {
    /// Local/dev build: folder-trust is inert (auto-trusts everything).
    InertBuild,
    /// Home, filesystem root, a non-UTF-8 or non-absolute path: never trusted.
    UnsafeRoot,
    /// No user home, or a relative store home (that would be a cwd-relative store).
    NoHome,
    /// The existing store could not be read or parsed; nothing was recorded and the file is untouched.
    Unreadable,
    /// The key no longer resolves to itself (the folder was deleted, moved, or is not canonical).
    KeyMoved,
}

impl std::fmt::Display for GrantRefuse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InertBuild => write!(f, "folder trust is off in this build"),
            Self::UnsafeRoot => write!(
                f,
                "This folder can't be trusted (home and root folders never are). Run Fuigo from a project folder."
            ),
            Self::NoHome => write!(
                f,
                "Couldn't save folder trust: no home directory for the trust store. \
                 Set FUIGO_HOME to an absolute directory (or unset it), then start Fuigo again."
            ),
            Self::Unreadable => write!(
                f,
                "Couldn't save folder trust: the trust store could not be read. \
                 Fix or delete trusted_folders.toml in your Fuigo home ($FUIGO_HOME, default ~/.fuigo), \
                 then start Fuigo again and trust the folder."
            ),
            Self::KeyMoved => write!(
                f,
                "Couldn't save folder trust: the folder path changed. \
                 Start Fuigo again from the folder you want to trust."
            ),
        }
    }
}

impl std::error::Error for GrantRefuse {}

/// What happened on disk after a real insert was attempted.
#[derive(Debug)]
pub enum PersistStatus {
    /// Written to `trusted_folders.toml`.
    Durable,
    /// The store was read (or is missing) but the lock or write failed (e.g. `--sandbox` denies writes under the
    /// home). Nothing was published, and the folder stays untrusted (there is no process-local grant).
    NotSaved { error: std::io::Error },
}

/// Result of an explicit grant (`--trust`, the trust question, `/trust`).
#[derive(Debug)]
pub enum GrantOutcome {
    /// A record was inserted; see `persist` for whether it reached disk.
    Granted { key: PathBuf, persist: PersistStatus },
    /// The exact key is already durably trusted (current consent); the store was not rewritten.
    AlreadyDurable { key: PathBuf },
    /// Nothing was recorded.
    Refused { reason: GrantRefuse },
}

impl std::fmt::Display for GrantOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Granted {
                persist: PersistStatus::NotSaved { error },
                ..
            } => write!(
                f,
                "Couldn't save folder trust ({error}); the folder stays untrusted. \
                 Check that your Fuigo home ($FUIGO_HOME, default ~/.fuigo) is writable, \
                 then run `fuigo --trust` in this folder."
            ),
            Self::Refused { reason } => write!(f, "{reason}"),
            Self::Granted { .. } | Self::AlreadyDurable { .. } => write!(f, "folder trust was saved"),
        }
    }
}

impl std::error::Error for GrantOutcome {}

/// How a gate should treat a [`GrantOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantResolution {
    /// Durable, already durable, or auto-trusted (inert build): the folder is trusted.
    Trusted,
    /// Nothing durable was recorded: the folder is not trusted.
    Unrecorded,
}

impl GrantOutcome {
    #[must_use]
    pub fn resolution(&self) -> GrantResolution {
        match self {
            Self::Granted {
                persist: PersistStatus::Durable,
                ..
            }
            | Self::AlreadyDurable { .. }
            | Self::Refused {
                reason: GrantRefuse::InertBuild,
            } => GrantResolution::Trusted,
            Self::Granted {
                persist: PersistStatus::NotSaved { .. },
                ..
            }
            | Self::Refused { .. } => GrantResolution::Unrecorded,
        }
    }

    /// True only when the grant answers the gate durably (or the build is inert).
    #[must_use]
    pub fn dismisses_gate(&self) -> bool {
        matches!(self.resolution(), GrantResolution::Trusted)
    }
}

/// Report a `--trust` result on stderr. Durable and auto-trusted outcomes are silent; an unsaved grant or a refusal
/// prints its reason and next step, so `--trust` never fails silently.
pub fn report_cli_trust_grant(outcome: &GrantOutcome) {
    if outcome.dismisses_gate() {
        return;
    }
    tracing::warn!(error = %outcome, "--trust: folder trust was not saved");
    fuigo_tty_utils::cli_eprintln!("{}", fuigo_tty_utils::untrusted(outcome));
}

/// Persist an explicit `--trust` / `/trust` grant for `trust_key(cwd)` (settings and commands, [`CONSENT_V`]).
pub fn grant_folder_trust(cwd: &Path) -> GrantOutcome {
    if folder_trust_inert() {
        return GrantOutcome::Refused {
            reason: GrantRefuse::InertBuild,
        };
    }
    match trust_key(cwd) {
        Ok(key) => grant_folder_trust_key(&key),
        Err(KeyError::Unrecordable) => GrantOutcome::Refused {
            reason: GrantRefuse::UnsafeRoot,
        },
        Err(KeyError::Canonicalize) => GrantOutcome::Refused {
            reason: GrantRefuse::KeyMoved,
        },
    }
}

/// Grant exactly the key the user was shown (the trust question's folder). Canonicalize-checks it; does not
/// re-derive [`trust_key`].
pub fn grant_folder_trust_key(key: &Path) -> GrantOutcome {
    checked_grant(TrustStore::default_path(), key)
}

/// [`grant_folder_trust_key`] against the store at `store_home.join(TRUST_FILE_NAME)` (tests, and callers with an
/// explicit home). A relative `store_home` is refused as [`GrantRefuse::NoHome`].
pub fn grant_folder_trust_key_in(store_home: &Path, key: &Path) -> GrantOutcome {
    let store_path = store_home
        .is_absolute()
        .then(|| store_home.join(crate::trust::TRUST_FILE_NAME));
    checked_grant(store_path, key)
}

/// The single pre-check owner: inert / canonical / unsafe-root once, then the store write.
fn checked_grant(store_path: Option<PathBuf>, key: &Path) -> GrantOutcome {
    if let Some(refused) = precheck_grant(key) {
        return refused;
    }
    let Some(store_path) = store_path else {
        return GrantOutcome::Refused {
            reason: GrantRefuse::NoHome,
        };
    };
    let mut store = TrustStore::load_from(store_path);
    apply_grant_to_store(&mut store, key)
}

fn precheck_grant(key: &Path) -> Option<GrantOutcome> {
    if folder_trust_inert() {
        return Some(GrantOutcome::Refused {
            reason: GrantRefuse::InertBuild,
        });
    }
    // An existing key must be its own canonical form (an alias or a moved folder is not the key that was shown).
    // A key that does not exist at all is granted as written only when it is absolute and lexically normal: that is
    // the standalone `fuigo -w` worktree whose recorded source repo was deleted, and such a record can only cover
    // that exact, normal prefix.
    let canonical = match dunce::canonicalize(key) {
        Ok(c) => c,
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                && key.is_absolute()
                && key
                    .components()
                    .all(|c| !matches!(c, std::path::Component::CurDir | std::path::Component::ParentDir)) =>
        {
            key.to_path_buf()
        }
        Err(_) => {
            return Some(GrantOutcome::Refused {
                reason: GrantRefuse::KeyMoved,
            });
        }
    };
    if canonical != key {
        return Some(GrantOutcome::Refused {
            reason: GrantRefuse::KeyMoved,
        });
    }
    if crate::trust::is_unsafe_trust_root(key) || key.to_str().is_none() {
        return Some(GrantOutcome::Refused {
            reason: GrantRefuse::UnsafeRoot,
        });
    }
    None
}

fn apply_grant_to_store(store: &mut TrustStore, key: &Path) -> GrantOutcome {
    let key = key.to_path_buf();
    if !store.disk_readable() {
        return GrantOutcome::Refused {
            reason: GrantRefuse::Unreadable,
        };
    }
    if !store.has_store_path() {
        return GrantOutcome::Refused {
            reason: GrantRefuse::NoHome,
        };
    }
    // Already durable needs a clean read and an exact record at the current consent (a Legacy record is rewritten).
    if store.has_decision(&key) && store.coverage(&key, &key) == (Coverage::Trusted { consent: CONSENT_V }) {
        set_process_decline(&key, false);
        return GrantOutcome::AlreadyDurable { key };
    }
    match store.grant(&key) {
        Ok(crate::trust::Recorded::Durable) => {
            set_process_decline(&key, false);
            note_trust_changed();
            GrantOutcome::Granted {
                key,
                persist: PersistStatus::Durable,
            }
        }
        Ok(crate::trust::Recorded::Skipped) => GrantOutcome::Refused {
            reason: GrantRefuse::UnsafeRoot,
        },
        Err(crate::trust::TrustPersistError::Unreadable(_)) => GrantOutcome::Refused {
            reason: GrantRefuse::Unreadable,
        },
        Err(crate::trust::TrustPersistError::Publish(error)) => {
            tracing::warn!(error = %error, "folder trust: the grant could not be saved; the folder stays untrusted");
            GrantOutcome::Granted {
                key,
                persist: PersistStatus::NotSaved { error },
            }
        }
    }
}

/// Persist an accepted interactive (stderr) prompt for `key`. Returns the outcome so the caller can report it.
pub fn persist_trust(store: &mut TrustStore, key: &Path) -> GrantOutcome {
    let outcome = apply_grant_to_store(store, key);
    if let GrantOutcome::Refused { reason } = &outcome {
        tracing::warn!(path = %key.display(), ?reason, "folder trust: grant refused");
    }
    outcome
}

/// The user said no for `key` (the question's `n`, `/untrust`): held in this process at once, then saved. Returns the
/// save error when the "no" could not be saved (the caller tells the user: untrusted here, not saved).
pub fn decline_folder_trust_key(key: &Path) -> Result<(), std::io::Error> {
    set_process_decline(key, true);
    if folder_trust_inert() {
        return Ok(());
    }
    let mut store = TrustStore::load();
    if !store.has_store_path() {
        return Err(std::io::Error::other("no absolute Fuigo home for the trust store"));
    }
    let result = store.set_untrusted(key);
    note_trust_changed();
    result
}

/// The result of `/untrust` ([`revoke_folder_trust_store`]).
#[derive(Debug)]
pub enum RevokeOutcome {
    /// The folder is untrusted now. `was_trusted`: it was trusted before; `saved`: the "no" reached the store.
    Revoked { key: PathBuf, was_trusted: bool, saved: Result<(), std::io::Error> },
    /// Nothing to revoke: an inert build, or a folder with no trust key (never trusted).
    NotApplicable,
}

impl RevokeOutcome {
    /// Whether the folder had been trusted.
    pub fn was_trusted(&self) -> bool {
        matches!(self, Self::Revoked { was_trusted: true, .. })
    }
}

/// `/untrust`: decline `trust_key(cwd)` in the store and in this process, whatever covered it before (a stored grant,
/// the config list). The next command asks and project settings stop applying.
pub fn revoke_folder_trust_store(cwd: &Path) -> RevokeOutcome {
    if folder_trust_inert() {
        return RevokeOutcome::NotApplicable;
    }
    let Ok(key) = trust_key(cwd) else {
        return RevokeOutcome::NotApplicable;
    };
    let was_trusted = decide_key(&key, false).is_trusted();
    let saved = decline_folder_trust_key(&key);
    if let Err(e) = &saved {
        tracing::warn!(path = %key.display(), error = %e, "folder trust: failed to persist untrust decision");
    }
    RevokeOutcome::Revoked { key, was_trusted, saved }
}

#[cfg(test)]
#[path = "folder_trust_grant_tests.rs"]
mod grant_tests;

/// Whether any repo-local trust-sensitive config is present for `cwd`.
/// When none are present there is nothing to gate, so we skip the prompt entirely.
/// Thin wrapper over [`collect_repo_config_kinds`] with `first_only = true`, so this hot path short-circuits on the first hit.
/// The gate and the display-only [`repo_config_kinds`] therefore enumerate the EXACT same markers and cannot drift.
pub fn repo_configs_present(cwd: &Path) -> bool {
    !collect_repo_config_kinds(cwd, true).is_empty()
}

/// Display-only (not itself the trust gate): the repo-local trust-sensitive config kinds present for `cwd`, deduped in cheap-to-expensive order.
/// Kinds: `mcp`, `plugins`, `permission`, `lsp`, `envrc`, `claude`, `hooks`, `agents`, `roles`, `personas`, `workflows`.
/// Single source with [`repo_configs_present`], which is `!repo_config_kinds(cwd).is_empty()`.
/// A folder the gate fired on therefore always has a non-empty, accurate kind list.
pub fn repo_config_kinds(cwd: &Path) -> Vec<&'static str> {
    collect_repo_config_kinds(cwd, false)
}

/// Whether a project `.fuigo/config.toml` `[permission]` value would contribute rules to the permission resolver.
/// Mirrors the shapes `permission::resolution` loads: non-empty `allow`/`deny`/`ask` arrays, or a non-empty verbose `rules` array.
/// Empty arrays and empty tables do not gate (same as an empty `[mcp_servers]` or `[plugins].paths`).
fn config_toml_permission_contributes(permission_value: &TomlValue) -> bool {
    let Some(table) = permission_value.as_table() else {
        // Non-table `[permission]` fails config load elsewhere
        // Treat it as a marker so a malicious non-table still trips the gate rather than resolving trusted
        return true;
    };
    for key in ["deny", "allow", "ask"] {
        if table
            .get(key)
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty())
        {
            return true;
        }
    }
    table
        .get("rules")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty())
}

pub(crate) fn path_present_or_uncertain(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

fn directory_present_or_uncertain(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(metadata) => metadata.is_dir(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

/// Shared scanner behind [`repo_configs_present`] and [`repo_config_kinds`].
/// With `first_only` it returns immediately after the first marker (the gate's short-circuit); otherwise it collects every distinct kind.
fn collect_repo_config_kinds(cwd: &Path, first_only: bool) -> Vec<&'static str> {
    // Resolve the git root and the cwd-to-root dir chain ONCE and reuse them across the git2-based marker checks below
    // This gate then does one git2 discover and one git2 walk instead of one discover and walk per marker check
    // On a non-git dir each discover walks to the filesystem root, and Windows taxes every such syscall 10-100x
    // The `.claude` settings-compat check keeps its own cheap `.git`-existence walk on purpose; see that check
    // Checks run cheap to expensive and short-circuit on the first hit when `first_only`
    // Project instruction and skill roots come from the same `StartupProjectSources` the loaders read, so detection cannot drift from loading
    let project_sources = fuigo_agent::repo::StartupProjectSources::resolve(cwd);
    let chain = &project_sources.chain;
    let mut kinds: Vec<&'static str> = Vec::new();
    // Record a distinct kind; when `first_only`, return as soon as one is found
    macro_rules! hit {
        ($k:expr) => {{
            let k: &'static str = $k;
            if !kinds.contains(&k) {
                kinds.push(k);
            }
            if first_only {
                return kinds;
            }
        }};
    }

    // `.mcp.json` anywhere from repo root down to cwd.
    if !crate::project_config::find_mcp_json_files_in(&chain.dirs).is_empty() {
        hit!("mcp");
    }
    // Project `.fuigo/config.toml` markers: a non-empty `[mcp_servers]` table or `[plugins].paths` array, or a contributing `[permission]` section
    // `[plugins].paths` loads as auto-trusted ConfigPath plugins; `[permission]` allow/deny/ask rules auto-approve or block tools
    // A clone whose ONLY repo-local config is either must still be gated (else it resolves Trusted and the loader runs ungated)
    for path in crate::project_config::find_project_configs_in(&chain.dirs) {
        let Ok(root) = fuigo_config::load_project_config_file(&path) else {
            continue;
        };
        let has_mcp_servers = root
            .get("mcp_servers")
            .and_then(|v| v.as_table())
            .is_some_and(|t| !t.is_empty());
        let has_plugin_paths = root
            .get("plugins")
            .and_then(|v| v.get("paths"))
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty());
        let has_permission = root
            .get("permission")
            .is_some_and(config_toml_permission_contributes);
        if has_mcp_servers {
            hit!("mcp");
        }
        if has_plugin_paths {
            hit!("plugins");
        }
        if has_permission {
            hit!("permission");
        }
    }
    // Project `.fuigo/lsp.json`.
    if cwd.join(".fuigo").join("lsp.json").is_file() {
        hit!("lsp");
    }
    // Project `.cursor/mcp.json`: vendor MCP loading is default-on and tagged `Project`, so a repo shipping ONLY this file must still be gated
    // File presence is enough
    if cwd.join(".cursor").join("mcp.json").is_file() {
        hit!("mcp");
    }
    // Project `.envrc` is auto-sourced in a bash subshell when `direnv` isn't installed (direct code-exec), so an `.envrc`-only clone must be gated
    // The loader reads `<cwd>/.envrc` directly (NOT a git-root walk), so probe at cwd to match exactly what gets executed
    if cwd.join(".envrc").is_file() {
        hit!("envrc");
    }
    // Hook loading reads project `.claude/settings.json` and `settings.local.json` at the git root only
    // The ENV and permission loaders walk EVERY dir from cwd to the repo root (`collect_project_claude_paths`)
    // Detect along the SAME walk via the shared reader, else a `.claude` `env` in a subdir (injected into every spawned subprocess) loads ungated
    // Keeps its own `.git`-existence walk (NOT the git2 chain) so detection stays identical to the loader, which bounds on a bare/empty `.git` too
    if crate::permission::claude_settings::project_claude_settings_present(cwd) {
        hit!("claude");
    }
    // Other project HOOK sources are resolved from the git worktree root only (the chain's `git_root`), NOT cwd
    // Hook discovery resolves from the same root via `workspace_key`, so root-level hooks are gated even when launched from a subdir
    // A repo-local hook file/dir is repo-controlled code-exec that must be gated
    // Otherwise a hooks-only clone (e.g. `.fuigo/hooks/evil.json`) would resolve trusted and run ungated.
    // Presence mirrors discovery's "something to gate" check
    let hook_root = chain.git_root.as_deref().unwrap_or(cwd);
    if path_present_or_uncertain(&hook_root.join(".fuigo").join("hooks"))
        || path_present_or_uncertain(&hook_root.join(".cursor").join("hooks.json"))
    {
        hit!("hooks");
    }
    // Project PLUGIN dirs: project-scoped plugins fall under folder-trust too, so a repo-local plugin dir is repo-controlled code-exec (hooks/MCP)
    // Else a plugin clone (e.g. `.fuigo/plugins/evil/`, even one in a subdir launched via `cd sub && fuigo`) would resolve trusted and run ungated.
    // Uses the shared cwd-to-git-root walk so detection matches exactly what `discover_plugins` scans for Project scope, erring on the secure side
    if !fuigo_agent::plugins::project_plugin_dirs_in(&chain.dirs).is_empty() {
        hit!("plugins");
    }
    // Project AGENT dirs (`.fuigo/agents` / `.claude/agents`): an agents-only clone must still be gated
    // A project agent definition can carry an inline `hooks:` block (repo-controlled code-exec) and can shadow a built-in subagent by name
    // Uses the shared cwd-to-git-root walk so detection can't drift from agent discovery (same pattern as the plugin check above)
    if !fuigo_agent::discovery::project_agent_dirs_in(&chain.dirs).is_empty() {
        hit!("agents");
    }
    // Presence matches exact-cwd discovery without parsing repository content.
    let fuigo = cwd.join(".fuigo");
    if directory_present_or_uncertain(&fuigo.join("roles")) {
        hit!("roles");
    }
    if directory_present_or_uncertain(&fuigo.join("personas")) {
        hit!("personas");
    }
    if directory_present_or_uncertain(&hook_root.join(".fuigo").join("workflows")) {
        hit!("workflows");
    }
    // A project `.fuigo/tool-guidance.toml` rewrites tool descriptions the model sees, so it must gate like instructions
    if chain.dirs.iter().any(|d| {
        path_present_or_uncertain(&d.join(".fuigo").join(crate::tool_guidance::FILE_NAME))
    }) {
        hit!("tool_guidance");
    }
    // Project instructions (AGENTS.md / CLAUDE.md / rules dirs) reach the model as agent instructions, so an instructions-only clone must gate too
    if fuigo_agent::prompt::agents_md::has_project_instruction_markers_in(
        project_sources.instruction_dirs(),
    ) {
        hit!("instructions");
    }
    // Project skill/command roots, even empty ones, likewise feed the model
    if fuigo_agent::prompt::skills::has_project_skill_dirs_in(project_sources.skill_dirs()) {
        hit!("skills");
    }
    // `~/.claude.json` `projects.<cwd>.mcpServers`.
    if claude_project_mcp_present(cwd) {
        hit!("mcp");
    }
    kinds
}

/// Display names under `~/.claude.json projects.<cwd>.mcpServers`, or `None` when the file/entry is absent or the object is empty.
/// Both [`claude_project_mcp_present`] and the shell's `project_scoped_mcp_names` derive from this one reader, so they never drift.
pub fn claude_project_mcp_names(cwd: &Path) -> Option<Vec<String>> {
    let home = fuigo_dirs::home_dir()?;
    let content = std::fs::read_to_string(home.join(".claude.json")).ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&content).ok()?;
    let cwd_key = cwd.to_string_lossy();
    let names: Vec<String> = value
        .get("projects")
        .and_then(|p| p.get(cwd_key.as_ref()))
        .and_then(|proj| proj.get("mcpServers"))
        .and_then(|m| m.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    (!names.is_empty()).then_some(names)
}

fn claude_project_mcp_present(cwd: &Path) -> bool {
    claude_project_mcp_names(cwd).is_some()
}

fn is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// MVP trust prompt: a plain stderr warning and a stdin y/N read.
/// Defaults to NO on empty input, EOF, or any non-yes answer.
/// Deliberately minimal (no ACP modal).
pub fn prompt_for_trust(key: &Path) -> bool {
    use std::io::BufRead;

    let mut err = std::io::stderr();
    write_trust_prompt(&mut err, key);

    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => false,
        Ok(_) => matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
    }
}

/// The prompt text. The folder path is the one untrusted thing in it (a cloned repo picks its own directory name).
fn write_trust_prompt(err: &mut impl std::io::Write, key: &Path) {
    let _ = writeln!(err);
    let _ = writeln!(err, "Do you trust the files in this folder?");
    // A hidden or control character in the name shows as one U+FFFD, so the line cannot be made to read like another prompt
    let folder = key.display().to_string();
    let _ = writeln!(err, "  {}", fuigo_tty_utils::replace_unsafe_display(&folder, '\u{fffd}'));
    let _ = writeln!(err, "{TRUST_QUESTION_BODY}");
    let _ = write!(err, "Trust this folder? [y/N] ");
    let _ = err.flush();
}

/// The explanation under the folder-trust question (TUI, stderr and ACP share it).
pub const TRUST_QUESTION_BODY: &str = "Trusting it lets Fuigo use this folder's own settings (MCP and LSP servers, hooks, \
.envrc, permission rules, instructions, skills) and run shell commands here without asking each time. A folder's \
files can make those run code, so trust only folders whose contents you would run yourself.";

/// The one-time re-ask for a folder trusted before 1.0.35 (settings only).
pub const TRUST_UPGRADE_BODY: &str = "Fuigo's folder trust now also covers shell commands. You trusted this folder's \
settings before; trust now means its settings load AND commands run here without asking each time.";

/// What "No" means, in every surface that asks.
pub const TRUST_DECLINE_LABEL: &str =
    "No: don't load its settings, and ask unless your approval or grant covers the command (reading, searching and editing still work)";

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// P181 (sweep): the trust prompt is a permission prompt written raw to stderr, and the folder path in it is chosen
    /// by whoever made the repo, so it cannot carry an escape sequence, a line separator or a hidden character.
    #[test]
    fn trust_prompt_shows_a_hostile_folder_name_without_control_or_hidden_characters() {
        let key = Path::new("/w/evil\u{1b}]0;owned\u{7}\u{202e}dir\u{2028}Trust? [y/N] y\u{e0041}");
        let mut out = Vec::new();
        write_trust_prompt(&mut out, key);
        let text = String::from_utf8(out).unwrap();
        assert!(
            !text.chars().any(|c| c != '\n' && (c.is_control() || fuigo_tty_utils::is_unsafe_display_char(c))),
            "{text:?}"
        );
        assert!(text.contains("\n  /w/evil\u{fffd}]0;owned\u{fffd}\u{fffd}dir\u{fffd}Trust? [y/N] y\u{fffd}\n"), "{text:?}");
        assert!(text.ends_with("[y/N] "), "{text:?}");
    }

    /// A `git init`'d temp dir, so repo discovery is bounded to it instead of any ancestor repo the system temp dir lives in.
    /// `find_mcp_json_files` / `find_project_configs` discover the enclosing repo and walk to its root.
    fn repo_tmp() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        tmp
    }

    #[test]
    fn repo_configs_present_false_when_empty() {
        let tmp = repo_tmp();
        assert!(!repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_configs_present_detects_mcp_json() {
        let tmp = repo_tmp();
        std::fs::write(tmp.path().join(".mcp.json"), "{}").unwrap();
        assert!(repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_configs_present_detects_fuigo_config_mcp_servers() {
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(fuigo.join("config.toml"), "[mcp_servers.x]\ncommand=\"y\"\n").unwrap();
        assert!(repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_configs_present_detects_fuigo_lsp_json() {
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(fuigo.join("lsp.json"), "{}").unwrap();
        assert!(repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_configs_present_detects_cursor_mcp_json() {
        let tmp = repo_tmp();
        let cursor = tmp.path().join(".cursor");
        std::fs::create_dir_all(&cursor).unwrap();
        std::fs::write(cursor.join("mcp.json"), "{}").unwrap();
        assert!(repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_configs_present_detects_envrc() {
        // An `.envrc`-only clone is auto-sourced in a bash subshell (direct RCE)
        // It must resolve untrusted even though it has no MCP/LSP/hook configs
        let tmp = repo_tmp();
        std::fs::write(tmp.path().join(".envrc"), "export FOO=bar\n").unwrap();
        assert!(repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_configs_present_detects_tool_guidance_file_from_subdir() {
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo")).unwrap();
        std::fs::write(tmp.path().join(".fuigo").join("tool-guidance.toml"), "").unwrap();
        let subdir = tmp.path().join("crates").join("inner");
        std::fs::create_dir_all(&subdir).unwrap();
        assert_eq!(repo_config_kinds(&subdir), vec!["tool_guidance"]);
    }

    #[test]
    fn repo_configs_present_detects_agents_md_from_subdir() {
        let tmp = repo_tmp();
        std::fs::write(tmp.path().join("AGENTS.md"), "# project\n").unwrap();
        let subdir = tmp.path().join("crates").join("inner");
        std::fs::create_dir_all(&subdir).unwrap();
        assert_eq!(repo_config_kinds(&subdir), vec!["instructions"]);
    }

    #[test]
    fn repo_configs_present_detects_project_rules_from_subdir() {
        let tmp = repo_tmp();
        let rules = tmp.path().join(".fuigo").join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(rules.join("style.md"), "# style\n").unwrap();
        let subdir = tmp.path().join("crates").join("inner");
        std::fs::create_dir_all(&subdir).unwrap();
        assert_eq!(repo_config_kinds(&subdir), vec!["instructions"]);
    }

    #[test]
    fn repo_configs_present_detects_empty_skill_roots_only_in_project_chain() {
        for config in [".fuigo", ".agents", ".claude", ".cursor"] {
            for leaf in ["skills", "commands"] {
                let tmp = repo_tmp();
                let repo = tmp.path().join("repo");
                std::fs::create_dir_all(&repo).unwrap();
                git2::Repository::init(&repo).unwrap();
                let outside = tmp.path().join(config).join(leaf);
                std::fs::create_dir_all(outside).unwrap();
                let subdir = repo.join("nested");
                std::fs::create_dir_all(&subdir).unwrap();
                let cwd = subdir.join("inner");
                std::fs::create_dir_all(cwd.join("child").join(config).join(leaf)).unwrap();
                assert!(repo_config_kinds(&cwd).is_empty());

                for dir in [&repo, &subdir, &cwd] {
                    let config_dir = dir.join(config);
                    std::fs::create_dir_all(&config_dir).unwrap();
                    assert!(repo_config_kinds(&cwd).is_empty());
                    let marker = config_dir.join(leaf);
                    std::fs::write(&marker, "not a directory").unwrap();
                    assert!(repo_config_kinds(&cwd).is_empty());
                    std::fs::remove_file(&marker).unwrap();
                    std::fs::create_dir(&marker).unwrap();
                    assert_eq!(repo_config_kinds(&cwd), vec!["skills"]);
                    std::fs::remove_dir(&marker).unwrap();
                }
            }
        }
    }

    #[test]
    fn repo_configs_present_detects_project_agents() {
        // A `.fuigo/agents`-only clone must be gated
        // A project agent definition can carry an inline `hooks:` block (code-exec) and can shadow a built-in subagent by name
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo").join("agents")).unwrap();
        assert!(repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_configs_present_detects_claude_agents() {
        // `.claude/agents` is the vendor-compat project agent dir; same gate.
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".claude").join("agents")).unwrap();
        assert!(repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_configs_present_detects_project_agents_from_subdir() {
        // Agents live at the git root but the session is launched from a subdir
        // Detection walks from cwd to the git root exactly like agent discovery, so it must still fire (a cwd-only probe would miss it)
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo").join("agents")).unwrap();
        let subdir = tmp.path().join("crates").join("inner");
        std::fs::create_dir_all(&subdir).unwrap();
        assert!(repo_configs_present(&subdir));
    }

    #[test]
    fn repo_configs_present_detects_project_roles() {
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo").join("roles")).unwrap();

        assert!(repo_configs_present(tmp.path()));
        assert!(repo_config_kinds(tmp.path()).contains(&"roles"));
    }

    #[test]
    fn repo_configs_present_detects_project_personas() {
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo").join("personas")).unwrap();

        assert!(repo_configs_present(tmp.path()));
        assert!(repo_config_kinds(tmp.path()).contains(&"personas"));
    }

    #[test]
    fn project_subagent_marker_regular_file_is_absent() {
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(fuigo.join("roles"), "not a directory").unwrap();
        assert!(!repo_configs_present(tmp.path()));
    }

    #[test]
    fn project_subagent_marker_at_repo_root_is_absent_from_subdir() {
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo/roles")).unwrap();
        let subdir = tmp.path().join("nested");
        std::fs::create_dir_all(&subdir).unwrap();
        assert!(!repo_configs_present(&subdir));
    }

    #[cfg(unix)]
    #[test]
    fn project_subagent_marker_symlink_to_directory_is_present() {
        let tmp = repo_tmp();
        let target = tmp.path().join("target-roles");
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(&fuigo).unwrap();
        std::os::unix::fs::symlink(&target, fuigo.join("roles")).unwrap();
        assert!(repo_configs_present(tmp.path()));
    }

    #[cfg(unix)]
    #[test]
    fn dangling_project_subagent_marker_is_absent() {
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::os::unix::fs::symlink("missing", fuigo.join("personas")).unwrap();
        assert!(!repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_configs_present_detects_project_workflows_from_subdir() {
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo").join("workflows")).unwrap();
        let subdir = tmp.path().join("crates").join("inner");
        std::fs::create_dir_all(&subdir).unwrap();
        assert!(repo_configs_present(&subdir));
        assert!(repo_config_kinds(&subdir).contains(&"workflows"));
    }

    #[test]
    fn repo_configs_present_detects_claude_settings_from_subdir() {
        // A `.claude/settings.json` `env` in a SUBDIR (no other repo config), launched from that subdir, must be detected
        // The env loader walks from cwd to the repo root, so detection walks the same path (a git-root-only probe would miss it)
        let tmp = repo_tmp();
        let subdir = tmp.path().join("crates").join("inner");
        let claude = subdir.join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        std::fs::write(claude.join("settings.json"), r#"{"env":{"X":"1"}}"#).unwrap();
        assert!(repo_configs_present(&subdir));
    }

    #[test]
    fn repo_configs_present_detects_project_hooks() {
        // A hooks-only repo (no MCP/LSP configs) must still be gated, so its project hooks don't run ungated when the folder is untrusted
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo").join("hooks")).unwrap();
        assert!(repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_configs_present_detects_project_hooks_file() {
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(fuigo.join("hooks"), "{}").unwrap();

        assert!(repo_configs_present(tmp.path()));
        assert!(repo_config_kinds(tmp.path()).contains(&"hooks"));
    }

    #[cfg(unix)]
    #[test]
    fn repo_configs_present_detects_dangling_project_hooks_symlink() {
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::os::unix::fs::symlink("missing-hooks", fuigo.join("hooks")).unwrap();

        assert!(repo_configs_present(tmp.path()));
        assert!(repo_config_kinds(tmp.path()).contains(&"hooks"));
    }

    /// P166/S13 (upstream 75810042): presence is type-agnostic, so a directory at a settings path gates too.
    #[test]
    fn repo_configs_present_detects_claude_settings_json_directory() {
        for name in ["settings.json", "settings.local.json"] {
            let tmp = repo_tmp();
            std::fs::create_dir_all(tmp.path().join(".claude").join(name)).unwrap();
            assert!(repo_configs_present(tmp.path()), "{name}");
            assert!(repo_config_kinds(tmp.path()).contains(&"claude"), "{name}");
        }
    }

    /// P166/S13: a directory at `.cursor/hooks.json` gates.
    #[test]
    fn repo_configs_present_detects_cursor_hooks_json_directory() {
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".cursor").join("hooks.json")).unwrap();
        assert!(repo_configs_present(tmp.path()));
        assert!(repo_config_kinds(tmp.path()).contains(&"hooks"));
    }

    /// P166/S13: a dangling symlink at `.cursor/hooks.json` or a `.claude` settings path is present, not absent.
    #[cfg(unix)]
    #[test]
    fn repo_configs_present_detects_dangling_vendor_settings_symlinks() {
        let tmp = repo_tmp();
        let cursor = tmp.path().join(".cursor");
        std::fs::create_dir_all(&cursor).unwrap();
        std::os::unix::fs::symlink("missing-hooks.json", cursor.join("hooks.json")).unwrap();
        assert!(repo_config_kinds(tmp.path()).contains(&"hooks"));

        for name in ["settings.json", "settings.local.json"] {
            let tmp = repo_tmp();
            let claude = tmp.path().join(".claude");
            std::fs::create_dir_all(&claude).unwrap();
            std::os::unix::fs::symlink("missing-settings.json", claude.join(name)).unwrap();
            assert!(repo_configs_present(tmp.path()), "{name}");
            assert!(repo_config_kinds(tmp.path()).contains(&"claude"), "{name}");
        }
    }

    #[test]
    fn repo_configs_present_detects_project_hooks_from_subdir() {
        // Hooks live at the git root but the session is launched from a subdir
        // The gate must still fire because discovery resolves hooks from the root
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo").join("hooks")).unwrap();
        let subdir = tmp.path().join("crates").join("inner");
        std::fs::create_dir_all(&subdir).unwrap();
        assert!(repo_configs_present(&subdir));
    }

    #[test]
    fn repo_configs_present_detects_project_plugins() {
        // A plugin-only repo (no MCP/LSP/hooks configs) must still be gated
        // Otherwise a project plugin's hooks/MCP would run ungated when the folder is untrusted
        let tmp = repo_tmp();
        std::fs::create_dir_all(tmp.path().join(".fuigo").join("plugins").join("x")).unwrap();
        assert!(repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_configs_present_detects_project_plugins_in_subdir() {
        // A plugin under a subdir (root otherwise clean), launched from that subdir, must still be gated
        // Detection walks from cwd to the git root exactly like discover_plugins, so a subdir-only plugin is not a fail-open hole
        let tmp = repo_tmp();
        let subdir = tmp.path().join("packages").join("foo");
        std::fs::create_dir_all(subdir.join(".fuigo").join("plugins").join("evil")).unwrap();
        assert!(repo_configs_present(&subdir));
    }

    #[test]
    fn repo_configs_present_false_for_empty_mcp_servers_table() {
        // A project config whose `[mcp_servers]` table is empty has nothing to gate, so it must not trip the gate
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(fuigo.join("config.toml"), "[mcp_servers]\n").unwrap();
        assert!(!repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_configs_present_detects_fuigo_config_plugins_paths() {
        // A repo whose ONLY repo-local config is `[plugins].paths` (no plugin dir, no MCP/LSP/hooks) must still be gated
        // Those paths load as auto-trusted ConfigPath plugins, so an ungated clone is a live RCE
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(fuigo.join("config.toml"), "[plugins]\npaths = [\"./x\"]\n").unwrap();
        assert!(repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_configs_present_false_for_empty_plugins_paths() {
        // An empty `[plugins].paths` (or a `[plugins]` table without `paths`) contributes no plugin code-exec, so it must not trip the gate
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(fuigo.join("config.toml"), "[plugins]\npaths = []\n").unwrap();
        assert!(!repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_configs_present_detects_fuigo_config_permission() {
        // A repo whose ONLY repo-local config is a contributing `[permission]` section (no MCP/plugins/hooks) must still be gated
        // Those allow rules auto-approve tool calls, so an ungated clone loads the attacker's policy
        // Also covers subdir launch (the cwd-to-git-root walk)
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(
            fuigo.join("config.toml"),
            "[permission]\nallow = [\"Bash(*)\"]\n",
        )
        .unwrap();
        assert!(repo_configs_present(tmp.path()));
        assert!(
            repo_config_kinds(tmp.path()).contains(&"permission"),
            "permission-only repo must report the permission kind"
        );
        let subdir = tmp.path().join("crates").join("inner");
        std::fs::create_dir_all(&subdir).unwrap();
        assert!(
            repo_configs_present(&subdir),
            "permission-only config at git root must gate subdir launches"
        );
    }

    #[test]
    fn repo_configs_present_false_for_empty_permission() {
        // Empty allow/deny/ask arrays contribute no rules, so they must not trip the gate (mirrors empty `[mcp_servers]` / empty `[plugins].paths`)
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(
            fuigo.join("config.toml"),
            "[permission]\nallow = []\ndeny = []\n",
        )
        .unwrap();
        assert!(!repo_configs_present(tmp.path()));
    }

    #[test]
    fn repo_config_kinds_matches_gate_and_reports_all_kinds() {
        // Single-source guard: `repo_config_kinds` must agree with the gate (`repo_configs_present == !repo_config_kinds(..).is_empty()`)
        // It must also report `plugins` via `[plugins].paths`, `claude` via `.claude/settings.json`, and `agents` via `.fuigo/agents`
        // Even a SUBDIR launch must report them (the cwd-to-git-root walk that `first_only` shares)
        // Guards against silent drift between the two
        let tmp = repo_tmp();
        let fuigo = tmp.path().join(".fuigo");
        std::fs::create_dir_all(fuigo.join("agents")).unwrap();
        std::fs::write(fuigo.join("config.toml"), "[plugins]\npaths = [\"./x\"]\n").unwrap();
        let claude = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        std::fs::write(claude.join("settings.json"), r#"{"env":{"X":"1"}}"#).unwrap();
        // Launch from a subdir: the walk must still find the root-level markers.
        let subdir = tmp.path().join("crates").join("inner");
        std::fs::create_dir_all(&subdir).unwrap();

        let kinds = repo_config_kinds(&subdir);
        for expected in ["plugins", "claude", "agents"] {
            assert!(
                kinds.contains(&expected),
                "repo_config_kinds missing {expected:?} (subdir launch); got {kinds:?}"
            );
        }
        // Gate and kinds must agree: a configured repo and an empty one
        assert_eq!(
            repo_configs_present(&subdir),
            !repo_config_kinds(&subdir).is_empty(),
            "gate must equal !kinds.is_empty() for a configured repo"
        );
        let empty = repo_tmp();
        assert!(!repo_configs_present(empty.path()));
        assert!(repo_config_kinds(empty.path()).is_empty());
        assert_eq!(
            repo_configs_present(empty.path()),
            !repo_config_kinds(empty.path()).is_empty(),
            "gate must equal !kinds.is_empty() for an empty repo"
        );
    }

    // FUIGO_HOME isolation mirrored from this crate's `permission::claude_compat` tests
    // The workspace crate has no `serial_test` or `fuigo-test-support` dev-dep
    // nextest runs each test in its own process; `ENV_LOCK` serializes the rare in-process `cargo test` thread
    // `EnvVarGuard` restores the prior value on drop so a panic can't leak state
    // The crate-shared lock also serializes against other env-mutating test modules (e.g. `trust`, `worktree`) under `cargo test --lib`.
    use crate::ENV_TEST_LOCK as ENV_LOCK;

    // The crate-shared env-var guard (one definition in `lib.rs`), aliased to the local `EnvVarGuard` name
    use crate::TestEnvGuard as EnvVarGuard;

    /// An isolated release-like world: own process (env is process-global), the env lock, a fresh absolute
    /// `FUIGO_HOME`, `FUIGO_TEST_VERSION` set (so the gate is live) and the switch unset.
    struct World {
        home: tempfile::TempDir,
        _guards: Vec<EnvVarGuard>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    fn world() -> Option<World> {
        if fuigo_test_support::env::rerun_in_own_process() {
            return None;
        }
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let guards = vec![
            EnvVarGuard::set("FUIGO_HOME", home.path()),
            EnvVarGuard::set(fuigo_version::TEST_VERSION_ENV, Path::new("0.0.0-sim")),
            EnvVarGuard::unset("FUIGO_FOLDER_TRUST"),
        ];
        Some(World { home, _guards: guards, _lock: lock })
    }

    impl World {
        fn config(&self, toml: &str) {
            std::fs::write(self.home.path().join(fuigo_config::USER_CONFIG_FILENAME), toml).unwrap();
        }
    }

    fn key_of(dir: &Path) -> PathBuf {
        trust_key(dir).expect("a recordable folder")
    }

    /// T6: an undecided folder (git or not) is asked when the caller can ask, and untrusted otherwise; there is no
    /// "no project settings, so trusted" exemption any more.
    #[test]
    fn t6_undecided_folder_prompts_or_is_untrusted() {
        let Some(_w) = world() else { return };
        let plain = tempfile::tempdir().unwrap();
        let repo = repo_tmp();
        for dir in [plain.path(), repo.path()] {
            assert_eq!(decide(dir, true), TrustDecision::Prompt(PromptReason::New), "{}", dir.display());
            assert!(matches!(decide(dir, false), TrustDecision::Untrusted(UntrustedReason::Undecided(_))));
        }
    }

    /// T12: a client that cannot ask (ACP without the v2 capability, headless) never grants, but a saved "yes"
    /// still holds for it; an undecided folder stays untrusted and its notice names the setting that trusts it.
    #[test]
    fn t12_a_client_that_cannot_ask_honours_saved_trust_and_grants_nothing() {
        let Some(_w) = world() else { return };
        let repo = repo_tmp();
        let TrustDecision::Untrusted(reason) = decide(repo.path(), false) else {
            panic!("an undecided folder is untrusted for a client that cannot ask");
        };
        let notice = untrusted_session_notice(&reason);
        assert!(notice.contains("trusted_folders"), "{notice}");
        assert!(!decide(repo.path(), false).is_trusted(), "asking without an answer grants nothing");
        assert!(grant_folder_trust(repo.path()).dismisses_gate());
        assert_eq!(decide(repo.path(), false), TrustDecision::Trusted);
    }

    /// T9: at home and root the notice says the folder can't be trusted, not how to trust it.
    #[test]
    fn t9_home_and_root_notice_says_they_are_never_trusted() {
        let Some(_w) = world() else { return };
        let TrustDecision::Untrusted(reason) = decide(Path::new("/"), false) else {
            panic!("root is untrusted");
        };
        assert!(reason.unrecordable());
        let notice = untrusted_session_notice(&reason);
        assert!(!notice.contains("trusted_folders ="), "{notice}");
    }

    /// T6: a grant trusts the folder (settings and commands) and its subfolders in the same repository.
    #[test]
    fn t6_grant_trusts_repo_and_its_subfolders() {
        let Some(_w) = world() else { return };
        let repo = repo_tmp();
        let sub = repo.path().join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        assert!(grant_folder_trust(&sub).dismisses_gate());
        assert_eq!(decide(repo.path(), false), TrustDecision::Trusted);
        assert_eq!(decide(&sub, false), TrustDecision::Trusted);
        let _real = TestFolderTrust::real();
        assert!(dir_trust(&sub).is_trusted());
    }

    /// T6: a record from before 1.0.35 (consent 0) is asked once more (Upgrade), untrusted until then.
    #[test]
    fn t6_legacy_record_is_reasked_once() {
        let Some(_w) = world() else { return };
        let repo = repo_tmp();
        let key = key_of(repo.path());
        TrustStore::load().set_trusted_legacy(&key).unwrap();
        assert_eq!(decide(repo.path(), true), TrustDecision::Prompt(PromptReason::Upgrade));
        assert!(matches!(decide(repo.path(), false), TrustDecision::Untrusted(UntrustedReason::Legacy(_))));
        assert!(grant_folder_trust_key(&key).dismisses_gate());
        assert_eq!(decide(repo.path(), true), TrustDecision::Trusted);
    }

    /// T7 (item 2): a nested repository (vendored clone) keeps its own key: the parent's grant does not cover it,
    /// and a more specific "no" beats an ancestor's "yes".
    #[test]
    fn t7_nested_repo_keeps_own_key_and_child_no_wins() {
        let Some(_w) = world() else { return };
        let parent = repo_tmp();
        let nested = parent.path().join("vendor/lib");
        std::fs::create_dir_all(&nested).unwrap();
        git2::Repository::init(&nested).unwrap();
        assert!(grant_folder_trust(parent.path()).dismisses_gate());
        assert_eq!(decide(parent.path(), false), TrustDecision::Trusted);
        assert!(!decide(&nested, false).is_trusted(), "an ancestor's grant must not cover a nested repository");
        // A plain subfolder that the user declined explicitly beats the repository's "yes" for anything it covers.
        let mut store = TrustStore::load();
        store.set_untrusted(&key_of(&nested)).unwrap();
        assert!(matches!(decide(&nested, false), TrustDecision::Untrusted(UntrustedReason::Declined(_))));
    }

    /// T7: home and the filesystem root are never trusted or asked, and a grant there is refused.
    #[test]
    fn t7_root_is_untrustable() {
        let Some(_w) = world() else { return };
        let root = Path::new("/");
        assert!(matches!(decide(root, true), TrustDecision::Untrusted(r) if r.unrecordable()));
        assert!(matches!(
            grant_folder_trust(root),
            GrantOutcome::Refused { reason: GrantRefuse::UnsafeRoot }
        ));
    }

    /// T7: `[folder_trust] trusted_folders` in the user's own config trusts a folder (the headless path); a stored
    /// "no" beats it, so `/untrust` always revokes.
    #[test]
    fn t7_config_list_trusts_and_stored_no_beats_it() {
        let Some(w) = world() else { return };
        let repo = repo_tmp();
        let key = key_of(repo.path());
        w.config(&format!("[folder_trust]\ntrusted_folders = [{:?}]\n", key.display().to_string()));
        assert_eq!(decide(repo.path(), false), TrustDecision::Trusted);
        let RevokeOutcome::Revoked { was_trusted, saved, .. } = revoke_folder_trust_store(repo.path()) else {
            panic!("a recordable folder is revocable");
        };
        assert!(was_trusted);
        saved.expect("saved");
        assert!(matches!(decide(repo.path(), true), TrustDecision::Untrusted(UntrustedReason::Declined(_))));
    }

    /// T7 (item 6): a "no" in this process beats the store and the config list even when it could not be saved.
    #[test]
    fn t7_unsaved_process_decline_beats_store() {
        let Some(w) = world() else { return };
        let repo = repo_tmp();
        let key = key_of(repo.path());
        assert!(grant_folder_trust_key(&key).dismisses_gate());
        // The store can no longer be written: its lock path is squatted by a directory.
        let store_path = w.home.path().join(crate::trust::TRUST_FILE_NAME);
        let lock = store_path.with_extension("toml.lock");
        let _ = std::fs::remove_file(&lock);
        std::fs::create_dir_all(&lock).unwrap();
        assert!(decline_folder_trust_key(&key).is_err(), "the 'no' could not be saved");
        assert!(matches!(decide(repo.path(), true), TrustDecision::Untrusted(UntrustedReason::Declined(_))));
        // A later "yes" lifts it again (only once it is saved).
        std::fs::remove_dir(store_path.with_extension("toml.lock")).unwrap();
        assert!(grant_folder_trust_key(&key).dismisses_gate());
        assert_eq!(decide(repo.path(), false), TrustDecision::Trusted);
    }

    /// T7: a "yes" that could not be saved leaves the folder untrusted (no session-only grant).
    #[test]
    fn t7_unsaved_grant_stays_untrusted() {
        let Some(w) = world() else { return };
        let repo = repo_tmp();
        let key = key_of(repo.path());
        let store_path = w.home.path().join(crate::trust::TRUST_FILE_NAME);
        std::fs::create_dir_all(store_path.with_extension("toml.lock")).unwrap();
        let outcome = grant_folder_trust_key(&key);
        assert!(matches!(outcome, GrantOutcome::Granted { persist: PersistStatus::NotSaved { .. }, .. }));
        assert_eq!(outcome.resolution(), GrantResolution::Unrecorded);
        assert!(outcome.to_string().contains("stays untrusted"), "{outcome}");
        assert!(!decide(repo.path(), false).is_trusted());
    }

    /// T11 (item 4): a relative `FUIGO_HOME` reads no user-home trust input: nothing is trusted, not even a folder
    /// a store or config list in that relative directory names.
    #[test]
    fn t11_relative_home_trusts_nothing() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cwd = tempfile::tempdir().unwrap();
        let repo = repo_tmp();
        let key = key_of(repo.path());
        let rel = cwd.path().join("relhome");
        std::fs::create_dir_all(&rel).unwrap();
        std::fs::write(
            rel.join(fuigo_config::USER_CONFIG_FILENAME),
            format!("[folder_trust]\nenabled = false\ntrusted_folders = [{:?}]\n", key.display().to_string()),
        )
        .unwrap();
        std::env::set_current_dir(cwd.path()).unwrap();
        let _guards = [
            EnvVarGuard::set("FUIGO_HOME", Path::new("relhome")),
            EnvVarGuard::set(fuigo_version::TEST_VERSION_ENV, Path::new("0.0.0-sim")),
            EnvVarGuard::unset("FUIGO_FOLDER_TRUST"),
        ];
        assert!(fuigo_config::user_fuigo_home().is_none());
        assert!(matches!(decide(repo.path(), true), TrustDecision::Untrusted(UntrustedReason::Inputs)));
        assert!(trust_input_paths().is_empty());
    }

    /// The user's own switch turns folder trust off (with the warning); the remote kill switch is not read.
    #[test]
    fn switch_off_trusts_every_folder() {
        let Some(w) = world() else { return };
        let repo = repo_tmp();
        w.config("[folder_trust]\nenabled = false\n");
        assert_eq!(decide(repo.path(), false), TrustDecision::Trusted);
        assert!(folder_trust_disabled());
    }

    /// An unstamped local build is inert: every folder is trusted and grants are no-ops.
    #[test]
    fn local_build_is_inert() {
        let Some(_w) = world() else { return };
        let _unset = EnvVarGuard::unset(fuigo_version::TEST_VERSION_ENV);
        if option_env!("FUIGO_VERSION").is_some() {
            return;
        }
        let repo = repo_tmp();
        assert_eq!(decide(repo.path(), false), TrustDecision::Trusted);
        assert!(matches!(grant_folder_trust(repo.path()), GrantOutcome::Refused { reason: GrantRefuse::InertBuild }));
        assert!(matches!(revoke_folder_trust_store(repo.path()), RevokeOutcome::NotApplicable));
    }

    /// T7 (item 3): the trust inputs are protected by file identity: a hard link to the store (or the registry) is
    /// the store.
    #[test]
    fn t7_trust_input_identity_catches_hard_links() {
        let Some(w) = world() else { return };
        let repo = repo_tmp();
        assert!(grant_folder_trust(repo.path()).dismisses_gate());
        let store = w.home.path().join(crate::trust::TRUST_FILE_NAME);
        let elsewhere = tempfile::tempdir().unwrap();
        let link = elsewhere.path().join("innocent.toml");
        std::fs::hard_link(&store, &link).unwrap();
        let physical = dunce::canonicalize(&link).unwrap();
        assert!(is_trust_input(&dunce::canonicalize(&store).unwrap()));
        assert!(is_trust_input(&physical), "a hard link to the store is the store");
        let other = elsewhere.path().join("other.toml");
        std::fs::write(&other, "x").unwrap();
        assert!(!is_trust_input(&dunce::canonicalize(&other).unwrap()));
    }

    /// The command-side cache follows a grant made after a verdict was cached.
    #[test]
    fn dir_trust_cache_follows_grants_and_declines() {
        let Some(_w) = world() else { return };
        let _real = TestFolderTrust::real();
        let repo = repo_tmp();
        assert!(!dir_trust(repo.path()).is_trusted());
        assert!(grant_folder_trust(repo.path()).dismisses_gate());
        assert!(dir_trust(repo.path()).is_trusted());
        let _ = revoke_folder_trust_store(repo.path());
        assert!(!dir_trust(repo.path()).is_trusted());
        assert!(!command_trust([repo.path(), Path::new("/")]).is_trusted());
    }

    /// A main checkout with one commit and a linked worktree outside it: `(tempdir, main, worktree)`.
    pub(crate) fn main_with_outside_worktree() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        let main = root.join("main");
        std::fs::create_dir_all(&main).unwrap();
        let repo = git2::Repository::init(&main).unwrap();
        let sig = git2::Signature::now("t", "t@t").unwrap();
        let tree = {
            let mut idx = repo.index().unwrap();
            let oid = idx.write_tree().unwrap();
            repo.find_tree(oid).unwrap()
        };
        repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[]).unwrap();
        let wt = root.join("wt");
        repo.worktree("wt", &wt, None).unwrap();
        (dir, main, wt)
    }

    /// Register `wt` (a standalone clone) as a Fuigo-managed worktree of `source` in `home`'s registry.
    pub(crate) fn register_managed_worktree(home: &Path, wt: &Path, source: &Path) {
        use fuigo_fast_worktree::{WorktreeDb, WorktreeKind, WorktreeRecord, WorktreeStatus};
        let db = WorktreeDb::open(home).unwrap();
        db.register(&WorktreeRecord {
            id: "wt".to_string(),
            path: wt.to_path_buf(),
            source_repo: source.to_path_buf(),
            repo_name: "repo".to_string(),
            kind: WorktreeKind::Session,
            creation_mode: "standalone".to_string(),
            git_ref: None,
            head_commit: None,
            session_id: None,
            creator_pid: None,
            created_at: 100,
            last_accessed_at: None,
            status: WorktreeStatus::Alive,
            metadata: None,
        })
        .unwrap();
    }

    /// u35 t2 (Fable H1, Astra 2): the main checkout's grant trusts its linked worktree outside it, for settings
    /// (`decide`) and commands (`dir_trust`, the command route), without a new question.
    #[test]
    fn t2_a_linked_worktree_of_a_granted_checkout_is_trusted() {
        let Some(_w) = world() else { return };
        let (_dir, main, wt) = main_with_outside_worktree();
        assert!(grant_folder_trust(&main).dismisses_gate());
        assert_eq!(decide(&wt, true), TrustDecision::Trusted, "no question in the worktree");
        assert_eq!(decide(&wt, false), TrustDecision::Trusted);
        let _real = TestFolderTrust::real();
        assert!(dir_trust(&wt).is_trusted());
        assert!(command_trust([wt.as_path()]).is_trusted());
    }

    /// u35 t2 (Fable H1): a `fuigo -w` managed worktree outside its source repository is trusted by the source's grant.
    #[test]
    fn t2_a_managed_worktree_of_a_granted_repository_is_trusted() {
        let Some(w) = world() else { return };
        let source = repo_tmp();
        let home = dunce::canonicalize(w.home.path()).unwrap();
        let wt = home.join("worktrees").join("repo").join("wt");
        std::fs::create_dir_all(&wt).unwrap();
        git2::Repository::init(&wt).unwrap();
        register_managed_worktree(&home, &wt, &dunce::canonicalize(source.path()).unwrap());
        assert!(grant_folder_trust(source.path()).dismisses_gate());
        assert_eq!(decide(&wt, true), TrustDecision::Trusted);
        let _real = TestFolderTrust::real();
        assert!(dir_trust(&wt).is_trusted());
        assert!(command_trust([wt.as_path()]).is_trusted());
    }

    /// u35 t2 (Astra 7): the test seam judges the physical folder only: a symlink inside a trusted folder that points
    /// into another folder is that other folder.
    #[cfg(unix)]
    #[test]
    fn t2_test_seam_judges_the_physical_folder() {
        let r = tempfile::tempdir().unwrap();
        let u = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(u.path(), r.path().join("l")).unwrap();
        let _only = TestFolderTrust::only(&[r.path()]);
        assert!(dir_trust(r.path()).is_trusted());
        assert!(!dir_trust(&r.path().join("l")).is_trusted(), "R/l is U");
        assert!(!dir_trust(&r.path().join("missing")).is_trusted(), "a folder that does not resolve is not trusted");
    }

    /// u35 t2 (Astra 3): a permission change on a trust input (the store made unreadable) changes the fingerprint,
    /// so no verdict cached before it is reused.
    #[cfg(unix)]
    #[test]
    fn t2_a_permission_change_on_a_trust_input_invalidates_the_cache() {
        use std::os::unix::fs::PermissionsExt;
        let Some(w) = world() else { return };
        let repo = repo_tmp();
        assert!(grant_folder_trust(repo.path()).dismisses_gate());
        let store = w.home.path().join(crate::trust::TRUST_FILE_NAME);
        let before = fingerprint();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o000)).unwrap();
        let after = fingerprint();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(before, after, "chmod must invalidate cached trust verdicts");
    }

    /// u35 t2 (Astra 6): a trust input that failed to load (a malformed user config) does not untrust a granted
    /// folder, but that verdict is not cached: it is decided again next time.
    #[test]
    fn t2_a_verdict_from_inputs_that_failed_to_load_is_not_cached() {
        let Some(w) = world() else { return };
        let repo = repo_tmp();
        assert!(grant_folder_trust(repo.path()).dismisses_gate());
        w.config("[folder_trust\nthis is not toml");
        let _real = TestFolderTrust::real();
        let canonical = dunce::canonicalize(repo.path()).unwrap();
        assert!(dir_trust(repo.path()).is_trusted(), "the store grant still counts");
        assert!(!DIR_CACHE.lock().contains_key(&canonical), "a verdict from failed inputs is never cached");
        w.config("");
        assert!(dir_trust(repo.path()).is_trusted());
        assert!(DIR_CACHE.lock().contains_key(&canonical), "a verdict from clean inputs is cached");
    }

    /// The real decision as the repository-tool judge, on every thread (`spawn_blocking` included): no test seam.
    fn real_repo_exec_judge(dir: &Path) -> bool {
        decide(dir, false) == TrustDecision::Trusted
    }

    struct NoNotifier;

    #[async_trait::async_trait]
    impl crate::worktree::WorktreeNotificationSender for NoNotifier {
        async fn send_worktree_status(&self, _progress: crate::worktree::WorktreeStatus) {}
    }

    /// `fuigo -w <label> [--ref <ref>]` with `[cli] worktree_type = "standalone"`: the workspace creation path, clean copy.
    fn create_standalone(source: &Path, label: &str, git_ref: Option<&str>) -> crate::worktree::WorktreeStatus {
        let req = crate::worktree::CreateWorktreeRequest {
            session_id: format!("t3-{label}"),
            source_path: source.to_string_lossy().into_owned(),
            worktree_path: None,
            copy_mode: crate::worktree::WorktreeCopyMode::Clean,
            git_ref: git_ref.map(str::to_string),
            copy_ignored_in_background: false,
            ignored_skip_patterns: vec![],
            worktree_type: Some(crate::worktree::WorktreeType::Standalone),
            label: Some(label.to_string()),
            grove_worktree: None,
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(crate::worktree::create_worktree_streaming(&req, &NoNotifier))
    }

    fn source_repo_with_main(dir: &Path) {
        use fuigo_test_utils::git::{git_commit_all, init_git_repo, run_git};
        init_git_repo(dir);
        std::fs::write(dir.join("tracked.txt"), "x").unwrap();
        git_commit_all(dir, "initial");
        run_git(dir, &["checkout", "-q", "-B", "main"]);
        run_git(dir, &["checkout", "-q", "-b", "side"]);
    }

    /// u35 t3 (Astra r2 H3): with a trusted source and standalone worktrees, clean creation and `--ref` creation run
    /// git in the new destination before the worktree database records it; under the real judge that git is covered by
    /// creation authority from the source, the worktree is created, it is trusted afterwards by its record, and the
    /// authority is gone. A failed creation withdraws the authority and removes the partial destination.
    #[test]
    fn t3_standalone_creation_from_a_trusted_source_runs_under_the_real_judge() {
        fuigo_test_utils::require_git!();
        let Some(w) = world() else { return };
        let source = tempfile::tempdir().unwrap();
        source_repo_with_main(source.path());
        assert!(grant_folder_trust(source.path()).dismisses_gate());
        fuigo_tty_utils::install_repo_exec_judge(real_repo_exec_judge);
        let base = dunce::canonicalize(w.home.path()).unwrap().join("worktrees");

        for (label, git_ref) in [("fresh", None), ("fresh-main", Some("main"))] {
            let status = create_standalone(source.path(), label, git_ref);
            let crate::worktree::WorktreeStatus::Created { worktree_path, .. } = status else {
                panic!("{label}: standalone creation from a trusted source failed: {status:?}");
            };
            let wt = PathBuf::from(&worktree_path);
            assert!(dunce::canonicalize(&wt).unwrap().starts_with(&base), "{label}: {worktree_path}");
            assert!(wt.join(".git").is_dir(), "{label}: standalone");
            assert!(wt.join("tracked.txt").is_file(), "{label}");
            assert_eq!(fuigo_tty_utils::worktree_creation_source(&wt), None, "{label}: authority withdrawn");
            assert!(real_repo_exec_judge(&wt), "{label}: trusted by its record afterwards");
        }

        let status = create_standalone(source.path(), "bad-ref", Some("no-such-ref"));
        assert!(matches!(status, crate::worktree::WorktreeStatus::Error { .. }), "{status:?}");
        let partial = std::fs::read_dir(&base)
            .unwrap()
            .flatten()
            .flat_map(|repo| std::fs::read_dir(repo.path()).into_iter().flatten().flatten())
            .map(|e| e.path())
            .find(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("bad-ref")));
        assert_eq!(partial, None, "a failed creation leaves no partial worktree");
    }

    /// u35 t3: an untrusted source repository still gets no standalone worktree (and nothing is created).
    #[test]
    fn t3_an_untrusted_source_gets_no_standalone_worktree() {
        fuigo_test_utils::require_git!();
        let Some(w) = world() else { return };
        let source = tempfile::tempdir().unwrap();
        source_repo_with_main(source.path());
        fuigo_tty_utils::install_repo_exec_judge(real_repo_exec_judge);
        for git_ref in [None, Some("main")] {
            let status = create_standalone(source.path(), "refused", git_ref);
            let crate::worktree::WorktreeStatus::Error { message, .. } = status else {
                panic!("an untrusted source must get no worktree: {status:?}");
            };
            assert!(message.contains("not a trusted folder"), "{message}");
        }
        let worktrees = w.home.path().join("worktrees");
        let made = std::fs::read_dir(&worktrees)
            .into_iter()
            .flatten()
            .flatten()
            .flat_map(|repo| std::fs::read_dir(repo.path()).into_iter().flatten().flatten())
            .count();
        assert_eq!(made, 0, "no worktree directory was created");
    }
}

