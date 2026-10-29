//! Launch permission policy (1.0.36 item a).
//!
//! A launcher sets `FUIGO_POLICY_PATH` to a TOML file that holds only `[permission]`, plus `FUIGO_POLICY_SHA256` with that
//! file's hash. A client can attach a second such file to one session with `_meta["fuigo/permissionPolicyPath"]` and
//! `_meta["fuigo/permissionPolicySha256"]`. Their rules join the owner's (deny > ask > allow); an `ask` from a launch
//! policy always reaches the client.
//!
//! The launcher's (or client's) hash is the authority, never the file: the first verified read of a file pins its rules
//! for the life of the process, and a later reference with a different hash is refused. With no policy set nothing here
//! runs: the store stays empty and every check is one atomic load.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use serde::Deserialize;
use sha2::Digest as _;

use crate::permission::rules::{find_first_unescaped, find_last_unescaped, parse_permission_rule, tool_name_to_filter};
use crate::permission::types::{PatternMode, PermissionRule, RequirementSource, RuleAction, ToolFilter};

/// The process policy file (absolute path).
pub const ENV_PATH: &str = "FUIGO_POLICY_PATH";
/// The process policy file's sha256 (64 hex digits), required with [`ENV_PATH`].
pub const ENV_SHA256: &str = "FUIGO_POLICY_SHA256";
/// Session `_meta` key naming a per-session policy file.
pub const META_PATH: &str = "fuigo/permissionPolicyPath";
/// Session `_meta` key carrying that file's sha256, required with [`META_PATH`].
pub const META_SHA256: &str = "fuigo/permissionPolicySha256";
/// Session response `_meta` key acknowledging the policy in force.
pub const META_ACK: &str = "fuigo/permissionPolicy";
/// Process exit code for a policy failure before ACP starts (sysexits `EX_CONFIG`).
pub const EXIT_CODE: i32 = 78;
/// Largest policy file read.
pub const MAX_BYTES: u64 = 256 * 1024;

/// One policy failure: written as a single JSON line on stderr (process) or as an ACP error's `data` (session).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub code: &'static str,
    pub path: String,
    pub line: Option<usize>,
    pub message: String,
}

impl PolicyError {
    pub fn new(code: &'static str, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self { code, path: path.into(), line: None, message: message.into() }
    }

    fn at(mut self, line: Option<usize>) -> Self {
        self.line = line;
        self
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "policy_error": self.code,
            "path": self.path,
            "line": self.line,
            "message": self.message,
        })
    }

    /// The single stderr line (no trailing newline).
    pub fn json_line(&self) -> String {
        self.to_json().to_string()
    }

    /// The session-level ACP error: invalid params (`-32602`) with this error as `data`.
    pub fn into_acp_error(self) -> agent_client_protocol::Error {
        agent_client_protocol::Error::invalid_params().data(self.to_json())
    }

    /// Print the stderr line and exit with [`EXIT_CODE`].
    #[allow(clippy::print_stderr)] // The documented contract: one JSON line on stderr before exit 78.
    pub fn exit(&self) -> ! {
        eprintln!("{}", self.json_line());
        std::process::exit(EXIT_CODE)
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} ({})", self.code, self.message, self.path)
    }
}

impl std::error::Error for PolicyError {}

/// Whether a policy came from the launcher's environment or a client's session `_meta`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchScope {
    Process,
    Session,
}

/// A verified, pinned policy file.
#[derive(Debug)]
pub struct LaunchPolicy {
    /// The path as given.
    pub path: PathBuf,
    /// Lowercase hex sha256 of exactly the bytes parsed.
    pub sha256: String,
    /// The pinned file, compared by identity so another name for it finds the pin.
    identity: Option<same_file::Handle>,
    /// The decoded rules (the snapshot; never re-read).
    pub rules: Vec<PermissionRule>,
}

impl LaunchPolicy {
    /// `(deny, ask, allow)` rule counts.
    pub fn counts(&self) -> (usize, usize, usize) {
        let count = |action| self.rules.iter().filter(|r| r.action == action).count();
        (count(RuleAction::Deny), count(RuleAction::Ask), count(RuleAction::Allow))
    }

    pub fn source(&self, scope: LaunchScope) -> RequirementSource {
        RequirementSource::LaunchPolicy {
            path: self.path.clone(),
            sha256: self.sha256.clone(),
            scope,
        }
    }

    /// Whether `path` names this pinned file (by identity; hard links and other names count).
    pub fn is_same_file(&self, path: &Path) -> bool {
        if path == self.path {
            return true;
        }
        let Some(identity) = &self.identity else { return false };
        let physical = dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        same_file::Handle::from_path(&physical).ok().as_ref() == Some(identity)
    }

    /// The binding key a session governed by this policy carries.
    pub fn binding(&self) -> PolicyBinding {
        PolicyBinding { path: self.path.to_string_lossy().into_owned(), sha256: self.sha256.clone() }
    }

    /// Build a policy without a file (tests).
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(path: &str, rules: Vec<PermissionRule>) -> Arc<Self> {
        Arc::new(Self { path: PathBuf::from(path), sha256: "0".repeat(64), identity: None, rules })
    }
}

/// `(path, sha256)` a governed session is bound to; also the marker written into the session record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct PolicyBinding {
    pub path: String,
    pub sha256: String,
}

// ═════════════════════════════════════════════════════════════════════════════
// Store: the process policy, the pins and the session bindings
// ═════════════════════════════════════════════════════════════════════════════

static PROCESS: OnceLock<Arc<LaunchPolicy>> = OnceLock::new();
static PINS: Mutex<Vec<Arc<LaunchPolicy>>> = Mutex::new(Vec::new());
/// Set on the first pin / binding, so the unset path never takes a lock.
static ANY_PINS: AtomicBool = AtomicBool::new(false);
static ANY_BINDINGS: AtomicBool = AtomicBool::new(false);
static BINDINGS: LazyLock<Mutex<HashMap<String, PolicyBinding>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// The process policy, when the launcher set one.
pub fn process() -> Option<&'static Arc<LaunchPolicy>> {
    PROCESS.get()
}

/// Whether this process runs under a launch policy.
pub fn has_process_policy() -> bool {
    PROCESS.get().is_some()
}

/// Whether a launch policy governs this call: the process has one, or the session carries one.
pub fn governs(session_flag: bool) -> bool {
    session_flag || has_process_policy()
}

/// Read `FUIGO_POLICY_PATH` / `FUIGO_POLICY_SHA256` once, verify and pin the file as the process policy.
/// `Ok(None)` when the variable is not set (the unset path does nothing else).
pub fn init_process_from_env() -> Result<Option<Arc<LaunchPolicy>>, PolicyError> {
    let Some(raw_path) = std::env::var_os(ENV_PATH) else {
        return Ok(None);
    };
    let path = raw_path.to_string_lossy().into_owned();
    let sha = std::env::var(ENV_SHA256).ok();
    let policy = verify_and_pin(&path, sha.as_deref())?;
    install_process(policy.clone());
    Ok(Some(policy))
}

/// Install `policy` as the process policy (first call wins).
pub fn install_process(policy: Arc<LaunchPolicy>) {
    let (deny, ask, allow) = policy.counts();
    if PROCESS.set(policy.clone()).is_ok() {
        tracing::info!(
            path = %policy.path.display(),
            sha256 = %policy.sha256,
            deny, ask, allow,
            "launch permission policy in force"
        );
    }
}

fn pins() -> std::sync::MutexGuard<'static, Vec<Arc<LaunchPolicy>>> {
    PINS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bindings() -> std::sync::MutexGuard<'static, HashMap<String, PolicyBinding>> {
    BINDINGS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether any policy file is pinned (one atomic load; `false` on the unset path).
pub fn any_pins() -> bool {
    ANY_PINS.load(Ordering::Acquire)
}

/// Every pinned file (process and session), for the edit floor.
pub fn pinned() -> Vec<Arc<LaunchPolicy>> {
    if !ANY_PINS.load(Ordering::Acquire) {
        return Vec::new();
    }
    pins().clone()
}

/// Whether `path` names a pinned policy file. No pins → `false` with no filesystem work.
pub fn is_pinned_policy_file(path: &Path) -> bool {
    if !ANY_PINS.load(Ordering::Acquire) {
        return false;
    }
    let pins = pins();
    if pins.is_empty() {
        return false;
    }
    pins.iter().any(|pin| pin.is_same_file(path))
}

/// Serializes every change of a session's binding with the registration of its actor, so the check, the binding and the
/// resident install are one step per session id.
static REGISTER: Mutex<()> = Mutex::new(());

fn register_lock() -> std::sync::MutexGuard<'static, ()> {
    REGISTER.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The binding check for `session_id`: its existing binding (if any) must equal `wanted`; `None` against an existing
/// binding is `session_policy_missing`, a different binding `session_policy_conflict`. Binds when unbound.
fn check_and_bind(session_id: &str, wanted: Option<&PolicyBinding>) -> Result<(), PolicyError> {
    let mut map = bindings();
    match (map.get(session_id), wanted) {
        (None, None) => Ok(()),
        (Some(existing), Some(wanted)) if existing == wanted => Ok(()),
        (Some(existing), None) => Err(PolicyError::new(
            "session_policy_missing",
            existing.path.clone(),
            "this session is governed by a launch policy; send its path and sha256 again",
        )),
        (Some(existing), Some(wanted)) => Err(PolicyError::new(
            "session_policy_conflict",
            wanted.path.clone(),
            format!("this session is governed by {} with a different policy", existing.path),
        )),
        (None, Some(wanted)) => {
            map.insert(session_id.to_owned(), wanted.clone());
            ANY_BINDINGS.store(true, Ordering::Release);
            Ok(())
        }
    }
}

/// Record that `session_id` is governed by `binding` in this process; survives actor release. An existing different
/// binding is refused (`session_policy_conflict`), never replaced.
pub fn bind_session(session_id: &str, binding: PolicyBinding) -> Result<(), PolicyError> {
    let _register = register_lock();
    check_and_bind(session_id, Some(&binding))
}

/// One registration step for a session actor: held from the binding check until the caller has installed the actor, so
/// an overlapping request for the same id cannot install an actor whose policy differs from the id's binding.
pub struct Registration {
    _guard: std::sync::MutexGuard<'static, ()>,
}

/// Begin registering an actor for `session_id` that runs under `binding` (`None`: no session policy). The id's binding
/// must be absent or equal; a governed actor binds an unbound id. Hold the result until the actor is resident.
pub fn begin_registration(session_id: &str, binding: Option<&PolicyBinding>) -> Result<Registration, PolicyError> {
    let guard = register_lock();
    check_and_bind(session_id, binding)?;
    Ok(Registration { _guard: guard })
}

/// The binding recorded for `session_id` in this process.
pub fn session_binding(session_id: &str) -> Option<PolicyBinding> {
    if !ANY_BINDINGS.load(Ordering::Acquire) {
        return None;
    }
    let map = bindings();
    if map.is_empty() {
        return None;
    }
    map.get(session_id).cloned()
}

fn valid_sha256(sha: &str) -> bool {
    sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify `path` against `expected_sha` and pin it. A file already pinned (by path or identity) answers from the pin:
/// equal hash → the pinned snapshot (bytes not parsed again); different → `hash_mismatch`.
pub fn verify_and_pin(path: &str, expected_sha: Option<&str>) -> Result<Arc<LaunchPolicy>, PolicyError> {
    check_absolute(path)?;
    let Some(expected) = expected_sha.map(str::trim) else {
        return Err(PolicyError::new(
            "hash_missing",
            path,
            format!("a policy path needs its sha256 ({ENV_SHA256} or _meta[\"{META_SHA256}\"])"),
        ));
    };
    if !valid_sha256(expected) {
        return Err(PolicyError::new("hash_missing", path, "the policy sha256 must be 64 hex digits"));
    }
    let expected = expected.to_ascii_lowercase();
    let pin_answer = |pin: &Arc<LaunchPolicy>| {
        if pin.sha256 == expected {
            Ok(pin.clone())
        } else {
            Err(PolicyError::new(
                "hash_mismatch",
                path,
                "the policy file is pinned in this process with a different sha256; a changed file needs a new process",
            ))
        }
    };
    if let Some(pin) = pins().iter().find(|pin| pin.path == Path::new(path)) {
        return pin_answer(pin);
    }
    let (bytes, identity) = read_policy_bytes(path)?;
    let by_identity = identity
        .as_ref()
        .and_then(|identity| pins().iter().find(|pin| pin.identity.as_ref() == Some(identity)).cloned());
    if let Some(pin) = by_identity {
        // Another name for a pinned file: the pinned snapshot (never re-parsed), bound by the name and hash this caller
        // asserted, and kept so the same name and hash answer from it again.
        let pinned = pin_answer(&pin)?;
        let alias = Arc::new(LaunchPolicy {
            path: PathBuf::from(path),
            sha256: pinned.sha256.clone(),
            identity,
            rules: pinned.rules.clone(),
        });
        let mut pins = pins();
        if let Some(pin) = pins.iter().find(|pin| pin.path == alias.path) {
            return pin_answer(pin);
        }
        pins.push(alias.clone());
        return Ok(alias);
    }
    let actual = sha256_hex(&bytes);
    if actual != expected {
        return Err(PolicyError::new(
            "hash_mismatch",
            path,
            format!("the policy file's sha256 is {actual}, not the one given"),
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| PolicyError::new("not_utf8", path, "the policy file is not UTF-8"))?;
    let rules = decode(text, path)?;
    let policy = Arc::new(LaunchPolicy { path: PathBuf::from(path), sha256: actual, identity, rules });
    let mut pins = pins();
    // A concurrent pin of the same file wins; answer from it.
    if let Some(pin) = pins.iter().find(|pin| pin.path == policy.path) {
        return pin_answer(pin);
    }
    pins.push(policy.clone());
    ANY_PINS.store(true, Ordering::Release);
    Ok(policy)
}

/// `fuigo policy check`: the same loader without a hash and without pinning. Returns the rules and the sha256.
pub fn check_file(path: &str) -> Result<(Vec<PermissionRule>, String), PolicyError> {
    check_absolute(path)?;
    let (bytes, _) = read_policy_bytes(path)?;
    let sha = sha256_hex(&bytes);
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| PolicyError::new("not_utf8", path, "the policy file is not UTF-8"))?;
    Ok((decode(text, path)?, sha))
}

fn check_absolute(path: &str) -> Result<(), PolicyError> {
    if path.is_empty() || !Path::new(path).is_absolute() {
        return Err(PolicyError::new("not_absolute", path, "the policy path must be absolute"));
    }
    Ok(())
}

// ═════════════════════════════════════════════════════════════════════════════
// File safety: final component not followed, regular file, size cap
// ═════════════════════════════════════════════════════════════════════════════

fn open_error(path: &str, err: &std::io::Error) -> PolicyError {
    #[cfg(unix)]
    if err.raw_os_error() == Some(libc::ELOOP) {
        return PolicyError::new("symlink", path, "the policy path is a symlink");
    }
    match err.kind() {
        std::io::ErrorKind::NotFound => PolicyError::new("not_found", path, "the policy file does not exist"),
        _ => PolicyError::new("unreadable", path, format!("the policy file cannot be opened: {err}")),
    }
}

#[cfg(unix)]
fn open_no_follow(path: &str) -> Result<std::fs::File, PolicyError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|err| open_error(path, &err))
}

#[cfg(windows)]
fn open_no_follow(path: &str) -> Result<std::fs::File, PolicyError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|err| open_error(path, &err))?;
    let metadata = file
        .metadata()
        .map_err(|err| PolicyError::new("unreadable", path, format!("the policy file cannot be inspected: {err}")))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PolicyError::new("symlink", path, "the policy path is a reparse point"));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_no_follow(path: &str) -> Result<std::fs::File, PolicyError> {
    std::fs::File::open(path).map_err(|err| open_error(path, &err))
}

/// Open without following the final component, check it is a regular file, read at most [`MAX_BYTES`].
fn read_policy_bytes(path: &str) -> Result<(Vec<u8>, Option<same_file::Handle>), PolicyError> {
    let file = open_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|err| PolicyError::new("unreadable", path, format!("the policy file cannot be inspected: {err}")))?;
    if !metadata.is_file() {
        return Err(PolicyError::new("not_regular_file", path, "the policy path is not a regular file"));
    }
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| PolicyError::new("unreadable", path, format!("the policy file cannot be read: {err}")))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(PolicyError::new(
            "too_large",
            path,
            format!("the policy file is larger than {MAX_BYTES} bytes"),
        ));
    }
    let identity = same_file::Handle::from_file(file).ok();
    Ok((bytes, identity))
}

// ═════════════════════════════════════════════════════════════════════════════
// Strict decoder (launch policies only; the shared lenient parser is untouched)
// ═════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictFile {
    #[serde(default)]
    permission: Option<StrictSection>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct StrictSection {
    #[serde(default)]
    allow: Vec<toml::Spanned<String>>,
    #[serde(default)]
    deny: Vec<toml::Spanned<String>>,
    #[serde(default)]
    ask: Vec<toml::Spanned<String>>,
    #[serde(default)]
    rules: Vec<toml::Spanned<StrictRule>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictRule {
    action: RuleAction,
    #[serde(default)]
    tool: Option<ToolFilter>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    pattern_mode: Option<PatternMode>,
}

fn line_of(text: &str, offset: usize) -> usize {
    text.as_bytes()[..offset.min(text.len())].iter().filter(|b| **b == b'\n').count() + 1
}

/// Decode a launch policy strictly: only `[permission]` with `allow`/`deny`/`ask`/`rules`, every rule fully consumed,
/// every pattern valid. No rules → `empty`.
pub fn decode(text: &str, path: &str) -> Result<Vec<PermissionRule>, PolicyError> {
    // Syntax first, so a type or key error is never reported for a file that does not parse.
    if let Err(err) = toml::from_str::<toml::Table>(text) {
        let line = err.span().map(|span| line_of(text, span.start));
        return Err(PolicyError::new("toml_syntax", path, err.message().to_owned()).at(line));
    }
    let file: StrictFile = toml::from_str(text).map_err(|err| {
        let line = err.span().map(|span| line_of(text, span.start));
        let message = err.message().to_owned();
        let code = if message.contains("unknown field") { "unknown_key" } else { "bad_rule" };
        PolicyError::new(code, path, message).at(line)
    })?;
    let section = file.permission.unwrap_or_default();
    let mut rules = Vec::new();
    for (action, entries) in [
        (RuleAction::Deny, &section.deny),
        (RuleAction::Ask, &section.ask),
        (RuleAction::Allow, &section.allow),
    ] {
        for entry in entries {
            let line = Some(line_of(text, entry.span().start));
            let rule = decode_compact(entry.get_ref(), action).map_err(|(code, message)| {
                PolicyError::new(code, path, message).at(line)
            })?;
            rules.push(rule);
        }
    }
    for entry in &section.rules {
        let line = Some(line_of(text, entry.span().start));
        let StrictRule { action, tool, pattern, pattern_mode } = entry.get_ref();
        let rule = PermissionRule {
            action: *action,
            tool: tool.clone().unwrap_or_default(),
            pattern: pattern.clone(),
            pattern_mode: pattern_mode.unwrap_or_default(),
        };
        check_domain_has_pattern(&rule).map_err(|message| PolicyError::new("bad_rule", path, message).at(line))?;
        check_pattern(&rule).map_err(|message| PolicyError::new("bad_pattern", path, message).at(line))?;
        rules.push(rule);
    }
    if rules.is_empty() {
        return Err(PolicyError::new("empty", path, "the policy has no rules"));
    }
    Ok(rules)
}

/// One compact rule (`"Bash(npm test)"`), accepted only in the forms the grammar names, fully consumed.
fn decode_compact(raw: &str, action: RuleAction) -> Result<PermissionRule, (&'static str, String)> {
    let bad = |why: &str| ("bad_rule", format!("`{raw}`: {why}"));
    if !compact_shape_ok(raw) {
        return Err(bad(
            "expected `*`, a tool name, `mcp__<server>[__<tool>]`, or `Tool(content)` with nothing after `)`",
        ));
    }
    let rule = parse_permission_rule(raw, action).map_err(|err| bad(&err.to_string()))?;
    check_domain_has_pattern(&rule).map_err(|message| bad(&message))?;
    check_pattern(&rule).map_err(|message| ("bad_pattern", format!("`{raw}`: {message}")))?;
    Ok(rule)
}

fn compact_shape_ok(raw: &str) -> bool {
    if raw == "*" {
        return true;
    }
    if raw != raw.trim() || raw.is_empty() {
        return false;
    }
    match find_first_unescaped(raw, b'(') {
        None => {
            if let Some(rest) = raw.strip_prefix("mcp__") {
                return mcp_rest_ok(rest);
            }
            raw != "grep" && tool_name_to_filter(raw).is_some()
        }
        Some(open) => {
            let prefix = &raw[..open];
            let after = &raw[open + 1..];
            tool_name_to_filter(prefix).is_some()
                && find_last_unescaped(after, b')').is_some_and(|close| close + 1 == after.len())
        }
    }
}

fn mcp_rest_ok(rest: &str) -> bool {
    if rest == "*" {
        return true;
    }
    let ok_name = |s: &str| {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    };
    match rest.split_once("__") {
        None => ok_name(rest),
        Some((server, tool)) => ok_name(server) && (tool == "*" || ok_name(tool)),
    }
}

/// A domain rule names a host: an empty one (`WebFetch(domain:)`) would otherwise cover every domain.
fn check_domain_has_pattern(rule: &PermissionRule) -> Result<(), String> {
    if rule.pattern_mode == PatternMode::Domain && rule.pattern.as_deref().is_none_or(str::is_empty) {
        return Err("a domain rule needs a host, such as `domain:example.com`".to_owned());
    }
    Ok(())
}

/// Every glob must build; a domain pattern must be a bare host.
fn check_pattern(rule: &PermissionRule) -> Result<(), String> {
    let Some(pattern) = rule.pattern.as_deref() else { return Ok(()) };
    match rule.pattern_mode {
        PatternMode::Glob => glob::Pattern::new(pattern)
            .map(|_| ())
            .map_err(|err| format!("invalid pattern `{pattern}`: {err}")),
        PatternMode::Domain => check_domain(pattern),
    }
}

fn check_domain(raw: &str) -> Result<(), String> {
    use fuigo_tools::implementations::fuigo_build::web_fetch::domain::normalize_domain;
    let domain = normalize_domain(raw);
    if let Some(rest) = domain.strip_prefix("*.") {
        return Err(format!("invalid domain `{raw}`: subdomains are already covered, write `{rest}`"));
    }
    let forbidden = |c: char| matches!(c, '/' | '@' | ':' | '*') || c.is_whitespace();
    if domain.is_empty() || domain.contains(forbidden) || url::Host::parse(&domain).is_err() {
        return Err(format!("invalid domain `{raw}`: expected a bare host such as `example.com`"));
    }
    Ok(())
}

// ═════════════════════════════════════════════════════════════════════════════
// Session policies (`_meta` path + sha256), binding and marker checks
// ═════════════════════════════════════════════════════════════════════════════

/// What a session request asserts in `_meta`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionPolicyClaim {
    pub path: Option<String>,
    pub sha256: Option<String>,
}

impl SessionPolicyClaim {
    /// Decode the claim. An absent key is unset; a key present with any value but a string (`null`, a number, an
    /// object) is `bad_claim`, never silently unset.
    pub fn from_meta(meta: Option<&serde_json::Map<String, serde_json::Value>>) -> Result<Self, PolicyError> {
        let get = |key: &str| match meta.and_then(|m| m.get(key)) {
            None => Ok(None),
            Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
            Some(other) => Err(PolicyError::new(
                "bad_claim",
                "",
                format!("_meta[\"{key}\"] must be a string, not {}", json_kind(other)),
            )),
        };
        Ok(Self { path: get(META_PATH)?, sha256: get(META_SHA256)? })
    }

    pub fn is_empty(&self) -> bool {
        self.path.is_none() && self.sha256.is_none()
    }

    /// Whether this claim names the binding exactly.
    fn matches(&self, binding: &PolicyBinding) -> bool {
        self.path.as_deref() == Some(binding.path.as_str())
            && self.sha256.as_deref().map(str::to_ascii_lowercase).as_deref() == Some(binding.sha256.as_str())
    }
}

fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// Whether a `_meta` object carries the session policy key (the bridge refuses to forward such a request).
pub fn meta_has_policy_key(meta: Option<&serde_json::Map<String, serde_json::Value>>) -> bool {
    meta.is_some_and(|m| m.contains_key(META_PATH) || m.contains_key(META_SHA256))
}

/// Resolve a session's policy claim (§4.1 b/d): verify the file against the client's hash and pin it; a session bound in
/// this process, or with a stored `marker`, must carry the same key and hash. `Ok(None)`: ungoverned.
pub fn resolve_session_claim(
    claim: &SessionPolicyClaim,
    session_id: Option<&str>,
    marker: Option<&PolicyBinding>,
) -> Result<Option<Arc<LaunchPolicy>>, PolicyError> {
    let bound = session_id.and_then(session_binding);
    let required = bound.as_ref().or(marker);
    let Some(path) = claim.path.as_deref() else {
        if claim.sha256.is_some() {
            return Err(PolicyError::new(
                "not_absolute",
                "",
                format!("_meta[\"{META_SHA256}\"] without _meta[\"{META_PATH}\"]"),
            ));
        }
        if let Some(required) = required {
            return Err(PolicyError::new(
                "session_policy_missing",
                required.path.clone(),
                "this session is governed by a launch policy; send its path and sha256 again",
            ));
        }
        return Ok(None);
    };
    let policy = verify_and_pin(path, claim.sha256.as_deref())?;
    for required in [bound.as_ref(), marker].into_iter().flatten() {
        if !claim.matches(required) {
            return Err(PolicyError::new(
                "session_policy_conflict",
                path,
                format!("this session is governed by {} with a different policy", required.path),
            ));
        }
    }
    Ok(Some(policy))
}

/// A resident session's installed policy vs the request's claim: equal → attach; any difference (none↔some included)
/// → `session_policy_conflict`.
pub fn check_resident_claim(
    claim: &SessionPolicyClaim,
    installed: Option<&PolicyBinding>,
) -> Result<(), PolicyError> {
    match installed {
        None if claim.is_empty() => Ok(()),
        Some(binding) if claim.matches(binding) => Ok(()),
        _ => Err(PolicyError::new(
            "session_policy_conflict",
            claim.path.clone().or_else(|| installed.map(|b| b.path.clone())).unwrap_or_default(),
            "the loaded session runs under a different launch policy",
        )),
    }
}

/// The ack a governed session's response carries in `_meta`.
pub fn ack_value(policy: &LaunchPolicy) -> serde_json::Value {
    serde_json::json!({ "sha256": policy.sha256 })
}

/// The ack for a session response: the session's own policy hash when it has one, else the process policy's; `None` for
/// an ungoverned session (the response then carries no key).
pub fn session_ack(session_sha256: Option<&str>) -> Option<serde_json::Value> {
    match session_sha256 {
        Some(sha256) => Some(serde_json::json!({ "sha256": sha256 })),
        None => process().map(|policy| ack_value(policy)),
    }
}

/// `route_refused` for a session request a leader or bridge must not handle.
pub fn route_refused(path: &str, why: &str) -> PolicyError {
    PolicyError::new("route_refused", path, why)
}

#[cfg(test)]
#[path = "launch_policy_tests.rs"]
mod tests;
