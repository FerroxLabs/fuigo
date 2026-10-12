//! Laundering refusal (peer messaging S7.1-S7.3, packet 7): the per-session denial ring and the denials carried by
//! released peer messages.
//!
//! The ring keeps the last [`DENIAL_RING`] permission denials of a session: the tool KIND and a hash of the normalised
//! target or command. Nothing here holds a path, a command line or a prompt: only kinds and hashes. In memory only, never in
//! the transcript. The log lives inside [`crate::permission::PeerInfluence`], which a session shares with its subagents, so
//! subagents write to and read from the root's ring.
//!
//! Normalisation (what "the same action" means; a reworded action hashes differently, which is a stated limit):
//! - A denial holds a SET of keys (at most [`MAX_KEYS_PER_DENIAL`] = 8, one per target); a request matches a carried denial
//!   when ANY of its keys equals a carried key. The ring still holds 16 denials. A DENIAL holds ONE key per target (decision
//!   63): a path is its symlink-resolved spelling, or the lexical one only when resolution fails, so one denied file is one
//!   stamp. A REQUEST is matched by EITHER spelling of every path target (`match_keys_for`: the lexical and the resolved
//!   one, when they differ), so a denial recorded while resolution failed still refuses the same spelling once resolution
//!   succeeds through a symlinked ancestor. Markers written before decision 63 hold both spellings, or only the lexical
//!   one: each still matches. Not unified: a link re-pointed after the denial (the original file stays refused by any
//!   spelling, the re-pointed spelling does not), hard links, case-insensitive file systems; Windows is not measured.
//! - `bash`: whitespace runs collapse to one space, ends trimmed. Case, quoting and argument order are kept.
//! - `read`, `grep`, `edit`: ONE key per target. The path is resolved as the packet 6 guard resolves it
//!   (`resolve_model_path`: quotes, `~`, display cwd), symlink-resolved (decision 63: a symlinked and a real spelling of
//!   one file are one recorded key; lexical when resolution fails; a request tries both spellings). `read` uses every file of `read_targets`; a patch has one key per target path. `grep` adds its glob.
//! - `web_fetch`: trimmed, scheme and host lower-cased, trailing `/` removed. `web_search`: whitespace collapsed, lower-cased.
//! - `mcp:<tool>`: the input as canonical JSON (object keys sorted, integral numbers written as integers).
//!   `agent_message`: the subagent id.
//! - Targetless requests have NO key and are never recorded, carried or matched: `read(None)`, `tool:<id>` (no input),
//!   an unparseable or empty edit, an empty command, query, URL or subagent id.
//!
//! The hash is `sha256:` plus the first 16 hex characters of SHA-256, as the peer audit log truncates it.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use fuigo_peer::DenialStamp;
use fuigo_peer::limits::{DENIAL_RING, DENIAL_STAMP_SECS, MAX_CARRIED_KEYS, MAX_DENIAL_FIELD_BYTES};
use sha2::{Digest, Sha256};

use crate::permission::types::{AccessKind, EditTargets, PermissionRequest, ReadResolution, ReadTargets};

/// Carried denial keys kept per receiving session. Never evicts: when full the newest key is dropped and counted.
const MAX_CARRIED: usize = MAX_CARRIED_KEYS;
/// Keys one denial may hold (multi-target actions); extras are dropped.
pub const MAX_KEYS_PER_DENIAL: usize = fuigo_peer::limits::MAX_KEYS_PER_DENIAL;
/// The hash of the "many targets" marker key (round 3): a request of one kind with more than [`MAX_KEYS_PER_DENIAL`]
/// targets is keyed by its first seven targets plus this marker, so the model that issues it does not choose which eight
/// targets are keyed. A carried marker matches ANY request of that kind with more than eight targets.
pub const MANY_TARGETS_HASH: &str = "many-targets";

/// What is known about how a refused request ended, on either path (`request()` and the hub). One rule decides which
/// outcomes the ring remembers ([`records_denial`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialCause {
    /// A policy rule, a `dontAsk` deny, the packet 6 guard or a laundering refusal.
    Policy,
    /// The human rejected or denied in the prompt.
    HumanReject,
    /// The human sent a follow-up message instead of approving: the human saying no.
    HumanFollowup,
    /// A prompt was shown and the human dismissed it.
    ShownThenCancelled,
    /// The prompt failed (error, timeout).
    PromptError,
    /// No prompt was shown (none available, or the requester went away first).
    NotShown,
    /// The requester was gone.
    RequesterGone,
    /// The permission manager or a check failed.
    ManagerFailure,
}

/// S7.1: whether a refusal ending as `cause` is a denial the ring remembers.
pub fn records_denial(cause: DenialCause) -> bool {
    matches!(
        cause,
        DenialCause::Policy | DenialCause::HumanReject | DenialCause::HumanFollowup | DenialCause::ShownThenCancelled
    )
}

/// Cap a key set at [`MAX_KEYS_PER_DENIAL`], never dropping a "many targets" marker.
pub fn cap_keys(mut keys: Vec<DenialKey>) -> Vec<DenialKey> {
    if keys.len() <= MAX_KEYS_PER_DENIAL {
        return keys;
    }
    let markers: Vec<DenialKey> = keys.iter().filter(|k| k.hash == MANY_TARGETS_HASH).cloned().collect();
    keys.retain(|k| k.hash != MANY_TARGETS_HASH);
    keys.truncate(MAX_KEYS_PER_DENIAL - markers.len().min(MAX_KEYS_PER_DENIAL));
    keys.extend(markers);
    keys.truncate(MAX_KEYS_PER_DENIAL);
    keys
}

/// One denial key: kind and hash only.
#[derive(Clone, PartialEq, Eq)]
pub struct DenialKey {
    pub kind: String,
    pub hash: String,
}

impl std::fmt::Debug for DenialKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DenialKey").field("kind", &self.kind).field("hash", &self.hash).finish()
    }
}

/// A match of a tool request against a carried denial: the message that carried it (its id) and the tool kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunderingHit {
    pub message_id: String,
    pub kind: String,
}

/// How full the carried list is, for the held row: keys kept and keys dropped because the list was full.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CarriedStats {
    pub carried: usize,
    pub overflow: usize,
}

#[derive(Debug)]
struct Entry {
    keys: Vec<DenialKey>,
    at: u64,
}

#[derive(Debug)]
struct Carried {
    key: DenialKey,
    message_id: String,
}

#[derive(Debug, Default)]
struct Inner {
    ring: VecDeque<Entry>,
    carried: Vec<Carried>,
    overflow: usize,
    hits: VecDeque<LaunderingHit>,
}

/// The shared denial state of one session tree. Cheap to clone (shared).
#[derive(Debug, Clone, Default)]
pub struct DenialLog(Arc<Mutex<Inner>>, Arc<std::sync::atomic::AtomicBool>);

/// Seconds on a monotonic clock, for the stamp window (a wall-clock jump cannot extend or cut it).
pub fn mono_secs() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_secs()
}

#[cfg(test)]
thread_local! {
    static KEY_COMPUTATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test counter: how many times this thread computed denial keys.
#[cfg(test)]
pub(crate) fn key_computations() -> usize {
    KEY_COMPUTATIONS.with(std::cell::Cell::get)
}

fn short_hash(s: &str) -> String {
    let d = Sha256::digest(s.as_bytes());
    format!("sha256:{}", d.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>())
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The ONE key target of a path (decision 63): the packet 6 guard's resolution (`resolve_model_path`), lexically normalised,
/// then symlink-resolved (`dunce::canonicalize` of the longest existing prefix, the rest appended lexically; see
/// `resolve_following_symlinks`). A file reached through a symlink (`/tmp` on macOS) and through its real path therefore
/// has the same target, so one denied file is one key. When resolution fails (loop, unreadable link, depth cap) the lexical
/// spelling is the key: the best effort, and a request spelled the same way is still refused. `literal` is a reader that
/// opens the path exactly as spelled. Never panics; only `lstat`/`readlink`/`canonicalize`, no network.
pub(crate) fn path_key_target(raw: &str, cwd: &Path, display: Option<&Path>, literal: bool) -> Option<String> {
    if raw.trim().is_empty() {
        return None;
    }
    let abs = if literal {
        let p = PathBuf::from(raw);
        if p.is_absolute() { p } else { cwd.join(p) }
    } else {
        fuigo_tools::types::resources::resolve_model_path(cwd, display, raw)
    };
    let target = crate::permission::policy::resolve_following_symlinks(&abs).unwrap_or(abs);
    Some(fuigo_paths::normalize_lexically(&target).to_string_lossy().into_owned())
}

/// The spellings a REQUEST for a path is matched by (decision 63, round 3): the lexical one (as a denial stores it when
/// resolution failed) and the symlink-resolved one (as a denial stores it otherwise), when they differ. Matching on either
/// keeps a request at least as strong as before the single-key change: the denial stores whichever spelling its own
/// resolution gave, and the request, whose resolution may differ, still finds it. Never used to RECORD a denial.
fn path_key_spellings(raw: &str, cwd: &Path, display: Option<&Path>, literal: bool) -> Vec<String> {
    if raw.trim().is_empty() {
        return Vec::new();
    }
    let abs = if literal {
        let p = PathBuf::from(raw);
        if p.is_absolute() { p } else { cwd.join(p) }
    } else {
        fuigo_tools::types::resources::resolve_model_path(cwd, display, raw)
    };
    let lexical = fuigo_paths::normalize_lexically(&abs).to_string_lossy().into_owned();
    let mut out = vec![lexical];
    if let Some(r) = crate::permission::policy::resolve_following_symlinks(&abs) {
        let r = fuigo_paths::normalize_lexically(&r).to_string_lossy().into_owned();
        if !out.contains(&r) {
            out.push(r);
        }
    }
    out
}

/// Canonical JSON: object keys sorted; a number with no fractional part is written as an integer (`1.0` is `1`).
fn canonical_json(v: &serde_json::Value) -> String {
    use serde_json::Value;
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::Value::String(k.clone()), canonical_json(&m[k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(canonical_json).collect::<Vec<_>>().join(",")),
        Value::Number(n) => match n.as_f64() {
            Some(f) if n.is_f64() && f.fract() == 0.0 && f.abs() < 9.0e15 => format!("{}", f as i64),
            _ => n.to_string(),
        },
        other => other.to_string(),
    }
}

/// A URL with its scheme and host lower-cased (path, query and userinfo keep their case), trimmed, trailing `/` removed.
fn normalise_url(u: &str) -> String {
    let t = u.trim();
    let out = match t.split_once("://") {
        Some((scheme, rest)) => {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            let (auth, tail) = rest.split_at(end);
            let auth = match auth.rfind('@') {
                Some(i) => format!("{}{}", &auth[..=i], auth[i + 1..].to_lowercase()),
                None => auth.to_lowercase(),
            };
            format!("{}://{auth}{tail}", scheme.to_lowercase())
        }
        None => t.to_owned(),
    };
    out.trim_end_matches('/').to_owned()
}

/// A tool name as a kind: the safe alphabet only, else a hash of it.
fn safe_kind(prefix: &str, name: &str) -> String {
    let ok = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    let mut k = if ok { format!("{prefix}{name}") } else { format!("{prefix}{}", short_hash(name)) };
    k.truncate(MAX_DENIAL_FIELD_BYTES);
    k
}

/// The keys of what one access asks for, per the normalisation rule in the module doc. Empty for a targetless access.
/// `real_cwd` and `display_cwd` are what the packet 6 guard uses.
///
/// This is the RECORDING function: one key per target (a path is its resolved spelling, lexical only when resolution
/// fails), so one denied file is one stamp. To CHECK a request against stored or carried keys use [`match_keys_for`].
pub fn denial_keys_for(
    access: &AccessKind,
    edit_targets: Option<&EditTargets>,
    read_targets: Option<&ReadTargets>,
    real_cwd: &Path,
    display_cwd: Option<&Path>,
) -> Vec<DenialKey> {
    keys_impl(access, edit_targets, read_targets, real_cwd, display_cwd, false)
}

/// The keys a REQUEST is matched by: [`denial_keys_for`] plus, for every path target, the other spelling (lexical and
/// symlink-resolved, when they differ). A request matches a stored or carried denial when ANY of these equals one of its
/// keys. Never record or stamp these (that would bring the double stamp back). May hold more than
/// [`MAX_KEYS_PER_DENIAL`] keys (up to two per target); do not cap it.
pub fn match_keys_for(
    access: &AccessKind,
    edit_targets: Option<&EditTargets>,
    read_targets: Option<&ReadTargets>,
    real_cwd: &Path,
    display_cwd: Option<&Path>,
) -> Vec<DenialKey> {
    keys_impl(access, edit_targets, read_targets, real_cwd, display_cwd, true)
}

fn keys_impl(
    access: &AccessKind,
    edit_targets: Option<&EditTargets>,
    read_targets: Option<&ReadTargets>,
    real_cwd: &Path,
    display_cwd: Option<&Path>,
    both: bool,
) -> Vec<DenialKey> {
    #[cfg(test)]
    KEY_COMPUTATIONS.with(|c| c.set(c.get() + 1));
    // One group per target; a group holds the spellings of that target (one when recording).
    let mut primary: Vec<Vec<String>> = Vec::new();
    let paths = |raws: &mut dyn Iterator<Item = &String>, literal: bool, primary: &mut Vec<Vec<String>>| {
        for raw in raws {
            let g = if both {
                path_key_spellings(raw, real_cwd, display_cwd, literal)
            } else {
                path_key_target(raw, real_cwd, display_cwd, literal).into_iter().collect()
            };
            primary.push(g);
        }
    };
    let kind = match access {
        AccessKind::Bash(cmd) => {
            primary.push(vec![collapse_ws(cmd)]);
            "bash".to_owned()
        }
        AccessKind::Read(p) => {
            match read_targets {
                Some(rt) if !rt.paths.is_empty() => {
                    paths(&mut rt.paths.iter(), rt.resolution == ReadResolution::Literal, &mut primary);
                }
                _ => {
                    if let Some(p) = p {
                        paths(&mut std::iter::once(p), false, &mut primary);
                    }
                }
            }
            "read".to_owned()
        }
        AccessKind::Grep { path, glob } => {
            let glob = glob.as_deref().unwrap_or_default();
            match path {
                Some(p) => {
                    let mut g: Vec<String> = Vec::new();
                    if both {
                        g = path_key_spellings(p, real_cwd, display_cwd, false);
                    } else {
                        g.extend(path_key_target(p, real_cwd, display_cwd, false));
                    }
                    primary.push(g.into_iter().map(|s| format!("{s}\n{glob}")).collect());
                }
                None if !glob.is_empty() => primary.push(vec![format!("\n{glob}")]),
                None => {}
            }
            "grep".to_owned()
        }
        AccessKind::Edit(p) => {
            match edit_targets {
                Some(EditTargets::Paths(ps)) => paths(&mut ps.iter(), false, &mut primary),
                Some(EditTargets::Unparseable(_)) => {}
                None if p.starts_with("task:") => primary.push(vec![p.clone()]),
                None if p.is_empty() || p == "apply_patch" => {}
                None => paths(&mut std::iter::once(p), false, &mut primary),
            }
            "edit".to_owned()
        }
        AccessKind::WebFetch(u) => {
            let n = normalise_url(u);
            if !n.is_empty() {
                primary.push(vec![n]);
            }
            "web_fetch".to_owned()
        }
        AccessKind::WebSearch(q) => {
            primary.push(vec![collapse_ws(q).to_lowercase()]);
            "web_search".to_owned()
        }
        AccessKind::MCPTool { name, input } => {
            primary.push(vec![canonical_json(input)]);
            safe_kind("mcp:", name)
        }
        AccessKind::AgentMessage { subagent_id } => {
            primary.push(vec![subagent_id.clone()]);
            "agent_message".to_owned()
        }
        // No input: nothing but the tool id, which would block every call of the tool.
        AccessKind::Tool(_) => return Vec::new(),
    };
    let mut keys: Vec<DenialKey> = Vec::new();
    let mut targets = 0usize;
    // Keys already pushed per target group, so the "first seven targets" cut works on targets, not on spellings.
    let mut ends: Vec<usize> = Vec::new();
    for g in primary {
        let mut any = false;
        for t in g {
            if t.is_empty() {
                continue;
            }
            any = true;
            let key = DenialKey { kind: kind.clone(), hash: short_hash(&t) };
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        if any {
            targets += 1;
            ends.push(keys.len());
        }
    }
    if targets > MAX_KEYS_PER_DENIAL {
        // More targets than keys: the first seven targets plus one marker, not the first eight.
        keys.truncate(ends[MAX_KEYS_PER_DENIAL - 2]);
        if !both {
            keys.truncate(MAX_KEYS_PER_DENIAL - 1);
        }
        keys.push(DenialKey { kind, hash: MANY_TARGETS_HASH.to_owned() });
        return keys;
    }
    if !both {
        keys.truncate(MAX_KEYS_PER_DENIAL);
    }
    keys
}

/// The keys of what `request` asks for, for RECORDING. Empty when it has no real target.
pub fn denial_keys(request: &PermissionRequest) -> Vec<DenialKey> {
    let (cwd, display) = match &request.path_context {
        Some(c) => (c.real_cwd.clone(), c.display_cwd.clone()),
        None => (std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")), None),
    };
    denial_keys_for(&request.access, request.edit_targets.as_ref(), request.read_targets.as_ref(), &cwd, display.as_deref())
}

/// The keys `request` is MATCHED by (either spelling of every path target); see [`match_keys_for`].
pub fn match_keys(request: &PermissionRequest) -> Vec<DenialKey> {
    let (cwd, display) = match &request.path_context {
        Some(c) => (c.real_cwd.clone(), c.display_cwd.clone()),
        None => (std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")), None),
    };
    match_keys_for(&request.access, request.edit_targets.as_ref(), request.read_targets.as_ref(), &cwd, display.as_deref())
}

/// What [`denial_keys`] needs from a request, copied so the keys can be computed after the request has been handed on, and
/// only when there is a denial to record. Holding it costs a clone, no hashing.
pub struct KeyBasis {
    access: AccessKind,
    path_context: Option<crate::permission::types::RequestPathContext>,
    edit_targets: Option<EditTargets>,
    read_targets: Option<ReadTargets>,
}

impl KeyBasis {
    pub fn of(request: &PermissionRequest) -> Self {
        Self {
            access: request.access.clone(),
            path_context: request.path_context.clone(),
            edit_targets: request.edit_targets.clone(),
            read_targets: request.read_targets.clone(),
        }
    }

    pub fn keys(&self) -> Vec<DenialKey> {
        let (cwd, display) = match &self.path_context {
            Some(c) => (c.real_cwd.clone(), c.display_cwd.clone()),
            None => (std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")), None),
        };
        denial_keys_for(&self.access, self.edit_targets.as_ref(), self.read_targets.as_ref(), &cwd, display.as_deref())
    }
}

/// The first key of `request` (kept for older callers); for a targetless request, the kind with an empty hash, which
/// [`DenialLog`] never records or matches.
pub fn denial_key(request: &PermissionRequest) -> DenialKey {
    denial_keys(request).into_iter().next().unwrap_or_else(|| DenialKey {
        kind: match &request.access {
            AccessKind::Bash(_) => "bash".to_owned(),
            AccessKind::Read(_) => "read".to_owned(),
            AccessKind::Grep { .. } => "grep".to_owned(),
            AccessKind::Edit(_) => "edit".to_owned(),
            AccessKind::WebFetch(_) => "web_fetch".to_owned(),
            AccessKind::WebSearch(_) => "web_search".to_owned(),
            AccessKind::MCPTool { name, .. } => safe_kind("mcp:", name),
            AccessKind::AgentMessage { .. } => "agent_message".to_owned(),
            AccessKind::Tool(id) => safe_kind("tool:", id),
        },
        hash: String::new(),
    })
}

fn lock(m: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl DenialLog {
    /// S7.1: remember a denial of one key. See [`DenialLog::record_keys`].
    pub fn record(&self, key: DenialKey, now: u64) {
        self.record_keys(vec![key], now);
    }

    /// S7.1: remember a denial (its keys: kind and hash), newest last, at most [`DENIAL_RING`] denials. No keys means a
    /// targetless request: nothing is recorded. A repeat of the same key set refreshes the time of the existing entry
    /// instead of adding a duplicate. `now` is [`mono_secs`] in production.
    pub fn record_keys(&self, mut keys: Vec<DenialKey>, now: u64) {
        keys.retain(|k| !k.hash.is_empty());
        let keys = cap_keys(keys);
        if keys.is_empty() {
            return;
        }
        let mut g = lock(&self.0);
        if let Some(i) = g.ring.iter().position(|e| e.keys.len() == keys.len() && keys.iter().all(|k| e.keys.contains(k))) {
            g.ring.remove(i);
        } else if g.ring.len() >= DENIAL_RING {
            g.ring.pop_front();
        }
        g.ring.push_back(Entry { keys, at: now });
    }

    /// Every key in the ring, oldest denial first (kind and hash), whatever its age.
    pub fn snapshot(&self) -> Vec<DenialKey> {
        lock(&self.0).ring.iter().flat_map(|e| e.keys.iter().cloned()).collect()
    }

    /// The key set of every denial in the ring, oldest first (kind and hash only), whatever its age. What the session stores,
    /// one marker per denial, so a multi-key denial keeps all its keys across a resume.
    pub fn entries(&self) -> Vec<Vec<DenialKey>> {
        lock(&self.0).ring.iter().map(|e| e.keys.clone()).collect()
    }

    /// The number of denials in the ring.
    pub fn ring_len(&self) -> usize {
        lock(&self.0).ring.len()
    }

    /// S7.2: the stamps for an outgoing message: EVERY key of every denial younger than 30 minutes, oldest first; empty when
    /// there are none (then the envelope carries nothing and its bytes are unchanged). At most `DENIAL_RING` denials of
    /// `MAX_KEYS_PER_DENIAL` keys, so never more than `MAX_DENIAL_STAMPS` (128), which is what an envelope may hold.
    pub fn stamps(&self, now: u64) -> Vec<DenialStamp> {
        let g = lock(&self.0);
        let mut out: Vec<DenialStamp> = Vec::new();
        for e in g.ring.iter().filter(|e| now.saturating_sub(e.at) < DENIAL_STAMP_SECS) {
            for key in &e.keys {
                let stamp = DenialStamp { tool_kind: key.kind.clone(), target_hash: key.hash.clone() };
                if !out.contains(&stamp) {
                    out.push(stamp);
                }
            }
        }
        out.truncate(fuigo_peer::limits::MAX_DENIAL_STAMPS);
        out
    }

    /// S7.3: keep the denials a released message carried, with the id of that message. Bounded at `fuigo_peer::limits::MAX_CARRIED_KEYS` (128) keys and never
    /// evicting: when full the newest key is dropped and counted (see [`DenialLog::carried_stats`]).
    pub fn carry(&self, message_id: &str, stamps: &[DenialStamp]) {
        let mut g = lock(&self.0);
        for s in stamps {
            let key = DenialKey { kind: s.tool_kind.clone(), hash: s.target_hash.clone() };
            if key.hash.is_empty() || g.carried.iter().any(|c| c.key == key) {
                continue;
            }
            if g.carried.len() >= MAX_CARRIED {
                g.overflow += 1;
                continue;
            }
            g.carried.push(Carried { key, message_id: message_id.to_owned() });
            self.1.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    /// Whether anything is carried: one atomic load, no lock (set under the mutex whenever the list changes).
    pub fn has_carried(&self) -> bool {
        self.1.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The carried count and how many keys were dropped because the list was full, for the held row.
    pub fn carried_stats(&self) -> CarriedStats {
        let g = lock(&self.0);
        CarriedStats { carried: g.carried.len(), overflow: g.overflow }
    }

    /// `/peers clear-influence`: forget the carried denials. The session's own ring stays.
    pub fn clear_carried(&self) {
        let mut g = lock(&self.0);
        g.carried.clear();
        g.overflow = 0;
        self.1.store(false, std::sync::atomic::Ordering::Release);
    }

    /// If `key` matches a carried denial (same kind and hash), queue a hit for the session to report and return it.
    pub fn match_carried(&self, key: &DenialKey) -> Option<LaunderingHit> {
        self.match_carried_any(std::slice::from_ref(key))
    }

    /// If ANY of `keys` equals a carried key, queue a hit for the session to report and return it.
    pub fn match_carried_any(&self, keys: &[DenialKey]) -> Option<LaunderingHit> {
        let mut g = lock(&self.0);
        let hit = g
            .carried
            .iter()
            .find(|c| !c.key.hash.is_empty() && keys.contains(&c.key))
            .map(|c| LaunderingHit { message_id: c.message_id.clone(), kind: c.key.kind.clone() })?;
        if g.hits.len() >= 64 {
            g.hits.pop_front();
        }
        g.hits.push_back(hit.clone());
        Some(hit)
    }

    /// The hits queued since the last call (the session turns them into a human notice, an audit line and a sender notice).
    pub fn take_hits(&self) -> Vec<LaunderingHit> {
        lock(&self.0).hits.drain(..).collect()
    }
}

/// What the model is told when a request matches a carried denial (kind only).
pub fn laundering_refused_text(kind: &str) -> String {
    format!(
        "Denied (laundering_refused): another session was denied this same `{kind}` action and sent it here. \
         It was not run. The human can run `/peers clear-influence` in this session to lift the restriction."
    )
}
