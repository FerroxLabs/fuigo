//! On-disk memory for the first-party key probe, shared by every Fuigo process of one user.
//!
//! Two kinds of entry live in one small file (`<fuigo home>/api-key-probe-state.json`, owner-only 0600):
//! - `unsupported`: the probed URL answered 404 or 405, so the route is missing there. Remembered 24 h per URL
//!   (the answer does not depend on the key).
//! - `verdicts`: a Usable or Unusable verdict for one (URL, key) pair, remembered 1 h.
//!
//! Only SHA-256 hashes, a verdict word and a time are stored: never the key, never the URL, never any response field.
//! URLs are normalised (userinfo, query and fragment dropped, trailing slash trimmed) before hashing.
//! The file is read whole (at most 64 KiB), an unreadable, corrupt, oversized or future-dated entry is ignored and
//! overwritten, each list keeps at most 64 entries (oldest dropped), and a write is an atomic rename (last writer wins).
//! No error from this module ever reaches the caller.

use super::api_key_probe::ApiKeyProbeVerdict;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// How long a 404 or 405 keeps the route out of the probe.
pub(crate) const UNSUPPORTED_TTL_SECS: u64 = 24 * 60 * 60;
/// How long a Usable or Unusable verdict is reused for the same key.
pub(crate) const VERDICT_TTL_SECS: u64 = 60 * 60;
const MAX_ENTRIES: usize = 64;
const MAX_FILE_BYTES: u64 = 64 * 1024;
// Not "...memory...": Fuigo run with `--no-memory` must write nothing whose name says memory (the P53 contract test and
// host applications check by name). This file is request bookkeeping, not agent memory.
const FILE_NAME: &str = "api-key-probe-state.json";
const LOCK_NAME: &str = "api-key-probe-state.lock";

#[derive(Debug, Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    unsupported: Vec<Unsupported>,
    #[serde(default)]
    verdicts: Vec<Cached>,
    /// Consecutive 401s from the model list, per (URL, credential) hash. Defaults to empty when missing.
    #[serde(default)]
    models_401: Vec<Rejected>,
    /// Consecutive 401s from the model list per URL hash, across all credentials (caps a flapping credential source).
    #[serde(default)]
    models_401_url: Vec<Rejected>,
}

/// A run of consecutive 401s: `n` of them, the last at `t`. `h` is a hash, never the credential or the URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Rejected {
    h: String,
    n: u32,
    t: u64,
}

/// Minutes to wait after the 1st, 2nd, ... consecutive 401; the last entry repeats.
pub(crate) const REJECT_BACKOFF_MINUTES: [u64; 6] = [1, 2, 4, 8, 16, 30];
/// A credential never seen before may fetch at once only while fewer than this many consecutive 401s were seen for the URL.
pub(crate) const URL_FREE_ATTEMPTS: u32 = 3;
const REJECT_TTL_SECS: u64 = 24 * 60 * 60;

/// How long to try for the lock, and the step between non-blocking attempts.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_millis(200);
const LOCK_STEP: std::time::Duration = std::time::Duration::from_millis(5);

/// Not `WouldBlock`: Windows surfaces contention (ERROR_LOCK_VIOLATION) as `Uncategorized`.
fn lock_is_contended(e: &std::io::Error) -> bool {
    let contended = fs2::lock_contended_error();
    e.kind() == contended.kind() && e.raw_os_error() == contended.raw_os_error()
}

/// A locked file, unlocked explicitly when dropped. A `flock` belongs to the open file description, so a child that
/// another thread forks (`Command::spawn`) between our open and its exec holds a copy of the descriptor and, if we
/// only closed ours, would keep the lock alive until it execs (same guard as `HeldLock` in `session/storage/jsonl`).
struct HeldFlock(std::fs::File);
impl Drop for HeldFlock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

/// Rejections whose write to the file FAILED (a read-only home): kept for this process only, so inside one process
/// the per-credential and per-URL waits still hold. Keyed by file path and hash. An entry exists only while the
/// file cannot be written: a later successful write drops it (the file is then the truth, and another process may
/// have cleared it), and a sign-in drops it. Across processes nothing can be remembered without a writable file.
static UNSAVED: std::sync::Mutex<Vec<Unsaved>> = std::sync::Mutex::new(Vec::new());

struct Unsaved {
    path: PathBuf,
    url_level: bool,
    e: Rejected,
}

fn unsaved() -> std::sync::MutexGuard<'static, Vec<Unsaved>> {
    UNSAVED.lock().unwrap_or_else(|e| e.into_inner())
}

fn backoff_secs(position_from_zero: usize) -> u64 {
    REJECT_BACKOFF_MINUTES[position_from_zero.min(REJECT_BACKOFF_MINUTES.len() - 1)] * 60
}

#[derive(Debug, Serialize, Deserialize)]
struct Unsupported {
    h: String,
    t: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Cached {
    h: String,
    v: String,
    t: u64,
}

pub(crate) struct RouteMemory {
    path: PathBuf,
}

/// Wall-clock seconds since the epoch; tests may pin it (and switch the memories off) to simulate many process starts.
pub(crate) fn unix_now() -> u64 {
    #[cfg(test)]
    {
        let pinned = test_clock::NOW.load(std::sync::atomic::Ordering::SeqCst);
        if pinned != 0 {
            return pinned;
        }
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Normalises a URL for hashing; `None` when it does not parse (then nothing is remembered).
fn normalise(url: &str) -> Option<String> {
    let mut u = url::Url::parse(url.trim()).ok()?;
    let _ = u.set_username("");
    let _ = u.set_password(None);
    u.set_query(None);
    u.set_fragment(None);
    Some(u.as_str().trim_end_matches('/').to_string())
}

fn hash(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0u8]);
    }
    format!("{:x}", h.finalize())
}

fn live(t: u64, now: u64, ttl: u64) -> bool {
    t <= now && now - t < ttl
}

impl RouteMemory {
    pub(crate) fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub(crate) fn default_location() -> Self {
        #[cfg(test)]
        if test_clock::PROBE_MEMORY_OFF.load(std::sync::atomic::Ordering::SeqCst) {
            return Self::at(PathBuf::new());
        }
        Self::at(fuigo_dirs::fuigo_home().join(FILE_NAME))
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Store {
        let Ok(file) = std::fs::File::open(&self.path) else {
            return Store::default();
        };
        let mut bytes = Vec::new();
        if file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).is_err() || bytes.len() as u64 > MAX_FILE_BYTES {
            return Store::default();
        }
        serde_json::from_slice(&bytes).unwrap_or_default()
    }

    /// One load-modify-save under the cross-process lock. `f` returns whether anything changed (nothing is written
    /// otherwise). Returns `None` when nothing changed, else whether the file was written.
    fn update(&self, now: u64, f: impl FnOnce(&mut Store) -> bool) -> Option<bool> {
        let _lock = self.lock();
        let mut store = self.load();
        if !f(&mut store) {
            return None;
        }
        #[cfg(test)]
        test_clock::between_load_and_save();
        Some(self.save(store, now))
    }

    /// The advisory lock on `api-key-probe-state.lock`, next to the file, so two Fuigo processes cannot lose each
    /// other's update. A short bounded wait; if the lock file cannot be opened or the lock is not free in time this
    /// returns `None` and the caller goes on without it (a lost update is possible, a block never is).
    fn lock(&self) -> Option<HeldFlock> {
        use fs2::FileExt as _;
        self.path.file_name()?; // an empty path (bookkeeping switched off) has no lock either
        let lock_path = self.path.with_file_name(LOCK_NAME);
        if let Some(parent) = lock_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let file = fuigo_config::owner_only_file_options(
            std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false),
        )
        .open(&lock_path)
        .ok()?;
        fuigo_config::tighten_own_regular_file_owner_only(&file, &lock_path);
        let deadline = std::time::Instant::now() + LOCK_WAIT;
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => return Some(HeldFlock(file)),
                Err(e) if lock_is_contended(&e) && std::time::Instant::now() < deadline => {
                    std::thread::sleep(LOCK_STEP);
                }
                Err(_) => return None,
            }
        }
    }

    /// Writes the file; true when it was written.
    fn save(&self, mut store: Store, now: u64) -> bool {
        store.unsupported.retain(|e| live(e.t, now, UNSUPPORTED_TTL_SECS));
        store.verdicts.retain(|e| live(e.t, now, VERDICT_TTL_SECS));
        store.unsupported.sort_by_key(|e| std::cmp::Reverse(e.t));
        store.verdicts.sort_by_key(|e| std::cmp::Reverse(e.t));
        for list in [&mut store.models_401, &mut store.models_401_url] {
            list.retain(|e| live(e.t, now, REJECT_TTL_SECS));
            list.sort_by_key(|e| std::cmp::Reverse(e.t));
            list.truncate(MAX_ENTRIES);
        }
        store.unsupported.truncate(MAX_ENTRIES);
        store.verdicts.truncate(MAX_ENTRIES);
        let Ok(json) = serde_json::to_string(&store) else {
            return false;
        };
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match fuigo_config::fs_atomic::write_atomically(&self.path, &json, Some(0o600)) {
            Err(e) => {
                tracing::debug!(error = %e, "api key probe memory not written");
                false
            }
            Ok(()) => {
                // Not compiled on Windows by the author: same helper `auth.json` uses; a failure is ignored.
                #[cfg(windows)]
                if let Err(e) = fuigo_secrets::owner_only::set_windows_owner_only_acl(&self.path) {
                    tracing::debug!(error = %e, "api key probe memory: owner-only ACL not applied");
                }
                true
            }
        }
    }

    /// True when `url` answered 404 or 405 less than 24 h before `now`.
    pub(crate) fn unsupported(&self, url: &str, now: u64) -> bool {
        let Some(url) = normalise(url) else {
            return false;
        };
        let h = hash(&["unsupported-v1", &url]);
        self.load().unsupported.iter().any(|e| e.h == h && live(e.t, now, UNSUPPORTED_TTL_SECS))
    }

    pub(crate) fn remember_unsupported(&self, url: &str, now: u64) {
        let Some(url) = normalise(url) else {
            return;
        };
        let h = hash(&["unsupported-v1", &url]);
        self.update(now, |store| {
            store.unsupported.retain(|e| e.h != h);
            store.unsupported.push(Unsupported { h, t: now });
            true
        });
    }

    /// The Usable or Unusable verdict for this (URL, key) pair stored less than 1 h before `now`.
    pub(crate) fn verdict(&self, url: &str, key: &str, now: u64) -> Option<ApiKeyProbeVerdict> {
        let url = normalise(url)?;
        let h = hash(&["verdict-v1", &url, key]);
        let store = self.load();
        let e = store.verdicts.iter().find(|e| e.h == h && live(e.t, now, VERDICT_TTL_SECS))?;
        match e.v.as_str() {
            "usable" => Some(ApiKeyProbeVerdict::Usable),
            "unusable" => Some(ApiKeyProbeVerdict::Unusable),
            _ => None,
        }
    }

    /// Stores Usable or Unusable; an Unknown verdict is never stored.
    pub(crate) fn store_verdict(&self, url: &str, key: &str, verdict: ApiKeyProbeVerdict, now: u64) {
        let word = match verdict {
            ApiKeyProbeVerdict::Usable => "usable",
            ApiKeyProbeVerdict::Unusable => "unusable",
            ApiKeyProbeVerdict::Unknown => return,
        };
        let Some(url) = normalise(url) else {
            return;
        };
        let h = hash(&["verdict-v1", &url, key]);
        self.update(now, |store| {
            store.verdicts.retain(|e| e.h != h);
            store.verdicts.push(Cached { h, v: word.to_string(), t: now });
            true
        });
    }

    /// The model-list memory file, or `None` when a test switched it off.
    pub(crate) fn models_location() -> Option<Self> {
        #[cfg(test)]
        if test_clock::MODELS_MEMORY_OFF.load(std::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        Some(Self::at(fuigo_dirs::fuigo_home().join(FILE_NAME)))
    }

    /// Seconds a background `GET /v1/models` with this credential must still wait (`None`: go ahead).
    /// Own run of 401s: table position n-1. URL-wide run (all credentials): once it reaches [`URL_FREE_ATTEMPTS`] the
    /// table applies to every credential at position n-3. The longer of the two wins. Future-dated entries are ignored.
    pub(crate) fn models_wait(&self, url: &str, credential: &[&str], now: u64) -> Option<u64> {
        let url = normalise(url)?;
        let mut store = self.load();
        for u in unsaved().iter().filter(|u| u.path == self.path) {
            let list = if u.url_level { &mut store.models_401_url } else { &mut store.models_401 };
            match list.iter_mut().find(|f| f.h == u.e.h) {
                Some(f) if f.t < u.e.t => *f = u.e.clone(),
                Some(_) => {}
                None => list.push(u.e.clone()),
            }
        }
        let ch = cred_hash(&url, credential);
        let uh = hash(&["models-401-url-v1", &url]);
        let mut remaining = 0u64;
        let due = |e: &Rejected, wait: u64| if e.t <= now { (e.t + wait).saturating_sub(now) } else { 0 };
        if let Some(e) = store.models_401.iter().find(|e| e.h == ch && live(e.t, now, REJECT_TTL_SECS)) {
            remaining = remaining.max(due(e, backoff_secs(e.n.saturating_sub(1) as usize)));
        }
        if let Some(e) = store.models_401_url.iter().find(|e| e.h == uh && live(e.t, now, REJECT_TTL_SECS))
            && e.n >= URL_FREE_ATTEMPTS
        {
            remaining = remaining.max(due(e, backoff_secs((e.n - URL_FREE_ATTEMPTS) as usize)));
        }
        (remaining > 0).then_some(remaining)
    }

    /// Records one 401 for this credential and for the URL.
    pub(crate) fn note_models_401(&self, url: &str, credential: &[&str], now: u64) {
        let Some(url) = normalise(url) else { return };
        let ch = cred_hash(&url, credential);
        let uh = hash(&["models-401-url-v1", &url]);
        let mut written = Vec::new();
        let saved = self.update(now, |store| {
            // Also count what this process remembers from a failed write (a read-only home).
            let held = unsaved();
            for (url_level, list, h) in [(false, &mut store.models_401, ch), (true, &mut store.models_401_url, uh)] {
                let from_file = list.iter().find(|e| e.h == h && live(e.t, now, REJECT_TTL_SECS)).map_or(0, |e| e.n);
                let from_memory = held
                    .iter()
                    .filter(|u| u.path == self.path && u.e.h == h && live(u.e.t, now, REJECT_TTL_SECS))
                    .map(|u| u.e.n)
                    .max()
                    .unwrap_or(0);
                list.retain(|e| e.h != h);
                let e = Rejected { h, n: from_file.max(from_memory).saturating_add(1), t: now };
                written.push(Unsaved { path: self.path.clone(), url_level, e: e.clone() });
                list.push(e);
            }
            true
        });
        let mut held = unsaved();
        held.retain(|u| !(u.path == self.path && written.iter().any(|w| w.e.h == u.e.h)));
        if saved == Some(false) {
            held.extend(written);
            // A bounded handful: an unwritable home must not grow this without limit.
            let excess = held.len().saturating_sub(2 * MAX_ENTRIES);
            held.drain(..excess);
        }
    }

    /// A network 200 for this credential: forget both its run and the URL-wide run. Writes only if something was there.
    pub(crate) fn clear_models_401(&self, url: &str, credential: &[&str], now: u64) {
        let Some(url) = normalise(url) else { return };
        let ch = cred_hash(&url, credential);
        let uh = hash(&["models-401-url-v1", &url]);
        unsaved().retain(|u| !(u.path == self.path && (u.e.h == ch || u.e.h == uh)));
        self.update(now, |store| {
            let (a, b) = (store.models_401.len(), store.models_401_url.len());
            store.models_401.retain(|e| e.h != ch);
            store.models_401_url.retain(|e| e.h != uh);
            store.models_401.len() != a || store.models_401_url.len() != b
        });
    }

    /// A successful sign-in or token refresh: forget every remembered model-list rejection.
    pub(crate) fn clear_all_models_401(&self, now: u64) {
        unsaved().retain(|u| u.path != self.path);
        self.update(now, |store| {
            if store.models_401.is_empty() && store.models_401_url.is_empty() {
                return false;
            }
            store.models_401.clear();
            store.models_401_url.clear();
            true
        });
    }
}

/// SHA-256 over a tag, the normalised URL and every credential string a fetch may send as the bearer.
fn cred_hash(url: &str, credential: &[&str]) -> String {
    let mut parts = vec!["models-401-v1", url];
    parts.extend_from_slice(credential);
    hash(&parts)
}

#[cfg(test)]
pub(crate) mod test_clock {
    use std::sync::atomic::{AtomicBool, AtomicU64};
    pub(crate) static NOW: AtomicU64 = AtomicU64::new(0);
    pub(crate) static PROBE_MEMORY_OFF: AtomicBool = AtomicBool::new(false);
    pub(crate) static MODELS_MEMORY_OFF: AtomicBool = AtomicBool::new(false);
    /// Microseconds every `update` sleeps between its load and its save (widens the lost-update window for a test).
    pub(crate) static SLEEP_BETWEEN_LOAD_AND_SAVE_US: AtomicU64 = AtomicU64::new(0);
    pub(super) fn between_load_and_save() {
        let us = SLEEP_BETWEEN_LOAD_AND_SAVE_US.load(std::sync::atomic::Ordering::SeqCst);
        if us > 0 {
            std::thread::sleep(std::time::Duration::from_micros(us));
        }
    }
}

#[cfg(test)]
mod tests;
