//! Slash command MRU / recency (`$FUIGO_HOME/slash-mru.json`).
//!
//! A flat map from canonical command name to `last_used` timestamp.
//! Tiebreaks use recency decay (7-day half-life, 0.1 floor); the map is bounded to [`MAX_ENTRIES`] entries.
//!
//! Ownership: each [`crate::slash::SlashController`] holds an `Rc<RefCell<SlashMru>>` (single-threaded UI; no mutex).
//! `AppView` owns one store and injects it into every controller (agent prompts and dashboard dispatch) so they stay in sync.
//! There is no process-global singleton. Default and test controllers get an isolated in-memory store (no disk I/O).
//!
//! Persistence: a `touch` only marks the store dirty (never blocks the UI on disk).
//! When a command is recorded, the controller hands an owned [`MruSnapshot`] to [`persist_async`].
//! That function serializes writes through one long-lived background thread; each write MERGES the snapshot into the
//! file under the shared state-file lock (later `last_used` wins), so pagers running at once keep each other's records.
//! The `Rc<RefCell>` itself never crosses a thread boundary; only the `Send` snapshot does.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::mpsc::{self, Sender};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::util::fuigo_home;

const RECENCY_HALF_LIFE_SECS: f64 = 7.0 * 86_400.0;
const RECENCY_FLOOR: f64 = 0.1;
const MAX_ENTRIES: usize = 256;

/// On-disk format. `by_command` is canonical; legacy `by_prefix` is migrated once.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MruFile {
    #[serde(default)]
    by_command: HashMap<String, u64>,
    /// Legacy per-prefix schema; only the migration reads it.
    #[serde(default)]
    by_prefix: HashMap<String, HashMap<String, u64>>,
}

#[derive(Debug)]
pub struct SlashMru {
    by_command: HashMap<String, u64>,
    loaded: bool,
    dirty: bool,
    /// When false (tests), the store never touches disk.
    persist_enabled: bool,
}

impl Default for SlashMru {
    fn default() -> Self {
        Self {
            by_command: HashMap::new(),
            loaded: false,
            dirty: false,
            persist_enabled: true,
        }
    }
}

impl SlashMru {
    pub fn new() -> Self {
        Self::default()
    }

    /// Isolated store for unit tests (no disk I/O).
    pub fn new_in_memory() -> Self {
        Self {
            loaded: true,
            persist_enabled: false,
            ..Self::default()
        }
    }

    fn store_path() -> PathBuf {
        fuigo_home().join("slash-mru.json")
    }

    fn normalize_command(command_name: &str) -> Option<String> {
        let name = command_name.trim().trim_start_matches('/');
        if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// The tiebreak score: the `last_used` timestamp (one per command, no use count) scaled by an exponential decay.
    /// A long-stale entry cannot win ties forever, and the floor keeps any prior use just above a command never used at all.
    fn recency_score(last_used: u64, now: u64) -> u64 {
        if last_used == 0 {
            return 0;
        }
        let age = now.saturating_sub(last_used) as f64;
        let factor = (0.5_f64.powf(age / RECENCY_HALF_LIFE_SECS)).max(RECENCY_FLOOR);
        ((last_used as f64) * factor) as u64
    }

    fn ensure_loaded(&mut self) {
        if self.loaded || !self.persist_enabled {
            if !self.loaded {
                self.loaded = true;
            }
            return;
        }
        let path = Self::store_path();
        match fs::read(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.loaded = true;
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "slash MRU: read failed; using empty store, persistence disabled for session"
                );
                // Mark loaded so we do not retry the read on every `rank_score` call (once per candidate per keystroke on the UI thread)
                // Disable persistence so we never clobber a file we could not read
                self.loaded = true;
                self.persist_enabled = false;
            }
            Ok(bytes) => match serde_json::from_slice::<MruFile>(&bytes) {
                Ok(file) => {
                    self.by_command = file.by_command;
                    if self.by_command.is_empty() && !file.by_prefix.is_empty() {
                        // Collapse legacy per-prefix buckets: keep the max timestamp per command
                        for bucket in file.by_prefix.values() {
                            for (cmd, ts) in bucket {
                                let e = self.by_command.entry(cmd.clone()).or_insert(0);
                                *e = (*e).max(*ts);
                            }
                        }
                        self.dirty = true;
                    }
                    self.trim_to_cap();
                    self.loaded = true;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "slash MRU: corrupt file ignored"
                    );
                    self.loaded = true;
                }
            },
        }
    }

    fn trim_to_cap(&mut self) {
        if self.by_command.len() <= MAX_ENTRIES {
            return;
        }
        let mut entries: Vec<(String, u64)> = self.by_command.drain().collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(MAX_ENTRIES);
        self.by_command = entries.into_iter().collect();
    }

    /// Record use of a canonical command name; the typed prefix is ignored because the map is flat.
    pub fn touch(&mut self, _typed_prefix: &str, command_name: &str) {
        let Some(cmd) = Self::normalize_command(command_name) else {
            return;
        };
        self.ensure_loaded();
        let now = Self::now_secs();
        self.by_command.insert(cmd, now);
        self.trim_to_cap();
        if self.persist_enabled {
            self.dirty = true;
        }
    }

    pub fn last_used(&mut self, _typed_prefix: &str, command_name: &str) -> u64 {
        let Some(cmd) = Self::normalize_command(command_name) else {
            return 0;
        };
        self.ensure_loaded();
        self.by_command.get(&cmd).copied().unwrap_or(0)
    }

    pub fn rank_score(&mut self, _typed_prefix: &str, command_name: &str) -> u64 {
        let ts = self.last_used("", command_name);
        Self::recency_score(ts, Self::now_secs())
    }

    /// Take an owned, `Send` snapshot to persist when dirty; clears the dirty flag.
    /// Returns `None` when persistence is disabled (tests) or nothing changed.
    /// The snapshot is written off the UI thread by [`persist_async`].
    pub fn take_persist_snapshot(&mut self) -> Option<MruSnapshot> {
        if !self.persist_enabled || !self.dirty {
            return None;
        }
        self.dirty = false;
        Some(MruSnapshot {
            path: Self::store_path(),
            by_command: self.by_command.clone(),
        })
    }

    /// Re-flag unpersisted changes after a failed write so the next [`Self::take_persist_snapshot`] retries.
    /// This is a no-op when persistence is off.
    pub fn mark_dirty(&mut self) {
        if self.persist_enabled {
            self.dirty = true;
        }
    }

    #[cfg(test)]
    pub fn seed_for_test(&mut self, _prefix: &str, command_name: &str, last_used: u64) {
        self.loaded = true;
        self.persist_enabled = false;
        if let Some(cmd) = Self::normalize_command(command_name) {
            self.by_command.insert(cmd, last_used);
        }
    }
}

/// An owned, `Send` snapshot of the MRU ready to write to disk.
/// [`SlashMru::take_persist_snapshot`] produces it on the UI thread; [`persist_async`] writes it off-thread.
#[derive(Debug)]
pub struct MruSnapshot {
    path: PathBuf,
    by_command: HashMap<String, u64>,
}

/// `ours` merged into what is on disk: per command the later `last_used`
/// wins, then the map is cut back to the [`MAX_ENTRIES`] most recent. A
/// legacy per-prefix file is collapsed first (as [`SlashMru::ensure_loaded`]
/// does); a corrupt one counts as empty.
fn merge_into_disk(disk: &[u8], ours: &HashMap<String, u64>) -> HashMap<String, u64> {
    let mut merged = match serde_json::from_slice::<MruFile>(disk) {
        Ok(file) if file.by_command.is_empty() => {
            let mut collapsed: HashMap<String, u64> = HashMap::new();
            for bucket in file.by_prefix.values() {
                for (cmd, ts) in bucket {
                    let e = collapsed.entry(cmd.clone()).or_insert(0);
                    *e = (*e).max(*ts);
                }
            }
            collapsed
        }
        Ok(file) => file.by_command,
        Err(_) => HashMap::new(),
    };
    for (cmd, ts) in ours {
        let e = merged.entry(cmd.clone()).or_insert(0);
        *e = (*e).max(*ts);
    }
    if merged.len() > MAX_ENTRIES {
        let mut entries: Vec<(String, u64)> = merged.into_iter().collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries.truncate(MAX_ENTRIES);
        merged = entries.into_iter().collect();
    }
    merged
}

impl MruSnapshot {
    /// Merge this snapshot into the file and replace it atomically. Returns
    /// `true` on success. Safe to call from a worker thread.
    ///
    /// A merge, not an overwrite (P72): each pager holds its own copy of the
    /// map, and writing it whole dropped every command another pager had
    /// recorded since this one loaded the file. The read-modify-write is the
    /// shared helper's (`fuigo_config::fs_atomic::edit_state_file`), serialized
    /// across processes; the temp name is unique (the fixed `slash-mru.json.tmp`
    /// let two pagers rename each other's half-written temp).
    fn write(&self) -> bool {
        use fuigo_config::fs_atomic::Edit;
        let written = fuigo_config::fs_atomic::edit_state_file(
            &self.path,
            |bytes| {
                fuigo_config::write_through::stage_file_atomically_with(
                    &self.path,
                    bytes,
                    fuigo_config::write_through::NewFileMode::Default,
                )
            },
            |current| {
                let disk = match current {
                    Ok(bytes) => bytes.unwrap_or_default(),
                    // Never replace a file that could not be read.
                    Err(e) => return Err(io::Error::new(e.kind(), e.to_string())),
                };
                let file = MruFile {
                    by_command: merge_into_disk(disk, &self.by_command),
                    by_prefix: HashMap::new(),
                };
                Ok(Edit::Replace {
                    contents: serde_json::to_vec(&file).map_err(io::Error::other)?,
                    value: (),
                })
            },
        );
        match written {
            Ok(()) => true,
            Err(e) => {
                tracing::debug!(error = %e, "slash MRU: persist failed");
                false
            }
        }
    }
}

/// Persist a snapshot off the UI thread.
/// Writes are serialized through a long-lived background thread (created on first use), so concurrent accepts can never reorder or tear the file.
/// The send is non-blocking; the `Rc<RefCell<SlashMru>>` never leaves the UI thread, only the `Send` snapshot does.
///
/// Returns `true` if the snapshot was handed to the writer thread or written synchronously.
/// Returns `false` only when no write could be attempted, so the caller can keep the store dirty and retry on the next record.
/// If the writer thread cannot be spawned, or its channel has hung up, this falls back to a best-effort synchronous write.
///
/// The off-thread write is best-effort: each snapshot is the full command map, so the next record re-persists everything after a disk failure.
///
/// The writer channel is the only process-global piece; it holds write-only I/O state and no ranking state, so tests with injected stores are unaffected.
pub fn persist_async(snapshot: MruSnapshot) -> bool {
    static WRITER: OnceLock<Option<Sender<MruSnapshot>>> = OnceLock::new();
    let tx = WRITER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<MruSnapshot>();
        match std::thread::Builder::new()
            .name("slash-mru-writer".to_string())
            .spawn(move || {
                while let Ok(snapshot) = rx.recv() {
                    snapshot.write();
                }
            }) {
            Ok(_) => Some(tx),
            Err(e) => {
                tracing::debug!(error = %e, "slash MRU: writer thread spawn failed; writing synchronously");
                None
            }
        }
    });
    match tx {
        Some(tx) => match tx.send(snapshot) {
            Ok(()) => true,
            // The writer thread is gone; write the snapshot returned in the send error synchronously rather than dropping it
            Err(e) => e.0.write(),
        },
        // The writer thread never started; fall back to a synchronous write
        None => snapshot.write(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn touch_is_flat_by_command() {
        let mut mru = SlashMru::new_in_memory();
        mru.touch("p", "pager-headless");
        mru.touch("q", "quit");
        assert!(mru.last_used("anything", "pager-headless") > 0);
        assert!(mru.last_used("x", "quit") > 0);
        // Flat: prefix does not scope records.
        assert_eq!(mru.last_used("p", "quit"), mru.last_used("q", "quit"));
    }

    #[test]
    fn strips_leading_slash_on_command() {
        let mut mru = SlashMru::new_in_memory();
        mru.touch("m", "/model");
        assert!(mru.last_used("", "model") > 0);
        assert_eq!(mru.last_used("", "/model"), mru.last_used("", "model"));
    }

    #[test]
    fn recency_decays_stale_entries() {
        let now = 1_700_000_000_u64;
        let recent = SlashMru::recency_score(now - 60, now);
        let week_old = SlashMru::recency_score(now - 7 * 86_400, now);
        let month_old = SlashMru::recency_score(now - 30 * 86_400, now);
        assert!(recent > week_old);
        assert!(week_old > month_old);
        assert!(month_old > 0);
        assert_eq!(SlashMru::recency_score(0, now), 0);
    }

    #[test]
    fn in_memory_store_never_dirties_for_disk() {
        let mut mru = SlashMru::new_in_memory();
        mru.touch("p", "plan");
        assert!(!mru.dirty);
        assert!(mru.take_persist_snapshot().is_none());
    }

    #[test]
    fn dirty_store_yields_one_snapshot_then_clears() {
        let mut mru = SlashMru::new(); // persist-enabled
        mru.loaded = true; // avoid disk read in test
        mru.touch("p", "plan");
        assert!(mru.dirty);
        assert!(mru.take_persist_snapshot().is_some());
        // Dirty flag cleared; no redundant second write.
        assert!(!mru.dirty);
        assert!(mru.take_persist_snapshot().is_none());
    }

    #[test]
    fn mark_dirty_requeues_after_failed_write() {
        // A snapshot was taken (dirty cleared) but the write could not be handed off; mark_dirty re-queues it so the next call retries
        let mut mru = SlashMru::new();
        mru.loaded = true;
        mru.touch("p", "plan");
        assert!(mru.take_persist_snapshot().is_some());
        assert!(mru.take_persist_snapshot().is_none()); // nothing to retry yet
        mru.mark_dirty();
        assert!(mru.take_persist_snapshot().is_some()); // retried
    }

    /// P72: two pagers persisting their own MRU copies at the same time keep
    /// each other's commands (each write merges; the later `last_used` wins),
    /// and no temp is left.
    #[test]
    #[serial_test::serial(FUIGO_HOME)] // the state lock lives under the fuigo home
    fn two_writers_persisting_at_once_keep_each_others_commands() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slash-mru.json");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let writer = |tag: &'static str| {
            let (path, barrier) = (path.clone(), barrier.clone());
            std::thread::spawn(move || {
                let mut mine = HashMap::new();
                barrier.wait();
                for i in 0..30u64 {
                    mine.insert(format!("{tag}{i}"), 1_000 + i);
                    let snapshot = MruSnapshot {
                        path: path.clone(),
                        by_command: mine.clone(),
                    };
                    assert!(snapshot.write(), "{tag}{i}");
                }
            })
        };
        let a = writer("a");
        let b = writer("b");
        a.join().unwrap();
        b.join().unwrap();
        let file: MruFile = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        for tag in ["a", "b"] {
            for i in 0..30u64 {
                assert_eq!(file.by_command.get(&format!("{tag}{i}")), Some(&(1_000 + i)), "{tag}{i}");
            }
        }
        let names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["slash-mru.json"]);
    }

    /// The merge keeps the later timestamp per command and the cap.
    #[test]
    fn merge_keeps_the_later_use_and_the_cap() {
        let disk = serde_json::to_vec(&MruFile {
            by_command: HashMap::from([("x".to_owned(), 5), ("y".to_owned(), 9)]),
            by_prefix: HashMap::new(),
        })
        .unwrap();
        let ours = HashMap::from([("x".to_owned(), 7), ("y".to_owned(), 3), ("z".to_owned(), 1)]);
        let merged = merge_into_disk(&disk, &ours);
        assert_eq!(merged.get("x"), Some(&7));
        assert_eq!(merged.get("y"), Some(&9));
        assert_eq!(merged.get("z"), Some(&1));
        let many: HashMap<String, u64> = (0..(MAX_ENTRIES as u64 + 10)).map(|i| (format!("c{i}"), i + 1)).collect();
        let merged = merge_into_disk(b"not json", &many);
        assert_eq!(merged.len(), MAX_ENTRIES);
        assert!(!merged.contains_key("c0"), "the oldest are cut");
    }

    #[test]
    fn mark_dirty_noop_when_persistence_disabled() {
        let mut mru = SlashMru::new_in_memory();
        mru.mark_dirty();
        assert!(!mru.dirty);
        assert!(mru.take_persist_snapshot().is_none());
    }
}
