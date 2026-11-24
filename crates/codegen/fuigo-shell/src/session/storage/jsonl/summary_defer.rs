//! Audit 1.0.47 F2: the per-record `summary.json` counters (`num_messages`, `num_chat_messages`, `last_active_at`) are held
//! in memory and land with the next summary write of the session: its turn boundary (a durable update), any other summary
//! patch, or a persistence barrier ([`StorageAdapter::flush_summary`](super::super::StorageAdapter::flush_summary)).
//! A crash mid-turn leaves the counters at most one turn behind; they are display data (the session list) and nothing
//! repairs or relies on their exact value. Records up to and including the first update of a session in this process still
//! go straight to disk, so a session that crashes in its first turn is never left looking like an unused husk
//! (`num_messages == 0`).
use super::super::summary_write::{CounterOp, SummaryPatch};
use crate::session::persistence::{CHAT_FORMAT_VERSION, Summary};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Pending {
    messages: usize,
    chat_messages: usize,
    activity: bool,
}

impl Pending {
    pub(super) fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Keyed by session folder, so every adapter of the session in this process folds the same counts.
static PENDING: std::sync::LazyLock<parking_lot::Mutex<HashMap<PathBuf, Pending>>> =
    std::sync::LazyLock::new(Default::default);

/// Hold `messages` / `chat_messages` increments (with activity) for `dir`. `false`: nothing held yet for this session in
/// this process, so the caller writes this one through. The first update's write-through creates the entry, and later
/// records are held; chat lines before it are written through, so `num_messages` is on disk from the first update on.
pub(super) fn defer(dir: &Path, messages: usize, chat_messages: usize) -> bool {
    let mut map = PENDING.lock();
    match map.get_mut(dir) {
        Some(pending) => {
            pending.messages += messages;
            pending.chat_messages += chat_messages;
            pending.activity = true;
            true
        }
        None => {
            // Only an update (`num_messages`, what the husk check reads) spends the write-through (review M2).
            if messages > 0 {
                map.insert(dir.to_path_buf(), Pending::default());
            }
            false
        }
    }
}

/// Move `dir`'s held counts into `patch`. An absolute `Set` already owns the count, so held increments of that counter are
/// dropped. Returns what was taken, for [`restore`] if the write fails.
pub(super) fn take_into(dir: &Path, patch: &mut SummaryPatch) -> Pending {
    let taken = PENDING
        .lock()
        .get_mut(dir)
        .map(std::mem::take)
        .unwrap_or_default();
    fold(&mut patch.messages, taken.messages);
    fold(&mut patch.chat_messages, taken.chat_messages);
    if taken.chat_messages > 0 {
        patch.chat_format_version = patch.chat_format_version.max(Some(CHAT_FORMAT_VERSION));
    }
    patch.record_activity |= taken.activity;
    taken
}

fn fold(op: &mut Option<CounterOp>, held: usize) {
    match op {
        _ if held == 0 => {}
        None => *op = Some(CounterOp::Increment(held)),
        Some(CounterOp::Increment(n)) => *n += held,
        Some(CounterOp::Set(_)) => {}
    }
}

/// Put back counts [`take_into`] took for a write that failed.
pub(super) fn restore(dir: &Path, taken: Pending) {
    if taken.is_empty() {
        return;
    }
    let mut map = PENDING.lock();
    let pending = map.entry(dir.to_path_buf()).or_default();
    pending.messages += taken.messages;
    pending.chat_messages += taken.chat_messages;
    pending.activity |= taken.activity;
}

/// Whether `dir` has held counts.
pub(super) fn has_pending(dir: &Path) -> bool {
    PENDING
        .lock()
        .get(dir)
        .is_some_and(|pending| !pending.is_empty())
}

/// A read of the summary in this process sees the held counts too (display only; nothing is written).
pub(super) fn overlay(dir: &Path, summary: &mut Summary) {
    if let Some(pending) = PENDING.lock().get(dir) {
        summary.num_messages = summary.num_messages.saturating_add(pending.messages);
        summary.num_chat_messages = summary
            .num_chat_messages
            .saturating_add(pending.chat_messages);
    }
}

/// The session's writer is released: forget it here (a later writer of the folder starts with a write-through again).
pub(super) fn forget(dir: &Path) {
    if let Some(pending) = PENDING.lock().remove(dir)
        && !pending.is_empty()
    {
        tracing::warn!(dir = %dir.display(), ?pending, "session released with summary counts not yet written");
    }
}
