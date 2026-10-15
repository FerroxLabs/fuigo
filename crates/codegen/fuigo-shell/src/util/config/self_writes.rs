//! The self-write ledger: the content hashes of `config.toml` versions that Fuigo ITSELF wrote for the user (today the
//! Shift+Tab permission-mode switch), recorded by `update_config_as_user` in this process after the write succeeded. The peer
//! integrity watch re-baselines a mode-only change to `fuigo_home/config.toml` silently ONLY when the new file's hash is the
//! NEWEST entry and newer than the watch's baseline; a mode-only change from anything else (a model tool edit, a shell
//! command) matches nothing and still trips the hold.
//!
//! Nothing outside this process can add an entry: no socket message, no notification. A session in another process than the
//! window (a leader) therefore never sees an entry, and a Shift+Tab under peer influence trips the hold there as before.

use std::collections::VecDeque;

use sha2::{Digest, Sha256};

/// Entries kept; the oldest is evicted.
const MAX_ENTRIES: usize = 8;

#[derive(Default)]
struct Ledger {
    seq: u64,
    entries: VecDeque<(u64, String)>,
}

// Tests run in parallel in one process: a per-thread ledger keeps them from seeing each other's writes.
#[cfg(not(test))]
static LEDGER: std::sync::Mutex<Ledger> = std::sync::Mutex::new(Ledger { seq: 0, entries: VecDeque::new() });
#[cfg(test)]
thread_local! {
    static LEDGER: std::cell::RefCell<Ledger> = std::cell::RefCell::new(Ledger::default());
}

fn with<R>(f: impl FnOnce(&mut Ledger) -> R) -> R {
    #[cfg(not(test))]
    {
        f(&mut LEDGER.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }
    #[cfg(test)]
    {
        LEDGER.with(|l| f(&mut l.borrow_mut()))
    }
}

/// Lowercase SHA-256 hex of `bytes` (the same form the integrity watch uses).
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Record the hash of a `config.toml` Fuigo just wrote (and only that).
pub(crate) fn record_own_write(hash: &str) {
    with(|l| {
        l.seq += 1;
        let seq = l.seq;
        l.entries.push_back((seq, hash.to_ascii_lowercase()));
        while l.entries.len() > MAX_ENTRIES {
            l.entries.pop_front();
        }
    });
}

/// The sequence number of the newest entry (0 when none): a watch records it at its baseline.
pub(crate) fn current_seq() -> u64 {
    with(|l| l.seq)
}

/// The sequence number of the NEWEST entry if it is newer than `floor` and has this hash. Older entries never match.
pub(crate) fn newest_matching_since(floor: u64, hash: &str) -> Option<u64> {
    with(|l| l.entries.back().filter(|(s, h)| *s > floor && h == hash).map(|(s, _)| *s))
}
