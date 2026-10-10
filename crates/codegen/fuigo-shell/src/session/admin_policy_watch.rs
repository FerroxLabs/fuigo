//! P186c (owner condition 1): what ONE session has already told its user about the admin-policy lock-down.
//!
//! A running process that holds a validated copy of an admin policy file and then reads a new version with a wrong-typed
//! pinned key enforces the lock-down (fuigo-config). The process-wide once-key there governs only the log line. Each session
//! keeps its own record of (file, version) here, so one process hosting several sessions tells each of them once, and the
//! user sees the same wording a fresh start gives (file and key named) at the next turn.
use fuigo_config::{AdminFileClass, AdminFileState};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// P186f: the most a turn start waits for the admin files. A hung mount under an admin path must not stall the turn;
/// enforcement lives in the loaders and does not depend on this notice.
pub(crate) const TURN_START_BUDGET: Duration = Duration::from_millis(200);

/// Builds the one-shot read for a check. Called on the session thread (it may capture per-thread state); the closure it
/// returns runs on a blocking thread.
type Reader = Arc<dyn Fn() -> Box<dyn FnOnce() -> Vec<AdminFileState> + Send> + Send + Sync>;

#[derive(Default)]
struct Inner {
    told: HashMap<PathBuf, u64>,
    /// Files whose last notice was "changed and is still not valid": a later valid read is said once (P186f round 2).
    told_invalid: HashSet<PathBuf>,
    /// Files whose last notice was "is now empty": a later valid read is said once (followups2). A blank stays silent.
    told_blank: HashSet<PathBuf>,
    /// Files in `told` whose lock-down is "broken and no validated copy" (round 2): when it ends, there is no "last valid
    /// policy" to fall back on, so the ending is worded differently.
    told_nocopy: HashSet<PathBuf>,
    /// Notices from a COMPLETED check that no turn has shown yet (a check that outlived its turn's budget).
    pending: Vec<String>,
    /// A read is outstanding (at most one per session).
    busy: bool,
}

impl Inner {
    fn notices(&mut self, states: &[AdminFileState]) -> Vec<String> {
        let now: Vec<&fuigo_config::AdminLockdown> = states
            .iter()
            .filter_map(|s| match &s.class {
                AdminFileClass::Locked(l) | AdminFileClass::BrokenNoCopy(l) => Some(l),
                _ => None,
            })
            .collect();
        let mut out = Vec::new();
        for s in states {
            match &s.class {
                AdminFileClass::BrokenNoCopy(l) => {
                    self.told_nocopy.insert(l.path.clone());
                }
                AdminFileClass::Locked(l) => {
                    self.told_nocopy.remove(&l.path);
                }
                _ => {}
            }
        }
        for l in &now {
            self.told_invalid.remove(&l.path);
            self.told_blank.remove(&l.path);
            if self.told.insert(l.path.clone(), l.version) != Some(l.version) {
                out.push(l.entered_notice());
            }
        }
        let gone: Vec<PathBuf> = self
            .told
            .keys()
            .filter(|p| !now.iter().any(|l| &l.path == *p))
            .cloned()
            .collect();
        for p in gone {
            self.told.remove(&p);
            let nocopy = self.told_nocopy.remove(&p);
            // P186f: "valid again" only when the file now reads as a valid document; a stable blank means the file sets no
            // policy (enforcement forgot the copy); any other exit (unparseable, missing) means enforcement is back on the
            // last valid copy
            let class = states.iter().find(|s| s.path == p).map(|s| &s.class);
            out.push(match class {
                Some(AdminFileClass::Valid) => fuigo_config::admin_lockdown_lifted_notice(&p),
                Some(AdminFileClass::Blank) => {
                    self.told_blank.insert(p.clone());
                    fuigo_config::admin_lockdown_emptied_notice(&p)
                }
                // round 2: no copy is held, so nothing is "in force again"; the file is gone, which sets no policy. Only
                // while that is still true: if a copy is held by now (a valid version was read in between), the loaders
                // enforce it, and the "still not valid" sentence below is the true one. A later valid file is then
                // announced once through `told_blank`.
                _ if nocopy && !fuigo_config::admin_requirements_copy_exists(&p) => {
                    self.told_blank.insert(p.clone());
                    fuigo_config::admin_lockdown_gone_notice(&p)
                }
                _ => {
                    self.told_invalid.insert(p.clone());
                    fuigo_config::admin_lockdown_ended_invalid_notice(&p)
                }
            });
        }
        // a file the user was told is "still not valid" and that now reads as a document: said once
        for s in states {
            if !self.told_invalid.contains(&s.path) {
                continue;
            }
            match s.class {
                AdminFileClass::Valid => out.push(fuigo_config::admin_policy_valid_in_force_notice(&s.path)),
                AdminFileClass::Blank => {
                    out.push(fuigo_config::admin_lockdown_emptied_notice(&s.path));
                    self.told_blank.insert(s.path.clone());
                }
                _ => continue,
            }
            self.told_invalid.remove(&s.path);
        }
        // a file the user was told "is now empty" that now reads as a valid document is in force: said once
        let emptied: Vec<PathBuf> = self.told_blank.iter().cloned().collect();
        for p in emptied {
            if states.iter().any(|s| s.path == p && matches!(s.class, AdminFileClass::Valid)) {
                out.push(fuigo_config::admin_policy_valid_in_force_notice(&p));
                self.told_blank.remove(&p);
            }
        }
        out
    }
}

/// Clears `busy` when the read ends, also when it panics.
struct BusyGuard(Arc<Mutex<Inner>>);

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.lock().busy = false;
    }
}

pub(crate) struct AdminPolicyWatch {
    inner: Arc<Mutex<Inner>>,
    reader: Reader,
}

impl Default for AdminPolicyWatch {
    fn default() -> Self {
        Self {
            inner: Arc::default(),
            reader: Arc::new(|| Box::new(fuigo_config::admin_policy_reader())),
        }
    }
}

impl AdminPolicyWatch {
    #[cfg(test)]
    pub(crate) fn with_reader(reader: Reader) -> Self {
        Self { inner: Arc::default(), reader }
    }

    /// Compare the lock-downs in force now with what was told. New file or new broken version: one entering notice.
    /// A file told about earlier and no longer locked: one lifting notice (or, if the file is not valid, the notice that the
    /// lock-down ended). Unchanged: nothing.
    pub(crate) fn notices(&mut self, states: &[AdminFileState]) -> Vec<String> {
        self.inner.lock().notices(states)
    }

    /// The turn-start check. The read runs on a blocking thread and is waited for at most `budget`; if it has not returned, no
    /// notice this turn (the read goes on, and a later turn shows what it finds). At most one read is outstanding: while it
    /// is, this returns at once. What was told is updated only from a completed read.
    pub(crate) async fn check(&self, budget: Duration) -> Vec<String> {
        {
            let mut g = self.inner.lock();
            if g.busy {
                return std::mem::take(&mut g.pending);
            }
            g.busy = true;
        }
        let guard = BusyGuard(self.inner.clone());
        let job = (self.reader)();
        let handle = tokio::task::spawn_blocking(move || {
            let guard = guard;
            let states = job();
            let mut g = guard.0.lock();
            let n = g.notices(&states);
            g.pending.extend(n);
        });
        // on timeout the handle is dropped: the blocking job is not cancelled and clears `busy` itself when it ends
        let _ = tokio::time::timeout(budget, handle).await;
        std::mem::take(&mut self.inner.lock().pending)
    }
}

#[cfg(test)]
#[path = "admin_policy_watch_tests.rs"]
mod tests;
