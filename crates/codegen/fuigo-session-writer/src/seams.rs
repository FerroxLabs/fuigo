//! Test-only pause points (compiled under `cfg(test)`, or the `test-support` feature for other crates' tests). A test
//! arms a gate by key; the code under test calls [`pass`] with the same key at the seam, which reports that it was
//! reached and blocks until the test opens the gate.
//! Keys carry the session id, so tests running in parallel never meet each other's gates.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, LazyLock, Mutex, PoisonError};
use std::time::Duration;

#[derive(Default)]
pub struct Gate {
    state: Mutex<(bool, bool)>, // (reached, open)
    cv: Condvar,
}

impl Gate {
    /// Wait until the code under test is paused at the seam.
    pub fn wait_reached(&self, timeout: Duration) -> bool {
        let guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let (guard, _) = self
            .cv
            .wait_timeout_while(guard, timeout, |(reached, _)| !*reached)
            .unwrap_or_else(PoisonError::into_inner);
        guard.0
    }

    /// Let the paused code go on.
    pub fn open(&self) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).1 = true;
        self.cv.notify_all();
    }
}

static GATES: LazyLock<Mutex<HashMap<String, Arc<Gate>>>> = LazyLock::new(Mutex::default);

/// Arm a one-shot gate at `key`.
pub fn arm(key: &str) -> Arc<Gate> {
    let gate = Arc::new(Gate::default());
    GATES.lock().unwrap_or_else(PoisonError::into_inner).insert(key.to_owned(), gate.clone());
    gate
}

/// The seam: pause here if a gate is armed at `key` (once), until the test opens it.
pub fn pass(key: &str) {
    let Some(gate) = GATES.lock().unwrap_or_else(PoisonError::into_inner).remove(key) else { return };
    let guard = gate.state.lock().unwrap_or_else(PoisonError::into_inner);
    let mut guard = guard;
    guard.0 = true;
    gate.cv.notify_all();
    let _guard = gate.cv.wait_while(guard, |(_, open)| !*open).unwrap_or_else(PoisonError::into_inner);
}
