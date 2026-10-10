//! Test-only helpers shared across modules of this crate.

/// Serialize tests that read or mutate the process-global remote kill-switch and key seam.
/// Any test that asserts on `signed_policy::verification_active()` while armed must hold it.
pub(crate) fn with_remote_disarm_lock<R>(f: impl FnOnce() -> R) -> R {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    f()
}
