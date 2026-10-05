//! P121 (K6): helper clients (the session-title client, the auto-mode classifier's route) are
//! resolved against the active model and the model catalog. They were built once and kept, so a
//! model switch or a catalog reload left them on the route they had been resolved to before.
//! [`HelperEpoch`] names what they were resolved against; [`EpochCache`] rebuilds a helper exactly
//! when it moves.

use std::future::Future;

/// What a helper client was resolved against: how many model switches and how many catalog reloads
/// the process had seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HelperEpoch {
    pub(crate) model_switch: u64,
    pub(crate) catalog_reload: u64,
    /// P132: how many times a session switched its own model (leader mode, where `model_switch` does not move).
    pub(crate) session_switches: u64,
}

/// A value built for one [`HelperEpoch`] and rebuilt when the epoch moves.
#[derive(Debug)]
pub(crate) struct EpochCache<T> {
    built_at: Option<HelperEpoch>,
    value: Option<T>,
}

impl<T> EpochCache<T> {
    pub(crate) fn new() -> Self {
        Self { built_at: None, value: None }
    }

    /// The cached value, rebuilt with `build` first when `epoch` differs from the one it was built at.
    pub(crate) async fn get_or_rebuild<F, Fut>(&mut self, epoch: HelperEpoch, build: F) -> &T
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        if self.built_at != Some(epoch) || self.value.is_none() {
            self.value = Some(build().await);
            self.built_at = Some(epoch);
        }
        self.value.as_ref().expect("built above")
    }
}

impl<T> Default for EpochCache<T> {
    fn default() -> Self {
        Self::new()
    }
}
