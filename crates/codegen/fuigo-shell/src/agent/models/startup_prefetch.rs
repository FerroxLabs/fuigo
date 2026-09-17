//! One shared startup fetch of `/v1/models` and `/v1/settings` per process.
//! A process global because the begin side (pager) and the commit side
//! (`bootstrap`) share no owner object. Cache writes land at one policy
//! re-checked commit point: normally in [`accept_within`], or in the worker as it
//! finishes when the boot has stopped waiting.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::{
    DegradedStartCause, ModelsCacheWrite, SettingsCacheWrite, SettingsPrefetch, prefetch_env,
    resolve_disk_auth, resolve_startup_endpoints,
};
use crate::agent::config::Config;
use crate::auth::{FuigoAuth, FuigoComConfig};
use crate::util::config::RemoteSettings;

static INFLIGHT: Mutex<Option<Arc<Inflight>>> = Mutex::new(None);

struct Inflight {
    origin: String,
    state: Mutex<State>,
    done: Condvar,
}

#[derive(Default)]
struct State {
    finished: bool,
    panicked: bool,
    settings: Option<RemoteSettings>,
    // True only when a settings request actually ran; a skipped fetch (no session
    // auth) must not read as a degraded start.
    settings_attempted: bool,
    // Set when a deadline-missed accept stops waiting; the worker then runs the
    // cache commit itself so a finished fetch's writes still land.
    abandoned: bool,
    models_write: Option<ModelsCacheWrite>,
    settings_write: Option<SettingsCacheWrite>,
}

/// Marks the fetch finished even if the worker panics, so waiters never hang.
/// When the boot abandoned the fetch, finishing also commits the caches: the
/// same lock orders the two, so exactly one side runs the commit.
struct FinishGuard(Arc<Inflight>);

impl Drop for FinishGuard {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        state.finished = true;
        state.panicked = std::thread::panicking();
        let abandoned_writes = state
            .abandoned
            .then(|| (state.models_write.take(), state.settings_write.take()));
        drop(state);
        self.0.done.notify_all();
        if let Some((models_write, settings_write)) = abandoned_writes {
            tracing::info!("abandoned settings prefetch finished; committing caches");
            commit_cache_writes(&self.0.origin, models_write, settings_write);
        }
    }
}

/// Pre-gate start: no managed-config sync, and nothing starts while a policy
/// repair is pending (no authenticated request under an untrusted policy).
pub fn begin_before_policy_gate(cfg: &Config) -> bool {
    if cfg!(test) {
        return INFLIGHT.lock().unwrap().is_some();
    }
    if cfg.remote_settings.is_some() || crate::managed_config::policy_repair_pending() {
        return false;
    }
    begin_inner(|| resolve_disk_auth(Some(cfg.fuigo_com_config.clone())))
}

/// Not repair-guarded (pre-gate parity with the callers it replaced).
pub fn begin(fuigo_com_config: Option<FuigoComConfig>) -> bool {
    begin_inner(|| resolve_disk_auth(fuigo_com_config))
}

/// [`begin`] with pre-resolved auth; a registered fetch wins and `auth` is dropped.
pub fn begin_with_auth(auth: Option<FuigoAuth>) -> bool {
    begin_inner(move || auth)
}

/// True when a fetch is in flight after the call (started or joined).
/// Auth is lazy so tests reach the guard without touching disk.
fn begin_inner(auth: impl FnOnce() -> Option<FuigoAuth>) -> bool {
    if cfg!(test) {
        return INFLIGHT.lock().unwrap().is_some();
    }
    if INFLIGHT.lock().unwrap().is_some() {
        return true;
    }
    // Reads disk; stay outside the registry lock.
    let Some(env) = prefetch_env(auth()) else {
        return false;
    };
    let mut inflight = INFLIGHT.lock().unwrap();
    if inflight.is_some() {
        return true;
    }
    let cell = Arc::new(Inflight {
        origin: env.endpoints.proxy_url(),
        state: Mutex::new(State::default()),
        done: Condvar::new(),
    });
    let worker_cell = cell.clone();
    std::thread::spawn(move || {
        let _guard = FinishGuard(worker_cell.clone());
        let (models, settings, settings_write) = super::run_prefetch(env);
        let mut state = worker_cell.state.lock().unwrap();
        match settings {
            SettingsPrefetch::Fetched(settings) => {
                state.settings = Some(*settings);
                state.settings_attempted = true;
            }
            SettingsPrefetch::Failed => state.settings_attempted = true,
            SettingsPrefetch::Skipped => {}
        }
        state.models_write = models.into_deferred_write();
        state.settings_write = settings_write;
    });
    *inflight = Some(cell);
    true
}

/// Proof the worker finished: removing the registry entry takes this token or the
/// dead-on-arrival discard in [`accept_within`], so a live fetch that could still
/// commit is never deregistered and a timed-out fetch stays behind as a tombstone.
struct Finished(Arc<Inflight>);

fn wait_finished(cell: Arc<Inflight>, deadline: Duration) -> Option<Finished> {
    let (state, wait) = cell
        .done
        .wait_timeout_while(cell.state.lock().unwrap(), deadline, |s| !s.finished)
        .unwrap();
    drop(state);
    if wait.timed_out() {
        return None;
    }
    Some(Finished(cell))
}

/// [`wait_finished`], but a timeout marks the fetch abandoned under the same
/// lock, so exactly one side — this waiter or the worker — commits the caches.
fn wait_finished_or_abandon(cell: Arc<Inflight>, deadline: Duration) -> Option<Finished> {
    let (mut state, _) = cell
        .done
        .wait_timeout_while(cell.state.lock().unwrap(), deadline, |s| !s.finished)
        .unwrap();
    if !state.finished {
        state.abandoned = true;
        drop(state);
        return None;
    }
    drop(state);
    Some(Finished(cell))
}

impl Finished {
    /// Remove the registry entry and yield the worker's result.
    fn take(self) -> State {
        deregister(&self.0);
        std::mem::take(&mut *self.0.state.lock().unwrap())
    }
}

fn deregister(cell: &Arc<Inflight>) {
    let mut registry = INFLIGHT.lock().unwrap();
    if registry.as_ref().is_some_and(|c| Arc::ptr_eq(c, cell)) {
        registry.take();
    }
}

/// Clone the settings once ready, leaving the fetch registered for
/// `bootstrap` to consume. Read-only.
pub fn wait_settings(timeout: Duration) -> Option<RemoteSettings> {
    let cell = INFLIGHT.lock().unwrap().clone()?;
    if !still_accepted(&cell.origin) {
        return None;
    }
    let finished = wait_finished(cell, timeout)?;
    if !still_accepted(&finished.0.origin) {
        return None;
    }
    finished.0.state.lock().unwrap().settings.clone()
}

pub(crate) enum Accept {
    /// A fetch was consumed. The boot's settings budget is spent even when it
    /// carried no settings: an empty fetch must not trigger a second
    /// pre-first-screen retry sequence (#278686).
    Consumed(Option<Box<RemoteSettings>>),
    /// Nothing usable was in flight; the caller may fetch under current policy.
    Miss,
}

/// The only commit point: consume the fetch, re-check policy, then persist and yield.
/// Waits at most `deadline` (the boot's `STARTUP_SETTINGS_WAIT_DEADLINE`): a miss spends the
/// settings budget and hands the cache commit to the still-running worker.
pub(crate) fn accept_within(deadline: Duration) -> (Accept, Option<DegradedStartCause>) {
    let Some(cell) = INFLIGHT.lock().unwrap().clone() else {
        return (Accept::Miss, None);
    };
    // Dead on arrival: a fetch that can no longer commit must not spend the
    // boot's one settings budget. Deregister it so the fallback can start a
    // fresh fetch under the current origin; its late writes are dropped.
    if !still_accepted(&cell.origin) {
        deregister(&cell);
        return (Accept::Miss, None);
    }
    let origin = cell.origin.clone();
    let Some(finished) = wait_finished_or_abandon(cell, deadline) else {
        // Budget spent: retrying would double the pre-first-screen fetches. The
        // degraded start is logged by `record_degraded_start`; a personal offline
        // boot is the expected path, so no unconditional warn here.
        return (
            Accept::Consumed(None),
            Some(DegradedStartCause::DeadlineMissed),
        );
    };
    let mut state = finished.take();
    let panicked = state.panicked;
    if panicked {
        tracing::warn!("settings prefetch thread panicked");
    }
    let settings = state.settings.take();
    let settings_attempted = state.settings_attempted;
    let models_write = state.models_write.take();
    let settings_write = state.settings_write.take();
    if !commit_cache_writes(&origin, models_write, settings_write) {
        return (Accept::Miss, None);
    }
    let degraded = if settings.is_some() {
        None
    } else if panicked {
        Some(DegradedStartCause::ThreadDied)
    } else if settings_attempted {
        tracing::info!("settings prefetch returned no settings");
        Some(DegradedStartCause::FetchFailed)
    } else {
        // No fetch ran (e.g. no session auth): a healthy no-auth boot, not degraded.
        None
    };
    (Accept::Consumed(settings.map(Box::new)), degraded)
}

/// One blocking fetch under the rules of [`begin_before_policy_gate`].
/// `deadline` is the boot's settings budget (`STARTUP_SETTINGS_WAIT_DEADLINE`); a Miss
/// fallback waits only that long, so a boot with no in-flight prefetch never blocks first
/// paint on the full retry ladder.
pub(crate) fn fetch_now_before_policy_gate(
    cfg: &Config,
    deadline: Duration,
) -> (Option<RemoteSettings>, Option<DegradedStartCause>) {
    if !begin_before_policy_gate(cfg) {
        return (None, None);
    }
    match accept_within(deadline) {
        (Accept::Consumed(settings), degraded) => (settings.map(|s| *s), degraded),
        (Accept::Miss, _) => (None, None),
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn clear_for_tests() {
    INFLIGHT.lock().unwrap().take();
}

/// The single commit body: re-check policy, then persist. False when the
/// fetch is no longer accepted (writes are dropped).
fn commit_cache_writes(
    origin: &str,
    models_write: Option<ModelsCacheWrite>,
    settings_write: Option<SettingsCacheWrite>,
) -> bool {
    if !still_accepted(origin) {
        return false;
    }
    if let Some(write) = models_write {
        write.commit();
    }
    if let Some(write) = settings_write {
        write.commit();
    }
    true
}

fn still_accepted(origin: &str) -> bool {
    if !crate::util::config::resolve_remote_fetch_enabled() {
        tracing::info!("startup prefetch discarded: remote_fetch disabled");
        return false;
    }
    if origin != resolve_startup_endpoints().proxy_url() {
        tracing::info!("startup prefetch discarded: fetch origin changed");
        return false;
    }
    true
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn inject_for_tests(settings: Option<RemoteSettings>) {
    inject_with_origin_for_tests(settings, resolve_startup_endpoints().proxy_url());
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn inject_with_origin_for_tests(settings: Option<RemoteSettings>, origin: String) {
    let cell = Arc::new(Inflight {
        origin,
        state: Mutex::new(State {
            finished: true,
            panicked: false,
            settings_attempted: settings.is_some(),
            settings,
            abandoned: false,
            models_write: None,
            settings_write: None,
        }),
        done: Condvar::new(),
    });
    *INFLIGHT.lock().unwrap() = Some(cell);
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn inflight_for_tests() -> bool {
    INFLIGHT.lock().unwrap().is_some()
}

#[cfg(test)]
#[path = "startup_prefetch_tests.rs"]
mod tests;
