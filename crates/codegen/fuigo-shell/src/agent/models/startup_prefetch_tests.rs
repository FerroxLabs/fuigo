use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::{
    Accept, DegradedStartCause, FinishGuard, INFLIGHT, Inflight, SettingsCacheWrite, State,
    accept_within, begin_before_policy_gate, clear_for_tests, inject_with_origin_for_tests,
};
use crate::agent::config::Config;
use crate::util::config::RemoteSettings;

fn marker_settings() -> Option<RemoteSettings> {
    Some(RemoteSettings {
        path_not_found_hints: Some(true),
        ..RemoteSettings::default()
    })
}

fn registered_marker() -> Option<bool> {
    let inflight = INFLIGHT.lock().unwrap();
    let cell = inflight.as_ref()?;
    let state = cell.state.lock().unwrap();
    state.settings.as_ref().and_then(|s| s.path_not_found_hints)
}

/// Same serial group as `init_tests`: both consume the process-wide fetch.
#[test]
#[serial_test::serial(remote_sig_disarm)]
fn begin_does_not_replace_an_inflight_fetch() {
    clear_for_tests();
    super::inject_for_tests(marker_settings());
    begin_before_policy_gate(&Config::default());
    assert_eq!(
        registered_marker(),
        Some(true),
        "the second begin must join the in-flight fetch, not replace it"
    );
    clear_for_tests();
}

#[test]
#[serial_test::serial(remote_sig_disarm)]
fn accept_discards_a_fetch_from_another_origin() {
    clear_for_tests();
    inject_with_origin_for_tests(marker_settings(), "https://elsewhere.invalid".to_string());
    assert!(
        matches!(accept_within(Duration::from_secs(5)).0, Accept::Miss),
        "a fetch from a different origin must not be applied"
    );
    assert!(
        !super::inflight_for_tests(),
        "the rejected fetch must be consumed, not left registered"
    );
}

#[test]
#[serial_test::serial(remote_sig_disarm)]
fn accept_deadline_spends_the_budget() {
    if !crate::util::config::resolve_remote_fetch_enabled() {
        eprintln!("skipped: remote_fetch disabled in this environment");
        return;
    }
    clear_for_tests();
    let never_finishing = Arc::new(Inflight {
        origin: super::resolve_startup_endpoints().proxy_url(),
        state: Mutex::new(State::default()),
        done: Condvar::new(),
    });
    *INFLIGHT.lock().unwrap() = Some(never_finishing.clone());
    let (accept, degraded) = accept_within(Duration::ZERO);
    assert!(
        matches!(accept, Accept::Consumed(None)),
        "a timed-out wait must spend the budget, not trigger a refetch"
    );
    assert_eq!(
        degraded,
        Some(DegradedStartCause::DeadlineMissed),
        "a timed-out fetch is a genuine degraded start"
    );
    assert!(
        super::inflight_for_tests(),
        "a timed-out fetch must stay registered so nothing can start behind it"
    );
    assert!(
        never_finishing.state.lock().unwrap().abandoned,
        "a timed-out fetch must hand its cache commit to the worker"
    );
    clear_for_tests();
}

/// A fetch that outlives the boot deadline must still land its cache writes
/// when the worker finishes; only the settings application is forfeited.
#[test]
#[serial_test::serial(remote_sig_disarm)]
fn abandoned_fetch_commits_caches_when_the_worker_finishes() {
    if !crate::util::config::resolve_remote_fetch_enabled() {
        eprintln!("skipped: remote_fetch disabled in this environment");
        return;
    }
    clear_for_tests();
    let cell = Arc::new(Inflight {
        origin: super::resolve_startup_endpoints().proxy_url(),
        state: Mutex::new(State::default()),
        done: Condvar::new(),
    });
    *INFLIGHT.lock().unwrap() = Some(cell.clone());
    let (accept, degraded) = accept_within(Duration::ZERO);
    assert!(matches!(accept, Accept::Consumed(None)));
    assert_eq!(degraded, Some(DegradedStartCause::DeadlineMissed));

    // The worker's final act: store its pending write, then finish.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings_cache.json");
    cell.state.lock().unwrap().settings_write = Some(SettingsCacheWrite::for_tests(path.clone()));
    drop(FinishGuard(cell));
    assert!(
        path.exists(),
        "the worker must commit the caches of a fetch the boot stopped waiting for"
    );
    clear_for_tests();
}

/// A Miss fallback must wait on the caller's boot deadline, not the worker's
/// full retry budget.
#[test]
#[serial_test::serial(remote_sig_disarm)]
fn fallback_fetch_honors_the_caller_deadline() {
    if !crate::util::config::resolve_remote_fetch_enabled() {
        eprintln!("skipped: remote_fetch disabled in this environment");
        return;
    }
    clear_for_tests();
    let never_finishing = Arc::new(Inflight {
        origin: super::resolve_startup_endpoints().proxy_url(),
        state: Mutex::new(State::default()),
        done: Condvar::new(),
    });
    *INFLIGHT.lock().unwrap() = Some(never_finishing);
    let started = std::time::Instant::now();
    let (settings, degraded) =
        super::fetch_now_before_policy_gate(&Config::default(), Duration::from_millis(30));
    assert!(
        settings.is_none(),
        "a deadline miss must not invent settings"
    );
    assert_eq!(degraded, Some(DegradedStartCause::DeadlineMissed));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "fallback waited the full retry budget ({:?}), not the boot deadline",
        started.elapsed()
    );
    clear_for_tests();
}

/// A fetch that can no longer commit must not spend the settings budget:
/// accept discards it without waiting, so the fallback fetch under the
/// current origin still fits inside the boot's one deadline window.
#[test]
#[serial_test::serial(remote_sig_disarm)]
fn stale_origin_fetch_is_discarded_without_waiting() {
    clear_for_tests();
    let never_finishing = Arc::new(Inflight {
        origin: "https://elsewhere.invalid".to_string(),
        state: Mutex::new(State::default()),
        done: Condvar::new(),
    });
    *INFLIGHT.lock().unwrap() = Some(never_finishing);
    let started = std::time::Instant::now();
    let (accept, degraded) = accept_within(Duration::from_secs(30));
    assert!(
        matches!(accept, Accept::Miss),
        "a dead-on-arrival fetch is a miss, not a spent budget"
    );
    assert!(
        degraded.is_none(),
        "the fallback fetch owns the degraded classification"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "a fetch that can never commit must not be waited on ({:?})",
        started.elapsed()
    );
    assert!(
        !super::inflight_for_tests(),
        "the stale fetch must be deregistered so a fresh fetch can start"
    );
    clear_for_tests();
}

/// Registers a finished fetch at the accepted origin so `accept_within` reaches
/// its degraded-start classification.
fn register_finished(settings: Option<RemoteSettings>, settings_attempted: bool) {
    let cell = Arc::new(Inflight {
        origin: super::resolve_startup_endpoints().proxy_url(),
        state: Mutex::new(State {
            finished: true,
            panicked: false,
            settings_attempted,
            settings,
            abandoned: false,
            models_write: None,
            settings_write: None,
        }),
        done: Condvar::new(),
    });
    *INFLIGHT.lock().unwrap() = Some(cell);
}

#[test]
#[serial_test::serial(remote_sig_disarm)]
fn no_auth_boot_is_not_a_degraded_start() {
    if !crate::util::config::resolve_remote_fetch_enabled() {
        eprintln!("skipped: remote_fetch disabled in this environment");
        return;
    }
    clear_for_tests();
    // prefetch_uncommitted skips the settings request with no session auth.
    register_finished(None, false);
    let (accept, degraded) = accept_within(Duration::ZERO);
    assert!(
        matches!(accept, Accept::Consumed(None)),
        "a no-auth boot still consumes the (empty) fetch"
    );
    assert!(
        degraded.is_none(),
        "a boot that never attempted settings must not record a degraded start"
    );
    clear_for_tests();
}

#[test]
#[serial_test::serial(remote_sig_disarm)]
fn attempted_settings_fetch_failure_is_a_degraded_start() {
    if !crate::util::config::resolve_remote_fetch_enabled() {
        eprintln!("skipped: remote_fetch disabled in this environment");
        return;
    }
    clear_for_tests();
    // A real fetch ran and yielded no settings.
    register_finished(None, true);
    let (accept, degraded) = accept_within(Duration::ZERO);
    assert!(matches!(accept, Accept::Consumed(None)));
    assert_eq!(
        degraded,
        Some(DegradedStartCause::FetchFailed),
        "an attempted fetch that yields no settings is a real degraded start"
    );
    clear_for_tests();
}

#[test]
#[serial_test::serial(remote_sig_disarm)]
fn wait_settings_leaves_the_fetch_for_accept() {
    if !crate::util::config::resolve_remote_fetch_enabled() {
        eprintln!("skipped: remote_fetch disabled in this environment");
        return;
    }
    clear_for_tests();
    super::inject_for_tests(marker_settings());
    assert_eq!(
        super::wait_settings(Duration::ZERO).and_then(|s| s.path_not_found_hints),
        Some(true),
    );
    match accept_within(Duration::from_secs(5)).0 {
        Accept::Consumed(settings) => assert_eq!(
            settings.and_then(|s| s.path_not_found_hints),
            Some(true),
            "wait_settings must not consume the fetch"
        ),
        Accept::Miss => panic!("wait_settings consumed the fetch"),
    }
}
