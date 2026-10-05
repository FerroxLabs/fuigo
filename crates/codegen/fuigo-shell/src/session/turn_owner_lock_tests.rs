use super::*;

/// No live actor: recovery may run.
#[test]
fn an_unheld_session_is_recoverable() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(matches!(
        try_recovery_lock(dir.path()),
        RecoveryLock::Acquired(_)
    ));
}

/// A live actor's shared lock (a separate open file description, exactly as another process would hold it)
/// makes recovery stand down, and releasing it makes the session recoverable again.
#[tokio::test]
async fn a_held_session_is_not_recoverable_until_released() {
    let dir = tempfile::tempdir().expect("tempdir");
    let owner = TurnOwnerLock::acquire(dir.path())
        .await
        .expect("not busy")
        .expect("owner lock");
    assert!(matches!(
        try_recovery_lock(dir.path()),
        RecoveryLock::HeldElsewhere
    ));
    let second_owner = TurnOwnerLock::acquire(dir.path())
        .await
        .expect("not busy")
        .expect("owners share the session");
    drop(owner);
    assert!(
        matches!(try_recovery_lock(dir.path()), RecoveryLock::HeldElsewhere),
        "any one live owner keeps the session live"
    );
    drop(second_owner);
    assert!(matches!(
        try_recovery_lock(dir.path()),
        RecoveryLock::Acquired(_)
    ));
}

/// Only one recoverer at a time, so two concurrent loads cannot both record the same turn.
#[test]
fn recovery_is_exclusive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let RecoveryLock::Acquired(guard) = try_recovery_lock(dir.path()) else {
        panic!("first recoverer must acquire");
    };
    assert!(matches!(
        try_recovery_lock(dir.path()),
        RecoveryLock::HeldElsewhere
    ));
    drop(guard);
}

/// Holds the exclusive (recovery) lock on another thread for `hold`, as another process's recovery would.
fn recovery_elsewhere(dir: &Path, hold: std::time::Duration) -> std::thread::JoinHandle<()> {
    let RecoveryLock::Acquired(guard) = try_recovery_lock(dir) else {
        panic!("recoverer must acquire");
    };
    std::thread::spawn(move || {
        std::thread::sleep(hold);
        drop(guard);
    })
}

/// Mutant discriminated: a blocking (`std::thread::sleep`) wait (N1).
/// The wait is awaited by the load on the agent's single-threaded `LocalSet` (`spawn_session_on_thread`), which
/// also runs every other session's load and the ACP connection. It must not stall it: other tasks keep running.
#[tokio::test(flavor = "current_thread")]
async fn waiting_for_the_owner_lock_does_not_block_the_local_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let releaser = recovery_elsewhere(dir.path(), std::time::Duration::from_millis(400));
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let ticks = std::rc::Rc::new(std::cell::Cell::new(0u32));
            let ticker = {
                let ticks = ticks.clone();
                tokio::task::spawn_local(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        ticks.set(ticks.get() + 1);
                    }
                })
            };
            let before = ticks.get();
            let lock = TurnOwnerLock::acquire(dir.path()).await;
            let during = ticks.get() - before;
            ticker.abort();
            assert!(
                matches!(lock, Ok(Some(_))),
                "the lock is taken once the recovery ends"
            );
            assert!(
                during >= 10,
                "other LocalSet tasks must keep running during the wait; they ran {during} times"
            );
        })
        .await;
    releaser.join().expect("releaser");
}

/// Mutant discriminated: a deadline after which the actor runs unlocked (N2).
/// The v2 wait gave up after 2 s and then ran for its whole lifetime without the lock, where a later recovery could
/// declare its live turn lost. The wait now never gives up to run unlocked, so a recovery longer than the old
/// deadline still ends locked.
#[tokio::test(flavor = "current_thread")]
async fn an_owner_waits_out_a_recovery_longer_than_the_old_deadline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let releaser = recovery_elsewhere(dir.path(), std::time::Duration::from_millis(2_500));
    let lock = TurnOwnerLock::acquire(dir.path()).await;
    releaser.join().expect("releaser");
    assert!(
        matches!(lock, Ok(Some(_))),
        "the actor must end up holding its lock"
    );
    assert!(
        matches!(try_recovery_lock(dir.path()), RecoveryLock::HeldElsewhere),
        "and a later recovery must see it live"
    );
}

/// A session dir that cannot hold the lock file yields `Unknown`, which callers treat as "do not declare".
#[tokio::test]
async fn an_unusable_session_dir_is_unknown_not_recoverable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("no-such-session");
    assert!(matches!(
        try_recovery_lock(&missing),
        RecoveryLock::Unknown(_)
    ));
    assert!(matches!(TurnOwnerLock::acquire(&missing).await, Ok(None)));
}

/// F2. Mutant discriminated: an owner wait with no bound.
/// A process that is alive but hung while holding the exclusive recovery lock (stopped in a debugger, wedged on
/// I/O) made `session/load` wait forever with no signal to the client. After `OWNER_WAIT_LIMIT` the wait gives up
/// with `OwnerLockBusy`, which the load returns as a retry error; no lock is taken and no actor is built, so no
/// `turn_started` is written unlocked.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_hung_recoverer_fails_the_load_at_the_bound_instead_of_waiting_forever() {
    let dir = tempfile::tempdir().expect("tempdir");
    let RecoveryLock::Acquired(hung) = try_recovery_lock(dir.path()) else {
        panic!("recoverer must acquire");
    };
    let started = tokio::time::Instant::now();

    let result = tokio::time::timeout(OWNER_WAIT_LIMIT * 2, TurnOwnerLock::acquire(dir.path()))
        .await
        .expect("the wait must end at its bound, not run on while the holder is hung");

    let Err(busy) = result else {
        panic!("a hung holder must fail the wait, not grant a lock: {result:?}");
    };
    assert!(busy.waited >= OWNER_WAIT_LIMIT);
    assert!(started.elapsed() < OWNER_WAIT_LIMIT + std::time::Duration::from_secs(1));
    let data = busy.into_acp_error().data.expect("typed error data");
    let message = data["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("being recovered by another Fuigo process") && message.contains("Retry"),
        "the client is told why and what to do: {data}"
    );
    assert_eq!(data["error_kind"], "session_unavailable", "{data}");
    drop(hung);
}

/// A recovery whose marker append outlived its bound keeps a shared hold: actors can take their lock at once, but
/// no second recovery can start (it would append a second marker).
#[tokio::test]
async fn a_downgraded_recovery_admits_owners_but_not_recoverers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let RecoveryLock::Acquired(guard) = try_recovery_lock(dir.path()) else {
        panic!("recoverer must acquire");
    };
    let shared = guard.into_shared().expect("shared hold");
    assert!(matches!(
        try_recovery_lock(dir.path()),
        RecoveryLock::HeldElsewhere
    ));
    let owner = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        TurnOwnerLock::acquire(dir.path()),
    )
    .await
    .expect("an owner is admitted at once")
    .expect("not busy");
    assert!(owner.is_some());
    drop(shared);
    drop(owner);
    assert!(
        matches!(try_recovery_lock(dir.path()), RecoveryLock::Acquired(_)),
        "released holds must make the session recoverable"
    );
}

/// P122 (P75 P-8): a forked child that has not exec'd yet holds a copy of the lock's open file description, and a
/// `flock` belongs to that description, so closing the parent's descriptor alone does not release it. Dropping a
/// guard must unlock explicitly. `try_clone` makes exactly that inherited copy: no fork, no timing.
/// Mutant discriminated: a guard that only closes its descriptor on drop.
#[tokio::test]
async fn a_dropped_owner_lock_releases_the_session_even_while_a_copy_of_its_descriptor_lives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let owner = TurnOwnerLock::acquire(dir.path())
        .await
        .expect("not busy")
        .expect("owner lock");
    let inherited = owner.file().try_clone().expect("inherited copy");
    assert!(matches!(
        try_recovery_lock(dir.path()),
        RecoveryLock::HeldElsewhere
    ));
    drop(owner);
    assert!(
        matches!(try_recovery_lock(dir.path()), RecoveryLock::Acquired(_)),
        "the session is recoverable the moment the owner is dropped"
    );
    drop(inherited);
}

/// The same for a recovery's exclusive guard.
#[test]
fn a_dropped_recovery_guard_releases_the_session_even_while_a_copy_of_its_descriptor_lives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let RecoveryLock::Acquired(guard) = try_recovery_lock(dir.path()) else {
        panic!("recoverer must acquire");
    };
    let inherited = guard.file().try_clone().expect("inherited copy");
    drop(guard);
    assert!(
        matches!(try_recovery_lock(dir.path()), RecoveryLock::Acquired(_)),
        "the session is recoverable the moment the guard is dropped"
    );
    drop(inherited);
}

/// The hand-over keeps the hold (shared) and the lock it hands over releases explicitly too.
/// Mutant discriminated: `into_shared` unlocking the descriptor it hands over.
#[test]
fn a_downgraded_recovery_keeps_its_hold_and_releases_it_when_dropped_with_a_copy_alive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let RecoveryLock::Acquired(guard) = try_recovery_lock(dir.path()) else {
        panic!("recoverer must acquire");
    };
    let inherited = guard.file().try_clone().expect("inherited copy");
    let shared = guard.into_shared().expect("shared hold");
    assert!(
        matches!(try_recovery_lock(dir.path()), RecoveryLock::HeldElsewhere),
        "the hand-over keeps the session held"
    );
    drop(shared);
    assert!(
        matches!(try_recovery_lock(dir.path()), RecoveryLock::Acquired(_)),
        "dropping the handed-over lock releases the session"
    );
    drop(inherited);
}

/// P122 Astra r1 MEDIUM: a conversion that fails may leave the exclusive hold in place (Linux `ENOMEM` before it touches
/// the lock), so `into_shared` unlocks explicitly on that path too, even while a copy of the descriptor lives.
/// Mutant discriminated: the failure path only closing the descriptor.
#[test]
fn a_failed_downgrade_releases_the_session_even_while_a_copy_of_its_descriptor_lives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let RecoveryLock::Acquired(guard) = try_recovery_lock(dir.path()) else {
        panic!("recoverer must acquire");
    };
    let inherited = guard.file().try_clone().expect("inherited copy");
    let shared = guard.into_shared_with(|_| Err(std::io::Error::from_raw_os_error(12)));
    assert!(shared.is_none(), "the conversion failed");
    assert!(
        matches!(try_recovery_lock(dir.path()), RecoveryLock::Acquired(_)),
        "a failed hand-over does not leave the session held"
    );
    drop(inherited);
}

/// P145 (S14): `turn_owner.lock` is a session file and is created owner-only like the others; on Windows the same
/// call replaces the inherited ACL with an owner-only one (verified live, see R145).
#[cfg(unix)]
#[test]
fn p145_turn_owner_lock_is_created_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let _guard = try_recovery_lock(dir.path());
    let mode = std::fs::metadata(dir.path().join(TURN_OWNER_LOCK_FILE))
        .expect("lock file exists")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

/// An existing lock file with a loose mode (an older version, a restored backup) is tightened when it is opened.
#[cfg(unix)]
#[test]
fn p145_a_loose_turn_owner_lock_is_tightened_on_open() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(TURN_OWNER_LOCK_FILE);
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _guard = try_recovery_lock(dir.path());
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
}
