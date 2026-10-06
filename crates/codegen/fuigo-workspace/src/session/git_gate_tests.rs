use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

use super::{FlightOp, GitGate};

fn init_temp_repo() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let repo = git2::Repository::init(tmp.path()).unwrap();
    repo.config().unwrap().set_str("user.name", "test").unwrap();
    repo.config()
        .unwrap()
        .set_str("user.email", "test@test.com")
        .unwrap();
    std::fs::write(tmp.path().join("README"), "hi\n").unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(Path::new("README")).unwrap();
    index.write().unwrap();
    let oid = index.write_tree().unwrap();
    let tree = repo.find_tree(oid).unwrap();
    let sig = git2::Signature::now("test", "test@test.com").unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[])
        .unwrap();
    tmp
}

fn status_op() -> FlightOp {
    FlightOp::Status {
        include_untracked: false,
        include_stats: false,
        ignore_submodules: true,
        include_patches: false,
    }
}

fn diff_op() -> FlightOp {
    FlightOp::Diff {
        from: "HEAD".into(),
        to: "working".into(),
        merge_base: false,
        include_patch: false,
        include_content: false,
        paths: Vec::new(),
    }
}

fn test_gate(snapshot_ttl: Duration, walk_timeout: Duration) -> GitGate {
    GitGate::with_config(snapshot_ttl, walk_timeout, 1, Duration::from_secs(2))
}

/// `GitGate::invalidate` resolves the root through the process-wide ROOT_CACHE, which every other gate user clears or refills.
/// A test that calls it must run in a process of its own (`rerun_in_own_process`), and fails loudly here when it does not.
fn invalidate_checked(gate: &GitGate, root: &Path) {
    fuigo_test_support::env::assert_own_process("GitGate::invalidate (the shared ROOT_CACHE)");
    gate.invalidate(root);
}

async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if counter.load(Ordering::SeqCst) >= expected {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for walk count {expected} (have {})",
                counter.load(Ordering::SeqCst)
            );
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn concurrent_identical_status_joins_one_walk_from_subdir_or_root() {
    let repo = init_temp_repo();
    let sub = repo.path().join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    let gate = test_gate(Duration::from_secs(5), Duration::from_secs(5));
    let walks = Arc::new(AtomicUsize::new(0));
    let release = tokio::sync::watch::channel(false).0;

    let mk_walk = |walks: Arc<AtomicUsize>, release: tokio::sync::watch::Sender<bool>| {
        move || {
            let walks = Arc::clone(&walks);
            let mut rx = release.subscribe();
            async move {
                walks.fetch_add(1, Ordering::SeqCst);
                while !*rx.borrow() {
                    rx.changed().await.unwrap();
                }
                Ok(7_u32)
            }
        }
    };

    let t1 = {
        let gate = gate.clone();
        let root = repo.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&walks), release.clone());
        tokio::spawn(async move { gate.run(&root, status_op(), walk).await })
    };
    wait_for_count(&walks, 1).await;
    let t2 = {
        let gate = gate.clone();
        let walk = mk_walk(Arc::clone(&walks), release.clone());
        tokio::spawn(async move { gate.run(&sub, status_op(), walk).await })
    };

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(walks.load(Ordering::SeqCst), 1);

    release.send(true).unwrap();
    let a = t1.await.unwrap().unwrap();
    let b = t2.await.unwrap().unwrap();
    assert_eq!((a, b), (7, 7));
}

#[tokio::test]
async fn snapshot_within_ttl_skips_second_walk() {
    let repo = init_temp_repo();
    let gate = test_gate(Duration::from_secs(5), Duration::from_secs(5));
    let walks = Arc::new(AtomicUsize::new(0));
    let walk = {
        let walks = Arc::clone(&walks);
        move || {
            let walks = Arc::clone(&walks);
            async move {
                walks.fetch_add(1, Ordering::SeqCst);
                Ok(3_u32)
            }
        }
    };

    let first = gate
        .run(repo.path(), status_op(), walk.clone())
        .await
        .unwrap();
    let second = gate.run(repo.path(), status_op(), walk).await.unwrap();
    assert_eq!((first, second, walks.load(Ordering::SeqCst)), (3, 3, 1));
}

#[tokio::test]
async fn joiners_do_not_start_a_second_walk() {
    let repo = init_temp_repo();
    let gate = test_gate(Duration::from_millis(500), Duration::from_secs(5));
    let walks = Arc::new(AtomicUsize::new(0));
    let release = tokio::sync::watch::channel(false).0;

    let mk_walk = |walks: Arc<AtomicUsize>, release: tokio::sync::watch::Sender<bool>| {
        move || {
            let walks = Arc::clone(&walks);
            let mut rx = release.subscribe();
            async move {
                walks.fetch_add(1, Ordering::SeqCst);
                while !*rx.borrow() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
                Ok(11_u32)
            }
        }
    };

    let t1 = {
        let gate = gate.clone();
        let root = repo.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&walks), release.clone());
        tokio::spawn(async move { gate.run(&root, status_op(), walk).await })
    };
    wait_for_count(&walks, 1).await;

    let mut joiners = Vec::new();
    for _ in 0..4 {
        let gate = gate.clone();
        let root = repo.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&walks), release.clone());
        joiners.push(tokio::spawn(async move {
            gate.run(&root, status_op(), walk).await
        }));
    }

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(walks.load(Ordering::SeqCst), 1);

    release.send(true).unwrap();
    let first = t1.await.unwrap().unwrap();
    for joiner in joiners {
        assert_eq!(joiner.await.unwrap().unwrap(), first);
    }

    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(walks.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn status_and_diffs_never_overlap_odb_walks() {
    let repo = init_temp_repo();
    let gate = test_gate(Duration::from_millis(1), Duration::from_secs(5));
    let in_walk = Arc::new(AtomicUsize::new(0));
    let max_in_walk = Arc::new(AtomicUsize::new(0));

    let mk_walk = |in_walk: Arc<AtomicUsize>, max_in_walk: Arc<AtomicUsize>, value: u32| {
        move || {
            let in_walk = Arc::clone(&in_walk);
            let max_in_walk = Arc::clone(&max_in_walk);
            async move {
                let current = in_walk.fetch_add(1, Ordering::SeqCst) + 1;
                max_in_walk.fetch_max(current, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(60)).await;
                in_walk.fetch_sub(1, Ordering::SeqCst);
                Ok(value)
            }
        }
    };

    let status = {
        let gate = gate.clone();
        let root = repo.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&in_walk), Arc::clone(&max_in_walk), 1);
        tokio::spawn(async move { gate.run(&root, status_op(), walk).await })
    };
    let diffs = {
        let gate = gate.clone();
        let root = repo.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&in_walk), Arc::clone(&max_in_walk), 2);
        tokio::spawn(async move { gate.run(&root, diff_op(), walk).await })
    };

    let a = status.await.unwrap().unwrap();
    let b = diffs.await.unwrap().unwrap();
    assert_eq!(max_in_walk.load(Ordering::SeqCst), 1);
    assert!(a == 1 || a == 2);
    assert!(b == 1 || b == 2);
}

#[tokio::test]
async fn walk_timeout_without_snapshot_is_error() {
    let repo = init_temp_repo();
    let gate = test_gate(Duration::from_secs(5), Duration::from_millis(30));
    let hang = Arc::new(Notify::new());
    let result = gate
        .run(repo.path(), status_op(), {
            let hang = Arc::clone(&hang);
            move || {
                let hang = Arc::clone(&hang);
                async move {
                    hang.notified().await;
                    Ok(1_u32)
                }
            }
        })
        .await;
    assert!(result.unwrap_err().to_string().contains("timed out"));
}

#[tokio::test]
async fn walk_timeout_after_ttl_does_not_resurrect_snapshot() {
    let repo = init_temp_repo();
    let gate = test_gate(Duration::from_millis(20), Duration::from_millis(40));
    let ok_walk = || async { Ok(9_u32) };
    assert_eq!(
        gate.run(repo.path(), status_op(), ok_walk).await.unwrap(),
        9
    );

    tokio::time::sleep(Duration::from_millis(40)).await;

    let hang = Arc::new(Notify::new());
    let timed = gate
        .run(repo.path(), status_op(), {
            let hang = Arc::clone(&hang);
            move || {
                let hang = Arc::clone(&hang);
                async move {
                    hang.notified().await;
                    Ok(10_u32)
                }
            }
        })
        .await;
    assert!(timed.unwrap_err().to_string().contains("timed out"));
}

#[tokio::test]
async fn late_ok_after_waiter_timeout_is_snapshotted() {
    let repo = init_temp_repo();
    let gate = test_gate(Duration::from_secs(5), Duration::from_millis(40));
    let walks = Arc::new(AtomicUsize::new(0));
    let hang = Arc::new(Notify::new());

    let timed = gate
        .run(repo.path(), status_op(), {
            let hang = Arc::clone(&hang);
            let walks = Arc::clone(&walks);
            move || {
                let hang = Arc::clone(&hang);
                let walks = Arc::clone(&walks);
                async move {
                    walks.fetch_add(1, Ordering::SeqCst);
                    hang.notified().await;
                    Ok(10_u32)
                }
            }
        })
        .await;
    assert!(timed.unwrap_err().to_string().contains("timed out"));
    assert_eq!(walks.load(Ordering::SeqCst), 1);

    hang.notify_waiters();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let later = gate
        .run(repo.path(), status_op(), {
            let walks = Arc::clone(&walks);
            move || {
                let walks = Arc::clone(&walks);
                async move {
                    walks.fetch_add(1, Ordering::SeqCst);
                    Ok(99_u32)
                }
            }
        })
        .await
        .unwrap();
    assert_eq!(later, 10);
    assert_eq!(walks.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalidate_skips_ttl_and_forces_new_walk() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let repo = init_temp_repo();
    let gate = test_gate(Duration::from_secs(5), Duration::from_secs(5));
    let walks = Arc::new(AtomicUsize::new(0));
    let mk = |walks: Arc<AtomicUsize>, value: u32| {
        move || {
            let walks = Arc::clone(&walks);
            async move {
                walks.fetch_add(1, Ordering::SeqCst);
                Ok(value)
            }
        }
    };

    assert_eq!(
        gate.run(repo.path(), status_op(), mk(Arc::clone(&walks), 1))
            .await
            .unwrap(),
        1
    );
    invalidate_checked(&gate, repo.path());
    assert_eq!(
        gate.run(repo.path(), status_op(), mk(Arc::clone(&walks), 2))
            .await
            .unwrap(),
        2
    );
    assert_eq!(walks.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_leader_does_not_wedge_slot() {
    let repo = init_temp_repo();
    let gate = test_gate(Duration::from_secs(5), Duration::from_secs(5));
    let walks = Arc::new(AtomicUsize::new(0));
    let release = tokio::sync::watch::channel(false).0;

    let mk_walk =
        |walks: Arc<AtomicUsize>, release: tokio::sync::watch::Sender<bool>, value: u32| {
            move || {
                let walks = Arc::clone(&walks);
                let mut rx = release.subscribe();
                async move {
                    walks.fetch_add(1, Ordering::SeqCst);
                    while !*rx.borrow() {
                        if rx.changed().await.is_err() {
                            break;
                        }
                    }
                    Ok(value)
                }
            }
        };

    tokio::select! {
        biased;
        result = gate.run(
            repo.path(),
            status_op(),
            mk_walk(Arc::clone(&walks), release.clone(), 1)
        ) => {
            panic!("leader finished before cancel: {result:?}");
        }
        _ = wait_for_count(&walks, 1) => {}
    }

    let after = gate.run(
        repo.path(),
        status_op(),
        mk_walk(Arc::clone(&walks), release.clone(), 2),
    );
    release.send(true).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), after)
        .await
        .expect("git gate stayed wedged after leader cancel")
        .unwrap_or_else(|error| panic!("{error:#}"));
    assert_eq!(got, 1);
    assert_eq!(walks.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalidate_during_inflight_does_not_return_stale_walk() {
    // `invalidate` finds the root through the process-wide ROOT_CACHE, which other gate tests clear (the unresolved-root path, a full cache).
    // A process of its own keeps that cache stable, so this test exercises the targeted path; the cleared-cache and
    // invalidate-all paths have their own tests below.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let repo = init_temp_repo();
    // Two ODB permits: the post-invalidate walk must be able to START while the first is still held open, or waiting for it below could never succeed.
    let gate = GitGate::with_config(
        Duration::from_secs(5),
        Duration::from_secs(5),
        2,
        Duration::from_secs(2),
    );
    let walks = Arc::new(AtomicUsize::new(0));
    let release = tokio::sync::watch::channel(false).0;

    let mk_walk = |walks: Arc<AtomicUsize>, release: tokio::sync::watch::Sender<bool>| {
        move || {
            let walks = Arc::clone(&walks);
            let mut rx = release.subscribe();
            async move {
                let n = walks.fetch_add(1, Ordering::SeqCst) + 1;
                while !*rx.borrow() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
                Ok(n)
            }
        }
    };

    let first = {
        let gate = gate.clone();
        let root = repo.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&walks), release.clone());
        tokio::spawn(async move { gate.run(&root, status_op(), walk).await })
    };
    wait_for_count(&walks, 1).await;
    invalidate_checked(&gate, repo.path());

    let second = {
        let gate = gate.clone();
        let root = repo.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&walks), release.clone());
        tokio::spawn(async move { gate.run(&root, status_op(), walk).await })
    };

    // Release only once the post-invalidate caller has started its own walk: releasing while its task may not have run yet lets the first walk finish and be seen first.
    wait_for_count(&walks, 2).await;
    release.send(true).unwrap();
    let after_invalidate = tokio::time::timeout(Duration::from_secs(2), second)
        .await
        .expect("post-invalidate status hung")
        .unwrap()
        .unwrap();
    assert_eq!(after_invalidate, 2);
    wait_for_count(&walks, 2).await;
    let _ = first.await;
}

/// The process-wide root cache is cleared by any invalidate whose root does not resolve (another
/// session, another test). An invalidate that lands after that, while this root's FIRST walk is in
/// flight, must still retire that walk: the next caller gets a fresh walk, not the stale one.
/// Before the fix the root resolved to nothing, the invalidate-all fallback bumped only roots that
/// already had an epoch, and the in-flight walk at the implicit epoch 0 stayed current.
#[tokio::test]
async fn invalidate_after_root_cache_clear_still_retires_the_inflight_walk() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let repo = init_temp_repo();
    // Two ODB permits: the stale walk keeps one while it is held open, and the fresh walk this
    // test expects needs the other. `test_gate`'s single permit would starve it.
    // Waiter timeout (60 s) above the 30 s observation window: a first caller that timed out and
    // retried at the new epoch would start another HELD walk the second caller could join.
    let gate = GitGate::with_config(
        Duration::from_secs(5),
        Duration::from_secs(60),
        2,
        Duration::from_secs(30),
    );
    let walks = Arc::new(AtomicUsize::new(0));
    let release = tokio::sync::watch::channel(false).0;
    let mk_walk = |walks: Arc<AtomicUsize>, release: tokio::sync::watch::Sender<bool>| {
        move || {
            let walks = Arc::clone(&walks);
            let mut rx = release.subscribe();
            async move {
                let n = walks.fetch_add(1, Ordering::SeqCst) + 1;
                while !*rx.borrow() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
                Ok(n)
            }
        }
    };
    let first = {
        let gate = gate.clone();
        let root = repo.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&walks), release.clone());
        tokio::spawn(async move { gate.run(&root, status_op(), walk).await })
    };
    wait_for_count(&walks, 1).await;
    // What a peer's unresolvable invalidate does to the shared cache.
    super::ROOT_CACHE.lock().clear();
    invalidate_checked(&gate, repo.path());
    // Fresh walks finish at once; only `first` was waiting on `release`.
    let fresh = tokio::sync::watch::channel(true).0;
    let second = {
        let gate = gate.clone();
        let root = repo.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&walks), fresh);
        tokio::spawn(async move { gate.run(&root, status_op(), walk).await })
    };
    let after_invalidate = tokio::time::timeout(Duration::from_secs(30), second)
        .await
        .expect("post-invalidate status hung")
        .unwrap()
        .unwrap();
    assert_eq!(
        after_invalidate, 2,
        "the walk begun before the invalidate must not be joined"
    );
    release.send(true).unwrap();
    let _ = first.await;
}

/// The invalidate-all fallback (a path that resolves to no tracked root) must retire EVERY tracked
/// root's in-flight walk, including a root that has never been invalidated and so has no epoch
/// entry yet. Bumping only existing epoch entries left such a walk current.
#[tokio::test]
async fn invalidate_all_retires_a_root_that_has_no_epoch_yet() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let repo = init_temp_repo();
    // Waiter timeout (60 s) above the 30 s observation window: a first caller that timed out and
    // retried at the new epoch would start another HELD walk the second caller could join.
    let gate = GitGate::with_config(
        Duration::from_secs(5),
        Duration::from_secs(60),
        2,
        Duration::from_secs(30),
    );
    let walks = Arc::new(AtomicUsize::new(0));
    let release = tokio::sync::watch::channel(false).0;
    let mk_walk = |walks: Arc<AtomicUsize>, release: tokio::sync::watch::Sender<bool>| {
        move || {
            let walks = Arc::clone(&walks);
            let mut rx = release.subscribe();
            async move {
                let n = walks.fetch_add(1, Ordering::SeqCst) + 1;
                while !*rx.borrow() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
                Ok(n)
            }
        }
    };
    let first = {
        let gate = gate.clone();
        let root = repo.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&walks), release.clone());
        tokio::spawn(async move { gate.run(&root, status_op(), walk).await })
    };
    wait_for_count(&walks, 1).await;
    // A path that is no repository and no tracked root: the invalidate-all path.
    let elsewhere = tempfile::tempdir().unwrap();
    invalidate_checked(&gate, &elsewhere.path().join("not-a-repo"));
    let fresh = tokio::sync::watch::channel(true).0;
    let second = {
        let gate = gate.clone();
        let root = repo.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&walks), fresh);
        tokio::spawn(async move { gate.run(&root, status_op(), walk).await })
    };
    let after_invalidate = tokio::time::timeout(Duration::from_secs(30), second)
        .await
        .expect("post-invalidate status hung")
        .unwrap()
        .unwrap();
    assert_eq!(
        after_invalidate, 2,
        "invalidate-all must retire the walk begun before it"
    );
    release.send(true).unwrap();
    let _ = first.await;
}

/// Invalidating a root whose first walk is in flight stays TARGETED after the process-wide root
/// cache is cleared: the root is recognised from its slot, so another root's snapshot survives.
/// Without slot recognition the invalidate fell through to invalidate-all and threw away every
/// root's snapshot.
#[tokio::test]
async fn targeted_invalidate_of_an_inflight_root_keeps_other_roots_snapshots() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let repo_a = init_temp_repo();
    let repo_b = init_temp_repo();
    // Waiter timeout (60 s) above the 30 s observation window, as above.
    let gate = GitGate::with_config(
        Duration::from_secs(60),
        Duration::from_secs(60),
        2,
        Duration::from_secs(30),
    );
    let walks = Arc::new(AtomicUsize::new(0));
    let mk_walk = |walks: Arc<AtomicUsize>, release: tokio::sync::watch::Sender<bool>| {
        move || {
            let walks = Arc::clone(&walks);
            let mut rx = release.subscribe();
            async move {
                let n = walks.fetch_add(1, Ordering::SeqCst) + 1;
                while !*rx.borrow() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
                Ok(n)
            }
        }
    };
    let open = tokio::sync::watch::channel(true).0;
    let b_first = gate
        .run(
            repo_b.path(),
            status_op(),
            mk_walk(Arc::clone(&walks), open.clone()),
        )
        .await
        .unwrap();
    assert_eq!(b_first, 1, "B's first walk populates its snapshot");

    let hold = tokio::sync::watch::channel(false).0;
    let a_walk = {
        let gate = gate.clone();
        let root = repo_a.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&walks), hold.clone());
        tokio::spawn(async move { gate.run(&root, status_op(), walk).await })
    };
    wait_for_count(&walks, 2).await;
    super::ROOT_CACHE.lock().clear();
    invalidate_checked(&gate, repo_a.path());

    let b_again = gate
        .run(
            repo_b.path(),
            status_op(),
            mk_walk(Arc::clone(&walks), open),
        )
        .await
        .unwrap();
    assert_eq!(b_again, 1, "invalidating A must not discard B's snapshot");
    assert_eq!(
        walks.load(Ordering::SeqCst),
        2,
        "B is served from its snapshot, not re-walked"
    );
    hold.send(true).unwrap();
    let _ = a_walk.await;
}

#[tokio::test]
async fn waiter_timeout_after_invalidate_does_not_return_stale_ok() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let repo = init_temp_repo();
    let gate = test_gate(Duration::from_secs(5), Duration::from_millis(40));
    let walks = Arc::new(AtomicUsize::new(0));
    let release = tokio::sync::watch::channel(false).0;

    let mk_walk = |walks: Arc<AtomicUsize>, release: tokio::sync::watch::Sender<bool>| {
        move || {
            let walks = Arc::clone(&walks);
            let mut rx = release.subscribe();
            async move {
                let n = walks.fetch_add(1, Ordering::SeqCst) + 1;
                while !*rx.borrow() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
                Ok(n)
            }
        }
    };

    let first = {
        let gate = gate.clone();
        let root = repo.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&walks), release.clone());
        tokio::spawn(async move { gate.run(&root, status_op(), walk).await })
    };
    wait_for_count(&walks, 1).await;
    invalidate_checked(&gate, repo.path());

    let second = {
        let gate = gate.clone();
        let root = repo.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&walks), release.clone());
        tokio::spawn(async move { gate.run(&root, status_op(), walk).await })
    };

    let second_result = tokio::time::timeout(Duration::from_secs(2), second)
        .await
        .expect("post-invalidate status hung")
        .unwrap();
    let err = second_result.expect_err("expected timeout");
    assert!(err.to_string().contains("timed out"), "{err:#}");

    release.send(true).unwrap();
    let _ = first.await;
}

#[tokio::test]
async fn root_cache_expires_so_a_new_nested_repo_is_rediscovered() {
    let parent = init_temp_repo();
    let nested = parent.path().join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    let gate = test_gate(Duration::from_secs(5), Duration::from_secs(5));
    gate.run(parent.path(), status_op(), || async { Ok(1_u32) })
        .await
        .unwrap();

    let before = super::canonical_git_root(&nested).await.unwrap();
    git2::Repository::init(&nested).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let after = super::canonical_git_root(&nested).await.unwrap();
    assert_ne!(before, after);
}

#[tokio::test]
async fn sustained_invalidate_during_inflight_run_returns_after_at_most_two_walks() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let repo = init_temp_repo();
    let walk_timeout = Duration::from_millis(500);
    let gate = test_gate(Duration::from_millis(1), walk_timeout);
    let walks = Arc::new(AtomicUsize::new(0));
    let release = tokio::sync::watch::channel(false).0;

    let mk_walk = |walks: Arc<AtomicUsize>, release: tokio::sync::watch::Sender<bool>| {
        move || {
            let walks = Arc::clone(&walks);
            let mut rx = release.subscribe();
            async move {
                walks.fetch_add(1, Ordering::SeqCst);
                while !*rx.borrow() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
                Ok(1_u32)
            }
        }
    };

    let run = {
        let gate = gate.clone();
        let root = repo.path().to_path_buf();
        let walk = mk_walk(Arc::clone(&walks), release.clone());
        tokio::spawn(async move { gate.run(&root, status_op(), walk).await })
    };
    wait_for_count(&walks, 1).await;
    invalidate_checked(&gate, repo.path());
    release.send(true).unwrap();

    let mut run = run;
    let result = tokio::time::timeout(walk_timeout.saturating_mul(3), async {
        loop {
            tokio::select! {
                biased;
                out = &mut run => break out,
                () = tokio::task::yield_now() => {
                    invalidate_checked(&gate, repo.path());
                }
            }
        }
    })
    .await
    .expect("run did not return under sustained invalidate")
    .expect("run task panicked");

    assert!(result.is_ok(), "{result:?}");
    assert!(walks.load(Ordering::SeqCst) <= super::MAX_EPOCH_RETRIES as usize + 1);
}

#[tokio::test]
async fn expired_snapshots_are_evicted_and_slots_are_capped() {
    let repo = init_temp_repo();
    let gate = test_gate(Duration::from_millis(20), Duration::from_secs(5));

    for i in 0..200u32 {
        let op = FlightOp::Diff {
            from: format!("from-{i}"),
            to: format!("to-{i}"),
            merge_base: false,
            include_patch: false,
            include_content: false,
            paths: vec![format!("p{i}")],
        };
        assert_eq!(
            gate.run(repo.path(), op, move || async move { Ok(i) })
                .await
                .unwrap(),
            i
        );
        assert!(gate.slot_count() <= super::MAX_SLOTS);
    }

    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(
        gate.run(repo.path(), status_op(), || async { Ok(0_u32) })
            .await
            .unwrap(),
        0
    );
    assert!(gate.slot_count() <= super::MAX_SLOTS);
}

#[tokio::test]
async fn patch_and_content_ops_skip_snapshot() {
    let repo = init_temp_repo();
    let gate = test_gate(Duration::from_secs(5), Duration::from_secs(5));

    let cases = [
        FlightOp::Diff {
            from: "HEAD".into(),
            to: "working".into(),
            merge_base: false,
            include_patch: false,
            include_content: true,
            paths: Vec::new(),
        },
        FlightOp::Diff {
            from: "HEAD".into(),
            to: "working".into(),
            merge_base: false,
            include_patch: true,
            include_content: false,
            paths: Vec::new(),
        },
        FlightOp::Status {
            include_untracked: false,
            include_stats: false,
            ignore_submodules: true,
            include_patches: true,
        },
    ];

    for op in cases {
        let walks = Arc::new(AtomicUsize::new(0));
        let mk = |walks: Arc<AtomicUsize>, value: u32| {
            move || {
                let walks = Arc::clone(&walks);
                async move {
                    walks.fetch_add(1, Ordering::SeqCst);
                    Ok(value)
                }
            }
        };
        assert_eq!(
            gate.run(repo.path(), op.clone(), mk(Arc::clone(&walks), 1))
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            gate.run(repo.path(), op, mk(Arc::clone(&walks), 2))
                .await
                .unwrap(),
            2
        );
        assert_eq!(walks.load(Ordering::SeqCst), 2);
    }
}
