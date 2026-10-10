//! Follow-up D items 2 and 3: the shared bookkeeping file under concurrent writers, and under an unwritable home.
use super::*;
use serial_test::serial;
use std::sync::atomic::Ordering;

const URL: &str = "http://127.0.0.1:9/v1";
const T0: u64 = 1_800_000_000;

/// Two writers, each with its own handle on everything (as two processes would have), 100 "record a 401" updates
/// each for different credentials. A pause between each load and its save makes the overlap certain. Without the
/// lock some increments of the URL-wide count are lost; with it, none.
#[test]
#[serial]
fn concurrent_writers_lose_no_401_count() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(FILE_NAME);
    test_clock::SLEEP_BETWEEN_LOAD_AND_SAVE_US.store(1500, Ordering::SeqCst);
    let workers: Vec<_> = ["fuigo-test-not-a-key-a", "fuigo-test-not-a-key-b"]
        .into_iter()
        .map(|cred| {
            let path = path.clone();
            std::thread::spawn(move || {
                let mem = RouteMemory::at(path);
                for _ in 0..100 {
                    mem.note_models_401(URL, &[cred], T0);
                    // Real processes do other work between two updates; a spin with no gap starves the other
                    // writer's polling (a lock is not a queue) and it gives up after its 200 ms.
                    std::thread::sleep(std::time::Duration::from_millis(3));
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    test_clock::SLEEP_BETWEEN_LOAD_AND_SAVE_US.store(0, Ordering::SeqCst);
    let store = RouteMemory::at(path).load();
    assert_eq!(store.models_401_url.len(), 1);
    assert_eq!(store.models_401_url[0].n, 200, "every one of the 200 updates is counted");
    let mut per: Vec<u32> = store.models_401.iter().map(|e| e.n).collect();
    per.sort();
    assert_eq!(per, vec![100, 100], "and each credential's own count is complete");
}

/// A home that cannot be written (a path under a regular FILE; works as root too): inside one process the URL cap and
/// the credential's own wait still hold. (Across processes nothing can be remembered; that is the limit.)
#[test]
#[serial]
fn an_unwritable_home_still_holds_the_cap_inside_one_process() {
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("a-regular-file");
    std::fs::write(&blocker, b"x").unwrap();
    let mem = RouteMemory::at(blocker.join(FILE_NAME));
    for k in 0..3 {
        mem.note_models_401(URL, &[&format!("fuigo-test-not-a-key-{k}")], T0 + k);
    }
    assert!(!mem.path().exists(), "precondition: nothing could be written");
    let w = mem.models_wait(URL, &["fuigo-test-not-a-key-new"], T0 + 10);
    assert!(w.is_some(), "three rejected credentials: the URL wait holds for a new one in this process");
    assert!(mem.models_wait(URL, &["fuigo-test-not-a-key-0"], T0 + 10).is_some(), "own wait holds");
    mem.clear_all_models_401(T0 + 11);
    assert!(mem.models_wait(URL, &["fuigo-test-not-a-key-new"], T0 + 11).is_none(), "a sign-in clears it");
    assert!(mem.models_wait(URL, &["fuigo-test-not-a-key-0"], T0 + 11).is_none());
}

/// A lock file that cannot be opened never blocks and never crashes: the update proceeds without it.
#[test]
#[serial]
fn a_lock_that_cannot_be_opened_does_not_block_the_update() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(FILE_NAME);
    std::fs::create_dir(dir.path().join(LOCK_NAME)).unwrap(); // a directory where the lock file should be
    let mem = RouteMemory::at(path);
    mem.note_models_401(URL, &["fuigo-test-not-a-key-a"], T0);
    assert!(mem.models_wait(URL, &["fuigo-test-not-a-key-a"], T0 + 1).is_some(), "written without the lock");
}

/// A lock held by someone else for longer than the wait: proceed without it, at most ~0.2 s late.
#[test]
#[serial]
fn a_lock_held_too_long_is_given_up_on() {
    use fs2::FileExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(FILE_NAME);
    let holder = std::fs::File::create(dir.path().join(LOCK_NAME)).unwrap();
    holder.lock_exclusive().unwrap();
    let mem = RouteMemory::at(path);
    let start = std::time::Instant::now();
    mem.note_models_401(URL, &["fuigo-test-not-a-key-a"], T0);
    assert!(start.elapsed() < std::time::Duration::from_secs(2), "bounded wait");
    assert!(mem.models_wait(URL, &["fuigo-test-not-a-key-a"], T0 + 1).is_some());
    holder.unlock().unwrap();
}
