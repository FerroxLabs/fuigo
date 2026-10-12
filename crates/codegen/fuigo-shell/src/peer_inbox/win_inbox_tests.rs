//! Packet 15c, group B: file-only tests of the Windows inbox (no pipe). Each has its own temp directory standing in for
//! `<home>\peers`; the locator code under test is the real one.

use super::*;
use crate::peer_inbox::rows::{decode_rows, encode_rows};

fn hid(c: char) -> HostId {
    HostId::new(&c.to_string().repeat(32)).unwrap()
}

fn row(c: char, pid: u32) -> HostRow {
    HostRow { host_id: hid(c), pid, started: 100, dir: HostDir::Home }
}

fn setup() -> (tempfile::TempDir, Arc<CheckedDir>) {
    let td = tempfile::tempdir().unwrap();
    let dir = Arc::new(CheckedDir::for_test(td.path().to_path_buf()));
    (td, dir)
}

fn put(dir: &CheckedDir, rows: &[HostRow]) {
    let b = encode_rows(rows).unwrap();
    update_locator(dir, LOCATOR_NAME, move |_| Some(b)).unwrap();
}

fn stored(dir: &CheckedDir) -> Vec<HostRow> {
    decode_rows(read_locator(dir, LOCATOR_NAME).unwrap().as_deref())
}

#[tokio::test]
async fn rows_of_other_hosts_come_from_the_locator_without_ours_and_capped() {
    let (_td, dir) = setup();
    assert!(read_others(&dir, &hid('a'), 8).await.unwrap().is_empty(), "no file: no rows");
    put(&dir, &[row('a', 1), row('b', 2), row('c', 3)]);
    let rows = read_others(&dir, &hid('a'), 8).await.unwrap();
    assert_eq!(rows, vec![row('b', 2), row('c', 3)]);
    assert_eq!(read_others(&dir, &hid('a'), 1).await.unwrap().len(), 1);
}

#[test]
fn our_row_is_added_then_removed_and_other_rows_are_never_touched() {
    let (_td, dir) = setup();
    put(&dir, &[row('b', 2)]);
    publish_row(&dir, row('a', 1)).unwrap();
    assert_eq!(stored(&dir), vec![row('b', 2), row('a', 1)]);
    remove_own_row(&dir, &hid('a'));
    assert_eq!(stored(&dir), vec![row('b', 2)]);
    remove_own_row(&dir, &hid('a'));
    assert_eq!(stored(&dir), vec![row('b', 2)], "idempotent");
    remove_own_row(&dir, &hid('b'));
    assert!(read_locator(&dir, LOCATOR_NAME).unwrap().is_none(), "the last row takes the file with it");
}

#[test]
fn a_full_locator_refuses_our_row_with_locator_full_and_changes_nothing() {
    let (_td, dir) = setup();
    let full: Vec<HostRow> = (0..fuigo_peer::locator_row::MAX_ROWS)
        .map(|i| HostRow { host_id: HostId::new(&format!("{i:032x}")).unwrap(), pid: 1, started: 1, dir: HostDir::Home })
        .collect();
    put(&dir, &full);
    assert_eq!(publish_row(&dir, row('a', 1)).err(), Some(Disabled::LocatorFull));
    assert_eq!(stored(&dir), full);
}

#[tokio::test]
async fn a_rejected_locator_gives_no_rows_a_typed_reason_and_no_panic() {
    let (td, dir) = setup();
    std::fs::create_dir(td.path().join(LOCATOR_NAME)).unwrap();
    let r = read_others(&dir, &hid('a'), 8).await;
    assert!(matches!(r, Err(Disabled::Rejected(_))), "{r:?}");
    assert!(publish_row(&dir, row('a', 1)).is_err());
    assert!(td.path().join(LOCATOR_NAME).is_dir(), "the directory is untouched");
}

#[tokio::test]
async fn a_garbage_locator_is_no_rows_and_is_rewritten_by_our_publish() {
    let (td, dir) = setup();
    // Created through the real writer so it passes the file checks (owner-only), then replaced by garbage bytes.
    update_locator(&dir, LOCATOR_NAME, |_| Some(b"this is not json".to_vec())).unwrap();
    assert!(read_others(&dir, &hid('a'), 8).await.unwrap().is_empty());
    publish_row(&dir, row('a', 1)).unwrap();
    assert_eq!(stored(&dir), vec![row('a', 1)]);
    drop(td);
}

fn make_tmp(td: &tempfile::TempDir, dir: &CheckedDir, name: &str, age: Duration) {
    // A file written by the real writer (owner-only descriptor), moved to a temp name and aged.
    update_locator(dir, "scratch", |_| Some(b"x".to_vec())).unwrap();
    let to = td.path().join(name);
    std::fs::rename(td.path().join("scratch"), &to).unwrap();
    let f = std::fs::OpenOptions::new().write(true).open(&to).unwrap();
    f.set_modified(std::time::SystemTime::now() - age).unwrap();
}

#[test]
fn stale_temp_files_are_swept_young_and_other_files_stay_and_the_count_is_bounded() {
    let (td, dir) = setup();
    put(&dir, &[row('b', 2)]);
    make_tmp(&td, &dir, ".tmp-1-1", Duration::from_secs(11 * 60));
    make_tmp(&td, &dir, ".tmp-1-2", Duration::from_secs(60 * 60));
    make_tmp(&td, &dir, ".tmp-1-3", Duration::from_secs(60 * 60));
    make_tmp(&td, &dir, ".tmp-1-young", Duration::from_secs(5));
    make_tmp(&td, &dir, "other-old", Duration::from_secs(60 * 60));
    let names = |td: &tempfile::TempDir| {
        let mut v: Vec<String> =
            std::fs::read_dir(td.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        v.sort();
        v
    };
    // Bounded: at most 2 of the 3 old ones go.
    let n = super::super::win_locator::sweep_stale_temps(&dir, STALE_TEMP_AGE, 2).unwrap();
    assert_eq!(n, 2);
    assert_eq!(names(&td).iter().filter(|n| n.starts_with(".tmp-1-") && *n != ".tmp-1-young").count(), 1);
    let n = super::super::win_locator::sweep_stale_temps(&dir, STALE_TEMP_AGE, STALE_TEMP_MAX).unwrap();
    assert_eq!(n, 1);
    let left = names(&td);
    assert!(left.contains(&".tmp-1-young".to_owned()), "{left:?}");
    assert!(left.contains(&"other-old".to_owned()), "{left:?}");
    assert!(left.contains(&LOCATOR_NAME.to_owned()), "{left:?}");
    assert!(!left.iter().any(|n| n.starts_with(".tmp-1-") && n != ".tmp-1-young"), "{left:?}");
    assert_eq!(stored(&dir), vec![row('b', 2)], "the locator is untouched");
}

#[test]
fn an_upper_case_temp_prefix_is_swept_too_and_the_decision_uses_the_handle_times() {
    let (td, dir) = setup();
    make_tmp(&td, &dir, ".TMP-2-1", Duration::from_secs(60 * 60));
    make_tmp(&td, &dir, ".TMP-2-young", Duration::from_secs(5));
    let n = super::super::win_locator::sweep_stale_temps(&dir, STALE_TEMP_AGE, STALE_TEMP_MAX).unwrap();
    assert_eq!(n, 1);
    assert!(!td.path().join(".TMP-2-1").exists());
    assert!(td.path().join(".TMP-2-young").exists());
}

fn mine() -> HostRow {
    row('a', std::process::id())
}

/// Wait (bounded) until our row is not in the locator.
fn gone_soon(dir: &CheckedDir) -> bool {
    for _ in 0..200 {
        if !stored(dir).iter().any(|r| r.host_id == hid('a')) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

#[tokio::test]
async fn a_start_cancelled_before_the_publish_runs_never_writes_a_row() {
    let (_td, dir) = setup();
    put(&dir, &[row('b', 2)]);
    let gate = Arc::new(PublishGate::default());
    let guard = RowGuard { dir: dir.clone(), host_id: hid('a'), gate: gate.clone(), armed: true };
    drop(guard); // cancelled: the undo runs (queued on a blocking thread)
    assert!(gone_soon(&dir));
    // the publish that was queued behind it runs late and must do nothing
    gate.publish(&dir, mine()).unwrap();
    assert_eq!(stored(&dir), vec![row('b', 2)]);
}

#[tokio::test]
async fn a_start_cancelled_while_the_publish_runs_leaves_no_row() {
    let (_td, dir) = setup();
    let gate = Arc::new(PublishGate::default());
    // the publish holds the gate while it writes; the guard is dropped meanwhile
    let held = gate.lock.lock().unwrap();
    let (g2, d2) = (gate.clone(), dir.clone());
    let publisher = std::thread::spawn(move || {
        // blocked on the gate until `held` is released, i.e. strictly after the cancel
        g2.publish(&d2, mine()).unwrap();
    });
    let guard = RowGuard { dir: dir.clone(), host_id: hid('a'), gate: gate.clone(), armed: true };
    drop(guard);
    std::thread::sleep(Duration::from_millis(100));
    drop(held);
    publisher.join().unwrap();
    assert!(gone_soon(&dir), "no row after a cancelled start");
    assert!(!stored(&dir).iter().any(|r| r.host_id == hid('a')));
}

#[test]
fn a_publish_that_finished_before_the_cancel_is_undone_in_order() {
    let (_td, dir) = setup();
    let gate = Arc::new(PublishGate::default());
    gate.publish(&dir, mine()).unwrap();
    assert!(stored(&dir).iter().any(|r| r.host_id == hid('a')));
    // outside any runtime: the guard removes the row synchronously
    drop(RowGuard { dir: dir.clone(), host_id: hid('a'), gate, armed: true });
    assert!(stored(&dir).is_empty());
}

#[test]
fn a_dropped_inbox_row_is_removed_synchronously_when_there_is_no_runtime() {
    // The same path `PeerInbox::drop` takes without a runtime: `remove_own_row` on the calling thread.
    let (_td, dir) = setup();
    put(&dir, &[mine(), row('b', 2)]);
    assert!(tokio::runtime::Handle::try_current().is_err());
    remove_own_row(&dir, &hid('a'));
    assert_eq!(stored(&dir), vec![row('b', 2)]);
}
