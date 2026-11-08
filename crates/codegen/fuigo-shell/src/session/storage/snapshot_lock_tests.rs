//! design F5 §5.6: `snapshot.lock` is a lock sidecar made through the session writer, so it carries B-F5 marks, and a
//! writer that is not held opens nothing (no by-path fallback).

use super::*;

fn marks_for(marks: &Path, kind: &str) -> std::collections::HashSet<String> {
    std::fs::read_dir(marks)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let rest = name.strip_prefix(&format!("{kind}."))?.to_string();
                    rest.rsplit('.').next().map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn lock_hashes(writer: &fuigo_session_writer::SessionWriter) -> Vec<String> {
    let plain = writer.dir().join(SNAPSHOT_LOCK_FILE);
    let mut hashes = vec![fuigo_session_writer::trace::path_hash(&plain)];
    if let Ok(real) = dunce::canonicalize(writer.dir()) {
        hashes.push(fuigo_session_writer::trace::path_hash(&real.join(SNAPSHOT_LOCK_FILE)));
    }
    hashes
}

#[tokio::test(flavor = "current_thread")]
async fn the_turn_start_snapshot_lock_is_opened_by_the_session_writer_with_marks() {
    let root = tempfile::tempdir().unwrap();
    let marks = root.path().join("f5-marks");
    let dir = root.path().join("sessions").join("snap-marks");
    std::fs::create_dir_all(&dir).unwrap();
    let writer = fuigo_session_writer::SessionWriter::try_claim(uuid::Uuid::now_v7().to_string(), &dir).expect("claim");
    fuigo_session_writer::trace::set_test_trace_dir(Some(marks.clone()));
    let held = acquire_async(&writer).await;
    let taken = held.is_some();
    drop(held);
    let blocking = acquire_blocking_as(Opener::Writer(&writer), &lock_path(&dir), &dir);
    fuigo_session_writer::trace::set_test_trace_dir(None);
    assert!(taken, "the actor's snapshot lock was not taken");
    assert!(matches!(blocking, Ok(Some(_))), "the fork's snapshot lock was not taken as the writer");
    let hashes = lock_hashes(&writer);
    let (begins, ends) = (marks_for(&marks, "b"), marks_for(&marks, "e"));
    assert!(hashes.iter().any(|h| begins.contains(h)), "no b mark for snapshot.lock: {begins:?}");
    assert!(hashes.iter().any(|h| ends.contains(h)), "no e mark for snapshot.lock: {ends:?}");
    assert!(dir.join(SNAPSHOT_LOCK_FILE).is_file());
}

#[tokio::test(flavor = "current_thread")]
async fn a_writer_that_is_not_held_opens_no_snapshot_lock() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("sessions").join("snap-gone");
    std::fs::create_dir_all(&dir).unwrap();
    let writer = fuigo_session_writer::SessionWriter::try_claim(uuid::Uuid::now_v7().to_string(), &dir).expect("claim");
    // The writer lets its hold go for a wipe: every later mutating call on it is refused and writes nothing.
    writer.delete_tree_sync().expect("delete");
    std::fs::create_dir_all(&dir).unwrap();
    assert!(acquire_async(&writer).await.is_none(), "a released writer took the snapshot lock");
    assert!(matches!(acquire_blocking_as(Opener::Writer(&writer), &lock_path(&dir), &dir), Ok(None)));
    assert!(!dir.join(SNAPSHOT_LOCK_FILE).exists(), "snapshot.lock was created by path without the writer's hold");
}
