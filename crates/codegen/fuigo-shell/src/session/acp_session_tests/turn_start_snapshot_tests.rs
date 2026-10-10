//! P123 (K17): the persistence actor writes a prompt's transcript echo and its chat item under the session's snapshot lock,
//! echo first, so a fork's snapshot sees the prompt in both files or in neither.

use crate::sampling::ConversationItem;
use crate::session::persistence::{PersistenceMsg, test_seam};
use crate::session::storage::StorageAdapter as _;
use agent_client_protocol as acp;

fn user_echo(session: &acp::SessionId, text: &str) -> crate::session::storage::SessionUpdate {
    let chunk = acp::ContentChunk::new(acp::ContentBlock::Text(acp::TextContent::new(text.to_string())))
        .meta(serde_json::json!({ "promptIndex": 0 }).as_object().cloned());
    crate::session::storage::SessionUpdate::Acp(Box::new(acp::SessionNotification::new(
        session.clone(),
        acp::SessionUpdate::UserMessageChunk(chunk),
    )))
}

#[tokio::test(flavor = "current_thread")]
async fn a_prompt_is_written_to_the_transcript_before_its_chat_item_and_under_the_snapshot_lock() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let info = crate::session::info::Info { id: acp::SessionId::new("p123-turn-start"), cwd: "/work".to_string() };
    let dir = crate::session::persistence::session_dir(&info);
    let storage = crate::session::storage::JsonlStorageAdapter::with_explicit_session_dir(dir.clone());
    storage.init_session(&info, crate::session::persistence::default_model_id()).await.unwrap();
    let tx = test_seam::spawn_actor(info.clone(), std::sync::Arc::new(storage));
    let lock_file = crate::session::storage::snapshot_lock::lock_path(&dir);
    let held = crate::session::storage::snapshot_lock::acquire_blocking(&lock_file, &lock_file).unwrap().unwrap();
    crate::session::storage::snapshot_lock::CONTENDED.lock().remove(&lock_file);
    let mut prompt = ConversationItem::user("PROMPT-P123");
    prompt.set_prompt_index(0);
    let turn = crate::session::persistence::SnapshotTurn::begin(&tx);
    tx.send(PersistenceMsg::Update(user_echo(&info.id, "PROMPT-P123"))).unwrap();
    tx.send(PersistenceMsg::Chat(prompt)).unwrap();
    drop(turn);
    // The actor is at the held lock: it wrote neither half.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !crate::session::storage::snapshot_lock::CONTENDED.lock().contains(&lock_file) {
        assert!(std::time::Instant::now() < deadline, "the actor never reached the snapshot lock");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
    assert!(!read("chat_history.jsonl").contains("PROMPT-P123"), "the chat item was written while a snapshot held the lock");
    assert!(!read("updates.jsonl").contains("PROMPT-P123"), "the echo was written while a snapshot held the lock");
    drop(held);
    // When the chat item is on disk its echo already is: no flush barrier is needed to see the transcript half.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !read("chat_history.jsonl").contains("PROMPT-P123") {
        assert!(std::time::Instant::now() < deadline, "the prompt was never written");
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert!(read("updates.jsonl").contains("PROMPT-P123"), "the chat item reached the disk before its transcript echo");
}

/// Astra P123 r3 H1: a prompt with several blocks queues several echoes before its chat item. The turn's begin takes the
/// snapshot lock, so no echo reaches the transcript while a snapshot holds it, and the lock stays until the turn's end.
#[tokio::test(flavor = "current_thread")]
async fn a_multi_block_prompt_holds_the_snapshot_lock_from_its_first_echo() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let info = crate::session::info::Info { id: acp::SessionId::new("p123-multi-block"), cwd: "/work".to_string() };
    let dir = crate::session::persistence::session_dir(&info);
    let storage = crate::session::storage::JsonlStorageAdapter::with_explicit_session_dir(dir.clone());
    storage.init_session(&info, crate::session::persistence::default_model_id()).await.unwrap();
    let tx = test_seam::spawn_actor(info.clone(), std::sync::Arc::new(storage));
    let lock_file = crate::session::storage::snapshot_lock::lock_path(&dir);
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
    // A snapshot holds the lock while two echoes arrive: neither may be written, not even the first one the merge flushes.
    let held = crate::session::storage::snapshot_lock::acquire_blocking(&lock_file, &lock_file).unwrap().unwrap();
    crate::session::storage::snapshot_lock::CONTENDED.lock().remove(&lock_file);
    let turn = crate::session::persistence::SnapshotTurn::begin(&tx);
    tx.send(PersistenceMsg::Update(user_echo(&info.id, "BLOCK-ONE"))).unwrap();
    tx.send(PersistenceMsg::Update(user_echo(&info.id, "BLOCK-TWO"))).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !crate::session::storage::snapshot_lock::CONTENDED.lock().contains(&lock_file) {
        assert!(std::time::Instant::now() < deadline, "the actor never reached the snapshot lock");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(!read("updates.jsonl").contains("BLOCK-"), "an echo was written while a snapshot held the lock");
    drop(held);
    let mut prompt = ConversationItem::user("BLOCK-ONE BLOCK-TWO");
    prompt.set_prompt_index(0);
    tx.send(PersistenceMsg::Chat(prompt)).unwrap();
    drop(turn);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !read("chat_history.jsonl").contains("BLOCK-ONE") {
        assert!(std::time::Instant::now() < deadline, "the prompt was never written");
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert!(read("updates.jsonl").contains("BLOCK-TWO"), "the echoes reached the disk before the chat item");
}

/// A prompt whose chat item arrives with no echo before it (a synthetic turn) takes the snapshot lock itself: while a
/// snapshot holds it the chat item is not written.
#[tokio::test(flavor = "current_thread")]
async fn a_chat_item_without_an_earlier_echo_still_waits_for_the_snapshot_lock() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let info = crate::session::info::Info { id: acp::SessionId::new("p123-no-echo"), cwd: "/work".to_string() };
    let dir = crate::session::persistence::session_dir(&info);
    let storage = crate::session::storage::JsonlStorageAdapter::with_explicit_session_dir(dir.clone());
    storage.init_session(&info, crate::session::persistence::default_model_id()).await.unwrap();
    let tx = test_seam::spawn_actor(info.clone(), std::sync::Arc::new(storage));
    let lock_file = crate::session::storage::snapshot_lock::lock_path(&dir);
    let held = crate::session::storage::snapshot_lock::acquire_blocking(&lock_file, &lock_file).unwrap().unwrap();
    crate::session::storage::snapshot_lock::CONTENDED.lock().remove(&lock_file);
    let mut prompt = ConversationItem::user("NO-ECHO-P123");
    prompt.set_prompt_index(0);
    tx.send(PersistenceMsg::Chat(prompt)).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !crate::session::storage::snapshot_lock::CONTENDED.lock().contains(&lock_file) {
        assert!(std::time::Instant::now() < deadline, "the actor never reached the snapshot lock");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let chat = std::fs::read_to_string(dir.join("chat_history.jsonl")).unwrap_or_default();
    assert!(!chat.contains("NO-ECHO-P123"), "the chat item was written while a snapshot held the lock");
    drop(held);
}

/// A fork's first step, on its own thread: take the snapshot lock the way `snapshot_source` does. Returns how long it took.
fn fork_takes_lock(lock_file: std::path::PathBuf) -> std::thread::JoinHandle<std::io::Result<std::time::Duration>> {
    std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let held = crate::session::storage::snapshot_lock::acquire_blocking(&lock_file, &lock_file)?;
        drop(held);
        Ok(started.elapsed())
    })
}

async fn wait_until_contended(lock_file: &std::path::Path, fork: &std::thread::JoinHandle<std::io::Result<std::time::Duration>>) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !crate::session::storage::snapshot_lock::CONTENDED.lock().contains(lock_file) {
        assert!(std::time::Instant::now() < deadline, "the fork never reached the held snapshot lock");
        assert!(!fork.is_finished(), "the fork got the lock although the turn holds it");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

async fn wait_finished(
    fork: std::thread::JoinHandle<std::io::Result<std::time::Duration>>,
    within: std::time::Duration,
    what: &str,
) -> std::time::Duration {
    let deadline = std::time::Instant::now() + within;
    while !fork.is_finished() {
        assert!(std::time::Instant::now() < deadline, "{what}");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    fork.join().unwrap().expect("the fork's lock")
}

async fn actor_in(name: &str) -> (
    fuigo_test_support::FuigoHome,
    crate::session::info::Info,
    std::path::PathBuf,
    tokio::sync::mpsc::UnboundedSender<PersistenceMsg>,
) {
    let home = fuigo_test_support::FuigoHome::new();
    let info = crate::session::info::Info { id: acp::SessionId::new(name), cwd: "/work".to_string() };
    let dir = crate::session::persistence::session_dir(&info);
    let storage = crate::session::storage::JsonlStorageAdapter::with_explicit_session_dir(dir.clone());
    storage.init_session(&info, crate::session::persistence::default_model_id()).await.unwrap();
    let tx = test_seam::spawn_actor(info.clone(), std::sync::Arc::new(storage));
    (home, info, dir, tx)
}

/// P135 (K17): a turn that is held half-way (its echo written, its chat item not yet, as during an image save) makes a fork
/// wait, and the fork goes ahead as soon as the turn ends, not before and not much after.
#[tokio::test(flavor = "current_thread")]
async fn a_fork_waits_for_a_turn_held_half_way_and_only_until_it_ends() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let (_home, info, dir, tx) = actor_in("p135-held-turn").await;
    let lock_file = crate::session::storage::snapshot_lock::lock_path(&dir);
    let turn = crate::session::persistence::SnapshotTurn::begin(&tx);
    tx.send(PersistenceMsg::Update(user_echo(&info.id, "HELD-P135"))).unwrap();
    let (ack, flushed) = tokio::sync::oneshot::channel();
    tx.send(PersistenceMsg::FlushAndAck { respond_to: ack }).unwrap();
    flushed.await.unwrap().unwrap();
    crate::session::storage::snapshot_lock::CONTENDED.lock().remove(&lock_file);
    let fork = fork_takes_lock(lock_file.clone());
    wait_until_contended(&lock_file, &fork).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!fork.is_finished(), "the fork went ahead while the turn was half-way");
    drop(turn);
    wait_finished(fork, std::time::Duration::from_secs(3), "the fork still waits after the turn ended").await;
}

/// P135 MEDIUM-1: a chat item that does not start a turn (the workflow status reminder, a completion drained between
/// turns) is written mid-turn, and must not release the lock before the prompt's own chat item.
#[tokio::test(flavor = "current_thread")]
async fn a_chat_item_that_does_not_start_a_turn_does_not_release_the_snapshot_lock() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let (_home, info, dir, tx) = actor_in("p135-reminder").await;
    let lock_file = crate::session::storage::snapshot_lock::lock_path(&dir);
    let turn = crate::session::persistence::SnapshotTurn::begin(&tx);
    tx.send(PersistenceMsg::Update(user_echo(&info.id, "PROMPT-P135"))).unwrap();
    // A reminder: a user item with no prompt index.
    tx.send(PersistenceMsg::Chat(ConversationItem::user("STATUS-REMINDER-P135"))).unwrap();
    let (ack, flushed) = tokio::sync::oneshot::channel();
    tx.send(PersistenceMsg::FlushAndAck { respond_to: ack }).unwrap();
    flushed.await.unwrap().unwrap();
    assert!(
        std::fs::read_to_string(dir.join("chat_history.jsonl")).unwrap_or_default().contains("STATUS-REMINDER-P135"),
        "the reminder was not written"
    );
    crate::session::storage::snapshot_lock::CONTENDED.lock().remove(&lock_file);
    let fork = fork_takes_lock(lock_file.clone());
    wait_until_contended(&lock_file, &fork).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!fork.is_finished(), "a chat item that does not start a turn released the lock before the prompt's chat item");
    let mut prompt = ConversationItem::user("PROMPT-P135");
    prompt.set_prompt_index(0);
    tx.send(PersistenceMsg::Chat(prompt)).unwrap();
    drop(turn);
    wait_finished(fork, std::time::Duration::from_secs(3), "the fork still waits after the turn ended").await;
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
    assert!(read("updates.jsonl").contains("PROMPT-P135") && read("chat_history.jsonl").contains("PROMPT-P135"));
}

/// A barrier that does not flush: it answers once the actor has handled every message sent before it.
async fn actor_caught_up(tx: &tokio::sync::mpsc::UnboundedSender<PersistenceMsg>) {
    let (ack, done) = tokio::sync::oneshot::channel();
    tx.send(PersistenceMsg::ProbeWritable { respond_to: ack }).unwrap();
    let _ = done.await;
}

/// P135 HIGH-1: a turn that is dropped (a cancel, an early return) or that panics ends its hold, so a fork is not kept
/// waiting for a prompt that will never get its chat item. The fork is at the held lock before the turn goes away, so the
/// test cannot pass by the fork simply coming first.
#[tokio::test(flavor = "current_thread")]
async fn a_dropped_or_panicking_turn_releases_the_snapshot_lock() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let (_home, info, dir, tx) = actor_in("p135-dropped").await;
    let lock_file = crate::session::storage::snapshot_lock::lock_path(&dir);
    for panics in [false, true] {
        let turn = crate::session::persistence::SnapshotTurn::begin(&tx);
        tx.send(PersistenceMsg::Update(user_echo(&info.id, "NEVER-GETS-A-CHAT-ITEM"))).unwrap();
        actor_caught_up(&tx).await;
        crate::session::storage::snapshot_lock::CONTENDED.lock().remove(&lock_file);
        let fork = fork_takes_lock(lock_file.clone());
        wait_until_contended(&lock_file, &fork).await;
        if panics {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _turn = turn;
                panic!("the turn panics");
            }));
        } else {
            drop(turn);
        }
        wait_finished(fork, std::time::Duration::from_secs(3), "the fork waits on a turn that is gone").await;
    }
}

/// P135: an end that belongs to another turn (a stale end) does not release the hold of the turn that holds the lock.
#[tokio::test(flavor = "current_thread")]
async fn an_end_for_another_turn_does_not_release_the_snapshot_lock() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let (_home, info, dir, tx) = actor_in("p135-stale-end").await;
    let lock_file = crate::session::storage::snapshot_lock::lock_path(&dir);
    let turn = crate::session::persistence::SnapshotTurn::begin(&tx);
    tx.send(PersistenceMsg::Update(user_echo(&info.id, "STALE-END-P135"))).unwrap();
    tx.send(PersistenceMsg::SnapshotEnd { turn_id: u64::MAX }).unwrap();
    actor_caught_up(&tx).await;
    crate::session::storage::snapshot_lock::CONTENDED.lock().remove(&lock_file);
    let fork = fork_takes_lock(lock_file.clone());
    wait_until_contended(&lock_file, &fork).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!fork.is_finished(), "an end for another turn released the lock");
    drop(turn);
    wait_finished(fork, std::time::Duration::from_secs(3), "the fork still waits after the turn ended").await;
}

/// P135: the hold is bounded for a turn that is gone. A turn that vanished without its end (a bug) must not keep forks
/// refused for good: the actor releases the lock on its own, and does not flush the buffered echo for the fork that follows
/// (the echo is then in neither file, as it was before the turn began).
#[tokio::test(flavor = "current_thread")]
async fn a_hold_whose_turn_is_gone_without_an_end_is_released_after_its_limit() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    crate::session::storage::snapshot_lock::HOLD_MAX_OVERRIDE_MS.store(400, std::sync::atomic::Ordering::Relaxed);
    let (_home, info, dir, tx) = actor_in("p135-bound").await;
    let lock_file = crate::session::storage::snapshot_lock::lock_path(&dir);
    crate::session::persistence::SnapshotTurn::begin(&tx).drop_losing_the_end();
    tx.send(PersistenceMsg::Update(user_echo(&info.id, "LOST-END-P135"))).unwrap();
    actor_caught_up(&tx).await;
    crate::session::storage::snapshot_lock::CONTENDED.lock().remove(&lock_file);
    let fork = fork_takes_lock(lock_file.clone());
    wait_until_contended(&lock_file, &fork).await;
    // The actor is idle: its own timer must end the hold.
    let waited = wait_finished(fork, std::time::Duration::from_secs(5), "the hold was never released").await;
    assert!(waited >= std::time::Duration::from_millis(100), "the hold ended before its limit: {waited:?}");
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
    assert!(!read("updates.jsonl").contains("LOST-END-P135"), "the expiry put an echo on disk with no chat item behind it");
    let (ack, flushed) = tokio::sync::oneshot::channel();
    tx.send(PersistenceMsg::FlushAndAck { respond_to: ack }).unwrap();
    flushed.await.unwrap().unwrap();
    assert!(read("updates.jsonl").contains("LOST-END-P135"), "the buffered echo is lost");
}

/// P135 (Astra r2 H2): a turn that is still running keeps its hold however long it takes, so a long image transcription
/// never leaves a prompt's echoes on disk with no chat item for a fork. Its end releases the lock.
#[tokio::test(flavor = "current_thread")]
async fn a_live_turn_keeps_the_snapshot_lock_past_the_time_limit() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    crate::session::storage::snapshot_lock::HOLD_MAX_OVERRIDE_MS.store(300, std::sync::atomic::Ordering::Relaxed);
    let (_home, info, dir, tx) = actor_in("p135-live-turn").await;
    let lock_file = crate::session::storage::snapshot_lock::lock_path(&dir);
    let turn = crate::session::persistence::SnapshotTurn::begin(&tx);
    tx.send(PersistenceMsg::Update(user_echo(&info.id, "LIVE-TURN-P135"))).unwrap();
    actor_caught_up(&tx).await;
    crate::session::storage::snapshot_lock::CONTENDED.lock().remove(&lock_file);
    let fork = fork_takes_lock(lock_file.clone());
    wait_until_contended(&lock_file, &fork).await;
    // More than three limits pass while the turn is alive and the actor idle.
    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
    assert!(!fork.is_finished(), "the hold expired under a turn that is still running");
    drop(turn);
    wait_finished(fork, std::time::Duration::from_secs(3), "the fork still waits after the turn ended").await;
}

/// P135 (P120 rule): the snapshot lock file is created owner-only.
#[cfg(unix)]
#[test]
fn the_snapshot_lock_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::TempDir::new().unwrap();
    let path = crate::session::storage::snapshot_lock::lock_path(dir.path());
    let held = crate::session::storage::snapshot_lock::acquire_blocking(&path, &path).unwrap().unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    drop(held);
    assert_eq!(mode & 0o077, 0, "the snapshot lock file is accessible to others: {mode:o}");
}

/// P135 (Astra r3 H): the hold's deadline passes while the turn's chat item and end are still queued (the actor had not run).
/// The actor must process the queue first, so a waiting fork gets the lock only after the chat item is written: the
/// per-message expiry check released it before.
#[tokio::test(flavor = "current_thread")]
async fn a_deadline_that_passes_with_the_chat_item_queued_does_not_release_the_lock_before_it() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    crate::session::storage::snapshot_lock::HOLD_MAX_OVERRIDE_MS.store(100, std::sync::atomic::Ordering::Relaxed);
    let (_home, info, dir, tx) = actor_in("p135-queued-chat").await;
    let lock_file = crate::session::storage::snapshot_lock::lock_path(&dir);
    let turn = crate::session::persistence::SnapshotTurn::begin(&tx);
    tx.send(PersistenceMsg::Update(user_echo(&info.id, "QUEUED-P135"))).unwrap();
    actor_caught_up(&tx).await;
    crate::session::storage::snapshot_lock::CONTENDED.lock().remove(&lock_file);
    // The fork waits at the lock and, the moment it has it, reads what a snapshot would copy.
    let fork = {
        let (lock_file, dir) = (lock_file.clone(), dir.clone());
        std::thread::spawn(move || {
            let held = crate::session::storage::snapshot_lock::acquire_blocking(&lock_file, &lock_file)?;
            let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
            let seen = (read("updates.jsonl"), read("chat_history.jsonl"));
            drop(held);
            std::io::Result::Ok(seen)
        })
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !crate::session::storage::snapshot_lock::CONTENDED.lock().contains(&lock_file) {
        assert!(std::time::Instant::now() < deadline, "the fork never reached the held snapshot lock");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    // No await from here to the next one: the actor cannot run while the chat item and the end are queued and the deadline passes.
    let mut prompt = ConversationItem::user("QUEUED-P135");
    prompt.set_prompt_index(0);
    tx.send(PersistenceMsg::Chat(prompt)).unwrap();
    drop(turn);
    std::thread::sleep(std::time::Duration::from_millis(300));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !fork.is_finished() {
        assert!(std::time::Instant::now() < deadline, "the fork never got the lock");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(
        crate::session::storage::snapshot_lock::EXPIRY_RELEASES.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "the time limit released the lock while the chat item and the end were still queued"
    );
    let (updates, chat) = fork.join().unwrap().expect("the fork's lock");
    assert!(chat.contains("QUEUED-P135"), "the lock was released before the chat item was written (fork saw updates={}, chat=none)", updates.contains("QUEUED-P135"));
    assert!(updates.contains("QUEUED-P135"), "the fork saw the chat item without its echo");
}

/// Lock hygiene (R-lock-hygiene): a descriptor copy that outlives the guard (a forked child's inherited copy; `try_clone`
/// stands in for it) must not keep the snapshot lock held after the guard is released.
#[test]
fn a_released_snapshot_lock_is_free_although_a_copy_of_its_descriptor_lives_on() {
    let dir = tempfile::tempdir().unwrap();
    let path = crate::session::storage::snapshot_lock::lock_path(dir.path());
    let held = crate::session::storage::snapshot_lock::acquire_blocking(&path, &path).unwrap().unwrap();
    let inherited = held.try_clone().unwrap();
    drop(held);
    let other = crate::session::storage::snapshot_lock::acquire_blocking(&path, &path);
    drop(inherited);
    assert!(other.is_ok_and(|lock| lock.is_some()), "the released snapshot lock stayed held by an inherited descriptor");
}
