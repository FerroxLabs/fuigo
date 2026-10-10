//! P164 (K19): a rewind Fuigo is killed in the middle of is reconciled when the session is loaded again.
//!
//! Each test makes the storage calls a forced rewind makes, in its order (lock, journal + durable copy + swap of
//! `rewind_points.jsonl`, save of the rewound conversation, `RewindMarker`, removal of the copy then the journal), stops
//! at one step as a kill would (the locks go with the process), and then runs what a load runs.
use super::*;
use crate::sampling::ConversationItem;
use crate::session::persistence::default_model_id;
use crate::session::storage::{
    ContentFingerprint, RewindConversation, RewindPointsRewrite, RewindStep, SessionUpdate, StorageAdapter,
    rewind_step_for_line,
};
use agent_client_protocol as acp;
use fuigo_workspace::session::file_state::RewindPoint;
use tempfile::TempDir;

/// The step a kill stops the rewind after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KilledAt {
    /// The journal and the copy are written; the swap of `rewind_points.jsonl` has not landed.
    BeforeSwap,
    /// `rewind_points.jsonl` is rewritten; the conversation is not saved.
    AfterSwap,
    /// The rewound conversation is saved; no `RewindMarker` yet.
    AfterConversationSaved,
    /// The `RewindMarker` is written; the cleanup has not started.
    AfterMarker,
    /// The copy is removed; the journal is not.
    BetweenRemovals,
}

struct Rig {
    _temp: TempDir,
    adapter: JsonlStorageAdapter,
    info: Info,
    points: PathBuf,
    copy: PathBuf,
    journal: PathBuf,
    chat: PathBuf,
    updates: PathBuf,
}

fn conversation_before() -> Vec<ConversationItem> {
    vec![
        ConversationItem::system("SYS"),
        ConversationItem::user("P0"),
        ConversationItem::assistant("R0"),
        ConversationItem::user("P1"),
        ConversationItem::assistant("R1"),
        ConversationItem::user("P2"),
        ConversationItem::assistant("R2"),
    ]
}

/// What a rewind to prompt #1 saves.
fn conversation_after() -> Vec<ConversationItem> {
    conversation_before().into_iter().take(3).collect()
}

fn some_update(session: &Info, text: &str) -> SessionUpdate {
    SessionUpdate::Fuigo(Box::new(crate::extensions::notification::SessionNotification {
        session_id: session.id.clone(),
        update: crate::extensions::notification::SessionUpdate::HistoryRepaired { message: text.into() },
        meta: None,
    }))
}

/// The `created_at` of the rewind's `RewindMarker`, chosen before it starts.
const MARKER_AT: &str = "2026-10-06T00:00:00+00:00";

fn rewind_marker(session: &Info, target: usize, created_at: &str) -> SessionUpdate {
    SessionUpdate::Fuigo(Box::new(crate::extensions::notification::SessionNotification {
        session_id: session.id.clone(),
        update: crate::extensions::notification::SessionUpdate::RewindMarker {
            target_prompt_index: target,
            created_at: created_at.into(),
        },
        meta: None,
    }))
}

fn user_prompt(session: &Info, text: &str) -> SessionUpdate {
    SessionUpdate::Acp(Box::new(acp::SessionNotification::new(
        session.id.clone(),
        acp::SessionUpdate::UserMessageChunk(acp::ContentChunk::new(acp::ContentBlock::Text(acp::TextContent::new(
            text.to_string(),
        )))),
    )))
}

/// A session with a three-prompt conversation, a rewind point for prompts 0..=3, and some transcript.
async fn rig(name: &str) -> Rig {
    let temp = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp.path().to_path_buf());
    let info = Info { id: acp::SessionId::new(name), cwd: "/test/p164".to_string() };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    adapter.replace_chat_history(&info, &conversation_before()).await.unwrap();
    for i in 0..4 {
        adapter.append_rewind_point(&info, &RewindPoint::new(i)).await.unwrap();
    }
    adapter.append_update(&info, &some_update(&info, "before the rewind")).await.unwrap();
    let points = adapter.rewind_points_file(&info);
    Rig {
        copy: crate::session::storage::rewind_points_pre_rewind_copy(&points),
        journal: crate::session::storage::rewind_points_journal(&points),
        chat: adapter.chat_file(&info),
        updates: adapter.updates_file(&info),
        points,
        adapter,
        info,
        _temp: temp,
    }
}

/// Run a rewind to prompt #1 with the storage calls the rewind handler makes, and stop it at `at`.
async fn rewind_killed_at(rig: &Rig, rewrite: RewindPointsRewrite, rewinds_conversation: bool, at: KilledAt) {
    let lock = rig.adapter.lock_rewind_points_rewrite(&rig.info).await.expect("the rewind takes its lock");
    let saved = conversation_after();
    let conversation = rewinds_conversation.then(|| RewindConversation {
        after: ContentFingerprint::of_jsonl(&saved).unwrap(),
        marker_created_at: MARKER_AT.into(),
    });
    let undo = rig
        .adapter
        .rewrite_rewind_points_holding(&rig.info, rewrite, conversation)
        .await
        .expect("the swap");
    assert!(rig.copy.is_file(), "the rewind keeps a durable copy while it runs");
    assert!(rig.journal.is_file(), "the rewind writes its journal before the copy");
    if at == KilledAt::BeforeSwap {
        // The rename over rewind_points.jsonl had not landed: the file still holds what the copy holds.
        std::fs::write(&rig.points, undo.previous.as_deref().unwrap()).unwrap();
    }
    if matches!(at, KilledAt::BeforeSwap | KilledAt::AfterSwap) {
        drop(lock);
        return;
    }
    if rewinds_conversation {
        assert!(rig.adapter.replace_chat_history_commit_aware(&rig.info, &saved).await.is_ok());
    }
    if at == KilledAt::AfterConversationSaved {
        drop(lock);
        return;
    }
    if rewinds_conversation {
        rig.adapter.append_update(&rig.info, &rewind_marker(&rig.info, 1, MARKER_AT)).await.unwrap();
    }
    if at == KilledAt::BetweenRemovals {
        std::fs::remove_file(&rig.copy).unwrap();
    }
    drop(lock);
}

fn point_indexes(path: &Path) -> Vec<usize> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<RewindPoint>(line).expect("every row parses").prompt_index)
        .collect()
}

fn markers_to(updates: &Path, target: usize) -> usize {
    std::fs::read_to_string(updates)
        .unwrap()
        .lines()
        .filter(|line| rewind_step_for_line(line) == RewindStep::Rewind { target })
        .count()
}

fn leftovers(rig: &Rig) -> (bool, bool) {
    (rig.copy.symlink_metadata().is_ok(), rig.journal.symlink_metadata().is_ok())
}

/// A rewind that may run again: its lock is free and its own leftover check (a copy at that path) passes.
async fn a_new_rewind_can_start(rig: &Rig) {
    assert!(rig.copy.symlink_metadata().is_err(), "a copy left behind would refuse the next rewind");
    let lock = rig.adapter.lock_rewind_points_rewrite(&rig.info).await.expect("the lock is free");
    drop(lock);
}

/// Killed between the copy and the swap: the rewind changed nothing (the copy holds what the file holds). The
/// leftover goes, nothing is lost, and the conversation is as it was.
#[tokio::test]
async fn killed_before_the_swap_the_leftover_goes_and_nothing_changed() {
    let rig = rig("p164-before-swap").await;
    let points_before = std::fs::read(&rig.points).unwrap();
    let chat_before = std::fs::read(&rig.chat).unwrap();
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::BeforeSwap).await;

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("the user is told");
    assert_eq!(std::fs::read(&rig.points).unwrap(), points_before);
    assert_eq!(std::fs::read(&rig.chat).unwrap(), chat_before, "the conversation is as it was");
    assert_eq!(leftovers(&rig), (false, false), "the copy and the journal are gone");
    assert!(notice.contains("prompt #1") && notice.contains("did not happen"), "{notice}");
    assert_eq!(markers_to(&rig.updates, 1), 0, "no rewind is recorded in the transcript");
    a_new_rewind_can_start(&rig).await;
}

/// Killed after the swap, before the conversation was saved: the rewind never committed, so rewind_points.jsonl gets
/// back what the copy holds (the saved file versions of prompts 1..=3 are not lost).
#[tokio::test]
async fn killed_after_the_swap_the_saved_file_history_is_put_back() {
    let rig = rig("p164-after-swap").await;
    let points_before = std::fs::read(&rig.points).unwrap();
    let chat_before = std::fs::read(&rig.chat).unwrap();
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterSwap).await;
    assert_eq!(point_indexes(&rig.points), vec![0], "fixture: the swap landed");

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("the user is told");
    assert_eq!(std::fs::read(&rig.points).unwrap(), points_before, "put back from the copy");
    assert_eq!(std::fs::read(&rig.chat).unwrap(), chat_before);
    assert_eq!(leftovers(&rig), (false, false));
    assert!(
        notice.contains("prompt #1") && notice.contains("did not happen") && notice.contains("running the same rewind again"),
        "{notice}"
    );
    a_new_rewind_can_start(&rig).await;
    // The rewind can be run again now, and its rewrite works.
    let lock = rig.adapter.lock_rewind_points_rewrite(&rig.info).await.unwrap();
    let undo = rig.adapter.rewrite_rewind_points_holding(&rig.info, RewindPointsRewrite::TruncateFrom(1), None).await;
    let undo = undo.expect("the rewind runs again");
    rig.adapter.end_rewind_points_rewrite(&rig.info, undo, false).await.unwrap();
    drop(lock);
    assert_eq!(point_indexes(&rig.points), vec![0]);
    assert_eq!(leftovers(&rig), (false, false));
}

/// A row appended after the swap (another Fuigo process) is kept behind what the copy holds, as the rewind's own
/// put-back keeps it.
#[tokio::test]
async fn a_put_back_on_load_keeps_a_row_appended_after_the_swap() {
    let rig = rig("p164-after-swap-appended").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterSwap).await;
    rig.adapter.append_rewind_point(&rig.info, &RewindPoint::new(9)).await.unwrap();

    rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("the user is told");
    assert_eq!(point_indexes(&rig.points), vec![0, 1, 2, 3, 9]);
    assert_eq!(leftovers(&rig), (false, false));
}

/// Killed before the swap and a row appended since: the file already holds everything (the copy's rows are its first
/// rows, which also start with what the truncation would have written); nothing is put back twice.
#[tokio::test]
async fn a_row_appended_after_a_kill_before_the_swap_is_not_doubled() {
    let rig = rig("p164-before-swap-appended").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::BeforeSwap).await;
    rig.adapter.append_rewind_point(&rig.info, &RewindPoint::new(9)).await.unwrap();

    rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("the user is told");
    assert_eq!(point_indexes(&rig.points), vec![0, 1, 2, 3, 9]);
    assert_eq!(leftovers(&rig), (false, false));
}

/// Killed after the rewound conversation was saved (the commit point), before the transcript and the cleanup: the
/// rewind went through. The copy goes, rewind_points.jsonl keeps what the rewind wrote, and the missing
/// `RewindMarker` is written so the transcript matches the conversation.
#[tokio::test]
async fn killed_after_the_conversation_was_saved_the_rewind_is_finished() {
    let rig = rig("p164-after-commit").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterConversationSaved).await;
    let chat_after = std::fs::read(&rig.chat).unwrap();
    assert_eq!(markers_to(&rig.updates, 1), 0, "fixture: no marker yet");

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("the user is told");
    assert_eq!(point_indexes(&rig.points), vec![0], "what the rewind wrote is kept");
    assert_eq!(std::fs::read(&rig.chat).unwrap(), chat_after, "the rewound conversation is kept");
    assert_eq!(leftovers(&rig), (false, false));
    assert_eq!(markers_to(&rig.updates, 1), 1, "the transcript records the rewind");
    assert!(
        notice.contains("prompt #1") && notice.contains("went through") && notice.contains("recorded in the transcript"),
        "{notice}"
    );
    a_new_rewind_can_start(&rig).await;
    // A second load finds nothing more to do.
    assert_eq!(rig.adapter.reconcile_interrupted_rewind(&rig.info).await, None);
    assert_eq!(markers_to(&rig.updates, 1), 1);
}

/// Killed after the `RewindMarker`, before the cleanup: finished, and the marker is not written twice.
#[tokio::test]
async fn killed_before_the_cleanup_the_copy_goes_and_the_marker_is_not_doubled() {
    let rig = rig("p164-before-cleanup").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterMarker).await;

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("the user is told");
    assert_eq!(point_indexes(&rig.points), vec![0]);
    assert_eq!(leftovers(&rig), (false, false));
    assert_eq!(markers_to(&rig.updates, 1), 1);
    assert!(notice.contains("went through") && !notice.contains("recorded in the transcript"), "{notice}");
}

/// Killed between removing the copy and removing the journal: the journal alone is removed, silently.
#[tokio::test]
async fn killed_between_the_two_removals_the_journal_goes() {
    let rig = rig("p164-between-removals").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::BetweenRemovals).await;
    assert_eq!(leftovers(&rig), (false, true), "fixture");

    assert_eq!(rig.adapter.reconcile_interrupted_rewind(&rig.info).await, None);
    assert_eq!(leftovers(&rig), (false, false));
    assert_eq!(point_indexes(&rig.points), vec![0]);
}

/// A conversation-only rewind (its rewrite folds the later points into the one before): put back when the
/// conversation was not saved, kept when it was.
#[tokio::test]
async fn a_conversation_only_rewind_is_undone_or_finished_by_its_commit() {
    let undone = rig("p164-merge-undone").await;
    let points_before = std::fs::read(&undone.points).unwrap();
    rewind_killed_at(&undone, RewindPointsRewrite::MergeFrom(1), true, KilledAt::AfterSwap).await;
    assert_ne!(std::fs::read(&undone.points).unwrap(), points_before, "fixture: the merge changed the file");
    let notice = undone.adapter.reconcile_interrupted_rewind(&undone.info).await.expect("told");
    assert_eq!(std::fs::read(&undone.points).unwrap(), points_before);
    assert!(!notice.contains("Files that rewind had already restored"), "a conversation-only rewind restores no file: {notice}");

    let finished = rig("p164-merge-finished").await;
    rewind_killed_at(&finished, RewindPointsRewrite::MergeFrom(1), true, KilledAt::AfterConversationSaved).await;
    let merged = std::fs::read(&finished.points).unwrap();
    finished.adapter.reconcile_interrupted_rewind(&finished.info).await.expect("told");
    assert_eq!(std::fs::read(&finished.points).unwrap(), merged);
    assert_eq!(leftovers(&finished), (false, false));
}

/// A FilesOnly rewind leaves the conversation alone: it went through exactly when its swap landed.
#[tokio::test]
async fn a_files_only_rewind_is_finished_when_its_swap_landed() {
    let before = rig("p164-files-before-swap").await;
    let points_before = std::fs::read(&before.points).unwrap();
    rewind_killed_at(&before, RewindPointsRewrite::TruncateFrom(1), false, KilledAt::BeforeSwap).await;
    let notice = before.adapter.reconcile_interrupted_rewind(&before.info).await.expect("told");
    assert_eq!(std::fs::read(&before.points).unwrap(), points_before);
    assert_eq!(leftovers(&before), (false, false));
    assert!(notice.contains("did not happen"), "{notice}");

    let after = rig("p164-files-after-swap").await;
    rewind_killed_at(&after, RewindPointsRewrite::TruncateFrom(1), false, KilledAt::AfterSwap).await;
    let notice = after.adapter.reconcile_interrupted_rewind(&after.info).await.expect("told");
    assert_eq!(point_indexes(&after.points), vec![0], "the file rewind went through: its rewrite is kept");
    assert_eq!(leftovers(&after), (false, false));
    assert!(notice.contains("went through"), "{notice}");
    assert_eq!(markers_to(&after.updates, 1), 0, "a FilesOnly rewind records no conversation rewind");
}

/// Neither the conversation from before the rewind nor the one it was saving: Fuigo cannot tell, so both versions
/// stay, the session keeps what rewind_points.jsonl holds, and the notice says which file holds what.
#[tokio::test]
async fn an_ambiguous_leftover_keeps_both_versions_and_says_which_is_which() {
    let rig = rig("p164-ambiguous").await;
    let points_before = std::fs::read(&rig.points).unwrap();
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterSwap).await;
    let points_now = std::fs::read(&rig.points).unwrap();
    rig.adapter.replace_chat_history(&rig.info, &[ConversationItem::user("something else")]).await.unwrap();

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("the user is told");
    assert_eq!(std::fs::read(&rig.points).unwrap(), points_now, "rewind_points.jsonl is left as it is");
    assert_eq!(std::fs::read(&rig.copy).unwrap(), points_before, "the copy is kept");
    assert_eq!(leftovers(&rig), (true, true));
    assert!(
        notice.contains("cannot tell")
            && notice.contains("prompt #1")
            && notice.contains(&rig.copy.display().to_string())
            && notice.contains(&rig.points.display().to_string())
            && notice.contains("as it was before that rewind"),
        "{notice}"
    );
}

/// A copy an older Fuigo left (no journal): removed when it holds what rewind_points.jsonl holds, kept (and told)
/// otherwise.
#[tokio::test]
async fn a_leftover_without_a_journal_goes_only_when_it_matches_the_file() {
    let same = rig("p164-legacy-same").await;
    std::fs::copy(&same.points, &same.copy).unwrap();
    let notice = same.adapter.reconcile_interrupted_rewind(&same.info).await.expect("told");
    assert_eq!(leftovers(&same), (false, false));
    assert!(notice.contains("nothing was lost"), "{notice}");

    let differs = rig("p164-legacy-differs").await;
    std::fs::write(&differs.copy, b"{}\n").unwrap();
    let notice = differs.adapter.reconcile_interrupted_rewind(&differs.info).await.expect("told");
    assert_eq!(leftovers(&differs), (true, false));
    assert_eq!(std::fs::read(&differs.copy).unwrap(), b"{}\n");
    assert!(notice.contains("cannot tell") && notice.contains("older Fuigo"), "{notice}");
}

/// A rewind running in another process (it holds the rewrite lock) is not a crashed one: its files are left alone.
#[tokio::test]
#[serial_test::serial(rewrite_lock_wait)]
async fn a_rewind_running_elsewhere_is_left_alone() {
    let rig = rig("p164-live-rewind").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterSwap).await;
    let other = JsonlStorageAdapter::with_root(rig._temp.path().to_path_buf());
    let held = other.lock_rewind_points_rewrite(&rig.info).await.expect("the other process's rewind holds the lock");
    let points_now = std::fs::read(&rig.points).unwrap();

    assert_eq!(rig.adapter.reconcile_interrupted_rewind(&rig.info).await, None);
    assert_eq!(leftovers(&rig), (true, true));
    assert_eq!(std::fs::read(&rig.points).unwrap(), points_now);
    drop(held);
    assert!(rig.adapter.reconcile_interrupted_rewind(&rig.info).await.is_some(), "once it is gone, the load reconciles");
}

/// A rewind that is done is not "running" any more even while a forked child still holds a copy of its lock file
/// descriptor (another thread's `Command::spawn` does that until the child execs): the lock goes when the rewind drops
/// it, not when the last copy of the descriptor closes. This was the shared cause of the intermittent failures of this
/// module under a busy crate run (the reconcile saw a "running rewind" and told the user nothing).
#[tokio::test]
async fn a_finished_rewind_is_not_running_because_a_forked_child_holds_a_copy_of_its_lock() {
    let rig = rig("p164-forked-copy").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterSwap).await;
    let other = JsonlStorageAdapter::with_root(rig._temp.path().to_path_buf());
    let held = other.lock_rewind_points_rewrite(&rig.info).await.expect("a rewind takes its lock");
    let child_copy = held.rewrite.as_ref().expect("the lock file is locked").try_clone().expect("a copy of the descriptor");
    drop(held);

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await;
    drop(child_copy);
    assert!(notice.is_some(), "the finished rewind's lock is released, so the load reconciles the leftover");
}

/// A live actor (in this or another process) holds the session: nothing is done.
#[tokio::test]
async fn a_session_held_by_a_live_actor_is_left_alone() {
    let rig = rig("p164-live-actor").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterSwap).await;
    let owner = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(rig.points.parent().unwrap().join(crate::session::turn_owner_lock::TURN_OWNER_LOCK_FILE))
        .unwrap();
    fs2::FileExt::try_lock_shared(&owner).expect("the live actor's shared hold");

    assert_eq!(rig.adapter.reconcile_interrupted_rewind(&rig.info).await, None);
    assert_eq!(leftovers(&rig), (true, true));
    fs2::FileExt::unlock(&owner).unwrap();
}

/// A link planted at the copy's path is never followed: both stay, and the user is told.
#[cfg(unix)]
#[tokio::test]
async fn a_link_at_the_copys_path_is_kept_and_not_followed() {
    let rig = rig("p164-link").await;
    let target = rig._temp.path().join("elsewhere");
    std::fs::write(&target, b"not yours").unwrap();
    std::os::unix::fs::symlink(&target, &rig.copy).unwrap();

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("told");
    assert!(notice.contains("not a regular file"), "{notice}");
    assert_eq!(std::fs::read(&target).unwrap(), b"not yours");
    assert!(rig.copy.symlink_metadata().unwrap().file_type().is_symlink());
}

/// The decision table, for the cases a kill cannot produce.
#[test]
fn the_conversation_saved_without_the_swap_is_ambiguous() {
    let copy = b"a\nb\n".to_vec();
    let written = b"a\n".to_vec();
    let saved = b"saved\n".to_vec();
    let journal = RewindJournal {
        version: 1,
        rewrite: RewindPointsRewrite::TruncateFrom(1),
        points_before: ContentFingerprint::of(&copy),
        points_written: ContentFingerprint::of(&written),
        chat_before: Some(ContentFingerprint::of(b"before\n")),
        chat_after: Some(ContentFingerprint::of(&saved)),
        marker_created_at: Some(MARKER_AT.into()),
        updates_len: Some(0),
    };
    let quiet = Some(Transcript::default());
    let marked = Some(Transcript { marker: true, later_history: false });
    assert!(matches!(decide(Some(&journal), Some(&copy), &copy, Some(&saved), quiet), Decision::Keep { .. }));
    assert_eq!(
        decide(Some(&journal), Some(&written), &copy, Some(&saved), quiet),
        Decision::Finish { record_marker: true }
    );
    assert_eq!(
        decide(Some(&journal), Some(&written), &copy, Some(&saved), marked),
        Decision::Finish { record_marker: false }
    );
    assert_eq!(decide(Some(&journal), Some(&written), &copy, Some(b"before\nmore\n"), quiet), Decision::Undo {
        restore: Some(copy.clone())
    });
    // A copy that is not what the journal says it is: neither side can be trusted.
    assert!(matches!(decide(Some(&journal), Some(&written), b"other\n", Some(&saved), quiet), Decision::Keep { .. }));
    // Astra r1 #1: a history that only starts like the saved conversation (a compaction by another actor) is no
    // evidence; without the rewind's marker it is ambiguous.
    assert!(matches!(
        decide(Some(&journal), Some(&written), &copy, Some(b"saved\nsummary\n"), quiet),
        Decision::Keep { .. }
    ));
    // ... and with the marker, the rewind went through.
    assert_eq!(
        decide(Some(&journal), Some(&written), &copy, Some(b"saved\nnext turn\n"), marked),
        Decision::Finish { record_marker: false }
    );
    // Astra r1 #2: the marker wins over a history that happens to start as before.
    assert_eq!(
        decide(Some(&journal), Some(&written), &copy, Some(b"before\nagain\n"), marked),
        Decision::Finish { record_marker: false }
    );
    // Astra r1 #3, #7: later turns without the marker, or a transcript that cannot be checked: keep both.
    let later = Some(Transcript { marker: false, later_history: true });
    assert!(matches!(decide(Some(&journal), Some(&written), &copy, Some(&saved), later), Decision::Keep { .. }));
    assert!(matches!(decide(Some(&journal), Some(&written), &copy, Some(&saved), None), Decision::Keep { .. }));
}

/// Astra r1 #1: killed after the swap; another actor then compacts the history into one that starts like the
/// conversation the rewind was saving. That is no evidence the rewind went through: both versions stay.
#[tokio::test]
async fn a_history_that_only_starts_like_the_saved_conversation_is_not_taken_as_the_commit() {
    let rig = rig("p164-r1-prefix").await;
    let points_before = std::fs::read(&rig.points).unwrap();
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterSwap).await;
    let mut compacted = conversation_after();
    compacted.push(ConversationItem::user("summary of P1 and P2"));
    rig.adapter.replace_chat_history(&rig.info, &compacted).await.unwrap();

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("told");
    assert_eq!(leftovers(&rig), (true, true), "{notice}");
    assert_eq!(std::fs::read(&rig.copy).unwrap(), points_before);
    assert!(notice.contains("cannot tell"), "{notice}");
}

/// Astra r1 #2: the rewind went through (its marker is in the transcript), its cleanup failed, and the conversation
/// then happened to be written again as it was before the rewind. The marker decides: finished, nothing put back,
/// rows appended since kept once.
#[tokio::test]
async fn the_rewinds_own_marker_decides_over_a_history_that_starts_as_before() {
    let rig = rig("p164-r1-marker").await;
    let chat_before = std::fs::read(&rig.chat).unwrap();
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterMarker).await;
    std::fs::write(&rig.chat, &chat_before).unwrap();
    rig.adapter.append_rewind_point(&rig.info, &RewindPoint::new(1)).await.unwrap();

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("told");
    assert_eq!(point_indexes(&rig.points), vec![0, 1], "what the rewind wrote, then the row appended since");
    assert_eq!(leftovers(&rig), (false, false));
    assert!(notice.contains("went through"), "{notice}");
    assert_eq!(markers_to(&rig.updates, 1), 1);
}

/// Another rewind's marker to the same prompt is not this rewind's evidence; it is later activity, so nothing is put
/// back on top of it (Astra r2 #1).
#[tokio::test]
async fn another_rewinds_marker_is_not_evidence() {
    let rig = rig("p164-r1-other-marker").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterSwap).await;
    rig.adapter.append_update(&rig.info, &rewind_marker(&rig.info, 1, "2020-01-01T00:00:00+00:00")).await.unwrap();

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("told");
    assert!(notice.contains("cannot tell"), "{notice}");
    assert!(notice.contains("later turns or compactions"), "{notice}");
    assert_eq!(point_indexes(&rig.points), vec![0], "nothing is put back");
    assert_eq!(leftovers(&rig), (true, true));
}

/// Astra r1 #3: the conversation was saved but its marker is missing, and the transcript has a later prompt: a marker
/// appended at the end would hide that prompt. Nothing is appended; both versions stay.
#[tokio::test]
async fn no_marker_is_appended_after_a_later_prompt() {
    let rig = rig("p164-r1-later-prompt").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterConversationSaved).await;
    rig.adapter.append_update(&rig.info, &user_prompt(&rig.info, "P1 again")).await.unwrap();
    let updates_before = std::fs::read(&rig.updates).unwrap();

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("told");
    assert_eq!(std::fs::read(&rig.updates).unwrap(), updates_before, "nothing is appended");
    assert_eq!(leftovers(&rig), (true, true));
    assert!(notice.contains("cannot tell") && notice.contains("later turns"), "{notice}");
}

/// Astra r1 #4: the transcript's append lock is held by another process: the load does not hang on it while it holds
/// the session; it keeps both versions and says so.
#[tokio::test]
async fn a_held_transcript_lock_does_not_hang_the_load() {
    let rig = rig("p164-r1-updates-lock").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterConversationSaved).await;
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(rig.updates.with_extension("jsonl.lock"))
        .unwrap();
    fs2::FileExt::try_lock_exclusive(&holder).expect("another process appends to updates.jsonl");

    let outcome =
        tokio::time::timeout(std::time::Duration::from_secs(20), rig.adapter.reconcile_interrupted_rewind(&rig.info)).await;
    fs2::FileExt::unlock(&holder).unwrap();
    let notice = outcome.expect("the load does not wait for ever").expect("told");
    assert_eq!(leftovers(&rig), (true, true));
    assert_eq!(markers_to(&rig.updates, 1), 0);
    assert!(notice.contains("cannot tell") && notice.contains("updates.jsonl"), "{notice}");
}

/// Astra r1 #5: a rewrite lock that cannot be taken at all is not "no lock needed": nothing changes.
#[tokio::test]
async fn an_unusable_rewrite_lock_changes_nothing() {
    let rig = rig("p164-r1-unusable-lock").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterSwap).await;
    let lock = rig.points.with_extension("jsonl.rewrite.lock");
    let _ = std::fs::remove_file(&lock);
    std::fs::create_dir(&lock).unwrap();
    let points_now = std::fs::read(&rig.points).unwrap();

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("told");
    assert_eq!(std::fs::read(&rig.points).unwrap(), points_now);
    assert_eq!(leftovers(&rig), (true, true));
    assert!(notice.contains("rewrite.lock"), "{notice}");
}

/// Astra r1 #6: evidence that is a link or a FIFO is refused, never followed or waited on.
#[cfg(unix)]
#[tokio::test]
async fn a_linked_or_fifo_journal_is_refused() {
    let linked = rig("p164-r1-journal-link").await;
    rewind_killed_at(&linked, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterSwap).await;
    let real = linked._temp.path().join("journal-elsewhere");
    std::fs::rename(&linked.journal, &real).unwrap();
    std::os::unix::fs::symlink(&real, &linked.journal).unwrap();
    let notice = linked.adapter.reconcile_interrupted_rewind(&linked.info).await.expect("told");
    assert!(notice.contains("cannot be used"), "{notice}");
    assert_eq!(leftovers(&linked), (true, true));
    assert_eq!(point_indexes(&linked.points), vec![0], "nothing is put back on the word of a link");

    let fifo = rig("p164-r1-journal-fifo").await;
    rewind_killed_at(&fifo, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterSwap).await;
    std::fs::remove_file(&fifo.journal).unwrap();
    let path = std::ffi::CString::new(fifo.journal.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: mkfifo(3) on a NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let outcome =
        tokio::time::timeout(std::time::Duration::from_secs(20), fifo.adapter.reconcile_interrupted_rewind(&fifo.info)).await;
    let notice = outcome.expect("a FIFO does not block the load").expect("told");
    assert!(notice.contains("cannot be used"), "{notice}");
}

/// Astra r1 #7: a transcript shorter than when the rewind started cannot be checked: nothing is removed.
#[tokio::test]
async fn a_transcript_that_cannot_be_checked_keeps_both() {
    let rig = rig("p164-r1-short-updates").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterConversationSaved).await;
    std::fs::write(&rig.updates, b"").unwrap();

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("told");
    assert_eq!(leftovers(&rig), (true, true));
    assert!(notice.contains("cannot tell") && notice.contains("updates.jsonl"), "{notice}");
}

/// Astra r2 #1: a rewind that went through (its marker is in the transcript), whose cleanup failed, and whose removed
/// turns were then written again byte for byte. When the transcript cannot be checked, the history looking as before
/// is no proof that the rewind did not happen: nothing is put back.
#[tokio::test]
async fn nothing_is_put_back_when_the_transcript_cannot_be_checked() {
    let rig = rig("p164-r2-unchecked").await;
    let chat_before = std::fs::read(&rig.chat).unwrap();
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterMarker).await;
    std::fs::write(&rig.chat, &chat_before).unwrap();
    rig.adapter.append_rewind_point(&rig.info, &RewindPoint::new(1)).await.unwrap();
    let points_now = std::fs::read(&rig.points).unwrap();
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(rig.updates.with_extension("jsonl.lock"))
        .unwrap();
    fs2::FileExt::try_lock_exclusive(&holder).expect("another process holds the transcript");

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("told");
    fs2::FileExt::unlock(&holder).unwrap();
    assert_eq!(std::fs::read(&rig.points).unwrap(), points_now, "nothing is put back");
    assert_eq!(leftovers(&rig), (true, true));
    assert!(notice.contains("cannot tell"), "{notice}");
}

/// Astra r2 #1: the conversation looks as before, but a prompt was recorded after the rewind started: nothing is put
/// back on top of it.
#[tokio::test]
async fn nothing_is_put_back_over_a_later_prompt() {
    let rig = rig("p164-r2-undo-later-prompt").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterSwap).await;
    rig.adapter.append_update(&rig.info, &user_prompt(&rig.info, "P3")).await.unwrap();

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("told");
    assert_eq!(point_indexes(&rig.points), vec![0]);
    assert_eq!(leftovers(&rig), (true, true));
    assert!(notice.contains("cannot tell") && notice.contains("later turns"), "{notice}");
}

/// Astra r2 #2: a compaction recorded after the rewind started: a marker appended at the end would abandon it, so
/// nothing is appended and both versions stay.
#[tokio::test]
async fn no_marker_is_appended_after_a_later_compaction() {
    let rig = rig("p164-r2-later-compaction").await;
    rewind_killed_at(&rig, RewindPointsRewrite::TruncateFrom(1), true, KilledAt::AfterConversationSaved).await;
    let checkpoint = SessionUpdate::Fuigo(Box::new(crate::extensions::notification::SessionNotification {
        session_id: rig.info.id.clone(),
        update: crate::extensions::notification::SessionUpdate::CompactionCheckpoint(Box::new(
            crate::extensions::notification::CompactionCheckpointInfo {
                checkpoint_id: "c1".into(),
                prompt_index_at_compaction: 1,
                checkpoint_file: "compaction_checkpoints/c1.json".into(),
                auto_continue: None,
                schema_version: 1,
                created_at: "2026-10-06T00:00:01+00:00".into(),
            },
        )),
        meta: None,
    }));
    rig.adapter.append_update(&rig.info, &checkpoint).await.unwrap();
    let updates_now = std::fs::read(&rig.updates).unwrap();

    let notice = rig.adapter.reconcile_interrupted_rewind(&rig.info).await.expect("told");
    assert_eq!(std::fs::read(&rig.updates).unwrap(), updates_now, "nothing is appended");
    assert_eq!(leftovers(&rig), (true, true));
    assert!(notice.contains("cannot tell") && notice.contains("compactions"), "{notice}");
}

/// Astra r2 #3: the rewind reads chat_history.jsonl for its journal without following a link: one planted there
/// refuses the rewrite, with nothing changed.
#[cfg(unix)]
#[tokio::test]
async fn a_rewind_does_not_read_its_journal_through_a_link() {
    let rig = rig("p164-r2-chat-link").await;
    let points_before = std::fs::read(&rig.points).unwrap();
    let real = rig._temp.path().join("chat-elsewhere");
    std::fs::rename(&rig.chat, &real).unwrap();
    std::os::unix::fs::symlink(&real, &rig.chat).unwrap();
    let lock = rig.adapter.lock_rewind_points_rewrite(&rig.info).await.unwrap();
    let conversation = Some(RewindConversation {
        after: ContentFingerprint::of_jsonl(&conversation_after()).unwrap(),
        marker_created_at: MARKER_AT.into(),
    });
    let refused = rig
        .adapter
        .rewrite_rewind_points_holding(&rig.info, RewindPointsRewrite::TruncateFrom(1), conversation)
        .await;
    drop(lock);
    let error = refused.expect_err("the rewrite is refused");
    assert!(error.to_string().contains("cannot be used"), "{error}");
    assert_eq!(std::fs::read(&rig.points).unwrap(), points_before);
    assert_eq!(leftovers(&rig), (false, false));
}
