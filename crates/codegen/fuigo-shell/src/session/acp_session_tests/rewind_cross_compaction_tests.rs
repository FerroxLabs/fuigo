use super::support::create_test_actor;

use crate::extensions::notification::{
    CompactionCheckpointFile, CompactionCheckpointInfo, SessionNotification as FuigoNotification,
    SessionUpdate as FuigoSessionUpdate,
};
use crate::sampling::ConversationItem;
use crate::session::storage::{SessionUpdate, SessionUpdateEnvelope};
use crate::session::{RewindMode, RewindRequest};
use agent_client_protocol as acp;

fn user_chunk(text: &str, prompt_index: usize) -> SessionUpdate {
    SessionUpdate::Acp(Box::new(acp::SessionNotification::new(
        acp::SessionId::new("s"),
        acp::SessionUpdate::UserMessageChunk(
            acp::ContentChunk::new(acp::ContentBlock::Text(acp::TextContent::new(
                text.to_string(),
            )))
            .meta(
                serde_json::json!({ "promptIndex": prompt_index })
                    .as_object()
                    .cloned(),
            ),
        ),
    )))
}

fn agent_chunk(text: &str) -> SessionUpdate {
    SessionUpdate::Acp(Box::new(acp::SessionNotification::new(
        acp::SessionId::new("s"),
        acp::SessionUpdate::AgentMessageChunk(acp::ContentChunk::new(acp::ContentBlock::Text(
            acp::TextContent::new(text.to_string()),
        ))),
    )))
}

fn checkpoint_update(id: &str, prompt_index_at_compaction: usize) -> SessionUpdate {
    SessionUpdate::Fuigo(Box::new(FuigoNotification {
        session_id: acp::SessionId::new("s"),
        update: FuigoSessionUpdate::CompactionCheckpoint(Box::new(CompactionCheckpointInfo {
            checkpoint_id: id.to_string(),
            prompt_index_at_compaction,
            checkpoint_file: format!("compaction_checkpoints/{id}.json"),
            auto_continue: None,
            schema_version: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        })),
        meta: None,
    }))
}

/// Writes the shared cross-compaction fixture into `session_dir`: a checkpoint file with compacted `[SYS, SUMMARY]` at prompt 5.
/// It also writes an `updates.jsonl` with prompts P0..P6 and the checkpoint record between P4 and P5.
fn write_compacted_session_fixture(session_dir: &std::path::Path, ckpt_id: &str) {
    std::fs::create_dir_all(session_dir.join("compaction_checkpoints")).unwrap();

    let ckpt_file = CompactionCheckpointFile {
        inherited_prefix_len: None,
        checkpoint_id: ckpt_id.to_string(),
        prompt_index_at_compaction: 5,
        compacted_history: vec![
            ConversationItem::system("SYS"),
            ConversationItem::user("SUMMARY"),
        ],
        schema_version: 1,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        original_user_info: Some("UI0".to_string()),
        reread_file_paths: vec![],
    };
    std::fs::write(
        session_dir.join(format!("compaction_checkpoints/{ckpt_id}.json")),
        serde_json::to_vec(&ckpt_file).unwrap(),
    )
    .unwrap();

    let updates = vec![
        user_chunk("P0", 0),
        user_chunk("P1", 1),
        user_chunk("P2", 2),
        user_chunk("P3", 3),
        user_chunk("P4", 4),
        checkpoint_update(ckpt_id, 5),
        user_chunk("P5", 5),
        agent_chunk("R5"),
        user_chunk("P6", 6),
    ];
    let mut content = Vec::new();
    for u in &updates {
        let env = SessionUpdateEnvelope::from_update(u).unwrap();
        content.extend(serde_json::to_vec(&env).unwrap());
        content.push(b'\n');
    }
    std::fs::write(session_dir.join("updates.jsonl"), content).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn rewind_pre_compaction_with_cancelled_turns_truncates_context_gb2961() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run_rewind_scenario()).await;
}

async fn run_rewind_scenario() {
    let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
    let (persistence_tx, _persistence_rx) = super::support::answering_persistence();
    let mut actor = create_test_actor(0, 200_000, 80, gateway_tx, persistence_tx).await;

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    actor.session_info.id = acp::SessionId::new(format!("rw-e2e-{unique}"));

    let session_dir = crate::session::persistence::session_dir(&actor.session_info);
    write_compacted_session_fixture(&session_dir, "ckpt5");

    let mut snap = actor
        .chat_state_handle
        .snapshot()
        .await
        .expect("snapshot available");
    snap.conversation = vec![
        ConversationItem::system("SYS"),
        ConversationItem::user("UI1"),
        ConversationItem::user("SUMMARY"),
        ConversationItem::user("P5"),
        ConversationItem::assistant("R5"),
        ConversationItem::user("P6"),
    ];
    snap.prompt_index = 7;
    snap.prompt_texts = (0..7).map(|i| format!("P{i}")).collect();
    snap.last_compaction_prompt_index = Some(5);
    actor.chat_state_handle.restore_snapshot(snap);

    let resp = actor
        .handle_rewind(RewindRequest {
            target_prompt_index: 3,
            force: true,
            mode: RewindMode::ConversationOnly,
        })
        .await
        .expect("handle_rewind ok");
    assert!(resp.success, "rewind should succeed: {resp:?}");

    let conv = actor.chat_state_handle.get_conversation().await;
    let texts: Vec<String> = conv.iter().map(|c| c.text_content()).collect();

    let _ = std::fs::remove_dir_all(&session_dir);

    assert_eq!(
        texts,
        vec!["SYS", "UI0", "P0", "P1", "P2"],
        "conversation must truncate to prompts 0..2 (got {texts:?})"
    );
    assert!(
        !texts
            .iter()
            .any(|t| ["P3", "P4", "P5", "P6", "SUMMARY"].contains(&t.as_str())),
        "post-target prompts / compacted summary must not leak into context: {texts:?}"
    );
    assert_eq!(
        actor.chat_state_handle.get_prompt_index().await,
        3,
        "prompt_index must be reset to the rewind target"
    );
}

/// `FilesOnly` is exempt from the chat-state prompt-index bound; its real bound is the on-disk snapshot index.
/// It therefore no-ops to success when out of range, the property the bridge relies on when the chat-state index is empty.
/// `ConversationOnly` is not exempt and still rejects an out-of-range target.
#[tokio::test(flavor = "current_thread")]
async fn files_only_rewind_is_exempt_from_chat_state_bound() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run_files_only_bound_scenario()).await;
}

async fn run_files_only_bound_scenario() {
    let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
    let (persistence_tx, _persistence_rx) = super::support::answering_persistence();
    let actor = create_test_actor(0, 200_000, 80, gateway_tx, persistence_tx).await;

    let mut snap = actor
        .chat_state_handle
        .snapshot()
        .await
        .expect("snapshot available");
    snap.prompt_index = 2;
    snap.prompt_texts = vec!["P0".into(), "P1".into()];
    actor.chat_state_handle.restore_snapshot(snap);

    // Out-of-range FilesOnly is exempt: it reverts nothing (no snapshots) but succeeds
    let oor = actor
        .handle_rewind(RewindRequest {
            target_prompt_index: 5,
            force: true,
            mode: RewindMode::FilesOnly,
        })
        .await
        .expect("files-only rewind ok");
    assert!(
        oor.success,
        "out-of-range FilesOnly must no-op succeed: {oor:?}"
    );
    assert!(oor.reverted_files.is_empty());

    // In-range FilesOnly also succeeds.
    let in_range = actor
        .handle_rewind(RewindRequest {
            target_prompt_index: 1,
            force: true,
            mode: RewindMode::FilesOnly,
        })
        .await
        .expect("files-only rewind ok");
    assert!(
        in_range.success,
        "in-range FilesOnly must succeed: {in_range:?}"
    );

    // ConversationOnly is still bounded by the chat-state index.
    let convo = actor
        .handle_rewind(RewindRequest {
            target_prompt_index: 5,
            force: true,
            mode: RewindMode::ConversationOnly,
        })
        .await
        .expect("handle_rewind returns Ok(success=false)");
    assert!(
        !convo.success,
        "out-of-range ConversationOnly must be rejected"
    );
    assert!(convo.error.is_some());
}

/// `rewind_file_counts` (the `GetRewindFileCounts` actor arm) maps the file-state tracker's per-prompt snapshot metadata to a count per prompt.
#[tokio::test(flavor = "current_thread")]
async fn rewind_file_counts_maps_snapshot_metadata() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run_file_counts_scenario()).await;
}

async fn run_file_counts_scenario() {
    use std::path::Path;

    let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
    let (persistence_tx, _persistence_rx) = super::support::answering_persistence();
    let actor = create_test_actor(0, 200_000, 80, gateway_tx, persistence_tx).await;

    let cwd = Path::new("/tmp");
    // Prompt 0 has two distinct file snapshots; prompt 1 has one.
    actor
        .file_state_tracker
        .add_before_snapshot_for_prompt(0, Path::new("/tmp/a.rs"), cwd, Some("a".into()))
        .await;
    actor
        .file_state_tracker
        .add_before_snapshot_for_prompt(0, Path::new("/tmp/b.rs"), cwd, Some("b".into()))
        .await;
    actor
        .file_state_tracker
        .add_before_snapshot_for_prompt(1, Path::new("/tmp/c.rs"), cwd, Some("c".into()))
        .await;

    let counts = actor.rewind_file_counts().await;
    assert_eq!(counts.get(&0).copied(), Some(2));
    assert_eq!(counts.get(&1).copied(), Some(1));
    assert_eq!(counts.get(&2).copied(), None);
}

/// A cross-compaction rewind to before the compaction point rebuilds the conversation without a summary.
/// The stale `last_compaction_prompt_index` must then be cleared.
/// Otherwise the per-model `x-compactions-remaining` header would wrongly report `0` for a session that no longer holds a summary.
#[tokio::test(flavor = "current_thread")]
async fn rewind_before_compaction_clears_stale_compaction_marker() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run_clears_marker_scenario()).await;
}

async fn run_clears_marker_scenario() {
    use fuigo_sampling_types::CompactionsRemaining;
    let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
    let (persistence_tx, _persistence_rx) = super::support::answering_persistence();
    let mut actor = create_test_actor(0, 200_000, 80, gateway_tx, persistence_tx).await;

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    actor.session_info.id = acp::SessionId::new(format!("rw-marker-{unique}"));

    let session_dir = crate::session::persistence::session_dir(&actor.session_info);
    write_compacted_session_fixture(&session_dir, "ckptm");

    let mut snap = actor
        .chat_state_handle
        .snapshot()
        .await
        .expect("snapshot available");
    snap.conversation = vec![
        ConversationItem::system("SYS"),
        ConversationItem::user("UI1"),
        ConversationItem::user("SUMMARY"),
        ConversationItem::user("P5"),
        ConversationItem::assistant("R5"),
        ConversationItem::user("P6"),
    ];
    snap.prompt_index = 7;
    snap.prompt_texts = (0..7).map(|i| format!("P{i}")).collect();
    // The session believes it holds a compaction summary from prompt 5.
    snap.last_compaction_prompt_index = Some(5);
    actor.chat_state_handle.restore_snapshot(snap);

    // Rewind to prompt 3, before the compaction point (5), so the summary is dropped from the rebuilt conversation and the marker must be cleared
    let resp = actor
        .handle_rewind(RewindRequest {
            target_prompt_index: 3,
            force: true,
            mode: RewindMode::ConversationOnly,
        })
        .await
        .expect("handle_rewind ok");
    assert!(resp.success, "rewind should succeed: {resp:?}");

    let marker = actor
        .chat_state_handle
        .get_last_compaction_prompt_index()
        .await;

    // End-to-end: advertise support so the gate runs, then read the header off the reconstructed config
    // It must report a fresh "1", not the stale "0"
    actor
        .compactions_remaining
        .set(Some(CompactionsRemaining::Dynamic(true)));
    let header = actor
        .reconstruct_full_config()
        .await
        .extra_headers
        .get("x-compactions-remaining")
        .cloned();

    let _ = std::fs::remove_dir_all(&session_dir);

    assert_eq!(
        marker, None,
        "pre-compaction rewind must clear the stale compaction marker"
    );
    assert_eq!(
        header.as_deref(),
        Some("1"),
        "header must report 1 after the summary is dropped (got {header:?})"
    );
}

/// Forking a session must carry the `compaction_checkpoints/{uuid}.json` files along with the copied checkpoint records.
/// Replay requires each referenced file, so without the copy every rewind in the forked session fails with "compaction checkpoint file missing".
/// The test drives the production `fork_session` path, so it covers the real file-copy step.
#[tokio::test(flavor = "current_thread")]
async fn rewind_succeeds_in_forked_session_with_compaction_checkpoint() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let local = tokio::task::LocalSet::new();
    local.run_until(run_forked_rewind_scenario()).await;
}

async fn run_forked_rewind_scenario() {
    // This test resolves the fuigo home more than once (and a concurrent guarded test may redirect it
    // between reads, then delete its directory); hold a private, exclusive one for the whole test.
    let _home = fuigo_test_support::FuigoHome::new();
    use crate::session::fork::{ForkSessionRequest, fork_session};
    use crate::session::storage::{JsonlStorageAdapter, StorageAdapter};

    let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
    let (persistence_tx, _persistence_rx) = super::support::answering_persistence();
    let mut actor = create_test_actor(0, 200_000, 80, gateway_tx, persistence_tx).await;

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut source_info = actor.session_info.clone();
    source_info.id = acp::SessionId::new(format!("rw-fork-src-{unique}"));
    let fork_id = format!("rw-fork-dst-{unique}");
    actor.session_info.id = acp::SessionId::new(fork_id.clone());

    // fork_session reads the source summary, so init a real session first.
    JsonlStorageAdapter::with_root(crate::util::fuigo_home::fuigo_home())
        .init_session(
            &source_info,
            crate::session::persistence::default_model_id(),
        )
        .await
        .unwrap();
    let source_dir = crate::session::persistence::session_dir(&source_info);
    write_compacted_session_fixture(&source_dir, "ckptf");

    fork_session(
        ForkSessionRequest {
            source_session_id: source_info.id.to_string(),
            source_cwd: source_info.cwd.clone(),
            new_cwd: actor.session_info.cwd.clone(),
            new_session_id: Some(fork_id.clone()),
            ..Default::default()
        },
        "test-agent",
        None,
    )
    .await
    .expect("fork_session ok");

    let target_dir = crate::session::persistence::session_dir(&actor.session_info);
    let forked_checkpoint = target_dir.join("compaction_checkpoints/ckptf.json");

    // Simulate the forked session's live post-compaction state.
    let mut snap = actor
        .chat_state_handle
        .snapshot()
        .await
        .expect("snapshot available");
    snap.conversation = vec![
        ConversationItem::system("SYS"),
        ConversationItem::user("UI1"),
        ConversationItem::user("SUMMARY"),
        ConversationItem::user("P5"),
        ConversationItem::assistant("R5"),
        ConversationItem::user("P6"),
    ];
    snap.prompt_index = 7;
    snap.prompt_texts = (0..7).map(|i| format!("P{i}")).collect();
    snap.last_compaction_prompt_index = Some(5);
    actor.chat_state_handle.restore_snapshot(snap);

    // Rewind to a post-compaction target: replay must load the checkpoint file from the forked session dir
    let resp = actor
        .handle_rewind(RewindRequest {
            target_prompt_index: 6,
            force: true,
            mode: RewindMode::ConversationOnly,
        })
        .await
        .expect("handle_rewind ok");

    let checkpoint_copied = forked_checkpoint.is_file();
    let prompt_index = actor.chat_state_handle.get_prompt_index().await;

    let _ = std::fs::remove_dir_all(&source_dir);
    let _ = std::fs::remove_dir_all(&target_dir);

    assert!(
        checkpoint_copied,
        "fork must copy the referenced checkpoint file"
    );
    assert!(
        resp.success,
        "rewind in a forked session must succeed once checkpoint files are copied: {resp:?}"
    );
    assert_eq!(
        prompt_index, 6,
        "prompt_index must be reset to the rewind target"
    );
}

// ── P111: a rewind that cannot finish must not have changed the project, and must not lose saved file contents ──

/// The test actor with its project filesystem on a real directory (the production `LocalFs`), so file reverts can fail
/// the way they do on disk. The gateway receiver is returned so the actor's gateway stays open.
async fn actor_on_real_fs(
    root: &std::path::Path,
    persistence_tx: tokio::sync::mpsc::UnboundedSender<crate::session::persistence::PersistenceMsg>,
    label: &str,
) -> (
    crate::session::acp_session::SessionActor,
    tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
) {
    let (gateway_tx, gateway_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut actor = create_test_actor(0, 200_000, 80, gateway_tx, persistence_tx).await;
    actor.tool_context.fs = fuigo_workspace::file_system::AsyncFsWrapper::new(std::sync::Arc::new(
        fuigo_workspace::file_system::LocalFs::new(root.to_path_buf()),
    ));
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    actor.session_info.id = acp::SessionId::new(format!("{label}-{unique}"));
    (actor, gateway_rx)
}

/// Whether the handler asked persistence to drop rewind snapshots (`rewind_points.jsonl`) since the last call.
fn drained_truncate_requests(recorded: &super::support::RecordedTruncations) -> Vec<usize> {
    std::mem::take(&mut *recorded.lock().unwrap())
}

/// The compacted conversation of `write_compacted_session_fixture`, live at prompt 7.
async fn restore_compacted_live_state(actor: &crate::session::acp_session::SessionActor) {
    let mut snap = actor
        .chat_state_handle
        .snapshot()
        .await
        .expect("snapshot available");
    snap.conversation = vec![
        ConversationItem::system("SYS"),
        ConversationItem::user("UI1"),
        ConversationItem::user("SUMMARY"),
        ConversationItem::user("P5"),
        ConversationItem::assistant("R5"),
        ConversationItem::user("P6"),
    ];
    snap.prompt_index = 7;
    snap.prompt_texts = (0..7).map(|i| format!("P{i}")).collect();
    snap.last_compaction_prompt_index = Some(5);
    actor.chat_state_handle.restore_snapshot(snap);
}

/// P111 (DI-01): "rewind all" across a compaction whose checkpoint file is gone (a reopened session, P88). The
/// conversation cannot be rebuilt, so the rewind fails, and it must fail BEFORE any project file is restored or
/// deleted: before P111 the files were reverted first and the response then said `success: false, reverted_files: []`.
#[tokio::test(flavor = "current_thread")]
async fn failed_cross_compaction_rewind_changes_no_project_file() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run_failed_replay_scenario()).await;
}

async fn run_failed_replay_scenario() {
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    let (persistence_tx, persistence_rx) = super::support::answering_persistence();
    let (actor, _gateway_rx) = actor_on_real_fs(root, persistence_tx, "p111-di01").await;

    let session_dir = crate::session::persistence::session_dir(&actor.session_info);
    write_compacted_session_fixture(&session_dir, "ckptgone");
    std::fs::remove_file(session_dir.join("compaction_checkpoints/ckptgone.json")).unwrap();
    restore_compacted_live_state(&actor).await;

    // Prompt 6 edited `edited.txt` and created `created.txt`.
    std::fs::write(root.join("edited.txt"), "after prompt 6").unwrap();
    std::fs::write(root.join("created.txt"), "created by prompt 6").unwrap();
    let tracker = &actor.file_state_tracker;
    tracker
        .add_before_snapshot_for_prompt(6, &root.join("edited.txt"), root, Some("before prompt 6".into()))
        .await;
    tracker
        .add_before_snapshot_for_prompt(6, &root.join("created.txt"), root, None)
        .await;

    let resp = actor
        .handle_rewind(RewindRequest {
            target_prompt_index: 3,
            force: true,
            mode: RewindMode::All,
        })
        .await
        .expect("handle_rewind returns Ok(success=false)");

    let edited = std::fs::read_to_string(root.join("edited.txt")).ok();
    let created_exists = root.join("created.txt").exists();
    let prompt_index = actor.chat_state_handle.get_prompt_index().await;
    let points = tracker.get_rewind_points().await;
    let truncated = drained_truncate_requests(&persistence_rx);
    let _ = std::fs::remove_dir_all(&session_dir);

    assert!(!resp.success, "the rewind cannot rebuild the conversation: {resp:?}");
    assert!(
        resp.error.as_deref().is_some_and(|e| e.contains("checkpoint")),
        "the response says why: {resp:?}"
    );
    assert_eq!(
        edited.as_deref(),
        Some("after prompt 6"),
        "no file may be restored by a rewind that failed"
    );
    assert!(created_exists, "no file may be deleted by a rewind that failed");
    assert!(resp.reverted_files.is_empty(), "{resp:?}");
    assert_eq!(prompt_index, 7, "the conversation is not rewound");
    assert!(
        points.iter().any(|p| p.prompt_index == 6 && p.file_snapshots.len() == 2),
        "the rewind snapshots are kept: {:?}",
        points.iter().map(|p| (p.prompt_index, p.file_snapshots.len())).collect::<Vec<_>>()
    );
    assert!(truncated.is_empty(), "no snapshot truncation was requested: {truncated:?}");
}

/// P111: the same "rewind all" across a compaction with its checkpoint intact still reverts the files and rebuilds the
/// conversation (the reorder of DI-01 changes when files are touched, not whether).
#[tokio::test(flavor = "current_thread")]
async fn cross_compaction_rewind_all_reverts_files_and_conversation() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run_cross_compaction_rewind_all_scenario()).await;
}

async fn run_cross_compaction_rewind_all_scenario() {
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    let (persistence_tx, persistence_rx) = super::support::answering_persistence();
    let (actor, _gateway_rx) = actor_on_real_fs(root, persistence_tx, "p111-all").await;

    let session_dir = crate::session::persistence::session_dir(&actor.session_info);
    write_compacted_session_fixture(&session_dir, "ckptall");
    restore_compacted_live_state(&actor).await;

    std::fs::write(root.join("edited.txt"), "after prompt 6").unwrap();
    std::fs::write(root.join("created.txt"), "created by prompt 6").unwrap();
    let tracker = &actor.file_state_tracker;
    tracker
        .add_before_snapshot_for_prompt(6, &root.join("edited.txt"), root, Some("before prompt 6".into()))
        .await;
    tracker
        .add_before_snapshot_for_prompt(6, &root.join("created.txt"), root, None)
        .await;

    let resp = actor
        .handle_rewind(RewindRequest {
            target_prompt_index: 3,
            force: true,
            mode: RewindMode::All,
        })
        .await
        .expect("handle_rewind ok");

    let texts: Vec<String> = actor
        .chat_state_handle
        .get_conversation()
        .await
        .iter()
        .map(|c| c.text_content())
        .collect();
    let truncated = drained_truncate_requests(&persistence_rx);
    let _ = std::fs::remove_dir_all(&session_dir);

    assert!(resp.success, "{resp:?}");
    assert_eq!(
        std::fs::read_to_string(root.join("edited.txt")).ok().as_deref(),
        Some("before prompt 6")
    );
    assert!(!root.join("created.txt").exists());
    assert_eq!(texts, vec!["SYS", "UI0", "P0", "P1", "P2"]);
    assert_eq!(actor.chat_state_handle.get_prompt_index().await, 3);
    assert_eq!(truncated, vec![3]);
}

/// P111 (DI-02): a file that cannot be restored, and one that cannot be deleted. Before P111 the handler logged them,
/// listed the failed deletion as reverted, rewound the conversation, dropped EVERY rewind snapshot at or after the
/// target (the only saved contents of the file it could not restore) and reported success.
///
/// The failures are ones root cannot override (the build host runs tests as root): the restored file's parent path is
/// a regular file, and the file to delete is a non-empty directory.
#[tokio::test(flavor = "current_thread")]
async fn partial_file_revert_reports_failures_and_keeps_saved_contents() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run_partial_file_revert_scenario()).await;
}

async fn run_partial_file_revert_scenario() {
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    let (persistence_tx, persistence_rx) = super::support::answering_persistence();
    let (actor, _gateway_rx) = actor_on_real_fs(root, persistence_tx, "p111-di02").await;

    let mut snap = actor
        .chat_state_handle
        .snapshot()
        .await
        .expect("snapshot available");
    snap.conversation = vec![
        ConversationItem::system("SYS"),
        ConversationItem::user("UI"),
        ConversationItem::user("P0"),
        ConversationItem::assistant("R0"),
        ConversationItem::user("P1"),
        ConversationItem::assistant("R1"),
    ];
    snap.prompt_index = 2;
    snap.prompt_texts = vec!["P0".into(), "P1".into()];
    actor.chat_state_handle.restore_snapshot(snap);

    // Prompt 1 edited `edited.txt` and `blocked/kept.txt`, and created `created`.
    std::fs::write(root.join("edited.txt"), "agent edit").unwrap();
    let tracker = &actor.file_state_tracker;
    tracker
        .add_before_snapshot_for_prompt(1, &root.join("edited.txt"), root, Some("original edited".into()))
        .await;
    tracker
        .add_before_snapshot_for_prompt(1, &root.join("blocked/kept.txt"), root, Some("original kept".into()))
        .await;
    tracker
        .add_before_snapshot_for_prompt(1, &root.join("created"), root, None)
        .await;
    // Since then `blocked` became a regular file and `created` a non-empty directory.
    std::fs::write(root.join("blocked"), "not a directory").unwrap();
    std::fs::create_dir_all(root.join("created/inner")).unwrap();

    let request = || RewindRequest {
        target_prompt_index: 1,
        force: true,
        mode: RewindMode::All,
    };
    let resp = actor.handle_rewind(request()).await.expect("handle_rewind ok");

    let error = resp.error.clone().unwrap_or_default();
    assert!(!resp.success, "a partial revert is not a success: {resp:?}");
    assert!(
        error.contains("blocked/kept.txt") && error.contains("created"),
        "every file that failed is reported: {error}"
    );
    assert_eq!(
        resp.reverted_files.len(),
        1,
        "only the restored file is listed as reverted: {resp:?}"
    );
    assert!(resp.reverted_files[0].ends_with("edited.txt"), "{resp:?}");
    assert_eq!(
        std::fs::read_to_string(root.join("edited.txt")).ok().as_deref(),
        Some("original edited")
    );
    assert!(root.join("created/inner").is_dir(), "the failed deletion changed nothing");
    assert_eq!(
        actor.chat_state_handle.get_prompt_index().await,
        2,
        "the conversation is not rewound while files disagree with it"
    );
    let points = tracker.get_rewind_points().await;
    assert!(
        points.iter().any(|p| p.prompt_index == 1 && p.file_snapshots.len() == 3),
        "the saved contents are kept for a retry: {:?}",
        points.iter().map(|p| (p.prompt_index, p.file_snapshots.len())).collect::<Vec<_>>()
    );
    let truncated = drained_truncate_requests(&persistence_rx);
    assert!(truncated.is_empty(), "rewind_points.jsonl is not truncated: {truncated:?}");

    // The cause is fixed; the same rewind now completes from the kept snapshots.
    std::fs::remove_file(root.join("blocked")).unwrap();
    std::fs::remove_dir_all(root.join("created")).unwrap();
    std::fs::write(root.join("created"), "agent created").unwrap();
    let retry = actor.handle_rewind(request()).await.expect("handle_rewind ok");
    assert!(retry.success, "{retry:?}");
    assert_eq!(
        std::fs::read_to_string(root.join("blocked/kept.txt")).ok().as_deref(),
        Some("original kept"),
        "the file that failed before is restored from its kept snapshot"
    );
    assert!(!root.join("created").exists());
    assert_eq!(actor.chat_state_handle.get_prompt_index().await, 1);
    assert_eq!(drained_truncate_requests(&persistence_rx), vec![1]);
}

/// P111 (Astra r1): a resumed session loads its saved file contents (`rewind_points.jsonl`) lazily. When that read
/// fails, the rewind must stop with nothing changed. Before, it planned from the in-memory points alone: it restored
/// only those files, rewound the conversation and reported success, and a later successful load inside
/// `truncate_from` then dropped the snapshots of the files it never restored.
#[tokio::test(flavor = "current_thread")]
async fn unreadable_saved_file_contents_stop_the_rewind() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run_unreadable_snapshots_scenario()).await;
}

async fn run_unreadable_snapshots_scenario() {
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    let (persistence_tx, persistence_rx) = super::support::answering_persistence();
    let (mut actor, _gateway_rx) = actor_on_real_fs(root, persistence_tx, "p111-lazy").await;
    // The deferred source cannot be read: it is a directory.
    let unreadable = tempfile::tempdir().unwrap();
    actor.file_state_tracker = std::sync::Arc::new(
        fuigo_workspace::session::file_state::FileStateTracker::with_lazy_source(unreadable.path().to_path_buf()),
    );

    let mut snap = actor
        .chat_state_handle
        .snapshot()
        .await
        .expect("snapshot available");
    snap.conversation = vec![
        ConversationItem::system("SYS"),
        ConversationItem::user("UI"),
        ConversationItem::user("P0"),
        ConversationItem::assistant("R0"),
        ConversationItem::user("P1"),
        ConversationItem::assistant("R1"),
    ];
    snap.prompt_index = 2;
    snap.prompt_texts = vec!["P0".into(), "P1".into()];
    actor.chat_state_handle.restore_snapshot(snap);

    // An in-memory point (the current process's own prompt) that a partial plan would act on.
    std::fs::write(root.join("edited.txt"), "agent edit").unwrap();
    actor
        .file_state_tracker
        .add_before_snapshot_for_prompt(1, &root.join("edited.txt"), root, Some("original".into()))
        .await;

    let resp = actor
        .handle_rewind(RewindRequest {
            target_prompt_index: 1,
            force: true,
            mode: RewindMode::All,
        })
        .await
        .expect("handle_rewind returns Ok(success=false)");

    assert!(!resp.success, "{resp:?}");
    assert!(
        resp.error.as_deref().is_some_and(|e| e.contains("saved file contents")),
        "the response says why: {resp:?}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("edited.txt")).ok().as_deref(),
        Some("agent edit"),
        "no file is restored from a partial plan"
    );
    assert_eq!(actor.chat_state_handle.get_prompt_index().await, 2);
    assert!(drained_truncate_requests(&persistence_rx).is_empty());
}

/// P111 (Astra r3): a malformed row in the saved file contents. The rows that parse would restore only some files; a
/// rewind that reverts files refuses instead, before and after a lenient load (a cancel or a conversation-only rewind
/// loads the same file leniently, skipping the row) consumed the deferred source.
#[tokio::test(flavor = "current_thread")]
async fn a_malformed_saved_snapshot_row_stops_the_rewind() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run_malformed_snapshot_row_scenario()).await;
}

async fn run_malformed_snapshot_row_scenario() {
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    let (persistence_tx, persistence_rx) = super::support::answering_persistence();
    let (mut actor, _gateway_rx) = actor_on_real_fs(root, persistence_tx, "p111-malformed").await;

    // rewind_points.jsonl: a readable point for prompt 1, then a row that does not parse (another prompt's files).
    let writer = fuigo_workspace::session::file_state::FileStateTracker::new();
    writer
        .add_before_snapshot_for_prompt(1, &root.join("edited.txt"), root, Some("original".into()))
        .await;
    let point = writer.get_rewind_points().await.remove(0);
    let saved = tempfile::tempdir().unwrap();
    let rewind_points = saved.path().join("rewind_points.jsonl");
    std::fs::write(
        &rewind_points,
        format!("{}\n{{\"prompt_index\": 1, \"file_snapshots\": [torn\n", serde_json::to_string(&point).unwrap()),
    )
    .unwrap();
    actor.file_state_tracker = std::sync::Arc::new(
        fuigo_workspace::session::file_state::FileStateTracker::with_lazy_source(rewind_points),
    );
    std::fs::write(root.join("edited.txt"), "agent edit").unwrap();

    let mut snap = actor
        .chat_state_handle
        .snapshot()
        .await
        .expect("snapshot available");
    snap.conversation = vec![
        ConversationItem::system("SYS"),
        ConversationItem::user("UI"),
        ConversationItem::user("P0"),
        ConversationItem::assistant("R0"),
        ConversationItem::user("P1"),
        ConversationItem::assistant("R1"),
    ];
    snap.prompt_index = 2;
    snap.prompt_texts = vec!["P0".into(), "P1".into()];
    actor.chat_state_handle.restore_snapshot(snap);

    let request = || RewindRequest {
        target_prompt_index: 1,
        force: true,
        mode: RewindMode::All,
    };
    let first = actor.handle_rewind(request()).await.expect("handle_rewind ok");
    // A lenient load (as a cancel or a conversation-only rewind makes) now consumes the deferred source.
    let _ = actor.file_state_tracker.max_prompt_index().await;
    let second = actor.handle_rewind(request()).await.expect("handle_rewind ok");

    for (label, resp) in [("strict load", &first), ("after a lenient load", &second)] {
        assert!(!resp.success, "{label}: {resp:?}");
        assert!(
            resp.error.as_deref().is_some_and(|e| e.contains("saved file contents")),
            "{label}: the response says why: {resp:?}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(root.join("edited.txt")).ok().as_deref(),
        Some("agent edit"),
        "no file is restored from a partial set"
    );
    assert_eq!(actor.chat_state_handle.get_prompt_index().await, 2);
    assert!(drained_truncate_requests(&persistence_rx).is_empty());
}

/// P111 (Astra r4 #4): a rewind requested its chat history replacement without an acknowledgement, dropped the
/// snapshots and reported success, while the persistence actor only logged a failed replacement. Here the real
/// persistence actor (production `JsonlStorageAdapter`, `ChannelChatPersistence` between the chat state and it) fails
/// every replacement: the rewind must report failure, keep the conversation and every snapshot, and leave
/// `chat_history.jsonl` as it was; once replacements work again the same rewind completes.
#[tokio::test(flavor = "current_thread")]
async fn a_rewind_whose_history_replacement_fails_reports_it_and_keeps_snapshots() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run_rewind_replacement_failure_scenario()).await;
}

async fn run_rewind_replacement_failure_scenario() {
    use crate::session::persistence::{PersistenceMsg, test_seam};
    use crate::session::storage::StorageAdapter as _;

    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    // Everything the session sends to persistence passes through here (to record truncations) to the real actor.
    let (forward_tx, mut forward_rx) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let (mut actor, _gateway_rx) = actor_on_real_fs(root, forward_tx.clone(), "p111-r5-rewind-persist").await;
    let info = actor.session_info.clone();
    let session_dir = crate::session::persistence::session_dir(&info);
    let storage = crate::session::storage::JsonlStorageAdapter::with_explicit_session_dir(session_dir.clone());
    storage
        .init_session(&info, crate::session::persistence::default_model_id())
        .await
        .unwrap();
    let conversation = vec![
        ConversationItem::system("SYS"),
        ConversationItem::user("UI"),
        ConversationItem::user("P0"),
        ConversationItem::assistant("R0"),
        ConversationItem::user("P1"),
        ConversationItem::assistant("R1"),
    ];
    let chat_file = session_dir.join("chat_history.jsonl");
    crate::session::storage::write_jsonl_atomic(&chat_file, &conversation).unwrap();
    let persistence = test_seam::spawn_actor(info.clone(), std::sync::Arc::new(storage));
    let truncations = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let restores = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let seen = truncations.clone();
    let restored = restores.clone();
    tokio::task::spawn_local(async move {
        while let Some(message) = forward_rx.recv().await {
            if let Some(from_index) = super::support::truncation_of(&message) {
                seen.borrow_mut().push(from_index);
            }
            if matches!(message, PersistenceMsg::EndRewindPointsAndAck { put_back: true, .. }) {
                restored.set(restored.get() + 1);
            }
            let _ = persistence.send(message);
        }
    });
    actor.chat_state_handle = super::support::spawn_test_chat_state(
        200_000,
        Box::new(crate::session::chat_persistence::ChannelChatPersistence::new(forward_tx.clone())),
    );
    let mut snap = actor.chat_state_handle.snapshot().await.expect("snapshot available");
    snap.conversation = conversation;
    snap.prompt_index = 2;
    snap.prompt_texts = vec!["P0".into(), "P1".into()];
    actor.chat_state_handle.restore_snapshot(snap);

    std::fs::write(root.join("edited.txt"), "agent edit").unwrap();
    actor
        .file_state_tracker
        .add_before_snapshot_for_prompt(1, &root.join("edited.txt"), root, Some("original".into()))
        .await;
    let barrier = || async {
        let (respond_to, done) = tokio::sync::oneshot::channel();
        forward_tx.send(PersistenceMsg::FlushAndAck { respond_to }).unwrap();
        let _ = done.await;
    };
    let request = || RewindRequest {
        target_prompt_index: 1,
        force: true,
        mode: RewindMode::All,
    };
    let chat_before = std::fs::read(&chat_file).unwrap();
    let points_file = session_dir.join("rewind_points.jsonl");
    let points_before = std::fs::read(&points_file).ok();

    test_seam::fail_history_replacements(&info.id.0, usize::MAX);
    let resp = actor.handle_rewind(request()).await.expect("handle_rewind ok");
    barrier().await;

    assert!(!resp.success, "a rewind whose history was not saved is not a success: {resp:?}");
    let error = resp.error.clone().unwrap_or_default();
    assert!(error.contains("conversation could not be saved"), "{error}");
    assert_eq!(actor.chat_state_handle.get_prompt_index().await, 2, "the conversation is not rewound");
    assert!(
        actor
            .chat_state_handle
            .get_conversation()
            .await
            .iter()
            .any(|item| item.text_content() == "P1"),
        "the model's history is not rewound either"
    );
    let points = actor.file_state_tracker.get_rewind_points().await;
    assert!(
        points.iter().any(|p| p.prompt_index == 1 && p.file_snapshots.len() == 1),
        "the saved contents are kept for a retry"
    );
    // P146: rewind_points.jsonl is rewritten before the conversation is saved, and put back when that save fails.
    assert_eq!(*truncations.borrow(), vec![1], "the rewrite was made under the rewind's lock");
    assert_eq!(restores.get(), 1, "and put back when the conversation could not be saved");
    assert_eq!(std::fs::read(&points_file).ok(), points_before, "rewind_points.jsonl is as it was");
    assert_eq!(std::fs::read(&chat_file).unwrap(), chat_before, "chat_history.jsonl is unchanged");

    // Replacements work again: the same rewind completes from the kept snapshots.
    test_seam::fail_history_replacements(&info.id.0, 0);
    let retry = actor.handle_rewind(request()).await.expect("handle_rewind ok");
    barrier().await;
    let saved = std::fs::read_to_string(&chat_file).unwrap();
    let _ = std::fs::remove_dir_all(&session_dir);

    assert!(retry.success, "{retry:?}");
    assert_eq!(actor.chat_state_handle.get_prompt_index().await, 1);
    assert_eq!(std::fs::read_to_string(root.join("edited.txt")).unwrap(), "original");
    assert_eq!(*truncations.borrow(), vec![1, 1]);
    assert_eq!(restores.get(), 1, "a rewind that went through puts nothing back");
    assert!(saved.contains("P0") && !saved.contains("P1"), "the rewound history is stored: {saved}");
}

/// P114 (Fable P111 #1): a torn row in the middle of `rewind_points.jsonl` (a record cut short inside a multi-byte
/// character when Fuigo stopped, terminated by the next append). What survives of it says it held prompt 2's saved
/// files, so only rewinds to prompt 2 or earlier need it. A rewind to prompt 2 is refused with nothing changed and a message
/// that names the file and line, says which rewinds still work and never says "try again"; a conversation-only rewind
/// is offered and works; a rewind to prompt 4 restores its files and rewinds the conversation.
#[tokio::test(flavor = "current_thread")]
async fn a_torn_saved_snapshot_row_refuses_only_the_rewinds_that_need_it() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run_torn_middle_row_scenario()).await;
}

async fn run_torn_middle_row_scenario() {
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    let (persistence_tx, persistence_rx) = super::support::answering_persistence();
    let (mut actor, _gateway_rx) = actor_on_real_fs(root, persistence_tx, "p114-torn").await;

    let writer = fuigo_workspace::session::file_state::FileStateTracker::new();
    for (prompt, file, before) in [(1, "a.txt", "a before 1"), (2, "d.txt", "café before 2"), (3, "b.txt", "b before 3"), (4, "c.txt", "c before 4")] {
        writer.add_before_snapshot_for_prompt(prompt, &root.join(file), root, Some(before.into())).await;
    }
    let rows: Vec<Vec<u8>> = writer
        .get_rewind_points()
        .await
        .iter()
        .map(|point| {
            let full = serde_json::to_vec(point).unwrap();
            if point.prompt_index == 2 {
                let accent = full.windows(2).position(|w| w == "é".as_bytes()).unwrap();
                full[..accent + 1].to_vec()
            } else {
                full
            }
        })
        .collect();
    let saved = tempfile::tempdir().unwrap();
    let rewind_points = saved.path().join("rewind_points.jsonl");
    std::fs::write(&rewind_points, rows.join(&b'\n').into_iter().chain([b'\n']).collect::<Vec<u8>>()).unwrap();
    actor.file_state_tracker = std::sync::Arc::new(
        fuigo_workspace::session::file_state::FileStateTracker::with_lazy_source(rewind_points.clone()),
    );
    for (file, now) in [("a.txt", "a now"), ("b.txt", "b now"), ("c.txt", "c now")] {
        std::fs::write(root.join(file), now).unwrap();
    }

    let mut snap = actor.chat_state_handle.snapshot().await.expect("snapshot available");
    snap.conversation = vec![ConversationItem::system("SYS"), ConversationItem::user("UI")];
    for i in 0..6 {
        snap.conversation.push(ConversationItem::user(format!("P{i}")));
        snap.conversation.push(ConversationItem::assistant(format!("R{i}")));
    }
    snap.prompt_index = 6;
    snap.prompt_texts = (0..6).map(|i| format!("P{i}")).collect();
    actor.chat_state_handle.restore_snapshot(snap);
    let request = |target_prompt_index, mode| RewindRequest { target_prompt_index, force: true, mode };

    let refused = actor.handle_rewind(request(2, RewindMode::All)).await.expect("handle_rewind ok");
    let error = refused.error.clone().unwrap_or_default();
    assert!(!refused.success, "{refused:?}");
    assert!(refused.reverted_files.is_empty(), "{refused:?}");
    assert!(error.contains(&rewind_points.display().to_string()) && error.contains("line 2"), "names file and line: {error}");
    assert!(error.contains("prompt #3 or later"), "says which file rewinds still work: {error}");
    assert!(error.to_lowercase().contains("conversation-only"), "offers the conversation-only rewind: {error}");
    assert!(!error.to_lowercase().contains("try again"), "retrying cannot repair the row: {error}");
    for (file, now) in [("a.txt", "a now"), ("b.txt", "b now"), ("c.txt", "c now")] {
        assert_eq!(std::fs::read_to_string(root.join(file)).unwrap(), now, "a refused rewind changed {file}");
    }
    assert_eq!(actor.chat_state_handle.get_prompt_index().await, 6, "the conversation is not rewound");
    assert!(drained_truncate_requests(&persistence_rx).is_empty());

    let restored = actor.handle_rewind(request(4, RewindMode::All)).await.expect("handle_rewind ok");
    assert!(restored.success, "a rewind that does not need the damaged row works: {restored:?}");
    assert_eq!(std::fs::read_to_string(root.join("c.txt")).unwrap(), "c before 4");
    assert_eq!(std::fs::read_to_string(root.join("b.txt")).unwrap(), "b now");
    assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "a now");
    assert_eq!(actor.chat_state_handle.get_prompt_index().await, 4);
    assert_eq!(drained_truncate_requests(&persistence_rx), vec![4]);

    let conversation_only = actor.handle_rewind(request(2, RewindMode::ConversationOnly)).await.expect("handle_rewind ok");
    assert!(conversation_only.success, "the offered conversation-only rewind works: {conversation_only:?}");
    assert_eq!(actor.chat_state_handle.get_prompt_index().await, 2);
    assert_eq!(std::fs::read_to_string(root.join("b.txt")).unwrap(), "b now", "files are left as they are");
}

/// P146 (K19): the rewind's rewrite of `rewind_points.jsonl` is part of the rewind. Its lock is taken before anything
/// changes: when it cannot be taken the rewind is refused with no file and no conversation changed. When the rewrite
/// itself fails after the rewind went through, the rewind is not reported as a success and says what is left to do.
#[tokio::test(flavor = "current_thread")]
async fn a_rewind_whose_rewind_points_rewrite_fails_is_not_a_success() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run_rewind_points_rewrite_failure_scenario()).await;
}

async fn run_rewind_points_rewrite_failure_scenario() {
    use crate::session::persistence::PersistenceMsg;
    // What the scripted persistence answers: (lock fails, rewrite fails).
    let script = std::sync::Arc::new(std::sync::Mutex::new((true, false)));
    let rewrites = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (persistence_tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    {
        let script = script.clone();
        let rewrites = rewrites.clone();
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                let (lock_fails, rewrite_fails) = *script.lock().unwrap();
                match message {
                    PersistenceMsg::LockRewindPointsRewrite { gate, respond_to } if gate.start() => {
                        let _ = respond_to.send(if lock_fails {
                            Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "held by another Fuigo process"))
                        } else {
                            Ok(Default::default())
                        });
                    }
                    PersistenceMsg::RewriteRewindPointsAndAck { rewrite, gate, respond_to } if gate.start() => {
                        rewrites.lock().unwrap().push(rewrite);
                        let _ = respond_to.send(if rewrite_fails {
                            Err(std::io::Error::other("disk full"))
                        } else {
                            Ok(Default::default())
                        });
                    }
                    PersistenceMsg::EndRewindPointsAndAck { gate, respond_to, .. } if gate.start() => {
                        let _ = respond_to.send(Ok(()));
                    }
                    _ => {}
                }
            }
        });
    }
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    let (actor, _gateway_rx) = actor_on_real_fs(root, persistence_tx, "p146-k19").await;
    let mut snap = actor.chat_state_handle.snapshot().await.expect("snapshot available");
    snap.conversation = vec![
        ConversationItem::system("SYS"),
        ConversationItem::user("UI"),
        ConversationItem::user("P0"),
        ConversationItem::assistant("R0"),
        ConversationItem::user("P1"),
        ConversationItem::assistant("R1"),
    ];
    snap.prompt_index = 2;
    snap.prompt_texts = vec!["P0".into(), "P1".into()];
    actor.chat_state_handle.restore_snapshot(snap);
    std::fs::write(root.join("edited.txt"), "agent edit").unwrap();
    actor
        .file_state_tracker
        .add_before_snapshot_for_prompt(1, &root.join("edited.txt"), root, Some("original".into()))
        .await;
    let request = |mode| RewindRequest { target_prompt_index: 1, force: true, mode };

    // 1. The lock is held elsewhere: refused, nothing changed, nothing rewritten.
    let refused = actor.handle_rewind(request(RewindMode::All)).await.expect("handle_rewind ok");
    assert!(!refused.success, "{refused:?}");
    let error = refused.error.clone().unwrap_or_default();
    assert!(error.contains("Nothing was changed") && error.contains("held by another Fuigo process"), "{error}");
    assert_eq!(std::fs::read_to_string(root.join("edited.txt")).unwrap(), "agent edit", "no file was reverted");
    assert_eq!(actor.chat_state_handle.get_prompt_index().await, 2, "the conversation is not rewound");
    assert!(
        actor.file_state_tracker.get_rewind_points().await.iter().any(|p| p.prompt_index == 1),
        "the saved contents are kept"
    );
    assert!(rewrites.lock().unwrap().is_empty());

    // 2. The lock is taken but the rewrite fails: not a success, the conversation is not rewound and every snapshot
    // is kept, so the same rewind can run again (the files were reverted, and the message says so).
    *script.lock().unwrap() = (false, true);
    let incomplete = actor.handle_rewind(request(RewindMode::All)).await.expect("handle_rewind ok");
    assert!(!incomplete.success, "a rewind whose rewind_points rewrite failed is not a success: {incomplete:?}");
    let error = incomplete.error.clone().unwrap_or_default();
    assert!(
        error.contains("is incomplete") && error.contains("disk full") && error.contains("conversation was not rewound")
            && error.contains("edited.txt") && error.contains("run the same rewind again"),
        "{error}"
    );
    assert_eq!(actor.chat_state_handle.get_prompt_index().await, 2, "the conversation is not rewound");
    assert!(
        actor.file_state_tracker.get_rewind_points().await.iter().any(|p| p.prompt_index == 1),
        "the saved contents are kept for a retry"
    );
    assert_eq!(
        *rewrites.lock().unwrap(),
        vec![crate::session::storage::RewindPointsRewrite::TruncateFrom(1)]
    );

    // 3. The same rewind, once the rewrite works, completes.
    *script.lock().unwrap() = (false, false);
    let finished = actor.handle_rewind(request(RewindMode::All)).await.expect("handle_rewind ok");
    assert!(finished.success, "{finished:?}");
    assert_eq!(actor.chat_state_handle.get_prompt_index().await, 1);
    assert_eq!(std::fs::read_to_string(root.join("edited.txt")).unwrap(), "original");
    assert_eq!(rewrites.lock().unwrap().len(), 2);
}

/// P146 (Astra r3 #4): a durable copy left by a rewind that did not finish (`rewind_points.jsonl.pre-rewind`) may hold
/// saved file versions rewind_points.jsonl lost. The next rewind is refused, names the file and says what to do, and
/// changes nothing.
#[tokio::test(flavor = "current_thread")]
async fn a_rewind_is_refused_while_an_unfinished_rewinds_copy_is_left() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run_leftover_pre_rewind_scenario()).await;
}

async fn run_leftover_pre_rewind_scenario() {
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    let (persistence_tx, persistence_rx) = super::support::answering_persistence();
    let (actor, _gateway_rx) = actor_on_real_fs(root, persistence_tx, "p146-leftover").await;
    let mut snap = actor.chat_state_handle.snapshot().await.expect("snapshot available");
    snap.conversation = vec![
        ConversationItem::system("SYS"),
        ConversationItem::user("UI"),
        ConversationItem::user("P0"),
        ConversationItem::assistant("R0"),
        ConversationItem::user("P1"),
        ConversationItem::assistant("R1"),
    ];
    snap.prompt_index = 2;
    snap.prompt_texts = vec!["P0".into(), "P1".into()];
    actor.chat_state_handle.restore_snapshot(snap);
    std::fs::write(root.join("edited.txt"), "agent edit").unwrap();
    actor
        .file_state_tracker
        .add_before_snapshot_for_prompt(1, &root.join("edited.txt"), root, Some("original".into()))
        .await;
    let session_dir = crate::session::persistence::session_dir(&actor.session_info);
    std::fs::create_dir_all(&session_dir).unwrap();
    let copy = session_dir.join("rewind_points.jsonl.pre-rewind");
    std::fs::write(&copy, b"{}\n").unwrap();
    let request = || RewindRequest { target_prompt_index: 1, force: true, mode: RewindMode::All };

    let refused = actor.handle_rewind(request()).await.expect("handle_rewind ok");
    assert!(!refused.success, "{refused:?}");
    let error = refused.error.clone().unwrap_or_default();
    assert!(error.contains("rewind_points.jsonl.pre-rewind") && error.contains("Nothing was changed"), "{error}");
    assert_eq!(std::fs::read_to_string(root.join("edited.txt")).unwrap(), "agent edit");
    assert_eq!(actor.chat_state_handle.get_prompt_index().await, 2);
    assert!(drained_truncate_requests(&persistence_rx).is_empty());

    // Dealt with: the rewind runs.
    std::fs::remove_file(&copy).unwrap();
    let done = actor.handle_rewind(request()).await.expect("handle_rewind ok");
    let _ = std::fs::remove_dir_all(&session_dir);
    assert!(done.success, "{done:?}");
    assert_eq!(drained_truncate_requests(&persistence_rx), vec![1]);
}

/// P153 (Fable P146 F1): a rewind that went through but whose `End` was abandoned (the persistence queue was stuck
/// behind another process's lock) must not leave `rewind_points.jsonl.pre-rewind` behind. The rewind task removes it
/// itself, and the next rewind is not refused.
#[tokio::test(flavor = "current_thread")]
async fn a_successful_rewind_whose_end_failed_does_not_leave_the_copy() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run_abandoned_end_scenario()).await;
}

async fn run_abandoned_end_scenario() {
    use crate::session::persistence::PersistenceMsg;
    let copy_path = std::sync::Arc::new(std::sync::Mutex::new(None::<std::path::PathBuf>));
    let (persistence_tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    {
        let copy_path = copy_path.clone();
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                match message {
                    PersistenceMsg::LockRewindPointsRewrite { gate, respond_to } if gate.start() => {
                        let _ = respond_to.send(Ok(Default::default()));
                    }
                    PersistenceMsg::RewriteRewindPointsAndAck { gate, respond_to, .. } if gate.start() => {
                        // The real rewrite leaves the durable copy behind until the End.
                        if let Some(path) = copy_path.lock().unwrap().clone() {
                            std::fs::write(path, b"{}\n").unwrap();
                        }
                        let _ = respond_to.send(Ok(Default::default()));
                    }
                    PersistenceMsg::EndRewindPointsAndAck { gate, respond_to, .. } if gate.start() => {
                        // The queue was stuck: the End never ran.
                        let _ = respond_to.send(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "abandoned behind another process's lock",
                        )));
                    }
                    _ => {}
                }
            }
        });
    }
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    let (actor, _gateway_rx) = actor_on_real_fs(root, persistence_tx, "p153-abandoned-end").await;
    let session_dir = crate::session::persistence::session_dir(&actor.session_info);
    std::fs::create_dir_all(&session_dir).unwrap();
    let copy = session_dir.join("rewind_points.jsonl.pre-rewind");
    *copy_path.lock().unwrap() = Some(copy.clone());
    let mut snap = actor.chat_state_handle.snapshot().await.expect("snapshot available");
    snap.conversation = vec![
        ConversationItem::system("SYS"),
        ConversationItem::user("UI"),
        ConversationItem::user("P0"),
        ConversationItem::assistant("R0"),
        ConversationItem::user("P1"),
        ConversationItem::assistant("R1"),
    ];
    snap.prompt_index = 2;
    snap.prompt_texts = vec!["P0".into(), "P1".into()];
    actor.chat_state_handle.restore_snapshot(snap);
    std::fs::write(root.join("edited.txt"), "agent edit").unwrap();
    actor
        .file_state_tracker
        .add_before_snapshot_for_prompt(1, &root.join("edited.txt"), root, Some("original".into()))
        .await;
    let request = |target| RewindRequest { target_prompt_index: target, force: true, mode: RewindMode::All };

    let done = actor.handle_rewind(request(1)).await.expect("handle_rewind ok");
    assert!(done.success, "{done:?}");
    assert!(
        copy.symlink_metadata().is_err(),
        "a rewind that went through leaves no rewind_points.jsonl.pre-rewind behind"
    );
    let next = actor.handle_rewind(request(0)).await.expect("handle_rewind ok");
    let _ = std::fs::remove_dir_all(&session_dir);
    assert!(
        !next.error.clone().unwrap_or_default().contains("did not finish"),
        "the next rewind is not refused over a copy that was not left: {next:?}"
    );
}

/// P153: the refusal text must not tell the user to move the copy over unless the transcript still shows the turns the
/// rewind should have removed. A planted symlink at the copy's path counts as a copy (it is not followed).
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn a_leftover_copy_refusal_says_when_to_move_it_and_a_link_is_not_followed() {
    let local = tokio::task::LocalSet::new();
    local.run_until(async {
        let project = tempfile::tempdir().unwrap();
        let root = project.path();
        let (persistence_tx, _persistence_rx) = super::support::answering_persistence();
        let (actor, _gateway_rx) = actor_on_real_fs(root, persistence_tx, "p153-refusal").await;
        let mut snap = actor.chat_state_handle.snapshot().await.expect("snapshot available");
        snap.conversation = vec![
            ConversationItem::system("SYS"),
            ConversationItem::user("UI"),
            ConversationItem::user("P0"),
            ConversationItem::assistant("R0"),
        ];
        snap.prompt_index = 1;
        snap.prompt_texts = vec!["P0".into()];
        actor.chat_state_handle.restore_snapshot(snap);
        let session_dir = crate::session::persistence::session_dir(&actor.session_info);
        std::fs::create_dir_all(&session_dir).unwrap();
        // A dangling link: `exists()` follows it and says no; the copy check must not.
        let copy = session_dir.join("rewind_points.jsonl.pre-rewind");
        std::os::unix::fs::symlink(root.join("nowhere"), &copy).unwrap();
        let refused = actor
            .handle_rewind(RewindRequest { target_prompt_index: 0, force: true, mode: RewindMode::All })
            .await
            .expect("handle_rewind ok");
        let _ = std::fs::remove_dir_all(&session_dir);
        assert!(!refused.success, "{refused:?}");
        let error = refused.error.clone().unwrap_or_default();
        assert!(
            error.contains("Delete it; move it over") && error.contains("transcript still shows the turns that rewind should have removed"),
            "{error}"
        );
    })
    .await;
}
