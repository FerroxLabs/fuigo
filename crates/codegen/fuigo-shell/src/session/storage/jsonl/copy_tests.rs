use crate::sampling::ConversationItem;
use crate::session::info::Info;
use crate::session::persistence::{CHAT_FORMAT_VERSION, default_model_id};
use crate::session::storage::{
    CopySessionOptions, CopySessionResult, JsonlStorageAdapter, SessionUpdate, StorageAdapter,
};
use crate::tools::todo::TodoState;
use agent_client_protocol as acp;
use tempfile::TempDir;

fn fork_user_chunk(session_id: &str, text: &str, prompt_index: usize) -> SessionUpdate {
    let chunk = acp::ContentChunk::new(acp::ContentBlock::Text(acp::TextContent::new(
        text.to_string(),
    )))
    .meta(
        serde_json::json!({ "promptIndex": prompt_index })
            .as_object()
            .cloned(),
    );
    SessionUpdate::Acp(Box::new(acp::SessionNotification::new(
        acp::SessionId::new(session_id),
        acp::SessionUpdate::UserMessageChunk(chunk),
    )))
}

fn fork_agent_chunk(session_id: &str, text: &str) -> SessionUpdate {
    SessionUpdate::Acp(Box::new(acp::SessionNotification::new(
        acp::SessionId::new(session_id),
        acp::SessionUpdate::AgentMessageChunk(acp::ContentChunk::new(acp::ContentBlock::Text(
            acp::TextContent::new(text.to_string()),
        ))),
    )))
}

fn fork_rewind_marker(session_id: &str, target_prompt_index: usize) -> SessionUpdate {
    use crate::extensions::notification::{
        SessionNotification as FuigoSessionNotification, SessionUpdate as FuigoSessionUpdateType,
    };
    SessionUpdate::Fuigo(Box::new(FuigoSessionNotification {
        session_id: acp::SessionId::new(session_id),
        update: FuigoSessionUpdateType::RewindMarker {
            target_prompt_index,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        },
        meta: None,
    }))
}

fn chat_user(text: &str, prompt_index: usize) -> ConversationItem {
    let mut item = ConversationItem::user(text);
    item.set_prompt_index(prompt_index);
    item
}

/// Fork truncation targets the live branch (dead-branch runs from a prior rewind overlap its stamps, since indices are branch-local).
/// Prompt N is kept inclusive in both the updates and chat (model-context) files.
#[tokio::test]
async fn copy_session_data_fork_truncates_live_branch_inclusive() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "src-rewound";
    let source_info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();

    // Prompt 1 was rewound and retried: P1-dead/A1-dead is the dead branch.
    for update in [
        fork_user_chunk(sid, "P0", 0),
        fork_agent_chunk(sid, "A0"),
        fork_user_chunk(sid, "P1-dead", 1),
        fork_agent_chunk(sid, "A1-dead"),
        fork_rewind_marker(sid, 1),
        fork_user_chunk(sid, "P1b", 1),
        fork_agent_chunk(sid, "A1b"),
        fork_user_chunk(sid, "P2", 2),
    ] {
        adapter.append_update(&source_info, &update).await.unwrap();
    }
    for item in [
        chat_user("P0", 0),
        ConversationItem::assistant("A0"),
        chat_user("P1b", 1),
        ConversationItem::assistant("A1b"),
        chat_user("P2", 2),
    ] {
        adapter
            .append_chat_message(&source_info, &item)
            .await
            .unwrap();
    }

    let fork_at = |target: usize, fork_id: &str| {
        let target_info = Info {
            id: acp::SessionId::new(fork_id),
            cwd: "/src".to_string(),
        };
        let options = CopySessionOptions {
            target_prompt_index: Some(target),
            ..Default::default()
        };
        (target_info, options)
    };

    // Fork at live prompt 1: keeps P0, A0, P1b, A1b in both files
    // A raw run count would cut inside the dead branch instead
    let (target_info, options) = fork_at(1, "fork-at-1");
    let result = adapter
        .copy_session_data(&source_info, &target_info, options)
        .await
        .unwrap();
    assert_eq!(result.updates_copied, 4);
    assert_eq!(result.chat_messages_copied, 4);
    let loaded = adapter.load_session(&target_info).await.unwrap();
    let last = loaded.updates.last().unwrap();
    assert!(
        matches!(
            last,
            SessionUpdate::Acp(n) if matches!(
                &n.update,
                acp::SessionUpdate::AgentMessageChunk(c)
                    if matches!(&c.content, acp::ContentBlock::Text(t) if t.text == "A1b")
            )
        ),
        "fork must end at the live branch's A1b, got {last:?}"
    );

    // Prompt 0 is kept inclusive; an exclusive cut would copy an empty model context here
    let (target_info, options) = fork_at(0, "fork-at-0");
    let result = adapter
        .copy_session_data(&source_info, &target_info, options)
        .await
        .unwrap();
    assert_eq!(result.updates_copied, 2, "P0 + A0");
    assert_eq!(result.chat_messages_copied, 2, "P0 + A0 in model context");
}

/// Without a `target_prompt_index`, every line streams through: rewind markers and dead branches survive a plain fork.
/// A regression that routes the default path through the rewind filter would strip them silently.
#[tokio::test]
async fn copy_session_data_without_prompt_target_preserves_dead_branches() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "src-dead-branch";
    let source_info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();

    for update in [
        fork_user_chunk(sid, "P0", 0),
        fork_agent_chunk(sid, "A0"),
        fork_user_chunk(sid, "P1-dead", 1),
        fork_rewind_marker(sid, 1),
        fork_user_chunk(sid, "P1b", 1),
    ] {
        adapter.append_update(&source_info, &update).await.unwrap();
    }

    let target_info = Info {
        id: acp::SessionId::new("fork-plain"),
        cwd: "/src".to_string(),
    };
    let result = adapter
        .copy_session_data(&source_info, &target_info, CopySessionOptions::default())
        .await
        .unwrap();
    assert_eq!(
        result.updates_copied, 5,
        "dead branch and rewind marker must survive a plain fork"
    );
}

/// The streaming fork copy skips torn or undecodable lines like the load path does, both with and without a prompt-index cut.
#[tokio::test]
async fn copy_session_data_skips_torn_updates_lines() {
    use std::io::Write as _;

    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "src-torn";
    let source_info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();

    for update in [fork_user_chunk(sid, "P0", 0), fork_agent_chunk(sid, "A0")] {
        adapter.append_update(&source_info, &update).await.unwrap();
    }
    // A torn append (truncated JSON) and an undecodable line.
    let updates_path = adapter.updates_file_path(&source_info).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&updates_path)
        .unwrap();
    file.write_all(b"{\"method\":\"session/update\",\"params\":{tor\n")
        .unwrap();
    file.write_all(&[0xFF, 0xFE, b'\n']).unwrap();
    drop(file);
    adapter
        .append_update(&source_info, &fork_user_chunk(sid, "P1", 1))
        .await
        .unwrap();

    let target_info = Info {
        id: acp::SessionId::new("fork-torn"),
        cwd: "/src".to_string(),
    };
    let result = adapter
        .copy_session_data(&source_info, &target_info, CopySessionOptions::default())
        .await
        .unwrap();
    assert_eq!(result.updates_copied, 3, "P0 + A0 + P1, torn lines dropped");
    let loaded = adapter.load_session(&target_info).await.unwrap();
    assert_eq!(loaded.updates.len(), 3);

    let target_info = Info {
        id: acp::SessionId::new("fork-torn-at-0"),
        cwd: "/src".to_string(),
    };
    let options = CopySessionOptions {
        target_prompt_index: Some(0),
        ..Default::default()
    };
    let result = adapter
        .copy_session_data(&source_info, &target_info, options)
        .await
        .unwrap();
    assert_eq!(result.updates_copied, 2, "P0 + A0; torn tail and P1 cut");
}

/// A torn line inside a multi-chunk user run ends the run during the prompt cut, so the second chunk opens a new counted turn.
/// Replay counts raw lines the same way; this test pins the boundary so a classifier change is deliberate.
#[tokio::test]
async fn torn_line_inside_user_run_splits_the_run_for_prompt_cut() {
    use std::io::Write as _;

    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "src-torn-mid-run";
    let source_info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();

    for update in [
        fork_user_chunk(sid, "P0", 0),
        fork_agent_chunk(sid, "A0"),
        fork_user_chunk(sid, "P1a", 1),
    ] {
        adapter.append_update(&source_info, &update).await.unwrap();
    }
    let updates_path = adapter.updates_file_path(&source_info).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&updates_path)
        .unwrap();
    file.write_all(b"{torn mid-run\n").unwrap();
    drop(file);
    for update in [
        fork_user_chunk(sid, "P1b", 1),
        fork_agent_chunk(sid, "A1"),
        fork_user_chunk(sid, "P2", 2),
    ] {
        adapter.append_update(&source_info, &update).await.unwrap();
    }

    let target_info = Info {
        id: acp::SessionId::new("fork-torn-mid-run"),
        cwd: "/src".to_string(),
    };
    let options = CopySessionOptions {
        target_prompt_index: Some(1),
        ..Default::default()
    };
    let result = adapter
        .copy_session_data(&source_info, &target_info, options)
        .await
        .unwrap();
    // P1b re-counts as a turn after the torn split, so the cut lands before it: P0, A0, P1a survive
    // The contiguous-run cut would have kept 5
    assert_eq!(result.updates_copied, 3, "P0 + A0 + P1a");
}

fn create_test_chat_messages() -> Vec<ConversationItem> {
    vec![
        ConversationItem::user("Hello world"),
        ConversationItem::user("How are you?"),
        ConversationItem::user("Test message"),
    ]
}

fn create_test_notification() -> acp::SessionNotification {
    acp::SessionNotification::new(
        acp::SessionId::new("test-session-123"),
        acp::SessionUpdate::AgentMessageChunk(acp::ContentChunk::new(acp::ContentBlock::Text(
            acp::TextContent::new("Test response".to_string()),
        ))),
    )
}

fn create_test_plan_state() -> TodoState {
    TodoState::default()
}

#[tokio::test]
async fn copy_session_data_copies_compaction_segments_when_enabled() {
    use crate::extensions::notification::CompactionSegmentFile;
    use fuigo_sampling_types::ConversationItem;

    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());

    let source_info = Info {
        id: acp::SessionId::new("seg-src"),
        cwd: "/source/workspace".to_string(),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();
    for msg in &create_test_chat_messages() {
        adapter
            .append_chat_message(&source_info, msg)
            .await
            .unwrap();
    }

    // Two compaction segments produce compaction/{segment_000.md, segment_001.md, INDEX.md}
    let seg = |s: &str| CompactionSegmentFile {
        items: vec![ConversationItem::user("a"), ConversationItem::user("b")],
        summary: s.to_string(),
        detail: fuigo_chat_state::CompactionDetail::Verbose,
        timestamp: "2026-01-01T00:00:00Z".to_string(),
    };
    adapter
        .write_compaction_segment(&source_info, &seg("first"))
        .await
        .unwrap();
    adapter
        .write_compaction_segment(&source_info, &seg("second"))
        .await
        .unwrap();

    let target_info = Info {
        id: acp::SessionId::new("seg-dst"),
        cwd: "/target/workspace".to_string(),
    };
    let result = adapter
        .copy_session_data(
            &source_info,
            &target_info,
            CopySessionOptions {
                copy_compaction_segments: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(result.compaction_segments_copied, 3);

    let dst = adapter
        .session_dir(&target_info)
        .join(fuigo_compaction_transcript::COMPACTION_DIR);
    assert!(dst.join("segment_000.md").is_file());
    assert!(dst.join("segment_001.md").is_file());
    assert!(dst.join("INDEX.md").is_file());
    assert!(
        std::fs::read_to_string(dst.join("segment_000.md"))
            .unwrap()
            .contains("# HISTORICAL -- DO NOT EDIT")
    );

    let target2 = Info {
        id: acp::SessionId::new("seg-dst-default"),
        cwd: "/target2/workspace".to_string(),
    };
    let result2 = adapter
        .copy_session_data(&source_info, &target2, CopySessionOptions::default())
        .await
        .unwrap();
    assert_eq!(result2.compaction_segments_copied, 0);
    assert!(
        !adapter
            .session_dir(&target2)
            .join(fuigo_compaction_transcript::COMPACTION_DIR)
            .exists()
    );
}

fn checkpoint_record(id: &str) -> SessionUpdate {
    checkpoint_record_with_path(id, &format!("compaction_checkpoints/{id}.json"))
}

fn checkpoint_record_with_path(id: &str, checkpoint_file: &str) -> SessionUpdate {
    use crate::extensions::notification::{
        CompactionCheckpointInfo, SessionNotification as FuigoSessionNotification,
        SessionUpdate as FuigoSessionUpdateType,
    };
    SessionUpdate::Fuigo(Box::new(FuigoSessionNotification {
        session_id: acp::SessionId::new("ckpt-src"),
        update: FuigoSessionUpdateType::CompactionCheckpoint(Box::new(CompactionCheckpointInfo {
            checkpoint_id: id.to_string(),
            prompt_index_at_compaction: 1,
            checkpoint_file: checkpoint_file.to_string(),
            auto_continue: None,
            schema_version: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        })),
        meta: None,
    }))
}

/// A user message chunk stamped with `_meta.promptIndex` so `truncate_for_prompt_by` counts it as a turn.
fn prompt_user_chunk(text: &str, prompt_index: usize) -> SessionUpdate {
    SessionUpdate::Acp(Box::new(acp::SessionNotification::new(
        acp::SessionId::new("ckpt-src"),
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

/// A current-format checkpoint (resolved prefix set). P111: a point-in-time copy whose cut keeps a LEGACY checkpoint
/// while the source's live history starts from a later one is now refused (the child would inherit that later
/// summary), so the cut fixture below uses the current format, whose cut is rebuilt from its projection.
async fn write_checkpoint_file(adapter: &JsonlStorageAdapter, info: &Info, id: &str) {
    use crate::extensions::notification::CompactionCheckpointFile;
    adapter
        .write_compaction_checkpoint(
            info,
            &CompactionCheckpointFile {
                inherited_prefix_len: Some(0),
                checkpoint_id: id.to_string(),
                prompt_index_at_compaction: 1,
                compacted_history: vec![],
                schema_version: 1,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                original_user_info: None,
                reread_file_paths: vec![],
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn copy_session_data_copies_referenced_compaction_checkpoints() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());

    let source_info = Info {
        id: acp::SessionId::new("ckpt-src"),
        cwd: "/source/workspace".to_string(),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();
    // Two records referencing the same file (e.g. a chained fork) must still produce one copy.
    for _ in 0..2 {
        adapter
            .append_update(&source_info, &checkpoint_record("ckpt-a"))
            .await
            .unwrap();
    }
    write_checkpoint_file(&adapter, &source_info, "ckpt-a").await;

    let target_info = Info {
        id: acp::SessionId::new("ckpt-dst"),
        cwd: "/target/workspace".to_string(),
    };
    let result = adapter
        .copy_session_data(&source_info, &target_info, CopySessionOptions::default())
        .await
        .unwrap();

    assert_eq!(result.compaction_checkpoints_copied, 1);
    assert_eq!(
        result.updates_copied, 2,
        "checkpoint records must be copied"
    );
    let rel = "compaction_checkpoints/ckpt-a.json";
    let copied = std::fs::read(adapter.session_dir(&target_info).join(rel)).unwrap();
    let original = std::fs::read(adapter.session_dir(&source_info).join(rel)).unwrap();
    assert_eq!(copied, original, "checkpoint file must be copied verbatim");
}

#[tokio::test]
async fn fork_filter_copy_skips_compaction_checkpoints() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());

    let source_info = Info {
        id: acp::SessionId::new("ckpt-src"),
        cwd: "/source/workspace".to_string(),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();
    adapter
        .append_update(&source_info, &checkpoint_record("ckpt-a"))
        .await
        .unwrap();
    write_checkpoint_file(&adapter, &source_info, "ckpt-a").await;

    let target_info = Info {
        id: acp::SessionId::new("ckpt-dst"),
        cwd: "/target/workspace".to_string(),
    };
    // fork_filter clears the copied updates, so no record survives and no checkpoint file should come along
    let result = adapter
        .copy_session_data(
            &source_info,
            &target_info,
            CopySessionOptions {
                fork_filter: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(result.compaction_checkpoints_copied, 0);
    assert_eq!(
        result.updates_copied, 0,
        "fork_filter clears the transcript"
    );
    assert!(
        !adapter
            .session_dir(&target_info)
            .join("compaction_checkpoints")
            .exists()
    );
}

#[tokio::test]
async fn target_prompt_index_truncation_gates_checkpoint_copy() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());

    let source_info = Info {
        id: acp::SessionId::new("ckpt-src"),
        cwd: "/source/workspace".to_string(),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();
    for update in [
        prompt_user_chunk("P0", 0),
        checkpoint_record("ckpt-early"),
        prompt_user_chunk("P1", 1),
        prompt_user_chunk("P2", 2),
        checkpoint_record("ckpt-late"),
    ] {
        adapter.append_update(&source_info, &update).await.unwrap();
    }
    write_checkpoint_file(&adapter, &source_info, "ckpt-early").await;
    write_checkpoint_file(&adapter, &source_info, "ckpt-late").await;

    let target_info = Info {
        id: acp::SessionId::new("ckpt-dst"),
        cwd: "/target/workspace".to_string(),
    };
    // Truncating to prompt 0 keeps [P0, ckpt-early] and drops the rest.
    let result = adapter
        .copy_session_data(
            &source_info,
            &target_info,
            CopySessionOptions {
                target_prompt_index: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(result.compaction_checkpoints_copied, 1);
    let dst = adapter
        .session_dir(&target_info)
        .join("compaction_checkpoints");
    assert!(
        dst.join("ckpt-early.json").is_file(),
        "record before the cut keeps its checkpoint file"
    );
    assert!(
        !dst.join("ckpt-late.json").exists(),
        "record after the cut must not pull its checkpoint file"
    );
}

#[tokio::test]
async fn dangling_checkpoint_record_copies_without_file() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());

    let source_info = Info {
        id: acp::SessionId::new("ckpt-src"),
        cwd: "/source/workspace".to_string(),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();
    // The record is present but its file was never written: the source was already broken
    adapter
        .append_update(&source_info, &checkpoint_record("ckpt-gone"))
        .await
        .unwrap();

    let target_info = Info {
        id: acp::SessionId::new("ckpt-dst"),
        cwd: "/target/workspace".to_string(),
    };
    let result = adapter
        .copy_session_data(&source_info, &target_info, CopySessionOptions::default())
        .await
        .unwrap();

    assert_eq!(result.compaction_checkpoints_copied, 0);
    assert_eq!(result.updates_copied, 1, "the record itself still copies");
    assert!(
        !adapter
            .session_dir(&target_info)
            .join("compaction_checkpoints/ckpt-gone.json")
            .exists()
    );
}

#[tokio::test]
async fn checkpoint_record_with_non_checkpoint_path_is_not_copied() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());

    let source_info = Info {
        id: acp::SessionId::new("ckpt-src"),
        cwd: "/source/workspace".to_string(),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();
    // A doctored record addressing another session file: copying it would clobber the target's rewritten updates.jsonl with raw source bytes
    adapter
        .append_update(
            &source_info,
            &checkpoint_record_with_path("ckpt-evil", "updates.jsonl"),
        )
        .await
        .unwrap();
    // A real checkpoint dir is present so the path-shape guard (not the missing-dir guard) is what rejects the record
    std::fs::create_dir_all(
        adapter
            .session_dir(&source_info)
            .join("compaction_checkpoints"),
    )
    .unwrap();

    let target_info = Info {
        id: acp::SessionId::new("ckpt-dst"),
        cwd: "/target/workspace".to_string(),
    };
    let result = adapter
        .copy_session_data(&source_info, &target_info, CopySessionOptions::default())
        .await
        .unwrap();

    assert_eq!(result.compaction_checkpoints_copied, 0);
    // The target updates must keep the transformed record (session id rewritten to the fork), not the source file's raw bytes
    let loaded = adapter.load_session(&target_info).await.unwrap();
    assert_eq!(loaded.updates.len(), 1);
    match &loaded.updates[0] {
        SessionUpdate::Fuigo(notification) => {
            assert_eq!(notification.session_id.0.as_ref(), "ckpt-dst");
        }
        other => panic!("Expected Fuigo update, got {other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_checkpoint_file_is_not_copied() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());

    let source_info = Info {
        id: acp::SessionId::new("ckpt-src"),
        cwd: "/source/workspace".to_string(),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();
    adapter
        .append_update(&source_info, &checkpoint_record("ckpt-a"))
        .await
        .unwrap();
    // Plant a symlink where the checkpoint file should be: the copy must not follow it out of the session directory
    let ckpt_dir = adapter
        .session_dir(&source_info)
        .join("compaction_checkpoints");
    std::fs::create_dir_all(&ckpt_dir).unwrap();
    let outside = temp_dir.path().join("outside.json");
    std::fs::write(&outside, b"outside bytes").unwrap();
    std::os::unix::fs::symlink(&outside, ckpt_dir.join("ckpt-a.json")).unwrap();

    let target_info = Info {
        id: acp::SessionId::new("ckpt-dst"),
        cwd: "/target/workspace".to_string(),
    };
    let result = adapter
        .copy_session_data(&source_info, &target_info, CopySessionOptions::default())
        .await
        .unwrap();

    assert_eq!(result.compaction_checkpoints_copied, 0);
    assert!(
        !adapter
            .session_dir(&target_info)
            .join("compaction_checkpoints/ckpt-a.json")
            .exists()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_checkpoint_dir_is_not_copied() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());

    let source_info = Info {
        id: acp::SessionId::new("ckpt-src"),
        cwd: "/source/workspace".to_string(),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();
    adapter
        .append_update(&source_info, &checkpoint_record("ckpt-a"))
        .await
        .unwrap();
    // Plant the whole compaction_checkpoints dir as a symlink to an outside dir holding a matching .json: nothing may be copied
    let outside_dir = temp_dir.path().join("outside");
    std::fs::create_dir_all(&outside_dir).unwrap();
    std::fs::write(outside_dir.join("ckpt-a.json"), b"outside bytes").unwrap();
    std::os::unix::fs::symlink(
        &outside_dir,
        adapter
            .session_dir(&source_info)
            .join("compaction_checkpoints"),
    )
    .unwrap();

    let target_info = Info {
        id: acp::SessionId::new("ckpt-dst"),
        cwd: "/target/workspace".to_string(),
    };
    let result = adapter
        .copy_session_data(&source_info, &target_info, CopySessionOptions::default())
        .await
        .unwrap();

    assert_eq!(result.compaction_checkpoints_copied, 0);
    assert!(
        !adapter
            .session_dir(&target_info)
            .join("compaction_checkpoints")
            .exists()
    );
}

#[tokio::test]
async fn copy_session_data_basic() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());

    let source_info = Info {
        id: acp::SessionId::new("source-session-123"),
        cwd: "/source/workspace".to_string(),
    };

    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();

    let messages = create_test_chat_messages();
    for msg in &messages {
        adapter
            .append_chat_message(&source_info, msg)
            .await
            .unwrap();
    }

    let notification = create_test_notification();
    adapter
        .append_update(&source_info, &SessionUpdate::Acp(Box::new(notification)))
        .await
        .unwrap();

    let plan_state = create_test_plan_state();
    adapter
        .write_plan_state(&source_info, &plan_state)
        .await
        .unwrap();

    let target_info = Info {
        id: acp::SessionId::new("fork-source-session-123-abcd1234"),
        cwd: "/target/workspace".to_string(),
    };

    let options = CopySessionOptions {
        parent_session_id: Some("source-session-123".to_string()),
        new_model_id: None,
        target_prompt_index: None,
        ..Default::default()
    };
    let result = adapter
        .copy_session_data(&source_info, &target_info, options)
        .await
        .unwrap();

    assert_eq!(result.chat_messages_copied, 3);
    assert_eq!(result.updates_copied, 1);
    assert!(result.plan_state_copied);

    let loaded = adapter.load_session(&target_info).await.unwrap();
    assert_eq!(loaded.summary.info.id, target_info.id);
    assert_eq!(loaded.summary.info.cwd, "/target/workspace");
    assert_eq!(loaded.summary.session_kind.as_deref(), Some("fork"));
    assert_eq!(
        loaded.summary.parent_session_id,
        Some("source-session-123".to_string())
    );
    assert!(loaded.summary.forked_at.is_some());
    assert_eq!(loaded.chat_history.len(), 3);
    assert_eq!(loaded.updates.len(), 1);
    match &loaded.updates[0] {
        SessionUpdate::Acp(notification) => {
            assert_eq!(
                notification.session_id.0.as_ref(),
                "fork-source-session-123-abcd1234"
            );
        }
        _ => panic!("Expected ACP update"),
    }
    assert!(loaded.plan_state.is_some());
}

#[tokio::test]
async fn copy_session_data_without_plan() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());

    let source_info = Info {
        id: acp::SessionId::new("source-no-plan"),
        cwd: "/source/workspace".to_string(),
    };

    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();

    adapter
        .append_chat_message(&source_info, &ConversationItem::user("Hello"))
        .await
        .unwrap();

    let target_info = Info {
        id: acp::SessionId::new("fork-source-no-plan-12345678"),
        cwd: "/target/workspace".to_string(),
    };

    let result = adapter
        .copy_session_data(&source_info, &target_info, Default::default())
        .await
        .unwrap();

    assert_eq!(result.chat_messages_copied, 1);
    assert_eq!(result.updates_copied, 0);
    assert!(!result.plan_state_copied);

    let loaded = adapter.load_session(&target_info).await.unwrap();
    assert!(loaded.plan_state.is_none());
}

#[tokio::test]
async fn copy_session_data_transforms_fuigo_updates() {
    use crate::extensions::notification::{
        DiffContent, SessionNotification as FuigoSessionNotification,
        SessionUpdate as FuigoSessionUpdateType,
    };

    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());

    let source_info = Info {
        id: acp::SessionId::new("source-fuigo"),
        cwd: "/source".to_string(),
    };

    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();

    let fuigo_notification = FuigoSessionNotification {
        session_id: acp::SessionId::new("source-fuigo"),
        update: FuigoSessionUpdateType::DiffReview {
            content: vec![DiffContent {
                diff: acp::Diff::new(std::path::PathBuf::from("/test/file.rs"), "new".to_string())
                    .old_text(Some("old".to_string())),
            }],
        },
        meta: None,
    };
    adapter
        .append_update(
            &source_info,
            &SessionUpdate::Fuigo(Box::new(fuigo_notification)),
        )
        .await
        .unwrap();

    let target_info = Info {
        id: acp::SessionId::new("fork-source-fuigo-abcd1234"),
        cwd: "/target".to_string(),
    };

    adapter
        .copy_session_data(&source_info, &target_info, Default::default())
        .await
        .unwrap();

    let loaded = adapter.load_session(&target_info).await.unwrap();
    match &loaded.updates[0] {
        SessionUpdate::Fuigo(notification) => {
            assert_eq!(
                notification.session_id.0.as_ref(),
                "fork-source-fuigo-abcd1234"
            );
        }
        _ => panic!("Expected Ferrox Labs update"),
    }
}

#[tokio::test]
async fn copy_session_data_source_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());

    let source_info = Info {
        id: acp::SessionId::new("nonexistent"),
        cwd: "/nonexistent".to_string(),
    };

    let target_info = Info {
        id: acp::SessionId::new("fork-nonexistent-abcd1234"),
        cwd: "/target".to_string(),
    };

    let result = adapter
        .copy_session_data(&source_info, &target_info, Default::default())
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn copy_session_data_with_model_override() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());

    let source_info = Info {
        id: acp::SessionId::new("source-model-test"),
        cwd: "/source".to_string(),
    };

    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();

    let target_info = Info {
        id: acp::SessionId::new("fork-model-test"),
        cwd: "/target".to_string(),
    };

    let options = CopySessionOptions {
        parent_session_id: Some("source-model-test".to_string()),
        new_model_id: Some("grok-3".to_string()),
        target_prompt_index: None,
        ..Default::default()
    };
    adapter
        .copy_session_data(&source_info, &target_info, options)
        .await
        .unwrap();

    let loaded = adapter.load_session(&target_info).await.unwrap();
    assert_eq!(loaded.summary.current_model_id.0.as_ref(), "grok-3");
    assert_eq!(
        loaded.summary.parent_session_id,
        Some("source-model-test".to_string())
    );
}

#[tokio::test]
async fn copy_session_data_skips_tool_state_directory() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());

    let source_info = Info {
        id: acp::SessionId::new("source-dir-tool-state"),
        cwd: "/source/project".to_string(),
    };

    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();

    adapter
        .append_chat_message(&source_info, &ConversationItem::user("Hello"))
        .await
        .unwrap();

    let source_dir = adapter.session_dir(&source_info);
    std::fs::create_dir_all(source_dir.join("tool_state.json").join("terminal")).unwrap();

    let target_info = Info {
        id: acp::SessionId::new("fork-dir-tool-state"),
        cwd: "/target/worktree".to_string(),
    };

    let result = adapter
        .copy_session_data(&source_info, &target_info, Default::default())
        .await
        .unwrap();

    assert!(!result.tool_state_copied);
    assert!(
        !adapter
            .session_dir(&target_info)
            .join("tool_state.json")
            .is_file()
    );
}

#[tokio::test]
async fn copy_fork_provenance_persisted_in_summary() {
    let tmp = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(tmp.path().to_path_buf());
    let source_info = Info {
        id: acp::SessionId::new("src-prov"),
        cwd: "/src".to_string(),
    };
    let target_info = Info {
        id: acp::SessionId::new("tgt-prov"),
        cwd: "/tgt".to_string(),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();

    let options = CopySessionOptions {
        parent_session_id: Some("src-prov".to_string()),
        session_kind: Some("subagent_fork".to_string()),
        fork_context_source: Some("forked".to_string()),
        fork_parent_prompt_id: Some("prompt-42".to_string()),
        ..Default::default()
    };
    adapter
        .copy_session_data(&source_info, &target_info, options)
        .await
        .unwrap();

    let data = adapter.load_session(&target_info).await.unwrap();
    assert_eq!(data.summary.session_kind.as_deref(), Some("subagent_fork"));
    assert_eq!(data.summary.fork_context_source.as_deref(), Some("forked"));
    assert_eq!(
        data.summary.fork_parent_prompt_id.as_deref(),
        Some("prompt-42")
    );
}

#[tokio::test]
async fn copy_session_data_inherits_source_summary_fields() {
    let tmp = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(tmp.path().to_path_buf());
    let source_info = Info {
        id: acp::SessionId::new("src-inherit"),
        cwd: "/src".to_string(),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();
    adapter
        .update_git_head(
            &source_info,
            Some("abc123".into()),
            Some("feature-branch".into()),
        )
        .await
        .unwrap();
    // Set the profile on disk so the assertion is independent of the process-global configured profile
    let mut src_summary = adapter.read_summary_sync(&source_info).unwrap();
    src_summary.sandbox_profile = Some("workspace".to_string());
    adapter
        .write_summary_sync(&source_info, &src_summary)
        .unwrap();

    let target_info = Info {
        id: acp::SessionId::new("tgt-inherit"),
        cwd: "/tgt".to_string(),
    };
    adapter
        .copy_session_data(&source_info, &target_info, CopySessionOptions::default())
        .await
        .unwrap();

    let loaded = adapter.load_summary(&target_info).await.unwrap();
    assert_eq!(loaded.head_commit.as_deref(), Some("abc123"));
    assert_eq!(loaded.head_branch.as_deref(), Some("feature-branch"));
    assert_eq!(loaded.sandbox_profile.as_deref(), Some("workspace"));
}

fn worktree_target_cwd(home: &std::path::Path) -> String {
    let cwd = home
        .join("worktrees")
        .join("fuigo")
        .join("fix-bug")
        .join("src");
    std::fs::create_dir_all(&cwd).unwrap();
    cwd.to_string_lossy().into_owned()
}

#[tokio::test]
#[serial_test::serial]
async fn fork_with_default_kind_into_worktree_cwd_stamps_worktree_identity() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = TempDir::new().unwrap();
    let _env = fuigo_test_support::EnvGuard::set("FUIGO_HOME", home.path());
    let adapter = JsonlStorageAdapter::with_root(home.path().join("sessions-root"));
    let source_info = Info {
        id: acp::SessionId::new("src-plain-fork"),
        cwd: "/src".to_string(),
    };
    let target_info = Info {
        id: acp::SessionId::new("tgt-in-worktree"),
        cwd: worktree_target_cwd(home.path()),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();

    adapter
        .copy_session_data(&source_info, &target_info, CopySessionOptions::default())
        .await
        .unwrap();

    let summary = adapter.load_summary(&target_info).await.unwrap();
    assert_eq!(summary.session_kind.as_deref(), Some("worktree"));
    assert_eq!(summary.worktree_label.as_deref(), Some("fix-bug"));
}

#[tokio::test]
#[serial_test::serial]
async fn explicit_subagent_fork_kind_wins_over_worktree_target_cwd() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = TempDir::new().unwrap();
    let _env = fuigo_test_support::EnvGuard::set("FUIGO_HOME", home.path());
    let adapter = JsonlStorageAdapter::with_root(home.path().join("sessions-root"));
    let source_info = Info {
        id: acp::SessionId::new("src-subagent-fork"),
        cwd: "/src".to_string(),
    };
    let target_info = Info {
        id: acp::SessionId::new("tgt-subagent-in-worktree"),
        cwd: worktree_target_cwd(home.path()),
    };
    adapter
        .init_session(&source_info, default_model_id())
        .await
        .unwrap();

    let options = CopySessionOptions {
        session_kind: Some("subagent_fork".to_string()),
        ..Default::default()
    };
    adapter
        .copy_session_data(&source_info, &target_info, options)
        .await
        .unwrap();

    let summary = adapter.load_summary(&target_info).await.unwrap();
    assert_eq!(summary.session_kind.as_deref(), Some("subagent_fork"));
    assert!(summary.source_workspace_dir.is_none());
    assert_eq!(summary.worktree_label.as_deref(), Some("fix-bug"));
}

async fn assert_copy_clears_pending_relocation(fork_filter: bool) {
    use crate::session::persistence::PendingCwdSwitchReminder;

    let tmp = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(tmp.path().to_path_buf());
    let source = Info {
        id: acp::SessionId::new(format!("pending-source-{fork_filter}")),
        cwd: "/src".into(),
    };
    let target = Info {
        id: acp::SessionId::new(format!("pending-target-{fork_filter}")),
        cwd: "/target".into(),
    };
    let mut summary = adapter
        .init_session(&source, default_model_id())
        .await
        .unwrap();
    summary.cwd_generation = 3;
    summary.previous_cwd = Some("/older".into());
    summary.pending_cwd_switch_reminder = Some(PendingCwdSwitchReminder {
        cwd_generation: 3,
        previous_cwd: "/src".into(),
        destination_cwd: "/destination".into(),
        content: "switch".into(),
        destination_project_instructions: None,
    });
    adapter.write_summary_sync(&source, &summary).unwrap();
    adapter
        .append_chat_message(
            &source,
            &ConversationItem::working_directory_switch("switch", 3),
        )
        .await
        .unwrap();

    adapter
        .copy_session_data(
            &source,
            &target,
            CopySessionOptions {
                fork_filter,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let copied = adapter.read_summary_sync(&target).unwrap();
    assert_eq!(copied.cwd_generation, 3);
    assert_eq!(copied.previous_cwd.as_deref(), Some("/older"));
    assert!(copied.pending_cwd_switch_reminder.is_none());
    let expected_generation = if fork_filter { 0 } else { 3 };
    assert_eq!(
        copied.cwd_switch_bookkeeping_generation,
        expected_generation
    );
    if !fork_filter {
        let before = copied.num_chat_messages;
        assert!(matches!(
            adapter
                .append_cwd_switch_commit_aware(
                    &target,
                    &ConversationItem::working_directory_switch("switch", 3),
                )
                .await
                .unwrap(),
            fuigo_chat_state::StrictAppendAck::AlreadyPresent(item)
                if item.text_content() == "switch"
        ));
        let retried = adapter.read_summary_sync(&target).unwrap();
        assert_eq!(retried.num_chat_messages, before);
        assert_eq!(
            adapter
                .read_chat_history_sync(adapter.chat_file(&target), CHAT_FORMAT_VERSION)
                .unwrap()
                .iter()
                .filter(|item| item.working_directory_switch_generation() == Some(3))
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn unfiltered_copy_clears_pending_relocation() {
    assert_copy_clears_pending_relocation(false).await;
}

#[tokio::test]
async fn filtered_copy_clears_pending_relocation() {
    assert_copy_clears_pending_relocation(true).await;
}

/// Each sidecar flag gates exactly its own file: one fork per flag disables only that flag and asserts only its file is missing.
/// A transposed flag or path in the `copy_sidecar_file` call sites fails.
/// A defaults fork then proves all five copy with their contents intact.
#[tokio::test]
async fn sidecar_flags_gate_their_files_independently() {
    let tmp = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(tmp.path().to_path_buf());
    let source = Info {
        id: acp::SessionId::new("src-sidecars"),
        cwd: "/src".to_string(),
    };
    adapter
        .init_session(&source, default_model_id())
        .await
        .unwrap();
    std::fs::write(adapter.plan_file(&source), b"plan").unwrap();
    std::fs::write(adapter.signals_file(&source), b"signals").unwrap();
    std::fs::write(adapter.plan_mode_state_file(&source), b"plan-mode").unwrap();
    std::fs::write(
        adapter.session_dir(&source).join("tool_state.json"),
        b"{\"todo\":[]}",
    )
    .unwrap();
    std::fs::write(adapter.announcement_state_file(&source), b"announcements").unwrap();

    type DisableFlag = fn(&mut CopySessionOptions);
    let cases: [(&str, DisableFlag); 5] = [
        ("plan", |o| o.copy_plan_state = false),
        ("signals", |o| o.copy_signals = false),
        ("plan_mode", |o| o.copy_plan_mode_state = false),
        ("tool_state", |o| o.copy_tool_state = false),
        ("announcement", |o| o.copy_announcement_state = false),
    ];
    for (off, (name, disable)) in cases.iter().enumerate() {
        let target = Info {
            id: acp::SessionId::new(format!("tgt-sidecar-off-{name}")),
            cwd: "/tgt".to_string(),
        };
        let mut options = CopySessionOptions::default();
        disable(&mut options);
        let result = adapter
            .copy_session_data(&source, &target, options)
            .await
            .unwrap();
        let copied = [
            result.plan_state_copied,
            result.signals_copied,
            result.plan_mode_state_copied,
            result.tool_state_copied,
            result.announcement_state_copied,
        ];
        let present = [
            adapter.plan_file(&target).exists(),
            adapter.signals_file(&target).exists(),
            adapter.plan_mode_state_file(&target).exists(),
            adapter
                .session_dir(&target)
                .join("tool_state.json")
                .exists(),
            adapter.announcement_state_file(&target).exists(),
        ];
        for (i, (copied, present)) in copied.into_iter().zip(present).enumerate() {
            let expected = i != off;
            assert_eq!(copied, expected, "{name} off: sidecar {i} copied flag");
            assert_eq!(present, expected, "{name} off: sidecar {i} file present");
        }
    }

    let target_on = Info {
        id: acp::SessionId::new("tgt-sidecars-on"),
        cwd: "/tgt".to_string(),
    };
    let result = adapter
        .copy_session_data(&source, &target_on, CopySessionOptions::default())
        .await
        .unwrap();
    assert!(result.plan_state_copied);
    assert!(result.signals_copied);
    assert!(result.plan_mode_state_copied);
    assert!(result.tool_state_copied);
    assert!(result.announcement_state_copied);
    assert_eq!(
        std::fs::read(adapter.plan_file(&target_on)).unwrap(),
        b"plan"
    );
    assert_eq!(
        std::fs::read(adapter.signals_file(&target_on)).unwrap(),
        b"signals"
    );
    assert_eq!(
        std::fs::read(adapter.plan_mode_state_file(&target_on)).unwrap(),
        b"plan-mode"
    );
    assert_eq!(
        std::fs::read(adapter.session_dir(&target_on).join("tool_state.json")).unwrap(),
        b"{\"todo\":[]}"
    );
    assert_eq!(
        std::fs::read(adapter.announcement_state_file(&target_on)).unwrap(),
        b"announcements"
    );
}

#[tokio::test]
async fn fork_restamps_usage_session_id() {
    use crate::session::usage_file::SessionUsageFile;

    let tmp = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(tmp.path().to_path_buf());
    let source = Info {
        id: acp::SessionId::new("src-usage"),
        cwd: "/src".to_string(),
    };
    adapter
        .init_session(&source, default_model_id())
        .await
        .unwrap();

    let mut usage = SessionUsageFile::new(source.id.to_string());
    usage.apply_turn(
        1,
        "t1",
        &crate::session::usage_file::UsageSummary {
            input_tokens: 10,
            output_tokens: 2,
            total_tokens: 12,
            model_calls: 1,
            turn_count: 1,
            ..Default::default()
        },
        None,
    );
    adapter.write_usage(&source, &usage).await.unwrap();

    let target = Info {
        id: acp::SessionId::new("tgt-usage"),
        cwd: "/tgt".to_string(),
    };
    adapter
        .copy_session_data(&source, &target, CopySessionOptions::default())
        .await
        .unwrap();

    let copied = adapter.read_usage(&target).await.unwrap().unwrap();
    assert_eq!(copied.session_id, "tgt-usage");
    assert_eq!(copied.turns.len(), 1);
    assert_eq!(copied.session.input_tokens, 10);
}

#[tokio::test]
async fn truncating_fork_drops_later_usage_turns() {
    use crate::session::usage_file::SessionUsageFile;

    let tmp = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(tmp.path().to_path_buf());
    let source = Info {
        id: acp::SessionId::new("src-usage-trunc"),
        cwd: "/src".to_string(),
    };
    adapter
        .init_session(&source, default_model_id())
        .await
        .unwrap();

    let mut usage = SessionUsageFile::new(source.id.to_string());
    let first = crate::session::usage_file::UsageSummary {
        input_tokens: 10,
        output_tokens: 2,
        total_tokens: 12,
        model_calls: 1,
        turn_count: 1,
        ..Default::default()
    };
    usage.apply_turn(1, "t1", &first, None);
    usage.apply_turn(
        2,
        "t2",
        &crate::session::usage_file::UsageSummary {
            input_tokens: 25,
            output_tokens: 7,
            total_tokens: 32,
            model_calls: 2,
            ..Default::default()
        },
        Some(&first),
    );
    adapter.write_usage(&source, &usage).await.unwrap();
    adapter
        .write_signals(
            &source,
            &crate::session::signals::SessionSignals {
                turn_count: 5,
                user_message_count: 5,
                assistant_message_count: 5,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let target = Info {
        id: acp::SessionId::new("tgt-usage-trunc"),
        cwd: "/tgt".to_string(),
    };
    adapter
        .copy_session_data(
            &source,
            &target,
            CopySessionOptions {
                target_prompt_index: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let copied = adapter.read_usage(&target).await.unwrap().unwrap();
    assert_eq!(copied.session_id, "tgt-usage-trunc");
    assert_eq!(copied.turns.len(), 1);
    assert_eq!(copied.turns[0].turn_number, 1);
    assert_eq!(copied.session.input_tokens, 10);
    let signals = adapter
        .load_session(&target)
        .await
        .unwrap()
        .signals
        .unwrap();
    assert_eq!(signals.turn_count, 1);
    assert_eq!(signals.user_message_count, 1);
}

#[tokio::test]
async fn copy_usage_is_independent_of_copy_signals() {
    use crate::session::usage_file::SessionUsageFile;

    let tmp = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(tmp.path().to_path_buf());
    let source = Info {
        id: acp::SessionId::new("src-usage-flag"),
        cwd: "/src".to_string(),
    };
    adapter
        .init_session(&source, default_model_id())
        .await
        .unwrap();
    std::fs::write(adapter.signals_file(&source), b"signals").unwrap();
    let mut usage = SessionUsageFile::new(source.id.to_string());
    usage.apply_turn(
        1,
        "t1",
        &crate::session::usage_file::UsageSummary {
            input_tokens: 10,
            total_tokens: 10,
            model_calls: 1,
            turn_count: 1,
            ..Default::default()
        },
        None,
    );
    adapter.write_usage(&source, &usage).await.unwrap();

    let no_signals = Info {
        id: acp::SessionId::new("tgt-no-signals"),
        cwd: "/tgt".to_string(),
    };
    adapter
        .copy_session_data(
            &source,
            &no_signals,
            CopySessionOptions {
                copy_signals: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let seeded = adapter
        .load_session(&no_signals)
        .await
        .unwrap()
        .signals
        .unwrap();
    assert_eq!(seeded.turn_count, 1);
    assert!(adapter.read_usage(&no_signals).await.unwrap().is_some());

    let no_usage = Info {
        id: acp::SessionId::new("tgt-no-usage"),
        cwd: "/tgt".to_string(),
    };
    adapter
        .copy_session_data(
            &source,
            &no_usage,
            CopySessionOptions {
                copy_usage: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(adapter.signals_file(&no_usage).exists());
    assert!(adapter.read_usage(&no_usage).await.unwrap().is_none());
}

/// A truncating (`target_prompt_index`) or filtering (`fork_filter`) fork can drop the failure announcement from the child's context.
/// The copied announcement state must end those episodes or a still-down server is never re-announced to the child.
///
/// The fixture and assertions use the real [`AnnouncementState`] so the strip helper's hard-coded key cannot drift from the serde name unnoticed.
/// On a rename the helper would no-op and the typed emptiness assert below would fail.
#[tokio::test]
async fn fork_truncation_clears_announced_failure_episodes() {
    use crate::session::announcement_state::{
        AnnouncedFailure, AnnouncementState, McpServerFingerprint,
    };

    let tmp = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(tmp.path().to_path_buf());
    let source = Info {
        id: acp::SessionId::new("src-episodes"),
        cwd: "/src".to_string(),
    };
    adapter
        .init_session(&source, default_model_id())
        .await
        .unwrap();
    let mut state = serde_json::to_value(AnnouncementState {
        mcp_server_fingerprints: std::collections::HashMap::from([(
            "srv".to_string(),
            McpServerFingerprint {
                tool_count: 1,
                description_hash: 2,
                tool_names_hash: 3,
            },
        )]),
        announced_skill_names: std::collections::HashSet::from(["commit".to_string()]),
        announced_failed_servers: std::collections::HashMap::from([(
            "dead".to_string(),
            AnnouncedFailure::Transport,
        )]),
    })
    .unwrap();
    state
        .as_object_mut()
        .unwrap()
        .insert("some_future_field".to_string(), true.into());
    std::fs::write(
        adapter.announcement_state_file(&source),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();

    type SetOption = fn(&mut CopySessionOptions);
    let cases: [(&str, SetOption); 2] = [
        ("truncating", |o| o.target_prompt_index = Some(0)),
        ("filtering", |o| o.fork_filter = true),
    ];
    for (name, set) in cases {
        let target = Info {
            id: acp::SessionId::new(format!("tgt-episodes-{name}")),
            cwd: "/tgt".to_string(),
        };
        let mut options = CopySessionOptions::default();
        set(&mut options);
        adapter
            .copy_session_data(&source, &target, options)
            .await
            .unwrap();
        let raw = std::fs::read(adapter.announcement_state_file(&target)).unwrap();
        let copied: AnnouncementState = serde_json::from_slice(&raw).unwrap();
        assert!(
            copied.announced_failed_servers.is_empty(),
            "{name}: failure episodes must be cleared"
        );
        assert_eq!(
            copied.mcp_server_fingerprints["srv"].tool_count, 1,
            "{name}: fingerprints survive"
        );
        assert!(
            copied.announced_skill_names.contains("commit"),
            "{name}: skill names survive"
        );
        let raw: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            raw["some_future_field"], true,
            "{name}: unknown fields survive"
        );
    }

    let target_full = Info {
        id: acp::SessionId::new("tgt-episodes-full"),
        cwd: "/tgt".to_string(),
    };
    adapter
        .copy_session_data(&source, &target_full, CopySessionOptions::default())
        .await
        .unwrap();
    let copied: AnnouncementState = serde_json::from_slice(
        &std::fs::read(adapter.announcement_state_file(&target_full)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        copied.announced_failed_servers.get("dead"),
        Some(&AnnouncedFailure::Transport),
        "full fork keeps episodes: its context retains the announcement"
    );
}

/// An overlong line is discarded without consuming an index, so the two copy passes stay aligned.
#[test]
fn capped_line_reader_discards_overlong_lines_without_shifting_indexes() {
    fn collect(input: &[u8], cap: usize) -> Vec<(usize, Vec<u8>)> {
        let mut seen = Vec::new();
        super::for_each_jsonl_line_capped(std::io::Cursor::new(input), cap, |index, line| {
            seen.push((index, line.to_vec()));
            Ok(std::ops::ControlFlow::Continue(()))
        })
        .unwrap();
        seen
    }

    // Exactly cap content bytes: kept.
    assert_eq!(collect(b"abcd\n", 4), vec![(0, b"abcd".to_vec())]);
    // One over cap: discarded; the next line takes the next index, not a shifted one
    assert_eq!(
        collect(b"aa\nxxxxx\nbb\n", 4),
        vec![(0, b"aa".to_vec()), (1, b"bb".to_vec())]
    );
    // Overlong spanning several drain chunks still finds the line end.
    assert_eq!(
        collect(b"xxxxxxxxxxxxxxxxxxxxx\ncc\n", 4),
        vec![(0, b"cc".to_vec())]
    );
    // Overlong unterminated at EOF: drain hits EOF and stops cleanly.
    assert_eq!(collect(b"aa\nxxxxxxxx", 4), vec![(0, b"aa".to_vec())]);
    // Unterminated within-cap tail is kept, matching the uncapped reader.
    assert_eq!(
        collect(b"aa\nbb", 4),
        vec![(0, b"aa".to_vec()), (1, b"bb".to_vec())]
    );
}

/// P88: a compaction marker at `prompt_index_at_compaction`, with its checkpoint file holding `projection`.
async fn compaction_at(
    adapter: &JsonlStorageAdapter,
    info: &Info,
    id: &str,
    prompt_index_at_compaction: usize,
    original_user_info: Option<&str>,
    projection: Vec<ConversationItem>,
) -> SessionUpdate {
    use crate::extensions::notification::{
        CompactionCheckpointFile, CompactionCheckpointInfo, SessionNotification as FuigoSessionNotification,
        SessionUpdate as FuigoSessionUpdateType,
    };
    adapter
        .write_compaction_checkpoint(
            info,
            &CompactionCheckpointFile {
                inherited_prefix_len: Some(0),
                checkpoint_id: id.to_string(),
                prompt_index_at_compaction,
                compacted_history: projection,
                schema_version: 1,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                original_user_info: original_user_info.map(str::to_string),
                reread_file_paths: vec![],
            },
        )
        .await
        .unwrap();
    SessionUpdate::Fuigo(Box::new(FuigoSessionNotification {
        session_id: info.id.clone(),
        update: FuigoSessionUpdateType::CompactionCheckpoint(Box::new(CompactionCheckpointInfo {
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

async fn p88_source(
    adapter: &JsonlStorageAdapter,
    sid: &str,
    updates: Vec<SessionUpdate>,
    chat: Vec<ConversationItem>,
) -> Info {
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    for update in updates {
        adapter.append_update(&info, &update).await.unwrap();
    }
    for item in chat {
        adapter.append_chat_message(&info, &item).await.unwrap();
    }
    info
}

async fn p88_fork_chat(adapter: &JsonlStorageAdapter, source: &Info, target: usize) -> serde_json::Value {
    let target_info = Info {
        id: acp::SessionId::new(format!("{}-fork-{target}", source.id.0)),
        cwd: "/src".to_string(),
    };
    adapter
        .copy_session_data(
            source,
            &target_info,
            CopySessionOptions {
                target_prompt_index: Some(target),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    serde_json::to_value(adapter.load_session(&target_info).await.unwrap().chat_history).unwrap()
}

/// P88: a compaction that a rewind abandoned does not survive the copy's cut, so a fork of the live branch truncates
/// the source chat (which already holds that branch, tool calls included) instead of a text-only rebuild.
#[tokio::test]
async fn fork_after_a_rewound_away_compaction_keeps_the_live_branch_tools() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p88-rewound-compaction";
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let abandoned = compaction_at(
        &adapter,
        &info,
        "abandoned",
        3,
        None,
        vec![ConversationItem::system("sys"), ConversationItem::user("summary of the abandoned branch")],
    )
    .await;
    let chat = vec![
        ConversationItem::system("sys"),
        chat_user("P0", 0),
        ConversationItem::assistant("A0"),
        chat_user("P1-new", 1),
        ConversationItem::assistant_tool_calls(vec![crate::sampling::ToolCall {
            id: "call-new".into(),
            name: "read_file".into(),
            arguments: "{}".into(),
        }]),
        ConversationItem::tool_result("call-new", "contents"),
        ConversationItem::assistant("A1-new"),
    ];
    let source = p88_source(
        &adapter,
        sid,
        vec![
            fork_user_chunk(sid, "P0", 0),
            fork_agent_chunk(sid, "A0"),
            fork_user_chunk(sid, "P1-old", 1),
            fork_agent_chunk(sid, "A1-old"),
            fork_user_chunk(sid, "P2-old", 2),
            fork_agent_chunk(sid, "A2-old"),
            abandoned,
            fork_rewind_marker(sid, 1),
            fork_user_chunk(sid, "P1-new", 1),
            fork_agent_chunk(sid, "A1-new"),
        ],
        chat.clone(),
    )
    .await;

    let forked = p88_fork_chat(&adapter, &source, 1).await;
    assert_eq!(forked, serde_json::to_value(chat).unwrap());
}

/// P88: the source's chat history starts from its LATER compaction (after P2); a fork cut at P1 must start from the
/// earlier one that survives the cut, not from a summary of turns after the cut. (Until P88 the child's first load
/// did this rebuild; it now happens at copy time, and only for point-in-time copies.)
#[tokio::test]
async fn fork_cut_between_compactions_starts_from_the_compaction_the_cut_keeps() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p88-between-compactions";
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let early = vec![ConversationItem::system("sys"), ConversationItem::user("summary of P0")];
    let late = vec![ConversationItem::system("sys"), ConversationItem::user("summary of P0 to P2")];
    let early_marker = compaction_at(&adapter, &info, "early", 1, None, early.clone()).await;
    let late_marker = compaction_at(&adapter, &info, "late", 3, None, late.clone()).await;
    let mut chat = late;
    chat.extend([chat_user("P3", 3), ConversationItem::assistant("A3")]);
    let source = p88_source(
        &adapter,
        sid,
        vec![
            fork_user_chunk(sid, "P0", 0),
            fork_agent_chunk(sid, "A0"),
            early_marker,
            fork_user_chunk(sid, "P1", 1),
            fork_agent_chunk(sid, "A1"),
            fork_user_chunk(sid, "P2", 2),
            fork_agent_chunk(sid, "A2"),
            late_marker,
            fork_user_chunk(sid, "P3", 3),
            fork_agent_chunk(sid, "A3"),
        ],
        chat,
    )
    .await;

    let forked = p88_fork_chat(&adapter, &source, 1).await;
    let mut p1 = ConversationItem::user("P1");
    p1.set_prompt_index(1);
    let mut expected = early;
    expected.extend([p1, ConversationItem::assistant("A1")]);
    assert_eq!(forked, serde_json::to_value(expected).unwrap());
}

/// P111 (DI-04): the fixture above, but the earlier checkpoint (the one the cut keeps) is missing. The history at the cut
/// cannot be rebuilt, and truncating the source's chat would hand the child the LATER compaction's summary of turns
/// after its fork point. The fork is refused and leaves no target session behind.
#[tokio::test]
async fn fork_cut_between_compactions_is_refused_when_the_kept_checkpoint_is_missing() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p111-between-compactions-missing";
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let early = vec![ConversationItem::system("sys"), ConversationItem::user("summary of P0")];
    let late = vec![ConversationItem::system("sys"), ConversationItem::user("summary of P0 to P2")];
    let early_marker = compaction_at(&adapter, &info, "early", 1, None, early).await;
    let late_marker = compaction_at(&adapter, &info, "late", 3, None, late.clone()).await;
    let mut chat = late;
    chat.extend([chat_user("P3", 3), ConversationItem::assistant("A3")]);
    let source = p88_source(
        &adapter,
        sid,
        vec![
            fork_user_chunk(sid, "P0", 0),
            fork_agent_chunk(sid, "A0"),
            early_marker,
            fork_user_chunk(sid, "P1", 1),
            fork_agent_chunk(sid, "A1"),
            fork_user_chunk(sid, "P2", 2),
            fork_agent_chunk(sid, "A2"),
            late_marker,
            fork_user_chunk(sid, "P3", 3),
            fork_agent_chunk(sid, "A3"),
        ],
        chat,
    )
    .await;
    std::fs::remove_file(adapter.session_dir(&source).join("compaction_checkpoints/early.json")).unwrap();

    let target_info = Info {
        id: acp::SessionId::new(format!("{sid}-fork-1")),
        cwd: "/src".to_string(),
    };
    let result = adapter
        .copy_session_data(
            &source,
            &target_info,
            CopySessionOptions {
                target_prompt_index: Some(1),
                ..Default::default()
            },
        )
        .await;
    let error = match result {
        Ok(_) => {
            let chat = adapter.load_session(&target_info).await.unwrap().chat_history;
            panic!(
                "the fork must be refused; it was made with history {:?}",
                chat.iter().map(ConversationItem::text_content).collect::<Vec<_>>()
            );
        }
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("Cannot fork at prompt #1"),
        "the refusal says why: {error}"
    );
    assert!(
        !adapter.session_dir(&target_info).exists(),
        "a refused fork leaves no target session"
    );
}

/// P111 (Astra r1, the same rule as DI-04): a fork cut BEFORE the compaction the source's history starts from. The cut
/// has no compaction, so truncating the source's chat kept that compaction's summary of P0 to P2 in a child forked
/// at P0 (R095 had accepted this as the 1.0.17 behaviour). The fork is refused and creates nothing.
#[tokio::test]
async fn fork_before_the_compaction_the_history_starts_from_is_refused() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p111-before-compaction";
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let projection = vec![ConversationItem::system("sys"), ConversationItem::user("summary of P0 to P2")];
    let marker = compaction_at(&adapter, &info, "late", 3, None, projection.clone()).await;
    let mut chat = projection;
    chat.extend([chat_user("P3", 3), ConversationItem::assistant("A3")]);
    let source = p88_source(
        &adapter,
        sid,
        vec![
            fork_user_chunk(sid, "P0", 0),
            fork_agent_chunk(sid, "A0"),
            fork_user_chunk(sid, "P1", 1),
            fork_agent_chunk(sid, "A1"),
            fork_user_chunk(sid, "P2", 2),
            fork_agent_chunk(sid, "A2"),
            marker,
            fork_user_chunk(sid, "P3", 3),
            fork_agent_chunk(sid, "A3"),
        ],
        chat,
    )
    .await;
    let target_info = Info {
        id: acp::SessionId::new(format!("{sid}-fork-0")),
        cwd: "/src".to_string(),
    };
    let result = adapter
        .copy_session_data(
            &source,
            &target_info,
            CopySessionOptions {
                target_prompt_index: Some(0),
                ..Default::default()
            },
        )
        .await;
    match result {
        Ok(_) => {
            let chat = adapter.load_session(&target_info).await.unwrap().chat_history;
            panic!(
                "the fork must be refused; it was made with history {:?}",
                chat.iter().map(ConversationItem::text_content).collect::<Vec<_>>()
            );
        }
        Err(error) => assert!(error.to_string().contains("Cannot fork at prompt #0"), "{error}"),
    }
    assert!(!adapter.session_dir(&target_info).exists(), "a refused fork creates nothing");
}

/// P111 (Astra r2): compactions at 2 and 4, then a rewind to 3 abandons the second. The source's history starts from
/// the FIRST compaction (a summary of P0 and P1); a fork at P0 must not inherit it. A replay of the whole transcript
/// loses the first compaction at the rewind, so the live timeline's markers decide.
#[tokio::test]
async fn fork_before_the_surviving_compaction_after_a_rewind_is_refused() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p111-rewind-between-compactions";
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let first = vec![ConversationItem::system("sys"), ConversationItem::user("summary of P0 and P1")];
    let second = vec![ConversationItem::system("sys"), ConversationItem::user("summary of P0 to P3")];
    let first_marker = compaction_at(&adapter, &info, "first", 2, None, first.clone()).await;
    let second_marker = compaction_at(&adapter, &info, "second", 4, None, second).await;
    let mut chat = first;
    chat.extend([chat_user("P2", 2), ConversationItem::assistant("A2")]);
    let source = p88_source(
        &adapter,
        sid,
        vec![
            fork_user_chunk(sid, "P0", 0),
            fork_agent_chunk(sid, "A0"),
            fork_user_chunk(sid, "P1", 1),
            fork_agent_chunk(sid, "A1"),
            first_marker,
            fork_user_chunk(sid, "P2", 2),
            fork_agent_chunk(sid, "A2"),
            fork_user_chunk(sid, "P3", 3),
            fork_agent_chunk(sid, "A3"),
            second_marker,
            fork_rewind_marker(sid, 3),
        ],
        chat,
    )
    .await;
    let target_info = Info {
        id: acp::SessionId::new(format!("{sid}-fork-0")),
        cwd: "/src".to_string(),
    };
    let result = adapter
        .copy_session_data(
            &source,
            &target_info,
            CopySessionOptions {
                target_prompt_index: Some(0),
                ..Default::default()
            },
        )
        .await;
    match result {
        Ok(_) => {
            let chat = adapter.load_session(&target_info).await.unwrap().chat_history;
            panic!(
                "the fork must be refused; it was made with history {:?}",
                chat.iter().map(ConversationItem::text_content).collect::<Vec<_>>()
            );
        }
        Err(error) => assert!(error.to_string().contains("Cannot fork at prompt #0"), "{error}"),
    }
    assert!(!adapter.session_dir(&target_info).exists(), "a refused fork creates nothing");
}

/// P111 (Astra r2): P88's rewound-away-compaction fork, with the abandoned compaction's checkpoint file gone. That
/// checkpoint is on a dead branch and decides nothing: the fork still truncates the source's live history.
#[tokio::test]
async fn an_unreadable_abandoned_checkpoint_does_not_block_a_fork() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p111-abandoned-unreadable";
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let abandoned = compaction_at(
        &adapter,
        &info,
        "abandoned",
        3,
        None,
        vec![ConversationItem::system("sys"), ConversationItem::user("summary of the abandoned branch")],
    )
    .await;
    let chat = vec![
        ConversationItem::system("sys"),
        chat_user("P0", 0),
        ConversationItem::assistant("A0"),
        chat_user("P1-new", 1),
        ConversationItem::assistant("A1-new"),
    ];
    let source = p88_source(
        &adapter,
        sid,
        vec![
            fork_user_chunk(sid, "P0", 0),
            fork_agent_chunk(sid, "A0"),
            fork_user_chunk(sid, "P1-old", 1),
            fork_agent_chunk(sid, "A1-old"),
            fork_user_chunk(sid, "P2-old", 2),
            fork_agent_chunk(sid, "A2-old"),
            abandoned,
            fork_rewind_marker(sid, 1),
            fork_user_chunk(sid, "P1-new", 1),
            fork_agent_chunk(sid, "A1-new"),
        ],
        chat.clone(),
    )
    .await;
    std::fs::remove_file(adapter.session_dir(&source).join("compaction_checkpoints/abandoned.json")).unwrap();
    let forked = p88_fork_chat(&adapter, &source, 1).await;
    assert_eq!(forked, serde_json::to_value(chat).unwrap());
}

/// P111 (Astra r2): the staged cut is session content; its directory is owner-only.
#[cfg(unix)]
#[test]
fn the_fork_staging_directory_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let parent = TempDir::new().unwrap();
    let staging = super::private_staging_dir(parent.path()).unwrap();
    let mode = std::fs::metadata(staging.dir.path()).unwrap().permissions().mode() & 0o777;
    assert!(staging.dir.path().join(".lock").is_file(), "the lock file has its name once it is locked");
    assert!(!staging.dir.path().join(".lock.init").exists());
    let lock = std::fs::File::open(staging.dir.path().join(".lock")).unwrap();
    assert!(fs2::FileExt::try_lock_exclusive(&lock).is_err(), "a live staging directory's lock is held");
    assert_eq!(mode, 0o700, "staging directory mode {mode:o}");
}

/// P111 (Astra r4 #6): a fork with an explicit `newSessionId` that names an existing session replaced that session's
/// transcript, chat history and summary. The copy must be refused with nothing written, for a whole copy and for a
/// point-in-time one.
#[tokio::test]
async fn copy_into_an_existing_session_is_refused_and_writes_nothing() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let source = Info {
        id: acp::SessionId::new("p111-copy-source"),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&source, default_model_id()).await.unwrap();
    let source = p88_source(
        &adapter,
        "p111-copy-source",
        vec![fork_user_chunk("p111-copy-source", "P0", 0), fork_agent_chunk("p111-copy-source", "A0")],
        vec![chat_user("P0", 0), ConversationItem::assistant("A0")],
    )
    .await;
    let existing = Info {
        id: acp::SessionId::new("p111-copy-existing"),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&existing, default_model_id()).await.unwrap();
    let existing = p88_source(
        &adapter,
        "p111-copy-existing",
        vec![fork_user_chunk("p111-copy-existing", "MINE", 0), fork_agent_chunk("p111-copy-existing", "KEEP")],
        vec![chat_user("MINE", 0), ConversationItem::assistant("KEEP")],
    )
    .await;
    let dir = adapter.session_dir(&existing);
    let snapshot = || {
        let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.file_type().unwrap().is_file())
            .map(|entry| (entry.file_name().to_string_lossy().into_owned(), std::fs::read(entry.path()).unwrap()))
            .collect();
        files.sort();
        files
    };
    let before = snapshot();

    for target_prompt_index in [None, Some(0)] {
        let result = adapter
            .copy_session_data(
                &source,
                &existing,
                CopySessionOptions {
                    target_prompt_index,
                    ..Default::default()
                },
            )
            .await;
        let error = result.expect_err("a copy onto an existing session must be refused");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists, "{error}");
        assert!(error.to_string().contains("already exists"), "{error}");
        assert_eq!(snapshot(), before, "the existing session is untouched ({target_prompt_index:?})");
    }
}

/// P111 (Astra r3): the only compaction's checkpoint is missing (so the cut cannot be replayed) and the saved history
/// after its summary has no prompt markers (written before them). Truncating it would count turns from the summary as
/// prompt 0 and keep P6 and P7 in a child forked at P5. The cut cannot be proven, so the fork is refused.
#[tokio::test]
async fn fork_of_an_unmarked_compacted_history_without_its_checkpoint_is_refused() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p111-unmarked-history";
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let projection = vec![ConversationItem::system("sys"), ConversationItem::user("summary of P0 to P4")];
    let marker = compaction_at(&adapter, &info, "only", 5, None, projection.clone()).await;
    let mut chat = projection;
    for i in 5..8 {
        chat.extend([ConversationItem::user(format!("P{i}")), ConversationItem::assistant(format!("A{i}"))]);
    }
    let mut updates = Vec::new();
    for i in 0..5 {
        updates.extend([fork_user_chunk(sid, &format!("P{i}"), i), fork_agent_chunk(sid, &format!("A{i}"))]);
    }
    updates.push(marker);
    for i in 5..8 {
        updates.extend([fork_user_chunk(sid, &format!("P{i}"), i), fork_agent_chunk(sid, &format!("A{i}"))]);
    }
    let source = p88_source(&adapter, sid, updates, chat).await;
    std::fs::remove_file(adapter.session_dir(&source).join("compaction_checkpoints/only.json")).unwrap();
    let target_info = Info {
        id: acp::SessionId::new(format!("{sid}-fork-5")),
        cwd: "/src".to_string(),
    };
    let result = adapter
        .copy_session_data(
            &source,
            &target_info,
            CopySessionOptions {
                target_prompt_index: Some(5),
                ..Default::default()
            },
        )
        .await;
    match result {
        Ok(_) => {
            let chat = adapter.load_session(&target_info).await.unwrap().chat_history;
            panic!(
                "the fork must be refused; it was made with history {:?}",
                chat.iter().map(ConversationItem::text_content).collect::<Vec<_>>()
            );
        }
        Err(error) => assert!(error.to_string().contains("Cannot fork at prompt #5"), "{error}"),
    }
    assert!(!adapter.session_dir(&target_info).exists(), "a refused fork creates nothing");
}

/// P132 (P114 follow-up): a refused fork must not leave an empty `<encoded-cwd>` directory behind when the fork itself
/// created it; a directory that was already there (empty or not) is never removed.
#[tokio::test]
async fn a_refused_fork_removes_the_cwd_directory_only_when_it_created_it() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p132-refused-fork";
    let (source, _) = mixed_marker_source(&adapter, sid, &[8]).await;
    for (n, (cwd, precreate)) in [("/p132-new-cwd", false), ("/p132-existing-cwd", true)].into_iter().enumerate() {
        let target_info = Info { id: acp::SessionId::new(format!("{sid}-fork-{n}")), cwd: cwd.to_string() };
        let cwd_dir = crate::util::fuigo_home::sessions_cwd_dir_in(temp_dir.path(), cwd);
        assert_eq!(adapter.session_dir(&target_info).parent().unwrap(), cwd_dir, "the target's cwd directory");
        if precreate {
            std::fs::create_dir_all(&cwd_dir).unwrap();
        }
        let result = adapter
            .copy_session_data(
                &source,
                &target_info,
                CopySessionOptions { target_prompt_index: Some(5), ..Default::default() },
            )
            .await;
        let error = result.expect_err("the unmarked compacted history must refuse the fork");
        assert!(error.to_string().contains("Cannot fork at prompt #5"), "{error}");
        assert_eq!(cwd_dir.exists(), precreate, "{n}: left behind: {:?}", std::fs::read_dir(&cwd_dir).ok().map(|d| d.count()));
    }
}

/// P132 (Astra r1): a cwd directory is claimed only by the call that makes it (an exclusive `create_dir`), never one
/// another process made first.
#[test]
fn claim_cwd_dir_claims_only_what_it_creates() {
    let temp_dir = TempDir::new().unwrap();
    let fresh = temp_dir.path().join("sessions/a");
    assert!(super::claim_cwd_dir(&fresh, true).unwrap(), "made by this call");
    assert!(!super::claim_cwd_dir(&fresh, true).unwrap(), "already there: not ours");
    // A caller-owned explicit directory's ancestors keep their permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let shared = temp_dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(super::claim_cwd_dir(&shared.join("cache"), false).unwrap());
        assert_eq!(std::fs::metadata(&shared).unwrap().permissions().mode() & 0o777, 0o755, "ancestor untouched");
    }
}

/// A compacted source whose only checkpoint is missing, whose saved history after the summary holds P5..P7 and P8,
/// with the prompts in `marked` carrying prompt markers and the others not (written by a version before them).
async fn mixed_marker_source(
    adapter: &JsonlStorageAdapter,
    sid: &str,
    marked: &[usize],
) -> (Info, Vec<ConversationItem>) {
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let projection = vec![ConversationItem::system("sys"), ConversationItem::user("summary of P0 to P4")];
    let marker = compaction_at(adapter, &info, "only", 5, None, projection.clone()).await;
    let mut chat = projection.clone();
    for i in 5..9 {
        let user = if marked.contains(&i) {
            chat_user(&format!("P{i}"), i)
        } else {
            ConversationItem::user(format!("P{i}"))
        };
        chat.extend([user, ConversationItem::assistant(format!("A{i}"))]);
    }
    let mut updates = Vec::new();
    for i in 0..5 {
        updates.extend([fork_user_chunk(sid, &format!("P{i}"), i), fork_agent_chunk(sid, &format!("A{i}"))]);
    }
    updates.push(marker);
    for i in 5..9 {
        updates.extend([fork_user_chunk(sid, &format!("P{i}"), i), fork_agent_chunk(sid, &format!("A{i}"))]);
    }
    let source = p88_source(adapter, sid, updates, chat).await;
    std::fs::remove_file(adapter.session_dir(&source).join("compaction_checkpoints/only.json")).unwrap();
    (source, projection)
}

/// Fork `source` at `target`; the copy must be refused and create nothing.
async fn assert_fork_refused(adapter: &JsonlStorageAdapter, source: &Info, target: usize) {
    let target_info = Info {
        id: acp::SessionId::new(format!("{}-fork-{target}", source.id.0)),
        cwd: "/src".to_string(),
    };
    let result = adapter
        .copy_session_data(
            source,
            &target_info,
            CopySessionOptions {
                target_prompt_index: Some(target),
                ..Default::default()
            },
        )
        .await;
    match result {
        Ok(_) => {
            let chat = adapter.load_session(&target_info).await.unwrap().chat_history;
            panic!(
                "the fork at P{target} must be refused; it was made with history {:?}",
                chat.iter().map(ConversationItem::text_content).collect::<Vec<_>>()
            );
        }
        Err(error) => assert!(error.to_string().contains(&format!("Cannot fork at prompt #{target}")), "{error}"),
    }
    assert!(!adapter.session_dir(&target_info).exists(), "a refused fork creates nothing");
}

/// P111 (Astra r4 #1): unmarked P5..P7 (written before prompt markers), then a marked P8 written after an upgrade, and
/// the checkpoint is missing. A fork at P5 cuts the transcript after P5, but the truncation of the saved history cuts
/// at the first marker past P5, which is P8, and would hand the child P6 and P7. The cut is not provable: refused.
#[tokio::test]
async fn fork_of_a_mixed_unmarked_then_marked_history_is_refused_where_the_cut_is_unprovable() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let (source, _) = mixed_marker_source(&adapter, "p111-mixed-markers", &[8]).await;
    assert_fork_refused(&adapter, &source, 5).await;
    assert_fork_refused(&adapter, &source, 6).await;
}

/// P111 (Astra r4 #1), the mixed history where the cut IS provable: forking at P7 cuts right before the marked P8, and
/// every turn before P8 is at or before P7, so the child gets the summary and P5..P7 exactly.
#[tokio::test]
async fn fork_of_a_mixed_history_right_before_the_first_marker_truncates_exactly() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let (source, projection) = mixed_marker_source(&adapter, "p111-mixed-exact", &[8]).await;
    let forked = p88_fork_chat(&adapter, &source, 7).await;
    let mut expected = projection;
    for i in 5..8 {
        expected.extend([ConversationItem::user(format!("P{i}")), ConversationItem::assistant(format!("A{i}"))]);
    }
    assert_eq!(forked, serde_json::to_value(expected).unwrap());
}

/// P111 (Astra r4 #1): the reverse mix (a marked P5, then unmarked P6..P8 written by an older version). Marker-only
/// truncation finds no marker past P5 and would keep P6..P8; the target's turn is marked but unmarked turns follow it.
#[tokio::test]
async fn fork_of_a_marked_then_unmarked_history_is_refused() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let (source, _) = mixed_marker_source(&adapter, "p111-marked-then-unmarked", &[5]).await;
    assert_fork_refused(&adapter, &source, 5).await;
}

/// P111 (DI-04), the case that still forks: the only compaction's checkpoint is missing and the cut is after it. The
/// source's chat history starts from that same compaction, so truncating it is exact (P88's L-1 degrade).
#[tokio::test]
async fn fork_after_the_only_compaction_truncates_when_its_checkpoint_is_missing() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p111-only-compaction-missing";
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let projection = vec![ConversationItem::system("sys"), ConversationItem::user("summary of P0")];
    let marker = compaction_at(&adapter, &info, "only", 1, None, projection.clone()).await;
    let mut chat = projection.clone();
    chat.extend([
        chat_user("P1", 1),
        ConversationItem::assistant("A1"),
        chat_user("P2", 2),
        ConversationItem::assistant("A2"),
    ]);
    let source = p88_source(
        &adapter,
        sid,
        vec![
            fork_user_chunk(sid, "P0", 0),
            fork_agent_chunk(sid, "A0"),
            marker,
            fork_user_chunk(sid, "P1", 1),
            fork_agent_chunk(sid, "A1"),
            fork_user_chunk(sid, "P2", 2),
            fork_agent_chunk(sid, "A2"),
        ],
        chat,
    )
    .await;
    std::fs::remove_file(adapter.session_dir(&source).join("compaction_checkpoints/only.json")).unwrap();

    let forked = p88_fork_chat(&adapter, &source, 1).await;
    let mut expected = projection;
    expected.extend([chat_user("P1", 1), ConversationItem::assistant("A1")]);
    assert_eq!(forked, serde_json::to_value(expected).unwrap());
}

/// P88: a legacy checkpoint (no resolved prefix, written before 1.0.10) never triggered the load-time rebuild, so a
/// point-in-time fork after it truncates the source chat and keeps the tool calls, as in 1.0.17.
#[tokio::test]
async fn fork_after_a_legacy_checkpoint_keeps_the_tools() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p88-legacy-checkpoint";
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let marker = compaction_at(
        &adapter,
        &info,
        "legacy",
        1,
        None,
        vec![ConversationItem::system("sys"), ConversationItem::user("summary of P0")],
    )
    .await;
    let path = adapter.session_dir(&info).join("compaction_checkpoints/legacy.json");
    let mut file: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let object = file.as_object_mut().unwrap();
    object.remove("resolved_prefix_len");
    object.remove("inherited_prefix_len");
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    let chat = vec![
        ConversationItem::system("sys"),
        ConversationItem::user("summary of P0"),
        chat_user("P1", 1),
        ConversationItem::assistant_tool_calls(vec![crate::sampling::ToolCall {
            id: "call-1".into(),
            name: "read_file".into(),
            arguments: "{}".into(),
        }]),
        ConversationItem::tool_result("call-1", "contents"),
        ConversationItem::assistant("A1"),
    ];
    let source = p88_source(
        &adapter,
        sid,
        vec![
            fork_user_chunk(sid, "P0", 0),
            fork_agent_chunk(sid, "A0"),
            marker,
            fork_user_chunk(sid, "P1", 1),
            fork_agent_chunk(sid, "A1"),
            fork_user_chunk(sid, "P2", 2),
        ],
        chat.clone(),
    )
    .await;
    let forked = p88_fork_chat(&adapter, &source, 1).await;
    assert_eq!(forked, serde_json::to_value(chat).unwrap());
}

/// P111 (Astra r6 #5): a copy reads the source's chat history before it stages the transcript. The source history is
/// fingerprinted first and checked after: appended to since is coherent, replaced (a rewind or compaction rewrite that
/// finished in between) is not, and the copy is then refused before the target exists.
#[test]
fn the_copy_coherence_check_accepts_appends_and_refuses_replacements() {
    let dir = TempDir::new().unwrap();
    let chat = dir.path().join("chat_history.jsonl");
    assert!(super::chat_file_still_starts_with(&chat, super::chat_file_fingerprint(&chat).unwrap().as_ref()).unwrap());
    std::fs::write(&chat, b"{\"a\":1}\n").unwrap();
    let seen = super::chat_file_fingerprint(&chat).unwrap();
    assert!(super::chat_file_still_starts_with(&chat, seen.as_ref()).unwrap());
    std::fs::write(&chat, b"{\"a\":1}\n{\"b\":2}\n").unwrap();
    assert!(super::chat_file_still_starts_with(&chat, seen.as_ref()).unwrap(), "appended: coherent");
    std::fs::write(&chat, b"{\"c\":3}\n{\"b\":2}\n").unwrap();
    assert!(!super::chat_file_still_starts_with(&chat, seen.as_ref()).unwrap(), "replaced: refused");
    std::fs::remove_file(&chat).unwrap();
    assert!(!super::chat_file_still_starts_with(&chat, seen.as_ref()).unwrap(), "removed: refused");
}

/// P111 (Astra r7 #2): the source commits a compaction (checkpoint, then marker) after the copy read its chat history
/// and before it staged the transcript; the separate rewrite of the source's chat history has not run yet. The chat
/// history the copy read is the pre-compaction one, while the transcript it stages ends with the new marker, and the
/// child would resume the pre-compaction history under a committed compaction, with no witness to recover from. The
/// copy is refused before the target exists.
#[tokio::test]
async fn a_compaction_committed_mid_copy_refuses_the_copy() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p111-compaction-mid-copy";
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let mut updates = Vec::new();
    let mut chat = vec![ConversationItem::system("sys")];
    for i in 0..3 {
        updates.extend([fork_user_chunk(sid, &format!("P{i}"), i), fork_agent_chunk(sid, &format!("A{i}"))]);
        chat.extend([chat_user(&format!("P{i}"), i), ConversationItem::assistant(format!("A{i}"))]);
    }
    let source = p88_source(&adapter, sid, updates, chat).await;
    let marker = compaction_at(
        &adapter,
        &source,
        "mid-copy",
        3,
        None,
        vec![ConversationItem::system("sys"), ConversationItem::user("summary of P0 to P2")],
    )
    .await;
    let marker_line = serde_json::to_string(&crate::session::storage::SessionUpdateEnvelope::from_update(&marker).unwrap())
        .unwrap()
        + "\n";
    let source_updates = adapter.updates_file(&source);
    super::AFTER_SOURCE_CHAT_READ.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().append(true).open(&source_updates).unwrap();
            file.write_all(marker_line.as_bytes()).unwrap();
        }));
    });
    let target_info = Info {
        id: acp::SessionId::new(format!("{sid}-fork")),
        cwd: "/src".to_string(),
    };
    let result = adapter.copy_session_data_sync(&source, &target_info, CopySessionOptions::default());
    super::AFTER_SOURCE_CHAT_READ.with(|hook| assert!(hook.borrow().is_none(), "the seam ran"));
    match result {
        Ok(_) => {
            let chat = adapter.load_session(&target_info).await.unwrap().chat_history;
            panic!(
                "the copy must be refused; it was made with history {:?}",
                chat.iter().map(ConversationItem::text_content).collect::<Vec<_>>()
            );
        }
        Err(error) => assert!(error.to_string().contains("try again"), "{error}"),
    }
    assert!(!adapter.session_dir(&target_info).exists(), "a refused copy creates nothing");
}

/// P111 (Astra r8 #1): the source's compaction committed (checkpoint, witness, marker) before the copy started, and its
/// separate rewrite of the chat history lands after the copy read that history and before the copy checks the witness.
/// The compaction kept the whole history it started from, so the rewrite STARTS with the bytes the copy read and the
/// coherence check accepts it. The witness must then be judged against the history the copy read (not the file as it
/// is by then, which looks landed): the child resumes the compacted history, never the pre-compaction one.
#[tokio::test]
async fn a_prefix_preserving_compaction_rewrite_landing_mid_copy_never_gives_the_old_history() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p111-prefix-rewrite-mid-copy";
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let source = p88_source(
        &adapter,
        sid,
        vec![fork_user_chunk(sid, "P0", 0), fork_agent_chunk(sid, "A0")],
        vec![],
    )
    .await;
    let old = vec![ConversationItem::system("sys"), chat_user("P0", 0), ConversationItem::assistant("A0")];
    let chat_path = adapter.chat_file(&source);
    std::fs::write(&chat_path, crate::session::storage::to_jsonl_bytes(&old).unwrap()).unwrap();
    let mut projection = old.clone();
    projection.push(ConversationItem::user("summary of P0"));
    let marker = compaction_at(&adapter, &source, "keeps-all", 1, None, projection.clone()).await;
    let checkpoint: crate::extensions::notification::CompactionCheckpointFile = serde_json::from_slice(
        &std::fs::read(adapter.session_dir(&source).join("compaction_checkpoints/keeps-all.json")).unwrap(),
    )
    .unwrap();
    super::super::compaction_witness::write_compaction_witness_sync(&adapter.session_dir(&source), &checkpoint).unwrap();
    adapter.append_update(&source, &marker).await.unwrap();
    let rewrite = crate::session::storage::to_jsonl_bytes(&projection).unwrap();
    assert!(rewrite.starts_with(&std::fs::read(&chat_path).unwrap()), "the rewrite keeps the history it started from");
    let rewrite_path = chat_path.clone();
    super::AFTER_SOURCE_CHAT_READ.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || std::fs::write(&rewrite_path, &rewrite).unwrap()));
    });
    let target_info = Info {
        id: acp::SessionId::new(format!("{sid}-fork")),
        cwd: "/src".to_string(),
    };
    let result = adapter.copy_session_data_sync(&source, &target_info, CopySessionOptions::default());
    super::AFTER_SOURCE_CHAT_READ.with(|hook| assert!(hook.borrow().is_none(), "the seam ran"));
    match result {
        Ok(_) => {
            let chat = adapter.load_session(&target_info).await.unwrap().chat_history;
            assert_eq!(
                chat.iter().map(ConversationItem::text_content).collect::<Vec<_>>(),
                projection.iter().map(ConversationItem::text_content).collect::<Vec<_>>(),
                "the child must resume the compacted history"
            );
        }
        Err(error) => {
            assert!(error.to_string().contains("try again"), "{error}");
            assert!(!adapter.session_dir(&target_info).exists(), "a refused copy creates nothing");
        }
    }
}

/// P114 (Fable P111 #3): the refusal of a point-in-time fork of an unmarked compacted history (written before prompt
/// markers) told the user to "fork at a prompt after the latest compaction", which prompt #6 already is: no prompt of
/// such a history can be cut exactly. The message must offer only what works, a fork of the whole session, and that
/// fork must work.
#[tokio::test]
async fn an_unmarked_history_fork_refusal_offers_only_the_whole_session_fork() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p114-unmarked-advice";
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let projection = vec![ConversationItem::system("sys"), ConversationItem::user("summary of P0 to P4")];
    let marker = compaction_at(&adapter, &info, "only", 5, None, projection.clone()).await;
    let mut chat = projection;
    for i in 5..8 {
        chat.extend([ConversationItem::user(format!("P{i}")), ConversationItem::assistant(format!("A{i}"))]);
    }
    let mut updates = Vec::new();
    for i in 0..5 {
        updates.extend([fork_user_chunk(sid, &format!("P{i}"), i), fork_agent_chunk(sid, &format!("A{i}"))]);
    }
    updates.push(marker);
    for i in 5..8 {
        updates.extend([fork_user_chunk(sid, &format!("P{i}"), i), fork_agent_chunk(sid, &format!("A{i}"))]);
    }
    let source = p88_source(&adapter, sid, updates, chat).await;
    std::fs::remove_file(adapter.session_dir(&source).join("compaction_checkpoints/only.json")).unwrap();
    let target = |suffix: &str| Info {
        id: acp::SessionId::new(format!("{sid}-{suffix}")),
        cwd: "/src".to_string(),
    };
    let error = adapter
        .copy_session_data(&source, &target("at-6"), CopySessionOptions { target_prompt_index: Some(6), ..Default::default() })
        .await
        .expect_err("the cut cannot be proven, so the fork is refused");
    let message = error.to_string();
    assert!(message.contains("Cannot fork at prompt #6"), "{message}");
    assert!(message.contains("prompt markers"), "says why: {message}");
    assert!(
        !message.contains("after the latest compaction"),
        "prompt #6 is already after the latest compaction; that advice cannot help: {message}"
    );
    assert!(message.contains("Fork the whole session instead"), "offers what works: {message}");
    adapter
        .copy_session_data(&source, &target("whole"), CopySessionOptions::default())
        .await
        .expect("the offered whole-session fork works");
}

/// P114 (Fable P111 #2): forks staged the transcript in the system temporary directory, so a fork failed where 1.0.20's
/// succeeded whenever `$TMPDIR` was missing, full or unwritable (and a tmpfs `/tmp` wrote the transcript to RAM and then
/// copied it again). The fork must work with an unusable `$TMPDIR` and leave no staging directory behind. The
/// environment is per process, so the scenario runs alone in a child test process, which points `TMPDIR` at a missing
/// directory once it has started (the test binary's own log directory is made in the temp dir at startup).
#[test]
fn a_fork_does_not_need_the_system_temp_dir() {
    const INNER: &str = "FUIGO_P114_FORK_STAGING_ROOT";
    if let Some(root) = std::env::var_os(INNER) {
        let missing_tmp = std::path::PathBuf::from(&root).join("no-such-tmp");
        // SAFETY: this child process runs this one test only (`--exact`, one test thread), and nothing else reads the
        // environment while it changes.
        for name in ["TMPDIR", "TMP", "TEMP"] {
            unsafe { std::env::set_var(name, &missing_tmp) };
        }
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(forks_with_an_unusable_temp_dir(std::path::PathBuf::from(root)));
        return;
    }
    let scratch = TempDir::new().unwrap();
    let root = scratch.path().join("sessions");
    std::fs::create_dir_all(&root).unwrap();
    let name = format!(
        "{}::a_fork_does_not_need_the_system_temp_dir",
        module_path!().split_once("::").map_or(module_path!(), |(_, rest)| rest)
    );
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"])
        .env(INNER, &root)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "the forks failed without a usable TMPDIR:\n{stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "the child ran the scenario:\n{stdout}");
}

async fn forks_with_an_unusable_temp_dir(root: std::path::PathBuf) {
    assert!(!std::env::temp_dir().exists(), "the child's temp dir is missing");
    let adapter = JsonlStorageAdapter::with_root(root.clone());
    let sid = "p114-no-tmp";
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let source = p88_source(
        &adapter,
        sid,
        vec![
            fork_user_chunk(sid, "P0", 0),
            fork_agent_chunk(sid, "A0"),
            fork_user_chunk(sid, "P1", 1),
            fork_agent_chunk(sid, "A1"),
        ],
        vec![chat_user("P0", 0), ConversationItem::assistant("A0"), chat_user("P1", 1), ConversationItem::assistant("A1")],
    )
    .await;
    for (suffix, target_prompt_index) in [("whole", None), ("at-0", Some(0))] {
        let target = Info {
            id: acp::SessionId::new(format!("{sid}-{suffix}")),
            cwd: "/src".to_string(),
        };
        adapter
            .copy_session_data(&source, &target, CopySessionOptions { target_prompt_index, ..Default::default() })
            .await
            .unwrap_or_else(|error| panic!("fork {suffix} failed: {error}"));
        let updates = std::fs::read_to_string(adapter.updates_file_path(&target).unwrap()).unwrap();
        assert!(updates.contains("P0"), "fork {suffix} has its transcript");
        assert_eq!(updates.contains("P1"), target_prompt_index.is_none(), "fork {suffix} is cut at its prompt");
    }
    let mut pending = vec![root.clone()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            assert!(!name.contains("fork-staging") && !name.starts_with("fuigo-fork-"), "staging left behind: {}", entry.path().display());
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            }
        }
    }
}

/// P114 (Astra r1 #4, #5): a staging directory sits next to the target session, where the listings skip it, and the
/// sweep of stale ones removes only directories that are old AND whose copy no longer holds their lock (a live copy,
/// even one suspended for days, keeps its directory).
#[tokio::test]
async fn fork_staging_is_hidden_from_listings_and_swept_only_when_dead() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let info = Info {
        id: acp::SessionId::new("p114-staging-listed"),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let target = Info {
        id: acp::SessionId::new("p114-staging-target"),
        cwd: "/src".to_string(),
    };
    let live = adapter.fork_staging_dir(&target).unwrap();
    let parent = live.dir.path().parent().unwrap().to_path_buf();
    assert_eq!(parent, adapter.session_dir(&target).parent().unwrap(), "staged next to the target");
    let listed: Vec<String> = adapter.list_sessions(None).await.unwrap().into_iter().map(|s| s.info.id.0.to_string()).collect();
    assert!(!listed.iter().any(|id| id.starts_with('.')), "a staging directory is not a session: {listed:?}");
    assert!(listed.iter().any(|id| id == "p114-staging-listed"), "the listing still works: {listed:?}");

    let long_ago = filetime::FileTime::from_unix_time(0, 0);
    filetime::set_file_mtime(live.dir.path(), long_ago).unwrap();
    let dead = parent.join(".fuigo-fork-staging-dead");
    std::fs::create_dir(&dead).unwrap();
    std::fs::write(dead.join(".lock"), b"").unwrap();
    filetime::set_file_mtime(&dead, long_ago).unwrap();
    let young = parent.join(".fuigo-fork-staging-young");
    std::fs::create_dir(&young).unwrap();
    let unlocked = parent.join(".fuigo-fork-staging-nolock");
    std::fs::create_dir(&unlocked).unwrap();
    std::fs::write(unlocked.join(".lock.init"), b"").unwrap();
    filetime::set_file_mtime(&unlocked, long_ago).unwrap();

    super::remove_stale_fork_staging(&parent);
    assert!(live.dir.path().exists(), "a live copy's staging directory is kept, however old");
    assert!(!dead.exists(), "an old one whose lock is free is removed");
    assert!(young.exists(), "a young one is kept (its copy may not have locked it yet)");
    assert!(unlocked.exists(), "one without a lock file is kept: no evidence its copy is gone (Astra r2 #4)");
}

/// Texts of the transcript lines (`updates.jsonl`) and of the chat history of `info`, for "is this turn in it" checks.
async fn p123_child_texts(adapter: &JsonlStorageAdapter, info: &Info) -> (String, Vec<String>) {
    let transcript = std::fs::read_to_string(adapter.updates_file(info)).unwrap();
    let chat = adapter
        .load_session(info)
        .await
        .unwrap()
        .chat_history
        .iter()
        .map(ConversationItem::text_content)
        .collect();
    (transcript, chat)
}

fn p123_append_line(path: &std::path::Path, line: &str) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(line.as_bytes()).unwrap();
    file.write_all(b"\n").unwrap();
}

fn p123_update_line(update: &SessionUpdate) -> String {
    serde_json::to_string(&crate::session::storage::SessionUpdateEnvelope::from_update(update).unwrap()).unwrap()
}

/// P123 (K17, Astra P111 r7 #2b / r9): a turn appended to a live source after the copy took its snapshot is in neither
/// the child's transcript nor its model history. Before, the transcript was read after the chat history, so a turn
/// appended in between was in the child's transcript but not in its model history. Both copies are checked: the whole
/// session, and a point-in-time copy whose cut would keep the late lines.
#[tokio::test]
async fn a_turn_appended_mid_copy_is_in_neither_the_transcript_nor_the_history() {
    for (suffix, target_prompt_index) in [("whole", None), ("cut", Some(1))] {
        let temp_dir = TempDir::new().unwrap();
        let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
        let sid = format!("p123-late-turn-{suffix}");
        let info = Info {
            id: acp::SessionId::new(sid.as_str()),
            cwd: "/src".to_string(),
        };
        adapter.init_session(&info, default_model_id()).await.unwrap();
        let source = p88_source(
            &adapter,
            &sid,
            vec![
                fork_user_chunk(&sid, "P0", 0),
                fork_agent_chunk(&sid, "A0"),
                fork_user_chunk(&sid, "P1", 1),
                fork_agent_chunk(&sid, "A1"),
            ],
            vec![chat_user("P0", 0), ConversationItem::assistant("A0"), chat_user("P1", 1), ConversationItem::assistant("A1")],
        )
        .await;
        // The late turn: for the whole copy a new prompt; for the cut at prompt 1 more of prompt 1's own turn.
        let (late_updates, late_chat): (Vec<SessionUpdate>, Vec<ConversationItem>) = match target_prompt_index {
            None => (
                vec![fork_user_chunk(&sid, "P2-LATE", 2), fork_agent_chunk(&sid, "A2-LATE")],
                vec![chat_user("P2-LATE", 2), ConversationItem::assistant("A2-LATE")],
            ),
            Some(_) => (
                vec![fork_agent_chunk(&sid, "A1-LATE")],
                vec![ConversationItem::assistant("A1-LATE")],
            ),
        };
        let (updates_path, chat_path) = (adapter.updates_file(&source), adapter.chat_file(&source));
        let late_update_lines: Vec<String> = late_updates.iter().map(p123_update_line).collect();
        let late_chat_lines: Vec<String> = late_chat.iter().map(|item| serde_json::to_string(item).unwrap()).collect();
        super::AFTER_SOURCE_CHAT_READ.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                for line in &late_update_lines {
                    p123_append_line(&updates_path, line);
                }
                for line in &late_chat_lines {
                    p123_append_line(&chat_path, line);
                }
            }));
        });
        let target_info = Info {
            id: acp::SessionId::new(format!("{sid}-fork")),
            cwd: "/src".to_string(),
        };
        adapter
            .copy_session_data_sync(&source, &target_info, CopySessionOptions { target_prompt_index, ..Default::default() })
            .unwrap_or_else(|error| panic!("{suffix}: the copy failed: {error}"));
        super::AFTER_SOURCE_CHAT_READ.with(|hook| assert!(hook.borrow().is_none(), "{suffix}: the seam ran"));
        let (transcript, chat) = p123_child_texts(&adapter, &target_info).await;
        let late = if target_prompt_index.is_none() { "P2-LATE" } else { "A1-LATE" };
        let in_transcript = transcript.contains(late);
        let in_history = chat.iter().any(|text| text.contains(late));
        assert_eq!(
            in_transcript, in_history,
            "{suffix}: the late turn is in the child's transcript ({in_transcript}) but its history says ({in_history}); it must be in both or neither"
        );
        assert!(!in_transcript, "{suffix}: the snapshot is taken before the late turn, so it is in neither");
    }
}

/// P123 (K17): the snapshot is taken with the source's append locks held, so an append in progress finishes first and a
/// new one waits. The copy therefore waits for a lock held on either file, and goes ahead once it is released. The test
/// waits for the copy to be at the lock (it records every lock it found held), so it depends on no timing.
#[tokio::test]
async fn the_copy_snapshot_waits_for_an_append_in_progress() {
    for locked in ["chat_history.jsonl", "updates.jsonl", "snapshot.lock"] {
        let temp_dir = TempDir::new().unwrap();
        let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
        let sid = format!("p123-lock-{}", locked.trim_end_matches(".jsonl"));
        let info = Info {
            id: acp::SessionId::new(sid.as_str()),
            cwd: "/src".to_string(),
        };
        adapter.init_session(&info, default_model_id()).await.unwrap();
        let source = p88_source(
            &adapter,
            &sid,
            vec![fork_user_chunk(&sid, "P0", 0), fork_agent_chunk(&sid, "A0")],
            vec![chat_user("P0", 0), ConversationItem::assistant("A0")],
        )
        .await;
        let lock_target = adapter.session_dir(&source).join(locked);
        let (lock_file, held) = if locked == "snapshot.lock" {
            let held = crate::session::storage::snapshot_lock::acquire_blocking(&lock_target, &lock_target).unwrap().unwrap();
            (lock_target.clone(), held)
        } else {
            (lock_target.with_extension("jsonl.lock"), JsonlStorageAdapter::lock_append(&lock_target).unwrap())
        };
        crate::session::storage::snapshot_lock::CONTENDED.lock().remove(&lock_file);
        let target_info = Info {
            id: acp::SessionId::new(format!("{sid}-fork")),
            cwd: "/src".to_string(),
        };
        let copier = adapter.clone();
        let (copy_source, copy_target) = (source.clone(), target_info.clone());
        let copy = std::thread::spawn(move || {
            copier.copy_session_data_sync(&copy_source, &copy_target, CopySessionOptions::default())
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !crate::session::storage::snapshot_lock::CONTENDED.lock().contains(&lock_file) {
            assert!(std::time::Instant::now() < deadline, "{locked}: the copy never reached the held lock");
            assert!(!copy.is_finished(), "{locked}: the copy finished without waiting for the lock held on the source");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!copy.is_finished(), "{locked}: the copy went ahead while an append to the source was in progress");
        assert!(!adapter.session_dir(&target_info).exists(), "{locked}: nothing is created while the snapshot waits");
        drop(held);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !copy.is_finished() {
            assert!(std::time::Instant::now() < deadline, "{locked}: the copy never finished after the lock was released");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        copy.join().unwrap().unwrap_or_else(|error| panic!("{locked}: the copy failed: {error}"));
    }
}

/// P123 (Astra r1 MEDIUM): a copy that keeps no transcript (a subagent's context copy, `fork_filter`) does not read the
/// transcript, so a transcript writer that holds its lock must not hold the copy up.
#[tokio::test]
async fn a_subagent_context_copy_does_not_wait_for_the_transcript_lock() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p123-fork-filter-lock";
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let source = p88_source(
        &adapter,
        sid,
        vec![fork_user_chunk(sid, "P0", 0), fork_agent_chunk(sid, "A0")],
        vec![chat_user("P0", 0), ConversationItem::assistant("A0")],
    )
    .await;
    let held = JsonlStorageAdapter::lock_append(&adapter.updates_file(&source)).unwrap();
    let target_info = Info {
        id: acp::SessionId::new(format!("{sid}-child")),
        cwd: "/src".to_string(),
    };
    let copier = adapter.clone();
    let (copy_source, copy_target) = (source.clone(), target_info.clone());
    let copy = std::thread::spawn(move || {
        copier.copy_session_data_sync(
            &copy_source,
            &copy_target,
            CopySessionOptions {
                fork_filter: true,
                ..Default::default()
            },
        )
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !copy.is_finished() {
        assert!(
            std::time::Instant::now() < deadline,
            "a copy that keeps no transcript waited for the transcript's append lock"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    copy.join().unwrap().expect("the context copy was made");
    drop(held);
}

/// Tool results in `items` whose tool call is not declared by an assistant item before them.
fn p123_orphaned_results(items: &[ConversationItem]) -> Vec<String> {
    let mut declared = std::collections::HashSet::new();
    let mut orphans = Vec::new();
    for item in items {
        match item {
            ConversationItem::Assistant(assistant) => {
                declared.extend(assistant.tool_calls.iter().map(|call| call.id.to_string()));
            }
            ConversationItem::ToolResult(result) if !declared.contains(&result.tool_call_id) => {
                orphans.push(result.tool_call_id.clone());
            }
            _ => {}
        }
    }
    orphans
}

/// A source whose assistant line carrying the tool call `p123-call` is torn in half, as a crash in the middle of an
/// append leaves it: the reader skips the line and the result after it has no call.
async fn p123_torn_source(adapter: &JsonlStorageAdapter, sid: &str) -> Info {
    let info = Info {
        id: acp::SessionId::new(sid),
        cwd: "/src".to_string(),
    };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let source = p88_source(
        adapter,
        sid,
        vec![
            fork_user_chunk(sid, "P0", 0),
            fork_agent_chunk(sid, "A0"),
            fork_user_chunk(sid, "P1", 1),
            fork_agent_chunk(sid, "A1"),
        ],
        vec![
            chat_user("P0", 0),
            ConversationItem::assistant_tool_calls(vec![fuigo_sampling_types::ToolCall {
                id: std::sync::Arc::<str>::from("p123-call"),
                name: "read_file".to_string(),
                arguments: std::sync::Arc::<str>::from("{}"),
            }]),
            ConversationItem::tool_result("p123-call", "file contents"),
            ConversationItem::assistant("A0"),
            chat_user("P1", 1),
            ConversationItem::assistant("A1"),
        ],
    )
    .await;
    let path = adapter.chat_file(&source);
    let text = std::fs::read_to_string(&path).unwrap();
    let mut out = String::new();
    let mut torn = false;
    for line in text.lines() {
        if !torn && line.contains("p123-call") {
            out.push_str(&line[..line.len() / 2]);
            torn = true;
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    assert!(torn, "fixture: the assistant line was torn");
    std::fs::write(&path, out).unwrap();
    source
}

/// P123 (K14): a fork of a session whose history is damaged (a torn line left a tool result without its call) gets a
/// repaired history. Before, the child inherited the orphaned result and every request of the fork was rejected. The
/// source file is not touched (it is the evidence), so the child needs no backup of its own.
#[tokio::test]
async fn a_fork_of_a_damaged_session_gets_a_repaired_history() {
    for (suffix, target_prompt_index) in [("whole", None), ("cut", Some(1))] {
        let temp_dir = TempDir::new().unwrap();
        let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
        let source = p123_torn_source(&adapter, &format!("p123-torn-{suffix}")).await;
        let before = std::fs::read(adapter.chat_file(&source)).unwrap();
        let target_info = Info {
            id: acp::SessionId::new(format!("p123-torn-{suffix}-fork")),
            cwd: "/src".to_string(),
        };
        adapter
            .copy_session_data(&source, &target_info, CopySessionOptions { target_prompt_index, ..Default::default() })
            .await
            .unwrap();
        let child = adapter.load_session(&target_info).await.unwrap().chat_history;
        assert_eq!(p123_orphaned_results(&child), Vec::<String>::new(), "{suffix}: the child inherited an orphaned tool result");
        assert_eq!(std::fs::read(adapter.chat_file(&source)).unwrap(), before, "{suffix}: the source file is left as it was");
    }
}

/// P123 (K14): the same for a session an earlier load already scrubbed (its raw file is kept as `.corrupt`, every line
/// parses now, the orphaned result is still there).
#[tokio::test]
async fn a_fork_of_a_session_scrubbed_by_an_earlier_load_gets_a_repaired_history() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let source = p123_torn_source(&adapter, "p123-scrubbed").await;
    let chat = adapter.chat_file(&source);
    let torn = std::fs::read(&chat).unwrap();
    // The earlier load: the reader kept the raw file as `.corrupt` and the file was rewritten without the torn line.
    std::fs::write(chat.with_extension("jsonl.corrupt"), &torn).unwrap();
    let scrubbed: Vec<&str> = std::str::from_utf8(&torn)
        .unwrap()
        .lines()
        .filter(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
        .collect();
    std::fs::write(&chat, scrubbed.join("\n") + "\n").unwrap();
    let target_info = Info {
        id: acp::SessionId::new("p123-scrubbed-fork"),
        cwd: "/src".to_string(),
    };
    adapter
        .copy_session_data(&source, &target_info, CopySessionOptions::default())
        .await
        .unwrap();
    let child = adapter.load_session(&target_info).await.unwrap().chat_history;
    assert_eq!(p123_orphaned_results(&child), Vec::<String>::new(), "the child inherited an orphaned tool result");
}

/// P123 (K14): resuming a subagent reads its history through `load_chat_history_from_dir`, which must hand back a
/// repaired history too, not the orphaned result a torn line left.
#[tokio::test]
async fn a_subagent_resume_reads_a_repaired_history() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let source = p123_torn_source(&adapter, "p123-resume").await;
    let history = adapter.load_chat_history_from_dir(&adapter.session_dir(&source)).unwrap();
    assert_eq!(p123_orphaned_results(&history), Vec::<String>::new(), "the resume history carries an orphaned tool result");
}

/// P123 (Astra r3 N3): a fork that is suspended must hold the source's writers only for the two stats. The snapshot
/// releases the append locks before it reads the chat history (checked by taking them from the seam that runs between).
#[tokio::test]
async fn the_snapshot_releases_its_locks_before_it_reads_the_history() {
    let temp_dir = TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(temp_dir.path().to_path_buf());
    let sid = "p123-n3";
    let info = Info { id: acp::SessionId::new(sid), cwd: "/src".to_string() };
    adapter.init_session(&info, default_model_id()).await.unwrap();
    let source = p88_source(
        &adapter,
        sid,
        vec![fork_user_chunk(sid, "P0", 0), fork_agent_chunk(sid, "A0")],
        vec![chat_user("P0", 0), ConversationItem::assistant("A0")],
    )
    .await;
    let free = std::rc::Rc::new(std::cell::Cell::new((false, false, false)));
    let seen = free.clone();
    let dir = adapter.session_dir(&source);
    super::AFTER_SNAPSHOT_LOCKS_RELEASED.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let can = |path: std::path::PathBuf| {
                let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path).unwrap();
                fs2::FileExt::try_lock_exclusive(&file).is_ok()
            };
            seen.set((
                can(dir.join("chat_history.jsonl.lock")),
                can(dir.join("updates.jsonl.lock")),
                can(dir.join("snapshot.lock")),
            ));
        }));
    });
    let target = Info { id: acp::SessionId::new(format!("{sid}-fork")), cwd: "/src".to_string() };
    adapter.copy_session_data_sync(&source, &target, CopySessionOptions::default()).unwrap();
    super::AFTER_SNAPSHOT_LOCKS_RELEASED.with(|hook| assert!(hook.borrow().is_none(), "the seam ran"));
    assert_eq!(free.get(), (true, true, true), "the snapshot still held a lock while it read the history");
}

/// Lock hygiene (R-lock-hygiene): the append lock a fork snapshot takes is free once released, even while a copy of its
/// descriptor (a forked child's, here `try_clone`) lives on.
#[test]
fn a_released_append_lock_is_free_although_a_copy_of_its_descriptor_lives_on() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("chat_history.jsonl");
    let held = super::lock_append_for_snapshot(&file).unwrap().unwrap();
    let inherited = held.try_clone().unwrap();
    drop(held);
    let lock = std::fs::OpenOptions::new().read(true).write(true).open(file.with_extension("jsonl.lock")).unwrap();
    let free = fs2::FileExt::try_lock_exclusive(&lock).is_ok();
    drop(inherited);
    assert!(free, "the released append lock stayed held by an inherited descriptor");
}

/// Lock hygiene follow-up 2 (R-lock-hygiene): the lock `lock_append` takes is free once its holder is dropped without
/// the explicit unlock (a panic or early return), even while a copy of its descriptor (a forked child's, here
/// `try_clone`) lives on.
#[cfg(unix)]
#[test]
fn a_dropped_lock_append_guard_is_free_although_a_copy_of_its_descriptor_lives_on() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("chat_history.jsonl");
    let held = JsonlStorageAdapter::lock_append(&file).unwrap();
    let inherited = held.try_clone().unwrap();
    drop(held);
    let lock = std::fs::OpenOptions::new().read(true).write(true).open(file.with_extension("jsonl.lock")).unwrap();
    let free = fs2::FileExt::try_lock_exclusive(&lock).is_ok();
    drop(inherited);
    assert!(free, "the dropped append lock stayed held by an inherited descriptor");
}
