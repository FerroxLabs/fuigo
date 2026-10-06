//! Pull-on-miss: fetch a session from the backend and hydrate local JSONL storage.

use crate::remote::client::{BackendClient, BackendError};

#[derive(Debug)]
pub enum PullResult {
    /// Written to local storage. The [`Info`] cwd comes from the backend (may differ from caller's).
    Hydrated(crate::session::info::Info),
    /// Not found on the backend.
    NotFound,
}

/// Fetch a session from the backend and hydrate local JSONL storage.
pub async fn pull_session_to_local(
    session_id: &str,
    client: &BackendClient,
) -> Result<PullResult, BackendError> {
    let loaded = match client.load_session_data(session_id).await {
        Ok(resp) => resp,
        Err(BackendError::SessionNotFound { .. }) => return Ok(PullResult::NotFound),
        Err(e) => return Err(e),
    };

    let remote = match loaded.session.as_ref() {
        Some(s) => s,
        None => return Ok(PullResult::NotFound),
    };

    // cwd is required for local dir placement; null means the session predates cwd writeback
    let cwd = match remote.cwd.as_ref() {
        Some(cwd) => cwd,
        None => {
            tracing::warn!(session_id, "Cannot pull session: backend has cwd=null");
            return Ok(PullResult::NotFound);
        }
    };

    let info = crate::session::info::Info {
        id: agent_client_protocol::SessionId::new(std::sync::Arc::from(session_id)),
        cwd: cwd.clone(),
    };
    let dir = crate::session::persistence::session_dir(&info);
    // Create the owner-only `<encoded-cwd>` dir up front (best-effort)
    if let Err(e) = crate::util::fuigo_home::ensure_sessions_cwd_dir(cwd) {
        tracing::warn!(?e, "failed to ensure sessions cwd dir for pulled session");
    }

    let num_messages = hydrate::write_to_dir(&dir, &loaded)?;

    tracing::info!(session_id, %cwd, num_messages, "Pulled session from backend");

    Ok(PullResult::Hydrated(info))
}

pub(crate) mod hydrate {
    use std::path::Path;
    use std::sync::Arc;

    use crate::remote::client::{BackendError, LoadDataResponse, LoadedMessage, SessionInfo};
    use crate::session::info::Info;
    use crate::session::persistence::{
        CHAT_FORMAT_VERSION, Summary, default_model_id, sanitize_and_cap_title,
    };
    use crate::session::storage::{SUMMARY_FILE, UPDATES_FILE};

    fn io_err(path: &Path, source: std::io::Error) -> BackendError {
        BackendError::Hydration {
            path: path.to_path_buf(),
            source,
        }
    }

    /// Write all session files to `dir`.
    pub(super) fn write_to_dir(
        dir: &Path,
        loaded: &LoadDataResponse,
    ) -> Result<usize, BackendError> {
        let remote = loaded
            .session
            .as_ref()
            .expect("caller checked session.is_some()");

        let info = Info {
            id: agent_client_protocol::SessionId::new(Arc::from(remote.session_id.as_str())),
            cwd: remote.cwd.clone().expect("caller verified cwd is Some"),
        };

        crate::util::fuigo_home::create_dir_all_owner_only(dir).map_err(|e| io_err(dir, e))?;

        let num_messages = loaded.messages.as_ref().map_or(0, |m| m.len());
        let mut num_chat_messages = 0;

        if let Some(ref messages) = loaded.messages {
            write_updates(dir, messages)?;
            num_chat_messages = crate::session::storage::chat_rebuild::rebuild_chat_history(dir)
                .map_err(|e| io_err(dir, e))?;
        }

        write_summary(dir, &info, remote, num_messages, num_chat_messages)?;
        write_remote_origin_marker(dir);

        Ok(num_messages)
    }

    fn write_summary(
        dir: &Path,
        info: &Info,
        remote: &SessionInfo,
        num_messages: usize,
        num_chat_messages: usize,
    ) -> Result<(), BackendError> {
        let meta = remote.metadata.as_ref();

        let model_id = meta
            .and_then(|m| m.get("modelId"))
            .and_then(|v| v.as_str())
            .map(agent_client_protocol::ModelId::new)
            .unwrap_or_else(default_model_id);

        let parent_session_id = meta
            .and_then(|m| m.get("parentSessionId"))
            .and_then(|v| v.as_str())
            .map(String::from);

        // Pull does not go through the rename extension, so strip and cap here before this reaches `display_name`
        //
        // `save_session_data` writes the metadata blob, not the session-row title (`upsert` there passes title=None)
        // Prefer an explicit blob title, including blank (meaning cleared), so a stale row cannot resurrect a pin or clobber a metadata-only rename
        let remote_title = match meta.and_then(|m| m.get("title")) {
            Some(v) => v.as_str().and_then(sanitize_and_cap_title),
            None => remote.title.as_deref().and_then(sanitize_and_cap_title),
        };
        let generated_title = if remote_title_is_manual(meta) {
            remote_title.clone()
        } else {
            None
        };
        let title_is_manual = generated_title.is_some();

        let mut summary = Summary {
            info: info.clone(),
            cwd_generation: 0,
            previous_cwd: None,
            pending_cwd_switch_reminder: None,
            cwd_switch_bookkeeping_generation: 0,
            session_summary: remote_title.unwrap_or_default(),
            created_at: parse_rfc3339_or_now(remote.created_at.as_deref()),
            updated_at: parse_rfc3339_or_now(remote.updated_at.as_deref()),
            num_messages,
            num_chat_messages,
            current_model_id: model_id,
            parent_session_id,
            forked_at: None,
            collection_id: None,
            next_trace_turn: 0,
            chat_format_version: CHAT_FORMAT_VERSION,
            prompt_display_cwd: None,
            session_kind: None,
            fork_context_source: None,
            fork_parent_prompt_id: None,
            inherited_prefix_len: None,
            hidden: None,
            source_workspace_dir: None,
            git_root_dir: None,
            git_remotes: Vec::new(),
            head_commit: None,
            head_branch: None,
            request_id: None,
            // Record the *local* fuigo_home (where this hydrated copy lives), not the original remote session's, since reconstruction runs locally
            fuigo_home: crate::session::persistence::fuigo_home_string(),
            last_active_at: None,
            generated_title,
            title_is_manual,
            worktree_label: None,
            agent_name: None,
            // Hydrated locally: record the profile this process runs under
            sandbox_profile: fuigo_sandbox::configured_profile_name().map(String::from),
            reasoning_effort: None,
            last_turn_summary: None,
            last_turn_summary_prompt_id: None,
            last_recap: None,
        };
        if let Some(identity) = crate::session::worktree::worktree_identity_for_cwd(&info.cwd) {
            summary.stamp_worktree_identity(&identity);
        }

        let json = serde_json::to_string_pretty(&summary)?;
        write_file(&dir.join(SUMMARY_FILE), json.as_bytes())
    }

    /// Convert backend JSON-RPC messages to local updates.jsonl (replayable methods only).
    pub(super) fn write_updates(
        dir: &Path,
        messages: &[LoadedMessage],
    ) -> Result<(), BackendError> {
        use std::io::Write;

        let path = dir.join(UPDATES_FILE);
        // Pulled session files are owner-only like local ones (P150, S14).
        let file = fuigo_config::create_file_owner_only(&path).map_err(|e| io_err(&path, e))?;
        let mut w = std::io::BufWriter::new(file);

        for msg in messages {
            let parsed = match serde_json::from_str::<serde_json::Value>(&msg.content) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if is_compaction_checkpoint(&parsed) {
                if let Some(line) = restore_checkpoint(dir, &parsed) {
                    let _ = w.write_all(line.as_bytes());
                    let _ = w.write_all(b"\n");
                }
                continue;
            }
            if !is_session_update(&parsed) {
                continue;
            }
            let parsed = match sanitize_pulled_marker(parsed) {
                Some(p) => p,
                None => continue,
            };
            if let Some(line) = to_envelope_line(&parsed) {
                let _ = w.write_all(line.as_bytes());
                let _ = w.write_all(b"\n");
            }
        }

        w.flush().map_err(|e| io_err(&path, e))
    }

    fn write_remote_origin_marker(dir: &Path) {
        let _ = fuigo_config::write_file_owner_only(
            &dir.join(".remote_origin"),
            format!("pulled_at={}\n", chrono::Utc::now().to_rfc3339()),
        );
    }

    /// Replayable JSON-RPC methods (excludes metadata like `prompt_complete`).
    const REPLAYABLE_METHODS: &[&str] = &["session/update", "_fuigo/session/update"];

    fn is_session_update(json_rpc: &serde_json::Value) -> bool {
        json_rpc
            .get("method")
            .and_then(|v| v.as_str())
            .is_some_and(|m| REPLAYABLE_METHODS.contains(&m))
    }

    fn is_compaction_checkpoint(json_rpc: &serde_json::Value) -> bool {
        json_rpc.get("method").and_then(|v| v.as_str())
            == Some(crate::session::export::COMPACTION_CHECKPOINT_METHOD)
    }

    /// A pulled `_fuigo/session/update` compaction marker names a file inside the session dir. The remote is not
    /// trusted: with a plain-token id the path is rewritten to `compaction_checkpoints/<id>.json`; any other marker
    /// (a path, dots, an absolute path as id) is dropped so nothing outside the session dir is ever named.
    fn sanitize_pulled_marker(mut json_rpc: serde_json::Value) -> Option<serde_json::Value> {
        use crate::extensions::notification::{SessionNotification, SessionUpdate};
        if json_rpc.get("method").and_then(|v| v.as_str()) != Some("_fuigo/session/update") {
            return Some(json_rpc);
        }
        let Some(params) = json_rpc.get("params") else {
            return Some(json_rpc);
        };
        let Ok(mut note) = serde_json::from_value::<SessionNotification>(params.clone()) else {
            return Some(json_rpc);
        };
        let SessionUpdate::CompactionCheckpoint(info) = &mut note.update else {
            return Some(json_rpc);
        };
        if !is_safe_checkpoint_id(&info.checkpoint_id) {
            tracing::warn!("Pull: dropping a compaction marker with an unsafe checkpoint id");
            return None;
        }
        info.checkpoint_file = format!("compaction_checkpoints/{}.json", info.checkpoint_id);
        json_rpc["params"] = serde_json::to_value(&note).ok()?;
        Some(json_rpc)
    }

    /// A checkpoint id becomes a file name, so only a plain token is accepted; anything else (a path, dots) is refused.
    fn is_safe_checkpoint_id(id: &str) -> bool {
        !id.is_empty()
            && id.len() <= 128
            && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    /// Write the uploaded checkpoint file under `compaction_checkpoints/` and return the `updates.jsonl` line for its
    /// marker, with the marker's file path rewritten to the local file (the remote path is never trusted). A malformed
    /// or unsafe message yields `None`: the pull continues and that compaction degrades to the summary-less resume.
    fn restore_checkpoint(dir: &Path, json_rpc: &serde_json::Value) -> Option<String> {
        use crate::extensions::notification::{
            CompactionCheckpointFile, SessionNotification, SessionUpdate,
        };
        let params = json_rpc.get("params")?;
        let file: CompactionCheckpointFile =
            serde_json::from_value(params.get("checkpoint")?.clone()).ok()?;
        let mut marker: SessionNotification =
            serde_json::from_value(params.get("marker")?.clone()).ok()?;
        let SessionUpdate::CompactionCheckpoint(info) = &mut marker.update else {
            return None;
        };
        if !is_safe_checkpoint_id(&file.checkpoint_id) || info.checkpoint_id != file.checkpoint_id {
            tracing::warn!("Pull: ignoring a compaction checkpoint with an unsafe or mismatched id");
            return None;
        }
        let rel = format!("compaction_checkpoints/{}.json", file.checkpoint_id);
        let sub = dir.join("compaction_checkpoints");
        crate::util::fuigo_home::create_dir_all_owner_only(&sub).ok()?;
        let bytes = serde_json::to_vec_pretty(&file).ok()?;
        // Owner-only like every session file (P120): the summary is conversation text.
        crate::session::storage::owner_only::write(&dir.join(&rel), bytes).ok()?;
        info.checkpoint_file = rel;
        let marker = serde_json::to_value(&marker).ok()?;
        serde_json::to_string(&serde_json::json!({
            "timestamp": 0u64,
            "method": "_fuigo/session/update",
            "params": marker,
        }))
        .ok()
    }

    fn to_envelope_line(json_rpc: &serde_json::Value) -> Option<String> {
        let method = json_rpc.get("method").and_then(|v| v.as_str())?;
        let params = json_rpc.get("params").cloned().unwrap_or_default();

        serde_json::to_string(&serde_json::json!({
            "timestamp": 0u64,
            "method": method,
            "params": params,
        }))
        .ok()
    }

    fn parse_rfc3339_or_now(s: Option<&str>) -> chrono::DateTime<chrono::Utc> {
        s.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(chrono::Utc::now)
    }

    fn write_file(path: &Path, data: &[u8]) -> Result<(), BackendError> {
        fuigo_config::write_file_owner_only(path, data).map_err(|e| io_err(path, e))
    }

    fn remote_title_is_manual(meta: Option<&serde_json::Value>) -> bool {
        meta.and_then(|m| {
            m.get("title_is_manual")
                .or_else(|| m.get("titleIsManual"))
                .and_then(|v| v.as_bool())
        })
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use crate::remote::client::LoadedMessage;

    #[test]
    #[serial_test::serial]
    fn hydrated_summary_stamps_worktree_identity_for_worktree_cwd() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let home = tempfile::TempDir::new().unwrap();
        let _env = fuigo_test_support::EnvGuard::set("FUIGO_HOME", home.path());
        let cwd = home.path().join("worktrees").join("fuigo").join("fix-bug");
        std::fs::create_dir_all(&cwd).unwrap();

        let data = crate::remote::client::LoadDataResponse {
            messages: None,
            session: Some(crate::remote::client::SessionInfo {
                session_id: "pulled-worktree".into(),
                title: None,
                cwd: Some(cwd.to_string_lossy().into_owned()),
                status: None,
                created_at: None,
                updated_at: None,
                metadata: None,
            }),
        };
        let dir = home.path().join("session-dir");
        super::hydrate::write_to_dir(&dir, &data).unwrap();

        let summary: crate::session::persistence::Summary =
            serde_json::from_slice(&std::fs::read(dir.join("summary.json")).unwrap()).unwrap();
        assert_eq!(summary.session_kind.as_deref(), Some("worktree"));
        assert_eq!(summary.worktree_label.as_deref(), Some("fix-bug"));
        assert!(summary.source_workspace_dir.is_none());
    }

    #[test]
    fn hydrate_writes_valid_updates_jsonl() {
        let tmp = tempfile::TempDir::new().unwrap();
        let messages = vec![
            LoadedMessage {
                id: "1".into(),
                content: r#"{"method":"session/update","params":{"update":"hello"}}"#.into(),
                timestamp: None,
            },
            LoadedMessage {
                id: "2".into(),
                content: r#"{"method":"session/update","params":{"update":"world"}}"#.into(),
                timestamp: None,
            },
        ];

        super::hydrate::write_updates(tmp.path(), &messages).unwrap();

        let content = std::fs::read_to_string(tmp.path().join("updates.jsonl")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["timestamp"], 0);
            assert_eq!(v["method"], "session/update");
            assert!(v["params"].is_object());
        }
    }

    #[test]
    fn rebuild_chat_history_merges_chunks() {
        use crate::session::export::ExportedMessage;
        use agent_client_protocol::{ContentBlock, ContentChunk, SessionUpdate, TextContent};
        use std::sync::Arc;

        // Build ACP notifications matching the RemoteSync path
        let sid = agent_client_protocol::SessionId::new(Arc::from("test"));
        let notifications = [
            agent_client_protocol::SessionNotification::new(
                sid.clone(),
                SessionUpdate::UserMessageChunk(ContentChunk::new(ContentBlock::Text(
                    TextContent::new("hello "),
                ))),
            ),
            agent_client_protocol::SessionNotification::new(
                sid.clone(),
                SessionUpdate::UserMessageChunk(ContentChunk::new(ContentBlock::Text(
                    TextContent::new("world"),
                ))),
            ),
            agent_client_protocol::SessionNotification::new(
                sid.clone(),
                SessionUpdate::AgentMessageChunk(ContentChunk::new(ContentBlock::Text(
                    TextContent::new("hi back"),
                ))),
            ),
        ];

        // Serialize through ExportedMessage (writeback path)
        let messages: Vec<LoadedMessage> = notifications
            .iter()
            .map(|n| {
                let exported = ExportedMessage::from_notification(n);
                LoadedMessage {
                    id: "x".into(),
                    content: exported.content,
                    timestamp: None,
                }
            })
            .collect();

        let data = crate::remote::client::LoadDataResponse {
            messages: Some(messages),
            session: Some(crate::remote::client::SessionInfo {
                session_id: "test".into(),
                title: None,
                cwd: Some("/tmp".into()),
                status: None,
                created_at: None,
                updated_at: None,
                metadata: None,
            }),
        };
        let tmp = tempfile::TempDir::new().unwrap();
        // Subdir so the owner-only assertion covers a dir write_to_dir created.
        let dir = tmp.path().join("session");
        super::hydrate::write_to_dir(&dir, &data).unwrap();

        #[cfg(unix)]
        assert_eq!(
            crate::test_support::unix_mode(&dir),
            0o700,
            "hydrated session dir must be owner-only"
        );

        let chat = std::fs::read_to_string(dir.join("chat_history.jsonl")).unwrap();
        let items: Vec<crate::sampling::ConversationItem> = chat
            .lines()
            .filter(|l| !l.is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        assert_eq!(items.len(), 2, "should have 1 user + 1 agent item");
        assert!(matches!(
            &items[0],
            crate::sampling::ConversationItem::User(_)
        ));
        assert!(matches!(
            &items[1],
            crate::sampling::ConversationItem::Assistant(_)
        ));
        if let crate::sampling::ConversationItem::User(u) = &items[0] {
            let text: String = u
                .content
                .iter()
                .filter_map(|p| match p {
                    crate::sampling::ContentPart::Text { text } => Some(text.as_ref()),
                    _ => None,
                })
                .collect();
            assert_eq!(text, "hello world");
        }
    }

    #[test]
    fn rebuild_chat_history_preserves_user_images() {
        use crate::session::export::ExportedMessage;
        use agent_client_protocol::{
            ContentBlock, ContentChunk, ImageContent, SessionUpdate, TextContent,
        };
        use std::sync::Arc;

        let sid = agent_client_protocol::SessionId::new(Arc::from("test"));
        let notifications = [
            agent_client_protocol::SessionNotification::new(
                sid.clone(),
                SessionUpdate::UserMessageChunk(ContentChunk::new(ContentBlock::Text(
                    TextContent::new("look at this"),
                ))),
            ),
            agent_client_protocol::SessionNotification::new(
                sid.clone(),
                SessionUpdate::UserMessageChunk(ContentChunk::new(ContentBlock::Image(
                    ImageContent::new(String::new(), String::new())
                        .uri(Some("data:image/png;base64,abc".into())),
                ))),
            ),
            agent_client_protocol::SessionNotification::new(
                sid.clone(),
                SessionUpdate::AgentMessageChunk(ContentChunk::new(ContentBlock::Text(
                    TextContent::new("I see an image"),
                ))),
            ),
        ];

        let messages: Vec<LoadedMessage> = notifications
            .iter()
            .map(|n| LoadedMessage {
                id: "x".into(),
                content: ExportedMessage::from_notification(n).content,
                timestamp: None,
            })
            .collect();

        let data = crate::remote::client::LoadDataResponse {
            messages: Some(messages),
            session: Some(crate::remote::client::SessionInfo {
                session_id: "test".into(),
                title: None,
                cwd: Some("/tmp".into()),
                status: None,
                created_at: None,
                updated_at: None,
                metadata: None,
            }),
        };
        let tmp = tempfile::TempDir::new().unwrap();
        super::hydrate::write_to_dir(tmp.path(), &data).unwrap();

        let chat = std::fs::read_to_string(tmp.path().join("chat_history.jsonl")).unwrap();
        let items: Vec<crate::sampling::ConversationItem> = chat
            .lines()
            .filter(|l| !l.is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        assert_eq!(items.len(), 2);
        if let crate::sampling::ConversationItem::User(u) = &items[0] {
            assert_eq!(u.content.len(), 2, "should have text + image parts");
            assert!(matches!(
                &u.content[0],
                crate::sampling::ContentPart::Text { .. }
            ));
            assert!(matches!(
                &u.content[1],
                crate::sampling::ContentPart::Image { .. }
            ));
        } else {
            panic!("expected User item");
        }
    }

    #[test]
    fn hydrate_skips_invalid_messages() {
        let tmp = tempfile::TempDir::new().unwrap();
        let messages = vec![
            LoadedMessage {
                id: "1".into(),
                content: r#"{"method":"session/update","params":{}}"#.into(),
                timestamp: None,
            },
            LoadedMessage {
                id: "bad".into(),
                content: "not valid json".into(),
                timestamp: None,
            },
            LoadedMessage {
                id: "3".into(),
                content: r#"{"method":"session/update","params":{"x":1}}"#.into(),
                timestamp: None,
            },
        ];

        super::hydrate::write_updates(tmp.path(), &messages).unwrap();

        let content = std::fs::read_to_string(tmp.path().join("updates.jsonl")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "invalid message should be skipped");
    }

    fn hydrate_summary(
        title: Option<&str>,
        metadata: Option<serde_json::Value>,
    ) -> crate::session::persistence::Summary {
        let data = crate::remote::client::LoadDataResponse {
            messages: None,
            session: Some(crate::remote::client::SessionInfo {
                session_id: "pull-title".into(),
                title: title.map(str::to_owned),
                cwd: Some("/tmp".into()),
                status: None,
                created_at: None,
                updated_at: None,
                metadata,
            }),
        };
        let tmp = tempfile::TempDir::new().unwrap();
        super::hydrate::write_to_dir(tmp.path(), &data).unwrap();
        let json = std::fs::read_to_string(tmp.path().join("summary.json")).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn hydrate_restores_title_is_manual_and_generated_title() {
        let summary = hydrate_summary(
            Some("Pinned hop"),
            Some(serde_json::json!({ "title_is_manual": true })),
        );
        assert!(summary.title_is_manual);
        assert_eq!(summary.generated_title.as_deref(), Some("Pinned hop"));
        assert_eq!(summary.manual_title_opt().as_deref(), Some("Pinned hop"));
    }

    #[test]
    fn hydrate_accepts_camel_case_title_is_manual() {
        let summary = hydrate_summary(
            Some("Camel"),
            Some(serde_json::json!({ "titleIsManual": true })),
        );
        assert!(summary.title_is_manual);
        assert_eq!(summary.generated_title.as_deref(), Some("Camel"));
    }

    #[test]
    fn hydrate_defaults_title_is_manual_false_when_absent() {
        let summary = hydrate_summary(Some("Auto remote"), None);
        assert!(!summary.title_is_manual);
        assert!(summary.generated_title.is_none());
        assert!(summary.manual_title_opt().is_none());
        assert_eq!(summary.display_title(), "Auto remote");
    }

    #[test]
    fn hydrate_ignores_manual_flag_over_blank_title() {
        let summary = hydrate_summary(
            Some("   "),
            Some(serde_json::json!({ "title_is_manual": true })),
        );
        assert!(!summary.title_is_manual);
        assert!(summary.generated_title.is_none());
        assert!(summary.manual_title_opt().is_none());
    }

    #[test]
    fn hydrate_ignores_manual_flag_over_none_title() {
        let summary = hydrate_summary(None, Some(serde_json::json!({ "title_is_manual": true })));
        assert!(!summary.title_is_manual);
        assert!(summary.generated_title.is_none());
        assert!(summary.manual_title_opt().is_none());
    }

    #[test]
    fn hydrate_prefers_metadata_title_over_stale_session_row() {
        let summary = hydrate_summary(
            Some("stale auto row"),
            Some(serde_json::json!({
                "title": "Pinned hop",
                "title_is_manual": true
            })),
        );
        assert!(summary.title_is_manual);
        assert_eq!(summary.generated_title.as_deref(), Some("Pinned hop"));
        assert_eq!(summary.manual_title_opt().as_deref(), Some("Pinned hop"));
        assert_eq!(summary.display_title(), "Pinned hop");
    }

    #[test]
    fn hydrate_blank_metadata_title_does_not_fall_back_to_stale_row() {
        let summary = hydrate_summary(
            Some("stale pinned row"),
            Some(serde_json::json!({
                "title": "",
                "title_is_manual": false
            })),
        );
        assert!(!summary.title_is_manual);
        assert!(summary.generated_title.is_none());
        assert!(summary.manual_title_opt().is_none());
        assert_eq!(summary.session_summary, "");
    }

    #[test]
    fn hydrate_from_summary_export_round_trips_manual_flag() {
        use crate::session::export::ExportedMetadata;
        use crate::session::info::Info;

        let info = Info {
            id: agent_client_protocol::SessionId::new("export-pull"),
            cwd: "/tmp".into(),
        };
        let mut summary = crate::session::persistence::Summary::new(
            &info,
            agent_client_protocol::ModelId::new("test-model"),
        )
        .unwrap();
        summary.generated_title = Some("Pinned hop".into());
        summary.title_is_manual = true;
        summary.session_summary = "stale auto".into();
        let meta = ExportedMetadata::from_summary(&summary);
        let json = serde_json::to_value(&meta).unwrap();
        let pulled = hydrate_summary(meta.title.as_deref(), Some(json));
        assert_eq!(pulled.manual_title_opt().as_deref(), Some("Pinned hop"));
        assert_eq!(pulled.display_title(), "Pinned hop");
    }

    #[test]
    fn hydrate_stale_exported_flag_does_not_promote_auto_fallback() {
        use crate::session::export::ExportedMetadata;
        use crate::session::info::Info;

        let info = Info {
            id: agent_client_protocol::SessionId::new("stale-hop"),
            cwd: "/tmp".into(),
        };
        let mut summary = crate::session::persistence::Summary::new(
            &info,
            agent_client_protocol::ModelId::new("test-model"),
        )
        .unwrap();
        summary.session_summary = "auto first-prompt summary".into();
        summary.generated_title = Some("   ".into());
        summary.title_is_manual = true;
        let meta = ExportedMetadata::from_summary(&summary);
        let pulled = hydrate_summary(
            meta.title.as_deref(),
            Some(serde_json::to_value(&meta).unwrap()),
        );
        assert!(pulled.manual_title_opt().is_none());
        assert!(!pulled.title_is_manual);
    }

    #[test]
    fn hydrate_strips_controls_and_caps_pulled_title() {
        use crate::session::persistence::MAX_TITLE_SCALARS;

        let dirty = format!("\u{1b}]0;PWNED\u{07}{}", "é".repeat(MAX_TITLE_SCALARS + 10));
        let summary = hydrate_summary(
            Some(&dirty),
            Some(serde_json::json!({ "title_is_manual": true })),
        );
        const PREFIX: &str = "]0;PWNED";
        let expected = format!(
            "{PREFIX}{}",
            "é".repeat(MAX_TITLE_SCALARS - PREFIX.chars().count())
        );
        assert_eq!(summary.display_title(), expected);
        assert_eq!(summary.display_title().chars().count(), MAX_TITLE_SCALARS);
        assert!(summary.title_is_manual);
        assert_eq!(
            summary.manual_title_opt().as_deref(),
            Some(expected.as_str())
        );
    }

    fn checkpoint_response(messages: Vec<LoadedMessage>) -> crate::remote::client::LoadDataResponse {
        crate::remote::client::LoadDataResponse {
            messages: Some(messages),
            session: Some(crate::remote::client::SessionInfo {
                session_id: "cp-pull".into(),
                title: None,
                cwd: Some("/tmp".into()),
                status: None,
                created_at: None,
                updated_at: None,
                metadata: None,
            }),
        }
    }

    fn acp_msg(user: bool, text: &str) -> LoadedMessage {
        use agent_client_protocol::{ContentBlock, ContentChunk, SessionUpdate, TextContent};
        let chunk = ContentChunk::new(ContentBlock::Text(TextContent::new(text.to_string())));
        let update = if user { SessionUpdate::UserMessageChunk(chunk) } else { SessionUpdate::AgentMessageChunk(chunk) };
        let n = agent_client_protocol::SessionNotification::new(agent_client_protocol::SessionId::new("cp-pull"), update);
        LoadedMessage { id: "x".into(), content: crate::session::export::ExportedMessage::from_notification(&n).content, timestamp: None }
    }

    fn checkpoint_msg(id: &str, text: &str) -> LoadedMessage {
        let (marker, file) = crate::session::export::checkpoint_upload_tests::marker_and_file(id, text);
        let exported = crate::session::export::ExportedMessage::compaction_checkpoint(&marker, &file).unwrap();
        LoadedMessage { id: "c".into(), content: exported.content, timestamp: None }
    }

    fn chat_texts(dir: &std::path::Path) -> String {
        std::fs::read_to_string(dir.join("chat_history.jsonl")).unwrap()
    }

    #[test]
    fn pulled_compacted_session_resumes_with_its_summary() {
        let data = checkpoint_response(vec![
            acp_msg(true, "old question"),
            acp_msg(false, "old answer"),
            checkpoint_msg("11111111-1111-1111-1111-111111111111", "SUMMARY-OF-OLD-WORK"),
            acp_msg(true, "new question"),
            acp_msg(false, "new answer"),
        ]);
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("s");
        super::hydrate::write_to_dir(&dir, &data).unwrap();
        let chat = chat_texts(&dir);
        assert!(chat.contains("SUMMARY-OF-OLD-WORK"), "summary missing: {chat}");
        assert!(!chat.contains("old question"), "pre-compaction turns must be replaced by the summary");
        assert!(chat.contains("new question") && chat.contains("new answer"));
        assert!(dir.join("compaction_checkpoints/11111111-1111-1111-1111-111111111111.json").is_file());
    }

    /// P132: the restored checkpoint holds the compaction summary (conversation text), so it is owner-only like every
    /// other session file, including when an older, looser file is already there.
    #[cfg(unix)]
    #[test]
    fn pulled_checkpoint_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let id = "33333333-3333-3333-3333-333333333333";
        let data = checkpoint_response(vec![acp_msg(true, "q"), checkpoint_msg(id, "SUMMARY-PRIVATE")]);
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("s");
        let file = dir.join(format!("compaction_checkpoints/{id}.json"));
        super::hydrate::write_to_dir(&dir, &data).unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&file), 0o600, "pulled checkpoint file must be 0600");
        // A pull over an existing loose file tightens it.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        super::hydrate::write_to_dir(&dir, &data).unwrap();
        assert_eq!(mode(&file), 0o600, "an existing loose checkpoint file must be tightened");
    }

    #[test]
    fn pulled_session_without_checkpoint_is_unchanged() {
        let data = checkpoint_response(vec![acp_msg(true, "q"), acp_msg(false, "a")]);
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("s");
        super::hydrate::write_to_dir(&dir, &data).unwrap();
        assert!(chat_texts(&dir).contains('q'));
        assert!(!dir.join("compaction_checkpoints").exists());
    }

    #[test]
    fn hostile_checkpoint_id_cannot_escape_the_session_dir() {
        let data = checkpoint_response(vec![
            acp_msg(true, "q"),
            checkpoint_msg("../../escaped", "SUMMARY"),
            acp_msg(true, "after"),
        ]);
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("a/b/s");
        super::hydrate::write_to_dir(&dir, &data).unwrap();
        assert!(!tmp.path().join("a/escaped.json").exists());
        assert!(!tmp.path().join("escaped.json").exists());
        let entries: Vec<_> = walk(tmp.path());
        assert!(entries.iter().all(|p| p.starts_with(&dir)), "files outside session dir: {entries:?}");
    }

    fn walk(p: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = vec![];
        for e in std::fs::read_dir(p).unwrap().flatten() {
            let path = e.path();
            if path.is_dir() { out.extend(walk(&path)); } else { out.push(path); }
        }
        out
    }

    #[test]
    fn malformed_checkpoint_message_is_skipped_not_fatal() {
        let bad = LoadedMessage { id: "c".into(), content: r#"{"method":"_fuigo/compaction_checkpoint","params":{"nope":1}}"#.into(), timestamp: None };
        let data = checkpoint_response(vec![acp_msg(true, "q"), bad, acp_msg(false, "a")]);
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("s");
        super::hydrate::write_to_dir(&dir, &data).unwrap();
        assert!(chat_texts(&dir).contains('a'));
    }

    #[test]
    fn remote_marker_file_path_is_never_trusted() {
        let id = "22222222-2222-2222-2222-222222222222";
        let mut msg = checkpoint_msg(id, "SUMMARY-X");
        msg.content = msg.content.replace(&format!("compaction_checkpoints/{id}.json"), "../../../outside.json");
        assert!(msg.content.contains("../../../outside.json"));
        let data = checkpoint_response(vec![acp_msg(true, "q"), msg, acp_msg(true, "after")]);
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("a/b/s");
        super::hydrate::write_to_dir(&dir, &data).unwrap();
        assert!(chat_texts(&dir).contains("SUMMARY-X"));
        let updates = std::fs::read_to_string(dir.join("updates.jsonl")).unwrap();
        assert!(!updates.contains("outside.json"), "marker kept the remote path: {updates}");
    }

    fn marker_update_msg(id: &str, file: &str) -> LoadedMessage {
        let (mut marker, _) = crate::session::export::checkpoint_upload_tests::marker_and_file(id, "x");
        if let crate::extensions::notification::SessionUpdate::CompactionCheckpoint(info) = &mut marker.update {
            info.checkpoint_file = file.into();
        }
        let m = crate::session::export::ExportedMessage::from_fuigo_notification(&marker);
        LoadedMessage { id: "m".into(), content: m.content, timestamp: None }
    }

    #[test]
    fn pulled_session_update_marker_path_is_rewritten_to_the_local_file() {
        let id = "33333333-3333-3333-3333-333333333333";
        for hostile in ["../../../etc/passwd", "/etc/passwd", "C:\\x\\y.json"] {
            let data = checkpoint_response(vec![acp_msg(true, "q"), marker_update_msg(id, hostile)]);
            let tmp = tempfile::TempDir::new().unwrap();
            let dir = tmp.path().join("a/b/s");
            super::hydrate::write_to_dir(&dir, &data).unwrap();
            let updates = std::fs::read_to_string(dir.join("updates.jsonl")).unwrap();
            assert!(!updates.contains(hostile.replace('\\', "\\\\").as_str()) && !updates.contains("passwd"), "{hostile}: {updates}");
            assert!(updates.contains(&format!("compaction_checkpoints/{id}.json")), "{updates}");
        }
    }

    #[test]
    fn pulled_session_update_marker_with_unsafe_id_is_dropped() {
        for bad in ["../../escape", "/abs/path", "a/b", ""] {
            let data = checkpoint_response(vec![acp_msg(true, "q"), marker_update_msg(bad, "compaction_checkpoints/x.json")]);
            let tmp = tempfile::TempDir::new().unwrap();
            let dir = tmp.path().join("s");
            super::hydrate::write_to_dir(&dir, &data).unwrap();
            let updates = std::fs::read_to_string(dir.join("updates.jsonl")).unwrap();
            assert!(!updates.contains("compaction_checkpoint"), "{bad:?} kept: {updates}");
        }
    }
}
