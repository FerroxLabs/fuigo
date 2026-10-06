//! Session export for sharing via the remote session-sharing backend.
//!
//! Uses `updates.jsonl` (ACP SessionNotifications) as the source of truth, not `chat_history.jsonl` which is only for LLM API calls.

use crate::session::info::Info;
use crate::session::persistence::Summary;
use crate::session::storage::{JsonlStorageAdapter, PersistedData, SessionUpdate, StorageAdapter};
use agent_client_protocol as acp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct AcpJsonRpcNotification<'a> {
    method: &'static str,
    params: &'a acp::SessionNotification,
}

#[derive(Debug, Serialize)]
struct FuigoJsonRpcNotification<'a> {
    method: &'static str,
    params: &'a crate::extensions::notification::SessionNotification,
}

const ACP_SESSION_UPDATE_METHOD: &str = "session/update";
const FUIGO_SESSION_UPDATE_METHOD: &str = "_fuigo/session/update";

/// JSON-RPC method of the upload message that carries a compaction checkpoint (marker plus file) through the backend's
/// opaque message store. Deliberately neither `session/update` nor `_fuigo/session/update`: clients that predate it
/// skip a method they do not replay, so an old client pulling a new upload sees exactly what it saw before.
pub(crate) const COMPACTION_CHECKPOINT_METHOD: &str = "_fuigo/compaction_checkpoint";

/// A checkpoint whose serialized upload exceeds this is not uploaded (the pulled session then resumes without its
/// summary, with a warning, as before). It bounds one message so a huge compaction cannot wedge the writeback queue.
pub(crate) const MAX_CHECKPOINT_UPLOAD_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Serialize)]
struct CheckpointParams<'a> {
    marker: &'a crate::extensions::notification::SessionNotification,
    checkpoint: &'a crate::extensions::notification::CompactionCheckpointFile,
}

#[derive(Debug, Serialize)]
struct CheckpointJsonRpc<'a> {
    method: &'static str,
    params: CheckpointParams<'a>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedMessage {
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

impl ExportedMessage {
    pub fn from_notification(notification: &acp::SessionNotification) -> Self {
        let wrapper = AcpJsonRpcNotification {
            method: ACP_SESSION_UPDATE_METHOD,
            params: notification,
        };
        let content = serde_json::to_string(&wrapper).unwrap_or_else(|_| "{}".to_string());

        let timestamp = notification
            .meta
            .as_ref()
            .and_then(|m| m.get("timestamp"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Self { content, timestamp }
    }

    /// Upload form of a committed compaction: the activation marker and the checkpoint file, in one message.
    /// `None` when it would exceed [`MAX_CHECKPOINT_UPLOAD_BYTES`] or fails to serialize.
    pub(crate) fn compaction_checkpoint(
        marker: &crate::extensions::notification::SessionNotification,
        checkpoint: &crate::extensions::notification::CompactionCheckpointFile,
    ) -> Option<Self> {
        let wrapper = CheckpointJsonRpc {
            method: COMPACTION_CHECKPOINT_METHOD,
            params: CheckpointParams { marker, checkpoint },
        };
        let content = serde_json::to_string(&wrapper).ok()?;
        if content.len() > MAX_CHECKPOINT_UPLOAD_BYTES {
            tracing::warn!(bytes = content.len(), "compaction checkpoint too large to upload; a pulled copy resumes without its summary");
            return None;
        }
        Some(Self { content, timestamp: None })
    }

    /// True for the upload message built by [`Self::compaction_checkpoint`] (its `method` is serialized first).
    pub(crate) fn is_compaction_checkpoint(&self) -> bool {
        self.content
            .starts_with(concat!(r#"{"method":""#, "_fuigo/compaction_checkpoint", r#"""#))
    }

    pub(crate) fn from_fuigo_notification(
        notification: &crate::extensions::notification::SessionNotification,
    ) -> Self {
        let wrapper = FuigoJsonRpcNotification {
            method: FUIGO_SESSION_UPDATE_METHOD,
            params: notification,
        };
        let content = serde_json::to_string(&wrapper).unwrap_or_else(|_| "{}".to_string());

        let timestamp = notification
            .meta
            .as_ref()
            .and_then(|m| m.get("timestamp"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Self { content, timestamp }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub cwd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_messages: Option<usize>,
    /// Parent session ID if this session was forked from another session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<String>,

    // --- Subagent-specific fields (all optional for backward compatibility) ---
    /// Session kind: "parent", "subagent", or "subagent_fork".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_kind: Option<String>,
    /// Subagent type (e.g., "general-purpose", "explore", "plan").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subagent_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subagent_persona: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subagent_role: Option<String>,
    /// Effective context source ("new" or "resumed").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_context_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subagent_depth: Option<u32>,
    /// Whether `title` was set by a manual rename; omitted when `None`.
    /// `ClearTitle` writes `Some(false)` so a merge-style backend drops a prior pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title_is_manual: Option<bool>,
}

impl ExportedMetadata {
    pub(crate) fn from_summary(summary: &Summary) -> Self {
        Self {
            title: summary.display_title_opt(),
            cwd: summary.info.cwd.clone(),
            model_id: Some(summary.current_model_id.0.to_string()),
            created_at: Some(summary.created_at.to_rfc3339()),
            updated_at: Some(summary.updated_at.to_rfc3339()),
            total_messages: Some(summary.num_messages),
            parent_session_id: summary.parent_session_id.clone(),
            session_kind: None,
            subagent_type: None,
            subagent_persona: None,
            subagent_role: None,
            fork_context_source: None,
            subagent_depth: None,
            title_is_manual: summary.manual_title_opt().is_some().then_some(true),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedSession {
    pub session_id: String,
    pub messages: Vec<ExportedMessage>,
    pub metadata: ExportedMetadata,
}

impl ExportedSession {
    pub(crate) fn from_persisted_data(info: &Info, data: &PersistedData) -> Self {
        let messages = Self::convert_updates(&data.updates);
        let metadata = ExportedMetadata::from_summary(&data.summary);

        Self {
            session_id: info.id.to_string(),
            messages,
            metadata,
        }
    }

    pub(crate) async fn from_local_session(info: &Info) -> std::io::Result<Self> {
        let storage = JsonlStorageAdapter::new();
        let data = storage.load_session(info).await?;
        Ok(Self::from_persisted_data(info, &data))
    }

    fn convert_updates(updates: &[SessionUpdate]) -> Vec<ExportedMessage> {
        updates
            .iter()
            .map(|update| match update {
                SessionUpdate::Acp(notification) => {
                    ExportedMessage::from_notification(notification)
                }
                SessionUpdate::Fuigo(notification) => {
                    ExportedMessage::from_fuigo_notification(notification)
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod from_summary_tests {
    use super::*;
    use crate::session::info::Info;
    use crate::session::persistence::Summary;

    #[test]
    fn from_summary_title_uses_display_title_not_stale_session_summary() {
        let info = Info {
            id: acp::SessionId::new("export-title"),
            cwd: "/tmp".into(),
        };
        let mut summary = Summary::new(&info, acp::ModelId::new("test-model")).unwrap();
        summary.session_summary = "stale auto title".into();
        summary.generated_title = Some("Manual rename".into());
        summary.title_is_manual = true;

        let meta = ExportedMetadata::from_summary(&summary);
        assert_eq!(
            meta.title.as_deref(),
            Some("Manual rename"),
            "export title must follow display_title() (generated_title), not session_summary"
        );
    }

    #[test]
    fn from_summary_auto_generated_title_wins_over_session_summary() {
        let info = Info {
            id: acp::SessionId::new("export-auto"),
            cwd: "/tmp".into(),
        };
        let mut summary = Summary::new(&info, acp::ModelId::new("test-model")).unwrap();
        summary.session_summary = "first prompt fallback".into();
        summary.generated_title = Some("Auto".into());
        summary.title_is_manual = false;
        assert_eq!(
            ExportedMetadata::from_summary(&summary).title.as_deref(),
            Some("Auto")
        );
    }

    #[test]
    fn from_summary_falls_back_to_session_summary_when_generated_absent() {
        let info = Info {
            id: acp::SessionId::new("export-fallback"),
            cwd: "/tmp".into(),
        };
        let mut summary = Summary::new(&info, acp::ModelId::new("test-model")).unwrap();
        summary.session_summary = "fallback".into();
        summary.generated_title = None;
        assert_eq!(
            ExportedMetadata::from_summary(&summary).title.as_deref(),
            Some("fallback")
        );
    }

    #[test]
    fn from_summary_blank_titles_export_none() {
        let info = Info {
            id: acp::SessionId::new("export-blank"),
            cwd: "/tmp".into(),
        };
        let mut summary = Summary::new(&info, acp::ModelId::new("test-model")).unwrap();
        summary.session_summary = "  ".into();
        summary.generated_title = Some("".into());
        assert_eq!(ExportedMetadata::from_summary(&summary).title, None);
    }

    #[test]
    fn from_summary_title_is_manual_true_when_manual() {
        let info = Info {
            id: acp::SessionId::new("export-manual-flag"),
            cwd: "/tmp".into(),
        };
        let mut summary = Summary::new(&info, acp::ModelId::new("test-model")).unwrap();
        summary.generated_title = Some("Pinned".into());
        summary.title_is_manual = true;
        assert_eq!(
            ExportedMetadata::from_summary(&summary).title_is_manual,
            Some(true)
        );
    }

    #[test]
    fn from_summary_omits_stale_manual_flag_over_blank_generated_title() {
        let info = Info {
            id: acp::SessionId::new("export-stale-flag"),
            cwd: "/tmp".into(),
        };
        let mut summary = Summary::new(&info, acp::ModelId::new("test-model")).unwrap();
        summary.session_summary = "auto first-prompt summary".into();
        summary.generated_title = Some("   ".into());
        summary.title_is_manual = true;
        let meta = ExportedMetadata::from_summary(&summary);
        assert!(
            summary.manual_title_opt().is_none(),
            "local contract: stale flag is not a manual title"
        );
        assert_eq!(
            meta.title_is_manual, None,
            "stale flag must not be exported"
        );
        assert_eq!(
            meta.title.as_deref(),
            Some("auto first-prompt summary"),
            "display fallback still exports as title text"
        );
    }

    #[test]
    fn title_is_manual_omitted_when_false_or_none() {
        let info = Info {
            id: acp::SessionId::new("export-flag-omit"),
            cwd: "/tmp".into(),
        };
        let mut summary = Summary::new(&info, acp::ModelId::new("test-model")).unwrap();
        summary.generated_title = Some("Auto".into());
        summary.title_is_manual = false;
        let meta = ExportedMetadata::from_summary(&summary);
        assert_eq!(meta.title_is_manual, None);
        let json = serde_json::to_value(&meta).unwrap();
        assert!(
            json.get("title_is_manual").is_none(),
            "false/None must omit the field for wire stability: {json}"
        );

        let mut none_flag = meta.clone();
        none_flag.title_is_manual = None;
        let json_none = serde_json::to_value(&none_flag).unwrap();
        assert!(json_none.get("title_is_manual").is_none());

        let mut explicit_false = meta;
        explicit_false.title_is_manual = Some(false);
        let json_false = serde_json::to_value(&explicit_false).unwrap();
        assert_eq!(
            json_false.get("title_is_manual"),
            Some(&serde_json::json!(false))
        );
    }

    #[test]
    fn title_is_manual_round_trips_when_true() {
        let meta = ExportedMetadata {
            title: Some("Pinned".into()),
            cwd: "/tmp".into(),
            model_id: None,
            created_at: None,
            updated_at: None,
            total_messages: None,
            parent_session_id: None,
            session_kind: None,
            subagent_type: None,
            subagent_persona: None,
            subagent_role: None,
            fork_context_source: None,
            subagent_depth: None,
            title_is_manual: Some(true),
        };
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["title_is_manual"], true);
        let back: ExportedMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(back.title_is_manual, Some(true));
        assert_eq!(back.title.as_deref(), Some("Pinned"));
    }
}

#[cfg(test)]
pub(crate) mod checkpoint_upload_tests {
    use super::*;
    use crate::extensions::notification as n;

    pub(crate) fn marker_and_file(id: &str, text: &str) -> (n::SessionNotification, n::CompactionCheckpointFile) {
        let marker = n::SessionNotification {
            session_id: acp::SessionId::new("s"),
            update: n::SessionUpdate::CompactionCheckpoint(Box::new(n::CompactionCheckpointInfo {
                checkpoint_id: id.into(),
                prompt_index_at_compaction: 1,
                checkpoint_file: format!("compaction_checkpoints/{id}.json"),
                auto_continue: None,
                schema_version: 1,
                created_at: "2026-10-04T00:00:00Z".into(),
            })),
            meta: None,
        };
        let file = n::CompactionCheckpointFile {
            inherited_prefix_len: None,
            checkpoint_id: id.into(),
            prompt_index_at_compaction: 1,
            compacted_history: vec![crate::sampling::ConversationItem::user(text)],
            schema_version: 1,
            created_at: "2026-10-04T00:00:00Z".into(),
            original_user_info: None,
            reread_file_paths: vec![],
        };
        (marker, file)
    }

    #[test]
    fn checkpoint_message_uses_a_method_old_clients_do_not_replay() {
        let (marker, file) = marker_and_file("cp-1", "SUMMARY");
        let msg = ExportedMessage::compaction_checkpoint(&marker, &file).expect("small checkpoint is uploaded");
        let v: serde_json::Value = serde_json::from_str(&msg.content).unwrap();
        let method = v["method"].as_str().unwrap();
        assert_eq!(method, COMPACTION_CHECKPOINT_METHOD);
        assert!(!["session/update", "_fuigo/session/update"].contains(&method));
        assert!(msg.content.contains("SUMMARY"));
    }

    #[test]
    fn oversized_checkpoint_is_not_uploaded() {
        let (marker, file) = marker_and_file("cp-big", &"x".repeat(MAX_CHECKPOINT_UPLOAD_BYTES + 1));
        assert!(ExportedMessage::compaction_checkpoint(&marker, &file).is_none());
    }
}
