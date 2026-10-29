//! Forks a saved session to a new working directory with a new session ID.
//! This creates new session files but does not start the session.

use crate::remote::BackendClient;
const FORK_LOG: &str = "fuigo_fork";
use crate::session::export::ExportedMetadata;
use crate::session::info::Info;
use crate::session::storage::{CopySessionOptions, JsonlStorageAdapter};
use crate::util::fuigo_home::fuigo_home;
use agent_client_protocol as acp;
use std::io;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkSessionRequest {
    pub source_session_id: String,
    pub source_cwd: String,
    pub new_cwd: String,
    /// If None, a new ID will be auto-generated.
    #[serde(default)]
    pub new_session_id: Option<String>,
    /// If None, the source session's model will be used.
    #[serde(default)]
    pub new_model_id: Option<String>,
    #[serde(default)]
    pub target_prompt_index: Option<usize>,
    /// Override `session_kind` in the forked summary. Defaults to `"fork"`.
    /// Worktree forks set this to `"worktree"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_kind: Option<String>,
    /// The original workspace directory this worktree session was spawned from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_workspace_dir: Option<String>,
    /// The request's `_meta` (1.0.36 item a: the launch policy key and hash a governed source requires).
    #[serde(default, rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkSessionResponse {
    pub new_session_id: String,
    pub chat_messages_copied: usize,
    pub updates_copied: usize,
    pub plan_state_copied: bool,
    pub new_cwd: String,
    pub parent_session_id: String,
    /// The model ID of the forked session (may differ from source if overridden)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_model_id: Option<String>,
    /// Response `_meta`: set only for a fork a launch policy governs (1.0.36 item a ack).
    #[serde(default, rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
    /// The source summary's launch policy marker, read with the copy (never serialized).
    #[serde(skip)]
    pub source_permission_policy: Option<fuigo_workspace::permission::launch_policy::PolicyBinding>,
    /// 1.0.36 item a: the launch policy the fork runs under (its id is bound to it before the copy); never serialized.
    #[serde(skip)]
    pub launch_policy: Option<std::sync::Arc<fuigo_workspace::permission::launch_policy::LaunchPolicy>>,
}

/// The [`PolicyError`](fuigo_workspace::permission::launch_policy::PolicyError) a fork was refused with, if that is why
/// [`fork_session`] failed.
pub fn fork_policy_error(
    err: &io::Error,
) -> Option<&fuigo_workspace::permission::launch_policy::PolicyError> {
    err.get_ref()?.downcast_ref()
}

/// 1.0.36 item a, before anything is copied: a source bound in this process or carrying the stored marker forks only with
/// a claim naming that policy, and the new id is bound to it first. A refusal leaves no copy.
fn resolve_fork_policy(
    storage: &JsonlStorageAdapter,
    source_info: &Info,
    new_session_id: &str,
    meta: Option<&serde_json::Map<String, serde_json::Value>>,
) -> io::Result<Option<std::sync::Arc<fuigo_workspace::permission::launch_policy::LaunchPolicy>>> {
    use fuigo_workspace::permission::launch_policy;
    let claim = launch_policy::SessionPolicyClaim::from_meta(meta).map_err(io::Error::other)?;
    // A source whose summary cannot be read is left to the copy, which reports it.
    let marker = storage.read_summary_sync(source_info).ok().and_then(|summary| summary.permission_policy);
    let policy = launch_policy::resolve_session_claim(&claim, Some(source_info.id.0.as_ref()), marker.as_ref())
        .map_err(io::Error::other)?;
    if let Some(policy) = &policy {
        launch_policy::bind_session(new_session_id, policy.binding()).map_err(io::Error::other)?;
    }
    Ok(policy)
}

/// 1.0.36 item a, after a fork: store the policy marker on the new id when the copied summary does not already carry this
/// binding, and return the response's `_meta` ack (`None` for an ungoverned fork with no process policy).
pub async fn finish_fork_policy(response: &ForkSessionResponse) -> io::Result<Option<serde_json::Value>> {
    use fuigo_workspace::permission::launch_policy;
    if let Some(policy) = &response.launch_policy {
        let binding = policy.binding();
        if response.source_permission_policy.as_ref() != Some(&binding) {
            let info = Info {
                id: acp::SessionId::new(response.new_session_id.clone()),
                cwd: response.new_cwd.clone(),
            };
            crate::session::persistence::write_permission_policy_marker(&info, binding).await?;
        }
    }
    Ok(launch_policy::session_ack(response.launch_policy.as_ref().map(|p| p.sha256.as_str()))
        .map(|ack| serde_json::json!({ launch_policy::META_ACK: ack })))
}

/// Uses a plain UUIDv7 with no prefix or source embedding, so IDs stay a constant 36 chars no matter how many fork rounds occur.
fn generate_fork_session_id(_source_id: &str) -> String {
    uuid::Uuid::now_v7().to_string()
}

pub async fn fork_session(
    request: ForkSessionRequest,
    agent_id: &str,
    auth_manager: Option<std::sync::Arc<crate::auth::AuthManager>>,
) -> io::Result<ForkSessionResponse> {
    let t0 = std::time::Instant::now();

    let root_dir = fuigo_home();
    let storage = JsonlStorageAdapter::with_root(root_dir.clone());

    // Build source and target Info
    let source_info = Info {
        id: acp::SessionId::new(request.source_session_id.clone()),
        cwd: request.source_cwd.clone(),
    };

    let new_session_id = request
        .new_session_id
        .clone()
        .unwrap_or_else(|| generate_fork_session_id(&request.source_session_id));

    let target_info = Info {
        id: acp::SessionId::new(new_session_id.clone()),
        cwd: request.new_cwd.clone(),
    };

    // Copy session data with parent tracking.
    // Runs on the blocking thread pool so concurrent fork copies can execute truly in parallel
    // On a LocalSet, async copy_session_data serializes because the sync disk I/O blocks the single-threaded runtime
    let options = CopySessionOptions {
        parent_session_id: Some(request.source_session_id.clone()),
        new_model_id: request.new_model_id.clone(),
        target_prompt_index: request.target_prompt_index,
        session_kind: request.session_kind.clone(),
        source_workspace_dir: request.source_workspace_dir.clone(),
        // Carry the parent's compaction segment archive into the fork so the child retains pre-compaction history
        // The live summary is already copied via chat_history.jsonl
        copy_compaction_segments: true,
        ..Default::default()
    };

    let meta = request.meta.clone();
    let (result, launch_policy) = tokio::task::spawn_blocking(move || {
        let launch_policy =
            resolve_fork_policy(&storage, &source_info, &target_info.id.0, meta.as_ref())?;
        storage
            .copy_session_data_sync(&source_info, &target_info, options)
            .map(|result| (result, launch_policy))
    })
    .await
    .map_err(|e| io::Error::other(format!("spawn_blocking panicked: {e}")))??;

    // S6.1: the peer-influenced state is stored IN the copied transcript (item kinds), so the fork inherits it.

    let copy_ms = t0.elapsed().as_millis() as u64;

    // Register the fork with the backend from a spawned task
    // The local fork works without it: all fork state is in session files on disk, and the backend learns of the session when the task completes
    // Spawning keeps the network round-trip (~200-400ms) off the critical path
    if let Some(am) = auth_manager {
        let sid = new_session_id.clone();
        let cwd = request.new_cwd.clone();
        let parent = request.source_session_id.clone();
        let model = request.new_model_id.clone();
        let aid = agent_id.to_string();
        tokio::spawn(async move {
            if let Err(e) =
                sync_forked_session_to_backend(&sid, &cwd, parent, model, &aid, am).await
            {
                tracing::warn!(
                    session_id = %sid,
                    error = %e,
                    "Failed to register forked session with backend (background)"
                );
            }
        });
    }

    let total_ms = t0.elapsed().as_millis() as u64;
    tracing::info!(
        target: FORK_LOG,
        session_id = %new_session_id,
        source_session = %request.source_session_id,
        copy_ms,
        total_ms,
        chat_copied = result.chat_messages_copied,
        updates_copied = result.updates_copied,
        "FORK_COPY: session data copied (backend sync spawned in background)"
    );

    Ok(ForkSessionResponse {
        new_session_id,
        chat_messages_copied: result.chat_messages_copied,
        updates_copied: result.updates_copied,
        plan_state_copied: result.plan_state_copied,
        new_cwd: request.new_cwd,
        parent_session_id: request.source_session_id,
        new_model_id: request.new_model_id,
        meta: None,
        source_permission_policy: result.source_permission_policy,
        launch_policy,
    })
}

/// Sync a forked session to the backend (for writeback mode).
async fn sync_forked_session_to_backend(
    session_id: &str,
    cwd: &str,
    parent_session_id: String,
    model_id: Option<String>,
    agent_id: &str,
    auth_manager: std::sync::Arc<crate::auth::AuthManager>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = BackendClient::new().with_auth_manager(auth_manager);
    let metadata = ExportedMetadata {
        title: None, // The title is generated later when the session runs
        cwd: cwd.to_string(),
        model_id,
        created_at: Some(chrono::Utc::now().to_rfc3339()),
        updated_at: Some(chrono::Utc::now().to_rfc3339()),
        total_messages: Some(0),
        parent_session_id: Some(parent_session_id),
        session_kind: None,
        subagent_type: None,
        subagent_persona: None,
        subagent_role: None,
        fork_context_source: None,
        subagent_depth: None,
        title_is_manual: None,
    };

    client
        .upsert_session(session_id, &metadata, agent_id)
        .await?;
    tracing::info!(
        session_id = %session_id,
        "Forked session registered with backend"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_fork_session_id_format() {
        let fork_id = generate_fork_session_id("abc123");

        assert_eq!(
            fork_id.len(),
            36,
            "Fork ID should be a standard UUID length"
        );
        assert!(
            uuid::Uuid::parse_str(&fork_id).is_ok(),
            "Fork ID should be a valid UUID"
        );
    }

    #[test]
    fn test_generate_fork_session_id_uniqueness() {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..100 {
            let fork_id = generate_fork_session_id("any-source");
            assert_eq!(fork_id.len(), 36);
            ids.insert(fork_id);
        }

        assert_eq!(ids.len(), 100, "All generated IDs should be unique");
    }

    #[test]
    fn test_generate_fork_session_id_constant_length() {
        let id1 = generate_fork_session_id("019c43b5-c4ae-7190-b058-693e24669ba9");
        let id2 = generate_fork_session_id(&id1);
        let id3 = generate_fork_session_id(&id2);

        assert_eq!(id1.len(), 36);
        assert_eq!(id2.len(), 36);
        assert_eq!(id3.len(), 36);
    }

    #[test]
    fn test_fork_session_request_serialization() {
        let request = ForkSessionRequest {
            source_session_id: "abc123".to_string(),
            source_cwd: "/old/project".to_string(),
            new_cwd: "/new/project".to_string(),
            new_session_id: Some("custom-session-id".to_string()),
            new_model_id: Some("grok-3".to_string()),
            target_prompt_index: None,
            ..Default::default()
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: ForkSessionRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.source_session_id, "abc123");
        assert_eq!(deserialized.source_cwd, "/old/project");
        assert_eq!(deserialized.new_cwd, "/new/project");
        assert_eq!(
            deserialized.new_session_id,
            Some("custom-session-id".to_string())
        );
        assert_eq!(deserialized.new_model_id, Some("grok-3".to_string()));
    }

    #[test]
    fn test_fork_session_request_without_optional_fields() {
        let json = r#"{"sourceSessionId":"abc123","sourceCwd":"/old","newCwd":"/new"}"#;
        let deserialized: ForkSessionRequest = serde_json::from_str(json).unwrap();

        assert_eq!(deserialized.source_session_id, "abc123");
        assert_eq!(deserialized.new_session_id, None);
        assert_eq!(deserialized.new_model_id, None);
    }

    #[test]
    fn test_fork_session_response_serialization() {
        let response = ForkSessionResponse {
            new_session_id: "fork-abc123-12345678".to_string(),
            chat_messages_copied: 42,
            updates_copied: 156,
            plan_state_copied: true,
            new_cwd: "/new/project".to_string(),
            parent_session_id: "abc123".to_string(),
            new_model_id: Some("grok-3".to_string()),
            meta: None,
            source_permission_policy: None,
            launch_policy: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ForkSessionResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.new_session_id, "fork-abc123-12345678");
        assert_eq!(deserialized.chat_messages_copied, 42);
        assert_eq!(deserialized.updates_copied, 156);
        assert!(deserialized.plan_state_copied);
        assert_eq!(deserialized.new_cwd, "/new/project");
        assert_eq!(deserialized.parent_session_id, "abc123");
        assert_eq!(deserialized.new_model_id, Some("grok-3".to_string()));
    }

    #[test]
    fn test_fork_session_response_without_model_override() {
        let response = ForkSessionResponse {
            new_session_id: "fork-abc123-12345678".to_string(),
            chat_messages_copied: 42,
            updates_copied: 156,
            plan_state_copied: true,
            new_cwd: "/new/project".to_string(),
            parent_session_id: "abc123".to_string(),
            new_model_id: None,
            meta: None,
            source_permission_policy: None,
            launch_policy: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("new_model_id"));
    }

    #[tokio::test]
    async fn fork_request_kind_materializes_on_child() {
        use crate::session::persistence::default_model_id;
        use crate::session::storage::StorageAdapter;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let adapter = JsonlStorageAdapter::with_root(tmp.path().to_path_buf());
        let source = Info {
            id: acp::SessionId::new("parent-kind"),
            cwd: "/src".to_string(),
        };
        adapter
            .init_session(&source, default_model_id())
            .await
            .unwrap();

        for (wire, expected) in [
            (Some("headless"), "headless"),
            (Some("fork"), "fork"),
            (None, "fork"),
        ] {
            let mut body = serde_json::json!({
                "sourceSessionId": source.id.to_string(),
                "sourceCwd": source.cwd,
                "newCwd": "/dst",
                "newSessionId": format!("child-{expected}-{}", wire.unwrap_or("omit")),
            });
            if let Some(kind) = wire {
                body["sessionKind"] = serde_json::Value::String(kind.into());
            }
            let request: ForkSessionRequest = serde_json::from_value(body).unwrap();
            let target = Info {
                id: acp::SessionId::new(request.new_session_id.clone().unwrap()),
                cwd: request.new_cwd.clone(),
            };
            adapter
                .copy_session_data(
                    &source,
                    &target,
                    CopySessionOptions {
                        parent_session_id: Some(request.source_session_id),
                        session_kind: request.session_kind,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let loaded = adapter.load_session(&target).await.unwrap();
            assert_eq!(
                loaded.summary.session_kind.as_deref(),
                Some(expected),
                "wire sessionKind={wire:?}"
            );
        }
    }

    /// Grok r1 #1: a governed source (stored marker, or bound in this process) forks only with a claim naming its
    /// policy; a refusal comes before the copy, and an accepted fork binds the new id first.
    #[tokio::test]
    async fn a_governed_source_forks_only_with_its_claim_and_binds_the_new_id() {
        use crate::session::persistence::default_model_id;
        use crate::session::storage::StorageAdapter;
        use fuigo_workspace::permission::launch_policy;
        use tempfile::TempDir;
        let tmp = TempDir::new().unwrap();
        let adapter = JsonlStorageAdapter::with_root(tmp.path().join("home"));
        let text = "[permission]\nask = [\"Bash\"]\n";
        let policy_file = tmp.path().join("fork-policy.toml");
        std::fs::write(&policy_file, text).unwrap();
        let policy_path = policy_file.to_string_lossy().into_owned();
        let sha = launch_policy::sha256_hex(text.as_bytes());
        let binding = launch_policy::PolicyBinding { path: policy_path.clone(), sha256: sha.clone() };
        let source = Info { id: acp::SessionId::new("u36-fork-marked"), cwd: "/src".to_string() };
        adapter.init_session(&source, default_model_id()).await.unwrap();
        adapter
            .apply_summary_patch(
                &source,
                crate::session::storage::summary_write::SummaryPatch {
                    permission_policy: Some(binding.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        // No claim: refused with the policy error (machine-readable), and nothing bound.
        let err = resolve_fork_policy(&adapter, &source, "u36-fork-child-none", None).unwrap_err();
        assert_eq!(fork_policy_error(&err).map(|e| e.code), Some("session_policy_missing"));
        assert!(launch_policy::session_binding("u36-fork-child-none").is_none());
        // A non-string claim value: bad_claim.
        let bad: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({ launch_policy::META_PATH: null })).unwrap();
        let err = resolve_fork_policy(&adapter, &source, "u36-fork-child-bad", Some(&bad)).unwrap_err();
        assert_eq!(fork_policy_error(&err).map(|e| e.code), Some("bad_claim"));
        // The matching claim: accepted, and the new id is bound before anything is copied.
        let claim: serde_json::Map<String, serde_json::Value> = serde_json::from_value(
            serde_json::json!({ launch_policy::META_PATH: policy_path, launch_policy::META_SHA256: sha }),
        )
        .unwrap();
        let policy = resolve_fork_policy(&adapter, &source, "u36-fork-child", Some(&claim)).unwrap().unwrap();
        assert_eq!(policy.binding(), binding);
        assert_eq!(launch_policy::session_binding("u36-fork-child"), Some(binding.clone()));
        // A source bound only in this process (its marker gone) is still governed.
        let unmarked = Info { id: acp::SessionId::new("u36-fork-bound"), cwd: "/src".to_string() };
        adapter.init_session(&unmarked, default_model_id()).await.unwrap();
        launch_policy::bind_session("u36-fork-bound", binding).unwrap();
        let err = resolve_fork_policy(&adapter, &unmarked, "u36-fork-child-2", None).unwrap_err();
        assert_eq!(fork_policy_error(&err).map(|e| e.code), Some("session_policy_missing"));
        // An ungoverned source forks as before.
        let plain = Info { id: acp::SessionId::new("u36-fork-plain"), cwd: "/src".to_string() };
        adapter.init_session(&plain, default_model_id()).await.unwrap();
        assert!(resolve_fork_policy(&adapter, &plain, "u36-fork-child-3", None).unwrap().is_none());
    }
}
