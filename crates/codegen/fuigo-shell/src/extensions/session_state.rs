//! `fuigo/session/state` reads a session's metadata columns.
//! `fuigo/session/import` writes them, with the transcript, to recreate a session on another host.

use std::path::{Path, PathBuf};

use agent_client_protocol as acp;
use serde::Deserialize;
use serde_json::{Value, json};

use super::ExtResult;
use crate::session::persistence::Summary;
use crate::session::storage as st;

/// The summary column, required to load a session.
const SUMMARY_COLUMN: &str = "summary";

/// Logical column name to its file under the session directory.
/// Paths come from the storage layer so import and load never disagree about the on-disk layout.
/// `summary` is last so import writes it last, as the commit marker; keep it there.
const COLUMNS: &[(&str, &str)] = &[
    ("plan", st::PLAN_FILE),
    ("planMode", st::PLAN_MODE_FILE),
    ("signals", st::SIGNALS_FILE),
    ("usage", st::USAGE_FILE),
    ("goal", st::GOAL_STATE_FILE),
    ("announcement", st::ANNOUNCEMENT_STATE_FILE),
    (SUMMARY_COLUMN, st::SUMMARY_FILE),
];

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateRequest {
    session_id: String,
    cwd: String,
}

/// A session id is a UUID (see acp_agent's new_session); requiring that keeps it safe to join into a filesystem path.
fn validate_session_uuid(session_id: &str) -> Result<(), acp::Error> {
    uuid::Uuid::try_parse(session_id)
        .map(|_| ())
        .map_err(|_| crate::acp_error::invalid_params("sessionId must be a UUID"))
}

/// `fuigo/session/state`: return metadata columns keyed by logical name.
/// Errors when the session isn't found on this host; a single record's absence is an error, unlike the empty collection `fuigo/session/updates` returns.
pub(crate) async fn handle_state(args: &acp::ExtRequest) -> ExtResult {
    let request: StateRequest = super::parse_params(args)?;
    validate_session_uuid(&request.session_id)?;

    let Some(dir) = resolve_session_dir(&request.session_id, &request.cwd) else {
        return Err(crate::acp_error::invalid_params("session not found"));
    };
    let mut state = serde_json::Map::new();
    for (column, rel) in COLUMNS {
        if let Ok(text) = std::fs::read_to_string(dir.join(rel))
            && let Ok(value) = serde_json::from_str::<Value>(&text)
        {
            state.insert((*column).to_string(), value);
        }
    }
    super::to_raw_response(&state)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportRequest {
    session_id: String,
    cwd: String,
    #[serde(default)]
    state: std::collections::HashMap<String, Value>,
    /// One JSON object per `updates.jsonl` line, not pre-serialized strings.
    #[serde(default)]
    updates: Vec<Value>,
}

/// `fuigo/session/import`: recreate a session on this host from mirrored columns and transcript.
/// A session that already exists locally is left unchanged.
pub(crate) async fn handle_import(args: &acp::ExtRequest) -> ExtResult {
    let mut request: ImportRequest = super::parse_params(args)?;
    validate_session_uuid(&request.session_id)?;

    let info = crate::session::info::Info {
        id: acp::SessionId::new(request.session_id.clone()),
        cwd: request.cwd.clone(),
    };
    let dir = crate::session::persistence::session_dir(&info);

    // resolve_session_dir requires summary.json to count a session as present
    // An interrupted import (dir created, summary not yet written) is therefore recreated on retry rather than skipped forever
    let has_local_session = resolve_session_dir(&request.session_id, &request.cwd).is_some();
    if !has_local_session {
        let Some(summary_value) = request.state.get_mut(SUMMARY_COLUMN) else {
            return Err(crate::acp_error::invalid_params(
                "session/import requires a summary column",
            ));
        };
        let Some(summary) = summary_value.as_object_mut() else {
            return Err(crate::acp_error::invalid_params(
                "session/import summary must be an object",
            ));
        };
        sanitize_summary_for_host(summary, &request.session_id, &request.cwd);
        // Reject a summary that would not load rather than persist one that makes the session unloadable and blocks re-import
        if Summary::deserialize(&*summary_value).is_err() {
            return Err(crate::acp_error::invalid_params(
                "summary column is not a valid summary",
            ));
        }
        // Write the `.cwd` sidecar for hash-based (long-path) dirs so the session stays recoverable by id, not just by (id, cwd)
        crate::util::fuigo_home::ensure_sessions_cwd_dir(&request.cwd)
            .map_err(|e| crate::acp_error::internal_error(e.to_string()))?;
        // F5 (design §5.5): the import claims the id without waiting and writes only through that writer. Open in this
        // process: `This session is open...`; open in another: `held elsewhere`. Either way nothing is written.
        let writer = crate::session::session_writer_lock::try_claim_writer(&request.session_id, dir.clone())?;
        match write_import(&writer, &request.state, &request.updates, &request.session_id) {
            Ok(()) => {}
            // Made meanwhile: 1.0.40's answer for a session that exists, nothing written.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && fuigo_session_writer::refusal(&e).is_none() => {
                return super::to_raw_response(&json!({ "imported": false }));
            }
            Err(e) => {
                return Err(match fuigo_session_writer::refusal(&e) {
                    Some(fuigo_session_writer::Refusal::HeldElsewhere) => {
                        crate::session::session_writer_lock::held_elsewhere_error()
                    }
                    _ => crate::acp_error::internal_error(e.to_string()),
                });
            }
        }
    }
    super::to_raw_response(&json!({ "imported": !has_local_session }))
}

/// Rewrite a mirrored summary's host-specific fields to describe this host.
fn sanitize_summary_for_host(summary: &mut serde_json::Map<String, Value>, id: &str, cwd: &str) {
    if let Some(info_obj) = summary.get_mut("info").and_then(Value::as_object_mut) {
        info_obj.insert("id".to_string(), Value::String(id.to_string()));
        info_obj.insert("cwd".to_string(), Value::String(cwd.to_string()));
    }
    summary.insert(
        "chat_format_version".to_string(),
        json!(crate::session::persistence::CHAT_FORMAT_VERSION),
    );
    summary.insert("git_remotes".to_string(), json!([]));
    for field in [
        "prompt_display_cwd",
        "source_workspace_dir",
        "git_root_dir",
        "head_commit",
        "head_branch",
        "worktree_label",
        "request_id",
    ] {
        summary.remove(field);
    }
    set_or_remove(
        summary,
        "fuigo_home",
        crate::session::persistence::fuigo_home_string(),
    );
    set_or_remove(
        summary,
        "sandbox_profile",
        fuigo_sandbox::configured_profile_name().map(String::from),
    );
}

fn set_or_remove(obj: &mut serde_json::Map<String, Value>, key: &str, value: Option<String>) {
    match value {
        Some(v) => {
            obj.insert(key.to_string(), Value::String(v));
        }
        None => {
            obj.remove(key);
        }
    }
}

/// Writes summary.json last, and each file to a temporary name first.
/// An interrupted import therefore leaves an incomplete session that load treats as absent.
/// F5 (design §5.3): every write is a method of the import's writer; the clears are its `remove`s. The folder may
/// already exist (a failed earlier import), so the writer makes it owner-only too, not only when it creates it.
fn write_import(
    writer: &fuigo_session_writer::SessionWriter,
    state: &std::collections::HashMap<String, Value>,
    updates: &[Value],
    session_id: &str,
) -> std::io::Result<()> {
    writer.ensure_folder_owner_only_sync()?;
    // The writer now holds the id (design F5 §9.4 B6): a session made after the caller's existence check (and closed before
    // the claim) is seen here, before anything of it is removed, and left unchanged as the check would have left it.
    if writer.dir().join(st::SUMMARY_FILE).exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "the session exists"));
    }

    // Clear every file this import owns so a leftover from a failed attempt can't merge with the new snapshot; this import is authoritative
    let _ = writer.remove_sync(st::CHAT_HISTORY_FILE);
    let _ = writer.remove_sync(st::UPDATES_FILE);
    for (_, rel) in COLUMNS {
        let _ = writer.remove_sync(rel);
    }

    if !updates.is_empty() {
        writer.replace_atomic_sync(st::UPDATES_FILE, &st::to_jsonl_bytes(updates)?)?;
    }

    for (column, rel) in COLUMNS {
        if let Some(value) = state.get(*column) {
            write_column(writer, rel, value)?;
        }
    }
    restamp_imported_usage(writer, session_id)?;
    Ok(())
}

fn restamp_imported_usage(writer: &fuigo_session_writer::SessionWriter, session_id: &str) -> std::io::Result<()> {
    let path = writer.dir().join(st::USAGE_FILE);
    let data = match std::fs::read(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let Ok(mut file) =
        serde_json::from_slice::<crate::session::usage_file::SessionUsageFile>(&data)
    else {
        return Ok(());
    };
    file.session_id = session_id.to_string();
    writer.replace_atomic_sync(
        st::USAGE_FILE,
        &serde_json::to_vec_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
    )
}

/// The writer creates `rel`'s parent directories (e.g. `goal/`) owner-only.
fn write_column(writer: &fuigo_session_writer::SessionWriter, rel: &str, value: &Value) -> std::io::Result<()> {
    writer.replace_atomic_sync(rel, value.to_string().as_bytes())
}

/// The session's directory, or `None` when it isn't found on this host.
/// Falls back to an id scan when `(id, cwd)` has no summary (subagents use their own cwd).
/// Both branches require summary.json so a bare directory doesn't count as present.
fn resolve_session_dir(session_id: &str, cwd: &str) -> Option<PathBuf> {
    let info = crate::session::info::Info {
        id: acp::SessionId::new(session_id.to_string()),
        cwd: cwd.to_string(),
    };
    let dir = crate::session::persistence::session_dir(&info);
    if dir.join(st::SUMMARY_FILE).is_file() {
        return Some(dir);
    }
    crate::session::persistence::find_session_dir_by_id(session_id)
        .filter(|found| found.join(st::SUMMARY_FILE).is_file())
}

#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[cfg(test)]
mod tests {
    /// A writer for `dir` under a fresh id (the import writes only through one).
    fn test_writer(dir: &std::path::Path) -> fuigo_session_writer::SessionWriter {
        fuigo_session_writer::SessionWriter::try_claim(uuid::Uuid::now_v7().to_string(), dir).expect("claim")
    }
    use super::*;
    use serde_json::json;

    #[test]
    fn sanitize_summary_for_host_rewrites_host_fields() {
        let mut summary = json!({
            "info": { "id": "s1", "cwd": "/remote/host/work" },
            "chat_format_version": 0,
            "prompt_display_cwd": "/remote/host/work",
            "source_workspace_dir": "/remote/host",
            "git_root_dir": "/remote/host/repo",
            "git_remotes": ["origin"],
            "head_commit": "deadbeef",
            "head_branch": "feature",
            "worktree_label": "wt",
            "request_id": "req-1",
        })
        .as_object()
        .unwrap()
        .clone();

        sanitize_summary_for_host(&mut summary, "s-new", "/local/work");

        assert_eq!(summary["info"]["id"], json!("s-new"));
        assert_eq!(summary["info"]["cwd"], json!("/local/work"));
        assert_eq!(
            summary["chat_format_version"],
            json!(crate::session::persistence::CHAT_FORMAT_VERSION)
        );
        assert_eq!(summary["git_remotes"], json!([]));
        for gone in [
            "prompt_display_cwd",
            "source_workspace_dir",
            "git_root_dir",
            "head_commit",
            "head_branch",
            "worktree_label",
            "request_id",
        ] {
            assert!(!summary.contains_key(gone), "{gone} should be dropped");
        }
    }

    #[test]
    fn write_import_writes_columns_updates_and_drops_stale_chat() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join("chat_history.jsonl"), b"stale cache").unwrap();
        // A column left by a failed prior import that the new payload omits.
        std::fs::write(dir.join("signals.json"), b"{\"stale\":true}").unwrap();

        let mut state = std::collections::HashMap::new();
        state.insert(
            "summary".to_string(),
            json!({ "info": { "id": "s1", "cwd": "/work" } }),
        );
        state.insert("plan".to_string(), json!({ "items": [] }));
        state.insert("goal".to_string(), json!({ "active": false }));
        let updates = vec![
            json!({ "method": "session/update", "params": { "a": 1 } }),
            json!({ "method": "session/update", "params": { "b": 2 } }),
        ];

        write_import(&test_writer(dir), &state, &updates, "s1").unwrap();

        #[cfg(unix)]
        assert_eq!(
            crate::test_support::unix_mode(dir),
            0o700,
            "imported session dir must be owner-only"
        );
        assert!(dir.join("summary.json").exists(), "summary.json written");
        assert_eq!(
            std::fs::read_to_string(dir.join("plan.json")).unwrap(),
            r#"{"items":[]}"#
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("goal/state.json")).unwrap(),
            r#"{"active":false}"#
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("updates.jsonl"))
                .unwrap()
                .lines()
                .count(),
            2
        );
        assert!(
            !dir.join("chat_history.jsonl").exists(),
            "stale chat cache dropped so load rebuilds"
        );
        assert!(
            !dir.join("signals.json").exists(),
            "orphan column from a failed import dropped"
        );
    }

    /// design F5 §9.4 B6: a session made after the import's existence check is seen under the import's writer, before
    /// anything is removed, and left byte-identical.
    #[test]
    fn write_import_leaves_a_session_made_after_the_check_unchanged() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join("summary.json"), b"{\"racer\":1}").unwrap();
        std::fs::write(dir.join("chat_history.jsonl"), b"racer chat").unwrap();
        std::fs::write(dir.join("updates.jsonl"), b"racer updates").unwrap();
        let mut state = std::collections::HashMap::new();
        state.insert("summary".to_string(), json!({ "info": { "id": "s1", "cwd": "/work" } }));
        let updates = vec![json!({ "method": "session/update", "params": { "a": 1 } })];

        let error = write_import(&test_writer(dir), &state, &updates, "s1").unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(dir.join("summary.json")).unwrap(), b"{\"racer\":1}");
        assert_eq!(std::fs::read(dir.join("chat_history.jsonl")).unwrap(), b"racer chat");
        assert_eq!(std::fs::read(dir.join("updates.jsonl")).unwrap(), b"racer updates");
    }

    #[test]
    fn write_import_restamps_usage_session_id() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        let mut state = std::collections::HashMap::new();
        state.insert(
            "summary".to_string(),
            json!({ "info": { "id": "imported-id", "cwd": "/work" } }),
        );
        state.insert(
            "usage".to_string(),
            json!({
                "sessionId": "source-id",
                "session": { "inputTokens": 10, "turnCount": 1 },
                "turns": [{ "turnNumber": 1, "inputTokens": 10 }]
            }),
        );
        write_import(&test_writer(dir), &state, &[], "imported-id").unwrap();
        let usage: crate::session::usage_file::SessionUsageFile =
            serde_json::from_slice(&std::fs::read(dir.join("usage.json")).unwrap()).unwrap();
        assert_eq!(usage.session_id, "imported-id");
        assert_eq!(usage.session.input_tokens, 10);
    }
}
