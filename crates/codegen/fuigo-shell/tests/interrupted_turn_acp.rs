//! A turn lost with its process, end to end over ACP: a real `MvpAgent` loads or resumes a session whose
//! `events.jsonl` holds an unclosed `turn_started`, and a turn that ends in an ordinary error is not later
//! mistaken for one. One `#[test]` because the harness env is process-global; each scenario uses its own session.

#[allow(dead_code)]
mod acp_harness;

use acp_harness::{RPC_TIMEOUT, connect_and_auth, new_session, run_agent_test};
use agent_client_protocol::{self as acp, Agent as _};
use base64::Engine as _;
use fuigo_shell::session::info::Info;
use fuigo_shell::session::storage::{JsonlStorageAdapter, StorageAdapter};
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

/// Records every `turn_completed` the agent sends, with the ext method it came on.
struct Recorder(mpsc::UnboundedSender<Value>);

#[async_trait::async_trait(?Send)]
impl acp::Client for Recorder {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        Ok(acp::RequestPermissionResponse::new(
            acp_harness::allow_once(&args),
        ))
    }
    async fn session_notification(&self, _: acp::SessionNotification) -> acp::Result<()> {
        Ok(())
    }
    async fn ext_notification(&self, args: acp::ExtNotification) -> acp::Result<()> {
        if let Ok(value) = serde_json::from_str::<Value>(args.params.get())
            && value["update"]["sessionUpdate"] == "turn_completed"
        {
            let _ = self.0.send(value);
        }
        Ok(())
    }
}

fn sessions_root() -> PathBuf {
    PathBuf::from(std::env::var("FUIGO_HOME").expect("FUIGO_HOME set")).join("sessions")
}

/// The session dir; the `<cwd>` level encodes the cwd internally, so it is found by scanning.
async fn session_dir(id: &str) -> PathBuf {
    let deadline = tokio::time::Instant::now() + RPC_TIMEOUT;
    loop {
        if let Ok(entries) = std::fs::read_dir(sessions_root())
            && let Some(dir) = entries
                .filter_map(|e| Some(e.ok()?.path().join(id)))
                .find(|p| p.is_dir())
        {
            return dir;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "session dir for {id} never appeared"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

const PROMPT_ID: &str = "prompt-lost-with-its-process";

/// A session whose previous process died mid-turn: `summary` names the turn and `events.jsonl` never closed it.
async fn seed_crashed_session(cwd: &Path, id: &str) -> PathBuf {
    let info = Info {
        id: acp::SessionId::new(id),
        cwd: cwd.to_string_lossy().into_owned(),
    };
    JsonlStorageAdapter::new()
        .init_session(&info, acp::ModelId::new("test-model"))
        .await
        .expect("init session");
    let dir = session_dir(id).await;
    let summary_path = dir.join("summary.json");
    let mut summary: Value =
        serde_json::from_slice(&std::fs::read(&summary_path).expect("read summary"))
            .expect("summary");
    summary["request_id"] = Value::from(PROMPT_ID);
    summary["next_trace_turn"] = Value::from(1);
    std::fs::write(&summary_path, serde_json::to_vec_pretty(&summary).unwrap())
        .expect("write summary");
    std::fs::write(
        dir.join("events.jsonl"),
        format!(
            "{}\n",
            serde_json::json!({
                "ts": "2026-09-29T00:00:01.000Z",
                "type": "turn_started",
                "session_id": id,
                "turn_number": 0,
                "model_id": "test-model",
                "yolo_mode": false,
                "conversation_message_count": 0,
                "session_relationship": "primary",
                "schema_version": "1.0",
            })
        ),
    )
    .expect("write events");
    dir
}

fn last_turn_event(dir: &Path) -> Value {
    std::fs::read_to_string(dir.join("events.jsonl"))
        .expect("read events")
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .rfind(|v| v["type"] == "turn_started" || v["type"] == "turn_ended")
        .expect("a turn event")
}

fn interrupted_markers_on_disk(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("updates.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains(r#""stop_reason":"interrupted""#))
        .count()
}

/// The `turn_completed` for the interrupted prompt, if one arrives within a short grace period.
async fn interrupted_marker(
    rx: &mut mpsc::UnboundedReceiver<Value>,
    session: &str,
) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let value = tokio::time::timeout_at(deadline, rx.recv()).await.ok()??;
        if value["sessionId"] == session
            && value["update"]["prompt_id"] == PROMPT_ID
            && value["update"]["stop_reason"] == "interrupted"
        {
            return Some(value);
        }
    }
}

fn png_base64() -> String {
    let img: image::ImageBuffer<image::Rgb<u8>, Vec<u8>> =
        image::ImageBuffer::from_fn(32, 32, |x, y| image::Rgb([x as u8, y as u8, 0]));
    let mut png = Vec::new();
    image::DynamicImage::ImageRgb8(img)
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .expect("encode png");
    base64::engine::general_purpose::STANDARD.encode(&png)
}

#[test]
fn a_turn_lost_with_its_process_is_recorded_and_reported_once() {
    run_agent_test(|cwd, _server| async move {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (conn, _init) = connect_and_auth(Recorder(tx), "interrupted-turn-fixture").await;

        // A. session/load replays the transcript, and the marker (appended before the replay) is part of it.
        let dir = seed_crashed_session(&cwd, "crashed-load").await;
        tokio::time::timeout(
            RPC_TIMEOUT,
            conn.load_session(acp::LoadSessionRequest::new(
                acp::SessionId::new("crashed-load"),
                cwd.clone(),
            )),
        )
        .await
        .expect("load timed out")
        .expect("load failed");
        let marker = interrupted_marker(&mut rx, "crashed-load")
            .await
            .expect("load: the client sees the interrupted marker");
        assert_eq!(
            marker["_meta"]["isReplay"], true,
            "load: it arrives as replay"
        );
        assert_eq!(
            interrupted_markers_on_disk(&dir),
            1,
            "load: one durable marker"
        );
        assert_eq!(
            last_turn_event(&dir)["outcome"],
            "interrupted",
            "load: events.jsonl closed"
        );

        // B. Audit finding 7. session/resume replays nothing, so the marker must be sent live.
        // Mutant discriminated: dropping the resume forward in `load_session`.
        let dir = seed_crashed_session(&cwd, "crashed-resume").await;
        tokio::time::timeout(
            RPC_TIMEOUT,
            conn.resume_session(acp::ResumeSessionRequest::new(
                acp::SessionId::new("crashed-resume"),
                cwd.clone(),
            )),
        )
        .await
        .expect("resume timed out")
        .expect("resume failed");
        let marker = interrupted_marker(&mut rx, "crashed-resume")
            .await
            .expect("resume: the client is told the turn was lost");
        assert_ne!(
            marker["_meta"]["isReplay"], true,
            "resume: a live update, not replay"
        );
        assert_eq!(
            interrupted_markers_on_disk(&dir),
            1,
            "resume: one durable marker"
        );
        assert_eq!(
            last_turn_event(&dir)["outcome"],
            "interrupted",
            "resume: events.jsonl closed"
        );

        // C. Audit finding 2. Another process has this session live: it holds the turn-owner lock (a separate
        // open file description here, exactly as another process's would be). Its open turn is running, not lost.
        // Mutant discriminated: recovery that ignores the lock.
        let dir = seed_crashed_session(&cwd, "live-elsewhere").await;
        let events_before = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
        let other_process = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join("turn_owner.lock"))
            .expect("open lock");
        fs2::FileExt::lock_shared(&other_process).expect("hold the session live");
        tokio::time::timeout(
            RPC_TIMEOUT,
            conn.load_session(acp::LoadSessionRequest::new(
                acp::SessionId::new("live-elsewhere"),
                cwd.clone(),
            )),
        )
        .await
        .expect("load timed out")
        .expect("load failed");
        assert!(
            interrupted_marker(&mut rx, "live-elsewhere")
                .await
                .is_none(),
            "live elsewhere: no interrupted marker for a running turn"
        );
        assert_eq!(
            interrupted_markers_on_disk(&dir),
            0,
            "live elsewhere: nothing persisted"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("events.jsonl")).unwrap(),
            events_before,
            "live elsewhere: the running turn's log is untouched"
        );
        drop(other_process);

        // D. Audit finding 6. A turn whose images cannot be saved returns its error before the common outcome
        // handling; it must still close its `turn_started`, or a later load calls it a crash.
        // Mutant discriminated: `handle_turn_input` without `close_open_turn` on its error path.
        let session = new_session(&conn, &cwd).await;
        let dir = session_dir(&session.0).await;
        std::fs::write(dir.join("assets"), b"not a directory").expect("block the assets dir");
        let result = tokio::time::timeout(
            RPC_TIMEOUT,
            conn.prompt(acp::PromptRequest::new(
                session.clone(),
                vec![
                    acp::ContentBlock::Text(acp::TextContent::new("what is this?".to_owned())),
                    acp::ContentBlock::Image(acp::ImageContent::new(png_base64(), "image/png")),
                ],
            )),
        )
        .await
        .expect("prompt timed out");
        assert!(result.is_err(), "the image save must fail: {result:?}");
        let last = last_turn_event(&dir);
        assert_eq!(
            last["type"], "turn_ended",
            "the failed turn is closed: {last}"
        );
        assert_eq!(last["outcome"], "error", "and closed as an error: {last}");
        // N3: the turn names its own prompt in `turn_started`, which is what crash recovery reads.
        // Mutant discriminated: `turn.rs` writing `prompt_id: None`.
        let started = std::fs::read_to_string(dir.join("events.jsonl"))
            .expect("read events")
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .rfind(|v| v["type"] == "turn_started")
            .expect("a turn_started");
        assert!(
            started["prompt_id"].as_str().is_some_and(|p| !p.is_empty()),
            "turn_started must carry its prompt id: {started}"
        );
    });
}
