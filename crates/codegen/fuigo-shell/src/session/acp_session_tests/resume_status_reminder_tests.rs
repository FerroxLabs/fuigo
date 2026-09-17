//! F028: on the first prompt after a cold resume the model gets one reminder listing the loops, subagents and
//! workflows that were still live when the previous process exited (`resume_status.json`, consumed once).

use super::support::create_test_actor;
use agent_client_protocol as acp;

#[tokio::test(flavor = "current_thread")]
async fn resumed_session_reminder_lists_loops_subagents_and_workflows() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
            let (persistence_tx, _persistence_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut actor = create_test_actor(0, 200_000, 80, gateway_tx, persistence_tx).await;
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            actor.session_info.id = acp::SessionId::new(format!("resume-status-{unique}"));
            let session_dir = crate::session::persistence::session_dir(&actor.session_info);
            std::fs::create_dir_all(&session_dir).unwrap();
            let snapshot_path = session_dir.join("resume_status.json");
            std::fs::write(
                &snapshot_path,
                r#"{
                  "loops": [{"id":"loop1","interval_secs":1200,"prompt":"babysit the deploy"}],
                  "subagents": [{"subagent_id":"sa1","subagent_type":"explore","description":"review the diff"}],
                  "workflows": [{"run_id":"wf1","objective":"ship it"}]
                }"#,
            )
            .unwrap();

            actor.inject_resumed_tasks_reminder();
            let conversation = actor.chat_state_handle.get_conversation().await;
            let consumed = !snapshot_path.exists();
            let _ = std::fs::remove_dir_all(&session_dir);

            let text = conversation
                .iter()
                .map(|item| item.text_content())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                text.contains("\"loop1\": every 1200s") && text.contains("babysit the deploy"),
                "the reminder must list the still-scheduled loop, got: {text}"
            );
            assert!(
                text.contains("\"sa1\" (explore): review the diff"),
                "the reminder must list the cancelled subagent, got: {text}"
            );
            assert!(
                text.contains("\"wf1\" (cancelled): ship it"),
                "the reminder must list the cancelled workflow, got: {text}"
            );
            assert!(consumed, "resume_status.json must be consumed by the first prompt");
        })
        .await;
}
