//! Actual ACP transport and session persistence with isolated, fake inference.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{RPC_TIMEOUT, connect_client, new_session, run_agent_test, spawn_agent_local_with_config};
use agent_client_protocol::{self as acp, Agent as _};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::mpsc;

struct Recorder(mpsc::UnboundedSender<Value>);
#[async_trait::async_trait(?Send)]
impl acp::Client for Recorder {
    async fn request_permission(&self, _: acp::RequestPermissionRequest) -> acp::Result<acp::RequestPermissionResponse> {
        Ok(acp::RequestPermissionResponse::new(acp::RequestPermissionOutcome::Cancelled))
    }
    async fn session_notification(&self, _: acp::SessionNotification) -> acp::Result<()> { Ok(()) }
    async fn ext_notification(&self, args: acp::ExtNotification) -> acp::Result<()> {
        if args.method.as_ref() == "fuigo/session_notification" {
            let value: Value = serde_json::from_str(args.params.get()).unwrap();
            if value["update"]["sessionUpdate"] == "turn_completed" {
                self.0.send(value).unwrap();
            }
        }
        Ok(())
    }
}

async fn terminal(rx: &mut mpsc::UnboundedReceiver<Value>) -> Value {
    tokio::time::timeout(RPC_TIMEOUT, rx.recv()).await.expect("terminal notification timeout")
        .expect("notification channel closed")
}

fn persisted_executions(dir: &std::path::Path) -> Vec<Value> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            found.extend(persisted_executions(&entry.path()));
        } else if entry.file_name().to_string_lossy().starts_with("execution-")
            && entry.path().extension().is_some_and(|e| e == "json") {
            found.push(serde_json::from_slice(&std::fs::read(entry.path()).unwrap()).unwrap());
        }
    }
    found
}

#[test]
fn acp_completion_and_cancellation_carry_durable_receipts() {
    // One test in this binary; set before the helper creates any worker threads.
    unsafe { std::env::set_var("FUIGO_MAX_MODEL_CALLS", "12"); }
    run_agent_test(|cwd, mock| async move {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let (conn, _) = connect_client(Recorder(tx), "execution-fixture", spawn_agent_local_with_config(config)).await;
        let session = new_session(&conn, &cwd).await;
        acp_harness::prompt_turn(&conn, &session, "Say ready.").await;
        let completed = terminal(&mut rx).await;
        let receipt = &completed["_meta"]["executionReceipt"];
        assert_eq!(receipt["partial"], false, "{completed}");
        let first_id = receipt["id"].as_str().expect("durable receipt ID").to_owned();
        let isolated_home = std::path::PathBuf::from(std::env::var_os("FUIGO_HOME").unwrap());
        assert!(persisted_executions(&isolated_home).iter().any(|state| state["terminal"] == *receipt),
            "delivered receipt must already exist on disk");

        // Observe dispatch before cancellation; no sleep-based assumption that
        // the prompt reached the inference server.
        mock.set_chunk_delay(Some(Duration::from_secs(2)));
        let requests_before = mock.requests().len();
        let prompt = conn.prompt(acp::PromptRequest::new(session.clone(), vec![acp::ContentBlock::Text(acp::TextContent::new("Keep responding until cancelled."))])
            .meta(json!({"promptId": "cancel-fixture"}).as_object().cloned()));
        let cancel = async {
            tokio::time::timeout(RPC_TIMEOUT, async {
                while mock.requests().len() == requests_before {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.expect("cancel fixture never dispatched");
            conn.cancel(acp::CancelNotification::new(session.clone())).await.expect("ACP cancel");
        };
        let (result, ()) = tokio::time::timeout(RPC_TIMEOUT, async { tokio::join!(prompt, cancel) }).await.expect("cancellation timed out");
        assert!(!matches!(&result, Ok(response) if response.stop_reason == acp::StopReason::EndTurn), "cancelled prompt reported normal completion");
        let cancelled = terminal(&mut rx).await;
        let receipt = &cancelled["_meta"]["executionReceipt"];
        assert_eq!(receipt["partial"], true, "{cancelled}");
        assert_ne!(receipt["id"].as_str().unwrap(), first_id);
        assert!(persisted_executions(&isolated_home).iter().any(|state| state["terminal"] == *receipt),
            "cancellation receipt must already exist on disk");
        assert!(rx.try_recv().is_err(), "duplicate terminal notification");
        mock.set_chunk_delay(None);
        tokio::time::timeout(RPC_TIMEOUT, conn.close_session(acp::CloseSessionRequest::new(session))).await.unwrap().unwrap();
    });
}
