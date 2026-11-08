//! design F5 §2 goal 1, §9.4 B2: a grant a session makes itself (`/hooks-trust`, the `/hooks` modal's Trust action) is
//! settled as the modal's grant is: after a durable save, one `folder_trust_reload` per session to a client that
//! advertised `fuigo/folderTrust.reload` and one reopen notice to a `reopenNotice` client; nothing for a grant that was
//! already durable, and nothing for a client that opted in to neither (its frames are 1.0.40's).
#![cfg(unix)]

#[allow(dead_code)]
mod acp_harness;
#[allow(dead_code)]
mod p148_support;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use acp_harness::{ext_method, new_session, run_agent_test, spawn_agent_local_with_config};
use agent_client_protocol as acp;
use serde_json::json;

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
const NOTICE: &str = "Folder trust is on. Reopen this session to use it.";

#[derive(Clone, Default)]
struct FrameClient {
    frames: Rc<RefCell<Vec<String>>>,
}

#[async_trait::async_trait(?Send)]
impl acp::Client for FrameClient {
    async fn request_permission(&self, args: acp::RequestPermissionRequest) -> acp::Result<acp::RequestPermissionResponse> {
        Ok(acp::RequestPermissionResponse::new(acp_harness::allow_once(&args)))
    }
    async fn session_notification(&self, args: acp::SessionNotification) -> acp::Result<()> {
        self.frames.borrow_mut().push(format!("session/update {}", serde_json::to_string(&args).unwrap_or_default()));
        Ok(())
    }
    async fn ext_method(&self, _args: acp::ExtRequest) -> acp::Result<acp::ExtResponse> {
        Err(acp::Error::method_not_found())
    }
    async fn ext_notification(&self, args: acp::ExtNotification) -> acp::Result<()> {
        self.frames.borrow_mut().push(format!("{} {}", args.method, args.params.get()));
        Ok(())
    }
}

impl FrameClient {
    fn count(&self, needle: &str) -> usize {
        self.frames.borrow().iter().filter(|f| f.contains(needle)).count()
    }
}

enum Via {
    Slash,
    HooksAction,
}

async fn grant(conn: &acp::ClientSideConnection, session: &acp::SessionId, via: &Via) {
    match via {
        Via::Slash => {
            let response = tokio::time::timeout(
                Duration::from_secs(60),
                acp::Agent::prompt(
                    conn,
                    acp::PromptRequest::new(session.clone(), vec![acp::ContentBlock::Text(acp::TextContent::new("/hooks-trust"))]),
                ),
            )
            .await
            .expect("/hooks-trust timed out")
            .expect("/hooks-trust");
            assert_eq!(response.stop_reason, acp::StopReason::EndTurn);
        }
        Via::HooksAction => {
            let outcome = ext_method(
                conn,
                "fuigo/hooks/action",
                json!({ "sessionId": session.0.to_string(), "action": { "type": "trust" } }),
            )
            .await;
            assert_eq!(outcome["result"]["status"].as_str().map(str::to_ascii_lowercase).as_deref(), Some("success"), "{outcome}");
        }
    }
    // The agent settles the session's report on its own task.
    tokio::time::sleep(Duration::from_millis(1500)).await;
}

/// Open an untrusted session for a client with `caps`, grant it twice through `via` (the second finds the grant durable),
/// and return the client's frames: (after the first grant, after the second).
#[allow(clippy::disallowed_methods, reason = "test code: writes the fixture AGENTS.md into the test-owned temp project dir `cwd`, never a session folder; no product session writer runs there")]
async fn grant_twice(cwd: PathBuf, caps: Option<serde_json::Value>, via: Via) -> (FrameClient, acp::SessionId, Vec<String>) {
    // SAFETY: the only other live threads are the mock's HTTP workers, which never read env.
    unsafe {
        std::env::set_var(fuigo_version::TEST_VERSION_ENV, "0.0-sim");
        std::env::set_var("FUIGO_FOLDER_TRUST", "1");
    }
    git2::Repository::init(&cwd).expect("git init");
    std::fs::write(cwd.join("AGENTS.md"), "project rules\n").expect("project file");
    let mut config = fuigo_shell::agent::config::Config::default();
    config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
    let client = FrameClient::default();
    let (conn, auth) = p148_support::connect_with_meta(
        client.clone(),
        "f5b3-session-grant",
        spawn_agent_local_with_config(config),
        caps.map(|caps| json!({ "fuigo/folderTrust": caps })),
        json!({ "headless": true }),
    )
    .await;
    auth.expect("authenticate");
    let key = fuigo_workspace::trust::workspace_key(&cwd);
    let session = new_session(&conn, &cwd).await;
    assert!(!fuigo_workspace::folder_trust::decide_key(&key, false).is_trusted(), "premise: untrusted");
    grant(&conn, &session, &via).await;
    assert!(fuigo_workspace::folder_trust::decide_key(&key, false).is_trusted(), "premise: the grant took effect");
    let first = client.frames.borrow().clone();
    grant(&conn, &session, &via).await;
    (client, session, first)
}

fn assert_offered_once(client: &FrameClient, session: &acp::SessionId, first: &[String]) {
    let reloads: Vec<_> = first.iter().filter(|f| f.contains("folder_trust_reload")).collect();
    assert_eq!(reloads.len(), 1, "one reload for the durable grant: {first:?}");
    assert!(reloads[0].starts_with("fuigo/session/update ") && reloads[0].contains(session.0.as_ref()), "{reloads:?}");
    assert_eq!(first.iter().filter(|f| f.contains(NOTICE)).count(), 1, "one reopen notice: {first:?}");
    assert_eq!(client.count("folder_trust_reload"), 1, "an already-durable grant offered a reload again");
    assert_eq!(client.count(NOTICE), 1, "an already-durable grant sent the reopen notice again");
}

#[test]
fn f5b3_slash_trust_offers_one_reload_and_notice_on_a_durable_grant_only() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    run_agent_test(|cwd, _mock| async move {
        let caps = json!({ "reload": true, "reopenNotice": true });
        let (client, session, first) = grant_twice(cwd, Some(caps), Via::Slash).await;
        assert_offered_once(&client, &session, &first);
    });
}

#[test]
fn f5b3_hooks_trust_action_offers_one_reload_and_notice_on_a_durable_grant_only() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    run_agent_test(|cwd, _mock| async move {
        let caps = json!({ "reload": true, "reopenNotice": true });
        let (client, session, first) = grant_twice(cwd, Some(caps), Via::HooksAction).await;
        assert_offered_once(&client, &session, &first);
    });
}

#[test]
fn f5b3_slash_trust_sends_a_client_without_the_opt_ins_no_reload_and_no_notice() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    run_agent_test(|cwd, _mock| async move {
        let (client, _session, first) = grant_twice(cwd, None, Via::Slash).await;
        assert_eq!(client.count("folder_trust_reload"), 0, "a client without reload was sent one: {first:?}");
        assert_eq!(client.count(NOTICE), 0, "a client without reopenNotice was sent the notice: {first:?}");
    });
}
