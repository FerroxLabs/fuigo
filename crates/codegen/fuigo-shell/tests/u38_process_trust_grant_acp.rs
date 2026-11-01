//! u38 F5: a GUI client's `"duration":"process"` reply trusts the folder through the real prompt path and saves nothing.
//!
//! Real path: a release-stamped (simulated) agent with folder trust on, a git repo with a project config, and a client
//! that advertises `fuigo/folderTrust.v2` and answers the process grant at once.
#![cfg(unix)]

#[allow(dead_code)]
mod acp_harness;
#[allow(dead_code)]
mod p148_support;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use acp_harness::{new_session, run_agent_test, spawn_agent_local_with_config};
use agent_client_protocol as acp;
use serde_json::json;

#[derive(Clone, Default)]
struct ProcessGrantClient {
    trust_requests: Rc<RefCell<usize>>,
}

#[async_trait::async_trait(?Send)]
impl acp::Client for ProcessGrantClient {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        Ok(acp::RequestPermissionResponse::new(acp_harness::allow_once(&args)))
    }
    async fn session_notification(&self, _: acp::SessionNotification) -> acp::Result<()> {
        Ok(())
    }
    async fn ext_method(&self, args: acp::ExtRequest) -> acp::Result<acp::ExtResponse> {
        if args.method.as_ref() == "fuigo/folder_trust/request" {
            *self.trust_requests.borrow_mut() += 1;
            let reply = json!({ "outcome": "trust", "scope": "configAndCommands", "duration": "process" });
            let raw = serde_json::value::to_raw_value(&reply).expect("raw");
            return Ok(acp::ExtResponse::new(std::sync::Arc::from(raw)));
        }
        Err(acp::Error::method_not_found())
    }
    async fn ext_notification(&self, _: acp::ExtNotification) -> acp::Result<()> {
        Ok(())
    }
}

#[test]
fn a_process_reply_trusts_the_folder_and_saves_nothing() {
    run_agent_test(|cwd, _mock| async move {
        // SAFETY: the only other live threads are the mock's HTTP workers, which never read env.
        unsafe {
            std::env::set_var(fuigo_version::TEST_VERSION_ENV, "0.0-sim");
            std::env::set_var("FUIGO_FOLDER_TRUST", "1");
        }
        git2::Repository::init(&cwd).expect("git init");
        std::fs::write(cwd.join("AGENTS.md"), "project rules\n").expect("project file");

        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let client = ProcessGrantClient::default();
        let (conn, auth) = p148_support::connect_with_meta(
            client.clone(),
            "u38-process-grant",
            spawn_agent_local_with_config(config),
            Some(json!({ "fuigo/folderTrust": { "v2": true } })),
            json!({ "headless": true }),
        )
        .await;
        auth.expect("authenticate");
        let key = fuigo_workspace::trust::workspace_key(&cwd);
        assert!(!fuigo_workspace::folder_trust::decide_key(&key, false).is_trusted(), "premise: undecided");
        let _session = new_session(&conn, &cwd).await;

        // The grant runs on a detached task after the client's answer.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while !fuigo_workspace::folder_trust::decide_key(&key, false).is_trusted()
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert_eq!(*client.trust_requests.borrow(), 1, "premise: the client is asked once");
        assert!(
            fuigo_workspace::folder_trust::decide_key(&key, false).is_trusted(),
            "the process reply trusts the folder for this process"
        );
        let store = fuigo_workspace::trust::TrustStore::default_path().expect("store path");
        assert!(!store.exists(), "a process grant saves nothing: {}", store.display());
    });
}
