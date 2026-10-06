//! P148 item 4 (e2e C1, P138 d-1, K20): when a GUI client grants folder trust, the session is told about a project
//! server's refused `FUIGO_API_KEY` reference exactly once. C1 saw the same note twice: the session's own start already
//! announced it (the project config is read, and its reference refused, even while the folder is untrusted), and the
//! post-grant reload announced it again.
//!
//! Real path: a release-stamped (simulated) agent with folder trust on, a git repo whose `.fuigo/config.toml` defines a
//! server naming the key, a client that advertises `fuigo/folderTrust.interactive` and answers `trust` at once.
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
use p148_support::Notices;
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct TrustingClient {
    notices: Notices,
    trust_requests: Rc<RefCell<usize>>,
}

#[async_trait::async_trait(?Send)]
impl acp::Client for TrustingClient {
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
            let raw = serde_json::value::to_raw_value(&json!({ "outcome": "trust" })).expect("raw");
            return Ok(acp::ExtResponse::new(std::sync::Arc::from(raw)));
        }
        Err(acp::Error::method_not_found())
    }
    async fn ext_notification(&self, args: acp::ExtNotification) -> acp::Result<()> {
        if let Ok(params) = serde_json::from_str::<Value>(args.params.get()) {
            self.notices.record(&params);
        }
        Ok(())
    }
}

#[test]
fn a_trust_grant_tells_the_session_about_a_refused_key_reference_once() {
    run_agent_test(|cwd, _mock| async move {
        // SAFETY: the only other live threads are the mock's HTTP workers, which never read env.
        unsafe {
            std::env::set_var(fuigo_version::TEST_VERSION_ENV, "0.0-sim");
            std::env::set_var("FUIGO_FOLDER_TRUST", "1");
        }
        git2::Repository::init(&cwd).expect("git init");
        std::fs::create_dir_all(cwd.join(".fuigo")).expect(".fuigo");
        std::fs::write(
            cwd.join(".fuigo").join("config.toml"),
            "[mcp_servers.p148projsrv]\nurl = \"http://127.0.0.1:9/mcp\"\nheaders = { \"X-Ref\" = \"${FUIGO_API_KEY}\" }\n",
        )
        .expect("project config");

        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let client = TrustingClient::default();
        let (conn, auth) = p148_support::connect_with_meta(
            client.clone(),
            "p148-trust-grant",
            spawn_agent_local_with_config(config),
            Some(json!({ "fuigo/folderTrust": { "interactive": true } })),
            json!({ "headless": true }),
        )
        .await;
        auth.expect("authenticate");
        let _session = new_session(&conn, &cwd).await;
        // The grant's reload runs on a detached task after the client's answer; let it and the session settle.
        tokio::time::sleep(Duration::from_secs(8)).await;

        assert_eq!(*client.trust_requests.borrow(), 1, "premise: the client is asked once and grants");
        let notes = client.notices.matching("p148projsrv");
        assert_eq!(
            notes.len(),
            1,
            "the refused reference must be announced exactly once across session start and the trust grant: {notes:#?}"
        );
    });
}
