//! F5-N (design F5 §4.1): after a durable folder-trust grant, a client that advertised `fuigo/folderTrust.reload` is sent
//! one `folder_trust_reload` per session, ephemeral (a reattach reports the reload as owed in its response `_meta` and
//! never replays the notification); a client without `reload` sees none of it. The grant writes no config file.
//!
//! Real path: a release-stamped (simulated) agent with folder trust on, a git repo with a project file, and a client that
//! advertises `fuigo/folderTrust.v2` and answers the durable grant at once.
#![cfg(unix)]

#[allow(dead_code)]
mod acp_harness;
#[allow(dead_code)]
mod p148_support;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use acp::Agent as _;
use acp_harness::{new_session, run_agent_test, spawn_agent_local_with_config};
use agent_client_protocol as acp;
use serde_json::json;

/// The two tests set process env for their agent; they run one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Clone, Default)]
struct GrantClient {
    trust_requests: Rc<RefCell<usize>>,
    /// Every notification the client received, as `<method> <params>`.
    frames: Rc<RefCell<Vec<String>>>,
}

#[async_trait::async_trait(?Send)]
impl acp::Client for GrantClient {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        Ok(acp::RequestPermissionResponse::new(acp_harness::allow_once(&args)))
    }
    async fn session_notification(&self, args: acp::SessionNotification) -> acp::Result<()> {
        let frame = serde_json::to_string(&args).unwrap_or_default();
        self.frames.borrow_mut().push(format!("session/update {frame}"));
        Ok(())
    }
    async fn ext_method(&self, args: acp::ExtRequest) -> acp::Result<acp::ExtResponse> {
        if args.method.as_ref() == "fuigo/folder_trust/request" {
            *self.trust_requests.borrow_mut() += 1;
            let reply = json!({ "outcome": "trust", "scope": "configAndCommands" });
            let raw = serde_json::value::to_raw_value(&reply).expect("raw");
            return Ok(acp::ExtResponse::new(std::sync::Arc::from(raw)));
        }
        Err(acp::Error::method_not_found())
    }
    async fn ext_notification(&self, args: acp::ExtNotification) -> acp::Result<()> {
        self.frames.borrow_mut().push(format!("{} {}", args.method, args.params.get()));
        Ok(())
    }
}

impl GrantClient {
    fn reloads(&self) -> Vec<String> {
        self.frames.borrow().iter().filter(|f| f.contains("folder_trust_reload")).cloned().collect()
    }
}

/// Every file F5 must never write, with its bytes (`None`: absent): config, requirements and sandbox files, trusted
/// plugin and hook-project lists, and `~/.claude.json`.
fn owner_files() -> Vec<(PathBuf, Option<Vec<u8>>)> {
    let fuigo_home = PathBuf::from(std::env::var_os("FUIGO_HOME").expect("FUIGO_HOME"));
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    let mut paths = vec![
        fuigo_home.join("config.toml"),
        fuigo_home.join("requirements.toml"),
        fuigo_home.join("sandbox.toml"),
        home.join(".claude.json"),
    ];
    for dir in [&fuigo_home, &home] {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("trusted-plugins") || name.starts_with("trusted-hook-projects") {
                paths.push(entry.path());
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths.into_iter().map(|path| (path.clone(), std::fs::read(&path).ok())).collect()
}

/// Grant the folder durably through the real prompt path for a client with `caps`, then reattach the resident session.
/// Returns the client, the notifications seen after the grant, and the reattach response's `_meta`.
#[allow(clippy::disallowed_methods, reason = "test code: writes the fixture AGENTS.md into the test-owned temp project dir `cwd`, never a session folder; no product session writer runs there")]
async fn grant_and_reattach(cwd: PathBuf, caps: serde_json::Value) -> (GrantClient, Vec<String>, Option<acp::Meta>) {
    // SAFETY: the only other live threads are the mock's HTTP workers, which never read env.
    unsafe {
        std::env::set_var(fuigo_version::TEST_VERSION_ENV, "0.0-sim");
        std::env::set_var("FUIGO_FOLDER_TRUST", "1");
    }
    git2::Repository::init(&cwd).expect("git init");
    std::fs::write(cwd.join("AGENTS.md"), "project rules\n").expect("project file");

    let mut config = fuigo_shell::agent::config::Config::default();
    config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
    let client = GrantClient::default();
    let (conn, auth) = p148_support::connect_with_meta(
        client.clone(),
        "f5n-reload",
        spawn_agent_local_with_config(config),
        Some(json!({ "fuigo/folderTrust": caps })),
        json!({ "headless": true }),
    )
    .await;
    auth.expect("authenticate");
    // After the agent's own start-up (a once-per-home marketplace migration may write `config.toml` then), before the grant.
    let before = owner_files();
    let key = fuigo_workspace::trust::workspace_key(&cwd);
    assert!(!fuigo_workspace::folder_trust::decide_key(&key, false).is_trusted(), "premise: undecided");
    let session = new_session(&conn, &cwd).await;

    // The grant runs on a detached task after the client's answer.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !fuigo_workspace::folder_trust::decide_key(&key, false).is_trusted()
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(*client.trust_requests.borrow(), 1, "premise: the client is asked once");
    assert!(fuigo_workspace::folder_trust::decide_key(&key, false).is_trusted(), "premise: the grant took effect");
    let store = fuigo_workspace::trust::TrustStore::default_path().expect("store path");
    assert!(store.exists(), "premise: the grant is durable: {}", store.display());
    // Let the rest of the grant task (notifications, server reload) run.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let after_grant = client.frames.borrow().clone();
    assert_eq!(owner_files(), before, "the grant wrote a config, requirements, sandbox, trusted-list or ~/.claude.json file");

    let loaded = tokio::time::timeout(
        Duration::from_secs(30),
        conn.load_session(acp::LoadSessionRequest::new(session.clone(), cwd.clone())),
    )
    .await
    .expect("session/load timed out")
    .expect("session/load");
    tokio::time::sleep(Duration::from_millis(500)).await;
    for frame in client.reloads() {
        assert!(frame.contains(session.0.as_ref()), "the reload names its session: {frame}");
    }
    (client, after_grant, loaded.meta)
}

#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[test]
fn f5n_a_durable_grant_sends_one_reload_owes_it_on_reattach_and_never_replays_it() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    run_agent_test(|cwd, _mock| async move {
        let caps = json!({ "v2": true, "reload": true });
        let (client, after_grant, meta) = grant_and_reattach(cwd, caps).await;
        let reloads: Vec<_> = after_grant.iter().filter(|f| f.contains("folder_trust_reload")).collect();
        assert_eq!(reloads.len(), 1, "one reload per session per grant: {after_grant:?}");
        assert!(reloads[0].contains("fuigo/session/update"), "{reloads:?}");
        assert_eq!(
            meta.as_ref().and_then(|m| m.get("fuigo/folderTrustReload")),
            Some(&json!({ "owed": true })),
            "a reattach to the granted session reports the reload as owed: {meta:?}"
        );
        assert_eq!(client.reloads().len(), 1, "the reattach replayed the reload: {:?}", client.frames.borrow());
    });
}

#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[test]
fn f5n_a_client_without_reload_is_sent_no_reload_and_no_owed_meta() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    run_agent_test(|cwd, _mock| async move {
        let (client, after_grant, meta) = grant_and_reattach(cwd, json!({ "v2": true })).await;
        assert!(client.reloads().is_empty(), "a client without reload was sent one: {after_grant:?}");
        assert!(
            meta.as_ref().is_none_or(|m| m.get("fuigo/folderTrustReload").is_none()),
            "a client without reload sees 1.0.40's load response: {meta:?}"
        );
    });
}
