//! 1.0.36 item a: the session side of the launch permission policy, through the real `session/new`, `session/load` and
//! `session/close` of an agent (`_meta` key + hash, the ack, the in-process binding and the stored marker).

use std::sync::Arc;
use std::time::Duration;

use acp::Agent as _;
use agent_client_protocol as acp;
use fuigo_test_support::EnvGuard;
use fuigo_workspace::permission::launch_policy::{self, META_ACK, META_PATH, META_SHA256};
use serde_json::json;

fn policy_code(e: &acp::Error) -> String {
    e.data
        .as_ref()
        .and_then(|d| d.get("policy_error"))
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_owned()
}

fn meta(value: serde_json::Value) -> Option<acp::Meta> {
    value.as_object().cloned()
}

/// No process policy: `fuigo/capabilities` has no `permissionPolicy` entry, and its keys are exactly the known ones.
#[test]
fn u36_capability_absent_without_a_process_policy() {
    assert!(launch_policy::process().is_none());
    let caps = super::super::acp_agent::fuigo_capabilities();
    let obj = caps.as_object().expect("object");
    assert!(!obj.contains_key("permissionPolicy"), "{caps}");
    let mut known: Vec<String> = ["toolOverrides", "authenticateApiKey", "sessionPark", "retryDiscard", "peerMessaging"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    known.extend(crate::agent::init_flags::capability_entries().keys().cloned());
    for key in obj.keys() {
        assert!(known.contains(key), "unexpected capability key {key}");
    }
}

/// What each flow test gets: a fresh agent (initialized), a workdir and a verified policy file.
struct Fixture {
    cwd: std::path::PathBuf,
    policy_path: String,
    policy_sha: String,
}

/// Run `body` in its own process with a mock inference server, a fresh home and an initialized agent.
fn run_with_agent<F, Fut>(test_name: &str, body: F)
where
    F: FnOnce(super::MvpAgentHandle, Fixture) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let Some(_home) = fuigo_test_support::env::fresh_process_home(test_name) else {
        return;
    };
    fuigo_extra_ca::ensure_default_crypto_provider();
    let mock_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("mock runtime");
    let server = mock_rt
        .block_on(fuigo_test_support::MockInferenceServer::start())
        .expect("mock server");
    let home = tempfile::tempdir().expect("home");
    let workdir = tempfile::tempdir().expect("workdir");
    let policy_dir = tempfile::tempdir().expect("policy dir");
    let policy_path = policy_dir.path().join("policy.toml");
    let policy_bytes = b"[permission]\nask = [\"Bash\"]\n";
    std::fs::write(&policy_path, policy_bytes).expect("write policy");
    let fixture = Fixture {
        cwd: workdir.path().to_path_buf(),
        policy_path: policy_path.to_string_lossy().into_owned(),
        policy_sha: launch_policy::sha256_hex(policy_bytes),
    };
    let url = server.url();
    let _env = [
        EnvGuard::set("HOME", home.path()),
        EnvGuard::set("USERPROFILE", home.path()),
        EnvGuard::set("FUIGO_CLI_CHAT_PROXY_BASE_URL", &url),
        EnvGuard::set("FUIGO_API_BASE_URL", &url),
        EnvGuard::set("FUIGO_API_KEY", "test-key-for-ci"),
        EnvGuard::set("FUIGO_TELEMETRY_ENABLED", "false"),
        EnvGuard::set("FUIGO_FEEDBACK_ENABLED", "false"),
        EnvGuard::set("FUIGO_TRACE_UPLOAD", "false"),
        EnvGuard::set("FUIGO_TURN_SUMMARY", "false"),
        EnvGuard::unset("FUIGO_MODELS_BASE_URL"),
        EnvGuard::unset("FUIGO_MODELS_LIST_URL"),
        EnvGuard::unset(launch_policy::ENV_PATH),
        EnvGuard::unset(launch_policy::ENV_SHA256),
    ];
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("agent runtime");
    tokio::task::LocalSet::new().block_on(&rt, async {
        let agent_config = crate::agent::config::Config::default();
        let (tx, mut gw_rx) = tokio::sync::mpsc::unbounded_channel();
        let agent = super::MvpAgent::new(
            super::GatewaySender::new(tx),
            &agent_config,
            Arc::new(agent_config.create_auth_manager()),
            None,
        )
        .expect("agent");
        tokio::task::spawn_local(async move {
            while let Some(message) = gw_rx.recv().await {
                match message {
                    fuigo_acp_lib::AcpClientMessage::ExtNotification(args) => {
                        let _ = args.response_tx.send(Ok(()));
                    }
                    fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                        let _ = args.response_tx.send(Ok(()));
                    }
                    _ => {}
                }
            }
        });
        agent
            .initialize(
                acp::InitializeRequest::new(acp::ProtocolVersion::V1)
                    .client_capabilities(
                        acp::ClientCapabilities::new()
                            .fs(acp::FileSystemCapabilities::new())
                            .terminal(false),
                    )
                    .meta(meta(json!({
                        "startupHints": {"nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true},
                        "clientType": "u36-policy",
                        "clientVersion": "0.0-test",
                    }))),
            )
            .await
            .expect("initialize");
        body(agent, fixture).await;
    });
}

/// A governed `session/new` (key + hash), returning its id.
async fn new_governed(agent: &super::MvpAgentHandle, fx: &Fixture) -> acp::SessionId {
    let governed_meta = json!({ META_PATH: fx.policy_path, META_SHA256: fx.policy_sha });
    tokio::time::timeout(
        WAIT,
        agent.new_session(acp::NewSessionRequest::new(fx.cwd.clone()).meta(meta(governed_meta))),
    )
    .await
    .expect("governed new timed out")
    .expect("governed new")
    .session_id
}

const WAIT: Duration = Duration::from_secs(120);
const FLOW_TEST: &str = "agent::mvp_agent::tests::u36_launch_policy_tests::u36_session_policy_new_load_flow";

/// One agent, end to end: ungoverned `session/new` (no ack); a path without a hash (`hash_missing`); a verified policy
/// (ack carries the sha256, marker stored); a resident load without the key (`session_policy_conflict`); after close, a
/// cold load without the key (`session_policy_missing`); a cold load with the key (ack again).
#[test]
#[serial_test::serial]
fn u36_session_policy_new_load_flow() {
    run_with_agent(FLOW_TEST, |agent, fx| async move {
        let cwd = fx.cwd.clone();
        let policy_sha = fx.policy_sha.clone();

        // (e) Ungoverned: no ack key.
        let plain = tokio::time::timeout(WAIT, agent.new_session(acp::NewSessionRequest::new(cwd.clone())))
            .await
            .expect("new timed out")
            .expect("ungoverned new");
        assert!(
            plain.meta.as_ref().is_some_and(|m| !m.contains_key(META_ACK)),
            "ungoverned response has no ack: {:?}",
            plain.meta
        );

        // (b) A path without its hash.
        let err = agent
            .new_session(acp::NewSessionRequest::new(cwd.clone()).meta(meta(json!({ META_PATH: fx.policy_path }))))
            .await
            .expect_err("path without hash is refused");
        assert_eq!(policy_code(&err), "hash_missing", "{err:?}");

        // (c) A verified policy: the ack carries its sha256, the id is bound and the marker is stored.
        let governed_meta = json!({ META_PATH: fx.policy_path, META_SHA256: policy_sha });
        let governed = tokio::time::timeout(
            WAIT,
            agent.new_session(acp::NewSessionRequest::new(cwd.clone()).meta(meta(governed_meta.clone()))),
        )
        .await
        .expect("governed new timed out")
        .expect("governed new");
        let ack = governed.meta.as_ref().and_then(|m| m.get(META_ACK)).cloned();
        assert_eq!(ack, Some(json!({ "sha256": policy_sha })));
        let sid = governed.session_id.clone();
        assert_eq!(
            launch_policy::session_binding(sid.0.as_ref()).map(|b| b.sha256),
            Some(policy_sha.clone()),
            "the governed id is bound in this process"
        );
        let dir = crate::session::persistence::find_persisted_session_dir(sid.0.as_ref()).expect("session dir");
        let summary: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("summary.json")).expect("summary")).expect("summary json");
        assert_eq!(summary["permission_policy"]["sha256"], json!(policy_sha), "marker stored");

        // (d) Resident load without the key: the installed policy differs from the request's (none).
        let err = agent
            .load_session(acp::LoadSessionRequest::new(sid.clone(), cwd.clone()))
            .await
            .expect_err("resident load without the key");
        assert_eq!(policy_code(&err), "session_policy_conflict", "{err:?}");

        // (d) After close, a cold load without the key of the bound id.
        agent
            .close_session(acp::CloseSessionRequest::new(sid.clone()))
            .await
            .expect("close");
        let err = agent
            .load_session(acp::LoadSessionRequest::new(sid.clone(), cwd.clone()))
            .await
            .expect_err("cold load without the key");
        assert_eq!(policy_code(&err), "session_policy_missing", "{err:?}");

        // A cold load with the key reattaches under the same policy, acked.
        let loaded = tokio::time::timeout(
            WAIT,
            agent.load_session(acp::LoadSessionRequest::new(sid.clone(), cwd.clone()).meta(meta(governed_meta))),
        )
        .await
        .expect("governed load timed out")
        .expect("governed load");
        assert_eq!(loaded.meta.as_ref().and_then(|m| m.get(META_ACK)).cloned(), Some(json!({ "sha256": policy_sha })));
    });
}

const FORK_TEST: &str = "agent::mvp_agent::tests::u36_launch_policy_tests::u36_fork_of_governed_session_needs_the_key";

/// `fuigo/session/fork` of a governed source: without the key → `session_policy_missing`; with key + hash → the response
/// carries the ack and the new id is bound to the same policy.
#[test]
#[serial_test::serial]
fn u36_fork_of_governed_session_needs_the_key() {
    run_with_agent(FORK_TEST, |agent, fx| async move {
        let source = new_governed(&agent, &fx).await;
        let cwd = fx.cwd.to_string_lossy().into_owned();
        let fork = |params: serde_json::Value| {
            let raw = serde_json::value::to_raw_value(&params).expect("params");
            agent.ext_method(acp::ExtRequest::new("fuigo/session/fork".to_owned(), Arc::from(raw)))
        };
        let base = json!({ "sourceSessionId": source.0.as_ref(), "sourceCwd": cwd, "newCwd": cwd });

        let err = fork(base.clone()).await.expect_err("fork without the key");
        assert_eq!(policy_code(&err), "session_policy_missing", "{err:?}");

        let mut with_key = base;
        with_key["_meta"] = json!({ META_PATH: fx.policy_path, META_SHA256: fx.policy_sha });
        let resp = fork(with_key).await.expect("fork with the key");
        let body: serde_json::Value = serde_json::from_str(resp.0.get()).expect("fork response json");
        assert_eq!(body["_meta"][META_ACK], json!({ "sha256": fx.policy_sha }), "{body}");
        let new_id = body["newSessionId"].as_str().expect("newSessionId");
        assert_eq!(
            launch_policy::session_binding(new_id).map(|b| b.sha256),
            Some(fx.policy_sha.clone()),
            "the fork's id is bound to the same policy"
        );
    });
}

const RACE_TEST: &str =
    "agent::mvp_agent::tests::u36_launch_policy_tests::u36_overlapping_new_sessions_cannot_replace_a_governed_actor";

/// A client-chosen `_meta.sessionId` must be a UUID.
const RACE_SEQ: &str = "01936f00-0000-7000-8000-000000000361";

/// What the id's resident actor runs under, if one is resident.
struct Resident {
    installed: Option<launch_policy::PolicyBinding>,
}

/// The resident actor (if any) and its launch policy binding (`None`: ungoverned), next to the id's binding in this
/// process.
fn installed_vs_bound(agent: &super::MvpAgentHandle, sid: &acp::SessionId) -> (Option<Resident>, Option<launch_policy::PolicyBinding>) {
    let resident = agent.resident_handle(sid).map(|handle| Resident {
        installed: handle.permission_handle.launch_policy().map(|policy| policy.binding()),
    });
    (resident, launch_policy::session_binding(sid.0.as_ref()))
}

/// Astra r1 #1: an ungoverned (or differently governed) `session/new` naming the same `_meta.sessionId` as a governed one
/// can never leave an actor resident whose policy differs from the id's binding, whether it runs after the governed one
/// or overlaps it.
#[test]
#[serial_test::serial]
fn u36_overlapping_new_sessions_cannot_replace_a_governed_actor() {
    run_with_agent(RACE_TEST, |agent, fx| async move {
        let cwd = fx.cwd.clone();
        let governed_meta = |sid: &str| json!({ "sessionId": sid, META_PATH: fx.policy_path, META_SHA256: fx.policy_sha });
        // Sequential: the governed session is resident; an ungoverned new for its id is refused and changes nothing.
        let sid = acp::SessionId::new(RACE_SEQ);
        tokio::time::timeout(
            WAIT,
            agent.new_session(acp::NewSessionRequest::new(cwd.clone()).meta(meta(governed_meta(RACE_SEQ)))),
        )
        .await
        .expect("governed new timed out")
        .expect("governed new");
        let err = agent
            .new_session(acp::NewSessionRequest::new(cwd.clone()).meta(meta(json!({ "sessionId": RACE_SEQ }))))
            .await
            .expect_err("an ungoverned new for a governed id");
        assert!(matches!(policy_code(&err).as_str(), "session_policy_missing" | ""), "{err:?}");
        let (resident, bound) = installed_vs_bound(&agent, &sid);
        assert_eq!(resident.expect("the governed actor stays resident").installed, bound);
        assert!(bound.is_some());

        // Overlapping: both requests in flight at once, in both orders. Whatever each returns, the resident actor runs
        // under exactly the id's binding.
        for (round, governed_first) in [(0, true), (1, false)] {
            let id = format!("01936f00-0000-7000-8000-00000000036{}", round + 2);
            let sid = acp::SessionId::new(id.as_str());
            let governed = agent.new_session(acp::NewSessionRequest::new(cwd.clone()).meta(meta(governed_meta(&id))));
            let plain = agent.new_session(acp::NewSessionRequest::new(cwd.clone()).meta(meta(json!({ "sessionId": id }))));
            let (governed, plain) = if governed_first {
                tokio::time::timeout(WAIT, async { tokio::join!(governed, plain) }).await.expect("race timed out")
            } else {
                let (plain, governed) =
                    tokio::time::timeout(WAIT, async { tokio::join!(plain, governed) }).await.expect("race timed out");
                (governed, plain)
            };
            if let Err(err) = &plain {
                assert!(matches!(policy_code(err).as_str(), "session_policy_missing" | ""), "round {round}: {err:?}");
            }
            let (resident, bound) = installed_vs_bound(&agent, &sid);
            if governed.is_ok() {
                assert!(bound.is_some(), "round {round}: the governed request bound the id");
            }
            if let Some(resident) = resident {
                assert_eq!(resident.installed, bound, "round {round}: resident actor vs the id's binding");
            }
        }
    });
}

const WORKTREE_FORK_TEST: &str =
    "agent::mvp_agent::tests::u36_launch_policy_tests::u36_worktree_fork_of_governed_session_passes_the_claim";

/// Every stored session (its `summary.json`) under the fuigo home.
fn stored_sessions() -> usize {
    fn walk(dir: &std::path::Path) -> usize {
        let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
        entries
            .flatten()
            .map(|e| {
                let path = e.path();
                if path.is_dir() {
                    walk(&path)
                } else {
                    usize::from(path.file_name().is_some_and(|n| n == "summary.json"))
                }
            })
            .sum()
    }
    walk(&crate::util::fuigo_home::fuigo_home())
}

/// `fuigo/git/worktree/resume_session` of a governed source passes the request's `_meta` claim to the fork: without it
/// the fork is refused (`session_policy_missing`) and no session copy is left; with key + hash the child is bound to the
/// same policy, carries the stored marker and the response carries the ack.
#[test]
#[serial_test::serial]
fn u36_worktree_fork_of_governed_session_passes_the_claim() {
    run_with_agent(WORKTREE_FORK_TEST, |agent, fx| async move {
        crate::test_support::ensure_hermetic_git_on_path();
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .current_dir(&fx.cwd)
                .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
                .args(args)
                .output()
                .expect("git");
            assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        };
        git(&["init", "-q"]);
        std::fs::write(fx.cwd.join("file.txt"), "x").expect("write");
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "init"]);

        let source = new_governed(&agent, &fx).await;
        let cwd = fx.cwd.to_string_lossy().into_owned();
        let resume = |params: serde_json::Value| {
            let raw = serde_json::value::to_raw_value(&params).expect("params");
            agent.ext_method(acp::ExtRequest::new("fuigo/git/worktree/resume_session".to_owned(), Arc::from(raw)))
        };
        let base = json!({ "sessionId": source.0.as_ref(), "sourceCwd": cwd, "restoreCode": false });
        let before = stored_sessions();
        assert!(before >= 1, "the governed source is stored");

        let resp = tokio::time::timeout(WAIT, resume(base.clone())).await.expect("timed out").expect("ext response");
        let body: serde_json::Value = serde_json::from_str(resp.0.get()).expect("json");
        assert!(body["result"].is_null(), "refused without the claim: {body}");
        let error = body["error"].to_string();
        assert!(error.contains("session_policy_missing"), "{body}");
        assert_eq!(stored_sessions(), before, "a refused worktree fork leaves no session copy");

        let mut with_key = base;
        with_key["_meta"] = json!({ META_PATH: fx.policy_path, META_SHA256: fx.policy_sha });
        let resp = tokio::time::timeout(WAIT, resume(with_key)).await.expect("timed out").expect("ext response");
        let body: serde_json::Value = serde_json::from_str(resp.0.get()).expect("json");
        let result = &body["result"];
        assert!(result.is_object(), "worktree fork with the claim: {body}");
        assert_eq!(result["_meta"][META_ACK], json!({ "sha256": fx.policy_sha }), "{body}");
        let child = result["sessionId"].as_str().expect("sessionId");
        assert_ne!(child, source.0.as_ref());
        assert_eq!(
            launch_policy::session_binding(child).map(|b| b.sha256),
            Some(fx.policy_sha.clone()),
            "the worktree fork's id is bound to the same policy"
        );
        assert_eq!(stored_sessions(), before + 1, "exactly one copy: the bound child");
        let info = crate::session::info::Info {
            id: acp::SessionId::new(child.to_owned()),
            cwd: result["effectiveCwd"].as_str().expect("effectiveCwd").to_owned(),
        };
        let summary: crate::session::persistence::Summary = serde_json::from_str(
            &std::fs::read_to_string(crate::session::persistence::session_dir(&info).join("summary.json"))
                .expect("child summary"),
        )
        .expect("summary json");
        assert_eq!(
            summary.permission_policy.map(|b| b.sha256),
            Some(fx.policy_sha.clone()),
            "the child carries the stored marker"
        );
    });
}
