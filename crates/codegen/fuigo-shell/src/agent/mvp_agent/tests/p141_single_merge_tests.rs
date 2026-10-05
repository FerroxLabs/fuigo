//! P141 (Fable LOW 2 on P138): `session/new`, `session/load` and `update_mcp_servers` merge the MCP sources ONCE per
//! request. P138 ran a second, local-only merge whenever the pager forwarded a copy (always, with the pager): every
//! "loaded from source" info line, "blocked by managed settings" and "folder untrusted: skipping" warning, the
//! `mcp_merge_managed` timer and the disk and plugin reads happened twice. Red first.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::build_minimal_agent_for_tests;

/// Counts the sourced merge's per-server "MCP server loaded from source" events on this thread.
struct CountLoaded(Arc<AtomicUsize>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CountLoaded {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        struct Message(bool);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" && format!("{value:?}").contains("MCP server loaded from source") {
                    self.0 = true;
                }
            }
        }
        let mut message = Message(false);
        event.record(&mut message);
        if message.0 {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_session_entry_merges_the_mcp_sources_once() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let home = fuigo_test_support::FuigoHome::new();
    let user_home = tempfile::tempdir().unwrap();
    let _h = fuigo_test_support::EnvGuard::set("HOME", user_home.path());
    std::fs::write(home.path().join("config.toml"), "[mcp_servers.p141-once]\nurl = \"https://o.p141.invalid/mcp\"\n").unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let forwarded =
        crate::util::config::load_mcp_servers(cwd.path(), &fuigo_tools::types::compat::CompatConfig::default());
    assert_eq!(forwarded.len(), 1, "fixture: the pager forwards the user's server");
    let agent = build_minimal_agent_for_tests();
    // The launch-dir plugin snapshot is built outside the count (it merges nothing).
    agent.ensure_plugin_registry();
    let loaded = Arc::new(AtomicUsize::new(0));
    let _guard = tracing_subscriber::registry().with(CountLoaded(loaded.clone())).set_default();
    let (_seed, merged) = agent.resolve_mcp_servers(forwarded, cwd.path()).await;
    drop(_guard);
    assert!(merged.iter().any(|s| crate::session::managed_mcp::mcp_server_name(s) == "p141-once"), "the user's server runs");
    assert_eq!(loaded.load(Ordering::SeqCst), 1, "the MCP sources were merged more than once for one session entry");
}

/// `fuigo/session/update_mcp_servers` admits a new client set: the session ACTOR gets the new hot-reload seed too (its
/// plugin reload re-merges its own copy), with the forwarded copy marked, and BEFORE the update. Astra P141 r1, r2.
#[tokio::test(flavor = "current_thread")]
async fn update_mcp_servers_hands_the_actor_the_new_seed() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    use acp::Agent as _;
    use agent_client_protocol as acp;
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let home = fuigo_test_support::FuigoHome::new();
    let user_home = tempfile::tempdir().unwrap();
    let _h = fuigo_test_support::EnvGuard::set("HOME", user_home.path());
    std::fs::write(home.path().join("config.toml"), "[mcp_servers.p141-upd]\nurl = \"https://u.p141.invalid/mcp\"\n").unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let forwarded =
        crate::util::config::load_mcp_servers(cwd.path(), &fuigo_tools::types::compat::CompatConfig::default());
    let agent = build_minimal_agent_for_tests();
    let sid = acp::SessionId::new("sess-p141-upd");
    let (mut handle, _tx, mut cmd_rx) = super::make_live_session_handle(&sid, None);
    handle.info.cwd = cwd.path().display().to_string();
    agent.insert_resident(&sid, handle);
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            // Records, in arrival order, the seeds handed over and the update (`None`).
            let actor = tokio::task::spawn_local(async move {
                let mut seen: Vec<Option<Vec<String>>> = Vec::new();
                while let Some(cmd) = cmd_rx.recv().await {
                    match cmd {
                        crate::session::SessionCommand::SetClientMcpSeed { seed } => seen.push(Some(seed.disk_copy_names())),
                        crate::session::SessionCommand::UpdateMcpServers { respond_to, .. } => {
                            seen.push(None);
                            let _ = respond_to.send(Ok(()));
                            return seen;
                        }
                        _ => {}
                    }
                }
                seen
            });
            let params = serde_json::json!({ "sessionId": "sess-p141-upd", "mcpServers": forwarded });
            agent
                .ext_method(acp::ExtRequest::new(
                    "fuigo/session/update_mcp_servers",
                    std::sync::Arc::from(serde_json::value::to_raw_value(&params).unwrap()),
                ))
                .await
                .expect("update_mcp_servers");
            let seen = tokio::time::timeout(std::time::Duration::from_secs(5), actor)
                .await
                .expect("the actor never got the update")
                .unwrap();
            // Before the update (Astra P141 r2): a plugin reload handled while MCP initializes must see the new seed.
            assert_eq!(seen, [Some(vec!["p141-upd".to_owned()]), None], "the actor's seed is not the admitted set, handed over first");
        })
        .await;
    let stored = agent.resident_handle(&sid).expect("resident").initial_client_mcp_servers.disk_copy_names();
    assert_eq!(stored, ["p141-upd"], "the handle's seed is not the admitted set");
}
