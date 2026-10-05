//! P125: a TUI session is synced to a relay FluxRouter does not operate only when the user opted in to its origin, and
//! a refusal is shown to the TUI (`fuigo/relay/refused`), not only logged.
//!
//! Through the real session setup (`MvpAgent::start_relay_sync`, which `session/new` and `session/load` call) with a
//! gateway receiver standing in for the client. Runs alone in its own process (the opt-in is read from
//! `$FUIGO_HOME/config.toml` and the environment).

use std::time::Duration;

use fuigo_acp_lib::AcpClientMessage;
use fuigo_test_support::EnvGuard;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::agent::config::{AgentMode, Config as AgentConfig};
use crate::agent::relay_opt_in::TRUSTED_RELAY_ORIGINS_ENV;

const TEST: &str = "agent::mvp_agent::tests::p125_relay_sync_tests::a_tui_session_on_an_untrusted_relay_is_not_synced_and_the_tui_is_told";
const RELAY_URL: &str = "wss://relay.example.test/ws";
const RELAY_ORIGIN: &str = "https://relay.example.test";

/// Every `fuigo/relay/refused` the client has been sent so far (each acknowledged).
async fn refusals(rx: &mut UnboundedReceiver<AcpClientMessage>, wait: Duration) -> Vec<serde_json::Value> {
    let mut found = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Some(msg)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        if let AcpClientMessage::ExtNotification(args) = msg {
            if &*args.request.method == crate::agent::relay_opt_in::RELAY_REFUSED_METHOD {
                found.push(serde_json::from_str(args.request.params.get()).unwrap());
            }
            let _ = args.response_tx.send(Ok(()));
        }
    }
    found
}

#[test]
fn a_tui_session_on_an_untrusted_relay_is_not_synced_and_the_tui_is_told() {
    let Some(_home) = fuigo_test_support::env::fresh_process_home(TEST) else {
        return;
    };
    let _env = [
        EnvGuard::set("FUIGO_RELAY_SYNC_ENABLED", "true"),
        EnvGuard::unset(TRUSTED_RELAY_ORIGINS_ENV),
        EnvGuard::set("FUIGO_TELEMETRY_ENABLED", "false"),
    ];
    crate::auth::set_test_oauth2_issuer(crate::auth::GROK_OAUTH2_ISSUER);
    crate::agent::config::Config::install_test_trusted_origins();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let temp = tempfile::tempdir().unwrap();
        let mut cfg = AgentConfig {
            mode: AgentMode::Tui,
            ..Default::default()
        };
        cfg.fuigo_com_config.fuigo_ws_url = RELAY_URL.to_owned();
        let auth_manager = std::sync::Arc::new(crate::auth::AuthManager::new(
            temp.path(),
            crate::auth::FuigoComConfig::default(),
        ));
        auth_manager.hot_swap(crate::auth::FuigoAuth {
            auth_mode: crate::auth::AuthMode::Oidc,
            oidc_issuer: Some(crate::auth::GROK_OAUTH2_ISSUER.to_string()),
            ..crate::auth::FuigoAuth::test_default()
        });
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let agent = crate::agent::mvp_agent::MvpAgent::new(
            crate::agent::mvp_agent::GatewaySender::new(tx),
            &cfg,
            auth_manager,
            None,
        )
        .expect("agent");
        let sid = agent_client_protocol::SessionId::new("p125-sync-session");
        let info = crate::session::info::Info {
            id: sid.clone(),
            cwd: "/tmp".to_string(),
        };

        // No opt-in: no sync, and the TUI is told which relay, why, and how to trust it.
        assert!(
            agent.start_relay_sync(&sid, &info).is_none(),
            "a session was synced to a relay no opt-in names"
        );
        let told = refusals(&mut rx, Duration::from_millis(500)).await;
        assert_eq!(told.len(), 1, "the TUI is told once: {told:?}");
        assert_eq!(told[0]["origin"], RELAY_ORIGIN);
        assert_eq!(told[0]["use"], "sync");
        assert_eq!(told[0]["sessionId"], "p125-sync-session");
        let message = told[0]["message"].as_str().unwrap();
        for needle in [
            RELAY_ORIGIN,
            "FluxRouter does not operate it",
            "trusted_origins = [\"https://relay.example.test\"]",
            "FUIGO_TRUSTED_RELAY_ORIGINS=https://relay.example.test",
        ] {
            assert!(message.contains(needle), "missing {needle:?}: {message}");
        }

        // Control: the same session, opted in through the environment, is synced and nobody is told of a refusal.
        let _opt_in = EnvGuard::set(TRUSTED_RELAY_ORIGINS_ENV, RELAY_ORIGIN);
        let sync = agent.start_relay_sync(&sid, &info);
        assert!(sync.is_some(), "an opted-in relay is synced to");
        let told = refusals(&mut rx, Duration::from_millis(500)).await;
        assert!(told.is_empty(), "an opted-in relay was reported as refused: {told:?}");
        drop(sync);
    });
    drop(local);
    drop(rt);
}
