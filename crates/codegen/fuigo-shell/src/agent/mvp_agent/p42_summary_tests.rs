//! P42: the session-summary (title) client is built straight from the primary sampling config, never
//! through `reconstruct_full_config`, so it needs its own send-time re-check (audit H1).
use super::*;
use crate::auth::{AuthManager, AuthMode, FuigoAuth, FuigoComConfig};
use crate::test_support::session_wire::{CONFIGURED_HOST, SessionWire, token_arrived};

const TOKEN: &str = "p42-summary-session-token-0b7e";
const MODULE: &str = "agent::mvp_agent::p42_summary_tests::";

#[test]
fn p42_wire_summary_client_fallback_rechecks_the_buffered_token() {
    if fuigo_test_support::env::fresh_process_home(&format!(
        "{MODULE}p42_wire_summary_client_fallback_rechecks_the_buffered_token"
    ))
    .is_none()
    {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        let mut wire = SessionWire::start().await;
        // Point the aux fallback's inference base at a refused destination too, so the summary client
        // falls back to (a clone of) the primary config — the path the audit found unchecked.
        // SAFETY: fresh single-test process, before any config is built.
        unsafe { std::env::set_var("FUIGO_API_BASE_URL", wire.loopback_url()) };
        crate::agent::config::Config::install_test_trusted_origins();
        let dir = tempfile::tempdir().unwrap();
        let am = std::sync::Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
        am.hot_swap(FuigoAuth {
            key: TOKEN.into(),
            auth_mode: AuthMode::Oidc,
            refresh_token: Some("rt".into()),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            ..FuigoAuth::test_default()
        });
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let agent = MvpAgent::new(
            GatewaySender::new(tx),
            &crate::agent::config::Config::default(),
            am,
            None,
        )
        .expect("agent builds");
        for (base, ok) in [
            (wire.loopback_url(), false),
            ("http://api.fluxrouter.ai/v1".to_string(), false),
            ("https://api.fluxrouter.ai/v1".to_string(), true),
        ] {
            let primary = fuigo_sampler::SamplerConfig {
                api_key: Some(TOKEN.into()),
                base_url: base.clone(),
                model: "p42-primary".into(),
                force_http1: true,
                max_retries: Some(0),
                ..Default::default()
            };
            let (client, _model) = agent.build_summary_client(&primary).expect("summary client");
            let request = fuigo_sampling_types::ConversationRequest {
                items: vec![fuigo_sampling_types::conversation::ConversationItem::user("p42")],
                ..Default::default()
            };
            let _ = client.conversation(request).await;
            let seen = wire.observed().await;
            if ok {
                assert!(
                    seen.iter().any(|o| o.target.starts_with(&format!("https://{CONFIGURED_HOST}"))
                        && o.authorization.as_deref() == Some(&format!("Bearer {TOKEN}"))),
                    "{base}: {seen:?}"
                );
            } else {
                assert!(!seen.is_empty(), "{base}: the summary request must arrive");
                assert!(!token_arrived(&seen, TOKEN), "{base}: {seen:?}");
            }
        }
    });
}
