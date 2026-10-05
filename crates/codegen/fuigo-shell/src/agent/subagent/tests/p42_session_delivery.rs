//! P42: the subagent session-token paths, proven on the wire (see the parent-session suite in
//! `session/acp_session_tests/p42_session_delivery_wire_tests.rs` for the harness rationale).
use super::*;
use crate::auth::{AuthManager, AuthMode, FuigoAuth, FuigoComConfig};
use crate::test_support::lsp_runtime::ctx_with_toggle;
use crate::test_support::session_wire::{CONFIGURED_HOST, Observed, SessionWire, token_arrived};
use std::collections::HashMap;

const TOKEN: &str = "p42-subagent-session-token-c4d1";
const CONFIGURED: &str = "https://api.fluxrouter.ai/v1";
const MODULE: &str = "agent::subagent::tests::p42_session_delivery::";

fn child(test: &str) -> bool {
    fuigo_test_support::env::fresh_process_home(&format!("{MODULE}{test}")).is_some()
}

fn run(f: impl std::future::Future<Output = ()>) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&rt, f);
}

fn manager() -> (tempfile::TempDir, std::sync::Arc<AuthManager>) {
    let dir = tempfile::tempdir().unwrap();
    let am = std::sync::Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
    am.hot_swap(FuigoAuth {
        key: TOKEN.into(),
        auth_mode: AuthMode::Oidc,
        refresh_token: Some("rt".into()),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        ..FuigoAuth::test_default()
    });
    (dir, am)
}

/// A session-based subagent context over `am`, whose parent session runs `model` at `base_url`
/// with `buffered` in its chat-state credentials.
fn session_ctx(
    am: std::sync::Arc<AuthManager>,
    base_url: &str,
    model: &str,
    buffered: Option<&str>,
) -> SubagentSpawnContext {
    crate::agent::config::Config::install_test_trusted_origins();
    let mut ctx = ctx_with_toggle(HashMap::new());
    ctx.auth_manager = am;
    ctx.auth_method_id = acp::AuthMethodId::new("cached_token");
    let parent = spawn_test_parent_chat_state(model);
    let mut cfg = test_sampling_config(model);
    cfg.base_url = base_url.to_string();
    parent.update_sampling_config(cfg);
    parent.update_credentials(fuigo_chat_state::Credentials {
        api_key: buffered.map(str::to_owned),
        auth_type: fuigo_chat_state::AuthType::SessionToken,
        ..Default::default()
    });
    ctx.parent_chat_state = Some(parent);
    ctx
}

async fn send(cfg: fuigo_sampler::SamplerConfig) {
    let mut cfg = cfg;
    cfg.force_http1 = true;
    cfg.max_retries = Some(0);
    let client = fuigo_sampler::SamplingClient::new(cfg).expect("sampler builds");
    let request = fuigo_sampling_types::ConversationRequest {
        items: vec![fuigo_sampling_types::conversation::ConversationItem::user("p42")],
        ..Default::default()
    };
    let _ = client.conversation(request).await;
}

fn withheld(seen: &[Observed], what: &str) {
    assert!(!seen.is_empty(), "{what}: request must arrive");
    assert!(!token_arrived(seen, TOKEN), "{what}: session token leaked: {seen:?}");
}

fn delivered(seen: &[Observed], what: &str) {
    assert!(
        seen.iter().any(|o| o.target.starts_with(&format!("https://{CONFIGURED_HOST}"))
            && o.authorization.as_deref() == Some(&format!("Bearer {TOKEN}"))),
        "{what}: {seen:?}"
    );
}

/// Inherited parent config at a refused destination: the resolver is gated by the one predicate (was the broad matcher).
#[test]
fn p42_wire_subagent_inherited_resolver_follows_the_one_predicate() {
    if !child("p42_wire_subagent_inherited_resolver_follows_the_one_predicate") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        let (_d, am) = manager();
        for (base, ok) in [
            (wire.loopback_url(), false),
            ("http://api.fluxrouter.ai/v1".to_string(), false),
            ("https://api.fluxrouter.ai:8443/v1".to_string(), false),
            (CONFIGURED.to_string(), true),
        ] {
            let ctx = session_ctx(am.clone(), &base, "", None);
            let (cfg, _) = read_parent_sampling_config(&ctx).await;
            send(cfg).await;
            let seen = wire.observed().await;
            if ok { delivered(&seen, &base) } else { withheld(&seen, &base) }
        }
    });
}

/// The parent's buffered session token is re-checked against the subagent's destination (live and fallback arms).
#[test]
fn p42_wire_subagent_inherited_buffered_token_is_rechecked() {
    if !child("p42_wire_subagent_inherited_buffered_token_is_rechecked") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        let (_d, am) = manager();
        let ctx = session_ctx(am.clone(), &wire.loopback_url(), "", Some(TOKEN));
        let (cfg, _) = read_parent_sampling_config(&ctx).await;
        send(cfg).await;
        withheld(&wire.observed().await, "live arm");

        let mut ctx = session_ctx(am, &wire.loopback_url(), "", None);
        ctx.parent_chat_state = None;
        ctx.sampling_config.base_url = wire.loopback_url();
        ctx.sampling_config.api_key = Some(TOKEN.into());
        let (cfg, _) = read_parent_sampling_config(&ctx).await;
        send(cfg).await;
        withheld(&wire.observed().await, "spawn-context fallback arm");
    });
}

/// A model-override subagent on a model with no own credential is `NotByok`, which used to attach the resolver anywhere.
#[test]
fn p42_wire_subagent_model_override_notbyok_follows_the_one_predicate() {
    if !child("p42_wire_subagent_model_override_notbyok_follows_the_one_predicate") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        let (_d, am) = manager();
        for (base, ok) in [(wire.loopback_url(), false), (CONFIGURED.to_string(), true)] {
            let mut ctx = session_ctx(am.clone(), CONFIGURED, "parent", None);
            ctx.auth = am.current_or_expired();
            let mut entry = test_model_entry("p42-override");
            entry.info.base_url = base.clone();
            ctx.available_models.insert("p42-override".into(), entry);
            let (cfg, _) = resolve_model_override_to_config("p42-override", &ctx).expect("resolves");
            send(cfg).await;
            let seen = wire.observed().await;
            if ok { delivered(&seen, &base) } else { withheld(&seen, &base) }
        }
    });
}
