//! These tests run the real turn loop against a mock server that 401s unauthenticated requests and 200s a fresh bearer.
//! A fail-closed (credential-less) 401 must not consume `AuthRetrySchedule` budget.
//! That was the failure seen in the field: each sleep cycle burned one slot.
//! Credentialed 401s stop after at most one session refresh and one resubmit.
//! A2.1: a failed refresh ends the prompt; one successful session refresh permits one resubmit.

use super::support::*;
use super::*;
use crate::auth::{AuthManager, AuthMode, FuigoAuth, FuigoComConfig};
use fuigo_test_support::{MockInferenceServer, MockModelEntry, ScriptedResponse};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// P42: since session-token delivery has one predicate, an `http://` loopback mock never receives the session
/// token. Each test therefore runs in a fresh process (the proxy and CA variables latch at the first HTTP
/// client) and reaches its mock through [`crate::test_support::session_wire::SessionFront`] as the configured
/// origin `https://api.fluxrouter.ai/v1`. The trust set is the production predicate; nothing is overridden.
static P42_FRONT: std::sync::OnceLock<crate::test_support::session_wire::SessionFront> =
    std::sync::OnceLock::new();

/// The configured-origin spelling of `server`'s URL (the front was started by [`p42_child`]).
async fn p42_front_url(server: &MockInferenceServer) -> String {
    crate::agent::config::Config::install_test_trusted_origins();
    P42_FRONT
        .get()
        .expect("p42_child starts the front before the test body")
        .front(&server.url())
}

/// `true` in the fresh child process that runs `test`'s body; the parent only checks the child passed.
/// In the child, the front starts here, before anything can build an HTTP client or load the TLS roots.
fn p42_child(test: &str) -> bool {
    let child = fuigo_test_support::env::fresh_process_home(&format!(
        "session::acp_session::auth_retry_budget_tests::{test}"
    ))
    .is_some();
    if child {
        P42_FRONT.get_or_init(crate::test_support::session_wire::SessionFront::start);
        // Real clock (P42): the front is real network I/O, which a paused clock cannot coexist with. The
        // production ladders run unchanged but every paced sleep is divided by this factor; the test-side waits
        // below use the same `paced`, so every ratio the assertions rely on is preserved.
        crate::session::acp_session::auth_retry::TEST_PACE_DIVISOR
            .store(P42_PACE_DIVISOR, std::sync::atomic::Ordering::Relaxed);
    }
    child
}

/// See [`p42_child`].
const P42_PACE_DIVISOR: u32 = 100;

/// A test-side wait or hang cap, on the same scale as the production paced sleeps.
fn paced(d: Duration) -> Duration {
    crate::session::acp_session::auth_retry::paced(d)
}

/// The token the mock server accepts and the refresher mints on success.
const FRESH_TOKEN: &str = "refreshed-test-token";

/// With `fail_pre_request`, mimics the post-wake sequence: `PreRequest` refreshes fail (the send
/// goes out fail-closed) while 401 recovery mints [`FRESH_TOKEN`] for `mint_ttl` — a TTL inside
/// the pre-request buffer (< 5 min) stays wire-valid yet keeps later prepares observable in `calls`.
struct WakeGapRefresher {
    calls: Arc<AtomicU32>,
    fail_pre_request: bool,
    mint_ttl: chrono::Duration,
}

#[async_trait::async_trait]
impl crate::auth::refresh::TokenRefresher for WakeGapRefresher {
    async fn refresh(
        &self,
        reason: crate::auth::refresh::RefreshReason,
    ) -> crate::auth::refresh::RefreshOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_pre_request && reason == crate::auth::refresh::RefreshReason::PreRequest {
            return crate::auth::refresh::RefreshOutcome::TransientFailure {
                message: "simulated post-wake network gap".to_string(),
            };
        }
        crate::auth::refresh::RefreshOutcome::success(FuigoAuth {
            key: FRESH_TOKEN.to_string(),
            auth_mode: AuthMode::Oidc,
            refresh_token: Some("rt-new".into()),
            expires_at: Some(chrono::Utc::now() + self.mint_ttl),
            ..FuigoAuth::test_default()
        })
    }
}

/// `(tempdir, manager)` with a hard-expired OIDC token, so the wire-valid resolver has nothing to stamp until the refresher succeeds.
/// The tempdir must outlive the manager (auth.json path).
fn expired_auth_manager(
    refresher: Arc<dyn crate::auth::refresh::TokenRefresher>,
) -> (tempfile::TempDir, Arc<AuthManager>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let am = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
    am.hot_swap(FuigoAuth {
        key: "initial-test-key".into(),
        auth_mode: AuthMode::Oidc,
        refresh_token: Some("rt".into()),
        expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        ..FuigoAuth::test_default()
    });
    am.set_refresher(refresher);
    (dir, am)
}

/// `fuigo/session_notification` payloads the client was sent.
type FuigoUpdates = Arc<parking_lot::Mutex<Vec<serde_json::Value>>>;

fn drain_gateway(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
) -> FuigoUpdates {
    let captured = FuigoUpdates::default();
    let sink = captured.clone();
    tokio::task::spawn_local(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                    let _ = args.response_tx.send(Ok(()));
                }
                fuigo_acp_lib::AcpClientMessage::ExtNotification(args) => {
                    if let Ok(value) = serde_json::from_str(args.params.get()) {
                        sink.lock().push(value);
                    }
                }
                _ => {}
            }
        }
    });
    captured
}

/// `(error_type, message)` of the turn's terminal `retryState`, if the client was told about one.
fn terminal_failure(updates: &FuigoUpdates) -> Option<(String, String)> {
    updates.lock().iter().find_map(|value| {
        let update = value.get("update")?;
        if update.get("sessionUpdate")? != "retry_state" || update.get("type")? != "failed" {
            return None;
        }
        Some((
            update.get("error_type")?.as_str()?.to_owned(),
            update.get("message")?.as_str()?.to_owned(),
        ))
    })
}

/// `(attempt, max_retries, reason)` of every `retryState` Retrying update the
/// client was sent, in order.
fn retrying_updates(updates: &FuigoUpdates) -> Vec<(u32, u32, String)> {
    updates
        .lock()
        .iter()
        .filter_map(|value| {
            let update = value.get("update")?;
            if update.get("sessionUpdate")? != "retry_state" || update.get("type")? != "retrying" {
                return None;
            }
            Some((
                update.get("attempt")?.as_u64()? as u32,
                update.get("max_retries")?.as_u64()? as u32,
                update.get("reason")?.as_str()?.to_owned(),
            ))
        })
        .collect()
}

/// Assert the full Retrying stream: attempts count 1..=`expected_len`, each carrying
/// `expected_max` and every reason needle (the retry-copy pin).
fn assert_retrying(
    updates: &FuigoUpdates,
    expected_len: usize,
    expected_max: u32,
    reason_needles: &[&str],
) {
    let retrying = retrying_updates(updates);
    assert_eq!(
        retrying.len(),
        expected_len,
        "Retrying update count: {retrying:?}"
    );
    for (i, (attempt, max_retries, reason)) in retrying.iter().enumerate() {
        assert_eq!(
            *attempt,
            (i + 1) as u32,
            "attempts must count consecutively"
        );
        assert_eq!(
            *max_retries, expected_max,
            "every Retrying must carry this path's budget: {retrying:?}"
        );
        for needle in reason_needles {
            assert!(reason.contains(needle), "retry copy regressed: {reason}");
        }
    }
}

/// Shape options for [`session_token_actor`].
#[derive(Default)]
struct ActorShape {
    parent_message_child: bool,
    /// Shape the actor like a spawned subagent turn — the only shape that
    /// gets a 429 wait budget.
    is_subagent: bool,
    /// Budgeted workflow child (`task_output_token_budget` grant) — excluded from the park.
    task_output_budget: Option<u64>,
    /// Flip the `uncharged_401_park` kill switch off.
    park_disabled: bool,
}

/// Actor wired for session-token auth against the mock server: a real sampler, the `cached_token` method, and the supplied auth manager.
/// `NotByok` model facts keep the session-token gate active against the loopback URL.
async fn session_token_actor(
    server: &MockInferenceServer,
    auth_manager: Arc<AuthManager>,
    shape: ActorShape,
) -> (Arc<SessionActor>, FuigoUpdates) {
    let front_url = p42_front_url(server).await;
    let sampling_cfg = fuigo_sampler::SamplerConfig {
        base_url: front_url.clone(),
        model: "test".to_string(),
        api_backend: fuigo_sampler::ApiBackend::Responses,
        context_window: 256_000,
        max_retries: Some(0),
        idle_timeout_secs: Some(30),
        ..Default::default()
    };
    let (sampler_event_tx, sampler_event_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_sampler::SamplingEvent>();
    let sampler_handle = fuigo_sampler::SamplerActor::spawn(
        sampling_cfg,
        fuigo_sampler::RetryPolicy {
            max_retries: 0,
            rate_limit_retry_threshold: 0,
            ..Default::default()
        },
        sampler_event_tx,
    );

    let (gateway_tx, gateway_rx) = tokio::sync::mpsc::unbounded_channel();
    let fuigo_updates = drain_gateway(gateway_rx);
    let (persistence_tx, persistence_rx) = tokio::sync::mpsc::unbounded_channel();
    drain_persistence(persistence_rx);

    let mut actor = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
    actor.sampler_handle = sampler_handle;
    actor.auth_manager = Some(auth_manager);
    if shape.parent_message_child { actor.startup_hints.parent_session_id = Some("parent-test".into()); }
    actor.auth_method_id = test_auth_method_id("cached_token");
    if shape.is_subagent {
        actor.startup_hints.is_subagent = true;
    }
    if shape.park_disabled {
        actor.uncharged_401_park_enabled = false;
    }
    if let Some(grant) = shape.task_output_budget {
        actor.tool_context.task_output_token_budget = Some(
            crate::tools::tool_context::TaskOutputTokenBudget::limited(grant),
        );
    }

    let mut cfg = actor
        .chat_state_handle
        .get_sampling_config()
        .await
        .expect("test actor has sampling config");
    cfg.base_url = front_url.clone();
    cfg.api_backend = fuigo_sampling_types::ApiBackend::Responses;
    cfg.model = "test".to_string();
    actor.chat_state_handle.update_sampling_config(cfg);
    let mut creds = actor.chat_state_handle.get_credentials().await;
    creds.api_key = None;
    creds.auth_type = fuigo_chat_state::AuthType::SessionToken;
    actor.chat_state_handle.update_credentials(creds);

    // Definite NotByok: the session-token gate must stay active against the loopback mock URL (an `Unknown` would demand a configured API origin)
    actor
        .model_auth_memo
        .replace(Some(crate::session::acp_session::ModelAuthMemo {
            model_id: "test".to_string(),
            facts: crate::agent::config::ModelAuthFacts {
                byok: crate::agent::auth_method::ModelByok::NotByok,
                auth_scheme: Default::default(),
            },
            provider: None,
        }));

    actor
        .workspace_ops
        .bind_local_session(
            &actor.session_id_string(),
            actor.tool_context.cwd.as_path().to_path_buf(),
            actor.tool_context.hunk_tracker_handle.clone(),
            actor.agent.borrow().tool_bridge().toolset(),
            None,
            actor.tool_context.peer_influence.clone(),
        )
        .expect("bind_local_session");

    let actor = Arc::new(actor);
    {
        let drainer = actor.clone();
        let mut sampler_event_rx = sampler_event_rx;
        tokio::task::spawn_local(async move {
            while let Some(event) = sampler_event_rx.recv().await {
                drainer.handle_sampling_event(event).await;
            }
        });
    }
    (actor, fuigo_updates)
}

async fn run_prompt(
    actor: &Arc<SessionActor>,
    prompt_id: &str,
) -> Result<crate::session::commands::PromptTurnOk, acp::Error> {
    run_prompt_with_cap(actor, prompt_id, 3600).await
}

/// [`run_prompt`] with an explicit hang cap, scaled like the paced sleeps; caps are anti-hang bounds only
/// and never assert timing.
async fn run_prompt_with_cap(
    actor: &Arc<SessionActor>,
    prompt_id: &str,
    cap_secs: u64,
) -> Result<crate::session::commands::PromptTurnOk, acp::Error> {
    let prompt_blocks = vec![acp::ContentBlock::Text(acp::TextContent::new(
        "hello".to_string(),
    ))];
    // Hang guard, not a latency assertion: only a wedged turn reaches it
    // P42: real clock, paced sleeps scaled by `P42_PACE_DIVISOR`; the cap is scaled the same way (floor 120 s)
    tokio::time::timeout(
        paced(Duration::from_secs(cap_secs)).max(Duration::from_secs(120)),
        actor.handle_prompt(
            prompt_id,
            prompt_blocks,
            PromptMode::Agent,
            None,
            None,
            None,
            None,
            true,
            /* send_now */ false,
            None,
            None,
            None,
        ),
    )
    .await
    .expect("turn must finish within timeout")
}

/// The turn future needs a session-sized stack (spawn.rs: 8 MiB); default test stacks overflow.
fn on_session_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(test)
        .expect("spawn test thread")
        .join()
        .expect("test thread panicked");
}

fn run_current_thread<F: std::future::Future>(paused: bool, fut: impl FnOnce() -> F) {
    let mut builder = tokio::runtime::Builder::new_current_thread();
    builder.enable_all();
    if paused {
        builder.start_paused(true);
    }
    let rt = builder.build().expect("test runtime");
    let local = tokio::task::LocalSet::new();
    rt.block_on(local.run_until(async move {
        fut().await;
    }));
}

/// `/responses` requests the mock server received, in order.
fn inference_requests(
    server: &MockInferenceServer,
) -> Vec<fuigo_test_support::mock_server::LogEntry> {
    server
        .requests()
        .into_iter()
        .filter(|r| r.path.contains("/responses"))
        .collect()
}

/// Exercises the current A2.1 prompt boundary against the real turn loop.
#[test]
fn fail_closed_401_is_uncharged_and_turn_survives() {
    if !p42_child("fail_closed_401_is_uncharged_and_turn_survives") {
        return;
    }
    on_session_stack(|| {
        run_current_thread(false, || async {
            let server = MockInferenceServer::start_with_required_auth(
                vec![MockModelEntry::new("test")],
                FRESH_TOKEN,
            )
            .await
            .expect("mock inference server");

            let calls = Arc::new(AtomicU32::new(0));
            // Pre-send refreshes fail like a post-wake network gap, so the first send goes out fail-closed; the 401-recovery refresh succeeds
            let refresher = Arc::new(WakeGapRefresher {
                calls: calls.clone(),
                fail_pre_request: true,
                mint_ttl: chrono::Duration::hours(1),
            });
            let (_dir, am) = expired_auth_manager(refresher);
            let (actor, updates) = session_token_actor(&server, am, ActorShape::default()).await;

            let outcome = run_prompt(&actor, "auth-retry-budget-fail-closed").await;
            assert!(
                outcome.is_ok(),
                "fail-closed 401 must not fail the turn: {outcome:?}"
            );

            let inference = inference_requests(&server);
            assert!(
                inference.len() >= 2,
                "expected the fail-closed send plus the resubmit; got {}",
                inference.len()
            );
            assert_eq!(
                inference[0].authorization, None,
                "first send must carry no Authorization header"
            );
            assert_eq!(
                inference.last().unwrap().authorization.as_deref(),
                Some(&format!("Bearer {FRESH_TOKEN}") as &str),
                "resubmit must carry the freshly refreshed bearer"
            );
            assert!(
                calls.load(Ordering::SeqCst) >= 2,
                "both the failing pre-flight and the recovery refresh must run"
            );
            // The named invariant: the fail-closed 401 rode the uncharged budget, not a charged slot.
            assert_retrying(
                &updates,
                1,
                AuthRetrySchedule::MAX_UNCHARGED_RESUBMITS,
                &["carried no credential"],
            );
        });
    });
}

/// One recovered fail-closed 401 prompt (the [`WakeGapRefresher`] wake sequence, a short mint TTL so every
/// refresh-driving prepare stays observable); returns the refresher call count.
fn recovered_fail_closed_401_refresh_calls(park_disabled: bool) -> u32 {
    let calls = Arc::new(AtomicU32::new(0));
    let observed = calls.clone();
    on_session_stack(move || {
        run_current_thread(false, || async move {
            let server = MockInferenceServer::start_with_required_auth(
                vec![MockModelEntry::new("test")],
                FRESH_TOKEN,
            )
            .await
            .expect("mock inference server");
            // The minted TTL sits inside the pre-request buffer: wire-valid for the
            // resubmit, yet every refresh-driving prepare stays observable in `calls`.
            let refresher = Arc::new(WakeGapRefresher {
                calls: calls.clone(),
                fail_pre_request: true,
                mint_ttl: chrono::Duration::minutes(4),
            });
            let (_dir, am) = expired_auth_manager(refresher);
            let (actor, updates) = session_token_actor(
                &server,
                am,
                ActorShape {
                    park_disabled,
                    ..Default::default()
                },
            )
            .await;

            let outcome = run_prompt(&actor, "recovered-fail-closed").await;
            assert!(
                outcome.is_ok(),
                "recovered fail-closed 401s must not fail the turn (park_disabled={park_disabled}): {outcome:?}"
            );
            assert_eq!(
                inference_requests(&server)
                    .last()
                    .expect("at least one send")
                    .authorization
                    .as_deref(),
                Some(&format!("Bearer {FRESH_TOKEN}") as &str),
                "resubmit must carry the recovered bearer"
            );
            assert!(
                terminal_failure(&updates).is_none(),
                "a surviving turn must not report a terminal retryState"
            );
        });
    });
    observed.load(Ordering::SeqCst)
}

/// Exercises the current A2.1 prompt boundary against the real turn loop.
#[test]
fn park_disabled_recovered_401_still_resubmits() {
    if !p42_child("park_disabled_recovered_401_still_resubmits") {
        return;
    }
    let parked = recovered_fail_closed_401_refresh_calls(false);
    let unparked = recovered_fail_closed_401_refresh_calls(true);
    assert!(
        unparked > parked,
        "flag off must restore every pre-park refresh attempt: park on {parked}, park off {unparked}"
    );
}

/// Exercises the current A2.1 prompt boundary against the real turn loop.
#[test]
fn authenticated_401_stops_after_one_refresh_and_resubmit() {
    if !p42_child("authenticated_401_stops_after_one_refresh_and_resubmit") { return; }
    on_session_stack(|| {
        run_current_thread(false, || async {
            let server = MockInferenceServer::start_with_required_auth(vec![MockModelEntry::new("test")], "never-issued-token").await.unwrap();
            let refresher = Arc::new(WakeGapRefresher { calls: Arc::new(AtomicU32::new(0)), fail_pre_request:false, mint_ttl:chrono::Duration::hours(1) });
            let (_dir, am) = expired_auth_manager(refresher);
            let (actor, updates) = session_token_actor(&server, am, ActorShape::default()).await;
            let error = run_prompt_with_cap(&actor, "one-refresh", 86_400).await.expect_err("second 401 is terminal");
            assert_eq!(error.data.unwrap()["upstream"]["http_status"],401);
            let requests = inference_requests(&server);
            assert_eq!(requests.len(), 2, "initial plus the sole resubmit");
            assert!(requests.iter().all(|r| r.authorization.as_deref()==Some(&format!("Bearer {FRESH_TOKEN}"))));
            assert!(terminal_failure(&updates).is_some());
            assert_eq!(actor.refusal_prompt.lock().unwrap().refreshes,1);
            assert_eq!(retrying_updates(&updates).len(),1);

        });
    });
}

/// Refresh-outage refresher: every refresh fails transiently, counting `ServerRejected` and
/// `PreRequest` attempts so tests pin that parked cycles dispatch neither. Recovery arrives
/// out-of-band (hot_swap + notify), the way production recovers.
#[derive(Default)]
struct DeferredRefreshNeverLands {
    server_rejected_calls: Arc<AtomicU32>,
    pre_request_calls: Arc<AtomicU32>,
}

#[async_trait::async_trait]
impl crate::auth::refresh::TokenRefresher for DeferredRefreshNeverLands {
    async fn refresh(
        &self,
        reason: crate::auth::refresh::RefreshReason,
    ) -> crate::auth::refresh::RefreshOutcome {
        match reason {
            crate::auth::refresh::RefreshReason::ServerRejected => {
                self.server_rejected_calls.fetch_add(1, Ordering::SeqCst);
            }
            crate::auth::refresh::RefreshReason::PreRequest => {
                self.pre_request_calls.fetch_add(1, Ordering::SeqCst);
            }
        }
        crate::auth::refresh::RefreshOutcome::TransientFailure {
            message: "refresh deferred: system sleep imminent".to_string(),
        }
    }
}

/// Re-authentication park announcements so far (Retrying updates for a 401, not transient 5xx retries).
fn reauth_parks(updates: &FuigoUpdates) -> usize {
    retrying_updates(updates)
        .iter()
        .filter(|(_, _, reason)| reason.contains("Re-authenticating"))
        .count()
}

/// Out-of-band recovery: a wire-valid token lands (and the refresh notify fires) once the turn has
/// announced `parks_for(after)` park cycles (`retryState` Retrying updates).
///
/// P42: these tests run on a real clock, where the first recovery dispatch costs real time, so a purely
/// time-based landing could beat the first parked resubmit. Landing on observed park cycles keeps the
/// sequence the assertions describe (credential-less send, parked resubmits, authenticated resubmit), with the
/// longer outage (`after` = 300 s) still producing proportionally more parked cycles than the short one (30 s).
fn land_fresh_token_after(actor: &Arc<SessionActor>, updates: &FuigoUpdates, after: Duration) {
    let parks = (after.as_secs() / 15).max(2) as usize;
    let updates = updates.clone();
    let waker = actor.auth_manager.clone().expect("actor has auth manager");
    tokio::task::spawn_local(async move {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        while reauth_parks(&updates) < parks && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        waker.hot_swap(FuigoAuth {
            key: FRESH_TOKEN.to_string(),
            auth_mode: AuthMode::Oidc,
            refresh_token: Some("rt-new".into()),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            ..FuigoAuth::test_default()
        });
        waker.refresh_notifier().notify_waiters();
    });
}

/// Exercises the current A2.1 prompt boundary against the real turn loop.
#[test]
fn failed_refresh_credential_less_401_parks_once_then_terminates() {
    if !p42_child("failed_refresh_credential_less_401_parks_once_then_terminates") { return; }
    on_session_stack(|| {
        run_current_thread(false, || async {
            let server = MockInferenceServer::start_with_required_auth(vec![MockModelEntry::new("test")], FRESH_TOKEN).await.unwrap();
            let refresher = Arc::new(DeferredRefreshNeverLands::default());
            let rejected = refresher.server_rejected_calls.clone();
            let preflight = refresher.pre_request_calls.clone();
            let (_dir, am) = expired_auth_manager(refresher);
            let (actor, updates) = session_token_actor(&server, am, ActorShape::default()).await;
            let error = run_prompt_with_cap(&actor, "bounded-refusal", 86_400).await.expect_err("failed refresh must terminate");
            assert_eq!(error.data.as_ref().unwrap()["upstream"]["http_status"], 401);
            assert_eq!(inference_requests(&server).len(), 2, "one parked credential-less resubmit");
            assert!(terminal_failure(&updates).is_some());
            assert_eq!(reauth_parks(&updates), 1, "the park counts as the sole resubmit");
            assert_eq!(actor.refusal_prompt.lock().unwrap().refreshes, 1);
            assert_eq!(actor.refusal_prompt.lock().unwrap().state, fuigo_sampling_types::refusal::PromptState::Terminal);
            let calls = (rejected.load(Ordering::SeqCst), preflight.load(Ordering::SeqCst));
            actor.prepare_sampler_for_turn().await;
            assert_eq!((rejected.load(Ordering::SeqCst), preflight.load(Ordering::SeqCst)), calls, "terminal prepares cannot refresh");

        });
    });
}

/// Exercises the current A2.1 prompt boundary against the real turn loop.
#[test]
fn failed_refresh_parked_resubmit_5xx_is_terminal() {
    if !p42_child("failed_refresh_parked_resubmit_5xx_is_terminal") { return; }
    on_session_stack(|| {
        run_current_thread(false, || async {
            let server = MockInferenceServer::start_with_required_auth(vec![MockModelEntry::new("test")], FRESH_TOKEN).await.unwrap();
            let refresher = Arc::new(DeferredRefreshNeverLands::default());
            let rejected = refresher.server_rejected_calls.clone();
            let preflight = refresher.pre_request_calls.clone();
            let (_dir, am) = expired_auth_manager(refresher);
            let (actor, updates) = session_token_actor(&server, am, ActorShape::default()).await;
            server.enqueue_response("/v1/responses", ScriptedResponse::json(401, serde_json::json!({"error":"missing API key"})));
            server.enqueue_response("/v1/responses", ScriptedResponse::json(502, serde_json::json!({"error":"bad gateway"})));
            let error = run_prompt_with_cap(&actor, "bounded-refusal", 86_400).await.expect_err("failed refresh must terminate");
            assert_eq!(error.data.as_ref().unwrap()["upstream"]["http_status"], 502);
            assert_eq!(inference_requests(&server).len(), 2, "one parked credential-less resubmit");
            assert!(terminal_failure(&updates).is_some());
            assert_eq!(reauth_parks(&updates), 1, "the park counts as the sole resubmit");
            assert_eq!(actor.refusal_prompt.lock().unwrap().refreshes, 1);
            assert_eq!(actor.refusal_prompt.lock().unwrap().state, fuigo_sampling_types::refusal::PromptState::Terminal);
            let calls = (rejected.load(Ordering::SeqCst), preflight.load(Ordering::SeqCst));
            actor.prepare_sampler_for_turn().await;
            assert_eq!((rejected.load(Ordering::SeqCst), preflight.load(Ordering::SeqCst)), calls, "terminal prepares cannot refresh");

        });
    });
}

/// Exercises the current A2.1 prompt boundary against the real turn loop.
#[test]
fn parked_429_wait_does_not_drive_refreshes() {
    if !p42_child("parked_429_wait_does_not_drive_refreshes") {
        return;
    }
    on_session_stack(|| {
        run_current_thread(false, || async {
            let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")])
                .await
                .expect("mock inference server");
            // One 429 rung, then the default 200: exactly one paced wait.
            server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::json(429, serde_json::json!({ "error": "rate limited" })),
            );

            let refresher = Arc::new(DeferredRefreshNeverLands::default());
            let pre_request_calls = refresher.pre_request_calls.clone();
            let server_rejected_calls = refresher.server_rejected_calls.clone();
            let (_dir, am) = expired_auth_manager(refresher);
            let (actor, _updates) = session_token_actor(
                &server,
                am,
                ActorShape {
                    is_subagent: true,
                    ..Default::default()
                },
            )
            .await;

            let request = super::rate_limit_backoff_tests::conversation_request(&actor).await;
            let mut budget = actor.rate_limit_wait_budget(None);
            let outcome = tokio::time::timeout(
                Duration::from_secs(300),
                actor.run_turn_via_sampler(
                    request,
                    &mut budget,
                    transient_state(0, true),
                    false,
                    TurnParkState::Parked,
                ),
            )
            .await
            .expect("turn must finish within timeout");
            assert!(outcome.is_err(), "Flux unknown 429 is terminal even for a parked subagent");
            assert_eq!(budget.attempts_used(), 0);
            assert_eq!(inference_requests(&server).len(),1);
            // The expired token makes every prepare observable: a re-prepare
            // during the wait would dispatch at least one preflight refresh.
            assert_eq!(
                pre_request_calls.load(Ordering::SeqCst),
                0,
                "a parked iteration's 429 waits must not drive preflight refreshes"
            );
            assert_eq!(
                server_rejected_calls.load(Ordering::SeqCst),
                0,
                "no recovery dispatch may run inside the rate-limit wait loop"
            );
        });
    });
}

/// Exercises the current A2.1 prompt boundary against the real turn loop.
#[test]
fn parked_turn_does_not_respawn_two_pass_prefire() {
    if !p42_child("parked_turn_does_not_respawn_two_pass_prefire") {
        return;
    }
    on_session_stack(|| {
        run_current_thread(false, || async {
            let server = MockInferenceServer::start_with_required_auth(
                vec![MockModelEntry::new("test")],
                FRESH_TOKEN,
            )
            .await
            .expect("mock inference server");

            let refresher = Arc::new(DeferredRefreshNeverLands::default());
            let (_dir, am) = expired_auth_manager(refresher);
            let (actor, updates) = session_token_actor(&server, am, ActorShape::default()).await;

            // Two-pass on, usage in the prefire band: 77% of 100k vs the 85%
            // threshold (the band opens at threshold − 10).
            {
                let mut agent_slot = actor.agent.borrow_mut();
                let agent = &*agent_slot;
                let mut policy = agent.compaction_policy().clone();
                policy.two_pass_enabled = true;
                let rebuilt = fuigo_agent::Agent::new(
                    agent.definition().clone(),
                    agent.prompt_context().clone(),
                    agent.system_prompt().to_string(),
                    std::sync::Arc::clone(agent.tool_bridge()),
                    agent.reminder_policy().clone(),
                    policy,
                    vec![],
                    false,
                );
                *agent_slot = rebuilt;
            }
            let mut cfg = actor
                .chat_state_handle
                .get_sampling_config()
                .await
                .expect("test actor has sampling config");
            cfg.context_window = std::num::NonZeroU64::new(100_000).expect("non-zero");
            actor.chat_state_handle.update_sampling_config(cfg);
            // ≥4 items so pass-1 survives its too-small check and reaches the auth-driving stage.
            use fuigo_sampling_types::ConversationItem;
            actor.chat_state_handle.replace_conversation(vec![
                ConversationItem::system("you are a coding agent"),
                ConversationItem::user("q1"),
                ConversationItem::assistant("a1"),
                ConversationItem::user("q2"),
                ConversationItem::assistant("a2"),
            ]);
            actor.chat_state_handle.record_token_usage(77_000);
            land_fresh_token_after(&actor, &updates, Duration::from_secs(30));

            let outcome = run_prompt_with_cap(&actor, "parked-prefire", 86_400).await;
            assert!(outcome.is_err(), "failed refresh must terminate: {outcome:?}");

            // Pass-1 sends: /responses requests without the foreground turn header.
            let pass1_sends = inference_requests(&server)
                .into_iter()
                .filter(|r| r.header("x-fuigo-turn-idx").is_none())
                .count();
            assert!(
                pass1_sends <= 1,
                "parked cycles must not re-spawn prefire pass-1; got {pass1_sends} pass-1 sends"
            );
        });
    });
}

/// Exercises the current A2.1 prompt boundary against the real turn loop.
#[test]
fn parked_turn_past_compact_threshold_does_not_auto_compact() {
    if !p42_child("parked_turn_past_compact_threshold_does_not_auto_compact") {
        return;
    }
    on_session_stack(|| {
        run_current_thread(false, || async {
            let server = MockInferenceServer::start_with_required_auth(
                vec![MockModelEntry::new("test")],
                FRESH_TOKEN,
            )
            .await
            .expect("mock inference server");

            let refresher = Arc::new(DeferredRefreshNeverLands::default());
            let (_dir, am) = expired_auth_manager(refresher);
            let (actor, updates) = session_token_actor(&server, am, ActorShape::default()).await;

            // 100k window, 85% threshold (create_test_actor): the seeded 90k
            // usage puts every check past the auto-compact trigger.
            let mut cfg = actor
                .chat_state_handle
                .get_sampling_config()
                .await
                .expect("test actor has sampling config");
            cfg.context_window = std::num::NonZeroU64::new(100_000).expect("non-zero");
            actor.chat_state_handle.update_sampling_config(cfg);
            // Enough items that a leaked compact would really sample instead of
            // short-circuiting on a too-small conversation.
            use fuigo_sampling_types::ConversationItem;
            actor.chat_state_handle.replace_conversation(vec![
                ConversationItem::system("you are a coding agent"),
                ConversationItem::user("q1"),
                ConversationItem::assistant("a1"),
                ConversationItem::user("q2"),
                ConversationItem::assistant("a2"),
            ]);

            // Usage crosses the threshold only after the first iteration's compact check (which runs un-parked):
            // P42 (real clock) seeds it once the first park is announced, so it lands between the park and the parked
            // iterations, which are what this test is about.
            let usage_seeder = actor.chat_state_handle.clone();
            let park_watch = updates.clone();
            tokio::task::spawn_local(async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
                while reauth_parks(&park_watch) < 1 && tokio::time::Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                usage_seeder.record_token_usage(90_000);
            });
            land_fresh_token_after(&actor, &updates, Duration::from_secs(30));

            let outcome = run_prompt_with_cap(&actor, "parked-no-auto-compact", 86_400).await;
            assert_eq!(reauth_parks(&updates), 1);
            assert_eq!(inference_requests(&server).len(), 2, "one initial POST and one parked resubmit");
            assert!(
                outcome.is_err(),
                "failed refresh must terminate before auto-compaction: {outcome:?}"
            );
            assert!(
                terminal_failure(&updates).is_some(),
                "a failed refresh must report a terminal retryState"
            );
            // Compact sends are the only /responses requests without the
            // foreground turn header (two-pass prefire stays off here).
            let compact_sends = inference_requests(&server)
                .into_iter()
                .filter(|r| r.header("x-fuigo-turn-idx").is_none())
                .count();
            assert_eq!(
                compact_sends, 0,
                "parked iterations must not send a credential-less compact"
            );
        });
    });
}

/// Exercises the current A2.1 prompt boundary against the real turn loop.
#[test]
fn late_token_landing_cannot_resubmit_a_terminal_401() {
    if !p42_child("late_token_landing_cannot_resubmit_a_terminal_401") { return; }
    on_session_stack(|| {
        run_current_thread(false, || async {
            let server = MockInferenceServer::start_with_required_auth(vec![MockModelEntry::new("test")], FRESH_TOKEN).await.unwrap();
            let refresher = Arc::new(DeferredRefreshNeverLands::default());
            let rejected = refresher.server_rejected_calls.clone();
            let preflight = refresher.pre_request_calls.clone();
            let (_dir, am) = expired_auth_manager(refresher);
            let (actor, updates) = session_token_actor(&server, am, ActorShape::default()).await;
            let error = run_prompt_with_cap(&actor, "bounded-refusal", 86_400).await.expect_err("failed refresh must terminate");
            assert_eq!(error.data.as_ref().unwrap()["upstream"]["http_status"], 401);
            assert_eq!(inference_requests(&server).len(), 2, "one parked credential-less resubmit");
            assert!(terminal_failure(&updates).is_some());
            assert_eq!(reauth_parks(&updates), 1, "the park counts as the sole resubmit");
            assert_eq!(actor.refusal_prompt.lock().unwrap().refreshes, 1);
            assert_eq!(actor.refusal_prompt.lock().unwrap().state, fuigo_sampling_types::refusal::PromptState::Terminal);
            let calls = (rejected.load(Ordering::SeqCst), preflight.load(Ordering::SeqCst));
            actor.prepare_sampler_for_turn().await;
            assert_eq!((rejected.load(Ordering::SeqCst), preflight.load(Ordering::SeqCst)), calls, "terminal prepares cannot refresh");
            actor.auth_manager.as_ref().unwrap().hot_swap(FuigoAuth {
                key: FRESH_TOKEN.into(), auth_mode: AuthMode::Oidc,
                refresh_token: Some("rt-new".into()),
                expires_at: Some(chrono::Utc::now()+chrono::Duration::hours(1)),
                ..FuigoAuth::test_default()
            });
            actor.auth_manager.as_ref().unwrap().refresh_notifier().notify_waiters();
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(inference_requests(&server).len(), 2, "token notification cannot resurrect a terminal prompt");

        });
    });
}

/// Exercises the current A2.1 prompt boundary against the real turn loop.
#[test]
fn never_recovering_401_terminates_before_runaway_budget() {
    if !p42_child("never_recovering_401_terminates_before_runaway_budget") { return; }
    on_session_stack(|| {
        run_current_thread(false, || async {
            let server = MockInferenceServer::start_with_required_auth(vec![MockModelEntry::new("test")], FRESH_TOKEN).await.unwrap();
            let refresher = Arc::new(DeferredRefreshNeverLands::default());
            let rejected = refresher.server_rejected_calls.clone();
            let preflight = refresher.pre_request_calls.clone();
            let (_dir, am) = expired_auth_manager(refresher);
            let (actor, updates) = session_token_actor(&server, am, ActorShape::default()).await;
            let error = run_prompt_with_cap(&actor, "bounded-refusal", 86_400).await.expect_err("failed refresh must terminate");
            assert_eq!(error.data.as_ref().unwrap()["upstream"]["http_status"], 401);
            assert_eq!(inference_requests(&server).len(), 2, "one parked credential-less resubmit");
            assert!(terminal_failure(&updates).is_some());
            assert_eq!(reauth_parks(&updates), 1, "the park counts as the sole resubmit");
            assert_eq!(actor.refusal_prompt.lock().unwrap().refreshes, 1);
            assert_eq!(actor.refusal_prompt.lock().unwrap().state, fuigo_sampling_types::refusal::PromptState::Terminal);
            let calls = (rejected.load(Ordering::SeqCst), preflight.load(Ordering::SeqCst));
            actor.prepare_sampler_for_turn().await;
            assert_eq!((rejected.load(Ordering::SeqCst), preflight.load(Ordering::SeqCst)), calls, "terminal prepares cannot refresh");

        });
    });
}

#[test]
fn r2_parent_message_reopens_terminal_child() {
    if !p42_child("r2_parent_message_reopens_terminal_child") { return; }
    on_session_stack(|| {
        run_current_thread(false, || async {
            let server = MockInferenceServer::start_with_models(vec![MockModelEntry::new("test")]).await.unwrap();
            let (_dir, am) = expired_auth_manager(Arc::new(DeferredRefreshNeverLands::default()));
            let (actor, _) = session_token_actor(&server, am, ActorShape { is_subagent: true, parent_message_child: true, ..Default::default() }).await;
            server.enqueue_response("/v1/responses", ScriptedResponse::json(402, serde_json::json!({"error":{"message":"refused"}})));
            assert!(run_prompt(&actor, "child-first").await.is_err());
            assert_eq!(actor.refusal_prompt.lock().unwrap().state, fuigo_sampling_types::refusal::PromptState::Terminal);
            let before = inference_requests(&server).len();
            server.enqueue_response("/v1/responses", ScriptedResponse::json(402, serde_json::json!({"error":{"message":"refused again"}})));
            let result = actor.handle_turn_input(super::turn_task::TurnInputRequest {
                prompt_id: "parent-instruction".into(),
                input_origin: InputOrigin::new(crate::session::PromptOrigin::ParentAgentMessage { message_id: "instruction".into(), sender_session_id: "parent-test".into() }),
                prompt_blocks: vec![acp::ContentBlock::Text(acp::TextContent::new("continue"))],
                prompt_mode: PromptMode::Agent, trace_gcs_config: None, artifact_tracker: None,
                client_identifier: None, screen_mode: None, verbatim: false, send_now: false,
                json_schema: None, persist_ack: None, parsed_prompt_tx: None, traceparent: None,
            }).await;
            assert_eq!(inference_requests(&server).len() - before, 1, "a parent instruction must make one new child POST");
            let error = result.expect_err("the parent must receive the real refusal");
            assert_eq!(error.data.as_ref().unwrap()["upstream"]["http_status"], 402);
        });
    });
}
