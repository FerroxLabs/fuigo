//! Integration tests for the actor and request_task layer.
//!
//! They live in `tests/` because they need a real `tokio::runtime` and a mock axum HTTP server for the `SamplingClient` to talk to.
//! Happy-path SSE payloads come from `fuigo_test_support::sse`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::routing::post;
use futures_util::stream::{self, StreamExt};
use indexmap::IndexMap;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use fuigo_sampler::{
    ApiBackend, RequestId, RetryPolicy, SamplerActor, SamplerConfig, SamplingChannel,
    SamplingErrorKind, SamplingEvent, StripReason,
};
use fuigo_sampling_types::{
    ConversationItem, ConversationRequest, DoomLoopRecoveryPolicy, INVALID_IMAGE_ERROR_CODE,
    UserItem,
};
use fuigo_test_support::{SseEvent, sse};

// ---------------------------------------------------------------------------
// Mock server harness
// ---------------------------------------------------------------------------

struct MockServer {
    addr: SocketAddr,
    shutdown_tx: oneshot::Sender<()>,
}

impl MockServer {
    async fn spawn(app: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        // Give the server a moment to start.
        tokio::time::sleep(Duration::from_millis(20)).await;
        Self { addr, shutdown_tx }
    }

    fn base_url(&self) -> String {
        format!("http://{}/v1", self.addr)
    }

    fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

// ---------------------------------------------------------------------------
// Config + request helpers
// ---------------------------------------------------------------------------

fn test_config(base_url: String, model: &str) -> SamplerConfig {
    SamplerConfig {
        flux_base_url: None,
        api_key: Some("test-key".into()),
        base_url,
        model: model.into(),
        max_completion_tokens: Some(1024),
        temperature: None,
        top_p: None,
        api_backend: ApiBackend::ChatCompletions,
        auth_scheme: Default::default(),
        extra_headers: IndexMap::new(),
        extra_response_includes: Vec::new(),
        query_params: IndexMap::new(),
        env_http_headers: IndexMap::new(),
        context_window: 128_000,
        max_request_bytes: None,
        force_http1: false,
        // Keep retries minimal so tests don't take forever.
        max_retries: Some(2),
        stream_tool_calls: false,
        idle_timeout_secs: Some(30),
        reasoning_effort: None,
        origin_client: None,
        client_identifier: None,
        deployment_id: None,
        user_id: None,
        client_version: None,
        attribution_callback: None,
        bearer_resolver: None,
        supports_backend_search: false,
        programmatic_tool_calling: false,
        compactions_remaining: None,
        compaction_at_tokens: None,
        doom_loop_recovery: None,
        subscription: None,
        subscription_resolver: None,
        header_injector: None,
        dispatch_gate: None,
        mtls_cert_dir: None,
        rate_limit_retry_threshold: None,
        reasoning_summary: None,
    }
}

fn user_request(text: &str) -> ConversationRequest {
    ConversationRequest {
        items: vec![ConversationItem::User(UserItem {
            content: vec![fuigo_sampling_types::ContentPart::Text {
                text: std::sync::Arc::<str>::from(text),
            }],
            synthetic_reason: None,
            ..Default::default()
        })],
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// SSE generators
// ---------------------------------------------------------------------------

/// Render test-helper [`SseEvent`]s (optional `event:` name and `data:`) as axum SSE events for this file's router-based harness.
fn sse_events_to_axum(events: Vec<SseEvent>) -> Vec<Event> {
    events
        .into_iter()
        .map(|e| {
            let ev = Event::default().data(e.data);
            match e.event {
                Some(name) => ev.event(name),
                None => ev,
            }
        })
        .collect()
}

fn text_chunk_event(content: &str, finish: bool) -> Event {
    let chunk = json!({
        "id": "chatcmpl-test",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "test-model",
        "choices": [{
            "index": 0,
            "delta": { "role": "assistant", "content": content },
            "finish_reason": if finish { json!("stop") } else { json!(null) }
        }]
    });
    Event::default().data(chunk.to_string())
}

// ---------------------------------------------------------------------------
// Actor lifecycle
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_then_active_count_zero_then_cancel_unknown_is_noop() {
    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let cfg = test_config("http://127.0.0.1:0/v1".into(), "test-model");
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);
    assert_eq!(handle.active_count().await, 0);
    handle.cancel(RequestId::from("nonexistent"));
    assert_eq!(handle.active_count().await, 0);
}

// ---------------------------------------------------------------------------
// Submit + event flow
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_emits_started_first_token_channel_completed() {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            let events = sse::chat_completion_events("hello world", "test-model");
            Sse::new(stream::iter(
                events.into_iter().map(Ok::<_, std::convert::Infallible>),
            ))
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let cfg = test_config(server.base_url(), "test-model");
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let rid = RequestId::from("req-1");
    handle.submit(rid.clone(), user_request("hi"));

    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(5)).await;
    server.shutdown();

    assert!(
        matches!(events[0], SamplingEvent::StreamStarted { .. }),
        "a submit's first event must be StreamStarted, got {:?}",
        events[0]
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SamplingEvent::FirstToken { .. }))
    );

    let texts: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            SamplingEvent::ChannelToken {
                channel: SamplingChannel::Text,
                text,
                ..
            } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(texts.join(""), "hello world");

    match events.last().unwrap() {
        SamplingEvent::Completed {
            request_id,
            response,
            ..
        } => {
            assert_eq!(request_id, &rid);
            if let Some(a) = response.assistant() {
                assert_eq!(a.content.as_ref(), "hello world");
            } else {
                panic!("expected Assistant message");
            }
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// submit_and_collect
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_and_collect_returns_response() {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            let events = sse::chat_completion_events("collected response", "test-model");
            Sse::new(stream::iter(
                events.into_iter().map(Ok::<_, std::convert::Infallible>),
            ))
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let cfg = test_config(server.base_url(), "test-model");
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let rid = RequestId::from("req-collect");
    let result = handle
        .submit_and_collect(rid, user_request("hi"))
        .await
        .expect("collected ok");
    server.shutdown();

    let (response, _metrics) = result;
    let a = response.assistant().expect("assistant item present");
    assert_eq!(a.content.as_ref(), "collected response");
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_in_flight_request_terminates_task() {
    // The server yields one chunk then hangs
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            let stream = stream::iter(vec![Ok::<_, std::convert::Infallible>(text_chunk_event(
                "starting", false,
            ))])
            .chain(stream::pending());
            Sse::new(stream)
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let cfg = test_config(server.base_url(), "test-model");
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let rid = RequestId::from("req-cancel");
    handle.submit(rid.clone(), user_request("hi"));

    // Wait for the first token to arrive so we know the request is in flight.
    let _ = await_event_matching(
        &mut event_rx,
        |e| matches!(e, SamplingEvent::FirstToken { .. }),
        Duration::from_secs(5),
    )
    .await
    .expect("first token");

    handle.cancel(rid.clone());

    // Expect a Failed event with the cancellation message.
    let failed = await_event_matching(
        &mut event_rx,
        |e| matches!(e, SamplingEvent::Failed { .. }),
        Duration::from_secs(5),
    )
    .await
    .expect("Failed event after cancel");

    if let SamplingEvent::Failed { error, .. } = failed {
        assert!(error.message.contains("cancelled"));
    }

    // Wait briefly for the task to clean up.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(handle.active_count().await, 0);
    server.shutdown();
}

// ---------------------------------------------------------------------------
// Concurrent requests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_requests_complete_with_correct_request_ids() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let events = sse::chat_completion_events(&format!("response-{n}"), "test-model");
                Sse::new(stream::iter(
                    events.into_iter().map(Ok::<_, std::convert::Infallible>),
                ))
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let cfg = test_config(server.base_url(), "test-model");
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let rid_a = RequestId::from("req-a");
    let rid_b = RequestId::from("req-b");
    handle.submit(rid_a.clone(), user_request("a"));
    handle.submit(rid_b.clone(), user_request("b"));

    // Drain until we see Completed for both.
    let mut completed_a = false;
    let mut completed_b = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !(completed_a && completed_b) {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            panic!(
                "timed out waiting for both requests to complete: a={completed_a}, b={completed_b}"
            );
        }
        let remaining = deadline - now;
        match tokio::time::timeout(remaining, event_rx.recv()).await {
            Ok(Some(SamplingEvent::Completed { request_id, .. })) if request_id == rid_a => {
                completed_a = true;
            }
            Ok(Some(SamplingEvent::Completed { request_id, .. })) if request_id == rid_b => {
                completed_b = true;
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("event channel closed"),
            Err(_) => panic!("timeout"),
        }
    }
    server.shutdown();
}

// ---------------------------------------------------------------------------
// Retry on transient transport error
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retries_on_500_then_succeeds() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    // First attempt: server error.
                    Err::<Sse<_>, (StatusCode, String)>((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({ "error": { "message": "transient" } }).to_string(),
                    ))
                } else {
                    // Subsequent attempts: success.
                    let events = sse::chat_completion_events("ok", "test-model");
                    Ok(Sse::new(stream::iter(
                        events.into_iter().map(Ok::<_, std::convert::Infallible>),
                    )))
                }
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    // Lots of retries available; backoff is jittered around 2s on first retry, so this test takes a bit to run
    let cfg = test_config(server.base_url(), "test-model");
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let rid = RequestId::from("req-retry");
    handle.submit(rid.clone(), user_request("hi"));

    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(15)).await;
    server.shutdown();

    let saw_retrying = events
        .iter()
        .any(|e| matches!(e, SamplingEvent::Retrying { .. }));
    assert!(saw_retrying, "expected at least one Retrying event");

    match events.last().unwrap() {
        SamplingEvent::Completed { response, .. } => {
            if let Some(a) = response.assistant() {
                assert_eq!(a.content.as_ref(), "ok");
            }
        }
        other => panic!("expected Completed after retry, got {other:?}"),
    }

    assert!(
        counter.load(Ordering::SeqCst) >= 2,
        "server hit at least twice"
    );
}

/// A coded `invalid_image` 400 strips the image, emits ServerRejected, retries, and completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_image_code_strips_and_retries() {
    const IMAGE_URI: &str = "data:image/png;base64,cG9pc29uZWQ=";
    let bodies = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let bodies_handler = Arc::clone(&bodies);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |body: String| {
            let bodies = Arc::clone(&bodies_handler);
            async move {
                let n = {
                    let mut b = bodies.lock().unwrap();
                    b.push(body);
                    b.len()
                };
                if n == 1 {
                    // The FLAT envelope the Ferrox Labs API's non-stream rejections actually use; the message alone must not matter
                    Err::<Sse<_>, (StatusCode, String)>((
                        StatusCode::BAD_REQUEST,
                        json!({
                            "code": INVALID_IMAGE_ERROR_CODE,
                            "error": "some future wording without the legacy phrase",
                        })
                        .to_string(),
                    ))
                } else {
                    let events = sse::chat_completion_events("recovered", "test-model");
                    Ok(Sse::new(stream::iter(
                        events.into_iter().map(Ok::<_, std::convert::Infallible>),
                    )))
                }
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        test_config(server.base_url(), "test-model"),
        RetryPolicy::default(),
        event_tx,
    );

    let mut request = user_request("what is in this image?");
    if let Some(ConversationItem::User(u)) = request.items.first_mut() {
        u.add_image(IMAGE_URI);
    }
    handle.submit(RequestId::from("req-image-code-strip"), request);

    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(15)).await;
    server.shutdown();

    assert!(
        events.iter().any(|e| match e {
            SamplingEvent::ImagesStripped {
                stripped_urls,
                reason: fuigo_sampler::StripReason::ServerRejected,
                ..
            } => stripped_urls.len() == 1 && stripped_urls[0].as_ref() == IMAGE_URI,
            _ => false,
        }),
        "expected server-rejected ImagesStripped carrying the poisoned URL, got {events:?}"
    );
    assert!(
        matches!(events.last(), Some(SamplingEvent::Completed { .. })),
        "expected Completed after strip-retry"
    );

    let bodies = bodies.lock().unwrap();
    assert_eq!(bodies.len(), 2, "one rejection, one strip-retry");
    assert!(bodies[0].contains(IMAGE_URI), "first attempt sends image");
    assert!(
        !bodies[1].contains(IMAGE_URI),
        "strip-retry must not resend the image"
    );
}

/// A legacy-phrase 400 with no code still strips and recovers, but the reason is `PayloadHeuristic`.
/// Without the deterministic code the server blamed nothing specific, so the strip must stay request-local.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_phrase_400_strips_as_heuristic() {
    const IMAGE_URI: &str = "data:image/png;base64,cG9pc29uZWQ=";
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err::<Sse<_>, (StatusCode, String)>((
                        StatusCode::BAD_REQUEST,
                        json!({
                            "error": {
                                "message": "Could not process image",
                                "type": "invalid_request_error",
                            }
                        })
                        .to_string(),
                    ))
                } else {
                    let events = sse::chat_completion_events("recovered", "test-model");
                    Ok(Sse::new(stream::iter(
                        events.into_iter().map(Ok::<_, std::convert::Infallible>),
                    )))
                }
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        test_config(server.base_url(), "test-model"),
        RetryPolicy::default(),
        event_tx,
    );

    let mut request = user_request("what is in this image?");
    if let Some(ConversationItem::User(u)) = request.items.first_mut() {
        u.add_image(IMAGE_URI);
    }
    handle.submit(RequestId::from("req-legacy-phrase-strip"), request);

    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(15)).await;
    server.shutdown();

    assert!(
        events.iter().any(|e| matches!(
            e,
            SamplingEvent::ImagesStripped {
                reason: StripReason::PayloadHeuristic,
                ..
            }
        )),
        "codeless legacy-phrase 400 must strip as PayloadHeuristic, got {events:?}"
    );
    assert!(
        !events.iter().any(|e| matches!(
            e,
            SamplingEvent::ImagesStripped {
                reason: StripReason::ServerRejected,
                ..
            }
        )),
        "no deterministic code, so never ServerRejected: {events:?}"
    );
    assert!(
        matches!(events.last(), Some(SamplingEvent::Completed { .. })),
        "expected Completed after strip-retry"
    );
}

/// Guards that `user_facing_api_error_message` keeps the `.image.source` path in a codeless `invalid_request_error`.
/// That way the codeless image-strip recovery fires on many-image dimension 400s instead of hard-failing every turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn many_image_dimension_400_strips_as_heuristic() {
    const IMAGE_URI: &str = "data:image/png;base64,cG9pc29uZWQ=";
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err::<Sse<_>, (StatusCode, String)>((
                        StatusCode::BAD_REQUEST,
                        json!({
                            "error": {
                                "message": "messages.0.content.4.image.source.base64.data: At least one of the image dimensions exceed max allowed size for many-image requests: 2000 pixels",
                                "type": "invalid_request_error",
                            }
                        })
                        .to_string(),
                    ))
                } else {
                    let events = sse::chat_completion_events("recovered", "test-model");
                    Ok(Sse::new(stream::iter(
                        events.into_iter().map(Ok::<_, std::convert::Infallible>),
                    )))
                }
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        test_config(server.base_url(), "test-model"),
        RetryPolicy::default(),
        event_tx,
    );

    let mut request = user_request("what is in this image?");
    if let Some(ConversationItem::User(u)) = request.items.first_mut() {
        u.add_image(IMAGE_URI);
    }
    handle.submit(RequestId::from("req-many-image-dimension-strip"), request);

    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(15)).await;
    server.shutdown();

    assert!(
        events.iter().any(|e| matches!(
            e,
            SamplingEvent::ImagesStripped {
                reason: StripReason::PayloadHeuristic,
                ..
            }
        )),
        "codeless many-image dimension 400 must strip as PayloadHeuristic, got {events:?}"
    );
    assert!(
        matches!(events.last(), Some(SamplingEvent::Completed { .. })),
        "expected Completed after strip-retry"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn image_400_with_nothing_left_to_strip_is_fatal_after_one_cycle() {
    // `stripped == 0` is the only bound on the strip-retry loop.
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err::<Sse<futures_util::stream::Empty<Result<Event, std::convert::Infallible>>>, _>(
                    (
                        StatusCode::BAD_REQUEST,
                        json!({
                            "code": INVALID_IMAGE_ERROR_CODE,
                            "error": "Base64 string of provided image cannot be decoded.",
                        })
                        .to_string(),
                    ),
                )
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        test_config(server.base_url(), "test-model"),
        RetryPolicy::default(),
        event_tx,
    );

    let mut request = user_request("what is in this image?");
    if let Some(ConversationItem::User(u)) = request.items.first_mut() {
        u.add_image("data:image/png;base64,cG9pc29uZWQ=");
    }
    handle.submit(RequestId::from("req-strip-exhausted"), request);

    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(15)).await;
    server.shutdown();

    let strips = events
        .iter()
        .filter(|e| matches!(e, SamplingEvent::ImagesStripped { .. }))
        .count();
    assert_eq!(strips, 1, "exactly one strip cycle");
    assert!(
        matches!(events.last(), Some(SamplingEvent::Failed { .. })),
        "second image 400 with nothing left to strip must be fatal, got {events:?}"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "one rejection, one strip-retry, then stop"
    );
}

/// RST with a zero retry budget: the decision is Fatal, so the proactive heuristic strip must NOT run.
/// There is no mutation, no ImagesStripped event, and no "left out of the retry" note for a retry that never happens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fatal_decision_does_not_strip_or_emit_images_stripped() {
    const IMAGE_URI: &str = "data:image/png;base64,cG9pc29uZWQ=";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        // RST every connection: peek then drop (see fuigo-http).
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((sock, _)) = accepted else { break };
                    let mut buf = [0u8; 64];
                    let _ = sock.peek(&mut buf).await;
                    drop(sock);
                }
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut config = test_config(format!("http://{addr}/v1"), "test-model");
    config.max_retries = Some(0);
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(config, RetryPolicy::default(), event_tx);

    let mut request = user_request("what is in this image?");
    if let Some(ConversationItem::User(u)) = request.items.first_mut() {
        u.add_image(IMAGE_URI);
    }
    handle.submit(RequestId::from("req-fatal-no-strip"), request);

    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(15)).await;
    let _ = shutdown_tx.send(());

    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SamplingEvent::ImagesStripped { .. })),
        "a Fatal decision must not strip or emit ImagesStripped, got {events:?}"
    );
    assert!(
        matches!(events.last(), Some(SamplingEvent::Failed { .. })),
        "expected terminal Failed, got {events:?}"
    );
}

/// An RST mid-upload (nginx-style 413) emits PayloadHeuristic and strips the request only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_reset_emits_payload_heuristic_and_strips_request() {
    const IMAGE_URI: &str = "data:image/png;base64,cG9pc29uZWQ=";
    let bodies = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let bodies_handler = Arc::clone(&bodies);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        // Peek then drop so the peer sees RST (see fuigo-http).
        if let Ok((sock, _)) = listener.accept().await {
            let mut buf = [0u8; 64];
            let _ = sock.peek(&mut buf).await;
            drop(sock);
        }
        let app = Router::new().route(
            "/v1/chat/completions",
            post(move |body: String| {
                let bodies = Arc::clone(&bodies_handler);
                async move {
                    bodies.lock().unwrap().push(body);
                    let events = sse::chat_completion_events("recovered", "test-model");
                    Sse::new(stream::iter(
                        events.into_iter().map(Ok::<_, std::convert::Infallible>),
                    ))
                }
            }),
        );
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        test_config(format!("http://{addr}/v1"), "test-model"),
        RetryPolicy::default(),
        event_tx,
    );

    let mut request = user_request("what is in this image?");
    if let Some(ConversationItem::User(u)) = request.items.first_mut() {
        u.add_image(IMAGE_URI);
    }
    handle.submit(RequestId::from("req-heuristic-strip"), request);

    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(15)).await;
    let _ = shutdown_tx.send(());

    assert!(
        events.iter().any(|e| match e {
            SamplingEvent::ImagesStripped {
                stripped_urls,
                reason: StripReason::PayloadHeuristic,
                ..
            } => stripped_urls.len() == 1 && stripped_urls[0].as_ref() == IMAGE_URI,
            _ => false,
        }),
        "connection reset must emit PayloadHeuristic ImagesStripped, got {events:?}"
    );
    assert!(
        !events.iter().any(|e| matches!(
            e,
            SamplingEvent::ImagesStripped {
                reason: StripReason::ServerRejected,
                ..
            }
        )),
        "heuristic path must not be labeled ServerRejected, got {events:?}"
    );
    assert!(
        matches!(events.last(), Some(SamplingEvent::Completed { .. })),
        "strip-retry must complete, got {events:?}"
    );
    let bodies = bodies.lock().unwrap();
    assert_eq!(bodies.len(), 1, "only the post-strip retry hits HTTP");
    assert!(
        !bodies[0].contains(IMAGE_URI),
        "in-flight request must be stripped before the retry"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_failure_does_not_emit_images_stripped() {
    // Connection refused is `is_connect`, not a body-upload reset.
    // A held closed port, not `127.0.0.1:1`: WSL2 mirrored networking never refuses a closed IPv4 loopback port.
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        test_config(
            format!("{}/v1", fuigo_test_support::refused_loopback_url()),
            "test-model",
        ),
        RetryPolicy::default(),
        event_tx,
    );

    let mut request = user_request("what is in this image?");
    if let Some(ConversationItem::User(u)) = request.items.first_mut() {
        u.add_image("data:image/png;base64,cG9pc29uZWQ=");
    }
    handle.submit(RequestId::from("req-connect-fail"), request);

    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(15)).await;
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SamplingEvent::ImagesStripped { .. })),
        "connect failure must not strip images, got {events:?}"
    );
    assert!(
        matches!(events.last(), Some(SamplingEvent::Failed { .. })),
        "exhausted connect retries must be Failed, got {events:?}"
    );
}

// ---------------------------------------------------------------------------
// Rate limit exhausts threshold
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limit_exhausts_at_threshold_and_yields_failed() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err::<
                    Sse<
                        futures_util::stream::Iter<
                            std::vec::IntoIter<Result<Event, std::convert::Infallible>>,
                        >,
                    >,
                    (StatusCode, String),
                >((
                    StatusCode::TOO_MANY_REQUESTS,
                    json!({ "error": { "message": "slow down" } }).to_string(),
                ))
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let cfg = test_config(server.base_url(), "test-model");
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let rid = RequestId::from("req-429");
    handle.submit(rid.clone(), user_request("hi"));

    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(60)).await;
    server.shutdown();

    match events.last().unwrap() {
        SamplingEvent::Failed { error, .. } => {
            assert_eq!(error.kind, SamplingErrorKind::RateLimited);
            assert_eq!(error.status_code, Some(429));
        }
        other => panic!("expected Failed(RateLimited), got {other:?}"),
    }

    let hits = counter.load(Ordering::SeqCst);
    // RATE_LIMIT_RETRY_THRESHOLD is 2, so the actor stops after two attempts: the first attempt and one retry that also 429s
    // Allow a small slack in case scheduling fires a third attempt before the threshold check
    assert!((1..=3).contains(&hits), "expected 1-3 hits, got {hits}");
}

/// F023: `[models.<key>] rate_limit_retry_threshold = N` reaches the sampler as `SamplerConfig::rate_limit_retry_threshold`
/// and replaces the actor's `RetryPolicy` default as the total-attempt ceiling for 429s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_rate_limit_threshold_controls_total_wire_attempts() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("retry-after", "0")],
                    json!({ "error": { "message": "slow down" } }).to_string(),
                )
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let mut cfg = test_config(server.base_url(), "test-model");
    cfg.max_retries = Some(6);
    cfg.rate_limit_retry_threshold = Some(4);
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let rid = RequestId::from("req-429-configured");
    handle.submit(rid.clone(), user_request("hi"));

    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(60)).await;
    server.shutdown();

    match events.last().unwrap() {
        SamplingEvent::Failed { error, .. } => {
            assert_eq!(error.kind, SamplingErrorKind::RateLimited);
            assert_eq!(error.status_code, Some(429));
        }
        other => panic!("expected Failed(RateLimited), got {other:?}"),
    }

    let hits = counter.load(Ordering::SeqCst);
    assert_eq!(
        hits, 4,
        "the configured threshold is a total-attempt ceiling and must override the policy default of 2"
    );
}

/// u38 F6: a rate-limit resend announces the ceiling that actually stops it, not the general retry budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u38_f6_rate_limit_resend_announces_the_rate_limit_ceiling() {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || async move {
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "0")],
                json!({ "error": { "message": "slow down" } }).to_string(),
            )
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let mut cfg = test_config(server.base_url(), "test-model");
    cfg.max_retries = Some(6);
    cfg.rate_limit_retry_threshold = Some(4);
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    handle.submit(RequestId::from("req-429-announce"), user_request("hi"));

    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(60)).await;
    server.shutdown();
    let announced: Vec<(u32, u32)> = events
        .iter()
        .filter_map(|event| match event {
            SamplingEvent::Retrying {
                attempt,
                max_retries,
                ..
            } => Some((*attempt, *max_retries)),
            _ => None,
        })
        .collect();
    assert_eq!(announced, vec![(1, 4), (2, 4), (3, 4)]);
}

/// u38 F6: the retry ceiling is unchanged: the display never adds or removes a wire call, and the count that comes back
/// with the failure is every call made, the resends of other kinds included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u38_f6_a_failed_request_reports_every_wire_attempt() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                let status = if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    StatusCode::INTERNAL_SERVER_ERROR
                } else {
                    StatusCode::TOO_MANY_REQUESTS
                };
                (
                    status,
                    [("retry-after", "0")],
                    json!({ "error": { "message": "slow down" } }).to_string(),
                )
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let mut cfg = test_config(server.base_url(), "test-model");
    cfg.max_retries = Some(6);
    cfg.rate_limit_retry_threshold = Some(3);
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let collected = handle
        .submit_and_collect_with_metadata(RequestId::from("req-429-attempts"), user_request("hi"))
        .await;
    server.shutdown();

    assert!(collected.result.is_err());
    assert_eq!(
        counter.load(Ordering::SeqCst),
        3,
        "the ceiling still stops at three calls"
    );
    assert_eq!(collected.attempts, 3);
}

// ---------------------------------------------------------------------------
// Auth error -> EmitToSession (immediate)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_401_emits_failed_immediately_no_retry() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err::<
                    Sse<
                        futures_util::stream::Iter<
                            std::vec::IntoIter<Result<Event, std::convert::Infallible>>,
                        >,
                    >,
                    (StatusCode, String),
                >((StatusCode::UNAUTHORIZED, "unauthorized".to_string()))
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let cfg = test_config(server.base_url(), "test-model");
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let rid = RequestId::from("req-auth");
    handle.submit(rid.clone(), user_request("hi"));

    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(5)).await;
    server.shutdown();

    // The session owns auth errors: `classify_error` returns `EmitToSession`, so the actor emits Failed immediately without retrying
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SamplingEvent::Retrying { .. }))
    );
    match events.last().unwrap() {
        SamplingEvent::Failed { error, .. } => {
            assert_eq!(error.kind, SamplingErrorKind::Auth);
        }
        other => panic!("expected Failed(Auth), got {other:?}"),
    }
    assert_eq!(counter.load(Ordering::SeqCst), 1, "no retries on 401");
}

// ---------------------------------------------------------------------------
// Anthropic Messages API: refusal stop_reason + mid-stream parse failure
// ---------------------------------------------------------------------------

fn messages_config(base_url: String) -> SamplerConfig {
    let mut cfg = test_config(base_url, "messages-compatible-model");
    cfg.api_backend = ApiBackend::Messages;
    cfg
}

/// Regression for the refusal-stop_reason incident.
/// A well-formed stream terminated by `stop_reason: "refusal"` must produce a successful completion from EXACTLY ONE request, no retry storm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn messages_refusal_stream_completes_with_single_request() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/messages",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let events = sse::messages_api_events(
                    "I can't help with that.",
                    "messages-compatible-model",
                    "refusal",
                );
                Sse::new(stream::iter(
                    events.into_iter().map(Ok::<_, std::convert::Infallible>),
                ))
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        messages_config(server.base_url()),
        RetryPolicy::default(),
        event_tx,
    );

    let result = handle
        .submit_and_collect(RequestId::from("req-refusal"), user_request("hi"))
        .await;
    server.shutdown();

    let (response, _metrics) = result.expect("refusal-terminated turn must complete");
    let a = response.assistant().expect("assistant item present");
    assert_eq!(a.content.as_ref(), "I can't help with that.");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "refusal must not trigger retries"
    );
}

/// Empty-bodied refusal: `message_start → message_delta(refusal) → message_stop` with zero content blocks must complete from exactly one request.
/// The content-less response must not be classified as a retryable EmptyResponse.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn messages_empty_refusal_completes_without_retry() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/messages",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut events =
                    sse::messages_api_events("", "messages-compatible-model", "refusal");
                // Drop the content block events; keep start/delta/stop only.
                events.drain(1..4);
                Sse::new(stream::iter(
                    events.into_iter().map(Ok::<_, std::convert::Infallible>),
                ))
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        messages_config(server.base_url()),
        RetryPolicy::default(),
        event_tx,
    );

    handle.submit(RequestId::from("req-empty-refusal"), user_request("hi"));
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(10)).await;
    server.shutdown();

    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SamplingEvent::Retrying { .. })),
        "content-less refusal must not be retried"
    );
    match events.last().unwrap() {
        SamplingEvent::Completed { response, .. } => {
            assert_eq!(
                response.stop_reason,
                Some(fuigo_sampling_types::StopReason::ContentFilter)
            );
        }
        other => panic!("expected Completed, got {other:?}"),
    }
    assert_eq!(counter.load(Ordering::SeqCst), 1, "exactly one request");
}

/// A mid-stream event that fails serde (after a valid `message_start`) is a deterministic response-parse failure.
/// It is Fatal on the first attempt and surfaces as a non-retryable Serialization error, never a retry storm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn messages_unparseable_event_is_fatal_without_retry() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app =
        Router::new().route(
            "/v1/messages",
            post(move || {
                let counter = Arc::clone(&counter_handler);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let mut events =
                        sse::messages_api_events("hello", "messages-compatible-model", "end_turn");
                    // Replace the tail with a `message_delta` missing the required `delta` field, which fails MessageStreamEvent serde
                    events.truncate(4);
                    events.push(Event::default().data(
                        json!({"type":"message_delta","usage":{"output_tokens":1}}).to_string(),
                    ));
                    Sse::new(stream::iter(
                        events.into_iter().map(Ok::<_, std::convert::Infallible>),
                    ))
                }
            }),
        );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        messages_config(server.base_url()),
        RetryPolicy::default(),
        event_tx,
    );

    handle.submit(RequestId::from("req-bad-event"), user_request("hi"));
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(10)).await;
    server.shutdown();

    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SamplingEvent::Retrying { .. })),
        "serde failures must not be retried"
    );
    match events.last().unwrap() {
        SamplingEvent::Failed { error, .. } => {
            assert_eq!(error.kind, SamplingErrorKind::Serialization);
            assert!(!error.is_retryable, "surfaced info must be non-retryable");
        }
        other => panic!("expected Failed(Serialization), got {other:?}"),
    }
    assert_eq!(counter.load(Ordering::SeqCst), 1, "exactly one attempt");
}

// ---------------------------------------------------------------------------
// UpdateConfig invalidates cache + applies to subsequent requests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_config_changes_subsequent_request_model() {
    use std::sync::Mutex;

    let captured_models: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_handler = Arc::clone(&captured_models);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |axum::Json(body): axum::Json<serde_json::Value>| {
            let captured = Arc::clone(&captured_handler);
            async move {
                let model = body
                    .get("model")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                captured.lock().unwrap().push(model);
                let events = sse::chat_completion_events("ok", "test-model");
                Sse::new(stream::iter(
                    events.into_iter().map(Ok::<_, std::convert::Infallible>),
                ))
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let cfg = test_config(server.base_url(), "model-A");
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let _ = handle
        .submit_and_collect(RequestId::from("req-1"), user_request("hi"))
        .await
        .expect("first req ok");

    let mut new_cfg = test_config(server.base_url(), "model-B");
    new_cfg.api_key = Some("test-key".into());
    handle.update_config(new_cfg);

    let _ = handle
        .submit_and_collect(RequestId::from("req-2"), user_request("hi"))
        .await
        .expect("second req ok");

    server.shutdown();

    let models = captured_models.lock().unwrap();
    assert_eq!(
        models.as_slice(),
        &["model-A".to_string(), "model-B".to_string()]
    );
}

// ---------------------------------------------------------------------------
// Responses doom-loop check signals
// ---------------------------------------------------------------------------

fn responses_config(base_url: String, doom_loop: Option<DoomLoopRecoveryPolicy>) -> SamplerConfig {
    let mut cfg = test_config(base_url, "test-model");
    cfg.api_backend = ApiBackend::Responses;
    cfg.doom_loop_recovery = doom_loop;
    cfg
}

/// Server-reported doom-loop triggers flow through the actor rung onto the completed response, without retries.
/// The trigger is non-confident (`@response` channel), so the recovery, which resamples only confident signals, leaves it alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn responses_doom_loop_signals_reach_completed_response() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/responses",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let events = sse_events_to_axum(sse::responses_api_doom_loop_terminal_only_events(
                    &["tail_repetition:4@response"],
                    "some thought",
                    "an answer",
                    "test-model",
                ));
                Sse::new(stream::iter(
                    events.into_iter().map(Ok::<_, std::convert::Infallible>),
                ))
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        responses_config(server.base_url(), Some(DoomLoopRecoveryPolicy::default())),
        RetryPolicy::default(),
        event_tx,
    );

    let result = handle
        .submit_and_collect(RequestId::from("req-doom-signal"), user_request("hi"))
        .await;
    server.shutdown();

    let (response, _metrics) = result.expect("a signalled turn still completes");
    assert_eq!(counter.load(Ordering::SeqCst), 1, "warn-only: no resample");
    assert_eq!(response.doom_loop_signals.len(), 1);
    assert_eq!(
        response.doom_loop_signals[0].raw,
        "tail_repetition:4@response"
    );
    assert_eq!(response.assistant_text(), "an answer");
}

/// Acceptance spec for the recovery rung: a confident tail signal is resampled once while its detector label remains observable.
/// The clean second response is accepted on its own budget even with transport retries disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn responses_confident_doom_loop_signal_resamples_once() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let bodies = Arc::new(std::sync::Mutex::new(Vec::<serde_json::Value>::new()));
    let bodies_handler = Arc::clone(&bodies);
    let app = Router::new().route(
        "/v1/responses",
        post(move |body: String| {
            let counter = Arc::clone(&counter_handler);
            let bodies = Arc::clone(&bodies_handler);
            async move {
                bodies
                    .lock()
                    .unwrap()
                    .push(serde_json::from_str(&body).unwrap());
                let attempt = counter.fetch_add(1, Ordering::SeqCst);
                let events = if attempt == 0 {
                    sse::responses_api_doom_loop_terminal_only_events(
                        &["tail_repetition:8@thinking"],
                        "loop loop loop",
                        "poisoned answer",
                        "test-model",
                    )
                } else {
                    sse::responses_api_reasoning_and_text_events(
                        "fresh thought",
                        "clean answer",
                        "test-model",
                    )
                };
                let events = sse_events_to_axum(events);
                Sse::new(stream::iter(
                    events.into_iter().map(Ok::<_, std::convert::Infallible>),
                ))
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let mut config = responses_config(server.base_url(), Some(DoomLoopRecoveryPolicy::default()));
    config.max_retries = Some(0);
    let handle = SamplerActor::spawn(config, RetryPolicy::default(), event_tx);

    let collected = handle
        .submit_and_collect_with_metadata(RequestId::from("req-doom-resample"), user_request("hi"))
        .await;
    server.shutdown();

    assert!(collected.terminal_event_queued);
    assert_eq!(
        collected.doom_loop_signals,
        vec!["tail_repetition:8@thinking".to_string()],
    );
    assert_eq!(1, collected.doom_loop_recovery_attempts.len());
    assert_eq!(
        collected.doom_loop_recovery_attempts[0].triggers,
        vec!["tail_repetition:8@thinking".to_string()]
    );
    let (response, _metrics) = collected
        .result
        .expect("recovery accepts the clean resample");
    assert_eq!(counter.load(Ordering::SeqCst), 2, "exactly one resample");
    assert_eq!(response.assistant_text(), "clean answer");
    assert!(
        response.doom_loop_signals.is_empty(),
        "the accepted response is the clean resample"
    );

    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(1)).await;
    assert!(events.iter().any(|event| matches!(
        event,
        SamplingEvent::DoomLoopSignals { triggers, .. }
            if triggers == &["tail_repetition:8@thinking".to_string()]
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        SamplingEvent::Retrying {
            doom_loop_triggers: Some(triggers),
            ..
        } if triggers == &["tail_repetition:8@thinking".to_string()]
    )));

    let bodies = bodies.lock().unwrap();
    let retry_input = bodies[1]["input"].as_array().unwrap();
    assert_eq!(retry_input.len(), 4);
    assert_eq!(retry_input[1]["summary"][0]["text"], "loop loop loop");
    assert_eq!(retry_input[2]["role"], "assistant");
    assert_eq!(retry_input[2]["content"], "poisoned answer");
    assert_eq!(retry_input[3]["role"], "user");
    let reminder = retry_input[3]["content"]
        .as_str()
        .expect("the reminder is a text item");
    assert!(
        reminder.starts_with("<system_reminder>") && reminder.ends_with("</system_reminder>"),
        "the retry closes with a synthetic system-reminder envelope: {reminder}"
    );
}

/// A caller that opted into `retry_only_before_output` cannot retract text it already received.
/// So a doomed turn that streamed output fails instead of resampling over the delivered prefix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn responses_doom_loop_does_not_resample_after_output_when_retry_only_before_output() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/responses",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let events = sse_events_to_axum(sse::responses_api_doom_loop_terminal_only_events(
                    &["tail_repetition:8@thinking"],
                    "loop loop loop",
                    "poisoned answer",
                    "test-model",
                ));
                Sse::new(stream::iter(
                    events.into_iter().map(Ok::<_, std::convert::Infallible>),
                ))
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let retry_policy = RetryPolicy {
        retry_only_before_output: true,
        ..RetryPolicy::default()
    };
    let handle = SamplerActor::spawn(
        responses_config(server.base_url(), Some(DoomLoopRecoveryPolicy::default())),
        retry_policy,
        event_tx,
    );

    let result = handle
        .submit_and_collect(RequestId::from("req-doom-no-retract"), user_request("hi"))
        .await;
    server.shutdown();

    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "no resample after output"
    );
    assert!(
        matches!(
            result,
            Err(fuigo_sampling_types::SamplingError::DoomLoopDetected { .. })
        ),
        "the doomed turn is surfaced rather than resampled: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Helpers for draining the event channel
// ---------------------------------------------------------------------------

/// A reasoning model that streams only reasoning (no text, no tool call) on every attempt.
/// On the default budget this used to resend the byte-identical request 14 more times over ~5 minutes; it must now fail within seconds.
/// Its replies repeat, so the second resend is the nudged one and a think-only reply to it ends the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn responses_reasoning_only_stream_fails_fast_after_the_empty_response_budget() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/responses",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let events = sse_events_to_axum(sse::responses_api_reasoning_only_events(
                    "Let me think about this carefully",
                    "test-model",
                ));
                Sse::new(stream::iter(
                    events.into_iter().map(Ok::<_, std::convert::Infallible>),
                ))
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let mut cfg = responses_config(server.base_url(), None);
    // The production default budget, not this file's test-speed budget of 2.
    cfg.max_retries = Some(fuigo_sampler::DEFAULT_MAX_RETRIES);
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let started = std::time::Instant::now();
    handle.submit(
        RequestId::from("req-reasoning-only"),
        user_request("Say hello in one word."),
    );
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(10)).await;
    let elapsed = started.elapsed();
    server.shutdown();

    assert!(
        elapsed < Duration::from_secs(10),
        "must fail in under 10 s: {elapsed:?}"
    );
    let retrying: Vec<(u32, u32, &str)> = events
        .iter()
        .filter_map(|e| match e {
            SamplingEvent::Retrying {
                attempt,
                max_retries,
                kind,
                ..
            } => Some((*attempt, *max_retries, kind.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(
        retrying,
        vec![(1, 3, "empty_response"), (2, 3, "empty_response")],
        "a plain resend, then the nudged one as the last attempt"
    );
    match events.last().unwrap() {
        SamplingEvent::Failed { error, .. } => {
            assert_eq!(error.kind.as_str(), "empty_response");
            assert_eq!(
                error.empty_response_context.as_ref().map(|c| c.reason),
                Some(fuigo_sampling_types::EmptyReason::ReasoningOnly)
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        3,
        "the original request, one plain resend and the nudged one"
    );
}

/// A 503 retry followed by a reasoning-only reply: the empty replies still get their own full budget.
/// The empty-response attempts used to be checked against the shared retry count, so they got zero resends after announcing a retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn responses_reasoning_only_after_a_503_keeps_its_own_budget() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/responses",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err::<Sse<_>, (StatusCode, String)>((
                        StatusCode::SERVICE_UNAVAILABLE,
                        json!({ "error": { "message": "overloaded" } }).to_string(),
                    ));
                }
                let events = sse_events_to_axum(sse::responses_api_reasoning_only_events(
                    "Let me think about this carefully",
                    "test-model",
                ));
                Ok(Sse::new(stream::iter(
                    events.into_iter().map(Ok::<_, std::convert::Infallible>),
                )))
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let mut cfg = responses_config(server.base_url(), None);
    cfg.max_retries = Some(fuigo_sampler::DEFAULT_MAX_RETRIES);
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let started = std::time::Instant::now();
    handle.submit(
        RequestId::from("req-503-then-reasoning-only"),
        user_request("Say hello in one word."),
    );
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(15)).await;
    let elapsed = started.elapsed();
    server.shutdown();

    let retrying: Vec<(u32, u32, &str)> = events
        .iter()
        .filter_map(|e| match e {
            SamplingEvent::Retrying {
                attempt,
                max_retries,
                kind,
                ..
            } => Some((*attempt, *max_retries, kind.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(
        retrying,
        vec![
            (1, 15, "api"),
            (1, 3, "empty_response"),
            (2, 3, "empty_response")
        ],
        "the 503 retry, then a plain think-only resend and the nudged one, on their own budget"
    );
    match events.last().unwrap() {
        SamplingEvent::Failed { error, .. } => assert_eq!(error.kind.as_str(), "empty_response"),
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        4,
        "the 503, the reasoning-only reply, a plain resend and the nudged one"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "fails in seconds: {elapsed:?}"
    );
}

/// The customer's pattern: a reasoning-only reply, then cached fully-empty replies.
/// Every empty reply of one request shares a single budget, so the announced denominator
/// stays put instead of stepping "(1/2)" then "(2/3)", and the resends stop at the cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn responses_mixed_empty_replies_share_one_announced_budget() {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/responses",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                // The first reply carries reasoning; every later one is fully empty.
                let events = if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    sse::responses_api_reasoning_only_events(
                        "Let me think about this carefully",
                        "test-model",
                    )
                } else {
                    sse::responses_api_script_exact("", "test-model")
                };
                Sse::new(stream::iter(
                    sse_events_to_axum(events)
                        .into_iter()
                        .map(Ok::<_, std::convert::Infallible>),
                ))
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let mut cfg = responses_config(server.base_url(), None);
    cfg.max_retries = Some(fuigo_sampler::DEFAULT_MAX_RETRIES);
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    handle.submit(
        RequestId::from("req-mixed-empty"),
        user_request("Say hello in one word."),
    );
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(15)).await;
    server.shutdown();

    let retrying: Vec<(u32, u32, &str)> = events
        .iter()
        .filter_map(|e| match e {
            SamplingEvent::Retrying {
                attempt,
                max_retries,
                kind,
                ..
            } => Some((*attempt, *max_retries, kind.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(
        retrying,
        vec![(1, 3, "empty_response"), (2, 3, "empty_response")],
        "one budget for both shapes, announced with one denominator"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        3,
        "the reasoning-only reply and two resends, whatever shape the resends come back in"
    );
    match events.last().unwrap() {
        SamplingEvent::Failed { error, .. } => assert_eq!(error.kind.as_str(), "empty_response"),
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// Drain the event channel until a terminal event (`Completed` or `Failed`) is received, or until `deadline` elapses.
async fn drain_until_terminal(
    rx: &mut mpsc::UnboundedReceiver<SamplingEvent>,
    timeout: Duration,
) -> Vec<SamplingEvent> {
    let mut out = Vec::new();
    let start = tokio::time::Instant::now();
    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            panic!(
                "drain_until_terminal timed out after {:?}; got {} events",
                timeout,
                out.len()
            );
        }
        let remaining = timeout - elapsed;
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(ev)) => {
                let terminal = matches!(
                    ev,
                    SamplingEvent::Completed { .. } | SamplingEvent::Failed { .. }
                );
                out.push(ev);
                if terminal {
                    return out;
                }
            }
            Ok(None) => panic!("event channel closed before terminal event"),
            Err(_) => panic!(
                "drain_until_terminal timed out after {:?}; got {} events",
                timeout,
                out.len()
            ),
        }
    }
}

/// Wait for the next event matching `pred`, or return `None` on timeout.
async fn await_event_matching(
    rx: &mut mpsc::UnboundedReceiver<SamplingEvent>,
    mut pred: impl FnMut(&SamplingEvent) -> bool,
    timeout: Duration,
) -> Option<SamplingEvent> {
    let start = tokio::time::Instant::now();
    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return None;
        }
        let remaining = timeout - elapsed;
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(ev)) => {
                if pred(&ev) {
                    return Some(ev);
                }
            }
            Ok(None) => return None,
            Err(_) => return None,
        }
    }
}

// ---------------------------------------------------------------------------
// P189 round 4 (M3): admission at the single dispatch point
// ---------------------------------------------------------------------------

/// A gate the test opens and closes, standing in for a session park.
struct TestGate(tokio::sync::watch::Receiver<bool>);

impl fuigo_sampling_types::DispatchGate for TestGate {
    fn wait_open(&self) -> fuigo_sampling_types::DispatchGateFuture<'_> {
        let mut rx = self.0.clone();
        Box::pin(async move {
            let _ = rx.wait_for(|open| *open).await;
        })
    }
}

fn gated_config(base_url: String, open: bool) -> (SamplerConfig, tokio::sync::watch::Sender<bool>) {
    let (tx, rx) = tokio::sync::watch::channel(open);
    let mut cfg = test_config(base_url, "test-model");
    cfg.dispatch_gate = Some(Arc::new(TestGate(rx)));
    (cfg, tx)
}

fn counting_ok_router(counter: Arc<AtomicU32>, fail_first: bool) -> Router {
    Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let counter = Arc::clone(&counter);
            async move {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                if fail_first && n == 0 {
                    Err::<Sse<_>, (StatusCode, String)>((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({ "error": { "message": "transient" } }).to_string(),
                    ))
                } else {
                    let events = sse::chat_completion_events("ok", "test-model");
                    Ok(Sse::new(stream::iter(
                        events.into_iter().map(Ok::<_, std::convert::Infallible>),
                    )))
                }
            }
        }),
    )
}

/// The subagent case: attempt 1 fails, the park starts, the sampler's backoff ends DURING the park, and the retry
/// must be held at the dispatch point: 0 further requests while parked, exactly 1 after the unpark.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subagent_retry_whose_backoff_ends_during_a_hold_park_sends_nothing() {
    let counter = Arc::new(AtomicU32::new(0));
    let server = MockServer::spawn(counting_ok_router(Arc::clone(&counter), true)).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let (cfg, gate) = gated_config(server.base_url(), true);
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let rid = RequestId::from("req-retry-park");
    handle.submit(rid.clone(), user_request("hi"));
    let _ = await_event_matching(
        &mut event_rx,
        |e| matches!(e, SamplingEvent::Retrying { .. }),
        Duration::from_secs(10),
    )
    .await
    .expect("retrying after the first failure");
    gate.send(false).unwrap(); // park starts while the sampler is in backoff
    tokio::time::sleep(Duration::from_secs(6)).await; // the backoff (about 2s, jittered) ends during the park
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "the retry was sent while parked"
    );

    gate.send(true).unwrap(); // unpark
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(15)).await;
    server.shutdown();
    assert!(
        matches!(events.last(), Some(SamplingEvent::Completed { .. })),
        "{:?}",
        events.last()
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "exactly one request after the unpark"
    );
}

/// A side call (a plain `conversation_collect`, no actor, no retry loop) reaches the dispatch point even if it got
/// past every earlier check: it sends nothing while the gate is closed and one request after it opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_side_call_past_execution_admission_is_held_at_dispatch() {
    let counter = Arc::new(AtomicU32::new(0));
    let server = MockServer::spawn(counting_ok_router(Arc::clone(&counter), false)).await;
    let (cfg, gate) = gated_config(server.base_url(), false);
    let client = fuigo_sampler::SamplingClient::new(cfg).expect("client");
    let call = tokio::spawn(async move { client.conversation_collect(user_request("hi")).await });
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "a side call dispatched while the gate was closed"
    );
    assert!(!call.is_finished());

    gate.send(true).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .expect("finishes")
        .expect("join");
    server.shutdown();
    result.expect("collect after unpark");
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

/// A call cancelled while it waits at the gate ends as cancelled and never dispatches, not even after the unpark.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_call_waiting_at_the_gate_ends_without_dispatch() {
    let counter = Arc::new(AtomicU32::new(0));
    let server = MockServer::spawn(counting_ok_router(Arc::clone(&counter), false)).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let (cfg, gate) = gated_config(server.base_url(), false);
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let rid = RequestId::from("req-cancel-gate");
    handle.submit(rid.clone(), user_request("hi"));
    tokio::time::sleep(Duration::from_millis(500)).await;
    handle.cancel(rid.clone());
    let failed = await_event_matching(
        &mut event_rx,
        |e| matches!(e, SamplingEvent::Failed { .. }),
        Duration::from_secs(5),
    )
    .await
    .expect("Failed event after cancel while gated");
    if let SamplingEvent::Failed { error, .. } = failed {
        assert!(error.message.contains("cancelled"));
    }
    gate.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "a cancelled call dispatched after the unpark"
    );
    assert_eq!(handle.active_count().await, 0);
    server.shutdown();
}

/// Counts `admit` calls (the durable call debit) and nothing else.
#[derive(Debug, Default)]
struct CountingAdmission {
    admits: AtomicU32,
}

impl fuigo_sampling_types::ExecutionAdmission for CountingAdmission {
    fn scope_id(&self) -> &str {
        "p189-a2-count"
    }
    fn admit(
        &self,
        _purpose: fuigo_sampling_types::RequestPurpose,
        _attempt_id: String,
    ) -> fuigo_sampling_types::AdmissionFuture<'_> {
        self.admits.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
    fn settle(
        &self,
        _attempt_id: String,
        _usage: Option<fuigo_sampling_types::TokenUsage>,
    ) -> fuigo_sampling_types::AdmissionFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

/// Grok r4 #7: a call held at the dispatch gate is not admitted yet, and one cancelled there never is: no call
/// slot is consumed by a cancel while parked. Admission happens once, after the gate opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_waiting_at_the_gate_is_not_admitted_until_it_dispatches() {
    let counter = Arc::new(AtomicU32::new(0));
    let server = MockServer::spawn(counting_ok_router(Arc::clone(&counter), false)).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let (cfg, gate) = gated_config(server.base_url(), false);
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);

    let admission = Arc::new(CountingAdmission::default());
    let mut cancelled = user_request("cancel me");
    cancelled.execution_admission = Some(admission.clone());
    let rid = RequestId::from("req-admit-cancel");
    handle.submit(rid.clone(), cancelled);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        admission.admits.load(Ordering::SeqCst),
        0,
        "admitted while held at the gate"
    );
    handle.cancel(rid.clone());
    let _ = await_event_matching(
        &mut event_rx,
        |e| matches!(e, SamplingEvent::Failed { .. }),
        Duration::from_secs(5),
    )
    .await
    .expect("Failed event after cancel while gated");
    assert_eq!(
        admission.admits.load(Ordering::SeqCst),
        0,
        "a cancel at the gate consumed a call slot"
    );

    let mut served = user_request("serve me");
    served.execution_admission = Some(admission.clone());
    handle.submit(RequestId::from("req-admit-serve"), served);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        admission.admits.load(Ordering::SeqCst),
        0,
        "admitted while the gate is closed"
    );
    gate.send(true).unwrap();
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(10)).await;
    server.shutdown();
    assert!(
        matches!(events.last(), Some(SamplingEvent::Completed { .. })),
        "{:?}",
        events.last()
    );
    assert_eq!(
        admission.admits.load(Ordering::SeqCst),
        1,
        "admitted exactly once, after the gate"
    );
}

/// An admission whose `admit` awaits (a durable write) while the gate closes; counts refunds.
#[derive(Debug, Default)]
struct SlowAdmission {
    admits: AtomicU32,
    refunds: AtomicU32,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl fuigo_sampling_types::ExecutionAdmission for SlowAdmission {
    fn scope_id(&self) -> &str {
        "p189-a2-r2-slow"
    }
    fn admit(
        &self,
        _purpose: fuigo_sampling_types::RequestPurpose,
        _attempt_id: String,
    ) -> fuigo_sampling_types::AdmissionFuture<'_> {
        Box::pin(async move {
            self.entered.notify_one();
            self.release.notified().await;
            self.admits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
    fn settle(
        &self,
        _attempt_id: String,
        _usage: Option<fuigo_sampling_types::TokenUsage>,
    ) -> fuigo_sampling_types::AdmissionFuture<'_> {
        Box::pin(async { Ok(()) })
    }
    fn refund(
        &self,
        _purpose: fuigo_sampling_types::RequestPurpose,
        _attempt_id: String,
    ) -> fuigo_sampling_types::AdmissionFuture<'_> {
        self.refunds.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

/// Opus r1 #1: a call inside the durable admission write while the gate closes sends NOTHING until the gate
/// reopens (the gate is awaited again after `admit`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_inside_the_admission_write_when_the_gate_closes_sends_nothing() {
    let counter = Arc::new(AtomicU32::new(0));
    let server = MockServer::spawn(counting_ok_router(Arc::clone(&counter), false)).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let (cfg, gate) = gated_config(server.base_url(), true);
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);
    let admission = Arc::new(SlowAdmission::default());
    let mut request = user_request("hi");
    request.execution_admission = Some(admission.clone());
    handle.submit(RequestId::from("req-r2-slow-admit"), request);
    admission.entered.notified().await; // inside the admission write, gate still open
    gate.send(false).unwrap(); // the park reaches Parked while the write is in flight
    admission.release.notify_one();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "a request left after the park was acknowledged"
    );
    gate.send(true).unwrap();
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(10)).await;
    server.shutdown();
    assert!(
        matches!(events.last(), Some(SamplingEvent::Completed { .. })),
        "{:?}",
        events.last()
    );
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        admission.refunds.load(Ordering::SeqCst),
        0,
        "a dispatched attempt must not be refunded"
    );
}

/// A call cancelled at the second gate (admitted, never sent) gives its call slot back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_cancelled_at_the_second_gate_refunds_its_slot() {
    let counter = Arc::new(AtomicU32::new(0));
    let server = MockServer::spawn(counting_ok_router(Arc::clone(&counter), false)).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let (cfg, gate) = gated_config(server.base_url(), true);
    let handle = SamplerActor::spawn(cfg, RetryPolicy::default(), event_tx);
    let admission = Arc::new(SlowAdmission::default());
    let mut request = user_request("hi");
    request.execution_admission = Some(admission.clone());
    let rid = RequestId::from("req-r2-cancel-second-gate");
    handle.submit(rid.clone(), request);
    admission.entered.notified().await;
    gate.send(false).unwrap();
    admission.release.notify_one();
    tokio::time::sleep(Duration::from_millis(300)).await;
    handle.cancel(rid);
    let _ = await_event_matching(
        &mut event_rx,
        |e| matches!(e, SamplingEvent::Failed { .. }),
        Duration::from_secs(5),
    )
    .await
    .expect("Failed event after cancel at the second gate");
    tokio::time::sleep(Duration::from_millis(300)).await;
    server.shutdown();
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    assert_eq!(admission.admits.load(Ordering::SeqCst), 1);
    assert_eq!(
        admission.refunds.load(Ordering::SeqCst),
        1,
        "the cancelled, never-sent attempt kept its slot"
    );
}

// ---------------------------------------------------------------------------
// Think-only replies (ollama qwen3:8b, canary b20-12 / b20-15)
// ---------------------------------------------------------------------------

/// Captured from ollama: `reasoning` deltas only, then `finish_reason: "stop"`, no content, no tool calls.
const B20_12: [&str; 3] = [
    include_str!("fixtures/ollama_think_only/b20-12-1.sse"),
    include_str!("fixtures/ollama_think_only/b20-12-2.sse"),
    include_str!("fixtures/ollama_think_only/b20-12-3.sse"),
];
const B20_15: [&str; 3] = [
    include_str!("fixtures/ollama_think_only/b20-15-1.sse"),
    include_str!("fixtures/ollama_think_only/b20-15-2.sse"),
    include_str!("fixtures/ollama_think_only/b20-15-3.sse"),
];
/// Captured from the same rig (b20-13): the two planned `use_tool` calls, `finish_reason: "tool_calls"`.
const B20_13_TOOLS: &str = include_str!("fixtures/ollama_think_only/b20-13-tools.sse");

/// Serve `bodies` as raw SSE, one per request (the last repeats), and record every request body.
async fn scripted_chat_server(
    bodies: Vec<String>,
) -> (MockServer, Arc<std::sync::Mutex<Vec<serde_json::Value>>>) {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_handler = Arc::clone(&seen);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |axum::Json(body): axum::Json<serde_json::Value>| {
            let seen = Arc::clone(&seen_handler);
            let bodies = bodies.clone();
            async move {
                let n = {
                    let mut seen = seen.lock().unwrap();
                    seen.push(body);
                    seen.len()
                };
                let body = bodies[(n - 1).min(bodies.len() - 1)].clone();
                (
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    body,
                )
            }
        }),
    );
    (MockServer::spawn(app).await, seen)
}

fn ollama_body(deltas: &[(serde_json::Value, Option<&str>)]) -> String {
    let mut out = String::new();
    for (delta, finish) in deltas {
        let chunk = json!({
            "id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 0,
            "model": "test-model", "system_fingerprint": "fp_ollama",
            "choices": [{ "index": 0, "delta": delta, "finish_reason": finish }]
        });
        out.push_str(&format!("data: {chunk}\n\n"));
    }
    out.push_str("data: [DONE]\n\n");
    out
}

fn messages(body: &serde_json::Value) -> Vec<serde_json::Value> {
    body["messages"].as_array().cloned().unwrap_or_default()
}

/// The production budget (the test default of 2 would cap every chain at one resend).
fn think_only_config(base_url: String) -> SamplerConfig {
    let mut cfg = test_config(base_url, "test-model");
    cfg.max_retries = Some(fuigo_sampler::DEFAULT_MAX_RETRIES);
    cfg
}

/// The six captured think-only replies (b20-12 then b20-15), first `n` of them.
fn think_only_chain(n: usize) -> Vec<String> {
    B20_12
        .iter()
        .chain(B20_15.iter())
        .take(n)
        .map(|s| s.to_string())
        .collect()
}

fn retrying_events(events: &[SamplingEvent]) -> Vec<(u32, u32, String)> {
    events
        .iter()
        .filter_map(|e| match e {
            SamplingEvent::Retrying {
                attempt,
                max_retries,
                reason,
                ..
            } => Some((*attempt, *max_retries, reason.clone())),
            _ => None,
        })
        .collect()
}

/// A think-only chain of up to five captured replies is resent unchanged until the model's tool-call reply completes the turn.
/// The reasoning in ollama's `reasoning` field is recognised: it streams on the reasoning channel and labels each resend.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ollama_think_only_chain_of_up_to_five_is_resent_unchanged_then_completes() {
    for think_only in [1, 5] {
        let mut bodies = think_only_chain(think_only);
        bodies.push(B20_13_TOOLS.to_string());
        let (server, seen) = scripted_chat_server(bodies).await;
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let handle = SamplerActor::spawn(
            think_only_config(server.base_url()),
            RetryPolicy::default(),
            event_tx,
        );
        handle.submit(
            RequestId::from("req-think-only"),
            user_request("Make exactly two tool calls in order."),
        );
        let events = drain_until_terminal(&mut event_rx, Duration::from_secs(40)).await;
        server.shutdown();

        assert!(
            events.iter().any(|e| matches!(
                e,
                SamplingEvent::ChannelToken {
                    channel: SamplingChannel::Reasoning,
                    ..
                }
            )),
            "ollama `reasoning` deltas stream as reasoning"
        );
        let retrying = retrying_events(&events);
        assert_eq!(
            retrying.len(),
            think_only,
            "one resend per think-only reply"
        );
        for (n, (attempt, max, reason)) in retrying.iter().enumerate() {
            assert_eq!(
                (*attempt, *max),
                (n as u32 + 1, 6),
                "resend {n} announces x/6"
            );
            assert!(reason.contains("reasoning_only") && reason.contains("think-only"));
        }
        match events.last().unwrap() {
            SamplingEvent::Completed { response, .. } => {
                let a = response.assistant().expect("assistant");
                assert_eq!(a.tool_calls.len(), 2, "the planned tool calls arrive");
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), think_only + 1);
        for body in seen.iter() {
            assert_eq!(
                serde_json::to_vec(body).unwrap(),
                serde_json::to_vec(&seen[0]).unwrap(),
                "every resend is byte-identical to the first request"
            );
        }
    }
}

/// Six think-only replies in a row, then a seventh to the nudged resend, end as a think-only failure, not a generic empty one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ollama_think_only_six_times_surfaces_think_only_after_six_attempts() {
    let (server, seen) = scripted_chat_server(think_only_chain(6)).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        think_only_config(server.base_url()),
        RetryPolicy::default(),
        event_tx,
    );
    handle.submit(
        RequestId::from("req-think-only-six"),
        user_request("Make exactly two tool calls in order."),
    );
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(40)).await;
    server.shutdown();

    assert_eq!(
        retrying_events(&events).len(),
        6,
        "five resends and the nudged one"
    );
    match events.last().unwrap() {
        SamplingEvent::Failed { error, .. } => {
            assert_eq!(error.kind.as_str(), "empty_response");
            let context = error.empty_response_context.as_ref().expect("context");
            assert_eq!(
                context.reason,
                fuigo_sampling_types::EmptyReason::ReasoningOnly
            );
            assert!(context.had_reasoning);
            assert_eq!(context.finish_reason.as_deref(), Some("stop"));
            assert_eq!(context.attempts, Some(7));
            assert!(
                error.message.contains("think-only"),
                "honest label: {}",
                error.message
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_six_unchanged_then_one_nudge(&seen.lock().unwrap());
}

/// The words only the think-only nudge carries.
const NUDGE_MARK: &str = "Reply to the user now";

fn carries_nudge(body: &serde_json::Value) -> bool {
    body.to_string().contains(NUDGE_MARK)
}

/// Run one request against `server` on the production budget and return its events and every request body.
async fn think_only_run(
    server: MockServer,
    seen: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
) -> (Vec<SamplingEvent>, Vec<serde_json::Value>) {
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        think_only_config(server.base_url()),
        RetryPolicy::default(),
        event_tx,
    );
    handle.submit(
        RequestId::from("req-think-only-nudge"),
        user_request("Make exactly two tool calls in order."),
    );
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(40)).await;
    server.shutdown();
    let seen = seen.lock().unwrap().clone();
    (events, seen)
}

/// The six budgeted attempts are byte-identical; the one after them is the first request plus the nudge alone.
fn assert_six_unchanged_then_one_nudge(seen: &[serde_json::Value]) {
    assert_eq!(
        seen.len(),
        7,
        "six budgeted attempts, then one nudged resend"
    );
    assert!(
        seen[..6].iter().all(|b| *b == seen[0]),
        "the six budgeted attempts stay byte-identical"
    );
    assert!(
        !seen[..6].iter().any(carries_nudge),
        "no nudge before the budget is spent"
    );
    let (first, last) = (messages(&seen[0]), messages(&seen[6]));
    assert_eq!(last.len(), first.len() + 1, "the nudge adds one message");
    assert_eq!(last[..first.len()], first[..], "and changes nothing else");
    assert!(
        carries_nudge(&last[first.len()]),
        "the added message is the nudge"
    );
}

/// det1: a deterministic model replays the same think-only reply to the same request, so unchanged resends cannot recover.
/// After the six unchanged attempts, one resend that carries the nudge gets the planned tool calls in the same turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn six_think_only_replies_get_one_nudged_resend_that_completes() {
    let mut bodies = think_only_chain(6);
    bodies.push(B20_13_TOOLS.to_string());
    let (server, seen) = scripted_chat_server(bodies).await;
    let (events, seen) = think_only_run(server, seen).await;

    match events.last().unwrap() {
        SamplingEvent::Completed { response, .. } => {
            let a = response.assistant().expect("assistant");
            assert_eq!(a.tool_calls.len(), 2, "the planned tool calls arrive");
        }
        other => panic!("expected Completed, got {other:?}"),
    }
    let retrying = retrying_events(&events);
    assert_eq!(
        retrying.len(),
        6,
        "five unchanged resends and the nudged one"
    );
    assert_eq!(
        (retrying[5].0, retrying[5].1),
        (6, 7),
        "the nudged resend is announced as the last attempt"
    );
    assert_six_unchanged_then_one_nudge(&seen);
}

/// A stuck model replays the same think-only reply until it is told to answer. The second identical reply skips the
/// plain resends left: the nudge goes out as resend 2 (attempt 3), not after six attempts, and gets the visible reply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stuck_model_that_answers_only_when_nudged_is_nudged_on_resend_2() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_handler = Arc::clone(&seen);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |axum::Json(body): axum::Json<serde_json::Value>| {
            let seen = Arc::clone(&seen_handler);
            async move {
                let reply = if carries_nudge(&body) {
                    ollama_body(&[(
                        json!({"role": "assistant", "content": "Done."}),
                        Some("stop"),
                    )])
                } else {
                    B20_12[0].to_string()
                };
                seen.lock().unwrap().push(body);
                (
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    reply,
                )
            }
        }),
    );
    let (events, seen) = think_only_run(MockServer::spawn(app).await, seen).await;

    match events.last().unwrap() {
        SamplingEvent::Completed { response, .. } => {
            let a = response.assistant().expect("assistant");
            assert_eq!(a.content.as_ref(), "Done.");
        }
        other => panic!("expected Completed, got {other:?}"),
    }
    let retrying = retrying_events(&events);
    let announced: Vec<(u32, u32)> = retrying.iter().map(|(a, m, _)| (*a, *m)).collect();
    assert_eq!(
        announced,
        vec![(1, 6), (2, 3)],
        "one plain resend, then the nudged one"
    );
    assert_eq!(
        seen.len(),
        3,
        "two identical think-only replies, then the nudged request"
    );
    assert!(
        seen[1] == seen[0] && !carries_nudge(&seen[1]),
        "the first resend is plain"
    );
    let (first, last) = (messages(&seen[0]), messages(&seen[2]));
    assert_eq!(last.len(), first.len() + 1, "the nudge adds one message");
    assert_eq!(last[..first.len()], first[..], "and changes nothing else");
    assert!(
        carries_nudge(&last[first.len()]),
        "the added message is the nudge"
    );
}

/// The stuck model never answers: a think-only reply to the nudged resend ends the turn there, after three attempts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stuck_model_still_think_only_after_the_nudge_ends_after_three_attempts() {
    let (server, seen) = scripted_chat_server(vec![B20_12[0].to_string()]).await;
    let (events, seen) = think_only_run(server, seen).await;
    match events.last().unwrap() {
        SamplingEvent::Failed { error, .. } => {
            let context = error.empty_response_context.as_ref().expect("context");
            assert_eq!(
                context.reason,
                fuigo_sampling_types::EmptyReason::ReasoningOnly
            );
            assert_eq!(context.attempts, Some(3));
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(seen.len(), 3);
    assert!(carries_nudge(&seen[2]) && !carries_nudge(&seen[1]));
}

/// A stop after the second think-only reply ends the turn during the resend wait: no third request is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_after_the_second_think_only_reply_makes_no_further_requests() {
    let (server, seen) = scripted_chat_server(think_only_chain(6)).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        think_only_config(server.base_url()),
        RetryPolicy::default(),
        event_tx,
    );
    let rid = RequestId::from("req-think-only-stop");
    handle.submit(
        rid.clone(),
        user_request("Make exactly two tool calls in order."),
    );
    let mut resends = 0;
    while resends < 2 {
        match tokio::time::timeout(Duration::from_secs(20), event_rx.recv()).await {
            Ok(Some(SamplingEvent::Retrying { .. })) => resends += 1,
            Ok(Some(SamplingEvent::Completed { .. } | SamplingEvent::Failed { .. })) => {
                panic!("terminal before the second think-only reply")
            }
            Ok(Some(_)) => {}
            other => panic!("event stream ended: {other:?}"),
        }
    }
    // The second Retrying is announced after attempt 2 came back think-only, before the 2 s resend wait
    handle.cancel(rid);
    let started = tokio::time::Instant::now();
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(5)).await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the stop ends the turn promptly"
    );
    match events.last().unwrap() {
        SamplingEvent::Failed { error, .. } => assert_eq!(error.kind.as_str(), "cancelled"),
        other => panic!("expected the cancelled terminal, got {other:?}"),
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    server.shutdown();
    assert_eq!(seen.lock().unwrap().len(), 2, "no request after the stop");
}

/// A reasoning reply that streamed a partial tool call is a tool-call reply, never a think-only one: it is not resent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_partial_tool_call_after_reasoning_is_never_resent_as_think_only() {
    let partial = ollama_body(&[
        (
            json!({"role": "assistant", "content": "", "reasoning": "Call the tool."}),
            None,
        ),
        (
            json!({"tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                "function": {"name": "use_tool"}}]}),
            Some("stop"),
        ),
    ]);
    let (server, seen) = scripted_chat_server(vec![partial]).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        think_only_config(server.base_url()),
        RetryPolicy::default(),
        event_tx,
    );
    handle.submit(RequestId::from("req-partial"), user_request("hi"));
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(20)).await;
    server.shutdown();
    assert!(retrying_events(&events).is_empty(), "no resend");
    assert!(
        !matches!(events.last().unwrap(), SamplingEvent::Failed { error, .. } if error.kind.as_str() == "empty_response"),
        "never classified empty: {:?}",
        events.last()
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
}

/// A stop while think-only resend #2 is still streaming ends the turn promptly: the open stream is dropped and no
/// further request is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_during_the_second_think_only_resend_stream_makes_no_further_requests() {
    let requests = Arc::new(AtomicU32::new(0));
    let requests_handler = Arc::clone(&requests);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let n = requests_handler.fetch_add(1, Ordering::SeqCst) as usize;
            async move {
                let body = if n < 2 {
                    stream::iter(vec![Ok::<_, std::convert::Infallible>(
                        B20_12[n].to_string(),
                    )])
                    .boxed()
                } else {
                    // Resend #2 streams its first captured reasoning delta, then hangs mid-stream
                    let first = B20_12[2].split_inclusive("\n\n").next().unwrap();
                    stream::iter(vec![Ok(first.to_string())])
                        .chain(stream::pending())
                        .boxed()
                };
                (
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    axum::body::Body::from_stream(body),
                )
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        think_only_config(server.base_url()),
        RetryPolicy::default(),
        event_tx,
    );
    let rid = RequestId::from("req-think-only-stop-in-stream");
    handle.submit(
        rid.clone(),
        user_request("Make exactly two tool calls in order."),
    );
    let mut resends = 0;
    while resends < 2 {
        match tokio::time::timeout(Duration::from_secs(20), event_rx.recv()).await {
            Ok(Some(SamplingEvent::Retrying { .. })) => resends += 1,
            Ok(Some(SamplingEvent::Completed { .. } | SamplingEvent::Failed { .. })) => {
                panic!("terminal before the second think-only resend")
            }
            Ok(Some(_)) => {}
            other => panic!("event stream ended: {other:?}"),
        }
    }
    // The next reasoning token comes from resend #2's response, which is now streaming
    await_event_matching(
        &mut event_rx,
        |e| {
            matches!(
                e,
                SamplingEvent::ChannelToken {
                    channel: SamplingChannel::Reasoning,
                    ..
                }
            )
        },
        Duration::from_secs(10),
    )
    .await
    .expect("resend #2 is streaming");
    assert_eq!(requests.load(Ordering::SeqCst), 3, "resend #2 is in flight");
    handle.cancel(rid);
    let started = tokio::time::Instant::now();
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(5)).await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the stop ends the turn promptly"
    );
    match events.last().unwrap() {
        SamplingEvent::Failed { error, .. } => assert_eq!(error.kind.as_str(), "cancelled"),
        other => panic!("expected the cancelled terminal, got {other:?}"),
    }
    assert!(
        retrying_events(&events).is_empty(),
        "no resend after the stop"
    );
    // Longer than the 2 s resend wait: a resend that slipped through would have been made by now
    tokio::time::sleep(Duration::from_secs(3)).await;
    server.shutdown();
    assert_eq!(
        requests.load(Ordering::SeqCst),
        3,
        "no request after the stop"
    );
}

/// The extra think-only resends end at the 180 s window from the first think-only reply, end to end on a mocked clock.
/// Resend #3 starts 120 s after the first think-only reply and is allowed; its reply is evaluated 190 s in, so the turn
/// spends the unchanged resends after 4 requests instead of 6; one nudged resend follows, then the think-only failure.
#[tokio::test]
async fn think_only_resends_stop_at_the_wall_cap_from_the_first_think_only_reply() {
    think_only_wall_cap_chain().await;
}

/// The same 180 s window caps a think-only chain under Murage's `FUIGO_MAX_RETRIES=3` pin, read from the env.
#[tokio::test]
async fn think_only_resends_stop_at_the_wall_cap_under_fuigo_max_retries_3() {
    if in_max_retries_env_child(
        "think_only_resends_stop_at_the_wall_cap_under_fuigo_max_retries_3",
        "3",
    )
    .await
    {
        think_only_wall_cap_chain().await;
    }
}

async fn think_only_wall_cap_chain() {
    let (server, seen) = scripted_chat_server(think_only_chain(6)).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        think_only_config(server.base_url()),
        RetryPolicy::default(),
        event_tx,
    );
    handle.submit(
        RequestId::from("req-think-only-wall-cap"),
        user_request("Make exactly two tool calls in order."),
    );
    let mut events = Vec::new();
    loop {
        let event = tokio::time::timeout(Duration::from_secs(20), event_rx.recv())
            .await
            .expect("event before the timeout")
            .expect("event stream open");
        let resend = matches!(event, SamplingEvent::Retrying { .. });
        let terminal = matches!(
            event,
            SamplingEvent::Completed { .. } | SamplingEvent::Failed { .. }
        );
        events.push(event);
        if terminal {
            break;
        }
        if resend {
            // Move the clock during the resend wait, while no request is in flight: 60 s, 60 s, then 70 s
            let step = if retrying_events(&events).len() < 3 {
                60
            } else {
                70
            };
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(step)).await;
            tokio::time::resume();
        }
    }
    server.shutdown();

    let retrying = retrying_events(&events);
    assert_eq!(
        retrying.len(),
        4,
        "resend #3 is inside the window, then the nudged one"
    );
    assert_eq!(
        (retrying[3].0, retrying[3].1),
        (4, 5),
        "the nudged resend is the last attempt"
    );
    match events.last().unwrap() {
        SamplingEvent::Failed { error, .. } => {
            assert_eq!(error.kind.as_str(), "empty_response");
            assert!(
                error.message.contains("(reasoning_only) - think-only"),
                "honest label: {}",
                error.message
            );
            let context = error.empty_response_context.as_ref().expect("context");
            assert_eq!(
                context.reason,
                fuigo_sampling_types::EmptyReason::ReasoningOnly
            );
            assert_eq!(context.attempts, Some(5));
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    let seen = seen.lock().unwrap();
    assert_eq!(
        seen.len(),
        5,
        "no unchanged resend after the window, one nudged resend"
    );
    assert!(seen[..4].iter().all(|b| *b == seen[0] && !carries_nudge(b)));
    assert!(
        carries_nudge(&seen[4]),
        "the last request carries the nudge"
    );
}

/// An attempt that streamed visible text after its reasoning is a reply, never a think-only one: one request, no resend.
/// Covers the text arriving on the finishing chunk, and the text followed by an empty finishing chunk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reasoning_then_visible_text_is_never_resent_as_think_only() {
    let reasoning = (
        json!({"role": "assistant", "content": "", "reasoning": "Plan the reply."}),
        None,
    );
    let shapes = [
        ollama_body(&[
            reasoning.clone(),
            (
                json!({"role": "assistant", "content": "Done."}),
                Some("stop"),
            ),
        ]),
        ollama_body(&[
            reasoning.clone(),
            (json!({"role": "assistant", "content": "Done."}), None),
            (json!({"role": "assistant", "content": ""}), Some("stop")),
        ]),
    ];
    for (shape, body) in shapes.into_iter().enumerate() {
        let (server, seen) = scripted_chat_server(vec![body]).await;
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let handle = SamplerActor::spawn(
            think_only_config(server.base_url()),
            RetryPolicy::default(),
            event_tx,
        );
        handle.submit(RequestId::from("req-visible-text"), user_request("hi"));
        let events = drain_until_terminal(&mut event_rx, Duration::from_secs(20)).await;
        server.shutdown();
        assert!(
            retrying_events(&events).is_empty(),
            "shape {shape}: no Retrying"
        );
        match events.last().unwrap() {
            SamplingEvent::Completed { response, .. } => {
                assert_eq!(response.assistant_text(), "Done.", "shape {shape}")
            }
            other => panic!("shape {shape}: expected Completed, got {other:?}"),
        }
        assert_eq!(seen.lock().unwrap().len(), 1, "shape {shape}: one request");
    }
}

/// Turns that do not stop think-only send exactly what they sent before the fix:
/// a normal reasoning-and-text turn makes one request, and a fully empty reply is resent byte-identical.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_think_only_turns_make_unchanged_requests() {
    let normal = ollama_body(&[
        (
            json!({"role": "assistant", "content": "", "reasoning": "Short."}),
            None,
        ),
        (json!({"role": "assistant", "content": "ok"}), Some("stop")),
    ]);
    let (server, seen) = scripted_chat_server(vec![normal.clone()]).await;
    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        test_config(server.base_url(), "test-model"),
        RetryPolicy::default(),
        event_tx,
    );
    let request = user_request("hi");
    let _ = handle
        .submit_and_collect(RequestId::from("req-normal"), request)
        .await
        .expect("normal turn ok");
    server.shutdown();
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "no extra round trip");
        assert_eq!(
            messages(&seen[0]),
            vec![json!({"role": "user", "content": "hi"})],
            "the request carries only the conversation"
        );
    }

    let empty = ollama_body(&[(json!({"role": "assistant", "content": ""}), Some("stop"))]);
    let (server, seen) = scripted_chat_server(vec![empty, normal]).await;
    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        test_config(server.base_url(), "test-model"),
        RetryPolicy::default(),
        event_tx,
    );
    let _ = handle
        .submit_and_collect(RequestId::from("req-empty"), user_request("hi"))
        .await
        .expect("resend recovers");
    server.shutdown();
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[0], seen[1],
            "a no_visible_content reply is resent unchanged"
        );
    }

    // Fully empty replies keep the old budget of three attempts on the production budget.
    let empty = ollama_body(&[(json!({"role": "assistant", "content": ""}), Some("stop"))]);
    let (server, seen) = scripted_chat_server(vec![empty]).await;
    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        think_only_config(server.base_url()),
        RetryPolicy::default(),
        event_tx,
    );
    let err = handle
        .submit_and_collect(RequestId::from("req-empty-budget"), user_request("hi"))
        .await
        .expect_err("empty every time");
    server.shutdown();
    match err {
        fuigo_sampling_types::SamplingError::EmptyResponse { context } => {
            assert_eq!(
                context.reason,
                fuigo_sampling_types::EmptyReason::NoVisibleContent
            );
            assert_eq!(context.attempts, Some(3));
        }
        other => panic!("expected EmptyResponse, got {other:?}"),
    }
    assert_eq!(
        seen.lock().unwrap().len(),
        3,
        "old budget for no_visible_content"
    );
}

/// Run one turn and return the response and the request body the server saw.
async fn one_chat_turn(
    sse_body: String,
    request: ConversationRequest,
) -> (
    fuigo_sampling_types::ConversationResponse,
    serde_json::Value,
) {
    let (server, seen) = scripted_chat_server(vec![sse_body]).await;
    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        test_config(server.base_url(), "test-model"),
        RetryPolicy::default(),
        event_tx,
    );
    let (response, _) = handle
        .submit_and_collect(RequestId::from("req-turn"), request)
        .await
        .expect("turn ok");
    server.shutdown();
    let body = seen.lock().unwrap()[0].clone();
    (response, body)
}

/// The turn-2 conversation: the turn-1 user message, the response items, then a new user message.
fn second_turn(response: &fuigo_sampling_types::ConversationResponse) -> ConversationRequest {
    let mut request = user_request("hi");
    request.items.extend(response.items.iter().cloned());
    request.items.extend(user_request("again").items);
    request
}

fn text_turn(reasoning: serde_json::Value) -> String {
    ollama_body(&[
        (reasoning, None),
        (json!({"role": "assistant", "content": "ok"}), Some("stop")),
    ])
}

/// Reasoning read from `delta.reasoning` is shown and stored, but never sent back.
/// Turn 2 is exactly what 1a61f452 sent: that code never read `reasoning`, so it stored no reasoning item.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delta_reasoning_is_display_only_and_never_echoed() {
    let turn1 = text_turn(json!({"role": "assistant", "content": "", "reasoning": "Plan."}));
    let (response, _) = one_chat_turn(turn1.clone(), user_request("hi")).await;
    let reasoning: Vec<_> = response.reasoning_items().collect();
    assert_eq!(reasoning.len(), 1, "the reasoning is stored");
    assert!(fuigo_sampling_types::is_display_only_reasoning_item(
        reasoning[0]
    ));

    let (_, body) = one_chat_turn(turn1.clone(), second_turn(&response)).await;
    assert!(
        !messages(&body)
            .iter()
            .any(|m| m.to_string().contains("reasoning")),
        "no reasoning field is sent back: {body}"
    );
    // What 1a61f452 sent: the same history with no reasoning item
    let mut old = response.clone();
    old.items
        .retain(|i| !matches!(i, ConversationItem::Reasoning(_)));
    let (_, old_body) = one_chat_turn(turn1, second_turn(&old)).await;
    assert_eq!(body, old_body, "turn 2 is unchanged from 1a61f452");
    assert_eq!(
        messages(&body),
        vec![
            json!({"role": "user", "content": "hi"}),
            json!({"role": "assistant", "content": "ok", "model_id": "test-model"}),
            json!({"role": "user", "content": "again"}),
        ]
    );
}

/// Reasoning that arrives as `reasoning_content` is still echoed back as `reasoning_content`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reasoning_content_is_still_echoed() {
    let turn1 =
        text_turn(json!({"role": "assistant", "content": "", "reasoning_content": "Plan."}));
    let (response, _) = one_chat_turn(turn1.clone(), user_request("hi")).await;
    let reasoning: Vec<_> = response.reasoning_items().collect();
    assert_eq!(reasoning.len(), 1);
    assert!(!fuigo_sampling_types::is_display_only_reasoning_item(
        reasoning[0]
    ));

    let (_, body) = one_chat_turn(turn1, second_turn(&response)).await;
    assert_eq!(messages(&body)[1]["reasoning_content"], json!("Plan."));
}

/// An empty `reasoning_content` does not hide a non-empty `reasoning` in the same delta.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_reasoning_content_does_not_hide_reasoning() {
    let turn1 = text_turn(
        json!({"role": "assistant", "content": "", "reasoning_content": "", "reasoning": "Plan."}),
    );
    let (response, _) = one_chat_turn(turn1, user_request("hi")).await;
    let reasoning: Vec<_> = response.reasoning_items().collect();
    assert_eq!(reasoning.len(), 1, "the reasoning is read");
    assert_eq!(
        fuigo_sampling_types::reasoning_item_text(reasoning[0]),
        "Plan."
    );
    assert!(fuigo_sampling_types::is_display_only_reasoning_item(
        reasoning[0]
    ));
}

// ---------------------------------------------------------------------------
// FUIGO_MAX_RETRIES from the process env (Murage pins 3 on every bot turn)
// ---------------------------------------------------------------------------

const MAX_RETRIES_ENV_CHILD: &str = "FUIGO_SAMPLER_MAX_RETRIES_ENV_CHILD";

/// Production reads `FUIGO_MAX_RETRIES` from the process env (`resolve_max_retries`), and the env is process-wide, so a
/// witness re-runs itself in a child test process with the variable set. Returns true in the child (run the body);
/// in the parent it runs the child, asserts that `test` ran and passed there, and returns false.
async fn in_max_retries_env_child(test: &str, value: &str) -> bool {
    if std::env::var_os(MAX_RETRIES_ENV_CHILD).is_some() {
        assert_eq!(std::env::var("FUIGO_MAX_RETRIES").as_deref(), Ok(value));
        return true;
    }
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(MAX_RETRIES_ENV_CHILD, "1")
        .env("FUIGO_MAX_RETRIES", value)
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "FUIGO_MAX_RETRIES={value} child run of {test}:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

/// Under `FUIGO_MAX_RETRIES=3`, a think-only chain on Chat Completions still gets its own six attempts: six requests,
/// resends announced 1/6..5/6, which the shell logs as `think-only resend attempt 2/6 .. 6/6`, then the nudged one (7/7).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn think_only_chain_under_fuigo_max_retries_3_gets_its_own_six_attempts() {
    if !in_max_retries_env_child(
        "think_only_chain_under_fuigo_max_retries_3_gets_its_own_six_attempts",
        "3",
    )
    .await
    {
        return;
    }
    let (server, seen) = scripted_chat_server(think_only_chain(6)).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        think_only_config(server.base_url()),
        RetryPolicy::default(),
        event_tx,
    );
    handle.submit(
        RequestId::from("req-think-only-env-3"),
        user_request("Make exactly two tool calls in order."),
    );
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(40)).await;
    server.shutdown();

    let retrying = retrying_events(&events);
    let announced: Vec<(u32, u32)> = retrying.iter().map(|(a, m, _)| (*a, *m)).collect();
    assert_eq!(
        announced,
        vec![(1, 6), (2, 6), (3, 6), (4, 6), (5, 6), (6, 7)]
    );
    // The shell's `shell.turn.think_only_resend` line is `attempt + 1`/`max_retries` of each Retrying
    let last = &retrying[4];
    assert_eq!(
        format!(
            "think-only resend attempt {}/{} reason=think_only",
            last.0 + 1,
            last.1
        ),
        "think-only resend attempt 6/6 reason=think_only"
    );
    match events.last().unwrap() {
        SamplingEvent::Failed { error, .. } => {
            assert!(error.message.contains("think-only"), "{}", error.message);
            let context = error.empty_response_context.as_ref().expect("context");
            assert_eq!(context.attempts, Some(7));
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_six_unchanged_then_one_nudge(&seen.lock().unwrap());
}

/// Under `FUIGO_MAX_RETRIES=3`, a dead Router still ends in bounded time: a refused connection and a 5xx each stop at
/// three attempts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dead_router_under_fuigo_max_retries_3_still_stops_at_three_attempts() {
    if !in_max_retries_env_child(
        "dead_router_under_fuigo_max_retries_3_still_stops_at_three_attempts",
        "3",
    )
    .await
    {
        return;
    }
    // Connection refused: a held closed loopback port
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        think_only_config(format!("{}/v1", fuigo_test_support::refused_loopback_url())),
        RetryPolicy::default(),
        event_tx,
    );
    handle.submit(RequestId::from("req-refused-env-3"), user_request("hi"));
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(30)).await;
    let announced: Vec<(u32, u32)> = retrying_events(&events)
        .iter()
        .map(|(a, m, _)| (*a, *m))
        .collect();
    assert_eq!(announced, vec![(1, 3), (2, 3)], "refused: three attempts");
    assert!(matches!(events.last(), Some(SamplingEvent::Failed { .. })));

    // 5xx
    let counter = Arc::new(AtomicU32::new(0));
    let counter_handler = Arc::clone(&counter);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let counter = Arc::clone(&counter_handler);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({ "error": { "message": "router down" } }).to_string(),
                )
            }
        }),
    );
    let server = MockServer::spawn(app).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        think_only_config(server.base_url()),
        RetryPolicy::default(),
        event_tx,
    );
    handle.submit(RequestId::from("req-5xx-env-3"), user_request("hi"));
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(30)).await;
    server.shutdown();
    assert!(matches!(events.last(), Some(SamplingEvent::Failed { .. })));
    assert_eq!(retrying_events(&events).len(), 2);
    assert_eq!(counter.load(Ordering::SeqCst), 3, "5xx: three attempts");
}

/// `FUIGO_MAX_RETRIES=0` (resends disabled) still turns think-only resends off: one request, no Retrying.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fuigo_max_retries_0_turns_think_only_resends_off() {
    if !in_max_retries_env_child("fuigo_max_retries_0_turns_think_only_resends_off", "0").await {
        return;
    }
    let (server, seen) = scripted_chat_server(think_only_chain(6)).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(
        think_only_config(server.base_url()),
        RetryPolicy::default(),
        event_tx,
    );
    handle.submit(
        RequestId::from("req-think-only-env-0"),
        user_request("Make exactly two tool calls in order."),
    );
    let events = drain_until_terminal(&mut event_rx, Duration::from_secs(20)).await;
    server.shutdown();
    assert!(retrying_events(&events).is_empty(), "no think-only resend");
    match events.last().unwrap() {
        SamplingEvent::Failed { error, .. } => {
            assert_eq!(error.kind.as_str(), "empty_response");
            let context = error.empty_response_context.as_ref().expect("context");
            assert_eq!(
                context.reason,
                fuigo_sampling_types::EmptyReason::ReasoningOnly
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(seen.lock().unwrap().len(), 1, "one request");
}
