//! P70a: what the sampler LOGS holds no credential the request carried (see the test's doc).
//!
//! This test owns a dedicated binary on purpose. `tracing` keeps one process-wide callsite-interest cache. A callsite
//! registered by another thread while this test's scoped subscriber is being installed can be cached as "never"
//! (tracing-core computes the interest before it links the callsite into the registry, so a concurrent
//! `rebuild_interest_cache` can miss it), and its records are then lost. Inside the lib test binary dozens of other
//! tests drive the same client callsites on other threads, which made this test fail about once a gate run. Alone in
//! its binary nothing else can touch a callsite while it runs, so the capture is deterministic.

use fuigo_sampler::{ApiBackend, SamplerConfig, SamplingClient};
use fuigo_sampling_types::{ChatCompletionRequest, CreateResponseWrapper, SamplingError, rs};
use tokio::net::TcpListener;

fn minimal_config() -> SamplerConfig {
    SamplerConfig {
        api_key: Some("test-key".to_string()),
        base_url: "https://example.test".to_string(),
        model: "test-model".to_string(),
        api_backend: ApiBackend::ChatCompletions,
        context_window: 8192,
        ..SamplerConfig::default()
    }
}

/// P70a: what the sampler LOGS holds no credential the request carried, and a body that fails to deserialize
/// is neither logged nor quoted in the error.
///
/// The request's URL carries keys (base-URL query and configured `query_params`) and its headers carry
/// credentials under names a denylist misses (`Cookie`, `x-credential`, a well-known name mapped to a key).
/// Every span and event the client emits, at every level, is captured across: a 401, a 500, a 2xx body that does
/// not deserialize, malformed stream chunks on the Responses and Chat Completions backends, and a refused
/// connection. No eight-character run of any credential is in any record. Controls: the endpoint path and the
/// header NAMES were logged, and each failure was logged.
///
/// Scope: logs only. The text of the errors RETURNED for a 401 or a transport failure still names the request
/// URL exactly as before (P70b decides what happens to error text); this test does not look at it.
#[tokio::test(flavor = "current_thread")]
async fn request_logs_hold_no_url_or_header_credentials_and_serde_errors_hold_no_body() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    struct Capture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
    struct Render<'a>(&'a mut String);
    impl tracing::field::Visit for Render<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" {}={value:?}", field.name()));
        }
    }
    impl<S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>> tracing_subscriber::Layer<S>
        for Capture
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _: &tracing::Id,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut line = attrs.metadata().name().to_owned();
            attrs.record(&mut Render(&mut line));
            self.0.lock().unwrap().push(line);
        }
        fn on_record(
            &self,
            _: &tracing::Id,
            values: &tracing::span::Record<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut line = "record".to_owned();
            values.record(&mut Render(&mut line));
            self.0.lock().unwrap().push(line);
        }
        fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            let mut line = event.metadata().name().to_owned();
            event.record(&mut Render(&mut line));
            self.0.lock().unwrap().push(line);
        }
    }

    const SECRETS: [&str; 6] = [
        "p70uq-FAKE-1a2b3c4d",
        "p70qp-FAKE-5e6f7a8b",
        "p70ck-FAKE-9c0d1e2f",
        "p70xc-FAKE-3a4b5c6d",
        "p70ak-FAKE-7e8f9a0b",
        "p70ae-FAKE-Kq4ZtW8x",
    ];
    // Values a response body carries; serde's own error text would quote them.
    const BODY_MARK: &str = "p70body-MARK-k3Vb9x";
    const STREAM_MARK: &str = "p70strm-MARK-9ZqT4h";
    const CHAT_MARK: &str = "p70chat-MARK-7HxN2c";
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let status = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(401));
    let (seen, status_now) = (hits.clone(), status.clone());
    let app = axum::Router::new().fallback(move || {
        let (seen, status_now) = (seen.clone(), status_now.clone());
        async move {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let code = status_now.load(std::sync::atomic::Ordering::SeqCst);
            let (content_type, body) = match code {
                // A modelled Responses event with a malformed body, then (201) a malformed chat chunk.
                200 => (
                    "text/event-stream",
                    format!("data: {}\n\n", serde_json::json!({ "type": "response.created", "sequence_number": 0, "response": STREAM_MARK })),
                ),
                201 => ("text/event-stream", format!("data: {}\n\n", serde_json::json!({ "choices": CHAT_MARK }))),
                // A 2xx body that fails to deserialize.
                299 => (
                    "application/json",
                    serde_json::json!({ "id": "r", "object": "response", "created_at": BODY_MARK }).to_string(),
                ),
                _ => ("application/json", serde_json::json!({ "error": { "message": "denied" } }).to_string()),
            };
            let code = if code == 201 { 200 } else { code };
            (axum::http::StatusCode::from_u16(code).unwrap(), [("content-type", content_type)], body)
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(Capture(captured.clone()));
    let _guard = subscriber.set_default();
    // The callsite interest cache is process-wide: a callsite first hit under another subscriber can be cached
    // as disabled and hide this test's own records.
    tracing::callsite::rebuild_interest_cache();
    let client_config = SamplerConfig {
        base_url: format!("http://{addr}/v1?key={}", SECRETS[0]),
        api_backend: ApiBackend::Responses,
        api_key: Some(SECRETS[4].to_owned()),
        query_params: [("sig".to_owned(), SECRETS[1].to_owned())].into_iter().collect(),
        extra_headers: [
            ("Cookie".to_owned(), format!("session={}", SECRETS[2])),
            ("x-credential".to_owned(), SECRETS[3].to_owned()),
            // A well-known header NAME mapped to a credential: the old name-based denylist logged its value.
            ("accept-encoding".to_owned(), SECRETS[5].to_owned()),
        ]
        .into_iter()
        .collect(),
        ..minimal_config()
    };
    let client = SamplingClient::new(client_config.clone()).unwrap();
    let request = rs::CreateResponse { input: rs::InputParam::Text("hi".to_owned()), ..Default::default() };

    // 401 on the stream call (the path that logs the request URL and headers).
    let err = client
        .create_response_stream(CreateResponseWrapper::new(request.clone()))
        .await
        .err()
        .expect("the 401 is an error");
    assert!(hits.load(std::sync::atomic::Ordering::SeqCst) >= 1, "control: the request reached the server");
    assert!(matches!(err, SamplingError::Auth { .. }), "control: a 401, not a pre-dispatch failure: {err:?}");
    // 500 on the unary call.
    status.store(500, std::sync::atomic::Ordering::SeqCst);
    let e = client.create_response(CreateResponseWrapper::new(request.clone())).await.expect_err("a 500 is an error");
    assert!(matches!(e, SamplingError::Api { .. }), "control: {e:?}");
    // A malformed 2xx body.
    status.store(299, std::sync::atomic::Ordering::SeqCst);
    let malformed = client
        .create_response(CreateResponseWrapper::new(request.clone()))
        .await
        .expect_err("a malformed body is an error");
    // A malformed modelled event in a Responses stream.
    status.store(200, std::sync::atomic::Ordering::SeqCst);
    let (mut stream, _, _) = client
        .create_response_stream(CreateResponseWrapper::new(request.clone()))
        .await
        .expect("a 200 stream opens");
    let stream_err = futures_util::StreamExt::next(&mut stream).await.expect("an item").expect_err("a malformed event");
    // A malformed chunk in a Chat Completions stream.
    status.store(201, std::sync::atomic::Ordering::SeqCst);
    let chat_client =
        SamplingClient::new(SamplerConfig { api_backend: ApiBackend::ChatCompletions, ..client_config.clone() }).unwrap();
    let chat_request: ChatCompletionRequest =
        serde_json::from_value(serde_json::json!({ "model": "m", "messages": [{ "role": "user", "content": "hi" }] }))
            .expect("chat request");
    let (mut chunks, _) = chat_client.chat_completion_stream(chat_request).await.expect("a 200 stream opens");
    let chat_err = futures_util::StreamExt::next(&mut chunks).await.expect("an item").expect_err("a malformed chunk");
    server.abort();
    // A transport failure: reqwest's error text names the request URL, and the client logs that text.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_addr = closed.local_addr().unwrap();
    drop(closed);
    // The path holds parentheses: text scanning that stops a URL at `)` would log the query after them.
    let offline = SamplingClient::new(SamplerConfig {
        base_url: format!("http://{closed_addr}/tenant(p70)/v1?key={}", SECRETS[0]),
        api_backend: ApiBackend::Responses,
        query_params: [("sig".to_owned(), SECRETS[1].to_owned())].into_iter().collect(),
        ..minimal_config()
    })
    .unwrap();
    let transport = offline
        .create_response_stream(CreateResponseWrapper::new(request))
        .await
        .err()
        .expect("a refused connection is an error");
    assert!(matches!(transport, SamplingError::Http(_)), "control: a transport failure: {transport:?}");

    // serde errors: category and position only, in the error and in its log line.
    // (the body of a Responses event is an internally tagged enum: serde reports no position for it)
    for (what, error, mark, positioned) in [
        ("unary body", &malformed, BODY_MARK, true),
        ("responses event", &stream_err, STREAM_MARK, false),
        ("chat chunk", &chat_err, CHAT_MARK, true),
    ] {
        assert!(matches!(error, SamplingError::Serialization(_)), "control ({what}): {error:?}");
        let shown = error.to_string();
        let summary = shown.strip_prefix("serialization error: ").unwrap_or_else(|| panic!("{what}: {shown}"));
        let (category, position) = summary.split_once(" error").unwrap_or_else(|| panic!("{what}: {shown}"));
        assert!(["Data", "Syntax", "Eof", "Io"].contains(&category), "{what}: a category is shown: {shown}");
        if positioned {
            let column = position.strip_prefix(" at line 1 column ").unwrap_or_else(|| panic!("{what}: {shown}"));
            assert!(column.parse::<u32>().is_ok_and(|c| c > 0), "{what}: a position is shown: {shown}");
        } else {
            assert_eq!(position, "", "{what}: nothing but the category: {shown}");
        }
        assert!(!format!("{shown} {error:?}").contains("MARK"), "{what}: the error quotes the body ({mark})");
    }
    let records = captured.lock().unwrap().clone();
    let logs = records.join("\n");
    let failures: Vec<&String> = records.iter().filter(|r| r.contains("Failed to deserialize")).collect();
    assert_eq!(failures.len(), 3, "control: each deserialization failure was logged once: {failures:?}");
    for record in failures {
        assert!(record.contains(" error") && record.contains("body_len="), "{record}");
        assert!(!record.contains("MARK"), "a deserialization failure logged the body: {record}");
    }
    // Nothing else logs a unary response body either. (Stream chunks are logged by the `sse_chunk` event, which
    // P70a does not change.)
    assert!(!logs.contains(BODY_MARK), "the malformed 2xx body was logged: {logs}");

    assert!(logs.contains("/v1/responses"), "control: the endpoint was logged: {logs}");
    for name in ["cookie", "x-credential", "accept-encoding", "authorization"] {
        assert!(logs.contains(&format!("header_name={name}")), "control: the header name {name} was logged: {logs}");
    }
    assert!(!logs.contains("header_value"), "a header value field was logged: {logs}");
    let dispatch_failure = records
        .iter()
        .find(|r| r.contains("HTTP dispatch failed"))
        .unwrap_or_else(|| panic!("control: the transport failure was logged: {logs}"));
    assert!(
        dispatch_failure.contains("/tenant(p70)/v1/responses?key=<redacted>&sig=<redacted>"),
        "control: the failed request's URL is in that line, redacted: {dispatch_failure}"
    );
    for secret in SECRETS {
        let chars: Vec<char> = secret.chars().collect();
        for w in chars.windows(8) {
            let frag: String = w.iter().collect();
            assert!(!logs.contains(&frag), "the sampler logged {frag:?} of a credential: {logs}");
        }
    }
}
