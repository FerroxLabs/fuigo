//! FA1–FA14: the sanitized Flux refusal fixtures drive the sampler through real HTTP.
//! Responses/messages in the fixtures are source-rendered, not live captures.
use fuigo_sampler::{
    ApiBackend, RequestId, RetryPolicy, SamplerActor, SamplerConfig, SamplingClient,
    SamplingErrorInfo, SamplingEvent,
};
use fuigo_sampling_types::{
    ContentPart, ConversationItem, ConversationRequest, SamplingError, UserItem,
};
use fuigo_test_support::{MockInferenceServer, ScriptedResponse};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

fn fixture(case: &str, backend: &ApiBackend) -> Value {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fuigo-sampling-types/tests/fixtures/flux-fixtures");
    let file = std::fs::read_dir(dir)
        .unwrap()
        .map(Result::unwrap)
        .find(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(&format!("{case}-"))
        })
        .unwrap();
    let v: Value = serde_json::from_slice(&std::fs::read(file.path()).unwrap()).unwrap();
    match backend {
        ApiBackend::ChatCompletions => v,
        _ => v["per_endpoint"][path(backend)].clone(),
    }
}
fn path(b: &ApiBackend) -> &'static str {
    match b {
        ApiBackend::ChatCompletions => "/v1/chat/completions",
        ApiBackend::Responses => "/v1/responses",
        ApiBackend::Messages => "/v1/messages",
    }
}
fn request() -> ConversationRequest {
    ConversationRequest {
        items: vec![ConversationItem::User(UserItem {
            content: vec![ContentPart::Text {
                text: Arc::from("hi"),
            }],
            ..Default::default()
        })],
        ..Default::default()
    }
}
fn response(v: &Value) -> ScriptedResponse {
    let mut r = ScriptedResponse::json(v["status"].as_u64().unwrap() as u16, v["body"].clone());
    if let Some(h) = v["headers"].as_object() {
        for (k, v) in h {
            if k == "x-flux-hold-reason" || k.starts_with("retry-after") {
                r.headers.push((k.clone(), v.as_str().unwrap().into()));
            }
        }
    }
    r
}
fn config(server: &MockInferenceServer, backend: ApiBackend) -> SamplerConfig {
    SamplerConfig {
        base_url: server.url(),
        flux_base_url: Some(server.url()),
        api_key: Some("fixture-dummy".into()),
        api_backend: backend,
        model: "test-model".into(),
        max_retries: Some(3),
        ..Default::default()
    }
}
async fn error(v: &Value, backend: ApiBackend, streaming: bool) -> SamplingError {
    let server = MockInferenceServer::start().await.unwrap();
    server.enqueue_response(path(&backend), response(v));
    let c = SamplingClient::new(config(&server, backend.clone())).unwrap();
    let e = match (backend, streaming) {
        (ApiBackend::ChatCompletions, true) => c
            .conversation_stream(request())
            .await
            .err()
            .expect("refusal"),
        (ApiBackend::Responses, true) => c
            .conversation_stream_responses(request())
            .await
            .err()
            .expect("refusal"),
        (ApiBackend::Messages, true) => c
            .conversation_stream_messages(request())
            .await
            .err()
            .expect("refusal"),
        (ApiBackend::ChatCompletions, false) => c.conversation(request()).await.unwrap_err(),
        (ApiBackend::Responses, false) => c.conversation_responses(request()).await.unwrap_err(),
        (ApiBackend::Messages, false) => c.conversation_messages(request()).await.unwrap_err(),
    };
    assert_eq!(server.request_count(), 1);
    e
}
async fn wire(v: &Value, b: ApiBackend) -> Value {
    serde_json::to_value(SamplingErrorInfo::from(&error(v, b, true).await).upstream()).unwrap()
}

#[tokio::test]
async fn hold_reason_header_reaches_upstream() {
    for b in [
        ApiBackend::ChatCompletions,
        ApiBackend::Responses,
        ApiBackend::Messages,
    ] {
        for streaming in [false, true] {
            // Replay case 16's chat body/header through each backend, as required by FA1.
            let v = fixture("16", &ApiBackend::ChatCompletions);
            let e = error(&v, b.clone(), streaming).await;
            assert_eq!(
                serde_json::to_value(SamplingErrorInfo::from(&e).upstream()).unwrap(),
                json!({"http_status":402,"hold_reason":"credit_exhausted"})
            );
        }
    }
}
#[tokio::test]
async fn flat_error_code_reaches_upstream() {
    for (n, code) in [
        ("10", "hourly_burn_limit"),
        ("12", "key_budget_reached"),
        ("15", "account_monthly_budget_exhausted"),
        ("18", "key_lifetime_cap_exhausted"),
    ] {
        assert_eq!(
            wire(&fixture(n, &ApiBackend::Responses), ApiBackend::Responses).await["code"],
            code
        );
    }
}
#[tokio::test]
async fn provider_specific_fields_code() {
    for (n, code) in [
        ("01", json!("free_tier_exhausted")),
        ("09", json!("batch_concurrency")),
        ("07", Value::Null),
    ] {
        assert_eq!(
            wire(
                &fixture(n, &ApiBackend::ChatCompletions),
                ApiBackend::ChatCompletions
            )
            .await["code"],
            code
        );
    }
}
#[tokio::test]
async fn messages_code_field() {
    let v = json!({"status":401,"body":{"type":"error","error":{"type":"authentication_error","code":"key_revoked","message":"revoked"}}});
    assert_eq!(wire(&v, ApiBackend::Messages).await["code"], "key_revoked");
}
#[tokio::test]
async fn retry_after_reaches_upstream() {
    for (n, b, wait) in [
        ("11", ApiBackend::ChatCompletions, 2),
        ("05", ApiBackend::Responses, 60),
        ("06", ApiBackend::Responses, 30),
        ("10", ApiBackend::Responses, 1800),
    ] {
        assert_eq!(wire(&fixture(n, &b), b).await["retry_after_s"], wait);
    }
    for v in [json!(7201), json!("60"), json!(-1), json!(60.5)] {
        assert!(
            wire(
                &json!({"status":429,"body":{"error":{"retry_after":v}}}),
                ApiBackend::Responses
            )
            .await["retry_after_s"]
                .is_null()
        );
    }
}
#[tokio::test]
async fn auth_401_carries_upstream() {
    for b in [
        ApiBackend::ChatCompletions,
        ApiBackend::Responses,
        ApiBackend::Messages,
    ] {
        for streaming in [false, true] {
            let mut v = fixture("14", &ApiBackend::Responses);
            for hold in [false, true] {
                if hold {
                    v["headers"]["x-flux-hold-reason"] = json!("key_revoked");
                }
                let e = error(&v, b.clone(), streaming).await;
                let info = SamplingErrorInfo::from(&e);
                let mut want = json!({"http_status":401,"type":"authentication_error","codes":["authentication_error"]});
                if hold {
                    want["hold_reason"] = json!("key_revoked");
                }
                assert_eq!(serde_json::to_value(info.upstream()).unwrap(), want);
                // Parent 413f407d6 events.rs:331: Auth status is additive only in upstream.
                assert_eq!(info.status_code, None);
            }
        }
    }
}
#[tokio::test]
async fn invalid_hold_reason_header_is_omitted() {
    for h in ["Credit Exhausted".to_string(), "a".repeat(65)] {
        let mut v = fixture("16", &ApiBackend::ChatCompletions);
        v["headers"]["x-flux-hold-reason"] = json!(h);
        assert!(
            wire(&v, ApiBackend::Responses)
                .await
                .get("hold_reason")
                .is_none()
        );
    }
}
async fn actor(v: Value, expect_retry: bool) {
    let b = ApiBackend::Responses;
    let server = MockInferenceServer::start().await.unwrap();
    for _ in 0..3 {
        server.enqueue_response(path(&b), response(&v));
    }
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let h = SamplerActor::spawn(config(&server, b), RetryPolicy::default(), tx);
    h.submit(RequestId::from("flux-refusal"), request());
    let mut retries = 0;
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(e) = rx.recv().await {
            match e {
                SamplingEvent::Retrying { .. } => {
                    retries += 1;
                    if expect_retry {
                        h.cancel(RequestId::from("flux-refusal"));
                        return;
                    }
                }
                SamplingEvent::Failed { .. } => return,
                SamplingEvent::Completed { .. } => panic!("refusal completed"),
                _ => (),
            }
        }
    })
    .await
    .unwrap();
    if expect_retry {
        assert!(retries > 0);
    } else {
        assert_eq!(retries, 0);
        assert_eq!(server.request_count(), 1);
    }
}
#[tokio::test]
async fn final_flux_codes_not_retried() {
    for n in ["01", "03", "04"] {
        actor(fixture(n, &ApiBackend::Responses), false).await;
    }
    actor(fixture("05", &ApiBackend::Responses), true).await;
}
#[tokio::test]
async fn payment_402_single_post() {
    actor(fixture("16", &ApiBackend::Responses), false).await;
    actor(fixture("14", &ApiBackend::Responses), false).await;
}

#[tokio::test]
async fn header_wait_precedes_body_and_ms_is_not_wire_metadata() {
    for (headers, expected) in [
        (json!({"retry-after":"2"}), json!(2)),
        (json!({"retry-after-ms":"1200"}), json!(60)),
        (json!({"retry-after":"7200"}), json!(7200)),
        (json!({"retry-after":"0"}), json!(0)),
        (json!({"retry-after":"7201"}), json!(60)),
    ] {
        let v = json!({"status":429,"headers":headers,"body":{"error":{"retry_after":60}}});
        assert_eq!(
            wire(&v, ApiBackend::Responses).await["retry_after_s"],
            expected
        );
    }
    let v = json!({"status":429,"headers":{"retry-after":"7201"},"body":{"error":{}}});
    assert!(wire(&v, ApiBackend::Responses).await["retry_after_s"].is_null());
}

#[tokio::test]
async fn wire_wait_is_independent_of_internal_cap() {
    let mut v = fixture("10", &ApiBackend::Responses);
    v["headers"]["retry-after"] = json!("1800");
    let e = error(&v, ApiBackend::Responses, true).await;
    let info = SamplingErrorInfo::from(&e);
    assert_eq!(
        serde_json::to_value(info.upstream()).unwrap()["retry_after_s"],
        1800
    );
    assert!(info.retry_after_secs.unwrap() <= 120);
}

#[tokio::test]
async fn reset_date_reaches_upstream() {
    assert_eq!(
        wire(
            &fixture("12", &ApiBackend::Responses),
            ApiBackend::Responses
        )
        .await["resets_at"],
        "2026-12-01T00:00:00Z"
    );
}

#[tokio::test]
async fn status_overrides_concurrency_hold() {
    actor(json!({"status":402,"headers":{"x-flux-hold-reason":"concurrency","retry-after":"2"},"body":{"error":{"type":"api_error","message":"held"}}}), false).await;
}

#[path = "../../fuigo-sampling-types/tests/support/busyloop_fixture.rs"]
mod busyloop_fixture;
#[tokio::test]
async fn fa13_responses_tsv_through_real_http_reader() {
    let inputs = busyloop_fixture::inputs();
    for r in busyloop_fixture::rows() {
        if r[2] != "resp" {
            continue;
        }
        let (_, st, h, b) = &inputs[&r[0]];
        let want = busyloop_fixture::reference("upstream_by_row")[&r[0]].clone();
        let got = wire(
            &json!({"status":st,"headers":h,"body":b}),
            ApiBackend::Responses,
        )
        .await;
        assert_eq!(got, want, "FA13 {}", r[0]);
    }
}
#[tokio::test]
async fn fa7_all_final_codes_in_three_wire_shapes() {
    for (code, _) in fuigo_sampling_types::refusal::FINAL_ORDER {
        for (status, field) in [(429, "state"), (402, "error"), (401, "header")] {
            let mut v = json!({"status":status,"headers":{},"body":{"error":{"message":"fixture refusal"}}});
            if field == "header" {
                v["headers"]["x-flux-hold-reason"] = json!(code);
            } else {
                v["body"]["error"][field] = json!(code);
            }
            actor(v, false).await;
        }
    }
}
#[tokio::test]
async fn fa9_and_a21_reject_boolean_and_malformed_waits() {
    for v in [json!(true), json!(false), json!("60"), json!(7201)] {
        assert!(
            wire(
                &json!({"status":429,"body":{"error":{"retry_after":v}}}),
                ApiBackend::Responses
            )
            .await["retry_after_s"]
                .is_null()
        );
    }
    for h in ["+2", "2.0", "7201"] {
        assert!(
            wire(
                &json!({"status":429,"headers":{"retry-after":h},"body":{"error":{}}}),
                ApiBackend::Responses
            )
            .await["retry_after_s"]
                .is_null()
        );
    }
}

#[tokio::test]
async fn s3_http_boundary_preserves_non_flux_retry_and_configured_flux_pause() {
    for b in [
        ApiBackend::ChatCompletions,
        ApiBackend::Responses,
        ApiBackend::Messages,
    ] {
        for (case, body, wait, flux) in [
            (
                "S3a",
                json!({"error":{"code":429,"message":"Resource has been exhausted (e.g. check quota).","status":"RESOURCE_EXHAUSTED"}}),
                None,
                false,
            ),
            (
                "S3b",
                json!({"error":{"type":"rate_limit_error","message":"rate limit exceeded"}}),
                Some(7),
                false,
            ),
            (
                "S3c",
                json!({"error":{"message":"opaque refusal"}}),
                None,
                true,
            ),
        ] {
            let server = MockInferenceServer::start().await.unwrap();
            let mut v = json!({"status":429,"body":body});
            if let Some(w) = wait {
                v["headers"] = json!({"retry-after":w.to_string()});
            }
            server.enqueue_response(path(&b), response(&v));
            let mut cfg = config(&server, b.clone());
            cfg.flux_base_url = flux.then(|| server.url());
            let client = SamplingClient::new(cfg).unwrap();
            let e = match b {
                ApiBackend::ChatCompletions => client.conversation(request()).await.unwrap_err(),
                ApiBackend::Responses => {
                    client.conversation_responses(request()).await.unwrap_err()
                }
                ApiBackend::Messages => client.conversation_messages(request()).await.unwrap_err(),
            };
            assert_eq!(e.upstream().flux_routed, flux, "{case}");
            assert_eq!(e.is_retryable(), !flux, "{case}");
            assert_eq!(e.is_terminal_refusal(), flux, "{case}");
            assert_eq!(e.retry_after(), wait, "{case}");
            assert_eq!(server.request_count(), 1, "{case}");
        }
    }
}

#[tokio::test]
async fn s3_non_flux_actor_retries_but_flux_actor_sends_once() {
    for (case, body, wait, flux) in [
        (
            "S3a",
            json!({"error":{"code":429,"message":"Resource has been exhausted (e.g. check quota).","status":"RESOURCE_EXHAUSTED"}}),
            None,
            false,
        ),
        (
            "S3b",
            json!({"error":{"type":"rate_limit_error","message":"rate limit exceeded"}}),
            Some(2),
            false,
        ),
        (
            "S3c",
            json!({"error":{"message":"opaque refusal"}}),
            None,
            true,
        ),
    ] {
        let server = MockInferenceServer::start().await.unwrap();
        let mut v = json!({"status":429,"body":body});
        if let Some(w) = wait {
            v["headers"] = json!({"retry-after":w.to_string()});
        }
        for _ in 0..3 {
            server.enqueue_response("/v1/responses", response(&v));
        }
        let mut cfg = config(&server, ApiBackend::Responses);
        cfg.flux_base_url = flux.then(|| server.url());
        cfg.max_retries = Some(2);
        cfg.rate_limit_retry_threshold = Some(2);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let h = SamplerActor::spawn(cfg, RetryPolicy::default(), tx);
        let start = std::time::Instant::now();
        h.submit(RequestId::from("host-scope"), request());
        let retries = tokio::time::timeout(Duration::from_secs(15), async {
            let mut retries = 0;
            while let Some(event) = rx.recv().await {
                match event {
                    SamplingEvent::Retrying { .. } => retries += 1,
                    SamplingEvent::Failed { .. } => return retries,
                    SamplingEvent::Completed { .. } => panic!("unexpected completion"),
                    _ => (),
                }
            }
            panic!("sampler ended without failure");
        })
        .await
        .unwrap();
        assert_eq!(retries, usize::from(!flux), "{case}");
        assert_eq!(server.request_count(), if flux { 1 } else { 2 }, "{case}");
        if wait.is_some() {
            assert!(
                start.elapsed() >= Duration::from_millis(1500),
                "Retry-After keeps existing jitter"
            );
        }
    }
}

#[tokio::test]
async fn p1_body_values_and_s3_provenance_survive_persisted_mirror() {
    let echo = "xk3-9f2a7c1e0b4d6a8f3e5c7b9d1f0a2c4e6b8d";
    for flux in [false, true] {
        let server = MockInferenceServer::start().await.unwrap();
        server.enqueue_response(
            "/v1/responses",
            ScriptedResponse::json(
                429,
                json!({"error":{"state":echo,"type":echo,"message":"refusal"}}),
            ),
        );
        let mut cfg = config(&server, ApiBackend::Responses);
        cfg.flux_base_url = flux.then(|| server.url());
        let client = SamplingClient::new(cfg).unwrap();
        let e = client.conversation_responses(request()).await.unwrap_err();
        let info = SamplingErrorInfo::from(&e);
        let saved = serde_json::to_value(&info).unwrap();
        for key in ["upstream_state", "upstream_type"] {
            assert_eq!(saved[key], "other");
        }
        for key in ["state", "type"] {
            assert_eq!(saved["upstream_details"][key], "other");
        }
        let replayed: SamplingErrorInfo = serde_json::from_value(saved).unwrap();
        assert_eq!(
            replayed.upstream().classify("refusal"),
            info.upstream().classify("refusal")
        );
        assert_eq!(replayed.upstream().flux_routed, flux);
    }
}
#[tokio::test]
async fn p5_sse_all_backends_preserve_upstream_through_actor() {
    for backend in [
        ApiBackend::ChatCompletions,
        ApiBackend::Responses,
        ApiBackend::Messages,
    ] {
        let server = MockInferenceServer::start().await.unwrap();
        server.enqueue_response(path(&backend),ScriptedResponse::sse(vec![fuigo_test_support::SseEvent::data(
            r#"{"error":{"state":"free_cap_reached","type":"rate_limit_exceeded","code":"free_cap_reached","message":"refusal"}}"#
        )]));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let sampler = SamplerActor::spawn(config(&server, backend), RetryPolicy::default(), tx);
        sampler.submit(RequestId::from("sse-state"), request());
        let info = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(event) = rx.recv().await {
                match event {
                    SamplingEvent::Failed { error, .. } => return error,
                    SamplingEvent::Retrying { .. } => panic!("final SSE code must not retry"),
                    _ => (),
                }
            }
            panic!("missing failure")
        })
        .await
        .unwrap();
        assert_eq!(info.upstream().state.as_deref(), Some("free_cap_reached"));
        assert_eq!(
            info.upstream().error_type.as_deref(),
            Some("rate_limit_exceeded")
        );
        assert_eq!(info.upstream().code.as_deref(), Some("free_cap_reached"));
        assert_eq!(server.request_count(), 1);
    }
}

#[tokio::test]
async fn h4_sse_terminal_text_stops_all_backends_at_raw_boundary() {
    for backend in [ApiBackend::ChatCompletions, ApiBackend::Responses, ApiBackend::Messages] {
        for payload in [
            json!({"error":{"message":"API key has been revoked"}}),
            json!({"error":{"message":"busy","provider_specific_fields":{"message":"API key has been revoked"}}}),
            json!({"type":"error","message":"busy","provider_specific_fields":{"message":"API key has been revoked"}}),
            json!({"type":"response.failed","response":{"error":{"message":"busy","provider_specific_fields":{"message":"API key has been revoked"}}}}),
            json!({"type":"response.error","message":"busy","provider_specific_fields":{"message":"API key has been revoked"}}),
        ] {
            let server = MockInferenceServer::start().await.unwrap();
            server.enqueue_response(path(&backend), ScriptedResponse::sse(vec![fuigo_test_support::SseEvent::data(payload.to_string())]));
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let sampler = SamplerActor::spawn(config(&server, backend.clone()), RetryPolicy::default(), tx);
            sampler.submit(RequestId::from("raw-sse"), request());
            let info = tokio::time::timeout(Duration::from_secs(5), async {
                while let Some(event) = rx.recv().await {
                    match event {
                        SamplingEvent::Failed { error, .. } => return error,
                        SamplingEvent::Retrying { .. } => panic!("Flux terminal SSE must not retry"),
                        _ => (),
                    }
                }
                panic!("missing failure")
            }).await.unwrap();
            assert!(info.upstream().flux_routed);
            assert!(info.upstream().classify(&info.message).is_terminal());
            assert_eq!(server.request_count(), 1);
        }
    }
}

#[tokio::test]
async fn h5_http_nested_terminal_text_stops_all_six_handlers() {
    for backend in [ApiBackend::ChatCompletions, ApiBackend::Responses, ApiBackend::Messages] {
        for streaming in [false, true] {
            let e = error(&json!({"status":503,"body":{"error":{"message":"busy","provider_specific_fields":{"message":"API key has been revoked"}}}}), backend.clone(), streaming).await;
            assert!(e.is_terminal_refusal());
            assert!(!e.is_retryable());
            let info = SamplingErrorInfo::from(&e);
            let replay: SamplingErrorInfo = serde_json::from_value(serde_json::to_value(info).unwrap()).unwrap();
            assert!(replay.upstream().classify("busy").is_terminal());
        }
    }
}

#[tokio::test]
async fn r1_every_http_constructor_and_mirror_retains_boundary_decision() {
    for backend in [ApiBackend::ChatCompletions, ApiBackend::Responses, ApiBackend::Messages] {
        for streaming in [false, true] {
            for status in [401, 503] {
                let error = error(&json!({"status":status,"body":{"error":{"message":"busy","provider_specific_fields":{"message":"API key has been revoked"}}}}), backend.clone(), streaming).await;
                error.assert_boundary_classified();
                let cloned = match fuigo_sampler::retry::classify_error(&error, 0, 3, 3) {
                    fuigo_sampler::retry::RetryDecision::Fatal(error) | fuigo_sampler::retry::RetryDecision::EmitToSession(error) => error,
                    _ => panic!("terminal error cannot retry"),
                };
                assert_eq!(cloned.upstream().classification(), error.upstream().classification());
                let info = SamplingErrorInfo::from(&cloned);
                let saved = serde_json::to_value(&info).unwrap();
                assert_eq!(saved["upstream_details"]["classification"]["reason"], "keyRevoked");
                let restored: SamplingErrorInfo = serde_json::from_value(saved).unwrap();
                assert_eq!(restored.upstream().classification(), info.upstream().classification());
                assert!(serde_json::to_value(restored.upstream()).unwrap().get("classification").is_none());
            }
        }
    }
}

#[test]
fn r1_route_identity_comes_from_request_not_response() {
    // A response URL must not become the authority for request provenance.
    // Guard all boundary handlers, including subscription, against reintroducing it.
    for source in [include_str!("../src/client.rs"), include_str!("../src/subscription.rs")] {
        assert!(!source.contains("is_flux_routed(response.url()"), "capture the request route before transport dispatch");
    }
}

#[tokio::test]
async fn r1_flux_refusal_status_survives_a_truncated_http_body() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for flux in [false, true] {
        for backend in [ApiBackend::ChatCompletions, ApiBackend::Responses, ApiBackend::Messages] {
            for streaming in [false, true] {
              for status in [401, 503] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let base = format!("http://{}/v1", listener.local_addr().unwrap());
                let server = tokio::spawn(async move {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") { head.push(socket.read_u8().await.unwrap()); }
                    let length: usize = String::from_utf8(head).unwrap().lines()
                        .find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
                    socket.read_exact(&mut vec![0; length]).await.unwrap();
                    let final_header = if status == 503 { "X-Flux-Hold-Reason: key_revoked\r\n" } else { "" };
                    let response = format!("HTTP/1.1 {status} Refused\r\n{final_header}Content-Length: 100\r\nConnection: close\r\n\r\n{{");
                    socket.write_all(response.as_bytes()).await.unwrap();
                });
                let client = SamplingClient::new(SamplerConfig {
                    base_url: base.clone(), flux_base_url: flux.then_some(base),
                    api_backend: backend.clone(), model: "test".into(), ..Default::default()
                }).unwrap();
                let error = match (backend.clone(), streaming) {
                    (ApiBackend::ChatCompletions, true) => client.conversation_stream(request()).await.err().unwrap(),
                    (ApiBackend::Responses, true) => client.conversation_stream_responses(request()).await.err().unwrap(),
                    (ApiBackend::Messages, true) => client.conversation_stream_messages(request()).await.err().unwrap(),
                    (ApiBackend::ChatCompletions, false) => client.conversation(request()).await.err().unwrap(),
                    (ApiBackend::Responses, false) => client.conversation_responses(request()).await.err().unwrap(),
                    (ApiBackend::Messages, false) => client.conversation_messages(request()).await.err().unwrap(),
                };
                server.await.unwrap();
                if flux {
                    assert!(error.is_terminal_refusal(), "a refused HTTP status must survive a failed body read: {error}");
                    error.assert_boundary_classified();
                    assert_eq!(error.upstream().http_status, Some(status));
                } else if streaming && status == 401 {
                    assert!(matches!(error, SamplingError::Auth { .. }), "the parent's streaming 401 handler already preserves auth status: {error}");
                } else {
                    assert!(matches!(error, SamplingError::Http(_)), "non-Flux keeps the parent's body-read error: {error}");
                }
              }
            }
        }
    }
}
