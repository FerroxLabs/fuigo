use super::*;

fn is_det(failure: &CompactFailure) -> bool {
    matches!(failure, CompactFailure::Deterministic(_))
}

fn is_overflow(failure: &CompactFailure) -> bool {
    matches!(failure, CompactFailure::Overflow(_))
}

fn api_error(status: StatusCode, message: &str) -> SamplingError {
    SamplingError::Api {
        status,
        message: message.into(),
        model_metadata: None,
        retry_after_secs: None,
        should_retry: None,
        error_code: None,
    }
}

#[test]
fn sampling_api_4xx_is_deterministic_except_408_and_429() {
    let det = |s: StatusCode| is_det(&classify_sampling_error(api_error(s, "test")));
    assert!(det(StatusCode::BAD_REQUEST));
    assert!(det(StatusCode::UNAUTHORIZED));
    assert!(det(StatusCode::FORBIDDEN));
    assert!(det(StatusCode::NOT_FOUND));
    assert!(!det(StatusCode::REQUEST_TIMEOUT));
    assert!(!det(StatusCode::TOO_MANY_REQUESTS));
    assert!(!det(StatusCode::INTERNAL_SERVER_ERROR));
    assert!(!det(StatusCode::BAD_GATEWAY));
    assert!(!det(StatusCode::SERVICE_UNAVAILABLE));
}

#[test]
fn sampling_api_413_is_overflow_by_status_alone() {
    assert!(is_overflow(&classify_sampling_error(api_error(
        StatusCode::PAYLOAD_TOO_LARGE,
        "Request failed (HTTP 413)."
    ))));
}

#[test]
fn sampling_api_drifted_size_wordings_are_overflow() {
    // Fleet-observed size-overflow wordings.
    for msg in [
        "exceed_context_size_error: request (300000 tokens) exceeds the model context size",
        "payload_too_large: Chat history exceeds the 800-message limit",
        "Input length (300000 tokens) exceeds the maximum allowed length (200000 tokens)",
    ] {
        assert!(
            is_overflow(&classify_sampling_error(api_error(
                StatusCode::BAD_REQUEST,
                msg
            ))),
            "should be overflow: {msg}"
        );
    }
    // A generic 400 stays plain Deterministic — no ladder.
    assert!(is_det(&classify_sampling_error(api_error(
        StatusCode::BAD_REQUEST,
        "invalid tool schema"
    ))));
}

#[test]
fn sampling_tpm_429_with_retry_after_stays_transient() {
    // A TPM 429 with Retry-After and size wording: the server is promising
    // capacity later, so the compaction loop backs off instead of burning an
    // input-ladder stage (see SamplingError::is_context_length_error).
    let size_text = "Request too large for model: Limit 30000, Requested 50000 tokens per min";
    let mut with_retry_after = api_error(StatusCode::TOO_MANY_REQUESTS, size_text);
    if let SamplingError::Api {
        retry_after_secs, ..
    } = &mut with_retry_after
    {
        *retry_after_secs = Some(7);
    }
    assert!(matches!(
        classify_sampling_error(with_retry_after),
        CompactFailure::Transient(_)
    ));
    // Without Retry-After the same wording is a per-request cap — Overflow.
    assert!(is_overflow(&classify_sampling_error(api_error(
        StatusCode::TOO_MANY_REQUESTS,
        size_text
    ))));
}

#[test]
fn sampling_stream_error_with_size_message_is_overflow() {
    // The fleet shape "stream error (BAD_REQUEST): Input length (N tokens)
    // exceeds the maximum allowed length (M tokens)".
    assert!(is_overflow(&classify_sampling_error(
        SamplingError::StreamError {
            error_type: "BAD_REQUEST".into(),
            message: "Input length (300000 tokens) exceeds the maximum allowed length \
                      (200000 tokens)"
                .into(),
            code: None,
        }
    )));
}

#[test]
fn sampling_stream_error_with_structured_size_code_is_overflow() {
    // Opaque message: the structured code slot is the only signal.
    for code in ["413", "payload_too_large", "request_too_large"] {
        assert!(
            is_overflow(&classify_sampling_error(SamplingError::StreamError {
                error_type: "BAD_REQUEST".into(),
                message: "request rejected".into(),
                code: Some(fuigo_sampling_types::ApiErrorCode::parse(code)),
            })),
            "should be overflow for code: {code}"
        );
    }
    // An opaque stream error with a non-size code stays transient.
    assert!(!is_det(&classify_sampling_error(
        SamplingError::StreamError {
            error_type: "server_error".into(),
            message: "internal error".into(),
            code: Some(fuigo_sampling_types::ApiErrorCode::parse(
                "overloaded_error"
            )),
        }
    )));
}

#[test]
fn sampling_non_api_variants_classify_correctly() {
    assert!(is_det(&classify_sampling_error(
        SamplingError::auth_unknown("expired")
    )));
    assert!(is_det(&classify_sampling_error(
        SamplingError::InvalidConfiguration("missing key")
    )));
    assert!(is_det(&classify_sampling_error(
        SamplingError::IdleTimeout { elapsed_secs: 60 }
    )));
    assert!(!is_det(&classify_sampling_error(
        SamplingError::EventStreamError("conn reset".into())
    )));
    assert!(!is_det(&classify_sampling_error(
        SamplingError::StreamError {
            error_type: "overloaded_error".into(),
            message: "try again".into(),
            code: None,
        }
    )));
}

#[test]
fn response_event_invalid_request_error_marker_is_deterministic() {
    // The documented schema-violation marker for the Anthropic Messages API
    // Production `messages.X.content.Y: thinking blocks ...` errors take this branch
    assert!(is_det(&classify_response_event_error(
        Some("invalid_request_error"),
        "messages.27.content.1: ..."
    )));
    // The marker can also appear in the message body (e.g. wrapped error envelopes from gateways).
    assert!(is_det(&classify_response_event_error(
        Some("400"),
        "Provider returned invalid_request_error: messages.X..."
    )));
}

#[test]
fn response_event_numeric_codes_match_http_classification() {
    let det = |c: &str| is_det(&classify_response_event_error(Some(c), "msg"));
    assert!(det("400"));
    assert!(det("401"));
    assert!(det("403"));
    assert!(det("404"));
    assert!(!det("408"));
    assert!(!det("429"));
    assert!(!det("500"));
    assert!(!det("503"));
}

#[test]
fn response_event_invalid_request_marker_with_size_text_is_overflow() {
    // Real overflows arrive AS invalid_request_error with size text — pins
    // that size outranks the schema marker.
    assert!(is_overflow(&classify_response_event_error(
        Some("invalid_request_error"),
        "prompt is too long: 300000 tokens > 200000 maximum"
    )));
}

#[test]
fn response_event_size_codes_are_overflow() {
    for code in ["413", "payload_too_large", "request_too_large"] {
        assert!(
            is_overflow(&classify_response_event_error(Some(code), "msg")),
            "should be overflow for code: {code}"
        );
    }
}

#[test]
fn response_event_unknown_code_defaults_to_transient() {
    // Uncertainty defaults to retry so we don't swallow blips
    assert!(!is_det(&classify_response_event_error(None, "msg")));
    assert!(!is_det(&classify_response_event_error(
        Some("error"),
        "msg"
    )));
    assert!(!is_det(&classify_response_event_error(
        Some("overloaded_error"),
        "msg"
    )));
}

#[test]
fn response_event_marker_in_message_with_no_code_is_deterministic() {
    // The most permissive shape an Anthropic Messages API might emit
    assert!(is_det(&classify_response_event_error(
        None,
        "messages.X.content.Y: invalid_request_error: ..."
    )));
}

#[test]
fn response_event_context_length_message_is_overflow() {
    // The inference backend streams the size overflow as a ResponseError with no usable code (`code="none"`); only the message identifies it
    assert!(is_overflow(&classify_response_event_error(
        None,
        "The prompt is too long for this model's context window."
    )));
}

#[test]
fn sampling_api_500_with_context_length_message_is_overflow() {
    // The sampler synthesizes status=500 from a streamed size overflow, so
    // status alone reads transient; the message must still short-circuit.
    assert!(is_overflow(&classify_sampling_error(api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "API error (status 500 Internal Server Error): \
         The prompt is too long for this model's context window."
    ))));
}

#[test]
fn sampling_http_is_transient() {
    // reqwest::Error has no public constructor; trigger one via a known-bad request
    // reqwest's TCP connect needs a Tokio reactor; futures::executor is not enough (CI runs in a Bazel sandbox where the failure surfaces)
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let http_err = rt
        .block_on(reqwest::get("http://127.0.0.1:0"))
        .expect_err("connecting to port 0 must fail");
    assert!(!is_det(&classify_sampling_error(SamplingError::Http(
        http_err
    ))));
}

#[test]
fn sampling_serialization_is_deterministic() {
    let serde_err = serde_json::from_str::<u32>("not a number").unwrap_err();
    assert!(is_det(&classify_sampling_error(
        SamplingError::Serialization(serde_err)
    )));
}

#[test]
fn classifier_preserves_acp_error_data() {
    let CompactFailure::Deterministic(err) = classify_sampling_error(SamplingError::Api {
        status: StatusCode::BAD_REQUEST,
        message: "bad payload".into(),
        model_metadata: None,
        retry_after_secs: None,
        should_retry: None,
        error_code: None,
    }) else {
        panic!("expected Deterministic for 400");
    };
    let data = err.data.as_ref().and_then(|d| d.as_str()).unwrap();
    assert!(data.contains("compact failed"));
    assert!(data.contains("bad payload"));

    let CompactFailure::Transient(err) = classify_sampling_error(SamplingError::Api {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: "upstream blip".into(),
        model_metadata: None,
        retry_after_secs: None,
        should_retry: None,
        error_code: None,
    }) else {
        panic!("expected Transient for 500");
    };
    let data = err.data.as_ref().and_then(|d| d.as_str()).unwrap();
    assert!(data.contains("upstream blip"));

    let CompactFailure::Overflow(err) = classify_sampling_error(api_error(
        StatusCode::PAYLOAD_TOO_LARGE,
        "Request failed (HTTP 413).",
    )) else {
        panic!("expected Overflow for 413");
    };
    let data = err.data.as_ref().and_then(|d| d.as_str()).unwrap();
    assert!(data.contains("compact failed"));
    assert!(data.contains("Request failed (HTTP 413)."));
}

#[test]
fn stream_timing_boundaries() {
    let mut t = StreamTiming::new();
    assert_eq!(t.count, 0);
    assert_eq!(t.ttft_ms(), None);
    assert_eq!(t.stream_ms(), None);
    assert_eq!(t.itl_max_ms(), None);
    t.record_delta();
    assert_eq!(t.count, 1);
    assert!(t.ttft_ms().is_some());
    assert!(t.stream_ms().is_some());
    assert_eq!(t.itl_max_ms(), None); // A gap needs at least 2 deltas
    t.record_delta();
    assert_eq!(t.count, 2);
    assert!(t.itl_max_ms().is_some());
}

#[test]
fn compaction_outcome_as_str_is_stable() {
    assert_eq!(CompactionOutcome::Success.as_str(), "success");
    assert_eq!(CompactionOutcome::Truncated.as_str(), "truncated");
    assert_eq!(CompactionOutcome::Deterministic.as_str(), "deterministic");
    assert_eq!(CompactionOutcome::Transient.as_str(), "transient");
    assert_eq!(CompactionOutcome::Degenerate.as_str(), "degenerate");
    assert_eq!(CompactionOutcome::Failed.as_str(), "failed");
}

// ── streamed TPM rate limits (upstream 1.0.26) ──────────────────────────────

/// The wording an OpenAI-compatible gateway puts on a tokens-per-minute 429.
/// It opens with "Request too large", which is exactly the anchor
/// `is_context_length_error` matches, so the size text and the rate-limit code
/// disagree about what this is.
const TPM_429_BODY: &str = "Request too large for grok-4.5 in organization org-x on tokens per min (TPM): Limit 30000, Requested 51000. Please try again in 42s.";

#[test]
fn response_event_streamed_tpm_429_is_transient_despite_size_wording() {
    // A TPM 429 delivered on the STREAM path (`ResponseFailed` / `ResponseError`).
    // Treating it as Overflow costs a wasted full-context summarization call
    // (100-400k input tokens) AND a permanent step down the input ladder, with
    // sticky Size suppression once the ladder is exhausted. The envelope path
    // already exempts 429; the stream path must agree.
    assert!(
        matches!(
            classify_response_event_error(Some("429"), TPM_429_BODY),
            CompactFailure::Transient(_)
        ),
        "a streamed 429 must retry, not ladder: {TPM_429_BODY}"
    );
    // 408 is the other status `classify_sampling_error` deliberately keeps retryable.
    assert!(
        matches!(
            classify_response_event_error(Some("408"), TPM_429_BODY),
            CompactFailure::Transient(_)
        ),
        "a streamed 408 must retry, not ladder"
    );
}

#[test]
fn streamed_rate_limit_slugs_are_transient_too() {
    // The `code` slot is not always a numeric status: Anthropic-style backends
    // spell the same rate limit as an error TYPE. Matching only "429" left every
    // slug spelling classifying as Overflow — the original bug in another
    // spelling.
    for code in [
        "rate_limit_error",
        "rate_limit_exceeded",
        "too_many_requests",
        "RATE_LIMIT_ERROR",
    ] {
        assert!(
            matches!(
                classify_response_event_error(Some(code), TPM_429_BODY),
                CompactFailure::Transient(_)
            ),
            "a streamed {code} must retry, not ladder"
        );
    }
}

#[test]
fn the_stream_path_carve_out_does_not_require_a_retry_after() {
    // The two paths agree on a 429 that carries `Retry-After`, and deliberately
    // do NOT agree without one. The envelope rule
    // (`SamplingError::is_context_length_error`) exempts a 429 only when the
    // server promised capacity later; a bare 429 with size wording there means
    // the request exceeds the cap outright, so it keeps laddering. The stream
    // event has no header to read — `ResponseFailed`/`ResponseError` carry a
    // code and a message and nothing else — so it trusts the code alone.
    //
    // This test states that rule rather than hiding it: the earlier version
    // asserted "parity" while setting `retry_after_secs = Some(42)`, the one
    // input on which the two paths cannot disagree.
    let with_retry_after = {
        let mut err = api_error(StatusCode::TOO_MANY_REQUESTS, TPM_429_BODY);
        if let SamplingError::Api {
            retry_after_secs, ..
        } = &mut err
        {
            *retry_after_secs = Some(42);
        }
        classify_sampling_error(err)
    };
    assert!(
        matches!(with_retry_after, CompactFailure::Transient(_)),
        "envelope path, 429 + Retry-After: transient"
    );
    assert!(
        matches!(
            classify_sampling_error(api_error(StatusCode::TOO_MANY_REQUESTS, TPM_429_BODY)),
            CompactFailure::Overflow(_)
        ),
        "envelope path, 429 with NO Retry-After: still ladders, by design"
    );
    assert!(
        matches!(
            classify_response_event_error(Some("429"), TPM_429_BODY),
            CompactFailure::Transient(_)
        ),
        "stream path has no header to read, so the code alone decides"
    );
}

#[test]
fn response_event_overflow_without_a_rate_limit_code_still_ladders() {
    // Regression guard for the carve-out above: only an explicit 429/408 may
    // outrank the size text. Every other shape a real overflow arrives in must
    // keep reaching the input ladder.
    for (code, message) in [
        (
            None,
            "The prompt is too long for this model's context window.",
        ),
        (
            Some("400"),
            "prompt is too long: 300000 tokens > 200000 maximum",
        ),
        (
            Some("invalid_request_error"),
            "prompt is too long: 300000 tokens > 200000 maximum",
        ),
        (Some("413"), "Request failed (HTTP 413)."),
        (Some("500"), "Request too large"),
    ] {
        assert!(
            is_overflow(&classify_response_event_error(code, message)),
            "should still be overflow: {code:?} / {message}"
        );
    }
}

// ── the Messages (Anthropic) backend's own stream errors ────────────────────

/// The verbatim SSE `data:` payload an Anthropic-style backend sends for a
/// tokens-per-minute 429.
const ANTHROPIC_TPM_429_FRAME: &str = r#"{"type":"error","error":{"type":"rate_limit_error","message":"Request too large for claude-sonnet-4 in organization org-x on tokens per min (TPM): Limit 30000, Requested 51000."}}"#;

/// The same frame shape for a genuine prompt-size rejection.
const ANTHROPIC_OVERFLOW_FRAME: &str = r#"{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 300000 tokens > 200000 maximum"}}"#;

#[test]
fn an_anthropic_stream_rate_limit_is_transient_on_the_compaction_loop() {
    // Production path, end to end, with nothing hand-built: the compaction
    // loop's Messages arm consumes `Client::conversation_stream_messages`,
    // whose SSE mapping runs `try_parse_stream_error` over every `data:`
    // payload before attempting a typed `MessageStreamEvent`. A provider error
    // frame therefore arrives as an `Err` item and lands here, on
    // `classify_sampling_error` (session_compact.rs, the `Err(e)` arm of the
    // Messages stream loop) -- not on `classify_response_event_error`, which
    // only ever sees the Responses backend's typed events.
    //
    // Classifying this as Overflow costs a wasted full-context summarization
    // call (100-400k input tokens) AND a permanent step down the
    // Verbatim -> VerbatimFitted -> Lossy ladder for the rest of the session.
    let err = fuigo_sampling_types::error::try_parse_stream_error(ANTHROPIC_TPM_429_FRAME)
        .expect("an Anthropic error frame parses as a stream error");
    assert!(
        matches!(classify_sampling_error(err), CompactFailure::Transient(_)),
        "a Messages-backend TPM 429 must retry, not ladder"
    );
}

#[test]
fn an_anthropic_stream_overflow_still_ladders() {
    // The carve-out must not swallow the case the ladder exists for.
    let err = fuigo_sampling_types::error::try_parse_stream_error(ANTHROPIC_OVERFLOW_FRAME)
        .expect("an Anthropic error frame parses as a stream error");
    assert!(
        is_overflow(&classify_sampling_error(err)),
        "a real prompt-size rejection must still reach the input ladder"
    );
}
