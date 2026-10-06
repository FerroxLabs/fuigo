//! P70b, option A, through the production `SamplingClient`: classify first, scrub only at the sinks.
//!
//! The credential sent here is literally a classifier marker (`Could not process image`), the case that broke the
//! scrub-before-classify design P70 tried (Astra r24). The error must still classify as an image rejection, the
//! internal transport (`SamplingErrorInfo`, which the shell classifies again) must still carry the upstream text as
//! it arrived, and the display/log scrub must still remove the credential.

use std::sync::Arc;

use fuigo_sampler::{SamplerConfig, SamplingClient, SamplingErrorInfo};
use fuigo_sampling_types::{ContentPart, ConversationItem, ConversationRequest, UserItem};
use fuigo_secrets::sent_credentials::scrub;
use fuigo_test_support::{MockInferenceServer, ScriptedResponse};

const MARKER_KEY: &str = "Could not process image";

fn user_request(text: &str) -> ConversationRequest {
    ConversationRequest {
        items: vec![ConversationItem::User(UserItem {
            content: vec![ContentPart::Text {
                text: Arc::<str>::from(text),
            }],
            ..Default::default()
        })],
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credential_that_is_a_classifier_marker_still_classifies_and_is_scrubbed_at_the_sink() {
    let server = MockInferenceServer::start().await.expect("start mock");
    server.enqueue_response(
        "/v1/chat/completions",
        ScriptedResponse::text(
            400,
            format!(r#"{{"error":{{"message":"{MARKER_KEY}","type":"invalid_request_error"}}}}"#),
        ),
    );
    let cfg = SamplerConfig {
        api_key: Some(MARKER_KEY.to_string()),
        base_url: server.url(),
        model: "test-model".to_string(),
        max_retries: Some(0),
        ..SamplerConfig::default()
    };
    let client = SamplingClient::new(cfg).expect("client");
    let err = match client.conversation_stream(user_request("hi")).await {
        Ok(_) => panic!("expected an API error"),
        Err(e) => e,
    };

    // Classified on the text as it arrived.
    assert!(
        err.is_image_processing_error(),
        "the image rejection must still classify: {err:?}"
    );
    let rendered = err.to_string();
    assert!(rendered.contains(MARKER_KEY), "{rendered}");
    // The internal transport the shell classifies again is not a sink: it keeps the text too.
    let info = SamplingErrorInfo::from(&err);
    assert!(info.message.contains(MARKER_KEY), "{}", info.message);

    // At a sink, the credential the client sent is gone.
    let shown = scrub(&rendered);
    assert!(!shown.contains(MARKER_KEY), "{shown}");
    assert!(shown.contains("<redacted>"), "{shown}");
}

/// A header configured under a name the client itself normally writes (`traceparent`) is still a configured value:
/// when it is what goes on the wire, a real dispatch records it and the sinks replace it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_configured_header_under_a_client_written_name_is_recorded_by_a_real_dispatch() {
    const CONFIGURED: &str = "p70b-configured-traceparent-secret";
    let server = MockInferenceServer::start().await.expect("start mock");
    server.enqueue_response(
        "/v1/chat/completions",
        ScriptedResponse::text(
            400,
            format!(r#"{{"error":{{"message":"bad proxy token {CONFIGURED}","type":"invalid_request_error"}}}}"#),
        ),
    );
    let mut cfg = SamplerConfig {
        api_key: Some("p70b-echo-test-key".to_string()),
        base_url: server.url(),
        model: "test-model".to_string(),
        max_retries: Some(0),
        ..SamplerConfig::default()
    };
    cfg.extra_headers
        .insert("traceparent".to_owned(), CONFIGURED.to_owned());
    let client = SamplingClient::new(cfg).expect("client");
    assert!(
        scrub(CONFIGURED).contains(CONFIGURED),
        "nothing is recorded before a request is sent"
    );
    let err = match client.conversation_stream(user_request("hi")).await {
        Ok(_) => panic!("expected an API error"),
        Err(e) => e,
    };
    let rendered = err.to_string();
    assert!(rendered.contains(CONFIGURED), "{rendered}");
    let shown = scrub(&rendered);
    assert!(!shown.contains(CONFIGURED), "{shown}");
    assert!(shown.contains("bad proxy token <redacted>"), "{shown}");
}
