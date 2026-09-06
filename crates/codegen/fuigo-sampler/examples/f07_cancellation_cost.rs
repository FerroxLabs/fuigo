use fuigo_sampler::{
    ApiBackend, RequestId, RetryPolicy, SamplerActor, SamplerConfig, SamplingEvent,
};
use fuigo_sampling_types::{ContentPart, ConversationItem, ConversationRequest, UserItem};
use fuigo_test_support::{
    InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, ScriptedResponse, SseEvent,
};
use std::{sync::Arc, time::Duration};

async fn run(cancel: bool) -> serde_json::Value {
    let server = MockInferenceServer::start().await.unwrap();
    let chunk = serde_json::json!({"id":"f07-partial","object":"chat.completion.chunk","created":1,"model":"test-model","choices":[{"index":0,"delta":{"role":"assistant","content":"partial audit content"},"finish_reason":null}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15,"cost_in_usd_ticks":123}});
    let mut gate = server.expect_response_blocked(
        "billed partial before terminal",
        InferenceRequestMatcher::auxiliary(InferenceEndpoint::ChatCompletions),
        ScriptedResponse::sse(vec![
            SseEvent::data(chunk.to_string()),
            SseEvent::data("[DONE]"),
        ]),
    );
    let config = SamplerConfig {
        base_url: server.url(),
        api_key: Some("fake-f07-key".into()),
        model: "test-model".into(),
        api_backend: ApiBackend::ChatCompletions,
        max_retries: Some(1),
        ..Default::default()
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let handle = SamplerActor::spawn(config, RetryPolicy::default(), tx);
    let rid = RequestId::from(if cancel { "f07-cancel" } else { "f07-complete" });
    let request = ConversationRequest {
        items: vec![ConversationItem::User(UserItem {
            content: vec![ContentPart::Text {
                text: Arc::from("hi"),
            }],
            ..Default::default()
        })],
        ..Default::default()
    };
    handle.submit(rid.clone(), request);
    let mut known = None;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match rx.recv().await.unwrap() {
                SamplingEvent::AttemptAccounting { accounting, .. }
                    if accounting.cost_usd_ticks == Some(123) =>
                {
                    known = Some(accounting)
                }
                SamplingEvent::FirstToken { .. } if known.is_some() => break,
                SamplingEvent::Failed { .. } | SamplingEvent::Completed { .. } => {
                    panic!("terminal before accounting/first token")
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), gate.wait_blocked())
        .await
        .unwrap();
    if cancel {
        handle.cancel(rid);
    } else {
        gate.release();
    }
    let terminal = tokio::time::timeout(Duration::from_secs(10), async { loop { match rx.recv().await.unwrap() { SamplingEvent::Completed { response, .. } => break serde_json::json!({"kind":"Completed","cost_ticks":response.cost_usd_ticks,"usage":response.usage}), SamplingEvent::Failed { error, .. } => break serde_json::json!({"kind":"Failed","error":error}), _ => {} } } }).await.unwrap();
    if cancel {
        gate.release();
        assert_eq!(terminal["kind"], "Failed");
    } else {
        assert_eq!(terminal["cost_ticks"], 123);
    }
    let known = known.unwrap();
    assert_eq!(known.cost_usd_ticks, Some(123));
    assert!(known.unknown_liability);
    serde_json::json!({"cancelled":cancel,"known_attempt_accounting":{"cost_ticks":known.cost_usd_ticks,"usage":known.usage,"unknown_liability":known.unknown_liability},"terminal":terminal})
}

#[tokio::main]
async fn main() {
    println!(
        "{}",
        serde_json::json!({"control":run(false).await,"cancelled":run(true).await})
    );
}
