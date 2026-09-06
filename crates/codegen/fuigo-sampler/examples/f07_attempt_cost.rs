use fuigo_sampler::{
    ApiBackend, RequestId, RetryPolicy, SamplerActor, SamplerConfig, SamplingEvent,
};
use fuigo_sampling_types::{ContentPart, ConversationItem, ConversationRequest, UserItem};
use fuigo_test_support::{MockInferenceServer, ScriptedResponse, sse};
use std::{sync::Arc, time::Duration};

fn billed(text: &str, ticks: i64) -> ScriptedResponse {
    let mut events = sse::chat_completion_script_exact(text, "test-model");
    for event in &mut events {
        if let Ok(mut data) = serde_json::from_str::<serde_json::Value>(&event.data) {
            if let Some(usage) = data.get_mut("usage") {
                usage["cost_in_usd_ticks"] = serde_json::json!(ticks);
                usage["completion_tokens"] = serde_json::json!(5);
                usage["total_tokens"] = serde_json::json!(15);
                event.data = data.to_string();
            }
        }
    }
    ScriptedResponse::sse(events)
}

#[tokio::main]
async fn main() {
    let server = MockInferenceServer::start().await.unwrap();
    server.enqueue_response("/v1/chat/completions", billed("", 100));
    server.enqueue_response("/v1/chat/completions", billed("accepted", 200));
    let config = SamplerConfig {
        base_url: server.url(),
        api_key: Some("fake-f07-key".into()),
        model: "test-model".into(),
        api_backend: ApiBackend::ChatCompletions,
        max_retries: Some(2),
        ..Default::default()
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let sampler = SamplerActor::spawn(config, RetryPolicy::default(), tx);
    let request = ConversationRequest {
        items: vec![ConversationItem::User(UserItem {
            content: vec![ContentPart::Text {
                text: Arc::from("hi"),
            }],
            ..Default::default()
        })],
        ..Default::default()
    };
    let (response, metrics) = tokio::time::timeout(
        Duration::from_secs(30),
        sampler.submit_and_collect(RequestId::from("f07-paid-empty"), request),
    )
    .await
    .unwrap()
    .unwrap();
    let mut completed_cost = None;
    while let Ok(event) = rx.try_recv() {
        if let SamplingEvent::Completed { response, .. } = event {
            completed_cost = response.cost_usd_ticks;
        }
    }
    assert_eq!(server.request_count_for("/v1/chat/completions"), 2);
    assert_eq!(response.cost_usd_ticks, Some(300));
    assert_eq!(completed_cost, Some(300));
    assert_eq!(response.assistant().unwrap().content.as_ref(), "accepted");
    println!(
        "{}",
        serde_json::json!({"provider_requests":2,"provider_reported_total_ticks":300,"returned_cost_ticks":response.cost_usd_ticks,"completed_event_cost_ticks":completed_cost,"accepted_text":response.assistant().unwrap().content,"metrics_attempts":metrics.attempts})
    );
}
