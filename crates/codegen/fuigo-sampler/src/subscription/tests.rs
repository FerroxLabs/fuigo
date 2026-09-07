use super::*;
use crate::{SamplerConfig, SamplingClient};
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use fuigo_sampling_types::{CreateResponseWrapper, rs};
use futures_util::StreamExt;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug)]
struct Resolver {
    endpoint: String,
    calls: AtomicUsize,
    expired: bool,
}
impl SubscriptionResolver for Resolver {
    fn resolve(&self) -> BoxFuture<'_, Result<SubscriptionBearer>> {
        Box::pin(async move {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(SubscriptionBearer::new(
                format!("fake-token-{n}"),
                "account-a".into(),
                if self.expired { 0 } else { u64::MAX },
            ))
        })
    }
    fn test_endpoint(&self) -> Option<String> {
        Some(self.endpoint.clone())
    }
}
type Capture = Arc<Mutex<Vec<(HeaderMap, serde_json::Value)>>>;
struct Server {
    endpoint: String,
    received: Capture,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn server(redirect: Option<String>) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/responses", listener.local_addr().unwrap());
    let received: Capture = Arc::new(Mutex::new(Vec::new()));
    let app=Router::new().route("/responses",post(move |State(received):State<Capture>,headers:HeaderMap,axum::Json(body):axum::Json<serde_json::Value>|{
        let redirect=redirect.clone();
        async move {
            let n={let mut r=received.lock().unwrap();r.push((headers,body));r.len()};
            if let Some(url)=redirect {return (StatusCode::TEMPORARY_REDIRECT,[("location",url)],"fake-secret-never-echo").into_response();}
            let output=if n==1 {serde_json::json!([{"type":"function_call","id":"fc1","call_id":"call1","name":"echo","arguments":"{\"text\":\"hello\"}","status":"completed"}])} else {serde_json::json!([{"type":"message","id":"msg2","role":"assistant","status":"completed","content":[{"type":"output_text","text":"hello","annotations":[]}]}])};
            let event=serde_json::json!({"type":"response.completed","sequence_number":1,"response":{"id":format!("r{n}"),"object":"response","created_at":0,"model":"fixture-model","status":"completed","output":output}});
            ([("content-type","text/event-stream")],format!("data: {event}\n\ndata: [DONE]\n\n")).into_response()
        }
    })).with_state(received.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Server {
        endpoint,
        received,
        task,
    }
}
fn resolver(server: &Server) -> Arc<Resolver> {
    Arc::new(Resolver {
        endpoint: server.endpoint.clone(),
        calls: AtomicUsize::new(0),
        expired: false,
    })
}
fn config(kind: SubscriptionKind, resolver: Arc<Resolver>) -> SamplerConfig {
    SamplerConfig {
        subscription: Some(kind),
        subscription_resolver: Some(resolver),
        base_url: kind.base_url().into(),
        model: "fixture-model".into(),
        api_backend: fuigo_sampling_types::ApiBackend::Responses,
        api_key: Some("paid-key-must-not-send".into()),
        extra_headers: indexmap::IndexMap::from([("x-api-key".into(), "other-secret".into())]),
        ..Default::default()
    }
}
fn request(input: serde_json::Value) -> CreateResponseWrapper {
    CreateResponseWrapper::new(serde_json::from_value(serde_json::json!({"model":"fixture-model","input":input,"temperature":0.5,"max_output_tokens":50,"instructions":"Follow this fixture instruction.","tools":[{"type":"function","name":"echo","description":"echo text","parameters":{"type":"object","properties":{"text":{"type":"string"}}}}]})).unwrap())
}

#[tokio::test]
async fn subscription_two_turn_tool_continuation_refreshes_and_preserves_reasoning() {
    for kind in [SubscriptionKind::Chatgpt, SubscriptionKind::Xai] {
        let server = server(None).await;
        let resolver = resolver(&server);
        let client = SamplingClient::new(config(kind, resolver.clone())).unwrap();
        let (mut events, _, _) = client
            .create_response_stream(request(
                serde_json::json!([{"role":"user","content":"echo hello"}]),
            ))
            .await
            .unwrap();
        let rs::ResponseStreamEvent::ResponseCompleted(completed) =
            events.next().await.unwrap().unwrap()
        else {
            panic!("completion expected")
        };
        let mut history = vec![
            serde_json::json!({"type":"reasoning","id":"reason1","summary":[],"encrypted_content":"opaque-reasoning"}),
        ];
        history.extend(
            completed
                .response
                .output
                .iter()
                .map(|v| serde_json::to_value(v).unwrap()),
        );
        history.push(
            serde_json::json!({"type":"function_call_output","call_id":"call1","output":"hello"}),
        );
        let (mut events, _, _) = client
            .create_response_stream(request(history.into()))
            .await
            .unwrap();
        assert!(matches!(
            events.next().await.unwrap().unwrap(),
            rs::ResponseStreamEvent::ResponseCompleted(_)
        ));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
        let received = server.received.lock().unwrap();
        assert_eq!(received.len(), 2);
        for (index, (headers, body)) in received.iter().enumerate() {
            assert_eq!(
                headers["authorization"],
                format!("Bearer fake-token-{}", index + 1)
            );
            assert!(!headers.contains_key("x-api-key"));
            assert!(!headers.contains_key("x-fuigo-conv-id"));
            assert_eq!(
                headers
                    .get("chatgpt-account-id")
                    .and_then(|v| v.to_str().ok()),
                if kind == SubscriptionKind::Chatgpt {
                    Some("account-a")
                } else {
                    None
                }
            );
            if kind == SubscriptionKind::Chatgpt {
                assert!(body.get("temperature").is_none());
                assert!(body.get("max_output_tokens").is_none());
                assert_eq!(body["instructions"], "Follow this fixture instruction.");
                assert_eq!(body["store"], false);
            }
        }
        assert_eq!(
            received[1].1["input"][0]["encrypted_content"],
            "opaque-reasoning"
        );
        assert_eq!(received[1].1["input"][1]["call_id"], "call1");
        assert_eq!(received[1].1["input"][2]["call_id"], "call1");
    }
}
#[tokio::test]
async fn subscription_nonstream_chatgpt_collects_stream_completion() {
    let server = server(None).await;
    let client = SamplingClient::new(config(SubscriptionKind::Chatgpt, resolver(&server))).unwrap();
    assert_eq!(
        client
            .create_response(request("hello".into()))
            .await
            .unwrap()
            .id,
        "r1"
    );
}
#[tokio::test]
async fn subscription_redirect_is_not_followed_and_error_body_is_redacted() {
    let attacker = server(None).await;
    let server = server(Some(attacker.endpoint.clone())).await;
    let client = SamplingClient::new(config(SubscriptionKind::Xai, resolver(&server))).unwrap();
    let error = client
        .create_response_stream(request("hello".into()))
        .await
        .err()
        .unwrap();
    assert!(!format!("{error:?} {error}").contains("fake-secret"));
    assert!(attacker.received.lock().unwrap().is_empty());
    assert_eq!(server.received.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn subscription_wrong_host_expired_and_deserialized_configs_fail_closed() {
    let server = server(None).await;
    let resolver = resolver(&server);
    let mut wrong = config(SubscriptionKind::Chatgpt, resolver.clone());
    wrong.base_url = "https://api.fluxrouter.ai/v1".into();
    assert!(
        SamplingClient::new(wrong)
            .unwrap()
            .create_response_stream(request("hello".into()))
            .await
            .is_err()
    );
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    let expired = Arc::new(Resolver {
        endpoint: server.endpoint.clone(),
        calls: AtomicUsize::new(0),
        expired: true,
    });
    assert!(
        SamplingClient::new(config(SubscriptionKind::Xai, expired))
            .unwrap()
            .create_response_stream(request("hello".into()))
            .await
            .is_err()
    );
    let saved = serde_json::to_value(config(SubscriptionKind::Xai, resolver)).unwrap();
    let revived = serde_json::from_value(saved).unwrap();
    assert!(
        SamplingClient::new(revived)
            .unwrap()
            .create_response_stream(request("hello".into()))
            .await
            .is_err()
    );
    assert!(server.received.lock().unwrap().is_empty());
}
#[derive(Debug)]
struct Waiting;
impl SubscriptionResolver for Waiting {
    fn resolve(&self) -> BoxFuture<'_, Result<SubscriptionBearer>> {
        Box::pin(std::future::pending())
    }
}
#[tokio::test]
async fn subscription_cancel_before_auth_never_dispatches() {
    let mut cfg = SamplerConfig {
        subscription: Some(SubscriptionKind::Xai),
        base_url: SubscriptionKind::Xai.base_url().into(),
        ..Default::default()
    };
    cfg.subscription_resolver = Some(Arc::new(Waiting));
    let client = SamplingClient::new(cfg).unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            client.create_response_stream(request("hello".into()))
        )
        .await
        .is_err()
    );
}

#[test]
fn subscription_chatgpt_maps_system_to_developer_without_losing_content() {
    let original = serde_json::json!({"model":"fixture-model","instructions":"original instructions","input":[{"type":"message","role":"system","content":[{"type":"input_text","text":"preserve system policy"}]},{"role":"user","content":"hello"}]});
    let mut chatgpt = original.clone();
    adapt_body(SubscriptionKind::Chatgpt, &mut chatgpt).unwrap();
    assert_eq!(chatgpt["input"][0]["role"], "developer");
    assert_eq!(
        chatgpt["input"][0]["content"],
        original["input"][0]["content"]
    );
    assert_eq!(chatgpt["instructions"], original["instructions"]);
    let mut xai = original.clone();
    adapt_body(SubscriptionKind::Xai, &mut xai).unwrap();
    assert_eq!(xai, original);
}

#[test]
fn subscription_codex_restores_streamed_output_without_replacing_terminal_output() {
    let item = serde_json::json!({"type":"function_call","id":"fc-1","call_id":"call-1","name":"read_file","arguments":"{}","status":"completed"});
    let mut done:rs::ResponseStreamEvent=serde_json::from_value(serde_json::json!({"type":"response.output_item.done","sequence_number":1,"output_index":0,"item":item.clone()})).unwrap();
    let terminal = |output: serde_json::Value| -> rs::ResponseStreamEvent {
        serde_json::from_value(serde_json::json!({"type":"response.completed","sequence_number":2,"response":{"id":"r1","object":"response","created_at":0,"model":"fixture-model","status":"completed","output":output}})).unwrap()
    };
    let mut accumulator = CodexOutput::default();
    accumulator.observe(&mut done);
    let mut completed = terminal(serde_json::json!([]));
    accumulator.observe(&mut completed);
    let rs::ResponseStreamEvent::ResponseCompleted(completed) = completed else {
        panic!("completed")
    };
    assert_eq!(
        serde_json::to_value(&completed.response.output[0]).unwrap()["call_id"],
        "call-1"
    );
    accumulator.observe(&mut done);
    let mut authoritative = item.clone();
    authoritative["call_id"] = "terminal-call".into();
    let mut completed = terminal(serde_json::json!([authoritative]));
    accumulator.observe(&mut completed);
    let rs::ResponseStreamEvent::ResponseCompleted(completed) = completed else {
        panic!("completed")
    };
    assert_eq!(
        serde_json::to_value(&completed.response.output[0]).unwrap()["call_id"],
        "terminal-call"
    );
}

#[tokio::test]
async fn subscription_codex_empty_terminal_output_reaches_real_stream_transform() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/responses", listener.local_addr().unwrap());
    let app=Router::new().route("/responses",post(||async {
        let done=serde_json::json!({"type":"response.output_item.done","sequence_number":1,"output_index":0,"item":{"type":"function_call","id":"fc1","call_id":"call1","name":"read_file","arguments":"{}","status":"completed"}});
        let terminal=serde_json::json!({"type":"response.completed","sequence_number":2,"response":{"id":"r1","object":"response","created_at":0,"model":"fixture-model","status":"completed","output":[]}});
        ([("content-type","text/event-stream")],format!("data: {done}\n\ndata: {terminal}\n\n"))
    }));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let resolver = Arc::new(Resolver {
        endpoint,
        calls: AtomicUsize::new(0),
        expired: false,
    });
    let client = SamplingClient::new(config(SubscriptionKind::Chatgpt, resolver)).unwrap();
    let response = client
        .create_response(request("hello".into()))
        .await
        .unwrap();
    assert_eq!(response.output.len(), 1);
    assert_eq!(
        serde_json::to_value(&response.output[0]).unwrap()["call_id"],
        "call1"
    );
    server.abort();
    let _ = server.await;
}

#[test]
fn subscription_switch_filters_foreign_reasoning_but_preserves_history_and_tool_ids() {
    use fuigo_sampling_types::{AssistantItem, ConversationItem, ConversationRequest, ToolCall};
    let reasoning = |id: &str| {
        ConversationItem::Reasoning(rs::ReasoningItem {
            id: id.into(),
            summary: vec![],
            content: None,
            encrypted_content: Some(format!("{id}-opaque")),
            status: None,
        })
    };
    let assistant = |model: &str, call: &str| {
        ConversationItem::Assistant(AssistantItem {
            content: "visible answer".into(),
            tool_calls: vec![ToolCall {
                id: call.into(),
                name: "read_file".into(),
                arguments: "{}".into(),
            }],
            model_id: Some(model.into()),
            model_fingerprint: None,
            reasoning_effort: None,
        })
    };
    let original = vec![
        ConversationItem::user("task"),
        reasoning("chatgpt"),
        assistant("gpt-6-astra", "call-chatgpt"),
        ConversationItem::tool_result("call-chatgpt", "first result"),
        reasoning("grok"),
        assistant("grok-4.6", "call-grok"),
        ConversationItem::tool_result("call-grok", "second result"),
        ConversationItem::user("continue"),
    ];
    for (model, reason_id) in [("gpt-6-astra", "chatgpt"), ("grok-4.6", "grok")] {
        let mut filtered = original.clone();
        retain_reasoning_for_model(&mut filtered, model);
        let reasoning_items = filtered
            .iter()
            .filter_map(|item| {
                if let ConversationItem::Reasoning(r) = item {
                    Some(r)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(reasoning_items.len(), 1);
        assert_eq!(reasoning_items[0].id, reason_id);
        assert_eq!(
            reasoning_items[0].encrypted_content.as_deref(),
            Some(format!("{reason_id}-opaque").as_str())
        );
        let visible = |items: &Vec<ConversationItem>| {
            serde_json::to_value(
                items
                    .iter()
                    .filter(|item| !matches!(item, ConversationItem::Reasoning(_)))
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        };
        assert_eq!(visible(&original), visible(&filtered));
        let request: rs::CreateResponse = (&ConversationRequest::from_items(filtered)).into();
        let body = serde_json::to_value(request).unwrap();
        let inputs = body["input"].as_array().unwrap();
        for call in ["call-chatgpt", "call-grok"] {
            assert_eq!(
                inputs
                    .iter()
                    .filter(
                        |item| item.get("call_id").and_then(serde_json::Value::as_str)
                            == Some(call)
                    )
                    .count(),
                2
            );
        }
    }
    assert_eq!(
        original
            .iter()
            .filter(|item| matches!(item, ConversationItem::Reasoning(_)))
            .count(),
        2,
        "stored/source history remains untouched"
    );
}
