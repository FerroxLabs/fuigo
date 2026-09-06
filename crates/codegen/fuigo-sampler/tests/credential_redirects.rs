//! Actual sampler requests must not replay credentials or prompts across origins.
mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use fuigo_sampler::{AuthScheme, SamplingClient};
use fuigo_sampling_types::{ContentPart, ConversationItem, ConversationRequest, UserItem};
use tokio::net::TcpListener;

#[tokio::test]
async fn sampler_rejects_redirected_key_and_prompt_on_normal_and_http1_clients() {
    for force_http1 in [false, true] {
        for status in [
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
        ] {
            let destination_calls = Arc::new(AtomicUsize::new(0));
            let sink = destination_calls.clone();
            let destination_app = Router::new().route(
                "/v1/chat/completions",
                post(move || {
                    let sink = sink.clone();
                    async move {
                        sink.fetch_add(1, Ordering::SeqCst);
                        "{}"
                    }
                }),
            );
            let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination_url = format!(
                "http://{}/v1/chat/completions",
                destination.local_addr().unwrap()
            );
            let destination_task = tokio::spawn(async move {
                axum::serve(destination, destination_app).await.unwrap();
            });

            let source_requests = Arc::new(Mutex::new(Vec::new()));
            let capture = source_requests.clone();
            let source_app = Router::new().route(
                "/v1/chat/completions",
                post(move |headers: HeaderMap, body: Bytes| {
                    let capture = capture.clone();
                    let location = destination_url.clone();
                    async move {
                        capture.lock().unwrap().push((headers, body));
                        (status, [("location", location)], "redirect")
                    }
                }),
            );
            let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let source_url = format!("http://{}/v1", source.local_addr().unwrap());
            let source_task = tokio::spawn(async move {
                axum::serve(source, source_app).await.unwrap();
            });

            let mut config = support::test_config(&source_url, "fake-provider-key");
            config.auth_scheme = AuthScheme::XApiKey;
            config.force_http1 = force_http1;
            config
                .extra_headers
                .insert("x-tenant-secret".into(), "fake-tenant-secret".into());
            let client = SamplingClient::new(config).unwrap();
            let request = ConversationRequest {
                items: vec![ConversationItem::User(UserItem {
                    content: vec![ContentPart::Text {
                        text: Arc::from("private-prompt-marker"),
                    }],
                    ..Default::default()
                })],
                ..Default::default()
            };
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                client.conversation(request),
            )
            .await
            .unwrap();
            source_task.abort();
            destination_task.abort();
            assert!(result.is_err(), "redirect must be rejected");
            assert_eq!(
                destination_calls.load(Ordering::SeqCst),
                0,
                "another origin received a request"
            );
            let captured = source_requests.lock().unwrap();
            assert_eq!(captured.len(), 1);
            assert_eq!(captured[0].0.get("x-api-key").unwrap(), "fake-provider-key");
            assert_eq!(
                captured[0].0.get("x-tenant-secret").unwrap(),
                "fake-tenant-secret"
            );
            assert!(String::from_utf8_lossy(&captured[0].1).contains("private-prompt-marker"));
        }
    }
}
