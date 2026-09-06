//! Fresh-process environment proxy tests exercise all six sampler dispatches.
mod support;

use fuigo_sampler::SamplingClient;
use fuigo_sampling_types::{
    ContentPart, ConversationItem, ConversationRequest, SamplingError, UserItem,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn request() -> ConversationRequest {
    ConversationRequest {
        items: vec![ConversationItem::User(UserItem {
            content: vec![ContentPart::Text {
                text: Arc::from("private-prompt-marker"),
            }],
            ..Default::default()
        })],
        ..Default::default()
    }
}

#[tokio::test]
async fn all_sampler_dispatches_refuse_upstream_before_proxy_receipt() {
    const CHILD: &str = "FUIGO_SAMPLER_PROXY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        for force_http1 in [false, true] {
            for base in ["https://api.x.ai/v1", "http://api.x.ai/v1"] {
                let mut config = support::test_config(base, "fake-provider-key");
                config.force_http1 = force_http1;
                let client = SamplingClient::new(config).unwrap();
                // Erase successful response shapes, preserving the concrete error.
                let results = [
                    client.conversation(request()).await.map(|_| ()),
                    client.conversation_stream(request()).await.map(|_| ()),
                    client.conversation_responses(request()).await.map(|_| ()),
                    client
                        .conversation_stream_responses(request())
                        .await
                        .map(|_| ()),
                    client.conversation_messages(request()).await.map(|_| ()),
                    client
                        .conversation_stream_messages(request())
                        .await
                        .map(|_| ()),
                ];
                for result in results {
                    assert!(
                        matches!(
                            result,
                            Err(SamplingError::InvalidConfiguration(
                                "fuigo refuses to contact upstream vendor host"
                            ))
                        ),
                        "unexpected result: {result:?}"
                    );
                }
            }
        }
        println!("sampler-proxy-child-entered-all-24-cases");
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let sink = calls.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            sink.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0; 8192];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(
                    b"HTTP/1.1 502 No-forwarding\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        }
    });
    let home = tempfile::tempdir().unwrap();
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "all_sampler_dispatches_refuse_upstream_before_proxy_receipt",
            "--nocapture",
        ])
        .env_clear()
        .env("HOME", home.path())
        .env(CHILD, "1")
        .env("HTTP_PROXY", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("ALL_PROXY", &proxy_url)
        .env("NO_PROXY", "")
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    task.abort();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("sampler-proxy-child-entered-all-24-cases")
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "proxy received forbidden sampler traffic"
    );
}
