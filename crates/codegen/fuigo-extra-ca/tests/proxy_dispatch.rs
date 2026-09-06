//! Proxy observers never forward traffic. Rejection is proved by zero receipt,
//! with raw-client and allowed-destination controls proving the observer works.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fuigo_extra_ca::dispatch::{self, DispatchError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Observer {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn observer() -> Observer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let sink = requests.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0; 4096];
            while !bytes.windows(4).any(|b| b == b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&buf[..n]);
            }
            let request = String::from_utf8(bytes).unwrap();
            let code = if request.starts_with("CONNECT ") {
                502
            } else {
                200
            };
            sink.lock().unwrap().push(request);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 {code} Observer\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    });
    Observer {
        url,
        requests,
        task,
    }
}

#[tokio::test]
async fn raw_control_proves_dns_guard_does_not_stop_proxy_connect() {
    let proxy = observer().await;
    let client = fuigo_extra_ca::build_reqwest_client(|b| {
        b.no_proxy()
            .proxy(reqwest::Proxy::all(&proxy.url).unwrap())
            .timeout(Duration::from_secs(3))
    })
    .unwrap();
    assert!(client.get("https://api.x.ai/v1").send().await.is_err());
    let received = proxy.requests.lock().unwrap();
    assert_eq!(received.len(), 1);
    assert!(received[0].starts_with("CONNECT api.x.ai:443 "));
}

#[tokio::test]
async fn checked_async_send_and_execute_block_before_explicit_proxy() {
    let proxy = observer().await;
    let client = fuigo_extra_ca::build_reqwest_client(|b| {
        b.no_proxy()
            .proxy(reqwest::Proxy::all(&proxy.url).unwrap())
            .timeout(Duration::from_secs(3))
    })
    .unwrap();
    for url in [
        "https://api.x.ai/v1",
        "http://api.x.ai/v1",
        "https://API.X.AI./v1",
    ] {
        assert!(matches!(
            dispatch::send(client.get(url)).await,
            Err(DispatchError::Denied(_))
        ));
        let request = client.get(url).build().unwrap();
        assert!(matches!(
            dispatch::execute(&client, request).await,
            Err(DispatchError::Denied(_))
        ));
    }
    assert!(proxy.requests.lock().unwrap().is_empty());
    assert_eq!(
        dispatch::send(client.get("http://allowed.example/v1"))
            .await
            .unwrap()
            .status(),
        200
    );
    let received = proxy.requests.lock().unwrap();
    assert_eq!(received.len(), 1);
    assert!(received[0].starts_with("GET http://allowed.example/v1 "));
}

#[tokio::test]
async fn checked_blocking_send_and_execute_block_before_explicit_proxy() {
    let proxy = observer().await;
    let proxy_url = proxy.url.clone();
    tokio::task::spawn_blocking(move || {
        let client = fuigo_extra_ca::build_blocking_reqwest_client(|b| {
            b.no_proxy()
                .proxy(reqwest::Proxy::all(&proxy_url).unwrap())
                .timeout(Duration::from_secs(3))
        })
        .unwrap();
        for url in ["https://api.x.ai/v1", "http://api.x.ai/v1"] {
            assert!(matches!(
                dispatch::send_blocking(client.get(url)),
                Err(DispatchError::Denied(_))
            ));
            let request = client.get(url).build().unwrap();
            assert!(matches!(
                dispatch::execute_blocking(&client, request),
                Err(DispatchError::Denied(_))
            ));
        }
        assert_eq!(
            dispatch::send_blocking(client.get("http://allowed.example/v1"))
                .unwrap()
                .status(),
            200
        );
    })
    .await
    .unwrap();
    let received = proxy.requests.lock().unwrap();
    assert_eq!(received.len(), 1);
    assert!(received[0].starts_with("GET http://allowed.example/v1 "));
}

#[tokio::test]
async fn environment_proxy_is_checked_in_a_fresh_process() {
    const CHILD: &str = "FUIGO_PROXY_DISPATCH_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let client =
            fuigo_extra_ca::build_reqwest_client(|b| b.timeout(Duration::from_secs(3))).unwrap();
        for url in ["https://api.x.ai/v1", "http://api.x.ai/v1"] {
            assert!(matches!(
                dispatch::send(client.get(url)).await,
                Err(DispatchError::Denied(_))
            ));
        }
        assert_eq!(
            dispatch::send(client.get("http://allowed.example/v1"))
                .await
                .unwrap()
                .status(),
            200
        );
        println!("checked-environment-child-entered");
        return;
    }
    let proxy = observer().await;
    let home = tempfile::tempdir().unwrap();
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "environment_proxy_is_checked_in_a_fresh_process",
            "--nocapture",
        ])
        .env_clear()
        .env("HOME", home.path())
        .env(CHILD, "1")
        .env("HTTP_PROXY", &proxy.url)
        .env("HTTPS_PROXY", &proxy.url)
        .env("ALL_PROXY", &proxy.url)
        .env("NO_PROXY", "")
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("checked-environment-child-entered"));
    let received = proxy.requests.lock().unwrap();
    assert_eq!(received.len(), 1);
    assert!(received[0].starts_with("GET http://allowed.example/v1 "));
}
