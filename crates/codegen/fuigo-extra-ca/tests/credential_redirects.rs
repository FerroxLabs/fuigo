//! Real receiving sockets pin credential/body forwarding, not only policy helpers.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Receiver {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn receiver(status: u16, location: Option<String>) -> Receiver {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let received = requests.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0; 4096];
            loop {
                let count = socket.read(&mut buf).await.unwrap();
                if count == 0 {
                    break;
                }
                bytes.extend_from_slice(&buf[..count]);
                if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let request = String::from_utf8(bytes).unwrap();
            // Relative redirect control terminates at /done on the same server.
            let done = request.lines().next().unwrap().contains(" /done ");
            received.lock().unwrap().push(request);
            let (code, extra) = if done {
                (200, String::new())
            } else {
                (
                    status,
                    location
                        .as_ref()
                        .map(|v| format!("Location: {v}\r\n"))
                        .unwrap_or_default(),
                )
            };
            let response = format!(
                "HTTP/1.1 {code} Test\r\n{extra}Content-Length: 2\r\nConnection: close\r\n\r\nok"
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    Receiver {
        url,
        requests,
        task,
    }
}

#[tokio::test]
async fn async_cross_origin_redirect_never_delivers_credentials_or_body() {
    for status in [301, 302, 303, 307, 308] {
        let destination = receiver(200, None).await;
        let source = receiver(status, Some(destination.url.clone())).await;
        let client =
            fuigo_extra_ca::build_reqwest_client(|b| b.no_proxy().timeout(Duration::from_secs(3)))
                .unwrap();
        let result = client
            .post(&source.url)
            .header("x-api-key", "fake-provider-key")
            .bearer_auth("fake-bearer")
            .body("private-request-body")
            .send()
            .await;
        assert!(
            result.is_err(),
            "{status} must reject cross-origin redirect"
        );
        assert!(
            destination.requests.lock().unwrap().is_empty(),
            "{status} contacted another origin"
        );
        let captured = source.requests.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert!(captured[0].contains("fake-provider-key"));
        assert!(captured[0].contains("private-request-body"));
    }
}

#[tokio::test]
async fn blocking_cross_origin_redirect_never_delivers_credentials_or_body() {
    for status in [307, 308] {
        let destination = receiver(200, None).await;
        let source = receiver(status, Some(destination.url.clone())).await;
        let url = source.url.clone();
        let rejected = tokio::task::spawn_blocking(move || {
            let client = fuigo_extra_ca::build_blocking_reqwest_client(|b| {
                b.no_proxy().timeout(Duration::from_secs(3))
            })
            .unwrap();
            client
                .post(url)
                .header("x-api-key", "fake-provider-key")
                .body("private-request-body")
                .send()
                .is_err()
        })
        .await
        .unwrap();
        assert!(rejected, "{status} must reject cross-origin redirect");
        assert!(destination.requests.lock().unwrap().is_empty());
        assert_eq!(source.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn same_origin_307_preserves_body_and_existing_no_redirect_stays_strict() {
    let source = receiver(307, Some("/done".to_string())).await;
    let client =
        fuigo_extra_ca::build_reqwest_client(|b| b.no_proxy().timeout(Duration::from_secs(3)))
            .unwrap();
    let response = client
        .post(&source.url)
        .header("x-api-key", "fake-provider-key")
        .body("private-request-body")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    {
        let captured = source.requests.lock().unwrap();
        assert_eq!(captured.len(), 2);
        assert!(
            captured
                .iter()
                .all(|r| r.contains("fake-provider-key") && r.contains("private-request-body"))
        );
    }
    let strict = fuigo_extra_ca::build_reqwest_client(|b| {
        b.no_proxy().redirect(reqwest::redirect::Policy::none())
    })
    .unwrap();
    assert_eq!(strict.get(&source.url).send().await.unwrap().status(), 307);
    assert_eq!(source.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn public_download_redirects_get_head_and_range_without_credentials() {
    use fuigo_extra_ca::public_download::PublicDownloadClient;
    let destination = receiver(200, None).await;
    let source = receiver(307, Some(destination.url.clone())).await;
    let client = PublicDownloadClient::new(Duration::from_secs(3)).unwrap();
    let url = format!("{}?signature=fake-url-authority", source.url);
    assert_eq!(client.get(&url).await.unwrap().status(), 200);
    assert_eq!(client.head(&url).await.unwrap().status(), 200);
    assert_eq!(client.get_range(&url, 3, 7).await.unwrap().status(), 200);
    let received = destination.requests.lock().unwrap();
    assert_eq!(received.len(), 3);
    assert!(received[0].starts_with("GET "));
    assert!(received[1].starts_with("HEAD "));
    assert!(received[2].contains("range: bytes=3-7"));
    for request in received.iter() {
        let request = request.to_ascii_lowercase();
        for forbidden in [
            "authorization:",
            "x-api-key:",
            "cookie:",
            "referer:",
            "fake-url-authority",
        ] {
            assert!(!request.contains(forbidden), "download leaked {forbidden}");
        }
        assert!(request.ends_with("\r\n\r\n"), "download must have no body");
    }
}

#[tokio::test]
async fn blocking_public_download_follows_without_url_referer() {
    let destination = receiver(200, None).await;
    let source = receiver(308, Some(destination.url.clone())).await;
    let url = format!("{}?signature=fake-url-authority", source.url);
    tokio::task::spawn_blocking(move || {
        let client = fuigo_extra_ca::public_download::BlockingPublicDownloadClient::new(
            Duration::from_secs(3),
        )
        .unwrap();
        assert_eq!(client.get(&url).unwrap().status(), 200);
    })
    .await
    .unwrap();
    let received = destination.requests.lock().unwrap();
    assert_eq!(received.len(), 1);
    assert!(!received[0].to_ascii_lowercase().contains("referer:"));
    assert!(!received[0].contains("fake-url-authority"));
}

#[tokio::test]
async fn public_download_rejects_userinfo_initially_and_on_redirect() {
    let destination = receiver(200, None).await;
    let with_user = destination
        .url
        .replacen("http://", "http://user:fake-password@", 1);
    let source = receiver(307, Some(with_user.clone())).await;
    let client =
        fuigo_extra_ca::public_download::PublicDownloadClient::new(Duration::from_secs(3)).unwrap();
    assert!(client.get(&with_user).await.is_err());
    assert!(client.get(&source.url).await.is_err());
    assert!(destination.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn redirect_loops_are_bounded() {
    let source = receiver(307, Some("/loop".to_string())).await;
    let client =
        fuigo_extra_ca::build_reqwest_client(|b| b.no_proxy().timeout(Duration::from_secs(3)))
            .unwrap();
    let error = client.get(&source.url).send().await.unwrap_err();
    assert!(format!("{error:?}").contains("redirect limit"));
    assert_eq!(source.requests.lock().unwrap().len(), 11);
    let public =
        fuigo_extra_ca::public_download::PublicDownloadClient::new(Duration::from_secs(3)).unwrap();
    let error = public.get(&source.url).await.unwrap_err();
    assert!(format!("{error:?}").contains("redirect limit"));
    assert_eq!(source.requests.lock().unwrap().len(), 22);
}
