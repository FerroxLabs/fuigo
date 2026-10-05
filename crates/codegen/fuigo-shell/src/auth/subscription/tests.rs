use super::*;
use axum::{Form, Router, routing::post};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

struct Server {
    endpoint: String,
    requests: Arc<Mutex<Vec<HashMap<String, String>>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn server(respond: impl Fn(usize) -> serde_json::Value + Send + Sync + 'static) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let respond = Arc::new(respond);
    let app = Router::new().route(
        "/token",
        post(move |Form(form): Form<HashMap<String, String>>| {
            let captured = captured.clone();
            let respond = respond.clone();
            async move {
                let count = {
                    let mut requests = captured.lock().unwrap();
                    requests.push(form);
                    requests.len()
                };
                axum::Json(respond(count))
            }
        }),
    );
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Server {
        endpoint,
        requests,
        task,
    }
}
fn token(provider: SubscriptionProvider, account: &str, expiry: u64) -> String {
    let mut value = serde_json::json!({ "iss": provider.issuer(), "exp": expiry });
    match provider {
        SubscriptionProvider::Chatgpt => {
            value["https://api.openai.com/auth"] =
                serde_json::json!({"chatgpt_account_id": account})
        }
        SubscriptionProvider::Xai => value["sub"] = account.into(),
    }
    format!(
        "header.{}.fake",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
    )
}
fn record(provider: SubscriptionProvider, account: &str) -> Credential {
    Credential {
        provider,
        issuer: provider.issuer().into(),
        client_id: provider.client_id().into(),
        account: account.into(),
        access_token: token(provider, account, now() + 60),
        refresh_token: Some("fake-refresh-1".into()),
        expires_at: now() + 60,
        refresh_pending: false,
    }
}
fn response(provider: SubscriptionProvider, account: &str) -> serde_json::Value {
    serde_json::json!({"access_token": token(provider, account, now()+3600), "token_type":"Bearer", "refresh_token":"fake-refresh-2", "expires_in":3600})
}
fn attempt_parts(attempt: &LoginAttempt) -> (u16, String, String, String) {
    let auth = url::Url::parse(attempt.authorization_url()).unwrap();
    let params: HashMap<_, _> = auth
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let redirect = url::Url::parse(&params["redirect_uri"]).unwrap();
    (
        redirect.port().unwrap(),
        redirect.path().into(),
        params["state"].clone(),
        params["code_challenge"].clone(),
    )
}
async fn callback_request(address: std::net::SocketAddr, target: &str) -> String {
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket
        .write_all(format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut output))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(output).unwrap()
}
async fn callback(port: u16, path: &str, state: &str) -> String {
    callback_request(
        (std::net::Ipv4Addr::LOCALHOST, port).into(),
        &format!("{path}?code=fake-code&state={state}"),
    )
    .await
}

#[tokio::test]
async fn callback_wrong_or_missing_state_then_correct_completes_login() {
    for provider in [SubscriptionProvider::Chatgpt, SubscriptionProvider::Xai] {
        let server = server(move |_| response(provider, "a")).await;
        let temp = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::new(temp.path());
        let attempt = LoginAttempt::bind(provider, 0)
            .await
            .unwrap()
            .with_endpoint(server.endpoint.clone());
        let (port, path, state, _) = attempt_parts(&attempt);
        let (result, _) = tokio::join!(
            attempt.finish_with_timeout(&store, CancellationToken::new(), Duration::from_secs(5)),
            async {
                for query in ["state=wrong-state", "", "state=wrong&state=duplicate"] {
                    let reply = callback_request(
                        (std::net::Ipv4Addr::LOCALHOST, port).into(),
                        &format!("{path}?code=fake-code&{query}"),
                    ).await;
                    assert!(reply.starts_with("HTTP/1.1 400"));
                    assert!(server.requests.lock().unwrap().is_empty());
                    assert!(!temp.path().join("subscriptions/credentials.json").exists());
                }
                assert!(callback(port, &path, &state).await.starts_with("HTTP/1.1 200"));
            }
        );
        result.unwrap();
        assert_eq!(server.requests.lock().unwrap().len(), 1);
        assert_eq!(store.status(provider).await.unwrap()[0].account, "a");
    }
}

/// Writes raw bytes to the callback port (half-closing the write side) and returns whatever
/// the listener answered before closing.
async fn raw_request(port: u16, bytes: &[u8]) -> String {
    let mut socket = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    socket.write_all(bytes).await.unwrap();
    socket.shutdown().await.unwrap();
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut output))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8_lossy(&output).into_owned()
}

#[tokio::test]
async fn callback_junk_never_ends_the_login_and_the_real_callback_still_completes() {
    let provider = SubscriptionProvider::Xai;
    let server = server(move |_| response(provider, "a")).await;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    let attempt = LoginAttempt::bind(provider, 0)
        .await
        .unwrap()
        .with_endpoint(server.endpoint.clone());
    let (port, path, state, _) = attempt_parts(&attempt);
    let (result, _) = tokio::join!(
        attempt.finish_with_timeout(&store, CancellationToken::new(), Duration::from_secs(10)),
        async {
            // Far more than any request budget: ignored requests are never counted.
            for _ in 0..40 {
                assert!(callback(port, &path, "wrong-state").await.starts_with("HTTP/1.1 400"));
            }
            let junk: [&[u8]; 6] = [
                b"\xff\xfe GET / HTTP/1.1\r\n\r\n",
                b"GET\r\n\r\n",
                b"GET //evil.example/callback HTTP/1.1\r\n\r\n",
                b"GET http://evil.example/callback HTTP/1.1\r\n\r\n",
                b"POST /callback HTTP/1.1\r\n\r\n",
                b"GET /callback?code=x&state=",
            ];
            for bytes in junk {
                let reply = raw_request(port, bytes).await;
                assert!(reply.starts_with("HTTP/1.1 400"), "{reply:?}");
            }
            // Malformed heads carrying THIS attempt's state, with a code or with an error:
            // ignored too, neither exchanged nor ending the login.
            for query in [format!("code=x&state={state}"), format!("state={state}&error=access_denied")] {
                for head in [
                    format!("GET {path}?{query}\r\n\r\n"),
                    format!("GET {path}?{query} HTTP/1.1 extra\r\n\r\n"),
                    format!("GET {path}?{query} HTTP/2\r\n\r\n"),
                    format!("GET {path}?{query} HTTP/1.1\r\nno-colon-header\r\n\r\n"),
                    format!("GET  {path}?{query} HTTP/1.1\r\n\r\n"),
                    format!("GET {path}?{query} HTTP/1.1\n\n"),
                    format!("GET {path}?{query} HTTP/1.1\r\nHost: localhost\r\nBad(Name): x\r\n\r\n"),
                    format!("GET {path}?{query} HTTP/1.1\r\nHost: local\u{0}host\r\n\r\n"),
                    format!("GET {path}?{query} HTTP/1.1\r\nHost: local\u{7f}host\r\n\r\n"),
                    format!("GET {path}?{query}&state={state} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
                    format!("GET {path}?{query}#junk HTTP/1.1\r\nHost: localhost\r\n\r\n"),
                    format!("GET {path}?{query}&x=\u{e9} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
                    format!("GET {path}?{query}&x=a\"b HTTP/1.1\r\nHost: localhost\r\n\r\n"),
                ] {
                    let reply = raw_request(port, head.as_bytes()).await;
                    assert!(reply.starts_with("HTTP/1.1 400"), "{head:?}: {reply:?}");
                }
            }
            assert!(
                raw_request(port, b"GET /elsewhere HTTP/1.1\r\n\r\n")
                    .await
                    .starts_with("HTTP/1.1 404")
            );
            assert!(server.requests.lock().unwrap().is_empty());
            assert!(callback(port, &path, &state).await.starts_with("HTTP/1.1 200"));
        }
    );
    result.unwrap();
    assert_eq!(server.requests.lock().unwrap().len(), 1);
    assert_eq!(store.status(provider).await.unwrap()[0].account, "a");
}

#[tokio::test]
async fn callback_idle_connections_do_not_block_the_real_callback() {
    let provider = SubscriptionProvider::Xai;
    let server = server(move |_| response(provider, "a")).await;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    let attempt = LoginAttempt::bind(provider, 0)
        .await
        .unwrap()
        .with_endpoint(server.endpoint.clone());
    let (port, path, state, _) = attempt_parts(&attempt);
    // Connected, never sending a request line, held open for the whole attempt.
    let mut idle = Vec::new();
    for _ in 0..4 {
        idle.push(
            TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap(),
        );
    }
    // The deadline is shorter than one idle connection's read timeout, so a listener that
    // served connections one at a time could not reach the real callback in time.
    let (result, reply) = tokio::join!(
        attempt.finish_with_timeout(&store, CancellationToken::new(), Duration::from_secs(3)),
        async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            callback(port, &path, &state).await
        }
    );
    result.unwrap();
    assert!(reply.starts_with("HTTP/1.1 200"));
    assert_eq!(store.status(provider).await.unwrap()[0].account, "a");
    drop(idle);
}

#[tokio::test]
async fn callback_correct_state_with_provider_error_still_aborts() {
    let provider = SubscriptionProvider::Xai;
    let server = server(move |_| response(provider, "a")).await;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    let attempt = LoginAttempt::bind(provider, 0)
        .await
        .unwrap()
        .with_endpoint(server.endpoint.clone());
    let (port, path, state, _) = attempt_parts(&attempt);
    let target = format!("{path}?state={state}&error=access_denied");
    let (result, reply) = tokio::join!(
        attempt.finish_with_timeout(&store, CancellationToken::new(), Duration::from_secs(5)),
        callback_request(
            (std::net::Ipv4Addr::LOCALHOST, port).into(),
            &target,
        )
    );
    assert!(matches!(result, Err(SubscriptionError::Callback)));
    assert!(reply.starts_with("HTTP/1.1 400"));
    assert!(server.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn callback_wrong_state_still_obeys_overall_timeout() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    let attempt = LoginAttempt::bind(SubscriptionProvider::Xai, 0).await.unwrap();
    let (port, path, _, _) = attempt_parts(&attempt);
    let (result, reply) = tokio::join!(
        attempt.finish_with_timeout(&store, CancellationToken::new(), Duration::from_millis(500)),
        callback(port, &path, "wrong-state")
    );
    assert!(reply.starts_with("HTTP/1.1 400"));
    assert!(matches!(result, Err(SubscriptionError::Timeout)));
}

/// Whether this host has an IPv6 loopback to bind (some containers and hardened hosts do not).
async fn host_has_ipv6_loopback() -> bool {
    match TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)).await {
        Ok(_) => true,
        Err(error) => {
            assert!(
                flow::ipv6_loopback_unavailable(&error),
                "unexpected IPv6 loopback probe failure: {error}"
            );
            false
        }
    }
}

#[tokio::test]
async fn chatgpt_listener_reserves_both_families_and_accepts_ipv6() {
    let provider = SubscriptionProvider::Chatgpt;
    let server = server(move |_| response(provider, "a")).await;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    let attempt = LoginAttempt::bind(provider, 0)
        .await
        .unwrap()
        .with_endpoint(server.endpoint.clone());
    let (port, path, state, _) = attempt_parts(&attempt);
    assert!(TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await.is_err());
    let target = format!("{path}?code=fake-code&state={state}");
    let address: std::net::SocketAddr = if host_has_ipv6_loopback().await {
        // The IPv6 side of the redirect is ours: nobody else can bind it ...
        assert!(TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port)).await.is_err());
        // ... and a browser that resolves localhost to ::1 completes the login there.
        (std::net::Ipv6Addr::LOCALHOST, port).into()
    } else {
        assert!(!attempt.listens_on_ipv6());
        (std::net::Ipv4Addr::LOCALHOST, port).into()
    };
    let (result, reply) = tokio::join!(
        attempt.finish_with_timeout(&store, CancellationToken::new(), Duration::from_secs(5)),
        callback_request(address, &target)
    );
    result.unwrap();
    assert!(reply.starts_with("HTTP/1.1 200"));
    assert_eq!(store.status(provider).await.unwrap()[0].account, "a");
}

#[tokio::test]
async fn chatgpt_listener_fails_if_either_loopback_family_is_occupied() {
    let occupied = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = occupied.local_addr().unwrap().port();
    assert!(matches!(
        LoginAttempt::bind(SubscriptionProvider::Chatgpt, port).await,
        Err(SubscriptionError::Listener)
    ));
    if host_has_ipv6_loopback().await {
        let occupied = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        let port = occupied.local_addr().unwrap().port();
        assert!(matches!(
            LoginAttempt::bind(SubscriptionProvider::Chatgpt, port).await,
            Err(SubscriptionError::Listener)
        ));
    }
}

/// The bind seam: IPv4 binds for real, IPv6 fails with `error` (or binds for real on `None`).
fn ipv6_bind_fails_with(
    error: Option<fn() -> std::io::Error>,
    ipv6_attempts: Arc<std::sync::atomic::AtomicUsize>,
) -> impl Fn(
    std::net::SocketAddr,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<TcpListener>>>> {
    move |address| {
        let ipv6_attempts = ipv6_attempts.clone();
        Box::pin(async move {
            if address.is_ipv6() {
                ipv6_attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if let Some(error) = error {
                    return Err(error());
                }
            }
            TcpListener::bind(address).await
        })
    }
}

#[tokio::test]
async fn chatgpt_listener_continues_on_ipv4_when_the_host_has_no_ipv6_loopback() {
    let mut unavailable: Vec<fn() -> std::io::Error> = vec![
        // EADDRNOTAVAIL: IPv6 disabled on the loopback interface.
        || std::io::Error::from(std::io::ErrorKind::AddrNotAvailable),
        // EAFNOSUPPORT: no IPv6 in the kernel at all.
        || std::io::Error::from_raw_os_error(flow::EAFNOSUPPORT),
    ];
    #[cfg(unix)]
    unavailable.push(|| std::io::Error::from_raw_os_error(libc::EADDRNOTAVAIL));
    for error in unavailable {
        let provider = SubscriptionProvider::Chatgpt;
        let server = server(move |_| response(provider, "a")).await;
        let temp = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::new(temp.path());
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let attempt = LoginAttempt::bind_with(provider, 0, ipv6_bind_fails_with(Some(error), attempts.clone()))
            .await
            .expect("no IPv6 loopback is not a reason to refuse sign-in")
            .with_endpoint(server.endpoint.clone());
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(!attempt.listens_on_ipv6());
        let (port, path, state, _) = attempt_parts(&attempt);
        let (result, reply) = tokio::join!(
            attempt.finish_with_timeout(&store, CancellationToken::new(), Duration::from_secs(5)),
            callback(port, &path, &state)
        );
        result.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"));
        assert_eq!(store.status(provider).await.unwrap()[0].account, "a");
    }
}

#[tokio::test]
async fn chatgpt_listener_aborts_when_ipv6_loopback_is_held_or_fails_otherwise() {
    let mut fatal: Vec<fn() -> std::io::Error> = vec![
        // Someone else holds [::1]:port: they would receive the redirect.
        || std::io::Error::from(std::io::ErrorKind::AddrInUse),
        // Unknown failures fail closed too: we cannot tell nobody else is listening there.
        || std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    ];
    #[cfg(unix)]
    fatal.push(|| std::io::Error::from_raw_os_error(libc::EADDRINUSE));
    for error in fatal {
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        assert!(matches!(
            LoginAttempt::bind_with(
                SubscriptionProvider::Chatgpt,
                0,
                ipv6_bind_fails_with(Some(error), attempts.clone())
            )
            .await,
            Err(SubscriptionError::Listener)
        ));
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    // xAI's redirect names 127.0.0.1, so it never binds IPv6 at all.
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attempt = LoginAttempt::bind_with(
        SubscriptionProvider::Xai,
        0,
        ipv6_bind_fails_with(Some(|| std::io::Error::from(std::io::ErrorKind::AddrInUse)), attempts.clone()),
    )
    .await
    .unwrap();
    assert!(!attempt.listens_on_ipv6());
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
    // An IPv4 failure aborts before IPv6 is tried.
    let occupied = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = occupied.local_addr().unwrap().port();
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    assert!(matches!(
        LoginAttempt::bind_with(SubscriptionProvider::Chatgpt, port, ipv6_bind_fails_with(None, attempts.clone())).await,
        Err(SubscriptionError::Listener)
    ));
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pkce_exchange_uses_attempt_verifier_and_saves_binding() {
    for provider in [SubscriptionProvider::Chatgpt, SubscriptionProvider::Xai] {
        let temp = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::new(temp.path());
        let attempt = LoginAttempt::bind(provider, 0).await.unwrap();
        let released = attempt.listener_drop_probe();
        let at_exchange = Arc::new(Mutex::new(None));
        let (probe, seen) = (released.clone(), at_exchange.clone());
        let server = server(move |_| {
            *seen.lock().unwrap() = Some(probe.load(std::sync::atomic::Ordering::SeqCst));
            response(provider, "a")
        })
        .await;
        let attempt = attempt.with_endpoint(server.endpoint.clone());
        let (port, path, state, challenge) = attempt_parts(&attempt);
        let (result, reply) = tokio::join!(
            attempt.finish(&store, CancellationToken::new()),
            callback(port, &path, &state)
        );
        result.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"));
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(requests[0]["code_verifier"].as_bytes())),
            challenge
        );
        assert_eq!(requests[0]["code"], "fake-code");
        assert_eq!(requests[0]["client_id"], provider.client_id());
        drop(requests);
        assert_eq!(store.status(provider).await.unwrap()[0].account, "a");
        // Released before the token exchange began, not merely by the end.
        assert_eq!(*at_exchange.lock().unwrap(), Some(true));
        assert!(released.load(std::sync::atomic::Ordering::SeqCst));
    }
}

#[tokio::test]
async fn cancelled_and_timed_out_login_release_listener() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    for cancel_first in [true, false] {
        let attempt = LoginAttempt::bind(SubscriptionProvider::Xai, 0)
            .await
            .unwrap();
        let released = attempt.listener_drop_probe();
        assert!(!released.load(std::sync::atomic::Ordering::SeqCst));
        let cancel = CancellationToken::new();
        if cancel_first {
            cancel.cancel();
        }
        let result = attempt
            .finish_with_timeout(&store, cancel, Duration::from_millis(10))
            .await;
        if cancel_first {
            assert!(matches!(result, Err(SubscriptionError::Cancelled)));
        } else {
            assert!(matches!(result, Err(SubscriptionError::Timeout)));
        }
        // Asserted on the listener itself, not by re-binding its ephemeral port: another
        // test may legitimately take that port the instant it is released.
        assert!(released.load(std::sync::atomic::Ordering::SeqCst));
    }
    assert!(!temp.path().join("subscriptions/credentials.json").exists());
}

#[tokio::test]
async fn concurrent_refresh_reloads_rotated_record_after_lock() {
    for provider in [SubscriptionProvider::Chatgpt, SubscriptionProvider::Xai] {
        let server = server(move |_| response(provider, "a")).await;
        let temp = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::new(temp.path());
        store.save(record(provider, "a")).await.unwrap();
        let sibling = SubscriptionStore::new(temp.path());
        let client = flow::TokenClient::local(provider, server.endpoint.clone());
        let (a, b) = tokio::join!(
            store.access_with(provider, None, client.clone()),
            sibling.access_with(provider, None, client)
        );
        assert_eq!(a.unwrap().bearer().unwrap(), b.unwrap().bearer().unwrap());
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["refresh_token"], "fake-refresh-1");
        assert_eq!(
            requests[0].get("scope").map(String::as_str),
            if provider == SubscriptionProvider::Xai {
                Some(provider.scope())
            } else {
                None
            }
        );
    }
}

#[tokio::test]
async fn ambiguous_refresh_and_expired_credentials_fail_closed_redacted() {
    let provider = SubscriptionProvider::Xai;
    let server = server(|_| serde_json::json!({"error":"fake-secret-do-not-echo"})).await;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(provider, "a")).await.unwrap();
    let client = flow::TokenClient::local(provider, server.endpoint.clone());
    let first = store
        .access_with(provider, None, client.clone())
        .await
        .unwrap_err();
    assert!(!format!("{first:?} {first}").contains("fake-secret"));
    assert!(matches!(
        store.access_with(provider, None, client).await,
        Err(SubscriptionError::LoginRequired)
    ));
    assert_eq!(server.requests.lock().unwrap().len(), 1);
    let mut expired = record(provider, "a");
    expired.expires_at = now() - 1;
    assert!(expired.access().is_err());
    assert!(!format!("{expired:?}").contains("fake-refresh"));
}

#[tokio::test]
async fn logout_isolates_provider_and_account_and_store_is_private() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store
        .save(record(SubscriptionProvider::Chatgpt, "a"))
        .await
        .unwrap();
    store
        .save(record(SubscriptionProvider::Chatgpt, "b"))
        .await
        .unwrap();
    store
        .save(record(SubscriptionProvider::Xai, "a"))
        .await
        .unwrap();
    store
        .logout(SubscriptionProvider::Chatgpt, Some("b"))
        .await
        .unwrap();
    let status = store.status(SubscriptionProvider::Chatgpt).await.unwrap();
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].account, "a");
    assert!(!status[0].selected);
    store
        .logout(SubscriptionProvider::Chatgpt, None)
        .await
        .unwrap();
    assert!(
        store
            .status(SubscriptionProvider::Chatgpt)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.status(SubscriptionProvider::Xai).await.unwrap().len(),
        1
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(temp.path().join("subscriptions"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(temp.path().join("subscriptions/credentials.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[tokio::test]
async fn logout_all_deletes_tokens_and_requires_fresh_login() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    for provider in [SubscriptionProvider::Chatgpt, SubscriptionProvider::Xai] {
        for account in ["a", "b"] {
            store.save(record(provider, account)).await.unwrap();
        }
    }
    let path = temp.path().join("subscriptions/credentials.json");
    assert!(path.exists());
    store.logout_all().await.unwrap();
    assert!(!path.exists());
    // Keep the lock inode shared by other processes.
    assert!(temp.path().join("subscriptions/credentials.lock").exists());
    let sibling = SubscriptionStore::new(temp.path());
    for provider in [SubscriptionProvider::Chatgpt, SubscriptionProvider::Xai] {
        let server = server(move |_| response(provider, "a")).await;
        let client = flow::TokenClient::local(provider, server.endpoint.clone());
        assert!(sibling.status(provider).await.unwrap().is_empty());
        for account in [None, Some("a"), Some("b")] {
            assert!(matches!(
                sibling.access_with(provider, account, client.clone()).await,
                Err(SubscriptionError::LoginRequired)
            ));
        }
        assert!(server.requests.lock().unwrap().is_empty());
    }
    assert!(!path.exists());
    store.logout_all().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn logout_all_waits_for_an_in_flight_refresh_so_it_cannot_write_the_tokens_back() {
    let provider = SubscriptionProvider::Chatgpt;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    // Expires inside the refresh margin, so the next access refreshes.
    store.save(record(provider, "a")).await.unwrap();
    let exchanging = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = exchanging.clone();
    let server = server(move |_| {
        seen.store(true, std::sync::atomic::Ordering::SeqCst);
        // Hold the exchange open (this blocks one worker of the multi-thread runtime).
        std::thread::sleep(Duration::from_millis(700));
        response(provider, "a")
    })
    .await;
    let refresh = tokio::spawn({
        let store = store.clone();
        let client = flow::TokenClient::local(provider, server.endpoint.clone());
        async move { store.access_with(provider, None, client).await }
    });
    while !exchanging.load(std::sync::atomic::Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // The refresh holds the store lock and is mid-exchange: logout must wait for it.
    store.logout_all().await.unwrap();
    assert!(refresh.await.unwrap().is_ok());
    let path = temp.path().join("subscriptions/credentials.json");
    assert!(!path.exists(), "a refresh wrote the tokens back after logout");
    let client = flow::TokenClient::local(provider, server.endpoint.clone());
    assert!(matches!(
        store.access_with(provider, None, client).await,
        Err(SubscriptionError::LoginRequired)
    ));
    assert_eq!(server.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn logout_all_deletes_only_inside_the_subscription_store() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(SubscriptionProvider::Xai, "a")).await.unwrap();
    let root = temp.path().join("subscriptions");
    // A write interrupted by a crash leaves its temp file: a full copy of the records.
    std::fs::write(root.join(".tmpAbC123"), b"fake-refresh-orphan").unwrap();
    std::fs::write(root.join("notes.txt"), b"not a credential file").unwrap();
    let outside = temp.path().join("auth.json");
    std::fs::write(&outside, b"session").unwrap();
    let outside_tmp = temp.path().join(".tmpOutside");
    std::fs::write(&outside_tmp, b"not ours").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, root.join(".tmpLink")).unwrap();
    store.logout_all().await.unwrap();
    assert!(!root.join("credentials.json").exists());
    assert!(!root.join(".tmpAbC123").exists());
    assert!(root.join("notes.txt").exists());
    assert!(root.join("credentials.lock").exists());
    assert_eq!(std::fs::read(&outside).unwrap(), b"session");
    assert!(outside_tmp.exists());
    #[cfg(unix)]
    assert!(std::fs::symlink_metadata(root.join(".tmpLink")).is_ok());
}

#[tokio::test]
async fn logout_all_removes_corrupt_credentials_without_parsing_them() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(SubscriptionProvider::Xai, "a")).await.unwrap();
    let path = temp.path().join("subscriptions/credentials.json");
    std::fs::write(&path, b"corrupt-fake-token").unwrap();
    store.logout_all().await.unwrap();
    assert!(!path.exists());
}

#[tokio::test]
async fn persistence_error_is_not_success_and_never_truncates_existing_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store
        .save(record(SubscriptionProvider::Chatgpt, "a"))
        .await
        .unwrap();
    let path = temp.path().join("subscriptions/credentials.json");
    std::fs::write(&path, b"corrupt-but-preserved-fake-secret").unwrap();
    assert!(matches!(
        store.save(record(SubscriptionProvider::Xai, "a")).await,
        Err(SubscriptionError::Storage)
    ));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"corrupt-but-preserved-fake-secret"
    );
}

#[tokio::test]
async fn rotated_persist_failure_is_reported_and_account_switch_is_rejected() {
    for changed_account in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::new(temp.path());
        let provider = SubscriptionProvider::Chatgpt;
        store.save(record(provider, "a")).await.unwrap();
        let path = temp.path().join("subscriptions/credentials.json");
        let server = server(move |_| {
            if !changed_account {
                std::fs::rename(&path, path.with_extension("pending")).unwrap();
                std::fs::create_dir(&path).unwrap();
            }
            response(provider, if changed_account { "other" } else { "a" })
        })
        .await;
        let result = store
            .access_with(
                provider,
                None,
                flow::TokenClient::local(provider, server.endpoint.clone()),
            )
            .await;
        if changed_account {
            assert!(matches!(result, Err(SubscriptionError::InvalidCredentials)));
        } else {
            // A real filesystem fault after the provider rotated the token: the new
            // credential is reported as unsaved, never as a stored success.
            assert!(result.unwrap().is_unpersisted());
        }
        assert_eq!(server.requests.lock().unwrap().len(), 1);
    }
}

fn on_disk(home: &Path, provider: SubscriptionProvider, account: &str) -> serde_json::Value {
    let bytes = std::fs::read(home.join("subscriptions/credentials.json")).unwrap();
    let records: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    records[provider.name()]["accounts"][account].clone()
}
/// Makes the store's post-exchange writes fail `faults` times, starting once the provider
/// has answered (the pre-exchange latch write is left alone).
async fn refresh_then_fail_writes(
    store: &SubscriptionStore,
    provider: SubscriptionProvider,
    faults: usize,
) -> (Result<SubscriptionAccess>, Server) {
    let injected = store.write_faults.clone();
    let rotating = server(move |_| {
        injected.store(faults, std::sync::atomic::Ordering::SeqCst);
        response(provider, "a")
    })
    .await;
    let result = store
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, rotating.endpoint.clone()),
        )
        .await;
    (result, rotating)
}

#[tokio::test]
async fn a_brief_disk_fault_after_a_refresh_is_retried_and_saved() {
    let provider = SubscriptionProvider::Xai;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(provider, "a")).await.unwrap();
    let (result, rotating) = refresh_then_fail_writes(&store, provider, 2).await;
    let access = result.expect("two failed writes are within the retry budget");
    assert!(!access.is_unpersisted());
    assert_eq!(rotating.requests.lock().unwrap().len(), 1);
    let saved = on_disk(temp.path(), provider, "a");
    assert_eq!(saved["refresh_token"], "fake-refresh-2");
    assert_eq!(saved["refresh_pending"], false);
}

#[tokio::test]
async fn a_refresh_that_cannot_be_saved_keeps_the_new_tokens_and_never_reuses_the_old() {
    let provider = SubscriptionProvider::Xai;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(provider, "a")).await.unwrap();
    let (result, rotating) = refresh_then_fail_writes(&store, provider, usize::MAX).await;
    let access = result.expect("a disk fault after a successful refresh must not sign out");
    assert!(access.is_unpersisted());
    let issued = access.bearer().unwrap().to_owned();
    assert_eq!(rotating.requests.lock().unwrap().len(), 1);
    // The disk still holds the rotated-away token behind the latch: no process may use it.
    let latched = on_disk(temp.path(), provider, "a");
    assert_eq!(latched["refresh_token"], "fake-refresh-1");
    assert_eq!(latched["refresh_pending"], true);

    // Disk still broken: the session keeps working on the new tokens, without a new exchange.
    let live = server(move |_| response(provider, "a")).await;
    let again = store
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, live.endpoint.clone()),
        )
        .await
        .unwrap();
    assert!(again.is_unpersisted());
    assert_eq!(again.bearer().unwrap(), issued);
    assert!(live.requests.lock().unwrap().is_empty());

    // Disk recovers: the next use saves the new tokens, still without a new exchange.
    store
        .write_faults
        .store(0, std::sync::atomic::Ordering::SeqCst);
    let healed = store
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, live.endpoint.clone()),
        )
        .await
        .unwrap();
    assert!(!healed.is_unpersisted());
    assert_eq!(healed.bearer().unwrap(), issued);
    assert!(live.requests.lock().unwrap().is_empty());
    let saved = on_disk(temp.path(), provider, "a");
    assert_eq!(saved["refresh_token"], "fake-refresh-2");
    assert_eq!(saved["refresh_pending"], false);

    // The next refresh presents the token the provider issued, never the rotated-away one.
    let path = temp.path().join("subscriptions/credentials.json");
    let mut records: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    records[provider.name()]["accounts"]["a"]["expires_at"] = now().into();
    std::fs::write(&path, serde_json::to_vec(&records).unwrap()).unwrap();
    store
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, live.endpoint.clone()),
        )
        .await
        .unwrap();
    let requests = live.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["refresh_token"], "fake-refresh-2");
}

#[tokio::test]
async fn unsaved_refresh_tokens_yield_to_a_logout_or_a_fresh_login() {
    let provider = SubscriptionProvider::Xai;
    for fresh_login in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::new(temp.path());
        store.save(record(provider, "a")).await.unwrap();
        let (result, _rotating) = refresh_then_fail_writes(&store, provider, usize::MAX).await;
        assert!(result.unwrap().is_unpersisted());
        store
            .write_faults
            .store(0, std::sync::atomic::Ordering::SeqCst);
        let live = server(move |_| response(provider, "a")).await;
        let client = flow::TokenClient::local(provider, live.endpoint.clone());
        if fresh_login {
            let mut login = record(provider, "a");
            login.refresh_token = Some("fake-refresh-login".into());
            login.expires_at = now() + 3600;
            let login_bearer = login.access_token.clone();
            store.save(login).await.unwrap();
            let access = store.access_with(provider, None, client).await.unwrap();
            assert!(!access.is_unpersisted());
            assert_eq!(access.bearer().unwrap(), login_bearer);
            assert_eq!(
                on_disk(temp.path(), provider, "a")["refresh_token"],
                "fake-refresh-login"
            );
        } else {
            store.logout(provider, None).await.unwrap();
            assert!(matches!(
                store.access_with(provider, None, client).await,
                Err(SubscriptionError::LoginRequired)
            ));
            assert!(on_disk(temp.path(), provider, "a").is_null());
        }
        assert!(live.requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn unsaved_refresh_tokens_are_ignored_once_the_disk_moved_on_elsewhere() {
    // Another process replaced the latched record (here: wrote a fresh login directly),
    // so the in-memory credential no longer supersedes what is on disk.
    let provider = SubscriptionProvider::Xai;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(provider, "a")).await.unwrap();
    let (result, _rotating) = refresh_then_fail_writes(&store, provider, usize::MAX).await;
    assert!(result.unwrap().is_unpersisted());
    store
        .write_faults
        .store(0, std::sync::atomic::Ordering::SeqCst);
    let other_process = SubscriptionStore::new(temp.path());
    let path = temp.path().join("subscriptions/credentials.json");
    let mut records: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut login = record(provider, "a");
    login.refresh_token = Some("fake-refresh-elsewhere".into());
    login.expires_at = now() + 3600;
    let login_bearer = login.access_token.clone();
    records[provider.name()]["accounts"]["a"] = serde_json::to_value(&login).unwrap();
    std::fs::write(&path, serde_json::to_vec(&records).unwrap()).unwrap();
    let live = server(move |_| response(provider, "a")).await;
    let access = other_process
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, live.endpoint.clone()),
        )
        .await
        .unwrap();
    assert!(!access.is_unpersisted());
    assert_eq!(access.bearer().unwrap(), login_bearer);
    assert_eq!(
        on_disk(temp.path(), provider, "a")["refresh_token"],
        "fake-refresh-elsewhere"
    );
    assert!(live.requests.lock().unwrap().is_empty());
}
#[tokio::test]
async fn an_unsaved_credential_near_expiry_is_never_refreshed_from_memory() {
    let provider = SubscriptionProvider::Xai;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(provider, "a")).await.unwrap();
    let injected = store.write_faults.clone();
    // The provider issues a credential that already needs refreshing within two minutes.
    let rotating = server(move |_| {
        injected.store(usize::MAX, std::sync::atomic::Ordering::SeqCst);
        serde_json::json!({"access_token": token(provider, "a", now() + 60), "token_type": "Bearer",
            "refresh_token": "fake-refresh-2", "expires_in": 60})
    })
    .await;
    let first = store
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, rotating.endpoint.clone()),
        )
        .await
        .unwrap();
    assert!(first.is_unpersisted());
    // Still unsaved and inside the refresh window: refuse rather than rotate a token that
    // only memory holds.
    let live = server(move |_| response(provider, "a")).await;
    assert!(matches!(
        store
            .access_with(
                provider,
                None,
                flow::TokenClient::local(provider, live.endpoint.clone())
            )
            .await,
        Err(SubscriptionError::Storage)
    ));
    assert!(live.requests.lock().unwrap().is_empty());
    // It was kept, not dropped: once the disk recovers it is saved and refreshed with the
    // token the provider issued.
    store
        .write_faults
        .store(0, std::sync::atomic::Ordering::SeqCst);
    let refreshed = store
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, live.endpoint.clone()),
        )
        .await
        .unwrap();
    assert!(!refreshed.is_unpersisted());
    let requests = live.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["refresh_token"], "fake-refresh-2");
}

#[tokio::test]
async fn unsaved_tokens_supersede_only_the_exact_latched_record() {
    let provider = SubscriptionProvider::Xai;
    // Each disk state differs from the latched record in exactly one respect.
    // The third case is a LATER latch over the same refresh token (a provider that did not
    // rotate, then another process's refresh): only the access token tells it apart.
    for (pending, refresh, later_access) in [
        (true, "fake-refresh-other", false),
        (false, "fake-refresh-1", false),
        (true, "fake-refresh-1", true),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::new(temp.path());
        store.save(record(provider, "a")).await.unwrap();
        let (result, _rotating) = refresh_then_fail_writes(&store, provider, usize::MAX).await;
        let unsaved = result.unwrap();
        assert!(unsaved.is_unpersisted());
        let unsaved_bearer = unsaved.bearer().unwrap().to_owned();
        store
            .write_faults
            .store(0, std::sync::atomic::Ordering::SeqCst);
        let path = temp.path().join("subscriptions/credentials.json");
        // Start from the latched record actually on disk and change one identifying field.
        let mut records: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let latched = &mut records[provider.name()]["accounts"]["a"];
        assert_eq!(latched["refresh_pending"], true);
        assert_eq!(latched["refresh_token"], "fake-refresh-1");
        latched["refresh_token"] = refresh.into();
        latched["refresh_pending"] = pending.into();
        if later_access {
            latched["access_token"] = "fake-later-access".into();
        }
        // Long-lived, so an unlatched record is served as is rather than refreshed.
        latched["expires_at"] = (now() + 3600).into();
        std::fs::write(&path, serde_json::to_vec(&records).unwrap()).unwrap();
        let live = server(move |_| response(provider, "a")).await;
        let result = store
            .access_with(
                provider,
                None,
                flow::TokenClient::local(provider, live.endpoint.clone()),
            )
            .await;
        if pending {
            // Somebody else's latch: it stands, and the stash does not overwrite it.
            assert!(matches!(result, Err(SubscriptionError::LoginRequired)));
            assert_eq!(
                on_disk(temp.path(), provider, "a")["refresh_token"],
                refresh
            );
        } else {
            let access = result.unwrap();
            assert!(!access.is_unpersisted());
            assert_ne!(access.bearer().unwrap(), unsaved_bearer);
            assert_eq!(
                on_disk(temp.path(), provider, "a")["refresh_pending"],
                false
            );
        }
        assert!(live.requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn logout_ends_unsaved_tokens_even_while_the_disk_is_failing() {
    let provider = SubscriptionProvider::Xai;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(provider, "a")).await.unwrap();
    let (result, _rotating) = refresh_then_fail_writes(&store, provider, usize::MAX).await;
    assert!(result.unwrap().is_unpersisted());
    // The disk is still failing, so the logout write fails too ...
    assert!(matches!(
        store.logout(provider, None).await,
        Err(SubscriptionError::Storage)
    ));
    // ... but the session-only credential is gone: the latch on disk now decides.
    let live = server(move |_| response(provider, "a")).await;
    assert!(matches!(
        store
            .access_with(
                provider,
                None,
                flow::TokenClient::local(provider, live.endpoint.clone())
            )
            .await,
        Err(SubscriptionError::LoginRequired)
    ));
    assert!(live.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_refresh_renamed_into_place_but_not_confirmed_durable_is_saved_again() {
    let provider = SubscriptionProvider::Xai;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(provider, "a")).await.unwrap();
    let injected = store.fsync_faults.clone();
    // Every write now lands its rename and then fails, as a failed directory fsync would.
    let rotating = server(move |_| {
        injected.store(usize::MAX, std::sync::atomic::Ordering::SeqCst);
        response(provider, "a")
    })
    .await;
    let first = store
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, rotating.endpoint.clone()),
        )
        .await
        .unwrap();
    assert!(first.is_unpersisted());
    // The new record is on disk, but nothing has confirmed it durable ...
    assert_eq!(
        on_disk(temp.path(), provider, "a")["refresh_token"],
        "fake-refresh-2"
    );
    let live = server(move |_| response(provider, "a")).await;
    let again = store
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, live.endpoint.clone()),
        )
        .await
        .unwrap();
    // ... so it is still reported unsaved rather than silently promoted.
    assert!(again.is_unpersisted());
    store
        .fsync_faults
        .store(0, std::sync::atomic::Ordering::SeqCst);
    let saved = store
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, live.endpoint.clone()),
        )
        .await
        .unwrap();
    assert!(!saved.is_unpersisted());
    assert_eq!(saved.bearer().unwrap(), first.bearer().unwrap());
    assert!(live.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn subscription_refresh_child_process() {
    let Ok(home) = std::env::var("FUIGO_SUBSCRIPTION_TEST_HOME") else {
        return;
    };
    let endpoint = std::env::var("FUIGO_SUBSCRIPTION_TEST_ENDPOINT").unwrap();
    let provider = SubscriptionProvider::Xai;
    SubscriptionStore::new(Path::new(&home))
        .access_with(provider, None, flow::TokenClient::local(provider, endpoint))
        .await
        .unwrap();
}

#[tokio::test]
async fn refresh_is_serialized_across_processes() {
    let provider = SubscriptionProvider::Xai;
    let server = server(move |_| response(provider, "a")).await;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(provider, "a")).await.unwrap();
    let spawn = || {
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "auth::subscription::tests::subscription_refresh_child_process",
            ])
            .env("FUIGO_SUBSCRIPTION_TEST_HOME", temp.path())
            .env("FUIGO_HOME", temp.path())
            .env("FUIGO_SUBSCRIPTION_TEST_ENDPOINT", &server.endpoint)
            .kill_on_drop(true);
        command.spawn().unwrap()
    };
    let mut a = spawn();
    let mut b = spawn();
    let (a, b) = tokio::join!(a.wait(), b.wait());
    assert!(a.unwrap().success());
    assert!(b.unwrap().success());
    assert_eq!(server.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn cancelled_refresh_finishes_persistence() {
    let provider = SubscriptionProvider::Xai;
    let server = server(move |_| response(provider, "a")).await;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(provider, "a")).await.unwrap();
    let client = flow::TokenClient::local(provider, server.endpoint.clone());
    let worker_store = store.clone();
    let worker =
        tokio::spawn(async move { worker_store.access_with(provider, None, client).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while server.requests.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    worker.abort();
    let _ = worker.await;
    // Waiting on the same file lock observes the completed persistence, not an in-memory cache.
    let access = store
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, server.endpoint.clone()),
        )
        .await
        .unwrap();
    assert!(access.bearer().is_ok());
    assert_eq!(server.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn manual_code_uses_original_pkce_and_releases_listener() {
    let provider = SubscriptionProvider::Xai;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    let attempt = LoginAttempt::bind(provider, 0).await.unwrap();
    let released = attempt.listener_drop_probe();
    let at_exchange = Arc::new(Mutex::new(None));
    let (probe, seen) = (released.clone(), at_exchange.clone());
    let server = server(move |_| {
        *seen.lock().unwrap() = Some(probe.load(std::sync::atomic::Ordering::SeqCst));
        response(provider, "a")
    })
    .await;
    let attempt = attempt.with_endpoint(server.endpoint.clone());
    let (_, _, _, challenge) = attempt_parts(&attempt);
    attempt
        .finish_with_code_input(
            &store,
            CancellationToken::new(),
            Duration::from_secs(2),
            std::future::ready(Ok("fake-manual-code".into())),
        )
        .await
        .unwrap();
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["code"], "fake-manual-code");
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Sha256::digest(requests[0]["code_verifier"].as_bytes())),
        challenge
    );
    drop(requests);
    // Released before the token exchange began, not merely by the end.
    assert_eq!(*at_exchange.lock().unwrap(), Some(true));
    assert!(released.load(std::sync::atomic::Ordering::SeqCst));
}

#[cfg(unix)]
#[tokio::test]
async fn manual_tty_restores_echo_on_completion_and_cancellation() {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    for complete in [true, false] {
        let pty = nix::pty::openpty(None, None).unwrap();
        let mut master = std::fs::File::from(pty.master);
        let slave = std::fs::File::from(pty.slave);
        let monitor = slave.try_clone().unwrap();
        let fd = slave.as_raw_fd();
        // SAFETY: live test-owned terminal, flags are only changed on this descriptor.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            assert!(flags >= 0);
            assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
        }
        let termios = |file: &std::fs::File| {
            let mut value = std::mem::MaybeUninit::<libc::termios>::uninit();
            // SAFETY: live PTY; initialized on successful tcgetattr.
            unsafe {
                assert_eq!(libc::tcgetattr(file.as_raw_fd(), value.as_mut_ptr()), 0);
                value.assume_init()
            }
        };
        let original = termios(&monitor).c_lflag;
        let reader = tokio::spawn(super::manual::read_from(slave));
        tokio::time::timeout(Duration::from_secs(2), async {
            while termios(&monitor).c_lflag & libc::ECHO != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        if complete {
            master.write_all(b"fake-manual-code\n").unwrap();
            assert_eq!(reader.await.unwrap().unwrap(), "fake-manual-code");
        } else {
            reader.abort();
            let _ = reader.await;
        }
        assert_eq!(termios(&monitor).c_lflag, original);
    }
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires a real controlling terminal; run explicitly from the live-verification Terminal tab"]
async fn manual_controlling_terminal_registers_with_async_reader() {
    let file = super::manual::open_terminal().expect("open concrete controlling terminal");
    let reader =
        tokio::io::unix::AsyncFd::new(file).expect("register concrete terminal with async reader");
    drop(reader); // No terminal input is read and no echo settings change.
}

/// A raw HTTP responder. The axum helper above can only answer 200 with a complete body;
/// classifying a refresh failure needs non-success statuses and truncated replies.
struct RawServer {
    endpoint: String,
    hits: Arc<Mutex<usize>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for RawServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn raw_server(reply: &'static [u8]) -> RawServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    let hits = Arc::new(Mutex::new(0usize));
    let counter = hits.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                match stream.read_u8().await {
                    Ok(byte) => head.push(byte),
                    Err(_) => break,
                }
            }
            if !head.ends_with(b"\r\n\r\n") {
                continue; // Not a request; never counted as a delivered exchange.
            }
            let length = String::from_utf8_lossy(&head)
                .to_ascii_lowercase()
                .lines()
                .find_map(|line| line.strip_prefix("content-length:").map(str::to_owned))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; length];
            let _ = stream.read_exact(&mut body).await;
            *counter.lock().unwrap() += 1;
            let _ = stream.write_all(reply).await;
            let _ = stream.flush().await;
        }
    });
    RawServer {
        endpoint,
        hits,
        task,
    }
}
fn pending_on_disk(home: &Path, provider: SubscriptionProvider, account: &str) -> bool {
    let bytes = std::fs::read(home.join("subscriptions/credentials.json")).unwrap();
    let records: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    records[provider.name()]["accounts"][account]["refresh_pending"]
        .as_bool()
        .unwrap()
}
/// A loopback port that refuses connections and stays reserved while the socket is held.
/// Binding without listening makes connects fail with ECONNREFUSED, and unlike a dropped
/// listener the port cannot be handed to a concurrently running test meanwhile.
fn refusing_port() -> (tokio::net::TcpSocket, u16) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket
        .bind((std::net::Ipv4Addr::LOCALHOST, 0).into())
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    (socket, port)
}
/// Proves the credential can still refresh itself: a live provider is offered and taken.
async fn refresh_succeeds_next(store: &SubscriptionStore, provider: SubscriptionProvider) {
    let live = server(move |_| response(provider, "a")).await;
    let access = store
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, live.endpoint.clone()),
        )
        .await
        .expect("a cleared marker must let the credential refresh itself");
    assert!(access.bearer().is_ok());
    assert_eq!(live.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_refused_refresh_does_not_force_a_relogin() {
    let provider = SubscriptionProvider::Xai;
    for (reply, status) in [
        (
            &b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                [..],
            503u16,
        ),
        (
            &b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..],
            429,
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::new(temp.path());
        store.save(record(provider, "a")).await.unwrap();
        let refusing = raw_server(reply).await;
        let error = store
            .access_with(
                provider,
                None,
                flow::TokenClient::local(provider, refusing.endpoint.clone()),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, SubscriptionError::Http(code) if code == status));
        assert_eq!(*refusing.hits.lock().unwrap(), 1);
        // The provider refused before reading the token, so nothing was rotated.
        assert!(!pending_on_disk(temp.path(), provider, "a"));
        refresh_succeeds_next(&store, provider).await;
    }
}

#[tokio::test]
async fn an_undelivered_refresh_does_not_force_a_relogin() {
    let provider = SubscriptionProvider::Xai;
    // A refused connection stands in for the wifi blip: the request never reaches a provider.
    let (_held, port) = refusing_port();
    let endpoint = format!("http://127.0.0.1:{port}/token");
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(provider, "a")).await.unwrap();
    let error = store
        .access_with(provider, None, flow::TokenClient::local(provider, endpoint))
        .await
        .unwrap_err();
    assert!(matches!(error, SubscriptionError::Network));
    assert!(!pending_on_disk(temp.path(), provider, "a"));
    refresh_succeeds_next(&store, provider).await;
}

#[tokio::test]
async fn a_rejected_refresh_token_still_forces_a_relogin() {
    let provider = SubscriptionProvider::Xai;
    for (reply, status) in [
        (
            &b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..],
            401u16,
        ),
        (
            &b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..],
            400,
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::new(temp.path());
        store.save(record(provider, "a")).await.unwrap();
        let rejecting = raw_server(reply).await;
        let error = store
            .access_with(
                provider,
                None,
                flow::TokenClient::local(provider, rejecting.endpoint.clone()),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, SubscriptionError::Http(code) if code == status));
        assert!(pending_on_disk(temp.path(), provider, "a"));
        let live = server(move |_| response(provider, "a")).await;
        assert!(matches!(
            store
                .access_with(
                    provider,
                    None,
                    flow::TokenClient::local(provider, live.endpoint.clone())
                )
                .await,
            Err(SubscriptionError::LoginRequired)
        ));
        assert!(live.requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn a_reply_lost_after_success_forces_a_relogin() {
    let provider = SubscriptionProvider::Xai;
    // 200 with a body that stops short: the provider answered and may have rotated
    // the token, and we cannot know what it issued.
    let truncating = raw_server(
        &b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{\"acce"[..],
    )
    .await;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(provider, "a")).await.unwrap();
    let error = store
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, truncating.endpoint.clone()),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, SubscriptionError::AmbiguousExchange));
    assert!(!format!("{error:?} {error}").contains("fake-refresh"));
    assert!(pending_on_disk(temp.path(), provider, "a"));
    let live = server(move |_| response(provider, "a")).await;
    assert!(matches!(
        store
            .access_with(
                provider,
                None,
                flow::TokenClient::local(provider, live.endpoint.clone())
            )
            .await,
        Err(SubscriptionError::LoginRequired)
    ));
    assert!(live.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_pending_marker_is_persisted_before_the_exchange_is_attempted() {
    let provider = SubscriptionProvider::Xai;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(provider, "a")).await.unwrap();
    let home = temp.path().to_owned();
    let observed = Arc::new(Mutex::new(None));
    let seen = observed.clone();
    // Crash safety: a process death between these two points must not leave a possibly
    // rotated token reusable, so the marker has to already be on disk when we get here.
    let live = server(move |_| {
        *seen.lock().unwrap() = Some(pending_on_disk(&home, provider, "a"));
        response(provider, "a")
    })
    .await;
    store
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, live.endpoint.clone()),
        )
        .await
        .unwrap();
    assert_eq!(*observed.lock().unwrap(), Some(true));
    assert!(!pending_on_disk(temp.path(), provider, "a"));
}

#[test]
fn a_broken_ca_bundle_is_reported_as_local_tls_configuration_naming_the_file() {
    let error = flow::or_local_tls(
        Err::<(), _>(()),
        Some(("FUIGO_EXTRA_CA_BUNDLE", "/etc/fuigo/broken-ca.pem".into())),
    )
    .unwrap_err();
    assert!(matches!(error, SubscriptionError::LocalTls(_)));
    let text = error.to_string();
    assert!(text.contains("local TLS/CA configuration error"), "{text}");
    assert!(text.contains("/etc/fuigo/broken-ca.pem"), "{text}");
    assert!(text.contains("FUIGO_EXTRA_CA_BUNDLE"), "{text}");
    assert!(!text.contains("not sent to the provider"), "{text}");
    // Nothing was built, so nothing can have been sent or consumed.
    assert!(!error.may_have_consumed_refresh_token());

    // A path is echoed escaped, so it cannot carry terminal controls.
    let hostile = flow::or_local_tls(
        Err::<(), _>(()),
        Some(("SSL_CERT_FILE", "/tmp/a\u{1b}[2Jb.pem".into())),
    )
    .unwrap_err()
    .to_string();
    assert!(!hostile.contains('\u{1b}'), "{hostile:?}");
    assert!(hostile.contains("SSL_CERT_FILE"), "{hostile}");

    let unconfigured = flow::or_local_tls(Err::<(), _>(()), None).unwrap_err();
    assert!(matches!(unconfigured, SubscriptionError::LocalTls(_)));
    assert!(unconfigured.to_string().contains("trust store"));

    assert!(flow::or_local_tls(Ok::<_, ()>(7), None).is_ok_and(|n| n == 7));
}

/// A loopback HTTPS endpoint whose certificate chains to a CA nobody trusts.
async fn untrusted_tls_endpoint() -> (String, tokio::task::JoinHandle<()>) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .signed_by(&key, &ca, &ca_key)
        .unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone(), ca.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}/token", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let _ = acceptor.accept(stream).await;
        }
    });
    (endpoint, task)
}

#[tokio::test]
async fn a_certificate_rejected_under_a_configured_ca_bundle_is_a_local_tls_error() {
    use fuigo_extra_ca::dispatch::AsyncRequestBuilderExt;
    let (endpoint, task) = untrusted_tls_endpoint().await;
    let client =
        fuigo_extra_ca::build_reqwest_client(|b| b.timeout(Duration::from_secs(20))).unwrap();
    let error = client.post(&endpoint).send_checked().await.unwrap_err();
    let rejected = flow::transport_error(
        &error,
        Some(("FUIGO_EXTRA_CA_BUNDLE", "/etc/fuigo/corp-ca.pem".into())),
    );
    assert!(
        matches!(rejected, SubscriptionError::LocalTls(_)),
        "{rejected:?}"
    );
    let text = rejected.to_string();
    assert!(text.contains("/etc/fuigo/corp-ca.pem"), "{text}");
    assert!(text.contains("certificate did not verify"), "{text}");
    assert!(!text.contains("not sent to the provider"), "{text}");
    assert!(!rejected.may_have_consumed_refresh_token());
    // No bundle configured: never advise trusting another CA; it stays a network error.
    assert!(matches!(
        flow::transport_error(&error, None),
        SubscriptionError::Network
    ));
    task.abort();
    // A refused connection is not a certificate problem, bundle or not.
    let (_held, port) = refusing_port();
    let refused = format!("https://127.0.0.1:{port}/token");
    let error = client.post(&refused).send_checked().await.unwrap_err();
    assert!(matches!(
        flow::transport_error(
            &error,
            Some(("FUIGO_EXTRA_CA_BUNDLE", "/etc/fuigo/corp-ca.pem".into()))
        ),
        SubscriptionError::Network
    ));
}

#[test]
fn a_local_tls_error_is_not_reported_to_sampling_as_a_login_problem() {
    let tls = inference::sampling_error(SubscriptionError::LocalTls("detail".into())).to_string();
    assert!(tls.contains("TLS/CA configuration"), "{tls}");
    assert!(!tls.contains("fuigo login"), "{tls}");
    let login = inference::sampling_error(SubscriptionError::LoginRequired).to_string();
    assert!(login.contains("fuigo login"), "{login}");
}

#[tokio::test]
async fn a_refresh_rejected_under_a_configured_ca_bundle_names_it_and_keeps_the_session() {
    let provider = SubscriptionProvider::Xai;
    let (endpoint, task) = untrusted_tls_endpoint().await;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(provider, "a")).await.unwrap();
    let client = flow::TokenClient::local(provider, endpoint).with_ca_bundle(Some((
        "FUIGO_EXTRA_CA_BUNDLE",
        "/etc/fuigo/corp-ca.pem".into(),
    )));
    let error = store.access_with(provider, None, client).await.unwrap_err();
    task.abort();
    assert!(matches!(error, SubscriptionError::LocalTls(_)), "{error:?}");
    assert!(
        error.to_string().contains("/etc/fuigo/corp-ca.pem"),
        "{error}"
    );
    // The handshake failed before the request was written: the token was not consumed.
    assert!(!pending_on_disk(temp.path(), provider, "a"));
    refresh_succeeds_next(&store, provider).await;
}

#[tokio::test]
async fn a_connection_dropped_after_the_request_was_sent_forces_a_relogin() {
    let provider = SubscriptionProvider::Xai;
    // The provider reads the whole request (and may rotate the token), then the connection
    // dies before any response header: what it issued is unknown.
    let dropping = raw_server(b"").await;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    store.save(record(provider, "a")).await.unwrap();
    let error = store
        .access_with(
            provider,
            None,
            flow::TokenClient::local(provider, dropping.endpoint.clone()),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, SubscriptionError::AmbiguousExchange),
        "{error:?}"
    );
    assert_eq!(*dropping.hits.lock().unwrap(), 1);
    assert!(pending_on_disk(temp.path(), provider, "a"));
    let live = server(move |_| response(provider, "a")).await;
    assert!(matches!(
        store
            .access_with(
                provider,
                None,
                flow::TokenClient::local(provider, live.endpoint.clone())
            )
            .await,
        Err(SubscriptionError::LoginRequired)
    ));
    assert!(live.requests.lock().unwrap().is_empty());
}
