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
async fn callback(port: u16, path: &str, state: &str) {
    let mut socket = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    socket
        .write_all(
            format!("GET {path}?code=fake-code&state={state} HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut output = Vec::new();
    socket.read_to_end(&mut output).await.unwrap();
}

#[tokio::test]
async fn callback_state_rejected_before_exchange_and_storage() {
    let provider = SubscriptionProvider::Chatgpt;
    let server = server(move |_| response(provider, "a")).await;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    let attempt = LoginAttempt::bind(provider, 0)
        .await
        .unwrap()
        .with_endpoint(server.endpoint.clone());
    let (port, path, _, _) = attempt_parts(&attempt);
    let (result, _) = tokio::join!(
        attempt.finish(&store, CancellationToken::new()),
        callback(port, &path, "wrong-state")
    );
    assert!(matches!(result, Err(SubscriptionError::Callback)));
    assert!(server.requests.lock().unwrap().is_empty());
    assert!(!temp.path().join("subscriptions/credentials.json").exists());
    assert!(
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn pkce_exchange_uses_attempt_verifier_and_saves_binding() {
    for provider in [SubscriptionProvider::Chatgpt, SubscriptionProvider::Xai] {
        let server = server(move |_| response(provider, "a")).await;
        let temp = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::new(temp.path());
        let attempt = LoginAttempt::bind(provider, 0)
            .await
            .unwrap()
            .with_endpoint(server.endpoint.clone());
        let (port, path, state, challenge) = attempt_parts(&attempt);
        let (result, _) = tokio::join!(
            attempt.finish(&store, CancellationToken::new()),
            callback(port, &path, &state)
        );
        result.unwrap();
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
        assert!(
            TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .is_ok()
        );
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
        let (port, _, _, _) = attempt_parts(&attempt);
        let cancel = CancellationToken::new();
        if cancel_first {
            cancel.cancel();
        }
        let result = attempt
            .finish_with_timeout(&store, cancel, Duration::from_millis(10))
            .await;
        assert!(matches!(
            result,
            Err(SubscriptionError::Cancelled | SubscriptionError::Timeout)
        ));
        assert!(
            TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .is_ok()
        );
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
        assert!(matches!(
            result,
            Err(SubscriptionError::Storage | SubscriptionError::InvalidCredentials)
        ));
        assert_eq!(server.requests.lock().unwrap().len(), 1);
    }
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
    let server = server(move |_| response(provider, "a")).await;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::new(temp.path());
    let attempt = LoginAttempt::bind(provider, 0)
        .await
        .unwrap()
        .with_endpoint(server.endpoint.clone());
    let (port, _, _, challenge) = attempt_parts(&attempt);
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
    assert!(
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
    );
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
