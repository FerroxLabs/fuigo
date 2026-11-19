//! Delta review D2-03 / D2-07: the signed-URL proxy decision is the HTTP library's own (the same variables, uppercase
//! before lowercase even when empty, unusable schemes ignored, its own `NO_PROXY` rules), and the local address check
//! and the client choice both follow it. Each case runs in a child process whose proxy environment is exactly the
//! case's, so the runner's own proxy settings can neither pass nor fail these tests; the dial tests have positive
//! controls proving which endpoint was reached.

#![allow(
    clippy::disallowed_methods,
    reason = "test clients hit localhost mocks"
)]

use super::{LOOKUP_OVERRIDE, LOOKUPS, StorageClient, check_signed_url, check_signed_urls};
use std::io::Read as _;
use std::time::Duration;
use tokio::io::AsyncReadExt as _;

const PROXY_VARS: [&str; 9] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "REQUEST_METHOD",
];
const CHILD_CASE: &str = "FUIGO_STORAGE_PROXY_TEST_CASE";
const SIGNED: &str = "https://objects.example.com/o?sig=1";
const BASE: &str = "https://proxy.example/v1";
const PRIVATE_PROXY: &str = "http://10.0.0.5:3128";

/// In a child: the index of the case it runs. In the parent: runs `test` once per entry of `cases`, each in a child
/// process whose proxy environment is exactly that entry (every other proxy variable removed), and returns `None`.
fn case_in_child(test: &str, cases: &[Vec<(&str, String)>]) -> Option<usize> {
    if let Ok(case) = std::env::var(CHILD_CASE) {
        return Some(case.parse().expect("case index"));
    }
    let module = module_path!()
        .split_once("::")
        .map_or(module_path!(), |(_, rest)| rest);
    let name = format!("{module}::{test}");
    for (index, vars) in cases.iter().enumerate() {
        let mut command =
            std::process::Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["--exact", &name, "--nocapture", "--test-threads=1"])
            .env(CHILD_CASE, index.to_string());
        for var in PROXY_VARS {
            command.env_remove(var);
        }
        for (key, value) in vars {
            command.env(key, value);
        }
        // Captured, not inherited: the child's own `test result:` line must not reach the parent's log.
        let output = command
            .stdin(std::process::Stdio::null())
            .output()
            .expect("run the child test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{test} case {index} {vars:?} failed\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains("1 passed"),
            "the filter must run {name}: {stdout}"
        );
    }
    None
}

fn vars(pairs: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    pairs
        .iter()
        .map(|(key, value)| (*key, (*value).to_owned()))
        .collect()
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

/// Each environment, and whether the HTTP library sends an https request to `objects.example.com` through a proxy.
fn https_cases() -> Vec<(Vec<(&'static str, String)>, bool)> {
    let p = PRIVATE_PROXY;
    let mut cases = vec![
        (vars(&[]), false),
        (vars(&[("HTTPS_PROXY", p)]), true),
        (vars(&[("https_proxy", p)]), true),
        (vars(&[("ALL_PROXY", p)]), true),
        (vars(&[("all_proxy", p)]), true),
        (vars(&[("HTTP_PROXY", p)]), false),
        (
            vars(&[("HTTPS_PROXY", p), ("NO_PROXY", "example.com")]),
            false,
        ),
        (
            vars(&[("HTTPS_PROXY", p), ("no_proxy", ".EXAMPLE.com")]),
            false,
        ),
        (vars(&[("HTTPS_PROXY", p), ("NO_PROXY", "*")]), false),
        // `*.domain` is not a pattern the library knows: still proxied.
        (
            vars(&[("HTTPS_PROXY", p), ("NO_PROXY", "*.example.com")]),
            true,
        ),
        (
            vars(&[
                ("HTTPS_PROXY", p),
                ("NO_PROXY", "other.example,tore.example"),
            ]),
            true,
        ),
        // A scheme the library cannot use is ignored: no proxy.
        (vars(&[("HTTPS_PROXY", "ftp://10.0.0.5:21")]), false),
        // A value the library cannot parse as a proxy is no proxy (Grok u45 round 2).
        (vars(&[("HTTPS_PROXY", "http://")]), false),
        // Under CGI (`REQUEST_METHOD` set) the library ignores every proxy variable (Grok u45 round 2).
        (
            vars(&[("HTTPS_PROXY", p), ("REQUEST_METHOD", "GET")]),
            false,
        ),
    ];
    // Environment names are case-sensitive on unix only; on Windows `HTTPS_PROXY` and `https_proxy` are one variable.
    #[cfg(unix)]
    cases.extend([
        // An empty uppercase variable wins over a set lowercase one: no proxy.
        (vars(&[("HTTPS_PROXY", ""), ("https_proxy", p)]), false),
        // An empty uppercase NO_PROXY wins over a lowercase list: still proxied.
        (
            vars(&[
                ("HTTPS_PROXY", p),
                ("NO_PROXY", ""),
                ("no_proxy", "objects.example.com"),
            ]),
            true,
        ),
    ]);
    cases
}

/// The local lookup is skipped exactly when the library will hand the request to a proxy (which resolves the host).
#[test]
fn the_local_address_check_follows_the_proxy_the_http_library_selects() {
    let cases = https_cases();
    let envs: Vec<_> = cases.iter().map(|(env, _)| env.clone()).collect();
    let Some(case) = case_in_child(
        "the_local_address_check_follows_the_proxy_the_http_library_selects",
        &envs,
    ) else {
        return;
    };
    let (env, proxied) = &cases[case];
    LOOKUP_OVERRIDE.with(|o| *o.borrow_mut() = Some(vec!["8.8.8.8".parse().unwrap()]));
    let result = block_on(check_signed_url(SIGNED, BASE));
    assert!(result.is_ok(), "{env:?}: {result:?}");
    let lookups = LOOKUPS.with(std::cell::Cell::get);
    assert_eq!(lookups, usize::from(!proxied), "{env:?}: proxied={proxied}");
}

/// Delta review D3-03: the proxy decision is made on the URL as the library normalizes it. A signed URL whose host
/// carries a percent-encoded character is the same host after normalization, so it is proxied (no local lookup)
/// exactly when the plain spelling is.
#[test]
fn the_proxy_decision_uses_the_normalized_url() {
    let cases = vec![vars(&[("HTTPS_PROXY", PRIVATE_PROXY)]), vars(&[])];
    let Some(case) = case_in_child("the_proxy_decision_uses_the_normalized_url", &cases) else {
        return;
    };
    let proxied = case == 0;
    LOOKUP_OVERRIDE.with(|o| *o.borrow_mut() = Some(vec!["8.8.8.8".parse().unwrap()]));
    let encoded = "https://obj%65cts.example.com/o?sig=1";
    let result = block_on(check_signed_url(encoded, BASE));
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        LOOKUPS.with(std::cell::Cell::get),
        usize::from(!proxied),
        "proxied={proxied}"
    );
}

/// Accept one connection already queued on `listener` (non-blocking) and return the start of what was sent on it.
fn queued_request_head(listener: &std::net::TcpListener) -> Option<String> {
    let (mut stream, _) = listener.accept().ok()?;
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).unwrap_or(0);
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// A private corporate proxy the library selects is dialled (positive control), including the precedence and
/// `NO_PROXY` cases the earlier helper misread; one the library does not select is not. The proxy is named
/// `localhost`, a private name the address-checked client would refuse to dial.
#[test]
fn a_private_https_proxy_the_http_library_selects_is_dialled() {
    if std::env::var(CHILD_CASE).is_ok() {
        block_on(async {
            let client = StorageClient::new(BASE, "t").client_for_signed_url(SIGNED);
            let _ = tokio::time::timeout(Duration::from_secs(3), client.get(SIGNED).send()).await;
        });
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let proxy = format!("http://localhost:{}", listener.local_addr().unwrap().port());
    let p = proxy.as_str();
    let mut dial_cases = vec![
        (vars(&[("HTTPS_PROXY", p)]), true),
        (
            vars(&[("HTTPS_PROXY", p), ("NO_PROXY", "*.example.com")]),
            true,
        ),
        (
            vars(&[("https_proxy", p), ("NO_PROXY", "example.com")]),
            false,
        ),
    ];
    // Case-sensitive environment names: unix only (one variable each on Windows).
    #[cfg(unix)]
    dial_cases.extend([
        (
            vars(&[
                ("HTTPS_PROXY", p),
                ("NO_PROXY", ""),
                ("no_proxy", "objects.example.com"),
            ]),
            true,
        ),
        (vars(&[("HTTPS_PROXY", ""), ("https_proxy", p)]), false),
    ]);
    for (env, dialled) in dial_cases {
        // The child's connection waits in the listen queue; it is read once the child has finished.
        let _ = case_in_child(
            "a_private_https_proxy_the_http_library_selects_is_dialled",
            std::slice::from_ref(&env),
        );
        let head = queued_request_head(&listener);
        if dialled {
            let head = head.unwrap_or_else(|| panic!("{env:?}: the proxy was not dialled"));
            assert!(
                head.starts_with("CONNECT objects.example.com:443"),
                "{env:?}: {head:?}"
            );
        } else {
            assert!(
                head.is_none(),
                "{env:?}: the proxy was dialled although the library connects directly: {head:?}"
            );
        }
    }
}

/// Whether a request from `client` to `url` reaches `listener`.
async fn dials(client: &reqwest::Client, listener: &tokio::net::TcpListener, url: &str) -> bool {
    let request = tokio::time::timeout(Duration::from_secs(2), client.get(url).send());
    let accepted = tokio::time::timeout(Duration::from_secs(2), listener.accept());
    let (_, accepted) = tokio::join!(request, accepted);
    matches!(accepted, Ok(Ok(_)))
}

/// Review L20: the connection to a signed-URL host is judged on the address it dials, so a name that answered public
/// at the check and private at the connection (DNS rebinding) is not connected to. `localhost` stands for that name;
/// the configured client reaching the same listener over the same scheme and host is the positive control.
#[test]
fn signed_url_connections_refuse_a_private_address() {
    if case_in_child(
        "signed_url_connections_refuse_a_private_address",
        &[vars(&[])],
    )
    .is_none()
    {
        return;
    }
    block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "https://localhost:{}/o",
            listener.local_addr().unwrap().port()
        );
        let storage = StorageClient::new(BASE, "t");
        assert!(
            dials(&storage.raw_http_client, &listener, &url).await,
            "positive control: the listener is reachable"
        );
        let checked = storage.client_for_signed_url(SIGNED);
        assert!(
            !dials(&checked, &listener, &url).await,
            "the client connected to a private address"
        );
    });
}

/// A signed URL on a loopback proxy's own loopback host keeps the client it always had.
#[test]
fn loopback_signed_urls_keep_the_configured_client() {
    if case_in_child(
        "loopback_signed_urls_keep_the_configured_client",
        &[vars(&[])],
    )
    .is_none()
    {
        return;
    }
    block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://127.0.0.1:{}/o?sig=1",
            listener.local_addr().unwrap().port()
        );
        let client = StorageClient::new("http://127.0.0.1:9/v1", "t").client_for_signed_url(&url);
        assert!(
            dials(&client, &listener, &url).await,
            "the loopback test path must still connect"
        );
    });
}

/// Review L20: a multipart upload looks each host up once, not once per part.
#[test]
fn signed_url_checks_look_each_host_up_once() {
    if case_in_child("signed_url_checks_look_each_host_up_once", &[vars(&[])]).is_none() {
        return;
    }
    LOOKUP_OVERRIDE.with(|o| *o.borrow_mut() = Some(vec!["8.8.8.8".parse().unwrap()]));
    LOOKUPS.with(|n| n.set(0));
    let mut urls: Vec<String> = (0..5)
        .map(|i| format!("https://objects.example.com/p?n={i}"))
        .collect();
    urls.extend((0..2).map(|i| format!("https://other.example.org/x?n={i}")));
    let result = block_on(check_signed_urls(&urls, BASE));
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        LOOKUPS.with(std::cell::Cell::get),
        2,
        "one lookup per host, not per part"
    );
}

/// Fable delta-2 Low 5: the address-checked signed-URL client sends the same User-Agent as the configured upload
/// client. An IP literal is dialled without a lookup, so the checked client reaches the local listener.
#[test]
fn the_checked_signed_url_client_sends_the_upload_user_agent() {
    if case_in_child(
        "the_checked_signed_url_client_sends_the_upload_user_agent",
        &[vars(&[])],
    )
    .is_none()
    {
        return;
    }
    super::set_signed_url_user_agent("fuigo-test-agent/1.0");
    block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://127.0.0.1:{}/",
            listener.local_addr().unwrap().port()
        );
        let client = StorageClient::new(BASE, "t").client_for_signed_url(SIGNED);
        let request = tokio::time::timeout(Duration::from_secs(2), client.get(&url).send());
        let head = tokio::time::timeout(Duration::from_secs(2), async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let n = stream.read(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase()
        });
        let (_, head) = tokio::join!(request, head);
        let head = head.expect("the checked client connected");
        assert!(head.contains("user-agent: fuigo-test-agent/1.0"), "{head}");
    });
}
