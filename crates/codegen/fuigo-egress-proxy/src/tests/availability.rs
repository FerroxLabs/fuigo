//! Availability of the proxy under slow transfers, silent peers, idle tunnels and accept errors
//! (audit S5-F14), and the `::1` listener (audit S5-F16).

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::server::{Acceptor, serve};

fn options(resolver: &Arc<MockResolver>, connector: &Arc<MockConnector>) -> EgressProxyOptions {
    EgressProxyOptions {
        resolver: resolver.clone(),
        connector: connector.clone(),
        ..Default::default()
    }
}

fn get(auth: &str) -> String {
    format!(
        "GET http://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\nProxy-Authorization: {auth}\r\n\r\n"
    )
}

/// A body that trickles for longer than `request_timeout` still arrives whole: the timeout is
/// per read, not for the transfer.
#[tokio::test]
async fn a_trickled_http_body_longer_than_the_timeout_arrives_whole() {
    let resolver = Arc::new(MockResolver::default());
    resolver.answer("allowed.example", vec![public_v4(80)]);
    let connector = Arc::new(MockConnector::default());
    let mut peer = connector.push();
    let mut opts = options(&resolver, &connector);
    opts.request_timeout = Duration::from_millis(400);
    let handle = EgressProxy::start(allow(&["http://allowed.example"]), opts)
        .await
        .unwrap();
    tokio::spawn(async move {
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0u8; 1024];
            let count = peer.read(&mut chunk).await.unwrap();
            request.extend_from_slice(&chunk[..count]);
        }
        peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n")
            .await
            .unwrap();
        for byte in b"abcdef" {
            tokio::time::sleep(Duration::from_millis(150)).await;
            peer.write_all(&[*byte]).await.unwrap();
        }
    });
    let response = send(
        handle.address(),
        get(&handle.proxy_authorization()).as_bytes(),
    )
    .await;
    assert_eq!(status(&response), 200);
    assert!(
        response.ends_with(b"abcdef"),
        "the whole body must arrive, got {:?}",
        String::from_utf8_lossy(&response)
    );
    handle.shutdown().await.unwrap();
}

/// Peers that connect and say nothing do not keep an authenticated request out once they are past
/// the grace period.
#[tokio::test]
async fn silent_connections_do_not_block_an_authenticated_request() {
    let resolver = Arc::new(MockResolver::default());
    resolver.answer("allowed.example", vec![public_v4(80)]);
    let connector = Arc::new(MockConnector::default());
    let mut peer = connector.push();
    let mut opts = options(&resolver, &connector);
    opts.max_connections = 4;
    opts.pre_auth_grace = Duration::from_millis(100);
    let handle = EgressProxy::start(allow(&["http://allowed.example"]), opts)
        .await
        .unwrap();
    let mut silent = Vec::new();
    for _ in 0..4 {
        silent.push(TcpStream::connect(handle.address()).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    tokio::spawn(async move {
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0u8; 1024];
            let count = peer.read(&mut chunk).await.unwrap();
            request.extend_from_slice(&chunk[..count]);
        }
        peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    });
    let response = send(
        handle.address(),
        get(&handle.proxy_authorization()).as_bytes(),
    )
    .await;
    assert_eq!(
        status(&response),
        200,
        "{:?}",
        String::from_utf8_lossy(&response)
    );
    drop(silent);
    handle.shutdown().await.unwrap();
}

/// A tunnel with no traffic either way is closed after the idle timeout.
#[tokio::test]
async fn an_idle_tunnel_is_closed() {
    let resolver = Arc::new(MockResolver::default());
    resolver.answer("allowed.example", vec![public_v4(443)]);
    let connector = Arc::new(MockConnector::default());
    let mut peer = connector.push();
    let mut opts = options(&resolver, &connector);
    opts.tunnel_idle_timeout = Duration::from_millis(300);
    let handle = EgressProxy::start(allow(&["https://allowed.example"]), opts)
        .await
        .unwrap();
    let mut stream = TcpStream::connect(handle.address()).await.unwrap();
    let request = format!(
        "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\nProxy-Authorization: {}\r\n\r\n",
        handle.proxy_authorization()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    read_response_head(&mut stream, &mut response).await;
    assert_eq!(status(&response), 200);
    let hello = test_client_hello(Some("allowed.example"));
    stream.write_all(&hello).await.unwrap();
    let mut received = vec![0; hello.len()];
    peer.read_exact(&mut received).await.unwrap();
    // `peer` stays open and silent: only the idle timeout can end the tunnel.
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
    assert!(ended.is_ok(), "the idle tunnel must be closed by the proxy");
    drop(peer);
    handle.shutdown().await.unwrap();
}

/// Fails the first accepts, then serves, like a transient `accept` error.
struct FlakyAcceptor {
    inner: tokio::net::TcpListener,
    failures: AtomicUsize,
}

#[async_trait]
impl Acceptor for FlakyAcceptor {
    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        if self
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            return Err(io::Error::other("injected accept failure"));
        }
        self.inner.accept().await
    }
}

#[tokio::test]
async fn an_accept_error_does_not_stop_the_server() {
    let inner = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = inner.local_addr().unwrap();
    let state = ProxyState::build(
        allow(&[]),
        Arc::new(PolicyOnly),
        EgressProxyOptions::default(),
    )
    .unwrap();
    let (_shutdown_tx, shutdown_rx) = mpsc::channel(1);
    let task = tokio::spawn(serve(
        FlakyAcceptor {
            inner,
            failures: AtomicUsize::new(2),
        },
        state,
        Arc::new(AtomicUsize::new(0)),
        shutdown_rx,
    ));
    let response = send(
        address,
        b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), 407);
    assert!(!task.is_finished(), "the serve loop must still be running");
    task.abort();
}

/// The sandbox rule names `localhost`, which is both loopback families; the proxy answers on
/// `::1` at its port too, so nothing else can sit there.
#[tokio::test]
async fn the_proxy_also_answers_on_ipv6_loopback() {
    let probe = tokio::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await;
    if probe.is_err() {
        return; // no IPv6 loopback on this host: the proxy serves IPv4 only, as it must
    }
    drop(probe);
    let fixture = Fixture::start(allow(&[])).await;
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), fixture.addr().port());
    let response = send(
        v6,
        b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;
    assert_eq!(
        status(&response),
        407,
        "the ::1 side reaches the same handler"
    );
    fixture.handle.shutdown().await.unwrap();
}

/// Writes to `peer` until a write fails (the proxy dropped its side), reporting that it ended.
fn flood_until_closed(mut peer: DuplexStream) -> JoinHandle<()> {
    tokio::spawn(async move {
        let chunk = vec![b'x'; 64 * 1024];
        while peer.write_all(&chunk).await.is_ok() {}
    })
}

/// Audit R02: a client that stops reading a response is dropped once no byte has reached it for
/// the request timeout, so it cannot hold a connection slot forever.
#[tokio::test]
async fn a_client_that_stops_reading_a_response_is_dropped() {
    let resolver = Arc::new(MockResolver::default());
    resolver.answer("allowed.example", vec![public_v4(80)]);
    let connector = Arc::new(MockConnector::default());
    let mut peer = connector.push();
    let mut opts = options(&resolver, &connector);
    opts.request_timeout = Duration::from_millis(300);
    let handle = EgressProxy::start(allow(&["http://allowed.example"]), opts)
        .await
        .unwrap();
    let mut stream = TcpStream::connect(handle.address()).await.unwrap();
    stream
        .write_all(get(&handle.proxy_authorization()).as_bytes())
        .await
        .unwrap();
    let mut request = Vec::new();
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let mut chunk = [0u8; 1024];
        let count = peer.read(&mut chunk).await.unwrap();
        request.extend_from_slice(&chunk[..count]);
    }
    peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1099511627776\r\n\r\n")
        .await
        .unwrap();
    // `stream` stays open and never reads: only a write deadline can end the response.
    let flood = flood_until_closed(peer);
    let ended = tokio::time::timeout(Duration::from_secs(10), flood).await;
    assert!(
        ended.is_ok(),
        "a stalled reader must not hold the connection open"
    );
    drop(stream);
    handle.shutdown().await.unwrap();
}

/// Audit R02: once the client has finished sending, a tunnel whose client stops reading is still
/// closed after the idle timeout instead of waiting on the write forever.
#[tokio::test]
async fn a_half_closed_tunnel_with_a_stalled_reader_is_closed() {
    let resolver = Arc::new(MockResolver::default());
    resolver.answer("allowed.example", vec![public_v4(443)]);
    let connector = Arc::new(MockConnector::default());
    let mut peer = connector.push();
    let mut opts = options(&resolver, &connector);
    opts.tunnel_idle_timeout = Duration::from_millis(300);
    let handle = EgressProxy::start(allow(&["https://allowed.example"]), opts)
        .await
        .unwrap();
    let mut stream = TcpStream::connect(handle.address()).await.unwrap();
    let request = format!(
        "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\nProxy-Authorization: {}\r\n\r\n",
        handle.proxy_authorization()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    read_response_head(&mut stream, &mut response).await;
    assert_eq!(status(&response), 200);
    let hello = test_client_hello(Some("allowed.example"));
    stream.write_all(&hello).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut received = Vec::new();
    peer.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, hello, "the client's half ends after the hello");
    // The client never reads: only a write deadline can end the remaining direction.
    let flood = flood_until_closed(peer);
    let ended = tokio::time::timeout(Duration::from_secs(10), flood).await;
    assert!(
        ended.is_ok(),
        "a stalled reader must not hold a half-closed tunnel open"
    );
    drop(stream);
    handle.shutdown().await.unwrap();
}

/// Audit L11: traffic in either direction keeps a tunnel open past the idle timeout; here the
/// client sends a keepalive byte well inside every idle window for several windows.
#[tokio::test]
async fn keepalives_keep_a_tunnel_open_past_the_idle_timeout() {
    let resolver = Arc::new(MockResolver::default());
    resolver.answer("allowed.example", vec![public_v4(443)]);
    let connector = Arc::new(MockConnector::default());
    let mut peer = connector.push();
    let mut opts = options(&resolver, &connector);
    opts.tunnel_idle_timeout = Duration::from_millis(300);
    let handle = EgressProxy::start(allow(&["https://allowed.example"]), opts)
        .await
        .unwrap();
    let mut stream = TcpStream::connect(handle.address()).await.unwrap();
    let request = format!(
        "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\nProxy-Authorization: {}\r\n\r\n",
        handle.proxy_authorization()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    read_response_head(&mut stream, &mut response).await;
    assert_eq!(status(&response), 200);
    let hello = test_client_hello(Some("allowed.example"));
    stream.write_all(&hello).await.unwrap();
    let mut received = vec![0; hello.len()];
    peer.read_exact(&mut received).await.unwrap();
    for _ in 0..12 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        stream.write_all(b"k").await.unwrap();
        let mut byte = [0u8; 1];
        peer.read_exact(&mut byte).await.unwrap();
    }
    peer.write_all(b"ok").await.unwrap();
    let mut reply = [0u8; 2];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut reply)).await;
    assert!(
        matches!(read, Ok(Ok(_))),
        "the kept-alive tunnel must still carry bytes"
    );
    assert_eq!(&reply, b"ok");
    handle.shutdown().await.unwrap();
}

/// Audit L12: when `::1` is taken at every port tried, the proxy still starts, on IPv4 loopback only.
#[tokio::test]
async fn an_occupied_ipv6_loopback_falls_back_to_ipv4_only() {
    let listeners = crate::server::bind_loopback_with(|_| async {
        Err::<tokio::net::TcpListener, _>(io::Error::from(io::ErrorKind::AddrInUse))
    })
    .await
    .expect("an occupied ::1 must not stop the proxy");
    assert!(!listeners.serves_ipv6());
    assert!(listeners.local_addr().unwrap().ip().is_loopback());
}

/// Audit L13: transfers keep one idle deadline per direction, renewed only when it fires, rather
/// than arming a fresh timer for every chunk read or written. A source guard: the defect is
/// per-chunk overhead, not behaviour a test can observe.
#[test]
fn transfers_do_not_arm_a_timer_per_chunk() {
    for (name, source, function) in [
        ("connect.rs", include_str!("../connect.rs"), "async fn pump"),
        ("http.rs", include_str!("../http.rs"), "async fn copy_exact"),
    ] {
        let start = source
            .find(function)
            .unwrap_or_else(|| panic!("{name}: {function} not found"));
        let end = start + source[start..].find("\n}\n").unwrap();
        let body = &source[start..end];
        assert!(
            !body.contains("time::timeout("),
            "{name}: {function} arms a timer per chunk"
        );
        assert!(
            !body.contains("write_all_idle"),
            "{name}: {function} arms a timer per write"
        );
    }
}

/// Neither reads nor takes a byte: a peer that has stopped reading with its buffers full.
struct StalledIo;

impl AsyncRead for StalledIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for StalledIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

/// Delta review (egress proxy): the request head written to an upstream that takes no bytes is bounded by the
/// request timeout; the client gets an answer instead of a connection held forever.
#[tokio::test]
async fn a_request_head_to_a_stalled_upstream_is_bounded() {
    let resolver = Arc::new(MockResolver::default());
    resolver.answer("allowed.example", vec![public_v4(80)]);
    let connector = Arc::new(MockConnector::default());
    connector.push_io(StalledIo);
    let mut opts = options(&resolver, &connector);
    opts.request_timeout = Duration::from_millis(300);
    let handle = EgressProxy::start(allow(&["http://allowed.example"]), opts)
        .await
        .unwrap();
    let mut stream = TcpStream::connect(handle.address()).await.unwrap();
    stream
        .write_all(get(&handle.proxy_authorization()).as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    let answered =
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response)).await;
    assert!(
        answered.is_ok(),
        "a stalled upstream must not hold the connection open"
    );
    handle.shutdown().await.unwrap();
}

/// Delta review (egress proxy): the TLS hello forwarded to an upstream that takes no bytes is bounded too.
#[tokio::test]
async fn a_tls_hello_to_a_stalled_upstream_is_bounded() {
    let resolver = Arc::new(MockResolver::default());
    resolver.answer("allowed.example", vec![public_v4(443)]);
    let connector = Arc::new(MockConnector::default());
    connector.push_io(StalledIo);
    let mut opts = options(&resolver, &connector);
    opts.request_timeout = Duration::from_millis(300);
    opts.tunnel_idle_timeout = Duration::from_millis(300);
    let handle = EgressProxy::start(allow(&["https://allowed.example"]), opts)
        .await
        .unwrap();
    let mut stream = TcpStream::connect(handle.address()).await.unwrap();
    let request = format!(
        "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\nProxy-Authorization: {}\r\n\r\n",
        handle.proxy_authorization()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    read_response_head(&mut stream, &mut response).await;
    assert_eq!(status(&response), 200);
    stream
        .write_all(&test_client_hello(Some("allowed.example")))
        .await
        .unwrap();
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut rest)).await;
    assert!(
        ended.is_ok(),
        "a stalled upstream must not hold the tunnel open"
    );
    handle.shutdown().await.unwrap();
}

/// Delta review (egress proxy): an error answer to a client that takes no bytes is bounded by the deadline it is given.
#[tokio::test]
async fn an_error_answer_to_a_stalled_client_is_bounded() {
    let written = tokio::time::timeout(
        Duration::from_secs(10),
        crate::error::write_error(
            &mut StalledIo,
            &crate::error::ProxyError::Overloaded,
            Duration::from_millis(100),
        ),
    )
    .await;
    assert!(
        matches!(written, Ok(Err(_))),
        "the write must fail at its deadline: {written:?}"
    );
}
