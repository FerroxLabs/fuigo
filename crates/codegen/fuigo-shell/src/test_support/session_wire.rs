//! P42 wire harness: what `Authorization` header actually reaches a destination.
//!
//! One loopback listener plays every destination a test needs:
//! * an HTTP forward proxy (`HTTP_PROXY` / `HTTPS_PROXY` point at it), so an `http://` request to a
//!   non-loopback host arrives here in absolute form, headers in the clear;
//! * a TLS-terminating tunnel for `CONNECT`, presenting a leaf for [`CONFIGURED_HOST`] signed by a
//!   throwaway CA that the process trusts through `FUIGO_EXTRA_CA_BUNDLE`, so an `https://` request to
//!   the configured origin (any port) is decrypted and recorded;
//! * a plain origin server, for a loopback URL aimed at the listener itself.
//!
//! Every request is answered `401`, and every request is recorded with its target and its
//! `Authorization` value. Nothing leaves the machine: proxied hosts are never resolved locally.
//!
//! The proxy and CA variables latch process-wide when the first HTTP client is built, so a test using
//! this harness must run in its own process (`fuigo_test_support::env::fresh_process_home`) and call
//! [`SessionWire::start`] before anything builds a client.

use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

/// Host of the configured origin the suite's fixture trust set contains (`https://api.fluxrouter.ai/v1`).
pub(crate) const CONFIGURED_HOST: &str = "api.fluxrouter.ai";

/// P47: a second host the front terminates TLS for: a service origin that is NOT FluxRouter-operated, for tests that
/// need a configured https service base where identity must be withheld (P43) but the session token may go (P47).
pub(crate) const SERVICE_HOST: &str = "service.example.test";

/// One request as the destination saw it.
#[derive(Clone, Debug)]
pub(crate) struct Observed {
    /// `https://host:port/path` for a tunnelled request, otherwise the request-line target.
    pub(crate) target: String,
    pub(crate) authorization: Option<String>,
}

pub(crate) struct SessionWire {
    pub(crate) port: u16,
    rx: mpsc::UnboundedReceiver<Observed>,
    _ca_dir: tempfile::TempDir,
}

impl SessionWire {
    /// Bind the listener, generate the CA, and point this process's proxy and CA variables at them.
    pub(crate) async fn start() -> Self {
        let (acceptor, ca_dir, ca_path) = tls_acceptor_and_ca();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let proxy = format!("http://127.0.0.1:{port}");
        // SAFETY: the caller runs alone in a fresh process, before any HTTP client exists.
        unsafe {
            for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"] {
                std::env::set_var(key, &proxy);
            }
            for key in ["NO_PROXY", "no_proxy", "FUIGO_API_KEY", "FUIGO_CODE_API_KEY", "SSL_CERT_FILE"] {
                std::env::remove_var(key);
            }
            std::env::set_var("FUIGO_EXTRA_CA_BUNDLE", &ca_path);
        }

        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _ = serve(socket, acceptor, tx).await;
                });
            }
        });
        Self {
            port,
            rx,
            _ca_dir: ca_dir,
        }
    }

    /// A loopback URL served by this listener and absent from every trust set.
    pub(crate) fn loopback_url(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port)
    }

    /// Everything recorded so far, after giving in-flight requests a moment to land.
    pub(crate) async fn observed(&mut self) -> Vec<Observed> {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let mut out = Vec::new();
        while let Ok(o) = self.rx.try_recv() {
            out.push(o);
        }
        out
    }
}

/// Whether any recorded request carried `token` in its `Authorization` header.
pub(crate) fn token_arrived(seen: &[Observed], token: &str) -> bool {
    seen.iter().any(|o| {
        o.authorization
            .as_deref()
            .is_some_and(|value| value.contains(token))
    })
}

async fn serve(
    mut socket: tokio::net::TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    tx: mpsc::UnboundedSender<Observed>,
) -> std::io::Result<()> {
    let (line, headers) = read_request(&mut socket).await?;
    if let Some(authority) = line
        .strip_prefix("CONNECT ")
        .and_then(|rest| rest.split_whitespace().next())
    {
        let authority = authority.to_string();
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let mut tls = acceptor.accept(socket).await?;
        let (inner_line, inner_headers) = read_request(&mut tls).await?;
        let path = inner_line.split_whitespace().nth(1).unwrap_or("").to_string();
        let _ = tx.send(Observed {
            target: format!("https://{authority}{path}"),
            authorization: header(&inner_headers, "authorization"),
        });
        respond(&mut tls).await
    } else {
        let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
        let _ = tx.send(Observed {
            target,
            authorization: header(&headers, "authorization"),
        });
        respond(&mut socket).await
    }
}

fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

async fn respond<S: AsyncWrite + Unpin>(stream: &mut S) -> std::io::Result<()> {
    let body = br#"{"error":{"message":"p42 wire harness","type":"invalid_request_error"}}"#;
    let head = format!(
        "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Read one request head (and its `Content-Length` body, discarded).
async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<(String, Vec<(String, String)>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let line = lines.next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let content_length = header(&headers, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut have = buf.len() - head_end;
    while have < content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        have += n;
    }
    Ok((line, headers))
}

/// A configured-origin FRONT for an existing mock server (P42 rework).
///
/// Since P42 an `http://` or loopback URL never receives the session token, so a session-auth test can no
/// longer aim its mock server's `http://127.0.0.1:PORT` directly. The front makes the mock reachable as the
/// configured origin `https://api.fluxrouter.ai/v1`: `HTTPS_PROXY` points at it, a `CONNECT` to
/// [`CONFIGURED_HOST`] is TLS-terminated with a throwaway CA (`FUIGO_EXTRA_CA_BUNDLE`) and the decrypted bytes
/// are forwarded unchanged to the current backend. `NO_PROXY` keeps loopback direct, so the test's own calls to
/// the mock are untouched. The request really is an `https` request to the configured origin, decided by the
/// production predicate; nothing about the trust set is overridden.
///
/// Same latching rule as [`SessionWire`]: start it first, in a fresh process.
pub(crate) struct SessionFront {
    backend: Arc<std::sync::Mutex<Option<String>>>,
    /// Bumped when the route changes; every open tunnel closes on a bump, so the client's pooled
    /// connections to the previous backend die and the next request opens a tunnel to the new one.
    route_generation: tokio::sync::watch::Sender<u64>,
    _ca_dir: tempfile::TempDir,
}

impl SessionFront {
    /// Synchronous: call it FIRST in the fresh process, before anything builds an HTTP client or loads the
    /// TLS roots (both latch on first use; a front started later is not trusted and the handshake aborts).
    pub(crate) fn start() -> Self {
        let (acceptor, ca_dir, ca_path) = tls_acceptor_and_ca();
        let backend: Arc<std::sync::Mutex<Option<String>>> = Arc::default();
        // The front runs on its OWN thread and runtime, so it serves regardless of how the caller's runtime is
        // driven. Callers must use a real clock: a paused tokio clock auto-advances whenever its runtime waits on
        // socket I/O, so any timeout would fire mid-handshake.
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let proxy = format!("http://{}", std_listener.local_addr().unwrap());
        let route = backend.clone();
        let (route_generation, generation_rx) = tokio::sync::watch::channel(0u64);
        std::thread::Builder::new()
            .name("p42-session-front".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("front runtime");
                rt.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
                    while let Ok((socket, _)) = listener.accept().await {
                        let acceptor = acceptor.clone();
                        let route = route.clone();
                        let rerouted = generation_rx.clone();
                        tokio::spawn(async move {
                            let _ = forward(socket, acceptor, route, rerouted).await;
                        });
                    }
                });
            })
            .expect("front thread");
        // SAFETY: the caller runs alone in a fresh process, before any HTTP client exists.
        unsafe {
            for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
                std::env::set_var(key, &proxy);
            }
            std::env::remove_var("ALL_PROXY");
            for key in ["NO_PROXY", "no_proxy"] {
                std::env::set_var(key, "127.0.0.1,localhost,::1");
            }
            std::env::remove_var("SSL_CERT_FILE");
            std::env::set_var("FUIGO_EXTRA_CA_BUNDLE", &ca_path);
        }
        Self {
            backend,
            route_generation,
            _ca_dir: ca_dir,
        }
    }

    /// Route the configured origin to `backend_url` (e.g. `MockInferenceServer::url()`) and return the
    /// configured-origin spelling of the same URL (`https://api.fluxrouter.ai/<path>`).
    pub(crate) fn front(&self, backend_url: &str) -> String {
        let parsed = url::Url::parse(backend_url).expect("backend url");
        let addr = format!(
            "{}:{}",
            parsed.host_str().expect("backend host"),
            parsed.port_or_known_default().expect("backend port")
        );
        let changed = {
            let mut current = self.backend.lock().unwrap();
            let changed = current.as_deref().is_some_and(|c| c != addr);
            *current = Some(addr);
            changed
        };
        if changed {
            self.route_generation.send_modify(|g| *g += 1);
        }
        format!("https://{CONFIGURED_HOST}{}", parsed.path().trim_end_matches('/'))
    }

    /// [`Self::front`], spelled as the non-FluxRouter service origin [`SERVICE_HOST`].
    pub(crate) fn front_service(&self, backend_url: &str) -> String {
        self.front(backend_url)
            .replacen(CONFIGURED_HOST, SERVICE_HOST, 1)
    }
}

fn tls_acceptor_and_ca() -> (tokio_rustls::TlsAcceptor, tempfile::TempDir, std::path::PathBuf) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![CONFIGURED_HOST.to_string(), SERVICE_HOST.to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca, &ca_key)
        .unwrap();
    let ca_dir = tempfile::tempdir().unwrap();
    let ca_path = ca_dir.path().join("ca.pem");
    std::fs::write(&ca_path, ca.pem()).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone(), ca.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    (tokio_rustls::TlsAcceptor::from(Arc::new(tls)), ca_dir, ca_path)
}

async fn forward(
    mut socket: tokio::net::TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    route: Arc<std::sync::Mutex<Option<String>>>,
    mut rerouted: tokio::sync::watch::Receiver<u64>,
) -> std::io::Result<()> {
    rerouted.borrow_and_update();
    let (line, _headers) = read_request(&mut socket).await?;
    let is_configured = line
        .strip_prefix("CONNECT ")
        .and_then(|rest| rest.split_whitespace().next())
        .is_some_and(|authority| {
            [CONFIGURED_HOST, SERVICE_HOST]
                .iter()
                .any(|host| authority == format!("{host}:443") || authority == *host)
        });
    if !is_configured {
        socket
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(());
    }
    let Some(backend) = route.lock().unwrap().clone() else {
        return Ok(());
    };
    socket
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let mut tls = acceptor.accept(socket).await?;
    let mut upstream = tokio::net::TcpStream::connect(backend).await?;
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream) => {}
        // Re-routed: close this tunnel so a pooled connection cannot reach the old backend.
        _ = rerouted.changed() => {}
    }
    Ok(())
}

/// P47: run the calling test alone in a fresh process behind a [`SessionFront`] (started first, as it must be).
/// `None` in the parent, which simply returns; the child runs the test with the front up. For fixtures whose
/// session-token service client (P47's service-endpoint trust class) may no longer reach a cleartext loopback mock:
/// `front.front(mock_url)` gives the mock's configured-origin spelling.
pub(crate) fn fronted_child(test_path: &str) -> Option<SessionFront> {
    fuigo_test_support::env::fresh_process_home(test_path)?;
    Some(SessionFront::start())
}
