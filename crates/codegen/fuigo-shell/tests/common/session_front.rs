//! A configured-origin front for a loopback mock, for integration tests that need a session-auth fetch to
//! reach the mock (P65).
//!
//! Since P42 the session token goes only to a configured `https` origin, never to `http://` or loopback
//! (`auth::session_delivery::session_may_reach`). A test that points `[endpoints]` straight at
//! `MockInferenceServer`'s `http://127.0.0.1:PORT/v1` therefore sees the session-auth `/v1/models` fetch refused
//! before it leaves the process. The front makes the mock reachable as `https://api.fluxrouter.ai/v1` instead:
//! `HTTPS_PROXY` points at it, a `CONNECT` to that host is TLS-terminated with a throwaway CA trusted through
//! `FUIGO_EXTRA_CA_BUNDLE`, and the decrypted bytes are forwarded unchanged to the mock. `NO_PROXY` keeps loopback
//! direct. The request really is an `https` request to a configured origin, decided by the production predicate;
//! nothing about the trust set is overridden.
//!
//! This is the non-`cfg(test)` twin of `fuigo_shell`'s `test_support::session_wire::SessionFront` (that module is
//! compiled only into the crate's own unit-test binary).
//!
//! The proxy and CA variables latch when the first HTTP client is built (and the CA when TLS roots first load),
//! so [`SessionFront::start`] must run before anything does either. It sets process environment variables while
//! other threads may exist (the test's runtime, the mock server's workers); that is sound only because none of
//! them reads the environment, and because the binary runs no other test that does (the shared
//! `common::leader` unit tests do not).
#![allow(dead_code)]

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The configured origin the front impersonates.
pub const CONFIGURED_HOST: &str = "api.fluxrouter.ai";

pub struct SessionFront {
    configured_url: String,
    _ca_dir: tempfile::TempDir,
}

impl SessionFront {
    /// Start the front for `backend_url` (e.g. `MockInferenceServer::url()`) on its own thread and runtime, and
    /// point this process's proxy and CA variables at it.
    pub fn start(backend_url: &str) -> Self {
        fuigo_extra_ca::ensure_default_crypto_provider();
        let (acceptor, ca_dir, ca_path) = tls_acceptor_and_ca();
        let parsed = url::Url::parse(backend_url).expect("backend url");
        let backend = format!(
            "{}:{}",
            parsed.host_str().expect("backend host"),
            parsed.port_or_known_default().expect("backend port")
        );
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind front");
        std_listener
            .set_nonblocking(true)
            .expect("nonblocking front");
        let proxy = format!("http://{}", std_listener.local_addr().expect("front addr"));
        std::thread::Builder::new()
            .name("p65-session-front".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("front runtime");
                rt.block_on(async move {
                    let listener =
                        tokio::net::TcpListener::from_std(std_listener).expect("front listener");
                    while let Ok((socket, _)) = listener.accept().await {
                        let acceptor = acceptor.clone();
                        let backend = backend.clone();
                        tokio::spawn(async move {
                            let _ = forward(socket, acceptor, backend).await;
                        });
                    }
                });
            })
            .expect("front thread");
        // SAFETY: called before any HTTP client exists; the threads alive at this point (test runtime, mock
        // workers, the front) never read the process environment.
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
            configured_url: format!(
                "https://{CONFIGURED_HOST}{}",
                parsed.path().trim_end_matches('/')
            ),
            _ca_dir: ca_dir,
        }
    }

    /// The configured-origin spelling of the backend URL (`https://api.fluxrouter.ai/<path>`).
    pub fn configured_url(&self) -> &str {
        &self.configured_url
    }
}

fn tls_acceptor_and_ca() -> (
    tokio_rustls::TlsAcceptor,
    tempfile::TempDir,
    std::path::PathBuf,
) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![CONFIGURED_HOST.to_string()])
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
    (
        tokio_rustls::TlsAcceptor::from(Arc::new(tls)),
        ca_dir,
        ca_path,
    )
}

async fn forward(
    mut socket: tokio::net::TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    backend: String,
) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if socket.read(&mut byte).await? == 0 {
            return Ok(());
        }
        head.push(byte[0]);
    }
    let line = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    let is_configured = line
        .strip_prefix("CONNECT ")
        .and_then(|rest| rest.split_whitespace().next())
        .is_some_and(|authority| authority == format!("{CONFIGURED_HOST}:443"));
    if !is_configured {
        socket
            .write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await?;
        return Ok(());
    }
    socket
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let mut tls = acceptor.accept(socket).await?;
    let mut upstream = tokio::net::TcpStream::connect(backend).await?;
    let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
    Ok(())
}
