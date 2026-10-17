//! A trusted-HTTPS front for a loopback mock, for tests that must run the product with **session auth**.
//!
//! The session token goes only to a configured `https` origin, never to `http://` or loopback
//! (`auth::session_delivery::session_may_reach`, and the P47 service-endpoint class for `/v1/settings`,
//! `/v1/user` and friends). A test that points the endpoints straight at [`crate::MockInferenceServer`]'s
//! `http://127.0.0.1:PORT/v1` therefore sees every session-auth request refused before it leaves the process.
//!
//! The front makes the mock reachable as `https://api.fluxrouter.ai/v1` instead. The child process is given
//! `HTTPS_PROXY` pointing at the front and `FUIGO_EXTRA_CA_BUNDLE` naming a throwaway CA. A `CONNECT` to
//! `api.fluxrouter.ai:443` is TLS-terminated with a leaf signed by that CA, and the decrypted bytes are forwarded
//! unchanged to the mock. The request is really an `https` request to a FluxRouter-operated origin, admitted by the
//! production predicate; nothing in the product's trust rules is relaxed. Only the CA the child trusts differs,
//! through the operator-facing `FUIGO_EXTRA_CA_BUNDLE` mechanism.
//!
//! Unlike the in-process twins used by the `fuigo-shell` tests, this front never touches the *parent's*
//! environment: it hands the child its variables as plain key/value pairs ([`SessionFront::child_env`]).

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The origin the front impersonates (the compiled FluxRouter API host).
pub const CONFIGURED_HOST: &str = "api.fluxrouter.ai";

/// A running front. Dropping it stops the accept loop.
pub struct SessionFront {
    proxy_url: String,
    configured_url: String,
    ca_path: std::path::PathBuf,
    _ca_dir: tempfile::TempDir,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl SessionFront {
    /// Start a front for `backend_url` (e.g. `MockInferenceServer::url()`) on its own thread and runtime.
    pub fn start(backend_url: &str) -> Self {
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
        let proxy_url = format!("http://{}", std_listener.local_addr().expect("front addr"));
        let (shutdown, mut stop) = tokio::sync::oneshot::channel::<()>();
        std::thread::Builder::new()
            .name("session-front".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("front runtime");
                rt.block_on(async move {
                    let listener =
                        tokio::net::TcpListener::from_std(std_listener).expect("front listener");
                    loop {
                        tokio::select! {
                            _ = &mut stop => break,
                            accepted = listener.accept() => {
                                let Ok((socket, _)) = accepted else { break };
                                let acceptor = acceptor.clone();
                                let backend = backend.clone();
                                tokio::spawn(async move {
                                    let _ = forward(socket, acceptor, backend).await;
                                });
                            }
                        }
                    }
                });
            })
            .expect("front thread");
        Self {
            proxy_url,
            configured_url: format!(
                "https://{CONFIGURED_HOST}{}",
                parsed.path().trim_end_matches('/')
            ),
            ca_path,
            _ca_dir: ca_dir,
            shutdown: Some(shutdown),
        }
    }

    /// The configured-origin spelling of the backend URL (`https://api.fluxrouter.ai/v1`).
    pub fn configured_url(&self) -> &str {
        &self.configured_url
    }

    /// `http://127.0.0.1:PORT`, the proxy the child must route `https` through.
    pub fn proxy_url(&self) -> &str {
        &self.proxy_url
    }

    /// The throwaway CA the child must trust (`FUIGO_EXTRA_CA_BUNDLE`).
    pub fn ca_path(&self) -> &std::path::Path {
        &self.ca_path
    }

    /// Environment for a child process so its requests to [`Self::configured_url`] reach the mock.
    /// Loopback stays direct (`NO_PROXY`), so local issuers and leader sockets are unaffected.
    pub fn child_env(&self) -> Vec<(&'static str, String)> {
        let mut env = Vec::new();
        for key in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            env.push((key, self.proxy_url.clone()));
        }
        for key in ["NO_PROXY", "no_proxy"] {
            env.push((key, "127.0.0.1,localhost,::1".to_owned()));
        }
        env.push((
            "FUIGO_EXTRA_CA_BUNDLE",
            self.ca_path.to_string_lossy().into_owned(),
        ));
        env
    }
}

impl Drop for SessionFront {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn connect_status(front: &SessionFront, authority: &str) -> String {
        let addr = front.proxy_url().trim_start_matches("http://").to_owned();
        let mut socket = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to front");
        socket
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await
            .expect("send CONNECT");
        let mut buf = vec![0u8; 256];
        let n = socket.read(&mut buf).await.expect("read status");
        String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned()
    }

    #[tokio::test]
    async fn front_tunnels_only_the_configured_host_and_hands_the_child_its_trust() {
        let front = SessionFront::start("http://127.0.0.1:9/v1");
        assert_eq!(front.configured_url(), "https://api.fluxrouter.ai/v1");

        assert_eq!(
            connect_status(&front, "api.fluxrouter.ai:443").await,
            "HTTP/1.1 200 Connection Established"
        );
        assert!(
            connect_status(&front, "example.com:443")
                .await
                .starts_with("HTTP/1.1 502"),
            "any other host must be refused, not tunnelled"
        );

        let env: std::collections::BTreeMap<_, _> = front.child_env().into_iter().collect();
        assert_eq!(env["HTTPS_PROXY"], front.proxy_url());
        assert_eq!(env["NO_PROXY"], "127.0.0.1,localhost,::1");
        let ca = std::fs::read_to_string(&env["FUIGO_EXTRA_CA_BUNDLE"]).expect("ca bundle file");
        assert!(ca.starts_with("-----BEGIN CERTIFICATE-----"), "{ca}");
    }
}
