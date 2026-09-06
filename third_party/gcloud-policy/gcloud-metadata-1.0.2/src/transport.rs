//! Optional process-owned transport policy shared by metadata and authentication.
//! Install once before credential discovery. The policy cannot be replaced later.
use std::sync::OnceLock;

pub struct Policy {
    pub configure: fn(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
    pub check_url: fn(&reqwest::Url) -> Result<(), String>,
}

static POLICY: OnceLock<Policy> = OnceLock::new();

pub fn install(policy: Policy) -> Result<(), &'static str> {
    POLICY.set(policy).map_err(|_| "GCS transport policy already installed")
}

pub fn client(timeout: std::time::Duration) -> Result<reqwest::Client, reqwest::Error> {
    let builder = reqwest::Client::builder().timeout(timeout);
    let builder = match POLICY.get() {
        Some(policy) => (policy.configure)(builder),
        None => builder,
    };
    // Approved reqwest 0.13 construction boundary: Fuigo installs configure
    // before credential discovery; standalone SDKs retain their default policy.
    #[allow(clippy::disallowed_methods)]
    builder.build()
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("GCS authentication destination denied by transport policy")]
    Denied,
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

pub trait RequestPolicyExt {
    fn send_guarded(self) -> impl std::future::Future<Output = Result<reqwest::Response, Error>> + Send;
}

impl RequestPolicyExt for reqwest::RequestBuilder {
    async fn send_guarded(self) -> Result<reqwest::Response, Error> {
        let (client, request) = self.build_split();
        let request = request.map_err(|error| Error::Http(error.without_url()))?;
        if let Some(policy) = POLICY.get() {
            (policy.check_url)(request.url()).map_err(|_| Error::Denied)?;
        }
        // Approved dispatch boundary; destination checked immediately above.
        #[allow(clippy::disallowed_methods)]
        client.execute(request).await.map_err(|error| Error::Http(error.without_url()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[tokio::test]
    async fn policy_blocks_proxy_contact_and_allows_local_response() {
        install(Policy {
            configure: |builder| builder.redirect(reqwest::redirect::Policy::none()),
            check_url: |url| {
                if url.host_str() == Some("127.0.0.1") { Ok(()) } else { Err("denied".into()) }
            },
        }).unwrap();
        assert!(install(Policy { configure: |b| b, check_url: |_| Ok(()) }).is_err());
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        proxy.set_nonblocking(true).unwrap();
        let http = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{}", proxy.local_addr().unwrap())).unwrap())
            .build().unwrap();
        let error = http.post("http://blocked.invalid/token")
            .body("fake-refresh-token").send_guarded().await.unwrap_err();
        assert!(matches!(error, Error::Denied));
        assert!(!error.to_string().contains("fake-refresh-token"));
        assert_eq!(proxy.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);

        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        server.set_nonblocking(true).unwrap();
        let worker = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                match server.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
                        let mut buf = [0; 2048];
                        stream.read(&mut buf).unwrap();
                        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline);
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(e) => panic!("local receiver: {e}"),
                }
            }
        });
        let response = client(std::time::Duration::from_secs(3)).unwrap()
            .get(format!("http://{addr}/token")).send_guarded().await.unwrap();
        assert_eq!(response.text().await.unwrap(), "ok");
        worker.join().unwrap();
    }
}
