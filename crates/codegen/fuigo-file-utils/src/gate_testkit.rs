//! P71 test kit: a recording storage endpoint for wire-level tests of the destination gate.
//!
//! Compiled only into test builds (`cfg(test)` or the `test-loopback-operator` feature). It listens
//! on loopback, records every byte any client sends (request lines, headers and bodies, chunk
//! framing included), and answers each request with a canned success so an upload that is allowed
//! to reach it completes. The class of a mock comes from the HOST its URL names:
//!
//! * [`RecordingEndpoint::fluxrouter_class`] is addressed as `127.0.0.1`, which the test seam in
//!   [`crate::destination_gate`] classifies FluxRouter-operated (class 1);
//! * [`RecordingEndpoint::third_party`] is addressed as `localhost`, which only the PRODUCTION rule
//!   classifies: a third-party proxy (class 3), which must receive nothing. (`localhost` rather than
//!   another `127.0.0.0/8` address: macOS binds only `127.0.0.1`.)
//!
//! Tests assert on what the mock RECEIVED, never on an upload's return value.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What a [`RecordingEndpoint`] has received.
#[derive(Default)]
struct Captured {
    connections: usize,
    requests: usize,
    bytes: Vec<u8>,
}

/// A loopback HTTP endpoint that records everything sent to it.
pub struct RecordingEndpoint {
    /// `host:port` as the mock's URLs spell it.
    authority: String,
    captured: Arc<Mutex<Captured>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for RecordingEndpoint {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// The path the mock's signed-URL answer points the client's `PUT` at (on the mock itself).
pub const SIGNED_PUT_PATH: &str = "/p71-signed-put";

/// The canned reply to every request. One JSON object that reads as a proxy `UploadResponse`
/// (snake_case keys) AND as a `SignedUploadUrlResponse` (camelCase keys) whose signed URL is this
/// mock's own [`SIGNED_PUT_PATH`], so the signed-URL flow goes on to `PUT` its payload here, where
/// it is recorded. An S3 `PutObject` ignores the body of a 200.
fn reply_for(authority: &str) -> String {
    format!(
        r#"{{"bucket":"mock-bucket","path":"mock/path","size":0,"content_type":"application/octet-stream","generation":1,"signedUrl":"http://{authority}{SIGNED_PUT_PATH}","contentType":"application/octet-stream","expiresInSecs":60}}"#
    )
}

impl RecordingEndpoint {
    /// A class 1 mock: its URLs name `127.0.0.1`, which the test seam classifies FluxRouter-operated.
    pub async fn fluxrouter_class() -> Self {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback mock");
        let port = listener.local_addr().expect("mock addr").port();
        Self::serving(format!("127.0.0.1:{port}"), vec![listener])
    }

    /// A mock whose URLs name `localhost`, so the production rule classifies it: as a storage proxy
    /// it is class 3 (third party) and must receive nothing; as an S3 `endpoint_url` it is the
    /// operator's bucket (class 2).
    ///
    /// It listens on `127.0.0.1` and, where the host has IPv6 loopback, on `[::1]` at the same port,
    /// so whichever address `localhost` resolves to first, a sender that (wrongly) connects reaches
    /// this mock and is recorded.
    pub async fn third_party() -> Self {
        for _ in 0..16 {
            let v4 = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind loopback mock");
            let port = v4.local_addr().expect("mock addr").port();
            match tokio::net::TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port)).await {
                Ok(v6) => return Self::serving(format!("localhost:{port}"), vec![v4, v6]),
                // The port is taken on `[::1]` by someone else: a `localhost` sender could reach them
                // instead of this mock. Take another port.
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
                // No IPv6 loopback on this host: `localhost` can only be `127.0.0.1`.
                Err(_) => return Self::serving(format!("localhost:{port}"), vec![v4]),
            }
        }
        panic!("no loopback port free on both 127.0.0.1 and [::1]");
    }

    fn serving(authority: String, listeners: Vec<tokio::net::TcpListener>) -> Self {
        let captured: Arc<Mutex<Captured>> = Arc::default();
        let reply: Arc<str> = reply_for(&authority).into();
        let tasks = listeners
            .into_iter()
            .map(|listener| {
                let shared = captured.clone();
                let reply = reply.clone();
                tokio::spawn(async move {
                    loop {
                        let Ok((stream, _)) = listener.accept().await else {
                            return;
                        };
                        let shared = shared.clone();
                        if let Ok(mut c) = shared.lock() {
                            c.connections += 1;
                        }
                        tokio::spawn(serve(stream, shared, reply.clone()));
                    }
                })
            })
            .collect();
        Self { authority, captured, tasks }
    }

    /// `http://host:port/v1`: the storage-proxy base URL of this mock.
    pub fn proxy_base_url(&self) -> String {
        format!("http://{}/v1", self.authority)
    }

    /// `http://host:port`: the endpoint URL of this mock (for an S3 `endpoint_url`).
    pub fn endpoint_url(&self) -> String {
        format!("http://{}", self.authority)
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> usize {
        self.captured.lock().map(|c| c.connections).unwrap_or(0)
    }

    /// Complete requests received so far.
    pub fn requests(&self) -> usize {
        self.captured.lock().map(|c| c.requests).unwrap_or(0)
    }

    /// Every byte received, in arrival order.
    pub fn received(&self) -> Vec<u8> {
        self.captured.lock().map(|c| c.bytes.clone()).unwrap_or_default()
    }

    /// Whether `needle` appears anywhere in what was received.
    pub fn received_contains(&self, needle: &[u8]) -> bool {
        let received = self.received();
        !needle.is_empty() && received.windows(needle.len()).any(|w| w == needle)
    }

    /// Wait (bounded by `timeout`) until at least one request has been received. For positive
    /// controls whose sender may complete asynchronously.
    pub async fn wait_for_request(&self, timeout: std::time::Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if self.requests() > 0 {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        self.requests() > 0
    }

    /// Give a sender that must NOT reach this mock time to (wrongly) do so, then report what the
    /// mock saw. For negative controls whose sender completes asynchronously.
    pub async fn settle(&self, quiet_for: std::time::Duration) {
        tokio::time::sleep(quiet_for).await;
    }
}

async fn serve(mut stream: tokio::net::TcpStream, shared: Arc<Mutex<Captured>>, body: Arc<str>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        // Read until one full request is buffered.
        let consumed = loop {
            if let Some(len) = request_len(&buf) {
                break len;
            }
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if let Ok(mut c) = shared.lock() {
                        c.bytes.extend_from_slice(&chunk[..n]);
                    }
                }
            }
        };
        buf.drain(..consumed);
        if let Ok(mut c) = shared.lock() {
            c.requests += 1;
        }
        let reply = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        if stream.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
    }
}

/// The length of the first complete request in `buf`, if one is fully buffered.
fn request_len(buf: &[u8]) -> Option<usize> {
    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
    if head.contains("transfer-encoding: chunked") {
        let mut at = head_end;
        loop {
            let line_end = buf[at..].windows(2).position(|w| w == b"\r\n")? + at;
            let size = usize::from_str_radix(
                String::from_utf8_lossy(&buf[at..line_end]).split(';').next()?.trim(),
                16,
            )
            .ok()?;
            at = line_end + 2;
            if size == 0 {
                // trailers (none expected) then the final CRLF
                return (buf.len() >= at + 2).then_some(at + 2);
            }
            at += size + 2;
            if buf.len() < at {
                return None;
            }
        }
    }
    let content_length = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    (buf.len() >= head_end + content_length).then_some(head_end + content_length)
}
