//! `bearer_token_file` through the real spawn path against loopback mocks: where the token goes (only to the configured
//! origin, never on a redirect to another), the refusals that skip one server, rotation, and nothing leaking into logs
//! or error text. Fake tokens only; every listener is 127.0.0.1.

#![allow(clippy::vec_init_then_push)] // each refusal case is commented where it is added

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use super::*;
use crate::bearer_token_file::bearer_token_file_meta;

const TOKEN: &str = "fake-bearer-FILE-token-9f8e7d";

type Seen = Arc<parking_lot::Mutex<Vec<(String, Option<String>)>>>;

fn token_file(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("token");
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

/// Answers every request 500 after recording `(path, Authorization)`.
async fn recording_mock() -> (String, Seen) {
    let seen: Seen = Arc::default();
    let log = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |uri: axum::http::Uri, headers: axum::http::HeaderMap| {
        let log = Arc::clone(&log);
        async move {
            let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).map(str::to_owned);
            log.lock().push((uri.path().to_owned(), auth));
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), seen)
}

/// Redirects every request (307) to `target`.
async fn redirecting_mock(target: String) -> String {
    let app = axum::Router::new().fallback(move || {
        let target = target.clone();
        async move { (axum::http::StatusCode::TEMPORARY_REDIRECT, [("location", target)]) }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn server_with_file(name: &str, url: &str, file: &str) -> acp::McpServer {
    acp::McpServer::Http(acp::McpServerHttp::new(name, url).meta(bearer_token_file_meta(file)))
}

fn start_ctx(writer: &fuigo_session_events::EventWriter) -> McpSpawnCtx<'_> {
    crate::isolate_fuigo_home_for_tests();
    McpSpawnCtx::for_session("sess", writer, OauthInteractivity::NonInteractive, None)
}

fn http_config(url: &str, file: &std::path::Path) -> HttpConfig {
    HttpConfig {
        url: url.to_owned(),
        headers: vec![],
        local_agent_endpoint: false,
        bearer_token_file: Some(crate::bearer_token_file::BearerTokenFile::new(
            crate::bearer_token_file::BearerTokenPath::parse(file.to_str().unwrap(), None).unwrap(),
        )),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_token_file_is_sent_as_a_bearer_to_the_configured_server() {
    let dir = tempfile::tempdir().unwrap();
    let file = token_file(dir.path(), &format!("{TOKEN}\n"));
    let (base, seen) = recording_mock().await;
    let writer = fuigo_session_events::EventWriter::noop();
    let ctx = start_ctx(&writer);
    let client = start_mcp_server(server_with_file("bf", &format!("{base}/mcp"), file.to_str().unwrap()), None, None, None, &ctx)
        .await
        .expect("a loopback http server may carry the token");
    let _ = client.ensure_initialized().await; // the mock answers 500; only the request matters
    let seen = seen.lock();
    assert!(!seen.is_empty(), "no request reached the mock");
    for (path, auth) in seen.iter() {
        assert_eq!(auth.as_deref(), Some(format!("Bearer {TOKEN}").as_str()), "{path}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cross_origin_redirect_never_receives_the_token() {
    let dir = tempfile::tempdir().unwrap();
    let file = token_file(dir.path(), &format!("{TOKEN}\n"));
    let (other, other_seen) = recording_mock().await;
    let redirector = redirecting_mock(format!("{other}/stolen")).await;
    let writer = fuigo_session_events::EventWriter::noop();
    let ctx = start_ctx(&writer);
    let client = start_mcp_server(server_with_file("bf", &format!("{redirector}/mcp"), file.to_str().unwrap()), None, None, None, &ctx)
        .await
        .expect("builds");
    let _ = client.ensure_initialized().await;
    let seen = other_seen.lock();
    assert!(seen.is_empty(), "the other origin received a request: {seen:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn rotation_is_picked_up_on_the_next_request_and_a_bad_file_sends_nothing() {
    use rmcp::transport::streamable_http_client::StreamableHttpClient;
    let dir = tempfile::tempdir().unwrap();
    let file = token_file(dir.path(), "fake-first-token-0001\n");
    let (base, seen) = recording_mock().await;
    let url = format!("{base}/mcp");
    let client = McpClient::build_http_client(&http_config(&url, &file), "rot", crate::mcp_http_client::WarnBudget::default())
        .expect("client");
    let delete = || client.delete_session(url.as_str().into(), "sid".into(), None, Default::default());
    let _ = delete().await;
    std::fs::write(&file, "fake-second-token-0002\n").unwrap();
    let _ = delete().await;
    // Loosen the mode: the request must fail before anything is sent.
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let denied = delete().await;
    assert!(denied.is_err());
    let rendered = format!("{denied:?}");
    assert!(!rendered.contains("fake-second-token-0002") && !rendered.contains("fake-first-token-0001"), "{rendered}");
    let seen = seen.lock();
    let auths: Vec<_> = seen.iter().map(|(_, a)| a.clone().unwrap_or_default()).collect();
    assert_eq!(auths, ["Bearer fake-first-token-0001", "Bearer fake-second-token-0002"], "{auths:?}");
}

#[tokio::test]
async fn refusals_skip_only_that_server_and_never_echo_the_token_or_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = token_file(dir.path(), &format!("{TOKEN}\n"));
    let path = file.to_str().unwrap();
    let writer = fuigo_session_events::EventWriter::noop();
    let ctx = start_ctx(&writer);
    let mut refused = Vec::new();
    // A plain-http server off this machine.
    refused.push(server_with_file("plain", "http://mcp.example.invalid/mcp", path));
    // A relative path, and an environment spelling.
    refused.push(server_with_file("rel", "https://mcp.example.invalid/mcp", "token"));
    refused.push(server_with_file("env", "https://mcp.example.invalid/mcp", "$HOME/token"));
    // Both forms: an inline Authorization header and the file.
    refused.push(acp::McpServer::Http(
        acp::McpServerHttp::new("both", "https://mcp.example.invalid/mcp")
            .headers(vec![acp::HttpHeader::new("authorization", "Bearer inline-fake-0000")])
            .meta(bearer_token_file_meta(path)),
    ));
    // A `_meta` value that is not a string.
    refused.push(acp::McpServer::Http(
        acp::McpServerHttp::new("num", "https://mcp.example.invalid/mcp")
            .meta(acp::Meta::from_iter([(crate::bearer_token_file::META_KEY.to_owned(), serde_json::json!(5))])),
    ));
    for server in refused {
        let name = mcp_server_name_of(&server);
        let err = match start_mcp_server(server, None, None, None, &ctx).await {
            Ok(_) => panic!("{name} must be refused"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains(&name), "{err}");
        assert!(!err.contains(TOKEN) && !err.contains(path) && !err.contains("inline-fake"), "{err}");
    }
    // An ordinary server beside them still starts.
    let ok = start_mcp_server(acp::McpServer::Http(acp::McpServerHttp::new("plainok", "http://127.0.0.1:9/mcp")), None, None, None, &ctx).await;
    assert!(ok.is_ok());
}

fn mcp_server_name_of(server: &acp::McpServer) -> String {
    match server {
        acp::McpServer::Http(h) => h.name.clone(),
        acp::McpServer::Sse(s) => s.name.clone(),
        other => panic!("not http: {other:?}"),
    }
}

/// A subscriber that keeps every event of every level as text.
#[derive(Clone, Default)]
struct Everything(Arc<parking_lot::Mutex<String>>);

struct Collect<'a>(&'a mut String);
impl tracing::field::Visit for Collect<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

impl tracing::Subscriber for Everything {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut text = self.0.lock();
        let _ = std::fmt::Write::write_str(&mut *text, event.metadata().target());
        text.push(' ');
        event.record(&mut Collect(&mut text));
        text.push('\n');
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test]
async fn nothing_logged_at_any_level_holds_the_token() {
    let logs = Everything::default();
    let _guard = tracing::subscriber::set_default(logs.clone());
    let dir = tempfile::tempdir().unwrap();
    let file = token_file(dir.path(), &format!("{TOKEN}\n"));
    let (base, _seen) = recording_mock().await;
    let url = format!("{base}/mcp");
    let writer = fuigo_session_events::EventWriter::noop();
    let ctx = start_ctx(&writer);
    let client = start_mcp_server(server_with_file("logs", &url, file.to_str().unwrap()), None, None, None, &ctx).await.unwrap();
    let _ = client.ensure_initialized().await;
    // A failing read logs its refusal too.
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
    let _ = client.ensure_initialized().await;
    let http = McpClient::build_http_client(&http_config(&url, &file), "logs", crate::mcp_http_client::WarnBudget::default()).unwrap();
    {
        use rmcp::transport::streamable_http_client::StreamableHttpClient;
        let _ = http.delete_session(url.as_str().into(), "sid".into(), None, Default::default()).await;
    }
    let text = logs.0.lock().clone();
    assert!(!text.is_empty(), "the capture saw nothing");
    assert!(!text.contains(TOKEN), "a log line holds the token:\n{text}");
    assert!(text.contains("bearer_token_file"), "the refusal should be logged by reason:\n{text}");
}
