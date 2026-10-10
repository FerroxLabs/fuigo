// Per-test-case module for the `pty_e2e` integration test crate.
#[allow(unused_imports)]
use super::common::*;

use std::io::Write as _;
use std::process::{Child, Command, Stdio};

const OAUTH_SERVER: &str = "ptyoauth";

/// A loopback MCP server whose OAuth token endpoint answers every POST with a same-origin 307.
/// `POST /mcp` is always 401, so a saved login with an expired access token must refresh.
/// Every POST to a token path appends a line to the hits file.
const REDIRECTING_OAUTH_SERVER_PY: &str = r#"import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port = int(sys.argv[1])
hits = sys.argv[2]
base = "http://127.0.0.1:%d" % port

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if "oauth-protected-resource" in self.path:
            doc = {"resource": base + "/mcp", "authorization_servers": [base]}
        elif "oauth-authorization-server" in self.path or "openid-configuration" in self.path:
            doc = {"issuer": base, "authorization_endpoint": base + "/authorize",
                   "token_endpoint": base + "/token-redir", "registration_endpoint": base + "/register",
                   "response_types_supported": ["code"], "code_challenge_methods_supported": ["S256"],
                   "grant_types_supported": ["authorization_code", "refresh_token"]}
        else:
            return self.reply(404)
        self.reply(200, json.dumps(doc).encode(), [("Content-Type", "application/json")])

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        if self.path.startswith("/token"):
            with open(hits, "a") as f:
                f.write(self.path + "\n")
            return self.reply(307, b"", [("Location", base + "/token-moved")])
        self.reply(401, b'{"error":"invalid_token"}', [
            ("Content-Type", "application/json"),
            ("WWW-Authenticate", 'Bearer resource_metadata="%s/.well-known/oauth-protected-resource"' % base)])

ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
"#;

struct OauthFixture {
    child: Child,
    hits: PathBuf,
}

impl Drop for OauthFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start the fixture, register it as a user-scope server and seed a saved login whose access token expired long ago.
#[allow(
    clippy::disallowed_methods,
    reason = "a test fixture; OauthFixture::drop kills and reaps the child"
)]
fn seed_oauth_fixture(content: &ContentController) -> OauthFixture {
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("pick a port");
        probe.local_addr().expect("local addr").port()
    };
    let fuigo_home = content.home().join(".fuigo");
    std::fs::create_dir_all(&fuigo_home).expect("create fake FUIGO_HOME");
    let script = fuigo_home.join("redirecting_oauth_server.py");
    std::fs::write(&script, REDIRECTING_OAUTH_SERVER_PY).expect("write the fixture");
    let hits = fuigo_home.join("token_hits.txt");
    let child = Command::new("python3")
        .arg(&script)
        .arg(port.to_string())
        .arg(&hits)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the OAuth fixture");
    let base = format!("http://127.0.0.1:{port}");
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let config = format!("[mcp_servers.{OAUTH_SERVER}]\nurl = \"{base}/mcp\"\nstartup_timeout_sec = 20\n");
    std::fs::write(fuigo_home.join("config.toml"), config).expect("write config.toml");
    let credentials = json!({
        format!("{OAUTH_SERVER}:{base}/mcp"): {
            "client_id": "pty-client",
            "token_response": {
                "access_token": "pty-expired-access-token",
                "token_type": "bearer",
                "expires_in": 60,
                "refresh_token": "pty-refresh-token"
            },
            "granted_scopes": [],
            "token_received_at": 1,
            "issuer": base
        }
    });
    let path = fuigo_home.join("mcp_credentials.json");
    let mut file = std::fs::File::create(&path).expect("create mcp_credentials.json");
    file.write_all(credentials.to_string().as_bytes())
        .expect("write mcp_credentials.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    OauthFixture { child, hits }
}

/// K7: an OAuth MCP server whose token endpoint redirects the refresh is listed as needing sign-in, and `/mcps` says the
/// refresh was refused (it showed only a bare badge; the log held the reason and the screen "Request failed").
/// The refresh token is posted to the redirecting endpoint at most twice (once per OAuth manager), not once per retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run the owning pty_e2e_* Cargo test with --ignored (see Cargo.toml)"]
async fn mcps_needs_auth_shows_why_the_refresh_was_refused() {
    let content = ContentController::start().await.expect("start content");
    content.set_response(format!("{MOCK_RESPONSE_SENTINEL} oauth reason."));
    let fixture = seed_oauth_fixture(&content);

    let binary = pager_binary().expect("resolve pager binary");
    let mut harness = PtyHarness::spawn_with_content_in_dir(
        &binary,
        DEFAULT_ROWS,
        DEFAULT_COLS,
        &content,
        &["--trust", "--no-leader"],
        Some(content.home()),
    )
    .expect("spawn pager");
    harness
        .wait_for_text(WELCOME_SCREEN_SENTINEL, WELCOME_TIMEOUT)
        .expect("welcome text");
    // A turn makes the session start its MCP servers; the saved login must refresh and is refused.
    harness
        .inject_keys(format!("{PROMPT}\r").as_bytes())
        .expect("submit prompt");
    harness
        .wait_for_text(MOCK_RESPONSE_SENTINEL, Duration::from_secs(60))
        .expect("response rendered");
    harness.update(Duration::from_secs(5));

    harness.inject_keys(b"/mcps\r").expect("submit /mcps");
    harness
        .wait_for_text("MCP Servers", Duration::from_secs(15))
        .expect("extensions modal open on MCP Servers tab");
    harness
        .wait_for_text(OAUTH_SERVER, MCP_MENU_LOAD_TIMEOUT)
        .expect("MCP server list loaded in menu");
    let found = harness.wait_for_text("refresh refused", Duration::from_secs(30));
    let screen = harness.screen_contents();
    assert!(
        found.is_ok(),
        "a server whose refresh was refused must say so\nscreen:\n{screen}"
    );
    assert!(
        screen.contains("redirect"),
        "the reason names the redirect\nscreen:\n{screen}"
    );
    assert!(
        !screen.contains("pty-refresh-token"),
        "the reason must not carry the credential\nscreen:\n{screen}"
    );
    harness.quit().expect("clean quit");

    let posts = std::fs::read_to_string(&fixture.hits)
        .map(|text| text.lines().count())
        .unwrap_or(0);
    assert!(
        posts <= 2,
        "the refresh token went to the redirecting endpoint {posts} times"
    );
}
