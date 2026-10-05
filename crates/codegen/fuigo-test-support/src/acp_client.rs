//! ACP stdio clients for testing fuigo sessions end-to-end, both backed by the shared [`TestProcess`].
//! [`FuigoStdioClient`] drives the typed `agent-client-protocol` connection.
//! [`RawStdioClient`] writes verbatim JSON-RPC lines for wire shapes the typed client cannot produce.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crate::scaled;

use agent_client_protocol::{self as acp, Agent as _};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use fuigo_acp_lib::LineBufferedRead;

use crate::env::fuigo_binary;
use crate::headless::stderr_tail;
use crate::mock_server::MockInferenceServer;
use crate::process::{TestOutput, TestProcess, TestProcessConfig, TestStdin};
use crate::sandbox::TestSandbox;

/// Spawn `fuigo agent stdio` with the sandbox's canonical hermetic environment.
/// `leading_args` go before the `agent stdio` subcommand (global flags).
fn spawn_agent_process(
    sandbox: &mut TestSandbox,
    server: &MockInferenceServer,
    cwd: &Path,
    extra_env: &[(&str, &str)],
    leading_args: &[&str],
) -> TestProcess {
    spawn_agent_process_with(
        sandbox,
        server,
        cwd,
        &AgentSpawnSpec {
            leading_args,
            extra_env,
            ..AgentSpawnSpec::default()
        },
    )
}

/// The argv and child-environment shape of one `fuigo <leading_args> agent <agent_args> stdio` spawn.
///
/// Exists because an embedder's argv puts flags on BOTH sides of `agent`: global `PagerArgs` flags
/// (`--permission-mode`, `--trust`, `--no-memory`) precede it, while `AgentArgs` flags (`--no-leader`,
/// `-m`, `--reasoning-effort`) sit between `agent` and `stdio`. The `leading_args` parameter of the older
/// spawn helpers can express only the first half.
#[derive(Debug, Clone, Copy, Default)]
pub struct AgentSpawnSpec<'a> {
    /// Global flags placed before `agent`.
    pub leading_args: &'a [&'a str],
    /// `agent` flags placed between `agent` and `stdio`.
    pub agent_args: &'a [&'a str],
    /// Child-env overrides, applied after the mock endpoint (and its fake `FUIGO_API_KEY`).
    pub extra_env: &'a [(&'a str, &'a str)],
    /// Child-env variables removed last, after the mock endpoint and `extra_env`.
    /// This is the only way to take away the fake `FUIGO_API_KEY` the mock endpoint installs:
    /// setting it to `""` is a different state (present-but-empty) from absent.
    pub remove_env: &'a [&'a str],
}

impl AgentSpawnSpec<'_> {
    /// The full argv after the binary name, exactly as the child receives it.
    pub fn argv(&self) -> Vec<String> {
        self.leading_args
            .iter()
            .copied()
            .chain(std::iter::once("agent"))
            .chain(self.agent_args.iter().copied())
            .chain(std::iter::once("stdio"))
            .map(str::to_owned)
            .collect()
    }
}

/// Spawn `fuigo <leading_args> agent <agent_args> stdio` per `spec`, with the sandbox's hermetic environment.
fn spawn_agent_process_with(
    sandbox: &mut TestSandbox,
    server: &MockInferenceServer,
    cwd: &Path,
    spec: &AgentSpawnSpec<'_>,
) -> TestProcess {
    sandbox.set_mock_url(server.url());
    for (key, value) in spec.extra_env {
        sandbox.set_env(*key, *value);
    }
    for key in spec.remove_env {
        sandbox.remove_env(*key);
    }

    let binary = fuigo_binary();
    let mut cmd = tokio::process::Command::new(&binary);
    cmd.args(spec.argv()).current_dir(cwd);

    TestProcess::spawn(
        cmd,
        sandbox,
        TestProcessConfig::new()
            .label("fuigo agent stdio")
            .stdin(TestStdin::Piped)
            .stdout(TestOutput::Piped),
    )
    .unwrap_or_else(|error| {
        panic!(
            "failed to spawn ACP test client at {} {:?}: {error}\n{}",
            binary.display(),
            spec.argv(),
            sandbox.diagnostic_summary(),
        )
    })
}

#[derive(Default)]
struct TextCapture {
    chunks: std::sync::Mutex<Vec<String>>,
    notification_count: AtomicU32,
}

/// ACP client impl: auto-approves permissions, captures text chunks.
struct TestAcpClient {
    capture: Arc<TextCapture>,
}

#[async_trait::async_trait(?Send)]
impl acp::Client for TestAcpClient {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        // Auto-approve: pick AllowOnce if available, otherwise first option.
        let outcome = args
            .options
            .iter()
            .find(|o| o.kind == acp::PermissionOptionKind::AllowOnce)
            .or(args.options.first())
            .map(|o| {
                acp::RequestPermissionOutcome::Selected(acp::SelectedPermissionOutcome::new(
                    o.option_id.clone(),
                ))
            })
            .unwrap_or(acp::RequestPermissionOutcome::Cancelled);

        Ok(acp::RequestPermissionResponse::new(outcome))
    }

    async fn session_notification(&self, args: acp::SessionNotification) -> acp::Result<()> {
        self.capture
            .notification_count
            .fetch_add(1, Ordering::SeqCst);

        if let acp::SessionUpdate::AgentMessageChunk(acp::ContentChunk { content, .. }) =
            args.update
            && let acp::ContentBlock::Text(text_content) = content
            && !text_content.text.is_empty()
        {
            self.capture.chunks.lock().unwrap().push(text_content.text);
        }
        Ok(())
    }
}

/// Drives `fuigo agent stdio` via the ACP protocol over pipes.
///
/// Handles the full lifecycle: spawn, initialize, authenticate, session, prompt.
/// Child process is killed on drop.
pub struct FuigoStdioClient {
    conn: acp::ClientSideConnection,
    process: TestProcess,
    sandbox: Option<TestSandbox>,
    capture: Arc<TextCapture>,
}

impl FuigoStdioClient {
    pub async fn spawn(server: &MockInferenceServer, cwd: &Path) -> Self {
        Self::spawn_with_sandbox(server, cwd, TestSandbox::new()).await
    }

    pub async fn spawn_with_sandbox(
        server: &MockInferenceServer,
        cwd: &Path,
        sandbox: TestSandbox,
    ) -> Self {
        Self::spawn_with_sandbox_env_and_args(server, cwd, sandbox, &[], &[]).await
    }

    pub async fn spawn_with_sandbox_env_and_args(
        server: &MockInferenceServer,
        cwd: &Path,
        sandbox: TestSandbox,
        extra_env: &[(&str, &str)],
        leading_args: &[&str],
    ) -> Self {
        Self::spawn_with_spec(
            server,
            cwd,
            sandbox,
            &AgentSpawnSpec {
                leading_args,
                extra_env,
                ..AgentSpawnSpec::default()
            },
        )
        .await
    }

    /// Spawn with full control of both argv halves and the child env (see [`AgentSpawnSpec`]).
    pub async fn spawn_with_spec(
        server: &MockInferenceServer,
        cwd: &Path,
        mut sandbox: TestSandbox,
        spec: &AgentSpawnSpec<'_>,
    ) -> Self {
        let mut process = spawn_agent_process_with(&mut sandbox, server, cwd, spec);

        let outgoing = process
            .take_stdin()
            .expect("child stdin missing")
            .compat_write();
        let incoming = process
            .take_stdout()
            .expect("child stdout missing")
            .compat();

        let capture = Arc::new(TextCapture::default());
        let client = TestAcpClient {
            capture: capture.clone(),
        };

        let incoming = LineBufferedRead::spawn_local(incoming);
        let (conn, handle_io) = acp::ClientSideConnection::new(client, outgoing, incoming, |fut| {
            tokio::task::spawn_local(fut);
        });
        tokio::task::spawn_local(handle_io);

        Self {
            conn,
            process,
            sandbox: Some(sandbox),
            capture,
        }
    }

    /// Initialize and authenticate (picks `api_key` auth method).
    pub async fn initialize(&self) -> acp::InitializeResponse {
        let init_resp = self
            .conn
            .initialize(
                acp::InitializeRequest::new(acp::ProtocolVersion::V1)
                    .client_capabilities(
                        acp::ClientCapabilities::new()
                            .fs(acp::FileSystemCapabilities::new())
                            .terminal(false),
                    )
                    .meta(
                        serde_json::json!({
                            "startupHints": {
                                "nonInteractive": true,
                                "skipGitStatus": true,
                                "skipProjectLayout": true
                            },
                            "clientType": "test-client",
                            "clientVersion": "0.0.0-test"
                        })
                        .as_object()
                        .cloned(),
                    ),
            )
            .await
            .expect("initialize failed");

        let api_key_method = init_resp
            .auth_methods
            .iter()
            .find(|m| &*m.id().0 == "fuigo.api_key")
            .unwrap_or_else(|| {
                let ids: Vec<_> = init_resp.auth_methods.iter().map(|m| &m.id().0).collect();
                panic!(
                    "expected auth method 'fuigo.api_key' but got: {ids:?}\n\
                     If the method ID changed, update this test."
                )
            });

        self.conn
            .authenticate(
                acp::AuthenticateRequest::new(api_key_method.id().clone())
                    .meta(serde_json::json!({"headless": true}).as_object().cloned()),
            )
            .await
            .expect("authenticate failed");

        init_resp
    }

    pub async fn create_session(&self, cwd: &Path) -> acp::SessionId {
        let resp = self
            .conn
            .new_session(acp::NewSessionRequest::new(cwd.to_path_buf()).mcp_servers(vec![]))
            .await
            .expect("session/new failed");
        resp.session_id
    }

    pub async fn create_session_with_model(&self, cwd: &Path, model_id: &str) -> acp::SessionId {
        let resp = self
            .conn
            .new_session(
                acp::NewSessionRequest::new(cwd.to_path_buf())
                    .mcp_servers(vec![])
                    .meta(
                        serde_json::json!({ "modelId": model_id })
                            .as_object()
                            .cloned(),
                    ),
            )
            .await
            .expect("session/new with modelId failed");
        resp.session_id
    }

    /// Switch model on an existing session via the typed ACP `session/set_model`.
    pub async fn set_model(
        &self,
        session_id: &acp::SessionId,
        model_id: &str,
    ) -> acp::Result<acp::SetSessionModelResponse> {
        use acp::Agent as _;
        self.conn
            .set_session_model(acp::SetSessionModelRequest::new(
                session_id.clone(),
                acp::ModelId::new(model_id),
            ))
            .await
    }

    pub async fn prompt(
        &self,
        session_id: &acp::SessionId,
        text: &str,
    ) -> acp::Result<acp::PromptResponse> {
        self.conn
            .prompt(acp::PromptRequest::new(
                session_id.clone(),
                vec![acp::ContentBlock::Text(acp::TextContent::new(
                    text.to_string(),
                ))],
            ))
            .await
    }

    pub fn captured_text(&self) -> String {
        self.capture.chunks.lock().unwrap().join("")
    }

    pub fn notification_count(&self) -> u32 {
        self.capture.notification_count.load(Ordering::SeqCst)
    }

    pub fn stderr(&self) -> String {
        self.process.stderr_tail().text
    }

    pub fn child_pid(&self) -> Option<u32> {
        self.process.pid()
    }

    pub fn process_diagnostics(&self) -> String {
        self.process.diagnostic_summary()
    }

    pub fn start_terminate(&mut self) -> std::io::Result<()> {
        self.process.start_terminate()
    }

    pub fn start_kill(&mut self) {
        self.process.start_kill();
    }

    pub async fn close(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.process.close().await
    }

    pub fn take_sandbox(&mut self) -> TestSandbox {
        self.sandbox.take().expect("test sandbox already taken")
    }

    pub fn sandbox(&self) -> &TestSandbox {
        self.sandbox.as_ref().expect("test sandbox already taken")
    }

    /// Logs elapsed time for tuning CI timeout budgets (visible with --nocapture).
    fn log_timing(what: &str, started: std::time::Instant) {
        eprintln!("[harness-timing] {what}: {:?}", started.elapsed());
    }

    pub async fn initialize_with_timeout(&self) -> acp::InitializeResponse {
        let started = std::time::Instant::now();
        let r = tokio::time::timeout(scaled(Duration::from_secs(20)), self.initialize())
            .await
            .unwrap_or_else(|_| panic!("initialize timed out\nstderr:\n{}", self.stderr()));
        Self::log_timing("initialize", started);
        r
    }

    pub async fn create_session_with_timeout(&self, cwd: &Path) -> acp::SessionId {
        let started = std::time::Instant::now();
        let r = tokio::time::timeout(scaled(Duration::from_secs(20)), self.create_session(cwd))
            .await
            .unwrap_or_else(|_| panic!("session/new timed out\nstderr:\n{}", self.stderr()));
        Self::log_timing("session/new", started);
        r
    }

    pub async fn create_session_with_model_timeout(
        &self,
        cwd: &Path,
        model_id: &str,
    ) -> acp::SessionId {
        tokio::time::timeout(
            scaled(Duration::from_secs(20)),
            self.create_session_with_model(cwd, model_id),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "session/new with modelId={model_id} timed out\nstderr:\n{}",
                self.stderr()
            )
        })
    }

    pub async fn set_model_with_timeout(
        &self,
        session_id: &acp::SessionId,
        model_id: &str,
    ) -> acp::Result<acp::SetSessionModelResponse> {
        tokio::time::timeout(
            scaled(Duration::from_secs(20)),
            self.set_model(session_id, model_id),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "session/set_model({model_id}) timed out\nstderr:\n{}",
                self.stderr()
            )
        })
    }

    pub async fn prompt_with_timeout(
        &self,
        session_id: &acp::SessionId,
        text: &str,
    ) -> acp::Result<acp::PromptResponse> {
        let started = std::time::Instant::now();
        let r = tokio::time::timeout(
            scaled(Duration::from_secs(30)),
            self.prompt(session_id, text),
        )
        .await
        .unwrap_or_else(|_| panic!("prompt timed out\nstderr:\n{}", self.stderr()));
        Self::log_timing("prompt", started);
        r
    }

    pub async fn load_session_with_timeout(
        &self,
        session_id: &acp::SessionId,
        cwd: &Path,
    ) -> acp::LoadSessionResponse {
        // 60s: session/load replays history and is slower under Rosetta (macos-x86_64 lifecycle CI)
        // 20s flaked repeatedly there
        tokio::time::timeout(
            scaled(Duration::from_secs(60)),
            self.conn.load_session(
                acp::LoadSessionRequest::new(session_id.clone(), cwd.to_path_buf())
                    .mcp_servers(vec![]),
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("session/load timed out\nstderr:\n{}", self.stderr()))
        .expect("session/load failed")
    }

    pub async fn ext_method(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> acp::Result<acp::ExtResponse> {
        let raw = serde_json::value::RawValue::from_string(params.to_string())
            .expect("serialize ext params");
        self.conn
            .ext_method(acp::ExtRequest::new(method, std::sync::Arc::from(raw)))
            .await
    }
}

/// How a [`RawStdioClient`] answers one agent-to-client request.
/// An answer callback may return this or an `Option<serde_json::Value>` (`Some` = result, `None` = refuse).
#[derive(Debug, Clone)]
pub enum RawReply {
    /// Reply with this `result`.
    Result(serde_json::Value),
    /// Reply with a `-32601` error.
    Refuse,
    /// Send nothing now: the caller answers later with [`RawStdioClient::respond`], so a test can hold a
    /// decision open and observe the agent while it is pending.
    Defer,
}

impl From<Option<serde_json::Value>> for RawReply {
    fn from(answer: Option<serde_json::Value>) -> Self {
        answer.map_or(Self::Refuse, Self::Result)
    }
}

/// Drives `fuigo agent stdio` with verbatim newline-delimited JSON-RPC lines.
///
/// Exists for wire shapes the typed [`FuigoStdioClient`] (`ClientSideConnection`, integer ids) can never produce.
/// Example: Xcode's Swift/Foundation `JSONEncoder` output, with escaped-slash methods (`"session\/prompt"`) and string UUID request ids.
/// Child process is killed on drop.
pub struct RawStdioClient {
    stdin: tokio::process::ChildStdin,
    stdout: tokio::io::BufReader<crate::process::TestProcessStdout>,
    process: TestProcess,
    sandbox: TestSandbox,
    /// Every stdout line the agent wrote, verbatim (trailing newline stripped), in arrival order.
    transcript: Vec<String>,
    /// Bytes of a line not yet terminated. Kept across a timed-out read (`read_until` appends what it
    /// read before being cancelled), so a deadline never drops or splits a message.
    pending: Vec<u8>,
}

impl RawStdioClient {
    pub async fn spawn(server: &MockInferenceServer, cwd: &Path) -> Self {
        Self::spawn_with_spec(server, cwd, TestSandbox::new(), &AgentSpawnSpec::default()).await
    }

    /// Spawn with full control of both argv halves and the child env (see [`AgentSpawnSpec`]).
    pub async fn spawn_with_spec(
        server: &MockInferenceServer,
        cwd: &Path,
        mut sandbox: TestSandbox,
        spec: &AgentSpawnSpec<'_>,
    ) -> Self {
        let mut process = spawn_agent_process_with(&mut sandbox, server, cwd, spec);

        let stdin = process.take_stdin().expect("child stdin missing");
        let child_stdout = process.take_stdout().expect("child stdout missing");

        Self {
            stdin,
            stdout: tokio::io::BufReader::new(child_stdout),
            process,
            sandbox,
            transcript: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// The sandbox the child runs in (its `HOME`, `FUIGO_HOME`, and effective env).
    pub fn sandbox(&self) -> &TestSandbox {
        &self.sandbox
    }

    /// Every stdout line received so far, verbatim, in arrival order.
    pub fn transcript(&self) -> &[String] {
        &self.transcript
    }

    /// Send one JSON-RPC request with a string `id` and wait for its response.
    /// Agent-to-client requests that arrive meanwhile go to `answer`: `Some(result)` replies with that
    /// result, `None` refuses with `-32601`.
    /// One scaled deadline covers the whole exchange, the request write and every reply write included,
    /// so an agent that stops draining stdin fails the test instead of hanging it.
    pub async fn request<R: Into<RawReply>>(
        &mut self,
        id: &str,
        method: &str,
        params: serde_json::Value,
        timeout: Duration,
        answer: impl FnMut(&serde_json::Value) -> R,
    ) -> serde_json::Value {
        let line = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let deadline = tokio::time::Instant::now() + scaled(timeout);
        self.send_line_until(&line.to_string(), deadline, method).await;
        self.response_until(id, method, timeout, deadline, answer).await
    }

    /// Answer an agent-to-client request (one the callback deferred, or one a wait returned) with `result`.
    /// The write is bounded by `timeout`.
    pub async fn respond(&mut self, id: &serde_json::Value, result: serde_json::Value, timeout: Duration) {
        let line = serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result });
        let deadline = tokio::time::Instant::now() + scaled(timeout);
        self.send_line_until(&line.to_string(), deadline, "respond").await;
    }

    /// [`Self::send_line`] bounded by `deadline`; a write still blocked at the deadline panics.
    async fn send_line_until(&mut self, line: &str, deadline: tokio::time::Instant, what: &str) {
        if tokio::time::timeout_at(deadline, self.send_line(line))
            .await
            .is_err()
        {
            panic!(
                "{what}: writing to the agent's stdin was still blocked at the deadline (the agent stopped reading)\nstderr:\n{}",
                stderr_tail(&self.stderr(), 1200)
            );
        }
    }

    /// Read until a message satisfying `matches` arrives and return it; `None` if `timeout` passes first.
    /// Agent-to-client requests that do not match are answered by `answer` (see [`Self::request`]).
    /// A closed stdout panics: a dead child is never "no message".
    pub async fn wait_for_message<R: Into<RawReply>>(
        &mut self,
        what: &str,
        timeout: Duration,
        mut matches: impl FnMut(&serde_json::Value) -> bool,
        mut answer: impl FnMut(&serde_json::Value) -> R,
    ) -> Option<serde_json::Value> {
        let deadline = tokio::time::Instant::now() + scaled(timeout);
        loop {
            let msg = self.next_message_until(what, deadline).await?;
            if matches(&msg) {
                return Some(msg);
            }
            self.answer_if_request(&msg, &mut answer, deadline, what).await;
        }
    }

    /// The next complete stdout line before `deadline`, newline stripped and recorded in the transcript:
    /// `Some(Some(line))`; `Some(None)` at end of stream; `None` on deadline.
    /// The one framing path for every reader on this client. Cancellation-safe: `read_until` keeps the
    /// bytes it read before a deadline in `pending`, and the next call completes that line. Bytes are
    /// decoded only once the line is complete; invalid UTF-8 is a hard failure (ACP is UTF-8 JSON),
    /// never silently repaired.
    async fn read_line_until(
        &mut self,
        what: &str,
        deadline: tokio::time::Instant,
    ) -> Option<Option<String>> {
        use tokio::io::AsyncBufReadExt as _;

        let next = self.stdout.read_until(b'\n', &mut self.pending);
        let read = tokio::time::timeout_at(deadline, next)
            .await
            .ok()?
            .unwrap_or_else(|e| panic!("{what}: agent stdout read failed: {e}"));
        if read == 0 && self.pending.is_empty() {
            return Some(None);
        }
        let line = String::from_utf8(std::mem::take(&mut self.pending))
            .unwrap_or_else(|e| panic!("{what}: the agent wrote invalid UTF-8 on stdout: {e}"));
        let line = line.trim_end_matches(['\n', '\r']).to_owned();
        self.transcript.push(line.clone());
        Some(Some(line))
    }

    /// Read one message before `deadline`; `None` on deadline. Non-JSON lines are recorded and skipped.
    async fn next_message_until(
        &mut self,
        what: &str,
        deadline: tokio::time::Instant,
    ) -> Option<serde_json::Value> {
        loop {
            let Some(line) = self.read_line_until(what, deadline).await? else {
                panic!(
                    "{what}: agent closed stdout ({} lines seen)\nstderr:\n{}",
                    self.transcript.len(),
                    stderr_tail(&self.stderr(), 1200)
                );
            };
            if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) {
                return Some(msg);
            }
        }
    }

    /// If `msg` is an agent-to-client request, reply: `answer` decides the result, `None` refuses.
    async fn answer_if_request<R: Into<RawReply>>(
        &mut self,
        msg: &serde_json::Value,
        answer: &mut impl FnMut(&serde_json::Value) -> R,
        deadline: tokio::time::Instant,
        what: &str,
    ) {
        let (Some(_), Some(req_id)) = (msg.get("method"), msg.get("id")) else {
            return;
        };
        let reply = match answer(msg).into() {
            RawReply::Result(result) => {
                serde_json::json!({ "jsonrpc": "2.0", "id": req_id, "result": result })
            }
            RawReply::Refuse => serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": { "code": -32601, "message": "unsupported by raw test client" },
            }),
            RawReply::Defer => return,
        };
        self.send_line_until(&reply.to_string(), deadline, what).await;
    }

    /// [`Self::response_for_id`] with agent-to-client requests answered by `answer` instead of refused.
    pub async fn response_for_id_answering<R: Into<RawReply>>(
        &mut self,
        id: &str,
        what: &str,
        timeout: Duration,
        answer: impl FnMut(&serde_json::Value) -> R,
    ) -> serde_json::Value {
        let deadline = tokio::time::Instant::now() + scaled(timeout);
        self.response_until(id, what, timeout, deadline, answer).await
    }

    /// Read until the response to `id`, answering agent-to-client requests, all before `deadline`.
    async fn response_until<R: Into<RawReply>>(
        &mut self,
        id: &str,
        what: &str,
        timeout: Duration,
        deadline: tokio::time::Instant,
        mut answer: impl FnMut(&serde_json::Value) -> R,
    ) -> serde_json::Value {
        let seen_before = self.transcript.len();
        loop {
            let Some(msg) = self.next_message_until(what, deadline).await else {
                let seen = &self.transcript[seen_before..];
                let tail: Vec<String> = seen
                    .iter()
                    .rev()
                    .take(3)
                    .map(|l| l.chars().take(200).collect())
                    .collect();
                panic!(
                    "{what}: no response to id {id:?} within {timeout:?} ({} other lines seen; last: {tail:?})\nstderr:\n{}",
                    seen.len(),
                    stderr_tail(&self.stderr(), 1200)
                );
            };
            if msg.get("method").is_none() && msg.get("id").and_then(|v| v.as_str()) == Some(id) {
                return msg;
            }
            self.answer_if_request(&msg, &mut answer, deadline, what).await;
        }
    }

    pub fn stderr(&self) -> String {
        self.process.stderr_tail().text
    }

    pub fn child_pid(&self) -> Option<u32> {
        self.process.pid()
    }

    pub fn process_diagnostics(&self) -> String {
        self.process.diagnostic_summary()
    }

    pub fn start_terminate(&mut self) -> std::io::Result<()> {
        self.process.start_terminate()
    }

    pub fn start_kill(&mut self) {
        self.process.start_kill();
    }

    pub async fn close(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.process.close().await
    }

    /// Write `line` verbatim followed by `\n`, and flush.
    pub async fn send_line(&mut self, line: &str) {
        use tokio::io::AsyncWriteExt as _;

        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write line to agent stdin");
        self.stdin.write_all(b"\n").await.expect("write newline");
        self.stdin.flush().await.expect("flush agent stdin");
    }

    /// Read stdout lines until the response to `id` arrives: a message with no `method` key and an exact string-id match.
    /// Returning is itself the id-echo assertion: an id echoed with different bytes or as a different JSON type never matches.
    /// Notifications are skipped.
    /// Any agent-to-client request is refused with a JSON-RPC error so a turn can never hang on this client, which advertises no capabilities.
    /// On timeout the panic reports how much non-matching traffic was seen and the last few lines.
    /// Zero traffic means true silence, the acp-0.6 escaped-method symptom.
    pub async fn response_for_id(
        &mut self,
        id: &str,
        what: &str,
        timeout: Duration,
    ) -> serde_json::Value {
        let deadline = tokio::time::Instant::now() + scaled(timeout);
        let mut skipped = 0_usize;
        let mut skipped_tail: Vec<String> = Vec::new();
        loop {
            // Shared framing (`read_line_until`), so this reader and the answering readers never split a
            // line between them after a timed-out read.
            let Some(next) = self.read_line_until(what, deadline).await else {
                panic!(
                    "{what}: no matching response within {timeout:?} ({skipped} other messages \
                     seen; last: {skipped_tail:?})\nstderr:\n{}",
                    stderr_tail(&self.stderr(), 1200)
                );
            };
            let Some(line) = next else {
                panic!(
                    "{what}: agent closed stdout before responding ({skipped} other messages \
                     seen)\nstderr:\n{}",
                    stderr_tail(&self.stderr(), 1200)
                );
            };
            let Ok(msg) = serde_json::from_str::<serde_json::Value>(line.trim_end()) else {
                push_skipped_tail(&mut skipped, &mut skipped_tail, &line);
                continue;
            };
            let is_response = msg.get("method").is_none();
            if is_response && msg.get("id").and_then(|v| v.as_str()) == Some(id) {
                return msg;
            }
            push_skipped_tail(&mut skipped, &mut skipped_tail, &line);
            if !is_response && let Some(req_id) = msg.get("id") {
                let refusal = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": { "code": -32601, "message": "unsupported by raw test client" },
                });
                self.send_line(&refusal.to_string()).await;
            }
        }
    }
}

/// Record a non-matching line for [`RawStdioClient::response_for_id`]'s timeout diagnostics: bump the count, keep the last 3 lines (truncated).
fn push_skipped_tail(skipped: &mut usize, tail: &mut Vec<String>, line: &str) {
    *skipped += 1;
    if tail.len() == 3 {
        tail.remove(0);
    }
    tail.push(line.trim_end().chars().take(200).collect());
}
