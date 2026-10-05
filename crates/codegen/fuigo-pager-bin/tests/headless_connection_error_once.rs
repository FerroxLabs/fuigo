//! P51: a headless failure is reported exactly once per failure, for every `--output-format`, at the
//! PROCESS boundary (the built `fuigo-pager` binary, `-p`).
//!
//! Before the fix, plain wrote the message from the emitter's `on_error` AND `main` wrote
//! `Error: <message>` for the returned `Err`, so a script saw the same failure twice on stderr. The
//! machine formats keep their one structured terminal event on stdout, and `main`'s stderr line stays
//! the human channel (one line). Failure classes covered: connection refused, `--timeout`, `--max-turns`.

// Unix only: the process fixture sends real signals (`libc` is a Unix-only dependency of this package).
#![cfg(unix)]

use std::io::Read as _;
use std::process::Stdio;
use std::time::Duration;

use fuigo_test_support::{
    InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, ScriptedResponse, TestSandbox,
    refused_loopback_url, sse,
};

const FORMATS: [&str; 4] = ["plain", "json", "streaming-json", "streaming-messages-json"];

fn pager_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Spawn `fuigo-pager <args>` in `sandbox` (retries off so a refused connection fails at once), run it
/// to the end, and capture both streams. `interrupt_when` is polled until true, then `signal` is sent.
fn run_child(
    sandbox: &TestSandbox,
    args: &[&str],
    interrupt_when: Option<&dyn Fn() -> bool>,
    signal: i32,
) -> Out {
    let mut cmd = std::process::Command::new(pager_binary());
    sandbox.apply_to_std_command(&mut cmd);
    cmd.env("FUIGO_MAX_RETRIES", "0")
        .args(args)
        .current_dir(sandbox.workspace())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[allow(clippy::disallowed_methods)] // test-owned child, waited on (or killed and reaped) in this function
    let mut child = cmd.spawn().expect("spawn fuigo-pager");
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let (tx_out, rx_out) = std::sync::mpsc::channel();
    let (tx_err, rx_err) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        let _ = tx_out.send(String::from_utf8_lossy(&b).into_owned());
    });
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        let _ = tx_err.send(String::from_utf8_lossy(&b).into_owned());
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    let mut interrupted = interrupt_when.is_none();
    let status = loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            break st;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the run must end on its own: {args:?}");
        }
        if !interrupted && interrupt_when.is_some_and(|ready| ready()) {
            // SAFETY: plain kill(2) on our own child's pid.
            let rc = unsafe { libc::kill(child.id() as i32, signal) };
            assert_eq!(rc, 0, "kill({signal}) on the child failed");
            interrupted = true;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    // Bounded: a descendant that kept a pipe open must fail the test, not hang it.
    let collect = |rx: std::sync::mpsc::Receiver<String>, what: &str| {
        rx.recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|_| panic!("{what} did not close after the run ended: {args:?}"))
    };
    Out {
        code: status.code(),
        stdout: collect(rx_out, "stdout"),
        stderr: collect(rx_err, "stderr"),
    }
}

/// A mock inference server whose first streamed chunk is held for two minutes: the session starts
/// normally, then the turn hangs until a timeout or a signal ends the run.
async fn hung_turn_server() -> std::sync::Arc<MockInferenceServer> {
    let server = MockInferenceServer::start().await.expect("start the mock inference server");
    server.preset_allow_access();
    server.set_chunk_delay(Some(Duration::from_secs(120)));
    let _ = (
        server.expect_response(
            "hung turn (responses)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
            ScriptedResponse::sse(sse::responses_api_reasoning_then_tool_call_events(
                "", "call-1", TOOL, "{}", "test-model",
            )),
        ),
        server.expect_response(
            "hung turn (chat completions)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::sse(sse::chat_completions_reasoning_then_tool_call_events(
                "", "call-1", TOOL, "{}", "test-model",
            )),
        ),
    );
    std::sync::Arc::new(server)
}

/// Whether the prompt's model request has reached the server (the turn is now in flight).
fn turn_in_flight(server: &MockInferenceServer) -> bool {
    server.requests().iter().any(|e| {
        e.method == "POST" && (e.path.contains("completions") || e.path.contains("responses"))
    })
}

fn sandbox_for(url: String) -> TestSandbox {
    TestSandbox::builder().git().mock_url(url).build()
}

fn occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// Every stdout line of the machine formats must be one JSON value; returns them.
fn json_lines(format: &str, stdout: &str) -> Vec<serde_json::Value> {
    if format == "json" {
        // The `json` format's whole stdout is one JSON document.
        return vec![serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("json: stdout must be exactly one JSON value ({e}):\n{stdout}")
        })];
    }
    stdout
        .lines()
        .map(|l| {
            serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("{format}: every stdout line must be JSON ({e}): {l:?}"))
        })
        .collect()
}

/// The text after `Error: ` on the one stderr line `main` writes for the returned `Err`.
fn main_error_message(stderr: &str) -> String {
    let lines: Vec<&str> = stderr.lines().filter(|l| l.starts_with("Error: ")).collect();
    assert_eq!(lines.len(), 1, "main must write exactly one `Error:` line\nstderr:\n{stderr}");
    lines[0]["Error: ".len()..].to_string()
}

/// Where a failed run's structured terminal event lives on the machine formats.
#[derive(Clone, Copy, PartialEq)]
enum Terminal {
    /// The error line IS the terminal document (`{"type":"error"}` / a `result` carrying the error).
    ErrorEvent,
    /// The run produced its own terminal document (`--max-turns`); the failure is `main`'s line.
    OwnDocument,
}

/// The one-failure contract for a run that exits non-zero with `main`'s `Error:` line.
fn assert_reported_once(format: &str, out: &Out, needle: &str, exit_code: i32, terminal: Terminal) {
    assert_eq!(out.code, Some(exit_code), "{format}: exit code\nstdout:\n{}\nstderr:\n{}", out.stdout, out.stderr);
    let msg = main_error_message(&out.stderr);
    assert!(msg.contains(needle), "{format}: unexpected message: {msg}");
    assert_eq!(
        occurrences(&out.stderr, &msg),
        1,
        "{format}: the failure must be printed once on stderr\nstderr:\n{}",
        out.stderr
    );
    // Nothing else on stderr: a second differently-worded line for the same failure is a duplicate too.
    let stderr_lines = out.stderr.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(stderr_lines, 1, "{format}: exactly one stderr line\nstderr:\n{}", out.stderr);
    let lines = json_lines_or_empty(format, &out.stdout);
    match format {
        // Plain prints a completed answer on stdout; a failure itself is never written there.
        "plain" if terminal == Terminal::OwnDocument => {}
        "plain" => assert_eq!(out.stdout.trim(), "", "plain prints no failure text on stdout"),
        "json" => {
            assert_eq!(lines.len(), 1, "{}", out.stdout);
            if terminal == Terminal::ErrorEvent {
                assert_eq!(lines[0]["type"], "error", "{}", out.stdout);
            }
        }
        "streaming-json" => {
            let errors = lines.iter().filter(|v| v["type"] == "error").count();
            let ends = lines.iter().filter(|v| v["type"] == "end").count();
            match terminal {
                Terminal::ErrorEvent => assert_eq!((errors, ends), (1, 0), "{}", out.stdout),
                Terminal::OwnDocument => assert_eq!((errors, ends), (0, 1), "{}", out.stdout),
            }
        }
        "streaming-messages-json" => {
            let results = lines.iter().filter(|v| v["type"] == "result").count();
            assert_eq!(results, 1, "{format}: exactly one terminal result\n{}", out.stdout);
        }
        other => panic!("unhandled format {other}"),
    }
    if format != "plain" && terminal == Terminal::ErrorEvent {
        assert_eq!(occurrences(&out.stdout, &msg), 1, "{format}: stdout\n{}", out.stdout);
    }
}

fn json_lines_or_empty(format: &str, stdout: &str) -> Vec<serde_json::Value> {
    if format == "plain" { Vec::new() } else { json_lines(format, stdout) }
}

#[test]
fn a_connection_error_is_reported_exactly_once_in_every_format() {
    for format in FORMATS {
        let sandbox = sandbox_for(refused_loopback_url());
        let out = run_child(&sandbox, &["-p", "say hi", "--trust", "--output-format", format], None, libc::SIGINT);
        assert_reported_once(format, &out, "error sending request", 1, Terminal::ErrorEvent);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timeout_is_reported_exactly_once_in_every_format() {
    for format in FORMATS {
        let server = hung_turn_server().await;
        let sandbox = sandbox_for(server.url());
        let out = tokio::task::spawn_blocking(move || {
            run_child(
                &sandbox,
                &["-p", "say hi", "--trust", "--timeout", "12", "--output-format", format],
                None,
                libc::SIGINT,
            )
        })
        .await
        .unwrap();
        assert_reported_once(format, &out, "Timed out after 12s", 1, Terminal::ErrorEvent);
    }
}

const TOOL: &str = "search_replace";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_turns_is_reported_exactly_once_in_every_format() {
    for format in FORMATS {
        let server = MockInferenceServer::start().await.expect("start the mock inference server");
        server.preset_allow_access();
        let sandbox = sandbox_for(server.url());
        let target = sandbox.workspace().join("edit_me.txt");
        std::fs::write(&target, "old line\n").unwrap();
        let arguments = serde_json::json!({
            "file_path": target.to_string_lossy(),
            "old_string": "old line",
            "new_string": "new line",
        })
        .to_string();
        let _e1 = server.expect_response(
            "tool call (responses)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
            ScriptedResponse::sse(sse::responses_api_reasoning_then_tool_call_events(
                "", "call-1", TOOL, &arguments, "test-model",
            )),
        );
        let _e2 = server.expect_response(
            "tool call (chat completions)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::sse(sse::chat_completions_reasoning_then_tool_call_events(
                "", "call-1", TOOL, &arguments, "test-model",
            )),
        );
        let fmt = format.to_string();
        let out = tokio::task::spawn_blocking(move || {
            run_child(
                &sandbox,
                &["-p", "edit", "--trust", "--yolo", "--max-turns", "1", "--output-format", &fmt],
                None,
                libc::SIGINT,
            )
        })
        .await
        .unwrap();
        assert_reported_once(format, &out, "max turns reached", 1, Terminal::OwnDocument);
    }
}

/// Ctrl-C / SIGTERM under `-p`: the run ends with the conventional `128 + signal` code, the failure is
/// reported once (the machine formats' structured terminal event, `main`'s one `Error:` line), and
/// output already streamed stays on stdout. Before P51 the process died to the default disposition:
/// no line, no terminal event, owned children not reaped.
async fn interrupted_run(format: &'static str, signal: i32) -> (Out, &'static str) {
    let server = hung_turn_server().await;
    let sandbox = sandbox_for(server.url());
    let srv = server.clone();
    let out = tokio::task::spawn_blocking(move || {
        let ready = || turn_in_flight(&srv);
        run_child(&sandbox, &["-p", "say hi", "--trust", "--output-format", format], Some(&ready), signal)
    })
    .await
    .unwrap();
    (
        out,
        match signal {
            libc::SIGTERM => "SIGTERM",
            libc::SIGHUP => "SIGHUP",
            _ => "SIGINT",
        },
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigint_is_reported_exactly_once_and_exits_130_in_every_format() {
    for format in FORMATS {
        let (out, name) = interrupted_run(format, libc::SIGINT).await;
        assert_reported_once(format, &out, &format!("Interrupted by {name}"), 130, Terminal::ErrorEvent);
        if format == "streaming-json" {
            let lines = json_lines(format, &out.stdout);
            assert!(
                lines.iter().any(|v| v["type"] == "available_commands"),
                "output streamed before the interrupt stays flushed on stdout:\n{}",
                out.stdout
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_exits_143_with_the_one_report() {
    let (out, name) = interrupted_run("json", libc::SIGTERM).await;
    assert_reported_once("json", &out, &format!("Interrupted by {name}"), 143, Terminal::ErrorEvent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sighup_exits_129_with_the_one_report() {
    let (out, name) = interrupted_run("plain", libc::SIGHUP).await;
    assert_reported_once("plain", &out, &format!("Interrupted by {name}"), 129, Terminal::ErrorEvent);
}

// ---------------------------------------------------------------------------------------------
// An interrupt AFTER the turn completed (a background task keeps the run waiting), and the reaping
// of the run's children.
// ---------------------------------------------------------------------------------------------

const ANSWER: &str = "ANSWER_MARKER_42";

/// Whether `pid` is no longer a running process. A zombie (state `Z`) counts as gone on purpose: it
/// has been killed and only awaits a parent's `wait`, which in a container may be an init that never
/// reaps; what this test guards is a task that is still RUNNING after the run ended.
fn process_is_gone(pid: i32) -> bool {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => true,
            Ok(stat) => stat.rsplit(") ").next().is_some_and(|rest| rest.starts_with('Z')),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: signal 0 only probes for existence.
        let rc = unsafe { libc::kill(pid, 0) };
        rc != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
}

/// Turn 1: the model backgrounds a long sleep (recording its pid). Turn 2: it answers `ANSWER`. The
/// turn is then complete and the run waits on the background task, which is when the signal lands.
async fn completed_then_interrupted(format: &'static str) -> (Out, i32) {
    let server = std::sync::Arc::new(
        MockInferenceServer::start().await.expect("start the mock inference server"),
    );
    server.preset_allow_access();
    let sandbox = sandbox_for(server.url());
    let pidfile = sandbox.workspace().join("bg.pid");
    let command = format!("echo $$ > {}; exec /bin/sleep 600", pidfile.display());
    let arguments = serde_json::json!({
        "command": command,
        "description": "background child for the interrupt test",
        "is_background": true,
    })
    .to_string();
    let _tool_turns = [
        server.expect_response(
            "bg tool call (responses)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
            ScriptedResponse::sse(sse::responses_api_reasoning_then_tool_call_events(
                "", "call-bg", "run_terminal_command", &arguments, "test-model",
            )),
        ),
        server.expect_response(
            "bg tool call (chat completions)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::sse(sse::chat_completions_reasoning_then_tool_call_events(
                "", "call-bg", "run_terminal_command", &arguments, "test-model",
            )),
        )
    ];
    let answer_turns = [
        server.expect_response(
            "answer (responses)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
            ScriptedResponse::sse(sse::responses_api_script_exact(ANSWER, "test-model")),
        ),
        server.expect_response(
            "answer (chat completions)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::sse(sse::chat_completion_script_exact(ANSWER, "test-model")),
        ),
    ];
    let pf = pidfile.clone();
    let (out, pid) = tokio::task::spawn_blocking(move || {
        let first_ready = std::cell::Cell::new(None::<std::time::Instant>);
        // Then a short margin for the run to process the response and settle into the background wait.
        let ready = || {
            // The answer turn has been fully served (observable on the mock), the task recorded its pid.
            if answer_turns.iter().any(|e| e.is_satisfied()) && pf.exists() {
                let t = first_ready.get().unwrap_or_else(|| {
                    let now = std::time::Instant::now();
                    first_ready.set(Some(now));
                    now
                });
                t.elapsed() > Duration::from_secs(8)
            } else {
                false
            }
        };
        let out = run_child(
            &sandbox,
            &["-p", "start a background task, then answer", "--trust", "--yolo", "--output-format", format],
            Some(&ready),
            libc::SIGINT,
        );
        // Read the pid before the sandbox (and with it the pid file) is dropped with this closure.
        let pid = std::fs::read_to_string(&pf).ok().and_then(|t| t.trim().parse::<i32>().ok());
        (out, pid)
    })
    .await
    .unwrap();
    let pid = pid.unwrap_or_else(|| {
        panic!(
            "{format}: the background task recorded no pid\ncode={:?}\nstdout:\n{}\nstderr:\n{}\nrequests:\n{}",
            out.code,
            out.stdout,
            out.stderr,
            server.request_log_summary()
        )
    });
    (out, pid)
}

/// The completed turn's answer and usage, read from the terminal document of each format (not grepped
/// from the whole stream), with the interrupt on that same document exactly once.
fn assert_answer_and_usage_preserved(format: &str, out: &Out) {
    let tokens = |v: &serde_json::Value| v["output_tokens"].as_u64().unwrap_or(0);
    let lines = json_lines_or_empty(format, &out.stdout);
    match format {
        "plain" => {
            // Plain has no usage representation; its answer is the streamed text, whole and alone.
            assert_eq!(out.stdout.trim(), ANSWER, "plain: stdout\n{}", out.stdout);
        }
        "json" => {
            let doc = &lines[0];
            assert_eq!(doc["text"], ANSWER, "json: {doc}");
            assert!(tokens(&doc["usage"]) > 0, "json: usage of the completed turn: {doc}");
            assert_eq!(doc["error"], "Interrupted by SIGINT; exiting 130", "json: {doc}");
        }
        "streaming-json" => {
            let text: String = lines
                .iter()
                .filter(|v| v["type"] == "text")
                .filter_map(|v| v["data"].as_str())
                .collect();
            assert_eq!(text, ANSWER, "streaming-json: streamed answer\n{}", out.stdout);
            assert!(
                lines.iter().any(|v| v["type"] == "usage" && tokens(&v["usage"]) > 0),
                "streaming-json: usage event\n{}",
                out.stdout
            );
            let ends: Vec<_> = lines.iter().filter(|v| v["type"] == "end").collect();
            assert_eq!(ends.len(), 1, "{}", out.stdout);
            assert_eq!(ends[0]["error"], "Interrupted by SIGINT; exiting 130", "{}", ends[0]);
            assert!(lines.iter().all(|v| v["type"] != "error"), "no second terminal record\n{}", out.stdout);
        }
        "streaming-messages-json" => {
            let result = lines.iter().find(|v| v["type"] == "result").expect("one result");
            // This format reports a turn's usage on its assistant message line; the error result
            // (no completed PromptResponse behind it) carries zeros, as it does for any error.
            assert!(
                lines.iter().any(|v| v["type"] == "assistant" && tokens(&v["message"]["usage"]) > 0),
                "messages: usage on the assistant message\n{}",
                out.stdout
            );
            assert_eq!(
                result["errors"],
                serde_json::json!(["Interrupted by SIGINT; exiting 130"]),
                "messages: {result}"
            );
            let text: String = lines
                .iter()
                .filter(|v| v["type"] == "assistant")
                .flat_map(|v| v["message"]["content"].as_array().cloned().unwrap_or_default())
                .filter(|b| b["type"] == "text")
                .filter_map(|b| b["text"].as_str().map(str::to_string))
                .collect();
            assert_eq!(text, ANSWER, "messages: the answer text blocks, exactly\n{}", out.stdout);
        }
        other => panic!("unhandled format {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupt_after_a_completed_response_keeps_the_answer_and_usage_in_every_format() {
    for format in FORMATS {
        let (out, pid) = completed_then_interrupted(format).await;
        // The turn completed first, so every format carries the interrupt on its ONE terminal document.
        let terminal = Terminal::OwnDocument;
        assert_reported_once(format, &out, "Interrupted by SIGINT", 130, terminal);
        assert!(
            out.stdout.contains(ANSWER),
            "{format}: the completed answer must survive the interrupt\nstdout:\n{}",
            out.stdout
        );
        assert_answer_and_usage_preserved(format, &out);
        // Children of the run: the backgrounded task must not outlive it.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !process_is_gone(pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(process_is_gone(pid), "{format}: background task {pid} survived the interrupted run");
    }
}

/// An interrupt while the SECOND model request is still pending: the first response (the tool call)
/// completed and was billed, so every format's terminal record must carry that spend, not zeros.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupt_mid_turn_reports_the_usage_already_spent_in_every_format() {
    for format in ["json", "streaming-json", "streaming-messages-json"] {
        let server = std::sync::Arc::new(
            MockInferenceServer::start().await.expect("start the mock inference server"),
        );
        server.preset_allow_access();
        let sandbox = sandbox_for(server.url());
        let arguments = serde_json::json!({
            "command": "echo hi",
            "description": "quick command",
        })
        .to_string();
        let _turn1 = [
            server.expect_response(
                "tool call (responses)",
                InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
                ScriptedResponse::sse(sse::responses_api_reasoning_then_tool_call_events(
                    "", "call-1", "run_terminal_command", &arguments, "test-model",
                )),
            ),
            server.expect_response(
                "tool call (chat completions)",
                InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
                ScriptedResponse::sse(sse::chat_completions_reasoning_then_tool_call_events(
                    "", "call-1", "run_terminal_command", &arguments, "test-model",
                )),
            ),
        ];
        // The follow-up request is received and then held: the turn cannot finish.
        let _turn2 = [
            server.expect_response_blocked(
                "held answer (responses)",
                InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
                ScriptedResponse::sse(sse::responses_api_script_exact(ANSWER, "test-model")),
            ),
            server.expect_response_blocked(
                "held answer (chat completions)",
                InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
                ScriptedResponse::sse(sse::chat_completion_script_exact(ANSWER, "test-model")),
            ),
        ];
        let srv = server.clone();
        let out = tokio::task::spawn_blocking(move || {
            let posts = || {
                srv.requests()
                    .iter()
                    .filter(|e| e.method == "POST" && (e.path.contains("completions") || e.path.contains("responses")))
                    .count()
            };
            let ready = || posts() >= 2;
            run_child(
                &sandbox,
                &["-p", "run a command", "--trust", "--yolo", "--output-format", format],
                Some(&ready),
                libc::SIGINT,
            )
        })
        .await
        .unwrap();
        assert_eq!(out.code, Some(130), "{format}: {}\n{}", out.stdout, out.stderr);
        let lines = json_lines(format, &out.stdout);
        let terminal = lines
            .iter()
            .rev()
            .find(|v| matches!(v["type"].as_str(), Some("error" | "result")))
            .unwrap_or_else(|| panic!("{format}: no terminal record\n{}", out.stdout));
        assert!(
            terminal["usage"]["output_tokens"].as_u64().unwrap_or(0) > 0,
            "{format}: the spent usage must be on the terminal record\n{terminal}"
        );
    }
}
