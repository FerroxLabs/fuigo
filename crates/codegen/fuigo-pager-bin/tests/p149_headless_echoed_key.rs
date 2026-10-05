//! P149 (S8, live lane C2 D1): at the PROCESS boundary (the built `fuigo-pager` binary, `-p`), a provider that
//! echoes the API key this process sent back in its error text must not get that key printed: not on `main`'s
//! `Error:` stderr line, and not in any `--output-format`'s stdout. The TUI and ACP clients already showed
//! `<redacted>`; the headless printer used to print the key verbatim (the in-process agent gateway bypassed the
//! ACP reply-rail scrub). Synthetic credentials only.

#![cfg(unix)]

use std::io::Read as _;
use std::process::Stdio;
use std::time::Duration;

use fuigo_test_support::{
    InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, ScriptedResponse, TestSandbox,
};

const FORMATS: [&str; 4] = ["plain", "json", "streaming-json", "streaming-messages-json"];
const SENT: &str = "fuigo-p149-SYNTH-process-key-0001";

fn pager_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

/// Run `fuigo-pager <args>` to the end in `sandbox` and return (exit code, stdout, stderr).
fn run_child(sandbox: &TestSandbox, args: &[&str]) -> (Option<i32>, String, String) {
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
    let out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        String::from_utf8_lossy(&b).into_owned()
    });
    let err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        String::from_utf8_lossy(&b).into_owned()
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            break st;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the run must end on its own: {args:?}");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    (status.code(), out.join().unwrap(), err.join().unwrap())
}

async fn echoing_server() -> MockInferenceServer {
    let server = MockInferenceServer::start().await.expect("start the mock inference server");
    server.preset_allow_access();
    let body = serde_json::json!({"error": {
        "message": format!("Credit limit reached for key {SENT}; top up to continue"),
        "type": "insufficient_quota",
    }});
    for (name, endpoint) in [
        ("402 echo (responses)", InferenceEndpoint::Responses),
        ("402 echo (chat completions)", InferenceEndpoint::ChatCompletions),
    ] {
        let _ = server.expect_response(
            name,
            InferenceRequestMatcher::foreground(endpoint),
            ScriptedResponse::json(402, body.clone()),
        );
    }
    server
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_echoed_api_key_is_redacted_in_every_headless_format() {
    for format in FORMATS {
        let server = echoing_server().await;
        let mut sandbox = TestSandbox::builder().git().mock_url(server.url()).build();
        sandbox.set_env("FUIGO_API_KEY", SENT);
        let (code, stdout, stderr) = tokio::task::spawn_blocking(move || {
            run_child(&sandbox, &["-p", "say hi", "--trust", "--output-format", format])
        })
        .await
        .unwrap();
        assert!(
            server.requests().iter().any(|e| e.method == "POST"
                && (e.path.contains("completions") || e.path.contains("responses"))),
            "{format}: control: the model request reached the mock\nstderr:\n{stderr}"
        );
        assert_ne!(code, Some(0), "{format}: a 402 fails the run\nstderr:\n{stderr}");
        assert!(!stderr.contains(SENT), "{format}: stderr printed the sent key:\n{stderr}");
        assert!(!stdout.contains(SENT), "{format}: stdout printed the sent key:\n{stdout}");
        let shown = format!("{stdout}\n{stderr}");
        assert!(
            shown.contains("<redacted>"),
            "{format}: control: the error is still reported\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
}
