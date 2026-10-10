//! K26 (P195): a LOW open-file limit ends `fuigo` with the start-up failure code `4`, never an abort.
//!
//! 1.0.21 exited `4` ("Fuigo never started, nothing was run") only when the tokio runtime itself could not be built.
//! With a limit just above that (`ulimit -n` 7 to 27 on Linux) a LATER start-up component failed instead, and which
//! one depended on the exact number: tokio's signal pipe and the async-io reactor `expect` (SIGABRT, exit 134, a
//! panic message), the shared HTTP client `expect`s the same way, and the config load, the managed-policy lock and the
//! agent runtime reported EMFILE as an ordinary error (exit `1`, indistinguishable from a failed run).
//!
//! The limits are provoked for real: the child runs under `ulimit -n N` (a hard limit, so the start-up raise cannot lift it).
//! The sweep below is EVERY limit from the lowest a shell can exec under up to the floor, each of which must exit `4`
//! with the "never started" line, and a control proves that a run AT the floor goes through to completion.

#![cfg(target_os = "linux")]

use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

use fuigo_test_support::{
    InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, ScriptedResponse, TestSandbox, git_workdir,
    run_headless_in_sandbox_borrowed_with_env, sse,
};

/// The floor `fuigo` refuses to start below (`MIN_OPEN_FILES` in `main.rs`). Kept as a literal on purpose: a change
/// to the floor must be a deliberate edit here too.
const FLOOR: u32 = 64;
/// Below 5 the shell cannot even exec the child.
const LOWEST: u32 = 5;
const STARTUP_FAILURE_EXIT_CODE: i32 = 4;

fn pager_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

struct Run {
    nofile: u32,
    code: Option<i32>,
    signal: Option<i32>,
    stderr: String,
}

fn run_with_nofile_limit(nofile: u32) -> Run {
    run_args_with_nofile_limit(nofile, &["--no-auto-update", "-p", "hello"])
}

fn run_args_with_nofile_limit(nofile: u32, args: &[&str]) -> Run {
    // Hermetic, like `runtime_startup_exit.rs`: no credentials, endpoints or config to act on, a disposable working
    // directory, every network kill switch the other process tests use.
    let sandbox = TestSandbox::builder().build();
    #[allow(
        clippy::disallowed_methods,
        reason = "the child is placed in its own process group and the whole group is SIGKILLed after it ends or on the deadline"
    )]
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("ulimit -n {nofile} && exec \"$0\" \"$@\""))
        .arg(pager_binary())
        .args(args)
        .env_clear()
        .envs(sandbox.env())
        .current_dir(sandbox.workspace())
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fuigo");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let (text_tx, text_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = std::io::Read::read_to_string(&mut stderr_pipe, &mut text);
        let _ = text_tx.send(text);
    });
    let pgid = i32::try_from(child.id()).expect("pid fits i32");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            // SAFETY: plain signal to the process group this test created above.
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
            break child.wait().expect("reap killed child");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    // SAFETY: plain signal to the process group this test created above (ESRCH when it is already empty).
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
    let signal = std::os::unix::process::ExitStatusExt::signal(&status);
    Run {
        nofile,
        code: status.code(),
        signal,
        stderr: text_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap_or_else(|_| String::from("<stderr not drained>")),
    }
}

/// Every limit under the floor ends the run with exit 4 and the "never started" line: no abort (a panic under
/// `panic = "abort"` is SIGABRT, or exit 134 through a shell), no exit 1.
#[test]
fn every_limit_under_the_floor_exits_four_never_an_abort() {
    let bad: Vec<String> = (LOWEST..FLOOR)
        .map(run_with_nofile_limit)
        .filter(|run| run.code != Some(STARTUP_FAILURE_EXIT_CODE) || !run.stderr.contains("never started"))
        .map(|run| {
            format!(
                "nofile={} exit={:?} signal={:?} stderr={:?}",
                run.nofile,
                run.code,
                run.signal,
                run.stderr.lines().take(3).collect::<Vec<_>>()
            )
        })
        .collect();
    assert!(
        bad.is_empty(),
        "every open-file limit from {LOWEST} to {} must exit {STARTUP_FAILURE_EXIT_CODE} (never started); these did not:\n{}",
        FLOOR - 1,
        bad.join("\n")
    );
}

/// The refusal names the limit and the remedy, so a person can fix it without reading the source.
#[test]
fn the_refusal_names_the_limit_and_the_remedy() {
    let run = run_with_nofile_limit(FLOOR - 1);
    assert_eq!(run.code, Some(STARTUP_FAILURE_EXIT_CODE), "stderr: {}", run.stderr);
    assert!(
        run.stderr.contains(&format!("open-file limit is {}", FLOOR - 1)),
        "names the limit in force: {}",
        run.stderr
    );
    assert!(run.stderr.contains(&format!("at least {FLOOR}")), "names the floor: {}", run.stderr);
    assert!(run.stderr.contains("ulimit -n"), "names the remedy: {}", run.stderr);
}

/// K26 (Grok r1): the subscription commands are dispatched before the agent path, so they must refuse the same way:
/// exit 4 and the line, not a generic error or EMFILE.
#[test]
fn subscription_commands_under_the_floor_exit_four_with_the_line() {
    let commands: [&[&str]; 3] = [
        &["login", "--provider", "chatgpt", "--status"],
        &["models", "--provider", "chatgpt"],
        &["logout", "--provider", "chatgpt"],
    ];
    for args in commands {
        for nofile in [LOWEST, 20, FLOOR - 1] {
            let run = run_args_with_nofile_limit(nofile, args);
            assert_eq!(
                run.code,
                Some(STARTUP_FAILURE_EXIT_CODE),
                "{args:?} at nofile={nofile} (signal {:?}) stderr: {}",
                run.signal,
                run.stderr
            );
            assert!(run.stderr.contains("never started"), "{args:?} nofile={nofile}: {}", run.stderr);
            assert!(run.stderr.contains(&format!("open-file limit is {nofile}")), "{args:?}: {}", run.stderr);
        }
    }
}

/// Control: AT the floor, `fuigo -p` starts and finishes a real turn against the mock server (exit 0), so the floor is
/// not set so high that it refuses a limit a run can use, and the refusals above are not an artefact of the fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_at_the_floor_starts_and_completes() {
    let server = MockInferenceServer::start().await.expect("start the mock inference server");
    server.preset_allow_access();
    let workdir = git_workdir();
    let _expect = [
        server.expect_response(
            "text (responses)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
            ScriptedResponse::sse(sse::responses_api_script_exact("the answer", "test-model")),
        ),
        server.expect_response(
            "text (chat completions)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::sse(sse::chat_completion_script_exact("the answer", "test-model")),
        ),
    ];
    let sandbox = TestSandbox::builder().mock_url(server.url()).build();
    let mut cmd = tokio::process::Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(format!("ulimit -n {FLOOR} && exec \"$0\" \"$@\""))
        .arg(pager_binary())
        .args(["-p", "say the answer", "--trust", "--yolo", "--output-format", "json"])
        .current_dir(workdir.workspace());
    let result = run_headless_in_sandbox_borrowed_with_env(cmd, &sandbox, &[]).await;
    assert!(!result.timed_out, "stdout:\n{}\nstderr:\n{}", result.stdout, result.stderr);
    assert_eq!(
        result.status.code(),
        Some(0),
        "a run at the floor completes\nstdout:\n{}\nstderr:\n{}\nrequests:\n{}",
        result.stdout,
        result.stderr,
        server.request_log_summary()
    );
}
