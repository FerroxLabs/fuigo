//! Contract D.5, literally, at the PROCESS boundary: `fuigo -p` is driven to a real permission
//! request and the exit status a script would see is asserted.
//!
//! Not `#[ignore]`d. The same two tests live in `fuigo-pager/tests/headless_denial_exit_code.rs`, but
//! the pager binary belongs to this package, so only here does cargo build it before the test runs and
//! bake its path in: `CARGO_BIN_EXE_fuigo-pager` is a COMPILE-time constant (read with `option_env!`,
//! as the sibling tests here do), not a runtime variable. `pager_binary()` passes that path to
//! `run_headless_in_sandbox`, so nothing falls back to `fuigo_binary()`'s target-dir heuristic, which can
//! shell out to a nested, unlocked `cargo build`. That is why that copy has to be `#[ignore]`d and this
//! one does not: `cargo test -p fuigo-pager-bin` runs the end-to-end denial test with no setup.
//!
//! | run | the tool call is | `$?` |
//! |---|---|---|
//! | no `--yolo` | refused: headless has nobody to ask | **3** |
//! | `--yolo`    | auto-approved                        | **0** |
//!
//! A real terminal attached instead of pipes is covered by the `pty_e2e` family
//! (`headless_denial_exits_three_under_a_real_tty`).

use fuigo_test_support::{
    InferenceEndpoint, InferenceExpectation, InferenceRequestMatcher, MockInferenceServer,
    ScriptedResponse, TestSandbox, git_workdir, run_headless_in_sandbox, sse,
};

/// The pager binary cargo built for this test run: `PAGER_BINARY` under Bazel (runfiles-relative), else
/// cargo's compile-time constant, like the sibling tests.
fn pager_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

/// `run_headless`, but pointed at this package's own binary instead of `fuigo_binary()`'s heuristic.
async fn run_headless(
    server: &MockInferenceServer,
    args: &[&str],
    cwd: &std::path::Path,
) -> fuigo_test_support::HeadlessResult {
    let sandbox = TestSandbox::builder().mock_url(server.url()).build();
    let mut cmd = tokio::process::Command::new(pager_binary());
    cmd.args(args).current_dir(cwd);
    run_headless_in_sandbox(cmd, sandbox).await
}

/// `search_replace` on a real file: a write that headless mode has no standing permission for, and
/// whose cancellation is terminal for the turn (`Decision::Cancelled` -> `ToolLoop::Cancelled` ->
/// `TurnOutcome::Cancelled { PermissionCancelled }`) rather than fed back to the model.
const TOOL: &str = "search_replace";

/// Script one foreground turn that asks for `TOOL`. Registered on both wire backends because which
/// one the resolved model uses is not this test's business; the other expectation simply goes
/// unclaimed.
fn script_one_tool_call(
    server: &MockInferenceServer,
    arguments: &str,
) -> Vec<InferenceExpectation> {
    vec![
        server.expect_response(
            "denied tool call (responses)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
            ScriptedResponse::sse(sse::responses_api_reasoning_then_tool_call_events(
                "",
                "call-1",
                TOOL,
                arguments,
                "test-model",
            )),
        ),
        server.expect_response(
            "denied tool call (chat completions)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::sse(sse::chat_completions_reasoning_then_tool_call_events(
                "",
                "call-1",
                TOOL,
                arguments,
                "test-model",
            )),
        ),
    ]
}

struct Fixture {
    server: MockInferenceServer,
    sandbox: TestSandbox,
    arguments: String,
}

async fn fixture() -> Fixture {
    let server = MockInferenceServer::start()
        .await
        .expect("start the mock inference server");
    server.preset_allow_access();
    let sandbox = git_workdir();
    let target = sandbox.workspace().join("edit_me.txt");
    std::fs::write(&target, "old line\n").expect("write the fixture file");
    let arguments = serde_json::json!({
        "file_path": target.to_string_lossy(),
        "old_string": "old line",
        "new_string": "new line",
    })
    .to_string();
    Fixture {
        server,
        sandbox,
        arguments,
    }
}

/// Contract D.2.1 at the process boundary: a run that ended because a permission was denied exits
/// with the dedicated code, and says why on stderr.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_denied_headless_run_exits_three_and_says_why() {
    let fx = fixture().await;
    let _expectations = script_one_tool_call(&fx.server, &fx.arguments);

    // No --yolo: headless mode has no operator, so the request is refused.
    let result = run_headless(
        &fx.server,
        &["-p", "edit the fixture", "--trust", "--output-format", "json"],
        fx.sandbox.workspace(),
    )
    .await;

    assert!(
        !result.timed_out,
        "the run must end on its own\nstderr:\n{}\nrequests:\n{}",
        result.stderr,
        fx.server.request_log_summary()
    );
    assert_eq!(
        result.status.code(),
        Some(3),
        "a blocked headless run exits 3 — not 0 (which reads as finished) and not 1 (which reads as \
         a crash)\nstdout:\n{}\nstderr:\n{}\nrequests:\n{}",
        result.stdout,
        result.stderr,
        fx.server.request_log_summary()
    );
    // D.2.3: one English line with the rule and the remedy, on stderr, with no TTY anywhere.
    assert!(
        result.stderr.contains("headless_never_approves"),
        "stderr must name the rule: {}",
        result.stderr
    );
    assert!(
        result.stderr.contains("blocked"),
        "stderr must say the run was blocked: {}",
        result.stderr
    );
    // D.2.2: the reason is on the document a machine reads, not only in the prose.
    let doc: serde_json::Value = serde_json::from_str(result.stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must stay exactly one JSON value ({e}): {}", result.stdout));
    assert_eq!(doc["stopReason"], "cancelled", "document: {doc}");
    assert_eq!(
        doc["permissionDenied"]["rule"], "headless_never_approves",
        "document: {doc}"
    );
    assert_eq!(doc["permissionDenied"]["exitCode"], 3, "document: {doc}");
    // D.2.4: the refused edit was not half-applied.
    assert_eq!(
        std::fs::read_to_string(fx.sandbox.workspace().join("edit_me.txt")).unwrap(),
        "old line\n",
        "a denial must leave the file untouched"
    );
}

/// The counter-test: the identical turn, approved, exits 0. Without this the `3` above could be
/// coming from anything in the fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_same_turn_approved_exits_zero() {
    let fx = fixture().await;
    let _expectations = script_one_tool_call(&fx.server, &fx.arguments);

    let result = run_headless(
        &fx.server,
        &[
            "-p",
            "edit the fixture",
            "--trust",
            "--yolo",
            "--output-format",
            "json",
        ],
        fx.sandbox.workspace(),
    )
    .await;

    assert!(
        !result.timed_out,
        "the run must end on its own\nstderr:\n{}",
        result.stderr
    );
    assert_eq!(
        result.status.code(),
        Some(0),
        "an approved tool call is an ordinary successful run\nstdout:\n{}\nstderr:\n{}\nrequests:\n{}",
        result.stdout,
        result.stderr,
        fx.server.request_log_summary()
    );
    assert!(
        !result.stderr.contains("headless_never_approves"),
        "nothing was denied, so nothing may claim it was: {}",
        result.stderr
    );
    // The 0 is the tool having RUN, not a model that moved on without it.
    assert_eq!(
        std::fs::read_to_string(fx.sandbox.workspace().join("edit_me.txt")).unwrap(),
        "new line\n",
        "the approved edit must have been applied\nrequests:\n{}",
        fx.server.request_log_summary()
    );
}
