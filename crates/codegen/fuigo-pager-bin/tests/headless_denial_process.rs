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
    script_tool_call(server, TOOL, arguments)
}

/// [`script_one_tool_call`] for any tool.
fn script_tool_call(
    server: &MockInferenceServer,
    tool: &str,
    arguments: &str,
) -> Vec<InferenceExpectation> {
    vec![
        server.expect_response(
            "denied tool call (responses)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
            ScriptedResponse::sse(sse::responses_api_reasoning_then_tool_call_events(
                "",
                "call-1",
                tool,
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
                tool,
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
    // One line per refusal, carrying the per-tool remedy: not a "refused" line followed by a "blocked" one.
    let fuigo_lines: Vec<&str> = result.stderr.lines().filter(|l| l.starts_with("fuigo: ")).collect();
    assert_eq!(fuigo_lines.len(), 1, "exactly one stderr line per refusal: {}", result.stderr);
    assert!(
        fuigo_lines[0].contains("acceptEdits") && fuigo_lines[0].contains("refused"),
        "the one line carries the edit remedy: {}",
        fuigo_lines[0]
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

// HEADLESS-PERM: `--permission-mode acceptEdits` must approve file edits in the workspace in a headless
// run, as `permissions.defaultMode = "acceptEdits"` does; shell commands and edits outside the workspace
// stay refused. Before the fix the flag only set the agent definition's mode, which the permission manager
// never reads, so `-p --permission-mode acceptEdits` refused the edit and exited 3.

/// A run with `--permission-mode acceptEdits` (plus `extra` flags), against the fixture's scripted call.
async fn run_accept_edits(fx: &Fixture, extra: &[&str]) -> fuigo_test_support::HeadlessResult {
    let mut args = vec![
        "-p",
        "edit the fixture",
        "--trust",
        "--permission-mode",
        "acceptEdits",
        "--output-format",
        "json",
    ];
    args.extend_from_slice(extra);
    let result = run_headless(&fx.server, &args, fx.sandbox.workspace()).await;
    assert!(
        !result.timed_out,
        "the run must end on its own\nstderr:\n{}\nrequests:\n{}",
        result.stderr,
        fx.server.request_log_summary()
    );
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_edits_approves_an_edit_inside_the_workspace_headless() {
    let fx = fixture().await;
    let _expectations = script_one_tool_call(&fx.server, &fx.arguments);

    let result = run_accept_edits(&fx, &[]).await;

    assert_eq!(
        result.status.code(),
        Some(0),
        "acceptEdits approves the edit, so the run is an ordinary success\nstdout:\n{}\nstderr:\n{}\nrequests:\n{}",
        result.stdout,
        result.stderr,
        fx.server.request_log_summary()
    );
    assert!(
        !result.stderr.contains("headless_never_approves") && !result.stderr.contains("refused"),
        "nothing was refused: {}",
        result.stderr
    );
    assert_eq!(
        std::fs::read_to_string(fx.sandbox.workspace().join("edit_me.txt")).unwrap(),
        "new line\n",
        "the approved edit must have been applied\nrequests:\n{}",
        fx.server.request_log_summary()
    );
}

/// A shell command is not a file edit: acceptEdits leaves it refused, and the refusal's remedy fits a shell
/// command (an `--allow` rule), not an edit and not a redirect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_edits_still_refuses_a_shell_command_headless() {
    let fx = fixture().await;
    // `rm -rf` of a directory the run owns: the same shape as the E2E that found the defect.
    let victim = fx.sandbox.workspace().join("victim");
    std::fs::create_dir(&victim).unwrap();
    std::fs::write(victim.join("keep.txt"), "keep\n").unwrap();
    let arguments = serde_json::json!({
        "command": "rm -rf ./victim",
        "description": "remove the victim directory",
    })
    .to_string();
    let _expectations = script_tool_call(&fx.server, "run_terminal_command", &arguments);

    let result = run_accept_edits(&fx, &[]).await;

    assert_eq!(
        result.status.code(),
        Some(3),
        "a shell command is still refused under acceptEdits\nstdout:\n{}\nstderr:\n{}\nrequests:\n{}",
        result.stdout,
        result.stderr,
        fx.server.request_log_summary()
    );
    assert!(victim.join("keep.txt").exists(), "a refused command must not run");
    assert!(
        result.stderr.contains("headless_never_approves"),
        "stderr: {}",
        result.stderr
    );
    assert!(
        result.stderr.contains("--allow"),
        "a shell refusal's remedy names an --allow rule: {}",
        result.stderr
    );
    assert!(
        !result.stderr.contains("redirect") && !result.stderr.contains("> file"),
        "a plain command's remedy must not talk about redirects: {}",
        result.stderr
    );
}

/// An edit outside the workspace is not covered by acceptEdits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_edits_still_refuses_an_edit_outside_the_workspace_headless() {
    let fx = fixture().await;
    let outside_dir = tempfile::tempdir().expect("create a directory outside the workspace");
    let outside = outside_dir.path().join("outside.txt");
    std::fs::write(&outside, "old line\n").unwrap();
    let arguments = serde_json::json!({
        "file_path": outside.to_string_lossy(),
        "old_string": "old line",
        "new_string": "new line",
    })
    .to_string();
    let _expectations = script_one_tool_call(&fx.server, &arguments);

    let result = run_accept_edits(&fx, &[]).await;

    assert_eq!(
        result.status.code(),
        Some(3),
        "an edit outside the workspace is still refused\nstdout:\n{}\nstderr:\n{}\nrequests:\n{}",
        result.stdout,
        result.stderr,
        fx.server.request_log_summary()
    );
    assert_eq!(
        std::fs::read_to_string(&outside).unwrap(),
        "old line\n",
        "the refused edit must leave the file untouched"
    );
}

/// DEFECT 3: an edit refusal's remedy fits an edit (acceptEdits), not a shell redirect, and the refusal is
/// one stderr line (no second `blocked` summary).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edit_refusal_remedy_names_accept_edits_not_redirects() {
    let fx = fixture().await;
    let _expectations = script_one_tool_call(&fx.server, &fx.arguments);

    let result = run_headless(
        &fx.server,
        &["-p", "edit the fixture", "--trust", "--output-format", "json"],
        fx.sandbox.workspace(),
    )
    .await;

    assert_eq!(result.status.code(), Some(3), "stderr:\n{}", result.stderr);
    let lines: Vec<&str> = result.stderr.lines().filter(|l| l.starts_with("fuigo: ")).collect();
    assert_eq!(lines.len(), 1, "exactly one stderr line: {}", result.stderr);
    assert!(lines[0].starts_with("fuigo: refused"), "the one line is the refusal: {}", lines[0]);
    assert!(
        lines[0].contains("acceptEdits"),
        "an edit refusal's remedy names acceptEdits: {}",
        lines[0]
    );
    assert!(
        !lines[0].contains("redirect") && !lines[0].contains("> file"),
        "an edit refusal's remedy must not talk about redirects: {}",
        lines[0]
    );
    let doc: serde_json::Value = serde_json::from_str(result.stdout.trim()).unwrap();
    assert!(
        doc["permissionDenied"]["remedy"]
            .as_str()
            .is_some_and(|r| r.contains("acceptEdits") && !r.contains("redirect")),
        "the record's remedy fits the tool too: {doc}"
    );
}
