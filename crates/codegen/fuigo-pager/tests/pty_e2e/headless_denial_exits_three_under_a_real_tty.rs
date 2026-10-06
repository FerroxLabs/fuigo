// Per-test-case module for the `pty_e2e` integration test crate.
#[allow(unused_imports)]
use super::common::*;

use fuigo_test_support::{
    InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, ScriptedResponse as Scripted,
    TestSandbox, sse,
};

/// Contract D.5 / D.3 end to end, with a real terminal attached.
///
/// `tests/headless_denial_exit_code.rs` (and its non-ignored twin in `fuigo-pager-bin`) prove the
/// exit code with stdio on pipes. D.3 says the decision to report "must not depend on TTY detection",
/// and a pipe-only test cannot catch a regression that only fires, or only stops firing, when fd 0/1/2
/// are a terminal -- which is exactly how a human runs `fuigo -p`. So this drives the same real turn
/// through the PTY harness: `fuigo -p` is asked for a write it has no standing permission for, the
/// harness is the controlling terminal, and the PROCESS exit status is read.
///
/// Pair: the identical turn with `--yolo` exits 0, so the 3 is attributable to the denial.
#[cfg(unix)]
async fn run_under_pty(extra_args: &[&str]) -> (Option<u32>, String, String) {
    let server = MockInferenceServer::start()
        .await
        .expect("start the mock inference server");
    server.preset_allow_access();
    let sandbox = TestSandbox::builder()
        .git()
        .mock_url(server.url())
        .build();
    let target = sandbox.workspace().join("edit_me.txt");
    std::fs::write(&target, "old line\n").expect("write the fixture file");
    let arguments = json!({
        "file_path": target.to_string_lossy(),
        "old_string": "old line",
        "new_string": "new line",
    })
    .to_string();
    // Both wire backends are scripted; whichever the resolved model uses claims its own.
    let _responses = server.expect_response(
        "denied tool call (responses)",
        InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
        Scripted::sse(sse::responses_api_reasoning_then_tool_call_events(
            "",
            "call-1",
            "search_replace",
            &arguments,
            "test-model",
        )),
    );
    let _chat = server.expect_response(
        "denied tool call (chat completions)",
        InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
        Scripted::sse(sse::chat_completions_reasoning_then_tool_call_events(
            "",
            "call-1",
            "search_replace",
            &arguments,
            "test-model",
        )),
    );

    let mut args = vec!["-p", "edit the fixture", "--trust", "--output-format", "json"];
    args.extend_from_slice(extra_args);
    let binary = pager_binary().expect("resolve pager binary");
    let mut harness = PtyHarness::new_in_sandbox_ops(
        &binary,
        DEFAULT_ROWS,
        DEFAULT_COLS,
        &args,
        &sandbox,
        &[EnvOp::set("NO_COLOR", "1")],
        Some(sandbox.workspace()),
    )
    .expect("spawn `fuigo -p` in a PTY");

    // Cold exec of a large debug binary plus one scripted turn; same budget as the other PTY exits.
    let code = match wait_for_exit_status(&mut harness, Duration::from_secs(120))
        .expect("wait for the headless run to exit")
    {
        PtyExitPoll::Exited(code) => Some(code),
        PtyExitPoll::Running | PtyExitPoll::PendingStatus => None,
    };
    // Drain what the child wrote just before exiting.
    for _ in 0..20 {
        harness.update(Duration::from_millis(100));
    }
    let raw = String::from_utf8_lossy(harness.raw_output()).into_owned();
    let file = std::fs::read_to_string(&target).expect("read the fixture file back");
    (
        code,
        format!("{raw}\n--- requests ---\n{}", server.request_log_summary()),
        file,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run the owning pty_e2e_* Cargo test with --ignored (see Cargo.toml)"]
#[cfg(unix)]
async fn headless_denial_exits_three_under_a_real_tty() {
    let (code, raw, file) = run_under_pty(&[]).await;
    assert_eq!(
        code,
        Some(3),
        "a blocked headless run exits 3 with a terminal attached too -- not 0 and not 1; raw:\n{raw}"
    );
    assert!(
        raw.contains("headless_never_approves"),
        "the terminal shows the rule that blocked the run; raw:\n{raw}"
    );
    assert!(
        raw.contains("blocked"),
        "the terminal says the run was blocked; raw:\n{raw}"
    );
    // D.2.4: a denial leaves no half-applied edit.
    assert_eq!(file, "old line\n", "the refused edit must not have been applied");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run the owning pty_e2e_* Cargo test with --ignored (see Cargo.toml)"]
#[cfg(unix)]
async fn the_same_turn_approved_exits_zero_under_a_real_tty() {
    let (code, raw, file) = run_under_pty(&["--yolo"]).await;
    assert_eq!(
        code,
        Some(0),
        "an approved tool call is an ordinary successful run under a terminal too; raw:\n{raw}"
    );
    assert!(
        !raw.contains("headless_never_approves"),
        "nothing was denied, so nothing may claim it was; raw:\n{raw}"
    );
    assert_eq!(file, "new line\n", "the approved edit was applied");
}
