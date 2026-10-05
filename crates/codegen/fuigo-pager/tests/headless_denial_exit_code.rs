//! The exit code a **process** reports for a headless permission denial.
//!
//! Everything else about Contract D is asserted in-process: `headless_run_outcome` is called
//! directly and `denial.exit_code()` is read as a value. Nothing spawned the binary and looked at
//! `$?`, which is the only thing a CI job ever sees. `main`'s three-arm outcome match
//! (`fuigo-pager-bin/src/main.rs`) was therefore covered by the compiler and nothing else.
//!
//! These two tests are the same scripted turn twice, differing only in `--yolo`:
//!
//! | run | the tool call is | `$?` |
//! |---|---|---|
//! | no `--yolo` | refused — headless has nobody to ask | **3** |
//! | `--yolo`    | auto-approved                        | **0** |
//!
//! So the `3` is attributable to the denial and to nothing else in the setup.
//!
//! A third (P02b) runs the refused turn once per `--output-format` and reads the structured denial
//! record back out of stdout the way a consumer would, never out of the stderr prose.
//!
//! Ignored by default, the same as every other test here that needs a built binary: the pager
//! binary lives in a different crate, so `CARGO_BIN_EXE_fuigo-pager` is not set for this one and
//! `fuigo_binary()` would otherwise shell out to `cargo build`. Run with an explicit binary:
//!
//! ```bash
//! FUIGO_BINARY=target/debug/fuigo-pager \
//!   cargo test -p fuigo-pager --test headless_denial_exit_code -- --ignored --test-threads=1
//! ```

use fuigo_test_support::{
    InferenceEndpoint, InferenceExpectation, InferenceRequestMatcher, MockInferenceServer,
    ScriptedResponse, TestSandbox, git_workdir, run_headless, sse,
};

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
#[ignore = "spawns the real pager binary; set FUIGO_BINARY and run with --ignored"]
async fn a_denied_headless_run_exits_three_and_says_why() {
    let fx = fixture().await;
    let _expectations = script_one_tool_call(&fx.server, &fx.arguments);

    // No --yolo: headless mode has no operator, so the request is refused.
    let result = run_headless(
        &fx.server,
        &[
            "-p",
            "edit the fixture",
            "--trust",
            "--output-format",
            "json",
        ],
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
    let doc: serde_json::Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "stdout must stay exactly one JSON value ({e}): {}",
            result.stdout
        )
    });
    assert_eq!(doc["stopReason"], "cancelled", "document: {doc}");
    assert_eq!(
        doc["permissionDenied"]["rule"], "headless_never_approves",
        "document: {doc}"
    );
    assert_eq!(doc["permissionDenied"]["exitCode"], 3, "document: {doc}");
    assert_eq!(doc["permissionDenied"]["endedRun"], true, "document: {doc}");
    // D.2.4: the refused edit left nothing half-applied.
    assert_eq!(
        std::fs::read_to_string(fx.sandbox.workspace().join("edit_me.txt")).expect("read fixture"),
        "old line\n",
        "a denied edit must leave the file untouched"
    );
}

/// P02b at the process boundary: the same blocked turn under every `--output-format`, each exiting
/// `3` and carrying the denial as data in its own terminal record — read here the way a consumer
/// would, by parsing stdout, never by reading the stderr prose.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns the real pager binary; set FUIGO_BINARY and run with --ignored"]
async fn every_output_format_reports_the_denial_as_data() {
    for format in ["plain", "json", "streaming-json", "streaming-messages-json"] {
        let fx = fixture().await;
        let _expectations = script_one_tool_call(&fx.server, &fx.arguments);
        let result = run_headless(
            &fx.server,
            &[
                "-p",
                "edit the fixture",
                "--trust",
                "--output-format",
                format,
            ],
            fx.sandbox.workspace(),
        )
        .await;
        let ctx = format!(
            "format {format}\nstdout:\n{}\nstderr:\n{}\nrequests:\n{}",
            result.stdout,
            result.stderr,
            fx.server.request_log_summary()
        );
        assert!(!result.timed_out, "the run must end on its own\n{ctx}");
        assert_eq!(result.status.code(), Some(3), "blocked exits 3\n{ctx}");
        // D.2.3, every format: the human line, with the rule and the remedy, on stderr.
        assert!(result.stderr.contains("headless_never_approves"), "{ctx}");
        assert!(result.stderr.contains("Remedy:"), "{ctx}");
        // D.2.4: nothing half-applied, whichever format reported it.
        assert_eq!(
            std::fs::read_to_string(fx.sandbox.workspace().join("edit_me.txt")).expect("read"),
            "old line\n",
            "{ctx}"
        );
        let lines = || {
            result
                .stdout
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    serde_json::from_str::<serde_json::Value>(l)
                        .unwrap_or_else(|e| panic!("every line is JSON ({e}): {l}\n{ctx}"))
                })
                .collect::<Vec<_>>()
        };
        match format {
            "plain" => {
                assert!(!result.stdout.contains("permissionDenied"), "{ctx}");
            }
            "json" => {
                let doc: serde_json::Value = serde_json::from_str(result.stdout.trim())
                    .unwrap_or_else(|e| panic!("one JSON value ({e})\n{ctx}"));
                assert_eq!(
                    doc["permissionDenied"]["rule"], "headless_never_approves",
                    "{ctx}"
                );
                assert_eq!(doc["permissionDenied"]["exitCode"], 3, "{ctx}");
            }
            "streaming-json" => {
                let lines = lines();
                let end = lines.last().expect("a terminal line");
                assert_eq!(end["type"], "end", "{ctx}");
                assert_eq!(
                    lines
                        .iter()
                        .filter(|l| l["type"] == "end" || l["type"] == "error")
                        .count(),
                    1,
                    "exactly one terminal line\n{ctx}"
                );
                assert_eq!(end["stopReason"], "cancelled", "{ctx}");
                assert_eq!(
                    end["permissionDenied"]["rule"], "headless_never_approves",
                    "{ctx}"
                );
                assert_eq!(end["permissionDenied"]["endedRun"], true, "{ctx}");
                assert_eq!(end["permissionDenied"]["exitCode"], 3, "{ctx}");
                // The record joins to the tool call already on the stream.
                let id = end["permissionDenied"]["toolCallId"].as_str().expect("id");
                assert!(
                    lines
                        .iter()
                        .any(|l| l["type"] == "tool_call" && l["toolCallId"] == id),
                    "{ctx}"
                );
            }
            "streaming-messages-json" => {
                let lines = lines();
                let res = lines.last().expect("a terminal line");
                assert_eq!(res["type"], "result", "{ctx}");
                assert_eq!(res["is_error"], true, "{ctx}");
                assert_eq!(res["stop_reason"], "cancelled", "{ctx}");
                let denials = res["permission_denials"]
                    .as_array()
                    .expect("permission_denials");
                assert_eq!(denials.len(), 1, "{ctx}");
                assert_eq!(denials[0]["tool_name"], TOOL, "{ctx}");
                assert_eq!(
                    lines.iter().filter(|l| l["type"] == "result").count(),
                    1,
                    "exactly one terminal result\n{ctx}"
                );
                // The entry joins to the `tool_use` block the transcript carried, input and all.
                let id = denials[0]["tool_use_id"].as_str().expect("id");
                let tool_use = lines
                    .iter()
                    .filter(|l| l["type"] == "assistant")
                    .filter_map(|l| l["message"]["content"].as_array())
                    .flatten()
                    .find(|b| b["type"] == "tool_use" && b["id"] == id)
                    .unwrap_or_else(|| panic!("a tool_use block for {id}\n{ctx}"));
                assert_eq!(denials[0]["tool_input"], tool_use["input"], "{ctx}");
                assert_eq!(denials[0]["tool_name"], tool_use["name"], "{ctx}");
            }
            _ => unreachable!(),
        }
    }
}

/// The counter-test: the identical turn, approved, exits 0. Without this the `3` above could be
/// coming from anything in the fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns the real pager binary; set FUIGO_BINARY and run with --ignored"]
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
}
