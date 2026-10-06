//! P144 (lane A2 of the 1.0.21 end-to-end run): the process-wide limits a `fuigo -p` run can be given,
//! `FUIGO_MAX_MODEL_CALLS` and `FUIGO_MAX_RUNTIME_SECS`, end the run the way the release note (B4) and
//! `14-headless-mode.md` "Exit Codes" say: exit **3**, one stderr line naming the rule, and the
//! `permissionDenied` record on the terminal document. Driven through the REAL binary, the way a script
//! runs it; the limits are process globals read from the environment, so only a child process can set
//! them.
//!
//! Before P144 none of these paths reached the typed denial P02e/P44 built:
//!
//! | run | before | now |
//! |---|---|---|
//! | call limit reached, the model calls a tool in the reserved final slot | exit 1 `Tool call rejected during finalization` | exit 3, `execution_model_call_limit` |
//! | call limit reached, the model answers in that slot | exit 1, the partial execution receipt | exit 3, `execution_model_call_limit` |
//! | runtime limit passes while the model request is in flight | exit 0, stop `cancelled` | exit 3, `execution_runtime_limit` |
//!
//! It also pins the permission remedy: `--allow "Bash"` (the guide's own example) lets an ordinary shell
//! command run in headless mode, and for a command no `--allow` rule can cover (a write by redirect) the
//! remedy line names the flag that works instead of `--allow`.

use fuigo_test_support::{
    InferenceEndpoint, InferenceExpectation, InferenceRequestMatcher, MockInferenceServer,
    ScriptedResponse, TestSandbox, git_workdir, run_headless_in_sandbox_borrowed_with_env, sse,
};

/// The shell tool as the default profile advertises it (lane A2 called it by this name too).
const SHELL_TOOL: &str = "run_terminal_command";

fn pager_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

struct Fixture {
    server: MockInferenceServer,
    sandbox: TestSandbox,
}

async fn fixture() -> Fixture {
    let server = MockInferenceServer::start()
        .await
        .expect("start the mock inference server");
    server.preset_allow_access();
    Fixture {
        server,
        sandbox: git_workdir(),
    }
}

impl Fixture {
    async fn run(&self, args: &[&str], env: &[(&str, &str)]) -> fuigo_test_support::HeadlessResult {
        // A fresh home per run; the workspace the tool writes to is the fixture's git checkout.
        let sandbox = TestSandbox::builder().mock_url(self.server.url()).build();
        let mut cmd = tokio::process::Command::new(pager_binary());
        cmd.args(args).current_dir(self.sandbox.workspace());
        let result = run_headless_in_sandbox_borrowed_with_env(cmd, &sandbox, env).await;
        assert!(
            !result.timed_out,
            "the run must end on its own\nstdout:\n{}\nstderr:\n{}\nrequests:\n{}",
            result.stdout,
            result.stderr,
            self.server.request_log_summary()
        );
        result
    }

    fn workspace_file(&self, name: &str) -> std::path::PathBuf {
        self.sandbox.workspace().join(name)
    }
}

/// One foreground model reply that calls the shell tool with `command`, on both wire backends (which
/// one the resolved model uses is not this test's business; the other expectation goes unclaimed).
fn script_shell_call(server: &MockInferenceServer, command: &str) -> Vec<InferenceExpectation> {
    let arguments = serde_json::json!({
        "command": command,
        "description": "run the command the test asked for",
    })
    .to_string();
    vec![
        server.expect_response(
            "shell call (responses)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
            ScriptedResponse::sse(sse::responses_api_reasoning_then_tool_call_events(
                "", "call-1", SHELL_TOOL, &arguments, "test-model",
            )),
        ),
        server.expect_response(
            "shell call (chat completions)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::sse(sse::chat_completions_reasoning_then_tool_call_events(
                "", "call-1", SHELL_TOOL, &arguments, "test-model",
            )),
        ),
    ]
}

/// One foreground model reply that is plain text.
fn script_text(server: &MockInferenceServer, text: &str) -> Vec<InferenceExpectation> {
    vec![
        server.expect_response(
            "text (responses)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
            ScriptedResponse::sse(sse::responses_api_script_exact(text, "test-model")),
        ),
        server.expect_response(
            "text (chat completions)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::sse(sse::chat_completion_script_exact(text, "test-model")),
        ),
    ]
}

/// The tail of the last model request body: where the tool result the model was sent shows why a tool
/// did or did not run.
fn last_request_tail(server: &MockInferenceServer) -> String {
    let Some(body) = server.request_bodies().into_iter().last() else {
        return String::new();
    };
    let tools: Vec<String> = body["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|tool| tool["function"]["name"].as_str().or(tool["name"].as_str()).map(str::to_owned))
        .collect();
    let messages = body.get("messages").or(body.get("input")).cloned().unwrap_or_default();
    let messages = messages.to_string();
    let tail: String = messages.chars().rev().take(1500).collect::<Vec<_>>().into_iter().rev().collect();
    format!("tools: {tools:?}\nmessages tail: {tail}")
}

/// The B4 contract for a run a budget ended: exit 3, the rule on the one stderr line, the record on the
/// single terminal JSON document.
fn assert_budget_denial(fx: &Fixture, result: &fuigo_test_support::HeadlessResult, rule: &str) {
    assert_eq!(
        result.status.code(),
        Some(3),
        "a run a budget ended exits 3 (B4) - not 0 (finished) and not 1 (crashed)\nstdout:\n{}\nstderr:\n{}\nrequests:\n{}",
        result.stdout,
        result.stderr,
        fx.server.request_log_summary()
    );
    assert!(
        result.stderr.contains(rule),
        "the stderr line must name the rule `{rule}`: {}",
        result.stderr
    );
    let doc: serde_json::Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|e| {
        panic!("stdout must stay exactly one JSON value ({e}): {}", result.stdout)
    });
    assert_eq!(doc["permissionDenied"]["rule"], rule, "document: {doc}");
    assert_eq!(doc["permissionDenied"]["exitCode"], 3, "document: {doc}");
}

/// A2 `s04_max_model_calls_1`: the only call is the final-answer slot, and the model calls a tool in it.
/// The tool must not run, and the run is a budget denial, not an internal error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tool_call_in_the_call_limits_final_slot_exits_three() {
    let fx = fixture().await;
    let _expect = script_shell_call(&fx.server, "touch must_not_exist.txt");
    let result = fx
        .run(
            &["-p", "do the work", "--trust", "--yolo", "--output-format", "json"],
            &[("FUIGO_MAX_MODEL_CALLS", "1")],
        )
        .await;
    assert_budget_denial(&fx, &result, "execution_model_call_limit");
    assert!(
        !result.stderr.contains("Tool call rejected during finalization"),
        "the old internal error must not be what the user sees: {}",
        result.stderr
    );
    assert!(
        !fx.workspace_file("must_not_exist.txt").exists(),
        "a call in the final-answer slot must never run"
    );
}

/// The call limit reached inside the turn, and the model answers in the reserved slot: the run still
/// ended because the limit left no room for more work, so it is the same denial (and the answer is not
/// lost: it is on the document's text).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_in_the_call_limits_final_slot_exits_three() {
    let fx = fixture().await;
    let _expect = script_text(&fx.server, "the reserved answer");
    let result = fx
        .run(
            &["-p", "do the work", "--trust", "--yolo", "--output-format", "json"],
            &[("FUIGO_MAX_MODEL_CALLS", "1")],
        )
        .await;
    assert_budget_denial(&fx, &result, "execution_model_call_limit");
}

/// Control: with calls to spare, the identical text turn is an ordinary success. Without it the 3 above
/// could come from anything in the fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_same_answer_with_calls_to_spare_exits_zero() {
    let fx = fixture().await;
    let _expect = script_text(&fx.server, "the ordinary answer");
    let result = fx
        .run(
            &["-p", "do the work", "--trust", "--yolo", "--output-format", "json"],
            &[("FUIGO_MAX_MODEL_CALLS", "50")],
        )
        .await;
    assert_eq!(
        result.status.code(),
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
    assert!(!result.stderr.contains("execution_model_call_limit"), "{}", result.stderr);
}

/// A2 `s04_runtime_limit`: the runtime limit passes while the model request is in flight. The agent
/// cuts the request short and cancels the session; that is the limit ending the run, so exit 3 with the
/// runtime rule - not exit 0 with a `cancelled` stop that reads as a finished run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_runtime_limit_passing_mid_request_exits_three() {
    let fx = fixture().await;
    // Held before its last event until the test ends: the request is in flight when the deadline passes.
    let _held = [
        fx.server.expect_response_blocked(
            "held text (responses)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
            ScriptedResponse::sse(sse::responses_api_script_exact("too late", "test-model")),
        ),
        fx.server.expect_response_blocked(
            "held text (chat completions)",
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::sse(sse::chat_completion_script_exact("too late", "test-model")),
        ),
    ];
    let result = fx
        .run(
            &["-p", "do the work", "--trust", "--yolo", "--output-format", "json"],
            &[("FUIGO_MAX_RUNTIME_SECS", "8")],
        )
        .await;
    assert!(
        fx.server.request_log_summary().contains("held text")
            || fx.server.has_responses_request()
            || fx.server.has_chat_completion_request(),
        "precondition: the model request was in flight when the limit passed\nrequests:\n{}",
        fx.server.request_log_summary()
    );
    assert_budget_denial(&fx, &result, "execution_runtime_limit");
}

/// The remedy B4's stderr line prints names `--allow`; the guide's example for the shell is
/// `--allow "Bash"`. Lane A2 saw the shell tool refused with `headless_never_approves` under exactly
/// that flag. A rule that is documented to work must let the tool run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allow_bash_lets_the_shell_tool_run_headless() {
    let fx = fixture().await;
    let _call = script_shell_call(&fx.server, "touch allowed.txt");
    let _then = script_text(&fx.server, "done");
    let result = fx
        .run(
            &["-p", "do the work", "--trust", "--allow", "Bash", "--output-format", "json"],
            &[],
        )
        .await;
    assert_eq!(
        result.status.code(),
        Some(0),
        "`--allow Bash` must pre-approve the shell tool\nstdout:\n{}\nstderr:\n{}\nrequests:\n{}",
        result.stdout,
        result.stderr,
        fx.server.request_log_summary()
    );
    assert!(!result.stderr.contains("headless_never_approves"), "{}", result.stderr);
    assert!(
        fx.workspace_file("allowed.txt").exists(),
        "the allowed command must have run\nstdout:\n{}\nstderr:\n{}\nlast request:\n{}",
        result.stdout,
        result.stderr,
        last_request_tail(&fx.server)
    );
}

/// The exact A2 command: a redirect into a file in the workspace. No `--allow` rule can pre-approve it:
/// a write by redirect is invisible to the words a rule matches, so the permission layer keeps it behind
/// a prompt on purpose (`narrow_allow_clears_write_floor`), and headless mode has nobody to ask. That is
/// the documented security floor, not the bug. The bug A2 hit is that the remedy printed for it said
/// "pass --allow", which cannot work here: the remedy must name what does, `--always-approve`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redirect_allow_bash_cannot_cover_names_the_remedy_that_works() {
    let fx = fixture().await;
    let _call = script_shell_call(&fx.server, "echo allowed > allowed.txt");
    let _then = script_text(&fx.server, "done");
    let result = fx
        .run(
            &["-p", "do the work", "--trust", "--allow", "Bash", "--output-format", "json"],
            &[],
        )
        .await;
    assert_eq!(
        result.status.code(),
        Some(3),
        "stdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
    assert!(!fx.workspace_file("allowed.txt").exists(), "nothing approved the write");
    let doc: serde_json::Value = serde_json::from_str(result.stdout.trim()).unwrap_or_else(|e| {
        panic!("stdout must stay exactly one JSON value ({e}): {}", result.stdout)
    });
    let remedy = doc["permissionDenied"]["remedy"].as_str().unwrap_or_default().to_owned();
    for text in [result.stderr.as_str(), remedy.as_str()] {
        assert!(
            text.contains("--always-approve") && text.contains("redirect"),
            "the remedy must say that a redirecting shell command needs --always-approve, since no \
             --allow rule covers it: {text}"
        );
    }
}

/// The remedy that line names really works: the identical turn under `--always-approve` runs the command.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_same_redirect_under_always_approve_runs() {
    let fx = fixture().await;
    let _call = script_shell_call(&fx.server, "echo allowed > allowed.txt");
    let _then = script_text(&fx.server, "done");
    let result = fx
        .run(
            &["-p", "do the work", "--trust", "--always-approve", "--output-format", "json"],
            &[],
        )
        .await;
    assert_eq!(
        result.status.code(),
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
    assert_eq!(
        std::fs::read_to_string(fx.workspace_file("allowed.txt")).unwrap_or_default(),
        "allowed\n",
        "the approved command must have run\nlast request:\n{}",
        last_request_tail(&fx.server)
    );
}
