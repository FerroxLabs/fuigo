//! 1.0.47 S2 (SL-06), design §7 test 7 (E3): the canary sweep at the PROCESS boundary. A secret-named environment
//! value (`DEPLOY_TOKEN`) reaches the model's tool call, the shell output (past the inline cap), the typed prompt and
//! the final answer of a real `fuigo -p` run. Afterwards no file under `$HOME` may hold it, except the two verbatim
//! stores (`/rewind` copies and permission grants). The control `DEPLOY_REGION` (not a secret name) survives, and the
//! headless stdout still shows the value: the layer changes only what is written at rest. Synthetic values only.
//!
//! The sweep checks every spelling the layer covers, not only the raw one (Fable S2 confirm review): a second value
//! (`DEPLOY_PASSWORD`, with a quote, a slash, a space and a plus, so its JSON-escaped and percent spellings differ from
//! the raw one) is printed raw, and both values are also printed base64-encoded; the sweep matches the raw, escaped,
//! percent and base64 spellings with the layer's own matcher.
//!
//! Fails on base (0bc521fd): the transcript, prompt history and terminal output files hold the value verbatim.

#![cfg(unix)]

use fuigo_test_support::{
    InferenceEndpoint, InferenceExpectation, InferenceRequestMatcher, MockInferenceServer,
    ScriptedResponse, TestSandbox, git_workdir, run_headless_in_sandbox_borrowed_with_env, sse,
};

/// File names this run writes under `sessions/` and `logs/`, each written through the session writer or
/// `fuigo_secrets::at_rest` (or a lock/verbatim store); a `.lock` sibling of any of them is fine.
const KNOWN: &[&str] = &[
    "unified.jsonl",
    "chat_history.jsonl",
    "events.jsonl",
    "prompt_context.json",
    "resources_state.json",
    "rewind_points.jsonl",
    "session_writer",
    "signals.json",
    "snapshot",
    "summary.json",
    "system_prompt.txt",
    "turn_owner",
    "updates.jsonl",
    "usage.json",
    "prompt_history.jsonl",
    "session_search.sqlite",
];
const SHELL_TOOL: &str = "run_terminal_command";
// Split so the literal is not a token-shaped string in the source.
const TOKEN: &str = concat!("dpl_", "live_Q7x2Lm9VtR4kZp8N");
const PASSWORD: &str = concat!("pw \"Zq8/", "Vt4 Lm2+Kx9\"");
const REGION: &str = concat!("eu-", "central-canary-region-7");

fn pager_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

fn script(server: &MockInferenceServer, command: &str, answer: &str) -> Vec<InferenceExpectation> {
    let arguments =
        serde_json::json!({"command": command, "description": "print the deploy settings"})
            .to_string();
    let mut out = Vec::new();
    for (label, endpoint, call, text) in [
        (
            "responses",
            InferenceEndpoint::Responses,
            sse::responses_api_reasoning_then_tool_call_events(
                "",
                "call-1",
                SHELL_TOOL,
                &arguments,
                "test-model",
            ),
            sse::responses_api_script_exact(answer, "test-model"),
        ),
        (
            "chat completions",
            InferenceEndpoint::ChatCompletions,
            sse::chat_completions_reasoning_then_tool_call_events(
                "",
                "call-1",
                SHELL_TOOL,
                &arguments,
                "test-model",
            ),
            sse::chat_completion_script_exact(answer, "test-model"),
        ),
    ] {
        out.push(server.expect_response(
            format!("canary shell call ({label})"),
            InferenceRequestMatcher::foreground(endpoint),
            ScriptedResponse::sse(call),
        ));
        out.push(server.expect_response(
            format!("canary answer ({label})"),
            InferenceRequestMatcher::foreground(endpoint),
            ScriptedResponse::sse(text),
        ));
    }
    out
}

/// Every regular file under `dir`, recursively (symlinks are not followed). A missing `dir` is empty; any other error
/// fails the test, since a sweep that skips evidence proves nothing (Astra code review Medium 5).
fn files_under(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => panic!("read_dir {}: {e}", dir.display()),
    };
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("entry in {}: {e}", dir.display()));
        let kind = entry
            .file_type()
            .unwrap_or_else(|e| panic!("file_type {}: {e}", entry.path().display()));
        if kind.is_dir() {
            files_under(&entry.path(), out);
        } else if kind.is_file() {
            out.push(entry.path());
        }
    }
}

/// The two verbatim stores (design §2.3): `/rewind` copies and permission grants keep their exact bytes.
fn is_verbatim_store(path: &std::path::Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    name.starts_with("rewind_points.jsonl")
        || name.contains(".pre-rewind")
        || name.starts_with("permission")
        || name.contains("grants")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secret_env_value_is_never_written_at_rest() {
    let server = MockInferenceServer::start()
        .await
        .expect("start the mock inference server");
    server.preset_allow_access();
    let workdir = git_workdir();
    let sandbox = TestSandbox::builder().mock_url(server.url()).build();
    // Foreground output past the inline cap: the value on every one of 3000 lines, plus the control.
    // Then the second value raw and both base64-encoded (encoded spellings, not only the raw one, Fable confirm review).
    let command = format!(
        "echo DEPLOY_REGION={REGION}; seq 1 3000 | sed 's/^/{TOKEN} line /'; printf '%s\\n' '{PASSWORD}'; \
         printf %s '{PASSWORD}' | base64; printf %s '{TOKEN}' | base64"
    );
    let answer = format!("The deploy token is {TOKEN} in {REGION}.");
    let _expect = script(&server, &command, &answer);
    let prompt = format!("Check the deploy settings; the token is {TOKEN}.");

    let mut cmd = tokio::process::Command::new(pager_binary());
    cmd.args([
        "-p",
        &prompt,
        "--trust",
        "--always-approve",
        "--output-format",
        "json",
    ])
    .current_dir(workdir.workspace());
    let env = [
        ("DEPLOY_TOKEN", TOKEN),
        ("DEPLOY_PASSWORD", PASSWORD),
        ("DEPLOY_REGION", REGION),
    ];
    let result = run_headless_in_sandbox_borrowed_with_env(cmd, &sandbox, &env).await;
    let context = format!(
        "stdout:\n{}\nstderr:\n{}\nrequests:\n{}",
        result.stdout,
        result.stderr,
        server.request_log_summary()
    );
    assert!(!result.timed_out, "the run must end on its own\n{context}");
    assert_eq!(result.status.code(), Some(0), "{context}");
    // Model-facing and live display are unchanged: the layer only touches bytes at rest.
    assert!(
        result.stdout.contains(TOKEN),
        "headless stdout still shows the value\n{context}"
    );

    let mut files = Vec::new();
    files_under(sandbox.home(), &mut files);
    files_under(sandbox.fuigo_home(), &mut files);
    files.sort();
    files.dedup();
    let root = sandbox.fuigo_home();
    let census: Vec<String> = files
        .iter()
        .filter_map(|f| f.strip_prefix(root).ok())
        .filter(|rel| rel.starts_with("sessions") || rel.starts_with("logs"))
        .map(|rel| rel.display().to_string())
        .collect();
    eprintln!(
        "census of the at-rest roots ({} files):\n{}",
        census.len(),
        census.join("\n")
    );
    // Census (Fable r2 #1.4): a file name under the roots that nobody classified fails, even if the canary missed it.
    let unknown: Vec<&String> = census
        .iter()
        .filter(|f| {
            let name = f.rsplit('/').next().unwrap_or_default();
            let base = name.strip_suffix(".lock").unwrap_or(name);
            !(KNOWN.contains(&base) || (f.contains("/terminal/") && name.ends_with(".log")))
        })
        .collect();
    assert!(
        unknown.is_empty(),
        "files under the at-rest roots nobody classified: {unknown:?}"
    );
    assert!(
        census.iter().any(|f| f.ends_with("updates.jsonl")),
        "control: the session was persisted\n{}",
        census.join("\n")
    );

    // The layer's own matcher, holding exactly the two values: every spelling (raw, JSON-escaped once and twice,
    // percent, base64) of either is a leak.
    fuigo_secrets::at_rest::clear_for_tests();
    fuigo_secrets::at_rest::record(TOKEN);
    fuigo_secrets::at_rest::record(PASSWORD);
    let mut leaks = Vec::new();
    let mut control_seen = false;
    for file in &files {
        let bytes = std::fs::read(file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        let holds = |needle: &str| bytes.windows(needle.len()).any(|w| w == needle.as_bytes());
        control_seen |= holds(REGION);
        let leaked =
            holds(TOKEN) || holds(PASSWORD) || fuigo_secrets::at_rest::contains_any(&bytes);
        if leaked && !is_verbatim_store(file) {
            leaks.push(file.display().to_string());
        }
    }
    assert!(
        control_seen,
        "control: DEPLOY_REGION is not a secret name and must survive at rest"
    );
    assert!(
        leaks.is_empty(),
        "the canary was written at rest in:\n{}",
        leaks.join("\n")
    );
}
