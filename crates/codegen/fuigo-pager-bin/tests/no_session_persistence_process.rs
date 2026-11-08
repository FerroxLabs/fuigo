//! F12 (1.0.41): `--no-session-persistence` at the PROCESS boundary (the built `fuigo-pager` binary).
//!
//! With the flag, a headless run saves nothing under `FUIGO_HOME/sessions`: no session folder, no
//! `session_search.sqlite` row, no `prompt_history.jsonl` line, nothing modified. The run itself is unchanged: the
//! tool runs, the reply prints, and `--output-format json` still carries a session id (one nothing can resume).
//! Without the flag the same turn persists as before. `--resume`/`--continue` with the flag is a clear error.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fuigo_test_support::{
    InferenceEndpoint, InferenceExpectation, InferenceRequestMatcher, MockInferenceServer,
    ScriptedResponse, TestSandbox, run_headless_in_sandbox_borrowed, sse,
};

/// The pager binary cargo built for this test run (`PAGER_BINARY` under Bazel), like the sibling tests.
fn pager_binary() -> PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

/// One file's identity for the before/after comparison: size, mtime and a content hash.
type Entry = (u64, Option<std::time::SystemTime>, u64);

/// Every file and directory under `root`, by path relative to it (directories carry a zero entry, so a new empty
/// directory is a difference too).
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Entry>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let rel = path.strip_prefix(root).unwrap().to_path_buf();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                out.insert(rel, (0, None, 0));
                walk(root, &path, out);
            } else {
                use std::hash::{Hash as _, Hasher as _};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                std::fs::read(&path).unwrap_or_default().hash(&mut h);
                out.insert(rel, (meta.len(), meta.modified().ok(), h.finish()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// Paths added, removed or changed between two snapshots, each tagged `+`, `-` or `~`.
fn diff(before: &BTreeMap<PathBuf, Entry>, after: &BTreeMap<PathBuf, Entry>) -> Vec<String> {
    let mut out = Vec::new();
    for (path, entry) in after {
        match before.get(path) {
            None => out.push(format!("+ {}", path.display())),
            Some(old) if old != entry => out.push(format!("~ {}", path.display())),
            Some(_) => {}
        }
    }
    for path in before.keys() {
        if !after.contains_key(path) {
            out.push(format!("- {}", path.display()));
        }
    }
    out
}

/// One foreground turn asking for `search_replace` on `edit_me.txt`, on both wire backends (the unused one stays
/// unclaimed); the follow-up request gets the mock's default text reply.
fn script_edit(
    server: &MockInferenceServer,
    sandbox: &TestSandbox,
    old: &str,
    new: &str,
) -> Vec<InferenceExpectation> {
    let arguments = serde_json::json!({
        "file_path": sandbox.workspace().join("edit_me.txt").to_string_lossy(),
        "old_string": old,
        "new_string": new,
    })
    .to_string();
    vec![
        server.expect_response(
            format!("edit to {new} (responses)"),
            InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
            ScriptedResponse::sse(sse::responses_api_reasoning_then_tool_call_events(
                "",
                "call-1",
                "search_replace",
                &arguments,
                "test-model",
            )),
        ),
        server.expect_response(
            format!("edit to {new} (chat completions)"),
            InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
            ScriptedResponse::sse(sse::chat_completions_reasoning_then_tool_call_events(
                "",
                "call-1",
                "search_replace",
                &arguments,
                "test-model",
            )),
        ),
    ]
}

async fn fixture() -> (MockInferenceServer, TestSandbox) {
    let server = MockInferenceServer::start()
        .await
        .expect("start the mock inference server");
    server.preset_allow_access();
    let sandbox = TestSandbox::builder().git().mock_url(server.url()).build();
    std::fs::write(sandbox.workspace().join("edit_me.txt"), "one\n")
        .expect("write the fixture file");
    (server, sandbox)
}

async fn run(sandbox: &TestSandbox, args: &[&str]) -> fuigo_test_support::HeadlessResult {
    let mut cmd = tokio::process::Command::new(pager_binary());
    cmd.args(args).current_dir(sandbox.workspace());
    let result = run_headless_in_sandbox_borrowed(cmd, sandbox).await;
    assert!(
        !result.timed_out,
        "the run must end on its own\nstderr:\n{}",
        result.stderr
    );
    result
}

/// An edit turn (`old` -> `new`) through `-p ... --yolo --output-format json` plus `extra`; asserts it succeeded,
/// ran the tool, and printed one JSON document, which it returns.
async fn edit_turn(
    server: &MockInferenceServer,
    sandbox: &TestSandbox,
    old: &str,
    new: &str,
    extra: &[&str],
) -> serde_json::Value {
    let _expectations = script_edit(server, sandbox, old, new);
    let mut args = vec![
        "-p",
        "edit the fixture",
        "--trust",
        "--yolo",
        "--output-format",
        "json",
    ];
    args.extend_from_slice(extra);
    let result = run(sandbox, &args).await;
    assert_eq!(
        result.status.code(),
        Some(0),
        "{args:?}\nstdout:\n{}\nstderr:\n{}\nrequests:\n{}",
        result.stdout,
        result.stderr,
        server.request_log_summary()
    );
    assert_eq!(
        std::fs::read_to_string(sandbox.workspace().join("edit_me.txt")).unwrap(),
        format!("{new}\n"),
        "the tool ran\nrequests:\n{}",
        server.request_log_summary()
    );
    assert!(
        !result.stderr.contains("nothing was written")
            && !result.stderr.contains("persistence is off"),
        "an unpersisted run is quiet about the writes it skips\nstderr:\n{}",
        result.stderr
    );
    serde_json::from_str(result.stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must stay one JSON value ({e}): {}", result.stdout))
}

/// Hook events a run reports by touching `hook-<event>` in the sandbox root (outside `FUIGO_HOME/sessions`).
const HOOK_EVENTS: [&str; 6] = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "Stop",
    "SessionEnd",
];

fn install_marker_hooks(sandbox: &TestSandbox) {
    let hooks_dir = sandbox.fuigo_home().join("hooks");
    std::fs::create_dir_all(&hooks_dir).expect("create the user hooks directory");
    let mut doc = serde_json::Map::new();
    for event in HOOK_EVENTS {
        let command = format!(
            "touch '{}'",
            sandbox.root().join(format!("hook-{event}")).display()
        );
        doc.insert(
            event.to_owned(),
            serde_json::json!([{"hooks": [{"type": "command", "command": command}]}]),
        );
    }
    std::fs::write(
        hooks_dir.join("markers.json"),
        serde_json::json!({"hooks": doc}).to_string(),
    )
    .expect("write the user hooks");
}

/// The hook events that fired since the last call (their markers are removed for the next run).
fn take_fired_hooks(sandbox: &TestSandbox) -> Vec<&'static str> {
    HOOK_EVENTS
        .into_iter()
        .filter(|event| std::fs::remove_file(sandbox.root().join(format!("hook-{event}"))).is_ok())
        .collect()
}

/// The session id a `--output-format json` document names.
fn session_id(doc: &serde_json::Value) -> String {
    doc.get("sessionId")
        .or_else(|| doc.get("session_id"))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("the JSON document carries a session id: {doc}"))
        .to_owned()
}

fn find_named(root: &Path, name: &str) -> Vec<PathBuf> {
    snapshot(root)
        .into_keys()
        .filter(|p| p.file_name().is_some_and(|n| n == name))
        .collect()
}

/// The key test: a default turn persists (and seeds `session_search.sqlite` and `prompt_history.jsonl`); the same
/// turn with `--no-session-persistence` then adds, removes and modifies nothing under `FUIGO_HOME/sessions`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_headless_turn_with_no_session_persistence_writes_nothing_under_sessions() {
    let (server, sandbox) = fixture().await;
    let sessions = sandbox.fuigo_home().join("sessions");
    install_marker_hooks(&sandbox);

    // Default: the turn persists as before.
    let home_before = snapshot(sandbox.fuigo_home());
    let doc = edit_turn(&server, &sandbox, "one", "two", &[]).await;
    let home_after = snapshot(sandbox.fuigo_home());
    eprintln!(
        "default run, FUIGO_HOME writes:\n{}",
        diff(&home_before, &home_after).join("\n")
    );
    let first_id = session_id(&doc);
    let default_doc = doc;
    let default_hooks = take_fired_hooks(&sandbox);
    assert!(
        default_hooks.contains(&"PostToolUse"),
        "the marker hooks run: {default_hooks:?}"
    );
    eprintln!("hooks fired without the flag: {default_hooks:?}");
    let events = find_named(&sessions, "events.jsonl");
    assert!(
        events
            .iter()
            .any(|p| p.to_string_lossy().contains(&first_id)),
        "the default run persists its session {first_id}: {events:?}"
    );
    assert!(
        !find_named(&sessions, "prompt_history.jsonl").is_empty(),
        "the default run records its prompt"
    );

    // --no-session-persistence: nothing under sessions changes.
    let before = snapshot(&sessions);
    let home_before = snapshot(sandbox.fuigo_home());
    let doc = edit_turn(
        &server,
        &sandbox,
        "two",
        "three",
        &["--no-session-persistence"],
    )
    .await;
    let home_after = snapshot(sandbox.fuigo_home());
    let after = snapshot(&sessions);
    eprintln!(
        "--no-session-persistence run, FUIGO_HOME writes:\n{}",
        diff(&home_before, &home_after).join("\n")
    );
    let second_id = session_id(&doc);
    assert_ne!(second_id, first_id, "a fresh session id is still reported");
    let keys = |d: &serde_json::Value| {
        d.as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    };
    assert_eq!(
        keys(&doc),
        keys(&default_doc),
        "the JSON document keeps its shape\nflag: {doc}\ndefault: {default_doc}"
    );
    assert_eq!(
        take_fired_hooks(&sandbox),
        default_hooks,
        "hooks (SessionEnd included, when the build fires it) run exactly as without the flag"
    );
    assert_eq!(
        diff(&before, &after),
        Vec::<String>::new(),
        "--no-session-persistence must not add, remove or modify anything under FUIGO_HOME/sessions"
    );
    assert!(
        !after
            .keys()
            .any(|p| p.to_string_lossy().contains(&second_id)),
        "no folder or file names the unpersisted session {second_id}"
    );
}

/// `--resume`/`--continue` need a stored session, which the flag says not to keep: a clear error, before any turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_or_continue_with_no_session_persistence_is_a_clear_error() {
    let (server, sandbox) = fixture().await;
    for extra in [
        &["--resume", "0b6f7e0a-0000-4000-8000-000000000001"][..],
        &["--continue"][..],
    ] {
        let mut args = vec!["-p", "hi", "--trust", "--no-session-persistence"];
        args.extend_from_slice(extra);
        let result = run(&sandbox, &args).await;
        assert_ne!(
            result.status.code(),
            Some(0),
            "{args:?} must fail\nstdout:\n{}",
            result.stdout
        );
        assert!(
            result.stderr.contains("--no-session-persistence")
                && result.stderr.contains("cannot be used with"),
            "{args:?}: the error names the flag and the conflict\nstderr:\n{}",
            result.stderr
        );
        assert!(
            !server.requests().iter().any(|e| e.method == "POST"),
            "{args:?}: refused before any model request\nrequests:\n{}",
            server.request_log_summary()
        );
    }
    assert!(
        !sandbox.fuigo_home().join("sessions").exists()
            || snapshot(&sandbox.fuigo_home().join("sessions")).is_empty(),
        "a refused run writes no session state"
    );
}

/// Review r1 H3: the same promise on a COLD home (nothing under `FUIGO_HOME/sessions` yet), with the sandbox on and a
/// subagent spawned that runs its own model turn, and then over an old (40-day) `permission.toml` with
/// `edit_policy = "allow"` (which 1.0.40's spawn migrated and its janitor removed): nothing under
/// `FUIGO_HOME/sessions` is created, modified or removed. An AllowAlways answer cannot be driven from a headless run
/// (`--yolo` answers AllowOnce whenever offered, and without it headless never approves), so that write is proven in
/// fuigo-workspace `r1h3_without_session_persistence_permission_state_touches_nothing_under_sessions`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::disallowed_methods,
    reason = "F5-A: the test reads the cwd bucket path only to seed an old permission.toml in a temp FUIGO_HOME and to assert nothing was written under sessions; it never writes a session folder"
)]
async fn r1h3_sandboxed_subagent_runs_on_a_cold_home_and_over_old_permission_state_write_nothing_under_sessions() {
    let (server, sandbox) = fixture().await;
    let sessions = sandbox.fuigo_home().join("sessions");
    let arguments = serde_json::json!({
        "description": "r1h3 child",
        "prompt": "say hi",
        "subagent_type": "general-purpose",
    })
    .to_string();
    let turn = |label: &'static str| {
        let (server, sandbox, arguments) = (&server, &sandbox, &arguments);
        async move {
            // The parent's first request spawns the subagent; the subagent's own turn and the parent's follow-up get
            // the mock's default text reply (`Echo: <last user text>`).
            let _expectations = [
                server.expect_response(
                    format!("{label}: spawn (responses)"),
                    InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
                    ScriptedResponse::sse(sse::responses_api_reasoning_then_tool_call_events(
                        "",
                        "call-t",
                        "spawn_subagent",
                        arguments,
                        "test-model",
                    )),
                ),
                server.expect_response(
                    format!("{label}: spawn (chat completions)"),
                    InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
                    ScriptedResponse::sse(sse::chat_completions_reasoning_then_tool_call_events(
                        "",
                        "call-t",
                        "spawn_subagent",
                        arguments,
                        "test-model",
                    )),
                ),
            ];
            let posts_before = server
                .requests()
                .iter()
                .filter(|e| e.method == "POST")
                .count();
            let mut cmd = tokio::process::Command::new(pager_binary());
            cmd.args([
                "-p",
                "spawn a subagent",
                "--trust",
                "--yolo",
                "--no-session-persistence",
                "--sandbox",
                "workspace",
            ])
            .env("FUIGO_SANDBOX_MODE", "observe")
            .current_dir(sandbox.workspace());
            let result = run_headless_in_sandbox_borrowed(cmd, sandbox).await;
            assert!(
                !result.timed_out,
                "{label}: the run ends\nstderr:\n{}",
                result.stderr
            );
            assert_eq!(
                result.status.code(),
                Some(0),
                "{label}\nstdout:\n{}\nstderr:\n{}",
                result.stdout,
                result.stderr
            );
            let posts: Vec<String> = server
                .requests()
                .iter()
                .filter(|e| e.method == "POST")
                .skip(posts_before)
                .map(|e| format!("{e:?}"))
                .collect();
            let last = posts.last().cloned().unwrap_or_default();
            assert!(
                posts.len() >= 3 && last.contains("<subagent_result>") && last.contains("Echo: say hi"),
                "{label}: the subagent spawned and ran its own turn ({} model requests)\n{}\nstderr: {}",
                posts.len(),
                server.request_log_summary(),
                result.stderr
            );
        }
    };

    // Cold home.
    assert!(
        !sessions.exists() || snapshot(&sessions).is_empty(),
        "fixture: a cold home"
    );
    let home_before = snapshot(sandbox.fuigo_home());
    turn("cold home").await;
    let made: Vec<String> = diff(&home_before, &snapshot(sandbox.fuigo_home()))
        .into_iter()
        .filter(|line| line[2..].starts_with("sessions"))
        .collect();
    assert_eq!(
        made,
        Vec::<String>::new(),
        "a cold home's sessions folder is not created or written"
    );

    // Over an old permission.toml with edit_policy = "allow".
    let bucket = fuigo_config::sessions_cwd_dir_in(
        sandbox.fuigo_home(),
        &sandbox.workspace().to_string_lossy(),
    );
    std::fs::create_dir_all(&bucket).unwrap();
    let file = bucket.join("permission.toml");
    std::fs::write(&file, "edit_policy = \"allow\"\n").unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(40 * 24 * 3600);
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(old)
        .unwrap();
    let before = snapshot(&sessions);
    turn("old permission state").await;
    assert_eq!(
        diff(&before, &snapshot(&sessions)),
        Vec::<String>::new(),
        "the old permission state is neither migrated nor removed, and nothing else appears"
    );
}

/// Review r2 (F12), the black-box oracle: for every {cold home, warm home with an existing 0700 cwd bucket} x sandbox
/// {off, observe, enforce, strict}, a headless `--no-session-persistence` run whose model asks for a shell command
/// and then a subagent (which runs its own turn) must (a) create or modify NOTHING under `FUIGO_HOME/sessions`
/// (path, size and mtime of the whole tree, before and after) and (b) not refuse the shell command. It names no call
/// site: whatever a future helper writes under the tree, or refuses, shows up here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::disallowed_methods,
    reason = "F5-A: the test seeds a warm cwd bucket by path in a temp FUIGO_HOME and asserts nothing under sessions changed; it never writes a session folder"
)]
async fn r2_no_session_persistence_matrix_cold_and_warm_home_by_sandbox_mode_writes_nothing_and_refuses_nothing() {
    use std::os::unix::fs::PermissionsExt as _;
    let mut failures = Vec::new();
    for warm in [false, true] {
        for mode in ["off", "observe", "enforce", "strict"] {
            let cell = format!("{} home / sandbox {mode}", if warm { "warm" } else { "cold" });
            let (server, sandbox) = fixture().await;
            let sessions = sandbox.fuigo_home().join("sessions");
            if warm {
                let bucket = fuigo_config::sessions_cwd_dir_in(
                    sandbox.fuigo_home(),
                    &sandbox.workspace().to_string_lossy(),
                );
                std::fs::create_dir_all(&bucket).unwrap();
                for dir in [&sessions, &bucket] {
                    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
                }
            }
            let shell_args = serde_json::json!({
                "command": "printf r2-shell-ran > r2_shell_ran.txt",
                "description": "r2 shell probe",
            })
            .to_string();
            let spawn_args = serde_json::json!({
                "description": "r2 child",
                "prompt": "say hi",
                "subagent_type": "general-purpose",
            })
            .to_string();
            // Registered in order: the parent's first request runs the shell command, its next one spawns the subagent;
            // the subagent's own turn and the parent's last request get the mock's default text reply.
            let mut _expectations = Vec::new();
            for (label, call, name, arguments) in [
                ("shell", "call-s", "run_terminal_command", &shell_args),
                ("spawn", "call-t", "spawn_subagent", &spawn_args),
            ] {
                _expectations.push(server.expect_response(
                    format!("{cell}: {label} (responses)"),
                    InferenceRequestMatcher::foreground(InferenceEndpoint::Responses),
                    ScriptedResponse::sse(sse::responses_api_reasoning_then_tool_call_events(
                        "", call, name, arguments, "test-model",
                    )),
                ));
                _expectations.push(server.expect_response(
                    format!("{cell}: {label} (chat completions)"),
                    InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
                    ScriptedResponse::sse(sse::chat_completions_reasoning_then_tool_call_events(
                        "", call, name, arguments, "test-model",
                    )),
                ));
            }
            // The whole `sessions` tree seen from FUIGO_HOME, so the folder itself appearing (empty) counts too.
            let tree = || {
                snapshot(sandbox.fuigo_home())
                    .into_iter()
                    .filter(|(path, _)| path.starts_with("sessions"))
                    .collect::<BTreeMap<_, _>>()
            };
            let before = tree();
            let mut cmd = tokio::process::Command::new(pager_binary());
            cmd.args(["-p", "run a command, then a subagent", "--trust", "--yolo", "--no-session-persistence"])
                .args(["--sandbox", if mode == "strict" { "strict" } else { "workspace" }])
                .env("FUIGO_SANDBOX_MODE", if mode == "strict" { "enforce" } else { mode })
                .current_dir(sandbox.workspace());
            let result = run_headless_in_sandbox_borrowed(cmd, &sandbox).await;
            let stderr_lower = result.stderr.to_lowercase();
            if mode == "strict"
                && (stderr_lower.contains("unsupported") || stderr_lower.contains("not supported"))
            {
                println!("SKIPPED {cell}: strict sandbox is not supported on this platform: {}", result.stderr.trim());
                continue;
            }
            let changed = diff(&before, &tree());
            if !changed.is_empty() {
                failures.push(format!("{cell}: (a) sessions/ changed: {changed:?}"));
            }
            let ran = std::fs::read_to_string(sandbox.workspace().join("r2_shell_ran.txt")).ok();
            if result.timed_out || result.status.code() != Some(0) || ran.as_deref() != Some("r2-shell-ran") {
                failures.push(format!(
                    "{cell}: (b) the shell command did not run (exit {:?}, file {ran:?})\nstderr:\n{}\nrequests:\n{}",
                    result.status.code(),
                    result.stderr,
                    {
                        let posts: Vec<String> = server.requests().iter().filter(|e| e.method == "POST").map(|e| format!("{e:?}")).collect();
                        let tail = |s: &String| s.rfind("call-s").map(|i| s[i.saturating_sub(300)..(i + 700).min(s.len())].to_string()).unwrap_or_else(|| "no call-s in the request".into());
                        format!("{}\nsecond request tail: {}", server.request_log_summary(), posts.get(1).map(tail).unwrap_or_default())
                    }
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{} cell(s) failed:\n{}", failures.len(), failures.join("\n---\n"));
}
