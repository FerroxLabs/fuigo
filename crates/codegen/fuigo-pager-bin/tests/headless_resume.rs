//! Headless resume must never select an unrelated recent session from a blank shell variable.
use fuigo_test_support::{MockInferenceServer, TestSandbox, run_headless_in_sandbox_borrowed};

fn pager_binary() -> std::path::PathBuf {
    std::env::var_os("PAGER_BINARY")
        .map(Into::into)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_fuigo-pager").into())
}

async fn run(sandbox: &TestSandbox, args: &[&str]) -> fuigo_test_support::HeadlessResult {
    let mut cmd = tokio::process::Command::new(pager_binary());
    cmd.args(args).current_dir(sandbox.workspace());
    run_headless_in_sandbox_borrowed(cmd, sandbox).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headless_resume_blank_fails_before_any_request() {
    let server = MockInferenceServer::start().await.unwrap();
    server.preset_allow_access();
    let sandbox = TestSandbox::builder().mock_url(server.url()).build();
    for value in ["", " ", "\t\n", "\u{2003}"] {
        let result = run(&sandbox, &["-p", "hello", "--resume", value, "--trust"]).await;
        assert!(!result.timed_out);
        assert!(!result.status.success());
        assert!(
            result.stderr.contains("--resume") && result.stderr.contains("--continue"),
            "value={value:?}: {}",
            result.stderr
        );
        assert_eq!(
            server.request_count(),
            0,
            "validation must precede all server requests"
        );
    }
    let result = run(&sandbox, &["-p", "hello", "--resume", "--trust"]).await;
    assert!(!result.status.success());
    assert!(result.stderr.contains("--continue"), "{}", result.stderr);
    assert!(
        result
            .stderr
            .contains("session ID or title in headless mode"),
        "{}",
        result.stderr
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headless_resume_keeps_real_id_title_and_continue() {
    let server = MockInferenceServer::start().await.unwrap();
    server.preset_allow_access();
    server.set_response("completed");
    let sandbox = TestSandbox::builder().mock_url(server.url()).build();
    let id = "31b75b60-c03d-4570-9607-0019505fae78";
    let first = run(
        &sandbox,
        &[
            "-p",
            "Resume regression title",
            "--session-id",
            id,
            "--trust",
            "--output-format",
            "json",
        ],
    )
    .await;
    assert!(first.status.success(), "{}\n{}", first.stdout, first.stderr);
    fn find_title(dir: &std::path::Path) -> Option<String> {
        for entry in std::fs::read_dir(dir).ok()?.flatten() {
            if entry.path().is_dir() {
                if let Some(title) = find_title(&entry.path()) {
                    return Some(title);
                }
            } else if entry.file_name() == "summary.json" {
                let summary: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(entry.path()).ok()?).ok()?;
                return summary["generated_title"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .or_else(|| summary["session_summary"].as_str())
                    .map(str::to_owned);
            }
        }
        None
    }
    let title =
        find_title(&sandbox.fuigo_home().join("sessions")).expect("persisted session title");
    assert!(!title.trim().is_empty());
    for flags in [
        vec!["--resume", id],
        vec!["--resume", title.as_str()],
        vec!["--continue"],
    ] {
        let mut args = vec!["-p", "next turn", "--trust", "--output-format", "json"];
        args.extend(flags);
        let result = run(&sandbox, &args).await;
        assert!(!result.timed_out);
        assert!(
            result.status.success(),
            "{args:?}: {}\n{}",
            result.stdout,
            result.stderr
        );
        let json: serde_json::Value = serde_json::from_str(&result.stdout).unwrap();
        assert_eq!(json["sessionId"].as_str(), Some(id), "{}", result.stdout);
    }
}

#[tokio::test]
async fn resume_help_explains_headless_target_and_continue() {
    let sandbox = TestSandbox::builder().build();
    let result = run(&sandbox, &["--help"]).await;
    assert!(result.status.success(), "{}", result.stderr);
    let help = result
        .stdout
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        help.contains(
            "Headless mode requires an ID or title; use --continue for the most recent session"
        ),
        "{help}"
    );
}
