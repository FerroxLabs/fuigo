//! ROWS-A2 (1.0.32) hook rows: 52.6 localhost HTTP hooks and load-time URL errors, 61.5 spawn failures name the
//! program, 59.6 PowerShell `$input` detection.

use crate::config::{HandlerType, HookProvenance, HookSpec, parse_hook_file};
use crate::error::HookError;
use crate::event::{HookEventEnvelope, HookEventName, HookPayload};
use crate::runner::command::run_command_hook;
use crate::runner::http::run_http_hook;
use crate::runner::{GateKind, HookRunnerResult, RunContext};
use std::path::Path;

fn envelope() -> HookEventEnvelope {
    HookEventEnvelope {
        hook_event_name: HookEventName::Stop,
        session_id: "rowsa2".into(),
        cwd: "/tmp".into(),
        workspace_root: "/tmp".into(),
        timestamp: "2026-01-01T00:00:00Z".into(),
        transcript_path: None,
        client_identifier: None,
        prompt_id: None,
        permission_mode: None,
        payload: HookPayload::Stop {
            reason: "test".into(),
            stop_hook_active: false,
            last_assistant_message: None,
            background_tasks: None,
            session_crons: None,
        },
    }
}

fn ctx() -> RunContext<'static> {
    RunContext { session_id: "rowsa2", workspace_root: "/tmp", process_scope: None }
}

fn spec_with(handler_type: HandlerType) -> HookSpec {
    HookSpec {
        name: "rowsa2".into(),
        event: HookEventName::Stop,
        handler_type,
        configured_matcher: None,
        matcher: None,
        enabled: true,
        command: None,
        command_raw: None,
        args: None,
        shell: None,
        url: None,
        url_raw: None,
        timeout_ms: 5_000,
        source_dir: std::env::temp_dir(),
        extra_env: Default::default(),
        layer: HookProvenance::File,
    }
}

/// One-shot local HTTP server answering `200 {}`; returns its port and a flag set when a request arrived.
async fn local_server() -> (u16, std::sync::Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[allow(clippy::disallowed_methods)] // local mock server; no TLS policy applies
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hit = std::sync::Arc::new(AtomicBool::new(false));
    let seen = std::sync::Arc::clone(&hit);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            seen.store(true, Ordering::SeqCst);
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
                .await;
            let _ = socket.flush().await;
        }
    });
    (port, hit)
}

#[tokio::test]
async fn http_hook_to_a_localhost_url_is_delivered() {
    for host in ["127.0.0.1", "localhost"] {
        let (port, hit) = local_server().await;
        let mut spec = spec_with(HandlerType::Http);
        let url = format!("http://{host}:{port}/hook");
        spec.url = Some(url.clone());
        spec.url_raw = Some(url);
        let (result, _, info, _) = run_http_hook(&spec, &envelope(), &ctx(), GateKind::Observe).await;
        assert!(
            matches!(result, HookRunnerResult::Success),
            "an http:// hook to {host} must run, got {result:?} ({info:?})"
        );
        assert!(hit.load(std::sync::atomic::Ordering::SeqCst), "the {host} server never saw the request");
    }
}

#[tokio::test]
async fn http_hook_to_a_non_local_http_url_is_still_refused() {
    let mut spec = spec_with(HandlerType::Http);
    spec.url = Some("http://93.184.216.34/hook".into());
    spec.url_raw = spec.url.clone();
    let (result, _, _, _) = run_http_hook(&spec, &envelope(), &ctx(), GateKind::Observe).await;
    match result {
        HookRunnerResult::Failed(reason) => assert!(reason.contains("https://"), "{reason}"),
        other => panic!("a plain-http public URL must be refused, got {other:?}"),
    }
}

fn http_hook_json(url: &str) -> String {
    serde_json::json!({ "hooks": { "Stop": [ { "hooks": [ { "type": "http", "url": url } ] } ] } }).to_string()
}

#[test]
fn an_invalid_hook_url_is_reported_when_the_hooks_load() {
    for (url, needle) in [
        ("not a url", "invalid"),
        ("ftp://example.com/hook", "https://"),
        ("http://example.com/hook", "https://"),
        ("https://", "invalid"),
    ] {
        let (specs, errors) = parse_hook_file(&http_hook_json(url), Path::new("/tmp/rowsa2-hooks.json"));
        assert!(specs.is_empty(), "{url}: a hook whose URL can never work must not load: {specs:?}");
        assert_eq!(errors.len(), 1, "{url}: {errors:?}");
        match &errors[0] {
            HookError::InvalidConfig { detail, .. } => assert!(detail.contains(needle), "{url}: {detail}"),
            other => panic!("{url}: expected InvalidConfig, got {other:?}"),
        }
    }
}

#[test]
fn valid_and_templated_hook_urls_still_load() {
    for url in [
        "https://example.com/hook",
        "http://localhost:8080/hook",
        "http://127.0.0.1:8080/hook",
        "http://[::1]:8080/hook",
        "https://${ROWSA2_HOST_NOT_SET}/hook",
        "${ROWSA2_URL_NOT_SET}",
    ] {
        let (specs, errors) = parse_hook_file(&http_hook_json(url), Path::new("/tmp/rowsa2-hooks.json"));
        assert!(errors.is_empty(), "{url}: {errors:?}");
        assert_eq!(specs.len(), 1, "{url}");
    }
}

/// A script whose `#!` interpreter does not exist passes every pre-spawn check (the file is there and executable) and
/// then fails in `exec`, with the bare "No such file or directory" that names nothing.
#[cfg(unix)]
#[tokio::test]
async fn a_spawn_failure_names_the_program_that_failed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("badshebang-hook.sh");
    std::fs::write(&script, "#!/nonexistent-rowsa2/interpreter\necho hi\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut spec = spec_with(HandlerType::Command);
    let program = script.to_string_lossy().into_owned();
    spec.command = Some(program.clone().into());
    spec.command_raw = Some(program);
    spec.args = Some(vec!["--flag".into()]);
    let (result, _, _) = run_command_hook(&spec, &envelope(), &ctx(), GateKind::Observe).await;
    match result {
        HookRunnerResult::Failed(message) => {
            assert!(message.contains("badshebang-hook.sh"), "the failure must name the program: {message}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn powershell_input_is_recognised_outside_single_quotes_only() {
    use crate::runner::command::reads_powershell_input;
    for yes in [
        "$input | ConvertFrom-Json",
        "$INPUT|ConvertFrom-Json | % { $_.cwd }",
        "$j = $input | Out-String; Write-Host $j",
        "\"$input\"",
        "foreach ($line in $input) { $line }",
    ] {
        assert!(reads_powershell_input(yes), "{yes}");
    }
    for no in [
        "Write-Host 'the $input stays literal'",
        "Write-Host $inputs",
        "Write-Host $input_dir",
        "Write-Host `$input",
        "echo hello",
    ] {
        assert!(!reads_powershell_input(no), "{no}");
    }
}
