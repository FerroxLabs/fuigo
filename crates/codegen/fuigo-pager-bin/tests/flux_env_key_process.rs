//! `FLUX_API_KEY` is a Flux credential at the PROCESS boundary (the built `fuigo-pager` binary), as `login --status`
//! already reports it: headless `-p` and `fuigo models` use it, exactly as they use `FUIGO_API_KEY`.
//!
//! Precedence, documented and pinned here: `FUIGO_API_KEY`, then `FUIGO_CODE_API_KEY`, then `FLUX_API_KEY`.
//! The mock inference server only answers a request that carries `Authorization: Bearer <expected key>`, so a run that
//! ignored the variable fails with 401 rather than passing by accident. Synthetic credentials only.

#![cfg(unix)]

use std::io::Read as _;
use std::process::Stdio;
use std::time::Duration;

use fuigo_test_support::{
    InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, MockModelEntry, ScriptedResponse, TestSandbox, sse,
};

const FLUX: &str = "flux-env-SYNTH-flux-key-0001";
const FUIGO: &str = "flux-env-SYNTH-fuigo-key-0002";
const SAVED: &str = "flux-env-SYNTH-saved-key-0004";
const LEGACY: &str = "flux-env-SYNTH-legacy-key-0003";

fn pager_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

/// Run `fuigo-pager <args>` to the end in `sandbox` and return (exit code, stdout, stderr).
fn run_child(sandbox: &TestSandbox, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = std::process::Command::new(pager_binary());
    sandbox.apply_to_std_command(&mut cmd);
    cmd.env("FUIGO_MAX_RETRIES", "0")
        .args(args)
        .current_dir(sandbox.workspace())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[allow(clippy::disallowed_methods)] // test-owned child, waited on (or killed and reaped) in this function
    let mut child = cmd.spawn().expect("spawn fuigo-pager");
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        String::from_utf8_lossy(&b).into_owned()
    });
    let err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        String::from_utf8_lossy(&b).into_owned()
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            break st;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the run must end on its own: {args:?}");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    (status.code(), out.join().unwrap(), err.join().unwrap())
}

/// A mock that answers inference only for `Authorization: Bearer <accepts>`, with one scripted text turn.
async fn server_accepting(accepts: &str) -> MockInferenceServer {
    let server = MockInferenceServer::start_with_required_auth(vec![MockModelEntry::new("test-model")], accepts)
        .await
        .expect("start the mock inference server");
    server.preset_allow_access();
    for (name, endpoint, events) in [
        ("hi (responses)", InferenceEndpoint::Responses, sse::responses_api_script_exact("hello there", "test-model")),
        (
            "hi (chat completions)",
            InferenceEndpoint::ChatCompletions,
            sse::chat_completion_script_exact("hello there", "test-model"),
        ),
    ] {
        let _ = server.expect_response(name, InferenceRequestMatcher::foreground(endpoint), ScriptedResponse::sse(events));
    }
    server
}

/// A sandbox whose Flux key variables are exactly `env` (the mock's own fake `FUIGO_API_KEY` is taken away first).
fn sandbox_with(server: &MockInferenceServer, env: &[(&str, &str)]) -> TestSandbox {
    let mut sandbox = TestSandbox::builder().git().mock_url(server.url()).build();
    for name in ["FUIGO_API_KEY", "FUIGO_CODE_API_KEY", "FLUX_API_KEY"] {
        sandbox.remove_env(name);
    }
    for (name, value) in env {
        sandbox.set_env(name, value);
    }
    sandbox
}

fn inference_authorizations(server: &MockInferenceServer) -> Vec<String> {
    server
        .requests()
        .iter()
        .filter(|e| e.method == "POST" && (e.path.contains("completions") || e.path.contains("responses")))
        .filter_map(|e| e.authorization.clone())
        .collect()
}

/// Run `-p` with `env` as the only Flux key variables and assert it signs in with `expected`.
async fn headless_uses(env: &'static [(&'static str, &'static str)], expected: &'static str) {
    let server = server_accepting(expected).await;
    let sandbox = sandbox_with(&server, env);
    let (code, stdout, stderr) =
        tokio::task::spawn_blocking(move || run_child(&sandbox, &["-p", "say hi", "--trust"])).await.unwrap();
    assert!(
        !stderr.contains("Not signed in") && !stdout.contains("Not signed in"),
        "{env:?}: headless -p ignored the key\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let sent = inference_authorizations(&server);
    assert!(
        !sent.is_empty() && sent.iter().all(|a| a == &format!("Bearer {expected}")),
        "{env:?}: the model request must carry the {expected} bearer, saw {sent:?}\nstderr:\n{stderr}"
    );
    assert_eq!(code, Some(0), "{env:?}: the run succeeds\nstdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("hello there"), "{env:?}: the scripted reply is printed\nstdout:\n{stdout}");
    for secret in [FLUX, FUIGO, LEGACY] {
        assert!(!stdout.contains(secret) && !stderr.contains(secret), "{env:?}: a key was printed");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headless_with_only_flux_api_key_authenticates() {
    headless_uses(&[("FLUX_API_KEY", FLUX)], FLUX).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headless_precedence_is_fuigo_then_legacy_then_flux() {
    headless_uses(&[("FUIGO_API_KEY", FUIGO), ("FUIGO_CODE_API_KEY", LEGACY), ("FLUX_API_KEY", FLUX)], FUIGO).await;
    headless_uses(&[("FUIGO_CODE_API_KEY", LEGACY), ("FLUX_API_KEY", FLUX)], LEGACY).await;
    headless_uses(&[("FUIGO_API_KEY", FUIGO), ("FLUX_API_KEY", FLUX)], FUIGO).await;
    // A blank higher-precedence variable does not hide a real one below it (discovery skips it the same way).
    headless_uses(&[("FUIGO_API_KEY", "  "), ("FLUX_API_KEY", FLUX)], FLUX).await;
}

/// Control: with no Flux key variable at all the same command still refuses, so the passes above are the variable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headless_with_no_key_still_says_not_signed_in() {
    let server = server_accepting(FLUX).await;
    let sandbox = sandbox_with(&server, &[]);
    let (code, stdout, stderr) =
        tokio::task::spawn_blocking(move || run_child(&sandbox, &["-p", "say hi", "--trust"])).await.unwrap();
    assert_eq!(code, Some(1), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stderr.contains("Not signed in"), "{stderr}");
    assert!(inference_authorizations(&server).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn models_with_only_flux_api_key_is_authenticated() {
    let server = server_accepting(FLUX).await;
    let sandbox = sandbox_with(&server, &[("FLUX_API_KEY", FLUX)]);
    let (code, stdout, stderr) =
        tokio::task::spawn_blocking(move || run_child(&sandbox, &["models"])).await.unwrap();
    assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("You are using FLUX_API_KEY."), "names the variable in use\nstdout:\n{stdout}");
    assert!(!stdout.contains("not authenticated"), "{stdout}");
    assert!(stdout.contains("test-model"), "the catalogue was fetched with the key\nstdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(!stdout.contains(FLUX) && !stderr.contains(FLUX), "the key was printed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn models_names_the_variable_that_wins() {
    let server = server_accepting(FUIGO).await;
    let sandbox = sandbox_with(&server, &[("FUIGO_API_KEY", FUIGO), ("FLUX_API_KEY", FLUX)]);
    let (code, stdout, stderr) =
        tokio::task::spawn_blocking(move || run_child(&sandbox, &["models"])).await.unwrap();
    assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("You are using FUIGO_API_KEY."), "{stdout}");
}

/// Defect 2 (E2E-MAC 1.0.32): a key saved by the picker or `login --provider flux`, with no env var, is a credential at
/// runtime and in `login --status`, so `fuigo models` must say so and list with it instead of "not authenticated".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn models_with_only_a_saved_key_says_which_credential_it_uses() {
    let server = server_accepting(SAVED).await;
    let sandbox = sandbox_with(&server, &[]);
    fuigo_shell::auth::store_api_key(sandbox.fuigo_home(), SAVED).expect("save the key");
    let (code, stdout, stderr) =
        tokio::task::spawn_blocking(move || run_child(&sandbox, &["models"])).await.unwrap();
    assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("Using your saved Flux Router key."), "names the credential\nstdout:\n{stdout}");
    assert!(!stdout.contains("not authenticated"), "{stdout}");
    assert!(stdout.contains("Default model:"), "the listing ran\nstdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(!stdout.contains(SAVED) && !stderr.contains(SAVED), "the key was printed");
}

/// The environment outranks the saved key, as at runtime, and the banner names the variable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn models_prefers_the_env_key_over_the_saved_key() {
    let server = server_accepting(FLUX).await;
    let sandbox = sandbox_with(&server, &[("FLUX_API_KEY", FLUX)]);
    fuigo_shell::auth::store_api_key(sandbox.fuigo_home(), SAVED).expect("save the key");
    let (code, stdout, stderr) =
        tokio::task::spawn_blocking(move || run_child(&sandbox, &["models"])).await.unwrap();
    assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("You are using FLUX_API_KEY."), "{stdout}");
    assert!(!stdout.contains("saved Flux Router key"), "{stdout}");
}

/// Control: no env key and no saved key still says so, so the passes above are the credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn models_with_no_key_says_not_authenticated() {
    let server = server_accepting(FLUX).await;
    let sandbox = sandbox_with(&server, &[]);
    let (_code, stdout, stderr) =
        tokio::task::spawn_blocking(move || run_child(&sandbox, &["models"])).await.unwrap();
    assert!(stdout.contains("You are not authenticated."), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(!stdout.contains("saved Flux Router key") && !stdout.contains("You are using"), "{stdout}");
}
