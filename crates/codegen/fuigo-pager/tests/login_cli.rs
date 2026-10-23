//! `fuigo login` as a user runs it: the real binary, an empty home, no network.
//!
//! These spawn the pager binary, so they are `#[ignore]`d for ordinary Cargo runs like the other
//! binary tests; select them with `--ignored` and `PAGER_BINARY` set.

use std::process::{Command, Stdio};

fn pager_binary() -> std::path::PathBuf {
    for key in ["PAGER_BINARY", "CARGO_BIN_EXE_fuigo-pager"] {
        if let Some(value) = std::env::var_os(key) {
            let path = std::path::PathBuf::from(value);
            if path.exists() {
                return path;
            }
        }
    }
    panic!("PAGER_BINARY is required when these tests are selected");
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], env: &[(&str, &str)]) -> Run {
    run_with_stdin(args, env, None).0
}

/// Like [`run`], with `stdin` piped in (a non-TTY) and the Fuigo home returned for inspection.
#[allow(
    clippy::disallowed_methods,
    reason = "the child is reaped by wait_with_output before this function returns"
)]
fn run_with_stdin(
    args: &[&str],
    env: &[(&str, &str)],
    stdin: Option<&str>,
) -> (Run, tempfile::TempDir) {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path().join("home");
    let fuigo_home = temp.path().join("fuigo-home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&fuigo_home).unwrap();
    let mut command = Command::new(pager_binary());
    command
        .env_clear()
        .env("HOME", &home)
        .env("FUIGO_HOME", &fuigo_home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("TERM", "xterm-256color")
        .env("NO_COLOR", "1")
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(args)
        .envs(env.iter().copied());
    let mut child = command.spawn().expect("spawn the pager binary");
    if let Some(text) = stdin {
        use std::io::Write as _;
        child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().expect("run the pager binary");
    (
        Run {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        temp,
    )
}

const IGNORE: &str = "spawns the real pager binary; CI/Bazel provides PAGER_BINARY";

/// Bare `fuigo login` with no terminal used to go straight to single sign-on and fail with "No OAuth2
/// issuer is configured". It prints the options and the command for each, and exits 2.
#[test]
#[ignore = "spawns the real pager binary; CI/Bazel provides PAGER_BINARY"]
fn bare_login_without_a_terminal_prints_the_options_and_exits_2() {
    let _ = IGNORE;
    let out = run(&["login"], &[]);
    assert_eq!(out.code, Some(2), "stdout: {} stderr: {}", out.stdout, out.stderr);
    for expected in [
        "Choose how Fuigo reaches a model.",
        "Flux Router: one key, every model (recommended)",
        "fuigo login --provider flux",
        "fuigo login --provider chatgpt",
        "fuigo login --provider xai",
    ] {
        assert!(out.stdout.contains(expected), "missing {expected:?} in:\n{}", out.stdout);
    }
    let all = format!("{}{}", out.stdout, out.stderr);
    assert!(!all.contains("OAuth2 issuer"), "{all}");
    assert!(!all.to_lowercase().contains("enterprise"), "{all}");
    // The upstream product name, built from parts so this guard adds no line naming it to the tree.
    assert!(!all.contains(concat!("Grok", " Build")) && !all.contains("grok.com"), "{all}");
    // Flux is first.
    assert!(
        out.stdout.find("Flux Router").unwrap() < out.stdout.find("ChatGPT subscription").unwrap(),
        "{}",
        out.stdout
    );
}

/// The old path is still there, under its own name, and keeps its enterprise error.
#[test]
#[ignore = "spawns the real pager binary; CI/Bazel provides PAGER_BINARY"]
fn provider_sso_keeps_the_old_error_when_no_issuer_is_configured() {
    let out = run(&["login", "--provider", "sso"], &[]);
    assert_ne!(out.code, Some(0), "{}{}", out.stdout, out.stderr);
    let all = format!("{}{}", out.stdout, out.stderr);
    assert!(all.contains("No OAuth2 issuer is configured"), "{all}");
    assert!(!all.contains("Choose how Fuigo reaches a model."), "{all}");
}

#[test]
#[ignore = "spawns the real pager binary; CI/Bazel provides PAGER_BINARY"]
fn status_lists_every_connection_with_flux_first_and_masks_keys() {
    let out = run(
        &["login", "--status"],
        &[("OPENAI_API_KEY", "sk-test-openai-key-SECRETBODY-9876")],
    );
    assert_eq!(out.code, Some(0), "stdout: {} stderr: {}", out.stdout, out.stderr);
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert!(lines[0].starts_with("Flux Router [Recommended]: Not set"), "{}", out.stdout);
    assert!(lines[0].contains("fluxrouter.ai"), "{}", out.stdout);
    assert!(out.stdout.contains("ChatGPT subscription: not signed in: /login"), "{}", out.stdout);
    assert!(out.stdout.contains("Grok subscription: not signed in: /login"), "{}", out.stdout);
    assert!(out.stdout.contains("OpenAI API key: ready: OPENAI_API_KEY \u{2022}\u{2022}\u{2022}\u{2022}9876"), "{}", out.stdout);
    assert!(!out.stdout.contains("SECRETBODY"), "a key leaked: {}", out.stdout);
    assert!(!out.stderr.contains("SECRETBODY"), "a key leaked: {}", out.stderr);
}

#[test]
#[ignore = "spawns the real pager binary; CI/Bazel provides PAGER_BINARY"]
fn a_provider_key_login_reports_readiness_and_never_stores_the_key() {
    let missing = run(&["login", "--provider", "anthropic"], &[]);
    assert_eq!(missing.code, Some(2), "{}{}", missing.stdout, missing.stderr);
    assert!(missing.stderr.contains("not set: export ANTHROPIC_API_KEY"), "{}", missing.stderr);

    let ready = run(
        &["login", "--provider", "openai"],
        &[("OPENAI_API_KEY", "sk-test-openai-key-SECRETBODY-9876")],
    );
    assert_eq!(ready.code, Some(0), "{}{}", ready.stdout, ready.stderr);
    assert!(ready.stderr.contains("/provider openai <model-id>"), "{}", ready.stderr);
    assert!(!ready.stderr.contains("SECRETBODY") && !ready.stdout.contains("SECRETBODY"));
}

/// `fuigo login --provider flux < keyfile`: a key piped on a non-TTY stdin is read as one line, stored owner-only
/// in `auth.json`, and never echoed. A fake key throughout.
#[test]
#[ignore = "spawns the real pager binary; CI/Bazel provides PAGER_BINARY"]
fn flux_login_reads_a_key_piped_on_stdin() {
    const FAKE: &str = "flx-fake-key-0123456789abcdef";
    let (out, temp) = run_with_stdin(&["login", "--provider", "flux"], &[], Some(&format!("  {FAKE}  \n")));
    assert_eq!(out.code, Some(0), "stdout: {} stderr: {}", out.stdout, out.stderr);
    assert!(!out.stdout.contains(FAKE) && !out.stderr.contains(FAKE), "the key must never be echoed");
    assert!(!out.stderr.contains("could not read a key"), "{}", out.stderr);
    let auth = temp.path().join("fuigo-home").join("auth.json");
    let text = std::fs::read_to_string(&auth).expect("auth.json written");
    assert!(text.contains(FAKE), "the trimmed key is stored");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(&auth).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

/// An empty pipe is an error, not a stored empty key.
#[test]
#[ignore = "spawns the real pager binary; CI/Bazel provides PAGER_BINARY"]
fn flux_login_with_an_empty_stdin_fails_without_storing() {
    let (out, temp) = run_with_stdin(&["login", "--provider", "flux"], &[], Some("\n"));
    assert_ne!(out.code, Some(0), "stdout: {} stderr: {}", out.stdout, out.stderr);
    assert!(!temp.path().join("fuigo-home").join("auth.json").exists());
}
