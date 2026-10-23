//! Pin for the persistent-state capture (spawn site 7): with no `SandboxLaunch` installed,
//! `ShellState::init` captures exactly what the golden, `init` without the seam, captures: same
//! script, argv, cwd and env. Linux-only, like the other spawn-site pins.

use std::path::Path;
use std::process::Stdio;

use tokio::io::AsyncReadExt;

use super::{INIT_STATE_MARKER, ShellKind, ShellState, parse_after_marker, parse_dump};
use crate::util::{EnvironmentVariablePattern, ShellEnvironmentPolicy};

/// `ShellState::init` without the seam.
async fn main_shell_state_init(
    shell: ShellKind,
    cwd: &Path,
    shell_env_policy: Option<&ShellEnvironmentPolicy>,
) -> ShellState {
    let dump_script = shell.dump_script();
    let dump_fn = shell.dump_function_name();
    let script = format!("{dump_script} builtin printf '{INIT_STATE_MARKER}\\n'; {dump_fn}");
    let args: Vec<&str> = match shell {
        ShellKind::Bash => vec!["-O", "extglob", "-ilc", &script],
        ShellKind::Zsh => vec!["-o", "extendedglob", "-ilc", &script],
    };
    let mut cmd = tokio::process::Command::new(shell.binary_path());
    cmd.args(&args)
        .current_dir(cwd)
        .stdin(fuigo_tty_utils::null_stdio())
        .stdout(Stdio::piped())
        .stderr(fuigo_tty_utils::null_stdio())
        .kill_on_drop(true);
    crate::util::detach_command(&mut cmd);
    fuigo_sandbox::child_net::restrict_child_network(&mut cmd);
    crate::util::apply_shell_environment_policy(&mut cmd, shell_env_policy);
    cmd.envs(crate::util::pager_env());
    #[allow(clippy::disallowed_methods)] // the golden for the pin; waited on by the test
    let mut child = cmd.spawn().unwrap();
    let mut full_output = String::new();
    if let Some(stdout) = child.stdout.as_mut() {
        stdout.read_to_string(&mut full_output).await.unwrap();
    }
    let _ = child.wait().await;
    let snapshot_raw = parse_after_marker(&full_output, INIT_STATE_MARKER);
    match parse_dump(shell, snapshot_raw) {
        Some((parsed_cwd, rest)) => ShellState {
            cwd: parsed_cwd,
            snapshot: rest,
            shell,
        },
        None => ShellState {
            cwd: cwd.to_path_buf(),
            snapshot: String::new(),
            shell,
        },
    }
}

#[tokio::test]
async fn cli_facing_persistent_state_capture_unchanged_without_hook() {
    // The dump carries the process-global credential denylist; a sibling test registering a name
    // between the golden and the live capture would differ them. A fresh single-test process
    // sees no such registration.
    if crate::util::shell_env_policy::t05_fresh_process(
        "computer::local::shell_state::cli_facing_unchanged_tests::cli_facing_persistent_state_capture_unchanged_without_hook",
    ) {
        return;
    }
    if !Path::new("/bin/bash").exists() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let cwd = dunce::canonicalize(tmp.path()).unwrap();
    let shell = ShellKind::detect();
    let policy = ShellEnvironmentPolicy {
        exclude: vec![EnvironmentVariablePattern::new_case_insensitive(
            "FUIGO_PIN_SECRET*",
        )],
        ..Default::default()
    };
    for policy in [None, Some(&policy)] {
        let golden = main_shell_state_init(shell, &cwd, policy).await;
        let live = ShellState::init(shell, &cwd, policy, None, None)
            .await
            .unwrap();
        assert_eq!(golden.shell, live.shell);
        assert_eq!(golden.cwd, live.cwd, "state cwd");
        assert_eq!(golden.snapshot, live.snapshot, "state snapshot");
    }
}
