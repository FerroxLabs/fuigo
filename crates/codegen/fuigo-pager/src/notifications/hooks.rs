use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use crate::notifications::NotificationEvent;
use crate::notifications::config::NotificationHook;

fn execute_hook(
    command: &str,
    event_str: &str,
    message: &str,
    session_id: Option<&str>,
    timeout: Duration,
) {
    let mut cmd = Command::new("sh");
    fuigo_tty_utils::remove_fuigo_owned_secrets(&mut cmd);
    cmd.arg("-c")
        .arg(command)
        .env("FUIGO_EVENT", event_str)
        .env("FUIGO_MESSAGE", message)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(sid) = session_id {
        cmd.env("FUIGO_SESSION_ID", sid);
    }

    fuigo_tty_utils::detach_std_command(&mut cmd);
    fuigo_sandbox::child_net::restrict_child_network_std(&mut cmd);

    #[allow(clippy::disallowed_methods)] // Enrolled below, once the child exists
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            tracing::debug!(error = %e, command, "hook spawn failed");
            return;
        }
    };

    let group = match fuigo_tty_utils::global_process_scope().enroll_std(&child) {
        Ok(group) => group,
        Err(error) => {
            tracing::debug!(error = %error, command, "hook process group enrollment failed");
            let _ = child.kill();
            if !matches!(
                fuigo_tty_utils::wait_child_bounded(&mut child, fuigo_tty_utils::KILL_REAP_TIMEOUT,),
                Ok(Some(_))
            ) && let Err((error, child, _)) =
                fuigo_tty_utils::spawn_child_reaper("notification-hook-reaper", child, None)
            {
                tracing::error!(error = %error, command, child_id = child.id(), "hook cleanup bounded abandonment after enrollment failure");
            }
            return;
        }
    };

    match fuigo_tty_utils::wait_child_bounded(&mut child, timeout) {
        Ok(Some(_)) => drop(group),
        Ok(None) => {
            tracing::warn!(command, "hook timed out");
            kill_tree_and_reap(child, group, command);
        }
        Err(error) if fuigo_tty_utils::is_child_wait_identity_uncertain(&error) => {
            tracing::error!(error = %error, command, "hook wait lost child identity; numeric cleanup forbidden");
            // After ECHILD the child may already be reaped and its pid or group id reused, so killing by id now or later is unsafe
            drop(group);
            abandon_child(child, None, command);
        }
        Err(error) => {
            tracing::debug!(error = %error, command, "hook wait failed");
            kill_tree_and_reap(child, group, command);
        }
    }
}

fn kill_tree_and_reap(mut child: Child, group: Arc<fuigo_tty_utils::ProcessGroup>, command: &str) {
    if let Err(group_error) = group.kill()
        && let Err(child_error) = child.kill()
    {
        tracing::warn!(error = %group_error, fallback_error = %child_error, command, "hook group and direct-child kill failed");
    }
    match fuigo_tty_utils::wait_child_bounded(&mut child, fuigo_tty_utils::KILL_REAP_TIMEOUT) {
        Ok(Some(_)) => drop(group),
        Ok(None) => abandon_child(child, Some(group), command),
        Err(error) => {
            tracing::warn!(error = %error, command, "hook bounded reap failed");
            abandon_child(child, Some(group), command);
        }
    }
}

fn abandon_child(child: Child, group: Option<Arc<fuigo_tty_utils::ProcessGroup>>, command: &str) {
    if let Err((error, child, group)) =
        fuigo_tty_utils::spawn_child_reaper("notification-hook-reaper", child, group)
    {
        tracing::error!(error = %error, command, child_id = child.id(), has_group = group.is_some(), "hook cleanup bounded abandonment: reaper thread spawn failed");
    }
}

pub fn run_hook(hook: &NotificationHook, event: &NotificationEvent) {
    let command = hook.command.clone();
    let event_str: &'static str = event.kind.as_str();
    let message = event.body.clone();
    let session_id = event.session_id.clone();
    let timeout = Duration::from_secs(hook.timeout_secs.max(1));

    std::thread::spawn(move || {
        execute_hook(
            &command,
            event_str,
            &message,
            session_id.as_deref(),
            timeout,
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifications::config::NotificationEventKind;
    use std::time::Instant;

    fn test_event() -> NotificationEvent {
        NotificationEvent {
            kind: NotificationEventKind::TurnComplete,
            title: "Fuigo".into(),
            body: "test body payload".into(),
            session_id: Some("test-session-123".into()),
        }
    }

    #[test]
    fn sets_environment_variables() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("env.txt");
        let command = format!(
            "printf 'FUIGO_EVENT=%s\\nFUIGO_MESSAGE=%s\\nFUIGO_SESSION_ID=%s\\n' \
             \"$FUIGO_EVENT\" \"$FUIGO_MESSAGE\" \"$FUIGO_SESSION_ID\" > {}",
            out.display()
        );

        execute_hook(
            &command,
            "Turn complete",
            "hello world",
            Some("sess-42"),
            Duration::from_secs(5),
        );

        let content = std::fs::read_to_string(&out).unwrap();
        assert!(
            content.contains("FUIGO_EVENT=Turn complete"),
            "missing FUIGO_EVENT: {content}"
        );
        assert!(
            content.contains("FUIGO_MESSAGE=hello world"),
            "missing FUIGO_MESSAGE: {content}"
        );
        assert!(
            content.contains("FUIGO_SESSION_ID=sess-42"),
            "missing FUIGO_SESSION_ID: {content}"
        );
    }

    #[test]
    fn omits_session_id_when_none() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("env.txt");
        let command = format!("env > {}", out.display());

        execute_hook(
            &command,
            "Turn complete",
            "msg",
            None,
            Duration::from_secs(5),
        );

        let content = std::fs::read_to_string(&out).unwrap();
        assert!(
            !content.contains("FUIGO_SESSION_ID"),
            "FUIGO_SESSION_ID should not be set: {content}"
        );
    }

    #[test]
    fn kills_descendants_on_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("descendant-finished");
        let command = format!("(sleep 2; touch {}) & wait", marker.display());
        execute_hook(
            &command,
            "Turn complete",
            "msg",
            None,
            Duration::from_millis(100),
        );
        let deadline = Instant::now() + Duration::from_millis(2300);
        while Instant::now() < deadline {
            assert!(!marker.exists(), "timeout must kill hook descendants");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn handles_failed_shell_command_gracefully() {
        execute_hook(
            "/nonexistent/path/binary",
            "Turn complete",
            "msg",
            None,
            Duration::from_secs(1),
        );
    }

    #[test]
    fn handles_nonzero_exit_gracefully() {
        execute_hook(
            "exit 1",
            "Turn complete",
            "msg",
            None,
            Duration::from_secs(5),
        );
    }

    #[test]
    fn successful_command_completes_without_error() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("done");
        let command = format!("touch {}", marker.display());

        execute_hook(
            &command,
            "Turn complete",
            "msg",
            None,
            Duration::from_secs(5),
        );

        assert!(marker.exists());
    }

    #[test]
    fn run_hook_spawns_thread_without_panic() {
        let hook = NotificationHook {
            command: "true".into(),
            events: vec![],
            only_unfocused: false,
            timeout_secs: 5,
        };
        run_hook(&hook, &test_event());
        std::thread::sleep(Duration::from_millis(200));
    }

    #[test]
    fn timeout_clamped_to_minimum_one_second() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("done");
        let hook = NotificationHook {
            command: format!("sleep 100; touch {}", marker.display()),
            events: vec![],
            only_unfocused: false,
            timeout_secs: 0, // Exercises the .max(1) clamp inside run_hook
        };
        let start = Instant::now();
        run_hook(&hook, &test_event());
        // Wait for the spawned thread to finish (the clamp turns 0 into a 1s timeout)
        std::thread::sleep(Duration::from_millis(2500));
        let elapsed = start.elapsed();
        assert!(
            !marker.exists(),
            "hook should have been killed by timeout before creating marker"
        );
        // Sanity: the whole thing completed well under 10s, confirming the timeout was ~1s (clamped) not 0s (instant) or unbounded
        assert!(
            elapsed < Duration::from_secs(5),
            "should complete within a few seconds, took {elapsed:?}"
        );
    }

    /// Polls for the hook's COMPLETE output instead of a fixed sleep: the spawned thread and the fork/exec take variable time on
    /// loaded systems. The file exists as soon as the shell's redirect creates it, before the payload writes, so "file exists" is
    /// not "hook done": wait until `complete` accepts the content. 30 s is a hang guard only.
    fn wait_for_complete_output(
        out: &std::path::Path,
        complete: impl Fn(&str) -> bool,
    ) -> String {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(c) = std::fs::read_to_string(out)
                && complete(&c)
            {
                return c;
            }
            assert!(
                Instant::now() < deadline,
                "hook did not produce its complete output within 30s (sh or printf may not be available)"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Single-quotes a path for `sh`, escaping embedded apostrophes.
    fn sh_quote(path: &std::path::Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
    }

    /// On drop (including a panic) releases the payload and then waits, bounded, until the payload has printed its last line,
    /// so the shell is past its polling loop before the caller's directory is removed.
    struct ReleaseOnDrop {
        release: std::path::PathBuf,
        out: std::path::PathBuf,
    }
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::write(&self.release, "");
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if std::fs::read_to_string(&self.out).is_ok_and(|c| c.ends_with('\n')) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    /// The shell creates and truncates its redirect target before the payload writes, so the wait helper can be offered an
    /// opened-but-unwritten (empty) file. The payload here is held back until the helper has been shown that empty file, so the
    /// order is forced rather than timed: a helper that returned on mere file existence returns the empty content (or never
    /// consults `complete` at all) and fails, whatever the host load.
    #[test]
    fn wait_for_complete_output_does_not_return_an_opened_but_unwritten_file() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("slow.txt");
        let release = dir.path().join("release");
        let hook = NotificationHook {
            command: format!(
                "{{ while [ ! -e {release} ]; do sleep 0.01; done; printf 'done\\n'; }} > {out}",
                release = sh_quote(&release),
                out = sh_quote(&out)
            ),
            events: vec![],
            only_unfocused: false,
            timeout_secs: 60,
        };
        run_hook(&hook, &test_event());
        // However this test exits (including a panic), release the payload and wait for it to finish before the directory goes
        // away, so the shell cannot be left polling a release file that no longer exists. Declared after `dir`, so it drops first.
        let _release_on_exit = ReleaseOnDrop {
            release: release.clone(),
            out: out.clone(),
        };

        let saw_unwritten_file = Arc::new(AtomicBool::new(false));
        let waiter = {
            let (out, seen) = (out.clone(), Arc::clone(&saw_unwritten_file));
            std::thread::spawn(move || {
                wait_for_complete_output(&out, |c| {
                    if c.is_empty() {
                        seen.store(true, Ordering::SeqCst);
                    }
                    c.ends_with('\n')
                })
            })
        };

        // Release the payload only after the helper has been offered the empty file; if the helper returns first it never saw it.
        let deadline = Instant::now() + Duration::from_secs(30);
        while !saw_unwritten_file.load(Ordering::SeqCst) {
            assert!(
                !waiter.is_finished(),
                "the wait helper returned without ever being offered the opened-but-unwritten file"
            );
            assert!(
                Instant::now() < deadline,
                "the hook never opened its output file within 30s"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        std::fs::write(&release, "").unwrap();
        assert_eq!(waiter.join().expect("waiter thread"), "done\n");
    }

    #[test]
    fn run_hook_passes_correct_env_via_thread() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("env.txt");
        let hook = NotificationHook {
            command: format!(
                "printf 'FUIGO_EVENT=%s\\nFUIGO_MESSAGE=%s\\nFUIGO_SESSION_ID=%s\\n' \
                 \"$FUIGO_EVENT\" \"$FUIGO_MESSAGE\" \"$FUIGO_SESSION_ID\" > {}",
                out.display()
            ),
            events: vec![],
            only_unfocused: false,
            timeout_secs: 5,
        };
        let event = test_event();
        run_hook(&hook, &event);

        let content = wait_for_complete_output(&out, |c| {
            c.contains("FUIGO_SESSION_ID=") && c.ends_with('\n')
        });
        assert!(content.contains("FUIGO_EVENT=Turn complete"));
        assert!(content.contains("FUIGO_MESSAGE=test body payload"));
        assert!(content.contains("FUIGO_SESSION_ID=test-session-123"));
    }
}

/// P120: a notification hook is a user-configured command; it must not inherit Fuigo's own secrets.
#[cfg(all(test, unix))]
mod p120_tests {
    use super::*;
    use fuigo_secrets::test_probe as probe;

    #[test]
    fn p120_notification_hooks_do_not_inherit_fuigo_secrets() {
        const NAME: &str = "notifications::hooks::p120_tests::p120_notification_hooks_do_not_inherit_fuigo_secrets";
        const REGISTERED: &str = "P120_HOOK_BEARER";
        if probe::in_parent(NAME, &[REGISTERED]) {
            return;
        }
        fuigo_tools::util::shell_env_policy::register_credential_env_names([REGISTERED]);
        let dir = probe::scratch_dir("p120-hook");
        let out = dir.join("env.txt");
        execute_hook(&format!("env > '{}'", out.display()), "p120", "message", Some("sid"), Duration::from_secs(20));
        let dump = std::fs::read_to_string(&out).expect("the hook ran");
        probe::assert_clean(&dump, &[]);
        probe::assert_kept(&dump, REGISTERED);
        assert!(dump.lines().any(|l| l == "FUIGO_EVENT=p120"), "control: the hook's own variables arrive");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
