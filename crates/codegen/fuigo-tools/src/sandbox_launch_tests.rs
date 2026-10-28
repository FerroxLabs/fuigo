use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use super::{
    CallId, CallKind, LaunchReceipt, OriginalArgv, SandboxLaunch, SandboxLaunchError,
    SandboxLaunchHook, child_env, original_argv, prepare, prepare_restoring, wire_prepared,
};
use crate::computer::types::ComputerError;

/// Replaces the command with a wrapper the way a backend does: a new `Command` carrying only
/// program/args/cwd/envs of the original.
struct WrappingHook {
    seen: Mutex<Vec<(OriginalArgv, CallId)>>,
}

impl SandboxLaunch for WrappingHook {
    fn prepare(
        &self,
        cmd: &mut tokio::process::Command,
        original: &OriginalArgv,
        call: &CallId,
    ) -> Result<Option<LaunchReceipt>, SandboxLaunchError> {
        self.seen
            .lock()
            .unwrap()
            .push((original.clone(), call.clone()));
        let envs: Vec<(OsString, Option<OsString>)> = cmd
            .as_std()
            .get_envs()
            .map(|(k, v)| (k.to_os_string(), v.map(|v| v.to_os_string())))
            .collect();
        let mut wrapped = tokio::process::Command::new("/usr/bin/wrapper");
        wrapped
            .arg("--tag")
            .arg(format!("fuigo-{call}"))
            .arg("--")
            .arg(&original.program)
            .args(&original.args)
            .current_dir(&original.cwd);
        for (key, value) in envs {
            match value {
                Some(value) => wrapped.env(key, value),
                None => wrapped.env_remove(key),
            };
        }
        *cmd = wrapped;
        Ok(Some(LaunchReceipt {
            sandboxed: true,
            backend: Some(super::BackendName::Seatbelt),
        }))
    }
}

struct RefusingHook;

#[derive(Debug, thiserror::Error)]
#[error("no per-command sandbox backend on this host")]
struct NoBackend;

impl SandboxLaunch for RefusingHook {
    fn prepare(
        &self,
        _cmd: &mut tokio::process::Command,
        _original: &OriginalArgv,
        _call: &CallId,
    ) -> Result<Option<LaunchReceipt>, SandboxLaunchError> {
        Err(SandboxLaunchError::new(NoBackend))
    }
}

fn argv(cmd: &tokio::process::Command) -> Vec<String> {
    let std_cmd = cmd.as_std();
    std::iter::once(std_cmd.get_program())
        .chain(std_cmd.get_args())
        .map(|s| s.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn no_hook_leaves_the_command_untouched() {
    let mut cmd = tokio::process::Command::new("/bin/bash");
    cmd.args(["-c", "echo hi"]).current_dir("/tmp");
    let receipt = prepare(None, &mut cmd, &CallId::tool("tc-1")).unwrap();
    assert_eq!(None, receipt);
    assert_eq!(vec!["/bin/bash", "-c", "echo hi"], argv(&cmd));
}

#[test]
fn hook_sees_the_pre_wrap_argv_and_the_call_id() {
    let hook = WrappingHook {
        seen: Mutex::new(Vec::new()),
    };
    let mut cmd = tokio::process::Command::new("/bin/bash");
    cmd.args(["-c", "echo hi"]).current_dir("/tmp");
    let receipt = prepare(Some(&hook), &mut cmd, &CallId::tool("tc-7"))
        .unwrap()
        .unwrap();
    assert!(receipt.sandboxed);
    let seen = hook.seen.lock().unwrap();
    let [(original, call)] = seen.as_slice() else {
        panic!("one prepare call, got {seen:?}");
    };
    assert_eq!(&CallId::tool("tc-7"), call);
    assert_eq!(Path::new("/bin/bash"), original.program);
    assert_eq!(
        vec![OsString::from("-c"), OsString::from("echo hi")],
        original.args
    );
    assert_eq!(Path::new("/tmp"), original.cwd);
}

/// Pins the spawn-site order: what `wire_prepared` sets *after* `prepare` lands on the wrapper and
/// the wrapper's argv is intact.
#[test]
fn stdio_set_after_prepare_keeps_the_wrapper_argv_intact() {
    let hook = WrappingHook {
        seen: Mutex::new(Vec::new()),
    };
    let mut cmd = tokio::process::Command::new("/bin/bash");
    cmd.args(["-c", "echo hi"])
        .current_dir("/tmp")
        .env("HTTP_PROXY", "http://127.0.0.1:3128")
        .env_remove("AWS_SECRET_ACCESS_KEY");
    prepare(Some(&hook), &mut cmd, &CallId::tool("tc-9")).unwrap();
    wire_prepared(&mut cmd, Stdio::piped());
    assert_eq!(
        vec![
            "/usr/bin/wrapper",
            "--tag",
            "fuigo-tc-9",
            "--",
            "/bin/bash",
            "-c",
            "echo hi"
        ],
        argv(&cmd)
    );
    assert_eq!(Some(Path::new("/tmp")), cmd.as_std().get_current_dir());
    let envs: Vec<(String, Option<String>)> = cmd
        .as_std()
        .get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect();
    assert!(envs.contains(&(
        "HTTP_PROXY".to_owned(),
        Some("http://127.0.0.1:3128".to_owned())
    )));
    assert!(envs.contains(&("AWS_SECRET_ACCESS_KEY".to_owned(), None)));
}

#[test]
fn a_refusing_hook_stops_the_spawn_with_its_reason() {
    let mut cmd = tokio::process::Command::new("/bin/bash");
    cmd.args(["-c", "echo hi"]);
    let err = prepare(Some(&RefusingHook), &mut cmd, &CallId::tool("tc-2")).unwrap_err();
    assert!(err.to_string().contains("no per-command sandbox backend"));
    assert!(
        err.downcast_ref::<NoBackend>().is_some(),
        "the daemon's error is reachable"
    );
    assert_eq!(vec!["/bin/bash", "-c", "echo hi"], argv(&cmd));
}

/// A refusal is one error at every spawn site: permission denied, naming the sandbox and the
/// daemon's reason, whether the site returns an `io::Error` or a `ComputerError`.
#[test]
fn a_refusal_is_one_permission_denied_error_at_every_site() {
    let text = "sandbox refused to run the command: no per-command sandbox backend on this host";
    let io = std::io::Error::from(SandboxLaunchError::new(NoBackend));
    assert_eq!(std::io::ErrorKind::PermissionDenied, io.kind());
    assert_eq!(text, io.to_string());
    let computer = ComputerError::from(SandboxLaunchError::new(NoBackend));
    assert_eq!(
        Some(std::io::ErrorKind::PermissionDenied),
        computer.io_error_kind()
    );
    assert!(computer.to_string().contains(text), "{computer}");
}

/// `wire_prepared` leaves the child a closed stdin and a session of its own, so it cannot reach
/// the terminal fuigo runs in, and the child dies with its handle.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn wire_prepared_detaches_the_child_and_closes_its_stdin() {
    const PROBE: &str = "read -r line; r=$?; read -r _ _ _ _ _ sid _ < /proc/$$/stat; \
                         echo \"$r $$ $sid\"";
    let mut cmd = tokio::process::Command::new("/bin/sh");
    cmd.args(["-c", PROBE]);
    wire_prepared(&mut cmd, Stdio::null());
    assert!(cmd.get_kill_on_drop());
    let output = cmd.output().await.unwrap();
    assert!(output.status.success(), "{output:?}");
    let out = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = out.split_whitespace().collect();
    let [read_status, pid, sid] = fields.as_slice() else {
        panic!("probe output {out:?}");
    };
    assert_ne!(
        "0", *read_status,
        "stdin is closed: the read hits end of file"
    );
    assert_eq!(pid, sid, "the child leads a session of its own");
}

#[test]
fn the_hook_wrapper_hands_out_the_same_implementation_twice() {
    let hook = SandboxLaunchHook::new(Arc::new(RefusingHook));
    let mut cmd = tokio::process::Command::new("/bin/true");
    assert!(prepare(Some(hook.as_launch()), &mut cmd, &CallId::tool("tc-3")).is_err());
    let original = original_argv(&cmd);
    assert!(
        hook.shared()
            .prepare(&mut cmd, &original, &CallId::tool("tc-4"))
            .is_err()
    );
    assert_eq!("SandboxLaunchHook(..)", format!("{hook:?}"));
}

/// What the command runs under is the daemon's environment with `cmd`'s sets and removals
/// applied, then what a replaying shell exports: an inherited variable `cmd` never names is part
/// of it, a removed one is not, and a restored value wins over `cmd`'s.
#[test]
fn the_child_environment_is_the_inherited_one_with_the_commands_entries_and_the_restored() {
    let inherited: Vec<(OsString, OsString)> = std::env::vars_os().take(2).collect();
    let [(kept, kept_value), (removed, _)] = inherited.as_slice() else {
        panic!("the test process inherits at least two variables: {inherited:?}");
    };
    let mut cmd = tokio::process::Command::new("/bin/true");
    cmd.env("FUIGO_CHILD_ENV_SET", "set")
        .env("FUIGO_CHILD_ENV_RESTORED", "set")
        .env_remove(removed);
    let restored = [(
        OsString::from("FUIGO_CHILD_ENV_RESTORED"),
        OsString::from("restored"),
    )];
    let env: BTreeMap<OsString, OsString> = child_env(&cmd, restored).into_iter().collect();
    assert_eq!(Some(kept_value), env.get(kept), "{kept:?} is inherited");
    assert_eq!(None, env.get(removed), "{removed:?} was removed");
    assert_eq!(
        Some(&OsString::from("set")),
        env.get(&OsString::from("FUIGO_CHILD_ENV_SET"))
    );
    assert_eq!(
        Some(&OsString::from("restored")),
        env.get(&OsString::from("FUIGO_CHILD_ENV_RESTORED"))
    );
}

/// Records what `prepare_restoring` hands the hook.
struct RestoringHook {
    restored: Mutex<Vec<Vec<(OsString, OsString)>>>,
}

impl SandboxLaunch for RestoringHook {
    fn prepare(
        &self,
        _cmd: &mut tokio::process::Command,
        _original: &OriginalArgv,
        _call: &CallId,
    ) -> Result<Option<LaunchReceipt>, SandboxLaunchError> {
        Err(SandboxLaunchError::new(NoBackend))
    }

    fn prepare_restoring(
        &self,
        _cmd: &mut tokio::process::Command,
        _original: &OriginalArgv,
        restored: &[(OsString, OsString)],
        _call: &CallId,
    ) -> Result<Option<LaunchReceipt>, SandboxLaunchError> {
        self.restored.lock().unwrap().push(restored.to_vec());
        Ok(None)
    }
}

/// A replaying shell's variables reach the hook through `prepare_restoring`, read only when a
/// hook is injected; a hook that reads no environment keeps `prepare`'s behavior.
#[test]
fn a_replaying_shell_hands_the_hook_what_it_exports() {
    let pyuser = (
        OsString::from("PYTHONUSERBASE"),
        OsString::from("/opt/pyuser"),
    );
    let hook = RestoringHook {
        restored: Mutex::new(Vec::new()),
    };
    let mut cmd = tokio::process::Command::new("/bin/true");
    prepare_restoring(
        Some(&hook),
        &mut cmd,
        || vec![pyuser.clone()],
        &CallId::tool("tc-10"),
    )
    .unwrap();
    assert_eq!(vec![vec![pyuser]], *hook.restored.lock().unwrap());
    // u35 g8: a tool call's exports are also read to judge its environment once a judge is
    // installed (another test may have installed one), so the unread case is a shell-init spawn
    let unread = || -> Vec<(OsString, OsString)> { panic!("no hook, nothing to read") };
    assert_eq!(
        None,
        prepare_restoring(None, &mut cmd, unread, &CallId::shell_init("tc-11")).unwrap()
    );
    let wrapping = WrappingHook {
        seen: Mutex::new(Vec::new()),
    };
    let receipt = prepare_restoring(Some(&wrapping), &mut cmd, Vec::new, &CallId::tool("tc-12"))
        .unwrap()
        .unwrap();
    assert!(receipt.sandboxed);
    assert_eq!(
        Some("/usr/bin/wrapper"),
        argv(&cmd).first().map(String::as_str)
    );
}

#[test]
fn original_argv_falls_back_to_the_process_cwd() {
    let cmd = tokio::process::Command::new("/bin/true");
    let original = original_argv(&cmd);
    assert_eq!(PathBuf::from("/bin/true"), original.program);
    assert!(original.args.is_empty());
    assert_eq!(std::env::current_dir().unwrap(), original.cwd);
}

/// The kind is a field, the spelling on the wire is the one `CommandTag` embeds, and it
/// parses back.
#[test]
fn call_ids_carry_their_kind_and_round_trip_through_the_wire_spelling() {
    let tool = CallId::tool("tc-5");
    let init = CallId::shell_init("login-env");
    assert_eq!((CallKind::Tool, "tc-5"), (tool.kind(), tool.as_str()));
    assert_eq!(
        (CallKind::ShellInit, "login-env"),
        (init.kind(), init.as_str())
    );
    assert_eq!("tc-5", tool.to_string());
    assert_eq!("shell-init:login-env", init.to_string());
    assert_eq!(tool, CallId::parse(&tool.to_string()));
    assert_eq!(init, CallId::parse(&init.to_string()));
}

/// A command the hook wrapped, captured and rebuilt on a fresh `Command`, is the wrapper: same
/// program, argv, directory and environment edits. This is how the session-cgroup placed sites
/// keep the placement `pre_exec` the hook's `*cmd = wrapped` would otherwise drop.
#[test]
fn captured_parts_rebuild_the_wrapped_command_on_a_fresh_command() {
    let hook = WrappingHook {
        seen: Mutex::new(Vec::new()),
    };
    let mut cmd = tokio::process::Command::new("/bin/echo");
    cmd.arg("hi")
        .current_dir("/tmp")
        .env("KEPT", "1")
        .env_remove("DROPPED");
    prepare(Some(&hook), &mut cmd, &CallId::tool("tc-parts")).unwrap();

    let parts = super::CommandParts::capture(&cmd);
    let mut rebuilt = parts.new_command();
    assert!(
        rebuilt.as_std().get_args().next().is_none()
            && rebuilt.as_std().get_envs().next().is_none(),
        "new_command is bare"
    );
    parts.apply(&mut rebuilt);

    assert_eq!(argv(&cmd), argv(&rebuilt));
    assert_eq!(
        cmd.as_std().get_current_dir(),
        rebuilt.as_std().get_current_dir()
    );
    let envs = |c: &tokio::process::Command| -> Vec<(OsString, Option<OsString>)> {
        c.as_std()
            .get_envs()
            .map(|(k, v)| (k.to_os_string(), v.map(|v| v.to_os_string())))
            .collect()
    };
    assert_eq!(envs(&cmd), envs(&rebuilt));
    assert!(envs(&rebuilt).contains(&(OsString::from("DROPPED"), None)));
    assert!(envs(&rebuilt).contains(&(OsString::from("KEPT"), Some(OsString::from("1")))));
    // Idempotent: a placed attempt that falls back to an unplaced one rebuilds from the same parts
    let mut again = parts.new_command();
    parts.apply(&mut again);
    assert_eq!(argv(&rebuilt), argv(&again));
}

/// u35-winenv: on Windows the environment the sandbox reads has ONE entry per variable: an edit of
/// `Path` replaces an inherited `PATH` (no stale copy beside it), a removal drops every spelling,
/// and a restored entry replaces too. Unix keeps the spellings as distinct variables.
#[test]
fn child_env_for_windows_has_one_entry_per_variable() {
    use crate::util::shell_env_policy::EnvPlatform;
    let os = |s: &str| OsString::from(s);
    let inherited = vec![
        (os("PATH"), os("C:\\stale")),
        (os("Path"), os("C:\\stale2")),
        (os("PYTHONUSERBASE"), os("C:\\old-base")),
        (os("Drop_Me"), os("x")),
    ];
    let edits = vec![
        (os("Path"), Some(os("C:\\edited"))),
        (os("DROP_ME"), None),
    ];
    let restored = vec![(os("PythonUserBase"), os("C:\\restored-base"))];
    let env = super::child_env_for(inherited.clone(), edits.clone(), restored.clone(), EnvPlatform::Windows);
    assert_eq!(
        env,
        vec![(os("PATH"), os("C:\\edited")), (os("PYTHONUSERBASE"), os("C:\\restored-base"))]
    );
    let env = super::child_env_for(inherited, edits, restored, EnvPlatform::Unix);
    let names: Vec<&OsString> = env.iter().map(|(k, _)| k).collect();
    assert_eq!(
        names,
        vec![&os("Drop_Me"), &os("PATH"), &os("PYTHONUSERBASE"), &os("Path"), &os("PythonUserBase")]
    );
}

/// u35 g9: a judge for the runner tests: `U35_STEER_A` / `U35_STEER_B` steer, nothing else does.
fn u35_test_judge(_command: &str, env: &[(String, String)], _dir: &Path) -> Option<String> {
    env.iter()
        .find(|(name, value)| matches!(name.as_str(), "U35_STEER_A" | "U35_STEER_B") && !value.is_empty())
        .map(|(name, _)| name.clone())
}

fn u35_env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs.iter().map(|(k, v)| (OsString::from(k), OsString::from(v))).collect()
}

/// u35 g9 (Astra r8 High 2): a child `PATH` that is empty or missing makes the shell search its
/// built-in default (bash's includes the current directory), so it steers like a dirty one.
#[test]
fn u35_g9_empty_or_missing_child_path_is_judged() {
    let dir = Path::new("/");
    let empty = u35_env(&[("PATH", ""), ("HOME", "/home/u")]);
    assert_eq!(super::judge_child_env(&empty, "ls", dir, u35_test_judge).as_deref(), Some("PATH"));
    let missing = u35_env(&[("HOME", "/home/u")]);
    assert_eq!(super::judge_child_env(&missing, "ls", dir, u35_test_judge).as_deref(), Some("PATH"));
    let clean = u35_env(&[("PATH", "/usr/bin:/bin"), ("HOME", "/home/u")]);
    assert_eq!(super::judge_child_env(&clean, "ls", dir, u35_test_judge), None);
}

/// u35 g9 (Astra/Grok r8 High 1): nothing is remembered between calls. Every call approved without
/// a grant is judged on its own environment, so a batch sibling under the same steering value is
/// refused like the first call, however many times it comes.
#[test]
fn u35_g9_every_no_grant_call_is_judged_on_its_own_environment() {
    let dir = Path::new("/");
    let steering = u35_env(&[("PATH", "/usr/bin"), ("U35_STEER_A", "1")]);
    for sibling in 0..3 {
        assert_eq!(
            super::judge_child_env(&steering, "ls", dir, u35_test_judge).as_deref(),
            Some("U35_STEER_A"),
            "call {sibling}"
        );
    }
    let other = u35_env(&[("PATH", "/usr/bin"), ("U35_STEER_B", "2")]);
    assert_eq!(super::judge_child_env(&other, "ls", dir, u35_test_judge).as_deref(), Some("U35_STEER_B"));
    // A call approved by a grant, an answer or an override is never refused by the check.
    let cmd = tokio::process::Command::new("true");
    assert!(super::check_child_env(&cmd, &steering, "ls", false, None).is_ok());
    // A call that carries no flag is judged.
    assert!(super::ApprovedWithoutGrant::of(None));
    assert!(!super::ApprovedWithoutGrant::of(Some(&super::ApprovedWithoutGrant(false))));
}

/// u35 g8 (release gate, `an_acp_error_in_the_body_still_answers_the_exit_plan_tail`): the
/// runner refused a plain tool call because Fuigo's own `GH_PAGER=cat` looked like the user's
/// steering variable. Fuigo's constants are never judged; another value of the same name is.
#[test]
fn u35_fuigo_own_pager_env_is_not_the_users() {
    for (name, value) in crate::util::pager_env() {
        assert!(super::is_fuigo_own_env(&name, &value), "{name}={value}");
    }
    assert!(!super::is_fuigo_own_env("GH_PAGER", "sh ./pager"));
    assert!(!super::is_fuigo_own_env("GIT_ASKPASS", ""));
    let steer_any = |_: &str, env: &[(String, String)], _: &Path| {
        env.iter().find(|(name, _)| name != "PATH").map(|(name, _)| name.clone())
    };
    let mut env: Vec<(OsString, OsString)> =
        crate::util::pager_env().into_iter().map(|(k, v)| (OsString::from(k), OsString::from(v))).collect();
    env.push((OsString::from("PATH"), OsString::from("/usr/bin")));
    assert_eq!(super::judge_child_env(&env, "git log -1", Path::new("/"), steer_any), None);
    env.push((OsString::from("GH_PAGER"), OsString::from("sh ./pager")));
    assert_eq!(super::judge_child_env(&env, "gh pr list", Path::new("/"), steer_any).as_deref(), Some("GH_PAGER"));
}

/// u35 g10 (Fable r9 Low): the refusal names only remedies that exist when it happens. Nothing
/// prompts here, and a remembered "always allow" is written only by a prompt answer.
#[test]
fn u35_g10_refusal_names_only_reachable_remedies() {
    let text = super::ChildEnvSteers { name: "GIT_ASKPASS".to_owned() }.to_string();
    assert!(
        text.contains("--allow 'Bash(") && text.contains("allow all commands") && text.contains("always-approve"),
        "{text}"
    );
    assert!(!text.contains("\"always allow\" for the command"), "{text}");
}

/// u35 g11 (owner decision; Astra r10 High 2): the shell runner refuses a call approved without a
/// grant when its shell is PowerShell or cmd.exe, which read commands differently from the bash
/// syntax the permission check judged; Git Bash and Unix shells are judged as before.
#[test]
fn u35_g11_runner_refuses_no_grant_calls_under_powershell_and_cmd() {
    use fuigo_config::shell::WindowsShellFamily as F;
    for shell in [F::Pwsh, F::PowerShell, F::Cmd] {
        let text = super::check_runner_shell(Some(shell)).expect_err("refused").to_string();
        assert!(text.contains(shell.name()) && text.contains("FUIGO_SHELL=bash"), "{text}");
        assert!(text.contains("--allow 'Bash(") && text.contains("allow all commands"), "{text}");
    }
    assert!(super::check_runner_shell(Some(F::GitBash)).is_ok());
    assert!(super::check_runner_shell(None).is_ok());
}

/// u35 g11 (Fable/Grok r10 Low): with no environment rule installed, a call approved without a
/// grant is refused outside this crate's tests.
#[test]
fn u35_g11_no_installed_judge_refuses_a_no_grant_call() {
    let text = super::missing_env_judge(true).expect_err("refused").to_string();
    assert!(text.contains("approval"), "{text}");
    assert!(super::missing_env_judge(false).is_ok());
}

/// u35 g12 (Fable r11 Low): the runner half of the Windows shell decision, through the real hop:
/// `check_child_env` asks the runner's shell family (set per thread here, so every host runs it)
/// and refuses a call approved without a grant under PowerShell or cmd.exe; a call a grant, an
/// answer or an override approved runs; Git Bash and Unix shells reach the environment check.
#[test]
fn u35_g12_check_child_env_refuses_no_grant_calls_under_powershell_and_cmd() {
    use fuigo_config::shell::WindowsShellFamily as F;
    let cmd = tokio::process::Command::new("/bin/echo");
    for shell in [F::Pwsh, F::PowerShell, F::Cmd] {
        let _shell = super::TestRunnerShell::set(Some(shell));
        let text = super::check_child_env(&cmd, &[], "ls -la", true, None).expect_err("refused").to_string();
        assert!(text.contains(shell.name()) && text.contains("FUIGO_SHELL=bash"), "{text}");
        assert!(super::check_child_env(&cmd, &[], "ls -la", false, None).is_ok(), "{shell:?}: a grant runs");
    }
    // u35 g13 (Fable r12 Low): with this crate's judge installed, Git Bash and Unix shells reach the
    // environment check and the call runs.
    super::install_env_judge(super::u35_test_child_judge);
    for shell in [Some(F::GitBash), None] {
        let _shell = super::TestRunnerShell::set(shell);
        super::check_child_env(&cmd, &[], "ls -la", true, None)
            .unwrap_or_else(|e| panic!("{shell:?}: reaches the environment check and runs: {e}"));
    }
}

/// u35 t1 T3: the shell runner refuses a command approved without a grant that runs in, or was judged in, a folder
/// that is not trusted; a grant runs it; with no rule installed the call is refused (strict, as outside tests).
#[test]
fn u35_t1_runner_refuses_an_ungranted_command_outside_a_trusted_folder() {
    super::install_trust_judge(super::u35_test_trust_judge);
    let trusted = tempfile::tempdir().unwrap();
    let mut cmd = tokio::process::Command::new("/bin/sh");
    cmd.current_dir(trusted.path());
    let text = super::check_child_env(&cmd, &[], "ls u35-t1-untrusted", true, None).expect_err("refused").to_string();
    assert!(text.contains("not trusted"), "{text}");
    assert!(super::check_child_env(&cmd, &[], "ls u35-t1-untrusted", false, None).is_ok(), "a grant runs");
    assert!(super::check_child_env(&cmd, &[], "ls", true, None).is_ok(), "a trusted folder runs");
    let judged = std::path::Path::new("/w/u35-t1-untrusted");
    assert!(
        super::check_child_env(&cmd, &[], "ls", true, Some(judged)).is_err(),
        "the directory the permission check judged it in counts too"
    );
    let untrusted_dir = trusted.path().join("u35-t1-untrusted");
    std::fs::create_dir_all(&untrusted_dir).unwrap();
    let mut there = tokio::process::Command::new("/bin/sh");
    there.current_dir(&untrusted_dir);
    assert!(super::check_child_env(&there, &[], "ls", true, None).is_err(), "where it runs counts");
    let no_rule = super::check_runner_trust_with(None, "ls", trusted.path(), None, true).expect_err("strict");
    assert!(no_rule.to_string().contains("no rule to check the folder"), "{no_rule}");
    assert!(super::check_runner_trust_with(None, "ls", trusted.path(), None, false).is_ok());
}
