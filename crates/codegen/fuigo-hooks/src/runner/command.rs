#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fuigo_tools::util::ProcessGroup;
use tokio::io::AsyncWriteExt;

use crate::config::{HookSpec, RUNNER_ALWAYS_SET_ENV};
use crate::event::{
    HookEventEnvelope, MAX_HOOK_FEEDBACK_CHARS, MAX_HOOK_OUTPUT_REPLACEMENT_CHARS, clip_reason,
    clip_text,
};
use crate::result::StopHookOutcome;

use super::{
    GateHookJson, GateKind, GateOutcome, HookHealth, HookRunnerResult, PostToolUseHookJson,
    PostToolUseParse, PromptHookJson, RunContext, StopHookJson, extract_system_message,
    gate_outcome, post_tool_use_json_to_outcome, prompt_json_to_block, stop_json_to_outcome,
};

const CAPTURE_HEADROOM_OVER_REPLACEMENT: usize = 16;
pub(crate) const MAX_OUTPUT_BYTES: usize =
    CAPTURE_HEADROOM_OVER_REPLACEMENT * MAX_HOOK_OUTPUT_REPLACEMENT_CHARS;

const GATE_EXIT_CODE: i32 = 2;

/// Killpg's a hook's process group unless the hook ran to completion.
///
/// Drop — not a return path — is what makes this cover *cancellation*: when the session-end path
/// cancels a deferred `SessionStart` hook it drops the hook's future mid-run, and tokio's
/// `kill_on_drop` SIGKILLs only the direct child, so a hook that backgrounded a grandchild would
/// otherwise leak it past the end of the session. Registration in the session's `ProcessScope`
/// cannot cover it either: the scope holds only a `Weak`, so dropping this owner makes the
/// enrollment dead and `kill_all` skips it.
struct HookProcessGuard {
    group: Option<Arc<ProcessGroup>>,
}

impl HookProcessGuard {
    fn arm(group: Option<Arc<ProcessGroup>>) -> Self {
        Self { group }
    }

    /// The hook exited on its own; leave whatever it deliberately backgrounded alone.
    fn disarm(&mut self) {
        self.group = None;
    }
}

impl Drop for HookProcessGuard {
    fn drop(&mut self) {
        if let Some(group) = self.group.take() {
            let _ = group.kill();
        }
    }
}

// SECURITY: a process group lets session close killpg the whole tree; kill_on_drop would leak detached grandchildren.
fn hook_process_group(child: &tokio::process::Child) -> Option<Arc<ProcessGroup>> {
    let mut group = ProcessGroup::new()
        .inspect_err(
            |e| tracing::warn!(pid = child.id(), error = %e, "hook: no process group; not reaped on session close"),
        )
        .ok()?;
    group
        .attach(child)
        .inspect_err(
            |e| tracing::warn!(pid = child.id(), error = %e, "hook: process group attach failed; not reaped on session close"),
        )
        .ok()?;
    Some(Arc::new(group))
}

pub async fn run_command_hook(
    spec: &HookSpec,
    envelope: &HookEventEnvelope,
    ctx: &RunContext<'_>,
    mode: GateKind,
) -> (HookRunnerResult, Duration, Option<String>) {
    let start = Instant::now();

    let Some(ref command) = spec.command else {
        return (
            HookRunnerResult::Failed("command hook has no 'command' field".into()),
            start.elapsed(),
            None,
        );
    };
    let command_str = command.to_string_lossy();

    let stdin_json = match serde_json::to_string(&envelope.to_hook_json()) {
        Ok(j) => j,
        Err(e) => {
            let elapsed = start.elapsed();
            return (
                HookRunnerResult::Failed(format!("failed to serialize envelope: {e}")),
                elapsed,
                None,
            );
        }
    };

    let debug_payloads = std::env::var("FUIGO_HOOK_DEBUG").is_ok_and(|v| v == "1");
    if debug_payloads {
        tracing::trace!(
            hook_name = %spec.name,
            stdin_bytes = stdin_json.len(),
            "hook stdin payload"
        );
    }

    // P70a: this hook's own child env, with the first-party key added only when its config names it explicitly.
    // Detection reads the command as parsed: aliases from its `env` map are substituted there (`$TOKEN` with
    // `TOKEN = "${FUIGO_API_KEY}"`), and an escaped `$${FUIGO_API_KEY}` is kept as written (Astra f5).
    let child_env = crate::env_expand::hook_child_env(
        Some(&command_str),
        &spec.extra_env,
        !matches!(
            crate::config::hook_origin(spec),
            crate::config::HookOrigin::ProjectFile | crate::config::HookOrigin::Plugin | crate::config::HookOrigin::Agent
        ),
    );

    // The base command as (program, args, fixed env), so it can be rebuilt for the
    // unplaced retry after a failed session-cgroup placement (P189).
    // A command that cannot be run at all is a CONFIG failure (see `crate::health`): it is reported once per session.
    let event_name = envelope.hook_event_name.to_string();
    let inputs = PlanInputs {
        workspace_root: ctx.workspace_root,
        session_id: ctx.session_id,
        event: &event_name,
    };
    let plan = match plan_command(spec, &command_str, &child_env, &inputs) {
        Ok(plan) => plan,
        Err(detail) => {
            return (
                HookRunnerResult::Failed(crate::health::config_failure(&detail)),
                start.elapsed(),
                None,
            );
        }
    };
    let CommandPlan {
        program,
        args: base_args,
        env: base_env,
        shell: is_shell_command,
        named_posix_shell,
    } = plan;
    #[cfg(unix)]
    let _ = (is_shell_command, named_posix_shell);

    #[cfg(not(unix))]
    let env_root = {
        use fuigo_config::shell::{WindowsShell, detect_windows_shell};
        if named_posix_shell || (is_shell_command && matches!(detect_windows_shell(), WindowsShell::GitBash(_))) {
            Cow::Owned(ctx.workspace_root.replace('\\', "/"))
        } else {
            Cow::Borrowed(ctx.workspace_root)
        }
    };
    #[cfg(unix)]
    let env_root = Cow::Borrowed(ctx.workspace_root);

    let mut child = match fuigo_tools::util::ProcessScope::spawn_placed(ctx.process_scope.as_ref(), || tokio::process::Command::new(&program), |cmd, _hook| {
        // P189: spawn_placed has already registered the placement as the first pre_exec
        // (apply_shell_environment_policy, detach_command and restrict_child_network all register one).
        cmd.args(&base_args).envs(base_env.iter().copied());
        fuigo_tools::util::apply_shell_environment_policy(cmd, None);
        fuigo_tools::util::detach_command(cmd);
        fuigo_sandbox::child_net::restrict_child_network(cmd);
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .current_dir(ctx.workspace_root)
            // SECURITY: extra_env is applied before the FUIGO_* identity vars so a hook cannot spoof them. It is applied
            // after `apply_shell_environment_policy`, which strips `FUIGO_API_KEY` by name, so the key reaches this child
            // only through `child_env`, i.e. when this hook's config names it (P70a).
            .envs(child_env.iter())
            .env("FUIGO_HOOK_EVENT", envelope.hook_event_name.to_string())
            .env("FUIGO_HOOK_NAME", &spec.name)
            .env("FUIGO_SESSION_ID", ctx.session_id)
            .env("FUIGO_WORKSPACE_ROOT", env_root.as_ref())
            .env("CLAUDE_PROJECT_DIR", env_root.as_ref())
            .kill_on_drop(true);
        Ok::<(), std::convert::Infallible>(())
    })
    .map_err(|e| match e {
        fuigo_tools::util::SpawnPlacedError::Spawn(e) => e,
        fuigo_tools::util::SpawnPlacedError::Build(never) => match never {},
        fuigo_tools::util::SpawnPlacedError::Stopping => std::io::Error::other("session is stopping; command not started"),
    }) {
        Ok(c) => c,
        Err(e) => {
            let elapsed = start.elapsed();
            let message = format!("failed to spawn command: {}: {e}", program.to_string_lossy());
            // A program that is missing or not executable can never run: a CONFIG failure, like a missing placeholder.
            let message = if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) {
                crate::health::config_failure(&message)
            } else {
                message
            };
            return (HookRunnerResult::Failed(message), elapsed, None);
        }
    };

    // Built whether or not there is a scope to enroll it in: the guard below is what killpg's the
    // tree if this future is dropped mid-run, and that path has no scope to fall back on.
    let hook_group = hook_process_group(&child);
    if let (Some(scope), Some(group)) = (ctx.process_scope.as_ref(), hook_group.as_ref())
        && !scope.register(group)
    {
        // `register` already killpg'd the group: the scope was closed and will not run again.
        return (
            HookRunnerResult::Failed("session closed before the hook ran".to_string()),
            start.elapsed(),
            None,
        );
    }
    let mut reap = HookProcessGuard::arm(hook_group.clone());

    let stdin = child.stdin.take();
    let timeout = Duration::from_millis(spec.timeout_ms);
    let result = tokio::time::timeout(timeout, async move {
        let write = async {
            if let Some(mut stdin) = stdin {
                let _ = stdin.write_all(stdin_json.as_bytes()).await;
            }
        };
        let (_, output) = tokio::join!(write, child.wait_with_output());
        output
    })
    .await;

    let elapsed = start.elapsed();

    if matches!(result, Ok(Ok(_))) {
        reap.disarm();
    } else if let Some(group) = &hook_group {
        let _ = group.kill();
    }

    match result {
        Err(_) => (
            HookRunnerResult::Failed(format!("timed out after {}ms", spec.timeout_ms)),
            elapsed,
            None,
        ),
        Ok(Err(e)) => (
            HookRunnerResult::Failed(format!("command execution failed: {e}")),
            elapsed,
            None,
        ),
        Ok(Ok(output)) => {
            let exit_code = output.status.code().unwrap_or(-1);

            let stdout = truncate_output(&output.stdout);
            let stderr = truncate_output(&output.stderr);

            if !stderr.is_empty() {
                if exit_code != 0 {
                    tracing::debug!(
                        hook_name = %spec.name,
                        stderr_bytes = stderr.len(),
                        stderr_first_line = stderr_first_line(&stderr).map(clip_reason).unwrap_or_default(),
                        "hook stderr output captured"
                    );
                } else {
                    tracing::debug!(
                        hook_name = %spec.name,
                        stderr_bytes = stderr.len(),
                        "hook stderr output captured"
                    );
                }
            }

            if debug_payloads {
                tracing::trace!(
                    hook_name = %spec.name,
                    stdout_bytes = stdout.len(),
                    "hook stdout payload"
                );
            }

            tracing::debug!(
                hook_name = %spec.name,
                exit_code,
                stdout_bytes = stdout.len(),
                stderr_bytes = stderr.len(),
                elapsed_ms = elapsed.as_millis() as u64,
                "hook command completed"
            );

            let system_message = extract_system_message(&stdout);
            let (result, elapsed) = match mode {
                GateKind::Observe => {
                    if exit_code == 0 {
                        (HookRunnerResult::Success, elapsed)
                    } else {
                        (
                            HookRunnerResult::Failed(append_stderr_line(
                                &format!("exit code {exit_code}"),
                                &stderr,
                            )),
                            elapsed,
                        )
                    }
                }
                GateKind::Tool => {
                    parse_blocking_result(&stdout, &stderr, exit_code, &spec.name, elapsed)
                }
                GateKind::Stop => {
                    parse_stop_result(&stdout, &stderr, exit_code, &spec.name, elapsed)
                }
                GateKind::PostTool => {
                    parse_post_tool_use_result(&stdout, &stderr, exit_code, &spec.name, elapsed)
                }
                GateKind::Prompt => {
                    parse_prompt_result(&stdout, &stderr, exit_code, &spec.name, elapsed)
                }
            };
            (result, elapsed, system_message)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PsQuote {
    Bare,
    Single,
    Double,
}

#[cfg(any(test, not(unix)))]
fn rewrite_posix_env_refs_for_powershell<'a>(
    command: &'a str,
    extra_env: &std::collections::HashMap<String, String>,
) -> Cow<'a, str> {
    let mut out: Option<String> = None;
    let mut cursor = 0;
    let mut first_rewrite_at: Option<usize> = None;
    for r in crate::env_expand::iter_env_var_references(command) {
        if r.start < cursor {
            continue;
        }
        if r.name.is_empty() || r.has_modifier {
            continue;
        }
        if !RUNNER_ALWAYS_SET_ENV.contains(&r.name) && !extra_env.contains_key(r.name) {
            continue;
        }
        let (quote, escaped) = powershell_ctx_at(command, r.start);
        if quote == PsQuote::Single || escaped {
            continue;
        }
        let buf = out.get_or_insert_with(|| String::with_capacity(command.len() + 24));
        if quote == PsQuote::Bare {
            let token_end = command[r.start..]
                .find(|c: char| {
                    c.is_whitespace()
                        || matches!(c, ';' | '|' | '&' | '<' | '>' | '(' | ')' | '[' | ']' | ',')
                })
                .map_or(command.len(), |i| r.start + i);
            buf.push_str(&command[cursor..r.start]);
            buf.push('"');
            rewrite_ps_env_refs_in_span(buf, &command[r.start..token_end], extra_env);
            buf.push('"');
            cursor = token_end;
        } else {
            buf.push_str(&command[cursor..r.start]);
            push_ps_env_ref(buf, r.braced, r.name);
            cursor = r.end;
        }
        if first_rewrite_at.is_none() {
            first_rewrite_at = Some(r.start);
        }
    }
    match out {
        None => Cow::Borrowed(command),
        Some(mut buf) => {
            buf.push_str(&command[cursor..]);
            if first_rewrite_at.is_some_and(|at| {
                let pad = command.len() - command.trim_start().len();
                at == pad || (command.as_bytes().get(pad) == Some(&b'"') && at == pad + 1)
            }) && !buf.starts_with("& ")
            {
                buf.insert_str(0, "& ");
            }
            Cow::Owned(buf)
        }
    }
}

#[cfg(any(test, not(unix)))]
fn rewrite_ps_env_refs_in_span(
    buf: &mut String,
    span: &str,
    extra_env: &std::collections::HashMap<String, String>,
) {
    let mut cur = 0;
    for r in crate::env_expand::iter_env_var_references(span) {
        if r.name.is_empty() || r.has_modifier {
            continue;
        }
        if !RUNNER_ALWAYS_SET_ENV.contains(&r.name) && !extra_env.contains_key(r.name) {
            continue;
        }
        buf.push_str(&span[cur..r.start]);
        push_ps_env_ref(buf, r.braced, r.name);
        cur = r.end;
    }
    buf.push_str(&span[cur..]);
}

#[cfg(any(test, not(unix)))]
fn push_ps_env_ref(buf: &mut String, braced: bool, name: &str) {
    if braced {
        buf.push_str("${env:");
        buf.push_str(name);
        buf.push('}');
    } else {
        buf.push_str("$env:");
        buf.push_str(name);
    }
}

fn powershell_ctx_at(command: &str, at: usize) -> (PsQuote, bool) {
    let bytes = command.as_bytes();
    let mut i = 0;
    let mut quote = PsQuote::Bare;
    while i < at {
        let c = bytes[i];
        match quote {
            PsQuote::Single => {
                if c == b'\'' {
                    quote = PsQuote::Bare;
                }
                i += 1;
            }
            PsQuote::Double => {
                if c == b'`' {
                    i = i.saturating_add(2);
                } else if c == b'"' {
                    quote = PsQuote::Bare;
                    i += 1;
                } else {
                    i += 1;
                }
            }
            PsQuote::Bare => {
                if c == b'`' {
                    i = i.saturating_add(2);
                } else if c == b'\'' {
                    quote = PsQuote::Single;
                    i += 1;
                } else if c == b'"' {
                    quote = PsQuote::Double;
                    i += 1;
                } else {
                    i += 1;
                }
            }
        }
    }
    let escaped = quote != PsQuote::Single && at > 0 && bytes[at - 1] == b'`';
    (quote, escaped)
}

#[cfg(not(unix))]
fn rewrite_hook_command_for_windows_shell<'a>(
    command: &'a str,
    extra_env: &std::collections::HashMap<String, String>,
) -> Cow<'a, str> {
    use fuigo_config::shell::{WindowsShell, detect_windows_shell};
    match detect_windows_shell() {
        WindowsShell::Pwsh | WindowsShell::PowerShell => {
            rewrite_posix_env_refs_for_powershell(command, extra_env)
        }
        WindowsShell::GitBash(_) => Cow::Borrowed(command),
        WindowsShell::Cmd => {
            if command.contains('$') {
                tracing::warn!(
                    "hook command uses $VAR but the Windows shell is cmd, which expands %VAR%"
                );
            }
            Cow::Borrowed(command)
        }
    }
}

/// How one command hook is started: the program, its arguments and any fixed environment.
pub(crate) struct CommandPlan {
    pub program: std::ffi::OsString,
    pub args: Vec<std::ffi::OsString>,
    pub env: Vec<(&'static str, &'static str)>,
    /// Whether the command goes through a shell (`sh -c`) rather than being executed directly.
    pub shell: bool,
    /// Whether the hook named its own POSIX shell (`"shell": "bash"`), so its paths are POSIX paths even on Windows.
    pub named_posix_shell: bool,
}

/// The runner-provided values a placeholder can resolve to.
pub(crate) struct PlanInputs<'a> {
    pub workspace_root: &'a str,
    pub session_id: &'a str,
    pub event: &'a str,
}

/// Shell-looking commands go through `sh -c`; the `command` + `args` form never does.
fn is_shell_form(spec: &HookSpec, command_str: &str) -> bool {
    spec.args.is_none()
        && (command_str.contains(' ')
            || command_str.contains('|')
            || command_str.contains('&')
            || command_str.contains(';')
            || command_str.contains('>')
            || command_str.contains('<')
            || command_str.contains('$')
            || command_str.starts_with('~'))
}

/// Decide how to start a command hook, or why it can never start (the `Err` text is the reason, without the CONFIG prefix).
///
/// * Shell form: only the known plugin placeholders ([`crate::config::KNOWN_HOOK_PLACEHOLDERS`]) are checked; every other
///   `${...}` is the script's own and is left to the shell.
/// * `command` + `args` form: executed directly. A bare command name is looked up on `PATH`; only a relative path that
///   contains a `/` is resolved against the plugin root (the hook's own directory for a non-plugin hook).
pub(crate) fn plan_command(
    spec: &HookSpec,
    command_str: &str,
    child_env: &std::collections::HashMap<String, String>,
    inputs: &PlanInputs<'_>,
) -> Result<CommandPlan, String> {
    if !is_shell_form(spec, command_str) {
        let program = resolve_program(spec, command_str, child_env)?;
        let args = expand_args(spec, child_env, inputs)?;
        return Ok(CommandPlan {
            program: program.into(),
            args,
            env: Vec::new(),
            shell: false,
            named_posix_shell: false,
        });
    }
    let unresolved = find_unresolved_env_vars(command_str, child_env);
    if !unresolved.is_empty() {
        return Err(format!(
            "required env var(s) not set: {}",
            unresolved.iter().map(|v| format!("${{{v}}}")).collect::<Vec<_>>().join(", ")
        ));
    }
    if let Some(name) = &spec.shell {
        if matches!(name.to_ascii_lowercase().as_str(), "powershell" | "pwsh") {
            warn_if_reads_powershell_input(spec, command_str);
        }
        let invocation = named_shell_invocation(name, command_str, child_env)?;
        return Ok(CommandPlan {
            program: invocation.0,
            args: invocation.1,
            env: invocation.2,
            shell: true,
            named_posix_shell: is_posix_shell_name(name),
        });
    }
    #[cfg(unix)]
    {
        Ok(CommandPlan {
            program: "sh".into(),
            args: vec!["-c".into(), command_str.into()],
            env: Vec::new(),
            shell: true,
            named_posix_shell: false,
        })
    }
    #[cfg(not(unix))]
    {
        let command_str = rewrite_hook_command_for_windows_shell(command_str, child_env);
        if matches!(
            fuigo_config::shell::detect_windows_shell(),
            fuigo_config::shell::WindowsShell::Pwsh | fuigo_config::shell::WindowsShell::PowerShell
        ) {
            warn_if_reads_powershell_input(spec, command_str.as_ref());
        }
        let inv = fuigo_config::shell::shell_command_argv(command_str.as_ref());
        Ok(CommandPlan {
            program: inv.program.into(),
            args: inv.args.into_iter().map(Into::into).collect(),
            env: inv.env,
            shell: true,
            named_posix_shell: false,
        })
    }
}

/// A shell the hook names must be a plain name looked up on `PATH`: no directory, no space, nothing a shell could parse.
fn validate_shell_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let starts_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    if starts_ok && name.len() <= 32 && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+')) {
        Ok(())
    } else {
        Err(format!(
            "unsupported \"shell\" value {name:?}: name a shell on PATH such as \"bash\" (no path, no spaces)"
        ))
    }
}

/// Whether an inline PowerShell command reads `$input` (the automatic variable that enumerates the pipeline, which for a
/// hook is the event JSON on stdin) outside single quotes. Platform-neutral so it is tested everywhere; the Windows build
/// calls it when it hands a command to PowerShell, and a hook that names `pwsh` or `powershell` does so on any platform.
pub(crate) fn reads_powershell_input(command: &str) -> bool {
    let bytes = command.as_bytes();
    let mut from = 0;
    while let Some(found) = command[from..].to_ascii_lowercase().find("$input") {
        let at = from + found;
        let end = at + "$input".len();
        let continues = bytes.get(end).is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
        let escaped = at > 0 && bytes[at - 1] == b'`';
        if !continues && !escaped && powershell_ctx_at(command, at).0 != PsQuote::Single {
            return true;
        }
        from = end;
    }
    false
}

/// Say, once per run, that an inline PowerShell hook reads `$input`: it runs, but it depends on PowerShell's own
/// stdin handling, which differs between `powershell` and `pwsh` and from a `-File` script.
fn warn_if_reads_powershell_input(spec: &HookSpec, command: &str) {
    if reads_powershell_input(command) {
        tracing::warn!(
            hook_name = %spec.name,
            "inline PowerShell hook reads $input; it runs, but $input behaves differently across PowerShell hosts. \
             Put the script in a .ps1 file and read the event with [Console]::In.ReadToEnd() for a stable result"
        );
    }
}

/// Whether `name` is a POSIX-style shell (`sh -c` syntax), as opposed to PowerShell or cmd.
fn is_posix_shell_name(name: &str) -> bool {
    !matches!(name.to_ascii_lowercase().as_str(), "powershell" | "pwsh" | "cmd")
}

/// `(program, args, env)` for a hook that names its shell: the shell is resolved on the hook's `PATH`, and when it is not
/// there the hook is a CONFIG failure ("bash not found"), never a quiet fallback to `sh`.
#[allow(clippy::type_complexity)]
fn named_shell_invocation(
    name: &str,
    command_str: &str,
    child_env: &std::collections::HashMap<String, String>,
) -> Result<(std::ffi::OsString, Vec<std::ffi::OsString>, Vec<(&'static str, &'static str)>), String> {
    validate_shell_name(name)?;
    let not_found = || format!("{name} not found on PATH (this hook sets \"shell\": \"{name}\")");
    let path_override = child_env.get("PATH").map(String::as_str);
    let program = resolve_named_shell(name, path_override).ok_or_else(not_found)?;
    let args: Vec<std::ffi::OsString> = match name.to_ascii_lowercase().as_str() {
        "powershell" | "pwsh" => ["-NoProfile", "-NonInteractive", "-Command"].iter().map(Into::into).chain([command_str.into()]).collect(),
        "cmd" => vec!["/C".into(), command_str.into()],
        _ => vec!["-c".into(), command_str.into()],
    };
    // Git Bash must not rewrite `/flag` arguments into Windows paths.
    let env = if cfg!(windows) && is_posix_shell_name(name) {
        vec![("MSYS_NO_PATHCONV", "1"), ("MSYS2_ARG_CONV_EXCL", "*")]
    } else {
        Vec::new()
    };
    Ok((program.into_os_string(), args, env))
}

#[cfg(unix)]
fn resolve_named_shell(name: &str, path_override: Option<&str>) -> Option<std::path::PathBuf> {
    find_on_path(name, path_override)
}

/// Windows: resolve a named shell on the hook's `PATH`. `bash` prefers Git Bash and never resolves to the WSL launcher.
#[cfg(not(unix))]
fn resolve_named_shell(name: &str, path_override: Option<&str>) -> Option<std::path::PathBuf> {
    use fuigo_config::shell::{WindowsShell, detect_windows_shell};
    if name.eq_ignore_ascii_case("bash") {
        if let WindowsShell::GitBash(path) = detect_windows_shell() {
            return Some(std::path::PathBuf::from(path));
        }
    }
    let path_var = match path_override {
        Some(p) => std::ffi::OsString::from(p),
        None => std::env::var_os("PATH")?,
    };
    resolve_named_shell_in(name, &path_var, &is_executable_file)
}

/// Whether `path` is under a directory whose `bash.exe` is not a usable POSIX shell: `System32` (the WSL launcher, which
/// runs a different filesystem) or `WindowsApps` (the Store alias stubs). Separators are normalised so the check is the
/// same for `C:\Windows\System32` and a POSIX test layout.
fn is_wsl_launcher_dir(path: &std::path::Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase().replace('\\', "/");
    lower.contains("/windows/system32") || lower.contains("/windowsapps")
}

/// `name` (as `<name>.exe`) looked up in the directories of `path_var`; `exists` says whether a candidate is a runnable file.
///
/// The `System32` / `WindowsApps` exclusion applies to `bash` ONLY: its `bash.exe` there is the WSL launcher. `powershell.exe`
/// and `cmd.exe` live in `System32` (under `System32\WindowsPowerShell\v1.0` for the former), and `pwsh` may be anywhere
/// (including the Store's `WindowsApps`), so those resolve wherever `PATH` finds them.
// Windows-only caller, but platform-neutral so the layout rules are unit-tested on every host.
#[cfg_attr(unix, allow(dead_code))]
fn resolve_named_shell_in(
    name: &str,
    path_var: &std::ffi::OsStr,
    exists: &dyn Fn(&std::path::Path) -> bool,
) -> Option<std::path::PathBuf> {
    let lower = name.to_ascii_lowercase();
    let is_bash = lower.strip_suffix(".exe").unwrap_or(&lower) == "bash";
    let exts = [".exe".to_string()];
    find_in_dirs(name, path_var, &exts, &|candidate| {
        !(is_bash && is_wsl_launcher_dir(candidate)) && exists(candidate)
    })
}

/// The directory a relative `./x.sh` hook path resolves against: the plugin root for a plugin hook, else the hook's own directory.
fn relative_root(spec: &HookSpec) -> std::path::PathBuf {
    if matches!(crate::config::hook_origin(spec), crate::config::HookOrigin::Plugin) {
        for key in ["CLAUDE_PLUGIN_ROOT", "FUIGO_PLUGIN_ROOT"] {
            if let Some(root) = spec.extra_env.get(key).filter(|v| !v.is_empty()) {
                return std::path::PathBuf::from(root);
            }
        }
    }
    spec.source_dir.clone()
}

fn resolve_program(
    spec: &HookSpec,
    command: &str,
    child_env: &std::collections::HashMap<String, String>,
) -> Result<std::path::PathBuf, String> {
    let path = std::path::Path::new(command);
    let exists = |p: std::path::PathBuf| {
        if p.exists() {
            Ok(p)
        } else {
            Err(format!("command not found: {}", p.display()))
        }
    };
    if path.is_absolute() {
        return exists(path.to_path_buf());
    }
    if command.contains('/') || command.contains(std::path::MAIN_SEPARATOR) {
        return exists(relative_root(spec).join(path));
    }
    let is_plugin = matches!(crate::config::hook_origin(spec), crate::config::HookOrigin::Plugin);
    // A non-plugin hook written as a bare script name has always meant "the script beside my hook file", so that stays first.
    // A plugin hook, or any hook in the `command` + `args` form, means a program on PATH (`node`).
    let beside_first = spec.args.is_none() && !is_plugin;
    let beside = spec.source_dir.join(command);
    if beside_first && beside.exists() {
        return Ok(beside);
    }
    if let Some(found) = find_on_path(command, child_env.get("PATH").map(String::as_str)) {
        return Ok(found);
    }
    if !is_plugin && beside.exists() {
        return Ok(beside);
    }
    Err(format!("command not found: {command} (not on PATH)"))
}

/// The extensions Windows may add to a bare program name, in `PATHEXT` order (`.COM;.EXE;.BAT;.CMD` when it is unset).
/// Only the four a process can be started from directly are kept (a `.JS` or `.VBS` entry cannot be spawned). A `.cmd` or
/// `.bat` is spawned directly: the standard library runs it through `cmd.exe` with its own argument quoting and refuses an
/// argument it cannot quote safely, so no hook text is ever re-parsed by a shell.
fn spawnable_pathext(pathext: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for ext in pathext.unwrap_or("").split(';') {
        let ext = ext.trim().to_ascii_lowercase();
        if matches!(ext.as_str(), ".com" | ".exe" | ".bat" | ".cmd") && !out.contains(&ext) {
            out.push(ext);
        }
    }
    if out.is_empty() {
        out = [".com", ".exe", ".bat", ".cmd"].iter().map(|e| (*e).to_string()).collect();
    }
    out
}

/// The file names to try for `name`: with no extensions (POSIX) just `name`; with them, `name` itself when it already ends
/// in one (`node.exe`), else `name` plus each extension in order.
fn candidate_file_names(name: &str, exts: &[String]) -> Vec<String> {
    let lower = name.to_ascii_lowercase();
    if exts.is_empty() || exts.iter().any(|e| lower.ends_with(e.as_str())) {
        return vec![name.to_string()];
    }
    exts.iter().map(|e| format!("{name}{e}")).collect()
}

/// First hit of `name` in the directories of `path_var`, directory by directory and extension by extension (the order
/// Windows itself uses). `accept` says whether a candidate is a runnable file (and may veto it).
fn find_in_dirs(
    name: &str,
    path_var: &std::ffi::OsStr,
    exts: &[String],
    accept: &dyn Fn(&std::path::Path) -> bool,
) -> Option<std::path::PathBuf> {
    let names = candidate_file_names(name, exts);
    std::env::split_paths(path_var)
        // An empty `PATH` entry would mean the current directory, and a hook must not pick a program out of the workspace that way.
        .filter(|dir| !dir.as_os_str().is_empty())
        .flat_map(|dir| names.iter().map(move |n| dir.join(n)))
        .find(|candidate| accept(candidate))
}

/// `name` looked up on `path_override` (the hook's own `PATH`) or, without one, the process `PATH`. On Windows a bare
/// name also tries the `PATHEXT` extensions, so `node` finds `node.exe` (or `node.cmd`).
fn find_on_path(name: &str, path_override: Option<&str>) -> Option<std::path::PathBuf> {
    let path_var = match path_override {
        Some(p) => std::ffi::OsString::from(p),
        None => std::env::var_os("PATH")?,
    };
    let exts = if cfg!(windows) { spawnable_pathext(std::env::var("PATHEXT").ok().as_deref()) } else { Vec::new() };
    find_in_dirs(name, &path_var, &exts, &is_executable_file)
}

fn is_executable_file(path: &std::path::Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn expand_args(
    spec: &HookSpec,
    child_env: &std::collections::HashMap<String, String>,
    inputs: &PlanInputs<'_>,
) -> Result<Vec<std::ffi::OsString>, String> {
    let mut missing = std::collections::BTreeSet::new();
    let args: Vec<std::ffi::OsString> = spec
        .args
        .iter()
        .flatten()
        .map(|arg| expand_known_placeholders(arg, spec, child_env, inputs, &mut missing).into())
        .collect();
    if missing.is_empty() {
        Ok(args)
    } else {
        Err(format!(
            "required env var(s) not set: {}",
            missing.iter().map(|v| format!("${{{v}}}")).collect::<Vec<_>>().join(", ")
        ))
    }
}

/// Expand the known placeholders in one argument; anything else (including `${NOT_OURS}`) stays literal, since no shell sees it.
fn expand_known_placeholders(
    arg: &str,
    spec: &HookSpec,
    child_env: &std::collections::HashMap<String, String>,
    inputs: &PlanInputs<'_>,
    missing: &mut std::collections::BTreeSet<String>,
) -> String {
    let mut out = String::with_capacity(arg.len());
    let mut cursor = 0;
    for r in crate::env_expand::iter_env_var_references(arg) {
        out.push_str(&arg[cursor..r.start]);
        cursor = r.end;
        let literal = &arg[r.start..r.end];
        if r.name.is_empty() || r.has_modifier || !crate::config::is_known_hook_placeholder(r.name) {
            out.push_str(literal);
            continue;
        }
        match placeholder_value(r.name, spec, child_env, inputs) {
            Some(value) => out.push_str(&value),
            None => {
                missing.insert(r.name.to_string());
                out.push_str(literal);
            }
        }
    }
    out.push_str(&arg[cursor..]);
    out
}

fn placeholder_value(
    name: &str,
    spec: &HookSpec,
    child_env: &std::collections::HashMap<String, String>,
    inputs: &PlanInputs<'_>,
) -> Option<String> {
    match name {
        "FUIGO_HOOK_EVENT" => return Some(inputs.event.to_string()),
        "FUIGO_HOOK_NAME" => return Some(spec.name.clone()),
        "FUIGO_SESSION_ID" => return Some(inputs.session_id.to_string()),
        "FUIGO_WORKSPACE_ROOT" | "CLAUDE_PROJECT_DIR" => return Some(inputs.workspace_root.to_string()),
        _ => {}
    }
    let from_env = |key: &str| child_env.get(key).cloned().or_else(|| std::env::var(key).ok());
    from_env(name).or_else(|| {
        // The bare `PLUGIN_ROOT` some plugins write is the plugin root under either spelling.
        (name == "PLUGIN_ROOT")
            .then(|| from_env("CLAUDE_PLUGIN_ROOT").or_else(|| from_env("FUIGO_PLUGIN_ROOT")))
            .flatten()
    })
}

/// Check, without running anything, that a command hook can start: its placeholders resolve and its program exists.
/// The `Err` text is the CONFIG failure reason (see `crate::health`).
pub(crate) fn validate_command_spec(
    spec: &HookSpec,
    workspace_root: &str,
    session_id: &str,
) -> Result<(), String> {
    let Some(command) = spec.command.as_ref() else {
        return Err("command hook has no 'command' field".to_string());
    };
    let event = spec.event.to_string();
    let inputs = PlanInputs {
        workspace_root,
        session_id,
        event: &event,
    };
    plan_command(spec, &command.to_string_lossy(), &spec.extra_env, &inputs).map(|_| ())
}

fn find_unresolved_env_vars(
    command_str: &str,
    extra_env: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    let locally_assigned = find_local_shell_assignments(command_str);
    let mut out: Vec<String> = Vec::new();
    for r in crate::env_expand::iter_env_var_references(command_str) {
        if r.name.is_empty() || r.has_modifier {
            continue;
        }
        // Only Fuigo's own placeholders are ours to demand: any other `${NAME}` is the script's (a loop variable, an
        // assignment inside a `case`), and refusing to run over it is what made valid scripts unrunnable.
        if !crate::config::is_known_hook_placeholder(r.name) {
            continue;
        }
        if RUNNER_ALWAYS_SET_ENV.contains(&r.name) {
            continue;
        }
        if extra_env.contains_key(r.name) {
            continue;
        }
        if std::env::var_os(r.name).is_some() {
            continue;
        }
        if locally_assigned.contains(r.name) {
            continue;
        }
        out.push(r.name.to_string());
    }
    out.sort();
    out.dedup();
    out
}

fn find_local_shell_assignments(command_str: &str) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    let bytes = command_str.as_bytes();
    let mut i = 0;
    let is_statement_start = |idx: usize| -> bool {
        if idx == 0 {
            return true;
        }
        let mut j = idx;
        while j > 0 {
            let c = bytes[j - 1];
            if c == b' ' || c == b'\t' {
                j -= 1;
                continue;
            }
            return matches!(c, b';' | b'&' | b'|' | b'\n' | b'(' | b'{');
        }
        true
    };
    while i < bytes.len() {
        let c = bytes[i];
        if !(c.is_ascii_alphabetic() || c == b'_') {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        let ident = std::str::from_utf8(&bytes[start..i]).unwrap_or("");
        if ident.is_empty() {
            continue;
        }
        if i < bytes.len() && bytes[i] == b'=' && is_statement_start(start) {
            names.insert(ident.to_string());
            continue;
        }
        if ident == "read" && is_statement_start(start) {
            while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
                i += 1;
            }
            while i < bytes.len() {
                let c2 = bytes[i];
                if matches!(c2, b';' | b'&' | b'|' | b'\n' | b'<' | b'>') {
                    break;
                }
                if c2 == b' ' || c2 == b'\t' {
                    i += 1;
                    continue;
                }
                if c2 == b'-' {
                    while i < bytes.len() && bytes[i] != b' ' && bytes[i] != b'\t' {
                        i += 1;
                    }
                    continue;
                }
                if !(c2.is_ascii_alphabetic() || c2 == b'_') {
                    break;
                }
                let s = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let read_ident = std::str::from_utf8(&bytes[s..i]).unwrap_or("");
                if !read_ident.is_empty() {
                    names.insert(read_ident.to_string());
                }
            }
        }
    }
    names
}

fn stderr_first_line(stderr: &str) -> Option<&str> {
    stderr.lines().map(str::trim).find(|line| !line.is_empty())
}

fn append_stderr_line(message: &str, stderr: &str) -> String {
    match stderr_first_line(stderr) {
        Some(line) => format!("{message}: {}", clip_reason(line)),
        None => message.to_string(),
    }
}

fn failed_with_exit_code(hook_name: &str, exit_code: i32, stderr: &str) -> HookRunnerResult {
    HookRunnerResult::Failed(append_stderr_line(
        &format!("hook '{hook_name}' failed with exit code {exit_code}"),
        stderr,
    ))
}

fn parse_blocking_result(
    stdout: &str,
    stderr: &str,
    exit_code: i32,
    hook_name: &str,
    elapsed: Duration,
) -> (HookRunnerResult, Duration) {
    let gate_document = if !stdout.trim().is_empty() {
        serde_json::from_str::<GateHookJson>(stdout.trim())
            .ok()
            .filter(GateHookJson::is_gate_document)
    } else {
        None
    };

    if let Some(json) = gate_document {
        let health = HookHealth::from_success(exit_code == 0);
        match gate_outcome(json, hook_name, stderr_first_line(stderr), health) {
            GateOutcome::Deny(reason) => {
                if exit_code != GATE_EXIT_CODE && exit_code != 0 {
                    tracing::warn!(
                        hook_name,
                        exit_code,
                        "JSON decision is 'deny' but exit code is not 0 or 2 — using JSON decision"
                    );
                }
                return (
                    HookRunnerResult::Deny {
                        reason,
                        hook_name: hook_name.to_string(),
                    },
                    elapsed,
                );
            }
            GateOutcome::Stop(reason) => {
                return (
                    HookRunnerResult::GateStop {
                        reason,
                        hook_name: hook_name.to_string(),
                    },
                    elapsed,
                );
            }
            GateOutcome::Allow { .. } | GateOutcome::Ask { .. } if exit_code == GATE_EXIT_CODE => {
                tracing::warn!(
                    hook_name,
                    "JSON decision is 'allow' or 'ask' but exit code is 2 — denying (stdout is ignored on exit 2)"
                );
            }
            GateOutcome::Defer if exit_code == GATE_EXIT_CODE => {
                tracing::warn!(
                    hook_name,
                    "JSON decision is 'defer' but exit code is 2 — denying (stdout is ignored on exit 2)"
                );
            }
            GateOutcome::Allow {
                updated_input,
                additional_context,
            } => {
                return (
                    HookRunnerResult::Allow {
                        updated_input,
                        additional_context,
                    },
                    elapsed,
                );
            }
            GateOutcome::Ask {
                reason,
                updated_input,
                additional_context,
            } => {
                return (
                    HookRunnerResult::Ask {
                        reason,
                        updated_input,
                        additional_context,
                    },
                    elapsed,
                );
            }
            GateOutcome::Defer => return (HookRunnerResult::Defer, elapsed),
            GateOutcome::Failed(err) if exit_code != GATE_EXIT_CODE => {
                return (
                    HookRunnerResult::Failed(append_stderr_line(&err, stderr)),
                    elapsed,
                );
            }
            GateOutcome::Failed(err) => {
                let reason = clip_reason(&match stderr_first_line(stderr) {
                    Some(line) => format!("{err}: {line}"),
                    None => err,
                });
                return (
                    HookRunnerResult::Deny {
                        reason,
                        hook_name: hook_name.to_string(),
                    },
                    elapsed,
                );
            }
        }
    }

    match exit_code {
        0 => (
            HookRunnerResult::Allow {
                updated_input: None,
                additional_context: None,
            },
            elapsed,
        ),
        GATE_EXIT_CODE => (
            HookRunnerResult::Deny {
                reason: stderr_first_line(stderr)
                    .map(clip_reason)
                    .unwrap_or_else(|| {
                        format!("denied by hook '{hook_name}' (exit code {GATE_EXIT_CODE})")
                    }),
                hook_name: hook_name.to_string(),
            },
            elapsed,
        ),
        _ => (failed_with_exit_code(hook_name, exit_code, stderr), elapsed),
    }
}

fn parse_stop_result(
    stdout: &str,
    stderr: &str,
    exit_code: i32,
    hook_name: &str,
    elapsed: Duration,
) -> (HookRunnerResult, Duration) {
    let trimmed = stdout.trim();
    if !trimmed.is_empty() {
        match serde_json::from_str::<StopHookJson>(trimmed) {
            Ok(json) => {
                return match stop_json_to_outcome(json, hook_name) {
                    Ok(outcome) => (HookRunnerResult::Stop(outcome), elapsed),
                    Err(err) => (HookRunnerResult::Failed(err), elapsed),
                };
            }
            Err(err) => {
                if trimmed.starts_with('{') {
                    tracing::warn!(
                        hook_name,
                        error = %err,
                        "stop hook stdout looks like JSON but failed to parse; falling back to the exit code"
                    );
                }
            }
        }
    }
    match exit_code {
        0 => (HookRunnerResult::Stop(StopHookOutcome::default()), elapsed),
        GATE_EXIT_CODE => {
            let feedback = stderr.trim();
            let block_reason = if feedback.is_empty() {
                format!("Blocked by stop hook '{hook_name}' (exit code {GATE_EXIT_CODE})")
            } else {
                feedback.to_string()
            };
            (
                HookRunnerResult::Stop(StopHookOutcome {
                    block_reason: Some(block_reason),
                    ..Default::default()
                }),
                elapsed,
            )
        }
        _ => (failed_with_exit_code(hook_name, exit_code, stderr), elapsed),
    }
}

fn parse_prompt_result(
    stdout: &str,
    stderr: &str,
    exit_code: i32,
    hook_name: &str,
    elapsed: Duration,
) -> (HookRunnerResult, Duration) {
    let stderr_message = {
        let trimmed = stderr.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    };
    let trimmed = stdout.trim();
    if !trimmed.is_empty() {
        match serde_json::from_str::<PromptHookJson>(trimmed) {
            Ok(json) => match prompt_json_to_block(&json, hook_name, stderr_message.as_deref()) {
                Ok(Some(reason)) => {
                    return (
                        HookRunnerResult::Block {
                            reason,
                            hook_name: hook_name.to_string(),
                        },
                        elapsed,
                    );
                }
                Ok(None) => {}
                Err(err) => {
                    if exit_code == GATE_EXIT_CODE {
                        tracing::warn!(
                            hook_name,
                            hook_failure = %err,
                            "prompt hook JSON is invalid but exit 2 still blocks"
                        );
                    } else {
                        return (
                            HookRunnerResult::Failed(append_stderr_line(&err, stderr)),
                            elapsed,
                        );
                    }
                }
            },
            Err(err) => {
                if trimmed.starts_with('{') {
                    tracing::warn!(
                        hook_name,
                        error = %err,
                        "prompt hook stdout looks like JSON but failed to parse; falling back to the exit code"
                    );
                }
            }
        }
    }
    match exit_code {
        0 => (HookRunnerResult::Success, elapsed),
        GATE_EXIT_CODE => (
            HookRunnerResult::Block {
                reason: stderr_message.unwrap_or_else(|| {
                    format!("Prompt blocked by hook '{hook_name}' (exit code {GATE_EXIT_CODE})")
                }),
                hook_name: hook_name.to_string(),
            },
            elapsed,
        ),
        _ => (
            HookRunnerResult::Failed(append_stderr_line(
                &format!("hook '{hook_name}' failed with exit code {exit_code}"),
                stderr,
            )),
            elapsed,
        ),
    }
}

fn parse_post_tool_use_result(
    stdout: &str,
    stderr: &str,
    exit_code: i32,
    hook_name: &str,
    elapsed: Duration,
) -> (HookRunnerResult, Duration) {
    let health = HookHealth::from_success(exit_code == 0);
    let trimmed = stdout.trim();
    let PostToolUseParse {
        mut outcome,
        failure,
    } = if trimmed.is_empty() {
        PostToolUseParse::default()
    } else {
        match serde_json::from_str::<PostToolUseHookJson>(trimmed) {
            Ok(json) => post_tool_use_json_to_outcome(json, hook_name, health),
            Err(err) => {
                if trimmed.starts_with('{') {
                    tracing::warn!(
                        hook_name,
                        error = %err,
                        "post_tool_use hook stdout looks like JSON but failed to parse; ignoring"
                    );
                }
                PostToolUseParse::default()
            }
        }
    };

    if exit_code == GATE_EXIT_CODE && outcome.block_reason.is_none() {
        let feedback = stderr.trim();
        if !feedback.is_empty() {
            outcome.block_reason = Some(clip_text(feedback, MAX_HOOK_FEEDBACK_CHARS));
        }
    }

    if exit_code != 0 && exit_code != GATE_EXIT_CODE {
        let exit_failure = append_stderr_line(
            &format!("hook '{hook_name}' failed with exit code {exit_code}"),
            stderr,
        );
        if outcome.is_empty() {
            return (HookRunnerResult::Failed(exit_failure), elapsed);
        }
        return (
            HookRunnerResult::PostToolUse {
                outcome,
                failure: Some(exit_failure),
            },
            elapsed,
        );
    }

    (HookRunnerResult::PostToolUse { outcome, failure }, elapsed)
}

fn truncate_output(bytes: &[u8]) -> String {
    if bytes.len() <= MAX_OUTPUT_BYTES {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        let mut truncated = String::from_utf8_lossy(&bytes[..MAX_OUTPUT_BYTES]).into_owned();
        truncated.push_str(" [truncated]");
        tracing::warn!(
            total_bytes = bytes.len(),
            max_bytes = MAX_OUTPUT_BYTES,
            "hook output truncated"
        );
        truncated
    }
}

pub fn resolve_command_path(spec: &HookSpec) -> Option<std::path::PathBuf> {
    let command = spec.command.as_ref()?;
    if command.is_absolute() {
        Some(command.clone())
    } else {
        Some(relative_root(spec).join(command))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{
        MAX_HOOK_FEEDBACK_CHARS, MAX_HOOK_OUTPUT_REPLACEMENT_CHARS, MAX_REASON_CHARS,
    };
    use crate::result::{OutputReplacement, ReplacementKind};

    fn parse(json: &str) -> HookRunnerResult {
        parse_blocking_result(json, "", 0, "test", Duration::ZERO).0
    }

    #[test]
    fn parse_rewrite_shapes() {
        let rewrite = |r: HookRunnerResult| match r {
            HookRunnerResult::Allow {
                updated_input: Some(rw),
                ..
            } => rw,
            other => panic!("expected Allow with rewrite, got {other:?}"),
        };
        for json in [
            r#"{"hookSpecificOutput":{"updatedInput":{"command":"xb build"}}}"#,
            r#"{"decision":"allow","hookSpecificOutput":{"updatedInput":{"command":"xb build"}}}"#,
        ] {
            assert_eq!(rewrite(parse(json))["command"], "xb build");
        }
        assert!(matches!(
            parse(r#"{"decision":"deny","hookSpecificOutput":{"updatedInput":{"command":"x"}}}"#),
            HookRunnerResult::Deny { .. }
        ));
        let (failed_hook, _) = parse_blocking_result(
            r#"{"hookSpecificOutput":{"updatedInput":{"command":"xb build"}}}"#,
            "",
            1,
            "test",
            Duration::ZERO,
        );
        assert!(matches!(
            failed_hook,
            HookRunnerResult::Allow {
                updated_input: None,
                ..
            }
        ));
    }

    #[test]
    fn unknown_decision_with_exit_2_still_denies() {
        let (result, _) = parse_blocking_result(
            r#"{"hookSpecificOutput":{"permissionDecision":"denied"}}"#,
            "writes outside the repo\n",
            2,
            "typo",
            Duration::ZERO,
        );
        match result {
            HookRunnerResult::Deny { reason, .. } => assert_eq!(
                reason,
                "unknown decision value 'denied' in 'hookSpecificOutput.permissionDecision' from hook 'typo': writes outside the repo"
            ),
            other => panic!("expected Deny, got {other:?}"),
        }

        let (result, _) = parse_blocking_result(
            r#"{"hookSpecificOutput":{"permissionDecision":"denied"}}"#,
            &"x".repeat(MAX_REASON_CHARS),
            2,
            "typo",
            Duration::ZERO,
        );
        match result {
            HookRunnerResult::Deny { reason, .. } => assert!(
                reason.starts_with(
                    "unknown decision value 'denied' in 'hookSpecificOutput.permissionDecision' from hook 'typo'"
                ),
                "the error must survive a full-length stderr line, got: {reason}"
            ),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn parse_decisions() {
        fn summarize(result: HookRunnerResult) -> String {
            match result {
                HookRunnerResult::Allow {
                    updated_input: Some(_),
                    ..
                } => "allow + rewrite".to_string(),
                HookRunnerResult::Allow { .. } => "allow".to_string(),
                HookRunnerResult::Ask {
                    reason,
                    updated_input,
                    ..
                } => {
                    let label = if updated_input.is_some() {
                        "ask + rewrite"
                    } else {
                        "ask"
                    };
                    match reason {
                        Some(reason) => format!("{label}: {reason}"),
                        None => label.to_string(),
                    }
                }
                HookRunnerResult::Defer => "defer".to_string(),
                HookRunnerResult::Deny { reason, .. } => format!("deny: {reason}"),
                HookRunnerResult::GateStop { reason, .. } => format!("stop: {reason}"),
                HookRunnerResult::Failed(error) => format!("failed: {error}"),
                other => panic!("expected a gate result, got {other:?}"),
            }
        }
        for (json, expected) in [
            (r#"{"decision":"allow"}"#, "allow"),
            (r#"{"decision":"approve"}"#, "allow"),
            (r#"{"decision":"block","reason":"nope"}"#, "deny: nope"),
            (r#"{"decision":"deny"}"#, "deny: denied by hook 'test'"),
            (
                r#"{"decision":"maybe"}"#,
                "failed: unknown decision value 'maybe' in 'decision' from hook 'test'",
            ),
            // `continue: false` at a tool gate refuses the call AND ends the turn
            (
                r#"{"decision":"allow","continue":false,"systemMessage":"hi"}"#,
                "stop: stopped by hook 'test' (continue: false)",
            ),
            (r#"{"continue":false,"stopReason":"enough"}"#, "stop: enough"),
            (r#"{"decision":"deny","reason":"why","continue":false}"#, "stop: why"),
            (r#"{"continue":true,"stopReason":"enough"}"#, "allow"),
            (
                r#"{"decision":"allow","hookSpecificOutput":{"updateInput":{"command":"x"}}}"#,
                "allow",
            ),
            (r#"{"updatedInput":{"command":"x"}}"#, "allow"),
            (r#"{"permissionDecision":"deny"}"#, "allow"),
            (
                r#"{"hookSpecificOutput":{"permissionDecision":"allow","updatedInput":"nope"}}"#,
                "allow",
            ),
            (
                r#"{"hookSpecificOutput":{"permissionDecision":"ask","updatedInput":"nope"}}"#,
                "ask",
            ),
            (
                r#"{"hookSpecificOutput":{"permissionDecision":"ask"}}"#,
                "ask",
            ),
            (
                r#"{"hookSpecificOutput":{"permissionDecision":"ask","updatedInput":{"command":"x"}}}"#,
                "ask + rewrite",
            ),
            (
                r#"{"decision":"allow","reason":"allow-reason","hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"ask-reason"}}"#,
                "ask: ask-reason",
            ),
            (
                r#"{"decision":"ask","hookSpecificOutput":{"permissionDecision":"allow","permissionDecisionReason":"allow-reason"}}"#,
                "allow",
            ),
            (
                r#"{"decision":"deny","reason":"nope","hookSpecificOutput":{"permissionDecision":"ask"}}"#,
                "ask: nope",
            ),
            (
                r#"{"decision":"allow","reason":"allow-reason","hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"block-reason"}}"#,
                "deny: block-reason",
            ),
            (
                r#"{"decision":"deny","hookSpecificOutput":{"permissionDecision":"allow","permissionDecisionReason":"allow side"}}"#,
                "allow",
            ),
            (
                r#"{"reason":"blocked: writes outside repo","hookSpecificOutput":{"permissionDecision":"deny"}}"#,
                "deny: blocked: writes outside repo",
            ),
            (
                r#"{"decision":"deny","hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"same call, one reason"}}"#,
                "deny: same call, one reason",
            ),
            (
                r#"{"hookSpecificOutput":{"permissionDecision":"maybe"}}"#,
                "failed: unknown decision value 'maybe' in 'hookSpecificOutput.permissionDecision' from hook 'test'",
            ),
            (
                r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"defer","permissionDecisionReason":"because"}}"#,
                "defer",
            ),
            (r#"{"decision":"defer"}"#, "defer"),
            (
                r#"{"decision":"defer","hookSpecificOutput":{"permissionDecision":"ask"}}"#,
                "ask",
            ),
            (
                r#"{"decision":"defer","hookSpecificOutput":{"permissionDecision":"maybe"}}"#,
                "failed: unknown decision value 'maybe' in 'hookSpecificOutput.permissionDecision' from hook 'test'",
            ),
        ] {
            assert_eq!(summarize(parse(json)), expected, "for {json}");
        }
    }

    #[test]
    fn json_reason_is_capped() {
        let long = "é".repeat(MAX_REASON_CHARS + 50);
        let json = serde_json::json!({ "decision": "deny", "reason": long }).to_string();
        match parse(&json) {
            HookRunnerResult::Deny { reason, .. } => {
                assert_eq!(
                    reason,
                    format!("{}… [+50 chars]", "é".repeat(MAX_REASON_CHARS))
                );
            }
            other => panic!("expected Deny, got {other:?}"),
        }

        let ask = serde_json::json!({ "decision": "ask", "reason": long }).to_string();
        match parse(&ask) {
            HookRunnerResult::Ask { reason, .. } => {
                assert_eq!(
                    reason,
                    Some(format!("{}… [+50 chars]", "é".repeat(MAX_REASON_CHARS)))
                );
            }
            other => panic!("expected Ask, got {other:?}"),
        }
    }

    #[test]
    fn allow_and_ask_carry_additional_context_and_drop_a_blank() {
        let context = |result: HookRunnerResult| match result {
            HookRunnerResult::Allow {
                additional_context, ..
            }
            | HookRunnerResult::Ask {
                additional_context, ..
            } => additional_context,
            other => panic!("expected Allow or Ask, got {other:?}"),
        };
        for decision in ["allow", "ask"] {
            assert_eq!(
                context(parse(&format!(
                    r#"{{"hookSpecificOutput":{{"permissionDecision":"{decision}","additionalContext":"note"}}}}"#
                )))
                .as_deref(),
                Some("note"),
                "for {decision}"
            );
            assert_eq!(
                context(parse(&format!(
                    r#"{{"hookSpecificOutput":{{"permissionDecision":"{decision}","additionalContext":"  "}}}}"#
                ))),
                None,
                "a blank additionalContext is not context, for {decision}"
            );
        }
    }

    #[test]
    fn additional_context_is_capped_in_characters_not_bytes() {
        let long = "é".repeat(MAX_HOOK_FEEDBACK_CHARS + 50);
        let json = serde_json::json!({
            "hookSpecificOutput": { "permissionDecision": "allow", "additionalContext": long }
        })
        .to_string();
        match parse(&json) {
            HookRunnerResult::Allow {
                additional_context, ..
            } => assert_eq!(
                additional_context,
                Some(format!(
                    "{}… [+50 chars]",
                    "é".repeat(MAX_HOOK_FEEDBACK_CHARS)
                ))
            ),
            other => panic!("expected Allow, got {other:?}"),
        }

        let stop = serde_json::json!({ "hookSpecificOutput": { "additionalContext": long } });
        let (result, _) = parse_stop_result(&stop.to_string(), "", 0, "s", Duration::ZERO);
        assert_eq!(
            stop_outcome(result).additional_context,
            Some(format!(
                "{}… [+50 chars]",
                "é".repeat(MAX_HOOK_FEEDBACK_CHARS)
            ))
        );
    }

    #[test]
    fn broken_hook_loses_its_additional_context() {
        let (result, _) = parse_blocking_result(
            r#"{"hookSpecificOutput":{"permissionDecision":"allow","additionalContext":"note"}}"#,
            "",
            1,
            "test",
            Duration::ZERO,
        );
        assert!(matches!(
            result,
            HookRunnerResult::Allow {
                additional_context: None,
                ..
            }
        ));
    }

    #[test]
    fn deny_drops_updated_input() {
        assert!(matches!(
            parse(r#"{"decision":"deny","hookSpecificOutput":{"updatedInput":{"command":"x"}}}"#),
            HookRunnerResult::Deny { .. }
        ));
    }

    #[test]
    fn failure_keeps_allow_but_drops_updated_input() {
        let (result, _) = parse_blocking_result(
            r#"{"hookSpecificOutput":{"updatedInput":{"command":"xb build"}}}"#,
            "",
            1,
            "test",
            Duration::ZERO,
        );
        assert!(matches!(
            result,
            HookRunnerResult::Allow {
                updated_input: None,
                ..
            }
        ));
    }

    #[test]
    fn non_object_updated_input_drops_the_rewrite() {
        assert!(matches!(
            parse(r#"{"hookSpecificOutput":{"permissionDecision":"allow","updatedInput":"nope"}}"#),
            HookRunnerResult::Allow {
                updated_input: None,
                ..
            }
        ));
    }

    #[test]
    fn unknown_decision_is_failed_naming_the_field() {
        let cases = [
            (
                r#"{"decision":"maybe"}"#,
                "unknown decision value 'maybe' in 'decision' from hook 'test'",
            ),
            (
                r#"{"hookSpecificOutput":{"permissionDecision":"maybe"}}"#,
                "unknown decision value 'maybe' in 'hookSpecificOutput.permissionDecision' from hook 'test'",
            ),
        ];
        for (json, expected) in cases {
            match parse(json) {
                HookRunnerResult::Failed(error) => assert_eq!(error, expected, "for {json}"),
                other => panic!("expected Failed, got {other:?}"),
            }
        }
    }

    #[test]
    fn ask_forces_the_prompt_with_its_reason() {
        assert!(matches!(
            parse(r#"{"hookSpecificOutput":{"permissionDecision":"ask"}}"#),
            HookRunnerResult::Ask { reason: None, .. }
        ));
        match parse(
            r#"{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"ask-reason"}}"#,
        ) {
            HookRunnerResult::Ask { reason, .. } => {
                assert_eq!(reason.as_deref(), Some("ask-reason"))
            }
            other => panic!("expected Ask, got {other:?}"),
        }
    }

    #[test]
    fn legacy_decision_applies_when_permission_decision_absent() {
        let cases = [
            (r#"{"decision":"approve"}"#, None),
            (r#"{"decision":"allow"}"#, None),
            (r#"{"decision":"block","reason":"nope"}"#, Some("nope")),
            (r#"{"decision":"deny"}"#, Some("denied by hook 'test'")),
        ];
        for (json, deny_reason) in cases {
            match (parse(json), deny_reason) {
                (HookRunnerResult::Allow { .. }, None) => {}
                (HookRunnerResult::Deny { reason, .. }, Some(expected)) => {
                    assert_eq!(reason, expected, "for {json}")
                }
                (other, _) => panic!("unexpected result for {json}: {other:?}"),
            }
        }
    }

    #[test]
    fn canonical_permission_decision_overrides_legacy_decision() {
        for json in [
            r#"{"decision":"block","hookSpecificOutput":{"permissionDecision":"allow"}}"#,
            r#"{"decision":"deny","hookSpecificOutput":{"permissionDecision":"allow"}}"#,
        ] {
            assert!(
                matches!(parse(json), HookRunnerResult::Allow { .. }),
                "canonical allow must override legacy block/deny, for {json}"
            );
        }
        match parse(
            r#"{"decision":"approve","hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"nope"}}"#,
        ) {
            HookRunnerResult::Deny { reason, .. } => assert_eq!(reason, "nope"),
            other => panic!("canonical deny must override legacy approve, got {other:?}"),
        }
    }

    #[test]
    fn deny_reason_and_stderr_excerpt_are_capped() {
        let long = "é".repeat(MAX_REASON_CHARS + 50);
        let capped = format!("{}… [+50 chars]", "é".repeat(MAX_REASON_CHARS));

        let json = serde_json::json!({ "decision": "deny", "reason": long }).to_string();
        match parse(&json) {
            HookRunnerResult::Deny { reason, .. } => assert_eq!(reason, capped),
            other => panic!("expected Deny, got {other:?}"),
        }

        let ask = serde_json::json!({ "decision": "ask", "reason": long }).to_string();
        match parse(&ask) {
            HookRunnerResult::Ask { reason, .. } => {
                assert_eq!(reason.as_deref(), Some(capped.as_str()));
            }
            other => panic!("expected Ask, got {other:?}"),
        }

        let (deny, _) = parse_blocking_result("", &long, 2, "test", Duration::ZERO);
        match deny {
            HookRunnerResult::Deny { reason, .. } => assert_eq!(reason, capped),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn exit_code_decides_when_no_gate_json() {
        for (stdout, code, expect_allow) in [
            ("", 0, true),
            ("not json at all", 0, true),
            (r#"{"detail":"ok"}"#, 0, true),
            ("", 2, false),
        ] {
            let (result, _) = parse_blocking_result(stdout, "", code, "test", Duration::ZERO);
            if expect_allow {
                assert!(
                    matches!(result, HookRunnerResult::Allow { .. }),
                    "for {stdout}"
                );
            } else {
                assert!(
                    matches!(result, HookRunnerResult::Deny { .. }),
                    "for {stdout}"
                );
            }
        }
        let (fail, _) = parse_blocking_result(r#"{"detail":"x"}"#, "", 1, "test", Duration::ZERO);
        assert!(matches!(fail, HookRunnerResult::Failed(_)));
    }

    #[test]
    fn exit_2_denies_over_json_allow() {
        let (deny, _) =
            parse_blocking_result(r#"{"decision":"allow"}"#, "", 2, "test", Duration::ZERO);
        assert!(matches!(deny, HookRunnerResult::Deny { .. }));
    }

    #[test]
    fn deny_and_failure_carry_first_stderr_line() {
        let (deny, _) = parse_blocking_result(
            "",
            "  \nrejected by policy\nmore\n",
            2,
            "test",
            Duration::ZERO,
        );
        match deny {
            HookRunnerResult::Deny { reason, .. } => assert_eq!(reason, "rejected by policy"),
            other => panic!("expected Deny, got {other:?}"),
        }

        let (fail, _) = parse_blocking_result("", "config missing\n", 1, "test", Duration::ZERO);
        match fail {
            HookRunnerResult::Failed(error) => assert!(
                error.contains("exit code 1") && error.contains("config missing"),
                "failure must carry exit code AND stderr text, got: {error}"
            ),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn stderr_line_is_capped() {
        let long = "é".repeat(MAX_REASON_CHARS + 50);
        let (deny, _) = parse_blocking_result("", &long, 2, "test", Duration::ZERO);
        match deny {
            HookRunnerResult::Deny { reason, .. } => assert_eq!(
                reason,
                format!("{}… [+50 chars]", "é".repeat(MAX_REASON_CHARS))
            ),
            other => panic!("expected Deny, got {other:?}"),
        }

        let exact = "x".repeat(MAX_REASON_CHARS);
        let (deny, _) = parse_blocking_result("", &exact, 2, "test", Duration::ZERO);
        match deny {
            HookRunnerResult::Deny { reason, .. } => assert_eq!(reason, exact),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn blank_json_reason_falls_back() {
        let blank = || {
            serde_json::from_str::<GateHookJson>(r#"{"decision":"deny","reason":"  "}"#)
                .expect("valid gate JSON")
        };
        assert!(
            matches!(gate_outcome(blank(), "h", Some("quota exceeded"), HookHealth::Healthy), GateOutcome::Deny(ref reason) if reason == "quota exceeded")
        );
        assert!(
            matches!(gate_outcome(blank(), "h", None, HookHealth::Healthy), GateOutcome::Deny(ref reason) if reason == "denied by hook 'h'")
        );
    }

    #[test]
    fn unknown_decision_failure_carries_stderr() {
        let (result, _) = parse_blocking_result(
            r#"{"decision":"maybe"}"#,
            "config missing\n",
            1,
            "test",
            Duration::ZERO,
        );
        match result {
            HookRunnerResult::Failed(error) => assert!(
                error.contains("maybe") && error.contains("config missing"),
                "got: {error}"
            ),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn blank_deny_reason_falls_back_to_stderr_then_generic() {
        let blank = || {
            serde_json::from_str::<GateHookJson>(r#"{"decision":"deny","reason":"  "}"#)
                .expect("valid gate JSON")
        };
        assert!(matches!(
            gate_outcome(blank(), "h", Some("quota exceeded"), HookHealth::Healthy),
            GateOutcome::Deny(ref reason) if reason == "quota exceeded"
        ));
        assert!(matches!(
            gate_outcome(blank(), "h", None, HookHealth::Healthy),
            GateOutcome::Deny(ref reason) if reason == "denied by hook 'h'"
        ));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn observe_failure_reports_exit_code_and_stderr_line() {
        let spec = make_shell_spec("echo 'disk full' >&2; exit 1");
        let (result, _, _) =
            run_command_hook(&spec, &make_envelope(), &make_ctx(), GateKind::Observe).await;
        match result {
            HookRunnerResult::Failed(error) => assert_eq!(error, "exit code 1: disk full"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn json_decision_vs_exit_code() {
        let (deny, _) = parse_blocking_result(
            r#"{"decision":"deny","reason":"nope"}"#,
            "",
            0,
            "test",
            Duration::ZERO,
        );
        assert!(matches!(deny, HookRunnerResult::Deny { .. }));

        let (blocked, _) =
            parse_blocking_result(r#"{"decision":"allow"}"#, "", 2, "test", Duration::ZERO);
        assert!(matches!(blocked, HookRunnerResult::Deny { .. }));

        let (ask_blocked, _) = parse_blocking_result(
            r#"{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"confirm"}}"#,
            "",
            2,
            "test",
            Duration::ZERO,
        );
        assert!(matches!(ask_blocked, HookRunnerResult::Deny { .. }));

        let (defer_blocked, _) = parse_blocking_result(
            r#"{"hookSpecificOutput":{"permissionDecision":"defer"}}"#,
            "",
            2,
            "test",
            Duration::ZERO,
        );
        assert!(matches!(defer_blocked, HookRunnerResult::Deny { .. }));
    }

    fn stop_outcome(result: HookRunnerResult) -> StopHookOutcome {
        match result {
            HookRunnerResult::Stop(outcome) => outcome,
            other => panic!("expected Stop outcome, got {other:?}"),
        }
    }

    #[test]
    fn stop_block_decision_with_reason() {
        let (result, _) = parse_stop_result(
            r#"{"decision":"block","reason":"tests are failing"}"#,
            "",
            0,
            "my-stop",
            Duration::ZERO,
        );
        let outcome = stop_outcome(result);
        assert_eq!(
            outcome,
            StopHookOutcome {
                block_reason: Some("tests are failing".into()),
                ..Default::default()
            }
        );

        let (result, _) =
            parse_stop_result(r#"{"decision":"block"}"#, "", 0, "my-stop", Duration::ZERO);
        assert_eq!(
            stop_outcome(result).block_reason.as_deref(),
            Some("Blocked by stop hook 'my-stop'")
        );
    }

    #[test]
    fn stop_exit_2_blocks_with_stderr() {
        let (result, _) =
            parse_stop_result("", "run the test suite first\n", 2, "s", Duration::ZERO);
        assert_eq!(
            stop_outcome(result).block_reason.as_deref(),
            Some("run the test suite first")
        );

        let (result, _) = parse_stop_result("", "", 2, "s", Duration::ZERO);
        assert_eq!(
            stop_outcome(result).block_reason.as_deref(),
            Some("Blocked by stop hook 's' (exit code 2)")
        );
    }

    #[test]
    fn stop_stdout_json_wins_over_exit_2() {
        let (result, _) = parse_stop_result(
            r#"{"continue":false,"stopReason":"enough","hookSpecificOutput":{"additionalContext":"ctx"}}"#,
            "log noise\n",
            2,
            "s",
            Duration::ZERO,
        );
        let outcome = stop_outcome(result);
        assert_eq!(
            outcome
                .force_stop
                .as_ref()
                .and_then(|f| f.reason.as_deref()),
            Some("enough")
        );
        assert_eq!(outcome.additional_context.as_deref(), Some("ctx"));

        let (result, _) = parse_stop_result("log noise\n", "blocked", 2, "s", Duration::ZERO);
        assert_eq!(
            stop_outcome(result).block_reason.as_deref(),
            Some("blocked")
        );
    }

    #[test]
    fn stop_continue_false_prevents_continuation() {
        let (result, _) = parse_stop_result(
            r#"{"continue":false,"stopReason":"budget exhausted"}"#,
            "",
            0,
            "s",
            Duration::ZERO,
        );
        let outcome = stop_outcome(result);
        assert_eq!(
            outcome,
            StopHookOutcome {
                force_stop: Some(crate::result::StopOverride {
                    reason: Some("budget exhausted".into()),
                }),
                ..Default::default()
            }
        );
        let (result, _) = parse_stop_result(r#"{"continue":true}"#, "", 0, "s", Duration::ZERO);
        assert!(stop_outcome(result).is_empty());
    }

    #[test]
    fn stop_allow_failure_and_unknown_decision() {
        let (result, _) = parse_stop_result("", "", 0, "s", Duration::ZERO);
        assert!(stop_outcome(result).is_empty());

        let (result, _) = parse_stop_result("all done!", "", 0, "s", Duration::ZERO);
        assert!(stop_outcome(result).is_empty());

        let (result, _) = parse_stop_result("", "boom", 1, "s", Duration::ZERO);
        match result {
            HookRunnerResult::Failed(error) => assert!(
                error.contains("exit code 1") && error.contains("boom"),
                "stop failure must carry exit code AND stderr text, got: {error}"
            ),
            other => panic!("expected Failed, got {other:?}"),
        }

        let (result, _) = parse_stop_result(r#"{"decision":"deny"}"#, "", 0, "s", Duration::ZERO);
        assert!(matches!(result, HookRunnerResult::Failed(_)));

        let (result, _) =
            parse_stop_result(r#"{"decision":"approve"}"#, "", 0, "s", Duration::ZERO);
        assert!(stop_outcome(result).is_empty());
    }

    fn prompt_block_reason(result: HookRunnerResult) -> String {
        match result {
            HookRunnerResult::Block { reason, .. } => reason,
            other => panic!("expected Block (prompt block), got {other:?}"),
        }
    }

    #[test]
    fn prompt_json_block_honored_on_any_exit_code() {
        for exit_code in [0, 1, 2, 127] {
            let (result, _) = parse_prompt_result(
                r#"{"decision":"block","reason":"policy says no"}"#,
                "",
                exit_code,
                "p",
                Duration::ZERO,
            );
            assert_eq!(
                prompt_block_reason(result),
                "policy says no",
                "exit code {exit_code}"
            );
        }
    }

    #[test]
    fn prompt_json_block_reason_falls_back_to_stderr_then_generic() {
        let (result, _) = parse_prompt_result(
            r#"{"decision":"block"}"#,
            "explained on stderr\n",
            0,
            "p",
            Duration::ZERO,
        );
        assert_eq!(prompt_block_reason(result), "explained on stderr");

        let (result, _) =
            parse_prompt_result(r#"{"decision":"block"}"#, "", 0, "p", Duration::ZERO);
        assert_eq!(prompt_block_reason(result), "Prompt blocked by hook 'p'");
    }

    #[test]
    fn prompt_exit_2_blocks_with_full_multiline_stderr() {
        let (result, _) = parse_prompt_result(
            "",
            "policy violated:\n- no prod deploys on friday\n",
            2,
            "p",
            Duration::ZERO,
        );
        assert_eq!(
            prompt_block_reason(result),
            "policy violated:\n- no prod deploys on friday"
        );

        let (result, _) = parse_prompt_result("", "", 2, "p", Duration::ZERO);
        assert_eq!(
            prompt_block_reason(result),
            "Prompt blocked by hook 'p' (exit code 2)"
        );
    }

    #[test]
    fn prompt_allow_on_exit_0_discards_stdout() {
        for stdout in [
            "",
            "plain context text",
            "{}",
            r#"{"hookSpecificOutput":{"additionalContext":"ctx","sessionTitle":"t"}}"#,
        ] {
            let (result, _) = parse_prompt_result(stdout, "", 0, "p", Duration::ZERO);
            assert!(
                matches!(result, HookRunnerResult::Success),
                "stdout {stdout:?} must allow"
            );
        }
    }

    #[test]
    fn prompt_unknown_decision_is_failure() {
        for stdout in [r#"{"decision":"deny"}"#, r#"{"decision":"allow"}"#] {
            let (result, _) = parse_prompt_result(stdout, "", 0, "p", Duration::ZERO);
            assert!(
                matches!(result, HookRunnerResult::Failed(_)),
                "stdout {stdout:?} must fail so typos surface"
            );
        }
    }

    #[test]
    fn prompt_invalid_decision_json_with_exit_2_blocks() {
        let (result, _) = parse_prompt_result(
            r#"{"decision":"allow"}"#,
            "still blocked",
            2,
            "p",
            Duration::ZERO,
        );
        assert_eq!(prompt_block_reason(result), "still blocked");
    }

    #[test]
    fn prompt_approve_decision_renders_no_verdict() {
        let (result, _) =
            parse_prompt_result(r#"{"decision":"approve"}"#, "", 0, "p", Duration::ZERO);
        assert!(matches!(result, HookRunnerResult::Success));
        let (result, _) = parse_prompt_result(
            r#"{"decision":"approve"}"#,
            "blocked anyway\n",
            2,
            "p",
            Duration::ZERO,
        );
        assert_eq!(prompt_block_reason(result), "blocked anyway");
    }

    #[test]
    fn prompt_other_exit_codes_fail_open() {
        let (result, _) = parse_prompt_result("", "boom\n", 1, "p", Duration::ZERO);
        match result {
            HookRunnerResult::Failed(error) => assert!(
                error.contains("exit code 1") && error.contains("boom"),
                "prompt failure must carry exit code AND stderr text, got: {error}"
            ),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    fn post_tool_use_outcome(result: HookRunnerResult) -> crate::result::PostToolUseHookOutcome {
        match result {
            HookRunnerResult::PostToolUse { outcome, .. } => outcome,
            other => panic!("expected PostToolUse outcome, got {other:?}"),
        }
    }

    #[test]
    fn post_tool_use_exit_2_feeds_stderr() {
        let (result, _) =
            parse_post_tool_use_result("", "lint found 3 issues\n", 2, "p", Duration::ZERO);
        assert_eq!(
            post_tool_use_outcome(result).block_reason.as_deref(),
            Some("lint found 3 issues")
        );
    }

    #[test]
    fn post_tool_use_broken_hook_keeps_only_its_block_reason() {
        let json = serde_json::json!({
            "decision": "block",
            "reason": "tests failed",
            "hookSpecificOutput": {
                "additionalContext": "all tests passed",
                "updatedToolOutput": { "type": "Bash" },
                "updatedMCPToolOutput": "all tests passed",
            },
        })
        .to_string();
        let (result, _) = parse_post_tool_use_result(&json, "boom", 1, "p", Duration::ZERO);
        let HookRunnerResult::PostToolUse { outcome, failure } = result else {
            panic!("a surviving block reason must still be delivered");
        };
        assert_eq!(outcome.block_reason.as_deref(), Some("tests failed"));
        assert_eq!(outcome.additional_context, None);
        assert_eq!(outcome.output_replacement, None);
        let failure = failure.expect("a non-zero exit is recorded even when a field parsed");
        assert!(
            failure.contains("exit code 1") && failure.contains("boom"),
            "failure must carry exit code and stderr, got: {failure}"
        );
    }

    #[test]
    fn truncate_output_respects_limit() {
        assert_eq!(truncate_output(b"hello world"), "hello world");

        let large = truncate_output(&vec![b'x'; MAX_OUTPUT_BYTES + 1000]);
        assert!(large.ends_with(" [truncated]"));
    }

    #[test]
    fn post_tool_use_replacement_at_ceiling_survives_capture_and_parse() {
        let at_ceiling = "x".repeat(MAX_HOOK_OUTPUT_REPLACEMENT_CHARS);
        let document = serde_json::json!({
            "hookSpecificOutput": { "updatedMCPToolOutput": at_ceiling },
        })
        .to_string();

        let captured = truncate_output(document.as_bytes());
        assert!(
            !captured.ends_with(" [truncated]"),
            "a ceiling replacement must fit the capture cap without truncation"
        );
        let (result, _) = parse_post_tool_use_result(&captured, "", 0, "p", Duration::ZERO);
        let outcome = post_tool_use_outcome(result);
        let Some(OutputReplacement {
            kind: ReplacementKind::Mcp,
            value,
            ..
        }) = outcome.output_replacement.as_ref()
        else {
            panic!("the ceiling replacement must survive, not be dropped as an empty success");
        };
        assert_eq!(
            value.as_str().map(str::len),
            Some(MAX_HOOK_OUTPUT_REPLACEMENT_CHARS),
            "the full ceiling-length replacement survives, unclipped"
        );
    }

    #[test]
    fn resolve_command_path_variants() {
        let spec =
            |handler: crate::config::HandlerType, command: Option<&str>, source: &str| HookSpec {
                name: "test".into(),
                event: crate::event::HookEventName::PreToolUse,
                handler_type: handler,
                configured_matcher: None,
                matcher: None,
                enabled: true,
                command: command.map(std::path::PathBuf::from),
                command_raw: command.map(str::to_string),
                args: None,
                shell: None,
                url: None,
                url_raw: None,
                timeout_ms: 5000,
                source_dir: std::path::PathBuf::from(source),
                extra_env: std::collections::HashMap::new(),
                layer: crate::config::HookProvenance::File,
            };
        use crate::config::HandlerType;
        assert_eq!(
            resolve_command_path(&spec(
                HandlerType::Command,
                Some("/usr/bin/hook"),
                "/some/dir"
            )),
            Some(std::path::PathBuf::from("/usr/bin/hook"))
        );
        assert_eq!(
            resolve_command_path(&spec(
                HandlerType::Command,
                Some("bin/check.sh"),
                "/project/.fuigo/hooks"
            )),
            Some(std::path::PathBuf::from(
                "/project/.fuigo/hooks/bin/check.sh"
            ))
        );
        assert_eq!(
            resolve_command_path(&spec(HandlerType::Http, None, "/project")),
            None
        );
    }

    fn make_shell_spec(command: &str) -> HookSpec {
        HookSpec {
            name: "test-hook".into(),
            event: crate::event::HookEventName::Stop,
            handler_type: crate::config::HandlerType::Command,
            configured_matcher: None,
            matcher: None,
            enabled: true,
            command: Some(command.into()),
            command_raw: Some(command.to_string()),
            args: None,
            shell: None,
            url: None,
            url_raw: None,
            timeout_ms: 5000,
            source_dir: std::env::temp_dir(),
            extra_env: std::collections::HashMap::new(),
            layer: crate::config::HookProvenance::File,
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn t05_mcp_hook_lsp_spawn_paths_hook() {
        const NAME: &str = "t05_mcp_hook_lsp_spawn_paths_hook";
        if std::env::var("T05_CHILD_TEST").as_deref() != Ok(NAME) {
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.arg(NAME)
                .arg("--test-threads=1")
                .env("T05_CHILD_TEST", NAME)
                .env("OPENAI_API_KEY", "fake-ambient")
                .env("ANTHROPIC_API_KEY", "fake-ambient");
            assert!(cmd.output().unwrap().status.success());
            return;
        }
        for selected in [false, true] {
            let check = if selected {
                "test \"$OPENAI_API_KEY\" = fake-selected"
            } else {
                "test -z \"${OPENAI_API_KEY+x}\""
            };
            let mut spec = make_shell_spec(&format!(
                "{check} && test -z \"${{ANTHROPIC_API_KEY+x}}\" && /bin/sh -c '{check} && test -z \"${{ANTHROPIC_API_KEY+x}}\"'"
            ));
            if selected {
                spec.extra_env
                    .insert("OPENAI_API_KEY".into(), "fake-selected".into());
            }
            let result = run_command_hook(&spec, &make_envelope(), &make_ctx(), GateKind::Observe)
                .await
                .0;
            assert!(matches!(result, HookRunnerResult::Success));
        }
    }

    /// P86 (CB-1), hooks: the credentials sit in the agent's OWN environment (a fresh test process
    /// whose env holds them; the names are literal so an emptied denylist cannot empty the test);
    /// the hook and its child must not see them, `P86_BENIGN` proves the parent env does reach the
    /// hook, and a key the user wrote into the hook's `env` still arrives.
    #[cfg(unix)]
    #[tokio::test]
    async fn p86_hooks_never_see_parent_credentials() {
        const NAME: &str = "p86_hooks_never_see_parent_credentials";
        if std::env::var("P86_CHILD_TEST").as_deref() != Ok(NAME) {
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.arg(NAME)
                .args(["--test-threads=1", "--nocapture"])
                .env("P86_CHILD_TEST", NAME)
                .env("P86_BENIGN", "kept");
            for name in [
                "FLUX_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
                "FUIGO_API_KEY",
                "OPENAI_API_KEY",
                "P86_CORP_KEY",
            ] {
                cmd.env(name, "fake-p86-ambient");
            }
            let output = cmd.output().unwrap();
            let stdout = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .replace("fake-p86-", "[redacted]-");
            assert!(
                output.status.success(),
                "isolated P86 hook probe failed: {stdout}"
            );
            assert!(stdout.contains("test result: ok. 1 passed"), "{stdout}");
            return;
        }
        // What the config loader does with a user's `env_key = "P86_CORP_KEY"`.
        fuigo_tools::util::shell_env_policy::register_credential_env_names(["P86_CORP_KEY"]);
        for selected in [false, true] {
            let flux = if selected {
                "test \"$FLUX_API_KEY\" = fake-p86-selected"
            } else {
                "test -z \"${FLUX_API_KEY+x}\""
            };
            let check = format!(
                "test \"$P86_BENIGN\" = kept && {flux} && test -z \"${{ANTHROPIC_AUTH_TOKEN+x}}${{FUIGO_API_KEY+x}}${{OPENAI_API_KEY+x}}${{P86_CORP_KEY+x}}\""
            );
            // The probe runs from a script file, not from the hook's command: a hook whose own config names
            // `FUIGO_API_KEY` is given the key on purpose (P70a), and this test is about inheritance.
            let dir = tempfile::tempdir().expect("tempdir");
            let script = dir.path().join("p86-probe.sh");
            std::fs::write(&script, format!("{check} && /bin/sh -c '{check}'\n")).expect("write probe");
            let mut spec = make_shell_spec(&format!("/bin/sh '{}'", script.display()));
            if selected {
                spec.extra_env
                    .insert("FLUX_API_KEY".into(), "fake-p86-selected".into());
            }
            let result = run_command_hook(&spec, &make_envelope(), &make_ctx(), GateKind::Observe)
                .await
                .0;
            assert!(
                matches!(result, HookRunnerResult::Success),
                "selected={selected}: {result:?}"
            );
        }
    }

    /// P70a follow-up: the agent no longer holds the user's saved API key in its environment, and every hook child has
    /// `FUIGO_API_KEY` stripped by name. A hook whose config names the key explicitly still gets it, through the
    /// installed credential resolver, in its own child environment only: (1) `$FUIGO_API_KEY` in its command, (2)
    /// `${FUIGO_API_KEY}` inside a value of its `env` map. (3) A script that reads `$FUIGO_API_KEY` from its inherited
    /// environment, with nothing in the hook's config naming it, gets nothing. The key is never written to this
    /// process's environment (`std::env::vars`, and `/proc/self/environ` on Linux).
    #[cfg(unix)]
    #[tokio::test]
    async fn p70a_first_party_key_reaches_a_hook_only_when_its_config_names_it() {
        const KEY: &str = crate::test_support::P70A_TEST_KEY;
        crate::test_support::install_p70a_key_resolver();
        let dir = tempfile::tempdir().expect("tempdir");
        let out = |name: &str| dir.path().join(name);
        let script = out("reads-inherited.sh");
        std::fs::write(
            &script,
            format!("printf '%s' \"${{FUIGO_API_KEY-unset}}\" > '{}'\n", out("implicit").display()),
        )
        .expect("write script");

        let explicit = make_shell_spec(&format!(
            "printf '%s' \"$FUIGO_API_KEY\" > '{}'",
            out("explicit").display()
        ));
        let mut via_env = make_shell_spec(&format!(
            "printf '%s' \"$P70A_TOKEN\" > '{}'",
            out("via-env").display()
        ));
        via_env
            .extra_env
            .insert("P70A_TOKEN".into(), "Bearer ${FUIGO_API_KEY}".into());
        let implicit = make_shell_spec(&format!("/bin/sh '{}'", script.display()));
        // Astra f1 #3: a reference nested in another variable's default still names the key.
        let nested = make_shell_spec(&format!(
            "printf '%s' \"${{P70A_UNSET_OVERRIDE:-$FUIGO_API_KEY}}\" > '{}'",
            out("nested").display()
        ));

        for (label, spec) in [("explicit", &explicit), ("via-env", &via_env), ("implicit", &implicit), ("nested", &nested)] {
            let result = run_command_hook(spec, &make_envelope(), &make_ctx(), GateKind::Observe)
                .await
                .0;
            assert!(matches!(result, HookRunnerResult::Success), "{label}: {result:?}");
        }
        let read = |name: &str| std::fs::read_to_string(out(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(read("explicit"), KEY, "a hook whose command names $FUIGO_API_KEY gets the key");
        assert_eq!(read("via-env"), format!("Bearer {KEY}"), "a hook env value naming ${{FUIGO_API_KEY}} gets the key");
        assert_eq!(read("implicit"), "unset", "a script reading an inherited FUIGO_API_KEY got it");
        assert_eq!(read("nested"), KEY, "a reference nested in a default did not get the key");
        assert!(
            !std::env::vars().any(|(_, v)| v.contains(KEY)),
            "the key entered this process's environment"
        );
        #[cfg(target_os = "linux")]
        {
            let environ = std::fs::read("/proc/self/environ").expect("/proc/self/environ");
            assert!(
                !String::from_utf8_lossy(&environ).contains(KEY),
                "the key is in /proc/self/environ"
            );
        }
    }

    /// P70a follow-up (Astra f5), through the PRODUCTION parser (`parse_hook_file`) and runner: (1) a command naming
    /// the key directly and, escaped, `$${FUIGO_API_KEY}` gets the key for the first only (the shell reads the kept
    /// `$$` as its PID); (2) an alias `$TOKEN` with `env = { TOKEN = "${FUIGO_API_KEY}" }` gets it (parsing substitutes
    /// the alias); (3) an alias whose value is the escaped form gets nothing.
    #[cfg(unix)]
    #[tokio::test]
    async fn p70a_parsed_hooks_resolve_plain_references_and_keep_escaped_ones() {
        const KEY: &str = crate::test_support::P70A_TEST_KEY;
        crate::test_support::install_p70a_key_resolver();
        let dir = tempfile::tempdir().expect("tempdir");
        let out = |name: &str| dir.path().join(name).display().to_string();
        let hook = |command: String, env: serde_json::Value| {
            serde_json::json!({ "type": "command", "command": command, "env": env })
        };
        let json = serde_json::json!({ "hooks": { "Stop": [ { "hooks": [
            hook(format!("printf '%s|%s' \"$FUIGO_API_KEY\" \"$${{FUIGO_API_KEY}}\" > '{}'", out("mixed")), serde_json::json!({})),
            hook(format!("printf '%s' \"$TOKEN\" > '{}'", out("alias")), serde_json::json!({ "TOKEN": "${FUIGO_API_KEY}" })),
            hook(format!("printf '%s' \"$TOKEN2\" > '{}'", out("escaped-alias")), serde_json::json!({ "TOKEN2": "$${FUIGO_API_KEY}" })),
            // Astra f6 #1: an escaped modifier form.
            hook(format!("printf '%s' \"$${{FUIGO_API_KEY:-fallback}}\" > '{}'", out("escaped-modifier")), serde_json::json!({})),
            // Astra f7 #1: an expanded value holding private-use characters next to an escaped reference.
            hook(
                format!("printf '%s|%s' \"$ALIAS\" \"$${{FUIGO_API_KEY}}\" > '{}'", out("pua-alias")),
                serde_json::json!({ "ALIAS": "\u{e000}{FUIGO_API_KEY}" }),
            ),
            // Astra f7 #2: an odd run is `$` (the PID, for a shell) and a reference: the hook names the key.
            hook(format!("printf '%s' \"$$${{FUIGO_API_KEY}}\" > '{}'", out("odd-run")), serde_json::json!({})),
        ] } ] } })
        .to_string();
        let (specs, errors) = crate::config::parse_hook_file_with_key_naming(&json, std::path::Path::new("/tmp/p70a-hooks.json"), true);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(specs.len(), 6);
        for spec in &specs {
            let result = run_command_hook(spec, &make_envelope(), &make_ctx(), GateKind::Observe).await.0;
            assert!(matches!(result, HookRunnerResult::Success), "{}: {result:?}", spec.name);
        }
        let read = |name: &str| std::fs::read_to_string(out(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let mixed = read("mixed");
        let (plain, escaped) = mixed.split_once('|').expect("two fields");
        assert_eq!(plain, KEY, "the plain reference did not get the key");
        assert!(!escaped.contains(KEY) && escaped.ends_with("{FUIGO_API_KEY}"), "the escaped one: {escaped:?}");
        assert_eq!(read("alias"), KEY, "an alias naming the key did not get it");
        assert!(!read("escaped-alias").contains(KEY), "an alias holding the escaped form got the key");
        let modifier = read("escaped-modifier");
        assert!(!modifier.contains(KEY) && modifier.ends_with("{FUIGO_API_KEY:-fallback}"), "{modifier:?}");
        let pua = read("pua-alias");
        assert!(!pua.contains(KEY) && pua.starts_with("\u{e000}{FUIGO_API_KEY}|"), "{pua:?}");
        assert!(read("odd-run").ends_with(KEY), "an odd run is a reference the hook named");
    }

    fn make_envelope() -> HookEventEnvelope {
        use crate::event::HookPayload;
        HookEventEnvelope {
            hook_event_name: crate::event::HookEventName::Stop,
            session_id: "test-session".into(),
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

    fn make_ctx() -> RunContext<'static> {
        RunContext {
            session_id: "test-session",
            workspace_root: "/tmp",
            process_scope: None,
        }
    }

    fn make_scoped_ctx(scope: fuigo_tools::util::ProcessScope) -> RunContext<'static> {
        RunContext {
            process_scope: Some(scope),
            ..make_ctx()
        }
    }

    /// P189 packet C: a hook child (and its descendants) is placed in the
    /// session cgroup. Skips unless a usable cgroup2 (a skip fails under
    /// `FUIGO_TEST_REQUIRE_CGROUP=1`).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn hook_child_is_in_the_session_cgroup() {
        use fuigo_tools::util::session_cgroup::{ProbeEnv, probe_with};
        let host = match probe_with(&ProbeEnv::system()) {
            Ok(h) => h,
            Err(r) => {
                println!("P189-CGROUP-SKIP {r} (hook)");
                assert!(std::env::var("FUIGO_TEST_REQUIRE_CGROUP").as_deref() != Ok("1"), "cgroup required: {r}");
                return;
            }
        };
        println!("P189-CGROUP-RAN hook");
        let scope = fuigo_tools::util::ProcessScope::with_session_cgroup(host.create_session().unwrap());
        let want = scope
            .session_cgroup()
            .unwrap()
            .dir()
            .strip_prefix("/sys/fs/cgroup")
            .unwrap()
            .to_string_lossy()
            .to_string();
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("cg");
        let spec = make_shell_spec(&format!("cat /proc/self/cgroup > {}", out.display()));
        let (result, _, _) =
            run_command_hook(&spec, &make_envelope(), &make_scoped_ctx(scope.clone()), GateKind::Observe).await;
        assert!(matches!(result, HookRunnerResult::Success), "{result:?}");
        let seen = std::fs::read_to_string(&out).unwrap();
        assert!(seen.contains(&want), "hook child not in session cgroup: {seen}");
        scope.release_session_cgroup();
    }

    /// Guard: the hook child is spawned through the placement entry, with the
    /// placement registered before any other `pre_exec`.
    #[test]
    fn hook_spawn_goes_through_spawn_placed_with_placement_first() {
        let src = include_str!("command.rs");
        let prod = &src[..src.find("\n#[cfg(test)]\nmod tests").unwrap()];
        assert!(!prod.contains(".spawn()"), "raw `.spawn()` in the hooks runner; use ProcessScope::spawn_placed");
        // Placement is registered by `spawn_placed` right after `new_command`, so the
        // configure closure must hold no placement or pre_exec call of its own.
        assert!(!prod.contains("hook.place("), "placement is registered by spawn_placed itself");
        assert!(prod.contains("spawn_placed(") && prod.contains("|| tokio::process::Command::new(&program)"));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn hook_times_out() {
        let mut spec = make_shell_spec("sleep 5");
        spec.timeout_ms = 100;
        let envelope = make_envelope();
        let ctx = make_ctx();
        let (result, _, _) = run_command_hook(&spec, &envelope, &ctx, GateKind::Observe).await;
        assert!(
            matches!(&result, HookRunnerResult::Failed(msg) if msg.contains("timed out")),
            "expected a timeout failure, got {result:?}"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn large_envelope_with_unreading_hook_does_not_deadlock() {
        use crate::event::HookPayload;
        let spec = make_shell_spec("head -c 200000 /dev/zero | tr '\\0' x");
        let mut envelope = make_envelope();
        envelope.payload = HookPayload::Stop {
            reason: "test".into(),
            stop_hook_active: false,
            last_assistant_message: Some("x".repeat(256 * 1024)),
            background_tasks: None,
            session_crons: None,
        };
        let ctx = make_ctx();
        let run = run_command_hook(&spec, &envelope, &ctx, GateKind::Observe);
        let (result, _, _) = tokio::time::timeout(std::time::Duration::from_secs(10), run)
            .await
            .expect("hook must not deadlock on a large envelope");
        assert!(matches!(result, HookRunnerResult::Success));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn hook_child_cannot_open_dev_tty() {
        if std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .is_err()
        {
            eprintln!("skipping: no controlling terminal");
            return;
        }

        let spec = make_shell_spec("exec 3>/dev/tty 2>/dev/null && exit 1 || exit 0");
        let envelope = make_envelope();
        let ctx = make_ctx();

        let (result, _duration, _) =
            run_command_hook(&spec, &envelope, &ctx, GateKind::Observe).await;

        assert!(
            matches!(result, HookRunnerResult::Success),
            "hook child should not be able to open /dev/tty after setsid(), got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn project_dir_env_is_exported_to_the_child() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("hook.sh");
        let workspace = tmp.path().to_string_lossy().into_owned();
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ntest \"${{CLAUDE_PROJECT_DIR}}\" = \"{workspace}\"\n",
                workspace = workspace
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).unwrap();
        }

        let mut spec = make_shell_spec("${CLAUDE_PROJECT_DIR}/hook.sh");
        spec.source_dir = tmp.path().to_path_buf();

        let envelope = make_envelope();
        let ctx = RunContext {
            session_id: "test-session",
            workspace_root: &workspace,
            process_scope: None,
        };
        let (result, _, _) = run_command_hook(&spec, &envelope, &ctx, GateKind::Observe).await;

        assert!(
            matches!(result, HookRunnerResult::Success),
            "hook should see CLAUDE_PROJECT_DIR set to the workspace root, got {:?}",
            result
        );
    }

    #[test]
    fn powershell_rewrite_cases() {
        let mut extra = std::collections::HashMap::new();
        extra.insert("PLUGIN_ROOT".to_string(), "/unused".to_string());
        let cases = [
            (
                r#"powershell -File "$CLAUDE_PROJECT_DIR/.claude/hooks/foo.ps1" ${PLUGIN_ROOT}"#,
                r#"powershell -File "$env:CLAUDE_PROJECT_DIR/.claude/hooks/foo.ps1" "${env:PLUGIN_ROOT}""#,
            ),
            (
                r#"$UNKNOWN ${CLAUDE_PROJECT_DIR:-.}/x bash -c '$CLAUDE_PROJECT_DIR/x.sh' `$CLAUDE_PROJECT_DIR"#,
                r#"$UNKNOWN ${CLAUDE_PROJECT_DIR:-.}/x bash -c '$CLAUDE_PROJECT_DIR/x.sh' `$CLAUDE_PROJECT_DIR"#,
            ),
            (
                "$CLAUDE_PROJECT_DIR/.claude/hooks/foo.ps1",
                r#"& "$env:CLAUDE_PROJECT_DIR/.claude/hooks/foo.ps1""#,
            ),
            (
                "$CLAUDE_PROJECT_DIR/.claude/hooks/foo.ps1; echo done",
                r#"& "$env:CLAUDE_PROJECT_DIR/.claude/hooks/foo.ps1"; echo done"#,
            ),
            (
                r#""$CLAUDE_PROJECT_DIR/.claude/hooks/foo.ps1""#,
                r#"& "$env:CLAUDE_PROJECT_DIR/.claude/hooks/foo.ps1""#,
            ),
            (
                r#"powershell -File $CLAUDE_PROJECT_DIR/.claude/hooks/foo.ps1"#,
                r#"powershell -File "$env:CLAUDE_PROJECT_DIR/.claude/hooks/foo.ps1""#,
            ),
            (
                "$CLAUDE_PROJECT_DIR/$FUIGO_HOOK_NAME.ps1",
                r#"& "$env:CLAUDE_PROJECT_DIR/$env:FUIGO_HOOK_NAME.ps1""#,
            ),
            (
                "Join-Path ($CLAUDE_PROJECT_DIR) hooks",
                r#"Join-Path ("$env:CLAUDE_PROJECT_DIR") hooks"#,
            ),
            (
                r#"Write-Host "don't skip $CLAUDE_PROJECT_DIR""#,
                r#"Write-Host "don't skip $env:CLAUDE_PROJECT_DIR""#,
            ),
        ];
        for (input, want) in cases {
            assert_eq!(
                rewrite_posix_env_refs_for_powershell(input, &extra).as_ref(),
                want,
                "{input}"
            );
        }
    }

    #[test]
    fn find_unresolved_detects_and_dedups() {
        let mut env = std::collections::HashMap::new();
        env.insert("KNOWN".to_string(), "x".to_string());
        assert_eq!(
            find_unresolved_env_vars("${KNOWN}/${CLAUDE_PLUGIN_DATA}/foo", &env),
            vec!["CLAUDE_PLUGIN_DATA".to_string()]
        );
        assert_eq!(
            find_unresolved_env_vars("$FUIGO_PLUGIN_DATA/foo", &env),
            vec!["FUIGO_PLUGIN_DATA".to_string()]
        );
        assert_eq!(
            find_unresolved_env_vars(
                "${CLAUDE_CONFIG_DIR} && ${CLAUDE_CONFIG_DIR}/foo $CLAUDE_CONFIG_DIR",
                &env,
            ),
            vec!["CLAUDE_CONFIG_DIR".to_string()]
        );
    }

    /// 1.0.32 HOOKS-COMPAT: a `${NAME}` that is not one of Fuigo's placeholders is the script's own (a loop variable,
    /// an assignment inside a `case`), and must never stop the hook from running.
    #[test]
    fn find_unresolved_leaves_the_scripts_own_variables_to_the_shell() {
        let env = std::collections::HashMap::new();
        for cmd in [
            r#"for _V in a b; do [ -e "${_V}.orphaned_at" ] && continue; done"#,
            r#"case "$x" in (*-*) _G=0;; (*) _G=1;; esac; echo "${_G}""#,
            "echo ${SOME_GB1183_UNSET_VAR} $SOME_GB1183_BARE_UNSET",
        ] {
            let v = find_unresolved_env_vars(cmd, &env);
            assert!(v.is_empty(), "`{cmd}` is the script's own, got {v:?}");
        }
        assert_eq!(
            find_unresolved_env_vars("${_V} ${CLAUDE_PLUGIN_ROOT}", &env),
            vec!["CLAUDE_PLUGIN_ROOT".to_string()],
            "a placeholder Fuigo is meant to provide is still checked"
        );
    }

    #[test]
    fn find_unresolved_skips_resolvable_vars() {
        let mut env = std::collections::HashMap::new();
        env.insert("CLAUDE_PLUGIN_ROOT".to_string(), "/plugins/foo".to_string());
        let v = find_unresolved_env_vars(
            "${FUIGO_HOOK_EVENT}/${CLAUDE_PROJECT_DIR}/${FUIGO_SESSION_ID}/${CLAUDE_PLUGIN_ROOT}/foo",
            &env,
        );
        assert!(
            v.is_empty(),
            "resolvable vars should not be flagged, got {v:?}"
        );
    }

    #[test]
    fn find_unresolved_skips_non_var_dollars() {
        let env = std::collections::HashMap::new();
        let v = find_unresolved_env_vars("echo $1 $$ $? $# $(date)", &env);
        assert!(
            v.is_empty(),
            "shell special params should not be flagged, got {v:?}"
        );
    }

    #[test]
    fn find_unresolved_skips_local_assignments() {
        let env = std::collections::HashMap::new();
        for cmd in [
            r#"INPUT=$(cat); echo "$INPUT" | grep -q foo"#,
            "read -r LINE; echo $LINE",
            "echo first; X=hello && echo $X | cat",
        ] {
            let v = find_unresolved_env_vars(cmd, &env);
            assert!(v.is_empty(), "`{cmd}` should not flag any var, got {v:?}");
        }
    }

    #[test]
    fn find_unresolved_skips_parameter_expansion_modifiers() {
        let env = std::collections::HashMap::new();
        let cases = [
            "${CLAUDE_PLUGIN_DATA:-/default/path.sh}",
            "${CLAUDE_PLUGIN_DATA-/default/path.sh}",
            "${CLAUDE_PLUGIN_DATA:=/assigned/path.sh}",
            "${CLAUDE_PLUGIN_DATA:?msg here}",
            "${CLAUDE_PLUGIN_DATA:+/used/if/set.sh}",
            "${CLAUDE_PLUGIN_DATA%.sh}",
            "${CLAUDE_PLUGIN_DATA#prefix/}",
            "${CLAUDE_PLUGIN_DATA/foo/bar}",
            "${CLAUDE_PLUGIN_DATA:0:5}",
        ];
        for case in cases {
            let v = find_unresolved_env_vars(case, &env);
            assert!(
                v.is_empty(),
                "parameter-expansion form `{case}` should not be flagged, got {v:?}"
            );
        }
    }

    #[tokio::test]
    async fn undefined_env_var_refuses_to_spawn() {
        let mut extra_env = std::collections::HashMap::new();
        extra_env.insert("UNRELATED_GB1183".to_string(), "/tmp".to_string());

        let spec = HookSpec {
            name: "test-undef".into(),
            event: crate::event::HookEventName::Stop,
            handler_type: crate::config::HandlerType::Command,
            configured_matcher: None,
            matcher: None,
            enabled: true,
            command: Some(std::path::PathBuf::from(
                "${CLAUDE_PLUGIN_ROOT}/does/not/exist.sh",
            )),
            command_raw: Some("${CLAUDE_PLUGIN_ROOT}/does/not/exist.sh".to_string()),
            args: None,
            shell: None,
            url: None,
            url_raw: None,
            timeout_ms: 5000,
            source_dir: std::env::temp_dir(),
            extra_env,
            layer: crate::config::HookProvenance::File,
        };

        let envelope = make_envelope();
        let ctx = make_ctx();
        let (result, _, _) = run_command_hook(&spec, &envelope, &ctx, GateKind::Observe).await;

        match result {
            HookRunnerResult::Failed(reason) => {
                assert!(
                    reason.contains("CLAUDE_PLUGIN_ROOT"),
                    "failure reason should name the undefined env var, got: {reason}"
                );
                assert!(
                    reason.contains("hook not executed"),
                    "failure reason should make clear the hook did not run, got: {reason}"
                );
                assert!(
                    !reason.contains("exit code"),
                    "failure reason should not reference an exit code (we never spawned), got: {reason}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn tilde_expansion_runs_via_shell() {
        let tmp = tempfile::tempdir().unwrap();
        let hook_dir = tmp.path().join(".fuigo-test-hooks-gb856");
        std::fs::create_dir_all(&hook_dir).unwrap();
        let script = hook_dir.join("tilde-test.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).unwrap();
        }

        let mut extra_env = std::collections::HashMap::new();
        extra_env.insert(
            "HOME".to_string(),
            tmp.path().to_string_lossy().into_owned(),
        );

        let mut spec = make_shell_spec("~/.fuigo-test-hooks-gb856/tilde-test.sh");
        spec.extra_env = extra_env;

        let envelope = make_envelope();
        let ctx = make_ctx();

        let mut result = run_command_hook(&spec, &envelope, &ctx, GateKind::Observe)
            .await
            .0;
        for _ in 0..8 {
            if !matches!(&result, HookRunnerResult::Failed(msg) if msg.starts_with("exit code 126"))
            {
                break;
            }
            result = run_command_hook(&spec, &envelope, &ctx, GateKind::Observe)
                .await
                .0;
        }

        assert!(
            matches!(result, HookRunnerResult::Success),
            "hook with ~/... path should be expanded via sh -c, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn parameter_expansion_default_is_not_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("default.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).unwrap();
        }

        let mut spec = make_shell_spec(&format!(
            "${{MISSING_GB1183_DEFAULT:-{}}}",
            script.display()
        ));
        spec.source_dir = tmp.path().to_path_buf();

        let envelope = make_envelope();
        let ctx = make_ctx();
        let (result, _, _) = run_command_hook(&spec, &envelope, &ctx, GateKind::Observe).await;

        assert!(
            matches!(result, HookRunnerResult::Success),
            "hook with parameter-expansion default must run, got {:?}",
            result
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_hook_session_close_reaps_whole_group() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("grandchild_alive");
        let mut spec = make_shell_spec(&format!(
            "sh -c 'sleep 2 && echo alive > {}' & wait",
            marker.display()
        ));
        spec.timeout_ms = 60_000;
        let envelope = make_envelope();
        let scope = fuigo_tools::util::ProcessScope::new();
        let hook_scope = scope.clone();
        let hook = tokio::spawn(async move {
            run_command_hook(
                &spec,
                &envelope,
                &make_scoped_ctx(hook_scope),
                GateKind::Observe,
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(800)).await;
        scope.kill_all();

        tokio::time::timeout(Duration::from_secs(15), hook)
            .await
            .expect("kill_all must reap the enrolled hook, not leave it on its 60s timeout")
            .expect("hook task join");

        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            !marker.exists(),
            "grandchild outlived session close, so the group was not killpg'd"
        );
    }

    /// Cancellation, not session close: the deferred `SessionStart` path drops a running hook's
    /// future at session end. `kill_on_drop` reaches only the direct child, so without a
    /// killpg-on-drop guard a hook that backgrounded a grandchild leaks it past the session.
    #[cfg(unix)]
    #[tokio::test]
    async fn command_hook_cancelled_mid_run_reaps_whole_group() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("grandchild_alive");
        let started = tmp.path().join("started");
        let mut spec = make_shell_spec(&format!(
            "sh -c 'sleep 3 && echo alive > {}' & touch {}; wait",
            marker.display(),
            started.display()
        ));
        spec.timeout_ms = 60_000;
        let envelope = make_envelope();
        let scope = fuigo_tools::util::ProcessScope::new();
        let ctx = make_scoped_ctx(scope);
        {
            let hook = run_command_hook(&spec, &envelope, &ctx, GateKind::Observe);
            tokio::pin!(hook);
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut hook => panic!("the hook must still be running when it is cancelled"),
                        _ = tokio::time::sleep(Duration::from_millis(20)) => {}
                    }
                    if started.exists() {
                        return;
                    }
                }
            })
            .await
            .expect("the hook must reach its backgrounded grandchild before being cancelled");
            // Dropping `hook` here is the cancel path.
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(
            !marker.exists(),
            "grandchild outlived the cancelled hook, so its group was not killpg'd"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_hook_fails_fast_when_scope_already_closed() {
        let scope = fuigo_tools::util::ProcessScope::new();
        scope.kill_all();
        let mut spec = make_shell_spec("sleep 600");
        spec.timeout_ms = 60_000;

        let (result, _, _) = tokio::time::timeout(
            Duration::from_secs(15),
            run_command_hook(
                &spec,
                &make_envelope(),
                &make_scoped_ctx(scope),
                GateKind::Observe,
            ),
        )
        .await
        .expect("a closed scope must fail the hook immediately, not run to its 60s timeout");

        assert!(
            matches!(result, HookRunnerResult::Failed(_)),
            "got {result:?}"
        );
    }

    // ---- Windows program resolution, driven by injected PATH / PATHEXT layouts so it runs on every host ----

    fn fake_fs(files: &[&str]) -> impl Fn(&std::path::Path) -> bool {
        let set: std::collections::HashSet<std::path::PathBuf> = files.iter().map(std::path::PathBuf::from).collect();
        move |p| set.contains(p)
    }

    fn path_of(dirs: &[&str]) -> std::ffi::OsString {
        std::env::join_paths(dirs).expect("test PATH")
    }

    fn exts(pathext: Option<&str>) -> Vec<String> {
        spawnable_pathext(pathext)
    }

    const SYS32: &str = "/c/Windows/System32";
    const PS_DIR: &str = "/c/Windows/System32/WindowsPowerShell/v1.0";

    #[test]
    fn named_shell_powershell_and_cmd_resolve_from_system32() {
        let fs = fake_fs(&["/c/Windows/System32/cmd.exe", "/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"]);
        let path = path_of(&[SYS32, PS_DIR]);
        assert_eq!(
            resolve_named_shell_in("cmd", &path, &fs),
            Some(std::path::PathBuf::from("/c/Windows/System32/cmd.exe"))
        );
        assert_eq!(
            resolve_named_shell_in("powershell", &path, &fs),
            Some(std::path::PathBuf::from("/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"))
        );
    }

    #[test]
    fn named_shell_bash_in_system32_or_windowsapps_is_rejected() {
        let fs = fake_fs(&[
            "/c/Windows/System32/bash.exe",
            "/c/Users/u/AppData/Local/Microsoft/WindowsApps/bash.exe",
            "/c/Git/bin/bash.exe",
        ]);
        // Only the WSL launcher / Store stub on PATH: no bash.
        let launcher_only = path_of(&[SYS32, "/c/Users/u/AppData/Local/Microsoft/WindowsApps"]);
        assert_eq!(resolve_named_shell_in("bash", &launcher_only, &fs), None);
        assert_eq!(resolve_named_shell_in("BASH", &launcher_only, &fs), None);
        assert_eq!(resolve_named_shell_in("bash.exe", &launcher_only, &fs), None);
        // A real bash later on PATH still wins.
        let with_git = path_of(&[SYS32, "/c/Git/bin"]);
        assert_eq!(
            resolve_named_shell_in("bash", &with_git, &fs),
            Some(std::path::PathBuf::from("/c/Git/bin/bash.exe"))
        );
    }

    #[test]
    fn named_shell_pwsh_resolves_wherever_it_is() {
        let fs = fake_fs(&[
            "/c/Program Files/PowerShell/7/pwsh.exe",
            "/c/Users/u/AppData/Local/Microsoft/WindowsApps/pwsh.exe",
        ]);
        assert_eq!(
            resolve_named_shell_in("pwsh", &path_of(&["/c/Program Files/PowerShell/7"]), &fs),
            Some(std::path::PathBuf::from("/c/Program Files/PowerShell/7/pwsh.exe"))
        );
        assert_eq!(
            resolve_named_shell_in("pwsh", &path_of(&["/c/Users/u/AppData/Local/Microsoft/WindowsApps"]), &fs),
            Some(std::path::PathBuf::from("/c/Users/u/AppData/Local/Microsoft/WindowsApps/pwsh.exe"))
        );
    }

    #[test]
    fn pathext_keeps_spawnable_extensions_in_order() {
        let all = |v: Vec<String>| v.join(",");
        assert_eq!(all(exts(Some(".COM;.EXE;.BAT;.CMD;.VBS;.JS;.MSC"))), ".com,.exe,.bat,.cmd");
        assert_eq!(all(exts(Some(".CMD;.EXE"))), ".cmd,.exe");
        assert_eq!(all(exts(Some(".exe;;.EXE; .bat "))), ".exe,.bat");
        // Unset, empty or nothing spawnable: the Windows default.
        assert_eq!(all(exts(None)), ".com,.exe,.bat,.cmd");
        assert_eq!(all(exts(Some(""))), ".com,.exe,.bat,.cmd");
        assert_eq!(all(exts(Some(".VBS;.JS"))), ".com,.exe,.bat,.cmd");
    }

    #[test]
    fn bare_name_resolves_through_pathext() {
        let fs = fake_fs(&["/n/node.exe"]);
        let path = path_of(&["/x", "/n"]);
        let e = exts(None);
        assert_eq!(find_in_dirs("node", &path, &e, &fs), Some(std::path::PathBuf::from("/n/node.exe")));
        // Already carries an extension: tried as written.
        assert_eq!(find_in_dirs("node.exe", &path, &e, &fs), Some(std::path::PathBuf::from("/n/node.exe")));
        assert_eq!(find_in_dirs("node.EXE", &path, &e, &fake_fs(&["/n/node.EXE"])), Some(std::path::PathBuf::from("/n/node.EXE")));
        // POSIX (no extensions): the name is taken literally.
        assert_eq!(find_in_dirs("node", &path, &[], &fs), None);
        // An empty PATH entry is never the current directory.
        assert_eq!(find_in_dirs("node", &path_of(&[""]), &e, &fake_fs(&["node.exe"])), None);
    }

    #[test]
    fn pathext_order_and_directory_order_decide_the_winner() {
        let both = fake_fs(&["/n/node.cmd", "/n/node.exe"]);
        let path = path_of(&["/n"]);
        assert_eq!(
            find_in_dirs("node", &path, &exts(Some(".CMD;.EXE")), &both),
            Some(std::path::PathBuf::from("/n/node.cmd"))
        );
        assert_eq!(find_in_dirs("node", &path, &exts(None), &both), Some(std::path::PathBuf::from("/n/node.exe")));
        // Directory by directory: an earlier directory's .cmd beats a later directory's .exe.
        let split = fake_fs(&["/a/node.cmd", "/b/node.exe"]);
        assert_eq!(
            find_in_dirs("node", &path_of(&["/a", "/b"]), &exts(None), &split),
            Some(std::path::PathBuf::from("/a/node.cmd"))
        );
    }

    #[test]
    fn cmd_shim_resolves_and_is_spawned_directly_with_literal_args() {
        // npm-style shim: only `npm.cmd` exists, and a bare `npm` finds it.
        let fs = fake_fs(&["/nodejs/npm.cmd", "/nodejs/npm"]);
        assert_eq!(
            find_in_dirs("npm", &path_of(&["/nodejs"]), &exts(None), &fs),
            Some(std::path::PathBuf::from("/nodejs/npm.cmd"))
        );
        // The plan runs the shim as the program with each argument kept as one literal argument: nothing is spliced into a
        // shell string by Fuigo (on Windows the standard library starts a .cmd through cmd.exe with its own quoting, and
        // refuses an argument it cannot quote safely).
        let dir = tempfile::tempdir().expect("tempdir");
        let shim = dir.path().join("npm.cmd");
        std::fs::write(&shim, "@echo off\r\n").expect("write shim");
        let mut spec = make_shell_spec(&shim.to_string_lossy());
        spec.args = Some(vec!["install".into(), "a b&c".into(), "%PATH%".into()]);
        let inputs = PlanInputs { workspace_root: "/w", session_id: "s", event: "Stop" };
        let plan = plan_command(&spec, &shim.to_string_lossy(), &std::collections::HashMap::new(), &inputs)
            .expect("plan");
        assert!(!plan.shell);
        assert_eq!(std::path::PathBuf::from(&plan.program), shim);
        let args: Vec<String> = plan.args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, ["install", "a b&c", "%PATH%"]);
    }

    #[test]
    fn relative_plugin_path_resolves_against_the_plugin_root() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(root.path().join("bin")).expect("mkdir");
        let tool = root.path().join("bin").join("run.cmd");
        std::fs::write(&tool, "@echo off\r\n").expect("write");
        let mut spec = make_shell_spec("bin/run.cmd");
        spec.layer = crate::config::HookProvenance::Plugin;
        spec.args = Some(vec!["--x".into()]);
        spec.extra_env.insert("CLAUDE_PLUGIN_ROOT".into(), root.path().to_string_lossy().into_owned());
        let inputs = PlanInputs { workspace_root: "/w", session_id: "s", event: "Stop" };
        let plan = plan_command(&spec, "bin/run.cmd", &std::collections::HashMap::new(), &inputs).expect("plan");
        assert_eq!(std::path::PathBuf::from(&plan.program), tool);
        // The native separator form resolves the same way.
        let native = format!("bin{}run.cmd", std::path::MAIN_SEPARATOR);
        let plan = plan_command(&spec, &native, &std::collections::HashMap::new(), &inputs).expect("plan");
        assert_eq!(std::path::PathBuf::from(&plan.program), tool);
        // A path that is not there is a config failure naming it.
        let err = plan_command(&spec, "bin/missing.cmd", &std::collections::HashMap::new(), &inputs)
            .err()
            .expect("missing");
        assert!(err.contains("command not found"), "{err}");
    }
}
