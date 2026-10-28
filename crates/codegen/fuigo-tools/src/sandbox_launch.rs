//! The per-command sandbox seam every shell spawn site goes through. The tools crate is
//! policy-blind: it hands the [`tokio::process::Command`] to the injected [`SandboxLaunch`] and
//! spawns whatever comes back; without an implementation the command runs unchanged.
//!
//! The wrapper replaces `*cmd` keeping only program, args, current dir and envs, so every site
//! sets stdio, `pre_exec` hooks, fd mappings, `kill_on_drop` and process-group settings *after*
//! [`prepare`], through [`wire_prepared`]:
//!
//! ```text
//! Command::new(program) → args → current_dir → envs
//!   → sandbox_launch::prepare(hook, &mut cmd, &call)
//!   → fd_mappings (if any)
//!   → sandbox_launch::wire_prepared: stdio → kill_on_drop → detach → restrict_child_network
//!   → spawn()
//! ```

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

pub use fuigo_sandbox::command::BackendName;
pub use fuigo_sandbox::command::OriginalArgv;
pub use fuigo_sandbox::command::{CallId, CallKind};

/// Why the hook refused to let the command run: the daemon's own error, carried across the seam
/// as one typed value so every spawn site maps it once. `Display` is the
/// text the tool reports; `source` is the daemon's error for a host that wants to match on it.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SandboxLaunchError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl SandboxLaunchError {
    pub fn new(error: impl std::error::Error + Send + Sync + 'static) -> SandboxLaunchError {
        SandboxLaunchError(Box::new(error))
    }

    /// The daemon's error, for a host that knows its type.
    pub fn downcast_ref<E: std::error::Error + 'static>(&self) -> Option<&E> {
        self.0.downcast_ref()
    }
}

/// The one error every spawn site returns for a refusal: the command never ran, and the tool
/// result says why.
impl From<SandboxLaunchError> for std::io::Error {
    fn from(reason: SandboxLaunchError) -> std::io::Error {
        if let Some(changed) = reason.downcast_ref::<ChildEnvSteers>() {
            return std::io::Error::new(std::io::ErrorKind::PermissionDenied, changed.to_string());
        }
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("sandbox refused to run the command: {reason}"),
        )
    }
}

impl From<SandboxLaunchError> for crate::computer::types::ComputerError {
    fn from(reason: SandboxLaunchError) -> crate::computer::types::ComputerError {
        std::io::Error::from(reason).into()
    }
}

/// What the hook did to one command. The daemon keeps the full receipt (rendered policy, exact
/// channel) keyed by `call_id`; the tools crate only needs to know whether the child ran wrapped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchReceipt {
    /// True when the command was rewritten to run inside an OS sandbox (`enforce`).
    pub sandboxed: bool,
    pub backend: Option<BackendName>,
}

/// Injected by the daemon. `prepare` rewrites `cmd` in place (or leaves it alone) and must not
/// spawn. An `Err` means the command must not run: the spawn site returns it as the tool error.
/// `call` names the spawn: a tool call the hub dispatched, or one of the terminal backend's own
/// shell-init spawns ([`CallKind::ShellInit`]) that no decoder runs on.
pub trait SandboxLaunch: Send + Sync {
    /// # Errors
    /// The reason the command must not run (no backend under `enforce`, an unrenderable policy).
    fn prepare(
        &self,
        cmd: &mut tokio::process::Command,
        original: &OriginalArgv,
        call: &CallId,
    ) -> Result<Option<LaunchReceipt>, SandboxLaunchError>;

    /// [`SandboxLaunch::prepare`] for a shell that exports variables of its own before the command
    /// runs (the persistent shell replaying its snapshot): `restored` are those variables, part of
    /// the environment the command runs under though `cmd` does not carry them ([`child_env`]).
    /// An implementation that reads no environment keeps the default.
    ///
    /// # Errors
    /// As [`SandboxLaunch::prepare`].
    fn prepare_restoring(
        &self,
        cmd: &mut tokio::process::Command,
        original: &OriginalArgv,
        _restored: &[(OsString, OsString)],
        call: &CallId,
    ) -> Result<Option<LaunchReceipt>, SandboxLaunchError> {
        self.prepare(cmd, original, call)
    }

    /// The backgrounded spawn of `call` exited (or was killed with its terminal). Called once
    /// per background task, possibly before the call's result reaches the hub.
    fn exited(&self, _call: &CallId) {}
}

/// The hook as stored in `Resources` (`resources.get::<SandboxLaunchHook>()`); the terminal
/// backend receives the same `Arc` at construction.
#[derive(Clone)]
pub struct SandboxLaunchHook(Arc<dyn SandboxLaunch>);

impl SandboxLaunchHook {
    pub fn new(launch: Arc<dyn SandboxLaunch>) -> Self {
        Self(launch)
    }

    /// The implementation, for a site that calls [`prepare`] directly.
    pub fn as_launch(&self) -> &dyn SandboxLaunch {
        self.0.as_ref()
    }

    /// The same implementation, shared with a backend constructed for the session.
    pub fn shared(&self) -> Arc<dyn SandboxLaunch> {
        Arc::clone(&self.0)
    }
}

impl std::fmt::Debug for SandboxLaunchHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SandboxLaunchHook(..)")
    }
}

/// What the site is about to run, read back from the pre-wrap command. A command with no
/// `current_dir` runs in the process cwd, which is what the decoder joins relative paths to.
pub fn original_argv(cmd: &tokio::process::Command) -> OriginalArgv {
    let std_cmd = cmd.as_std();
    OriginalArgv {
        program: PathBuf::from(std_cmd.get_program()),
        args: std_cmd.get_args().map(OsString::from).collect(),
        cwd: std_cmd.get_current_dir().map_or_else(
            || std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            std::path::Path::to_path_buf,
        ),
    }
}

/// Run the hook when one is injected. Call it right after program/args/cwd/env are set and before
/// stdio, fd mappings, `pre_exec` and `kill_on_drop` (see the module docs).
///
/// # Errors
/// Whatever the hook refuses with; the site must not spawn.
pub fn prepare(
    hook: Option<&dyn SandboxLaunch>,
    cmd: &mut tokio::process::Command,
    call: &CallId,
) -> Result<Option<LaunchReceipt>, SandboxLaunchError> {
    let Some(hook) = hook else {
        return Ok(None);
    };
    let original = original_argv(cmd);
    hook.prepare(cmd, &original, call)
}

/// [`prepare`] for a shell that exports `restored()` before the command runs
/// ([`SandboxLaunch::prepare_restoring`]); `restored` is read only when a hook is injected.
///
/// # Errors
/// Whatever the hook refuses with; the site must not spawn.
pub fn prepare_restoring(
    hook: Option<&dyn SandboxLaunch>,
    cmd: &mut tokio::process::Command,
    restored: impl FnOnce() -> Vec<(OsString, OsString)>,
    call: &CallId,
) -> Result<Option<LaunchReceipt>, SandboxLaunchError> {
    let Some(hook) = hook else {
        return Ok(None);
    };
    let original = original_argv(cmd);
    hook.prepare_restoring(cmd, &original, &restored(), call)
}

/// u35 g9: how the permission check approved the tool call a command belongs to, carried with the
/// call (a [`fuigo_tool_runtime::ToolCallContext`] extension, then
/// [`crate::computer::types::TerminalRunRequest::approved_without_grant`]). `true`: some part of
/// it was approved without a grant, by the read-only lists, the Auto mode fast path or the Auto mode
/// classifier, which judged
/// Fuigo's own environment and not the one its shell will run it in, so the shell runner judges
/// that environment ([`check_child_env`]). `false`: the user's grant, answer or override approved
/// all of it. A call that carries no flag is judged ([`ApprovedWithoutGrant::of`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovedWithoutGrant(pub bool);

impl ApprovedWithoutGrant {
    /// The flag a call carries; a missing one counts as `true`, so the check applies.
    pub fn of(flag: Option<&ApprovedWithoutGrant>) -> bool {
        flag.is_none_or(|flag| flag.0)
    }
}

/// u35 g9: the permission classifier's rule for the environment a command runs under: the first
/// variable of `env` that can steer what `command` runs or loads in `dir`, if any (the classifier's
/// `inherited_env_steers`, for the command's own programs, over `env` instead of Fuigo's). Installed
/// by the permission manager ([`install_env_judge`]).
pub type EnvJudge = fn(command: &str, env: &[(String, String)], dir: &std::path::Path) -> Option<String>;

static ENV_JUDGE: std::sync::RwLock<Option<EnvJudge>> = std::sync::RwLock::new(None);

/// Install the rule the shell runner applies to a no-grant call's environment ([`check_child_env`]).
/// u35 g11 (Grok r10 Low): a poisoned lock still takes the judge (the slot holds a plain `fn`).
pub fn install_env_judge(judge: EnvJudge) {
    *ENV_JUDGE.write().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(judge);
}

fn env_judge() -> Option<EnvJudge> {
    *ENV_JUDGE.read().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// u35 t1 (design d2 §3.6): the folder-trust rule for a call approved without a grant: whether `command`, run in
/// each of `dirs` (where it runs, and where the permission check judged it), starts in trusted folders (u35 t3: a folder
/// the command names does not count). The same function the permission check uses. Installed by the permission manager
/// ([`install_trust_judge`]).
pub type TrustJudge = fn(command: &str, dirs: &[&std::path::Path]) -> bool;

static TRUST_JUDGE: std::sync::RwLock<Option<TrustJudge>> = std::sync::RwLock::new(None);

/// Install the folder-trust rule the shell runner applies to a no-grant call ([`check_child_env`]).
pub fn install_trust_judge(judge: TrustJudge) {
    *TRUST_JUDGE.write().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(judge);
}

fn trust_judge() -> Option<TrustJudge> {
    *TRUST_JUDGE.read().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// u35 t1 (design d2 §3.6): a command approved without a grant did not run, because it starts in a folder that is not
/// trusted.
#[derive(Debug, thiserror::Error)]
#[error(
    "the command did not run: it was approved without a grant, but it starts in a folder that is not trusted \
     ({dir}). Outside a trusted folder every shell command needs the user's approval or a grant: the user \
     can trust the folder (`/trust`, or `fuigo --trust` there) or allow the command with an allow rule (such as \
     `--allow 'Bash(ls *)'`)"
)]
pub struct UntrustedFolderShell {
    pub dir: String,
}

/// u35 t1: no folder-trust rule installed for a call approved without a grant (as [`NoEnvJudge`]).
#[derive(Debug, thiserror::Error)]
#[error(
    "the command did not run: it was approved without a grant, and no rule to check the folder it runs in is \
     installed, so it needs the user's approval"
)]
pub struct NoTrustJudge;

/// u35 t1 (design d2 §3.6): for a call approved without a grant, the folder-trust check, run before the environment
/// check: `exec_dir` (where it runs) and `request_cwd` (where the permission check judged it) must both keep it in
/// trusted folders.
///
/// # Errors
/// [`UntrustedFolderShell`], or [`NoTrustJudge`] when `strict` and no rule is installed: the site must not spawn.
pub fn check_runner_trust(
    command: &str,
    exec_dir: &std::path::Path,
    request_cwd: Option<&std::path::Path>,
    strict: bool,
) -> Result<(), SandboxLaunchError> {
    check_runner_trust_with(trust_judge(), command, exec_dir, request_cwd, strict)
}

/// [`check_runner_trust`] with the rule given.
fn check_runner_trust_with(
    judge: Option<TrustJudge>,
    command: &str,
    exec_dir: &std::path::Path,
    request_cwd: Option<&std::path::Path>,
    strict: bool,
) -> Result<(), SandboxLaunchError> {
    let Some(judge) = judge else {
        if strict {
            tracing::warn!("a command approved without a grant has no folder-trust rule installed; refused");
            return Err(SandboxLaunchError::new(NoTrustJudge));
        }
        return Ok(());
    };
    let mut dirs = vec![exec_dir];
    dirs.extend(request_cwd.filter(|dir| *dir != exec_dir));
    if judge(command, &dirs) {
        return Ok(());
    }
    tracing::warn!(dir = %exec_dir.display(), "a command approved without a grant would run outside a trusted folder; refused");
    Err(SandboxLaunchError::new(UntrustedFolderShell { dir: exec_dir.display().to_string() }))
}

/// u35 g10: the one judge the tests of this crate install (the rule is process-wide, so every test
/// that installs one installs this): it judges only `FUIGO_U35_CHILD_STEER` in the environment and
/// the marker `u35-g10-steer` in the command, so other tests' spawns are untouched.
#[cfg(test)]
pub(crate) fn u35_test_child_judge(
    command: &str,
    env: &[(String, String)],
    _dir: &std::path::Path,
) -> Option<String> {
    if env.iter().any(|(name, _)| name == "FUIGO_U35_CHILD_STEER") {
        return Some("FUIGO_U35_CHILD_STEER".to_owned());
    }
    command.contains("u35-g10-steer").then(|| "U35_G10_STEER".to_owned())
}

/// u35 t1: the folder-trust rule this crate's tests install (process-wide, so every test that installs one installs
/// this): only a directory or command carrying the marker `u35-t1-untrusted` is outside a trusted folder.
#[cfg(test)]
pub(crate) fn u35_test_trust_judge(command: &str, dirs: &[&std::path::Path]) -> bool {
    !command.contains("u35-t1-untrusted") && !dirs.iter().any(|dir| dir.to_string_lossy().contains("u35-t1-untrusted"))
}

/// u35 g10 (Fable r9 Low): the remedies named are the ones that exist when this refuses; a remembered
/// "always allow" is written only by a prompt answer, and nothing prompts here.
/// u35 g9: a command approved without a grant did not run, because the environment its shell
/// would give it (the login shell's capture, the persistent shell's exports, the session's
/// variables) can change which program runs or what it loads.
#[derive(Debug, thiserror::Error)]
#[error(
    "the command did not run: it was approved without a grant, as a read-only command, but the shell \
     environment Fuigo would run it in sets {name} in a way that can change which program runs or what \
     it loads. In this environment the command needs the user's approval: the user can allow it with an \
     allow rule (such as `--allow 'Bash(ls *)'`), \"allow all commands\" or always-approve, or remove \
     {name} from the environment (the login shell's startup files, an earlier `export`, or the \
     session's variables)"
)]
pub struct ChildEnvSteers {
    pub name: String,
}

/// u35 g11 (owner decision): a command approved without a grant did not run, because the shell the
/// runner uses (PowerShell or cmd.exe) does not read commands the way the read-only checks judged it.
#[derive(Debug, thiserror::Error)]
#[error(
    "the command did not run: it was approved by a read-only check Fuigo could not vouch for, as Fuigo runs \
     commands in {shell}, which reads quoting, separators and redirects differently from the bash syntax \
     those checks judge. In {shell} every command needs the user's approval: the user can allow it with \
     an allow rule (such as `--allow 'Bash(ls *)'`), \"allow all commands\" or always-approve, or run \
     commands in Git Bash (`FUIGO_SHELL=bash`)"
)]
pub struct UnvouchedShell {
    pub shell: String,
}

/// u35 g11 (Fable/Grok r10 Low): no judge installed for a call approved without a grant. Every
/// production entry point installs one before it approves anything, so this is an entry point that
/// did not; the call is refused (`strict`). This crate's own tests install the judge they need, so
/// they are not strict.
#[derive(Debug, thiserror::Error)]
#[error(
    "the command did not run: it was approved without a grant, and no rule to check the environment \
     it would run in is installed, so it needs the user's approval"
)]
pub struct NoEnvJudge;

/// u35 g11 (owner decision): a call approved without a grant is refused when the runner's shell does
/// not read bash syntax (`shell`: `None` on Unix), so the permission check could not vouch for it.
///
/// # Errors
/// [`UnvouchedShell`]: the site must not spawn.
pub fn check_runner_shell(shell: Option<fuigo_config::shell::WindowsShellFamily>) -> Result<(), SandboxLaunchError> {
    match shell {
        Some(family) if !family.reads_bash_syntax() => {
            tracing::warn!(shell = family.name(), "a command approved without a grant would run in a shell the checks do not model; refused");
            Err(SandboxLaunchError::new(UnvouchedShell { shell: family.name().to_owned() }))
        }
        _ => Ok(()),
    }
}

/// The Windows shell the runner uses (`None` on Unix); in this crate's tests, the one a test set
/// ([`TestRunnerShell`]), so the refusal is proved on every host (u35 g12, Fable r11 Low).
fn runner_shell_family() -> Option<fuigo_config::shell::WindowsShellFamily> {
    #[cfg(test)]
    if let Some(shell) = TEST_RUNNER_SHELL.with(std::cell::Cell::get) {
        return shell;
    }
    fuigo_config::shell::runner_windows_shell_family()
}

#[cfg(test)]
thread_local! {
    static TEST_RUNNER_SHELL: std::cell::Cell<Option<Option<fuigo_config::shell::WindowsShellFamily>>> =
        const { std::cell::Cell::new(None) };
}

/// u35 g12: until dropped, this thread's runner checks see the runner use `shell` (`None`: a Unix shell).
#[cfg(test)]
pub(crate) struct TestRunnerShell(Option<Option<fuigo_config::shell::WindowsShellFamily>>);

#[cfg(test)]
impl TestRunnerShell {
    pub(crate) fn set(shell: Option<fuigo_config::shell::WindowsShellFamily>) -> Self {
        Self(TEST_RUNNER_SHELL.with(|cell| cell.replace(Some(shell))))
    }
}

#[cfg(test)]
impl Drop for TestRunnerShell {
    fn drop(&mut self) {
        TEST_RUNNER_SHELL.with(|cell| cell.set(self.0));
    }
}

/// u35 g11 (Fable/Grok r10 Low): what a call approved without a grant gets when no judge is installed.
///
/// # Errors
/// [`NoEnvJudge`] when `strict`.
pub fn missing_env_judge(strict: bool) -> Result<(), SandboxLaunchError> {
    if strict {
        tracing::warn!("a command approved without a grant has no environment rule installed; refused");
        Err(SandboxLaunchError::new(NoEnvJudge))
    } else {
        Ok(())
    }
}

/// u35 g8: whether `name=value` is one Fuigo itself sets on every tool-call shell
/// ([`crate::util::pager_env`]: `GIT_PAGER=cat`, `GH_PAGER=cat`, `GIT_EDITOR=true` and the like,
/// so no pager or editor blocks). Fuigo's own constants are not the user's environment and are
/// never judged; a different value of the same name is.
pub fn is_fuigo_own_env(name: &str, value: &str) -> bool {
    crate::util::pager_env().get(name).is_some_and(|own| own == value)
}

/// u35 g9: the variable of `env` (a command's whole environment) that steers what `command` runs
/// in `dir`, by `judge`. A missing or empty `PATH` steers: the shell then searches its built-in
/// default, which for bash includes the current directory. Fuigo's own constants
/// ([`is_fuigo_own_env`]) are not judged. On Windows names are compared upper-cased.
pub fn judge_child_env(
    env: &[(OsString, OsString)],
    command: &str,
    dir: &std::path::Path,
    judge: EnvJudge,
) -> Option<String> {
    let env: Vec<(String, String)> = env
        .iter()
        .map(|(name, value)| {
            let name = name.to_string_lossy();
            let name = if cfg!(windows) { name.to_ascii_uppercase() } else { name.into_owned() };
            (name, value.to_string_lossy().into_owned())
        })
        .filter(|(name, value)| !is_fuigo_own_env(name, value))
        .collect();
    if !env.iter().any(|(name, value)| name == "PATH" && !value.is_empty()) {
        return Some("PATH".to_owned());
    }
    judge(command, &env, dir)
}

/// u35 g9: for a tool call approved without a grant, judge the exact environment its shell will
/// run `command` under (`cmd`'s, with `restored` exported on top) by the classifier's rule, and
/// refuse the call when it steers ([`ChildEnvSteers`]). A call approved by a grant, an answer or
/// an override (`approved_without_grant == false`) is never refused here. Nothing is remembered
/// between calls: every flagged call is judged on its own environment.
///
/// # Errors
/// [`ChildEnvSteers`]: the site must not spawn.
pub fn check_child_env(
    cmd: &tokio::process::Command,
    restored: &[(OsString, OsString)],
    command: &str,
    approved_without_grant: bool,
    request_cwd: Option<&std::path::Path>,
) -> Result<(), SandboxLaunchError> {
    if !approved_without_grant {
        return Ok(());
    }
    // u35 t1 (design d2 §3.6): the folder-trust check runs first.
    check_runner_trust(command, &original_argv(cmd).cwd, request_cwd, cfg!(not(test)))?;
    check_runner_shell(runner_shell_family())?;
    let Some(judge) = env_judge() else {
        return missing_env_judge(cfg!(not(test)));
    };
    let env = child_env(cmd, restored.iter().cloned());
    match judge_child_env(&env, command, &original_argv(cmd).cwd, judge) {
        Some(name) => {
            tracing::warn!(%name, "a command approved without a grant would run under a steering environment; refused");
            Err(SandboxLaunchError::new(ChildEnvSteers { name }))
        }
        None => Ok(()),
    }
}

/// The environment the command runs under: what `cmd` spawns with (the daemon's own environment
/// with `cmd`'s sets and removals applied), then `restored` on top. Exact because no spawn site
/// clears `cmd`'s environment: a clear is not reported, so a policy base env removes names instead.
pub fn child_env(
    cmd: &tokio::process::Command,
    restored: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    child_env_for(
        std::env::vars_os(),
        cmd.as_std()
            .get_envs()
            .map(|(name, value)| (name.to_os_string(), value.map(std::ffi::OsStr::to_os_string))),
        restored,
        crate::util::shell_env_policy::EnvPlatform::host(),
    )
}

/// The platform-parameterised core of [`child_env`]. On Windows a variable has one value whatever
/// the spelling of its name, as `std::process::Command` applies it: an edit or a restored entry
/// replaces (or removes) every spelling already present, and inherited duplicates keep their first
/// spelling with the LAST value (std's own capture of the block). A case-sensitive map would keep a
/// stale `PATH` beside the edited `Path`, and a reader of that list could act on the stale value.
pub(crate) fn child_env_for(
    inherited: impl IntoIterator<Item = (OsString, OsString)>,
    edits: impl IntoIterator<Item = (OsString, Option<OsString>)>,
    restored: impl IntoIterator<Item = (OsString, OsString)>,
    platform: crate::util::shell_env_policy::EnvPlatform,
) -> Vec<(OsString, OsString)> {
    use crate::util::shell_env_policy::EnvPlatform;
    if platform == EnvPlatform::Unix {
        let mut env: BTreeMap<OsString, OsString> = inherited.into_iter().collect();
        for (name, value) in edits {
            match value {
                Some(value) => env.insert(name, value),
                None => env.remove(&name),
            };
        }
        env.extend(restored);
        return env.into_iter().collect();
    }
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    let set = |env: &mut Vec<(OsString, OsString)>, name: OsString, value: Option<OsString>| {
        let existing = env.iter().position(|(k, _)| platform.same_os_name(k, &name));
        match (existing, value) {
            (Some(i), Some(value)) => env[i].1 = value,
            (None, Some(value)) => env.push((name, value)),
            (_, None) => env.retain(|(k, _)| !platform.same_os_name(k, &name)),
        }
    };
    for (name, value) in inherited {
        set(&mut env, name, Some(value));
    }
    for (name, value) in edits {
        set(&mut env, name, value);
    }
    for (name, value) in restored {
        set(&mut env, name, Some(value));
    }
    env.sort();
    env
}

/// What every spawn site sets on the command [`prepare`] handed back, the wrapper when there is
/// one: stdin closed, stdout piped, `stderr`, `kill_on_drop`, the detach hook, then the
/// child-network filter. A site's fd mappings go on before this, so they map first in the child.
pub fn wire_prepared(cmd: &mut tokio::process::Command, stderr: std::process::Stdio) {
    // No `process_group(0)`: std runs setpgid() before the pre_exec hooks, so the detach hook's
    // setsid() would fail with EPERM
    cmd.stdin(fuigo_tty_utils::null_stdio())
        .stdout(std::process::Stdio::piped())
        .stderr(stderr)
        .kill_on_drop(true);
    fuigo_tty_utils::detach_command(cmd);
    fuigo_sandbox::child_net::restrict_child_network(cmd);
}

/// The program, args, current dir and environment edits of a command: exactly what a wrapper
/// keeps, so a command [`prepare`]d once can be rebuilt on a fresh `Command` any number of times.
///
/// Fuigo's session-cgroup placement (`ProcessScope::spawn_placed`) registers its `pre_exec` on
/// the bare `Command` it creates, before the site configures it. A wrapper that replaces `*cmd`
/// would drop that hook, so the placed sites `prepare` a plain command first, capture it here,
/// and hand `spawn_placed` a constructor and a configurator built from the capture: the wrapper's
/// program and argv are spawned with the placement still in front of every other `pre_exec`.
#[derive(Clone)]
pub struct CommandParts {
    program: OsString,
    args: Vec<OsString>,
    cwd: Option<PathBuf>,
    envs: Vec<(OsString, Option<OsString>)>,
}

/// `Debug` prints the env NAMES only: the values carry the proxy credential and whatever secrets the caller exported.
impl std::fmt::Debug for CommandParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&OsString> = self.envs.iter().map(|(name, _)| name).collect();
        f.debug_struct("CommandParts")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("cwd", &self.cwd)
            .field("env_names", &names)
            .finish()
    }
}

impl CommandParts {
    /// What `cmd` would spawn with: its program, args, current dir and env sets/removals.
    pub fn capture(cmd: &tokio::process::Command) -> Self {
        let std_cmd = cmd.as_std();
        CommandParts {
            program: std_cmd.get_program().to_os_string(),
            args: std_cmd.get_args().map(OsString::from).collect(),
            cwd: std_cmd.get_current_dir().map(std::path::Path::to_path_buf),
            envs: std_cmd
                .get_envs()
                .map(|(name, value)| (name.to_os_string(), value.map(OsString::from)))
                .collect(),
        }
    }

    /// A bare command for the captured program: no args, dir, env, stdio or hooks.
    pub fn new_command(&self) -> tokio::process::Command {
        tokio::process::Command::new(&self.program)
    }

    /// Set the captured args, current dir and env edits on `cmd` (made by [`Self::new_command`]).
    pub fn apply(&self, cmd: &mut tokio::process::Command) {
        cmd.args(&self.args);
        if let Some(cwd) = &self.cwd {
            cmd.current_dir(cwd);
        }
        for (name, value) in &self.envs {
            match value {
                Some(value) => cmd.env(name, value),
                None => cmd.env_remove(name),
            };
        }
    }
}

/// Tell the hook, when one is injected, that the backgrounded spawn of `call` exited.
pub fn exited(hook: Option<&dyn SandboxLaunch>, call: &CallId) {
    if let Some(hook) = hook {
        hook.exited(call);
    }
}

#[cfg(test)]
#[path = "sandbox_launch_tests.rs"]
mod tests;
