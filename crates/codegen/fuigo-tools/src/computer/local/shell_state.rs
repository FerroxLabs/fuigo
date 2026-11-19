//! Persistent shell state across command invocations.
//!
//! After each command, the shell's environment
//! (env vars, cwd, functions, aliases, options) is serialized via a dump script,
//! and replayed before the next command. Each invocation is still a fresh process,
//! but the user observes a single continuous session.
//!
//! State is transported via extra file descriptors (fd 3 for input, fd 4 for output)
//! so that dump traffic never pollutes stdout/stderr.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use command_fds::FdMapping;
use nix::libc;
use tokio::io::AsyncReadExt;

// ============================================================================
// Marker constants
// ============================================================================

const BASH_STATE_START_MARKER: &str = "__FUIGO_BASH_STATE_START__";
const BASH_STATE_END_MARKER: &str = "__FUIGO_BASH_STATE_END__";
const ZSH_STATE_START_MARKER: &str = "__FUIGO_ZSH_STATE_START__";
const ZSH_STATE_END_MARKER: &str = "__FUIGO_ZSH_STATE_END__";

/// Marker emitted by the init path to separate login-shell noise (MOTD, etc.)
/// from the actual state dump on stdout.
const INIT_STATE_MARKER: &str = "__FUIGO_INIT_STATE_MARKER__";

/// Maximum time to wait for a shell state init (login shell + rc files).
const INIT_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum time to wait for the dump once the command is over (the shell is gone or has begun writing it).
/// If a background process inherits fd 4, the reader would hang forever without this. It never runs while the
/// command itself is still running: a foreground command may take as long as it likes.
pub(super) const DUMP_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Environment overrides applied to every agent terminal / persistent shell spawn.
/// Prevents color/pager noise in captured output and marks the process as agent-driven.
pub fn shell_env_overrides() -> HashMap<String, String> {
    HashMap::from([
        ("TERM".to_string(), "dumb".to_string()),
        ("NO_COLOR".to_string(), "1".to_string()),
        ("FORCE_COLOR".to_string(), "0".to_string()),
        // Re-applied last via [`crate::util::apply_fuigo_agent_marker`] so request
        // env cannot clear it.
        (
            crate::util::FUIGO_AGENT_ENV.to_string(),
            crate::util::FUIGO_AGENT_ENV_VALUE.to_string(),
        ),
    ])
}

/// Returns the sudo alias injection string if `SUDO_ASKPASS` is configured.
/// When set, `alias sudo='sudo -A'` makes any `sudo` in the user's command
/// use the askpass helper instead of blocking on tty input.
fn sudo_alias_injection() -> String {
    match std::env::var("SUDO_ASKPASS") {
        Ok(val) if !val.is_empty() => "alias sudo='sudo -A'; ".to_string(),
        _ => String::new(),
    }
}

// ============================================================================
// Dump scripts (embedded as const strings)
// ============================================================================

/// Bash state dump script. Captures env vars, POSIX options, bash options,
/// functions, and aliases as base64-encoded replayable shell snippets.
const DUMP_BASH_STATE_SCRIPT: &str = r##"
dump_bash_state() {
  set -euo pipefail
  # The dump's function bodies and base64 buffers can be large. Under `set -a`,
  # exporting these private assignments makes even base64/grep fail with E2BIG.
  # Capture the user's option before disabling it for dump bookkeeping.
  local __fuigo_dump_allexport=off
  if [[ $- == *a* ]]; then __fuigo_dump_allexport=on; fi
  builtin set +a
  builtin export -n __fuigo_dump_allexport
  if ! command -v base64 >/dev/null 2>&1; then
    echo "Error: base64 command is required" >&2
    return 1
  fi

  _emit() {
    builtin printf '%s\n' "$1"
  }

  _emit_encoded() {
    local content="$1"
    local var_name="$2"
    if [[ -n "$content" ]]; then
      builtin printf 'fuigo_snap_%s=$(command base64 -d <<'"'"'FUIGO_SNAP_EOF_%s'"'"'\n' "$var_name" "$var_name"
      command base64 <<<"$content" | command tr -d '\n'
      builtin printf '\nFUIGO_SNAP_EOF_%s\n' "$var_name"
      builtin printf ')\n'
      builtin printf 'eval "$fuigo_snap_%s"\n' "$var_name"
      # Replaying POSIX options can enable allexport before later blocks decode.
      # Drop each private buffer before another external decoder is started.
      builtin printf 'builtin unset fuigo_snap_%s\n' "$var_name"
    fi
  }

  _emit "__FUIGO_BASH_STATE_START__"

  _emit "$PWD"

  local env_vars
  env_vars=$(__FUIGO_CREDENTIAL_SCRUB__; builtin export -p 2>/dev/null | command grep -viE '_proxy=|FUIGO_SANDBOX|FUIGO_AGENT=|SUDO_ASKPASS|FUIGO_ASKPASS|ELECTRON_RUN_AS_NODE|SSH_AUTH_SOCK|DBUS_SESSION_BUS_ADDRESS|XDG_RUNTIME_DIR|WAYLAND_DISPLAY|GPG_TTY' || true)
  _emit_encoded "$env_vars" "ENV_VARS_B64"

  # errexit/pipefail here are this function's own `set -euo pipefail` (set is
  # shell-global in bash); replaying them would abort later user commands.
  local posix_opts
  posix_opts=$(builtin shopt -po 2>/dev/null | command grep -vE '^set [-+]o (nounset|errexit|pipefail|allexport)$' || true)
  if [[ $__fuigo_dump_allexport == on ]]; then
    posix_opts+=$'\nset -o allexport'
  else
    posix_opts+=$'\nset +o allexport'
  fi
  _emit_encoded "$posix_opts" "POSIX_OPTS_B64"

  local bash_opts
  bash_opts=$(builtin shopt -p 2>/dev/null || true)
  _emit_encoded "$bash_opts" "BASH_OPTS_B64"

  local all_functions
  all_functions=$(builtin declare -f 2>/dev/null || true)
  _emit_encoded "$all_functions" "FUNCTIONS_B64"

  local aliases
  aliases=$(builtin alias -p 2>/dev/null || true)
  _emit_encoded "$aliases" "ALIASES_B64"

  _emit "# end of bash state dump"
  _emit "__FUIGO_BASH_STATE_END__"
  if [[ $__fuigo_dump_allexport == on ]]; then builtin set -a; fi
}
"##;

/// Zsh state dump script. Captures env vars, zsh options, functions, and aliases
/// as base64-encoded replayable shell snippets.
const DUMP_ZSH_STATE_SCRIPT: &str = r##"
function dump_zsh_state() {
  # The caller's options, copied before `emulate -L` below resets them to zsh's defaults for this function (u46 r3:
  # without this the dump only ever listed the emulation's own options and no option a command set carried). The
  # options block is the difference from those defaults, spelled as `setopt` lists it (`NAME` / `noNAME`).
  builtin zmodload -F zsh/parameter p:options 2>/dev/null
  local -A __fuigo_caller_opts
  __fuigo_caller_opts=("${(@kv)options}")
  emulate -L zsh -o errreturn -o pipefail
  set -u

  builtin zmodload -F zsh/parameter p:parameters p:options p:functions p:aliases p:galiases p:saliases 2>/dev/null || true

  _emit() {
    builtin print -r -- "$1"
  }

  _emit_encoded() {
    local content="$1"
    local var_name="$2"
    if [[ -n "$content" ]]; then
      builtin printf 'fuigo_snap_%s=$(command base64 -d <<'"'"'FUIGO_SNAP_EOF_%s'"'"'\n' "$var_name" "$var_name"
      command base64 <<<"$content" | command tr -d '\n'
      builtin printf '\nFUIGO_SNAP_EOF_%s\n' "$var_name"
      builtin printf ')\n'
      builtin printf 'eval "$fuigo_snap_%s"\n' "$var_name"
    fi
  }

  _emit "__FUIGO_ZSH_STATE_START__"

  _emit "$PWD"

  local env_vars
  env_vars=$(__FUIGO_CREDENTIAL_SCRUB__; builtin typeset -xp 2>/dev/null | command grep -viE '_proxy=|FUIGO_SANDBOX|FUIGO_AGENT=|SUDO_ASKPASS|FUIGO_ASKPASS|ELECTRON_RUN_AS_NODE|SSH_AUTH_SOCK|DBUS_SESSION_BUS_ADDRESS|XDG_RUNTIME_DIR|WAYLAND_DISPLAY|GPG_TTY' || true)
  _emit_encoded "$env_vars" "ENV_VARS_B64"

  # nounset/errexit/errreturn/pipefail would abort later user commands.
  local zsh_opts
  local __fuigo_o
  # u46 r4: the baseline is zsh's own defaults (`emulate -R zsh` resets every option; plain `emulate` only the portability
  # ones, which left options such as nocaseglob equal on both sides and so never carried). `extendedglob` is the option
  # Fuigo's init shell starts with (`-o extendedglob`), not the user's: replaying it would turn an unquoted `^`, `#` or
  # `~` in every command into a glob operator.
  zsh_opts=$(emulate -R zsh; for __fuigo_o in ${(ok)__fuigo_caller_opts}; do [[ ${__fuigo_caller_opts[$__fuigo_o]} == "${options[$__fuigo_o]-}" ]] && continue; if [[ ${__fuigo_caller_opts[$__fuigo_o]} == on ]]; then builtin print -r -- "$__fuigo_o"; else builtin print -r -- "no$__fuigo_o"; fi; done | command grep -vE '^(no)?(nounset|errexit|errreturn|pipefail|localoptions|localtraps|localpatterns|extendedglob)$' | command awk '{printf "builtin setopt %s 2>/dev/null || true\n", $0}' || true)
  _emit_encoded "$zsh_opts" "ZSH_OPTS_B64"

  # TRAP* and hook functions act as soon as they are defined (before the restore guard runs), so they are not kept.
  local all_functions
  all_functions=$(for __fuigo_fn in ${(ok)functions}; do case $__fuigo_fn in (__FUIGO_UNREPLAYED_FUNCTIONS__) ;; (*) builtin typeset -f -- "$__fuigo_fn";; esac; done 2>/dev/null || true)
  _emit_encoded "$all_functions" "FUNCTIONS_B64"

  local aliases
  aliases=$({ builtin alias -L; builtin alias -gL; builtin alias -sL } 2>/dev/null || true)
  _emit_encoded "$aliases" "ALIASES_B64"

  _emit "# end of zsh state dump"
  _emit "__FUIGO_ZSH_STATE_END__"
}
"##;

// ============================================================================
// Shell kind
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    Bash,
    Zsh,
}

impl ShellKind {
    /// Detect the user's shell from `$SHELL`, falling back to bash.
    pub fn detect() -> Self {
        match fuigo_config::shell::detect_unix_shell_kind() {
            fuigo_config::shell::UnixShellKind::Bash => Self::Bash,
            fuigo_config::shell::UnixShellKind::Zsh => Self::Zsh,
        }
    }

    /// Resolved absolute path to the shell binary. Falls back from `$SHELL` →
    /// `which` → common dirs → `/bin/<name>`. Result is cached process-wide
    /// in `fuigo_config::shell::unix_shell_path`. See that function for
    /// the full cascade. Returns `&'static str`.
    pub fn binary_path(&self) -> &'static str {
        let kind = match self {
            Self::Bash => fuigo_config::shell::UnixShellKind::Bash,
            Self::Zsh => fuigo_config::shell::UnixShellKind::Zsh,
        };
        fuigo_config::shell::unix_shell_path(kind)
    }

    /// The user's primary rc file name (relative to `$HOME`).
    pub fn rc_file_name(&self) -> &str {
        match self {
            Self::Bash => ".bashrc",
            Self::Zsh => ".zshrc",
        }
    }

    fn dump_script(&self) -> String {
        let script = match self {
            Self::Bash => DUMP_BASH_STATE_SCRIPT,
            Self::Zsh => DUMP_ZSH_STATE_SCRIPT,
        };
        // Scrub inside the capture subshell, before serialization. This handles
        // mixed-case names and multiline values without parsing shell source.
        script
            .replace(
                "__FUIGO_CREDENTIAL_SCRUB__",
                &self.credential_scrub("builtin exit 1"),
            )
            .replace(
                "__FUIGO_UNREPLAYED_FUNCTIONS__",
                &super::restore_guard::zsh_unreplayed_functions(),
            )
    }

    /// Shell code that unsets every exported credential variable on the denylist, running
    /// `on_unset_failure` if an unset fails.
    fn credential_scrub(&self, on_unset_failure: &str) -> String {
        // Configured names come from user config and are spliced into a shell `case` pattern: an
        // ASCII letter becomes a case-insensitive class, an ASCII digit or `_` stays as is, and
        // every other character is quoted, so any name (zsh accepts non-ASCII ones) is matched
        // literally and none can inject shell syntax.
        let patterns = crate::util::shell_env_policy::credential_env_names()
            .into_iter()
            .map(|name| {
                name.chars()
                    .map(|c| {
                        if c.is_ascii_alphabetic() {
                            format!("[{}{}]", c.to_ascii_lowercase(), c.to_ascii_uppercase())
                        } else if c.is_ascii_digit() || c == '_' {
                            c.to_string()
                        } else if c == '\'' {
                            "\\'".to_string()
                        } else {
                            format!("'{c}'")
                        }
                    })
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("|");
        // Bash splits `compgen -e` on IFS, which an rc file can change (`IFS=:` would turn the
        // whole list into one word that matches nothing); this runs in the capture subshell, so
        // resetting IFS here does not touch the user's shell. Zsh does not word-split arrays.
        let names = match self {
            Self::Bash => "$(builtin compgen -e)",
            Self::Zsh => "${(k)parameters}",
        };
        let reset_ifs = match self {
            Self::Bash => "IFS=$' \\t\\n'; ",
            Self::Zsh => "",
        };
        // The `(pattern)` form: bash 3.2 (stock macOS) cannot parse a `case` arm without the leading `(` inside the
        // dump's `$(...)`.
        format!(
            "{reset_ifs}for __fuigo_env_name in {names}; do case \"$__fuigo_env_name\" in ({patterns}) builtin unset \"$__fuigo_env_name\" 2>/dev/null || {on_unset_failure};; esac; done"
        )
    }

    fn dump_function_name(&self) -> &str {
        match self {
            Self::Bash => "dump_bash_state",
            Self::Zsh => "dump_zsh_state",
        }
    }

    fn start_marker(&self) -> &str {
        match self {
            Self::Bash => BASH_STATE_START_MARKER,
            Self::Zsh => ZSH_STATE_START_MARKER,
        }
    }

    fn end_marker(&self) -> &str {
        match self {
            Self::Bash => BASH_STATE_END_MARKER,
            Self::Zsh => ZSH_STATE_END_MARKER,
        }
    }
}

// ============================================================================
// ShellState
// ============================================================================

/// Persistent shell state: a serialized snapshot that can be replayed to restore
/// env vars, cwd, functions, aliases, and shell options in a fresh shell process.
#[derive(Debug, Clone)]
pub struct ShellState {
    /// Current working directory (from the dump's first line).
    pub cwd: PathBuf,
    /// Replayable shell script (everything after the cwd line, minus markers).
    pub snapshot: String,
    /// Which shell produced this state.
    pub shell: ShellKind,
    /// u46 r2/r3: how confined the spawn that wrote this state ran, and the state last written by an unconfined one
    /// ([`ReplayTrust`]).
    pub trust: ReplayTrust,
}

/// u46 r3: what the persistent shell knows about who wrote its state. One rule for everything a spawn leaves that can
/// act as code (environment, options, aliases, functions): it replays only into a spawn AT LEAST AS CONFINED as the
/// one that wrote it (`producer`). A less confined spawn gets the directory from the latest state and everything else
/// from `trusted_snapshot`, the state last written by an unconfined spawn (the login capture is the user's own
/// startup files, or an `off`/`observe` command), so the user's own settings survive a switch out of the sandbox.
#[derive(Debug, Clone, Default)]
pub struct ReplayTrust {
    pub producer: crate::sandbox_launch::SpawnConfinement,
    /// The snapshot an unconfined spawn last wrote. `None` while `producer` is unconfined: the current snapshot is
    /// that state (kept once, not copied on every command of the normal path).
    pub trusted_snapshot: Option<String>,
}

impl ShellState {
    /// Initialize shell state by running an interactive login shell that loads
    /// the user's rc files, then capturing the resulting environment.
    ///
    /// This is the expensive path — only called once (lazily on first command).
    pub async fn init(
        shell: ShellKind,
        cwd: &Path,
        shell_env_policy: Option<&crate::util::ShellEnvironmentPolicy>,
        session_scope: Option<&crate::util::ProcessScope>,
        sandbox_hook: Option<&dyn crate::sandbox_launch::SandboxLaunch>,
    ) -> Result<Self, crate::computer::types::ComputerError> {
        let dump_script = shell.dump_script();
        let dump_fn = shell.dump_function_name();

        // Build the one-liner: define the dump function, print a marker (to separate
        // login noise from our output), then call the dump function.
        let script = format!("{dump_script} builtin printf '{INIT_STATE_MARKER}\\n'; {dump_fn}");

        let args: Vec<&str> = match shell {
            ShellKind::Bash => vec!["-O", "extglob", "-ilc", &script],
            ShellKind::Zsh => vec!["-o", "extendedglob", "-ilc", &script],
        };

        // stderr is intentionally discarded (Stdio::null) — we never read it,
        // and piping it would risk a deadlock if the user's rc files write >64KB
        // to stderr (fills the pipe buffer, child blocks on write, parent blocks
        // on stdout read).
        // P189-placed: the sandbox hook rewrites a plain command; spawn_placed then rebuilds it from the
        // captured parts so the session-cgroup placement stays the first pre_exec.
        let mut plain = tokio::process::Command::new(shell.binary_path());
        plain.args(&args).current_dir(cwd);
        // Filter helper entry and remove provider exports again during capture,
        // including values supplied by startup files.
        crate::util::apply_shell_environment_policy(&mut plain, shell_env_policy);
        plain.envs(crate::util::pager_env());
        let call = crate::sandbox_launch::CallId::shell_init("shell-state");
        crate::sandbox_launch::prepare(sandbox_hook, &mut plain, &call)?;
        let parts = crate::sandbox_launch::CommandParts::capture(&plain);
        let mut child = fuigo_tty_utils::ProcessScope::spawn_placed(
            session_scope,
            || parts.new_command(),
            |cmd, _hook| {
                // P189: spawn_placed has already registered the placement as the first pre_exec.
                parts.apply(cmd);
                crate::sandbox_launch::wire_prepared(cmd, fuigo_tty_utils::null_stdio());
                Ok::<(), std::convert::Infallible>(())
            },
        )
        .map_err(|e| {
            let e = match e {
                fuigo_tty_utils::SpawnPlacedError::Spawn(e) => e,
                fuigo_tty_utils::SpawnPlacedError::Build(never) => match never {},
                fuigo_tty_utils::SpawnPlacedError::Stopping => {
                    std::io::Error::other("session is stopping; command not started")
                }
            };
            crate::computer::types::ComputerError::io(format!(
                "failed to spawn {shell:?} for shell state init: {e}"
            ))
        })?;

        let mut full_output = String::new();
        if let Some(ref mut stdout) = child.stdout {
            // Apply init timeout to prevent hangs from slow rc files (e.g. network mounts).
            match tokio::time::timeout(INIT_TIMEOUT, stdout.read_to_string(&mut full_output)).await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    tracing::warn!("shell state init: read error: {e}");
                }
                Err(_) => {
                    tracing::warn!(
                        "shell state init: timed out after {}s reading login shell output",
                        INIT_TIMEOUT.as_secs()
                    );
                    child.kill().await.ok();
                }
            }
        }

        let _ = child.wait().await;

        // Extract output after our marker (skip MOTD, bashrc echo, etc.)
        let snapshot_raw = parse_after_marker(&full_output, INIT_STATE_MARKER);

        match parse_dump(shell, snapshot_raw) {
            Some((parsed_cwd, rest)) => Ok(Self {
                cwd: parsed_cwd,
                trust: ReplayTrust::default(),
                snapshot: rest,
                shell,
            }),
            None => {
                // Dump failed or was killed — use empty state with the given cwd.
                tracing::warn!("shell state init: dump markers missing, using empty state");
                Ok(Self {
                    cwd: cwd.to_path_buf(),
                    snapshot: String::new(),
                    shell,
                    trust: Default::default(),
                })
            }
        }
    }

    /// Build the wrapper command and fd pipe pair for a persistent shell invocation.
    ///
    /// Returns `(shell_binary, args, state_in_fd, state_out_fd)` where:
    /// - `state_in_fd` is a pipe the caller writes the prior snapshot to (fd 3 in the child)
    /// - `state_out_fd` is a pipe the caller reads the new dump from (fd 4 in the child)
    ///
    /// The caller must:
    /// 1. Write `self.snapshot` to `state_in_fd` then close it
    /// 2. Spawn the child with the returned args + fd_mappings
    /// 3. Read `state_out_fd` after the child exits
    /// 4. Call `parse_dump()` on the result to update state
    ///
    /// `cwd_override`: if provided, the child uses this cwd instead of the
    ///    persistent shell's tracked cwd. Used for per-call `working_directory`
    ///    overrides from `TerminalRunRequest`.
    pub fn prepare_command(
        &self,
        user_command: &str,
        cwd_override: Option<&Path>,
        search_shadows: super::SearchShadowConfig,
        spawn_notice: Option<&str>,
    ) -> std::io::Result<PreparedCommand> {
        let bash_major = match self.shell {
            ShellKind::Bash => bash_major(self.shell.binary_path()),
            ShellKind::Zsh => None,
        };
        self.prepare_command_for(
            user_command,
            cwd_override,
            search_shadows,
            spawn_notice,
            bash_major,
        )
    }

    /// [`Self::prepare_command`] for a bash whose major version is `bash_major` (`None`: unknown or zsh). Bash
    /// below 4 gets its state dump through a named FIFO (audit L3, see the comment at the wrapper); every other
    /// shell keeps the descriptor-based channel unchanged.
    pub(crate) fn prepare_command_for(
        &self,
        user_command: &str,
        cwd_override: Option<&Path>,
        search_shadows: super::SearchShadowConfig,
        spawn_notice: Option<&str>,
        bash_major: Option<u32>,
    ) -> std::io::Result<PreparedCommand> {
        let use_fifo = self.shell == ShellKind::Bash && bash_major.is_some_and(|major| major < 4);
        let dump_script = self.shell.dump_script();
        let dump_fn = self.shell.dump_function_name();
        let sudo_inject = sudo_alias_injection();
        let search_inject = super::embedded_search_tools::search_injection(search_shadows);

        // Create two OS pipes: one for state-in (fd 3), one for state-out (fd 4).
        // os_pipe() creates fds with O_CLOEXEC (atomically on Linux,
        // best-effort on macOS) so concurrent forks can't leak them.
        let (state_in_read, state_in_write) = os_pipe()?;
        let (state_out_read, state_out_write, fifo) = if use_fifo {
            let (reader, fifo) = make_dump_fifo()?;
            (reader, None, Some(fifo))
        } else {
            let (read, write) = os_pipe()?;
            (read, Some(write), None)
        };

        // Ensure the parent-only ends have CLOEXEC (redundant on Linux
        // where os_pipe uses pipe2, but needed as a safety net on macOS
        // where pipe+fcntl has a small race window).
        set_cloexec(&state_in_write)?;
        set_cloexec(&state_out_read)?;
        // The child-bound ends (state_in_read, state_out_write) also have
        // CLOEXEC from os_pipe(). This is fine: fd_mappings uses dup2()
        // which clears CLOEXEC on the target fd (3/4), so the child keeps
        // them across exec. The originals are closed on exec by CLOEXEC.

        // The dump pipe is closed around the user command, so no program it runs inherits it (audit L3).
        // Bash: the wrapper first moves the pipe from fd 4 to fd 200 (`exec`, a plain dup that programs WOULD
        // inherit) and closes it around the user command with `200>&-`; fd 4 is closed throughout. Zsh keeps it on
        // fd 4 and closes it with `4>&-` (zsh cannot name a descriptor above 9 in a redirection, and `{var}>&-`
        // closes for good). Accepted limit: while the command runs, the shell keeps a saved copy of the pipe to
        // restore afterwards; a builtin in the same shell can reach its own descriptors (bash: the copy at fd 10+),
        // which only lets the command alter state it could set directly anyway. (Plain `exec`: `builtin exec`
        // would apply the redirections to the `builtin` command only and undo them.)
        // Bash below 4 (stock macOS 3.2) also hands that saved copy to the programs it runs, and closing it breaks the
        // restore. There the shell holds no descriptor for the dump at all: it writes the dump to a named FIFO the
        // parent made in a private 0700 directory (`make_dump_fifo`), opened only for that one write after the user
        // command; fd 4 is not mapped. The parent removes FIFO and directory when its reader ends (`DumpPipe`).
        // The wrapper command:
        // 1. Read prior snapshot from fd 3, eval it (restores env/funcs/aliases/opts)
        // 2. Run the user's command (passed as $1)
        // 3. Dump new state to fd 4
        // 4. Exit with the user command's exit code
        let (channel_open, dump_to, channel_close) = match &fifo {
            Some(fifo) => (
                "".to_owned(),
                format!(">{}", sh_single_quote(fifo.path())),
                "",
            ),
            None => (
                "exec 200>&4 4>&-; ".to_owned(),
                ">&200".to_owned(),
                " 200>&-",
            ),
        };
        let wrapper = match self.shell {
            ShellKind::Bash => format!(
                // Merge the user command's stderr into its
                // stdout via `2>&1` so the captured byte stream preserves
                // chronological write order. Without this, the bash tool's
                // separate stdout/stderr pipes (each read in lockstep)
                // emit all-of-stdout-then-all-of-stderr in a single poll
                // tick, so a command like `echo X 1>&2 && echo Y` shows
                // up as `Y\nX\n` instead of the chronological `X\nY\n`.
                // Shell-level diagnostics (eval syntax errors, etc.) still
                // land on the outer shell's stderr — those are unaffected.
                // Re-export FUIGO_AGENT=1 after snapshot eval so agent-definition
                // selectors (or other values) from prior shells cannot clear the
                // agent sentinel (process env alone is insufficient).
                //
                // Copy $1/$2 into plain variables and clear the positional
                // parameters (`builtin set --`) BEFORE eval'ing the user
                // command: `source <script>` with no arguments makes the
                // sourced script inherit the caller's positional parameters,
                // so e.g. conda's `bin/activate` (which forwards "$@" to
                // `conda activate`) would receive the entire wrapped command
                // string as an environment name. Clearing them matches the
                // plain `bash -c "<command>"` execution path, where $# is 0.
                //
                // The snapshot can restore `allexport` (set -a), which would
                // auto-export the temp variable — so strip the export
                // attribute post-assignment (`declare +x`; inline `declare +x
                // var=value` does NOT beat allexport) and unset it after the
                // eval so it can never reach child processes or the state
                // dump (`export -p`).
                //
                // u35: the restore guard runs first after the snapshot eval (shadowing functions and aliases out,
                // parse-affecting options forced); the rest runs only if it succeeded. See `restore_guard`.
                "{channel_open}{dump_script} \
                 snap=$(command cat <&3) && builtin shopt -s extglob && builtin eval -- \"$snap\" && \
                 {{ {guarded}}}; \
                 COMMAND_EXIT_CODE=$?; builtin unset __fuigo_user_cmd 2>/dev/null; {dump_fn} {dump_to}; builtin exit $COMMAND_EXIT_CODE",
                guarded = super::restore_guard::bash_guarded(&format!(
                    "builtin set +u 2>/dev/null || true; \
                     builtin export FUIGO_AGENT=1; \
                     builtin export PWD=\"$(builtin pwd)\"; \
                     builtin shopt -s expand_aliases 2>/dev/null; {sudo_inject}{search_inject}\
                     builtin printf '%s' \"${{2:-}}\"; \
                     __fuigo_user_cmd=\"$1\"; builtin declare +x __fuigo_user_cmd 2>/dev/null; builtin set --; \
                     builtin eval \"$__fuigo_user_cmd\" 2>&1{channel_close}; "
                )),
            ),
            // After snapshot restore: force nonomatch so login dumps cannot re-arm NOMATCH for model globs.
            // See the bash wrapper comment for why positional parameters are
            // cleared before the user-command eval (zsh's `source`/`.` inherits
            // them identically).
            ShellKind::Zsh => format!(
                "{dump_script} \
                 snap=$(command cat <&3); \
                 builtin unsetopt aliases 2>/dev/null; \
                 builtin unalias -m '*' 2>/dev/null || true; \
                 builtin eval \"$snap\" && \
                 {{ {guarded}}}; \
                 COMMAND_EXIT_CODE=$?; builtin unset __fuigo_user_cmd 2>/dev/null; {dump_fn} >&4; builtin exit $COMMAND_EXIT_CODE",
                guarded = super::restore_guard::zsh_guarded(&format!(
                    "builtin unsetopt nounset 2>/dev/null || true; \
                     builtin setopt nonomatch 2>/dev/null || true; \
                     builtin export FUIGO_AGENT=1; \
                     builtin export PWD=\"$(builtin pwd)\"; \
                     builtin setopt aliases 2>/dev/null; {sudo_inject}{search_inject}\
                     builtin printf '%s' \"${{2:-}}\"; \
                     __fuigo_user_cmd=\"$1\"; builtin typeset +x __fuigo_user_cmd 2>/dev/null; builtin set --; \
                     builtin eval \"$__fuigo_user_cmd\" 2>&1 4>&-; "
                )),
            ),
        };

        let effective_cwd = cwd_override.unwrap_or(&self.cwd);

        let mut args: Vec<String> = match self.shell {
            ShellKind::Bash => vec![
                "-O".into(),
                "extglob".into(),
                "-c".into(),
                wrapper,
                "--".into(),
                user_command.into(),
            ],
            ShellKind::Zsh => vec!["-c".into(), wrapper, "--".into(), user_command.into()],
        };
        if let Some(notice) = spawn_notice {
            args.push(notice.into());
        }

        let mut fd_mappings = vec![FdMapping {
            parent_fd: state_in_read,
            child_fd: 3,
        }];
        if let Some(state_out_write) = state_out_write {
            fd_mappings.push(FdMapping {
                parent_fd: state_out_write,
                child_fd: 4,
            });
        }

        Ok(PreparedCommand {
            binary: self.shell.binary_path().to_string(),
            args,
            fd_mappings,
            state_in_write,
            state_out_read: DumpPipe {
                fifo,
                fd: state_out_read,
                child_pid: 0,
            },
            cwd: effective_cwd.to_path_buf(),
        })
    }

    /// What to write to the state-in pipe for the next command when it runs as confined as the spawn that wrote this
    /// state: the snapshot as a replay script (see [`replay_script`]).
    pub fn replay_script(&self) -> Vec<u8> {
        replay_script_with(self.shell, &self.snapshot, self.trusted_snapshot(), false)
    }

    /// u46 r3: [`Self::replay_script`] for a spawn running under `next`. When `next` is less confined than the spawn
    /// that wrote this state ([`SpawnConfinement::is_less_confined_than`]) only the directory comes from it: the
    /// environment, options, aliases and functions come from the state an unconfined spawn last wrote
    /// ([`ReplayTrust`]), with a warning in the command's output when that leaves anything out.
    ///
    /// [`SpawnConfinement::is_less_confined_than`]: crate::sandbox_launch::SpawnConfinement::is_less_confined_than
    pub fn replay_script_for(&self, next: &crate::sandbox_launch::SpawnConfinement) -> Vec<u8> {
        let less_confined = next.is_less_confined_than(&self.trust.producer);
        replay_script_with(
            self.shell,
            &self.snapshot,
            self.trusted_snapshot(),
            less_confined,
        )
    }

    /// The state an unconfined spawn last wrote: the current snapshot while its producer is unconfined, else the one
    /// kept aside when a confined spawn first replaced it (empty if none was kept).
    fn trusted_snapshot(&self) -> &str {
        if self.trust.producer == crate::sandbox_launch::SpawnConfinement::default() {
            &self.snapshot
        } else {
            self.trust.trusted_snapshot.as_deref().unwrap_or_default()
        }
    }

    /// Update this state from a raw dump string (read from fd 4).
    /// Returns `true` if the state was successfully updated.
    /// Take only the directory from a dump (P86: the rest of a dump taken under an older
    /// credential denylist is discarded, but the shell keeps the directory the command left).
    pub fn update_cwd_from_dump(&mut self, raw: &str) {
        if let Some((new_cwd, _)) = parse_dump(self.shell, raw)
            && new_cwd.is_absolute()
        {
            self.cwd = new_cwd;
        }
    }

    /// Install a dump without changing who is recorded as having written the state (tests, and callers that know
    /// no spawn confinement).
    pub fn update_from_dump(&mut self, raw: &str) -> bool {
        match parse_dump(self.shell, raw) {
            Some((new_cwd, new_snapshot)) => {
                if new_cwd.is_absolute() {
                    self.cwd = new_cwd;
                }
                self.snapshot = new_snapshot;
                true
            }
            None => {
                tracing::debug!("shell state dump markers missing, keeping previous state");
                false
            }
        }
    }

    /// u46 r3: install a dump written by a spawn that ran under `producer`. An unconfined producer's state is the
    /// trusted state from now on; the first confined producer after one keeps the state it replaces aside as the
    /// trusted state ([`ReplayTrust`]).
    pub fn update_from_dump_by(
        &mut self,
        raw: &str,
        producer: crate::sandbox_launch::SpawnConfinement,
    ) -> bool {
        let Some((new_cwd, new_snapshot)) = parse_dump(self.shell, raw) else {
            tracing::debug!("shell state dump markers missing, keeping previous state");
            return false;
        };
        if new_cwd.is_absolute() {
            self.cwd = new_cwd;
        }
        let unconfined = crate::sandbox_launch::SpawnConfinement::default();
        let previous = std::mem::replace(&mut self.snapshot, new_snapshot);
        if producer == unconfined {
            self.trust.trusted_snapshot = None;
        } else if self.trust.producer == unconfined {
            self.trust.trusted_snapshot = Some(previous);
        }
        self.trust.producer = producer;
        true
    }
}

/// Everything needed to spawn a persistent shell command.
pub struct PreparedCommand {
    /// Resolved shell binary path (e.g. `/bin/bash`, `/opt/homebrew/bin/bash`,
    /// or `/run/current-system/sw/bin/bash` on NixOS). See
    /// [`ShellKind::binary_path`] for the resolution cascade.
    pub binary: String,
    /// Full argument list for the shell.
    pub args: Vec<String>,
    /// Fd mappings to pass to `CommandFdExt::fd_mappings()`.
    pub fd_mappings: Vec<FdMapping>,
    /// Write end of the state-input pipe. Caller writes `snapshot` here, then drops.
    pub state_in_write: OwnedFd,
    /// Read end of the state-output channel. Caller reads the new dump from here after exit.
    pub state_out_read: DumpPipe,
    /// Working directory for the child process.
    pub cwd: PathBuf,
}

// ============================================================================
// Helpers
// ============================================================================

/// The parent's end of the state-dump channel. For bash 3 it also owns the FIFO the shell writes to, so FIFO and
/// directory are removed whenever this is dropped: after a normal read, a timeout, an aborted reader or an error
/// before spawn.
pub struct DumpPipe {
    // Declared first so it drops first: the path is unlinked before the descriptor closes, so a shell that opens the
    // path late finds nothing (instead of blocking on a FIFO nobody reads).
    fifo: Option<DumpFifo>,
    fd: OwnedFd,
    child_pid: u32,
}

impl DumpPipe {
    /// Tell a FIFO-backed reader which process writes the dump, so it stops waiting when that process is gone
    /// without having written one (a pipe reports that by EOF; a FIFO the parent holds open for reading does not).
    pub fn watch_child(&mut self, pid: Option<u32>) {
        self.child_pid = pid.unwrap_or(0);
    }

    #[cfg(test)]
    pub(crate) fn fifo_path(&self) -> Option<&Path> {
        self.fifo.as_ref().map(DumpFifo::path)
    }
}

impl AsRawFd for DumpPipe {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// A private directory (mode 0700, made by `mkdtemp`) holding the dump FIFO (mode 0600).
struct DumpFifo {
    path: PathBuf,
    _dir: tempfile::TempDir,
}

impl DumpFifo {
    fn path(&self) -> &Path {
        &self.path
    }
}

/// Make the dump FIFO and open it for reading and writing (non-blocking, close-on-exec): holding a write end keeps
/// the open from blocking and the reader from seeing EOF before the shell has written.
fn make_dump_fifo() -> std::io::Result<(OwnedFd, DumpFifo)> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::Builder::new().prefix("fuigo-dump-").tempdir()?;
    // `mkdtemp` already makes it 0700; say so explicitly rather than rely on the library's default.
    #[allow(
        clippy::disallowed_methods,
        reason = "a fresh private temp directory outside any session folder, emptied and removed with the dump channel"
    )]
    let restricted = std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700));
    restricted?;
    let path = dir.path().join("dump");
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `c_path` is a valid NUL-terminated path that outlives both calls.
    let fd = unsafe {
        if libc::mkfifo(c_path.as_ptr(), 0o600) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        libc::open(
            c_path.as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened and nothing else owns it.
    let reader = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok((reader, DumpFifo { path, _dir: dir }))
}

/// `path` as one single-quoted shell word.
fn sh_single_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

/// Major version of the bash at `binary`, probed once per path (`None`: it could not be run or read). Only the
/// answer "below 4" changes anything, so an unknown version keeps the descriptor-based channel.
fn bash_major(binary: &str) -> Option<u32> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<u32>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(found) = cache
        .lock()
        .ok()
        .and_then(|cache| cache.get(binary).copied())
    {
        return found;
    }
    let probed = probe_bash_major(binary);
    if let Ok(mut cache) = cache.lock() {
        cache.insert(binary.to_owned(), probed);
    }
    probed
}

pub(crate) fn probe_bash_major(binary: &str) -> Option<u32> {
    #[allow(
        clippy::disallowed_methods,
        reason = "a one-shot `bash -c printf` that is waited on and exits at once; nothing outlives it"
    )]
    // P189-unplaced: a probe, not a session tool process: `bash -c printf` runs for milliseconds and is waited on here.
    let out = std::process::Command::new(binary)
        .args([
            "--noprofile",
            "--norc",
            "-c",
            "printf %s \"${BASH_VERSINFO[0]}\"",
        ])
        .env_remove("BASH_ENV")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    String::from_utf8(out.stdout).ok()?.trim().parse().ok()
}

/// Create an OS pipe, returning `(read_end, write_end)` as `OwnedFd`.
///
/// On Linux, uses `nix::unistd::pipe2(O_CLOEXEC)` to atomically set
/// close-on-exec, eliminating the race window between `pipe()` and
/// `fcntl(F_SETFD)` where a concurrent `fork()` could leak fds to an
/// unrelated child.
///
/// On macOS, `pipe2` is not exposed by `nix` 0.30 (the kernel added it
/// in 10.15 but `nix`'s cfg gate hasn't caught up). Falls back to
/// `pipe()` + `fcntl(FD_CLOEXEC)` with a best-effort race window.
fn os_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    // Linux: atomic O_CLOEXEC via pipe2.
    #[cfg(target_os = "linux")]
    {
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
    }

    // macOS (and other non-Linux Unix): pipe() + fcntl best-effort.
    #[cfg(not(target_os = "linux"))]
    {
        let (read_fd, write_fd) =
            nix::unistd::pipe().map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        // Best-effort CLOEXEC — small race window on macOS between pipe()
        // and these fcntl calls, but unavoidable without pipe2.
        let _ = set_cloexec(&read_fd);
        let _ = set_cloexec(&write_fd);
        Ok((read_fd, write_fd))
    }
}

/// Set FD_CLOEXEC on a file descriptor so it is NOT inherited by child processes.
///
/// This is critical for pipe fds that should stay parent-only: without CLOEXEC,
/// the child inherits both ends of a pipe after fork, preventing EOF from being
/// signaled when the parent closes its end.
fn set_cloexec(fd: &OwnedFd) -> std::io::Result<()> {
    let raw = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The decoded blocks of a stored snapshot (`fuigo_snap_<NAME>=$(command base64 -d <<'FUIGO_SNAP_EOF_<NAME>'`, one
/// base64 line, the end line), in order. Every other line (the `)`, `eval` and `unset` lines, comments) is skipped.
fn snapshot_blocks(snapshot: &str) -> Vec<(&str, Vec<u8>)> {
    let mut blocks = Vec::new();
    let mut lines = snapshot.lines();
    while let Some(line) = lines.next() {
        let Some(name) = line
            .strip_prefix("fuigo_snap_")
            .and_then(|rest| rest.split_once("=$(command base64 -d <<'FUIGO_SNAP_EOF_"))
            .and_then(|(name, rest)| (rest.strip_suffix('\'') == Some(name)).then_some(name))
        else {
            continue;
        };
        let (Some(payload), Some(end)) = (lines.next(), lines.next()) else {
            break;
        };
        if end.strip_prefix("FUIGO_SNAP_EOF_") != Some(name) {
            continue;
        }
        if let Ok(mut text) = base64::engine::general_purpose::STANDARD.decode(payload.trim()) {
            if name == "ENV_VARS_B64" {
                text = scrub_env_block(&text);
            }
            blocks.push((name, text));
        }
    }
    blocks
}

/// True for a variable name the dump never carries into a snapshot (the dump's own `grep -v` list plus the credential
/// denylist). Compared case-insensitively, as the dump's filter is.
fn is_denied_env_name(name: &[u8]) -> bool {
    let name = String::from_utf8_lossy(name).to_ascii_uppercase();
    const DENIED: &[&str] = &[
        "SUDO_ASKPASS",
        "FUIGO_ASKPASS",
        "ELECTRON_RUN_AS_NODE",
        "SSH_AUTH_SOCK",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "WAYLAND_DISPLAY",
        "GPG_TTY",
        "FUIGO_AGENT",
    ];
    name.ends_with("_PROXY")
        || name.contains("FUIGO_SANDBOX")
        || DENIED.contains(&name.as_str())
        || crate::util::shell_env_policy::credential_env_names()
            .iter()
            .any(|denied| denied.eq_ignore_ascii_case(&name))
}

/// r1h3, u46 r2: the env block of a snapshot with every command that is not a plain export of an allowed variable
/// removed ([`env_command_entries`]). The shell's own dump only ever writes such commands, but a frame is only as
/// trustworthy as whoever wrote it (a running command can write a complete frame of its own into the channel), so
/// installing a frame must not carry anything else.
fn scrub_env_block(script: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(script.len());
    for command in env_block_commands(script) {
        if command.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if env_command_entries(command).is_some() {
            out.extend_from_slice(command);
            out.push(b'\n');
        }
    }
    out
}

/// An env block split at unquoted newlines and `;` (quote-aware, like [`shell_commands`]).
fn env_block_commands(script: &[u8]) -> Vec<&[u8]> {
    let mut commands = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < script.len() {
        match script[i] {
            b'\\' => i += 1,
            b'\'' => {
                i += 1;
                while i < script.len() && script[i] != b'\'' {
                    i += 1;
                }
            }
            b'"' => {
                i += 1;
                while i < script.len() && script[i] != b'"' {
                    if script[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'$' if script.get(i + 1) == Some(&b'\'') => {
                i += 2;
                while i < script.len() && script[i] != b'\'' {
                    if script[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'\n' | b';' => {
                commands.push(&script[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    commands.push(&script[start.min(script.len())..]);
    commands
}

/// One variable an env block exports: its name and value (`None`: exported without one).
type EnvEntry = (Vec<u8>, Option<Vec<u8>>);

/// u46 r2: one command of an env block read as data, or `None` when it is anything but what `export -p` /
/// `typeset -xp` print: `declare`/`typeset`/`export`, attribute flags only (no nameref `-n`, array `-a`/`-A`,
/// function `-f`), then `NAME` or `NAME=value` words with a valid, allowed name (so `NAME+=value`, `eval …` and
/// expansions are not read), or zsh's tied `export -T NAME name=( … )`. The values are quote-removed text.
fn env_command_entries(command: &[u8]) -> Option<Vec<EnvEntry>> {
    if let Some(entry) = zsh_tied_export(command) {
        return Some(vec![entry]);
    }
    let commands = shell_commands(command);
    let [Some(words)] = commands.as_slice() else {
        return None;
    };
    let (verb, args) = words.split_first()?;
    if !matches!(verb.as_slice(), b"declare" | b"typeset" | b"export") {
        return None;
    }
    let mut entries = Vec::new();
    for arg in args {
        if let Some(flags) = arg.strip_prefix(b"-") {
            let attributes = !flags.is_empty()
                && flags
                    .iter()
                    .all(|b| matches!(b, b'x' | b'r' | b'i' | b'l' | b'u' | b't' | b'g'));
            if !attributes {
                return None;
            }
            continue;
        }
        let (name, value) = match arg.iter().position(|&b| b == b'=') {
            Some(eq) => (&arg[..eq], Some(arg[eq + 1..].to_vec())),
            None => (arg.as_slice(), None),
        };
        if !is_env_name(name) || is_denied_env_name(name) {
            return None;
        }
        entries.push((name.to_vec(), value));
    }
    Some(entries)
}

/// zsh's `export -T NAME name=( word … )` (an exported tied parameter such as `PATH`, also with other attribute
/// letters such as `-UT`) as `NAME` and its words joined with `:`; `None` for anything else.
fn zsh_tied_export(command: &[u8]) -> Option<EnvEntry> {
    // `export -T` and the same with other attribute letters (`-UT` after `typeset -U PATH path`; Fable r3 M3).
    let rest = command.trim_ascii().strip_prefix(b"export -")?;
    let (flags, rest) = rest.split_at(rest.iter().position(|&b| b == b' ')?);
    let rest = &rest[1..];
    if !flags.contains(&b'T')
        || !flags
            .iter()
            .all(|b| matches!(b, b'T' | b'U' | b'x' | b'r' | b'l' | b'u' | b'g'))
    {
        return None;
    }
    let (name, rest) = rest.split_at(rest.iter().position(|&b| b == b' ')?);
    let rest = &rest[1..];
    let open = rest.windows(2).position(|w| w == b"=(")?;
    let (array, inner) = (&rest[..open], rest[open + 2..].strip_suffix(b")")?);
    if !is_env_name(name) || !is_env_name(array) || is_denied_env_name(name) {
        return None;
    }
    let words = match shell_commands(inner).as_slice() {
        [] => Vec::new(),
        [Some(words)] => words.clone(),
        _ => return None,
    };
    Some((name.to_vec(), Some(words.join(&b':'))))
}

/// `[A-Za-z_][A-Za-z0-9_]*`.
fn is_env_name(name: &[u8]) -> bool {
    name.split_first().is_some_and(|(first, rest)| {
        (first.is_ascii_alphabetic() || *first == b'_')
            && rest.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
    })
}

/// u46 r2: every variable an env block exports, read as data ([`env_command_entries`]).
fn env_entries(script: &[u8]) -> Vec<EnvEntry> {
    env_block_commands(script)
        .into_iter()
        .filter_map(env_command_entries)
        .flatten()
        .collect()
}

/// `text` as one single-quoted shell word.
fn push_single_quoted(out: &mut Vec<u8>, text: &[u8]) {
    out.push(b'\'');
    for &b in text {
        if b == b'\'' {
            out.extend_from_slice(b"'\\''");
        } else {
            out.push(b);
        }
    }
    out.push(b'\'');
}

/// u46 r3: variables that pick code a shell or the dynamic loader runs on its own (a startup file, a prompt or trace
/// string, an exported function, a preloaded library). They replay from the state an unconfined spawn wrote (the
/// user's own startup files or an unsandboxed command, which could run that code anyway); from a sandboxed
/// command's state only into an equally confined spawn (u46 r3tweak, see [`replayed_env_entries`]).
fn is_startup_env_name(name: &[u8]) -> bool {
    const STARTUP: &[&[u8]] = &[
        b"BASH_ENV",
        b"ENV",
        b"PROMPT_COMMAND",
        b"PS0",
        b"PS4",
        b"PROMPT4",
        b"ZDOTDIR",
        b"LD_PRELOAD",
        b"LD_LIBRARY_PATH",
        b"LD_AUDIT",
    ];
    STARTUP.contains(&name) || name.starts_with(b"DYLD_") || name.starts_with(b"BASH_FUNC_")
}

/// u46 r2/r3: the variables a replay exports: `block`'s data entries, except the startup selectors
/// ([`is_startup_env_name`]), which come from `trusted_block` (the env block of the state an unconfined spawn wrote).
///
/// u46 r3tweak: `same_trust` (the next spawn is at least as confined as the one that wrote `block`): the startup
/// selectors carry from `block` like any other variable, since nothing is escalated. PS4 and PROMPT4 only act
/// under xtrace, which is never replayed, so they stay trusted-only in every case (they are harmless to drop).
fn replayed_env_entries(block: &[u8], trusted_block: &[u8], same_trust: bool) -> Vec<EnvEntry> {
    let trusted_only = |name: &[u8]| {
        is_startup_env_name(name) && (!same_trust || matches!(name, b"PS4" | b"PROMPT4"))
    };
    let mut entries: Vec<EnvEntry> = env_entries(block)
        .into_iter()
        .filter(|(name, _)| !trusted_only(name))
        .collect();
    entries.extend(
        env_entries(trusted_block)
            .into_iter()
            .filter(|(name, _)| trusted_only(name)),
    );
    entries
}

/// u46 r2: the env block rebuilt from its data as `export NAME='value'` (or `export NAME`) lines, as
/// [`replay_script_with`] writes them. Attributes (integer, readonly, case) are not carried: an integer attribute
/// would evaluate the value arithmetically, which is code.
#[cfg(test)]
fn env_replay(block: &[u8], trusted_block: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in replayed_env_entries(block, trusted_block, true) {
        out.extend_from_slice(b"export ");
        out.extend_from_slice(&name);
        if let Some(value) = value {
            out.push(b'=');
            push_single_quoted(&mut out, &value);
        }
        out.push(b'\n');
    }
    out
}

/// u46 r3: an option name exactly as the dump spells it: lower case, `[a-z][a-z0-9_-]*` for bash (`set -o` and
/// `shopt` names, `interactive-comments`), `[a-z][a-z0-9]*` for zsh (`setopt` prints names lower case without
/// underscores, a default-on option that is off as `noNAME`).
fn is_canonical_option_name(shell: ShellKind, name: &[u8]) -> bool {
    name.split_first().is_some_and(|(first, rest)| {
        first.is_ascii_lowercase()
            && rest.iter().all(|&b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || (shell == ShellKind::Bash && matches!(b, b'_' | b'-'))
            })
    })
}

/// u46 r2/r3: an options-block line to replay: exactly a form the dump writes (bash `set -o NAME`, `set +o NAME`,
/// `shopt -s NAME`, `shopt -u NAME`; zsh `builtin setopt NAME 2>/dev/null || true`) with a canonical name
/// ([`is_canonical_option_name`]), and never one that names tracing or echoing input. A traced command expands `PS4`
/// (command substitutions included, with zsh's `promptsubst`) before the restore guard could switch it off, so
/// `xtrace` and `verbose` are not replayed in any form, nor `noexec` (no command would run, all silently "succeed";
/// Fable r3 L1): zsh reads option names ignoring case and underscores and
/// takes `noNAME` as the negation, so the check is on the name lower-cased, underscores dropped, with and without a
/// leading `no`. In bash `history`/`histexpand` are left out too: inside this one eval they would turn on `!`
/// history expansion for the definitions that follow (`eval` only switches history off for its own text); the guard
/// forces `histexpand` off anyway.
fn is_replayed_option_line(shell: ShellKind, line: &[u8]) -> bool {
    let name = match shell {
        ShellKind::Bash => [&b"set -o "[..], b"set +o ", b"shopt -s ", b"shopt -u "]
            .iter()
            .find_map(|prefix| line.strip_prefix(*prefix)),
        ShellKind::Zsh => line
            .strip_prefix(b"builtin setopt ")
            .and_then(|rest| rest.strip_suffix(b" 2>/dev/null || true")),
    };
    let Some(name) = name.filter(|name| is_canonical_option_name(shell, name)) else {
        return false;
    };
    let normal: Vec<u8> = name
        .iter()
        .filter(|&&b| b != b'_')
        .map(u8::to_ascii_lowercase)
        .collect();
    let positive = normal.strip_prefix(b"no").unwrap_or(&normal);
    let never: &[&[u8]] = match shell {
        ShellKind::Bash => &[b"xtrace", b"verbose", b"exec", b"history", b"histexpand"],
        ShellKind::Zsh => &[b"xtrace", b"verbose", b"exec"],
    };
    !never.contains(&normal.as_slice()) && !never.contains(&positive)
}

/// u46 r2/r3: one command of an aliases block (split quote-aware, so a value holding a newline stays whole) of the
/// form the dump writes: `alias [--] NAME=VALUE` (bash `alias -p`), and zsh's `alias -L` forms with `-g`/`-s` and
/// `$'…'` values. The words are read as data ([`shell_commands`]: quotes removed, any expansion, redirection or second
/// command makes it unreadable) and rebuilt as `alias [-g |-s ]-- 'NAME'='VALUE'`; `None` for anything else.
/// Defining an alias runs nothing; the value only expands inside a later command, after the restore guard.
fn alias_command(shell: ShellKind, command: &[u8]) -> Option<Vec<u8>> {
    let commands = shell_commands(command);
    let [Some(words)] = commands.as_slice() else {
        return None;
    };
    let (verb, mut args) = words.split_first()?;
    if verb != b"alias" {
        return None;
    }
    let mut kind: &[u8] = b"";
    if shell == ShellKind::Zsh
        && let Some((flag, rest)) = args.split_first()
        && matches!(flag.as_slice(), b"-g" | b"-s")
    {
        kind = if flag == b"-g" { b"-g " } else { b"-s " };
        args = rest;
    }
    if args.first().is_some_and(|arg| arg == b"--") {
        args = &args[1..];
    }
    let [definition] = args else {
        return None;
    };
    let eq = definition.iter().position(|&b| b == b'=')?;
    let (name, value) = (&definition[..eq], &definition[eq + 1..]);
    let plain_name = |b: &u8| b.is_ascii_graphic() && !b"'\"\\`$;&|<>()=".contains(b);
    if name.is_empty() || !name.iter().all(plain_name) {
        return None;
    }
    let mut out = b"alias ".to_vec();
    out.extend_from_slice(kind);
    out.extend_from_slice(b"-- ");
    push_single_quoted(&mut out, name);
    out.push(b'=');
    push_single_quoted(&mut out, value);
    Some(out)
}

/// What the replay prints when it leaves a sandboxed command's settings out ([`ShellState::replay_script_for`]).
pub(crate) const SETTINGS_WITHHELD_WARNING: &str = "warning: shell settings from a sandboxed command were not carried into this less-sandboxed command";

/// u35: the script the wrapper evaluates to restore `snapshot` as confined as the spawn that wrote it (see
/// [`replay_script_with`]).
#[cfg(test)]
pub(crate) fn replay_script(shell: ShellKind, snapshot: &str) -> Vec<u8> {
    replay_script_with(shell, snapshot, snapshot, false)
}

/// Variables whose value follows the directory or the process, not the user's settings: a difference in them alone
/// is not worth the withheld-settings warning.
fn is_volatile_env_name(name: &[u8]) -> bool {
    matches!(name, b"PWD" | b"OLDPWD" | b"SHLVL" | b"_")
}

/// u46 r3: what a replay restores from one state, every part read as data.
struct Replayed {
    env: Vec<EnvEntry>,
    options: Vec<Vec<u8>>,
    aliases: Vec<Vec<u8>>,
    functions: Vec<u8>,
}

impl Replayed {
    /// `snapshot`'s settings; the startup selectors of the env come from `trusted_env` ([`replayed_env_entries`]).
    fn of(shell: ShellKind, snapshot: &str, trusted_env: &[u8], same_trust: bool) -> Replayed {
        let blocks = snapshot_blocks(snapshot);
        let block = |name: &str| -> &[u8] {
            blocks
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, text)| text.as_slice())
                .unwrap_or_default()
        };
        let option_blocks: &[&str] = match shell {
            ShellKind::Bash => &["POSIX_OPTS_B64", "BASH_OPTS_B64"],
            ShellKind::Zsh => &["ZSH_OPTS_B64"],
        };
        Replayed {
            env: replayed_env_entries(block("ENV_VARS_B64"), trusted_env, same_trust),
            options: option_blocks
                .iter()
                .flat_map(|name| block(name).split(|&b| b == b'\n'))
                .filter(|line| is_replayed_option_line(shell, line))
                .map(<[u8]>::to_vec)
                .collect(),
            aliases: env_block_commands(block("ALIASES_B64"))
                .into_iter()
                .filter_map(|command| alias_command(shell, command))
                .collect(),
            functions: block("FUNCTIONS_B64").trim_ascii().to_vec(),
        }
    }

    /// True when `other` holds the same settings a user would notice missing: everything but the volatile variables.
    fn same_settings(&self, other: &Replayed) -> bool {
        let settled = |r: &Replayed| -> Vec<EnvEntry> {
            r.env
                .iter()
                .filter(|(name, _)| !is_volatile_env_name(name))
                .cloned()
                .collect()
        };
        settled(self) == settled(other)
            && self.options == other.options
            && self.aliases == other.aliases
            && self.functions == other.functions
    }
}

/// The env block of `snapshot`, decoded (empty when it has none).
fn env_block(snapshot: &str) -> Vec<u8> {
    snapshot_blocks(snapshot)
        .into_iter()
        .find(|(name, _)| *name == "ENV_VARS_B64")
        .map(|(_, text)| text)
        .unwrap_or_default()
}

/// u35, u46 r2/r3: the script the wrapper evaluates to restore state, built from decoded blocks read as data so that
/// the replay calls nothing a replayed definition can intercept (no `eval`, `command`, `base64` or `builtin` after the
/// first definition): exports rebuilt from the parsed env, options in the dump's own forms minus tracing
/// ([`is_replayed_option_line`]), then alias expansion off, the aliases rebuilt from their parsed words, and the
/// function definitions last. Defining a function runs nothing (zsh `TRAP*` and hook functions, which do act on
/// definition, are not dumped), and the restore guard runs right after. Text outside the dump's blocks, and blocks of
/// other names, are not replayed.
///
/// `latest` is the current state, `trusted` the state an unconfined spawn last wrote (the same text when the latest
/// producer was unconfined). `less_confined`: the next spawn is less confined than the one that wrote `latest`, so
/// everything comes from `trusted` (the directory is not part of the script), with [`SETTINGS_WITHHELD_WARNING`]
/// printed first when that leaves anything of `latest` out. Startup selectors in the env always come from `trusted`
/// ([`is_startup_env_name`]).
fn replay_script_with(
    shell: ShellKind,
    latest: &str,
    trusted: &str,
    less_confined: bool,
) -> Vec<u8> {
    let trusted_env = env_block(trusted);
    let source = if less_confined { trusted } else { latest };
    let replayed = Replayed::of(shell, source, &trusted_env, !less_confined);
    let aliases_off: &[u8] = match shell {
        ShellKind::Bash => b"builtin shopt -u expand_aliases",
        ShellKind::Zsh => b"builtin unsetopt aliases",
    };
    let mut script = Vec::new();
    let mut push = |text: &[u8]| {
        script.extend_from_slice(text);
        script.push(b'\n');
    };
    if less_confined && !Replayed::of(shell, latest, &trusted_env, true).same_settings(&replayed) {
        // First, before any definition: nothing replayed can stand in for it yet.
        let mut warn = b"builtin printf '%s\\n' ".to_vec();
        push_single_quoted(&mut warn, SETTINGS_WITHHELD_WARNING.as_bytes());
        push(&warn);
    }
    for (name, value) in &replayed.env {
        let mut line = b"export ".to_vec();
        line.extend_from_slice(name);
        if let Some(value) = value {
            line.push(b'=');
            push_single_quoted(&mut line, value);
        }
        push(&line);
    }
    for line in &replayed.options {
        push(line);
    }
    push(aliases_off);
    for alias in &replayed.aliases {
        push(alias);
    }
    push(&replayed.functions);
    // The replay's status is the wrapper's go-ahead; a reserved word, so no definition can stand in for it.
    push(b"[[ -n x ]]");
    script
}

/// Parse a state dump, validating start/end markers.
/// Returns `(cwd, snapshot_rest)` or `None` if markers are missing.
fn parse_dump(shell: ShellKind, raw: &str) -> Option<(PathBuf, String)> {
    let start = shell.start_marker();
    let end = shell.end_marker();

    let start_line = format!("{start}\n");
    let end_line = format!("{end}\n");

    // r1h3: the shell's dump is the last complete frame (a command can write frames of its own into the channel
    // before it): cut at the last end line, then at the last start line before it. Bytes after the last end line
    // are not part of any frame.
    let end_at = raw
        .rmatch_indices(&end_line)
        .map(|(at, _)| at)
        .find(|&at| at == 0 || raw[..at].ends_with('\n'))?;
    let frame = &raw[..end_at + end_line.len()];
    let start_at = frame[..end_at]
        .rmatch_indices(&start_line)
        .map(|(at, _)| at)
        .find(|&at| at == 0 || frame[..at].ends_with('\n'))?;
    let raw = &frame[start_at..];

    // Strip markers
    let without_markers = &raw[start_line.len()..raw.len() - end_line.len()];

    // First line is $PWD
    let newline_pos = without_markers.find('\n')?;
    let cwd = &without_markers[..newline_pos];
    let rest = &without_markers[newline_pos..]; // includes the leading \n

    Some((PathBuf::from(cwd), rest.to_string()))
}

/// Extract the portion of `output` after the first occurrence of `marker\n`.
/// If the marker is not found, returns the full output.
fn parse_after_marker<'a>(output: &'a str, marker: &str) -> &'a str {
    let needle = format!("{marker}\n");
    match output.find(&needle) {
        Some(idx) => &output[idx + needle.len()..],
        None => output,
    }
}

/// Write the snapshot to the state-in pipe, then close the fd.
/// Uses blocking I/O on a dedicated thread (pipes are not regular files).
pub async fn write_snapshot_to_pipe(
    snapshot: impl AsRef<[u8]>,
    fd: OwnedFd,
) -> std::io::Result<()> {
    let data = snapshot.as_ref().to_vec();
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        // Safety: we own the fd.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd.as_raw_fd()) };
        std::mem::forget(fd);
        file.write_all(&data)?;
        file.flush()?;
        drop(file); // closes the fd → child sees EOF on its read end
        Ok(())
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Read the full dump output from the state-out pipe with a timeout.
///
/// If a background process inherits fd 4, the pipe never closes and the reader
/// hangs. The timeout (5s close timeout) prevents this from blocking the actor loop forever. It starts when the
/// command is over (the shell process is gone, or the first dump byte arrived), not at spawn. On timeout, returns an
/// empty string, so marker validation fails and prior state is kept. A reader whose pid is unknown (never
/// `watch_child`ed) keeps a deadline counted from the call.
pub async fn read_dump_from_pipe(pipe: DumpPipe) -> std::io::Result<String> {
    // Ends a FIFO-backed reader's loop when this future ends (normal return, timeout or abort), so no blocking
    // thread outlives its caller and the FIFO is always removed.
    struct CancelOnDrop(Arc<AtomicBool>);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let _cancel_on_drop = CancelOnDrop(Arc::clone(&cancel));
    let DumpPipe {
        fifo,
        fd,
        child_pid,
    } = pipe;
    // Read until either of the END markers appears, *not* until EOF.
    //
    // When the user's command backgrounds a subprocess (`cmd &`), the bg
    // shell inherits fd 4 (the dump pipe's write-end) and keeps it open
    // until *it* exits. The parent shell finishes its dump and exits, but
    // the kernel doesn't close the read-end's EOF until every write-end
    // holder closes theirs. Without marker-driven termination we'd block
    // on `read_to_string` for the entire bg lifetime, hit the 5s safety
    // timeout, and discard the (perfectly complete) dump — which manifests
    // as `cd` / function / alias state silently failing to persist after
    // any command that backgrounds something. (See harness scenarios
    // "State persistence after backgrounded command" and the cd-roundtrip
    // tests for shell state persistence parity.)
    //
    // We additionally cap on `DUMP_READ_TIMEOUT` so a shell that crashed
    // before emitting the END marker doesn't wedge the actor.
    match tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let raw = fd.as_raw_fd();
        let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
        std::mem::forget(fd);
        // Declared after `file`, so it drops first: unlink, then close.
        let fifo_guard = fifo;
        let mut buf = String::new();
        let mut chunk = [0u8; 4096];
        // The dump timeout runs from the end of the command, so a long foreground command keeps its state.
        let mut deadline = (child_pid == 0).then(|| Instant::now() + DUMP_READ_TIMEOUT);
        loop {
            // Wake every 100 ms to notice a cancel and the end of the command (a FIFO the parent holds open
            // for writing too never reaches EOF, and a pipe a background program holds does not either).
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            // Sampled before the poll: bytes written before the shell exited are then already readable.
            let gone = child_gone(child_pid);
            // r1h3: once a complete frame is in hand the reader watches for the shell to exit on a short tick (the
            // shell exits right after writing its dump): a FIFO the parent holds open never reaches EOF, and neither
            // does a pipe a background program still holds a copy of (u46 r2 L1: both channels).
            let tick = if buf.ends_with(&format!("{BASH_STATE_END_MARKER}\n"))
                || buf.ends_with(&format!("{ZSH_STATE_END_MARKER}\n"))
            {
                5
            } else {
                100
            };
            let readable = wait_readable(raw, tick);
            // r1h3: the clock starts when the shell is gone, not at the first byte: a running command can write a
            // forged frame into the channel, and that must not start (or shorten) the wait for the real dump.
            if deadline.is_none() && gone {
                deadline = Some(Instant::now() + DUMP_READ_TIMEOUT);
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(None);
            }
            if gone && !readable {
                // The shell is gone and everything it wrote has been read (a program that kept the channel
                // open would otherwise hold this loop until the deadline).
                break;
            }
            if !readable && fifo_guard.is_none() {
                // A blocking pipe read would stall the loop: only read what is there.
                continue;
            }
            let n = match file.read(&mut chunk) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if child_gone(child_pid) && fifo_guard.is_some() {
                        break;
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };
            if n == 0 {
                // EOF: every write-end holder closed fd 4 (the
                // expected path when no bg subprocess was spawned).
                break;
            }
            buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
            bound_dump_buffer(&mut buf);
            // r1h3: with a known shell pid the dump is the LAST frame, written by the wrapper after the user
            // command, so keep reading until the shell is gone or the channel reaches EOF: a command can write a
            // complete frame of its own into the channel while it runs, and the first END marker is not proof
            // of the shell's dump. Only a reader that does not know the pid (`child_pid == 0`) still stops at the
            // first END marker, as it cannot tell when the command is over.
            if child_pid == 0
                && (buf.contains(BASH_STATE_END_MARKER) || buf.contains(ZSH_STATE_END_MARKER))
            {
                break;
            }
        }
        drop(fifo_guard);
        drop(file);
        Ok(Some(buf))
    })
    .await
    .map_err(std::io::Error::other)?
    {
        Ok(Some(buf)) => Ok(buf),
        Err(e) => Err(e),
        Ok(None) => {
            tracing::warn!(
                "shell state dump read timed out after {}s (END marker never arrived)",
                DUMP_READ_TIMEOUT.as_secs()
            );
            Ok(String::new())
        }
    }
}

/// Most the dump reader keeps while it waits for the last frame (a real dump of a very large environment is far
/// below this).
const DUMP_BUFFER_CAP: usize = 32 * 1024 * 1024;

/// Keep the reader's buffer to a tail: past [`DUMP_BUFFER_CAP`], drop everything before the last start marker (the
/// frame in progress); with no marker in the buffer, drop it all (nothing in it can become a valid frame).
fn bound_dump_buffer(buf: &mut String) {
    if buf.len() <= DUMP_BUFFER_CAP {
        return;
    }
    let last_start = [BASH_STATE_START_MARKER, ZSH_STATE_START_MARKER]
        .iter()
        .filter_map(|marker| buf.rfind(marker))
        .max();
    match last_start {
        Some(at) if at > 0 => {
            buf.drain(..at);
        }
        // One frame alone over the cap is not a dump this reader will install; with no marker nothing can
        // become a valid frame.
        _ => buf.clear(),
    }
}

/// Block up to `ms` milliseconds until `fd` is readable (or hung up).
fn wait_readable(fd: RawFd, ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid `pollfd` that lives across the call.
    unsafe { libc::poll(&mut pfd, 1, ms) > 0 }
}

/// True when the shell `pid` (non-zero, a child of this process) has ended; an unknown pid (0) is never gone.
///
/// u46 r2 (M2, L4): asked with `waitid(WNOWAIT)`, which leaves the child for its owner to reap: an exited child that
/// is not reaped yet (a zombie, as after a timeout kill) counts as gone, which `kill(pid, 0)` cannot tell, and a pid
/// that is no longer this process's child (reaped, then perhaps reused by an unrelated process) is gone as well.
fn child_gone(pid: u32) -> bool {
    let id = libc::id_t::from(pid);
    if pid == 0 {
        return false;
    }
    loop {
        // SAFETY: `info` is a plain-data out parameter that lives across the call.
        let (rc, info) = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            let rc = libc::waitid(
                libc::P_PID,
                id,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            );
            (rc, info)
        };
        if rc == 0 {
            // WNOHANG: a child that is still running leaves `si_pid` zero.
            if siginfo_pid(&info) != 0 {
                return true;
            }
            break;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::ECHILD) => return true,
            _ => break,
        }
    }
    // SAFETY: signal 0 only checks that the process exists.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn siginfo_pid(info: &libc::siginfo_t) -> libc::pid_t {
    // SAFETY: filled in by `waitid` for a child event (or zeroed).
    unsafe { info.si_pid() }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn siginfo_pid(info: &libc::siginfo_t) -> libc::pid_t {
    info.si_pid
}

// ============================================================================
// Tests
// ============================================================================

/// The variables `snapshot` exports when it is replayed: its `export -p` (bash) or `typeset -xp`
/// (zsh) block, decoded and read back. A name exported without a value is left out, and so is
/// every command this does not read in full: nothing is guessed.
pub fn snapshot_exports(snapshot: &str) -> Vec<(OsString, OsString)> {
    let env = env_block(snapshot);
    exports_of(replayed_env_entries(&env, &env, true))
}

fn exports_of(entries: Vec<EnvEntry>) -> Vec<(OsString, OsString)> {
    entries
        .into_iter()
        .filter_map(|(name, value)| Some((OsString::from_vec(name), OsString::from_vec(value?))))
        .collect()
}

impl ShellState {
    /// u46 r3: the variables the next command's replay exports when it runs as confined as the spawn that wrote this
    /// state (what the env judge and the sandbox hook see): [`snapshot_exports`]. A less confined spawn replays the
    /// trusted state's env instead, which was itself the latest state, and judged, when an unconfined spawn wrote it.
    pub fn restored_exports(&self) -> Vec<(OsString, OsString)> {
        snapshot_exports(&self.snapshot)
    }

    /// u46 r4: [`Self::restored_exports`] for a spawn running under `next`: when `next` is less confined than the
    /// producer of this state, its replay exports the trusted state's env ([`Self::replay_script_for`]), so that is
    /// what the env judge must read.
    pub fn restored_exports_for(
        &self,
        next: &crate::sandbox_launch::SpawnConfinement,
    ) -> Vec<(OsString, OsString)> {
        if next.is_less_confined_than(&self.trust.producer) {
            let trusted_env = env_block(self.trusted_snapshot());
            exports_of(replayed_env_entries(&trusted_env, &trusted_env, false))
        } else {
            self.restored_exports()
        }
    }
}

/// `script` as shell commands (split at unquoted newlines and `;`), each a list of words with
/// their quoting removed: `'…'`, `"…"`, `$'…'` and a backslash outside quotes. `None` for a
/// command that needs more than quote removal (an expansion, a subshell, a redirection); an
/// unterminated quote ends the read.
fn shell_commands(script: &[u8]) -> Vec<Option<Vec<Vec<u8>>>> {
    let mut rest = script;
    let mut commands = Vec::new();
    let mut words = Some(Vec::new());
    let mut word: Option<Vec<u8>> = None;
    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        match byte {
            b' ' | b'\t' => end_word(&mut word, &mut words),
            b'\n' | b';' => {
                end_word(&mut word, &mut words);
                if words.as_ref().is_none_or(|words| !words.is_empty()) {
                    commands.push(words.replace(Vec::new()));
                }
            }
            b'\\' => {
                if let Some((&escaped, tail)) = rest.split_first() {
                    rest = tail;
                    if escaped != b'\n' {
                        word.get_or_insert_with(Vec::new).push(escaped);
                    }
                }
            }
            b'\'' => {
                let Some(end) = rest.iter().position(|&b| b == b'\'') else {
                    return commands;
                };
                let (quoted, tail) = rest.split_at(end);
                word.get_or_insert_with(Vec::new).extend_from_slice(quoted);
                rest = tail.get(1..).unwrap_or_default();
            }
            b'"' | b'$' if byte == b'"' || rest.first() == Some(&b'\'') => {
                let quoted = word.get_or_insert_with(Vec::new);
                let read = if byte == b'"' {
                    double_quoted(rest, quoted)
                } else {
                    ansi_c_quoted(rest.get(1..).unwrap_or_default(), quoted)
                };
                let Some((tail, readable)) = read else {
                    return commands;
                };
                rest = tail;
                if !readable {
                    words = None;
                }
            }
            b'$' | b'`' | b'(' | b')' | b'|' | b'&' | b'<' | b'>' => words = None,
            other => word.get_or_insert_with(Vec::new).push(other),
        }
    }
    end_word(&mut word, &mut words);
    if words.as_ref().is_none_or(|words| !words.is_empty()) {
        commands.push(words);
    }
    commands
}

fn end_word(word: &mut Option<Vec<u8>>, words: &mut Option<Vec<Vec<u8>>>) {
    if let (Some(word), Some(words)) = (word.take(), words.as_mut()) {
        words.push(word);
    }
}

/// The rest of a `"…"` word into `word`: what follows the closing quote (`None` when there is
/// none) and whether the word is its text alone. A backslash escapes only `$`, `` ` ``, `"`, `\`
/// and a newline, as in the shell; an unescaped `$` or `` ` `` is an expansion, not text.
fn double_quoted<'a>(mut rest: &'a [u8], word: &mut Vec<u8>) -> Option<(&'a [u8], bool)> {
    let mut readable = true;
    loop {
        let (&byte, tail) = rest.split_first()?;
        rest = tail;
        match byte {
            b'"' => return Some((rest, readable)),
            b'\\' => {
                let (&escaped, tail) = rest.split_first()?;
                rest = tail;
                match escaped {
                    b'$' | b'`' | b'"' | b'\\' => word.push(escaped),
                    b'\n' => {}
                    other => word.extend_from_slice(&[b'\\', other]),
                }
            }
            b'$' | b'`' => readable = false,
            other => word.push(other),
        }
    }
}

/// The rest of a `$'…'` word into `word` with its escapes decoded: what follows the closing quote
/// (`None` when there is none) and whether every escape was one this decodes. `\u`, `\c` and the
/// like are not, and leave the command unread rather than wrong.
fn ansi_c_quoted<'a>(mut rest: &'a [u8], word: &mut Vec<u8>) -> Option<(&'a [u8], bool)> {
    let mut readable = true;
    loop {
        let (&byte, tail) = rest.split_first()?;
        rest = tail;
        if byte == b'\'' {
            return Some((rest, readable));
        }
        if byte != b'\\' {
            word.push(byte);
            continue;
        }
        let (&escaped, tail) = rest.split_first()?;
        rest = tail;
        let decoded = match escaped {
            b'n' => Some(b'\n'),
            b't' => Some(b'\t'),
            b'r' => Some(b'\r'),
            b'a' => Some(0x07),
            b'b' => Some(0x08),
            b'e' | b'E' => Some(0x1b),
            b'f' => Some(0x0c),
            b'v' => Some(0x0b),
            b'\\' | b'\'' | b'"' | b'?' => Some(escaped),
            b'0'..=b'7' | b'x' => {
                let (radix, lead) = if escaped == b'x' {
                    (16, String::new())
                } else {
                    (8, char::from(escaped).to_string())
                };
                let digits = rest
                    .iter()
                    .take_while(|b| char::from(**b).is_digit(radix))
                    .take(2)
                    .count();
                let (more, tail) = rest.split_at(digits);
                rest = tail;
                let text: String = lead
                    .chars()
                    .chain(more.iter().map(|b| char::from(*b)))
                    .collect();
                u32::from_str_radix(&text, radix)
                    .ok()
                    .and_then(|value| u8::try_from(value).ok())
            }
            _ => None,
        };
        match decoded {
            Some(decoded) => word.push(decoded),
            None => readable = false,
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "shell_state_fifo_tests.rs"]
mod fifo_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "shell_state_cli_facing_unchanged_tests.rs"]
mod cli_facing_unchanged_tests;

#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    /// P86: any configured credential name is spliced into the scrub as a literal pattern, so a
    /// hostile `env_key` cannot inject shell syntax and a non-ASCII (zsh-valid) name is still
    /// matched; built-in and plain registered names are scrubbed case-insensitively.
    #[cfg(unix)]
    #[test]
    fn p86_configured_names_reach_the_scrub_as_literal_patterns() {
        // Registered names are upper-cased, so the payloads use no letters: unquoted, each would
        // create a file named by its digit in the working directory.
        let hostile = ["P86_$(:>9)", "P86_`:>8`", "P86_) :>7;; *(", "P86_'; :>6; '"];
        crate::util::shell_env_policy::register_credential_env_names(hostile);
        crate::util::shell_env_policy::register_credential_env_names([
            "P86_SCRUB_CORP_KEY",
            "P86_\u{e9}",
        ]);
        for shell in [ShellKind::Bash, ShellKind::Zsh] {
            let script = shell.credential_scrub("exit 1");
            assert!(script.contains("[pP]86_[sS][cC][rR][uU][bB]_[cC][oO][rR][pP]_[kK][eE][yY]"));
            assert!(script.contains("[fF][lL][uU][xX]_[aA][pP][iI]_[kK][eE][yY]"));
            assert!(script.contains("[pP]86_'\u{e9}'"), "{script}");
        }
        let dir = tempfile::tempdir().unwrap();
        let scrub = ShellKind::Bash.credential_scrub("exit 1");
        let output = std::process::Command::new("bash")
            .current_dir(dir.path())
            .args([
                "-c",
                &format!(
                    "export P86_SCRUB_CORP_KEY=x p86_scrub_corp_key=y KEEP=1; ({scrub}; test -z \"${{P86_SCRUB_CORP_KEY+x}}${{p86_scrub_corp_key+x}}\" && test \"$KEEP\" = 1 && printf ok)"
                ),
            ])
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "ok",
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for digit in ["6", "7", "8", "9"] {
            assert!(
                !dir.path().join(digit).exists(),
                "a registered name ran shell code ({digit})"
            );
        }
        // Still denied to children: only the shell splice quotes it.
        for name in hostile {
            assert!(crate::util::shell_env_policy::is_provider_credential(name));
        }
    }

    /// P86 (Astra r2 #4): the bash scrub still finds a credential when the shell's IFS was
    /// changed (an rc file's `IFS=:` would otherwise make `compgen -e` one word).
    #[cfg(unix)]
    #[test]
    fn p86_bash_scrub_ignores_a_changed_ifs() {
        let scrub = ShellKind::Bash.credential_scrub("exit 1");
        let script = format!(
            "export IFS=: GROQ_API_KEY=fake-p86 P86_SCRUB_KEEP=kept; ({scrub}; test -z \"${{GROQ_API_KEY+x}}\" && test \"$P86_SCRUB_KEEP\" = kept && printf scrubbed)"
        );
        let output = std::process::Command::new("bash")
            .args(["-c", &script])
            .env_remove("GROQ_API_KEY")
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&output.stdout), "scrubbed");
    }

    #[test]
    fn shell_env_overrides_marks_agent_terminal() {
        let env = shell_env_overrides();
        assert_eq!(
            env.get(crate::util::FUIGO_AGENT_ENV).map(String::as_str),
            Some(crate::util::FUIGO_AGENT_ENV_VALUE)
        );
        assert_eq!(env.get("TERM").map(String::as_str), Some("dumb"));
        assert_eq!(env.get("NO_COLOR").map(String::as_str), Some("1"));
    }

    #[test]
    fn parse_dump_valid_bash() {
        let raw = "__FUIGO_BASH_STATE_START__\n\
                    /home/user/project\n\
                    export FOO=bar\n\
                    # end of bash state dump\n\
                    __FUIGO_BASH_STATE_END__\n";
        let (cwd, rest) = parse_dump(ShellKind::Bash, raw).unwrap();
        assert_eq!(cwd, PathBuf::from("/home/user/project"));
        assert!(rest.contains("export FOO=bar"));
    }

    #[test]
    fn parse_dump_valid_zsh() {
        let raw = "__FUIGO_ZSH_STATE_START__\n\
                    /tmp\n\
                    typeset -x FOO=bar\n\
                    # end of zsh state dump\n\
                    __FUIGO_ZSH_STATE_END__\n";
        let (cwd, rest) = parse_dump(ShellKind::Zsh, raw).unwrap();
        assert_eq!(cwd, PathBuf::from("/tmp"));
        assert!(rest.contains("typeset -x FOO=bar"));
    }

    #[test]
    fn parse_dump_missing_start_marker() {
        let raw = "/home/user\nexport FOO=bar\n__FUIGO_BASH_STATE_END__\n";
        assert!(parse_dump(ShellKind::Bash, raw).is_none());
    }

    #[test]
    fn parse_dump_missing_end_marker() {
        let raw = "__FUIGO_BASH_STATE_START__\n/home/user\nexport FOO=bar\n";
        assert!(parse_dump(ShellKind::Bash, raw).is_none());
    }

    #[test]
    fn parse_dump_wrong_shell_markers() {
        let raw = "__FUIGO_ZSH_STATE_START__\n/tmp\nstuff\n__FUIGO_ZSH_STATE_END__\n";
        assert!(parse_dump(ShellKind::Bash, raw).is_none());
    }

    #[test]
    fn parse_dump_empty_snapshot() {
        let raw = "__FUIGO_BASH_STATE_START__\n\
                    /home/user\n\
                    # end of bash state dump\n\
                    __FUIGO_BASH_STATE_END__\n";
        let (cwd, rest) = parse_dump(ShellKind::Bash, raw).unwrap();
        assert_eq!(cwd, PathBuf::from("/home/user"));
        assert!(rest.contains("# end of bash state dump"));
    }

    #[test]
    fn parse_after_marker_found() {
        let output = "Welcome to Ubuntu\nMOTD line\n__FUIGO_INIT_STATE_MARKER__\nactual data\n";
        let result = parse_after_marker(output, "__FUIGO_INIT_STATE_MARKER__");
        assert_eq!(result, "actual data\n");
    }

    #[test]
    fn parse_after_marker_not_found() {
        let output = "just some output\n";
        let result = parse_after_marker(output, "__FUIGO_INIT_STATE_MARKER__");
        assert_eq!(result, output);
    }

    /// Returns true iff a usable bash binary exists at the resolved path.
    /// Used to gate integration tests so they're skipped (rather than failing)
    /// on systems where bash isn't installed (e.g. minimal containers).
    /// On NixOS the resolver returns the nix-store / profile path, so this
    /// guard works there too.
    fn bash_available() -> bool {
        std::path::Path::new(ShellKind::Bash.binary_path()).exists()
    }

    /// Returns true iff a usable zsh binary exists at the resolved path.
    /// Mirrors [`bash_available`] so zsh integration tests skip (rather than
    /// fail) on systems without zsh installed.
    fn zsh_available() -> bool {
        std::path::Path::new(ShellKind::Zsh.binary_path()).exists()
    }

    #[test]
    fn shell_kind_binary_path_resolves_to_correct_kind() {
        // The resolver may pick any absolute path (e.g. `/opt/homebrew/bin/bash`
        // on macOS+brew, `/run/current-system/sw/bin/bash` on NixOS), but the
        // file name must match the requested kind.
        let bash = std::path::Path::new(ShellKind::Bash.binary_path())
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        assert_eq!(bash, "bash", "Bash kind must resolve to a *bash* binary");

        let zsh = std::path::Path::new(ShellKind::Zsh.binary_path())
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        assert_eq!(zsh, "zsh", "Zsh kind must resolve to a *zsh* binary");
    }

    #[test]
    fn shell_state_update_from_dump() {
        let mut state = ShellState {
            cwd: PathBuf::from("/old"),
            snapshot: String::new(),
            shell: ShellKind::Bash,
            trust: Default::default(),
        };

        let dump = "__FUIGO_BASH_STATE_START__\n\
                     /new/dir\n\
                     export X=1\n\
                     # end of bash state dump\n\
                     __FUIGO_BASH_STATE_END__\n";
        assert!(state.update_from_dump(dump));
        assert_eq!(state.cwd, PathBuf::from("/new/dir"));
        assert!(state.snapshot.contains("export X=1"));
    }

    #[test]
    fn shell_state_update_keeps_previous_on_bad_dump() {
        let mut state = ShellState {
            cwd: PathBuf::from("/original"),
            snapshot: "old stuff".into(),
            shell: ShellKind::Bash,
            trust: Default::default(),
        };

        assert!(!state.update_from_dump("garbage output\n"));
        assert_eq!(state.cwd, PathBuf::from("/original"));
        assert_eq!(state.snapshot, "old stuff");
    }

    fn snapshot_with_exports(script: &str) -> String {
        let payload = base64::engine::general_purpose::STANDARD.encode(script);
        format!(
            "\nfuigo_snap_ENV_VARS_B64=$(command base64 -d <<'FUIGO_SNAP_EOF_ENV_VARS_B64'\n\
             {payload}\nFUIGO_SNAP_EOF_ENV_VARS_B64\n)\neval \"$fuigo_snap_ENV_VARS_B64\"\n"
        )
    }

    fn utf8_exports(snapshot: &str) -> Vec<(String, String)> {
        snapshot_exports(snapshot)
            .into_iter()
            .map(|(name, value)| (name.into_string().unwrap(), value.into_string().unwrap()))
            .collect()
    }

    /// The exports a snapshot replays read back through the quoting both shells print: bash's
    /// `declare -x NAME="…"` with its backslash escapes and a multi-line value, zsh's bare,
    /// `'…'` and `$'…'` words, and zsh's tied `export -T` (u46 r2: the replay exports it too). A name
    /// with no value and a word needing an expansion are left out rather than guessed.
    #[test]
    fn snapshot_exports_read_back_both_shells_quoting() {
        let bash = "declare -x PYTHONUSERBASE=\"/opt/py user\"\n\
                    declare -x ESCAPED=\"a\\\"b\\$c\\\\d\\`e\"\n\
                    declare -x MULTI=\"one\ntwo\"\n\
                    declare -x OLDPWD\n\
                    declare -rx READONLY=\"r\"\n";
        let zsh = "export XDG_DATA_HOME=/opt/share\n\
                   export QUOTED='it'\\''s'\n\
                   export ANSI=$'tab\\there\\041'\n\
                   typeset -x EMPTY=''\n\
                   export -T PATHLIKE pathlike=( /a /b )\n\
                   export EXPANDS=\"$HOME\"\n";
        let expected: Vec<(String, String)> = [
            ("PYTHONUSERBASE", "/opt/py user"),
            ("ESCAPED", "a\"b$c\\d`e"),
            ("MULTI", "one\ntwo"),
            ("READONLY", "r"),
            ("XDG_DATA_HOME", "/opt/share"),
            ("QUOTED", "it's"),
            ("ANSI", "tab\there!"),
            ("EMPTY", ""),
            ("PATHLIKE", "/a:/b"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
        assert_eq!(
            expected,
            utf8_exports(&snapshot_with_exports(&format!("{bash}{zsh}")))
        );
        assert!(snapshot_exports("# no exports block\n").is_empty());
    }

    /// A real dump from each shell reads back to the value the shell exported, whatever quoting
    /// the value needs.
    #[tokio::test]
    async fn snapshot_exports_read_back_a_real_dump() {
        let value = "/opt/py user/it's \"q\" $HOME `x` \\ tab\there";
        let policy = crate::util::ShellEnvironmentPolicy {
            set: HashMap::from([("PYTHONUSERBASE".to_owned(), value.to_owned())]),
            ..Default::default()
        };
        let cwd = std::env::current_dir().unwrap();
        for (shell, available) in [
            (ShellKind::Bash, bash_available()),
            (ShellKind::Zsh, zsh_available()),
        ] {
            if !available {
                continue;
            }
            let state = ShellState::init(shell, &cwd, Some(&policy), None, None)
                .await
                .unwrap();
            let exports = utf8_exports(&state.snapshot);
            assert!(
                exports.contains(&("PYTHONUSERBASE".to_owned(), value.to_owned())),
                "{shell:?}: {exports:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_init_bash() {
        // Integration test: actually runs bash and captures state.
        // Skip in environments without bash.
        if !bash_available() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let state = ShellState::init(ShellKind::Bash, &cwd, None, None, None)
            .await
            .unwrap();
        assert!(state.cwd.is_absolute());
        // The snapshot should contain at least some env var exports
        assert!(
            state.snapshot.contains("fuigo_snap_") || state.snapshot.is_empty(),
            "snapshot should contain encoded blocks or be empty: {:?}",
            &state.snapshot[..state.snapshot.len().min(200)]
        );
    }

    #[tokio::test]
    async fn test_prepare_command_and_roundtrip() {
        use command_fds::CommandFdExt;

        // Integration test: prepare a command, spawn it, verify state roundtrip.
        if !bash_available() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None)
            .await
            .unwrap();

        // Run "export FUIGO_TEST_VAR=hello" and capture the new state
        let prep = state
            .prepare_command(
                "export FUIGO_TEST_VAR=hello",
                None,
                crate::computer::local::SearchShadowConfig::default(),
                None,
            )
            .unwrap();

        let mut cmd = tokio::process::Command::new(&prep.binary);
        cmd.args(&prep.args)
            .current_dir(&prep.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        cmd.fd_mappings(prep.fd_mappings).unwrap();

        #[allow(clippy::disallowed_methods)] // test fixture; the test reaps it
        let child = cmd.spawn().unwrap();
        // Drop cmd to release the FdMapping OwnedFds held in its pre_exec closure.
        // Without this, the parent keeps the write-end of the state-out pipe open,
        // and the read task never sees EOF.
        drop(cmd);

        // Write snapshot to fd 3
        let snapshot = state.replay_script();
        let write_handle =
            tokio::spawn(
                async move { write_snapshot_to_pipe(&snapshot, prep.state_in_write).await },
            );

        // Read new dump from fd 4
        let read_handle =
            tokio::spawn(async move { read_dump_from_pipe(prep.state_out_read).await });

        let output = child.wait_with_output().await.unwrap();
        assert!(output.status.success(), "command failed: {:?}", output);

        write_handle.await.unwrap().unwrap();
        let dump = read_handle.await.unwrap().unwrap();

        assert!(
            state.update_from_dump(&dump),
            "dump should have valid markers, got: {:?}",
            &dump[..dump.len().min(500)]
        );
        // The snapshot contains base64-encoded env vars, so the variable name
        // won't appear in plaintext. Verify the dump was valid and non-empty.
        assert!(
            !state.snapshot.is_empty(),
            "snapshot should be non-empty after a successful command"
        );
        assert!(state.cwd.is_absolute(), "cwd should be absolute");
    }

    /// Helper: run a command against a ShellState, update state, return (exit_code, stdout).
    async fn run_command(state: &mut ShellState, command: &str) -> (i32, String) {
        run_command_in(state, command, None).await
    }

    /// [`run_command`] with the shell binary replaced by `binary` (another bash version).
    async fn run_command_in(
        state: &mut ShellState,
        command: &str,
        binary: Option<&str>,
    ) -> (i32, String) {
        run_command_full(state, command, binary, None).await
    }

    /// [`run_command`] for a spawn running under `next` (u46 r2: the replay it gets).
    async fn run_command_under(
        state: &mut ShellState,
        command: &str,
        next: &crate::sandbox_launch::SpawnConfinement,
    ) -> (i32, String) {
        run_command_full(state, command, None, Some(next)).await
    }

    async fn run_command_full(
        state: &mut ShellState,
        command: &str,
        binary: Option<&str>,
        next: Option<&crate::sandbox_launch::SpawnConfinement>,
    ) -> (i32, String) {
        use command_fds::CommandFdExt;

        // A bash given by path is judged by its own version (3.2 gets the FIFO channel), not the resolved one's.
        let prep = match binary {
            Some(binary) => state.prepare_command_for(
                command,
                None,
                crate::computer::local::SearchShadowConfig::default(),
                None,
                probe_bash_major(binary),
            ),
            None => state.prepare_command(
                command,
                None,
                crate::computer::local::SearchShadowConfig::default(),
                None,
            ),
        }
        .unwrap();
        let mut cmd = tokio::process::Command::new(binary.unwrap_or(&prep.binary));
        cmd.args(&prep.args)
            .current_dir(&prep.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd.fd_mappings(prep.fd_mappings).unwrap();
        #[allow(clippy::disallowed_methods)] // test fixture; the test reaps it
        let child = cmd.spawn().unwrap();
        drop(cmd);

        let snapshot = match next {
            Some(next) => state.replay_script_for(next),
            None => state.replay_script(),
        };
        let write_handle =
            tokio::spawn(
                async move { write_snapshot_to_pipe(&snapshot, prep.state_in_write).await },
            );
        let read_handle =
            tokio::spawn(async move { read_dump_from_pipe(prep.state_out_read).await });

        let output = child.wait_with_output().await.unwrap();
        write_handle.await.unwrap().unwrap();
        let dump = read_handle.await.unwrap().unwrap();
        // As the terminal installs a dump: tagged with the spawn's confinement.
        match next {
            Some(next) => state.update_from_dump_by(&dump, next.clone()),
            None => state.update_from_dump(&dump),
        };

        let code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        (code, stdout)
    }

    /// The user command must not hold the state-out descriptor: whatever it writes there would be read ahead of the
    /// shell's own dump.
    #[tokio::test]
    async fn user_command_cannot_write_the_state_dump_descriptor() {
        if !bash_available() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None)
            .await
            .unwrap();
        let (_, stdout) = run_command(&mut state, "echo forged >&4").await;
        assert!(
            stdout.to_lowercase().contains("bad file descriptor"),
            "fd 4 must be closed for the user command, got: {stdout:?}"
        );
        let (code, stdout) = run_command(&mut state, "echo still-works").await;
        assert_eq!(code, 0);
        assert_eq!(stdout.trim(), "still-works");
    }

    /// Audit L3 (delta review): no program the user command runs inherits the state-dump pipe, under any descriptor.
    /// An external program writes a complete forged dump to every descriptor from 3 to 255; had one reached the pipe,
    /// its END marker would cut the shell's own dump short and the state set in the same command would be lost.
    #[tokio::test]
    async fn external_programs_cannot_reach_the_state_dump() {
        for (kind, available, start, end) in [
            (
                ShellKind::Bash,
                bash_available(),
                BASH_STATE_START_MARKER,
                BASH_STATE_END_MARKER,
            ),
            (
                ShellKind::Zsh,
                zsh_available(),
                ZSH_STATE_START_MARKER,
                ZSH_STATE_END_MARKER,
            ),
        ] {
            if !available || !bash_available() {
                continue;
            }
            let cwd = std::env::current_dir().unwrap();
            let mut state = ShellState::init(kind, &cwd, None, None, None)
                .await
                .unwrap();
            // A separate bash process (`/bin/sh` may be dash, which cannot name a descriptor above 9).
            let bash = ShellKind::Bash.binary_path();
            let forge = format!(
                "export L3_KEPT=yes; {bash} -c 'i=3; while [ $i -le 255 ]; do \
                 (printf \"%s\\nexport L3_FORGED=1\\n%s\\n\" {start} {end} >&$i) 2>/dev/null; i=$((i+1)); done'"
            );
            run_command(&mut state, &forge).await;
            let (_, stdout) =
                run_command(&mut state, "echo ${L3_KEPT:-lost} ${L3_FORGED:-clean}").await;
            assert_eq!(
                stdout.trim(),
                "yes clean",
                "{kind:?}: an external program reached the dump pipe"
            );
        }
    }

    #[tokio::test]
    async fn test_cd_persists_across_commands() {
        if !bash_available() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None)
            .await
            .unwrap();

        // cd to /tmp (macOS resolves to /private/tmp via symlink)
        let (code, _) = run_command(&mut state, "cd /tmp").await;
        assert_eq!(code, 0);

        // Next command should see the resolved /tmp as cwd
        let (code, stdout) = run_command(&mut state, "pwd").await;
        assert_eq!(code, 0);
        let actual_pwd = stdout.trim();
        assert!(
            actual_pwd == "/tmp" || actual_pwd == "/private/tmp",
            "cwd should be /tmp or /private/tmp, got: {actual_pwd}"
        );
        assert_eq!(state.cwd.to_str().unwrap(), actual_pwd);
    }

    #[tokio::test]
    async fn test_env_var_persists_across_commands() {
        if !bash_available() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None)
            .await
            .unwrap();

        // Export a variable
        let (code, _) = run_command(&mut state, "export MY_TEST_VAR=persistent_value").await;
        assert_eq!(code, 0);

        // Next command should see it
        let (code, stdout) = run_command(&mut state, "echo $MY_TEST_VAR").await;
        assert_eq!(code, 0);
        assert_eq!(stdout.trim(), "persistent_value");
    }

    /// GPG_TTY exported in one command must not be replayed into the next via the snapshot.
    #[tokio::test]
    async fn test_gpg_tty_excluded_from_snapshot_bash() {
        if !bash_available() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None)
            .await
            .unwrap();

        let (code, _) = run_command(&mut state, "export GPG_TTY=/fuigo-sentinel-tty").await;
        assert_eq!(code, 0);

        let (code, stdout) = run_command(&mut state, "echo \"[$GPG_TTY]\"").await;
        assert_eq!(code, 0);
        assert!(
            !stdout.contains("/fuigo-sentinel-tty"),
            "GPG_TTY must not persist across commands via the snapshot, got: {stdout:?}"
        );
    }

    /// Same as the bash case, exercising the zsh `typeset -xp` dump grep.
    #[tokio::test]
    async fn test_gpg_tty_excluded_from_snapshot_zsh() {
        if !zsh_available() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Zsh, &cwd, None, None, None)
            .await
            .unwrap();

        let (code, _) = run_command(&mut state, "export GPG_TTY=/fuigo-sentinel-tty").await;
        assert_eq!(code, 0);

        let (code, stdout) = run_command(&mut state, "echo \"[$GPG_TTY]\"").await;
        assert_eq!(code, 0);
        assert!(
            !stdout.contains("/fuigo-sentinel-tty"),
            "GPG_TTY must not persist across commands via the snapshot, got: {stdout:?}"
        );
    }

    /// Unmatched globs must not abort with NOMATCH after login snapshot restore.
    #[tokio::test]
    async fn test_zsh_unmatched_glob_does_not_abort() {
        if !zsh_available() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Zsh, &cwd, None, None, None)
            .await
            .unwrap();

        let prep = state
            .prepare_command(
                "true",
                None,
                crate::computer::local::SearchShadowConfig::default(),
                None,
            )
            .unwrap();
        let wrapper = prep
            .args
            .iter()
            .find(|a| a.contains("builtin eval"))
            .expect("zsh wrapper should be in prepare_command args");
        let snap_pos = wrapper
            .find("eval \"$snap\"")
            .expect("wrapper must restore snapshot via eval \"$snap\"");
        let nonomatch_pos = wrapper
            .find("setopt nonomatch")
            .expect("wrapper must force nonomatch after snapshot restore");
        assert!(
            nonomatch_pos > snap_pos,
            "nonomatch must be forced after snapshot eval, wrapper={wrapper:?}"
        );

        let pattern = "--include=*.no_such_ext_xyz_12345";
        let (code, stdout) = run_command(&mut state, &format!("printf '%s\\n' {pattern}")).await;
        assert_eq!(code, 0, "unmatched glob must not fail, stdout={stdout:?}");
        assert!(
            stdout.contains(pattern),
            "expected literal unmatched glob in output, got: {stdout:?}"
        );
        assert!(
            !stdout.contains("no matches found"),
            "NOMATCH error must not appear, got: {stdout:?}"
        );
    }

    /// A user `.zshrc` that replaces `run-help` (oh-my-zsh and distro rc files alias it to
    /// `man` or redefine it) and aliases `grep` must not break replay. The wrapper turns
    /// aliases off, runs `unalias -m '*'`, and evals the snapshot (functions before aliases),
    /// so a function body is never alias-expanded at definition time. (u35: `grep` is a safe-listed
    /// program name, so the restore guard then disables the replayed `grep` alias.) The snapshot here is produced by the
    /// real init path (`-ilc` dump) from a real startup file, not hand-written.
    #[tokio::test]
    async fn test_zsh_startup_run_help_and_grep_alias_replay() {
        if !zsh_available() {
            return;
        }
        let variants = [
            (
                "alias",
                "alias run-help=man\nalias grep=\"grep --color=never\"",
            ),
            (
                "function",
                "run-help() { echo hijacked-run-help; }\nalias grep=\"grep --color=never\"",
            ),
            (
                "function-then-alias",
                "run-help() { echo hijacked-run-help; }\nalias run-help=man\nalias grep=\"grep --color=never\"",
            ),
        ];
        for (name, rc) in variants {
            let zdotdir = tempfile::tempdir().unwrap();
            std::fs::write(zdotdir.path().join(".zshrc"), format!("{rc}\n")).unwrap();
            let dump = ShellKind::Zsh.dump_script();
            let script = format!(
                "{dump} builtin printf '{INIT_STATE_MARKER}\\n'; {}",
                ShellKind::Zsh.dump_function_name()
            );
            let out = std::process::Command::new(ShellKind::Zsh.binary_path())
                .args(["-o", "extendedglob", "-ilc", &script])
                .env("ZDOTDIR", zdotdir.path())
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .unwrap();
            let full = String::from_utf8_lossy(&out.stdout).into_owned();
            let (cwd, snapshot) =
                parse_dump(ShellKind::Zsh, parse_after_marker(&full, INIT_STATE_MARKER))
                    .unwrap_or_else(|| panic!("[{name}] dump must parse, got: {full:?}"));
            let mut state = ShellState {
                cwd,
                snapshot,
                shell: ShellKind::Zsh,
                trust: Default::default(),
            };

            // `grep` is aliased to `grep --color=never` in the startup file: the replayed alias is the user
            // environment, but the wrapper itself (and its `command grep` dump filters) must not
            // be affected, so the dump still round-trips and the command runs.
            let (code, stdout) = run_command(&mut state, "printf 'a\\nb\\n' | grep b").await;
            assert_eq!(
                code, 0,
                "[{name}] command using grep must succeed, stdout={stdout:?}"
            );
            assert_eq!(stdout.trim(), "b", "[{name}] unexpected output: {stdout:?}");

            // State dumped after the run must still replay (functions + aliases survived).
            let (code, stdout) = run_command(&mut state, "echo still-alive").await;
            assert_eq!(
                code, 0,
                "[{name}] second command must run, stdout={stdout:?}"
            );
            assert!(stdout.contains("still-alive"), "[{name}] got {stdout:?}");
            assert!(
                !stdout.contains("parse error")
                    && !stdout.contains("defining function based on alias"),
                "[{name}] replay must not hit alias-expansion errors: {stdout:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_function_persists_across_commands() {
        if !bash_available() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None)
            .await
            .unwrap();

        // Define a function
        let (code, _) = run_command(&mut state, "greet() { echo \"hello $1\"; }").await;
        assert_eq!(code, 0);

        // Call it in the next command
        let (code, stdout) = run_command(&mut state, "greet world").await;
        assert_eq!(code, 0);
        assert_eq!(stdout.trim(), "hello world");
    }

    /// Regression test: a script sourced WITHOUT arguments by the user command
    /// must not see the wrapper's positional parameters ($1 = the whole
    /// command string, $2 = the spawn notice). Conda's `bin/activate` forwards
    /// "$@" to `conda activate`, so a leak makes every `activate_conda`-
    /// prefixed command fail with `EnvironmentLocationNotFound: Not a conda
    /// environment: <cwd>/<the entire command string>`.
    #[tokio::test]
    async fn test_sourced_script_does_not_inherit_wrapper_positional_args_bash() {
        if !bash_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let probe = dir.path().join("activate_probe.sh");
        std::fs::write(&probe, "echo \"SOURCED_ARGC=$#\"\n").unwrap();

        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None)
            .await
            .unwrap();

        let (code, stdout) = run_command(
            &mut state,
            &format!("source {} && echo AFTER_SOURCE_OK", probe.display()),
        )
        .await;
        assert_eq!(code, 0, "command failed, stdout={stdout:?}");
        assert!(
            stdout.contains("SOURCED_ARGC=0"),
            "sourced script must see zero positional args, got: {stdout:?}"
        );
        assert!(stdout.contains("AFTER_SOURCE_OK"), "got: {stdout:?}");
    }

    /// Regression test: with `allexport` active (restored from the snapshot
    /// after the model runs `set -a`), the wrapper's `__fuigo_user_cmd` temp
    /// variable must not leak into child-process environments or persist into
    /// subsequent commands via the state dump.
    #[tokio::test]
    async fn test_user_cmd_var_not_exported_under_allexport_bash() {
        if !bash_available() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None)
            .await
            .unwrap();

        // Turn on allexport; the option is captured by the dump and replayed
        // into every subsequent command's shell.
        let (code, _) = run_command(&mut state, "set -a").await;
        assert_eq!(code, 0);

        // This command's wrapper assigns __fuigo_user_cmd under allexport.
        // printenv only sees exported vars — it must not see the temp var
        // (neither from this command's own assignment nor re-exported from a
        // previous command's state dump).
        let (code, stdout) = run_command(
            &mut state,
            "printenv __fuigo_user_cmd >/dev/null 2>&1 && echo LEAKED_TO_ENV || echo ENV_CLEAN",
        )
        .await;
        assert_eq!(code, 0);
        assert!(
            stdout.contains("ENV_CLEAN") && !stdout.contains("LEAKED_TO_ENV"),
            "temp var must not be exported to child processes under allexport, got: {stdout:?}"
        );
    }

    /// Same as the bash variant: zsh's `source`/`.` also inherits the caller's
    /// positional parameters when invoked without arguments.
    #[tokio::test]
    async fn test_sourced_script_does_not_inherit_wrapper_positional_args_zsh() {
        if !zsh_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let probe = dir.path().join("activate_probe.sh");
        std::fs::write(&probe, "echo \"SOURCED_ARGC=$#\"\n").unwrap();

        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Zsh, &cwd, None, None, None)
            .await
            .unwrap();

        let (code, stdout) = run_command(
            &mut state,
            &format!("source {} && echo AFTER_SOURCE_OK", probe.display()),
        )
        .await;
        assert_eq!(code, 0, "command failed, stdout={stdout:?}");
        assert!(
            stdout.contains("SOURCED_ARGC=0"),
            "sourced script must see zero positional args, got: {stdout:?}"
        );
        assert!(stdout.contains("AFTER_SOURCE_OK"), "got: {stdout:?}");
    }

    #[tokio::test]
    async fn test_alias_persists_across_commands() {
        if !bash_available() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None)
            .await
            .unwrap();

        // Define an alias
        let (code, _) = run_command(&mut state, "alias ll='ls -la'").await;
        assert_eq!(code, 0);

        // Verify the alias survives by checking the dump itself (base64-encoded).
        // We can't check plaintext in the snapshot since it's base64, but we can
        // verify the snapshot is valid and non-empty (alias was captured in the dump).
        assert!(
            !state.snapshot.is_empty(),
            "snapshot should be non-empty after alias"
        );
    }

    #[tokio::test]
    async fn test_embedded_search_shadows() {
        use super::super::embedded_search_tools::search_injection;
        let shadows = crate::computer::local::SearchShadowConfig::default();
        if !bash_available() {
            return;
        }
        let inject = search_injection(shadows);
        if inject.is_empty() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None)
            .await
            .unwrap();

        let prep = state.prepare_command("true", None, shadows, None).unwrap();
        // Shadows enabled → the self-resolving find/grep functions are always
        // installed (they fall back to the OS binary if bfs/ugrep aren't found).
        assert!(
            prep.args
                .iter()
                .any(|a| a.contains("find()") && a.contains("grep()")),
            "prepare_command should install find/grep shadows; args={:?}",
            prep.args
        );

        let (code, stdout) = run_command(&mut state, "type -t find && type -t grep").await;
        assert_eq!(code, 0, "type -t find/grep failed: {stdout}");
        assert_eq!(
            stdout.lines().filter(|l| l.trim() == "function").count(),
            2,
            "expected find and grep to both be shell functions, got: {stdout:?}"
        );

        // Only assert the binary actually routes to ugrep when ugrep resolves on
        // this host; otherwise the shadow correctly falls back to OS grep.
        if which::which("ugrep").is_ok() {
            let (code, stdout) = run_command(&mut state, "grep --version | head -3").await;
            assert_eq!(code, 0, "grep --version failed: {stdout}");
            assert!(
                stdout.to_ascii_lowercase().contains("ugrep"),
                "expected ugrep in --version output when ugrep resolves: {stdout:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_bad_command_preserves_state() {
        if !bash_available() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None)
            .await
            .unwrap();

        // Set up some state
        let (_, _) = run_command(&mut state, "export SURVIVE_TEST=yes").await;
        let prev_cwd = state.cwd.clone();

        // Run a failing command — state should still update (dump runs regardless)
        let (code, _) = run_command(&mut state, "false").await;
        assert_ne!(code, 0);

        // Previous state should still be there
        assert_eq!(state.cwd, prev_cwd);
        let (_, stdout) = run_command(&mut state, "echo $SURVIVE_TEST").await;
        assert_eq!(stdout.trim(), "yes");
    }

    /// u35: a state whose snapshot carries `script` as its functions block, the last thing the replay evaluates.
    fn raw_state(shell: ShellKind, script: &str) -> ShellState {
        ShellState {
            cwd: std::env::current_dir().unwrap(),
            snapshot: encoded_blocks(&[("FUNCTIONS_B64", script)]),
            shell,
            trust: Default::default(),
        }
    }

    /// Snapshot text in the dump's block format.
    fn encoded_blocks(blocks: &[(&str, &str)]) -> String {
        blocks
            .iter()
            .map(|(name, text)| {
                let payload = base64::engine::general_purpose::STANDARD.encode(text);
                format!(
                    "fuigo_snap_{name}=$(command base64 -d <<'FUIGO_SNAP_EOF_{name}'\n{payload}\n\
                     FUIGO_SNAP_EOF_{name}\n)\neval \"$fuigo_snap_{name}\"\n"
                )
            })
            .collect()
    }

    /// u35: a restored `set -k` must not turn a later plain `NAME=value` argument into an environment assignment.
    #[tokio::test]
    async fn u35_restored_keyword_option_does_not_reinterpret_plain_args_bash() {
        if !bash_available() {
            return;
        }
        // The option line exactly as the dump's `shopt -po` writes it.
        let mut state = raw_state(ShellKind::Bash, "set -o keyword\n");
        let (code, stdout) = run_command(&mut state, "echo FOO=bar").await;
        assert_eq!(code, 0, "{stdout:?}");
        assert_eq!(
            stdout.trim(),
            "FOO=bar",
            "restored keyword option changed a plain argument"
        );
    }

    /// u35: zsh `EQUALS` (`=name` becomes a path) is forced off, so a plain `=name` argument stays literal.
    #[tokio::test]
    async fn u35_restored_equals_option_does_not_reinterpret_plain_args_zsh() {
        if !zsh_available() {
            return;
        }
        let mut state = raw_state(ShellKind::Zsh, "builtin setopt equals magicequalsubst\n");
        let (code, stdout) = run_command(&mut state, "echo =ls").await;
        assert_eq!(code, 0, "{stdout:?}");
        assert_eq!(
            stdout.trim(),
            "=ls",
            "restored EQUALS option changed a plain argument"
        );
    }

    /// u35: replayed functions and aliases named after safe-listed programs (or after the builtins the wrapper uses,
    /// or the command-not-found hook) never run in place of the real program.
    #[tokio::test]
    async fn u35_replayed_shadows_of_safe_listed_programs_are_dropped_bash() {
        if !bash_available() {
            return;
        }
        let mut state = raw_state(
            ShellKind::Bash,
            "builtin() { echo SHADOW; }\nunset() { echo SHADOW; }\nlocal() { echo SHADOW; }\n\
             ls() { echo SHADOW; }\npython3.99() { echo SHADOW; }\n\
             command_not_found_handle() { echo SHADOW; }\nalias wc='echo SHADOW'\nalias printf='echo SHADOW'\n",
        );
        let (_, stdout) = run_command(
            &mut state,
            "ls -d /\nwc -c /dev/null\nprintf '%s\\n' plain-ok\npython3.99 --version",
        )
        .await;
        assert!(
            !stdout.contains("SHADOW"),
            "a replayed shadow ran: {stdout:?}"
        );
        assert!(stdout.lines().any(|l| l.trim() == "/"), "{stdout:?}");
        assert!(
            stdout.contains("0 /dev/null") && stdout.contains("plain-ok"),
            "{stdout:?}"
        );
        // The shadows are gone from the next snapshot as well.
        let (_, stdout) = run_command(&mut state, "ls -d /").await;
        assert_eq!(stdout.trim(), "/");
    }

    /// u35: the zsh guard disables shadowing functions and aliases (including `builtin` itself), `TRAP*` functions,
    /// and every global and suffix alias.
    #[tokio::test]
    async fn u35_replayed_shadows_of_safe_listed_programs_are_dropped_zsh() {
        if !zsh_available() {
            return;
        }
        let mut state = raw_state(
            ShellKind::Zsh,
            "builtin() { echo SHADOW; }\nls() { echo SHADOW; }\nTRAPZERR() { echo SHADOW; }\n\
             alias wc='echo SHADOW'\nalias -g GLOBAL_WORD='; echo SHADOW'\nalias -s txt='echo SHADOW'\n",
        );
        let (_, stdout) = run_command(
            &mut state,
            "ls -d /\nwc -c /dev/null\necho GLOBAL_WORD\nfalse",
        )
        .await;
        assert!(
            !stdout.contains("SHADOW"),
            "a replayed shadow ran: {stdout:?}"
        );
        assert!(stdout.lines().any(|l| l.trim() == "/"), "{stdout:?}");
        assert!(
            stdout.contains("0 /dev/null") && stdout.contains("GLOBAL_WORD"),
            "{stdout:?}"
        );
    }

    /// u35: a shadow the guard cannot remove (a read-only function) refuses the command instead of running it.
    #[tokio::test]
    async fn u35_unremovable_shadow_refuses_the_command_bash() {
        if !bash_available() {
            return;
        }
        let mut state = raw_state(ShellKind::Bash, "ls() { echo SHADOW; }\nreadonly -f ls\n");
        let (code, stdout) = run_command(&mut state, "echo RAN; ls -d /").await;
        assert_ne!(code, 0);
        assert!(
            !stdout.contains("RAN") && !stdout.contains("SHADOW"),
            "{stdout:?}"
        );
    }

    /// g5a: every bash on this machine (the resolved one, `/bin/bash`, and any listed in `FUIGO_TEST_EXTRA_BASH`,
    /// colon-separated; on macOS `/bin/bash` is 3.2).
    fn bash_binaries() -> Vec<String> {
        let mut found: Vec<String> = vec![
            ShellKind::Bash.binary_path().to_owned(),
            "/bin/bash".to_owned(),
        ];
        if let Ok(extra) = std::env::var("FUIGO_TEST_EXTRA_BASH") {
            found.extend(
                extra
                    .split(':')
                    .filter(|p| !p.is_empty())
                    .map(str::to_owned),
            );
        }
        found.retain(|p| std::path::Path::new(p).exists());
        found.dedup();
        found
    }

    /// g5a: the guard works on bash 3.2 through 5.x: an empty snapshot runs the command, functions named `[` and `ls`
    /// are dropped (`[` only outside POSIX mode on 3.2), and a read-only `[` function refuses the command.
    #[tokio::test]
    async fn u35_guard_runs_on_every_available_bash() {
        for bash in bash_binaries() {
            let mut state = raw_state(ShellKind::Bash, "");
            state.snapshot.clear();
            let (code, stdout) = run_command_in(&mut state, "echo plain-ok", Some(&bash)).await;
            assert_eq!(
                (code, stdout.trim()),
                (0, "plain-ok"),
                "{bash}: empty snapshot"
            );
            // That bash's own dump replays: a function, an alias and an export persist.
            let define = "g5a_fn() { echo FN; }; alias g5a_al='echo AL'; export G5A=v";
            assert_eq!(
                run_command_in(&mut state, define, Some(&bash)).await.0,
                0,
                "{bash}"
            );
            let (code, stdout) =
                run_command_in(&mut state, "g5a_fn; g5a_al; echo \"$G5A\"", Some(&bash)).await;
            assert_eq!(
                (code, stdout.split_whitespace().collect::<Vec<_>>()),
                (0, vec!["FN", "AL", "v"]),
                "{bash}"
            );

            let mut state = raw_state(
                ShellKind::Bash,
                "function [ { echo SHADOW; }\nls() { echo SHADOW; }\n",
            );
            let (code, stdout) =
                run_command_in(&mut state, "[ -d / ] && echo DIR; ls -d /", Some(&bash)).await;
            assert_eq!(code, 0, "{bash}: {stdout:?}");
            assert!(
                !stdout.contains("SHADOW") && stdout.contains("DIR"),
                "{bash}: {stdout:?}"
            );
            assert!(
                stdout.lines().any(|l| l.trim() == "/"),
                "{bash}: {stdout:?}"
            );

            let mut state = raw_state(
                ShellKind::Bash,
                "function [ { echo SHADOW; }\nreadonly -f '['\n",
            );
            let (code, stdout) = run_command_in(&mut state, "echo RAN", Some(&bash)).await;
            assert_ne!(code, 0, "{bash}: {stdout:?}");
            assert!(!stdout.contains("RAN"), "{bash}: {stdout:?}");
        }
    }

    /// g5a: functions an earlier command defined named after what the old replay called (`eval`, `command`) never run
    /// during the replay: it calls nothing after the first definition, and the guard then drops them.
    #[tokio::test]
    async fn u35_replay_calls_nothing_a_replayed_function_can_intercept() {
        for (shell, available) in [
            (ShellKind::Bash, bash_available()),
            (ShellKind::Zsh, zsh_available()),
        ] {
            if !available {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let mark = dir.path().join("mark");
            let mut state = raw_state(shell, "");
            state.snapshot.clear();
            let define = format!(
                "eval() {{ : >> '{m}'; builtin eval \"$@\"; }}; command() {{ : >> '{m}'; builtin command \"$@\"; }}; \
                 alias fuigo_probe_alias=true",
                m = mark.display()
            );
            run_command(&mut state, &define).await;
            let _ = std::fs::remove_file(&mark);
            let (code, stdout) = run_command(&mut state, "echo after").await;
            assert_eq!((code, stdout.trim()), (0, "after"), "{shell:?}");
            assert!(
                !mark.exists(),
                "{shell:?}: a replayed eval/command function ran"
            );
        }
    }

    /// u35 g6 (Astra r5 Low): a multiline alias makes the guard's alias loop skip continuation lines; a replayed
    /// `continue` function must not run there (it could define `ls` again after the functions were dropped).
    #[tokio::test]
    async fn u35_replayed_continue_does_not_run_in_the_guard_bash() {
        for bash in bash_binaries() {
            let mut state = raw_state(ShellKind::Bash, "");
            state.snapshot.clear();
            let define =
                "alias g6_multi='echo one\necho two'; continue() { ls() { echo SHADOW; }; }";
            assert_eq!(
                run_command_in(&mut state, define, Some(&bash)).await.0,
                0,
                "{bash}"
            );
            let (_, stdout) = run_command_in(&mut state, "ls -d /", Some(&bash)).await;
            assert!(
                !stdout.contains("SHADOW"),
                "{bash}: a replayed continue() ran in the guard: {stdout:?}"
            );
            assert!(
                stdout.lines().any(|l| l.trim() == "/"),
                "{bash}: {stdout:?}"
            );
        }
    }

    /// g5a: zsh `TRAPDEBUG`, `zshexit` and `chpwd` defined by an earlier command do not run in a later one (they are
    /// not dumped, and the guard disables them).
    #[tokio::test]
    async fn u35_trap_and_hook_functions_are_not_replayed_zsh() {
        if !zsh_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mark = |n: &str| dir.path().join(n);
        let mut state = raw_state(ShellKind::Zsh, "");
        state.snapshot.clear();
        let define = format!(
            "TRAPDEBUG() {{ : >> '{}'; }}; zshexit() {{ : >> '{}'; }}; chpwd() {{ : >> '{}'; }}",
            mark("debug").display(),
            mark("exit").display(),
            mark("chpwd").display()
        );
        run_command(&mut state, &define).await;
        for name in ["debug", "exit", "chpwd"] {
            let _ = std::fs::remove_file(mark(name));
        }
        let target = dir.path().display().to_string();
        let (code, stdout) = run_command(&mut state, &format!("cd '{target}'; echo after")).await;
        assert_eq!((code, stdout.trim()), (0, "after"));
        for name in ["debug", "exit", "chpwd"] {
            assert!(!mark(name).exists(), "the replayed {name} hook ran");
        }
    }

    /// g5a: a replayed `xtrace` and an exported `PS4` with a command substitution never run it: the replay leaves the
    /// `xtrace` line out, and the guard turns `xtrace` off and resets `PS4` (zsh also `PROMPT_SUBST`), so neither a
    /// later plain command nor a plain `set -x` expands the replayed `PS4`.
    #[tokio::test]
    async fn u35_replayed_xtrace_does_not_expand_a_replayed_ps4() {
        for (shell, available, setup) in [
            (ShellKind::Bash, bash_available(), ""),
            (ShellKind::Zsh, zsh_available(), "setopt promptsubst; "),
        ] {
            if !available {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let mark = dir.path().join("mark");
            let mut state = raw_state(shell, "");
            state.snapshot.clear();
            run_command(
                &mut state,
                &format!("{setup}export PS4='$(: >> {})+ '", mark.display()),
            )
            .await;
            assert!(!mark.exists(), "{shell:?}: PS4 expanded without xtrace");
            run_command(&mut state, "set -x").await;
            assert!(
                !mark.exists(),
                "{shell:?}: set -x expanded the replayed PS4"
            );
            let (code, stdout) = run_command(&mut state, "echo after").await;
            assert_eq!((code, stdout.trim()), (0, "after"), "{shell:?}");
            assert!(
                !mark.exists(),
                "{shell:?}: the replayed xtrace expanded PS4"
            );
        }
    }

    /// g5a (Fable r4): the zsh fail-closed path. A snapshot that replaces the `functions` hash keeps a shadow the guard
    /// cannot see, so the command is refused.
    #[tokio::test]
    async fn u35_unremovable_shadow_refuses_the_command_zsh() {
        if !zsh_available() {
            return;
        }
        let mut state = raw_state(
            ShellKind::Zsh,
            "unset functions\ntypeset -A functions\nls() { echo SHADOW; }\n",
        );
        let (code, stdout) = run_command(&mut state, "echo RAN; ls -d /").await;
        assert_ne!(code, 0);
        assert!(
            !stdout.contains("RAN") && !stdout.contains("SHADOW"),
            "{stdout:?}"
        );
    }

    /// g5a (Fable r4): bash `histexpand` restored from the options block is forced off, so `!` in a plain word stays.
    #[tokio::test]
    async fn u35_restored_histexpand_does_not_change_plain_args_bash() {
        if !bash_available() {
            return;
        }
        let mut state = raw_state(ShellKind::Bash, "");
        state.snapshot = encoded_blocks(&[("POSIX_OPTS_B64", "set -o histexpand\n")]);
        let (code, stdout) = run_command(&mut state, "echo hi!x").await;
        assert_eq!((code, stdout.trim()), (0, "hi!x"));
    }

    /// g5a (Fable r4): zsh `AUTO_CD` restored from the options block is forced off, so a directory name in command
    /// position does not change directory.
    #[tokio::test]
    async fn u35_restored_auto_cd_does_not_change_directory_zsh() {
        if !zsh_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let target = dunce::canonicalize(dir.path())
            .unwrap()
            .display()
            .to_string();
        let mut state = raw_state(ShellKind::Zsh, "");
        state.snapshot = encoded_blocks(&[(
            "ZSH_OPTS_B64",
            "builtin setopt autocd 2>/dev/null || true\n",
        )]);
        let (_, stdout) = run_command(&mut state, &format!("{target}\npwd -P")).await;
        assert_ne!(
            stdout.lines().last().map(str::trim),
            Some(target.as_str()),
            "{stdout:?}"
        );
    }

    /// g5a (Fable r4): a shadow an earlier command defined is dropped from the next command (both shells).
    #[tokio::test]
    async fn u35_shadow_from_an_earlier_command_is_dropped() {
        for (shell, available) in [
            (ShellKind::Bash, bash_available()),
            (ShellKind::Zsh, zsh_available()),
        ] {
            if !available {
                continue;
            }
            let mut state = raw_state(shell, "");
            state.snapshot.clear();
            run_command(&mut state, "ls() { echo SHADOW; }").await;
            let (code, stdout) = run_command(&mut state, "ls -d /").await;
            assert_eq!((code, stdout.trim()), (0, "/"), "{shell:?}");
        }
    }

    // -----------------------------------------------------------------------------------------------------------
    // u46 r2: state replay is data across a per-call trust boundary. The env block replays from its parsed exports,
    // option and alias lines only in the dump's own forms, and functions (code) only into a spawn no less confined
    // than the one that wrote them.
    // -----------------------------------------------------------------------------------------------------------

    fn available_shells() -> Vec<ShellKind> {
        let mut shells = Vec::new();
        if bash_available() {
            shells.push(ShellKind::Bash);
        }
        if zsh_available() {
            shells.push(ShellKind::Zsh);
        }
        shells
    }

    /// A hostile env block (as a forged frame would carry it): `eval`, a top-level command, `+=` appends to denied
    /// names, a nameref onto a denied name. None of it runs or installs a denied variable; a plain export carries.
    #[tokio::test]
    async fn u46_hostile_env_block_replays_as_data_only() {
        for shell in available_shells() {
            let dir = tempfile::tempdir().unwrap();
            let mark = dir.path().join("mark");
            let env = format!(
                "eval 'export SUDO_ASKPASS=/tmp/ask'\n\
                 X=1; touch {mark}\n\
                 export SSH_AUTH_SOCK+=/tmp/s\n\
                 export http_proxy+=http://h\n\
                 declare -x -n r=SUDO_ASKPASS\n\
                 export r=/x\n\
                 export KEPT='a b'\n",
                mark = mark.display()
            );
            let mut state = ShellState {
                cwd: std::env::current_dir().unwrap(),
                snapshot: encoded_blocks(&[("ENV_VARS_B64", &env)]),
                shell,
                trust: Default::default(),
            };
            let (_, stdout) = run_command(
                &mut state,
                r#"printf 'ASK=%s SOCK=%s HP=%s KEPT=%s\n' "${SUDO_ASKPASS-unset}" "${SSH_AUTH_SOCK-unset}" "${http_proxy-unset}" "${KEPT-unset}""#,
            )
            .await;
            for gone in ["/tmp/ask", "/tmp/s", "http://h", "ASK=/x"] {
                assert!(
                    !stdout.contains(gone),
                    "{shell:?}: {gone} reached the command: {stdout:?}"
                );
            }
            assert!(stdout.contains("KEPT=a b"), "{shell:?}: {stdout:?}");
            assert!(!mark.exists(), "{shell:?}: a command in the env block ran");
        }
    }

    /// Option and alias blocks keep only lines in the dump's own forms: a legit option and alias carry, anything
    /// else (a command after an option, a second command on an alias line, a bare command) is dropped.
    #[tokio::test]
    async fn u46_hostile_option_and_alias_lines_are_dropped() {
        for shell in available_shells() {
            let dir = tempfile::tempdir().unwrap();
            let mark = dir.path().join("mark");
            let mark = mark.display();
            let (options_block, options, probe) = match shell {
                ShellKind::Bash => (
                    "BASH_OPTS_B64",
                    format!("shopt -s globstar\nshopt -s nullglob; touch {mark}\ntouch {mark}\n"),
                    "shopt -q globstar && echo OPT=on; alias ll",
                ),
                ShellKind::Zsh => (
                    "ZSH_OPTS_B64",
                    format!(
                        "builtin setopt globstarshort 2>/dev/null || true\n\
                         builtin setopt nullglob 2>/dev/null || touch {mark}\ntouch {mark}\n"
                    ),
                    "[[ -o globstarshort ]] && echo OPT=on; alias ll",
                ),
            };
            let aliases = format!(
                "alias ll='ls -l'\nalias q='x'; touch {mark}\nalias z=$(touch {mark})\ntouch {mark}\n"
            );
            let mut state = ShellState {
                cwd: std::env::current_dir().unwrap(),
                snapshot: encoded_blocks(&[(options_block, &options), ("ALIASES_B64", &aliases)]),
                shell,
                trust: Default::default(),
            };
            let (_, stdout) = run_command(&mut state, probe).await;
            assert!(
                stdout.contains("OPT=on"),
                "{shell:?}: option lost: {stdout:?}"
            );
            assert!(
                stdout.contains("ls -l"),
                "{shell:?}: alias lost: {stdout:?}"
            );
            assert!(
                !std::path::Path::new(&mark.to_string()).exists(),
                "{shell:?}: a hostile line ran"
            );
        }
    }

    fn sandboxed(grants: &[&str]) -> crate::sandbox_launch::SpawnConfinement {
        crate::sandbox_launch::SpawnConfinement::of(Some(&crate::sandbox_launch::LaunchReceipt {
            sandboxed: true,
            backend: None,
            grants: grants.iter().map(|g| (*g).to_owned()).collect(),
        }))
    }

    /// A function an unconfined spawn wrote (the login capture's startup files), trusted into any spawn.
    const RC_FN: &str = "u46rc() { echo rc-ran; }\n";

    /// Functions, aliases and env written under `enforce` (here a forged functions block with a top-level command) do
    /// not replay into a less confined spawn (`off`, or the re-run with a grant): the command is not run, the warning
    /// is printed, the directory and the state an unconfined spawn wrote (its functions, aliases and env) carry. Into
    /// an equally confined spawn they carry (the normal path is unchanged).
    #[tokio::test]
    async fn u46_functions_replay_only_into_an_equally_confined_spawn() {
        let unconfined = crate::sandbox_launch::SpawnConfinement::default();
        for shell in available_shells() {
            for (label, next, carries) in [
                ("off", unconfined.clone(), false),
                ("grant re-run", sandboxed(&["g-1", "replay:x"]), false),
                ("same mode", sandboxed(&[]), true),
            ] {
                let dir = tempfile::tempdir().unwrap();
                let mark = dir.path().join("mark");
                let functions = format!(
                    "{RC_FN}touch {}\nu46fn() {{ echo fn-ran; }}\n",
                    mark.display()
                );
                let mut state = ShellState {
                    cwd: dir.path().to_path_buf(),
                    snapshot: encoded_blocks(&[
                        ("ENV_VARS_B64", "export KEPT='a b'\n"),
                        ("ALIASES_B64", "alias u46al='echo al-ran'\n"),
                        ("FUNCTIONS_B64", &functions),
                    ]),
                    shell,
                    trust: ReplayTrust {
                        producer: sandboxed(&[]),
                        trusted_snapshot: Some(encoded_blocks(&[
                            ("ENV_VARS_B64", "export RCV='rc v'\n"),
                            ("ALIASES_B64", "alias u46rcal='echo from-rc-alias'\n"),
                            ("FUNCTIONS_B64", RC_FN),
                        ])),
                    },
                };
                let (_, stdout) = run_command_under(
                    &mut state,
                    "u46rc; u46rcal; u46fn 2>/dev/null || echo no-fn; u46al 2>/dev/null || echo no-al; pwd; \
                     echo \"KEPT=${KEPT-unset} RCV=${RCV-unset}\"",
                    &next,
                )
                .await;
                let ctx = format!("{shell:?} {label}: {stdout:?}");
                assert_eq!(stdout.contains("fn-ran"), carries, "{ctx}");
                assert_eq!(stdout.contains("al-ran"), carries, "{ctx}");
                assert_eq!(stdout.contains("KEPT=a b"), carries, "{ctx}");
                assert_eq!(stdout.contains("RCV=rc v"), !carries, "{ctx}");
                assert_eq!(mark.exists(), carries, "{ctx}");
                assert_eq!(
                    stdout.contains(SETTINGS_WITHHELD_WARNING),
                    !carries,
                    "{ctx}"
                );
                assert!(stdout.contains("rc-ran"), "{ctx}: trusted function lost");
                assert_eq!(stdout.contains("from-rc-alias"), !carries, "{ctx}");
                let dir = dir.path().canonicalize().unwrap();
                assert!(stdout.contains(&*dir.to_string_lossy()), "{ctx}");
                // The warning is once per occurrence: the state the less confined spawn left is its own.
                let (_, again) = run_command_under(&mut state, "true", &next).await;
                assert!(
                    !again.contains(SETTINGS_WITHHELD_WARNING),
                    "{shell:?} {label}: {again:?}"
                );
            }
        }
    }

    /// The trust rule itself: less confined is leaving the sandbox or holding a grant key the producer lacked.
    #[test]
    fn u46_spawn_confinement_order() {
        let off = crate::sandbox_launch::SpawnConfinement::default();
        assert!(off.is_less_confined_than(&sandboxed(&[])));
        assert!(sandboxed(&["g"]).is_less_confined_than(&sandboxed(&[])));
        assert!(sandboxed(&["h"]).is_less_confined_than(&sandboxed(&["g"])));
        assert!(!sandboxed(&["g"]).is_less_confined_than(&sandboxed(&["g"])));
        assert!(!sandboxed(&[]).is_less_confined_than(&sandboxed(&["g"])));
        assert!(!sandboxed(&[]).is_less_confined_than(&off));
        assert!(!off.is_less_confined_than(&off));
    }

    /// The env block reads back to the same data the replay exports: zsh's tied `export -T PATH path=( … )` is a
    /// `PATH` export, attributes are dropped, and an integer attribute never evaluates its value.
    #[test]
    fn u46_env_replay_is_rebuilt_from_data() {
        let block =
            b"declare -x A=\"x y\"\ndeclare -ix N=\"a[$(touch /tmp/u46)]\"\ndeclare -x OLDPWD\n\
export -T PATH path=( /a '/b c' )\nexport Q='it'\\''s'\n";
        let replay = String::from_utf8(env_replay(block, b"")).unwrap();
        assert_eq!(
            replay,
            "export A='x y'\nexport OLDPWD\nexport PATH='/a:/b c'\nexport Q='it'\\''s'\n"
        );
    }

    // -----------------------------------------------------------------------------------------------------------
    // u46 r3: one trust rule for all replayed state (env, options, aliases, functions), startup selectors only from
    // an unconfined spawn's state, tracing never replayed in any spelling, multiline aliases read whole.
    // -----------------------------------------------------------------------------------------------------------

    fn state_with(
        shell: ShellKind,
        blocks: &[(&str, &str)],
        producer: crate::sandbox_launch::SpawnConfinement,
    ) -> ShellState {
        let confined = producer != crate::sandbox_launch::SpawnConfinement::default();
        ShellState {
            cwd: std::env::current_dir().unwrap(),
            snapshot: encoded_blocks(blocks),
            shell,
            trust: ReplayTrust {
                producer,
                trusted_snapshot: confined.then(String::new),
            },
        }
    }

    /// Astra r3 C1: `PS4` with a command substitution plus tracing switched on in any spelling zsh (or bash) accepts
    /// (`XTRACE`, `x_trace`, `unsetopt noxtrace`) never runs the substitution: not from a sandboxed command's state
    /// into an unsandboxed spawn, not into an equally confined one, and not even from an unconfined state whose `PS4`
    /// does carry (the option layer alone holds).
    #[tokio::test]
    async fn u46r3_tracing_options_never_replay_in_any_spelling() {
        let off = crate::sandbox_launch::SpawnConfinement::default();
        for shell in available_shells() {
            for (label, producer, next) in [
                ("sandbox->off", sandboxed(&[]), off.clone()),
                ("sandbox->sandbox", sandboxed(&[]), sandboxed(&[])),
                ("off->off", off.clone(), off.clone()),
            ] {
                let dir = tempfile::tempdir().unwrap();
                let mark = dir.path().join("mark");
                let env = format!("export PS4='$(touch {})'\n", mark.display());
                let (block, options, probe) = match shell {
                    ShellKind::Zsh => (
                        "ZSH_OPTS_B64",
                        "builtin setopt promptsubst 2>/dev/null || true\n\
                         builtin setopt XTRACE 2>/dev/null || true\n\
                         builtin setopt x_trace 2>/dev/null || true\n\
                         builtin setopt X_TRACE 2>/dev/null || true\n\
                         builtin unsetopt noxtrace 2>/dev/null || true\n\
                         builtin unsetopt NO_XTRACE 2>/dev/null || true\n\
                         builtin setopt verbose 2>/dev/null || true\n\
                         builtin setopt xtrace 2>/dev/null || true\n\
                         builtin setopt globstarshort 2>/dev/null || true\n",
                        "[[ -o xtrace ]] && echo XT=on; [[ -o globstarshort ]] && echo OPT=on; true",
                    ),
                    ShellKind::Bash => (
                        "POSIX_OPTS_B64",
                        "set -o xtrace\nset -o verbose\nset -o XTRACE\nset -o noclobber\n",
                        "[[ -o xtrace ]] && echo XT=on; [[ -o noclobber ]] && echo OPT=on; true",
                    ),
                };
                let mut state =
                    state_with(shell, &[("ENV_VARS_B64", &env), (block, options)], producer);
                let (_, stdout) = run_command_under(&mut state, probe, &next).await;
                let ctx = format!("{shell:?} {label}: {stdout:?}");
                assert!(!mark.exists(), "{ctx}: PS4 substitution ran");
                assert!(!stdout.contains("XT=on"), "{ctx}");
                // Same trust: the ordinary option still carries.
                if label != "sandbox->off" {
                    assert!(stdout.contains("OPT=on"), "{ctx}");
                }
            }
        }
    }

    /// The option filter itself: canonical names only, tracing never, whatever the spelling or negation.
    #[test]
    fn u46r3_option_lines_are_canonical_and_never_trace() {
        let zsh = |name: &str| format!("builtin setopt {name} 2>/dev/null || true");
        for keep in [
            "globstarshort",
            "nonomatch",
            "promptsubst",
            "notify",
            "extendedglob",
        ] {
            assert!(
                is_replayed_option_line(ShellKind::Zsh, zsh(keep).as_bytes()),
                "{keep}"
            );
        }
        for drop in [
            "xtrace",
            "XTRACE",
            "x_trace",
            "X_TRACE",
            "noxtrace",
            "NO_XTRACE",
            "verbose",
            "Verbose",
            "no_verbose",
        ] {
            assert!(
                !is_replayed_option_line(ShellKind::Zsh, zsh(drop).as_bytes()),
                "{drop}"
            );
        }
        for line in [
            "builtin unsetopt noxtrace 2>/dev/null || true",
            "builtin unsetopt nomatch 2>/dev/null || true",
            "builtin setopt xtrace",
        ] {
            assert!(
                !is_replayed_option_line(ShellKind::Zsh, line.as_bytes()),
                "{line}"
            );
        }
        for keep in [
            "set -o noclobber",
            "set +o emacs",
            "shopt -s globstar",
            "set -o interactive-comments",
        ] {
            assert!(
                is_replayed_option_line(ShellKind::Bash, keep.as_bytes()),
                "{keep}"
            );
        }
        for drop in [
            "set -o xtrace",
            "set +o xtrace",
            "set -o verbose",
            "set -o XTRACE",
            "set -o history",
            "set -o histexpand",
            "set -o noexec",
            "shopt -s Globstar",
        ] {
            assert!(
                !is_replayed_option_line(ShellKind::Bash, drop.as_bytes()),
                "{drop}"
            );
        }
    }

    /// Astra r3 H1: an alias a sandboxed command left (`curl='touch …; curl'`) is not defined in a less sandboxed
    /// spawn; into an equally confined one it carries.
    #[tokio::test]
    async fn u46r3_aliases_from_a_sandboxed_command_skip_a_less_sandboxed_one() {
        let off = crate::sandbox_launch::SpawnConfinement::default();
        for shell in available_shells() {
            for (next, carries) in [(off.clone(), false), (sandboxed(&[]), true)] {
                let dir = tempfile::tempdir().unwrap();
                let mark = dir.path().join("mark");
                let aliases = format!("alias curl='touch {}; true'\n", mark.display());
                let mut state = state_with(shell, &[("ALIASES_B64", &aliases)], sandboxed(&[]));
                let (_, stdout) =
                    run_command_under(&mut state, "curl --version >/dev/null 2>&1; true", &next)
                        .await;
                let ctx = format!("{shell:?} carries={carries}: {stdout:?}");
                assert_eq!(mark.exists(), carries, "{ctx}");
                assert_eq!(
                    stdout.contains(SETTINGS_WITHHELD_WARNING),
                    !carries,
                    "{ctx}"
                );
            }
        }
    }

    /// Astra r3 H2 + r3tweak: `BASH_ENV` (and the other startup selectors) a sandboxed command exported reaches no
    /// less confined spawn; an equally confined one gets it like any variable (no escalation); exported by an
    /// unconfined spawn (the user's own) it carries everywhere.
    #[tokio::test]
    async fn u46r3_bash_env_from_a_sandboxed_command_reaches_only_equal_trust() {
        let off = crate::sandbox_launch::SpawnConfinement::default();
        for shell in available_shells() {
            for (label, producer, next, carries) in [
                ("sandbox->off", sandboxed(&[]), off.clone(), false),
                ("sandbox->sandbox", sandboxed(&[]), sandboxed(&[]), true),
                ("off->off", off.clone(), off.clone(), true),
            ] {
                let dir = tempfile::tempdir().unwrap();
                let mark = dir.path().join("mark");
                let script = dir.path().join("startup.sh");
                std::fs::write(&script, format!("touch {}\n", mark.display())).unwrap();
                let env = format!(
                    "export BASH_ENV={0}\nexport ENV={0}\nexport LD_PRELOAD=/u46/none.so\nexport KEPT=k\n",
                    script.display()
                );
                let mut state = state_with(shell, &[("ENV_VARS_B64", &env)], producer);
                let (_, stdout) = run_command_under(
                    &mut state,
                    "echo \"BE=${BASH_ENV-unset} LP=${LD_PRELOAD-unset}\"; unset LD_PRELOAD; /bin/bash -c true",
                    &next,
                )
                .await;
                let ctx = format!("{shell:?} {label}: {stdout:?}");
                assert_eq!(mark.exists(), carries, "{ctx}");
                assert_eq!(stdout.contains("BE=unset"), !carries, "{ctx}");
                assert_eq!(stdout.contains("LP=unset"), !carries, "{ctx}");
            }
        }
    }

    /// r3tweak: a variable a sandboxed command exports, such as `LD_LIBRARY_PATH`, reaches the next sandboxed command
    /// (through real dumps), and not an unsandboxed or granted re-run.
    #[tokio::test]
    async fn u46r3tweak_sandboxed_loader_path_carries_to_the_next_sandboxed_command() {
        let off = crate::sandbox_launch::SpawnConfinement::default();
        for shell in available_shells() {
            for (next, carries) in [(sandboxed(&[]), true), (off.clone(), false)] {
                let mut state = raw_state(shell, "");
                state.snapshot.clear();
                run_command_under(
                    &mut state,
                    "export LD_LIBRARY_PATH=/opt/x BASH_ENV=./x",
                    &sandboxed(&[]),
                )
                .await;
                let (_, stdout) = run_command_under(
                    &mut state,
                    "echo \"LL=${LD_LIBRARY_PATH-unset} BE=${BASH_ENV-unset}\"",
                    &next,
                )
                .await;
                let ctx = format!("{shell:?} carries={carries}: {stdout:?}");
                assert_eq!(stdout.contains("LL=/opt/x"), carries, "{ctx}");
                assert_eq!(stdout.contains("BE=./x"), carries, "{ctx}");
            }
        }
    }

    /// Astra r3 H4: an alias whose value holds a newline (bash prints it across lines inside single quotes, zsh as
    /// `$'…'`) carries to the next command at the same trust, through a real dump.
    #[tokio::test]
    async fn u46r3_multiline_alias_carries() {
        for shell in available_shells() {
            let mut state = raw_state(shell, "");
            state.snapshot.clear();
            let define = match shell {
                ShellKind::Bash => "alias greet='echo one\necho two'",
                ShellKind::Zsh => "alias greet=$'echo one\\necho two'",
            };
            run_command_under(&mut state, define, &sandboxed(&[])).await;
            let (_, stdout) = run_command_under(&mut state, "greet", &sandboxed(&[])).await;
            assert!(
                stdout.contains("one") && stdout.contains("two"),
                "{shell:?}: {stdout:?}"
            );
        }
    }

    /// The normal path is unchanged: through real dumps, at the same confinement, env values (spaces, quotes,
    /// newlines, unicode, a changed `PATH`), aliases, functions and options carry, without a warning.
    #[tokio::test]
    async fn u46r3_same_trust_replay_keeps_everything() {
        for shell in available_shells() {
            for next in [
                crate::sandbox_launch::SpawnConfinement::default(),
                sandboxed(&[]),
            ] {
                let mut state = raw_state(shell, "");
                state.snapshot.clear();
                let option = match shell {
                    ShellKind::Bash => "shopt -s globstar",
                    ShellKind::Zsh => "setopt globstarshort",
                };
                let define = format!(
                    "export SP='a b' QU=\"it's \\\"q\\\"\" NL=$'x\\ny' UNI='h\u{e9}llo \u{1f511}'; \
                     export PATH=\"/u46/bin:$PATH\"; alias ll='echo ll-ran'; u46f() {{ echo f-ran; }}; {option}"
                );
                run_command_under(&mut state, &define, &next).await;
                let probe = match shell {
                    ShellKind::Bash => "shopt -q globstar && echo OPT=on",
                    ShellKind::Zsh => "[[ -o globstarshort ]] && echo OPT=on",
                };
                let (_, stdout) = run_command_under(
                    &mut state,
                    &format!(
                        "printf '[%s]' \"$SP\" \"$QU\" \"$NL\" \"$UNI\" \"${{PATH%%:*}}\"; echo; ll; u46f; {probe}"
                    ),
                    &next,
                )
                .await;
                let ctx = format!("{shell:?} {next:?}: {stdout:?}");
                assert!(
                    stdout.contains("[a b][it's \"q\"][x\ny][h\u{e9}llo \u{1f511}][/u46/bin]"),
                    "{ctx}"
                );
                for want in ["ll-ran", "f-ran", "OPT=on"] {
                    assert!(stdout.contains(want), "{ctx}: {want}");
                }
                assert!(!stdout.contains(SETTINGS_WITHHELD_WARNING), "{ctx}");
            }
        }
    }

    /// u46 r4 L1: the env judge reads the env the spawn's replay exports: the trusted state's for a less confined spawn.
    #[test]
    fn u46r4_judged_exports_follow_the_replayed_block() {
        let env = |text: &str| encoded_blocks(&[("ENV_VARS_B64", text)]);
        for shell in [ShellKind::Bash, ShellKind::Zsh] {
            let (latest, trusted) = match shell {
                ShellKind::Bash => (
                    "declare -x LATEST_ONLY=\"l\"\n",
                    "declare -x BASH_ENV=\"t\"\n",
                ),
                ShellKind::Zsh => ("export LATEST_ONLY=l\n", "export BASH_ENV=t\n"),
            };
            let state = ShellState {
                cwd: std::env::current_dir().unwrap(),
                snapshot: env(latest),
                shell,
                trust: ReplayTrust {
                    producer: sandboxed(&[]),
                    trusted_snapshot: Some(env(trusted)),
                },
            };
            let names = |next: &crate::sandbox_launch::SpawnConfinement| -> Vec<String> {
                state
                    .restored_exports_for(next)
                    .into_iter()
                    .map(|(n, _)| n.to_string_lossy().into_owned())
                    .collect()
            };
            assert_eq!(names(&sandboxed(&[])), ["LATEST_ONLY"], "{shell:?}");
            assert_eq!(
                names(&crate::sandbox_launch::SpawnConfinement::default()),
                ["BASH_ENV"],
                "{shell:?}"
            );
        }
    }

    /// u46 r4 H2 (real zsh): Fuigo's own init option `extendedglob` is never replayed (an unquoted `^` stays a
    /// literal in a fresh command), and an option plain `emulate` leaves alone (`nocaseglob`) carries from a command.
    #[tokio::test]
    async fn u46r4_zsh_init_option_is_not_replayed_and_user_options_carry() {
        if !zsh_available() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Zsh, &cwd, None, None, None)
            .await
            .unwrap();
        let next = crate::sandbox_launch::SpawnConfinement::default();
        let (_, first) = run_command_under(
            &mut state,
            "[[ -o extendedglob ]] && echo EG=on; echo ^foo; setopt nocaseglob autopushd",
            &next,
        )
        .await;
        assert!(!first.contains("EG=on"), "{first:?}");
        assert!(first.contains("^foo"), "{first:?}");
        for _ in 0..2 {
            let (_, again) = run_command_under(
                &mut state,
                "[[ -o extendedglob ]] && echo EG=on; echo ^foo; \
                 [[ -o nocaseglob ]] && echo NCG=on; [[ -o autopushd ]] && echo APD=on; true",
                &next,
            )
            .await;
            assert!(!again.contains("EG=on"), "{again:?}");
            assert!(again.contains("^foo"), "{again:?}");
            assert!(
                again.contains("NCG=on") && again.contains("APD=on"),
                "{again:?}"
            );
        }
    }

    /// Fable r3 M3: `typeset -U PATH path` makes zsh dump `export -UT PATH path=( … )`; a changed `PATH` still carries.
    #[tokio::test]
    async fn u46r3_zsh_unique_tied_path_carries() {
        if !zsh_available() {
            return;
        }
        assert_eq!(
            zsh_tied_export(b"export -UT PATH path=( /a '/b c' )"),
            Some((b"PATH".to_vec(), Some(b"/a:/b c".to_vec())))
        );
        assert_eq!(zsh_tied_export(b"export -UTn PATH path=( /a )"), None);
        let mut state = raw_state(ShellKind::Zsh, "");
        state.snapshot.clear();
        run_command(
            &mut state,
            "typeset -U PATH path; export PATH=\"/u46/bin:$PATH\"",
        )
        .await;
        let (_, stdout) = run_command(&mut state, "echo \"P=${PATH%%:*}\"").await;
        assert!(stdout.contains("P=/u46/bin"), "{stdout:?}");
    }

    /// Fable r3 H3: a sandboxed command's `PATH` change does not reach the granted re-run (the env falls back whole);
    /// the next equally confined command keeps it.
    #[tokio::test]
    async fn u46r3_path_from_a_sandboxed_command_skips_the_granted_rerun() {
        for shell in available_shells() {
            let mut state = raw_state(shell, "");
            state.snapshot.clear();
            run_command(&mut state, "export PATH=\"/u46/login:$PATH\"").await;
            run_command_under(&mut state, "export PATH=\"./evil:$PATH\"", &sandboxed(&[])).await;
            let probe = "echo \"P=${PATH%%:*}\"";
            let (_, rerun) =
                run_command_under(&mut state, probe, &sandboxed(&["g-1", "replay:x"])).await;
            assert!(rerun.contains("P=/u46/login"), "{shell:?}: {rerun:?}");
            assert!(
                rerun.contains(SETTINGS_WITHHELD_WARNING),
                "{shell:?}: {rerun:?}"
            );
            let mut same = raw_state(shell, "");
            same.snapshot.clear();
            run_command_under(&mut same, "export PATH=\"./evil:$PATH\"", &sandboxed(&[])).await;
            let (_, kept) = run_command_under(&mut same, probe, &sandboxed(&[])).await;
            assert!(kept.contains("P=./evil"), "{shell:?}: {kept:?}");
        }
    }

    /// Fable r3 M2: the env judge reads the same env block the replay does. A forged first block whose end line is
    /// wrong is skipped by both; the later well-formed one is what is judged and what runs.
    #[test]
    fn u46r3_env_judge_and_replay_read_the_same_block() {
        let good = base64::engine::general_purpose::STANDARD.encode("export SEEN=replayed\n");
        let forged = base64::engine::general_purpose::STANDARD.encode("export SEEN=judged\n");
        let snapshot = format!(
            "fuigo_snap_ENV_VARS_B64=$(command base64 -d <<'FUIGO_SNAP_EOF_ENV_VARS_B64'\n{forged}\nNOT_THE_END\n)\n\
             fuigo_snap_ENV_VARS_B64=$(command base64 -d <<'FUIGO_SNAP_EOF_ENV_VARS_B64'\n{good}\nFUIGO_SNAP_EOF_ENV_VARS_B64\n)\n"
        );
        let judged = snapshot_exports(&snapshot);
        assert_eq!(judged, vec![("SEEN".into(), "replayed".into())]);
        let replay = String::from_utf8(replay_script(ShellKind::Bash, &snapshot)).unwrap();
        assert!(
            replay.contains("export SEEN='replayed'") && !replay.contains("judged"),
            "{replay}"
        );
    }
}
