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
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use std::collections::HashMap;
use std::time::Duration;

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

/// Maximum time to wait for the dump reader task after the child process exits.
/// Uses a 5s close timeout. If a background process inherits fd 4,
/// the reader would hang forever without this.
const DUMP_READ_TIMEOUT: Duration = Duration::from_secs(5);

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

  # errreturn/pipefail here are this function's own `emulate -L` options
  # (setopt lists them while inside); replaying them would abort later user
  # commands.
  local zsh_opts
  zsh_opts=$(setopt 2>/dev/null | command grep -vE '^(nounset|errexit|errreturn|pipefail)$' | command awk '{printf "builtin setopt %s 2>/dev/null || true\n", $0}' || true)
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
            .replace("__FUIGO_CREDENTIAL_SCRUB__", &self.credential_scrub("builtin exit 1"))
            .replace("__FUIGO_UNREPLAYED_FUNCTIONS__", &super::restore_guard::zsh_unreplayed_functions())
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
        let mut child = fuigo_tty_utils::ProcessScope::spawn_placed(session_scope, || parts.new_command(), |cmd, _hook| {
            // P189: spawn_placed has already registered the placement as the first pre_exec.
            parts.apply(cmd);
            crate::sandbox_launch::wire_prepared(cmd, fuigo_tty_utils::null_stdio());
            Ok::<(), std::convert::Infallible>(())
        })
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
        let dump_script = self.shell.dump_script();
        let dump_fn = self.shell.dump_function_name();
        let sudo_inject = sudo_alias_injection();
        let search_inject = super::embedded_search_tools::search_injection(search_shadows);

        // Create two OS pipes: one for state-in (fd 3), one for state-out (fd 4).
        // os_pipe() creates fds with O_CLOEXEC (atomically on Linux,
        // best-effort on macOS) so concurrent forks can't leak them.
        let (state_in_read, state_in_write) = os_pipe()?;
        let (state_out_read, state_out_write) = os_pipe()?;

        // Ensure the parent-only ends have CLOEXEC (redundant on Linux
        // where os_pipe uses pipe2, but needed as a safety net on macOS
        // where pipe+fcntl has a small race window).
        set_cloexec(&state_in_write)?;
        set_cloexec(&state_out_read)?;
        // The child-bound ends (state_in_read, state_out_write) also have
        // CLOEXEC from os_pipe(). This is fine: fd_mappings uses dup2()
        // which clears CLOEXEC on the target fd (3/4), so the child keeps
        // them across exec. The originals are closed on exec by CLOEXEC.

        // The wrapper command:
        // 1. Read prior snapshot from fd 3, eval it (restores env/funcs/aliases/opts)
        // 2. Run the user's command (passed as $1)
        // 3. Dump new state to fd 4
        // 4. Exit with the user command's exit code
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
                "{dump_script} \
                 snap=$(command cat <&3) && builtin shopt -s extglob && builtin eval -- \"$snap\" && \
                 {{ {guarded}}}; \
                 COMMAND_EXIT_CODE=$?; builtin unset __fuigo_user_cmd 2>/dev/null; {dump_fn} >&4; builtin exit $COMMAND_EXIT_CODE",
                guarded = super::restore_guard::bash_guarded(&format!(
                    "builtin set +u 2>/dev/null || true; \
                     builtin export FUIGO_AGENT=1; \
                     builtin export PWD=\"$(builtin pwd)\"; \
                     builtin shopt -s expand_aliases 2>/dev/null; {sudo_inject}{search_inject}\
                     builtin printf '%s' \"${{2:-}}\"; \
                     __fuigo_user_cmd=\"$1\"; builtin declare +x __fuigo_user_cmd 2>/dev/null; builtin set --; \
                     builtin eval \"$__fuigo_user_cmd\" 2>&1; "
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
                     builtin eval \"$__fuigo_user_cmd\" 2>&1; "
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

        let fd_mappings = vec![
            FdMapping {
                parent_fd: state_in_read,
                child_fd: 3,
            },
            FdMapping {
                parent_fd: state_out_write,
                child_fd: 4,
            },
        ];

        Ok(PreparedCommand {
            binary: self.shell.binary_path().to_string(),
            args,
            fd_mappings,
            state_in_write,
            state_out_read,
            cwd: effective_cwd.to_path_buf(),
        })
    }

    /// What to write to the state-in pipe for the next command: the snapshot as a replay script (see
    /// [`replay_script`]).
    pub fn replay_script(&self) -> Vec<u8> {
        replay_script(self.shell, &self.snapshot)
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
    /// Read end of the state-output pipe. Caller reads the new dump from here after exit.
    pub state_out_read: OwnedFd,
    /// Working directory for the child process.
    pub cwd: PathBuf,
}

// ============================================================================
// Helpers
// ============================================================================

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
        if let Ok(text) = base64::engine::general_purpose::STANDARD.decode(payload.trim()) {
            blocks.push((name, text));
        }
    }
    blocks
}

/// u35: the script the wrapper evaluates to restore `snapshot`, built from its decoded blocks so that the replay
/// calls nothing a replayed definition can intercept (no `eval`, `command`, `base64` or `builtin` after the first
/// definition): exports, then options with the lines that turn on `xtrace` (and bash history) left out (a traced command expands `PS4`,
/// command substitutions included, before the restore guard could turn it off), then alias expansion off, the aliases,
/// and the function definitions last. Defining a function runs nothing (zsh `TRAP*` and hook functions, which do act
/// on definition, are not dumped), and the restore guard runs right after. Text outside the dump's blocks, and blocks
/// of other names, are not replayed.
pub(crate) fn replay_script(shell: ShellKind, snapshot: &str) -> Vec<u8> {
    let blocks = snapshot_blocks(snapshot);
    let block = |name: &str| -> &[u8] {
        blocks.iter().find(|(n, _)| *n == name).map(|(_, text)| text.as_slice()).unwrap_or_default()
    };
    // Option lines left out: `xtrace` (see above), and in bash `history`/`histexpand`, which inside this one eval
    // would turn on `!` history expansion for the definitions that follow (`eval` only switches history off for its
    // own text, and the dump's per-block evals used to scope it). The guard forces `histexpand` off anyway.
    let (options, dropped, aliases_off): (&[&str], &[&[u8]], &[u8]) = match shell {
        ShellKind::Bash => (
            &["POSIX_OPTS_B64", "BASH_OPTS_B64"],
            &[b"set -o xtrace", b"set -o history", b"set -o histexpand"],
            b"builtin shopt -u expand_aliases",
        ),
        ShellKind::Zsh => (&["ZSH_OPTS_B64"], &[b"builtin setopt xtrace "], b"builtin unsetopt aliases"),
    };
    let mut script = Vec::new();
    let mut push = |text: &[u8]| {
        script.extend_from_slice(text);
        script.push(b'\n');
    };
    push(block("ENV_VARS_B64"));
    for name in options {
        for line in block(name).split(|&b| b == b'\n') {
            if !dropped.iter().any(|d| line.starts_with(d)) {
                push(line);
            }
        }
    }
    push(aliases_off);
    push(block("ALIASES_B64"));
    push(block("FUNCTIONS_B64"));
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

    if !raw.starts_with(&start_line) || !raw.ends_with(&end_line) {
        return None;
    }

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
pub async fn write_snapshot_to_pipe(snapshot: impl AsRef<[u8]>, fd: OwnedFd) -> std::io::Result<()> {
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
/// hangs. The timeout (5s close timeout) prevents this from
/// blocking the actor loop forever. On timeout, returns whatever was read so far
/// (which is typically empty, so marker validation will fail and prior state is kept).
pub async fn read_dump_from_pipe(fd: OwnedFd) -> std::io::Result<String> {
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
    match tokio::time::timeout(
        DUMP_READ_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut file = unsafe { std::fs::File::from_raw_fd(fd.as_raw_fd()) };
            std::mem::forget(fd);
            let mut buf = String::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = file.read(&mut chunk)?;
                if n == 0 {
                    // EOF: every write-end holder closed fd 4 (the
                    // expected path when no bg subprocess was spawned).
                    break;
                }
                buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                // Either marker suffices; we accept whichever shell the
                // child happens to be (bash vs zsh).
                if buf.contains(BASH_STATE_END_MARKER) || buf.contains(ZSH_STATE_END_MARKER) {
                    break;
                }
            }
            drop(file);
            Ok(buf)
        }),
    )
    .await
    {
        Ok(join_result) => join_result.map_err(std::io::Error::other)?,
        Err(_timeout) => {
            tracing::warn!(
                "shell state dump read timed out after {}s (END marker never arrived)",
                DUMP_READ_TIMEOUT.as_secs()
            );
            Ok(String::new())
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

/// The variables `snapshot` exports when it is replayed: its `export -p` (bash) or `typeset -xp`
/// (zsh) block, decoded and read back. A name exported without a value is left out, and so is
/// every command this does not read in full: nothing is guessed.
pub fn snapshot_exports(snapshot: &str) -> Vec<(OsString, OsString)> {
    let header = "fuigo_snap_ENV_VARS_B64=$(command base64 -d <<'FUIGO_SNAP_EOF_ENV_VARS_B64'";
    let Some(payload) = snapshot.lines().skip_while(|line| *line != header).nth(1) else {
        return Vec::new();
    };
    let Ok(script) = base64::engine::general_purpose::STANDARD.decode(payload.trim()) else {
        return Vec::new();
    };
    shell_commands(&script)
        .into_iter()
        .flatten()
        .flat_map(exported_assignments)
        .collect()
}

/// `declare`/`typeset`/`export` assignments among a command's words. Arrays and tied parameters
/// (`-a`, `-A`, `-T`) are not environment variables.
fn exported_assignments(words: Vec<Vec<u8>>) -> Vec<(OsString, OsString)> {
    let Some((verb, args)) = words.split_first() else {
        return Vec::new();
    };
    if !matches!(verb.as_slice(), b"declare" | b"typeset" | b"export") {
        return Vec::new();
    }
    let mut assignments = Vec::new();
    for arg in args {
        if arg.first() == Some(&b'-') {
            if arg.iter().any(|b| matches!(b, b'a' | b'A' | b'T')) {
                return Vec::new();
            }
            continue;
        }
        let Some(eq) = arg.iter().position(|&b| b == b'=') else {
            continue;
        };
        let (name, value) = arg.split_at(eq);
        let is_name = name.split_first().is_some_and(|(first, rest)| {
            (first.is_ascii_alphabetic() || *first == b'_')
                && rest.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
        });
        if is_name {
            assignments.push((
                OsString::from_vec(name.to_vec()),
                OsString::from_vec(value.get(1..).unwrap_or_default().to_vec()),
            ));
        }
    }
    assignments
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
#[path = "shell_state_cli_facing_unchanged_tests.rs"]
mod cli_facing_unchanged_tests;

#[cfg(test)]
mod tests {
    use std::process::Stdio;
    use super::*;

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
    /// `'…'` and `$'…'` words. A name with no value, a tied parameter and a word needing an
    /// expansion are left out rather than guessed.
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
        let state = ShellState::init(ShellKind::Bash, &cwd, None, None, None).await.unwrap();
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
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None).await.unwrap();

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
    async fn run_command_in(state: &mut ShellState, command: &str, binary: Option<&str>) -> (i32, String) {
        use command_fds::CommandFdExt;

        let prep = state
            .prepare_command(
                command,
                None,
                crate::computer::local::SearchShadowConfig::default(),
                None,
            )
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

        let snapshot = state.replay_script();
        let write_handle =
            tokio::spawn(
                async move { write_snapshot_to_pipe(&snapshot, prep.state_in_write).await },
            );
        let read_handle =
            tokio::spawn(async move { read_dump_from_pipe(prep.state_out_read).await });

        let output = child.wait_with_output().await.unwrap();
        write_handle.await.unwrap().unwrap();
        let dump = read_handle.await.unwrap().unwrap();
        state.update_from_dump(&dump);

        let code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        (code, stdout)
    }

    #[tokio::test]
    async fn test_cd_persists_across_commands() {
        if !bash_available() {
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None).await.unwrap();

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
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None).await.unwrap();

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
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None).await.unwrap();

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
        let mut state = ShellState::init(ShellKind::Zsh, &cwd, None, None, None).await.unwrap();

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
        let mut state = ShellState::init(ShellKind::Zsh, &cwd, None, None, None).await.unwrap();

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
            ("alias", "alias run-help=man\nalias grep=\"grep --color=never\""),
            ("function", "run-help() { echo hijacked-run-help; }\nalias grep=\"grep --color=never\""),
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
            let (cwd, snapshot) = parse_dump(ShellKind::Zsh, parse_after_marker(&full, INIT_STATE_MARKER))
                .unwrap_or_else(|| panic!("[{name}] dump must parse, got: {full:?}"));
            let mut state = ShellState { cwd, snapshot, shell: ShellKind::Zsh };

            // `grep` is aliased to `grep --color=never` in the startup file: the replayed alias is the user
            // environment, but the wrapper itself (and its `command grep` dump filters) must not
            // be affected, so the dump still round-trips and the command runs.
            let (code, stdout) = run_command(&mut state, "printf 'a\\nb\\n' | grep b").await;
            assert_eq!(code, 0, "[{name}] command using grep must succeed, stdout={stdout:?}");
            assert_eq!(stdout.trim(), "b", "[{name}] unexpected output: {stdout:?}");

            // State dumped after the run must still replay (functions + aliases survived).
            let (code, stdout) = run_command(&mut state, "echo still-alive").await;
            assert_eq!(code, 0, "[{name}] second command must run, stdout={stdout:?}");
            assert!(stdout.contains("still-alive"), "[{name}] got {stdout:?}");
            assert!(
                !stdout.contains("parse error") && !stdout.contains("defining function based on alias"),
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
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None).await.unwrap();

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
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None).await.unwrap();

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
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None).await.unwrap();

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
        let mut state = ShellState::init(ShellKind::Zsh, &cwd, None, None, None).await.unwrap();

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
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None).await.unwrap();

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
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None).await.unwrap();

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
        let mut state = ShellState::init(ShellKind::Bash, &cwd, None, None, None).await.unwrap();

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
        assert_eq!(stdout.trim(), "FOO=bar", "restored keyword option changed a plain argument");
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
        assert_eq!(stdout.trim(), "=ls", "restored EQUALS option changed a plain argument");
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
        assert!(!stdout.contains("SHADOW"), "a replayed shadow ran: {stdout:?}");
        assert!(stdout.lines().any(|l| l.trim() == "/"), "{stdout:?}");
        assert!(stdout.contains("0 /dev/null") && stdout.contains("plain-ok"), "{stdout:?}");
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
        let (_, stdout) = run_command(&mut state, "ls -d /\nwc -c /dev/null\necho GLOBAL_WORD\nfalse").await;
        assert!(!stdout.contains("SHADOW"), "a replayed shadow ran: {stdout:?}");
        assert!(stdout.lines().any(|l| l.trim() == "/"), "{stdout:?}");
        assert!(stdout.contains("0 /dev/null") && stdout.contains("GLOBAL_WORD"), "{stdout:?}");
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
        assert!(!stdout.contains("RAN") && !stdout.contains("SHADOW"), "{stdout:?}");
    }

    /// g5a: every bash on this machine (the resolved one, `/bin/bash`, and any listed in `FUIGO_TEST_EXTRA_BASH`,
    /// colon-separated; on macOS `/bin/bash` is 3.2).
    fn bash_binaries() -> Vec<String> {
        let mut found: Vec<String> = vec![ShellKind::Bash.binary_path().to_owned(), "/bin/bash".to_owned()];
        if let Ok(extra) = std::env::var("FUIGO_TEST_EXTRA_BASH") {
            found.extend(extra.split(':').filter(|p| !p.is_empty()).map(str::to_owned));
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
            assert_eq!((code, stdout.trim()), (0, "plain-ok"), "{bash}: empty snapshot");
            // That bash's own dump replays: a function, an alias and an export persist.
            let define = "g5a_fn() { echo FN; }; alias g5a_al='echo AL'; export G5A=v";
            assert_eq!(run_command_in(&mut state, define, Some(&bash)).await.0, 0, "{bash}");
            let (code, stdout) = run_command_in(&mut state, "g5a_fn; g5a_al; echo \"$G5A\"", Some(&bash)).await;
            assert_eq!((code, stdout.split_whitespace().collect::<Vec<_>>()), (0, vec!["FN", "AL", "v"]), "{bash}");

            let mut state = raw_state(ShellKind::Bash, "function [ { echo SHADOW; }\nls() { echo SHADOW; }\n");
            let (code, stdout) = run_command_in(&mut state, "[ -d / ] && echo DIR; ls -d /", Some(&bash)).await;
            assert_eq!(code, 0, "{bash}: {stdout:?}");
            assert!(!stdout.contains("SHADOW") && stdout.contains("DIR"), "{bash}: {stdout:?}");
            assert!(stdout.lines().any(|l| l.trim() == "/"), "{bash}: {stdout:?}");

            let mut state = raw_state(ShellKind::Bash, "function [ { echo SHADOW; }\nreadonly -f '['\n");
            let (code, stdout) = run_command_in(&mut state, "echo RAN", Some(&bash)).await;
            assert_ne!(code, 0, "{bash}: {stdout:?}");
            assert!(!stdout.contains("RAN"), "{bash}: {stdout:?}");
        }
    }

    /// g5a: functions an earlier command defined named after what the old replay called (`eval`, `command`) never run
    /// during the replay: it calls nothing after the first definition, and the guard then drops them.
    #[tokio::test]
    async fn u35_replay_calls_nothing_a_replayed_function_can_intercept() {
        for (shell, available) in [(ShellKind::Bash, bash_available()), (ShellKind::Zsh, zsh_available())] {
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
            assert!(!mark.exists(), "{shell:?}: a replayed eval/command function ran");
        }
    }

    /// u35 g6 (Astra r5 Low): a multiline alias makes the guard's alias loop skip continuation lines; a replayed
    /// `continue` function must not run there (it could define `ls` again after the functions were dropped).
    #[tokio::test]
    async fn u35_replayed_continue_does_not_run_in_the_guard_bash() {
        for bash in bash_binaries() {
            let mut state = raw_state(ShellKind::Bash, "");
            state.snapshot.clear();
            let define = "alias g6_multi='echo one\necho two'; continue() { ls() { echo SHADOW; }; }";
            assert_eq!(run_command_in(&mut state, define, Some(&bash)).await.0, 0, "{bash}");
            let (_, stdout) = run_command_in(&mut state, "ls -d /", Some(&bash)).await;
            assert!(!stdout.contains("SHADOW"), "{bash}: a replayed continue() ran in the guard: {stdout:?}");
            assert!(stdout.lines().any(|l| l.trim() == "/"), "{bash}: {stdout:?}");
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
            run_command(&mut state, &format!("{setup}export PS4='$(: >> {})+ '", mark.display())).await;
            assert!(!mark.exists(), "{shell:?}: PS4 expanded without xtrace");
            run_command(&mut state, "set -x").await;
            assert!(!mark.exists(), "{shell:?}: set -x expanded the replayed PS4");
            let (code, stdout) = run_command(&mut state, "echo after").await;
            assert_eq!((code, stdout.trim()), (0, "after"), "{shell:?}");
            assert!(!mark.exists(), "{shell:?}: the replayed xtrace expanded PS4");
        }
    }

    /// g5a (Fable r4): the zsh fail-closed path. A snapshot that replaces the `functions` hash keeps a shadow the guard
    /// cannot see, so the command is refused.
    #[tokio::test]
    async fn u35_unremovable_shadow_refuses_the_command_zsh() {
        if !zsh_available() {
            return;
        }
        let mut state =
            raw_state(ShellKind::Zsh, "unset functions\ntypeset -A functions\nls() { echo SHADOW; }\n");
        let (code, stdout) = run_command(&mut state, "echo RAN; ls -d /").await;
        assert_ne!(code, 0);
        assert!(!stdout.contains("RAN") && !stdout.contains("SHADOW"), "{stdout:?}");
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
        let target = dunce::canonicalize(dir.path()).unwrap().display().to_string();
        let mut state = raw_state(ShellKind::Zsh, "");
        state.snapshot = encoded_blocks(&[("ZSH_OPTS_B64", "builtin setopt autocd 2>/dev/null || true\n")]);
        let (_, stdout) = run_command(&mut state, &format!("{target}\npwd -P")).await;
        assert_ne!(stdout.lines().last().map(str::trim), Some(target.as_str()), "{stdout:?}");
    }

    /// g5a (Fable r4): a shadow an earlier command defined is dropped from the next command (both shells).
    #[tokio::test]
    async fn u35_shadow_from_an_earlier_command_is_dropped() {
        for (shell, available) in [(ShellKind::Bash, bash_available()), (ShellKind::Zsh, zsh_available())] {
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
}
