//! Cross-platform child-process lifecycle helpers for `tokio::process::Command`.
//!
//! The spawn-lifecycle primitives are re-exported from the lightweight
//! [`fuigo_tty_utils`] crate; this module adds the logging reap wrapper
//! (tracing is unavailable there).

pub use fuigo_tty_utils::{
    ProcessGroup, ProcessScope, detach_command, global_process_scope, new_process_group,
};

/// Prepare a search child (`rg` and friends): the policy base environment, then
/// [`fuigo_tty_utils::detach_search_command`]. P113 (Astra r2 #4): the search tools spawned their child with the
/// agent's whole environment, so a credential the denylist keeps from every other child (a provider key, Fuigo's own
/// secrets, a configured `env_key` or MCP token) reached `rg`, or a wrapper named by `RG_BIN_PATH`. Clears the
/// command's environment: call it before setting any variable on `cmd`.
pub fn detach_search_command(cmd: &mut tokio::process::Command) {
    crate::util::shell_env_policy::install_policy_base_env(
        cmd,
        Some(&crate::util::ShellEnvironmentPolicy::default()),
    );
    fuigo_tty_utils::detach_search_command(cmd);
}

/// Reap an already-killed search child, bounded by
/// [`fuigo_tty_utils::KILL_REAP_TIMEOUT`]; on `None` warn and leave the corpse
/// to tokio's orphan reaper.
pub async fn reap_killed_search_child(
    child: &mut tokio::process::Child,
) -> Option<std::process::ExitStatus> {
    let status = fuigo_tty_utils::reap_killed_bounded(child, fuigo_tty_utils::KILL_REAP_TIMEOUT).await;
    if status.is_none() {
        tracing::warn!(
            reap_timeout_secs = fuigo_tty_utils::KILL_REAP_TIMEOUT.as_secs(),
            "killed search child not reaped (bound expired — likely uninterruptible kernel I/O — or wait failed); abandoning to the orphan reaper"
        );
    }
    status
}
