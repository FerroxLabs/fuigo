//! Cross-platform child-process lifecycle helpers for `tokio::process::Command`.
//!
//! The spawn-lifecycle primitives are re-exported from the lightweight
//! [`fuigo_tty_utils`] crate; this module adds the logging reap wrapper
//! (tracing is unavailable there).

pub use fuigo_tty_utils::{
    ProcessGroup, ProcessScope, SpawnPlacedError, detach_command, global_process_scope, new_process_group,
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

/// Whether the child `cmd` starts will have a non-empty `PATH`: the command's own edits (any
/// spelling on Windows, last edit wins) over the inherited value. A cleared environment
/// (`env_clear`) is invisible to `get_envs`; the spawn sites that log this never clear.
pub fn child_path_is_set(cmd: &std::process::Command) -> bool {
    child_path_is_set_for(
        cmd.get_envs(),
        std::env::var_os("PATH").is_some_and(|v| !v.is_empty()),
        crate::util::shell_env_policy::EnvPlatform::host(),
    )
}

/// Whether `name` is `PATH` on this host (any spelling on Windows), for a spawn site that does not
/// hold a `std::process::Command` (a PTY builder).
pub fn is_path_var(name: &str) -> bool {
    crate::util::shell_env_policy::EnvPlatform::host().same_name(name, "PATH")
}

pub(crate) fn child_path_is_set_for<'a>(
    edits: impl IntoIterator<Item = (&'a std::ffi::OsStr, Option<&'a std::ffi::OsStr>)>,
    inherited: bool,
    platform: crate::util::shell_env_policy::EnvPlatform,
) -> bool {
    let mut set = inherited;
    for (name, value) in edits {
        if name.to_str().is_some_and(|n| platform.same_name(n, "PATH")) {
            set = value.is_some_and(|v| !v.is_empty());
        }
    }
    set
}

/// A shell (or program) that failed to start, as logged at the spawn sites: the program path, the
/// OS error code and whether `PATH` was set on the child. Never carries an environment value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellSpawnFailure {
    pub site: &'static str,
    pub program: String,
    pub os_error: Option<i32>,
    pub kind: std::io::ErrorKind,
    pub path_set: bool,
}

impl ShellSpawnFailure {
    pub fn new(site: &'static str, program: &std::ffi::OsStr, err: &std::io::Error, path_set: bool) -> Self {
        Self {
            site,
            program: program.to_string_lossy().into_owned(),
            os_error: err.raw_os_error(),
            kind: err.kind(),
            path_set,
        }
    }

    /// The failure for an error that reached the caller only as text (a dependency formatted the
    /// `io::Error` into its message): the OS error code is the last `(os error N)` in `text`, and the
    /// kind is the one std gives that code. No code in the text leaves both unknown.
    pub fn from_error_text(site: &'static str, program: &std::ffi::OsStr, text: &str, path_set: bool) -> Self {
        let os_error = text.rmatch_indices("(os error ").find_map(|(at, marker)| {
            let digits = text[at + marker.len()..].split(')').next()?;
            digits.trim().parse::<i32>().ok()
        });
        Self {
            site,
            program: program.to_string_lossy().into_owned(),
            os_error,
            kind: os_error.map_or(std::io::ErrorKind::Other, |code| std::io::Error::from_raw_os_error(code).kind()),
            path_set,
        }
    }

    /// The failure for `cmd` (its program and its child's `PATH`).
    pub fn for_command(site: &'static str, cmd: &std::process::Command, err: &std::io::Error) -> Self {
        Self::new(site, cmd.get_program(), err, child_path_is_set(cmd))
    }

    /// Log at warn with structured fields.
    pub fn log(&self) {
        tracing::warn!(
            site = self.site,
            program = %self.program,
            os_error = ?self.os_error,
            kind = ?self.kind,
            path_set = self.path_set,
            "{self}"
        );
    }
}

impl std::fmt::Display for ShellSpawnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: failed to start shell {:?} (", self.site, self.program)?;
        match self.os_error {
            Some(code) => write!(f, "os error {code}")?,
            None => f.write_str("no os error code")?,
        }
        write!(
            f,
            ", {:?}); PATH {} on the child",
            self.kind,
            if self.path_set { "set" } else { "NOT set" }
        )
    }
}

/// Test support shared by the spawn sites' tests (in this and other crates): a `tracing` subscriber
/// that records every event as `LEVEL: name=value ...` text, for asserting what a site logged.
/// Install it with `tracing::subscriber::set_default` (thread-local; use a current-thread runtime).
#[doc(hidden)]
pub mod capture {
    use std::sync::{Arc, Mutex, PoisonError};

    #[derive(Clone, Default)]
    pub struct CaptureEvents(pub Arc<Mutex<Vec<String>>>);

    impl CaptureEvents {
        /// Every event recorded so far, one per line.
        pub fn text(&self) -> String {
            self.0.lock().unwrap_or_else(PoisonError::into_inner).join("\n")
        }
    }

    impl tracing::Subscriber for CaptureEvents {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Fields(String);
            impl tracing::field::Visit for Fields {
                fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                    use std::fmt::Write as _;
                    let _ = write!(self.0, " {}={:?}", field.name(), value);
                }
            }
            let mut fields = Fields(format!("{}:", event.metadata().level()));
            event.record(&mut fields);
            self.0.lock().unwrap_or_else(PoisonError::into_inner).push(fields.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
}

#[cfg(test)]
mod u35_winenv_tests {
    use super::{ShellSpawnFailure, child_path_is_set_for};
    use crate::util::shell_env_policy::EnvPlatform;
    use std::ffi::OsStr;

    #[test]
    fn path_set_follows_the_last_edit_in_any_windows_spelling() {
        let p = |s: &'static str| OsStr::new(s);
        assert!(child_path_is_set_for([], true, EnvPlatform::Windows));
        assert!(!child_path_is_set_for([], false, EnvPlatform::Unix));
        assert!(!child_path_is_set_for([(p("Path"), None)], true, EnvPlatform::Windows));
        assert!(child_path_is_set_for([(p("Path"), None)], true, EnvPlatform::Unix));
        assert!(child_path_is_set_for(
            [(p("PATH"), None), (p("path"), Some(p("C:\\bin")))],
            false,
            EnvPlatform::Windows
        ));
        assert!(!child_path_is_set_for([(p("PATH"), Some(p("")))], true, EnvPlatform::Unix));
        assert!(child_path_is_set_for([(p("OTHER"), None)], true, EnvPlatform::Unix));
    }

    #[test]
    fn spawn_failure_reads_the_os_error_code_back_from_text() {
        let program = OsStr::new("C:\\Windows\\System32\\cmd.exe");
        let text = "CreateProcessW `x` in cwd `None` failed: Access is denied. (os error 5)";
        let failure = ShellSpawnFailure::from_error_text("pty", program, text, true);
        assert_eq!(failure.os_error, Some(5));
        assert_eq!(failure.kind, std::io::Error::from_raw_os_error(5).kind());
        assert_eq!(failure.program, "C:\\Windows\\System32\\cmd.exe");
        let failure = ShellSpawnFailure::from_error_text("pty", program, "doesn't exist (ENOENT)", false);
        assert_eq!((failure.os_error, failure.kind), (None, std::io::ErrorKind::Other));
        let failure = ShellSpawnFailure::from_error_text("pty", program, "(os error x) then (os error 2)", false);
        assert_eq!(failure.os_error, Some(2));
    }

    #[test]
    fn spawn_failure_reports_code_program_and_path_but_no_env_value() {
        let mut cmd = std::process::Command::new("C:\\Windows\\System32\\cmd.exe");
        cmd.env("PATH", "secret-looking-path-value");
        let err = std::io::Error::from_raw_os_error(2);
        let failure = ShellSpawnFailure::for_command("test", &cmd, &err);
        assert_eq!(failure.os_error, Some(2));
        assert!(failure.path_set);
        let text = failure.to_string();
        assert!(text.contains("os error 2"), "{text}");
        assert!(text.contains("cmd.exe"), "{text}");
        assert!(text.contains("PATH set"), "{text}");
        assert!(!text.contains("secret-looking"), "{text}");

        cmd.env_remove("PATH");
        let failure = ShellSpawnFailure::for_command("test", &cmd, &std::io::Error::other("x"));
        assert_eq!(failure.os_error, None);
        assert!(failure.to_string().contains("PATH NOT set"));
    }
}
