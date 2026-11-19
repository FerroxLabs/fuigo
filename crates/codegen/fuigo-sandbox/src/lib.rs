#![allow(
    unused_imports,
    unused_variables,
    unused_mut,
    unreachable_code,
    dead_code
)]
//! OS-level sandboxing for Fuigo via [nono](https://crates.io/crates/nono).
//!
//! Applied once at process startup. Covers in-process `tokio::fs` calls and child processes.
//! Network is left open at the process level (agent needs LLM API); child network is blocked per-subprocess via seccomp.
//!
//! The `enforce` feature (on by default) pulls in `nono` for kernel-enforced sandboxing (Landlock/Seatbelt).
//! When disabled, the crate still provides lightweight helpers (`log_violation`, `should_restrict_child_network`, `child_net`).
//! Those helpers compile on all targets including musl.
//!
//! ```rust,no_run
//! use fuigo_sandbox::{SandboxManager, ProfileName};
//! use std::path::Path;
//!
//! let workspace = Path::new("/home/user/project");
//! let mut sandbox = SandboxManager::new(ProfileName::Workspace, workspace);
//! sandbox.apply(workspace).expect("sandbox apply failed");
//! sandbox.install();
//! ```
mod allow_path;
pub mod child_net;
pub mod command;
mod deny;
mod git_write_deny;
mod home_write_deny;
mod hook_write_deny;
mod logging;
mod network_policy;
mod paths;
mod profiles;
mod read_deny_verify;
mod runtime_sockets;
mod startup_warnings;
pub use startup_warnings::consume_startup_warnings;
#[cfg(test)]
mod test_util;
mod types;
mod workspace_write;
pub use git_write_deny::{GitPathKind, GitProtectedPath};
pub use hook_write_deny::{
    profile_enforces_hook_write_deny, verify_git_write_deny_enforced,
    verify_hook_write_deny_enforced,
};
pub use logging::SandboxLogger;
pub use network_policy::{
    ChildNetworkPolicy, NETWORK_POLICY_SNAPSHOT_VERSION, NetworkPolicySnapshot,
    NetworkPolicySnapshotError, WebsiteAction, WebsiteOrigin, WebsiteOriginError, WebsitePolicy,
};
pub use profiles::{
    ProfileName, ProfileSource, SandboxConfig, SandboxProfile, install_project_profile_judge,
    load_sandbox_config, sandbox_profile_conflicts,
};
pub use read_deny_verify::{verify_data_write_deny_enforced, verify_read_deny_enforced};
pub use types::{SandboxEvent, SandboxEventType, SandboxMetrics};
/// Whether this profile requires direct-hook write protection (non-devbox enforcing profiles).
/// Shell fails closed when protection cannot be applied.
pub fn requires_hook_write_deny(profile: &ProfileName, workspace: &Path) -> bool {
    if !profile_enforces_hook_write_deny(profile) || *profile == ProfileName::Off {
        return false;
    }
    let config = profiles::load_sandbox_config(workspace);
    match profile.selected(&config).as_ref() {
        ProfileName::Custom(name) => {
            config.profiles.get(name).and_then(|p| p.extends.as_deref()) != Some("devbox")
        }
        ProfileName::Devbox => false,
        _ => true,
    }
}
#[cfg(all(feature = "enforce", unix))]
use nono::Sandbox;
use std::path::Path;
#[cfg(any(target_os = "linux", test))]
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
static SANDBOX: OnceLock<GlobalSandboxState> = OnceLock::new();
static CONFIGURED_PROFILE: OnceLock<String> = OnceLock::new();
static CONFINEMENT_ROOT: OnceLock<std::path::PathBuf> = OnceLock::new();
static AUTO_ALLOW_BASH: AtomicBool = AtomicBool::new(false);
const BWRAP_ENV_VAR: &str = "__FUIGO_INSIDE_BWRAP";
pub fn is_inside_bwrap() -> bool {
    std::env::var(BWRAP_ENV_VAR).is_ok()
}
/// Set in this process, and so inherited by everything it spawns, once Fuigo has applied a kernel confinement (Landlock or Seatbelt) to it.
/// Landlock leaves no other trace a child can read, so `fuigo update` and the auto-updater use this to see they are already confined.
pub const CONFINED_ENV_VAR: &str = "__FUIGO_CONFINED";
/// True when this process is confined by Fuigo: inside the bwrap re-exec, or after a kernel confinement it applied itself or inherited.
pub fn is_confined() -> bool {
    is_inside_bwrap() || std::env::var_os(CONFINED_ENV_VAR).is_some()
}
#[cfg(all(feature = "enforce", unix))]
fn mark_confined() {
    // SAFETY: called from `apply`, at startup, before the process spawns the threads that read the environment.
    unsafe { std::env::set_var(CONFINED_ENV_VAR, "1") };
}
pub fn trust_bwrap_marker_for_devbox() -> bool {
    false
}
struct GlobalSandboxState {
    profile: String,
    logger: SandboxLogger,
    applied: bool,
    restrict_network_at_known_linux_launches: bool,
}
/// The per-spawn seccomp filter is self-contained: it needs neither Landlock nor bwrap, so it keys on the resolved `restrict_network` alone.
/// In the degraded states (Landlock unsupported, or `Sandbox::apply` failing inside bwrap) this filter is the only remaining enforcement.
/// Keying on Landlock success would silently disable that session-long child-network control; keying on the config is the fail-closed direction.
fn restrict_network_at_known_linux_launches(configured: bool) -> bool {
    configured && cfg!(target_os = "linux")
}
/// Whether known Linux child launch paths should install the seccomp network filter.
pub fn should_restrict_child_network() -> bool {
    SANDBOX
        .get()
        .is_some_and(|state| state.restrict_network_at_known_linux_launches)
}
/// Whether bash commands should be auto-approved when the sandbox is active.
pub fn should_auto_allow_bash() -> bool {
    AUTO_ALLOW_BASH.load(Ordering::Relaxed) && is_active()
}
pub fn set_auto_allow_bash(enabled: bool) {
    AUTO_ALLOW_BASH.store(enabled, Ordering::Relaxed);
}
/// Record the resolved sandbox profile at process startup (including `"off"`).
pub fn set_configured_profile(name: impl Into<String>) {
    let _ = CONFIGURED_PROFILE.set(name.into());
}
/// Resolved sandbox profile from startup, or `None` if `set_configured_profile` was never called.
pub fn configured_profile_name() -> Option<&'static str> {
    CONFIGURED_PROFILE.get().map(|s| s.as_str())
}
/// The non-`off` sandbox profile this process was **requested** with, if any.
///
/// This is the configured request, not a report that enforcement succeeded.
/// `is_active()` can be false while the process is still confined (e.g. some Linux bwrap paths).
/// A requested-but-unapplied profile already warns the user; keying on the request is the fail-closed choice.
pub fn requested_confinement_profile() -> Option<&'static str> {
    configured_profile_name().filter(|name| profile_confines(name))
}
/// Record the workspace the startup sandbox is scoped to.
pub fn set_confinement_root(workspace: &Path) {
    let _ = CONFINEMENT_ROOT.set(workspace.to_path_buf());
}
/// The workspace that [`requested_confinement_profile`] confines this process to, or `None` without one.
pub fn confinement_root() -> Option<&'static Path> {
    requested_confinement_profile()?;
    CONFINEMENT_ROOT.get().map(std::path::PathBuf::as_path)
}
fn profile_confines(name: &str) -> bool {
    name.parse::<ProfileName>()
        .is_ok_and(|profile| profile != ProfileName::Off)
}
/// Column cap of the profile name inside the "sandbox unavailable" warning.
const UNAVAILABLE_PROFILE_MAX_CHARS: usize = 128;
/// Appended to every Windows sandbox warning: the sandbox is optional, and WSL2 is the way to get one.
pub const WINDOWS_WSL2_HINT: &str = "The sandbox is optional and off by default. \
To use one, run Fuigo inside WSL2 with bubblewrap installed (sudo apt install bubblewrap).";
/// The warning shown at every start on Windows when a sandbox profile is set: no sandbox can exist there, so Fuigo keeps running.
///
/// `None` off Windows (Linux and macOS keep their existing fail-closed behaviour and messages, with or without `enforce`),
/// and for profile `off` (or a name that is not a confining profile).
/// The profile name is config text, so it is scrubbed of terminal-control and hidden characters and capped.
pub fn unavailable_warning_for(profile: &str, on_windows: bool) -> Option<String> {
    if !on_windows || !profile_confines(profile) {
        return None;
    }
    let clean = fuigo_tty_utils::scrub_unsafe_display(profile, Some(' '));
    let clean: String = clean.chars().take(UNAVAILABLE_PROFILE_MAX_CHARS).collect();
    Some(format!(
        "Sandbox profile {clean} is set but sandboxing is not available on Windows: \
         commands and file tools run unsandboxed. {WINDOWS_WSL2_HINT}"
    ))
}
/// [`unavailable_warning_for`] for the profile this process was configured with, on this platform.
///
/// Also the loud warning when the only `bwrap` available can be replaced by a user-level program (see
/// [`bwrap_risk_warning`]); it travels through every channel the Windows warning uses (stderr, ACP notice, `/status`,
/// welcome screen).
pub fn unavailable_warning() -> Option<String> {
    configured_profile_name()
        .and_then(|profile| unavailable_warning_for(profile, cfg!(windows)))
        .or_else(bwrap_risk_warning)
}

/// Warning text for a launcher that the user (or group/others) can replace.
#[cfg(target_os = "linux")]
fn replaceable_launcher_text(path: &Path) -> String {
    format!(
        "Sandbox launcher {} can be replaced by a user-level program: \
         reinstall bubblewrap from your system packages.",
        fuigo_tty_utils::untrusted(&path.display().to_string())
    )
}

/// `Some` when this process runs under a `bwrap` that a user-level program can replace and no safe one existed.
pub fn bwrap_risk_warning() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let launcher = RESOLVED_BWRAP.get()?;
        launcher
            .replaceable
            .then(|| replaceable_launcher_text(&launcher.path))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
/// Whether the sandbox was successfully applied to this process.
pub fn is_active() -> bool {
    SANDBOX.get().is_some_and(|s| s.applied)
}
/// The active sandbox profile name, or `None` if sandbox is not applied.
pub fn profile_name() -> Option<&'static str> {
    SANDBOX
        .get()
        .filter(|s| s.applied)
        .map(|s| s.profile.as_str())
}
/// The violation is flushed to disk immediately. No-op if sandbox is not active.
pub fn log_violation(target: &str, operation: &str) {
    if let Some(state) = SANDBOX.get() {
        state.logger.log(SandboxEvent::fs_violation(
            &state.profile,
            target,
            operation,
        ));
        let _ = state.logger.flush_to_disk();
    }
}
/// Flush sandbox events to disk. No-op if not initialized.
pub fn flush() {
    if let Some(state) = SANDBOX.get()
        && let Err(e) = state.logger.flush_to_disk()
    {
        tracing::warn!(error = %e, "Failed to flush sandbox events to disk");
    }
}
/// Violation metrics, or `None` if sandbox is not active.
pub fn metrics() -> Option<&'static SandboxMetrics> {
    SANDBOX.get().map(|s| s.logger.metrics())
}
/// Manages the OS-level sandbox. Call `apply()` then `install()`.
pub struct SandboxManager {
    profile: ProfileName,
    logger: SandboxLogger,
    net_restricted: bool,
    applied: bool,
}
impl SandboxManager {
    /// Nothing is applied until `apply()` is called.
    pub fn new(profile: ProfileName, _workspace: &Path) -> Self {
        let net_restricted = profile.restricts_network();
        Self {
            profile,
            logger: SandboxLogger::new(),
            net_restricted,
            applied: false,
        }
    }
    /// Apply the sandbox to the current process. **Irreversible.**
    /// Degrades gracefully if the platform doesn't support it.
    #[cfg(all(feature = "enforce", unix))]
    pub fn apply(&mut self, workspace: &Path) -> anyhow::Result<()> {
        if self.profile == ProfileName::Off {
            tracing::info!("Sandbox disabled (profile: off)");
            return Ok(());
        }
        if requires_hook_write_deny(&self.profile, workspace) {
            fuigo_config::ensure_fuigo_hook_slots(paths::fuigo_home().as_path())
                .map_err(|e| anyhow::anyhow!("hook write-deny ensure failed: {e}"))?;
        }
        hook_write_deny::maybe_install_namespace_lockdown_inside_bwrap(&self.profile, workspace)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let config = profiles::load_sandbox_config(workspace);
        let mut resolved = self.profile.resolve_profile(workspace, &config)?;
        self.net_restricted = resolved.restrict_network;
        let support = Sandbox::support_info();
        if !support.is_supported {
            tracing::warn!(
                details = %support.details,
                "Sandbox not supported on this platform, continuing without sandbox"
            );
            self.logger.log(SandboxEvent::apply_failed(
                &self.profile.to_string(),
                workspace,
                &support.details,
            ));
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        workspace_write::verify_boundary(&self.profile, workspace, &config)?;
        let mut caps = ProfileName::capability_set_from_profile(
            workspace,
            &resolved,
            self.profile.denies_workspace_write(&config),
        )?;
        workspace_write::apply_seatbelt_boundary(
            &self.profile,
            workspace,
            &config,
            &resolved,
            &mut caps,
        )?;
        resolved.deny = deny::effective_deny_paths(workspace, &resolved.deny);
        match Sandbox::apply(&caps) {
            Ok(_) => {
                self.applied = true;
                mark_confined();
                self.logger.log(SandboxEvent::profile_applied(
                    &self.profile.to_string(),
                    workspace,
                    &resolved,
                ));
                tracing::info!(
                    profile = %self.profile,
                    workspace = %workspace.display(),
                    restrict_network_configured = self.net_restricted,
                    "Sandbox applied (kernel-enforced, irreversible)"
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    profile = %self.profile,
                    error = %e,
                    "Sandbox could not be applied, continuing without sandbox"
                );
                self.logger.log(SandboxEvent::apply_failed(
                    &self.profile.to_string(),
                    workspace,
                    &e,
                ));
                Ok(())
            }
        }
    }
    /// Stub when `enforce` feature is disabled; sandbox is not applied.
    #[cfg(not(all(feature = "enforce", unix)))]
    pub fn apply(&mut self, _workspace: &Path) -> anyhow::Result<()> {
        tracing::info!(
            profile = %self.profile,
            "Sandbox enforcement unavailable (built without 'enforce' feature)"
        );
        Ok(())
    }
    /// Store globally for session-lifetime violation logging.
    pub fn install(self) {
        let _ = self.logger.flush_to_disk();
        let _ = SANDBOX.set(GlobalSandboxState {
            profile: self.profile.to_string(),
            logger: self.logger,
            applied: self.applied,
            restrict_network_at_known_linux_launches: restrict_network_at_known_linux_launches(
                self.net_restricted,
            ),
        });
    }
    #[cfg(all(feature = "enforce", unix))]
    pub fn support_info() -> nono::SupportInfo {
        Sandbox::support_info()
    }
    pub fn is_applied(&self) -> bool {
        self.applied
    }
    /// Whether known Linux child launch paths should install the seccomp network filter.
    pub fn restrict_child_network(&self) -> bool {
        restrict_network_at_known_linux_launches(self.net_restricted)
    }
    pub fn profile(&self) -> &ProfileName {
        &self.profile
    }
    /// Access the sandbox event logger (before `install()`).
    pub fn logger(&self) -> &SandboxLogger {
        &self.logger
    }
}
/// Build a bwrap command that re-execs the current process with `deny_write` paths mounted read-only.
/// `deny_read` paths are bound over with an unreadable placeholder (EPERM on read).
///
/// Returns `None` if already inside bwrap. Caller should `cmd.exec()` the result.
pub fn bwrap_reexec_command(
    deny_write: &[&str],
    deny_read: &[&str],
) -> Option<std::process::Command> {
    #[cfg(target_os = "linux")]
    {
        bwrap_reexec_command_ex(deny_write, None, deny_read, &[])
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (deny_write, deny_read);
        None
    }
}
/// Like [`bwrap_reexec_command`] plus the optional hook and runtime-socket plans.
#[cfg(target_os = "linux")]
pub(crate) fn bwrap_reexec_command_ex(
    deny_write_optional: &[&str],
    hook_plan: Option<&hook_write_deny::HookWriteDenyBwrapPlan>,
    deny_read: &[&str],
    runtime_socket_denies: &[PathBuf],
) -> Option<std::process::Command> {
    bwrap_reexec_command_with_workspace(
        deny_write_optional,
        hook_plan,
        deny_read,
        runtime_socket_denies,
        None,
    )
}

#[cfg(target_os = "linux")]
fn bwrap_reexec_command_with_workspace(
    deny_write_optional: &[&str],
    hook_plan: Option<&hook_write_deny::HookWriteDenyBwrapPlan>,
    deny_read: &[&str],
    runtime_socket_denies: &[PathBuf],
    readonly_workspace: Option<&Path>,
) -> Option<std::process::Command> {
    if is_inside_bwrap() {
        return None;
    }
    let self_exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            fuigo_tty_utils::cli_eprintln!(
                "error: could not resolve the current executable for the bwrap re-exec: {}",
                fuigo_tty_utils::untrusted(&e)
            );
            return None;
        }
    };
    // OsString: an argument that is not UTF-8 is handed to the re-exec as the bytes it is, never a panic.
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let mut cmd = std::process::Command::new(resolve_bwrap_program());
    cmd.arg("--cap-drop").arg("ALL");
    cmd.arg("--bind").arg("/").arg("/");
    if let Some(workspace) = readonly_workspace {
        workspace_write::append_ancestor_binds(&mut cmd, workspace);
    }
    for path in deny_write_optional {
        if Path::new(path).exists() {
            cmd.arg("--ro-bind").arg(path).arg(path);
        }
    }
    if let Some(plan) = hook_plan
        && let Err(e) = hook_write_deny::append_hook_plan_binds(&mut cmd, plan)
    {
        fuigo_tty_utils::cli_eprintln!(
            "error: hook write-deny plan materialization failed: {}",
            fuigo_tty_utils::untrusted(&e)
        );
        return None;
    }
    // Keep the existing preparation pass: bwrap creates missing mask targets
    // while their parents are writable. The final pass below restores the masks.
    append_bwrap_read_denies(&mut cmd, deny_read)?;
    let sentinel = match read_deny_verify::ensure_bwrap_sentinel_dir() {
        Ok(path) => path,
        Err(e) => {
            fuigo_tty_utils::cli_eprintln!(
                "error: could not prepare the bwrap containment sentinel: {}",
                fuigo_tty_utils::untrusted(&e)
            );
            return None;
        }
    };
    cmd.arg("--ro-bind").arg(&sentinel).arg(&sentinel);
    cmd.arg("--dev-bind").arg("/dev").arg("/dev");
    // Deliberately NO --unshare-pid (audit S5-F20): this re-exec wraps the whole fuigo process, and
    // fuigo records its own pid for other processes to test (leader pid files, auth lock holder
    // stamps checked with kill(pid, 0) and /proc/<pid>). In a private PID namespace those pids
    // would name a different process to every reader outside it.
    cmd.arg("--proc").arg("/proc");
    let encoded_runtime_socket_denies =
        match runtime_sockets::encode_bwrap_runtime_socket_denies(runtime_socket_denies) {
            Ok(encoded) => encoded,
            Err(error) => {
                fuigo_tty_utils::cli_eprintln!(
                    "error: runtime-socket deny handoff encoding failed: {}",
                    fuigo_tty_utils::untrusted(&error)
                );
                return None;
            }
        };
    cmd.env(BWRAP_ENV_VAR, "1");
    cmd.env(
        runtime_sockets::BWRAP_RUNTIME_SOCKET_DENY_ENV_VAR,
        encoded_runtime_socket_denies,
    );
    if let Some(workspace) = readonly_workspace {
        workspace_write::append_readonly_bind(&mut cmd, workspace);
        // A parent bind replaces earlier child mounts. Reapply read masks and the
        // containment sentinel after the workspace boundary, never expose denied data.
        append_bwrap_read_denies(&mut cmd, deny_read)?;
        cmd.arg("--ro-bind").arg(&sentinel).arg(&sentinel);
    }
    startup_warnings::handoff(&mut cmd);
    if let Some(launcher) = RESOLVED_BWRAP.get() {
        cmd.env(
            BWRAP_RESOLVED_HANDOFF,
            format!(
                "{}{}:{}",
                if launcher.from_path { "path" } else { "system" },
                if launcher.replaceable { "!" } else { "" },
                launcher.path.display()
            ),
        );
    }
    cmd.arg("--").arg(self_exe).args(args);
    Some(cmd)
}
/// Fixed system directories searched for `bwrap`, in order. `PATH` is not consulted first: a
/// user-writable `PATH` entry ahead of the system directories must not pick the sandbox launcher.
#[cfg(target_os = "linux")]
const BWRAP_SYSTEM_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/local/bin"];

/// Program used when no `bwrap` exists anywhere: absolute and non-existent, so the exec fails without a `PATH` search.
#[cfg(target_os = "linux")]
const BWRAP_NOT_FOUND: &str = "/nonexistent/fuigo-bwrap-not-found";

/// Where [`choose_bwrap`] found its `bwrap`, and what it passed over on the way.
#[cfg(target_os = "linux")]
#[derive(Debug, Default, PartialEq, Eq)]
struct BwrapChoice {
    /// The binary to launch; `None` when no usable one exists.
    path: Option<PathBuf>,
    /// The binary came from a `PATH` entry because no system directory had a usable one.
    from_path: bool,
    /// Candidates that exist but were passed over because they (or their directory) can be replaced by the user.
    skipped: Vec<PathBuf>,
    /// No safe candidate existed, so `path` is the first replaceable one (warn, don't refuse).
    replaceable: bool,
    /// Whether the first skipped candidate came from `PATH` (parallel to `skipped[0]`).
    first_skipped_from_path: bool,
}

/// Pick `bwrap`: the first usable file in `dirs`, then in the (absolute) `path_var` entries.
/// `replaceable` says whether a candidate could be swapped by the user or others; such a candidate is skipped (and
/// recorded) while a safe one exists. When none does, the first replaceable candidate in search order is chosen and
/// flagged, so the caller can warn loudly instead of refusing.
#[cfg(target_os = "linux")]
fn choose_bwrap(
    dirs: &[&str],
    path_var: Option<&std::ffi::OsStr>,
    replaceable: impl Fn(&Path) -> bool,
) -> BwrapChoice {
    let mut choice = BwrapChoice::default();
    let system = dirs.iter().map(PathBuf::from).collect::<Vec<_>>();
    let from_path = path_var
        .map(|p| std::env::split_paths(p).collect::<Vec<_>>())
        .unwrap_or_default();
    for (is_path, dir) in system
        .iter()
        .map(|d| (false, d))
        .chain(from_path.iter().map(|d| (true, d)))
    {
        // A relative `PATH` entry is the current directory in disguise; never a launcher location.
        if !dir.is_absolute() {
            continue;
        }
        let candidate = dir.join("bwrap");
        if !is_executable_file(&candidate) || choice.skipped.contains(&candidate) {
            continue;
        }
        if replaceable(&candidate) {
            if choice.skipped.is_empty() {
                choice.first_skipped_from_path = is_path;
            }
            choice.skipped.push(candidate);
            continue;
        }
        choice.path = Some(candidate);
        choice.from_path = is_path;
        break;
    }
    if choice.path.is_none()
        && let Some(first) = choice.skipped.first()
    {
        choice.path = Some(first.clone());
        choice.from_path = choice.first_skipped_from_path;
        choice.replaceable = true;
    }
    choice
}

/// A regular file with at least one execute bit; anything else would fail the exec where a `PATH` search moves on.
#[cfg(target_os = "linux")]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Whether `path` (a file) or the directory holding it can be modified by someone who should not be able to:
/// group/world-writable mode bits, or (for a non-root user) any write access. Looked at both for the listed path and
/// for what a symlink resolves to.
#[cfg(target_os = "linux")]
fn bwrap_candidate_is_replaceable(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    fn risky(p: &Path, root: bool) -> bool {
        let Ok(meta) = std::fs::metadata(p) else {
            return false;
        };
        if meta.mode() & 0o022 != 0 {
            return true;
        }
        if root {
            return false;
        }
        let Ok(c) = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(p.as_os_str()))
        else {
            return false;
        };
        // SAFETY: `c` is a valid NUL-terminated path.
        unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
    }
    // SAFETY: geteuid has no preconditions.
    let root = unsafe { libc::geteuid() } == 0;
    let mut targets = vec![path.to_path_buf()];
    if let Some(parent) = path.parent() {
        targets.push(parent.to_path_buf());
    }
    if let Ok(real) = dunce::canonicalize(path) {
        if let Some(parent) = real.parent() {
            targets.push(parent.to_path_buf());
        }
        targets.push(real);
    }
    targets.iter().any(|t| risky(t, root))
}

/// The user-facing warnings for a choice, as `(dedupe key, text)`. Pure so the wording is testable.
#[cfg(target_os = "linux")]
fn bwrap_choice_warnings(choice: &BwrapChoice) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // When a replaceable candidate had to be used, it gets the one loud warning below, not a "not using it" one.
    let passed_over = if choice.replaceable {
        &choice.skipped[1..]
    } else {
        &choice.skipped[..]
    };
    for skipped in passed_over {
        out.push((
            format!("bwrap-skipped:{}", skipped.display()),
            format!(
                "WARNING: ignoring bubblewrap at {}: the file or its directory is writable by your user, \
                 your group or others, so it could be replaced; not using it as the sandbox launcher.",
                fuigo_tty_utils::untrusted(&skipped.display().to_string())
            ),
        ));
    }
    match (&choice.path, choice.from_path) {
        (Some(path), _) if choice.replaceable => out.push((
            format!("bwrap-replaceable:{}", path.display()),
            format!("WARNING: {}", replaceable_launcher_text(path)),
        )),
        (Some(path), true) => out.push((
            format!("bwrap-from-path:{}", path.display()),
            format!(
                "WARNING: bubblewrap (bwrap) was not found in {}; using {} from PATH. \
                 Install it system-wide (sudo apt install bubblewrap) so the launcher does not depend on PATH.",
                BWRAP_SYSTEM_DIRS.join(", "),
                fuigo_tty_utils::untrusted(&path.display().to_string())
            ),
        )),
        _ => {}
    }
    out
}

/// What [`resolve_bwrap_program`] chose, handed across the re-exec so `/status` in the sandboxed process can show it.
#[cfg(target_os = "linux")]
const BWRAP_RESOLVED_HANDOFF: &str = "__FUIGO_BWRAP_RESOLVED";

#[cfg(target_os = "linux")]
struct ResolvedBwrap {
    path: PathBuf,
    from_path: bool,
    replaceable: bool,
}

#[cfg(target_os = "linux")]
static RESOLVED_BWRAP: std::sync::OnceLock<ResolvedBwrap> = std::sync::OnceLock::new();

/// Read (once) and scrub the resolved-launcher handoff. Called from `consume_startup_warnings`.
pub(crate) fn consume_bwrap_handoff() {
    #[cfg(target_os = "linux")]
    {
        if let Ok(value) = std::env::var(BWRAP_RESOLVED_HANDOFF)
            && let Some((source, path)) = value.split_once(':')
        {
            let _ = RESOLVED_BWRAP.set(ResolvedBwrap {
                path: PathBuf::from(path),
                from_path: source.starts_with("path"),
                replaceable: source.ends_with('!'),
            });
        }
        // SAFETY: the caller of `consume_startup_warnings` guarantees single-threaded startup.
        unsafe { std::env::remove_var(BWRAP_RESOLVED_HANDOFF) };
    }
}

/// One line for `/status`: which `bwrap` launches the sandbox, or `None` when this process was not started through one.
pub fn bwrap_status_line() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let launcher = RESOLVED_BWRAP.get()?;
        let raw = launcher.path.display().to_string();
        let shown = fuigo_tty_utils::scrub_unsafe_display(&raw, Some(' '));
        let mut line = shown.into_owned();
        if launcher.from_path {
            line.push_str(" (found via PATH; not in a system directory)");
        }
        if launcher.replaceable {
            line.push_str(" (WARNING: can be replaced by a user-level program; reinstall bubblewrap from your system packages)");
        }
        Some(line)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Test-only override of [`BWRAP_SYSTEM_DIRS`]: a `:`-separated list (empty = no directory) that replaces the fixed
/// system directories so a test can make `bwrap` genuinely unavailable on a host that has it installed in `/usr/bin`.
/// Compiled in only with the `test-bwrap-dirs` feature, which only dev-dependencies enable; a release build does not
/// contain the lookup at all.
#[cfg(all(target_os = "linux", feature = "test-bwrap-dirs"))]
pub const TEST_BWRAP_DIRS_ENV: &str = "FUIGO_TEST_BWRAP_DIRS";

#[cfg(all(target_os = "linux", feature = "test-bwrap-dirs"))]
fn bwrap_dirs_override() -> Option<Vec<String>> {
    let raw = std::env::var(TEST_BWRAP_DIRS_ENV).ok()?;
    Some(
        raw.split(':')
            .filter(|d| !d.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

/// The `bwrap` to launch: the first usable one in the fixed system directories. When none is installed
/// there, fall back to a `PATH` lookup (warn, don't refuse) so a custom install still works. A candidate whose file
/// or directory the user (or group/others) can write is skipped with a warning. The chosen path is logged once
/// (debug) and handed to the re-exec for `/status`.
/// This is the only place a `bwrap` is chosen: the re-exec runs exactly this program, and a missing one makes
/// the exec fail, which a required boundary turns into a refusal to start.
#[cfg(target_os = "linux")]
fn resolve_bwrap_program() -> PathBuf {
    let path_var = std::env::var_os("PATH");
    #[cfg(feature = "test-bwrap-dirs")]
    let overridden = bwrap_dirs_override();
    #[cfg(not(feature = "test-bwrap-dirs"))]
    let overridden: Option<Vec<String>> = None;
    let dirs: Vec<&str> = match &overridden {
        Some(dirs) => dirs.iter().map(String::as_str).collect(),
        None => BWRAP_SYSTEM_DIRS.to_vec(),
    };
    let choice = choose_bwrap(&dirs, path_var.as_deref(), bwrap_candidate_is_replaceable);
    for (key, text) in bwrap_choice_warnings(&choice) {
        if startup_warnings::first(key) {
            fuigo_tty_utils::cli_eprintln!("{text}");
        }
    }
    match choice.path {
        Some(path) => {
            if startup_warnings::first(format!("bwrap-resolved:{}", path.display())) {
                tracing::debug!(bwrap = %path.display(), from_path = choice.from_path, "resolved bwrap launcher");
            }
            let _ = RESOLVED_BWRAP.set(ResolvedBwrap {
                path: path.clone(),
                from_path: choice.from_path,
                replaceable: choice.replaceable,
            });
            path
        }
        // Nothing found at all. Never exec `bwrap` by bare name: that searches `PATH`, including relative entries
        // such as `.`, and would run a project-local file as the launcher. An absolute path that cannot exist makes
        // the exec fail (a required boundary then refuses to start) after a clear message.
        None => {
            if startup_warnings::first("bwrap-not-found".to_string()) {
                fuigo_tty_utils::cli_eprintln!(
                    "error: bubblewrap (bwrap) not found in /usr/bin, /bin, /usr/local/bin or absolute PATH entries"
                );
            }
            PathBuf::from(BWRAP_NOT_FOUND)
        }
    }
}

#[cfg(target_os = "linux")]
fn append_bwrap_read_denies(cmd: &mut std::process::Command, deny_read: &[&str]) -> Option<()> {
    if !deny_read.is_empty() {
        for path in deny_read {
            let Some(blocked) = bwrap_blocked_source_for_path(Path::new(path)) else {
                fuigo_tty_utils::cli_eprintln!(
                    "error: could not create bwrap placeholder for read-deny path {}; \
                     refusing to start with a partial sandbox",
                    fuigo_tty_utils::untrusted(&path)
                );
                return None;
            };
            cmd.arg("--ro-bind").arg(&blocked).arg(path);
        }
    }
    Some(())
}
/// Choose file vs directory placeholder for a deny path (existing dirs need a dir bind).
#[cfg(all(feature = "enforce", target_os = "linux"))]
fn bwrap_blocked_source_for_path(path: &Path) -> Option<PathBuf> {
    if deny::deny_path_is_dir(path) {
        bwrap_blocked_placeholder("sandbox-blocked-dir", true)
    } else {
        bwrap_blocked_placeholder("sandbox-blocked", false)
    }
}
/// Without kernel enforcement there are no read-deny placeholders to bind over.
#[cfg(all(not(feature = "enforce"), target_os = "linux"))]
fn bwrap_blocked_source_for_path(_path: &Path) -> Option<PathBuf> {
    None
}
/// chmod a placeholder to mode 000 so a bwrap bind-over yields EPERM on read.
#[cfg(all(feature = "enforce", target_os = "linux"))]
fn chmod_000(path: &Path) -> Option<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path).ok()?.permissions();
    perms.set_mode(0o000);
    std::fs::set_permissions(path, perms).ok()?;
    Some(())
}
/// Zero-permission placeholder (file or dir) under `fuigo_home` used by bwrap bind-over.
///
/// The placeholder name is suffixed with the current PID so concurrent fuigo processes don't race each other's create/remove/chmod on a shared path.
/// A lost race could yield `None`, silently dropping the bind and failing open.
#[cfg(all(feature = "enforce", target_os = "linux"))]
fn bwrap_blocked_placeholder(name: &str, want_dir: bool) -> Option<PathBuf> {
    use std::fs::OpenOptions;
    let path = paths::fuigo_home().join(format!("{name}.{}", std::process::id()));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok()?;
    }
    if path.exists() {
        if path.is_dir() == want_dir {
            chmod_000(&path)?;
            return Some(path);
        }
        if path.is_dir() {
            std::fs::remove_dir_all(&path).ok()?;
        } else {
            std::fs::remove_file(&path).ok()?;
        }
    }
    if want_dir {
        std::fs::create_dir(&path).ok()?;
    } else {
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .ok()?;
    }
    chmod_000(&path)?;
    Some(path)
}
/// Whether a profile write-denies `/data` via the devbox bwrap bind (built-in `devbox` or a custom profile that `extends = "devbox"`).
/// This is a pure mount, so it applies even WITHOUT the `enforce` feature.
#[cfg(target_os = "linux")]
fn is_devbox_based(profile: &ProfileName, config: &SandboxConfig) -> bool {
    match profile.selected(config).as_ref() {
        ProfileName::Devbox => true,
        ProfileName::Custom(name) => {
            config.profiles.get(name).and_then(|p| p.extends.as_deref()) == Some("devbox")
        }
        _ => false,
    }
}
/// Whether kernel read-deny enforcement is required.
/// This is the single source of truth, so callers (e.g. the shell's fail-closed startup path) cannot drift and silently fail open.
///
/// Decided directly from the profile config, NOT from the resolved/expanded deny set, which returns empty on failure.
/// Keying "requires" on that empty-on-error result would silently downgrade to fail-open (Linux) when resolution hiccups.
/// This intrinsic check stays fail-closed.
#[cfg(all(feature = "enforce", unix))]
pub fn requires_read_deny(profile: &ProfileName, workspace: &Path) -> bool {
    if !matches!(profile, ProfileName::Custom(_) | ProfileName::Minimal) {
        return false;
    }
    let config = profiles::load_sandbox_config(workspace);
    match profile.selected(&config).as_ref() {
        ProfileName::Custom(name) => config.profiles.get(name).is_some_and(|p| {
            if !p.deny.is_empty() {
                return true;
            }
            match p.restrict_network {
                Some(explicit) => explicit,
                None => p
                    .extends
                    .as_deref()
                    .and_then(|base| base.parse::<ProfileName>().ok())
                    .is_some_and(|base| base.restricts_network()),
            }
        }),
        _ => false,
    }
}
/// Stub when `enforce` is unavailable; nothing is kernel-enforced.
#[cfg(not(all(feature = "enforce", unix)))]
pub fn requires_read_deny(_profile: &ProfileName, _workspace: &Path) -> bool {
    false
}
/// Whether an existing `/data` needs the devbox bwrap read-only bind.
///
/// Filesystem errors other than `NotFound` conservatively require bwrap.
#[cfg(target_os = "linux")]
pub fn requires_data_write_deny(profile: &ProfileName, workspace: &Path) -> bool {
    requires_data_write_deny_for(
        profile,
        &profiles::load_sandbox_config(workspace),
        data_path_requires_bind(Path::new("/data")),
    )
}
#[cfg(target_os = "linux")]
fn requires_data_write_deny_for(
    profile: &ProfileName,
    config: &SandboxConfig,
    is_data_present: bool,
) -> bool {
    is_devbox_based(profile, config) && is_data_present
}
#[cfg(target_os = "linux")]
fn data_path_requires_bind(path: &Path) -> bool {
    path.try_exists().unwrap_or(true)
}
/// Whether a `resolve_profile` failure must refuse startup.
/// Any profile that enforces hook write-deny or its own deny list cannot proceed with an empty plan.
/// The read-deny arm covers deny-carrying `extends = "devbox"` profiles, which the hook arm does not.
/// Devbox resolution is infallible today, so that arm is defense in depth against a future fallible resolve step.
#[cfg(all(feature = "enforce", target_os = "linux"))]
fn resolve_failure_must_refuse(profile: &ProfileName, workspace: &Path) -> bool {
    requires_hook_write_deny(profile, workspace)
        || requires_read_deny(profile, workspace)
        || requires_data_write_deny(profile, workspace)
}
#[cfg(target_os = "linux")]
struct BwrapDenyPlan {
    readonly_workspace: Option<PathBuf>,
    deny_write_optional: Vec<String>,
    hook_plan: Option<hook_write_deny::HookWriteDenyBwrapPlan>,
    deny_read: Vec<String>,
    runtime_socket_denies: Vec<PathBuf>,
    requires_read_deny: bool,
}
#[cfg(all(feature = "enforce", target_os = "linux"))]
fn bwrap_deny_plan(profile: &ProfileName, workspace: &Path) -> Option<BwrapDenyPlan> {
    let config = profiles::load_sandbox_config(workspace);
    let requires_read_deny = requires_read_deny(profile, workspace);
    let deny_write_optional: Vec<String> = if requires_data_write_deny(profile, workspace) {
        vec!["/data".to_string()]
    } else {
        Vec::new()
    };
    let resolved = if *profile == ProfileName::Off {
        None
    } else {
        match profile.resolve_profile_with_runtime_sockets(workspace, &config) {
            Ok(resolved) => Some(resolved),
            Err(e) => {
                if resolve_failure_must_refuse(profile, workspace) {
                    fuigo_tty_utils::cli_eprintln!(
                        "error: sandbox profile resolve failed: {}",
                        fuigo_tty_utils::untrusted(&e)
                    );
                    return None;
                }
                None
            }
        }
    };
    let entries = resolved
        .as_ref()
        .map(|(profile, _)| profile.deny.clone())
        .unwrap_or_default();
    let runtime_socket_denies = resolved
        .as_ref()
        .map(|(_, sockets)| sockets.clone())
        .unwrap_or_default();
    let needs_hooks = requires_hook_write_deny(profile, workspace);
    let mut hook_plan = if needs_hooks {
        match hook_write_deny::prepare_hook_write_deny(profile) {
            Ok(hook_write_deny::HookWriteDenyPrepare::NotRequired) => None,
            Ok(hook_write_deny::HookWriteDenyPrepare::Plan(plan)) => Some(plan),
            Err(e) => {
                fuigo_tty_utils::cli_eprintln!(
                    "error: hook write-deny plan failed: {}",
                    fuigo_tty_utils::untrusted(&e)
                );
                return None;
            }
        }
    } else {
        None
    };
    // Git hooks and configs ride on the hook plan: same profiles, same read-only binds
    if let (Some(plan), Some((resolved_profile, _))) = (hook_plan.as_mut(), resolved.as_ref())
        && let Err(e) = hook_write_deny::add_git_leaves_to_plan(
            plan,
            &resolved_profile.git_write_deny,
            &resolved_profile.read_write,
        )
    {
        fuigo_tty_utils::cli_eprintln!(
            "error: git write-deny plan failed: {}",
            fuigo_tty_utils::untrusted(&e)
        );
        return None;
    }
    if needs_hooks && hook_plan.is_none() {
        fuigo_tty_utils::cli_eprintln!(
            "error: hook write-deny is required but no plan was prepared"
        );
        return None;
    }
    let (exact, globs) = deny::partition_deny_entries(&entries);
    let mut deny_read = deny::exact_deny_path_strings(workspace, &exact);
    let has_globs = !globs.is_empty();
    if has_globs {
        tracing::warn!(
            count = globs.len(),
            "sandbox deny globs are enforced best-effort on Linux (expanded at launch); \
             files matching them that are created later are NOT covered"
        );
        match deny::expand_deny_globs(workspace, &globs, deny::DENY_GLOB_CAPS) {
            Ok(paths) => deny_read.extend(paths),
            Err(reason) => {
                tracing::error!(%reason, "sandbox deny-glob expansion failed; refusing to start");
                fuigo_tty_utils::cli_eprintln!(
                    "error: sandbox deny glob could not be enforced on Linux: {}",
                    fuigo_tty_utils::untrusted(&reason)
                );
                return None;
            }
        }
    }
    Some(BwrapDenyPlan {
        readonly_workspace: workspace_write::boundary_path(profile, workspace, &config),
        deny_write_optional,
        hook_plan,
        deny_read,
        runtime_socket_denies,
        requires_read_deny,
    })
}
/// Without kernel enforcement there is no read-deny; the devbox `/data` write-deny and the hook write-deny plan still apply.
#[cfg(all(not(feature = "enforce"), target_os = "linux"))]
fn bwrap_deny_plan(profile: &ProfileName, workspace: &Path) -> Option<BwrapDenyPlan> {
    let config = profiles::load_sandbox_config(workspace);
    let deny_write_optional: Vec<String> = if requires_data_write_deny(profile, workspace) {
        vec!["/data".to_string()]
    } else {
        Vec::new()
    };
    let mut hook_plan = if requires_hook_write_deny(profile, workspace) {
        match hook_write_deny::prepare_hook_write_deny(profile) {
            Ok(hook_write_deny::HookWriteDenyPrepare::NotRequired) => None,
            Ok(hook_write_deny::HookWriteDenyPrepare::Plan(plan)) => Some(plan),
            Err(e) => {
                fuigo_tty_utils::cli_eprintln!(
                    "error: hook write-deny plan failed: {}",
                    fuigo_tty_utils::untrusted(&e)
                );
                return None;
            }
        }
    } else {
        None
    };
    // Without Landlock every path is writable, so every git target is bound
    if let Some(plan) = hook_plan.as_mut() {
        let bound = profile
            .resolve_profile(workspace, &config)
            .map_err(|e| e.to_string())
            .and_then(|resolved| {
                hook_write_deny::add_git_leaves_to_plan(
                    plan,
                    &resolved.git_write_deny,
                    &[PathBuf::from("/")],
                )
                .map_err(|e| e.to_string())
            });
        if let Err(e) = bound {
            fuigo_tty_utils::cli_eprintln!(
                "error: git write-deny plan failed: {}",
                fuigo_tty_utils::untrusted(&e)
            );
            return None;
        }
    }
    Some(BwrapDenyPlan {
        readonly_workspace: workspace_write::boundary_path(profile, workspace, &config),
        deny_write_optional,
        hook_plan,
        deny_read: Vec::new(),
        runtime_socket_denies: Vec::new(),
        requires_read_deny: false,
    })
}
/// Build the bwrap re-exec command a profile needs on Linux.
/// Returns `None` when no re-exec is needed (already inside bwrap, nothing to deny) or the deny plan could not be built.
/// Plan failures print their cause.
#[cfg(target_os = "linux")]
pub fn bwrap_reexec_for_profile(
    profile: &ProfileName,
    workspace: &Path,
) -> Option<std::process::Command> {
    if is_inside_bwrap() {
        return None;
    }
    let BwrapDenyPlan {
        readonly_workspace,
        deny_write_optional,
        hook_plan,
        deny_read,
        runtime_socket_denies,
        requires_read_deny,
    } = bwrap_deny_plan(profile, workspace)?;
    if readonly_workspace.is_none()
        && deny_write_optional.is_empty()
        && hook_plan.is_none()
        && deny_read.is_empty()
        && !requires_read_deny
    {
        return None;
    }
    let write_opt: Vec<&str> = deny_write_optional.iter().map(String::as_str).collect();
    let read_refs: Vec<&str> = deny_read.iter().map(String::as_str).collect();
    bwrap_reexec_command_with_workspace(
        &write_opt,
        hook_plan.as_ref(),
        &read_refs,
        &runtime_socket_denies,
        readonly_workspace.as_deref(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    #[test]
    fn unavailable_warning_text_on_windows_is_exact() {
        assert_eq!(
            unavailable_warning_for("workspace", true).as_deref(),
            Some(
                "Sandbox profile workspace is set but sandboxing is not available on Windows: \
                 commands and file tools run unsandboxed. The sandbox is optional and off by default. \
                 To use one, run Fuigo inside WSL2 with bubblewrap installed (sudo apt install bubblewrap)."
            )
        );
    }
    #[cfg(target_os = "linux")]
    fn make_bwrap(dir: &Path, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = dir.join("bwrap");
        std::fs::write(&file, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        file
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn a_non_executable_bwrap_is_skipped_for_the_next_candidate() {
        let root = tempfile::tempdir().unwrap();
        let _plain = make_bwrap(&root.path().join("plain"), 0o644);
        let good = make_bwrap(&root.path().join("good"), 0o755);
        let dirs = [
            root.path().join("plain").to_str().unwrap().to_owned(),
            root.path().join("good").to_str().unwrap().to_owned(),
        ];
        let dirs: Vec<&str> = dirs.iter().map(String::as_str).collect();
        let choice = choose_bwrap(&dirs, None, |_| false);
        assert_eq!(choice.path, Some(good));
        assert!(choice.skipped.is_empty());
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn a_missing_bwrap_is_never_launched_by_bare_name() {
        assert!(Path::new(BWRAP_NOT_FOUND).is_absolute());
        assert!(!Path::new(BWRAP_NOT_FOUND).exists());
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn bwrap_in_a_world_writable_dir_is_skipped_for_the_next_candidate() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let bad_dir = root.path().join("bad");
        let good_dir = root.path().join("good");
        let bad = make_bwrap(&bad_dir, 0o755);
        std::fs::set_permissions(&bad_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let good = make_bwrap(&good_dir, 0o755);
        let dirs = [bad_dir.to_str().unwrap(), good_dir.to_str().unwrap()];
        // A user running the suite can write both dirs, so decide by mode bits only here.
        let by_mode = |p: &Path| {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(p).unwrap().mode() & 0o022 != 0
                || std::fs::metadata(p.parent().unwrap()).unwrap().mode() & 0o022 != 0
        };
        let choice = choose_bwrap(&dirs, None, by_mode);
        assert_eq!(choice.skipped, vec![bad.clone()]);
        assert_eq!(choice.path, Some(good));
        assert!(!choice.from_path);
        let warnings = bwrap_choice_warnings(&choice);
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].1.contains(bad.to_str().unwrap()),
            "{warnings:?}"
        );
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn bwrap_with_a_group_or_world_writable_file_is_replaceable() {
        let root = tempfile::tempdir().unwrap();
        let file = make_bwrap(&root.path().join("d"), 0o775);
        assert!(bwrap_candidate_is_replaceable(&file));
        let file = make_bwrap(&root.path().join("e"), 0o757);
        assert!(bwrap_candidate_is_replaceable(&file));
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn bwrap_writable_by_the_current_user_is_replaceable_unless_root() {
        let root = tempfile::tempdir().unwrap();
        let file = make_bwrap(&root.path().join("d"), 0o755);
        // SAFETY: geteuid has no preconditions.
        let is_root = unsafe { libc::geteuid() } == 0;
        // Owned and writable by this user: replaceable for a normal user. Root's own files are the system's.
        assert_eq!(bwrap_candidate_is_replaceable(&file), !is_root);
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn bwrap_from_path_is_used_last_and_warns() {
        let root = tempfile::tempdir().unwrap();
        let sys = root.path().join("sys-empty");
        std::fs::create_dir_all(&sys).unwrap();
        let on_path = make_bwrap(&root.path().join("custom"), 0o755);
        let path_var =
            std::env::join_paths([Path::new("relative-dir"), on_path.parent().unwrap()]).unwrap();
        let choice = choose_bwrap(&[sys.to_str().unwrap()], Some(&path_var), |_| false);
        assert_eq!(choice.path, Some(on_path.clone()));
        assert!(choice.from_path);
        let warnings = bwrap_choice_warnings(&choice);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].1.contains("from PATH"), "{warnings:?}");
        assert!(
            warnings[0].1.contains(on_path.to_str().unwrap()),
            "{warnings:?}"
        );
        // A system-directory hit means no PATH warning at all.
        let sys_bwrap = make_bwrap(&sys, 0o755);
        let choice = choose_bwrap(&[sys.to_str().unwrap()], Some(&path_var), |_| false);
        assert_eq!(choice.path, Some(sys_bwrap));
        assert!(bwrap_choice_warnings(&choice).is_empty());
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn bwrap_with_only_replaceable_candidates_uses_the_first_and_warns_loudly() {
        let root = tempfile::tempdir().unwrap();
        let first = make_bwrap(&root.path().join("d1"), 0o755);
        let second = make_bwrap(&root.path().join("d2"), 0o755);
        let dirs = [
            first.parent().unwrap().to_str().unwrap(),
            second.parent().unwrap().to_str().unwrap(),
        ];
        let choice = choose_bwrap(&dirs, None, |_| true);
        assert_eq!(choice.path, Some(first.clone()));
        assert!(choice.replaceable);
        let warnings = bwrap_choice_warnings(&choice);
        let text = warnings
            .iter()
            .map(|(_, t)| t.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains(first.to_str().unwrap()), "{text}");
        assert!(
            text.contains("can be replaced by a user-level program"),
            "{text}"
        );
        assert!(
            text.contains("reinstall bubblewrap from your system packages"),
            "{text}"
        );
        // The other replaceable candidate is passed over quietly-as-before, the chosen one is not "ignored".
        assert!(
            !text.contains(&format!("ignoring bubblewrap at {}", first.display())),
            "{text}"
        );
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn a_safe_candidate_is_preferred_over_an_earlier_replaceable_one() {
        let root = tempfile::tempdir().unwrap();
        let bad = make_bwrap(&root.path().join("bad"), 0o755);
        let good = make_bwrap(&root.path().join("good"), 0o755);
        let dirs = [
            bad.parent().unwrap().to_str().unwrap(),
            good.parent().unwrap().to_str().unwrap(),
        ];
        let bad_for_test = bad.clone();
        let choice = choose_bwrap(&dirs, None, move |p| p == bad_for_test);
        assert_eq!(choice.path, Some(good));
        assert!(!choice.replaceable);
    }
    #[test]
    fn windows_warning_says_optional_and_points_to_wsl2() {
        let w = unavailable_warning_for("workspace", true).unwrap();
        assert!(w.contains("optional and off by default"), "{w}");
        assert!(w.contains("WSL2"), "{w}");
        assert!(w.contains("sudo apt install bubblewrap"), "{w}");
    }
    #[test]
    fn unavailable_warning_is_absent_for_off_and_off_windows() {
        assert_eq!(unavailable_warning_for("off", true), None);
        // Linux and macOS, with or without `enforce`: no new text; existing behaviour stays.
        assert_eq!(unavailable_warning_for("workspace", false), None);
        assert_eq!(unavailable_warning_for("strict", false), None);
        #[cfg(not(windows))]
        assert_eq!(unavailable_warning(), None);
    }
    #[test]
    fn unavailable_warning_scrubs_the_profile_name() {
        let w = unavailable_warning_for("evil\x1b[31m\nname", true).unwrap();
        assert!(!w.contains('\x1b'));
        assert!(!w.contains('\n'));
    }
    /// Save, set/remove, and auto-restore an env var on drop.
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }
    impl EnvGuard {
        fn set(key: &'static str, val: &str) -> Self {
            let prev = std::env::var(key).ok();
            unsafe { std::env::set_var(key, val) };
            Self { key, prev }
        }
        fn remove(key: &'static str) -> Self {
            let prev = std::env::var(key).ok();
            unsafe { std::env::remove_var(key) };
            Self { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }
    #[test]
    #[serial(bwrap_env)]
    fn is_confined_sees_the_bwrap_and_the_kernel_confinement_markers() {
        // Sets the inside-bwrap/confined marker: in its own process, or a parallel test resolving a profile
        // would take the inside-bwrap path and see no socket hand-off.
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _b = EnvGuard::remove(BWRAP_ENV_VAR);
        let _c = EnvGuard::remove(CONFINED_ENV_VAR);
        assert!(!is_confined(), "no sandbox: not confined");
        {
            let _g = EnvGuard::set(CONFINED_ENV_VAR, "1");
            assert!(
                is_confined(),
                "Landlock-only confinement leaves just the confined marker"
            );
            assert!(!is_inside_bwrap());
        }
        let _g = EnvGuard::set(BWRAP_ENV_VAR, "1");
        assert!(is_confined());
    }
    #[test]
    #[serial(bwrap_env)]
    fn bwrap_reexec_returns_none_inside_bwrap() {
        // Sets the inside-bwrap/confined marker: in its own process, or a parallel test resolving a profile
        // would take the inside-bwrap path and see no socket hand-off.
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _g = EnvGuard::set(BWRAP_ENV_VAR, "1");
        let result = bwrap_reexec_command(&["/data"], &[]);
        assert!(
            result.is_none(),
            "should return None when already inside bwrap"
        );
    }
    #[test]
    #[serial(bwrap_env)]
    #[cfg(target_os = "linux")]
    fn bwrap_reexec_returns_some_outside_bwrap() {
        let _g = EnvGuard::remove(BWRAP_ENV_VAR);
        let result = bwrap_reexec_command(&["/tmp"], &[]);
        assert!(result.is_some(), "should return Some when not inside bwrap");
        let cmd = result.unwrap();
        let program = Path::new(cmd.get_program());
        assert_eq!(
            program.file_name().and_then(|n| n.to_str()),
            Some("bwrap"),
            "program should be bwrap"
        );
    }
    #[test]
    #[serial(bwrap_env)]
    #[cfg(target_os = "linux")]
    fn bwrap_reexec_keeps_the_host_pid_namespace() {
        let _g = EnvGuard::remove(BWRAP_ENV_VAR);
        let cmd = bwrap_reexec_command(&["/tmp"], &[]).expect("bwrap command");
        assert!(
            cmd.get_args().all(|a| a != "--unshare-pid"),
            "pids fuigo records for other processes must stay valid outside the sandbox"
        );
    }
    #[test]
    #[serial(bwrap_env)]
    #[cfg(target_os = "linux")]
    fn bwrap_reexec_ignores_a_fake_bwrap_first_on_path() {
        use std::os::unix::fs::PermissionsExt;
        let Some(system) =
            choose_bwrap(BWRAP_SYSTEM_DIRS, None, bwrap_candidate_is_replaceable).path
        else {
            eprintln!("skipped: bwrap not found in a system directory");
            return;
        };
        let _g = EnvGuard::remove(BWRAP_ENV_VAR);
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("bwrap");
        std::fs::write(&fake, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let old_path = std::env::var_os("PATH");
        let mut joined = std::ffi::OsString::from(dir.path());
        joined.push(":");
        joined.push(old_path.clone().unwrap_or_default());
        unsafe { std::env::set_var("PATH", &joined) };
        let cmd = bwrap_reexec_command(&["/tmp"], &[]);
        match old_path {
            Some(v) => unsafe { std::env::set_var("PATH", v) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        let cmd = cmd.expect("bwrap command");
        assert_eq!(Path::new(cmd.get_program()), system.as_path());
        assert_ne!(Path::new(cmd.get_program()), fake.as_path());
    }
    #[test]
    #[serial(bwrap_env)]
    #[cfg(target_os = "linux")]
    fn bwrap_reexec_hands_outer_runtime_socket_set_to_inner_process() {
        let _g = EnvGuard::remove(BWRAP_ENV_VAR);
        let sockets = vec![PathBuf::from("/run/docker.sock")];
        let cmd = bwrap_reexec_command_ex(&[], None, &[], &sockets).expect("bwrap command");
        let handed = cmd
            .get_envs()
            .find_map(|(key, value)| {
                (key == runtime_sockets::BWRAP_RUNTIME_SOCKET_DENY_ENV_VAR).then(|| {
                    value
                        .expect("handoff env has a value")
                        .to_string_lossy()
                        .into_owned()
                })
            })
            .expect("runtime-socket handoff env");
        assert_eq!(
            serde_json::from_str::<Vec<PathBuf>>(&handed).unwrap(),
            sockets
        );
    }
    #[test]
    #[serial(bwrap_env)]
    fn trust_bwrap_marker_for_devbox_requires_sentinel_mount() {
        // Sets the inside-bwrap/confined marker: in its own process, or a parallel test resolving a profile
        // would take the inside-bwrap path and see no socket hand-off.
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _g = EnvGuard::set(BWRAP_ENV_VAR, "1");
        assert!(
            !trust_bwrap_marker_for_devbox(),
            "env marker without the sentinel mount must not be trusted"
        );
    }
    #[test]
    #[serial(bwrap_env)]
    fn trust_bwrap_marker_for_devbox_false_outside_bwrap() {
        let _g = EnvGuard::remove(BWRAP_ENV_VAR);
        assert!(!trust_bwrap_marker_for_devbox());
        assert!(!is_inside_bwrap());
    }
    #[test]
    #[serial(bwrap_env)]
    #[cfg(target_os = "linux")]
    fn bwrap_reexec_skips_nonexistent_paths() {
        let _g = EnvGuard::remove(BWRAP_ENV_VAR);
        let result = bwrap_reexec_command(&["/nonexistent-test-path-xyz-12345"], &[]);
        let cmd = result.unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(
            !args.iter().any(|a| a == "/nonexistent-test-path-xyz-12345"),
            "should skip non-existent deny_write paths, got args: {args:?}"
        );
    }
    #[test]
    #[serial(bwrap_env)]
    #[cfg(all(feature = "enforce", target_os = "linux"))]
    fn bwrap_reexec_binds_nonexistent_deny_read_paths() {
        let _g = EnvGuard::remove(BWRAP_ENV_VAR);
        let missing = "/nonexistent-deny-read-path-xyz-12345";
        let result = bwrap_reexec_command(&[], &[missing]);
        let cmd = result.unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        let has_bind = args
            .windows(3)
            .any(|w| w[0] == "--ro-bind" && w[2] == missing);
        assert!(
            has_bind,
            "should bind-over non-existent deny_read paths, got args: {args:?}"
        );
    }
    #[test]
    #[serial(bwrap_env)]
    #[cfg(target_os = "linux")]
    fn bwrap_reexec_mounts_existing_paths_read_only() {
        let _g = EnvGuard::remove(BWRAP_ENV_VAR);
        let result = bwrap_reexec_command(&["/tmp"], &[]);
        let cmd = result.unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        let has_ro_bind = args.windows(3).any(|w| w == ["--ro-bind", "/tmp", "/tmp"]);
        assert!(
            has_ro_bind,
            "should mount existing paths as --ro-bind, got args: {args:?}"
        );
    }
    /// Hook plan: rootward ancestor RW self-binds precede leaf RO; no bwrap version flags required.
    /// Identity revalidation is part of append.
    #[test]
    #[serial(bwrap_env)]
    #[cfg(target_os = "linux")]
    fn bwrap_hook_plan_binds_ancestors_then_leaves() {
        let _g = EnvGuard::remove(BWRAP_ENV_VAR);
        let root = std::env::temp_dir().join(format!(
            "fuigo-bwrap-hook-plan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let parent = root.join("sessions");
        let leaf = parent.join("extra-hooks");
        std::fs::create_dir_all(&leaf).unwrap();
        let sources = [fuigo_config::GlobalHookSource {
            path: leaf.clone(),
            kind: fuigo_config::GlobalHookSourceKind::ConfiguredSource,
        }];
        let plan = hook_write_deny::build_bwrap_plan(&sources).expect("plan");
        assert!(
            !plan.ancestor_rw_binds.iter().any(|p| p == Path::new("/")),
            "must not RW-bind /: {:?}",
            plan.ancestor_rw_binds
        );
        assert!(
            plan.ancestor_rw_binds.iter().any(|p| p == &parent),
            "immediate parent must be pinned: {:?}",
            plan.ancestor_rw_binds
        );
        for w in plan.ancestor_rw_binds.windows(2) {
            assert!(
                w[0].components().count() <= w[1].components().count(),
                "ancestors not rootward: {:?}",
                plan.ancestor_rw_binds
            );
        }
        let moved = root.join("extra-hooks-old");
        std::fs::rename(&leaf, &moved).unwrap();
        std::fs::create_dir_all(&leaf).unwrap();
        let mut refuse = std::process::Command::new("bwrap");
        let err = hook_write_deny::append_hook_plan_binds(&mut refuse, &plan);
        assert!(err.is_err(), "must refuse replaced leaf identity");
        let _ = std::fs::remove_dir_all(&leaf);
        std::fs::rename(&moved, &leaf).unwrap();
        let plan = hook_write_deny::build_bwrap_plan(&sources).expect("plan2");
        let cmd = bwrap_reexec_command_ex(&[], Some(&plan), &[], &[]).expect("bwrap command");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(
            !args.iter().any(|a| a == "--disable-userns"),
            "must not require --disable-userns: {args:?}"
        );
        assert!(
            args.windows(2).any(|w| w == ["--cap-drop", "ALL"]),
            "expected --cap-drop ALL: {args:?}"
        );
        let parent_s = parent.to_string_lossy().to_string();
        let leaf_s = leaf.to_string_lossy().to_string();
        let anc_parent = args
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == parent_s && w[2] == parent_s);
        let leaf_pos = args
            .windows(3)
            .position(|w| w[0] == "--ro-bind" && w[1] == leaf_s && w[2] == leaf_s);
        assert!(anc_parent.is_some(), "expected RW bind of parent: {args:?}");
        assert!(leaf_pos.is_some(), "expected RO bind of leaf: {args:?}");
        assert!(
            anc_parent.unwrap() < leaf_pos.unwrap(),
            "ancestor RW must precede leaf RO; args: {args:?}"
        );
        for anc in &plan.ancestor_rw_binds {
            let a = anc.to_string_lossy().to_string();
            let pos = args
                .windows(3)
                .position(|w| w[0] == "--bind" && w[1] == a && w[2] == a);
            assert!(pos.is_some(), "missing RW bind for {a}: {args:?}");
            assert!(pos.unwrap() < leaf_pos.unwrap());
        }
        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    #[serial(bwrap_env)]
    #[cfg(target_os = "linux")]
    fn bwrap_reexec_uses_dev_bind() {
        let _g = EnvGuard::remove(BWRAP_ENV_VAR);
        let result = bwrap_reexec_command(&[], &[]);
        let cmd = result.unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        let has_dev_bind = args.windows(3).any(|w| w == ["--dev-bind", "/dev", "/dev"]);
        assert!(
            has_dev_bind,
            "should use --dev-bind for /dev passthrough, got args: {args:?}"
        );
    }
    #[test]
    fn profile_confines_only_for_non_off_profiles() {
        assert!(!super::profile_confines("off"));
        assert!(!super::profile_confines("none"));
        assert!(super::profile_confines("strict"));
        assert!(super::profile_confines("read-only"));
        assert!(super::profile_confines("readonly"));
        assert!(super::profile_confines("my-custom-profile"));
    }
    #[test]
    fn known_launch_guard_keys_on_config_not_apply_state() {
        assert_eq!(
            restrict_network_at_known_linux_launches(true),
            cfg!(target_os = "linux")
        );
        assert!(!restrict_network_at_known_linux_launches(false));
        let manager = SandboxManager::new(ProfileName::ReadOnly, Path::new("/tmp"));
        assert!(!manager.is_applied());
        assert_eq!(
            manager.restrict_child_network(),
            cfg!(target_os = "linux"),
            "arming must not require applied=true"
        );
    }
    /// Create a temp workspace whose `.fuigo/sandbox.toml` contains `toml_body`.
    /// Returns the workspace path (caller removes it).
    #[cfg(all(feature = "enforce", unix))]
    fn temp_workspace_with_sandbox_toml(tag: &str, toml_body: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let ws = std::env::temp_dir().join(format!("fuigo-{tag}-{}-{nanos}", std::process::id()));
        let fuigo = ws.join(".fuigo");
        std::fs::create_dir_all(&fuigo).unwrap();
        std::fs::write(fuigo.join(fuigo_config::SANDBOX_CONFIG_FILENAME), toml_body).unwrap();
        ws
    }
    /// Create a temp workspace defining a `denytest` profile (extends `workspace`) with the given `deny` list.
    /// `deny_toml` is the raw TOML array body (e.g. `"\".env\""`).
    #[cfg(all(feature = "enforce", unix))]
    fn temp_workspace_with_deny(tag: &str, deny_toml: &str) -> PathBuf {
        temp_workspace_with_sandbox_toml(
            tag,
            &format!("[profiles.denytest]\nextends = \"workspace\"\ndeny = [{deny_toml}]\n"),
        )
    }
    #[test]
    #[cfg(all(feature = "enforce", unix))]
    fn requires_read_deny_only_for_custom_profile_with_deny() {
        let ws = temp_workspace_with_deny("requires-deny", "\".env\"");
        assert!(requires_read_deny(
            &ProfileName::Custom("denytest".to_string()),
            &ws
        ));
        assert!(!requires_read_deny(
            &ProfileName::Custom("undefined".to_string()),
            &ws
        ));
        assert!(!requires_read_deny(&ProfileName::Workspace, &ws));
        assert!(!requires_read_deny(&ProfileName::Strict, &ws));
        assert!(!requires_read_deny(&ProfileName::Devbox, &ws));
        assert!(!requires_read_deny(&ProfileName::Off, &ws));
        let _ = std::fs::remove_dir_all(&ws);
    }
    #[test]
    #[cfg(all(feature = "enforce", unix))]
    fn requires_read_deny_for_custom_profile_with_effective_restrict_network() {
        let ws = temp_workspace_with_sandbox_toml(
            "requires-net-true",
            "[profiles.netdeny]\nextends = \"devbox\"\nrestrict_network = true\n",
        );
        assert!(requires_read_deny(
            &ProfileName::Custom("netdeny".to_string()),
            &ws
        ));
        let _ = std::fs::remove_dir_all(&ws);
        let ws = temp_workspace_with_sandbox_toml(
            "requires-net-false",
            "[profiles.netoff]\nextends = \"workspace\"\nrestrict_network = false\n",
        );
        assert!(!requires_read_deny(
            &ProfileName::Custom("netoff".to_string()),
            &ws
        ));
        let _ = std::fs::remove_dir_all(&ws);
        let ws = temp_workspace_with_sandbox_toml(
            "requires-net-none",
            "[profiles.netnone]\nextends = \"workspace\"\n",
        );
        assert!(!requires_read_deny(
            &ProfileName::Custom("netnone".to_string()),
            &ws
        ));
        let _ = std::fs::remove_dir_all(&ws);
        let ws = temp_workspace_with_sandbox_toml(
            "requires-net-inherit",
            "[profiles.netinherit]\nextends = \"read-only\"\n",
        );
        assert!(requires_read_deny(
            &ProfileName::Custom("netinherit".to_string()),
            &ws
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }
    #[test]
    #[cfg(all(feature = "enforce", target_os = "linux"))]
    fn requires_data_write_deny_for_devbox_based_profiles_when_data_exists() {
        let mut config = SandboxConfig::default();
        config.profiles.insert(
            "devext".to_string(),
            profiles::ProfileConfig {
                extends: Some("devbox".to_string()),
                restrict_network: None,
                workspace_write: None,
                read_only: Vec::new(),
                read_write: Vec::new(),
                deny: Vec::new(),
            },
        );
        config.profiles.insert(
            "wsext".to_string(),
            profiles::ProfileConfig {
                extends: Some("workspace".to_string()),
                restrict_network: None,
                workspace_write: None,
                read_only: Vec::new(),
                read_write: Vec::new(),
                deny: Vec::new(),
            },
        );
        let data_root = temp_workspace_with_sandbox_toml("requires-data-root", "");
        let existing_data = data_root.join("data");
        std::fs::create_dir(&existing_data).unwrap();
        let missing_data = data_root.join("missing-data");
        assert!(data_path_requires_bind(&existing_data));
        assert!(!data_path_requires_bind(&missing_data));
        assert!(requires_data_write_deny_for(
            &ProfileName::Devbox,
            &config,
            true
        ));
        assert!(requires_data_write_deny_for(
            &ProfileName::Custom("devext".to_string()),
            &config,
            true
        ));
        assert!(!requires_data_write_deny_for(
            &ProfileName::Custom("wsext".to_string()),
            &config,
            true
        ));
        assert!(!requires_data_write_deny_for(
            &ProfileName::Workspace,
            &config,
            true
        ));
        assert!(!requires_data_write_deny_for(
            &ProfileName::Off,
            &config,
            true
        ));
        assert!(!requires_data_write_deny_for(
            &ProfileName::Devbox,
            &config,
            false
        ));
        let _ = std::fs::remove_dir_all(&data_root);
    }
    #[test]
    #[serial(bwrap_env)]
    #[cfg(all(feature = "enforce", target_os = "linux"))]
    fn bwrap_reexec_uses_dir_placeholder_for_directories() {
        let _g = EnvGuard::remove(BWRAP_ENV_VAR);
        let dir = std::env::temp_dir().join(format!("fuigo-deny-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_str = dir.to_string_lossy().to_string();
        let result = bwrap_reexec_command(&[], &[&dir_str]);
        let cmd = result.unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        let blocked_dir = paths::fuigo_home()
            .join(format!("sandbox-blocked-dir.{}", std::process::id()))
            .to_string_lossy()
            .to_string();
        let has_dir_bind = args
            .windows(3)
            .any(|w| w[0] == "--ro-bind" && w[1] == blocked_dir && w[2] == dir_str);
        assert!(
            has_dir_bind,
            "existing directories should bind over sandbox-blocked-dir, got args: {args:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    #[serial(bwrap_env)]
    #[cfg(all(feature = "enforce", target_os = "linux"))]
    fn bwrap_reexec_for_profile_devbox_extends_composes_data_and_read_deny() {
        let _g = EnvGuard::remove(BWRAP_ENV_VAR);
        let ws = temp_workspace_with_sandbox_toml(
            "devbox-compose",
            "[profiles.devcustom]\nextends = \"devbox\"\ndeny = [\"secret.pem\"]\n",
        );
        let cmd = bwrap_reexec_for_profile(&ProfileName::Custom("devcustom".to_string()), &ws)
            .expect("devbox-extending custom with deny should build a re-exec command");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        let deny_path = ws.join("secret.pem").to_string_lossy().to_string();
        assert!(
            args.windows(3)
                .any(|w| w[0] == "--ro-bind" && w[2] == deny_path),
            "expected read-deny bind for {deny_path}, got args: {args:?}"
        );
        if Path::new("/data").exists() {
            assert!(
                args.windows(3)
                    .any(|w| w == ["--ro-bind", "/data", "/data"]),
                "expected /data write-deny ro-bind, got args: {args:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&ws);
        let ws_ws = temp_workspace_with_sandbox_toml(
            "ws-empty",
            "[profiles.wsempty]\nextends = \"workspace\"\n",
        );
        assert!(
            bwrap_reexec_for_profile(&ProfileName::Custom("wsempty".to_string()), &ws_ws).is_some(),
            "non-devbox custom must re-exec for direct-hook write-deny"
        );
        let _ = std::fs::remove_dir_all(&ws_ws);
    }
    #[test]
    #[cfg(all(feature = "enforce", target_os = "linux"))]
    fn resolve_failure_refuses_for_deny_carrying_devbox_extends() {
        let workspace = temp_workspace_with_sandbox_toml(
            "resolve-refuse",
            "[profiles.devdeny]\nextends = \"devbox\"\ndeny = [\"secret.pem\"]\n",
        );
        let profile = ProfileName::Custom("devdeny".to_string());
        assert!(!requires_hook_write_deny(&profile, &workspace));
        assert!(resolve_failure_must_refuse(&profile, &workspace));
        let _ = std::fs::remove_dir_all(&workspace);
    }
    #[test]
    #[serial(bwrap_env)]
    #[cfg(all(feature = "enforce", target_os = "linux"))]
    fn bwrap_reexec_for_profile_skips_plan_inside_bwrap() {
        // Sets the inside-bwrap/confined marker: in its own process, or a parallel test resolving a profile
        // would take the inside-bwrap path and see no socket hand-off.
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let _g = EnvGuard::set(BWRAP_ENV_VAR, "1");
        let workspace = temp_workspace_with_sandbox_toml(
            "inside-bwrap-skip",
            "[profiles.devskip]\nextends = \"devbox\"\ndeny = [\"secret.pem\"]\n",
        );
        assert!(
            bwrap_reexec_for_profile(&ProfileName::Custom("devskip".to_string()), &workspace)
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&workspace);
    }
}
