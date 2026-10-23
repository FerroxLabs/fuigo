//! Pins the process-wide surface the fuigo CLI calls: each entry point coerces to its declared
//! fn-pointer type, and an unapplied process is inactive, unconfigured, with a no-op
//! child-network filter.

use std::path::Path;

use fuigo_sandbox::{ProfileName, SandboxLogger, SandboxManager, SandboxMetrics};

/// `cargo public-api`-style snapshot of the CLI-facing signatures, checked by the compiler.
#[test]
fn cli_facing_process_wide_surface_unchanged() {
    let _: fn(ProfileName, &Path) -> SandboxManager = SandboxManager::new;
    let _: fn(&mut SandboxManager, &Path) -> anyhow::Result<()> = SandboxManager::apply;
    let _: fn(SandboxManager) = SandboxManager::install;
    let _: fn(&SandboxManager) -> bool = SandboxManager::is_applied;
    let _: fn(&SandboxManager) -> bool = SandboxManager::restrict_child_network;
    let _: fn(&SandboxManager) -> &ProfileName = SandboxManager::profile;
    let _: fn(&SandboxManager) -> &SandboxLogger = SandboxManager::logger;

    let _: fn(&mut tokio::process::Command) = fuigo_sandbox::child_net::restrict_child_network;
    let _: fn(&mut std::process::Command) = fuigo_sandbox::child_net::restrict_child_network_std;

    let _: fn() -> bool = fuigo_sandbox::is_inside_bwrap;
    let _: fn() -> bool = fuigo_sandbox::trust_bwrap_marker_for_devbox;
    let _: fn() -> bool = fuigo_sandbox::should_restrict_child_network;
    let _: fn() -> bool = fuigo_sandbox::should_auto_allow_bash;
    let _: fn(bool) = fuigo_sandbox::set_auto_allow_bash;
    // `impl Into<String>` cannot be named as a fn pointer; both call shapes the CLI uses compile
    let set_by_string: fn(String) = |name| fuigo_sandbox::set_configured_profile(name);
    let set_by_str: fn(&str) = |name| fuigo_sandbox::set_configured_profile(name);
    let _ = (set_by_string, set_by_str);
    let _: fn() -> Option<&'static str> = fuigo_sandbox::configured_profile_name;
    let _: fn() -> Option<&'static str> = fuigo_sandbox::requested_confinement_profile;
    let _: fn() -> bool = fuigo_sandbox::is_active;
    let _: fn() -> Option<&'static str> = fuigo_sandbox::profile_name;
    let _: fn(&str, &str) = fuigo_sandbox::log_violation;
    let _: fn() = fuigo_sandbox::flush;
    let _: fn() -> Option<&'static SandboxMetrics> = fuigo_sandbox::metrics;

    let _: fn(&ProfileName, &Path) -> bool = fuigo_sandbox::requires_hook_write_deny;
    let _: fn(&ProfileName) -> bool = fuigo_sandbox::profile_enforces_hook_write_deny;
    let _: fn() -> Result<(), String> = fuigo_sandbox::verify_hook_write_deny_enforced;
    let _: fn(&Path) -> Vec<String> = fuigo_sandbox::sandbox_profile_conflicts;
    let _: fn(&Path) -> fuigo_sandbox::SandboxConfig = fuigo_sandbox::load_sandbox_config;
    let _: fn(&[&str], &[&str]) -> Option<std::process::Command> =
        fuigo_sandbox::bwrap_reexec_command;
    #[cfg(target_os = "linux")]
    {
        let _: fn(&ProfileName, &Path) -> Option<std::process::Command> =
            fuigo_sandbox::bwrap_reexec_for_profile;
        let _: fn(&ProfileName, &Path) -> bool = fuigo_sandbox::requires_data_write_deny;
    }
    #[cfg(unix)]
    {
        let _: fn(&ProfileName, &Path) -> bool = fuigo_sandbox::requires_read_deny;
    }

    // The profile vocabulary the shell's `--sandbox` flag and `[sandbox] profile` parse into
    let _ = ProfileName::Off;
    let _ = ProfileName::Custom("devbox-like".to_owned());
    assert_eq!(Ok(ProfileName::Off), "off".parse::<ProfileName>());
}

/// A process that never called `SandboxManager::apply`: nothing is active, nothing is
/// configured, the per-spawn child-network filter leaves the command as it is.
#[test]
fn cli_facing_process_wide_getters_unchanged_without_apply() {
    assert!(!fuigo_sandbox::is_active());
    assert_eq!(None, fuigo_sandbox::profile_name());
    assert!(!fuigo_sandbox::should_restrict_child_network());
    assert!(!fuigo_sandbox::should_auto_allow_bash());
    assert!(fuigo_sandbox::metrics().is_none());
    // No-ops on an unapplied process
    fuigo_sandbox::log_violation("/nowhere", "write");
    fuigo_sandbox::flush();

    let mut cmd = tokio::process::Command::new("/bin/true");
    cmd.arg("--flag").current_dir("/").env("K", "v");
    fuigo_sandbox::child_net::restrict_child_network(&mut cmd);
    let std_cmd = cmd.as_std();
    assert_eq!(Path::new("/bin/true"), Path::new(std_cmd.get_program()));
    assert_eq!(
        vec![std::ffi::OsStr::new("--flag")],
        std_cmd.get_args().collect::<Vec<_>>()
    );
    assert_eq!(Some(Path::new("/")), std_cmd.get_current_dir());
    assert_eq!(
        vec![(std::ffi::OsStr::new("K"), Some(std::ffi::OsStr::new("v")))],
        std_cmd.get_envs().collect::<Vec<_>>()
    );

    let mut std_command = std::process::Command::new("/bin/true");
    std_command.arg("--flag");
    fuigo_sandbox::child_net::restrict_child_network_std(&mut std_command);
    assert_eq!(
        vec![std::ffi::OsStr::new("--flag")],
        std_command.get_args().collect::<Vec<_>>()
    );
}

/// The `off` profile the CLI defaults to: not applied, no child-network restriction, the profile
/// echoed back.
#[test]
fn cli_facing_off_profile_manager_unchanged() {
    let manager = SandboxManager::new(ProfileName::Off, Path::new("/"));
    assert!(!manager.is_applied());
    assert!(!manager.restrict_child_network());
    assert_eq!(&ProfileName::Off, manager.profile());
    assert!(!fuigo_sandbox::requires_hook_write_deny(
        &ProfileName::Off,
        Path::new("/")
    ));
    assert!(!fuigo_sandbox::profile_enforces_hook_write_deny(
        &ProfileName::Off
    ));
}
