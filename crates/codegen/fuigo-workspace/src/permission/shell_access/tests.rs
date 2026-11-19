use super::*;
use crate::permission::bash_command_splitting::{
    MAX_INLINE_SHELL_DEPTH, MAX_TRANSPARENT_PREFIX_DEPTH, MAX_WRAPPER_DEPTH,
};
use crate::permission::types::{
    PatternMode, PermissionConfig, PermissionRule, RuleAction, ToolFilter,
};

fn file_rule(action: RuleAction, tool: ToolFilter, pattern: &str) -> PermissionRule {
    PermissionRule {
        action,
        tool,
        pattern: Some(pattern.to_owned()),
        pattern_mode: PatternMode::Glob,
    }
}

fn bash_rule(action: RuleAction, pattern: &str) -> PermissionRule {
    file_rule(action, ToolFilter::Bash, pattern)
}

fn compiled(rules: Vec<PermissionRule>) -> CompiledPolicy {
    CompiledPolicy::new(PermissionConfig::new(rules))
}

fn cwd() -> &'static std::path::Path {
    std::path::Path::new("/work")
}

#[test]
fn shell_file_gate_distinguishes_ask_provenance() {
    let ask = compiled(vec![file_rule(
        RuleAction::Ask,
        ToolFilter::Read,
        "**/secrets/**",
    )]);
    // Rule match: an identified operand hits the ask rule.
    assert_eq!(
        ask.evaluate_shell_file_access_gate("cat secrets/token.txt", cwd()),
        Some(GateDecision::AskRuleMatch)
    );
    // Fail-closed: a recursive reader has no pinnable operands.
    assert_eq!(
        ask.evaluate_shell_file_access_gate("rg TODO", cwd()),
        Some(GateDecision::AskFailClosed)
    );
    // Fail-closed: a dynamic operand on a known reader is unpinnable.
    assert_eq!(
        ask.evaluate_shell_file_access_gate("cat \"$F\"", cwd()),
        Some(GateDecision::AskFailClosed)
    );
    // A rule match anywhere outranks a fail-closed floor in the same script.
    assert_eq!(
        ask.evaluate_shell_file_access_gate("rg TODO && cat secrets/token.txt", cwd()),
        Some(GateDecision::AskRuleMatch)
    );
    // Deny rules keep rejecting with provenance preserved.
    let deny = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    assert!(matches!(
        deny.evaluate_shell_file_access_gate("cat .env", cwd()),
        Some(GateDecision::Reject(_))
    ));
}

#[test]
fn shell_gate_matches_cwd_relative_rules_on_absolute_operands() {
    let deny = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "src/**",
    )]);
    // A rooted relative rule keys on the same file spelled absolutely, matching the direct Read tool gate (which evaluates with the cwd)
    assert!(matches!(
        deny.evaluate_shell_file_access_gate("cat /work/src/secret.txt", cwd()),
        Some(GateDecision::Reject(_))
    ));
    // An absolute operand is cwd-independent, so it stays covered even after a `cd` unpins the working directory
    assert!(matches!(
        deny.evaluate_shell_file_access_gate("cd /tmp && cat /work/src/secret.txt", cwd()),
        Some(GateDecision::Reject(_))
    ));
    // Outside the working directory the rooted rule stays silent.
    assert_eq!(
        deny.evaluate_shell_file_access_gate("cat /elsewhere/src/secret.txt", cwd()),
        None
    );
}

#[test]
fn sensitive_edit_targets_and_lexical_aliases_prompt() {
    for path in [
        "/home/user/.zshrc",
        "/etc",
        "/etc/fuigo-test",
        "/work/subdir/../.git/hooks/pre-commit",
        "/home/user/.fuigo/sandbox.toml",
        "/work/project/.fuigo/sandbox.toml",
    ] {
        assert!(
            edit_target_protection(Path::new(path)).is_some(),
            "protected edit target must prompt: {path}"
        );
    }
    for path in [
        "/work/src/main.rs",
        "/work/project/.fuigo/config.toml/backup",
        "/work/project/sandbox.toml",
        "/work/project/requirements.toml",
        "/work/project/managed_config.toml",
    ] {
        assert!(
            edit_target_protection(Path::new(path)).is_none(),
            "ordinary edit target should not prompt: {path}"
        );
    }
}

#[test]
fn sensitive_edit_targets_include_submodule_hooks() {
    for path in [
        "/work/.git/modules/foo/hooks/pre-commit",
        "/work/.git/modules/submodules/sglang-private/hooks/pre-commit",
        "/work/.git/modules/outer/modules/inner/hooks/pre-commit",
        "/work/subdir/../.git/modules/foo/hooks/pre-commit",
    ] {
        assert!(
            edit_target_protection(Path::new(path)).is_some(),
            "submodule hook target must prompt: {path}"
        );
    }
    for path in [
        "/work/.git/modules/hooks/pre-commit",
        "/work/.git/module/foo/hooks/pre-commit",
        "/work/.git/modules/foo/hook/pre-commit",
        "/work/.git/modules/foo/hooks-disabled/pre-commit",
        "/work/src/modules/foo/hooks/pre-commit",
    ] {
        assert!(
            edit_target_protection(Path::new(path)).is_none(),
            "non-hook control must not prompt: {path}"
        );
    }
}

/// P166 r9 (MEDIUM 6): the `git config` SET classifier and the ambient config scan read ONE key table, so every
/// table entry is both a SET redirect and an ambient exec entry (and a benign value is neither).
#[test]
fn p166_r9_config_key_table_is_shared_by_set_and_ambient_scan() {
    use crate::permission::exec_risk::{
        COMMAND_VALUED_CONFIG_KEYS, ConfigValue, local_git_config_entry_is_exec,
    };
    assert!(COMMAND_VALUED_CONFIG_KEYS.len() >= 30);
    for (pattern, rule) in COMMAND_VALUED_CONFIG_KEYS {
        let key = if *rule == ConfigValue::ExtBase {
            pattern.replace('*', "ext::sh -c evil")
        } else {
            pattern.replace('*', "x.y")
        };
        let (command, benign) = match rule {
            ConfigValue::Any => ("/tmp/evil", None),
            ConfigValue::NotBool => ("/tmp/evil", Some("false")),
            ConfigValue::ExtBase => ("x", None),
            ConfigValue::Bang => ("!/tmp/evil", Some("merge")),
            ConfigValue::PathLike => ("/tmp/evil", Some("smtp.example.com")),
            ConfigValue::NotNever => ("always", Some("never")),
            ConfigValue::Url => ("ext::sh -c evil", Some("https://github.com/a/b")),
            ConfigValue::TraceTarget => ("/tmp/trace.json", Some("2")),
        };
        assert!(
            local_git_config_entry_is_exec(&key, command),
            "ambient: {key}={command}"
        );
        assert!(
            config_words_set_command_valued(&[key.as_str(), command]),
            "set (config): {key} {command}"
        );
        if let Some(benign) = benign {
            assert!(
                !local_git_config_entry_is_exec(&key, benign),
                "ambient benign: {key}={benign}"
            );
            assert!(
                !config_words_set_command_valued(&[key.as_str(), benign]),
                "set benign: {key} {benign}"
            );
        }
    }
    for key in ["url.https://b/.insteadof", "url.https://b/.pushinsteadof"] {
        assert!(
            !local_git_config_entry_is_exec(key, "ext::sh -c evil"),
            "{key}"
        );
        assert!(
            !config_words_set_command_valued(&[key, "ext::sh -c evil"]),
            "{key}"
        );
    }
    for key in [
        "user.name",
        "pull.rebase",
        "color.ui",
        "core.autocrlf",
        "diff.tool",
    ] {
        assert!(!local_git_config_entry_is_exec(key, "x"), "{key}");
        assert!(!config_words_set_command_valued(&[key, "x"]), "{key}");
    }
}

#[test]
fn edit_target_protection_classifies_reasons() {
    let cases = [
        (
            "/home/user/.fuigo/hooks/evil.json",
            ProtectedEditReason::HookRoot,
        ),
        ("/work/.git/hooks/pre-commit", ProtectedEditReason::GitHooks),
        ("/home/user/.ssh/id_rsa", ProtectedEditReason::Ssh),
        ("/home/user/.zshrc", ProtectedEditReason::StartupFile),
        ("/etc/hosts", ProtectedEditReason::Etc),
        (
            "/home/user/.fuigo/config.toml",
            ProtectedEditReason::FuigoConfig,
        ),
        (
            "/home/user/.fuigo/sandbox.toml",
            ProtectedEditReason::FuigoSandbox,
        ),
        (
            "/work/project/.fuigo/sandbox.toml",
            ProtectedEditReason::FuigoSandbox,
        ),
        (
            "/home/user/.fuigo/managed_config.toml",
            ProtectedEditReason::FuigoConfig,
        ),
        (
            "/home/user/.fuigo/requirements.toml",
            ProtectedEditReason::FuigoConfig,
        ),
        (
            "/home/user/.claude/settings.json",
            ProtectedEditReason::ClaudeSettings,
        ),
        (
            "/home/user/.cursor/hooks.json",
            ProtectedEditReason::CursorHooks,
        ),
    ];
    for (path, reason) in cases {
        assert_eq!(
            edit_target_protection(Path::new(path)),
            Some(reason),
            "{path}"
        );
        assert!(reason.description().is_some(), "{path}");
    }
    assert_eq!(
        edit_target_protection(Path::new("/home/user/project/src/main.rs")),
        None
    );
    assert!(ProtectedEditReason::Sensitive.description().is_none());
}

#[test]
fn sensitive_edit_targets_include_hook_roots() {
    for path in [
        "/home/user/.fuigo/hooks/evil.json",
        "/home/user/.fuigo/hooks/nested/deep.json",
        "/home/user/.fuigo/hooks-paths",
        "/home/user/.claude/settings.json",
        "/home/user/.claude/settings.local.json",
        "/home/user/.cursor/hooks.json",
        "/work/project/.fuigo/hooks/local.json",
        "/work/project/.fuigo/hooks-paths",
    ] {
        assert!(
            edit_target_protection(Path::new(path)).is_some(),
            "hook root edit target must prompt: {path}"
        );
    }
    for path in [
        "/home/user/.fuigo/hooks-disabled/note.json",
        "/home/user/.fuigo/hooks-evil/note.json",
        "/home/user/project/src/hooks.json",
        "/home/user/.claude/other.json",
        "/home/user/.cursor/settings.json",
    ] {
        assert!(
            edit_target_protection(Path::new(path)).is_none(),
            "ordinary edit target should not prompt: {path}"
        );
    }
}

#[test]
fn path_is_under_user_fuigo_hook_root_matches_relocated_home() {
    let home = Path::new("/custom/fuigo-home");
    for path in [
        "/custom/fuigo-home/hooks/x.json",
        "/custom/fuigo-home/hooks/nested/deep.json",
        "/custom/fuigo-home/hooks",
        "/custom/fuigo-home/hooks-paths",
    ] {
        assert!(
            path_is_under_user_fuigo_hook_root(Path::new(path), home),
            "must match under custom fuigo home: {path}"
        );
    }
    for path in [
        "/custom/fuigo-home/hooks-disabled/note.json",
        "/custom/fuigo-home/hooks-evil/note.json",
        "/custom/fuigo-home/config.toml",
        "/custom/other/hooks/x.json",
        "/custom/fuigo-home-extra/hooks/x.json",
    ] {
        assert!(
            !path_is_under_user_fuigo_hook_root(Path::new(path), home),
            "must not match outside hook roots: {path}"
        );
    }
}

#[test]
#[cfg(unix)]
fn sensitive_edit_targets_follow_symlinks() {
    use std::os::unix::fs::symlink;
    let ws = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let startup = outside.path().join(".zshrc");
    std::fs::write(&startup, b"").unwrap();
    symlink(&startup, ws.path().join("file-link")).unwrap();
    std::fs::create_dir_all(outside.path().join(".git/hooks")).unwrap();
    symlink(
        outside.path().join(".git/hooks"),
        ws.path().join("hooks-link"),
    )
    .unwrap();
    std::fs::create_dir_all(outside.path().join(".git/modules/foo/hooks")).unwrap();
    symlink(
        outside.path().join(".git/modules/foo/hooks"),
        ws.path().join("module-hooks-link"),
    )
    .unwrap();
    let fuigo_hook = outside.path().join(".fuigo/hooks/evil.json");
    std::fs::create_dir_all(fuigo_hook.parent().unwrap()).unwrap();
    std::fs::write(&fuigo_hook, b"{}").unwrap();
    symlink(&fuigo_hook, ws.path().join("fuigo-hook-link")).unwrap();

    for path in [
        ws.path().join("file-link"),
        ws.path().join("hooks-link/new-hook"),
        ws.path().join("module-hooks-link/new-hook"),
        ws.path().join("fuigo-hook-link"),
    ] {
        assert!(
            edit_target_protection(&path).is_some(),
            "symlinked protected edit target must prompt: {}",
            path.display()
        );
    }
}

/// A custom `$FUIGO_HOME` has no `.fuigo` path component, so the live `config.toml` / `sandbox.toml` must be caught by the home-prefix branch.
#[test]
fn fuigo_config_files_under_custom_fuigo_home_are_protected() {
    let home = tempfile::tempdir().unwrap();
    let home_path = home.path();
    for (file, reason) in [
        (
            fuigo_config::USER_CONFIG_FILENAME,
            ProtectedEditReason::FuigoConfig,
        ),
        (
            fuigo_config::MANAGED_CONFIG_FILENAME,
            ProtectedEditReason::FuigoConfig,
        ),
        (
            fuigo_config::REQUIREMENTS_FILENAME,
            ProtectedEditReason::FuigoConfig,
        ),
        (
            fuigo_config::SANDBOX_CONFIG_FILENAME,
            ProtectedEditReason::FuigoSandbox,
        ),
    ] {
        let path = home_path.join(file);
        let components = [file];
        assert_eq!(
            protected_fuigo_config_file_with_home(&path, &components, Some(home_path)),
            Some(reason),
            "{file} directly under $FUIGO_HOME must be protected"
        );
    }
    // Same file names elsewhere (or with no resolvable home) stay ordinary.
    let elsewhere = home_path
        .join("sub")
        .join(fuigo_config::SANDBOX_CONFIG_FILENAME);
    assert_eq!(
        protected_fuigo_config_file_with_home(
            &elsewhere,
            &["sub", fuigo_config::SANDBOX_CONFIG_FILENAME],
            Some(home_path)
        ),
        None
    );
    assert_eq!(
        protected_fuigo_config_file_with_home(
            &home_path.join(fuigo_config::SANDBOX_CONFIG_FILENAME),
            &[fuigo_config::SANDBOX_CONFIG_FILENAME],
            None
        ),
        None
    );
}

/// The resolved-symlink arm of the fuigo-home match must decide.
/// `$FUIGO_HOME` points at a symlink while the edit targets the physical home directory, so the lexical parent-equality arm cannot fire.
#[test]
#[cfg(unix)]
fn fuigo_config_under_symlinked_fuigo_home_is_protected() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().unwrap();
    let real_home = tmp.path().join("real-home");
    std::fs::create_dir(&real_home).unwrap();
    let link = tmp.path().join("home-link");
    symlink(&real_home, &link).unwrap();
    // Tempdir paths can themselves contain symlinks (macOS `/var -> /private/var`)
    // Compare against the physical home the production resolver will produce
    let physical_home = resolve_following_symlinks(&real_home).unwrap();
    assert_eq!(
        protected_fuigo_config_file_with_home(
            &physical_home.join(fuigo_config::SANDBOX_CONFIG_FILENAME),
            &[fuigo_config::SANDBOX_CONFIG_FILENAME],
            Some(&link)
        ),
        Some(ProtectedEditReason::FuigoSandbox)
    );
}

/// P166/S5 (upstream 48271133): spawn configs and the per-session grant stores are protected edit targets.
/// `mcp.json` / `lsp.json` start servers; `sessions/<scope>/permission*.toml` holds the agent's own approvals.
#[cfg(unix)]
#[test]
fn spawn_configs_and_grant_stores_are_protected() {
    for (path, reason) in [
        ("/home/user/.fuigo/mcp.json", ProtectedEditReason::McpConfig),
        ("/home/user/.fuigo/lsp.json", ProtectedEditReason::McpConfig),
        (
            "/work/project/.fuigo/lsp.json",
            ProtectedEditReason::McpConfig,
        ),
        (
            "/work/project/.fuigo/mcp.json",
            ProtectedEditReason::McpConfig,
        ),
        ("/work/project/.mcp.json", ProtectedEditReason::McpConfig),
        (
            "/work/project/sub/.MCP.json",
            ProtectedEditReason::McpConfig,
        ),
        (
            "/work/project/.cursor/mcp.json",
            ProtectedEditReason::McpConfig,
        ),
        (
            "/home/user/.cursor/mcp.json",
            ProtectedEditReason::McpConfig,
        ),
        ("/home/user/.claude.json", ProtectedEditReason::McpConfig),
        (
            "/home/user/.fuigo/sessions/ws/permission.toml",
            ProtectedEditReason::FuigoConfig,
        ),
        (
            "/home/user/.fuigo/sessions/%2Fwork%2Fproject/permission_fuigo-pager.toml",
            ProtectedEditReason::FuigoConfig,
        ),
        (
            "/home/user/.fuigo/sessions/ws/../ws/permission_zed.toml",
            ProtectedEditReason::FuigoConfig,
        ),
    ] {
        assert_eq!(
            edit_target_protection(Path::new(path)),
            Some(reason),
            "{path}"
        );
        assert!(reason.description().is_some(), "{path}");
    }
    for path in [
        "/work/project/mcp.json",
        "/work/project/lsp.json",
        "/work/project/config/mcp.json.bak",
        "/work/project/.fuigo/sub/mcp.json",
        "/work/project/sessions/x/permission_fuigo-pager.toml",
        "/work/project/sessions/x/permission.toml",
        "/home/user/.fuigo/sessions/ws/permissions.toml",
        "/home/user/.fuigo/sessions/ws/permission_x.json",
        "/home/user/.fuigo/sessions/ws/sub/permission.toml",
    ] {
        assert_eq!(edit_target_protection(Path::new(path)), None, "{path}");
    }
}

/// P166/S5: a custom `$FUIGO_HOME` has no `.fuigo` component, so its spawn configs and grant stores need the home-prefix branch.
#[test]
fn spawn_configs_and_grant_stores_under_custom_fuigo_home_are_protected() {
    let home = tempfile::tempdir().unwrap();
    let home_path = home.path();
    for file in ["mcp.json", "lsp.json"] {
        assert_eq!(
            protected_fuigo_config_file_with_home(&home_path.join(file), &[file], Some(home_path)),
            Some(ProtectedEditReason::McpConfig),
            "{file}"
        );
    }
    for file in ["permission.toml", "permission_fuigo-pager.toml"] {
        let grant = home_path.join("sessions").join("ws").join(file);
        assert_eq!(
            protected_fuigo_config_file_with_home(
                &grant,
                &["sessions", "ws", file],
                Some(home_path)
            ),
            Some(ProtectedEditReason::FuigoConfig),
            "{file} under $FUIGO_HOME/sessions must be protected"
        );
    }
    // A `sessions/` tree elsewhere is ordinary.
    let elsewhere = home_path
        .join("sub")
        .join("sessions")
        .join("ws")
        .join("permission.toml");
    assert_eq!(
        protected_fuigo_config_file_with_home(
            &elsewhere,
            &["sub", "sessions", "ws", "permission.toml"],
            Some(home_path)
        ),
        None
    );
    assert_eq!(
        protected_fuigo_config_file_with_home(&home_path.join("mcp.json"), &["mcp.json"], None),
        None
    );
}

/// P166/S5: the grant store behind a symlinked `$FUIGO_HOME` is caught by the resolved arm.
#[test]
#[cfg(unix)]
fn grant_store_under_symlinked_fuigo_home_is_protected() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().unwrap();
    let real_home = tmp.path().join("real-home");
    std::fs::create_dir(&real_home).unwrap();
    let link = tmp.path().join("home-link");
    symlink(&real_home, &link).unwrap();
    let physical_home = resolve_following_symlinks(&real_home).unwrap();
    let grant = physical_home
        .join("sessions")
        .join("ws")
        .join("permission.toml");
    assert_eq!(
        protected_fuigo_config_file_with_home(
            &grant,
            &["sessions", "ws", "permission.toml"],
            Some(&link)
        ),
        Some(ProtectedEditReason::FuigoConfig)
    );
}

/// `protected_edit_reason` lowercases path components before matching.
/// The canonical filename constants must stay lowercase or the const patterns silently stop firing.
#[test]
fn protected_config_filename_constants_are_lowercase() {
    for name in [
        fuigo_config::USER_CONFIG_FILENAME,
        fuigo_config::MANAGED_CONFIG_FILENAME,
        fuigo_config::REQUIREMENTS_FILENAME,
    ] {
        assert_eq!(name, name.to_ascii_lowercase(), "{name}");
    }
}

#[test]
fn resolved_root_alias_matches_physical_destination() {
    let resolved_root = resolve_following_symlinks(Path::new("/etc")).unwrap();
    assert!(resolved_path_is_within_root(
        &resolved_root.join("fuigo-test"),
        Path::new("/etc")
    ));
    assert!(!resolved_path_is_within_root(
        Path::new("/tmp/fuigo-test"),
        Path::new("/etc")
    ));
}

#[test]
#[cfg(target_os = "macos")]
fn private_etc_alias_requires_prompt() {
    assert!(edit_target_protection(Path::new("/private/etc/hosts")).is_some());
}

#[test]
#[cfg(unix)]
fn resolved_symlink_target_hits_read_deny() {
    use std::os::unix::fs::symlink;
    let ws = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret_dir = outside.path().join("prohibited-zone");
    std::fs::create_dir(&secret_dir).unwrap();
    std::fs::write(secret_dir.join("data.txt"), b"secret").unwrap();
    symlink(&secret_dir, ws.path().join("linked")).unwrap();

    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/prohibited-zone/**",
    )]);
    let decision = policy.evaluate_shell_file_access("cat linked/data.txt", ws.path());
    assert!(
        matches!(decision, Some(Decision::Reject(_))),
        "read via a symlink to a denied dir must be rejected, got {decision:?}"
    );
}

#[test]
#[cfg(unix)]
fn dangling_symlink_write_hits_edit_deny() {
    use std::os::unix::fs::symlink;
    let ws = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret_dir = outside.path().join("prohibited-zone");
    std::fs::create_dir(&secret_dir).unwrap();
    // Dangling link: target doesn't exist yet.
    symlink(secret_dir.join("new.txt"), ws.path().join("out")).unwrap();

    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Edit,
        "**/prohibited-zone/**",
    )]);
    let decision = policy.evaluate_shell_file_access("echo hi > out", ws.path());
    assert!(
        matches!(decision, Some(Decision::Reject(_))),
        "write through a dangling symlink into a denied dir must be rejected, got {decision:?}"
    );
}

#[test]
#[cfg(unix)]
fn resolved_symlink_to_allowed_target_not_blocked() {
    use std::os::unix::fs::symlink;
    let ws = tempfile::tempdir().unwrap();
    std::fs::create_dir(ws.path().join("real")).unwrap();
    std::fs::write(ws.path().join("real/data.txt"), b"ok").unwrap();
    symlink(ws.path().join("real"), ws.path().join("linked")).unwrap();

    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/prohibited-zone/**",
    )]);
    assert!(
        policy
            .evaluate_shell_file_access("cat linked/data.txt", ws.path())
            .is_none(),
        "a symlink to a non-denied path must not be blocked"
    );
}

/// `..` after a symlink must resolve physically: `link/../dir2/x` where `link -> <zone>/dir` lands in `<zone>/dir2/x`, not `<cwd>/dir2/x`.
#[test]
#[cfg(unix)]
fn resolved_symlink_dotdot_hits_read_deny() {
    use std::os::unix::fs::symlink;
    let ws = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let zone = outside.path().join("prohibited-zone");
    std::fs::create_dir_all(zone.join("dir")).unwrap();
    std::fs::create_dir_all(zone.join("dir2")).unwrap();
    std::fs::write(zone.join("dir2/x"), b"secret").unwrap();
    symlink(zone.join("dir"), ws.path().join("link")).unwrap();

    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/prohibited-zone/**",
    )]);
    let decision = policy.evaluate_shell_file_access("cat link/../dir2/x", ws.path());
    assert!(
        matches!(decision, Some(Decision::Reject(_))),
        "`..` after a symlink must resolve into the denied tree, got {decision:?}"
    );
}

/// An unresolvable operand (symlink cycle) fails closed to Ask rather than silently passing the gate.
#[test]
#[cfg(unix)]
fn unresolvable_symlink_operand_asks() {
    use std::os::unix::fs::symlink;
    let ws = tempfile::tempdir().unwrap();
    symlink(ws.path().join("b"), ws.path().join("a")).unwrap();
    symlink(ws.path().join("a"), ws.path().join("b")).unwrap();

    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/prohibited-zone/**",
    )]);
    let decision = policy.evaluate_shell_file_access("cat a", ws.path());
    assert!(
        matches!(decision, Some(Decision::Ask)),
        "unresolvable symlink operand must escalate to Ask, got {decision:?}"
    );
}

/// A *mid-path* symlink chain that can't be resolved (non-symlink leaf) must still fail closed to Ask, not skip the check.
#[test]
#[cfg(unix)]
fn unresolvable_midpath_symlink_operand_asks() {
    use std::os::unix::fs::symlink;
    let ws = tempfile::tempdir().unwrap();
    // Directory-component cycle: `linkdir -> linkdir2 -> linkdir`
    symlink(ws.path().join("linkdir2"), ws.path().join("linkdir")).unwrap();
    symlink(ws.path().join("linkdir"), ws.path().join("linkdir2")).unwrap();

    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/prohibited-zone/**",
    )]);
    // Leaf `file.txt` is not itself a symlink; the link is the `linkdir` component.
    let decision = policy.evaluate_shell_file_access("cat linkdir/file.txt", ws.path());
    assert!(
        matches!(decision, Some(Decision::Ask)),
        "unresolvable mid-path symlink chain must escalate to Ask, got {decision:?}"
    );
}

#[test]
fn shell_readers_hit_read_deny() {
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    for cmd in [
        "cat .env",
        "grep . .env",
        "head -n 5 .env",
        "sed -n 1p .env",
        "dd if=.env",
        "base64 .env",
        "sort < .env",
        "sort <.env",
        "grep -f .env README.md",
        "sed -f .env README.md",
        "awk -f .env README.md",
        // additional readers: dumpers, jq, PS/grep-alts, compressed
        "diff .env /dev/null",
        "comm .env /dev/null",
        "rev .env",
        "jq . .env",
        "select-string FAKE .env",
        "ag FAKE .env",
        "zcat .env",
        "zgrep FAKE .env",
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Reject(_))
            ),
            "expected deny for {cmd}"
        );
    }
}

/// u35: an unquoted glob read target is checked against deny rules as a pattern: it asks when it could match a
/// denied path (now or once created), and passes when it cannot. A quoted glob is a literal name.
#[test]
fn glob_read_targets_are_checked_as_patterns() {
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    for cmd in [
        "cat *",
        "cat ./.e*",
        "head -n 1 ?env",
        "cat .[e]nv",
        "grep x sub/*",
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Ask | Decision::Reject(_))
            ),
            "a glob that could match .env must not pass: {cmd}"
        );
    }
    for cmd in [
        "cat src/*.rs",
        "cat ./*.md",
        "head -n 1 docs/ch?.txt",
        "cat '*.env'",
        "cat \\*",
    ] {
        assert_eq!(policy.evaluate_shell_file_access(cmd, cwd()), None, "{cmd}");
    }
    // A match that is a symlink to a denied file is caught through the expansion.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".env"), "x").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(dir.path().join(".env"), dir.path().join("notes.md")).unwrap();
        assert!(
            policy
                .evaluate_shell_file_access("cat ./*.md", dir.path())
                .is_some()
        );
    }
}

#[test]
fn shell_writers_hit_edit_deny() {
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Edit,
        "**/.env",
    )]);
    for cmd in [
        "tee .env",
        "dd of=.env",
        "Set-Content .env secret",
        "Out-File .env",
        "echo secret > .env",
        "echo secret >.env",
        "echo secret >>.env",
        "sed -i.bak s/FAKE/HACKED/ .env",
        "sed -ni s/FAKE/HACKED/ .env",
        "sort README.md -o .env",
        // Abbreviated long options and short-option clusters (getopt spellings of `--output`/`-o`).
        "sort README.md --out=.env",
        "sort README.md --outp .env",
        "sort README.md --o=.env",
        "sort -no .env README.md",
        "sort -ro .env README.md",
        "sort -ro.env README.md",
        "go build -o=.env ./cmd",
        "go build --o=.env ./cmd",
        "rustc -go .env main.rs",
        "rustc --out .env main.rs",
        "git archive -vo .env HEAD",
        "git -C . archive -vo.env HEAD",
        "git format-patch -no .env HEAD~1",
        "git diff --out=.env",
        "git log --outp .env",
        "git format-patch --output-directory=.env -1 HEAD",
        "git format-patch --output-directory .env -1 HEAD",
        "rustc --emit=link=.env main.rs",
        "git format-patch -M -o .env -1 HEAD",
        "git --namespace -- archive -o .env HEAD",
        "sort --temp -- -o .env README.md",
        "go build -tags -- -o .env ./cmd",
        "git -C repo -- format-patch -o .env HEAD",
        "git --git-dir /repo -- archive -o .env",
        "git format-patch -S -- -o .env HEAD~1",
        "git format-patch -v -- -o .env HEAD~1",
        "truncate -s 0 .env",
        "Tee-Object .env",
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Reject(_))
            ),
            "expected deny for {cmd}"
        );
    }
}

/// Write targets that `special_file_operands` finds for one whitespace-split command.
fn output_flag_writes(cmd: &str) -> Vec<String> {
    let words: Vec<String> = cmd.split_whitespace().map(str::to_owned).collect();
    let program = words.first().cloned().unwrap_or_default();
    special_file_operands(&program, &words)
        .into_iter()
        .filter(|(_, mode)| matches!(mode, ShellFileMode::Write))
        .map(|(path, _)| path)
        .collect()
}

/// A git pickaxe value that looks like an output flag is not a write, so an Edit deny on the path stays quiet.
#[test]
fn git_pickaxe_value_is_not_an_edit() {
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Edit,
        "**/Cargo.toml",
    )]);
    let cmd = "git log -1 -pS --out Cargo.toml";
    assert!(
        !matches!(
            policy.evaluate_shell_file_access(cmd, cwd()),
            Some(Decision::Reject(_))
        ),
        "`{cmd}` must not hit an Edit deny on Cargo.toml"
    );
}

/// Auto-mode write detection sees the same output spellings, so they are never auto-allowed as read-only.
#[test]
fn output_flag_spellings_reach_auto_mode_write_paths() {
    let words = |cmd: &str| -> Vec<String> { cmd.split_whitespace().map(str::to_owned).collect() };
    for (cmd, path) in [
        ("sort a --out=w.txt", "w.txt"),
        ("sort -ro w.txt a", "w.txt"),
        ("git format-patch --output-directory=w -1", "w"),
        ("git archive -vo w.tar HEAD", "w.tar"),
        ("rustc --emit=link=w main.rs", "w"),
        ("sort a -o", ""),
        ("git format-patch -M -o w -1", "w"),
        ("git --namespace -- archive -o w HEAD", "w"),
        ("sort --temp -- -o w a", "w"),
        ("go build -tags -- -o w ./cmd", "w"),
        ("git -C repo -- format-patch -o w HEAD", "w"),
        ("git --git-dir /repo -- archive -o w", "w"),
        ("git format-patch -S -- -o w HEAD~1", "w"),
        ("git format-patch -v -- -o w HEAD~1", "w"),
    ] {
        assert!(
            command_words_write_paths(&words(cmd))
                .iter()
                .any(|p| p == path),
            "`{cmd}` must report a write to {path:?}"
        );
    }
    assert!(command_words_write_paths(&words("git status -uno")).is_empty());
    assert!(command_words_write_paths(&words("git log -1 -pS --out Cargo.toml")).is_empty());
}

/// S6: every spelling getopt_long / getopt / getopts accept for the output flag is a write,
/// and an option letter that takes its own value hides a later `o` (no false write).
#[test]
fn output_flag_spellings_are_writes() {
    let cases: &[(&str, &[&str])] = &[
        // Exact and attached forms (unchanged behaviour).
        ("sort a -o out", &["out"]),
        ("sort a -oout", &["out"]),
        ("sort a --output=out", &["out"]),
        ("sort a --output out", &["out"]),
        // Abbreviated long options; an ambiguous one (git `--outp`) still counts.
        ("sort a --out=out", &["out"]),
        ("sort a --outp out", &["out"]),
        ("sort a --o out", &["out"]),
        ("git diff --outp out", &["out"]),
        ("git log --out=out", &["out"]),
        // getopt clusters: `-o` after plain flags takes the rest of the word or the next word.
        ("sort -ro out a", &["out"]),
        ("sort -rno out a", &["out"]),
        ("sort -rout a", &["ut"]),
        ("sort -o-x a", &["-x"]),
        ("rustc -go out main.rs", &["out"]),
        ("rustc -Ogoout main.rs", &["out"]),
        ("git archive -vo out HEAD", &["out"]),
        ("git -C . archive -9vo out HEAD", &["out"]),
        ("git format-patch -kno out HEAD~1", &["out"]),
        // Go's flag package: `-o=FILE` and `--o=FILE` mean `-o FILE`.
        ("go build -o=out ./cmd", &["out"]),
        ("go build --o=out ./cmd", &["out"]),
        // rustc `--out-dir` and its abbreviations.
        ("rustc --out-dir=d main.rs", &["d"]),
        ("rustc --out-d d main.rs", &["d"]),
        // git `--output-directory` (format-patch) in full and abbreviated (Astra R1 HIGH).
        ("git format-patch --output-directory=out -1", &["out"]),
        ("git format-patch --output-directory out -1", &["out"]),
        ("git format-patch --output-dir out -1", &["out"]),
        // git keeps a literal `=`: only Go strips it (Astra R1 HIGH).
        ("git -c alias.a=archive a -o=blocked HEAD", &["=blocked"]),
        ("git archive -o=out HEAD", &["=out"]),
        ("sort a -o=out", &["=out"]),
        // rustc `--emit TYPE=PATH`.
        ("rustc --emit=link=out main.rs", &["out"]),
        ("rustc --emit obj=o1,link=o2 main.rs", &["o1", "o2"]),
        // An optional-argument letter never consumes the next word, and scanning starts after the git verb
        // (Astra R2 HIGH).
        ("git format-patch -M -o out -1", &["out"]),
        ("git format-patch -C -B -X -U -o out -1", &["out"]),
        ("git --namespace -- archive -o out HEAD", &["out"]),
        // A `--` that may be an option's value does not end the scan (Astra R3 HIGH).
        ("sort --temp -- -o out a", &["out"]),
        ("go build -tags -- -o out ./cmd", &["out"]),
        // Round 4 (Grok 4.7): a `--` among git's global options ends them; the next word is the verb.
        ("git -C repo -- format-patch -o out HEAD", &["out"]),
        ("git -- format-patch -o out", &["out"]),
        ("git -c x=y -- diff --output out", &["out"]),
        ("git --git-dir /repo -- archive -o out", &["out"]),
        ("git --git-dir=/repo -- archive -o out", &["out"]),
        ("git --git-d /repo -- archive -vo out", &["out"]),
        ("git --namespace foo -- archive -o out", &["out"]),
        // format-patch `-v` takes the next word even when it is `--` (git 2.50: `-v -- -o od` writes od).
        ("git format-patch -v -- -o out HEAD~1", &["out"]),
        // `-S` and the other diff letters do not take a following `-o` (git 2.50: `-S -o od` writes od), and a
        // `--` after a value letter may be its value, so the scan goes on.
        ("git format-patch -S -o out HEAD~1", &["out"]),
        ("git format-patch -S -- -o out HEAD~1", &["out"]),
        ("git format-patch -pS -- -o out HEAD~1", &["out"]),
        // A missing value is still a write (empty path), never silently dropped.
        ("sort a -o", &[""]),
        ("sort a --out", &[""]),
        ("sort a -ro", &[""]),
    ];
    for (cmd, expected) in cases {
        assert_eq!(output_flag_writes(cmd), *expected, "writes of `{cmd}`");
    }
    // Not writes: the `o` is a value of an earlier letter, or the program does not cluster.
    for cmd in [
        "sort -to a b",
        "sort -k1o a",
        "sort -So a",
        "rustc -Copt-level=3 main.rs",
        "rustc -Lnative=/opt/lib main.rs",
        "git status -uno",
        "git format-patch -vo HEAD~1",
        "go test -json ./...",
        "sort --check a",
        "git diff --output-indicator-new=x",
        // The verb is the first word after git's global options, not any word (Astra R1 MEDIUM).
        "git status -uno .env archive",
        "git -C archive status -uno",
        // Global-option values are never rescanned as the verb's options.
        "git --git-dir -o status",
        // `--` ends options, and a word consumed as another option's value is not a flag (Astra R1 MEDIUM).
        "sort -- -ro .env",
        "go build -- -o=out",
        "git log --grep --out -1",
        "sort -t -o out",
        "sort --key -o out",
        "rustc --emit=link main.rs",
        // Values of `-S` and `--remap-path-prefix` are not rescanned as flags (Astra R2 MEDIUM).
        "git log -1 -S --out Cargo.toml",
        "git log -G -o x",
        "rustc --remap-path-prefix --emit=link=.env --print=cfg",
        // A clustered git pickaxe takes the next word (Astra R3 MEDIUM).
        "git log -1 -pS --out Cargo.toml",
        // format-patch `-v` takes `-o` as its value (git 2.50: no write).
        "git format-patch -v -o x HEAD~1",
    ] {
        assert!(
            output_flag_writes(cmd).is_empty(),
            "`{cmd}` must not report an output write, got {:?}",
            output_flag_writes(cmd)
        );
    }
}

#[test]
fn inline_shells_hit_read_and_edit_denies() {
    let read = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    let mut commands: Vec<String> = ["bash", "sh", "dash", "zsh", "ksh"]
        .into_iter()
        .map(|shell| format!("{shell} -c 'cat .env'"))
        .collect();
    commands.extend([
        r#"/bin/bash -c 'cat .env'"#.to_owned(),
        r#"bash -lc 'cat .env'"#.to_owned(),
        r#"bash -c -x 'cat .env'"#.to_owned(),
        r#"bash -c -- 'cat .env'"#.to_owned(),
        r#"bash -c -o pipefail 'cat .env'"#.to_owned(),
        r#"bash -c -O extglob 'cat .env'"#.to_owned(),
        r#"bash -c -Oextglob 'cat .env'"#.to_owned(),
        r#"bash -c +O extglob 'cat .env'"#.to_owned(),
        r#"bash -c +Oextglob 'cat .env'"#.to_owned(),
        r#"bash -c +o pipefail 'cat .env'"#.to_owned(),
        r#"timeout 5 bash -c 'cat .env'"#.to_owned(),
        r#"bash -c "sh -c 'cat .env'""#.to_owned(),
        r#"bash -c 'cat .env' "$IGNORED""#.to_owned(),
    ]);
    for cmd in commands {
        assert!(
            matches!(
                read.evaluate_shell_file_access(&cmd, cwd()),
                Some(Decision::Reject(_))
            ),
            "inline read must be denied: {cmd}"
        );
    }
    for cmd in [
        r#"bash -- -c 'cat .env'"#,
        r#"bash script.sh -c 'cat .env'"#,
    ] {
        assert!(
            read.evaluate_shell_file_access(cmd, cwd()).is_none(),
            "non-inline shell form must stay unchanged: {cmd}"
        );
    }
    let edit = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Edit,
        "**/.env",
    )]);
    assert!(matches!(
        edit.evaluate_shell_file_access(r#"bash -c 'echo secret > .env'"#, cwd()),
        Some(Decision::Reject(_))
    ));
}

#[test]
fn untrusted_inline_shells_ask() {
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    for cmd in [
        r#"bash -c "$SCRIPT" 'cat .env'"#,
        r#"env FOO=1 bash -c "$SCRIPT""#,
        "bash -c",
        "bash -c 'cat",
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Ask)
            ),
            "untrusted inline script must ask: {cmd}"
        );
    }

    assert!(
        policy
            .evaluate_shell_file_access(r#"bash -c 'bash -c '\''cat README.md'\'''"#, cwd(),)
            .is_none(),
        "concatenated literal script operands remain recursively analyzable"
    );

    let malformed_control = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "/unrelated/secret",
    )]);
    assert!(
        malformed_control
            .evaluate_shell_file_access("echo 'unterminated", cwd())
            .is_none(),
        "top-level malformed non-inline command keeps legacy behavior"
    );

    let mut nested = "cat README.md".to_owned();
    for _ in 0..MAX_INLINE_SHELL_DEPTH {
        nested = format!("bash -c {}", shell_quote(&nested));
    }
    assert!(
        policy.evaluate_shell_file_access(&nested, cwd()).is_none(),
        "the maximum supported nesting remains analyzable"
    );
    nested = format!("bash -c {}", shell_quote(&nested));
    assert!(matches!(
        policy.evaluate_shell_file_access(&nested, cwd()),
        Some(Decision::Ask)
    ));

    let deny = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    let mut nested = "cat .env".to_owned();
    for _ in 0..=MAX_INLINE_SHELL_DEPTH {
        nested = format!("bash -c {}", shell_quote(&nested));
    }
    let cmd = format!("{nested}; cat .env");
    assert!(matches!(
        deny.evaluate_shell_file_access(&cmd, cwd()),
        Some(Decision::Reject(_))
    ));
}

fn shell_quote(script: &str) -> String {
    format!("'{}'", script.replace('\'', r#"'\''"#))
}

#[test]
fn wrapper_depth_exhaustion_asks() {
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    let wrapped = |depth: usize| format!("{}bash -c 'cat README.md'", "env ".repeat(depth));
    assert!(
        policy
            .evaluate_shell_file_access(&wrapped(MAX_WRAPPER_DEPTH), cwd())
            .is_none(),
        "maximum canonical wrapper depth remains analyzable"
    );
    assert!(matches!(
        policy.evaluate_shell_file_access(&wrapped(MAX_WRAPPER_DEPTH + 1), cwd()),
        Some(Decision::Ask)
    ));
}

/// Opaque `env -S`, dynamic program `-c`, transparent prefixes, escape folding.
#[test]
fn inline_shell_opaque_and_transparent_forms_escalate() {
    let read = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    let must_escalate = |cmd: &str| {
        assert!(
            matches!(
                read.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Reject(_)) | Some(Decision::Ask)
            ),
            "must not fail open: {cmd}"
        );
    };

    // env -S / --split-string is opaque (no packed reparse).
    for cmd in [
        "env -S 'cat .env'",
        r#"env -S 'bash -c "cat .env"'"#,
        "env --split-string 'cat .env'",
        "env --split-string=cat",
        "env -Scat",
        "/usr/bin/env -S 'cat .env'",
        "timeout 5 env -S 'cat .env'",
        "env -S",
    ] {
        must_escalate(cmd);
    }
    // Ordinary env assignment / peel still Rejects the reader.
    assert!(matches!(
        read.evaluate_shell_file_access("env FOO=1 cat .env", cwd()),
        Some(Decision::Reject(_))
    ));
    assert!(matches!(
        read.evaluate_shell_file_access("env cat .env", cwd()),
        Some(Decision::Reject(_))
    ));
    // Reject still wins over an opaque Ask floor.
    assert!(matches!(
        read.evaluate_shell_file_access("env -S 'cat README.md'; cat .env", cwd()),
        Some(Decision::Reject(_))
    ));

    // Untrusted program head with a supported `-c` shape escalates.
    for cmd in [
        r#"$SHELL -c 'cat .env'"#,
        r#"$(echo bash) -c 'cat .env'"#,
        r#"$SHELL -lc 'cat .env'"#,
        r#"timeout 5 $SHELL -c 'cat .env'"#,
    ] {
        must_escalate(cmd);
    }
    // Dynamic head without an inline `-c` shape is not a global Ask.
    assert!(
        read.evaluate_shell_file_access(r#"$CMD README.md"#, cwd())
            .is_none(),
        "dynamic non-inline program must stay inert"
    );

    // Transparent exec/command/builtin prefixes (outer and in-script)
    for cmd in [
        "bash -c 'exec cat .env'",
        "bash -c 'command cat .env'",
        "bash -c 'builtin cat .env'",
        "exec bash -c 'cat .env'",
        "command bash -c 'cat .env'",
        "command cat .env",
        "exec cat .env",
        "command -p cat .env",
        "exec -a name cat .env",
        "bash -c 'command -p cat .env'",
        "bash -c 'exec bash -c \"cat .env\"'",
    ] {
        must_escalate(cmd);
    }
    // Display forms of `command` are not peeled into readers.
    assert!(
        read.evaluate_shell_file_access("command -v cat", cwd())
            .is_none(),
        "command -v display form must not invent a read"
    );
    // Unknown prefix options fail closed.
    must_escalate("exec -u cat .env");
    must_escalate("command -Z cat .env");

    // Eight peels reach the reader; a ninth Asks.
    let nested_exec = |depth: usize| format!("{}cat .env", "exec ".repeat(depth));
    assert!(
        matches!(
            read.evaluate_shell_file_access(&nested_exec(MAX_TRANSPARENT_PREFIX_DEPTH), cwd()),
            Some(Decision::Reject(_))
        ),
        "maximum transparent prefix depth must still reach the denied reader"
    );
    assert!(
        matches!(
            read.evaluate_shell_file_access(&nested_exec(MAX_TRANSPARENT_PREFIX_DEPTH + 1), cwd()),
            Some(Decision::Ask)
        ),
        "one extra transparent prefix must fail closed"
    );
    // Mixed / path-qualified prefixes at the supported budget still Reject.
    let mixed = format!(
        "{}cat .env",
        "exec command builtin /usr/bin/exec ".repeat(MAX_TRANSPARENT_PREFIX_DEPTH / 4)
    );
    assert!(
        matches!(
            read.evaluate_shell_file_access(&mixed, cwd()),
            Some(Decision::Reject(_))
        ),
        "mixed path-qualified transparent prefixes within budget must Reject"
    );
    // Reject still beats transparent-depth exhaustion Ask.
    let exhausted_then_deny = format!(
        "{}; cat .env",
        nested_exec(MAX_TRANSPARENT_PREFIX_DEPTH + 1).replace("cat .env", "cat README.md")
    );
    assert!(
        matches!(
            read.evaluate_shell_file_access(&exhausted_then_deny, cwd()),
            Some(Decision::Reject(_))
        ),
        "a later denied reader must beat transparent exhaustion Ask"
    );

    // Shell escapes fold before program/flag/path matching.
    for cmd in [
        r#"b\ash -c 'cat .env'"#,
        r#"bash \-c 'cat .env'"#,
        r#"bash -c "cat .en\\v""#,
        r#"bash -c "b\\ash -c 'cat .env'""#,
    ] {
        must_escalate(cmd);
    }
    // Single quotes stay literal (no escape fold).
    assert!(
        read.evaluate_shell_file_access(r#"cat '.en\v'"#, cwd())
            .is_none(),
        "single-quoted backslash must remain literal"
    );
}

#[test]
fn shell_gate_merges_decisions_so_deny_beats_earlier_ask() {
    // The whole command runs once approved, so a later deny must beat an earlier ask.
    let policy = compiled(vec![
        file_rule(RuleAction::Ask, ToolFilter::Edit, "**/dump.txt"),
        file_rule(RuleAction::Ask, ToolFilter::Read, "**/notes.txt"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/.env"),
    ]);
    for cmd in [
        // Redirect target (checked first) asks; the read operand denies.
        "cat .env > dump.txt",
        // First operand asks; the second denies.
        "cat notes.txt .env",
        // Outer read asks; recursively discovered inner read denies.
        "cat notes.txt; bash -c 'cat .env'",
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Reject(_))
            ),
            "deny on a later path must win over an earlier ask for {cmd}"
        );
    }
}

#[test]
fn shell_in_place_sed_enforces_read_deny() {
    // `sed -i` reads each operand before rewriting it, so a Read deny must block it.
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    for cmd in ["sed -i s/FAKE/X/ .env", "sed -ni s/FAKE/X/ .env"] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Reject(_))
            ),
            "in-place sed must honor a Read deny for {cmd}"
        );
    }
}

#[test]
fn powershell_and_windows_path_readers_hit_read_deny() {
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    for cmd in [
        "Get-Content .env",
        "gc .env",
        "type .env",
        "more .env",
        "Get-Content C:\\Users\\alice\\repo\\.env",
        "Get-Content /c/Users/alice/repo/.env",
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Reject(_))
            ),
            "expected deny for {cmd}"
        );
    }
}

/// A relative operand after any in-shell `cd`/`pushd`/`env -C` is unpinnable and must Ask.
/// Only path-scoped rules are affected; basename denies still fire.
#[test]
fn shell_cwd_change_escalates_path_scoped_operands() {
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "/repo-b/.env", // path-scoped: matching would need the untracked cd target
    )]);
    let session = std::path::Path::new("/repo-a");
    for cmd in [
        "cd /repo-b && cat .env",                 // cd in the current shell
        "pushd /repo-b; cat .env",                // pushd is never folded
        "if true; then cd /repo-b; fi; cat .env", // conditional cd
        "env -C /repo-b cat .env",                // env chdir wrapper
        "env --chdir=/repo-b cat .env",
        "/usr/bin/env -C /repo-b cat .env", // path-qualified env
        "env FOO=1 -C /repo-b cat .env",    // chdir after an assignment
        "cd /repo-b && echo x > .env",      // redirect operand too
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, session),
                Some(Decision::Ask)
            ),
            "an unpinnable cwd change must escalate: {cmd}"
        );
    }
}

#[test]
fn inline_shell_cwd_uncertainty_preserves_rejects() {
    let exact = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "/repo-a/.env",
    )]);
    for cmd in [
        r#"cd /repo-b && bash -c 'cat .env'"#,
        r#"env -C /repo-b bash -c 'cat .env'"#,
        r#"(cd /repo-b; bash -c 'cat .env')"#,
        r#"bash -c 'cd /repo-b && cat .env'"#,
        r#"bash -c '(cd /repo-b; cat .env)'"#,
    ] {
        assert!(
            matches!(
                exact.evaluate_shell_file_access(cmd, std::path::Path::new("/repo-a")),
                Some(Decision::Ask)
            ),
            "relative inline path under an unpinned cwd must ask: {cmd}"
        );
    }

    let basename = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    for cmd in [
        r#"cd /repo-b && bash -c 'cat .env'"#,
        r#"(cd /repo-b; bash -c 'cat .env')"#,
        r#"bash -c 'cd /repo-b && cat .env'"#,
        r#"bash -c '(cd /repo-b; cat .env)'"#,
    ] {
        assert!(matches!(
            basename.evaluate_shell_file_access(cmd, std::path::Path::new("/repo-a")),
            Some(Decision::Reject(_))
        ));
    }

    let absolute = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "/repo-b/.env",
    )]);
    assert!(matches!(
        absolute.evaluate_shell_file_access(
            r#"env -C /elsewhere bash -c 'cat /repo-b/.env'"#,
            std::path::Path::new("/repo-a"),
        ),
        Some(Decision::Reject(_))
    ));
}

/// A `**/` basename deny matches regardless of cwd, so a `cd`/`env -C` can't smuggle a denied read past the gate.
#[test]
fn shell_basename_deny_survives_cwd_change() {
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    let session = std::path::Path::new("/repo-a");
    for cmd in [
        "cd /repo-b && cat .env",
        "env -C /repo-b cat .env",
        "pushd /repo-b; cat .env",
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, session),
                Some(Decision::Reject(_))
            ),
            "a basename deny must still fire under a cwd change: {cmd}"
        );
    }
}

/// A `cd` in a pipeline/subshell/backgrounded `&` doesn't change a sibling's cwd.
/// Their reads resolve against the original cwd, not the `cd` target.
#[test]
fn shell_cd_does_not_scope_across_pipe_subshell_or_background() {
    // Deny is scoped to the original cwd (`/work`), where the reader runs.
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "/work/secret.env",
    )]);
    for cmd in [
        "cd /elsewhere | cat secret.env",  // pipeline segment: own subshell
        "(cd /elsewhere); cat secret.env", // subshell ended with `;`
        "cd /elsewhere & cat secret.env",  // backgrounded cd
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Reject(_))
            ),
            "cd must not scope across boundary: {cmd}"
        );
    }
    // A deny scoped to the cd target must not fire; the reader never runs there
    let elsewhere = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "/elsewhere/secret.env",
    )]);
    assert!(
        elsewhere
            .evaluate_shell_file_access("cd /elsewhere | cat secret.env", cwd())
            .is_none(),
        "reader runs in the original cwd, so the cd-target deny must not match"
    );
}

/// After `--`, tokens are positional even when they start with `-`.
/// A path like `-/../.env` must still be deny-checked (not skipped as a flag).
#[test]
fn shell_double_dash_end_of_options_extracts_paths() {
    let read = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    assert!(matches!(
        read.evaluate_shell_file_access("cat -- -/../.env", cwd()),
        Some(Decision::Reject(_))
    ));
    let edit = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Edit,
        "**/.env",
    )]);
    assert!(matches!(
        edit.evaluate_shell_file_access("rm -- -/../.env", cwd()),
        Some(Decision::Reject(_))
    ));
}

/// `cp`/`mv`/`ln`/`install`/`rm`/`touch` move/destroy files: sources are reads (exfil), destinations are writes.
#[test]
fn shell_path_commands_hit_deny() {
    // Reading a denied source (exfil via copy/move) is caught by a Read deny.
    let read = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    for cmd in [
        "cp .env /tmp/x",
        "mv .env /tmp/exfil",
        "install .env /tmp/x",
    ] {
        assert!(
            matches!(
                read.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Reject(_))
            ),
            "source read must be denied: {cmd}"
        );
    }
    // Writing/deleting a denied path is caught by an Edit deny.
    let edit = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Edit,
        "**/.env",
    )]);
    for cmd in [
        "rm .env",
        "touch .env",
        "mkdir .env",
        "cp src .env",
        "ln -s src .env",
    ] {
        assert!(
            matches!(
                edit.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Reject(_))
            ),
            "write/delete must be denied: {cmd}"
        );
    }
    // A copy source is a read, not an edit: an Edit-only deny must not fire.
    assert!(
        edit.evaluate_shell_file_access("cp .env /tmp/x", cwd())
            .is_none(),
        "copying a source only reads it, so an Edit-only deny must not match"
    );
}

/// A reader whose operand can't be pinned (glob, recursive search, expansion) prompts.
#[test]
fn ambiguous_known_reader_prompts_when_path_cannot_be_pinned() {
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    for cmd in ["cat *.env", "grep -r secret .", "cat \"$HOME/.env\""] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Ask)
            ),
            "unpinnable reader must prompt: {cmd}"
        );
    }
}

/// A positional `=`-operand is a filename (deny-checked); only leading `VAR=value` assignments are dropped by the AST.
#[test]
fn shell_reader_checks_equals_containing_operand() {
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/data=*.env",
    )]);
    assert!(
        matches!(
            policy.evaluate_shell_file_access("cat data=v1.env", cwd()),
            Some(Decision::Reject(_))
        ),
        "operand containing = must be deny-checked"
    );
    // A leading assignment is not an operand, so it isn't treated as a file.
    assert!(
        policy
            .evaluate_shell_file_access("FOO=data=v1.env cat README.md", cwd())
            .is_none()
    );
}

/// An expansion nested in a quoted/concatenated operand (`.e"$X"`) is ambiguous and prompts, not treated as a literal.
#[test]
fn shell_nested_expansion_operand_prompts() {
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    for cmd in ["cat .e\"$X\"", "cat .e\"$(echo nv)\"", "cat pre\"${X}\"suf"] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Ask)
            ),
            "nested expansion must be ambiguous and prompt: {cmd}"
        );
    }
}

/// `rg`/`ag`/`ack` recurse a directory (no path, `.`, or `dir/`), so a Read deny on a path they could reach must prompt.
/// A single file operand scopes them.
#[test]
fn shell_recursive_readers_prompt_for_directory_search() {
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    for cmd in [
        "rg secret",      // no path: searches cwd
        "ack secret",     // no path
        "rg secret .",    // directory operand
        "rg secret src/", // directory operand
        "ag secret .",
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Ask)
            ),
            "recursive directory search must prompt: {cmd}"
        );
    }
    assert!(
        policy
            .evaluate_shell_file_access("rg secret README.md", cwd())
            .is_none(),
        "a single file operand scopes the search"
    );
}

/// Arbitrary interpreters run code we don't parse, so reads inside them fall through.
#[test]
fn non_reader_is_not_covered_by_shell_gate() {
    let policy = compiled(vec![file_rule(
        RuleAction::Deny,
        ToolFilter::Read,
        "**/.env",
    )]);
    for cmd in [
        "python -c \"open('.env').read()\"",
        "node -e \"require('fs').readFileSync('.env')\"",
    ] {
        assert!(
            policy.evaluate_shell_file_access(cmd, cwd()).is_none(),
            "expected no shell gate decision for {cmd}"
        );
    }
}

/// Representative enterprise deny/ask fixture for managed-policy tests `[permission]` tier.
/// Tool mapping: `Read` to Read, `Write`/`Edit` to Edit, `Bash` to Bash.
fn enterprise_requirements_policy() -> CompiledPolicy {
    compiled(vec![
        // ── ask = [...] ──
        bash_rule(RuleAction::Ask, "kubectl *"),
        bash_rule(RuleAction::Ask, "terraform apply *"),
        bash_rule(RuleAction::Ask, "aws *"),
        bash_rule(RuleAction::Ask, "gcloud *"),
        bash_rule(RuleAction::Ask, "az *"),
        bash_rule(RuleAction::Ask, "ssh *"),
        bash_rule(RuleAction::Ask, "security *"),
        bash_rule(RuleAction::Ask, "op *"),
        file_rule(RuleAction::Ask, ToolFilter::Read, "**/secrets/**"),
        file_rule(RuleAction::Ask, ToolFilter::Edit, "**/secrets/**"), // Write(..)
        file_rule(RuleAction::Ask, ToolFilter::Edit, "**/secrets/**"), // Edit(..)
        file_rule(RuleAction::Ask, ToolFilter::Read, "**/Library/Mail/**"),
        // ── deny = [...] ──
        bash_rule(RuleAction::Deny, "rm -rf *"),
        bash_rule(RuleAction::Deny, "sudo *"),
        bash_rule(RuleAction::Deny, "su *"),
        bash_rule(RuleAction::Deny, "ssh *.corp.example"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/.env"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/.env.*"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/*.pem"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/*.key"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/*.p12"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/*.pfx"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/*.jks"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/*.keystore"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/.ssh/**"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/.aws/**"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/.config/gcloud/**"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/.kube/**"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/.internal-deploy/**"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/.git-credentials"),
        file_rule(RuleAction::Deny, ToolFilter::Read, "**/terraform.tfstate"),
        file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/terraform.tfstate.backup",
        ),
        file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/Library/Keychains/**",
        ),
        file_rule(RuleAction::Deny, ToolFilter::Edit, "**/.env*"), // Write(..)
        file_rule(RuleAction::Deny, ToolFilter::Edit, "**/.ssh/**"), // Write(..)
        file_rule(RuleAction::Deny, ToolFilter::Edit, "**/*.pem"), // Write(..)
        file_rule(RuleAction::Deny, ToolFilter::Edit, "**/*.key"), // Write(..)
        file_rule(RuleAction::Deny, ToolFilter::Edit, "**/*.p12"), // Write(..)
        file_rule(RuleAction::Deny, ToolFilter::Edit, "**/.internal-deploy/**"), // Write(..)
        file_rule(RuleAction::Deny, ToolFilter::Edit, "**/terraform.tfstate"), // Write(..)
        file_rule(
            RuleAction::Deny,
            ToolFilter::Edit,
            "**/terraform.tfstate.backup",
        ), // Write(..)
        file_rule(
            RuleAction::Deny,
            ToolFilter::Edit,
            "**/Library/Keychains/**",
        ), // Write(..)
        file_rule(RuleAction::Deny, ToolFilter::Edit, "**/.env"),
        file_rule(RuleAction::Deny, ToolFilter::Edit, "**/.env.*"),
    ])
}

/// fd-prefixed/glued READ redirects must still hit the Read deny via the AST walk.
#[test]
fn adversarial_fd_and_glued_read_redirects_denied() {
    let policy = enterprise_requirements_policy();
    for cmd in [
        "cat 0<.env",
        "cat 0< .env",
        "cat<.env",
        "grep secret 0<.env",
        "sort 0< .env",
        "head -n1 0<.env",
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Reject(_))
            ),
            "read redirect must be denied: {cmd}"
        );
    }
}

/// fd-prefixed / glued WRITE redirects (truncate, append, stderr, both-streams) must hit the Edit deny.
#[test]
fn adversarial_fd_and_glued_write_redirects_denied() {
    let policy = enterprise_requirements_policy();
    for cmd in [
        "echo x 1>.env",
        "echo x 1> .env",
        "echo x 2>.env",
        "echo x 2> .env",
        "echo x &>.env",
        "echo x &> .env",
        "echo x 1>>.env",
        "echo x>>.env",
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Reject(_))
            ),
            "write redirect must be denied: {cmd}"
        );
    }
}

#[test]
fn adversarial_fd_duplication_and_numeric_filenames() {
    let parsed = |cmd: &str| {
        let tree = try_parse_shell(cmd).expect("shell parses");
        command_write_paths_in_tree(tree.root_node(), cmd)
    };
    assert!(parsed("cat payload 2>&1").is_empty());
    assert!(parsed("cat payload 1>&-").is_empty());
    assert!(parsed("cat payload 0<&3").is_empty());
    assert_eq!(parsed("cat payload > 3"), vec!["3"]);
}

/// An outer reader fed a substitution can't pin its operand (Ask); an inner literal read (incl. inside `<(…)`) is a hard deny.
#[test]
fn adversarial_substitution_readers_do_not_bypass() {
    let policy = enterprise_requirements_policy();
    for cmd in [
        "cat $(echo .env)",
        "xxd `echo .env`",
        "cut -d= -f2 $(echo .env)",
        "tac $(printf .env)",
        "nl $(echo .env)",
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Ask)
            ),
            "substitution reader must prompt: {cmd}"
        );
    }
    for cmd in [
        "echo $(cat .env)",
        "echo `cat .env`",
        "echo $(base64 key.pem)",
        "diff <(cat .env) x",
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Reject(_))
            ),
            "inner literal read must be denied: {cmd}"
        );
    }
}

/// Enterprise-policy coverage beyond the single-rule tests.
#[test]
fn adversarial_enterprise_matrix_denies_and_asks() {
    let policy = enterprise_requirements_policy();
    for cmd in [
        // readers only covered here
        "tail -n1 .env",
        "strings .env",
        "wc -c .env",
        "od -An .env",
        "xxd .env",
        "hexdump -C .env",
        "tac .env",
        "nl .env",
        // non-.env deny globs (*.pem, .ssh/**, .aws/**, .kube/**)
        "cat key.pem",
        "cat .ssh/id_rsa",
        "cat .aws/credentials",
        "cat .kube/config",
        // wrapper stripping / program basename
        "/bin/cat .env",
        "env FOO=1 cat .env",
        "timeout 5 cat .env",
        // path normalization and `..` traversal
        "cat ./.env",
        "cat subdir/../.env",
        // chaining / pipeline, checked per segment
        "ls && cat .env",
        "cat README.md; cat .env",
        "cat .env | head -n1",
        // case-insensitive command match
        "GET-CONTENT .env",
    ] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Reject(_))
            ),
            "must deny: {cmd}"
        );
    }
    // Ask rules reached through the shell gate (Read and Edit on **/secrets/**)
    for cmd in ["cat secrets/value.txt", "echo x > secrets/new.txt"] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Ask)
            ),
            "must ask: {cmd}"
        );
    }
}

/// Decision-level mirror of the managed-config e2e.
/// Asserts the `Decision` the manager computes on the real sentinel paths, no inference.
/// Covers all four entry points: read tool, write/edit tools, bash rules, shell gate.
#[test]
fn live_enterprise_e2e_matrix_decision_parity() {
    // What the model can do and the manager function that decides it
    #[derive(Clone, Copy)]
    enum Vector {
        /// File-read tool / list_dir: `evaluate(AccessKind::Read(..))`.
        ReadTool(&'static str),
        /// write / search_replace / apply_patch: `evaluate(AccessKind::Edit(..))`.
        EditTool(&'static str),
        /// Bash command rules: `evaluate(AccessKind::Bash(..))`.
        Bash(&'static str),
        /// Shell file args: `evaluate_shell_file_access(cmd, cwd)`.
        Shell(&'static str),
    }
    #[derive(Clone, Copy)]
    enum Expect {
        /// Managed deny means `Reject(_)` (the live SENTINEL must never leak).
        Deny,
        /// Managed ask means `Ask` (the live model is prompted).
        Ask,
        /// Not denied/asked means `None` (the live file stays readable / command runs).
        Allowed,
    }
    use Expect::{Allowed, Ask, Deny};
    use Vector::{Bash, EditTool, ReadTool, Shell};

    let policy = enterprise_requirements_policy();
    let matrix: &[(&str, Vector, Expect)] = &[
        // ── file-read tool: real sentinel files (setup.sh) ──
        ("read .env", ReadTool(".env"), Deny),
        ("read .env.staging", ReadTool(".env.staging"), Deny), // **/.env.*
        ("read src/server.pem", ReadTool("src/server.pem"), Deny), // **/*.pem
        (
            "read terraform.tfstate",
            ReadTool("terraform.tfstate"),
            Deny,
        ),
        (
            "read secrets/api_key.txt",
            ReadTool("secrets/api_key.txt"),
            Ask,
        ), // **/secrets/**
        ("read README.md (neg)", ReadTool("README.md"), Allowed),
        ("read src/main.py (neg)", ReadTool("src/main.py"), Allowed),
        // ── file-read tool: every remaining deny/ask glob in the policy ──
        ("read *.key", ReadTool("config/id_rsa.key"), Deny),
        ("read *.p12", ReadTool("cert.p12"), Deny),
        ("read *.pfx", ReadTool("cert.pfx"), Deny),
        ("read *.jks", ReadTool("keystore.jks"), Deny),
        ("read *.keystore", ReadTool("app.keystore"), Deny),
        ("read .ssh/**", ReadTool(".ssh/id_rsa"), Deny),
        ("read .aws/**", ReadTool(".aws/credentials"), Deny),
        (
            "read .config/gcloud/**",
            ReadTool(".config/gcloud/access_tokens.db"),
            Deny,
        ),
        ("read .kube/**", ReadTool(".kube/config"), Deny),
        (
            "read .internal-deploy/**",
            ReadTool(".internal-deploy/config"),
            Deny,
        ),
        ("read .git-credentials", ReadTool(".git-credentials"), Deny),
        (
            "read terraform.tfstate.backup",
            ReadTool("terraform.tfstate.backup"),
            Deny,
        ),
        (
            "read Library/Keychains/**",
            ReadTool("Library/Keychains/login.keychain-db"),
            Deny,
        ),
        (
            "read Library/Mail/** (ask)",
            ReadTool("Library/Mail/Inbox.mbox"),
            Ask,
        ),
        // ── file-read tool: lookalike negatives (must NOT match) ──
        ("read key.pem.txt (neg)", ReadTool("key.pem.txt"), Allowed),
        (
            "read my.env.example (neg)",
            ReadTool("my.env.example"),
            Allowed,
        ),
        // ── write/edit tool: Write(..)/Edit(..) denies + secrets ask ──
        ("edit .env", EditTool(".env"), Deny),
        ("edit .env.local", EditTool(".env.local"), Deny), // **/.env* and **/.env.*
        ("edit src/server.pem", EditTool("src/server.pem"), Deny), // Write(**/*.pem)
        ("edit *.key", EditTool("config/id_rsa.key"), Deny),
        ("edit *.p12", EditTool("cert.p12"), Deny),
        (
            "edit terraform.tfstate",
            EditTool("terraform.tfstate"),
            Deny,
        ),
        ("edit .ssh/**", EditTool(".ssh/authorized_keys"), Deny),
        (
            "edit .internal-deploy/**",
            EditTool(".internal-deploy/config"),
            Deny,
        ),
        (
            "edit Library/Keychains/**",
            EditTool("Library/Keychains/login.keychain-db"),
            Deny,
        ),
        (
            "edit secrets/** (ask)",
            EditTool("secrets/api_key.txt"),
            Ask,
        ),
        // Real-policy asymmetry: *.pfx/*.jks/*.keystore are Read-denied but have NO Write rule, so editing them is allowed (faithful to deploy)
        ("edit *.pfx (no write rule)", EditTool("cert.pfx"), Allowed),
        ("edit README.md (neg)", EditTool("README.md"), Allowed),
        ("edit src/main.py (neg)", EditTool("src/main.py"), Allowed),
        // ── bash command rules: deny set ──
        ("bash rm -rf", Bash("rm -rf /tmp/x"), Deny),
        ("bash sudo", Bash("sudo apt-get update"), Deny),
        ("bash su", Bash("su - root"), Deny),
        // ssh to *.corp.example is deny even though `ssh *` is ask (deny wins).
        ("bash ssh corp-example", Bash("ssh prod.corp.example"), Deny),
        // ── bash command rules: ask set ──
        ("bash kubectl", Bash("kubectl get pods -A"), Ask),
        (
            "bash terraform apply",
            Bash("terraform apply -auto-approve"),
            Ask,
        ),
        ("bash aws", Bash("aws s3 ls"), Ask),
        ("bash gcloud", Bash("gcloud auth list"), Ask),
        ("bash az", Bash("az account show"), Ask),
        ("bash ssh (non-corp-example)", Bash("ssh user@host"), Ask),
        (
            "bash security",
            Bash("security find-generic-password -s x"),
            Ask,
        ),
        ("bash op", Bash("op read op://vault/item"), Ask),
        // ── bash command rules: negatives ──
        ("bash ls (neg)", Bash("ls -la"), Allowed),
        ("bash git status (neg)", Bash("git status"), Allowed),
        // ── shell file-access gate: readers / redirects / substitutions ──
        ("sh cat .env", Shell("cat .env"), Deny),
        ("sh cat .env.staging", Shell("cat .env.staging"), Deny),
        ("sh cat src/server.pem", Shell("cat src/server.pem"), Deny),
        (
            "sh cat terraform.tfstate",
            Shell("cat terraform.tfstate"),
            Deny,
        ),
        ("sh grep FAKE .env", Shell("grep FAKE .env"), Deny),
        ("sh base64 .env", Shell("base64 .env"), Deny),
        ("sh cat 0<.env", Shell("cat 0<.env"), Deny), // fd-prefixed read redirect
        ("sh cat<.env", Shell("cat<.env"), Deny),     // glued read redirect
        ("sh cat $(echo .env)", Shell("cat $(echo .env)"), Ask), // unpinnable substitution
        (
            "sh diff <(cat .env)",
            Shell("diff <(cat .env) /dev/null"),
            Deny,
        ), // process sub
        ("sh cat subdir/../.env", Shell("cat subdir/../.env"), Deny), // `..` traversal
        ("sh cat .ssh/id_rsa", Shell("cat .ssh/id_rsa"), Deny),
        // ── shell file-access gate: writers (file must stay unchanged) ──
        ("sh echo > .env", Shell("echo HACKED > .env"), Deny), // write redirect
        (
            "sh sed -ni .env",
            Shell("sed -ni s/FAKE/HACKED/ .env"),
            Deny,
        ), // in-place sed
        ("sh tee .env", Shell("printf HACKED | tee .env"), Deny), // pipe into tee
        (
            "sh echo > tfstate",
            Shell("echo x > terraform.tfstate"),
            Deny,
        ),
        // ── shell file-access gate: secrets ask + negatives ──
        (
            "sh cat secrets/api_key.txt",
            Shell("cat secrets/api_key.txt"),
            Ask,
        ),
        (
            "sh echo > secrets/new.txt",
            Shell("echo x > secrets/new.txt"),
            Ask,
        ),
        ("sh cat README.md (neg)", Shell("cat README.md"), Allowed),
        (
            "sh cat src/main.py (neg)",
            Shell("cat src/main.py"),
            Allowed,
        ),
    ];

    for &(label, vector, expect) in matrix {
        let decision = match vector {
            ReadTool(path) => policy.evaluate(&AccessKind::Read(Some(path.to_string()))),
            EditTool(path) => policy.evaluate(&AccessKind::Edit(path.to_string())),
            Bash(cmd) => policy.evaluate(&AccessKind::Bash(cmd.to_string())),
            Shell(cmd) => policy.evaluate_shell_file_access(cmd, cwd()),
        };
        match expect {
            Deny => assert!(
                matches!(decision, Some(Decision::Reject(_))),
                "[{label}] expected Deny (Reject), got {decision:?}"
            ),
            Ask => assert!(
                matches!(decision, Some(Decision::Ask)),
                "[{label}] expected Ask, got {decision:?}"
            ),
            Allowed => assert!(
                decision.is_none(),
                "[{label}] expected allowed (None), got {decision:?}"
            ),
        }
    }
}

/// Negative controls: legit reads/writes and lookalike names aren't blocked.
#[test]
fn adversarial_legitimate_commands_not_overblocked() {
    let policy = enterprise_requirements_policy();
    for cmd in [
        "cat README.md",
        "head -n 5 README.md",
        "tail -n 5 README.md",
        "grep hello README.md",
        "sed -n 1p README.md",
        "wc -c README.md",
        "cut -d: -f1 README.md",
        "sort README.md",
        "uniq README.md",
        "pwd",
        "date",
        "whoami",
        "git status --short",
        "ls && cat README.md",
        "cat my.env.example",
        "cat env.txt",
        "cat key.pem.txt",
        "cat env.dir/README.md",
        "echo ok > scratch.txt",
        "echo x 2>/dev/null",
        "cat README.md 2>&1",
        // Path-moving commands on non-restricted files stay inert.
        "cp README.md backup.md",
        "mv old.txt new.txt",
        "rm scratch.txt",
        "touch newfile.txt",
        "mkdir build",
    ] {
        assert!(
            policy.evaluate_shell_file_access(cmd, cwd()).is_none(),
            "must not over-block: {cmd}"
        );
    }
}

/// No Read/Edit/Any rules: skip the shell gate entirely, even for known readers.
#[test]
fn adversarial_no_file_rules_means_no_shell_gate() {
    let policy = compiled(vec![bash_rule(RuleAction::Deny, "rm*")]);
    assert!(
        policy
            .evaluate_shell_file_access("cat .env", cwd())
            .is_none()
    );
}

/// Local mirror of the grep tool's read-exclude derivation: `Deny` rules on `Read`/`Any`.
/// Proves a no-restriction policy derives zero read-excludes.
fn read_deny_globs(config: &PermissionConfig) -> Vec<String> {
    config
        .rules
        .iter()
        .filter(|r| {
            r.action == RuleAction::Deny && matches!(r.tool, ToolFilter::Read | ToolFilter::Any)
        })
        .filter_map(|r| r.pattern.clone())
        .collect()
}

/// Read/exfil vectors the shell gate classifies under a policy; reused to prove a no-restriction policy gates none of them.
const BYPASS_VECTORS: &[&str] = &[
    "cat .env",
    "grep FAKE .env",
    "base64 .env",
    "cat 0<.env",
    "cat<.env",
    "cat $(echo .env)",
    "diff <(cat .env) /dev/null",
    "echo X > .env",
    "sed -ni s/// .env",
];

/// No-restriction policies (empty / Bash-only / Allow-only-file) must be inert.
/// The gate stays off, every bypass vector is declined, and the policy derives zero read-excludes.
#[test]
fn h1_no_restriction_policies_are_inert() {
    let policies: [(&str, Vec<PermissionRule>); 3] = [
        ("empty", vec![]),
        (
            "bash-only",
            vec![
                bash_rule(RuleAction::Deny, "rm -rf *"),
                bash_rule(RuleAction::Ask, "kubectl *"),
            ],
        ),
        (
            "allow-only-file",
            vec![
                file_rule(RuleAction::Allow, ToolFilter::Read, "**"),
                file_rule(RuleAction::Allow, ToolFilter::Edit, "**"),
            ],
        ),
    ];
    for (label, rules) in policies {
        let config = PermissionConfig::new(rules.clone());
        let policy = compiled(rules);
        assert!(
            !policy.has_file_restrictions,
            "[{label}] no-restriction policy must not arm the file gate"
        );
        for cmd in BYPASS_VECTORS {
            assert!(
                policy.evaluate_shell_file_access(cmd, cwd()).is_none(),
                "[{label}] inert policy must not gate `{cmd}`"
            );
        }
        assert!(
            read_deny_globs(&config).is_empty(),
            "[{label}] inert policy must derive zero recursive-grep read-excludes"
        );
    }
}

/// The policy must not over-match legit look-alikes (direct read or shell gate).
/// It targets dotfile `.env`/`.env.<x>` and real cert globs, not any `env`/`pem`.
#[test]
fn h2_enterprise_policy_does_not_over_match_legit_paths() {
    let policy = enterprise_requirements_policy();
    for path in [
        "environment.txt",
        "foo.env",
        "my.env.example",
        "src/env.rs",
        "environments/config.yaml",
        "README.md",
        "src/main.py",
        "prevent.pem.md",
        ".environment/app.conf",
    ] {
        let direct = policy.evaluate(&AccessKind::Read(Some(path.to_string())));
        assert!(
            !matches!(direct, Some(Decision::Reject(_))),
            "[read {path}] legit look-alike must not be denied, got {direct:?}"
        );
        let shell = policy.evaluate_shell_file_access(&format!("cat {path}"), cwd());
        assert!(
            !matches!(shell, Some(Decision::Reject(_))),
            "[cat {path}] legit look-alike must not be denied, got {shell:?}"
        );
    }
    // Nuance: `**/.env.*` DOES catch a dotfile `.env.<suffix>` (both vectors)…
    for path in [".env.example", ".env.staging"] {
        assert!(
            matches!(
                policy.evaluate(&AccessKind::Read(Some(path.to_string()))),
                Some(Decision::Reject(_))
            ),
            "[read {path}] must be denied by **/.env.*"
        );
        assert!(
            matches!(
                policy.evaluate_shell_file_access(&format!("cat {path}"), cwd()),
                Some(Decision::Reject(_))
            ),
            "[cat {path}] must be denied by **/.env.*"
        );
    }
    // …but `my.env.example` (not a dotfile) is NOT caught.
    assert!(
        policy
            .evaluate(&AccessKind::Read(Some("my.env.example".to_string())))
            .is_none(),
        "my.env.example must not match **/.env.*"
    );
}

/// The shell gate never hard-blocks legit reads; fail-closed cases (glob, recursion, unpinnable substitution) `Ask`, not `Reject`.
#[test]
fn h3_enterprise_gate_never_false_blocks_legit() {
    let policy = enterprise_requirements_policy();
    for cmd in ["cat README.md", "grep foo src/main.py", "wc -l src/main.py"] {
        assert!(
            policy.evaluate_shell_file_access(cmd, cwd()).is_none(),
            "legit read must not be gated: {cmd}"
        );
    }
    for cmd in ["cat *.md", "grep -r foo .", "cat $(echo README.md)"] {
        assert!(
            matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Ask)
            ),
            "fail-closed case must ask, never reject: {cmd}"
        );
    }
}

/// A deployment that ships managed config with no `[permission]` rules must see zero gating (no secrets embedded, only the empty rule set).
#[test]
fn unrestricted_enterprise_has_no_file_restrictions() {
    let policy = compiled(vec![]);
    assert!(
        !policy.has_file_restrictions,
        "a deployment with no [permission] rules must not arm the file gate"
    );
    for cmd in BYPASS_VECTORS {
        assert!(
            policy.evaluate_shell_file_access(cmd, cwd()).is_none(),
            "no-restriction enterprise policy must not gate `{cmd}`"
        );
    }
}
