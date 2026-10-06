use super::{
    EnvironmentVariablePattern, ShellEnvironmentPolicy, ShellEnvironmentPolicyInherit,
    apply_shell_environment_policy, create_env_from_vars,
};
use std::collections::HashMap;

fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn patterns(globs: &[&str]) -> Vec<EnvironmentVariablePattern> {
    globs
        .iter()
        .map(|g| EnvironmentVariablePattern::new_case_insensitive(g))
        .collect()
}

#[test]
fn apply_policy_reshapes_command_env() {
    let mut set = HashMap::new();
    set.insert("MY_FLAG".to_string(), "1".to_string());
    let policy = ShellEnvironmentPolicy {
        inherit: ShellEnvironmentPolicyInherit::None,
        set,
        ..Default::default()
    };
    let mut cmd = tokio::process::Command::new("true");
    apply_shell_environment_policy(&mut cmd, Some(&policy));
    let envs: HashMap<String, String> = cmd
        .as_std()
        .get_envs()
        .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
        .collect();
    assert_eq!(envs.get("MY_FLAG").map(String::as_str), Some("1"));
    // inherit=None cleared the env, so no inherited PATH leaks through.
    assert!(!envs.contains_key("PATH"));
}

#[test]
fn apply_empty_exclusions_still_filters_credentials() {
    let mut cmd = tokio::process::Command::new("true");
    let noop = ShellEnvironmentPolicy {
        exclude: Vec::new(),
        ..Default::default()
    };
    apply_shell_environment_policy(&mut cmd, Some(&noop));
    assert!(!noop.is_noop());
    assert!(
        cmd.as_std()
            .get_envs()
            .all(|(key, _)| !super::is_provider_credential(&key.to_string_lossy()))
    );
}

#[test]
fn t05_known_names_and_policy_precedence() {
    for exclude in [Vec::new(), patterns(&["CUSTOM_*"])] {
        let policy = ShellEnvironmentPolicy {
            exclude,
            ..Default::default()
        };
        let mut input = vars(&[("PATH", "/bin"), ("BENIGN", "ok")]);
        for name in super::credential_env_names() {
            input.push((name.to_string(), "fake-t05".into()));
            input.push((name.to_ascii_lowercase(), "fake-t05".into()));
        }
        let env = create_env_from_vars(input, &policy);
        assert_eq!(env.len(), 2);
        assert_eq!(env["BENIGN"], "ok");
    }
}

#[test]
fn t05_deliberate_delivery() {
    let mut policy = ShellEnvironmentPolicy::default();
    policy
        .set
        .insert("OPENAI_API_KEY".into(), "fake-selected".into());
    let env = create_env_from_vars(vars(&[("ANTHROPIC_API_KEY", "fake-ambient")]), &policy);
    assert_eq!(
        env.get("OPENAI_API_KEY").map(String::as_str),
        Some("fake-selected")
    );
    assert!(!env.contains_key("ANTHROPIC_API_KEY"));
    assert!(!policy.allows("OPENAI_API_KEY"));
    policy.include_only = patterns(&["PATH"]);
    assert!(
        create_env_from_vars(Vec::new(), &policy)
            .get("OPENAI_API_KEY")
            .is_none()
    );
}

#[test]
fn default_excludes_drop_secrets_when_enabled() {
    let policy = ShellEnvironmentPolicy {
        ignore_default_excludes: false,
        ..Default::default()
    };
    assert!(!policy.is_noop());
    let env = create_env_from_vars(
        vars(&[
            ("PATH", "/bin"),
            ("MY_API_KEY", "x"),
            ("MY_SECRET", "y"),
            ("GH_TOKEN", "z"),
        ]),
        &policy,
    );
    assert_eq!(env.get("PATH").map(String::as_str), Some("/bin"));
    assert!(!env.contains_key("MY_API_KEY"));
    assert!(!env.contains_key("MY_SECRET"));
    assert!(!env.contains_key("GH_TOKEN"));
}

#[test]
fn inherit_none_starts_empty_then_set_applies() {
    let mut set = HashMap::new();
    set.insert("PATH".to_string(), "/usr/bin".to_string());
    set.insert("MY_FLAG".to_string(), "1".to_string());
    let policy = ShellEnvironmentPolicy {
        inherit: ShellEnvironmentPolicyInherit::None,
        set,
        ..Default::default()
    };
    let env = create_env_from_vars(vars(&[("PATH", "/bin"), ("HOME", "/root")]), &policy);
    assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
    assert_eq!(env.get("MY_FLAG").map(String::as_str), Some("1"));
    assert!(!env.contains_key("HOME"));
}

#[test]
fn inherit_core_keeps_only_core_vars() {
    let policy = ShellEnvironmentPolicy {
        inherit: ShellEnvironmentPolicyInherit::Core,
        ..Default::default()
    };
    let env = create_env_from_vars(vars(&[("PATH", "/bin"), ("RANDOM_VAR", "v")]), &policy);
    assert_eq!(env.get("PATH").map(String::as_str), Some("/bin"));
    assert!(!env.contains_key("RANDOM_VAR"));
}

#[test]
fn exclude_and_include_only_filter() {
    let policy = ShellEnvironmentPolicy {
        exclude: patterns(&["AWS_*"]),
        include_only: patterns(&["PATH", "HOME"]),
        ..Default::default()
    };
    let env = create_env_from_vars(
        vars(&[
            ("PATH", "/bin"),
            ("HOME", "/root"),
            ("AWS_SECRET", "s"),
            ("OTHER", "o"),
        ]),
        &policy,
    );
    assert_eq!(env.get("PATH").map(String::as_str), Some("/bin"));
    assert_eq!(env.get("HOME").map(String::as_str), Some("/root"));
    assert!(!env.contains_key("AWS_SECRET"));
    assert!(!env.contains_key("OTHER"));
}

#[test]
fn allows_filters_by_name_case_insensitively() {
    let policy = ShellEnvironmentPolicy {
        exclude: patterns(&["aws_*"]), // lowercase pattern, uppercase var
        include_only: patterns(&["PATH", "HOME"]),
        ..Default::default()
    };
    assert!(policy.allows("PATH"));
    assert!(!policy.allows("AWS_SECRET")); // excluded (case-insensitive)
    assert!(!policy.allows("OTHER")); // not in include_only

    let scrub = ShellEnvironmentPolicy {
        ignore_default_excludes: false,
        ..Default::default()
    };
    assert!(!scrub.allows("my_api_key")); // `*KEY*` matches case-insensitively
    assert!(ShellEnvironmentPolicy::default().allows("MY_API_KEY")); // unrelated API keys retain their existing behavior
}

#[test]
fn allows_with_inherit_honors_inherit() {
    // inherit = none admits nothing.
    let none = ShellEnvironmentPolicy {
        inherit: ShellEnvironmentPolicyInherit::None,
        ..Default::default()
    };
    assert!(!none.allows_with_inherit("PATH"));
    assert!(!none.allows_with_inherit("FOO"));

    // inherit = core admits only core names.
    let core = ShellEnvironmentPolicy {
        inherit: ShellEnvironmentPolicyInherit::Core,
        ..Default::default()
    };
    assert!(core.allows_with_inherit("PATH"));
    assert!(!core.allows_with_inherit("RANDOM_VAR"));

    // inherit = all defers to `allows` (exclude still applies).
    let all = ShellEnvironmentPolicy {
        exclude: patterns(&["AWS_*"]),
        ..Default::default()
    };
    assert!(all.allows_with_inherit("RANDOM_VAR"));
    assert!(!all.allows_with_inherit("AWS_SECRET"));
}

/// The credential denylist on its own, with the policy's `exclude` list EMPTY: the default
/// `exclude` also names `FUIGO_API_KEY`/`FUIGO_CODE_API_KEY`, so a test on the default policy
/// passed even with the denylist switched off (the audit's mutant M4). Names are literal, so
/// emptying the denylist cannot empty the test.
#[test]
fn default_shell_policy_excludes_fuigo_credentials() {
    let policy = ShellEnvironmentPolicy {
        exclude: Vec::new(),
        ..Default::default()
    };
    let credentials = [
        "FUIGO_API_KEY",
        "FUIGO_CODE_API_KEY",
        "FLUX_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
    ];
    let mut input = vars(&[("PATH", "/bin"), ("OTHER_VAR", "keep")]);
    for name in credentials {
        input.push((name.to_string(), "secret".into()));
        input.push((name.to_ascii_lowercase(), "secret".into()));
    }
    let env = create_env_from_vars(input, &policy);
    for name in credentials {
        assert!(!env.contains_key(name), "{name} reached the child env");
        assert!(
            !env.contains_key(&name.to_ascii_lowercase()),
            "{name} (lowercase) reached the child env"
        );
        assert!(!policy.allows(name), "{name} passes the layered-env filter");
    }
    assert_eq!(env.get("OTHER_VAR").map(String::as_str), Some("keep"));
    assert_eq!(env.get("PATH").map(String::as_str), Some("/bin"));
}

/// The credentials are in the PARENT's own environment (a fresh test process, see
/// [`super::p86_parent_env`]) and the child is spawned through the production entry point the
/// hooks, stdio MCP servers, static shells and toolset probes use. The old version set the key on
/// the command, which `env_clear` wipes whatever the denylist says, so it could not fail.
#[cfg(unix)]
#[tokio::test]
async fn default_shell_policy_keeps_credentials_out_of_child_processes() {
    if super::p86_parent_env("default_shell_policy_keeps_credentials_out_of_child_processes") {
        return;
    }
    let no_excludes = ShellEnvironmentPolicy {
        exclude: Vec::new(),
        ..Default::default()
    };
    let default_policy = ShellEnvironmentPolicy::default();
    for policy in [None, Some(&default_policy), Some(&no_excludes)] {
        let mut cmd = tokio::process::Command::new("/bin/sh");
        let check = super::P86_CHILD_CHECK;
        cmd.args(["-c", &format!("{check} && /bin/sh -c '{check}'")]);
        apply_shell_environment_policy(&mut cmd, policy);
        assert!(
            cmd.status().await.unwrap().success(),
            "a child (or grandchild) saw a parent credential, or lost the benign variable"
        );
    }
}

/// P86: a name the config loader registers joins the denylist (case-insensitively), and names that
/// would break every child or are not variable names are never registered.
#[test]
fn p86_registered_names_join_the_denylist_and_core_names_never_do() {
    super::register_credential_env_names([
        "P86_UNIT_corp_key",
        " P86_UNIT_SPACED ",
        "",
        "PATH",
        "user",
        "P86_UNIT_A=B",
        "P86_UNIT_\0NUL",
    ]);
    assert!(super::is_provider_credential("P86_UNIT_CORP_KEY"));
    assert!(super::is_provider_credential("p86_unit_corp_key"));
    // Kept exactly: the configured name (spaces included) is the variable that is read.
    assert!(super::is_provider_credential(" P86_UNIT_SPACED "));
    assert!(!super::is_provider_credential("P86_UNIT_SPACED"));
    // A blank-only name is a valid Unix variable name that `env_key` would read: denied too.
    super::register_credential_env_names(["   "]);
    assert!(super::is_provider_credential("   "));
    assert!(!super::is_provider_credential(""));
    // Neither platform's core variables can be registered.
    super::register_credential_env_names(super::CORE_ENV_VARS);
    for core in super::CORE_ENV_VARS {
        assert!(!super::is_provider_credential(core), "{core}");
    }
    for never in [
        "PATH",
        "USER",
        "user",
        "P86_UNIT_A=B",
        "P86_UNIT_A",
        "P86_UNIT_\0NUL",
    ] {
        assert!(!super::is_provider_credential(never), "{never:?}");
    }
    let names = super::credential_env_names();
    assert!(names.iter().any(|name| name == "P86_UNIT_CORP_KEY"));
    assert!(names.iter().any(|name| name == "FLUX_API_KEY"));
    assert!(names.iter().any(|name| name == "ANTHROPIC_AUTH_TOKEN"));
    assert!(
        !names
            .iter()
            .any(|name| name.is_empty() || name.contains('='))
    );
    let policy = ShellEnvironmentPolicy {
        exclude: Vec::new(),
        ..Default::default()
    };
    let env = create_env_from_vars(
        vars(&[
            ("P86_UNIT_CORP_KEY", "secret"),
            (" P86_UNIT_SPACED ", "secret"),
            ("PATH", "/bin"),
            ("USER", "me"),
        ]),
        &policy,
    );
    assert!(!env.contains_key("P86_UNIT_CORP_KEY"));
    assert!(!env.contains_key(" P86_UNIT_SPACED "));
    assert_eq!(env.get("PATH").map(String::as_str), Some("/bin"));
    assert_eq!(env.get("USER").map(String::as_str), Some("me"));
    // The user's explicit `set` still delivers a registered name.
    let mut explicit = ShellEnvironmentPolicy::default();
    explicit
        .set
        .insert("P86_UNIT_CORP_KEY".into(), "chosen".into());
    let env = create_env_from_vars(vars(&[("P86_UNIT_CORP_KEY", "ambient")]), &explicit);
    assert_eq!(
        env.get("P86_UNIT_CORP_KEY").map(String::as_str),
        Some("chosen")
    );
}
