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
        for name in super::PROVIDER_CREDENTIAL_NAMES {
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

#[test]
fn default_shell_policy_excludes_fuigo_credentials() {
    let policy = ShellEnvironmentPolicy::default();
    let env = create_env_from_vars(
        vars(&[
            ("PATH", "/bin"),
            ("FUIGO_API_KEY", "secret"),
            ("FUIGO_CODE_API_KEY", "legacy-secret"),
            ("OTHER_VAR", "keep"),
        ]),
        &policy,
    );
    assert!(!env.contains_key("FUIGO_API_KEY"));
    assert!(!env.contains_key("FUIGO_CODE_API_KEY"));
    assert!(!policy.allows("FUIGO_API_KEY"));
    assert_eq!(env.get("OTHER_VAR").map(String::as_str), Some("keep"));
}

#[cfg(unix)]
#[tokio::test]
async fn default_shell_policy_keeps_credentials_out_of_child_processes() {
    let default_policy = ShellEnvironmentPolicy::default();
    for policy in [Some(&default_policy), None] {
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.args([
            "-c",
            "test -z \"${FUIGO_API_KEY+x}\" && test -z \"${FUIGO_CODE_API_KEY+x}\"",
        ]);
        cmd.env("FUIGO_API_KEY", "stored-test-credential");
        cmd.env("FUIGO_CODE_API_KEY", "legacy-test-credential");
        apply_shell_environment_policy(&mut cmd, policy);
        assert!(
            cmd.status().await.unwrap().success(),
            "the child must not receive either Fuigo credential"
        );
    }
}
