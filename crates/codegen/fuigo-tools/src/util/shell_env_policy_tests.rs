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
    assert!(!create_env_from_vars(Vec::new(), &policy).contains_key("OPENAI_API_KEY"));
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
    super::register_credential_env_names(super::EnvPlatform::host().core_vars());
    for core in super::EnvPlatform::host().core_vars() {
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

// u35-winenv: Windows environment names are case-insensitive. These run on every host through the
// platform-parameterised core, so the Windows rules are covered by the Linux test run.
mod u35_winenv {
    use super::super::{
        EnvPlatform, ShellEnvironmentPolicy, ShellEnvironmentPolicyInherit, collapse_env_names,
        create_env_for, install_base_env_for, names_to_remove,
    };
    use super::{patterns, vars};
    use std::collections::HashMap;
    use std::ffi::OsString;

    fn spellings_of(env: &HashMap<String, String>, name: &str) -> Vec<String> {
        let mut keys: Vec<String> = env
            .keys()
            .filter(|k| k.eq_ignore_ascii_case(name))
            .cloned()
            .collect();
        keys.sort();
        keys
    }

    #[test]
    fn windows_collapses_case_variants_keeping_the_first_spelling_and_value() {
        let policy = ShellEnvironmentPolicy::default();
        let env = create_env_for(
            vars(&[("Path", "C:\\good"), ("PATH", "C:\\bad"), ("path", "C:\\worse")]),
            &policy,
            EnvPlatform::Windows,
        );
        assert_eq!(spellings_of(&env, "PATH"), vec!["Path".to_string()]);
        assert_eq!(env["Path"], "C:\\good");
        // Reversed block order: the first entry still wins.
        let env = create_env_for(
            vars(&[("PATH", "C:\\first"), ("Path", "C:\\second")]),
            &policy,
            EnvPlatform::Windows,
        );
        assert_eq!(spellings_of(&env, "PATH"), vec!["PATH".to_string()]);
        assert_eq!(env["PATH"], "C:\\first");
    }

    #[test]
    fn windows_collapse_takes_the_value_the_process_resolves() {
        let out = collapse_env_names(
            vars(&[("Path", "C:\\block-first"), ("PATH", "C:\\block-second")]),
            EnvPlatform::Windows,
            |name| name.eq_ignore_ascii_case("path").then(|| "C:\\resolved".to_string()),
        );
        assert_eq!(out, vars(&[("Path", "C:\\resolved")]));
        // No resolution: the first entry's value.
        let out = collapse_env_names(
            vars(&[("Path", "C:\\a"), ("PATH", "C:\\b")]),
            EnvPlatform::Windows,
            |_| None,
        );
        assert_eq!(out, vars(&[("Path", "C:\\a")]));
    }

    #[test]
    fn unix_keeps_case_variants_as_distinct_variables() {
        let env = create_env_for(
            vars(&[("Path", "/a"), ("PATH", "/b")]),
            &ShellEnvironmentPolicy::default(),
            EnvPlatform::Unix,
        );
        assert_eq!(env["Path"], "/a");
        assert_eq!(env["PATH"], "/b");
        assert!(!env.contains_key("PATHEXT"), "PATHEXT is a Windows default only");
    }

    #[test]
    // `exclude`/`include_only` already matched any ASCII spelling before 1.0.35; what this pins is
    // that the collapse leaves exactly ONE spelling for them to act on (and PATHEXT re-added).
    fn windows_collapse_leaves_one_spelling_for_exclude_and_include_only() {
        let mut policy = ShellEnvironmentPolicy {
            exclude: patterns(&["secret_thing"]),
            ..ShellEnvironmentPolicy::default()
        };
        let env = create_env_for(
            vars(&[("Secret_Thing", "x"), ("SECRET_THING", "y"), ("Keep", "k")]),
            &policy,
            EnvPlatform::Windows,
        );
        assert!(spellings_of(&env, "SECRET_THING").is_empty());
        assert_eq!(env["Keep"], "k");

        policy.exclude.clear();
        policy.include_only = patterns(&["path"]);
        let env = create_env_for(
            vars(&[("Path", "C:\\p"), ("PATH", "C:\\q"), ("Other", "o")]),
            &policy,
            EnvPlatform::Windows,
        );
        assert_eq!(env["Path"], "C:\\p");
        assert!(!env.contains_key("Other"));
        // PATHEXT is re-added after include_only so commands stay runnable.
        assert!(env.contains_key("PATHEXT"));
    }

    #[test]
    fn windows_set_replaces_every_inherited_spelling() {
        let mut policy = ShellEnvironmentPolicy::default();
        policy.set.insert("PATH".into(), "C:\\set".into());
        let env = create_env_for(
            vars(&[("Path", "C:\\inherited")]),
            &policy,
            EnvPlatform::Windows,
        );
        assert_eq!(spellings_of(&env, "PATH"), vec!["PATH".to_string()]);
        assert_eq!(env["PATH"], "C:\\set");
        // Two `set` spellings of one name: one entry, and the same one whatever order the `set` map
        // iterates in. Each policy below is a FRESH HashMap (its own random seed) with the two
        // spellings inserted in opposite orders, so without the sort some pairs disagree.
        policy.set.insert("Path".into(), "C:\\set2".into());
        let first = create_env_for(Vec::new(), &policy, EnvPlatform::Windows);
        assert_eq!(spellings_of(&first, "PATH").len(), 1);
        for round in 0..16 {
            let mut order = [("PATH", "C:\\set"), ("Path", "C:\\set2")];
            if round % 2 == 1 {
                order.reverse();
            }
            let mut fresh = ShellEnvironmentPolicy::default();
            for (name, value) in order {
                fresh.set.insert(name.into(), value.into());
            }
            let env = create_env_for(Vec::new(), &fresh, EnvPlatform::Windows);
            assert_eq!(env, first, "round {round}");
        }
        // Unix: two distinct variables.
        let env = create_env_for(Vec::new(), &policy, EnvPlatform::Unix);
        assert_eq!(env["PATH"], "C:\\set");
        assert_eq!(env["Path"], "C:\\set2");
    }

    #[test]
    fn windows_core_inherit_keeps_case_variant_core_names_once() {
        let policy = ShellEnvironmentPolicy {
            inherit: ShellEnvironmentPolicyInherit::Core,
            ..ShellEnvironmentPolicy::default()
        };
        let env = create_env_for(
            vars(&[
                ("Path", "C:\\p"),
                ("PATH", "C:\\q"),
                ("ComSpec", "C:\\Windows\\system32\\cmd.exe"),
                ("SystemRoot", "C:\\Windows"),
                ("RANDOM", "r"),
            ]),
            &policy,
            EnvPlatform::Windows,
        );
        assert_eq!(spellings_of(&env, "PATH"), vec!["Path".to_string()]);
        assert!(env.contains_key("ComSpec") && env.contains_key("SystemRoot"));
        assert!(!env.contains_key("RANDOM"));
        // The Unix core list has no ComSpec.
        let env = create_env_for(
            vars(&[("PATH", "/bin"), ("ComSpec", "x")]),
            &policy,
            EnvPlatform::Unix,
        );
        assert!(env.contains_key("PATH") && !env.contains_key("ComSpec"));
    }

    #[test]
    fn remove_loop_removes_every_uncarried_spelling_and_keeps_carried_ones() {
        let policy = ShellEnvironmentPolicy {
            exclude: patterns(&["drop_me"]),
            ..ShellEnvironmentPolicy::default()
        };
        let inherited = vars(&[
            ("Path", "C:\\p"),
            ("PATH", "C:\\q"),
            ("Drop_Me", "1"),
            ("DROP_ME", "2"),
        ]);
        let base = create_env_for(inherited.clone(), &policy, EnvPlatform::Windows);
        let names: Vec<OsString> = inherited.iter().map(|(k, _)| OsString::from(k)).collect();
        let mut removed = names_to_remove(names.clone(), &base, EnvPlatform::Windows);
        removed.sort();
        assert_eq!(removed, vec![OsString::from("DROP_ME"), OsString::from("Drop_Me")]);
        // Unix: `PATH` is its own variable, carried; nothing named PATH is removed.
        let base = create_env_for(inherited, &policy, EnvPlatform::Unix);
        let mut removed = names_to_remove(names, &base, EnvPlatform::Unix);
        removed.sort();
        assert_eq!(removed, vec![OsString::from("DROP_ME"), OsString::from("Drop_Me")]);
    }

    // A guard, not proof of 1.0.35: ASCII-case credential matching predates it.
    #[test]
    fn windows_credentials_are_dropped_in_any_spelling() {
        let env = create_env_for(
            vars(&[("OpenAI_Api_Key", "fake"), ("OPENAI_API_KEY", "fake2"), ("Path", "C:\\p")]),
            &ShellEnvironmentPolicy::default(),
            EnvPlatform::Windows,
        );
        assert!(spellings_of(&env, "OPENAI_API_KEY").is_empty());
        assert_eq!(env["Path"], "C:\\p");
    }

    /// Windows resolves `\u{f6}auth` and `\u{d6}AUTH` to ONE variable. With `\u{d6}AUTH` registered as a
    /// credential and a block holding both spellings (the process reads `secret` for either), the
    /// child must get neither spelling and never the secret. An ASCII-only collapse kept both
    /// entries, each with the resolved secret, and the ASCII-only credential check dropped only one.
    #[test]
    fn windows_unicode_case_alias_cannot_carry_a_registered_credential() {
        super::super::register_credential_env_names(["\u{d6}AUTH_U35W"]);
        let block = vars(&[("\u{d6}AUTH_U35W", "secret"), ("\u{f6}auth_u35w", "benign"), ("Path", "C:\\p")]);
        let collapsed = collapse_env_names(block, EnvPlatform::Windows, |name| {
            fuigo_secrets::child_env::windows_env_names_equal(name, "\u{d6}AUTH_U35W").then(|| "secret".to_string())
        });
        assert_eq!(collapsed.len(), 2, "one entry per Windows variable: {collapsed:?}");
        let env = create_env_for(collapsed, &ShellEnvironmentPolicy::default(), EnvPlatform::Windows);
        assert!(!env.values().any(|v| v == "secret"), "{env:?}");
        assert!(
            !env.keys().any(|k| fuigo_secrets::child_env::windows_env_names_equal(k, "\u{d6}AUTH_U35W")),
            "{env:?}"
        );
        assert_eq!(env["Path"], "C:\\p");
    }

    /// On Windows an `exclude` glob also removes a Unicode-case alias of the name it matches
    /// (`\u{131}` uppercases to `I`, which the glob's per-character lowercase fold misses); Unix keeps
    /// the exact-name rule.
    #[test]
    fn windows_exclude_matches_unicode_case_aliases() {
        let policy = ShellEnvironmentPolicy {
            exclude: patterns(&["api_*"]),
            ..ShellEnvironmentPolicy::default()
        };
        let block = vars(&[("AP\u{131}_X_U35", "v"), ("Keep", "k")]);
        let env = create_env_for(block.clone(), &policy, EnvPlatform::Windows);
        assert!(!env.contains_key("AP\u{131}_X_U35"), "{env:?}");
        assert_eq!(env["Keep"], "k");
        assert!(!policy.allows_on("AP\u{131}_X_U35", EnvPlatform::Windows));
        let env = create_env_for(block, &policy, EnvPlatform::Unix);
        assert!(env.contains_key("AP\u{131}_X_U35"));
        assert!(policy.allows_on("AP\u{131}_X_U35", EnvPlatform::Unix));
    }

    /// u35-winenv r2 (Astra r2 Medium): the fold is applied to the pattern's literals too, so on
    /// Windows a non-ASCII pattern matches the ASCII name Windows equates with it, in both `exclude`
    /// and `include_only`, and an ASCII pattern matches a non-ASCII alias. b62b45bfa folded only a
    /// non-ASCII NAME, so `AP\u{131}_*` left `API_AUTH` in the child.
    #[test]
    fn windows_policy_globs_fold_the_pattern_and_the_name() {
        let exclude = ShellEnvironmentPolicy {
            exclude: patterns(&["AP\u{131}_*"]),
            ..ShellEnvironmentPolicy::default()
        };
        assert!(!exclude.allows_on("API_AUTH", EnvPlatform::Windows));
        assert!(!exclude.allows_on("api_auth", EnvPlatform::Windows));
        assert!(!exclude.allows_on("AP\u{131}_AUTH", EnvPlatform::Windows));
        assert!(exclude.allows_on("APX_AUTH", EnvPlatform::Windows));
        let env = create_env_for(vars(&[("API_AUTH", "v"), ("Keep", "k")]), &exclude, EnvPlatform::Windows);
        assert!(!env.contains_key("API_AUTH"), "{env:?}");
        assert_eq!(env["Keep"], "k");
        // Unix: names are exact; `\u{131}` is not `i` to the glob.
        assert!(exclude.allows_on("API_AUTH", EnvPlatform::Unix));

        for (pattern, name) in [("AP\u{131}_*", "API_AUTH"), ("API_*", "AP\u{131}_AUTH")] {
            let include = ShellEnvironmentPolicy {
                include_only: patterns(&[pattern]),
                ..ShellEnvironmentPolicy::default()
            };
            assert!(include.allows_on(name, EnvPlatform::Windows), "{pattern} keeps {name}");
            assert!(!include.allows_on("OTHER", EnvPlatform::Windows));
            assert!(!include.allows_on(name, EnvPlatform::Unix), "{pattern} vs {name} on Unix");
        }
    }

    /// The wide fold only ever REMOVES: it widens `exclude`, never `include_only`, where Windows' own
    /// equality decides. `\u{3f4}` (capital theta symbol) and `\u{3d1}` (theta symbol) differ under
    /// the glob's lowercase fold and under Windows' uppercase, but both lower-then-upper to `\u{398}`.
    #[test]
    fn windows_wide_fold_widens_exclude_but_never_include_only() {
        let (pattern, name) = ("\u{3f4}EEP_*", "\u{3d1}EEP_U35R2");
        let exclude = ShellEnvironmentPolicy {
            exclude: patterns(&[pattern]),
            ..ShellEnvironmentPolicy::default()
        };
        assert!(!exclude.allows_on(name, EnvPlatform::Windows));
        assert!(exclude.allows_on(name, EnvPlatform::Unix));
        let include = ShellEnvironmentPolicy {
            include_only: patterns(&[pattern]),
            ..ShellEnvironmentPolicy::default()
        };
        assert!(!include.allows_on(name, EnvPlatform::Windows));
        assert!(include.allows_on("\u{3b8}eep_u35r2", EnvPlatform::Windows), "the glob's own fold still applies");
    }

    /// `inherit = "core"` matches core names exactly on Unix (`path` is a different variable from
    /// `PATH` there) and in any spelling on Windows.
    #[test]
    fn core_inherit_matches_exactly_on_unix_and_any_spelling_on_windows() {
        let policy = ShellEnvironmentPolicy {
            inherit: ShellEnvironmentPolicyInherit::Core,
            ..ShellEnvironmentPolicy::default()
        };
        let block = vars(&[("path", "/x"), ("home", "/h"), ("PATH", "/bin")]);
        let env = create_env_for(block, &policy, EnvPlatform::Unix);
        assert!(!env.contains_key("path") && !env.contains_key("home"), "{env:?}");
        assert_eq!(env["PATH"], "/bin");
        assert!(!policy.allows_with_inherit_on("path", EnvPlatform::Unix));
        assert!(!policy.allows_with_inherit_on("user", EnvPlatform::Unix));
        assert!(policy.allows_with_inherit_on("PATH", EnvPlatform::Unix));
        assert!(policy.allows_with_inherit_on("path", EnvPlatform::Windows));
        assert!(policy.allows_with_inherit_on("SystemRoot", EnvPlatform::Windows));
    }

    /// At the `Command` boundary (what the child and the sandbox's `get_envs` see): an inherited
    /// block with `PATH` and `Path` leaves exactly one PATH edit, a set, and no removal of either
    /// spelling; names the base does not carry are removed.
    #[test]
    fn windows_command_gets_one_path_edit_and_no_path_removal() {
        let base: HashMap<String, String> =
            [("Path".to_string(), "C:\\p".to_string())].into_iter().collect();
        let mut cmd = tokio::process::Command::new("unused");
        install_base_env_for(
            &mut cmd,
            ["PATH", "Path", "DROPPED"].map(OsString::from),
            base,
            EnvPlatform::Windows,
        );
        let edits: Vec<(String, Option<String>)> = cmd
            .as_std()
            .get_envs()
            .map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(|v| v.to_string_lossy().into_owned())))
            .collect();
        let path_edits: Vec<&(String, Option<String>)> =
            edits.iter().filter(|(k, _)| k.eq_ignore_ascii_case("PATH")).collect();
        assert_eq!(path_edits, vec![&("Path".to_string(), Some("C:\\p".to_string()))], "{edits:?}");
        assert!(edits.contains(&("DROPPED".to_string(), None)), "{edits:?}");
    }
}
