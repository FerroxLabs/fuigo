//! P166 round 13B (owner-approved 2026-10-08). Feature 2: the exact-value allowlist for harmless editor, pager and
//! credential-helper values (this file). Feature 1 (branch switches under a narrow git grant) is tested in
//! `p166_r13b_branch_tests.rs`.

use super::p166_r8_sweep_tests::floor;
use super::{ClassifierSecurityFinding, PermissionState, evaluate_bash};
use crate::permission::exec_risk::{
    COMMAND_VALUED_CONFIG_KEYS, HARMLESS_COMMAND_VALUES, command_valued_config, harmless_config_value, harmless_env_value,
    is_git_exec_env_assignment,
};

fn exec(cmd: &str) -> bool {
    evaluate_bash(cmd, &PermissionState::default(), true)
        .assessment
        .contains(ClassifierSecurityFinding::ExecOrAmbientGit)
}

fn project() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join(".git/hooks")).unwrap();
    project
}

/// Each allowed value passes on the env path (prefix, `env`, `export`, plain quotes).
#[test]
fn p166_r13b_allowed_env_values_pass() {
    let mut wrong = Vec::new();
    for row in HARMLESS_COMMAND_VALUES {
        for name in row.env.iter().filter(|name| name.starts_with("GIT_")) {
            for value in row.values {
                for cmd in [
                    format!("{name}={value} git log"),
                    format!("env {name}={value} git log"),
                    format!("{name}='{value}' git log"),
                    format!("{name}=\"{value}\" git log"),
                ] {
                    if exec(&cmd) {
                        wrong.push(cmd);
                    }
                }
            }
        }
    }
    // `export NAME=value; git ...`: the allowlist leaves exactly the baseline (an unrelated `export` is judged the same).
    let baseline = exec("export FOO=1; git log");
    eprintln!("FP13B baseline `export FOO=1; git log` exec={baseline}");
    for (name, value) in [("GIT_PAGER", "cat"), ("GIT_EDITOR", "true"), ("GIT_EDITOR", "nano"), ("GIT_SEQUENCE_EDITOR", "nano")] {
        let cmd = format!("export {name}={value}; git log");
        assert_eq!(exec(&cmd), baseline, "{cmd}");
        assert!(exec(&format!("export {name}=vim; git log")), "export {name}=vim must stay exec risk");
    }
    for cmd in ["GIT_PAGER=cat git log", "GIT_EDITOR=true git commit --amend --no-edit", "GIT_SEQUENCE_EDITOR=nano git rebase -i HEAD~2"] {
        assert!(!exec(cmd), "{cmd}");
    }
    assert!(wrong.is_empty(), "allowlisted env values still exec risk: {wrong:#?}");
}

/// Near misses and other variables stay exec risk.
#[test]
fn p166_r13b_env_near_misses_stay_blocked() {
    let rows = [
        "GIT_PAGER='cat -' git log",
        "GIT_PAGER=' cat' git log",
        "GIT_PAGER='cat ' git log",
        "GIT_PAGER='cat;id' git log",
        "GIT_PAGER='cat|id' git log",
        "GIT_PAGER=Cat git log",
        "GIT_PAGER=true git log",
        "GIT_PAGER=less git log",
        "GIT_PAGER=/bin/cat git log",
        "GIT_PAGER='$(id)' git log",
        "GIT_PAGER='`id`' git log",
        "GIT_EDITOR='true --x' git commit",
        "GIT_EDITOR='nano -c x' git commit",
        "GIT_EDITOR=vim git commit",
        "GIT_EDITOR=nvim git commit",
        "GIT_EDITOR=vi git commit",
        "GIT_EDITOR='code --wait' git commit",
        "GIT_EDITOR=emacs git commit",
        "GIT_EDITOR=cat git commit",
        "GIT_SEQUENCE_EDITOR=vim git rebase -i HEAD~2",
        "GIT_SSH_COMMAND=cat git fetch",
        "GIT_SSH_COMMAND=true git fetch",
        "GIT_ASKPASS=true git fetch",
        "GIT_EXTERNAL_DIFF=true git diff",
        "env GIT_EDITOR=vim git commit",
        "export GIT_PAGER='cat -'; git log",
    ];
    let wrong: Vec<&&str> = rows.iter().filter(|cmd| !exec(cmd)).collect();
    assert!(wrong.is_empty(), "near misses must stay exec risk: {wrong:#?}");
    assert!(!is_git_exec_env_assignment("GIT_PAGER=cat"));
    assert!(is_git_exec_env_assignment("GIT_PAGER=cat -"));
}

/// Config keys: allowed values are not command-valued; near misses are.
#[test]
fn p166_r13b_config_key_allowlist() {
    for (key, value) in [
        ("core.pager", "cat"),
        ("pager.log", "cat"),
        ("core.editor", "true"),
        ("core.editor", "nano"),
        ("sequence.editor", "true"),
        ("sequence.editor", "nano"),
        ("credential.helper", "store"),
        ("credential.helper", "cache"),
        ("credential.helper", "osxkeychain"),
        ("credential.helper", "manager"),
        ("credential.https://example.com.helper", "store"),
        ("Core.Editor", "nano"),
    ] {
        assert!(!command_valued_config(key, Some(value)), "{key}={value}");
    }
    for (key, value) in [
        ("core.pager", "cat -"),
        ("core.pager", " cat"),
        ("core.pager", "cat;id"),
        ("core.pager", "true"),
        ("core.editor", "vim"),
        ("core.editor", "nvim"),
        ("core.editor", "vi"),
        ("core.editor", "code --wait"),
        ("core.editor", "emacs"),
        ("core.editor", "true --x"),
        ("core.editor", "nano -c x"),
        ("core.editor", " true"),
        ("core.editor", "true\n"),
        ("core.editor", "cat"),
        ("sequence.editor", "vim"),
        ("credential.helper", "store --file=x"),
        ("credential.helper", "/usr/bin/store"),
        ("credential.helper", "!store"),
        ("credential.helper", "Store"),
        ("credential.helper", "store "),
        ("credential.helper", "nano"),
        ("credential.https://example.com.helper", "!store"),
        ("core.sshcommand", "true"),
        ("core.askpass", "true"),
        ("core.hookspath", "true"),
        ("credential.username", "!x"),
    ] {
        // `credential.username` is not command-valued at all: skip it in the must-be-blocked list.
        if key == "credential.username" {
            continue;
        }
        assert!(command_valued_config(key, Some(value)), "{key}={value:?}");
    }
    assert!(command_valued_config("core.editor", None), "no value known: fail closed");
}

/// The `git config` SET path: the allowed value takes no protected floor; a near miss does.
#[test]
fn p166_r13b_git_config_set_path() {
    let project = project();
    let cwd = project.path();
    for cmd in [
        "git config core.editor true",
        "git config core.editor nano",
        "git config core.pager cat",
        "git config pager.log cat",
        "git config sequence.editor true",
        "git config credential.helper store",
        "git config credential.helper cache",
        "git config credential.helper osxkeychain",
        "git config credential.helper manager",
        "git config credential.https://example.com.helper store",
    ] {
        assert!(floor(cwd, cmd).is_none(), "{cmd}");
    }
    for cmd in [
        "git config core.editor vim",
        "git config core.editor 'true --x'",
        "git config core.editor 'nano -c x'",
        "git config core.pager 'cat -'",
        "git config credential.helper 'store --file=x'",
        "git config credential.helper /usr/bin/store",
        "git config credential.helper '!store'",
        "git config credential.helper Store",
        "git config core.sshCommand true",
    ] {
        assert!(floor(cwd, cmd).is_some(), "{cmd}");
    }
}

/// The env path and the config-key path read the same table, row by row.
#[test]
fn p166_r13b_env_and_config_paths_share_one_table() {
    assert!(!HARMLESS_COMMAND_VALUES.is_empty());
    for row in HARMLESS_COMMAND_VALUES {
        for value in row.values {
            for name in row.env {
                assert!(harmless_env_value(name, value), "env {name}={value}");
            }
            for key in row.keys {
                let concrete = key.replace('*', "x");
                assert!(harmless_config_value(&concrete, value), "key {concrete}={value}");
            }
        }
    }
    // Each variable and key pattern the table names is one the exec tables flag today (so the allowlist removes a
    // real finding); GIT_SSH_COMMAND is in no row.
    for row in HARMLESS_COMMAND_VALUES {
        assert!(!row.env.contains(&"GIT_SSH_COMMAND"));
        for key in row.keys {
            let concrete = key.replace('*', "x");
            assert!(
                command_valued_config(&concrete, Some("definitely-not-allowed")),
                "{concrete} must be command-valued without the allowlist"
            );
            assert!(
                COMMAND_VALUED_CONFIG_KEYS.iter().any(|(pattern, _)| pattern == key),
                "{key} must be in the command-valued key table"
            );
        }
    }
}

/// Before/base/after probe: prints one line per listed command (`FP13B <cmd> => ...`).
#[test]
fn p166_r13b_probe_listed_commands() {
    let project = project();
    let cwd = project.path();
    for cmd in [
        "GIT_PAGER=cat git log",
        "GIT_EDITOR=true git commit --amend --no-edit",
        "git config core.editor true",
        "git config core.editor vim",
        "git config credential.helper store",
        "git config credential.helper 'store --file=x'",
        "GIT_SSH_COMMAND='ssh -i key' git fetch",
    ] {
        let evaluation = evaluate_bash(cmd, &PermissionState::default(), true);
        let floor = super::bash_protected_write_target(&evaluation, cwd, None);
        eprintln!("FP13B {cmd} => floor={floor:?} findings={:?}", evaluation.assessment);
    }
}
