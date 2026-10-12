//! S6.4 / S6.2 (packet 6 part B1): the peer guard for shell commands and the session store, in every mode.
//! Each command is DENIED while the session is peer-influenced and never sees the guard otherwise.

use super::peer_guard_tests::{decide, is_guard_denial, modes};
use super::*;

/// (label, command) pairs, all aimed at a protected file in the cwd or an alias of one.
const CASES: &[(&str, &str)] = &[
    ("redirect", "echo x > CLAUDE.md"),
    ("append", "echo x >> CLAUDE.md"),
    ("tee", "echo x | tee CLAUDE.md"),
    ("cp", "cp src.txt CLAUDE.md"),
    ("mv_rename_over", "mv src.txt CLAUDE.md"),
    ("symlink_alias", "echo x > alias.txt"),
    ("sed_i", "sed -i s/a/b/ CLAUDE.md"),
    ("git_config", "git config user.name x"),
    ("unparseable", "if then fi (( ;; <<<"),
    ("transcript", "echo x >> .fuigo/sessions/enc/id/transcript.jsonl"),
    ("session_state", "echo '{}' > .fuigo/sessions/enc/id/peer_influence.json"),
];

fn prepare(root: &std::path::Path) {
    std::fs::write(root.join("CLAUDE.md"), "x").unwrap();
    std::fs::write(root.join("src.txt"), "x").unwrap();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::write(root.join(".git/config"), "[core]\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("CLAUDE.md"), root.join("alias.txt")).unwrap();
    std::fs::write(root.join("a.txt"), "x").unwrap();
    std::fs::create_dir_all(root.join("s/rules")).unwrap();
    std::fs::write(root.join("s/rules/a.md"), "evil").unwrap();
    std::fs::write(root.join("s/CLAUDE.md"), "evil").unwrap();
}

/// Round 2, item 1: a glob word is unpinned inside the extended scope.
const GLOB_CASES: &[(&str, &str)] = &[
    ("glob_append", "echo x >> CLAUDE.m?"),
    ("glob_cp", "cp evil AGENTS.m*"),
    ("glob_tee", "echo x | tee .claude/rule?/a.md"),
    ("glob_git_config", "echo y >> .git/confi?"),
    ("glob_rm", "rm CLAUDE.m?"),
    ("glob_bracket", "rm CLAUDE.[m]d"),
];

/// Round 2, item 1b: opaque write targets, opaque nested shells, pipes and here-docs into a shell.
const OPAQUE_CASES: &[(&str, &str)] = &[
    ("opaque_redirect", "echo x > \"$OUT\""),
    ("opaque_sh_c", "sh -c \"$X\""),
    ("pipe_into_sh", "printf 'echo y > CLAUDE.md' | sh"),
    ("pipe_into_bash", "printf 'echo y > CLAUDE.md' | bash"),
    ("heredoc_into_sh", "sh <<EOF\necho y > CLAUDE.md\nEOF"),
    ("heredoc_into_bash", "bash <<'EOF'\necho y > CLAUDE.md\nEOF"),
];

/// Round 2, item 2: a directory landing on a protected container.
const LANDING_CASES: &[(&str, &str)] = &[
    ("tree_copy_into_claude", "mkdir -p s/rules && echo evil > s/rules/a.md && cp -r s/. .claude/"),
    ("tree_copy_existing_s", "cp -r s/. .claude/"),
    ("mv_dir_to_claude", "mv s .claude"),
    ("mv_dir_to_cursor", "mv s .cursor"),
    ("cp_dir_to_fuigo", "cp -r s .fuigo"),
    ("rsync_dir_to_claude", "rsync -a s/ .claude/"),
    ("cp_file_into_claude_dir", "cp a.txt .claude/"),
    ("cp_parents_nested", "cp --parents sub/CLAUDE.md out/"),
    ("cp_parents_rules", "cp --parents rules/a.md .claude/"),
    ("rsync_dir_to_cwd_root", "rsync -a s/ ./"),
];

/// Round 2, item 3: links, both ends, hard and symbolic.
const LINK_CASES: &[(&str, &str)] = &[
    ("ln_hard", "ln CLAUDE.md n.txt"),
    ("ln_hard_then_write", "ln CLAUDE.md n.txt && echo evil >> n.txt"),
    ("ln_symlink_then_write", "ln -s .claude/rules r && echo x > r/a.md"),
    ("ln_symlink_to_container", "ln -s .claude c"),
    ("ln_into_protected_dest", "ln a.txt CLAUDE.md"),
    ("cp_l", "cp -l CLAUDE.md n.txt"),
    ("cp_s", "cp -s CLAUDE.md n.txt"),
    ("cp_long_link", "cp --link CLAUDE.md n.txt"),
];

async fn assert_table_denied(cases: &[(&str, &str)]) {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let tmp = tempfile::tempdir().unwrap();
                let root = dunce::canonicalize(tmp.path()).unwrap();
                prepare(&root);
                let cwd = AbsPathBuf::new(root.clone()).unwrap();
                let influenced = make(&cwd);
                let control = make(&cwd);
                influenced.set_peer_influenced(true);
                for (label, cmd) in cases {
                    let d = decide(&influenced, &root, AccessKind::Bash((*cmd).to_owned()), None).await;
                    assert!(is_guard_denial(&d), "{name}/{label}: must be denied, got {d}");
                    let c = decide(&control, &root, AccessKind::Bash((*cmd).to_owned()), None).await;
                    assert!(!is_guard_denial(&c), "{name}/{label}: control must not see the guard: {c}");
                }
            }
        })
        .await;
}

#[tokio::test]
async fn s6_4_r2_glob_words_are_denied_when_influenced() {
    assert_table_denied(GLOB_CASES).await;
}

#[tokio::test]
async fn s6_4_r2_directory_landings_on_protected_containers_are_denied_when_influenced() {
    assert_table_denied(LANDING_CASES).await;
}

#[tokio::test]
async fn s6_4_r2_opaque_shell_forms_are_denied_when_influenced() {
    assert_table_denied(OPAQUE_CASES).await;
}

#[tokio::test]
async fn s6_4_r2_link_operands_are_denied_when_influenced() {
    assert_table_denied(LINK_CASES).await;
}

#[tokio::test]
async fn s6_4_r2_refusal_text_tells_unanalysable_from_resolved() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let tmp = tempfile::tempdir().unwrap();
                let root = dunce::canonicalize(tmp.path()).unwrap();
                prepare(&root);
                let h = make(&AbsPathBuf::new(root.clone()).unwrap());
                h.set_peer_influenced(true);
                for cmd in ["if then fi (( ;; <<<", "echo x > \"$OUT\""] {
                    let d = decide(&h, &root, AccessKind::Bash(cmd.to_owned()), None).await;
                    assert!(is_guard_denial(&d), "{name}/{cmd}: {d}");
                    assert!(d.contains("could not be analysed"), "{name}/{cmd}: {d}");
                }
                let d = decide(&h, &root, AccessKind::Bash("echo x > CLAUDE.md".into()), None).await;
                assert!(is_guard_denial(&d) && !d.contains("could not be analysed"), "{name}: {d}");
            }
        })
        .await;
}

/// Round 2, item 5: ordinary commands still pass when influenced and equal the control.
#[tokio::test]
async fn s6_4_r2_ordinary_commands_pass_when_influenced() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let tmp = tempfile::tempdir().unwrap();
                let root = dunce::canonicalize(tmp.path()).unwrap();
                prepare(&root);
                let cwd = AbsPathBuf::new(root.clone()).unwrap();
                let influenced = make(&cwd);
                let control = make(&cwd);
                influenced.set_peer_influenced(true);
                for cmd in [
                    "ls",
                    "cat CLAUDE.md",
                    "grep x CLAUDE.md",
                    "git status",
                    "echo hi > notes.txt",
                    "cp a.txt b.txt",
                    "ln -s a.txt b.txt",
                    "ln a.txt h.txt",
                ] {
                    let a = decide(&influenced, &root, AccessKind::Bash(cmd.to_owned()), None).await;
                    let b = decide(&control, &root, AccessKind::Bash(cmd.to_owned()), None).await;
                    assert_eq!(a, b, "{name}/{cmd}");
                    assert!(!is_guard_denial(&a), "{name}/{cmd}: {a}");
                }
            }
        })
        .await;
}

/// `git config --get` is a read: the guard does not deny it (it falls to the ordinary path, same as the control).
#[tokio::test]
async fn s6_4_r2_git_config_get_is_not_a_guard_denial() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let tmp = tempfile::tempdir().unwrap();
                let root = dunce::canonicalize(tmp.path()).unwrap();
                prepare(&root);
                let h = make(&AbsPathBuf::new(root.clone()).unwrap());
                h.set_peer_influenced(true);
                let d = decide(&h, &root, AccessKind::Bash("git config --get user.name".into()), None).await;
                assert!(!is_guard_denial(&d), "{name}: {d}");
            }
        })
        .await;
}

#[tokio::test]
async fn s6_4_shell_table_every_mode_denies_when_influenced_and_is_untouched_otherwise() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let tmp = tempfile::tempdir().unwrap();
                let root = dunce::canonicalize(tmp.path()).unwrap();
                prepare(&root);
                let cwd = AbsPathBuf::new(root.clone()).unwrap();
                let influenced = make(&cwd);
                let control = make(&cwd);
                influenced.set_peer_influenced(true);
                for (label, cmd) in CASES {
                    let d = decide(&influenced, &root, AccessKind::Bash((*cmd).to_owned()), None).await;
                    assert!(is_guard_denial(&d), "{name}/{label}: must be denied, got {d}");
                    let c = decide(&control, &root, AccessKind::Bash((*cmd).to_owned()), None).await;
                    assert!(!is_guard_denial(&c), "{name}/{label}: control must not see the guard: {c}");
                }
            }
        })
        .await;
}

#[tokio::test]
async fn s6_4_ordinary_shell_commands_match_the_control_when_influenced() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let tmp = tempfile::tempdir().unwrap();
                let root = dunce::canonicalize(tmp.path()).unwrap();
                prepare(&root);
                let cwd = AbsPathBuf::new(root.clone()).unwrap();
                let influenced = make(&cwd);
                let control = make(&cwd);
                influenced.set_peer_influenced(true);
                for cmd in ["ls -la", "echo x > out.txt", "cp src.txt copy.txt", "git status", "cat CLAUDE.md"] {
                    let a = decide(&influenced, &root, AccessKind::Bash(cmd.to_owned()), None).await;
                    let b = decide(&control, &root, AccessKind::Bash(cmd.to_owned()), None).await;
                    assert_eq!(a, b, "{name}/{cmd}");
                    assert!(!is_guard_denial(&a), "{name}/{cmd}");
                }
            }
        })
        .await;
}

/// A subagent's handle is a clone sharing the parent's flag (part A); its shell write is denied too.
#[tokio::test]
async fn s6_4_subagent_clone_of_an_influenced_handle_is_denied_a_shell_write() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let tmp = tempfile::tempdir().unwrap();
                let root = dunce::canonicalize(tmp.path()).unwrap();
                prepare(&root);
                let parent = make(&AbsPathBuf::new(root.clone()).unwrap());
                let child = parent.clone();
                parent.set_peer_influenced(true);
                let d = decide(&child, &root, AccessKind::Bash("echo x > CLAUDE.md".into()), None).await;
                assert!(is_guard_denial(&d), "{name}: {d}");
            }
        })
        .await;
}

#[test]
fn s6_2_session_store_is_in_the_protected_set() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let home = dunce::canonicalize(t.path()).unwrap();
    let _env = crate::LockedTestEnv::lock().set("FUIGO_HOME", &home);
    for f in ["sessions/enc/id/transcript.jsonl", "sessions/enc/id/peer_influence.json"] {
        assert!(crate::permission::peer_guard::is_peer_protected_path(&home.join(f)), "{f}");
    }
    assert!(!crate::permission::peer_guard::is_peer_protected_path(&home.join("elsewhere/x.txt")));
    // Through `request()` as well, in every mode.
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(tokio::task::LocalSet::new().run_until(async {
        for (name, make) in modes() {
            let h = make(&AbsPathBuf::new(home.clone()).unwrap());
            h.set_peer_influenced(true);
            let p = home.join("sessions/enc/id/transcript.jsonl").to_string_lossy().into_owned();
            let d = decide(&h, &home, AccessKind::Edit(p), None).await;
            assert!(is_guard_denial(&d), "{name}: {d}");
        }
    }));
}

/// The extended set is scoped to the guard's evaluation: the ordinary floor never sees it.
#[test]
fn s6_4_extended_set_does_not_leak_into_the_ordinary_floor() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    let p = root.join("CLAUDE.md");
    assert!(crate::permission::shell_access::edit_target_protection(&p).is_none());
    assert!(crate::permission::shell_access::with_peer_extended_set(|| crate::permission::shell_access::edit_target_protection(&p).is_some()));
    assert!(crate::permission::shell_access::edit_target_protection(&p).is_none());
}

/// The scope never leaks into the ordinary floor through `request()`: a non-influenced session edits CLAUDE.md as the control.
#[tokio::test]
async fn s6_4_extended_set_does_not_leak_through_request() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let tmp = tempfile::tempdir().unwrap();
                let root = dunce::canonicalize(tmp.path()).unwrap();
                prepare(&root);
                let h = make(&AbsPathBuf::new(root.clone()).unwrap());
                h.set_peer_influenced(true);
                let _ = decide(&h, &root, AccessKind::Bash("echo x > CLAUDE.md".into()), None).await;
                h.set_peer_influenced(false);
                let d = decide(&h, &root, AccessKind::Bash("echo x > CLAUDE.md".into()), None).await;
                assert!(!is_guard_denial(&d), "{name}: {d}");
            }
        })
        .await;
}

/// Round 3, items 1-6: each is DENIED when influenced and is not a guard denial for the control.
const R3_CASES: &[(&str, &str)] = &[
    ("brace_redirect_seq", "echo x > CLAUDE.{m..m}d"),
    ("brace_redirect_git", "echo x > .git/confi{g..g}"),
    ("brace_redirect_list", "echo x > CLAUDE.{md,x}"),
    ("source_file", "source evil.sh"),
    ("dot_file", ". ./evil.sh"),
    ("eval_text", "eval \"$(cat evil.txt)\""),
    ("eval_literal", "eval echo hi"),
    ("rm_dot", "rm -rf ."),
    ("rm_git", "rm -rf .git"),
    ("rm_claude_md", "rm CLAUDE.md"),
    ("rmdir_dot", "rmdir ."),
    ("mv_source_git", "mv .git gone"),
    ("mv_source_dot", "mv . ../elsewhere"),
    ("shred_dot", "shred -u CLAUDE.md"),
    ("truncate_protected", "truncate -s 0 CLAUDE.md"),
    ("truncate_git_config", "truncate -s 0 .git/config"),
    ("xargs_rm", "echo CLAUDE.md | xargs rm"),
    ("xargs_cp", "echo x | xargs cp a.txt"),
    ("xargs_sh", "echo x | xargs sh -c true"),
    ("find_exec_rm", "find . -name x -exec rm {} \\;"),
    ("find_execdir_mv", "find . -execdir mv {} y \\;"),
    ("find_ok_chmod", "find . -ok chmod 600 {} \\;"),
    ("find_delete", "find . -name CLAUDE.md -delete"),
    ("find_exec_sed_i", "find . -exec sed -i s/a/b/ {} +"),
    ("chmod_protected", "chmod 777 CLAUDE.md"),
    ("chmod_r_git", "chmod -R u+w .git/config"),
    ("chown_protected", "chown me CLAUDE.md"),
    ("chattr_protected", "chattr +i CLAUDE.md"),
    ("touch_protected", "touch CLAUDE.md"),
    ("git_remote_add", "git remote add origin https://example.com/r.git"),
    ("git_remote_set_url", "git remote set-url origin https://example.com/r.git"),
    ("git_remote_rm", "git remote rm origin"),
    ("git_submodule_add", "git submodule add https://example.com/r.git sub"),
    ("git_submodule_update", "git submodule update --init"),
    ("git_branch_upstream", "git branch -u origin/main"),
    ("git_branch_set_upstream", "git branch --set-upstream-to=origin/main"),
    ("git_init", "git init"),
    ("git_clone", "git clone https://example.com/r.git"),
    ("git_worktree_add", "git worktree add ../wt"),
    ("git_lfs_install", "git lfs install"),
    ("git_c_sshcommand", "git -c core.sshCommand=evil fetch"),
    ("git_c_fsmonitor", "git -c core.fsmonitor=evil status"),
    ("git_c_editor", "git -c core.editor=evil commit"),
    ("git_c_hookspath", "git -c core.hooksPath=/x status"),
    ("git_exec_path", "git --exec-path=/x status"),
    ("git_c_attached_sshcommand", "git -ccore.sshCommand=evil fetch"),
    ("git_c_attached_fsmonitor", "git -ccore.fsmonitor=evil status"),
    ("git_c_attached_editor", "git -ccore.editor=evil commit"),
    ("git_config_env_attached", "git --config-env=core.sshCommand=EVIL fetch"),
    ("git_config_env_split", "git --config-env core.sshCommand=EVIL fetch"),
    ("git_exec_path_abbrev", "git --exec-p=/x status"),
    ("git_branch_upstream_attached", "git branch -uorigin/main"),
    ("git_branch_set_upstream_abbrev", "git branch --set-up=origin/main"),
    ("git_branch_unset_abbrev_short", "git branch --u"),
    ("git_branch_unset_abbrev", "git branch --unset"),
    ("git_branch_edit_abbrev_short", "git branch --e"),
    ("git_branch_edit_abbrev", "git branch --edit"),
];

/// Round 3, item 8: glob and brace words use the "could not be analysed" text.
const R3_UNANALYSED: &[&str] = &["echo x >> CLAUDE.m?", "rm CLAUDE.[m]d", "echo x > CLAUDE.{md,x}", "echo x > CLAUDE.{m..m}d"];

/// Round 3 controls (items 1-7): these PASS the guard when influenced, same as the control.
const R3_PASS: &[&str] = &[
    "find . -name x",
    "find . -name x -exec grep y {} \\;",
    "echo CLAUDE.md | xargs grep x",
    "git remote -v",
    "git branch",
    "git config --get user.name",
    "git status",
    "git log",
    "git diff",
    "rm notes.txt",
    "rm -rf build",
    "mv a.txt b.txt",
    "touch notes.txt",
    "chmod 644 a.txt",
    "echo {a,b}",
    "git branch -vv",
    "git branch -a",
    "git branch --all",
    "git branch --list",
    "git branch --show-current",
    "git branch --contains HEAD",
    "git -c color.ui=always status",
    "git -ccolor.ui=always status",
    "git checkout main",
    "git switch main",
    "git pull",
    "cargo build",
    "npm test",
    "python script.py",
    "make",
];

#[tokio::test]
async fn s6_4_r3_command_forms_are_denied_when_influenced() {
    assert_table_denied(R3_CASES).await;
}

#[tokio::test]
async fn s6_4_r3_glob_and_brace_words_use_the_unanalysable_text() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let tmp = tempfile::tempdir().unwrap();
                let root = dunce::canonicalize(tmp.path()).unwrap();
                prepare(&root);
                let h = make(&AbsPathBuf::new(root.clone()).unwrap());
                h.set_peer_influenced(true);
                for cmd in R3_UNANALYSED {
                    let d = decide(&h, &root, AccessKind::Bash((*cmd).to_owned()), None).await;
                    assert!(is_guard_denial(&d) && d.contains("could not be analysed"), "{name}/{cmd}: {d}");
                }
            }
        })
        .await;
}

#[tokio::test]
async fn s6_4_r3_controls_pass_when_influenced() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let tmp = tempfile::tempdir().unwrap();
                let root = dunce::canonicalize(tmp.path()).unwrap();
                prepare(&root);
                let cwd = AbsPathBuf::new(root.clone()).unwrap();
                let influenced = make(&cwd);
                let control = make(&cwd);
                influenced.set_peer_influenced(true);
                for cmd in R3_PASS {
                    let a = decide(&influenced, &root, AccessKind::Bash((*cmd).to_owned()), None).await;
                    let b = decide(&control, &root, AccessKind::Bash((*cmd).to_owned()), None).await;
                    assert_eq!(a, b, "{name}/{cmd}");
                    assert!(!is_guard_denial(&a), "{name}/{cmd}: {a}");
                }
            }
        })
        .await;
}
