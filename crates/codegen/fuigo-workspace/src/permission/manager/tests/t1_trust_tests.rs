//! u35 t1 (design d2 §6): folder trust in the local permission manager. T1 route matrix, T4 final check, T5 the
//! directories that count (the ones a command starts in, u35 t3), T10 revocation, the project-tier policy (§3.4) and D1 (sandbox auto-allow).

use super::*;
use crate::folder_trust::TestFolderTrust;
use crate::permission::auto_mode::ClassifierVerdict;
use crate::permission::rules::parse_permission_rule;
use crate::permission::types::{PermissionConfig, PromptPolicy, RuleAction};

const CMDS: [&str; 8] =
    ["ls", "git status", "true", "cargo test", "cd sub && yarn ls", "bash -c 'x'", "bash -c 'echo cd'", "sleep 1; ls"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Ask,
    AutoAllow,
    AutoBlock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Grant {
    None,
    Exact,
    FullPrefix,
    PartialPrefix,
    AllowAll,
    UserRule,
    CatchAll,
    Yolo,
    PromptAllow,
    PromptDeny,
}

const MODES: [Mode; 3] = [Mode::Ask, Mode::AutoAllow, Mode::AutoBlock];
const GRANTS: [Grant; 10] = [
    Grant::None,
    Grant::Exact,
    Grant::FullPrefix,
    Grant::PartialPrefix,
    Grant::AllowAll,
    Grant::UserRule,
    Grant::CatchAll,
    Grant::Yolo,
    Grant::PromptAllow,
    Grant::PromptDeny,
];

/// What happened to one command: `R` ran unasked, `P` the user was asked, `D` refused unasked.
fn outcome(resolution: &PermissionResolution) -> char {
    let prompted = resolution.event.as_ref().is_some_and(|e| e.user_prompted);
    match (&resolution.decision, prompted) {
        (_, true) => 'P',
        (Decision::Allow, false) => 'R',
        _ => 'D',
    }
}

fn repo() -> (tempfile::TempDir, AbsPathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    git2::Repository::init(tmp.path()).unwrap();
    std::fs::create_dir_all(tmp.path().join("sub")).unwrap();
    let cwd = AbsPathBuf::new(dunce::canonicalize(tmp.path()).unwrap()).unwrap();
    (tmp, cwd)
}

fn rule(text: &str) -> crate::permission::types::PermissionRule {
    parse_permission_rule(text, RuleAction::Allow).unwrap()
}

/// One manager per (mode, grant) over every command; the user answers every prompt with allow.
async fn row(mode: Mode, grant: Grant) -> (String, usize) {
    let (_tmp, cwd) = repo();
    let mut state = PermissionState::default();
    match grant {
        Grant::Exact => state.allowed_bash_commands.extend(CMDS.iter().map(|c| (*c).to_owned())),
        Grant::FullPrefix => state.allowed_bash_commands.extend(
            ["ls", "git status", "true", "cargo test", "yarn ls", "bash -c", "sleep"].map(str::to_owned),
        ),
        Grant::PartialPrefix => {
            state.allowed_bash_commands.insert("sleep".to_owned());
        }
        Grant::AllowAll => state.allow_bash_execute = true,
        _ => {}
    }
    persist_state(&cwd, &state, None).await;
    let config = match grant {
        Grant::UserRule => Some(PermissionConfig::new(CMDS.iter().map(|c| rule(&format!("Bash({c})"))).collect())),
        Grant::CatchAll => Some(PermissionConfig::new(vec![rule("Bash")])),
        Grant::PromptAllow => Some(PermissionConfig { prompt_policy: PromptPolicy::Allow, ..PermissionConfig::new(vec![]) }),
        Grant::PromptDeny => Some(PermissionConfig { prompt_policy: PromptPolicy::Deny, ..PermissionConfig::new(vec![]) }),
        _ => None,
    };
    let (mgr, _events) =
        manager_with_recording_client_remember(&cwd, config, SelectingClient::new(true), ClientType::Generic, true);
    if grant == Grant::Yolo {
        mgr.set_yolo_mode(true);
    }
    let seen = match mode {
        Mode::Ask => None,
        Mode::AutoAllow | Mode::AutoBlock => {
            mgr.set_auto_mode(true);
            let verdict = if mode == Mode::AutoAllow { ClassifierVerdict::Allow } else { ClassifierVerdict::Block };
            let (clf, seen) = capturing_classifier(verdict);
            mgr.set_classifier(Some(clf));
            Some(seen)
        }
    };
    let mut out = String::new();
    for cmd in CMDS {
        let resolution = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            mgr.request(PermissionRequest::new(AccessKind::Bash(cmd.to_owned()), tool_call())),
        )
        .await
        .expect("permission request must resolve");
        out.push(outcome(&resolution));
    }
    (out, seen.map_or(0, |seen| seen.lock().unwrap().len()))
}

/// u35 t1 T1: the route matrix in a trusted folder is r14's (minus the g12–g14 vetoes, none of which fire in a clean
/// repository): the golden table below was recorded on the r14 base (fec3e0954) with this same matrix.
const TRUSTED_GOLDEN: &str = include_str!("t1_trusted_golden.txt");

fn table_line(mode: Mode, grant: Grant, row: &str) -> String {
    format!("{mode:?}/{grant:?}: {row}")
}

/// u35 t1 T1: the route matrix outside a trusted folder (design d2 §3.5): only the user's grant or override runs a
/// command, dontAsk refuses, everything else asks; the model is never asked.
const UNTRUSTED_EXPECTED: &str = include_str!("t1_untrusted_expected.txt");

#[tokio::test]
async fn t1_route_matrix_trusted_rows_match_r14_and_untrusted_rows_need_a_grant() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut trusted_table = Vec::new();
            let mut untrusted_table = Vec::new();
            for mode in MODES {
                for grant in GRANTS {
                    let (trusted, _) = row(mode, grant).await;
                    let (untrusted, classifier_calls) = {
                        let _untrusted = TestFolderTrust::untrusted();
                        row(mode, grant).await
                    };
                    trusted_table.push(table_line(mode, grant, &trusted));
                    untrusted_table.push(table_line(mode, grant, &untrusted));
                    if matches!(grant, Grant::None | Grant::PartialPrefix) {
                        assert_eq!(classifier_calls, 0, "{mode:?}/{grant:?}: the classifier is never asked");
                    }
                }
            }
            let trusted = trusted_table.join("\n");
            let untrusted = untrusted_table.join("\n");
            println!("T1 trusted table:\n{trusted}\nT1 untrusted table:\n{untrusted}");
            assert_eq!(trusted.trim(), TRUSTED_GOLDEN.trim(), "trusted rows must equal the r14 golden table");
            assert_eq!(untrusted.trim(), UNTRUSTED_EXPECTED.trim(), "untrusted rows");
        })
        .await;
}

/// u35 t1 T1: a prefix grant in a trusted repository whose configuration uses `includeIf` runs as on r14.
#[tokio::test]
async fn t1_trusted_prefix_grant_with_include_if_config_runs_as_r14() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = repo();
            let config = cwd.as_path().join(".git/config");
            let mut text = std::fs::read_to_string(&config).unwrap();
            text.push_str("[includeIf \"gitdir:/nowhere/\"]\n\tpath = /nowhere/x\n");
            std::fs::write(&config, text).unwrap();
            let mut state = PermissionState::default();
            state.allowed_bash_commands.insert("git status".to_owned());
            persist_state(&cwd, &state, None).await;
            let (mgr, _events) =
                manager_with_recording_client_remember(&cwd, None, SelectingClient::new(true), ClientType::Generic, true);
            let resolution = mgr.request(PermissionRequest::new(AccessKind::Bash("git status".into()), tool_call())).await;
            assert_eq!(outcome(&resolution), 'R', "{:?}", resolution.event);
            // D3: a word naming git in a command that is not git (g14's hidden-git veto) no longer stops the model's
            // allow in a trusted folder.
            mgr.set_auto_mode(true);
            let (clf, _seen) = capturing_classifier(ClassifierVerdict::Allow);
            mgr.set_classifier(Some(clf));
            for cmd in ["which git", "type git", "echo git"] {
                let resolution = mgr.request(PermissionRequest::new(AccessKind::Bash(cmd.into()), tool_call())).await;
                assert_eq!(outcome(&resolution), 'R', "{cmd}: {:?}", resolution.event);
            }
        })
        .await;
}

/// u35 t1 T4: the final check refuses a shell command approved without a grant in a folder that is not trusted, and
/// nothing else.
#[test]
fn t4_final_check_refuses_only_ungranted_allows_outside_trusted_folders() {
    let refused = |d: Option<Decision>| matches!(d, Some(Decision::Reject(m)) if m.contains("untrusted folder"));
    assert!(refused(final_shell_check(true, &Decision::Allow, Some(true))), "an injected SAFE_COMMAND allow");
    assert!(refused(final_shell_check(true, &Decision::Allow, None)), "an allow that does not say how");
    assert!(final_shell_check(true, &Decision::Allow, Some(false)).is_none(), "a grant runs");
    assert!(final_shell_check(false, &Decision::Allow, Some(true)).is_none(), "a trusted folder");
    assert!(final_shell_check(true, &Decision::Ask, Some(true)).is_none(), "only an allow is checked");
}

/// u35 t1 T5 (narrowed in u35 t3): the directories a command is judged in are the ones it starts in: trusted R,
/// untrusted U.
#[tokio::test]
async fn t5_the_folders_a_command_starts_in_count() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_r_tmp, r) = repo();
            let (_u_tmp, u) = repo();
            let _trust = TestFolderTrust::only(&[r.as_path()]);
            let mgr = manager_with_recording_client_remember(&r, None, SelectingClient::new(true), ClientType::Generic, true).0;
            // The tool's own working directory (OpenCode `workdir`) is a folder the command starts in.
            let mut request = PermissionRequest::new(AccessKind::Bash("ls".into()), tool_call());
            request.exec_cwd = Some(u.as_path().to_path_buf());
            assert_eq!(outcome(&mgr.request(request).await), 'P', "workdir=U");
            assert!(!runner_trust_judge("ls", &[r.as_path(), u.as_path()]), "the runner judges its workdir too");
        })
        .await;
}

/// u35 t3 (R2): a literal folder change from a trusted start folder is judged by the start folder: the actor routes
/// it as in a fully trusted world (r14), and the runner's check agrees. Folder trust adds no prompt for it.
#[tokio::test]
async fn t3_a_literal_dir_change_from_a_trusted_start_folder_is_judged_by_the_start_folder() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_r_tmp, r) = repo();
            let (_u_tmp, u) = repo();
            #[cfg(unix)]
            std::os::unix::fs::symlink(u.as_path(), r.as_path().join("l")).unwrap();
            let _trust = TestFolderTrust::only(&[r.as_path()]);
            let mgr = manager_with_recording_client_remember(&r, None, SelectingClient::new(true), ClientType::Generic, true).0;
            let u_str = u.as_path().display().to_string();
            let mut cmds = vec![
                format!("cd {u_str} && ls"),
                format!("git -C {u_str} status"),
                format!("env -C {u_str} ls"),
                format!("make -C {u_str} all"),
                format!("GIT_DIR={u_str}/.git git log"),
                format!("echo GIT_DIR={u_str}/.git"),
                "cd sub && ls".to_owned(),
                "cd \"$X\" && ls".to_owned(),
                "bash -c 'ls'".to_owned(),
                "ls".to_owned(),
            ];
            if cfg!(unix) {
                cmds.push("cd l && ls".to_owned());
                cmds.push("cd l/.. && ls".to_owned());
            }
            for cmd in &cmds {
                let resolution = mgr.request(PermissionRequest::new(AccessKind::Bash(cmd.clone()), tool_call())).await;
                let trusted_r14 = {
                    let _all = TestFolderTrust::set(crate::folder_trust::CommandTrust::Trusted);
                    let m = manager_with_recording_client_remember(&r, None, SelectingClient::new(true), ClientType::Generic, true).0;
                    outcome(&m.request(PermissionRequest::new(AccessKind::Bash(cmd.clone()), tool_call())).await)
                };
                assert_eq!(outcome(&resolution), trusted_r14, "{cmd}: {:?}", resolution.event);
                assert!(runner_trust_judge(cmd, &[r.as_path()]), "{cmd}: the runner agrees");
            }
        })
        .await;
}

/// u35 t3: an untrusted start folder still asks, whatever folder the command names (a trusted one included).
#[tokio::test]
async fn t3_an_untrusted_start_folder_still_asks() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_r_tmp, r) = repo();
            let (_u_tmp, u) = repo();
            let _trust = TestFolderTrust::only(&[r.as_path()]);
            let mgr = manager_with_recording_client_remember(&u, None, SelectingClient::new(true), ClientType::Generic, true).0;
            let r_str = r.as_path().display().to_string();
            for cmd in ["ls".to_owned(), format!("cd {r_str} && ls"), format!("git -C {r_str} status")] {
                let resolution = mgr.request(PermissionRequest::new(AccessKind::Bash(cmd.clone()), tool_call())).await;
                assert_eq!(outcome(&resolution), 'P', "{cmd}: {:?}", resolution.event);
                assert!(!runner_trust_judge(&cmd, &[u.as_path()]), "{cmd}: the runner refuses an ungranted allow");
            }
        })
        .await;
}

/// u35 t1 (design d2 §3.4): a command whose folder is not trusted is judged without the project tier: the session
/// folder's own allow rule covers `make` there and nowhere else, and it drops when the folder is revoked (T10).
#[tokio::test]
async fn t10_project_rules_apply_only_in_the_trusted_folder_and_drop_on_revoke() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_r_tmp, r) = repo();
            let (_u_tmp, u) = repo();
            std::fs::create_dir_all(r.as_path().join(".fuigo")).unwrap();
            std::fs::write(r.as_path().join(".fuigo/config.toml"), "[permission]\nallow = [\"Bash(make *)\"]\n").unwrap();
            let trust = TestFolderTrust::only(&[r.as_path()]);
            let mgr = manager_with_recording_client_remember(&r, None, SelectingClient::new(true), ClientType::Generic, true).0;
            mgr.set_session_policy_inputs(crate::permission::resolution::SessionPolicyInputs {
                cwd: r.as_path().to_path_buf(),
                cli_rules: Vec::new(),
                mode_hint: None,
                yolo_pin: None,
                session_policy: None,
            });
            let ask = |cmd: String| PermissionRequest::new(AccessKind::Bash(cmd), tool_call());
            assert_eq!(outcome(&mgr.request(ask("make all".into())).await), 'R', "the project rule in its folder");
            // The same rule in an untrusted folder's own config is not used there.
            std::fs::create_dir_all(u.as_path().join(".fuigo")).unwrap();
            std::fs::write(u.as_path().join(".fuigo/config.toml"), "[permission]\nallow = [\"Bash(make *)\"]\n").unwrap();
            let in_u = manager_with_recording_client_remember(&u, None, SelectingClient::new(true), ClientType::Generic, true).0;
            in_u.set_session_policy_inputs(crate::permission::resolution::SessionPolicyInputs {
                cwd: u.as_path().to_path_buf(),
                cli_rules: Vec::new(),
                mode_hint: None,
                yolo_pin: None,
                session_policy: None,
            });
            let resolution = in_u.request(ask("make all".into())).await;
            assert_eq!(outcome(&resolution), 'P', "make in U: not a trusted folder: {:?}", resolution.event);
            // T10: the folder is revoked: the next command asks (and the policy is rebuilt on the trust change).
            drop(trust);
            let _none = TestFolderTrust::only(&[]);
            crate::folder_trust::note_trust_changed();
            assert_eq!(outcome(&mgr.request(ask("make all".into())).await), 'P', "after /untrust the next command asks");
        })
        .await;
}

/// u35 t1 D1: sandbox auto-allow is not consent outside a trusted folder.
#[test]
fn d1_sandbox_auto_allow_never_runs_a_command_outside_a_trusted_folder() {
    let mut evaluation = evaluate_bash("ls", &PermissionState::default(), true);
    assert!(sandbox_may_auto_allow_bash(Some(&evaluation), true));
    evaluation.untrusted_folder = true;
    assert!(!sandbox_may_auto_allow_bash(Some(&evaluation), true));
    assert!(no_grant_approval_switched_off(&evaluation));
    assert!(shell_switches_off_auto(Some(&evaluation)));
    assert!(classifier_allow_needs_user(Some(&evaluation)));
    evaluation.exact_grant = true;
    assert!(!no_grant_approval_switched_off(&evaluation), "a grant still covers it");
}

/// u35 t1 (design d2 §5.4): dontAsk refuses a command outside a trusted folder with the folder-trust text.
#[tokio::test]
async fn t9_dont_ask_refusal_names_the_trusted_folders_setting() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = repo();
            let _untrusted = TestFolderTrust::untrusted();
            let config = PermissionConfig { prompt_policy: PromptPolicy::Deny, ..PermissionConfig::new(vec![]) };
            let mgr = manager_with_recording_client_remember(&cwd, Some(config), SelectingClient::new(true), ClientType::Generic, true).0;
            let resolution = mgr.request(PermissionRequest::new(AccessKind::Bash("ls".into()), tool_call())).await;
            let Decision::PolicyDeny(text) = &resolution.decision else { panic!("{:?}", resolution.decision) };
            assert!(text.contains("[folder_trust] trusted_folders") && text.contains("fuigo --trust"), "{text}");
        })
        .await;
}

/// u35 t1 T11: Fuigo's own trust inputs are protected edits, and `fuigo --trust` asks even under allow-all.
#[tokio::test]
async fn t11_trust_inputs_are_protected_and_fuigo_trust_asks_under_allow_all() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = repo();
            let state = PermissionState { allow_bash_execute: true, ..PermissionState::default() };
            persist_state(&cwd, &state, None).await;
            let mgr = manager_with_recording_client_remember(&cwd, None, SelectingClient::new(true), ClientType::Generic, true).0;
            for cmd in ["fuigo --trust", "fuigo --trust-folder .", "/usr/local/bin/fuigo --trust"] {
                let resolution = mgr.request(PermissionRequest::new(AccessKind::Bash(cmd.into()), tool_call())).await;
                assert_eq!(outcome(&resolution), 'P', "{cmd}: {:?}", resolution.event);
            }
            assert_eq!(outcome(&mgr.request(PermissionRequest::new(AccessKind::Bash("fuigo --version".into()), tool_call())).await), 'R');
        })
        .await;
    let home = std::path::Path::new("/home/u/.fuigo");
    for name in [fuigo_config::TRUSTED_FOLDERS_FILENAME, "config.toml", "worktrees.db", "worktrees.h-box.db-wal"] {
        assert!(crate::permission::shell_access::edit_target_protection(&home.join(name)).is_some(), "{name}");
    }
}

/// u35 t1 T13: each call is judged on its own: in one batch outside a trusted folder, the exact-granted call runs and
/// the next, ungranted one asks.
#[tokio::test]
async fn t13_each_call_in_a_batch_needs_its_own_grant() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = repo();
            let _untrusted = TestFolderTrust::untrusted();
            let mut state = PermissionState::default();
            state.allowed_bash_commands.insert("ls".to_owned());
            persist_state(&cwd, &state, None).await;
            let mgr = manager_with_recording_client_remember(&cwd, None, SelectingClient::new(true), ClientType::Generic, true).0;
            let first = mgr.request(PermissionRequest::new(AccessKind::Bash("ls".into()), tool_call()));
            let second = mgr.request(PermissionRequest::new(AccessKind::Bash("git status".into()), tool_call()));
            let (first, second) = tokio::join!(first, second);
            assert_eq!(outcome(&first), 'R', "the granted call: {:?}", first.event);
            assert_eq!(outcome(&second), 'P', "the ungranted call: {:?}", second.event);
        })
        .await;
}

/// u35 t2: a release-like trust world for a test of the real decision: own process, a fresh absolute `FUIGO_HOME`,
/// `FUIGO_TEST_VERSION` set (the gate is live) and the switch unset. `None` in the parent of the re-run.
fn real_trust_world() -> Option<(tempfile::TempDir, Vec<crate::TestEnvGuard>, std::sync::MutexGuard<'static, ()>)> {
    if fuigo_test_support::env::rerun_in_own_process() {
        return None;
    }
    let lock = crate::ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let guards = vec![
        crate::TestEnvGuard::set("FUIGO_HOME", home.path()),
        crate::TestEnvGuard::set(fuigo_version::TEST_VERSION_ENV, std::path::Path::new("0.0.0-sim")),
        crate::TestEnvGuard::unset("FUIGO_FOLDER_TRUST"),
    ];
    Some((home, guards, lock))
}

/// u35 t2 (Fable H1, Astra 2): in a linked worktree and a `fuigo -w` managed worktree of a granted repository, the
/// actor routes a command as in the trusted repository itself (no new prompt).
// The env lock serializes this process-global environment for the whole test, awaits included.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn t2_worktrees_of_a_granted_repository_route_commands_as_trusted() {
    let Some((home, _guards, _lock)) = real_trust_world() else { return };
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let _real = TestFolderTrust::real();
            let (_dir, main, linked) = crate::folder_trust::tests::main_with_outside_worktree();
            assert!(crate::folder_trust::grant_folder_trust(&main).dismisses_gate());
            let source = tempfile::tempdir().unwrap();
            git2::Repository::init(source.path()).unwrap();
            let source = dunce::canonicalize(source.path()).unwrap();
            let fuigo_home = dunce::canonicalize(home.path()).unwrap();
            let managed = fuigo_home.join("worktrees").join("repo").join("wt");
            std::fs::create_dir_all(&managed).unwrap();
            git2::Repository::init(&managed).unwrap();
            crate::folder_trust::tests::register_managed_worktree(&fuigo_home, &managed, &source);
            assert!(crate::folder_trust::grant_folder_trust(&source).dismisses_gate());
            for wt in [linked, managed] {
                let cwd = AbsPathBuf::new(wt.clone()).unwrap();
                let mgr = manager_with_recording_client_remember(&cwd, None, SelectingClient::new(true), ClientType::Generic, true).0;
                let resolution = mgr.request(PermissionRequest::new(AccessKind::Bash("ls".into()), tool_call())).await;
                assert_eq!(outcome(&resolution), 'R', "{}: {:?}", wt.display(), resolution.event);
            }
        })
        .await;
}

/// u35 t2 (Fable L1, design d2 §3.5): YOLO runs every command outside a trusted folder, whatever mode was on before
/// it. (Auto and YOLO are exclusive: the T1 `Auto*/Yolo` rows switch Auto on after YOLO, which leaves YOLO, so those
/// rows are Auto with no grant.)
#[tokio::test]
async fn t2_yolo_runs_outside_a_trusted_folder_after_auto() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = repo();
            let _untrusted = TestFolderTrust::untrusted();
            let mgr = manager_with_recording_client_remember(&cwd, None, SelectingClient::new(true), ClientType::Generic, true).0;
            mgr.set_auto_mode(true);
            let (clf, _seen) = capturing_classifier(ClassifierVerdict::Block);
            mgr.set_classifier(Some(clf));
            mgr.set_yolo_mode(true);
            let mut out = String::new();
            for cmd in CMDS {
                out.push(outcome(&mgr.request(PermissionRequest::new(AccessKind::Bash(cmd.to_owned()), tool_call())).await));
            }
            assert_eq!(out, "RRRRRRRR");
        })
        .await;
}
