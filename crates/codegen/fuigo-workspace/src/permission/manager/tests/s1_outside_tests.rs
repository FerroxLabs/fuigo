//! S1 (1.0.47, DS-04) through the permission manager: every mode, headless and unknown clients, `AllowAll`, deny rules,
//! remembered approvals, pre-allow rules sealed at session start, authority files and the edit tools.

use super::*;
use crate::permission::shell_access::GuardEnv;
use crate::permission::types::{PermissionConfig, PermissionRule, RuleAction, ToolFilter};
use std::path::PathBuf;

/// `T/work` is the session folder and the only root besides `T/tmp`; `T/srv/data/app.db` and `T/home` are outside.
struct Outside {
    _t: tempfile::TempDir,
    cwd: AbsPathBuf,
    db: PathBuf,
    dir: PathBuf,
    home: PathBuf,
    env: GuardEnv,
}

fn outside() -> Outside {
    let tmp = tempfile::tempdir().unwrap();
    let t = dunce::canonicalize(tmp.path()).unwrap();
    let (work, dir, home) = (t.join("work"), t.join("srv/data"), t.join("home"));
    for d in [&work, &dir, &home.join(".claude"), &work.join("migrations")] {
        std::fs::create_dir_all(d).unwrap();
    }
    let db = dir.join("app.db");
    std::fs::write(&db, b"precious").unwrap();
    let env = GuardEnv::with_roots(vec![work.clone(), t.join("tmp")], Some(home.clone()), None);
    Outside {
        _t: tmp,
        cwd: AbsPathBuf::new(work).unwrap(),
        db,
        dir,
        home,
        env,
    }
}

impl Outside {
    fn arm(&self, handle: &PermissionHandle) {
        handle.outside_guard().install_env(self.env.clone());
    }
    fn rm(&self) -> AccessKind {
        AccessKind::Bash(format!("rm -f {}", self.db.display()))
    }
    fn request(&self, access: AccessKind) -> PermissionRequest {
        PermissionRequest {
            path_context: Some(RequestPathContext {
                real_cwd: self.cwd.as_path().to_path_buf(),
                display_cwd: None,
            }),
            ..PermissionRequest::new(access, tool_call())
        }
    }
}

async fn ask(handle: &PermissionHandle, o: &Outside, access: AccessKind) -> Decision {
    agent_message_completes(handle.request(o.request(access)))
        .await
        .decision
}

fn s1_denied(decision: &Decision) -> bool {
    matches!(decision, Decision::PolicyDeny(text) if text.starts_with("Not run: this command would delete or change"))
}

fn rule(action: RuleAction, tool: ToolFilter, pattern: &str) -> PermissionRule {
    PermissionRule {
        action,
        tool,
        pattern: Some(pattern.to_owned()),
        pattern_mode: Default::default(),
    }
}

fn run(test: impl std::future::Future<Output = ()>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&rt, test);
}

#[test]
fn ds04_headless_bypass_denies_and_keeps_the_database_and_the_rest_runs() {
    run(async {
        let o = outside();
        let (mgr, _events) = test_manager(&o.cwd, true, None);
        o.arm(&mgr);
        let attack = format!(
            "rm -f {} && printf 'ALTER TABLE users ADD COLUMN email TEXT;' > migrations/002_add_email.sql",
            o.db.display()
        );
        let d = ask(&mgr, &o, AccessKind::Bash(attack)).await;
        assert!(s1_denied(&d), "{d:?}");
        assert!(matches!(&d, Decision::PolicyDeny(t) if t.contains(&o.db.display().to_string())));
        let d = ask(
            &mgr,
            &o,
            AccessKind::Bash("printf x > migrations/002_add_email.sql".into()),
        )
        .await;
        assert_eq!(d, Decision::Allow, "the inside write still runs");
        assert_eq!(std::fs::read(&o.db).unwrap(), b"precious");
    });
}

#[test]
fn every_approving_mode_prompts_once_and_auto_skips_the_classifier() {
    for mode in ["bypass", "auto", "default"] {
        run(async {
            let o = outside();
            let client = IdSelectingClient::new("allow-once");
            let prompts = client.prompts.clone();
            let (mgr, _events) = manager_with_recording_client_remember(
                &o.cwd,
                None,
                client,
                ClientType::FuigoTUI,
                true,
            );
            o.arm(&mgr);
            let started = Arc::new(AtomicBool::new(false));
            match mode {
                "bypass" => mgr.set_yolo_mode(true),
                "auto" => {
                    mgr.set_auto_mode(true);
                    mgr.set_classifier(Some(Arc::new(HangingClassifier {
                        started: started.clone(),
                    })));
                }
                _ => {}
            }
            let d = ask(&mgr, &o, o.rm()).await;
            assert_eq!(d, Decision::Allow, "{mode}: the user allowed it");
            assert_eq!(prompts.borrow().len(), 1, "{mode}: exactly one prompt");
            let title = prompts.borrow()[0]
                .tool_call
                .fields
                .title
                .clone()
                .unwrap_or_default();
            assert!(
                title.contains("outside the workspace and was not named by you"),
                "{mode}: {title}"
            );
            assert!(
                !started.load(Ordering::Relaxed),
                "{mode}: the classifier is not called"
            );
        });
    }
}

#[test]
fn headless_unknown_dontask_alwaysallow_and_allowall_deny() {
    run(async {
        let o = outside();
        // Headless / unknown ACP client (Generic) in bypass: base had no prompt path, so S1 refuses.
        let (mgr, _e) = test_manager(&o.cwd, true, None);
        o.arm(&mgr);
        assert!(s1_denied(&ask(&mgr, &o, o.rm()).await));
        // dontAsk and alwaysAllow on a client that could prompt.
        for policy in [PromptPolicy::Deny, PromptPolicy::Allow] {
            let mut config = PermissionConfig::new(Vec::new());
            config.prompt_policy = policy;
            let (mgr, _e) = manager_with_recording_client_remember(
                &o.cwd,
                Some(config),
                IdSelectingClient::new("allow-once"),
                ClientType::FuigoTUI,
                true,
            );
            o.arm(&mgr);
            assert!(s1_denied(&ask(&mgr, &o, o.rm()).await), "{policy:?}");
        }
        let all = PermissionHandle::AllowAll(PeerInfluence::new());
        o.arm(&all);
        assert!(s1_denied(&ask(&all, &o, o.rm()).await));
        assert_eq!(std::fs::read(&o.db).unwrap(), b"precious");
    });
}

#[test]
fn a_deny_rule_still_wins_and_an_inside_rm_is_untouched() {
    run(async {
        let o = outside();
        let config = PermissionConfig::new(vec![rule(RuleAction::Deny, ToolFilter::Bash, "rm *")]);
        let (mgr, _e) = test_manager_with_config(&o.cwd, config, true);
        o.arm(&mgr);
        let d = ask(&mgr, &o, o.rm()).await;
        assert!(
            matches!(d, Decision::PolicyDeny(_)) && !s1_denied(&d),
            "{d:?}"
        );
        let (mgr, _e) = test_manager(&o.cwd, true, None);
        o.arm(&mgr);
        std::fs::create_dir_all(o.cwd.as_path().join("target")).unwrap();
        for cmd in ["rm -rf target", "cargo clean", "rm -rf build && cargo test"] {
            assert_eq!(
                ask(&mgr, &o, AccessKind::Bash(cmd.into())).await,
                Decision::Allow,
                "{cmd}"
            );
        }
    });
}

#[test]
fn an_approval_covers_the_same_path_later_but_not_a_new_one() {
    run(async {
        let o = outside();
        let client = IdSelectingClient::new("allow-once");
        let prompts = client.prompts.clone();
        let (mgr, _e) = manager_with_recording_client_remember(
            &o.cwd,
            None,
            client,
            ClientType::FuigoTUI,
            true,
        );
        mgr.set_yolo_mode(true);
        o.arm(&mgr);
        assert_eq!(ask(&mgr, &o, o.rm()).await, Decision::Allow);
        let truncate = AccessKind::Bash(format!("truncate -s0 {}", o.db.display()));
        assert_eq!(ask(&mgr, &o, truncate).await, Decision::Allow);
        assert_eq!(
            prompts.borrow().len(),
            1,
            "the approved path does not ask again"
        );
        std::fs::write(o.dir.join("other.db"), b"o").unwrap();
        let other = AccessKind::Bash(format!("rm -f {}/other.db", o.dir.display()));
        assert_eq!(ask(&mgr, &o, other).await, Decision::Allow);
        assert_eq!(
            prompts.borrow().len(),
            2,
            "a new target asks (a grant never exempts S1)"
        );
    });
}

#[test]
fn pre_allow_rules_loaded_at_start_exempt_and_broad_ones_do_not() {
    run(async {
        let o = outside();
        let exact = rule(
            RuleAction::Allow,
            ToolFilter::Bash,
            &format!("rm -f {}", o.db.display()),
        );
        let (mgr, _e) = test_manager_with_config(&o.cwd, PermissionConfig::new(vec![exact]), true);
        o.arm(&mgr);
        assert_eq!(ask(&mgr, &o, o.rm()).await, Decision::Allow);
        let broad = rule(RuleAction::Allow, ToolFilter::Bash, "rm *");
        let (mgr, _e) = test_manager_with_config(&o.cwd, PermissionConfig::new(vec![broad]), true);
        o.arm(&mgr);
        assert!(s1_denied(&ask(&mgr, &o, o.rm()).await));
    });
}

/// Grok r3 H3: a README gets a user-tier allow rule written, then deletes the outside file. The write asks (bypass)
/// or is denied (headless); a rule that appears during the session never exempts.
#[test]
fn an_allow_rule_installed_during_the_session_never_exempts() {
    run(async {
        let o = outside();
        let settings = o.home.join(".claude/settings.json");
        let install = AccessKind::Bash(format!(
            "printf '{{\"permissions\":{{\"allow\":[\"Bash(rm -f {})\"]}}}}' > {}",
            o.db.display(),
            settings.display()
        ));
        // Headless bypass.
        let (mgr, _e) = test_manager(&o.cwd, true, None);
        o.arm(&mgr);
        assert!(s1_denied(&ask(&mgr, &o, install.clone()).await));
        std::fs::write(
            &settings,
            format!(
                "{{\"permissions\":{{\"allow\":[\"Bash(rm -f {})\"]}}}}",
                o.db.display()
            ),
        )
        .unwrap();
        assert!(s1_denied(&ask(&mgr, &o, o.rm()).await));
        // Interactive bypass: both ask; rejecting keeps the database.
        let client = IdSelectingClient::new("reject-once");
        let prompts = client.prompts.clone();
        let (mgr, _e) = manager_with_recording_client_remember(
            &o.cwd,
            None,
            client,
            ClientType::FuigoTUI,
            true,
        );
        mgr.set_yolo_mode(true);
        o.arm(&mgr);
        assert!(!matches!(ask(&mgr, &o, install).await, Decision::Allow));
        assert!(!matches!(ask(&mgr, &o, o.rm()).await, Decision::Allow));
        assert_eq!(prompts.borrow().len(), 2);
        assert_eq!(std::fs::read(&o.db).unwrap(), b"precious");
    });
}

#[test]
fn edit_tools_overwriting_outside_files_ask_and_agent_created_files_do_not() {
    run(async {
        let o = outside();
        let (mgr, _e) = test_manager(&o.cwd, true, None);
        o.arm(&mgr);
        assert!(s1_denied(
            &ask(&mgr, &o, AccessKind::Edit(o.db.display().to_string())).await
        ));
        // Fable r2 N3: create, then edit, the agent's own outside file in headless bypass.
        let notes = o.home.join("Documents/notes.md");
        std::fs::create_dir_all(notes.parent().unwrap()).unwrap();
        let edit = AccessKind::Edit(notes.display().to_string());
        assert_eq!(ask(&mgr, &o, edit.clone()).await, Decision::Allow);
        std::fs::write(&notes, b"by the write tool").unwrap();
        assert_eq!(ask(&mgr, &o, edit.clone()).await, Decision::Allow);
        // After a resume (a new manager: the sets are memory only) the same edit asks again.
        let (resumed, _e) = test_manager(&o.cwd, true, None);
        o.arm(&resumed);
        assert!(s1_denied(&ask(&resumed, &o, edit).await));
    });
}

#[test]
fn a_typed_path_exempts_until_resume() {
    run(async {
        let o = outside();
        let (mgr, _e) = test_manager(&o.cwd, true, None);
        o.arm(&mgr);
        mgr.note_user_text(
            &format!("delete {} please", o.db.display()),
            o.cwd.as_path(),
            None,
        );
        // A subagent shares the handle, so it shares the typed path.
        let child = mgr.clone();
        assert_eq!(ask(&child, &o, o.rm()).await, Decision::Allow);
        let (resumed, _e) = test_manager(&o.cwd, true, None);
        o.arm(&resumed);
        assert!(s1_denied(&ask(&resumed, &o, o.rm()).await));
    });
}

/// A2: the guard resolves operands where the runner starts the command (workdir, then the shell's directory).
#[test]
fn exec_dir_follows_the_runner_precedence() {
    let o = outside();
    let base = o.cwd.as_path().to_path_buf();
    let mut request = o.request(o.rm());
    assert_eq!(outside_exec_dir(&request, &base), base);
    request.shell_run_dir = Some(o.dir.clone());
    assert_eq!(outside_exec_dir(&request, &base), o.dir);
    request.exec_cwd = Some(base.join("../srv/data"));
    assert_eq!(outside_exec_dir(&request, &base), base.join("../srv/data"));
}

/// A third-party ACP host is `Generic`; when it declares `fuigo/permissionPrompts` it is asked in bypass, without it it
/// is refused, and a recognised client is unchanged (`every_approving_mode_prompts_once_and_auto_skips_the_classifier`).
#[test]
fn a_generic_host_that_declares_prompts_is_asked_in_bypass() {
    run(async {
        let o = outside();
        let client = IdSelectingClient::new("allow-once");
        let prompts = client.prompts.clone();
        let (mgr, _e) =
            manager_with_recording_client_remember(&o.cwd, None, client, ClientType::Generic, true);
        mgr.set_yolo_mode(true);
        o.arm(&mgr);
        mgr.outside_guard().set_client_prompts();
        assert_eq!(ask(&mgr, &o, o.rm()).await, Decision::Allow);
        assert_eq!(prompts.borrow().len(), 1);

        let client = IdSelectingClient::new("allow-once");
        let prompts = client.prompts.clone();
        let (mgr, _e) =
            manager_with_recording_client_remember(&o.cwd, None, client, ClientType::Generic, true);
        mgr.set_yolo_mode(true);
        o.arm(&mgr);
        assert!(s1_denied(&ask(&mgr, &o, o.rm()).await));
        assert!(prompts.borrow().is_empty());
    });
}

/// Design r3 §2 / §8.7: hub-routed calls are unchanged by S1. The hub never consults the guard, so an outside `rm`
/// gets exactly the answer an inside `rm` gets, with and without a catch-all `Bash` allow rule.
#[test]
fn hub_routed_calls_are_pinned_to_base() {
    let o = outside();
    let cwd = o.cwd.as_path();
    let catch_all = crate::permission::policy::CompiledPolicy::new(PermissionConfig::new(vec![
        crate::permission::rules::parse_permission_rule("Bash", RuleAction::Allow).unwrap(),
    ]));
    let inside = AccessKind::Bash("rm -f migrations/old.sql".into());
    for (policy, allows) in [(None, false), (Some(&catch_all), true)] {
        assert_eq!(
            hub_needs_default_prompt(&o.rm(), policy, allows, cwd),
            hub_needs_default_prompt(&inside, policy, allows, cwd),
            "allows={allows}"
        );
    }
}
