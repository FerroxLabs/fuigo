//! S6.1-S6.3 (packet 6 part A): the peer guard in every mode. The guard may only make a decision stricter: a
//! peer-influenced session is DENIED a protected edit in every mode, and every other request is judged exactly as in
//! an identical session without the state.

use super::*;
use crate::permission::peer_guard::is_peer_protected_path;
use crate::permission::types::{
    EditTargets, PatternMode, PermissionConfig, PermissionRule, PromptPolicy, ResolvedBaseMode, RuleAction,
    ToolFilter,
};

fn tool_call() -> acp::ToolCallUpdate {
    acp::ToolCallUpdate::new("t1", acp::ToolCallUpdateFields::new())
}

fn spawn(cwd: &AbsPathBuf, config: Option<PermissionConfig>, yolo: bool) -> PermissionHandle {
    let (tx, _rx) = mpsc::unbounded_channel();
    let (h, _events) = spawn_permission_manager_with_pin(
        acp::SessionId::new(Arc::from("peer-guard")),
        GatewaySender::new(tx),
        cwd.clone(),
        ClientType::Generic,
        config,
        vec![],
        vec![],
        yolo,
        None,
        true,
        None,
        None,
    );
    h
}

/// Every mode the S6.3 table names. `None` is the allow-all handle.
type Maker = Box<dyn Fn(&AbsPathBuf) -> PermissionHandle>;

pub(super) fn modes() -> Vec<(&'static str, Maker)> {
    let cfg = |f: fn(&mut PermissionConfig)| {
        move |cwd: &AbsPathBuf| {
            let mut c = PermissionConfig::new(vec![]);
            f(&mut c);
            spawn(cwd, Some(c), false)
        }
    };
    vec![
        ("default", Box::new(|cwd| spawn(cwd, None, false))),
        ("yolo", Box::new(|cwd| spawn(cwd, None, true))),
        // Plan mode lives outside the permission layer (the session's plan state): the handle is the default one. The
        // shell-side plan-file bypass is skipped for an influenced session (`tool_calls.rs`, `plan_file_auto_approve`).
        ("plan", Box::new(|cwd| spawn(cwd, None, false))),
        ("allow_all_handle", Box::new(|_| PermissionHandle::allow_all())),
        ("auto", Box::new(cfg(|c| c.prompt_policy = PromptPolicy::Auto))),
        ("acceptEdits", Box::new(cfg(|c| c.resolved_base = ResolvedBaseMode::AcceptEdits))),
        ("dontAsk", Box::new(cfg(|c| c.prompt_policy = PromptPolicy::Deny))),
        ("bypassPermissions", Box::new(cfg(|c| c.resolved_base = ResolvedBaseMode::BypassPermissions))),
        ("AlwaysAllow", Box::new(cfg(|c| c.prompt_policy = PromptPolicy::Allow))),
        (
            "AllowAnyRule",
            Box::new(|cwd| {
                let rule = PermissionRule {
                    action: RuleAction::Allow,
                    tool: ToolFilter::Any,
                    pattern: None,
                    pattern_mode: PatternMode::Glob,
                };
                spawn(cwd, Some(PermissionConfig::new(vec![rule])), false)
            }),
        ),
        (
            "edit_grant",
            Box::new(|cwd| {
                let h = spawn(cwd, None, false);
                if let PermissionHandle::Actor { mode_view, .. } = &h {
                    mode_view.session_edit_grant.store(true, Ordering::SeqCst);
                }
                h
            }),
        ),
    ]
}

pub(super) async fn decide(h: &PermissionHandle, cwd: &std::path::Path, access: AccessKind, targets: Option<EditTargets>) -> String {
    let request = PermissionRequest {
        path_context: Some(crate::permission::types::RequestPathContext {
            real_cwd: cwd.to_path_buf(),
            display_cwd: None,
        }),
        edit_targets: targets,
        ..PermissionRequest::new(access, tool_call())
    };
    match tokio::time::timeout(std::time::Duration::from_secs(60), h.request(request)).await {
        // The event minus its clock-dependent fields (timestamp, wait, queue depth).
        Ok(r) => format!(
            "{:?}|{:?}",
            r.decision,
            r.event.map(|e| (e.decision, e.decision_reason, e.permission_mode, e.auto_approved, e.user_prompted, e.prompt_outcome, e.reject_reason))
        ),
        Err(_) => "TIMEOUT".to_owned(),
    }
}

/// A decision that really happened: a timeout is a test failure, never an equal pair.
async fn decide_live(h: &PermissionHandle, cwd: &std::path::Path, access: AccessKind, targets: Option<EditTargets>) -> String {
    let d = decide(h, cwd, access, targets).await;
    assert_ne!(d, "TIMEOUT", "the decision timed out");
    d
}

pub(super) fn is_guard_denial(s: &str) -> bool {
    s.starts_with("PolicyDeny(") && s.contains("read messages from another session") && s.contains("/peers clear-influence")
}

#[test]
fn s6_2_protected_set_membership() {
    let t = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(t.path()).unwrap();
    for p in [
        "CLAUDE.md", "sub/dir/AGENTS.md", "CLAUDE.local.md", ".claude/CLAUDE.md", ".claude/rules/a.md",
        ".fuigo/skills/x/SKILL.md", ".claude/agents/a.md", ".fuigo/commands/c.md", ".claude/settings.json",
        ".mcp.json", ".git/config", ".git/hooks/pre-commit", ".fuigo/peers/audit.log", ".fuigo/config.toml",
        ".fuigo/hooks/h.json", ".gitconfig",
    ] {
        assert!(is_peer_protected_path(&root.join(p)), "{p} must be protected");
    }
    for p in ["src/main.rs", "README.md", "docs/claude_notes.txt", ".claude/plans/p.md"] {
        assert!(!is_peer_protected_path(&root.join(p)), "{p} must not be protected");
    }
}

#[cfg(unix)]
#[test]
fn s6_2_symlink_into_set_and_symlinked_parent_and_dotdot() {
    let t = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(t.path()).unwrap();
    std::fs::create_dir_all(root.join("real/.claude")).unwrap();
    std::fs::write(root.join("CLAUDE.md"), "x").unwrap();
    std::fs::create_dir_all(root.join("work")).unwrap();
    std::os::unix::fs::symlink(root.join("CLAUDE.md"), root.join("work/notes.txt")).unwrap();
    std::os::unix::fs::symlink(root.join("real/.claude"), root.join("work/innocent")).unwrap();
    assert!(is_peer_protected_path(&root.join("work/notes.txt")), "symlink into the set");
    assert!(is_peer_protected_path(&root.join("work/innocent/settings.json")), "symlinked parent");
    assert!(is_peer_protected_path(&root.join("work/../CLAUDE.md")), "dotdot");
    assert!(is_peer_protected_path(&root.join("work/x/../../CLAUDE.md")), "dotdot through a missing dir");
    assert!(!is_peer_protected_path(&root.join("work/ordinary.txt")));
}

#[tokio::test]
async fn s6_3_table_every_mode_denies_protected_and_matches_control_elsewhere() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let tmp = tempfile::tempdir().unwrap();
                let root = dunce::canonicalize(tmp.path()).unwrap();
                let cwd = AbsPathBuf::new(root.clone()).unwrap();
                let influenced = make(&cwd);
                let control = make(&cwd);
                influenced.set_peer_influenced(true);
                assert!(influenced.is_peer_influenced() && !control.is_peer_influenced(), "{name}");
                let prot = root.join("CLAUDE.md").to_string_lossy().into_owned();
                let ordinary = root.join("src/lib.rs").to_string_lossy().into_owned();
                let rel_prot = ".claude/settings.json".to_owned();

                assert!(!decide(&control, &root, AccessKind::Read(None), None).await.starts_with("TIMEOUT"), "{name}");
                for p in [&prot, &rel_prot] {
                    let d = decide(&influenced, &root, AccessKind::Edit(p.clone()), None).await;
                    assert!(is_guard_denial(&d), "{name}: protected {p} must be denied, got {d}");
                }
                // A human-typed prompt is not special-cased: the guard sees only the request.
                // Ordinary path: identical to the control session in the same mode.
                let a = decide(&influenced, &root, AccessKind::Edit(ordinary.clone()), None).await;
                let b = decide(&control, &root, AccessKind::Edit(ordinary.clone()), None).await;
                assert!(!a.starts_with("TIMEOUT") && !b.starts_with("TIMEOUT"), "{name}: not a timeout: {a} / {b}");
                assert_eq!(a, b, "{name}: ordinary edit must match the control");
                assert!(!is_guard_denial(&a), "{name}");
                // Non-edit tools untouched.
                let a = decide_live(&influenced, &root, AccessKind::Read(Some(prot.clone())), None).await;
                let b = decide_live(&control, &root, AccessKind::Read(Some(prot.clone())), None).await;
                assert_eq!(a, b, "{name}: read must match the control");
                // Control (not influenced) is byte-identical to a fresh session in the protected case: never a guard denial.
                let c = decide_live(&control, &root, AccessKind::Edit(prot.clone()), None).await;
                assert!(!is_guard_denial(&c), "{name}: control must not see the guard: {c}");
            }
        })
        .await;
}

#[tokio::test]
async fn s6_3_multi_file_edit_with_one_protected_target_is_denied() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let tmp = tempfile::tempdir().unwrap();
                let root = dunce::canonicalize(tmp.path()).unwrap();
                let cwd = AbsPathBuf::new(root.clone()).unwrap();
                let h = make(&cwd);
                h.set_peer_influenced(true);
                let targets = EditTargets::Paths(vec!["src/a.rs".into(), "AGENTS.md".into(), "src/b.rs".into()]);
                let d = decide(&h, &root, AccessKind::Edit("apply_patch".into()), Some(targets)).await;
                assert!(is_guard_denial(&d), "{name}: {d}");
                assert!(d.contains("AGENTS.md"), "{name}: names the protected target");
            }
        })
        .await;
}

#[tokio::test]
async fn s6_1_flag_is_live_shared_and_clears() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let tmp = tempfile::tempdir().unwrap();
            let root = dunce::canonicalize(tmp.path()).unwrap();
            let cwd = AbsPathBuf::new(root.clone()).unwrap();
            let h = spawn(&cwd, None, true);
            let clone = h.clone();
            let prot = root.join("CLAUDE.md").to_string_lossy().into_owned();
            let before = decide_live(&clone, &root, AccessKind::Edit(prot.clone()), None).await;
            assert!(!is_guard_denial(&before));
            h.set_peer_influenced(true);
            assert!(is_guard_denial(&decide(&clone, &root, AccessKind::Edit(prot.clone()), None).await), "clone sees it");
            h.set_peer_influenced(false);
            assert_eq!(decide(&clone, &root, AccessKind::Edit(prot), None).await, before);
            // Shared flag replaces the handle's own.
            let shared = PeerInfluence::new();
            let h2 = spawn(&cwd, None, false).with_peer_influence(shared.clone());
            shared.set(true);
            assert!(h2.is_peer_influenced());
        })
        .await;
}

#[tokio::test]
async fn s6_1_status_style_turn_with_no_write_changes_nothing() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let tmp = tempfile::tempdir().unwrap();
                let root = dunce::canonicalize(tmp.path()).unwrap();
                let cwd = AbsPathBuf::new(root.clone()).unwrap();
                let influenced = make(&cwd);
                let control = make(&cwd);
                influenced.set_peer_influenced(true);
                for access in [
                    AccessKind::Read(Some("src/lib.rs".into())),
                    AccessKind::Bash("git status".into()),
                    AccessKind::WebSearch("rust".into()),
                ] {
                    let a = decide_live(&influenced, &root, access.clone(), None).await;
                    let b = decide_live(&control, &root, access, None).await;
                    assert_eq!(a, b, "{name}");
                }
            }
        })
        .await;
}

/// Round 3: a table over EVERY entry of the protected set under the default `.fuigo` / `.claude` layout, plus the
/// over-protection negatives (a same-named file elsewhere is free).
#[test]
fn r3_protected_set_table_every_entry_and_over_protection_negatives() {
    let t = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(t.path()).unwrap();
    for p in [
        // plugins and the marketplace list
        ".fuigo/plugins/x/plugin.json", ".claude/plugins/known_marketplaces.json", ".fuigo/plugins/known_marketplaces.json",
        // bundle directories and memory
        ".fuigo/personas/p.md", ".fuigo/roles/r.md", ".fuigo/prompts/p.md", ".fuigo/workflows/w.yaml", ".fuigo/memory/m.md",
        // peer config, audit log and its rotation
        ".fuigo/peers/p.toml", ".fuigo/peer-audit.jsonl", ".fuigo/peer-audit.jsonl.1",
        // instruction files and rule directories
        "CLAUDE.md", "a/b/AGENTS.md", "CLAUDE.local.md", ".claude/rules/a.md", ".fuigo/rules/a.md", ".cursor/rules/a.md",
        ".fuigo/skills/s/SKILL.md", ".claude/agents/a.md", ".fuigo/commands/c.md",
        // git config
        ".git/config", "wt/.git/config.worktree", ".git/modules/m/config", ".gitconfig", ".config/git/config",
        // the floor
        ".claude/settings.json", ".mcp.json", ".fuigo/config.toml", ".fuigo/hooks/h.json",
    ] {
        assert!(is_peer_protected_path(&root.join(p)), "{p} must be protected");
    }
    for p in [
        "src/main.rs", "src/commands/x.rs", "docs/rules.md", "src/plugins/mod.rs", "memory/notes.txt", "peer-notes.txt",
        "any/known_marketplaces.json", "known_marketplaces.json", "peer-audit.jsonl", "logs/peer-audit.jsonl.1",
        "src/personas/a.md", "roles/r.md", "workflows/w.yaml", ".claude/plans/p.md",
    ] {
        assert!(!is_peer_protected_path(&root.join(p)), "{p} must not be protected");
    }
}

/// Round 3: under a RELOCATED Fuigo home (no `.fuigo` component) every home directory and the audit log are protected.
#[test]
fn s6_2_relocated_fuigo_home_dirs_are_protected() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let home = dunce::canonicalize(t.path()).unwrap();
    let _env = crate::LockedTestEnv::lock().set("FUIGO_HOME", &home);
    for d in ["rules", "skills", "agents", "commands", "peers", "plugins", "hooks", "memory", "personas", "roles", "prompts", "workflows"] {
        assert!(is_peer_protected_path(&home.join(d).join("x.md")), "{d}");
    }
    assert!(is_peer_protected_path(&home.join("plugins/known_marketplaces.json")));
    assert!(is_peer_protected_path(&home.join("peer-audit.jsonl")));
    assert!(is_peer_protected_path(&home.join("peer-audit.jsonl.1")));
    assert!(!is_peer_protected_path(&home.join("sub/peer-audit.jsonl")), "only the home's own log");
    assert!(!is_peer_protected_path(&home.join("unrelated.txt")));
}

#[tokio::test]
async fn s6_3_task_pseudo_path_in_a_protected_cwd_is_not_denied() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(tmp.path()).unwrap().join(".claude/rules");
    std::fs::create_dir_all(&root).unwrap();
    let cwd = AbsPathBuf::new(root.clone()).unwrap();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let h = spawn(&cwd, None, true);
            h.set_peer_influenced(true);
            let d = decide(&h, &root, AccessKind::Edit("task:general".into()), None).await;
            assert!(!is_guard_denial(&d), "{d}");
        })
        .await;
}

#[test]
fn s6_3_denial_text_says_what_and_how_to_lift() {
    let t = crate::permission::peer_guard::peer_guard_denial_text("CLAUDE.md");
    assert!(t.contains("this session has read messages from another session"));
    assert!(t.contains("cannot change settings"));
    assert!(t.contains("`/peers clear-influence`"));
}

#[cfg(unix)]
#[tokio::test]
async fn s6_3_symlink_into_set_is_denied_through_request() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let tmp = tempfile::tempdir().unwrap();
                let root = dunce::canonicalize(tmp.path()).unwrap();
                std::fs::write(root.join("CLAUDE.md"), "x").unwrap();
                std::os::unix::fs::symlink(root.join("CLAUDE.md"), root.join("notes.txt")).unwrap();
                let h = make(&AbsPathBuf::new(root.clone()).unwrap());
                h.set_peer_influenced(true);
                let d = decide(&h, &root, AccessKind::Edit("notes.txt".into()), None).await;
                assert!(is_guard_denial(&d), "{name}: {d}");
            }
        })
        .await;
}

/// Finding 5: with a long home the inbox socket and locator live in `$XDG_RUNTIME_DIR/fuigo/<hash>/peers`; an influenced
/// session may not write there in any mode.
#[tokio::test]
async fn xs_p8f_runtime_peers_dir_is_protected_through_request() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    let (runtime, home) = (root.join("run"), root.join("some-long-home"));
    let peers = fuigo_peer::runtime_peers_dir(&runtime, &home);
    std::fs::create_dir_all(&peers).unwrap();
    *crate::permission::peer_guard::TEST_RUNTIME_DIR.write().unwrap() = Some((runtime.clone(), home.clone()));
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for (name, make) in modes() {
                let h = make(&AbsPathBuf::new(root.clone()).unwrap());
                h.set_peer_influenced(true);
                for target in [peers.join("hosts.json"), peers.join("abc.sock"), peers.join("new/x.txt")] {
                    let d = decide(&h, &root, AccessKind::Edit(target.to_string_lossy().into_owned()), None).await;
                    assert!(is_guard_denial(&d), "{name}: {d}");
                }
                // A sibling that is not the peers directory stays free.
                let other = fuigo_peer::runtime_home_dir(&runtime, &home).join("other.txt");
                let d = decide(&h, &root, AccessKind::Edit(other.to_string_lossy().into_owned()), None).await;
                assert!(!is_guard_denial(&d), "{name}: sibling must not be denied: {d}");
            }
        })
        .await;
    *crate::permission::peer_guard::TEST_RUNTIME_DIR.write().unwrap() = None;
}
