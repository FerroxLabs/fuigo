//! P175c: a deny/ask rule written with an absolute path through a symlinked directory applies to the other spelling of
//! the same file (the physical one), and the reverse. Tests go through the real entry points: the native
//! Read/Edit/Grep evaluation and the shell file-access gate. Layout: `<tmp>/real/secrets/key`, `<tmp>/link -> real`,
//! cwd `<tmp>/ws` (not aliased).

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use crate::permission::policy::CompiledPolicy;
use crate::permission::rules::parse_permission_rule;
use crate::permission::types::{AccessKind, Decision, PermissionConfig, RuleAction};

struct Fixture {
    _tmp: TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let root = dunce::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir_all(root.join("real/secrets")).unwrap();
        std::fs::write(root.join("real/secrets/key"), "k").unwrap();
        std::fs::create_dir_all(root.join("ws")).unwrap();
        symlink(root.join("real"), root.join("link")).unwrap();
        Self { _tmp: tmp, root }
    }
    fn cwd(&self) -> PathBuf {
        self.root.join("ws")
    }
    /// The rule spelled through the link
    fn linked(&self, rest: &str) -> String {
        format!("{}/link/{rest}", self.root.display())
    }
    fn physical(&self, rest: &str) -> String {
        format!("{}/real/{rest}", self.root.display())
    }
}

fn policy(action: RuleAction, rule: &str) -> CompiledPolicy {
    CompiledPolicy::new(PermissionConfig::new(vec![
        parse_permission_rule(rule, action).expect("parse rule"),
    ]))
}

fn is_reject(decision: &Option<Decision>) -> bool {
    matches!(decision, Some(Decision::Reject(_)))
}

fn native(policy: &CompiledPolicy, access: AccessKind, cwd: &Path) -> Option<Decision> {
    policy.evaluate_with_cwd(&access, Some(cwd))
}

#[test]
fn deny_rule_via_link_applies_to_physical_native_access() {
    let f = Fixture::new();
    let p = policy(RuleAction::Deny, &format!("Read({})", f.linked("secrets/**")));
    let phys = f.physical("secrets/key");
    let new = f.physical("secrets/new.txt");
    for (what, access) in [
        ("read", AccessKind::Read(Some(phys.clone()))),
        ("grep", AccessKind::Grep { path: Some(phys.clone()), glob: None }),
        ("read of a file not yet created", AccessKind::Read(Some(new))),
    ] {
        let decision = native(&p, access, &f.cwd());
        assert!(is_reject(&decision), "{what}: {decision:?}");
    }
}

#[test]
fn deny_rule_via_link_applies_to_physical_edit() {
    let f = Fixture::new();
    let p = policy(RuleAction::Deny, &format!("Edit({})", f.linked("secrets/**")));
    let decision = native(&p, AccessKind::Edit(f.physical("secrets/new.txt")), &f.cwd());
    assert!(is_reject(&decision), "{decision:?}");
}

#[test]
fn ask_rule_via_link_applies_to_physical_read() {
    let f = Fixture::new();
    let p = policy(RuleAction::Ask, &format!("Read({})", f.linked("secrets/**")));
    let decision = native(&p, AccessKind::Read(Some(f.physical("secrets/key"))), &f.cwd());
    assert_eq!(decision, Some(Decision::Ask));
}

#[test]
fn deny_rule_physical_applies_to_linked_native_access() {
    let f = Fixture::new();
    let p = policy(RuleAction::Deny, &format!("Read({})", f.physical("secrets/**")));
    let decision = native(&p, AccessKind::Read(Some(f.linked("secrets/key"))), &f.cwd());
    assert!(is_reject(&decision), "{decision:?}");
}

#[test]
fn deny_rule_via_link_applies_to_physical_shell_read_and_write() {
    let f = Fixture::new();
    let p = policy(RuleAction::Deny, &format!("Read({})", f.linked("secrets/**")));
    let cmd = format!("cat {}", f.physical("secrets/key"));
    let decision = p.evaluate_shell_file_access(&cmd, &f.cwd());
    assert!(is_reject(&decision), "cat: {decision:?}");
    let pe = policy(RuleAction::Deny, &format!("Edit({})", f.linked("secrets/**")));
    let cmd = format!("echo x > {}", f.physical("secrets/new.txt"));
    let decision = pe.evaluate_shell_file_access(&cmd, &f.cwd());
    assert!(is_reject(&decision), "redirect: {decision:?}");
}

#[test]
fn ask_rule_via_link_applies_to_physical_shell_read() {
    let f = Fixture::new();
    let p = policy(RuleAction::Ask, &format!("Read({})", f.linked("secrets/**")));
    let cmd = format!("cat {}", f.physical("secrets/key"));
    assert_eq!(p.evaluate_shell_file_access(&cmd, &f.cwd()), Some(Decision::Ask));
}

#[test]
fn deny_rule_physical_applies_to_linked_shell_read() {
    let f = Fixture::new();
    let p = policy(RuleAction::Deny, &format!("Read({})", f.physical("secrets/**")));
    let cmd = format!("cat {}", f.linked("secrets/key"));
    let decision = p.evaluate_shell_file_access(&cmd, &f.cwd());
    assert!(is_reject(&decision), "{decision:?}");
}

#[test]
fn alias_spelling_never_grants_an_allow_and_unrelated_paths_stay_allowed() {
    let f = Fixture::new();
    // An allow written via the link is not applied to the physical spelling (unchanged: fails closed to a prompt)
    let allow = policy(RuleAction::Allow, &format!("Read({})", f.linked("secrets/**")));
    let decision = native(&allow, AccessKind::Read(Some(f.physical("secrets/key"))), &f.cwd());
    assert_ne!(decision, Some(Decision::Allow), "{decision:?}");
    // A deny on the secrets directory does not touch a sibling directory
    let deny = policy(RuleAction::Deny, &format!("Read({})", f.linked("secrets/**")));
    std::fs::create_dir_all(f.root.join("real/open")).unwrap();
    let decision = native(&deny, AccessKind::Read(Some(f.physical("open/x"))), &f.cwd());
    assert!(!is_reject(&decision), "{decision:?}");
    let cmd = format!("cat {}", f.physical("open/x"));
    assert_eq!(deny.evaluate_shell_file_access(&cmd, &f.cwd()), None);
}

#[test]
fn p175f_deny_rule_via_link_applies_when_the_target_and_its_directory_do_not_exist() {
    let f = Fixture::new();
    // `real/pending/` and `real/pending/key` do not exist yet; `link` is the symlink.
    let pr = policy(RuleAction::Deny, &format!("Read({})", f.linked("pending/key")));
    let decision = native(&pr, AccessKind::Read(Some(f.physical("pending/key"))), &f.cwd());
    assert!(is_reject(&decision), "read: {decision:?}");
    let pe = policy(RuleAction::Deny, &format!("Edit({})", f.linked("pending/key")));
    let decision = native(&pe, AccessKind::Edit(f.physical("pending/key")), &f.cwd());
    assert!(is_reject(&decision), "edit: {decision:?}");
    // Only the leaf is missing.
    let pl = policy(RuleAction::Deny, &format!("Read({})", f.linked("secrets/later")));
    let decision = native(&pl, AccessKind::Read(Some(f.physical("secrets/later"))), &f.cwd());
    assert!(is_reject(&decision), "leaf missing: {decision:?}");
    // A sibling stays undenied.
    let decision = native(&pr, AccessKind::Read(Some(f.physical("pending/other"))), &f.cwd());
    assert!(!is_reject(&decision), "sibling: {decision:?}");
}

#[test]
fn p175g_retargeted_link_is_judged_immediately() {
    let f = Fixture::new();
    std::fs::create_dir_all(f.root.join("realB/secrets")).unwrap();
    let pr = policy(RuleAction::Deny, &format!("Read({})", f.linked("secrets/**")));
    // Fills any cache.
    let decision = native(&pr, AccessKind::Read(Some(f.physical("secrets/x"))), &f.cwd());
    assert!(is_reject(&decision), "before retarget: {decision:?}");
    std::fs::remove_file(f.root.join("link")).unwrap();
    symlink(f.root.join("realB"), f.root.join("link")).unwrap();
    let decision = native(
        &pr,
        AccessKind::Read(Some(format!("{}/realB/secrets/x", f.root.display()))),
        &f.cwd(),
    );
    assert!(is_reject(&decision), "after retarget: {decision:?}");
}

#[test]
fn p175g_link_created_after_a_miss_is_judged_immediately() {
    let f = Fixture::new();
    std::fs::remove_file(f.root.join("link")).unwrap();
    let pr = policy(RuleAction::Deny, &format!("Read({})", f.linked("secrets/**")));
    // The link is absent: a miss (physical spelling is not covered yet).
    let _ = native(&pr, AccessKind::Read(Some(f.physical("secrets/x"))), &f.cwd());
    symlink(f.root.join("real"), f.root.join("link")).unwrap();
    let decision = native(&pr, AccessKind::Read(Some(f.physical("secrets/x"))), &f.cwd());
    assert!(is_reject(&decision), "after create: {decision:?}");
}
