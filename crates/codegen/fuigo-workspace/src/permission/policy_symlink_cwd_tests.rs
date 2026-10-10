//! Path rules under a symlinked cwd (P156, ported from upstream `policy/path_match_tests.rs`).
//! Deny/ask rules match a path under the cwd's physical (symlink-resolved) form as well as its written form.
//! Allow rules keep matching the written form only, so a symlink never widens an allow.

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use crate::permission::policy::CompiledPolicy;
use crate::permission::rules::parse_permission_rule;
use crate::permission::types::{AccessKind, Decision, PermissionConfig, PermissionRule, RuleAction};

#[test]
fn symlinked_cwd_rules_match_every_spelling_of_a_workspace_path() {
    let fixture = SymlinkedWorkspace::new();
    let cwd = fixture.cwd();
    let ws = fixture.physical_ws();
    let notes = path_string(&ws.join("notes.toml"));
    let logical_notes = path_string(&cwd.join("notes.toml"));
    let physical_ws_glob = format!("{}/**", path_string(&ws));
    let read = |path: &str| AccessKind::Read(Some(path.to_owned()));
    let edit = |path: &str| AccessKind::Edit(path.to_owned());
    let cases = [
        (
            "alias read",
            vec![deny("Read(notes.toml)")],
            read("alias"),
            reject("read", "notes.toml"),
        ),
        (
            "physical edit",
            vec![deny("Edit(notes.toml)")],
            edit(&notes),
            reject("edit", "notes.toml"),
        ),
        (
            "physical edit through sub/..",
            vec![deny("Edit(notes.toml)")],
            edit(&path_string(&ws.join("sub/../notes.toml"))),
            reject("edit", "notes.toml"),
        ),
        (
            "new file spelled physically",
            vec![deny("Edit(new.toml)")],
            edit(&path_string(&ws.join("new.toml"))),
            reject("edit", "new.toml"),
        ),
        (
            "grep physical path",
            vec![deny("Read(notes.toml)")],
            AccessKind::Grep {
                path: Some(notes.clone()),
                glob: None,
            },
            reject("read", "notes.toml"),
        ),
        (
            "ask alias",
            vec![ask("Read(notes.toml)")],
            read("alias"),
            Some(Decision::Ask),
        ),
        (
            "ask physical",
            vec![ask("Read(./**)")],
            read(&notes),
            Some(Decision::Ask),
        ),
        (
            "../ws from symlinked cwd",
            vec![deny("Read(notes.toml)")],
            read("../ws/notes.toml"),
            reject("read", "notes.toml"),
        ),
        (
            "logical absolute deny, alias",
            vec![deny(&format!("Read({logical_notes})"))],
            read("alias"),
            reject("read", &logical_notes),
        ),
        (
            "logical absolute deny, physical",
            vec![deny(&format!("Read({logical_notes})"))],
            read(&notes),
            reject("read", &logical_notes),
        ),
        (
            "physical absolute deny, written",
            vec![deny(&format!("Read({physical_ws_glob})"))],
            read("notes.toml"),
            reject("read", &physical_ws_glob),
        ),
        (
            "relative deny beats physical absolute allow",
            vec![
                allow(&format!("Edit({physical_ws_glob})")),
                deny("Edit(notes.toml)"),
            ],
            edit(&notes),
            reject("edit", "notes.toml"),
        ),
        (
            // Fuigo divergence from upstream (which allows here): an allow is never widened by the physical cwd
            "relative allow does not cover the physical spelling",
            vec![allow("Edit(./**)")],
            edit(&notes),
            None,
        ),
        (
            "relative allow still covers the written spelling",
            vec![allow("Edit(./**)")],
            edit("notes.toml"),
            Some(Decision::Allow),
        ),
        (
            "allow stops at physical sibling",
            vec![allow("Edit(./**)")],
            edit(&path_string(&fixture.physical_real().join("other.toml"))),
            None,
        ),
        (
            "allow stops at physical sibling through ws/..",
            vec![allow("Edit(./**)")],
            edit(&path_string(&ws.join("../other.toml"))),
            None,
        ),
        (
            "allow ignores .. escape, relative",
            vec![allow("Edit(./**)")],
            edit("../../b/c/real/ws/x"),
            None,
        ),
        (
            "deny ignores .. escape that lands elsewhere physically",
            vec![deny("Read(notes.toml)")],
            read("../../b/c/real/ws/notes.toml"),
            None,
        ),
        (
            "allow ignores .. escape, absolute",
            vec![allow("Edit(./**)")],
            edit(&path_string(&cwd.join("../../b/c/real/ws/x"))),
            None,
        ),
    ];

    let expected: Vec<_> = cases
        .iter()
        .map(|(name, _, _, decision)| (*name, decision.clone()))
        .collect();
    let actual: Vec<_> = cases
        .iter()
        .map(|(name, rules, access, _)| {
            let policy = CompiledPolicy::new(PermissionConfig::new(rules.clone()));
            (*name, policy.evaluate_with_cwd(access, Some(&cwd)))
        })
        .collect();
    assert_eq!(expected, actual);
}

/// The brief's case: `Deny(./secret/**)` under a symlinked cwd must catch the real path, the written path,
/// and a symlinked subdirectory that leads into `secret/`.
#[test]
fn symlinked_cwd_relative_secret_deny_matches_real_written_and_linked_subdir_paths() {
    let fixture = SymlinkedWorkspace::new();
    let cwd = fixture.cwd();
    let ws = fixture.physical_ws();
    let policy = CompiledPolicy::new(PermissionConfig::new(vec![
        deny("Read(./secret/**)"),
        allow("Read(./**)"),
    ]));
    let read = |path: &str| policy.evaluate_with_cwd(&AccessKind::Read(Some(path.to_owned())), Some(&cwd));
    let denied = reject("read", "./secret/**");
    let cases = [
        ("written relative", read("secret/key"), denied.clone()),
        ("written absolute", read(&path_string(&cwd.join("secret/key"))), denied.clone()),
        ("real absolute", read(&path_string(&ws.join("secret/key"))), denied.clone()),
        ("real absolute, new file", read(&path_string(&ws.join("secret/new"))), denied.clone()),
        ("linked subdir, written", read("vault/key"), denied.clone()),
        ("linked subdir, real", read(&path_string(&ws.join("vault/key"))), denied.clone()),
        ("other file, written", read("notes.toml"), Some(Decision::Allow)),
    ];
    let expected: Vec<_> = cases.iter().map(|(n, _, want)| (*n, want.clone())).collect();
    let actual: Vec<_> = cases.iter().map(|(n, got, _)| (*n, got.clone())).collect();
    assert_eq!(expected, actual);
}

/// A symlink pointing outside the workspace: an allow for the workspace never covers the outside target,
/// whether the tool names the target directly or the cwd itself resolves outside.
#[test]
fn symlink_outside_workspace_never_widens_a_workspace_allow() {
    let fixture = SymlinkedWorkspace::new();
    let cwd = fixture.cwd();
    let outside = fixture.outside();
    let policy = CompiledPolicy::new(PermissionConfig::new(vec![allow("Edit(./**)")]));
    let edit = |path: &str| policy.evaluate_with_cwd(&AccessKind::Edit(path.to_owned()), Some(&cwd));
    assert_eq!(edit(&path_string(&outside.join("x"))), None, "outside target spelled directly");
    assert_eq!(
        edit(&path_string(&fixture.physical_ws().join("escape/x"))),
        None,
        "outside link spelled under the physical cwd"
    );
    assert_eq!(
        edit(&path_string(&fixture.physical_ws().join("x"))),
        None,
        "physical cwd is not covered by a written-cwd allow"
    );

    // A deny keyed on the outside target still catches every spelling through the link
    let target_glob = format!("{}/**", path_string(&outside));
    let deny_policy =
        CompiledPolicy::new(PermissionConfig::new(vec![deny(&format!("Edit({target_glob})"))]));
    let denied = reject("edit", &target_glob);
    for path in [
        "escape/x".to_owned(),
        path_string(&cwd.join("escape/x")),
        path_string(&fixture.physical_ws().join("escape/x")),
    ] {
        assert_eq!(
            deny_policy.evaluate_with_cwd(&AccessKind::Edit(path.clone()), Some(&cwd)),
            denied,
            "{path}"
        );
    }
}

/// Astra P156 r1 #2: a workspace allow on the written alias of a link that leaves the workspace must not carry to
/// the outside target, unless an allow also covers the target. In-workspace links and non-workspace allows are unchanged.
#[test]
fn workspace_allow_does_not_follow_a_link_out_of_the_workspace() {
    let fixture = SymlinkedWorkspace::new();
    let cwd = fixture.cwd();
    let outside = fixture.outside();
    let eval = |rules: Vec<PermissionRule>, access: AccessKind, cwd: &Path| {
        CompiledPolicy::new(PermissionConfig::new(rules)).evaluate_with_cwd(&access, Some(cwd))
    };
    let edit = |path: &str| AccessKind::Edit(path.to_owned());
    let read = |path: &str| AccessKind::Read(Some(path.to_owned()));
    let outside_glob = format!("{}/**", path_string(&outside));
    let cases = [
        ("written alias out", vec![allow("Edit(./**)")], edit("escape/x"), &cwd, None),
        (
            "written absolute alias out",
            vec![allow("Edit(./**)")],
            edit(&path_string(&cwd.join("escape/x"))),
            &cwd,
            None,
        ),
        (
            "outside target also allowed",
            vec![allow("Edit(./**)"), allow(&format!("Edit({outside_glob})"))],
            edit("escape/x"),
            &cwd,
            Some(Decision::Allow),
        ),
        ("in-workspace file link", vec![allow("Read(./**)")], read("alias"), &cwd, Some(Decision::Allow)),
        ("in-workspace dir link", vec![allow("Read(./**)")], read("vault/key"), &cwd, Some(Decision::Allow)),
        ("plain file, symlinked cwd", vec![allow("Edit(./**)")], edit("notes.toml"), &cwd, Some(Decision::Allow)),
        (
            "non-workspace absolute allow through a link is unchanged",
            vec![allow(&format!("Edit({}/**)", path_string(&fixture.root.join("link"))))],
            edit(&path_string(&cwd.join("notes.toml"))),
            &outside,
            Some(Decision::Allow),
        ),
    ];
    let expected: Vec<_> = cases.iter().map(|(n, _, _, _, want)| (*n, want.clone())).collect();
    let actual: Vec<_> = cases
        .iter()
        .map(|(n, rules, access, cwd, _)| (*n, eval(rules.clone(), access.clone(), cwd)))
        .collect();
    assert_eq!(expected, actual);
}

/// Astra P156 r1 #1: when the written cwd contains its own physical form (`<root>/link/..` resolves to `<root>/b/c`
/// while it normalizes to `<root>`), a deny keyed on the physical-relative spelling still matches.
#[test]
fn deny_matches_physical_relative_spelling_when_written_cwd_contains_physical_cwd() {
    let fixture = SymlinkedWorkspace::new();
    let cwd = fixture.root.join("link/..");
    let target = path_string(&fixture.physical_ws().join("notes.toml"));
    let deny_policy = CompiledPolicy::new(PermissionConfig::new(vec![deny("Read(./real/**)")]));
    let ask_policy = CompiledPolicy::new(PermissionConfig::new(vec![ask("Read(./real/**)")]));
    assert_eq!(
        deny_policy.evaluate_with_cwd(&AccessKind::Read(Some(target.clone())), Some(&cwd)),
        reject("read", "./real/**")
    );
    assert_eq!(
        ask_policy.evaluate_with_cwd(&AccessKind::Read(Some(target.clone())), Some(&cwd)),
        Some(Decision::Ask)
    );
    assert_eq!(
        deny_policy.evaluate_shell_file_access(&format!("cat {target}"), &cwd),
        reject("read", "./real/**")
    );
    // The written-relative spelling keeps matching too
    let written = CompiledPolicy::new(PermissionConfig::new(vec![deny("Read(./b/c/real/**)")]));
    assert_eq!(
        written.evaluate_with_cwd(&AccessKind::Read(Some(target)), Some(&cwd)),
        reject("read", "./b/c/real/**")
    );
}

/// Astra P156 r2: containment is judged against the physical workspace, narrow allows on in-workspace links keep
/// working, and a written-cwd absolute deny matches the physical spelling when the written cwd contains it.
#[test]
fn outbound_link_containment_uses_the_physical_workspace_and_keeps_in_workspace_allows() {
    let fixture = SymlinkedWorkspace::new();
    let cwd = fixture.cwd();
    let dotdot_cwd = fixture.root.join("link/..");
    let ws = fixture.physical_ws();
    let eval = |rules: Vec<PermissionRule>, access: AccessKind, cwd: &Path| {
        CompiledPolicy::new(PermissionConfig::new(rules)).evaluate_with_cwd(&access, Some(cwd))
    };
    let edit = |path: &str| AccessKind::Edit(path.to_owned());
    let read = |path: &str| AccessKind::Read(Some(path.to_owned()));
    let physical_ws_glob = format!("{}/**", path_string(&ws));
    let written_notes = path_string(&fixture.root.join("real/ws/notes.toml"));
    let cases = [
        (
            "written cwd containing its physical form, link out",
            vec![allow("Edit(./**)")],
            edit("real/ws/escape/x"),
            &dotdot_cwd,
            None,
        ),
        (
            "physical absolute allow, link out",
            vec![allow(&format!("Edit({physical_ws_glob})"))],
            edit(&path_string(&ws.join("escape/x"))),
            &cwd,
            None,
        ),
        ("narrow allow on an in-workspace file link", vec![allow("Edit(alias)")], edit("alias"), &cwd, Some(Decision::Allow)),
        (
            "narrow allow on an in-workspace dir link",
            vec![allow("Read(vault/**)")],
            read("vault/key"),
            &cwd,
            Some(Decision::Allow),
        ),
        (
            "written-cwd absolute deny, physical operand",
            vec![deny(&format!("Read({written_notes})"))],
            read(&path_string(&ws.join("notes.toml"))),
            &dotdot_cwd,
            reject("read", &written_notes),
        ),
    ];
    let expected: Vec<_> = cases.iter().map(|(n, _, _, _, want)| (*n, want.clone())).collect();
    let actual: Vec<_> = cases
        .iter()
        .map(|(n, rules, access, cwd, _)| (*n, eval(rules.clone(), access.clone(), cwd)))
        .collect();
    assert_eq!(expected, actual);
}

/// Astra P156 r3: `sub/../` cannot skip the physical containment check, and an outside target that an allow names
/// through a symlinked ancestor of the cwd (`/tmp/...` for `/private/tmp/...`) keeps its v1.0.21 allow.
#[test]
fn containment_ignores_dotdot_and_honours_allows_spelled_through_a_linked_ancestor() {
    let fixture = SymlinkedWorkspace::new();
    let cwd = fixture.cwd();
    let ws = fixture.physical_ws();
    let eval = |rules: Vec<PermissionRule>, path: &str| {
        CompiledPolicy::new(PermissionConfig::new(rules))
            .evaluate_with_cwd(&AccessKind::Edit(path.to_owned()), Some(&cwd))
    };
    let physical_ws_glob = format!("{}/**", path_string(&ws));
    let linked_other = path_string(&fixture.root.join("link/other.toml"));
    let cases = [
        (
            "physical absolute allow, link out through sub/..",
            eval(vec![allow(&format!("Edit({physical_ws_glob})"))], &path_string(&ws.join("sub/../escape/x"))),
            None,
        ),
        (
            "relative allow, link out through sub/..",
            eval(vec![allow("Edit(./**)")], "sub/../escape/x"),
            None,
        ),
        (
            "outside target allowed via the linked ancestor spelling",
            eval(vec![allow("Edit(./**)"), allow(&format!("Edit({linked_other})"))], "up"),
            Some(Decision::Allow),
        ),
        (
            "outside target not allowed under any spelling",
            eval(vec![allow("Edit(./**)")], "up"),
            None,
        ),
    ];
    let expected: Vec<_> = cases.iter().map(|(n, _, want)| (*n, want.clone())).collect();
    let actual: Vec<_> = cases.iter().map(|(n, got, _)| (*n, got.clone())).collect();
    assert_eq!(expected, actual);
}

#[test]
fn symlinked_cwd_shell_reads_match_relative_deny_only_for_workspace_files() {
    let fixture = SymlinkedWorkspace::new();
    let cwd = fixture.cwd();
    let policy = CompiledPolicy::new(PermissionConfig::new(vec![deny("Read(notes.toml)")]));
    let ws = fixture.physical_ws();
    let cases = [
        ("cat alias".to_owned(), reject("read", "notes.toml")),
        (
            format!("cat {}", path_string(&ws.join("notes.toml"))),
            reject("read", "notes.toml"),
        ),
        (
            format!("cat {}", path_string(&ws.join("sub/../notes.toml"))),
            reject("read", "notes.toml"),
        ),
        ("cat ../../b/c/real/ws/notes.toml".to_owned(), None),
    ];

    let expected: Vec<_> = cases
        .iter()
        .map(|(cmd, decision)| (cmd.as_str(), decision.clone()))
        .collect();
    let actual: Vec<_> = cases
        .iter()
        .map(|(cmd, _)| (cmd.as_str(), policy.evaluate_shell_file_access(cmd, &cwd)))
        .collect();
    assert_eq!(expected, actual);
}

#[test]
fn symlinked_cwd_shell_secret_deny_matches_real_and_linked_subdir_paths() {
    let fixture = SymlinkedWorkspace::new();
    let cwd = fixture.cwd();
    let ws = fixture.physical_ws();
    let policy = CompiledPolicy::new(PermissionConfig::new(vec![deny("Read(./secret/**)")]));
    let denied = reject("read", "./secret/**");
    for cmd in [
        "cat secret/key".to_owned(),
        format!("cat {}", path_string(&ws.join("secret/key"))),
        "cat vault/key".to_owned(),
        format!("cat {}", path_string(&ws.join("vault/key"))),
    ] {
        assert_eq!(policy.evaluate_shell_file_access(&cmd, &cwd), denied, "{cmd}");
    }
}

/// `<tmp>/b/c/real/ws/{notes.toml, alias -> notes.toml, sub/, secret/key, vault -> secret, escape -> <tmp>/outside, up -> ../other.toml}`,
/// `<tmp>/b/c/real/other.toml` and `<tmp>/outside/`, entered as cwd `<tmp>/link/ws` through `<tmp>/link -> <tmp>/b/c/real`
struct SymlinkedWorkspace {
    _tmp: TempDir,
    root: PathBuf,
}

impl SymlinkedWorkspace {
    fn new() -> SymlinkedWorkspace {
        let tmp = tempfile::tempdir().expect("create tempdir");
        // The canonical root keeps `link` the only cwd symlink, so `..` counts match on every OS (macOS `/var` -> `/private/var`)
        let root = dunce::canonicalize(tmp.path()).expect("canonicalize tempdir");
        let real = root.join("b/c/real");
        std::fs::create_dir_all(real.join("ws/sub")).expect("create real workspace");
        std::fs::create_dir_all(real.join("ws/secret")).expect("create secret dir");
        std::fs::create_dir_all(root.join("outside")).expect("create outside dir");
        std::fs::write(real.join("other.toml"), b"beta = 2\n").expect("write other.toml");
        std::fs::write(real.join("ws/notes.toml"), b"alpha = 1\n").expect("write notes.toml");
        std::fs::write(real.join("ws/secret/key"), b"k\n").expect("write secret key");
        symlink("notes.toml", real.join("ws/alias")).expect("link alias to notes.toml");
        symlink("secret", real.join("ws/vault")).expect("link vault to secret");
        symlink(root.join("outside"), real.join("ws/escape")).expect("link escape to outside");
        symlink(real.join("other.toml"), real.join("ws/up")).expect("link up to other.toml");
        symlink(&real, root.join("link")).expect("link cwd parent to real");
        SymlinkedWorkspace { _tmp: tmp, root }
    }

    fn cwd(&self) -> PathBuf {
        self.root.join("link/ws")
    }

    fn physical_real(&self) -> PathBuf {
        self.root.join("b/c/real")
    }

    fn physical_ws(&self) -> PathBuf {
        self.physical_real().join("ws")
    }

    fn outside(&self) -> PathBuf {
        self.root.join("outside")
    }
}

fn deny(rule: &str) -> PermissionRule {
    parse_permission_rule(rule, RuleAction::Deny).expect("parse deny rule")
}

fn ask(rule: &str) -> PermissionRule {
    parse_permission_rule(rule, RuleAction::Ask).expect("parse ask rule")
}

fn allow(rule: &str) -> PermissionRule {
    parse_permission_rule(rule, RuleAction::Allow).expect("parse allow rule")
}

fn reject(tool: &str, pattern: &str) -> Option<Decision> {
    Some(Decision::Reject(format!(
        "Denied by permission policy: deny rule on {tool} matching \"{pattern}\""
    )))
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
