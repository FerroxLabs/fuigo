//! Ported from upstream `sandbox/src/command/git_config_tests.rs` (adapted to Fuigo's entry list)
//! plus the P158 gap and Linux bwrap-plan tests.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::{
    GIT_CONFIG_GLOBAL_ENV, GIT_CONFIG_INCLUDE_DEPTH, GIT_DIRS_LIMIT, GIT_METADATA_READ_LIMIT,
    GitConfigEnv, GitEntries, GitMetadataUnread, GitPathKind, GitProtectedPath,
    XDG_CONFIG_HOME_ENV, denies,
};

fn entries(ws: &Path, user_home: Option<&Path>, write_roots: &[PathBuf]) -> GitEntries {
    super::git_entries_in(ws, user_home, write_roots, &GitConfigEnv::default())
}

fn git_entries(ws: &Path, user_home: Option<&Path>, write_roots: &[PathBuf]) -> Vec<GitProtectedPath> {
    let got = entries(ws, user_home, write_roots);
    assert!(got.unread.is_empty(), "{:?}", got.unread);
    got.protected
}

fn has(got: &[GitProtectedPath], path: impl AsRef<Path>, kind: GitPathKind) -> bool {
    got.iter()
        .any(|entry| entry.path == path.as_ref() && entry.kind == kind)
}

fn tree(got: &[GitProtectedPath], path: impl AsRef<Path>) -> bool {
    has(got, path, GitPathKind::Dir)
}

fn file(got: &[GitProtectedPath], path: impl AsRef<Path>) -> bool {
    has(got, path, GitPathKind::File)
}

fn env(config_global: Option<&str>, xdg_config_home: Option<&str>) -> GitConfigEnv {
    GitConfigEnv {
        config_global: config_global.map(OsString::from),
        xdg_config_home: xdg_config_home.map(OsString::from),
        ..GitConfigEnv::default()
    }
}

fn write_hooks_config(path: &Path, hooks: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("[core]\n\thooksPath = {hooks}\n")).unwrap();
}

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "fuigo-p158-git-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    dunce::canonicalize(&root).unwrap()
}

/// P158 gap: the workspace repository's hooks, config and worktree config are denied, as trees
/// or files; the rest of `.git` (objects, refs, index, `info/exclude`) is not, so git and Fuigo's
/// commit workflow still work.
#[test]
fn p158_workspace_git_hooks_and_config_are_denied() {
    let root = scratch("gap");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git/hooks")).unwrap();
    std::fs::write(ws.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(tree(&got, ws.join(".git/hooks")), "{got:?}");
    assert!(file(&got, ws.join(".git/config")), "{got:?}");
    assert!(
        has(&got, ws.join(".git/config.worktree"), GitPathKind::OptionalFile),
        "{got:?}"
    );
    assert!(denies(&got, &ws.join(".git/hooks/pre-commit")));
    assert!(!denies(&got, &ws.join(".git/info/exclude")), "{got:?}");
    for free in [".git/objects/ab/cd", ".git/index", ".git/refs/heads/main", "src/lib.rs"] {
        assert!(!denies(&got, &ws.join(free)), "{free} denied: {got:?}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Fuigo accepted limit: a workspace with no repository at start gets no workspace entries, so
/// an agent can still `git init` a new project; the global config is still protected.
#[test]
fn p158_no_repository_at_start_protects_only_the_global_config() {
    let root = scratch("no-repo");
    let ws = root.join("ws");
    let home = root.join("home");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let got = git_entries(&ws, Some(&home), &[]);
    assert!(!got.iter().any(|entry| entry.path.starts_with(&ws)), "{got:?}");
    assert!(file(&got, home.join(".gitconfig")), "{got:?}");
    assert!(file(&got, home.join(".config/git/config")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn hooks_path_resolves_home_relative_values_and_the_global_config() {
    let root = scratch("hooks-path-home");
    let ws = root.join("ws");
    let home = root.join("home");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::create_dir_all(home.join(".config/git")).unwrap();
    std::fs::write(ws.join(".git/config"), "[core]\n\thooksPath = ~/repo-hooks\n").unwrap();
    std::fs::write(home.join(".gitconfig"), "[core]\n\thooksPath = ~/.githooks\n").unwrap();
    std::fs::write(
        home.join(".config/git/config"),
        "[core]\n\thooksPath = tools/shared-hooks\n",
    )
    .unwrap();
    let got = git_entries(&ws, Some(&home), &[]);
    for expected in [
        home.join("repo-hooks"),
        home.join(".githooks"),
        ws.join("tools/shared-hooks"),
    ] {
        assert!(tree(&got, &expected), "{expected:?} in {got:?}");
    }
    assert!(!denies(&got, &ws.join("~")), "{got:?}");
    let got = git_entries(&ws, None, &[]);
    assert!(!denies(&got, &ws.join("~")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn hooks_path_under_a_named_user_protects_both_homes_it_can_name() {
    let root = scratch("hooks-path-user");
    let ws = root.join("ws");
    let home = root.join("users/me");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let floor_for = |value: &str, user_home: Option<&Path>| {
        std::fs::write(
            ws.join(".git/config"),
            format!("[core]\n\thooksPath = {value}\n"),
        )
        .unwrap();
        git_entries(&ws, user_home, &[])
    };
    let got = floor_for("~alice/hooks", Some(&home));
    for expected in [home.join("hooks"), root.join("users/alice/hooks")] {
        assert!(tree(&got, &expected), "{expected:?} in {got:?}");
    }
    let in_ws = ws.join("~alice/hooks");
    assert!(!denies(&got, &in_ws), "{got:?}");
    let got = floor_for("~alice/hooks", None);
    assert!(!denies(&got, &in_ws), "{got:?}");
    let got = floor_for("tools/hooks", Some(&home));
    assert!(tree(&got, ws.join("tools/hooks")), "{got:?}");
    assert!(!tree(&got, home.join("tools/hooks")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn hooks_path_is_the_last_assignment_git_reads() {
    let root = scratch("hooks-path-last");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    let floor_for = |config: &str| {
        std::fs::write(ws.join(".git/config"), config).unwrap();
        git_entries(&ws, None, &[])
    };
    let got = floor_for(concat!(
        "[core]\n\thooksPath = first-hooks\n\thooksPath = second-hooks\n",
        "[user]\n\tname = someone\n",
        "[core] hooksPath = \"last hooks\" ; trailing\n",
        "[core \"sub\"]\n\thooksPath = sub-hooks\n",
    ));
    assert!(tree(&got, ws.join("last hooks")), "{got:?}");
    for stale in ["first-hooks", "second-hooks", "sub-hooks"] {
        assert!(!tree(&got, ws.join(stale)), "{stale} in {got:?}");
    }
    let got = floor_for("[core]\n\thooksPath =\n\thooksPath = back-hooks\n");
    assert!(tree(&got, ws.join("back-hooks")), "{got:?}");
    let got = floor_for("[core]\n\thooksPath = gone-hooks\n[core]\n\thooksPath = \"\"\n");
    assert!(!tree(&got, ws.join("gone-hooks")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn hooks_path_follows_includes_in_place() {
    let root = scratch("hooks-path-include");
    let ws = root.join("ws");
    let home = root.join("home");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(ws.join("team.gitconfig"), "[core]\n\thooksPath = team-hooks\n").unwrap();
    std::fs::write(
        home.join("personal.gitconfig"),
        "[core]\n\thooksPath = ~/personal-hooks\n",
    )
    .unwrap();
    let floor_for = |config: &str| {
        std::fs::write(ws.join(".git/config"), config).unwrap();
        git_entries(&ws, Some(&home), &[])
    };
    let got =
        floor_for("[core]\n\thooksPath = repo-hooks\n[include]\n\tpath = ../team.gitconfig\n");
    assert!(tree(&got, ws.join("team-hooks")), "{got:?}");
    assert!(!tree(&got, ws.join("repo-hooks")), "{got:?}");
    assert!(file(&got, ws.join("team.gitconfig")), "{got:?}");
    let got =
        floor_for("[include]\n\tpath = ../team.gitconfig\n[core]\n\thooksPath = repo-hooks\n");
    assert!(tree(&got, ws.join("repo-hooks")), "{got:?}");
    assert!(!tree(&got, ws.join("team-hooks")), "{got:?}");
    let got = floor_for("[include]\n\tpath = ~/personal.gitconfig\n\tpath = missing.gitconfig\n");
    assert!(tree(&got, home.join("personal-hooks")), "{got:?}");
    assert!(file(&got, home.join("personal.gitconfig")), "{got:?}");
    assert!(file(&got, ws.join(".git/missing.gitconfig")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_include_chain_past_the_bound_is_unread_not_skipped() {
    let root = scratch("include-depth");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::write(
        ws.join(".git/config"),
        "[core]\n\thooksPath = loop-hooks\n[include]\n\tpath = config\n",
    )
    .unwrap();
    let got = entries(&ws, None, &[]);
    assert!(tree(&got.protected, ws.join("loop-hooks")), "{got:?}");
    assert!(
        got.unread
            .iter()
            .all(|unread| matches!(unread, GitMetadataUnread::IncludesUnfollowed { .. })),
        "{:?}",
        got.unread
    );
    assert!(!got.unread.is_empty());
    let chain = |links: usize| {
        for level in 0..links {
            std::fs::write(
                ws.join(format!(".git/level{level}")),
                format!("[include]\n\tpath = level{}\n", level + 1),
            )
            .unwrap();
        }
        std::fs::write(
            ws.join(format!(".git/level{links}")),
            "[core]\n\thooksPath = deep-hooks\n",
        )
        .unwrap();
        std::fs::write(ws.join(".git/config"), "[include]\n\tpath = level0\n").unwrap();
        entries(&ws, None, &[])
    };
    let followed = chain(GIT_CONFIG_INCLUDE_DEPTH - 1);
    assert!(tree(&followed.protected, ws.join("deep-hooks")), "{followed:?}");
    assert!(followed.unread.is_empty(), "{:?}", followed.unread);
    let past = chain(GIT_CONFIG_INCLUDE_DEPTH);
    assert!(!tree(&past.protected, ws.join("deep-hooks")), "{past:?}");
    assert!(
        past.unread.iter().any(|unread| matches!(
            unread,
            GitMetadataUnread::IncludesUnfollowed { path, .. }
                if *path == ws.join(format!(".git/level{GIT_CONFIG_INCLUDE_DEPTH}"))
        )),
        "{:?}",
        past.unread
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_include_that_cannot_be_resolved_is_unread_not_skipped() {
    let root = scratch("include-unresolved");
    let ws = root.join("ws");
    let home = root.join("home");
    let config = ws.join(".git/config");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    for (text, value, user_home, reason) in [
        (
            "[include]\n\tpath = ~bob/team\n",
            "~bob/team",
            Some(&home),
            "is under another user's home",
        ),
        (
            "[include]\n\tpath = ~/bob/team\n",
            "~/bob/team",
            None,
            "is under a home directory that is not known",
        ),
        (
            "[include]\n\tpath = %(prefix)/etc/team\n",
            "%(prefix)/etc/team",
            Some(&home),
            "is under git's install prefix",
        ),
        ("[include]\n\tpath =\n", "", Some(&home), "is empty"),
    ] {
        std::fs::write(&config, text).unwrap();
        let got = entries(&ws, user_home.map(PathBuf::as_path), std::slice::from_ref(&ws));
        let want = GitMetadataUnread::Unreadable {
            path: config.clone(),
            reason: format!("its include {value:?} {reason}, not resolved here"),
        };
        assert!(got.unread.contains(&want), "{text}: {:?}", got.unread);
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_conditional_include_protects_its_hooks_path_beside_the_effective_one() {
    let root = scratch("include-if");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::write(ws.join(".git/work.gitconfig"), "[core]\n\thooksPath = work-hooks\n").unwrap();
    std::fs::write(
        ws.join(".git/config"),
        "[core]\n\thooksPath = repo-hooks\n[includeIf \"gitdir:/opt/x/\"]\n\tpath = work.gitconfig\n",
    )
    .unwrap();
    let got = git_entries(&ws, None, &[]);
    assert!(tree(&got, ws.join("repo-hooks")), "{got:?}");
    assert!(tree(&got, ws.join("work-hooks")), "{got:?}");
    assert!(file(&got, ws.join(".git/work.gitconfig")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_dotted_header_splits_at_its_first_dot() {
    let root = scratch("dotted-header");
    let ws = root.join("ws");
    write_hooks_config(&ws.join(".git/work.gitconfig"), "work-hooks");
    write_hooks_config(&ws.join(".git/team.gitconfig"), "team-hooks");
    std::fs::write(
        ws.join(".git/config"),
        concat!(
            "[IncludeIf.GitDir]\n\tpath = work.gitconfig\n",
            "[includeIf.or \"gitdir:/opt/x/\"]\n\tpath = team.gitconfig\n",
            "[ \"x\"]\n\tname = v\n",
            "[core.x]\n\thooksPath = sub-hooks\n",
            "[core]\n\thooksPath = repo-hooks\n",
        ),
    )
    .unwrap();
    let got = git_entries(&ws, None, &[]);
    for expected in ["repo-hooks", "work-hooks", "team-hooks"] {
        assert!(tree(&got, ws.join(expected)), "{expected} missing from {got:?}");
    }
    assert!(!tree(&got, ws.join("sub-hooks")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_config_line_git_rejects_leaves_the_file_unread() {
    let root = scratch("rejected-line");
    let ws = root.join("ws");
    let config = ws.join(".git/config");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::write(
        &config,
        concat!(
            "[core]\n\thooksPath = early-hooks\n",
            "[includeIf.gitdir:/path]\n\tpath = work.gitconfig\n",
            "[core]\n\thooksPath = late-hooks\n",
        ),
    )
    .unwrap();
    let got = entries(&ws, None, &[]);
    let rejected = GitMetadataUnread::Unreadable {
        path: config.clone(),
        reason: "its line 3 does not parse as git config, so nothing from there on is read"
            .to_owned(),
    };
    assert!(got.unread.contains(&rejected), "{:?}", got.unread);
    assert!(tree(&got.protected, ws.join("early-hooks")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// A hooks path at or above a write root is narrowed to the hooks git runs by name there.
#[test]
fn a_hooks_path_holding_a_write_root_is_narrowed_to_hook_names() {
    let root = scratch("narrowed");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::write(ws.join(".git/config"), "[core]\n\thooksPath = .\n").unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(!tree(&got, &ws), "the workspace itself must not be denied: {got:?}");
    assert!(has(&got, ws.join("pre-commit"), GitPathKind::HookFile), "{got:?}");
    assert!(has(&got, ws.join("fsmonitor-watchman"), GitPathKind::HookFile), "{got:?}");
    assert!(!denies(&got, &ws.join("README.md")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// A stow'd `~/.gitconfig` is read through its link and protected as named, where it leads and
/// as the link node itself.
#[cfg(unix)]
#[test]
fn configs_are_read_through_symlinks_and_protected_where_they_lead() {
    let root = scratch("symlinks");
    let ws = root.join("ws");
    let home = root.join("home");
    let dotfiles = root.join("dotfiles");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    write_hooks_config(&dotfiles.join("gitconfig"), "~/stowed-hooks");
    std::os::unix::fs::symlink(dotfiles.join("gitconfig"), home.join(".gitconfig")).unwrap();
    let got = git_entries(&ws, Some(&home), &[]);
    assert!(file(&got, home.join(".gitconfig")), "{got:?}");
    assert!(file(&got, dotfiles.join("gitconfig")), "{got:?}");
    assert!(
        has(&got, home.join(".gitconfig"), GitPathKind::LinkNode),
        "{got:?}"
    );
    assert!(tree(&got, home.join("stowed-hooks")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// A workspace that is a linked worktree: its `.git` file, its git directory's pointer files and
/// `config.worktree`, and the common directory's hooks and config. The other linked worktrees'
/// pointer files are not (Fuigo removes its own worktrees).
#[test]
fn p158_a_linked_worktree_workspace_protects_its_pointers_and_the_common_dir() {
    let root = scratch("linked");
    let main = root.join("main");
    let ws = root.join("wt");
    let gitdir = main.join(".git/worktrees/wt");
    std::fs::create_dir_all(&gitdir).unwrap();
    std::fs::create_dir_all(main.join(".git/worktrees/other")).unwrap();
    std::fs::write(main.join(".git/worktrees/other/gitdir"), "/elsewhere/.git\n").unwrap();
    std::fs::create_dir_all(main.join(".git/hooks")).unwrap();
    std::fs::write(main.join(".git/config"), "[core]\n\thooksPath = shared-hooks\n").unwrap();
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join(".git"), format!("gitdir: {}\n", gitdir.display())).unwrap();
    std::fs::write(gitdir.join("commondir"), "../..\n").unwrap();
    std::fs::write(gitdir.join("gitdir"), format!("{}\n", ws.join(".git").display())).unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(file(&got, ws.join(".git")), "{got:?}");
    assert!(file(&got, gitdir.join("commondir")), "{got:?}");
    assert!(file(&got, gitdir.join("gitdir")), "{got:?}");
    assert!(tree(&got, main.join(".git/hooks")), "{got:?}");
    assert!(file(&got, main.join(".git/config")), "{got:?}");
    assert!(tree(&got, ws.join("shared-hooks")), "{got:?}");
    assert!(
        !denies(&got, &main.join(".git/worktrees/other/gitdir")),
        "{got:?}"
    );
    assert!(!tree(&got, gitdir.join("hooks")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Submodule git directories present under `.git/modules` (a directory holding `HEAD`, nested
/// ones under their parent's `modules`) get the same entries and their hooks paths, resolved
/// against the workspace; a directory on the way that is no git directory gets none.
#[test]
fn p158_present_submodule_git_dirs_are_protected() {
    let root = scratch("submodules");
    let ws = root.join("ws");
    let sub = ws.join(".git/modules/libs/a");
    let nested = sub.join("modules/inner");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(sub.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(nested.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(sub.join("config"), "[core]\n\thooksPath = sub-hooks\n").unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    for dir in [&sub, &nested] {
        assert!(tree(&got, dir.join("hooks")), "{dir:?}: {got:?}");
        assert!(file(&got, dir.join("config")), "{dir:?}: {got:?}");
    }
    assert!(tree(&got, ws.join("sub-hooks")), "{got:?}");
    assert!(!tree(&got, ws.join(".git/modules/libs/hooks")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// `extensions.worktreeConfig` makes `config.worktree` a file git reads (a required file); the
/// other linked worktrees stay uncovered.
#[test]
fn p158_worktree_config_extension_makes_config_worktree_required() {
    let root = scratch("wt-config");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git/worktrees/other")).unwrap();
    std::fs::write(
        ws.join(".git/worktrees/other/gitdir"),
        format!("{}\n", root.join("other/.git").display()),
    )
    .unwrap();
    std::fs::write(
        ws.join(".git/worktrees/other/config.worktree"),
        "[core]\n\thooksPath = other-hooks\n",
    )
    .unwrap();
    std::fs::write(ws.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(
        has(&got, ws.join(".git/config.worktree"), GitPathKind::OptionalFile),
        "{got:?}"
    );
    assert!(
        !denies(&got, &ws.join(".git/worktrees/other/config.worktree")),
        "{got:?}"
    );
    std::fs::write(ws.join(".git/config"), "[extensions]\n\tworktreeConfig = true\n").unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(file(&got, ws.join(".git/config.worktree")), "{got:?}");
    // The other linked worktrees are not covered (Fuigo removes its own worktrees)
    assert!(
        !denies(&got, &ws.join(".git/worktrees/other/config.worktree")),
        "{got:?}"
    );
    assert!(!tree(&got, root.join("other/other-hooks")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn a_fifo_in_a_configs_place_does_not_stall_the_scan() {
    let root = scratch("fifo");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    let fifo = std::ffi::CString::new(
        ws.join(".git/config")
            .into_os_string()
            .into_encoded_bytes(),
    )
    .unwrap();
    // SAFETY: `fifo` is a valid NUL-terminated path and `mkfifo` reads nothing else.
    assert_eq!(0, unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) });
    let (done, finished) = std::sync::mpsc::channel();
    let scanned = ws.clone();
    std::thread::spawn(move || {
        let _ = done.send(entries(&scanned, None, &[]));
    });
    let got = finished
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("the scan must return with a FIFO in the config's place");
    assert!(file(&got.protected, ws.join(".git/config")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_modules_tree_past_the_bound_is_unread() {
    let root = scratch("modules-bound");
    let ws = root.join("ws");
    let modules = ws.join(".git/modules");
    for index in 0..GIT_DIRS_LIMIT {
        std::fs::create_dir_all(modules.join(format!("m{index}"))).unwrap();
    }
    let got = entries(&ws, None, &[]);
    assert!(got.unread.is_empty(), "{:?}", got.unread);
    std::fs::create_dir_all(modules.join("one-more")).unwrap();
    let got = entries(&ws, None, &[]);
    assert_eq!(
        vec![GitMetadataUnread::GitDirsUnlisted {
            tree: modules.clone(),
            limit: GIT_DIRS_LIMIT,
        }],
        got.unread
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_config_past_the_read_limit_is_unread() {
    let root = scratch("too-large");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    let big = usize::try_from(GIT_METADATA_READ_LIMIT).unwrap() + 1;
    std::fs::write(ws.join(".git/config"), "#".repeat(big)).unwrap();
    let got = entries(&ws, None, &[]);
    assert!(
        got.unread.contains(&GitMetadataUnread::TooLarge {
            path: ws.join(".git/config"),
            limit: GIT_METADATA_READ_LIMIT,
        }),
        "{:?}",
        got.unread
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_global_config_is_where_the_environment_puts_it() {
    let root = scratch("global-env");
    let ws = root.join("ws");
    let home = root.join("home");
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    write_hooks_config(&home.join(".gitconfig"), "~/home-hooks");
    write_hooks_config(&home.join(".config/git/config"), "~/xdg-default-hooks");
    write_hooks_config(&elsewhere.join("xdg/git/config"), "~/xdg-hooks");
    write_hooks_config(&elsewhere.join("global.gitconfig"), "~/global-hooks");
    let run = |env: &GitConfigEnv| {
        let got = super::git_entries_in(&ws, Some(&home), &[], env);
        assert!(got.unread.is_empty(), "{:?}", got.unread);
        got.protected
    };
    let hooks = |name: &str| home.join(name);
    let got = run(&GitConfigEnv::default());
    assert!(tree(&got, hooks("home-hooks")), "{got:?}");
    assert!(tree(&got, hooks("xdg-default-hooks")), "{got:?}");
    assert!(file(&got, home.join(".gitconfig")), "{got:?}");
    assert!(file(&got, home.join(".config/git/config")), "{got:?}");
    assert!(!tree(&got, hooks("xdg-hooks")), "{got:?}");
    let xdg = elsewhere.join("xdg");
    let got = run(&env(None, xdg.to_str()));
    assert!(tree(&got, hooks("xdg-hooks")), "{got:?}");
    assert!(file(&got, xdg.join("git/config")), "{got:?}");
    assert!(!tree(&got, hooks("xdg-default-hooks")), "{got:?}");
    let got = run(&env(None, Some("")));
    assert!(tree(&got, hooks("xdg-default-hooks")), "{got:?}");
    let global = elsewhere.join("global.gitconfig");
    let got = run(&env(global.to_str(), xdg.to_str()));
    assert!(tree(&got, hooks("global-hooks")), "{got:?}");
    assert!(file(&got, &global), "{got:?}");
    for not_read in ["home-hooks", "xdg-hooks", "xdg-default-hooks"] {
        assert!(!tree(&got, hooks(not_read)), "{not_read} in {got:?}");
    }
    let got = run(&env(Some(""), None));
    for not_read in ["home-hooks", "xdg-default-hooks", "global-hooks"] {
        assert!(!tree(&got, hooks(not_read)), "{not_read} in {got:?}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn a_device_as_the_global_config_is_read_not_protected_and_a_relative_one_is_unread() {
    let root = scratch("global-env-edge");
    let ws = root.join("ws");
    let home = root.join("home");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    write_hooks_config(&home.join(".gitconfig"), "~/home-hooks");
    let got = super::git_entries_in(&ws, Some(&home), &[], &env(Some("/dev/null"), None));
    assert!(got.unread.is_empty(), "{:?}", got.unread);
    assert!(!denies(&got.protected, Path::new("/dev/null")), "{got:?}");
    assert!(!tree(&got.protected, home.join("home-hooks")), "{got:?}");
    for (config_global, xdg, name) in [
        (Some("rel/gitconfig"), None, GIT_CONFIG_GLOBAL_ENV),
        (None, Some("rel/xdg"), XDG_CONFIG_HOME_ENV),
    ] {
        let got = super::git_entries_in(&ws, Some(&home), &[], &env(config_global, xdg));
        let [GitMetadataUnread::Unreadable { path, reason }] = got.unread.as_slice() else {
            panic!("{name}: {:?}", got.unread);
        };
        assert_eq!(Path::new(config_global.or(xdg).unwrap()), path.as_path());
        assert!(reason.contains(name) && reason.contains("relative"), "{reason}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_host_env_is_read_variable_for_variable() {
    assert_eq!("GIT_CONFIG_GLOBAL", GIT_CONFIG_GLOBAL_ENV);
    assert_eq!("XDG_CONFIG_HOME", XDG_CONFIG_HOME_ENV);
    let got = GitConfigEnv::from_lookup(|name| match name {
        GIT_CONFIG_GLOBAL_ENV => Some(OsString::from("/g")),
        _ => None,
    });
    assert_eq!(env(Some("/g"), None), got);
}

/// The Linux bwrap plan binds every target inside a writable root read-only, creating git's own
/// layout where missing, skipping what lies outside the roots and an optional file, pinning the
/// ancestors; a link node inside a root and a missing narrowed hook refuse.
#[cfg(target_os = "linux")]
#[test]
fn p158_linux_plan_binds_git_targets_inside_writable_roots() {
    use crate::hook_write_deny::{HookWriteDenyBwrapPlan, HookWriteDenyError, add_git_leaves_to_plan};
    let root = scratch("plan");
    let ws = root.join("ws");
    let outside = root.join("outside");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::write(ws.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let mut got = git_entries(&ws, None, std::slice::from_ref(&ws));
    got.push(GitProtectedPath {
        path: outside.join("gitconfig"),
        kind: GitPathKind::File,
    });
    let empty = || HookWriteDenyBwrapPlan {
        ancestor_rw_binds: Vec::new(),
        leaves: Vec::new(),
        dir_json_snapshots: Vec::new(),
        pinned: Vec::new(),
        rebinds: Vec::new(),
    };
    let mut plan = empty();
    add_git_leaves_to_plan(&mut plan, &got, std::slice::from_ref(&ws)).expect("plan");
    let leaves: Vec<&Path> = plan.leaves.iter().map(|leaf| leaf.path.as_path()).collect();
    for expected in [".git/hooks", ".git/config"] {
        assert!(leaves.contains(&ws.join(expected).as_path()), "{expected}: {leaves:?}");
    }
    assert!(ws.join(".git/hooks").is_dir(), "a missing hooks dir is created to be bound");
    assert!(!ws.join(".git/config.worktree").exists(), "an optional file is not created");
    assert!(!leaves.contains(&outside.join("gitconfig").as_path()), "{leaves:?}");
    assert!(!outside.join("gitconfig").exists());
    assert!(plan.ancestor_rw_binds.contains(&ws.join(".git")), "{:?}", plan.ancestor_rw_binds);
    assert!(plan.ancestor_rw_binds.contains(&ws), "{:?}", plan.ancestor_rw_binds);
    for leaf in &leaves {
        assert!(!plan.ancestor_rw_binds.iter().any(|a| a == leaf), "{leaf:?}");
    }

    let link = vec![GitProtectedPath {
        path: ws.join(".git/config"),
        kind: GitPathKind::LinkNode,
    }];
    let err = add_git_leaves_to_plan(&mut empty(), &link, std::slice::from_ref(&ws)).unwrap_err();
    assert!(matches!(err, HookWriteDenyError::GitSymlink { .. }), "{err:?}");
    let hook = vec![GitProtectedPath {
        path: ws.join("pre-commit"),
        kind: GitPathKind::HookFile,
    }];
    let err = add_git_leaves_to_plan(&mut empty(), &hook, std::slice::from_ref(&ws)).unwrap_err();
    assert!(matches!(err, HookWriteDenyError::GitHookMissing { .. }), "{err:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r1 #1: an ordinary `.git` must not grow a `commondir` that sends git elsewhere.
#[test]
fn p158_r1_an_ordinary_git_dir_denies_a_new_commondir() {
    let root = scratch("r1-commondir");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(
        has(&got, ws.join(".git/commondir"), GitPathKind::OptionalFile),
        "{got:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r1 #2: a symlinked `.git` is a link node, so it cannot be re-pointed.
#[cfg(unix)]
#[test]
fn p158_r1_a_symlinked_git_dir_is_a_link_node() {
    let root = scratch("r1-git-link");
    let ws = root.join("ws");
    let meta = root.join("metadata");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(meta.join("hooks")).unwrap();
    std::os::unix::fs::symlink(&meta, ws.join(".git")).unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(has(&got, ws.join(".git"), GitPathKind::LinkNode), "{got:?}");
    assert!(tree(&got, meta.join("hooks")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r1 #3: a hook that is a symlink is protected where it leads.
#[cfg(unix)]
#[test]
fn p158_r1_a_symlinked_hook_protects_its_target() {
    let root = scratch("r1-hook-link");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git/hooks")).unwrap();
    std::fs::create_dir_all(ws.join("scripts")).unwrap();
    std::fs::write(ws.join("scripts/pre-commit"), "#!/bin/sh\n").unwrap();
    std::os::unix::fs::symlink("../../scripts/pre-commit", ws.join(".git/hooks/pre-commit"))
        .unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(file(&got, ws.join("scripts/pre-commit")), "{got:?}");
    assert!(denies(&got, &ws.join("scripts/pre-commit")));
    assert!(!denies(&got, &ws.join("scripts/other.sh")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r1 #4: `..` after a symlink resolves where the kernel puts it.
#[cfg(unix)]
#[test]
fn p158_r1_dot_dot_after_a_symlink_resolves_as_the_kernel_does() {
    let root = scratch("r1-dotdot");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::create_dir_all(ws.join("target/deeper")).unwrap();
    std::os::unix::fs::symlink(ws.join("target/deeper"), ws.join("alias")).unwrap();
    std::fs::write(ws.join(".git/config"), "[core]\n\thooksPath = alias/../hooks\n").unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(tree(&got, ws.join("target/hooks")), "{got:?}");
    assert!(has(&got, ws.join("alias"), GitPathKind::LinkNode), "{got:?}");
    assert!(!tree(&got, ws.join("hooks")), "the lexical spelling is not git's: {got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r1 #5: a present submodule's checkout pointer is protected, and a linked-worktree
/// workspace's submodules get their entries.
#[test]
fn p158_r1_present_submodule_checkout_pointers_are_protected() {
    let root = scratch("r1-sub-pointer");
    let ws = root.join("ws");
    let module = ws.join(".git/modules/sub");
    std::fs::create_dir_all(&module).unwrap();
    std::fs::write(module.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(module.join("config"), "[core]\n\tworktree = ../../../sub\n").unwrap();
    std::fs::create_dir_all(ws.join("sub")).unwrap();
    std::fs::write(ws.join("sub/.git"), "gitdir: ../.git/modules/sub\n").unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(file(&got, ws.join("sub/.git")), "{got:?}");

    let main = root.join("main");
    let wt = root.join("wt");
    let gitdir = main.join(".git/worktrees/wt");
    let wt_module = main.join(".git/modules/lib");
    std::fs::create_dir_all(&gitdir).unwrap();
    std::fs::create_dir_all(&wt_module).unwrap();
    std::fs::write(wt_module.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::create_dir_all(&wt).unwrap();
    std::fs::write(wt.join(".git"), format!("gitdir: {}\n", gitdir.display())).unwrap();
    std::fs::write(gitdir.join("commondir"), "../..\n").unwrap();
    let got = git_entries(&wt, None, std::slice::from_ref(&wt));
    assert!(tree(&got, wt_module.join("hooks")), "{got:?}");
    assert!(file(&got, wt_module.join("config")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r1 #6: a `core.hooksPath` in the system config is protected; the system config is
/// where `GIT_CONFIG_SYSTEM` / `GIT_CONFIG_NOSYSTEM` put it.
#[cfg(unix)]
#[test]
fn p158_r1_the_system_config_hooks_path_is_protected() {
    let root = scratch("r1-system");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    let system = root.join("etc/gitconfig");
    write_hooks_config(&system, ".company-hooks");
    let env = GitConfigEnv {
        system_configs: vec![system.clone()],
        ..GitConfigEnv::default()
    };
    let got = super::git_entries_in(&ws, None, std::slice::from_ref(&ws), &env);
    assert!(got.unread.is_empty(), "{:?}", got.unread);
    assert!(tree(&got.protected, ws.join(".company-hooks")), "{got:?}");

    let present = |_: &Path| true;
    let (configs, unread) = super::system_configs(None, true, present);
    assert!(configs.is_empty() && unread.is_none());
    let (configs, unread) = super::system_configs(Some(OsString::from("/x/gitconfig")), false, present);
    assert_eq!(configs, vec![PathBuf::from("/x/gitconfig")]);
    assert!(unread.is_none());
    let (configs, _) = super::system_configs(Some(OsString::new()), false, present);
    assert!(configs.is_empty());
    let (configs, unread) = super::system_configs(Some(OsString::from("rel")), false, present);
    assert!(configs.is_empty() && unread.is_some());
    let (configs, _) = super::system_configs(None, false, |path| path == Path::new("/etc/gitconfig"));
    assert_eq!(configs, vec![PathBuf::from("/etc/gitconfig")]);
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r1 #7: a submodule or separate-git-dir checkout has no `commondir`; it is denied where it
/// can be but never made required (Linux would create it empty, which git refuses).
#[test]
fn p158_r1_a_missing_pointer_file_is_optional() {
    let root = scratch("r1-separate");
    let ws = root.join("ws");
    let gitdir = root.join("separate.git");
    std::fs::create_dir_all(&gitdir).unwrap();
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join(".git"), format!("gitdir: {}\n", gitdir.display())).unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&root));
    assert!(
        has(&got, gitdir.join("commondir"), GitPathKind::OptionalFile),
        "{got:?}"
    );
    assert!(tree(&got, gitdir.join("hooks")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r1 #8: `core.hooksPath=/dev/null` (git's way to disable hooks) protects no device.
#[cfg(unix)]
#[test]
fn p158_r1_a_device_hooks_path_is_not_protected() {
    let root = scratch("r1-devnull");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::write(ws.join(".git/config"), "[core]\n\thooksPath = /dev/null\n").unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(!denies(&got, Path::new("/dev/null")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r1 #9: a shared relative `core.hooksPath` is anchored on the workspace only, so the
/// other linked worktrees (which Fuigo removes) get no protected trees.
#[test]
fn p158_r1_other_worktrees_are_not_anchored() {
    let root = scratch("r1-anchors");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git/worktrees/other")).unwrap();
    std::fs::write(
        ws.join(".git/worktrees/other/gitdir"),
        format!("{}\n", root.join("other/.git").display()),
    )
    .unwrap();
    std::fs::write(ws.join(".git/config"), "[core]\n\thooksPath = .husky\n").unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&root));
    assert!(tree(&got, ws.join(".husky")), "{got:?}");
    assert!(!tree(&got, root.join("other/.husky")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r1 #3 on Linux: a symlinked hook inside a bound hooks tree does not refuse, and its
/// target is bound; a missing optional pointer is not created.
#[cfg(target_os = "linux")]
#[test]
fn p158_r1_linux_plan_binds_symlinked_hook_targets_and_skips_missing_pointers() {
    use crate::hook_write_deny::{HookWriteDenyBwrapPlan, add_git_leaves_to_plan};
    let root = scratch("r1-plan");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git/hooks")).unwrap();
    std::fs::write(ws.join(".git/config"), "").unwrap();
    std::fs::create_dir_all(ws.join("scripts")).unwrap();
    std::fs::write(ws.join("scripts/pre-commit"), "#!/bin/sh\n").unwrap();
    std::os::unix::fs::symlink("../../scripts/pre-commit", ws.join(".git/hooks/pre-commit"))
        .unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    let mut plan = HookWriteDenyBwrapPlan {
        ancestor_rw_binds: Vec::new(),
        leaves: Vec::new(),
        dir_json_snapshots: Vec::new(),
        pinned: Vec::new(),
        rebinds: Vec::new(),
    };
    add_git_leaves_to_plan(&mut plan, &got, std::slice::from_ref(&ws)).expect("plan");
    let leaves: Vec<&Path> = plan.leaves.iter().map(|leaf| leaf.path.as_path()).collect();
    assert!(leaves.contains(&ws.join("scripts/pre-commit").as_path()), "{leaves:?}");
    assert!(!ws.join(".git/commondir").exists(), "a missing pointer must not be created");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r2 N1: a dangling hook link protects what it would lead to, as a hook that must exist
/// (Linux refuses; macOS denies creating it).
#[cfg(unix)]
#[test]
fn p158_r2_a_dangling_hook_link_protects_its_future_target() {
    let root = scratch("r2-dangling");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git/hooks")).unwrap();
    std::os::unix::fs::symlink("../../scripts/pre-commit", ws.join(".git/hooks/pre-commit"))
        .unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(
        has(&got, ws.join("scripts/pre-commit"), GitPathKind::HookFile),
        "{got:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r2 N2: a submodule git directory must not grow a `commondir` either.
#[test]
fn p158_r2_a_submodule_git_dir_denies_a_new_commondir() {
    let root = scratch("r2-sub-commondir");
    let ws = root.join("ws");
    let module = ws.join(".git/modules/sub");
    std::fs::create_dir_all(&module).unwrap();
    std::fs::write(module.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(
        has(&got, module.join("commondir"), GitPathKind::OptionalFile),
        "{got:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r2 N3: a relative global `core.hooksPath` is protected in every present submodule
/// checkout too, where a commit inside the submodule runs it.
#[test]
fn p158_r2_an_inherited_relative_hooks_path_covers_submodule_checkouts() {
    let root = scratch("r2-inherited");
    let ws = root.join("ws");
    let home = root.join("home");
    let module = ws.join(".git/modules/sub");
    std::fs::create_dir_all(&module).unwrap();
    std::fs::write(module.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(module.join("config"), "[core]\n\tworktree = ../../../sub\n").unwrap();
    std::fs::create_dir_all(ws.join("sub")).unwrap();
    write_hooks_config(&home.join(".gitconfig"), ".company-hooks");
    let got = git_entries(&ws, Some(&home), std::slice::from_ref(&ws));
    assert!(tree(&got, ws.join(".company-hooks")), "{got:?}");
    assert!(tree(&got, ws.join("sub/.company-hooks")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r2 N6: a protected hook with a hard-link alias refuses (a write through the alias
/// would change it), and so does a hard-linked config.
#[cfg(unix)]
#[test]
fn p158_r2_a_hard_linked_hook_or_config_refuses() {
    let root = scratch("r2-hardlink");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git/hooks")).unwrap();
    std::fs::create_dir_all(ws.join("scripts")).unwrap();
    std::fs::write(ws.join("scripts/pre-commit"), "#!/bin/sh\n").unwrap();
    std::fs::hard_link(ws.join("scripts/pre-commit"), ws.join(".git/hooks/pre-commit")).unwrap();
    let got = entries(&ws, None, std::slice::from_ref(&ws));
    assert!(
        got.unread.contains(&GitMetadataUnread::HardLinked {
            path: ws.join(".git/hooks/pre-commit"),
        }),
        "{:?}",
        got.unread
    );
    std::fs::remove_file(ws.join(".git/hooks/pre-commit")).unwrap();
    std::fs::write(ws.join(".git/config"), "").unwrap();
    std::fs::hard_link(ws.join(".git/config"), ws.join("config-alias")).unwrap();
    let got = entries(&ws, None, std::slice::from_ref(&ws));
    assert!(
        got.unread.contains(&GitMetadataUnread::HardLinked {
            path: ws.join(".git/config"),
        }),
        "{:?}",
        got.unread
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r2 N8: an unquoted value keeps its inner tab as written, and the space spelling older
/// git reads is protected beside it.
#[test]
fn p158_r2_inner_whitespace_is_kept_and_both_spellings_protected() {
    let root = scratch("r2-tab");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::write(ws.join(".git/config"), "[core]\n\thooksPath = a\tb\n").unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(tree(&got, ws.join("a\tb")), "{got:?}");
    assert!(tree(&got, ws.join("a b")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Runs `scan` with an unprivileged user's file permissions, so a mode bit is really enforced:
/// as root (the Hetzner gate runs as root) on a thread whose filesystem ids are `nobody`'s
/// (Linux keeps them per thread, and leaving fsuid 0 drops the DAC override capabilities).
/// `unlistable` must fail to list there, or the test fails: it never passes without asserting.
#[cfg(unix)]
fn unprivileged<T: Send>(unlistable: &Path, scan: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                // SAFETY: geteuid is always safe.
                if unsafe { libc::geteuid() } == 0 {
                    drop_file_identity();
                }
                assert!(
                    std::fs::read_dir(unlistable).is_err(),
                    "{} is still listable, so this test cannot assert",
                    unlistable.display()
                );
                scan()
            })
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

#[cfg(target_os = "linux")]
fn drop_file_identity() {
    const NOBODY: libc::uid_t = 65534;
    // SAFETY: setfsgid/setfsuid change only the calling thread's filesystem ids (glibc does not
    // broadcast them to other threads); the thread ends with the scan.
    unsafe {
        libc::setfsgid(NOBODY);
        libc::setfsuid(NOBODY);
    }
    // SAFETY: an invalid id changes nothing and returns the current one
    let now = unsafe { libc::setfsuid(libc::uid_t::MAX) };
    assert_eq!(u32::try_from(now).ok(), Some(NOBODY), "filesystem uid not dropped");
}

#[cfg(all(unix, not(target_os = "linux")))]
fn drop_file_identity() {
    panic!("root lists every directory and this host has no per-thread filesystem id: run unprivileged");
}

/// Astra r3 N6: a protected tree that cannot be listed refuses (it may hide an aliased hook).
/// Run with an unprivileged user's permissions, also as root (Grok G5b).
#[cfg(unix)]
#[test]
fn p158_r3_an_unlistable_hooks_tree_refuses() {
    use std::os::unix::fs::PermissionsExt;
    let root = scratch("r3-unlistable");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git/hooks")).unwrap();
    std::fs::set_permissions(ws.join(".git/hooks"), std::fs::Permissions::from_mode(0o111)).unwrap();
    let got = unprivileged(&ws.join(".git/hooks"), || {
        entries(&ws, None, std::slice::from_ref(&ws))
    });
    std::fs::set_permissions(ws.join(".git/hooks"), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        got.unread.iter().any(|unread| matches!(
            unread,
            GitMetadataUnread::Unreadable { path, .. } if *path == ws.join(".git/hooks")
        )),
        "{:?}",
        got.unread
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r3 N8: an include whose tab older git reads as a space is read in that spelling too.
#[test]
fn p158_r3_the_tab_variant_of_an_include_is_read() {
    let root = scratch("r3-include-tab");
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::write(ws.join(".git/config"), "[include]\n\tpath = ../a\tb\n").unwrap();
    write_hooks_config(&ws.join("a b"), "space-hooks");
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(file(&got, ws.join("a b")), "{got:?}");
    assert!(file(&got, ws.join("a\tb")), "{got:?}");
    assert!(tree(&got, ws.join("space-hooks")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r3 N11: a pointer keeps every byte but its trailing CR/LF, as git reads it.
#[test]
fn p158_r3_a_pointer_keeps_significant_spaces() {
    let root = scratch("r3-pointer-space");
    let ws = root.join("ws");
    let meta = root.join("meta ");
    std::fs::create_dir_all(meta.join("hooks")).unwrap();
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join(".git"), format!("gitdir: {}\r\n", meta.display())).unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&root));
    assert!(tree(&got, meta.join("hooks")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r3 N12: a `.git` directory with an existing `commondir` protects the common directory.
#[test]
fn p158_r3_a_git_dir_follows_an_existing_commondir() {
    let root = scratch("r3-dir-commondir");
    let ws = root.join("ws");
    let common = ws.join("common-meta");
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::create_dir_all(common.join("hooks")).unwrap();
    std::fs::write(ws.join(".git/commondir"), "../common-meta\n").unwrap();
    std::fs::write(common.join("config"), "[core]\n\thooksPath = shared-hooks\n").unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(file(&got, ws.join(".git/commondir")), "{got:?}");
    assert!(tree(&got, common.join("hooks")), "{got:?}");
    assert!(file(&got, common.join("config")), "{got:?}");
    assert!(tree(&got, ws.join("shared-hooks")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Astra r3 N13: a symlinked submodule git directory is followed and its link protected.
#[cfg(unix)]
#[test]
fn p158_r3_a_symlinked_module_dir_is_followed() {
    let root = scratch("r3-module-link");
    let ws = root.join("ws");
    let meta = ws.join("sub-meta");
    std::fs::create_dir_all(ws.join(".git/modules")).unwrap();
    std::fs::create_dir_all(meta.join("hooks")).unwrap();
    std::fs::write(meta.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    std::os::unix::fs::symlink("../../sub-meta", ws.join(".git/modules/sub")).unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(tree(&got, meta.join("hooks")), "{got:?}");
    assert!(file(&got, meta.join("config")), "{got:?}");
    assert!(
        has(&got, ws.join(".git/modules/sub"), GitPathKind::LinkNode),
        "{got:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Grok G1: a `.git/modules` that cannot be listed (or a directory under it) hides submodule git
/// directories and their hooks; it refuses, as the hooks walk does (N6). Run with an
/// unprivileged user's permissions, also as root.
#[cfg(unix)]
#[test]
fn p158_g1_an_unlistable_modules_tree_refuses() {
    use std::os::unix::fs::PermissionsExt;
    for (tag, blocked) in [("top", ".git/modules"), ("nested", ".git/modules/group")] {
        let root = scratch(&format!("g1-modules-{tag}"));
        let ws = root.join("ws");
        let module = ws.join(".git/modules/group/sub");
        std::fs::create_dir_all(module.join("hooks")).unwrap();
        std::fs::write(module.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let blocked = ws.join(blocked);
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o111)).unwrap();
        let got = unprivileged(&blocked, || entries(&ws, None, std::slice::from_ref(&ws)));
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            got.unread.iter().any(|unread| matches!(
                unread,
                GitMetadataUnread::Unreadable { path, .. } if *path == blocked
            )),
            "{tag}: {:?}",
            got.unread
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// Grok G2: a `.git` or `commondir` pointer whose path is not UTF-8 is not read under a lossy
/// spelling (which misses the directory git uses); it refuses.
#[cfg(target_os = "linux")]
#[test]
fn p158_g2_a_non_utf8_pointer_refuses() {
    use std::os::unix::ffi::OsStrExt as _;
    let root = scratch("g2-pointer-bytes");
    let meta = root.join(std::ffi::OsStr::from_bytes(b"meta-\xff"));
    std::fs::create_dir_all(meta.join("hooks")).unwrap();
    let ws = root.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let mut pointer = b"gitdir: ".to_vec();
    pointer.extend_from_slice(meta.as_os_str().as_bytes());
    pointer.push(b'\n');
    std::fs::write(ws.join(".git"), &pointer).unwrap();
    let got = entries(&ws, None, std::slice::from_ref(&root));
    assert!(
        got.unread.contains(&GitMetadataUnread::NotUtf8 {
            path: ws.join(".git"),
        }),
        "{:?}",
        got.unread
    );
    let ws2 = root.join("ws2");
    std::fs::create_dir_all(ws2.join(".git")).unwrap();
    std::fs::write(ws2.join(".git/commondir"), b"../../meta-\xff\n").unwrap();
    let got = entries(&ws2, None, std::slice::from_ref(&root));
    assert!(
        got.unread.contains(&GitMetadataUnread::NotUtf8 {
            path: ws2.join(".git/commondir"),
        }),
        "{:?}",
        got.unread
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Grok G3: `init.templateDir` (`git init` and `git clone` copy its hooks and config into the
/// new repository) is protected where the configs name it, includes followed in place and a
/// conditional value protected beside the effective one.
#[test]
fn p158_g3_init_template_dir_is_protected() {
    let root = scratch("g3-template");
    let ws = root.join("ws");
    let home = root.join("home");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(home.join(".git-templates/hooks")).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        "[init]\n\ttemplateDir = ~/.git-templates\n[includeIf \"gitdir:~/elsewhere/\"]\n\tpath = more.inc\n",
    )
    .unwrap();
    std::fs::write(
        home.join("more.inc"),
        format!("[init]\n\ttemplatedir = {}\n", root.join("tpl2").display()),
    )
    .unwrap();
    std::fs::write(
        ws.join("sys.gitconfig"),
        format!("[init]\n\ttemplateDir = {}\n", root.join("tpl3").display()),
    )
    .unwrap();
    let env = GitConfigEnv {
        system_configs: vec![ws.join("sys.gitconfig")],
        ..GitConfigEnv::default()
    };
    let got = super::git_entries_in(&ws, Some(&home), std::slice::from_ref(&ws), &env);
    assert!(got.unread.is_empty(), "{:?}", got.unread);
    assert!(tree(&got.protected, home.join(".git-templates")), "{:?}", got.protected);
    assert!(tree(&got.protected, root.join("tpl2")), "{:?}", got.protected);
    assert!(tree(&got.protected, root.join("tpl3")), "{:?}", got.protected);
    let _ = std::fs::remove_dir_all(&root);
}

/// Grok G3: `GIT_TEMPLATE_DIR`, which git reads before `init.templateDir`, is protected too.
#[test]
fn p158_g3_git_template_dir_env_is_protected() {
    let root = scratch("g3-template-env");
    let ws = root.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let tpl = root.join("env-tpl");
    let tpl_value = OsString::from(tpl.as_os_str());
    let env = GitConfigEnv::from_lookup(|name| match name {
        "GIT_TEMPLATE_DIR" => Some(tpl_value.clone()),
        "GIT_CONFIG_NOSYSTEM" => Some(OsString::from("1")),
        _ => None,
    });
    let got = super::git_entries_in(&ws, None, std::slice::from_ref(&ws), &env);
    assert!(got.unread.is_empty(), "{:?}", got.unread);
    assert!(tree(&got.protected, &tpl), "{:?}", got.protected);
    let _ = std::fs::remove_dir_all(&root);
}

/// Grok G3: a template directory holding a write root is narrowed, as a hooks path is, to the
/// files git copies and then reads or runs (its `config` and the hooks).
#[test]
fn p158_g3_a_template_dir_holding_a_write_root_is_narrowed() {
    let root = scratch("g3-template-narrow");
    let ws = root.join("ws");
    let home = root.join("home");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        format!("[init]\n\ttemplateDir = {}\n", root.display()),
    )
    .unwrap();
    let got = git_entries(&ws, Some(&home), std::slice::from_ref(&ws));
    assert!(!tree(&got, &root), "{got:?}");
    assert!(has(&got, root.join("config"), GitPathKind::HookFile), "{got:?}");
    assert!(
        has(&got, root.join("hooks/pre-commit"), GitPathKind::HookFile),
        "{got:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Grok G3: a template directory git resolves from each command's working directory (relative)
/// or its install prefix is not known here; it refuses.
#[test]
fn p158_g3_an_unresolvable_template_dir_is_unread() {
    for value in ["rel/tpl", "%(prefix)/share/tpl"] {
        let root = scratch("g3-template-rel");
        let ws = root.join("ws");
        let home = root.join("home");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join(".gitconfig"), format!("[init]\n\ttemplateDir = {value}\n")).unwrap();
        let got = entries(&ws, Some(&home), std::slice::from_ref(&ws));
        assert!(
            got.unread.iter().any(|unread| matches!(
                unread,
                GitMetadataUnread::Unreadable { path, .. } if *path == home.join(".gitconfig")
            )),
            "{value}: {:?}",
            got.unread
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// Grok G3: a hook in the template directory that is a symlink is protected where it leads
/// (the copy keeps the link).
#[cfg(unix)]
#[test]
fn p158_g3_a_symlinked_template_hook_is_protected_where_it_leads() {
    let root = scratch("g3-template-link");
    let ws = root.join("ws");
    let home = root.join("home");
    std::fs::create_dir_all(ws.join("scripts")).unwrap();
    std::fs::write(ws.join("scripts/pc"), "#!/bin/sh\n").unwrap();
    std::fs::create_dir_all(home.join("tpl/hooks")).unwrap();
    std::os::unix::fs::symlink(ws.join("scripts/pc"), home.join("tpl/hooks/pre-commit")).unwrap();
    std::fs::write(home.join(".gitconfig"), "[init]\n\ttemplateDir = ~/tpl\n").unwrap();
    let got = git_entries(&ws, Some(&home), std::slice::from_ref(&ws));
    assert!(tree(&got, home.join("tpl")), "{got:?}");
    assert!(file(&got, ws.join("scripts/pc")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Grok r2: a template whose `hooks` is a symlink to a directory, or whose `config` (or
/// `config.worktree`) is a symlink to a file, is copied with the links kept; each target is
/// protected, also when the template holds no write root.
#[cfg(unix)]
#[test]
fn p158_g5_symlinked_template_hooks_and_config_are_protected_where_they_lead() {
    let root = scratch("g5-template-links");
    let ws = root.join("ws");
    let home = root.join("home");
    std::fs::create_dir_all(ws.join("tplhooks")).unwrap();
    std::fs::write(ws.join("tplhooks/pre-commit"), "#!/bin/sh\n").unwrap();
    std::fs::write(ws.join("tplconfig"), "[core]\n").unwrap();
    std::fs::write(ws.join("tplwtconfig"), "").unwrap();
    std::fs::create_dir_all(home.join("tpl")).unwrap();
    std::os::unix::fs::symlink(ws.join("tplhooks"), home.join("tpl/hooks")).unwrap();
    std::os::unix::fs::symlink(ws.join("tplconfig"), home.join("tpl/config")).unwrap();
    std::os::unix::fs::symlink(ws.join("tplwtconfig"), home.join("tpl/config.worktree")).unwrap();
    std::fs::write(home.join(".gitconfig"), "[init]\n\ttemplateDir = ~/tpl\n").unwrap();
    let got = git_entries(&ws, Some(&home), std::slice::from_ref(&ws));
    assert!(tree(&got, home.join("tpl")), "{got:?}");
    assert!(tree(&got, ws.join("tplhooks")), "{got:?}");
    assert!(file(&got, ws.join("tplconfig")), "{got:?}");
    assert!(file(&got, ws.join("tplwtconfig")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Grok r3: git copies a template symlink's text, so a relative one resolves from each new git
/// directory, not from the template; it cannot be protected here and refuses (an entry link and
/// a hook link in a real `hooks` directory alike). The template lies outside the write roots.
#[cfg(unix)]
#[test]
fn p158_g6_a_relative_template_link_is_unread() {
    let root = scratch("g6-template-rel");
    let ws = root.join("ws");
    let home = root.join("home");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(home.join("tplhooks")).unwrap();
    std::fs::write(home.join("tplconfig"), "").unwrap();
    std::fs::create_dir_all(home.join("tpl")).unwrap();
    std::os::unix::fs::symlink("../tplhooks", home.join("tpl/hooks")).unwrap();
    std::os::unix::fs::symlink("../tplconfig", home.join("tpl/config")).unwrap();
    std::fs::create_dir_all(home.join("tpl2/hooks")).unwrap();
    std::os::unix::fs::symlink("../../tplhooks/pc", home.join("tpl2/hooks/pre-commit")).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        "[init]\n\ttemplateDir = ~/tpl\n[includeIf \"gitdir:~/elsewhere/\"]\n\tpath = more.inc\n",
    )
    .unwrap();
    std::fs::write(home.join("more.inc"), "[init]\n\ttemplateDir = ~/tpl2\n").unwrap();
    let got = entries(&ws, Some(&home), std::slice::from_ref(&ws));
    for link in [
        home.join("tpl/hooks"),
        home.join("tpl/config"),
        home.join("tpl2/hooks/pre-commit"),
    ] {
        assert!(
            got.unread.iter().any(|unread| matches!(
                unread,
                GitMetadataUnread::Unreadable { path, .. } if *path == link
            )),
            "{}: {:?}",
            link.display(),
            got.unread
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Grok r3 LOW: a symlink loop under a tree already bound read-only names no writable file and
/// cannot be re-pointed, so the Linux plan skips that leaf; a loop nothing covers still refuses.
#[cfg(target_os = "linux")]
#[test]
fn p158_g6_a_link_loop_under_a_bound_tree_is_skipped() {
    use crate::hook_write_deny::{HookWriteDenyBwrapPlan, add_git_leaves_to_plan};
    let root = scratch("g6-loop");
    let ws = root.join("ws");
    let home = root.join("home");
    let tpl = ws.join("tpl");
    std::fs::create_dir_all(&tpl).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::os::unix::fs::symlink(tpl.join("loopb"), tpl.join("config")).unwrap();
    std::os::unix::fs::symlink(tpl.join("config"), tpl.join("loopb")).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        format!("[init]\n\ttemplateDir = {}\n", tpl.display()),
    )
    .unwrap();
    let got = git_entries(&ws, Some(&home), std::slice::from_ref(&ws));
    assert!(tree(&got, &tpl), "{got:?}");
    let empty = || HookWriteDenyBwrapPlan {
        ancestor_rw_binds: Vec::new(),
        leaves: Vec::new(),
        dir_json_snapshots: Vec::new(),
        pinned: Vec::new(),
        rebinds: Vec::new(),
    };
    let mut plan = empty();
    add_git_leaves_to_plan(&mut plan, &got, std::slice::from_ref(&ws)).expect("plan");
    assert!(plan.leaves.iter().any(|leaf| leaf.path == tpl), "{:?}", plan.leaves);
    std::os::unix::fs::symlink(ws.join("loose-b"), ws.join("loose")).unwrap();
    std::os::unix::fs::symlink(ws.join("loose"), ws.join("loose-b")).unwrap();
    let lone = vec![GitProtectedPath {
        path: ws.join("loose"),
        kind: GitPathKind::File,
    }];
    add_git_leaves_to_plan(&mut empty(), &lone, std::slice::from_ref(&ws))
        .expect_err("a loop no bound tree covers still refuses");
    let _ = std::fs::remove_dir_all(&root);
}

/// Grok G4 (documented limit): `.gitmodules` stays writable. Git refuses an `update = !command`
/// from it and copies only a non-command update method into the protected `.git/config`, and
/// `git mv`/`git rm` of a submodule must keep editing it.
#[test]
fn p158_g4_gitmodules_stays_writable() {
    let root = scratch("g4-gitmodules");
    let ws = root.join("ws");
    let module = ws.join(".git/modules/sub");
    std::fs::create_dir_all(&module).unwrap();
    std::fs::write(module.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(ws.join(".gitmodules"), "[submodule \"sub\"]\n\tpath = sub\n").unwrap();
    let got = git_entries(&ws, None, std::slice::from_ref(&ws));
    assert!(tree(&got, module.join("hooks")), "{got:?}");
    assert!(!denies(&got, &ws.join(".gitmodules")), "{got:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// The template's narrowed names are its `config` and every hook git runs by name.
#[test]
fn p158_g3_template_names_track_the_hook_names() {
    let want: Vec<String> = std::iter::once("config".to_owned())
        .chain(
            super::GIT_HOOK_NAMES
                .split_whitespace()
                .map(|name| format!("hooks/{name}")),
        )
        .collect();
    let got: Vec<&str> = super::TEMPLATE_READ_BENEATH.split_whitespace().collect();
    assert_eq!(want, got);
}
