//! P166 round 13B feature 1: before a narrow allow (`Bash(git:*)`) clears the ordinary FileWrite floor of a
//! branch-moving git verb, ask git (read-only) whether any tree the command involves tracks a protected name.
//!
//! The plan (`exec_risk::branch_switch_plan`) says which trees; this module runs `git rev-parse` / `git ls-tree` with a
//! hardened environment and judges the listing. Anything that cannot be determined keeps the floor.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Cap on the bytes read from one `git ls-tree` (exceeding it is undetermined).
pub(crate) const MAX_LISTING_BYTES: usize = 16 * 1024 * 1024;
/// Wall-clock bound for one git child (exceeding it is undetermined).
pub(crate) const GIT_CHILD_TIMEOUT: Duration = Duration::from_secs(2);
/// Bound for a whole check run off the actor (several children).
pub(crate) const CHECK_TIMEOUT: Duration = Duration::from_secs(8);

/// One tree-ish the command involves. `required`: a ref that does not resolve is undetermined (otherwise it is
/// skipped, as for `@{upstream}` of a branch with no upstream). A tree that cannot be LISTED (over the cap, timeout,
/// git error) is undetermined whether required or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TreeRef {
    pub rev: String,
    pub required: bool,
    /// `checkout|switch <name>`: when the local ref does not resolve, git would create the branch from the unique
    /// `refs/remotes/*/<name>`; judge that tree instead (zero or several matches are undetermined).
    pub guess_remote: bool,
    /// When this ref does not resolve, nothing can be rewritten (`git stash pop` with no stash): the probe is cleared.
    pub na_if_absent: bool,
    /// This is `HEAD`: an unborn HEAD is skipped (only the target tree is judged).
    pub unborn_ok: bool,
}

impl TreeRef {
    pub(crate) fn new(rev: impl Into<String>, required: bool) -> Self {
        Self { rev: rev.into(), required, guess_remote: false, na_if_absent: false, unborn_ok: false }
    }
}

/// The result of asking for one tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TreeListing {
    /// The ref does not resolve (git answered "no such revision").
    NotPresent,
    /// Every file path in the tree.
    Listed(Vec<Vec<u8>>),
    /// Over the byte cap, a timeout, a spawn or git error, an unexpected exit code or malformed output.
    Undetermined,
}

/// Remote-tracking refs carrying a given short branch name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RemoteMatch {
    None,
    One(String),
    Undetermined,
}

/// The trees of one git invocation, and the directory git runs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TreeProbe {
    pub cwd: PathBuf,
    pub trees: Vec<TreeRef>,
}

/// What the branch-switch rule needs to do for one command.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum BranchSwitchPlan {
    /// No listed verb (or only a verb that rewrites nothing): nothing to ask, behaviour as before.
    #[default]
    NotApplicable,
    /// A listed verb in a form this rule does not model: the floor is kept, no git call.
    Undetermined,
    Probe(Vec<TreeProbe>),
}

/// Source of tree listings; tests inject one, production uses [`GitTreeLister`].
pub(crate) trait TreeLister: Send + Sync {
    /// The repository root for a command run in `cwd`.
    fn repo_root(&self, cwd: &Path) -> Option<PathBuf>;
    /// `Some(true)` for a bare repository (no working tree to rewrite); `None` when that cannot be told.
    fn is_bare(&self, cwd: &Path) -> Option<bool> {
        let _ = cwd;
        Some(false)
    }
    /// Whether `HEAD` is an unborn branch (attached, no commit yet).
    fn head_unborn(&self, cwd: &Path) -> bool {
        let _ = cwd;
        false
    }
    /// The tree of `rev`: not present, every file path (relative to the repository root, raw bytes), or undetermined.
    fn names(&self, cwd: &Path, rev: &str) -> TreeListing;
    /// `refs/remotes/*/<name>` matches for a branch short name.
    fn remote_tracking(&self, cwd: &Path, name: &str) -> RemoteMatch {
        let _ = (cwd, name);
        RemoteMatch::Undetermined
    }
    /// The whole probe in as few git children as possible (see [`GitTreeLister`]); `None` means "use the per-tree
    /// methods above".
    fn resolve_probe(&self, probe: &TreeProbe) -> Option<ProbeResolution> {
        let _ = probe;
        None
    }
    /// Whether `submodule.recurse` / `checkout.recurseSubmodules` is true at any config level (the user's own config
    /// included). `None` when that cannot be told.
    fn submodule_recursion(&self, cwd: &Path) -> Option<bool> {
        let _ = cwd;
        Some(false)
    }
}

/// Pseudo revision for "every path the next `git add -A && git commit` could put in HEAD": the index plus untracked,
/// not-ignored files of the work tree.
pub(crate) const WORKTREE_REV: &str = ":worktree";
/// Pseudo revision: the untracked, not-ignored files (what `git stash -u` removes).
pub(crate) const UNTRACKED_REV: &str = ":untracked";
/// Pseudo revision: every untracked file, ignored ones included (what `git stash -a` removes).
pub(crate) const UNTRACKED_ALL_REV: &str = ":untracked-all";

fn is_pseudo_rev(rev: &str) -> bool {
    matches!(rev, WORKTREE_REV | UNTRACKED_REV | UNTRACKED_ALL_REV)
}

/// What a batched resolve found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProbeResolution {
    /// No work tree to rewrite (`bare`), or not a repository / not told (`bare` false: undetermined).
    NoWorkTree { bare: bool },
    WorkTree { root: PathBuf, listings: Vec<TreeListing> },
}

/// Whether the floor must be KEPT: some tree involved tracks a protected name, or that cannot be determined.
pub(crate) fn plan_keeps_floor(plan: &BranchSwitchPlan, lister: &dyn TreeLister) -> bool {
    match plan {
        BranchSwitchPlan::NotApplicable => false,
        BranchSwitchPlan::Undetermined => true,
        BranchSwitchPlan::Probe(probes) => probes.iter().any(|probe| probe_keeps_floor(probe, lister)),
    }
}

fn probe_keeps_floor(probe: &TreeProbe, lister: &dyn TreeLister) -> bool {
    let (root, listings) = match lister.resolve_probe(probe) {
        Some(ProbeResolution::NoWorkTree { bare }) => return !bare,
        Some(ProbeResolution::WorkTree { root, listings }) => (root, listings),
        None => {
            let Some(root) = lister.repo_root(&probe.cwd) else {
                // No work tree: a bare repository has nothing to rewrite; anything else that is not a repository is undetermined.
                return lister.is_bare(&probe.cwd) != Some(true);
            };
            (root.clone(), per_tree_listings(probe, lister))
        }
    };
    let mut modules = false;
    for (tree, listing) in probe.trees.iter().zip(listings) {
        match listing {
            TreeListing::Undetermined => return true,
            TreeListing::NotPresent if tree.na_if_absent => return false,
            TreeListing::NotPresent if tree.unborn_ok && lister.head_unborn(&probe.cwd) => {}
            TreeListing::NotPresent if tree.required => return true,
            TreeListing::NotPresent => {}
            TreeListing::Listed(names) => {
                if names.iter().any(|name| name_is_protected(&root, name)) {
                    return true;
                }
                modules |= names.iter().any(|name| name == b".gitmodules");
            }
        }
    }
    // A checkout that recurses into submodules rewrites trees `ls-tree -r` of the superproject does not list.
    modules && lister.submodule_recursion(&probe.cwd) != Some(false)
}

/// The trees are independent: list them side by side so the whole check stays inside CHECK_TIMEOUT when the machine is
/// busy (every git child is still bounded by GIT_CHILD_TIMEOUT).
fn per_tree_listings(probe: &TreeProbe, lister: &dyn TreeLister) -> Vec<TreeListing> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = probe
            .trees
            .iter()
            .map(|tree| scope.spawn(move || names_with_remote_guess(lister, &probe.cwd, tree)))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or(TreeListing::Undetermined)).collect()
    })
}

fn names_with_remote_guess(lister: &dyn TreeLister, cwd: &Path, tree: &TreeRef) -> TreeListing {
    let mut listing = lister.names(cwd, &tree.rev);
    if listing == TreeListing::NotPresent && tree.guess_remote {
        listing = match lister.remote_tracking(cwd, &tree.rev) {
            RemoteMatch::One(reference) => match lister.names(cwd, &reference) {
                TreeListing::NotPresent => TreeListing::Undetermined,
                other => other,
            },
            RemoteMatch::None | RemoteMatch::Undetermined => TreeListing::Undetermined,
        };
    }
    listing
}

fn name_is_protected(root: &Path, name: &[u8]) -> bool {
    #[cfg(unix)]
    let relative = {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(name))
    };
    #[cfg(not(unix))]
    let relative = PathBuf::from(String::from_utf8_lossy(name).into_owned());
    crate::permission::shell_access::lexical_path_is_protected(&root.join(relative))
}

/// Production lister: direct `git` children, no shell, hardened environment.
pub(crate) struct GitTreeLister;

impl TreeLister for GitTreeLister {
    fn repo_root(&self, cwd: &Path) -> Option<PathBuf> {
        let out = run_git(cwd, &["rev-parse", "--show-toplevel"], 64 * 1024)?;
        let text = String::from_utf8(out).ok()?;
        let text = text.trim_end_matches('\n');
        (!text.is_empty()).then(|| PathBuf::from(text))
    }

    fn is_bare(&self, cwd: &Path) -> Option<bool> {
        let out = run_git(cwd, &["rev-parse", "--is-bare-repository"], 64)?;
        match String::from_utf8(out).ok()?.trim() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }
    }

    fn head_unborn(&self, cwd: &Path) -> bool {
        // Attached (`symbolic-ref` succeeds) and the branch it names has no commit.
        run_git(cwd, &["symbolic-ref", "--quiet", "HEAD"], 4096).is_some()
    }

    fn names(&self, cwd: &Path, rev: &str) -> TreeListing {
        if is_pseudo_rev(rev) {
            return list_pseudo(cwd, rev);
        }
        if rev.is_empty() || rev.starts_with('-') {
            return TreeListing::Undetermined;
        }
        let mut all = match list_tree(cwd, rev, true) {
            TreeListing::Listed(names) => names,
            other => return other,
        };
        // Replace refs: the real command may see a replaced object where this check (told to ignore replacements)
        // sees the original. When any replace ref exists, list both and judge the union.
        match run_git(cwd, &["for-each-ref", "--count=1", "--format=%(refname)", "refs/replace/"], 4096) {
            None => return TreeListing::Undetermined,
            Some(out) if out.is_empty() => {}
            Some(_) => match list_tree(cwd, rev, false) {
                TreeListing::Listed(more) => all.extend(more),
                _ => return TreeListing::Undetermined,
            },
        }
        TreeListing::Listed(all)
    }

    fn resolve_probe(&self, probe: &TreeProbe) -> Option<ProbeResolution> {
        Some(self.batched(probe))
    }

    fn submodule_recursion(&self, cwd: &Path) -> Option<bool> {
        submodule_recursion_with_home(cwd, std::env::var_os("HOME").as_deref())
    }

    fn remote_tracking(&self, cwd: &Path, name: &str) -> RemoteMatch {
        if name.is_empty() || name.starts_with('-') || name.contains(['*', '?', '[', '\\']) {
            return RemoteMatch::Undetermined;
        }
        let pattern = format!("refs/remotes/*/{name}");
        let Some(out) = run_git(cwd, &["for-each-ref", "--format=%(refname)", &pattern], 1024 * 1024) else {
            return RemoteMatch::Undetermined;
        };
        let Ok(text) = String::from_utf8(out) else {
            return RemoteMatch::Undetermined;
        };
        // `*` also matches `/`: keep only `refs/remotes/<remote>/<name>` with the remote one path component.
        let mut found = text.lines().filter(|line| {
            line.strip_prefix("refs/remotes/").and_then(|rest| rest.split_once('/')).is_some_and(|(_, tail)| tail == name)
        });
        match (found.next(), found.next()) {
            (None, _) => RemoteMatch::None,
            (Some(one), None) => RemoteMatch::One(one.to_owned()),
            _ => RemoteMatch::Undetermined,
        }
    }
}

impl GitTreeLister {
    /// Round 1 (two children side by side): discovery (`rev-parse --is-bare-repository --show-toplevel
    /// --glob=refs/replace/*`: bare state, root and any replace ref in one child) and `cat-file --batch-check` over
    /// `<rev>` and `<rev>^{tree}` of every tree (one line each, `<rev> missing` per unresolvable name, so a failure is
    /// attributed to its own ref). Round 2: one `ls-tree` per DISTINCT tree id, side by side. With a replace ref the
    /// resolve runs once more without `--no-replace-objects` and the union of both views is listed.
    fn batched(&self, probe: &TreeProbe) -> ProbeResolution {
        let cwd = probe.cwd.as_path();
        let batch: Vec<usize> = (0..probe.trees.len())
            .filter(|&i| {
                let rev = &probe.trees[i].rev;
                !is_pseudo_rev(rev) && !rev.is_empty() && !rev.starts_with('-') && !rev.contains(['\n', '\r', '\0'])
            })
            .collect();
        let revs: Vec<&str> = batch.iter().map(|&i| probe.trees[i].rev.as_str()).collect();
        let (discovery, resolved) = std::thread::scope(|scope| {
            let a = scope.spawn(|| discover(cwd));
            let c = scope.spawn(|| resolve_revs(cwd, &revs, true));
            (a.join().unwrap_or(Discovery::Unknown), c.join().unwrap_or_default())
        });
        let (root, replaced) = match discovery {
            Discovery::Root { root, replaced } => (root, replaced),
            Discovery::Bare => return ProbeResolution::NoWorkTree { bare: true },
            Discovery::Unknown => return ProbeResolution::NoWorkTree { bare: false },
        };
        let unresolved = |revs: &[&str]| vec![Resolved::Unknown; revs.len()];
        let mut views = vec![if resolved.len() == revs.len() { resolved } else { unresolved(&revs) }];
        if replaced {
            let second = resolve_revs(cwd, &revs, false);
            views.push(if second.len() == revs.len() { second } else { unresolved(&revs) });
        }
        // Jobs: the distinct (tree id, replacement view) pairs, plus the work tree when asked for.
        let mut jobs: Vec<(String, bool)> = Vec::new();
        for (view_index, view) in views.iter().enumerate() {
            for item in view {
                if let Resolved::Tree(sha) = item {
                    let job = (sha.clone(), view_index == 0);
                    if !jobs.contains(&job) {
                        jobs.push(job);
                    }
                }
            }
        }
        let pseudo: Vec<&str> = {
            let mut v: Vec<&str> = probe.trees.iter().map(|t| t.rev.as_str()).filter(|r| is_pseudo_rev(r)).collect();
            v.dedup();
            v
        };
        let (tree_results, worktree) = std::thread::scope(|scope| {
            let handles: Vec<_> = jobs.iter().map(|(sha, no_replace)| scope.spawn(move || list_tree_id(cwd, sha, *no_replace))).collect();
            let w: Vec<_> = pseudo.iter().map(|rev| (*rev, scope.spawn(move || list_pseudo(cwd, rev)))).collect();
            let results: Vec<TreeListing> = handles.into_iter().map(|h| h.join().unwrap_or(TreeListing::Undetermined)).collect();
            let w: Vec<(&str, TreeListing)> = w.into_iter().map(|(r, h)| (r, h.join().unwrap_or(TreeListing::Undetermined))).collect();
            (results, w)
        });
        let mut listings = Vec::with_capacity(probe.trees.len());
        for (i, tree) in probe.trees.iter().enumerate() {
            if is_pseudo_rev(&tree.rev) {
                let found = worktree.iter().find(|(r, _)| *r == tree.rev.as_str()).map(|(_, l)| l.clone());
                listings.push(found.unwrap_or(TreeListing::Undetermined));
                continue;
            }
            let Some(position) = batch.iter().position(|&b| b == i) else {
                listings.push(TreeListing::Undetermined);
                continue;
            };
            let mut listing = combine(&views, position, &jobs, &tree_results);
            if listing == TreeListing::NotPresent && tree.guess_remote {
                listing = names_with_remote_guess(self, cwd, tree);
            }
            listings.push(listing);
        }
        ProbeResolution::WorkTree { root, listings }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Resolved {
    NotPresent,
    Tree(String),
    Unknown,
}

enum Discovery {
    Root { root: PathBuf, replaced: bool },
    Bare,
    Unknown,
}

fn discover(cwd: &Path) -> Discovery {
    let args = ["rev-parse", "--is-bare-repository", "--show-toplevel", "--glob=refs/replace/*"];
    let Some(done) = run_command(hardened_git_command(cwd, &args), None, 1024 * 1024) else {
        return Discovery::Unknown;
    };
    let Some(Ok(text)) = done.out.map(String::from_utf8) else {
        return Discovery::Unknown;
    };
    let mut lines = text.lines();
    match (done.code, lines.next(), lines.next()) {
        // Bare: `--show-toplevel` dies after the first line.
        (_, Some("true"), _) => Discovery::Bare,
        // Line structure: `false`, the top level, then at most one line per replace ref. A work-tree path that holds a
        // newline breaks it (the path text and a replace-ref line cannot be told apart): undetermined.
        (Some(0), Some("false"), Some(root)) if !root.is_empty() => {
            let rest: Vec<&str> = lines.collect();
            let replaced = !rest.is_empty();
            let well_formed = rest.iter().all(|l| (l.len() == 40 || l.len() == 64) && l.bytes().all(|b| b.is_ascii_hexdigit()));
            if well_formed {
                Discovery::Root { root: PathBuf::from(root), replaced }
            } else {
                Discovery::Unknown
            }
        }
        _ => Discovery::Unknown,
    }
}

/// Resolve `<rev>` and `<rev>^{tree}` for each rev with `cat-file --batch-check` children. A name that does not exist
/// prints `<rev> missing`; a few forms DIE instead (`@{upstream}` with no upstream configured) and end the child, so
/// the lines printed before the death say which rev it was (not present, as `rev-parse --verify` exit 128 was before)
/// and the rest are resolved by one more child. At most one extra child per dying rev. Empty on any other failure.
fn resolve_revs(cwd: &Path, revs: &[&str], no_replace: bool) -> Vec<Resolved> {
    let mut out: Vec<Resolved> = Vec::with_capacity(revs.len());
    while out.len() < revs.len() {
        let rest = &revs[out.len()..];
        let mut input = Vec::new();
        for rev in rest {
            input.extend_from_slice(format!("{rev}\n{rev}^{{tree}}\n").as_bytes());
        }
        let mut args = vec!["cat-file", "--batch-check"];
        if no_replace {
            args.insert(0, "--no-replace-objects");
        }
        let Some(done) = run_command(hardened_git_command(cwd, &args), Some(input), 1024 * 1024) else {
            return Vec::new();
        };
        let Some(Ok(text)) = done.out.map(String::from_utf8) else {
            return Vec::new();
        };
        let lines: Vec<&str> = text.lines().collect();
        let complete = lines.len() / 2;
        match done.code {
            Some(0) if lines.len() == rest.len() * 2 => {}
            // Died on the rev after the complete pairs (an even number of lines printed).
            Some(128) if lines.len().is_multiple_of(2) && complete < rest.len() => {}
            _ => return Vec::new(),
        }
        out.extend(rest.iter().take(complete).enumerate().map(|(i, rev)| classify(rev, lines[2 * i], lines[2 * i + 1])));
        if complete < rest.len() {
            out.push(Resolved::NotPresent);
        }
    }
    out
}

fn classify(rev: &str, first: &str, second: &str) -> Resolved {
    let is_hex_id = |s: &str| matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit());
    // `<rev> missing`: the NAME does not resolve (an existing name whose object is gone prints the object id).
    if first == format!("{rev} missing") && !is_hex_id(rev) {
        return Resolved::NotPresent;
    }
    let mut parts = first.split(' ');
    let named = matches!((parts.next(), parts.next(), parts.next(), parts.next()), (Some(id), Some(kind), Some(size), None)
        if is_hex_id(id) && matches!(kind, "commit" | "tag" | "tree") && size.bytes().all(|b| b.is_ascii_digit()));
    let mut parts = second.split(' ');
    match (named, parts.next(), parts.next(), parts.next(), parts.next()) {
        (true, Some(id), Some("tree"), Some(size), None) if is_hex_id(id) && size.bytes().all(|b| b.is_ascii_digit()) => {
            Resolved::Tree(id.to_owned())
        }
        _ => Resolved::Unknown,
    }
}

/// One tree's listing from the views (first = `--no-replace-objects`, second = with replacements) and the job results.
fn combine(views: &[Vec<Resolved>], position: usize, jobs: &[(String, bool)], results: &[TreeListing]) -> TreeListing {
    let first = &views[0][position];
    let mut all = Vec::new();
    for (view_index, view) in views.iter().enumerate() {
        match (&view[position], first) {
            (Resolved::Tree(sha), _) => {
                let key = (sha.clone(), view_index == 0);
                let Some(at) = jobs.iter().position(|j| *j == key) else {
                    return TreeListing::Undetermined;
                };
                match &results[at] {
                    TreeListing::Listed(names) => all.extend(names.iter().cloned()),
                    _ => return TreeListing::Undetermined,
                }
            }
            // Not present in every view: not present. Present in one view only (a replace ref changed it): undetermined.
            (Resolved::NotPresent, Resolved::NotPresent) => {}
            _ => return TreeListing::Undetermined,
        }
    }
    if matches!(first, Resolved::NotPresent) { TreeListing::NotPresent } else { TreeListing::Listed(all) }
}

/// Every path of a tree object (a tree id from a batch resolve, so no second resolve).
fn list_tree_id(cwd: &Path, sha: &str, no_replace: bool) -> TreeListing {
    let mut args = vec!["ls-tree", "-r", "--name-only", "-z", "--full-tree", sha];
    if no_replace {
        args.insert(0, "--no-replace-objects");
    }
    match run_git_outcome(cwd, &args, MAX_LISTING_BYTES) {
        GitRun::Output(listing) => {
            TreeListing::Listed(listing.split(|b| *b == 0).filter(|name| !name.is_empty()).map(<[u8]>::to_vec).collect())
        }
        _ => TreeListing::Undetermined,
    }
}

/// Work-tree pseudo revisions. `:worktree` is the index plus untracked, not-ignored files; `:untracked` only the
/// untracked, not-ignored ones; `:untracked-all` every untracked file, ignored included.
fn list_pseudo(cwd: &Path, rev: &str) -> TreeListing {
    let args: &[&str] = match rev {
        UNTRACKED_REV => &["ls-files", "-z", "--others", "--exclude-standard", "--full-name"],
        UNTRACKED_ALL_REV => &["ls-files", "-z", "--others", "--full-name"],
        _ => &["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--full-name"],
    };
    list_ls_files(cwd, args)
}

/// Index plus untracked, not-ignored files (paths relative to the repository root).
fn list_ls_files(cwd: &Path, args: &[&str]) -> TreeListing {
    match run_git_outcome(cwd, args, MAX_LISTING_BYTES) {
        GitRun::Output(listing) => {
            TreeListing::Listed(listing.split(|b| *b == 0).filter(|name| !name.is_empty()).map(<[u8]>::to_vec).collect())
        }
        _ => TreeListing::Undetermined,
    }
}

/// `git config --type=bool --get-regexp` for the two submodule-recursion keys, with the user's global and system
/// config visible (reading config executes nothing). True at any level, or any failure: `None`/`Some(true)`.
pub(crate) fn submodule_recursion_with_home(cwd: &Path, home: Option<&std::ffi::OsStr>) -> Option<bool> {
    let args = ["config", "--type=bool", "--get-regexp", r"^(submodule\.recurse|checkout\.recursesubmodules)$"];
    let mut command = hardened_git_command(cwd, &args);
    command.env_remove("GIT_CONFIG_NOSYSTEM").env_remove("GIT_CONFIG_GLOBAL");
    if let Some(home) = home {
        command.env("HOME", home);
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        command.env("XDG_CONFIG_HOME", xdg);
    }
    let done = run_command(command, None, 64 * 1024)?;
    match (done.code, done.out) {
        // Exit 1: no such key at any level.
        (Some(1), _) => Some(false),
        (Some(0), Some(out)) => {
            let text = String::from_utf8(out).ok()?;
            Some(text.lines().any(|line| line.rsplit(' ').next() == Some("true")))
        }
        _ => None,
    }
}

/// `rev`'s tree listing: not present only when the name does not resolve; every other failure (spawn, timeout, signal,
/// an unreadable tree, malformed output, `ls-tree` failing) is undetermined.
fn list_tree(cwd: &Path, rev: &str, no_replace: bool) -> TreeListing {
    let list_args: Vec<&str> = if no_replace {
        vec!["--no-replace-objects", "ls-tree", "-r", "--name-only", "-z", "--full-tree"]
    } else {
        vec!["ls-tree", "-r", "--name-only", "-z", "--full-tree"]
    };
    // One child answers both the tree and the commit-ish: `rev-parse rev rev^{tree}` prints two ids. With the tree
    // object missing, `rev^{tree}` can answer the commit's own id, so two equal ids are never listed.
    let tree_ish = format!("{rev}^{{tree}}");
    let ids_args: Vec<&str> = if no_replace {
        vec!["--no-replace-objects", "rev-parse", rev, &tree_ish]
    } else {
        vec!["rev-parse", rev, &tree_ish]
    };
    let ids = match run_git_outcome(cwd, &ids_args, 4096) {
        GitRun::Output(out) => out,
        GitRun::Exit(1 | 128) => {
            // Not resolvable as a tree. "Not present" only when the NAME itself does not resolve (exit 1, or 128 for
            // the forms that die such as `@{upstream}` with no upstream); a name that resolves but whose tree cannot
            // be read is a damaged or partial repository.
            let name_args: Vec<&str> = if no_replace {
                vec!["--no-replace-objects", "rev-parse", "--verify", "--quiet", "--end-of-options", rev]
            } else {
                vec!["rev-parse", "--verify", "--quiet", "--end-of-options", rev]
            };
            return match run_git_outcome(cwd, &name_args, 4096) {
                GitRun::Exit(1 | 128) => TreeListing::NotPresent,
                _ => TreeListing::Undetermined,
            };
        }
        _ => return TreeListing::Undetermined,
    };
    let Ok(ids) = String::from_utf8(ids) else {
        return TreeListing::Undetermined;
    };
    let mut lines = ids.lines();
    let (Some(commit_ish), Some(sha), None) = (lines.next(), lines.next(), lines.next()) else {
        return TreeListing::Undetermined;
    };
    if commit_ish == sha {
        return TreeListing::Undetermined;
    }
    // Only a real tree is listed (a damaged tree can make `rev^{tree}` answer an unrelated commit id).
    let type_args: Vec<&str> =
        if no_replace { vec!["--no-replace-objects", "cat-file", "-t", sha] } else { vec!["cat-file", "-t", sha] };
    match run_git_outcome(cwd, &type_args, 64) {
        GitRun::Output(kind) if kind.trim_ascii() == b"tree" => {}
        _ => return TreeListing::Undetermined,
    }
    let mut args = list_args;
    args.push(sha);
    match run_git_outcome(cwd, &args, MAX_LISTING_BYTES) {
        GitRun::Output(listing) => {
            TreeListing::Listed(listing.split(|b| *b == 0).filter(|name| !name.is_empty()).map(<[u8]>::to_vec).collect())
        }
        _ => TreeListing::Undetermined,
    }
}

/// How one git child ended.
#[derive(Debug)]
pub(crate) enum GitRun {
    /// Exit 0 with the captured output.
    Output(Vec<u8>),
    /// A non-zero exit code (the output is discarded).
    Exit(i32),
    /// Spawn failure, timeout, signal, or output over the cap.
    Bound,
}

fn run_git(cwd: &Path, args: &[&str], cap: usize) -> Option<Vec<u8>> {
    match run_git_outcome(cwd, args, cap) {
        GitRun::Output(out) => Some(out),
        _ => None,
    }
}

/// Read at most `cap` bytes; `None` when the stream is longer or fails.
pub(crate) fn read_capped(mut reader: impl Read, cap: usize) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Some(data),
            Ok(n) => {
                data.extend_from_slice(&chunk[..n]);
                if data.len() > cap {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

/// The protocols a lazy fetch (partial clone promisor remote) could use. Every one is denied explicitly: a bare
/// `protocol.allow=never` is only the default for protocols with no `protocol.<name>.allow` of their own.
const DENIED_PROTOCOLS: [&str; 6] = ["file", "git", "ssh", "http", "https", "ext"];

/// The hardened `git` command for one read-only child: no shell, the parent environment cleared (so a poisoned
/// `GIT_DIR`, `GIT_WORK_TREE`, `GIT_CONFIG_*`, `GIT_EXEC_PATH`, ... never reaches it), and no way to start a fetch.
///
/// Lazy fetch: git 2.46+ honours `GIT_NO_LAZY_FETCH=1`, which makes a missing promisor object an error. Older git
/// (the build box has 2.43) ignores it; there the guard is the transport policy (`protocol.allow=never`, every
/// `protocol.<name>.allow=never` on the command line, which outranks repository config, and an empty
/// `GIT_ALLOW_PROTOCOL`), so the fetch child dies before any transport starts and the object stays missing. Either
/// way a missing object fails the child, which is undetermined.
pub(crate) fn hardened_git_command(cwd: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", "/nonexistent")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "")
        .args([
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.allow=never",
            "-c",
            "core.alternateRefsCommand=",
        ]);
    for protocol in DENIED_PROTOCOLS {
        command.arg("-c").arg(format!("protocol.{protocol}.allow=never"));
    }
    command.args(args).current_dir(cwd).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    command
}

/// A finished child: exit code (None: signal) and stdout (None: over the cap or unreadable).
struct Finished {
    code: Option<i32>,
    out: Option<Vec<u8>>,
}

/// Every child spawned by the check, for the child-count regression test: (working directory, arguments).
#[cfg(test)]
pub(crate) static SPAWNED: std::sync::Mutex<Vec<(PathBuf, Vec<String>)>> = std::sync::Mutex::new(Vec::new());

/// Spawn `command` (optionally feeding `stdin`), cap stdout at `cap` bytes, bound it by [`GIT_CHILD_TIMEOUT`].
/// `None`: spawn failure or timeout.
fn run_command(mut command: Command, stdin: Option<Vec<u8>>, cap: usize) -> Option<Finished> {
    #[cfg(test)]
    if let Ok(mut log) = SPAWNED.lock() {
        let args = command.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        log.push((command.get_current_dir().map(Path::to_path_buf).unwrap_or_default(), args));
    }
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    #[allow(clippy::disallowed_methods)] // bounded to GIT_CHILD_TIMEOUT; killed and waited on every path below
    let Ok(mut child) = command.spawn() else {
        return None;
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = pipe.write_all(&data);
        });
    }
    let reader = std::thread::spawn(move || read_capped(stdout, cap));
    let started = Instant::now();
    while !reader.is_finished() {
        if started.elapsed() > GIT_CHILD_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return None;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let out = reader.join().ok().flatten();
    if out.is_none() {
        let _ = child.kill();
    }
    let status = child.wait().ok()?;
    Some(Finished { code: status.code(), out })
}

/// Run [`hardened_git_command`] with stdout capped at `cap` bytes and wall-clock bounded by [`GIT_CHILD_TIMEOUT`].
fn run_git_outcome(cwd: &Path, args: &[&str], cap: usize) -> GitRun {
    match run_command(hardened_git_command(cwd, args), None, cap) {
        Some(Finished { code: Some(0), out: Some(data) }) => GitRun::Output(data),
        Some(Finished { code: Some(code), .. }) if code != 0 => GitRun::Exit(code),
        _ => GitRun::Bound,
    }
}

#[cfg(test)]
pub(crate) fn run_git_for_tests(cwd: &Path, args: &[&str], cap: usize) -> Option<Vec<u8>> {
    run_git(cwd, args, cap)
}
