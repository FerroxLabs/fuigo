//! The Read-deny globs ([`DenyReadGlobs`](crate::types::resources::DenyReadGlobs)) as a path filter (P198), for the
//! tools that list or check names themselves (`list_dir`, the explicit-file check of the grep tools).
//!
//! It decides with THE POLICY'S OWN matcher: the same path spellings (absolute, cwd-relative, `./`-relative, the
//! physical-cwd forms) and the same `glob::Pattern` options the permission check uses for a `Read` of the path
//! (`util::path_match`, which `fuigo-workspace`'s policy calls too). A path is filtered exactly when a `Read` of it
//! would be denied by those rules. Round 3: the search tools hand ripgrep NO excludes; they judge what it printed with [`ResultFilter`] / [`RgNullStream`].
use std::path::{Path, PathBuf};

use crate::util::path_match::{
    RuleBase, literal_dir_prefix, path_match_forms, path_pattern_matches, physical_alias_pattern_string_bounded,
};

/// Total time `ReadDenyFilter::new` may spend resolving physical aliases across all rules.
const ALIAS_BUDGET: std::time::Duration = std::time::Duration::from_millis(250);

/// A path filter built from Read-deny globs. Built only when there is something to deny, so a session with no read
/// rules does no matching at all (no filter object, no per-file work).
#[derive(Debug, Clone)]
pub struct ReadDenyFilter {
    cwd: PathBuf,
    /// The cwd with symlinks resolved, when it differs from the written one (resolved once, here).
    physical: Option<PathBuf>,
    /// `None` is the policy's tool-wide `*`.
    patterns: Vec<Option<glob::Pattern>>,
    /// The literal directory parts of the rules that are syntactically total ([`total_prefix`]).
    totals: Vec<Total>,
    /// The walked root as given and with symlinks resolved, when they differ: a root that is a symlink into a denied tree
    /// is judged by where its children really are.
    root: Option<(PathBuf, PathBuf)>,
}

impl ReadDenyFilter {
    /// `None` when `globs` is empty (nothing to filter) or none of them compiles.
    pub fn new(cwd: &Path, globs: &[String]) -> Option<Self> {
        // P175f: a rule spelled through a symlinked directory also applies to the physical spelling, which is what
        // `ResultFilter` judges a result by. The extra rules are added next to the written ones, never instead.
        // The resolution is bounded by ONE budget for the whole build (a rule prefix on a hung mount must not stall
        // a search): once it is spent, the remaining rules get no alias, as before P175f.
        let deadline = std::time::Instant::now() + ALIAS_BUDGET;
        let aliases: Vec<String> = globs
            .iter()
            .filter_map(|g| {
                let (prefix, rest) = literal_dir_prefix(g)?;
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    return None;
                }
                physical_alias_pattern_string_bounded(&prefix, &rest, left)
            })
            .collect();
        let globs: Vec<String> = globs.iter().cloned().chain(aliases).collect();
        let globs = globs.as_slice();
        let patterns: Vec<Option<glob::Pattern>> = globs
            .iter()
            .filter_map(|g| {
                if g == "*" {
                    Some(None)
                } else {
                    glob::Pattern::new(g).ok().map(Some)
                }
            })
            .collect();
        if patterns.is_empty() {
            return None;
        }
        let physical = RuleBase::new(cwd).resolved_physical();
        let totals = globs.iter().filter_map(|g| total_prefix(g)).collect();
        Some(Self {
            cwd: cwd.to_path_buf(),
            physical,
            patterns,
            totals,
            root: None,
        })
    }

    fn denies_text(&self, path: &Path) -> bool {
        let text = path.to_string_lossy();
        let base = RuleBase::with_physical(&self.cwd, self.physical.clone());
        self.patterns.iter().any(|p| match p {
            None => true,
            Some(pat) => path_pattern_matches(&text, pat, Some(&base)),
        })
    }

    /// The same filter for a walk of `root`: a path under `root` is also judged by its place under the canonical `root`.
    pub fn rooted(mut self, root: &Path) -> Self {
        if let Ok(canonical) = dunce::canonicalize(root)
            && canonical != root
        {
            self.root = Some((root.to_path_buf(), canonical));
        }
        self
    }

    /// Whether a `Read` of `path` (absolute, or relative to the cwd) would be denied. A file is judged by the matcher.
    /// A directory is pruned (its name hidden, never entered) ONLY when a rule is syntactically total under it (see
    /// [`total_prefix`]) or the rule is the catch-all `*`; every other directory is entered and each child is judged by
    /// the matcher on its own path. Deciding "total" parses the rule text and never samples child names, so a rule
    /// like `**/*[0-9]` or `**/[!.]*` cannot hide a directory of allowed files.
    pub fn denies(&self, path: &Path, is_dir: bool) -> bool {
        let judge = |p: &Path| {
            if is_dir {
                self.total_under(p)
            } else {
                self.denies_text(p)
            }
        };
        if judge(path) {
            return true;
        }
        match &self.root {
            Some((given, canonical)) => path
                .strip_prefix(given)
                .is_ok_and(|rel| judge(&canonical.join(rel))),
            None => false,
        }
    }

    /// Whether some rule denies EVERYTHING below directory `dir`: the catch-all, or a rule whose text is exactly
    /// `<P>/**` or `<P>/**/*` with a literal `P` that is `dir` or an ancestor of it in one of the spellings the policy
    /// matches (absolute, cwd-relative, `./`-relative, physical cwd).
    fn total_under(&self, dir: &Path) -> bool {
        if self.patterns.iter().any(Option::is_none) {
            return true;
        }
        if self.totals.is_empty() {
            return false;
        }
        let base = RuleBase::with_physical(&self.cwd, self.physical.clone());
        let forms = path_match_forms(&dir.to_string_lossy(), Some(&base));
        self.totals.iter().any(|total| match total {
            Total::Under(prefix) => forms
                .iter()
                .any(|f| f == prefix || f.strip_prefix(prefix.as_str()).is_some_and(|rest| rest.starts_with('/'))),
            // `**/P/**`: only the cwd-relative spellings are considered (an absolute one is simply not claimed).
            Total::AnyDepth(name) => forms.iter().filter(|f| !f.starts_with('/')).any(|f| {
                f == name
                    || f.ends_with(&format!("/{name}"))
                    || f.contains(&format!("/{name}/"))
                    || f.starts_with(&format!("{name}/"))
            }),
        })
    }
}

/// A rule that denies everything below a directory, by its text.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Total {
    /// `P/**` or `P/**/*`: everything strictly below the literal path `P`.
    Under(String),
    /// `**/P/**` or `**/P/**/*`: everything below a directory whose cwd-relative spelling ends in, or passes through, `P`.
    AnyDepth(String),
}

/// The literal directory part `P` of a rule that is syntactically total under `P`: the rule text is exactly `P/**` or
/// `P/**/*` (or `**/P/**`, `**/P/**/*`), and `P` holds no glob metacharacter (`* ? [ ] { }` or a backslash), so the matcher treats `P` literally
/// and the pattern matches every path strictly below `P` in the spelling `P` is written in (`*` and `**` match any
/// name, with or without a leading dot). A trailing-slash rule (`P/**/`) only matches paths that end in a slash, so it
/// is NOT total. Any other rule returns `None`: its directory is entered and each child judged, which can only cost
/// time, never hide an allowed file (a pruned directory's every child would be denied by the matcher anyway) and
/// never reveal more than a name the policy does not deny.
fn total_prefix(rule: &str) -> Option<Total> {
    let prefix = rule.strip_suffix("/**/*").or_else(|| rule.strip_suffix("/**"))?;
    let meta = |p: &str| p.chars().any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}' | '\\'));
    if let Some(name) = prefix.strip_prefix("**/") {
        return (!meta(name) && !name.is_empty() && !name.starts_with('/') && !name.ends_with('/'))
            .then(|| Total::AnyDepth(name.to_string()));
    }
    (!meta(prefix) && !prefix.ends_with('/')).then(|| Total::Under(prefix.to_string()))
}

/// Judges the files a search printed (P198 round 3). Every result path is judged by [`ReadDenyFilter`] as written
/// (resolved against the cwd) AND by where it really is (its directory canonicalised, cached per directory), so the
/// outcome never depends on how ripgrep spelled the path, on a symlinked cwd, root or directory, or on ripgrep's own
/// glob dialect. With no rules it denies nothing and does no work.
#[derive(Debug)]
pub struct ResultFilter {
    filter: Option<ReadDenyFilter>,
    cwd: PathBuf,
    dirs: std::collections::HashMap<PathBuf, Option<PathBuf>>,
}

impl ResultFilter {
    pub fn new(cwd: &Path, globs: &[String]) -> Self {
        Self { filter: ReadDenyFilter::new(cwd, globs), cwd: cwd.to_path_buf(), dirs: Default::default() }
    }

    /// Whether any rule exists (otherwise nothing is ever denied).
    pub fn is_active(&self) -> bool {
        self.filter.is_some()
    }

    /// Whether the result file `path` (absolute, or relative to the cwd) is denied.
    pub fn denies(&mut self, path: &Path) -> bool {
        let Some(filter) = &self.filter else {
            return false;
        };
        let abs = if path.is_absolute() { path.to_path_buf() } else { self.cwd.join(path) };
        if filter.denies(&abs, false) {
            return true;
        }
        // Fail closed: a result whose parent or name cannot be resolved cannot be judged by where it really is.
        let (Some(parent), Some(name)) = (abs.parent(), abs.file_name()) else {
            return true;
        };
        let canonical = self
            .dirs
            .entry(parent.to_path_buf())
            .or_insert_with(|| dunce::canonicalize(parent).ok())
            .clone();
        match canonical {
            Some(dir) => filter.denies(&dir.join(name), false),
            None => true,
        }
    }

    /// [`Self::denies`] for the raw bytes of a path ripgrep printed.
    pub fn denies_bytes(&mut self, path: &[u8]) -> bool {
        #[cfg(unix)]
        let p = {
            use std::os::unix::ffi::OsStrExt;
            PathBuf::from(std::ffi::OsStr::from_bytes(path))
        };
        #[cfg(not(unix))]
        let p = PathBuf::from(String::from_utf8_lossy(path).into_owned());
        self.denies(&p)
    }
}

/// A streaming post-filter over `rg --files --null` (the glob tool's file listing): records are one path each, NUL
/// terminated, and ripgrep prints no notice into that stream, so there is nothing to mis-attribute. It drops every
/// denied path and re-emits the rest as `path\n`. (Searches use [`crate::util::rg_json::RgJsonStream`] instead.)
#[derive(Debug)]
pub struct RgNullStream {
    results: ResultFilter,
    buf: Vec<u8>,
}

impl RgNullStream {
    pub fn new_files(results: ResultFilter) -> Self {
        Self { results, buf: Vec::new() }
    }

    /// Whether any rule exists (otherwise the caller should not ask ripgrep for `--null`).
    pub fn is_active(&self) -> bool {
        self.results.is_active()
    }

    /// Feed a chunk of ripgrep output; returns the bytes to show so far.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some(i) = self.buf.iter().position(|b| *b == 0) {
            let path: Vec<u8> = self.buf.drain(..=i).take(i).collect();
            if !self.results.denies_bytes(&path) {
                out.extend_from_slice(&path);
                out.push(b'\n');
            }
        }
        out
    }

    /// The end of the output (an unterminated tail is never a complete record, so it is dropped).
    pub fn finish(&mut self) -> Vec<u8> {
        self.buf.clear();
        Vec::new()
    }
}

/// Whether a search rooted at the explicit `path` is refused: a Read-deny rule covers it (as written, or through a symlink).
/// Ripgrep reads a file it is given even when a `--glob !` exclude names it, so the grep tools check before it runs.
pub async fn explicit_search_path_denied(cwd: &Path, globs: &[String], path: &Path) -> bool {
    let Some(filter) = ReadDenyFilter::new(cwd, globs) else {
        return false;
    };
    let is_dir = path.is_dir();
    // Also with `.` / `..` collapsed: the tools hand ripgrep the path as it is, this only widens the refusal.
    if filter.denies(path, is_dir) || filter.denies(&path.components().collect::<PathBuf>(), is_dir) {
        return true;
    }
    match crate::util::fs::try_canonicalize(path).await {
        Ok(physical) => filter.denies(&physical, is_dir),
        // Fail closed: an existing entry (a link included) that cannot be resolved cannot be judged by where it leads.
        Err(_) => path.symlink_metadata().is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(cwd: &str, globs: &[&str]) -> ReadDenyFilter {
        ReadDenyFilter::new(Path::new(cwd), &globs.iter().map(|g| g.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn an_absolute_rule_is_applied_in_the_policy_path_form() {
        let f = filter("/abs/proj", &["/abs/proj/secrets/**"]);
        assert!(f.denies(Path::new("secrets/key"), false));
        assert!(f.denies(Path::new("/abs/proj/secrets/key"), false));
        assert!(f.denies(Path::new("secrets"), true), "a directory every child of which is denied is hidden");
        assert!(!f.denies(Path::new("src/a.rs"), false));
    }

    #[test]
    fn a_sibling_with_a_common_prefix_is_not_denied() {
        let f = filter("/a", &["/a/secret/**"]);
        assert!(!f.denies(Path::new("/a/secrets-public/x"), false));
        assert!(!f.denies(Path::new("/a/secrets-public"), true));
        assert!(f.denies(Path::new("/a/secret/x"), false));
    }

    #[test]
    fn a_bare_name_denies_only_that_exact_path_like_the_policy() {
        let f = filter("/w", &["secret"]);
        assert!(f.denies(Path::new("secret"), false), "the path `secret` is denied");
        assert!(!f.denies(Path::new("secret/notes.txt"), false), "the policy allows a Read of secret/notes.txt");
        assert!(!f.denies(Path::new("secret"), true), "a directory is visible when only some names inside are denied");
    }

    #[test]
    fn a_directory_is_pruned_only_when_everything_below_is_denied() {
        for (rule, pruned) in [("dir/**", true), ("dir/x", false), ("dir/*", false), ("dir/*.pem", false), ("**/x", false)] {
            let f = filter("/w", &[rule]);
            assert_eq!(f.denies(Path::new("dir"), true), pruned, "rule {rule}");
        }
        let f = filter("/w", &["dir/*"]);
        assert!(f.denies(Path::new("dir/a.txt"), false) && !f.denies(Path::new("dir/sub/a.txt"), false));
    }


    #[test]
    fn totality_is_decided_from_the_rule_text_and_implies_every_child_is_denied() {
        let cases = [
            ("secrets/**", "secrets", true),
            ("secrets/**/*", "secrets", true),
            ("/w/secrets/**", "secrets", true),
            ("./secrets/**", "secrets", true),
            ("secrets/**", "secrets/sub", true),
            ("**/secrets/**", "secrets", true),
            ("**/secrets/**", "a/secrets", true),
            ("*", "secrets", true),
            ("secrets/**/", "secrets", false),
            ("**/*[0-9]", "src", false),
            ("**/[!.]*", "src", false),
            ("secrets/*/**", "secrets", false),
            ("secrets/**/*.md", "secrets", false),
            ("sec*/**", "secrets", false),
            ("secrets/**", "secrets-public", false),
            ("**/secrets/**", "other", false),
        ];
        for (rule, dir, pruned) in cases {
            let f = filter("/w", &[rule]);
            assert_eq!(f.denies(Path::new(dir), true), pruned, "rule {rule} dir {dir}");
            if pruned {
                // Soundness: a pruned directory hides nothing the matcher allows.
                for child in ["a", ".hidden", "a/b", "a/.b/c.md", "x.rs"] {
                    assert!(f.denies(&Path::new(dir).join(child), false), "{rule}: child {child} of {dir} must be denied");
                }
            }
        }
    }

    #[test]
    fn a_result_that_cannot_be_resolved_is_dropped_when_rules_exist() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = dunce::canonicalize(tmp.path()).unwrap();
        std::fs::write(cwd.join("ok.txt"), "x").unwrap();
        let mut rf = ResultFilter::new(&cwd, &["secrets/**".to_string()]);
        assert!(!rf.denies(Path::new("ok.txt")), "a resolvable allowed file is kept");
        assert!(rf.denies(Path::new("no-such-dir/ok.txt")), "an unresolvable parent is dropped");
        assert!(rf.denies(Path::new("/")), "a path with no parent or name is dropped");
        let mut none = ResultFilter::new(&cwd, &[]);
        assert!(!none.denies(Path::new("no-such-dir/ok.txt")), "no rules: nothing is dropped");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_root_is_judged_by_its_canonical_place() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = dunce::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir_all(cwd.join("secrets")).unwrap();
        std::fs::write(cwd.join("secrets/key"), "k").unwrap();
        std::os::unix::fs::symlink(cwd.join("secrets"), cwd.join("alias")).unwrap();
        let f = filter(cwd.to_str().unwrap(), &["secrets/**"]);
        assert!(!f.denies(&cwd.join("alias/key"), false), "unrooted, the link hides the place");
        let f = f.rooted(&cwd.join("alias"));
        assert!(f.denies(&cwd.join("alias/key"), false));
    }
}

/// P198 round 2: one fixture and one set of assertions that every walker and every search tool is run against, so the
/// three `list_dir` walkers and the three grep tools are held to the same contract through their own tool entry points.
#[cfg(test)]
pub(crate) mod fixture {
    use std::future::Future;
    use std::path::PathBuf;

    pub(crate) struct Tree {
        _tmp: tempfile::TempDir,
        pub base: PathBuf,
        pub proj: PathBuf,
        pub link: PathBuf,
    }

    /// `base/proj` holds `secrets/key_material.txt`, `secret/notes.txt`, `secrets-public/x.txt`, `public.txt`, the
    /// links `alias -> secrets` and `keylink -> secrets/key_material.txt`; `base/link -> proj`; `base/other/outside.txt`.
    pub(crate) fn tree() -> Tree {
        let tmp = tempfile::TempDir::new().unwrap();
        let base = dunce::canonicalize(tmp.path()).unwrap();
        let proj = base.join("proj");
        for (rel, body) in [
            ("proj/secrets/key_material.txt", "FAKE_SECRET\n"),
            ("proj/secret/notes.txt", "FAKE_NOTES\n"),
            ("proj/secrets-public/x.txt", "FAKE_SIBLING\n"),
            ("proj/public.txt", "FAKE_PUBLIC\n"),
            ("other/outside.txt", "FAKE_OUTSIDE\n"),
        ] {
            let p = base.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        std::os::unix::fs::symlink("secrets", proj.join("alias")).unwrap();
        std::os::unix::fs::symlink("secrets/key_material.txt", proj.join("keylink")).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&proj, &link).unwrap();
        Tree { _tmp: tmp, base, proj, link }
    }

    /// The lines of a search output in a fixed order: ripgrep walks in parallel, so two runs over the same files print
    /// the same lines in different orders.
    pub(crate) fn sorted_lines(out: &str) -> Vec<&str> {
        let mut lines: Vec<&str> = out.lines().collect();
        lines.sort_unstable();
        lines
    }

    /// Whether some line of a listing is exactly the entry `name` (a name, not a substring of a longer one).
    pub(crate) fn has_name(out: &str, name: &str) -> bool {
        out.lines().any(|l| l.trim_start_matches(['-', ' ', '\t']).trim_end_matches('/').trim() == name)
    }

    /// The `list_dir` contract, run through `list(cwd, directory, deny globs) -> printed listing`.
    pub(crate) async fn check_list<F, Fut>(list: F)
    where
        F: Fn(PathBuf, String, Vec<String>) -> Fut,
        Fut: Future<Output = String>,
    {
        let t = tree();
        let abs = |rel: &str| format!("{}/{}", t.proj.display(), rel);
        let ls = |cwd: &PathBuf, dir: &str, deny: Vec<String>| list(cwd.clone(), dir.to_string(), deny);

        // Absolute rule on the directory: the directory name and everything under it are gone, siblings stay. Also with the
        // cwd reached through a symlink.
        for cwd in [&t.proj, &t.link] {
            let out = ls(cwd, ".", vec![abs("secrets/**")]).await;
            assert!(!out.contains("key_material.txt"), "cwd {}: {out}", cwd.display());
            assert!(!has_name(&out, "secrets"), "the denied directory name is hidden, cwd {}: {out}", cwd.display());
            assert!(has_name(&out, "public.txt") && has_name(&out, "secrets-public") && has_name(&out, "secret"), "{out}");
        }
        // Control: no rule shows the name, so the checks above are not vacuous.
        let out = ls(&t.proj, ".", Vec::new()).await;
        assert!(has_name(&out, "secrets") && out.contains("key_material.txt"), "{out}");
        // A rule outside the cwd neither breaks the listing nor hides anything in it.
        let out = ls(&t.proj, ".", vec![format!("{}/other/**", t.base.display())]).await;
        assert_eq!(out, ls(&t.proj, ".", Vec::new()).await);

        // Bare name `secret`: matches only the path `secret`, so `secret/notes.txt` is readable (see
        // `hub_permission::tests::bare_name_and_sibling_verdicts`) and is therefore listed.
        let out = ls(&t.proj, ".", vec!["secret".to_string()]).await;
        assert!(has_name(&out, "notes.txt") && has_name(&out, "secret"), "{out}");

        // Symlink root: `alias -> secrets` under `secrets/**` shows no denied name; without the rule it shows them.
        let out = ls(&t.proj, "alias", vec!["secrets/**".to_string()]).await;
        assert!(!out.contains("key_material.txt"), "{out}");
        let out = ls(&t.proj, "alias", Vec::new()).await;
        assert!(out.contains("key_material.txt"), "control: {out}");

        // Siblings with a common prefix are untouched.
        let out = ls(&t.proj, ".", vec!["secret/**".to_string()]).await;
        assert!(has_name(&out, "x.txt") && out.contains("key_material.txt") && !out.contains("notes.txt"), "{out}");
        let out = ls(&t.proj, ".", vec!["secrets/**".to_string()]).await;
        assert!(has_name(&out, "x.txt") && has_name(&out, "notes.txt") && !out.contains("key_material.txt"), "{out}");
    }

    /// The search contract for a directory root, run through `search(cwd, path, deny globs) -> everything the tool printed`.
    pub(crate) async fn check_grep<F, Fut>(search: F)
    where
        F: Fn(PathBuf, Option<String>, Vec<String>) -> Fut,
        Fut: Future<Output = String>,
    {
        let t = tree();
        let abs = |rel: &str| format!("{}/{}", t.proj.display(), rel);
        let run = |cwd: &PathBuf, path: Option<&str>, deny: Vec<String>| {
            search(cwd.clone(), path.map(str::to_string), deny)
        };
        let secret_seen = |out: &str| out.contains("key_material.txt") || out.contains("FAKE_SECRET");

        // KNOWN GAP (receipt, Unverified): `t.link` as the cwd is not covered here. ripgrep roots its excludes at the
        // physical cwd, so a search path spelled through the symlink is not read as under it.
        for cwd in [&t.proj] {
            for path in [None, Some("."), Some("secrets"), Some("alias")] {
                let out = run(cwd, path, vec![abs("secrets/**")]).await;
                assert!(!secret_seen(&out), "cwd {} path {path:?}: {out}", cwd.display());
                if path.is_none() || path == Some(".") {
                    assert!(out.contains("public.txt"), "an allowed file is still found, cwd {}: {out}", cwd.display());
                }
            }
        }
        // Control: with no rule the denied file is found.
        assert!(secret_seen(&run(&t.proj, None, Vec::new()).await));
        // A rule outside the cwd neither breaks the search nor excludes anything in it.
        let out = run(&t.proj, None, vec![format!("{}/other/**", t.base.display())]).await;
        assert!(secret_seen(&out) && out.contains("public.txt") && !out.contains("outside.txt"), "{out}");
        // Bare name `secret`: `secret/notes.txt` is readable, so it is found.
        let out = run(&t.proj, None, vec!["secret".to_string()]).await;
        assert!(out.contains("notes.txt"), "{out}");
        // Siblings with a common prefix are untouched.
        let out = run(&t.proj, None, vec!["secret/**".to_string()]).await;
        assert!(out.contains("secrets-public") && secret_seen(&out) && !out.contains("notes.txt"), "{out}");
        let out = run(&t.proj, None, vec!["secrets/**".to_string()]).await;
        assert!(out.contains("secrets-public") && out.contains("notes.txt") && !secret_seen(&out), "{out}");
    }

    /// A denied explicit file is refused: no content and, whatever the spelling, not the name it really has.
    pub(crate) async fn check_explicit_file<F, Fut>(search: F)
    where
        F: Fn(PathBuf, String, Vec<String>) -> Fut,
        Fut: Future<Output = String>,
    {
        let t = tree();
        let deny = vec!["secrets/**".to_string()];
        let direct = t.proj.join("secrets/key_material.txt").to_string_lossy().into_owned();
        let via_link = t.proj.join("keylink").to_string_lossy().into_owned();
        for path in ["secrets/key_material.txt", direct.as_str()] {
            let out = search(t.proj.clone(), path.to_string(), deny.clone()).await;
            assert!(!out.contains("FAKE_SECRET"), "{path}: {out}");
        }
        for path in ["keylink", via_link.as_str()] {
            let out = search(t.proj.clone(), path.to_string(), deny.clone()).await;
            assert!(!out.contains("FAKE_SECRET") && !out.contains("key_material.txt"), "{path}: {out}");
        }
        // Controls: with no rule the same spellings do read it, and an allowed explicit file is searched under the rule.
        for path in ["secrets/key_material.txt", "keylink"] {
            let out = search(t.proj.clone(), path.to_string(), Vec::new()).await;
            assert!(out.contains("FAKE_SECRET") || out.contains("key_material.txt") || out.contains("keylink"), "{path}: {out}");
        }
        let out = search(t.proj.clone(), "public.txt".to_string(), deny).await;
        assert!(out.contains("public.txt") || out.contains("FAKE_PUBLIC"), "{out}");
    }

    /// P198 round 3: the post-filter contract, run through `search(cwd, path, deny globs) -> everything the tool printed`
    /// (file names appear in every output mode and in the glob listing; the files all contain `FAKE`).
    pub(crate) async fn check_round3<F, Fut>(search: F)
    where
        F: Fn(PathBuf, Option<String>, Vec<String>) -> Fut,
        Fut: Future<Output = String>,
    {
        check_round3_with(search, true).await
    }

    /// [`check_round3`]; `gone_cwd_without_rules_runs` is false for a tool that must keep integration `0e5a6b09`'s
    /// invocation when there are no rules (codex `grep_files` sets `current_dir` unconditionally, so a missing cwd
    /// fails the spawn exactly as it did there).
    pub(crate) async fn check_round3_with<F, Fut>(search: F, gone_cwd_without_rules_runs: bool)
    where
        F: Fn(PathBuf, Option<String>, Vec<String>) -> Fut,
        Fut: Future<Output = String>,
    {
        use super::ReadDenyFilter;
        let tmp = tempfile::TempDir::new().unwrap();
        let base = dunce::canonicalize(tmp.path()).unwrap();
        let proj = base.join("proj");
        let files = [
            "proj/secrets/KEYA.txt",
            "proj/secrets/NOTESA.txt",
            "proj/secrets/x",
            "proj/Secrets/KEYB.txt",
            "proj/.ENV",
            "proj/src/SRCA.txt",
            "proj/sub/SUBPEM.pem",
            "proj/TOPPEM.pem",
            "proj/dir/DIRX.txt",
            "proj/dir/sub/DIRSUB.txt",
            "proj/BRACE.{pem,txt}",
            "proj/COLON:FILE.txt",
            "proj/!bang.txt",
            "proj/pubfile.txt",
            "outside/.ssh/SSHKEY.txt",
            "outside/OUTOK.txt",
        ];
        for rel in files {
            let p = base.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, format!("FAKE {rel}\n")).unwrap();
        }
        let link = base.join("link");
        std::os::unix::fs::symlink(&proj, &link).unwrap();
        let gone = base.join("gone");
        let abs = |rel: &str| format!("{}/{}", proj.display(), rel);
        let s = |v: &str| v.to_string();

        struct Case {
            name: &'static str,
            cwd: PathBuf,
            path: Option<String>,
            deny: Vec<String>,
            hidden: Vec<&'static str>,
            shown: Vec<&'static str>,
        }
        let cases = vec![
            // (1) a symlinked session cwd.
            Case { name: "link cwd", cwd: link.clone(), path: None, deny: vec![s("secrets/**")], hidden: vec!["KEYA"], shown: vec!["pubfile"] },
            Case { name: "link cwd, dot", cwd: link.clone(), path: Some(s(".")), deny: vec![s("secrets/**")], hidden: vec!["KEYA"], shown: vec!["pubfile"] },
            Case { name: "link cwd, link rule", cwd: link.clone(), path: None, deny: vec![format!("{}/secrets/**", link.display())], hidden: vec!["KEYA"], shown: vec!["pubfile"] },
            // (2) case: the policy matcher is case-insensitive.
            Case { name: "case file", cwd: proj.clone(), path: None, deny: vec![s("**/.env")], hidden: vec![".ENV"], shown: vec!["pubfile"] },
            Case { name: "case dir", cwd: proj.clone(), path: None, deny: vec![s("secrets/**")], hidden: vec!["KEYA", "KEYB"], shown: vec!["pubfile", "SRCA"] },
            // (3) an absolute rule outside the cwd, reached through an ancestor search root.
            Case { name: "outside rule", cwd: proj.clone(), path: Some(base.display().to_string()), deny: vec![format!("{}/outside/.ssh/**", base.display())], hidden: vec!["SSHKEY"], shown: vec!["OUTOK", "pubfile"] },
            // (4) braces are literal for the policy.
            Case { name: "braces", cwd: proj.clone(), path: None, deny: vec![s("*.{pem,txt}")], hidden: vec!["BRACE"], shown: vec!["SUBPEM", "TOPPEM", "pubfile"] },
            // (5) false-denial guards.
            Case { name: "abs star pem", cwd: proj.clone(), path: None, deny: vec![abs("*.pem")], hidden: vec!["TOPPEM"], shown: vec!["SUBPEM"] },
            Case { name: "trailing slash", cwd: proj.clone(), path: None, deny: vec![s("src/")], hidden: vec![], shown: vec!["SRCA"] },
            Case { name: "literal child", cwd: proj.clone(), path: None, deny: vec![s("secrets/x")], hidden: vec![], shown: vec!["KEYA", "NOTESA"] },
            Case { name: "dir star", cwd: proj.clone(), path: None, deny: vec![s("dir/*")], hidden: vec!["DIRX"], shown: vec!["DIRSUB"] },
            Case { name: "bang rule", cwd: proj.clone(), path: None, deny: vec![s("!bang.txt")], hidden: vec!["bang"], shown: vec!["pubfile", "SRCA", "KEYA"] },
            // (5c) an explicit directory is searched unless EVERYTHING below it is denied.
            Case { name: "dir literal child", cwd: proj.clone(), path: Some(s("secrets")), deny: vec![s("secrets/x")], hidden: vec![], shown: vec!["KEYA", "NOTESA"] },
            Case { name: "dir star child", cwd: proj.clone(), path: Some(s("dir")), deny: vec![s("dir/*")], hidden: vec!["DIRX"], shown: vec!["DIRSUB"] },
            Case { name: "dir all denied", cwd: proj.clone(), path: Some(s("secrets")), deny: vec![s("secrets/**")], hidden: vec!["KEYA", "NOTESA"], shown: vec![] },
            // (6) a name holding `:`.
            Case { name: "colon", cwd: proj.clone(), path: None, deny: vec![s("COLON:FILE.txt")], hidden: vec!["COLON"], shown: vec!["pubfile"] },
            // (7) a missing session cwd does not fail the spawn.
            Case { name: "gone cwd", cwd: gone.clone(), path: Some(proj.display().to_string()), deny: vec![abs("secrets/**")], hidden: vec!["KEYA"], shown: vec!["pubfile"] },
            Case { name: "gone cwd, no rule", cwd: gone.clone(), path: Some(proj.display().to_string()), deny: vec![], hidden: vec![], shown: vec!["pubfile", "KEYA"] },
        ];
        for c in cases {
            if c.name == "gone cwd, no rule" && !gone_cwd_without_rules_runs {
                continue;
            }
            // The policy's own verdicts, so a "shown" token is a file the policy allows.
            if let Some(f) = ReadDenyFilter::new(&c.cwd, &c.deny) {
                for (tok, rel) in [("SRCA", "src/SRCA.txt"), ("NOTESA", "secrets/NOTESA.txt"), ("DIRSUB", "dir/sub/DIRSUB.txt"), ("SUBPEM", "sub/SUBPEM.pem")] {
                    if c.shown.contains(&tok) {
                        assert!(!f.denies(&proj.join(rel), false), "{}: the policy must allow {rel}", c.name);
                    }
                }
            }
            let out = search(c.cwd.clone(), c.path.clone(), c.deny.clone()).await;
            for h in &c.hidden {
                assert!(!out.contains(h), "{}: `{h}` must be hidden: {out}", c.name);
            }
            for v in &c.shown {
                assert!(out.contains(v), "{}: `{v}` must still be found: {out}", c.name);
            }
            // The denied files' content never appears.
            for h in &c.hidden {
                assert!(!out.contains(&format!("FAKE {h}")), "{}: content of `{h}`: {out}", c.name);
            }
        }
    }

    /// P198 round 4 tree under `proj`: allowed files (plain, two binary shapes, odd names) and, with `denied`, a
    /// `secrets` directory holding the same shapes with `FAKE_DENIED*` bodies.
    pub(crate) fn write_r4_tree(proj: &std::path::Path, denied: bool) {
        use std::os::unix::ffi::OsStrExt;
        let filler = "x".repeat(79).repeat(2600);
        let filler = filler.as_bytes().chunks(79).map(|c| format!("{}\n", std::str::from_utf8(c).unwrap())).collect::<String>();
        let put = |rel: &[u8], body: Vec<u8>| {
            let p = proj.join(std::ffi::OsStr::from_bytes(rel));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        let early_then_nul = |tag: &str| format!("FAKE_{tag}\n{filler}\0 FAKE_{tag}_LATE\n").into_bytes();
        let nul_in_match = |tag: &str| format!("{filler}x\0 FAKE_{tag}\n").into_bytes();
        put(b"pub.txt", b"FAKE_PUB\n".to_vec());
        put(b"aa_bin", early_then_nul("BIN_EARLY"));
        put(b"zz_bin", nul_in_match("BIN_NOTICE"));
        put(b"odd:name.txt", b"FAKE_ODD\n".to_vec());
        put(b"nl\nname.txt", b"FAKE_NL\n".to_vec());
        put(b"bad\xff.txt", b"FAKE_BAD\n".to_vec());
        for i in 0..12 {
            put(format!("bins/b{i:02}").as_bytes(), nul_in_match("BIN_MANY"));
            put(format!("bins/c{i:02}").as_bytes(), early_then_nul("BIN_MANY2"));
        }
        if denied {
            for i in 0..12 {
                put(format!("secrets/t{i:02}.txt").as_bytes(), format!("FAKE_DENIED_T{i}\n").into_bytes());
            }
            put(b"secrets/key.txt", b"FAKE_DENIED\n".to_vec());
            put(b"secrets/aa_bin.dat", early_then_nul("DENIED_BIN"));
            put(b"secrets/zz_bin.dat", nul_in_match("DENIED_NOTICE"));
            put(b"secrets/we\nird:name.txt", b"FAKE_DENIED_NL\n".to_vec());
            put(b"secrets/bad\xff.txt", b"FAKE_DENIED_BAD\n".to_vec());
        }
    }

    /// P198 round 4 contract, run through `search(cwd, path, deny globs) -> everything the tool printed` for the
    /// pattern `FAKE`: binary files (both notice shapes) before and after a denied file, odd file names, a failing
    /// ripgrep, and "a rule is present but nothing is denied" printing what no rule prints.
    pub(crate) async fn check_round4<F, Fut>(search: F)
    where
        F: Fn(PathBuf, Option<String>, Vec<String>) -> Fut,
        Fut: Future<Output = String>,
    {
        use std::os::unix::fs::PermissionsExt;
        let t = tree();
        let proj = t.base.join("r4");
        std::fs::create_dir_all(&proj).unwrap();
        write_r4_tree(&proj, true);
        let deny = vec!["secrets/**".to_string()];
        // (1) a denied file's lines and name never appear, whatever binary notices sit beside it.
        for _ in 0..5 {
            let out = search(proj.clone(), None, deny.clone()).await;
            for bad in ["FAKE_DENIED", "key.txt", "aa_bin.dat", "zz_bin.dat", "ird:name", "secrets", "t00.txt"] {
                assert!(!out.contains(bad), "`{bad}` leaked: {}", out.escape_debug());
            }
            assert!(out.contains("pub.txt") || out.contains("FAKE_PUB"), "an allowed file is still found: {}", out.escape_debug());
        }
        // Control: without the rule the same tree does show them, so the checks above are not vacuous.
        let out = search(proj.clone(), None, Vec::new()).await;
        assert!(out.contains("key.txt") || out.contains("FAKE_DENIED"), "control: {}", out.escape_debug());
        // (2) a mode-000 file and directory under the denied directory make ripgrep exit 2: nothing of them is shown.
        let locked = proj.join("secrets/locked.txt");
        std::fs::write(&locked, "FAKE_LOCKED\n").unwrap();
        std::fs::create_dir_all(proj.join("secrets/lockeddir")).unwrap();
        std::fs::write(proj.join("secrets/lockeddir/in.txt"), "FAKE_LOCKED_IN\n").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::set_permissions(proj.join("secrets/lockeddir"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let out = search(proj.clone(), None, deny.clone()).await;
        std::fs::set_permissions(proj.join("secrets/lockeddir"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
        for bad in ["locked", "Permission denied", "secrets"] {
            assert!(!out.contains(bad), "`{bad}` leaked: {}", out.escape_debug());
        }
        // (5) a rule that denies nothing prints exactly what no rule prints (modulo ripgrep's parallel order).
        let plain = tree();
        let p5 = plain.base.join("r5");
        std::fs::create_dir_all(&p5).unwrap();
        write_r4_tree(&p5, false);
        std::fs::write(p5.join("g.txt"), "1\nFAKE\n3\n4\n5\n6\nFAKE\n8\n").unwrap();
        let none = search(p5.clone(), None, Vec::new()).await;
        let with_rule = search(p5.clone(), None, vec!["nothing-here/**".to_string()]).await;
        assert!(none.contains("FAKE_PUB") || none.contains("pub.txt"), "{}", none.escape_debug());
        assert_eq!(sorted_lines(&none), sorted_lines(&with_rule), "a rule that denies nothing changes the output");
    }

    /// P198 round 4: `**/*[0-9]` and `**/[!.]*` are not "total" under any directory, so a directory is entered and each
    /// child is judged by the matcher: `src/README.md` and `src/.env` are shown exactly when the policy allows a Read.
    /// `search(cwd, path, deny)` prints everything a tool printed for `FAKE`.
    pub(crate) async fn check_round4_rules<F, Fut>(search: F)
    where
        F: Fn(PathBuf, Option<String>, Vec<String>) -> Fut,
        Fut: Future<Output = String>,
    {
        use super::ReadDenyFilter;
        let t = tree();
        let proj = t.base.join("r4rules");
        for (rel, body) in [("src/README.md", "FAKE_README\n"), ("src/.env", "FAKE_DOTENV\n"), ("src/main1", "FAKE_MAIN1\n")] {
            let p = proj.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        for rule in ["**/*[0-9]", "**/[!.]*"] {
            let deny = vec![rule.to_string()];
            let f = ReadDenyFilter::new(&proj, &deny).unwrap();
            assert!(!f.denies(&proj.join("src"), true), "{rule}: `src` is not pruned");
            let out = search(proj.clone(), None, deny).await;
            for (tok, rel) in [("FAKE_README", "src/README.md"), ("FAKE_MAIN1", "src/main1")] {
                let allowed = !f.denies(&proj.join(rel), false);
                let shown = out.contains(tok) || out.contains(rel.rsplit('/').next().unwrap());
                assert_eq!(shown, allowed, "{rule}: {rel} (policy allows: {allowed}): {}", out.escape_debug());
            }
            let dot_allowed = !f.denies(&proj.join("src/.env"), false);
            assert!(dot_allowed || !out.contains("FAKE_DOTENV"), "{rule}: denied .env leaked");
        }
        // P175f: an absolute rule spelled through the symlink `base/link -> proj` also hides the physical spelling.
        let via_link = format!("{}/link/secrets/**", t.base.display());
        let control = search(t.proj.clone(), Some(t.proj.display().to_string()), Vec::new()).await;
        assert!(control.contains("FAKE_SECRET") || control.contains("key_material"), "control: {}", control.escape_debug());
        for (cwd, path) in [(t.proj.clone(), Some(t.proj.display().to_string())), (t.proj.clone(), None), (t.base.clone(), Some(t.proj.display().to_string()))] {
            let out = search(cwd, path.clone(), vec![via_link.clone()]).await;
            assert!(!out.contains("FAKE_SECRET") && !out.contains("key_material"), "via link, root {path:?}: {}", out.escape_debug());
            assert!(out.contains("FAKE_PUBLIC") || out.contains("public.txt"), "via link, root {path:?}: sibling kept: {}", out.escape_debug());
        }
    }

    /// P198 round 4 for the `list_dir` walkers, through `list(cwd, directory, deny globs) -> printed listing`: the rules
    /// `secrets/**`, `secrets/**/*` and `<abs cwd>/secrets/**` still hide the directory name, and `**/*[0-9]` /
    /// `**/[!.]*` list `src/README.md` and `src/.env` exactly when the policy allows a Read of them.
    pub(crate) async fn check_list_round4<F, Fut>(list: F)
    where
        F: Fn(PathBuf, String, Vec<String>) -> Fut,
        Fut: Future<Output = String>,
    {
        use super::ReadDenyFilter;
        let t = tree();
        let proj = t.base.join("r4list");
        for rel in ["secrets/key.txt", "src/README.md", "src/.env", "src/main1"] {
            let p = proj.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "x").unwrap();
        }
        for rule in ["secrets/**".to_string(), "secrets/**/*".to_string(), format!("{}/secrets/**", proj.display())] {
            let out = list(proj.clone(), ".".to_string(), vec![rule.clone()]).await;
            assert!(!has_name(&out, "secrets") && !out.contains("key.txt"), "{rule}: {out}");
            assert!(has_name(&out, "src"), "{rule}: {out}");
        }
        for rule in ["**/*[0-9]", "**/[!.]*"] {
            let deny = vec![rule.to_string()];
            let f = ReadDenyFilter::new(&proj, &deny).unwrap();
            let out = list(proj.clone(), "src".to_string(), deny).await;
            for name in ["README.md", "main1"] {
                let allowed = !f.denies(&proj.join("src").join(name), false);
                assert_eq!(has_name(&out, name), allowed, "{rule}: {name} (policy allows: {allowed}): {out}");
            }
            let out = list(proj.clone(), ".".to_string(), vec![rule.to_string()]).await;
            assert!(has_name(&out, "src"), "{rule}: a directory is entered, not pruned: {out}");
        }
        // P175f: an absolute rule spelled through the symlink `base/link -> proj` also hides the physical spelling.
        let out = list(t.proj.clone(), ".".to_string(), vec![format!("{}/link/secrets/**", t.base.display())]).await;
        assert!(!out.contains("key_material.txt") && !has_name(&out, "secrets"), "via link: {out}");
        assert!(has_name(&out, "public.txt") && has_name(&out, "secrets-public"), "via link: siblings kept: {out}");
    }
}
