//! Path matching shared by the permission policy (`fuigo-workspace`) and the tools that must judge a path the same way
//! (P198: `list_dir`, `grep` and `glob` hide what a `Read` of the path would deny). One implementation, so the two cannot disagree.
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use fuigo_paths::normalize_lexically;

/// Cwd that relative path rules anchor to, kept as written and with symlinks resolved (ported from upstream `RuleBase`).
pub struct RuleBase<'a> {
    /// The cwd as the caller wrote it
    pub lexical: &'a Path,
    pub lexical_normalized: PathBuf,
    /// The cwd with symlinks resolved on first use, `None` when that fails, changes nothing, or is withheld
    physical: OnceLock<Option<PathBuf>>,
}

impl<'a> RuleBase<'a> {
    pub fn new(cwd: &'a Path) -> Self {
        RuleBase {
            lexical: cwd,
            lexical_normalized: normalize_lexically(cwd),
            physical: OnceLock::new(),
        }
    }

    /// A base whose physical cwd was resolved earlier (see [`RuleBase::resolved_physical`]), so a filter that judges many
    /// paths resolves the cwd's symlinks once.
    pub fn with_physical(cwd: &'a Path, physical: Option<PathBuf>) -> Self {
        RuleBase {
            lexical: cwd,
            lexical_normalized: normalize_lexically(cwd),
            physical: OnceLock::from(physical),
        }
    }

    /// The physical cwd (symlinks resolved) when it differs from the written one.
    pub fn resolved_physical(&self) -> Option<PathBuf> {
        self.physical().map(Path::to_path_buf)
    }

    /// The same cwd with its physical form withheld: for a path whose `..` was collapsed as text before matching,
    /// and for allow rules, which a symlinked cwd must never widen.
    pub fn without_physical(&self) -> Self {
        RuleBase {
            lexical: self.lexical,
            lexical_normalized: self.lexical_normalized.clone(),
            physical: OnceLock::from(None),
        }
    }

    pub fn physical(&self) -> Option<&Path> {
        self.physical
            .get_or_init(|| {
                self.lexical
                    .is_absolute()
                    .then_some(self.lexical)
                    .and_then(resolve_following_symlinks)
                    .map(|physical| normalize_lexically(&physical))
                    .filter(|physical| *physical != self.lexical_normalized)
            })
            .as_deref()
    }
}

/// Normalized absolute form, plus cwd-relative and `./`-prefixed spellings for a path under either cwd form (so `Read(./**)` matches bare `src/main.rs`).
/// A path under only the physical cwd also gets its absolute spelling under the written cwd, so logically written absolute rules match it.
/// A path written with `..` gets no physical-cwd forms here; the escalate-only target re-check supplies them.
/// Normalization never leaves `.`/`..` in the forms, so a relative spelling is produced only for paths genuinely under one of the cwds.
/// Tilde paths are matched literally only (see [`is_tilde_path`]).
pub fn path_match_forms(path: &str, base: Option<&RuleBase<'_>>) -> Vec<String> {
    let abs = absolute_normalized_path(path, base.map(|base| base.lexical));
    let mut forms = vec![path_match_string(&abs)];

    if let Some(base) = base {
        let mut rels: Vec<&Path> = abs
            .strip_prefix(&base.lexical_normalized)
            .ok()
            .into_iter()
            .collect();
        // `..` was collapsed against the written cwd, so the result says nothing about the physical one.
        // Otherwise the physical-relative spelling is offered too, even when the written cwd also contains the path
        // (a written cwd like `<link>/..` can normalize to an ancestor of its physical form).
        let physical_rel = (!path_has_parent_dir(Path::new(path)))
            .then(|| base.physical())
            .flatten()
            .and_then(|physical| abs.strip_prefix(physical).ok())
            .filter(|rel| !rels.contains(rel));
        if let Some(rel) = physical_rel {
            // The same path spelled under the written cwd, so written absolute rules match it
            let written: PathBuf = base
                .lexical_normalized
                .components()
                .chain(rel.components())
                .collect();
            forms.push(path_match_string(&written));
            rels.push(rel);
        }
        for rel in rels {
            let rel_s = path_match_string(rel);
            if rel_s.is_empty() || rel_s == "." {
                forms.extend([".".to_owned(), "./".to_owned()]);
            } else {
                forms.push(format!("./{rel_s}"));
                forms.push(rel_s);
            }
        }
    } else if abs.is_relative() && !path_has_parent_dir(&abs) && !is_tilde_path(&abs) {
        // No session cwd: still offer `./form` so `./**` matches bare relatives.
        let lex_s = path_match_string(&abs);
        if lex_s != "." && !lex_s.is_empty() {
            forms.push(format!("./{lex_s}"));
        }
    }
    forms
}

pub fn absolute_normalized_path(path: &str, cwd: Option<&Path>) -> PathBuf {
    let raw = Path::new(path);
    if is_tilde_path(raw) {
        // Kept raw: no cwd-join and no collapse; collapsing `~/../x` to `x` would make it look workspace-relative
        return raw.to_path_buf();
    }
    let joined = match cwd {
        Some(cwd) if !raw.is_absolute() => cwd.join(raw),
        _ => raw.to_path_buf(),
    };
    normalize_lexically(&joined)
}

/// A leading `~` component is expanded to the home directory by the tools (`resolve_model_path`) *after* this gate runs.
/// Such a path must never be treated as cwd-relative.
/// A manufactured `./~/…` spelling would satisfy workspace allows like `./**` while the tool escapes to the real home.
/// Tilde paths are matched literally instead, exactly as patterns treat `~`.
pub fn is_tilde_path(path: &Path) -> bool {
    matches!(
        path.components().next(),
        Some(Component::Normal(first)) if first.to_string_lossy().starts_with('~')
    )
}

pub fn path_match_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub fn path_has_parent_dir(path: &Path) -> bool {
    path.components().any(|c| matches!(c, Component::ParentDir))
}

/// Follow every symlink, including dangling leaves and missing trailing components.
pub fn resolve_following_symlinks(path: &Path) -> Option<PathBuf> {
    fn walk(path: &Path, depth: usize) -> Option<PathBuf> {
        const MAX_SYMLINK_DEPTH: usize = 40;
        if depth > MAX_SYMLINK_DEPTH {
            return None;
        }
        // `dunce` avoids Windows `\\?\` verbatim paths (repo convention).
        if let Ok(canonical) = dunce::canonicalize(path) {
            return Some(canonical);
        }
        // Parent-first so a dangling or not-yet-created leaf still follows links.
        let parent = path.parent()?;
        let file_name = path.file_name()?;
        let resolved_parent = walk(parent, depth + 1)?;
        let candidate = resolved_parent.join(file_name);
        // NotFound is a new path; any other metadata error fails closed.
        let metadata = match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return None,
        };
        if metadata.is_some_and(|metadata| metadata.file_type().is_symlink()) {
            // Unreadable link target fails closed rather than treating the link path as real.
            let target = std::fs::read_link(&candidate).ok()?;
            let target = if target.is_absolute() {
                target
            } else {
                resolved_parent.join(target)
            };
            return walk(&target, depth + 1);
        }
        Some(candidate)
    }
    walk(path, 0)
}

/// Split an absolute path pattern into its literal directory prefix and the rest (`/a/b/**` -> `/a/b`, `/**`).
/// `None` when the pattern is not absolute or has no literal directory component.
pub fn literal_dir_prefix(pattern: &str) -> Option<(String, String)> {
    if !pattern.starts_with('/') {
        return None;
    }
    let mut end = 0;
    for (i, c) in pattern.char_indices() {
        match c {
            '*' | '?' | '[' | '{' => break,
            '/' if i > 0 => end = i,
            _ => {}
        }
        if i + c.len_utf8() == pattern.len() {
            end = pattern.len();
        }
    }
    (end > 1).then(|| (pattern[..end].to_owned(), pattern[end..].to_owned()))
}

/// P175f: the pattern `prefix + rest` with its literal directory prefix replaced by the prefix's physical form
/// (symlinks followed, missing trailing components kept). `None` when nothing changes or the prefix cannot be resolved.
pub fn physical_alias_pattern_string(prefix: &str, rest: &str) -> Option<String> {
    let physical = resolve_following_symlinks(Path::new(prefix))?;
    let physical = path_match_string(&physical);
    (physical != prefix).then(|| format!("{}{rest}", glob::Pattern::escape(&physical)))
}

/// [`physical_alias_pattern_string`] bounded by `limit`: the resolution runs on its own thread and the caller waits at
/// most `limit`. `None` on timeout (the resolving thread is left to finish on its own), exactly as when there is no alias.
pub fn physical_alias_pattern_string_bounded(prefix: &str, rest: &str, limit: std::time::Duration) -> Option<String> {
    bounded_alias(prefix, rest, limit, &ALIAS_STUCK, physical_alias_pattern_string)
}

/// How many resolver threads were given up on (timed out) and have not returned yet. While it is non-zero (a hung
/// mount) no new resolver is spawned and calls return `None` at once, so at most one thread is ever parked behind it.
/// Resolvers that finish within their budget never count, so concurrent searches do not affect each other.
static ALIAS_STUCK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

const RUNNING: u8 = 0;
const DONE: u8 = 1;
const ABANDONED: u8 = 2;

/// Marks one resolver call finished when the thread ends, however it ends; releases its stuck count if abandoned.
struct Finish(std::sync::Arc<std::sync::atomic::AtomicU8>, &'static std::sync::atomic::AtomicUsize);

impl Drop for Finish {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        if self.0.compare_exchange(RUNNING, DONE, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            self.1.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn bounded_alias(
    prefix: &str,
    rest: &str,
    limit: std::time::Duration,
    // The stuck count to use: [`ALIAS_STUCK`] in the product; tests pass their own so they cannot disturb other tests.
    stuck: &'static std::sync::atomic::AtomicUsize,
    resolve: impl FnOnce(&str, &str) -> Option<String> + Send + 'static,
) -> Option<String> {
    use std::sync::atomic::{AtomicU8, Ordering};
    if stuck.load(Ordering::SeqCst) > 0 {
        return None;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let (prefix, rest) = (prefix.to_owned(), rest.to_owned());
    let state = std::sync::Arc::new(AtomicU8::new(RUNNING));
    let finish = Finish(state.clone(), stuck);
    let spawned = std::thread::Builder::new().name("alias-resolve".into()).spawn(move || {
        let out = resolve(&prefix, &rest);
        // Marked finished before the caller is woken, so a normal call leaves nothing behind.
        drop(finish);
        let _ = tx.send(out);
    });
    if spawned.is_err() {
        return None;
    }
    if let Ok(out) = rx.recv_timeout(limit) {
        return out;
    }
    // Timed out (or the thread died): count first, then claim; if the thread finishes in between, it releases the
    // count itself, and if it had already finished the claim fails and the count is returned here.
    stuck.fetch_add(1, Ordering::SeqCst);
    if state.compare_exchange(RUNNING, ABANDONED, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        stuck.fetch_sub(1, Ordering::SeqCst);
    }
    None
}

/// The options the policy matches path rules with: `*` does not cross a `/`.
pub fn path_glob_options() -> glob::MatchOptions {
    glob::MatchOptions {
        require_literal_separator: true,
        require_literal_leading_dot: false,
        ..Default::default()
    }
}

/// Whether a path rule's compiled pattern matches `path` in any of the spellings the policy offers for it.
/// This is the policy's own test for `Read`/`Edit`/`Grep` rules.
pub fn path_pattern_matches(path: &str, pattern: &glob::Pattern, base: Option<&RuleBase<'_>>) -> bool {
    path_match_forms(path, base)
        .iter()
        .any(|text| pattern.matches_with(text, path_glob_options()))
}

#[cfg(test)]
mod bounded_alias_tests {
    use std::time::{Duration, Instant};

    use super::*;

    /// These tests share [`TEST_STUCK`], so they run one at a time.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The tests' own stuck count: a resolver they leave parked must not switch the alias off for other tests of this
    /// binary that build a real `ReadDenyFilter` (Grok p175f r3 LOW).
    static TEST_STUCK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// Wait (bounded) until no resolver thread is in flight.
    fn wait_idle() {
        let deadline = Instant::now() + Duration::from_secs(10);
        while TEST_STUCK.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            assert!(Instant::now() < deadline, "resolver still in flight");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_slow_resolver_yields_none_within_about_the_limit() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let start = Instant::now();
        let out = bounded_alias("/x", "/**", Duration::from_millis(100), &TEST_STUCK, |_, _| {
            std::thread::sleep(Duration::from_secs(2));
            Some("/never".to_owned())
        });
        assert_eq!(out, None);
        assert!(start.elapsed() < Duration::from_millis(1500), "waited {:?}", start.elapsed());
        wait_idle();
    }

    #[cfg(unix)]
    #[test]
    fn a_prefix_through_a_link_returns_the_alias() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        wait_idle();
        let tmp = tempfile::TempDir::new().unwrap();
        let root = dunce::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let prefix = format!("{}/link", root.display());
        let out = physical_alias_pattern_string_bounded(&prefix, "/secrets/**", Duration::from_secs(5));
        assert_eq!(out, Some(format!("{}/real/secrets/**", glob::Pattern::escape(&root.display().to_string()))));
    }

    #[test]
    fn a_stuck_resolver_is_the_only_one_ever_spawned() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let runs = std::sync::Arc::new(AtomicUsize::new(0));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let r = runs.clone();
        let start = Instant::now();
        let out = bounded_alias("/x", "/**", Duration::from_millis(100), &TEST_STUCK, move |_, _| {
            r.fetch_add(1, Ordering::SeqCst);
            let _ = release_rx.recv();
            Some("/late".to_owned())
        });
        assert_eq!(out, None);
        assert!(start.elapsed() >= Duration::from_millis(90), "first call returned early");
        for n in 2..=3 {
            let r = runs.clone();
            let start = Instant::now();
            let out = bounded_alias("/y", "/**", Duration::from_millis(100), &TEST_STUCK, move |_, _| {
                r.fetch_add(1, Ordering::SeqCst);
                Some("/fast".to_owned())
            });
            assert_eq!(out, None, "call {n} while stuck");
            assert!(start.elapsed() < Duration::from_millis(50), "call {n} waited {:?}", start.elapsed());
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1, "a second resolver ran while the first was stuck");
        let _ = release_tx.send(());
        wait_idle();
    }

    #[test]
    fn a_recovered_mount_is_used_again() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let out = bounded_alias("/x", "/**", Duration::from_millis(50), &TEST_STUCK, move |_, _| {
            let _ = release_rx.recv();
            None
        });
        assert_eq!(out, None);
        let _ = release_tx.send(());
        wait_idle();
        let out = bounded_alias("/y", "/**", Duration::from_millis(500), &TEST_STUCK, |_, _| Some("/alias".to_owned()));
        assert_eq!(out, Some("/alias".to_owned()));
    }
}
