//! Home-directory resolution generally: USERPROFILE-first `home_dir`, plus
//! fuigo-home (`$FUIGO_HOME` or `<home>/.fuigo`). Shared by `fuigo-config`
//! and `fuigo-fast-worktree`.
//!
//! Which function to call:
//! - [`fuigo_home`]: the usual choice, a cached, created path to build on.
//! - [`user_fuigo_home`]: `None` instead of a cwd fallback when no home resolves.
//! - [`default_fuigo_home`]: the `<home>/.fuigo` default, ignoring `$FUIGO_HOME`, so callers can detect an override.
//! - [`resolve_fuigo_home`]: a fresh, uncached resolve.
//! - [`resolve_fuigo_home_with_source`]: [`resolve_fuigo_home`] plus where the path came from.
//! - [`home_dir`]: the home directory itself, for sibling dot dirs (`~/.claude`, `~/.agents`, ...).
//!
//! TODO: collapse these getters by threading the path through config as an
//! explicit value.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Where a resolved fuigo home came from, so "why did fuigo pick this
/// directory?" is answerable in diagnostics without re-reading the
/// environment at the asking site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuigoHomeSource {
    /// A non-empty `$FUIGO_HOME` override.
    EnvOverride,
    /// `<home>/.fuigo` derived from the home directory.
    HomeDefault,
}

/// The user's home directory via [`std::env::home_dir`]: `HOME` on Unix (with
/// a passwd fallback), `USERPROFILE` on Windows.
///
/// Deliberately not `dirs::home_dir()`: on Windows `dirs` asks the
/// known-folder API and ignores a redirected `USERPROFILE`, while this crate
/// resolves `~/.fuigo` from the profile variable — mixing the two sources puts
/// the fuigo directory and other home-anchored dot directories in different
/// trees. Every home-anchored path must come from this one function.
#[allow(deprecated, clippy::disallowed_methods)] // the one sanctioned std::env::home_dir call
pub fn home_dir() -> Option<PathBuf> {
    std::env::home_dir()
}

/// `<home>/.fuigo`, canonicalized via `dunce` (not `std::fs::canonicalize`,
/// which yields Windows `\\?\` verbatim paths).
fn fuigo_home_in(home: &Path) -> PathBuf {
    dunce::canonicalize(home)
        .unwrap_or_else(|_| home.to_path_buf())
        .join(".fuigo")
}

/// `$FUIGO_HOME` verbatim when non-empty, else `<home>/.fuigo`. The env value is
/// used as-is (not canonicalized) so it stays stable and comparable: callers do
/// literal prefix checks against it, and downstream symlink guards must still see
/// its original components.
fn resolve_fuigo_home_from(
    fuigo_home_env: Option<&OsStr>,
    os_home: Option<&Path>,
) -> Option<(PathBuf, FuigoHomeSource)> {
    if let Some(env) = fuigo_home_env.filter(|env| !env.is_empty()) {
        return Some((PathBuf::from(env), FuigoHomeSource::EnvOverride));
    }
    os_home.map(|home| (fuigo_home_in(home), FuigoHomeSource::HomeDefault))
}

/// Resolve the fuigo home from the environment (fresh, no cache); `None` if neither resolves.
pub fn resolve_fuigo_home() -> Option<PathBuf> {
    resolve_fuigo_home_with_source().map(|(home, _)| home)
}

/// [`resolve_fuigo_home`] plus the [`FuigoHomeSource`] the path came from.
pub fn resolve_fuigo_home_with_source() -> Option<(PathBuf, FuigoHomeSource)> {
    resolve_fuigo_home_from(
        std::env::var_os("FUIGO_HOME").as_deref(),
        home_dir().as_deref(),
    )
}

/// The default `<home>/.fuigo`, used when `$FUIGO_HOME` is unset.
pub fn default_fuigo_home() -> PathBuf {
    fuigo_home_in(&home_dir().unwrap_or_else(|| PathBuf::from(".")))
}

/// The fuigo home, created if missing and cached for the process; falls back to
/// [`default_fuigo_home`] when neither `$FUIGO_HOME` nor a home resolves.
pub fn fuigo_home() -> PathBuf {
    static FUIGO_HOME: OnceLock<PathBuf> = OnceLock::new();
    FUIGO_HOME
        .get_or_init(|| {
            let home = resolve_fuigo_home().unwrap_or_else(default_fuigo_home);
            if let Err(err) = std::fs::create_dir_all(&home) {
                tracing::warn!(path = %home.display(), %err, "failed to create fuigo home");
            }
            home
        })
        .clone()
}

/// Like [`fuigo_home`], but `None` when no home resolves (no cwd fallback).
pub fn user_fuigo_home() -> Option<PathBuf> {
    resolve_fuigo_home().is_some().then(fuigo_home)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::ffi::OsString;

    #[test]
    fn env_wins_over_os_home() {
        let resolved =
            resolve_fuigo_home_from(Some(OsStr::new("/custom/home")), Some(Path::new("/home/u")));
        assert_eq!(
            resolved,
            Some((PathBuf::from("/custom/home"), FuigoHomeSource::EnvOverride))
        );
    }

    #[test]
    fn env_used_verbatim_even_when_it_exists() {
        // A real, existing dir whose canonical form differs (macOS symlinks
        // `/var` -> `/private/var`): the env value must come back unchanged.
        let tmp = tempfile::tempdir().unwrap();
        let resolved = resolve_fuigo_home_from(Some(tmp.path().as_os_str()), None);
        assert_eq!(
            resolved,
            Some((tmp.path().to_path_buf(), FuigoHomeSource::EnvOverride))
        );
    }

    #[test]
    fn empty_env_falls_through_to_os_home() {
        let tmp = tempfile::tempdir().unwrap();
        let resolved = resolve_fuigo_home_from(Some(&OsString::new()), Some(tmp.path()));
        assert_eq!(
            resolved,
            Some((
                dunce::canonicalize(tmp.path()).unwrap().join(".fuigo"),
                FuigoHomeSource::HomeDefault
            ))
        );
    }

    #[test]
    fn default_fuigo_home_has_no_verbatim_prefix() {
        // The reason we canonicalize via dunce: std::fs::canonicalize yields
        // `\\?\` verbatim paths on Windows that break git and byte-exact
        // comparisons. No-op assertion on Unix.
        let home = default_fuigo_home();
        assert!(!home.to_string_lossy().starts_with(r"\\?\"));
        assert!(home.ends_with(".fuigo"));
    }

    #[test]
    fn none_when_nothing_resolves() {
        assert_eq!(
            resolve_fuigo_home_from(/* fuigo_home_env */ None, /* os_home */ None),
            None
        );
    }
}
