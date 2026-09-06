//! Provides marketplace source configuration and plugin discovery, indexed with a filesystem fallback.
//! Install integration goes through the existing `InstallRegistry` pipeline.

pub mod catalog;
pub mod config;
pub mod error;
pub mod git;
pub mod index;
pub mod install_resolve;
pub mod installer;
pub mod matcher;
pub mod scanner;
pub mod types;

pub use config::{
    env_require_sha, load_extra_sources_from_settings, load_extra_sources_from_settings_in,
    load_require_sha, load_sources,
};
pub use error::MarketplaceError;
pub use scanner::scan_marketplace;
pub use types::*;

/// Contributor-configured display name retained for compatibility.
///
/// This is source identity, not evidence that the source is verified or official.
pub const OFFICIAL_SOURCE_NAME: &str = "Ferrox Labs Official";

/// Contributor-configured git URL retained for compatibility.
///
/// This is source identity, not evidence that the source is verified or official.
pub const OFFICIAL_SOURCE_GIT_URL: &str = "https://github.com/FerroxLabs/plugin-marketplace.git";

/// The independently verified official source, when ownership has been established.
///
/// No marketplace currently has that status. Persisted names and URLs never populate this
/// decision implicitly.
pub const VERIFIED_OFFICIAL_SOURCE: Option<(&str, &str)> = None;

/// Whether a source has the explicit verified-official designation.
pub fn is_verified_official_source(source_name: &str, source_url_or_path: &str) -> bool {
    VERIFIED_OFFICIAL_SOURCE.is_some_and(|(verified_name, verified_url)| {
        source_name == verified_name
            && canonical_github_owner_repo(source_url_or_path)
                == canonical_github_owner_repo(verified_url)
    })
}

/// Whether `url` matches the contributor-configured Ferrox source identity.
///
/// This compatibility helper does not confer verified or official status. Privileged decisions
/// must use [`is_verified_official_source`].
pub fn is_official_source_url(url: &str) -> bool {
    canonical_github_owner_repo(url).as_deref() == Some("ferroxlabs/plugin-marketplace")
}

/// Normalized lowercase `owner/repo` from a GitHub URL (HTTPS/http/ssh/scp, `www.`, trailing `.git`/`/`), or `None` if not a GitHub URL.
pub(crate) fn canonical_github_owner_repo(url: &str) -> Option<String> {
    let s = url.trim();
    let s = s.strip_suffix('/').unwrap_or(s);
    let s = s.strip_suffix(".git").unwrap_or(s);
    let lower = s.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .or_else(|| lower.strip_prefix("ssh://"))
        .unwrap_or(&lower);
    let rest = rest.strip_prefix("git@").unwrap_or(rest);
    let rest = rest.strip_prefix("www.").unwrap_or(rest);
    let owner_repo = rest
        .strip_prefix("github.com/")
        .or_else(|| rest.strip_prefix("github.com:"))?;
    if owner_repo.is_empty() {
        None
    } else {
        Some(owner_repo.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_identity_is_retained_but_not_verified() {
        assert_eq!(
            OFFICIAL_SOURCE_GIT_URL,
            "https://github.com/FerroxLabs/plugin-marketplace.git"
        );
        assert_eq!(VERIFIED_OFFICIAL_SOURCE, None);
    }

    #[test]
    fn persisted_names_and_url_forms_never_self_verify() {
        for (name, url) in [
            (OFFICIAL_SOURCE_NAME, OFFICIAL_SOURCE_GIT_URL),
            (
                OFFICIAL_SOURCE_NAME,
                "git@github.com:FerroxLabs/plugin-marketplace.git",
            ),
            (
                "fuigo-org/plugin-marketplace",
                "https://github.com/fuigo-org/plugin-marketplace.git",
            ),
        ] {
            assert!(!is_verified_official_source(name, url), "{name} {url}");
        }
    }

    #[test]
    fn is_official_matches_ssh_form() {
        assert!(is_official_source_url(
            "git@github.com:FerroxLabs/plugin-marketplace.git"
        ));
        assert!(is_official_source_url(
            "git@github.com:FerroxLabs/plugin-marketplace"
        ));
        assert!(is_official_source_url(
            "ssh://git@github.com/FerroxLabs/plugin-marketplace.git"
        ));
        assert!(is_official_source_url(
            "ssh://git@github.com/FerroxLabs/plugin-marketplace"
        ));
    }

    #[test]
    fn is_official_rejects_unrelated_urls() {
        assert!(!is_official_source_url(
            "https://github.com/anthropics/claude-plugins-official.git"
        ));
        assert!(!is_official_source_url(
            "https://github.com/FerroxLabs/some-other-repo.git"
        ));
        assert!(!is_official_source_url(""));
    }

    #[test]
    fn is_official_matches_noncanonical_forms() {
        assert!(is_official_source_url(
            "https://GitHub.com/FERROXLABS/Plugin-Marketplace"
        ));
        assert!(is_official_source_url(
            "https://github.com/FerroxLabs/plugin-marketplace/"
        ));
        assert!(is_official_source_url(
            "https://github.com/FerroxLabs/plugin-marketplace.git/"
        ));
        assert!(is_official_source_url(
            "http://github.com/FerroxLabs/plugin-marketplace"
        ));
        assert!(is_official_source_url(
            "https://www.github.com/FerroxLabs/plugin-marketplace.git"
        ));
        assert!(is_official_source_url(
            "git@github.com:FERROXLABS/plugin-marketplace.git"
        ));
    }
}
