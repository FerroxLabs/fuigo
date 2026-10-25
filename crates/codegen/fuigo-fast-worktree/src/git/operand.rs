//! Validation of user-supplied git operands (refs, URLs) before they reach a `git` command line.
//!
//! A value that starts with `-` is parsed by git as an option (`--upload-pack=...`, `-b`), so every
//! user-supplied ref is checked here and passed after `--` where git supports it.
//! Fuigo's plugin installer carries the same rule (`validate_git_operand` in `fuigo-agent`'s
//! `plugins/git_install.rs`); that crate does not depend on this one, so the rule is stated twice and must be changed in both places.

/// Trim and validate a git operand. `kind` names it in the message ("ref", "URL").
pub fn validate_git_operand<'a>(value: &'a str, kind: &str) -> Result<&'a str, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("empty git {kind}"));
    }
    if value.contains('\0') {
        return Err(format!("git {kind} contains NUL"));
    }
    if value.starts_with('-') {
        return Err(format!("git {kind} may not begin with '-'"));
    }
    Ok(value)
}

/// Validate and trim a git ref used as a CLI operand.
pub fn validate_git_ref(git_ref: &str) -> Result<&str, String> {
    validate_git_operand(git_ref, "ref")
}

/// Validate a typed worktree name. Names become directory names after sanitising, but a leading `-` is
/// refused outright rather than silently stripped, so `fuigo -w --upload-pack=x` never looks accepted.
pub fn validate_worktree_name(name: &str) -> Result<&str, String> {
    let trimmed = name.trim();
    if trimmed.starts_with('-') {
        return Err("worktree name may not begin with '-'".to_owned());
    }
    if trimmed.contains('\0') {
        return Err("worktree name contains NUL".to_owned());
    }
    Ok(name)
}

/// clap `value_parser` for `--worktree-ref` / `--ref`: refuse up front with the message.
pub fn parse_git_ref_arg(value: &str) -> Result<String, String> {
    validate_git_ref(value).map(str::to_owned)
}

/// clap `value_parser` for a typed worktree name. An empty value (bare `-w`) is allowed: the name is generated.
pub fn parse_worktree_name_arg(value: &str) -> Result<String, String> {
    validate_worktree_name(value).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_option_shaped_nul_and_empty_refs() {
        for bad in ["-x", "--upload-pack=a", "  -b", "-", "a\0b", "", "   "] {
            assert!(validate_git_ref(bad).is_err(), "{bad:?}");
        }
        assert_eq!(validate_git_ref("-x").unwrap_err(), "git ref may not begin with '-'");
    }

    #[test]
    fn accepts_ordinary_refs_trimmed() {
        for ok in ["main", " origin/main ", "v1.2.3", "refs/heads/a-b", "HEAD~2", "feature/caf\u{e9}"] {
            assert!(validate_git_ref(ok).is_ok(), "{ok:?}");
        }
        assert_eq!(validate_git_ref(" main ").unwrap(), "main");
    }

    #[test]
    fn worktree_names_keep_unicode_and_refuse_leading_dash() {
        assert!(validate_worktree_name("caf\u{e9}").is_ok());
        assert!(validate_worktree_name("").is_ok());
        assert!(validate_worktree_name("-x").is_err());
        assert!(validate_worktree_name(" --x").is_err());
    }
}
