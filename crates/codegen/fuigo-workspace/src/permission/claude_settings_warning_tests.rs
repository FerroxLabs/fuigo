//! 75.F1: permission rules that do not load warn at session open instead of being skipped silently.
use super::*;

fn project(settings: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    std::fs::create_dir(dir.path().join(".claude")).unwrap();
    std::fs::write(dir.path().join(".claude/settings.json"), settings).unwrap();
    dir
}

/// The warnings that name this project's settings file (the developer's own `~/.claude` may add others).
fn mine(dir: &tempfile::TempDir, trusted: bool) -> Vec<String> {
    let root = dir.path().display().to_string();
    permission_load_warnings(dir.path(), trusted)
        .into_iter()
        .filter(|w| w.contains(&root))
        .collect()
}

#[test]
fn invalid_json_warns_once_naming_the_file_and_the_reason() {
    let dir = project("{ \"permissions\": { \"deny\": [\"Bash(rm *)\"] ");
    let w = mine(&dir, true);
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(w[0].contains("settings.json"), "{w:?}");
    assert!(w[0].contains("not valid JSON"), "{w:?}");
    assert!(w[0].contains("did not load"), "{w:?}");
}

#[test]
fn a_bad_rule_warns_with_the_rule_and_the_reason_and_good_rules_stay_quiet() {
    let dir = project(r#"{"permissions":{"deny":["Bash(rm"],"allow":["Read(src/**)","NotebookEdit"]}}"#);
    let w = mine(&dir, true);
    assert_eq!(w.len(), 1, "one warning per file: {w:?}");
    assert!(w[0].contains("Bash(rm"), "{w:?}");
    assert!(w[0].contains("NotebookEdit"), "{w:?}");
    assert!(!w[0].contains("Read(src/**)"), "a rule that loaded is not reported: {w:?}");
    assert!(w[0].contains("2 permission rules"), "{w:?}");
}

#[test]
fn a_valid_file_and_an_untrusted_project_file_produce_no_warning() {
    let ok = project(r#"{"permissions":{"allow":["Read(src/**)"]}}"#);
    assert!(mine(&ok, true).is_empty());
    // An untrusted folder's project file is not read at all, so it cannot warn either.
    let bad = project("not json");
    assert!(mine(&bad, false).is_empty());
}

#[test]
fn control_characters_in_a_rule_cannot_forge_terminal_output() {
    let dir = project("{\"permissions\":{\"allow\":[\"Bash(\\u001b[2Jx\"]}}");
    let w = mine(&dir, true);
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(!w[0].chars().any(char::is_control), "{w:?}");
}

#[test]
fn a_settings_path_that_is_not_a_regular_file_warns() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    std::fs::create_dir_all(dir.path().join(".claude/settings.json")).unwrap();
    let w = mine(&dir, true);
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(w[0].contains("settings.json"), "{w:?}");
    assert!(w[0].contains("could not be read"), "{w:?}");
    assert!(w[0].contains("not a regular file"), "{w:?}");
}

#[test]
fn a_settings_file_behind_an_unusable_parent_warns_and_only_a_missing_file_is_absent() {
    // `.claude` is a file, so the settings path fails with NotADirectory, not NotFound: reported, not skipped.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    std::fs::write(dir.path().join(".claude"), "x").unwrap();
    let w = mine(&dir, true);
    // One note per settings file under it (settings.json and settings.local.json).
    assert!(!w.is_empty(), "{w:?}");
    assert!(w.iter().all(|n| n.contains("could not be read")), "{w:?}");

    // No `.claude` at all is simply absent.
    let none = tempfile::tempdir().unwrap();
    std::fs::create_dir(none.path().join(".git")).unwrap();
    assert!(mine(&none, true).is_empty());
}

#[cfg(unix)]
#[test]
fn a_settings_file_in_a_directory_that_denies_search_warns() {
    use std::os::unix::fs::PermissionsExt;
    let dir = project(r#"{"permissions":{"deny":["Bash(rm *)"]}}"#);
    let claude = dir.path().join(".claude");
    std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o000)).unwrap();
    let denied = std::fs::metadata(claude.join("settings.json")).is_err();
    let w = mine(&dir, true);
    std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
    if !denied {
        // Running as root: the kernel lets us through, so the denial cannot be produced here. The two tests above
        // drive the same non-NotFound branch with errors root also gets.
        return;
    }
    // The denial hides every file under `.claude`, so `settings.local.json` warns too when it is checked.
    assert!(!w.is_empty(), "{w:?}");
    assert!(w.iter().all(|n| n.contains("could not be read")), "{w:?}");
    assert!(w.iter().any(|n| n.contains("settings.json")), "{w:?}");
}
