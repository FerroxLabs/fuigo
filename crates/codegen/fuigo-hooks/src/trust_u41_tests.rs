//! 75.B18: disabling a project hook applies to that repo only.
use super::*;
use crate::config::HookSpec;
use crate::discovery::{HookSource, load_hooks_from_sources};
use crate::event::HookEventName;

const GUARD: &str =
    r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"guard.sh"}]}]}}"#;

/// Load the single project hook of a repo laid out as `<root>/.claude/settings.json`.
fn project_hook(root: &Path) -> HookSpec {
    let claude = root.join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    let settings = claude.join("settings.json");
    std::fs::write(&settings, GUARD).unwrap();
    let (registry, errors) = load_hooks_from_sources(&[], &[HookSource::SettingsFile(&settings)]);
    assert!(errors.is_empty());
    let hooks = registry.hooks_for(HookEventName::PreToolUse);
    assert_eq!(hooks.len(), 1);
    hooks[0].clone()
}

#[test]
fn disabling_a_project_hook_leaves_the_same_named_hook_in_another_repo_running() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("disabled-hooks");
    let a = project_hook(&dir.path().join("repo-a"));
    let b = project_hook(&dir.path().join("repo-b"));
    assert_eq!(a.name, b.name, "same-named guard hook in two repos");

    disable_hook_with_file(&disable_key(&a), &file).unwrap();

    let disabled = DisabledHooks::from_file(&file, false);
    assert!(disabled.blocks(&a), "disabled in the repo it was disabled in");
    assert!(!disabled.blocks(&b), "the other repo's same-named hook still runs");
}

#[test]
fn enabling_in_one_repo_does_not_touch_the_other_repos_disable() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("disabled-hooks");
    let a = project_hook(&dir.path().join("repo-a"));
    let b = project_hook(&dir.path().join("repo-b"));
    disable_hook_with_file(&disable_key(&a), &file).unwrap();
    disable_hook_with_file(&disable_key(&b), &file).unwrap();

    assert!(enable_hook_with_file(&disable_key(&a), &file).unwrap());

    let disabled = DisabledHooks::from_file(&file, false);
    assert!(!disabled.blocks(&a));
    assert!(disabled.blocks(&b));
}

#[test]
fn user_and_global_hooks_keep_their_bare_name() {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("g.json");
    std::fs::write(&settings, GUARD).unwrap();
    let (registry, _) = load_hooks_from_sources(&[HookSource::SettingsFile(&settings)], &[]);
    let g = registry.hooks_for(HookEventName::PreToolUse)[0].clone();
    assert!(g.name.starts_with("global/"));
    assert_eq!(disable_key(&g), g.name);
}

#[test]
fn a_legacy_bare_disable_still_applies_in_every_repo_and_is_not_rewritten() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("disabled-hooks");
    let a = project_hook(&dir.path().join("repo-a"));
    let b = project_hook(&dir.path().join("repo-b"));
    let legacy = format!("# mine\n{}\nproject/not-loaded\nglobal/x\n", a.name);
    std::fs::write(&file, &legacy).unwrap();

    // Exactly as in 1.0.40: the bare name switches the hook off wherever it is loaded.
    let disabled = DisabledHooks::from_file(&file, false);
    assert!(disabled.blocks(&a), "still disabled in repo-a");
    assert!(disabled.blocks(&b), "still disabled in repo-b");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), legacy, "reading never rewrites the file");
}

#[test]
fn a_new_disable_in_one_repo_does_not_affect_another() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("disabled-hooks");
    let a = project_hook(&dir.path().join("repo-a"));
    let b = project_hook(&dir.path().join("repo-b"));
    disable_hook_with_file(&disable_key(&a), &file).unwrap();
    let disabled = DisabledHooks::from_file(&file, false);
    assert!(disabled.blocks(&a));
    assert!(!disabled.blocks(&b));
}

#[test]
fn disabling_beside_a_legacy_entry_keeps_it_and_enabling_removes_both() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("disabled-hooks");
    let a = project_hook(&dir.path().join("repo-a"));
    let b = project_hook(&dir.path().join("repo-b"));
    std::fs::write(&file, format!("{}\nglobal/x\n", a.name)).unwrap();

    disable_hook_with_file(&disable_key(&a), &file).unwrap();
    let disabled = DisabledHooks::from_file(&file, false);
    assert!(disabled.blocks(&a) && disabled.blocks(&b), "the bare line still covers repo-b");

    assert!(enable_hook_with_file(&disable_key(&a), &file).unwrap());
    let disabled = DisabledHooks::from_file(&file, false);
    assert!(!disabled.blocks(&a) && !disabled.blocks(&b), "the user enabled the hook");
    assert!(std::fs::read_to_string(&file).unwrap().contains("global/x"));
}

#[test]
fn a_partly_invalid_file_never_re_enables_a_disabled_hook() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("disabled-hooks");
    let a = project_hook(&dir.path().join("repo-a"));
    let mut bytes = format!("{}\n", a.name).into_bytes();
    bytes.extend_from_slice(&[0xff, 0xfe, b'\n']);
    std::fs::write(&file, &bytes).unwrap();
    assert!(DisabledHooks::from_file(&file, false).blocks(&a));
    // Toggling refuses rather than rewriting a file it cannot read whole; the bytes are untouched.
    assert!(disable_hook_with_file(&disable_key(&a), &file).is_err());
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    assert!(DisabledHooks::from_file(&file, false).blocks(&a));

    // A file that cannot be read at all skips every non-managed hook.
    let unreadable = dir.path().join("dir-disabled-hooks");
    std::fs::create_dir(&unreadable).unwrap();
    assert!(DisabledHooks::from_file(&unreadable, false).blocks(&a));
}

#[test]
fn repo_paths_that_differ_only_in_edge_whitespace_or_odd_bytes_stay_distinct() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("disabled-hooks");
    let plain = project_hook(&dir.path().join("repos").join("app"));
    let spaced = project_hook(&dir.path().join("repos").join("app "));
    let lead = project_hook(&dir.path().join("repos").join(" app"));
    assert_ne!(disable_key(&plain), disable_key(&spaced));
    assert_ne!(disable_key(&plain), disable_key(&lead));

    disable_hook_with_file(&disable_key(&spaced), &file).unwrap();
    let disabled = DisabledHooks::from_file(&file, false);
    assert!(disabled.blocks(&spaced));
    assert!(!disabled.blocks(&plain), "`app` is not `app `");
    assert!(!disabled.blocks(&lead));

    assert!(enable_hook_with_file(&disable_key(&spaced), &file).unwrap());
    assert!(!DisabledHooks::from_file(&file, false).blocks(&spaced));
}

#[test]
fn the_scope_encoding_is_injective_for_odd_bytes_and_keeps_the_old_form() {
    use std::os::unix::ffi::OsStrExt;
    let raw = |b: &[u8]| escape_scope(Path::new(std::ffi::OsStr::from_bytes(b)));
    assert_ne!(raw(b"/r/\xff"), raw(b"/r/\xfe"), "two non-UTF-8 names do not both become U+FFFD");
    assert_ne!(raw(b"/r/\xff"), raw("/r/\u{fffd}".as_bytes()));
    assert_ne!(raw(b"/r/a%20"), raw(b"/r/a "));
    assert_ne!(raw(b"/r/a\t"), raw(b"/r/a "));
    // An interior space, and a path with no edge whitespace, read exactly as an earlier build wrote them.
    assert_eq!(raw(b"/my repo/app"), "/my repo/app");
    assert_eq!(raw(b"/r/100%"), "/r/100%25");
}
