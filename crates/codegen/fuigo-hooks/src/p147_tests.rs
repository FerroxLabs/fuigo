//! P147 (e2e lane C1, release notes S16/B32): only hook FILES whose real path is under `$FUIGO_HOME/hooks/` may name the
//! saved key. A user-level hook file anywhere else (`~/.claude/settings.json`, a `~/.fuigo/hooks-paths` target outside
//! `$FUIGO_HOME/hooks`, a symlink in `$FUIGO_HOME/hooks` that points outside it) is refused like a project's: the
//! reference is removed with a note, and the hook's child gets no key. Red first: each loaded through the real global
//! discovery path (`load_from_source_in`, global tier).

use crate::discovery::{HookSource, load_from_source_in};
use crate::env_expand::{hook_child_env, references_first_party_key};
use crate::test_support::{P70A_TEST_KEY, install_p70a_key_resolver};
use std::path::Path;

fn hook_json(command: &str) -> String {
    serde_json::json!({ "hooks": { "SessionStart": [ { "hooks": [
        { "type": "command", "command": command, "env": { "TOKEN": "${FUIGO_API_KEY}" } }
    ] } ] } })
    .to_string()
}

/// Load `source` as a GLOBAL source and return what one hook's child would get: (parsed command, FUIGO_API_KEY in the
/// child env, TOKEN in the child env).
fn child_of(source: &HookSource<'_>, user: &Path) -> (String, Option<String>, String) {
    let (specs, errors) = load_from_source_in(source, true, Some(user));
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(specs.len(), 1, "{specs:?}");
    let command = specs[0].command.as_ref().unwrap().to_string_lossy().into_owned();
    let child = hook_child_env(Some(&command), &specs[0].extra_env, true);
    (command, child.get("FUIGO_API_KEY").cloned(), child.get("TOKEN").cloned().unwrap_or_default())
}

fn assert_refused(label: &str, (command, key, token): (String, Option<String>, String), file_marker: &str) {
    assert!(!references_first_party_key(&command), "{label}: the command still names the key: {command}");
    assert!(key.is_none(), "{label}: the hook child was handed FUIGO_API_KEY");
    assert!(!token.contains(P70A_TEST_KEY), "{label}: TOKEN carries the saved key");
    let notes = fuigo_config::key_naming::refusal_notes();
    assert!(
        notes.iter().any(|n| n.contains(file_marker) && n.contains("FUIGO_API_KEY")),
        "{label}: no refusal note naming {file_marker}: {notes:?}"
    );
}

/// `~/.claude/settings.json` hooks are a global source but not a listed file: refused, with a note.
#[cfg(unix)]
#[test]
fn claude_settings_hooks_cannot_name_the_saved_key() {
    install_p70a_key_resolver();
    let tmp = tempfile::tempdir().unwrap();
    let user = tmp.path().join(".fuigo");
    std::fs::create_dir_all(user.join("hooks")).unwrap();
    let claude = tmp.path().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    let settings = claude.join("settings.json");
    std::fs::write(&settings, hook_json("cmd-p147-claude ${FUIGO_API_KEY}")).unwrap();
    assert_refused("~/.claude/settings.json", child_of(&HookSource::SettingsFile(&settings), &user), ".claude/settings.json");
}

/// A `hooks-paths` directory outside `$FUIGO_HOME/hooks` is the user's choice but not a listed place: refused.
#[cfg(unix)]
#[test]
fn a_hooks_paths_directory_outside_the_hooks_dir_cannot_name_the_saved_key() {
    install_p70a_key_resolver();
    let tmp = tempfile::tempdir().unwrap();
    let user = tmp.path().join(".fuigo");
    std::fs::create_dir_all(user.join("hooks")).unwrap();
    let elsewhere = tmp.path().join("dotfiles/p147-hooks");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("p147-elsewhere.json"), hook_json("cmd-p147-elsewhere $FUIGO_API_KEY")).unwrap();
    assert_refused("hooks-paths target", child_of(&HookSource::Directory(&elsewhere), &user), "p147-elsewhere.json");
}

/// A symlink in `$FUIGO_HOME/hooks` that points outside it is judged by its real path: refused. A plain file in the
/// same directory is the control and keeps the key (in TOKEN and as FUIGO_API_KEY for its command).
#[cfg(unix)]
#[test]
fn a_symlink_in_the_hooks_dir_to_an_outside_file_cannot_name_the_saved_key() {
    install_p70a_key_resolver();
    let tmp = tempfile::tempdir().unwrap();
    let user = tmp.path().join(".fuigo");
    let hooks = user.join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    let outside = tmp.path().join("p147-outside.json");
    std::fs::write(&outside, hook_json("cmd-p147-link ${FUIGO_API_KEY}")).unwrap();
    std::os::unix::fs::symlink(&outside, hooks.join("p147-link.json")).unwrap();
    assert_refused("symlink to outside", child_of(&HookSource::Directory(&hooks), &user), "p147-link.json");

    std::fs::remove_file(hooks.join("p147-link.json")).unwrap();
    std::fs::write(hooks.join("p147-own.json"), hook_json("cmd-p147-own ${FUIGO_API_KEY}")).unwrap();
    let (command, key, token) = child_of(&HookSource::Directory(&hooks), &user);
    assert!(references_first_party_key(&command), "control lost its reference: {command}");
    assert_eq!(key.as_deref(), Some(P70A_TEST_KEY), "a file under $FUIGO_HOME/hooks must keep the key");
    assert_eq!(token, P70A_TEST_KEY);
}

/// A symlinked `$FUIGO_HOME/hooks` directory (dotfiles) is still the user's hooks directory: its files keep the key.
#[cfg(unix)]
#[test]
fn a_symlinked_hooks_dir_keeps_the_saved_key() {
    install_p70a_key_resolver();
    let tmp = tempfile::tempdir().unwrap();
    let user = tmp.path().join(".fuigo");
    std::fs::create_dir_all(&user).unwrap();
    let real = tmp.path().join("dotfiles/fuigo-hooks");
    std::fs::create_dir_all(&real).unwrap();
    std::os::unix::fs::symlink(&real, user.join("hooks")).unwrap();
    std::fs::write(real.join("p147-dot.json"), hook_json("cmd-p147-dot ${FUIGO_API_KEY}")).unwrap();
    let hooks = user.join("hooks");
    let (_, key, _) = child_of(&HookSource::Directory(&hooks), &user);
    assert_eq!(key.as_deref(), Some(P70A_TEST_KEY));
}
