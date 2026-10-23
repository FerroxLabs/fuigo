use super::*;

fn write(dir: &tempfile::TempDir, name: &str, text: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, text).unwrap();
    path
}

fn hook(event: &str, matcher: Option<&str>, command: &str, timeout: Option<u64>) -> ImportableItem {
    ImportableItem::Hook {
        event: event.to_string(),
        matcher: matcher.map(str::to_string),
        command: command.to_string(),
        timeout,
    }
}

fn merged(current: Option<&str>, items: &[ImportableItem]) -> (serde_json::Value, usize) {
    let target = std::path::Path::new("imported-from-claude.json");
    let merge = merge_hooks(target, current, items).unwrap();
    let text = merge.contents.expect("the merge changed the file");
    (serde_json::from_str(&text).unwrap(), merge.added)
}

#[test]
fn extract_hooks_basic_command() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        &dir,
        "settings.json",
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[
            {"type":"command","command":"echo hi","timeout":7}]}]}}"#,
    );
    let items = extract_hooks_from_settings_file(&path);
    let [ImportableItem::Hook {
        event,
        matcher,
        command,
        timeout,
    }] = items.as_slice()
    else {
        panic!("expected exactly one Hook, got {items:?}");
    };
    assert_eq!(event, "PreToolUse");
    assert_eq!(matcher.as_deref(), Some("Bash"));
    assert_eq!(command, "echo hi");
    assert_eq!(*timeout, Some(7));
}

#[test]
fn extract_hooks_skips_non_command_handlers() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        &dir,
        "settings.json",
        r#"{"hooks":{"PostToolUse":[{"hooks":[
            {"type":"http","url":"https://example.com"},
            {"type":"command","command":"true"}]}]}}"#,
    );
    assert_eq!(extract_hooks_from_settings_file(&path).len(), 1);
}

#[test]
fn extract_hooks_unreadable_or_hookless_files_yield_nothing() {
    let dir = tempfile::tempdir().unwrap();
    assert!(extract_hooks_from_settings_file(&dir.path().join("missing.json")).is_empty());
    let no_hooks = write(&dir, "a.json", r#"{"permissions":{"allow":[]}}"#);
    assert!(extract_hooks_from_settings_file(&no_hooks).is_empty());
    let not_json = write(&dir, "b.json", "{ nope");
    assert!(extract_hooks_from_settings_file(&not_json).is_empty());
    let hooks_a_string = write(&dir, "c.json", r#"{"hooks":"oops"}"#);
    assert!(extract_hooks_from_settings_file(&hooks_a_string).is_empty());
}

#[test]
fn extract_hooks_multiple_events_and_matchers() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        &dir,
        "settings.json",
        r#"{"hooks":{
            "PreToolUse":[
                {"matcher":"Bash","hooks":[{"type":"command","command":"a"}]},
                {"matcher":"Edit","hooks":[{"type":"command","command":"b"}]}],
            "PostToolUse":[{"hooks":[
                {"type":"command","command":"c"},{"type":"command","command":"d"}]}]}}"#,
    );
    let items = extract_hooks_from_settings_file(&path);
    assert_eq!(items.len(), 4);
    let events: std::collections::BTreeSet<&str> = items
        .iter()
        .filter_map(|i| match i {
            ImportableItem::Hook { event, .. } => Some(event.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(events, ["PostToolUse", "PreToolUse"].into_iter().collect());
}

/// An empty matcher string is the same as no matcher, which is what dedup relies on.
#[test]
fn extract_hooks_empty_matcher_is_none_and_empty_command_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        &dir,
        "settings.json",
        r#"{"hooks":{"PreToolUse":[{"matcher":"","hooks":[{"type":"command","command":""}]}]}}"#,
    );
    let items = extract_hooks_from_settings_file(&path);
    let [ImportableItem::Hook {
        matcher, command, ..
    }] = items.as_slice()
    else {
        panic!("expected one hook, got {items:?}");
    };
    assert_eq!(*matcher, None);
    assert_eq!(command, "");
}

#[test]
fn merge_into_a_new_file_writes_the_native_shape() {
    let (json, added) = merged(None, &[hook("PreToolUse", Some("Bash"), "echo x", None)]);
    assert_eq!(added, 1);
    let groups = json["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups.first().unwrap()["matcher"], "Bash");
    assert_eq!(groups.first().unwrap()["hooks"][0]["type"], "command");
    assert_eq!(groups.first().unwrap()["hooks"][0]["command"], "echo x");
    assert!(groups.first().unwrap()["hooks"][0].get("timeout").is_none());
}

#[test]
fn merge_dedups_on_event_matcher_and_command() {
    let current = r#"{"hooks":{"PreToolUse":[
        {"matcher":"Bash","hooks":[{"type":"command","command":"echo x"}]}]}}"#;
    let (json, added) = merged(
        Some(current),
        &[
            hook("PreToolUse", Some("Bash"), "echo x", None),
            hook("PreToolUse", Some("Bash"), "echo y", None),
            hook("PreToolUse", Some("Edit"), "echo x", None),
            hook("PreToolUse", None, "echo x", None),
        ],
    );
    assert_eq!(added, 3, "same command under another matcher, or none, is a new hook");
    assert_eq!(json["hooks"]["PreToolUse"].as_array().unwrap().len(), 4);
}

#[test]
fn merge_refreshes_or_removes_the_timeout_in_place() {
    let current = r#"{"hooks":{"PreToolUse":[
        {"matcher":"Bash","hooks":[{"type":"command","command":"echo x","timeout":5}]}]}}"#;
    let (json, added) = merged(Some(current), &[hook("PreToolUse", Some("Bash"), "echo x", Some(60))]);
    assert_eq!(added, 0, "a refresh is not a new hook");
    let groups = json["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups.first().unwrap()["hooks"][0]["timeout"], 60);

    let (json, added) = merged(Some(current), &[hook("PreToolUse", Some("Bash"), "echo x", None)]);
    assert_eq!(added, 0);
    assert!(json["hooks"]["PreToolUse"][0]["hooks"][0].get("timeout").is_none());
}

#[test]
fn merge_without_hooks_or_changes_writes_nothing() {
    let target = std::path::Path::new("h.json");
    let env = ImportableItem::EnvVar {
        key: "X".into(),
        value: "y".into(),
    };
    let none = merge_hooks(target, None, &[env]).unwrap();
    assert!(none.contents.is_none());
    assert_eq!(none.added, 0);
}

#[test]
fn merge_replaces_malformed_json_but_refuses_the_wrong_shape() {
    let target = std::path::Path::new("h.json");
    let items = [hook("Stop", None, "echo", None)];

    let (json, added) = merged(Some("{ not json"), &items);
    assert_eq!(added, 1);
    assert!(json["hooks"]["Stop"].is_array());

    let err = merge_hooks(target, Some("[1,2]"), &items).unwrap_err().to_string();
    assert!(err.contains("root is not a JSON object"), "{err}");
    let err = merge_hooks(target, Some(r#"{"hooks":[]}"#), &items).unwrap_err().to_string();
    assert!(err.contains("hooks is not a JSON object"), "{err}");
    let err = merge_hooks(target, Some(r#"{"hooks":{"Stop":{}}}"#), &items)
        .unwrap_err()
        .to_string();
    assert!(err.contains("hooks.Stop is not a JSON array"), "{err}");
}

#[test]
fn debug_output_hides_commands() {
    let shown = format!("{:?}", hook("PreToolUse", None, "curl -H 'Authorization: Bearer sekrit'", None));
    assert!(!shown.contains("sekrit"), "{shown}");
}
