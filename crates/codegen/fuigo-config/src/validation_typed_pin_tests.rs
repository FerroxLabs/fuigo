//! P186c (owner decision 24): a running process that holds a validated copy of an admin policy file applies the single
//! audited lock-down while a NEW version has a wrong-typed pinned key, and lifts it when a valid version is read. Every
//! other error class keeps the copy. The tests drive the loaders the config load uses.
use super::*;

const LAX: &str = "[ui]\nyolo = true\n";
const BROKEN: &str = "[ui]\nyolo = \"yes\"\n[sandbox]\nprofile = \"strict\"\n";
const FIXED: &str = "[sandbox]\nprofile = \"strict\"\n";

/// Messages shown for `path` so far (one entry per emitted notice).
fn notices(path: &Path) -> Vec<String> {
    lockdown_notices_for_test(path)
}

fn put(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
}

#[test]
fn requirements_wrong_typed_pin_locks_down_once_and_lifts_p186c() {
    let sys = tempfile::tempdir().unwrap();
    let path = sys.path().join("requirements.toml");
    put(&path, LAX);
    assert_eq!(load_admin_requirements_layer(&path).unwrap()["ui"]["yolo"].as_bool(), Some(true));
    // (a) the new version breaks only on a wrong-typed pin: the lock-down, same as the no-copy path
    put(&path, BROKEN);
    let locked = load_admin_requirements_layer(&path).unwrap();
    let fresh_dir = tempfile::tempdir().unwrap();
    let fresh = fresh_dir.path().join("requirements.toml");
    put(&fresh, BROKEN);
    assert_eq!(locked, load_admin_requirements_layer(&fresh).unwrap());
    assert_eq!(locked, admin_lockdown_requirements());
    let n = notices(&path);
    assert_eq!(n.len(), 1, "{n:?}");
    assert!(n[0].contains(&path.display().to_string()) && n[0].contains("ui.yolo"), "{n:?}");
    // (b) the same broken version again: still locked, no repeat
    assert_eq!(load_admin_requirements_layer(&path).unwrap(), admin_lockdown_requirements());
    assert_eq!(load_admin_requirements_layer(&path).unwrap(), admin_lockdown_requirements());
    assert_eq!(notices(&path).len(), 1);
    // (c) a valid version lifts it: the file's own policy, no stale lock-down key
    put(&path, FIXED);
    let v = load_admin_requirements_layer(&path).unwrap();
    assert_eq!(v["sandbox"]["profile"].as_str(), Some("strict"));
    assert!(v.get("models").is_none() && v.get("permission").is_none() && v.get("ui").is_none(), "{v:?}");
    // (d) broken again: locked again, shown again
    put(&path, BROKEN);
    assert_eq!(load_admin_requirements_layer(&path).unwrap(), admin_lockdown_requirements());
    assert_eq!(notices(&path).len(), 2);
}

#[test]
fn managed_config_wrong_typed_pin_locks_down_once_and_lifts_p186c() {
    let sys = tempfile::tempdir().unwrap();
    let path = sys.path().join("managed_config.toml");
    put(&path, LAX);
    assert!(crate::loader::load_admin_config_file(&path).is_ok());
    put(&path, BROKEN);
    let locked = crate::loader::load_admin_config_file(&path).unwrap();
    assert_eq!(locked, admin_lockdown_managed_config());
    assert_eq!(notices(&path).len(), 1);
    assert_eq!(crate::loader::load_admin_config_file(&path).unwrap(), admin_lockdown_managed_config());
    assert_eq!(notices(&path).len(), 1);
    put(&path, FIXED);
    let v = crate::loader::load_admin_config_file(&path).unwrap();
    assert_eq!(v["sandbox"]["profile"].as_str(), Some("strict"));
    assert!(v.get("permission").is_none(), "{v:?}");
    put(&path, BROKEN);
    assert_eq!(crate::loader::load_admin_config_file(&path).unwrap(), admin_lockdown_managed_config());
    assert_eq!(notices(&path).len(), 2);
}

#[test]
fn claude_json_wrong_typed_key_locks_down_once_and_lifts_p186c() {
    let sys = tempfile::tempdir().unwrap();
    let path = sys.path().join("managed-settings.json");
    put(&path, r#"{"permissions":{"deny":["Bash"]}}"#);
    assert!(matches!(managed_settings_json(&path), ManagedSettingsJson::Loaded(_)));
    put(&path, r#"{"permissions":{"deny":"Bash"},"deniedMcpServers":[{"serverName":"x"}]}"#);
    match managed_settings_json(&path) {
        ManagedSettingsJson::Broken(d) => assert!(d.contains("permissions.deny"), "{d}"),
        other => panic!("expected the lock-down, got {other:?}"),
    }
    let n = notices(&path);
    assert_eq!(n.len(), 1, "{n:?}");
    assert!(n[0].contains(&path.display().to_string()) && n[0].contains("permissions.deny"), "{n:?}");
    assert!(matches!(managed_settings_json(&path), ManagedSettingsJson::Broken(_)));
    assert_eq!(notices(&path).len(), 1);
    put(&path, r#"{"permissions":{"deny":["Bash","Write"]}}"#);
    assert!(matches!(managed_settings_json(&path), ManagedSettingsJson::Loaded(_)));
    put(&path, r#"{"permissions":{"deny":"Bash"}}"#);
    assert!(matches!(managed_settings_json(&path), ManagedSettingsJson::Broken(_)));
    assert_eq!(notices(&path).len(), 2);
}

/// Guards that hold before and after: every other error class keeps the copy; no copy is the lock-down; valid applies.
#[test]
fn other_error_classes_keep_the_copy_p186c() {
    let sys = tempfile::tempdir().unwrap();
    let path = sys.path().join("requirements.toml");
    put(&path, LAX);
    assert!(admin_requirements_source_checked(&path).unwrap().is_some());
    for (name, text) in [
        ("unparseable", "[ui\nyolo = "),
        ("half-written", "[ui]\nyolo = tr"),
    ] {
        put(&path, text);
        let kept = admin_requirements_source_checked(&path).unwrap_or_else(|e| panic!("{name}: {e}")).unwrap();
        assert_eq!(kept, LAX, "{name}");
        assert_eq!(load_admin_requirements_layer(&path).unwrap()["ui"]["yolo"].as_bool(), Some(true), "{name}");
    }
    std::fs::remove_file(&path).unwrap();
    assert_eq!(admin_requirements_source_checked(&path).unwrap().unwrap(), LAX);
    assert!(notices(&path).is_empty());
    // wrong-typed pin with NO copy: the lock-down, as today
    let fresh = sys.path().join("fresh").join("requirements.toml");
    std::fs::create_dir_all(fresh.parent().unwrap()).unwrap();
    put(&fresh, BROKEN);
    assert!(admin_requirements_source_checked(&fresh).is_err());
    assert_eq!(load_admin_requirements_layer(&fresh), Some(admin_lockdown_requirements()));
    // a fully valid new version is applied
    put(&path, FIXED);
    assert_eq!(load_admin_requirements_layer(&path).unwrap()["sandbox"]["profile"].as_str(), Some("strict"));
}
