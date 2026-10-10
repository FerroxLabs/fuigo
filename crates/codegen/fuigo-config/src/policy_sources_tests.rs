//! P169: policy layer reading and the tighten-only pins.

use super::*;

fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    p
}

struct Dirs {
    _tmp: tempfile::TempDir,
    sys: PathBuf,
    home: PathBuf,
}

fn dirs() -> Dirs {
    let tmp = tempfile::tempdir().unwrap();
    let sys = tmp.path().join("etc-fuigo");
    let home = tmp.path().join("home-fuigo");
    std::fs::create_dir_all(&sys).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    Dirs {
        _tmp: tmp,
        sys,
        home,
    }
}

fn sources(d: &Dirs, vendor: Option<&Path>) -> Vec<PolicySource> {
    policy_sources_at(Some(&d.sys), Some(&d.home), vendor, None)
}

#[test]
fn no_policy_files_means_no_sources_and_no_pins() {
    let d = dirs();
    let s = sources(&d, None);
    assert!(s.is_empty(), "{s:?}");
    assert_eq!(
        resolve_bool_pin(BoolPin::NonManagedHooks, &s),
        PolicyPin::Unpinned
    );
}

#[test]
fn only_policy_keys_cross_into_the_source() {
    let d = dirs();
    write(
        &d.sys,
        "requirements.toml",
        "allow_managed_hooks_only = true\n[features]\ntelemetry = false\n",
    );
    let s = sources(&d, None);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].tier, PolicyLayerTier::SystemRequirements);
    let json = s[0].policy.as_ref().unwrap();
    assert_eq!(
        json.get("allow_managed_hooks_only"),
        Some(&serde_json::json!(true))
    );
    assert!(
        json.get("features").is_none(),
        "non-policy keys must not cross: {json}"
    );
}

#[test]
fn sources_come_out_in_tier_order() {
    let d = dirs();
    write(
        &d.home,
        "managed_config.toml",
        "allow_managed_hooks_only = false\n",
    );
    write(
        &d.home,
        "requirements.toml",
        "allow_managed_hooks_only = false\n",
    );
    write(
        &d.sys,
        "managed_config.toml",
        "allow_managed_hooks_only = false\n",
    );
    write(
        &d.sys,
        "requirements.toml",
        "allow_managed_hooks_only = false\n",
    );
    let vendor = write(&d.sys, "managed-settings.json", "{}");
    let tiers: Vec<_> = sources(&d, Some(&vendor)).iter().map(|s| s.tier).collect();
    assert_eq!(
        tiers,
        vec![
            PolicyLayerTier::SystemRequirements,
            PolicyLayerTier::SystemManaged,
            PolicyLayerTier::UserRequirements,
            PolicyLayerTier::UserManaged,
            PolicyLayerTier::Vendor,
        ]
    );
}

/// Fail closed on admin paths: a policy file there that exists but does not parse is an `Err` source, never a skipped
/// one. A broken user-home file is skipped (P169 Grok 4.7 C).
#[test]
fn unparseable_admin_files_are_err_sources_and_broken_user_files_are_skipped() {
    let d = dirs();
    write(
        &d.sys,
        "requirements.toml",
        "allow_managed_hooks_only = [\n",
    );
    write(&d.home, "managed_config.toml", "this is = = not toml\n");
    let vendor = write(&d.sys, "managed-settings.json", "{ not json");
    let s = sources(&d, Some(&vendor));
    let tiers: Vec<_> = s.iter().map(|s| s.tier).collect();
    assert_eq!(
        tiers,
        vec![PolicyLayerTier::SystemRequirements, PolicyLayerTier::Vendor],
        "{s:?}"
    );
    assert!(s.iter().all(|s| s.policy.is_err()), "{s:?}");
}

/// P169 (Grok 4.7 C, shared with P183): a broken `~/.fuigo/requirements.toml` or `managed_config.toml` (unparseable,
/// a directory, a dangling symlink) warns and is skipped: no source, no pin, nothing locked down.
#[test]
fn broken_user_home_files_are_skipped_and_engage_nothing() {
    let d = dirs();
    write(&d.home, "requirements.toml", "[[[ broken");
    std::fs::create_dir_all(d.home.join("managed_config.toml")).unwrap();
    let s = sources(&d, None);
    assert!(s.is_empty(), "{s:?}");
    for pin in BoolPin::ALL {
        assert!(!resolve_bool_pin(pin, &s).is_disabled(), "{pin:?}");
    }
    #[cfg(unix)]
    {
        let d = dirs();
        std::os::unix::fs::symlink(d.home.join("nowhere"), d.home.join("requirements.toml"))
            .unwrap();
        assert!(sources(&d, None).is_empty());
        // The same dangling symlink on an admin path fails closed.
        std::os::unix::fs::symlink(d.sys.join("nowhere"), d.sys.join("requirements.toml"))
            .unwrap();
        let s = sources(&d, None);
        assert_eq!(s.len(), 1);
        assert!(s[0].policy.is_err());
    }
}

/// A user-home file that parses still contributes its rules, and a malformed key in it still fails closed.
#[test]
fn a_parsed_user_file_still_binds_and_its_malformed_keys_fail_closed() {
    let d = dirs();
    write(
        &d.home,
        "managed_config.toml",
        "enable_all_project_mcp_servers = false\n",
    );
    let s = sources(&d, None);
    assert!(resolve_bool_pin(BoolPin::ProjectMcp, &s).is_disabled());
    write(
        &d.home,
        "managed_config.toml",
        "allow_managed_hooks_only = 3\n",
    );
    assert!(resolve_bool_pin(BoolPin::NonManagedHooks, &sources(&d, None)).is_disabled());
}

#[test]
fn a_directory_where_a_policy_file_belongs_fails_closed() {
    let d = dirs();
    std::fs::create_dir_all(d.sys.join("requirements.toml")).unwrap();
    let s = sources(&d, None);
    assert_eq!(s.len(), 1);
    assert!(s[0].policy.is_err());
}

#[test]
fn hooks_pin_engages_on_true_only() {
    let d = dirs();
    write(
        &d.sys,
        "requirements.toml",
        "allow_managed_hooks_only = false\n",
    );
    assert_eq!(
        resolve_bool_pin(BoolPin::NonManagedHooks, &sources(&d, None)),
        PolicyPin::Unpinned
    );
    let p = write(
        &d.sys,
        "requirements.toml",
        "allow_managed_hooks_only = true\n",
    );
    assert_eq!(
        resolve_bool_pin(BoolPin::NonManagedHooks, &sources(&d, None)),
        PolicyPin::Disabled {
            ownership: PolicyLayerOwnership::Admin,
            source: p,
        }
    );
}

#[test]
fn hooks_pin_reads_the_claude_spelling_in_managed_settings_json() {
    let d = dirs();
    let vendor = write(
        &d.sys,
        "managed-settings.json",
        r#"{"allowManagedHooksOnly": true}"#,
    );
    let pin = resolve_bool_pin(BoolPin::NonManagedHooks, &sources(&d, Some(&vendor)));
    assert_eq!(pin.source(), Some(vendor.as_path()));
}

/// A non-bool or conflicting value applies the engaging value.
#[test]
fn hooks_pin_invalid_values_fail_closed() {
    let d = dirs();
    write(
        &d.home,
        "managed_config.toml",
        "allow_managed_hooks_only = \"yes\"\n",
    );
    assert!(resolve_bool_pin(BoolPin::NonManagedHooks, &sources(&d, None)).is_disabled());
    let d = dirs();
    let vendor = write(
        &d.sys,
        "managed-settings.json",
        r#"{"allowManagedHooksOnly": false, "allow_managed_hooks_only": true}"#,
    );
    assert!(resolve_bool_pin(BoolPin::NonManagedHooks, &sources(&d, Some(&vendor))).is_disabled());
}

#[test]
fn an_unreadable_admin_layer_engages_every_pin() {
    let d = dirs();
    write(&d.sys, "requirements.toml", "[[[ broken");
    let s = sources(&d, None);
    for pin in BoolPin::ALL {
        assert!(resolve_bool_pin(pin, &s).is_disabled(), "{pin:?}");
    }
}

#[test]
fn project_mcp_pin_engages_on_false() {
    let d = dirs();
    write(
        &d.home,
        "managed_config.toml",
        "enable_all_project_mcp_servers = true\n",
    );
    assert!(!resolve_bool_pin(BoolPin::ProjectMcp, &sources(&d, None)).is_disabled());
    write(
        &d.home,
        "managed_config.toml",
        "enable_all_project_mcp_servers = false\n",
    );
    let pin = resolve_bool_pin(BoolPin::ProjectMcp, &sources(&d, None));
    assert!(matches!(
        pin,
        PolicyPin::Disabled {
            ownership: PolicyLayerOwnership::User,
            ..
        }
    ));
}

/// The first engaging layer names the pin, but an admin layer re-attributes a user-owned one (never the reverse).
#[test]
fn admin_layer_reattributes_a_user_pin() {
    let mut pin = PolicyPin::Unpinned;
    pin.tighten(Path::new("/u"), PolicyLayerOwnership::User);
    pin.tighten(Path::new("/a"), PolicyLayerOwnership::Admin);
    assert_eq!(pin.source(), Some(Path::new("/a")));
    pin.tighten(Path::new("/u2"), PolicyLayerOwnership::User);
    assert_eq!(pin.source(), Some(Path::new("/a")));
}

#[test]
fn grant_ownership_rule() {
    use PolicyLayerOwnership::{Admin, User};
    assert!(Admin.accepts_grant_from(Admin));
    assert!(!Admin.accepts_grant_from(User));
    assert!(User.accepts_grant_from(User));
    assert!(User.accepts_grant_from(Admin));
}

#[test]
fn mdm_layer_is_admin_and_first() {
    let d = dirs();
    write(
        &d.home,
        "requirements.toml",
        "allow_managed_hooks_only = false\n",
    );
    let mdm: toml::Value = toml::from_str("allow_managed_hooks_only = true\n").unwrap();
    let s = policy_sources_at(Some(&d.sys), Some(&d.home), None, Some(Ok(mdm)));
    assert_eq!(s[0].tier, PolicyLayerTier::Mdm);
    let pin = resolve_bool_pin(BoolPin::NonManagedHooks, &s);
    assert!(matches!(
        pin,
        PolicyPin::Disabled {
            ownership: PolicyLayerOwnership::Admin,
            ..
        }
    ));
}

/// Astra r1 #1: a forced MDM payload that does not decode is an error source (fail closed).
#[test]
fn a_broken_mdm_layer_is_an_err_source() {
    let d = dirs();
    let s = policy_sources_at(Some(&d.sys), Some(&d.home), None, Some(Err("bad".into())));
    assert_eq!(s.len(), 1);
    assert!(s[0].policy.is_err());
    assert!(resolve_bool_pin(BoolPin::NonManagedHooks, &s).is_disabled());
}

/// P169 (Grok 4.7 #5): an admin-path file a non-root user could have written fails closed instead of applying as a
/// user-owned layer (an emptied one would otherwise wipe the org rules). User-home files are judged by tier only.
#[cfg(unix)]
#[test]
fn a_writable_or_foreign_owned_admin_file_fails_closed() {
    use std::os::unix::fs::PermissionsExt;
    let d = dirs();
    let p = write(&d.sys, "managed_config.toml", "");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o664)).unwrap();
    let s = sources(&d, None);
    assert_eq!(s.len(), 1, "{s:?}");
    assert!(s[0].policy.is_err(), "a group-writable admin file must fail closed: {s:?}");
    assert_eq!(s[0].ownership, PolicyLayerOwnership::Admin);
    for pin in BoolPin::ALL {
        assert!(resolve_bool_pin(pin, &s).is_disabled(), "{pin:?}");
    }
    let v = write(&d.sys, "managed-settings.json", "{}");
    std::fs::set_permissions(&v, std::fs::Permissions::from_mode(0o646)).unwrap();
    let s = sources(&d, Some(&v));
    assert!(s.iter().all(|s| s.policy.is_err()), "an other-writable Claude file fails closed: {s:?}");

    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&v, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(sources(&d, Some(&v)).iter().all(|s| s.policy.is_ok()), "0644 and owned: applies");
    // Owned by someone other than the admin uid (root in production): fails closed.
    let other = process_euid().wrapping_add(1);
    let s = policy_sources_owned_by(Some(&d.sys), Some(&d.home), Some(&v), None, other);
    assert_eq!(s.len(), 2);
    assert!(s.iter().all(|s| s.policy.is_err()), "{s:?}");

    // A writable user-home file is the user's own layer: it applies.
    let u = write(&d.home, "managed_config.toml", "allow_managed_hooks_only = true\n");
    std::fs::set_permissions(&u, std::fs::Permissions::from_mode(0o666)).unwrap();
    let s = policy_sources_owned_by(None, Some(&d.home), None, None, other);
    assert_eq!(s.len(), 1);
    assert!(s[0].policy.is_ok());
    assert_eq!(s[0].ownership, PolicyLayerOwnership::User);
}

/// Astra r1 #1: an unreadable Claude file fails closed instead of vanishing.
#[cfg(unix)]
#[test]
fn an_unreadable_vendor_file_is_an_err_source() {
    let d = dirs();
    let dir = d.sys.join("claude");
    let vendor = write(&dir, "managed-settings.json", "{}");
    // A directory path where the file is expected: reading it fails with an error other than NotFound.
    let s = sources(&d, Some(&dir));
    assert_eq!(s.len(), 1, "{s:?}");
    assert!(s[0].policy.is_err());
    let s = sources(&d, Some(&vendor));
    assert!(s[0].policy.is_ok());
}

/// P183 round 9 (Grok r5 H1): an admin requirements file whose only tightening sits in a version override with a bad bound is
/// an `Err` source (lock-down), not its base; a user file keeps its base (the P162 rule for user layers).
#[test]
fn admin_bad_version_override_is_err_user_keeps_base_p183r9() {
    let d = dirs();
    let body = "allow_managed_mcp_servers_only = false\n[[version_overrides]]\nminimum_version = \"not-semver\"\n";
    write(&d.sys, "requirements.toml", body);
    write(&d.home, "requirements.toml", body);
    let s = policy_sources_at(Some(&d.sys), Some(&d.home), None, None);
    let sys = s.iter().find(|x| x.tier == PolicyLayerTier::SystemRequirements).unwrap();
    assert!(sys.policy.is_err(), "admin: lock-down");
    let user = s.iter().find(|x| x.tier == PolicyLayerTier::UserRequirements).unwrap();
    assert!(user.policy.is_ok(), "user: base kept");
    let mdm: toml::Value = toml::from_str(body).unwrap();
    let s = policy_sources_at(Some(&d.sys), None, None, Some(Ok(mdm)));
    assert!(s.iter().find(|x| x.tier == PolicyLayerTier::Mdm).unwrap().policy.is_err());
}

/// P183 round 12 (Grok r8) sequence 2: an admin TOML with a wrong-typed key is `Err` in the policy engine, the hooks-only pin
/// is engaged (user hooks do not run), and the requirements reader gives the same verdict for the same file.
#[test]
fn wrong_typed_admin_toml_engages_the_hooks_pin_and_both_readers_agree_p183r12() {
    for (name, tier) in [
        (REQUIREMENTS_FILENAME, PolicyLayerTier::SystemRequirements),
        (MANAGED_CONFIG_FILENAME, PolicyLayerTier::SystemManaged),
    ] {
        let d = dirs();
        let p = write(&d.sys, name, "allow_managed_hooks_only = false\n[ui]\nyolo = \"no\"\n");
        let s = sources(&d, None);
        let src = s.iter().find(|x| x.tier == tier).unwrap();
        assert!(src.policy.is_err(), "{name}: {:?}", src.policy);
        assert!(resolve_bool_pin(BoolPin::NonManagedHooks, &s).is_disabled(), "{name}");
        assert!(
            crate::validation::admin_requirements_source_checked(&p).is_err(),
            "{name}: the requirements reader must agree"
        );
    }
}

/// P183 round 12: a fully valid admin file is `Ok` on both paths with the same pins; an unknown key is ignored (no
/// lock-down) on both.
#[test]
fn valid_and_unknown_key_admin_toml_agree_with_identical_pins_p183r12() {
    let d = dirs();
    let doc = "allow_managed_hooks_only = true\nfuture_key = 1\n";
    let p = write(&d.sys, REQUIREMENTS_FILENAME, doc);
    let s = sources(&d, None);
    let json = s[0].policy.as_ref().expect("unknown key must not lock down");
    assert_eq!(json.get("allow_managed_hooks_only"), Some(&serde_json::json!(true)));
    assert!(json.get("future_key").is_none());
    assert!(resolve_bool_pin(BoolPin::NonManagedHooks, &s).is_disabled());
    let kept = crate::validation::admin_requirements_source_checked(&p).unwrap().unwrap();
    let layer: toml::Value = toml::from_str(&kept).unwrap();
    assert_eq!(layer.get("allow_managed_hooks_only"), Some(&toml::Value::Boolean(true)));
}
