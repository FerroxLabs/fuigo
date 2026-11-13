use super::*;

fn config(base: &str, setting: &str) -> SandboxConfig {
    toml::from_str(&format!(
        "[profiles.review]\nextends = {base:?}\n{setting}\n"
    ))
    .unwrap()
}

#[test]
fn omitted_workspace_write_preserves_every_existing_base() {
    let workspace = std::env::current_dir().unwrap();
    for base in ["workspace", "devbox", "read-only", "strict"] {
        let config = config(base, "future_option = true");
        assert_eq!(config.profiles["review"].workspace_write, None);
        let inherited = ProfileName::Custom("review".into())
            .resolve_profile(&workspace, &config)
            .unwrap();
        let builtin = base
            .parse::<ProfileName>()
            .unwrap()
            .resolve_profile(&workspace, &SandboxConfig::default())
            .unwrap();
        assert_eq!(inherited.read_only, builtin.read_only, "{base}");
        assert_eq!(inherited.read_write, builtin.read_write, "{base}");
        assert_eq!(inherited.default_read, builtin.default_read, "{base}");
        assert_eq!(
            inherited.restrict_network, builtin.restrict_network,
            "{base}"
        );
        assert_eq!(inherited.deny, builtin.deny, "{base}");
    }
}

#[test]
fn workspace_override_matrix_and_landlock_input_golden() {
    let workspace = std::env::current_dir().unwrap();
    let custom = ProfileName::Custom("review".into());
    let mut golden = String::new();
    for base in ["workspace", "devbox", "read-only", "strict", "minimal"] {
        for setting in ["", "workspace_write = true", "workspace_write = false"] {
            let config = config(base, setting);
            let profile = custom.resolve_profile(&workspace, &config).unwrap();
            let writable = profile.read_write.contains(&workspace);
            let denied = custom.denies_workspace_write(&config);
            golden.push_str(&format!("{base} {}: launch_grant={writable} boundary={denied} default_read={} restrict_network={}\n", if setting.is_empty() { "omitted" } else { setting.split(" = ").nth(1).unwrap() }, profile.default_read, profile.restrict_network));
        }
    }
    assert_eq!(
        golden,
        include_str!("../tests/fixtures/workspace-write-landlock.txt")
    );
}

#[test]
fn minimal_keeps_strict_reads_and_only_state_temp_writes() {
    let workspace = std::env::current_dir().unwrap();
    let config = SandboxConfig::default();
    let strict = ProfileName::Strict
        .resolve_profile(&workspace, &config)
        .unwrap();
    let minimal = ProfileName::Minimal
        .resolve_profile(&workspace, &config)
        .unwrap();
    assert_eq!(minimal.read_only, strict.read_only);
    assert_eq!(minimal.restrict_network, strict.restrict_network);
    assert_eq!(
        minimal.read_write,
        strict
            .read_write
            .into_iter()
            .filter(|p| p != &workspace)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        "minimal".parse::<ProfileName>().unwrap(),
        ProfileName::Minimal
    );
    assert!(
        crate::unavailable_warning_for("minimal", true)
            .unwrap()
            .contains("unsandboxed")
    );
}

#[cfg(unix)]
#[test]
fn false_beats_explicit_grants_and_symlink_aliases() {
    let temp = tempfile::tempdir().unwrap();
    let prefix = temp.path().join("prefix");
    std::os::unix::fs::symlink(temp.path(), &prefix).unwrap();
    let workspace = prefix.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let alias = temp.path().join("alias");
    std::os::unix::fs::symlink(&workspace, &alias).unwrap();
    let config = config(
        "workspace",
        &format!(
            "workspace_write = false\nread_write = [{:?}, {:?}, {:?}]",
            workspace.display().to_string(),
            alias.display().to_string(),
            workspace.join("new").display().to_string()
        ),
    );
    let profile = ProfileName::Custom("review".into())
        .resolve_profile(&workspace, &config)
        .unwrap();
    let canonical_workspace = dunce::canonicalize(&workspace).unwrap();
    assert_ne!(
        workspace, canonical_workspace,
        "fixture must use a symlink prefix"
    );
    assert!(
        !profile
            .read_write
            .iter()
            .any(|p| canonical_path(p).starts_with(&canonical_workspace)),
        "workspace grant remains: {:?}",
        profile.read_write
    );
    assert!(
        profile.read_write.contains(&PathBuf::from("/tmp")),
        "temp parent remains useful outside workspace"
    );
    assert!(
        !workspace.join("new").exists(),
        "resolution must not create an excluded grant"
    );
}

#[cfg(all(feature = "enforce", unix))]
#[test]
fn minimal_and_custom_false_seatbelt_golden_true_has_no_boundary() {
    let temp = tempfile::tempdir_in("/tmp").unwrap();
    let workspace = temp.path();
    for (name, config) in [
        (ProfileName::Minimal, SandboxConfig::default()),
        (
            ProfileName::Custom("review".into()),
            config("workspace", "workspace_write = false"),
        ),
        (
            ProfileName::Custom("review".into()),
            config("minimal", "workspace_write = true"),
        ),
    ] {
        let profile = name.resolve_profile(workspace, &config).unwrap();
        let mut caps = nono::CapabilitySet::new();
        let mut rules =
            apply_seatbelt_boundary(&name, workspace, &config, &profile, &mut caps).unwrap();
        // Replace only the generated leaf, preserving /tmp and /private/tmp aliases.
        let leaf = workspace.file_name().unwrap().to_str().unwrap();
        for rule in &mut rules {
            *rule = rule.replace(leaf, "fuigo-workspace-write-golden");
        }
        let expected = if name.denies_workspace_write(&config) {
            include_str!("../tests/fixtures/workspace-write-seatbelt.sbpl")
        } else {
            ""
        };
        // On macOS /tmp canonicalizes to /private/tmp; both input spellings
        // deliberately cover the same filters. Compare the exact rule set.
        rules.sort();
        rules.dedup();
        let mut expected: Vec<_> = expected.lines().collect();
        expected.sort();
        assert_eq!(rules, expected);
        assert!(!rules.iter().any(|rule| rule.contains("file-read")));
    }
}

#[cfg(target_os = "linux")]
#[test]
#[serial_test::serial(bwrap_env)]
fn minimal_and_custom_bwrap_boundary_golden() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = temp.path();
    let canonical = canonical_path(workspace);
    let alias = workspace.join("alias");
    std::os::unix::fs::symlink(workspace, &alias).unwrap();
    for (name, config) in [
        (ProfileName::Minimal, SandboxConfig::default()),
        (
            ProfileName::Custom("review".into()),
            config("devbox", "workspace_write = false"),
        ),
        (
            ProfileName::Custom("review".into()),
            config("minimal", "workspace_write = true"),
        ),
    ] {
        let boundary = boundary_path(&name, &alias, &config);
        assert_eq!(
            boundary,
            name.denies_workspace_write(&config)
                .then(|| canonical.clone())
        );
        let config_dir = workspace.join(".fuigo");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("sandbox.toml"),
            toml::to_string(&config).unwrap(),
        )
        .unwrap();
        let cmd = crate::bwrap_reexec_for_profile(&name, workspace).unwrap();
        let args: Vec<_> = cmd.get_args().collect();
        let separator = args.iter().position(|a| *a == "--").unwrap();
        if boundary.is_some() {
            let mut relevant = Vec::new();
            for part in args[..separator].windows(3) {
                if (part[0] == "--bind" && part[1] == "/tmp" && part[2] == "/tmp")
                    || (part[0] == "--ro-bind"
                        && part[1] == canonical.as_os_str()
                        && part[2] == canonical.as_os_str())
                {
                    relevant.extend(part.iter().map(|arg| {
                        arg.to_string_lossy().replace(
                            canonical.to_str().unwrap(),
                            "/tmp/fuigo-workspace-write-golden",
                        )
                    }));
                }
            }
            assert_eq!(
                relevant.join("\n") + "\n",
                include_str!("../tests/fixtures/workspace-write-bwrap.txt")
            );
            let bind = args[..separator]
                .windows(3)
                .position(|part| {
                    part[0] == "--ro-bind"
                        && part[1] == canonical.as_os_str()
                        && part[2] == canonical.as_os_str()
                })
                .unwrap();
            assert!(bind > args.iter().position(|arg| *arg == "--dev-bind").unwrap());
            assert!(bind > args.iter().position(|arg| *arg == "--proc").unwrap());
        } else {
            assert!(!args.windows(3).any(|part| part[0] == "--ro-bind"
                && part[1] == canonical.as_os_str()
                && part[2] == canonical.as_os_str()));
        }
    }
}

#[cfg(all(feature = "enforce", unix))]
#[test]
fn seatbelt_workspace_ancestors_use_canonical_write_roots() {
    let temp = tempfile::tempdir().unwrap();
    let parent = dunce::canonicalize(temp.path()).unwrap();
    let workspace = parent.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let alias = parent.join("alias");
    std::os::unix::fs::symlink(&workspace, &alias).unwrap();
    let (entries, roots) = seatbelt_boundary_inputs(&alias, &[workspace.join("..")]);
    assert!(roots.contains(&parent));
    assert!(entries.contains(&(workspace, true)));
    let rules = crate::deny::render_write_deny_rules(&entries, &roots)
        .unwrap()
        .rules;
    assert!(rules.contains(&format!(
        "(deny file-write-unlink (literal {:?}))",
        parent.to_str().unwrap()
    )));
}

#[cfg(all(feature = "enforce", unix))]
#[test]
fn seatbelt_workspace_protects_ancestors_through_overlapping_grants() {
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path()).unwrap();
    let parent = root.join("parent");
    let narrow = parent.join("narrow");
    let workspace = narrow.join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let (entries, roots) = seatbelt_boundary_inputs(&workspace, &[root.clone(), narrow]);
    assert_eq!(roots, [root]);
    let rules = crate::deny::render_write_deny_rules(&entries, &roots)
        .unwrap()
        .rules;
    assert!(
        rules.contains(&format!(
            "(deny file-write-unlink (literal {:?}))",
            parent.to_str().unwrap()
        )),
        "the wider grant must not permit relocating the parent of the narrower grant"
    );
}

#[test]
fn legacy_minimal_selection_preserves_custom_policy() {
    let workspace = std::env::current_dir().unwrap();
    for base in ["workspace", "devbox", "strict", "read-only"] {
        for setting in ["", "workspace_write = true", "workspace_write = false"] {
            let mut config = config(base, setting);
            let definition = config.profiles["review"].clone();
            config.profiles.insert("minimal".into(), definition);
            let selected = ProfileName::Minimal
                .resolve_profile(&workspace, &config)
                .unwrap();
            let custom = ProfileName::Custom("review".into());
            let expected = custom.resolve_profile(&workspace, &config).unwrap();
            assert_eq!(selected.read_only, expected.read_only, "{base} {setting}");
            assert_eq!(selected.read_write, expected.read_write, "{base} {setting}");
            assert_eq!(selected.deny, expected.deny, "{base} {setting}");
            assert_eq!(selected.write_deny, expected.write_deny, "{base} {setting}");
            assert_eq!(
                selected.default_read, expected.default_read,
                "{base} {setting}"
            );
            assert_eq!(
                selected.restrict_network, expected.restrict_network,
                "{base} {setting}"
            );
            assert_eq!(
                ProfileName::Minimal.denies_workspace_write(&config),
                custom.denies_workspace_write(&config)
            );
            #[cfg(target_os = "linux")]
            assert_eq!(
                crate::is_devbox_based(&ProfileName::Minimal, &config),
                base == "devbox"
            );
        }
    }
}

#[cfg(all(feature = "enforce", unix))]
#[test]
fn relative_missing_write_grants_never_materialize_in_readonly_workspace() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = temp.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let config = config("minimal", "read_write = [\"build/out\"]");
    let name = ProfileName::Custom("review".into());
    let profile = name.resolve_profile(&workspace, &config).unwrap();
    assert!(
        !profile
            .read_write
            .iter()
            .any(|p| p == Path::new("build/out") || p.starts_with(&workspace)),
        "{:?}",
        profile.read_write
    );
    name.to_capability_set_with_config(&workspace, &config)
        .unwrap();
    assert!(!workspace.join("build").exists());
    // Materialization rechecks the boundary before creating any missing grant.
    let mut profile = profile;
    profile.read_write.push("build/out".into());
    ProfileName::capability_set_from_profile(&workspace, &profile, true).unwrap();
    assert!(!workspace.join("build").exists());
}
