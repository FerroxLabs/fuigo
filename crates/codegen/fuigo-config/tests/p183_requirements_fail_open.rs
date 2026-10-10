//! P183: requirements fail-open leftovers, through the public startup API.
//!
//! This binary holds ONE test on purpose: it writes the process environment (`FUIGO_TEST_VERSION`,
//! `FUIGO_MANAGED_CONFIG_FAIL_CLOSED`), which is only sound while no other thread reads it.

use std::path::Path;

fn set_env(k: &str, v: &str) {
    // SAFETY: the only test in this binary; no other thread reads the environment while it runs.
    unsafe { std::env::set_var(k, v) };
}

fn remove_env(k: &str) {
    // SAFETY: as in `set_env`.
    unsafe { std::env::remove_var(k) };
}

fn write_requirements(home: &Path, contents: &str) {
    std::fs::write(home.join("requirements.toml"), contents).unwrap();
}

#[test]
fn requirements_fail_open_leftovers_p183() {
    // Hermetic (Astra r1, r2): `validate_requirements_for_dirs` checks only this test's home, never the host's /etc/fuigo or
    // MDM profile, with the live environment that the cases below set. Every refusal must also name THIS test's file.
    let home = tempfile::tempdir().unwrap();
    let ours = home.path().join("requirements.toml").display().to_string();
    let check = || fuigo_config::validate_requirements_for_dirs(None, Some(home.path()));
    let refused_for_ours = |what: &str| {
        let err = check().expect_err(what);
        let msg = err.to_string();
        assert!(
            msg.contains(&ours),
            "{what}: refused for another layer: {msg}"
        );
        msg
    };
    remove_env("FUIGO_MANAGED_CONFIG_FAIL_CLOSED");

    // 1. A garbage FUIGO_TEST_VERSION must not bypass fail_closed override validation.
    set_env(fuigo_version::TEST_VERSION_ENV, "garbage");
    write_requirements(
        home.path(),
        "fail_closed = true\n[[version_overrides]]\nminimum_version = \"not-a-version\"\n",
    );
    refused_for_ours(
        "FUIGO_TEST_VERSION=garbage bypassed fail_closed version_overrides validation",
    );

    // 2. ...nor make the loader silently skip a valid override patch (a patch can be the tightening one).
    let mut v: toml::Value = toml::from_str(
        "[ui]\nyolo = true\n[[version_overrides]]\nminimum_version = \"0.0.0\"\n[version_overrides.ui]\nyolo = false\n",
    )
    .unwrap();
    fuigo_config::apply_version_overrides_with_registered(&mut v).unwrap();
    assert_eq!(
        v["ui"]["yolo"].as_bool(),
        Some(false),
        "FUIGO_TEST_VERSION=garbage stripped the override patch without applying it"
    );
    remove_env(fuigo_version::TEST_VERSION_ENV);

    // 3. A user-home requirements file that is not TOML at all, but whose own fail_closed line is readable, refuses to start.
    write_requirements(home.path(), "fail_closed = true\n[ui\nyolo = false\n");
    let msg = refused_for_ours(
        "unparseable fail_closed requirements file was dropped and startup allowed",
    );
    assert!(
        msg.contains("TOML parse error"),
        "names the parse error: {msg}"
    );

    // 4. Without fail_closed, the user-home layer warns loudly and starts (P162's user-layer rule: user-writable, not admin-owned).
    write_requirements(home.path(), "[ui\nyolo = false\n");
    let warnings = check().unwrap();
    assert!(
        warnings.len() == 1 && warnings[0].contains(&ours),
        "the caller must get a warning to print: {warnings:?}"
    );

    // 5. The fail_closed env can only tighten: forced on, the same unparseable user file refuses to start.
    set_env("FUIGO_MANAGED_CONFIG_FAIL_CLOSED", "1");
    refused_for_ours(
        "FUIGO_MANAGED_CONFIG_FAIL_CLOSED=1 did not refuse an unparseable requirements file",
    );
    remove_env("FUIGO_MANAGED_CONFIG_FAIL_CLOSED");
}
