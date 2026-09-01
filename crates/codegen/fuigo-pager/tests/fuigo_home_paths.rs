//! `FUIGO_HOME` override tests in an isolated binary so `fuigo_home()`'s process-wide `OnceLock` initializes from the overridden env var.

use std::path::PathBuf;

#[test]
#[serial_test::serial(FUIGO_HOME)]
fn fuigo_home_override_path_helpers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fuigo_home = tmp.path().to_path_buf();
    unsafe {
        std::env::set_var("FUIGO_HOME", &fuigo_home);
    }

    assert_eq!(
        fuigo_pager::util::pager_toml_path(),
        fuigo_home.join("pager.toml")
    );
    assert_eq!(
        fuigo_pager::util::display_fuigo_home_prefix(),
        "$FUIGO_HOME"
    );
    assert_eq!(
        fuigo_pager::util::display_user_fuigo_path("config.toml"),
        "$FUIGO_HOME/config.toml"
    );

    let memory_path = fuigo_home.join("memory/MEMORY.md");
    assert_eq!(
        fuigo_pager::util::abbreviate_path(&memory_path.display().to_string()),
        "$FUIGO_HOME/memory/MEMORY.md"
    );

    // The copy toast abbreviates paths the same way, so a custom $FUIGO_HOME outside $HOME still shows the short form
    assert_eq!(
        fuigo_pager::clipboard::display_copy_path(&fuigo_home.join("last-copy.txt")),
        "$FUIGO_HOME/last-copy.txt"
    );

    assert!(fuigo_pager::util::is_under_user_fuigo_home(&memory_path));
    assert!(!fuigo_pager::util::is_under_user_fuigo_home(
        PathBuf::from("/tmp/other").as_path()
    ));
}

/// Isolated because `fuigo_home()`'s `OnceLock` is already initialized by the time the shared lib-test binary reaches a case like this.
#[test]
#[serial_test::serial(FUIGO_HOME)]
fn disk_usage_run_creates_no_fuigo_home() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ghost = tmp.path().join("ghost-home");
    unsafe {
        std::env::set_var("FUIGO_HOME", &ghost);
    }

    for json in [false, true] {
        fuigo_pager::disk_usage_cmd::run(fuigo_pager::disk_usage_cmd::DiskUsageArgs { json })
            .expect("a missing home is not an error");
        assert!(
            !ghost.exists(),
            "fuigo du must not create the home it reports on (json={json})"
        );
    }
}
