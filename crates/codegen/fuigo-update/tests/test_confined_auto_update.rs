//! A process confined by a sandbox profile never starts an update on its own; it says to run `fuigo update`.
//! This binary sets the profile for its whole process (the setting is write-once), so the unconfined behaviour is covered by the other test binaries.

#![cfg(unix)]

mod common;

use serial_test::serial;

use common::{
    FakeBinGuard, can_exec_shell_scripts, make_update_config, reset_home, set_test_version,
    test_home,
};
use fuigo_update::auto_update::{auto_update_block_notice_for_test, auto_update_target, ensure_latest_on_disk};

fn confine() {
    fuigo_sandbox::set_configured_profile("workspace");
}

fn setup() -> FakeBinGuard {
    confine();
    let _ = test_home();
    reset_home();
    set_test_version("0.2.5");
    // SAFETY: serial_test ensures no race; reset_home clears this between tests.
    unsafe { std::env::set_var("FUIGO_INSTALLER", "gh-release") };
    let g = FakeBinGuard::install_gh();
    g.set_stable_only_stdout("v0.2.7\n");
    g
}

#[tokio::test]
#[serial]
async fn confined_leader_converge_does_not_install() {
    if !can_exec_shell_scripts() {
        eprintln!("skipping: shell scripts cannot execute in this sandbox");
        return;
    }
    let g = setup();
    let cfg = make_update_config("stable");

    let outcome = ensure_latest_on_disk(&cfg).await.unwrap();

    assert_eq!(outcome.installed, None);
    assert!(
        !g.args_log().iter().any(|l| l.contains("release download")),
        "a confined process must not download: {:?}",
        g.args_log()
    );
}

#[tokio::test]
#[serial]
async fn confined_process_has_no_auto_update_target_and_says_to_run_update() {
    if !can_exec_shell_scripts() {
        eprintln!("skipping: shell scripts cannot execute in this sandbox");
        return;
    }
    let _g = setup();
    let cfg = make_update_config("stable");

    assert_eq!(auto_update_target(&cfg).await, None);
    let notice = auto_update_block_notice_for_test("0.2.7").expect("confined");
    assert!(notice.contains("confined in a sandbox"), "{notice}");
    assert!(notice.contains("Run `fuigo update`"), "{notice}");
}
