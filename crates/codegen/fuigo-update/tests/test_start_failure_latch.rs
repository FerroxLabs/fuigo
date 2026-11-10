//! A version that downloads fine but fails to start on this machine is not retried by automatic updates until a newer version is out.
//! An explicit `fuigo update` still tries it.

#![cfg(unix)]

mod common;

use serial_test::serial;

use common::artifact_server::{ArtifactServer, Mode};
use common::{
    FakeBinGuard, can_exec_shell_scripts, make_update_config, reset_home, set_test_version,
    small_good_artifact, test_home,
};
use fuigo_update::auto_update::{
    CliUpdateTrigger, auto_update_block_notice_for_test, ensure_latest_on_disk,
    install_internal_from_base, run_install_script,
};

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn failed_start_latches_that_version_only_until_it_installs_cleanly() {
    if !can_exec_shell_scripts() {
        eprintln!("skipping: shell scripts cannot execute in this sandbox");
        return;
    }
    let server = ArtifactServer::start(small_good_artifact());
    let _ = test_home();
    reset_home();
    let cfg = make_update_config("stable");

    server.set_mode(Mode::Garbage);
    install_internal_from_base(Some("0.1.181"), &cfg, &server.uri())
        .await
        .expect_err("a binary that cannot start must not install");

    let notice = auto_update_block_notice_for_test("0.1.181").expect("0.1.181 is latched");
    assert!(notice.contains("failed to start on this machine"), "{notice}");
    assert!(notice.contains("fuigo update"), "{notice}");
    assert_eq!(
        auto_update_block_notice_for_test("0.1.182"),
        None,
        "a newer version is not latched"
    );

    // The same version installing cleanly (an explicit retry) lifts the latch.
    server.set_mode(Mode::Full);
    install_internal_from_base(Some("0.1.181"), &cfg, &server.uri())
        .await
        .expect("clean serve installs");
    assert_eq!(auto_update_block_notice_for_test("0.1.181"), None);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn automatic_install_of_a_latched_version_is_refused_before_any_download() {
    if !can_exec_shell_scripts() {
        eprintln!("skipping: shell scripts cannot execute in this sandbox");
        return;
    }
    let server = ArtifactServer::start(small_good_artifact());
    let _ = test_home();
    reset_home();
    let cfg = make_update_config("stable");
    server.set_mode(Mode::Garbage);
    install_internal_from_base(Some("0.1.181"), &cfg, &server.uri())
        .await
        .expect_err("garbage");

    for trigger in [CliUpdateTrigger::AutoBackground, CliUpdateTrigger::LeaderConverge] {
        let err = run_install_script("internal", Some("0.1.181"), &cfg, trigger)
            .await
            .expect_err("a latched version must not be retried automatically");
        let msg = format!("{err:#}");
        assert!(msg.contains("failed to start on this machine"), "{msg}");
    }
}

#[tokio::test]
#[serial]
async fn leader_converge_skips_a_latched_target() {
    if !can_exec_shell_scripts() {
        eprintln!("skipping: shell scripts cannot execute in this sandbox");
        return;
    }
    let _ = test_home();
    reset_home();
    set_test_version("0.2.5");
    // SAFETY: serial_test ensures no race; reset_home clears this between tests.
    unsafe { std::env::set_var("FUIGO_INSTALLER", "gh-release") };
    let g = FakeBinGuard::install_gh();
    g.set_stable_only_stdout("v0.2.7\n");
    std::fs::write(test_home().join(".update-start-failed"), "0.2.7\n").unwrap();
    let cfg = make_update_config("stable");

    let outcome = ensure_latest_on_disk(&cfg).await.unwrap();

    assert_eq!(outcome.installed, None);
    assert!(
        !g.args_log().iter().any(|l| l.contains("release download")),
        "no download for a latched version: {:?}",
        g.args_log()
    );
}
