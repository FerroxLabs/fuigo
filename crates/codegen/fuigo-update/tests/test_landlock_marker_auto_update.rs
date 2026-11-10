//! A process Fuigo confined with Landlock has no bwrap marker; the `__FUIGO_CONFINED` marker alone must block auto-update.
//! No profile is configured here, so the only confinement signal is the marker.

#![cfg(unix)]

use fuigo_update::auto_update::auto_update_block_notice_for_test;
use serial_test::serial;

#[test]
#[serial]
fn landlock_marker_alone_blocks_auto_update() {
    // SAFETY: serial_test keeps this binary single-threaded around the env.
    unsafe { std::env::remove_var("__FUIGO_CONFINED") };
    unsafe { std::env::remove_var("__FUIGO_INSIDE_BWRAP") };
    assert_eq!(auto_update_block_notice_for_test("0.2.7"), None, "unconfined must stay unblocked");
    unsafe { std::env::set_var("__FUIGO_CONFINED", "1") };
    let notice = auto_update_block_notice_for_test("0.2.7").expect("a Landlock-confined process must be blocked");
    assert!(notice.contains("confined in a sandbox"), "{notice}");
    unsafe { std::env::remove_var("__FUIGO_CONFINED") };
}
