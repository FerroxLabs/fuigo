//! PTY e2e: permission Auto mode is distinct on the real pager screen.
//!
//! Uses `fuigo-pager-pty-harness` (`PtyHarness`) and Shift+Tab (CSI Z, compatible with `ptyctl` key injection) to cycle the permission modes.
//! The mode banner must show Auto as its own mode, distinct from Always-Approve, and the ring must skip it with the gate off.
//!
//! The pager runs against the harness's mock model endpoint with the harness's fake API key, so the tests need no developer
//! `auth.json` and never meet the API-key screen: a run that cannot reach the mode ring fails instead of passing vacuously.
//!
//! Run with:
//! `cargo test -p fuigo-pager --test pty_auto_mode -- --ignored --nocapture`
// Test, bench or example code: its prints reach a harness or a developer, never a user, so the
// workspace print deny (R077) is waived here.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::time::Duration;

use fuigo_pager_pty_harness::{ContentController, EnvOp, PtyHarness, pager_binary};

const ROWS: u16 = 40;
const COLS: u16 = 120;
const WELCOME_TIMEOUT: Duration = Duration::from_secs(25);
const WELCOME_SCREEN_SENTINEL: &str = "Quit";
const BANNER_TIMEOUT: Duration = Duration::from_secs(10);

/// Back-tab (Shift+Tab, CSI Z); the pager binds it to CycleMode.
const SHIFT_TAB: &[u8] = b"\x1b[Z";

/// Spawn the pager on the welcome screen with the auto-permission-mode feature gate pinned.
/// `FUIGO_AUTO_PERMISSION_MODE` is the highest gate layer below requirements; "1" and "0" parse to on and off (`fuigo_config::env_bool`).
/// It is set on the child, which merges it over the inherited environment, so a value exported in the shell can't flip the result.
fn spawn_pager(content: &ContentController, gate_on: bool) -> PtyHarness {
    let binary = pager_binary().expect("resolve pager binary via harness env");
    let gate = [EnvOp::set(
        "FUIGO_AUTO_PERMISSION_MODE",
        if gate_on { "1" } else { "0" },
    )];
    let mut harness =
        PtyHarness::spawn_with_content_env_ops(&binary, ROWS, COLS, content, &[], &gate)
            .expect("spawn pager in PTY (fuigo-pager-pty-harness)");
    harness
        .wait_for_text(WELCOME_SCREEN_SENTINEL, WELCOME_TIMEOUT)
        .unwrap_or_else(|_| {
            panic!(
                "welcome screen never appeared; screen:\n{}",
                harness.screen_contents()
            )
        });
    harness
}

/// Press Shift+Tab and wait for the transient `Switched to mode: <mode>` banner.
fn cycle_to(harness: &mut PtyHarness, mode: &str) {
    harness.inject_keys(SHIFT_TAB).expect("inject Shift+Tab");
    let banner = format!("Switched to mode: {mode}");
    harness
        .wait_for_text(&banner, BANNER_TIMEOUT)
        .unwrap_or_else(|_| {
            panic!(
                "Shift+Tab never showed {banner:?}; screen:\n{}",
                harness.screen_contents()
            )
        });
}

/// Cycle into Auto on the welcome (pre-session) screen and assert the mode banner shows Auto, not Always-Approve alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns real pager PTY; run with cargo test -- --ignored"]
async fn pty_shift_tab_cycles_to_auto_mode_banner() {
    let content = ContentController::start().await.expect("start content");
    let mut harness = spawn_pager(&content, true);

    // Normal to Plan, then Plan to Auto
    cycle_to(&mut harness, "Plan");
    cycle_to(&mut harness, "Auto");
    let screen = harness.screen_contents();
    assert!(
        !screen.contains("Switched to mode: Always-Approve"),
        "the second press must land on Auto, not skip it; screen:\n{screen}"
    );

    // Auto is followed by Always-Approve: the two are distinct modes
    cycle_to(&mut harness, "Always-Approve");
}

/// Gate off (the shipped default): the Shift+Tab ring must skip Auto entirely, so the feature is inert and the classifier never launches.
/// The ring cycles Normal, Plan, Always-Approve, back to Normal.
/// The negative companion to the gate-on cycle test; it proves the gate governs the UI ring, not just the engine.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns real pager PTY; run with cargo test -- --ignored"]
async fn pty_shift_tab_skips_auto_when_gate_off() {
    let content = ContentController::start().await.expect("start content");
    let mut harness = spawn_pager(&content, false);

    // Cycle the full ring (4 presses returns to Normal)
    // Plan and Always-Approve must appear, proving the ring otherwise works; Auto must never appear
    let mut saw_plan = false;
    let mut saw_always = false;
    let mut saw_auto = false;
    for _ in 0..4 {
        harness.inject_keys(SHIFT_TAB).expect("inject Shift+Tab");
        // Drain output so the new mode banner renders before we read
        // `wait_for_text("Switched to mode:")` would hit its fast path and return instantly on the prior press's banner still on screen
        // Pump for a fixed window instead; the screen tracker keeps only the latest frame, so each read reflects the current mode
        harness.update(Duration::from_secs(2));
        let screen = harness.screen_contents();
        saw_plan |= screen.contains("Switched to mode: Plan");
        saw_always |= screen.contains("Switched to mode: Always-Approve");
        saw_auto |= screen.contains("Switched to mode: Auto");
    }

    assert!(
        !saw_auto,
        "gate OFF: Shift+Tab ring must skip Auto, but the Auto banner appeared"
    );
    assert!(
        saw_plan && saw_always,
        "gate OFF: ring should still cycle Plan and Always-Approve \
         (saw_plan={saw_plan}, saw_always={saw_always}); screen:\n{}",
        harness.screen_contents()
    );
}
