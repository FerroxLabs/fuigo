// Per-test-case module for the `pty_e2e` integration test crate.
#[allow(unused_imports)]
use super::common::*;

const EDIT_DONE: &str = "P152_EDIT_AFTER_ALLOW_ONCE";

/// The prompt row the cursor is on: the radio marker `(●)` (`(•)` on a legacy console) marks it.
fn focused_permission_row(screen: &str) -> Option<String> {
    screen
        .lines()
        .find(|l| l.contains("(\u{25cf})") || l.contains("(\u{2022})"))
        .map(str::to_owned)
}

/// P152 (e2e lane B #6, lane M #4): a permission prompt is a safety prompt.
/// 1. Its cursor starts on the least permissive approve row ("Yes", allow once), never on "Yes, and don't ask again for
///    anything (always-approve mode)", so a reflexive Enter cannot grant blanket permission.
/// 2. Text the user was already typing when the prompt opened must not answer it: letters are not selector keys, and the
///    Enter that ends a burst of typing is held instead of approving the focused row.
/// 3. A deliberate Enter afterwards approves once: the edit lands and no always-approve mode is persisted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run the owning pty_e2e_* Cargo test with --ignored (see Cargo.toml)"]
async fn permission_prompt_preselects_allow_once_and_holds_typed_enter() {
    let content = ContentController::start().await.expect("start content");
    let edit_target = content.home().join("p152_needs_prompt.txt");
    std::fs::write(&edit_target, "old line\n").expect("write edit fixture");
    let edit_abs = dunce::canonicalize(&edit_target).unwrap_or(edit_target.clone());

    let binary = pager_binary().expect("resolve pager binary");
    let mut harness = PtyHarness::spawn_with_content_in_dir(
        &binary,
        DEFAULT_ROWS,
        DEFAULT_COLS,
        &content,
        &["--trust"],
        Some(content.home()),
    )
    .expect("spawn pager");
    harness
        .wait_for_text(WELCOME_SCREEN_SENTINEL, WELCOME_TIMEOUT)
        .expect("welcome");

    let _edit_turn = expect_tool_turn(
        &content,
        "call_p152_edit",
        "search_replace",
        json!({
            "file_path": edit_abs.to_string_lossy(),
            "old_string": "old line",
            "new_string": "new line",
        })
        .to_string(),
    );
    content.set_response(EDIT_DONE);
    harness
        .inject_keys(b"edit the fixture\r")
        .expect("submit edit that needs permission");
    harness
        .wait_for_text("No, reject", Duration::from_secs(60))
        .expect("permission modal opens");
    harness.update(Duration::from_millis(300));

    // 1. The preselected row is plain "Yes" (allow once).
    let screen = harness.screen_contents();
    let focused = focused_permission_row(&screen)
        .unwrap_or_else(|| panic!("no focused permission row on screen:\n{screen}"));
    assert!(
        !focused.contains("don't ask again") && !focused.contains("allow all edits"),
        "the permission prompt must not preselect a blanket grant; focused row: {focused:?}\nscreen:\n{screen}"
    );
    assert!(
        focused.trim_end().ends_with("Yes"),
        "the permission prompt must preselect the allow-once row; focused row: {focused:?}\nscreen:\n{screen}"
    );

    // 2. Typing through the prompt (letters, then Enter in the same burst) answers nothing.
    harness
        .inject_keys(b"hello there\r")
        .expect("type through the open prompt");
    harness.update(Duration::from_millis(1500));
    let screen = harness.screen_contents();
    assert!(
        screen.contains("No, reject"),
        "an Enter that ends a burst of typing must not answer the permission prompt\nscreen:\n{screen}"
    );
    assert_eq!(
        std::fs::read_to_string(&edit_target).expect("read fixture"),
        "old line\n",
        "typed-through text must not approve the edit"
    );
    assert!(
        !screen.contains(EDIT_DONE),
        "the turn must still be waiting on the prompt\nscreen:\n{screen}"
    );

    // 3. A deliberate Enter approves once.
    harness.inject_keys(b"\r").expect("deliberate enter");
    harness
        .wait_for_text(EDIT_DONE, Duration::from_secs(90))
        .expect("turn settles after allow once");
    assert_eq!(
        std::fs::read_to_string(&edit_target).expect("read fixture"),
        "new line\n",
        "the deliberate Enter approves the edit"
    );
    let config = std::fs::read_to_string(content.home().join(".fuigo").join("config.toml"))
        .unwrap_or_default();
    assert!(
        !config.contains("always-approve"),
        "allow once must not persist always-approve mode; config.toml:\n{config}"
    );
    assert!(
        !harness.contains_text("panicked"),
        "pager panicked\nscreen:\n{}",
        harness.screen_contents()
    );
    harness.quit().expect("clean quit");
}
