// Per-test-case module for the `pty_e2e` integration test crate.
#[allow(unused_imports)]
use super::common::*;

const FIXTURE: &str = "rewind_note.txt";
const ORIGINAL: &str = "ORIGINAL_LINE";
const EDITED: &str = "EDITED_BY_AGENT";
const SETTLED: &str = "REWIND_FILES_SETTLED";

fn read_fixture(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Wait (bounded) for the fixture to satisfy `ok`, returning its final content.
fn wait_for_fixture(
    harness: &mut PtyHarness,
    path: &Path,
    secs: u64,
    ok: impl Fn(&str) -> bool,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let text = read_fixture(path);
        if ok(&text) || Instant::now() >= deadline {
            return text;
        }
        harness.update(Duration::from_millis(100));
    }
}

/// Spawn the pager, let the agent edit the fixture through its file tool in one turn, and leave it idle with the edit on disk.
/// Returns the harness, the content controller and the fixture path.
async fn session_with_one_agent_edit() -> (PtyHarness, ContentController, PathBuf) {
    let content = ContentController::start().await.expect("start content");
    let target = content.home().join(FIXTURE);
    std::fs::write(&target, format!("{ORIGINAL}\n")).expect("write fixture");
    let abs = dunce::canonicalize(&target).unwrap_or(target.clone());
    let args = json!({
        "file_path": abs.to_string_lossy(),
        "old_string": ORIGINAL,
        "new_string": EDITED,
    })
    .to_string();
    let _edit = expect_tool_turn(&content, "call_rw_1", "search_replace", args);
    let _settled = content.expect_agent_turn("settled", format!("{SETTLED} done."));
    content.set_response("REWIND_FILES_EXTRA");

    let binary = pager_binary().expect("resolve pager binary");
    let mut harness = PtyHarness::spawn_with_content_in_dir(
        &binary,
        DEFAULT_ROWS,
        DEFAULT_COLS,
        &content,
        &["--yolo", "--trust"],
        Some(content.home()),
    )
    .expect("spawn pager");
    harness
        .wait_for_text(WELCOME_SCREEN_SENTINEL, WELCOME_TIMEOUT)
        .expect("welcome");
    harness
        .inject_keys(format!("{PROMPT}\r").as_bytes())
        .expect("submit prompt");
    harness
        .wait_for_text(SETTLED, Duration::from_secs(90))
        .unwrap_or_else(|_| panic!("turn did not settle:\n{}", harness.screen_contents()));
    harness
        .wait_for_turn_idle(Duration::from_secs(15))
        .expect("turn idle");
    let text = read_fixture(&abs);
    assert!(text.contains(EDITED), "the agent's edit must be on disk, got {text:?}");
    (harness, content, abs)
}

/// Open `/rewind`, pick the only turn and wait for the confirm dialog.
async fn open_rewind_confirm(harness: &mut PtyHarness) {
    harness.inject_keys(b"/rewind\r").expect("type /rewind");
    harness
        .wait_for_text("Rewind to which turn?", Duration::from_secs(20))
        .unwrap_or_else(|_| panic!("picker did not open:\n{}", harness.screen_contents()));
    harness.inject_keys(b"\r").expect("pick the turn");
    harness
        .wait_for_text("rewind conversation and files", Duration::from_secs(15))
        .unwrap_or_else(|_| panic!("confirm did not open:\n{}", harness.screen_contents()));
}

/// PTY: the agent edits a file, then `/rewind` -> "Yes, rewind conversation and files" puts the file back and says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run with cargo test -p fuigo-pager --test pty_e2e_shell_tools -- --ignored"]
async fn rewind_conversation_and_files_restores_the_edited_file() {
    let (mut harness, _content, abs) = session_with_one_agent_edit().await;
    open_rewind_confirm(&mut harness).await;
    harness.inject_keys(b"y").expect("choose conversation and files");
    let text = wait_for_fixture(&mut harness, &abs, 30, |t| t.contains(ORIGINAL));
    assert!(
        text.contains(ORIGINAL) && !text.contains(EDITED),
        "rewind with files must restore the original, got {text:?}\nscreen:\n{}",
        harness.screen_contents()
    );
    // The file is restored on disk before the pager has rendered the result, and FIXTURE is already on screen in the
    // Edit block of the agent turn, so wait for the real event: the rewind result message naming the reverted file.
    harness
        .wait_for_text("Reverted conversation and 1 file", Duration::from_secs(15))
        .unwrap_or_else(|_| panic!("the rewind result must be reported:\n{}", harness.screen_contents()));
    assert!(harness.contains_text(FIXTURE), "the restored file must be named:\n{}", harness.screen_contents());
    harness.quit().expect("clean quit");
}

/// PTY: "conversation only" rewinds the transcript and leaves the agent's edit on disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run with cargo test -p fuigo-pager --test pty_e2e_shell_tools -- --ignored"]
async fn rewind_conversation_only_leaves_the_file_as_it_is() {
    let (mut harness, _content, abs) = session_with_one_agent_edit().await;
    open_rewind_confirm(&mut harness).await;
    harness.inject_keys(b"c").expect("choose conversation only");
    harness
        .wait_for_text("Reverted conversation", Duration::from_secs(30))
        .unwrap_or_else(|_| panic!("rewind did not finish:\n{}", harness.screen_contents()));
    harness.update(Duration::from_millis(500));
    let text = read_fixture(&abs);
    assert!(
        text.contains(EDITED) && !text.contains(ORIGINAL),
        "conversation only must not touch the file, got {text:?}"
    );
    harness.quit().expect("clean quit");
}

/// PTY: a file changed outside Fuigo since the checkpoint is reported, left alone, and only overwritten after the user says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run with cargo test -p fuigo-pager --test pty_e2e_shell_tools -- --ignored"]
async fn rewind_reports_a_conflicting_file_and_does_not_overwrite_it() {
    let (mut harness, _content, abs) = session_with_one_agent_edit().await;
    let external = format!("{EDITED}\nEXTERNAL_EDIT\n");
    std::fs::write(&abs, &external).expect("external edit");
    open_rewind_confirm(&mut harness).await;
    harness.inject_keys(b"y").expect("choose conversation and files");
    harness
        .wait_for_text("changed outside Fuigo", Duration::from_secs(30))
        .unwrap_or_else(|_| panic!("conflict not reported:\n{}", harness.screen_contents()));
    assert!(harness.contains_text(FIXTURE), "{}", harness.screen_contents());
    harness.update(Duration::from_millis(500));
    assert_eq!(read_fixture(&abs), external, "a conflicting file must not be overwritten unasked");
    // Cancel: still untouched.
    harness.inject_keys(b"n").expect("cancel");
    harness.update(Duration::from_millis(500));
    assert_eq!(read_fixture(&abs), external, "cancel must leave the file alone");
    // Ask again and overwrite explicitly.
    open_rewind_confirm(&mut harness).await;
    harness.inject_keys(b"y").expect("again");
    harness
        .wait_for_text("changed outside Fuigo", Duration::from_secs(30))
        .expect("conflict reported again");
    harness.inject_keys(b"o").expect("overwrite");
    let text = wait_for_fixture(&mut harness, &abs, 30, |t| t.contains(ORIGINAL));
    assert!(text.contains(ORIGINAL), "explicit overwrite must restore, got {text:?}");
    harness.quit().expect("clean quit");
}
