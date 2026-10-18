// Per-test-case module for the `leader_pty_e2e` integration test crate.
#[allow(unused_imports)]
use super::common::*;

/// The one session folder under the home's session store, and its writable state files as (name, contents).
fn session_state(home: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, Vec<u8>)>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                matches!(n, "plan_mode.json" | "updates.jsonl" | "chat_history.jsonl" | "signals.json")
            }) {
                out.push((p.clone(), std::fs::read(&p).unwrap_or_default()));
            }
        }
    }
    let mut out = Vec::new();
    walk(&home.join(".fuigo").join("sessions"), &mut out);
    out.sort();
    out
}

/// 1.0.30 P30-DIRECT: with the shared leader off, a second window's `fuigo --resume <id>` of a session that is open in
/// another window is refused before the TUI starts: it prints why, exits non-zero and writes nothing into the session.
/// Once the first window has quit, the same command opens the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "PTY e2e; run with cargo test -p fuigo-pager --test leader_pty_e2e -- --ignored --test-threads=1"]
async fn direct_resume_of_a_session_open_in_another_window_is_refused() {
    let content = ContentController::start().await.expect("start content");
    content.set_response(format!("{} first turn payload.", turn_sentinel(1)));
    let home = content.home().to_path_buf();
    let binary = pager_binary().expect("binary");
    let spawn = |args: &[&str]| -> PtyHarness {
        PtyHarness::spawn_with_content(&binary, DEFAULT_ROWS, DEFAULT_COLS, &content, args).expect("spawn")
    };

    let mut a = spawn(&["--no-leader"]);
    a.wait_for_text(WELCOME_SCREEN_SENTINEL, LEADER_TIMEOUT).expect("A welcome");
    a.inject_keys(format!("{PROMPT}\r").as_bytes()).expect("A submit turn 1");
    a.wait_for_text(&turn_sentinel(1), STREAM_TIMEOUT).expect("A turn 1");
    a.inject_keys(b"\x1b[Z").expect("A BackTab");
    a.wait_for_text("Switched to mode: Plan", Duration::from_secs(20)).expect("A -> plan");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !session_state(&home)
        .iter()
        .any(|(p, s)| p.ends_with("plan_mode.json") && String::from_utf8_lossy(s).contains("Pending"))
        && Instant::now() < deadline
    {
        a.update(Duration::from_millis(200));
    }
    a.update(Duration::from_secs(2));
    let before = session_state(&home);
    let plan = before.iter().find(|(p, _)| p.ends_with("plan_mode.json")).expect("plan_mode.json written");
    assert!(String::from_utf8_lossy(&plan.1).contains("\"Pending\""), "A's plan mode persisted: {before:?}");
    let sid = plan.0.parent().unwrap().file_name().unwrap().to_str().unwrap().to_string();

    // Window C, also without the leader, resumes the session A has open.
    let mut c = spawn(&["--no-leader", "--resume", sid.as_str()]);
    let code = c.wait_for_exit_and_drain(Duration::from_secs(120), Duration::from_secs(2)).expect("C exits");
    let c_text = String::from_utf8_lossy(c.raw_output()).into_owned();
    assert_ne!(code, 0, "C opened a session that is open in another window\n{c_text}");
    assert!(
        c_text.contains("This session is open in another Fuigo window"),
        "C did not say why it refused the session\n{c_text}"
    );
    assert!(c_text.contains("--leader"), "C's refusal does not point at the shared leader\n{c_text}");
    a.update(Duration::from_secs(1));
    assert_eq!(session_state(&home), before, "the refused window wrote into the session");
    assert!(a.is_running().expect("A alive"), "A exited\n{}", a.screen_contents());

    // A quits: the session is free, and C's same command now opens it.
    a.quit().expect("quit A");
    let _ = a.wait_for_exit_and_drain(Duration::from_secs(60), Duration::from_secs(1));
    let mut c2 = spawn(&["--no-leader", "--resume", sid.as_str()]);
    c2.wait_for_text(&turn_sentinel(1), LEADER_TIMEOUT).expect("C opened the session after A quit");
    assert!(c2.is_running().expect("C alive"), "C exited\n{}", c2.screen_contents());
    c2.quit().expect("quit C");
}
