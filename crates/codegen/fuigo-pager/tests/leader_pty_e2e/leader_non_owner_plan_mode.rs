// Per-test-case module for the `leader_pty_e2e` integration test crate.
#[allow(unused_imports)]
use super::common::*;

/// Every `plan_mode.json` under the cluster home, as (path, contents).
fn plan_mode_files(home: &std::path::Path) -> Vec<(std::path::PathBuf, String)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, String)>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.file_name().is_some_and(|n| n == "plan_mode.json") {
                out.push((p.clone(), std::fs::read_to_string(&p).unwrap_or_default()));
            }
        }
    }
    let mut out = Vec::new();
    walk(&home.join(".fuigo").join("sessions"), &mut out);
    out.sort();
    out
}

enum Launch {
    /// Explicit `--leader --leader-socket`; C uses `--resume` (most recent).
    ClusterMostRecent,
    /// Explicit `--leader --leader-socket`; C uses `--resume <id>`.
    ClusterById,
    /// No leader flags: `[cli] use_leader = true` in the shared config elects the default leader; C uses `--resume <id>`.
    DefaultLeaderById,
}

async fn non_owner_cannot_change_plan_mode(launch: Launch) {
    let cluster = LeaderCluster::start(DEFAULT_ROWS, DEFAULT_COLS).await.expect("start cluster");
    cluster.content().set_response(format!("{} first turn payload.", turn_sentinel(1)));
    let home = cluster.content().home().to_path_buf();
    let binary = pager_binary().expect("binary");
    if matches!(launch, Launch::DefaultLeaderById) {
        let cfg = home.join(".fuigo").join("config.toml");
        let mut text = std::fs::read_to_string(&cfg).unwrap_or_default();
        text.push_str("\n[cli]\nuse_leader = true\n");
        std::fs::write(&cfg, text).expect("write config");
    }
    let spawn = |args: &[&str]| -> PtyHarness {
        PtyHarness::spawn_with_content(&binary, DEFAULT_ROWS, DEFAULT_COLS, cluster.content(), args).expect("spawn")
    };

    let mut a = match launch {
        Launch::DefaultLeaderById => spawn(&[]),
        _ => cluster.spawn_leader(&[]).expect("spawn pager A"),
    };
    a.wait_for_text(WELCOME_SCREEN_SENTINEL, LEADER_TIMEOUT).expect("A welcome");
    a.inject_keys(format!("{PROMPT}\r").as_bytes()).expect("A submit turn 1");
    a.wait_for_text(&turn_sentinel(1), STREAM_TIMEOUT).expect("A turn 1");
    // The owner enters plan mode.
    a.inject_keys(b"\x1b[Z").expect("A BackTab");
    a.wait_for_text("Switched to mode: Plan", Duration::from_secs(20)).expect("A -> plan");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !plan_mode_files(&home).iter().any(|(_, s)| s.contains("Pending")) && Instant::now() < deadline {
        a.update(Duration::from_millis(200));
    }
    let before = plan_mode_files(&home);
    assert_eq!(before.len(), 1, "one session: {before:?}");
    assert!(before[0].1.contains("\"Pending\""), "owner plan mode persisted: {before:?}");
    let sid = before[0].0.parent().unwrap().file_name().unwrap().to_str().unwrap().to_string();

    // C opens the same session (non-owner) and cycles Shift+Tab: Plan, Auto (leaves plan on C's side), Always-Approve.
    let mut c = match launch {
        Launch::ClusterMostRecent => cluster.attach(&[]).expect("spawn pager C"),
        Launch::ClusterById => cluster.attach(&[sid.as_str()]).expect("spawn pager C"),
        Launch::DefaultLeaderById => spawn(&["--resume", sid.as_str()]),
    };
    c.wait_for_text(&turn_sentinel(1), LEADER_TIMEOUT).expect("C replayed A's transcript");
    c.update(Duration::from_secs(2));
    assert_eq!(plan_mode_files(&home), before, "opening the session as a non-owner changed plan_mode.json");
    for press in 1..=3 {
        c.inject_keys(b"\x1b[Z").expect("C BackTab");
        c.update(Duration::from_secs(3));
        let now = plan_mode_files(&home);
        assert_eq!(now, before, "a non-owner Shift+Tab #{press} changed plan_mode.json\nC screen:\n{}", c.screen_contents());
    }
    assert!(a.is_running().expect("A alive"), "A exited\n{}", a.screen_contents());
    c.quit().expect("quit C");
    a.quit().expect("quit A");
}

/// 1.0.30 P30-LEADER (r8): a window that does not own a shared session (it opened the session with `--resume` while the
/// owner is live) cannot change the session's plan mode, on the agent or in `plan_mode.json`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "PTY e2e; run with cargo test -p fuigo-pager --test leader_pty_e2e -- --ignored --test-threads=1"]
async fn leader_non_owner_shift_tab_cannot_change_plan_mode() {
    non_owner_cannot_change_plan_mode(Launch::ClusterMostRecent).await;
}

/// As above, C naming the session: `--resume <id>`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "PTY e2e; run with cargo test -p fuigo-pager --test leader_pty_e2e -- --ignored --test-threads=1"]
async fn leader_non_owner_shift_tab_by_id_cannot_change_plan_mode() {
    non_owner_cannot_change_plan_mode(Launch::ClusterById).await;
}

/// As above with no leader flags: both windows find the default shared leader (`[cli] use_leader = true`), as a user does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "PTY e2e; run with cargo test -p fuigo-pager --test leader_pty_e2e -- --ignored --test-threads=1"]
async fn leader_default_non_owner_shift_tab_cannot_change_plan_mode() {
    non_owner_cannot_change_plan_mode(Launch::DefaultLeaderById).await;
}
