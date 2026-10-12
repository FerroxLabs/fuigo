//! P189 packet C: real-cgroup placement through the local terminal backend.
//! Skips (prints `P189-CGROUP-SKIP`) when no usable cgroup2; a skip is a
//! failure under `FUIGO_TEST_REQUIRE_CGROUP=1`. Membership is read from
//! `/proc/<pid>/cgroup` (tests only). Tests create cgroups only under this
//! process's own cgroup (`fuigo-park-*`, via the module) and remove them.
#![allow(clippy::print_stdout)]

use super::terminal::*;
use crate::computer::types::*;
use crate::notification::types::ToolNotificationHandle;
use crate::util::ProcessScope;
use crate::util::session_cgroup::{ParkHost, ProbeEnv, probe_with};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn host(name: &str) -> Option<ParkHost> {
    match probe_with(&ProbeEnv::system()) {
        Ok(h) => {
            println!("P189-CGROUP-RAN {name}");
            Some(h)
        }
        Err(r) => {
            println!("P189-CGROUP-SKIP {r} ({name})");
            assert!(
                std::env::var("FUIGO_TEST_REQUIRE_CGROUP").as_deref() != Ok("1"),
                "cgroup required but unavailable: {r}"
            );
            None
        }
    }
}

fn want(scope: &ProcessScope) -> String {
    scope
        .session_cgroup()
        .unwrap()
        .dir()
        .strip_prefix("/sys/fs/cgroup")
        .unwrap()
        .to_string_lossy()
        .to_string()
}

fn cgroup_of(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default()
}

fn read_pid(f: &Path) -> u32 {
    for _ in 0..400 {
        if let Ok(s) = std::fs::read_to_string(f)
            && let Ok(p) = s.trim().parse()
        {
            return p;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("no pid file {f:?}");
}

fn request(command: &str) -> TerminalRunRequest {
    let output_file = std::env::temp_dir().join(format!(
        "p189c-{}-{}.out",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    TerminalRunRequest {
        command: command.to_string(),
        working_directory: PathBuf::from("/tmp"),
        env: Default::default(),
        timeout: Duration::from_secs(30),
        output_byte_limit: 10000,
        output_file,
        notification_handle: ToolNotificationHandle::noop(),
        tool_call_id: "p189c".to_string(),
        display_command: None,
        auto_background_on_timeout: false,
        foreground_block_budget: None,
        kind: TaskKind::Bash,
        owner_session_id: None,
        description: None,
    }
}

fn backends(scope: &ProcessScope) -> Vec<(&'static str, LocalTerminalBackend)> {
    let shadows = super::SearchShadowConfig::default;
    vec![
        ("static", LocalTerminalBackend::new_local_with_login_shell_capture(shadows(), true, None, Some(scope.clone()))),
        ("plain", LocalTerminalBackend::new_local_with_login_shell_capture(shadows(), false, None, Some(scope.clone()))),
        ("persistent", LocalTerminalBackend::new_local_with_persistent_shell(shadows(), None, Some(scope.clone()))),
    ]
}

fn run_local<F: std::future::Future>(f: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&rt, f)
}

#[test]
fn real_foreground_background_and_setsid_grandchild_are_in_the_session_cgroup() {
    let Some(host) = host("terminal-placement") else { return };
    let scope = ProcessScope::with_session_cgroup(host.create_session().unwrap());
    let want = want(&scope);
    let tmp = tempfile::tempdir().unwrap();
    run_local(async {
        for (name, backend) in backends(&scope) {
            let d = tmp.path().join(name);
            std::fs::create_dir_all(&d).unwrap();
            let (fg, bg, gc) = (d.join("fg"), d.join("bg"), d.join("gc"));
            let r = backend.run(request(&format!("echo $$ > {}", fg.display()))).await.unwrap();
            assert_eq!(r.exit_code, Some(0), "{name}");
            let mut req = request(&format!(
                "echo $$ > {}; setsid sh -c 'echo $$ > {}; sleep 60' & sleep 60",
                bg.display(),
                gc.display()
            ));
            req.tool_call_id = format!("bg-{name}");
            let handle = backend.run_background(req).await.unwrap();
            let (bgp, gcp) = (read_pid(&bg), read_pid(&gc));
            for pid in [bgp, gcp] {
                assert!(cgroup_of(pid).contains(&want), "{name}: {pid} not placed: {}", cgroup_of(pid));
            }
            let _ = handle;
        }
    });
    // Test cleanup: this test created the cgroup.
    std::fs::write(scope.session_cgroup().unwrap().dir().join("cgroup.kill"), "1").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    scope.release_session_cgroup();
}

#[test]
fn real_foreground_command_runs_inside_the_cgroup() {
    // The foreground shell exits before it can be inspected from outside, so it
    // reports its own membership.
    let Some(host) = host("terminal-foreground-self") else { return };
    let scope = ProcessScope::with_session_cgroup(host.create_session().unwrap());
    let want = want(&scope);
    run_local(async {
        for (name, backend) in backends(&scope) {
            let r = backend.run(request("cat /proc/self/cgroup")).await.unwrap();
            assert!(r.combined_output.contains(&want), "{name}: foreground not in session cgroup: {}", r.combined_output);
        }
    });
    scope.release_session_cgroup();
}

#[test]
fn real_subagent_clone_lands_in_root_cgroup_and_two_sessions_differ() {
    let Some(host) = host("terminal-subagent-two") else { return };
    let root = ProcessScope::with_session_cgroup(host.create_session().unwrap());
    let other = ProcessScope::with_session_cgroup(host.create_session().unwrap());
    let (w_root, w_other) = (want(&root), want(&other));
    assert_ne!(w_root, w_other);
    let subagent_scope = root.clone();
    run_local(async {
        let shadows = super::SearchShadowConfig::default;
        let sub = LocalTerminalBackend::new_local_with_login_shell_capture(shadows(), false, None, Some(subagent_scope));
        let o = LocalTerminalBackend::new_local_with_login_shell_capture(shadows(), false, None, Some(other.clone()));
        let r = sub.run(request("cat /proc/self/cgroup")).await.unwrap();
        assert!(r.combined_output.contains(&w_root));
        let r = o.run(request("cat /proc/self/cgroup")).await.unwrap();
        assert!(r.combined_output.contains(&w_other));
    });
    root.release_session_cgroup();
    other.release_session_cgroup();
}

#[test]
fn real_session_end_keeps_nohup_alive_and_directory_then_empty_dir_is_removed() {
    let Some(host) = host("terminal-session-end") else { return };
    let scope = ProcessScope::with_session_cgroup(host.create_session().unwrap());
    let dir = scope.session_cgroup().unwrap().dir().to_path_buf();
    let tmp = tempfile::tempdir().unwrap();
    let nh = tmp.path().join("nh");
    run_local(async {
        let backend = LocalTerminalBackend::new_local_with_login_shell_capture(
            super::SearchShadowConfig::default(),
            false,
            None,
            Some(scope.clone()),
        );
        let r = backend
            .run(request(&format!("nohup setsid sh -c 'echo $$ > {}; sleep 60' >/dev/null 2>&1 &", nh.display())))
            .await
            .unwrap();
        assert_eq!(r.exit_code, Some(0));
    });
    let pid = read_pid(&nh);
    scope.kill_all(); // what take_session does first
    scope.release_session_cgroup();
    assert!(Path::new(&format!("/proc/{pid}")).exists(), "session end must not kill a nohup server");
    assert!(dir.exists(), "populated cgroup directory must stay");
    std::fs::write(dir.join("cgroup.kill"), "1").unwrap();
    for _ in 0..200 {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    scope.release_session_cgroup();
    assert!(!dir.exists(), "an empty cgroup directory is removed");
}

#[test]
fn memory_cgroup_yields_only_when_both_apply() {
    assert!(memory_cgroup_yields(true, true));
    assert!(!memory_cgroup_yields(true, false));
    assert!(!memory_cgroup_yields(false, true));
    assert!(!memory_cgroup_yields(false, false));
}
