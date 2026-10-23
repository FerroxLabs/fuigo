//! 1.0.32 HOOKS-COMPAT: the real `hooks.json` files of two installed plugins (claude-mem 13.28.0 and stripe 0.10.3),
//! copied under `tests/fixtures/hooks_compat/` with their scripts stubbed, must load and run through the plugin adapter.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use fuigo_hooks::config::HookSpec;
use fuigo_hooks::event::{HookEventEnvelope, HookEventName, HookPayload};
use fuigo_hooks::runner::command::run_command_hook;
use fuigo_hooks::runner::{GateKind, HookRunnerResult, RunContext};

use super::hooks_adapter::parse_plugin_hooks;

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hooks_compat").join(name)
}

/// A stub `node` that records its arguments, one invocation per line.
fn stub_node(bin: &Path, log: &Path) {
    std::fs::create_dir_all(bin).unwrap();
    let node = bin.join("node");
    std::fs::write(&node, format!("#!/bin/sh\necho \"$@\" >> {}\n", log.display())).unwrap();
    std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn envelope() -> HookEventEnvelope {
    HookEventEnvelope {
        hook_event_name: HookEventName::SessionStart,
        session_id: "fixture-session".into(),
        cwd: "/tmp".into(),
        workspace_root: "/tmp".into(),
        timestamp: "2026-01-01T00:00:00Z".into(),
        transcript_path: None,
        client_identifier: None,
        prompt_id: None,
        permission_mode: None,
        payload: HookPayload::SessionStart { source: "new".into(), model_id: None, agent_type: None },
    }
}

/// Parse the fixture plugin rooted at `root` and run every hook it declares, returning (hook name, outcome) pairs.
fn run_plugin_hooks(name: &str, root: &Path, extra_env: &[(&str, String)]) -> Vec<(String, String)> {
    let (specs, warnings) = parse_plugin_hooks(
        &root.join("hooks/hooks.json"),
        name,
        &root.display().to_string(),
        &root.join("data").display().to_string(),
    );
    assert!(!specs.is_empty(), "fixture {name} yielded no hooks: {warnings:?}");
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let mut outcomes = Vec::new();
    for mut spec in specs {
        for (k, v) in extra_env {
            spec.extra_env.insert((*k).into(), v.clone());
        }
        let ctx = RunContext { session_id: "fixture-session", workspace_root: "/tmp", process_scope: None };
        let result = rt.block_on(run_command_hook(&spec, &envelope(), &ctx, GateKind::Observe)).0;
        let verdict = match &result {
            HookRunnerResult::Failed(e) => format!("FAILED: {e}"),
            _ => "ok".to_string(),
        };
        outcomes.push((spec.name.clone(), verdict));
    }
    outcomes
}

fn invocations(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log).unwrap_or_default().lines().map(str::to_string).collect()
}

#[test]
fn claude_mem_13_28_0_hooks_json_runs_instead_of_refusing_its_own_shell_variables() {
    const NAME: &str = "plugins::hooks_compat_fixture_tests::claude_mem_13_28_0_hooks_json_runs_instead_of_refusing_its_own_shell_variables";
    if let Ok(root) = std::env::var("HOOKS_COMPAT_ROOT") {
        // Child process: its HOME and PATH are the parent's stub ones, which the adapter bakes into the command at load time.
        for (name, verdict) in run_plugin_hooks("claude-mem", Path::new(&root), &[]) {
            assert_eq!(verdict, "ok", "{name}");
        }
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("claude-mem");
    copy_tree(&fixture("claude-mem"), &root);
    let log = tmp.path().join("node.log");
    let bin = tmp.path().join("bin");
    stub_node(&bin, &log);
    // claude-mem puts `$HOME/.nvm/versions/node/v<latest>/bin` first on PATH, ahead of any real node on the host:
    // a home whose newest nvm node is the stub makes the run hermetic.
    let home = tmp.path().join("home");
    stub_node(&home.join(".nvm/versions/node/v20.0.0/bin"), &log);
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([NAME, "--exact", "--test-threads=1", "--nocapture"])
        .env("HOOKS_COMPAT_ROOT", &root)
        .env("HOME", &home)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "child run failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let calls = invocations(&log);
    let runner = format!("{}/scripts/bun-runner.js", root.display());
    assert!(
        calls.iter().any(|c| c.starts_with(&runner) && c.contains("worker-service.cjs")),
        "expected the bun-runner invocation under the plugin root, got {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c.contains("session-init")),
        "the user_prompt_submit hook reached its node call, got {calls:?}"
    );
}

#[test]
fn stripe_0_10_3_hooks_json_runs_node_from_path_with_the_expanded_script() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("stripe");
    copy_tree(&fixture("stripe"), &root);
    let log = tmp.path().join("node.log");
    let bin = tmp.path().join("bin");
    stub_node(&bin, &log);
    let path = format!("{}:/usr/bin:/bin", bin.display());
    for (name, verdict) in run_plugin_hooks("stripe", &root, &[("PATH", path)]) {
        assert_eq!(verdict, "ok", "{name}");
    }
    let calls = invocations(&log);
    let session_start = format!("{}/scripts/lifecycle/sessionStart.mjs", root.display());
    assert!(calls.contains(&session_start), "expected {session_start} in {calls:?}");
}

#[allow(dead_code)]
fn _assert_spec_is_used(_: HookSpec) {}
