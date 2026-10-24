//! 1.0.32 HOOKS-COMPAT: plugin hooks written for other hosts must run, and a hook that cannot run must not spam the transcript.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::config::{HookProvenance, HookSpec, parse_hook_file};
use crate::discovery::HookRegistry;
use crate::dispatcher::dispatch_non_blocking;
use crate::event::{HookEventEnvelope, HookEventName, HookPayload};
use crate::result::HookRunResult;
use crate::runner::command::run_command_hook;
use crate::runner::{GateKind, HookRunnerResult, RunContext};

fn envelope(session: &str) -> HookEventEnvelope {
    HookEventEnvelope {
        hook_event_name: HookEventName::SessionStart,
        session_id: session.into(),
        cwd: "/tmp".into(),
        workspace_root: "/tmp".into(),
        timestamp: "2026-01-01T00:00:00Z".into(),
        transcript_path: None,
        client_identifier: None,
        prompt_id: None,
        permission_mode: None,
        payload: HookPayload::SessionStart {
            source: "new".into(),
            model_id: None,
            agent_type: None,
        },
    }
}

fn ctx(session: &str) -> RunContext<'_> {
    RunContext {
        session_id: session,
        workspace_root: "/tmp",
        process_scope: None,
    }
}

/// One plugin hook parsed from a `hooks.json` at `<root>/hooks/hooks.json`, stamped like the plugin adapter does.
fn plugin_spec(root: &Path, handler: serde_json::Value) -> HookSpec {
    plugin_spec_for(root, "SessionStart", handler)
}

fn plugin_spec_for(root: &Path, event_key: &str, handler: serde_json::Value) -> HookSpec {
    let json = serde_json::json!({"hooks": {event_key: [{"hooks": [handler]}]}});
    let hooks_dir = root.join("hooks");
    std::fs::create_dir_all(&hooks_dir).unwrap();
    let (mut specs, errors) = parse_hook_file(&json.to_string(), &hooks_dir.join("hooks.json"));
    assert!(errors.is_empty(), "{errors:?}");
    let mut spec = specs.remove(0);
    spec.layer = HookProvenance::Plugin;
    spec.name = format!("plugin/compat/{}", spec.name);
    let root = root.display().to_string();
    for key in ["CLAUDE_PLUGIN_ROOT", "FUIGO_PLUGIN_ROOT"] {
        spec.extra_env.insert(key.into(), root.clone());
    }
    spec
}

fn write_exec(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn registry(specs: Vec<HookSpec>) -> HookRegistry {
    let (mut registry, _) = crate::discovery::load_hooks(None, None);
    registry.append_specs(specs);
    registry
}

fn path_with(dir: &Path) -> String {
    format!("{}:/usr/bin:/bin", dir.display())
}

/// The runner result of one hook, with a real child process.
async fn run(spec: &HookSpec) -> HookRunnerResult {
    run_command_hook(spec, &envelope("compat-run"), &ctx("compat-run"), GateKind::Observe)
        .await
        .0
}

#[tokio::test]
async fn bash_hook_using_its_own_vars_runs_and_sees_plugin_root_expanded() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker");
    // `_V` is a loop variable and `_G` is assigned in a `case`: the script defines both itself. `${CLAUDE_PLUGIN_ROOT}` is ours.
    let command = format!(
        "for _V in one two; do _G=${{_V}}-x; done; printf '%s %s' \"${{_G}}\" \"${{CLAUDE_PLUGIN_ROOT}}\" > {}",
        marker.display()
    );
    let spec = plugin_spec(
        dir.path(),
        serde_json::json!({"type": "command", "shell": "bash", "command": command}),
    );
    let result = run(&spec).await;
    assert!(matches!(result, HookRunnerResult::Success), "got {result:?}");
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        format!("two-x {}", dir.path().display())
    );
}

#[tokio::test]
async fn command_with_args_runs_a_binary_from_path_with_expanded_args() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let out = dir.path().join("out");
    write_exec(
        &bin.join("compat-node"),
        &format!("printf '%s|' \"$@\" > {}", out.display()),
    );
    let mut spec = plugin_spec(
        dir.path(),
        serde_json::json!({
            "type": "command",
            "command": "compat-node",
            "args": ["${CLAUDE_PLUGIN_ROOT}/scripts/start.mjs", "literal ${NOT_OURS}"]
        }),
    );
    spec.extra_env.insert("PATH".into(), path_with(&bin));
    let result = run(&spec).await;
    assert!(matches!(result, HookRunnerResult::Success), "got {result:?}");
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        format!("{}/scripts/start.mjs|literal ${{NOT_OURS}}|", dir.path().display())
    );
}

#[tokio::test]
async fn dot_slash_command_resolves_against_the_plugin_root_not_the_hooks_dir() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("ran");
    write_exec(&dir.path().join("x.sh"), &format!("echo yes > {}", out.display()));
    let spec = plugin_spec(dir.path(), serde_json::json!({"type": "command", "command": "./x.sh"}));
    let result = run(&spec).await;
    assert!(matches!(result, HookRunnerResult::Success), "got {result:?}");
    assert_eq!(std::fs::read_to_string(&out).unwrap().trim(), "yes");
}

#[tokio::test]
async fn a_config_failure_is_reported_once_per_session_across_many_calls() {
    let dir = tempfile::tempdir().unwrap();
    let spec = plugin_spec(
        dir.path(),
        serde_json::json!({"type": "command", "command": "compat-no-such-binary-xyz", "args": ["a"]}),
    );
    let registry = registry(vec![spec]);
    let session = "compat-once-per-session";
    let (mut failed, mut skipped) = (0, 0);
    for _ in 0..6 {
        let results = dispatch_non_blocking(
            &registry,
            HookEventName::SessionStart,
            &envelope(session),
            &ctx(session),
        )
        .await;
        for r in &results {
            match r {
                HookRunResult::Failed { .. } => failed += 1,
                HookRunResult::Skipped { .. } => skipped += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
    }
    assert_eq!((failed, skipped), (1, 5), "one notice, then silently skipped");
}

#[tokio::test]
async fn a_runtime_failure_keeps_running_and_is_never_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let spec = plugin_spec(dir.path(), serde_json::json!({"type": "command", "command": "exit 3"}));
    let registry = registry(vec![spec]);
    let session = "compat-runtime";
    for _ in 0..3 {
        let results = dispatch_non_blocking(
            &registry,
            HookEventName::SessionStart,
            &envelope(session),
            &ctx(session),
        )
        .await;
        assert!(matches!(results[0], HookRunResult::Failed { .. }), "{results:?}");
    }
}

fn pre_tool_use_envelope(session: &str) -> HookEventEnvelope {
    HookEventEnvelope {
        hook_event_name: HookEventName::PreToolUse,
        payload: HookPayload::PreToolUse {
            tool_name: "run_terminal_cmd".into(),
            tool_use_id: "tu-1".into(),
            tool_input: serde_json::json!({"command": "ls"}),
            tool_input_truncated: false,
            subagent_type: None,
            origin: None,
            peer_influenced: None,
        },
        ..envelope(session)
    }
}

#[tokio::test]
async fn a_blocking_denial_stays_visible_and_is_never_silenced_by_a_config_failure_next_to_it() {
    let dir = tempfile::tempdir().unwrap();
    let broken = plugin_spec_for(
        dir.path(),
        "PreToolUse",
        serde_json::json!({"type": "command", "command": "compat-no-such-binary-xyz", "args": []}),
    );
    let mut denier = plugin_spec_for(
        dir.path(),
        "PreToolUse",
        serde_json::json!({"type": "command", "command": "echo nope >&2; exit 2"}),
    );
    denier.name = "plugin/compat/denier".into();
    let registry = registry(vec![broken, denier]);
    let session = "compat-denial";
    for round in 0..3 {
        let result = crate::dispatcher::dispatch_pre_tool_use(
            &registry,
            &pre_tool_use_envelope(session),
            &ctx(session),
        )
        .await;
        assert!(
            matches!(result.decision, crate::result::HookDecision::Deny { .. }),
            "round {round}: the denial still blocks: {:?}",
            result.decision
        );
        let blocked = result.results.iter().filter(|r| matches!(r, HookRunResult::Blocked { .. })).count();
        let failed = result.results.iter().filter(|r| matches!(r, HookRunResult::Failed { .. })).count();
        let skipped = result.results.iter().filter(|r| matches!(r, HookRunResult::Skipped { .. })).count();
        assert_eq!(blocked, 1, "round {round}: the denial is reported (inline) every time");
        assert_eq!((failed, skipped), if round == 0 { (1, 0) } else { (0, 1) }, "round {round}");
    }
    assert!(
        crate::health::runtime_failure_for(session, "plugin/compat/denier").is_none(),
        "a denial is a successful run, not a failure"
    );
}

#[tokio::test]
async fn startup_validation_finds_config_failures_once_and_the_first_prompt_is_already_quiet() {
    let dir = tempfile::tempdir().unwrap();
    let broken_exec = plugin_spec(
        dir.path(),
        serde_json::json!({"type": "command", "command": "compat-no-such-binary-xyz", "args": ["a"]}),
    );
    let mut broken_placeholder = plugin_spec(
        dir.path(),
        serde_json::json!({"type": "command", "command": "echo ${CLAUDE_PLUGIN_DATA}"}),
    );
    broken_placeholder.extra_env.remove("CLAUDE_PLUGIN_ROOT");
    broken_placeholder.name = "plugin/other/data".into();
    let mut fine = plugin_spec(
        dir.path(),
        serde_json::json!({"type": "command", "shell": "bash", "command": "for _V in a; do echo \"${_V}\" > /dev/null; done"}),
    );
    fine.name = "plugin/compat/fine".into();
    let registry = registry(vec![broken_exec, broken_placeholder, fine]);
    let session = "compat-startup";

    let problems = crate::health::validate_registry(&registry, "/tmp", session);
    assert_eq!(problems.len(), 2, "{problems:?}");
    let notice = crate::health::grouped_notice(&problems).unwrap();
    assert!(notice.starts_with("2 plugin hooks can't run: "), "{notice}");
    assert!(notice.contains("compat (compat-no-such-binary-xyz not found)"), "{notice}");
    assert!(notice.contains("other (needs CLAUDE_PLUGIN_DATA)"), "{notice}");
    assert!(notice.ends_with(". /hooks for details."), "{notice}");

    assert!(
        crate::health::validate_registry(&registry, "/tmp", session).is_empty(),
        "already known: no second notice"
    );
    let results = dispatch_non_blocking(&registry, HookEventName::SessionStart, &envelope(session), &ctx(session)).await;
    let failed = results.iter().filter(|r| matches!(r, HookRunResult::Failed { .. })).count();
    let skipped = results.iter().filter(|r| matches!(r, HookRunResult::Skipped { .. })).count();
    let ok = results.iter().filter(|r| matches!(r, HookRunResult::Success { .. })).count();
    assert_eq!((failed, skipped, ok), (0, 2, 1), "nothing fails loudly on the first prompt: {results:?}");
}

#[tokio::test]
async fn a_known_placeholder_that_is_not_set_in_args_is_a_config_failure_naming_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut spec = plugin_spec(
        dir.path(),
        serde_json::json!({"type": "command", "command": "/bin/echo", "args": ["${CLAUDE_PLUGIN_DATA}/x"]}),
    );
    spec.extra_env.remove("CLAUDE_PLUGIN_DATA");
    match run(&spec).await {
        HookRunnerResult::Failed(error) => {
            assert!(crate::health::is_config_failure(&error), "{error}");
            assert!(error.contains("CLAUDE_PLUGIN_DATA"), "{error}");
        }
        other => panic!("expected a config failure, got {other:?}"),
    }
}

#[tokio::test]
async fn a_runtime_failure_is_listed_as_failing_with_its_last_error_until_a_good_run() {
    let dir = tempfile::tempdir().unwrap();
    let spec = plugin_spec(dir.path(), serde_json::json!({"type": "command", "command": "echo broke >&2; exit 3"}));
    let registry = registry(vec![spec.clone()]);
    let session = "compat-failing";
    let disabled = crate::trust::DisabledHooks::from_names([]);
    let before = crate::health::diagnose(&spec, session, "/tmp", &disabled);
    assert_eq!(before.state, crate::health::DiagState::Ok);

    dispatch_non_blocking(&registry, HookEventName::SessionStart, &envelope(session), &ctx(session)).await;
    let after = crate::health::diagnose(&spec, session, "/tmp", &disabled);
    assert_eq!(after.state, crate::health::DiagState::Failing);
    assert!(after.reason.as_deref().unwrap_or_default().contains("broke"), "{after:?}");
    assert!(after.fix_hint.is_some());
    assert_eq!(after.source, "compat");
}

#[tokio::test]
async fn a_bare_script_beside_a_users_own_hook_file_still_runs() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("ran");
    write_exec(&dir.path().join("mine.sh"), &format!("echo yes > {}", out.display()));
    let json = serde_json::json!({"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "mine.sh"}]}]}});
    let (mut specs, errors) = parse_hook_file(&json.to_string(), &dir.path().join("hooks.json"));
    assert!(errors.is_empty());
    let spec = specs.remove(0);
    assert!(matches!(run(&spec).await, HookRunnerResult::Success));
    assert_eq!(std::fs::read_to_string(&out).unwrap().trim(), "yes");
}

#[test]
fn args_survive_a_serde_round_trip_so_a_remote_workspace_runs_the_same_command() {
    let dir = tempfile::tempdir().unwrap();
    let spec = plugin_spec(
        dir.path(),
        serde_json::json!({"type": "command", "command": "node", "args": ["${CLAUDE_PLUGIN_ROOT}/a.mjs", "--x"]}),
    );
    assert_eq!(spec.args.as_deref(), Some(&["${CLAUDE_PLUGIN_ROOT}/a.mjs".to_string(), "--x".to_string()][..]));
    let back: HookSpec = serde_json::from_value(serde_json::to_value(&spec).unwrap()).unwrap();
    assert_eq!(back.args, spec.args);
    let shell = plugin_spec(dir.path(), serde_json::json!({"type": "command", "command": "echo hi"}));
    assert!(serde_json::to_value(&shell).unwrap().get("args").is_none(), "the shell form adds nothing to the wire");
}

// ---- HOOKS-COMPAT-B: the hook's "shell" field ----

/// Runs a hook whose command prints `$0` (the shell's own name) into a file, and returns what it printed.
async fn shell_zero(handler_shell: Option<&str>) -> String {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("zero");
    let mut handler = serde_json::json!({"type": "command", "command": format!("printf '%s' \"$0\" > {}", out.display())});
    if let Some(shell) = handler_shell {
        handler["shell"] = shell.into();
    }
    let spec = plugin_spec(dir.path(), handler);
    let result = run(&spec).await;
    assert!(matches!(result, HookRunnerResult::Success), "got {result:?}");
    std::fs::read_to_string(&out).unwrap()
}

#[tokio::test]
async fn shell_bash_runs_the_command_in_bash_and_an_absent_field_keeps_sh() {
    let with_bash = shell_zero(Some("bash")).await;
    assert!(with_bash.ends_with("bash"), "shell:bash must run in bash, ran in {with_bash:?}");
    assert_eq!(shell_zero(None).await, "sh", "no field keeps the existing `sh -c`");
}

#[tokio::test]
async fn a_bash_only_construct_runs_with_shell_bash() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    // An array and `[[ ]]` are bash syntax; dash (the `sh` on Debian/Ubuntu) rejects the first line outright.
    let command = format!(
        "arr=(a b c); if [[ ${{#arr[@]}} -eq 3 && $BASH_VERSION != '' ]]; then printf yes > {}; fi",
        out.display()
    );
    let spec = plugin_spec(dir.path(), serde_json::json!({"type": "command", "shell": "bash", "command": command}));
    let result = run(&spec).await;
    assert!(matches!(result, HookRunnerResult::Success), "got {result:?}");
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "yes");
}

#[tokio::test]
async fn a_missing_shell_is_a_config_failure_with_a_hint_and_never_a_silent_sh() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let mut spec = plugin_spec(
        dir.path(),
        serde_json::json!({"type": "command", "shell": "bash", "command": format!("echo ran > {}", out.display())}),
    );
    spec.extra_env.insert("PATH".into(), String::new());
    let HookRunnerResult::Failed(error) = run(&spec).await else {
        panic!("a missing bash must fail the hook");
    };
    assert!(crate::health::is_config_failure(&error), "must be a CONFIG failure, got {error:?}");
    assert!(error.contains("bash not found"), "{error:?}");
    assert!(!out.exists(), "the command must not have run under a fallback shell");
    assert_eq!(crate::health::short_reason(crate::health::config_failure_detail(&error)), "bash not found");
}

#[tokio::test]
async fn a_shell_that_is_not_a_plain_name_is_a_config_failure() {
    for bad in ["/bin/bash", "my shell", "bash;id", "", "-c", "../bash", "bash\nx"] {
        let dir = tempfile::tempdir().unwrap();
        let spec = plugin_spec(dir.path(), serde_json::json!({"type": "command", "shell": bad, "command": "echo $HOME"}));
        let HookRunnerResult::Failed(error) = run(&spec).await else {
            panic!("shell {bad:?} must be refused");
        };
        assert!(crate::health::is_config_failure(&error), "{bad:?}: {error:?}");
        assert!(error.contains("unsupported \"shell\""), "{bad:?}: {error:?}");
    }
}

#[test]
fn shell_survives_a_serde_round_trip_and_is_absent_when_unset() {
    let dir = tempfile::tempdir().unwrap();
    let spec = plugin_spec(dir.path(), serde_json::json!({"type": "command", "shell": "bash", "command": "echo $A"}));
    let value = serde_json::to_value(&spec).unwrap();
    assert_eq!(value.get("shell").and_then(|v| v.as_str()), Some("bash"));
    let back: HookSpec = serde_json::from_value(value).unwrap();
    assert_eq!(serde_json::to_value(&back).unwrap().get("shell").and_then(|v| v.as_str()), Some("bash"));
    let plain = plugin_spec(dir.path(), serde_json::json!({"type": "command", "command": "echo $A"}));
    assert!(serde_json::to_value(&plain).unwrap().get("shell").is_none());
}

/// The real claude-mem 13.28.0 `hooks/hooks.json` (copied verbatim), every hook of it, with the plugin's scripts and `node` stubbed.
#[tokio::test]
async fn the_real_claude_mem_hooks_run_end_to_end_in_bash() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!("hooks_compat_fixtures/claude-mem-13.28.0-hooks.json")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let scripts = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join("bun-runner.js"), "").unwrap();
    std::fs::write(scripts.join("worker-service.cjs"), "").unwrap();
    // The hook puts `$HOME/.nvm/versions/node/v<newest>/bin` first on PATH, ahead of any real node on the machine, so the stub goes there.
    let bin = dir.path().join(".nvm/versions/node/v99.0.0/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = dir.path().join("node.log");
    write_exec(&bin.join("node"), &format!("printf '%s\\n' \"$*\" >> {}", log.display()));
    let mut ran = 0;
    for (event, groups) in fixture["hooks"].as_object().unwrap() {
        // Fuigo has no `Setup` event, so the plugin's Setup hook is not loaded (as before this packet).
        if event == "Setup" {
            continue;
        }
        for group in groups.as_array().unwrap() {
            for handler in group["hooks"].as_array().unwrap() {
                assert_eq!(handler["shell"], "bash", "the fixture is the bash-shell plugin");
                // `$HOME` and `$PATH` in a command are expanded when the hook file is loaded, so the hook's own `env` supplies them there.
                let mut handler = handler.clone();
                handler["env"] = serde_json::json!({"PATH": "/usr/bin:/bin", "HOME": dir.path().display().to_string()});
                let spec = plugin_spec_for(dir.path(), event, handler);
                let result = run(&spec).await;
                assert!(matches!(result, HookRunnerResult::Success), "{event}: got {result:?}");
                ran += 1;
            }
        }
    }
    assert_eq!(ran, 7);
    let calls = std::fs::read_to_string(&log).unwrap();
    assert_eq!(calls.lines().count(), 7, "every hook reached its node worker: {calls}");
    let want = format!("{0}/scripts/bun-runner.js {0}/scripts/worker-service.cjs ", dir.path().display());
    assert!(calls.lines().all(|l| l.starts_with(&want)), "{calls}");
}

#[allow(dead_code)]
fn _unused(_: HashMap<String, String>, _: PathBuf) {}
