//! u35 (Fuigo 1.0.35): `session/set_mode` accepts only Fuigo's own mode ids and advertises the live mode (A1); agent
//! files from a repo load only from a trusted folder, never under a built-in name, and only by a plain name (A2).
//!
//! Trust tests run in their own process (`rerun_in_own_process`) with a private `FUIGO_HOME`, a release-stamped build
//! (so the folder-trust gate engages) and the production hook installed first: "not loaded" then means the installed
//! hook denied the folder, not that no hook was installed.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use acp::Agent as _;
use agent_client_protocol as acp;
use fuigo_test_support::EnvGuard;
use serde_json::json;

use super::{MvpAgentHandle, build_minimal_agent_for_tests, make_test_handle};
use crate::session::SessionCommand;
use crate::session::plan_mode::{PlanModeState, PromptMode};

const MARKER: &str = "U35-PWNED-MARKER";

fn marker_agent(name: &str) -> String {
    format!(
        "---\nname: {name}\ndescription: u35 fixture\nuserMessageTemplate:\n  custom: \"{MARKER}\"\n---\n{MARKER} body\n"
    )
}

/// A git-initialised repo (bounds the trust walk) holding `.fuigo/agents/<stem>.md` marker files.
fn repo_with_agents(stems: &[&str]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    git2::Repository::init(tmp.path()).unwrap();
    let agents = tmp.path().join(".fuigo").join("agents");
    std::fs::create_dir_all(&agents).unwrap();
    for stem in stems {
        let path = agents.join(format!("{stem}.md"));
        std::fs::write(&path, marker_agent(stem)).unwrap();
        let def = fuigo_agent::AgentDefinition::from_file(&path).expect("fixture must parse");
        assert!(
            def.prompt_body.as_deref().is_some_and(|b| b.contains(MARKER)),
            "fixture body carries the marker"
        );
    }
    tmp
}

fn has_marker(def: &fuigo_agent::AgentDefinition) -> bool {
    def.prompt_body.as_deref().is_some_and(|b| b.contains(MARKER))
        || format!("{:?}", def.user_message_template).contains(MARKER)
        || format!("{:?}", def.system_prompt).contains(MARKER)
}

/// Process-wide trust setup for a test that already re-ran itself in its own process.
struct TrustEnv {
    _home: fuigo_test_support::FuigoHome,
    _release: EnvGuard,
    _flag: EnvGuard,
}

fn trust_env() -> TrustEnv {
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::create_dir_all(home.path().join("agents")).unwrap();
    crate::agent::folder_trust::install_project_agent_trust();
    TrustEnv {
        _home: home,
        _release: EnvGuard::set(fuigo_version::TEST_VERSION_ENV, "0.0.0-sim"),
        _flag: EnvGuard::unset("FUIGO_FOLDER_TRUST"),
    }
}

fn grant_trust(cwd: &Path) {
    let mut store = fuigo_workspace::trust::TrustStore::load();
    store
        .grant(&fuigo_workspace::trust::workspace_key(cwd))
        .unwrap();
    crate::agent::folder_trust::resolve_and_record(cwd, None, false);
}

fn local_handle(cwd: &Path) -> crate::session::SessionHandle {
    let mut handle = make_test_handle("test-model", false, None);
    handle.tool_context = crate::tools::ToolContext::new_local_context(
        fuigo_paths::AbsPathBuf::new(cwd.to_path_buf()).unwrap(),
        Arc::new(fuigo_workspace::file_system::LocalFs::new(cwd.to_path_buf())),
        Arc::new(crate::terminal::LocalTerminalRunner),
    );
    handle
}

// ── A1: the protocol edge ────────────────────────────────────────────────────────────────────────────────────────────

/// RED at base: an unknown id is sent to the actor and nothing answers, so the timeout fires.
#[tokio::test]
async fn set_session_mode_rejects_unknown_id() {
    let agent = build_minimal_agent_for_tests();
    let sid = acp::SessionId::new("u35-set-mode");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut handle = make_test_handle("grok-3", false, None);
    handle.cmd_tx = tx;
    agent.insert_resident(&sid, handle);
    for id in [
        "explore",
        "codex",
        "evil",
        "PLAN",
        "browser-use",
        "",
        "../.fuigo/agents/evil",
        "/repo/.fuigo/agents/evil",
    ] {
        let request = acp::SetSessionModeRequest::new(sid.clone(), id);
        let result = tokio::time::timeout(Duration::from_secs(5), agent.set_session_mode(request)).await;
        let Ok(Err(err)) = result else {
            panic!("set_mode({id:?}) must be refused at once, got {result:?}");
        };
        assert_eq!(err.code, acp::Error::invalid_params().code, "{id:?}");
        let data = err.data.expect("typed data");
        assert_eq!(data["error_kind"], "invalid_request", "{id:?}");
        assert!(rx.try_recv().is_err(), "set_mode({id:?}) must not reach the session actor");
    }
}

/// The four supported ids still go through to the actor.
#[tokio::test]
async fn set_session_mode_forwards_supported_ids() {
    let agent = build_minimal_agent_for_tests();
    let sid = acp::SessionId::new("u35-set-mode-ok");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut handle = make_test_handle("grok-3", false, None);
    handle.cmd_tx = tx;
    agent.insert_resident(&sid, handle);
    for id in ["default", "plan", "ask", "browser_use"] {
        let request = acp::SetSessionModeRequest::new(sid.clone(), id);
        let (result, seen) = tokio::join!(agent.set_session_mode(request), async {
            match rx.recv().await.unwrap() {
                SessionCommand::SessionMode {
                    session_mode,
                    responds_to,
                } => {
                    let _ = responds_to.send(());
                    session_mode.0.to_string()
                }
                _ => panic!("expected SessionMode"),
            }
        });
        assert!(result.is_ok(), "{id}: {result:?}");
        assert_eq!(seen, id);
    }
}

// ── A1: advertised mode ──────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn advertised_mode_id_table() {
    use crate::session::acp_session::advertised_mode_id;
    let cases = [
        (PlanModeState::Pending, PromptMode::Agent, "plan"),
        (PlanModeState::Active, PromptMode::Agent, "plan"),
        (PlanModeState::Active, PromptMode::Ask, "plan"),
        (PlanModeState::ExitPending, PromptMode::Agent, "default"),
        (PlanModeState::ExitPending, PromptMode::Ask, "ask"),
        (PlanModeState::Inactive, PromptMode::Ask, "ask"),
        (PlanModeState::Inactive, PromptMode::Agent, "default"),
    ];
    for (plan, prompt, want) in cases {
        assert_eq!(advertised_mode_id(plan, prompt, false), want, "{plan:?} + {prompt:?}");
    }
    // u36: plan (Pending/Active) > browser_use > ask > default.
    let browser = [
        (PlanModeState::Pending, PromptMode::Agent, "plan"),
        (PlanModeState::Active, PromptMode::Ask, "plan"),
        (PlanModeState::ExitPending, PromptMode::Agent, "browser_use"),
        (PlanModeState::Inactive, PromptMode::Ask, "browser_use"),
        (PlanModeState::Inactive, PromptMode::Agent, "browser_use"),
    ];
    for (plan, prompt, want) in browser {
        assert_eq!(advertised_mode_id(plan, prompt, true), want, "browser + {plan:?} + {prompt:?}");
    }
}

fn plan_tracker_in(state: PlanModeState) -> crate::session::plan_mode::PlanModeTracker {
    crate::session::plan_mode::PlanModeTracker::from_snapshot(
        std::path::PathBuf::from("/tmp"),
        crate::session::plan_mode::PlanModeSnapshot {
            state,
            was_previously_active: false,
            reminder_count: 0,
            pending_exit_reminder: false,
            awaiting_plan_approval: false,
        },
    )
}

/// A resident session advertises from its live tracker and prompt mode; a cold one from the persisted plan state.
#[tokio::test]
async fn advertised_session_modes_reads_the_live_handle() {
    let agent = build_minimal_agent_for_tests();
    let modes = |sid: &acp::SessionId, persisted| agent.advertised_session_modes(sid, persisted);
    let ids = |m: &acp::SessionModeState| -> Vec<String> {
        m.available_modes.iter().map(|m| m.id.0.to_string()).collect()
    };

    // Cold: no resident handle.
    let cold = acp::SessionId::new("u35-cold");
    let m = modes(&cold, None);
    assert_eq!(m.current_mode_id.0.as_ref(), "default");
    assert_eq!(ids(&m), ["default", "plan", "ask", "browser_use"]);
    assert_eq!(modes(&cold, Some(PlanModeState::Active)).current_mode_id.0.as_ref(), "plan");
    assert_eq!(modes(&cold, Some(PlanModeState::Inactive)).current_mode_id.0.as_ref(), "default");

    let sid = acp::SessionId::new("u35-resident");
    let handle = make_test_handle("grok-3", false, None);
    let prompt = handle.current_prompt_mode.clone();
    let plan = handle.plan_mode.clone();
    agent.insert_resident(&sid, handle);
    assert_eq!(modes(&sid, Some(PlanModeState::Active)).current_mode_id.0.as_ref(), "default", "live beats persisted");
    *prompt.lock() = PromptMode::Ask;
    assert_eq!(modes(&sid, None).current_mode_id.0.as_ref(), "ask");
    *prompt.lock() = PromptMode::Agent; // what set_mode("browser_use") stores
    assert_eq!(modes(&sid, None).current_mode_id.0.as_ref(), "default");
    plan.lock().enter_pending();
    assert_eq!(modes(&sid, None).current_mode_id.0.as_ref(), "plan");
    *plan.lock() = plan_tracker_in(PlanModeState::Active);
    assert_eq!(modes(&sid, None).current_mode_id.0.as_ref(), "plan");
    // Plan switched off mid-turn: ExitPending falls through to the prompt mode.
    plan.lock().user_exit(true);
    assert_eq!(plan.lock().state(), PlanModeState::ExitPending);
    assert_eq!(modes(&sid, None).current_mode_id.0.as_ref(), "default");
}

// ── A2: trust-gated agent discovery, reached through each entry point ────────────────────────────────────────────────

static SWITCHES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Drive a zero-turn model switch from `active` to a model whose `agent_type` is `target`, answering the actor's side.
/// Returns the definition the switch asked the session to rebuild with (`None`: it kept the current harness).
async fn switch_rebuild_definition(
    agent: &MvpAgentHandle,
    cwd: &Path,
    active: &str,
    target: &str,
) -> Option<fuigo_agent::AgentDefinition> {
    use crate::agent::config::{EndpointsConfig, ModelEntry};
    let n = SWITCHES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let model_id = format!("u35-switch-model-{n}");
    let mut entry = ModelEntry::fallback(&model_id, &EndpointsConfig::default());
    entry.info.user_selectable = true;
    entry.info.agent_type = target.to_string();
    entry.info.agent_type_inferred = false;
    agent.models_manager.insert_test_entry(model_id.clone(), entry);
    let sid = acp::SessionId::new(format!("u35-switch-{n}"));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut handle = local_handle(cwd);
    handle.cmd_tx = tx;
    agent.insert_resident(&sid, handle);
    let request = serde_json::from_value::<acp::SetSessionModelRequest>(json!({
        "sessionId": sid.0.as_ref(), "modelId": model_id
    }))
    .unwrap();
    let mut switch = std::pin::pin!(agent.set_session_model(request));
    let mut rebuilt = None;
    loop {
        tokio::select! {
            _ = &mut switch => break,
            Some(cmd) = rx.recv() => match cmd {
                SessionCommand::GetActiveAgent { responds_to } => {
                    let _ = responds_to.send(Some(active.to_string()));
                }
                SessionCommand::RebuildAgentForDefinition { definition, responds_to } => {
                    rebuilt = Some(definition);
                    let _ = responds_to.send(Ok(()));
                }
                SessionCommand::SetSessionModel { sampling_config, responds_to, .. } => {
                    let _ = responds_to.send(Ok(acp::ModelId::new(sampling_config.model.clone())));
                }
                _ => {}
            },
        }
    }
    rebuilt
}

fn resolve_with_fuigo_agent(cwd: &Path, value: &str) -> fuigo_agent::AgentDefinition {
    let _agent_env = EnvGuard::set("FUIGO_AGENT", value);
    super::MvpAgent::resolve_agent_definition(
        cwd,
        None,
        &crate::agent::config::AgentSelectionConfig::default(),
        None,
        None,
    )
}

fn task_context<'a>(
    cwd: &'a Path,
    toggles: &'a std::collections::HashMap<String, bool>,
) -> fuigo_subagent_resolution::DefinitionResolutionContext<'a> {
    fuigo_subagent_resolution::DefinitionResolutionContext {
        cwd,
        plugins: None,
        cli_agents: &[],
        toggles,
        allowed_types: None,
    }
}

/// RED at base. An untrusted folder's agent files reach no entry point: model switch, `FUIGO_AGENT`, Task.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn untrusted_project_agents_reach_no_entry_point() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _trust = trust_env();
    let repo = repo_with_agents(&["explore", "codex", "fuigo-build-plan", "custom", "ask", "default"]);
    let cwd = repo.path();
    assert!(
        !crate::agent::folder_trust::project_scope_allowed(cwd),
        "fixture: the installed hook must deny this folder"
    );
    tokio::task::LocalSet::new()
        .run_until(async {
            let agent = build_minimal_agent_for_tests();
            // (b) model switch: stock -> codex, codex -> fuigo-build-plan, strict -> custom.
            let codex = switch_rebuild_definition(&agent, cwd, "fuigo-build", "codex")
                .await
                .expect("stock -> codex rebuilds");
            assert_eq!(codex.scope, fuigo_agent::config::AgentScope::BuiltIn);
            assert!(!has_marker(&codex));
            let plan = switch_rebuild_definition(&agent, cwd, "codex", "fuigo-build-plan")
                .await
                .expect("codex -> fuigo-build-plan rebuilds");
            assert_eq!(plan.scope, fuigo_agent::config::AgentScope::BuiltIn);
            assert!(!has_marker(&plan));
            let custom = switch_rebuild_definition(&agent, cwd, "codex", "custom").await;
            assert!(custom.is_none(), "an untrusted custom harness never loads: {custom:?}");
        })
        .await;
    // (c) FUIGO_AGENT by name.
    let stock = resolve_with_fuigo_agent(cwd, "custom");
    assert_ne!(stock.name, "custom");
    assert!(!has_marker(&stock));
    let explore = resolve_with_fuigo_agent(cwd, "explore");
    assert_eq!(explore.name, "explore");
    assert_eq!(explore.scope, fuigo_agent::config::AgentScope::BuiltIn);
    assert!(!has_marker(&explore));
    // (d) Task.
    let toggles = std::collections::HashMap::new();
    let ctx = task_context(cwd, &toggles);
    assert!(fuigo_subagent_resolution::discover_agent_definition("custom", &ctx).is_none());
    assert!(!fuigo_subagent_resolution::available_agent_names(&ctx).contains(&"custom".to_string()));
    assert!(
        !fuigo_agent::discovery::all_subagents(cwd, &toggles)
            .iter()
            .any(|e| e.name == "custom")
    );
}

/// One enabled plugin `plug` whose `reviewer` agent asks for a full prompt and a marker user template.
fn plugin_registry(agent_dir: &Path, trusted: bool, scope: fuigo_agent::plugins::PluginScope) -> fuigo_agent::plugins::PluginRegistry {
    use fuigo_agent::plugins::discovery::{DiscoveredPlugin, PluginId};
    use fuigo_agent::plugins::manifest::PluginManifest;
    std::fs::create_dir_all(agent_dir).unwrap();
    std::fs::write(
        agent_dir.join("reviewer.md"),
        format!("---\nname: reviewer\ndescription: u35 plugin fixture\npromptMode: full\nuserMessageTemplate:\n  custom: \"{MARKER}\"\n---\n{MARKER} body\n"),
    )
    .unwrap();
    let root = agent_dir.parent().unwrap().to_path_buf();
    let dp = DiscoveredPlugin {
        manifest: PluginManifest {
            name: "plug".into(),
            ..Default::default()
        },
        id: PluginId::new(scope, &root, "plug"),
        root: root.clone(),
        canonical_root: root,
        scope,
        origin: match scope {
            fuigo_agent::plugins::PluginScope::Project => fuigo_agent::plugins::PluginOrigin::ProjectFuigo,
            _ => fuigo_agent::plugins::PluginOrigin::UserFuigo,
        },
        trusted,
        skill_dirs: vec![],
        command_dirs: vec![],
        agent_dirs: vec![agent_dir.to_path_buf()],
        hooks_path: None,
        mcp_config_path: None,
        lsp_config_path: None,
        conflict: None,
    };
    fuigo_agent::plugins::PluginRegistry::from_discovered(vec![dp], &[], &["plug".to_string()])
}

/// RED before the r1 fix (Astra High). An enabled but untrusted plugin's agent never reaches the zero-turn harness
/// rebuild, by qualified or bare `agent_type`; once the plugin is trusted the same switch rebuilds with it.
#[tokio::test(flavor = "current_thread")]
async fn untrusted_plugin_agents_never_reach_the_rebuild_actor() {
    let repo = tempfile::tempdir().unwrap();
    git2::Repository::init(repo.path()).unwrap();
    let cwd = repo.path();
    let plugin_home = tempfile::tempdir().unwrap();
    let agent_dir = plugin_home.path().join("plug").join("agents");
    tokio::task::LocalSet::new()
        .run_until(async {
            for scope in [fuigo_agent::plugins::PluginScope::Project, fuigo_agent::plugins::PluginScope::User] {
                let mut agent = build_minimal_agent_for_tests();
                agent.set_plugin_registry_for_tests(plugin_registry(&agent_dir, false, scope));
                for target in ["plug:reviewer", "reviewer"] {
                    let rebuilt = switch_rebuild_definition(&agent, cwd, "codex", target).await;
                    assert!(
                        rebuilt.is_none(),
                        "{scope:?} untrusted plugin agent {target:?} reached the rebuild: {rebuilt:?}"
                    );
                }
            }
            let mut agent = build_minimal_agent_for_tests();
            agent.set_plugin_registry_for_tests(plugin_registry(
                &agent_dir,
                true,
                fuigo_agent::plugins::PluginScope::User,
            ));
            let rebuilt = switch_rebuild_definition(&agent, cwd, "codex", "plug:reviewer")
                .await
                .expect("a trusted plugin agent rebuilds");
            assert_eq!(rebuilt.plugin_name.as_deref(), Some("plug"));
            assert!(has_marker(&rebuilt), "the trusted plugin's own prompt is used");
        })
        .await;
}

/// u35 r2 (Fable Low): the Task entry point itself. An enabled but untrusted plugin's agent is neither resolved by the
/// Task tool's own lookup (qualified or bare) nor offered to the model in its agent list; trusted, it is both.
#[test]
fn untrusted_plugin_agents_never_reach_the_task_entry_point() {
    let repo = tempfile::tempdir().unwrap();
    git2::Repository::init(repo.path()).unwrap();
    let cwd = repo.path();
    let plugin_home = tempfile::tempdir().unwrap();
    let agent_dir = plugin_home.path().join("plug").join("agents");
    let toggles = std::collections::HashMap::new();
    for scope in [fuigo_agent::plugins::PluginScope::Project, fuigo_agent::plugins::PluginScope::User] {
        let registry = plugin_registry(&agent_dir, false, scope);
        let ctx = fuigo_subagent_resolution::DefinitionResolutionContext {
            plugins: Some(&registry),
            ..task_context(cwd, &toggles)
        };
        for target in ["plug:reviewer", "reviewer"] {
            assert!(
                fuigo_subagent_resolution::discover_agent_definition(target, &ctx).is_none(),
                "{scope:?} untrusted plugin agent {target:?} resolved for Task"
            );
        }
        let names = fuigo_subagent_resolution::available_agent_names(&ctx);
        assert!(
            !names.iter().any(|n| n == "plug:reviewer" || n == "reviewer"),
            "{scope:?} untrusted plugin agent offered to the model: {names:?}"
        );
    }
    let registry = plugin_registry(&agent_dir, true, fuigo_agent::plugins::PluginScope::User);
    let ctx = fuigo_subagent_resolution::DefinitionResolutionContext {
        plugins: Some(&registry),
        ..task_context(cwd, &toggles)
    };
    let def = fuigo_subagent_resolution::discover_agent_definition("plug:reviewer", &ctx)
        .expect("a trusted plugin agent resolves for Task");
    assert_eq!(def.plugin_name.as_deref(), Some("plug"));
    assert!(
        fuigo_subagent_resolution::available_agent_names(&ctx).contains(&"plug:reviewer".to_string()),
        "a trusted plugin agent is offered"
    );
}

/// RED at base (the shadow half). Once the folder is trusted its own agent loads, but a built-in name still wins.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn trusted_project_agents_load_but_never_shadow() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _trust = trust_env();
    let repo = repo_with_agents(&["explore", "codex", "custom"]);
    let cwd = repo.path();
    grant_trust(cwd);
    assert!(crate::agent::folder_trust::project_scope_allowed(cwd));
    let custom = resolve_with_fuigo_agent(cwd, "custom");
    assert_eq!(custom.name, "custom");
    assert!(has_marker(&custom));
    tokio::task::LocalSet::new()
        .run_until(async {
            let agent = build_minimal_agent_for_tests();
            let custom = switch_rebuild_definition(&agent, cwd, "codex", "custom")
                .await
                .expect("trusted custom harness rebuilds");
            assert_eq!(custom.name, "custom");
            assert!(has_marker(&custom));
            let codex = switch_rebuild_definition(&agent, cwd, "fuigo-build", "codex")
                .await
                .expect("stock -> codex rebuilds");
            assert_eq!(codex.scope, fuigo_agent::config::AgentScope::BuiltIn);
            assert!(!has_marker(&codex));
        })
        .await;
    let explore = resolve_with_fuigo_agent(cwd, "explore");
    assert_eq!(explore.scope, fuigo_agent::config::AgentScope::BuiltIn);
    let toggles = std::collections::HashMap::new();
    let entries = fuigo_agent::discovery::all_subagents(cwd, &toggles);
    let explore = entries.iter().find(|e| e.name == "explore").expect("explore row");
    assert_eq!(
        explore.source,
        fuigo_agent::discovery::SubagentSource::Builtin(fuigo_agent::config::BuiltinAgentName::Explore)
    );
    assert_eq!(explore.shadows_builtin, None);
    assert!(entries.iter().any(|e| e.name == "custom"));
}

// ── A2 rule 0: names that are paths, through each entry point (test 8) ───────────────────────────────────────────────

/// An untrusted repo holding `.fuigo/agents/evil.md`; returns it with the absolute and relative traversal names.
fn evil_repo() -> (tempfile::TempDir, String, String) {
    let repo = repo_with_agents(&["evil"]);
    let abs = repo
        .path()
        .join(".fuigo")
        .join("agents")
        .join("evil")
        .to_string_lossy()
        .into_owned();
    // From `$FUIGO_HOME/agents` up to `/`, then down into the repo.
    let rel = format!("../../../../../../../../..{abs}");
    (repo, abs, rel)
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn path_agent_names_are_refused_at_every_entry_point() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _trust = trust_env();
    let (repo, abs, rel) = evil_repo();
    let cwd = repo.path();
    // (a) `_meta.agentProfile` string.
    for name in [&abs, &rel] {
        let meta = json!({ "agentProfile": name });
        let def = crate::upload::turn::parse_agent_profile_from_meta(meta.as_object());
        assert!(def.is_none(), "agentProfile {name:?} must not resolve: {def:?}");
    }
    // (c) Task.
    let toggles = std::collections::HashMap::new();
    let ctx = task_context(cwd, &toggles);
    for name in [rel.as_str(), "../evil", "p:../evil", abs.as_str()] {
        assert!(
            fuigo_subagent_resolution::discover_agent_definition(name, &ctx).is_none(),
            "Task {name:?}"
        );
        let vctx = fuigo_subagent_resolution::DefinitionValidationContext {
            cwd,
            plugins: None,
            cli_agent_names: &[],
            toggles: &toggles,
            allowed_types: None,
        };
        assert!(
            fuigo_subagent_resolution::validate_agent_name(name, &vctx).is_err(),
            "validate {name:?}"
        );
    }
    tokio::task::LocalSet::new()
        .run_until(async {
            let agent = build_minimal_agent_for_tests();
            // (b) env-overlay `[models] agent_type` naming a file: the model switch keeps the built-in harness.
            let rebuilt = switch_rebuild_definition(&agent, cwd, "codex", &abs).await;
            assert!(rebuilt.is_none(), "agent_type {abs:?} must not load a file: {rebuilt:?}");
        })
        .await;
}

// ── A1 end to end: `modes` on session/new and session/load ───────────────────────────────────────────────────────────

const MODES_TEST: &str = "agent::mvp_agent::tests::u35_modes_tests::session_responses_advertise_modes";

#[test]
#[serial_test::serial]
fn session_responses_advertise_modes() {
    let Some(_home) = fuigo_test_support::env::fresh_process_home(MODES_TEST) else {
        return;
    };
    fuigo_extra_ca::ensure_default_crypto_provider();
    let mock_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("mock runtime");
    let server = mock_rt
        .block_on(fuigo_test_support::MockInferenceServer::start())
        .expect("mock server");
    let home = tempfile::tempdir().expect("home");
    let workdir = tempfile::tempdir().expect("workdir");
    let url = server.url();
    let _env = [
        EnvGuard::set("HOME", home.path()),
        EnvGuard::set("USERPROFILE", home.path()),
        EnvGuard::set("FUIGO_CLI_CHAT_PROXY_BASE_URL", &url),
        EnvGuard::set("FUIGO_API_BASE_URL", &url),
        EnvGuard::set("FUIGO_API_KEY", "test-key-for-ci"),
        EnvGuard::set("FUIGO_TELEMETRY_ENABLED", "false"),
        EnvGuard::set("FUIGO_FEEDBACK_ENABLED", "false"),
        EnvGuard::set("FUIGO_TRACE_UPLOAD", "false"),
        EnvGuard::set("FUIGO_TURN_SUMMARY", "false"),
        EnvGuard::unset("FUIGO_MODELS_BASE_URL"),
        EnvGuard::unset("FUIGO_MODELS_LIST_URL"),
    ];
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("agent runtime");
    tokio::task::LocalSet::new().block_on(&rt, async {
        let agent_config = crate::agent::config::Config::default();
        let (tx, mut gw_rx) = tokio::sync::mpsc::unbounded_channel();
        let agent = super::MvpAgent::new(
            super::GatewaySender::new(tx),
            &agent_config,
            Arc::new(agent_config.create_auth_manager()),
            None,
        )
        .expect("agent");
        tokio::task::spawn_local(async move {
            while let Some(message) = gw_rx.recv().await {
                match message {
                    fuigo_acp_lib::AcpClientMessage::ExtNotification(args) => {
                        let _ = args.response_tx.send(Ok(()));
                    }
                    fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                        let _ = args.response_tx.send(Ok(()));
                    }
                    _ => {}
                }
            }
        });
        agent
            .initialize(
                acp::InitializeRequest::new(acp::ProtocolVersion::V1)
                    .client_capabilities(
                        acp::ClientCapabilities::new()
                            .fs(acp::FileSystemCapabilities::new())
                            .terminal(false),
                    )
                    .meta(
                        json!({
                            "startupHints": {"nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true},
                            "clientType": "u35-modes",
                            "clientVersion": "0.0-test",
                        })
                        .as_object()
                        .cloned(),
                    ),
            )
            .await
            .expect("initialize");
        let ids = |m: &acp::SessionModeState| -> Vec<String> {
            m.available_modes.iter().map(|m| m.id.0.to_string()).collect()
        };

        // session/new: the four ids, current default.
        let created = tokio::time::timeout(
            Duration::from_secs(120),
            agent.new_session(acp::NewSessionRequest::new(workdir.path().to_path_buf())),
        )
        .await
        .expect("new timed out")
        .expect("new failed");
        let modes = created.modes.expect("session/new advertises modes");
        assert_eq!(ids(&modes), ["default", "plan", "ask", "browser_use"]);
        assert_eq!(modes.current_mode_id.0.as_ref(), "default");

        // set_mode("ask") on the live session, then attach: current follows.
        agent
            .set_session_mode(acp::SetSessionModeRequest::new(created.session_id.clone(), "ask"))
            .await
            .expect("set ask");
        let load = |id: acp::SessionId| {
            acp::LoadSessionRequest::new(id, workdir.path().to_path_buf())
        };
        let loaded = tokio::time::timeout(Duration::from_secs(120), agent.load_session(load(created.session_id.clone())))
            .await
            .expect("load timed out")
            .expect("load failed");
        assert_eq!(loaded.modes.expect("load advertises modes").current_mode_id.0.as_ref(), "ask");

        agent
            .set_session_mode(acp::SetSessionModeRequest::new(created.session_id.clone(), "browser_use"))
            .await
            .expect("set browser_use");
        let loaded = agent.load_session(load(created.session_id.clone())).await.expect("load");
        assert_eq!(
            loaded.modes.unwrap().current_mode_id.0.as_ref(),
            "browser_use",
            "a resident browser session reports browser_use"
        );

        agent
            .set_session_mode(acp::SetSessionModeRequest::new(created.session_id.clone(), "plan"))
            .await
            .expect("set plan");
        let loaded = agent.load_session(load(created.session_id.clone())).await.expect("load");
        assert_eq!(loaded.modes.unwrap().current_mode_id.0.as_ref(), "plan");

        // session/resume carries the same modes block (r1 Fable L: docs and release notes promise it).
        let resumed = tokio::time::timeout(
            Duration::from_secs(120),
            agent.resume_session(acp::ResumeSessionRequest::new(
                created.session_id.clone(),
                workdir.path().to_path_buf(),
            )),
        )
        .await
        .expect("resume timed out")
        .expect("resume failed");
        let modes = resumed.modes.expect("session/resume advertises modes");
        assert_eq!(ids(&modes), ["default", "plan", "ask", "browser_use"]);
        assert_eq!(modes.current_mode_id.0.as_ref(), "plan");
    });
}

/// Cold load of a session whose persisted plan state is Active advertises `plan`.
const COLD_TEST: &str = "agent::mvp_agent::tests::u35_modes_tests::cold_load_of_persisted_plan_advertises_plan";

#[test]
#[serial_test::serial]
fn cold_load_of_persisted_plan_advertises_plan() {
    let Some(_home) = fuigo_test_support::env::fresh_process_home(COLD_TEST) else {
        return;
    };
    fuigo_extra_ca::ensure_default_crypto_provider();
    let mock_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("mock runtime");
    let server = mock_rt
        .block_on(fuigo_test_support::MockInferenceServer::start())
        .expect("mock server");
    let home = tempfile::tempdir().expect("home");
    let workdir = tempfile::tempdir().expect("workdir");
    let url = server.url();
    let _env = [
        EnvGuard::set("HOME", home.path()),
        EnvGuard::set("USERPROFILE", home.path()),
        EnvGuard::set("FUIGO_CLI_CHAT_PROXY_BASE_URL", &url),
        EnvGuard::set("FUIGO_API_BASE_URL", &url),
        EnvGuard::set("FUIGO_API_KEY", "test-key-for-ci"),
        EnvGuard::set("FUIGO_TELEMETRY_ENABLED", "false"),
        EnvGuard::set("FUIGO_FEEDBACK_ENABLED", "false"),
        EnvGuard::set("FUIGO_TRACE_UPLOAD", "false"),
        EnvGuard::set("FUIGO_TURN_SUMMARY", "false"),
        EnvGuard::unset("FUIGO_MODELS_BASE_URL"),
        EnvGuard::unset("FUIGO_MODELS_LIST_URL"),
    ];
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("agent runtime");
    tokio::task::LocalSet::new().block_on(&rt, async {
        use crate::session::storage::{JsonlStorageAdapter, StorageAdapter};
        let id = "u35-cold-plan";
        let info = crate::session::info::Info {
            id: acp::SessionId::new(id),
            cwd: workdir.path().to_string_lossy().into_owned(),
        };
        JsonlStorageAdapter::new()
            .init_session(&info, acp::ModelId::new("test-model"))
            .await
            .expect("init session");
        let dir = crate::session::persistence::session_dir(&info);
        let snapshot = crate::session::plan_mode::PlanModeSnapshot {
            state: PlanModeState::Active,
            was_previously_active: true,
            reminder_count: 1,
            pending_exit_reminder: false,
            awaiting_plan_approval: false,
        };
        std::fs::write(
            dir.join(crate::session::storage::PLAN_MODE_FILE),
            serde_json::to_vec(&snapshot).unwrap(),
        )
        .unwrap();
        let agent_config = crate::agent::config::Config::default();
        let (tx, mut gw_rx) = tokio::sync::mpsc::unbounded_channel();
        let agent = super::MvpAgent::new(
            super::GatewaySender::new(tx),
            &agent_config,
            Arc::new(agent_config.create_auth_manager()),
            None,
        )
        .expect("agent");
        tokio::task::spawn_local(async move {
            while let Some(message) = gw_rx.recv().await {
                match message {
                    fuigo_acp_lib::AcpClientMessage::ExtNotification(args) => {
                        let _ = args.response_tx.send(Ok(()));
                    }
                    fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                        let _ = args.response_tx.send(Ok(()));
                    }
                    _ => {}
                }
            }
        });
        agent
            .initialize(
                acp::InitializeRequest::new(acp::ProtocolVersion::V1)
                    .client_capabilities(
                        acp::ClientCapabilities::new()
                            .fs(acp::FileSystemCapabilities::new())
                            .terminal(false),
                    )
                    .meta(
                        json!({
                            "startupHints": {"nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true},
                            "clientType": "u35-modes",
                            "clientVersion": "0.0-test",
                        })
                        .as_object()
                        .cloned(),
                    ),
            )
            .await
            .expect("initialize");
        let loaded = tokio::time::timeout(
            Duration::from_secs(120),
            agent.load_session(acp::LoadSessionRequest::new(
                acp::SessionId::new(id),
                workdir.path().to_path_buf(),
            )),
        )
        .await
        .expect("load timed out")
        .expect("load failed");
        let modes = loaded.modes.expect("load advertises modes");
        assert_eq!(modes.current_mode_id.0.as_ref(), "plan");
        assert_eq!(modes.available_modes.len(), 4);
    });
}
