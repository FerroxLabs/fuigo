//! u35 (A1/A2): the actor ignores a mode id that is not Fuigo's own, reports every accepted switch, and a project agent
//! file reaches the system prompt only from a trusted folder and only by a plain name.

use std::sync::Arc;

use super::support::*;
use super::*;
use fuigo_sampling_types::ConversationItem;

const MARKER: &str = "U35-PWNED-MARKER";

async fn actor_with_events() -> (
    SessionActor,
    tokio::sync::mpsc::UnboundedReceiver<SessionEvent>,
    tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
) {
    let (gateway_tx, gateway_rx) = tokio::sync::mpsc::unbounded_channel();
    let (persistence_tx, _persistence_rx) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let (actor, events) = create_test_actor_ex(1_000, 200_000, 85, gateway_tx, persistence_tx).await;
    (actor, events, gateway_rx)
}

fn mode_updates(events: &mut tokio::sync::mpsc::UnboundedReceiver<SessionEvent>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(event) = events.try_recv() {
        let text = format!("{event:?}");
        if text.contains("CurrentModeUpdate") {
            for id in ["default", "plan", "ask", "browser_use"] {
                if text.contains(&format!("SessionModeId(\"{id}\")")) {
                    out.push(id.to_string());
                }
            }
        }
    }
    out
}

async fn system_text(actor: &SessionActor) -> String {
    actor
        .chat_state_handle
        .get_conversation()
        .await
        .iter()
        .find_map(|item| match item {
            ConversationItem::System(sys) => Some(sys.content.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

/// An unsupported id that reaches the actor (persisted state, an internal sender) changes nothing.
#[tokio::test(flavor = "current_thread")]
async fn handle_session_mode_ignores_an_unsupported_id() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, _events, _gw) = actor_with_events().await;
            actor.handle_session_mode(acp::SessionModeId::new("ask")).await;
            assert_eq!(*actor.current_prompt_mode.lock(), PromptMode::Ask);
            let agent_type = actor.active_agent_type.lock().clone();
            for id in ["evil", "explore", "codex", "PLAN", "browser-use", ""] {
                actor.handle_session_mode(acp::SessionModeId::new(id)).await;
                assert_eq!(*actor.current_prompt_mode.lock(), PromptMode::Ask, "{id:?}");
                assert_eq!(
                    actor.plan_mode.lock().state(),
                    crate::session::plan_mode::PlanModeState::Inactive,
                    "{id:?}"
                );
                assert_eq!(*actor.active_agent_type.lock(), agent_type, "{id:?}");
            }
            actor.handle_session_mode(acp::SessionModeId::new("plan")).await;
            actor.handle_session_mode(acp::SessionModeId::new("evil")).await;
            assert_eq!(
                actor.plan_mode.lock().state(),
                crate::session::plan_mode::PlanModeState::Pending,
                "an unsupported id does not switch plan off"
            );
            assert_eq!(*actor.current_prompt_mode.lock(), PromptMode::Plan);
        })
        .await;
}

/// Every accepted switch is reported; browser_use is reported as `default`, matching what attach advertises.
#[tokio::test(flavor = "current_thread")]
async fn every_accepted_switch_emits_the_advertised_mode() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, mut events, _gw) = actor_with_events().await;
            let _ = mode_updates(&mut events);
            actor.handle_session_mode(acp::SessionModeId::new("ask")).await;
            assert_eq!(mode_updates(&mut events), ["ask"]);
            actor.handle_session_mode(acp::SessionModeId::new("browser_use")).await;
            assert_eq!(mode_updates(&mut events), ["default"]);
            assert_eq!(*actor.current_prompt_mode.lock(), PromptMode::Agent);
            actor.handle_session_mode(acp::SessionModeId::new("default")).await;
            assert_eq!(mode_updates(&mut events), ["default"]);
            actor.handle_session_mode(acp::SessionModeId::new("plan")).await;
            assert_eq!(mode_updates(&mut events), ["plan"]);
            actor.handle_session_mode(acp::SessionModeId::new("ask")).await;
            assert_eq!(mode_updates(&mut events), ["ask"], "plan off: exactly one update");
            actor.handle_session_mode(acp::SessionModeId::new("evil")).await;
            assert!(mode_updates(&mut events).is_empty(), "an ignored id reports nothing");
        })
        .await;
}

fn untrusted_repo(stems: &[&str]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    git2::Repository::init(tmp.path()).unwrap();
    let agents = tmp.path().join(".fuigo").join("agents");
    std::fs::create_dir_all(&agents).unwrap();
    for stem in stems {
        let path = agents.join(format!("{stem}.md"));
        std::fs::write(
            &path,
            format!(
                "---\nname: {stem}\ndescription: u35 fixture\nuserMessageTemplate:\n  custom: \"{MARKER}\"\n---\n{MARKER} body\n"
            ),
        )
        .unwrap();
        fuigo_agent::AgentDefinition::from_file(&path).expect("fixture must parse");
    }
    tmp
}

/// RED at base. In an untrusted folder `set_mode("ask")` / `("default")` find no repo `ask.md` / `default.md`, and a
/// path-shaped id never loads the file it names.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn untrusted_project_agents_never_reach_the_system_prompt_via_set_mode() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::create_dir_all(home.path().join("agents")).unwrap();
    crate::agent::folder_trust::install_project_agent_trust();
    let _release = fuigo_test_support::EnvGuard::set(fuigo_version::TEST_VERSION_ENV, "0.0.0-sim");
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let repo = untrusted_repo(&["ask", "default", "evil"]);
    assert!(!crate::agent::folder_trust::project_scope_allowed(repo.path()));
    let evil_abs = repo
        .path()
        .join(".fuigo")
        .join("agents")
        .join("evil")
        .to_string_lossy()
        .into_owned();
    tokio::task::LocalSet::new()
        .run_until(async {
            let (mut actor, _events, _gw) = actor_with_events().await;
            actor.tool_context.cwd = fuigo_paths::AbsPathBuf::new(repo.path().to_path_buf()).unwrap();
            let actor = Arc::new(actor);
            actor
                .chat_state_handle
                .replace_conversation(vec![ConversationItem::system("sys")]);
            let agent_type = actor.active_agent_type.lock().clone();
            for id in ["ask", "default", evil_abs.as_str()] {
                actor.handle_session_mode(acp::SessionModeId::new(id)).await;
                let system = system_text(&actor).await;
                assert!(!system.contains(MARKER), "set_mode({id:?}) put a repo file in System: {system}");
                assert_eq!(*actor.active_agent_type.lock(), agent_type, "{id:?}");
            }
        })
        .await;
}
