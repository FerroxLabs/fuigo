//! u36 b2: `set_mode` to `default`/`ask` keeps the session's head. A `default.md`/`ask.md` supplies only the template;
//! the client override, `_meta.rules` and the turn's memory block stay, composed as a fresh session composes them.
//! Without such a file the head is not touched.

use std::sync::Arc;

use super::support::*;
use super::*;
use crate::session::human_rules::{append_human_rules, extract_human_rules};
use fuigo_sampling_types::ConversationItem;

const RULES: &str = "U36B2 session rules";
const OVERRIDE: &str = "U36B2 client override";
fn nonce() -> &'static str {
    crate::session::helpers::memory_context::memory_context_nonce()
}

fn memory_block() -> String {
    format!(
        "{}\nremembered fact\n{}",
        fuigo_chat_state::memory_context_open_tag(nonce()),
        fuigo_chat_state::memory_context_close_tag(nonce())
    )
}

/// A never-switched control session's stored head: the spawn composition (`build_spawn_system_prompt`: override
/// verbatim, else template + `<human_rules>`) after its first turn appended the memory block (`inject_memory_reminder`).
fn control_head(template: &str, override_prompt: Option<&str>) -> String {
    let head = match override_prompt {
        Some(prompt) => prompt.to_owned(),
        None => {
            let mut prompt = template.to_owned();
            append_human_rules(&mut prompt, RULES);
            prompt
        }
    };
    format!("{}\n\n{}", head.trim_end_matches('\n'), memory_block())
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

/// A session in `cwd` whose stored head is the control head for its own template (and `override_prompt`, if any).
async fn session(
    cwd: &std::path::Path,
    override_prompt: Option<&str>,
) -> (
    Arc<SessionActor>,
    tokio::sync::mpsc::UnboundedReceiver<SessionEvent>,
    tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
) {
    let (gateway_tx, gateway_rx) = tokio::sync::mpsc::unbounded_channel();
    let (persistence_tx, _persistence_rx) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let (mut actor, events) = create_test_actor_ex(1_000, 200_000, 85, gateway_tx, persistence_tx).await;
    actor.tool_context.cwd = fuigo_paths::AbsPathBuf::new(cwd.to_path_buf()).unwrap();
    *actor.system_prompt_override.borrow_mut() = override_prompt.map(str::to_owned);
    let template = actor.agent.borrow().system_prompt().to_owned();
    actor
        .chat_state_handle
        .replace_conversation(vec![ConversationItem::system(control_head(&template, override_prompt))]);
    (Arc::new(actor), events, gateway_rx)
}

/// What a fresh session would use as its template had it been spawned with the mode's definition.
async fn rendered_template(actor: &SessionActor, name: &str) -> String {
    let def = fuigo_agent::discovery::by_name_in_cwd(name, actor.tool_context.cwd.as_path())
        .unwrap_or_else(|| panic!("{name}.md fixture must be discoverable"));
    let (ctx, bridge) = {
        let agent = actor.agent.borrow();
        (agent.prompt_context_for_definition(&def), Arc::clone(agent.tool_bridge()))
    };
    ctx.render(&bridge).await.expect("mode definition renders")
}

fn write_mode_files(agents: &std::path::Path) {
    std::fs::create_dir_all(agents).unwrap();
    for stem in ["default", "ask"] {
        let path = agents.join(format!("{stem}.md"));
        std::fs::write(
            &path,
            format!("---\nname: {stem}\ndescription: u36 b2 fixture\n---\nU36B2-{stem}-BODY\n"),
        )
        .unwrap();
        fuigo_agent::AgentDefinition::from_file(&path).expect("fixture must parse");
    }
}

fn assert_one_rules_and_memory(head: &str) {
    assert_eq!(head.matches("<!-- session-rules -->").count(), 1, "{head}");
    assert_eq!(
        head.matches(&fuigo_chat_state::memory_context_open_tag(nonce())).count(),
        1,
        "{head}"
    );
}

/// Green at base too (no lookup hit was already a no-op); pins that no hit means no head write, with and without a
/// client override.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn without_a_mode_file_set_mode_leaves_the_head_untouched() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::create_dir_all(home.path().join("agents")).unwrap();
    let cwd = tempfile::tempdir().unwrap();
    tokio::task::LocalSet::new()
        .run_until(async {
            for override_prompt in [None, Some(OVERRIDE)] {
                let (actor, _events, _gw) = session(cwd.path(), override_prompt).await;
                let control = system_text(&actor).await;
                let agent_type = actor.active_agent_type.lock().clone();
                for id in ["default", "ask", "default"] {
                    actor.handle_session_mode(acp::SessionModeId::new(id)).await;
                    assert_eq!(system_text(&actor).await, control, "{id} {override_prompt:?}");
                    assert_eq!(*actor.active_agent_type.lock(), agent_type);
                }
            }
        })
        .await;
}

/// RED at base: the bare render replaced the head, dropping `_meta.rules` and the memory block. Now the head equals a
/// control session spawned on the definition's template; switching back and forth is stable.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_mode_file_supplies_only_the_template() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    write_mode_files(&home.path().join("agents"));
    let cwd = tempfile::tempdir().unwrap();
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, _events, _gw) = session(cwd.path(), None).await;
            for id in ["default", "ask", "default", "ask"] {
                let template = rendered_template(&actor, id).await;
                assert!(template.contains(&format!("U36B2-{id}-BODY")));
                actor.handle_session_mode(acp::SessionModeId::new(id)).await;
                let head = system_text(&actor).await;
                assert_eq!(head, control_head(&template, None), "set_mode({id})");
                assert_eq!(extract_human_rules(&head), Some(RULES));
                assert_one_rules_and_memory(&head);
                assert_eq!(actor.active_agent_type.lock().as_deref(), Some(id));
            }
        })
        .await;
}

/// RED at base: the bare render replaced the client override. The override wins verbatim, as at spawn and on a model
/// switch, so the head is unchanged; the mode's agent type still applies.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_client_override_survives_a_mode_file() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    write_mode_files(&home.path().join("agents"));
    let cwd = tempfile::tempdir().unwrap();
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, _events, _gw) = session(cwd.path(), Some(OVERRIDE)).await;
            let control = system_text(&actor).await;
            assert_eq!(control, control_head("", Some(OVERRIDE)));
            for id in ["default", "ask"] {
                actor.handle_session_mode(acp::SessionModeId::new(id)).await;
                assert_eq!(system_text(&actor).await, control, "set_mode({id})");
                assert_eq!(actor.active_agent_type.lock().as_deref(), Some(id));
            }
        })
        .await;
}

/// A mode file whose body carries the session-rules marker: its block is template text, never `_meta.rules`, so it is
/// not re-appended by later set_mode calls.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_mode_file_with_the_rules_marker_is_not_taken_for_rules() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let agents = home.path().join("agents");
    std::fs::create_dir_all(&agents).unwrap();
    for stem in ["default", "ask"] {
        let path = agents.join(format!("{stem}.md"));
        std::fs::write(
            &path,
            format!(
                "---\nname: {stem}\ndescription: u36 marker fixture\n---\nU36MK-{stem}\n\n<!-- session-rules -->\n<human_rules>\nMODEFILE-RULES-{stem}\n</human_rules>\n"
            ),
        )
        .unwrap();
        fuigo_agent::AgentDefinition::from_file(&path).expect("fixture must parse");
    }
    let cwd = tempfile::tempdir().unwrap();
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, _events, _gw) = session(cwd.path(), None).await;
            for id in ["default", "default", "ask", "default"] {
                let template = rendered_template(&actor, id).await;
                assert!(template.contains(&format!("MODEFILE-RULES-{id}")), "{template}");
                actor.handle_session_mode(acp::SessionModeId::new(id)).await;
                let head = system_text(&actor).await;
                assert_eq!(extract_human_rules(&head), Some(RULES), "{head}");
                assert_eq!(head, control_head(&template, None), "set_mode({id})");
                assert_eq!(head.matches(&format!("MODEFILE-RULES-{id}")).count(), 1, "{head}");
            }
        })
        .await;
}
