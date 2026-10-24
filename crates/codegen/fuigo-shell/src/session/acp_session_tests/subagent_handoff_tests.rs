//! A turn ended while a foreground `task` call was blocked on its child: the child is moved to the background and
//! the call's tool result says so, instead of the generic "was not executed" the repair would write.
use super::support::*;
use super::*;
use fuigo_tool_types::HandedOffSubagentState;
use fuigo_tools::implementations::fuigo_build::task::types::{
    HandedOffForegroundSubagent, SubagentEvent,
};

type HandOffLog = std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>;

/// A coordinator that answers every `HandOffForeground` with `children` and records `(parent session, prompt id)`.
fn scripted_hand_off_coordinator(
    children: Vec<HandedOffForegroundSubagent>,
) -> (
    tokio::sync::mpsc::UnboundedSender<SubagentEvent>,
    HandOffLog,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<SubagentEvent>();
    let log: HandOffLog = Default::default();
    let log_task = std::sync::Arc::clone(&log);
    tokio::task::spawn_local(async move {
        while let Some(event) = rx.recv().await {
            if let SubagentEvent::HandOffForeground(request) = event {
                log_task
                    .lock()
                    .unwrap()
                    .push((request.parent_session_id, request.prompt_id));
                let _ = request.respond_to.send(children.clone());
            }
        }
    });
    (tx, log)
}

fn running_child() -> HandedOffForegroundSubagent {
    HandedOffForegroundSubagent {
        subagent_id: "sa-1".to_owned(),
        tool_call_id: "call-spawn".to_owned(),
        subagent_type: "explore".to_owned(),
        description: "scan src".to_owned(),
        state: HandedOffSubagentState::Running,
    }
}

/// An actor mid-turn on prompt `running`, with a `spawn_subagent` call and a `read_file` call both unanswered.
async fn actor_blocked_in_a_spawn(
    tx: tokio::sync::mpsc::UnboundedSender<SubagentEvent>,
) -> SessionActor {
    let (gateway_tx, _gateway_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (persistence_tx, _persistence_rx) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let mut actor = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
    actor.tool_context.subagent_event_tx = Some(tx);
    actor
        .chat_state_handle
        .push_assistant_response(ConversationItem::assistant_tool_calls(vec![
            fuigo_sampling_types::ToolCall {
                id: "call-spawn".into(),
                name: "spawn_subagent".into(),
                arguments: "{}".into(),
            },
            fuigo_sampling_types::ToolCall {
                id: "call-read".into(),
                name: "read_file".into(),
                arguments: "{}".into(),
            },
        ]));
    *actor
        .current_prompt_id
        .lock()
        .expect("current_prompt_id mutex poisoned") = Some("running".to_string());
    {
        let mut state = actor.state.lock().await;
        state.running_task = Some(AgentTask::new(
            "running",
            tokio::task::spawn_local(async {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            })
            .abort_handle(),
        ));
        state.pending_inputs.push_back(user_item("running", "test"));
    }
    actor
}

async fn tool_results(actor: &SessionActor) -> Vec<(String, String)> {
    actor
        .chat_state_handle
        .get_conversation()
        .await
        .iter()
        .filter_map(|item| match item {
            ConversationItem::ToolResult(result) => {
                Some((result.tool_call_id.to_string(), result.content.to_string()))
            }
            _ => None,
        })
        .collect()
}

async fn cancel(actor: &SessionActor, cancel_subagents: bool, trigger: crate::session::CancelTrigger) {
    let _ = actor
        .cancel_running_task(crate::session::CancelOptions {
            cancel_subagents,
            trigger: Some(trigger),
            user_initiated: true,
            ..Default::default()
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_stopped_turn_tells_the_model_its_spawn_moved_to_the_background() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (tx, log) = scripted_hand_off_coordinator(vec![running_child()]);
            let actor = actor_blocked_in_a_spawn(tx).await;
            cancel(&actor, false, crate::session::CancelTrigger::CtrlC).await;

            let results = tool_results(&actor).await;
            let spawn = results
                .iter()
                .find(|(id, _)| id == "call-spawn")
                .expect("the spawn call is answered");
            assert!(
                spawn.1.contains("moved to the background because the user stopped this turn")
                    && spawn.1.contains("not cancelled")
                    && spawn.1.contains("subagent_id: sa-1"),
                "{}",
                spawn.1
            );
            assert!(
                !spawn.1.contains("was not executed"),
                "must not claim the spawn never ran: {}",
                spawn.1
            );
            let read = results
                .iter()
                .find(|(id, _)| id == "call-read")
                .expect("the other call is answered");
            assert!(
                read.1.contains("halted by the harness (user_cancel)")
                    && read.1.contains("`read_file` was not executed"),
                "a call no child belongs to keeps the generic text: {}",
                read.1
            );
            assert_eq!(
                vec![(actor.session_id_string(), "running".to_owned())],
                *log.lock().unwrap(),
                "the coordinator is asked once, for the cancelled prompt"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_send_now_message_names_itself_as_the_reason() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (tx, _log) = scripted_hand_off_coordinator(vec![running_child()]);
            let actor = actor_blocked_in_a_spawn(tx).await;
            cancel(&actor, false, crate::session::CancelTrigger::SendNow).await;

            let results = tool_results(&actor).await;
            let spawn = results
                .iter()
                .find(|(id, _)| id == "call-spawn")
                .expect("the spawn call is answered");
            assert!(
                spawn
                    .1
                    .contains("moved to the background because the user's message ended this turn"),
                "{}",
                spawn.1
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_stop_that_cancels_subagents_hands_nothing_off() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (tx, log) = scripted_hand_off_coordinator(vec![running_child()]);
            let actor = actor_blocked_in_a_spawn(tx).await;
            cancel(&actor, true, crate::session::CancelTrigger::CtrlC).await;

            let results = tool_results(&actor).await;
            let spawn = results
                .iter()
                .find(|(id, _)| id == "call-spawn")
                .expect("the spawn call is answered");
            assert!(
                spawn.1.contains("halted by the harness (user_cancel)"),
                "the child was cancelled, not moved: {}",
                spawn.1
            );
            assert!(
                log.lock().unwrap().is_empty(),
                "no hand-off is requested when the stop cancels subagents"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_coordinator_that_never_answers_costs_the_cancel_two_seconds_not_the_turn() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            // Receives the hand-off request and never replies to it. Every other event is dropped, so its
            // requester sees a closed channel and moves on, as with the other coordinator stubs in this suite.
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<SubagentEvent>();
            tokio::task::spawn_local(async move {
                let mut held = Vec::new();
                while let Some(event) = rx.recv().await {
                    if let SubagentEvent::HandOffForeground(request) = event {
                        held.push(request);
                    }
                }
            });
            let actor = actor_blocked_in_a_spawn(tx).await;
            let started = std::time::Instant::now();
            tokio::time::timeout(
                std::time::Duration::from_secs(15),
                cancel(&actor, false, crate::session::CancelTrigger::CtrlC),
            )
            .await
            .expect("a coordinator that never answers must not hold the cancel past its bound");
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "the cancel waited {:?} for a coordinator that never answers",
                started.elapsed()
            );

            let results = tool_results(&actor).await;
            assert_eq!(2, results.len(), "{results:?}");
            assert!(
                results
                    .iter()
                    .all(|(_, text)| text.contains("halted by the harness (user_cancel)")),
                "{results:?}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_child_that_finished_before_the_turn_ended_is_reported_as_finished() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut child = running_child();
            child.state = HandedOffSubagentState::Finished;
            let (tx, _log) = scripted_hand_off_coordinator(vec![child]);
            let actor = actor_blocked_in_a_spawn(tx).await;
            cancel(&actor, false, crate::session::CancelTrigger::CtrlC).await;

            let results = tool_results(&actor).await;
            let spawn = results
                .iter()
                .find(|(id, _)| id == "call-spawn")
                .expect("the spawn call is answered");
            assert!(
                spawn.1.contains("finished, but the user stopped this turn")
                    && spawn.1.contains("subagent_id: sa-1")
                    && !spawn.1.contains("moved to the background"),
                "the child's own state is the one told: {}",
                spawn.1
            );
        })
        .await;
}
