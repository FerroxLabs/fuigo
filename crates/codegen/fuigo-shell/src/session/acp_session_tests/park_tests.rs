//! P189: a parked session starts no self-started turn and drains no notifications until unpark, and a
//! parked root's subagents wait at their model calls.

use super::support::*;
use super::*;
use crate::session::quiesce::{self, ParkMode};

fn wake(prompt_id: &str, origin: crate::session::PromptOrigin) -> InputItem {
    input_with_origin_rx(prompt_id, origin).0
}

fn monitor_event(task_id: &str) -> PendingNotification {
    PendingNotification {
        prompt_id: format!("monitor-{task_id}"),
        prompt_blocks: vec![acp::ContentBlock::Text(acp::TextContent::new(format!(
            "<monitor-event description=\"p189\" task_id=\"{task_id}\">\nDONE\n</monitor-event>"
        )))],
        priority: NotificationPriority::Next,
        source: NotificationSource::MonitorEvent {
            task_id: task_id.to_string(),
        },
    }
}

async fn test_actor() -> std::sync::Arc<SessionActor> {
    let (gateway_tx, _) = tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (persistence_tx, _) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let mut actor = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
    // The park registry is process-wide and test actors share one id: give each its own so parallel tests
    // never see each other's parks.
    actor.session_info.id = acp::SessionId::new(format!("p189-actor-{}", uuid::Uuid::new_v4()));
    std::sync::Arc::new(actor)
}

fn park(session_id: &str) -> quiesce::ParkOp {
    let op = quiesce::begin_park(session_id, ParkMode::Hold).expect("not parked yet");
    assert!(quiesce::complete_park(session_id, op));
    quiesce::ParkOp { session: session_id.into(), op }
}

/// A background command's completion wake, a subagent's completion wake and a scheduler fire queued while
/// the session is parked do not start a turn; a monitor event stays pending instead of becoming a drain
/// turn. The probe reports all of it. At unpark the queue runs in its original order.
#[tokio::test(flavor = "current_thread")]
async fn parked_session_starts_no_self_started_turn_until_unpark() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = test_actor().await;
            let session_id = actor.session_info.id.0.to_string();
            let probe_op = park(&session_id);
            {
                let mut state = actor.state.lock().await;
                state.pending_inputs.push_back(wake(
                    "task-completed-bg-1",
                    crate::session::PromptOrigin::TaskCompleted {
                        task_id: "bg-1".to_string(),
                    },
                ));
                state.pending_inputs.push_back(wake(
                    "subagent-completed-sub-1",
                    crate::session::PromptOrigin::SubagentCompleted {
                        subagent_id: "sub-1".to_string(),
                    },
                ));
                state.pending_inputs.push_back(wake(
                    "scheduler-fired-loop-1",
                    crate::session::PromptOrigin::SchedulerFired,
                ));
                state.pending_notifications.push(monitor_event("mon-1"));
            }
            let (completion_tx, _completion_rx) = tokio::sync::mpsc::unbounded_channel();
            SessionActor::maybe_start_running_task(actor.clone(), completion_tx.clone()).await;
            SessionActor::maybe_drain_notifications(actor.clone(), completion_tx.clone()).await;
            {
                let state = actor.state.lock().await;
                assert!(state.running_task.is_none(), "a parked session started a turn");
                assert_eq!(state.pending_inputs.len(), 3);
                assert_eq!(
                    state.pending_notifications.len(),
                    1,
                    "the idle drain turned a monitor event into a turn while parked"
                );
            }
            let report = actor.quiesce_probe(&probe_op, false).await;
            assert!(!report.turn_running);
            assert_eq!(report.queued_inputs, 3);
            assert_eq!(report.pending_notifications, 1);

            quiesce::unpark(&session_id);
            SessionActor::maybe_start_running_task(actor.clone(), completion_tx.clone()).await;
            let state = actor.state.lock().await;
            assert_eq!(
                state.running_prompt_id(),
                Some("task-completed-bg-1"),
                "unpark runs the deferred wakes in their original order"
            );
        })
        .await;
}

/// A monitor event held by the park becomes the usual drain turn after unpark.
#[tokio::test(flavor = "current_thread")]
async fn held_monitor_event_drains_after_unpark() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = test_actor().await;
            let session_id = actor.session_info.id.0.to_string();
            let _ = park(&session_id);
            actor
                .state
                .lock()
                .await
                .pending_notifications
                .push(monitor_event("mon-2"));
            let (completion_tx, _completion_rx) = tokio::sync::mpsc::unbounded_channel();
            SessionActor::maybe_drain_notifications(actor.clone(), completion_tx.clone()).await;
            assert_eq!(actor.state.lock().await.pending_notifications.len(), 1);
            quiesce::unpark(&session_id);
            SessionActor::maybe_drain_notifications(actor.clone(), completion_tx).await;
            let state = actor.state.lock().await;
            assert!(state.pending_notifications.is_empty());
            assert!(
                state.pending_inputs.iter().any(|input| matches!(
                    input.input_origin.as_prompt_origin(),
                    crate::session::PromptOrigin::NotificationDrain
                )),
                "the held monitor event must become a drain turn after unpark"
            );
        })
        .await;
}

/// A subagent of a parked root (a background subagent, or a scheduler loop subagent) is not blocked from
/// being admitted, but its model calls wait until the root unparks.
#[tokio::test(flavor = "current_thread")]
async fn a_parked_roots_subagent_waits_at_its_model_call() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = test_actor().await;
            let child_id = actor.session_info.id.0.to_string();
            let root_id = format!("p189-root-{}", uuid::Uuid::new_v4());
            let _link = quiesce::SessionGuard::new(&child_id, Some(&root_id));
            park(&root_id);
            assert!(!quiesce::is_self_quiesced(&child_id));
            let call = actor.prepare_chat_completion(false);
            tokio::pin!(call);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(300), &mut call)
                    .await
                    .is_err(),
                "a subagent of a parked root called the model"
            );
            quiesce::unpark(&root_id);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(10), call)
                .await
                .expect("unpark releases the subagent's model call");
        })
        .await;
}

/// Astra r1 #5: a side call's client prepared BEFORE the park must still wait at its dispatch while the tree
/// is parked (the park could be acknowledged between preparing the client and sending the request).
#[tokio::test(flavor = "current_thread")]
async fn a_side_call_prepared_before_the_park_waits_at_dispatch() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = test_actor().await;
            let session_id = actor.session_info.id.0.to_string();
            let client = actor
                .prepare_chat_completion(false)
                .await
                .expect("client before the park");
            park(&session_id);
            let request = fuigo_sampling_types::ConversationRequest::default();
            let call = client.conversation_collect_with_idle_timeout(
                request,
                std::time::Duration::from_millis(200),
            );
            tokio::pin!(call);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(300), &mut call)
                    .await
                    .is_err(),
                "a side call dispatched while its session was parked"
            );
            quiesce::unpark(&session_id);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(10), call)
                .await
                .expect("unpark releases the side call");
        })
        .await;
}

/// F3: a stop probe that the actor reaches after its park was withdrawn (and replaced) aborts nothing and
/// records no debt on the replacement park.
#[tokio::test(flavor = "current_thread")]
async fn a_queued_stop_probe_does_nothing_once_withdrawn() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = test_actor().await;
            let session_id = actor.session_info.id.0.to_string();
            let p = park(&session_id);
            *actor.title_refresh_task.borrow_mut() = Some(tokio::task::spawn_local(std::future::pending::<()>()));
            assert!(quiesce::withdraw(&session_id, p.op).is_some());
            let _q = park(&session_id);
            let _ = actor.quiesce_probe(&p, true).await;
            assert!(actor.title_refresh_task.borrow().is_some(), "a stale probe aborted the title refresh");
            assert!(
                !quiesce::entry(&session_id).expect("Q").owed.title_refresh,
                "a stale probe recorded a debt on the replacement park"
            );
            quiesce::unpark(&session_id);
        })
        .await;
}

/// Unparks `0` when a test ends (also on a failed assertion), so a park never outlives its test.
struct UnparkOnDrop(String);
impl Drop for UnparkOnDrop {
    fn drop(&mut self) {
        quiesce::unpark(&self.0);
    }
}

/// An actor for a test that drives `run_session`. The park registry is process-wide and keyed by session id,
/// and `run_session`'s `SessionGuard` forgets that id's park when it exits: a test actor left on the shared
/// `test-actor` id would park every other test's actor and have its own park wiped by theirs.
async fn run_loop_actor(
    gateway_tx: tokio::sync::mpsc::UnboundedSender<fuigo_acp_lib::AcpClientMessage>,
    persistence_tx: tokio::sync::mpsc::UnboundedSender<PersistenceMsg>,
) -> (SessionActor, tokio::sync::mpsc::UnboundedReceiver<SessionEvent>) {
    let (mut actor, event_rx) = create_test_actor_ex(0, 256_000, 85, gateway_tx, persistence_tx).await;
    actor.session_info.id = acp::SessionId::new(format!("p189-actor-{}", uuid::Uuid::new_v4()));
    (actor, event_rx)
}

/// A park on one test actor never gates an unrelated test actor built by the shared helpers (the interference
/// that made `peer_admit`/`parent_message` tests fail when this file's kill test ran beside them).
#[tokio::test(flavor = "current_thread")]
async fn parking_one_test_actor_leaves_an_unrelated_test_actor_alone() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, _g) = tokio::sync::mpsc::unbounded_channel();
            let (persistence_tx, _p) = tokio::sync::mpsc::unbounded_channel();
            let (parked_actor, _event_rx) = run_loop_actor(gateway_tx, persistence_tx).await;
            let (gateway_tx, _g2) = tokio::sync::mpsc::unbounded_channel();
            let (persistence_tx, _p2) = tokio::sync::mpsc::unbounded_channel();
            let other = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
            let parked_id = parked_actor.session_info.id.0.to_string();
            let _unpark = UnparkOnDrop(parked_id.clone());
            park(&parked_id);
            assert!(
                !quiesce::is_self_quiesced(other.session_info.id.0.as_ref()),
                "a park on {parked_id} quiesced an unrelated test actor ({})",
                other.session_info.id.0
            );
        })
        .await;
}

/// F3 residual: a kill the actor reaches after its park was withdrawn is dropped at execution (the fence is
/// checked when the actor RUNS the command, not only when it was queued). A current park's kill still runs.
#[tokio::test(flavor = "current_thread")]
async fn a_queued_kill_is_dropped_once_its_park_is_withdrawn() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, _g) = tokio::sync::mpsc::unbounded_channel();
            let (persistence_tx, _p) = tokio::sync::mpsc::unbounded_channel();
            let (actor, event_rx) = run_loop_actor(gateway_tx, persistence_tx).await;
            let actor = std::sync::Arc::new(actor);
            let session_id = actor.session_info.id.0.to_string();
            let _unpark = UnparkOnDrop(session_id.clone());
            let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<SessionCommand>();
            let (_chat_tx, chat_rx) = tokio::sync::mpsc::unbounded_channel();
            tokio::task::spawn_local(super::run_session(
                actor,
                cmd_rx,
                chat_rx,
                event_rx,
                None,
                std::sync::Arc::new(parking_lot::Mutex::new(
                    fuigo_workspace::file_system::CodebaseIndexManager::new(),
                )),
                std::path::PathBuf::from("/tmp"),
                crate::session::fs_watch::FsWatchCapabilities::none(),
            ));
            let kill = |park: quiesce::ParkOp| {
                let (tx, rx) = tokio::sync::oneshot::channel();
                cmd_tx
                    .send(SessionCommand::KillBackgroundTask {
                        task_id: "no-such-task".into(),
                        source: fuigo_tools::types::KillSource::Teardown,
                        park: Some(park),
                        respond_to: tx,
                    })
                    .expect("loop receiving");
                rx
            };
            let p = park(&session_id);
            let live = tokio::time::timeout(std::time::Duration::from_secs(5), kill(p.clone()))
                .await
                .expect("answered")
                .expect("reply");
            assert_ne!(live.err().as_deref(), Some("park no longer current"), "a current park's kill was dropped");
            assert!(quiesce::withdraw(&session_id, p.op).is_some());
            let stale = tokio::time::timeout(std::time::Duration::from_secs(5), kill(p))
                .await
                .expect("answered")
                .expect("reply");
            assert_eq!(stale.err().as_deref(), Some("park no longer current"), "a withdrawn park's kill ran");
        })
        .await;
}

// ---------------------------------------------------------------------------------------------------------
// P189 A2: peer messages and a held session. Every test uses its own session ids and unparks on drop.
// ---------------------------------------------------------------------------------------------------------

use crate::session::peer_message::{PeerAdmission, PeerRefusal, force_peer_messaging_for_test, test_envelope};

fn fresh(tag: &str) -> String {
    format!("p189a2-{tag}-{}", uuid::Uuid::new_v4())
}

async fn actor_with_id(id: &str) -> std::sync::Arc<SessionActor> {
    let (gateway_tx, _) = tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (persistence_tx, _) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let mut actor = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
    actor.session_info.id = acp::SessionId::new(id.to_owned());
    std::sync::Arc::new(actor)
}

async fn queued_peer_ids(actor: &SessionActor) -> Vec<String> {
    actor
        .state
        .lock()
        .await
        .pending_inputs
        .iter()
        .filter(|i| i.input_origin.as_prompt_origin().is_peer())
        .map(|i| i.prompt_id.clone())
        .collect()
}

/// A peer message to a HELD session is committed to the protected queue and reported admitted, but starts no turn
/// (so no model call), the park stays in force, and the turn starts at unpark.
#[tokio::test(flavor = "current_thread")]
async fn a_peer_message_to_a_held_session_queues_starts_nothing_and_runs_at_unpark() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let id = fresh("held-peer");
            let actor = actor_with_id(&id).await;
            let _unpark = UnparkOnDrop(id.clone());
            park(&id);
            let (completion_tx, _completion_rx) = tokio::sync::mpsc::unbounded_channel();
            let outcome = actor
                .admit_peer_message_for_test(test_envelope("m1", "lane a", "hi"), completion_tx.clone())
                .await;
            assert_eq!(outcome, PeerAdmission::Admitted { prompt_id: "peer-message-m1".into() });
            assert_eq!(queued_peer_ids(&actor).await, ["peer-message-m1"]);
            assert!(actor.state.lock().await.running_task.is_none(), "a peer message woke a held session");
            assert!(
                quiesce::entry(&id).is_some_and(|e| e.phase == quiesce::ParkPhase::Parked),
                "the park is no longer in force"
            );
            // Another wake attempt (any trigger) still starts nothing.
            SessionActor::maybe_start_running_task(actor.clone(), completion_tx.clone()).await;
            assert!(actor.state.lock().await.running_task.is_none());

            quiesce::unpark(&id);
            SessionActor::maybe_start_running_task(actor.clone(), completion_tx).await;
            assert_eq!(
                actor.state.lock().await.running_prompt_id(),
                Some("peer-message-m1"),
                "the queued peer message starts at unpark"
            );
        })
        .await;
}

/// The peer rechecks (S4.7) still run when the held row starts at unpark: a session that opted out meanwhile
/// does not start the row.
#[tokio::test(flavor = "current_thread")]
async fn the_peer_recheck_still_applies_when_the_held_row_starts_at_unpark() {
    use crate::session::peer_admission::{OperatorPresence, PeerAdmissionConfig};
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let id = fresh("held-recheck");
            let actor = actor_with_id(&id).await;
            let _unpark = UnparkOnDrop(id.clone());
            park(&id);
            let (completion_tx, _completion_rx) = tokio::sync::mpsc::unbounded_channel();
            actor
                .admit_peer_message_for_test(test_envelope("m1", "lane a", "hi"), completion_tx.clone())
                .await;
            assert_eq!(queued_peer_ids(&actor).await.len(), 1);
            actor.peer_admission.configure(PeerAdmissionConfig {
                opted_in: false,
                policy: fuigo_config_types::PeerInboundPolicy::Accept,
                operator: OperatorPresence::Present,
                relay_driven: false,
            });
            quiesce::unpark(&id);
            SessionActor::maybe_start_running_task(actor.clone(), completion_tx).await;
            assert!(actor.state.lock().await.running_task.is_none(), "a row that no longer qualifies started");
            assert!(queued_peer_ids(&actor).await.is_empty(), "the unqualified row stayed queued");
        })
        .await;
}

/// With the feature off nothing changes for a held session: refused, nothing stored.
#[tokio::test(flavor = "current_thread")]
async fn with_peer_messaging_off_a_held_session_still_refuses_and_stores_nothing() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let _off = force_peer_messaging_for_test(false);
            let id = fresh("held-off");
            let actor = actor_with_id(&id).await;
            let _unpark = UnparkOnDrop(id.clone());
            park(&id);
            let (completion_tx, _completion_rx) = tokio::sync::mpsc::unbounded_channel();
            let outcome = actor
                .admit_peer_message_for_test(test_envelope("m1", "lane a", "hi"), completion_tx)
                .await;
            assert_eq!(outcome, PeerAdmission::Refused(PeerRefusal::FeatureOff));
            assert!(actor.state.lock().await.pending_inputs.is_empty());
        })
        .await;
}

/// While the session is PARKING (waiting for its running turn), a peer message is not promoted into that turn at a
/// safe point: it stays queued, so it cannot keep the turn alive for ever. A session that is not parking still
/// promotes it (control).
#[tokio::test(flavor = "current_thread")]
async fn a_parking_session_does_not_promote_a_peer_row_into_the_turn_it_waits_for() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let id = fresh("parking-peer");
            let actor = actor_with_id(&id).await;
            let _unpark = UnparkOnDrop(id.clone());
            {
                let mut state = actor.state.lock().await;
                state.pending_inputs.push_back(user_item("running", "owner"));
                state.running_task = Some(running_task_stub("running"));
            }
            let (completion_tx, _completion_rx) = tokio::sync::mpsc::unbounded_channel();
            let op = quiesce::begin_park(&id, ParkMode::Hold).expect("parking");
            actor
                .admit_peer_message_for_test(test_envelope("m1", "lane a", "hi"), completion_tx)
                .await;
            assert!(!actor.drain_interjections_at_safe_point().await, "a peer row entered the parked-for turn");
            assert_eq!(queued_peer_ids(&actor).await, ["peer-message-m1"]);
            // Park completes with the row still queued (the turn ended); it then runs at unpark.
            actor.state.lock().await.running_task = None;
            actor.state.lock().await.pending_inputs.retain(|i| i.prompt_id != "running");
            assert!(quiesce::complete_park(&id, op));
            assert_eq!(queued_peer_ids(&actor).await.len(), 1);
            quiesce::unpark(&id);
            // Control: no park, the same state promotes the row.
            {
                let mut state = actor.state.lock().await;
                state.pending_inputs.push_front(user_item("running2", "owner"));
                state.running_task = Some(running_task_stub("running2"));
            }
            assert!(actor.drain_interjections_at_safe_point().await, "without a park the row is promoted");
        })
        .await;
}

/// A peer message to a non-registered CHILD of a held root starts no turn while the root is held (the child has
/// no park entry of its own), and the child starts it once the root is released.
#[tokio::test(flavor = "current_thread")]
async fn a_peer_message_to_a_child_of_a_held_root_waits_for_the_root() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let root = fresh("root");
            let child = fresh("child");
            let _link = quiesce::SessionGuard::new(&child, Some(&root));
            let actor = actor_with_id(&child).await;
            let _unpark = UnparkOnDrop(root.clone());
            park(&root);
            let (completion_tx, _completion_rx) = tokio::sync::mpsc::unbounded_channel();
            let outcome = actor
                .admit_peer_message_for_test(test_envelope("m1", "lane a", "hi"), completion_tx)
                .await;
            assert_eq!(outcome, PeerAdmission::Admitted { prompt_id: "peer-message-m1".into() });
            assert_eq!(queued_peer_ids(&actor).await.len(), 1);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            assert!(
                actor.state.lock().await.running_task.is_none(),
                "a peer message started a turn in a child of a held root"
            );
            assert!(quiesce::is_parked(&child));

            quiesce::unpark(&root);
            let started = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if actor.state.lock().await.running_task.is_some() {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await;
            assert!(started.is_ok(), "the child never started the queued peer message after the root unparked");
        })
        .await;
}

/// The same for a child whose root is only PARKING: its running turn does not take the peer row at a safe point.
#[tokio::test(flavor = "current_thread")]
async fn a_child_of_a_parking_root_does_not_promote_a_peer_row() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let root = fresh("root-parking");
            let child = fresh("child-parking");
            let _link = quiesce::SessionGuard::new(&child, Some(&root));
            let actor = actor_with_id(&child).await;
            let _unpark = UnparkOnDrop(root.clone());
            {
                let mut state = actor.state.lock().await;
                state.pending_inputs.push_back(user_item("running", "owner"));
                state.running_task = Some(running_task_stub("running"));
            }
            let (completion_tx, _completion_rx) = tokio::sync::mpsc::unbounded_channel();
            quiesce::begin_park(&root, ParkMode::Hold).expect("root parking");
            actor
                .admit_peer_message_for_test(test_envelope("m1", "lane a", "hi"), completion_tx)
                .await;
            assert!(!actor.drain_interjections_at_safe_point().await);
            assert_eq!(queued_peer_ids(&actor).await.len(), 1);
        })
        .await;
}

async fn wait_running(actor: &SessionActor) -> bool {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if actor.state.lock().await.running_task.is_some() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}

/// Opus r1 #2, lost wake A: the row is admitted while the child is busy and the root is NOT held; the root then
/// parks, the child's turn ends and the start is blocked with no waiter armed at enqueue. The block site arms it.
#[tokio::test(flavor = "current_thread")]
async fn a_peer_row_admitted_before_the_root_parked_starts_after_the_root_unparks() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let root = fresh("root-wake-a");
            let child = fresh("child-wake-a");
            let _link = quiesce::SessionGuard::new(&child, Some(&root));
            let actor = actor_with_id(&child).await;
            let _unpark = UnparkOnDrop(root.clone());
            actor.state.lock().await.running_task = Some(running_task_stub("busy"));
            let (completion_tx, _completion_rx) = tokio::sync::mpsc::unbounded_channel();
            actor.admit_peer_message_for_test(test_envelope("wa", "lane a", "hi"), completion_tx.clone()).await;
            quiesce::begin_park(&root, ParkMode::Hold).expect("root parking");
            actor.state.lock().await.running_task = None; // the child's turn ended
            SessionActor::maybe_start_running_task(actor.clone(), completion_tx).await;
            assert!(actor.state.lock().await.running_task.is_none(), "a peer row started under a parking root");
            quiesce::unpark(&root);
            assert!(wait_running(&actor).await, "the blocked peer row never started: no waiter was armed at the block");
        })
        .await;
}

/// Opus r1 #2, lost wake B: the waiter fires at unpark and the root is parked AGAIN before its start-time check.
#[tokio::test(flavor = "current_thread")]
async fn a_peer_row_whose_root_is_reparked_before_the_start_check_still_starts_later() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let root = fresh("root-wake-b");
            let child = fresh("child-wake-b");
            let _link = quiesce::SessionGuard::new(&child, Some(&root));
            let actor = actor_with_id(&child).await;
            let _unpark = UnparkOnDrop(root.clone());
            park(&root);
            let (completion_tx, _completion_rx) = tokio::sync::mpsc::unbounded_channel();
            actor.admit_peer_message_for_test(test_envelope("wb", "lane a", "hi"), completion_tx).await;
            let guard = actor.state.lock().await; // the waiter's restart parks on this lock
            quiesce::unpark(&root);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            park(&root); // re-parked before the start-time check
            drop(guard);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            assert!(actor.state.lock().await.running_task.is_none(), "started under a re-parked root");
            quiesce::unpark(&root);
            assert!(wait_running(&actor).await, "the waiter was lost by the re-park");
        })
        .await;
}

/// Opus r1 #3: a non-peer row queued behind a blocked peer row starts, so the root's turn that waits on the child
/// can end; the peer row stays queued.
#[tokio::test(flavor = "current_thread")]
async fn a_non_peer_row_behind_a_blocked_peer_row_still_starts() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let root = fresh("root-skip");
            let child = fresh("child-skip");
            let _link = quiesce::SessionGuard::new(&child, Some(&root));
            let actor = actor_with_id(&child).await;
            let _unpark = UnparkOnDrop(root.clone());
            actor.state.lock().await.running_task = Some(running_task_stub("busy"));
            let (completion_tx, _completion_rx) = tokio::sync::mpsc::unbounded_channel();
            quiesce::begin_park(&root, ParkMode::Hold).expect("root parking");
            actor.admit_peer_message_for_test(test_envelope("ws", "lane a", "hi"), completion_tx.clone()).await;
            actor.state.lock().await.pending_inputs.push_back(user_item("from-parent", "parent says"));
            actor.state.lock().await.running_task = None;
            SessionActor::maybe_start_running_task(actor.clone(), completion_tx).await;
            assert!(wait_running(&actor).await, "the non-peer row behind the peer row never started");
            assert_eq!(queued_peer_ids(&actor).await.len(), 1, "the peer row must stay queued");
        })
        .await;
}

fn spawn_run_loop(
    actor: &std::sync::Arc<SessionActor>,
    event_rx: tokio::sync::mpsc::UnboundedReceiver<SessionEvent>,
) -> (
    tokio::sync::mpsc::UnboundedSender<SessionCommand>,
    tokio::sync::mpsc::UnboundedSender<fuigo_chat_state::ChatStateEvent>,
) {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<SessionCommand>();
    // The caller keeps the chat-state sender alive: a closed channel ends the loop's wait.
    let (chat_tx, chat_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::task::spawn_local(super::run_session(
        actor.clone(),
        cmd_rx,
        chat_rx,
        event_rx,
        None,
        std::sync::Arc::new(parking_lot::Mutex::new(
            fuigo_workspace::file_system::CodebaseIndexManager::new(),
        )),
        std::path::PathBuf::from("/tmp"),
        crate::session::fs_watch::FsWatchCapabilities::none(),
    ));
    (cmd_tx, chat_tx)
}

fn release(op: u64, owed: quiesce::OwedWork, kick: bool) -> SessionCommand {
    SessionCommand::QuiesceRelease { op, owed, reopen_spawns: false, kick, reminder: None }
}

/// Returns once the session loop has handled everything sent before it (the kill of a task that does not exist is
/// answered in command order).
async fn barrier(cmd_tx: &tokio::sync::mpsc::UnboundedSender<SessionCommand>) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(SessionCommand::KillBackgroundTask {
            task_id: "no-such-task".into(),
            source: fuigo_tools::types::KillSource::Teardown,
            park: None,
            respond_to: tx,
        })
        .expect("loop receiving");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), rx).await.expect("answered");
}

/// The `QuiesceRelease` handler of an unpark starts a queued peer message (the rechecks run at that start).
#[tokio::test(flavor = "current_thread")]
async fn the_unpark_release_starts_a_queued_peer_message() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let id = fresh("release-peer");
            let (gateway_tx, _g) = tokio::sync::mpsc::unbounded_channel();
            let (persistence_tx, _p) = tokio::sync::mpsc::unbounded_channel();
            let (mut actor, event_rx) = create_test_actor_ex(0, 256_000, 85, gateway_tx, persistence_tx).await;
            actor.session_info.id = acp::SessionId::new(id.clone());
            let actor = std::sync::Arc::new(actor);
            let _unpark = UnparkOnDrop(id.clone());
            let (cmd_tx, _chat_tx) = spawn_run_loop(&actor, event_rx);
            let p = park(&id);
            let (completion_tx, _completion_rx) = tokio::sync::mpsc::unbounded_channel();
            actor
                .admit_peer_message_for_test(test_envelope("m1", "lane a", "hi"), completion_tx)
                .await;
            barrier(&cmd_tx).await;
            assert!(actor.state.lock().await.running_task.is_none(), "a held session started a turn");
            quiesce::unpark(&id);
            cmd_tx.send(release(p.op, quiesce::OwedWork::default(), true)).expect("send");
            barrier(&cmd_tx).await; // the release has been handled once this answers
            assert_eq!(actor.state.lock().await.running_prompt_id(), Some("peer-message-m1"));
        })
        .await;
}

/// Grok r4 #4/#8: a release of park P that the actor reaches while park Q holds the session starts nothing and
/// hands its owed work (title refresh, family debt) to Q instead of running it under Q.
#[tokio::test(flavor = "current_thread")]
async fn a_stale_release_neither_kicks_nor_runs_owed_work_under_the_replacement_park() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let _on = force_peer_messaging_for_test(true);
            let id = fresh("stale-release");
            let (gateway_tx, _g) = tokio::sync::mpsc::unbounded_channel();
            let (persistence_tx, _p) = tokio::sync::mpsc::unbounded_channel();
            let (mut actor, event_rx) = create_test_actor_ex(0, 256_000, 85, gateway_tx, persistence_tx).await;
            actor.session_info.id = acp::SessionId::new(id.clone());
            let actor = std::sync::Arc::new(actor);
            let _unpark = UnparkOnDrop(id.clone());
            let (cmd_tx, _chat_tx) = spawn_run_loop(&actor, event_rx);
            let p = park(&id);
            assert!(quiesce::withdraw(&id, p.op).is_some());
            let q = park(&id);
            let (completion_tx, _completion_rx) = tokio::sync::mpsc::unbounded_channel();
            // Queued work that a kick would start.
            actor
                .admit_peer_message_for_test(test_envelope("m1", "lane a", "hi"), completion_tx)
                .await;
            let owed = quiesce::OwedWork {
                turn_summary: None,
                title_refresh: true,
                family_switch_compact: Some(quiesce::FamilyDebt { origin_family: "a".into() }),
            };
            cmd_tx.send(release(p.op, owed.clone(), true)).expect("send");
            barrier(&cmd_tx).await;
            assert!(actor.state.lock().await.running_task.is_none(), "P's release started a turn under Q");
            let entry = quiesce::entry(&id).expect("Q still holds");
            assert_eq!(entry.op, q.op);
            assert_eq!(entry.owed, owed, "P's owed work moved to Q");
        })
        .await;
}

// ---------------------------------------------------------------------------------------------------------
// P189 A2 round 3: only the client prompt that began an un-park finishes it; a scheduled fire waits behind it.
// ---------------------------------------------------------------------------------------------------------

fn fire_prompt(prompt_id: &str) -> (SessionCommand, tokio::sync::oneshot::Receiver<crate::session::commands::PromptTurnResult>) {
    let (respond_to, rx) = tokio::sync::oneshot::channel();
    let cmd = SessionCommand::Prompt {
        prompt_id: prompt_id.into(),
        prompt_blocks: vec![acp::ContentBlock::Text(acp::TextContent::new("scheduled job"))],
        prompt_mode: PromptMode::Agent,
        artifact_upload_ctx: None,
        client_identifier: None,
        screen_mode: None,
        verbatim: true,
        traceparent: None,
        json_schema: None,
        send_now: false,
        admission: None,
        origin: crate::session::PromptOrigin::SchedulerFired,
        tool_overrides_update: None,
        respond_to,
        prompt_admitted: None,
        persist_ack: None,
        parsed_prompt_tx: None,
    };
    (cmd, rx)
}

async fn spawn_loop(actor: std::sync::Arc<SessionActor>, event_rx: tokio::sync::mpsc::UnboundedReceiver<SessionEvent>) -> tokio::sync::mpsc::UnboundedSender<SessionCommand> {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<SessionCommand>();
    let (chat_tx, chat_rx) = tokio::sync::mpsc::unbounded_channel();
    std::mem::forget(chat_tx);
    tokio::task::spawn_local(super::run_session(
        actor,
        cmd_rx,
        chat_rx,
        event_rx,
        None,
        std::sync::Arc::new(parking_lot::Mutex::new(fuigo_workspace::file_system::CodebaseIndexManager::new())),
        std::path::PathBuf::from("/tmp"),
        crate::session::fs_watch::FsWatchCapabilities::none(),
    ));
    cmd_tx
}

/// A scheduled fire reaching the actor while the session is `Unparking` is queued: it does not remove the entry
/// and starts no turn. When the client prompt's unpark finishes (here by the guard path, as for a cancelled
/// prompt) the queued fire starts.
#[tokio::test(flavor = "current_thread")]
async fn a_scheduled_fire_during_unparking_neither_finishes_the_unpark_nor_starts_a_turn() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, _g) = tokio::sync::mpsc::unbounded_channel();
            let (persistence_tx, _p) = tokio::sync::mpsc::unbounded_channel();
            let (actor, event_rx) = run_loop_actor(gateway_tx, persistence_tx).await;
            let actor = std::sync::Arc::new(actor);
            let id = actor.session_info.id.0.to_string();
            let _unpark = UnparkOnDrop(id.clone());
            let cmd_tx = spawn_loop(actor.clone(), event_rx).await;
            let p = park(&id);
            assert!(quiesce::begin_implicit_unpark(&id, p.op).is_some());
            let (cmd, _rx) = fire_prompt("scheduler-fired-root-1");
            cmd_tx.send(cmd).expect("loop receiving");
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            assert_eq!(quiesce::entry(&id).map(|e| e.phase), Some(quiesce::ParkPhase::Unparking), "the fire finished the un-park");
            {
                let state = actor.state.lock().await;
                assert!(state.running_task.is_none(), "the fire's turn started while the session was Unparking");
                assert_eq!(state.pending_inputs.len(), 1, "the fire row is kept queued");
            }
            assert!(quiesce::finish_unpark(&id, p.op));
            assert!(wait_running(&actor).await, "the queued fire never started after the un-park finished");
        })
        .await;
}

/// The same for a scheduled fire on a CHILD whose root is `Unparking`: no child turn until the entry is gone.
#[tokio::test(flavor = "current_thread")]
async fn a_scheduled_fire_on_a_child_of_an_unparking_root_waits_for_the_entry_to_go() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let root = fresh("ufire-root");
            let child = fresh("ufire-child");
            let _link = quiesce::SessionGuard::new(&child, Some(&root));
            let _unpark = UnparkOnDrop(root.clone());
            let (gateway_tx, _g) = tokio::sync::mpsc::unbounded_channel();
            let (persistence_tx, _p) = tokio::sync::mpsc::unbounded_channel();
            let (mut actor, event_rx) = run_loop_actor(gateway_tx, persistence_tx).await;
            actor.session_info.id = acp::SessionId::new(child.clone());
            let actor = std::sync::Arc::new(actor);
            let cmd_tx = spawn_loop(actor.clone(), event_rx).await;
            let p = park(&root);
            assert!(quiesce::begin_implicit_unpark(&root, p.op).is_some());
            let (cmd, _rx) = fire_prompt("scheduler-fired-child-1");
            cmd_tx.send(cmd).expect("loop receiving");
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            {
                let state = actor.state.lock().await;
                assert!(state.running_task.is_none(), "a child fire started a turn under an Unparking root");
                assert_eq!(state.pending_inputs.len(), 1, "the fire row is kept queued");
            }
            assert!(quiesce::finish_unpark(&root, p.op));
            assert!(wait_running(&actor).await, "the child never started the queued fire after the root's entry went");
        })
        .await;
}
