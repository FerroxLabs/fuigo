//! P189 packet A2: Grok r4 findings 3, 5, 8 and 9, driven through the real `handle_park` / `implicit_unpark`.
//! Every test uses its own session id (the park table is process-wide).

use std::time::{Duration, Instant};

use agent_client_protocol as acp;
use fuigo_tools::implementations::fuigo_build::scheduler::types::{FoldReply, SchedulerCommand};

use super::p189_park_round3_tests::{insert_session, park_request};
use super::{build_minimal_agent_for_tests, run_local_for_bridge_test};
use crate::extensions::session_park::{handle_park, implicit_unpark};
use crate::session::SessionCommand;
use crate::session::quiesce::{self, FamilyDebt, ParkMode, ParkPhase};

fn fresh(tag: &str) -> String {
    format!("p189a2-{tag}-{}", uuid::Uuid::new_v4())
}

/// Removes the session's park entry when a test ends, even by a failed assert (the table is process-wide).
struct UnparkOnDrop(String);

impl Drop for UnparkOnDrop {
    fn drop(&mut self) {
        quiesce::unpark(&self.0);
    }
}

/// Grok r4 #3: a prompt's implicit unpark follows EVERY replacement of the park it folded for (here two), not
/// only one, and unparks the park that holds at the end.
#[test]
fn implicit_unpark_follows_more_than_one_replacement() {
    run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let id_owned = fresh("many-replacements");
        let id = id_owned.as_str();
        let _unpark = UnparkOnDrop(id_owned.clone());
        let sid = acp::SessionId::new(id_owned.clone());
        let (_cmd_rx, mut sched_rx) = insert_session(&agent, &sid);
        let p = quiesce::begin_park(id, ParkMode::Hold).expect("park P");
        assert!(quiesce::complete_park(id, p));
        let session = agent.session_handle_waiting_for_load(&sid).await.expect("session");
        let driver = async {
            let mut current = p;
            for round in 0..3 {
                let next = tokio::time::timeout(Duration::from_secs(3), sched_rx.recv()).await;
                let Ok(Some(SchedulerCommand::SetPaused { op, reply, fold, .. })) = next else {
                    panic!("no fold in round {round}: the prompt gave up following the park");
                };
                assert_eq!(op, current, "round {round} must fold the park that holds");
                if round < 2 {
                    quiesce::withdraw(id, current);
                    current = quiesce::begin_park(id, ParkMode::Hold).expect("replacement park");
                }
                let _ = reply.send(FoldReply { id: fold.as_ref().map(|f| f.id), fires: Vec::new() });
            }
            current
        };
        let (guard, last) = tokio::join!(implicit_unpark(&agent, &session, id), driver);
        let guard = guard.expect("no error").expect("the last park was unparked by the prompt");
        assert_eq!(quiesce::entry(id).map(|e| (e.op, e.phase)), Some((last, ParkPhase::Unparking)));
        drop(guard);
        quiesce::unpark(id);
    });
}

/// Grok r4 #3: when parks keep replacing each other the prompt FAILS instead of continuing on a parked session.
#[test]
fn implicit_unpark_fails_the_prompt_if_the_session_is_still_parked() {
    run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let id_owned = fresh("still-parked");
        let id = id_owned.as_str();
        let _unpark = UnparkOnDrop(id_owned.clone());
        let sid = acp::SessionId::new(id_owned.clone());
        let (_cmd_rx, mut sched_rx) = insert_session(&agent, &sid);
        let mut current = quiesce::begin_park(id, ParkMode::Hold).expect("park");
        assert!(quiesce::complete_park(id, current));
        let session = agent.session_handle_waiting_for_load(&sid).await.expect("session");
        let driver = async {
            while let Some(SchedulerCommand::SetPaused { reply, fold, .. }) = sched_rx.recv().await {
                quiesce::withdraw(id, current);
                current = quiesce::begin_park(id, ParkMode::Hold).expect("replacement park");
                let _ = reply.send(FoldReply { id: fold.as_ref().map(|f| f.id), fires: Vec::new() });
            }
        };
        let result = tokio::select! {
            result = implicit_unpark(&agent, &session, id) => result,
            () = driver => unreachable!("the scheduler channel stays open"),
        };
        assert!(result.is_err(), "the prompt must fail while the session is still parked");
        assert!(quiesce::entry(id).is_some_and(|e| e.phase != ParkPhase::Unparking), "still parked");
        quiesce::unpark(id);
    });
}

/// A client that accepts everything but never finishes writing the `unparked` marker: a slow `park_hold.release`.
struct StuckClient;

#[async_trait::async_trait(?Send)]
impl acp::Client for StuckClient {
    async fn request_permission(
        &self,
        _args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        Err(acp::Error::method_not_found())
    }

    async fn session_notification(&self, _args: acp::SessionNotification) -> acp::Result<()> {
        Ok(())
    }

    async fn ext_notification(&self, _args: acp::ExtNotification) -> acp::Result<()> {
        std::future::pending().await
    }
}

/// Grok r4 #5: the scheduler fold is committed even when writing the held frames (`park_hold.release`) is slow:
/// the release is queued and the fold committed BEFORE that write, so the scheduler's bounded commit wait
/// cannot lapse after the reminder was already queued.
#[test]
fn the_fold_is_committed_before_the_held_frames_are_written() {
    run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let _client = crate::agent::park_hold::ParkHoldClient::new(StuckClient, agent.park_hold.clone());
        let id_owned = fresh("commit-first");
        let id = id_owned.as_str();
        let _unpark = UnparkOnDrop(id_owned.clone());
        let sid = acp::SessionId::new(id_owned.clone());
        let (mut cmd_rx, mut sched_rx) = insert_session(&agent, &sid);
        let op = quiesce::begin_park(id, ParkMode::Hold).expect("park");
        assert!(quiesce::complete_park(id, op));
        let session = agent.session_handle_waiting_for_load(&sid).await.expect("session");
        let driver = async {
            let Some(SchedulerCommand::SetPaused { reply, fold, .. }) = sched_rx.recv().await else {
                panic!("no fold");
            };
            let fold = fold.expect("a fold transaction");
            let want = fold.id;
            let _ = reply.send(FoldReply { id: Some(want), fires: Vec::new() });
            let committed = tokio::time::timeout(Duration::from_secs(3), fold.commit)
                .await
                .ok()
                .and_then(Result::ok);
            (committed == Some(want), cmd_rx.try_recv().ok())
        };
        let (committed, release) = tokio::select! {
            _ = implicit_unpark(&agent, &session, id) => panic!("the stuck client let the release finish"),
            out = driver => out,
        };
        assert!(committed, "the fold was not committed while the held frames were still being written");
        assert!(matches!(release, Some(SessionCommand::QuiesceRelease { op: released, .. }) if released == op));
        quiesce::unpark(id);
    });
}

/// Grok r4 #8: a park withdrawn before its ack hands the model-switch debt it accumulated to the release that
/// the session actor runs; the debt is not dropped with the entry.
#[test]
fn a_withdrawn_park_keeps_its_family_debt() {
    run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let id_owned = fresh("debt");
        let id = id_owned.as_str();
        let _unpark = UnparkOnDrop(id_owned.clone());
        let sid = acp::SessionId::new(id_owned.clone());
        let (mut cmd_rx, mut sched_rx) = insert_session(&agent, &sid);
        let driver = async {
            // The scheduler pause is requested while the park is Parking; a model switch records the debt there,
            // and the scheduler never answers, so the park fails `timeout` and withdraws.
            let Some(SchedulerCommand::SetPaused { .. }) = sched_rx.recv().await else {
                panic!("no pause");
            };
            assert!(quiesce::owe(id, |o| o.note_model_switch(true, Some("a".into()), "b")));
            std::future::pending::<()>().await;
        };
        let request = park_request(id, "hold", 1);
        let result = tokio::select! {
            r = handle_park(&agent, &request) => r,
            () = driver => unreachable!(),
        };
        assert!(result.is_err());
        let mut debt = None;
        while let Ok(cmd) = cmd_rx.try_recv() {
            if let SessionCommand::QuiesceRelease { owed, .. } = cmd {
                debt = owed.family_switch_compact;
            }
        }
        assert_eq!(debt, Some(FamilyDebt { origin_family: "a".into() }), "the withdraw dropped the debt");
    });
}

/// Grok r4 #9: the already-parked probe is bounded by the request's ONE deadline. The park request waits about
/// 4 s for a loading session, then asks the actor, which never answers: the reply comes at `timeoutMs + 5 s`
/// from the request start (about 6 s here), not 5 s after the load finished (about 9 s).
#[test]
fn the_idempotent_probe_is_bounded_by_the_one_deadline() {
    run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let id_owned = fresh("idem-deadline");
        let id = id_owned.as_str();
        let _unpark = UnparkOnDrop(id_owned.clone());
        let sid = acp::SessionId::new(id_owned.clone());
        // The session does not exist until its load finishes (4 s in), as for a real `session/load`.
        let load = agent.begin_session_load(&sid);
        let op = quiesce::begin_park(id, ParkMode::Hold).expect("park");
        assert!(quiesce::complete_park(id, op));
        assert!(quiesce::ack_park(id, op, 0));
        let started = Instant::now();
        let finish_load = async {
            tokio::time::sleep(Duration::from_secs(4)).await;
            let channels = insert_session(&agent, &sid);
            drop(load);
            channels
        };
        let request = park_request(id, "hold", 1000);
        let (result, _channels) = tokio::join!(handle_park(&agent, &request), finish_load);
        let took = started.elapsed();
        let error = result.expect_err("an unanswered probe must fail the request");
        let wire = serde_json::to_string(&error).unwrap_or_default();
        assert!(wire.contains(r#""reason":"timeout""#), "a deadline miss must be reported as timeout: {wire}");
        assert!(took > Duration::from_millis(5500), "the probe was never waited on (the session was not found?): {took:?}");
        assert!(took < Duration::from_millis(7500), "the probe outlived the one deadline: {took:?}");
        quiesce::unpark(id);
    });
}

/// Opus r1 #4: the implicit unpark is drop-safe. A prompt future dropped while the held frames are still being
/// written (a hung `park_hold.release`) must not leave the entry Unparking.
#[test]
fn a_dropped_implicit_unpark_does_not_leave_the_entry_unparking() {
    run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let _client = crate::agent::park_hold::ParkHoldClient::new(StuckClient, agent.park_hold.clone());
        let id_owned = fresh("drop-implicit");
        let id = id_owned.as_str();
        let _unpark = UnparkOnDrop(id_owned.clone());
        let sid = acp::SessionId::new(id_owned.clone());
        let (_cmd_rx, mut sched_rx) = insert_session(&agent, &sid);
        let op = quiesce::begin_park(id, ParkMode::Hold).expect("park");
        assert!(quiesce::complete_park(id, op));
        let session = agent.session_handle_waiting_for_load(&sid).await.expect("session");
        let driver = async {
            let Some(SchedulerCommand::SetPaused { reply, fold, .. }) = sched_rx.recv().await else {
                panic!("no fold");
            };
            let _ = reply.send(FoldReply { id: fold.as_ref().map(|f| f.id), fires: Vec::new() });
            tokio::time::sleep(Duration::from_millis(300)).await;
        };
        tokio::select! {
            _ = implicit_unpark(&agent, &session, id) => panic!("the stuck client let the release finish"),
            () = driver => {}
        }
        assert!(quiesce::entry(id).is_none(), "the dropped prompt left the entry behind: {:?}", quiesce::entry(id).map(|e| e.phase));
    });
}

/// Opus r1 #5: the explicit unpark queues the release (the owed work and the kick) BEFORE the frame write, so a
/// hung write or a dropped future cannot lose them.
#[test]
fn the_explicit_unpark_queues_its_release_before_writing_the_frames() {
    run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let _client = crate::agent::park_hold::ParkHoldClient::new(StuckClient, agent.park_hold.clone());
        let id_owned = fresh("explicit-order");
        let id = id_owned.as_str();
        let _unpark = UnparkOnDrop(id_owned.clone());
        let sid = acp::SessionId::new(id_owned.clone());
        let (mut cmd_rx, mut sched_rx) = insert_session(&agent, &sid);
        let op = quiesce::begin_park(id, ParkMode::Hold).expect("park");
        assert!(quiesce::complete_park(id, op));
        assert!(quiesce::ack_park(id, op, 0));
        let session = agent.session_handle_waiting_for_load(&sid).await.expect("session");
        let driver = async {
            let Some(SchedulerCommand::SetPaused { reply, fold, .. }) = sched_rx.recv().await else {
                panic!("no resume");
            };
            let _ = reply.send(FoldReply { id: fold.as_ref().map(|f| f.id), fires: Vec::new() });
            tokio::time::timeout(Duration::from_secs(3), cmd_rx.recv()).await
        };
        let release = tokio::select! {
            _ = crate::extensions::session_park::unpark_session(&agent, &session, id) => panic!("the stuck client let the unpark finish"),
            out = driver => out,
        };
        assert!(
            matches!(release, Ok(Some(SessionCommand::QuiesceRelease { op: released, kick: true, .. })) if released == op),
            "the release was not queued before the frame write"
        );
    });
}

/// Owner decision 45 (2026-10-11): a scheduled-task fire never un-parks. A fire notification written BEFORE the
/// park and redeemed AFTER the session is parked leaves the session parked, starts no turn (no `Prompt` command,
/// so no model call) and replies `end_turn`; its text rides the reminder of the next real prompt, and that
/// normal client prompt still un-parks.
#[test]
fn a_scheduled_fire_redeemed_while_parked_does_not_unpark_and_is_folded_into_the_next_prompt() {
    use acp::Agent as _;
    run_local_for_bridge_test(|| async {
        let agent = std::rc::Rc::new(build_minimal_agent_for_tests());
        let id_owned = fresh("fire-parked");
        let id = id_owned.as_str();
        let _unpark = UnparkOnDrop(id_owned.clone());
        let sid = acp::SessionId::new(id_owned.clone());
        let (mut cmd_rx, mut sched_rx) = insert_session(&agent, &sid);
        // The shell announced the fire (and minted its ticket) BEFORE the park.
        let text = crate::session::cron_fire_tickets::scheduled_prompt_text("check the deploy", "task-1", "every 5m");
        let ticket = crate::session::cron_fire_tickets::mint(id, &text);
        let op = quiesce::begin_park(id, ParkMode::Hold).expect("park");
        assert!(quiesce::complete_park(id, op));
        assert!(quiesce::ack_park(id, op, 0));

        let fire = acp::PromptRequest::new(sid.clone(), vec![acp::ContentBlock::Text(acp::TextContent::new(text))])
            .meta(serde_json::json!({ "promptId": format!("scheduler-fired-{ticket}"), "mode": "agent" }).as_object().cloned());
        let reply = tokio::time::timeout(Duration::from_secs(5), agent.prompt(fire))
            .await
            .expect("the fire prompt must return at once, not start a turn")
            .expect("a folded fire gets a normal reply");
        assert_eq!(reply.stop_reason, acp::StopReason::EndTurn);
        assert_eq!(quiesce::entry(id).map(|e| e.phase), Some(ParkPhase::Parked), "a scheduled fire un-parked the session");
        assert!(sched_rx.try_recv().is_err(), "a fire must not touch the scheduler pause");
        while let Ok(cmd) = cmd_rx.try_recv() {
            assert!(!matches!(cmd, SessionCommand::Prompt { .. }), "a fire started a turn");
        }

        // A normal client prompt still un-parks, and the fire rides its reminder.
        let normal = acp::PromptRequest::new(sid.clone(), vec![acp::ContentBlock::Text(acp::TextContent::new("hello".to_owned()))])
            .meta(serde_json::json!({ "mode": "agent" }).as_object().cloned());
        let prompting = std::rc::Rc::clone(&agent);
        let task = tokio::task::spawn_local(async move { prompting.prompt(normal).await });
        let driver = async {
            let Some(SchedulerCommand::SetPaused { reply, fold, .. }) = sched_rx.recv().await else {
                panic!("the normal prompt did not fold");
            };
            let _ = reply.send(FoldReply { id: fold.as_ref().map(|f| f.id), fires: Vec::new() });
            while let Some(cmd) = cmd_rx.recv().await {
                if let SessionCommand::QuiesceRelease { reminder, .. } = cmd {
                    return reminder;
                }
            }
            None
        };
        let reminder = tokio::time::timeout(Duration::from_secs(5), driver).await.expect("no release");
        task.abort();
        let reminder = reminder.expect("the release carried no reminder");
        assert!(reminder.contains("check the deploy"), "the fire's text is missing from the next prompt: {reminder}");
    });
}

/// Opus r1 #10: `prompt()` itself returns the error (not just `implicit_unpark`) when parks keep replacing each
/// other and the session stays parked.
#[test]
fn prompt_itself_fails_while_the_session_stays_parked() {
    use acp::Agent as _;
    run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let id_owned = fresh("prompt-still-parked");
        let id = id_owned.as_str();
        let _unpark = UnparkOnDrop(id_owned.clone());
        let sid = acp::SessionId::new(id_owned.clone());
        let (_cmd_rx, mut sched_rx) = insert_session(&agent, &sid);
        let mut current = quiesce::begin_park(id, ParkMode::Hold).expect("park");
        assert!(quiesce::complete_park(id, current));
        let driver = async {
            while let Some(SchedulerCommand::SetPaused { reply, fold, .. }) = sched_rx.recv().await {
                quiesce::withdraw(id, current);
                current = quiesce::begin_park(id, ParkMode::Hold).expect("replacement park");
                let _ = reply.send(FoldReply { id: fold.as_ref().map(|f| f.id), fires: Vec::new() });
            }
        };
        let request = acp::PromptRequest::new(sid.clone(), vec![acp::ContentBlock::Text(acp::TextContent::new("hi".to_owned()))])
            .meta(serde_json::json!({ "mode": "agent" }).as_object().cloned());
        let result = tokio::select! {
            result = agent.prompt(request) => result,
            () = driver => unreachable!("the scheduler channel stays open"),
        };
        assert!(result.is_err(), "prompt() must fail while the session is still parked");
    });
}

/// Round 3 #2: a scheduled fire on a CHILD of a parked root is folded for the root: no turn on the child, the root
/// stays parked, and the text rides the root's next real prompt.
#[test]
fn a_scheduled_fire_on_a_child_of_a_parked_root_is_folded_and_starts_no_turn() {
    use acp::Agent as _;
    run_local_for_bridge_test(|| async {
        let agent = std::rc::Rc::new(build_minimal_agent_for_tests());
        let root_owned = fresh("fire-root");
        let child_owned = fresh("fire-child");
        let (root, child) = (root_owned.as_str(), child_owned.as_str());
        let _unpark = UnparkOnDrop(root_owned.clone());
        let _link = quiesce::SessionGuard::new(child, Some(root));
        let root_sid = acp::SessionId::new(root_owned.clone());
        let child_sid = acp::SessionId::new(child_owned.clone());
        let (mut root_rx, mut sched_rx) = insert_session(&agent, &root_sid);
        let (mut child_rx, _child_sched) = insert_session(&agent, &child_sid);
        let text = crate::session::cron_fire_tickets::scheduled_prompt_text("child cron job", "task-9", "every 5m");
        let ticket = crate::session::cron_fire_tickets::mint(child, &text);
        let op = quiesce::begin_park(root, ParkMode::Hold).expect("park");
        assert!(quiesce::complete_park(root, op));
        assert!(quiesce::ack_park(root, op, 0));

        let fire = acp::PromptRequest::new(child_sid.clone(), vec![acp::ContentBlock::Text(acp::TextContent::new(text))])
            .meta(serde_json::json!({ "promptId": format!("scheduler-fired-{ticket}"), "mode": "agent" }).as_object().cloned());
        let reply = tokio::time::timeout(Duration::from_secs(5), agent.prompt(fire))
            .await
            .expect("a child fire under a parked root must return at once, not start a turn")
            .expect("a folded fire gets a normal reply");
        assert_eq!(reply.stop_reason, acp::StopReason::EndTurn);
        assert_eq!(quiesce::entry(root).map(|e| e.phase), Some(ParkPhase::Parked), "the fire un-parked the root");
        while let Ok(cmd) = child_rx.try_recv() {
            assert!(!matches!(cmd, SessionCommand::Prompt { .. }), "a fire started a turn on the child");
        }

        let normal = acp::PromptRequest::new(root_sid.clone(), vec![acp::ContentBlock::Text(acp::TextContent::new("hello".to_owned()))])
            .meta(serde_json::json!({ "mode": "agent" }).as_object().cloned());
        let prompting = std::rc::Rc::clone(&agent);
        let task = tokio::task::spawn_local(async move { prompting.prompt(normal).await });
        let driver = async {
            let Some(SchedulerCommand::SetPaused { reply, fold, .. }) = sched_rx.recv().await else {
                panic!("the normal prompt did not fold");
            };
            let _ = reply.send(FoldReply { id: fold.as_ref().map(|f| f.id), fires: Vec::new() });
            while let Some(cmd) = root_rx.recv().await {
                if let SessionCommand::QuiesceRelease { reminder, .. } = cmd {
                    return reminder;
                }
            }
            None
        };
        let reminder = tokio::time::timeout(Duration::from_secs(5), driver).await.expect("no release");
        task.abort();
        let reminder = reminder.expect("the release carried no reminder");
        assert!(reminder.contains("child cron job"), "the child's fire is missing from the root's next prompt: {reminder}");
    });
}

/// Round 3 #5: a fire that arrives while the session is `Unparking` takes the normal path; it queues no second
/// `QuiesceRelease` for the op that is already releasing.
#[test]
fn a_scheduled_fire_during_unparking_queues_no_second_release() {
    use acp::Agent as _;
    run_local_for_bridge_test(|| async {
        let agent = std::rc::Rc::new(build_minimal_agent_for_tests());
        let id_owned = fresh("fire-unparking");
        let id = id_owned.as_str();
        let _unpark = UnparkOnDrop(id_owned.clone());
        let sid = acp::SessionId::new(id_owned.clone());
        let (mut cmd_rx, _sched_rx) = insert_session(&agent, &sid);
        let text = crate::session::cron_fire_tickets::scheduled_prompt_text("late job", "task-2", "every 5m");
        let ticket = crate::session::cron_fire_tickets::mint(id, &text);
        let op = quiesce::begin_park(id, ParkMode::Hold).expect("park");
        assert!(quiesce::complete_park(id, op));
        assert!(quiesce::begin_implicit_unpark(id, op).is_some());
        let fire = acp::PromptRequest::new(sid.clone(), vec![acp::ContentBlock::Text(acp::TextContent::new(text))])
            .meta(serde_json::json!({ "promptId": format!("scheduler-fired-{ticket}"), "mode": "agent" }).as_object().cloned());
        let prompting = std::rc::Rc::clone(&agent);
        let task = tokio::task::spawn_local(async move { prompting.prompt(fire).await });
        tokio::time::sleep(Duration::from_millis(500)).await;
        task.abort();
        // The mock session has no actor: the fire only reaches the command channel. It must not have removed the entry
        // (only the client prompt that began the un-park finishes it); the real-actor test for the turn is
        // `a_scheduled_fire_during_unparking_neither_finishes_the_unpark_nor_starts_a_turn` (park_tests.rs).
        assert_eq!(quiesce::entry(id).map(|e| e.phase), Some(ParkPhase::Unparking), "the fire finished the un-park");
        while let Ok(cmd) = cmd_rx.try_recv() {
            assert!(!matches!(cmd, SessionCommand::QuiesceRelease { .. }), "a fire during Unparking queued a second release");
        }
    });
}
