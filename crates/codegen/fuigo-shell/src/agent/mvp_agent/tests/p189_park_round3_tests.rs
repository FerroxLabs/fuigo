//! P189 round 3 group B: the park/unpark state machine, driven through the real `handle_park` /
//! `implicit_unpark` against a hand-made session actor and scheduler.

use std::time::{Duration, Instant};

use agent_client_protocol as acp;
use fuigo_tools::implementations::fuigo_build::scheduler::types::{
    FoldReply, FoldedFire, SchedulerCommand, SchedulerHandle,
};
use tokio::sync::mpsc;

use super::{build_minimal_agent_for_tests, make_test_handle, run_local_for_bridge_test};
use crate::extensions::session_park::{handle_park, implicit_unpark};
use crate::session::SessionCommand;
use crate::session::quiesce::{self, ParkMode, QuiesceReport};

pub(super) fn park_request(sid: &str, mode: &str, timeout_ms: u64) -> acp::ExtRequest {
    let raw = serde_json::value::to_raw_value(
        &serde_json::json!({ "sessionId": sid, "mode": mode, "timeoutMs": timeout_ms }),
    )
    .unwrap();
    acp::ExtRequest::new("_fuigo/session/park", std::sync::Arc::from(raw))
}

/// A resident session whose actor channel and scheduler channel the test owns.
pub(super) fn insert_session(
    agent: &super::MvpAgent,
    sid: &acp::SessionId,
) -> (
    mpsc::UnboundedReceiver<SessionCommand>,
    mpsc::UnboundedReceiver<SchedulerCommand>,
) {
    let mut handle = make_test_handle("test", false, None);
    handle.info.id = sid.clone();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    handle.cmd_tx = cmd_tx;
    let (sched_tx, sched_rx) = mpsc::unbounded_channel();
    handle.scheduler_handle = Some(SchedulerHandle(sched_tx));
    agent.insert_resident(sid, handle);
    (cmd_rx, sched_rx)
}

/// Astra r2 #10: `timeoutMs: 1` with a scheduler that never acknowledges the pause or the resume replies within
/// about 5 s (`start + timeoutMs + 5 s`), not 10 s.
#[test]
fn park_replies_within_one_overall_deadline_when_the_scheduler_never_answers() {
    run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("p189r3-deadline");
        let (_cmd_rx, _sched_rx) = insert_session(&agent, &sid);
        let started = Instant::now();
        let result = handle_park(&agent, &park_request("p189r3-deadline", "hold", 1)).await;
        let took = started.elapsed();
        assert!(result.is_err(), "a park whose scheduler never answers must fail");
        assert!(took < Duration::from_secs(7), "the park took {took:?}, over one overall deadline");
        assert!(quiesce::entry("p189r3-deadline").is_none(), "the failed park left an entry");
    });
}

/// F7: a park for a session whose `session/load` never finishes answers within about `timeoutMs + 5 s` (the one
/// overall deadline starts at `handle_park` entry and bounds the load wait), not after the 60 s load wait.
#[test]
fn park_replies_within_the_overall_deadline_when_load_never_finishes() {
    run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("p189r4-load-never");
        let _load = agent.begin_session_load(&sid); // held for the whole test: the load never finishes
        let started = Instant::now();
        let result = handle_park(&agent, &park_request("p189r4-load-never", "hold", 1000)).await;
        let took = started.elapsed();
        assert!(result.is_err(), "a park whose session never finishes loading must fail");
        assert!(took < Duration::from_secs(8), "the park took {took:?}, over timeoutMs + 5 s");
        assert!(quiesce::entry("p189r4-load-never").is_none(), "the failed park left an entry");
    });
}

/// Astra r2 #7: when the `QuiesceRelease` cannot be queued the scheduler fold is NOT committed.
#[test]
fn implicit_unpark_does_not_commit_the_fold_when_the_release_was_not_queued() {
    run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("p189r3-fold");
        let (cmd_rx, mut sched_rx) = insert_session(&agent, &sid);
        drop(cmd_rx); // the actor is gone: the release cannot be queued
        let op = quiesce::begin_park("p189r3-fold", ParkMode::Hold).expect("park");
        assert!(op > 0);
        let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
        tokio::task::spawn_local(async move {
            if let Some(SchedulerCommand::SetPaused { reply, fold, .. }) = sched_rx.recv().await {
                let id = fold.as_ref().map(|f| f.id);
                let _ = reply.send(FoldReply {
                    id,
                    fires: vec![FoldedFire {
                        task_id: "t1".into(),
                        prompt: "p".into(),
                        human_schedule: "every minute".into(),
                    }],
                });
                let committed = match fold {
                    Some(fold) => fold.commit.await.is_ok_and(|c| Some(c) == id),
                    None => false,
                };
                let _ = outcome_tx.send(committed);
            }
        });
        let session = agent.session_handle_waiting_for_load(&sid).await.expect("session");
        let _guard = implicit_unpark(&agent, &session, "p189r3-fold").await;
        let committed = tokio::time::timeout(Duration::from_secs(3), outcome_rx)
            .await
            .expect("the scheduler saw the fold")
            .expect("outcome");
        assert!(!committed, "the fold was committed although the release was never queued");
        quiesce::unpark("p189r3-fold");
    });
}

/// Astra r2 #8: the cancel generation does not move while the scheduler fold is still being awaited, and moves
/// once the park has become `Unparking`.
#[test]
fn implicit_unpark_bumps_the_generation_only_after_the_fold() {
    run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("p189r3-gen");
        let (_cmd_rx, mut sched_rx) = insert_session(&agent, &sid);
        let op = quiesce::begin_park("p189r3-gen", ParkMode::Hold).expect("park");
        assert!(quiesce::complete_park("p189r3-gen", op));
        let session = agent.session_handle_waiting_for_load(&sid).await.expect("session");
        let driver = async {
            let Some(SchedulerCommand::SetPaused { reply, .. }) = sched_rx.recv().await else {
                panic!("the fold was never requested");
            };
            assert_eq!(
                quiesce::cancel_generation("p189r3-gen"),
                0,
                "the generation moved while the fold was still awaited"
            );
            assert!(quiesce::is_parked("p189r3-gen"), "the park stopped holding before the fold answered");
            let _ = reply.send(FoldReply::default());
        };
        let (_guard, ()) = tokio::join!(implicit_unpark(&agent, &session, "p189r3-gen"), driver);
        assert_eq!(quiesce::cancel_generation("p189r3-gen"), 1);
        quiesce::unpark("p189r3-gen");
    });
}

/// Astra r2 #4: an idempotent park whose park was withdrawn while its probe was in flight must not reply
/// `parked: true`.
#[test]
fn idempotent_park_rechecks_its_entry_after_the_probe() {
    run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("p189r3-idem");
        let (mut cmd_rx, _sched_rx) = insert_session(&agent, &sid);
        let op = quiesce::begin_park("p189r3-idem", ParkMode::Hold).expect("park");
        assert!(quiesce::complete_park("p189r3-idem", op));
        assert!(quiesce::ack_park("p189r3-idem", op, 0));
        tokio::task::spawn_local(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                if let SessionCommand::Quiesce { respond_to, .. } = cmd {
                    // The probe is in flight: an explicit unpark ends the park, then the actor answers.
                    quiesce::unpark("p189r3-idem");
                    let _ = respond_to.send(QuiesceReport::default());
                }
            }
        });
        let result = handle_park(&agent, &park_request("p189r3-idem", "hold", 1000)).await;
        assert!(result.is_err(), "an idempotent park replied parked:true for a park that no longer exists");
    });
}

#[test]
fn the_modes_list_drives_the_advertisement_and_the_gate() {
    let cap = super::super::acp_agent::session_park_capability();
    let names: Vec<String> = serde_json::from_value(cap["modes"].clone()).expect("modes");
    assert_eq!(names, quiesce::advertised_modes());
    assert_eq!(names, ["hold"], "P189 A1: stop is not available on any OS");
    assert!(ParkMode::Hold.advertised());
    assert!(!ParkMode::Stop.advertised());
}

fn running_task(id: &str) -> fuigo_tools::types::TaskSnapshot {
    serde_json::from_value(serde_json::json!({
        "task_id": id,
        "command": "sleep 100",
        "cwd": "/",
        "start_time": { "secs_since_epoch": 1, "nanos_since_epoch": 0 },
        "end_time": null,
        "output": "",
        "output_file": "/dev/null",
        "truncated": false,
        "exit_code": null,
        "signal": null,
        "completed": false
    }))
    .expect("task snapshot")
}

/// F3: `implicit_unpark` of park P, whose fold was awaited while P was replaced by Q, unparks Q (one retry from
/// the fresh entry) and never transitions Q by P's identity.
#[test]
fn implicit_unpark_of_p_does_not_transition_replacement_q() {
    run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("p189r4-pq");
        let (_cmd_rx, mut sched_rx) = insert_session(&agent, &sid);
        let p = quiesce::begin_park("p189r4-pq", ParkMode::Hold).expect("park P");
        assert!(quiesce::complete_park("p189r4-pq", p));
        let session = agent.session_handle_waiting_for_load(&sid).await.expect("session");
        let mut ops_seen = Vec::new();
        let driver = async {
            // First fold: P is withdrawn and replaced by Q while the scheduler is answering.
            let Some(SchedulerCommand::SetPaused { op, reply, fold, .. }) = sched_rx.recv().await else {
                panic!("no fold");
            };
            ops_seen.push(op);
            quiesce::withdraw("p189r4-pq", p);
            let q = quiesce::begin_park("p189r4-pq", ParkMode::Hold).expect("park Q");
            assert!(q > p);
            let _ = reply.send(FoldReply { id: fold.as_ref().map(|f| f.id), fires: Vec::new() });
            // Second fold, for Q's op.
            let Some(SchedulerCommand::SetPaused { op, reply, fold, .. }) = sched_rx.recv().await else {
                panic!("no retry");
            };
            ops_seen.push(op);
            assert_eq!(op, q, "the retry must fold Q's op, not P's");
            let _ = reply.send(FoldReply { id: fold.as_ref().map(|f| f.id), fires: Vec::new() });
            q
        };
        let (guard, q) = tokio::join!(implicit_unpark(&agent, &session, "p189r4-pq"), driver);
        assert_eq!(ops_seen.len(), 2);
        let guard = guard.expect("Q was unparked by the prompt");
        assert_eq!(quiesce::entry("p189r4-pq").map(|e| (e.op, e.phase)), Some((q, quiesce::ParkPhase::Unparking)));
        drop(guard);
        quiesce::unpark("p189r4-pq");
    });
}
