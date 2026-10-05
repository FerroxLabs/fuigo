//! P09-F2: a deferred recovery's late marker reaches every client exactly once, through the REAL
//! `MvpAgent::finish_deferred_recovery` and the real delta-replay reader, observed at the agent's gateway.
//!
//! "Two clients": the leader routes by the `fuigo/leaderClientId` stamp the agent puts on a notification. A replay
//! aimed at the loading client A carries that stamp (A alone gets it); an unstamped notification is broadcast to every
//! subscriber, B included. So B's delivery is "an unstamped, non-replay marker reached the gateway", and A is
//! double-served when an unstamped marker follows an unstamped replay of the same marker. The leader itself and a
//! second ACP connection are not in this loop (the agent test harness has one connection; stalling the real
//! persistence actor past the recovery bound needs a seam that does not exist), so the stamp contract is the model.

use std::cell::RefCell;
use std::rc::Rc;

use agent_client_protocol as acp;
use serde_json::Value;

use super::{build_agent_with_gateway_rx, make_live_session_handle, run_local_for_bridge_test};
use crate::session::info::Info;
use crate::session::interrupted_turn::{
    BroadcastReplay, RecoveryOutcome, recover_interrupted_turn,
};
use crate::session::persistence::{DurableAppendError, Summary, default_model_id};
use crate::session::storage::{SessionUpdate, SessionUpdateEnvelope};

const SID: &str = "deferred-marker-delivery";
const TURN_STARTED: &str = r#"{"ts":"2026-09-29T00:00:01.000Z","type":"turn_started","session_id":"deferred-marker-delivery","turn_number":3,"model_id":"m","yolo_mode":false,"conversation_message_count":2,"session_relationship":"root","schema_version":"1.0"}"#;
const SEED: &str = r#"{"timestamp":1,"method":"session/update","params":{"n":1}}"#;
const LATE: std::time::Duration = std::time::Duration::from_secs(15);

/// One interrupted-turn marker as the gateway saw it.
#[derive(Debug)]
struct Seen {
    replay: bool,
    stamped_for: Option<Value>,
}

#[derive(Clone, Copy, PartialEq)]
enum Lands {
    /// The marker is on disk before the load's replay reads: the replay carries it.
    BeforeTheReplay,
    /// It lands only when the append is acknowledged, after the replay has finished reading.
    AfterTheReplay,
}

/// Pumps the gateway: records every interrupted-turn marker notification and acknowledges everything.
fn pump(
    mut gw_rx: tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
) -> Rc<RefCell<Vec<Seen>>> {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let sink = Rc::clone(&seen);
    tokio::task::spawn_local(async move {
        while let Some(message) = gw_rx.recv().await {
            if let fuigo_acp_lib::AcpClientMessage::ExtNotification(args) = message {
                if let Ok(params) = serde_json::from_str::<Value>(args.request.params.get())
                    && params["update"]["stop_reason"] == "interrupted"
                {
                    sink.borrow_mut().push(Seen {
                        replay: params["_meta"]["isReplay"] == true,
                        stamped_for: params["_meta"].get("fuigo/leaderClientId").cloned(),
                    });
                }
                let _ = args.response_tx.send(Ok(()));
            }
        }
    });
    seen
}

fn write_marker(updates: &std::path::Path, update: &SessionUpdate) {
    let line = serde_json::to_string(&SessionUpdateEnvelope::from_update(update).expect("envelope"))
        .expect("serialize");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(updates)
        .expect("open updates");
    std::io::Write::write_all(&mut file, format!("{line}\n").as_bytes()).expect("append");
}

/// Runs a deferred recovery for a resident session and a load that replayed with `target` (the loading client, or
/// `None` for a broadcast replay), then returns what the gateway saw.
async fn run(lands: Lands, target: Option<Value>) -> Vec<Seen> {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("events.jsonl"), format!("{TURN_STARTED}\n")).expect("events");
    let updates = dir.path().join("updates.jsonl");
    std::fs::write(&updates, format!("{SEED}\n")).expect("updates");
    let mut summary = Summary::new(
        &Info {
            id: acp::SessionId::new(SID),
            cwd: dir.path().to_string_lossy().into_owned(),
        },
        default_model_id(),
    )
    .expect("summary");
    summary.next_trace_turn = 4;
    summary.request_id = Some("req-abc".into());

    let (agent, gw_rx) = build_agent_with_gateway_rx();
    let seen = pump(gw_rx);
    let sid = acp::SessionId::new(SID);
    let (handle, _cmd_tx, _cmd_rx) = make_live_session_handle(&sid, None);
    agent.insert_resident(&sid, handle);

    let marker_path = updates.clone();
    let append = move |update: SessionUpdate| {
        if lands == Lands::BeforeTheReplay {
            write_marker(&marker_path, &update);
        }
        Box::pin(async move {
            tokio::time::sleep(LATE).await;
            if lands == Lands::AfterTheReplay {
                write_marker(&marker_path, &update);
            }
            Ok::<(), DurableAppendError>(())
        })
    };
    let Some(RecoveryOutcome::Deferred(deferred)) =
        recover_interrupted_turn(dir.path(), Some(&updates), &summary, &sid, append).await
    else {
        panic!("an append past the bound must defer");
    };

    // The load's replay, run for real right after recovery returned `Deferred`.
    let (completions, read_through) = agent.replay_session_updates_from_offset_enqueue(
        &sid,
        &Some(updates.clone()),
        0,
        None,
        target.as_ref(),
        true,
    );
    for completion in completions {
        let _ = completion.await;
    }
    agent
        .finish_deferred_recovery(
            sid,
            deferred,
            BroadcastReplay::new(Some(updates), Some(read_through), target.as_ref()),
        )
        .await
        .expect("finish task");
    // Let the pump drain what the forwards enqueued.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    std::mem::take(&mut *seen.borrow_mut())
}

/// Mutants discriminated: forwarding the late marker unconditionally at the call site, or handing the finisher no
/// `BroadcastReplay`. Client A's broadcast replay already carried the marker to A and B; a live copy duplicates it.
#[test]
fn a_broadcast_replay_that_carried_the_marker_is_not_followed_by_a_live_copy() {
    run_local_for_bridge_test(|| async {
        tokio::time::pause();
        let seen = run(Lands::BeforeTheReplay, None).await;
        assert_eq!(seen.len(), 1, "exactly one delivery to every client: {seen:?}");
        assert!(seen[0].replay && seen[0].stamped_for.is_none(), "{seen:?}");
    });
}

/// Mutant discriminated: `BroadcastReplay::new` ignoring the target (the round-1 HIGH). The replay was aimed at
/// client A alone, so client B has not seen the marker and must still get the live copy.
#[test]
fn a_targeted_replay_does_not_suppress_client_bs_live_delivery() {
    run_local_for_bridge_test(|| async {
        tokio::time::pause();
        // The leader injects the loading client's numeric `ClientId`; it reads it back with `as_u64()`
        // (`leader/server.rs::extract_target_client_id`), and anything else broadcasts.
        let a = Value::from(7_u64);
        assert_eq!(a.as_u64(), Some(7));
        let seen = run(Lands::BeforeTheReplay, Some(a.clone())).await;
        assert_eq!(seen.len(), 2, "A's replay plus B's live copy: {seen:?}");
        assert!(
            seen.iter().any(|s| s.replay && s.stamped_for.as_ref() == Some(&a)),
            "the replay is for A alone: {seen:?}"
        );
        assert!(
            seen.iter().any(|s| !s.replay && s.stamped_for.is_none()),
            "B gets an unstamped live marker: {seen:?}"
        );
    });
}

/// A marker that lands after the replay's last read is not in the replay for anyone: one live copy, no more, no less.
#[test]
fn a_marker_that_lands_after_the_replay_is_delivered_live_once() {
    run_local_for_bridge_test(|| async {
        tokio::time::pause();
        let seen = run(Lands::AfterTheReplay, None).await;
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(!seen[0].replay && seen[0].stamped_for.is_none(), "{seen:?}");
    });
}
