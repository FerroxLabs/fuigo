//! Unit-level resume and close: request translation, kind resolution, and close ordering.
//! Protocol behavior is asserted on the wire in `tests/acp_session_setup_wire.rs`.
use crate::agent::mvp_agent::session_lifecycle::{
    CLOSE_INTAKE_WAIT, CLOSE_TOTAL_BUDGET, CloseOutcome,
};
use crate::agent::mvp_agent::session_setup::{
    AttachOperation, AttachPolicy, RESUME_REFUSES_CHAT, RESUME_REFUSES_EXTRA_DIRS,
    load_request_for_resume,
};
use crate::session::SessionLiveState;
use agent_client_protocol as acp;
use pretty_assertions::assert_eq;
use serde_json::json;
fn meta_of(value: serde_json::Value) -> acp::Meta {
    value.as_object().cloned().expect("meta must be an object")
}
fn mcp_servers() -> Vec<acp::McpServer> {
    vec![acp::McpServer::Stdio(
        acp::McpServerStdio::new("filesystem", std::path::PathBuf::from("/bin/mcp"))
            .args(vec!["--stdio".to_string()]),
    )]
}
fn resume_request(meta: serde_json::Value) -> acp::ResumeSessionRequest {
    acp::ResumeSessionRequest::new(
        acp::SessionId::new("sess-resume"),
        std::path::PathBuf::from("/tmp/proj"),
    )
    .mcp_servers(mcp_servers())
    .meta(meta_of(meta))
}
/// A `SessionThread` the sweep will see as finished.
async fn exited_thread() -> crate::session::SessionThread {
    let thread = crate::session::SessionThread::from_handle(std::thread::spawn(|| {}));
    while !thread.is_finished() {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    thread
}
fn expected_load(meta: serde_json::Value) -> acp::LoadSessionRequest {
    acp::LoadSessionRequest::new(
        acp::SessionId::new("sess-resume"),
        std::path::PathBuf::from("/tmp/proj"),
    )
    .mcp_servers(mcp_servers())
    .meta(meta_of(meta))
}
/// The load path drops these, so resume must refuse rather than pretend.
/// The message is asserted because a test agent has several ways to reach `invalid_params`, and the generic code alone passes without the guard.
#[test]
fn resume_refuses_additional_directories_it_cannot_honor() {
    super::run_local_for_bridge_test(|| async {
        use acp::Agent as _;
        let err = super::build_minimal_agent_for_tests()
            .resume_session(
                resume_request(json!({}))
                    .additional_directories(vec![std::path::PathBuf::from("/tmp/extra")]),
            )
            .await
            .expect_err("resume must refuse roots it drops");
        assert_eq!(err.code, acp::Error::invalid_params().code);
        let data = err.data.expect("typed data");
        assert_eq!(data["message"], RESUME_REFUSES_EXTRA_DIRS);
        assert_eq!(data["error_kind"], "invalid_request");
    });
}
/// Every input is crossed with both methods, because the interesting cases are the interactions.
/// An explicit `_meta` request outranks resume's defaults, and the agent's own `restore_code` does not reach resume at all.
#[test]
fn attach_policy_gives_resume_no_replay_and_no_unasked_checkout() {
    let policy = |op, meta: serde_json::Value, agent_restore_code| {
        AttachPolicy::resolve(op, Some(&meta_of(meta)), agent_restore_code)
    };
    let expect = |no_replay, restore_code| AttachPolicy {
        no_replay,
        restore_code,
    };
    assert_eq!(
        policy(AttachOperation::Resume, json!({}), true),
        expect(true, false),
        "resume must not replay, and must not inherit the agent's restore_code"
    );
    assert_eq!(
        policy(AttachOperation::Resume, json!({ "noReplay": false }), false),
        expect(true, false),
        "the spec fixes resume at no-replay, so a client cannot ask for one"
    );
    assert_eq!(
        policy(
            AttachOperation::Resume,
            json!({ "fuigo/restore_code": true }),
            false
        ),
        expect(true, false),
        "not even on request: resume can land mid-turn, and a checkout would \
         move files under the turn it is reattaching to"
    );
    assert_eq!(
        policy(AttachOperation::Load, json!({}), true),
        expect(false, true),
        "load replays and honors the agent's restore_code"
    );
    assert_eq!(
        policy(
            AttachOperation::Load,
            json!({ "noReplay": true, "fuigo/restore_code": false }),
            true
        ),
        expect(true, false),
        "load takes both from the client when the client states them"
    );
}
/// The translation carries shape, not policy: a client's `_meta` reaches the load path unedited now that intent is carried on `AttachOperation`.
#[test]
fn resume_translation_does_not_rewrite_client_meta() {
    assert_eq!(
        load_request_for_resume(resume_request(
            json!({ "noReplay": false, "fuigo/restore_code": true })
        )),
        expected_load(json!({ "noReplay": false, "fuigo/restore_code": true })),
    );
}
/// A chat load rebuilds the session under the same id, so a close waiting on intake can find a live replacement with a client attached.
/// Closing by id alone ends that replacement; this pins that it does not.
#[test]
fn close_does_not_free_a_session_that_replaced_its_target() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-replaced");
        let (original, _tx, _rx) = super::make_live_session_handle(&sid, Some("turn-1"));
        agent.insert_resident(&sid, original);
        let intake = agent.dispatch_lock(&sid);
        let intake_guard = intake.lock().await;
        let mut close = std::pin::pin!(agent.close_active_session(&sid));
        assert!(futures::poll!(close.as_mut()).is_pending());
        let (replacement, _tx2, _rx2) = super::make_live_session_handle(&sid, Some("turn-2"));
        agent.insert_resident(&sid, replacement);
        drop(intake_guard);
        assert_eq!(
            close.await,
            CloseOutcome::Superseded,
            "a close whose target was replaced must say so, not report NotResident"
        );
        assert!(
            agent.is_resident(&sid),
            "close must leave the session that replaced its target"
        );
        assert!(
            agent.finalize_spy.borrow().is_empty(),
            "finalizing a replacement would end a live session"
        );
    });
}
/// `attach_session` sweeps before it drains.
/// The thread here is the evicted actor's, and the sweep's not-resident branch would drop it out from under the drain about to wait on it.
#[test]
fn the_sweep_leaves_an_evicted_session_mid_attach() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-attach-sweep");
        agent
            .session_registry
            .set_thread(&sid, exited_thread().await);
        let _attach = agent.begin_session_load(&sid);
        agent.sweep_dead_sessions();
        assert!(
            agent.session_registry.has_thread(&sid),
            "the drain still has to wait on the old actor's thread"
        );
    });
}
/// The other half: once the session is resident again, a finished thread means the actor died.
/// Skipping the reap there leaves the attach reusing a dead channel and reporting success.
#[test]
fn the_sweep_still_reaps_a_resident_session_whose_actor_died_mid_attach() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-attach-crashed");
        let (handle, _tx, _rx) = super::make_live_session_handle(&sid, None);
        agent.insert_resident(&sid, handle);
        agent
            .session_registry
            .set_thread(&sid, exited_thread().await);
        let _attach = agent.begin_session_load(&sid);
        agent.sweep_dead_sessions();
        assert!(
            !agent.is_resident(&sid),
            "a resident session with a dead actor must still be reaped, or the \
             attach hands the client a channel nobody is reading"
        );
    });
}
/// The drain exists for a session that was evicted and is still flushing.
/// A resident session's thread is the actor this attach reuses, so it never finishes, and draining it spends the whole budget on every reconnect.
#[test]
fn attaching_to_a_resident_session_does_not_wait_on_its_live_thread() {
    use acp::Agent as _;
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-resident-attach");
        let (handle, _tx, _rx) = super::make_live_session_handle(&sid, None);
        agent.insert_resident(&sid, handle);
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        agent.session_registry.set_thread(
            &sid,
            crate::session::SessionThread::from_handle(std::thread::spawn(move || {
                let _ = stop_rx.recv();
            })),
        );
        let mut attach = std::pin::pin!(agent.load_session(acp::LoadSessionRequest::new(
            sid.clone(),
            std::path::PathBuf::from("/tmp/proj"),
        )));
        assert!(
            futures::poll!(attach.as_mut()).is_ready(),
            "the attach must reach its first real await without draining"
        );
        drop(stop_tx);
    });
}
/// The load guard publishes `Attaching`, so it must retire it: left set, a failed attach stays transitional and its thread is never reaped.
#[test]
fn a_failed_attach_leaves_no_trace() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-attaching");
        {
            let _guard = agent.begin_session_load(&sid);
            assert_eq!(
                agent.session_live_state_for(&sid),
                Some(SessionLiveState::Attaching),
                "an in-flight load publishes Attaching"
            );
            agent.session_registry.set_turn_number(&sid, 7);
        }
        assert_eq!(
            agent.session_live_state_for(&sid),
            None,
            "a load that produced nothing must leave no lifecycle state behind"
        );
        assert_eq!(
            agent.session_registry.counts().entries,
            0,
            "and no registry entry either: an attach populates the entry before \
             it registers a handle, so clearing one field is not enough"
        );
    });
}
/// A load registers its handle and then keeps running.
/// Closing on handle presence alone frees the session out from under the rest of that load.
#[test]
fn close_waits_for_an_in_flight_load_to_settle() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-cold-load");
        let guard = agent.begin_session_load(&sid);
        let (handle, _tx, _rx) = super::make_live_session_handle(&sid, None);
        agent.insert_resident(&sid, handle);
        let mut close = std::pin::pin!(agent.close_active_session(&sid));
        assert!(
            futures::poll!(close.as_mut()).is_pending(),
            "close must not free a session whose load is still running"
        );
        drop(guard);
        assert_eq!(close.await, CloseOutcome::Closed);
        assert!(!agent.is_resident(&sid));
    });
}
/// Concurrent attaches capture each other's `Attaching`, so the displaced `Working` is unrecoverable from the capture.
/// The guard must ask the handle; recording `IdleResident` here would misreport a running turn.
#[test]
fn an_attach_over_a_running_turn_settles_back_to_working() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-attach-midturn");
        let (handle, _tx, _rx) = super::make_live_session_handle(&sid, Some("turn-1"));
        agent.insert_resident(&sid, handle);
        agent.set_session_live_state(&sid, SessionLiveState::Working);
        {
            let _first = agent.begin_session_load(&sid);
            let _second = agent.begin_session_load(&sid);
        }
        assert_eq!(
            agent.session_live_state_for(&sid),
            Some(SessionLiveState::Working),
            "the turn is still running, so the attach must not record it idle"
        );
    });
}
/// A second load supersedes the first.
/// The older guard must not retire the state the newer attach is still relying on.
#[test]
fn a_superseded_load_leaves_the_newer_attach_attaching() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-superseded-load");
        let first = agent.begin_session_load(&sid);
        let _second = agent.begin_session_load(&sid);
        drop(first);
        assert_eq!(
            agent.session_live_state_for(&sid),
            Some(SessionLiveState::Attaching),
            "the newer load still owns the attach"
        );
    });
}
/// The other half of the ordering contract: the wait is bounded.
/// A prompt whose intake preamble stalls, on an auth refresh say, must not hold the close open with it.
/// Time is paused, so this pins the timeout rather than sleeping on it.
#[test]
fn close_gives_up_on_an_intake_that_stalls() {
    use acp::Agent as _;
    super::run_local_for_bridge_test(|| async {
        tokio::time::pause();
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-stalled-intake");
        let (handle, _tx, _rx) = super::make_live_session_handle(&sid, Some("turn-1"));
        agent.insert_resident(&sid, handle);
        let intake = agent.dispatch_lock(&sid);
        let _never_released = intake.lock().await;
        let mut close =
            std::pin::pin!(agent.close_session(acp::CloseSessionRequest::new(sid.clone())));
        assert!(
            futures::poll!(close.as_mut()).is_pending(),
            "close waits for intake first"
        );
        tokio::time::timeout(CLOSE_INTAKE_WAIT * 10, close)
            .await
            .expect("close must give up on the intake, not wait on it forever")
            .expect("close responds once it stops waiting");
        assert!(
            !agent.is_resident(&sid),
            "close must still free the session it gave up ordering behind"
        );
    });
}
/// Every stage stalled at once must still answer within [`CLOSE_TOTAL_BUDGET`], not settle, intake, and drain stacked end to end.
/// Time is paused; reverting the `stage_budget` shrinking fails the elapsed assertion.
#[test]
fn close_answers_within_the_aggregate_budget() {
    super::run_local_for_bridge_test(|| async {
        tokio::time::pause();
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-aggregate-budget");
        let (handle, _tx, _rx) = super::make_live_session_handle(&sid, Some("turn-1"));
        agent.insert_resident(&sid, handle);
        let _stuck_load = agent.begin_session_load(&sid);
        let intake = agent.dispatch_lock(&sid);
        let _never_released = intake.lock().await;
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        agent.session_registry.set_thread(
            &sid,
            crate::session::SessionThread::from_handle(std::thread::spawn(move || {
                let _ = stop_rx.recv();
            })),
        );
        let started = tokio::time::Instant::now();
        let outcome = agent.close_active_session(&sid).await;
        assert_eq!(outcome, CloseOutcome::Closed);
        assert!(
            started.elapsed() <= CLOSE_TOTAL_BUDGET + std::time::Duration::from_secs(1),
            "every stage stalled, and close still waited {:?}: the aggregate \
             budget must cap the sum, not let the stages stack",
            started.elapsed()
        );
        drop(stop_tx);
    });
}
/// F5-C5/F5-T (design F5 §6.1): the session's end sends the persistence task `ReleaseWriter` (as `spawn.rs` does after
/// `run_session`), and close waits for the task's tail flush and release, so the writer is free when close answers
/// "closed", inside the close budget, even while another handle to the persistence task is still held (a held handle
/// alone keeps the task, and so its clone, alive).
#[test]
fn close_frees_the_persistence_writer_while_a_persistence_handle_is_still_held() {
    super::run_local_for_bridge_test(|| async {
        let home = tempfile::TempDir::new().unwrap();
        let sid = acp::SessionId::new(format!("sess-close-release-{}", uuid::Uuid::now_v7()));
        let dir = home.path().join(sid.0.as_ref());
        let writer = fuigo_session_writer::SessionWriter::try_claim(sid.0.to_string(), &dir).expect("claim");
        let persistence = crate::session::persistence::new_with_explicit_dir(
            &crate::session::info::Info { id: sid.clone(), cwd: "/tmp".to_string() },
            dir.clone(),
            crate::session::persistence::default_model_id(),
            crate::sampling::Client::new(fuigo_sampler::SamplerConfig::default()).unwrap(),
            "test-model".to_owned(),
            writer,
        )
        .await
        .expect("persistence task starts");
        let held = persistence.clone();
        let agent = super::build_minimal_agent_for_tests();
        let (mut handle, _tx, _rx) = super::make_live_session_handle(&sid, None);
        handle.persistence_tx = persistence.tx.clone();
        let session_end = persistence.tx.clone();
        tokio::task::spawn_local(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            let _ = session_end.send(crate::session::persistence::PersistenceMsg::ReleaseWriter);
        });
        drop(persistence);
        agent.insert_resident(&sid, handle);
        agent.session_registry.set_thread(&sid, exited_thread().await);
        assert!(!fuigo_session_writer::SessionWriter::is_free(&sid.0), "the persistence task holds the writer");

        let started = tokio::time::Instant::now();
        assert_eq!(agent.close_active_session(&sid).await, CloseOutcome::Closed);
        let free = fuigo_session_writer::SessionWriter::is_free(&sid.0);
        let elapsed = started.elapsed();
        assert!(free, "close answered after {elapsed:?} with the persistence task's writer clone still held");
        assert!(elapsed < CLOSE_TOTAL_BUDGET, "close and the release took {elapsed:?}, over the budget");
        drop(held);
    });
}
/// F5-T CT1 (design F5 §6.1, §9.2): close never answers while a tail write still holds the session's writer (here the
/// `resources_state.json` channel-close flush, after the session thread has ended). 1.0.40 drained the thread only and
/// answered "closed" with the write still running. The tail outlasts close's 0.5 s resume-status wait, so only a
/// wait for the writer itself can cover it.
#[test]
fn f5t_ct1_close_never_answers_while_a_tail_write_still_holds_the_writer() {
    super::run_local_for_bridge_test(|| async {
        let home = tempfile::TempDir::new().unwrap();
        let sid = acp::SessionId::new(format!("sess-f5t-ct1-{}", uuid::Uuid::now_v7()));
        let writer =
            fuigo_session_writer::SessionWriter::try_claim(sid.0.to_string(), home.path().join(sid.0.as_ref()))
                .expect("claim");
        let agent = super::build_minimal_agent_for_tests();
        let (handle, _tx, _rx) = super::make_live_session_handle(&sid, None);
        agent.insert_resident(&sid, handle);
        agent.session_registry.set_thread(&sid, exited_thread().await);
        let tail = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(2000));
            let _ = writer.replace_atomic_sync("resources_state.json", b"{}");
            drop(writer);
        });
        let started = tokio::time::Instant::now();
        assert_eq!(agent.close_active_session(&sid).await, CloseOutcome::Closed);
        let elapsed = started.elapsed();
        assert!(
            fuigo_session_writer::SessionWriter::is_free(&sid.0),
            "close answered after {elapsed:?} while the tail write still held the writer"
        );
        assert!(elapsed < CLOSE_TOTAL_BUDGET, "close took {elapsed:?}, over the budget");
        tail.join().unwrap();
    });
}
/// The response carries what the close did, so a caller can see the quiet cases (`notResident`, `superseded`) without reading agent logs.
#[test]
fn close_reports_its_outcome_in_response_meta() {
    use acp::Agent as _;
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let response = agent
            .close_session(acp::CloseSessionRequest::new(acp::SessionId::new(
                "sess-never-seen",
            )))
            .await
            .expect("closing an inactive session succeeds");
        assert_eq!(
            response
                .meta
                .as_ref()
                .and_then(|m| m.get("fuigo/closeOutcome")),
            Some(&json!("notResident")),
            "the outcome must reach the client, not just the log line"
        );
    });
}
/// Close must not let `Cancel` overtake the prompt it is meant to cancel.
/// Holding the lock stands in for a prompt mid-intake: pending while held, resolved once released.
#[test]
fn close_orders_behind_prompt_intake() {
    use acp::Agent as _;
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-close-contended");
        let (handle, _tx, _rx) = super::make_live_session_handle(&sid, Some("turn-1"));
        agent.insert_resident(&sid, handle);
        let intake = agent.dispatch_lock(&sid);
        let intake_guard = intake.lock().await;
        let mut close =
            std::pin::pin!(agent.close_session(acp::CloseSessionRequest::new(sid.clone())));
        assert!(
            futures::poll!(close.as_mut()).is_pending(),
            "close must wait for prompt intake before cancelling"
        );
        assert!(
            agent.is_resident(&sid),
            "a close still waiting must not have freed the session"
        );
        drop(intake_guard);
        let response = close.await.expect("close completes once intake releases");
        assert!(
            !agent.is_resident(&sid),
            "close must free the session once it holds the lock"
        );
        assert_eq!(
            response
                .meta
                .as_ref()
                .and_then(|m| m.get("fuigo/closeOutcome")),
            Some(&json!("closed")),
            "a genuine close must report itself as one"
        );
    });
}
/// Presence stores thread and live together, but the shims still accept independent writes.
/// Reverting `set_live` to drop the thread (or `set_thread` to ignore an existing live bit) breaks the unload-then-drain path.
/// Disconnect records Dormant and keeps the actor thread for reconnect.
#[test]
fn presence_shims_keep_thread_across_live_writes() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-presence-shim");
        agent
            .session_registry
            .set_thread(&sid, exited_thread().await);
        agent.set_session_live_state(&sid, SessionLiveState::Dormant);
        assert!(
            agent.session_registry.has_thread(&sid),
            "set_live must not drop the thread a later drain waits on"
        );
        assert_eq!(
            agent.session_live_state_for(&sid),
            Some(SessionLiveState::Dormant),
            "set_thread must not clear the live bit unload just recorded"
        );
    });
}
/// `release` used to set `live = None` while keeping a running thread.
/// Folding that into `Evicted` must still report no live state, or roster readers start seeing a ghost Dormant/Closed for a session that closed.
#[test]
fn release_keeps_a_running_thread_without_a_live_bit() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-release-evicted");
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        agent.session_registry.set_thread(
            &sid,
            crate::session::SessionThread::from_handle(std::thread::spawn(move || {
                let _ = stop_rx.recv();
            })),
        );
        agent.set_session_live_state(&sid, SessionLiveState::Working);
        agent.set_turn_number(&sid, 1);
        agent.session_registry.release(&sid);
        assert!(
            agent.session_registry.has_thread(&sid),
            "a running thread must survive release for the sweep"
        );
        assert_eq!(
            agent.session_live_state_for(&sid),
            None,
            "release drops the live bit: the session is gone, only the flush remains"
        );
        assert_eq!(
            agent.session_registry.counts().session_live_state,
            0,
            "Evicted must not count as a live-state entry"
        );
        drop(stop_tx);
    });
}
/// `settle_attach` must restore a displaced Working turn, not the Attaching the second guard captured.
/// Reverting settle-from-handle to prior_live only records IdleResident here.
#[test]
fn settle_attach_restores_displaced_working() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-fail-attach-working");
        let (handle, _tx, _rx) = super::make_live_session_handle(&sid, Some("turn-1"));
        agent.insert_resident(&sid, handle);
        agent.set_session_live_state(&sid, SessionLiveState::Working);
        {
            let _guard = agent.begin_session_load(&sid);
            assert_eq!(
                agent.session_live_state_for(&sid),
                Some(SessionLiveState::Attaching)
            );
        }
        assert_eq!(
            agent.session_live_state_for(&sid),
            Some(SessionLiveState::Working),
            "failed attach must restore the running turn it displaced"
        );
    });
}
/// Successful spawn leaves Resident before the guard drops.
/// settle_attach must not take that presence away.
/// Reverting it to always `take()` drops the handle on every successful load.
#[test]
fn settle_attach_is_a_noop_once_the_session_is_already_resident() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-fail-attach-noop");
        let guard = agent.begin_session_load(&sid);
        let (handle, _tx, _rx) = super::make_live_session_handle(&sid, None);
        agent.insert_resident(&sid, handle);
        agent.set_session_live_state(&sid, SessionLiveState::IdleResident);
        drop(guard);
        assert!(
            agent.is_resident(&sid),
            "successful spawn then guard drop must leave the resident handle"
        );
        assert_eq!(
            agent.session_live_state_for(&sid),
            Some(SessionLiveState::IdleResident)
        );
    });
}
/// A reconnect attach parks the running actor thread in `displaced` and settles via guard drop with the cloned handle still present.
/// Reverting settle_attach's settle-from-handle branch to keep only Attaching's own thread (and drop `displaced`) loses that record.
/// The sweep then cannot reap a crash and drains have nothing to wait on.
#[test]
fn fail_attach_keeps_the_displaced_running_thread() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-fail-attach-thread");
        let (handle, _tx, _rx) = super::make_live_session_handle(&sid, None);
        agent.insert_resident(&sid, handle);
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        agent.session_registry.set_thread(
            &sid,
            crate::session::SessionThread::from_handle(std::thread::spawn(move || {
                let _ = stop_rx.recv();
            })),
        );
        {
            let _guard = agent.begin_session_load(&sid);
            assert!(
                agent.session_registry.has_thread(&sid),
                "begin_attach must keep the running thread reachable via displaced"
            );
        }
        assert!(
            agent.session_registry.has_thread(&sid),
            "guard-drop settle must keep the running thread, not drop displaced"
        );
        drop(stop_tx);
    });
}
/// A cold load registers the handle and records IdleResident while the load guard is still alive.
/// Reverting `set_live` to replace presence wholesale retires Attaching at actor spawn.
/// `wait_for_load_to_settle` then returns early, and `session_load_in_flight` goes false while the handle is registered but the bridge is empty.
#[test]
fn set_live_does_not_retire_an_in_flight_attach() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-cold-load-set-live");
        let guard = agent.begin_session_load(&sid);
        let (handle, _tx, _rx) = super::make_live_session_handle(&sid, None);
        agent.insert_resident(&sid, handle);
        agent.set_session_live_state(&sid, SessionLiveState::IdleResident);
        assert!(
            agent.session_registry.is_attaching(&sid),
            "set_live during a load must leave the attach in flight"
        );
        assert!(
            agent.session_registry.attach_waiter(&sid).is_some(),
            "wait_for_load_to_settle still needs the waiter until the guard drops"
        );
        drop(guard);
        assert!(
            !agent.session_registry.is_attaching(&sid),
            "the guard drop is what settles the attach"
        );
        assert!(agent.is_resident(&sid));
        assert_eq!(
            agent.session_live_state_for(&sid),
            Some(SessionLiveState::IdleResident)
        );
    });
}
/// Client-disconnect eviction writes Working against a still-resident session.
/// Reverting `set_live` to replace presence wholesale erases a racing attach's waiter.
/// Close and history-load then stop waiting at the disconnect write instead of at load completion.
#[test]
fn disconnect_eviction_does_not_erase_a_mid_attach() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-disconnect-mid-attach");
        let (handle, _tx, _rx) = super::make_live_session_handle(&sid, Some("turn-1"));
        agent.insert_resident(&sid, handle);
        let guard = agent.begin_session_load(&sid);
        agent.set_session_live_state(&sid, SessionLiveState::Working);
        assert!(
            agent.session_registry.is_attaching(&sid),
            "a disconnect Working write must not retire the in-flight attach"
        );
        assert!(
            agent.session_registry.attach_waiter(&sid).is_some(),
            "the owning waiter must survive the disconnect write"
        );
        drop(guard);
        assert!(
            !agent.session_registry.is_attaching(&sid),
            "the owning guard still settles the attach"
        );
        assert!(agent.is_resident(&sid));
        assert_eq!(
            agent.session_live_state_for(&sid),
            Some(SessionLiveState::Working),
            "settle_attach must honor the Working activity recorded mid-attach"
        );
    });
}
/// An unload mid-attach shuts the actor down through the Attaching copy of its handle, so the displaced resident's channel is closed by settle time.
/// Reverting the closed-channel demotion in `settle_attach` restores a resident nobody hosts.
#[test]
fn a_settled_attach_does_not_resurrect_an_unloaded_resident() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-unload-mid-attach");
        let (handle, _tx, rx) = super::make_live_session_handle(&sid, None);
        agent.insert_resident(&sid, handle);
        let guard = agent.begin_session_load(&sid);
        let _ = agent.session_registry.take_resident(&sid);
        drop(rx);
        drop(guard);
        assert!(
            agent.resident_handle(&sid).is_none(),
            "the restored presence must not host a dead channel"
        );
        assert_eq!(
            agent.session_live_state_for(&sid),
            Some(SessionLiveState::Dormant),
            "an unloaded session settles Dormant, not phantom-resident"
        );
    });
}
/// Internal spellings must not round-trip from a client.
/// Reverting `from_client` to a full parse maps them to internal variants and fails this.
#[test]
fn a_client_cannot_spell_internal_cancel_triggers() {
    use crate::session::CancelTrigger;
    for spelling in ["send_now", "shutdown", "session_close", "session_delete"] {
        assert_eq!(
            CancelTrigger::from_client(spelling),
            CancelTrigger::Client(spelling.to_string()),
        );
    }
    assert_eq!(CancelTrigger::from_client("esc"), CancelTrigger::Esc);
    assert_eq!(CancelTrigger::from_client("ctrl_c"), CancelTrigger::CtrlC);
}
/// The attach adopts the incoming actor's thread on Attaching's own slot.
/// A settle that produced nothing must hand it to `release`, which keeps a running thread for the sweep.
/// Reverting the Evicted hand-off in `settle_attach`'s empty branch drops it.
#[test]
fn a_settled_attach_keeps_the_thread_it_adopted() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-adopted-thread");
        let guard = agent.begin_session_load(&sid);
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        agent.session_registry.set_thread(
            &sid,
            crate::session::SessionThread::from_handle(std::thread::spawn(move || {
                let _ = stop_rx.recv();
            })),
        );
        drop(guard);
        assert!(
            agent.session_registry.has_thread(&sid),
            "a running thread adopted mid-attach must survive the settle"
        );
        drop(stop_tx);
    });
}
/// A client disconnect must not unload a session an attach is rebuilding: the handle it would shut down is the attach's copy.
/// Reverting the `is_attaching` gate in `handle_evict_sessions` unloads it.
#[test]
fn disconnect_does_not_unload_a_session_mid_attach() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-evict-mid-attach");
        let (handle, _tx, _rx) = super::make_live_session_handle(&sid, None);
        agent.insert_resident(&sid, handle);
        let _attach = agent.begin_session_load(&sid);
        super::drive_disconnect_many(&agent, &[&sid]).await;
        assert!(
            agent.resident_handle(&sid).is_some(),
            "a mid-attach session must survive the disconnect unload"
        );
        assert!(
            agent.session_registry.is_attaching(&sid),
            "and the attach must still be in flight"
        );
    });
}
/// F5-N (design F5 §4.1 A1, §6.1 step 3): a close whose session writer is still held at the budget answers `timeout` to a
/// client that advertised `fuigo/folderTrust.reload` or `.v2`, and 1.0.39's `closed` to every other client.
#[test]
fn f5n_close_answers_timeout_to_a_reload_or_v2_client_and_closed_to_the_rest() {
    use acp::Agent as _;
    super::run_local_for_bridge_test(|| async {
        let home = tempfile::TempDir::new().unwrap();
        for (reload, v2, want) in
            [(false, false, "closed"), (true, false, "timeout"), (false, true, "timeout"), (true, true, "timeout")]
        {
            let agent = super::build_minimal_agent_for_tests();
            agent.folder_trust_reload.set(reload);
            agent.interactive_trust_client.set(v2);
            let sid = acp::SessionId::new(format!("sess-f5n-close-{}", uuid::Uuid::now_v7()));
            let writer =
                fuigo_session_writer::SessionWriter::try_claim(sid.0.to_string(), home.path().join(sid.0.as_ref()))
                    .expect("claim");
            let (handle, _tx, _rx) = super::make_live_session_handle(&sid, None);
            agent.insert_resident(&sid, handle);
            agent.session_registry.set_thread(&sid, exited_thread().await);
            tokio::time::pause();
            let response = agent
                .close_session(acp::CloseSessionRequest::new(sid.clone()))
                .await
                .expect("close answers");
            tokio::time::resume();
            assert_eq!(
                response.meta.as_ref().and_then(|m| m.get("fuigo/closeOutcome")),
                Some(&json!(want)),
                "reload={reload} v2={v2}: the writer was still held at the close budget"
            );
            assert!(!agent.is_resident(&sid));
            drop(writer);
        }
    });
}
/// F5-N (design F5 §4.1): an owed reload is reported on a reattach to the resident session, to a `reload` client only; a
/// client without it keeps 1.0.40's response. A cold attach builds the session trusted, so it pays the debt and reports
/// nothing, then or later.
#[test]
fn f5n_owed_reload_is_reported_on_a_reattach_to_a_reload_client_only() {
    super::run_local_for_bridge_test(|| async {
        let agent = super::build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("sess-f5n-owed");
        agent.folder_trust_reload.set(true);
        assert_eq!(agent.folder_trust_reload_owed_meta(&sid, true), None, "nothing owed yet");
        agent.folder_trust_reload_owed.borrow_mut().insert(sid.clone());
        agent.folder_trust_reload.set(false);
        assert_eq!(agent.folder_trust_reload_owed_meta(&sid, true), None, "a client without reload sees 1.0.40's response");
        agent.folder_trust_reload.set(true);
        assert_eq!(agent.folder_trust_reload_owed_meta(&sid, true), Some(json!({"owed": true})));
        assert_eq!(agent.folder_trust_reload_owed_meta(&sid, true), Some(json!({"owed": true})), "owed until paid");
        assert_eq!(agent.folder_trust_reload_owed_meta(&sid, false), None, "a cold attach builds it trusted");
        assert_eq!(agent.folder_trust_reload_owed_meta(&sid, true), None, "and pays the debt");
    });
}
