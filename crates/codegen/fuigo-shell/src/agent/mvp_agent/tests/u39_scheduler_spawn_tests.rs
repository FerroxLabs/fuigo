//! Item S (E6), RS2: child spawn hands the child the scheduler the parent's toolset runs now, so a child's scheduled task
//! lands on the live scheduler (and survives the child) after the parent's zero-turn model switch.
use super::{build_minimal_agent_for_tests, make_test_handle};
use agent_client_protocol as acp;
use fuigo_tools::implementations::fuigo_build::scheduler::types::SchedulerHandle;

#[tokio::test(flavor = "current_thread")]
async fn rs2_child_spawn_takes_the_live_scheduler_after_a_switch() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let agent = build_minimal_agent_for_tests();
            let sid = acp::SessionId::new("u39-rs2-parent");
            let (old_tx, old_rx) = tokio::sync::mpsc::unbounded_channel();
            let handle = make_test_handle("test-model", false, None);
            handle.scheduler_handle.set(Some(SchedulerHandle(old_tx)));
            let live = handle.scheduler_handle.clone();
            agent.insert_resident(&sid, handle);
            // The zero-turn switch: the old scheduler is cancelled and the actor re-points the shared handle.
            drop(old_rx);
            let (new_tx, mut new_rx) = tokio::sync::mpsc::unbounded_channel();
            live.set(Some(SchedulerHandle(new_tx)));
            let ctx = agent.build_subagent_spawn_context(sid.0.as_ref());
            let inherited = ctx.parent_scheduler_handle.expect("child inherits the parent's scheduler");
            assert!(!inherited.0.is_closed(), "the child reaches a scheduler that runs");
            let (reply, _rx) = tokio::sync::oneshot::channel();
            inherited
                .0
                .send(fuigo_tools::implementations::fuigo_build::scheduler::types::SchedulerCommand::List { reply })
                .expect("delivered to the live scheduler");
            assert!(new_rx.try_recv().is_ok(), "the child's command reaches the live scheduler");
        })
        .await;
}

/// RS1, park: after the zero-turn switch re-points the session's scheduler handle, park's pause reaches the scheduler
/// that runs, not the cancelled one.
#[test]
fn rs1_park_after_a_switch_pauses_the_live_scheduler() {
    use super::p189_park_round3_tests::park_request;
    use fuigo_tools::implementations::fuigo_build::scheduler::types::SchedulerCommand;
    super::run_local_for_bridge_test(|| async {
        let agent = build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("u39-rs1-park");
        let (old_tx, mut old_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut handle = make_test_handle("test-model", false, None);
        handle.info.id = sid.clone();
        handle.scheduler_handle.set(Some(SchedulerHandle(old_tx)));
        let live = handle.scheduler_handle.clone();
        agent.insert_resident(&sid, handle);
        // The zero-turn switch: the actor re-points the shared handle at the new toolset's scheduler.
        let (new_tx, mut new_rx) = tokio::sync::mpsc::unbounded_channel();
        live.set(Some(SchedulerHandle(new_tx)));
        let request = park_request("u39-rs1-park", "hold", 1);
        let (_, pause) = tokio::join!(
            crate::extensions::session_park::handle_park(&agent, &request),
            async {
                let pause = tokio::time::timeout(std::time::Duration::from_secs(5), new_rx.recv())
                    .await
                    .expect("park reached the live scheduler")
                    .expect("open");
                let paused = matches!(pause, SchedulerCommand::SetPaused { paused: true, .. });
                drop(pause);
                paused
            }
        );
        assert!(pause, "park sent the live scheduler its pause");
        assert!(
            !matches!(old_rx.try_recv(), Ok(SchedulerCommand::SetPaused { .. })),
            "park paused the cancelled scheduler"
        );
    });
}

/// RS2, end to end: the child's scheduled task lands on the scheduler the parent's rebuilt toolset runs and fires
/// once after the child exits.
#[test]
fn rs2_child_task_fires_once_on_the_live_scheduler_after_the_child_exits() {
    use fuigo_tools::implementations::fuigo_build::scheduler::types::{
        ScheduledTask, SchedulerCommand,
    };
    use fuigo_tools::notification::{ToolNotification, ToolNotificationHandle};
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let dir = tempfile::tempdir().expect("tempdir");
    super::run_local_for_bridge_test(|| async {
        // The parent's rebuilt toolset: a real scheduler whose notifications the test reads.
        let (notifications, mut notification_rx) = ToolNotificationHandle::channel();
        let (gateway_tx, _gateway) = tokio::sync::mpsc::unbounded_channel();
        let (persistence_tx, _persistence) = tokio::sync::mpsc::unbounded_channel();
        let actor = crate::session::acp_session::support::create_test_actor(
            0,
            256_000,
            85,
            gateway_tx,
            persistence_tx,
        )
        .await;
        let Ok(mut spec) =
            std::sync::Arc::try_unwrap(crate::session::agent_rebuild::test_rebuild_spec_default())
        else {
            unreachable!("a fresh spec has one owner");
        };
        spec.bridge_state_path = dir.path().join("tool_state.json");
        spec.tools_notification_handle = notifications;
        let definition = actor.agent.borrow().definition().clone();
        let rebuilt = std::sync::Arc::new(spec)
            .build_agent(definition)
            .await
            .expect("rebuilt toolset");
        let live_scheduler = {
            let toolset = rebuilt.tool_bridge().toolset();
            let res = toolset.resources.lock().await;
            res.get::<SchedulerHandle>()
                .cloned()
                .expect("a top-level toolset runs its own scheduler")
        };

        let agent = build_minimal_agent_for_tests();
        let sid = acp::SessionId::new("u39-rs2-fire");
        let (old_tx, old_rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = make_test_handle("test-model", false, None);
        handle.scheduler_handle.set(Some(SchedulerHandle(old_tx)));
        let live = handle.scheduler_handle.clone();
        agent.insert_resident(&sid, handle);
        drop(old_rx);
        live.set(Some(live_scheduler));

        // The child creates a one-shot task as its scheduler tool does, then exits.
        let ctx = agent.build_subagent_spawn_context(sid.0.as_ref());
        let inherited = ctx
            .parent_scheduler_handle
            .expect("child inherits the parent's scheduler");
        let mut task = ScheduledTask::new(1, "u39 rs2 child task".into(), false, false);
        task.foreground = true;
        let task_id = task.id.clone();
        let (reply, rx) = tokio::sync::oneshot::channel();
        inherited
            .0
            .send(SchedulerCommand::Create { task, reply })
            .expect("the live scheduler accepts the child's task");
        tokio::time::timeout(std::time::Duration::from_secs(5), rx)
            .await
            .expect("reply")
            .expect("sent")
            .expect("created");
        drop(inherited);

        let mut fired = 0;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(6);
        while let Ok(Some(notification)) =
            tokio::time::timeout_at(deadline, notification_rx.recv()).await
        {
            if let ToolNotification::ScheduledTaskFired(fire) = notification
                && fire.task_id == task_id
            {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 1,
            "the child's task fires once on the live scheduler"
        );
        drop(rebuilt);
    });
}
