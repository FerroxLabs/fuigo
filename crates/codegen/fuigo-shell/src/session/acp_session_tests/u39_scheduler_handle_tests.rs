//! Item S (E6): after a zero-turn model switch the session handle names the scheduler the new toolset runs, not the
//! cancelled one, so park and child spawn reach the scheduler that runs.
use super::super::support::create_test_actor;
use super::*;
use fuigo_tools::implementations::fuigo_build::scheduler::types::{
    ScheduledTask, SchedulerCommand, SchedulerHandle,
};
use std::time::Duration;

async fn toolset_scheduler(actor: &SessionActor) -> SchedulerHandle {
    let toolset = actor.agent.borrow().tool_bridge().toolset();
    let res = toolset.resources.lock().await;
    res.get::<SchedulerHandle>()
        .cloned()
        .expect("a top-level toolset runs its own scheduler")
}

async fn list(handle: &SchedulerHandle) -> Option<Vec<String>> {
    let (reply, rx) = tokio::sync::oneshot::channel();
    handle.0.send(SchedulerCommand::List { reply }).ok()?;
    let snapshot = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .ok()?
        .ok()?;
    Some(snapshot.tasks.into_iter().map(|task| task.id).collect())
}

async fn closed_within(handle: &SchedulerHandle, limit: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < deadline {
        if handle.0.is_closed() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    handle.0.is_closed()
}

fn on_local<F: std::future::Future>(body: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    tokio::task::LocalSet::new().block_on(&rt, body)
}

/// RS1: after a zero-turn switch, the handle reaches the live scheduler (a task created through it is listed), and the
/// value it held before names the cancelled one.
#[test]
fn rs1_zero_turn_switch_repoints_the_handle_at_the_live_scheduler() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    on_local(async {
        let (gateway_tx, _gateway) = tokio::sync::mpsc::unbounded_channel();
        let (persistence_tx, _persistence) = tokio::sync::mpsc::unbounded_channel();
        let actor = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
        let before = toolset_scheduler(&actor).await;
        // As the spawn literal does.
        actor.scheduler_handle_live.set(Some(before.clone()));
        let live = actor.scheduler_handle_live.clone();
        let actor = Arc::new(actor);
        let definition = actor.agent.borrow().definition().clone();
        actor
            .handle_rebuild_agent_for_definition(definition)
            .await
            .expect("zero-turn switch");

        let after = live.get().expect("handle kept");
        let running = toolset_scheduler(&actor).await;
        assert!(
            after.0.same_channel(&running.0),
            "the handle names the new toolset's scheduler"
        );
        assert!(!after.0.same_channel(&before.0));
        assert!(
            closed_within(&before, Duration::from_secs(5)).await,
            "the old scheduler was cancelled"
        );

        let (reply, rx) = tokio::sync::oneshot::channel();
        let task = ScheduledTask::new(3600, "u39 rs1".into(), true, false);
        let id = task.id.clone();
        after
            .0
            .send(SchedulerCommand::Create { task, reply })
            .expect("live scheduler accepts");
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("reply")
            .expect("sent")
            .expect("created");
        assert!(
            list(&after)
                .await
                .expect("live scheduler answers")
                .contains(&id),
            "the task is listed"
        );
    });
}

/// One recurring task first due `due_in` from now.
fn resumed_task(foreground: bool, due_in: Duration) -> ScheduledTask {
    let mut task = ScheduledTask::new(60, "u39 rs3".into(), true, false);
    task.foreground = foreground;
    task.created_at = chrono::Utc::now() - chrono::Duration::seconds(60)
        + chrono::Duration::from_std(due_in).expect("due_in");
    task
}

/// A resumed session's resources file holding `task`.
#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
async fn write_resumed_state(dir: &std::path::Path, task: &ScheduledTask) {
    use fuigo_tools::implementations::fuigo_build::scheduler::types::SchedulerState;
    use fuigo_tools::types::resources::{Resources, State};
    let mut resources = Resources::new();
    resources.register_state::<SchedulerState>();
    resources.get_or_default::<State<SchedulerState>>().tasks = vec![task.clone()];
    let persistence =
        fuigo_tools::persistence::ResourcesPersistence::new_at(dir.join("resources_state.json"));
    persistence.save(&resources);
    persistence.flush().await;
}

/// RS3: a resumed session whose task comes due inside a zero-turn switch's build window. The resumed toolset and the
/// rebuilt one run their schedulers over the same state file, as a real session's do. Returns
/// `(ScheduledTaskFired count, loop child spawn count)`.
fn rs3_fires_across_switch(foreground: bool) -> (usize, usize) {
    use fuigo_tools::implementations::fuigo_build::task::types::SubagentEvent;
    use fuigo_tools::notification::{ToolNotification, ToolNotificationHandle};
    let dir = tempfile::tempdir().expect("tempdir");
    on_local(async {
        let task = resumed_task(foreground, Duration::from_millis(1500));
        write_resumed_state(dir.path(), &task).await;
        let (notifications, mut notification_rx) = ToolNotificationHandle::channel();
        let (subagent_tx, mut coordinator_rx) =
            tokio::sync::mpsc::unbounded_channel::<SubagentEvent>();
        let (forward_tx, mut subagent_rx) = tokio::sync::mpsc::unbounded_channel();
        // A stand-in coordinator: a loop child it has been sent stays live, which is what every background fire asks.
        tokio::task::spawn_local(async move {
            let mut spawned = false;
            while let Some(event) = coordinator_rx.recv().await {
                match event {
                    SubagentEvent::LoopUnitActive(query) => {
                        let _ = query.respond_to.send(spawned);
                    }
                    event => {
                        spawned |= matches!(event, SubagentEvent::Spawn(_));
                        let _ = forward_tx.send(event);
                    }
                }
            }
        });
        let (gateway_tx, _gateway) = tokio::sync::mpsc::unbounded_channel();
        let (persistence_tx, _persistence) = tokio::sync::mpsc::unbounded_channel();
        let mut actor = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
        let Ok(mut spec) =
            Arc::try_unwrap(crate::session::agent_rebuild::test_rebuild_spec_default())
        else {
            unreachable!("a fresh spec has one owner");
        };
        // One state path for both builds: the resumed toolset and the rebuilt one share the session's state file.
        spec.bridge_state_path = dir.path().join("tool_state.json");
        spec.tools_notification_handle = notifications;
        spec.subagent_event_tx = Some(subagent_tx);
        actor.rebuild_spec = Arc::new(spec);
        let definition = actor.agent.borrow().definition().clone();
        let resumed = actor
            .rebuild_spec
            .build_agent(definition.clone())
            .await
            .expect("resume build");
        *actor.agent.borrow_mut() = resumed;
        actor
            .scheduler_handle_live
            .set(Some(toolset_scheduler(&actor).await));
        let actor = Arc::new(actor);
        // The resumed scheduler fires as the switch begins; the rebuild then loads the same state file, where that
        // fire's cadence advance is not yet persisted, and arms a second scheduler over it. The window is made
        // certain below: the resumed toolset's pending writes are flushed and the pre-fire state is written back.
        let first = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match notification_rx.recv().await {
                    Some(ToolNotification::ScheduledTaskFired(_)) => return,
                    Some(_) => {}
                    None => panic!("notification channel closed"),
                }
            }
        })
        .await;
        assert!(first.is_ok(), "the resumed scheduler fires the due task");
        let resumed_toolset = actor.agent.borrow().tool_bridge().toolset();
        resumed_toolset.flush_persistence().await;
        drop(resumed_toolset);
        write_resumed_state(dir.path(), &task).await;
        actor
            .handle_rebuild_agent_for_definition(definition)
            .await
            .expect("zero-turn switch");
        tokio::time::sleep(Duration::from_secs(3)).await;
        let mut fired = 1;
        while let Ok(notification) = notification_rx.try_recv() {
            if matches!(notification, ToolNotification::ScheduledTaskFired(_)) {
                fired += 1;
            }
        }
        let mut spawned = 0;
        while let Ok(event) = subagent_rx.try_recv() {
            if let SubagentEvent::Spawn(spawn) = event {
                // The switch cancelled the scheduler that accepted the spawn; the spawn itself must survive it.
                assert!(
                    !spawn.request.cancel_token.is_cancelled(),
                    "the scheduler switch cancelled an accepted loop spawn"
                );
                spawned += 1;
            }
        }
        (fired, spawned)
    })
}

/// RS3, foreground task: one fire, one prompt.
#[test]
fn rs3_foreground_task_due_in_switch_window_fires_once() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    assert_eq!(rs3_fires_across_switch(true), (1, 0));
}

/// RS3, background loop task: one child spawned.
#[test]
fn rs3_background_loop_task_due_in_switch_window_spawns_once() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    assert_eq!(rs3_fires_across_switch(false), (1, 1));
}

/// Before any switch, and in sessions that never switch, the value is the spawn-time one.
#[test]
fn rs1_no_switch_keeps_the_spawn_value() {
    let handle = crate::session::LiveSchedulerHandle::new(None);
    assert!(handle.get().is_none());
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let value = SchedulerHandle(tx);
    let shared = crate::session::LiveSchedulerHandle::new(Some(value.clone()));
    let clone = shared.clone();
    assert!(clone.get().expect("set").0.same_channel(&value.0));
}
