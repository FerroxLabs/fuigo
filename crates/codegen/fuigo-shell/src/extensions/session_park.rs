//! P189: `_fuigo/session/park` and `_fuigo/session/unpark`.
//!
//! A client that keeps one Fuigo process warm between user messages parks the session after `end_turn`.
//! While parked, nothing in the session (or its subagents) starts a turn on its own, nothing calls the
//! model, and no frame for it reaches the client. The work is deferred, not dropped, and runs after unpark.
//! The exact wire contract is in `docs/strike/receipts/R189-p189.md` ("Wire spec").

use std::time::Duration;

use agent_client_protocol as acp;
use tokio::sync::oneshot;

use super::{ExtResult, parse_params, to_raw_response};
use crate::agent::MvpAgent;
use crate::session::SessionCommand;
use crate::session::quiesce::{self, OwedWork, ParkMode, ParkOp, ParkPhase, QuiesceReport};

/// JSON-RPC error code of every park failure; `data.reason` says which.
pub const PARK_ERROR_CODE: i32 = -32010;
/// How long a park waits for a running turn to end when the request names no `timeoutMs`.
pub const DEFAULT_PARK_TIMEOUT_MS: u64 = 30_000;
/// The longest wait a request may ask for.
pub const MAX_PARK_TIMEOUT_MS: u64 = 600_000;
/// How often a waiting park re-checks the running turn.
const PROBE_INTERVAL: Duration = Duration::from_millis(20);

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParkRequest {
    session_id: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnparkRequest {
    session_id: String,
}

/// `data.reason` values of a [`PARK_ERROR_CODE`] error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParkFailure {
    /// The running turn did not end within `timeoutMs`. The session is left unparked.
    Timeout,
    /// Another park of this session is still waiting for its turn to end.
    InProgress,
    /// An unpark or a `session/prompt` withdrew the park before it completed.
    Withdrawn,
    /// The session actor is gone.
    SessionClosed,
    /// `mode: "stop"` could not confirm every process the session's tools started is dead. Not parked.
    StopIncomplete,
}

impl ParkFailure {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::InProgress => "park_in_progress",
            Self::Withdrawn => "withdrawn",
            Self::SessionClosed => "session_closed",
            Self::StopIncomplete => "stop_incomplete",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Timeout => "the running turn did not end before the park timeout; the session was not parked",
            Self::InProgress => "a park of this session is already waiting for its turn to end",
            Self::Withdrawn => "the park was withdrawn (unpark or a new prompt) before it completed",
            Self::SessionClosed => "the session closed before it could be parked",
            Self::StopIncomplete => "a process started by the session's tools could not be confirmed dead; the session was not parked",
        }
    }

    fn to_error(self, session_id: &str, timeout_ms: u64) -> acp::Error {
        acp::Error::new(PARK_ERROR_CODE, "Session park failed").data(
            crate::acp_error::error_data_with_fields(
                crate::acp_error::AcpErrorKind::SessionUnavailable,
                self.message(),
                serde_json::json!({
                    "reason": self.reason(),
                    "sessionId": session_id,
                    "timeoutMs": timeout_ms,
                }),
            ),
        )
    }
}

fn unknown_session(session_id: &str) -> acp::Error {
    crate::acp_error::invalid_params(format!("session not found: {session_id}"))
}

fn park_reply(
    session_id: &str,
    mode: ParkMode,
    already_parked: bool,
    report: &QuiesceReport,
    running_tasks: usize,
    stopped_tasks: usize,
) -> serde_json::Value {
    serde_json::json!({
        "parked": true,
        "sessionId": session_id,
        "mode": mode.as_str(),
        "alreadyParked": already_parked,
        "deferred": {
            "queuedInputs": report.queued_inputs,
            "pendingNotifications": report.pending_notifications,
            "turnSummary": report.turn_summary_deferred,
            "titleRefresh": report.title_refresh_deferred,
        },
        "running": { "backgroundTasks": running_tasks },
        "stopped": { "backgroundTasks": stopped_tasks },
    })
}

/// Upper bound on any single await of the park on the session actor, the scheduler or the terminal backend.
const STEP_BOUND: Duration = Duration::from_secs(5);
/// Most park ops one implicit unpark follows before it gives up and fails the prompt (each is a replacement).
const MAX_UNPARK_ROUNDS: u32 = 8;
/// How long a (not yet advertised) stop park waits for its killed background tasks to leave the terminal backend.
const STOP_TASK_WAIT: Duration = Duration::from_secs(5);

/// `fut` bounded by `min(now + STEP_BOUND, deadline)`; `None` on timeout.
async fn bounded<T>(deadline: tokio::time::Instant, fut: impl std::future::Future<Output = T>) -> Option<T> {
    let step = std::cmp::min(tokio::time::Instant::now() + STEP_BOUND, deadline);
    tokio::time::timeout_at(step, fut).await.ok()
}

async fn probe(session: &crate::session::SessionHandle, park: &ParkOp, stop: bool) -> Option<QuiesceReport> {
    let (tx, rx) = oneshot::channel();
    session
        .cmd_tx
        .send(SessionCommand::Quiesce {
            op: park.clone(),
            stop,
            respond_to: tx,
        })
        .ok()?;
    rx.await.ok()
}

async fn running_task_ids(session: &crate::session::SessionHandle) -> Vec<String> {
    session
        .list_tasks()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|task| task.end_time.is_none())
        .map(|task| task.task_id)
        .collect()
}

/// Kill every running background task of park `park` (bounded); returns how many kills succeeded. The kill
/// command is queued under the registry lease of `park`, one lease per kill (not one per list): once the park
/// is withdrawn or replaced no further kill is sent.
async fn kill_running_tasks(
    session: &crate::session::SessionHandle,
    park: &ParkOp,
    deadline: tokio::time::Instant,
) -> usize {
    let Some(ids) = bounded(deadline, running_task_ids(session)).await else {
        return 0;
    };
    let mut stopped = 0;
    for task_id in ids {
        let (tx, rx) = oneshot::channel();
        let mut queued = false;
        let current = quiesce::run_if_current(park, || {
            queued = session
                .cmd_tx
                .send(SessionCommand::KillBackgroundTask {
                    task_id,
                    source: fuigo_tools::types::KillSource::Teardown,
                    park: Some(park.clone()),
                    respond_to: tx,
                })
                .is_ok();
        });
        if !current {
            break;
        }
        if queued && matches!(bounded(deadline, rx).await, Some(Ok(Ok(_)))) {
            stopped += 1;
        }
    }
    stopped
}

type FoldedFires = Vec<fuigo_tools::implementations::fuigo_build::scheduler::types::FoldedFire>;

/// Distinguishes the fold transactions of one park op.
static FOLD_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Send `SetPaused` to the session's scheduler. `Ok(fires)` once acknowledged (or when the session has no
/// scheduler); `Err` when no acknowledgement came within the step bound.
async fn send_scheduler_paused(
    session: &crate::session::SessionHandle,
    op: u64,
    paused: bool,
    fold_overdue: bool,
    fold: Option<fuigo_tools::implementations::fuigo_build::scheduler::types::FoldTxn>,
    deadline: tokio::time::Instant,
) -> Result<FoldedFires, ()> {
    use fuigo_tools::implementations::fuigo_build::scheduler::types::SchedulerCommand;
    let Some(handle) = session.scheduler_handle.as_ref() else {
        return Ok(Vec::new());
    };
    let (reply, rx) = oneshot::channel();
    let expected = fold.as_ref().map(|f| f.id);
    if handle
        .0
        .send(SchedulerCommand::SetPaused {
            op,
            paused,
            fold_overdue,
            reply,
            fold,
        })
        .is_err()
    {
        // The scheduler is gone: nothing can fire.
        return Ok(Vec::new());
    }
    match bounded(deadline, rx).await {
        // A reply for another transaction is no answer to this one.
        Some(Ok(reply)) if reply.id == expected => Ok(reply.fires),
        Some(Ok(_)) => Err(()),
        Some(Err(_)) => Ok(Vec::new()),
        None => Err(()),
    }
}

/// Resume the session's scheduler; due fires run as usual.
async fn resume_scheduler(session: &crate::session::SessionHandle, op: u64) {
    resume_scheduler_by(session, op, tokio::time::Instant::now() + STEP_BOUND).await;
}

/// [`resume_scheduler`] bounded by `deadline` as well (Astra r2 #10: a failing park's withdrawal resume stays
/// inside the park's one overall deadline; the command is sent even when the deadline has passed).
async fn resume_scheduler_by(session: &crate::session::SessionHandle, op: u64, deadline: tokio::time::Instant) {
    let deadline = std::cmp::min(deadline, tokio::time::Instant::now() + STEP_BOUND);
    let _ = send_scheduler_paused(session, op, false, false, None, deadline).await;
}

/// Owner decision 45, 2026-10-11: does a scheduled-task fire (a prompt whose id carries the `scheduler-fired-`
/// prefix, verified or not) un-park a parked session? No. `implicitUnpark` applies to prompts the client sends on
/// its own behalf only; a fire is folded into the next real prompt. The ONE place this is decided.
pub(crate) const fn scheduled_fire_unparks() -> bool {
    false
}

/// True when `prompt_id` is a scheduled-task fire id (verified ticket or not).
pub(crate) fn is_scheduled_fire_id(prompt_id: &str) -> bool {
    prompt_id.starts_with(crate::session::cron_fire_tickets::PROMPT_ID_PREFIX)
}

/// A scheduled-task fire arrived: if a park holds the session (its own, or its root's when it is a child), note its
/// text for that park's release, consume its ticket and return `true` (the caller ends the prompt without a turn).
/// `false`: no park holds the session now; the caller takes the normal prompt path and the ticket is untouched.
/// The text is the task prompt without the shell's own framing block.
pub(crate) fn fold_scheduled_fire(session_id: &str, prompt_id: &str, blocks: &[acp::ContentBlock]) -> bool {
    let text = blocks
        .iter()
        .filter_map(|block| match block {
            acp::ContentBlock::Text(text) => Some(text.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let text = text.rsplit("</system-reminder>").next().unwrap_or(&text).trim().to_owned();
    if !quiesce::fold_fire_if_holding(session_id, text) {
        return false;
    }
    let _verified = crate::session::cron_fire_tickets::redeem(session_id, prompt_id, blocks);
    true
}

/// The reminder for folded scheduled-task prompts (see [`fold_scheduled_fire`]).
fn fires_reminder(texts: &[String]) -> Option<String> {
    if texts.is_empty() {
        return None;
    }
    // The dropped-count notice line (`FoldedFires::into_texts`) is not an arrived prompt.
    let arrived = texts.iter().filter(|t| !(t.starts_with('(') && t.ends_with(" earlier scheduled prompts were dropped)"))).count();
    let mut text = format!(
        "While the session was parked, {arrived} scheduled task prompt(s) arrived. They were not run; their next run follows the usual interval:"
    );
    for fire in texts {
        text.push_str("\n- ");
        text.push_str(fire);
    }
    Some(text)
}

/// Join the reminders of the due-fire fold and of the folded prompts.
fn merge_reminders(first: Option<String>, second: Option<String>) -> Option<String> {
    match (first, second) {
        (Some(a), Some(b)) => Some(format!("{a}\n\n{b}")),
        (a, b) => a.or(b),
    }
}

/// The reminder that tells the next turn which scheduled fires came due while the session was parked.
fn folded_fires_reminder(fires: &[fuigo_tools::implementations::fuigo_build::scheduler::types::FoldedFire]) -> Option<String> {
    if fires.is_empty() {
        return None;
    }
    let mut text = format!(
        "While the session was parked, {} scheduled task(s) came due. They were not run; their next run follows the usual interval:",
        fires.len()
    );
    for fire in fires {
        text.push_str(&format!(
            "\n- task_id {} ({}): {}",
            fire.task_id, fire.human_schedule, fire.prompt
        ));
    }
    Some(text)
}

/// Withdraw park `op` (it failed before its ack): unpark it, resume the scheduler, and let the session run
/// whatever it held meanwhile. A park that replaced it is never touched.
async fn withdraw(
    session: &crate::session::SessionHandle,
    session_id: &str,
    op: u64,
    deadline: tokio::time::Instant,
) {
    if let Some(entry) = quiesce::withdraw(session_id, op) {
        resume_scheduler_by(session, op, deadline).await;
        let _ = session.cmd_tx.send(SessionCommand::QuiesceRelease {
            op,
            owed: entry.owed,
            reopen_spawns: entry.mode == ParkMode::Stop,
            kick: true,
            reminder: fires_reminder(&entry.fires.into_texts()),
        });
    }
}

/// Park `op` is no longer the session's park: it was withdrawn by an unpark or a prompt (which resumed or
/// will resume the scheduler). If no park holds the session now, make sure the scheduler this park paused
/// runs again.
async fn on_withdrawn(
    session: &crate::session::SessionHandle,
    session_id: &str,
    op: u64,
    timeout_ms: u64,
    deadline: tokio::time::Instant,
) -> acp::Error {
    // Resume by op is idempotent: the scheduler applies it only if `op` still owns the pause, so a replacement
    // park's pause is never lifted and no registry read is needed first.
    resume_scheduler_by(session, op, deadline).await;
    ParkFailure::Withdrawn.to_error(session_id, timeout_ms)
}

/// Handle `fuigo/session/park`.
///
/// Order (Astra r1 #3/#4/#10): every step that talks to the session actor, the scheduler or the terminal
/// backend runs while the park is still `Parking`, so nothing it sends is held by the park itself (an ACP
/// terminal's `terminal/output` would wait for the unpark, a circular wait). Each such await is bounded.
/// Only then does the park complete and acknowledge.
pub async fn handle_park(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    let req: ParkRequest = parse_params(args)?;
    let mode = ParkMode::parse(req.mode.as_deref())
        .filter(|m| m.advertised())
        .ok_or_else(|| {
            crate::acp_error::invalid_params(format!(
                "mode must be one of {:?} on this platform",
                quiesce::advertised_modes()
            ))
        })?;
    let timeout_ms = req
        .timeout_ms
        .unwrap_or(DEFAULT_PARK_TIMEOUT_MS)
        .clamp(1, MAX_PARK_TIMEOUT_MS);
    // F7: ONE deadline for the whole request, started here: the wait for a loading session, every step and the
    // final scans all count against it.
    let park_started = tokio::time::Instant::now();
    let turn_deadline = park_started + Duration::from_millis(timeout_ms);
    let hard_deadline = turn_deadline + STEP_BOUND;
    let session_id = req.session_id;
    let sid = acp::SessionId::new(session_id.clone());
    let session = tokio::time::timeout_at(hard_deadline, agent.session_handle_waiting_for_load(&sid))
        .await
        .map_err(|_| ParkFailure::Timeout.to_error(&session_id, timeout_ms))?
        .ok_or_else(|| unknown_session(&session_id))?;

    if let Some(entry) = quiesce::entry(&session_id) {
        // Idempotent once acknowledged: report the park that holds, with the running-task count recorded at
        // its ack (asking the terminal backend now would wait on the held connection).
        if entry.acked && entry.phase == ParkPhase::Parked {
            // Grok r4 #9: bounded by the request's ONE deadline (the load wait above already spent part of it),
            // not by a fresh step bound.
            let park = ParkOp { session: session_id.as_str().into(), op: entry.op };
            // Opus r1 #9: a deadline miss is a `timeout`; only a dropped probe channel is `SessionClosed`.
            let report = match bounded(hard_deadline, probe(&session, &park, false)).await {
                None => return Err(ParkFailure::Timeout.to_error(&session_id, timeout_ms)),
                Some(None) => return Err(ParkFailure::SessionClosed.to_error(&session_id, timeout_ms)),
                Some(Some(report)) => report,
            };
            // Astra r2 #4: the park may have been withdrawn or replaced while the probe was in flight.
            if !quiesce::op_is_current(&session_id, entry.op)
                || !quiesce::entry(&session_id).is_some_and(|now| now.acked && now.phase == ParkPhase::Parked)
            {
                return Err(ParkFailure::Withdrawn.to_error(&session_id, timeout_ms));
            }
            return to_raw_response(&park_reply(
                &session_id,
                entry.mode,
                true,
                &report,
                entry.running_at_ack,
                0,
            ));
        }
        return Err(ParkFailure::InProgress.to_error(&session_id, timeout_ms));
    }
    let Some(op) = quiesce::begin_park(&session_id, mode) else {
        return Err(ParkFailure::InProgress.to_error(&session_id, timeout_ms));
    };
    let stop = mode == ParkMode::Stop;
    // Operation identity is checked where each side effect executes (see `quiesce::run_if_current`): the
    // actor validates `Quiesce.op`, `kill_running_tasks` fences each kill, the scheduler pause is owned by
    // `op`. A withdrawn park therefore does nothing more,
    // and `complete_park`/`ack_park` (which take `op`) end it.
    let park = ParkOp { session: session_id.as_str().into(), op };

    // 1. No timer fires while parked. No acknowledgement in time: the park fails `timeout`.
    if send_scheduler_paused(&session, op, true, false, None, hard_deadline)
        .await
        .is_err()
    {
        withdraw(&session, &session_id, op, hard_deadline).await;
        return Err(ParkFailure::Timeout.to_error(&session_id, timeout_ms));
    }
    // 2. `mode: "stop"`: kill the running background tasks.
    let mut stopped_tasks = 0;
    if stop {
        stopped_tasks += kill_running_tasks(&session, &park, hard_deadline).await;
    }
    // 3. Wait for the running turn to end.
    let mut stop_subagents = stop;
    let mut turn_was_running = false;
    let report = loop {
        if !quiesce::op_is_current(&session_id, op) {
            return Err(on_withdrawn(&session, &session_id, op, timeout_ms, hard_deadline).await);
        }
        let report = match bounded(hard_deadline, probe(&session, &park, stop_subagents)).await {
            Some(Some(report)) => report,
            Some(None) => {
                withdraw(&session, &session_id, op, hard_deadline).await;
                return Err(ParkFailure::SessionClosed.to_error(&session_id, timeout_ms));
            }
            None => {
                withdraw(&session, &session_id, op, hard_deadline).await;
                return Err(ParkFailure::Timeout.to_error(&session_id, timeout_ms));
            }
        };
        stop_subagents = false;
        if !report.turn_running {
            break report;
        }
        turn_was_running = true;
        if tokio::time::Instant::now() >= turn_deadline {
            withdraw(&session, &session_id, op, hard_deadline).await;
            return Err(ParkFailure::Timeout.to_error(&session_id, timeout_ms));
        }
        tokio::time::sleep(PROBE_INTERVAL).await;
    };
    // 4. `mode: "stop"` (not advertised in this packet, so unreachable): the running background tasks are gone.
    if stop {
        // Tasks the finishing turn started after step 2.
        if turn_was_running {
            stopped_tasks += kill_running_tasks(&session, &park, hard_deadline).await;
        }
        // The terminal backend notices its killed tasks exited on its next reap.
        let tasks_deadline = std::cmp::min(
            tokio::time::Instant::now() + STOP_TASK_WAIT,
            hard_deadline,
        );
        let mut still_running = bounded(tasks_deadline, running_task_ids(&session)).await;
        while still_running.as_ref().is_none_or(|ids| !ids.is_empty())
            && tokio::time::Instant::now() < tasks_deadline
        {
            tokio::time::sleep(PROBE_INTERVAL).await;
            if !quiesce::op_is_current(&session_id, op) {
                break;
            }
            still_running = bounded(tasks_deadline, running_task_ids(&session)).await;
        }
        if still_running.is_none_or(|ids| !ids.is_empty()) {
            tracing::warn!(session_id = %session_id, "stop park: a background task is still running");
            withdraw(&session, &session_id, op, hard_deadline).await;
            return Err(ParkFailure::StopIncomplete.to_error(&session_id, timeout_ms));
        }
    }
    // 5. The background tasks a hold park leaves running (asked while still Parking: never held).
    let running_tasks = if stop {
        0
    } else {
        match bounded(hard_deadline, running_task_ids(&session)).await {
            Some(ids) => ids.len(),
            None => {
                withdraw(&session, &session_id, op, hard_deadline).await;
                return Err(ParkFailure::Timeout.to_error(&session_id, timeout_ms));
            }
        }
    };
    // 6. From here no model call starts in the session tree and its frames are held.
    if !quiesce::complete_park(&session_id, op) {
        return Err(on_withdrawn(&session, &session_id, op, timeout_ms, hard_deadline).await);
    }
    // 8. Acknowledge, start holding process-wide frames, then reply: every frame the connection writes from
    // here on is held, so none can follow the acknowledgement.
    if !quiesce::ack_park(&session_id, op, running_tasks) {
        return Err(on_withdrawn(&session, &session_id, op, timeout_ms, hard_deadline).await);
    }
    agent.park_hold.mark_parked(&session_id);
    tracing::info!(
        session_id = %session_id,
        mode = mode.as_str(),
        elapsed_ms = park_started.elapsed().as_millis() as u64,
        "session parked"
    );
    to_raw_response(&park_reply(
        &session_id,
        mode,
        false,
        &report,
        running_tasks,
        stopped_tasks,
    ))
}

/// `result._meta` key of a parked `session/load` reply: the settled state of every MCP server.
pub const MCP_READY_META_KEY: &str = "fuigo/mcpReady";
/// Upper bound on the parked-load wait. Each server's own startup timeout (default 30 s) ends its handshake
/// first and records it failed; this only guards against a server whose status never settles.
const MCP_READY_WAIT: Duration = Duration::from_secs(35);
const MCP_READY_POLL: Duration = Duration::from_millis(50);

/// One server's entry in `fuigo/mcpReady`.
fn mcp_server_states(
    snapshot: &crate::extensions::mcp::McpStatusSnapshot,
) -> Vec<(String, Option<&'static str>)> {
    use crate::extensions::mcp::McpSessionStatus;
    // Astra r2 NEW-4: the configured servers, then the in-process SDK servers (no `configs` entry).
    let configured = snapshot
        .configs
        .iter()
        .map(|config| fuigo_mcp::servers::mcp_server_name(config).to_owned());
    let sdk = snapshot
        .acp_servers
        .iter()
        .filter(|name| !snapshot.configs.iter().any(|c| fuigo_mcp::servers::mcp_server_name(c) == name.as_str()))
        .cloned();
    configured
        .chain(sdk)
        .map(|name| {
            let client = snapshot.clients.iter().find(|c| c.name == name);
            let state = if client.is_some_and(|c| c.status == McpSessionStatus::Ready) {
                Some("ready")
            } else if snapshot.init_failed.contains_key(&name)
                || snapshot.auth_required.contains(&name)
                || client.is_some_and(|c| {
                    matches!(c.status, McpSessionStatus::Unavailable | McpSessionStatus::SetupRequired)
                })
            {
                Some("failed")
            } else {
                None
            };
            (name, state)
        })
        .collect()
}

/// A `session/load` of a PARKED session may not write the MCP-ready notification, so its reply carries the
/// readiness instead: wait until every configured MCP server is ready or failed (bounded), and return
/// `{"servers":[{"name","status":"ready"|"failed"|"timeout"}]}`.
pub(crate) async fn wait_mcp_settled(session: &crate::session::SessionHandle) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + MCP_READY_WAIT;
    let mut states = Vec::new();
    loop {
        let (tx, rx) = oneshot::channel();
        if session
            .cmd_tx
            .send(SessionCommand::GetMcpStatus { respond_to: tx })
            .is_err()
        {
            break;
        }
        // Astra r1 #10: a status reply that never comes ends the wait at its deadline.
        let Ok(Ok(snapshot)) = tokio::time::timeout_at(deadline, rx).await else {
            break;
        };
        states = mcp_server_states(&snapshot);
        if states.iter().all(|(_, state)| state.is_some()) || tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(MCP_READY_POLL).await;
    }
    let servers: Vec<serde_json::Value> = states
        .into_iter()
        .map(|(name, state)| serde_json::json!({ "name": name, "status": state.unwrap_or("timeout") }))
        .collect();
    serde_json::json!({ "servers": servers })
}

/// What an unpark released.
pub(crate) struct UnparkOutcome {
    pub(crate) was_parked: bool,
    pub(crate) frames: usize,
    pub(crate) dropped_frames: usize,
}

/// Explicit unpark (`_fuigo/session/unpark`) of `session_id` if it is parked or parking: resume its scheduler
/// (due fires run as usual), write its held frames in order, then let the session run what the park deferred.
pub(crate) async fn unpark_session(
    agent: &MvpAgent,
    session: &crate::session::SessionHandle,
    session_id: &str,
) -> UnparkOutcome {
    let not_parked = UnparkOutcome {
        was_parked: false,
        frames: 0,
        dropped_frames: 0,
    };
    if quiesce::entry(session_id).is_none_or(|entry| entry.phase == ParkPhase::Unparking) {
        return not_parked;
    }
    let op = quiesce::entry(session_id).map_or(0, |entry| entry.op);
    // Astra r1 #8: resume the scheduler BEFORE the unpark; a fire meanwhile queues behind the park.
    resume_scheduler(session, op).await;
    let Some(entry) = quiesce::unpark(session_id) else {
        return not_parked;
    };
    // Opus r1 #5: queue the release (the owed work and the kick) BEFORE the slow frame write, as the implicit
    // path does: a hung write or a dropped future must not lose either.
    let _ = session.cmd_tx.send(SessionCommand::QuiesceRelease {
        op: entry.op,
        owed: entry.owed,
        reopen_spawns: entry.mode == ParkMode::Stop,
        kick: true,
        reminder: fires_reminder(&entry.fires.into_texts()),
    });
    let released = agent.park_hold.release(session_id).await;
    tracing::info!(session_id = %session_id, frames = released.frames, "session unparked");
    UnparkOutcome {
        was_parked: true,
        frames: released.frames,
        dropped_frames: released.dropped,
    }
}

/// Finishes an implicit unpark if the prompt never reached the session actor (an error path of
/// `session/prompt`); harmless once the actor finished it.
pub(crate) struct ImplicitUnparkGuard {
    session_id: String,
    op: u64,
}

impl Drop for ImplicitUnparkGuard {
    fn drop(&mut self) {
        quiesce::finish_unpark(&self.session_id, self.op);
    }
}

/// The internal method of the gateway barrier (never written to the client; `ParkHoldClient` answers it).
pub(crate) const PARK_BARRIER_METHOD: &str = "fuigo/internal/park_barrier";

/// Implicit unpark (a `session/prompt` on a parked or parking session), Astra r1 #8:
/// 1. barrier through the connection's gateway: every request queued before it has registered with the hold
///    (and seen the park), so the cancel below reaches it too;
/// 2. bump the root's cancel generation: requests held under the park belong to the turn before it and are
///    answered cancelled;
/// 3. resume the scheduler with a two-phase fold (nothing is advanced unless its reminder is delivered);
/// 4. `Unparking`: model calls and frames flow again, but the session starts no turn of its own until the
///    prompt is queued (the actor finishes the unpark right after queueing it, so no deferred wake can run
///    ahead of the user's prompt);
/// 5. write the held frames and the marker, queue the owed work and the folded fires' reminder, commit the fold.
pub(crate) async fn implicit_unpark(
    agent: &MvpAgent,
    session: &crate::session::SessionHandle,
    session_id: &str,
) -> Result<Option<ImplicitUnparkGuard>, acp::Error> {
    let Some(entry) = quiesce::entry(session_id) else {
        return Ok(None);
    };
    if entry.phase == ParkPhase::Unparking {
        return Ok(None);
    }
    if entry.phase == ParkPhase::Parked {
        let Ok(params) = serde_json::value::to_raw_value(&serde_json::json!({})) else {
            return Err(crate::acp_error::internal_error("park barrier could not be built"));
        };
        let barrier = acp::ExtRequest::new(PARK_BARRIER_METHOD, std::sync::Arc::from(params));
        if tokio::time::timeout(STEP_BOUND, agent.gateway.send(barrier))
            .await
            .is_err()
        {
            tracing::warn!(session_id = %session_id, "park barrier: the gateway did not answer in time");
        }
    }
    // Astra r2 #8: the scheduler fold is awaited FIRST; the cancel generation then moves together with the
    // transition to `Unparking` (inside `begin_implicit_unpark`, no await between), so a request registering
    // during the fold is not cancelled by a park that is still holding.
    use fuigo_tools::implementations::fuigo_build::scheduler::types::{FoldId, FoldTxn};
    // The fold belongs to ONE park op. If the park was replaced while it was awaited (P withdrawn, Q parked), the
    // prompt still has to unpark: Grok r4 #3, loop from the fresh entry while a DIFFERENT park op holds the
    // session (each round is one bounded fold, and a round only repeats because a new park replaced the last),
    // and fail the prompt if the session is still parked when the loop gives up.
    let mut current = entry;
    let mut rounds = 0_u32;
    let (entry, commit_tx, fold_id, fold_answered, folded) = loop {
        let fold_id = FoldId {
            op: current.op,
            nonce: FOLD_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        };
        let (commit_tx, commit_rx) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + STEP_BOUND;
        // A scheduler that did not answer inside the bound listed nothing we know of: dropping `commit_tx` below
        // (and the scheduler's undeliverable reply) leaves its tasks unchanged and the fire runs as usual.
        let folded_ok = send_scheduler_paused(
            session,
            current.op,
            false,
            true,
            Some(FoldTxn { id: fold_id, commit: commit_rx }),
            deadline,
        )
        .await;
        let fold_answered = folded_ok.is_ok();
        let folded = folded_ok.unwrap_or_default();
        if let Some(entry) = quiesce::begin_implicit_unpark(session_id, current.op) {
            break (entry, commit_tx, fold_id, fold_answered, folded);
        }
        rounds += 1;
        match quiesce::entry(session_id) {
            // The park changed op under us: fold and unpark the one that holds now.
            Some(next) if next.op != current.op && next.phase != ParkPhase::Unparking && rounds < MAX_UNPARK_ROUNDS => {
                current = next;
            }
            // Another prompt or an explicit unpark won, or nothing parks the session any more.
            Some(next) if next.phase == ParkPhase::Unparking => return Ok(None),
            None => return Ok(None),
            // Still parked by a park this prompt could not unpark: the turn would never start.
            Some(_) => {
                return Err(crate::acp_error::session_unavailable(
                    "the session is parked and the prompt could not unpark it; retry the prompt",
                ));
            }
        }
    };
    // Opus r1 #4: armed as soon as the entry is Unparking, so a hung frame write or a dropped prompt future
    // cannot leave it there.
    let guard = ImplicitUnparkGuard {
        session_id: session_id.to_owned(),
        op: entry.op,
    };
    // The prompt's turn replaces the previous turn's summary; a title refresh still runs.
    let release = SessionCommand::QuiesceRelease {
        op: entry.op,
        owed: OwedWork {
            turn_summary: None,
            title_refresh: entry.owed.title_refresh,
            family_switch_compact: entry.owed.family_switch_compact,
        },
        reopen_spawns: entry.mode == ParkMode::Stop,
        kick: false,
        reminder: merge_reminders(folded_fires_reminder(&folded), fires_reminder(&entry.fires.into_texts())),
    };
    // Astra r2 #7: the fold is committed ONLY if the release (which carries the fold's reminder) was queued;
    // otherwise the commit sender is dropped and the scheduler leaves its tasks unchanged.
    // Grok r4 #5: queue the release and commit the fold BEFORE the slow part (writing the held frames), so the
    // scheduler's bounded commit wait cannot lapse after the reminder was queued.
    if session.cmd_tx.send(release).is_ok() {
        if fold_answered {
            let _ = commit_tx.send(fold_id);
        }
    } else {
        tracing::warn!(session_id = %session_id, "implicit unpark: the release was not queued; the fold is not committed");
    }
    let released = agent.park_hold.release(session_id).await;
    tracing::info!(session_id = %session_id, frames = released.frames, "session unparked by a prompt");
    Ok(Some(guard))
}

/// Handle `fuigo/session/unpark`.
pub async fn handle_unpark(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    let req: UnparkRequest = parse_params(args)?;
    let sid = acp::SessionId::new(req.session_id.clone());
    let session = agent
        .session_handle_waiting_for_load(&sid)
        .await
        .ok_or_else(|| unknown_session(&req.session_id))?;
    let outcome = unpark_session(agent, &session, &req.session_id).await;
    to_raw_response(&serde_json::json!({
        "resumed": true,
        "sessionId": req.session_id,
        "wasParked": outcome.was_parked,
        "released": {
            "frames": outcome.frames,
            "droppedFrames": outcome.dropped_frames,
        },
    }))
}

#[cfg(test)]
mod tests {
    /// P189 A2 r3: the "(N earlier scheduled prompts were dropped)" line is a notice, not an arrived prompt.
    #[test]
    fn the_arrived_count_excludes_the_dropped_notice() {
        let id = format!("p189a2-count-{}", uuid::Uuid::new_v4());
        let op = quiesce::begin_park(&id, quiesce::ParkMode::Hold).expect("park");
        assert!(quiesce::complete_park(&id, op));
        for n in 0..(quiesce::MAX_FOLDED_FIRES + 8) {
            assert!(quiesce::fold_fire_if_holding(&id, format!("job {n}")));
        }
        let texts = quiesce::entry(&id).expect("entry").fires.into_texts();
        quiesce::unpark(&id);
        assert_eq!(texts.len(), quiesce::MAX_FOLDED_FIRES + 1, "32 kept plus the notice line");
        let reminder = fires_reminder(&texts).expect("reminder");
        assert!(reminder.contains(&format!("{} scheduled task prompt(s) arrived", quiesce::MAX_FOLDED_FIRES)), "{reminder}");
        assert!(reminder.contains("(8 earlier scheduled prompts were dropped)"));
    }

    use super::*;

    /// Astra r1 #10/#7: every await of the park is bounded; a scheduler (or actor) that never answers ends
    /// the step at its bound, which the park reports as `timeout`.
    #[tokio::test(flavor = "current_thread")]
    async fn a_step_that_never_answers_ends_at_its_bound() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        let never = std::future::pending::<()>();
        let outcome = tokio::time::timeout(Duration::from_secs(10), bounded(deadline, never))
            .await
            .expect("bounded must end at its deadline");
        assert_eq!(outcome, None);
        assert_eq!(ParkFailure::Timeout.reason(), "timeout");
    }

    /// Astra r2 NEW-4: the parked load's readiness includes the in-process SDK servers (registered by
    /// `_meta["fuigo/mcp/servers"]`, no `configs` entry), ready or failed, not only the configured ones.
    #[test]
    fn mcp_readiness_includes_sdk_servers() {
        use crate::extensions::mcp::{McpClientStatus, McpSessionStatus, McpStatusSnapshot};
        let client = |name: &str, status| McpClientStatus {
            name: name.to_owned(),
            status,
            tools: Vec::new(),
            icons: Vec::new(),
        };
        let mut snapshot = McpStatusSnapshot {
            clients: vec![client("sdk-ok", McpSessionStatus::Ready)],
            acp_servers: vec!["sdk-ok".to_owned(), "sdk-bad".to_owned(), "sdk-slow".to_owned()],
            ..Default::default()
        };
        snapshot.init_failed.insert("sdk-bad".to_owned(), "handshake failed".to_owned());
        let states = mcp_server_states(&snapshot);
        let state_of = |name: &str| states.iter().find(|(n, _)| n == name).map(|(_, s)| *s);
        assert_eq!(state_of("sdk-ok"), Some(Some("ready")));
        assert_eq!(state_of("sdk-bad"), Some(Some("failed")));
        assert_eq!(state_of("sdk-slow"), Some(None), "an unsettled SDK server must hold the wait (then time out)");
    }

    #[test]
    fn park_params_default_to_hold_and_reject_unknown_modes() {
        let req: ParkRequest =
            serde_json::from_value(serde_json::json!({ "sessionId": "s" })).expect("parse");
        assert_eq!(ParkMode::parse(req.mode.as_deref()), Some(ParkMode::Hold));
        assert_eq!(req.timeout_ms, None);
        let req: ParkRequest = serde_json::from_value(
            serde_json::json!({ "sessionId": "s", "mode": "freeze", "timeoutMs": 5 }),
        )
        .expect("parse");
        assert_eq!(ParkMode::parse(req.mode.as_deref()), None);
        assert_eq!(req.timeout_ms, Some(5));
    }

    #[test]
    fn park_error_is_typed_with_its_reason() {
        let err = ParkFailure::Timeout.to_error("s-1", 250);
        assert_eq!(i32::from(err.code), PARK_ERROR_CODE);
        let data = err.data.expect("typed data");
        assert_eq!(data["reason"], "timeout");
        assert_eq!(data["sessionId"], "s-1");
        assert_eq!(data["timeoutMs"], 250);
        assert_eq!(data["error_kind"], "session_unavailable");
    }

    #[test]
    fn park_reply_has_the_documented_shape() {
        let report = QuiesceReport {
            turn_running: false,
            queued_inputs: 2,
            pending_notifications: 1,
            turn_summary_deferred: true,
            title_refresh_deferred: false,
        };
        let reply = park_reply("s-1", ParkMode::Stop, false, &report, 3, 1);
        assert_eq!(
            reply,
            serde_json::json!({
                "parked": true,
                "sessionId": "s-1",
                "mode": "stop",
                "alreadyParked": false,
                "deferred": {
                    "queuedInputs": 2,
                    "pendingNotifications": 1,
                    "turnSummary": true,
                    "titleRefresh": false,
                },
                "running": { "backgroundTasks": 3 },
                "stopped": { "backgroundTasks": 1 },
            })
        );
    }
}
