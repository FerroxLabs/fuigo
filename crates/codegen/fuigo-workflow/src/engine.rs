use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use rhai::{Dynamic, EvalAltResult, Position};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::host::{AgentOpts, HostError, WorkflowHostRequest};
use crate::journal::{HOST_ERROR_KEY, Journal, JournalError, request_hash};
use crate::run::{PauseKind, WorkflowOutcome};
use crate::{MAX_HOST_CALLS, MAX_PARALLEL};

pub struct WorkflowRunParams {
    pub script: String,
    pub args: serde_json::Value,
    pub journal: Journal,
    pub host_tx: mpsc::UnboundedSender<WorkflowHostRequest>,
    pub cancel: CancellationToken,
    pub max_ops: u64,
}

impl WorkflowRunParams {
    pub const DEFAULT_MAX_OPS: u64 = 100_000_000;
}

#[derive(Debug, Clone)]
enum ControlToken {
    Complete(serde_json::Value),
    Pause(PauseKind, String),
    Budget(String),
    Cancelled,
    Fatal(String),
}

struct Ctx {
    host_tx: mpsc::UnboundedSender<WorkflowHostRequest>,
    journal: Journal,
    seq: u64,
    /// The run's stop signal (the manager fires it on pause, stop and session shutdown).
    cancel: CancellationToken,
}

impl Ctx {
    fn replaying(&self) -> bool {
        self.journal.covers(self.seq)
    }

    fn next_seq(&mut self) -> ScriptResult<u64> {
        Ok(self.reserve_seqs(1)?.start)
    }

    fn reserve_seqs(&mut self, count: usize) -> ScriptResult<std::ops::Range<u64>> {
        let count = u64::try_from(count).map_err(|_| {
            terminated(ControlToken::Fatal(
                "workflow host-call count overflowed".into(),
            ))
        })?;
        let end = self.seq.checked_add(count).ok_or_else(|| {
            terminated(ControlToken::Fatal(
                "workflow host-call count overflowed".into(),
            ))
        })?;
        if end > MAX_HOST_CALLS {
            return Err(terminated(ControlToken::Fatal(format!(
                "workflow exceeded the maximum of {MAX_HOST_CALLS} result-bearing host calls"
            ))));
        }
        let start = self.seq;
        self.seq = end;
        Ok(start..end)
    }

    fn record(
        &mut self,
        seq: u64,
        kind: &str,
        hash: String,
        value: serde_json::Value,
    ) -> ScriptResult<()> {
        self.journal.initialize_recovery().map_err(journal_fatal)?;
        self.journal
            .record(seq, kind, hash, value)
            .map_err(journal_fatal)
    }
}

type ScriptResult<T> = Result<T, Box<EvalAltResult>>;

enum PendingAgent {
    Replayed(serde_json::Value),
    Live {
        seq: u64,
        hash: String,
        reply_rx: oneshot::Receiver<Result<crate::host::AgentResult, HostError>>,
    },
}

fn drain_parallel_replies(ctx: &Rc<RefCell<Ctx>>, pending: Vec<PendingAgent>) {
    for entry in pending {
        if let PendingAgent::Live { reply_rx, .. } = entry {
            let _ = await_host_reply(ctx, reply_rx);
        }
    }
}

/// Waits for the host's reply to a request the engine has already sent, without outliving the host.
///
/// A plain `blocking_recv` can wait forever on the engine itself. When a send races the host dropping
/// its receiver, tokio's mpsc can leave the request in the channel after the receiver's drop has drained
/// it; the request, and the reply sender inside it, then live until the channel's last sender is
/// dropped. The engine holds that sender, so it would wait on its own handle (P38: engine threads parked
/// in `release_agent_calls` behind a closed host channel). Once the channel reports closed, nothing still
/// queued can ever be received, so the engine lets go of its sender: that frees any stranded request, and
/// its dropped reply sender ends this wait with `RecvError`, the same answer as any dropped reply. A
/// request the host already received keeps its reply sender and is still awaited. Later sends fail
/// exactly as they would on the closed channel.
fn await_host_reply<T>(
    ctx: &Rc<RefCell<Ctx>>,
    mut reply_rx: oneshot::Receiver<T>,
) -> Result<T, oneshot::error::RecvError> {
    let replied = {
        let ctx = ctx.borrow();
        let mut closed = std::pin::pin!(ctx.host_tx.closed());
        block_on(std::future::poll_fn(|cx| {
            if let Poll::Ready(reply) = Pin::new(&mut reply_rx).poll(cx) {
                return Poll::Ready(Some(reply));
            }
            closed.as_mut().poll(cx).map(|()| None)
        }))
    };
    if let Some(reply) = replied {
        return reply;
    }
    let (detached, _) = mpsc::unbounded_channel();
    drop(std::mem::replace(&mut ctx.borrow_mut().host_tx, detached));
    block_on(reply_rx)
}

/// What a host call ends with when the host is gone: its channel refused the request (`failure` is
/// then "workflow host channel closed") or the reply was lost ("workflow host dropped reply").
///
/// If the run's stop signal has fired, the host going away is that stop taking effect: on cancel the
/// host answers what it has queued with `Cancelled` and ends, and a request sent into that teardown
/// is dropped with the receiver or stranded (P38). Such a call ends exactly as if the host had
/// answered `HostError::Cancelled`, so the run finishes `Cancelled`, which the manager keeps as
/// `UserPaused` for a pause and `Cancelled` for a stop. No result or terminal is journaled for it; a
/// dispatch intent already recorded stays, so resuming past an effect-bearing call reports its outcome
/// unknown, exactly as after any stop that interrupts one. Without a stop, a vanished host is a failure
/// (P38-F).
fn host_gone(ctx: &Rc<RefCell<Ctx>>, failure: &str) -> Box<EvalAltResult> {
    if ctx.borrow().cancel.is_cancelled() {
        terminated(ControlToken::Cancelled)
    } else {
        terminated(ControlToken::Fatal(failure.into()))
    }
}

/// Drives `future` to completion on this thread. The engine runs on a plain blocking thread, and the
/// futures it waits on (tokio `sync` primitives) need only a waker, not a runtime.
fn block_on<F: Future>(future: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl std::task::Wake for Unpark {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &std::sync::Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(std::sync::Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
        std::thread::park();
    }
}

pub fn run_workflow(params: WorkflowRunParams) -> WorkflowOutcome {
    let WorkflowRunParams {
        script,
        args,
        journal,
        host_tx,
        cancel,
        max_ops,
    } = params;

    let ctx = Rc::new(RefCell::new(Ctx {
        host_tx,
        journal,
        seq: 0,
        cancel: cancel.clone(),
    }));

    let mut engine = rhai::Engine::new();
    crate::route_script_output(&mut engine);
    engine.set_max_operations(max_ops);
    engine.set_max_call_levels(64);
    engine.set_max_expr_depths(128, 64);
    engine.set_max_string_size(16 * 1024 * 1024);
    engine.set_max_array_size(65_536);
    engine.set_max_map_size(65_536);
    engine.set_module_resolver(rhai::module_resolvers::DummyModuleResolver::new());
    engine.disable_symbol("eval");
    engine.register_fn("timestamp", || -> ScriptResult<()> {
        Err(runtime_error(
            "timestamp() is unavailable: workflow scripts must be deterministic (wall-clock \
             time breaks resume). Pass timestamps in via `args` instead.",
        ))
    });
    engine.register_fn("sleep", |_seconds: i64| -> ScriptResult<()> {
        Err(runtime_error(
            "sleep() is unavailable in workflow scripts — host calls already block until \
             their work finishes.",
        ))
    });
    engine.register_fn("sleep", |_seconds: f64| -> ScriptResult<()> {
        Err(runtime_error(
            "sleep() is unavailable in workflow scripts — host calls already block until \
             their work finishes.",
        ))
    });
    engine.register_fn("exit", || -> ScriptResult<()> {
        Err(runtime_error(
            "exit() is unavailable — end a workflow with complete(value) or pause(kind, msg).",
        ))
    });

    engine.on_progress(move |_ops| {
        if cancel.is_cancelled() {
            Some(Dynamic::from(ControlToken::Cancelled))
        } else {
            None
        }
    });

    register_host_fns(&mut engine, &ctx);

    let ast = match engine.compile(&script) {
        Ok(ast) => ast,
        Err(e) => {
            return WorkflowOutcome::Failed {
                error: format!("script failed to compile: {e}"),
            };
        }
    };

    let mut scope = rhai::Scope::new();
    let args_dyn = match rhai::serde::to_dynamic(&args) {
        Ok(d) => d,
        Err(e) => {
            return WorkflowOutcome::Failed {
                error: format!("invalid workflow args: {e}"),
            };
        }
    };
    scope.push_dynamic("args", args_dyn);

    match engine.eval_ast_with_scope::<Dynamic>(&mut scope, &ast) {
        Ok(value) => WorkflowOutcome::Completed {
            result: dynamic_to_value(value),
        },
        Err(err) => outcome_from_error(*err),
    }
}

fn outcome_from_error(err: EvalAltResult) -> WorkflowOutcome {
    if let Some(token) = find_control_token(&err) {
        return match token {
            ControlToken::Complete(result) => WorkflowOutcome::Completed { result },
            ControlToken::Pause(kind, message) => WorkflowOutcome::Paused { kind, message },
            ControlToken::Budget(message) => WorkflowOutcome::BudgetExceeded { message },
            ControlToken::Cancelled => WorkflowOutcome::Cancelled,
            ControlToken::Fatal(error) => WorkflowOutcome::Failed { error },
        };
    }
    WorkflowOutcome::Failed {
        error: crate::with_rhai_hint(err.to_string()),
    }
}

fn find_control_token(err: &EvalAltResult) -> Option<ControlToken> {
    match err {
        EvalAltResult::ErrorTerminated(token, _) => token.clone().try_cast::<ControlToken>(),
        EvalAltResult::ErrorInFunctionCall(_, _, inner, _) => find_control_token(inner),
        EvalAltResult::ErrorInModule(_, inner, _) => find_control_token(inner),
        _ => None,
    }
}

fn terminated(token: ControlToken) -> Box<EvalAltResult> {
    Box::new(EvalAltResult::ErrorTerminated(
        Dynamic::from(token),
        Position::NONE,
    ))
}

fn runtime_error(message: impl Into<String>) -> Box<EvalAltResult> {
    Box::new(EvalAltResult::ErrorRuntime(
        Dynamic::from(message.into()),
        Position::NONE,
    ))
}

fn journal_fatal(error: JournalError) -> Box<EvalAltResult> {
    terminated(ControlToken::Fatal(error.to_string()))
}

fn dynamic_to_value(d: Dynamic) -> serde_json::Value {
    rhai::serde::from_dynamic::<serde_json::Value>(&d).unwrap_or(serde_json::Value::Null)
}

fn value_to_dynamic(v: &serde_json::Value) -> ScriptResult<Dynamic> {
    rhai::serde::to_dynamic(v).map_err(|e| runtime_error(format!("host result conversion: {e}")))
}

fn map_to_value(map: rhai::Map) -> ScriptResult<serde_json::Value> {
    rhai::serde::from_dynamic::<serde_json::Value>(&Dynamic::from_map(map))
        .map_err(|e| runtime_error(format!("invalid options map: {e}")))
}

fn replay_spawn_agent(
    journal: &Journal,
    seq: u64,
    payload: &serde_json::Value,
    hash: &str,
) -> Result<Option<serde_json::Value>, JournalError> {
    let normal = journal.replay(seq, "spawn_agent", hash);
    match &normal {
        Ok(Some(_)) => return normal,
        Ok(None) | Err(JournalError::Divergence { .. }) => {}
        Err(_) => return normal,
    }

    let Some(mut legacy_payload) = payload.as_object().cloned() else {
        return normal;
    };
    if legacy_payload.remove("effort").is_none() {
        return normal;
    }
    let legacy_hash = request_hash("spawn_agent", &serde_json::Value::Object(legacy_payload));
    journal.replay(seq, "spawn_agent", &legacy_hash)
}

fn host_call<T>(
    ctx: &Rc<RefCell<Ctx>>,
    kind: &'static str,
    payload: serde_json::Value,
    build: impl FnOnce(oneshot::Sender<Result<T, HostError>>) -> WorkflowHostRequest,
    to_result: impl FnOnce(T) -> serde_json::Value,
) -> ScriptResult<serde_json::Value> {
    let hash = request_hash(kind, &payload);
    let seq = ctx.borrow_mut().next_seq()?;

    let replayed = {
        let ctx = ctx.borrow();
        if kind == "spawn_agent" {
            replay_spawn_agent(&ctx.journal, seq, &payload, &hash)
        } else {
            ctx.journal.replay(seq, kind, &hash)
        }
    };
    match replayed {
        Ok(Some(recorded)) => {
            if let Some(err) = replay_host_error(&recorded) {
                return Err(err);
            }
            return Ok(recorded);
        }
        Ok(None) => {}
        Err(error) => return Err(journal_fatal(error)),
    }

    ctx.borrow_mut()
        .journal
        .dispatch(seq, kind, &hash)
        .map_err(journal_fatal)?;
    let (reply_tx, reply_rx) = oneshot::channel();
    let sent = ctx.borrow().host_tx.send(build(reply_tx));
    sent.map_err(|_| host_gone(ctx, "workflow host channel closed"))?;

    let reply = await_host_reply(ctx, reply_rx)
        .map_err(|_| host_gone(ctx, "workflow host dropped reply"))?;

    let value = match reply {
        Ok(v) => to_result(v),
        Err(HostError::AgentCallQuotaExceeded { requested, maximum }) => {
            return Err(runtime_error(format!(
                "workflow agent-call quota exceeded: requested {requested}, maximum {maximum}"
            )));
        }
        Err(HostError::BudgetExceeded) => {
            return Err(terminated(ControlToken::Budget(
                "workflow agent budget exceeded".into(),
            )));
        }
        Err(HostError::Cancelled) => return Err(terminated(ControlToken::Cancelled)),
        Err(HostError::Unsupported(msg)) => {
            let sentinel = host_error_sentinel(&msg);
            ctx.borrow_mut().record(seq, kind, hash, sentinel)?;
            return Err(runtime_error(msg));
        }
        Err(HostError::Failed(msg)) => {
            let sentinel = host_error_sentinel(&msg);
            ctx.borrow_mut().record(seq, kind, hash, sentinel)?;
            return Err(runtime_error(msg));
        }
    };

    ctx.borrow_mut().record(seq, kind, hash, value.clone())?;
    Ok(value)
}

const HOST_TERMINAL_KEY: &str = "__fuigo_workflow_parallel_terminal";
const TERMINAL_BUDGET: &str = "budget_exceeded";
const TERMINAL_CANCELLED: &str = "cancelled";
const TERMINAL_DROPPED_REPLY: &str = "dropped_reply";

fn host_error_sentinel(message: &str) -> serde_json::Value {
    serde_json::json!({ HOST_ERROR_KEY: message })
}

fn replay_host_error(recorded: &serde_json::Value) -> Option<Box<rhai::EvalAltResult>> {
    let message = recorded.get(HOST_ERROR_KEY)?.as_str()?;
    Some(runtime_error(message.to_string()))
}

fn host_terminal_sentinel(kind: &str) -> serde_json::Value {
    serde_json::json!({ HOST_TERMINAL_KEY: kind })
}

fn host_terminal_error(kind: &str) -> Box<rhai::EvalAltResult> {
    match kind {
        TERMINAL_BUDGET => terminated(ControlToken::Budget(
            "workflow agent budget exceeded".into(),
        )),
        TERMINAL_CANCELLED => terminated(ControlToken::Cancelled),
        TERMINAL_DROPPED_REPLY => {
            terminated(ControlToken::Fatal("workflow host dropped reply".into()))
        }
        _ => terminated(ControlToken::Fatal(
            "workflow journal contains an unknown terminal marker".into(),
        )),
    }
}

fn is_host_terminal_sentinel(recorded: &serde_json::Value) -> bool {
    recorded.get(HOST_TERMINAL_KEY).is_some()
}

fn host_emit(ctx: &Rc<RefCell<Ctx>>, build: impl FnOnce(bool) -> WorkflowHostRequest) {
    let (replaying, tx) = {
        let ctx = ctx.borrow();
        (ctx.replaying(), ctx.host_tx.clone())
    };
    let _ = tx.send(build(replaying));
}

fn reserve_agent_calls(ctx: &Rc<RefCell<Ctx>>, count: usize) -> ScriptResult<()> {
    if count == 0 {
        return Ok(());
    }
    let count =
        u64::try_from(count).map_err(|_| runtime_error("workflow agent-call count overflowed"))?;
    let (reply_tx, reply_rx) = oneshot::channel();
    let sent = ctx
        .borrow()
        .host_tx
        .send(WorkflowHostRequest::ReserveAgentCalls {
            count,
            reply: reply_tx,
        });
    sent.map_err(|_| host_gone(ctx, "workflow host channel closed"))?;
    match await_host_reply(ctx, reply_rx)
        .map_err(|_| host_gone(ctx, "workflow host dropped reply"))?
    {
        Ok(()) => Ok(()),
        Err(HostError::AgentCallQuotaExceeded { requested, maximum }) => {
            Err(terminated(ControlToken::Budget(format!(
                "workflow agent budget exceeded: requested {requested}, maximum {maximum}"
            ))))
        }
        Err(HostError::Cancelled) => Err(terminated(ControlToken::Cancelled)),
        Err(HostError::BudgetExceeded) => Err(terminated(ControlToken::Budget(
            "workflow agent budget exceeded".into(),
        ))),
        Err(HostError::Unsupported(message) | HostError::Failed(message)) => {
            Err(runtime_error(message))
        }
    }
}

fn release_agent_calls(ctx: &Rc<RefCell<Ctx>>, count: usize) {
    if count == 0 {
        return;
    }
    let Ok(count) = u64::try_from(count) else {
        return;
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    if ctx
        .borrow()
        .host_tx
        .send(WorkflowHostRequest::ReleaseAgentCalls {
            count,
            reply: reply_tx,
        })
        .is_err()
    {
        return;
    }
    let _ = await_host_reply(ctx, reply_rx);
}

fn is_resumable_unjournaled_terminal(err: &EvalAltResult) -> bool {
    matches!(
        find_control_token(err),
        Some(ControlToken::Cancelled | ControlToken::Budget(_))
    )
}

fn spawn_agent_call(ctx: &Rc<RefCell<Ctx>>, opts: AgentOpts) -> ScriptResult<Dynamic> {
    let payload = serde_json::to_value(&opts)
        .map_err(|e| runtime_error(format!("invalid agent options: {e}")))?;
    let hash = request_hash("spawn_agent", &payload);
    let is_live = {
        let ctx = ctx.borrow();
        match replay_spawn_agent(&ctx.journal, ctx.seq, &payload, &hash) {
            Ok(Some(_)) => false,
            Ok(None) => true,
            Err(error) => return Err(journal_fatal(error)),
        }
    };
    if is_live {
        reserve_agent_calls(ctx, 1)?;
    }
    let value = match host_call(
        ctx,
        "spawn_agent",
        payload,
        |reply| WorkflowHostRequest::SpawnAgent { opts, reply },
        |result| serde_json::to_value(result).unwrap_or(serde_json::Value::Null),
    ) {
        Ok(value) => value,
        Err(err) => {
            if is_live && is_resumable_unjournaled_terminal(&err) {
                release_agent_calls(ctx, 1);
            }
            return Err(err);
        }
    };
    value_to_dynamic(&value)
}

fn agent_opts_from_map(prompt: Option<&str>, map: rhai::Map) -> ScriptResult<AgentOpts> {
    let value = map_to_value(map)?;
    let mut opts: AgentOpts = serde_json::from_value(value)
        .map_err(|e| runtime_error(format!("invalid agent options: {e}")))?;
    if let Some(prompt) = prompt {
        opts.prompt = prompt.to_string();
    }
    if opts.prompt.trim().is_empty() {
        return Err(runtime_error("agent prompt must not be empty"));
    }
    Ok(opts)
}

fn register_host_fns(engine: &mut rhai::Engine, ctx: &Rc<RefCell<Ctx>>) {
    let c = ctx.clone();
    engine.register_fn("agent", move |prompt: &str| -> ScriptResult<Dynamic> {
        spawn_agent_call(
            &c,
            AgentOpts {
                prompt: prompt.to_string(),
                ..Default::default()
            },
        )
    });
    let c = ctx.clone();
    engine.register_fn(
        "agent",
        move |prompt: &str, opts: rhai::Map| -> ScriptResult<Dynamic> {
            let opts = agent_opts_from_map(Some(prompt), opts)?;
            spawn_agent_call(&c, opts)
        },
    );

    let c = ctx.clone();
    engine.register_fn(
        "parallel",
        move |items: rhai::Array| -> ScriptResult<rhai::Array> {
            if items.len() > MAX_PARALLEL {
                return Err(runtime_error(format!(
                    "parallel() accepts at most {MAX_PARALLEL} items per call (got {})",
                    items.len()
                )));
            }
            let mut opts_list = Vec::with_capacity(items.len());
            for item in items {
                let map = item
                    .try_cast::<rhai::Map>()
                    .ok_or_else(|| runtime_error("parallel() items must be option maps"))?;
                opts_list.push(agent_opts_from_map(None, map)?);
            }

            let requests = opts_list
                .into_iter()
                .map(|opts| {
                    let payload = serde_json::to_value(&opts)
                        .map_err(|e| runtime_error(format!("invalid agent options: {e}")))?;
                    let hash = request_hash("spawn_agent", &payload);
                    Ok((opts, payload, hash))
                })
                .collect::<ScriptResult<Vec<_>>>()?;
            let live_count = {
                let ctx = c.borrow();
                let mut seq = ctx.seq;
                let mut live = 0usize;
                for (_, payload, hash) in &requests {
                    match replay_spawn_agent(&ctx.journal, seq, payload, hash) {
                        Ok(Some(_)) => {}
                        Ok(None) => live += 1,
                        Err(error) => return Err(journal_fatal(error)),
                    }
                    seq = seq.checked_add(1).ok_or_else(|| {
                        terminated(ControlToken::Fatal(
                            "workflow host-call count overflowed".into(),
                        ))
                    })?;
                }
                live
            };
            reserve_agent_calls(&c, live_count)?;
            let mut pending = Vec::with_capacity(requests.len());
            for (opts, payload, hash) in requests {
                // Bind first: draining waits on the host and borrows `c`, so no borrow may be held.
                let seq = c.borrow_mut().next_seq();
                let seq = seq.inspect_err(|_| {
                    drain_parallel_replies(&c, std::mem::take(&mut pending));
                })?;
                let replayed = replay_spawn_agent(&c.borrow().journal, seq, &payload, &hash);
                match replayed {
                    Ok(Some(value)) => pending.push(PendingAgent::Replayed(value)),
                    Ok(None) => {
                        let dispatched = c.borrow_mut().journal.dispatch(seq, "spawn_agent", &hash);
                        if let Err(error) = dispatched {
                            drain_parallel_replies(&c, pending);
                            return Err(journal_fatal(error));
                        }
                        let (reply_tx, reply_rx) = oneshot::channel();
                        if c.borrow()
                            .host_tx
                            .send(WorkflowHostRequest::SpawnAgent {
                                opts,
                                reply: reply_tx,
                            })
                            .is_err()
                        {
                            drain_parallel_replies(&c, pending);
                            return Err(host_gone(&c, "workflow host channel closed"));
                        }
                        pending.push(PendingAgent::Live {
                            seq,
                            hash,
                            reply_rx,
                        });
                    }
                    Err(error) => {
                        drain_parallel_replies(&c, pending);
                        return Err(journal_fatal(error));
                    }
                }
            }

            let mut resolved: Vec<(Option<(u64, String)>, serde_json::Value)> =
                Vec::with_capacity(pending.len());
            let mut terminal_kind: Option<String> = None;
            let mut terminal_error = None;
            let mut resumable_terminal = false;
            for entry in pending {
                match entry {
                    PendingAgent::Replayed(value) => {
                        if is_host_terminal_sentinel(&value) {
                            let kind = value
                                .get(HOST_TERMINAL_KEY)
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("unknown")
                                .to_string();
                            if kind == TERMINAL_BUDGET || kind == TERMINAL_CANCELLED {
                                terminal_kind.get_or_insert(kind);
                                resumable_terminal = true;
                            } else {
                                terminal_kind.get_or_insert(kind);
                            }
                            continue;
                        }
                        if let Some(error) = replay_host_error(&value) {
                            terminal_error.get_or_insert(error);
                            continue;
                        }
                        resolved.push((None, value));
                    }
                    PendingAgent::Live {
                        seq,
                        hash,
                        reply_rx,
                    } => {
                        let value = match await_host_reply(&c, reply_rx) {
                            Ok(Ok(result)) => {
                                serde_json::to_value(result).unwrap_or(serde_json::Value::Null)
                            }
                            Ok(Err(HostError::BudgetExceeded)) => {
                                terminal_kind.get_or_insert_with(|| TERMINAL_BUDGET.to_string());
                                resumable_terminal = true;
                                host_terminal_sentinel(TERMINAL_BUDGET)
                            }
                            Ok(Err(HostError::Cancelled)) => {
                                terminal_kind.get_or_insert_with(|| TERMINAL_CANCELLED.to_string());
                                resumable_terminal = true;
                                host_terminal_sentinel(TERMINAL_CANCELLED)
                            }
                            // A reply lost to the teardown of a stopped run is that stop (see `host_gone`).
                            Err(_) if c.borrow().cancel.is_cancelled() => {
                                terminal_kind.get_or_insert_with(|| TERMINAL_CANCELLED.to_string());
                                resumable_terminal = true;
                                host_terminal_sentinel(TERMINAL_CANCELLED)
                            }
                            Err(_) => {
                                terminal_kind
                                    .get_or_insert_with(|| TERMINAL_DROPPED_REPLY.to_string());
                                host_terminal_sentinel(TERMINAL_DROPPED_REPLY)
                            }
                            Ok(Err(
                                HostError::AgentCallQuotaExceeded { .. }
                                | HostError::Unsupported(_)
                                | HostError::Failed(_),
                            )) => serde_json::Value::Null,
                        };
                        resolved.push((Some((seq, hash)), value));
                    }
                }
            }

            if resumable_terminal {
                release_agent_calls(&c, live_count);
            } else {
                for (live, value) in &resolved {
                    let Some((seq, hash)) = live else {
                        continue;
                    };
                    if let Err(error) =
                        c.borrow_mut()
                            .record(*seq, "spawn_agent", hash.clone(), value.clone())
                    {
                        terminal_error.get_or_insert(error);
                        break;
                    }
                }
            }

            if let Some(kind) = terminal_kind {
                return Err(host_terminal_error(&kind));
            }
            if let Some(error) = terminal_error {
                return Err(error);
            }

            let mut results = rhai::Array::with_capacity(resolved.len());
            for (_, value) in resolved {
                match value_to_dynamic(&value) {
                    Ok(value) => results.push(value),
                    Err(error) => return Err(error),
                }
            }
            Ok(results)
        },
    );

    let c = ctx.clone();
    engine.register_fn("phase", move |title: &str| {
        let title = title.to_string();
        host_emit(&c, |replayed| WorkflowHostRequest::Phase {
            title,
            replayed,
        });
    });

    let c = ctx.clone();
    engine.register_fn("log", move |message: &str| {
        let message = message.to_string();
        host_emit(&c, |replayed| WorkflowHostRequest::Log {
            message,
            replayed,
        });
    });
    let c = ctx.clone();
    engine.on_print(move |message| {
        let message = message.to_string();
        host_emit(&c, |replayed| WorkflowHostRequest::Log {
            message,
            replayed,
        });
    });

    let c = ctx.clone();
    engine.on_debug(move |message, _source, _pos| {
        let message = message.to_string();
        host_emit(&c, |replayed| WorkflowHostRequest::Log {
            message,
            replayed,
        });
    });

    let c = ctx.clone();
    engine.register_fn(
        "telemetry_event",
        move |name: &str, fields: rhai::Map| -> ScriptResult<()> {
            let fields = map_to_value(fields)?;
            let name = name.to_string();
            host_emit(&c, |replayed| WorkflowHostRequest::Telemetry {
                name,
                fields,
                replayed,
            });
            Ok(())
        },
    );

    engine.register_fn("complete", move |value: Dynamic| -> ScriptResult<()> {
        Err(terminated(ControlToken::Complete(dynamic_to_value(value))))
    });
    engine.register_fn("complete", move || -> ScriptResult<()> {
        Err(terminated(ControlToken::Complete(serde_json::Value::Null)))
    });

    engine.register_fn(
        "pause",
        move |kind: &str, message: &str| -> ScriptResult<()> {
            let kind: PauseKind = kind.parse().map_err(|e: String| runtime_error(e))?;
            Err(terminated(ControlToken::Pause(kind, message.to_string())))
        },
    );

    let c = ctx.clone();
    engine.register_fn(
        "await_user",
        move |kind: &str, message: &str| -> ScriptResult<()> {
            let parsed: PauseKind = kind.parse().map_err(|e: String| runtime_error(e))?;
            let payload = serde_json::json!({ "kind": kind, "message": message });
            let hash = request_hash("await_user", &payload);
            let seq = c.borrow_mut().next_seq()?;
            let replayed = c.borrow().journal.replay(seq, "await_user", &hash);
            match replayed {
                Ok(Some(_)) => Ok(()),
                Ok(None) => {
                    c.borrow_mut()
                        .record(seq, "await_user", hash, serde_json::Value::Null)?;
                    Err(terminated(ControlToken::Pause(parsed, message.to_string())))
                }
                Err(error) => Err(journal_fatal(error)),
            }
        },
    );

    let c = ctx.clone();
    engine.register_fn("budget", move || -> ScriptResult<Dynamic> {
        let value = host_call(
            &c,
            "budget",
            serde_json::Value::Null,
            |reply| WorkflowHostRequest::BudgetQuery { reply },
            |state| serde_json::to_value(state).unwrap_or(serde_json::Value::Null),
        )?;
        value_to_dynamic(&value)
    });

    let c = ctx.clone();
    engine.register_fn(
        "render_template",
        move |name: &str, vars: rhai::Map| -> ScriptResult<Dynamic> {
            let vars = map_to_value(vars)?;
            let payload = serde_json::json!({ "name": name, "vars": vars });
            let name = name.to_string();
            let value = host_call(
                &c,
                "render_template",
                payload,
                |reply| WorkflowHostRequest::RenderTemplate { name, vars, reply },
                serde_json::Value::String,
            )?;
            value_to_dynamic(&value)
        },
    );

    let c = ctx.clone();
    engine.register_fn(
        "write_scratch_file",
        move |name: &str, content: &str| -> ScriptResult<Dynamic> {
            let payload = serde_json::json!({ "name": name, "content": content });
            let (name, content) = (name.to_string(), content.to_string());
            let value = host_call(
                &c,
                "write_scratch_file",
                payload,
                |reply| WorkflowHostRequest::WriteScratchFile {
                    name,
                    content,
                    reply,
                },
                serde_json::Value::String,
            )?;
            value_to_dynamic(&value)
        },
    );

    let c = ctx.clone();
    engine.register_fn(
        "read_scratch_file",
        move |name: &str| -> ScriptResult<Dynamic> {
            let payload = serde_json::json!({ "name": name });
            let name = name.to_string();
            let value = host_call(
                &c,
                "read_scratch_file",
                payload,
                |reply| WorkflowHostRequest::ReadScratchFile { name, reply },
                serde_json::Value::String,
            )?;
            value_to_dynamic(&value)
        },
    );

    let c = ctx.clone();
    engine.register_fn(
        "git_diff_since",
        move |commit: &str| -> ScriptResult<Dynamic> {
            let payload = serde_json::json!({ "commit": commit });
            let commit = commit.to_string();
            let value = host_call(
                &c,
                "git_diff_since",
                payload,
                |reply| WorkflowHostRequest::GitDiffSince { commit, reply },
                serde_json::Value::String,
            )?;
            value_to_dynamic(&value)
        },
    );

    engine.register_fn("fingerprint", |text: &str| -> String {
        crate::journal::request_hash("fingerprint", &serde_json::Value::String(text.to_string()))
    });
    engine.register_fn("json_encode", |value: Dynamic| -> ScriptResult<String> {
        serde_json::to_string(&dynamic_to_value(value))
            .map_err(|error| runtime_error(format!("json encoding failed: {error}")))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{AgentResult, BudgetState};

    fn spawn_mock_host(
        mut rx: mpsc::UnboundedReceiver<WorkflowHostRequest>,
        mut on_request: impl FnMut(WorkflowHostRequest) + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            while let Some(req) = rx.blocking_recv() {
                match req {
                    WorkflowHostRequest::ReserveAgentCalls { reply, .. }
                    | WorkflowHostRequest::ReleaseAgentCalls { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    other => on_request(other),
                }
            }
        })
    }

    fn spawn_budget_tracking_host(
        mut rx: mpsc::UnboundedReceiver<WorkflowHostRequest>,
        agents_used: std::sync::Arc<std::sync::atomic::AtomicU64>,
        mut on_request: impl FnMut(WorkflowHostRequest) + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            while let Some(req) = rx.blocking_recv() {
                match req {
                    WorkflowHostRequest::ReserveAgentCalls { count, reply } => {
                        agents_used.fetch_add(count, std::sync::atomic::Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    WorkflowHostRequest::ReleaseAgentCalls { count, reply } => {
                        let _ = agents_used.fetch_update(
                            std::sync::atomic::Ordering::SeqCst,
                            std::sync::atomic::Ordering::SeqCst,
                            |used| Some(used.saturating_sub(count)),
                        );
                        let _ = reply.send(Ok(()));
                    }
                    other => on_request(other),
                }
            }
        })
    }

    fn agent_result(output: &str) -> AgentResult {
        AgentResult {
            agent_id: "child-1".into(),
            success: true,
            output: serde_json::Value::String(output.into()),
            cancelled: false,
            tokens_used: 10,
            duration_ms: 5,
        }
    }

    fn params(
        script: &str,
        journal: Journal,
        host_tx: mpsc::UnboundedSender<WorkflowHostRequest>,
    ) -> WorkflowRunParams {
        WorkflowRunParams {
            script: script.to_string(),
            args: serde_json::json!({ "objective": "test" }),
            journal,
            host_tx,
            cancel: CancellationToken::new(),
            max_ops: WorkflowRunParams::DEFAULT_MAX_OPS,
        }
    }

    /// The request a stranding host leaves behind.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Strand {
        Reserve,
        Release,
        Spawn,
        Budget,
    }

    /// A host that serves normally until it meets the request `strand` names, then stops serving and
    /// strands that request the way tokio's mpsc does when a send races the receiver's drop: the receiver
    /// is gone (the channel reports closed), and the request, with its reply sender, lives until the
    /// channel's last sender is dropped. `upgrade()` returning `None` is exactly "the last sender is gone".
    /// Any other `SpawnAgent` is answered by `spawn_reply`. `on_strand` runs once the host holds the
    /// request and before it stops serving: that is where a test fires the run's stop signal, the way a
    /// user's pause or stop lands while the request is in the channel and tears the host down.
    fn spawn_stranding_host(
        mut rx: mpsc::UnboundedReceiver<WorkflowHostRequest>,
        senders: mpsc::WeakUnboundedSender<WorkflowHostRequest>,
        strand: Strand,
        spawn_reply: fn() -> Result<AgentResult, HostError>,
        on_strand: impl FnOnce() + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let stranded = loop {
                let Some(req) = rx.blocking_recv() else {
                    return;
                };
                match (strand, req) {
                    (Strand::Reserve, req @ WorkflowHostRequest::ReserveAgentCalls { .. })
                    | (Strand::Release, req @ WorkflowHostRequest::ReleaseAgentCalls { .. })
                    | (Strand::Spawn, req @ WorkflowHostRequest::SpawnAgent { .. })
                    | (Strand::Budget, req @ WorkflowHostRequest::BudgetQuery { .. }) => break req,
                    (_, WorkflowHostRequest::ReserveAgentCalls { reply, .. })
                    | (_, WorkflowHostRequest::ReleaseAgentCalls { reply, .. }) => {
                        let _ = reply.send(Ok(()));
                    }
                    (_, WorkflowHostRequest::SpawnAgent { reply, .. }) => {
                        let _ = reply.send(spawn_reply());
                    }
                    _ => {}
                }
            };
            on_strand();
            drop(rx);
            while senders.upgrade().is_some() {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            drop(stranded);
        })
    }

    /// Runs the workflow on its own thread so a wedged engine is a named failure, not a hung test.
    fn run_bounded(test: &str, params: WorkflowRunParams) -> WorkflowOutcome {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done_tx.send(run_workflow(params));
        });
        done_rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .unwrap_or_else(|_| {
                panic!(
                    "{test}: the workflow engine was still waiting on a host reply 20 s after the \
                     host channel closed with that request stranded in it (P38 wedge)"
                )
            })
    }

    fn run_with_stranded(test: &str, script: &str, strand: Strand) -> WorkflowOutcome {
        let (tx, rx) = mpsc::unbounded_channel();
        let host = spawn_stranding_host(
            rx,
            tx.downgrade(),
            strand,
            || Err(HostError::Cancelled),
            || {},
        );
        let outcome = run_bounded(test, params(script, Journal::new(None), tx));
        host.join().expect("stranding host panicked");
        outcome
    }

    /// As `run_with_stranded`, but the run's stop signal fires while the stranded request is in the
    /// channel, as when the user pauses or stops the run during that host call (P38-F). Engine-side a
    /// pause and a stop are the same signal; the manager tells them apart by its pause intent.
    fn run_stopped_with_stranded(
        test: &str,
        script: &str,
        strand: Strand,
        journal: Journal,
    ) -> WorkflowOutcome {
        let (tx, rx) = mpsc::unbounded_channel();
        let stop = CancellationToken::new();
        let stop_in_host = stop.clone();
        let host = spawn_stranding_host(
            rx,
            tx.downgrade(),
            strand,
            || Ok(agent_result("answered")),
            move || stop_in_host.cancel(),
        );
        let mut params = params(script, journal, tx);
        params.cancel = stop;
        let outcome = run_bounded(test, params);
        host.join().expect("stranding host panicked");
        outcome
    }

    /// A host that fires the run's stop signal and stops serving when the first `ReserveAgentCalls`
    /// arrives, and only then grants it, so every request the engine sends afterwards is refused by the
    /// closed channel. Deterministic stand-in for a send that loses the race with the host's teardown.
    fn run_stopped_with_refused_send(test: &str, script: &str) -> WorkflowOutcome {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let stop = CancellationToken::new();
        let stop_in_host = stop.clone();
        let host = std::thread::spawn(move || {
            while let Some(req) = rx.blocking_recv() {
                if let WorkflowHostRequest::ReserveAgentCalls { reply, .. } = req {
                    stop_in_host.cancel();
                    drop(rx);
                    let _ = reply.send(Ok(()));
                    return;
                }
            }
        });
        let mut params = params(script, Journal::new(None), tx);
        params.cancel = stop;
        let outcome = run_bounded(test, params);
        host.join().expect("refusing host panicked");
        outcome
    }

    fn legacy_spawn_agent_hash(opts: &AgentOpts) -> String {
        let mut payload = serde_json::to_value(opts).unwrap();
        assert!(payload.as_object_mut().unwrap().remove("effort").is_some());
        request_hash("spawn_agent", &payload)
    }

    #[test]
    fn happy_path_completes_with_agent_output() {
        let (tx, rx) = mpsc::unbounded_channel();
        let host = spawn_mock_host(rx, |req| match req {
            WorkflowHostRequest::SpawnAgent { reply, .. } => {
                let _ = reply.send(Ok(agent_result("agent says hi")));
            }
            WorkflowHostRequest::Phase { .. } | WorkflowHostRequest::Log { .. } => {}
            other => panic!("unexpected request: {other:?}"),
        });

        let outcome = run_workflow(params(
            r#"
            let meta = #{ name: "t", description: "d" };
            phase("Work");
            let r = agent("do it", #{ label: "worker" });
            complete(r.output);
            "#,
            Journal::new(None),
            tx,
        ));
        drop(host);

        match outcome {
            WorkflowOutcome::Completed { result } => {
                assert_eq!(result, serde_json::json!("agent says hi"));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn catchable_host_failure_journals_and_replays() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("journal.jsonl");
        let script = r#"
            let meta = #{ name: "t", description: "d" };
            let d = "";
            try { d = git_diff_since("abc"); } catch (e) { d = "fallback"; }
            let r = agent("work");
            complete(r.output + ":" + d);
        "#;

        let (tx, rx) = mpsc::unbounded_channel();
        let host = spawn_mock_host(rx, |req| match req {
            WorkflowHostRequest::GitDiffSince { reply, .. } => {
                let _ = reply.send(Err(crate::host::HostError::Failed("boom".into())));
            }
            WorkflowHostRequest::SpawnAgent { reply, .. } => {
                let _ = reply.send(Ok(agent_result("one")));
            }
            WorkflowHostRequest::Phase { .. } | WorkflowHostRequest::Log { .. } => {}
            other => panic!("unexpected request: {other:?}"),
        });
        let outcome = run_workflow(params(script, Journal::new(Some(journal_path.clone())), tx));
        drop(host);
        match outcome {
            WorkflowOutcome::Completed { result } => {
                assert_eq!(result, serde_json::json!("one:fallback"));
            }
            other => panic!("expected Completed, got {other:?}"),
        }

        let (tx, rx) = mpsc::unbounded_channel();
        let host = spawn_mock_host(rx, |req| match req {
            WorkflowHostRequest::Phase { .. } | WorkflowHostRequest::Log { .. } => {}
            other => panic!("replay must not hit the host: {other:?}"),
        });
        let outcome = run_workflow(params(script, Journal::load(journal_path).unwrap(), tx));
        drop(host);
        match outcome {
            WorkflowOutcome::Completed { result } => {
                assert_eq!(result, serde_json::json!("one:fallback"));
            }
            other => panic!("expected replayed Completed, got {other:?}"),
        }
    }

    #[test]
    fn await_user_pauses_once_then_passes_on_resume() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("journal.jsonl");
        let script = r#"
            let meta = #{ name: "t", description: "d" };
            await_user("back_off", "needs a human");
            complete("resumed");
        "#;

        let (tx, _rx) = mpsc::unbounded_channel();
        let outcome = run_workflow(params(script, Journal::new(Some(journal_path.clone())), tx));
        match outcome {
            WorkflowOutcome::Paused { kind, message } => {
                assert_eq!(kind, PauseKind::BackOff);
                assert_eq!(message, "needs a human");
            }
            other => panic!("expected Paused, got {other:?}"),
        }

        let (tx, _rx) = mpsc::unbounded_channel();
        let outcome = run_workflow(params(script, Journal::load(journal_path).unwrap(), tx));
        match outcome {
            WorkflowOutcome::Completed { result } => {
                assert_eq!(result, serde_json::json!("resumed"));
            }
            other => panic!("expected Completed after resume, got {other:?}"),
        }
    }

    #[test]
    fn timestamp_is_blocked_for_determinism() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let outcome = run_workflow(params(
            r#"
            let meta = #{ name: "t", description: "d" };
            let t = timestamp();
            complete("unreachable");
            "#,
            Journal::new(None),
            tx,
        ));
        match outcome {
            WorkflowOutcome::Failed { error } => {
                assert!(error.contains("deterministic"), "unexpected error: {error}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn args_are_visible_to_script() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let outcome = run_workflow(params(
            r#"
            let meta = #{ name: "t", description: "d" };
            complete(args.objective);
            "#,
            Journal::new(None),
            tx,
        ));
        match outcome {
            WorkflowOutcome::Completed { result } => {
                assert_eq!(result, serde_json::json!("test"));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn pause_maps_kind() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let outcome = run_workflow(params(
            r#"
            let meta = #{ name: "t", description: "d" };
            pause("back_off", "too many rejections");
            "#,
            Journal::new(None),
            tx,
        ));
        match outcome {
            WorkflowOutcome::Paused { kind, message } => {
                assert_eq!(kind, PauseKind::BackOff);
                assert_eq!(message, "too many rejections");
            }
            other => panic!("expected Paused, got {other:?}"),
        }
    }

    #[test]
    fn cancellation_wins_over_pure_loop() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut p = params(
            r#"
            let meta = #{ name: "t", description: "d" };
            let x = 0;
            loop { x += 1; }
            "#,
            Journal::new(None),
            tx,
        );
        p.cancel = cancel;
        assert!(matches!(run_workflow(p), WorkflowOutcome::Cancelled));
    }

    #[test]
    fn parallel_rejects_oversized_fanout_before_spawning() {
        let (tx, rx) = mpsc::unbounded_channel();
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let requests_in_host = requests.clone();
        let host = spawn_mock_host(rx, move |req| {
            requests_in_host.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                let _ = reply.send(Ok(agent_result("unexpected")));
            }
        });
        let script = format!(
            r#"
            let meta = #{{ name: "t", description: "d" }};
            let jobs = [];
            for i in 0..{} {{ jobs.push(#{{ prompt: "job" + i.to_string() }}); }}
            parallel(jobs);
            "#,
            MAX_PARALLEL + 1
        );
        let outcome = run_workflow(params(&script, Journal::new(None), tx));
        drop(host);
        match outcome {
            WorkflowOutcome::Failed { error } => {
                assert!(error.contains("parallel() accepts at most"), "got: {error}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn host_call_limit_is_non_catchable_and_prevents_sends() {
        let (tx, rx) = mpsc::unbounded_channel();
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let requests_in_host = requests.clone();
        let host = spawn_mock_host(rx, move |req| {
            requests_in_host.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let WorkflowHostRequest::BudgetQuery { reply } = req {
                let _ = reply.send(Ok(BudgetState {
                    total: None,
                    spent: 0,
                    reserved: 0,
                    remaining: None,
                }));
            }
        });
        let mut journal = Journal::new(None);
        let hash = request_hash("budget", &serde_json::Value::Null);
        for seq in 0..MAX_HOST_CALLS {
            journal
                .record(
                    seq,
                    "budget",
                    hash.clone(),
                    serde_json::json!({ "total": null, "spent": 0, "reserved": 0, "remaining": null }),
                )
                .unwrap();
        }
        let script = format!(
            r#"
            let meta = #{{ name: "t", description: "d" }};
            for i in 0..{} {{ budget(); }}
            try {{ budget(); }} catch (e) {{ complete("caught"); }}
            complete("unreachable");
            "#,
            MAX_HOST_CALLS
        );
        let outcome = run_workflow(params(&script, journal, tx));
        drop(host);
        match outcome {
            WorkflowOutcome::Failed { error } => {
                assert!(error.contains("maximum of"), "got: {error}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn parallel_setup_error_drains_already_sent_replies() {
        let (tx, rx) = mpsc::unbounded_channel();
        let first_reply_observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first_reply_in_host = first_reply_observed.clone();
        let host = spawn_mock_host(rx, move |req| {
            if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                first_reply_in_host.store(
                    reply.send(Ok(agent_result("drained"))).is_ok(),
                    std::sync::atomic::Ordering::SeqCst,
                );
            }
        });
        let mut journal = Journal::new(None);
        // This fixture models a current run approaching the call cap, not a
        // legacy journal crossing its unprotected recovery boundary.
        journal.initialize_recovery().unwrap();
        let hash = request_hash("budget", &serde_json::Value::Null);
        for seq in 0..MAX_HOST_CALLS - 1 {
            journal
                .record(
                    seq,
                    "budget",
                    hash.clone(),
                    serde_json::json!({ "total": null, "spent": 0, "reserved": 0, "remaining": null }),
                )
                .unwrap();
        }
        let script = format!(
            r#"
            let meta = #{{ name: "t", description: "d" }};
            for i in 0..{} {{ budget(); }}
            parallel([#{{ prompt: "live" }}, #{{ prompt: "over-limit" }}]);
            "#,
            MAX_HOST_CALLS - 1
        );
        let outcome = run_workflow(params(&script, journal, tx));
        drop(host);
        match outcome {
            WorkflowOutcome::Failed { error } => {
                assert!(error.contains("maximum of"), "got: {error}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(first_reply_observed.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn parallel_budget_exceeded_blocks_ambiguous_panel_resume() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("journal.jsonl");
        let (tx, rx) = mpsc::unbounded_channel();
        let second_reply_observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second_reply_in_host = second_reply_observed.clone();
        let mut request_index = 0;
        let host = spawn_mock_host(rx, move |req| {
            if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                if request_index == 0 {
                    let _ = reply.send(Err(HostError::BudgetExceeded));
                } else {
                    second_reply_in_host.store(
                        reply.send(Ok(agent_result("drained"))).is_ok(),
                        std::sync::atomic::Ordering::SeqCst,
                    );
                }
                request_index += 1;
            }
        });
        let script = r#"
            let meta = #{ name: "t", description: "d" };
            parallel([#{ prompt: "first" }, #{ prompt: "second" }]);
        "#;
        let outcome = run_workflow(params(script, Journal::new(Some(journal_path.clone())), tx));
        drop(host);
        assert!(matches!(outcome, WorkflowOutcome::BudgetExceeded { .. }));
        assert!(second_reply_observed.load(std::sync::atomic::Ordering::SeqCst));

        let journal = Journal::load(journal_path).unwrap();
        assert_eq!(
            journal.len(),
            0,
            "resumable budget terminal must not journal the parallel panel"
        );

        let (tx, rx) = mpsc::unbounded_channel();
        let live_again = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let live_again_host = live_again.clone();
        let host = spawn_mock_host(rx, move |req| {
            if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                live_again_host.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = reply.send(Ok(agent_result("after raise")));
            }
        });
        let replay = run_workflow(params(script, journal, tx));
        drop(host);
        assert!(
            matches!(replay, WorkflowOutcome::Failed { ref error } if error.contains("unknown outcome"))
        );
        assert_eq!(live_again.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn stranded_release_ack_does_not_wedge_a_cancelled_agent() {
        let outcome = run_with_stranded(
            "stranded_release_ack_does_not_wedge_a_cancelled_agent",
            r#"
                let meta = #{ name: "t", description: "d" };
                let r = agent("work");
                complete(r.output);
            "#,
            Strand::Release,
        );
        assert!(
            matches!(outcome, WorkflowOutcome::Cancelled),
            "a lost release ack must not change the cancelled outcome, got {outcome:?}"
        );
    }

    #[test]
    fn stranded_release_ack_does_not_wedge_a_cancelled_parallel() {
        let outcome = run_with_stranded(
            "stranded_release_ack_does_not_wedge_a_cancelled_parallel",
            r#"
                let meta = #{ name: "t", description: "d" };
                let results = parallel([#{ prompt: "first" }, #{ prompt: "second" }]);
                complete(results);
            "#,
            Strand::Release,
        );
        assert!(
            matches!(outcome, WorkflowOutcome::Cancelled),
            "a lost release ack must not change the cancelled outcome, got {outcome:?}"
        );
    }

    #[test]
    fn stranded_reservation_fails_the_run_instead_of_wedging_it() {
        let outcome = run_with_stranded(
            "stranded_reservation_fails_the_run_instead_of_wedging_it",
            r#"
                let meta = #{ name: "t", description: "d" };
                let r = agent("work");
                complete(r.output);
            "#,
            Strand::Reserve,
        );
        assert!(
            matches!(outcome, WorkflowOutcome::Failed { ref error } if error.contains("workflow host dropped reply")),
            "got {outcome:?}"
        );
    }

    #[test]
    fn stranded_host_call_fails_the_run_instead_of_wedging_it() {
        let outcome = run_with_stranded(
            "stranded_host_call_fails_the_run_instead_of_wedging_it",
            r#"
                let meta = #{ name: "t", description: "d" };
                let r = agent("work");
                complete(r.output);
            "#,
            Strand::Spawn,
        );
        assert!(
            matches!(outcome, WorkflowOutcome::Failed { ref error } if error.contains("workflow host dropped reply")),
            "got {outcome:?}"
        );
    }

    #[test]
    fn stranded_parallel_agent_fails_the_run_instead_of_wedging_it() {
        let outcome = run_with_stranded(
            "stranded_parallel_agent_fails_the_run_instead_of_wedging_it",
            r#"
                let meta = #{ name: "t", description: "d" };
                let results = parallel([#{ prompt: "first" }, #{ prompt: "second" }]);
                complete(results);
            "#,
            Strand::Spawn,
        );
        // The second request either reached the channel before the host stopped serving (and is
        // dropped with the receiver) or its send fails; both end the run, through the pending-reply
        // loop or `drain_parallel_replies` respectively.
        assert!(
            matches!(outcome, WorkflowOutcome::Failed { ref error }
                if error.contains("workflow host dropped reply")
                    || error.contains("workflow host channel closed")),
            "got {outcome:?}"
        );
    }

    // P38-F: a pause or stop that lands while a request is lost to the host's teardown must finish the
    // run `Cancelled` (the manager keeps a pause as `UserPaused`), not `Failed`.

    const ONE_AGENT: &str = r#"
        let meta = #{ name: "t", description: "d" };
        let r = agent("work");
        complete(r.output);
    "#;

    fn assert_stopped(test: &str, outcome: &WorkflowOutcome) {
        assert!(
            matches!(outcome, WorkflowOutcome::Cancelled),
            "{test}: a host request lost to the teardown of a paused or stopped run must end the run \
             Cancelled, not {outcome:?}"
        );
    }

    #[test]
    fn stopped_run_with_stranded_reservation_ends_cancelled_and_resumes_live() {
        let test = "stopped_run_with_stranded_reservation_ends_cancelled_and_resumes_live";
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("journal.jsonl");
        // A current (v2) journal, as after any earlier journaled step. (A journal file that was never
        // written loads as legacy and cannot continue at all; that is independent of P38-F, see R021.)
        let mut journal = Journal::new(Some(journal_path.clone()));
        journal.initialize_recovery().unwrap();
        let outcome = run_stopped_with_stranded(test, ONE_AGENT, Strand::Reserve, journal);
        assert_stopped(test, &outcome);

        // The reservation never reached the host, so nothing was dispatched: resume runs the agent live.
        let (tx, rx) = mpsc::unbounded_channel();
        let host = spawn_mock_host(rx, |req| {
            if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                let _ = reply.send(Ok(agent_result("after resume")));
            }
        });
        let journal = Journal::load(journal_path).unwrap();
        let resumed = run_bounded(test, params(ONE_AGENT, journal, tx));
        drop(host);
        assert!(
            matches!(resumed, WorkflowOutcome::Completed { ref result } if result == "after resume"),
            "{test}: resume after the stop must run the agent live, got {resumed:?}"
        );
    }

    #[test]
    fn stopped_run_with_stranded_agent_host_call_ends_cancelled() {
        let test = "stopped_run_with_stranded_agent_host_call_ends_cancelled";
        let outcome = run_stopped_with_stranded(test, ONE_AGENT, Strand::Spawn, Journal::new(None));
        assert_stopped(test, &outcome);
    }

    #[test]
    fn stopped_run_with_stranded_budget_host_call_ends_cancelled() {
        let test = "stopped_run_with_stranded_budget_host_call_ends_cancelled";
        let outcome = run_stopped_with_stranded(
            test,
            r#"
                let meta = #{ name: "t", description: "d" };
                let b = budget();
                complete(b);
            "#,
            Strand::Budget,
            Journal::new(None),
        );
        assert_stopped(test, &outcome);
    }

    #[test]
    fn stopped_parallel_with_stranded_agent_ends_cancelled_without_journaling_a_terminal() {
        let test =
            "stopped_parallel_with_stranded_agent_ends_cancelled_without_journaling_a_terminal";
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("journal.jsonl");
        let outcome = run_stopped_with_stranded(
            test,
            // One item, so the request is always awaited in the pending-reply loop (a second one could
            // instead be refused at send, which `stopped_parallel_whose_agent_send_is_refused…` covers).
            r#"
                let meta = #{ name: "t", description: "d" };
                let results = parallel([#{ prompt: "only" }]);
                complete(results);
            "#,
            Strand::Spawn,
            Journal::new(Some(journal_path.clone())),
        );
        assert_stopped(test, &outcome);
        // A journaled `dropped_reply` terminal would fail every later resume of this panel. (The
        // dispatch intent is still recorded, as for any stop during a live agent; this checks only that
        // no result or terminal entry was written.)
        let journal = Journal::load(journal_path).unwrap();
        assert_eq!(
            journal.len(),
            0,
            "{test}: a stopped panel must not journal a terminal for the lost reply"
        );
    }

    #[test]
    fn stopped_run_whose_agent_send_is_refused_ends_cancelled() {
        let test = "stopped_run_whose_agent_send_is_refused_ends_cancelled";
        let outcome = run_stopped_with_refused_send(test, ONE_AGENT);
        assert_stopped(test, &outcome);
    }

    #[test]
    fn stopped_parallel_whose_agent_send_is_refused_ends_cancelled() {
        let test = "stopped_parallel_whose_agent_send_is_refused_ends_cancelled";
        let outcome = run_stopped_with_refused_send(
            test,
            r#"
                let meta = #{ name: "t", description: "d" };
                let results = parallel([#{ prompt: "first" }, #{ prompt: "second" }]);
                complete(results);
            "#,
        );
        assert_stopped(test, &outcome);
    }

    #[test]
    fn a_host_that_vanishes_without_a_stop_still_fails_the_run() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let host = std::thread::spawn(move || {
            while let Some(req) = rx.blocking_recv() {
                if let WorkflowHostRequest::ReserveAgentCalls { reply, .. } = req {
                    drop(rx);
                    let _ = reply.send(Ok(()));
                    return;
                }
            }
        });
        let outcome = run_bounded(
            "a_host_that_vanishes_without_a_stop_still_fails_the_run",
            params(ONE_AGENT, Journal::new(None), tx),
        );
        host.join().expect("host panicked");
        assert!(
            matches!(outcome, WorkflowOutcome::Failed { ref error } if error.contains("workflow host channel closed")),
            "without a stop a vanished host is a failure, got {outcome:?}"
        );
    }

    #[test]
    fn a_reply_the_host_already_received_is_still_awaited_after_its_channel_closes() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let host = std::thread::spawn(move || {
            loop {
                match rx.blocking_recv() {
                    Some(WorkflowHostRequest::ReserveAgentCalls { reply, .. }) => {
                        let _ = reply.send(Ok(()));
                    }
                    Some(WorkflowHostRequest::SpawnAgent { reply, .. }) => {
                        drop(rx);
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        let _ =
                            reply.send(Ok(agent_result("finished after the host stopped serving")));
                        return;
                    }
                    Some(_) => {}
                    None => return,
                }
            }
        });
        let outcome = run_bounded(
            "a_reply_the_host_already_received_is_still_awaited_after_its_channel_closes",
            params(
                r#"
                    let meta = #{ name: "t", description: "d" };
                    let r = agent("work");
                    complete(r.output);
                "#,
                Journal::new(None),
                tx,
            ),
        );
        host.join().expect("host panicked");
        match outcome {
            WorkflowOutcome::Completed { result } => assert_eq!(
                result,
                serde_json::json!("finished after the host stopped serving")
            ),
            other => panic!("an in-flight reply must still be delivered, got {other:?}"),
        }
    }

    #[test]
    fn cancelled_live_agent_releases_budget_so_resume_does_not_double_charge() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("journal.jsonl");
        let agents_used = std::sync::Arc::new(AtomicU64::new(0));
        let script = r#"
            let meta = #{ name: "t", description: "d" };
            let r = agent("work");
            complete(r.output);
        "#;

        {
            let used = agents_used.clone();
            let (tx, rx) = mpsc::unbounded_channel();
            let host = spawn_budget_tracking_host(rx, used, |req| {
                if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                    let _ = reply.send(Err(HostError::Cancelled));
                }
            });
            let outcome =
                run_workflow(params(script, Journal::new(Some(journal_path.clone())), tx));
            drop(host);
            assert!(matches!(outcome, WorkflowOutcome::Cancelled));
            assert_eq!(
                agents_used.load(Ordering::SeqCst),
                0,
                "cancelled agent must ReleaseAgentCalls the reserved slot"
            );
            assert_eq!(
                Journal::load(journal_path.clone()).unwrap().len(),
                0,
                "cancelled agent must leave the spawn unjournaled"
            );
        }

        {
            let used = agents_used.clone();
            let (tx, rx) = mpsc::unbounded_channel();
            let host = spawn_budget_tracking_host(rx, used, |req| {
                if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                    let _ = reply.send(Ok(agent_result("after resume")));
                }
            });
            let outcome = run_workflow(params(
                script,
                Journal::load(journal_path.clone()).unwrap(),
                tx,
            ));
            drop(host);
            match outcome {
                WorkflowOutcome::Failed { error } => assert!(error.contains("unknown outcome")),
                other => panic!("expected ambiguous outcome after cancellation, got {other:?}"),
            }
            assert_eq!(
                agents_used.load(Ordering::SeqCst),
                0,
                "ambiguous cancellation must not dispatch again"
            );
        }
    }

    #[test]
    fn cancelled_parallel_releases_budget_so_resume_does_not_double_charge() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("journal.jsonl");
        let agents_used = std::sync::Arc::new(AtomicU64::new(0));
        let script = r#"
            let meta = #{ name: "t", description: "d" };
            let results = parallel([#{ prompt: "first" }, #{ prompt: "second" }]);
            complete(results);
        "#;

        {
            let used = agents_used.clone();
            let (tx, rx) = mpsc::unbounded_channel();
            let host = spawn_budget_tracking_host(rx, used, |req| {
                if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                    let _ = reply.send(Err(HostError::Cancelled));
                }
            });
            let outcome =
                run_workflow(params(script, Journal::new(Some(journal_path.clone())), tx));
            drop(host);
            assert!(matches!(outcome, WorkflowOutcome::Cancelled));
            assert_eq!(
                agents_used.load(Ordering::SeqCst),
                0,
                "cancelled parallel must release live_count reserved slots"
            );
            assert_eq!(Journal::load(journal_path.clone()).unwrap().len(), 0);
        }

        {
            let used = agents_used.clone();
            let (tx, rx) = mpsc::unbounded_channel();
            let host = spawn_budget_tracking_host(rx, used, |req| {
                if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                    let _ = reply.send(Ok(agent_result("ok")));
                }
            });
            let outcome = run_workflow(params(
                script,
                Journal::load(journal_path.clone()).unwrap(),
                tx,
            ));
            drop(host);
            assert!(
                matches!(outcome, WorkflowOutcome::Failed { ref error } if error.contains("unknown outcome"))
            );
            assert_eq!(
                agents_used.load(Ordering::SeqCst),
                0,
                "ambiguous panel must not dispatch again"
            );
        }
    }

    #[test]
    fn budget_exceeded_live_agent_releases_budget_so_resume_does_not_double_charge() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("journal.jsonl");
        let agents_used = std::sync::Arc::new(AtomicU64::new(0));
        let script = r#"
            let meta = #{ name: "t", description: "d" };
            let r = agent("work");
            complete(r.output);
        "#;

        {
            let used = agents_used.clone();
            let (tx, rx) = mpsc::unbounded_channel();
            let host = spawn_budget_tracking_host(rx, used, |req| {
                if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                    let _ = reply.send(Err(HostError::BudgetExceeded));
                }
            });
            let outcome =
                run_workflow(params(script, Journal::new(Some(journal_path.clone())), tx));
            drop(host);
            assert!(matches!(outcome, WorkflowOutcome::BudgetExceeded { .. }));
            assert_eq!(
                agents_used.load(Ordering::SeqCst),
                0,
                "budget-exceeded agent must ReleaseAgentCalls the reserved slot"
            );
            assert_eq!(Journal::load(journal_path.clone()).unwrap().len(), 0);
        }

        {
            let used = agents_used.clone();
            let (tx, rx) = mpsc::unbounded_channel();
            let host = spawn_budget_tracking_host(rx, used, |req| {
                if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                    let _ = reply.send(Ok(agent_result("after raise")));
                }
            });
            let outcome = run_workflow(params(
                script,
                Journal::load(journal_path.clone()).unwrap(),
                tx,
            ));
            drop(host);
            match outcome {
                WorkflowOutcome::Failed { error } => assert!(error.contains("unknown outcome")),
                other => panic!("expected ambiguous outcome after budget terminal, got {other:?}"),
            }
            assert_eq!(
                agents_used.load(Ordering::SeqCst),
                0,
                "ambiguous budget terminal must not dispatch again"
            );
        }
    }

    #[test]
    fn parallel_journals_soft_failure_null_and_later_success() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("journal.jsonl");
        let (tx, rx) = mpsc::unbounded_channel();
        let mut request_index = 0;
        let host = spawn_mock_host(rx, move |req| {
            if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                if request_index == 0 {
                    let _ = reply.send(Err(HostError::Failed("boom".into())));
                } else {
                    let _ = reply.send(Ok(agent_result("ok")));
                }
                request_index += 1;
            }
        });
        let script = r#"
            let meta = #{ name: "t", description: "d" };
            let results = parallel([#{ prompt: "first" }, #{ prompt: "second" }]);
            complete(results);
        "#;
        let outcome = run_workflow(params(script, Journal::new(Some(journal_path.clone())), tx));
        drop(host);
        assert!(matches!(outcome, WorkflowOutcome::Completed { .. }));
        let journal = Journal::load(journal_path).unwrap();
        assert_eq!(journal.len(), 2);

        let (tx, mut rx) = mpsc::unbounded_channel();
        let replay = run_workflow(params(script, journal, tx));
        assert!(matches!(replay, WorkflowOutcome::Completed { .. }));
        assert!(
            rx.try_recv().is_err(),
            "dense soft-failure replay must not reexecute either sibling"
        );
    }

    #[test]
    fn parallel_replays_catchable_failure_sentinel() {
        let mut journal = Journal::new(None);
        let opts = AgentOpts {
            prompt: "replayed".into(),
            ..Default::default()
        };
        let hash = request_hash("spawn_agent", &serde_json::to_value(&opts).unwrap());
        journal
            .record(
                0,
                "spawn_agent",
                hash,
                host_error_sentinel("replayed failure"),
            )
            .unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();
        let outcome = run_workflow(params(
            r#"
            let meta = #{ name: "t", description: "d" };
            try {
                parallel([#{ prompt: "replayed" }]);
                complete("not caught");
            } catch (e) {
                complete("caught:" + e);
            }
            "#,
            journal,
            tx,
        ));
        match outcome {
            WorkflowOutcome::Completed { result } => {
                assert_eq!(result, serde_json::json!("caught:replayed failure"));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn parallel_preserves_order_and_nulls_failures() {
        let (tx, rx) = mpsc::unbounded_channel();
        let host = spawn_mock_host(rx, |req| {
            if let WorkflowHostRequest::SpawnAgent { opts, reply } = req {
                if opts.prompt.contains("fail") {
                    let _ = reply.send(Err(HostError::Failed("boom".into())));
                } else {
                    let _ = reply.send(Ok(agent_result(&format!("ok:{}", opts.prompt))));
                }
            }
        });
        let outcome = run_workflow(params(
            r#"
            let meta = #{ name: "t", description: "d" };
            let results = parallel([
                #{ prompt: "a" },
                #{ prompt: "fail-b" },
                #{ prompt: "c" },
            ]);
            let summary = results.map(|r| if r == () { "null" } else { r.output });
            complete(summary);
            "#,
            Journal::new(None),
            tx,
        ));
        drop(host);
        match outcome {
            WorkflowOutcome::Completed { result } => {
                assert_eq!(result, serde_json::json!(["ok:a", "null", "ok:c"]));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn agent_replays_legacy_hash_without_effort() {
        let opts = AgentOpts {
            prompt: "legacy single".into(),
            effort: Some("high".into()),
            ..Default::default()
        };
        let legacy_hash = legacy_spawn_agent_hash(&opts);
        assert_ne!(
            legacy_hash,
            request_hash("spawn_agent", &serde_json::to_value(&opts).unwrap())
        );
        let mut journal = Journal::new(None);
        journal
            .record(
                0,
                "spawn_agent",
                legacy_hash,
                serde_json::to_value(agent_result("legacy result")).unwrap(),
            )
            .unwrap();

        let (tx, mut rx) = mpsc::unbounded_channel();
        let outcome = run_workflow(params(
            r#"
            let meta = #{ name: "t", description: "d" };
            let result = agent("legacy single", #{ effort: "high" });
            complete(result.output);
            "#,
            journal,
            tx,
        ));

        match outcome {
            WorkflowOutcome::Completed { result } => {
                assert_eq!(result, serde_json::json!("legacy result"));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "replay must not hit the host");
    }

    #[test]
    fn parallel_replays_legacy_hashes_without_effort() {
        let opts = [
            AgentOpts {
                prompt: "legacy first".into(),
                effort: Some("low".into()),
                ..Default::default()
            },
            AgentOpts {
                prompt: "legacy second".into(),
                effort: Some("high".into()),
                ..Default::default()
            },
        ];
        let mut journal = Journal::new(None);
        for (seq, (opts, output)) in opts
            .iter()
            .zip(["first result", "second result"])
            .enumerate()
        {
            journal
                .record(
                    seq as u64,
                    "spawn_agent",
                    legacy_spawn_agent_hash(opts),
                    serde_json::to_value(agent_result(output)).unwrap(),
                )
                .unwrap();
        }

        let (tx, mut rx) = mpsc::unbounded_channel();
        let outcome = run_workflow(params(
            r#"
            let meta = #{ name: "t", description: "d" };
            let results = parallel([
                #{ prompt: "legacy first", effort: "low" },
                #{ prompt: "legacy second", effort: "high" },
            ]);
            complete(results.map(|result| result.output));
            "#,
            journal,
            tx,
        ));

        match outcome {
            WorkflowOutcome::Completed { result } => {
                assert_eq!(result, serde_json::json!(["first result", "second result"]));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "replay must not hit the host");
    }

    #[test]
    fn new_agent_recording_hash_includes_effort() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("journal.jsonl");
        let (tx, rx) = mpsc::unbounded_channel();
        let host = spawn_mock_host(rx, |req| {
            if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                let _ = reply.send(Ok(agent_result("recorded")));
            }
        });
        let outcome = run_workflow(params(
            r#"
            let meta = #{ name: "t", description: "d" };
            agent("new recording", #{ effort: "high" });
            complete("ok");
            "#,
            Journal::new(Some(journal_path.clone())),
            tx,
        ));
        drop(host);
        assert!(matches!(outcome, WorkflowOutcome::Completed { .. }));

        let opts = AgentOpts {
            prompt: "new recording".into(),
            effort: Some("high".into()),
            ..Default::default()
        };
        let journal = Journal::load(journal_path).unwrap();
        let current_hash = request_hash("spawn_agent", &serde_json::to_value(&opts).unwrap());
        assert!(
            journal
                .replay(0, "spawn_agent", &current_hash)
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            journal.replay(0, "spawn_agent", &legacy_spawn_agent_hash(&opts)),
            Err(JournalError::Divergence { .. })
        ));
    }

    #[test]
    fn agent_current_hash_mismatch_still_diverges() {
        let opts = AgentOpts {
            prompt: "original prompt".into(),
            effort: Some("high".into()),
            ..Default::default()
        };
        let mut journal = Journal::new(None);
        journal
            .record(
                0,
                "spawn_agent",
                request_hash("spawn_agent", &serde_json::to_value(&opts).unwrap()),
                serde_json::to_value(agent_result("must not replay")).unwrap(),
            )
            .unwrap();

        let (tx, mut rx) = mpsc::unbounded_channel();
        let outcome = run_workflow(params(
            r#"
            let meta = #{ name: "t", description: "d" };
            agent("edited prompt", #{ effort: "high" });
            "#,
            journal,
            tx,
        ));

        match outcome {
            WorkflowOutcome::Failed { error } => {
                assert!(error.contains("divergence"), "got: {error}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "divergent replay must not hit the host"
        );
    }

    #[test]
    fn journal_replay_skips_host_calls() {
        let script = r#"
            let meta = #{ name: "t", description: "d" };
            let a = agent("first");
            let b = budget();
            complete(#{ out: a.output, spent: b.spent, reserved: b.reserved, remaining: b.remaining });
        "#;

        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("journal.jsonl");

        let (tx, rx) = mpsc::unbounded_channel();
        let host = spawn_mock_host(rx, |req| match req {
            WorkflowHostRequest::SpawnAgent { reply, .. } => {
                let _ = reply.send(Ok(agent_result("recorded output")));
            }
            WorkflowHostRequest::BudgetQuery { reply } => {
                let _ = reply.send(Ok(BudgetState {
                    total: Some(1000),
                    spent: 123,
                    reserved: 100,
                    remaining: Some(777),
                }));
            }
            _ => {}
        });
        let first = run_workflow(params(script, Journal::new(Some(journal_path.clone())), tx));
        drop(host);
        let WorkflowOutcome::Completed { result: first } = first else {
            panic!("first run should complete");
        };

        let (tx, rx) = mpsc::unbounded_channel();
        let host = spawn_mock_host(rx, |req| match req {
            WorkflowHostRequest::SpawnAgent { .. } | WorkflowHostRequest::BudgetQuery { .. } => {
                panic!("replay must not hit the host")
            }
            _ => {}
        });
        let second = run_workflow(params(script, Journal::load(journal_path).unwrap(), tx));
        drop(host);
        let WorkflowOutcome::Completed { result: second } = second else {
            panic!("resumed run should complete");
        };
        assert_eq!(first, second);
        assert_eq!(second["spent"], serde_json::json!(123));
        assert_eq!(second["reserved"], serde_json::json!(100));
        assert_eq!(second["remaining"], serde_json::json!(777));
    }

    #[test]
    fn lost_effect_reply_never_redispatches_serial_or_parallel_agents() {
        for script in [
            r#"agent("effect");"#,
            r#"parallel([#{prompt: "effect"}, #{prompt: "effect2"}]);"#,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("journal.jsonl");
            let effects = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed = effects.clone();
            let (tx, rx) = mpsc::unbounded_channel();
            let host = spawn_mock_host(rx, move |req| {
                if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                    observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    drop(reply);
                }
            });
            assert!(matches!(
                run_workflow(params(script, Journal::new(Some(path.clone())), tx)),
                WorkflowOutcome::Failed { .. }
            ));
            drop(host);
            let count = effects.load(std::sync::atomic::Ordering::SeqCst);
            assert!(count > 0);
            let (tx, mut rx) = mpsc::unbounded_channel();
            let outcome = run_workflow(params(script, Journal::load(path).unwrap(), tx));
            assert!(matches!(outcome, WorkflowOutcome::Failed { .. }));
            assert!(
                rx.try_recv().is_err(),
                "ambiguous replay must not reach host"
            );
            assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), count);
        }
    }

    #[test]
    fn journal_write_failure_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("journal.jsonl");
        std::fs::create_dir(&journal_path).unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let host = spawn_mock_host(rx, |req| {
            if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                let _ = reply.send(Ok(agent_result("unpersisted")));
            }
        });
        let outcome = run_workflow(params(
            r#"
            let meta = #{ name: "t", description: "d" };
            agent("work");
            complete("must not complete");
            "#,
            Journal::new(Some(journal_path)),
            tx,
        ));
        drop(host);
        match outcome {
            WorkflowOutcome::Failed { error } => {
                assert!(error.contains("journal io"), "got: {error}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn journal_divergence_fails_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("journal.jsonl");

        let (tx, rx) = mpsc::unbounded_channel();
        let host = spawn_mock_host(rx, |req| {
            if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                let _ = reply.send(Ok(agent_result("v1")));
            }
        });
        let first = run_workflow(params(
            r#"
            let meta = #{ name: "t", description: "d" };
            agent("original prompt");
            complete("ok");
            "#,
            Journal::new(Some(journal_path.clone())),
            tx,
        ));
        drop(host);
        assert!(matches!(first, WorkflowOutcome::Completed { .. }));

        let (tx, _rx) = mpsc::unbounded_channel();
        let second = run_workflow(params(
            r#"
            let meta = #{ name: "t", description: "d" };
            agent("EDITED prompt");
            complete("ok");
            "#,
            Journal::load(journal_path).unwrap(),
            tx,
        ));
        match second {
            WorkflowOutcome::Failed { error } => {
                assert!(error.contains("divergence"), "got: {error}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn phase_carries_replay_flag() {
        let script = r#"
            let meta = #{ name: "t", description: "d" };
            phase("One");
            agent("x");
            phase("Two");
            complete("ok");
        "#;
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("journal.jsonl");

        let (tx, rx) = mpsc::unbounded_channel();
        let host = spawn_mock_host(rx, |req| {
            if let WorkflowHostRequest::SpawnAgent { reply, .. } = req {
                let _ = reply.send(Ok(agent_result("y")));
            }
        });
        let _ = run_workflow(params(script, Journal::new(Some(journal_path.clone())), tx));
        drop(host);

        let (tx, rx) = mpsc::unbounded_channel();
        let phases = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let phases_in_host = phases.clone();
        let host = spawn_mock_host(rx, move |req| {
            if let WorkflowHostRequest::Phase { title, replayed } = req {
                phases_in_host.lock().unwrap().push((title, replayed));
            }
        });
        let _ = run_workflow(params(script, Journal::load(journal_path).unwrap(), tx));
        host.join().unwrap();

        let phases = phases.lock().unwrap();
        assert_eq!(
            phases.as_slice(),
            &[("One".into(), true), ("Two".into(), false)]
        );
    }

    #[test]
    fn json_encode_quotes_untrusted_strings() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let outcome = run_workflow(params(
            r#"
            let meta = #{ name: "t", description: "d" };
            complete(json_encode("</tag>\nquoted"));
            "#,
            Journal::new(None),
            tx,
        ));
        match outcome {
            WorkflowOutcome::Completed { result } => {
                assert_eq!(result, serde_json::json!("\"</tag>\\nquoted\""));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }
}
