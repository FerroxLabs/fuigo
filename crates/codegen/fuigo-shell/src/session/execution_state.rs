//! Session persistence actor owns every durable execution transition.
//! A prepared admission is a conservative debit even if transport never starts.
use crate::acp_error::{ExecutionBudgetDenial, ExecutionBudgetRule};
use crate::session::persistence::PersistenceMsg;
use fuigo_sampling_types::{AdmissionFuture, ExecutionAdmission, RequestPurpose};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io,
    path::Path,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicI64, Ordering},
    },
};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Phase {
    Working,
    Finalizing,
    Terminal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TerminalReceipt {
    pub id: String,
    pub execution_id: String,
    pub partial: bool,
    pub pending_attempts: Vec<String>,
    pub optional_pending_attempts: Vec<String>,
    pub pending_tool_calls: Vec<String>,
    pub reason: String,
    pub evidence_refs: Vec<String>,
    pub completed_checks: String,
    #[serde(default)]
    pub known_session_edited_paths: Vec<String>,
    #[serde(default)]
    pub omitted_edited_paths: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub(crate) version: u32,
    pub(crate) execution_id: String,
    pub(crate) phase: Phase,
    pub(crate) max_calls: u64,
    pub(crate) calls: u64,
    pub(crate) completion_admitted: bool,
    #[serde(default)]
    recall_finalization: bool,
    pub(crate) max_tool_rounds: Option<u64>,
    pub(crate) tool_rounds: u64,
    pub(crate) pending_tools: BTreeSet<String>,
    pub(crate) limits: TokenLimits,
    pub(crate) total_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) unknown_usage: bool,
    pub(crate) deadline_ms: Option<i64>,
    pub(crate) pending: BTreeSet<String>,
    pub(crate) optional_attempts: BTreeSet<String>,
    pub(crate) admitted: BTreeSet<String>,
    /// Finished attempts no resend has taken over yet. Still pending (still unresolved
    /// work) until a resubmit of the same logical call supersedes them.
    #[serde(default)]
    pub(crate) abandoned: BTreeSet<String>,
    pub(crate) terminal: Option<TerminalReceipt>,
    #[serde(default)]
    known_session_edited_paths: Vec<String>,
    #[serde(default)]
    omitted_edited_paths: usize,
    #[serde(default)]
    grants: BTreeMap<String, GrantState>,
    #[serde(default)]
    child_aliases: BTreeMap<String, String>,
    /// P89. Whether the receipt in `terminal` ended a TURN rather than the execution, so the next
    /// turn of the same goal may reopen the record ([`Change::Reopen`]). Decided once, when the
    /// receipt is issued ([`TurnEnd`]). `None` on a record written before P89: [`may_reopen`] then
    /// judges by what the record shows ([`legacy_reopenable`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reopenable: Option<bool>,
    /// P89. The receipts of earlier turns this execution was reopened after, oldest first, at most
    /// [`EARLIER_RECEIPTS_KEPT`]: the record of what each interrupted turn left unresolved.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    earlier_receipts: Vec<TerminalReceipt>,
    /// P89. How many times this execution was reopened, including receipts no longer kept.
    #[serde(default)]
    reopened: u64,
    /// P121 (K8). Attempts whose usage never reported and which were charged a conservative
    /// estimate instead (`(total, output)` tokens), so the same attempt is never charged twice and a
    /// late settlement can top the estimate up to the real figure. Only under a token budget.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    estimated: BTreeMap<String, (u64, u64)>,
    /// P121 (K8). The largest `(total, output)` any one attempt of this execution reported: a
    /// request-derived floor for what an unreported request cost, since a goal's context only grows.
    #[serde(default, skip_serializing_if = "is_zero_pair")]
    largest_request: (u64, u64),
}

fn is_zero_pair(pair: &(u64, u64)) -> bool {
    *pair == (0, 0)
}

/// Remember the largest single request that reported usage ([`Snapshot::largest_request`]).
fn note_reported_usage(state: &mut Snapshot, usage: &fuigo_sampling_types::TokenUsage) {
    state.largest_request.0 = state.largest_request.0.max(u64::from(usage.total_tokens));
    state.largest_request.1 = state.largest_request.1.max(u64::from(usage.completion_tokens));
}

/// P121 (K8). What an attempt whose usage is unknown is charged under a token budget, in tokens.
/// A request can cost more than this; a late settlement tops the charge up to the real figure.
const UNKNOWN_ATTEMPT_TOTAL_TOKENS: u64 = 16_384;
const UNKNOWN_ATTEMPT_OUTPUT_TOKENS: u64 = 4_096;

/// P121 (K8). Charge `attempt_id`, whose usage will never be reported, a conservative estimate
/// against each token limit the record has, once.
///
/// This replaces failing closed (`unknown_usage`, which denied every later admission, and for a
/// terminal record could only be lifted by a settlement that never came). The estimate is a real
/// debit: enough interrupted requests spend the budget like any other usage, and the goal then
/// stops with the budget's own typed denial (`TotalTokensExhausted`), which says what to do. What
/// it never does is stop a goal for good on usage nobody can ever learn.
fn charge_unknown_usage(state: &mut Snapshot, attempt_id: &str) {
    if state.estimated.contains_key(attempt_id) {
        return;
    }
    let (total, output) = charge_estimate(state);
    state.estimated.insert(attempt_id.to_owned(), (total, output));
}

/// Debit one unknown attempt's estimate against each token limit the record has.
fn charge_estimate(state: &mut Snapshot) -> (u64, u64) {
    // At least the largest request this execution has seen report: its context only grows, so an
    // unreported request cost no less than that, and never less than the fixed floor.
    let total = if state.limits.total.is_some() {
        UNKNOWN_ATTEMPT_TOTAL_TOKENS.max(state.largest_request.0)
    } else {
        0
    };
    let output = if state.limits.output.is_some() {
        UNKNOWN_ATTEMPT_OUTPUT_TOKENS.max(state.largest_request.1)
    } else {
        0
    };
    state.total_tokens = state.total_tokens.saturating_add(total);
    state.output_tokens = state.output_tokens.saturating_add(output);
    (total, output)
}

/// P121 (K8). Usage reported late for an attempt that was already charged an estimate: the
/// estimate stays, and only what the real figure exceeds it by is added. Reporting less never
/// lowers the charge.
fn settle_estimated(state: &mut Snapshot, attempt_id: &str, usage: Option<&fuigo_sampling_types::TokenUsage>) {
    let Some((estimated_total, estimated_output)) = state.estimated.remove(attempt_id) else {
        return;
    };
    if let Some(usage) = usage {
        note_reported_usage(state, usage);
        state.total_tokens = state
            .total_tokens
            .saturating_add(u64::from(usage.total_tokens).saturating_sub(estimated_total));
        state.output_tokens = state
            .output_tokens
            .saturating_add(u64::from(usage.completion_tokens).saturating_sub(estimated_output));
    }
}

/// P89. How many superseded receipts a reopened execution keeps.
const EARLIER_RECEIPTS_KEPT: usize = 16;

/// P89. How the turn that issues a terminal receipt ended. Only the turn knows: the record alone
/// cannot tell a user's Esc from a budget stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TurnEnd {
    /// The turn answered normally (`EndTurn`).
    Succeeded,
    /// The turn stopped without a normal answer for a reason that is not a limit: the user
    /// cancelled, the provider failed, the answer was cut at max output tokens, the provider
    /// refused. It ends the turn, never the goal.
    Interrupted,
    /// A limit stopped the turn (a budget denial, `--max-turns`), or the cause is not known.
    Stopped,
}

impl TurnEnd {
    fn of_succeeded(succeeded: bool) -> Self {
        if succeeded { Self::Succeeded } else { Self::Stopped }
    }
}

/// P89. The limit a record has run out of: what keeps a goal's execution terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exhaustion {
    Budget(ExecutionBudgetRule),
    /// `--max-turns`: every tool round the execution was allowed is spent.
    ToolRounds(u64),
}

/// P89. The limit a TERMINAL record `state` has run out of at `now_ms`, if any: the same bounds the
/// turn loop finalizes on (`process_conversation_turn`) and admission refuses on ([`admit_attempt`]).
///
/// An attempt still pending when the turn ended was in flight (the user's Esc, a provider failure; a
/// title, a recap or a background child's request that had not come back), so its token usage is not
/// known. P89 failed closed on that and left a budgeted goal unable to resume (K8). P121 charges it
/// a conservative estimate when the record is reopened instead ([`charge_unknown_usage`]), so it is
/// not a reason to refuse here.
pub(crate) fn exhaustion(state: &Snapshot, now_ms: i64) -> Option<Exhaustion> {
    if state.deadline_ms.is_some_and(|d| now_ms >= d) {
        return Some(Exhaustion::Budget(ExecutionBudgetRule::RuntimeLimit));
    }
    if let Some(denial) = token_budget_denial_for(state, true) {
        return Some(Exhaustion::Budget(denial.rule));
    }
    if state.calls >= state.max_calls.saturating_sub(1) {
        // The last call is the final answer's; no work is left.
        return Some(Exhaustion::Budget(ExecutionBudgetRule::ModelCallLimit));
    }
    state
        .max_tool_rounds
        .filter(|max| state.tool_rounds >= *max)
        .map(Exhaustion::ToolRounds)
}

/// P144. The budget denial a turn ended with when the loop FINALIZED it on a budget: the model-call
/// limit reserving its last call for the final answer, a token budget running out, or the runtime limit
/// passing. `None` for a recall finalization (recall finishing inside its own budget is an ordinary
/// completion), a crash-recovery finalization, and a `--max-turns` mirror (`max_tool_rounds`), which has
/// its own documented stop.
///
/// Before P144 such a turn ended as a partial receipt with no `data.code` (the model answered in the
/// reserved slot) or as `-32603 Tool call rejected during finalization` (it called a tool there), so
/// `fuigo -p` exited 1 for a run that a limit ended (lane A2, B4). Read off `state` BEFORE the terminal
/// receipt moves it out of `Finalizing`.
pub(crate) fn budget_finalization_denial(state: &Snapshot) -> Option<ExecutionBudgetDenial> {
    budget_finalization_denial_at(state, chrono::Utc::now().timestamp_millis())
}

/// [`budget_finalization_denial`] judged at `now_ms`, the moment the turn returned (Astra r3): a clock
/// read later, after an await, could find the deadline passed and relabel a call-limit answer.
pub(crate) fn budget_finalization_denial_at(state: &Snapshot, now_ms: i64) -> Option<ExecutionBudgetDenial> {
    if state.phase != Phase::Finalizing || state.recall_finalization {
        return None;
    }
    if let Some(Exhaustion::Budget(rule)) = exhaustion(state, now_ms) {
        return Some(budget_denial(state, rule));
    }
    // The unknown-usage clause `exhaustion` leaves out for a terminal record still finalizes a live one.
    if let Some(denial) = token_budget_denial(state) {
        return Some(denial);
    }
    // The process-wide counter (shared with other sessions and children) left only reserved capacity.
    fuigo_sampler::execution_budget::process_budget()
        .ok()
        .flatten()
        .is_some_and(|budget| budget.working_capacity_exhausted())
        .then(|| budget_denial(state, ExecutionBudgetRule::ModelCallLimit))
}

/// P89. A record written before P89 does not say how its turn ended. It is reopened only when it
/// shows nothing a turn could have left unresolved and no finalization was spent on it, which is
/// the clean-cancel latch the audit reproduced. A crash-poisoned record (P03's fixtures) keeps its
/// liabilities and stays terminal.
fn legacy_reopenable(state: &Snapshot) -> bool {
    (!state.completion_admitted || state.recall_finalization)
        && state.pending.iter().all(|id| state.optional_attempts.contains(id))
        && state.pending_tools.is_empty()
        && state.abandoned.is_empty()
}

/// P89. Whether a goal's next turn may reopen this terminal record: its last turn ended the TURN,
/// not the execution, and no limit is spent. A genuinely spent budget stays terminal.
pub(crate) fn may_reopen(state: &Snapshot, now_ms: i64) -> bool {
    state.phase == Phase::Terminal
        && state.terminal.is_some()
        && exhaustion(state, now_ms).is_none()
        && state.reopenable.unwrap_or_else(|| legacy_reopenable(state))
}

/// P89. Why a goal cannot continue on its terminal record, for a person: which limit stopped it and
/// what to do. `None` when the record may be reopened (or is not terminal).
pub(crate) fn goal_end_reason(state: &Snapshot, now_ms: i64) -> Option<String> {
    if state.phase != Phase::Terminal || may_reopen(state, now_ms) {
        return None;
    }
    Some(match exhaustion(state, now_ms) {
        Some(Exhaustion::Budget(rule)) => budget_denial(state, rule).message(),
        Some(Exhaustion::ToolRounds(max)) => format!(
            "This goal has used all {max} tool rounds `--max-turns` allows. \
             Use /goal clear, then /goal <objective> to start a new one."
        ),
        None => format!(
            "This goal's execution stopped at a limit or with work whose outcome is unknown \
             (receipt {}), so it is not continued automatically. \
             Use /goal clear, then /goal <objective> to start a new one.",
            state.terminal.as_ref().map(|r| r.id.as_str()).unwrap_or("unknown")
        ),
    })
}

/// P89. The refusal a goal's turn ends with when its record cannot be reopened: the budget denial
/// itself when a budget is spent (so the client reads the rule and the remedy as data, Contract
/// D.4), otherwise [`GoalExecutionEnded`].
fn goal_ended_error(state: &Snapshot, now_ms: i64) -> io::Error {
    match exhaustion(state, now_ms) {
        Some(Exhaustion::Budget(rule)) => io::Error::other(budget_denial(state, rule)),
        _ => io::Error::other(GoalExecutionEnded(
            goal_end_reason(state, now_ms).unwrap_or_else(|| "This goal's execution has ended.".into()),
        )),
    }
}

/// P89. A goal's terminal record that may not be reopened, for a reason other than a spent budget.
/// Carries the person-facing [`goal_end_reason`].
#[derive(Debug, Clone)]
pub(crate) struct GoalExecutionEnded(pub String);

impl std::fmt::Display for GoalExecutionEnded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GoalExecutionEnded {}

/// The [`GoalExecutionEnded`] carried by `error`, if that is what it is.
pub(crate) fn goal_ended_of(error: &io::Error) -> Option<GoalExecutionEnded> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<GoalExecutionEnded>())
        .cloned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GrantState {
    max_calls: u64,
    calls: u64,
    optional: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct TokenLimits {
    pub total: Option<u64>,
    pub output: Option<u64>,
    pub initial_total: u64,
}

pub(crate) fn should_track_execution(
    process_budget: bool,
    active_goal: bool,
    turn_limit: bool,
    output_limit: bool,
    parent_grant: bool,
) -> bool {
    process_budget || active_goal || turn_limit || output_limit || parent_grant
}

pub(crate) fn should_terminalize(active_goal: bool, completed: bool, phase: Phase) -> bool {
    !active_goal || !completed || phase != Phase::Working
}

#[derive(Debug)]
pub(crate) enum Change {
    Open {
        max_calls: u64,
        deadline_ms: Option<i64>,
        max_tool_rounds: Option<u64>,
        limits: TokenLimits,
    },
    Read,
    Finalize,
    FinalizeRecall,
    Admit {
        completion: bool,
        optional: bool,
        attempt_id: String,
    },
    Settle {
        attempt_id: String,
        usage: Option<fuigo_sampling_types::TokenUsage>,
    },
    /// Settle an attempt its own resend took over.
    Supersede {
        attempt_id: String,
        usage: Option<fuigo_sampling_types::TokenUsage>,
    },
    /// Mark a finished attempt no resend has taken over (it stays pending).
    Abandon {
        attempt_id: String,
    },
    Tools {
        ids: Vec<String>,
    },
    ToolsSettled {
        ids: Vec<String>,
    },
    /// Issue the terminal receipt with a known success flag and no cause: a non-success is
    /// [`TurnEnd::Stopped`]. Turn ends say how they ended with [`Change::TurnTerminal`].
    Terminal {
        succeeded: bool,
    },
    /// P89. Issue the terminal receipt for a turn that ended by `end`.
    TurnTerminal {
        end: TurnEnd,
    },
    /// P89. Reopen a goal's terminal record for the goal's next turn ([`may_reopen`]). The issued
    /// receipt moves to `earlier_receipts`, and what it lists as unresolved is settled into it: the
    /// interrupted turn is over, and its in-flight work is never re-run. The call, tool-round and
    /// token counters are kept, so the goal's limits still bind. `observed_total` is the goal's own
    /// token count, which may have grown by what the interrupted turn streamed.
    Reopen {
        observed_total: u64,
    },
    EditedPaths {
        paths: BTreeSet<String>,
    },
    Grant {
        child_id: String,
        resume_from: Option<String>,
        optional: bool,
    },
    ChildAdmit {
        grant_id: String,
        attempt_id: String,
    },
    ChildTools {
        grant_id: String,
        ids: Vec<String>,
    },
    /// Clear the liability sets of a crash-poisoned `Terminal` execution. P03.
    ///
    /// A crash can persist an execution at `Phase::Terminal` while `pending`,
    /// `pending_tools` or `abandoned` still name unresolved work. That state is a
    /// permanent latch: the file key is stable across restarts
    /// (`blake3(session_id \0 root_id)`), every transition that could resolve the work is
    /// denied at `Terminal`, and `Change::Open` on an existing file is a no-op read. The
    /// armed `abandoned` sweep then fires on every open and cannot help, because each
    /// transition it drives is refused.
    ///
    /// Reconciliation FINALIZES the liability; it never re-runs anything. The phase stays
    /// `Terminal` and the issued `TerminalReceipt` is left byte-identical, because the
    /// receipt is the record of what was lost at the crash boundary. This clears the
    /// liability, not the history.
    Reconcile,
    /// P121 (K8). A turn was rewound (Esc after a request was sent, before its first output) without a
    /// terminal receipt: every non-optional attempt still in flight reported no usage and never will.
    /// Charge each a conservative estimate and settle it, keeping its call debit, so the request is
    /// accounted for however the goal continues.
    ChargeInFlight,
    /// P121 (K8). The model request about to be sent has at least `tokens` of input: a floor for what
    /// an unreported request costs ([`Snapshot::largest_request`]), known even when no request of
    /// this execution has reported usage yet.
    NoteContext { tokens: u64 },
}

#[derive(Debug)]
pub struct ExecutionMutation {
    key: String,
    change: Change,
}

fn denied(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn denied_owned(message: String) -> io::Error {
    io::Error::other(message)
}

/// The token-budget refusal carried by `error`, when the guard in [`admit_attempt`] produced it.
///
/// The guard returns its [`ExecutionBudgetDenial`] as the `io::Error` payload, so it survives the
/// persistence actor's round trip by value; every other refusal is a plain message and yields `None`.
pub(crate) fn budget_denial_of(error: &io::Error) -> Option<ExecutionBudgetDenial> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ExecutionBudgetDenial>())
        .cloned()
}

/// Contract D.4: the token-budget clause of [`admit_attempt`], as a typed refusal.
///
/// Same three clauses in the same order as before; only the shape of the answer changed. Unknown usage
/// still FAILS CLOSED whenever a token budget is set.
pub(crate) fn token_budget_denial(state: &Snapshot) -> Option<ExecutionBudgetDenial> {
    token_budget_denial_for(state, false)
}

/// [`token_budget_denial`], optionally leaving out the unknown-usage clause. P121 (K8): a TERMINAL
/// record's `unknown_usage` (set by an earlier version, or by a completion that reported nothing)
/// does not keep a goal from resuming; reopening charges it an estimate instead ([`Change::Reopen`]).
/// Admission to a live execution still fails closed on it (Contract D.4).
fn token_budget_denial_for(state: &Snapshot, ignore_unknown: bool) -> Option<ExecutionBudgetDenial> {
    let rule = if state.limits.total.is_some_and(|limit| state.total_tokens >= limit) {
        ExecutionBudgetRule::TotalTokensExhausted
    } else if state.limits.output.is_some_and(|limit| state.output_tokens >= limit) {
        ExecutionBudgetRule::OutputTokensExhausted
    } else if !ignore_unknown
        && state.unknown_usage
        && (state.limits.total.is_some() || state.limits.output.is_some())
    {
        ExecutionBudgetRule::TokenUsageUnknown
    } else {
        return None;
    };
    Some(budget_denial(state, rule))
}

/// The refusal by `rule`, carrying `state`'s token counters as its figures.
pub(crate) fn budget_denial(state: &Snapshot, rule: ExecutionBudgetRule) -> ExecutionBudgetDenial {
    ExecutionBudgetDenial {
        rule,
        total_token_limit: state.limits.total,
        total_tokens_used: state.total_tokens,
        output_token_limit: state.limits.output,
        output_tokens_used: state.output_tokens,
        // A `TokenUsageUnknown` refusal is always about unknown usage, including the in-flight
        // attempts of an interrupted turn the record never saw settle (P89, [`exhaustion`]).
        unknown_usage: state.unknown_usage || rule == ExecutionBudgetRule::TokenUsageUnknown,
    }
}

/// P44: a refusal by the model-call or runtime limit, as the `io::Error` the admission returns. Typed the
/// same way as the token guard's ([`budget_denial_of`] reads it back), so it reaches the client as the
/// same denial instead of a status-less `api` error.
fn limit_denied(state: &Snapshot, rule: ExecutionBudgetRule) -> io::Error {
    io::Error::other(budget_denial(state, rule))
}

/// P44: the rule of a refusal by the SAMPLER's process-wide limits, read off the failed request's error
/// message.
///
/// The sampler's process budget (`fuigo_sampler::execution_budget`) refuses with
/// `SamplingError::InvalidConfiguration(CALL_LIMIT | WALL_LIMIT)`, which reaches the turn as a
/// status-less `api` error whose message is exactly that error's rendering. There is no typed channel
/// across that boundary, so this compares against the rendering of the sampler's own exported constants,
/// never a copy of their wording: a rewording on either side cannot drift silently. The comparison is
/// exact, not a substring, so a provider error that merely quotes the text (a status-less stream error
/// is also `api`) is never taken for a local limit. The durable execution mirrors both limits and normally refuses first (typed at its own
/// admission); this covers what reaches the sampler past that mirror (another session or child
/// spending the shared counter, the deadline falling between the two checks).
pub(crate) fn process_limit_rule(message: &str) -> Option<ExecutionBudgetRule> {
    use fuigo_sampler::execution_budget::{CALL_LIMIT, WALL_LIMIT};
    use fuigo_sampling_types::SamplingError;
    let refused_by = |limit: &'static str| message == SamplingError::InvalidConfiguration(limit).to_string();
    if refused_by(CALL_LIMIT) {
        Some(ExecutionBudgetRule::ModelCallLimit)
    } else if refused_by(WALL_LIMIT) {
        Some(ExecutionBudgetRule::RuntimeLimit)
    } else {
        None
    }
}

/// The refusal of any change but `Open` to a record that does not exist yet.
const EXECUTION_STATE_MISSING: &str = "execution state missing";

pub(crate) async fn apply(dir: &Path, mutation: ExecutionMutation) -> io::Result<Snapshot> {
    // The key is a fixed-length hash minted locally, never a client-provided path.
    if mutation.key.len() != 64 || !mutation.key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(denied("invalid execution identity"));
    }
    let path = dir.join(format!("execution-{}.json", mutation.key));
    let mut state = match tokio::fs::read(&path).await {
        Ok(bytes) => serde_json::from_slice::<Snapshot>(&bytes).map_err(io::Error::other)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let Change::Open {
                max_calls,
                deadline_ms,
                max_tool_rounds,
                limits,
            } = &mutation.change
            else {
                return Err(denied(EXECUTION_STATE_MISSING));
            };
            if *max_calls == 0 {
                // The process's model-call limit had nothing left when this execution opened (P44).
                return Err(io::Error::other(ExecutionBudgetDenial {
                    rule: ExecutionBudgetRule::ModelCallLimit,
                    total_token_limit: limits.total,
                    total_tokens_used: limits.initial_total,
                    output_token_limit: limits.output,
                    output_tokens_used: 0,
                    unknown_usage: false,
                }));
            }
            Snapshot {
                version: 1,
                execution_id: uuid::Uuid::new_v4().to_string(),
                phase: Phase::Working,
                max_calls: *max_calls,
                calls: 0,
                abandoned: BTreeSet::new(),
                completion_admitted: false,
                recall_finalization: false,
                deadline_ms: *deadline_ms,
                max_tool_rounds: *max_tool_rounds,
                tool_rounds: 0,
                pending_tools: BTreeSet::new(),
                limits: limits.clone(),
                total_tokens: limits.initial_total,
                output_tokens: 0,
                unknown_usage: false,
                pending: BTreeSet::new(),
                optional_attempts: BTreeSet::new(),
                admitted: BTreeSet::new(),
                terminal: None,
                known_session_edited_paths: Vec::new(),
                omitted_edited_paths: 0,
                grants: BTreeMap::new(),
                child_aliases: BTreeMap::new(),
                reopenable: None,
                earlier_receipts: Vec::new(),
                reopened: 0,
                estimated: BTreeMap::new(),
                largest_request: (0, 0),
            }
        }
        Err(error) => return Err(error),
    };
    if state.version != 1 || state.calls > state.max_calls {
        return Err(denied("unsupported or inconsistent execution state"));
    }
    if matches!(mutation.change, Change::Read) {
        return Ok(state);
    }
    transition(
        &mut state,
        mutation.change,
        chrono::Utc::now().timestamp_millis(),
    )?;
    // Existing atomic primitive syncs bytes and the existing session directory.
    // The actor serializes this write with all other execution mutations.
    crate::session::storage::write_bytes_atomic_async(
        &path,
        serde_json::to_vec(&state).map_err(io::Error::other)?,
    )
    .await?;
    Ok(state)
}

fn background_grant_may_continue(state: &Snapshot, optional: bool) -> bool {
    optional && state.phase == Phase::Terminal
        && state.terminal.as_ref().is_some_and(|receipt| !receipt.partial)
}

fn admit_attempt(
    state: &mut Snapshot,
    completion: bool,
    optional: bool,
    attempt_id: String,
    now_ms: i64,
    continuing_background: bool,
) -> io::Result<()> {
    if state.admitted.contains(&attempt_id) {
        return Err(denied("execution admission already consumed"));
    }
    if uuid::Uuid::parse_str(&attempt_id).is_err() {
        return Err(denied("invalid admission identity"));
    }
    // Same clauses, same order, same refusals as before P44. Only the budget clauses -- the deadline
    // and the call counts -- now answer with a typed denial; the phase and protocol clauses stay plain
    // messages, because they are not a limit the operator set.
    if state.phase == Phase::Terminal && !continuing_background {
        return Err(denied("execution is terminal or expired"));
    }
    if state.deadline_ms.is_some_and(|d| now_ms >= d) {
        return Err(limit_denied(state, ExecutionBudgetRule::RuntimeLimit));
    }
    if let Some(denial) = token_budget_denial(state) {
        return Err(io::Error::other(denial));
    }
    if completion {
        if state.phase != Phase::Finalizing || state.completion_admitted {
            return Err(denied("completion admission unavailable"));
        }
        if state.calls >= state.max_calls {
            return Err(limit_denied(state, ExecutionBudgetRule::ModelCallLimit));
        }
    } else if state.phase != Phase::Working && !continuing_background {
        return Err(denied("execution completion capacity reserved"));
    } else if state.calls >= state.max_calls.saturating_sub(1) {
        // The last call is reserved for the final answer, so work has none left.
        return Err(limit_denied(state, ExecutionBudgetRule::ModelCallLimit));
    }
    state.calls += 1;
    state.completion_admitted |= completion;
    state.pending.insert(attempt_id.clone());
    if optional {
        state.optional_attempts.insert(attempt_id.clone());
    }
    state.admitted.insert(attempt_id);
    Ok(())
}

/// Release an attempt whose resend took over the same logical call.
///
/// The resend carries the liability forward, so the attempt stops counting as
/// unresolved work on the terminal receipt. Its call debit is never refunded, and
/// usage it reported is still charged.
///
/// Unlike [`Change::Settle`], a superseded attempt with no reported usage does not set
/// `unknown_usage`, which denies every later admission under a token budget and finalizes
/// the turn. P121: under a token limit it is charged a conservative estimate instead. That protection is what keeps the empty-response path safe: an empty reply is
/// never a `Change::Settle` (only a provider completion settles), so every resent empty
/// attempt arrives here, carrying the usage the provider reported if it reported any and
/// nothing if it did not. Without the distinction, the two empty replies in a row that this
/// release exists to fix would deny the work that follows them.
/// Pinned by `empty_replies_leave_the_execution_token_budget_usable` and by
/// `a_resent_attempt_settles_while_an_abandoned_one_stays_unresolved`.
fn supersede_attempt(
    state: &mut Snapshot,
    attempt_id: &str,
    usage: Option<fuigo_sampling_types::TokenUsage>,
) {
    state.abandoned.remove(attempt_id);
    if state.pending.remove(attempt_id) {
        match usage {
            Some(usage) => {
                note_reported_usage(state, &usage);
                state.total_tokens = state
                    .total_tokens
                    .saturating_add(u64::from(usage.total_tokens));
                state.output_tokens = state
                    .output_tokens
                    .saturating_add(u64::from(usage.completion_tokens));
            }
            // P121 (K8). A resend that took the attempt over without usage: charged a
            // conservative estimate under a token limit (it used to be free), never `unknown_usage`.
            None => charge_unknown_usage(state, attempt_id),
        }
    }
}

fn transition(state: &mut Snapshot, change: Change, now_ms: i64) -> io::Result<()> {
    match change {
        Change::Read | Change::Open { .. } => {}
        Change::EditedPaths { paths } => {
            // Session-scoped observed edits, not a claim that this execution
            // created every path. Never revise an already-issued terminal ID.
            if state.terminal.is_none() {
                state.omitted_edited_paths = paths.len().saturating_sub(128);
                state.known_session_edited_paths = paths.into_iter().take(128).collect();
            }
        }
        Change::Finalize => {
            if state.phase == Phase::Terminal {
                return Err(denied("execution is terminal"));
            }
            state.phase = Phase::Finalizing;
            state.recall_finalization = false;
        }
        Change::FinalizeRecall => {
            if state.phase != Phase::Working {
                return Err(denied("recall cannot reopen finalizing execution"));
            }
            state.phase = Phase::Finalizing;
            state.recall_finalization = true;
        }
        Change::Admit {
            completion,
            optional,
            attempt_id,
        } => {
            admit_attempt(state, completion, optional, attempt_id, now_ms, false)?;
        }
        Change::Settle { attempt_id, usage } => {
            if !state.admitted.contains(&attempt_id) {
                return Err(denied("unknown execution admission"));
            }
            if state.estimated.contains_key(&attempt_id) {
                // P121 (K8). Already charged an estimate: the late report only tops it up.
                state.pending.remove(&attempt_id);
                settle_estimated(state, &attempt_id, usage.as_ref());
            } else if state.pending.remove(&attempt_id) {
                if let Some(usage) = usage {
                    note_reported_usage(state, &usage);
                    state.total_tokens = state
                        .total_tokens
                        .saturating_add(u64::from(usage.total_tokens));
                    state.output_tokens = state
                        .output_tokens
                        .saturating_add(u64::from(usage.completion_tokens));
                } else {
                    state.unknown_usage = true;
                }
            }
        }
        Change::Supersede { attempt_id, usage } => {
            if !state.admitted.contains(&attempt_id) {
                return Err(denied("unknown execution admission"));
            }
            // P121 (K8). A resend that reports no usage is charged a conservative estimate
            // ([`supersede_attempt`]), on a Working and on a Terminal record alike. P89 recorded
            // it as unknown usage on a terminal record, which could never be lifted.
            if state.estimated.contains_key(&attempt_id) {
                state.pending.remove(&attempt_id);
                state.abandoned.remove(&attempt_id);
                // Without usage the estimate stays charged and stays open to a later report.
                if usage.is_some() {
                    settle_estimated(state, &attempt_id, usage.as_ref());
                }
            } else {
                supersede_attempt(state, &attempt_id, usage);
            }
        }
        Change::Abandon { attempt_id } => {
            if !state.admitted.contains(&attempt_id) {
                return Err(denied("unknown execution admission"));
            }
            if state.pending.contains(&attempt_id) {
                state.abandoned.insert(attempt_id);
            }
        }
        Change::Tools { ids } => {
            if state.phase != Phase::Working
                || state.deadline_ms.is_some_and(|d| now_ms >= d)
                || state
                    .max_tool_rounds
                    .is_some_and(|max| state.tool_rounds >= max)
                || ids.iter().any(|id| state.pending_tools.contains(id))
            {
                return Err(denied("execution actions unavailable"));
            }
            state.tool_rounds = state
                .tool_rounds
                .checked_add(1)
                .ok_or_else(|| denied("tool round budget exhausted"))?;
            state.pending_tools.extend(ids);
        }
        Change::ToolsSettled { ids } => {
            for id in ids {
                state.pending_tools.remove(&id);
            }
        }
        Change::Terminal { succeeded } => {
            issue_terminal(state, TurnEnd::of_succeeded(succeeded));
        }
        Change::TurnTerminal { end } => issue_terminal(state, end),
        Change::Reopen { observed_total } => {
            if !may_reopen(state, now_ms) {
                // Typed (the budget's denial, or the reason), so a limit that ran out between the
                // caller's check and this write still reaches the client as that limit.
                return Err(goal_ended_error(state, now_ms));
            }
            let receipt = state
                .terminal
                .take()
                .ok_or_else(|| denied("terminal receipt missing"))?;
            // P121 (K8). What was in flight when the turn ended reported no usage and never will
            // (an Esc before the first output, a provider failure): charge each a conservative
            // estimate under a token budget, so the budget still counts it and the goal resumes.
            let in_flight: Vec<String> = state.pending.iter().cloned().collect();
            for id in &in_flight {
                charge_unknown_usage(state, id);
            }
            // A record latched on unknown usage (by an earlier version, or a completion that
            // reported nothing) is charged one estimate for it and resumes.
            if state.unknown_usage {
                charge_estimate(state);
                state.unknown_usage = false;
            }
            state.earlier_receipts.push(receipt);
            if state.earlier_receipts.len() > EARLIER_RECEIPTS_KEPT {
                state.earlier_receipts.remove(0);
            }
            state.reopened = state.reopened.saturating_add(1);
            state.reopenable = None;
            state.phase = Phase::Working;
            state.completion_admitted = false;
            state.recall_finalization = false;
            // Settled into the receipt just kept: the attempts were in flight when the turn ended
            // and are over. Their calls stay debited. Their usage is unknown, which only matters
            // under a token budget -- and there it was charged an estimate just above
            // (P121). `observed_total` below carries what the goal itself counted. Optional attempts (a title, a recap)
            // never made a receipt partial and may still settle, so they stay.
            let optional = &state.optional_attempts;
            state.pending.retain(|id| optional.contains(id));
            state.pending_tools.clear();
            state.abandoned.clear();
            state.total_tokens = state.total_tokens.max(observed_total);
        }
        Change::NoteContext { tokens } => {
            state.largest_request.0 = state.largest_request.0.max(tokens);
        }
        Change::ChargeInFlight => {
            let in_flight: Vec<String> = state
                .pending
                .iter()
                .filter(|id| !state.optional_attempts.contains(*id))
                .cloned()
                .collect();
            for id in in_flight {
                charge_unknown_usage(state, &id);
                state.pending.remove(&id);
                state.abandoned.remove(&id);
            }
        }
        Change::Reconcile => {
            // Terminal only. Reconciling anything else would be clearing live work.
            if state.phase != Phase::Terminal {
                return Err(denied("only a terminal execution can be reconciled"));
            }
            // ONLY `abandoned`, which is the set that arms the sweep. Deliberately NOT
            // `pending` or `pending_tools`.
            //
            // An earlier draft cleared all three and broke
            // `process_exit_recovers_pending_admission_and_terminal_identity`, which pins
            // `state.pending == before.pending` across a crash recovery. That test is
            // right and the draft was wrong: at Terminal every transition is denied
            // anyway, so clearing those two sets changed no behaviour while destroying
            // the recovered record of what was outstanding. The liability that actually
            // latches is the sweep, and the sweep arms from `abandoned` alone.
            state.abandoned.clear();
        }
        Change::Grant {
            child_id,
            resume_from,
            optional,
        } => {
            if state.phase != Phase::Working || state.deadline_ms.is_some_and(|d| now_ms >= d) {
                return Err(denied("parent execution cannot grant child work"));
            }
            // Native task IDs may be caller-supplied names, not just UUIDs.
            // This is an opaque JSON-map key, never a filesystem path.
            if child_id.is_empty() {
                return Err(denied("invalid child identity"));
            }
            let grant_id = if let Some(source) = resume_from {
                state
                    .child_aliases
                    .get(&source)
                    .cloned()
                    .ok_or_else(|| denied("resumed child has no durable parent grant"))?
            } else {
                child_id.clone()
            };
            if !state.grants.contains_key(&grant_id) {
                let max_calls = state
                    .max_calls
                    .saturating_sub(state.calls)
                    .saturating_sub(1);
                if max_calls == 0 {
                    return Err(denied("parent completion capacity reserved"));
                }
                state.grants.insert(
                    grant_id.clone(),
                    GrantState {
                        max_calls,
                        calls: 0,
                        optional,
                    },
                );
            }
            if state
                .child_aliases
                .get(&child_id)
                .is_some_and(|old| old != &grant_id)
            {
                return Err(denied("child grant identity conflict"));
            }
            state.child_aliases.insert(child_id, grant_id);
        }
        Change::ChildAdmit {
            grant_id,
            attempt_id,
        } => {
            let grant = state
                .grants
                .get(&grant_id)
                .ok_or_else(|| denied("child grant missing"))?;
            if grant.calls >= grant.max_calls {
                // The grant is the child's share of the parent's call limit (P44).
                return Err(limit_denied(state, ExecutionBudgetRule::ModelCallLimit));
            }
            let optional = grant.optional;
            // A child's final response is work charged to its parent; it never
            // consumes the parent's protected final inference opportunity.
            let continuing = background_grant_may_continue(state, optional);
            admit_attempt(state, false, optional, attempt_id, now_ms, continuing)?;
            state.grants.get_mut(&grant_id).unwrap().calls += 1;
        }
        Change::ChildTools { grant_id, ids } => {
            let grant = state
                .grants
                .get(&grant_id)
                .ok_or_else(|| denied("child grant missing"))?;
            if (state.phase != Phase::Working && !background_grant_may_continue(state, grant.optional))
                || state.deadline_ms.is_some_and(|d| now_ms >= d) {
                return Err(denied("parent execution actions unavailable"));
            }
            if !grant.optional {
                // A foreground child's actions are the parent's LIABILITIES, not the parent's
                // TOOL ROUNDS. They go on `pending_tools` (scoped by grant, see
                // `ChildGrant::scoped_ids`) so a terminal receipt issued while the child is
                // still acting is `partial`, and `tools_settled` clears them through the same
                // grant. They do not step `tool_rounds`: `max_tool_rounds` is the durable mirror
                // of the parent's own `--max-turns`, whose unit is the parent's agentic turns
                // (`docs/user-guide/14-headless-mode.md`: subagent sampler calls do not count on
                // that counter family), and the child inherits the same bound for rounds of its
                // own (`resolve_subagent_max_turns`) which its own record enforces. Routing this
                // through `Change::Tools` charged every child round to the parent, so a child
                // inheriting N was denied its last round with "execution actions unavailable"
                // and the parent's next round became a finalize slot - `-32603` for both, on a
                // documented flag. `foreground_child_rounds_are_liabilities_not_parent_rounds`
                // and `tests/max_turns_foreground_child_acp.rs` pin this.
                if ids.iter().any(|id| state.pending_tools.contains(id)) {
                    return Err(denied("execution actions unavailable"));
                }
                state.pending_tools.extend(ids);
            }
        }
    }
    Ok(())
}

/// Issue the terminal receipt once; every later terminal change only re-asserts the phase.
fn issue_terminal(state: &mut Snapshot, end: TurnEnd) {
    if state.terminal.is_none() {
        let succeeded = end == TurnEnd::Succeeded;
        // P89. Decided before the phase moves to Terminal. A finalization the turn loop entered on a
        // limit (or a crash recovery forced) is not a turn interruption, even when the turn's answer
        // then came back normally; a recall finalization is. A spent limit the record itself shows
        // is judged when the record is reopened ([`may_reopen`]), not here: counters only grow and
        // deadlines only pass, so that check can only get stricter.
        state.reopenable = Some(
            end != TurnEnd::Stopped
                && (state.phase != Phase::Finalizing || state.recall_finalization),
        );
        let partial = !succeeded
            || state
                .pending
                .iter()
                .any(|id| !state.optional_attempts.contains(id))
            || !state.pending_tools.is_empty()
            || (state.phase == Phase::Finalizing && !state.recall_finalization);
        state.terminal = Some(TerminalReceipt {
            id: uuid::Uuid::new_v4().to_string(), execution_id: state.execution_id.clone(),
            partial, pending_attempts: state.pending.iter().cloned().collect(),
            optional_pending_attempts: state.pending.intersection(&state.optional_attempts).cloned().collect(),
            pending_tool_calls: state.pending_tools.iter().cloned().collect(),
            evidence_refs: vec!["updates.jsonl".into(), "chat_history.jsonl".into()],
            completed_checks: "unknown; inspect persisted tool and event evidence".into(),
            known_session_edited_paths: state.known_session_edited_paths.clone(),
            omitted_edited_paths: state.omitted_edited_paths,
            reason: if partial { "Execution stopped with bounded capacity or unresolved work. Consult persisted conversation and tool results; pending attempts must not be replayed automatically." }
                else { "Turn returned normally; persisted conversation and tool results remain the evidence." }.into(),
        });
    }
    state.phase = Phase::Terminal;
}

#[derive(Debug)]
pub(crate) struct Execution {
    key: String,
    prompt_id: Mutex<String>,
    tx: mpsc::WeakUnboundedSender<PersistenceMsg>,
    deadline_ms: AtomicI64,
    parent_grant: Option<Arc<ChildGrant>>,
    /// Whether any attempt of this execution is abandoned and still waiting for a resubmit
    /// to take it over. [`Execution::supersede_pending_attempts`] runs before every model
    /// submission and almost always has nothing to do; without this it pays a persistence
    /// round trip and a state-file read each time to learn that. Set by [`ExecutionAdmission::abandon`]
    /// (a child grant's abandon reaches its parent through the same method) and seeded from
    /// the durable state at [`Execution::open`], so a restored execution still sweeps.
    abandoned_attempts: std::sync::atomic::AtomicBool,
    /// The admission of the turn's CURRENT model request ([`Execution::begin_turn_request`]), so the
    /// turn that sees that request fail can read the token-budget refusal it recorded (Contract
    /// D.4). Per request, not per execution: a side call (`/btw`, a recap) refused under the same
    /// execution records into its own [`RequestAdmission`] and can never be what the turn reports.
    ///
    /// Holds only the request's denial SLOT, never the request itself: the request owns an
    /// `Arc<Execution>`, so holding it here would be a reference cycle that outlives `release`.
    turn_request: Mutex<Option<DenialSlot>>,
    /// P89. Set once this instance has issued the terminal receipt, so a goal's next turn that finds
    /// it still registered knows to read the record and reopen it instead of adopting it as is.
    terminal_issued: std::sync::atomic::AtomicBool,
    /// P89 (L-2). Identifies this instance as the owner of its key's completion reservation in
    /// [`RESERVATION_OWNERS`].
    instance: u64,
    /// P121 (K8). The input size of the largest request this instance has sent
    /// ([`Execution::note_request_context`]); written to the record when an unreported request is
    /// charged, so the charge is at least that request's input.
    context_hint: std::sync::atomic::AtomicU64,
}

type DenialSlot = Arc<Mutex<Option<ExecutionBudgetDenial>>>;

/// P89 (L-2). Which [`Execution`] instance holds each key's completion reservation in the process
/// budget. The sampler's reservation set is keyed by scope alone, so two instances of one key (a
/// displaced execution still referenced by a background child, and its successor) share a slot; only
/// the instance that took it may give it back when it is dropped.
static RESERVATION_OWNERS: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
static NEXT_INSTANCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn reservation_owners() -> std::sync::MutexGuard<'static, HashMap<String, u64>> {
    RESERVATION_OWNERS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// The admission capability of ONE model request, recording that request's own token-budget refusal.
///
/// The sampler flattens every admission refusal to a string at the [`ExecutionAdmission`] boundary, so
/// the typed [`ExecutionBudgetDenial`] is kept here, on the object the request itself carries
/// (`ConversationRequest::execution_admission`). Correlation is by construction: only an admission made
/// through this wrapper can fill it. Everything except recording is delegated to the execution.
#[derive(Debug)]
pub(crate) struct RequestAdmission {
    execution: Arc<Execution>,
    denial: DenialSlot,
}

impl RequestAdmission {
    /// This request's token-budget refusal, if one of its required admissions was refused by the
    /// guard. Taken once.
    pub(crate) fn take_budget_denial(&self) -> Option<ExecutionBudgetDenial> {
        self.denial.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

// Retain through cancellation so the existing terminal-delivery path can commit
// its receipt even after the turn future has been dropped. Removed after delivery.
static CURRENT: OnceLock<Mutex<HashMap<String, Arc<Execution>>>> = OnceLock::new();

impl Execution {
    pub(crate) async fn grant_child(
        self: &Arc<Self>,
        child_id: &str,
        resume_from: Option<String>,
        optional: bool,
    ) -> io::Result<Arc<ChildGrant>> {
        let state = self
            .change(Change::Grant {
                child_id: child_id.to_owned(),
                resume_from,
                optional,
            })
            .await?;
        let grant_id = state
            .child_aliases
            .get(child_id)
            .cloned()
            .ok_or_else(|| denied("child grant acknowledgment missing"))?;
        Ok(Arc::new(ChildGrant {
            parent: self.clone(),
            grant_id,
        }))
    }
    pub(crate) async fn open(
        tx: &mpsc::UnboundedSender<PersistenceMsg>,
        session_id: &str,
        root_id: &str,
        prompt_id: &str,
        max_calls: u64,
        deadline_ms: Option<i64>,
        max_tool_rounds: Option<u64>,
        limits: TokenLimits,
        parent_grant: Option<Arc<ChildGrant>>,
    ) -> io::Result<Arc<Self>> {
        Self::open_inner(
            tx, session_id, root_id, prompt_id, max_calls, deadline_ms, max_tool_rounds, limits,
            parent_grant, false,
        )
        .await
    }

    /// P89. [`Execution::open`] for the next turn of an active goal (`root_id` is the goal id).
    ///
    /// A goal's turns share one record, and an earlier turn that was interrupted -- the user's Esc,
    /// a provider error, a max-tokens cut, a refusal -- left it terminal. That ended the TURN, not
    /// the goal: the record is reopened ([`Change::Reopen`]) with its counters intact. A record a
    /// limit stopped stays terminal, and the open is refused with the reason and the remedy
    /// ([`goal_end_reason`]; a spent budget as its typed denial).
    pub(crate) async fn open_goal(
        tx: &mpsc::UnboundedSender<PersistenceMsg>,
        session_id: &str,
        goal_id: &str,
        prompt_id: &str,
        max_calls: u64,
        deadline_ms: Option<i64>,
        max_tool_rounds: Option<u64>,
        limits: TokenLimits,
        parent_grant: Option<Arc<ChildGrant>>,
    ) -> io::Result<Arc<Self>> {
        Self::open_inner(
            tx, session_id, goal_id, prompt_id, max_calls, deadline_ms, max_tool_rounds, limits,
            parent_grant, true,
        )
        .await
    }

    async fn open_inner(
        tx: &mpsc::UnboundedSender<PersistenceMsg>,
        session_id: &str,
        root_id: &str,
        prompt_id: &str,
        max_calls: u64,
        deadline_ms: Option<i64>,
        max_tool_rounds: Option<u64>,
        limits: TokenLimits,
        parent_grant: Option<Arc<ChildGrant>>,
        continuing: bool,
    ) -> io::Result<Arc<Self>> {
        let key = blake3::hash(format!("{session_id}\0{root_id}").as_bytes())
            .to_hex()
            .to_string();
        let observed_total = limits.initial_total;
        if let Some(existing) = Self::current(session_id).filter(|e| e.key == key) {
            if continuing && existing.terminal_issued.load(Ordering::Acquire) {
                // The previous turn of this goal issued a receipt on this very instance.
                existing.reopen(session_id, observed_total).await?;
            }
            *existing.prompt_id.lock().unwrap_or_else(|e| e.into_inner()) = prompt_id.to_owned();
            // A new turn on the same execution: an earlier turn's request, and any refusal it
            // recorded and never reported, are not this turn's.
            existing
                .turn_request
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            return Ok(existing);
        }
        let execution = Arc::new(Self {
            key,
            prompt_id: Mutex::new(prompt_id.to_owned()),
            tx: tx.downgrade(),
            deadline_ms: AtomicI64::new(i64::MAX),
            parent_grant,
            abandoned_attempts: std::sync::atomic::AtomicBool::new(false),
            turn_request: Mutex::new(None),
            terminal_issued: std::sync::atomic::AtomicBool::new(false),
            instance: NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed),
            context_hint: std::sync::atomic::AtomicU64::new(0),
        });
        let state = execution
            .change(Change::Open {
                max_calls,
                deadline_ms,
                max_tool_rounds,
                limits,
            })
            .await?;
        execution
            .deadline_ms
            .store(state.deadline_ms.unwrap_or(i64::MAX), Ordering::Release);
        let reopening = continuing && state.phase == Phase::Terminal;
        let state = if reopening {
            // P89. Refused here, before the turn records anything, with the reason and the remedy.
            execution.reopen_record(session_id, &state, observed_total).await?
        } else if state.phase == Phase::Terminal && !state.abandoned.is_empty() {
            // P03. A crash-poisoned execution can be Terminal with unresolved liabilities.
            // Reconcile BEFORE arming the sweep below: otherwise the sweep fires on every
            // open and every transition it drives is denied at Terminal, which is the latch
            // that permanently kills this session+goal.
            execution.change(Change::Reconcile).await?
        } else {
            state
        };
        // A restored execution may already carry abandoned attempts; its first sweep must run.
        execution
            .abandoned_attempts
            .store(!state.abandoned.is_empty(), Ordering::Release);
        // A restored execution with an unknown attempt may only finalize; it must
        // never repeat actions whose effects were lost at the crash boundary.
        if state.phase == Phase::Working
            && (state
                .pending
                .iter()
                .any(|id| !state.optional_attempts.contains(id))
                || !state.pending_tools.is_empty())
        {
            execution.change(Change::Finalize).await?;
        }
        if state.phase == Phase::Terminal {
            execution.terminal_issued.store(true, Ordering::Release);
        } else if !reopening {
            // (A reopened record reserved before it reopened.)
            make_room(session_id, &execution.key);
            execution.reserve(&state)?;
        }
        let mut registry = CURRENT
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        registry.retain(|_, execution| execution.tx.strong_count() > 0);
        registry.insert(session_id.to_owned(), execution.clone());
        Ok(execution)
    }

    /// P89. Reopen this registered instance's terminal record for the goal's next turn.
    async fn reopen(&self, session_id: &str, observed_total: u64) -> io::Result<()> {
        let state = self.snapshot().await?;
        if state.phase == Phase::Terminal {
            let state = self.reopen_record(session_id, &state, observed_total).await?;
            self.abandoned_attempts
                .store(!state.abandoned.is_empty(), Ordering::Release);
        }
        self.terminal_issued.store(false, Ordering::Release);
        Ok(())
    }

    /// P89. Reopen the terminal record `state` read, or refuse with why it must stay terminal. The
    /// completion reservation is taken FIRST: a reservation the process budget refuses leaves the
    /// record terminal and untouched, never working without a final answer to fall back on.
    async fn reopen_record(
        &self,
        session_id: &str,
        state: &Snapshot,
        observed_total: u64,
    ) -> io::Result<Snapshot> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        if !may_reopen(state, now_ms) {
            return Err(goal_ended_error(state, now_ms));
        }
        make_room(session_id, &self.key);
        self.reserve(state)?;
        match self.change(Change::Reopen { observed_total }).await {
            Ok(reopened) => Ok(reopened),
            Err(error) => {
                self.give_back_reservation();
                Err(error)
            }
        }
    }

    /// Reserve this execution's final answer in the process budget, if one is set, and record this
    /// instance as the reservation's owner (L-2).
    ///
    /// Lock order, everywhere: [`RESERVATION_OWNERS`], then the sampler's budget. The owners lock is
    /// held across the sampler call, so another instance of the same key can never give the slot
    /// back between this reservation and the ownership it records.
    fn reserve(&self, state: &Snapshot) -> io::Result<()> {
        if let Some(budget) = fuigo_sampler::execution_budget::process_budget().map_err(denied)? {
            let mut owners = reservation_owners();
            // No call left to reserve for the final answer is the model-call limit (P44).
            budget.reserve_completion(&self.key).map_err(|refusal| {
                if refusal == fuigo_sampler::execution_budget::CALL_LIMIT {
                    limit_denied(state, ExecutionBudgetRule::ModelCallLimit)
                } else {
                    denied(refusal)
                }
            })?;
            owners.insert(self.key.clone(), self.instance);
        }
        Ok(())
    }

    /// P89 (L-2). Give back the completion reservation this instance took, if it still holds it.
    fn give_back_reservation(&self) {
        let mut owners = reservation_owners();
        if owners.get(&self.key) == Some(&self.instance) {
            if let Ok(Some(budget)) = fuigo_sampler::execution_budget::process_budget() {
                budget.release_completion(&self.key);
            }
            owners.remove(&self.key);
        }
    }

    /// P89. Whether a goal's next turn would find `goal_id`'s record unable to continue, and why
    /// ([`goal_end_reason`]). `/goal resume` asks this before it hands the goal back to the model.
    /// `None` when there is no record yet, it may continue, or it cannot be read (the turn's own
    /// open then reports what is wrong).
    pub(crate) async fn goal_resume_blocker(
        tx: &mpsc::UnboundedSender<PersistenceMsg>,
        session_id: &str,
        goal_id: &str,
    ) -> Option<String> {
        let key = blake3::hash(format!("{session_id}\0{goal_id}").as_bytes())
            .to_hex()
            .to_string();
        let (respond_to, rx) = oneshot::channel();
        tx.send(PersistenceMsg::ExecutionState {
            mutation: ExecutionMutation {
                key,
                change: Change::Read,
            },
            respond_to,
        })
        .ok()?;
        let state = rx.await.ok()?.ok()?;
        goal_end_reason(&state, chrono::Utc::now().timestamp_millis())
    }

    pub(crate) fn current(session_id: &str) -> Option<Arc<Self>> {
        CURRENT
            .get()?
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(session_id)
            .cloned()
    }
    pub(crate) fn for_prompt(session_id: &str, prompt_id: &str) -> Option<Arc<Self>> {
        Self::current(session_id).filter(|execution| {
            *execution
                .prompt_id
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                == prompt_id
        })
    }

    pub(crate) fn release(&self, session_id: &str) {
        if let Some(registry) = CURRENT.get() {
            let mut registry = registry.lock().unwrap_or_else(|e| e.into_inner());
            if registry.get(session_id).is_some_and(|e| e.key == self.key) {
                registry.remove(session_id);
            }
        }
    }

    async fn change(&self, change: Change) -> io::Result<Snapshot> {
        let tx = self
            .tx
            .upgrade()
            .ok_or_else(|| denied("execution persistence closed"))?;
        let (respond_to, rx) = oneshot::channel();
        tx.send(PersistenceMsg::ExecutionState {
            mutation: ExecutionMutation {
                key: self.key.clone(),
                change,
            },
            respond_to,
        })
        .map_err(|_| denied("execution persistence closed"))?;
        rx.await
            .map_err(|_| denied("execution persistence acknowledgment lost"))?
    }

    pub(crate) async fn snapshot(&self) -> io::Result<Snapshot> {
        self.change(Change::Read).await
    }
    /// P121 (K8). See [`Change::ChargeInFlight`].
    pub(crate) async fn charge_in_flight(&self) -> io::Result<()> {
        self.record_context_hint().await?;
        self.change(Change::ChargeInFlight).await.map(|_| ())
    }

    /// P121 (K8). The request about to be sent has about `tokens` of input. Kept in memory only;
    /// [`Self::record_context_hint`] writes it when an unreported request is charged.
    pub(crate) fn note_request_context(&self, tokens: u64) {
        self.context_hint.fetch_max(tokens, Ordering::Relaxed);
    }

    async fn record_context_hint(&self) -> io::Result<()> {
        let tokens = self.context_hint.load(Ordering::Relaxed);
        if tokens > 0 {
            self.change(Change::NoteContext { tokens }).await?;
        }
        Ok(())
    }
    pub(crate) async fn finalize(&self) -> io::Result<()> {
        self.change(Change::Finalize).await.map(|_| ())
    }
    pub(crate) async fn finalize_recall(&self) -> io::Result<()> {
        self.change(Change::FinalizeRecall).await.map(|_| ())
    }
    pub(crate) async fn tools(&self, ids: Vec<String>) -> io::Result<()> {
        if let Some(parent) = &self.parent_grant {
            parent.tools(ids.clone()).await?;
        }
        let admitted = self.change(Change::Tools { ids: ids.clone() }).await.map(|_| ());
        // A round this record refuses (its own bound, phase or deadline) never runs, so it must
        // not stay registered on the parent as a liability: `tools_settled` is only reached after
        // the calls execute, and an unsettled entry would mark the parent's receipt `partial`
        // for work that never started.
        if admitted.is_err() && let Some(parent) = &self.parent_grant {
            let _ = Box::pin(parent.parent.tools_settled(parent.scoped_ids(ids))).await;
        }
        admitted
    }
    pub(crate) async fn tools_settled(&self, ids: Vec<String>) -> io::Result<()> {
        if let Some(parent) = &self.parent_grant {
            Box::pin(parent.parent.tools_settled(parent.scoped_ids(ids.clone()))).await?;
        }
        self.change(Change::ToolsSettled { ids }).await.map(|_| ())
    }
    /// Supersede every abandoned attempt of this execution, because this caller is
    /// resubmitting a logical call and the sampler marked those attempts finished.
    ///
    /// In-flight attempts are untouched -- only an attempt the sampler already handed off
    /// with [`Change::Abandon`] is ever marked. Abandoned attempts of OTHER logical calls in
    /// the same execution (a side call's, a subagent's through its parent grant) are swept
    /// too: the execution's abandoned set is not partitioned by logical call, and the
    /// sweeping resubmit does not know which attempts belong to it. That is deliberate --
    /// an abandoned attempt is finished work whoever left it, and leaving one behind makes
    /// the turn's terminal receipt partial -- but it is wider than "the caller's own call".
    ///
    /// Costs nothing when nothing is abandoned: that is the common case, and this runs
    /// before every model submission.
    pub(crate) async fn supersede_pending_attempts(&self) -> io::Result<()> {
        if !self.abandoned_attempts.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        // Anything that fails leaves the sweep armed, so the next submission retries it.
        let abandoned = match self.snapshot().await {
            Ok(state) => state.abandoned,
            Err(error) => {
                self.abandoned_attempts.store(true, Ordering::Release);
                return Err(error);
            }
        };
        for attempt_id in abandoned {
            // `supersede` carries the same settlement to a parent grant.
            if let Err(error) = ExecutionAdmission::supersede(self, attempt_id, None).await {
                self.abandoned_attempts.store(true, Ordering::Release);
                return Err(denied_owned(error));
            }
        }
        Ok(())
    }

    pub(crate) async fn terminal(&self, succeeded: bool) -> io::Result<TerminalReceipt> {
        self.issue_terminal(Change::Terminal { succeeded }).await
    }

    /// P89. [`Execution::terminal`] for a turn that ended by `end`. Only a turn interrupted for a
    /// reason that is not a limit leaves the record reopenable by the goal's next turn.
    pub(crate) async fn terminal_after(&self, end: TurnEnd) -> io::Result<TerminalReceipt> {
        self.issue_terminal(Change::TurnTerminal { end }).await
    }

    async fn issue_terminal(&self, change: Change) -> io::Result<TerminalReceipt> {
        // The receipt may be left unreported-in-flight (an Esc): keep the input size it was sent with.
        self.record_context_hint().await?;
        let receipt = self
            .change(change)
            .await?
            .terminal
            .ok_or_else(|| denied("terminal receipt missing"))?;
        self.terminal_issued.store(true, Ordering::Release);
        if let Some(budget) = fuigo_sampler::execution_budget::process_budget().map_err(denied)? {
            let mut owners = reservation_owners();
            budget.release_completion(&self.key);
            owners.remove(&self.key);
        }
        Ok(receipt)
    }

    pub(crate) async fn record_edited_paths(&self, paths: BTreeSet<String>) -> io::Result<()> {
        self.change(Change::EditedPaths { paths }).await.map(|_| ())
    }

    /// A per-request admission for one side call (`/btw`): records only its own refusal and is
    /// never what the turn reports.
    pub(crate) fn request_admission(self: &Arc<Self>) -> Arc<RequestAdmission> {
        Arc::new(RequestAdmission {
            execution: self.clone(),
            denial: Arc::new(Mutex::new(None)),
        })
    }

    /// The admission for the turn's next model request, registered as the turn's CURRENT request so
    /// [`Execution::take_turn_request_denial`] reads that request's refusal and nothing older.
    pub(crate) fn begin_turn_request(self: &Arc<Self>) -> Arc<RequestAdmission> {
        let request = self.request_admission();
        *self.turn_request.lock().unwrap_or_else(|e| e.into_inner()) = Some(request.denial.clone());
        request
    }

    /// The token-budget refusal recorded by the turn's current model request, if any (Contract D.4).
    pub(crate) fn take_turn_request_denial(&self) -> Option<ExecutionBudgetDenial> {
        self.turn_request
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .and_then(|slot| slot.lock().unwrap_or_else(|e| e.into_inner()).take())
    }

    /// [`ExecutionAdmission::admit`], keeping the token-budget refusal typed for a caller that records
    /// it. The string is what the sampler sees, unchanged.
    async fn admit_typed(
        &self,
        purpose: RequestPurpose,
        attempt_id: String,
    ) -> Result<(), (String, Option<ExecutionBudgetDenial>)> {
        if let Some(parent) = &self.parent_grant {
            parent.admit(attempt_id.clone()).await.map_err(|error| {
                (
                    "parent execution admission denied or not durable".to_string(),
                    budget_denial_of(&error),
                )
            })?;
        }
        self.change(Change::Admit {
            completion: purpose == RequestPurpose::Completion,
            optional: matches!(purpose, RequestPurpose::Title | RequestPurpose::Recap),
            attempt_id,
        })
        .await
        .map(|_| ())
        .map_err(|error| {
            (
                "execution admission denied or not durable".to_string(),
                budget_denial_of(&error),
            )
        })
    }
}

/// P89 (L-2). An execution that never reached `terminal()` -- its session closed while its goal was
/// still working, a later prompt of the same session displaced it, or the turn left early on an
/// error -- gives its completion reservation back when the last reference to it goes.
impl Drop for Execution {
    fn drop(&mut self) {
        self.give_back_reservation();
    }
}

/// P89 (L-2). Before an execution reserves: drop the registered executions of sessions whose
/// persistence is gone (closed sessions), and the one `session_id` registered under another key
/// (a goal execution a plain prompt is about to replace), so the reservations they hold are back
/// in the process budget before this one is counted against it. Dropped outside the registry lock.
fn make_room(session_id: &str, key: &str) {
    let displaced: Vec<Arc<Execution>> = {
        let Some(registry) = CURRENT.get() else {
            return;
        };
        let mut registry = registry.lock().unwrap_or_else(|e| e.into_inner());
        let mut displaced = Vec::new();
        registry.retain(|session, execution| {
            let keep = execution.tx.strong_count() > 0
                && !(session == session_id && execution.key != key);
            if !keep {
                displaced.push(execution.clone());
            }
            keep
        });
        displaced
    };
    drop(displaced);
}

impl ExecutionAdmission for RequestAdmission {
    fn scope_id(&self) -> &str {
        self.execution.scope_id()
    }
    fn remaining_time(&self) -> Option<std::time::Duration> {
        self.execution.remaining_time()
    }
    fn admit(&self, purpose: RequestPurpose, attempt_id: String) -> AdmissionFuture<'_> {
        Box::pin(async move {
            self.execution
                .admit_typed(purpose, attempt_id)
                .await
                .map_err(|(message, denial)| {
                    // An optional side call (a title, a recap) does not end anything, so its refusal
                    // is never recorded as a denial to report.
                    let optional = matches!(purpose, RequestPurpose::Title | RequestPurpose::Recap);
                    if let Some(denial) = denial.filter(|_| !optional) {
                        let mut slot = self.denial.lock().unwrap_or_else(|e| e.into_inner());
                        if slot.is_none() {
                            *slot = Some(denial);
                        }
                    }
                    message
                })
        })
    }
    fn settle(
        &self,
        attempt_id: String,
        usage: Option<fuigo_sampling_types::TokenUsage>,
    ) -> AdmissionFuture<'_> {
        ExecutionAdmission::settle(self.execution.as_ref(), attempt_id, usage)
    }
    fn supersede(
        &self,
        attempt_id: String,
        usage: Option<fuigo_sampling_types::TokenUsage>,
    ) -> AdmissionFuture<'_> {
        ExecutionAdmission::supersede(self.execution.as_ref(), attempt_id, usage)
    }
    fn abandon(&self, attempt_id: String) -> AdmissionFuture<'_> {
        ExecutionAdmission::abandon(self.execution.as_ref(), attempt_id)
    }
}

impl ExecutionAdmission for Execution {
    fn scope_id(&self) -> &str {
        &self.key
    }
    fn remaining_time(&self) -> Option<std::time::Duration> {
        let deadline = self.deadline_ms.load(Ordering::Acquire);
        let own = (deadline != i64::MAX).then(|| {
            std::time::Duration::from_millis(
                deadline
                    .saturating_sub(chrono::Utc::now().timestamp_millis())
                    .max(0) as u64,
            )
        });
        match (
            own,
            self.parent_grant
                .as_ref()
                .and_then(|parent| parent.parent.remaining_time()),
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
    fn admit(&self, purpose: RequestPurpose, attempt_id: String) -> AdmissionFuture<'_> {
        Box::pin(async move {
            self.admit_typed(purpose, attempt_id)
                .await
                .map_err(|(message, _)| message)
        })
    }
    fn settle(
        &self,
        attempt_id: String,
        usage: Option<fuigo_sampling_types::TokenUsage>,
    ) -> AdmissionFuture<'_> {
        Box::pin(async move {
            if let Some(parent) = &self.parent_grant {
                parent
                    .parent
                    .settle(attempt_id.clone(), usage.clone())
                    .await?;
            }
            self.change(Change::Settle { attempt_id, usage })
                .await
                .map(|_| ())
                .map_err(|_| "execution settlement not durable".into())
        })
    }
    fn supersede(
        &self,
        attempt_id: String,
        usage: Option<fuigo_sampling_types::TokenUsage>,
    ) -> AdmissionFuture<'_> {
        Box::pin(async move {
            if let Some(parent) = &self.parent_grant {
                parent
                    .parent
                    .supersede(attempt_id.clone(), usage.clone())
                    .await?;
            }
            self.change(Change::Supersede { attempt_id, usage })
                .await
                .map(|_| ())
                .map_err(|_| "execution settlement not durable".into())
        })
    }
    fn abandon(&self, attempt_id: String) -> AdmissionFuture<'_> {
        Box::pin(async move {
            if let Some(parent) = &self.parent_grant {
                parent.parent.abandon(attempt_id.clone()).await?;
            }
            // Arm the sweep the next submission runs BEFORE the durable round trip, not after.
            //
            // What this guarantees: the in-process flag is never behind the durable `abandoned`
            // set, so no sweep can read it disarmed for an abandon that has already been ordered
            // -- including forever, which is what an armed-after flag did when the write failed.
            //
            // What it does NOT guarantee: that a sweep inside the round trip finds anything. The
            // snapshot it reads still lists the attempt as pending until the `Change::Abandon`
            // write lands, so a resubmit in that window still supersedes nothing and can still
            // leave a partial receipt. The window is narrowed, not closed; it stays unreachable
            // only because every shell resubmit path sleeps, compacts or refreshes credentials
            // first, which is a property of four call sites, not an invariant.
            //
            // Arming first costs at most one `Change::Read` on a sweep that has nothing to do.
            self.abandoned_attempts
                .store(true, std::sync::atomic::Ordering::Release);
            self.change(Change::Abandon { attempt_id })
                .await
                .map(|_| ())
                .map_err(|_| -> String { "execution settlement not durable".into() })
        })
    }
}

#[derive(Debug)]
pub(crate) struct ChildGrant {
    parent: Arc<Execution>,
    grant_id: String,
}

impl ChildGrant {
    async fn admit(&self, attempt_id: String) -> io::Result<()> {
        self.parent
            .change(Change::ChildAdmit {
                grant_id: self.grant_id.clone(),
                attempt_id,
            })
            .await
            .map(|_| ())
    }
    async fn tools(&self, ids: Vec<String>) -> io::Result<()> {
        self.parent
            .change(Change::ChildTools {
                grant_id: self.grant_id.clone(),
                ids: self.scoped_ids(ids),
            })
            .await
            .map(|_| ())
    }
    fn scoped_ids(&self, ids: Vec<String>) -> Vec<String> {
        ids.into_iter()
            .map(|id| format!("{}:{id}", self.grant_id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_activation_does_not_require_process_environment() {
        assert!(!should_track_execution(false, false, false, false, false));
        for i in 0..5 {
            let mut inputs = [false; 5];
            inputs[i] = true;
            assert!(should_track_execution(inputs[0], inputs[1], inputs[2], inputs[3], inputs[4]));
        }
        assert!(!should_terminalize(true, true, Phase::Working));
        assert!(should_terminalize(true, false, Phase::Working));
        assert!(should_terminalize(false, true, Phase::Working));
        assert!(should_terminalize(true, true, Phase::Finalizing));
        assert!(should_terminalize(true, true, Phase::Terminal));
    }

    #[tokio::test]
    async fn settled_recall_can_complete_but_budget_stop_and_pending_work_cannot() {
        for (recall, succeeded, pending) in [(true, true, false), (false, true, false), (true, false, false), (true, true, true)] {
            let dir = tempfile::tempdir().unwrap();
            let mut state = apply(dir.path(), mutation(&key(), Change::Open {
                max_calls: 4, deadline_ms: None, max_tool_rounds: Some(3), limits: TokenLimits::default(),
            })).await.unwrap();
            if pending {
                transition(&mut state, Change::Tools { ids: vec!["unresolved".into()] }, 0).unwrap();
            }
            transition(&mut state, if recall { Change::FinalizeRecall } else { Change::Finalize }, 0).unwrap();
            let attempt = uuid::Uuid::new_v4().to_string();
            transition(&mut state, Change::Admit { completion: true, optional: false, attempt_id: attempt.clone() }, 0).unwrap();
            transition(&mut state, Change::Settle { attempt_id: attempt, usage: Some(Default::default()) }, 0).unwrap();
            transition(&mut state, Change::Terminal { succeeded }, 0).unwrap();
            assert_eq!(state.terminal.unwrap().partial, !recall || !succeeded || pending);
        }
    }

    #[tokio::test]
    async fn issued_background_grant_outlives_successful_turn_without_reopening_parent() {
        for (optional, succeeded) in [(true, true), (true, false), (false, true)] {
            let dir = tempfile::tempdir().unwrap();
            let key = key();
            let mut state = apply(dir.path(), mutation(&key, Change::Open {
                max_calls: 4, deadline_ms: None, max_tool_rounds: Some(2),
                limits: TokenLimits::default(),
            })).await.unwrap();
            transition(&mut state, Change::Grant {
                child_id: "named-child".into(), resume_from: None, optional,
            }, 0).unwrap();
            transition(&mut state, Change::Terminal { succeeded }, 0).unwrap();
            let receipt = serde_json::to_value(&state.terminal).unwrap();
            let child_call = || Change::ChildAdmit {
                grant_id: "named-child".into(), attempt_id: uuid::Uuid::new_v4().to_string(),
            };
            let may_continue = optional && succeeded;
            assert_eq!(transition(&mut state, child_call(), 0).is_ok(), may_continue);
            assert_eq!(transition(&mut state, Change::ChildTools {
                grant_id: "named-child".into(), ids: vec!["child-action".into()],
            }, 0).is_ok(), may_continue);
            assert!(transition(&mut state, Change::Grant {
                child_id: "late-child".into(), resume_from: None, optional: true,
            }, 0).is_err());
            assert!(transition(&mut state, Change::Tools { ids: vec!["parent-action".into()] }, 0).is_err());
            assert!(transition(&mut state, Change::Admit {
                completion: false, optional: true, attempt_id: uuid::Uuid::new_v4().to_string(),
            }, 0).is_err());
            if may_continue {
                state.deadline_ms = Some(0);
                assert!(transition(&mut state, child_call(), 1).is_err());
                assert!(transition(&mut state, Change::ChildTools {
                    grant_id: "named-child".into(), ids: vec!["late-action".into()],
                }, 1).is_err());
                state.deadline_ms = None;
                state.limits.total = Some(0);
                assert!(transition(&mut state, child_call(), 0).is_err());
                state.limits.total = None;
                transition(&mut state, child_call(), 0).unwrap();
                transition(&mut state, child_call(), 0).unwrap();
                assert!(transition(&mut state, child_call(), 0).is_err());
                assert_eq!(state.calls, 3, "parent final slot stays protected");
                assert_eq!(state.pending.len(), 3, "unknown child liabilities retained");
            }
            assert_eq!(state.phase, Phase::Terminal);
            assert_eq!(serde_json::to_value(&state.terminal).unwrap(), receipt);
        }
    }

    fn fixture_actor(dir: std::path::PathBuf) -> (mpsc::UnboundedSender<PersistenceMsg>, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let PersistenceMsg::ExecutionState { mutation, respond_to } = message {
                    let _ = respond_to.send(apply(&dir, mutation).await);
                } else {
                    panic!("unexpected fixture message");
                }
            }
        });
        (tx, task)
    }

    type SeenChanges = Arc<Mutex<Vec<String>>>;

    /// [`fixture_actor`] that also records the variant of every change it applied, so a test
    /// can count what actually left the process.
    fn counting_fixture_actor(
        dir: std::path::PathBuf,
    ) -> (
        mpsc::UnboundedSender<PersistenceMsg>,
        tokio::task::JoinHandle<()>,
        SeenChanges,
    ) {
        let seen: SeenChanges = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let PersistenceMsg::ExecutionState {
                    mutation,
                    respond_to,
                } = message
                {
                    let label = format!("{:?}", mutation.change);
                    sink.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(label.split_whitespace().next().unwrap_or("").to_owned());
                    let _ = respond_to.send(apply(&dir, mutation).await);
                } else {
                    panic!("unexpected fixture message");
                }
            }
        });
        (tx, task, seen)
    }

    fn reads(seen: &SeenChanges) -> usize {
        seen.lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|label| *label == "Read")
            .count()
    }

    /// The sweep that takes abandoned attempts over runs before EVERY model submission, and
    /// the common case is that nothing was abandoned. Reading the durable state to discover
    /// that is a persistence-actor round trip and a state-file read per model call, forever.
    /// The execution remembers whether anything is abandoned, so the no-op sweep never leaves
    /// the process -- and it starts sweeping again the moment something is.
    #[tokio::test]
    async fn a_sweep_with_nothing_to_supersede_never_leaves_the_process() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, actor, seen) = counting_fixture_actor(dir.path().to_owned());
        let session = uuid::Uuid::new_v4().to_string();
        let execution = Execution::open(
            &tx,
            &session,
            "quiet",
            "turn1",
            9,
            None,
            Some(9),
            TokenLimits::default(),
            None,
        )
        .await
        .unwrap();
        // Three model submissions of one turn, each preceded by the sweep, none abandoned.
        for _ in 0..3 {
            execution.supersede_pending_attempts().await.unwrap();
            let attempt = uuid::Uuid::new_v4().to_string();
            execution
                .admit(RequestPurpose::Work, attempt.clone())
                .await
                .unwrap();
            execution
                .settle(attempt, Some(fuigo_sampling_types::TokenUsage::default()))
                .await
                .unwrap();
        }
        assert_eq!(
            reads(&seen),
            0,
            "a sweep with nothing to supersede costs no round trip: {:?}",
            seen.lock().unwrap_or_else(|e| e.into_inner())
        );

        // An abandoned attempt still gets taken over, and the sweep goes quiet again after.
        let attempt = uuid::Uuid::new_v4().to_string();
        execution
            .admit(RequestPurpose::Work, attempt.clone())
            .await
            .unwrap();
        ExecutionAdmission::abandon(execution.as_ref(), attempt.clone())
            .await
            .unwrap();
        execution.supersede_pending_attempts().await.unwrap();
        let state = execution.snapshot().await.unwrap();
        assert!(
            state.abandoned.is_empty() && !state.pending.contains(&attempt),
            "the sweep takes the abandoned attempt over: {state:?}"
        );
        let settled = reads(&seen);
        execution.supersede_pending_attempts().await.unwrap();
        assert_eq!(
            reads(&seen),
            settled,
            "the sweep is quiet again once nothing is abandoned"
        );
        execution.release(&session);
        drop(tx);
        actor.await.unwrap();
    }

    /// `abandon` arms the sweep BEFORE its durable round trip, not after.
    ///
    /// The in-process flag is what [`Execution::supersede_pending_attempts`] consults to skip
    /// the no-op sweep. Armed only after the acknowledgment returns, it lags the durable
    /// `abandoned` set for the whole round trip -- and stays disarmed forever if the write
    /// fails -- so a resubmit that sweeps inside that window reads it disarmed, skips the
    /// sweep, and leaves the attempt pending: the partial receipt (and its `-32603`) the
    /// sweep exists to prevent.
    ///
    /// Arming first removes that disagreement; it does not close the window. Until the
    /// `Change::Abandon` write lands, the snapshot a sweep reads still lists the attempt as
    /// pending, so a resubmit inside the round trip supersedes nothing either way. What is
    /// pinned here is the flag's ordering, which is what the optimisation in
    /// `supersede_pending_attempts` reads. Nothing reaches that window today only because
    /// every shell resubmit path happens to sleep, compact or refresh credentials first,
    /// which is a property of four call sites, not an invariant.
    /// Arming first costs at most one `Change::Read` on a sweep that turns out to be a no-op.
    #[tokio::test]
    async fn abandon_arms_the_sweep_before_its_durable_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_owned();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (in_flight_tx, in_flight_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        // A persistence actor that holds the abandon's acknowledgment until the test releases it.
        let actor = tokio::spawn(async move {
            let mut in_flight = Some(in_flight_tx);
            let mut release = Some(release_rx);
            while let Some(message) = rx.recv().await {
                let PersistenceMsg::ExecutionState {
                    mutation,
                    respond_to,
                } = message
                else {
                    panic!("unexpected fixture message");
                };
                if matches!(mutation.change, Change::Abandon { .. }) {
                    if let Some(tx) = in_flight.take() {
                        let _ = tx.send(());
                    }
                    if let Some(rx) = release.take() {
                        let _ = rx.await;
                    }
                }
                let _ = respond_to.send(apply(&path, mutation).await);
            }
        });
        let session = uuid::Uuid::new_v4().to_string();
        let execution = Execution::open(
            &tx,
            &session,
            "abandon-race",
            "turn1",
            9,
            None,
            Some(9),
            TokenLimits::default(),
            None,
        )
        .await
        .unwrap();
        let attempt = uuid::Uuid::new_v4().to_string();
        execution
            .admit(RequestPurpose::Work, attempt.clone())
            .await
            .unwrap();

        let mut abandoning = ExecutionAdmission::abandon(execution.as_ref(), attempt.clone());
        tokio::select! {
            biased;
            _ = &mut abandoning => panic!("the fixture holds the acknowledgment; abandon cannot have returned"),
            _ = in_flight_rx => {}
        }
        assert!(
            execution
                .abandoned_attempts
                .load(std::sync::atomic::Ordering::Acquire),
            "the sweep must be armed while the abandon's round trip is still in flight"
        );
        let _ = release_tx.send(());
        abandoning.await.expect("the abandon is durable");
        execution.supersede_pending_attempts().await.unwrap();
        assert!(
            execution.snapshot().await.unwrap().pending.is_empty(),
            "the sweep still takes the abandoned attempt over"
        );
        execution.release(&session);
        drop(tx);
        actor.await.unwrap();
    }

    #[tokio::test]
    async fn goal_continuation_preserves_authority_and_bounded_edit_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, actor) = fixture_actor(dir.path().to_owned());
        let session = uuid::Uuid::new_v4().to_string();
        let first = Execution::open(&tx, &session, "goal", "turn1", 4, None, Some(2), TokenLimits::default(), None).await.unwrap();
        let attempt = uuid::Uuid::new_v4().to_string();
        first.admit(RequestPurpose::Work, attempt.clone()).await.unwrap();
        first.settle(attempt, Some(fuigo_sampling_types::TokenUsage::default())).await.unwrap();
        let next = Execution::open(&tx, &session, "goal", "turn2", 99, None, Some(99), TokenLimits::default(), None).await.unwrap();
        assert!(Arc::ptr_eq(&first, &next));
        assert!(Execution::for_prompt(&session, "turn1").is_none());
        assert!(Execution::for_prompt(&session, "turn2").is_some());
        let state = next.snapshot().await.unwrap();
        assert_eq!((state.calls, state.max_calls, state.max_tool_rounds), (1, 4, Some(2)));
        assert_eq!(state.phase, Phase::Working);
        next.record_edited_paths((0..130).map(|n| format!("src/{n:03}.rs")).collect()).await.unwrap();
        let receipt = next.terminal(true).await.unwrap();
        assert!(!receipt.partial);
        assert_eq!(receipt.known_session_edited_paths.len(), 128);
        assert_eq!(receipt.omitted_edited_paths, 2);
        assert!(receipt.completed_checks.starts_with("unknown"));
        next.record_edited_paths(BTreeSet::new()).await.unwrap();
        let repeated = next.terminal(false).await.unwrap();
        assert_eq!(serde_json::to_value(&receipt).unwrap(), serde_json::to_value(&repeated).unwrap());
        next.release(&session);
        drop(tx);
        actor.await.unwrap();
    }

    /// A foreground child inheriting `--max-turns N` gets N rounds of its own, and the parent
    /// keeps every one of ITS N: the child's actions are the parent's liabilities (pending until
    /// settled, `partial` on a receipt issued while they run) but never the parent's tool rounds.
    ///
    /// Before this pin, `Change::ChildTools` on a non-optional grant ran `Change::Tools` on the
    /// parent, so with N = 2 the parent's spawn round plus the child's first round exhausted the
    /// parent's mirror: the child's second round was denied ("execution actions unavailable" ->
    /// `-32603 Tool execution admission not durable or finalizing` on the child prompt) and the
    /// parent's next round was a finalize slot (`-32603` again). The full turn-loop shape is
    /// `tests/max_turns_foreground_child_acp.rs`; this is the same sequence at the records.
    #[tokio::test]
    async fn foreground_child_rounds_are_liabilities_not_parent_rounds() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, actor) = fixture_actor(dir.path().to_owned());
        let parent_session = uuid::Uuid::new_v4().to_string();
        let child_session = uuid::Uuid::new_v4().to_string();
        let parent = Execution::open(&tx, &parent_session, "parent-root", "parent-prompt", 99, None, Some(2), TokenLimits::default(), None).await.unwrap();
        // Round 1 of 2: the parent spawns the child. The spawn call stays pending until the
        // child returns, exactly as a blocking `spawn_subagent` does in the turn loop.
        parent.tools(vec!["spawn".into()]).await.unwrap();
        let grant = parent.grant_child("child", None, /* optional */ false).await.unwrap();
        let child = Execution::open(&tx, &child_session, "child-root", "child-prompt", 99, None, Some(2), TokenLimits::default(), Some(grant)).await.unwrap();

        for round in ["c1", "c2"] {
            child.tools(vec![round.into()]).await.unwrap_or_else(|e| {
                panic!("child round {round} is inside the child's own bound of 2 and must be admitted: {e}")
            });
            let mid = parent.snapshot().await.unwrap();
            assert!(
                mid.pending_tools.contains(&format!("child:{round}")),
                "a foreground child's action is pending on the parent while it runs: {:?}",
                mid.pending_tools
            );
            child.tools_settled(vec![round.into()]).await.unwrap();
        }
        assert!(
            child.tools(vec!["c3".into()]).await.is_err(),
            "the child's OWN record bounds it at 2 rounds"
        );

        let after_child = parent.snapshot().await.unwrap();
        assert_eq!(
            (after_child.tool_rounds, after_child.max_tool_rounds),
            (1, Some(2)),
            "the child's two rounds are not the parent's: the parent has spent one round (the spawn)"
        );
        assert!(
            after_child.pending_tools.iter().all(|id| id == "spawn"),
            "settled child actions, and the refused third one that never ran, are not parent \
             liabilities: {:?}",
            after_child.pending_tools
        );
        // Round 2 of 2 for the parent, after the child came back.
        parent.tools_settled(vec!["spawn".into()]).await.unwrap();
        parent.tools(vec!["second".into()]).await.expect("the parent's own second round");
        parent.tools_settled(vec!["second".into()]).await.unwrap();
        assert!(parent.tools(vec!["third".into()]).await.is_err(), "the parent's bound still holds");

        parent.release(&parent_session);
        child.release(&child_session);

        // The receipt contract is unchanged: a foreground child's action still pending when the
        // parent goes terminal makes the parent's receipt `partial`, with nothing of the
        // parent's own outstanding.
        let parent_session = uuid::Uuid::new_v4().to_string();
        let child_session = uuid::Uuid::new_v4().to_string();
        let parent = Execution::open(&tx, &parent_session, "parent-root", "parent-prompt", 99, None, Some(2), TokenLimits::default(), None).await.unwrap();
        parent.tools(vec!["spawn".into()]).await.unwrap();
        parent.tools_settled(vec!["spawn".into()]).await.unwrap();
        let grant = parent.grant_child("child", None, false).await.unwrap();
        let child = Execution::open(&tx, &child_session, "child-root", "child-prompt", 99, None, Some(2), TokenLimits::default(), Some(grant)).await.unwrap();
        child.tools(vec!["unsettled".into()]).await.unwrap();
        let receipt = parent.terminal(true).await.unwrap();
        assert!(receipt.partial, "an unsettled foreground child action is unresolved work");
        assert_eq!(receipt.pending_tool_calls, vec!["child:unsettled".to_string()]);
        parent.release(&parent_session);
        child.release(&child_session);
        drop(tx);
        actor.await.unwrap();
    }

    #[tokio::test]
    async fn a_resent_attempt_settles_while_an_abandoned_one_stays_unresolved() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, actor) = fixture_actor(dir.path().to_owned());
        let session = uuid::Uuid::new_v4().to_string();
        let limits = TokenLimits {
            total: Some(100_000),
            initial_total: 0,
            output: None,
        };
        let recovered = Execution::open(
            &tx,
            &session,
            "resent",
            "turn1",
            9,
            None,
            Some(9),
            limits.clone(),
            None,
        )
        .await
        .unwrap();
        let first = uuid::Uuid::new_v4().to_string();
        recovered
            .admit(RequestPurpose::Work, first.clone())
            .await
            .unwrap();
        ExecutionAdmission::supersede(recovered.as_ref(), first.clone(), None)
            .await
            .unwrap();
        assert!(
            recovered.snapshot().await.unwrap().pending.is_empty(),
            "the resend takes the failed attempt over"
        );
        let second = uuid::Uuid::new_v4().to_string();
        recovered
            .admit(RequestPurpose::Work, second.clone())
            .await
            .expect("a superseded attempt with no usage must not poison the token budget");
        recovered
            .settle(second, Some(fuigo_sampling_types::TokenUsage::default()))
            .await
            .unwrap();
        let state = recovered.snapshot().await.unwrap();
        assert!(state.pending.is_empty());
        assert_eq!(state.calls, 2, "both attempts keep their debit");
        let receipt = recovered.terminal(true).await.unwrap();
        assert!(
            !receipt.partial,
            "a turn its retry rescued is not partial: {receipt:?}"
        );
        recovered.release(&session);

        let abandoned = Execution::open(
            &tx,
            &session,
            "abandoned",
            "turn2",
            9,
            None,
            Some(9),
            limits,
            None,
        )
        .await
        .unwrap();
        let attempt = uuid::Uuid::new_v4().to_string();
        abandoned
            .admit(RequestPurpose::Work, attempt.clone())
            .await
            .unwrap();
        ExecutionAdmission::abandon(abandoned.as_ref(), attempt.clone())
            .await
            .unwrap();
        assert_eq!(
            abandoned.snapshot().await.unwrap().pending,
            BTreeSet::from([attempt.clone()]),
            "nothing has taken the attempt over yet"
        );
        abandoned.supersede_pending_attempts().await.unwrap();
        let state = abandoned.snapshot().await.unwrap();
        assert!(
            state.pending.is_empty() && state.abandoned.is_empty(),
            "the resubmit takes it over: {state:?}"
        );
        assert!(!abandoned.terminal(true).await.unwrap().partial);
        abandoned.release(&session);

        let stranded = Execution::open(
            &tx,
            &session,
            "stranded",
            "turn3",
            9,
            None,
            Some(9),
            TokenLimits::default(),
            None,
        )
        .await
        .unwrap();
        let attempt = uuid::Uuid::new_v4().to_string();
        stranded
            .admit(RequestPurpose::Work, attempt.clone())
            .await
            .unwrap();
        ExecutionAdmission::abandon(stranded.as_ref(), attempt)
            .await
            .unwrap();
        assert!(
            stranded.terminal(true).await.unwrap().partial,
            "an attempt no resubmit took over is still unresolved work"
        );
        stranded.release(&session);
        drop(tx);
        actor.await.unwrap();
    }

    #[tokio::test]
    async fn process_exit_recovers_pending_admission_and_terminal_identity() {
        const CHILD_DIR: &str = "FUIGO_E3_CRASH_FIXTURE_DIR";
        const CHILD_STAGE: &str = "FUIGO_E3_CRASH_FIXTURE_STAGE";
        const SESSION: &str = "e3-crash-session";
        const ROOT: &str = "e3-crash-goal";
        if let Some(dir) = std::env::var_os(CHILD_DIR) {
            let dir = std::path::PathBuf::from(dir);
            let (tx, _actor) = fixture_actor(dir.clone());
            let execution = Execution::open(&tx, SESSION, ROOT, "first", 3, None, Some(2), TokenLimits::default(), None).await.unwrap();
            execution.admit(RequestPurpose::Work, uuid::Uuid::new_v4().to_string()).await.unwrap();
            execution.tools(vec!["unsettled-action".into()]).await.unwrap();
            let stage = std::env::var(CHILD_STAGE).unwrap();
            if stage != "admitted" {
                let receipt = execution.terminal(false).await.unwrap();
                if stage == "delivered" {
                    // Scripted consumer receives the durable ID; no acknowledgment
                    // is made before process exit. This is not an ACP E2E claim.
                    crate::session::storage::write_bytes_atomic_async(
                        &dir.join("consumer-received.json"), serde_json::to_vec(&receipt).unwrap(),
                    ).await.unwrap();
                }
            }
            std::process::exit(0); // No actor drain or Rust destructor cleanup.
        }
        for stage in ["admitted", "terminal", "delivered"] {
            let dir = tempfile::tempdir().unwrap();
            let mut child = tokio::process::Command::new(std::env::current_exe().unwrap());
            child.arg("--exact")
                .arg("session::execution_state::tests::process_exit_recovers_pending_admission_and_terminal_identity")
                .env(CHILD_DIR, dir.path()).env(CHILD_STAGE, stage)
                .env_remove("FUIGO_MAX_MODEL_CALLS").env_remove("FUIGO_MAX_RUNTIME_SECS")
                .kill_on_drop(true);
            let result = tokio::time::timeout(std::time::Duration::from_secs(60), child.output()).await
                .expect("crash fixture child timed out").unwrap();
            assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
            let key = blake3::hash(format!("{SESSION}\0{ROOT}").as_bytes()).to_hex().to_string();
            let before = apply(dir.path(), mutation(&key, Change::Read)).await.unwrap();
            let (tx, actor) = fixture_actor(dir.path().to_owned());
            let restored = Execution::open(&tx, SESSION, ROOT, "resumed", 99, None, Some(99), TokenLimits::default(), None).await.unwrap();
            let state = restored.snapshot().await.unwrap();
            assert_eq!((state.calls, state.max_calls), (1, 3));
            assert_eq!(state.pending, before.pending);
            assert_eq!(state.pending_tools, before.pending_tools);
            assert!(restored.admit(RequestPurpose::Work, uuid::Uuid::new_v4().to_string()).await.is_err());
            assert!(restored.tools(vec!["stale-action".into()]).await.is_err());
            let receipt = restored.terminal(true).await.unwrap();
            assert!(receipt.partial, "unknown effects cannot become success on restart");
            if let Some(previous) = before.terminal {
                assert_eq!(serde_json::to_value(previous).unwrap(), serde_json::to_value(&receipt).unwrap());
            }
            if stage == "delivered" {
                let received: TerminalReceipt = serde_json::from_slice(&tokio::fs::read(dir.path().join("consumer-received.json")).await.unwrap()).unwrap();
                assert_eq!(received.id, receipt.id);
            }
            restored.release(SESSION);
            drop(tx);
            actor.await.unwrap();
        }
    }

    /// P89 (audit L-2). Under a process-wide call limit every open, non-terminal execution reserves
    /// one call for its final answer, and before P89 only `terminal()` gave it back. Two executions
    /// never get there: a session closed while its goal was still working, and a goal execution a
    /// later prompt of the same session displaced from the registry (also what an early `?` exit
    /// in the turn leaves behind). Each kept its slot forever, taking a call from every other
    /// session of a long-lived engine. Here the limit is 3 calls: the two stranded reservations
    /// plus the live one would leave nothing for a fourth session to work with.
    ///
    /// The process budget is a process-wide `OnceLock` read from the environment, so the scenario
    /// runs in a child process of this test binary with `FUIGO_MAX_MODEL_CALLS` set.
    #[tokio::test]
    async fn reservations_of_executions_that_never_reach_terminal_are_given_back() {
        const CHILD: &str = "FUIGO_P89_RESERVATION_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let budget = fuigo_sampler::execution_budget::process_budget()
                .unwrap()
                .expect("the child runs under a call limit");
            let dir = tempfile::tempdir().unwrap();
            // Session A: its goal is still working when the session closes.
            let (closed_tx, closed_actor) = fixture_actor(dir.path().to_owned());
            let stranded = Execution::open(&closed_tx, "p89-closed", "goal-a", "a-1", 3, None, None, TokenLimits::default(), None)
                .await
                .unwrap();
            drop(stranded);
            drop(closed_tx);
            closed_actor.await.unwrap();
            // Session B: a goal turn, then a plain prompt of the same session displaces it.
            let (tx, actor) = fixture_actor(dir.path().to_owned());
            let goal = Execution::open(&tx, "p89-live", "goal-b", "b-1", 3, None, None, TokenLimits::default(), None)
                .await
                .unwrap();
            drop(goal);
            let prompt = Execution::open(&tx, "p89-live", "prompt-b-2", "b-2", 3, None, None, TokenLimits::default(), None)
                .await
                .unwrap();
            assert!(
                !budget.working_capacity_exhausted(),
                "only the live execution may hold a reservation"
            );
            // A further session can still open and do work.
            let other = Execution::open(&tx, "p89-other", "prompt-c", "c-1", 3, None, None, TokenLimits::default(), None)
                .await
                .expect("a stranded reservation must not refuse another session");
            other
                .admit(RequestPurpose::Work, uuid::Uuid::new_v4().to_string())
                .await
                .expect("and that session can work");
            prompt.terminal(true).await.unwrap();
            other.terminal(true).await.unwrap();
            prompt.release("p89-live");
            other.release("p89-other");
            drop((prompt, other, tx));
            actor.await.unwrap();
            return;
        }
        let child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("session::execution_state::tests::reservations_of_executions_that_never_reach_terminal_are_given_back")
            .arg("--nocapture")
            .env(CHILD, "1")
            .env("FUIGO_MAX_MODEL_CALLS", "3")
            .env_remove("FUIGO_MAX_RUNTIME_SECS")
            .kill_on_drop(true)
            .output();
        let result = tokio::time::timeout(std::time::Duration::from_secs(120), child)
            .await
            .expect("reservation child timed out")
            .unwrap();
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            result.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    // ── P89: a goal's terminal record after an interrupted turn ─────────

    async fn goal_turn(
        tx: &mpsc::UnboundedSender<PersistenceMsg>,
        session: &str,
        goal: &str,
        prompt: &str,
        limits: TokenLimits,
    ) -> io::Result<Arc<Execution>> {
        Execution::open_goal(tx, session, goal, prompt, 9, None, Some(5), limits, None).await
    }

    /// The audit's H-2 reproduction, inverted. A goal turn that ended without unresolved work,
    /// interrupted (Esc, provider error, max-tokens cut, refusal) or even successfully while the goal
    /// paused itself, leaves the record terminal; the goal's next turn reopens it with its counters
    /// intact and the earlier receipt kept. Only a turn a limit stopped leaves it terminal.
    #[tokio::test]
    async fn an_interrupted_goal_turn_reopens_and_a_stopped_one_does_not() {
        for end in [TurnEnd::Interrupted, TurnEnd::Succeeded, TurnEnd::Stopped] {
            let dir = tempfile::tempdir().unwrap();
            let (tx, actor) = fixture_actor(dir.path().to_owned());
            let session = uuid::Uuid::new_v4().to_string();
            let first = goal_turn(&tx, &session, "goal", "turn-1", TokenLimits::default()).await.unwrap();
            let attempt = uuid::Uuid::new_v4().to_string();
            first.admit(RequestPurpose::Work, attempt.clone()).await.unwrap();
            first.settle(attempt, Some(fuigo_sampling_types::TokenUsage::default())).await.unwrap();
            first.tools(vec!["round-1".into()]).await.unwrap();
            first.tools_settled(vec!["round-1".into()]).await.unwrap();
            let receipt = first.terminal_after(end).await.unwrap();
            first.release(&session);
            drop(first);

            let next = goal_turn(&tx, &session, "goal", "turn-2", TokenLimits::default()).await;
            if end == TurnEnd::Stopped {
                let error = next.expect_err("a turn a limit stopped leaves the goal terminal");
                let ended = goal_ended_of(&error).expect("refused with the reason, not a storage error");
                assert!(ended.0.contains("/goal clear"), "{}", ended.0);
            } else {
                let next = next.unwrap_or_else(|e| panic!("{end:?}: the goal's next turn must reopen: {e}"));
                let state = next.snapshot().await.unwrap();
                assert_eq!(state.phase, Phase::Working, "{end:?}");
                assert!(state.terminal.is_none(), "{end:?}");
                assert_eq!(
                    (state.calls, state.max_calls, state.tool_rounds, state.max_tool_rounds),
                    (1, 9, 1, Some(5)),
                    "{end:?}: the goal's limits still bind across the reopen"
                );
                assert_eq!(state.reopened, 1);
                assert_eq!(state.earlier_receipts.len(), 1);
                assert_eq!(state.earlier_receipts[0].id, receipt.id, "the interrupted turn's receipt is kept");
                next.admit(RequestPurpose::Work, uuid::Uuid::new_v4().to_string())
                    .await
                    .unwrap_or_else(|e| panic!("{end:?}: the reopened goal must admit work: {e}"));
                let second = next.terminal_after(TurnEnd::Succeeded).await.unwrap();
                assert_ne!(second.id, receipt.id, "a reopened turn issues its own receipt");
                next.release(&session);
            }
            drop(tx);
            actor.await.unwrap();
        }
    }

    /// The registered instance path: the goal's next turn finds the very instance whose turn
    /// issued the receipt still in the registry (nothing released it), and must reopen it rather
    /// than adopt a terminal record.
    #[tokio::test]
    async fn a_still_registered_goal_execution_is_reopened_by_the_next_turn() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, actor) = fixture_actor(dir.path().to_owned());
        let session = uuid::Uuid::new_v4().to_string();
        let first = goal_turn(&tx, &session, "goal", "turn-1", TokenLimits::default()).await.unwrap();
        first.terminal_after(TurnEnd::Interrupted).await.unwrap();
        let next = goal_turn(&tx, &session, "goal", "turn-2", TokenLimits::default()).await.unwrap();
        assert!(Arc::ptr_eq(&first, &next), "the registered instance is adopted");
        assert_eq!(next.snapshot().await.unwrap().phase, Phase::Working);
        next.admit(RequestPurpose::Work, uuid::Uuid::new_v4().to_string()).await.unwrap();
        // A plain open (not a goal continuation) of a terminal record never reopens it.
        next.terminal_after(TurnEnd::Interrupted).await.unwrap();
        next.release(&session);
        let plain = Execution::open(&tx, &session, "goal", "turn-3", 9, None, Some(5), TokenLimits::default(), None)
            .await
            .unwrap();
        assert_eq!(plain.snapshot().await.unwrap().phase, Phase::Terminal);
        plain.release(&session);
        drop((first, next, plain, tx));
        actor.await.unwrap();
    }

    /// Esc mid-request and mid-tool: the turn ends with an attempt and a tool call unresolved. Their
    /// outcome is recorded on the kept receipt; the reopened record carries neither as live work
    /// (so it does not force a finalization), keeps their call debit, and never re-runs them.
    ///
    /// Under a token budget the in-flight attempt's usage is unknown. P121 (K8): it is charged a
    /// conservative estimate when the goal is reopened, so the budget stays enforced and the goal
    /// is never left unable to resume (P89 refused it for good, `TokenUsageUnknown`).
    #[tokio::test]
    async fn reopening_settles_the_interrupted_turns_liabilities_into_its_receipt() {
        // (total-token budget, output-token budget, the in-flight attempt is optional: a title)
        for (total, output, optional) in [
            (None, None, false),
            (Some(1_000_000), None, false),
            (None, Some(500_000), false),
            (None, None, true),
            (Some(1_000_000), None, true),
        ] {
            let budgeted = total.is_some() || output.is_some();
            let dir = tempfile::tempdir().unwrap();
            let (tx, actor) = fixture_actor(dir.path().to_owned());
            let session = uuid::Uuid::new_v4().to_string();
            let limits = TokenLimits { total, output, initial_total: 0 };
            let first = goal_turn(&tx, &session, "goal", "turn-1", limits.clone()).await.unwrap();
            let in_flight = uuid::Uuid::new_v4().to_string();
            let purpose = if optional { RequestPurpose::Title } else { RequestPurpose::Work };
            first.admit(purpose, in_flight.clone()).await.unwrap();
            first.tools(vec!["running-tool".into()]).await.unwrap();
            let receipt = first.terminal_after(TurnEnd::Interrupted).await.unwrap();
            assert!(receipt.partial);
            assert_eq!(receipt.pending_attempts, vec![in_flight.clone()]);
            assert_eq!(receipt.pending_tool_calls, vec!["running-tool".to_string()]);
            first.release(&session);
            drop(first);

            // The goal tracker counted 700 tokens, some streamed by the interrupted attempt.
            let observed = TokenLimits { initial_total: 700, ..limits };
            let next = goal_turn(&tx, &session, "goal", "turn-2", observed).await;
            if budgeted {
                // P121 (K8): the in-flight attempt's usage is unknown, so it is charged a
                // conservative estimate and the goal resumes. The refusal that used to latch here
                // could not be lifted by anything but a late settlement that never came.
                let next = next.expect("unknown in-flight usage is charged, never a permanent refusal");
                let state = next.snapshot().await.unwrap();
                assert_eq!(state.phase, Phase::Working, "{state:?}");
                assert!(!state.unknown_usage, "an estimate is charged instead: {state:?}");
                let (spent, limit) = match (total, output) {
                    (Some(limit), _) => (state.total_tokens, limit),
                    (None, Some(limit)) => (state.output_tokens, limit),
                    (None, None) => unreachable!("budgeted"),
                };
                assert!(spent > 0 && spent < limit, "a conservative charge below the limit: {state:?}");
                next.tools(vec!["next-tool".into()]).await.expect("the reopened goal may act");
                next.release(&session);
            } else {
                let next = next.unwrap();
                let state = next.snapshot().await.unwrap();
                assert_eq!(state.phase, Phase::Working, "no forced finalization: {state:?}");
                // An optional attempt (a title) may still come back and settle, so it stays.
                assert_eq!(state.pending.is_empty(), !optional, "{state:?}");
                assert!(state.pending_tools.is_empty() && state.abandoned.is_empty());
                assert_eq!(state.calls, 1, "the interrupted attempt keeps its debit");
                assert_eq!(state.total_tokens, 700, "the goal's own count is carried in");
                assert_eq!(state.earlier_receipts[0].pending_attempts, vec![in_flight]);
                next.tools(vec!["next-tool".into()]).await.expect("the reopened goal may act");
                next.release(&session);
            }
            drop(tx);
            actor.await.unwrap();
        }
    }

    /// P121 (K8). A resend that takes over an in-flight attempt of a token-budgeted terminal record
    /// without usage does not leave the goal unable to resume (P89 kept the refusal, Astra r3): the
    /// attempt is charged a conservative estimate, the usage is not marked unknown, and the record
    /// reopens. With usage the real figure is charged.
    #[test]
    fn a_resend_without_usage_is_charged_an_estimate_and_the_goal_resumes() {
        for with_usage in [false, true] {
            let mut state = budgeted_terminal_with_pending_attempt();
            let attempt = state.pending.iter().next().cloned().unwrap();
            let usage = with_usage.then(|| fuigo_sampling_types::TokenUsage { total_tokens: 30, ..Default::default() });
            transition(&mut state, Change::Supersede { attempt_id: attempt, usage }, 0).unwrap();
            assert!(state.pending.is_empty());
            assert!(!state.unknown_usage, "with_usage={with_usage}: an estimate, never unknown usage");
            assert!(may_reopen(&state, 0), "with_usage={with_usage}");
            if with_usage {
                assert_eq!(state.total_tokens, 30);
            } else {
                assert!(state.total_tokens > 0 && state.total_tokens < 1_000_000, "{}", state.total_tokens);
            }
            transition(&mut state, Change::Reopen { observed_total: 0 }, 0).unwrap();
            assert_eq!(state.phase, Phase::Working);
        }
    }

    /// P144. Only a turn the loop finalized ON A BUDGET ends as that budget's denial: not a recall
    /// finalization (recall finishing inside its own budget is an ordinary answer), not a record that is
    /// not finalizing, and not a finalization with no budget spent (crash recovery).
    #[test]
    fn only_a_budget_finalization_is_a_budget_denial() {
        let mut state = budgeted_terminal_with_pending_attempt();
        state.terminal = None;
        state.phase = Phase::Finalizing;
        state.max_calls = 2;
        state.calls = 1;
        let rule = |state: &Snapshot| budget_finalization_denial(state).map(|denial| denial.rule);
        assert_eq!(rule(&state), Some(ExecutionBudgetRule::ModelCallLimit), "{state:?}");
        state.recall_finalization = true;
        assert_eq!(rule(&state), None, "a recall finalization is not a budget's");
        state.recall_finalization = false;
        state.phase = Phase::Working;
        assert_eq!(rule(&state), None, "a record that is not finalizing");
        state.phase = Phase::Finalizing;
        state.max_calls = 9;
        state.calls = 0;
        assert_eq!(rule(&state), None, "a finalization with no budget spent");
        state.total_tokens = 1_000_000;
        assert_eq!(rule(&state), Some(ExecutionBudgetRule::TotalTokensExhausted));
    }

    /// P144 (Astra r3). The finalization's budget is judged at the moment given, not when the
    /// function happens to run: a call-limit answer that returned before the deadline keeps the
    /// call-limit rule even if the deadline has passed by the time it is reported.
    #[test]
    fn the_finalization_budget_is_judged_when_the_turn_returned() {
        let mut state = budgeted_terminal_with_pending_attempt();
        state.terminal = None;
        state.phase = Phase::Finalizing;
        state.max_calls = 2;
        state.calls = 1;
        let now = chrono::Utc::now().timestamp_millis();
        state.deadline_ms = Some(now - 1);
        let rule = |at: i64| budget_finalization_denial_at(&state, at).map(|denial| denial.rule);
        assert_eq!(rule(now - 2), Some(ExecutionBudgetRule::ModelCallLimit), "returned before the deadline");
        assert_eq!(rule(now - 1), Some(ExecutionBudgetRule::RuntimeLimit), "returned at the deadline");
    }

    fn budgeted_terminal_with_pending_attempt() -> Snapshot {
        let mut state = latch_fixture(LATCH_PENDING_TOOLS);
        state.pending_tools.clear();
        state.pending.clear();
        state.abandoned.clear();
        state.completion_admitted = false;
        state.calls = 1;
        state.max_calls = 9;
        state.tool_rounds = 0;
        state.deadline_ms = None;
        state.max_tool_rounds = None;
        state.limits = TokenLimits { total: Some(1_000_000), output: Some(500_000), initial_total: 0 };
        state.total_tokens = 0;
        state.output_tokens = 0;
        state.unknown_usage = false;
        state.reopenable = Some(true);
        let attempt = uuid::Uuid::new_v4().to_string();
        state.admitted.insert(attempt.clone());
        state.pending.insert(attempt);
        state
    }

    /// P121 (K8). The superseded attempt of a WORKING record that reports no usage is charged too
    /// (it was free, so a goal could spend past its budget through resends), but only under a token
    /// limit, only the limit it counts against, and never past what is left.
    #[test]
    fn a_superseded_attempt_without_usage_is_charged_under_a_token_limit_only() {
        for (total, output) in [(Some(1_000_000u64), None), (None, Some(500_000u64)), (None, None)] {
            let mut state = budgeted_terminal_with_pending_attempt();
            state.phase = Phase::Working;
            state.terminal = None;
            state.limits = TokenLimits { total, output, initial_total: 0 };
            let attempt = state.pending.iter().next().cloned().unwrap();
            transition(&mut state, Change::Supersede { attempt_id: attempt, usage: None }, 0).unwrap();
            assert!(!state.unknown_usage);
            assert_eq!(state.total_tokens > 0, total.is_some(), "total limit {total:?}");
            assert_eq!(state.output_tokens > 0, output.is_some(), "output limit {output:?}");
            assert!(state.total_tokens < total.unwrap_or(u64::MAX));
            assert!(state.output_tokens < output.unwrap_or(u64::MAX));
        }
    }

    /// P121 (K8). Interrupted turns that leave a request in flight are charged like any other usage:
    /// each resume is admitted while the budget lasts, and when estimates have spent it the goal
    /// stops with the budget's own typed denial (rule and remedy as data), never with the unknown
    /// usage that nobody can learn.
    #[test]
    fn repeated_interruptions_spend_the_budget_and_stop_with_its_own_denial() {
        let mut state = budgeted_terminal_with_pending_attempt();
        state.limits = TokenLimits { total: Some(50_000), output: Some(9_000), initial_total: 0 };
        state.max_calls = 1_000;
        let mut resumed = 0;
        let denial = loop {
            transition(&mut state, Change::Reopen { observed_total: 0 }, 0).unwrap();
            resumed += 1;
            assert!(resumed < 20, "estimates must spend the budget: {state:?}");
            let attempt = uuid::Uuid::new_v4().to_string();
            let admitted = transition(&mut state, Change::Admit { completion: false, optional: false, attempt_id: attempt }, 0);
            if let Err(error) = admitted {
                break budget_denial_of(&error).expect("the budget's own typed denial");
            }
            transition(&mut state, Change::TurnTerminal { end: TurnEnd::Interrupted }, 0).unwrap();
            if !may_reopen(&state, 0) {
                break match exhaustion(&state, 0) {
                    Some(Exhaustion::Budget(rule)) => budget_denial(&state, rule),
                    other => panic!("expected the budget's own denial, got {other:?}"),
                };
            }
        };
        assert_eq!(resumed, 3, "{state:?}");
        assert!(!state.unknown_usage && !denial.unknown_usage, "{denial:?}");
        assert!(
            matches!(denial.rule, ExecutionBudgetRule::TotalTokensExhausted | ExecutionBudgetRule::OutputTokensExhausted),
            "{denial:?}"
        );
    }

    /// P121 (K8). An unreported request is charged at least as much as the largest request this
    /// execution has seen report (a goal's context only grows), not a fixed guess: two interrupted
    /// requests on a 60,000-token context spend a 100,000-token budget instead of costing 32,768.
    #[test]
    fn an_unreported_request_costs_at_least_the_largest_request_seen() {
        let mut state = budgeted_terminal_with_pending_attempt();
        state.limits = TokenLimits { total: Some(100_000), output: None, initial_total: 0 };
        let second = uuid::Uuid::new_v4().to_string();
        state.admitted.insert(second.clone());
        state.pending.insert(second);
        let reported = uuid::Uuid::new_v4().to_string();
        state.admitted.insert(reported.clone());
        state.pending.insert(reported.clone());
        let usage = fuigo_sampling_types::TokenUsage { total_tokens: 60_000, ..Default::default() };
        transition(&mut state, Change::Settle { attempt_id: reported, usage: Some(usage) }, 0).unwrap();
        assert_eq!(state.total_tokens, 60_000);
        assert!(may_reopen(&state, 0), "60,000 of 100,000 is spent: the goal may resume");
        transition(&mut state, Change::Reopen { observed_total: 0 }, 0).unwrap();
        assert!(state.total_tokens >= 60_000 * 3, "each unreported request costs at least 60,000: {}", state.total_tokens);
        assert_eq!(
            token_budget_denial(&state).map(|denial| denial.rule),
            Some(ExecutionBudgetRule::TotalTokensExhausted),
            "the budget is spent, and says so"
        );
    }

    /// P121 (K8). With NO earlier request having reported usage, an unreported request is still
    /// charged at least its own input: the turn notes the request's context before sending it.
    /// Two interrupted requests on a 60,000-token conversation spend a 100,000-token budget.
    #[tokio::test]
    async fn an_interrupted_request_is_charged_at_least_its_own_input_with_no_history() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, actor) = fixture_actor(dir.path().to_owned());
        let session = uuid::Uuid::new_v4().to_string();
        let limits = TokenLimits { total: Some(100_000), output: None, initial_total: 0 };
        let mut resumes = 0;
        let denial = loop {
            let turn = match goal_turn(&tx, &session, "goal", &format!("turn-{resumes}"), limits.clone()).await {
                Ok(turn) => turn,
                Err(error) => break budget_denial_of(&error).expect("the budget's own denial"),
            };
            resumes += 1;
            assert!(resumes < 6, "the budget must be spent");
            turn.note_request_context(60_000);
            if turn.admit(RequestPurpose::Work, uuid::Uuid::new_v4().to_string()).await.is_err() {
                let state = turn.snapshot().await.unwrap();
                break token_budget_denial(&state).expect("the budget's own denial");
            }
            turn.terminal_after(TurnEnd::Interrupted).await.unwrap();
            turn.release(&session);
        };
        assert_eq!(resumes, 3, "two interrupted 60,000-token requests spend 100,000: the third turn is refused");
        assert_eq!(denial.rule, ExecutionBudgetRule::TotalTokensExhausted);
        drop(tx);
        actor.await.unwrap();
    }

    /// P121 (K8). A late report for an estimated request is remembered as the largest request too.
    #[test]
    fn a_late_report_raises_the_floor_for_later_estimates() {
        let mut state = budgeted_terminal_with_pending_attempt();
        state.limits = TokenLimits { total: Some(1_000_000), output: None, initial_total: 0 };
        let attempt = state.pending.iter().next().cloned().unwrap();
        transition(&mut state, Change::Reopen { observed_total: 0 }, 0).unwrap();
        let usage = fuigo_sampling_types::TokenUsage { total_tokens: 60_000, ..Default::default() };
        transition(&mut state, Change::Settle { attempt_id: attempt, usage: Some(usage) }, 0).unwrap();
        let next = uuid::Uuid::new_v4().to_string();
        transition(&mut state, Change::Admit { completion: false, optional: false, attempt_id: next.clone() }, 0).unwrap();
        let before = state.total_tokens;
        transition(&mut state, Change::Supersede { attempt_id: next, usage: None }, 0).unwrap();
        assert!(state.total_tokens - before >= 60_000, "{}", state.total_tokens - before);
    }

    /// P121 (K8). A turn rewound after its request was sent (no terminal receipt) settles the
    /// request: charged an estimate under a token limit, its call debit kept, an optional attempt
    /// (a title) left to settle on its own.
    #[test]
    fn a_rewound_turns_in_flight_request_is_charged_and_settled() {
        for limited in [true, false] {
            let mut state = budgeted_terminal_with_pending_attempt();
            state.phase = Phase::Working;
            state.terminal = None;
            if !limited {
                state.limits = TokenLimits::default();
            }
            let work = state.pending.iter().next().cloned().unwrap();
            let title = uuid::Uuid::new_v4().to_string();
            state.admitted.insert(title.clone());
            state.pending.insert(title.clone());
            state.optional_attempts.insert(title.clone());
            let calls = state.calls;
            transition(&mut state, Change::ChargeInFlight, 0).unwrap();
            assert!(!state.pending.contains(&work), "the request is settled");
            assert!(state.pending.contains(&title), "an optional attempt may still settle");
            assert_eq!(state.calls, calls, "its call debit stays");
            assert!(!state.unknown_usage);
            assert_eq!(state.total_tokens > 0, limited, "{state:?}");
            // However the goal continues, the request is already accounted for.
            transition(&mut state, Change::TurnTerminal { end: TurnEnd::Interrupted }, 0).unwrap();
            assert!(may_reopen(&state, 0));
        }
    }

    /// P121 (K8). A goal an earlier version latched on unknown usage (terminal, `unknown_usage`
    /// set, its attempt already taken over) resumes after the upgrade: reopening charges one
    /// estimate for it. A LIVE record still fails closed on unknown usage (Contract D.4).
    #[test]
    fn a_goal_latched_on_unknown_usage_by_an_earlier_version_resumes() {
        let mut state = budgeted_terminal_with_pending_attempt();
        state.pending.clear();
        state.unknown_usage = true;
        assert!(may_reopen(&state, 0), "a terminal record's unknown usage no longer blocks the resume");
        transition(&mut state, Change::Reopen { observed_total: 0 }, 0).unwrap();
        assert_eq!(state.phase, Phase::Working);
        assert!(!state.unknown_usage);
        assert!(state.total_tokens > 0, "charged an estimate for it");
        state.unknown_usage = true;
        assert_eq!(
            token_budget_denial(&state).map(|denial| denial.rule),
            Some(ExecutionBudgetRule::TokenUsageUnknown),
            "a live record still fails closed"
        );
    }

    /// P121 (K8). The same attempt is never charged twice (a reopen, then a resend), and late
    /// usage replaces a smaller estimate with the real figure and keeps a larger one.
    #[test]
    fn an_estimate_is_charged_once_and_late_usage_never_lowers_it() {
        for (actual, expect_actual) in [(100_000u64, true), (10, false)] {
            let mut state = budgeted_terminal_with_pending_attempt();
            state.limits = TokenLimits { total: Some(1_000_000), output: None, initial_total: 0 };
            let attempt = state.pending.iter().next().cloned().unwrap();
            transition(&mut state, Change::Reopen { observed_total: 0 }, 0).unwrap();
            let estimate = state.total_tokens;
            assert!(estimate > 0 && estimate < 100_000, "{estimate}");
            transition(&mut state, Change::Supersede { attempt_id: attempt.clone(), usage: None }, 0).unwrap();
            assert_eq!(state.total_tokens, estimate, "charged once");
            let usage = fuigo_sampling_types::TokenUsage { total_tokens: actual as _, ..Default::default() };
            transition(&mut state, Change::Settle { attempt_id: attempt, usage: Some(usage) }, 0).unwrap();
            assert_eq!(state.total_tokens, if expect_actual { actual } else { estimate });
            assert!(!state.unknown_usage);
        }
    }

    /// The reopen transition refuses by itself, typed, when a limit ran out after the caller's
    /// check (Astra r1 finding 3): the client still reads the limit, not a storage failure.
    #[test]
    fn a_reopen_the_record_refuses_is_refused_as_the_limit() {
        let mut state = latch_fixture(LATCH_PENDING_TOOLS);
        state.pending_tools.clear();
        state.pending.clear();
        state.abandoned.clear();
        state.completion_admitted = false;
        state.calls = 0;
        state.max_calls = 9;
        state.tool_rounds = 0;
        state.max_tool_rounds = None;
        state.limits = TokenLimits::default();
        state.unknown_usage = false;
        state.reopenable = Some(true);
        state.deadline_ms = Some(10);
        let error = transition(&mut state, Change::Reopen { observed_total: 0 }, 20).unwrap_err();
        assert_eq!(
            budget_denial_of(&error).map(|denial| denial.rule),
            Some(ExecutionBudgetRule::RuntimeLimit)
        );
        state.deadline_ms = None;
        state.reopenable = Some(false);
        let error = transition(&mut state, Change::Reopen { observed_total: 0 }, 20).unwrap_err();
        assert!(goal_ended_of(&error).is_some(), "a stopped turn's record is refused with its reason");
    }

    /// The counter-test: an interrupted turn on a goal whose budget is genuinely spent stays
    /// terminal, refused with the budget's own typed denial (rule and remedy as data).
    #[tokio::test]
    async fn a_spent_budget_stays_terminal_whatever_ended_the_turn() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, actor) = fixture_actor(dir.path().to_owned());
        let session = uuid::Uuid::new_v4().to_string();
        let limits = TokenLimits { total: Some(100), output: None, initial_total: 0 };
        let first = goal_turn(&tx, &session, "goal", "turn-1", limits.clone()).await.unwrap();
        let attempt = uuid::Uuid::new_v4().to_string();
        first.admit(RequestPurpose::Work, attempt.clone()).await.unwrap();
        first
            .settle(attempt, Some(fuigo_sampling_types::TokenUsage { total_tokens: 150, ..Default::default() }))
            .await
            .unwrap();
        first.terminal_after(TurnEnd::Interrupted).await.unwrap();
        first.release(&session);
        drop(first);
        let error = goal_turn(&tx, &session, "goal", "turn-2", limits).await.expect_err("spent stays spent");
        let denial = budget_denial_of(&error).expect("the typed budget denial");
        assert_eq!(denial.rule, ExecutionBudgetRule::TotalTokensExhausted);
        assert_eq!((denial.total_tokens_used, denial.total_token_limit), (150, Some(100)));
        let key = blake3::hash(format!("{session}\0goal").as_bytes()).to_hex().to_string();
        let state = apply(dir.path(), mutation(&key, Change::Read)).await.unwrap();
        assert_eq!(state.phase, Phase::Terminal, "the refused reopen left the record untouched");
        assert!(goal_end_reason(&state, 0).unwrap().contains("Remedy"));
        drop(tx);
        actor.await.unwrap();
    }

    /// Records written before P89 carry no `reopenable`. The clean-cancel latch the audit
    /// reproduced (terminal, nothing unresolved, no finalization spent) reopens; P03's
    /// crash-poisoned fixtures keep their liabilities and stay terminal.
    #[test]
    fn records_from_before_p89_reopen_only_when_nothing_was_left_unresolved() {
        for raw in [LATCH_PENDING_TOOLS, LATCH_STRANDED_ATTEMPT] {
            let state = latch_fixture(raw);
            assert_eq!(state.reopenable, None, "a pre-P89 record");
            assert!(!may_reopen(&state, 0), "a crash-poisoned record stays terminal");
            let mut state = state;
            assert!(transition(&mut state, Change::Reopen { observed_total: 0 }, 0).is_err());
            assert_eq!(state.phase, Phase::Terminal);
        }
        let mut clean = latch_fixture(LATCH_PENDING_TOOLS);
        clean.pending_tools.clear();
        clean.pending.clear();
        clean.abandoned.clear();
        clean.completion_admitted = false;
        clean.calls = 0;
        clean.max_calls = 9;
        clean.tool_rounds = 0;
        clean.deadline_ms = None;
        clean.max_tool_rounds = None;
        clean.limits = TokenLimits::default();
        clean.unknown_usage = false;
        // The shape the audit's probe produced: Terminal, partial, nothing outstanding.
        let raw = serde_json::to_value(&clean).unwrap();
        assert!(raw.get("reopenable").is_none(), "absent on the wire, as in an old file");
        assert!(may_reopen(&clean, 0));
        transition(&mut clean, Change::Reopen { observed_total: 0 }, 0).unwrap();
        assert_eq!(clean.phase, Phase::Working);
    }

    /// Turn ends at the transition level: the cause decides, and a finalization the turn loop
    /// entered on a limit is a stop even when the turn then "succeeded".
    #[test]
    fn the_receipt_records_whether_the_turn_or_the_execution_ended() {
        let open = || {
            let mut state = latch_fixture(LATCH_PENDING_TOOLS);
            state.phase = Phase::Working;
            state.terminal = None;
            state.pending_tools.clear();
            state.pending.clear();
            state.abandoned.clear();
            state.completion_admitted = false;
            state.calls = 0;
            state.tool_rounds = 0;
            state.deadline_ms = None;
            state.max_tool_rounds = None;
            state.limits = TokenLimits::default();
            state.unknown_usage = false;
            state.max_calls = 9;
            state
        };
        for (end, finalizing, recall, reopenable) in [
            (TurnEnd::Interrupted, false, false, true),
            (TurnEnd::Succeeded, false, false, true),
            (TurnEnd::Stopped, false, false, false),
            (TurnEnd::Succeeded, true, false, false),
            (TurnEnd::Interrupted, true, false, false),
            (TurnEnd::Succeeded, true, true, true),
        ] {
            let mut state = open();
            if finalizing {
                transition(&mut state, if recall { Change::FinalizeRecall } else { Change::Finalize }, 0).unwrap();
            }
            transition(&mut state, Change::TurnTerminal { end }, 0).unwrap();
            assert_eq!(state.reopenable, Some(reopenable), "{end:?} finalizing={finalizing} recall={recall}");
            assert_eq!(may_reopen(&state, 0), reopenable);
        }
        // The legacy entry point keeps its meaning: a non-success is a stop.
        let mut state = open();
        transition(&mut state, Change::Terminal { succeeded: false }, 0).unwrap();
        assert_eq!(state.reopenable, Some(false));
    }

    /// A limit that runs out AFTER the interrupted turn's receipt (the runtime deadline passes
    /// while the goal is paused), and a pre-P89 record whose budget is spent, both stay terminal:
    /// the reopen itself checks the record's limits, whatever the receipt said.
    #[test]
    fn a_limit_spent_after_the_receipt_still_keeps_the_record_terminal() {
        let clean = || {
            let mut state = latch_fixture(LATCH_PENDING_TOOLS);
            state.pending_tools.clear();
            state.pending.clear();
            state.abandoned.clear();
            state.completion_admitted = false;
            state.calls = 0;
            state.max_calls = 9;
            state.tool_rounds = 0;
            state.deadline_ms = None;
            state.max_tool_rounds = None;
            state.limits = TokenLimits::default();
            state.unknown_usage = false;
            state
        };
        let mut interrupted = clean();
        interrupted.reopenable = Some(true);
        assert!(may_reopen(&interrupted, 1_000));
        interrupted.deadline_ms = Some(500);
        assert!(!may_reopen(&interrupted, 1_000), "the deadline passed while the goal waited");
        assert!(goal_end_reason(&interrupted, 1_000).unwrap().contains(ExecutionBudgetRule::RuntimeLimit.id()));
        assert!(transition(&mut interrupted, Change::Reopen { observed_total: 0 }, 1_000).is_err());
        assert_eq!(interrupted.phase, Phase::Terminal);

        let mut legacy = clean();
        assert!(may_reopen(&legacy, 0), "precondition: a clean pre-P89 record reopens");
        legacy.calls = 8;
        assert!(!may_reopen(&legacy, 0), "its model calls are spent");
        let mut legacy = clean();
        legacy.limits.total = Some(100);
        legacy.total_tokens = 100;
        assert!(!may_reopen(&legacy, 0), "its token budget is spent");
        let mut legacy = clean();
        legacy.max_tool_rounds = Some(3);
        legacy.tool_rounds = 3;
        assert!(!may_reopen(&legacy, 0), "its `--max-turns` rounds are spent");
        assert!(goal_end_reason(&legacy, 0).unwrap().contains("--max-turns"));
    }

    /// P89 (L-2) at a tight limit, so each give-back is load-bearing. `FUIGO_MAX_MODEL_CALLS=2`:
    /// two closed sessions' reservations must be back BEFORE a new execution reserves (else it is
    /// refused); a goal displaced by a plain prompt of its own session must give its slot back
    /// before the prompt reserves; and a goal reopened after an interrupted turn must reserve its
    /// final answer again.
    #[tokio::test]
    async fn reservations_are_given_back_before_the_next_one_is_counted_and_retaken_on_reopen() {
        const CHILD: &str = "FUIGO_P89_TIGHT_RESERVATION_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let budget = fuigo_sampler::execution_budget::process_budget()
                .unwrap()
                .expect("the child runs under a call limit");
            let reserved_both = || budget.working_capacity_exhausted();
            let dir = tempfile::tempdir().unwrap();
            let open = |tx: &mpsc::UnboundedSender<PersistenceMsg>, session: &str, root: &str| {
                let tx = tx.clone();
                let (session, root) = (session.to_owned(), root.to_owned());
                async move { Execution::open(&tx, &session, &root, "p", 2, None, None, TokenLimits::default(), None).await }
            };
            // Two sessions close while their executions are still working.
            let (closed_a, actor_a) = fixture_actor(dir.path().to_owned());
            let (closed_b, actor_b) = fixture_actor(dir.path().to_owned());
            drop(open(&closed_a, "p89-closed-a", "goal").await.unwrap());
            drop(open(&closed_b, "p89-closed-b", "goal").await.unwrap());
            assert!(reserved_both(), "precondition: both slots are held");
            drop((closed_a, closed_b));
            actor_a.await.unwrap();
            actor_b.await.unwrap();

            let (tx, actor) = fixture_actor(dir.path().to_owned());
            let goal = Execution::open_goal(&tx, "p89-live", "goal", "g-1", 2, None, None, TokenLimits::default(), None)
                .await
                .expect("closed sessions' reservations are back before this one is counted");
            let other = open(&tx, "p89-other", "work").await.unwrap();
            assert!(reserved_both());
            drop(goal);
            let prompt = open(&tx, "p89-live", "prompt").await
                .expect("the displaced goal's reservation is back before the prompt's is counted");
            prompt.terminal(true).await.unwrap();
            other.terminal(true).await.unwrap();
            prompt.release("p89-live");
            other.release("p89-other");
            drop((prompt, other));
            assert!(!reserved_both());

            // Reopen re-reserves: interrupted (slot given back), reopened (slot retaken).
            let goal = Execution::open_goal(&tx, "p89-reopen", "goal", "r-1", 2, None, None, TokenLimits::default(), None)
                .await
                .unwrap();
            goal.terminal_after(TurnEnd::Interrupted).await.unwrap();
            let again = Execution::open_goal(&tx, "p89-reopen", "goal", "r-2", 2, None, None, TokenLimits::default(), None)
                .await
                .unwrap();
            assert!(Arc::ptr_eq(&goal, &again));
            let third = open(&tx, "p89-third", "work").await.unwrap();
            assert!(reserved_both(), "the reopened goal holds its final answer's slot again");
            again.terminal(true).await.unwrap();
            third.terminal(true).await.unwrap();
            again.release("p89-reopen");
            third.release("p89-third");
            assert!(!reserved_both());

            // Two instances of one key (Astra r1 finding 2): a displaced instance something still
            // references must not give back the slot its successor now holds.
            let displaced = open(&tx, "p89-overlap", "goal").await.unwrap();
            let prompt = open(&tx, "p89-overlap", "prompt").await.unwrap();
            let successor = open(&tx, "p89-overlap", "goal").await.unwrap();
            assert!(!Arc::ptr_eq(&displaced, &successor), "a second instance of the same key");
            assert!(reserved_both());
            drop(displaced);
            assert!(reserved_both(), "the successor still holds the key's slot");
            successor.terminal(true).await.unwrap();
            prompt.terminal(true).await.unwrap();
            successor.release("p89-overlap");
            drop((goal, again, third, prompt, successor, tx));
            actor.await.unwrap();
            assert!(!reserved_both());
            return;
        }
        let child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("session::execution_state::tests::reservations_are_given_back_before_the_next_one_is_counted_and_retaken_on_reopen")
            .arg("--nocapture")
            .env(CHILD, "1")
            .env("FUIGO_MAX_MODEL_CALLS", "2")
            .env_remove("FUIGO_MAX_RUNTIME_SECS")
            .kill_on_drop(true)
            .output();
        let result = tokio::time::timeout(std::time::Duration::from_secs(120), child)
            .await
            .expect("reservation child timed out")
            .unwrap();
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            result.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    // ── P03: the Terminal-with-unresolved-work latch ──────────────────
    //
    // Both fixtures are real crash-poisoned executions captured from a live machine and
    // sanitized: `known_session_edited_paths` is empty, `omitted_edited_paths` is 0,
    // `grants` holds only uuid-keyed counters, and `terminal.reason` is one of the two
    // fixed strings built in `Change::Terminal`. No prompt text and no filesystem path.

    /// Mode A: Terminal with a stranded tool call.
    const LATCH_PENDING_TOOLS: &str = include_str!("execution_latch_terminal_pending_tools.json");
    /// Mode B: Terminal with a stranded required attempt that is also `abandoned`.
    const LATCH_STRANDED_ATTEMPT: &str =
        include_str!("execution_latch_terminal_stranded_attempt.json");

    fn latch_fixture(raw: &str) -> Snapshot {
        serde_json::from_str(raw).expect("fixture deserializes as a Snapshot")
    }

    /// Invariant 4: the fixtures are baseline on-disk files and must keep loading.
    #[test]
    fn latch_fixtures_deserialize_at_version_1() {
        for raw in [LATCH_PENDING_TOOLS, LATCH_STRANDED_ATTEMPT] {
            let state = latch_fixture(raw);
            assert_eq!(state.version, 1);
            assert_eq!(state.phase, Phase::Terminal);
            assert!(state.terminal.is_some(), "a poisoned state has a receipt");
        }
    }

    /// Mode A is deliberately NOT changed by this packet, and this test pins that limit
    /// so nobody reads P03 as covering it.
    ///
    /// Mode A is Terminal with a stranded tool call and an EMPTY `abandoned` set. The
    /// sweep therefore never arms for it, so the over-arm this packet fixes does not
    /// apply. Whether mode A is latched at all by some other mechanism is UNVERIFIED —
    /// the brief asserted it, the reproduction it asked for was never obtained, and
    /// `Execution::open` does not error at Terminal in either mode. Reconciliation leaves
    /// mode A's record exactly as found.
    #[test]
    fn mode_a_has_no_armed_sweep_and_is_left_untouched() {
        let mut state = latch_fixture(LATCH_PENDING_TOOLS);
        assert_eq!(state.pending_tools.len(), 1, "fixture precondition");
        assert!(
            state.abandoned.is_empty(),
            "mode A's sweep never arms, which is why this packet does not reach it"
        );

        transition(&mut state, Change::Reconcile, 0).unwrap();

        assert_eq!(state.pending_tools.len(), 1, "the record is preserved");
        assert!(state.pending.is_empty(), "mode A had none to begin with");
    }

    /// Mode B. The stranded id is simultaneously `pending` and `abandoned`, which is what
    /// arms the sweep that then cannot act.
    #[test]
    fn reconcile_clears_a_stranded_attempt_and_disarms_the_sweep() {
        let mut state = latch_fixture(LATCH_STRANDED_ATTEMPT);
        assert_eq!(state.pending.len(), 1, "fixture precondition");
        assert_eq!(state.abandoned.len(), 1, "fixture precondition");
        let stranded = state.pending.iter().next().unwrap().clone();
        assert!(
            !state.optional_attempts.contains(&stranded),
            "the stranded attempt is required, not optional"
        );

        transition(&mut state, Change::Reconcile, 0).unwrap();

        assert!(state.abandoned.is_empty(), "the sweep must no longer arm");
        assert_eq!(
            state.pending.len(),
            1,
            "the recovered record of what was outstanding must survive; only the \
             sweep-arming set is cleared"
        );
    }

    /// Invariant 3. The receipt is the crash-boundary evidence. Reconciliation clears the
    /// liability, never the history -- the ids stay named in the receipt.
    #[test]
    fn reconcile_leaves_the_terminal_receipt_untouched() {
        for raw in [LATCH_PENDING_TOOLS, LATCH_STRANDED_ATTEMPT] {
            let mut state = latch_fixture(raw);
            let before = serde_json::to_string(&state.terminal).unwrap();

            transition(&mut state, Change::Reconcile, 0).unwrap();

            let after = serde_json::to_string(&state.terminal).unwrap();
            assert_eq!(before, after, "the issued receipt must be byte-identical");
            let receipt = state.terminal.as_ref().unwrap();
            assert!(receipt.partial, "the work really was lost");
            assert!(
                !receipt.pending_attempts.is_empty() || !receipt.pending_tool_calls.is_empty(),
                "the receipt still names what was stranded"
            );
        }
    }

    /// The property `process_exit_recovers_pending_admission_and_terminal_identity`
    /// pins, restated at the transition level. An earlier draft of this packet cleared
    /// `pending` and `pending_tools` too and broke that test. It was the draft that was
    /// wrong: at Terminal every transition is denied anyway, so clearing them changed no
    /// behaviour while destroying the recovered record of what was outstanding.
    #[test]
    fn reconcile_preserves_the_recovered_pending_record() {
        for raw in [LATCH_PENDING_TOOLS, LATCH_STRANDED_ATTEMPT] {
            let mut state = latch_fixture(raw);
            let pending_before = state.pending.clone();
            let tools_before = state.pending_tools.clone();

            transition(&mut state, Change::Reconcile, 0).unwrap();

            assert_eq!(state.pending, pending_before);
            assert_eq!(state.pending_tools, tools_before);
        }
    }

    /// Invariants 1, 2 and 5. Reconciliation must not reopen anything: the phase stays
    /// Terminal and every transition that was denied before is still denied. A fix that
    /// made `/goal` work by re-running lost work would be wrong by construction.
    #[tokio::test]
    async fn reconcile_never_reopens_the_execution() {
        let mut state = latch_fixture(LATCH_STRANDED_ATTEMPT);
        transition(&mut state, Change::Reconcile, 0).unwrap();

        assert_eq!(state.phase, Phase::Terminal, "phase is monotone toward Terminal");

        // Finalize is still refused, so a caller cannot double-finalize.
        assert!(transition(&mut state, Change::Finalize, 0).is_err());
        // Tools are still refused.
        assert!(
            transition(&mut state, Change::Tools { ids: vec!["t".into()] }, 0).is_err()
        );
        // A non-background admission is still refused.
        assert!(
            transition(
                &mut state,
                Change::Admit {
                    completion: false,
                    optional: false,
                    attempt_id: uuid::Uuid::new_v4().to_string(),
                },
                0,
            )
            .is_err()
        );
        assert_eq!(state.phase, Phase::Terminal);
    }

    /// Reconciliation is for crash-poisoned Terminal states only. Clearing the liability
    /// sets of a live execution would be discarding work in flight.
    #[test]
    fn reconcile_refuses_outside_terminal() {
        let mut state = latch_fixture(LATCH_PENDING_TOOLS);
        for phase in [Phase::Working, Phase::Finalizing] {
            state.phase = phase;
            assert!(
                transition(&mut state, Change::Reconcile, 0).is_err(),
                "reconcile must refuse at {phase:?}"
            );
        }
    }

    fn mutation(key: &str, change: Change) -> ExecutionMutation {
        ExecutionMutation {
            key: key.into(),
            change,
        }
    }
    fn key() -> String {
        blake3::hash(b"fixture execution").to_hex().to_string()
    }

    #[tokio::test]
    async fn child_grants_share_parent_cap_and_resume_without_reset() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = key();
        apply(
            dir.path(),
            mutation(
                &key,
                Change::Open {
                    max_calls: 4,
                    deadline_ms: None,
                    max_tool_rounds: None,
                    limits: TokenLimits::default(),
                },
            ),
        )
        .await
        .unwrap();
        let a = uuid::Uuid::new_v4().to_string();
        let b = uuid::Uuid::new_v4().to_string();
        for id in [&a, &b] {
            apply(
                dir.path(),
                mutation(
                    &key,
                    Change::Grant {
                        child_id: id.clone(),
                        resume_from: None,
                        optional: false,
                    },
                ),
            )
            .await
            .unwrap();
        }
        let first = uuid::Uuid::new_v4().to_string();
        apply(
            dir.path(),
            mutation(
                &key,
                Change::ChildAdmit {
                    grant_id: a.clone(),
                    attempt_id: first.clone(),
                },
            ),
        )
        .await
        .unwrap();
        let resumed = uuid::Uuid::new_v4().to_string();
        let state = apply(
            dir.path(),
            mutation(
                &key,
                Change::Grant {
                    child_id: resumed.clone(),
                    resume_from: Some(a.clone()),
                    optional: true,
                },
            ),
        )
        .await
        .unwrap();
        assert_eq!(state.child_aliases[&resumed], a);
        assert_eq!(state.grants[&a].calls, 1);
        assert!(
            !state.grants[&a].optional,
            "resume cannot downgrade requiredness"
        );
        assert!(
            state.pending.contains(&first),
            "unknown debit survives resume"
        );
        for id in [&a, &b] {
            apply(
                dir.path(),
                mutation(
                    &key,
                    Change::ChildAdmit {
                        grant_id: id.clone(),
                        attempt_id: uuid::Uuid::new_v4().to_string(),
                    },
                ),
            )
            .await
            .unwrap();
        }
        assert!(
            apply(
                dir.path(),
                mutation(
                    &key,
                    Change::ChildAdmit {
                        grant_id: a,
                        attempt_id: uuid::Uuid::new_v4().to_string()
                    }
                )
            )
            .await
            .is_err()
        );
        apply(dir.path(), mutation(&key, Change::Finalize))
            .await
            .unwrap();
        assert!(
            apply(
                dir.path(),
                mutation(
                    &key,
                    Change::ChildTools {
                        grant_id: b,
                        ids: vec!["late-action".into()]
                    }
                )
            )
            .await
            .is_err()
        );
        assert_eq!(
            apply(
                dir.path(),
                mutation(
                    &key,
                    Change::Admit {
                        completion: true,
                        optional: false,
                        attempt_id: uuid::Uuid::new_v4().to_string()
                    }
                )
            )
            .await
            .unwrap()
            .calls,
            4
        );
    }

    #[tokio::test]
    async fn background_child_liability_is_reported_without_failing_parent() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = key();
        apply(
            dir.path(),
            mutation(
                &key,
                Change::Open {
                    max_calls: 4,
                    deadline_ms: None,
                    max_tool_rounds: None,
                    limits: TokenLimits::default(),
                },
            ),
        )
        .await
        .unwrap();
        let child = uuid::Uuid::new_v4().to_string();
        apply(
            dir.path(),
            mutation(
                &key,
                Change::Grant {
                    child_id: child.clone(),
                    resume_from: None,
                    optional: true,
                },
            ),
        )
        .await
        .unwrap();
        let attempt = uuid::Uuid::new_v4().to_string();
        apply(
            dir.path(),
            mutation(
                &key,
                Change::ChildAdmit {
                    grant_id: child.clone(),
                    attempt_id: attempt.clone(),
                },
            ),
        )
        .await
        .unwrap();
        apply(
            dir.path(),
            mutation(
                &key,
                Change::ChildTools {
                    grant_id: child,
                    ids: vec!["background-action".into()],
                },
            ),
        )
        .await
        .unwrap();
        let receipt = apply(
            dir.path(),
            mutation(&key, Change::Terminal { succeeded: true }),
        )
        .await
        .unwrap()
        .terminal
        .unwrap();
        assert!(!receipt.partial);
        assert_eq!(receipt.optional_pending_attempts, vec![attempt]);
    }

    #[tokio::test]
    async fn foreign_resume_grant_is_rejected_without_new_allowance() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = key();
        apply(
            dir.path(),
            mutation(
                &key,
                Change::Open {
                    max_calls: 4,
                    deadline_ms: None,
                    max_tool_rounds: None,
                    limits: TokenLimits::default(),
                },
            ),
        )
        .await
        .unwrap();
        assert!(
            apply(
                dir.path(),
                mutation(
                    &key,
                    Change::Grant {
                        child_id: uuid::Uuid::new_v4().to_string(),
                        resume_from: Some(uuid::Uuid::new_v4().to_string()),
                        optional: false
                    }
                )
            )
            .await
            .is_err()
        );
        assert!(
            apply(dir.path(), mutation(&key, Change::Read))
                .await
                .unwrap()
                .grants
                .is_empty()
        );
    }

    #[tokio::test]
    async fn execution_debit_survives_reload_and_blocks_blind_replay() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = key();
        let initial = apply(
            dir.path(),
            mutation(
                &key,
                Change::Open {
                    max_calls: 3,
                    deadline_ms: None,
                    max_tool_rounds: None,
                    limits: TokenLimits::default(),
                },
            ),
        )
        .await
        .unwrap();
        let attempt = uuid::Uuid::new_v4().to_string();
        apply(
            dir.path(),
            mutation(
                &key,
                Change::Admit {
                    completion: false,
                    optional: false,
                    attempt_id: attempt.clone(),
                },
            ),
        )
        .await
        .unwrap();
        let reloaded = apply(
            dir.path(),
            mutation(
                &key,
                Change::Open {
                    max_calls: 100,
                    deadline_ms: None,
                    max_tool_rounds: None,
                    limits: TokenLimits::default(),
                },
            ),
        )
        .await
        .unwrap();
        assert_eq!(reloaded.execution_id, initial.execution_id);
        assert_eq!(reloaded.calls, 1);
        assert_eq!(reloaded.max_calls, 3);
        assert!(reloaded.pending.contains(&attempt));
        assert!(
            apply(
                dir.path(),
                mutation(
                    &key,
                    Change::Admit {
                        completion: false,
                        optional: false,
                        attempt_id: attempt.clone()
                    }
                )
            )
            .await
            .is_err()
        );
        apply(
            dir.path(),
            mutation(
                &key,
                Change::Settle {
                    attempt_id: attempt.clone(),
                    usage: Some(fuigo_sampling_types::TokenUsage {
                        total_tokens: 12,
                        completion_tokens: 4,
                        ..Default::default()
                    }),
                },
            ),
        )
        .await
        .unwrap();
        let settled = apply(
            dir.path(),
            mutation(
                &key,
                Change::Settle {
                    attempt_id: attempt,
                    usage: None,
                },
            ),
        )
        .await
        .unwrap();
        assert_eq!(settled.calls, 1);
        assert!(settled.pending.is_empty());
        assert_eq!(settled.total_tokens, 12);
        assert_eq!(settled.output_tokens, 4);
        assert!(!settled.unknown_usage);
    }

    #[tokio::test]
    async fn execution_reserves_completion_and_persists_one_terminal_identity() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = key();
        apply(
            dir.path(),
            mutation(
                &key,
                Change::Open {
                    max_calls: 1,
                    deadline_ms: None,
                    max_tool_rounds: None,
                    limits: TokenLimits::default(),
                },
            ),
        )
        .await
        .unwrap();
        assert!(
            apply(
                dir.path(),
                mutation(
                    &key,
                    Change::Admit {
                        completion: false,
                        optional: false,
                        attempt_id: uuid::Uuid::new_v4().to_string()
                    }
                )
            )
            .await
            .is_err()
        );
        apply(dir.path(), mutation(&key, Change::Finalize))
            .await
            .unwrap();
        let attempt = uuid::Uuid::new_v4().to_string();
        apply(
            dir.path(),
            mutation(
                &key,
                Change::Admit {
                    completion: true,
                    optional: false,
                    attempt_id: attempt.clone(),
                },
            ),
        )
        .await
        .unwrap();
        // Crash/cancel after debit and before settlement retains unknown work.
        let first = apply(
            dir.path(),
            mutation(&key, Change::Terminal { succeeded: false }),
        )
        .await
        .unwrap()
        .terminal
        .unwrap();
        let second = apply(
            dir.path(),
            mutation(&key, Change::Terminal { succeeded: true }),
        )
        .await
        .unwrap()
        .terminal
        .unwrap();
        assert_eq!(first.id, second.id);
        assert!(second.partial);
        assert_eq!(second.pending_attempts, vec![attempt]);
        assert!(
            apply(
                dir.path(),
                mutation(
                    &key,
                    Change::Admit {
                        completion: true,
                        optional: false,
                        attempt_id: uuid::Uuid::new_v4().to_string()
                    }
                )
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn execution_write_failure_never_returns_admission_success() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = key();
        let path = dir.path().join(format!("execution-{key}.json"));
        std::fs::create_dir(&path).unwrap();
        assert!(
            apply(
                dir.path(),
                mutation(
                    &key,
                    Change::Open {
                        max_calls: 3,
                        deadline_ms: None,
                        max_tool_rounds: None,
                        limits: TokenLimits::default()
                    }
                )
            )
            .await
            .is_err()
        );
        assert!(path.is_dir());
    }

    #[tokio::test]
    async fn execution_scopes_and_deadlines_remain_distinct() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = key();
        let b = blake3::hash(b"other session execution")
            .to_hex()
            .to_string();
        apply(
            dir.path(),
            mutation(
                &a,
                Change::Open {
                    max_calls: 2,
                    deadline_ms: Some(0),
                    max_tool_rounds: None,
                    limits: TokenLimits::default(),
                },
            ),
        )
        .await
        .unwrap();
        apply(
            dir.path(),
            mutation(
                &b,
                Change::Open {
                    max_calls: 2,
                    deadline_ms: None,
                    max_tool_rounds: None,
                    limits: TokenLimits::default(),
                },
            ),
        )
        .await
        .unwrap();
        assert!(
            apply(
                dir.path(),
                mutation(
                    &a,
                    Change::Admit {
                        completion: false,
                        optional: false,
                        attempt_id: uuid::Uuid::new_v4().to_string()
                    }
                )
            )
            .await
            .is_err()
        );
        assert_eq!(
            apply(
                dir.path(),
                mutation(
                    &b,
                    Change::Admit {
                        completion: false,
                        optional: false,
                        attempt_id: uuid::Uuid::new_v4().to_string()
                    }
                )
            )
            .await
            .unwrap()
            .calls,
            1
        );
        assert_eq!(
            apply(dir.path(), mutation(&a, Change::Read))
                .await
                .unwrap()
                .calls,
            0
        );
    }

    #[tokio::test]
    async fn optional_title_liability_does_not_fail_completed_work() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = key();
        apply(
            dir.path(),
            mutation(
                &key,
                Change::Open {
                    max_calls: 3,
                    deadline_ms: None,
                    max_tool_rounds: Some(1),
                    limits: TokenLimits::default(),
                },
            ),
        )
        .await
        .unwrap();
        let attempt = uuid::Uuid::new_v4().to_string();
        apply(
            dir.path(),
            mutation(
                &key,
                Change::Admit {
                    completion: false,
                    optional: true,
                    attempt_id: attempt.clone(),
                },
            ),
        )
        .await
        .unwrap();
        let receipt = apply(
            dir.path(),
            mutation(&key, Change::Terminal { succeeded: true }),
        )
        .await
        .unwrap()
        .terminal
        .unwrap();
        assert!(!receipt.partial);
        assert_eq!(receipt.optional_pending_attempts, vec![attempt]);
    }

    #[tokio::test]
    async fn tool_debits_and_pending_ids_survive_reload_and_finalization_blocks_actions() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = key();
        apply(
            dir.path(),
            mutation(
                &key,
                Change::Open {
                    max_calls: 4,
                    deadline_ms: None,
                    max_tool_rounds: Some(1),
                    limits: TokenLimits::default(),
                },
            ),
        )
        .await
        .unwrap();
        apply(
            dir.path(),
            mutation(
                &key,
                Change::Tools {
                    ids: vec!["call-1".into()],
                },
            ),
        )
        .await
        .unwrap();
        let state = apply(dir.path(), mutation(&key, Change::Read))
            .await
            .unwrap();
        assert_eq!(state.tool_rounds, 1);
        assert!(state.pending_tools.contains("call-1"));
        apply(dir.path(), mutation(&key, Change::Finalize))
            .await
            .unwrap();
        assert!(
            apply(
                dir.path(),
                mutation(
                    &key,
                    Change::Tools {
                        ids: vec!["call-2".into()]
                    }
                )
            )
            .await
            .is_err()
        );
    }


    fn usage(total: u32, output: u32) -> fuigo_sampling_types::TokenUsage {
        fuigo_sampling_types::TokenUsage {
            total_tokens: total,
            completion_tokens: output,
            ..Default::default()
        }
    }

    fn admit_work(state: &mut Snapshot) -> io::Result<String> {
        let attempt = uuid::Uuid::new_v4().to_string();
        transition(state, Change::Admit { completion: false, optional: false, attempt_id: attempt.clone() }, 0)?;
        Ok(attempt)
    }

    /// Contract D.4: each clause of the token-budget guard refuses with a TYPED denial naming its
    /// own rule, in the guard's own order, and every other refusal stays a plain message.
    ///
    /// Before P02e the three clauses shared one string ("execution token budget exhausted or
    /// unknown"), so nothing past this function could tell a budget denial from a durable-write
    /// failure, let alone which budget.
    #[tokio::test]
    async fn every_token_budget_clause_refuses_with_its_own_typed_rule() {
        let open = |limits: TokenLimits| async move {
            let dir = tempfile::tempdir().unwrap();
            let state = apply(dir.path(), mutation(&key(), Change::Open {
                max_calls: 9, deadline_ms: None, max_tool_rounds: None, limits,
            })).await.unwrap();
            (dir, state)
        };
        // Total budget spent.
        let (_dir, mut state) = open(TokenLimits { total: Some(100), output: Some(1_000), initial_total: 0 }).await;
        let attempt = admit_work(&mut state).unwrap();
        transition(&mut state, Change::Settle { attempt_id: attempt, usage: Some(usage(100, 10)) }, 0).unwrap();
        let denial = budget_denial_of(&admit_work(&mut state).unwrap_err()).expect("typed");
        assert_eq!(denial.rule, ExecutionBudgetRule::TotalTokensExhausted);
        assert_eq!((denial.total_token_limit, denial.total_tokens_used), (Some(100), 100));
        assert_eq!(state.calls, 1, "a refused admission debits nothing");

        // Output budget spent; the total budget still has room.
        let (_dir, mut state) = open(TokenLimits { total: Some(1_000), output: Some(40), initial_total: 0 }).await;
        let attempt = admit_work(&mut state).unwrap();
        transition(&mut state, Change::Settle { attempt_id: attempt, usage: Some(usage(50, 40)) }, 0).unwrap();
        let denial = budget_denial_of(&admit_work(&mut state).unwrap_err()).expect("typed");
        assert_eq!(denial.rule, ExecutionBudgetRule::OutputTokensExhausted);
        assert_eq!((denial.output_token_limit, denial.output_tokens_used), (Some(40), 40));

        // Usage unknown under a token budget: fails CLOSED with room left on both limits.
        let (_dir, mut state) = open(TokenLimits { total: Some(1_000_000), output: None, initial_total: 0 }).await;
        let attempt = admit_work(&mut state).unwrap();
        transition(&mut state, Change::Settle { attempt_id: attempt, usage: None }, 0).unwrap();
        let denial = budget_denial_of(&admit_work(&mut state).unwrap_err()).expect("typed");
        assert_eq!(denial.rule, ExecutionBudgetRule::TokenUsageUnknown);
        assert!(denial.unknown_usage);
        // ...and a completion admission is refused by the same guard, before its own checks.
        transition(&mut state, Change::Finalize, 0).unwrap();
        let completion = transition(&mut state, Change::Admit {
            completion: true, optional: false, attempt_id: uuid::Uuid::new_v4().to_string(),
        }, 0).unwrap_err();
        assert_eq!(budget_denial_of(&completion).map(|d| d.rule), Some(ExecutionBudgetRule::TokenUsageUnknown));

        // Order: total before output before unknown, the order the guard always checked them in.
        let (_dir, mut state) = open(TokenLimits { total: Some(10), output: Some(10), initial_total: 0 }).await;
        let attempt = admit_work(&mut state).unwrap();
        transition(&mut state, Change::Settle { attempt_id: attempt, usage: Some(usage(10, 10)) }, 0).unwrap();
        state.unknown_usage = true;
        assert_eq!(
            budget_denial_of(&admit_work(&mut state).unwrap_err()).map(|d| d.rule),
            Some(ExecutionBudgetRule::TotalTokensExhausted)
        );

        // No token budget: unknown usage refuses nothing, and a call-count refusal is not a TOKEN
        // denial (since P44 it is the model-call limit's own; `every_limit_clause_...` pins that).
        let (_dir, mut state) = open(TokenLimits::default()).await;
        state.unknown_usage = true;
        admit_work(&mut state).expect("no token budget, nothing to fail closed on");
        state.calls = state.max_calls - 1;
        let reserved = admit_work(&mut state).unwrap_err();
        assert_eq!(budget_denial_of(&reserved).map(|d| d.rule), Some(ExecutionBudgetRule::ModelCallLimit));
        assert!(token_budget_denial(&state).is_none());
    }

    /// P44: the deadline and call-count clauses of the admission refuse with the typed denial of their
    /// limit (`RuntimeLimit`, `ModelCallLimit`), in the admission's own order, while every phase and
    /// protocol clause stays a plain message -- the same refusals as before, only the budget ones typed.
    #[tokio::test]
    async fn every_limit_clause_refuses_with_its_own_typed_rule() {
        let open = |max_calls: u64, deadline_ms: Option<i64>| async move {
            let dir = tempfile::tempdir().unwrap();
            let state = apply(dir.path(), mutation(&key(), Change::Open {
                max_calls, deadline_ms, max_tool_rounds: None, limits: TokenLimits::default(),
            })).await.unwrap();
            (dir, state)
        };
        let admit = |state: &mut Snapshot, completion: bool, now_ms: i64| {
            transition(state, Change::Admit {
                completion, optional: false, attempt_id: uuid::Uuid::new_v4().to_string(),
            }, now_ms)
        };
        let rule_of = |error: io::Error| budget_denial_of(&error).map(|d| d.rule).ok_or(error.to_string());

        // Deadline: refused at and after it, as the runtime limit; admitted just before.
        let (_dir, mut state) = open(9, Some(1_000)).await;
        admit(&mut state, false, 999).expect("before the deadline");
        assert_eq!(rule_of(admit(&mut state, false, 1_000).unwrap_err()), Ok(ExecutionBudgetRule::RuntimeLimit));
        assert_eq!(state.calls, 1, "a refused admission debits nothing");
        // ...and before the token guard, which it always preceded.
        state.limits.total = Some(0);
        assert_eq!(rule_of(admit(&mut state, false, 1_000).unwrap_err()), Ok(ExecutionBudgetRule::RuntimeLimit));
        state.limits.total = None;
        // A terminal execution is not a limit: it stays the plain refusal, deadline or not.
        transition(&mut state, Change::Terminal { succeeded: true }, 0).unwrap();
        assert_eq!(rule_of(admit(&mut state, false, 1_000).unwrap_err()), Err("execution is terminal or expired".into()));

        // Work: the last call is reserved for the final answer, so work is refused one call early.
        let (_dir, mut state) = open(3, None).await;
        admit(&mut state, false, 0).unwrap();
        admit(&mut state, false, 0).unwrap();
        assert_eq!(rule_of(admit(&mut state, false, 0).unwrap_err()), Ok(ExecutionBudgetRule::ModelCallLimit));
        // A completion before finalizing is a protocol refusal, not a limit.
        assert_eq!(rule_of(admit(&mut state, true, 0).unwrap_err()), Err("completion admission unavailable".into()));
        // Finalizing: work is refused for the phase (plain), the final answer is admitted.
        transition(&mut state, Change::Finalize, 0).unwrap();
        state.calls = 0;
        assert_eq!(rule_of(admit(&mut state, false, 0).unwrap_err()), Err("execution completion capacity reserved".into()));
        state.calls = 2;
        admit(&mut state, true, 0).expect("the reserved final call");
        // A second completion is a protocol refusal even with calls to spare...
        state.max_calls = 9;
        assert_eq!(rule_of(admit(&mut state, true, 0).unwrap_err()), Err("completion admission unavailable".into()));
        // ...and a completion with every call spent is the limit.
        state.completion_admitted = false;
        state.calls = state.max_calls;
        assert_eq!(rule_of(admit(&mut state, true, 0).unwrap_err()), Ok(ExecutionBudgetRule::ModelCallLimit));

        // A child's grant is its share of the parent's call limit.
        let (_dir, mut state) = open(3, None).await;
        transition(&mut state, Change::Grant { child_id: "child".into(), resume_from: None, optional: false }, 0).unwrap();
        let child_call = || Change::ChildAdmit { grant_id: "child".into(), attempt_id: uuid::Uuid::new_v4().to_string() };
        transition(&mut state, child_call(), 0).unwrap();
        transition(&mut state, child_call(), 0).unwrap();
        assert_eq!(rule_of(transition(&mut state, child_call(), 0).unwrap_err()), Ok(ExecutionBudgetRule::ModelCallLimit));

        // An execution opened with no call left (`remaining_calls() == Some(0)`) is the limit too.
        let dir = tempfile::tempdir().unwrap();
        let refused = apply(dir.path(), mutation(&key(), Change::Open {
            max_calls: 0, deadline_ms: None, max_tool_rounds: None,
            limits: TokenLimits { total: Some(50), output: None, initial_total: 7 },
        })).await.unwrap_err();
        let denial = budget_denial_of(&refused).expect("typed");
        assert_eq!(denial.rule, ExecutionBudgetRule::ModelCallLimit);
        assert_eq!((denial.total_token_limit, denial.total_tokens_used), (Some(50), 7));
    }

    /// P44: the sampler's process-wide refusals are recognized from the error the turn actually
    /// receives -- `SamplingErrorInfo` built from the sampler's own `InvalidConfiguration(CALL_LIMIT |
    /// WALL_LIMIT)` -- and nothing else is.
    #[test]
    fn process_limit_refusals_are_recognized_by_the_samplers_own_constants() {
        use fuigo_sampler::execution_budget::{CALL_LIMIT, WALL_LIMIT};
        use fuigo_sampling_types::SamplingError;
        let message = |reason: &'static str| {
            fuigo_sampler::SamplingErrorInfo::from(&SamplingError::InvalidConfiguration(reason)).message
        };
        assert_eq!(process_limit_rule(&message(CALL_LIMIT)), Some(ExecutionBudgetRule::ModelCallLimit));
        assert_eq!(process_limit_rule(&message(WALL_LIMIT)), Some(ExecutionBudgetRule::RuntimeLimit));
        for other in [
            "execution admission denied or could not be persisted",
            "execution budget limits must be positive integers",
            "execution deadline exhausted before transport",
        ] {
            assert_eq!(process_limit_rule(&message(other)), None, "{other}");
        }
        // A provider's own error that merely quotes the text is not the local limit.
        for quoted in [CALL_LIMIT.to_string(), format!("stream error: {}", message(WALL_LIMIT))] {
            assert_eq!(process_limit_rule(&quoted), None, "{quoted}");
        }
    }

    /// The refusal survives the persistence actor and is recorded by the REQUEST whose admission was
    /// refused -- required purposes only, a title or recap never ends anything -- including a child
    /// refused through its parent's grant. The turn reads only its CURRENT request's refusal: a side
    /// call's refusal under the same execution (`/btw`), an earlier request's, or an earlier turn's is
    /// never what the turn reports.
    #[tokio::test]
    async fn only_the_refused_request_records_its_budget_denial() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, actor) = fixture_actor(dir.path().to_owned());
        let session = uuid::Uuid::new_v4().to_string();
        let limits = || TokenLimits { total: Some(100), output: None, initial_total: 0 };
        let execution = Execution::open(
            &tx, &session, "budget-latch", "turn1", 9, None, None, limits(), None,
        )
        .await
        .unwrap();
        let child_grant = execution.grant_child("child", None, false).await.unwrap();
        let child_session = uuid::Uuid::new_v4().to_string();
        let child = Execution::open(
            &tx, &child_session, "child-root", "child-turn", 9, None, None,
            TokenLimits::default(), Some(child_grant),
        )
        .await
        .unwrap();

        let attempt = uuid::Uuid::new_v4().to_string();
        execution.admit(RequestPurpose::Work, attempt.clone()).await.unwrap();
        execution.settle(attempt, Some(usage(150, 20))).await.unwrap();
        let next = || uuid::Uuid::new_v4().to_string();

        // A side call refused under the same execution records into its own request only.
        let side = execution.request_admission();
        let turn = execution.begin_turn_request();
        assert!(side.admit(RequestPurpose::Work, next()).await.is_err());
        assert_eq!(side.take_budget_denial().map(|d| d.rule), Some(ExecutionBudgetRule::TotalTokensExhausted));
        assert_eq!(execution.take_turn_request_denial(), None, "a side call's refusal is not the turn's");

        // Optional purposes never record, even on the turn's own request.
        for optional in [RequestPurpose::Title, RequestPurpose::Recap] {
            assert!(turn.admit(optional, next()).await.is_err());
        }
        assert_eq!(execution.take_turn_request_denial(), None, "an optional refusal never records");

        // The execution's own capability records nothing, for anyone.
        let refused = execution.admit(RequestPurpose::Work, next()).await;
        assert_eq!(refused, Err("execution admission denied or not durable".to_string()),
            "the sampler-facing string is unchanged");
        assert_eq!(execution.take_turn_request_denial(), None);

        let refused = turn.admit(RequestPurpose::Work, next()).await;
        assert_eq!(refused, Err("execution admission denied or not durable".to_string()));
        let denial = execution.take_turn_request_denial().expect("the turn's request recorded it");
        assert_eq!(denial.rule, ExecutionBudgetRule::TotalTokensExhausted);
        assert_eq!((denial.total_token_limit, denial.total_tokens_used), (Some(100), 150));
        assert_eq!(execution.take_turn_request_denial(), None, "taken once");

        // A later request replaces the earlier one: its unreported refusal is not the new request's.
        assert!(turn.admit(RequestPurpose::Completion, next()).await.is_err());
        let _later = execution.begin_turn_request();
        assert_eq!(execution.take_turn_request_denial(), None, "an earlier request's refusal is gone");

        // A child refused by its parent's budget reports the parent's denial.
        let child_request = child.begin_turn_request();
        assert!(child_request.admit(RequestPurpose::Work, next()).await.is_err());
        assert_eq!(
            child.take_turn_request_denial().map(|d| d.rule),
            Some(ExecutionBudgetRule::TotalTokensExhausted)
        );

        // A new turn on the same execution starts with nothing recorded.
        let stale = execution.begin_turn_request();
        assert!(stale.admit(RequestPurpose::Work, next()).await.is_err());
        let reopened = Execution::open(
            &tx, &session, "budget-latch", "turn2", 9, None, None, limits(), None,
        )
        .await
        .unwrap();
        assert!(Arc::ptr_eq(&reopened, &execution));
        assert_eq!(reopened.take_turn_request_denial(), None, "an earlier turn's refusal is not this turn's");

        child.release(&child_session);
        execution.release(&session);
        // No reference cycle: once the registry and every request handle are gone, so is the record.
        let weak = Arc::downgrade(&execution);
        drop((child, child_request, side, turn, stale, _later, reopened, execution));
        assert!(weak.upgrade().is_none(), "the execution outlived its requests: a reference cycle");
        drop(tx);
        actor.await.unwrap();
    }
}
