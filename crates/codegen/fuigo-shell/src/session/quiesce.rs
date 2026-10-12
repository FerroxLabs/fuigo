//! P189: session park / quiesce state (`_fuigo/session/park`, `_fuigo/session/unpark`).
//!
//! A client that keeps one Fuigo process warm between user messages parks the session after `end_turn`.
//! While a session is parked nothing in it starts a turn on its own, nothing calls the model, and the
//! connection holds every frame for it (see `crate::agent::park_hold`). Work that would have run is
//! deferred, never dropped: it runs after `unpark`.
//!
//! The registry is process-wide and keyed by session id (UUIDs), so concurrent sessions and tests never
//! share an entry. A session's subagents run as their own in-process session actors; each registers its
//! parent here, so parking a root also quiesces its whole subagent tree.
//!
//! Two phases:
//! - `Parking`: the park request is waiting for the running turn to end. Self-started turns, the
//!   notification drain and post-turn side work of the parked session are already held, but the running
//!   turn (and its subagents) may still call the model so it can finish.
//! - `Parked`: every model call in the tree waits until unpark, and frames are held. The park is
//!   acknowledged (`acked`) once its reply is ready; a second park before that is `park_in_progress`.
//! - `Unparking`: an implicit unpark (`session/prompt`) is in flight. Model calls and frames flow again, but
//!   the session still starts no turn of its own until the prompt is queued (`finish_unpark`), so a
//!   deferred wake can never run ahead of the user's prompt.
//!
//! Every park carries an operation id: completing, acknowledging and withdrawing act only on their own park,
//! so a park that was withdrawn and replaced can never complete the replacement.

use fuigo_tools::util::OpFence;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// How a park treats background work that is already running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParkMode {
    /// Default. Running background commands and monitors keep running to completion; their completion
    /// events are held and the wake turns they would start are deferred. Running subagents block before
    /// their next model call.
    Hold,
    /// Kill running background commands and monitors, and cancel running subagents, before parking.
    Stop,
}

/// The ONE list of park modes this build advertises. `fuigo/capabilities` advertises it and `handle_park`
/// refuses (-32602) a mode that is not in it. P189 A1: `stop` is not available on any OS (a later packet
/// builds it on a per-session cgroup and changes this function).
pub(crate) const fn advertised_modes() -> &'static [&'static str] {
    &["hold"]
}

impl ParkMode {
    /// Whether this OS advertises (and so accepts) the mode.
    pub(crate) fn advertised(self) -> bool {
        advertised_modes().contains(&self.as_str())
    }

    pub(crate) fn parse(raw: Option<&str>) -> Option<Self> {
        match raw {
            None | Some("hold") => Some(Self::Hold),
            Some("stop") => Some(Self::Stop),
            Some(_) => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Stop => "stop",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParkPhase {
    Parking,
    Parked,
    Unparking,
}

/// Work a park took over and owes the session at unpark.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct OwedWork {
    /// The prompt id whose turn summary was aborted or never started; re-run at unpark.
    pub(crate) turn_summary: Option<String>,
    /// A title refresh was aborted or skipped; re-checked at unpark.
    pub(crate) title_refresh: bool,
    /// A family-switch compaction (`set_model`) was skipped while parked: set at the first switch away from the
    /// origin family, kept by later switches, cleared when the model returns to the origin family. The context
    /// window is not stored: it is read when the compaction runs.
    pub(crate) family_switch_compact: Option<FamilyDebt>,
}

impl OwedWork {
    /// F8: account one model switch that happened while parked. `leaving` is the identity (family, else model id)
    /// of the model being left and `arriving` that of the new one; `compacts` is whether this switch would
    /// compact if the session were running (a family switch over model-minted history).
    pub(crate) fn note_model_switch(&mut self, compacts: bool, leaving: Option<String>, arriving: &str) {
        match &self.family_switch_compact {
            // Back in the origin family: nothing is owed any more.
            Some(debt) if debt.origin_family == arriving => self.family_switch_compact = None,
            // Already owed: later switches keep the first origin.
            Some(_) => {}
            None if compacts => {
                self.family_switch_compact = leaving.map(|origin_family| FamilyDebt { origin_family });
            }
            None => {}
        }
    }
}

/// The compaction a parked family switch owes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FamilyDebt {
    /// The `model_family` the session had before the first switch while parked.
    pub(crate) origin_family: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ParkEntry {
    pub(crate) mode: ParkMode,
    pub(crate) phase: ParkPhase,
    pub(crate) owed: OwedWork,
    /// The park operation that owns this entry.
    pub(crate) op: u64,
    /// The park's reply is ready (after the stop sweep's final check); later parks are idempotent.
    pub(crate) acked: bool,
    /// Background tasks still running at the ack, reported again by an idempotent park without asking the
    /// terminal backend (an ACP terminal's `terminal/output` is held while parked).
    pub(crate) running_at_ack: usize,
    /// Scheduled-task prompts folded while this entry held the session (owner decision 45). They live in the
    /// entry itself, so noting one and taking them for the release are each ONE critical section on the park
    /// table, and they are dropped with the entry when the session ends.
    pub(crate) fires: FoldedFires,
}

/// Most folded scheduled prompts kept per park entry.
pub(crate) const MAX_FOLDED_FIRES: usize = 32;
/// Most total bytes of folded scheduled prompts kept per park entry (one prompt is cut to this).
pub(crate) const MAX_FOLDED_FIRE_BYTES: usize = 64 * 1024;

/// Folded scheduled-task prompt texts, oldest first, bounded by [`MAX_FOLDED_FIRES`] and
/// [`MAX_FOLDED_FIRE_BYTES`]; on overflow the newest are kept.
#[derive(Debug, Clone, Default)]
pub(crate) struct FoldedFires {
    texts: std::collections::VecDeque<String>,
    bytes: usize,
    dropped: usize,
}

impl FoldedFires {
    fn push(&mut self, mut text: String) {
        if text.len() > MAX_FOLDED_FIRE_BYTES {
            let mut end = MAX_FOLDED_FIRE_BYTES;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        self.bytes += text.len();
        self.texts.push_back(text);
        while self.texts.len() > MAX_FOLDED_FIRES || self.bytes > MAX_FOLDED_FIRE_BYTES {
            let Some(old) = self.texts.pop_front() else { break };
            self.bytes -= old.len();
            self.dropped += 1;
        }
    }

    /// The texts, oldest first; a first line says how many earlier ones were dropped.
    pub(crate) fn into_texts(self) -> Vec<String> {
        let mut out = Vec::with_capacity(self.texts.len() + 1);
        if self.dropped > 0 {
            out.push(format!("({} earlier scheduled prompts were dropped)", self.dropped));
        }
        out.extend(self.texts);
        out
    }
}

/// The session actor's answer to a park probe (`SessionCommand::Quiesce`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct QuiesceReport {
    /// A turn is still running (or finalizing); the park waits for it.
    pub(crate) turn_running: bool,
    /// Queued inputs held by the park: wake turns (task, subagent, workflow, scheduler) and queued prompts.
    pub(crate) queued_inputs: usize,
    /// Pending notifications (monitor events, task completions) the idle drain would have turned into a turn.
    pub(crate) pending_notifications: usize,
    /// The turn summary was deferred to unpark.
    pub(crate) turn_summary_deferred: bool,
    /// The title refresh was deferred to unpark.
    pub(crate) title_refresh_deferred: bool,
}

#[derive(Default)]
struct Inner {
    parked: HashMap<String, ParkEntry>,
    /// child session id -> parent session id. A link outlives its child's actor (a closed child's held frames
    /// and requests stay under its parked root) and is dropped with its root.
    parents: HashMap<String, String>,
    /// session id -> prompt id of the last turn summary it started, so a park can abort and re-run it.
    last_summary_prompt: HashMap<String, String>,
    /// root session id -> cancel generation, bumped by each implicit unpark: requests (and reverse MCP calls)
    /// held under the park that see it move belong to the turn before the park and are answered cancelled.
    /// Dropped with the root.
    cancel_generation: HashMap<String, u64>,
    /// root session id -> number of `session/load` replies of the parked root being prepared.
    parked_loads: HashMap<String, usize>,
}

struct Registry {
    inner: Mutex<Inner>,
    /// Bumped on every park-state change so waiters re-check.
    changed: tokio::sync::watch::Sender<u64>,
}

static NEXT_OP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| Registry {
    inner: Mutex::new(Inner::default()),
    changed: tokio::sync::watch::channel(0).0,
});

/// Parent links deeper than this are treated as a cycle and ignored.
const MAX_DEPTH: usize = 64;

fn lock() -> std::sync::MutexGuard<'static, Inner> {
    REGISTRY
        .inner
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bump() {
    REGISTRY.changed.send_modify(|v| *v = v.wrapping_add(1));
}

impl Inner {
    /// The strongest phase on `session_id` or any ancestor.
    fn effective_phase(&self, session_id: &str) -> Option<ParkPhase> {
        let mut current = session_id;
        let mut best: Option<ParkPhase> = None;
        for _ in 0..MAX_DEPTH {
            if let Some(entry) = self.parked.get(current) {
                match entry.phase {
                    ParkPhase::Parked => return Some(ParkPhase::Parked),
                    ParkPhase::Parking => best = Some(ParkPhase::Parking),
                    ParkPhase::Unparking => {}
                }
            }
            match self.parents.get(current) {
                Some(parent) => current = parent.as_str(),
                None => break,
            }
        }
        best
    }
}

/// Start parking `session_id`. Returns the park's operation id, or `None` when it is already parking,
/// parked or unparking (nothing changes).
pub(crate) fn begin_park(session_id: &str, mode: ParkMode) -> Option<u64> {
    let op = {
        let mut inner = lock();
        if inner.parked.contains_key(session_id) {
            return None;
        }
        let op = NEXT_OP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        inner.parked.insert(
            session_id.to_owned(),
            ParkEntry {
                mode,
                phase: ParkPhase::Parking,
                owed: OwedWork::default(),
                op,
                acked: false,
                running_at_ack: 0,
                fires: FoldedFires::default(),
            },
        );
        op
    };
    bump();
    Some(op)
}

/// Move park `op` of `session_id` from `Parking` to `Parked`. Returns `false` when that park was
/// withdrawn meanwhile (even if another park took its place).
pub(crate) fn complete_park(session_id: &str, op: u64) -> bool {
    let done = {
        let mut inner = lock();
        match inner.parked.get_mut(session_id) {
            Some(entry) if entry.op == op && entry.phase == ParkPhase::Parking => {
                entry.phase = ParkPhase::Parked;
                true
            }
            _ => false,
        }
    };
    if done {
        bump();
    }
    done
}

/// Acknowledge park `op` (its reply is about to be sent), recording the running-task count it reports.
/// Returns `false` when that park is no longer the session's parked entry.
pub(crate) fn ack_park(session_id: &str, op: u64, running_tasks: usize) -> bool {
    let mut inner = lock();
    match inner.parked.get_mut(session_id) {
        Some(entry) if entry.op == op && entry.phase == ParkPhase::Parked => {
            entry.acked = true;
            entry.running_at_ack = running_tasks;
            true
        }
        _ => false,
    }
}

/// Withdraw park `op` (it failed or timed out before its ack). Another park's entry is never touched.
pub(crate) fn withdraw(session_id: &str, op: u64) -> Option<ParkEntry> {
    let removed = {
        let mut inner = lock();
        if inner
            .parked
            .get(session_id)
            .is_some_and(|entry| entry.op == op && entry.phase != ParkPhase::Unparking)
        {
            inner.parked.remove(session_id)
        } else {
            None
        }
    };
    if removed.is_some() {
        bump();
    }
    removed
}

/// Explicit unpark (`_fuigo/session/unpark`): remove the park on `session_id`, whatever its phase except an
/// implicit unpark already in flight (which the prompt finishes), returning what it was.
pub(crate) fn unpark(session_id: &str) -> Option<ParkEntry> {
    let removed = {
        let mut inner = lock();
        if inner
            .parked
            .get(session_id)
            .is_some_and(|entry| entry.phase != ParkPhase::Unparking)
        {
            inner.parked.remove(session_id)
        } else {
            None
        }
    };
    if removed.is_some() {
        bump();
    }
    removed
}

/// Implicit unpark, step 1 (`session/prompt`): the session stops holding model calls and frames, but stays
/// self-quiesced (starts no turn) until [`finish_unpark`]. Returns the entry as it was.
/// `expected_op` is the park op the caller observed; a different (replacement) op is left untouched and the
/// result is the same as for a session that is not parked.
pub(crate) fn begin_implicit_unpark(session_id: &str, expected_op: u64) -> Option<ParkEntry> {
    let entry = {
        let mut guard = lock();
        let inner = &mut *guard;
        match inner.parked.get_mut(session_id) {
            Some(entry) if entry.phase != ParkPhase::Unparking && entry.op == expected_op => {
                let mut before = entry.clone();
                // The folded fires leave with the transition (same critical section): a fire noting itself later
                // sees `Unparking`, not a holding park, and takes the normal path.
                before.fires = std::mem::take(&mut entry.fires);
                entry.phase = ParkPhase::Unparking;
                // Astra r2 #8: the cancel generation moves in the SAME critical section as the transition, so a
                // request held under the park is cancelled exactly when the park stops holding.
                if before.phase == ParkPhase::Parked {
                    *inner.cancel_generation.entry(session_id.to_owned()).or_default() += 1;
                }
                Some(before)
            }
            _ => None,
        }
    };
    if entry.is_some() {
        bump();
    }
    entry
}

/// Implicit unpark, step 2: the prompt is queued; the session may start turns again.
pub(crate) fn finish_unpark(session_id: &str, op: u64) -> bool {
    let removed = {
        let mut inner = lock();
        if inner
            .parked
            .get(session_id)
            .is_some_and(|entry| entry.op == op && entry.phase == ParkPhase::Unparking)
        {
            inner.parked.remove(session_id).is_some()
        } else {
            false
        }
    };
    if removed {
        bump();
    }
    removed
}

/// Implicit unpark, step 2 as the session actor sees it: a prompt was just queued on `session_id`; if an
/// implicit unpark is in flight, it is finished (whichever operation it is: the prompt that started it is
/// the next queued input either way). A scheduled fire (`prompt_id` carries the fire prefix, verified or
/// not) never finishes it: only the client prompt that began the unpark may.
pub(crate) fn finish_unpark_on_prompt(session_id: &str, prompt_id: &str) {
    if crate::extensions::session_park::is_scheduled_fire_id(prompt_id) {
        return;
    }
    let removed = {
        let mut inner = lock();
        if inner
            .parked
            .get(session_id)
            .is_some_and(|entry| entry.phase == ParkPhase::Unparking)
        {
            inner.parked.remove(session_id).is_some()
        } else {
            false
        }
    };
    if removed {
        bump();
    }
}

/// Grok r4 #4: a release for park `op` reached the actor while ANOTHER park (`!= op`, not already unparking)
/// holds the session. The release then does not run its work under that park: the owed work moves to the
/// current park (which runs it at its own unpark) and `Ok` is returned. Otherwise the owed work comes back
/// in `Err` for the caller to run now. A session that is not parked takes the `Err` path untouched.
pub(crate) fn hand_over_owed(session_id: &str, op: u64, owed: OwedWork) -> Result<(), OwedWork> {
    let mut inner = lock();
    match inner.parked.get_mut(session_id) {
        Some(entry) if entry.op != op && entry.phase != ParkPhase::Unparking => {
            let current = &mut entry.owed;
            if current.turn_summary.is_none() {
                current.turn_summary = owed.turn_summary;
            }
            current.title_refresh |= owed.title_refresh;
            if current.family_switch_compact.is_none() {
                current.family_switch_compact = owed.family_switch_compact;
            }
            Ok(())
        }
        _ => Err(owed),
    }
}

/// Test helper: bump `root`'s cancel generation as `begin_implicit_unpark` does for a parked root.
#[cfg(test)]
pub(crate) fn note_implicit_unpark(root: &str) {
    *lock().cancel_generation.entry(root.to_owned()).or_default() += 1;
    bump();
}

/// `root`'s cancel generation (see [`note_implicit_unpark`]).
pub(crate) fn cancel_generation(root: &str) -> u64 {
    lock().cancel_generation.get(root).copied().unwrap_or_default()
}

/// Marks a `session/load` reply of a parked root in preparation.
pub(crate) struct ParkedLoadGuard {
    root: String,
}

/// A parked `session/load` of `root` is being answered: its MCP reconnect may exchange reverse
/// `_fuigo/mcp/sdk_call` traffic, as part of answering the client's own request.
pub(crate) fn begin_parked_load(root: &str) -> ParkedLoadGuard {
    *lock().parked_loads.entry(root.to_owned()).or_default() += 1;
    bump();
    ParkedLoadGuard {
        root: root.to_owned(),
    }
}

impl Drop for ParkedLoadGuard {
    fn drop(&mut self) {
        {
            let mut inner = lock();
            if let Some(count) = inner.parked_loads.get_mut(&self.root) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    inner.parked_loads.remove(&self.root);
                }
            }
        }
        bump();
    }
}

/// A parked `session/load` of `root` is in preparation.
pub(crate) fn is_loading(root: &str) -> bool {
    lock().parked_loads.contains_key(root)
}

/// Park operation `op` is still `session_id`'s park (not withdrawn, replaced or unparking). An EARLY-EXIT hint
/// for waiting loops only: it proves nothing about the moment a side effect runs. Side effects go through
/// [`run_if_current`] / [`with_current_owed`] / an [`OpFence`], which check and act under one lock.
pub(crate) fn op_is_current(session_id: &str, op: u64) -> bool {
    lock()
        .parked
        .get(session_id)
        .is_some_and(|entry| entry.op == op && entry.phase != ParkPhase::Unparking)
}

/// One park operation of one session: the identity a side effect is fenced on.
#[derive(Clone, Debug)]
pub(crate) struct ParkOp {
    pub(crate) session: std::sync::Arc<str>,
    pub(crate) op: u64,
}

/// Runs `f` under the registry lock only if `park` is still the session's current park op (not withdrawn,
/// replaced or unparking), so an unpark or withdraw cannot interleave with `f`. `f` must be synchronous and
/// short (no I/O wait, no await). Returns whether it ran.
pub(crate) fn run_if_current(park: &ParkOp, f: impl FnOnce()) -> bool {
    let guard = lock();
    let current = guard
        .parked
        .get(&*park.session)
        .is_some_and(|entry| entry.op == park.op && entry.phase != ParkPhase::Unparking);
    if current {
        f();
    }
    drop(guard);
    current
}

/// Like [`run_if_current`], and `f` may also record the work the park owes (under the same lock, so the
/// abort it pairs with and the debt cannot be separated by an unpark).
pub(crate) fn with_current_owed(park: &ParkOp, f: impl FnOnce(&mut OwedWork)) -> bool {
    let mut guard = lock();
    match guard.parked.get_mut(&*park.session) {
        Some(entry) if entry.op == park.op && entry.phase != ParkPhase::Unparking => {
            f(&mut entry.owed);
            true
        }
        _ => false,
    }
}

/// The [`OpFence`] of `park`, for crates that cannot see this module.
pub(crate) fn park_op_fence(park: ParkOp) -> OpFence {
    std::sync::Arc::new(move |f: &mut dyn FnMut()| run_if_current(&park, f))
}

/// [`park_op_fence`] from a session id and op.
pub(crate) fn op_fence(session_id: &str, op: u64) -> OpFence {
    park_op_fence(ParkOp { session: session_id.into(), op })
}

/// The park entry set directly on `session_id` (not inherited from an ancestor).
pub(crate) fn entry(session_id: &str) -> Option<ParkEntry> {
    lock().parked.get(session_id).cloned()
}

/// `session_id` itself is parking or parked: it starts no turn, drains no notifications and runs no
/// post-turn side work. A subagent of a parked root is not held here: its turn may be admitted (so its
/// spawner's admission wait never times out) and then blocks at its first model call ([`is_parked`]).
pub(crate) fn is_self_quiesced(session_id: &str) -> bool {
    lock().parked.contains_key(session_id)
}

impl Inner {
    /// `session_id` (when `include_self`) or an ancestor has a park that is `Parking` or `Parked`.
    fn holding(&self, session_id: &str, include_self: bool) -> bool {
        let mut current = session_id;
        let mut first = true;
        for _ in 0..MAX_DEPTH {
            if (include_self || !first)
                && self
                    .parked
                    .get(current)
                    .is_some_and(|entry| entry.phase != ParkPhase::Unparking)
            {
                return true;
            }
            first = false;
            match self.parents.get(current) {
                Some(parent) => current = parent.as_str(),
                None => break,
            }
        }
        false
    }
}

impl Inner {
    /// `session_id` (when `include_self`) or an ancestor has a park entry in ANY phase, `Unparking` included.
    fn has_entry(&self, session_id: &str, include_self: bool) -> bool {
        let mut current = session_id;
        let mut first = true;
        for _ in 0..MAX_DEPTH {
            if (include_self || !first) && self.parked.contains_key(current) {
                return true;
            }
            first = false;
            match self.parents.get(current) {
                Some(parent) => current = parent.as_str(),
                None => break,
            }
        }
        false
    }
}

/// `session_id` or an ancestor has a park entry in any phase (a queued scheduled fire waits until none is left).
pub(crate) fn has_park_in_tree(session_id: &str) -> bool {
    lock().has_entry(session_id, true)
}

/// A strict ancestor of `session_id` has a park entry in any phase, `Unparking` included.
pub(crate) fn has_park_above(session_id: &str) -> bool {
    lock().has_entry(session_id, false)
}

/// `session_id` or one of its ancestors is parking or parked: a peer message must not be promoted into a running
/// turn (it could keep the turn the park waits for alive). False for every session that is not in a park.
pub(crate) fn is_tree_holding(session_id: &str) -> bool {
    lock().holding(session_id, true)
}

/// A strict ancestor of `session_id` is parking or parked: the root holds this child, which has no entry of its
/// own, so a peer message to it must not start a turn until the root is released.
pub(crate) fn is_ancestor_holding(session_id: &str) -> bool {
    lock().holding(session_id, false)
}

/// The nearest of `session_id` and its ancestors that is parked (acknowledged), if any.
pub(crate) fn parked_root(session_id: &str) -> Option<String> {
    let inner = lock();
    let mut current = session_id;
    for _ in 0..MAX_DEPTH {
        if inner
            .parked
            .get(current)
            .is_some_and(|entry| entry.phase == ParkPhase::Parked)
        {
            return Some(current.to_owned());
        }
        match inner.parents.get(current) {
            Some(parent) => current = parent.as_str(),
            None => break,
        }
    }
    None
}

/// `session_id` or an ancestor is parked (acknowledged): no model call may start.
pub(crate) fn is_parked(session_id: &str) -> bool {
    lock().effective_phase(session_id) == Some(ParkPhase::Parked)
}

/// Record work the park owes the session (or, for a subagent, nothing: subagents own no summary/title).
pub(crate) fn owe(session_id: &str, f: impl FnOnce(&mut OwedWork)) -> bool {
    let mut inner = lock();
    match inner.parked.get_mut(session_id) {
        Some(entry) if entry.phase != ParkPhase::Unparking => {
            f(&mut entry.owed);
            true
        }
        _ => false,
    }
}

/// Owner decision 45: fold a scheduled-task fire into the park that holds `session_id` (its own entry, else the
/// nearest holding ancestor's: a child of a held root). Returns `false` when no park holds the session (none, or
/// only an `Unparking` one): the fire then takes the normal path. State check and note are ONE critical section
/// with the transitions that take the fires, so a fire lands in exactly one release or sees no holding park.
pub(crate) fn fold_fire_if_holding(session_id: &str, text: String) -> bool {
    let mut guard = lock();
    let inner = &mut *guard;
    let mut current = session_id.to_owned();
    for _ in 0..MAX_DEPTH {
        if let Some(entry) = inner.parked.get_mut(&current)
            && entry.phase != ParkPhase::Unparking
        {
            entry.fires.push(text);
            return true;
        }
        match inner.parents.get(&current) {
            Some(parent) => current = parent.clone(),
            None => break,
        }
    }
    false
}

/// Remember the prompt id of the turn summary `session_id` just started.
pub(crate) fn note_turn_summary(session_id: &str, prompt_id: &str) {
    lock()
        .last_summary_prompt
        .insert(session_id.to_owned(), prompt_id.to_owned());
}

/// The prompt id of the last turn summary `session_id` started.
pub(crate) fn last_turn_summary_prompt(session_id: &str) -> Option<String> {
    lock().last_summary_prompt.get(session_id).cloned()
}

/// Wait until no model call is held for `session_id` (it and every ancestor are not `Parked`).
/// Returns at once when nothing is parked. Cancel-safe: dropping the future just stops waiting.
pub(crate) async fn wait_model_allowed(session_id: &str) {
    let mut rx = REGISTRY.changed.subscribe();
    loop {
        if !is_parked(session_id) {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// A subscription that fires on every park-state change (for frame holds and waiters).
pub(crate) fn subscribe() -> tokio::sync::watch::Receiver<u64> {
    REGISTRY.changed.subscribe()
}

impl Inner {
    fn root_of<'a>(&'a self, session_id: &'a str) -> &'a str {
        let mut current = session_id;
        for _ in 0..MAX_DEPTH {
            match self.parents.get(current) {
                Some(parent) => current = parent.as_str(),
                None => break,
            }
        }
        current
    }

    fn descends_from(&self, session_id: &str, ancestor: &str) -> bool {
        let mut current = session_id;
        for _ in 0..MAX_DEPTH {
            if current == ancestor {
                return true;
            }
            match self.parents.get(current) {
                Some(parent) => current = parent.as_str(),
                None => return false,
            }
        }
        false
    }

    fn lineage(&self, root: &str) -> Vec<String> {
        let mut sessions = vec![root.to_owned()];
        sessions.extend(
            self.parents
                .keys()
                .filter(|child| self.descends_from(child, root) && child.as_str() != root)
                .cloned(),
        );
        sessions
    }
}

/// The top of `session_id`'s subagent chain (itself when it has no parent).
pub(crate) fn root_of(session_id: &str) -> String {
    lock().root_of(session_id).to_owned()
}

/// Ties a live session actor to the registry: links a subagent to its parent, and on drop forgets the
/// session's own park. A subagent's link stays until its root closes, so a closed child's held frames and
/// requests stay under its parked root; a root's close drops its whole lineage's links.
pub(crate) struct SessionGuard {
    session_id: String,
}

impl SessionGuard {
    pub(crate) fn new(session_id: &str, parent_session_id: Option<&str>) -> Self {
        if let Some(parent) = parent_session_id
            && parent != session_id
        {
            lock()
                .parents
                .insert(session_id.to_owned(), parent.to_owned());
            bump();
        }
        Self {
            session_id: session_id.to_owned(),
        }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let changed = {
            let mut inner = lock();
            inner.last_summary_prompt.remove(&self.session_id);
            let a = inner.parked.remove(&self.session_id).is_some();
            // A root takes its lineage's links with it; a child keeps its link while its root lives.
            let b = if inner.parents.contains_key(&self.session_id) {
                false
            } else {
                let lineage = inner.lineage(&self.session_id);
                let before = inner.parents.len();
                for child in lineage {
                    inner.parents.remove(&child);
                }
                // Astra r1 #12: the root's cancel record and load count go with it.
                let pruned = inner.cancel_generation.remove(&self.session_id).is_some()
                    | inner.parked_loads.remove(&self.session_id).is_some();
                inner.parents.len() != before || pruned
            };
            a || b
        };
        if changed {
            bump();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(tag: &str) -> String {
        format!("p189-{tag}-{}", uuid::Uuid::new_v4())
    }

    #[test]
    fn mode_parses_default_hold_and_rejects_unknown() {
        assert_eq!(ParkMode::parse(None), Some(ParkMode::Hold));
        assert_eq!(ParkMode::parse(Some("hold")), Some(ParkMode::Hold));
        assert_eq!(ParkMode::parse(Some("stop")), Some(ParkMode::Stop));
        assert_eq!(ParkMode::parse(Some("pause")), None);
    }

    #[test]
    fn parking_quiesces_but_only_parked_blocks_model_calls() {
        let root = sid("root");
        assert!(!is_self_quiesced(&root));
        let op = begin_park(&root, ParkMode::Hold).expect("first park");
        assert!(begin_park(&root, ParkMode::Stop).is_none(), "a second park is a no-op");
        assert!(is_self_quiesced(&root));
        assert!(!is_parked(&root), "the running turn may still finish while parking");
        assert!(complete_park(&root, op));
        assert!(is_parked(&root));
        let entry = unpark(&root).expect("was parked");
        assert_eq!(entry.mode, ParkMode::Hold);
        assert!(!is_self_quiesced(&root));
        assert!(unpark(&root).is_none());
    }

    #[test]
    fn a_parked_root_quiesces_its_whole_subagent_tree() {
        let root = sid("root");
        let child = sid("child");
        let grandchild = sid("grandchild");
        let _c = SessionGuard::new(&child, Some(&root));
        let _g = SessionGuard::new(&grandchild, Some(&child));
        let op = begin_park(&root, ParkMode::Hold).expect("park");
        complete_park(&root, op);
        assert!(is_parked(&grandchild));
        assert!(is_parked(&child));
        assert!(
            !is_self_quiesced(&child),
            "a subagent's turns may still be admitted; only its model calls wait"
        );
        unpark(&root);
        assert!(!is_parked(&grandchild));
    }

    #[test]
    fn dropping_the_guard_forgets_a_parked_session() {
        let root = sid("root");
        {
            let _g = SessionGuard::new(&root, None);
            let op = begin_park(&root, ParkMode::Hold).expect("park");
            complete_park(&root, op);
            assert!(is_parked(&root));
        }
        assert!(!is_self_quiesced(&root));
    }

    /// Astra r1 #9: a subagent's actor ending (its guard drops) must not make its held frames and requests
    /// look unparked while its root is still parked.
    #[test]
    fn a_childs_teardown_keeps_it_under_its_parked_root() {
        let root = sid("root");
        let child = sid("child");
        let _root_guard = SessionGuard::new(&root, None);
        let op = begin_park(&root, ParkMode::Hold).expect("park");
        complete_park(&root, op);
        {
            let _child_guard = SessionGuard::new(&child, Some(&root));
            assert!(is_parked(&child));
        }
        assert!(is_parked(&child), "a closed child left its parked root's hold");
        assert_eq!(parked_root(&child).as_deref(), Some(root.as_str()));
    }

    #[test]
    fn complete_park_after_unpark_reports_withdrawn() {
        let root = sid("root");
        let op = begin_park(&root, ParkMode::Hold).expect("park");
        unpark(&root);
        assert!(!complete_park(&root, op));
        assert!(!is_parked(&root));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn model_wait_releases_on_unpark() {
        let root = sid("root");
        let op = begin_park(&root, ParkMode::Hold).expect("park");
        complete_park(&root, op);
        let waiter = {
            let root = root.clone();
            tokio::spawn(async move { wait_model_allowed(&root).await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished(), "a parked session must hold model calls");
        unpark(&root);
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("unpark releases the wait")
            .expect("waiter task");
    }

    #[test]
    fn owed_work_is_returned_by_unpark() {
        let root = sid("root");
        assert!(!owe(&root, |o| o.title_refresh = true), "nothing to owe when not parked");
        begin_park(&root, ParkMode::Stop);
        owe(&root, |o| o.turn_summary = Some("p-1".into()));
        owe(&root, |o| o.title_refresh = true);
        let entry = unpark(&root).expect("parked");
        assert_eq!(entry.mode, ParkMode::Stop);
        assert_eq!(entry.owed.turn_summary.as_deref(), Some("p-1"));
        assert!(entry.owed.title_refresh);
    }

    /// Astra r1 #4: a park acts only on its own operation. After A is withdrawn and B begins, A can neither
    /// complete, acknowledge nor withdraw B.
    #[test]
    fn a_stale_park_never_touches_its_replacement() {
        let root = sid("root");
        let a = begin_park(&root, ParkMode::Stop).expect("park a");
        assert!(withdraw(&root, a).is_some());
        let b = begin_park(&root, ParkMode::Hold).expect("park b");
        assert_ne!(a, b);
        assert!(!complete_park(&root, a), "a stale park completed its replacement");
        assert!(withdraw(&root, a).is_none(), "a stale park withdrew its replacement");
        assert!(complete_park(&root, b));
        assert!(!ack_park(&root, a, 0));
        assert!(ack_park(&root, b, 3));
        let entry = entry(&root).expect("parked");
        assert!(entry.acked);
        assert_eq!(entry.running_at_ack, 3);
        unpark(&root);
    }

    /// An implicit unpark that expected another park op leaves the entry alone and reports "not parked".
    #[test]
    fn implicit_unpark_with_a_different_expected_op_changes_nothing() {
        let root = sid("op-mismatch");
        let op = begin_park(&root, ParkMode::Hold).expect("park");
        complete_park(&root, op);
        assert!(begin_implicit_unpark(&root, op + 1000).is_none());
        assert!(is_parked(&root), "the park is untouched");
        let fence = op_fence(&root, op);
        let mut ran = false;
        assert!(fence(&mut || ran = true) && ran, "the fence runs for the current op");
        assert!(!op_fence(&root, op + 1000)(&mut || panic!("a stale op must not run")));
        unpark(&root);
    }

    /// Astra r1 #8: an implicit unpark lets model calls through at once but keeps the session from starting
    /// its own turns until the prompt is queued.
    #[test]
    fn implicit_unpark_keeps_the_session_quiesced_until_the_prompt_is_queued() {
        let root = sid("root");
        let op = begin_park(&root, ParkMode::Hold).expect("park");
        complete_park(&root, op);
        let entry = begin_implicit_unpark(&root, op).expect("parked");
        assert_eq!(entry.op, op);
        assert!(!is_parked(&root), "model calls and frames flow during the implicit unpark");
        assert!(is_self_quiesced(&root), "no self-started turn may run ahead of the prompt");
        assert!(unpark(&root).is_none(), "an explicit unpark leaves an implicit one to the prompt");
        assert!(!owe(&root, |o| o.title_refresh = true), "nothing is owed once unparking");
        finish_unpark_on_prompt(&root, "client-1");
        assert!(!is_self_quiesced(&root));
    }


    /// Astra r1 #12: a root's cancel record goes with the root.
    #[test]
    fn cancel_records_are_pruned_with_the_root() {
        let root = sid("root");
        {
            let _g = SessionGuard::new(&root, None);
            note_implicit_unpark(&root);
            assert_eq!(cancel_generation(&root), 1);
            assert!(lock().cancel_generation.contains_key(&root));
        }
        assert!(!lock().cancel_generation.contains_key(&root), "the root's cancel record outlived it");
    }

    /// F3: the owed-work recorder runs only for the park that still owns the entry.
    #[test]
    fn owed_work_is_recorded_only_for_the_current_op() {
        let root = sid("owed-op");
        let _r = SessionGuard::new(&root, None);
        let p = begin_park(&root, ParkMode::Hold).expect("park");
        let park = ParkOp { session: root.as_str().into(), op: p };
        assert!(with_current_owed(&park, |owed| owed.title_refresh = true));
        assert!(withdraw(&root, p).is_some());
        let q = begin_park(&root, ParkMode::Hold).expect("replacement");
        assert!(!with_current_owed(&park, |owed| owed.title_refresh = true), "a stale op ran");
        assert!(!entry(&root).expect("Q").owed.title_refresh, "P's debt leaked into Q");
        assert_ne!(p, q);
    }


    /// F8: A -> B -> A while parked owes nothing; A -> B -> C keeps the first origin and owes one compaction.
    #[test]
    fn a_reverted_family_switch_owes_nothing() {
        let mut owed = OwedWork::default();
        owed.note_model_switch(true, Some("a".into()), "b");
        assert_eq!(owed.family_switch_compact, Some(FamilyDebt { origin_family: "a".into() }));
        owed.note_model_switch(true, Some("b".into()), "a");
        assert_eq!(owed.family_switch_compact, None, "the model is back in its origin family");
        owed.note_model_switch(true, Some("a".into()), "b");
        owed.note_model_switch(true, Some("b".into()), "c");
        assert_eq!(owed.family_switch_compact, Some(FamilyDebt { origin_family: "a".into() }));
    }

    /// F8: the debt stores no context window, so the compaction can only use the window current when it runs.
    #[test]
    fn the_owed_compaction_uses_the_final_window() {
        let mut owed = OwedWork::default();
        owed.note_model_switch(true, Some("a".into()), "b");
        owed.note_model_switch(false, Some("b".into()), "b2");
        // The whole debt is the origin family: nothing about any window survives to be stale.
        assert_eq!(owed.family_switch_compact, Some(FamilyDebt { origin_family: "a".into() }));
    }


    /// Grok r4 #4/#8: a release for park P that runs while park Q holds hands its owed work (including the
    /// family debt) to Q; with no park, or with its own park op, it runs the work itself.
    #[test]
    fn a_stale_release_hands_its_owed_work_to_the_current_park() {
        let id = format!("p189a2-handover-{}", uuid::Uuid::new_v4());
        let owed = || OwedWork {
            turn_summary: Some("p-1".into()),
            title_refresh: true,
            family_switch_compact: Some(FamilyDebt { origin_family: "a".into() }),
        };
        assert!(hand_over_owed(&id, 1, owed()).is_err(), "no park: the release runs its own work");
        let q = begin_park(&id, ParkMode::Hold).expect("park Q");
        assert!(hand_over_owed(&id, q, owed()).is_err(), "Q's own release is not stale");
        assert!(hand_over_owed(&id, q + 1000, owed()).is_ok());
        let entry = entry(&id).expect("Q");
        assert_eq!(entry.owed, owed(), "the debt and the deferred work moved to Q");
        unpark(&id);
    }

    /// An unparking park is not a holder: its prompt is about to run the released work.
    #[test]
    fn a_release_is_not_stale_against_an_unparking_session() {
        let id = format!("p189a2-handover-unparking-{}", uuid::Uuid::new_v4());
        let q = begin_park(&id, ParkMode::Hold).expect("park");
        assert!(complete_park(&id, q));
        assert!(begin_implicit_unpark(&id, q).is_some());
        assert!(hand_over_owed(&id, q + 1, OwedWork::default()).is_err());
        finish_unpark(&id, q);
    }

    /// The peer-hold predicates: strict ancestors for starting a child, self-or-ancestor for promotion; false
    /// for a session that is in no park (the behaviour of every session that never parks).
    #[test]
    fn peer_hold_predicates_follow_the_root_and_are_false_without_a_park() {
        let root = format!("p189a2-root-{}", uuid::Uuid::new_v4());
        let child = format!("p189a2-child-{}", uuid::Uuid::new_v4());
        let _guard = SessionGuard::new(&child, Some(&root));
        assert!(!is_tree_holding(&child) && !is_ancestor_holding(&child) && !is_tree_holding(&root));
        let op = begin_park(&root, ParkMode::Hold).expect("park");
        assert!(is_tree_holding(&root) && !is_ancestor_holding(&root), "Parking holds the root itself");
        assert!(is_tree_holding(&child) && is_ancestor_holding(&child), "Parking root holds its child");
        assert!(complete_park(&root, op));
        assert!(is_ancestor_holding(&child));
        assert!(begin_implicit_unpark(&root, op).is_some());
        assert!(!is_tree_holding(&root) && !is_ancestor_holding(&child), "Unparking holds nothing");
        finish_unpark(&root, op);
        assert!(!is_ancestor_holding(&child));
    }

    /// Step 4: a session that never parked leaves no state behind and takes no park action.
    #[test]
    fn a_session_that_never_parks_is_untouched_by_the_park_hooks() {
        let id = format!("p189a2-never-{}", uuid::Uuid::new_v4());
        finish_unpark_on_prompt(&id, "client-1");
        assert!(!owe(&id, |_| panic!("owe ran for a session that is not parked")));
        assert!(withdraw(&id, 1).is_none() && unpark(&id).is_none() && entry(&id).is_none());
        assert!(!is_self_quiesced(&id) && !is_parked(&id) && parked_root(&id).is_none());
        assert_eq!(cancel_generation(&id), 0);
        let before = last_turn_summary_prompt(&id);
        assert_eq!(before, None);
        note_turn_summary(&id, "prompt-1");
        assert_eq!(last_turn_summary_prompt(&id).as_deref(), Some("prompt-1"));
        // The only state `note_turn_summary` leaves is cleared with the session.
        drop(SessionGuard::new(&id, None));
        assert_eq!(last_turn_summary_prompt(&id), None, "SessionGuard drop must clear the summary record");
    }

    /// Round 3 #3: a fire noted before the transition rides that release; one after it sees no holding park.
    #[test]
    fn a_folded_fire_lands_in_exactly_one_release() {
        let id = sid("fold-atomic");
        let op = begin_park(&id, ParkMode::Hold).unwrap();
        assert!(complete_park(&id, op));
        assert!(fold_fire_if_holding(&id, "before".into()));
        let taken = begin_implicit_unpark(&id, op).expect("unpark");
        assert_eq!(taken.fires.into_texts(), vec!["before".to_owned()]);
        assert!(!fold_fire_if_holding(&id, "after".into()), "a fire folded into an Unparking entry would be lost");
        assert!(finish_unpark(&id, op));
        assert!(!fold_fire_if_holding(&id, "gone".into()));
    }

    /// Round 3 #3: the folded text goes away with the entry (session end, explicit unpark, withdraw).
    #[test]
    fn folded_fires_are_drained_with_the_entry() {
        let id = sid("fold-drain");
        let op = begin_park(&id, ParkMode::Hold).unwrap();
        assert!(fold_fire_if_holding(&id, "parking".into()));
        assert!(complete_park(&id, op));
        assert!(fold_fire_if_holding(&id, "parked".into()));
        assert_eq!(unpark(&id).unwrap().fires.into_texts(), vec!["parking".to_owned(), "parked".to_owned()]);
        let op = begin_park(&id, ParkMode::Hold).unwrap();
        assert!(fold_fire_if_holding(&id, "stale".into()));
        drop(SessionGuard { session_id: id.clone() });
        assert!(entry(&id).is_none());
        let again = begin_park(&id, ParkMode::Hold).unwrap();
        assert_ne!(op, again);
        assert!(unpark(&id).unwrap().fires.into_texts().is_empty(), "a new park inherited an old session's fires");
    }

    /// Round 3 #2: a child of a held root folds into the root's entry.
    #[test]
    fn a_child_fire_folds_into_the_holding_root() {
        let (root, child) = (sid("fold-root"), sid("fold-child"));
        let _link = SessionGuard::new(&child, Some(&root));
        assert!(!fold_fire_if_holding(&child, "none".into()), "no park: normal path");
        let op = begin_park(&root, ParkMode::Hold).unwrap();
        assert!(complete_park(&root, op));
        assert!(fold_fire_if_holding(&child, "child job".into()));
        assert_eq!(unpark(&root).unwrap().fires.into_texts(), vec!["child job".to_owned()]);
    }

    /// Round 3 #4: the folded fires are capped by count and by bytes; the newest are kept and one line says how
    /// many earlier ones were dropped.
    #[test]
    fn folded_fires_are_capped_keeping_the_newest() {
        let mut fires = FoldedFires::default();
        for n in 0..(MAX_FOLDED_FIRES + 5) {
            fires.push(format!("fire {n}"));
        }
        let texts = fires.into_texts();
        assert_eq!(texts.len(), MAX_FOLDED_FIRES + 1);
        assert_eq!(texts[0], "(5 earlier scheduled prompts were dropped)");
        assert_eq!(texts[1], "fire 5");
        assert_eq!(texts.last().unwrap(), &format!("fire {}", MAX_FOLDED_FIRES + 4));

        let mut fires = FoldedFires::default();
        let big = "x".repeat(MAX_FOLDED_FIRE_BYTES / 2 + 1);
        fires.push(big.clone());
        fires.push(big);
        fires.push("newest".into());
        let texts = fires.into_texts();
        assert_eq!(texts.len(), 3, "{texts:?}");
        assert!(texts[0].starts_with("(1 earlier"));
        assert_eq!(texts[2], "newest");
        let mut fires = FoldedFires::default();
        fires.push("é".repeat(MAX_FOLDED_FIRE_BYTES));
        assert!(fires.into_texts()[0].len() <= MAX_FOLDED_FIRE_BYTES);
    }
}
