//! Session persistence actor owns every durable execution transition.
//! A prepared admission is a conservative debit even if transport never starts.
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
    pub(crate) terminal: Option<TerminalReceipt>,
    #[serde(default)]
    known_session_edited_paths: Vec<String>,
    #[serde(default)]
    omitted_edited_paths: usize,
    #[serde(default)]
    grants: BTreeMap<String, GrantState>,
    #[serde(default)]
    child_aliases: BTreeMap<String, String>,
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
    Tools {
        ids: Vec<String>,
    },
    ToolsSettled {
        ids: Vec<String>,
    },
    Terminal {
        succeeded: bool,
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
}

#[derive(Debug)]
pub struct ExecutionMutation {
    key: String,
    change: Change,
}

fn denied(message: &'static str) -> io::Error {
    io::Error::other(message)
}

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
                return Err(denied("execution state missing"));
            };
            if *max_calls == 0 {
                return Err(denied("execution budget exhausted"));
            }
            Snapshot {
                version: 1,
                execution_id: uuid::Uuid::new_v4().to_string(),
                phase: Phase::Working,
                max_calls: *max_calls,
                calls: 0,
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
    if (state.phase == Phase::Terminal && !continuing_background)
        || state.deadline_ms.is_some_and(|d| now_ms >= d) {
        return Err(denied("execution is terminal or expired"));
    }
    if state.limits.total.is_some_and(|limit| state.total_tokens >= limit)
        || state.limits.output.is_some_and(|limit| state.output_tokens >= limit)
        || (state.unknown_usage && (state.limits.total.is_some() || state.limits.output.is_some())) {
        return Err(denied("execution token budget exhausted or unknown"));
    }
    if completion {
        if state.phase != Phase::Finalizing || state.completion_admitted || state.calls >= state.max_calls {
            return Err(denied("completion admission unavailable"));
        }
    } else if (state.phase != Phase::Working && !continuing_background)
        || state.calls >= state.max_calls.saturating_sub(1) {
        return Err(denied("execution completion capacity reserved"));
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
            if state.pending.remove(&attempt_id) {
                if let Some(usage) = usage {
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
            if state.terminal.is_none() {
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
                return Err(denied("child grant exhausted"));
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
                transition(state, Change::Tools { ids }, now_ms)?;
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct Execution {
    key: String,
    prompt_id: Mutex<String>,
    tx: mpsc::WeakUnboundedSender<PersistenceMsg>,
    deadline_ms: AtomicI64,
    parent_grant: Option<Arc<ChildGrant>>,
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
        let key = blake3::hash(format!("{session_id}\0{root_id}").as_bytes())
            .to_hex()
            .to_string();
        if let Some(existing) = Self::current(session_id).filter(|e| e.key == key) {
            *existing.prompt_id.lock().unwrap_or_else(|e| e.into_inner()) = prompt_id.to_owned();
            return Ok(existing);
        }
        let execution = Arc::new(Self {
            key,
            prompt_id: Mutex::new(prompt_id.to_owned()),
            tx: tx.downgrade(),
            deadline_ms: AtomicI64::new(i64::MAX),
            parent_grant,
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
        if state.phase != Phase::Terminal {
            if let Some(budget) =
                fuigo_sampler::execution_budget::process_budget().map_err(denied)?
            {
                budget.reserve_completion(&execution.key).map_err(denied)?;
            }
        }
        let mut registry = CURRENT
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        registry.retain(|_, execution| execution.tx.strong_count() > 0);
        registry.insert(session_id.to_owned(), execution.clone());
        Ok(execution)
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
        self.change(Change::Tools { ids }).await.map(|_| ())
    }
    pub(crate) async fn tools_settled(&self, ids: Vec<String>) -> io::Result<()> {
        if let Some(parent) = &self.parent_grant {
            Box::pin(parent.parent.tools_settled(parent.scoped_ids(ids.clone()))).await?;
        }
        self.change(Change::ToolsSettled { ids }).await.map(|_| ())
    }
    pub(crate) async fn terminal(&self, succeeded: bool) -> io::Result<TerminalReceipt> {
        let receipt = self
            .change(Change::Terminal { succeeded })
            .await?
            .terminal
            .ok_or_else(|| denied("terminal receipt missing"))?;
        if let Some(budget) = fuigo_sampler::execution_budget::process_budget().map_err(denied)? {
            budget.release_completion(&self.key);
        }
        Ok(receipt)
    }

    pub(crate) async fn record_edited_paths(&self, paths: BTreeSet<String>) -> io::Result<()> {
        self.change(Change::EditedPaths { paths }).await.map(|_| ())
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
            if let Some(parent) = &self.parent_grant {
                parent
                    .admit(attempt_id.clone())
                    .await
                    .map_err(|_| "parent execution admission denied or not durable".to_string())?;
            }
            self.change(Change::Admit {
                completion: purpose == RequestPurpose::Completion,
                optional: matches!(purpose, RequestPurpose::Title | RequestPurpose::Recap),
                attempt_id,
            })
            .await
            .map(|_| ())
            .map_err(|_| "execution admission denied or not durable".into())
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
}
