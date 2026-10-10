//! Session persistence actor: every session-file write for a session flows through one FIFO channel, drained by [`SessionPersistence::run`].
//!
//! # Loss contract on hard power loss
//!
//! - Fire-and-forget writes (streamed chunks, mid-turn tool records, feedback / btw_history appends) are buffered.
//!   Anything since the last barrier may be lost, bounded to the actively-running turn's tail.
//! - Anything a caller awaits (`FlushAndAck`, `AppendUpdateDurablyAndAck`, `AppendCwdSwitchAndAck`) is on stable media when the ack fires.
//!   A barrier syncs only the files dirtied since the last one.
//!   A failed buffered write (chat append, streamed update, …) latches until the next barrier.
//!   That barrier then returns the error instead of acking a sync of stale or missing bytes.
//! - Atomic-rename writes fsync the temp file before the rename, so replacing a file yields the old or the new content, never garbage.
//!   A create additionally syncs the containing directory, and session-dir creation syncs every directory the new chain is created into.
//!   So a first-time create (a session's first `summary.json`, and the session directory holding it) is durable once the write returns.
//!   Windows has no directory fsync; there NTFS metadata journaling can roll a very recent create back to absent, never to garbage.

use chrono::{DateTime, Utc};
use std::borrow::Cow;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::StorageMode;

use crate::remote::RemoteSync;

use crate::sampling::Client as OaiCompatClient;
use crate::sampling::ConversationItem;
use crate::session::export::ExportedMetadata;
use fuigo_workspace::session::file_state::RewindPoint;

use crate::session::signals::SessionSignals;
use crate::session::storage::relocation::{RelocationError, RelocationView};
use crate::session::storage::{JsonlStorageAdapter, StorageAdapter};
use crate::session::visibility::ClassifiedSessionKind;
use crate::tools::todo::TodoState;
use crate::util::fuigo_home::fuigo_home;
use agent_client_protocol as acp;
use fuigo_acp_lib::AcpAgentGatewaySender as GatewaySender;
use fuigo_sampling_types::ReasoningEffort;

use crate::extensions::notification::{
    DISK_FULL_ERROR_TYPE, DISK_FULL_USER_MESSAGE, RetryState,
    SessionNotification as FuigoSessionNotification, SessionUpdate as FuigoSessionUpdate,
};
use crate::session::info::Info;
use crate::session::replay_events::SessionEvent;
use tokio::sync::{mpsc, watch};

/// - Version 0: Legacy ChatRequestMessage format (default for old sessions)
/// - Version 1: ConversationItem format (used for new sessions)
pub const CHAT_FORMAT_VERSION: u8 = 1;

/// Maximum Unicode scalars in a session title (`/rename`, dashboard editor, and the `fuigo/session/rename` ext boundary).
/// Counted after control-strip and trim.
pub const MAX_TITLE_SCALARS: usize = 100;

/// UTF-8 byte ceiling before we bother stripping controls.
/// 4 bytes/scalar plus slack so a handful of C0 bytes that will be stripped don't trip a false reject.
/// Anything larger is already over the scalar cap.
pub const MAX_TITLE_BYTES: usize = MAX_TITLE_SCALARS * 4 + 64;

/// C0/C1 plus the bidi/format overrides the dashboard rename editor already rejects.
/// Shared by the persist path (drops these chars) and the display path (replaces them with U+FFFD) so the character class cannot drift.
#[inline]
pub fn is_forbidden_title_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            // The classes `fuigo_tty_utils::is_unsafe_display_char` added; ZWJ and ZWNJ stay legal in titles.
            // The tag block U+E0020..E007F is left out on purpose: `strip_loose_tags` keeps a valid flag's tags and drops the rest.
            | '\u{00AD}' | '\u{180E}' | '\u{2028}' | '\u{2029}' | '\u{FFF9}'..='\u{FFFB}'
            | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
        )
}

/// Drop C0/C1 and bidi/format controls, then trim.
/// The ext boundary, pull hydrate, and pager ingest share this.
/// A title therefore cannot carry terminal escapes or RTL overrides into `display_name` / `summary.json`.
///
/// Already-clean input is borrowed (trim is a subslice); only a title that actually contains forbidden chars allocates.
pub fn sanitize_rename_title(title: &str) -> Cow<'_, str> {
    let has_tag = title.chars().any(is_tag_char);
    if has_tag || title.chars().any(is_forbidden_title_char) {
        // Tags first: only a valid subdivision flag keeps its tags
        let tagged: Cow<'_, str> = if has_tag {
            Cow::Owned(fuigo_tty_utils::strip_loose_tags(title))
        } else {
            Cow::Borrowed(title)
        };
        let mut cleaned: String = tagged
            .chars()
            .filter(|c| !is_forbidden_title_char(*c))
            .collect();
        let trimmed = cleaned.trim();
        if trimmed.len() != cleaned.len() {
            cleaned = trimmed.to_string();
        }
        Cow::Owned(cleaned)
    } else {
        Cow::Borrowed(title.trim())
    }
}

/// The Unicode tag block, which only a valid subdivision flag may use
#[inline]
pub fn is_tag_char(c: char) -> bool {
    matches!(c, '\u{E0020}'..='\u{E007F}')
}

/// Sanitize then cap. `None` when the result is blank.
/// Overlong titles are truncated (ingest/pull defense); the ext rename path rejects instead.
pub fn sanitize_and_cap_title(title: &str) -> Option<String> {
    let cleaned = sanitize_rename_title(title);
    if cleaned.is_empty() {
        return None;
    }
    if cleaned.chars().count() <= MAX_TITLE_SCALARS {
        Some(cleaned.into_owned())
    } else {
        let head: String = cleaned.chars().take(MAX_TITLE_SCALARS).collect();
        // The cut can leave half a subdivision flag, whose loose tags would hide text
        Some(fuigo_tty_utils::strip_loose_tags(&head))
    }
}

#[derive(Debug, Clone)]
pub struct PersistenceContentChunk {
    content_chunks: Vec<acp::ContentBlock>,
}

impl PersistenceContentChunk {
    pub(crate) fn new(content_chunks: Vec<acp::ContentBlock>) -> Self {
        Self { content_chunks }
    }
}

/// Mirrors generated titles to the session registry after local persistence succeeds.
#[derive(Clone)]
pub(crate) struct RegistryGeneratedTitleSync {
    pub client: crate::agent::session_registry_client::SessionRegistryClient,
    pub suppress_for_zdr: bool,
}

use crate::session::storage::SessionUpdate;
use serde::{Deserialize, Serialize};

// /btw side question persistence types

/// A single /btw side question entry persisted to `btw_history.jsonl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BtwEntry {
    pub btw_session_id: String,
    pub parent_session_id: String,
    pub asked_at: DateTime<Utc>,
    pub question: String,
    /// The model's response (empty if failed).
    pub answer: String,
    pub model: String,
    pub success: bool,
    /// Error message if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Model-call attempts made (1 means no retry).
    /// Entries written before this field existed deserialize as 1.
    #[serde(default = "default_btw_attempts")]
    pub attempts: u32,
}

fn default_btw_attempts() -> u32 {
    1
}

// Local feedback persistence types

/// A feedback entry persisted to `~/.fuigo/sessions/.../feedback.jsonl`.
///
/// Uses a tagged enum so different feedback types are self-describing in the JSONL file (currently only `UserFeedback`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LocalFeedbackEntry {
    /// Regular user feedback (spontaneous or solicited via heuristics)
    UserFeedback(UserFeedbackEntry),
}

/// A user feedback entry (thumbs, stars, text, or dismiss).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserFeedbackEntry {
    pub submitted_at: DateTime<Utc>,
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_number: Option<i64>,
    /// Whether this was a response to a server-initiated FeedbackRequest
    pub solicited: bool,
    /// The feedback request ID (only set for solicited feedback)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// True if the user dismissed the feedback request without responding
    #[serde(default, skip_serializing_if = "is_false")]
    pub dismissed: bool,
    /// The full submission payload (omitted when dismissed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submission: Option<prod_mc_cli_chat_proxy_types::feedback_types::FeedbackSubmission>,
}

/// Helper for `#[serde(skip_serializing_if)]` on bool fields.
pub(crate) fn is_false(v: &bool) -> bool {
    !v
}

#[cfg(test)]
#[path = "persistence_feedback_tests.rs"]
mod feedback_tests;

#[derive(Debug, Clone)]
pub struct CopiedSessionFile {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SessionStateCopy {
    pub files: Vec<CopiedSessionFile>,
}

/// A turn's claim on the session's snapshot lock (P135, K17). [`SnapshotTurn::begin`] asks the persistence actor to take
/// the lock before the turn's first transcript echo; the drop sends the end, on every exit of the turn (success, an early
/// error, a cancel that drops the future, a panic), so the lifetime is the turn's and not inferred from message kinds.
pub(crate) struct SnapshotTurn {
    tx: tokio::sync::mpsc::UnboundedSender<PersistenceMsg>,
    turn_id: u64,
    /// The actor holds a `Weak` of this: it is alive exactly while the turn is, so the actor can tell a turn that is still
    /// running (its hold must stand, however long an image transcription takes) from one that is gone without an end.
    alive: std::sync::Arc<()>,
    send_end: bool,
}

impl SnapshotTurn {
    pub(crate) fn begin(tx: &tokio::sync::mpsc::UnboundedSender<PersistenceMsg>) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let turn_id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let alive = std::sync::Arc::new(());
        let _ = tx.send(PersistenceMsg::SnapshotBegin { turn_id, alive: std::sync::Arc::downgrade(&alive) });
        Self { tx: tx.clone(), turn_id, alive, send_end: true }
    }

    /// Test seam: the turn goes away and its end is lost.
    #[cfg(test)]
    pub(crate) fn drop_losing_the_end(mut self) {
        self.send_end = false;
    }
}

impl Drop for SnapshotTurn {
    fn drop(&mut self) {
        let _ = &self.alive;
        if self.send_end {
            let _ = self.tx.send(PersistenceMsg::SnapshotEnd { turn_id: self.turn_id });
        }
    }
}

/// Lets a caller stop waiting for a queued persistence request so that it never runs afterwards (P146): the actor
/// starts the request only if the caller has not given up, and the caller gives up only if it has not started.
#[derive(Debug, Clone, Default)]
pub struct AckGate(std::sync::Arc<std::sync::Mutex<AckGateState>>);

#[derive(Debug, Default, PartialEq, Eq)]
enum AckGateState {
    #[default]
    Queued,
    Started,
    Abandoned,
}

impl AckGate {
    /// Actor side: `true` when the request may run (the caller still waits).
    pub(crate) fn start(&self) -> bool {
        let mut state = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if *state == AckGateState::Queued {
            *state = AckGateState::Started;
        }
        *state == AckGateState::Started
    }

    /// Caller side: `true` when the request had not started and now never will.
    pub(crate) fn abandon(&self) -> bool {
        let mut state = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if *state == AckGateState::Queued {
            *state = AckGateState::Abandoned;
        }
        *state == AckGateState::Abandoned
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum PersistenceMsg {
    PresentationHints {
        hints: crate::session::tool_presentation::PresentationHints,
        respond_to: tokio::sync::oneshot::Sender<io::Result<()>>,
    },
    ExecutionState {
        mutation: crate::session::execution_state::ExecutionMutation,
        respond_to: tokio::sync::oneshot::Sender<io::Result<crate::session::execution_state::Snapshot>>,
    },
    CommitCompactionAndAck {
        checkpoint: crate::extensions::notification::CompactionCheckpointFile,
        activation: SessionUpdate,
        cancel: tokio_util::sync::CancellationToken,
        respond_to: tokio::sync::oneshot::Sender<Result<(), fuigo_chat_state::commands::CompactionCommitError>>,
    },
    Update(SessionUpdate),
    /// A turn is about to echo its prompt: take the session's snapshot lock and keep it until the matching
    /// [`PersistenceMsg::SnapshotEnd`] (P135, K17). Sent by [`SnapshotTurn::begin`].
    SnapshotBegin {
        turn_id: u64,
        /// Alive while the turn's [`SnapshotTurn`] exists: the hold's time limit applies only once it is gone.
        alive: std::sync::Weak<()>,
    },
    /// The turn `turn_id` has written its prompt (or left early): release the snapshot lock. Sent by the drop of
    /// [`SnapshotTurn`], so on every exit path. Ignored when `turn_id` does not hold the lock.
    SnapshotEnd {
        turn_id: u64,
    },
    AppendUpdateDurablyAndAck {
        update: SessionUpdate,
        respond_to:
            tokio::sync::oneshot::Sender<Result<(), crate::session::storage::AppendUpdateError>>,
    },
    ContentChunk(PersistenceContentChunk),
    Chat(ConversationItem),
    AppendCwdSwitchAndAck {
        item: ConversationItem,
        respond_to: tokio::sync::oneshot::Sender<
            Result<fuigo_chat_state::StrictAppendAck, fuigo_chat_state::StrictAppendError>,
        >,
    },
    /// Replace the entire chat history (used for compaction). Not acknowledged: a compaction's rewrite that does not
    /// land is recovered from disk by the compaction witness (later appends keep going to the file), and the failure
    /// fails the next FlushAndAck.
    ReplaceChatHistory(Vec<ConversationItem>),
    /// Replace the entire chat history and acknowledge the disk outcome (a rewind, which must not report success
    /// unless its history replacement persisted).
    ReplaceChatHistoryAndAck {
        messages: Vec<ConversationItem>,
        respond_to: tokio::sync::oneshot::Sender<io::Result<()>>,
    },
    /// Destructive image-strip rewrite: back up the on-disk history first, and only rewrite if the backup landed.
    /// Acks the combined disk outcome.
    ReplaceChatHistoryForStripAndAck {
        messages: Vec<ConversationItem>,
        respond_to: tokio::sync::oneshot::Sender<io::Result<()>>,
    },
    CurrentModel {
        model_id: acp::ModelId,
        /// The active agent definition name (e.g. `"fuigo-build"`).
        /// Persisted in `summary.agent_name` so session resume doesn't depend on the mutable model catalog.
        agent_name: Option<String>,
        reasoning_effort: Option<Option<ReasoningEffort>>,
    },
    PlanState(TodoState),
    PlanModeState(crate::session::plan_mode::PlanModeSnapshot),
    RewindPoint(RewindPoint),
    /// Truncate rewind points from a specific prompt index (inclusive).
    /// Syncs the persisted file with the in-memory FileStateTracker after rewind.
    TruncateRewindPoints {
        from_index: usize,
    },
    /// Merge rewind points at indices >= `target_index` into the previous point (read-modify-write on disk, after a ConversationOnly rewind).
    /// Disk is authoritative, so a partial in-memory tracker can't truncate history.
    MergeRewindPointsFrom {
        target_index: usize,
    },
    /// Take the rewind points rewrite lock for a rewind, before the rewind changes anything (P146). The reply carries
    /// the held lock, or the error that refuses the rewind (`WouldBlock`: another process kept it past the wait).
    /// Skipped when `gate` says the rewind stopped waiting before it started.
    LockRewindPointsRewrite {
        gate: AckGate,
        respond_to: tokio::sync::oneshot::Sender<io::Result<crate::session::storage::RewindPointsRewriteLock>>,
    },
    /// The rewind's rewrite of `rewind_points.jsonl`, made before the rewound conversation is saved, while the rewind
    /// holds the lock [`PersistenceMsg::LockRewindPointsRewrite`] took (P146, K19). The reply carries what the file
    /// held and what was written. The lock never travels in a message: one given up on cannot keep it.
    RewriteRewindPointsAndAck {
        rewrite: crate::session::storage::RewindPointsRewrite,
        /// What the rewind commits next, for its journal (P164); `None`: the rewind leaves the conversation as it is.
        conversation: Option<crate::session::storage::RewindConversation>,
        gate: AckGate,
        respond_to: tokio::sync::oneshot::Sender<io::Result<crate::session::storage::RewindPointsUndo>>,
    },
    /// The rewind of [`PersistenceMsg::RewriteRewindPointsAndAck`] is done. `put_back`: the rewound conversation was
    /// not saved, so the rewind did not go through and `rewind_points.jsonl` gets back what it held.
    EndRewindPointsAndAck {
        undo: crate::session::storage::RewindPointsUndo,
        put_back: bool,
        gate: AckGate,
        respond_to: tokio::sync::oneshot::Sender<io::Result<()>>,
    },
    /// Collection ID for telemetry tracing
    CollectionId(String),
    /// Monotonic telemetry turn counter and optional request_id for trace metadata/filenames.
    /// This is the "next turn" value (i.e., after increment).
    NextTraceTurn {
        next_trace_turn: u64,
        request_id: Option<String>,
    },
    Signals(SessionSignals),
    UsageTurn {
        turn_number: u32,
        live: crate::session::usage_file::UsageSummary,
    },
    /// Persist announcement tracking state (MCP and skill announcement dedup).
    AnnouncementState(crate::session::announcement_state::AnnouncementState),
    GoalModeState(crate::session::goal_tracker::GoalOrchestration),
    DeleteGoalModeState {
        respond_to: tokio::sync::oneshot::Sender<io::Result<()>>,
    },
    WorkflowRunState(crate::session::workflow::store::WorkflowRunManifest),
    WorkflowRunStateAndAck {
        manifest: crate::session::workflow::store::WorkflowRunManifest,
        respond_to: tokio::sync::oneshot::Sender<io::Result<()>>,
    },
    DeleteWorkflowRunState(String),
    Feedback(LocalFeedbackEntry),
    /// Persist a /btw side question entry
    Btw(BtwEntry),
    /// Persist updated HEAD commit and branch to summary.
    GitHead {
        commit: Option<String>,
        branch: Option<String>,
    },
    /// Persist a compaction checkpoint file to `compaction_checkpoints/{id}.json`.
    CompactionCheckpoint(crate::extensions::notification::CompactionCheckpointFile),
    /// Persist a compaction request and response artifact to `compaction_requests/{request_id}.json` for offline prompt iteration.
    /// The file holds the exact ConversationItem list sent to the compaction model plus the summary it returned (or the final error).
    /// It rides on the post-turn session archive to cloud storage automatically; no separate upload path is needed.
    CompactionRequest(crate::extensions::notification::CompactionRequestFile),
    /// Persist a recap request and response artifact to `recap_requests/{request_id}.json`.
    /// Same GCS ride-along as compaction requests; enables offline recap prompt / garble replay.
    RecapRequest(crate::extensions::notification::RecapRequestFile),
    /// Persist a compaction segment (`Segments` mode).
    CompactionSegment(crate::extensions::notification::CompactionSegmentFile),
    /// Generated session title from background LLM task.
    /// Routed back through the persistence channel so the storage write stays sequential with other summary.json mutations.
    GeneratedTitle(String),
    /// P121 (K6): rebuilt title client after a model switch or a catalog reload.
    ReplaceSummaryHelper(crate::session::summary::SummaryHelper),
    /// Early-session title refresh (turns 3 and 6): overwrite an existing auto title with one regenerated from the whole conversation.
    /// Never overwrites a manual `/rename` (enforced atomically under the summary lock).
    RegenerateTitle(String),
    /// Persist a bounded preview of the latest session recap so session listings can show it whenever available.
    /// `None` clears it (rewind removed the described turns).
    LastRecap(Option<String>),
    /// Manual `/rename` title.
    /// Rides this FIFO channel so the resulting `SetTitle` cannot race a `GeneratedTitle` `SetTitle` out-of-band.
    ManualTitleRenamed(String),
    /// `/rename --auto`: reset [`crate::session::summary::SummaryGenerator`] so the next content chunk regenerates.
    /// Storage is already cleared by the ext handler; remote stores stay untouched until the fresh auto title is adopted.
    ResetTitleToAuto,
    /// Per-turn dashboard summary as `(text, prompt_id)`.
    /// Replaces (`Some`) or clears (`None`, on conversation rewind) the previous one in `summary.json`.
    LastTurnSummary(Option<(String, String)>),
    /// Enable remote writeback for a session created `Local` before remote settings resolved (non-blocking startup); backfills its local history.
    UpgradeToWriteback {
        auth_manager: Arc<crate::auth::AuthManager>,
    },
    Flush,
    /// Flush all pending writes AND fsync the session files, then signal the caller.
    /// Unlike `Flush` (fire-and-forget, page-cache only), this is a **sync barrier**.
    /// The caller's oneshot resolves only after all prior writes are on stable media.
    FlushAndAck {
        respond_to: tokio::sync::oneshot::Sender<io::Result<()>>,
    },
    ProbeWritable {
        respond_to: tokio::sync::oneshot::Sender<io::Result<()>>,
    },
    /// Flush all pending writes, then copy the current session directory contents and return the in-memory snapshot to the caller.
    /// The caller can tar.gz and upload the copy to GCS, etc.
    CopyFile {
        one_shot: tokio::sync::oneshot::Sender<anyhow::Result<SessionStateCopy>>,
    },
}

/// Scripted compaction fixtures retain their observation channel while using
/// real temporary checkpoint/activation writes for the mandatory acknowledgement.
#[cfg(test)]
pub(crate) async fn compaction_fixture_persistence(
    observed: mpsc::UnboundedSender<PersistenceMsg>,
) -> mpsc::UnboundedSender<PersistenceMsg> {
    let dir = tempfile::tempdir().unwrap();
    let storage = JsonlStorageAdapter::with_explicit_session_dir(dir.path().to_path_buf());
    let info = Info { id: acp::SessionId::new("compaction-fixture"), cwd: "/tmp".into() };
    storage.init_session(&info, default_model_id()).await.unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let _owned_dir = dir;
        while let Some(message) = rx.recv().await {
            match message {
                PersistenceMsg::CommitCompactionAndAck { checkpoint, activation, cancel, respond_to } => {
                    use fuigo_chat_state::commands::CompactionCommitError;
                    let result = async {
                        if cancel.is_cancelled() {
                            return Err(CompactionCommitError::NotCommitted(io::Error::other("cancelled fixture")));
                        }
                        storage.write_compaction_checkpoint(&info, &checkpoint).await.map_err(CompactionCommitError::NotCommitted)?;
                        storage.append_update_durable_commit_aware(&info, &activation).await.map_err(|error| match error {
                            crate::session::storage::AppendUpdateError::NotCommitted(error) => CompactionCommitError::NotCommitted(error),
                            crate::session::storage::AppendUpdateError::Committed(error) => CompactionCommitError::Committed(error),
                        })?;
                        let _ = observed.send(PersistenceMsg::CompactionCheckpoint(checkpoint));
                        let _ = observed.send(PersistenceMsg::Update(activation));
                        Ok(())
                    }.await;
                    let _ = respond_to.send(result);
                }
                PersistenceMsg::ReplaceChatHistoryAndAck { messages, respond_to } => {
                    let _ = respond_to.send(Ok(()));
                    let _ = observed.send(PersistenceMsg::ReplaceChatHistory(messages));
                }
                // In this scripted fixture the ordinary messages are observations,
                // not disk writes. FIFO acknowledgment ensures the observer sees
                // all messages preceding the barrier before inspecting its queue.
                PersistenceMsg::FlushAndAck { respond_to } => {
                    let _ = respond_to.send(Ok(()));
                }
                other => { let _ = observed.send(other); }
            }
        }
    });
    tx
}

pub use fuigo_shared::session::session_dir;

type RelocationResult<T> = crate::session::storage::relocation::Result<T>;
type SummaryReader = fn(&Path) -> RelocationResult<Summary>;

// Test-only count of `storage_view` loads on this thread, so a batch API can pin "one view per
// call" rather than merely "the right answer". Thread-local because the suite runs tests in
// parallel and each test body owns its own thread.
#[cfg(test)]
thread_local! {
    pub(crate) static STORAGE_VIEW_LOADS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test-only reader for [`STORAGE_VIEW_LOADS`].
#[cfg(test)]
pub(crate) fn storage_view_loads() -> usize {
    STORAGE_VIEW_LOADS.with(std::cell::Cell::get)
}

fn storage_view(sessions_root: &Path) -> RelocationResult<RelocationView> {
    #[cfg(test)]
    STORAGE_VIEW_LOADS.with(|n| n.set(n.get() + 1));
    RelocationView::load_for_sessions_root(sessions_root)
}

/// Check if a session exists locally under the given cwd.
///
/// This is the correct check for the `-r` resume path.
/// A session is only "already local" if it lives under the **same** cwd as the current invocation.
/// A session stored under a different cwd does NOT satisfy this check; the caller must still run the remote restore into the requested cwd.
pub fn session_exists_for_cwd(session_id: &str, cwd: &str) -> bool {
    let sessions_root = crate::util::fuigo_home::fuigo_home().join("sessions");
    session_exists_for_cwd_in_root(session_id, cwd, &sessions_root)
}

/// A directory is a resumable session only if it has a `summary.json`; this skips `images/`-only stubs that would otherwise hijack `--resume`.
/// Used by the resume/restore resolution path; `find_session_dir_by_id` intentionally stays dir-only for non-resume compatibility.
fn is_persisted_session_dir(session_path: &Path) -> bool {
    session_path.join("summary.json").is_file()
}

/// Inner implementation of `session_exists_for_cwd` with an injectable root.
/// Separated for deterministic tempdir-based tests.
fn session_exists_for_cwd_in_root(session_id: &str, cwd: &str, sessions_root: &Path) -> bool {
    let encoded = crate::util::fuigo_home::encode_cwd_dirname(cwd);
    let session_path = sessions_root.join(&encoded).join(session_id);
    is_persisted_session_dir(&session_path)
}

/// Find the local child session id that was previously restored from `remote_session_id` in the given `cwd`.
///
/// When a remote session is restored, a new local child is created with `summary.parent_session_id == remote_session_id`.
/// On a second `fuigo -r <remote_id>` in the same cwd, this function returns the already-restored child so no duplicate restore is performed.
///
/// If multiple children match (e.g., from older duplicate restores), the most recently used one is returned.
/// Selection is fully deterministic:
/// 1. Newest `updated_at` timestamp in `summary.json`
/// 2. Newest session directory mtime as a tie-breaker (catches equal timestamps)
/// 3. Lexicographically largest session id as the final stable tie-breaker
///
/// Returns `Some(local_child_id)` when at least one matching child is found.
pub fn find_local_child_for_remote(remote_session_id: &str, cwd: &str) -> Option<String> {
    let sessions_root = crate::util::fuigo_home::fuigo_home().join("sessions");
    find_local_child_for_remote_in_root(remote_session_id, cwd, &sessions_root)
}

/// Resolve a session ID to one that is available locally under `cwd`.
///
/// Checks in order:
///   1. `session_id` exists directly under `cwd`: returns it as-is.
///   2. A previously restored child of `session_id` exists: returns the child ID.
///   3. Neither found: returns `None` (caller should restore from remote).
pub fn resolve_local_session(session_id: &str, cwd: &str) -> Option<String> {
    if session_exists_for_cwd(session_id, cwd) {
        return Some(session_id.to_string());
    }
    find_local_child_for_remote(session_id, cwd)
}

// Repo-wide session resolution (for worktree resume)

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LocalSessionResolutionKind {
    ExactCwd,
    RestoredChildInExactCwd,
    SameRepoDifferentCwd,
    RestoredChildInSameRepoDifferentCwd,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResolvedLocalSession {
    pub session_id: String,
    pub cwd: String,
    pub resolution_kind: LocalSessionResolutionKind,
}

/// Resolve a session across multiple candidate cwds for worktree resume.
///
/// The first cwd in `candidate_cwds` should be the exact current cwd so it gets priority.
/// For each candidate, checks both direct session existence and previously-restored children.
///
/// Returns `None` when no local match exists in any candidate.
pub(crate) fn resolve_local_session_for_repo(
    session_id: &str,
    candidate_cwds: &[&str],
) -> Option<ResolvedLocalSession> {
    let sessions_root = crate::util::fuigo_home::fuigo_home().join("sessions");
    resolve_local_session_for_repo_in_root(session_id, candidate_cwds, &sessions_root)
}

pub(crate) fn resolve_local_session_for_repo_in_root(
    session_id: &str,
    candidate_cwds: &[&str],
    sessions_root: &Path,
) -> Option<ResolvedLocalSession> {
    for (i, &cwd) in candidate_cwds.iter().enumerate() {
        let is_exact = i == 0;

        if session_exists_for_cwd_in_root(session_id, cwd, sessions_root) {
            return Some(ResolvedLocalSession {
                session_id: session_id.to_owned(),
                cwd: cwd.to_owned(),
                resolution_kind: if is_exact {
                    LocalSessionResolutionKind::ExactCwd
                } else {
                    LocalSessionResolutionKind::SameRepoDifferentCwd
                },
            });
        }

        if let Some(child_id) = find_local_child_for_remote_in_root(session_id, cwd, sessions_root)
        {
            return Some(ResolvedLocalSession {
                session_id: child_id,
                cwd: cwd.to_owned(),
                resolution_kind: if is_exact {
                    LocalSessionResolutionKind::RestoredChildInExactCwd
                } else {
                    LocalSessionResolutionKind::RestoredChildInSameRepoDifferentCwd
                },
            });
        }
    }
    None
}
fn find_local_child_for_remote_in_root(
    remote_session_id: &str,
    cwd: &str,
    sessions_root: &Path,
) -> Option<String> {
    let encoded = crate::util::fuigo_home::encode_cwd_dirname(cwd);
    let cwd_dir = sessions_root.join(&encoded);
    if !cwd_dir.exists() {
        return None;
    }

    // Collect all matching children
    // Multiple can exist from older versions that restored a duplicate on each `fuigo -r <remote_id>`
    // Tuple: (updated_at, dir_mtime_nanos, session_id), all sorted descending
    let mut candidates: Vec<(String, u128, String)> = Vec::new();

    let entries = std::fs::read_dir(&cwd_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let summary_path = path.join("summary.json");
        if !summary_path.exists() {
            continue;
        }
        // Parse minimum fields without deserializing the full Summary, so we don't fail on missing/extra fields from older/newer formats
        if let Ok(raw) = std::fs::read_to_string(&summary_path)
            && let Ok(partial) = serde_json::from_str::<serde_json::Value>(&raw)
            && partial.get("parent_session_id").and_then(|v| v.as_str()) == Some(remote_session_id)
            && let Some(session_id) = path.file_name().and_then(|n| n.to_str())
        {
            let updated_at = partial
                .get("updated_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // Directory mtime as a tie-breaker for equal updated_at values.
            let dir_mtime = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .map(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0)
                })
                .unwrap_or(0);
            candidates.push((updated_at, dir_mtime, session_id.to_string()));
        }
    }

    // Sort descending by all three keys for full determinism.
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)).then(b.2.cmp(&a.2)));
    candidates.into_iter().next().map(|(_, _, id)| id)
}

/// Check if a session exists locally by session ID.
/// Searches across ALL cwd directories under `~/.fuigo/sessions/`.
///
/// Use `session_exists_for_cwd` instead when the target cwd is known (e.g., the `-r` resume path) to avoid false-positive matches.
/// Find a session by ID across **all** CWD directories under `~/.fuigo/sessions/`.
///
/// Unlike [`resolve_local_session`] which only checks a single CWD, this scans every encoded-CWD subdirectory.
/// Returns the decoded CWD path that contains the session, or `None` if not found anywhere.
///
/// The pager's `--resume` uses this to find sessions created in a different CWD (e.g., a worktree) than the one the user is currently in.
pub fn resolve_local_session_any_cwd(session_id: &str) -> Option<String> {
    resolve_local_session_any_cwd_result(session_id)
        .ok()
        .flatten()
}

/// Resolve a batch of candidate IDs against one point-in-time storage view.
/// Loading [`RelocationView`] walks the local session tree, so callers that need to classify a list must use this API rather than calling [`resolve_local_session_any_cwd`] once per entry.
pub fn resolve_local_session_ids_any_cwd<S: AsRef<str>>(
    session_ids: &[S],
) -> io::Result<std::collections::HashSet<String>> {
    resolve_local_session_ids_any_cwd_in_root(session_ids, &fuigo_home().join("sessions"))
        .map_err(io::Error::other)
}

fn resolve_local_session_ids_any_cwd_in_root<S: AsRef<str>>(
    session_ids: &[S],
    sessions_root: &Path,
) -> RelocationResult<std::collections::HashSet<String>> {
    let view = storage_view(sessions_root)?;
    Ok(session_ids
        .iter()
        .map(AsRef::as_ref)
        .filter(|session_id| {
            view.find_persisted_session_dir(session_id)
                .is_ok_and(|path| path.is_some())
        })
        .map(str::to_owned)
        .collect())
}

pub(crate) fn resolve_local_session_any_cwd_result(session_id: &str) -> io::Result<Option<String>> {
    resolve_local_session_any_cwd_in_root(session_id, &fuigo_home().join("sessions"))
        .map_err(io::Error::other)
}

fn resolve_local_session_any_cwd_in_root(
    session_id: &str,
    sessions_root: &Path,
) -> Result<Option<String>, crate::session::storage::relocation::RelocationError> {
    let Some(session_path) = storage_view(sessions_root)?.find_persisted_session_dir(session_id)?
    else {
        return Ok(None);
    };
    Ok(session_path
        .parent()
        .and_then(crate::util::fuigo_home::decode_cwd_from_dirname))
}

/// Scan all CWD directories for a session and return its directory path.
pub fn find_session_dir_by_id(session_id: &str) -> Option<PathBuf> {
    find_any_session_dir_by_id_result(session_id).ok().flatten()
}

pub(crate) fn find_persisted_session_dir_by_id_result(
    session_id: &str,
) -> io::Result<Option<PathBuf>> {
    find_persisted_session_dir_by_id_in_root_result(session_id, &fuigo_home().join("sessions"))
}

pub(crate) fn find_persisted_session_dir_by_id_in_root_result(
    session_id: &str,
    sessions_root: &Path,
) -> io::Result<Option<PathBuf>> {
    storage_view(sessions_root)
        .and_then(|view| view.find_persisted_session_dir(session_id))
        .map_err(io::Error::other)
}

pub(crate) fn find_any_session_dir_by_id_result(session_id: &str) -> io::Result<Option<PathBuf>> {
    storage_view(&fuigo_home().join("sessions"))
        .and_then(|view| view.find_any_session_dir(session_id))
        .map_err(io::Error::other)
}

#[cfg(test)]
fn session_exists_in_root(session_id: &str, sessions_root: &Path) -> bool {
    find_persisted_session_dir_by_id_in_root_result(session_id, sessions_root)
        .is_ok_and(|path| path.is_some())
}

/// Whether a session dir's `summary.json` records a manual `/rename` (`false` if missing/unreadable).
/// Cheap read for paths that only need the manual flag without loading the full session.
pub(crate) fn title_is_manual_in_dir(session_dir: &Path) -> bool {
    std::fs::read(session_dir.join("summary.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Summary>(&bytes).ok())
        .is_some_and(|summary| summary.title_is_manual)
}

/// Find and read a session summary given only its ID (scans all CWD directories).
pub(crate) fn find_summary_by_session_id(session_id: &str) -> Option<Summary> {
    find_summary_by_session_id_in_root(session_id, &fuigo_home().join("sessions"))
}

/// Inner implementation with injectable root for testing.
pub(crate) fn find_summary_by_session_id_in_root(
    session_id: &str,
    sessions_root: &Path,
) -> Option<Summary> {
    let path = storage_view(sessions_root)
        .ok()?
        .find_persisted_session_dir(session_id)
        .ok()
        .flatten()?;
    read_summary_from_dir(&path).ok()
}

fn read_summary_from_dir(session_dir: &Path) -> RelocationResult<Summary> {
    let path = session_dir.join("summary.json");
    let bytes = std::fs::read(&path).map_err(|error| RelocationError::Io {
        operation: "read",
        path: path.clone(),
        source: error,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| RelocationError::Json { path, source })
}

/// Dir index plus on-demand summary reads.
/// Search classifies only the FTS hits it walks.
/// Loading every `summary.json` on each query is too expensive at the ~12K-session scale already called out for recent listing.
pub(crate) struct SessionKindIndex {
    view: RelocationView,
}

impl SessionKindIndex {
    pub(crate) fn load() -> io::Result<Self> {
        Self::load_in_root(&fuigo_home().join("sessions"))
    }

    pub(crate) fn load_in_root(sessions_root: &Path) -> io::Result<Self> {
        Ok(Self {
            view: storage_view(sessions_root).map_err(io::Error::other)?,
        })
    }

    pub(crate) fn kind(&self, session_id: &str) -> ClassifiedSessionKind {
        match self.view.find_persisted_session_dir(session_id) {
            Ok(Some(dir)) => match read_summary_from_dir(&dir) {
                Ok(summary) if summary.is_headless() => ClassifiedSessionKind::Headless,
                Ok(_) => ClassifiedSessionKind::Interactive,
                Err(_) => ClassifiedSessionKind::Unknown,
            },
            Ok(None) | Err(_) => ClassifiedSessionKind::Unknown,
        }
    }
}

/// Which local rows may satisfy a most-recent startup selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecentSessionSelection {
    Interactive,
    Any,
}

impl RecentSessionSelection {
    /// Used at startup: `Exclude` selects only interactive most-recent rows; `Include`/`Only` keep headless rows eligible (`-p` continuation).
    pub fn from_headless_policy(policy: crate::session::visibility::HeadlessPolicy) -> Self {
        match policy {
            crate::session::visibility::HeadlessPolicy::Exclude => Self::Interactive,
            crate::session::visibility::HeadlessPolicy::Only
            | crate::session::visibility::HeadlessPolicy::Include => Self::Any,
        }
    }

    pub fn admits(self, summary: &Summary) -> bool {
        match self {
            Self::Interactive => !summary.is_headless(),
            Self::Any => true,
        }
    }
}

/// The most recently updated interactive local session summary for `cwd`.
fn most_recent_local_summary_for_cwd_in_root(cwd: &str, sessions_root: &Path) -> Option<Summary> {
    most_recent_local_summary_for_cwd_in_view(
        cwd,
        &storage_view(sessions_root).ok()?,
        read_summary_from_dir,
        RecentSessionSelection::Interactive,
    )
    .ok()
    .flatten()
}

fn most_recent_local_summary_for_cwd_in_view(
    cwd: &str,
    view: &RelocationView,
    read_summary: SummaryReader,
    selection: RecentSessionSelection,
) -> RelocationResult<Option<Summary>> {
    let mut best: Option<Summary> = None;
    for session_dir in view.session_dirs(Some(cwd))? {
        let summary = match read_summary(&session_dir) {
            Ok(summary) => summary,
            Err(RelocationError::Json { .. }) => continue,
            Err(RelocationError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                continue;
            }
            Err(error) => return Err(error),
        };
        if summary.is_hidden() || summary.is_unused_optimistic_husk() || !selection.admits(&summary)
        {
            continue;
        }
        if best.as_ref().is_none_or(|current| {
            let time = summary.last_active_at.unwrap_or(summary.updated_at);
            let current_time = current.last_active_at.unwrap_or(current.updated_at);
            time > current_time
                || (time == current_time && summary.info.id.0.as_ref() < current.info.id.0.as_ref())
        }) {
            best = Some(summary);
        }
    }
    Ok(best)
}

/// Sync, local-only summaries for `cwd` under the caller's title-selection policy.
/// Explicit-id lookup remains inclusive through [`find_summary_by_session_id`].
/// For startup paths that must resolve a resume target before the irreversible OS sandbox is applied; async callers use [`list_summaries`].
///
/// Listing failures propagate so pre-sandbox callers can fail closed.
/// Individual unreadable summaries are skipped, matching the async path's tolerance for a single corrupt file.
pub fn local_summaries_for_cwd_sync(
    cwd: &str,
    selection: RecentSessionSelection,
) -> io::Result<Vec<Summary>> {
    local_summaries_for_cwd_sync_in_root(cwd, selection, &fuigo_home().join("sessions"))
}

fn local_summaries_for_cwd_sync_in_root(
    cwd: &str,
    selection: RecentSessionSelection,
    sessions_root: &Path,
) -> io::Result<Vec<Summary>> {
    let view = storage_view(sessions_root).map_err(io::Error::other)?;
    let dirs = view.session_dirs(Some(cwd)).map_err(io::Error::other)?;
    Ok(dirs
        .iter()
        .filter_map(|dir| read_summary_from_dir(dir).ok())
        .filter(|summary| !summary.is_hidden() && selection.admits(summary))
        .collect())
}

/// Best-effort lookup of the sandbox profile persisted with a session that is about to be resumed.
/// Used at startup to restore the session's profile before the (irreversible) OS sandbox is applied.
///
/// - `session_id`: the explicit id from `--resume <id>` / `--load <id>` / `-s <id>`.
///   Resolved directly across all cwds, then (for a remote id that was restored into a local child) via that child's `parent_session_id`.
/// - `cwd`: the current working directory.
///   Used to resolve a remote id to its local child, and as the lookup key for `-c` / `--continue` and bare `--resume` (most-recent-for-cwd).
///
/// Returns `None` when not resuming, the session isn't found locally, or it has no persisted profile (sessions created before this was tracked).
/// Callers then fall back to the normal config/CLI resolution.
pub fn resumed_session_sandbox_profile(
    session_id: Option<&str>,
    cwd: Option<&str>,
) -> Option<String> {
    resumed_session_sandbox_profile_in_root(session_id, cwd, &fuigo_home().join("sessions"))
}

/// Resolve the saved profile for the same typed most-recent view used at startup.
pub fn resolve_recent_session_sandbox_profile(
    cwd: Option<&str>,
    selection: RecentSessionSelection,
) -> Option<String> {
    most_recent_local_summary_for_cwd_in_view(
        cwd?,
        &storage_view(&fuigo_home().join("sessions")).ok()?,
        read_summary_from_dir,
        selection,
    )
    .ok()
    .flatten()
    .and_then(|summary| summary.sandbox_profile)
}

fn resumed_session_sandbox_profile_in_root(
    session_id: Option<&str>,
    cwd: Option<&str>,
    sessions_root: &Path,
) -> Option<String> {
    if let Some(id) = session_id.filter(|s| !s.is_empty()) {
        // Direct match by id (across all cwds).
        if let Some(summary) = find_summary_by_session_id_in_root(id, sessions_root) {
            return summary.sandbox_profile;
        }
        // A remote id resumes into a local child (fresh id, `parent_session_id` set to the remote id)
        // Mirror the canonical resume path so the peek doesn't miss the restored session's saved profile
        if let Some(cwd) = cwd
            && let Some(child) = find_local_child_for_remote_in_root(id, cwd, sessions_root)
        {
            return find_summary_by_session_id_in_root(&child, sessions_root)
                .and_then(|s| s.sandbox_profile);
        }
        return None;
    }
    if let Some(cwd) = cwd {
        return most_recent_local_summary_for_cwd_in_root(cwd, sessions_root)
            .and_then(|s| s.sandbox_profile);
    }
    None
}

/// Owner-only and durable session dir for writers that bypass `init_session` (chat-kind, pre-init fork stamp).
/// A later occupied `init_session` will not re-sync the encoded-cwd direntry.
pub(crate) fn ensure_owner_only_session_dir(info: &Info) -> std::io::Result<PathBuf> {
    ensure_owner_only_session_dir_in(&fuigo_home(), info)
}

/// Inner implementation with an injectable fuigo home for tests.
fn ensure_owner_only_session_dir_in(fuigo_home: &Path, info: &Info) -> std::io::Result<PathBuf> {
    ensure_owner_only_session_dir_in_with(
        fuigo_home,
        info,
        crate::session::storage::sync_dir_durable,
        crate::session::storage::sync_file_durable,
    )
}

fn ensure_owner_only_session_dir_in_with(
    fuigo_home: &Path,
    info: &Info,
    sync_dir: impl Fn(&Path) -> std::io::Result<()>,
    sync_file: impl Fn(&std::fs::File) -> std::io::Result<()>,
) -> std::io::Result<PathBuf> {
    let dir = session_dir_in(fuigo_home, info);
    crate::session::storage::create_dir_all_durable_with(
        &dir,
        |dir| {
            // Keep swallowing ensure errors: other failures must not block session-dir create
            // But fsync `.cwd` on Ok so a later parent-dir sync cannot freeze a torn marker
            if let Ok(cwd_dir) =
                crate::util::fuigo_home::ensure_sessions_cwd_dir_in(fuigo_home, &info.cwd)
            {
                crate::session::storage::sync_cwd_marker_if_present_with(&cwd_dir, &sync_file)?;
            }
            crate::util::fuigo_home::create_dir_all_owner_only(dir)
        },
        sync_dir,
    )?;
    Ok(dir)
}

/// `session_dir` with an injectable fuigo home (pure path computation).
fn session_dir_in(fuigo_home: &Path, info: &Info) -> PathBuf {
    crate::util::fuigo_home::sessions_cwd_dir_in(fuigo_home, &info.cwd).join(info.id.to_string())
}

/// Get file path for storing a large prompt.
/// Creates the prompts subdirectory if it doesn't exist.
/// Path format: `{session_dir}/prompts/prompt_{prompt_index}.txt`
pub(crate) fn get_prompt_file_path(info: &Info, prompt_index: usize) -> PathBuf {
    get_prompt_file_path_in(&fuigo_home(), info, prompt_index)
}

/// Inner implementation with an injectable fuigo home for tests.
fn get_prompt_file_path_in(fuigo_home: &Path, info: &Info, prompt_index: usize) -> PathBuf {
    // Best-effort; failures surface on the prompt-file write itself.
    let _ = ensure_owner_only_session_dir_in(fuigo_home, info);
    let prompts_dir = session_dir_in(fuigo_home, info).join("prompts");
    let _ = crate::util::fuigo_home::create_dir_all_owner_only(&prompts_dir);
    prompts_dir.join(format!("prompt_{}.txt", prompt_index))
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingCwdSwitchReminder {
    pub cwd_generation: u64,
    pub previous_cwd: String,
    #[serde(alias = "cwd")]
    pub destination_cwd: String,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_project_instructions: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Summary {
    pub info: Info,
    /// Monotonic generation of the authoritative cwd in `info.cwd`.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cwd_generation: u64,
    /// Cwd immediately preceding the current generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_cwd: Option<String>,
    /// Reminder staged for exactly-once append during relocation completion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_cwd_switch_reminder: Option<PendingCwdSwitchReminder>,
    /// Latest switch generation reflected in `num_chat_messages` bookkeeping.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cwd_switch_bookkeeping_generation: u64,
    pub session_summary: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub num_messages: usize,
    #[serde(default)]
    pub num_chat_messages: usize,
    pub current_model_id: acp::ModelId,
    /// Parent session ID if this session was forked from another session
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forked_at: Option<DateTime<Utc>>,
    /// Collection ID for telemetry trace uploads (one per session)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection_id: Option<String>,
    /// Next telemetry trace turn id (monotonic, persisted).
    /// Used to generate unique turn ids for telemetry metadata/filenames even across rewinds.
    #[serde(default)]
    pub next_trace_turn: u64,
    /// Chat history format version:
    /// - 0 (default): Legacy ChatRequestMessage format
    /// - 1: ConversationItem format
    #[serde(default)]
    pub chat_format_version: u8,
    /// Stable display path for forked sessions.
    ///
    /// When set, the system prompt's `Workspace Path` and prompt metadata paths show this value instead of the worktree/overlay path (`info.cwd`).
    /// Persisted so the override survives session restore/reload without the caller needing to resend it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_display_cwd: Option<String>,
    /// What created this session: `"fork"`, `"subagent"`, `"subagent_fork"`, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_kind: Option<String>,
    /// How the session's initial context was bootstrapped: `"new"` or `"forked"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_context_source: Option<String>,
    /// The parent prompt/turn ID that triggered this fork.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_parent_prompt_id: Option<String>,
    /// Number of conversation items inherited from the parent session.
    /// During compaction, items below this index are preserved as-is (the "inherited prefix").
    /// Only items after this boundary are summarized.
    /// `None` means no inherited prefix (non-forked session).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited_prefix_len: Option<usize>,
    /// Visibility override. `None` means the default for `session_kind`, `Some` is explicit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
    /// The original workspace directory this worktree session was spawned from.
    /// Used by clients to group worktree sessions under their source workspace regardless of the worktree's actual `cwd`.
    /// Only set when `session_kind == "worktree"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_workspace_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_root_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub git_remotes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Absolute path to the `.fuigo` directory, used by reconstruction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuigo_home: Option<String>,
    /// When the session last had content added (user or model messages).
    /// Only advanced locally by `append_update` / `append_chat_message`; never touched by remote registry operations or metadata-only writes.
    /// `None` for sessions created before this field was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_active_at: Option<DateTime<Utc>>,
    /// LLM-generated session title persisted separately from `session_summary`.
    /// When present, this is preferred for display over `session_summary`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_title: Option<String>,
    /// True when `generated_title` was set by a manual `/rename` (vs auto LLM title).
    /// Manual titles render inline in the prompt's top border on resume.
    #[serde(default, skip_serializing_if = "is_false")]
    pub title_is_manual: bool,
    /// Human-readable label for the worktree directory (e.g. "nuke-v-tables").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree_label: Option<String>,
    /// The agent definition name that was active when the session was last saved.
    /// Used during session resume to avoid re-deriving from the (mutable) model catalog.
    /// If the model is removed or its `agent_type` changes between sessions, the persisted value still restores the correct harness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    /// The OS sandbox profile this session ran under (e.g. "workspace", "strict", "off", or a custom name).
    /// Persisted so a resumed session is restored to the same profile instead of silently falling back to the config default.
    /// A fallback would break commands that worked before (a stricter profile denies filesystem/network the session relied on).
    /// `None` for sessions created before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<ReasoningEffort>,
    /// Ultra-short summary of the most recent successful turn, shown as the dashboard row's secondary line (via the roster for non-attached clients).
    /// Displayed until replaced by the next successful turn (or cleared by a conversation rewind).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_turn_summary: Option<String>,
    /// Prompt id of the turn `last_turn_summary` describes (provenance).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_turn_summary_prompt_id: Option<String>,
    /// Bounded preview of the most recent session recap ("where was I").
    /// Persisted so session listings (`/resume`, `/session-info`) can show it whenever available.
    /// Distinct from `last_turn_summary` (a summary of the final turn only).
    /// Regenerated on demand by `/recap`; this holds the last committed value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_recap: Option<String>,
}

/// `Summary::session_kind` for sessions whose cwd is inside a fuigo-managed worktree.
/// `source_workspace_dir` is only ever set alongside this kind.
pub(crate) const WORKTREE_SESSION_KIND: &str = "worktree";

/// Current `fuigo_home` as a UTF-8 string, or `None` if the path isn't valid UTF-8.
pub(crate) fn fuigo_home_string() -> Option<String> {
    crate::util::fuigo_home::fuigo_home()
        .to_str()
        .map(String::from)
}

pub fn default_model_id() -> acp::ModelId {
    acp::ModelId::new(crate::models::default_model())
}

impl Summary {
    pub(crate) fn new(info: &Info, model_id: acp::ModelId) -> std::io::Result<Self> {
        let git_metadata =
            fuigo_workspace::session::git::resolve_persisted_session_git_metadata_sync(
                std::path::Path::new(&info.cwd),
            );
        let mut summary = Self {
            info: info.clone(),
            cwd_generation: 0,
            previous_cwd: None,
            pending_cwd_switch_reminder: None,
            cwd_switch_bookkeeping_generation: 0,
            session_summary: String::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            num_messages: 0,
            num_chat_messages: 0,
            current_model_id: model_id,
            parent_session_id: None,
            forked_at: None,
            collection_id: None,
            next_trace_turn: 0,
            chat_format_version: CHAT_FORMAT_VERSION,
            prompt_display_cwd: None,
            session_kind: None,
            fork_context_source: None,
            fork_parent_prompt_id: None,
            inherited_prefix_len: None,
            hidden: None,
            source_workspace_dir: None,
            git_root_dir: git_metadata.git_root_dir,
            git_remotes: git_metadata.git_remotes,
            head_commit: git_metadata.head_commit,
            head_branch: git_metadata.head_branch,
            request_id: None,
            fuigo_home: fuigo_home_string(),
            last_active_at: None,
            generated_title: None,
            title_is_manual: false,
            worktree_label: None,
            agent_name: None,
            sandbox_profile: None,
            reasoning_effort: None,
            last_turn_summary: None,
            last_turn_summary_prompt_id: None,
            last_recap: None,
        };
        if let Some(identity) = crate::session::worktree::worktree_identity_for_cwd(&info.cwd) {
            summary.stamp_worktree_identity(&identity);
        }
        Ok(summary)
    }

    /// Mark this summary as a worktree session: kind, label, and source workspace all come from the path-derived `identity`.
    pub(crate) fn stamp_worktree_identity(
        &mut self,
        identity: &crate::session::worktree::WorktreeIdentity,
    ) {
        self.session_kind = Some(WORKTREE_SESSION_KIND.to_string());
        self.worktree_label = Some(identity.label.clone());
        self.source_workspace_dir = identity.source_workspace_dir.clone();
    }

    /// Whether this session should be excluded from history listings.
    pub fn is_hidden(&self) -> bool {
        self.hidden.unwrap_or(
            self.session_kind
                .as_deref()
                .is_some_and(|k| k.starts_with("subagent")),
        )
    }

    /// Whether this is a one-shot `fuigo -p` session.
    /// Deliberately not part of [`Self::is_hidden`]: headless sessions stay listable (the picker's Headless page, the search index).
    /// They are only excluded from the default pages by `HeadlessPolicy`.
    /// Unstamped summaries (`session_kind` absent) are interactive, including pre-stamp one-shots and remote twins the registry has not classified.
    /// They still fill default `/resume`.
    pub fn is_headless(&self) -> bool {
        self.session_kind.as_deref() == Some(crate::session::visibility::SESSION_KIND_HEADLESS)
    }

    /// Preferred display title: `generated_title` if non-empty, else `session_summary`.
    pub fn display_title(&self) -> &str {
        self.generated_title
            .as_deref()
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .unwrap_or(&self.session_summary)
    }

    /// Unused TUI-open husk: untitled, 0 messages, and no fork provenance.
    /// Worktree stamps do not exempt. `session_kind == "fork"` or
    /// `parent_session_id` / `forked_at` do (worktree forks keep kind `worktree`).
    pub fn is_unused_optimistic_husk(&self) -> bool {
        if matches!(self.session_kind.as_deref(), Some("fork"))
            || self
                .parent_session_id
                .as_deref()
                .is_some_and(|id| !id.is_empty())
            || self.forked_at.is_some()
        {
            return false;
        }
        self.num_messages == 0 && self.display_title().trim().is_empty()
    }

    /// [`Self::display_title`] as an `Option`, `None` when blank.
    pub fn display_title_opt(&self) -> Option<String> {
        let title = self.display_title().trim();
        (!title.is_empty()).then(|| title.to_string())
    }

    /// The manually-`/rename`d title (trimmed), `None` for auto-generated or blank titles.
    /// Binds to `generated_title` (the field `title_is_manual` describes), never the `session_summary` display fallback.
    /// A stale flag over a blank manual title therefore can't relabel an auto summary as manual.
    /// When `Some`, it equals [`Self::display_title_opt`] (a non-blank `generated_title` wins the display chain).
    pub fn manual_title_opt(&self) -> Option<String> {
        self.title_is_manual
            .then_some(self.generated_title.as_deref())
            .flatten()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
    }

    /// Last-change time (unix millis): `last_active_at`, else `updated_at`.
    pub fn last_change_unix_ms(&self) -> i64 {
        self.last_active_at
            .unwrap_or(self.updated_at)
            .timestamp_millis()
    }
}

#[cfg(test)]
#[path = "persistence_is_hidden_tests.rs"]
mod is_hidden_tests;

#[cfg(test)]
#[path = "persistence_head_fields_tests.rs"]
mod head_fields_tests;

#[cfg(test)]
#[path = "persistence_generated_title_tests.rs"]
mod generated_title_tests;

/// The session actor's ordered event queue, installed on the persistence actor once the session
/// that owns it exists (see [`PersistenceHandle::install_retry_status_mirror`]).
///
/// `OnceLock` rather than a constructor argument because the handle is built before the session:
/// `persistence::new` is awaited and its handle passed into `SessionActor`, which is where
/// `event_tx` is created.
pub(crate) type RetryStatusMirrorSlot =
    Arc<std::sync::OnceLock<mpsc::UnboundedSender<crate::session::replay_events::SessionEvent>>>;

#[derive(Clone)]
pub struct PersistenceHandle {
    pub tx: mpsc::UnboundedSender<PersistenceMsg>,
    noop: bool,
    disk_full_rx: watch::Receiver<bool>,
    retry_status_mirror: RetryStatusMirrorSlot,
}

fn actor_channel() -> (
    PersistenceHandle,
    mpsc::UnboundedReceiver<PersistenceMsg>,
    mpsc::WeakUnboundedSender<PersistenceMsg>,
    watch::Sender<bool>,
    RetryStatusMirrorSlot,
) {
    let (tx, rx) = mpsc::unbounded_channel::<PersistenceMsg>();
    let (disk_full_tx, disk_full_rx) = watch::channel(false);
    let retry_status_mirror: RetryStatusMirrorSlot = Default::default();
    let weak = tx.downgrade();
    let handle = PersistenceHandle {
        tx,
        noop: false,
        disk_full_rx,
        retry_status_mirror: retry_status_mirror.clone(),
    };
    (handle, rx, weak, disk_full_tx, retry_status_mirror)
}

#[derive(Debug)]
pub(crate) enum DurableAppendError {
    NotCommitted(io::Error),
    Committed(io::Error),
    AcknowledgementLost(io::Error),
}

impl std::fmt::Display for DurableAppendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCommitted(error)
            | Self::Committed(error)
            | Self::AcknowledgementLost(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for DurableAppendError {}

impl From<crate::session::storage::AppendUpdateError> for DurableAppendError {
    fn from(error: crate::session::storage::AppendUpdateError) -> Self {
        use crate::session::storage::AppendUpdateError;
        match error {
            AppendUpdateError::NotCommitted(error) => Self::NotCommitted(error),
            AppendUpdateError::Committed(error) => Self::Committed(error),
        }
    }
}

impl PersistenceHandle {
    #[cfg(test)]
    pub(crate) fn from_sender_for_test(tx: mpsc::UnboundedSender<PersistenceMsg>) -> Self {
        Self::from_parts_for_test(tx, watch::channel(false).1)
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        tx: mpsc::UnboundedSender<PersistenceMsg>,
        disk_full_rx: watch::Receiver<bool>,
    ) -> Self {
        Self::from_parts_for_test_with_mirror(tx, disk_full_rx, Default::default())
    }

    /// [`Self::from_parts_for_test`] sharing the actor's retry-status mirror slot, so a test can
    /// install a session queue on an actor it built itself.
    #[cfg(test)]
    pub(crate) fn from_parts_for_test_with_mirror(
        tx: mpsc::UnboundedSender<PersistenceMsg>,
        disk_full_rx: watch::Receiver<bool>,
        retry_status_mirror: RetryStatusMirrorSlot,
    ) -> Self {
        Self {
            tx,
            noop: false,
            disk_full_rx,
            retry_status_mirror,
        }
    }

    pub fn noop() -> Self {
        let (tx, _rx) = mpsc::unbounded_channel();
        Self {
            tx,
            noop: true,
            disk_full_rx: watch::channel(false).1,
            retry_status_mirror: Default::default(),
        }
    }

    /// Give the actor the session's ordered event queue so its disk-full `retry_state` mirror
    /// rides the same path as every other mirror (flush the replay buffer, then send) instead of
    /// going straight to the gateway, where it could overtake answer text already generated.
    ///
    /// First caller wins; the session that owns this handle installs its queue once, at spawn.
    pub(crate) fn install_retry_status_mirror(
        &self,
        event_tx: mpsc::UnboundedSender<crate::session::replay_events::SessionEvent>,
    ) {
        let _ = self.retry_status_mirror.set(event_tx);
    }

    pub fn is_noop(&self) -> bool {
        self.noop
    }

    #[cfg(test)]
    pub(crate) fn is_disk_full(&self) -> bool {
        *self.disk_full_rx.borrow()
    }

    pub(crate) fn subscribe_disk_full(&self) -> watch::Receiver<bool> {
        self.disk_full_rx.clone()
    }

    /// Append after older buffered updates and wait for the durable barrier.
    ///
    /// [`DurableAppendError::NotCommitted`] is safe to retry; [`DurableAppendError::Committed`] means the replay line landed.
    /// [`DurableAppendError::AcknowledgementLost`] has unknown status.
    /// No-op handles return `Unsupported`.
    pub(crate) async fn append_update_durably(
        &self,
        update: SessionUpdate,
    ) -> Result<(), DurableAppendError> {
        if self.noop {
            return Err(DurableAppendError::NotCommitted(io::Error::new(
                io::ErrorKind::Unsupported,
                "durable session update append is unsupported by a no-op persistence handle",
            )));
        }
        let (respond_to, response) = tokio::sync::oneshot::channel();
        self.tx
            .send(PersistenceMsg::AppendUpdateDurablyAndAck { update, respond_to })
            .map_err(|_| {
                DurableAppendError::NotCommitted(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "session persistence actor stopped before durable append dispatch",
                ))
            })?;
        response
            .await
            .map_err(|_| {
                DurableAppendError::AcknowledgementLost(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "session persistence actor stopped before durable append acknowledgement",
                ))
            })?
            .map_err(DurableAppendError::from)
    }
}

enum PendingAppendOutcome {
    CommittedOk(acp::SessionNotification),
    CommittedErr(acp::SessionNotification, io::Error),
    NotCommittedErr(acp::SessionNotification, io::Error),
}

struct SessionPersistence {
    info: Info,
    storage: Arc<dyn StorageAdapter>,
    /// Pending ACP notification for merging consecutive text chunks
    pending_notification: Option<acp::SessionNotification>,
    rx: mpsc::UnboundedReceiver<PersistenceMsg>,
    remote_sync: Option<RemoteSync>,
    /// True only for sessions created this run (not resumed); gates the writeback backfill so a resumed, already-synced session isn't re-sent.
    created_fresh: bool,
    /// WebSocket-based relay sync for real-time session sharing.
    /// This streams updates to the relay backend in addition to local persistence.
    relay_sync: Option<crate::relay::RelaySync>,
    /// Session title generation lifecycle.
    summary: crate::session::summary::SummaryGenerator,
    registry_title_sync: Option<RegistryGeneratedTitleSync>,
    /// Client gateway for `SessionSummaryGenerated` notifications.
    /// Used to announce an auto-generated title only once it has actually been adopted (see the `GeneratedTitle` handler).
    /// A title rejected for racing a manual `/rename` thus never reaches the client.
    /// `None` for the subagent variant, whose lifecycle notifications are handled by the coordinator.
    gateway: Option<GatewaySender>,
    /// Read every turn, not at construction, so a session opened before the decision landed still indexes.
    search_index: crate::session::storage::search::SharedSearchIndex,
    disk_full_tx: watch::Sender<bool>,
    disk_full_notified: bool,
    /// The owning session's ordered event queue, once it exists.
    ///
    /// EVERY session installs one at spawn, subagents included: a subagent's persistence handle is
    /// built in `agent::subagent::handle_request` and handed to the same `spawn_session_actor`,
    /// which calls [`PersistenceHandle::install_retry_status_mirror`] unconditionally.
    /// So this is empty only before that call: a write that fails between `persistence::new` /
    /// `load_light` returning and spawn reaching the install (`init_session` and the early writes
    /// happen in that window), a [`PersistenceHandle::noop`], and tests that run the actor with no
    /// session.
    retry_status_mirror: RetryStatusMirrorSlot,
    /// Files that took buffered writes since the last successful sync barrier.
    /// Atomic-rename writes are durable at write time and never enter the set.
    dirty_files: crate::session::storage::SessionFileSet,
    /// First buffered-write failure since the last barrier.
    /// `FlushAndAck` must not return `Ok` after a chat/update append that never reached disk.
    /// Fsyncing the previous bytes is not durability for that write.
    pending_write_error: Option<io::Error>,
    last_usage_live: Option<crate::session::usage_file::UsageSummary>,
    last_usage_turn: Option<u32>,
    last_incoming_turn: Option<u32>,
    /// The session's snapshot lock, held from a turn's `SnapshotBegin` until its `SnapshotEnd` (P135, K17),
    /// and released early only for a turn that is gone without an end, after
    /// [`snapshot_lock::hold_max`](crate::session::storage::snapshot_lock::hold_max).
    turn_start_guard: Option<crate::session::storage::snapshot_lock::SnapshotHold>,
}

/// P188: whether two notifications come from different model attempts (both stamped, with different
/// `_meta.streamStartMs`). Such chunks are never merged into one persisted line.
fn crosses_attempts(a: &acp::SessionNotification, b: &acp::SessionNotification) -> bool {
    let stream_of = |n: &acp::SessionNotification| {
        n.meta
            .as_ref()
            .and_then(|m| m.get("streamStartMs"))
            .and_then(serde_json::Value::as_i64)
    };
    matches!((stream_of(a), stream_of(b)), (Some(x), Some(y)) if x != y)
}

#[cfg(test)]
mod p188_crosses_attempts_tests {
    use super::*;

    #[test]
    fn only_two_stamped_different_attempts_cross() {
        let chunk = |stream: Option<i64>| {
            let n = acp::SessionNotification::new(
                acp::SessionId::new("s"),
                acp::SessionUpdate::AgentMessageChunk(acp::ContentChunk::new(acp::ContentBlock::Text(
                    acp::TextContent::new("t"),
                ))),
            );
            match stream {
                Some(stream) => n.meta(serde_json::json!({ "streamStartMs": stream }).as_object().cloned()),
                None => n,
            }
        };
        assert!(crosses_attempts(&chunk(Some(1)), &chunk(Some(2))));
        assert!(!crosses_attempts(&chunk(Some(1)), &chunk(Some(1))));
        assert!(!crosses_attempts(&chunk(None), &chunk(Some(2))));
        assert!(!crosses_attempts(&chunk(Some(1)), &chunk(None)));
    }
}

impl SessionPersistence {
    fn try_merge_text(prev: &mut acp::ContentBlock, new: &acp::ContentBlock) -> bool {
        match (prev, new) {
            (acp::ContentBlock::Text(prev_text), acp::ContentBlock::Text(new_text))
                if prev_text.annotations.is_none()
                    && prev_text.meta.is_none()
                    && new_text.annotations.is_none()
                    && new_text.meta.is_none() =>
            {
                prev_text.text.push_str(&new_text.text);
                true
            }
            _ => false,
        }
    }

    fn is_empty_chunk(update: &acp::SessionUpdate) -> bool {
        match update {
            acp::SessionUpdate::AgentMessageChunk(chunk)
            | acp::SessionUpdate::AgentThoughtChunk(chunk) => {
                let empty_text =
                    matches!(&chunk.content, acp::ContentBlock::Text(t) if t.text.is_empty());
                let no_meta = chunk.meta.is_none();
                empty_text && no_meta
            }
            _ => false,
        }
    }

    /// Attempt to merge consecutive ACP text notifications to reduce storage writes.
    /// Returns Some(notification) if the pending notification should be written now.
    fn maybe_merge_notification(
        &mut self,
        incoming: &acp::SessionNotification,
    ) -> Option<acp::SessionNotification> {
        // Always skip empty chunks: don't store them at all
        if Self::is_empty_chunk(&incoming.update) {
            return None;
        }

        let Some(pending) = self.pending_notification.take() else {
            self.pending_notification = Some(incoming.clone());
            return None;
        };

        // P188: never merge chunks of two model attempts; a discard voids one by its `_meta.streamStartMs`
        if crosses_attempts(&pending, incoming) {
            self.pending_notification = Some(incoming.clone());
            return Some(pending);
        }
        let pending_update = pending.update.clone();
        match (&incoming.update, pending_update) {
            (
                acp::SessionUpdate::AgentMessageChunk(new_chunk),
                acp::SessionUpdate::AgentMessageChunk(mut pending_chunk),
            )
            | (
                acp::SessionUpdate::AgentThoughtChunk(new_chunk),
                acp::SessionUpdate::AgentThoughtChunk(mut pending_chunk),
            ) => {
                let did_merge = pending_chunk.meta.is_none()
                    && new_chunk.meta.is_none()
                    && Self::try_merge_text(&mut pending_chunk.content, &new_chunk.content);

                if did_merge {
                    let merged_update = match &incoming.update {
                        acp::SessionUpdate::AgentMessageChunk(_) => {
                            acp::SessionUpdate::AgentMessageChunk(pending_chunk)
                        }
                        acp::SessionUpdate::AgentThoughtChunk(_) => {
                            acp::SessionUpdate::AgentThoughtChunk(pending_chunk)
                        }
                        _ => unreachable!(),
                    };
                    self.pending_notification = Some(
                        acp::SessionNotification::new(incoming.session_id.clone(), merged_update)
                            .meta(incoming.meta.clone()),
                    );
                    None
                } else {
                    self.pending_notification = Some(incoming.clone());
                    Some(pending)
                }
            }
            _ => {
                self.pending_notification = Some(incoming.clone());
                Some(pending)
            }
        }
    }

    async fn write_update(
        &mut self,
        update: &SessionUpdate,
    ) -> Result<(), crate::session::storage::AppendUpdateError> {
        let result = self
            .storage
            .append_update_commit_aware(&self.info, update)
            .await;
        self.observe_append_update(&result);
        match &result {
            Ok(()) | Err(crate::session::storage::AppendUpdateError::Committed(_)) => {
                self.dirty_files.updates = true;
            }
            Err(crate::session::storage::AppendUpdateError::NotCommitted(error)) => {
                self.note_write_failure(error);
            }
        }
        result
    }

    fn note_write_failure(&mut self, error: &io::Error) {
        if self.pending_write_error.is_none() {
            self.pending_write_error = Some(io::Error::new(error.kind(), error.to_string()));
        }
    }

    fn take_pending_write_error(&mut self) -> io::Result<()> {
        match self.pending_write_error.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn observe_io<T>(&mut self, result: &io::Result<T>) {
        match result {
            Ok(_) => self.clear_disk_full(),
            Err(error) if is_disk_full_io_error(error) => self.mark_disk_full(),
            Err(_) => {}
        }
    }

    fn observe_append_update(
        &mut self,
        result: &Result<(), crate::session::storage::AppendUpdateError>,
    ) {
        match result {
            Ok(()) => self.clear_disk_full(),
            Err(
                crate::session::storage::AppendUpdateError::NotCommitted(error)
                | crate::session::storage::AppendUpdateError::Committed(error),
            ) if is_disk_full_io_error(error) => self.mark_disk_full(),
            Err(_) => {}
        }
    }

    fn observe_append_chat(
        &mut self,
        result: &Result<(), crate::session::storage::AppendChatError>,
    ) {
        match result {
            Ok(()) => self.clear_disk_full(),
            Err(
                crate::session::storage::AppendChatError::NotCommitted(error)
                | crate::session::storage::AppendChatError::Committed(error),
            ) if is_disk_full_io_error(error) => self.mark_disk_full(),
            Err(_) => {}
        }
    }

    fn mark_disk_full(&mut self) {
        if !*self.disk_full_tx.borrow() {
            let _ = self.disk_full_tx.send(true);
        }
        if self.disk_full_notified {
            return;
        }
        self.disk_full_notified = true;
        self.emit_disk_full_notification();
    }

    fn clear_disk_full(&mut self) {
        if *self.disk_full_tx.borrow() {
            let _ = self.disk_full_tx.send(false);
        }
        self.disk_full_notified = false;
    }

    fn emit_disk_full_notification(&self) {
        let Some(gateway) = &self.gateway else {
            return;
        };
        let state = RetryState::Failed {
            error_type: DISK_FULL_ERROR_TYPE.to_string(),
            message: DISK_FULL_USER_MESSAGE.to_string(),
            verdicts: None,
        };
        let notification = FuigoSessionNotification {
            session_id: self.info.id.clone(),
            update: FuigoSessionUpdate::RetryState(state.clone()),
            meta: None,
        };
        if let Ok(params) = serde_json::value::to_raw_value(&notification) {
            gateway.forward_fire_and_forget(acp::ExtNotification::new(
                "fuigo/session_notification",
                params.into(),
            ));
        }
        // The standard-rail mirror every `retry_state` gets, so stock ACP clients see why the turn failed.
        // This actor is the one mirror producer outside the session: a write fails while the session
        // is streaming, so the mirror takes the session's ordered queue like the others rather than
        // racing that text to the gateway, and the session stamps the paragraph separator and the
        // prompt id, which are its state and not this task's.
        let queued = self.retry_status_mirror.get().is_some_and(|event_tx| {
            event_tx
                .send(SessionEvent::RetryStatusMirror(Box::new(state.clone())))
                .is_ok()
        });
        if !queued {
            // No queue is installed yet -- the write failed before spawn reached
            // `install_retry_status_mirror`, or this is a `noop`/test handle -- or the session loop
            // is gone. A subagent is NOT one of these: it installs a queue like every other
            // session. In each of those cases nothing can be queued ahead of the mirror, so send it
            // directly and open no paragraph of its own.
            gateway.forward_fire_and_forget(
                crate::extensions::notification::retry_status_notification(
                    self.info.id.clone(),
                    &state,
                    None,
                    /*after_thought_text*/ false,
                ),
            );
        }
    }

    async fn probe_writable(&self) -> io::Result<()> {
        let dir = self
            .storage
            .updates_file_path(&self.info)
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "session directory is unknown; cannot probe disk space",
                )
            })?;
        tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&dir)?;
            let probe = dir.join(".disk_ok");
            fuigo_config::write_file_owner_only(&probe, b"ok")?;
            let _ = std::fs::remove_file(&probe);
            io::Result::Ok(())
        })
        .await
        .map_err(io::Error::other)?
    }

    fn queue_acp_sync(&self, notification: acp::SessionNotification) {
        if let Some(sync) = &self.remote_sync {
            sync.queue(notification.clone());
        }
        if let Some(relay) = &self.relay_sync {
            relay.queue(notification);
        }
    }

    /// Enable writeback for a session created `Local` before settings resolved.
    /// Build the sync and (for a fresh session) backfill its local-only history.
    /// No-op once syncing, so a repeat upgrade is harmless.
    async fn upgrade_to_writeback(&mut self, auth_manager: Arc<crate::auth::AuthManager>) {
        if self.remote_sync.is_some() {
            return;
        }
        // Flush the merge-pending notification so the backfill re-reads it.
        let _ = self.flush_pending().await;
        let persisted = match self.storage.load_session(&self.info).await {
            Ok(persisted) => persisted,
            Err(error) => {
                tracing::warn!(%error, "writeback upgrade: failed to load session for backfill");
                return;
            }
        };
        let remote_sync = match init_remote_sync(
            &persisted.summary,
            StorageMode::Writeback,
            Some(auth_manager),
        ) {
            Ok(Some(remote_sync)) => remote_sync,
            // ZDR team, or nothing to do: leave the session local-only.
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(%error, "writeback upgrade: remote sync init failed");
                return;
            }
        };
        // Fresh-only backfill; see `backfill_updates_to_sync`.
        let backfilled =
            backfill_updates_to_sync(self.created_fresh, persisted.updates, &remote_sync);
        if self.created_fresh {
            tracing::info!(
                session_id = %self.info.id,
                backfilled,
                "writeback enabled after settings arrival; backfilled local-only history",
            );
        } else {
            tracing::info!(
                session_id = %self.info.id,
                "writeback enabled for resumed session; forward-only, no backfill",
            );
        }
        self.remote_sync = Some(remote_sync);
    }

    fn finish_pending_append(
        notification: acp::SessionNotification,
        result: Result<(), crate::session::storage::AppendUpdateError>,
    ) -> PendingAppendOutcome {
        match result {
            Ok(()) => PendingAppendOutcome::CommittedOk(notification),
            Err(crate::session::storage::AppendUpdateError::NotCommitted(error)) => {
                PendingAppendOutcome::NotCommittedErr(notification, error)
            }
            Err(crate::session::storage::AppendUpdateError::Committed(error)) => {
                PendingAppendOutcome::CommittedErr(notification, error)
            }
        }
    }

    /// Restore uncommitted failures; sync committed records before returning errors.
    async fn drain_pending(&mut self) -> Result<(), crate::session::storage::AppendUpdateError> {
        if let Some(notification) = self.pending_notification.take() {
            // `write_update` latches NotCommitted
            // This record is restored below for retry, so a latch from *this* miss is stale
            // A fire-and-forget durable append (TurnCompleted drops its ack) would otherwise make the next FlushAndAck fail
            // That failure would come after a successful redrain and prompt-byte sync
            // A prior latch from a dropped buffered write is left in place
            let had_prior_latch = self.pending_write_error.is_some();
            let result = self
                .write_update(&SessionUpdate::Acp(Box::new(notification.clone())))
                .await;
            match Self::finish_pending_append(notification, result) {
                PendingAppendOutcome::CommittedOk(notification) => {
                    self.queue_acp_sync(notification);
                }
                PendingAppendOutcome::CommittedErr(notification, error) => {
                    self.queue_acp_sync(notification);
                    return Err(crate::session::storage::AppendUpdateError::Committed(error));
                }
                PendingAppendOutcome::NotCommittedErr(notification, error) => {
                    self.pending_notification = Some(notification);
                    if !had_prior_latch {
                        self.pending_write_error = None;
                    }
                    return Err(crate::session::storage::AppendUpdateError::NotCommitted(
                        error,
                    ));
                }
            }
        }
        Ok(())
    }

    async fn handle_durable_append(
        &mut self,
        update: SessionUpdate,
    ) -> Result<(), crate::session::storage::AppendUpdateError> {
        match self.drain_pending().await {
            Ok(()) => {}
            // Pending is already in the file / page cache
            // Aborting here would drop a fire-and-forget TurnCompleted (the ack is dropped after the turn pre-flush) with no retry
            Err(crate::session::storage::AppendUpdateError::Committed(_)) => {}
            Err(error) => return Err(error),
        }
        let result = self
            .storage
            .append_update_durable_commit_aware(&self.info, &update)
            .await;
        self.observe_append_update(&result);
        match &result {
            // Already fsynced at write time; stay off the dirty set.
            Ok(()) => {}
            // `write_all` reached the page cache (file barrier or bookkeeping failed)
            // A later idle FlushAndAck must retry the fsync; TurnCompleted drops the ack after the turn's pre-flush, so this is the only retry path
            Err(crate::session::storage::AppendUpdateError::Committed(_)) => {
                self.dirty_files.updates = true;
            }
            // The latch is for buffered chat/update/rewind misses.
            // This path already reports via AppendUpdateDurablyAndAck
            // Latching would make the next FlushAndAck fail after it has already synced later prompt bytes (TurnCompleted drops its ack)
            Err(crate::session::storage::AppendUpdateError::NotCommitted(_)) => {}
        }
        match (&update, &result) {
            (SessionUpdate::Acp(notification), Ok(()))
            | (
                SessionUpdate::Acp(notification),
                Err(crate::session::storage::AppendUpdateError::Committed(_)),
            ) => self.queue_acp_sync((**notification).clone()),
            _ => {}
        }
        result
    }

    /// Flush any pending merged ACP notification to disk and remote sync.
    /// A no-op drain must not clear the disk-full latch.
    async fn flush_pending(&mut self) -> io::Result<()> {
        let result = match self.drain_pending().await {
            Ok(()) => Ok(()),
            // JSONL reached the page cache; `write_update` already dirtied updates so the barrier sync retries fsync
            // Returning Err here would withhold persist_ack after a successful prompt-byte sync (the same contract as chat Committed misses)
            Err(crate::session::storage::AppendUpdateError::Committed(error)) => {
                tracing::warn!(%error, "failed to write pending update");
                Ok(())
            }
            Err(error) => Err(error.into_io_error()),
        };
        if let Err(error) = &result {
            tracing::warn!(%error, "failed to write pending update");
        }
        if let Some(sync) = &self.remote_sync {
            sync.flush();
        }
        if let Some(relay) = &self.relay_sync {
            relay.flush();
        }
        result
    }

    /// Flush pending writes and sync the files dirtied since the last successful barrier to stable media; an idle barrier syncs nothing.
    /// First error wins: a NotCommitted drain outranks a failed sync.
    /// A Committed drain is already on the dirty set and does not fail the ack.
    async fn flush_and_sync(&mut self) -> io::Result<()> {
        let flushed = self.flush_pending().await;
        let prior_write = self.take_pending_write_error();
        let synced = self.sync_files_and_clear(self.dirty_files).await;
        flushed.and(prior_write).and(synced)
    }

    /// Announce a newly adopted auto title (first generation or refresh) to the client, remote store, and session registry.
    /// Called only after the title actually landed on disk, so a title rejected for racing a manual `/rename` is never announced.
    fn announce_adopted_title(&self, title: String) {
        crate::session::summary::notify_client(&self.gateway, &self.info, &title);
        if let Some(sync) = &self.remote_sync {
            sync.set_title(title.clone());
        }
        if let Some(reg) = self.registry_title_sync.as_ref()
            && !reg.suppress_for_zdr
        {
            let client = reg.client.clone();
            let sid = self.info.id.to_string();
            tokio::spawn(async move {
                let req = crate::agent::session_registry_client::UpdateRequest {
                    summary: Some(title),
                    first_prompt: None,
                    last_turn_number: None,
                    repo_head_at_end: None,
                    restorable_turn_number: None,
                };
                if let Err(e) = client.update(&sid, &req).await {
                    tracing::warn!(
                        error = %e,
                        session_id = %sid,
                        "session registry summary sync failed after title update"
                    );
                }
            });
        }
    }

    /// [`Self::flush_and_sync`] over the full barrier file set: `CopyFile` snapshots the whole session directory regardless of dirtiness.
    /// Does not consume `pending_write_error`: CopyFile is not the durability barrier.
    /// Stealing the latch would let a later FlushAndAck ack after a buffered write never reached disk.
    async fn flush_and_sync_all(&mut self) -> io::Result<()> {
        let flushed = self.flush_pending().await;
        let synced = self
            .sync_files_and_clear(crate::session::storage::SessionFileSet::ALL)
            .await;
        flushed.and(synced)
    }

    async fn sync_files_and_clear(
        &mut self,
        files: crate::session::storage::SessionFileSet,
    ) -> io::Result<()> {
        if files.is_empty() {
            return Ok(());
        }
        let synced = self
            .storage
            .sync_session_files_selected(&self.info, files)
            .await;
        match &synced {
            Ok(()) => self.dirty_files = Default::default(),
            Err(e) => tracing::warn!(?e, "Failed to sync session files to disk"),
        }
        synced
    }

    /// The hold has been kept for [`snapshot_lock::hold_max`](crate::session::storage::snapshot_lock::hold_max). A turn that
    /// is still running keeps it, however long it takes (an image transcription is minutes per image, and releasing then
    /// would leave a prompt's echoes on disk with no chat item for a fork that follows); the time is counted again. A hold
    /// whose turn is gone without its end (a bug, not an expected case) is released, so forks are never refused for good.
    ///
    /// Expiry runs only when the channel is drained (the caller's `timeout_at` fires only when `recv` found nothing before the
    /// deadline, and re-checks `rx.is_empty()`): a queued message, such as the turn's own chat item and end, is always
    /// processed first, so the lock is never released ahead of a chat item whose echoes are already buffered (Astra P135 r3 H).
    async fn expire_snapshot_hold(&mut self) {
        let Some(hold) = self.turn_start_guard.as_mut() else { return };
        if hold.turn_alive() {
            tracing::debug!(turn_id = hold.turn_id, "the snapshot lock stays held: its turn is still running");
            hold.since = std::time::Instant::now();
            return;
        }
        let hold = self.turn_start_guard.take().expect("checked above");
        #[cfg(test)]
        crate::session::storage::snapshot_lock::EXPIRY_RELEASES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::warn!(
            turn_id = hold.turn_id,
            held_ms = hold.since.elapsed().as_millis() as u64,
            "the snapshot lock was held past its limit by a turn that is gone, without an end; releasing it"
        );
        // The echoes still buffered stay buffered (the next write flushes them).
    }

    async fn run(mut self) {
        // Persistence traffic counts as worktree activity, debounced to avoid per-message DB writes
        // Long-resident sessions (leader/remote, active for days without a re-open) thus stay out of gc expiry
        // The constructors fire the t=0 touch, so this starts at now().
        let mut last_worktree_touch = std::time::Instant::now();
        loop {
            let received = match self.turn_start_guard.as_ref().map(|hold| hold.expires_at()) {
                Some(deadline) => match tokio::time::timeout_at(deadline.into(), self.rx.recv()).await {
                    Ok(received) => received,
                    Err(_) => {
                        // `timeout_at` polls `recv` before the deadline, so this arm runs only when nothing was ready; the
                        // check keeps the invariant explicit should a message have landed since.
                        if self.rx.is_empty() {
                            self.expire_snapshot_hold().await;
                        }
                        continue;
                    }
                },
                None => self.rx.recv().await,
            };
            let Some(msg) = received else { break };
            if last_worktree_touch.elapsed() >= WORKTREE_TOUCH_INTERVAL {
                last_worktree_touch = std::time::Instant::now();
                // Detached on purpose: opportunistic refresh, no ordering need.
                spawn_worktree_touch(&self.info);
            }
            match msg {
                PersistenceMsg::PresentationHints { hints, respond_to } => {
                    let result = crate::session::tool_presentation::persist_hints(&session_dir(&self.info), &hints).await;
                    let _ = respond_to.send(result);
                }
                PersistenceMsg::UpgradeToWriteback { auth_manager } => {
                    self.upgrade_to_writeback(auth_manager).await;
                }
                PersistenceMsg::Flush => {
                    let _ = self.flush_pending().await;
                }
                PersistenceMsg::FlushAndAck { respond_to } => {
                    let result = self.flush_and_sync().await;
                    let _ = respond_to.send(result);
                }
                PersistenceMsg::ProbeWritable { respond_to } => {
                    let result = self.probe_writable().await;
                    self.observe_io(&result);
                    let _ = respond_to.send(result);
                }
                PersistenceMsg::SnapshotBegin { turn_id, alive } => {
                    // A hold still open belongs to a turn whose end never arrived: it ends here (never two holds, and the
                    // old file must be closed before the lock is taken again, or this task would wait for itself).
                    if self.turn_start_guard.is_some() {
                        tracing::warn!(turn_id, "a new turn began while the snapshot lock was still held; releasing the old hold");
                        let _ = self.flush_pending().await;
                        self.turn_start_guard = None;
                    }
                    self.turn_start_guard = crate::session::storage::snapshot_lock::acquire_async(&session_dir(&self.info))
                        .await
                        .map(|file| crate::session::storage::snapshot_lock::SnapshotHold::new(turn_id, file, alive));
                }
                PersistenceMsg::SnapshotEnd { turn_id } => {
                    if self.turn_start_guard.as_ref().is_some_and(|hold| hold.turn_id == turn_id) {
                        // The echoes still buffered are written before the hold ends.
                        let _ = self.flush_pending().await;
                        self.turn_start_guard = None;
                    }
                }
                PersistenceMsg::Update(update) => {
                    match update {
                        SessionUpdate::Acp(notification) => {
                            // ACP notifications use merging to coalesce consecutive text chunks
                            if let Some(to_write) = self.maybe_merge_notification(&notification) {
                                match self
                                    .write_update(&SessionUpdate::Acp(Box::new(to_write.clone())))
                                    .await
                                {
                                    Ok(())
                                    | Err(crate::session::storage::AppendUpdateError::Committed(
                                        _,
                                    )) => {
                                        self.queue_acp_sync(to_write);
                                    }
                                    Err(error) => tracing::warn!(%error, "failed to write update"),
                                }
                            }
                        }
                        SessionUpdate::Fuigo(ref fuigo) => {
                            // P188: a `retry_state` voids the chunks before it, so they must be on disk before it.
                            // The merge buffer may still hold the last of them; write it first.
                            if matches!(
                                fuigo.update,
                                crate::extensions::notification::SessionUpdate::RetryState(_)
                            ) && let Err(error) = self.drain_pending().await
                            {
                                tracing::warn!(%error, "failed to write pending update before a retry_state");
                            }
                            // Ferrox Labs notifications are written directly without merging
                            if let Err(error) = self.write_update(&update).await {
                                tracing::warn!(%error, "failed to write update");
                            }
                        }
                    }
                }
                PersistenceMsg::AppendUpdateDurablyAndAck { update, respond_to } => {
                    let result = self.handle_durable_append(update).await;
                    // Test-only: hold this ack back so a recovery's bound can be outlived by an append that has
                    // already landed. Compiled out of every non-test build.
                    #[cfg(test)]
                    let Some((result, respond_to)) =
                        test_seam::maybe_delay_ack(&self.info.id.0, result, respond_to)
                    else {
                        continue;
                    };
                    // A dropped receiver is a fire-and-forget durable append (e.g. the TurnCompleted terminal).
                    // Its errors would otherwise vanish with the unread ack
                    if let Err(Err(error)) = respond_to.send(result) {
                        tracing::warn!(%error, "failed to write durable update");
                    }
                }
                PersistenceMsg::Chat(chat_msg) => {
                    // A prompt starts a turn: its transcript echoes were written while the turn's snapshot lock was held
                    // (`SnapshotBegin`), and the chat item is written under it, so a fork's snapshot sees the prompt in both
                    // files or in neither (P123, K17). The hold ends with the turn's `SnapshotEnd`, never with a chat item
                    // (a workflow reminder or a completion between turns is not the prompt, P135). The lock is taken here
                    // for a prompt item when no turn holds it.
                    let is_turn_start =
                        matches!(&chat_msg, ConversationItem::User(user) if user.prompt_index.is_some());
                    let _turn_start = if is_turn_start {
                        let guard = if self.turn_start_guard.is_some() {
                            None
                        } else {
                            crate::session::storage::snapshot_lock::acquire_async(&session_dir(&self.info)).await
                        };
                        let _ = self.flush_pending().await;
                        guard
                    } else {
                        None
                    };
                    let result = self
                        .storage
                        .append_chat_message_commit_aware(&self.info, &chat_msg)
                        .await;
                    self.observe_append_chat(&result);
                    match &result {
                        Ok(()) => self.dirty_files.chat = true,
                        Err(crate::session::storage::AppendChatError::Committed(error)) => {
                            tracing::warn!(
                                %error,
                                "failed to write chat bookkeeping after append"
                            );
                            self.dirty_files.chat = true;
                        }
                        Err(crate::session::storage::AppendChatError::NotCommitted(error)) => {
                            tracing::warn!(%error, "failed to write chat message");
                            self.note_write_failure(error);
                        }
                    }
                }
                PersistenceMsg::AppendCwdSwitchAndAck { item, respond_to } => {
                    let result = self
                        .storage
                        .append_cwd_switch_commit_aware(&self.info, &item)
                        .await
                        .map_err(|error| match error {
                            crate::session::storage::AppendCwdSwitchError::NotCommitted(error) => {
                                fuigo_chat_state::StrictAppendError::NotCommitted(error)
                            }
                            crate::session::storage::AppendCwdSwitchError::Committed {
                                acknowledgement,
                                source,
                            } => fuigo_chat_state::StrictAppendError::Committed {
                                acknowledgement,
                                source,
                            },
                        });
                    let _ = respond_to.send(result);
                }
                PersistenceMsg::ReplaceChatHistory(messages) => {
                    tracing::info!(
                        num_messages = messages.len(),
                        "Replacing chat history (compaction)"
                    );
                    if let Err(e) = self.replace_chat_history_now(&messages).await {
                        // Not lost: a compaction's rewrite that did not land is recovered from disk (the compaction
                        // witness recognises the old history and takes the items appended after it). The failure
                        // still fails the next FlushAndAck, so the turn reports that a write did not reach disk.
                        tracing::warn!(?e, "failed to replace chat history");
                        self.note_write_failure(&e);
                    }
                }
                PersistenceMsg::ReplaceChatHistoryAndAck {
                    messages,
                    respond_to,
                } => {
                    let result = self.replace_chat_history_acknowledged(&messages).await;
                    let _ = respond_to.send(result);
                }
                PersistenceMsg::ReplaceChatHistoryForStripAndAck {
                    messages,
                    respond_to,
                } => {
                    let result = crate::session::storage::strip_rewrite_gated(
                        self.storage.as_ref(),
                        &self.info,
                        &messages,
                    )
                    .await;
                    self.observe_io(&result);
                    if let Err(e) = &result {
                        tracing::warn!(?e, "image-strip history rewrite failed");
                    }
                    let _ = respond_to.send(result);
                }
                PersistenceMsg::CurrentModel {
                    model_id,
                    agent_name,
                    reasoning_effort,
                } => {
                    if let Err(e) = self
                        .storage
                        .update_current_model_and_agent(
                            &self.info,
                            &model_id,
                            agent_name.as_deref(),
                            reasoning_effort,
                        )
                        .await
                    {
                        tracing::warn!(?e, "failed to update current model");
                    }
                    if let Some(sync) = &self.remote_sync {
                        sync.set_model_id(model_id.0.to_string());
                    }
                }
                PersistenceMsg::PlanState(state) => {
                    // Atomic-rename: durable at write time, never on the dirty set
                    // A failed plan write must not latch into `pending_write_error`
                    // That latch is for buffered chat/update/rewind misses
                    // Latching here would make the next FlushAndAck fail after it has already synced those bytes
                    let result = self.storage.write_plan_state(&self.info, &state).await;
                    self.observe_io(&result);
                    if let Err(e) = result {
                        tracing::warn!(?e, "failed to write plan state");
                    }
                }
                PersistenceMsg::PlanModeState(state) => {
                    if let Err(e) = self.storage.write_plan_mode_state(&self.info, &state).await {
                        tracing::warn!(?e, "failed to write plan mode state");
                    }
                }
                PersistenceMsg::GoalModeState(state) => {
                    if let Err(e) = self.storage.write_goal_mode_state(&self.info, &state).await {
                        tracing::warn!(?e, "failed to write goal mode state");
                    }
                }
                PersistenceMsg::DeleteGoalModeState { respond_to } => {
                    let result = self.storage.delete_goal_mode_state(&self.info).await;
                    if let Err(e) = &result {
                        tracing::warn!(?e, "failed to delete goal mode state");
                    }
                    let _ = respond_to.send(result);
                }
                PersistenceMsg::WorkflowRunState(manifest) => {
                    if let Err(error) = self
                        .storage
                        .write_workflow_run_state(&self.info, &manifest)
                        .await
                    {
                        tracing::warn!(run_id = %manifest.state.run_id, ?error, "failed to write workflow run state");
                    }
                }
                PersistenceMsg::WorkflowRunStateAndAck {
                    manifest,
                    respond_to,
                } => {
                    let result = self
                        .storage
                        .write_workflow_run_state(&self.info, &manifest)
                        .await;
                    if let Err(error) = &result {
                        tracing::warn!(run_id = %manifest.state.run_id, ?error, "failed to write acknowledged workflow run state");
                    }
                    let _ = respond_to.send(result);
                }
                PersistenceMsg::DeleteWorkflowRunState(run_id) => {
                    if let Err(e) = self
                        .storage
                        .delete_workflow_run_state(&self.info, &run_id)
                        .await
                    {
                        tracing::warn!(%run_id, ?e, "failed to delete workflow run state");
                    }
                }
                PersistenceMsg::ContentChunk(content_chunks) => {
                    let content_part = content_chunks
                        .content_chunks
                        .into_iter()
                        .filter_map(|content_chunk| match content_chunk {
                            acp::ContentBlock::Text(text) => Some(text.text),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    self.summary.update(content_part);

                    // Notify session search index so this turn becomes searchable
                    crate::session::storage::search::notify_session_updated(
                        self.search_index.decision().writer(),
                        &self.info.id.to_string(),
                        &self.info.cwd,
                    );
                }
                PersistenceMsg::GeneratedTitle(title) => {
                    // Auto-generated titles must never overwrite a title the user set via `/rename`
                    // `set_generated_title_if_absent` writes only when the session still has no title (checked atomically under the summary lock)
                    // A manual rename that raced this generation thus wins, and its title is not clobbered locally or on remotes
                    match self
                        .storage
                        .set_generated_title_if_absent(&self.info, title.clone())
                        .await
                    {
                        Ok(true) => self.announce_adopted_title(title),
                        Ok(false) => {
                            tracing::debug!(
                                "skipped auto-generated title; session already has a title"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(?e, "failed to persist generated session title");
                        }
                    }
                }
                PersistenceMsg::RegenerateTitle(title) => {
                    // Overwrites an existing auto title but never a manual `/rename` (enforced atomically under the summary lock)
                    match self
                        .storage
                        .regenerate_generated_title(&self.info, title.clone())
                        .await
                    {
                        Ok(true) => self.announce_adopted_title(title),
                        Ok(false) => {
                            tracing::debug!("skipped title refresh; session has a manual title");
                        }
                        Err(e) => {
                            tracing::warn!(?e, "failed to persist refreshed session title");
                        }
                    }
                }
                PersistenceMsg::LastRecap(recap) => {
                    if let Err(e) = self.storage.set_last_recap(&self.info, recap).await {
                        tracing::warn!(?e, "failed to persist session recap");
                    }
                }
                PersistenceMsg::ManualTitleRenamed(title) => {
                    if let Some(sync) = &self.remote_sync {
                        sync.set_manual_title(title);
                    }
                }
                PersistenceMsg::ReplaceSummaryHelper(helper) => {
                    self.summary.replace_helper(helper);
                }
                PersistenceMsg::ResetTitleToAuto => {
                    self.summary.reset();
                    if let Some(sync) = &self.remote_sync {
                        sync.clear_title();
                    }
                }
                PersistenceMsg::LastTurnSummary(summary) => {
                    if let Err(e) = self
                        .storage
                        .set_last_turn_summary(&self.info, summary)
                        .await
                    {
                        tracing::warn!(?e, "failed to persist last turn summary");
                    }
                }
                PersistenceMsg::RewindPoint(point) => {
                    let result = self.storage.append_rewind_point(&self.info, &point).await;
                    self.observe_io(&result);
                    match result {
                        Ok(()) => self.dirty_files.rewind_points = true,
                        Err(e) => {
                            tracing::warn!(?e, "failed to write rewind point");
                            self.note_write_failure(&e);
                        }
                    }
                }
                PersistenceMsg::TruncateRewindPoints { from_index } => {
                    if let Err(e) = self
                        .storage
                        .truncate_rewind_points_from(&self.info, from_index)
                        .await
                    {
                        tracing::warn!(?e, from_index, "failed to truncate rewind points");
                    }
                }
                PersistenceMsg::LockRewindPointsRewrite { gate, respond_to } => {
                    if gate.start() {
                        let result = self.storage.lock_rewind_points_rewrite(&self.info).await;
                        if let Err(e) = &result {
                            tracing::warn!(?e, "rewind refused: the rewind points rewrite lock was not taken");
                        }
                        // A reply nobody waits for any more drops the lock with it.
                        let _ = respond_to.send(result);
                    }
                }
                PersistenceMsg::RewriteRewindPointsAndAck { rewrite, conversation, gate, respond_to } => {
                    if gate.start() {
                        let result = self
                            .storage
                            .rewrite_rewind_points_holding(&self.info, rewrite, conversation)
                            .await;
                        if let Err(e) = &result {
                            tracing::warn!(?e, ?rewrite, "failed to rewrite rewind points for a rewind");
                        }
                        let _ = respond_to.send(result);
                    }
                }
                PersistenceMsg::EndRewindPointsAndAck { undo, put_back, gate, respond_to } => {
                    if gate.start() {
                        let result = self.storage.end_rewind_points_rewrite(&self.info, undo, put_back).await;
                        if let Err(e) = &result {
                            tracing::warn!(?e, put_back, "failed to finish the rewind of rewind points");
                        }
                        let _ = respond_to.send(result);
                    }
                }
                PersistenceMsg::MergeRewindPointsFrom { target_index } => {
                    if let Err(e) = self
                        .storage
                        .merge_rewind_points_from(&self.info, target_index)
                        .await
                    {
                        tracing::warn!(?e, target_index, "failed to merge rewind points");
                    }
                }
                PersistenceMsg::CollectionId(collection_id) => {
                    if let Err(e) = self
                        .storage
                        .update_collection_id(&self.info, &collection_id)
                        .await
                    {
                        tracing::warn!(?e, "failed to write collection id");
                    }
                }
                PersistenceMsg::NextTraceTurn {
                    next_trace_turn,
                    request_id,
                } => {
                    if let Err(e) = self
                        .storage
                        .update_next_trace_turn(&self.info, next_trace_turn, request_id.as_deref())
                        .await
                    {
                        tracing::warn!(?e, "failed to write next trace turn");
                    }
                }
                PersistenceMsg::Signals(signals) => {
                    if let Err(e) = self.storage.write_signals(&self.info, &signals).await {
                        tracing::warn!(?e, "failed to write session signals");
                    }
                }
                PersistenceMsg::UsageTurn { turn_number, live } => {
                    if let Err(e) = self.persist_usage_turn(turn_number, &live).await {
                        tracing::warn!(?e, turn_number, "failed to write session usage");
                    }
                }
                PersistenceMsg::AnnouncementState(state) => {
                    if let Err(e) = self
                        .storage
                        .write_announcement_state(&self.info, &state)
                        .await
                    {
                        tracing::warn!(?e, "failed to write announcement state");
                    }
                }
                PersistenceMsg::Feedback(entry) => {
                    if let Err(e) = self.storage.append_feedback(&self.info, &entry).await {
                        tracing::warn!(?e, "failed to write feedback entry");
                    }
                }
                PersistenceMsg::Btw(entry) => {
                    if let Err(e) = self.storage.append_btw(&self.info, &entry).await {
                        tracing::warn!(?e, "failed to write btw entry");
                    }
                }
                PersistenceMsg::GitHead { commit, branch } => {
                    if let Err(e) = self
                        .storage
                        .update_git_head(&self.info, commit, branch)
                        .await
                    {
                        tracing::warn!(?e, "failed to persist git HEAD");
                    }
                }
                PersistenceMsg::ExecutionState { mutation, respond_to } => {
                    let result = crate::session::execution_state::apply(&session_dir(&self.info), mutation).await;
                    let _ = respond_to.send(result);
                }
                PersistenceMsg::CompactionCheckpoint(checkpoint) => {
                    if let Err(e) = self
                        .storage
                        .write_compaction_checkpoint(&self.info, &checkpoint)
                        .await
                    {
                        tracing::warn!(?e, "failed to write compaction checkpoint file");
                    }
                }
                PersistenceMsg::CommitCompactionAndAck { checkpoint, activation, cancel, respond_to } => {
                    use fuigo_chat_state::commands::CompactionCommitError;
                    let sync_marker = match (&self.remote_sync, &activation) {
                        (Some(_), SessionUpdate::Fuigo(marker)) => Some((**marker).clone()),
                        _ => None,
                    };
                    let result = async {
                        if cancel.is_cancelled() {
                            return Err(CompactionCommitError::NotCommitted(io::Error::other("compaction cancelled before prepare")));
                        }
                        self.storage.write_compaction_checkpoint(&self.info, &checkpoint).await.map_err(CompactionCommitError::NotCommitted)?;
                        if cancel.is_cancelled() {
                            // Retain prepared files as raw evidence; without a
                            // marker they have no replay authority.
                            return Err(CompactionCommitError::NotCommitted(io::Error::other("compaction cancelled before activation")));
                        }
                        // The rewrite of chat_history.jsonl with the projection follows the acknowledgement as a
                        // separate message. The witness lets a load tell that this marker committed while that rewrite
                        // never landed (a crash in between), and resume from the projection instead (P111, DI-03).
                        self.storage
                            .write_compaction_witness(&self.info, &checkpoint)
                            .await
                            .map_err(CompactionCommitError::NotCommitted)?;
                        self.handle_durable_append(activation).await.map_err(|error| match error {
                            crate::session::storage::AppendUpdateError::NotCommitted(error) => CompactionCommitError::NotCommitted(error),
                            crate::session::storage::AppendUpdateError::Committed(error) => CompactionCommitError::Committed(error),
                        })
                    }.await;
                    if matches!(&result, Ok(()) | Err(CompactionCommitError::Committed(_))) {
                        // The marker is on disk: witness entries of earlier compactions are no longer needed.
                        self.storage.compaction_activated(&self.info, &checkpoint.checkpoint_id).await;
                        // Carry the checkpoint through remote storage so a pulled copy resumes with its summary.
                        if let (Some(sync), Some(marker)) = (&self.remote_sync, &sync_marker)
                            && let Some(message) = crate::session::export::ExportedMessage::compaction_checkpoint(marker, &checkpoint)
                        {
                            sync.queue_checkpoint(message);
                        }
                    }
                    let _ = respond_to.send(result);
                }
                PersistenceMsg::CompactionRequest(request) => {
                    if let Err(e) = self
                        .storage
                        .write_compaction_request(&self.info, &request)
                        .await
                    {
                        tracing::warn!(?e, "failed to write compaction request artifact");
                    }
                }
                PersistenceMsg::RecapRequest(request) => {
                    if let Err(e) = self.storage.write_recap_request(&self.info, &request).await {
                        tracing::warn!(?e, "failed to write recap request artifact");
                    }
                }
                PersistenceMsg::CompactionSegment(segment) => {
                    if let Err(e) = self
                        .storage
                        .write_compaction_segment(&self.info, &segment)
                        .await
                    {
                        tracing::warn!(?e, "failed to write compaction segment");
                    }
                }
                PersistenceMsg::CopyFile { one_shot } => {
                    // Snapshot is best-effort. Leave the write-failure latch for FlushAndAck so persist_ack cannot fire after a miss.
                    let _ = self.flush_and_sync_all().await;

                    let result = self.copy_session_dir_to_memory().await;
                    let _ = one_shot.send(result);
                }
            }
        }

        let _ = self.flush_pending().await;
    }

    /// Replace `chat_history.jsonl` with `messages` (atomically: the file is the old history or the new one).
    async fn replace_chat_history_now(&mut self, messages: &[ConversationItem]) -> io::Result<()> {
        #[cfg(test)]
        if test_seam::take_history_replacement_failure(&self.info.id.0) {
            return Err(io::Error::other("injected chat history replacement failure"));
        }
        let result = self.storage.replace_chat_history(&self.info, messages).await;
        self.observe_io(&result);
        result
    }

    /// Replace the chat history for a caller that may not report success unless the new history is stored (a rewind).
    /// `Ok` when `chat_history.jsonl` holds `messages`, even if bookkeeping after that failed (the history is what the
    /// caller asked to persist); `Err` only when the file still holds the previous history, so the caller can keep it.
    async fn replace_chat_history_acknowledged(&mut self, messages: &[ConversationItem]) -> io::Result<()> {
        #[cfg(test)]
        if test_seam::take_history_replacement_failure(&self.info.id.0) {
            return Err(io::Error::other("injected chat history replacement failure"));
        }
        let result = self
            .storage
            .replace_chat_history_commit_aware(&self.info, messages)
            .await;
        self.observe_append_chat(&result);
        match result {
            Ok(()) => Ok(()),
            Err(crate::session::storage::AppendChatError::Committed(error)) => {
                tracing::warn!(%error, "chat history replaced; bookkeeping after it failed");
                Ok(())
            }
            Err(crate::session::storage::AppendChatError::NotCommitted(error)) => Err(error),
        }
    }

    async fn copy_session_dir_to_memory(&self) -> anyhow::Result<SessionStateCopy> {
        let session_dir = session_dir(&self.info);
        tokio::task::spawn_blocking(move || {
            let mut files = Vec::new();

            if !session_dir.exists() {
                return Ok(SessionStateCopy { files });
            }

            collect_session_files_recursive(&session_dir, &session_dir, &mut files);
            collect_mcp_stderr_logs(&mut files);

            Ok(SessionStateCopy { files })
        })
        .await?
    }
}

impl SessionPersistence {
    async fn persist_usage_turn(
        &mut self,
        turn_number: u32,
        live: &crate::session::usage_file::UsageSummary,
    ) -> io::Result<()> {
        let mut file = self
            .storage
            .read_usage(&self.info)
            .await?
            .unwrap_or_else(|| {
                crate::session::usage_file::SessionUsageFile::new(self.info.id.to_string())
            });
        // Fork copies parent usage.json verbatim; always restamp so the child is not attributed to the parent after new turns
        file.session_id = self.info.id.to_string();
        file.restore_apply_cursor(self.last_incoming_turn, self.last_usage_turn);
        file.apply_turn(
            turn_number,
            Utc::now().to_rfc3339(),
            live,
            self.last_usage_live.as_ref(),
        );
        let (incoming, written) = file.apply_cursor();
        self.storage.write_usage(&self.info, &file).await?;
        self.last_usage_live = Some(live.clone());
        self.last_incoming_turn = incoming;
        self.last_usage_turn = written;
        Ok(())
    }
}

#[path = "persistence_archive_logs.rs"]
mod archive_logs;

/// Collect MCP server stderr logs from `~/.fuigo/logs/mcp/` for inclusion in the session archive.
/// Each log is capped at [`archive_logs::MAX_ARCHIVED_LOG_BYTES`] (first and last half around a marker).
fn collect_mcp_stderr_logs(files: &mut Vec<CopiedSessionFile>) {
    let mcp_log_dir = fuigo_config::fuigo_home().join("logs").join("mcp");
    let Ok(entries) = std::fs::read_dir(&mcp_log_dir) else {
        return;
    };
    let mut paths: Vec<_> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        if path.extension().is_none_or(|ext| ext != "log") {
            continue;
        }
        let Some(file_name) = path.file_name() else {
            continue;
        };
        // Same open as the terminal logs: no link followed, never blocks on a FIFO, regular files only.
        let file = match crate::session::storage::open_beneath_nofollow(
            &mcp_log_dir,
            std::path::Path::new(file_name),
        ) {
            Ok(file) => file,
            Err(_) => {
                tracing::debug!(path = %path.display(), "session copy: MCP stderr log skipped");
                continue;
            }
        };
        if let Ok(data) = archive_logs::read_log_for_archive(file)
            && !data.is_empty()
        {
            let name = format!("mcp_stderr/{}", file_name.to_string_lossy());
            files.push(CopiedSessionFile { name, data });
        }
    }
}

/// Recursively collect all files from `dir` into `files`, using paths relative to `base`.
/// This captures subdirectories like `prompts/` which contain large-prompt files referenced by truncated chat history entries.
fn collect_session_files_recursive(base: &Path, dir: &Path, files: &mut Vec<CopiedSessionFile>) {
    collect_session_files_walk(base, dir, files);
    archive_logs::collect_terminal_logs(base, files);
}

/// The name a copied file carries: the path relative to the session folder with `/` between components on every OS (the
/// archive and the server use `/`). On unix a backslash can be part of a file name, so the path is used as it is; on
/// Windows the components are joined with `/`. `None` for a non-UTF-8 name (the file is skipped, as before).
pub(super) fn copied_file_name(rel_path: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        let mut parts = Vec::new();
        for component in rel_path.components() {
            parts.push(component.as_os_str().to_str()?);
        }
        Some(parts.join("/"))
    }
    #[cfg(not(windows))]
    {
        rel_path.to_str().map(str::to_owned)
    }
}

fn collect_session_files_walk(base: &Path, dir: &Path, files: &mut Vec<CopiedSessionFile>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            tracing::warn!(?dir, ?e, "Failed to read directory during session copy");
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        // Never through a symlink (P146): a link planted in the session folder (a checkpoint, a subdirectory) would
        // pull a file from outside it into the copy. `file_type` does not follow links, and the read opens every
        // folder and the file relative to the session folder without following one swapped in since.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_file() {
            let rel_path = match path.strip_prefix(base) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let Some(name) = copied_file_name(rel_path) else {
                continue;
            };
            let opened = match crate::session::storage::open_beneath_nofollow(base, rel_path) {
                Ok(file) => Ok(file),
                Err(crate::session::storage::BeneathRefusal::Io(error)) => Err(error),
                Err(crate::session::storage::BeneathRefusal::Refused(what)) => {
                    tracing::warn!(path = %path.display(), what, "session copy: file refused");
                    continue;
                }
            };
            let data = match opened.and_then(|mut file| {
                let mut data = Vec::new();
                std::io::Read::read_to_end(&mut file, &mut data).map(|_| data)
            }) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(?e, "Failed to read session file during copy");
                    continue;
                }
            };
            files.push(CopiedSessionFile {
                name,
                data,
            });
        } else if file_type.is_dir() && path != base.join(archive_logs::TERMINAL_DIR) {
            // `terminal/` is bounded separately (newest first, per-log cap) by `collect_terminal_logs`.
            collect_session_files_walk(base, &path, files);
        }
    }
}

/// Queue a fresh session's local-only ACP history to `remote_sync` (Ferrox Labs updates are never synced), returning the count.
/// Resumed sessions are forward-only.
/// Their prior history may already be on the backend (which appends by content, no per-message id), so re-sending would duplicate.
fn backfill_updates_to_sync(
    created_fresh: bool,
    updates: Vec<SessionUpdate>,
    remote_sync: &RemoteSync,
) -> usize {
    if !created_fresh {
        return 0;
    }
    let mut backfilled = 0usize;
    for update in updates {
        if let SessionUpdate::Acp(notification) = update {
            remote_sync.queue(*notification);
            backfilled += 1;
        }
    }
    remote_sync.flush();
    backfilled
}

fn init_remote_sync(
    summary: &Summary,
    storage_mode: StorageMode,
    auth_manager: Option<Arc<crate::auth::AuthManager>>,
) -> io::Result<Option<RemoteSync>> {
    match storage_mode {
        StorageMode::Local => Ok(None),
        StorageMode::Writeback => {
            let auth_manager = auth_manager.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Writeback storage mode requires authentication. Run 'fuigo login' first.",
                )
            })?;
            if let Some(auth) = auth_manager.current_or_expired() {
                if auth.is_zdr_team() {
                    tracing::debug!("ZDR team: skipping remote sync");
                    return Ok(None);
                }
            } else {
                tracing::warn!(
                    "writeback: no auth loaded yet, ZDR check skipped (backend enforces server-side)"
                );
            }
            tracing::info!("Writeback mode enabled, syncing to backend");
            let client =
                crate::remote::BackendClient::new().with_auth_manager(auth_manager.clone());
            let metadata = ExportedMetadata::from_summary(summary);
            Ok(Some(RemoteSync::new(
                summary.info.id.to_string(),
                metadata,
                client,
            )))
        }
    }
}

/// Pull a session from the backend if not found locally.
/// Returns the pulled session's [`Info`] (cwd may differ from caller's on different machines), or `None` if not found or on error.
async fn try_pull_from_remote(info: &Info, client: &crate::remote::BackendClient) -> Option<Info> {
    // BackendClient resolves auth internally via its auth_manager.
    client.auth_manager.as_ref()?;

    tracing::info!(session_id = %info.id, "Session not found locally, trying backend");

    match crate::remote::pull_session_to_local(&info.id.0, client).await {
        Ok(crate::remote::PullResult::Hydrated(pulled_info)) => {
            tracing::info!(
                session_id = %info.id,
                pulled_cwd = %pulled_info.cwd,
                "Pulled session from backend"
            );
            Some(pulled_info)
        }
        Ok(crate::remote::PullResult::NotFound) => {
            tracing::debug!(session_id = %info.id, "Session not found on backend either");
            None
        }
        Err(e) => {
            tracing::warn!(session_id = %info.id, error = %e, "Backend pull failed");
            None
        }
    }
}

pub(crate) fn is_disk_full_io_error(e: &io::Error) -> bool {
    if e.kind() == io::ErrorKind::StorageFull {
        return true;
    }
    #[cfg(unix)]
    {
        matches!(
            e.raw_os_error(),
            Some(raw) if raw == libc::ENOSPC || raw == libc::EDQUOT
        )
    }
    #[cfg(windows)]
    {
        const ERROR_DISK_FULL: i32 = 112;
        const ERROR_HANDLE_DISK_FULL: i32 = 39;
        matches!(
            e.raw_os_error(),
            Some(ERROR_DISK_FULL | ERROR_HANDLE_DISK_FULL)
        )
    }
    #[cfg(not(any(unix, windows)))]
    false
}

/// Map a persistence `io::Error` into an `acp::Error` with a human-friendly `message` and a stable `data.code` for log aggregation.
pub(crate) fn io_error_to_acp(e: &io::Error) -> acp::Error {
    let (message, code) = if is_disk_full_io_error(e) {
        ("No space left on device", "FS_DISK_QUOTA_EXCEEDED")
    } else {
        match e.kind() {
            io::ErrorKind::NotFound => ("Path not found.", "FS_NOT_FOUND"),
            io::ErrorKind::PermissionDenied => ("Permission denied.", "FS_PERMISSION_DENIED"),
            _ => {
                tracing::warn!(error = %e, kind = ?e.kind(), raw_os = ?e.raw_os_error(), "unclassified persistence I/O error");
                ("An unexpected I/O error occurred.", "FS_OTHER")
            }
        }
    };
    acp::Error::new(acp::ErrorCode::InternalError.into(), message.to_string()).data(
        crate::acp_error::error_data_with_fields(
            crate::acp_error::AcpErrorKind::SessionStorage,
            message,
            serde_json::json!({
                "code": code,
                "detail": e.to_string(),
            }),
        ),
    )
}

#[cfg(test)]
#[path = "persistence_io_error_to_acp_tests.rs"]
mod io_error_to_acp_tests;

/// Best-effort worktree liveness touch: stamp `last_accessed_at` on the worktree containing this session's cwd.
/// `fuigo worktree gc` then expires by last use, not creation time.
/// Lives here (not in a `StorageAdapter`) so every session create/load path shares it regardless of backend.
fn spawn_worktree_touch(info: &Info) -> tokio::task::JoinHandle<()> {
    let cwd = info.cwd.clone();
    tokio::task::spawn_blocking(move || {
        crate::session::worktree::touch_worktree_for_cwd(&cwd);
    })
}

/// Bound on how long session open waits for the liveness touch to commit.
/// Generous vs the DB's 5s busy_timeout without letting a pathologically locked worktrees.db stall init.
const WORKTREE_TOUCH_INIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Touch the worktree and wait (bounded) for the write to commit before the session open completes.
/// A detached touch can land after gc's pre-removal re-check reads the row, letting gc delete a worktree that is actively being opened or resumed.
/// Awaiting a blocking-pool task does not block the runtime.
/// On timeout the task keeps running detached (the old fire-and-forget behavior) and init proceeds.
async fn touch_worktree_for_session(info: &Info) {
    if tokio::time::timeout(WORKTREE_TOUCH_INIT_TIMEOUT, spawn_worktree_touch(info))
        .await
        .is_err()
    {
        tracing::debug!(
            cwd = %info.cwd,
            "worktree liveness touch still pending at session open"
        );
    }
}

/// Floor between activity-driven worktree touches from the persistence actor.
const WORKTREE_TOUCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// What the actor is handed once and holds for the life of the session.
pub(crate) struct SessionDeps {
    pub(crate) title_policy: crate::agent::config::TitlePolicy,
    pub(crate) sampling_client: OaiCompatClient,
    pub(crate) storage_mode: StorageMode,
    pub(crate) auth_manager: Option<Arc<crate::auth::AuthManager>>,
    pub(crate) relay_sync: Option<crate::relay::RelaySync>,
    pub(crate) gateway: Option<GatewaySender>,
    pub(crate) session_summary_model: String,
    pub(crate) registry_title_sync: Option<RegistryGeneratedTitleSync>,
    pub(crate) search_index: crate::session::storage::search::SharedSearchIndex,
    /// Client-claimed kind for a fresh session (allowlisted at `session/new`; currently only `"headless"`).
    /// Ignored by the load paths, which never restamp a persisted kind.
    pub(crate) session_kind: Option<String>,
}

pub(crate) async fn new(
    info: &Info,
    model_id: acp::ModelId,
    deps: SessionDeps,
) -> io::Result<PersistenceHandle> {
    let SessionDeps {
        title_policy,
        sampling_client,
        storage_mode,
        auth_manager,
        relay_sync,
        gateway,
        session_summary_model,
        registry_title_sync,
        search_index,
        session_kind,
    } = deps;
    let root_dir = fuigo_home();
    let storage: Box<dyn StorageAdapter> = Box::new(JsonlStorageAdapter::with_root(root_dir));

    let mut summary = storage.init_session(info, model_id.clone()).await?;
    touch_worktree_for_session(info).await;

    // Stamp the claimed kind only on a summary that has none yet: a dir left by a crash keeps its persisted kind (init_session already loaded it)
    // Goes through the locked atomic summary writer so it cannot clobber a concurrent writer's fields or leave a torn summary.json
    if summary.session_kind.is_none()
        && let Some(kind) = session_kind
    {
        storage
            .set_session_kind_if_absent(info, kind.clone())
            .await?;
        summary.session_kind = Some(kind);
    }

    if summary.current_model_id != model_id {
        storage.update_current_model(info, &model_id).await?;
        summary.current_model_id = model_id;
    }

    let (handle, rx, summary_tx, disk_full_tx, retry_status_mirror) = actor_channel();

    let info_clone = info.clone();
    let title_session_id = info.id.to_string();
    let storage: Arc<dyn StorageAdapter> = Arc::from(storage);
    let remote_sync = init_remote_sync(&summary, storage_mode, auth_manager)?;
    tokio::task::spawn(async move {
        let persistence = SessionPersistence {
            info: info_clone,
            storage: storage.clone(),
            pending_notification: None,
            rx,
            remote_sync: remote_sync.clone(),
            created_fresh: true,
            relay_sync,
            summary: crate::session::summary::SummaryGenerator::new(
                crate::session::summary::SummaryConfig {
                    session_id: title_session_id,
                    policy: title_policy,
                    sampling_client,
                    model: session_summary_model,
                    persistence_tx: summary_tx,
                },
            ),
            registry_title_sync,
            gateway,
            search_index,
            disk_full_tx,
            disk_full_notified: false,
            retry_status_mirror,
            dirty_files: Default::default(),
            pending_write_error: None,
            last_usage_live: None,
            last_usage_turn: None,
            last_incoming_turn: None,
            turn_start_guard: None,
        };
        persistence.run().await;
    });

    Ok(handle)
}

/// Create a persistence handle that writes to an explicit directory on disk.
/// Used for subagent child sessions (top-level `sessions/<cwd>/<id>` dirs; only their metadata nests under the parent's session dir).
///
/// Unlike [`new()`], this:
/// - Uses `JsonlStorageAdapter::with_explicit_session_dir()` to bypass the standard `{root}/sessions/{cwd}/{id}/` path computation.
/// - Skips remote sync (subagent sessions are not synced to cloud).
/// - Skips relay sync (subagent sessions are not shared).
/// - Skips gateway (lifecycle notifications are handled by the coordinator).
pub(crate) async fn new_with_explicit_dir(
    info: &Info,
    target_dir: PathBuf,
    model_id: acp::ModelId,
    sampling_client: OaiCompatClient,
    session_summary_model: String,
) -> io::Result<PersistenceHandle> {
    let summary_path = target_dir.join("summary.json");
    let storage: Box<dyn StorageAdapter> =
        Box::new(JsonlStorageAdapter::with_explicit_session_dir(target_dir));

    let mut summary = storage.init_session(info, model_id.clone()).await?;
    touch_worktree_for_session(info).await;
    // A worktree cwd pre-stamps `"worktree"` in `Summary::new`
    // Without the override here the subagent would appear in user session listings (`is_hidden` only hides `subagent*` kinds)
    if summary
        .session_kind
        .as_deref()
        .is_none_or(|kind| kind == WORKTREE_SESSION_KIND)
    {
        summary.session_kind = Some("subagent".to_string());
        summary.source_workspace_dir = None;
    }
    let summary_json = serde_json::to_vec_pretty(&summary)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(&summary_path, summary_json)?;

    if summary.current_model_id != model_id {
        storage.update_current_model(info, &model_id).await?;
        summary.current_model_id = model_id;
    }

    let (handle, rx, summary_tx, disk_full_tx, retry_status_mirror) = actor_channel();

    let info_clone = info.clone();
    let title_session_id = info.id.to_string();
    let storage: Arc<dyn StorageAdapter> = Arc::from(storage);
    tokio::task::spawn(async move {
        let persistence = SessionPersistence {
            info: info_clone,
            storage: storage.clone(),
            pending_notification: None,
            rx,
            remote_sync: None,
            created_fresh: false,
            relay_sync: None,
            summary: crate::session::summary::SummaryGenerator::new(
                crate::session::summary::SummaryConfig {
                    session_id: title_session_id,
                    policy: Default::default(),
                    sampling_client,
                    model: session_summary_model,
                    persistence_tx: summary_tx,
                },
            ),
            registry_title_sync: None,
            gateway: None,
            // A bootstrap never sees a subagent session: `list_sessions_sync` drops hidden summaries, and a subagent kind is hidden
            // Skip it here too
            search_index: crate::session::storage::search::SharedSearchIndex::never_indexed(),
            disk_full_tx,
            disk_full_notified: false,
            retry_status_mirror,
            dirty_files: Default::default(),
            pending_write_error: None,
            last_usage_live: None,
            last_usage_turn: None,
            last_incoming_turn: None,
            turn_start_guard: None,
        };
        persistence.run().await;
    });

    Ok(handle)
}

/// Restore payload without updates in memory, for streaming replay.
pub struct PersistedInfo {
    pub summary: Summary,
    pub chat_history: Vec<ConversationItem>,
    pub plan_state: Option<TodoState>,
    pub plan_mode_state: Option<crate::session::plan_mode::PlanModeSnapshot>,
    /// Path to updates file for streaming reads
    pub updates_file_path: Option<std::path::PathBuf>,
    /// Adapter-owned path to `rewind_points.jsonl` for the session's `FileStateTracker` to load lazily.
    /// `None` if the backend doesn't persist rewind points to a streamable file.
    pub rewind_points_file_path: Option<std::path::PathBuf>,
    /// Persisted session signals (None for old sessions without signals file)
    pub signals: Option<SessionSignals>,
    /// Persisted announcement tracking state (None for sessions before this feature)
    pub announcement_state: Option<crate::session::announcement_state::AnnouncementState>,
    /// Persisted goal mode orchestration state (None for sessions without goal mode)
    pub goal_mode_state: Option<crate::session::goal_tracker::GoalOrchestration>,
    pub workflow_runs: Vec<crate::session::workflow::store::RestoredWorkflowRun>,
    /// Set when `chat_history` was repaired at load after unreadable lines (P96): the note to show the user.
    pub history_repair_notice: Option<String>,
}

/// On NotFound, try pulling from backend. Returns pulled info or the original error.
async fn pull_on_miss(
    info: &Info,
    client: &crate::remote::BackendClient,
    err: io::Error,
) -> io::Result<Info> {
    if err.kind() != io::ErrorKind::NotFound {
        return Err(err);
    }
    try_pull_from_remote(info, client).await.ok_or(err)
}

/// Resume never depends on the latest compaction checkpoint (see [`load_light`]), but a rewind past that compaction
/// does: it reads the checkpoint file and refuses when it is missing or unreadable. Say so once, at load, instead of
/// failing the load the way 1.0.10-1.0.19 did (L-1). Never returns an error.
async fn warn_on_unreadable_compaction_checkpoint(
    storage: &dyn StorageAdapter,
    info: &Info,
    updates_path: &std::path::Path,
) {
    let checkpoint = match crate::session::helpers::replay::find_latest_compaction_checkpoint(updates_path) {
        Ok(Some(checkpoint)) => checkpoint,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(session_id = %info.id.0, %error,
                "could not scan updates.jsonl for compaction checkpoints; resuming from chat_history.jsonl");
            return;
        }
    };
    let problem = match storage.read_compaction_checkpoint(info, &checkpoint.checkpoint_file).await {
        Ok(file) if file.schema_version == 1 && checkpoint.schema_version == 1 => return,
        Ok(file) => format!(
            "unsupported checkpoint schema (marker {}, file {})",
            checkpoint.schema_version, file.schema_version
        ),
        Err(error) => error.to_string(),
    };
    tracing::warn!(
        session_id = %info.id.0,
        checkpoint = %checkpoint.checkpoint_file,
        %problem,
        "latest compaction checkpoint is unreadable; resuming from chat_history.jsonl \
         (rewinding to before this compaction will not be possible)"
    );
}

/// Load a session without reading updates into memory.
/// Instead, provides the path to the updates file for streaming reads.
pub(crate) async fn load_light(
    info: &Info,
    backend: Option<&crate::remote::BackendClient>,
    deps: SessionDeps,
) -> io::Result<(PersistedInfo, PersistenceHandle)> {
    let SessionDeps {
        title_policy,
        sampling_client,
        storage_mode,
        auth_manager,
        relay_sync,
        gateway,
        session_summary_model,
        registry_title_sync,
        search_index,
        session_kind: _,
    } = deps;
    let root_dir = fuigo_home();
    let jsonl_storage = JsonlStorageAdapter::with_root(root_dir.clone());
    let storage: Box<dyn StorageAdapter> = Box::new(jsonl_storage.clone());

    // A rewind Fuigo was killed in the middle of left its durable copy of rewind_points.jsonl behind: undone or
    // finished here, under the rewind's own lock, before anything of the session is read (P164, K19). The history
    // this load returns is read after it (Astra r3): read before, it could be the conversation a rewind that went
    // through had already replaced, which startup would then write back. It also runs before the repair below, which
    // may rewrite chat_history.jsonl, the file that tells whether the rewind went through. A session only on the
    // backend has no leftover here.
    let rewind_notice = jsonl_storage.reconcile_interrupted_rewind(info).await;
    let (mut persisted, loaded_info) = match storage.load_session_without_updates(info).await {
        Ok(p) => (p, info.clone()),
        Err(e) => match backend {
            Some(client) => {
                let pulled = pull_on_miss(info, client, e).await?;
                let p = storage.load_session_without_updates(&pulled).await?;
                (p, pulled)
            }
            None => return Err(e),
        },
    };
    #[cfg(any(test, feature = "test-support"))]
    crate::session::storage::rewind_crash_seam::note_history_read(
        &loaded_info.id.0,
        crate::session::storage::rewind_points_pre_rewind_copy(&session_dir(&loaded_info).join("rewind_points.jsonl"))
            .symlink_metadata()
            .is_ok(),
    );
    // A torn line the reader skipped can leave a tool result without its call, which strict providers reject on every
    // request. Repair that here, behind a backup of the file as found (P96). The same holds when an earlier load
    // skipped the line and left its `.corrupt` copy (a session that broke before P96). The repair does nothing for a
    // session a live actor holds (a reconnect, or another process): it needs the exclusive turn-owner lock.
    // A compaction that committed (its marker is in updates.jsonl) while its rewrite of chat_history.jsonl never
    // landed left the history from before it in the file, followed by everything written since. The load already took
    // the checkpoint's projection and those later items instead (P111, DI-03; `load_session_without_updates`), and
    // counts their unreadable lines, so the repair below covers the recovered history too; spawn persists it.
    let repair_notice = jsonl_storage
        .repair_after_corrupt_load(&loaded_info, &mut persisted)
        .await
        .map(|repair| repair.notice());
    let history_repair_notice = match (rewind_notice, repair_notice) {
        (Some(rewind), Some(repair)) => Some(format!("{rewind}\n{repair}")),
        (rewind, repair) => rewind.or(repair),
    };
    // Touch on load too: resuming must reset the worktree's gc expiry clock.
    touch_worktree_for_session(&loaded_info).await;

    let updates_file_path = storage.updates_file_path(&loaded_info);
    let rewind_points_file_path = storage.rewind_points_file_path(&loaded_info);

    // `chat_history.jsonl` is the model's own record and stays authoritative on resume, compacted or not: after a
    // compaction commits, the chat-state actor rewrites it to the exact compacted projection and appends every later
    // message (tool calls and tool results included) to it. 1.0.10-1.0.19 replaced it here with
    // `replay_to_prompt(updates.jsonl)`, a text-only rebuild meant for rewinds, which drops tool calls and results and
    // merges the assistant text around them (P88). The checkpoint is only inspected so a damaged one is reported; it
    // never decides what the model sees and never fails the load (it used to).
    if let Some(updates_path) = updates_file_path.as_ref() {
        warn_on_unreadable_compaction_checkpoint(storage.as_ref(), &loaded_info, updates_path).await;
    }

    let persisted_info = PersistedInfo {
        summary: persisted.summary,
        chat_history: persisted.chat_history,
        plan_state: persisted.plan_state,
        plan_mode_state: persisted.plan_mode_state,
        updates_file_path,
        rewind_points_file_path,
        signals: persisted.signals,
        announcement_state: persisted.announcement_state,
        goal_mode_state: persisted.goal_mode_state,
        workflow_runs: persisted.workflow_runs,
        history_repair_notice,
    };

    let (handle, rx, summary_tx, disk_full_tx, retry_status_mirror) = actor_channel();

    let storage: Arc<dyn StorageAdapter> = Arc::from(storage);
    let remote_sync = init_remote_sync(&persisted_info.summary, storage_mode, auth_manager)?;

    let has_title = !persisted_info.summary.display_title().is_empty();
    tokio::task::spawn(async move {
        let mut summary_gen = crate::session::summary::SummaryGenerator::new(
            crate::session::summary::SummaryConfig {
                session_id: loaded_info.id.to_string(),
                policy: title_policy,
                sampling_client,
                model: session_summary_model,
                persistence_tx: summary_tx,
            },
        );
        if has_title {
            summary_gen.mark_done();
        }
        let persistence = SessionPersistence {
            info: loaded_info,
            storage: storage.clone(),
            pending_notification: None,
            rx,
            remote_sync: remote_sync.clone(),
            created_fresh: false,
            relay_sync,
            summary: summary_gen,
            registry_title_sync,
            gateway,
            search_index,
            disk_full_tx,
            disk_full_notified: false,
            retry_status_mirror,
            dirty_files: Default::default(),
            pending_write_error: None,
            last_usage_live: None,
            last_usage_turn: None,
            last_incoming_turn: None,
            turn_start_guard: None,
        };
        persistence.run().await;
    });

    Ok((persisted_info, handle))
}

/// List session summaries, optionally filtered by cwd (absolute path string).
/// Returns summaries sorted by `last_active_at` (else `updated_at`) descending.
pub async fn list_summaries(cwd: Option<&str>) -> io::Result<Vec<Summary>> {
    let root_dir = crate::util::fuigo_home::fuigo_home();
    let storage: Box<dyn StorageAdapter> = Box::new(JsonlStorageAdapter::with_root(root_dir));
    storage.list_sessions(cwd).await
}

/// Failure modes of [`delete_session_history`].
///
/// Kept distinct so callers can report a precise message.
/// A remote failure is reported separately from a local-disk failure: the remote delete runs first and aborts the whole operation.
#[derive(Debug, thiserror::Error)]
pub enum DeleteSessionError {
    /// Listing local summaries (to resolve the on-disk session dir) failed.
    #[error("failed to list sessions: {0}")]
    List(#[source] io::Error),
    /// The remote (writeback) copy could not be deleted; local bits were left untouched so the operation can be retried.
    #[error("failed to delete remote session data: {0}")]
    Remote(#[source] crate::remote::client::BackendError),
    /// The local on-disk session directory could not be removed.
    #[error("failed to delete session: {0}")]
    Local(#[source] io::Error),
}

/// Where a session copy was actually removed by [`delete_session_history`].
///
/// Both fields are `false` when nothing existed to delete (still a success).
/// Callers use [`Self::any_removed`] to decide between a "deleted" and a "not found" message without conflating a remote-only delete with a no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionDeletion {
    /// A local on-disk session directory was found and removed.
    pub local_removed: bool,
    /// A remote (writeback) copy was found and removed.
    /// `false` when `needs_remote` was not set, or the remote copy was already absent (the backend returned `404`).
    pub remote_removed: bool,
}

impl SessionDeletion {
    pub fn any_removed(self) -> bool {
        self.local_removed || self.remote_removed
    }
}

/// Permanently delete a session's history.
/// This removes the remote (writeback) copy when `needs_remote`, the local on-disk session directory, and the FTS search-index entry.
///
/// Idempotent: a session that is missing locally (e.g. remote-only) still succeeds.
/// A remote `404` (copy already gone) is treated as success rather than an error.
/// When `needs_remote` is set the remote delete runs *first* and is authoritative: only on its success (or a `404`) are the local bits removed.
/// This ordering prevents a partial delete where the local copy is nuked but the remote copy lingers and re-appears on the next session list.
///
/// Returns a [`SessionDeletion`] recording which copies (local / remote) were actually removed.
/// Both fields `false` means nothing existed (still `Ok`).
pub async fn delete_session_history(
    session_id: &str,
    cwd: Option<&str>,
    needs_remote: bool,
    auth_manager: Arc<crate::auth::AuthManager>,
    search_index: Option<&fuigo_session_search::SearchIndexManager>,
) -> Result<SessionDeletion, DeleteSessionError> {
    let sid = acp::SessionId::new(Arc::from(session_id));

    // Resolve the local session info, scoping to cwd if provided
    // A remote-only session won't be found here; that's fine, the remote delete (if applicable) still runs
    let summaries = list_summaries(cwd)
        .await
        .map_err(DeleteSessionError::List)?;
    let local_info = summaries
        .iter()
        .find(|s| s.info.id == sid)
        .map(|s| s.info.clone());

    // Remote delete first (authoritative for cloud history)
    // A genuine failure aborts before any local mutation so the row does not reappear
    // A `404` means the copy is already gone, so deletion stays idempotent and falls through to local cleanup
    let remote_removed = if needs_remote {
        let result = crate::remote::client::BackendClient::new()
            .with_auth_manager(auth_manager)
            .delete_session_data(session_id)
            .await;
        classify_remote_delete(result)?
    } else {
        false
    };

    let removed = match local_info {
        Some(info) => {
            JsonlStorageAdapter::default()
                .delete_session(&info)
                .await
                .map_err(DeleteSessionError::Local)?;
            Some(info)
        }
        None => None,
    };
    let local_removed = removed.is_some();

    // Also evict when no workspace was named: that row outlives the directory and nothing else prunes it
    if local_removed || cwd.is_none() {
        crate::session::storage::search::evict_session(
            &crate::util::fuigo_home::fuigo_home(),
            session_id,
        )
        .await;
    }
    // The eviction above is a point in time
    // Queue the indexer too so an upsert already under way, which would otherwise write the row back, is followed by a re-read that finds nothing
    if let Some(info) = removed {
        crate::session::storage::search::notify_session_updated(
            search_index,
            &info.id.to_string(),
            &info.cwd,
        );
    }

    Ok(SessionDeletion {
        local_removed,
        remote_removed,
    })
}

/// Classify a remote `delete_session_data` result, reporting whether a remote copy was actually removed.
/// A `2xx` means a copy was deleted (`Ok(true)`); a `404` means it was already gone so deletion stays idempotent (`Ok(false)`).
/// Any other backend error aborts the delete (`Err`) so local bits are left untouched and it can be retried.
fn classify_remote_delete(
    result: Result<(), crate::remote::client::BackendError>,
) -> Result<bool, DeleteSessionError> {
    use crate::remote::client::BackendError;
    match result {
        Ok(()) => Ok(true),
        Err(BackendError::RequestFailed { status: 404, .. }) => Ok(false),
        Err(e) => Err(DeleteSessionError::Remote(e)),
    }
}

#[cfg(test)]
#[path = "persistence_tests.rs"]
mod durable_update_tests;

#[cfg(test)]
#[path = "persistence_delete_session_history_tests.rs"]
mod delete_session_history_tests;

#[cfg(test)]
#[path = "persistence_worktree_stamp_tests.rs"]
mod worktree_stamp_tests;

/// List the `limit` most recently modified session summaries across all workspaces.
/// Uses stat-based mtime sorting to avoid reading every summary file on disk; final order uses `last_active_at` else `updated_at`.
pub async fn list_recent_summaries(limit: usize) -> io::Result<Vec<Summary>> {
    let root_dir = crate::util::fuigo_home::fuigo_home();
    let storage = JsonlStorageAdapter::with_root(root_dir);
    storage.list_sessions_recent(limit).await
}

// Session folder TTL cleanup

static CLEANUP_SESSIONS_ONCE: std::sync::Once = std::sync::Once::new();

const DEFAULT_CLEANUP_TTL_DAYS: u32 = 30;

/// P172 (D1): the only folders swept inside a session that is still in use. Everything else in a session folder
/// (compaction checkpoints, prompt offloads, rewind points, chat and update history, subagent transcripts) is a
/// write-once artifact a resume or rewind still reads, so its own age says nothing about whether it is needed.
const SWEPT_BLOB_DIRS: [&str; 4] = ["images", "videos", "downloads", archive_logs::TERMINAL_DIR];

/// Walk `~/.fuigo/sessions/` once per process and age out what is older than `[storage] cleanup_ttl_days` (30 days
/// by default), judging each session folder as a unit:
/// - a session whose newest file (in the folder or its subfolders) is older than the TTL (nobody has used it for that
///   long) is removed whole;
/// - any other session keeps everything except stale files in its disposable caches ([`SWEPT_BLOB_DIRS`]);
/// - `live_session_dir` (the session this process is attaching) is never removed, only its caches are pruned.
///
/// Callers [`mark_session_live`] first, so other processes' sweeps see the attach. Symlinks are never followed.
///
/// This is a **synchronous** function intended to be called via `tokio::task::spawn_blocking`.
/// It then runs on the thread pool and never competes with the agent's single-threaded `LocalSet`.
#[tracing::instrument(skip_all)]
pub(crate) fn cleanup_stale_sessions(live_session_dir: &Path) {
    CLEANUP_SESSIONS_ONCE.call_once(|| {
        let ttl_days = resolve_cleanup_ttl_days();
        let sessions_root = fuigo_home().join("sessions");

        tracing::info!(
            target: "fuigo_shell::session::persistence",
            sessions_root = %sessions_root.display(),
            ttl_days,
            live = %live_session_dir.display(),
            "SESSION_CLEANUP_START: scanning for stale sessions"
        );

        let stats = cleanup_stale_sessions_inner(
            &sessions_root,
            ttl_days,
            Some(live_session_dir),
            CleanupLevel::SessionsRoot,
        );

        tracing::info!(
            target: "fuigo_shell::session::persistence",
            sessions_root = %sessions_root.display(),
            files_deleted = stats.files_deleted,
            dirs_removed = stats.dirs_removed,
            sessions_removed = stats.sessions_removed,
            errors = stats.errors,
            "SESSION_CLEANUP_DONE"
        );
    });
}

pub(crate) fn session_sweep_done() -> bool {
    CLEANUP_SESSIONS_ONCE.is_completed()
}

/// Prefix of the lock an attach holds shared while it marks its session live, and the sweep holds exclusively from
/// before its last look at an idle session until that session has left its path: `<cwd folder>/<prefix><session>`.
/// Separate from `turn_owner.lock`, whose exclusive holder can also be an interrupted-turn recovery (seconds long): an
/// attach must never wait for that here. P178: it lives NEXT TO the session folder, not in it, because Windows (NTFS)
/// refuses to rename a folder while any handle beneath it is open, so a lock held inside the folder would block the
/// very rename it protects. A dot name is never listed as a session.
pub(crate) const SWEEP_LOCK_PREFIX: &str = ".fuigo-sweep-lock-";

/// A session used this recently cannot be removed by any sweep, whatever its TTL (`cleanup_ttl_days` is at least 1),
/// for at least the next hour. It is the timestamp side of an unbumpable mark; the load's guard is the sweep lock its
/// [`LiveMark`] holds until the actor holds `turn_owner.lock` (P176).
const UNMARKED_SAFE_AGE: std::time::Duration = std::time::Duration::from_secs(23 * 3600);

/// Prefix of the name an idle session is renamed to (next to it, in its cwd folder) before it is deleted. A dot name
/// is never listed as a session; a leftover (an interrupted delete) is removed by the next sweep.
const REMOVING_PREFIX: &str = ".fuigo-sweep-removing-";

/// Prefix of the name a session is kept under when the sweep had to put it back (something marked it while it was
/// being removed) and its path had been taken meanwhile. A dot name, never listed and never removed by a sweep.
const KEPT_PREFIX: &str = ".fuigo-sweep-kept-";

#[path = "persistence_sweep_pin.rs"]
mod sweep_pin;

/// How long an attach waits for a sweep that is removing its session right now. The sweep holds its sweep lock only
/// for its last look and one rename, so reaching this means that process is stuck.
const MARK_LIVE_WAIT_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Why an attach could not mark its session live, and so must not load it.
#[derive(Debug)]
pub(crate) enum MarkLiveError {
    /// A sweep in another process held this session's sweep lock past [`MARK_LIVE_WAIT_LIMIT`].
    SweepBusy,
    /// Nothing in a session idle for a day or more could be bumped (read-only files, a Windows sharing violation): a
    /// concurrent sweep could remove it while it loads.
    Unmarkable { dir: PathBuf, error: io::Error },
}

impl MarkLiveError {
    pub(crate) fn into_acp_error(self) -> agent_client_protocol::Error {
        match self {
            Self::SweepBusy => crate::acp_error::session_unavailable(
                "This session is being cleaned up by another Fuigo process. Retry loading it in a moment; if this \
                 persists, that process may be stuck and restarting it releases the session.",
            ),
            Self::Unmarkable { dir, error } => crate::acp_error::session_unavailable(format!(
                "This session was not loaded: Fuigo could not record that it is in use, because neither summary.json \
                 nor updates.jsonl in {} could be updated ({error}). Without that record the 30-day session cleanup \
                 of another Fuigo process could remove the session while it loads. Make those files writable (or \
                 close the program holding them) and retry.",
                dir.display()
            )),
        }
    }
}

/// Bumps `summary.json`'s mtime so a sweep (this process's or another's) sees the attach that is about to read this
/// session folder. Runs before the session is read and before this process's sweep is spawned: the sweep's live-dir
/// exclusion only covers one folder in one process, and neither loading nor initialising a session rewrites the
/// summary. A folder without a regular `summary.json` (a fresh `session/new`, a stub, a session just removed) has
/// nothing to bump.
///
/// The mark holds the session's sweep lock ([`SWEEP_LOCK_PREFIX`]) shared, so it cannot fall between a sweep's last
/// look at this session and the rename that takes the session off its path: either the sweep looks after the mark and
/// keeps the session, or the mark waits (asynchronously) until the session is gone and finds nothing to mark, and the
/// load then finds no session, never a half one. Nothing is written, and no link is followed (`O_NOFOLLOW`, a FIFO
/// cannot block the open; `FILE_FLAG_OPEN_REPARSE_POINT` on Windows).
///
/// P178: when `summary.json` cannot be bumped, `updates.jsonl` is (the sweep counts both); when neither can, the load
/// fails ([`MarkLiveError::Unmarkable`]) unless the session was used within [`UNMARKED_SAFE_AGE`], which no sweep can
/// remove during a load.
pub(crate) async fn mark_session_live(session_dir: &Path) -> Result<LiveMark, MarkLiveError> {
    mark_session_live_waiting(session_dir, MARK_LIVE_WAIT_LIMIT).await
}

/// What an attach holds from its mark until its actor holds `turn_owner.lock` shared (P176): the session's sweep lock,
/// shared. No sweep can take it exclusively meanwhile, so the session cannot be removed while it loads, however long
/// the load takes or is suspended (before P176 only the mark's timestamp protected it, which a load suspended past the
/// TTL outlived). Dropping it releases the lock; the actor's `turn_owner.lock` protects the session from then on.
#[must_use = "hold the mark until the session's actor holds turn_owner.lock"]
#[derive(Debug)]
pub(crate) struct LiveMark {
    _sweep_lock: Option<crate::session::storage::jsonl::HeldLock>,
}

async fn mark_session_live_waiting(
    session_dir: &Path,
    wait_limit: std::time::Duration,
) -> Result<LiveMark, MarkLiveError> {
    mark_session_live_with(session_dir, wait_limit, &touch_nofollow).await
}

/// `touch` bumps one file's mtime (tests inject one that fails, as a read-only file or a Windows sharing violation
/// does).
async fn mark_session_live_with(
    session_dir: &Path,
    wait_limit: std::time::Duration,
    touch: &dyn Fn(&Path) -> io::Result<()>,
) -> Result<LiveMark, MarkLiveError> {
    let summary = session_dir.join("summary.json");
    let is_regular_summary =
        || std::fs::symlink_metadata(&summary).is_ok_and(|metadata| metadata.file_type().is_file());
    if !is_regular_summary() {
        return Ok(LiveMark { _sweep_lock: None });
    }
    // Without the lock (a filesystem without advisory locks, a planted link) the mark goes ahead unguarded: loads keep
    // working there. A sweep that cannot lock either keeps the session; one that can (a lock failure in this process
    // only) still keeps it, because it looks at the session again after taking it off its path and puts back one
    // that anything marked in between (`cleanup_pinned_session`, P176)
    let shared = match open_sweep_lock(session_dir) {
        Some(lock) => {
            if take_lock_waiting(&lock, false, wait_limit).await == LockWait::Busy {
                tracing::warn!(
                    dir = %session_dir.display(),
                    "a session sweep held this session past the limit; failing the load"
                );
                return Err(MarkLiveError::SweepBusy);
            }
            Some(crate::session::storage::jsonl::HeldLock::new(lock))
        }
        None => None,
    };
    let mark = LiveMark { _sweep_lock: shared };
    if !is_regular_summary() {
        return Ok(mark);
    }
    // P178 (Astra r1): a worktree identity repair (`summary_write::repair_worktree_identity`, run by session listing)
    // records summary.json's mtime, rewrites the file and restores that older mtime, all under `summary.json.lock`. A
    // bump in between would be erased and the sweep would then see an idle session this attach is loading. So the
    // summary is bumped under the same lock; when it cannot be taken (a writer holds it past the limit, a planted
    // link) the transcript is bumped instead, which the repair never touches.
    // Only a lock actually taken excludes a repair (Astra r2); it is held to the end of the mark.
    let summary_lock = match open_lock_nofollow(session_dir, SUMMARY_LOCK_FILE) {
        Some(lock) if take_lock_waiting(&lock, true, wait_limit).await == LockWait::Taken => Some(crate::session::storage::jsonl::HeldLock::new(lock)),
        _ => None,
    };
    let summary_held = summary_lock.is_some();
    let error = if summary_held {
        match touch(&summary) {
            Ok(()) => return Ok(mark),
            Err(error) => error,
        }
    } else {
        io::Error::other("summary.json.lock could not be taken")
    };
    // The transcript is the other file the sweep's activity rule always sees
    let updates = session_dir.join("updates.jsonl");
    if touch(&updates).is_ok() {
        tracing::debug!(
            target: "fuigo_shell::session::persistence",
            file = %summary.display(),
            %error,
            "SESSION_MARK_LIVE_ERROR: marked updates.jsonl instead"
        );
        return Ok(mark);
    }
    // Recent use is trusted only under the summary lock: without it, an identity repair may have published a fresh
    // summary that it is about to backdate (Astra r2). The summary lock this mark may just have created is not use.
    let recently_used = summary_held
        && session_activity_scan(
            session_dir,
            ACTIVITY_SCAN_MAX_ENTRIES,
            &[crate::session::turn_owner_lock::TURN_OWNER_LOCK_FILE, SUMMARY_LOCK_FILE],
        )
        .is_ok_and(|newest| {
            newest.is_some_and(|mtime| mtime.elapsed().map_or(true, |age| age < UNMARKED_SAFE_AGE))
        });
    tracing::warn!(
        target: "fuigo_shell::session::persistence",
        dir = %session_dir.display(),
        %error,
        recently_used,
        "SESSION_MARK_LIVE_ERROR: neither summary.json nor updates.jsonl could be marked"
    );
    if recently_used {
        return Ok(mark);
    }
    Err(MarkLiveError::Unmarkable { dir: session_dir.to_path_buf(), error })
}

/// The sidecar lock every `summary.json` writer holds (`storage::summary_write`).
const SUMMARY_LOCK_FILE: &str = "summary.json.lock";

/// How [`take_lock_waiting`] ended.
#[derive(Debug, PartialEq, Eq)]
enum LockWait {
    Taken,
    /// Another holder kept it past the limit.
    Busy,
    /// A lock error that is not contention (a filesystem without advisory locks): no other party can hold it there
    /// either, but it is not held.
    Unsupported,
}

/// Waits (asynchronously) until `lock` is taken, shared or exclusive.
async fn take_lock_waiting(lock: &std::fs::File, exclusive: bool, wait_limit: std::time::Duration) -> LockWait {
    let started = tokio::time::Instant::now();
    loop {
        // UFCS: std's inherent `File::try_lock*` (Rust 1.89+) return a different error type.
        let attempt =
            if exclusive { fs2::FileExt::try_lock_exclusive(lock) } else { fs2::FileExt::try_lock_shared(lock) };
        match attempt {
            Err(error) if fuigo_workspace::util::is_lock_contended(&error) => {
                if started.elapsed() >= wait_limit {
                    return LockWait::Busy;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(_) => return LockWait::Unsupported,
            Ok(()) => return LockWait::Taken,
        }
    }
}

/// Sets `path`'s mtime to now without following a link at that path and without writing anything. Fails on a missing,
/// non-regular or unwritable file.
fn touch_nofollow(path: &Path) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    // Write access is required for `set_modified` on Windows; nothing is written
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        // Open the entry itself, never the target of a link swapped in after the caller's check; a link opened this
        // way is not a regular file and is refused below
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    file.set_modified(std::time::SystemTime::now())
}

/// Where `session_dir`'s sweep lock lives: next to it, never inside it (see [`SWEEP_LOCK_PREFIX`]).
fn sweep_lock_path(session_dir: &Path) -> Option<PathBuf> {
    let name = session_dir.file_name()?.to_string_lossy();
    Some(session_dir.parent()?.join(format!("{SWEEP_LOCK_PREFIX}{name}")))
}

/// The lock an attach holds shared while it marks `session_dir` live (see [`SWEEP_LOCK_PREFIX`]).
fn open_sweep_lock(session_dir: &Path) -> Option<std::fs::File> {
    let path = sweep_lock_path(session_dir)?;
    open_lock_nofollow(path.parent()?, &path.file_name()?.to_string_lossy())
}

/// Resolve TTL from config.toml `[storage] cleanup_ttl_days`, falling back to 30.
fn resolve_cleanup_ttl_days() -> u32 {
    if let Ok(layers) = crate::config::ConfigLayers::load() {
        let effective = layers.effective_config_disk_only();
        if let Some(storage) = effective.get("storage")
            && let Some(ttl) = storage.get("cleanup_ttl_days")
            && let Some(days) = ttl.as_integer()
            && days > 0
        {
            return days as u32;
        }
    }
    DEFAULT_CLEANUP_TTL_DAYS
}

#[derive(Debug, Default, PartialEq)]
struct CleanupStats {
    files_deleted: u32,
    dirs_removed: u32,
    sessions_removed: u32,
    errors: u32,
}

impl CleanupStats {
    fn absorb(&mut self, other: CleanupStats) {
        self.files_deleted += other.files_deleted;
        self.dirs_removed += other.dirs_removed;
        self.sessions_removed += other.sessions_removed;
        self.errors += other.errors;
    }
}

/// `sessions/` holds one folder per encoded cwd, each holding session folders.
#[derive(Clone, Copy)]
enum CleanupLevel {
    SessionsRoot,
    Cwd,
}

/// Stray files at these two levels (`session_search.sqlite`, `prompt_history.jsonl`) keep the per-file mtime rule;
/// dot entries (the `.cwd` markers, hidden indexes) and symlinks are skipped. P176: `root` is pinned and every folder
/// below it is opened relative to its pinned parent, never through a link ([`sweep_pin::PinnedDir`]).
fn cleanup_stale_sessions_inner(
    root: &Path,
    ttl_days: u32,
    live_session_dir: Option<&Path>,
    level: CleanupLevel,
) -> CleanupStats {
    match sweep_pin::PinnedDir::open_root(root) {
        Ok(root) => cleanup_pinned_level(&[], &root, ttl_days, live_session_dir, level),
        Err(_) => CleanupStats::default(),
    }
}

fn cleanup_pinned_level(
    ancestors: &[&sweep_pin::PinnedDir],
    dir: &sweep_pin::PinnedDir,
    ttl_days: u32,
    live_session_dir: Option<&Path>,
    level: CleanupLevel,
) -> CleanupStats {
    use sweep_pin::EntryKind;

    let mut stats = CleanupStats::default();
    let names = match dir.entry_names() {
        Ok(names) => names,
        Err(error) => {
            tracing::debug!(
                target: "fuigo_shell::session::persistence",
                dir = %dir.path().display(),
                %error,
                "SESSION_CLEANUP_READ_ERROR"
            );
            stats.errors += 1;
            return stats;
        }
    };
    let chain: Vec<&sweep_pin::PinnedDir> = ancestors.iter().copied().chain(std::iter::once(dir)).collect();

    for name in names {
        let name_text = name.to_string_lossy().into_owned();
        if name_text.starts_with(REMOVING_PREFIX) && matches!(level, CleanupLevel::Cwd) {
            // An idle session whose removal was decided and started (it was renamed off its path) but not finished.
            // P176: only under its session's sweep lock, held exclusively: the sweep that moved it holds that lock
            // until it has either committed to the removal or put the session back (Astra r1 HIGH: another sweep
            // deleted a folder the first one was putting back). One with activity newer than the TTL is kept (a
            // removal that had to be put back and could not be). A name that does not parse is kept.
            if let Some(session_name) = removing_session_name(&name_text)
                && dir.child_info(&name).is_ok_and(|info| info.kind == EntryKind::Dir)
            {
                let lock_name = format!("{SWEEP_LOCK_PREFIX}{session_name}");
                if let Some(held) = try_lock_exclusive_pinned(&dir.child_path(&name), dir, &lock_name)
                    && session_last_activity(&dir.child_path(&name))
                        .is_ok_and(|newest| newest.is_none_or(|mtime| is_stale(mtime, ttl_days)))
                    && dir.remove_child_tree(&name).is_ok()
                {
                    stats.dirs_removed += 1;
                    // A lock file this created for a session that no longer exists is removed while held, as the
                    // removal itself does; one whose session exists stays (an attach may hold it)
                    if dir
                        .child_info(std::ffi::OsStr::new(session_name))
                        .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
                    {
                        let _ = dir.remove_child_file(std::ffi::OsStr::new(&lock_name));
                    }
                    drop(held);
                }
            }
            continue;
        }
        if let Some(session_name) = name_text.strip_prefix(SWEEP_LOCK_PREFIX)
            && matches!(level, CleanupLevel::Cwd)
        {
            // A sweep lock whose session is gone (deleted by hand, or a mark that lost the race with a removal). One
            // whose session exists, or whose session cannot be looked up, stays: an attach may hold it, and a new file
            // at the same path would let a sweep and that attach lock different files. It is removed only while held
            // exclusively, so no attach or sweep is using it.
            let session_is_gone = || {
                dir.child_info(std::ffi::OsStr::new(session_name))
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
            };
            if session_is_gone()
                && let Ok(info) = dir.child_info(&name)
                && info.kind == EntryKind::File
                && info.modified.is_some_and(|mtime| is_stale(mtime, ttl_days))
                && let Some(held) = try_lock_exclusive_pinned(&dir.child_path(std::ffi::OsStr::new(session_name)), dir, &name_text)
                && session_is_gone()
            {
                remove_pinned_file(dir, &name, &mut stats);
                drop(held);
            }
            continue;
        }
        if name_text.starts_with('.') {
            continue;
        }

        let info = match dir.child_info(&name) {
            Ok(info) => info,
            Err(_) => {
                stats.errors += 1;
                continue;
            }
        };
        match info.kind {
            // A symlink (or anything else) is never followed
            EntryKind::Other => {}
            EntryKind::Dir => match level {
                CleanupLevel::SessionsRoot => {
                    let child = match dir.open_child(&name) {
                        Ok(child) => child,
                        Err(error) => {
                            // Swapped for a link since the look above: never entered
                            stats.errors += 1;
                            tracing::debug!(
                                target: "fuigo_shell::session::persistence",
                                dir = %dir.child_path(&name).display(),
                                %error,
                                "SESSION_CLEANUP_DIR_SKIPPED"
                            );
                            continue;
                        }
                    };
                    let child_stats = cleanup_pinned_level(&chain, &child, ttl_days, live_session_dir, CleanupLevel::Cwd);
                    let removed_session = child_stats.sessions_removed > 0;
                    stats.absorb(child_stats);
                    // Released first: on Windows the pin itself would refuse the removal
                    drop(child);
                    // A cwd folder we did not empty may belong to a session being created right now
                    if removed_session && dir.remove_child_empty_dir(&name).is_ok() {
                        stats.dirs_removed += 1;
                        tracing::debug!(
                            target: "fuigo_shell::session::persistence",
                            dir = %dir.child_path(&name).display(),
                            "SESSION_CLEANUP_RMDIR"
                        );
                    }
                }
                CleanupLevel::Cwd => {
                    if live_session_dir.is_some_and(|live| dir.child_path(&name) == live) {
                        // Interactive fuigo usually has one session and it is this one, so skipping the prune here
                        // would mean its caches never age out
                        prune_pinned_session_caches(dir, &name, ttl_days, &mut stats);
                    } else {
                        stats.absorb(cleanup_pinned_session(&chain, &name, ttl_days, &SweepHooks::none()));
                    }
                }
            },
            EntryKind::File => {
                if info.modified.is_some_and(|mtime| is_stale(mtime, ttl_days)) {
                    remove_pinned_file(dir, &name, &mut stats);
                }
            }
        }
    }

    stats
}

fn cleanup_session_dir(session_dir: &Path, ttl_days: u32) -> CleanupStats {
    cleanup_session_dir_with(session_dir, ttl_days, &StdRename, || {}, || {}, |_| {})
}

/// How the sweep takes an idle session off its path. Production is [`StdRename`]; the tests add a double that refuses
/// when a handle of this process is open beneath the folder, as NTFS does, so the handle-lifetime part of the Windows
/// rule is tested on Linux (not Windows itself: foreign handles, sharing modes, delete-pending names).
trait SessionDirRename {
    /// Renames `from` to `to`, both in the pinned folder `dir`.
    fn rename(&self, dir: &sweep_pin::PinnedDir, from: &std::ffi::OsStr, to: &std::ffi::OsStr) -> io::Result<()>;
}

struct StdRename;

impl SessionDirRename for StdRename {
    fn rename(&self, dir: &sweep_pin::PinnedDir, from: &std::ffi::OsStr, to: &std::ffi::OsStr) -> io::Result<()> {
        dir.rename_child(from, to)
    }
}

/// A test window that runs at most once.
type SweepHook<'a> = std::cell::RefCell<Option<Box<dyn FnOnce() + 'a>>>;
type AfterRenameHook<'a> = std::cell::RefCell<Option<Box<dyn FnOnce(&Path) + 'a>>>;

/// Test windows inside the removal of one idle session (production runs none).
struct SweepHooks<'a> {
    renamer: &'a dyn SessionDirRename,
    /// Between the first look and the locks.
    before_lock: SweepHook<'a>,
    /// Between the last look and the rename.
    before_rename: SweepHook<'a>,
    /// Once the session has left its path and the locks are released.
    after_rename: AfterRenameHook<'a>,
}

impl SweepHooks<'static> {
    fn none() -> Self {
        SweepHooks {
            renamer: &StdRename,
            before_lock: std::cell::RefCell::new(None),
            before_rename: std::cell::RefCell::new(None),
            after_rename: std::cell::RefCell::new(None),
        }
    }
}

impl SweepHooks<'_> {
    fn before_lock(&self) {
        if let Some(hook) = self.before_lock.borrow_mut().take() {
            hook();
        }
    }

    fn before_rename(&self) {
        if let Some(hook) = self.before_rename.borrow_mut().take() {
            hook();
        }
    }

    fn after_rename(&self, removing: &Path) {
        if let Some(hook) = self.after_rename.borrow_mut().take() {
            hook(removing);
        }
    }
}

/// `before_lock` runs between the first look and the locks, `before_rename` between the last look and the rename,
/// `after_rename` once the session has left its path and the locks are released (tests attach the session in those
/// windows). The session's cwd folder is pinned when this starts.
fn cleanup_session_dir_with<'a>(
    session_dir: &Path,
    ttl_days: u32,
    renamer: &'a dyn SessionDirRename,
    before_lock: impl FnOnce() + 'a,
    before_rename: impl FnOnce() + 'a,
    after_rename: impl FnOnce(&Path) + 'a,
) -> CleanupStats {
    let hooks = SweepHooks {
        renamer,
        before_lock: std::cell::RefCell::new(Some(Box::new(before_lock))),
        before_rename: std::cell::RefCell::new(Some(Box::new(before_rename))),
        after_rename: std::cell::RefCell::new(Some(Box::new(after_rename))),
    };
    let (Some(parent), Some(name)) = (session_dir.parent(), session_dir.file_name()) else {
        return CleanupStats { errors: 1, ..CleanupStats::default() };
    };
    match sweep_pin::PinnedDir::open_root(parent) {
        Ok(cwd) => cleanup_pinned_session(&[&cwd], name, ttl_days, &hooks),
        Err(_) => CleanupStats { errors: 1, ..CleanupStats::default() },
    }
}

/// Judges the session `name` in the last folder of `chain` (its cwd folder; the folders above it come first), all
/// pinned.
fn cleanup_pinned_session(
    chain: &[&sweep_pin::PinnedDir],
    name: &std::ffi::OsStr,
    ttl_days: u32,
    hooks: &SweepHooks<'_>,
) -> CleanupStats {
    let mut stats = CleanupStats::default();
    let Some(cwd) = chain.last().copied() else {
        stats.errors += 1;
        return stats;
    };
    let session_dir = cwd.child_path(name);
    let session_dir = session_dir.as_path();
    let first_look = session_last_activity(session_dir).and_then(|newest_file| match newest_file {
        Some(mtime) => Ok(mtime),
        // A folder without files of its own (a stub) is judged by its own mtime, read before the sweep's lock files
        // are created in it (which changes that mtime)
        None => cwd.child_info(name)?.modified.ok_or_else(|| io::Error::other("no mtime")),
    });
    let last_activity = match first_look {
        Ok(t) => t,
        Err(error) => {
            stats.errors += 1;
            tracing::debug!(
                target: "fuigo_shell::session::persistence",
                dir = %session_dir.display(),
                %error,
                "SESSION_CLEANUP_METADATA_ERROR"
            );
            return stats;
        }
    };
    if !is_stale(last_activity, ttl_days) {
        prune_pinned_session_caches(cwd, name, ttl_days, &mut stats);
        return stats;
    }

    // Another process may be attaching or running this session right now. A live actor holds `turn_owner.lock`
    // shared for its whole life (and takes it before writing anything); an attach holds the session's sweep lock
    // shared from its mark until its actor holds `turn_owner.lock` (`mark_session_live`, P176). So:
    // 1. this sweep takes the sweep lock exclusively and holds it until the session has left its path: from here no
    //    attach can complete a mark, and no attach is between its mark and its actor;
    // 2. it takes `turn_owner.lock` exclusively (no live actor anywhere) and CLOSES it again at once (P178): Windows
    //    refuses to rename a folder with any handle open beneath it, and the sweep lock lives outside the folder for
    //    the same reason. Closing it reopens no window: an actor only starts while its attach holds the sweep lock;
    // 3. it looks again; the session goes only if it still looks unused, and only if every pinned folder above it is
    //    still the one its path names (P176), so what it read through paths is what it acts on;
    // 4. the rename is atomic and relative to the pinned cwd folder: from then on nobody can open anything at the
    //    session's path, so no attach or actor can start on a half-deleted session or put a file into the tree being
    //    deleted. On Windows a handle another process holds inside the folder refuses the rename and the session is
    //    kept;
    // 5. P176: it looks a last time at the moved folder. An attach whose lock failed (a filesystem whose locks fail
    //    for it but not for this sweep) marks without waiting; a mark that landed before the rename shows here, and
    //    the session is put back;
    // 6. the sweep lock file is removed while still held, then released.
    hooks.before_lock();
    let sweep_lock_name = format!("{SWEEP_LOCK_PREFIX}{}", name.to_string_lossy());
    let Some(sweep_lock) = try_lock_exclusive_pinned(session_dir, cwd, &sweep_lock_name) else {
        return stats;
    };
    let session_pin = match cwd.open_child(name) {
        Ok(pin) => pin,
        Err(_) => {
            stats.errors += 1;
            return stats;
        }
    };
    let Some(turn_owner) = try_lock_exclusive_pinned(
        session_dir,
        &session_pin,
        crate::session::turn_owner_lock::TURN_OWNER_LOCK_FILE,
    ) else {
        return stats;
    };
    drop(turn_owner);
    // Released before the rename: on Windows it would refuse it
    drop(session_pin);
    match session_last_activity(session_dir) {
        Ok(None) => {}
        Ok(Some(t)) if is_stale(t, ttl_days) => {}
        Ok(Some(_)) => return stats,
        Err(_) => {
            stats.errors += 1;
            return stats;
        }
    }
    let Some(removing_name) = removing_name(name) else {
        stats.errors += 1;
        return stats;
    };
    let removing = cwd.child_path(&removing_name);
    hooks.before_rename();
    if !chain.iter().all(|pinned| pinned.still_at_path())
        || !cwd.child_info(name).is_ok_and(|info| info.kind == sweep_pin::EntryKind::Dir)
    {
        stats.errors += 1;
        tracing::warn!(
            target: "fuigo_shell::session::persistence",
            dir = %session_dir.display(),
            "SESSION_CLEANUP_RM_SESSION_ERROR: a folder on the session's path changed during the sweep; session kept"
        );
        return stats;
    }
    if let Err(error) = hooks.renamer.rename(cwd, name, &removing_name) {
        stats.errors += 1;
        // Not debug: on Windows this is how a session another program holds open is kept, and a rename that keeps
        // failing would otherwise hide that idle sessions are never removed
        tracing::warn!(
            target: "fuigo_shell::session::persistence",
            dir = %session_dir.display(),
            %error,
            "SESSION_CLEANUP_RM_SESSION_ERROR: session kept"
        );
        return stats;
    }
    let marked_meanwhile = match session_last_activity(&removing) {
        Ok(Some(t)) => !is_stale(t, ttl_days),
        Ok(None) => false,
        Err(_) => true,
    };
    if marked_meanwhile || !cwd.child_info(&removing_name).is_ok_and(|info| info.kind == sweep_pin::EntryKind::Dir) {
        stats.errors += 1;
        put_back(cwd, &removing_name, name, session_dir);
        return stats;
    }
    // A waiting attach holds the unlinked file and then finds no session; Windows deletes it once the last handle
    // closes. A failure only leaves a 0-byte dot file that the orphan rule clears after the TTL.
    let _ = cwd.remove_child_file(std::ffi::OsStr::new(&sweep_lock_name));
    drop(sweep_lock);
    hooks.after_rename(&removing);
    // Nothing in the tree is followed: a link inside the folder is removed, never its target. A leftover (Windows
    // keeps a file a waiting attach still has open) is finished by the next sweep.
    match cwd.remove_child_tree(&removing_name) {
        Ok(()) => {
            stats.sessions_removed += 1;
            tracing::info!(
                target: "fuigo_shell::session::persistence",
                dir = %session_dir.display(),
                "SESSION_CLEANUP_RM_SESSION"
            );
        }
        Err(error) => {
            // The session is already gone from its path; only its leftover bytes remain, under a dot name
            stats.sessions_removed += 1;
            stats.errors += 1;
            tracing::warn!(
                target: "fuigo_shell::session::persistence",
                dir = %removing.display(),
                %error,
                "SESSION_CLEANUP_RM_SESSION_ERROR: leftover removed by the next sweep"
            );
        }
    }
    stats
}

/// Puts a session the sweep moved off its path back, because something marked it in between. If its path has been
/// taken meanwhile, or the filesystem has no atomic no-replace rename, the folder is kept under a name no sweep
/// removes and that is logged (nothing restores it by itself; the warning names both paths).
fn put_back(cwd: &sweep_pin::PinnedDir, removing_name: &std::ffi::OsStr, name: &std::ffi::OsStr, session_dir: &Path) {
    // Never over anything at the path, not even an empty folder a creator is about to fill (Astra r3)
    match cwd.rename_child_noreplace_strict(removing_name, name) {
        Ok(()) => tracing::info!(
            target: "fuigo_shell::session::persistence",
            dir = %session_dir.display(),
            "SESSION_CLEANUP_PUT_BACK: the session was marked while it was being removed; kept"
        ),
        Err(error) => {
            let kept = std::ffi::OsString::from(format!(
                "{KEPT_PREFIX}{}-{}",
                name.to_string_lossy(),
                std::process::id()
            ));
            let kept_ok = cwd.rename_child_noreplace(removing_name, &kept).is_ok();
            tracing::warn!(
                target: "fuigo_shell::session::persistence",
                dir = %session_dir.display(),
                kept = %cwd.child_path(if kept_ok { &kept } else { removing_name }).display(),
                %error,
                "SESSION_CLEANUP_PUT_BACK_ERROR: the session was marked while it was being removed, and it could not be \
                 put back safely (its path is taken, or this filesystem has no atomic no-replace rename); its files \
                 are kept under this name"
            );
        }
    }
}

/// The session a removal folder ([`removing_name`]) was named after.
fn removing_session_name(name: &str) -> Option<&str> {
    let rest = name.strip_prefix(REMOVING_PREFIX)?;
    let mut parts = rest.rsplitn(3, '-');
    let (nanos, pid, session) = (parts.next()?, parts.next()?, parts.next()?);
    let numeric = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    (numeric(nanos) && numeric(pid) && !session.is_empty()).then_some(session)
}

/// `.fuigo-sweep-removing-<session>-<pid>-<nanos>`: next to the session, so the rename stays in one folder, and
/// unique per attempt.
fn removing_name(name: &std::ffi::OsStr) -> Option<std::ffi::OsString> {
    let name = name.to_str()?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    Some(format!("{REMOVING_PREFIX}{name}-{}-{nanos}", std::process::id()).into())
}

/// Deletes regular files older than `ttl_days` from the [`SWEPT_BLOB_DIRS`] of the session `name` in the pinned `cwd`.
/// Never rmdir: a writer may sit between its `create_dir_all` and its write. The session folder and each cache folder
/// are opened relative to their pinned parent and are refused when they are a link or a reparse point (P176: on
/// Windows the check and the open are one step, see [`sweep_pin`]); any entry in a cache folder that is not a regular
/// file is left alone, and what is stat'ed and removed is resolved against the pinned cache folder.
fn prune_pinned_session_caches(
    cwd: &sweep_pin::PinnedDir,
    name: &std::ffi::OsStr,
    ttl_days: u32,
    stats: &mut CleanupStats,
) {
    let session = match cwd.open_child(name) {
        Ok(session) => session,
        Err(error) => {
            tracing::debug!(
                target: "fuigo_shell::session::persistence",
                dir = %cwd.child_path(name).display(),
                %error,
                "SESSION_CLEANUP_BLOB_DIR_SKIPPED"
            );
            return;
        }
    };
    for dir_name in SWEPT_BLOB_DIRS {
        prune_pinned_blob_dir(&session, dir_name, ttl_days, stats);
    }
}

fn prune_pinned_blob_dir(session: &sweep_pin::PinnedDir, dir_name: &str, ttl_days: u32, stats: &mut CleanupStats) {
    let dir = match session.open_child(std::ffi::OsStr::new(dir_name)) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(error) => {
            // A symlink, a reparse point, or a file where the cache folder should be; never followed
            tracing::debug!(
                target: "fuigo_shell::session::persistence",
                dir = %session.child_path(std::ffi::OsStr::new(dir_name)).display(),
                %error,
                "SESSION_CLEANUP_BLOB_DIR_SKIPPED"
            );
            return;
        }
    };
    let Ok(names) = dir.entry_names() else {
        stats.errors += 1;
        return;
    };
    for name in names {
        let Ok(info) = dir.child_info(&name) else {
            stats.errors += 1;
            continue;
        };
        if info.kind == sweep_pin::EntryKind::File && info.modified.is_some_and(|mtime| is_stale(mtime, ttl_days)) {
            remove_pinned_file(&dir, &name, stats);
        }
    }
}

/// Opens (creating, owner-only) the lock file `name` in `session_dir` without ever following a link at that path:
/// `O_NOFOLLOW` on Unix, `FILE_FLAG_OPEN_REPARSE_POINT` on Windows (a link is then opened itself and refused as not a
/// regular file). `None` when it cannot be opened that way (a missing folder, a planted link).
fn open_lock_nofollow(session_dir: &Path, name: &str) -> Option<std::fs::File> {
    let path = session_dir.join(name);
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    // Owner-only like every other session file (P145), including the Windows ACL, which is applied by path and so
    // only once the opened entry is known to be a regular file (not a link)
    use crate::session::storage::owner_only;
    match owner_only::owner_only(&mut options).open(&path) {
        Ok(file) if file.metadata().is_ok_and(|metadata| metadata.is_file()) => {
            owner_only::tighten(&file, &path).ok()?;
            Some(file)
        }
        Ok(_) => None,
        Err(error) => {
            tracing::debug!(
                target: "fuigo_shell::session::persistence",
                file = %path.display(),
                %error,
                "SESSION_LOCK_UNAVAILABLE"
            );
            None
        }
    }
}

/// The lock file `name` in the pinned `dir`, held exclusively for the sweep of `session_dir`. `None` when it is held or
/// cannot be taken at all (a planted link, a filesystem without advisory locks): the session is then kept.
fn try_lock_exclusive_pinned(session_dir: &Path, dir: &sweep_pin::PinnedDir, name: &str) -> Option<crate::session::storage::jsonl::HeldLock> {
    let file = dir.open_lock(name)?;
    // UFCS: std's inherent `File::try_lock` (Rust 1.89+) returns a different error type.
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => Some(crate::session::storage::jsonl::HeldLock::new(file)),
        Err(error) => {
            tracing::debug!(
                target: "fuigo_shell::session::persistence",
                dir = %session_dir.display(),
                lock = name,
                %error,
                "SESSION_CLEANUP_SESSION_HELD: session kept"
            );
            None
        }
    }
}

/// How many entries the activity scan of one session may look at, and how deep below the session folder it goes
/// (`subagents/<id>/subagents/<id>/prompts/` is 5). Past either bound the scan fails and the session is kept: it is
/// never judged idle on a partial look.
const ACTIVITY_SCAN_MAX_ENTRIES: usize = 20_000;
const ACTIVITY_SCAN_MAX_DEPTH: usize = 8;

/// Newest mtime among the session's regular files, in the folder and in its subfolders (`None` if it has none).
/// `updates.jsonl` grows with every persisted update and [`mark_session_live`] bumps `summary.json` on every attach;
/// loading alone rewrites neither. P178: files a live session writes only into a subfolder (`compaction_checkpoints/`,
/// `prompts/`, `subagents/`, `terminal/`, ...) count too, so no such writer can see its session judged idle. Symlinks
/// are never followed, and folder mtimes are not activity (the cache prune changes them). The top-level
/// `turn_owner.lock` is not activity: the sweep itself creates it to lock the session.
fn session_last_activity(session_dir: &Path) -> io::Result<Option<std::time::SystemTime>> {
    session_last_activity_within(session_dir, ACTIVITY_SCAN_MAX_ENTRIES)
}

/// [`session_last_activity`] with an explicit bound on the entries it may look at (tests use a small one).
fn session_last_activity_within(
    session_dir: &Path,
    max_entries: usize,
) -> io::Result<Option<std::time::SystemTime>> {
    session_activity_scan(session_dir, max_entries, &[crate::session::turn_owner_lock::TURN_OWNER_LOCK_FILE])
}

/// The activity scan, skipping the named top-level files.
fn session_activity_scan(
    session_dir: &Path,
    max_entries: usize,
    ignored_top_level: &[&str],
) -> io::Result<Option<std::time::SystemTime>> {
    let mut newest: Option<std::time::SystemTime> = None;
    let mut budget = max_entries;
    let mut pending = vec![(session_dir.to_path_buf(), 0_usize)];
    while let Some((dir, depth)) = pending.pop() {
        // A subfolder removed while we look (a writer's cleanup, a cache prune) holds no activity any more
        let vanished = |error: &io::Error| depth > 0 && error.kind() == io::ErrorKind::NotFound;
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if vanished(&error) => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            budget = budget.checked_sub(1).ok_or_else(|| {
                io::Error::other(format!("more than {max_entries} entries; session kept without judging it"))
            })?;
            if depth == 0 && ignored_top_level.iter().any(|name| entry.file_name() == *name) {
                continue;
            }
            let metadata = match std::fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if vanished(&error) => continue,
                Err(error) => return Err(error),
            };
            let file_type = metadata.file_type();
            if file_type.is_file() {
                if let Ok(mtime) = metadata.modified() {
                    newest = Some(newest.map_or(mtime, |n| n.max(mtime)));
                }
            } else if file_type.is_dir() {
                if depth >= ACTIVITY_SCAN_MAX_DEPTH {
                    return Err(io::Error::other(format!(
                        "folders nested deeper than {ACTIVITY_SCAN_MAX_DEPTH}; session kept without judging it"
                    )));
                }
                pending.push((entry.path(), depth + 1));
            }
        }
    }
    Ok(newest)
}

fn remove_pinned_file(dir: &sweep_pin::PinnedDir, name: &std::ffi::OsStr, stats: &mut CleanupStats) {
    match dir.remove_child_file(name) {
        Ok(()) => {
            stats.files_deleted += 1;
            tracing::debug!(
                target: "fuigo_shell::session::persistence",
                file = %dir.child_path(name).display(),
                "SESSION_CLEANUP_DELETE"
            );
        }
        Err(error) => {
            stats.errors += 1;
            tracing::debug!(
                target: "fuigo_shell::session::persistence",
                file = %dir.child_path(name).display(),
                %error,
                "SESSION_CLEANUP_DELETE_ERROR"
            );
        }
    }
}

fn is_stale(mtime: std::time::SystemTime, ttl_days: u32) -> bool {
    let ttl = std::time::Duration::from_secs(u64::from(ttl_days) * 86400);
    mtime.elapsed().is_ok_and(|age| age > ttl)
}

#[cfg(test)]
#[path = "persistence_cleanup_stale_sessions_tests.rs"]
mod cleanup_stale_sessions_tests;

#[cfg(test)]
#[path = "persistence_agent_name_persistence_tests.rs"]
mod agent_name_persistence_tests;

#[cfg(test)]
#[path = "persistence_collect_session_files_tests.rs"]
mod collect_session_files_tests;

#[cfg(test)]
#[path = "persistence_session_exists_tests.rs"]
mod session_exists_tests;

#[cfg(test)]
#[path = "persistence_find_summary_by_session_id_tests.rs"]
mod find_summary_by_session_id_tests;

#[cfg(test)]
#[path = "persistence_resumed_sandbox_profile_tests.rs"]
mod resumed_sandbox_profile_tests;

#[cfg(test)]
#[path = "persistence_session_exists_for_cwd_tests.rs"]
mod session_exists_for_cwd_tests;

#[cfg(test)]
#[path = "persistence_find_local_child_tests.rs"]
mod find_local_child_tests;

#[cfg(test)]
#[path = "persistence_resolve_local_session_tests.rs"]
mod resolve_local_session_tests;

#[cfg(test)]
#[path = "persistence_repo_wide_resolution_tests.rs"]
mod repo_wide_resolution_tests;

#[cfg(test)]
#[path = "persistence_actor_lifetime_tests.rs"]
mod actor_lifetime_tests;

/// Test-only seam: holds the acknowledgement of a session's next durable append until the test releases it (the write
/// itself is not held), and counts finished deferred-recovery finishers. `cfg(test)`, so none of it exists in a
/// shipped build.
#[cfg(test)]
pub(crate) mod test_seam {
    use std::collections::HashMap;
    use std::sync::Mutex;

    type Ack = tokio::sync::oneshot::Sender<Result<(), crate::session::storage::AppendUpdateError>>;
    type WrittenSignal = (
        Option<tokio::sync::oneshot::Sender<()>>,
        Option<tokio::sync::oneshot::Receiver<()>>,
    );
    type Outcome = Result<(), crate::session::storage::AppendUpdateError>;

    static HELD: Mutex<Option<HashMap<String, tokio::sync::oneshot::Receiver<()>>>> = Mutex::new(None);
    /// Per session: signalled once the held append has been written, and awaited just before the load's replay.
    static WRITTEN: Mutex<Option<HashMap<String, WrittenSignal>>> = Mutex::new(None);
    static FINISHED: Mutex<Option<HashMap<String, usize>>> = Mutex::new(None);
    /// Per session: how many more chat history replacements fail (P111).
    static FAILING_REPLACEMENTS: Mutex<Option<HashMap<String, usize>>> = Mutex::new(None);

    type BeforeTurnOwnerLock = Box<dyn FnOnce(&std::path::Path) + Send>;
    /// Per session: runs once, in the load, right before the actor takes `turn_owner.lock` (P176).
    static BEFORE_TURN_OWNER_LOCK: Mutex<Option<HashMap<String, BeforeTurnOwnerLock>>> = Mutex::new(None);

    /// Runs `hook` (with the session folder) the next time `session_id`'s actor is about to take `turn_owner.lock`.
    pub(crate) fn before_turn_owner_lock(session_id: &str, hook: impl FnOnce(&std::path::Path) + Send + 'static) {
        BEFORE_TURN_OWNER_LOCK
            .lock()
            .expect("before turn owner lock")
            .get_or_insert_with(HashMap::new)
            .insert(session_id.to_owned(), Box::new(hook));
    }

    pub(crate) fn run_before_turn_owner_lock(session_id: &str, session_dir: &std::path::Path) {
        let hook = BEFORE_TURN_OWNER_LOCK
            .lock()
            .expect("before turn owner lock")
            .as_mut()
            .and_then(|hooks| hooks.remove(session_id));
        if let Some(hook) = hook {
            hook(session_dir);
        }
    }

    /// One real sweep of one session folder (as another process's sweep would judge it); how many sessions it removed.
    pub(crate) fn sweep_session_dir(session_dir: &std::path::Path, ttl_days: u32) -> u32 {
        super::cleanup_session_dir(session_dir, ttl_days).sessions_removed
    }

    /// The next `count` chat history replacements of `session_id` fail before touching the disk (`0` disarms).
    pub(crate) fn fail_history_replacements(session_id: &str, count: usize) {
        FAILING_REPLACEMENTS
            .lock()
            .expect("failing replacements")
            .get_or_insert_with(HashMap::new)
            .insert(session_id.to_owned(), count);
    }

    /// Whether this chat history replacement of `session_id` is to fail (consumes one armed failure).
    pub(super) fn take_history_replacement_failure(session_id: &str) -> bool {
        let mut armed = FAILING_REPLACEMENTS.lock().expect("failing replacements");
        match armed.as_mut().and_then(|armed| armed.get_mut(session_id)) {
            Some(remaining) if *remaining > 0 => {
                *remaining -= 1;
                true
            }
            _ => false,
        }
    }

    /// A real persistence actor for `info` over `storage`, for tests outside this module that need production disk
    /// behaviour behind a `PersistenceMsg` channel.
    pub(crate) fn spawn_actor(
        info: super::Info,
        storage: std::sync::Arc<dyn super::StorageAdapter>,
    ) -> tokio::sync::mpsc::UnboundedSender<super::PersistenceMsg> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let (disk_full_tx, _disk_full_rx) = tokio::sync::watch::channel(false);
        let sampling_client =
            super::OaiCompatClient::new(fuigo_sampler::SamplerConfig::default()).expect("sampling client");
        let summary = crate::session::summary::SummaryGenerator::new(crate::session::summary::SummaryConfig {
            sampling_client,
            model: String::new(),
            policy: Default::default(),
            session_id: info.id.to_string(),
            persistence_tx: tx.downgrade(),
        });
        tokio::spawn(
            super::SessionPersistence {
                info,
                storage,
                pending_notification: None,
                rx,
                remote_sync: None,
                created_fresh: false,
                relay_sync: None,
                summary,
                registry_title_sync: None,
                gateway: None,
                search_index: crate::session::storage::search::SharedSearchIndex::never_indexed(),
                disk_full_tx,
                disk_full_notified: false,
                retry_status_mirror: Default::default(),
                dirty_files: Default::default(),
                pending_write_error: None,
                last_usage_live: None,
                last_usage_turn: None,
                last_incoming_turn: None,
                turn_start_guard: None,
            }
            .run(),
        );
        tx
    }

    /// Releases a held acknowledgement; dropping it releases too.
    pub(crate) struct AckRelease(tokio::sync::oneshot::Sender<()>);

    impl AckRelease {
        pub(crate) fn release(self) {
            let _ = self.0.send(());
        }
    }

    /// The next durable append for `session_id` is written at once, but acknowledged only once the returned handle
    /// is released.
    pub(crate) fn hold_next_durable_ack(session_id: &str) -> AckRelease {
        let (release, held) = tokio::sync::oneshot::channel();
        HELD.lock()
            .expect("held acks")
            .get_or_insert_with(HashMap::new)
            .insert(session_id.to_owned(), held);
        let (written_tx, written_rx) = tokio::sync::oneshot::channel();
        WRITTEN
            .lock()
            .expect("written")
            .get_or_insert_with(HashMap::new)
            .insert(session_id.to_owned(), (Some(written_tx), Some(written_rx)));
        AckRelease(release)
    }

    /// `Some` hands the append straight back (nothing held); `None` means the ack was taken over and is sent once
    /// released, from a detached task.
    pub(super) fn maybe_delay_ack(
        session_id: &str,
        result: Outcome,
        respond_to: Ack,
    ) -> Option<(Outcome, Ack)> {
        let held = HELD
            .lock()
            .expect("held acks")
            .as_mut()
            .and_then(|held| held.remove(session_id));
        let Some(held) = held else {
            return Some((result, respond_to));
        };
        if let Some((Some(written), _)) = WRITTEN
            .lock()
            .expect("written")
            .as_mut()
            .and_then(|written| written.get_mut(session_id))
            .map(|entry| (entry.0.take(), ()))
        {
            let _ = written.send(());
        }
        tokio::spawn(async move {
            let _ = held.await;
            let _ = respond_to.send(result);
        });
        None
    }

    /// Called by a load just before its replay: waits (bounded) until the held append has been written, so the replay
    /// is ordered after the marker's write. A no-op when nothing is armed for the session.
    pub(crate) async fn await_held_write(session_id: &str) {
        let written = WRITTEN
            .lock()
            .expect("written")
            .as_mut()
            .and_then(|written| written.get_mut(session_id))
            .and_then(|entry| entry.1.take());
        if let Some(written) = written {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(60), written).await;
        }
    }

    /// Drop guard a deferred-recovery finisher holds, so a test can wait for it to be completely done.
    pub(crate) struct FinisherDone(pub(crate) String);

    impl Drop for FinisherDone {
        fn drop(&mut self) {
            // A finisher that panicked did not complete; the test then times out instead of passing.
            if std::thread::panicking() {
                return;
            }
            *FINISHED
                .lock()
                .expect("finished")
                .get_or_insert_with(HashMap::new)
                .entry(std::mem::take(&mut self.0))
                .or_default() += 1;
        }
    }

    pub(crate) fn finishers_done(session_id: &str) -> usize {
        FINISHED
            .lock()
            .expect("finished")
            .as_ref()
            .and_then(|done| done.get(session_id).copied())
            .unwrap_or(0)
    }
}
