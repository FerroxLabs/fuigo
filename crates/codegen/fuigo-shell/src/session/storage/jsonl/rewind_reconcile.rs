//! A rewind that Fuigo was killed in the middle of, found again when its session is loaded (P164, K19).
//!
//! A forced rewind changes three things in order, while it holds the rewind points rewrite lock
//! (`rewind_points.jsonl.rewrite.lock`, P146):
//!
//! 1. the rewind's journal (`rewind_points.jsonl.pre-rewind.journal`) and then a durable copy of `rewind_points.jsonl`
//!    (`rewind_points.jsonl.pre-rewind`) are written, and `rewind_points.jsonl` is rewritten (the swap);
//! 2. the rewound conversation is saved as `chat_history.jsonl` (the rewind's commit point), and then a
//!    `RewindMarker` whose `created_at` the journal names is appended to `updates.jsonl`;
//! 3. the copy, then the journal, are removed.
//!
//! A kill anywhere in there leaves the copy behind. Before P164 nothing looked at it again until the next rewind,
//! which was refused with instructions. Now the load of the session decides, holding the exclusive turn-owner lock (no
//! live actor anywhere, so no rewind is running in this or another process), the rewind's own rewrite lock and the
//! append locks of `rewind_points.jsonl` and `updates.jsonl`:
//!
//! - **the rewind went through**: its own `RewindMarker` is in `updates.jsonl` after where the transcript ended when
//!   it started, or `chat_history.jsonl` is exactly the conversation it saved; and `rewind_points.jsonl` holds what it
//!   wrote (then maybe rows appended since). Only its cleanup was cut short: the copy goes, and its `RewindMarker` is
//!   appended when the transcript lacks it and records nothing after it;
//! - **the rewind did not happen**: no such marker, and `chat_history.jsonl` still starts with what it held when the
//!   rewind started. `rewind_points.jsonl` gets back what the copy holds, followed by any row appended after the swap
//!   (as the rewind's own put-back does);
//! - **a rewind that leaves the conversation alone** (FilesOnly) went through exactly when its swap landed;
//! - **anything else** (no journal and a copy that differs from the file, a conversation that matches neither side, a
//!   file changed by someone else since, a transcript that cannot be checked or repaired, a lock that cannot be
//!   taken, evidence that is not a regular file): both files are kept, the session loads what
//!   `rewind_points.jsonl` holds, and the user is told which file holds what. Rewinds stay refused until one of them
//!   is removed, as before.
//!
//! A journal without a copy is what a kill between the two removals (or before the copy was written) leaves: it is
//! removed. Every file is read without following a link (`open_beneath_nofollow`), so a planted link or FIFO is
//! refused instead of followed or waited on. Nothing here waits for a lock for long: a held rewrite lock belongs to a
//! running rewind, whose files are left to it; the next load looks again. The P178 session sweep never takes the
//! rewrite lock and only tries the turn-owner lock, so neither side can wait for the other.

use std::io::{self, Read, Seek};
use std::path::{Path, PathBuf};

use super::JsonlStorageAdapter;
use crate::session::info::Info;
use crate::session::storage::{ContentFingerprint, RewindConversation, RewindPointsRewrite};

const JOURNAL_VERSION: u32 = 1;

/// How long the load waits for an append lock (an append in another process finishes quickly).
const APPEND_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// What a rewind is about to do, written before its durable copy (see the module doc).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct RewindJournal {
    version: u32,
    rewrite: RewindPointsRewrite,
    /// What `rewind_points.jsonl` held (what the copy holds).
    points_before: ContentFingerprint,
    /// What the rewrite writes to `rewind_points.jsonl`.
    points_written: ContentFingerprint,
    /// `chat_history.jsonl` when the rewind started (`None`: it did not exist). Only for a rewind of the conversation.
    #[serde(default)]
    chat_before: Option<ContentFingerprint>,
    /// The conversation the rewind saves; `None`: the rewind leaves the conversation as it is (FilesOnly).
    #[serde(default)]
    chat_after: Option<ContentFingerprint>,
    /// The `created_at` of the rewind's `RewindMarker`.
    #[serde(default)]
    marker_created_at: Option<String>,
    /// Length of `updates.jsonl` when the rewind started: its `RewindMarker` can only be after that.
    #[serde(default)]
    updates_len: Option<u64>,
}

impl RewindJournal {
    pub(super) fn new(
        rewrite: RewindPointsRewrite,
        previous: &[u8],
        written: &[u8],
        conversation: Option<RewindConversation>,
        chat_path: &Path,
        updates_path: &Path,
    ) -> io::Result<Self> {
        // Read like the load reads its evidence: never through a link, never from a FIFO (Astra r2 #3).
        let chat_before = match &conversation {
            Some(_) => {
                let dir = chat_path.parent().unwrap_or(Path::new("."));
                read_evidence(dir, chat_path).map_err(io::Error::other)?.as_deref().map(ContentFingerprint::of)
            }
            None => None,
        };
        let updates_len = match std::fs::symlink_metadata(updates_path) {
            Ok(metadata) => Some(metadata.len()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Some(0),
            Err(_) => None,
        };
        let (chat_after, marker_created_at) = match conversation {
            Some(RewindConversation { after, marker_created_at }) => (Some(after), Some(marker_created_at)),
            None => (None, None),
        };
        Ok(Self {
            version: JOURNAL_VERSION,
            rewrite,
            points_before: ContentFingerprint::of(previous),
            points_written: ContentFingerprint::of(written),
            chat_before,
            chat_after,
            marker_created_at,
            updates_len,
        })
    }

    pub(super) fn to_bytes(&self) -> io::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(io::Error::other)
    }

    fn parse(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice::<Self>(bytes).ok().filter(|journal| journal.version == JOURNAL_VERSION)
    }

    fn target(&self) -> usize {
        match self.rewrite {
            RewindPointsRewrite::TruncateFrom(index) | RewindPointsRewrite::MergeFrom(index) => index,
        }
    }
}

/// Remove a rewind's durable copy, then its journal (a missing one is already removed). Links are removed as links.
pub(crate) fn remove_copy_then_journal(rewind_points: &Path) -> io::Result<()> {
    remove_if_present(&crate::session::storage::rewind_points_pre_rewind_copy(rewind_points))?;
    remove_if_present(&crate::session::storage::rewind_points_journal(rewind_points))
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// `path` (a file of the session folder `dir`), opened without following a link and only when it is a regular file.
/// `Ok(None)`: it does not exist. `Err`: why it cannot be used, for the user.
fn open_evidence(dir: &Path, path: &Path) -> Result<Option<std::fs::File>, String> {
    use crate::session::storage::BeneathRefusal;
    let name = path.file_name().map(Path::new).unwrap_or(path);
    match crate::session::storage::open_beneath_nofollow(dir, name) {
        Ok(file) => Ok(Some(file)),
        Err(BeneathRefusal::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(BeneathRefusal::Io(error)) => Err(format!("{} could not be read ({error})", path.display())),
        Err(BeneathRefusal::Refused(why)) => Err(format!("{} cannot be used: {why}", path.display())),
    }
}

fn read_evidence(dir: &Path, path: &Path) -> Result<Option<Vec<u8>>, String> {
    let Some(mut file) = open_evidence(dir, path)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| format!("{} could not be read ({error})", path.display()))?;
    Ok(Some(bytes))
}

/// What `rewind_points.jsonl` shows of the rewind's swap.
#[derive(Debug, PartialEq, Eq)]
enum Points {
    /// It holds what the rewind wrote, and then `appended` (rows appended after the swap).
    Rewritten { appended: Vec<u8> },
    /// It holds what the copy holds (and maybe rows appended after it): the swap did not land.
    Unchanged,
    /// Something else.
    Unknown,
}

/// What the session's files show of the rewind's commit.
#[derive(Debug, PartialEq, Eq)]
enum Conversation {
    /// A FilesOnly rewind: the conversation is not part of it.
    NotPartOfIt,
    Saved,
    NotSaved,
    Unknown,
}

/// What `updates.jsonl` holds after the point where it ended when the rewind started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct Transcript {
    /// The rewind's own `RewindMarker` (its target and the `created_at` the journal names).
    pub(super) marker: bool,
    /// Something that moves the conversation was recorded after that point: a prompt, a compaction, another
    /// rewind. The rewind's marker would then not mark where it happened.
    pub(super) later_history: bool,
}

/// What the load does with the leftover.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Decision {
    /// The rewind did not happen: `rewind_points.jsonl` gets these bytes back (`None`: it already holds them).
    Undo { restore: Option<Vec<u8>> },
    /// The rewind went through; only its cleanup was cut short. `record_marker`: its `RewindMarker` is appended.
    Finish { record_marker: bool },
    /// Both files stay; the reason is told to the user.
    Keep { reason: String },
}

fn points_state(journal: &RewindJournal, current: Option<&[u8]>, copy: &[u8]) -> Points {
    if !journal.points_before.matches(copy) {
        return Points::Unknown;
    }
    let Some(current) = current else {
        return Points::Unknown;
    };
    // Rows can be appended after either content. A truncation writes the first rows of the copy, so a file that still
    // starts with the whole copy also starts with what was written: the longer of the two decides. A rewrite that
    // changed nothing (what was written is the copy) counts as a swap that landed.
    let starts_as_copy = current.starts_with(copy);
    let starts_as_written = journal.points_written.is_prefix_of(current);
    if starts_as_written && (!starts_as_copy || journal.points_written.len >= copy.len() as u64) {
        let start = usize::try_from(journal.points_written.len).unwrap_or(usize::MAX);
        return Points::Rewritten { appended: current.get(start..).unwrap_or_default().to_vec() };
    }
    if starts_as_copy { Points::Unchanged } else { Points::Unknown }
}

/// `transcript`: `None` when `updates.jsonl` could not be checked.
fn conversation_state(journal: &RewindJournal, chat: Option<&[u8]>, transcript: Option<Transcript>) -> Conversation {
    let Some(after) = &journal.chat_after else {
        return Conversation::NotPartOfIt;
    };
    // The rewind's own marker is written only once its conversation is saved.
    if transcript.is_some_and(|transcript| transcript.marker) {
        return Conversation::Saved;
    }
    // Exactly the conversation it saved. Only a prefix of it is no evidence: another rewrite of the history (a
    // compaction) can start the same way.
    if chat.is_some_and(|chat| after.matches(chat)) {
        return Conversation::Saved;
    }
    let starts_as_before = match &journal.chat_before {
        Some(before) => chat.is_some_and(|chat| before.is_prefix_of(chat)),
        None => chat.is_none_or(<[u8]>::is_empty),
    };
    if starts_as_before { Conversation::NotSaved } else { Conversation::Unknown }
}

/// The copy put back, followed by what was appended after the swap (on its own line).
fn restored(copy: &[u8], appended: &[u8]) -> Vec<u8> {
    let mut bytes = copy.to_vec();
    if !appended.is_empty() && !bytes.is_empty() && !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    bytes.extend_from_slice(appended);
    bytes
}

/// Decide what a leftover copy means. `journal`: `None` when there is none (a Fuigo older than 1.0.22 left the copy)
/// or it cannot be read. `chat` and `transcript` are read only for a journal of a conversation rewind; `transcript` is
/// `None` when `updates.jsonl` could not be checked.
pub(super) fn decide(
    journal: Option<&RewindJournal>,
    current: Option<&[u8]>,
    copy: &[u8],
    chat: Option<&[u8]>,
    transcript: Option<Transcript>,
) -> Decision {
    let Some(journal) = journal else {
        // No record of what the rewind did. A copy that holds what the file holds loses nothing when it goes.
        return if current == Some(copy) {
            Decision::Undo { restore: None }
        } else {
            Decision::Keep {
                reason: "it was left by an older Fuigo, which records nothing about the rewind, and it differs from \
                         rewind_points.jsonl"
                    .into(),
            }
        };
    };
    let points = points_state(journal, current, copy);
    match (conversation_state(journal, chat, transcript), points) {
        (Conversation::NotPartOfIt, Points::Rewritten { .. }) => Decision::Finish { record_marker: false },
        (Conversation::Saved, Points::Rewritten { .. }) => match transcript {
            Some(Transcript { marker: true, .. }) => Decision::Finish { record_marker: false },
            Some(Transcript { marker: false, later_history: false }) => Decision::Finish { record_marker: true },
            Some(Transcript { marker: false, later_history: true }) => Decision::Keep {
                reason: "the conversation was rewound, but updates.jsonl records later turns or compactions and not \
                         the rewind"
                    .into(),
            },
            None => Decision::Keep { reason: "updates.jsonl could not be checked for the rewind".into() },
        },
        (Conversation::NotPartOfIt | Conversation::NotSaved, Points::Unchanged) => Decision::Undo { restore: None },
        // Putting the copy back is the one destructive undo: it needs the transcript checked, without the rewind's
        // marker (that would be Saved) and without later activity (Astra r2 #1). Leaving a file that already holds
        // the copy as it is loses nothing.
        (Conversation::NotSaved, Points::Rewritten { appended }) => match transcript {
            Some(Transcript { later_history: false, .. }) => Decision::Undo { restore: Some(restored(copy, &appended)) },
            Some(_) => Decision::Keep {
                reason: "the conversation was not rewound, but updates.jsonl records later turns or compactions".into(),
            },
            None => Decision::Keep { reason: "updates.jsonl could not be checked for the rewind".into() },
        },
        (Conversation::Unknown, _) => Decision::Keep {
            reason: "chat_history.jsonl matches neither the conversation from before that rewind nor the one it was \
                     saving"
                .into(),
        },
        (Conversation::Saved, Points::Unchanged) => Decision::Keep {
            reason: "the conversation was rewound but rewind_points.jsonl was not".into(),
        },
        (_, Points::Unknown) => Decision::Keep {
            reason: "rewind_points.jsonl (or the copy) was changed since that rewind wrote it".into(),
        },
    }
}

/// What `updates.jsonl` (opened without following a link) holds after byte `from`. `None`: it is shorter than that.
fn read_transcript(
    mut file: std::fs::File,
    from: u64,
    target: usize,
    created_at: &str,
) -> io::Result<Option<Transcript>> {
    if file.metadata()?.len() < from {
        return Ok(None);
    }
    file.seek(io::SeekFrom::Start(from))?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail)?;
    let mut transcript = Transcript::default();
    for line in tail.split(|byte| *byte == b'\n').filter_map(|line| std::str::from_utf8(line).ok()) {
        if let crate::session::storage::RewindStep::UserChunk { .. } = crate::session::storage::rewind_step_for_line(line) {
            transcript.later_history = true;
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value["method"] != crate::session::storage::FUIGO_SESSION_UPDATE_METHOD {
            continue;
        }
        let update = &value["params"]["update"];
        match update["sessionUpdate"].as_str() {
            Some("rewind_marker") => {
                let ours = update["target_prompt_index"].as_u64() == Some(target as u64)
                    && update["created_at"].as_str() == Some(created_at);
                if ours {
                    transcript.marker = true;
                } else {
                    transcript.later_history = true;
                }
            }
            Some("compaction_checkpoint") => transcript.later_history = true,
            _ => {}
        }
    }
    Ok(Some(transcript))
}

/// Append the rewind's `RewindMarker`; the caller holds the append lock of `updates.jsonl`.
fn append_rewind_marker(updates: &Path, session: &Info, target: usize, created_at: &str) -> io::Result<()> {
    let update = crate::session::storage::SessionUpdate::Fuigo(Box::new(
        crate::extensions::notification::SessionNotification {
            session_id: session.id.clone(),
            update: crate::extensions::notification::SessionUpdate::RewindMarker {
                target_prompt_index: target,
                created_at: created_at.to_owned(),
            },
            meta: None,
        },
    ));
    let envelope = crate::session::storage::SessionUpdateEnvelope::from_update(&update).map_err(io::Error::other)?;
    let mut line = serde_json::to_vec(&envelope).map_err(io::Error::other)?;
    line.push(b'\n');
    JsonlStorageAdapter::append_jsonl_line_locked(
        updates,
        line,
        super::AppendDurability::Durable,
        crate::session::storage::sync_file_durable,
        || crate::session::storage::sync_parent_dir_durable(updates),
    )
    .map_err(super::AppendLineError::into_io_error)
}

/// The files of one session the reconcile looks at.
struct Files {
    dir: PathBuf,
    points: PathBuf,
    copy: PathBuf,
    journal: PathBuf,
    chat: PathBuf,
    updates: PathBuf,
}

/// Why [`bounded_lock`] did not take a lock.
enum LockFailure {
    /// Someone holds it past the wait.
    Held(String),
    /// It cannot be used at all.
    Unusable(String),
}

impl LockFailure {
    fn reason(self) -> String {
        match self {
            Self::Held(reason) | Self::Unusable(reason) => reason,
        }
    }
}

/// A lock taken with a bounded wait, or why it was not. Unlike the rewrite itself, a lock file that cannot be used
/// is not taken as "no lock needed": the reconcile then changes nothing.
fn bounded_lock(
    path: &Path,
    lock_path: PathBuf,
    shared: bool,
    wait: std::time::Duration,
) -> Result<super::HeldLock, LockFailure> {
    match JsonlStorageAdapter::lock_bounded(path, lock_path.clone(), shared, std::time::Instant::now() + wait) {
        Ok(Some(lock)) => Ok(lock),
        Ok(None) => Err(LockFailure::Unusable(format!("{} cannot be opened or locked", lock_path.display()))),
        Err(error) => Err(LockFailure::Held(format!("{} is held by another Fuigo process ({error})", lock_path.display()))),
    }
}

impl JsonlStorageAdapter {
    /// Reconcile a rewind of `info` that Fuigo was killed in the middle of (see the module doc). Returns the note
    /// shown to the user, `None` when there was nothing to do or the session is in use (a live actor or a running
    /// rewind, in this or another process: its files are not a leftover).
    pub(crate) async fn reconcile_interrupted_rewind(&self, info: &Info) -> Option<String> {
        let points = self.rewind_points_file(info);
        let files = Files {
            dir: self.session_dir(info),
            copy: crate::session::storage::rewind_points_pre_rewind_copy(&points),
            journal: crate::session::storage::rewind_points_journal(&points),
            chat: self.chat_file(info),
            updates: self.updates_file(info),
            points,
        };
        if files.copy.symlink_metadata().is_err() && files.journal.symlink_metadata().is_err() {
            return None;
        }
        let info = info.clone();
        tokio::task::spawn_blocking(move || {
            use crate::session::turn_owner_lock::{RecoveryLock, try_recovery_lock};
            let _exclusive = match try_recovery_lock(&files.dir) {
                RecoveryLock::Acquired(guard) => guard,
                RecoveryLock::HeldElsewhere => {
                    tracing::debug!(session_id = %info.id, "interrupted rewind check skipped: a live actor holds the session");
                    return None;
                }
                RecoveryLock::Unknown(error) => {
                    tracing::warn!(session_id = %info.id, %error, "interrupted rewind check skipped: session liveness unknown");
                    return None;
                }
            };
            // The lock a rewind holds from before it changes anything until it is done. Never waited for: held, it
            // belongs to a rewind that is running, and its files are left to it. One that cannot be taken at all
            // leaves the files as they are, and the user is told.
            let rewrite_lock = files.points.with_extension("jsonl.rewrite.lock");
            let _rewrite = match bounded_lock(&files.points, rewrite_lock, false, std::time::Duration::ZERO) {
                Ok(lock) => lock,
                Err(LockFailure::Held(reason)) => {
                    tracing::debug!(session_id = %info.id, %reason, "interrupted rewind check skipped: a rewind is running");
                    return None;
                }
                Err(LockFailure::Unusable(reason)) => return Some(kept_notice(&files, None, &reason)),
            };
            let append_lock = files.points.with_extension("jsonl.lock");
            let _append = match bounded_lock(&files.points, append_lock, true, APPEND_LOCK_WAIT) {
                Ok(lock) => lock,
                Err(failure) => return Some(kept_notice(&files, None, &failure.reason())),
            };
            // Every lock is released when its file is dropped, on every path.
            reconcile_locked(&files, &info)
        })
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "interrupted rewind check stopped");
            None
        })
    }
}

fn reconcile_locked(files: &Files, info: &Info) -> Option<String> {
    if let Err(error) = files.copy.symlink_metadata() {
        if error.kind() != io::ErrorKind::NotFound {
            return Some(kept_notice(files, None, &format!("{} could not be checked ({error})", files.copy.display())));
        }
        // A journal alone: the rewind stopped before its copy was written, or its cleanup between the two removals.
        // Either way there is nothing to reconcile.
        if let Err(error) = remove_if_present(&files.journal) {
            tracing::warn!(session_id = %info.id, %error, "a rewind's journal without its copy could not be removed");
        }
        return None;
    }
    let inputs = (|| {
        let copy = read_evidence(&files.dir, &files.copy)?
            .ok_or_else(|| format!("{} disappeared while it was checked", files.copy.display()))?;
        let journal = read_evidence(&files.dir, &files.journal)?.as_deref().and_then(RewindJournal::parse);
        let current = read_evidence(&files.dir, &files.points)?;
        let chat = match journal.as_ref().and_then(|journal| journal.chat_after.as_ref()) {
            Some(_) => read_evidence(&files.dir, &files.chat)?,
            None => None,
        };
        Ok::<_, String>((copy, journal, current, chat))
    })();
    let (copy, journal, current, chat) = match inputs {
        Ok(inputs) => inputs,
        Err(reason) => return Some(kept_notice(files, None, &reason)),
    };
    let target = journal.as_ref().map(RewindJournal::target);
    // The transcript is checked (and repaired) under its own append lock, held until the end.
    let (transcript, _updates_lock) = match journal.as_ref() {
        Some(RewindJournal { chat_after: Some(_), marker_created_at: Some(created_at), updates_len: Some(from), .. }) => {
            match bounded_lock(&files.updates, files.updates.with_extension("jsonl.lock"), false, APPEND_LOCK_WAIT) {
                Ok(lock) => {
                    let transcript = match open_evidence(&files.dir, &files.updates) {
                        Ok(Some(file)) => read_transcript(file, *from, target.unwrap_or_default(), created_at)
                            .unwrap_or_else(|error| {
                                tracing::warn!(session_id = %info.id, %error, "updates.jsonl could not be read");
                                None
                            }),
                        Ok(None) => (*from == 0).then(Transcript::default),
                        Err(reason) => {
                            tracing::warn!(session_id = %info.id, %reason, "updates.jsonl cannot be checked");
                            None
                        }
                    };
                    (transcript, Some(lock))
                }
                Err(failure) => {
                    let reason = failure.reason();
                    tracing::warn!(session_id = %info.id, %reason, "updates.jsonl cannot be checked");
                    (None, None)
                }
            }
        }
        _ => (None, None),
    };
    let decision = decide(journal.as_ref(), current.as_deref(), &copy, chat.as_deref(), transcript);
    // The decision's bytes are saved file contents: only what was decided is logged.
    let decided = match &decision {
        Decision::Undo { .. } => "undo",
        Decision::Finish { .. } => "finish",
        Decision::Keep { .. } => "keep both",
    };
    tracing::warn!(session_id = %info.id, ?target, decided, "found the leftover of a rewind that did not finish");
    Some(match decision {
        Decision::Undo { restore } => {
            if let Some(bytes) = restore
                && let Err(error) = crate::session::storage::write_bytes_atomic(&files.points, &bytes)
            {
                return Some(kept_notice(
                    files,
                    target,
                    &format!("rewind_points.jsonl could not be put back from the copy ({error})"),
                ));
            }
            format!("{}{}", undone_notice(journal.as_ref()), cleanup(files, info))
        }
        Decision::Finish { record_marker } => {
            let journal = journal.as_ref()?;
            let mut marker_note = "";
            if record_marker && let Some(created_at) = &journal.marker_created_at {
                if let Err(error) = append_rewind_marker(&files.updates, info, journal.target(), created_at) {
                    // The transcript would still show the rewound turns: keep everything and say so.
                    return Some(kept_notice(
                        files,
                        target,
                        &format!("the rewind could not be recorded in updates.jsonl ({error})"),
                    ));
                }
                marker_note = " The rewind was also recorded in the transcript (updates.jsonl), where it was missing.";
            }
            format!(
                "An earlier rewind of this session to prompt #{} went through, but Fuigo stopped before it had \
                 cleaned up.{marker_note}{}",
                journal.target(),
                cleanup(files, info)
            )
        }
        Decision::Keep { reason } => kept_notice(files, target, &reason),
    })
}

/// Remove the copy then the journal, and say how that went, naming only what is left (Astra r2 #4).
fn cleanup(files: &Files, info: &Info) -> String {
    let copy = files.copy.display();
    if let Err(error) = remove_if_present(&files.copy) {
        tracing::warn!(session_id = %info.id, %error, "the leftover copy of a rewind could not be removed");
        return format!(
            " The copy of the saved file history from before it ({copy}) is no longer needed, but it could not be \
             removed ({error}); rewinds of this session are refused until you delete it."
        );
    }
    if let Err(error) = remove_if_present(&files.journal) {
        // Harmless: a journal without its copy refuses nothing and the next load removes it.
        tracing::warn!(session_id = %info.id, %error, path = %files.journal.display(), "a rewind's journal could not be removed");
    }
    format!(" The copy of the saved file history from before it ({copy}) is no longer needed and was removed.")
}

fn undone_notice(journal: Option<&RewindJournal>) -> String {
    let Some(journal) = journal else {
        return "An earlier rewind of this session stopped before it changed the saved file history \
                (rewind_points.jsonl): the copy it left held the same history, so nothing was lost. If the transcript \
                still shows turns you rewound, run that rewind again."
            .to_owned();
    };
    let target = journal.target();
    let files_note = match journal.rewrite {
        RewindPointsRewrite::TruncateFrom(_) => {
            " Files that rewind had already restored may hold their earlier contents; running the same rewind again \
             finishes it."
        }
        RewindPointsRewrite::MergeFrom(_) => "",
    };
    let what = if journal.chat_after.is_some() {
        "before it rewound the conversation, so it did not happen: the conversation is as it was"
    } else {
        "before it was recorded, so it did not happen"
    };
    format!(
        "An earlier rewind of this session to prompt #{target} stopped {what}, and this session's saved file history \
         (rewind_points.jsonl) is back to what it was before that rewind.{files_note} Run the rewind again if you \
         still want it."
    )
}

fn kept_notice(files: &Files, target: Option<usize>, reason: &str) -> String {
    let which = target.map(|target| format!(" to prompt #{target}")).unwrap_or_default();
    let (points, copy) = (files.points.display(), files.copy.display());
    format!(
        "An earlier rewind of this session{which} did not finish, and Fuigo cannot tell whether it went through: \
         {reason}. Both versions are kept. {points} holds this session's saved file history as it is now, and the \
         session uses it; {copy} holds it as it was before that rewind. The conversation is loaded as it was saved. \
         Rewinds of this session are refused until one of the two is removed: if the transcript still shows the \
         turns that rewind should have removed, move {copy} over rewind_points.jsonl; otherwise delete {copy}."
    )
}

#[cfg(test)]
#[path = "rewind_reconcile_tests.rs"]
mod tests;
