//! Load-time repair of a history damaged by a torn `chat_history.jsonl` line (P96).
//!
//! The lenient reader skips a line it cannot parse. When that line was the assistant message carrying a tool call, the
//! `ToolResult` after it is left without its call, and strict providers reject every request of the session (HTTP 400).
//! [`JsonlStorageAdapter::repair_after_corrupt_load`] runs the same repair as `fuigo/session/repair` when the session is
//! loaded, under these rules:
//!
//! - It acts only when the reader skipped a line AND the repair changes the history. "Skipped a line" is either of:
//!   the reader skipped at least one line on this load, or an earlier load did and left its raw copy of the file,
//!   `chat_history.jsonl.corrupt`, next to it. The second case is a session that broke before this repair existed:
//!   that earlier load's snapshot already rewrote the file without the unreadable line, so every line parses now and
//!   the orphaned result is still there. Anything else leaves the file and the loaded history exactly as they were.
//! - The `.corrupt` copy is only looked at (does a regular file of that name exist); it is never changed or removed.
//! - It acts only while it holds the session's exclusive turn-owner lock, so no actor in this or any other process
//!   has the file open for writing, and it decides on a fresh read made under that lock. The lock guard moves with the
//!   backup and the rewrite onto their blocking thread, so a load that is dropped meanwhile still holds the lock until
//!   that I/O is done.
//! - Before the file is rewritten, the file as found is copied to `chat_history.jsonl.pre-repair`. The copy is staged
//!   under a unique name, flushed, and published with a hard link, which never replaces an existing file: the first
//!   copy wins (the same intent as the `.pre-strip` copy made before an image strip).
//! - When that copy cannot be made, the file is not rewritten. The repaired history is still handed to the session,
//!   and the file is marked so that no later rewrite of it in this process goes ahead without the copy either
//!   ([`rewrite_gate`]). Appends are not rewrites and continue. A rewind or a compaction, whose rewrite is not
//!   acknowledged, is refused up front while the copy is owed ([`history_rewrite_refusal`]), before anything is sent to
//!   the model (no memory-save request, no prefire pass, no summary).
//! - While the copy is owed no refused rewrite is lost silently (P123): an automatic compaction shows its failure note once
//!   and then stays quiet until the backup can be made ([`refused_auto_compaction`]); a mode or model switch and the other
//!   changes whose rewrite is refused say once that the file was not rewritten and why ([`note_for_refused_rewrite`]); an
//!   image strip says the saved history still holds the image ([`image_strip_not_saved_note`]). The notes end with the debt
//!   ([`forget_owed`]), so a later debt shows its own.
//! - The note of the repair itself is saved in the transcript and not replayed by a later load.
//! - A fork of a damaged session and a subagent resume get the history repaired in memory (the source file is not touched,
//!   or, for a subagent, its raw file stays as the reader's `.corrupt` copy).

use super::JsonlStorageAdapter;
use crate::session::info::Info;
use crate::session::storage::{PersistedDataLight, StorageAdapter};
use fuigo_chat_state::compaction_utils::HistoryRepairReport;
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Chat files whose load-time repair lives only in memory because the `.pre-repair` copy could not be made.
static BACKUP_OWED: LazyLock<parking_lot::Mutex<HashSet<PathBuf>>> =
    LazyLock::new(|| parking_lot::Mutex::new(HashSet::new()));

/// The user-facing notes about a refused rewrite that are shown once per session while the backup is owed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum NoteKind {
    /// An automatic compaction was refused.
    AutoCompaction,
    /// A change to the session (a mode or model switch, ...) could not be written to the history file.
    FileNotRewritten,
}

/// Which notes were already shown for a chat file's current debt. Entries end with the debt ([`forget_owed`]).
static NOTED: LazyLock<parking_lot::Mutex<HashSet<(PathBuf, NoteKind)>>> =
    LazyLock::new(|| parking_lot::Mutex::new(HashSet::new()));

/// `true` the first time it is asked for `kind` on `chat_path` since the backup became owed, `false` afterwards: the
/// caller shows its note only on `true`, so a session shows it once and then stays quiet until the backup can be made.
pub(crate) fn first_note(chat_path: &Path, kind: NoteKind) -> bool {
    NOTED.lock().insert((chat_path.to_path_buf(), kind))
}

/// The backup exists now: the debt ends, and so do the notes that were shown for it (a later debt shows its own).
fn forget_owed(chat_path: &Path) {
    BACKUP_OWED.lock().remove(chat_path);
    NOTED.lock().retain(|(path, _)| path != chat_path);
}

/// Test hook: mark `chat_path` as owing its `.pre-repair` backup, as a failed load-time repair does.
#[cfg(test)]
pub(crate) fn owe_backup_for_test(chat_path: &Path) {
    BACKUP_OWED.lock().insert(chat_path.to_path_buf());
}

fn backup_path(chat_path: &Path) -> PathBuf {
    chat_path.with_extension("jsonl.pre-repair")
}

/// The raw copy the lenient reader keeps the first time it cannot use a file as it is (`read_chat_history_counting_sync`).
fn quarantine_path(chat_path: &Path) -> PathBuf {
    chat_path.with_extension("jsonl.corrupt")
}

/// The reader's `.corrupt` copy next to `chat_path`, when an earlier load left one. Only a regular file counts.
/// This only looks: the copy is never changed or removed here.
pub(super) fn quarantine_of_earlier_load(chat_path: &Path) -> Option<PathBuf> {
    let quarantine = quarantine_path(chat_path);
    match std::fs::symlink_metadata(&quarantine) {
        Ok(meta) if meta.is_file() => Some(quarantine),
        _ => None,
    }
}

/// How the `.pre-repair` copy came to exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RepairBackup {
    /// This call copied the file as found.
    Created(PathBuf),
    /// A copy from an earlier repair is there and was kept (first copy wins); this call copied nothing.
    AlreadyPresent(PathBuf),
}

/// Whether a backup is already at `backup`. Only a regular file counts; anything else there is an error, because it
/// is not a copy of the history and nothing can be published under that name.
fn existing_backup(backup: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(backup) {
        Ok(meta) if meta.is_file() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a regular file", backup.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Publish the staged copy as `backup` without ever replacing a file that is already there.
/// A hard link fails when the name exists, so of two racing publishers exactly one wins and the other keeps the
/// winner's copy. (A rename would replace it.)
fn publish_backup(staging: &Path, backup: &Path) -> io::Result<RepairBackup> {
    match std::fs::hard_link(staging, backup) {
        Ok(()) => Ok(RepairBackup::Created(backup.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if existing_backup(backup)? {
                Ok(RepairBackup::AlreadyPresent(backup.to_path_buf()))
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

/// Copy `chat_path` to `chat_history.jsonl.pre-repair` unless that copy already exists.
/// The copy is flushed to stable storage before it is published, and its directory entry after. The directory entry
/// is flushed also when the copy was already there: a retry after a failed directory flush finds the published file,
/// and only a flush that succeeds makes it count.
fn backup_before_repair(chat_path: &Path) -> io::Result<RepairBackup> {
    let backup = backup_path(chat_path);
    let published = if existing_backup(&backup)? {
        RepairBackup::AlreadyPresent(backup.clone())
    } else {
        let staging = chat_path.with_extension(format!(
            "jsonl.pre-repair.{}.tmp",
            uuid::Uuid::now_v7()
        ));
        let published = (|| -> io::Result<RepairBackup> {
            crate::session::storage::owner_only::copy(chat_path, &staging)?;
            let staged = std::fs::OpenOptions::new().write(true).open(&staging)?;
            crate::session::storage::sync_file_durable(&staged)?;
            drop(staged);
            publish_backup(&staging, &backup)
        })();
        let _ = std::fs::remove_file(&staging);
        published?
    };
    if let Some(dir) = backup.parent() {
        sync_backup_dir(dir)?;
    }
    Ok(published)
}

/// Flush the directory entry of the backup to stable storage.
fn sync_backup_dir(dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    if seams::dir_sync_fails(dir) {
        return Err(io::Error::other("directory sync failed (test seam)"));
    }
    crate::session::storage::sync_dir_durable(dir)
}

/// Hooks for the unit tests: hold an atomic write while it runs, make the backup's directory sync fail.
#[cfg(test)]
pub(crate) mod seams {
    use std::collections::{HashMap, HashSet};
    use std::path::{Path, PathBuf};
    use std::sync::LazyLock;

    type Held = (
        tokio::sync::oneshot::Sender<()>,
        std::sync::mpsc::Receiver<()>,
    );
    static HELD_WRITES: LazyLock<parking_lot::Mutex<HashMap<PathBuf, Held>>> =
        LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));
    static FAILING_DIR_SYNCS: LazyLock<parking_lot::Mutex<HashSet<PathBuf>>> =
        LazyLock::new(|| parking_lot::Mutex::new(HashSet::new()));

    /// Hold the next atomic write of `path` (`write_bytes_atomic`) before it writes anything. The first receiver
    /// fires once the write is held; the write goes on when the sender sends or is dropped.
    pub(crate) fn hold_next_write(
        path: &Path,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        HELD_WRITES
            .lock()
            .insert(path.to_path_buf(), (started_tx, release_rx));
        (started_rx, release_tx)
    }

    /// Called by `write_bytes_atomic`: blocks while a test holds this write.
    pub(crate) fn wait_if_held(path: &Path) {
        let held = HELD_WRITES.lock().remove(path);
        if let Some((started, release)) = held {
            let _ = started.send(());
            let _ = release.recv();
        }
    }

    pub(crate) fn fail_dir_sync(dir: &Path, fail: bool) {
        if fail {
            FAILING_DIR_SYNCS.lock().insert(dir.to_path_buf());
        } else {
            FAILING_DIR_SYNCS.lock().remove(dir);
        }
    }

    pub(super) fn dir_sync_fails(dir: &Path) -> bool {
        FAILING_DIR_SYNCS.lock().contains(dir)
    }
}

/// Gate for every rewrite of a session's `chat_history.jsonl`.
///
/// A file whose load-time repair could not be backed up must not be rewritten until the copy exists, because the
/// rewrite would put the repaired history on disk and the bytes as found would be gone. The copy is tried again here;
/// while it keeps failing, the rewrite is refused with the copy's error. Files that owe no copy pass straight through.
pub(crate) fn rewrite_gate(chat_path: &Path) -> io::Result<()> {
    if !BACKUP_OWED.lock().contains(chat_path) {
        return Ok(());
    }
    backup_before_repair(chat_path)?;
    forget_owed(chat_path);
    Ok(())
}

/// Why `action` (a rewind or a compaction of the conversation) cannot run now, or `None` when it can.
///
/// Such an operation changes the history in memory and records itself in the transcript, and its rewrite of
/// `chat_history.jsonl` is sent to the persistence actor without an acknowledgement. While a load-time repair of this
/// session still owes its backup, [`rewrite_gate`] refuses that rewrite, so the file would keep the messages the
/// operation dropped and the next load would hand them back to the model. The caller therefore asks first and refuses
/// before it changes anything. Asking retries the backup; once it is made the gate is open and nothing is refused.
pub(crate) fn history_rewrite_refusal(session_info: &Info, action: &str) -> Option<String> {
    refusal_for_chat_file(&chat_path_of(session_info), action)
}

fn refusal_for_chat_file(chat_path: &Path, action: &str) -> Option<String> {
    let error = rewrite_gate(chat_path).err()?;
    Some(refusal_text(chat_path, &error, action))
}

fn refusal_text(chat_path: &Path, error: &io::Error, action: &str) -> String {
    format!(
        "Cannot {action} now: when this session was opened its saved history was repaired, but the history file \
         could not be backed up first ({error}), so the file is not rewritten until a backup can be made at {}. \
         Nothing was changed. Free disk space or clear that path, then try again.",
        backup_path(chat_path).display()
    )
}

/// Whether `session_info`'s history file still owes its backup. Only looks: unlike [`rewrite_gate`] it never retries the
/// copy, so a check made every turn (the prefire decision) cannot repeat a large copy on a full disk.
pub(crate) fn backup_is_owed(session_info: &Info) -> bool {
    BACKUP_OWED.lock().contains(&chat_path_of(session_info))
}

/// Where the session's `chat_history.jsonl` is.
fn chat_path_of(session_info: &Info) -> PathBuf {
    crate::session::persistence::session_dir(session_info).join(crate::session::storage::CHAT_HISTORY_FILE)
}

/// The sentence every note shares: why the history file is not being rewritten (retries the backup).
fn not_rewritten_cause(chat_path: &Path, error: &io::Error) -> String {
    format!(
        "when this session was opened its saved history was repaired, but the history file could not be backed up first \
         ({error}), so it is not rewritten until a backup can be made at {}",
        backup_path(chat_path).display()
    )
}

/// The note for a change to the session (`what`: a mode or model switch, ...) whose rewrite of the history file was
/// refused because the backup is owed, or `None` when nothing is owed, the backup could be made just now, or this session
/// already showed this note. The change itself was made in memory; only the file is behind, so the note says so instead of
/// the refusal being logged and nothing else (P123, K14; Astra P96 r3).
pub(crate) fn note_for_refused_rewrite(session_info: &Info, what: &str) -> Option<String> {
    note_for_refused_rewrite_at(&chat_path_of(session_info), what, true)
}

/// [`note_for_refused_rewrite`] for a change that is NOT applied again when the session is resumed (pruning goal directives
/// after the goal has ended: nothing prunes them on the next load), so the note must not promise that (P135).
pub(crate) fn note_for_refused_unrepeated_rewrite(session_info: &Info, what: &str) -> Option<String> {
    note_for_refused_rewrite_at(&chat_path_of(session_info), what, false)
}

fn note_for_refused_rewrite_at(chat_path: &Path, what: &str, reapplied_on_resume: bool) -> Option<String> {
    let error = rewrite_gate(chat_path).err()?;
    if !first_note(chat_path, NoteKind::FileNotRewritten) {
        return None;
    }
    let consequence = if reapplied_on_resume {
        "The change applies to this run only and is applied again when the session is resumed"
    } else {
        "The change applies to this run only; the saved history keeps what was to be removed, and a resumed session loads it again"
    };
    Some(format!(
        "Session history file not rewritten: {what}. {consequence}; {}. Free disk space or clear that path.",
        not_rewritten_cause(chat_path, &error)
    ))
}

/// An automatic compaction refused because the backup is owed.
pub(crate) struct RefusedAutoCompaction {
    /// What the compaction returns to its caller, every time.
    pub refusal: String,
    /// The failure note for the user: `Some` the first time since the backup became owed, `None` afterwards (the session
    /// stays quiet until the backup can be made). Starts lowercase, as the renderer puts its own headline in front.
    pub note: Option<String>,
}

/// `Err` when an automatic compaction must not start because the backup is owed (asking retries the backup); `Ok(())`
/// when nothing is owed or the backup could be made just now.
pub(crate) fn refused_auto_compaction(session_info: &Info) -> Result<(), RefusedAutoCompaction> {
    refused_auto_compaction_at(&chat_path_of(session_info))
}

fn refused_auto_compaction_at(chat_path: &Path) -> Result<(), RefusedAutoCompaction> {
    let Err(error) = rewrite_gate(chat_path) else {
        return Ok(());
    };
    let refusal = refusal_text(chat_path, &error, "compact the conversation");
    let note = first_note(chat_path, NoteKind::AutoCompaction).then(|| {
        format!(
            "the conversation was not compacted: {}. Free disk space or clear that path; compaction goes ahead by \
             itself once a backup can be made. This note is shown once.",
            not_rewritten_cause(chat_path, &error)
        )
    });
    Err(RefusedAutoCompaction { refusal, note })
}

/// For an image strip the history file could not take: the sentence that says the saved history still holds the image and
/// why, or `None` when the file is not behind.
pub(crate) fn image_strip_not_saved_note(session_info: &Info) -> Option<String> {
    image_strip_not_saved_note_at(&chat_path_of(session_info))
}

fn image_strip_not_saved_note_at(chat_path: &Path) -> Option<String> {
    let error = rewrite_gate(chat_path).err()?;
    Some(format!(
        "The saved history still holds the image: {}.",
        not_rewritten_cause(chat_path, &error)
    ))
}

/// What happened to the file on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RepairDisk {
    /// The copy exists and the repaired history was written.
    Rewritten(RepairBackup),
    /// The copy could not be made (the error text is kept); the file was left as found.
    BackupFailed(String),
    /// The copy exists, but writing the repaired history failed (the error text is kept).
    RewriteFailed(RepairBackup, String),
}

/// A repair made while loading a session.
#[derive(Debug, Clone)]
pub(crate) struct LoadRepair {
    /// Lines of `chat_history.jsonl` the reader could not parse on this load.
    pub skipped_lines: usize,
    /// The `.corrupt` copy an earlier load left, when one is there.
    pub earlier_quarantine: Option<PathBuf>,
    pub report: HistoryRepairReport,
    pub disk: RepairDisk,
}

fn count(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

impl LoadRepair {
    /// The note shown to the user: what was changed (counts), why, and where the original is.
    /// It is sent as `SessionUpdate::HistoryRepaired` and starts with "Session history repaired:".
    pub(crate) fn notice(&self) -> String {
        let mut changes = Vec::new();
        let stripped = self.report.stripped_tool_result_ids.len();
        if stripped > 0 {
            changes.push(format!(
                "removed {}",
                count(
                    stripped,
                    "tool result that had lost its tool call",
                    "tool results that had lost their tool calls"
                )
            ));
        }
        if self.report.duplicates_removed > 0 {
            changes.push(format!(
                "removed {}",
                count(
                    self.report.duplicates_removed,
                    "duplicate tool result",
                    "duplicate tool results"
                )
            ));
        }
        if self.report.synthetic_results_inserted > 0 {
            changes.push(format!(
                "added {} for tool calls left without one",
                count(
                    self.report.synthetic_results_inserted,
                    "placeholder result",
                    "placeholder results"
                )
            ));
        }
        let cause = match (&self.earlier_quarantine, self.skipped_lines) {
            (Some(quarantine), 0) => format!(
                "an earlier load found damage in the saved history and removed it from the file (the raw file from \
                 then is kept at {}); left as it was, the provider would have rejected every request",
                quarantine.display()
            ),
            _ => format!(
                "{} in the saved history (a write cut short, for example by a crash); left as it was, the provider \
                 would have rejected every request",
                count(self.skipped_lines, "unreadable line", "unreadable lines")
            ),
        };
        let found = format!(
            "Session history repaired: {}. Cause: {cause}.",
            changes.join("; ")
        );
        let disk = match &self.disk {
            RepairDisk::Rewritten(RepairBackup::Created(path)) => format!(
                "Backup of the file as it was before the repair: {}",
                path.display()
            ),
            RepairDisk::Rewritten(RepairBackup::AlreadyPresent(path)) => format!(
                "A backup from an earlier repair is already at {} and was kept; the file was not copied again \
                 before this repair.",
                path.display()
            ),
            RepairDisk::BackupFailed(error) => format!(
                "The history file could not be backed up ({error}), so it was not rewritten when the session was \
                 opened. The repair is in memory for now; the file is rewritten only once a backup can be made."
            ),
            RepairDisk::RewriteFailed(backup, error) => {
                let (RepairBackup::Created(path) | RepairBackup::AlreadyPresent(path)) = backup;
                format!(
                    "A backup is at {}, but saving the repaired history failed ({error}). \
                     The repair applies to this run only.",
                    path.display()
                )
            }
        };
        format!("{found} {disk}")
    }
}

impl JsonlStorageAdapter {
    /// Repair `data.chat_history` after a load that skipped unreadable lines. See the module doc for the rules.
    ///
    /// `None` means nothing was done: no line was skipped (on this load, or on an earlier one that left its `.corrupt`
    /// copy), the history needs no repair, or the session is
    /// held by a live actor (in this or another process). A live actor owns the file, and a line read while it is
    /// being appended looks torn, so the repair needs the exclusive turn-owner lock, the same proof of "nobody is
    /// running this session" that interrupted-turn recovery uses. Where that cannot be established, nothing is done.
    pub(crate) async fn repair_after_corrupt_load(
        &self,
        info: &Info,
        data: &mut PersistedDataLight,
    ) -> Option<LoadRepair> {
        let chat_path = self.chat_file(info);
        if data.skipped_chat_lines == 0 && quarantine_of_earlier_load(&chat_path).is_none() {
            return None;
        }
        use crate::session::turn_owner_lock::{RecoveryLock, try_recovery_lock};
        let session_dir = self.session_dir(info);
        let exclusive = match try_recovery_lock(&session_dir) {
            RecoveryLock::Acquired(guard) => guard,
            RecoveryLock::HeldElsewhere => {
                tracing::debug!(session_id = %info.id, "load-time history repair skipped: a live actor holds the session");
                return None;
            }
            RecoveryLock::Unknown(error) => {
                tracing::warn!(session_id = %info.id, %error,
                    "load-time history repair skipped: session liveness unknown");
                return None;
            }
        };
        // Decide on what the file holds now, under the lock: the first read was made without it.
        match self.load_session_without_updates(info).await {
            Ok(fresh) => *data = fresh,
            Err(error) => {
                tracing::warn!(session_id = %info.id, %error,
                    "load-time history repair skipped: the history could not be read again");
                return None;
            }
        }
        // The reader may have made the `.corrupt` copy during the read above; look again under the lock.
        let earlier_quarantine = quarantine_of_earlier_load(&chat_path);
        if data.skipped_chat_lines == 0 && earlier_quarantine.is_none() {
            return None;
        }
        let mut repaired = data.chat_history.clone();
        let report = fuigo_chat_state::compaction_utils::repair_history(&mut repaired);
        if !report.changed() {
            return None;
        }
        // The backup and the rewrite run on a blocking thread that owns the lock guard. Dropping this load (leader
        // shutdown drops its task) does not stop that thread, so the guard has to live there: the lock stays held
        // until the file I/O is done, and no other writer can take the session and append before a late rename would
        // replace what it wrote.
        let (adapter, rewrite_info, rewrite_path, history) =
            (self.clone(), info.clone(), chat_path.clone(), repaired.clone());
        let disk = tokio::task::spawn_blocking(move || {
            let _exclusive = exclusive;
            adapter.write_load_repair_sync(&rewrite_info, &rewrite_path, &history)
        })
        .await
        .unwrap_or_else(|error| {
            // The writer panicked: whether the backup exists is unknown, so hold back every rewrite until it does.
            BACKUP_OWED.lock().insert(chat_path.clone());
            RepairDisk::BackupFailed(format!("the repair writer stopped: {error}"))
        });
        data.chat_history = repaired;
        let repair = LoadRepair {
            skipped_lines: data.skipped_chat_lines,
            earlier_quarantine,
            report,
            disk,
        };
        tracing::warn!(
            session_id = %info.id,
            path = %chat_path.display(),
            skipped_lines = repair.skipped_lines,
            earlier_quarantine = ?repair.earlier_quarantine,
            duplicates_removed = repair.report.duplicates_removed,
            stripped_tool_result_ids = ?repair.report.stripped_tool_result_ids,
            synthetic_results_inserted = repair.report.synthetic_results_inserted,
            disk = ?repair.disk,
            "session history repaired at load after unreadable chat history lines (now or on an earlier load)"
        );
        Some(repair)
    }

    /// Back up the file as found, then write the repaired history. Blocking; the caller holds the exclusive lock.
    fn write_load_repair_sync(
        &self,
        info: &Info,
        chat_path: &Path,
        repaired: &[crate::sampling::ConversationItem],
    ) -> RepairDisk {
        match backup_before_repair(chat_path) {
            Ok(backup) => {
                forget_owed(chat_path);
                match self.replace_chat_history_after_backup_sync(info, repaired) {
                    Ok(()) => RepairDisk::Rewritten(backup),
                    Err(error) => RepairDisk::RewriteFailed(backup, error.to_string()),
                }
            }
            Err(error) => {
                BACKUP_OWED.lock().insert(chat_path.to_path_buf());
                RepairDisk::BackupFailed(error.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sampling::ConversationItem;
    use crate::session::persistence::default_model_id;
    use agent_client_protocol as acp;
    use fuigo_sampling_types::ToolCall;
    use tempfile::TempDir;

    fn info(id: &str) -> Info {
        Info {
            id: acp::SessionId::new(id),
            cwd: "/work".to_string(),
        }
    }

    /// A session whose history is a system prompt, a prompt, an assistant tool call, its result and an answer.
    async fn seed(root: &Path, id: &str) -> (JsonlStorageAdapter, Info) {
        let adapter = JsonlStorageAdapter::with_root(root.to_path_buf());
        let info = info(id);
        adapter
            .init_session(&info, default_model_id())
            .await
            .expect("init session");
        let items = [
            ConversationItem::system("sys"),
            ConversationItem::user("prompt"),
            ConversationItem::assistant_tool_calls(vec![ToolCall {
                id: "call_LOST".into(),
                name: "read_file".to_string(),
                arguments: "{}".into(),
            }]),
            ConversationItem::tool_result("call_LOST", "the result"),
            ConversationItem::assistant("the answer"),
        ];
        for item in &items {
            adapter
                .append_chat_message(&info, item)
                .await
                .expect("append chat message");
        }
        (adapter, info)
    }

    /// Cut line `at` (0-based) of the chat file in half; returns the damaged file's bytes.
    fn tear(adapter: &JsonlStorageAdapter, info: &Info, at: usize) -> Vec<u8> {
        let path = adapter.chat_file(info);
        let bytes = std::fs::read(&path).expect("read chat file");
        let mut out = Vec::new();
        for (i, line) in bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .enumerate()
        {
            out.extend_from_slice(if i == at {
                &line[..line.len() / 2]
            } else {
                line
            });
            out.push(b'\n');
        }
        std::fs::write(&path, &out).expect("write torn chat file");
        out
    }

    /// Remove line `at` (0-based) of the chat file, as the snapshot written after an earlier lenient load did with a
    /// torn line. Every remaining line parses. Returns the file's bytes.
    fn scrub(adapter: &JsonlStorageAdapter, info: &Info, at: usize) -> Vec<u8> {
        let path = adapter.chat_file(info);
        let kept: Vec<u8> = std::fs::read(&path)
            .expect("read chat file")
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .enumerate()
            .filter(|(i, _)| *i != at)
            .flat_map(|(_, l)| l.iter().copied().chain(std::iter::once(b'\n')))
            .collect();
        std::fs::write(&path, &kept).expect("write scrubbed chat file");
        kept
    }

    /// Where the lenient reader keeps the raw file the first time it skips a line (`chat_history.jsonl.corrupt`).
    fn corrupt_copy(adapter: &JsonlStorageAdapter, info: &Info) -> PathBuf {
        quarantine_path(&adapter.chat_file(info))
    }

    /// The state an earlier release left behind: the first load after the tear kept the raw file as `.corrupt`, and
    /// its snapshot rewrote the chat file without the torn line. Returns (the `.corrupt` bytes, the chat file bytes).
    fn broken_before_this_release(adapter: &JsonlStorageAdapter, info: &Info) -> (Vec<u8>, Vec<u8>) {
        let torn = tear(adapter, info, 2);
        std::fs::write(corrupt_copy(adapter, info), &torn).expect("write the .corrupt copy");
        (torn, scrub(adapter, info, 2))
    }

    fn has_result(items: &[ConversationItem], id: &str) -> bool {
        items
            .iter()
            .any(|i| matches!(i, ConversationItem::ToolResult(tr) if tr.tool_call_id == id))
    }

    #[tokio::test]
    async fn torn_assistant_line_is_repaired_and_the_backup_holds_the_original_bytes() {
        let tmp = TempDir::new().unwrap();
        let (adapter, info) = seed(tmp.path(), "019f3df7-3d70-7f60-8ca0-a38d2d0056a1").await;
        let original = tear(&adapter, &info, 2);

        let mut data = adapter.load_session_without_updates(&info).await.unwrap();
        assert_eq!(data.skipped_chat_lines, 1, "the reader reports the torn line");
        assert!(
            has_result(&data.chat_history, "call_LOST"),
            "fixture: the loaded history carries the orphaned result"
        );
        let repair = adapter
            .repair_after_corrupt_load(&info, &mut data)
            .await
            .expect("a repair");

        assert!(!has_result(&data.chat_history, "call_LOST"));
        assert_eq!(repair.report.stripped_tool_result_ids, vec!["call_LOST"]);
        let backup = backup_path(&adapter.chat_file(&info));
        assert_eq!(repair.disk, RepairDisk::Rewritten(RepairBackup::Created(backup.clone())));
        assert_eq!(std::fs::read(&backup).unwrap(), original, "the backup is the file as found");
        // The file on disk now loads clean, and a second load has nothing to repair.
        let mut again = adapter.load_session_without_updates(&info).await.unwrap();
        assert_eq!(again.skipped_chat_lines, 0);
        assert!(!has_result(&again.chat_history, "call_LOST"));
        assert_eq!(again.chat_history.len(), 3);
        assert!(adapter.repair_after_corrupt_load(&info, &mut again).await.is_none());
        let notice = repair.notice();
        for want in ["1 unreadable line", "removed 1 tool result", &backup.display().to_string()] {
            assert!(notice.contains(want), "notice lacks {want:?}: {notice}");
        }
    }

    /// The note as the user reads it, word for word.
    #[test]
    fn the_notice_names_the_repair_and_reads_as_a_plain_sentence() {
        let backup = PathBuf::from("/s/chat_history.jsonl.pre-repair");
        let mut repair = LoadRepair {
            skipped_lines: 1,
            earlier_quarantine: None,
            report: HistoryRepairReport {
                stripped_tool_result_ids: vec!["call_a".into(), "call_b".into()],
                ..Default::default()
            },
            disk: RepairDisk::Rewritten(RepairBackup::Created(backup)),
        };
        assert_eq!(
            repair.notice(),
            "Session history repaired: removed 2 tool results that had lost their tool calls. Cause: 1 unreadable line \
             in the saved history (a write cut short, for example by a crash); left as it was, the provider would \
             have rejected every request. Backup of the file as it was before the repair: \
             /s/chat_history.jsonl.pre-repair"
        );
        repair.disk = RepairDisk::BackupFailed("no space".into());
        let notice = repair.notice();
        assert!(notice.starts_with("Session history repaired: removed 2 tool results"), "{notice}");
        assert!(notice.contains("could not be backed up (no space)"), "{notice}");
        assert!(!notice.to_lowercase().contains("image"), "{notice}");
    }

    #[tokio::test]
    async fn clean_session_is_left_byte_identical_with_no_backup() {
        let tmp = TempDir::new().unwrap();
        let (adapter, info) = seed(tmp.path(), "019f3df7-3d70-7f60-8ca0-a38d2d0056a2").await;
        let path = adapter.chat_file(&info);
        let original = std::fs::read(&path).unwrap();

        let mut data = adapter.load_session_without_updates(&info).await.unwrap();
        let loaded = data.chat_history.len();
        assert_eq!(data.skipped_chat_lines, 0);
        assert!(adapter.repair_after_corrupt_load(&info, &mut data).await.is_none());

        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(data.chat_history.len(), loaded);
        assert!(!backup_path(&path).exists());
    }

    /// Both conditions are needed. A skipped line whose loss leaves a valid history is not a reason to rewrite, and
    /// neither is an orphan the reader did not cause (no skipped line).
    #[tokio::test]
    async fn one_condition_alone_does_not_trigger_a_repair() {
        let tmp = TempDir::new().unwrap();
        // Skipped line, valid history: the final answer is torn.
        let (adapter, info) = seed(tmp.path(), "019f3df7-3d70-7f60-8ca0-a38d2d0056a3").await;
        let original = tear(&adapter, &info, 4);
        let mut data = adapter.load_session_without_updates(&info).await.unwrap();
        assert_eq!(data.skipped_chat_lines, 1);
        assert!(adapter.repair_after_corrupt_load(&info, &mut data).await.is_none());
        let path = adapter.chat_file(&info);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(!backup_path(&path).exists());

        // Orphaned result, no skipped line: the assistant line is absent, every remaining line parses.
        let (adapter, info) = seed(tmp.path(), "019f3df7-3d70-7f60-8ca0-a38d2d0056a4").await;
        let path = adapter.chat_file(&info);
        let kept: Vec<u8> = std::fs::read(&path)
            .unwrap()
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .enumerate()
            .filter(|(i, _)| *i != 2)
            .flat_map(|(_, l)| l.iter().copied().chain(std::iter::once(b'\n')))
            .collect();
        std::fs::write(&path, &kept).unwrap();
        let mut data = adapter.load_session_without_updates(&info).await.unwrap();
        assert_eq!(data.skipped_chat_lines, 0);
        assert!(has_result(&data.chat_history, "call_LOST"), "fixture: orphan present");
        assert!(!corrupt_copy(&adapter, &info).exists(), "fixture: no .corrupt copy");
        assert!(adapter.repair_after_corrupt_load(&info, &mut data).await.is_none());
        assert!(has_result(&data.chat_history, "call_LOST"));
        assert_eq!(std::fs::read(&path).unwrap(), kept);
        assert!(!backup_path(&path).exists());
    }

    #[tokio::test]
    async fn failed_backup_leaves_the_disk_alone_and_blocks_later_rewrites_until_it_succeeds() {
        let tmp = TempDir::new().unwrap();
        let (adapter, info) = seed(tmp.path(), "019f3df7-3d70-7f60-8ca0-a38d2d0056a5").await;
        let original = tear(&adapter, &info, 2);
        let path = adapter.chat_file(&info);
        // A directory where the backup belongs: no backup can be published, and a directory is not a backup.
        // (This fails for root too, unlike a read-only directory.)
        let blocker = backup_path(&path);
        std::fs::create_dir(&blocker).unwrap();

        let mut data = adapter.load_session_without_updates(&info).await.unwrap();
        let repair = adapter
            .repair_after_corrupt_load(&info, &mut data)
            .await
            .expect("a repair");

        assert!(matches!(repair.disk, RepairDisk::BackupFailed(_)), "{:?}", repair.disk);
        assert!(!has_result(&data.chat_history, "call_LOST"), "repaired in memory");
        assert_eq!(std::fs::read(&path).unwrap(), original, "disk left as found");
        assert!(blocker.is_dir());
        assert!(repair.notice().contains("could not be backed up"));

        // Any later rewrite of the file (the spawn snapshot, a system prompt swap, a compaction) is refused too.
        adapter
            .replace_chat_history(&info, &data.chat_history)
            .await
            .expect_err("a rewrite without the backup must be refused");
        assert_eq!(std::fs::read(&path).unwrap(), original);
        // Appends are not rewrites.
        adapter
            .append_chat_message(&info, &ConversationItem::user("next"))
            .await
            .expect("append");
        let with_append = std::fs::read(&path).unwrap();
        assert!(with_append.starts_with(&original));

        // Once the copy can be made, the next rewrite makes it first and then goes ahead.
        std::fs::remove_dir(&blocker).unwrap();
        adapter
            .replace_chat_history(&info, &data.chat_history)
            .await
            .expect("rewrite after the backup succeeded");
        assert_eq!(std::fs::read(backup_path(&path)).unwrap(), with_append);
        let reloaded = adapter.load_session_without_updates(&info).await.unwrap();
        assert_eq!(reloaded.skipped_chat_lines, 0);
        assert!(!has_result(&reloaded.chat_history, "call_LOST"));
    }

    /// Two loaders can both find no backup and both stage one. Whoever publishes second must keep the first copy.
    #[test]
    fn publishing_never_replaces_a_backup_that_appeared_meanwhile() {
        let tmp = TempDir::new().unwrap();
        let backup = tmp.path().join("chat_history.jsonl.pre-repair");
        let staging = tmp.path().join("staged.tmp");
        std::fs::write(&backup, b"the first copy").unwrap();
        std::fs::write(&staging, b"a later copy").unwrap();
        assert_eq!(
            publish_backup(&staging, &backup).unwrap(),
            RepairBackup::AlreadyPresent(backup.clone())
        );
        assert_eq!(std::fs::read(&backup).unwrap(), b"the first copy");
    }

    /// A live actor holds the shared turn-owner lock. A load that reads its file mid-append must leave it alone.
    #[tokio::test]
    async fn a_session_held_by_a_live_actor_is_not_repaired() {
        let tmp = TempDir::new().unwrap();
        let (adapter, info) = seed(tmp.path(), "019f3df7-3d70-7f60-8ca0-a38d2d0056a7").await;
        let original = tear(&adapter, &info, 2);
        let path = adapter.chat_file(&info);
        let held = crate::session::turn_owner_lock::TurnOwnerLock::acquire(&adapter.session_dir(&info))
            .await
            .expect("lock not busy")
            .expect("fixture: the actor's shared lock is held");

        let mut data = adapter.load_session_without_updates(&info).await.unwrap();
        assert!(adapter.repair_after_corrupt_load(&info, &mut data).await.is_none());
        assert!(has_result(&data.chat_history, "call_LOST"), "the loaded history is left as read");
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(!backup_path(&path).exists());

        // Once the actor is gone the same load repairs it.
        drop(held);
        assert!(adapter.repair_after_corrupt_load(&info, &mut data).await.is_some());
    }

    #[tokio::test]
    async fn an_existing_backup_is_never_overwritten() {
        let tmp = TempDir::new().unwrap();
        let (adapter, info) = seed(tmp.path(), "019f3df7-3d70-7f60-8ca0-a38d2d0056a6").await;
        tear(&adapter, &info, 2);
        let backup = backup_path(&adapter.chat_file(&info));
        std::fs::write(&backup, b"first backup").unwrap();

        let mut data = adapter.load_session_without_updates(&info).await.unwrap();
        let repair = adapter
            .repair_after_corrupt_load(&info, &mut data)
            .await
            .expect("a repair");

        assert_eq!(repair.disk, RepairDisk::Rewritten(RepairBackup::AlreadyPresent(backup.clone())));
        assert_eq!(std::fs::read(&backup).unwrap(), b"first backup");
        assert!(repair.notice().contains("earlier repair"));
    }

    /// A load can be dropped while its repair is writing (leader shutdown drops the load's task). The write itself
    /// runs on a blocking thread and is not stopped by that, so the exclusive lock must stay held until the write is
    /// done: another process that took the lock in between could append, and the late rename would replace that.
    #[tokio::test]
    async fn a_cancelled_load_keeps_the_session_locked_until_its_rewrite_is_done() {
        use crate::session::turn_owner_lock::{RecoveryLock, try_recovery_lock};
        let tmp = TempDir::new().unwrap();
        let (adapter, info) = seed(tmp.path(), "019f3df7-3d70-7f60-8ca0-a38d2d0056c1").await;
        let original = tear(&adapter, &info, 2);
        let path = adapter.chat_file(&info);
        let dir = adapter.session_dir(&info);
        let mut data = adapter.load_session_without_updates(&info).await.unwrap();

        let (started, release) = seams::hold_next_write(&path);
        {
            let repair = adapter.repair_after_corrupt_load(&info, &mut data);
            tokio::pin!(repair);
            tokio::select! {
                _ = &mut repair => panic!("the repair finished although its rewrite is held"),
                started = started => started.expect("the rewrite started"),
            }
            // The load is dropped here, in the middle of its rewrite.
        }
        assert!(
            matches!(try_recovery_lock(&dir), RecoveryLock::HeldElsewhere),
            "the session lock was released while the repair's rewrite was still running"
        );
        assert_eq!(std::fs::read(&path).unwrap(), original, "fixture: the rewrite is still held");

        // Once the rewrite is done, the lock is let go and the file holds the repaired history.
        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match try_recovery_lock(&dir) {
                RecoveryLock::Acquired(_) => break,
                RecoveryLock::HeldElsewhere => {
                    assert!(std::time::Instant::now() < deadline, "the lock was never let go");
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                RecoveryLock::Unknown(error) => panic!("lock state unknown: {error}"),
            }
        }
        let reloaded = adapter.load_session_without_updates(&info).await.unwrap();
        assert_eq!(reloaded.skipped_chat_lines, 0);
        assert!(!has_result(&reloaded.chat_history, "call_LOST"));
        assert_eq!(std::fs::read(backup_path(&path)).unwrap(), original);
    }

    /// The backup counts only once its directory entry is flushed. When that flush fails the repair is not written,
    /// and a retry must flush again: finding the published file is not enough to clear the debt.
    #[tokio::test]
    async fn a_failed_directory_sync_of_the_backup_is_redone_before_the_gate_opens() {
        let tmp = TempDir::new().unwrap();
        let (adapter, info) = seed(tmp.path(), "019f3df7-3d70-7f60-8ca0-a38d2d0056c2").await;
        let original = tear(&adapter, &info, 2);
        let path = adapter.chat_file(&info);
        let dir = adapter.session_dir(&info);
        seams::fail_dir_sync(&dir, true);
        let mut data = adapter.load_session_without_updates(&info).await.unwrap();
        let repair = adapter
            .repair_after_corrupt_load(&info, &mut data)
            .await
            .expect("a repair");
        assert!(matches!(repair.disk, RepairDisk::BackupFailed(_)), "{:?}", repair.disk);
        assert_eq!(std::fs::read(&path).unwrap(), original, "disk left as found");
        assert_eq!(
            std::fs::read(backup_path(&path)).unwrap(),
            original,
            "fixture: the copy was published before the directory sync failed"
        );

        // The directory still cannot be flushed: the retry must fail, and the file must not be rewritten.
        rewrite_gate(&path).expect_err("the gate opened without a flushed backup directory");
        adapter
            .replace_chat_history(&info, &data.chat_history)
            .await
            .expect_err("a rewrite before the backup directory is flushed must be refused");
        assert_eq!(std::fs::read(&path).unwrap(), original);

        // Once the flush works, the gate opens.
        seams::fail_dir_sync(&dir, false);
        rewrite_gate(&path).expect("the gate opens once the directory is flushed");
        adapter
            .replace_chat_history(&info, &data.chat_history)
            .await
            .expect("rewrite after the backup is durable");
        assert_eq!(std::fs::read(backup_path(&path)).unwrap(), original);
    }

    /// While the gate is closed, a rewind or compaction is refused before it changes anything, with a message that
    /// says why; once the backup can be made, nothing is refused.
    #[tokio::test]
    async fn a_destructive_rewrite_is_refused_while_the_backup_is_owed() {
        let tmp = TempDir::new().unwrap();
        let chat = tmp.path().join("chat_history.jsonl");
        std::fs::write(&chat, b"{}\n").unwrap();
        let blocker = backup_path(&chat);
        std::fs::create_dir(&blocker).unwrap();
        BACKUP_OWED.lock().insert(chat.clone());

        let message = refusal_for_chat_file(&chat, "rewind the conversation").expect("refused");
        for want in [
            "Cannot rewind the conversation",
            "could not be backed up",
            "Nothing was changed",
            &blocker.display().to_string(),
        ] {
            assert!(message.contains(want), "message lacks {want:?}: {message}");
        }
        std::fs::remove_dir(&blocker).unwrap();
        assert_eq!(refusal_for_chat_file(&chat, "compact the conversation"), None);
        assert_eq!(std::fs::read(&blocker).unwrap(), b"{}\n");
        let untouched = tmp.path().join("other").join("chat_history.jsonl");
        assert_eq!(refusal_for_chat_file(&untouched, "compact the conversation"), None);
    }

    /// A session that broke before this release: no line is unreadable any more, but the `.corrupt` copy says an
    /// earlier load skipped one, and the orphaned result is still in the file. It is repaired, once.
    #[tokio::test]
    async fn a_history_scrubbed_by_an_earlier_load_is_repaired_when_its_corrupt_copy_is_there() {
        let tmp = TempDir::new().unwrap();
        let (adapter, info) = seed(tmp.path(), "019f3df7-3d70-7f60-8ca0-a38d2d0056b1").await;
        let (corrupt_bytes, as_found) = broken_before_this_release(&adapter, &info);
        let path = adapter.chat_file(&info);
        let corrupt = corrupt_copy(&adapter, &info);

        let mut data = adapter.load_session_without_updates(&info).await.unwrap();
        assert_eq!(data.skipped_chat_lines, 0, "fixture: every line parses");
        assert!(has_result(&data.chat_history, "call_LOST"), "fixture: orphan present");
        let repair = adapter
            .repair_after_corrupt_load(&info, &mut data)
            .await
            .expect("a repair");

        assert!(!has_result(&data.chat_history, "call_LOST"));
        assert_eq!(repair.skipped_lines, 0);
        assert_eq!(repair.report.stripped_tool_result_ids, vec!["call_LOST"]);
        let backup = backup_path(&path);
        assert_eq!(repair.disk, RepairDisk::Rewritten(RepairBackup::Created(backup.clone())));
        assert_eq!(std::fs::read(&backup).unwrap(), as_found, "the backup is the file as found");
        assert_eq!(std::fs::read(&corrupt).unwrap(), corrupt_bytes, "the .corrupt copy is left alone");
        let notice = repair.notice();
        for want in [
            "Session history repaired: removed 1 tool result",
            "an earlier load",
            &corrupt.display().to_string(),
            &backup.display().to_string(),
        ] {
            assert!(notice.contains(want), "notice lacks {want:?}: {notice}");
        }
        assert!(!notice.contains("0 unreadable"), "{notice}");

        // A second load finds nothing to do: the file, the backup and the .corrupt copy stay as they are.
        let repaired_bytes = std::fs::read(&path).unwrap();
        let mut again = adapter.load_session_without_updates(&info).await.unwrap();
        assert_eq!(again.skipped_chat_lines, 0);
        assert!(!has_result(&again.chat_history, "call_LOST"));
        assert!(adapter.repair_after_corrupt_load(&info, &mut again).await.is_none());
        assert_eq!(std::fs::read(&path).unwrap(), repaired_bytes);
        assert_eq!(std::fs::read(&backup).unwrap(), as_found);
        assert_eq!(std::fs::read(&corrupt).unwrap(), corrupt_bytes);
    }

    /// A `.corrupt` copy next to a history that needs no repair changes nothing.
    #[tokio::test]
    async fn a_corrupt_copy_next_to_a_valid_history_changes_nothing() {
        let tmp = TempDir::new().unwrap();
        let (adapter, info) = seed(tmp.path(), "019f3df7-3d70-7f60-8ca0-a38d2d0056b2").await;
        let path = adapter.chat_file(&info);
        let original = std::fs::read(&path).unwrap();
        let corrupt = corrupt_copy(&adapter, &info);
        std::fs::write(&corrupt, b"{\"torn").unwrap();

        let mut data = adapter.load_session_without_updates(&info).await.unwrap();
        let loaded = data.chat_history.len();
        assert_eq!(data.skipped_chat_lines, 0);
        assert!(adapter.repair_after_corrupt_load(&info, &mut data).await.is_none());

        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(data.chat_history.len(), loaded);
        assert!(!backup_path(&path).exists());
        assert_eq!(std::fs::read(&corrupt).unwrap(), b"{\"torn");
    }

    /// Only a regular file is the reader's copy. A directory of that name is not a reason to repair.
    #[tokio::test]
    async fn a_directory_named_like_the_corrupt_copy_is_not_a_reason_to_repair() {
        let tmp = TempDir::new().unwrap();
        let (adapter, info) = seed(tmp.path(), "019f3df7-3d70-7f60-8ca0-a38d2d0056b3").await;
        let as_found = scrub(&adapter, &info, 2);
        let path = adapter.chat_file(&info);
        std::fs::create_dir(corrupt_copy(&adapter, &info)).unwrap();

        let mut data = adapter.load_session_without_updates(&info).await.unwrap();
        assert!(has_result(&data.chat_history, "call_LOST"), "fixture: orphan present");
        assert!(adapter.repair_after_corrupt_load(&info, &mut data).await.is_none());
        assert!(has_result(&data.chat_history, "call_LOST"));
        assert_eq!(std::fs::read(&path).unwrap(), as_found);
        assert!(!backup_path(&path).exists());
    }

    /// The rules of the repair hold for this trigger too: no backup, no rewrite; a live actor, no repair.
    #[tokio::test]
    async fn the_corrupt_copy_trigger_keeps_the_backup_and_lock_rules() {
        let tmp = TempDir::new().unwrap();
        // Backup impossible: repaired in memory, disk as found, the .corrupt copy untouched.
        let (adapter, info) = seed(tmp.path(), "019f3df7-3d70-7f60-8ca0-a38d2d0056b4").await;
        let (corrupt_bytes, as_found) = broken_before_this_release(&adapter, &info);
        let path = adapter.chat_file(&info);
        std::fs::create_dir(backup_path(&path)).unwrap();
        let mut data = adapter.load_session_without_updates(&info).await.unwrap();
        let repair = adapter
            .repair_after_corrupt_load(&info, &mut data)
            .await
            .expect("a repair");
        assert!(matches!(repair.disk, RepairDisk::BackupFailed(_)), "{:?}", repair.disk);
        assert!(!has_result(&data.chat_history, "call_LOST"), "repaired in memory");
        assert_eq!(std::fs::read(&path).unwrap(), as_found, "disk left as found");
        assert_eq!(std::fs::read(corrupt_copy(&adapter, &info)).unwrap(), corrupt_bytes);
        adapter
            .replace_chat_history(&info, &data.chat_history)
            .await
            .expect_err("a rewrite without the backup must be refused");
        assert_eq!(std::fs::read(&path).unwrap(), as_found);

        // Held by a live actor: nothing is done.
        let (adapter, info) = seed(tmp.path(), "019f3df7-3d70-7f60-8ca0-a38d2d0056b5").await;
        let (_, as_found) = broken_before_this_release(&adapter, &info);
        let path = adapter.chat_file(&info);
        let held = crate::session::turn_owner_lock::TurnOwnerLock::acquire(&adapter.session_dir(&info))
            .await
            .expect("lock not busy")
            .expect("fixture: the actor's shared lock is held");
        let mut data = adapter.load_session_without_updates(&info).await.unwrap();
        assert!(adapter.repair_after_corrupt_load(&info, &mut data).await.is_none());
        assert!(has_result(&data.chat_history, "call_LOST"), "the loaded history is left as read");
        assert_eq!(std::fs::read(&path).unwrap(), as_found);
        assert!(!backup_path(&path).exists());
        drop(held);
        assert!(adapter.repair_after_corrupt_load(&info, &mut data).await.is_some());
    }
    /// P120 (Astra r2 #6): the pre-repair backup of a loose chat file is owner-only.
    #[cfg(unix)]
    #[test]
    fn p120_pre_repair_backup_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let chat = dir.path().join("chat_history.jsonl");
        std::fs::write(&chat, b"{}\n").unwrap();
        std::fs::set_permissions(&chat, std::fs::Permissions::from_mode(0o644)).unwrap();
        backup_before_repair(&chat).unwrap();
        let mode = std::fs::metadata(backup_path(&chat)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// P123 (K14): the notes about a refused rewrite are shown once per debt, per kind. They end with the debt: once the
    /// backup is made a later debt shows its own.
    #[test]
    fn a_note_is_shown_once_while_the_backup_is_owed_and_again_for_the_next_debt() {
        let tmp = TempDir::new().unwrap();
        let chat = tmp.path().join("chat_history.jsonl");
        std::fs::write(&chat, b"{}\n").unwrap();
        let blocker = backup_path(&chat);
        std::fs::create_dir(&blocker).unwrap();
        BACKUP_OWED.lock().insert(chat.clone());
        assert!(rewrite_gate(&chat).is_err(), "the debt is real");
        assert!(first_note(&chat, NoteKind::AutoCompaction), "the first note is shown");
        assert!(!first_note(&chat, NoteKind::AutoCompaction), "the second is not");
        assert!(first_note(&chat, NoteKind::FileNotRewritten), "each kind has its own note");
        assert!(!first_note(&chat, NoteKind::FileNotRewritten));
        std::fs::remove_dir(&blocker).unwrap();
        rewrite_gate(&chat).expect("the backup can be made now");
        // A later debt (the backup is gone and blocked again) shows its notes again.
        std::fs::remove_file(&blocker).unwrap();
        std::fs::create_dir(&blocker).unwrap();
        BACKUP_OWED.lock().insert(chat.clone());
        assert!(rewrite_gate(&chat).is_err());
        assert!(first_note(&chat, NoteKind::AutoCompaction), "a new debt shows its note again");
    }

    /// P135: pruning goal directives is not made again when the session is resumed, so its note must not promise that.
    #[test]
    fn the_note_for_an_unrepeated_rewrite_does_not_promise_it_is_applied_on_resume() {
        let tmp = TempDir::new().unwrap();
        let chat = tmp.path().join("chat_history.jsonl");
        std::fs::write(&chat, b"{}\n").unwrap();
        let blocker = backup_path(&chat);
        std::fs::create_dir(&blocker).unwrap();
        BACKUP_OWED.lock().insert(chat.clone());
        let note = note_for_refused_rewrite_at(&chat, "removing the earlier goal directives", false).expect("a note");
        assert!(!note.contains("applied again when the session is resumed"), "{note}");
        assert!(note.contains("a resumed session loads it again"), "{note}");
        assert!(note.contains("this run only"), "{note}");
    }

    /// P123 (K14): the note for a change whose file rewrite is refused names the change, the cause and the path, once;
    /// nothing is said when nothing is owed.
    #[test]
    fn the_refused_rewrite_note_says_what_was_not_saved_and_why() {
        let tmp = TempDir::new().unwrap();
        let chat = tmp.path().join("chat_history.jsonl");
        std::fs::write(&chat, b"{}\n").unwrap();
        assert_eq!(note_for_refused_rewrite_at(&chat, "the new mode's instructions", true), None, "nothing is owed");
        let blocker = backup_path(&chat);
        std::fs::create_dir(&blocker).unwrap();
        BACKUP_OWED.lock().insert(chat.clone());
        let note = note_for_refused_rewrite_at(&chat, "the new mode's instructions", true).expect("a note");
        for want in [
            "Session history file not rewritten: the new mode's instructions",
            "could not be backed up",
            "this run only",
            &blocker.display().to_string(),
        ] {
            assert!(note.contains(want), "note lacks {want:?}: {note}");
        }
        assert_eq!(note_for_refused_rewrite_at(&chat, "the new mode's instructions", true), None, "shown once");
        let refused = refused_auto_compaction_at(&chat).expect_err("refused");
        assert!(refused.refusal.contains("Cannot compact the conversation"), "{}", refused.refusal);
        assert!(refused.note.expect("first").contains("not compacted"));
        assert!(refused_auto_compaction_at(&chat).expect_err("refused again").note.is_none(), "the second is quiet");
        assert!(image_strip_not_saved_note_at(&chat).expect("note").contains("still holds the image"));
        std::fs::remove_dir(&blocker).unwrap();
        assert!(refused_auto_compaction_at(&chat).is_ok(), "the backup could be made, nothing is refused");
        assert_eq!(image_strip_not_saved_note_at(&chat), None);
    }
}
