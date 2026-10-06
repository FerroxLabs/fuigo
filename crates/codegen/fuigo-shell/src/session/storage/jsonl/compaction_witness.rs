//! Recovery of a compaction whose `chat_history.jsonl` rewrite did not land (P111, DI-03 and Astra r4-r6).
//!
//! A compaction commits in the persistence actor: the checkpoint file is written, then the `CompactionCheckpoint`
//! marker is appended to `updates.jsonl` (the commit point), and the acknowledgement lets the chat-state actor apply
//! the compacted projection in memory. The rewrite of `chat_history.jsonl` with that projection is a separate message
//! that follows. When that rewrite does not land (the process stops first, or the write fails), `chat_history.jsonl`
//! still starts with the pre-compaction history, and every chat item written after the compaction is appended after
//! it. Since P88 resume trusts `chat_history.jsonl`, that would silently resume the pre-compaction history.
//!
//! Before the marker is appended, the commit adds a witness entry next to the session files: the checkpoint id, the
//! length and SHA-256 of `chat_history.jsonl` as it is at that moment (after an fsync of it, plus the SHA-256 of its
//! last bytes for a cheap first check), and the length and SHA-256 of the rewrite that is to follow (the projection,
//! serialized as the rewrite writes it). Then:
//!
//! - every whole rewrite of `chat_history.jsonl` that lands, other than a compaction's own (a rewind's, a strip, a
//!   load repair, the startup re-persist), removes the witness: the file is the session's history again. A
//!   compaction's own rewrite keeps it; the rewrite fingerprint tells that file apart;
//! - when the compaction's marker is committed, the entries of earlier compactions are dropped (their markers are no
//!   longer the latest); entries of compactions that never activated are kept behind it, bounded, without ever
//!   dropping the entry the latest marker in the transcript names (that pruning is best effort);
//! - a load (or a fork of the session) uses an entry only when the file still STARTS with the bytes it recorded and
//!   does NOT start with the rewrite it expected (a rewrite that landed just before the witness could be removed), and
//!   the entry names the latest compaction marker. The history is then that checkpoint's projection followed by the
//!   chat items appended after the recorded bytes, in order. Lines that do not parse are counted, so the load-time
//!   repair (P96) treats them as it treats a torn line in the file;
//! - when the file is unchanged since a witnessed commit but no entry names the latest marker at all, and the file
//!   does not start with that compaction's projection, the history is that checkpoint rebuilt from the transcript, as
//!   1.0.20 resumed every compacted session (text only), rather than the history from before the compaction.
//!
//! Anything else leaves `chat_history.jsonl` authoritative, as P88 made it: sessions of earlier versions, forks (the
//! witness is not copied), and every session whose rewrite landed (no witness: a load reads nothing more).

use std::io;
use std::path::Path;

use crate::extensions::notification::CompactionCheckpointFile;
use crate::sampling::ConversationItem;

/// File name of the witness, in the session directory.
pub(crate) const COMPACTION_WITNESS_FILE: &str = "compaction_witness.json";

/// Entries kept: the one the latest committed marker names (its rewrite may be outstanding) and the newest others.
const KEPT_ENTRIES: usize = 16;

/// Bytes at the end of the recorded history that the cheap first check hashes.
const TAIL_SAMPLE: u64 = 4096;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct CompactionWitness {
    entries: Vec<WitnessEntry>,
    /// Checkpoint ids whose entries overflow eviction dropped (newest last, bounded): the only evidence that a
    /// compaction's entry is missing because it was evicted, rather than because a landed rewrite made the file
    /// authoritative and removed the witness (P111, Astra r8 #2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    evicted: Vec<String>,
}

/// Evicted checkpoint ids remembered.
const KEPT_EVICTED: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct WitnessEntry {
    /// The checkpoint whose marker the commit appends right after this entry is durable.
    checkpoint_id: String,
    /// `chat_history.jsonl` when the commit started; `None` when there was no such file.
    chat_history: Option<ChatFingerprint>,
    /// The rewrite of `chat_history.jsonl` that follows the commit (the serialized projection).
    rewrite: Fingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Fingerprint {
    len: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ChatFingerprint {
    len: u64,
    sha256: String,
    /// SHA-256 of the last `min(len, TAIL_SAMPLE)` bytes.
    tail_sha256: String,
}

/// A history recovered from an unapplied compaction.
#[derive(Debug)]
pub(crate) struct RecoveredHistory {
    pub(crate) history: Vec<ConversationItem>,
    /// Lines after the recorded bytes that did not parse (dropped from `history`).
    pub(crate) skipped_lines: usize,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

fn chat_fingerprint_of(bytes: &[u8]) -> ChatFingerprint {
    let len = bytes.len() as u64;
    ChatFingerprint {
        len,
        sha256: sha256_hex(bytes),
        tail_sha256: sha256_hex(&bytes[(len.saturating_sub(TAIL_SAMPLE)) as usize..]),
    }
}

fn read_witness(path: &Path) -> io::Result<Option<CompactionWitness>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn write_witness(path: &Path, witness: &CompactionWitness) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(witness).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    crate::session::storage::write_bytes_atomic(path, &bytes)
}

/// Make `chat_history.jsonl` durable as it is, then durably add the witness entry for `checkpoint`.
/// Blocking. The caller (the compaction commit) appends the activation marker only after this succeeded.
pub(crate) fn write_compaction_witness_sync(session_dir: &Path, checkpoint: &CompactionCheckpointFile) -> io::Result<()> {
    let chat_path = session_dir.join(crate::session::storage::CHAT_HISTORY_FILE);
    // The fingerprint must describe what a crash leaves on disk, so the chat file is flushed first.
    // Write access without truncation: Windows flushes a file only through a handle that may write to it.
    match std::fs::OpenOptions::new().write(true).open(&chat_path) {
        Ok(file) => crate::session::storage::sync_file_durable(&file)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let chat_history = match std::fs::read(&chat_path) {
        Ok(bytes) => Some(chat_fingerprint_of(&bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    // The rewrite writes the projection with the same serializer.
    let rewrite_bytes = crate::session::storage::to_jsonl_bytes(&checkpoint.compacted_history)?;
    let rewrite = Fingerprint {
        len: rewrite_bytes.len() as u64,
        sha256: sha256_hex(&rewrite_bytes),
    };
    let path = session_dir.join(COMPACTION_WITNESS_FILE);
    // Earlier entries are kept: an earlier compaction's rewrite may still be outstanding, and if this one never
    // activates, its entry is the one a load needs. An unreadable witness is replaced.
    let mut witness = read_witness(&path).ok().flatten().unwrap_or_default();
    witness.entries.retain(|entry| entry.checkpoint_id != checkpoint.checkpoint_id);
    witness.entries.push(WitnessEntry {
        checkpoint_id: checkpoint.checkpoint_id.clone(),
        chat_history,
        rewrite,
    });
    if witness.entries.len() > KEPT_ENTRIES {
        evict_excess_entries(session_dir, &mut witness);
    }
    write_witness(&path, &witness)
}

/// Drop the oldest entries until [`KEPT_ENTRIES`] remain, never the one the latest committed marker names: its
/// rewrite may still be outstanding. Which entry that is comes from the transcript itself, not from the pruning after
/// the activation, which is best effort and may have failed and left older entries ahead of it (P111, Astra r7 #1).
/// When the transcript cannot be read, nothing is dropped this time.
/// The ids dropped are recorded in `evicted`.
fn evict_excess_entries(session_dir: &Path, witness: &mut CompactionWitness) {
    let updates_path = session_dir.join(crate::session::storage::UPDATES_FILE);
    let committed = match crate::session::helpers::replay::find_latest_compaction_checkpoint(&updates_path) {
        Ok(latest) => latest.map(|latest| latest.checkpoint_id),
        Err(error) => {
            tracing::warn!(%error, "could not scan updates.jsonl; keeping every compaction witness entry");
            return;
        }
    };
    let mut excess = witness.entries.len().saturating_sub(KEPT_ENTRIES);
    let evicted = &mut witness.evicted;
    witness.entries.retain(|entry| {
        if excess == 0 || committed.as_deref() == Some(entry.checkpoint_id.as_str()) {
            return true;
        }
        excess -= 1;
        evicted.push(entry.checkpoint_id.clone());
        false
    });
    let over = evicted.len().saturating_sub(KEPT_EVICTED);
    evicted.drain(..over);
}

/// The marker of `checkpoint_id` is committed: entries of earlier compactions (and of attempts that never activated)
/// are no longer needed. Best effort: a stale entry only costs a check.
pub(crate) fn compaction_activated_sync(session_dir: &Path, checkpoint_id: &str) {
    let path = session_dir.join(COMPACTION_WITNESS_FILE);
    let Ok(Some(mut witness)) = read_witness(&path) else {
        return;
    };
    witness.entries.retain(|entry| entry.checkpoint_id == checkpoint_id);
    witness.evicted.clear();
    if let Err(error) = write_witness(&path, &witness) {
        tracing::warn!(path = %path.display(), %error, "could not prune the compaction witness");
    }
}

/// `chat_history.jsonl` in `session_dir` was rewritten as a whole with `written` (`None`: rebuilt from the transcript)
/// and the rewrite landed. Unless that was a compaction's own rewrite (its bytes are the rewrite an entry expects; the
/// rewrite fingerprint then tells it apart), no compaction rewrite is outstanding any more and the witness is removed.
/// Best effort.
pub(crate) fn clear_after_chat_rewrite(session_dir: &Path, written: Option<&[u8]>) {
    let path = session_dir.join(COMPACTION_WITNESS_FILE);
    if !path.exists() {
        return;
    }
    if let Some(written) = written
        && let Ok(Some(witness)) = read_witness(&path)
    {
        let len = written.len() as u64;
        let mut sha = None;
        let is_a_compaction_rewrite = witness.entries.iter().any(|entry| {
            entry.rewrite.len == len && *sha.get_or_insert_with(|| sha256_hex(written)) == entry.rewrite.sha256
        });
        if is_a_compaction_rewrite {
            return;
        }
    }
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(path = %path.display(), %error, "could not remove the compaction witness"),
    }
}

/// Whether `bytes` (the start of the chat file, read up to `len`) has SHA-256 `sha256`.
fn starts_with(file_bytes: &[u8], len: u64, sha256: &str) -> bool {
    (file_bytes.len() as u64) >= len && sha256_hex(&file_bytes[..len as usize]) == sha256
}

/// The bytes after the recorded history, when the file still starts with it and not with the expected rewrite.
fn appended_after_recorded(
    chat_path: &Path,
    recorded: &ChatFingerprint,
    rewrite: &Fingerprint,
) -> io::Result<Option<Vec<u8>>> {
    use std::io::{Read, Seek};
    let mut file = match std::fs::File::open(chat_path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() < recorded.len {
        return Ok(None);
    }
    // Cheap first check: after another history was written, the bytes where the recorded one ended differ.
    let sample_start = recorded.len.saturating_sub(TAIL_SAMPLE);
    file.seek(io::SeekFrom::Start(sample_start))?;
    let mut sample = vec![0u8; (recorded.len - sample_start) as usize];
    file.read_exact(&mut sample)?;
    if sha256_hex(&sample) != recorded.tail_sha256 {
        return Ok(None);
    }
    file.seek(io::SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(appended_in(&bytes, recorded, rewrite).map(<[u8]>::to_vec))
}

/// [`appended_after_recorded`] on chat bytes already read.
fn appended_in<'a>(bytes: &'a [u8], recorded: &ChatFingerprint, rewrite: &Fingerprint) -> Option<&'a [u8]> {
    // The rewrite landed (its bytes may begin with the recorded ones, when the compaction kept the whole history it
    // started from): the file is authoritative.
    if starts_with(bytes, rewrite.len, &rewrite.sha256) || !starts_with(bytes, recorded.len, &recorded.sha256) {
        return None;
    }
    Some(&bytes[recorded.len as usize..])
}

/// The chat history a recovery judges: the file as it is now, or the bytes a caller already read from it (`None`:
/// there was no file), so the judgement is about exactly the history that caller uses (P111, Astra r8 #1).
#[derive(Clone, Copy)]
enum ChatBytes<'a> {
    File(&'a Path),
    Captured(Option<&'a [u8]>),
}

impl ChatBytes<'_> {
    fn appended_after(self, recorded: &ChatFingerprint, rewrite: &Fingerprint) -> io::Result<Option<Vec<u8>>> {
        match self {
            Self::File(path) => appended_after_recorded(path, recorded, rewrite),
            Self::Captured(bytes) => Ok(bytes.and_then(|bytes| appended_in(bytes, recorded, rewrite)).map(<[u8]>::to_vec)),
        }
    }

    fn read(self) -> io::Result<Vec<u8>> {
        match self {
            Self::File(path) => match std::fs::read(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
                other => other,
            },
            Self::Captured(bytes) => Ok(bytes.unwrap_or_default().to_vec()),
        }
    }
}

/// The chat items in `appended` (JSONL written after the recorded history) and how many lines did not parse.
fn parse_appended(appended: &[u8]) -> (Vec<ConversationItem>, usize) {
    let mut items = Vec::new();
    let mut skipped = 0;
    for line in appended.split(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<ConversationItem>(line) {
            Ok(item) => items.push(item),
            Err(error) => {
                skipped += 1;
                tracing::warn!(%error, "unreadable chat item written after an unapplied compaction");
            }
        }
    }
    (items, skipped)
}

/// The history to resume with when the latest compaction committed but its `chat_history.jsonl` rewrite did not land
/// (its projection, then the items appended since), or `None` when `chat_history.jsonl` is authoritative (see the
/// module docs). Never fails: a problem is logged and leaves `chat_history.jsonl` authoritative.
pub(crate) fn recover_unapplied_compaction(session_dir: &Path) -> Option<RecoveredHistory> {
    let chat_path = session_dir.join(crate::session::storage::CHAT_HISTORY_FILE);
    recover_unapplied_compaction_from(session_dir, ChatBytes::File(&chat_path))
}

/// [`recover_unapplied_compaction`] judged against `chat`, the bytes of `chat_history.jsonl` the caller read (`None`:
/// no file) rather than the file as it is by now. A copy uses it: a compaction rewrite that lands after the copy read
/// the history must not make the history it read look current (P111, Astra r8 #1).
pub(crate) fn recover_unapplied_compaction_in(session_dir: &Path, chat: Option<&[u8]>) -> Option<RecoveredHistory> {
    recover_unapplied_compaction_from(session_dir, ChatBytes::Captured(chat))
}

fn recover_unapplied_compaction_from(session_dir: &Path, chat: ChatBytes<'_>) -> Option<RecoveredHistory> {
    let witness_path = session_dir.join(COMPACTION_WITNESS_FILE);
    let witness = match read_witness(&witness_path) {
        Ok(Some(witness)) => witness,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(path = %witness_path.display(), %error, "compaction witness unreadable; ignoring it");
            return None;
        }
    };
    // The chat file is checked against each entry before the transcript is scanned: a session whose rewrite landed
    // matches none of them.
    let mut candidates = Vec::new();
    for entry in witness.entries.iter().rev() {
        // An empty recorded history proves nothing: every file starts with it.
        let Some(recorded) = entry.chat_history.as_ref().filter(|recorded| recorded.len > 0) else {
            continue;
        };
        match chat.appended_after(recorded, &entry.rewrite) {
            Ok(Some(appended)) => candidates.push((entry, appended)),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, "could not read chat_history.jsonl for the compaction witness");
                return None;
            }
        }
    }
    if candidates.is_empty() {
        return None;
    }
    let updates_path = session_dir.join(crate::session::storage::UPDATES_FILE);
    let latest = match crate::session::helpers::replay::find_latest_compaction_checkpoint(&updates_path) {
        Ok(Some(latest)) => latest,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(%error, "could not scan updates.jsonl for the compaction witness; resuming from chat_history.jsonl");
            return None;
        }
    };
    let Some((entry, appended)) =
        candidates.into_iter().find(|(entry, _)| entry.checkpoint_id == latest.checkpoint_id)
    else {
        // No candidate names the latest marker. Only an entry that eviction dropped leaves the history unaccounted
        // for; otherwise its entry says its rewrite landed (or the file was replaced), or the witness was removed by a
        // landed whole rewrite and written afresh since (Astra r8 #2): the file is authoritative.
        if !witness.evicted.contains(&latest.checkpoint_id) {
            return None;
        }
        return rebuild_without_an_entry(session_dir, chat, &updates_path, &latest);
    };
    let checkpoint_path = crate::extensions::notification::contained_checkpoint_path(session_dir, &latest.checkpoint_file);
    let checkpoint: CompactionCheckpointFile = match crate::extensions::notification::read_contained_checkpoint(session_dir, &latest.checkpoint_file)
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)))
    {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            tracing::warn!(path = %checkpoint_path.display(), %error,
                "the latest compaction did not reach chat_history.jsonl, but its checkpoint is unreadable; \
                 resuming from chat_history.jsonl");
            return None;
        }
    };
    if checkpoint.schema_version != 1 || latest.schema_version != 1 || checkpoint.checkpoint_id != entry.checkpoint_id {
        tracing::warn!(path = %checkpoint_path.display(),
            "the latest compaction did not reach chat_history.jsonl, but its checkpoint does not match; \
             resuming from chat_history.jsonl");
        return None;
    }
    let (later, skipped_lines) = parse_appended(&appended);
    tracing::warn!(checkpoint = %latest.checkpoint_file, appended_items = later.len(), skipped_lines,
        "the latest compaction committed but its rewrite of chat_history.jsonl never landed; resuming from the \
         compacted history and the items written after it");
    let mut history = checkpoint.compacted_history;
    history.extend(later);
    Some(RecoveredHistory { history, skipped_lines })
}

/// The latest committed compaction's entry was evicted, while the chat file is unchanged since a later witnessed
/// commit started (P111, Astra r7 #1). Eviction never drops the entry the latest marker names when it runs, so this
/// is a safety net. When the chat file starts with that
/// compaction's projection its rewrite landed and the file is authoritative. Otherwise nothing tells where the history
/// before the compaction ends, and the history is that checkpoint rebuilt from the transcript: what 1.0.20 resumed
/// with on every load (text only), instead of the history from before the compaction. `None` (with a warning) when
/// the rebuild does not apply.
fn rebuild_without_an_entry(
    session_dir: &Path,
    chat: ChatBytes<'_>,
    updates_path: &Path,
    latest: &crate::extensions::notification::CompactionCheckpointInfo,
) -> Option<RecoveredHistory> {
    let checkpoint_path = crate::extensions::notification::contained_checkpoint_path(session_dir, &latest.checkpoint_file);
    let projection = crate::extensions::notification::read_contained_checkpoint(session_dir, &latest.checkpoint_file)
        .and_then(|bytes| {
            serde_json::from_slice::<CompactionCheckpointFile>(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
        .and_then(|checkpoint| crate::session::storage::to_jsonl_bytes(&checkpoint.compacted_history));
    let landed = match (projection, chat.read()) {
        (Ok(projection), Ok(chat)) => chat.starts_with(&projection),
        (Err(error), _) | (_, Err(error)) => {
            tracing::warn!(path = %checkpoint_path.display(), %error,
                "the latest compaction has no witness entry and cannot be checked; resuming from chat_history.jsonl");
            return None;
        }
    };
    if landed {
        return None;
    }
    match crate::session::helpers::replay::replay_if_latest_compaction_active(updates_path, session_dir) {
        Ok(Some(history)) => {
            tracing::warn!(checkpoint = %latest.checkpoint_file,
                "the latest compaction committed without its rewrite of chat_history.jsonl and without a witness \
                 entry; resuming from its checkpoint rebuilt from the transcript");
            Some(RecoveredHistory { history, skipped_lines: 0 })
        }
        Ok(None) => {
            tracing::warn!(checkpoint = %latest.checkpoint_file,
                "the latest compaction has no witness entry and its checkpoint cannot be rebuilt; resuming from \
                 chat_history.jsonl");
            None
        }
        Err(error) => {
            tracing::warn!(checkpoint = %latest.checkpoint_file, %error,
                "the latest compaction has no witness entry and its checkpoint is unreadable; resuming from \
                 chat_history.jsonl");
            None
        }
    }
}

/// [`recover_unapplied_compaction`]'s history alone.
pub(crate) fn unapplied_compaction_projection(session_dir: &Path) -> Option<Vec<ConversationItem>> {
    recover_unapplied_compaction(session_dir).map(|recovered| recovered.history)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint_line(id: &str, at: usize) -> String {
        let update = crate::session::storage::SessionUpdate::Fuigo(Box::new(
            crate::extensions::notification::SessionNotification {
                session_id: agent_client_protocol::SessionId::new("s"),
                update: crate::extensions::notification::SessionUpdate::CompactionCheckpoint(Box::new(
                    crate::extensions::notification::CompactionCheckpointInfo {
                        checkpoint_id: id.to_string(),
                        prompt_index_at_compaction: at,
                        checkpoint_file: format!("compaction_checkpoints/{id}.json"),
                        auto_continue: None,
                        schema_version: 1,
                        created_at: "2026-01-01T00:00:00Z".to_string(),
                    },
                )),
                meta: None,
            },
        ));
        let envelope = crate::session::storage::SessionUpdateEnvelope::from_update(&update).unwrap();
        serde_json::to_string(&envelope).unwrap() + "\n"
    }

    fn write_checkpoint(dir: &Path, id: &str, history: Vec<ConversationItem>) -> CompactionCheckpointFile {
        std::fs::create_dir_all(dir.join("compaction_checkpoints")).unwrap();
        let file = CompactionCheckpointFile {
            inherited_prefix_len: Some(0),
            checkpoint_id: id.to_string(),
            prompt_index_at_compaction: 1,
            compacted_history: history,
            schema_version: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            original_user_info: None,
            reread_file_paths: vec![],
        };
        std::fs::write(
            dir.join(format!("compaction_checkpoints/{id}.json")),
            serde_json::to_vec(&file).unwrap(),
        )
        .unwrap();
        file
    }

    fn raw(items: &[ConversationItem]) -> Vec<u8> {
        crate::session::storage::to_jsonl_bytes(items).unwrap()
    }

    fn chat(dir: &Path, items: &[ConversationItem]) {
        crate::session::storage::write_jsonl_atomic(&dir.join("chat_history.jsonl"), items).unwrap();
    }

    fn texts(items: &[ConversationItem]) -> Vec<String> {
        items.iter().map(ConversationItem::text_content).collect()
    }

    /// The witness only overrides the chat file while that file still starts with exactly what the commit saw.
    #[test]
    fn projection_only_while_the_chat_file_starts_with_what_the_commit_saw() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let old = vec![ConversationItem::system("SYS"), ConversationItem::user("P0")];
        let projection = vec![ConversationItem::system("SYS"), ConversationItem::user("SUMMARY")];
        chat(dir, &old);
        let c1 = write_checkpoint(dir, "c1", projection.clone());
        write_compaction_witness_sync(dir, &c1).unwrap();

        // Witness written, marker not appended (the commit stopped before its commit point): nothing to recover.
        std::fs::write(dir.join("updates.jsonl"), "").unwrap();
        assert!(unapplied_compaction_projection(dir).is_none());

        // Marker appended, chat rewrite lost: the projection.
        std::fs::write(dir.join("updates.jsonl"), checkpoint_line("c1", 1)).unwrap();
        let got = unapplied_compaction_projection(dir).expect("projection");
        assert_eq!(
            serde_json::to_value(&got).unwrap(),
            serde_json::to_value(&projection).unwrap()
        );

        // Items appended after the commit (the rewrite still not landed) follow the projection (P111, Astra r4 #3).
        let mut appended = old.clone();
        appended.push(ConversationItem::assistant("R0"));
        std::fs::write(dir.join("chat_history.jsonl"), raw(&appended)).unwrap();
        let got = unapplied_compaction_projection(dir).expect("projection and the items after it");
        assert_eq!(texts(&got), ["SYS", "SUMMARY", "R0"]);

        // Any change to the recorded bytes themselves (here: one item dropped) makes the file authoritative. The
        // bytes are put in place without the rewrite hook, as a crash would leave them.
        std::fs::write(dir.join("chat_history.jsonl"), raw(&old[..1])).unwrap();
        assert!(unapplied_compaction_projection(dir).is_none());

        // The rewrite landed but the process stopped before the witness was removed: the file is authoritative.
        std::fs::write(dir.join("chat_history.jsonl"), raw(&projection)).unwrap();
        assert!(unapplied_compaction_projection(dir).is_none());
        let mut after = projection.clone();
        after.push(ConversationItem::assistant("R0"));
        std::fs::write(dir.join("chat_history.jsonl"), raw(&after)).unwrap();
        assert!(unapplied_compaction_projection(dir).is_none());

        // A whole rewrite through the storage writer removes the witness.
        chat(dir, &appended);
        assert!(!dir.join(COMPACTION_WITNESS_FILE).exists());
        assert!(unapplied_compaction_projection(dir).is_none());

        // A later compaction without a witness of its own: the old witness names another checkpoint.
        chat(dir, &old);
        let mut updates = checkpoint_line("c1", 1);
        updates.push_str(&checkpoint_line("c2", 2));
        std::fs::write(dir.join("updates.jsonl"), updates).unwrap();
        assert!(unapplied_compaction_projection(dir).is_none());
    }

    /// P111 (Astra r5 #4): compaction c1 committed but its rewrite never landed; compaction c2 then wrote its witness
    /// entry and never activated (its marker not committed). The latest marker is still c1, and c1's entry must still
    /// be there to recover from.
    #[test]
    fn a_later_unactivated_compaction_keeps_the_earlier_entry() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let old = vec![ConversationItem::system("SYS"), ConversationItem::user("P0")];
        chat(dir, &old);
        let c1 = write_checkpoint(dir, "c1", vec![ConversationItem::system("SYS"), ConversationItem::user("SUMMARY1")]);
        write_compaction_witness_sync(dir, &c1).unwrap();
        std::fs::write(dir.join("updates.jsonl"), checkpoint_line("c1", 1)).unwrap();
        let mut appended = old.clone();
        appended.push(ConversationItem::user("P1"));
        std::fs::write(dir.join("chat_history.jsonl"), raw(&appended)).unwrap();
        let c2 = write_checkpoint(dir, "c2", vec![ConversationItem::system("SYS"), ConversationItem::user("SUMMARY2")]);
        write_compaction_witness_sync(dir, &c2).unwrap();

        let got = unapplied_compaction_projection(dir).expect("c1 is still recoverable");
        assert_eq!(texts(&got), ["SYS", "SUMMARY1", "P1"]);

        // c2 activates and its rewrite never lands either: c2's projection, then what came after it.
        compaction_activated_sync(dir, "c2");
        let mut updates = checkpoint_line("c1", 1);
        updates.push_str(&checkpoint_line("c2", 2));
        std::fs::write(dir.join("updates.jsonl"), updates).unwrap();
        appended.push(ConversationItem::user("P2"));
        std::fs::write(dir.join("chat_history.jsonl"), raw(&appended)).unwrap();
        let got = unapplied_compaction_projection(dir).expect("c2 recoverable");
        assert_eq!(texts(&got), ["SYS", "SUMMARY2", "P2"]);
    }

    /// P111 (Astra r6 #1): a compaction that kept the whole history it started from (here the system head of a session
    /// compacted before its first prompt) writes a rewrite that BEGINS with the recorded bytes. Once that rewrite
    /// landed, the file must stay authoritative even if the witness is still there, instead of the projection being
    /// taken again with the rewrite's own items appended to it.
    #[test]
    fn a_landed_rewrite_that_starts_with_the_recorded_history_is_authoritative() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let head = vec![ConversationItem::system("SYS")];
        let projection = vec![ConversationItem::system("SYS"), ConversationItem::user("SUMMARY")];
        chat(dir, &head);
        let c1 = write_checkpoint(dir, "c1", projection.clone());
        write_compaction_witness_sync(dir, &c1).unwrap();
        std::fs::write(dir.join("updates.jsonl"), checkpoint_line("c1", 1)).unwrap();

        // Landed, the witness not yet removed (a crash in between), then a later message appended.
        let mut landed = projection.clone();
        landed.push(ConversationItem::user("P1"));
        std::fs::write(dir.join("chat_history.jsonl"), raw(&landed)).unwrap();
        assert!(unapplied_compaction_projection(dir).is_none());

        // Not landed: the head, then a later message.
        let mut stale = head.clone();
        stale.push(ConversationItem::user("P1"));
        std::fs::write(dir.join("chat_history.jsonl"), raw(&stale)).unwrap();
        let got = unapplied_compaction_projection(dir).expect("recovered");
        assert_eq!(texts(&got), ["SYS", "SUMMARY", "P1"]);
    }

    /// P111 (Astra r6 #4): many later compactions write their entries and never activate; the committed one whose
    /// rewrite is outstanding is never evicted.
    #[test]
    fn unactivated_attempts_never_evict_the_committed_entry() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let old = vec![ConversationItem::system("SYS"), ConversationItem::user("P0")];
        chat(dir, &old);
        let c1 = write_checkpoint(dir, "c1", vec![ConversationItem::system("SYS"), ConversationItem::user("SUMMARY1")]);
        write_compaction_witness_sync(dir, &c1).unwrap();
        std::fs::write(dir.join("updates.jsonl"), checkpoint_line("c1", 1)).unwrap();
        compaction_activated_sync(dir, "c1");
        for attempt in 0..3 * KEPT_ENTRIES {
            let id = format!("attempt-{attempt}");
            let attempt = write_checkpoint(dir, &id, vec![ConversationItem::user("never activated")]);
            write_compaction_witness_sync(dir, &attempt).unwrap();
        }
        let witness = read_witness(&dir.join(COMPACTION_WITNESS_FILE)).unwrap().unwrap();
        assert!(witness.entries.len() <= KEPT_ENTRIES);
        let got = unapplied_compaction_projection(dir).expect("c1 is still recoverable");
        assert_eq!(texts(&got), ["SYS", "SUMMARY1"]);
    }

    /// P111 (Astra r7 #1): c0 activated and its rewrite landed. c1 then committed, but the pruning after its activation
    /// failed (simulated: never run) and its rewrite never landed either, so the witness still lists c0 first. More
    /// attempts than the witness keeps then never activate. The entry the latest marker (c1) names must survive them:
    /// the load resumes c1's projection and what came after it, not the history from before c1.
    #[test]
    fn the_latest_committed_entry_survives_eviction_when_its_pruning_failed() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let old = vec![ConversationItem::system("SYS"), ConversationItem::user("P0")];
        chat(dir, &old);
        let c0_projection = vec![ConversationItem::system("SYS"), ConversationItem::user("SUMMARY0")];
        let c0 = write_checkpoint(dir, "c0", c0_projection.clone());
        write_compaction_witness_sync(dir, &c0).unwrap();
        std::fs::write(dir.join("updates.jsonl"), checkpoint_line("c0", 1)).unwrap();
        compaction_activated_sync(dir, "c0");
        // c0's own rewrite lands (the witness is kept: the bytes are a compaction rewrite).
        chat(dir, &c0_projection);
        let mut history = c0_projection.clone();
        history.push(ConversationItem::user("P1"));
        std::fs::write(dir.join("chat_history.jsonl"), raw(&history)).unwrap();

        let c1 = write_checkpoint(dir, "c1", vec![ConversationItem::system("SYS"), ConversationItem::user("SUMMARY1")]);
        write_compaction_witness_sync(dir, &c1).unwrap();
        let mut updates = checkpoint_line("c0", 1);
        updates.push_str(&checkpoint_line("c1", 1));
        std::fs::write(dir.join("updates.jsonl"), updates).unwrap();
        // No `compaction_activated_sync(dir, "c1")`: its pruning failed. No rewrite: it failed too.
        history.push(ConversationItem::user("P2"));
        std::fs::write(dir.join("chat_history.jsonl"), raw(&history)).unwrap();

        for attempt in 0..2 * KEPT_ENTRIES {
            let id = format!("attempt-{attempt}");
            let attempt = write_checkpoint(dir, &id, vec![ConversationItem::user("never activated")]);
            write_compaction_witness_sync(dir, &attempt).unwrap();
        }
        let witness = read_witness(&dir.join(COMPACTION_WITNESS_FILE)).unwrap().unwrap();
        assert!(witness.entries.len() <= KEPT_ENTRIES);
        assert!(witness.entries.iter().any(|entry| entry.checkpoint_id == "c1"), "c1's entry was evicted");
        let got = unapplied_compaction_projection(dir).expect("c1 is still recoverable");
        assert_eq!(texts(&got), ["SYS", "SUMMARY1", "P2"]);
    }

    /// P111 (Astra r7 #1), the load side: the witness holds no entry for the latest committed marker, while the chat
    /// file is unchanged since a later witnessed attempt and does not start with that compaction's projection.
    ///
    /// Without evidence that the entry was evicted, that is an ordinary state (Astra r8 #2): the witness is removed by
    /// every other whole rewrite that lands (a new system head, a strip), and an attempt that never activates writes a
    /// fresh one; the file is authoritative. With that evidence (the witness lists the entry as evicted), its rewrite
    /// never landed and nothing tells where the history before it ends, so the load rebuilds the latest checkpoint from
    /// the transcript, as 1.0.20 did on every resume, instead of resuming the history from before the compaction.
    #[test]
    fn a_committed_marker_without_an_entry_falls_back_to_the_checkpoint_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let old = vec![ConversationItem::system("SYS"), ConversationItem::user("P0")];
        chat(dir, &old);
        let projection = vec![ConversationItem::system("SYS"), ConversationItem::user("SUMMARY1")];
        write_checkpoint(dir, "c1", projection.clone());
        std::fs::write(dir.join("updates.jsonl"), checkpoint_line("c1", 1)).unwrap();
        let attempt = write_checkpoint(dir, "attempt", vec![ConversationItem::user("never activated")]);
        write_compaction_witness_sync(dir, &attempt).unwrap();
        let witness = read_witness(&dir.join(COMPACTION_WITNESS_FILE)).unwrap().unwrap();
        assert_eq!(witness.entries.len(), 1);
        assert!(unapplied_compaction_projection(dir).is_none(), "no evidence of an evicted entry: the file decides");

        // The evidence, as `evict_excess_entries` records it.
        let path = dir.join(COMPACTION_WITNESS_FILE);
        let mut json: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        json["evicted"] = serde_json::json!(["c1"]);
        std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        let got = unapplied_compaction_projection(dir).expect("rebuilt from the checkpoint");
        assert_eq!(texts(&got)[..2], ["SYS", "SUMMARY1"]);
        assert!(!texts(&got).contains(&"P0".to_string()), "pre-compaction history resumed: {:?}", texts(&got));

        // The compaction's rewrite did land (the file starts with its projection): the file stays authoritative.
        let mut landed = projection.clone();
        landed.push(ConversationItem::user("P1"));
        std::fs::write(dir.join("chat_history.jsonl"), raw(&landed)).unwrap();
        write_compaction_witness_sync(dir, &attempt).unwrap();
        assert!(unapplied_compaction_projection(dir).is_none());
    }

    /// P111 (Astra r8 #2): an entry eviction drops is recorded, and is the evidence the load-side fallback needs. Here
    /// c1's entry is evicted while its marker is not yet in the transcript (the only way eviction can drop the entry of
    /// a compaction that becomes the latest), and the marker is then found: the checkpoint is rebuilt.
    #[test]
    fn an_evicted_entry_is_recorded_and_lets_the_load_rebuild_its_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        chat(dir, &[ConversationItem::system("SYS"), ConversationItem::user("P0")]);
        std::fs::write(dir.join("updates.jsonl"), "").unwrap();
        let c1 = write_checkpoint(dir, "c1", vec![ConversationItem::system("SYS"), ConversationItem::user("SUMMARY1")]);
        write_compaction_witness_sync(dir, &c1).unwrap();
        for attempt in 0..KEPT_ENTRIES {
            let id = format!("attempt-{attempt}");
            let attempt = write_checkpoint(dir, &id, vec![ConversationItem::user("never activated")]);
            write_compaction_witness_sync(dir, &attempt).unwrap();
        }
        let witness = read_witness(&dir.join(COMPACTION_WITNESS_FILE)).unwrap().unwrap();
        assert_eq!(witness.evicted, ["c1"]);
        std::fs::write(dir.join("updates.jsonl"), checkpoint_line("c1", 1)).unwrap();
        let got = unapplied_compaction_projection(dir).expect("rebuilt from the checkpoint");
        assert_eq!(texts(&got)[..2], ["SYS", "SUMMARY1"]);
        assert!(!texts(&got).contains(&"P0".to_string()), "pre-compaction history resumed: {:?}", texts(&got));
    }

    /// P111 (Astra r6 #2): a line written after the recorded history that does not parse is counted, so the load-time
    /// repair treats it like a torn line in the file.
    #[test]
    fn unreadable_appended_lines_are_counted() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let old = vec![ConversationItem::system("SYS"), ConversationItem::user("P0")];
        chat(dir, &old);
        let c1 = write_checkpoint(dir, "c1", vec![ConversationItem::system("SYS"), ConversationItem::user("SUMMARY")]);
        write_compaction_witness_sync(dir, &c1).unwrap();
        std::fs::write(dir.join("updates.jsonl"), checkpoint_line("c1", 1)).unwrap();
        let mut bytes = raw(&old);
        bytes.extend_from_slice(b"{\"torn\n");
        bytes.extend(raw(&[ConversationItem::user("P1")]));
        std::fs::write(dir.join("chat_history.jsonl"), bytes).unwrap();
        let recovered = recover_unapplied_compaction(dir).expect("recovered");
        assert_eq!(recovered.skipped_lines, 1);
        assert_eq!(texts(&recovered.history), ["SYS", "SUMMARY", "P1"]);
    }

    /// No witness (every session an earlier version wrote, and every fork): the chat file is authoritative.
    #[test]
    fn no_witness_means_the_chat_file_is_authoritative() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        chat(dir, &[ConversationItem::system("SYS")]);
        write_checkpoint(dir, "c1", vec![ConversationItem::user("SUMMARY")]);
        std::fs::write(dir.join("updates.jsonl"), checkpoint_line("c1", 1)).unwrap();
        assert!(unapplied_compaction_projection(dir).is_none());
    }
}
