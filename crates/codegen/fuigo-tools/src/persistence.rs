//! Background persistence for tool state.
//!
//! [`ResourcesPersistence`] persists `Resources` state (the new architecture).
//! Old `ToolStatePersistence` and `PersistenceLayer` have been deleted.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use fuigo_session_writer::SessionWriter;

use crate::types::resources::Resources;

/// The tool-state file in a session folder.
pub const RESOURCES_STATE_FILE: &str = "resources_state.json";

/// Where the background writer puts the state.
enum StateTarget {
    /// A session folder, through its writer (design F5 §5.4.2). The writer loop owns this clone until after its last
    /// (channel-close) flush, so the session's writer is not free while that flush can still land (CT-W3b).
    Session(SessionWriter),
    /// A file outside any session folder ([`ResourcesPersistence::new_at`]).
    Path(PathBuf),
}

impl StateTarget {
    async fn write(&self, value: &serde_json::Value, durable: bool) -> io::Result<()> {
        match self {
            // The writer's replace is always durable (temp, sync, rename, directory sync).
            Self::Session(writer) => {
                let json = serde_json::to_vec_pretty(value)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                // 1.0.40's repair, kept through the writer (F5-X deviation 5): a directory where the state file belongs
                // is removed before the write, as `replace_state_path` / `publish_durable` do by path.
                if writer.dir().join(RESOURCES_STATE_FILE).is_dir() {
                    tracing::warn!("Resources state path in the session folder is a directory — removing before write");
                    writer.remove_tree(RESOURCES_STATE_FILE).await?;
                }
                writer.replace_atomic(RESOURCES_STATE_FILE, json).await
            }
            Self::Path(path) if durable => ResourcesPersistence::write_json_durable(path, value).await,
            Self::Path(path) => ResourcesPersistence::write_json(path, value).await,
        }
    }

    /// [`Self::write`] for a loop whose runtime is gone ([`Tail`]). A by-path target is not a session folder and keeps
    /// 1.0.40's behaviour (a snapshot pending when its runtime stops is not written).
    fn write_sync(&self, value: &serde_json::Value) -> io::Result<()> {
        match self {
            Self::Session(writer) => {
                let json = serde_json::to_vec_pretty(value)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                if writer.dir().join(RESOURCES_STATE_FILE).is_dir() {
                    writer.remove_tree_sync(RESOURCES_STATE_FILE)?;
                }
                writer.replace_atomic_sync(RESOURCES_STATE_FILE, &json)
            }
            Self::Path(_) => Ok(()),
        }
    }
}

/// The writer loop's receiver, target and unwritten snapshot. A session's current-thread runtime that shuts down drops
/// the loop at its next await instead of letting it see the closed channel and run its tail flush, so a save made just
/// before the session ended was lost (box B8: the scheduler's fire, saved 40 ms before the close, never reached
/// `resources_state.json`, and the reloaded loop fired at once). Dropped, this takes the commands still queued and
/// writes the last snapshot synchronously, before its writer clone goes, so the writer is free only after it landed
/// (design F5 §6.1).
struct Tail {
    rx: tokio::sync::mpsc::UnboundedReceiver<ResourcesPersistenceCommand>,
    target: StateTarget,
    pending: Option<serde_json::Value>,
    state_path: PathBuf,
}

impl Drop for Tail {
    fn drop(&mut self) {
        let mut acks = Vec::new();
        let mut flushed = Vec::new();
        while let Ok(command) = self.rx.try_recv() {
            match command {
                ResourcesPersistenceCommand::Save(snapshot) => self.pending = Some(snapshot),
                ResourcesPersistenceCommand::SaveAndFlush { snapshot, respond_to } => {
                    self.pending = Some(snapshot);
                    acks.push(respond_to);
                }
                ResourcesPersistenceCommand::Flush(done) => flushed.push(done),
            }
        }
        let result = self.pending.take().map_or(Ok(()), |snapshot| self.target.write_sync(&snapshot));
        if let Err(error) = &result {
            tracing::warn!(?error, state_path = ?self.state_path, "Failed to flush resources state at shutdown");
        }
        for ack in acks {
            let _ = ack.send(result.as_ref().map(|_| ()).map_err(|error| io::Error::new(error.kind(), error.to_string())));
        }
        for done in flushed {
            let _ = done.send(());
        }
    }
}

/// Background persistence for `Resources` state/params.
///
/// Same pattern as `ToolStatePersistence` — debounced background writes with
/// atomic rename. Takes a `serde_json::Value` from `Resources::serialize()`
/// and writes it to disk. On load, parses the JSON and feeds it to
/// `Resources::load_from()`.
///
/// This replaces the old `ToolStatePersistence` pipeline for the new
/// architecture. During migration both coexist; once all tools are migrated,
/// `ToolStatePersistence` will be deleted.
pub struct ResourcesPersistence {
    /// `None` means this handle reads and writes nothing.
    state_path: Option<PathBuf>,
    /// Channel to send serialized state to the background writer
    tx: tokio::sync::mpsc::UnboundedSender<ResourcesPersistenceCommand>,
}

#[cfg(test)]
pub(crate) type ControlledSave = (
    serde_json::Value,
    tokio::sync::oneshot::Sender<io::Result<()>>,
);

enum ResourcesPersistenceCommand {
    /// Write this serialized Resources value to disk
    Save(serde_json::Value),
    SaveAndFlush {
        snapshot: serde_json::Value,
        respond_to: tokio::sync::oneshot::Sender<io::Result<()>>,
    },
    /// Flush pending writes and notify when done
    Flush(tokio::sync::oneshot::Sender<()>),
}

impl ResourcesPersistence {
    /// A handle that reads and writes nothing.
    /// For tests, and for sessions with no state directory, which keep their resources in memory for the life of the session.
    pub fn noop() -> Self {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            state_path: None,
            tx,
        }
    }

    #[cfg(test)]
    pub(crate) fn controlled() -> (Self, tokio::sync::mpsc::UnboundedReceiver<ControlledSave>) {
        let (tx, mut commands) =
            tokio::sync::mpsc::unbounded_channel::<ResourcesPersistenceCommand>();
        let (observed_tx, observed_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(command) = commands.recv().await {
                match command {
                    ResourcesPersistenceCommand::Save(_) => {}
                    ResourcesPersistenceCommand::SaveAndFlush {
                        snapshot,
                        respond_to,
                    } => {
                        let _ = observed_tx.send((snapshot, respond_to));
                    }
                    ResourcesPersistenceCommand::Flush(done) => {
                        let _ = done.send(());
                    }
                }
            }
        });
        (
            Self {
                state_path: Some(PathBuf::from("/dev/null")),
                tx,
            },
            observed_rx,
        )
    }

    /// Persist into the session folder of `writer` (`resources_state.json`) and spawn the background writer task, which
    /// owns the writer clone until its last flush has landed (design F5 §5.4.2).
    pub fn new(writer: SessionWriter) -> Self {
        let state_path = writer.dir().join(RESOURCES_STATE_FILE);
        Self::spawn(state_path, StateTarget::Session(writer))
    }

    /// Persist to `state_path` by path, for a file that is **not** in a session folder: the workspace daemon's tree
    /// (`<fuigo_home>/workspace/sessions/`), a headless state folder, tests. A session folder uses [`Self::new`].
    pub fn new_at(state_path: PathBuf) -> Self {
        Self::spawn(state_path.clone(), StateTarget::Path(state_path))
    }

    fn spawn(state_path: PathBuf, target: StateTarget) -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let log_path = state_path.clone();
        tokio::spawn(async move {
            Self::writer_loop(rx, target, log_path).await;
        });

        Self {
            state_path: Some(state_path),
            tx,
        }
    }

    /// Load existing Resources state from disk, if the file exists.
    ///
    /// Reads the JSON, parses it into the nested `HashMap<String, HashMap<String, Value>>`
    /// shape that `Resources::load_from()` expects, and applies it to the given resources.
    ///
    /// Returns `true` if state was loaded, `false` if there is no path, no file, or a parse error.
    pub fn load(&self, resources: &mut Resources) -> bool {
        let Some(state_path) = self.state_path.as_ref() else {
            return false;
        };

        let json = match std::fs::read_to_string(state_path) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let top: serde_json::Value = match serde_json::from_str(&json) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to parse resources state from {state_path:?}: {e}");
                return false;
            }
        };

        let data = match Self::value_to_nested_map(top) {
            Some(m) => m,
            None => {
                tracing::warn!("Resources state file {state_path:?} has unexpected shape");
                return false;
            }
        };

        resources.load_from(data);
        true
    }

    /// Save the current Resources state (non-blocking).
    /// Sends a serialized snapshot to the background writer.
    pub fn save(&self, resources: &Resources) {
        if self.state_path.is_none() {
            return;
        }
        let snapshot = resources.serialize();
        let _ = self.tx.send(ResourcesPersistenceCommand::Save(snapshot));
    }

    /// Replace pending snapshots, write this snapshot, and acknowledge the result.
    pub fn enqueue_save_and_flush(
        &self,
        snapshot: serde_json::Value,
    ) -> io::Result<tokio::sync::oneshot::Receiver<io::Result<()>>> {
        if self.state_path.is_none() {
            let (respond_to, response) = tokio::sync::oneshot::channel();
            let _ = respond_to.send(Ok(()));
            return Ok(response);
        }
        let (respond_to, response) = tokio::sync::oneshot::channel();
        self.tx
            .send(ResourcesPersistenceCommand::SaveAndFlush {
                snapshot,
                respond_to,
            })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "resources persistence writer stopped",
                )
            })?;
        Ok(response)
    }

    /// Await an acknowledgement returned by [`Self::enqueue_save_and_flush`].
    pub async fn await_save_and_flush(
        response: tokio::sync::oneshot::Receiver<io::Result<()>>,
    ) -> io::Result<()> {
        response.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "resources persistence writer dropped acknowledgement",
            )
        })?
    }

    /// Replace pending snapshots, write this snapshot, and await the result.
    pub async fn save_and_flush(&self, snapshot: serde_json::Value) -> io::Result<()> {
        Self::await_save_and_flush(self.enqueue_save_and_flush(snapshot)?).await
    }

    /// `None` when this handle writes nothing.
    pub fn state_path(&self) -> Option<&std::path::Path> {
        self.state_path.as_deref()
    }

    /// Flush pending writes. Call on graceful shutdown.
    pub async fn flush(&self) {
        if self.state_path.is_none() {
            return;
        }
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let _ = self.tx.send(ResourcesPersistenceCommand::Flush(done_tx));
        let _ = done_rx.await;
    }

    /// Convert the `serde_json::Value` (from serialize()) into the nested
    /// HashMap structure that `load_from()` expects.
    fn value_to_nested_map(
        val: serde_json::Value,
    ) -> Option<
        std::collections::HashMap<String, std::collections::HashMap<String, serde_json::Value>>,
    > {
        let top = val.as_object()?;
        let mut result = std::collections::HashMap::new();
        for (cat_key, cat_val) in top {
            let inner_obj = cat_val.as_object()?;
            let mut inner = std::collections::HashMap::new();
            for (k, v) in inner_obj {
                inner.insert(k.clone(), v.clone());
            }
            result.insert(cat_key.clone(), inner);
        }
        Some(result)
    }

    async fn writer_loop(
        rx: tokio::sync::mpsc::UnboundedReceiver<ResourcesPersistenceCommand>,
        target: StateTarget,
        state_path: PathBuf,
    ) {
        let mut tail = Tail { rx, target, pending: None, state_path };
        let mut debounce = tokio::time::interval(Duration::from_millis(500));
        debounce.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                cmd = tail.rx.recv() => {
                    match cmd {
                        Some(ResourcesPersistenceCommand::Save(snapshot)) => {
                            tail.pending = Some(snapshot);
                        }
                        Some(ResourcesPersistenceCommand::SaveAndFlush {
                            snapshot,
                            respond_to,
                        }) => {
                            tail.pending = None;
                            let result = tail.target.write(&snapshot, true).await;
                            let _ = respond_to.send(result);
                        }
                        Some(ResourcesPersistenceCommand::Flush(done)) => {
                            if let Some(snapshot) = tail.pending.take()
                                && let Err(error) = tail.target.write(&snapshot, false).await
                            {
                                tracing::warn!(
                                    ?error,
                                    state_path = ?tail.state_path,
                                    "Failed to flush resources state"
                                );
                            }
                            let _ = done.send(());
                        }
                        None => {
                            if let Some(snapshot) = tail.pending.take()
                                && let Err(error) = tail.target.write(&snapshot, false).await
                            {
                                tracing::warn!(
                                    ?error,
                                    state_path = ?tail.state_path,
                                    "Failed to flush resources state"
                                );
                            }
                            break;
                        }
                    }
                }
                _ = debounce.tick() => {
                    if let Some(snapshot) = tail.pending.take()
                        && let Err(error) = tail.target.write(&snapshot, false).await
                    {
                        tracing::warn!(
                            ?error,
                            state_path = ?tail.state_path,
                            "Failed to save resources state"
                        );
                    }
                }
            }
        }
    }

    async fn write_json(path: &Path, value: &serde_json::Value) -> io::Result<()> {
        let (tmp_path, json) = Self::prepare_write(path, value)?;
        let mut file = Self::create_owner_only(&tmp_path).await?;
        file.write_all(&json).await?;
        // tokio's File acknowledges a write before the blocking write has run; flush waits for it and reports its error
        // (ENOSPC, ...) before the temp replaces the last good snapshot (Astra P145 r1 #1).
        file.flush().await?;
        drop(file);
        Self::replace_state_path(path, &tmp_path).await
    }

    /// Create (truncate) the temp file owner-only (P145). `resources_state.json` lives in the session directory and is a
    /// session file like the others: 0600 on Unix (at creation, and tightened if the temp already existed looser), the
    /// owner-only ACL on Windows, where it used to keep the folder's inherited ACL. The rename keeps the temp's
    /// mode/ACL. Tightening is best effort: a filesystem without permissions must not stop tool state from being saved.
    #[allow(clippy::disallowed_methods, reason = "StateTarget::Path branch writes resources_state.json outside any session folder (workspace daemon tree or headless state folder, via ResourcesPersistence::new_at, registry/types.rs:1241 only when ctx.session_writer is None); session folders go through the writer. Rests on ctx.state_path never naming a session folder, per code comment, not verified; not inside a session folder")]
    async fn create_owner_only(tmp_path: &Path) -> io::Result<tokio::fs::File> {
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(tmp_path).await?;
        if let Err(error) = fuigo_secrets::owner_only::restrict_to_owner(tmp_path) {
            static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!(?error, ?tmp_path, "resources state: could not restrict it to owner-only; continuing");
            }
        }
        Ok(file)
    }

    async fn write_json_durable(path: &Path, value: &serde_json::Value) -> io::Result<()> {
        let (tmp_path, json) = Self::prepare_write(path, value)?;
        let result = async {
            let mut file = Self::create_owner_only(&tmp_path).await?;
            file.write_all(&json).await?;
            file.sync_all().await?;
            drop(file);
            Self::publish_durable(path, &tmp_path).await
        }
        .await;
        Self::cleanup_temp_on_error(&tmp_path, result).await
    }

    #[allow(clippy::disallowed_methods, reason = "StateTarget::Path branch writes resources_state.json outside any session folder (workspace daemon tree or headless state folder, via ResourcesPersistence::new_at, registry/types.rs:1241 only when ctx.session_writer is None); session folders go through the writer. Rests on ctx.state_path never naming a session folder, per code comment, not verified; not inside a session folder")]
    async fn cleanup_temp_on_error(tmp_path: &Path, result: io::Result<()>) -> io::Result<()> {
        if result.is_err() {
            let _ = tokio::fs::remove_file(tmp_path).await;
        }
        result
    }

    fn prepare_write(path: &Path, value: &serde_json::Value) -> io::Result<(PathBuf, Vec<u8>)> {
        let json = serde_json::to_vec_pretty(value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok((path.with_extension("json.tmp"), json))
    }

    #[allow(clippy::disallowed_methods, reason = "StateTarget::Path branch writes resources_state.json outside any session folder (workspace daemon tree or headless state folder, via ResourcesPersistence::new_at, registry/types.rs:1241 only when ctx.session_writer is None); session folders go through the writer. Rests on ctx.state_path never naming a session folder, per code comment, not verified; not inside a session folder")]
    async fn replace_state_path(path: &Path, tmp_path: &Path) -> io::Result<()> {
        if path.is_dir() {
            tracing::warn!(
                "Resources state path {:?} is a directory — removing before write",
                path
            );
            tokio::fs::remove_dir_all(path).await?;
        }
        tokio::fs::rename(tmp_path, path).await
    }

    #[cfg(not(windows))]
    async fn publish_durable(path: &Path, tmp_path: &Path) -> io::Result<()> {
        // A bare filename has an empty parent, so the write would land in the server's own directory, shared by every session.
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "resources state has no parent directory",
                )
            })?;

        Self::replace_state_path(path, tmp_path).await?;
        tokio::fs::File::open(parent).await?.sync_all().await
    }

    #[cfg(windows)]
    async fn publish_durable(path: &Path, tmp_path: &Path) -> io::Result<()> {
        use windows::Win32::Storage::FileSystem::MoveFileExW;
        use windows::core::PCWSTR;
        if path.is_dir() {
            tokio::fs::remove_dir_all(path).await?;
        }
        let from = Self::windows_extended_path(tmp_path)?;
        let to = Self::windows_extended_path(path)?;
        unsafe {
            MoveFileExW(
                PCWSTR(from.as_ptr()),
                PCWSTR(to.as_ptr()),
                Self::WINDOWS_MOVE_FLAGS,
            )
        }
        .map_err(io::Error::other)
    }

    #[cfg(windows)]
    const WINDOWS_MOVE_FLAGS: windows::Win32::Storage::FileSystem::MOVE_FILE_FLAGS =
        windows::Win32::Storage::FileSystem::MOVE_FILE_FLAGS(1 | 8);

    #[cfg(windows)]
    fn windows_extended_path(path: &Path) -> io::Result<Vec<u16>> {
        use std::os::windows::ffi::OsStrExt;
        let path = std::path::absolute(path)?;
        let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains NUL",
            ));
        }
        let unc = wide.starts_with(&[92, 92]);
        let mut result = if unc { r"\\?\UNC\" } else { r"\\?\" }
            .encode_utf16()
            .collect::<Vec<_>>();
        if unc {
            wide.drain(..2);
        }
        result.extend(wide);
        result.push(0);
        Ok(result)
    }
}

// Old `PersistenceLayer` / `PersistenceRunner` deleted.
// ToolState persistence replaced by Resources persistence via `ResourcesPersistence`.

#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[cfg(test)]
mod tests {
    use super::*;

    // ResourcesPersistence tests
    // -----------------------------------------------------------------------

    use crate::types::resources::{Resources, State, WebCitationCounter};

    #[tokio::test]
    async fn resources_save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("resources_state.json");

        let persistence = ResourcesPersistence::new_at(state_path);

        // Build resources with registered state types
        let mut resources = Resources::new();
        resources.register_state::<WebCitationCounter>();

        // Populate WebCitationCounter
        {
            let counter = resources.get_or_default::<State<WebCitationCounter>>();
            counter.counter = 7;
        }

        // Save and flush
        persistence.save(&resources);
        persistence.flush().await;

        // Load into fresh resources (with same registrations)
        let mut restored = Resources::new();
        restored.register_state::<WebCitationCounter>();
        assert!(persistence.load(&mut restored));

        // Verify WebCitationCounter roundtripped
        let counter = restored.get::<State<WebCitationCounter>>().unwrap();
        assert_eq!(counter.counter, 7);
    }

    /// P145 (S14): `resources_state.json` is a session file and is written owner-only by both writers (debounced and
    /// durable), including over a loose temp left behind. Windows gets the owner-only ACL (verified live, R145).
    #[cfg(unix)]
    #[tokio::test]
    async fn p145_resources_state_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resources_state.json");
        let value = serde_json::json!({"state": {}});

        ResourcesPersistence::write_json(&path, &value).await.unwrap();
        assert_eq!(mode(&path), 0o600, "debounced writer");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, b"stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666)).unwrap();
        ResourcesPersistence::write_json_durable(&path, &value).await.unwrap();
        assert_eq!(mode(&path), 0o600, "durable writer over a loose leftover temp");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap()).unwrap(),
            value
        );
    }

    #[tokio::test]
    async fn resources_load_returns_false_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("nonexistent.json");

        let persistence = ResourcesPersistence::new_at(state_path);
        let mut resources = Resources::new();
        assert!(!persistence.load(&mut resources));
    }

    #[tokio::test]
    async fn resources_load_returns_false_on_corrupt_json() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("resources_state.json");
        std::fs::write(&state_path, "{ this is not valid json }").unwrap();

        let persistence = ResourcesPersistence::new_at(state_path);
        let mut resources = Resources::new();
        assert!(!persistence.load(&mut resources));
    }

    /// Atomic-rename guarantee: a concurrent reader hammering the path while
    /// the writer streams 200 snapshots must never observe torn JSON.
    #[tokio::test]
    async fn writer_atomic_rename_never_exposes_partial_json() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("resources_state.json");
        let persistence = ResourcesPersistence::new_at(state_path.clone());

        let mut resources = Resources::new();
        resources.register_state::<WebCitationCounter>();

        let done = std::sync::Arc::new(AtomicBool::new(false));
        let reader_done = done.clone();
        let reader_path = state_path.clone();
        let reader = tokio::spawn(async move {
            while !reader_done.load(Ordering::Relaxed) {
                if let Ok(s) = tokio::fs::read_to_string(&reader_path).await {
                    assert!(
                        serde_json::from_str::<serde_json::Value>(&s).is_ok(),
                        "reader observed a torn/partial write (atomic-rename violated): {s:?}"
                    );
                }
                tokio::task::yield_now().await;
            }
        });

        for i in 0..200u64 {
            {
                let counter = resources.get_or_default::<State<WebCitationCounter>>();
                counter.counter = i as u32;
            }
            persistence.save(&resources);
            persistence.flush().await;
        }

        done.store(true, Ordering::Relaxed);
        reader.await.unwrap();

        // Final state is intact and reflects the last write.
        let content = std::fs::read_to_string(&state_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed["state"]["fuigo_build.WebCitation"].is_object());
    }

    #[tokio::test]
    async fn resources_flush_writes_pending() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("resources_state.json");

        let persistence = ResourcesPersistence::new_at(state_path.clone());

        let mut resources = Resources::new();
        resources.register_state::<WebCitationCounter>();
        {
            let counter = resources.get_or_default::<State<WebCitationCounter>>();
            counter.counter = 42;
        }

        persistence.save(&resources);
        persistence.flush().await;

        // File should exist with correct structure
        assert!(state_path.exists());
        let content = std::fs::read_to_string(&state_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        // Should have "state" category with "fuigo_build.WebCitation" key
        assert!(parsed["state"]["fuigo_build.WebCitation"].is_object());
    }

    #[tokio::test]
    async fn save_and_flush_supersedes_older_pending_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("resources_state.json");
        let persistence = ResourcesPersistence::new_at(state_path.clone());
        persistence.flush().await;

        let mut resources = Resources::new();
        resources.register_state::<WebCitationCounter>();
        resources
            .get_or_default::<State<WebCitationCounter>>()
            .counter = 1;
        persistence.save(&resources);

        resources
            .get_or_default::<State<WebCitationCounter>>()
            .counter = 2;
        persistence
            .save_and_flush(resources.serialize())
            .await
            .unwrap();
        persistence.flush().await;

        let content = std::fs::read_to_string(state_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["state"]["fuigo_build.WebCitation"]["counter"], 2);
    }

    #[tokio::test]
    async fn save_and_flush_error_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("missing");
        let state_path = parent.join("resources_state.json");
        let persistence = ResourcesPersistence::new_at(state_path.clone());

        let mut resources = Resources::new();
        resources.register_state::<WebCitationCounter>();
        resources
            .get_or_default::<State<WebCitationCounter>>()
            .counter = 7;
        let snapshot = resources.serialize();

        assert!(persistence.save_and_flush(snapshot.clone()).await.is_err());

        std::fs::create_dir(parent).unwrap();
        persistence.save_and_flush(snapshot).await.unwrap();

        let content = std::fs::read_to_string(state_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["state"]["fuigo_build.WebCitation"]["counter"], 7);
    }

    #[tokio::test]
    async fn enqueued_acknowledged_save_precedes_a_newer_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("resources_state.json");
        let persistence = ResourcesPersistence::new_at(state_path.clone());
        persistence.flush().await;

        let mut resources = Resources::new();
        resources.register_state::<WebCitationCounter>();
        resources
            .get_or_default::<State<WebCitationCounter>>()
            .counter = 1;
        let acknowledgement = persistence
            .enqueue_save_and_flush(resources.serialize())
            .unwrap();

        resources
            .get_or_default::<State<WebCitationCounter>>()
            .counter = 2;
        persistence.save(&resources);

        ResourcesPersistence::await_save_and_flush(acknowledgement)
            .await
            .unwrap();
        persistence.flush().await;

        let content = std::fs::read_to_string(state_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["state"]["fuigo_build.WebCitation"]["counter"], 2);
    }

    #[tokio::test]
    async fn post_create_failure_cleans_temp_and_allows_retry() {
        let dir = tempfile::tempdir().unwrap();
        let tmp_path = dir.path().join("resources_state.json.tmp");
        std::fs::write(&tmp_path, "partial").unwrap();
        let error = io::Error::other("publish failed");
        let returned = ResourcesPersistence::cleanup_temp_on_error(&tmp_path, Err(error))
            .await
            .unwrap_err();
        assert_eq!(returned.to_string(), "publish failed");
        assert!(!tmp_path.exists());
        std::fs::write(&tmp_path, "retry").unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_publish_supports_long_paths_and_legacy_directory() {
        use windows::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };
        assert_eq!(
            ResourcesPersistence::WINDOWS_MOVE_FLAGS.0,
            MOVEFILE_REPLACE_EXISTING.0 | MOVEFILE_WRITE_THROUGH.0
        );
        let long = PathBuf::from(format!(r"C:\{}", "long\\".repeat(60)));
        let wide = ResourcesPersistence::windows_extended_path(&long).unwrap();
        assert!(wide.len() > 260 && String::from_utf16_lossy(&wide).starts_with(r"\\?\"));
        let unc =
            ResourcesPersistence::windows_extended_path(Path::new(r"\\server\share\state.json"))
                .unwrap();
        assert!(String::from_utf16_lossy(&unc).starts_with(r"\\?\UNC\"));
        assert!(ResourcesPersistence::windows_extended_path(Path::new("bad\0path")).is_err());

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("state.json");
        std::fs::create_dir(&target).unwrap();
        let temp = dir.path().join("state.json.tmp");
        std::fs::write(&temp, "new").unwrap();
        ResourcesPersistence::publish_durable(&target, &temp)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(target).unwrap(), "new");
    }

    /// A bare filename would land in the server's own directory, shared by every session.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn durable_write_refuses_a_path_with_no_directory() {
        let error = ResourcesPersistence::publish_durable(
            Path::new("resources_state.json"),
            Path::new("resources_state.json.tmp"),
        )
        .await
        .expect_err("a bare filename must not publish");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn noop_persistence_neither_reads_nor_writes() {
        let noop = ResourcesPersistence::noop();

        noop.save_and_flush(serde_json::json!({"state": {}}))
            .await
            .unwrap();

        assert!(noop.state_path().is_none());
        assert!(!noop.load(&mut Resources::new()));
    }

    /// CT-W3b (design F5 §9.1; the `resources_state.json` half of §9.2 CT1): drop every handle, so the writer loop's
    /// channel-close flush runs, and pause that flush before its rename. The session's writer is not free until the
    /// flush has landed. 1.0.40's loop wrote by path and held no writer, so nothing kept the session's slot.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ct_w3b_channel_close_flush_holds_the_session_writer_until_it_lands() {
        use fuigo_session_writer::{SessionWriter, seams};
        struct OpenOnDrop(std::sync::Arc<seams::Gate>);
        impl Drop for OpenOnDrop {
            fn drop(&mut self) {
                self.0.open();
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let id = "ct-w3b-resources-channel-close-flush";
        let folder = dir.path().join(id);
        let writer = SessionWriter::try_claim(id, &folder).unwrap();
        let gate = seams::arm(&format!("rename:{id}"));
        let _open_on_unwind = OpenOnDrop(gate.clone());

        let persistence = ResourcesPersistence::new(writer);
        persistence
            .tx
            .send(ResourcesPersistenceCommand::Save(
                serde_json::json!({"state": {"ct_w3b": "tail"}}),
            ))
            .unwrap();
        drop(persistence);

        let reached = tokio::task::spawn_blocking({
            let gate = gate.clone();
            move || gate.wait_reached(Duration::from_secs(10))
        })
        .await
        .unwrap();
        assert!(reached, "the channel-close flush reached its rename");
        assert!(!SessionWriter::is_free(id), "the paused tail flush holds the writer");
        let soon = tokio::time::Instant::now() + Duration::from_millis(200);
        assert!(!SessionWriter::wait_free(id, soon).await, "wait_free cannot return before the flush lands");

        gate.open();
        let later = tokio::time::Instant::now() + Duration::from_secs(10);
        assert!(SessionWriter::wait_free(id, later).await, "the writer frees once the flush has landed");
        let text = std::fs::read_to_string(folder.join(RESOURCES_STATE_FILE)).unwrap();
        assert!(text.contains("tail"), "the tail flush landed: {text}");
    }

    /// F5-B6 (box B8): a session's thread drops its current-thread runtime right after the actor ends, and that drops the
    /// writer loop before it sees the closed channel. A save made just before (the scheduler's fire) must still land,
    /// and land before the writer is free; before, it was lost and the reloaded loop counted from its creation.
    #[test]
    fn f5b6_a_save_pending_when_the_runtime_stops_lands_before_free() {
        use fuigo_session_writer::SessionWriter;
        let dir = tempfile::tempdir().unwrap();
        let id = "f5b6-resources-runtime-drop";
        let folder = dir.path().join(id);
        let writer = SessionWriter::try_claim(id, &folder).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let persistence = rt.block_on(async {
            let persistence = ResourcesPersistence::new(writer);
            persistence.save_and_flush(serde_json::json!({"state": {"f5b6": "created"}})).await.unwrap();
            persistence
                .tx
                .send(ResourcesPersistenceCommand::Save(serde_json::json!({"state": {"f5b6": "fired"}})))
                .unwrap();
            // The loop takes the save as its pending snapshot (the debounce has not ticked), as after a fire.
            tokio::task::yield_now().await;
            persistence
        });
        assert!(!SessionWriter::is_free(id), "fixture: the loop holds the writer");
        drop(persistence);
        drop(rt);
        assert!(SessionWriter::is_free(id), "the writer frees with the loop");
        let text = std::fs::read_to_string(folder.join(RESOURCES_STATE_FILE)).unwrap();
        assert!(text.contains("fired"), "the pending save was lost with the runtime: {text}");
    }

    /// F5-X deviation 5, restored: through the session writer, a directory where `resources_state.json` belongs is
    /// removed and the state written, as 1.0.40 did by path. Fails with the writer branch's repair taken out (the
    /// writer's replace cannot rename a file over a directory).
    #[tokio::test]
    async fn writer_path_repairs_a_directory_at_the_state_path() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("session");
        std::fs::create_dir_all(folder.join(RESOURCES_STATE_FILE).join("nested")).unwrap();
        let writer = SessionWriter::try_claim("resources-dir-repair", &folder).unwrap();
        let persistence = ResourcesPersistence::new(writer);
        persistence
            .save_and_flush(serde_json::json!({ "repaired": true }))
            .await
            .expect("the save repairs the directory and lands");
        let path = folder.join(RESOURCES_STATE_FILE);
        assert!(path.is_file(), "the state path is a file again");
        assert!(std::fs::read_to_string(&path).unwrap().contains("repaired"));
    }

    /// Review r1 H1: the loop's in-flight blocking replace of an older snapshot A outlives the runtime that dropped the
    /// loop; `Tail::drop` then writes the newer B. A must never land after B. Here A is paused at its rename (holding
    /// the writer's replace order), the runtime stops, and A goes on only after: B lands last.
    #[test]
    fn r1h1_an_inflight_older_replace_paused_at_its_rename_never_lands_after_the_shutdown_flush() {
        r1h1_case("rename", "r1h1-paused-at-rename");
    }

    /// Review r1 H1: as above, with A's blocking task not yet at the file at all when B lands: A is superseded and
    /// writes nothing.
    #[test]
    fn r1h1_an_older_replace_whose_task_starts_after_the_shutdown_flush_does_not_land() {
        r1h1_case("replace", "r1h1-not-started");
    }

    fn r1h1_case(seam: &str, id: &str) {
        use fuigo_session_writer::{SessionWriter, seams};
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join(id);
        let writer = SessionWriter::try_claim(id, &folder).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let gate = seams::arm(&format!("{seam}:{id}"));
        let persistence = rt.block_on(async {
            let persistence = ResourcesPersistence::new(writer);
            // A: the loop starts its blocking replace and awaits it.
            let _ack = persistence.enqueue_save_and_flush(serde_json::json!({"state": {"r1h1": "older-A"}})).unwrap();
            let reached = tokio::task::spawn_blocking({
                let gate = gate.clone();
                move || gate.wait_reached(Duration::from_secs(10))
            })
            .await
            .unwrap();
            assert!(reached, "A's blocking replace is paused at the {seam} seam");
            persistence
        });
        // B: queued behind the loop (which is still awaiting A); `Tail::drop` takes it.
        persistence
            .tx
            .send(ResourcesPersistenceCommand::Save(serde_json::json!({"state": {"r1h1": "newer-B"}})))
            .unwrap();
        drop(persistence);
        let opener = std::thread::spawn({
            let gate = gate.clone();
            move || {
                std::thread::sleep(Duration::from_millis(300));
                gate.open();
            }
        });
        rt.shutdown_background();
        opener.join().unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(10);
        while !SessionWriter::is_free(id) && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(SessionWriter::is_free(id), "both writes finished");
        let text = std::fs::read_to_string(folder.join(RESOURCES_STATE_FILE)).unwrap();
        assert!(text.contains("newer-B"), "an older snapshot landed after the newer shutdown flush: {text}");
    }
}
