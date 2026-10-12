//! The peer audit log (peer messaging, packet 5 part B; S8.1-S8.4): `<fuigo home>/peer-audit.jsonl`, one JSON line per event.
//!
//! A local file and nothing else: no network, no telemetry. A line carries EXACTLY these keys, always all present (`null` when
//! unknown), and nothing else: `t` (unix seconds), `msg` (message id), `from_host`, `from_session`, `to_host`, `to_session`,
//! `mode` (the sender's CLAIMED mode), `bytes` (body length), `outcome`, `reason`, `count`. Never the body, a name, a title, a
//! token, a path or an address string.
//!
//! Ids are written RAW, not hashed: they are random identifiers (a 128-bit host id, a session id that is already a file name in
//! the same home), the log's job is to be matched against transcripts and the other end's log, and a hash would defeat that
//! while hiding nothing a reader of the home does not already have. Every string field is still restricted to
//! `[A-Za-z0-9._:-]`, 64 characters; anything else (a message id is peer-supplied text) is replaced by `sha256:` + 16 hex.
//!
//! Bounds (S8.2): the file is rotated to `peer-audit.jsonl.1` before it passes 8 MiB (minus 64 KiB headroom for racing writers),
//! so the two files together stay under 16 MiB. Rejections (`refused`, `saturated`, `duplicate`) of the same (pair, outcome,
//! reason) are ONE line per minute with a count; the table is capped at 256 keys, and what does not fit, plus individual events
//! beyond 600 per minute, are counted into one `suppressed` line per minute.
//!
//! Writing never blocks or fails the message path: callers only `try_send` into a bounded channel (dropping with a counter when
//! full); one writer thread per home does all file I/O. A write error is swallowed after one rate-limited `tracing` warning
//! that carries the error kind only. Several processes of one user append to the same file with `O_APPEND` single writes;
//! rotation takes the repo's cross-process file lock and re-checks the size under it, so it happens once.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use fuigo_peer::{Address, Envelope};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub(crate) const FILE_NAME: &str = "peer-audit.jsonl";
pub(crate) const ROTATED_NAME: &str = "peer-audit.jsonl.1";
const LOCK_NAME: &str = ".peer-audit.lock";
/// One file's cap; two files (current and rotated) bound the total at twice this.
pub(crate) const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Rotate this far under the cap so lines from a process that has not noticed the rotation yet still fit.
const ROTATE_HEADROOM: u64 = 64 * 1024;
const WINDOW_SECS: u64 = 60;
const MAX_AGG_KEYS: usize = 256;
const MAX_INDIVIDUAL_LINES_PER_WINDOW: u32 = 600;
const QUEUE_CAP: usize = 1024;
const MAX_FIELD_CHARS: usize = 64;
const WARN_EVERY: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Outcome {
    Admitted,
    Held,
    Released,
    Reheld,
    Expired,
    RejectedByOperator,
    Refused,
    Saturated,
    Duplicate,
    Suppressed,
    /// S6.6: a protected file changed in a peer-influenced session (`msg` = path hash, `reason` = old and new content hashes).
    IntegrityChanged,
    /// S7.3: a tool request matched a carried denial (`msg` = carrying message id, `reason` = the tool kind).
    LaunderingRefused,
    /// S7.4: the model refused a message (ids only; the model's reason text is never written).
    ModelRefused,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Held => "held",
            Self::Released => "released",
            Self::Reheld => "reheld",
            Self::Expired => "expired",
            Self::RejectedByOperator => "rejected_by_operator",
            Self::Refused => "refused",
            Self::Saturated => "saturated",
            Self::Duplicate => "duplicate",
            Self::Suppressed => "suppressed",
            Self::IntegrityChanged => "integrity_changed",
            Self::LaunderingRefused => "laundering_refused",
            Self::ModelRefused => "model_refused",
        }
    }

    fn aggregated(self) -> bool {
        matches!(self, Self::Refused | Self::Saturated | Self::Duplicate)
    }
}

/// Keep a field to the safe alphabet and length; otherwise replace it with a short hash (never the text itself).
pub(crate) fn clean(s: &str) -> String {
    let ok = !s.is_empty()
        && s.chars().count() <= MAX_FIELD_CHARS
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    if ok {
        s.to_owned()
    } else {
        let d = Sha256::digest(s.as_bytes());
        format!("sha256:{}", d.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>())
    }
}

fn reason_str<T: Serialize>(r: &T) -> Option<String> {
    match serde_json::to_value(r) {
        Ok(serde_json::Value::String(s)) => Some(clean(&s)),
        _ => None,
    }
}

/// One audit event, already restricted to the allowed fields.
#[derive(Debug, Clone)]
pub(crate) struct Event {
    pub t: u64,
    msg: Option<String>,
    from_host: Option<String>,
    from_session: Option<String>,
    to_session: Option<String>,
    mode: Option<String>,
    bytes: u64,
    outcome: Outcome,
    reason: Option<String>,
}

impl Event {
    pub(crate) fn from_envelope<R: Serialize>(
        env: &Envelope,
        to_session: Option<&str>,
        outcome: Outcome,
        reason: Option<&R>,
        t: u64,
    ) -> Self {
        Self {
            t,
            msg: Some(clean(&env.message_id)),
            from_host: Some(clean(env.from.host_id())),
            from_session: Some(clean(env.from.session_id())),
            to_session: to_session.map(clean),
            mode: Some(clean(&env.from_mode.to_wire())),
            bytes: env.body.len() as u64,
            outcome,
            reason: reason.and_then(reason_str),
        }
    }

    /// S6.6: ids and hashes only, never a path or content. `msg` is the path hash; `reason` is `chg:<old16>:<new16>` (`absent` for a
    /// missing file).
    pub(crate) fn integrity_changed(
        to_session: Option<&str>,
        c: &crate::session::peer_integrity::Change,
        t: u64,
    ) -> Self {
        let short = |h: &Option<String>| h.as_deref().map_or_else(|| "absent".to_owned(), |h| h.chars().take(16).collect());
        Self {
            t,
            msg: Some(clean(&crate::session::peer_integrity::path_hash(&c.path))),
            from_host: None,
            from_session: None,
            to_session: to_session.map(clean),
            mode: None,
            bytes: 0,
            outcome: Outcome::IntegrityChanged,
            reason: Some(clean(&format!("chg:{}:{}", short(&c.old_hash), short(&c.new_hash)))),
        }
    }

    /// For an event where only the tracking key (sender address string, message id) is at hand.
    pub(crate) fn from_key<R: Serialize>(
        key: &(String, String),
        to_session: Option<&str>,
        outcome: Outcome,
        reason: Option<&R>,
        t: u64,
    ) -> Self {
        let from = key.0.parse::<Address>().ok();
        Self {
            t,
            msg: Some(clean(&key.1)),
            from_host: from.as_ref().map(|a| clean(a.host_id())),
            from_session: from.as_ref().map(|a| clean(a.session_id())),
            to_session: to_session.map(clean),
            mode: None,
            bytes: 0,
            outcome,
            reason: reason.and_then(reason_str),
        }
    }

    fn agg_key(&self) -> AggKey {
        (self.from_host.clone(), self.from_session.clone(), self.to_session.clone(), self.outcome, self.reason.clone())
    }
}

type AggKey = (Option<String>, Option<String>, Option<String>, Outcome, Option<String>);

/// The written line. Field order is the documented order; a test pins the key set.
#[derive(Serialize)]
struct Line<'a> {
    t: u64,
    msg: Option<&'a str>,
    from_host: Option<&'a str>,
    from_session: Option<&'a str>,
    /// No host id exists for the receiving process yet (the transport packet adds one): always null until then.
    to_host: Option<&'a str>,
    to_session: Option<&'a str>,
    mode: Option<&'a str>,
    bytes: u64,
    outcome: &'static str,
    reason: Option<&'a str>,
    count: u64,
}

fn render(ev: &Event, count: u64) -> String {
    let line = Line {
        t: ev.t,
        msg: ev.msg.as_deref(),
        from_host: ev.from_host.as_deref(),
        from_session: ev.from_session.as_deref(),
        to_host: None,
        to_session: ev.to_session.as_deref(),
        mode: ev.mode.as_deref(),
        bytes: ev.bytes,
        outcome: ev.outcome.as_str(),
        reason: ev.reason.as_deref(),
        count,
    };
    let mut s = serde_json::to_string(&line).unwrap_or_default();
    s.push('\n');
    s
}

struct Agg {
    first: Event,
    count: u64,
}

/// The synchronous heart: aggregation, bounds, file handling. No threads; the writer thread (and the tests) drive it.
pub(crate) struct AuditCore {
    dir: PathBuf,
    cap: u64,
    file: Option<File>,
    window: u64,
    agg: HashMap<AggKey, Agg>,
    suppressed: u64,
    individual: u32,
    /// Test seam: when set, every write fails as a full disk would.
    fail: Option<Arc<AtomicBool>>,
    errors: Arc<AtomicU64>,
    last_warn: Option<Instant>,
}

impl AuditCore {
    pub(crate) fn new(dir: PathBuf, cap: u64, fail: Option<Arc<AtomicBool>>, errors: Arc<AtomicU64>) -> Self {
        Self {
            dir,
            cap,
            file: None,
            window: 0,
            agg: HashMap::new(),
            suppressed: 0,
            individual: 0,
            fail,
            errors,
            last_warn: None,
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.join(FILE_NAME)
    }

    fn limit(&self) -> u64 {
        self.cap.saturating_sub(ROTATE_HEADROOM.min(self.cap / 2))
    }

    pub(crate) fn record(&mut self, ev: Event) {
        self.roll(ev.t);
        if ev.outcome.aggregated() {
            let key = ev.agg_key();
            if let Some(a) = self.agg.get_mut(&key) {
                a.count += 1;
            } else if self.agg.len() < MAX_AGG_KEYS {
                self.agg.insert(key, Agg { first: ev, count: 1 });
            } else {
                self.suppressed += 1;
            }
        } else if self.individual < MAX_INDIVIDUAL_LINES_PER_WINDOW {
            self.individual += 1;
            self.write_line(&render(&ev, 1));
        } else {
            self.suppressed += 1;
        }
    }

    /// Close the minute window when `now` is past it: one line per aggregated key, one `suppressed` line.
    pub(crate) fn roll(&mut self, now: u64) {
        let w = now / WINDOW_SECS;
        if w <= self.window {
            return;
        }
        self.emit_window();
        self.window = w;
    }

    /// Emit what is pending regardless of the clock (shutdown, tests).
    pub(crate) fn flush_all(&mut self) {
        self.emit_window();
    }

    /// Number of aggregation keys held (bounded by `MAX_AGG_KEYS`).
    #[cfg(test)]
    pub(crate) fn table_len(&self) -> usize {
        self.agg.len()
    }

    fn emit_window(&mut self) {
        let start = self.window * WINDOW_SECS;
        let mut aggs: Vec<Agg> = self.agg.drain().map(|(_, a)| a).collect();
        aggs.sort_by_key(|a| a.first.t);
        for a in aggs {
            let mut ev = a.first;
            ev.t = ev.t.max(start);
            self.write_line(&render(&ev, a.count));
        }
        if self.suppressed > 0 {
            let ev = Event {
                t: start,
                msg: None,
                from_host: None,
                from_session: None,
                to_session: None,
                mode: None,
                bytes: 0,
                outcome: Outcome::Suppressed,
                reason: None,
            };
            let n = std::mem::take(&mut self.suppressed);
            self.write_line(&render(&ev, n));
        }
        self.individual = 0;
    }

    /// Append one line. On any error the line is dropped, the error counter rises and one rate-limited warning goes to `tracing`.
    fn write_line(&mut self, line: &str) {
        if let Err(e) = self.append(line) {
            self.file = None;
            self.errors.fetch_add(1, Ordering::Relaxed);
            let due = self.last_warn.is_none_or(|t| t.elapsed() >= WARN_EVERY);
            if due {
                self.last_warn = Some(Instant::now());
                tracing::warn!(kind = ?e.kind(), "peer audit log write failed; audit lines are being dropped");
            }
        }
    }

    fn append(&mut self, line: &str) -> io::Result<()> {
        if self.fail.as_ref().is_some_and(|f| f.load(Ordering::Relaxed)) {
            return Err(io::Error::new(io::ErrorKind::StorageFull, "injected"));
        }
        self.ensure_open()?;
        let len = match self.file.as_ref() {
            Some(f) => f.metadata()?.len(),
            None => 0,
        };
        if len > 0 && len + line.len() as u64 > self.limit() {
            self.rotate(line.len() as u64)?;
        }
        let file = self.file.as_mut().ok_or_else(|| io::Error::other("no file"))?;
        // One write call per line on an O_APPEND handle: lines from several processes never interleave.
        file.write_all(line.as_bytes())
    }

    /// Open (creating mode 0600 / owner-only ACL), or re-open when another process rotated the path away from our handle.
    fn ensure_open(&mut self) -> io::Result<()> {
        let path = self.path();
        if self.file.is_some() && same_file(self.file.as_ref(), &path) {
            return Ok(());
        }
        self.file = None;
        self.file = Some(open_owner_only(&path)?);
        Ok(())
    }

    /// Rotate under the cross-process lock; re-check the size under it so two processes cannot both rotate.
    fn rotate(&mut self, incoming: u64) -> io::Result<()> {
        let path = self.path();
        let _lock = fuigo_config::fs_atomic::lock_file_for_write(&self.dir.join(LOCK_NAME))?;
        let current = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if current > 0 && current + incoming > self.limit() {
            // rename replaces the old rotated file atomically: a crash leaves either the old or the new one, and at most one
            // partial last line (an append cut short).
            std::fs::rename(&path, self.dir.join(ROTATED_NAME))?;
        }
        self.file = None;
        self.file = Some(open_owner_only(&path)?);
        Ok(())
    }
}

#[cfg(unix)]
fn same_file(open: Option<&File>, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let (Some(f), Ok(p)) = (open, std::fs::symlink_metadata(path)) else {
        return false;
    };
    f.metadata().is_ok_and(|m| m.ino() == p.ino() && m.dev() == p.dev())
}

#[cfg(not(unix))]
fn same_file(open: Option<&File>, path: &Path) -> bool {
    open.is_some() && path.exists()
}

fn open_owner_only(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Created 0600 from the first byte; never follow a planted link.
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let f = o.open(path)?;
    // Unix: fixes a pre-existing looser mode. Windows: the owner-only ACL (not run on Windows).
    fuigo_secrets::owner_only::restrict_to_owner(path)?;
    Ok(f)
}

enum Msg {
    Event(Event),
    /// Flush pending aggregates and acknowledge (tests).
    #[cfg(test)]
    Flush(std::sync::mpsc::Sender<()>),
}

/// The handle sessions use: a bounded queue to one writer thread. `submit` never blocks and never does I/O.
pub(crate) struct Sink {
    tx: SyncSender<Msg>,
    dropped: AtomicU64,
    errors: Arc<AtomicU64>,
}

fn registry() -> &'static Mutex<HashMap<PathBuf, Weak<Sink>>> {
    static R: OnceLock<Mutex<HashMap<PathBuf, Weak<Sink>>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

impl Sink {
    /// The shared sink for a home directory: one writer thread per directory per process.
    pub(crate) fn for_dir(dir: &Path) -> Option<Arc<Sink>> {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        reg.retain(|_, w| w.strong_count() > 0);
        if let Some(s) = reg.get(dir).and_then(Weak::upgrade) {
            return Some(s);
        }
        let s = Self::spawn(dir.to_path_buf(), MAX_FILE_BYTES, None)?;
        reg.insert(dir.to_path_buf(), Arc::downgrade(&s));
        Some(s)
    }

    pub(crate) fn spawn(dir: PathBuf, cap: u64, fail: Option<Arc<AtomicBool>>) -> Option<Arc<Sink>> {
        let (tx, rx) = sync_channel::<Msg>(QUEUE_CAP);
        let errors = Arc::new(AtomicU64::new(0));
        let core = AuditCore::new(dir, cap, fail, errors.clone());
        std::thread::Builder::new().name("peer-audit".into()).spawn(move || writer_loop(core, rx)).ok()?;
        Some(Arc::new(Sink { tx, dropped: AtomicU64::new(0), errors }))
    }

    pub(crate) fn submit(&self, ev: Event) {
        match self.tx.try_send(Msg::Event(ev)) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Events dropped because the queue was full (`/peers` shows it in a later packet).
    #[allow(dead_code, reason = "read by tests now, by /peers in a later packet")]
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Write errors seen by the writer (lines lost to a failing disk).
    #[allow(dead_code, reason = "read by tests now, by /peers in a later packet")]
    pub(crate) fn write_errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    /// Wait (bounded) until everything queued so far is written and pending aggregates are flushed.
    #[cfg(test)]
    pub(crate) fn flush(&self) {
        let (ack, wait) = std::sync::mpsc::channel();
        if self.tx.send(Msg::Flush(ack)).is_ok() {
            let _ = wait.recv_timeout(Duration::from_secs(20));
        }
    }
}

fn wall_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn writer_loop(mut core: AuditCore, rx: Receiver<Msg>) {
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(Msg::Event(ev)) => core.record(ev),
            #[cfg(test)]
            Ok(Msg::Flush(ack)) => {
                core.flush_all();
                let _ = ack.send(());
            }
            Err(RecvTimeoutError::Timeout) => core.roll(wall_now()),
            Err(RecvTimeoutError::Disconnected) => {
                core.flush_all();
                return;
            }
        }
    }
}

/// What the admission state holds: who the receiver is, and a lazily created sink for the fuigo home.
#[derive(Default)]
pub(crate) struct AuditCtx {
    to_session: Option<String>,
    sink: Option<Arc<Sink>>,
    #[cfg(test)]
    dir_override: Option<PathBuf>,
}

impl AuditCtx {
    pub(crate) fn set_receiver(&mut self, session_id: &str) {
        self.to_session = Some(session_id.to_owned());
    }

    pub(crate) fn to_session(&self) -> Option<&str> {
        self.to_session.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn set_dir_for_test(&mut self, dir: PathBuf) {
        self.dir_override = Some(dir);
        self.sink = None;
    }

    #[cfg(test)]
    pub(crate) fn set_sink_for_test(&mut self, sink: Arc<Sink>) {
        self.sink = Some(sink);
    }

    #[cfg(test)]
    pub(crate) fn sink_for_test(&self) -> Option<Arc<Sink>> {
        self.sink.clone()
    }

    /// Queue an event. With `features.peer_messaging` off nothing happens: no thread, no directory, no file.
    pub(crate) fn emit(&mut self, ev: Event) {
        if !crate::session::peer_message::peer_messaging_enabled() {
            return;
        }
        if self.sink.is_none() {
            // A unit test writes only where it was told to (`set_dir_for_test`), never to the real fuigo home.
            #[cfg(test)]
            let Some(dir) = self.dir_override.clone() else {
                return;
            };
            #[cfg(not(test))]
            let dir = fuigo_dirs::fuigo_home();
            self.sink = Sink::for_dir(&dir);
        }
        if let Some(s) = &self.sink {
            s.submit(ev);
        }
    }
}

#[cfg(test)]
#[path = "peer_audit_tests.rs"]
mod tests;
