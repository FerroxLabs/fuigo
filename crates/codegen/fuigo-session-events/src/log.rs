use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use fuigo_session_writer::{SessionAppend, SessionWriter};
use serde::Serialize;

use crate::types::Event;

#[derive(Serialize)]
struct EventEntry {
    ts: String,
    #[serde(flatten)]
    event: Event,
}

const EVENTS_FILE: &str = "events.jsonl";

/// Writes events to `events.jsonl`.
/// Clones share one file, and the writer is `Send + Sync` so background tasks can hold one.
///
/// Opened in a session folder ([`EventWriter::open`]), the log is a [`SessionAppend`]: every clone holds the session's
/// [`SessionWriter`] until it drops, so the session's writer is not free while any clone can still write (design F5
/// §5.4.2, CT-W3c).
#[derive(Clone)]
pub struct EventWriter {
    inner: Arc<EventWriterInner>,
}

struct EventWriterInner {
    file: Mutex<Option<Sink>>,
    error_logged: AtomicBool,
}

/// Where an [`EventWriter`] appends.
enum Sink {
    /// A session folder's log, through its writer.
    Session(SessionAppend),
    /// A log outside any session folder ([`EventWriter::open_at`]).
    File(File),
}

/// Open the event log owner-only (P120): created 0600 on Unix, and tightened to 0600 when it already exists with a
/// looser mode. Windows keeps the inherited ACL (see below).
///
/// The tightening is best effort (P134): on a filesystem without Unix modes (vfat, exFAT, some FUSE and SMB mounts)
/// `fchmod` answers EPERM, ENOTSUP or EINVAL, and 1.0.20 wrote the log there. A refusal is logged once per process and
/// the log is still opened.
#[allow(clippy::disallowed_methods, reason = "EventWriter::open_at only (Sink::File): events.jsonl in a directory that is not a session folder (workspace tree, tests); a session folder log goes through SessionAppend (EventWriter::open)")]
fn open_owner_only(options: &mut std::fs::OpenOptions, path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        open_owner_only_with(options, path, |file| {
            use std::os::unix::fs::PermissionsExt as _;
            if file.metadata()?.permissions().mode() & 0o777 != 0o600 {
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(())
        })
    }
    // Windows (P145): the owner-only ACL from `fuigo-secrets` (it used to live only in `fuigo-shell-base`, which this crate
    // cannot depend on, so the log kept the folder's inherited ACL: release note K18). Best effort, warned once, like Unix.
    #[cfg(windows)]
    {
        static WARNED: AtomicBool = AtomicBool::new(false);
        let file = options.open(path)?;
        if let Err(error) = fuigo_secrets::owner_only::restrict_to_owner(path)
            && !WARNED.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                path = %path.display(),
                %error,
                "could not restrict {EVENTS_FILE} to owner-only; continuing with the inherited ACL"
            );
        }
        Ok(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        options.open(path)
    }
}

/// [`open_owner_only`] with the tightening injected.
#[cfg(unix)]
fn open_owner_only_with(
    options: &mut std::fs::OpenOptions,
    path: &Path,
    tighten: impl FnOnce(&File) -> std::io::Result<()>,
) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    static WARNED: AtomicBool = AtomicBool::new(false);
    let file = options.mode(0o600).open(path)?;
    if let Err(error) = tighten(&file)
        && !WARNED.swap(true, Ordering::Relaxed)
    {
        tracing::warn!(
            path = %path.display(),
            %error,
            "could not restrict {EVENTS_FILE} to owner-only (a filesystem without Unix permissions?); continuing unprotected"
        );
    }
    Ok(file)
}

impl EventWriter {
    /// Open the session's `events.jsonl` through its writer (owner-only, created if missing). Every clone of the
    /// returned writer holds a clone of `writer` until it drops.
    pub fn open(writer: &SessionWriter) -> Self {
        let sink = writer
            .open_append(EVENTS_FILE)
            .map_err(|e| {
                tracing::warn!(session = writer.id(), error = %e, "failed to open {EVENTS_FILE}");
                e
            })
            .ok()
            .map(Sink::Session);
        Self::with_sink(sink)
    }

    /// Open `dir/events.jsonl` where `dir` is **not** a session folder: the workspace daemon's own tree
    /// (`<fuigo_home>/workspace/sessions/`), and tests. A session folder is opened with [`EventWriter::open`].
    #[allow(clippy::disallowed_methods, reason = "EventWriter::open_at: events.jsonl in a directory that is not a session folder (<fuigo_home>/workspace/sessions/, tests); session folders use EventWriter::open(&SessionWriter) (design F5 5.4.2)")]
    pub fn open_at(dir: &Path) -> Self {
        let path = dir.join(EVENTS_FILE);
        let file = open_owner_only(std::fs::OpenOptions::new().create(true).append(true), &path)
            .map_err(|e| {
                tracing::warn!(path = %path.display(), error = %e, "failed to open {EVENTS_FILE}");
                e
            })
            .ok()
            .map(Sink::File);
        Self::with_sink(file)
    }

    fn with_sink(sink: Option<Sink>) -> Self {
        Self {
            inner: Arc::new(EventWriterInner {
                file: Mutex::new(sink),
                error_logged: AtomicBool::new(false),
            }),
        }
    }

    pub fn noop() -> Self {
        Self {
            inner: Arc::new(EventWriterInner {
                file: Mutex::new(None),
                error_logged: AtomicBool::new(true), // True from the start, so this writer never warns
            }),
        }
    }

    pub fn emit(&self, event: Event) {
        let Ok(line) = encode_line(&event_entry(event)) else {
            return;
        };

        let Ok(mut guard) = self.inner.file.lock() else {
            return;
        };
        let written = match guard.as_mut() {
            Some(Sink::Session(log)) => log.write_all(&line),
            Some(Sink::File(f)) => f.write_all(&line),
            None => Ok(()),
        };
        if let Err(e) = written
            && !self.inner.error_logged.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(error = %e, "{EVENTS_FILE} write failed");
        }
    }
}

/// One `events.jsonl` line, newline included, holding no credential this process sent (P113, CIE-01).
///
/// Events carry text that came from a child, a server or a provider (an MCP server's undecodable stdout sample, its
/// error messages, a tool-call error), and the file is persisted and packed into feedback archives. So every string
/// in the event is passed through the sent-credential scrub (P70b) before it is written: a recorded credential reads
/// `<redacted>` and the line stays JSON. Then the encoded line passes the byte-level scrub, which replaces one in an
/// object key and withholds the whole line if one is still there (a credential formed around the placeholder).
///
/// The event's `type` tag is Fuigo's own constant, never outside text, and readers (interrupted-turn recovery) find
/// events by it, so it is kept as written even if a recorded credential happens to equal it (Astra r2 #6).
fn encode_line(entry: &EventEntry) -> serde_json::Result<Vec<u8>> {
    use fuigo_secrets::sent_credentials;
    let mut line = if sent_credentials::is_empty() {
        serde_json::to_vec(entry)?
    } else {
        let mut value = serde_json::to_value(entry)?;
        let tag = value.as_object_mut().and_then(|fields| fields.remove("type"));
        sent_credentials::scrub_json_strings(&mut value);
        let body = serde_json::to_vec(&value)?;
        let body = sent_credentials::scrub_bytes(&body).unwrap_or(body);
        match (tag, body.strip_prefix(b"{")) {
            // `ts` is always there, so the scrubbed object is never empty: the tag goes first, then a comma.
            (Some(tag), Some(fields)) => {
                let mut line = b"{\"type\":".to_vec();
                line.extend(serde_json::to_vec(&tag)?);
                line.push(b',');
                line.extend_from_slice(fields);
                line
            }
            // Withheld (not an object any more), or an event without a tag.
            _ => body,
        }
    };
    line.push(b'\n');
    Ok(line)
}

/// Appends one event to the session's `events.jsonl` through its writer and reports whether it landed, for callers
/// that must not assume it did. A torn last line (a writer that died mid-line) would swallow the appended event into
/// one unparseable line, so a missing trailing newline is written first. The data is synced before this returns.
pub fn append_event_checked(writer: &SessionWriter, event: Event) -> std::io::Result<()> {
    let line = encode_line(&event_entry(event)).map_err(std::io::Error::other)?;
    writer.append_line_checked_sync(EVENTS_FILE, &line)
}

fn event_entry(event: Event) -> EventEntry {
    EventEntry {
        ts: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        event,
    }
}

impl std::fmt::Debug for EventWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventWriter").finish()
    }
}

#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[cfg(test)]
mod tests {
    /// P134: a filesystem that refuses `fchmod` must not stop the event log from opening.
    #[cfg(unix)]
    #[test]
    fn p134_event_log_opens_when_fchmod_is_refused() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(EVENTS_FILE);
        let mut file = open_owner_only_with(
            std::fs::OpenOptions::new().create(true).append(true),
            &path,
            |_| Err(std::io::Error::from_raw_os_error(1)),
        )
        .expect("a refused fchmod must not fail the open");
        file.write_all(b"{}\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{}\n");
    }

    use super::*;

    /// Tests: [`append_event_checked`] on a folder, through a writer claimed for it under a fresh id (the by-path
    /// variant is gone, design F5 §5.4.2).
    fn append_event_checked_at(dir: &Path, event: Event) -> std::io::Result<()> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = format!("events-test-{}", NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        let writer = SessionWriter::try_claim(id, dir).expect("claim");
        append_event_checked(&writer, event)
    }
    use crate::types::{
        EVENT_SCHEMA_VERSION, Event, SessionRelationship, ToolOutcome, TurnOutcomeLabel,
    };

    fn _assert_event_writer_is_send_sync_clone()
    where
        EventWriter: Send + Sync + Clone,
    {
    }

    /// P113 (CIE-01): both writers pass every string through the sent-credential scrub, nested JSON included, and the
    /// byte-level pass catches one in an object key (which the string scrub leaves alone).
    #[test]
    fn p113_written_events_hold_no_sent_credential() {
        const KEY: &str = "p113-FAKE-session-events-key-91c2";
        fuigo_secrets::sent_credentials::record(KEY);
        let dir = tempfile::tempdir().unwrap();
        EventWriter::open_at(dir.path()).emit(Event::McpTransportDecodeError {
            server_name: "s".into(),
            error: format!("bad {KEY}"),
            sample: format!("printed {KEY}"),
        });
        append_event_checked_at(
            dir.path(),
            Event::TurnEnded {
                outcome: TurnOutcomeLabel::Completed,
                cancellation_category: None,
                cancellation_context: Some(serde_json::json!({"detail": [format!("x {KEY}")]})),
            },
        )
        .unwrap();
        append_event_checked_at(
            dir.path(),
            Event::TurnEnded {
                outcome: TurnOutcomeLabel::Completed,
                cancellation_category: None,
                cancellation_context: Some(serde_json::json!({ KEY: 1 })),
            },
        )
        .unwrap();
        let text = std::fs::read_to_string(dir.path().join(EVENTS_FILE)).unwrap();
        assert!(!text.contains(KEY), "{text}");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        let decode: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(decode["sample"], "printed <redacted>");
        assert_eq!(decode["error"], "bad <redacted>");
        let nested: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(nested["cancellation_context"]["detail"][0], "x <redacted>");
        let keyed: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(keyed["cancellation_context"]["<redacted>"], 1);
    }

    /// P163 (1.0.21 K24): a recorded key that reaches an event re-encoded (inside HTTP `Basic`, a URL-safe base64
    /// JSON blob, percent-encoded) is replaced in `events.jsonl` too.
    #[test]
    fn p163_written_events_hold_no_re_encoded_sent_credential() {
        const KEY: &str = "p163-FAKE-events-key-7d1e";
        // base64("alice:" + KEY), URL-safe base64 of {"k":"KEY"}, and KEY with every byte percent-encoded.
        const BASIC: &str = "YWxpY2U6cDE2My1GQUtFLWV2ZW50cy1rZXktN2QxZQ==";
        const BLOB: &str = "eyJrIjoicDE2My1GQUtFLWV2ZW50cy1rZXktN2QxZSJ9";
        const PCT: &str =
            "%70%31%36%33%2D%46%41%4B%45%2D%65%76%65%6E%74%73%2D%6B%65%79%2D%37%64%31%65";
        fuigo_secrets::sent_credentials::record(KEY);
        let dir = tempfile::tempdir().unwrap();
        append_event_checked_at(
            dir.path(),
            Event::McpTransportDecodeError {
                server_name: "s".into(),
                error: format!("echoed Authorization: Basic {BASIC}"),
                sample: format!("token={BLOB}&k={PCT}"),
            },
        )
        .unwrap();
        let text = std::fs::read_to_string(dir.path().join(EVENTS_FILE)).unwrap();
        // The base64 characters that only the key determines, and the encoded key.
        for leak in ["cDE2My1GQUtFLWV2ZW50cy1rZXkt", "%70%31%36%33%2D"] {
            assert!(!text.contains(leak), "{leak}: {text}");
        }
        let event: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
        assert!(
            event["error"].as_str().unwrap().contains("<redacted>"),
            "{text}"
        );
        assert!(
            event["sample"].as_str().unwrap().ends_with("&k=<redacted>"),
            "{text}"
        );
    }

    /// P113 (Astra r2 #6): a recorded credential that equals an event's `type` tag leaves the tag as written, so
    /// readers still recognise the event; the same text elsewhere in the event is still replaced. Its own process:
    /// recording `turn_ended` would rewrite every other test's events.
    #[test]
    fn p113_a_credential_equal_to_an_event_tag_keeps_the_tag() {
        const NAME: &str = "p113_a_credential_equal_to_an_event_tag_keeps_the_tag";
        if std::env::var("P113_CHILD_TEST").as_deref() != Ok(NAME) {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg(NAME)
                .args(["--test-threads=1", "--nocapture"])
                .env("P113_CHILD_TEST", NAME)
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&output.stdout).into_owned();
            assert!(output.status.success(), "isolated P113 probe failed: {text}");
            assert!(text.contains("test result: ok. 1 passed"), "{text}");
            return;
        }
        fuigo_secrets::sent_credentials::record("turn_ended");
        let dir = tempfile::tempdir().unwrap();
        append_event_checked_at(
            dir.path(),
            Event::TurnEnded {
                outcome: TurnOutcomeLabel::Completed,
                cancellation_category: None,
                cancellation_context: Some(serde_json::json!({"note": "turn_ended"})),
            },
        )
        .unwrap();
        let text = std::fs::read_to_string(dir.path().join(EVENTS_FILE)).unwrap();
        let event: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
        assert_eq!(event["type"], "turn_ended", "{text}");
        assert_eq!(event["cancellation_context"]["note"], "<redacted>", "{text}");
        assert!(event["ts"].is_string(), "{text}");
    }

    #[test]
    fn test_emit_writes_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let writer = EventWriter::open_at(dir.path());

        writer.emit(Event::TurnStarted {
            session_id: "test-session".into(),
            turn_number: 1,
            model_id: "grok-3".into(),
            yolo_mode: false,
            conversation_message_count: 0,
            session_relationship: SessionRelationship::Primary,
            schema_version: EVENT_SCHEMA_VERSION.into(),
            redirect_kind: None,
            prompt_id: None,
        });
        writer.emit(Event::FirstToken);
        writer.emit(Event::ToolCompleted {
            tool_name: "bash".into(),
            duration_ms: 1500,
            outcome: ToolOutcome::Success,
            tool_call_id: "call_xyz".into(),
            source: crate::types::ToolCompletedSource::Shell,
            rewriting_hook: None,
        });
        writer.emit(Event::TurnEnded {
            outcome: TurnOutcomeLabel::Completed,
            cancellation_category: None,
            cancellation_context: None,
        });

        let text = std::fs::read_to_string(dir.path().join("events.jsonl")).unwrap();
        let lines: Vec<&str> = text.trim().split('\n').collect();
        assert_eq!(lines.len(), 4);

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["type"], "turn_started");
        assert_eq!(first["session_id"], "test-session");
        assert!(first["ts"].as_str().is_some());

        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["type"], "first_token");

        let third: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(third["type"], "tool_completed");
        assert_eq!(third["tool_name"], "bash");
        assert_eq!(third["duration_ms"], 1500);
        assert_eq!(third["tool_call_id"], "call_xyz");
        assert!(
            third.get("source").is_none(),
            "shell ToolCompleted must omit source"
        );

        let fourth: serde_json::Value = serde_json::from_str(lines[3]).unwrap();
        assert_eq!(fourth["type"], "turn_ended");
        assert_eq!(fourth["outcome"], "completed");
        assert!(fourth.get("cancellation_category").is_none());
    }

    /// A torn tail must not swallow the appended event: the repair newline keeps it on a line of its own.
    #[test]
    fn append_event_checked_repairs_a_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        std::fs::write(
            &path,
            br#"{"ts":"x","type":"turn_started"}
{"ts":"y","type":"tool_sta"#,
        )
        .unwrap();

        append_event_checked_at(
            dir.path(),
            Event::TurnEnded {
                outcome: TurnOutcomeLabel::Interrupted,
                cancellation_category: None,
                cancellation_context: None,
            },
        )
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with('\n'));
        let last: serde_json::Value =
            serde_json::from_str(text.lines().last().unwrap()).expect("appended line parses");
        assert_eq!(last["type"], "turn_ended");
        assert_eq!(last["outcome"], "interrupted");
    }

    /// A clean tail gets no blank line, and a missing file is created.
    #[test]
    fn append_event_checked_adds_no_blank_line_and_creates_the_file() {
        let dir = tempfile::tempdir().unwrap();
        append_event_checked_at(dir.path(), Event::FirstToken).unwrap();
        append_event_checked_at(dir.path(), Event::FirstToken).unwrap();
        let text = std::fs::read_to_string(dir.path().join("events.jsonl")).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.lines().all(|l| !l.is_empty()));
    }

    #[test]
    fn cloned_writer_shares_file() {
        let dir = tempfile::tempdir().unwrap();
        let w1 = EventWriter::open_at(dir.path());
        let w2 = w1.clone();

        w1.emit(Event::FirstToken);
        w2.emit(Event::FirstToken);

        let text = std::fs::read_to_string(dir.path().join("events.jsonl")).unwrap();
        let lines: Vec<&str> = text.trim().split('\n').collect();
        assert_eq!(lines.len(), 2, "both writes should go to the same file");
    }
    /// P120 (Astra r1 #6): `events.jsonl` is owner-only, created so and tightened when it already exists loose.
    #[cfg(unix)]
    #[test]
    fn p120_events_log_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(EVENTS_FILE);
        let mode = || std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let event = || Event::TurnEnded {
            outcome: TurnOutcomeLabel::Completed,
            cancellation_category: None,
            cancellation_context: None,
        };
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let writer = EventWriter::open_at(dir.path());
        writer.emit(event());
        assert_eq!(mode(), 0o600, "EventWriter::open tightens an existing file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        append_event_checked_at(dir.path(), event()).unwrap();
        assert_eq!(mode(), 0o600, "append_event_checked tightens an existing file");
        std::fs::remove_file(&path).unwrap();
        append_event_checked_at(dir.path(), event()).unwrap();
        assert_eq!(mode(), 0o600, "a new file is created owner-only");
    }

    /// CT-W3c, `EventWriter` half (design F5 §9.1): an `EventWriter` clone moved into a task holds the session's
    /// writer, so the slot is not free until every clone has dropped. 1.0.40's `EventWriter::open(&Path)` held none.
    #[test]
    fn ct_w3c_event_writer_clones_hold_the_session_writer() {
        use fuigo_session_writer::SessionWriter;
        let dir = tempfile::tempdir().unwrap();
        let id = "ct-w3c-event-writer-clone";
        let folder = dir.path().join(id);
        let writer = SessionWriter::try_claim(id, &folder).unwrap();
        let events = EventWriter::open(&writer);
        drop(writer);
        assert!(!SessionWriter::is_free(id), "the EventWriter holds the writer");

        let (reached_tx, reached_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let in_task = events.clone();
        let task = std::thread::spawn(move || {
            in_task.emit(Event::FirstToken);
            reached_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            in_task.emit(Event::FirstToken);
        });
        reached_rx.recv().unwrap();
        drop(events);
        assert!(!SessionWriter::is_free(id), "a clone in a running task still holds the writer");
        release_tx.send(()).unwrap();
        task.join().unwrap();
        assert!(SessionWriter::is_free(id), "the last clone's drop frees the writer");

        let text = std::fs::read_to_string(folder.join(EVENTS_FILE)).unwrap();
        assert_eq!(text.lines().count(), 2, "{text}");
    }

    /// `append_event_checked` through the writer keeps the torn-tail repair, creates the log owner-only, and writes
    /// nothing once the writer released the folder for a delete.
    #[test]
    fn append_event_checked_through_the_writer() {
        use fuigo_session_writer::SessionWriter;
        let dir = tempfile::tempdir().unwrap();
        let id = "append-event-checked-through-the-writer";
        let folder = dir.path().join(id);
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join(EVENTS_FILE), b"{\"type\":\"first_token\"").unwrap();
        let writer = SessionWriter::try_claim(id, &folder).unwrap();
        append_event_checked(&writer, Event::FirstToken).unwrap();
        let text = std::fs::read_to_string(folder.join(EVENTS_FILE)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "the torn line is ended, not swallowed: {text}");
        assert!(serde_json::from_str::<serde_json::Value>(lines[1]).is_ok(), "{text}");

        writer.delete_tree_sync().unwrap();
        assert!(append_event_checked(&writer, Event::FirstToken).is_err());
        assert!(!folder.exists(), "nothing recreated the deleted folder");
    }
}
