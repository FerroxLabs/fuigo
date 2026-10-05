use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;
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
#[derive(Clone)]
pub struct EventWriter {
    inner: Arc<EventWriterInner>,
}

struct EventWriterInner {
    file: Mutex<Option<File>>,
    error_logged: AtomicBool,
}

/// Open the event log owner-only (P120): created 0600 on Unix, and tightened to 0600 when it already exists with a
/// looser mode. Windows keeps the inherited ACL (see below).
///
/// The tightening is best effort (P134): on a filesystem without Unix modes (vfat, exFAT, some FUSE and SMB mounts)
/// `fchmod` answers EPERM, ENOTSUP or EINVAL, and 1.0.20 wrote the log there. A refusal is logged once per process and
/// the log is still opened.
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
    pub fn open(session_dir: &Path) -> Self {
        let path = session_dir.join(EVENTS_FILE);
        let file = open_owner_only(std::fs::OpenOptions::new().create(true).append(true), &path)
            .map_err(|e| {
                tracing::warn!(path = %path.display(), error = %e, "failed to open {EVENTS_FILE}");
                e
            })
            .ok();
        Self {
            inner: Arc::new(EventWriterInner {
                file: Mutex::new(file),
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
        let entry = EventEntry {
            ts: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            event,
        };
        let Ok(line) = encode_line(&entry) else {
            return;
        };

        let Ok(mut guard) = self.inner.file.lock() else {
            return;
        };
        if let Some(ref mut f) = *guard
            && let Err(e) = f.write_all(&line)
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

/// Appends one event to `session_dir/events.jsonl` and reports whether it landed, for callers that must not assume it did.
/// A torn last line (a writer that died mid-line) would swallow the appended event into one unparseable line,
/// so a missing trailing newline is written first. The data is synced before this returns.
pub fn append_event_checked(session_dir: &Path, event: Event) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};

    let entry = EventEntry {
        ts: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        event,
    };
    let mut line = encode_line(&entry).map_err(std::io::Error::other)?;
    let mut file = open_owner_only(
        std::fs::OpenOptions::new().read(true).append(true).create(true),
        &session_dir.join(EVENTS_FILE),
    )?;
    let len = file.metadata()?.len();
    if len > 0 {
        file.seek(SeekFrom::Start(len - 1))?;
        let mut last = [0u8; 1];
        file.read_exact(&mut last)?;
        if last[0] != b'\n' {
            line.insert(0, b'\n');
        }
    }
    // Append mode: the write lands at the end whatever the read position.
    file.write_all(&line)?;
    file.sync_data()
}

impl std::fmt::Debug for EventWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventWriter").finish()
    }
}

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
        EventWriter::open(dir.path()).emit(Event::McpTransportDecodeError {
            server_name: "s".into(),
            error: format!("bad {KEY}"),
            sample: format!("printed {KEY}"),
        });
        append_event_checked(
            dir.path(),
            Event::TurnEnded {
                outcome: TurnOutcomeLabel::Completed,
                cancellation_category: None,
                cancellation_context: Some(serde_json::json!({"detail": [format!("x {KEY}")]})),
            },
        )
        .unwrap();
        append_event_checked(
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
        append_event_checked(
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
        let writer = EventWriter::open(dir.path());

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

        append_event_checked(
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
        append_event_checked(dir.path(), Event::FirstToken).unwrap();
        append_event_checked(dir.path(), Event::FirstToken).unwrap();
        let text = std::fs::read_to_string(dir.path().join("events.jsonl")).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.lines().all(|l| !l.is_empty()));
    }

    #[test]
    fn cloned_writer_shares_file() {
        let dir = tempfile::tempdir().unwrap();
        let w1 = EventWriter::open(dir.path());
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
        let writer = EventWriter::open(dir.path());
        writer.emit(event());
        assert_eq!(mode(), 0o600, "EventWriter::open tightens an existing file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        append_event_checked(dir.path(), event()).unwrap();
        assert_eq!(mode(), 0o600, "append_event_checked tightens an existing file");
        std::fs::remove_file(&path).unwrap();
        append_event_checked(dir.path(), event()).unwrap();
        assert_eq!(mode(), 0o600, "a new file is created owner-only");
    }
}
