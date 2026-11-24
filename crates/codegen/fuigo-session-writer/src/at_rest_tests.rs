//! 1.0.47 S2 (SL-06): every byte-taking method and hatch of the writer goes through the at-rest layer, and the
//! verbatim rewind store does not (design §2.2, test 3; Grok r2 #2; Fable r2 #2, #3, F#7).

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::Path;

use crate::SessionWriter;

/// A value recorded at rest for these tests only (split: no token-shaped literal in the source).
fn secret() -> String {
    let value = concat!("wr", "_live_S2Writer9KxQ").to_owned();
    fuigo_secrets::at_rest::record(&value);
    value
}

fn writer(tag: &str) -> (tempfile::TempDir, SessionWriter, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("dir");
    let id = format!("s2-{tag}-{}", std::process::id());
    let session = dir.path().join("sessions").join(&id);
    let w = SessionWriter::try_claim(&id, &session).expect("claim");
    (dir, w, session)
}

fn read(session: &Path, rel: &str) -> String {
    String::from_utf8(std::fs::read(session.join(rel)).expect("read")).expect("utf8")
}

#[test]
fn every_byte_method_scrubs_a_transcript_and_keeps_the_rewind_store() {
    let s = secret();
    let line = format!("{{\"out\":\"DEPLOY_TOKEN={s}\"}}\n");
    let (_d, w, session) = writer("methods");
    type Case<'a> = (&'a str, &'a dyn Fn(&str));
    let cases: [Case; 5] = [
        ("append", &|rel| {
            w.append_sync(rel, line.as_bytes()).expect("append")
        }),
        ("checked", &|rel| {
            w.append_line_checked_sync(rel, line.as_bytes())
                .expect("checked")
        }),
        ("replace", &|rel| {
            w.replace_atomic_sync(rel, line.as_bytes())
                .expect("replace")
        }),
        ("create", &|rel| {
            let _ = w.remove_sync(rel);
            w.create_new_sync(rel, line.as_bytes()).expect("create")
        }),
        ("hatch", &|rel| {
            w.with_append_file(rel, |file| file.write_all(line.as_bytes()))
                .expect("open")
                .expect("write")
        }),
    ];
    for (name, write) in cases {
        let rel = format!("{name}.jsonl");
        write(&rel);
        let text = read(&session, &rel);
        assert!(!text.contains(&s), "{name}: {text}");
        assert!(text.contains("<redacted>"), "{name}: {text}");
        serde_json::from_str::<serde_json::Value>(text.lines().last().expect("line"))
            .expect("json");
        let _ = w.remove_sync("rewind_points.jsonl");
        write("rewind_points.jsonl");
        assert!(
            read(&session, "rewind_points.jsonl").contains(&s),
            "{name}: the rewind store is verbatim"
        );
    }
}

#[test]
fn the_append_hatch_keeps_read_and_seek_for_the_torn_tail_check() {
    let s = secret();
    let (_d, w, session) = writer("hatch");
    w.append_sync("chat_history.jsonl", b"{\"a\":1}")
        .expect("seed torn");
    w.with_append_file("chat_history.jsonl", |file| -> std::io::Result<()> {
        let len = file.metadata()?.len();
        file.seek(SeekFrom::Start(len - 1))?;
        let mut last = [0u8; 1];
        file.read_exact(&mut last)?;
        assert_eq!(last[0], b'}');
        file.write_all(format!("\n{{\"b\":\"{s}\"}}\n").as_bytes())?;
        file.sync_all()
    })
    .expect("open")
    .expect("append");
    assert_eq!(
        read(&session, "chat_history.jsonl"),
        "{\"a\":1}\n{\"b\":\"<redacted>\"}\n"
    );
}

#[test]
fn copy_in_move_in_and_cross_class_rename_scrub_before_publishing() {
    let s = secret();
    let (dir, w, session) = writer("copy");
    let src = dir.path().join("outside.jsonl");
    std::fs::write(&src, format!("{{\"v\":\"{s}\"}}\n")).expect("src");
    w.copy_in_sync(&src, "fork/updates.jsonl").expect("copy_in");
    assert!(!read(&session, "fork/updates.jsonl").contains(&s));
    w.copy_in_sync(&src, "rewind_points.jsonl")
        .expect("copy_in verbatim");
    assert!(read(&session, "rewind_points.jsonl").contains(&s));
    w.move_in_sync(&src, "updates.jsonl").expect("move_in");
    assert!(!read(&session, "updates.jsonl").contains(&s));
    assert!(!src.exists(), "the staged source is removed");
    w.rename_sync("rewind_points.jsonl", "restored.jsonl")
        .expect("rename");
    assert!(!read(&session, "restored.jsonl").contains(&s));
    assert!(!session.join("rewind_points.jsonl").exists());
}

/// Astra code review round 2, High 2: an imported JSON lines file (and a JSON file) goes through the record-aware
/// edit: a value that spans JSON syntax withholds only its record, two recorded ids keep distinct placeholders, and
/// every line still parses, by copy and by move.
#[test]
fn an_imported_json_file_is_edited_record_by_record() {
    let (a, b) = (
        concat!("id", "_live_ImportA7xQ"),
        concat!("id", "_live_ImportB8yR"),
    );
    let fragment = concat!(r#""foo":"Imp"#, r#"ortC9zS""#);
    for value in [a, b, fragment] {
        fuigo_secrets::at_rest::record(value);
    }
    let (dir, w, session) = writer("import");
    let src = dir.path().join("legacy.jsonl");
    let lines = format!("{{\"id\":\"{a}\"}}\n{{\"id\":\"{b}\"}}\n{{{fragment}}}\n{{\"ok\":1}}\n");
    for (how, rel) in [("copy", "fork/updates.jsonl"), ("move", "updates.jsonl")] {
        std::fs::write(&src, &lines).expect("src");
        if how == "copy" {
            w.copy_in_sync(&src, rel).expect("copy_in");
        } else {
            w.move_in_sync(&src, rel).expect("move_in");
        }
        let out = read(&session, rel);
        let parsed: Vec<serde_json::Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{how}: {l}: {e}")))
            .collect();
        assert_eq!(parsed.len(), 4, "{how}: {out}");
        assert!(
            ![a, b, fragment].iter().any(|v| out.contains(v)),
            "{how}: {out}"
        );
        assert_ne!(
            parsed[0]["id"], parsed[1]["id"],
            "{how}: distinct ids stay distinct"
        );
        assert_eq!(
            parsed[2],
            serde_json::json!({"fuigo_withheld_at_rest": true}),
            "{how}"
        );
        assert_eq!(parsed[3], serde_json::json!({"ok": 1}), "{how}");
    }
    std::fs::write(&src, format!("{{\"id\":\"{a}\",\"n\":2}}")).expect("src");
    w.copy_in_sync(&src, "summary.json").expect("copy_in json");
    let summary: serde_json::Value =
        serde_json::from_str(&read(&session, "summary.json")).expect("parses");
    assert_eq!(summary["n"], 2);
    assert_ne!(summary["id"], a);
}

/// Astra code review round 3, High 3 and Fable's Medium: a copy or move of JSON lines still catches a value spanning
/// records (two valid JSON records; a multi-line value one of whose lines is JSON), withholding exactly the records it
/// touches; every line still parses.
#[test]
fn an_imported_value_spanning_records_withholds_them() {
    let spanning = concat!("{\"Gq4w\":\"Zr", "8kLm\"}\n{\"Hd2v\":\"Xs6pNa\"}");
    let multi = concat!("{\"Yb7c", "\":5}\n{\"Fe1u\":6}");
    for value in [spanning, multi] {
        fuigo_secrets::at_rest::record(value);
    }
    let (dir, w, session) = writer("spanning");
    let src = dir.path().join("legacy.jsonl");
    let lines = format!("{{\"ok\":0}}\n{spanning}\n{{\"ok\":1}}\n{multi}\n{{\"ok\":2}}\n");
    for (how, rel) in [("copy", "fork/updates.jsonl"), ("move", "updates.jsonl")] {
        std::fs::write(&src, &lines).expect("src");
        if how == "copy" {
            w.copy_in_sync(&src, rel).expect("copy_in");
        } else {
            w.move_in_sync(&src, rel).expect("move_in");
        }
        let out = read(&session, rel);
        assert!(
            !fuigo_secrets::at_rest::contains_any(out.as_bytes()),
            "{how}: {out}"
        );
        let parsed: Vec<serde_json::Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{how}: {l}: {e}")))
            .collect();
        let marker = serde_json::json!({"fuigo_withheld_at_rest": true});
        assert_eq!(parsed.len(), 7, "{how}: {out}");
        for (i, value) in parsed.iter().enumerate() {
            match i {
                0 | 3 | 6 => assert_eq!(value["ok"], i / 3, "{how}: {out}"),
                _ => assert_eq!(value, &marker, "{how}: {out}"),
            }
        }
    }
}

/// Sean's S2 decision (schema words): every copy path is record-aware by position. With a recorded value equal to a
/// schema word, a fork sidecar, a load-repair staging file (`*.jsonl.pre-repair.<id>.tmp`, named `.tmp`) and a file
/// whose name says nothing (sniffed by its first byte) keep the word only as a `type` label; a string value equal to it
/// is redacted, two recorded ids stay distinct, every line that parsed still parses, and a torn line is scrubbed as
/// text, never written raw. Fails on 41ccbcdf (stream copies) and on 0a24a59b for the repair and unnamed copies.
#[test]
fn copies_keep_schema_labels_and_scrub_values_by_position() {
    let word = "backend_tool_call";
    let (a, b) = (
        concat!("id", "_live_LabelA7xQ"),
        concat!("id", "_live_LabelB8yR"),
    );
    for value in [word, a, b] {
        fuigo_secrets::at_rest::record(value);
    }
    let src_lines = format!(
        "{{\"type\":\"{word}\",\"id\":\"{a}\",\"text\":\"{word}\"}}\n\
         {{\"type\":\"{word}\",\"id\":\"{b}\"}}\n\
         torn {{\"text\":\"{a} and {word}\n\
         {{\"type\":\"user\",\"text\":\"said {word}\"}}\n"
    );
    let (dir, w, session) = writer("labels");
    let src = dir.path().join("legacy");
    for rel in [
        "fork/chat_history.jsonl",
        "chat_history.jsonl.pre-repair.0191.tmp",
        "compaction_checkpoints/abc",
    ] {
        std::fs::write(&src, &src_lines).expect("src");
        w.copy_in_sync(&src, rel).expect("copy_in");
        let out = read(&session, rel);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4, "{rel}: {out}");
        let parsed: Vec<serde_json::Value> = [0, 1, 3]
            .iter()
            .map(|&i| {
                serde_json::from_str(lines[i])
                    .unwrap_or_else(|e| panic!("{rel}: {}: {e}", lines[i]))
            })
            .collect();
        assert_eq!(parsed[0]["type"], word, "{rel}: the label stays");
        assert_eq!(parsed[0]["text"], "<redacted>", "{rel}: the value goes");
        assert_eq!(parsed[1]["type"], word, "{rel}");
        assert_ne!(parsed[0]["id"], parsed[1]["id"], "{rel}: distinct ids");
        assert_eq!(parsed[2]["text"], "said <redacted>", "{rel}");
        assert!(
            !lines[2].contains(a) && !lines[2].contains(word),
            "{rel}: torn line: {}",
            lines[2]
        );
        for value in [a, b] {
            assert!(!out.contains(value), "{rel}: {out}");
        }
        assert_eq!(
            out.matches(word).count(),
            2,
            "{rel}: only the two labels: {out}"
        );
        assert!(
            std::fs::read_dir(session.join(Path::new(rel).parent().unwrap_or(Path::new(""))))
                .expect("dir")
                .all(|e| !e
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
                    || rel.ends_with(".tmp")),
            "{rel}: no temporary sibling left behind"
        );
    }
}

/// Astra N3: media (`images/`, `videos/`, `downloads/`) lands byte for byte through every path, a fork's copy included.
#[test]
fn media_is_written_byte_exact() {
    let s = secret();
    let mut bytes = b"\xff\xd8\xff\xe0JFIF\0".to_vec();
    bytes.extend_from_slice(format!("\"{s}\"").as_bytes());
    bytes.push(0xd9);
    let (dir, w, session) = writer("media");
    w.replace_atomic_sync("images/1.jpg", &bytes)
        .expect("replace");
    w.create_new_sync("videos/2.mp4", &bytes).expect("create");
    let src = dir.path().join("fetched.pdf");
    std::fs::write(&src, &bytes).expect("src");
    w.copy_in_sync(&src, "downloads/3.pdf").expect("copy_in");
    w.move_in_sync(&src, "images/4.jpg").expect("move_in");
    for rel in [
        "images/1.jpg",
        "videos/2.mp4",
        "downloads/3.pdf",
        "images/4.jpg",
    ] {
        assert_eq!(
            std::fs::read(session.join(rel)).expect("read"),
            bytes,
            "{rel}"
        );
    }
}

/// Fable S2 confirm review: media is chosen by content, not by path. Text written under `images/`, `videos/` or
/// `downloads/` (no image, video or PDF signature) goes through the layer on every path.
#[test]
fn text_under_a_media_folder_is_transformed() {
    let s = secret();
    let text = format!("DEPLOY_TOKEN={s}\n");
    let (dir, w, session) = writer("media-text");
    w.replace_atomic_sync("images/notes.txt", text.as_bytes())
        .expect("replace");
    w.create_new_sync("videos/notes.txt", text.as_bytes())
        .expect("create");
    w.append_sync("downloads/append.txt", text.as_bytes())
        .expect("append");
    let src = dir.path().join("fetched.txt");
    std::fs::write(&src, &text).expect("src");
    w.copy_in_sync(&src, "downloads/copied.txt")
        .expect("copy_in");
    w.move_in_sync(&src, "images/moved.txt").expect("move_in");
    for rel in [
        "images/notes.txt",
        "videos/notes.txt",
        "downloads/append.txt",
        "downloads/copied.txt",
        "images/moved.txt",
    ] {
        let written = read(&session, rel);
        assert!(!written.contains(&s), "{rel}: {written}");
        assert!(written.contains("<redacted>"), "{rel}: {written}");
    }
}

#[test]
fn a_hard_link_never_crosses_classes() {
    let (_d, w, _session) = writer("link");
    w.append_sync("rewind_points.jsonl", b"{}\n").expect("seed");
    assert!(
        w.hard_link_in_no_replace_sync("rewind_points.jsonl", "chat_history.jsonl.pre-repair")
            .is_err()
    );
    w.append_sync("staged.tmp", b"{}\n").expect("seed");
    w.hard_link_in_no_replace_sync("staged.tmp", "chat_history.jsonl.pre-repair")
        .expect("same class");
}

/// Fable code review #1: the sidecar is opened for writing (an exclusive `flock` on a Linux NFS home needs it), yet the
/// handle can only lock: it implements no `Write`, `Deref<Target = File>` or `AsRef<File>`.
#[test]
fn a_lock_handle_is_writable_underneath_and_exposes_no_write() {
    trait NotImplemented<A> {
        fn check() {}
    }
    impl<T: ?Sized> NotImplemented<()> for T {}
    struct ViaWrite;
    struct ViaDeref;
    struct ViaAsRef;
    impl<T: ?Sized + std::io::Write> NotImplemented<ViaWrite> for T {}
    impl<T: ?Sized + std::ops::Deref<Target = std::fs::File>> NotImplemented<ViaDeref> for T {}
    impl<T: ?Sized + AsRef<std::fs::File>> NotImplemented<ViaAsRef> for T {}
    // Ambiguous (a compile error) if any of the three impls applies.
    <crate::SessionLock as NotImplemented<_>>::check();
    <&crate::SessionLock as NotImplemented<_>>::check();

    let (_d, w, session) = writer("lock");
    let lock = w.open_lock("turn_owner.lock").expect("lock");
    assert!(session.join("turn_owner.lock").exists());
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        // SAFETY: F_GETFL on a descriptor this test owns for the call's duration.
        let flags = unsafe { libc::fcntl(lock.0.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(
            flags & libc::O_ACCMODE,
            libc::O_RDWR,
            "opened read and write"
        );
    }
    lock.lock_exclusive().expect("exclusive");
    let other = w.open_lock("turn_owner.lock").expect("reopen");
    assert!(
        other.try_lock_exclusive().is_err(),
        "held by the first handle"
    );
    lock.unlock().expect("unlock");
    other.try_lock_exclusive().expect("free again");
}

#[test]
fn a_stream_handle_finishes_and_never_grows() {
    let s = secret();
    let (_d, w, session) = writer("stream");
    let log = w.open_append_stream("terminal/call.log").expect("open");
    log.write_all(format!("DEPLOY_TOKEN={}", &s[..9]).as_bytes())
        .expect("half");
    log.write_all(format!("{}\nnext\n", &s[9..]).as_bytes())
        .expect("rest");
    log.write_all(&s.as_bytes()[..12]).expect("held");
    log.finish().expect("finish");
    let text = read(&session, "terminal/call.log");
    assert_eq!(text, "DEPLOY_TOKEN=<redacted>\nnext\n<redacted>");
    log.set_len(1 << 20).expect("set_len");
    assert_eq!(
        read(&session, "terminal/call.log").len(),
        text.len(),
        "set_len never grows"
    );
    log.set_len(4).expect("cut");
    assert_eq!(read(&session, "terminal/call.log"), "DEPL");
    let events = w.open_append("events.jsonl").expect("events");
    events
        .write_all(format!("{{\"e\":\"{s}\"}}\n").as_bytes())
        .expect("event");
    assert_eq!(read(&session, "events.jsonl"), "{\"e\":\"<redacted>\"}\n");
    drop(log);
}

#[test]
fn at_rest_bytes_is_what_lands() {
    let s = secret();
    let (_d, w, session) = writer("bytes");
    let line = format!("{{\"v\":\"{s}\"}}\n");
    w.replace_atomic_sync("chat_history.jsonl", line.as_bytes())
        .expect("write");
    assert_eq!(
        &*w.at_rest_bytes("chat_history.jsonl", line.as_bytes()),
        std::fs::read(session.join("chat_history.jsonl"))
            .expect("read")
            .as_slice()
    );
    assert_eq!(
        &*w.at_rest_bytes("rewind_points.jsonl", line.as_bytes()),
        line.as_bytes()
    );
}
