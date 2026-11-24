//! S2 at-rest layer tests (design §7 tests 1, 2, 4; Astra r2 A#9, A#10, N2; Fable r2 #4, #5, #7).

use super::*;
use crate::sent_credentials;

static LOCK: Mutex<()> = Mutex::new(());

/// The SL-06 canary value, split so the source holds no token-shaped literal.
fn canary() -> String {
    concat!("dpl_", "live_Q7x2Lm9VtR4kZp8N").to_owned()
}

fn fresh() -> std::sync::MutexGuard<'static, ()> {
    let guard = LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    clear_for_tests();
    guard
}

fn t(bytes: &[u8]) -> Vec<u8> {
    transform_whole(bytes).into_owned()
}

#[test]
fn the_value_floor_and_the_name_rule() {
    let _g = fresh();
    for word in ["postgres", "assistant", "12345678", "ABCDEFGHIJ", "short7!"] {
        assert!(!recordable(word), "{word} must not be recorded");
    }
    for value in [canary().as_str(), "Passw0rd!", "lowercase-but-sixteen-plus"] {
        assert!(recordable(value), "{value} must be recorded");
    }
    // Astra code review High 2: a schema word that meets the floor is recorded (the JSON edit protects the schema).
    for word in ["backend_tool_call", "sessionId", "toolCallId"] {
        assert!(recordable(word), "{word} meets the floor");
    }
    for name in [
        "DEPLOY_TOKEN",
        "deploy_token_file",
        "DB_PASSWORD",
        "MY_APIKEY",
        "GITHUB_ACCESS_KEY",
        "OPENAI_API_KEY",
    ] {
        assert!(is_secret_env_name(name), "{name}");
    }
    assert!(!is_secret_env_name("DEPLOY_REGION"));
}

/// Canary C (1.0.47): the launch policy path and hash are the session record's policy marker, so they are never
/// recorded; a redacted marker made every cold `session/load` after a restart a `session_policy_conflict`.
#[test]
fn the_launch_policy_path_and_hash_are_not_recorded() {
    let _g = fresh();
    for name in [
        "FUIGO_POLICY_PATH",
        "FUIGO_POLICY_SHA256",
        "fuigo_policy_sha256",
    ] {
        assert!(!is_secret_env_name(name), "{name}");
    }
}

/// Astra code review High 2: a value equal to a schema tag (and one inside a key) is replaced in ordinary text and in
/// string values, user text that is exactly the word included, while the structural tokens (keys, `type` tags) stay, so the record still loads; a non-schema key holding a value
/// still withholds its record.
#[test]
fn a_schema_word_value_is_redacted_everywhere_but_the_schema_tokens() {
    let _g = fresh();
    record("backend_tool_call");
    record("autoCompactThreshold");
    let line = br#"{"type":"backend_tool_call","autoCompactThresholdPercent":80,"text":"pw is backend_tool_call","note":"autoCompactThreshold"}"#;
    let out = String::from_utf8(t(line)).unwrap();
    assert_eq!(
        out,
        r#"{"type":"backend_tool_call","autoCompactThresholdPercent":80,"text":"pw is <redacted>","note":"<redacted>"}"#
    );
    // Round 2 High 1: user text that is exactly a schema word is not structural, so it is redacted.
    assert_eq!(
        String::from_utf8(t(br#"{"text":"backend_tool_call"}"#)).unwrap(),
        r#"{"text":"<redacted>"}"#
    );
    assert_eq!(
        t(b"plain text: backend_tool_call\n"),
        b"plain text: <redacted>\n"
    );
    let keyed = String::from_utf8(t(br#"{"my backend_tool_call key":1}"#)).unwrap();
    assert_eq!(keyed, WITHHELD_MARKER);
}

/// Sean's S2 decision: tags are kept by position for every serde tag key (`kind`, `tool_type`, not only `type`), and JSON
/// lines with a torn line are still edited record by record: each parsing line keeps its labels, the torn line is
/// scrubbed as text, nothing is written raw, and a schema word survives only in label positions.
#[test]
fn torn_json_lines_keep_labels_by_position_and_scrub_the_rest() {
    let _g = fresh();
    record("backend_tool_call");
    record(&canary());
    let c = canary();
    let kind =
        br#"{"kind":"backend_tool_call","tool_type":"backend_tool_call","q":"backend_tool_call"}"#;
    assert_eq!(
        String::from_utf8(t(kind)).unwrap(),
        r#"{"kind":"backend_tool_call","tool_type":"backend_tool_call","q":"<redacted>"}"#
    );
    let lines = format!(
        "{{\"type\":\"backend_tool_call\",\"text\":\"{c}\"}}\n{{\"text\":\"backend_tool_call {c}\n{{\"type\":\"user\",\"text\":\"backend_tool_call\"}}\n"
    );
    let out = String::from_utf8(t(lines.as_bytes())).unwrap();
    let got: Vec<&str> = out.lines().collect();
    assert_eq!(got.len(), 3, "{out}");
    assert_eq!(
        got[0],
        r#"{"type":"backend_tool_call","text":"<redacted>"}"#
    );
    assert!(
        !got[1].contains(&c) && !got[1].contains("backend_tool_call"),
        "{out}"
    );
    assert_eq!(got[2], r#"{"type":"user","text":"<redacted>"}"#);
}

#[test]
fn a_non_utf8_value_never_panics_and_its_text_runs_are_recorded() {
    let _g = fresh();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let mut raw = b"Abcdefgh1234".to_vec();
        raw.push(0xff);
        raw.extend_from_slice(b"Zyxwvut9876");
        record_os(OsStr::from_bytes(&raw));
        assert_eq!(t(b"x Abcdefgh1234 y"), b"x <redacted> y");
        // Astra code review High 3: short valid runs between invalid bytes; the value as text reads lossy.
        let short = b"Ab1c\xffDe2f\xfeGh3i";
        record_os(OsStr::from_bytes(short));
        let lossy = String::from_utf8_lossy(short).into_owned();
        assert_eq!(t(format!("v={lossy}.").as_bytes()), b"v=<redacted>.");
        // ... and its exact bytes, whole and written one byte at a time.
        let mut text = b"v=".to_vec();
        text.extend_from_slice(short);
        text.extend_from_slice(b".\n");
        assert_eq!(t(&text), b"v=<redacted>.\n");
        let mut stream = AtRestStream::new();
        let mut out = Vec::new();
        for byte in &text {
            stream.push(std::slice::from_ref(byte), &mut out);
        }
        stream.finish(&mut out);
        assert!(!out.windows(short.len()).any(|w| w == short), "{out:?}");
        assert!(out.ends_with(b"<redacted>.\n"), "{out:?}");
    }
}

#[test]
fn capture_records_secret_named_variables_only() {
    let _g = fresh();
    // SAFETY-free: set_var is unsafe in edition 2024; the test holds the module lock and uses unique names.
    unsafe {
        std::env::set_var("S2_TEST_DEPLOY_TOKEN_FILE", canary());
        std::env::set_var("S2_TEST_DEPLOY_REGION", "Region-Abc123");
    }
    capture_env();
    assert_eq!(t(canary().as_bytes()), PLACEHOLDER.as_bytes());
    assert_eq!(t(b"Region-Abc123"), b"Region-Abc123");
    unsafe {
        std::env::remove_var("S2_TEST_DEPLOY_TOKEN_FILE");
        std::env::remove_var("S2_TEST_DEPLOY_REGION");
    }
}

#[test]
fn a_sent_credential_stays_scrubbed_at_rest_after_display_eviction() {
    let _g = fresh();
    let _s = sent_credentials::REGISTRY_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    sent_credentials::record("sent-Key-9a8b7c6d");
    sent_credentials::clear_for_tests();
    assert!(sent_credentials::is_empty());
    assert_eq!(t(b"echo sent-Key-9a8b7c6d"), b"echo <redacted>");
}

#[test]
fn env_secrets_do_not_change_display_scrubbing() {
    let _g = fresh();
    let _s = sent_credentials::REGISTRY_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    sent_credentials::clear_for_tests();
    record(&canary());
    let line = format!("DEPLOY_TOKEN={}", canary());
    assert!(sent_credentials::scrub_bytes(line.as_bytes()).is_none());
    assert_eq!(
        crate::redact_secrets(&line),
        crate::redact_secrets(&line.clone())
    );
    assert!(sent_credentials::is_empty());
}

#[test]
fn json_is_edited_inside_strings_only() {
    let _g = fresh();
    record(&canary());
    let c = canary();
    let input = format!(
        "{{\"type\":\"tool_result\",\"n\":12, \"out\":\"DEPLOY_TOKEN={c}\\n\", \"nested\":{{\"k\":[\"{c}\"]}}}}\n{{\"b\":\"plain\"}}\n"
    );
    let out = String::from_utf8(t(input.as_bytes())).unwrap();
    assert_eq!(
        out,
        "{\"type\":\"tool_result\",\"n\":12, \"out\":\"DEPLOY_TOKEN=<redacted>\\n\", \"nested\":{\"k\":[\"<redacted>\"]}}\n{\"b\":\"plain\"}\n"
    );
    for line in out.lines() {
        serde_json::from_str::<serde_json::Value>(line).unwrap();
    }
}

#[test]
fn json_escaped_spellings_are_found_and_stay_valid() {
    let _g = fresh();
    let value = "q\"uo\\te-Abc123xyz";
    record(value);
    let doc =
        serde_json::json!({ "inner": serde_json::json!({ "v": value }).to_string(), "v": value })
            .to_string();
    let out = t(doc.as_bytes());
    serde_json::from_slice::<serde_json::Value>(&out).unwrap();
    assert!(!contains_any(&out), "{}", String::from_utf8_lossy(&out));
}

#[test]
fn a_match_that_begins_inside_an_escape_never_splits_it() {
    // Astra r2 N2: `nAbc1234` raw inside `"\nAbc1234"` starts on the `n` of `\n`.
    let _g = fresh();
    record("nAbc1234");
    let out = t(br#"{"a":"\nAbc1234","b":"nAbc1234"}"#);
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(!contains_any(&out), "{}", String::from_utf8_lossy(&out));
    assert!(parsed["a"].as_str().unwrap().contains(PLACEHOLDER));
}

#[test]
fn ids_get_distinct_stable_placeholders() {
    let _g = fresh();
    record("SecretOne-Aa1");
    record("SecretTwo-Bb2");
    let input = br#"{"tool_call_id":"SecretOne-Aa1","x":1}
{"tool_call_id":"SecretTwo-Bb2","x":2}
{"call_id":"SecretOne-Aa1","x":3}
"#;
    let out = String::from_utf8(t(input)).unwrap();
    let ids: Vec<String> = out
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v.as_object()
                .unwrap()
                .values()
                .next()
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_ne!(ids[0], ids[1], "two values, two ids");
    assert_eq!(ids[0], ids[2], "the same value pairs");
    assert!(ids[0].starts_with("<redacted-"));
}

#[test]
fn a_value_outside_a_string_withholds_the_record_never_raw() {
    let _g = fresh();
    record(&canary());
    let c = canary();
    let input = format!("{{\"{c}\":1}}\n{{\"ok\":\"kept\"}}\n");
    let out = String::from_utf8(t(input.as_bytes())).unwrap();
    assert_eq!(out, format!("{WITHHELD_MARKER}\n{{\"ok\":\"kept\"}}\n"));
}

#[test]
fn the_fallback_is_checked_too() {
    // Astra r2 A#9: a value equal to the marker's key.
    let _g = fresh();
    record("fuigo_withheld_at_rest");
    let out = t(b"{\"fuigo_withheld_at_rest\":true}\n");
    assert_eq!(out, b"{}\n");
    assert!(!contains_any(&out));
    record(WITHHELD);
    let text = t(format!("x {WITHHELD} y\n").as_bytes());
    assert!(!contains_any(&text));
}

#[test]
fn text_is_scrubbed_and_lines_are_kept() {
    let _g = fresh();
    record(&canary());
    let input = format!("a\nDEPLOY_TOKEN={}\nb\n", canary());
    assert_eq!(t(input.as_bytes()), b"a\nDEPLOY_TOKEN=<redacted>\nb\n");
    assert!(matches!(transform_whole(b"nothing here"), Cow::Borrowed(_)));
}

/// Every spelling of `value` that the index covers, for the split tests.
fn spellings(value: &str) -> Vec<Vec<u8>> {
    let json_once = serde_json::to_string(value).unwrap();
    let json_once = json_once[1..json_once.len() - 1].to_owned();
    let json_twice = serde_json::to_string(&json_once).unwrap();
    let json_twice = json_twice[1..json_twice.len() - 1].to_owned();
    let unicode: String = value
        .chars()
        .map(|c| format!("\\u{:04x}", c as u32))
        .collect();
    let pct_upper: String = value.bytes().map(|b| format!("%{b:02X}")).collect();
    let pct_lower: String = value.bytes().map(|b| format!("%{b:02x}")).collect();
    let plus = value.replace(' ', "+");
    let entry = Entry::new(value);
    let mut out: Vec<Vec<u8>> = vec![
        value.into(),
        json_once.into(),
        json_twice.into(),
        unicode.into(),
        pct_upper.into(),
        pct_lower.into(),
        plus.into(),
    ];
    out.extend(
        entry
            .spellings()
            .skip(1)
            .map(|s| s.text.as_bytes().to_vec()),
    );
    out
}

fn stream_all(chunks: &[&[u8]]) -> Vec<u8> {
    let mut stream = AtRestStream::new();
    let mut out = Vec::new();
    for chunk in chunks {
        stream.push(chunk, &mut out);
    }
    stream.finish(&mut out);
    out
}

#[test]
fn a_stream_split_at_every_offset_never_writes_a_value() {
    let _g = fresh();
    let value = "multi line\nVaLue-9 x";
    record(value);
    record(&canary());
    for v in [value.to_owned(), canary()] {
        for spelling in spellings(&v) {
            let mut text = b"before ".to_vec();
            text.extend_from_slice(&spelling);
            text.extend_from_slice(b" after\n");
            for cut in 0..=text.len() {
                let out = stream_all(&[&text[..cut], &text[cut..]]);
                assert!(
                    !contains_any(&out),
                    "cut {cut} of {:?}: {:?}",
                    String::from_utf8_lossy(&spelling),
                    String::from_utf8_lossy(&out)
                );
            }
        }
    }
}

#[test]
fn at_most_three_key_chars_land_before_the_placeholder() {
    let _g = fresh();
    let c = canary();
    record(&c);
    for cut in 1..c.len() {
        let mut stream = AtRestStream::new();
        let mut out = Vec::new();
        stream.push(&c.as_bytes()[..cut], &mut out);
        let raw = out.len();
        assert!(raw < HOLD_CHARS, "cut {cut}: {raw} raw bytes released");
        stream.push(&c.as_bytes()[cut..], &mut out);
        stream.finish(&mut out);
        assert!(!contains_any(&out));
    }
}

#[test]
fn ordinary_output_is_never_held() {
    let _g = fresh();
    record(&canary());
    let mut stream = AtRestStream::new();
    let mut out = Vec::new();
    for line in [
        "$ make\n",
        "compiling dpl\n",
        "100% done %20\n",
        "path\\to\\file\n",
    ] {
        out.clear();
        stream.push(line.as_bytes(), &mut out);
        assert_eq!(out, line.as_bytes());
        assert!(!stream.holding());
    }
}

#[test]
fn finish_keeps_the_context() {
    // Fable r2 #5: half a value, finish, the other half.
    let _g = fresh();
    let c = canary();
    record(&c);
    let mut stream = AtRestStream::new();
    let mut out = Vec::new();
    stream.push(&c.as_bytes()[..10], &mut out);
    stream.finish(&mut out);
    stream.push(&c.as_bytes()[10..], &mut out);
    stream.finish(&mut out);
    assert!(!contains_any(&out), "{}", String::from_utf8_lossy(&out));
    assert!(!String::from_utf8_lossy(&out).contains(&c[..8]));
}

/// Fable code review #2: an 80-byte value, finished after 60 bytes, whose rest arrives in three writes, lands as one
/// placeholder and nothing of its rest; a beginning that turns out not to continue releases what follows.
#[test]
fn a_mid_value_finish_never_writes_the_rest_raw() {
    let _g = fresh();
    let value: String = (0..80)
        .map(|i| char::from(b"aZ3kQ9mXr7Tp2Lw"[i % 15]))
        .collect();
    record(&value);
    let v = value.as_bytes();
    let mut stream = AtRestStream::new();
    let mut out = Vec::new();
    stream.push(b"key=", &mut out);
    stream.push(&v[..60], &mut out);
    stream.finish(&mut out);
    stream.push(&v[60..66], &mut out);
    stream.finish(&mut out);
    stream.push(&v[66..73], &mut out);
    let mut last = v[73..].to_vec();
    last.extend_from_slice(b" ok\n");
    stream.push(&last, &mut out);
    stream.finish(&mut out);
    let expected = format!("key={PLACEHOLDER} ok\n");
    assert_eq!(String::from_utf8_lossy(&out), expected);

    let mut stream = AtRestStream::new();
    let mut out = Vec::new();
    stream.push(&v[..20], &mut out);
    stream.finish(&mut out);
    stream.push(b"; done\n", &mut out);
    stream.finish(&mut out);
    assert_eq!(
        String::from_utf8_lossy(&out),
        format!("{PLACEHOLDER}; done\n")
    );
}

/// Astra code review High 1: a long value (raw, JSON-escaped multiline, percent-encoded) written one or three bytes at
/// a time, or in random small pieces, never reaches disk past its first three key characters (the design's
/// [`HOLD_CHARS`] allowance), though no single push sees it whole.
#[test]
fn a_long_value_in_small_writes_never_lands_whole() {
    let _g = fresh();
    let raw = format!("Ab1{}", "x".repeat(77));
    let multiline = format!("Mq7{}\n{}", "y".repeat(40), "z".repeat(40));
    record(&raw);
    record(&multiline);
    let escaped = serde_json::to_string(&multiline).unwrap();
    let percent = format!("%41%62%31{}", "x".repeat(77));
    for (name, written, secret) in [
        ("raw", raw.clone(), raw.clone()),
        ("multiline", escaped.clone(), "y".repeat(40)),
        ("percent", percent, "x".repeat(60)),
    ] {
        // Sizes 1 and 3, then random pieces of 1 to 7 bytes (size 0 below), with a fixed seed.
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        for size in [1, 3, 0, 0, 0] {
            let mut stream = AtRestStream::new();
            let mut out = Vec::new();
            let text = format!("out {written} end\n");
            let mut rest = text.as_bytes();
            while !rest.is_empty() {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let n = if size > 0 {
                    size
                } else {
                    1 + (seed >> 61) as usize
                };
                let (piece, tail) = rest.split_at(n.min(rest.len()));
                stream.push(piece, &mut out);
                rest = tail;
            }
            stream.finish(&mut out);
            let out = String::from_utf8_lossy(&out);
            assert!(!out.contains(&secret), "{name}/{size}: {out}");
            assert!(
                out.contains(PLACEHOLDER) && out.ends_with(" end\n"),
                "{name}/{size}: {out}"
            );
        }
    }
}

#[test]
fn drop_and_finish_never_write_held_bytes_raw() {
    let _g = fresh();
    let c = canary();
    record(&c);
    let mut sink = Vec::new();
    {
        let mut file = AtRestFile::stream(&mut sink);
        file.write_all(&c.as_bytes()[..12]).unwrap();
    }
    assert_eq!(sink, PLACEHOLDER.as_bytes());
}

#[test]
fn record_mode_transforms_each_write_as_a_record() {
    let _g = fresh();
    record(&canary());
    let mut sink = Vec::new();
    {
        let mut file = AtRestFile::records(&mut sink);
        writeln!(file, "{{\"msg\":\"{}\"}}", canary()).unwrap();
    }
    assert!(!contains_any(&sink));
}

/// Fable S2 confirm review: media is verbatim by its signature, not by its folder.
#[test]
fn media_is_verbatim_by_content_not_by_path() {
    use std::path::Path;
    let heads: [&[u8]; 8] = [
        b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR",
        b"\xff\xd8\xff\xe0\0\x10JFIF",
        b"GIF89a\x01\0",
        b"%PDF-1.7\n",
        b"RIFF\x24\0\0\0WEBPVP8 ",
        b"\0\0\0\x18ftypmp42",
        b"\0\0\0\x1cftypavif",
        b"\x1a\x45\xdf\xa3\x9f\x42\x86",
    ];
    for head in heads {
        assert_eq!(
            Verbatim::for_session_write(Path::new("images/1.jpg"), head),
            Some(Verbatim::Media),
            "{head:?}"
        );
    }
    for text in [
        &b"DEPLOY_TOKEN=x\n"[..],
        b"{\"a\":1}",
        b"",
        b"RIFF\0\0\0\0WAVE",
    ] {
        assert_eq!(
            Verbatim::for_session_write(Path::new("downloads/3.pdf"), text),
            None,
            "{text:?}"
        );
    }
    assert_eq!(
        Verbatim::for_session_write(Path::new("rewind_points.jsonl"), b"{}"),
        Some(Verbatim::RewindStore)
    );
    assert_eq!(
        Verbatim::for_session_write(Path::new("chat.jsonl"), b"%PDF-1.7"),
        None
    );
}

/// Fable S2 confirm review (Grok round-1 Medium 1): an id placeholder depends on the id alone, with no per-process
/// nonce, so the same id written by two processes gives the same placeholder. The expected string is fixed here, so a
/// process-dependent input would fail it.
#[test]
fn an_id_placeholder_is_the_same_in_every_process() {
    let one = id_placeholder(b"SecretOne-Aa1");
    assert_eq!(one, id_placeholder(b"SecretOne-Aa1"));
    assert_ne!(one, id_placeholder(b"SecretTwo-Bb2"));
    assert_eq!(one, "<redacted-7aedac2af15d>");
}

#[test]
fn verbatim_names_the_rewind_store_and_media_only() {
    use std::path::Path;
    assert_eq!(
        Verbatim::for_session_rel(Path::new("rewind_points.jsonl")),
        Some(Verbatim::RewindStore)
    );
    assert_eq!(
        Verbatim::for_session_rel(Path::new("chat_history.jsonl")),
        None
    );
    assert_eq!(Verbatim::for_session_rel(Path::new("terminal/x.log")), None);
    for media in ["images/1.jpg", "videos/2.mp4", "downloads/3.pdf"] {
        assert_eq!(
            Verbatim::for_session_rel(Path::new(media)),
            Some(Verbatim::Media),
            "{media}"
        );
    }
    assert_eq!(Verbatim::for_session_rel(Path::new("images")), None);
    assert_eq!(Verbatim::for_session_rel(Path::new("web_fetch/1.md")), None);
}

/// A value the differential test records: 8 to 23 chars from an alphabet with the characters that take escapes
/// (quote, backslash, slash, space, `+`, `%`, newline, non-ASCII), often sharing a head with the value before it.
fn differential_value(next: &mut impl FnMut() -> u64, before: Option<&str>) -> String {
    const CHARS: &[char] = &[
        'a', 'q', 'Z', 'K', '7', '0', '_', '-', '"', '\\', '/', ' ', '+', '%', '\n', 'é', '…', '=',
    ];
    loop {
        let mut value: String = match before {
            Some(b) if next().is_multiple_of(2) => {
                b.chars().take(4 + (next() % 6) as usize).collect()
            }
            _ => String::new(),
        };
        let len = 8 + (next() % 16) as usize;
        while value.chars().count() < len {
            value.push(CHARS[(next() % CHARS.len() as u64) as usize]);
        }
        if recordable(&value) {
            return value;
        }
    }
}

/// A text built from pieces of the recorded spellings (whole, cut off before a truncation mark, cut off, a tail,
/// percent-escaped, JSON-escaped once or twice) and noise rich in the bytes the matcher keys on.
fn differential_text(next: &mut impl FnMut() -> u64, spellings: &[String]) -> Vec<u8> {
    const NOISE: &[&[u8]] = &[
        b"%",
        b"\\",
        b"+",
        b" ",
        b"\n",
        b"\"",
        "…".as_bytes(),
        b"\xE2\x80",
        b"%2",
        b"\\u00",
        b"\\\\",
        b"{\"k\":\"",
        b"\"}",
        b"a",
        b"Z",
        b"7",
        b"/",
        b"=",
        b"<redacted>",
    ];
    let mut out = Vec::new();
    for _ in 0..1 + next() % 5 {
        let s = spellings[(next() % spellings.len() as u64) as usize].as_bytes();
        let cut = (next() % (s.len() as u64 + 1)) as usize;
        match next() % 9 {
            0 | 1 => out.extend_from_slice(s),
            2 => {
                out.extend_from_slice(&s[..cut]);
                out.extend_from_slice("…".as_bytes());
            }
            3 => out.extend_from_slice(&s[..cut]),
            4 => out.extend_from_slice(&s[cut..]),
            5 => {
                for &c in s {
                    match next() % 4 {
                        0 => out.extend(format!("%{c:02X}").bytes()),
                        1 => out.extend(format!("%{c:02x}").bytes()),
                        2 if c == b' ' => out.push(b'+'),
                        _ => out.push(c),
                    }
                }
            }
            level => {
                let slash = if level == 8 { "\\\\" } else { "\\" };
                for &c in s {
                    if c.is_ascii() && next().is_multiple_of(3) {
                        out.extend(format!("{slash}u{:04x}", c).bytes());
                    } else {
                        out.push(c);
                    }
                }
            }
        }
        for _ in 0..next() % 4 {
            out.extend_from_slice(NOISE[(next() % NOISE.len() as u64) as usize]);
        }
    }
    out
}

/// Everything the at-rest layer writes for `text`, and every match the index reports for it in order: whole, as a
/// stream split in two at every offset, and in random small pieces.
fn differential_outputs(snap: &Snapshot, text: &[u8], pieces: &[usize]) -> Vec<Vec<u8>> {
    let mut outs = Vec::new();
    let mut seq = Vec::new();
    snap.index.for_each_match(text, true, &mut |start, end| {
        seq.extend(format!("{start}-{end},").bytes());
        true
    });
    outs.push(seq);
    outs.push(transform_whole(text).into_owned());
    let mut stream = |chunks: &mut dyn Iterator<Item = &[u8]>| {
        let mut st = AtRestStream::new();
        for chunk in chunks {
            let mut out = Vec::new();
            st.push(chunk, &mut out);
            outs.push(out);
        }
        let mut out = Vec::new();
        st.finish(&mut out);
        outs.push(out);
    };
    for cut in 0..=text.len() {
        stream(&mut [&text[..cut], &text[cut..]].into_iter());
    }
    let mut rest = text;
    stream(&mut pieces.iter().map_while(|&n| {
        let (head, tail) = rest.split_at(n.min(rest.len()));
        rest = tail;
        (!head.is_empty()).then_some(head)
    }));
    outs
}

/// S2 test 11: the prefilter (aho-corasick heads, memmem marks, memchr3 view triggers) changes nothing. The
/// byte-at-a-time matcher and the prefiltered one give byte-identical output (the 4-char hold, the live suffix,
/// decoded views, escape atoms, the match order) over generated texts, each whole, at every two-way split offset and
/// in random pieces. 1,000 texts in the suite; set `AT_REST_DIFFERENTIAL_TEXTS` for a longer run.
#[test]
fn the_prefilter_changes_no_output() {
    let _g = fresh();
    let texts: usize = std::env::var("AT_REST_DIFFERENTIAL_TEXTS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(1_000);
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let (mut done, mut streams, mut dfa_sets) = (0, 0, 0);
    while done < texts {
        clear_for_tests();
        let mut before: Option<String> = None;
        // Past 64 needle heads they are scanned in groups of 64 (20 to 31 values) or, past eight groups, by one DFA (130
        // to 149 values), not by one packed SIMD searcher (Fable S2 confirm review #1); neither may change any output.
        let count = match next() % 8 {
            0 => 130 + next() % 20,
            1 | 2 => 20 + next() % 12,
            _ => 1 + next() % 5,
        };
        for _ in 0..count {
            let value = differential_value(&mut next, before.as_deref());
            record(&value);
            before = Some(value);
        }
        let snap = snapshot().expect("recorded");
        dfa_sets += usize::from(snap.index.heads_dfa());
        let spellings: Vec<String> = snap.cut.iter().map(|s| s.text.to_owned()).collect();
        for _ in 0..50.min(texts - done) {
            let text = differential_text(&mut next, &spellings);
            let pieces: Vec<usize> = (0..text.len()).map(|_| 1 + (next() % 7) as usize).collect();
            sent_credentials::PREFILTER_OFF.with(|off| off.set(true));
            let old = differential_outputs(&snap, &text, &pieces);
            sent_credentials::PREFILTER_OFF.with(|off| off.set(false));
            let new = differential_outputs(&snap, &text, &pieces);
            assert!(
                old == new,
                "the prefilter changed the output for {:?} (values {spellings:?})",
                String::from_utf8_lossy(&text)
            );
            streams += text.len() + 2;
            done += 1;
        }
    }
    assert!(dfa_sets > 0, "no set reached the grouped heads path");
    eprintln!(
        "prefilter differential: {done} texts, {streams} streams, {dfa_sets} sets past one packed searcher, 0 differences"
    );
}

/// Astra code review round 3, High 1 (Sean's decision): a recorded schema word stays only in a label position of
/// Fuigo's own record (its top-level keys, a top-level tag, a tag at a known nested path). The same word in nested user
/// JSON (a tool argument or result object, an MCP payload), as a `type` value or inside a key, is scrubbed.
#[test]
fn schema_words_stay_only_in_the_records_own_label_positions() {
    let _g = fresh();
    record("backend_tool_call");
    let own =
        br#"{"type":"backend_tool_call","kind":{"tool_type":"backend_tool_call","id":"ws_1"}}"#;
    assert_eq!(
        t(own),
        own.to_vec(),
        "Fuigo's own discriminators are labels"
    );
    let record: serde_json::Value = serde_json::from_slice(&t(own)).unwrap();
    assert_eq!(record["type"], "backend_tool_call");
    assert_eq!(record["kind"]["tool_type"], "backend_tool_call");

    for nested in [
        r#"{"type":"assistant","tool_calls":[{"arguments":{"type":"backend_tool_call"}}]}"#,
        r#"{"type":"tool_result","content":{"type":"backend_tool_call","kind":"backend_tool_call"}}"#,
        r#"{"type":"tool_result","result":[{"type":"backend_tool_call"}]}"#,
    ] {
        let out = String::from_utf8(t(nested.as_bytes())).unwrap();
        assert_eq!(out.matches("backend_tool_call").count(), 0, "{out}");
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_ne!(parsed["type"], "backend_tool_call", "{out}");
        assert!(out.contains(PLACEHOLDER), "{out}");
    }

    // A recorded value inside a key of user JSON is scrubbed and the record still loads; a top-level key that is not
    // exactly a schema word still withholds its record.
    let keyed =
        br#"{"type":"tool_result","result":{"backend_tool_call":1,"a backend_tool_call b":2}}"#;
    let out = String::from_utf8(t(keyed)).unwrap();
    assert!(!out.contains("backend_tool_call"), "{out}");
    assert!(
        serde_json::from_str::<serde_json::Value>(&out).is_ok(),
        "{out}"
    );
    assert_eq!(
        String::from_utf8(t(br#"{"a backend_tool_call b":1}"#)).unwrap(),
        WITHHELD_MARKER
    );

    // The final-bytes postcondition holds per position too: on mixed lines a nested tag is not exempt.
    let mixed =
        b"{\"type\":\"backend_tool_call\"}\n{\"args\":{\"type\":\"backend_tool_call\"}}\ntorn {\n";
    let out = String::from_utf8(t(mixed)).unwrap();
    assert_eq!(out.matches("backend_tool_call").count(), 1, "{out}");
    assert!(out.starts_with(r#"{"type":"backend_tool_call"}"#), "{out}");
}

/// Fable round-3 Medium: an `updates.jsonl` notification tag (`params.update.sessionUpdate`) is a label; the same key
/// at any other nesting (user JSON) is scrubbed like any string.
#[test]
fn session_update_tag_is_a_label_only_at_its_notification_path() {
    let _g = fresh();
    record("auto_compact_started");
    let own = br#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s1","update":{"sessionUpdate":"auto_compact_started","reason":"r"}}}"#;
    assert_eq!(t(own), own.to_vec(), "the notification tag is a label");
    for nested in [
        r#"{"type":"tool_result","result":{"update":{"sessionUpdate":"auto_compact_started"}}}"#,
        r#"{"params":{"sessionUpdate":"auto_compact_started"}}"#,
    ] {
        let out = String::from_utf8(t(nested.as_bytes())).unwrap();
        assert!(!out.contains("auto_compact_started"), "{out}");
        assert!(
            serde_json::from_str::<serde_json::Value>(&out).is_ok(),
            "{out}"
        );
    }
}

/// `out` with every percent escape and JSON `\u` escape (surrogate pairs included) decoded: an oracle that does not
/// rely on the matcher's own views.
fn decoded(out: &[u8]) -> String {
    let mut bytes = Vec::new();
    let mut i = 0;
    while i < out.len() {
        if out[i] == b'%'
            && let Some(b) = out
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok())
        {
            bytes.push(b);
            i += 3;
        } else {
            bytes.push(out[i]);
            i += 1;
        }
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let (mut units, mut result, mut rest) = (Vec::new(), String::new(), text.as_str());
    let flush = |units: &mut Vec<u16>, result: &mut String| {
        result.push_str(&String::from_utf16_lossy(units));
        units.clear();
    };
    while let Some(at) = rest.find("\\u") {
        let hex = rest
            .get(at + 2..at + 6)
            .and_then(|h| u16::from_str_radix(h, 16).ok());
        match hex {
            Some(unit) => {
                if at > 0 {
                    flush(&mut units, &mut result);
                    result.push_str(&rest[..at]);
                }
                units.push(unit);
                rest = &rest[at + 6..];
            }
            None => {
                flush(&mut units, &mut result);
                result.push_str(&rest[..at + 2]);
                rest = &rest[at + 2..];
            }
        }
    }
    flush(&mut units, &mut result);
    result.push_str(rest);
    result
}

/// Astra code review round 3, High 2: a `finish` releases a short held beginning raw, but the stream keeps that
/// beginning's whole source span, so a value encoded long (percent-encoded emoji, JSON surrogate pairs) whose rest
/// arrives after the finish is still caught. A finish at every boundary of the encoding.
#[test]
fn a_finish_inside_an_encoded_value_keeps_its_whole_span() {
    let _g = fresh();
    let value = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}\u{1F604}\u{1F605}Aa";
    assert!(recordable(value));
    record(value);
    let percent: String = value.bytes().map(|b| format!("%{b:02X}")).collect();
    let surrogates: String = value
        .encode_utf16()
        .map(|u| format!("\\u{u:04x}"))
        .collect();
    assert!(decoded(percent.as_bytes()).contains(value));
    assert!(decoded(surrogates.as_bytes()).contains(value));
    for encoded in [&percent, &surrogates] {
        let encoded = encoded.as_bytes();
        for cut in 1..encoded.len() {
            let mut stream = AtRestStream::new();
            let mut out = Vec::new();
            stream.push(b"log: ", &mut out);
            stream.push(&encoded[..cut], &mut out);
            stream.finish(&mut out);
            stream.push(&encoded[cut..], &mut out);
            stream.push(b" done\n", &mut out);
            stream.finish(&mut out);
            assert!(
                !decoded(&out).contains(value) && !contains_any(&out),
                "finish after {cut} bytes: {}",
                String::from_utf8_lossy(&out)
            );
        }
    }
}

/// Astra code review round 3, High 3 and Fable's Medium: JSON lines copied record by record still catch a value
/// spanning records: two valid JSON records, a JSON record and a text line, and a multi-line value one of whose lines
/// is itself JSON. Every record it touches is withheld, the others stay, and every JSON line still parses; also when
/// the match sits past the publish window or a settled batch, between filler records.
#[test]
fn copied_json_lines_catch_a_value_spanning_records() {
    let _g = fresh();
    let two_records = "{\"Kx9q\":\"Vw4zR1\"}\n{\"Ty7m\":\"Pb2nQ8\"}";
    let json_text = "Jh5sLc\"}\nMr8dWq";
    let multi = "-----Q7kz\n{\"Nf3p\":1}\n";
    for v in [two_records, json_text, multi] {
        record(v);
    }
    let filler = "{\"type\":\"user\",\"text\":\"filler line for the window\"}\n".repeat(400);
    let cases: [(String, usize); 3] = [
        (format!("{two_records}\n{{\"after\":1}}\n"), 2),
        (
            format!("{{\"m\":\"hi {json_text} rest\n{{\"after\":1}}\n"),
            2,
        ),
        (format!("intro\n{multi}{{\"after\":1}}\n"), 2),
    ];
    // Past one settled batch too: the match lands in a later batch, checked with the window before it.
    let big = filler.repeat(50);
    for (body, gone) in cases {
        for source in [
            body.clone(),
            format!("{filler}{body}{filler}"),
            format!("{big}{body}{big}"),
        ] {
            let mut lines = AtRestLines::new();
            let mut out = Vec::new();
            for line in source.as_bytes().split_inclusive(|&c| c == b'\n') {
                lines.push(line, &mut out).unwrap();
            }
            lines.finish(&mut out).unwrap();
            let text = String::from_utf8(out.clone()).unwrap();
            assert!(!contains_any(&out), "{text}");
            assert_eq!(text.lines().count(), source.lines().count(), "{text}");
            let withheld = text
                .lines()
                .filter(|l| *l == WITHHELD_MARKER || *l == WITHHELD)
                .count();
            assert_eq!(withheld, gone, "{text}");
            assert!(text.contains("\n{\"after\":1}\n"), "{text}");
            assert_eq!(
                text.matches("filler line").count(),
                source.matches("filler line").count()
            );
        }
    }
}
