use super::*;

fn write_updates_jsonl(lines: &[String]) -> tempfile::NamedTempFile {
    use std::io::Write as _;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    for line in lines {
        writeln!(f, "{line}").unwrap();
    }
    f
}

fn acp_update(session_update_json: &str) -> String {
    format!(
        r#"{{"timestamp":1,"method":"session/update","params":{{"sessionId":"s","update":{session_update_json}}}}}"#
    )
}

fn fuigo_update(session_update_json: &str) -> String {
    format!(
        r#"{{"timestamp":1,"method":"_fuigo/session/update","params":{{"sessionId":"s","update":{session_update_json}}}}}"#
    )
}

#[test]
fn test_single_pass_extracts_user_prompts() {
    let lines = vec![
        acp_update(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"hello world"}}"#,
        ),
        acp_update(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hi there"}}"#,
        ),
    ];
    let f = write_updates_jsonl(&lines);
    let (content, _bytes) = collect_all_indexable_content_single_pass(f.path()).unwrap();
    assert!(
        content.contains("hello world"),
        "should contain user prompt"
    );
}

#[test]
fn test_single_pass_extracts_assistant_text() {
    let lines = vec![
        acp_update(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"assistant reply"}}"#,
        ),
        acp_update(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"next prompt"}}"#,
        ),
    ];
    let f = write_updates_jsonl(&lines);
    let (content, _bytes) = collect_all_indexable_content_single_pass(f.path()).unwrap();
    assert!(
        content.contains("assistant reply"),
        "should contain assistant text"
    );
}

#[test]
fn test_single_pass_extracts_tool_metadata() {
    let lines = vec![acp_update(
        r#"{"sessionUpdate":"tool_call","toolCallId":"tc1","title":"Read file","kind":"read","locations":[{"path":"/tmp/foo.rs"}]}"#,
    )];
    let f = write_updates_jsonl(&lines);
    let (content, _bytes) = collect_all_indexable_content_single_pass(f.path()).unwrap();
    assert!(content.contains("Read file"), "should contain tool title");
    assert!(
        content.contains("/tmp/foo.rs"),
        "should contain tool location path"
    );
}

#[test]
fn test_single_pass_extracts_text_with_json_escapes() {
    // Escaped JSON strings cannot be borrowed as &str; a regression to borrowed peek fields silently drops these messages from the index
    let lines = vec![
        acp_update(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"fix the bug\nin main.rs"}}"#,
        ),
        acp_update(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"use \"quotes\" and caf\u00e9"}}"#,
        ),
        acp_update(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"! echo \"hi\"","_meta":{"bash_command":"echo \"hi\""}}}"#,
        ),
        acp_update(
            r#"{"sessionUpdate":"tool_call","toolCallId":"tc1","title":"Run \"cargo test\"","kind":"execute","locations":[{"path":"/tmp/my\tdir/foo.rs"}]}"#,
        ),
    ];
    let f = write_updates_jsonl(&lines);
    let (content, _bytes) = collect_all_indexable_content_single_pass(f.path()).unwrap();
    assert!(
        content.contains("fix the bug\nin main.rs"),
        "multiline user prompt must be indexed: {content:?}"
    );
    assert!(
        content.contains("use \"quotes\" and caf\u{e9}"),
        "assistant text with escaped quotes and unicode escape must be indexed: {content:?}"
    );
    assert!(
        content.contains("Run \"cargo test\""),
        "tool title with escaped quotes must be indexed: {content:?}"
    );
    assert!(
        content.contains("/tmp/my\tdir/foo.rs"),
        "tool location path with escapes must be indexed: {content:?}"
    );
    assert!(
        !content.contains("echo \"hi\""),
        "escaped bash command must still be excluded from the index: {content:?}"
    );
}

#[test]
fn test_single_pass_handles_rewind() {
    let lines = vec![
        acp_update(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"first prompt"}}"#,
        ),
        acp_update(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"first reply"}}"#,
        ),
        acp_update(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"second prompt"}}"#,
        ),
        acp_update(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"second reply"}}"#,
        ),
        fuigo_update(
            r#"{"sessionUpdate":"rewind_marker","target_prompt_index":1,"created_at":"2024-01-01"}"#,
        ),
        acp_update(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"replacement prompt"}}"#,
        ),
        acp_update(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"replacement reply"}}"#,
        ),
    ];
    let f = write_updates_jsonl(&lines);
    let (content, _bytes) = collect_all_indexable_content_single_pass(f.path()).unwrap();
    assert!(
        content.contains("first prompt"),
        "first prompt should survive rewind"
    );
    assert!(
        !content.contains("second prompt"),
        "rewound prompt should be removed"
    );
    assert!(
        content.contains("replacement prompt"),
        "replacement prompt should be present"
    );
}

#[test]
fn test_single_pass_thought_chunk_does_not_flush_assistant() {
    let lines = vec![
        acp_update(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hello"}}"#,
        ),
        acp_update(
            r#"{"sessionUpdate":"agent_thought_chunk","content":{"type":"text","text":"thinking about stuff"}}"#,
        ),
        acp_update(
            r#"{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"world"}}"#,
        ),
        // A user message ends the assistant turn
        acp_update(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"thanks"}}"#,
        ),
    ];
    let f = write_updates_jsonl(&lines);
    let (content, _bytes) = collect_all_indexable_content_single_pass(f.path()).unwrap();
    assert!(
        content.contains("hello world"),
        "thought chunk should not flush assistant text: got {content:?}"
    );
}

#[test]
fn test_single_pass_empty_file() {
    let f = write_updates_jsonl(&[]);
    let (content, bytes) = collect_all_indexable_content_single_pass(f.path()).unwrap();
    assert!(content.is_empty() || content.trim().is_empty());
    assert_eq!(bytes, 0, "empty file should report 0 bytes read");
}

#[test]
fn test_single_pass_nonexistent_file() {
    let (content, bytes) =
        collect_all_indexable_content_single_pass(Path::new("/nonexistent/updates.jsonl")).unwrap();
    assert!(content.is_empty());
    assert_eq!(bytes, 0, "nonexistent file should report 0 bytes read");
}

#[test]
fn test_single_pass_assistant_text_cap() {
    // Two 60K chunks in the same turn: the 100K assistant cap should truncate the second chunk
    let big_text = "x".repeat(60_000);
    let lines = vec![
        acp_update(&format!(
            r#"{{"sessionUpdate":"agent_message_chunk","content":{{"type":"text","text":"{big_text}"}}}}"#
        )),
        acp_update(&format!(
            r#"{{"sessionUpdate":"agent_message_chunk","content":{{"type":"text","text":"{big_text}"}}}}"#
        )),
        // Flush the assistant turn
        acp_update(
            r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"q"}}"#,
        ),
    ];
    let f = write_updates_jsonl(&lines);
    let (content, _bytes) = collect_all_indexable_content_single_pass(f.path()).unwrap();
    // The assistant section is the only source of 'x'
    let x_count = content.chars().filter(|&c| c == 'x').count();
    assert!(
        x_count <= 100_000,
        "assistant text should be capped at 100K chars, got {x_count}"
    );
    assert!(
        x_count < 120_001,
        "without the cap this would be 120K, got {x_count}"
    );
    assert!(
        x_count > 50_000,
        "should have collected at least the first 60K chunk, got {x_count}"
    );
}

#[test]
fn test_single_pass_tool_call_count_cap() {
    // Generate 250 tool calls; only the first 200 should be indexed
    let lines: Vec<String> = (0..250)
        .map(|i| {
            acp_update(&format!(
                r#"{{"sessionUpdate":"tool_call","toolCallId":"tc{i}","title":"tool_{i}","kind":"exec","locations":[]}}"#
            ))
        })
        .collect();
    let f = write_updates_jsonl(&lines);
    let (content, _bytes) = collect_all_indexable_content_single_pass(f.path()).unwrap();
    assert!(
        !content.contains("tool_200"),
        "tool calls beyond 200 should be ignored"
    );
    assert!(
        !content.contains("tool_249"),
        "tool calls beyond 200 should be ignored"
    );
    assert!(content.contains("tool_0"), "first tool should be indexed");
    assert!(
        content.contains("tool_199"),
        "tool #200 (0-indexed) should be indexed"
    );
}

#[test]
fn test_single_pass_tool_chars_cap() {
    // Generate tool calls with long titles that exceed the 100K char budget
    let long_title = "a".repeat(20_000);
    let lines: Vec<String> = (0..10)
        .map(|i| {
            acp_update(&format!(
                r#"{{"sessionUpdate":"tool_call","toolCallId":"tc{i}","title":"{long_title}","kind":"exec","locations":[]}}"#
            ))
        })
        .collect();
    let f = write_updates_jsonl(&lines);
    let (content, _bytes) = collect_all_indexable_content_single_pass(f.path()).unwrap();
    let a_count = content.chars().filter(|&c| c == 'a').count();
    assert!(
        a_count <= 100_000,
        "tool metadata should be capped at 100K chars, got {a_count}"
    );
    assert!(
        a_count > 19_000,
        "should have collected at least one tool title, got {a_count}"
    );
}

#[test]
fn test_single_pass_reports_bytes_read() {
    let lines = vec![acp_update(
        r#"{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"hello"}}"#,
    )];
    let f = write_updates_jsonl(&lines);
    let file_size = std::fs::metadata(f.path()).unwrap().len();

    let (_content, bytes_read) = collect_all_indexable_content_single_pass(f.path()).unwrap();
    assert_eq!(
        bytes_read, file_size,
        "bytes_read should match the actual file size"
    );
    assert!(
        bytes_read > 0,
        "bytes_read should be non-zero for non-empty file"
    );
}

fn append_bytes(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    f.write_all(bytes).unwrap();
}

/// Full single pass over a copy, so neither the reference nor `path`'s cached state touches the other.
fn full_pass(path: &Path) -> String {
    let dir = tempfile::TempDir::new().unwrap();
    let copy = dir.path().join("copy.jsonl");
    std::fs::copy(path, &copy).unwrap();
    let content = collect_all_indexable_content_single_pass(&copy).unwrap().0;
    forget_cached_tail(&copy);
    content
}

fn user_pi(text: &str, prompt_index: usize) -> String {
    acp_update(&format!(
        r#"{{"sessionUpdate":"user_message_chunk","content":{{"type":"text","text":"{text}"}},"_meta":{{"promptIndex":{prompt_index}}}}}"#
    ))
}

fn agent(text: &str) -> String {
    acp_update(&format!(
        r#"{{"sessionUpdate":"agent_message_chunk","content":{{"type":"text","text":"{text}"}}}}"#
    ))
}

/// F3: extraction resumed from the cached prefix gives exactly the text of a full pass, through rewinds, tool calls,
/// invalid UTF-8, a record caught half-written, and a file that shrinks or is replaced.
#[test]
fn test_incremental_extraction_matches_full_pass() {
    let f = write_updates_jsonl(&[user_pi("first prompt", 0), agent("first reply")]);
    let path = f.path();
    forget_cached_tail(path);
    let incremental = |path: &Path| collect_all_indexable_content_single_pass(path).unwrap().0;
    // That read seeded the cache; every stage below resumes from the previous one
    assert_eq!(incremental(path), full_pass(path));

    let tool = acp_update(
        r#"{"sessionUpdate":"tool_call","toolCallId":"tc1","title":"Read file","kind":"read","locations":[{"path":"/tmp/foo.rs"}]}"#,
    );
    let rewind = fuigo_update(
        r#"{"sessionUpdate":"rewind_marker","target_prompt_index":1,"created_at":"2024-01-01"}"#,
    );
    let half = user_pi("half written prompt", 3);
    let stages: Vec<Vec<u8>> = vec![
        format!(
            "{}\n{}\n{tool}\n",
            user_pi("second prompt", 1),
            agent("second reply")
        )
        .into_bytes(),
        format!("{rewind}\n{}\n", user_pi("replacement prompt", 1)).into_bytes(),
        // A chunk split across reads continues the same user message
        format!("{}\n\n", user_pi("continued", 1)).into_bytes(),
        b"\xff\xfe not utf8\r\n".to_vec(),
        format!("{}\n", agent("after the bad line")).into_bytes(),
        half.as_bytes()[..half.len() / 2].to_vec(),
        format!("{}\n", &half[half.len() / 2..]).into_bytes(),
    ];
    for (i, stage) in stages.iter().enumerate() {
        append_bytes(path, stage);
        let got = incremental(path);
        let want = full_pass(path);
        assert_eq!(
            got, want,
            "stage {i}: incremental text differs from a full pass"
        );
    }
    let all = full_pass(path);
    assert!(all.contains("replacement prompt") && !all.contains("second prompt"));
    assert!(all.contains("half written prompt"));

    // Shrunk in place: the cached prefix no longer holds
    std::fs::write(path, format!("{}\n", user_pi("rewritten", 0))).unwrap();
    assert_eq!(incremental(path), full_pass(path));

    // Replaced by rename with a longer file: a new inode is a new file
    let dir = tempfile::TempDir::new().unwrap();
    let other = dir.path().join("u.jsonl");
    std::fs::write(
        &other,
        format!(
            "{}\n{}\n{}\n",
            user_pi("renamed in", 0),
            agent("x"),
            user_pi("more", 1)
        ),
    )
    .unwrap();
    std::fs::rename(&other, path).unwrap();
    assert_eq!(incremental(path), full_pass(path));
}

/// F3: once a transcript is cached, the next extraction reads only the appended bytes.
/// Proved by changing an early byte in place: the resumed text still has the old word, a full pass has the new one.
#[test]
fn test_incremental_extraction_reads_only_the_appended_tail() {
    let filler = agent(&"filler ".repeat(40));
    let f = write_updates_jsonl(&[user_pi("alpha prompt", 0), filler]);
    let path = f.path();
    forget_cached_tail(path);
    collect_all_indexable_content_single_pass(path).unwrap();

    let original = std::fs::read(path).unwrap();
    let at = original.windows(5).position(|w| w == b"alpha").unwrap();
    let mut edited = original.clone();
    edited[at..at + 5].copy_from_slice(b"omega");
    {
        use std::io::{Seek as _, Write as _};
        let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        file.seek(io::SeekFrom::Start(0)).unwrap();
        file.write_all(&edited).unwrap();
    }
    append_bytes(path, format!("{}\n", user_pi("bravo prompt", 1)).as_bytes());

    let (resumed, _) = collect_all_indexable_content_single_pass(path).unwrap();
    assert!(resumed.contains("alpha prompt") && resumed.contains("bravo prompt"));
    assert!(
        !resumed.contains("omega"),
        "the cached prefix must not be re-read"
    );
    forget_cached_tail(path);
    let full = collect_all_indexable_content_single_pass(path).unwrap().0;
    assert!(full.contains("omega prompt") && !full.contains("alpha"));
}

/// Measurement for F3 (run with `--ignored --nocapture`): a ~20 MB, 10k-turn transcript, full pass vs one appended turn.
#[test]
#[ignore = "measurement, not a gate"]
fn measure_incremental_extraction_10k_turns() {
    let reply = "r".repeat(1_900);
    let mut lines = Vec::new();
    for i in 0..10_000 {
        lines.push(user_pi(&format!("prompt {i}"), i));
        lines.push(agent(&reply));
    }
    let f = write_updates_jsonl(&lines);
    let path = f.path();
    let size = std::fs::metadata(path).unwrap().len();
    forget_cached_tail(path);
    let t = std::time::Instant::now();
    let full = collect_all_indexable_content_single_pass(path).unwrap().0;
    let full_time = t.elapsed();
    append_bytes(
        path,
        format!("{}\n{}\n", user_pi("prompt 10000", 10_000), agent(&reply)).as_bytes(),
    );
    let grown = std::fs::metadata(path).unwrap().len();
    let t = std::time::Instant::now();
    let resumed = collect_all_indexable_content_single_pass(path).unwrap().0;
    let tail_time = t.elapsed();
    assert_ne!(full, resumed);
    assert_eq!(resumed, full_pass(path));
    forget_cached_tail(path);
    println!(
        "F3 measure: file {size} B; full pass reads {size} B in {full_time:?}; after one turn the resumed pass reads {} B in {tail_time:?}",
        grown - size
    );
}
