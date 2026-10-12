//! Model-facing reads of the stored conversation.
//!
//! Peer state markers (five kinds) are persisted state and must never reach a model. Every reader whose result can reach a
//! model reads through `ChatStateHandle::get_conversation_for_model()`. The four readers here are the ones with a test that
//! builds their input from a history holding every marker kind; the rest call the accessor in place. The source pin at the
//! bottom fails when a new raw `get_conversation()` appears anywhere else in this crate.

use fuigo_chat_state::ChatStateHandle;
use fuigo_sampling_types::ConversationItem;

use super::acp_session::{
    LAZINESS_CONTEXT_ITEM_LIMIT, LAZINESS_MIN_ASSISTANT_TURNS, LAZINESS_MIN_USER_TURNS, laziness_window_start,
};

/// The laziness classifier's source items: the model-facing history trimmed to its context window.
pub(crate) async fn laziness_source_items(handle: &ChatStateHandle) -> Vec<ConversationItem> {
    let mut source_items = handle.get_conversation_for_model().await;
    let window_start = laziness_window_start(
        &source_items,
        LAZINESS_CONTEXT_ITEM_LIMIT,
        LAZINESS_MIN_USER_TURNS,
        LAZINESS_MIN_ASSISTANT_TURNS,
    );
    if window_start > 0 {
        source_items.drain(0..window_start);
    }
    source_items
}

/// The whole-conversation title refresh input.
pub(crate) async fn title_refresh_conversation(handle: &ChatStateHandle) -> Vec<ConversationItem> {
    handle.get_conversation_for_model().await
}

/// The turn summary input (the model sees this history plus the instruction).
pub(crate) async fn turn_summary_conversation(handle: &ChatStateHandle) -> Vec<ConversationItem> {
    handle.get_conversation_for_model().await
}

/// The goal evaluator's bounded transcript.
pub(crate) async fn goal_transcript(handle: &ChatStateHandle) -> String {
    super::goal_evaluator::bounded_goal_transcript(&handle.get_conversation_for_model().await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuigo_sampling_types::PeerCarriedState;

    fn marker_history() -> Vec<ConversationItem> {
        let carried = PeerCarriedState {
            carried: vec![("bash".into(), "sha256:ab".into(), "m1".into())],
            refused: vec!["lane a".into()],
        };
        vec![
            ConversationItem::system("sys"),
            ConversationItem::user("<user_query>\nwork on it\n</user_query>"),
            ConversationItem::peer_influence_marker(true),
            ConversationItem::assistant("first answer"),
            ConversationItem::peer_integrity_tripped_marker(),
            ConversationItem::peer_denial_marker("edit", "sha256:cd", 100),
            ConversationItem::peer_carried_denials_marker(&carried),
            ConversationItem::peer_influence_marker(false),
            ConversationItem::user("<user_query>\nnext thing\n</user_query>"),
            ConversationItem::assistant("second answer"),
        ]
    }

    fn handle_with(items: Vec<ConversationItem>) -> ChatStateHandle {
        let handle = crate::session::acp_session::support::spawn_test_chat_state(
            200_000,
            Box::new(fuigo_chat_state::NullChatPersistence),
        );
        handle.replace_conversation(items);
        handle
    }

    fn has_marker(items: &[ConversationItem]) -> bool {
        items.iter().any(|i| i.is_peer_influence_marker() || i.text_content().contains("[state marker"))
    }

    #[test]
    fn the_fixture_holds_all_five_marker_kinds() {
        assert_eq!(marker_history().iter().filter(|i| i.is_peer_influence_marker()).count(), 5);
    }

    #[tokio::test]
    async fn laziness_classifier_input_holds_no_marker() {
        let items = laziness_source_items(&handle_with(marker_history())).await;
        assert!(!has_marker(&items), "markers reached the laziness classifier input");
        let text = crate::session::acp_session::flatten_transcript_for_classifier(&items, true);
        assert!(!text.contains("[state marker") && text.contains("second answer"));
    }

    #[tokio::test]
    async fn title_refresh_input_holds_no_marker() {
        let items = title_refresh_conversation(&handle_with(marker_history())).await;
        assert!(!has_marker(&items), "markers reached the title refresh input");
        assert!(items.iter().any(|i| i.text_content().contains("second answer")));
    }

    #[tokio::test]
    async fn turn_summary_input_holds_no_marker() {
        let items = turn_summary_conversation(&handle_with(marker_history())).await;
        assert!(!has_marker(&items), "markers reached the turn summary input");
        assert!(super::super::helpers::turn_summary::last_user_anchor(&items).is_some());
    }

    #[tokio::test]
    async fn goal_transcript_holds_no_marker() {
        let text = goal_transcript(&handle_with(marker_history())).await;
        assert!(!text.contains("[state marker"), "markers reached the goal transcript: {text}");
        assert!(text.contains("second answer"));
    }

    /// A history with no marker comes out unchanged and in order, on every path (the filter is a no-op for it).
    #[tokio::test]
    async fn a_history_without_markers_is_returned_unchanged_in_order() {
        let plain: Vec<ConversationItem> =
            marker_history().into_iter().filter(|i| !i.is_peer_influence_marker()).collect();
        let handle = handle_with(plain.clone());
        let json = |v: &[ConversationItem]| serde_json::to_value(v).expect("serialize");
        let want = json(&plain);
        assert_eq!(json(&handle.get_conversation_for_model().await), want);
        assert_eq!(json(&title_refresh_conversation(&handle).await), want);
        assert_eq!(json(&turn_summary_conversation(&handle).await), want);
        assert_eq!(json(&laziness_source_items(&handle).await), want);
    }

    // ---- source pin -------------------------------------------------------------------------------------------------

    /// Every non-test file of this crate allowed to call the RAW `get_conversation()`: (file under `src`, count, why the site must
    /// see the markers). Everything else that can reach a model uses `get_conversation_for_model()`.
    const RAW_READ_ALLOW: &[(&str, usize, &str)] = &[
        ("session/compaction.rs", 3, "prefire/two-pass indices and fingerprint align with the raw history; inputs go through prepare_conversation_*, which drop markers"),
        ("session/acp_session_impl/goal.rs", 1, "read-modify-replace of the stored history (removes old goal directives); markers must survive"),
        ("session/acp_session_impl/model_switch.rs", 4, "read-modify-replace of the stored history, persistence snapshot, and a variant-presence predicate"),
        ("session/acp_session_impl/rewind.rs", 2, "rewind/replay rewrites the stored history; the other is a user-turn count"),
        ("session/acp_session_impl/turn.rs", 2, "memory-context presence predicate and read-modify-replace of the stored history"),
        ("session/acp_session_impl/read_dedupe_hook.rs", 1, "tool-result presence check, nothing leaves the process"),
        ("session/acp_session_impl/session_mode.rs", 1, "read-modify-replace of the stored system head"),
        ("session/acp_session_impl/session_setup.rs", 1, "read-modify-replace of the stored history at setup"),
    ];

    const RAW_READ: &str = "get_conversation()";

    /// The non-test text of a source file: comment lines dropped, and every inline `#[cfg(test)] mod x {` body (up to its closing
    /// `}` at column 0) skipped. `mod x;` file modules are separate files, found by name in `collect`.
    fn non_test_code(src: &str) -> String {
        let lines: Vec<&str> = src.lines().collect();
        let mut out = String::new();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            if line.starts_with("#[cfg(test)]")
                && lines.get(i + 1).is_some_and(|n| n.starts_with("mod ") && n.trim_end().ends_with('{'))
            {
                i += 2;
                while i < lines.len() && lines[i] != "}" {
                    i += 1;
                }
                i += 1;
                continue;
            }
            if !line.trim_start().starts_with("//") {
                out.push_str(line);
                out.push('\n');
            }
            i += 1;
        }
        out
    }

    /// Violations for `files` (path under `src`, content) against `allow`.
    fn pin_violations(files: &[(String, String)], allow: &[(&str, usize, &str)]) -> Vec<String> {
        let mut out = Vec::new();
        for (path, content) in files {
            let n = non_test_code(content).matches(RAW_READ).count();
            let allowed = allow.iter().find(|(p, _, _)| p == path).map(|(_, c, _)| *c).unwrap_or(0);
            if n != allowed {
                out.push(format!(
                    "{path}: {n} raw `get_conversation()` call(s), the allow-list says {allowed}. A raw read hands persisted peer \
                     state markers to whoever uses it: if the result can reach a model use `get_conversation_for_model()`; if the \
                     site is state logic that must see the markers, add it to RAW_READ_ALLOW with a reason."
                ));
            }
        }
        for (p, c, reason) in allow {
            assert!(!reason.is_empty(), "allow-list entry {p} needs a reason");
            if *c > 0 && !files.iter().any(|(path, _)| path == p) {
                out.push(format!("{p}: allow-listed but the file does not exist"));
            }
        }
        out
    }

    fn collect(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_owned();
            if path.is_dir() {
                if name != "tests" && name != "acp_session_tests" {
                    collect(&path, root, out);
                }
            } else if name.ends_with(".rs") && !name.ends_with("tests.rs") && name != "tests.rs" {
                let rel = path.strip_prefix(root).expect("under root").to_string_lossy().replace('\\', "/");
                out.push((rel, std::fs::read_to_string(&path).expect("read")));
            }
        }
    }

    #[test]
    fn no_raw_conversation_read_outside_the_allow_list() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect(&root, &root, &mut files);
        assert!(files.len() > 100, "scan found only {} files", files.len());
        let me = "session/model_facing_reads.rs";
        files.retain(|(p, _)| p != me);
        let violations = pin_violations(&files, RAW_READ_ALLOW);
        assert!(violations.is_empty(), "{}", violations.join("\n"));
    }

    /// The pin works: planted sources trip it, a matching allow-list entry clears it, test code and comments are ignored.
    #[test]
    fn the_pin_catches_a_planted_raw_read() {
        let planted = "async fn f(h: &H) { let c = h.get_conversation().await; }\n";
        let files = vec![("session/new_site.rs".to_owned(), planted.to_owned())];
        let v = pin_violations(&files, &[]);
        assert_eq!(v.len(), 1);
        assert!(v[0].contains("get_conversation_for_model()") && v[0].contains("RAW_READ_ALLOW"));
        assert!(pin_violations(&files, &[("session/new_site.rs", 1, "state logic")]).is_empty());
        // One more than allowed trips it.
        let two = vec![("a.rs".to_owned(), format!("{planted}{planted}"))];
        assert_eq!(pin_violations(&two, &[("a.rs", 1, "r")]).len(), 1);
        // Comments and test modules do not count; a stale entry does.
        let quiet = "// h.get_conversation()\n#[cfg(test)]\nmod tests {\n    fn t(h:&H){ h.get_conversation(); }\n}\n";
        assert!(pin_violations(&[("q.rs".to_owned(), quiet.to_owned())], &[]).is_empty());
        assert_eq!(pin_violations(&[], &[("gone.rs", 1, "r")]).len(), 1);
        // A test module in the middle of a file hides only its own body, not a raw read after it.
        let mid = "#[cfg(test)]\nmod t {\n    fn a(h:&H){ h.get_conversation(); }\n}\nfn b(h:&H){ h.get_conversation(); }\n";
        assert_eq!(pin_violations(&[("m.rs".to_owned(), mid.to_owned())], &[]).len(), 1);
    }
}
