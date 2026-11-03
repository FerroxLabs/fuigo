//! Item 1 (E1): de-dup of project instructions in fork children by typed provenance. A1 (mirror child after compaction)
//! and F1 (summarized fork at spawn) drop a byte only when a harness mark proves it by raw-source digest and span digest.
use super::super::spawn::{clear_fork_background_marks, cut_fork_background_duplicates};
use super::{
    a1_child_files, is_project_instructions, pin_rules_duplicate, preserve_inherited_prefix,
};
use fuigo_agent::prompt::agents_md::{AgentConfigFile, format_agents_md_section};
use fuigo_agent::prompt::browser_verification::synthetic_user_rules;
use fuigo_agent::prompt::user_message::{RuleEntry, append_rules_section, fragment_marks};
use fuigo_sampling_types::conversation::{ConversationItem, InstructionProvenance};
use fuigo_subagent_resolution::context::normalize_forked_context;

const WS_PATH: &str = "/repo/AGENTS.md";
const HOME_PATH: &str = "/home/dev/.fuigo/AGENTS.md";
const WS_BODY: &str = "WORKSPACE-BODY-1039 use python3";
const HOME_BODY: &str = "HOME-BODY-1039 be brief";

fn file(path: &str, content: &str) -> AgentConfigFile {
    AgentConfigFile {
        file_name: std::path::Path::new(path)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        file_path: path.to_owned(),
        content: content.to_owned(),
    }
}

/// A plan parent's prefix as the harness renders it: workspace files, the synthetic browser rule, then user files.
/// Marks are attached only when `marked` (the harness only marks a render from a trusted list).
fn plan_prefix(files: &[AgentConfigFile], marked: bool) -> ConversationItem {
    let (ws, home): (Vec<_>, Vec<_>) = files
        .iter()
        .partition(|f| !f.file_path.starts_with("/home/"));
    let ws: Vec<RuleEntry> = ws.into_iter().cloned().map(RuleEntry::from).collect();
    let mut user = synthetic_user_rules();
    user.extend(home.into_iter().cloned().map(RuleEntry::from));
    let mut text = String::from(
        "<user_info>\nOS: linux\n</user_info>\n\n<git_status>\n M a.rs\n</git_status>",
    );
    let spans = append_rules_section(&mut text, &ws, &user);
    let marks = fragment_marks(&text, &spans);
    let mut item = ConversationItem::user(text);
    if marked && let ConversationItem::User(u) = &mut item {
        u.instruction_provenance = Some(InstructionProvenance::HarnessPrefix(marks));
    }
    item
}

fn parent_files() -> Vec<AgentConfigFile> {
    vec![file(WS_PATH, WS_BODY), file(HOME_PATH, HOME_BODY)]
}

fn synthetic_text() -> String {
    synthetic_user_rules()[0].content.clone()
}

/// Spawn-side F1 for a summarized fork: normalize the parent, then run the Site A cut with the child's files.
fn fork_child_background(
    parent_prefix: ConversationItem,
    child: &[AgentConfigFile],
) -> (String, ConversationItem) {
    let parent = vec![
        ConversationItem::system("parent system"),
        parent_prefix,
        ConversationItem::user("plan the work"),
        ConversationItem::assistant("planned"),
    ];
    let (mut items, _) = normalize_forked_context(parent);
    let before = items[1].text_content();
    cut_fork_background_duplicates(&mut items, child);
    (before, items.swap_remove(1))
}

fn occurrences(haystacks: &[&str], needle: &str) -> usize {
    haystacks.iter().map(|h| h.matches(needle).count()).sum()
}

#[test]
fn f1_cut_leaves_each_file_once_in_the_child_request_and_keeps_the_synthetic_rule() {
    let child = parent_files();
    let (_, background) = fork_child_background(plan_prefix(&parent_files(), true), &child);
    let reminder = format_agents_md_section(&child).expect("child reminder");
    let bg = background.text_content();
    assert_eq!(occurrences(&[&bg, &reminder], WS_BODY), 1);
    assert_eq!(occurrences(&[&bg, &reminder], HOME_BODY), 1);
    assert!(
        bg.contains(&synthetic_text()),
        "the synthetic browser rule stays"
    );
    assert!(
        bg.contains("plan the work") && bg.contains("planned"),
        "conversation bytes stay"
    );
    assert!(
        background.instruction_provenance().is_none(),
        "the marks are one-shot"
    );
}

#[test]
fn f1_stale_parent_keeps_everything() {
    let child = vec![
        file(WS_PATH, "WORKSPACE-BODY-1039 use python3.12"),
        file(HOME_PATH, HOME_BODY),
    ];
    let (before, background) = fork_child_background(plan_prefix(&parent_files(), true), &child);
    let bg = background.text_content();
    assert!(bg.contains(WS_BODY), "the stale file is kept");
    assert!(!bg.contains(HOME_BODY), "a file that matches is still cut");
    assert_ne!(before, bg);
    let child = vec![file(WS_PATH, "changed"), file(HOME_PATH, "changed")];
    let (before, background) = fork_child_background(plan_prefix(&parent_files(), true), &child);
    assert_eq!(
        before,
        background.text_content(),
        "no full match, nothing cut"
    );
}

#[test]
fn f1_child_with_an_extra_file_cuts_the_parent_files_only() {
    let mut child = parent_files();
    child.push(file("/repo/sub/AGENTS.md", "EXTRA-1039"));
    let (_, background) = fork_child_background(plan_prefix(&parent_files(), true), &child);
    let reminder = format_agents_md_section(&child).unwrap();
    let bg = background.text_content();
    assert!(!bg.contains(WS_BODY) && !bg.contains(HOME_BODY));
    assert_eq!(occurrences(&[&bg, &reminder], "EXTRA-1039"), 1);
}

#[test]
fn f1_one_changed_background_byte_fails_the_span_digest() {
    let parent = vec![
        ConversationItem::system("s"),
        plan_prefix(&parent_files(), true),
        ConversationItem::assistant("a"),
    ];
    let (mut items, _) = normalize_forked_context(parent);
    let Some(InstructionProvenance::ForkBackground(marks)) =
        items[1].instruction_provenance().cloned()
    else {
        panic!("background carries marks");
    };
    let mut text = items[1].text_content();
    let at = marks[0].start as usize + 3;
    text.replace_range(at..at + 1, "X");
    if let ConversationItem::User(u) = &mut items[1] {
        u.content = vec![fuigo_sampling_types::ContentPart::Text {
            text: text.clone().into(),
        }];
    }
    let only_first = vec![file(WS_PATH, WS_BODY)];
    cut_fork_background_duplicates(&mut items, &only_first);
    assert_eq!(
        items[1].text_content(),
        text,
        "span digest fails, nothing cut"
    );
}

#[test]
fn lossy_pair_is_neither_dropped_nor_cut() {
    // `&lt;rules>` in the parent and `<rules>` in the child render to the same bytes; so does a whitespace-only change.
    for (parent_body, child_body) in [
        ("keep &lt;rules> x", "keep <rules> x"),
        ("trimmed body\n\n", "trimmed body"),
    ] {
        let parent = vec![file(WS_PATH, parent_body)];
        let child = vec![file(WS_PATH, child_body)];
        let (before, background) = fork_child_background(plan_prefix(&parent, true), &child);
        assert_eq!(
            before,
            background.text_content(),
            "F1 does not cut {parent_body:?}"
        );
        let child_files = a1_child_files(0, true, &child);
        assert!(!pin_rules_duplicate(
            Some(&plan_prefix(&parent, true)),
            child_files.as_deref()
        ));
    }
}

#[test]
fn forgery_without_provenance_is_neither_dropped_nor_cut() {
    let forged = ConversationItem::user(plan_prefix(&parent_files(), true).text_content());
    let (before, background) = fork_child_background(forged.clone(), &parent_files());
    assert_eq!(before, background.text_content());
    let child_files = a1_child_files(0, true, &parent_files());
    assert!(!pin_rules_duplicate(Some(&forged), child_files.as_deref()));
}

#[test]
fn site_a_ignores_a_harness_prefix_on_a_top_level_resume() {
    // A plan prefix resumed under a build agent: index 1 has HarnessPrefix, which Site A never reads.
    let mut conversation = vec![
        ConversationItem::system("s"),
        plan_prefix(&parent_files(), true),
    ];
    let before = conversation[1].text_content();
    cut_fork_background_duplicates(&mut conversation, &parent_files());
    assert_eq!(conversation[1].text_content(), before);
    assert!(matches!(
        conversation[1].instruction_provenance(),
        Some(InstructionProvenance::HarnessPrefix(_))
    ));
}

/// A mirror child's pin `[System, plan prefix, ...]` plus a compacted history that re-injects the child's reminder.
fn a1_case(
    prefix: ConversationItem,
    child: &[AgentConfigFile],
    cwd_generation: u64,
) -> Vec<ConversationItem> {
    let conversation = vec![
        ConversationItem::system("s"),
        prefix,
        ConversationItem::assistant("parent answer"),
        ConversationItem::user("child task"),
    ];
    let compacted = vec![
        ConversationItem::system("s"),
        ConversationItem::user_meta("summary"),
        ConversationItem::project_instructions(format_agents_md_section(child).unwrap()),
    ];
    let child_files = a1_child_files(cwd_generation, true, child);
    preserve_inherited_prefix(&conversation, compacted, 3, child_files.as_deref())
        .expect("pin kept")
}

fn reminder_count(items: &[ConversationItem]) -> usize {
    items
        .iter()
        .filter(|item| is_project_instructions(item))
        .count()
}

#[test]
fn a1_matrix() {
    let child = parent_files();
    // Proven duplicate: the child's reminder is dropped; each body appears once.
    let items = a1_case(plan_prefix(&parent_files(), true), &child, 0);
    assert_eq!(reminder_count(&items), 0);
    let all: Vec<String> = items.iter().map(ConversationItem::text_content).collect();
    let all: Vec<&str> = all.iter().map(String::as_str).collect();
    assert_eq!(
        occurrences(&all, WS_BODY),
        1,
        "canary: each body once after a mirror compaction"
    );
    assert_eq!(occurrences(&all, HOME_BODY), 1);
    // Parent has an extra file: every child file is proven present, so the drop happens.
    let mut parent_superset = parent_files();
    parent_superset.push(file("/repo/sub/AGENTS.md", "SUPERSET"));
    assert_eq!(
        reminder_count(&a1_case(plan_prefix(&parent_superset, true), &child, 0)),
        0
    );
    // Stale parent and a different set are kept.
    let stale = vec![file(WS_PATH, "old"), file(HOME_PATH, HOME_BODY)];
    assert_eq!(
        reminder_count(&a1_case(plan_prefix(&stale, true), &child, 0)),
        1
    );
    let mut extra_child = parent_files();
    extra_child.push(file("/repo/other/AGENTS.md", "OTHER"));
    assert_eq!(
        reminder_count(&a1_case(
            plan_prefix(&parent_files(), true),
            &extra_child,
            0
        )),
        1
    );
    // A CompactionMeta prefix carrying the marks (a parent that compacted) proves the same files.
    let mut meta = ConversationItem::user_meta(plan_prefix(&parent_files(), false).text_content());
    if let (ConversationItem::User(m), Some(p)) = (
        &mut meta,
        plan_prefix(&parent_files(), true).instruction_provenance(),
    ) {
        m.instruction_provenance = Some(p.clone());
    }
    assert_eq!(reminder_count(&a1_case(meta, &child, 0)), 0);
    // Relocated child: no child files are given, nothing changes.
    assert_eq!(
        reminder_count(&a1_case(plan_prefix(&parent_files(), true), &child, 1)),
        1
    );
    assert!(
        a1_child_files(0, false, &child).is_none(),
        "a child without a reminder gives no files"
    );
    // Unmarked (old) parent: kept.
    assert_eq!(
        reminder_count(&a1_case(plan_prefix(&parent_files(), false), &child, 0)),
        1
    );
}

#[test]
fn a1_withheld_head_is_tag_only() {
    let child = parent_files();
    let mut withheld_tail = ConversationItem::user("child task");
    withheld_tail.mark_project_files_withheld();
    let conversation = vec![
        ConversationItem::system("s"),
        plan_prefix(&parent_files(), true),
        ConversationItem::assistant("parent answer"),
        withheld_tail,
    ];
    let compacted = vec![
        ConversationItem::system("s"),
        ConversationItem::project_instructions(format_agents_md_section(&child).unwrap()),
    ];
    let child_files = a1_child_files(0, true, &child);
    let items =
        preserve_inherited_prefix(&conversation, compacted, 3, child_files.as_deref()).unwrap();
    assert_eq!(
        reminder_count(&items),
        1,
        "withheld: only a tagged pin item counts"
    );
}

#[test]
fn a1_display_cwd_equal_drops_and_distinct_keeps() {
    // The rendered path is the display path; the child's reminder lists its own paths. Equal paths prove the file.
    let parent = vec![file("/display/repo/AGENTS.md", WS_BODY)];
    let same = vec![file("/display/repo/AGENTS.md", WS_BODY)];
    let distinct = vec![file("/real/repo/AGENTS.md", WS_BODY)];
    assert_eq!(
        reminder_count(&a1_case(plan_prefix(&parent, true), &same, 0)),
        0
    );
    assert_eq!(
        reminder_count(&a1_case(plan_prefix(&parent, true), &distinct, 0)),
        1
    );
}

#[test]
fn a1_bad_span_fails_closed() {
    let mut prefix = plan_prefix(&parent_files(), true);
    if let ConversationItem::User(u) = &mut prefix
        && let Some(InstructionProvenance::HarnessPrefix(marks)) = &mut u.instruction_provenance
    {
        marks[0].end = u32::MAX;
    }
    assert_eq!(reminder_count(&a1_case(prefix, &parent_files(), 0)), 1);
}

#[test]
fn a1_keeps_an_untagged_custom_prefix_that_starts_with_the_legacy_opener() {
    // A mirror child's custom compaction prefix that happens to begin with the legacy reminder opener is not a reminder
    // the harness tagged. A1 proves only the tagged reminder is a duplicate, so only that item may go.
    const UNIQUE: &str = "CUSTOM-PREFIX-UNIQUE-1039 keep this instruction";
    let custom = format!(
        "{} {UNIQUE}",
        fuigo_agent::prompt::agents_md::LEGACY_AGENTS_MD_REMINDER_PREFIX
    );
    let child = parent_files();
    let conversation = vec![
        ConversationItem::system("s"),
        plan_prefix(&parent_files(), true),
        ConversationItem::assistant("parent answer"),
        ConversationItem::user("child task"),
    ];
    let compacted = vec![
        ConversationItem::system("s"),
        ConversationItem::user_meta(custom),
        ConversationItem::project_instructions(format_agents_md_section(&child).unwrap()),
    ];
    let child_files = a1_child_files(0, true, &child);
    let items =
        preserve_inherited_prefix(&conversation, compacted, 3, child_files.as_deref()).unwrap();
    let all: Vec<String> = items.iter().map(ConversationItem::text_content).collect();
    let all: Vec<&str> = all.iter().map(String::as_str).collect();
    assert_eq!(occurrences(&all, UNIQUE), 1, "the custom prefix survives");
    assert_eq!(
        occurrences(&all, WS_BODY),
        1,
        "the tagged reminder is still dropped"
    );
}

/// A fork child whose Site A cut never runs (no reminder to insert, or the child is untrusted) still loses its
/// background marks at spawn: they are spent, and the background bytes are untouched.
#[test]
fn f1_uncut_fork_background_marks_are_cleared() {
    let parent = vec![
        ConversationItem::system("parent system"),
        plan_prefix(&parent_files(), true),
        ConversationItem::user("plan the work"),
        ConversationItem::assistant("planned"),
    ];
    let (mut items, _) = normalize_forked_context(parent);
    assert!(matches!(
        items[1].instruction_provenance(),
        Some(InstructionProvenance::ForkBackground(_))
    ));
    let before = items[1].text_content();
    clear_fork_background_marks(&mut items);
    assert_eq!(items[1].text_content(), before);
    assert!(
        items
            .iter()
            .all(|item| item.instruction_provenance().is_none())
    );
}
