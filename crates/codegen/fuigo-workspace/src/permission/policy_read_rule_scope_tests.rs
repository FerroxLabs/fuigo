//! u36 item c: a `Read` rule, bare or path-scoped, reaches every tool that reads file content or a listing, and never the
//! session's own bookkeeping ([`AccessKind::Session`]: to-dos, skills, plan mode, questions). Only an `any` rule reaches
//! bookkeeping, exactly as before. A tool whose handler opens a path or returns a path, listing or file bytes is a path-less
//! `Read`, never bookkeeping. Every `ToolInput` variant is enumerated so a new one cannot fall out of Read coverage.

use std::collections::BTreeSet;

use fuigo_tools::implementations::fuigo_build::peer_tools::{
    ListAgentsInput, PeerToolInput, RefusePeerMessageInput, SendMessageInput,
};
use fuigo_tools::types::ToolInput;

use crate::permission::policy::CompiledPolicy;
use crate::permission::rules::parse_permission_rule;
use crate::permission::types::{
    AccessKind, Decision, PatternMode, PermissionConfig, PermissionRule, RuleAction, ToolFilter,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// Reads file content or a listing: every `Read` deny/ask reaches it.
    FileRead,
    /// Session bookkeeping: no `Read` rule reaches it, an `any` rule does, and it stays auto-allowed.
    Bookkeeping,
    /// Anything else (edits, commands, web, side effects): never classified as a read or as bookkeeping.
    Other,
}

/// The match is exhaustive with no catch-all: a new `ToolInput` variant does not compile until it is listed here, and
/// listing it puts it in `ALL_VARIANTS`, which the coverage test requires a fixture for.
macro_rules! tool_input_variants {
    ($($variant:ident),* $(,)?) => {
        const ALL_VARIANTS: &[&str] = &[$(stringify!($variant)),*];
        fn variant_name(input: &ToolInput) -> &'static str {
            match input {
                $(ToolInput::$variant(..) => stringify!($variant),)*
            }
        }
    };
}

tool_input_variants!(
    ReadFile, SearchReplace, Bash, Grep, ListDir, TodoWrite, Skill, MCPTool, TaskOutput, WaitTasks, KillTask, Task,
    WebSearch, ImageGen, ImageEdit, ImageToVideo, ReferenceToVideo, WebFetch, Write, ApplyPatch, HashlineEdit,
    CodexListDir, CodexGrepFiles, CodexReadFile, MemorySearch, MemoryGet, SearchTool, UseTool, EnterPlanMode,
    ExitPlanMode, AskUserQuestion, SendSubagentMessage, Lsp, Monitor, SchedulerCreate, SchedulerDelete, SchedulerList,
    UpdateGoal, Workflow, Peer, Dynamic,
);

fn wire(label: &str, value: serde_json::Value) -> ToolInput {
    serde_json::from_value(value.clone()).unwrap_or_else(|e| panic!("{label} fixture must parse: {e}: {value}"))
}

/// One or more fixtures per `ToolInput` variant, labelled and with the coverage a `Read` rule must give it.
fn fixtures() -> Vec<(&'static str, Expect, ToolInput)> {
    use Expect::{Bookkeeping, FileRead, Other};
    use serde_json::json;
    let mut out: Vec<(&'static str, Expect, ToolInput)> = [
        ("read_file", FileRead, json!({"variant": "ReadFile", "target_file": "/w/src/a.rs"})),
        ("read_file files", FileRead, json!({"variant": "ReadFile", "files": [{"path": "/w/src/a.rs"}]})),
        ("list_dir", FileRead, json!({"variant": "ListDir", "target_directory": "/w/src"})),
        ("grep", FileRead, json!({"variant": "Grep", "pattern": "fn main", "path": "/w/src"})),
        ("grep no path", FileRead, json!({"variant": "Grep", "pattern": "fn main"})),
        ("codex read_file", FileRead, json!({"variant": "CodexReadFile", "file_path": "/w/.env"})),
        ("codex read_file no path", FileRead, json!({"variant": "CodexReadFile"})),
        ("codex list_dir", FileRead, json!({"variant": "CodexListDir", "dir_path": "/w/secrets"})),
        ("codex grep_files", FileRead, json!({"variant": "CodexGrepFiles", "pattern": "key", "path": "/w"})),
        ("memory_get", FileRead, json!({"variant": "MemoryGet", "path": "notes.md"})),
        ("lsp", FileRead, json!({"variant": "Lsp", "operation": "hover", "file_path": "/w/src/main.rs"})),
        ("lsp workspace", FileRead, json!({"variant": "Lsp", "operation": "workspaceSymbol", "query": "main"})),
        (
            "workflow validate script_path",
            FileRead,
            json!({"variant": "Workflow", "source": {"type": "script_path", "script_path": "/w/flow.rhai"}, "validate_only": true}),
        ),
        ("todo_write", Bookkeeping, json!({"variant": "TodoWrite", "todos": []})),
        ("skill", FileRead, json!({"variant": "Skill", "skill": "create-workflow"})),
        ("task_output", FileRead, json!({"variant": "TaskOutput", "task_ids": ["t1"]})),
        ("wait_tasks", FileRead, json!({"variant": "WaitTasks", "task_ids": ["t1"], "mode": "wait_any"})),
        ("kill_task", FileRead, json!({"variant": "KillTask", "task_id": "t1"})),
        ("memory_search", FileRead, json!({"variant": "MemorySearch", "query": "notes"})),
        ("search_tool", Bookkeeping, json!({"variant": "SearchTool", "query": "deploy"})),
        ("scheduler_list", Bookkeeping, json!({"variant": "SchedulerList"})),
        ("enter_plan_mode", FileRead, json!({"variant": "EnterPlanMode"})),
        ("exit_plan_mode", FileRead, json!({"variant": "ExitPlanMode"})),
        (
            "ask_user_question",
            Bookkeeping,
            json!({"variant": "AskUserQuestion", "questions": [{"question": "Which?", "options": [{"label": "a", "description": "A"}]}]}),
        ),
        ("update_goal", FileRead, json!({"variant": "UpdateGoal", "message": "progress"})),
        (
            "workflow validate name",
            FileRead,
            json!({"variant": "Workflow", "source": {"type": "name", "name": "ship"}, "validate_only": true}),
        ),
        (
            "workflow validate script",
            FileRead,
            json!({"variant": "Workflow", "source": {"type": "script", "script": "let meta = #{ name: \"x\", description: \"y\" };"}, "validate_only": true}),
        ),
        ("search_replace", Other, json!({"variant": "SearchReplace", "file_path": "/w/a.rs", "old_string": "a", "new_string": "b"})),
        ("bash", Other, json!({"variant": "Bash", "command": "cat /w/a.rs", "description": "read"})),
        ("mcp", Other, json!({"variant": "MCPTool", "tool_name": "fs_read", "tool_input": {}})),
        ("task", Other, json!({"variant": "Task", "prompt": "p", "description": "d"})),
        ("web_search", Other, json!({"variant": "WebSearch", "query": "rust"})),
        ("web_fetch", Other, json!({"variant": "WebFetch", "url": "https://example.com"})),
        ("write", Other, json!({"variant": "Write", "file_path": "/w/a.rs", "content": "x"})),
        ("apply_patch", Other, json!({"variant": "ApplyPatch", "patch": "*** Begin Patch\n*** End Patch"})),
        ("hashline_edit", Other, json!({"variant": "HashlineEdit", "file_path": "/w/a.rs", "edits": []})),
        ("use_tool", Other, json!({"variant": "UseTool", "tool_name": "t", "tool_input": {}})),
        ("send_subagent_message", Other, json!({"variant": "SendSubagentMessage", "subagent_id": "s1", "text": "hi"})),
        ("monitor", Other, json!({"variant": "Monitor", "command": "tail -f log", "description": "watch"})),
        ("workflow launch", Other, json!({"variant": "Workflow", "source": {"type": "name", "name": "ship"}})),
        ("dynamic read", FileRead, json!({"variant": "Dynamic", "filePath": "/w/a.rs"})),
        ("dynamic glob", FileRead, json!({"variant": "Dynamic", "pattern": "*.rs"})),
        ("dynamic todos", Bookkeeping, json!({"variant": "Dynamic", "todos": []})),
        ("dynamic skill", FileRead, json!({"variant": "Dynamic", "name": "create-workflow"})),
        ("dynamic unknown", Other, json!({"variant": "Dynamic", "target": "prod"})),
    ]
    .into_iter()
    .map(|(label, expect, value)| (label, expect, wire(label, value)))
    .collect();
    out.push(("peer list_agents", FileRead, ToolInput::Peer(PeerToolInput::ListAgents(ListAgentsInput { page: None }))));
    out.push((
        "peer refuse",
        Bookkeeping,
        ToolInput::Peer(PeerToolInput::RefusePeerMessage(RefusePeerMessageInput {
            message_id: "m1".to_owned(),
            reason: "no".to_owned(),
        })),
    ));
    out.push((
        "peer send",
        Other,
        ToolInput::Peer(PeerToolInput::SendMessage(SendMessageInput {
            to: "agent".to_owned(),
            message: "hi".to_owned(),
            summary: None,
            notify_when_idle: None,
        })),
    ));
    for (label, input) in crate::permission::types::tests::side_effecting_tool_inputs() {
        out.push((label, Other, input));
    }
    out
}

fn policy(rule: PermissionRule) -> CompiledPolicy {
    CompiledPolicy::new(PermissionConfig::new(vec![rule]))
}

fn read_rule(spelling: &str, action: RuleAction) -> CompiledPolicy {
    policy(parse_permission_rule(spelling, action).unwrap())
}

fn any_rule(action: RuleAction) -> CompiledPolicy {
    policy(PermissionRule {
        action,
        tool: ToolFilter::Any,
        pattern: None,
        pattern_mode: PatternMode::Glob,
    })
}

fn fixture(label: &str) -> AccessKind {
    let (_, _, input) = fixtures()
        .into_iter()
        .find(|(l, _, _)| *l == label)
        .unwrap_or_else(|| panic!("no fixture {label}"));
    AccessKind::from(&input)
}

/// Every `ToolInput` variant has at least one fixture, so the classification test below sees all of them.
#[test]
fn every_tool_input_variant_has_a_read_coverage_fixture() {
    let covered: BTreeSet<&str> = fixtures().iter().map(|(_, _, input)| variant_name(input)).collect();
    let missing: Vec<&&str> = ALL_VARIANTS.iter().filter(|v| !covered.contains(**v)).collect();
    assert!(missing.is_empty(), "ToolInput variants with no Read-coverage fixture: {missing:?}");
}

/// Fail closed: every file-reading tool is reached by a bare `Read` deny and ask (and `Read(*)`), exactly as before;
/// adding a tool to `Session` requires its whole call chain to be file-free (everything else is a path-less `Read`);
/// bookkeeping is reached by none of them, only by `any`; nothing else is classified as a read or as bookkeeping.
#[test]
fn read_rules_reach_every_file_read_and_no_bookkeeping() {
    for (label, expect, input) in fixtures() {
        let access = AccessKind::from(&input);
        match expect {
            Expect::FileRead => {
                assert!(
                    matches!(access, AccessKind::Read(_) | AccessKind::Grep { .. }),
                    "{label} must be a file read, got {access:?}"
                );
                for spelling in ["Read", "Read(*)"] {
                    assert!(
                        matches!(read_rule(spelling, RuleAction::Deny).evaluate(&access), Some(Decision::Reject(_))),
                        "deny {spelling} must reach {label}"
                    );
                    assert_eq!(
                        read_rule(spelling, RuleAction::Ask).evaluate(&access),
                        Some(Decision::Ask),
                        "ask {spelling} must reach {label}"
                    );
                }
            }
            Expect::Bookkeeping => {
                assert!(matches!(access, AccessKind::Session), "{label} must be bookkeeping, got {access:?}");
                for spelling in ["Read", "Read(*)", "Read(**)"] {
                    for action in [RuleAction::Deny, RuleAction::Ask] {
                        assert_eq!(
                            read_rule(spelling, action).evaluate(&access),
                            None,
                            "{action:?} {spelling} must not reach {label}"
                        );
                    }
                }
                assert!(
                    matches!(any_rule(RuleAction::Deny).evaluate(&access), Some(Decision::Reject(_))),
                    "an `any` deny must still reach {label}"
                );
                assert_eq!(any_rule(RuleAction::Ask).evaluate(&access), Some(Decision::Ask), "any ask: {label}");
            }
            Expect::Other => assert!(
                !matches!(access, AccessKind::Read(_) | AccessKind::Grep { .. } | AccessKind::Session),
                "{label} must not be classified as a read or bookkeeping, got {access:?}"
            ),
        }
    }
}

/// The embedding-app shape `ask = ["Read"]` (and `deny = ["Read"]`): file reads ask, bookkeeping does not.
#[test]
fn bare_read_ask_and_deny_cover_file_reads_not_bookkeeping() {
    for action in [RuleAction::Ask, RuleAction::Deny] {
        let rule = read_rule("Read", action);
        for label in ["read_file", "list_dir", "grep", "lsp"] {
            assert!(rule.evaluate(&fixture(label)).is_some(), "{action:?} Read must reach {label}");
        }
        for label in ["todo_write", "ask_user_question", "scheduler_list"] {
            assert_eq!(rule.evaluate(&fixture(label)), None, "{action:?} Read must not reach {label}");
        }
    }
    let any = any_rule(RuleAction::Ask);
    for label in ["todo_write", "ask_user_question", "scheduler_list"] {
        assert_eq!(any.evaluate(&fixture(label)), Some(Decision::Ask), "an `any` ask must reach {label}");
    }
}

/// Path-scoped `Read(**)` / `Read(**/.ssh/**)` keep their behaviour on path-carrying reads and never reach bookkeeping
/// (`Read(**)` did not reach a path-less access before either).
#[test]
fn path_scoped_read_rules_keep_path_behaviour() {
    let all = read_rule("Read(**)", RuleAction::Deny);
    assert!(matches!(all.evaluate(&fixture("read_file")), Some(Decision::Reject(_))));
    assert!(matches!(all.evaluate(&fixture("grep")), Some(Decision::Reject(_))));
    assert_eq!(all.evaluate(&fixture("lsp workspace")), None);
    assert_eq!(all.evaluate(&fixture("todo_write")), None);
    let ssh = read_rule("Read(**/.ssh/**)", RuleAction::Ask);
    assert_eq!(ssh.evaluate(&AccessKind::Read(Some("/home/u/.ssh/id_ed25519".to_owned()))), Some(Decision::Ask));
    assert_eq!(ssh.evaluate(&fixture("read_file")), None);
    assert_eq!(ssh.evaluate(&fixture("todo_write")), None);
}
