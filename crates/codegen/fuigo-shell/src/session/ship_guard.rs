//! The never-merge rule of `/ship` and `/steward`: while a watch is armed, a turn the user did not type (a wake from a
//! background command, monitor, subagent or `/loop`) may not merge, approve, enable auto-merge or force-push, by shell
//! command or GitHub MCP tool, and neither may a subagent such a turn spawns.
//! Typed turns and their subagents are never touched, and a session that never ran `/ship` or `/steward` sees no change.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Default)]
pub(crate) struct ShipGuard {
    armed: AtomicBool,
    unattended_turn: AtomicBool,
    /// A subagent spawned by an unattended turn of an armed session: armed for its whole life, and no turn is typed.
    inherited: bool,
    /// The prompts the user typed; a subagent spawned by any other prompt of an armed session inherits the guard.
    typed_prompts: parking_lot::Mutex<HashSet<String>>,
}

impl ShipGuard {
    /// A skill the user typed as a slash command. `/ship` or `/steward` arms the guard; with the argument `stop` it disarms.
    pub(crate) fn on_typed_skill(&self, name: &str, args: &str) {
        if !self.inherited && matches!(name, "ship" | "steward") {
            self.armed.store(args.trim() != "stop", Ordering::Relaxed);
        }
    }

    /// Turn `prompt_id` is starting; `human_typed` is true only for a prompt the user typed.
    pub(crate) fn begin_turn(&self, prompt_id: &str, human_typed: bool) {
        let typed = human_typed && !self.inherited;
        self.unattended_turn.store(!typed, Ordering::Relaxed);
        if typed {
            self.typed_prompts.lock().insert(prompt_id.to_owned());
        }
    }

    /// The guard of a subagent that prompt `parent_prompt_id` of this session spawns: inherited (armed, never typed) when
    /// this session is armed and the user did not type that prompt (a harness spawn has none), a fresh one otherwise.
    pub(crate) fn for_child(&self, parent_prompt_id: Option<&str>) -> Arc<Self> {
        let typed = parent_prompt_id.is_some_and(|id| self.typed_prompts.lock().contains(id));
        Arc::new(if self.armed.load(Ordering::Relaxed) && !typed {
            Self {
                armed: AtomicBool::new(true),
                unattended_turn: AtomicBool::new(true),
                inherited: true,
                typed_prompts: Default::default(),
            }
        } else {
            Self::default()
        })
    }

    /// The refusal for a call of `tool_name` whose input would merge, approve, auto-merge or force-push (a shell
    /// `command`, or a GitHub MCP tool and its arguments), when armed and the turn is unattended. `None` otherwise.
    pub(crate) fn refusal(
        &self,
        tool_name: &str,
        tool_input: &serde_json::Value,
    ) -> Option<String> {
        if !self.armed.load(Ordering::Relaxed) || !self.unattended_turn.load(Ordering::Relaxed) {
            return None;
        }
        let action = tool_input
            .get("command")
            .and_then(serde_json::Value::as_str)
            .and_then(forbidden_action)
            .or_else(|| forbidden_mcp_action(tool_name, tool_input))?;
        Some(format!(
            "Refused by the /ship and /steward never-merge rule: {action} is not allowed on a turn the user did not \
             type. The user merges the pull request. Typing `/steward stop` ends the watch and this rule."
        ))
    }
}

/// What a GitHub MCP tool call would do that the watch forbids, if anything. Matched on the tool part of
/// `server__tool` (any server name, so a renamed GitHub server is still covered) plus its arguments:
/// - `merge_pull_request`;
/// - a review write with `event` `APPROVE` (`pull_request_review_write`, `create_pull_request_review`,
///   `create_and_submit_pull_request_review`, `submit_pending_pull_request_review`);
/// - enabling auto-merge (`enable_auto_merge`, `enable_pull_request_auto_merge`);
/// - a ref update with `force: true` (`update_ref`, `update_git_ref`).
///
/// Every other tool passes, `update_pull_request_branch` included; whole servers are never blocked.
fn forbidden_mcp_action(tool_name: &str, args: &serde_json::Value) -> Option<&'static str> {
    let tool = tool_name.rsplit("__").next().unwrap_or(tool_name);
    let approves = || {
        args.get("event")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|event| event.eq_ignore_ascii_case("approve"))
    };
    match tool {
        "merge_pull_request" => Some("merging a pull request (MCP `merge_pull_request`)"),
        "pull_request_review_write"
        | "create_pull_request_review"
        | "create_and_submit_pull_request_review"
        | "submit_pending_pull_request_review"
            if approves() =>
        {
            Some("approving a pull request through an MCP review tool")
        }
        "enable_auto_merge" | "enable_pull_request_auto_merge" => {
            Some("enabling auto-merge through an MCP tool")
        }
        "update_ref" | "update_git_ref"
            if args.get("force").and_then(serde_json::Value::as_bool) == Some(true) =>
        {
            Some("force-updating a ref through an MCP tool")
        }
        _ => None,
    }
}

/// What a shell command line would do that the watch forbids, if anything.
// shortcut: a token scan per shell segment, not a shell parser; a script, alias or `git -c alias.x=...` still gets
// through (Claude Code states the same limit). Upgrade if a real bypass shows up in practice.
pub(crate) fn forbidden_action(command: &str) -> Option<&'static str> {
    let cleaned: String = command
        .chars()
        .map(|c| {
            if matches!(c, '\'' | '"' | '`' | '(' | ')' | '{' | '}' | '\\') {
                ' '
            } else {
                c
            }
        })
        .collect();
    for segment in cleaned.split([';', '&', '|', '\n']) {
        let words: Vec<&str> = segment.split_whitespace().collect();
        for (i, word) in words.iter().enumerate() {
            let program = word.rsplit('/').next().unwrap_or(word);
            let action = match program.trim_end_matches(".exe") {
                "gh" => gh_action(&words[i + 1..]),
                "git" => git_action(&words[i + 1..]),
                _ => None,
            };
            if action.is_some() {
                return action;
            }
        }
    }
    None
}

fn gh_action(args: &[&str]) -> Option<&'static str> {
    match args {
        ["pr", "merge", ..] => Some("merging a pull request (`gh pr merge`)"),
        ["pr", "review", rest @ ..] if rest.iter().any(|a| *a == "--approve" || *a == "-a") => {
            Some("approving a pull request (`gh pr review --approve`)")
        }
        ["api", rest @ ..]
            if rest.iter().any(|a| {
                let a = a.to_ascii_lowercase();
                a.ends_with("/merge")
                    || a.contains("mergepullrequest")
                    || a.contains("enablepullrequestautomerge")
                    || (a.contains("event") && a.contains("approve"))
            }) =>
        {
            Some("merging, approving or enabling auto-merge through `gh api`")
        }
        _ => None,
    }
}

fn git_action(args: &[&str]) -> Option<&'static str> {
    // Skip git's global options (`-C <dir>`, `-c <key=value>`, `--git-dir=...`) to reach the subcommand.
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        match *arg {
            "-C" | "-c" => i += 2,
            a if a.starts_with('-') => i += 1,
            _ => break,
        }
    }
    let ("push", rest) = (*args.get(i)?, &args[i + 1..]) else {
        return None;
    };
    rest.iter()
        .any(|a| {
            a.starts_with("--force")
                || *a == "--mirror"
                || (a.starts_with('-') && !a.starts_with("--") && a.contains('f'))
                || (a.starts_with('+') && a.len() > 1)
        })
        .then_some("force-pushing (`git push --force`)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_merge_approve_auto_merge_and_force_push() {
        for command in [
            "gh pr merge 12 --squash",
            "gh pr merge --auto --squash",
            "cd repo && /usr/bin/gh pr merge 3",
            "gh pr review 7 --approve",
            "gh pr review -a",
            "gh api -X PUT repos/o/r/pulls/5/merge",
            "gh api graphql -f query='mutation { mergePullRequest(input: {pullRequestId: \"x\"}) { clientMutationId } }'",
            "gh api graphql -f query='mutation { enablePullRequestAutoMerge(input: {}) { clientMutationId } }'",
            "gh api repos/o/r/pulls/5/reviews -f event=APPROVE",
            "git push --force",
            "git push -f origin feature",
            "git push -uf origin feature",
            "git push --force-with-lease origin feature",
            "git -C /tmp/repo push --force",
            "git push origin +feature",
            "git push --mirror",
            "echo ok; git push -f",
            "bash -c \"gh pr merge 9\"",
        ] {
            assert!(forbidden_action(command).is_some(), "must block: {command}");
        }
    }

    #[test]
    fn allows_the_normal_watch_commands() {
        for command in [
            "git push",
            "git push -u origin feature",
            "git merge origin/main",
            "git commit -m 'merge base'",
            "gh pr view 12 --json state,mergeable",
            "gh pr checks 12 --watch --fail-fast",
            "gh pr review 7 --comment -b 'looks off'",
            "gh pr list --search merge",
            "gh api repos/o/r/pulls/5/comments",
            "gh run rerun 99 --failed",
            "git fetch origin && git merge origin/main && git push origin feature",
        ] {
            assert_eq!(forbidden_action(command), None, "must allow: {command}");
        }
    }

    #[test]
    fn refuses_only_when_armed_and_unattended() {
        let merge = serde_json::json!({"command": "gh pr merge 12"});
        let refused = |guard: &ShipGuard, input: &serde_json::Value| {
            guard.refusal("run_terminal_command", input)
        };
        let guard = ShipGuard::default();
        guard.begin_turn("p1", false);
        assert_eq!(refused(&guard, &merge), None, "never armed: no change");
        guard.on_typed_skill("steward", "");
        assert!(
            refused(&guard, &merge).is_some(),
            "armed + wake turn: denied"
        );
        guard.begin_turn("p2", true);
        assert_eq!(
            refused(&guard, &merge),
            None,
            "a typed turn is never touched"
        );
        guard.begin_turn("p3", false);
        assert_eq!(
            refused(&guard, &serde_json::json!({"command": "git push"})),
            None
        );
        guard.on_typed_skill("review", "");
        assert!(
            refused(&guard, &merge).is_some(),
            "other skills leave it armed"
        );
        guard.on_typed_skill("ship", " stop ");
        assert_eq!(refused(&guard, &merge), None, "`/ship stop` disarms");
        guard.on_typed_skill("ship", "high");
        assert!(refused(&guard, &merge).is_some(), "`/ship` arms");
    }

    #[test]
    fn mcp_merge_approve_auto_merge_and_force_ref_are_refused_by_tool_and_arguments() {
        use serde_json::json;
        let guard = ShipGuard::default();
        guard.on_typed_skill("ship", "");
        guard.begin_turn("wake", false);
        for (tool, args) in [
            (
                "github__merge_pull_request",
                json!({"owner": "o", "repo": "r", "pullNumber": 5}),
            ),
            (
                "com-github-github-mcp-server__merge_pull_request",
                json!({}),
            ),
            ("merge_pull_request", json!({})),
            (
                "github__pull_request_review_write",
                json!({"method": "create", "event": "APPROVE"}),
            ),
            (
                "github__pull_request_review_write",
                json!({"method": "submit_pending", "event": "approve"}),
            ),
            (
                "github__create_and_submit_pull_request_review",
                json!({"event": "APPROVE"}),
            ),
            (
                "github__submit_pending_pull_request_review",
                json!({"event": "APPROVE"}),
            ),
            ("github__enable_auto_merge", json!({"pullNumber": 5})),
            ("gh__enable_pull_request_auto_merge", json!({})),
            (
                "github__update_ref",
                json!({"ref": "heads/main", "sha": "abc", "force": true}),
            ),
        ] {
            assert!(
                guard.refusal(tool, &args).is_some(),
                "must refuse {tool} {args}"
            );
        }
        for (tool, args) in [
            (
                "github__update_pull_request_branch",
                json!({"pullNumber": 5}),
            ),
            (
                "github__pull_request_review_write",
                json!({"method": "create", "event": "COMMENT"}),
            ),
            (
                "github__pull_request_review_write",
                json!({"method": "create", "event": "REQUEST_CHANGES"}),
            ),
            ("github__pull_request_read", json!({"method": "get"})),
            (
                "github__create_pull_request",
                json!({"title": "merge base"}),
            ),
            (
                "github__update_ref",
                json!({"ref": "heads/feature", "sha": "abc", "force": false}),
            ),
            (
                "github__add_issue_comment",
                json!({"body": "please merge_pull_request"}),
            ),
            ("linear__save_issue", json!({"event": "APPROVE"})),
        ] {
            assert_eq!(guard.refusal(tool, &args), None, "must allow {tool} {args}");
        }
        guard.begin_turn("typed", true);
        assert_eq!(
            guard.refusal("github__merge_pull_request", &json!({})),
            None,
            "a typed turn is never touched"
        );
    }

    #[test]
    fn a_subagent_of_a_wake_turn_inherits_the_guard_and_a_typed_turns_does_not() {
        let merge = serde_json::json!({"command": "gh pr merge 12"});
        let mcp_merge = serde_json::json!({});
        let parent = ShipGuard::default();
        parent.begin_turn("typed-1", true);
        let unarmed_child = parent.for_child(Some("wake-0"));
        unarmed_child.begin_turn("c", false);
        assert_eq!(
            unarmed_child.refusal("run_terminal_command", &merge),
            None,
            "unarmed parent: a fresh child guard"
        );
        parent.on_typed_skill("steward", "");
        parent.begin_turn("wake-1", false);
        for spawned_by in [Some("wake-1"), None] {
            let child = parent.for_child(spawned_by);
            child.begin_turn("child-1", true);
            child.on_typed_skill("steward", "stop");
            assert!(
                child.refusal("run_terminal_command", &merge).is_some(),
                "child of {spawned_by:?}: armed and unattended for life"
            );
            assert!(
                child
                    .for_child(Some("child-1"))
                    .refusal("github__merge_pull_request", &mcp_merge)
                    .is_some(),
                "a grandchild inherits too"
            );
        }
        let typed_child = parent.for_child(Some("typed-1"));
        typed_child.begin_turn("c", false);
        assert_eq!(
            typed_child.refusal("run_terminal_command", &merge),
            None,
            "a child of a typed turn is unaffected, even spawned late"
        );
        parent.on_typed_skill("steward", "stop");
        let after_stop = parent.for_child(Some("wake-1"));
        after_stop.begin_turn("c", false);
        assert_eq!(
            after_stop.refusal("run_terminal_command", &merge),
            None,
            "a disarmed parent passes nothing on"
        );
    }
}
