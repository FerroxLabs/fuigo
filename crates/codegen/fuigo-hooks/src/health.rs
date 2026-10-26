#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

//! Hook health: which hooks can run in a session, and why not.
//!
//! A hook failure is one of two kinds, and they are shown very differently:
//!
//! * **CONFIG**: the hook can never start as written (a placeholder it needs is not set, its program is not found or
//!   not executable). Retrying changes nothing, so it is reported **once per session** as one grouped notice and the
//!   hook is skipped silently from then on.
//! * **RUNTIME**: the hook started and exited non-zero or timed out. It keeps running, and its failure is counted in
//!   the hooks chip rather than printed into the transcript. A blocking denial is not a failure at all and stays inline.
//!
//! This module holds the per-session record of both, the CONFIG classification (a stable prefix on the failure text, so
//! the classification survives the `HookRunnerResult::Failed(String)` shape every runner returns), the startup check
//! that finds CONFIG failures before the first prompt, and the per-hook diagnosis `/hooks` and `fuigo doctor` list.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, PoisonError};

use crate::config::{HandlerType, HookOrigin, HookSpec, hook_origin};
use crate::discovery::HookRegistry;
use crate::runner::HookRunnerResult;
use crate::trust::{DisabledHooks, HookSkipReason};

/// Start of every CONFIG failure's text. The remainder is the reason.
pub const CONFIG_FAILURE_PREFIX: &str = "hook not executed: ";

/// The failure text for a hook that can never start, with the given reason.
pub fn config_failure(detail: &str) -> String {
    format!("{CONFIG_FAILURE_PREFIX}{detail}")
}

/// Whether a hook's failure text is a CONFIG failure (as opposed to a RUNTIME one).
pub fn is_config_failure(error: &str) -> bool {
    error.starts_with(CONFIG_FAILURE_PREFIX)
}

/// The reason inside a CONFIG failure's text (the text unchanged if it carries no prefix).
pub fn config_failure_detail(error: &str) -> &str {
    error.strip_prefix(CONFIG_FAILURE_PREFIX).unwrap_or(error)
}

#[derive(Default)]
struct SessionBoard {
    /// Hook name to the reason it can never start.
    config: HashMap<String, String>,
    /// Hook name to the error of its most recent failed run. Cleared by the next successful run.
    runtime: HashMap<String, String>,
}

/// Sessions are small and short-lived; the cap only stops a pathological process from growing the map without bound.
const MAX_SESSIONS: usize = 512;

static BOARD: LazyLock<Mutex<HashMap<String, SessionBoard>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn with_session<R>(session_id: &str, f: impl FnOnce(&mut SessionBoard) -> R) -> R {
    let mut boards = BOARD.lock().unwrap_or_else(PoisonError::into_inner);
    if boards.len() >= MAX_SESSIONS && !boards.contains_key(session_id) {
        boards.clear();
    }
    f(boards.entry(session_id.to_string()).or_default())
}

/// Record a CONFIG failure. Returns whether it is new for this session, i.e. whether it still needs its one notice.
pub fn record_config_failure(session_id: &str, hook_name: &str, detail: &str) -> bool {
    with_session(session_id, |b| {
        b.config.insert(hook_name.to_string(), detail.to_string()).is_none()
    })
}

/// The reason this hook can never start in this session, if a CONFIG failure was recorded for it.
pub fn config_failure_for(session_id: &str, hook_name: &str) -> Option<String> {
    with_session(session_id, |b| b.config.get(hook_name).cloned())
}

/// The error of this hook's most recent failed run in this session, if its last run failed.
pub fn runtime_failure_for(session_id: &str, hook_name: &str) -> Option<String> {
    with_session(session_id, |b| b.runtime.get(hook_name).cloned())
}

/// Forget everything recorded for a session (after a hooks reload, when the configuration may have been fixed).
pub fn reset_session(session_id: &str) {
    BOARD
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(session_id);
}

/// Record that a hook ran and failed (a RUNTIME failure), so `/hooks` and `fuigo doctor` can show its last error.
pub fn record_runtime_failure(session_id: &str, hook_name: &str, error: &str) {
    with_session(session_id, |b| {
        b.runtime.insert(hook_name.to_string(), error.to_string());
    });
}

/// Record one finished run so the next dispatch skips a hook that can never start and `/hooks` can show the last error.
pub(crate) fn note_result(session_id: &str, hook_name: &str, result: &HookRunnerResult) {
    match result {
        HookRunnerResult::Failed(error) if is_config_failure(error) => {
            record_config_failure(session_id, hook_name, config_failure_detail(error));
        }
        HookRunnerResult::Failed(error) => with_session(session_id, |b| {
            b.runtime.insert(hook_name.to_string(), error.clone());
        }),
        _ => with_session(session_id, |b| {
            b.runtime.remove(hook_name);
        }),
    }
}

/// The plugin name of a `plugin/<name>/...` hook, else the tier it came from (`global`, `project`, ...).
pub fn hook_source(hook_name: &str) -> String {
    let source = crate::config::hook_display_name(hook_name);
    if let Some(rest) = source.strip_prefix(crate::config::PLUGIN_HOOK_PREFIX) {
        return rest.split('/').next().unwrap_or(rest).to_string();
    }
    match source.split_once('/') {
        Some((tier, _)) => tier.to_string(),
        None => source.to_string(),
    }
}

/// A few words for the grouped notice: "needs ${A}", "node not found".
pub fn short_reason(detail: &str) -> String {
    if let Some(vars) = detail.strip_prefix("required env var(s) not set: ") {
        return format!("needs {}", vars.replace("${", "").replace('}', ""));
    }
    if let Some(rest) = detail.strip_prefix("command not found: ") {
        let program = rest.split(" (").next().unwrap_or(rest);
        let name = program.rsplit('/').next().unwrap_or(program);
        return format!("{name} not found");
    }
    if let Some((name, _)) = detail.split_once(" not found on PATH") {
        return format!("{name} not found");
    }
    if let Some(rest) = detail.strip_prefix("failed to spawn command: ") {
        return format!("can't start: {rest}");
    }
    detail.to_string()
}

/// What to do about a CONFIG failure.
pub fn config_fix_hint(detail: &str) -> String {
    const DISABLE: &str = "Or disable the hook in /hooks to silence it.";
    if let Some(vars) = detail.strip_prefix("required env var(s) not set: ") {
        return format!(
            "Set {} in the environment or in the hook's env, or fix the plugin's hooks file. {DISABLE}",
            vars.replace("${", "").replace('}', "")
        );
    }
    if detail.starts_with("command not found: ") || detail.contains(" not found on PATH") {
        let name = short_reason(detail).trim_end_matches(" not found").to_string();
        return format!("Install {name} or add it to PATH, then reload hooks. {DISABLE}");
    }
    format!("Fix the hook's command, then reload hooks. {DISABLE}")
}

/// What to do about a RUNTIME failure.
pub fn runtime_fix_hint() -> String {
    "Run the hook's command by hand to see the error. Disable the hook in /hooks to stop it running.".to_string()
}

/// One hook that cannot start, found by [`validate_registry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigProblem {
    pub hook_name: String,
    /// Plugin name or tier, see [`hook_source`].
    pub source: String,
    pub is_plugin: bool,
    pub detail: String,
}

/// Validate every enabled command hook once, without running anything, and record each CONFIG failure for the session.
/// Returns the problems that are new for this session (the caller shows them as one grouped notice).
pub fn validate_registry(
    registry: &HookRegistry,
    workspace_root: &str,
    session_id: &str,
) -> Vec<ConfigProblem> {
    let disabled = DisabledHooks::load();
    let mut problems = Vec::new();
    for spec in registry.all_hooks() {
        if !matches!(spec.handler_type, HandlerType::Command) || !spec.enabled || disabled.skip_reason(spec).is_some() {
            continue;
        }
        let Err(detail) = crate::runner::command::validate_command_spec(spec, workspace_root, session_id) else {
            continue;
        };
        if record_config_failure(session_id, &spec.name, &detail) {
            problems.push(ConfigProblem {
                hook_name: spec.name.clone(),
                source: hook_source(&spec.name),
                is_plugin: hook_origin(spec) == HookOrigin::Plugin,
                detail,
            });
        }
    }
    problems
}

/// The one notice for a set of CONFIG failures:
/// "2 plugin hooks can't run: claude-mem (needs X), stripe (node not found). /hooks for details."
pub fn grouped_notice(problems: &[ConfigProblem]) -> Option<String> {
    if problems.is_empty() {
        return None;
    }
    let mut by_source: Vec<(&str, Vec<String>)> = Vec::new();
    for p in problems {
        let reason = short_reason(&p.detail);
        match by_source.iter_mut().find(|(source, _)| *source == p.source) {
            Some((_, reasons)) => {
                if !reasons.contains(&reason) {
                    reasons.push(reason);
                }
            }
            None => by_source.push((&p.source, vec![reason])),
        }
    }
    let list = by_source
        .iter()
        .map(|(source, reasons)| format!("{source} ({})", reasons.join("; ")))
        .collect::<Vec<_>>()
        .join(", ");
    let n = problems.len();
    let noun = match (problems.iter().all(|p| p.is_plugin), n) {
        (true, 1) => "plugin hook can't".to_string(),
        (true, _) => "plugin hooks can't".to_string(),
        (false, 1) => "hook can't".to_string(),
        (false, _) => "hooks can't".to_string(),
    };
    Some(format!("{n} {noun} run: {list}. /hooks for details."))
}

/// Whether a hook can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagState {
    Ok,
    Skipped,
    Failing,
}

/// One hook as `/hooks` and `fuigo doctor` list it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookDiagnosis {
    pub source: String,
    pub state: DiagState,
    /// Why the hook is skipped, or its last error when failing.
    pub reason: Option<String>,
    pub fix_hint: Option<String>,
}

/// Diagnose one hook for this session: disabled, cannot start (recorded or found now), failing at runtime, or fine.
pub fn diagnose(
    spec: &HookSpec,
    session_id: &str,
    workspace_root: &str,
    disabled: &DisabledHooks,
) -> HookDiagnosis {
    let source = hook_source(&spec.name);
    let skipped = |reason: String, fix_hint: String| HookDiagnosis {
        source: source.clone(),
        state: DiagState::Skipped,
        reason: Some(reason),
        fix_hint: Some(fix_hint),
    };
    match disabled.skip_reason(spec) {
        Some(HookSkipReason::UserDisabled) => {
            return skipped("disabled".to_string(), "Enable it again in /hooks.".to_string());
        }
        Some(HookSkipReason::ManagedOnly) => {
            let why = if disabled.managed_only_by_env() {
                "only managed hooks run (FUIGO_MANAGED_HOOKS_ONLY)"
            } else {
                "only managed hooks run (allow_managed_hooks_only)"
            };
            return skipped(
                why.to_string(),
                "Managed policy decides this; ask your administrator.".to_string(),
            );
        }
        None => {}
    }
    if matches!(spec.handler_type, HandlerType::Command) {
        let detail = config_failure_for(session_id, &spec.name).or_else(|| {
            crate::runner::command::validate_command_spec(spec, workspace_root, session_id).err()
        });
        if let Some(detail) = detail {
            let hint = config_fix_hint(&detail);
            return skipped(detail, hint);
        }
    }
    match runtime_failure_for(session_id, &spec.name) {
        Some(error) => HookDiagnosis {
            source,
            state: DiagState::Failing,
            reason: Some(error),
            fix_hint: Some(runtime_fix_hint()),
        },
        None => HookDiagnosis {
            source,
            state: DiagState::Ok,
            reason: None,
            fix_hint: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problem(source: &str, is_plugin: bool, detail: &str) -> ConfigProblem {
        ConfigProblem {
            hook_name: format!("{source}/h"),
            source: source.to_string(),
            is_plugin,
            detail: detail.to_string(),
        }
    }

    #[test]
    fn config_failures_are_told_apart_from_runtime_failures_by_their_prefix() {
        assert!(is_config_failure(&config_failure("command not found: node")));
        assert!(!is_config_failure("exit 1: boom"));
        assert!(!is_config_failure("timed out after 5000ms"));
        assert_eq!(config_failure_detail(&config_failure("x")), "x");
    }

    #[test]
    fn short_reasons_are_a_few_words() {
        assert_eq!(short_reason("required env var(s) not set: ${A}, ${B}"), "needs A, B");
        assert_eq!(short_reason("command not found: node (not on PATH)"), "node not found");
        assert_eq!(short_reason("command not found: /plug/hooks/run.sh"), "run.sh not found");
    }

    #[test]
    fn grouped_notice_names_every_hook_source_once() {
        let notice = grouped_notice(&[
            problem("claude-mem", true, "required env var(s) not set: ${X}"),
            problem("claude-mem", true, "required env var(s) not set: ${X}"),
            problem("stripe", true, "command not found: node (not on PATH)"),
        ])
        .unwrap();
        assert_eq!(
            notice,
            "3 plugin hooks can't run: claude-mem (needs X), stripe (node not found). /hooks for details."
        );
        let mixed = grouped_notice(&[problem("global", false, "command not found: lint")]).unwrap();
        assert_eq!(mixed, "1 hook can't run: global (lint not found). /hooks for details.");
        assert_eq!(grouped_notice(&[]), None);
    }

    #[test]
    fn hook_source_is_the_plugin_name_or_the_tier() {
        assert_eq!(hook_source("plugin/stripe/hooks:session_start[0].hooks[0]"), "stripe");
        assert_eq!(hook_source("global/lint:pre_tool_use[0].hooks[0]"), "global");
        assert_eq!(hook_source("project/x:stop[0].hooks[1]"), "project");
    }

    #[test]
    fn the_board_remembers_config_failures_once_and_runtime_failures_until_a_good_run() {
        let session = "health-board-unit";
        let config = HookRunnerResult::Failed(config_failure("command not found: node"));
        note_result(session, "plugin/p/a", &config);
        assert_eq!(config_failure_for(session, "plugin/p/a").as_deref(), Some("command not found: node"));
        assert!(!record_config_failure(session, "plugin/p/a", "command not found: node"), "already recorded");

        note_result(session, "plugin/p/b", &HookRunnerResult::Failed("exit 2: bad".into()));
        assert_eq!(runtime_failure_for(session, "plugin/p/b").as_deref(), Some("exit 2: bad"));
        assert!(config_failure_for(session, "plugin/p/b").is_none());
        note_result(session, "plugin/p/b", &HookRunnerResult::Success);
        assert!(runtime_failure_for(session, "plugin/p/b").is_none());

        reset_session(session);
        assert!(config_failure_for(session, "plugin/p/a").is_none());
    }
}
