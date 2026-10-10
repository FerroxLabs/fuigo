//! Managed-policy preflight for one permission request.
//!
//! Evaluates the direct rule pass and both bash security gates once and keeps each gate's `Ask` provenance.
//! A rule-match Ask is an actual policy match and stays a prompt; a fail-closed Ask means analysis could not decompose the command to check rules.
//! In auto mode a fail-closed Ask defers to the classifier.
//! The manager consumes this single result instead of correlating parallel booleans at every decision site.

use std::path::Path;

use crate::permission::manager::reasons;
use crate::permission::policy::{CompiledPolicy, GateDecision, combine_decisions};
use crate::permission::types::{AccessKind, Decision};

/// One request's managed-policy evaluation, computed before any fast path.
pub(crate) struct GatePreflight {
    direct: Option<Decision>,
    bash_command: Option<GateDecision>,
    shell_file: Option<GateDecision>,
    /// A native path hit an unresolvable symlink under deny/ask file rules; blocks YOLO.
    native_symlink_fail_closed: bool,
    /// In auto mode, a fail-closed gate Ask with no rule match lets the classifier run (Allow executes, Block denies within budget).
    /// A rule-match Ask never defers.
    defers_gate_ask: bool,
}

/// One `apply_patch` target in every spelling that names the file the tool writes (P184).
pub(crate) struct EditTargetSpellings {
    /// The path `ApplyPatchTool` writes: `cwd.join(path)`, not collapsed, so `..` after a symlink stays physical.
    pub(crate) written: String,
    /// The model's spelling (the patch header), when it differs from `written`.
    pub(crate) raw: Option<String>,
    /// `written` with every symlink followed literally (no separator rewriting); `None` when it cannot be resolved.
    pub(crate) physical: Option<String>,
    /// Whether an allow on `written` can be trusted. The policy reads `\` as a separator, so on Unix (where it is an
    /// ordinary filename byte) a backslash spelling can match a rule written for a different file: such a target never
    /// earns an allow (deny and ask still bind).
    allow_trusted: bool,
}

impl EditTargetSpellings {
    pub(crate) fn new(cwd: &Path, path: &str) -> Self {
        let written_path = cwd.join(path);
        let written = written_path.to_string_lossy().into_owned();
        let physical = crate::permission::policy::resolve_following_symlinks(&written_path)
            .map(|p| p.to_string_lossy().into_owned());
        let allow_trusted = !(cfg!(unix) && written.contains('\\'));
        Self {
            raw: (path != written).then(|| path.to_owned()),
            physical,
            allow_trusted,
            written,
        }
    }

    /// The spellings other than `written`.
    fn others(&self) -> impl Iterator<Item = &String> {
        self.raw
            .iter()
            .chain(self.physical.iter().filter(|p| **p != self.written))
    }
}

impl GatePreflight {
    /// `cwd` is the requesting session's execution cwd (not necessarily the manager's): path rules and shell-file operands anchor to it.
    pub(crate) fn evaluate(
        policy: Option<&CompiledPolicy>,
        access: &AccessKind,
        cwd: &Path,
        auto_mode: bool,
    ) -> Self {
        let (direct, native_symlink_fail_closed) = match policy {
            Some(policy) => policy.evaluate_with_cwd_details(access, Some(cwd)),
            None => (None, false),
        };
        let (bash_command, shell_file) = match (policy, access) {
            (Some(policy), AccessKind::Bash(cmd)) => (
                policy.evaluate_bash_command_gate(cmd),
                policy.evaluate_shell_file_access_gate(cmd, cwd),
            ),
            _ => (None, None),
        };
        let rule_match_ask = matches!(direct, Some(Decision::Ask))
            || matches!(bash_command, Some(GateDecision::AskRuleMatch))
            || matches!(shell_file, Some(GateDecision::AskRuleMatch));
        let fail_closed_ask = matches!(bash_command, Some(GateDecision::AskFailClosed))
            || matches!(shell_file, Some(GateDecision::AskFailClosed));
        // WHY: a fail-closed Ask means analysis could not decompose the command to check rules, so the classifier arbitrates it
        // A rule-match Ask is an actual policy match that stays a prompt (never waived by a model)
        let defers_gate_ask = auto_mode && fail_closed_ask && !rule_match_ask;
        Self {
            direct,
            bash_command,
            shell_file,
            native_symlink_fail_closed,
            defers_gate_ask,
        }
    }

    /// One multi-file edit (`apply_patch`, P184) judged as an `Edit` of each target, the strictest result winning.
    ///
    /// Any deny refuses, otherwise any ask prompts; an allow rule covers the edit only when it covers every target (a
    /// target no rule matches leaves the decision to the default flow, unlike [`combine_decisions`], where `None` is
    /// neutral). A target behind an unresolvable symlink fails closed as it does for a single-file edit.
    ///
    /// Each target is judged in every spelling of the file the tool writes ([`EditTargetSpellings`]): a deny or ask on
    /// any spelling binds, and only the written path earns an allow (as for a single-file edit, whose symlink re-check
    /// is deny/ask only) - never a Unix spelling with a backslash, which the policy would read as a separator. A target whose physical path cannot be determined fails
    /// closed to a prompt.
    pub(crate) fn evaluate_edit_targets(
        policy: Option<&CompiledPolicy>,
        targets: &[EditTargetSpellings],
        cwd: &Path,
    ) -> Self {
        let mut deny: Option<Decision> = None;
        let mut ask = false;
        let mut all_allow = !targets.is_empty();
        let mut native_symlink_fail_closed = false;
        let mut judge = |spelling: &str| match policy {
            Some(policy) => {
                let (decision, fail_closed) = policy
                    .evaluate_with_cwd_details(&AccessKind::Edit(spelling.to_owned()), Some(cwd));
                native_symlink_fail_closed |= fail_closed;
                decision
            }
            None => None,
        };
        for target in targets {
            let mut written = judge(&target.written);
            let mut restrictive = None;
            for other in target.others() {
                if let Some(decision @ (Decision::Ask | Decision::Reject(_) | Decision::PolicyDeny(_))) =
                    judge(other)
                {
                    restrictive = combine_decisions(restrictive, Some(decision));
                }
            }
            if target.physical.is_none() {
                restrictive = combine_decisions(restrictive, Some(Decision::Ask));
            }
            // Astra r2 H1 / r3 HIGH: a backslash spelling on Unix can match a rule for another file
            if !target.allow_trusted && matches!(written, Some(Decision::Allow)) {
                written = None;
            }
            match combine_decisions(written, restrictive) {
                Some(Decision::Allow) => {}
                Some(Decision::Ask) => {
                    ask = true;
                    all_allow = false;
                }
                Some(refusal @ (Decision::Reject(_) | Decision::PolicyDeny(_))) => {
                    deny.get_or_insert(refusal);
                    all_allow = false;
                }
                _ => all_allow = false,
            }
        }
        let direct = deny
            .or(ask.then_some(Decision::Ask))
            .or(all_allow.then_some(Decision::Allow));
        Self {
            direct,
            bash_command: None,
            shell_file: None,
            native_symlink_fail_closed,
            defers_gate_ask: false,
        }
    }

    /// A tool that reads several files (P174) judged as a `Read` of each, the strictest result winning.
    ///
    /// `targets` holds, per file, every spelling of the file the tool opens (the model's spelling first, then the
    /// spelling the tool resolves it to); a deny or ask on any spelling binds, and only the first earns an allow. A
    /// file that could not be resolved (`false`) is refused. Across
    /// files any deny refuses, otherwise any ask prompts; for a read (`access` is `Read`) an allow rule covers the call
    /// only when it covers every file. For any other access (an image tool that opens local files) the files add only
    /// their deny or ask to the access's own result: reading a file never allows a side effect. The access's own
    /// restrictive result always binds too. A file behind an unresolvable symlink fails closed as for a single read.
    pub(crate) fn evaluate_read_targets(
        policy: Option<&CompiledPolicy>,
        access: &AccessKind,
        targets: &[(Vec<String>, bool)],
        cwd: &Path,
        auto_mode: bool,
    ) -> Self {
        let base = Self::evaluate(policy, access, cwd, auto_mode);
        let Some(policy) = policy else {
            return base;
        };
        let mut deny: Option<Decision> = None;
        let mut ask = false;
        let mut all_allow = !targets.is_empty();
        let mut native_symlink_fail_closed = base.native_symlink_fail_closed;
        for (spellings, resolved) in targets {
            // A target whose file could not be resolved in time is refused (Astra r3: an approvable prompt for the
            // spelling would let the reader open a file nobody judged).
            let mut decision = (!resolved).then(|| {
                Decision::Reject(
                    "the file a read target names could not be resolved in time to check it against Read rules"
                        .to_owned(),
                )
            });
            for (index, spelling) in spellings.iter().enumerate() {
                let (judged, fail_closed) = policy
                    .evaluate_with_cwd_details(&AccessKind::Read(Some(spelling.clone())), Some(cwd));
                native_symlink_fail_closed |= fail_closed;
                match judged {
                    Some(Decision::Allow) if index > 0 => {}
                    judged => decision = combine_decisions(decision, judged),
                }
            }
            match decision {
                Some(Decision::Allow) => {}
                Some(Decision::Ask) => {
                    ask = true;
                    all_allow = false;
                }
                Some(refusal @ (Decision::Reject(_) | Decision::PolicyDeny(_))) => {
                    deny.get_or_insert(refusal);
                    all_allow = false;
                }
                _ => all_allow = false,
            }
        }
        let is_read = matches!(access, AccessKind::Read(_));
        let targets_decision = deny
            .or(ask.then_some(Decision::Ask))
            .or((is_read && all_allow).then_some(Decision::Allow));
        let base_direct = match base.direct {
            // A read's own path is one of `targets` (or it names none): only its refusal or ask still binds.
            Some(Decision::Allow) if is_read => None,
            direct => direct,
        };
        Self {
            direct: combine_decisions(base_direct, targets_decision),
            native_symlink_fail_closed,
            ..base
        }
    }

    /// Combined managed decision (deny > ask > allow).
    pub(crate) fn policy_decision(&self) -> Option<Decision> {
        let bash_command = self.bash_command.clone().map(GateDecision::into_decision);
        let shell_file = self.shell_file.clone().map(GateDecision::into_decision);
        combine_decisions(
            combine_decisions(self.direct.clone(), bash_command),
            shell_file,
        )
    }

    pub(crate) fn policy_forced_prompt(&self) -> bool {
        matches!(self.policy_decision(), Some(Decision::Ask))
    }

    /// Bash-gate Ask, shell-file Ask, or native symlink fail-closed; blocks YOLO.
    pub(crate) fn shell_forced_prompt(&self) -> bool {
        self.bash_command.as_ref().is_some_and(GateDecision::is_ask)
            || self.shell_file_forced_prompt()
            || self.native_symlink_fail_closed
    }

    /// Blocks bash grants from satisfying a Read/Edit ask escalated from shell-file access.
    pub(crate) fn shell_file_forced_prompt(&self) -> bool {
        self.shell_file.as_ref().is_some_and(GateDecision::is_ask)
    }

    /// Whether the auto classifier may run despite a gate Ask: no Ask at all, or a fail-closed Ask that defers.
    pub(crate) fn admits_auto_classifier(&self) -> bool {
        !self.policy_forced_prompt() || self.defers_gate_ask()
    }

    /// Deferral is active: a fail-closed Ask may be classified.
    /// A classifier Block denies within budget; it does not bind like a prompt and still spends budget.
    pub(crate) fn defers_gate_ask(&self) -> bool {
        self.defers_gate_ask
    }

    /// The gate-owned prompt trigger for telemetry, or `None` when a bash floor or plain `needs_user` forced the prompt.
    /// Rule-match Asks keep their gate label; a deferrable Ask does not.
    pub(crate) fn prompt_trigger(
        &self,
        auto_prompt_reason: Option<&'static str>,
    ) -> Option<&'static str> {
        if matches!(self.direct, Some(Decision::Ask)) {
            return Some(reasons::POLICY_ASK);
        }
        // WHY: a preempting request floor owns the reason
        // A deferrable Ask whose classifier a floor blocked (`auto_prompt_reason` None) yields it
        if self.defers_gate_ask() {
            return auto_prompt_reason;
        }
        if self.bash_command.as_ref().is_some_and(GateDecision::is_ask) {
            return Some(reasons::BASH_COMMAND_GATE_ASK);
        }
        if self.shell_file_forced_prompt() {
            return Some(reasons::SHELL_FILE_GATE_ASK);
        }
        auto_prompt_reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::types::{
        PatternMode, PermissionConfig, PermissionRule, RuleAction, ToolFilter,
    };

    fn bash_rule(action: RuleAction, pattern: &str) -> PermissionRule {
        PermissionRule {
            action,
            tool: ToolFilter::Bash,
            pattern: Some(pattern.to_owned()),
            pattern_mode: PatternMode::Glob,
        }
    }

    fn policy() -> CompiledPolicy {
        CompiledPolicy::new(PermissionConfig::new(vec![
            bash_rule(RuleAction::Deny, "rm -rf *"),
            bash_rule(RuleAction::Ask, "git push*"),
        ]))
    }

    #[test]
    fn preflight_reports_gate_state_coherently() {
        let policy = policy();
        let cwd = Path::new("/work");
        let bash = |cmd: &str| AccessKind::Bash(cmd.to_owned());

        // Fail-closed Ask in auto: classified; Block denies within budget; trigger follows classifier outcome.
        let deferred = GatePreflight::evaluate(Some(&policy), &bash("echo \"$(date)\""), cwd, true);
        assert!(deferred.policy_forced_prompt());
        assert!(deferred.admits_auto_classifier());
        assert!(deferred.defers_gate_ask());
        assert_eq!(
            deferred.prompt_trigger(Some(reasons::AUTO_CLASSIFIER_DENY)),
            Some(reasons::AUTO_CLASSIFIER_DENY)
        );

        // Same request outside auto mode: nothing admits the classifier and the gate label is the trigger
        let ask_mode =
            GatePreflight::evaluate(Some(&policy), &bash("echo \"$(date)\""), cwd, false);
        assert!(ask_mode.policy_forced_prompt());
        assert!(!ask_mode.admits_auto_classifier());
        assert!(!ask_mode.defers_gate_ask());
        assert_eq!(
            ask_mode.prompt_trigger(None),
            Some(reasons::BASH_COMMAND_GATE_ASK)
        );

        // Rule-match Ask in auto mode stays binding with its gate label; a rule match never defers, even alongside a fail-closed floor
        let rule_match = GatePreflight::evaluate(
            Some(&policy),
            &bash("echo hi && git push origin main"),
            cwd,
            true,
        );
        assert!(!rule_match.admits_auto_classifier());
        assert!(!rule_match.defers_gate_ask());
        assert_eq!(
            rule_match.prompt_trigger(None),
            Some(reasons::BASH_COMMAND_GATE_ASK)
        );

        // No policy at all: inert preflight.
        let inert = GatePreflight::evaluate(None, &bash("echo hi"), cwd, true);
        assert!(inert.policy_decision().is_none());
        assert!(inert.admits_auto_classifier());
        assert!(!inert.defers_gate_ask());
        assert_eq!(inert.prompt_trigger(None), None);
    }

    #[test]
    #[cfg(unix)]
    fn native_unresolvable_symlink_forces_shell_prompt() {
        use std::os::unix::fs::symlink;

        let ws = tempfile::tempdir().unwrap();
        symlink(ws.path().join("b"), ws.path().join("a")).unwrap();
        symlink(ws.path().join("a"), ws.path().join("b")).unwrap();

        let restricted = CompiledPolicy::new(PermissionConfig::new(vec![PermissionRule {
            action: RuleAction::Deny,
            tool: ToolFilter::Edit,
            pattern: Some("**/unrelated/**".into()),
            pattern_mode: PatternMode::Glob,
        }]));
        let access = AccessKind::Edit("a".into());
        let preflight = GatePreflight::evaluate(Some(&restricted), &access, ws.path(), false);
        assert!(
            matches!(preflight.policy_decision(), Some(Decision::Ask)),
            "expected Ask for unresolvable native symlink"
        );
        assert!(
            preflight.shell_forced_prompt(),
            "expected shell_forced_prompt for YOLO"
        );
        assert_eq!(preflight.prompt_trigger(None), Some(reasons::POLICY_ASK));

        // WHY: Grep-only rules are outside has_file_restrictions but still fail closed.
        let grep_only = CompiledPolicy::new(PermissionConfig::new(vec![PermissionRule {
            action: RuleAction::Deny,
            tool: ToolFilter::Grep,
            pattern: Some("**/unrelated/**".into()),
            pattern_mode: PatternMode::Glob,
        }]));
        let grep_access = AccessKind::Grep {
            path: Some("a".into()),
            glob: None,
        };
        let grep_preflight =
            GatePreflight::evaluate(Some(&grep_only), &grep_access, ws.path(), false);
        assert!(matches!(
            grep_preflight.policy_decision(),
            Some(Decision::Ask)
        ));
        assert!(grep_preflight.shell_forced_prompt());

        let open = CompiledPolicy::new(PermissionConfig::new(vec![]));
        let open_preflight = GatePreflight::evaluate(Some(&open), &access, ws.path(), false);
        assert!(open_preflight.policy_decision().is_none());
        assert!(!open_preflight.shell_forced_prompt());
    }
}
