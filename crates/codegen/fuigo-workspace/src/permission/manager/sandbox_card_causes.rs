//! Why a shell command is asked about, in the terms the sandbox-card rule reads
//! ([`crate::permission::sandbox_card::card_replaces`]). Pure over one [`BashEvaluation`]: it decides
//! nothing, it only names each reason the default prompt has so the rule can weigh them.

use super::{BashEvaluation, SegmentEvaluation};
use crate::permission::auto_mode::ClassifierSecurityFinding as Finding;
use crate::permission::branch_switch::BranchSwitchPlan;
use crate::permission::sandbox_card::{AskCause, SandboxCover};
use fuigo_tools::types::resources::resolve_model_path;
use std::path::Path;

/// The plain network clients: a segment that is one of these, with nothing else wrong with the command, is
/// an egress ask. A closed list on purpose: a tool not on it keeps its ask.
const NETWORK_CLIENTS: [&str; 2] = ["curl", "wget"];

/// Every reason the default prompt has for this command (`policy_allows`: a configured allow rule matched
/// it, so the ask is the broad-allow deferral to the request floor; otherwise the ask is the default one).
pub(super) fn bash_ask_causes(
    evaluation: &BashEvaluation,
    policy_allows: bool,
    branch_plan: &BranchSwitchPlan,
    cwd: &Path,
    cover: &SandboxCover,
) -> Vec<AskCause> {
    let mut causes: Vec<AskCause> = Vec::new();
    let mut push = |cause: AskCause| {
        if !causes.contains(&cause) {
            causes.push(cause);
        }
    };
    let findings = &evaluation.assessment;
    for finding in Finding::ALL
        .iter()
        .copied()
        .filter(|f| findings.contains(*f))
    {
        push(match finding {
            Finding::UnparseableShell => AskCause::UnparseableShell,
            Finding::UnvettedEnv => AskCause::UnvettedEnv,
            Finding::UnresolvedArgument => AskCause::UnresolvedArgument,
            Finding::FileWrite if policy_allows && findings.is_file_write_only() => {
                AskCause::FileWriteDeferral {
                    inside_scope: writes_stay_in_scope(evaluation, branch_plan, cwd, cover),
                }
            }
            Finding::FileWrite => AskCause::Kept("a file write no allow rule covers"),
            Finding::FailClosedPolicy => AskCause::Kept("the policy could not be checked"),
            Finding::OpaqueShell => AskCause::Kept("a nested or dynamic shell"),
            Finding::ExecOrAmbientGit => {
                AskCause::Kept("an execution callback or ambient git config")
            }
            Finding::EnvInjection => AskCause::Kept("environment injection"),
            Finding::DangerousCommand => AskCause::Kept("a destructive or high-impact command"),
            Finding::SpecialExecSurface => AskCause::Kept("a special executable or disclosure surface"),
            // u35 g7/g8: the inherited variable (`PATH`, `LD_PRELOAD`, ...) that decided.
            Finding::InheritedEnvironment => {
                AskCause::Kept(evaluation.env_steering.unwrap_or("the inherited environment"))
            }
            Finding::RepositoryHook => AskCause::Kept("the repository's own git hooks"),
        });
    }
    // With an allow rule the segments are the rule's business; without one each segment that is not
    // safe-listed is a reason of its own.
    if !policy_allows {
        match &evaluation.segments {
            SegmentEvaluation::AutoAllow { .. } => {}
            SegmentEvaluation::Unparseable => push(AskCause::UnparseableShell),
            SegmentEvaluation::NeedsPrompts { segments } => {
                for segment in segments {
                    // u35 r3: a read-only command asked about only because the script is not plain text.
                    push(if evaluation.gated_segments.contains(segment) {
                        AskCause::UnparseableShell
                    } else if is_network_client(segment) {
                        AskCause::NetworkEgress
                    } else {
                        AskCause::Kept("a command outside the safe list")
                    });
                }
            }
            SegmentEvaluation::Reject(_) => push(AskCause::Kept("a command the user rejected")),
        }
    }
    causes
}

/// Whether a prompted segment (the unwrapped command, words joined by a space) is a plain network client.
fn is_network_client(segment: &str) -> bool {
    let Some(first) = segment.split_whitespace().next() else {
        return false;
    };
    crate::permission::policy::normalized_command_head(&[first.to_owned()])
        .is_some_and(|head| NETWORK_CLIENTS.contains(&head.as_str()))
}

/// Whether every write of the script is concrete and inside the sandbox's write scope. A script that runs
/// git (a branch switch, a pull, a clean rewrite files no target names), a branch-switch plan, a symbolic
/// link, a write nothing can pin, and a script with no concrete write at all are all "not known".
fn writes_stay_in_scope(
    evaluation: &BashEvaluation,
    branch_plan: &BranchSwitchPlan,
    cwd: &Path,
    cover: &SandboxCover,
) -> bool {
    matches!(branch_plan, BranchSwitchPlan::NotApplicable)
        && evaluation.write_facts.writes_stay_within(
            cwd,
            |base, path| resolve_model_path(base, None, path),
            |path| cover.contains_write(path),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The causes the default prompt names for `cmd` with no grant and no allow rule, under a standing cover.
    fn causes(cmd: &str) -> Vec<AskCause> {
        let evaluation = super::super::evaluate_bash(cmd, &super::super::PermissionState::default(), true);
        let cover = SandboxCover::for_test(false, vec![PathBuf::from("/ws")]);
        bash_ask_causes(&evaluation, false, &BranchSwitchPlan::NotApplicable, Path::new("/ws"), &cover)
    }

    /// g4 (Fable r3 M2): a read-only command asked about only because it is not plain text is named as unparseable
    /// shell; the same form of a program outside the safe list, or a form with a finding of its own, keeps its cause.
    #[test]
    fn gate_only_asks_are_named_unparseable_shell() {
        for cmd in ["ls ~/x", "ls src/*.rs", "ls 2>&1", "cd src && git status", "command ls -la"] {
            assert_eq!(causes(cmd), vec![AskCause::UnparseableShell], "{cmd:?}");
        }
        assert_eq!(causes("foo ~/x"), vec![AskCause::Kept("a command outside the safe list")]);
        assert_eq!(
            causes("cat *.md"),
            vec![AskCause::UnresolvedArgument, AskCause::Kept("a command outside the safe list")]
        );
    }
}
