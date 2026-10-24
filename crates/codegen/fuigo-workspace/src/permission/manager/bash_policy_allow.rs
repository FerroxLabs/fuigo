//! Configured Bash allows over recovered filename scripts, and the deferral of a configured allow to the request floor.
//!
//! A script such as `LOG=/tmp/log; ls -lh "$LOG"; rg -n ERROR "$LOG" | head` defeats word-only decomposition, so the
//! evaluation recovers it ([`crate::permission::bash_permission_script::PermissionScript`]) without guessing variable
//! values. The functions here decide what such a script may clear.

use super::{
    BashEvaluation, bash_request_floor_requires_prompt, narrow_allow_clears_write_floor,
};
use crate::permission::auto_mode::ClassifierSecurityFinding;
use crate::permission::auto_mode::ClassifierSecurityFinding::{UnresolvedArgument, UnvettedEnv};
use crate::permission::policy::CompiledPolicy;
use crate::permission::types::AccessKind;

/// A configured Allow clears the floor for a recovered filename script whose only findings are the recovered argument
/// and the witnessed assignment.
pub(super) fn configured_filename_allow(evaluation: Option<&BashEvaluation>) -> bool {
    evaluation.is_some_and(|e| {
        e.recovered_eligible
            && ClassifierSecurityFinding::ALL.iter().all(|finding| {
                matches!(finding, UnresolvedArgument | UnvettedEnv)
                    || !e.assessment.contains(*finding)
            })
    })
}

/// Auto mode must classify a recovered script unless an exact whole-script grant already authorizes it.
pub(super) fn requires_recovered_classification(evaluation: Option<&BashEvaluation>) -> bool {
    evaluation.is_some_and(|e| e.assessment.contains(UnresolvedArgument) && !e.exact_grant)
}

/// Whether a configured policy Allow is deferred to the confirmation floor for this request.
/// Callers reach this only on a policy Allow. `configured_mode`: configured rules decide (not dontAsk).
/// `branch_floor_kept`: the branch-switch verdict (see [`narrow_allow_clears_write_floor`]).
pub(super) fn broad_allow_deferred(
    evaluation: Option<&BashEvaluation>,
    policy: Option<&CompiledPolicy>,
    access: &AccessKind,
    configured_mode: bool,
    branch_floor_kept: bool,
) -> bool {
    (requires_recovered_classification(evaluation)
        || bash_request_floor_requires_prompt(evaluation))
        && !narrow_allow_clears_write_floor(evaluation, policy, access, branch_floor_kept)
        && !(configured_mode && configured_filename_allow(evaluation))
}
