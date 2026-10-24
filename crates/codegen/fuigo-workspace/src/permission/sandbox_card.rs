//! Which shell asks the sandbox card stands in for.
//!
//! The folder's per-command sandbox settles a violation with a card after the run (`sandbox_gate`). When a
//! command is really wrapped by a backend under `enforce`, four of the permission policy's own asks become
//! redundant: what they guard against is what the wrapper confines. This module is the ONE place that says
//! which, so the list can be read, tested and documented in a single spot ([`card_replaces`]).
//!
//! The condition is checked per call at decision time ([`SandboxCover::for_call`]), from the sandbox's state
//! as the hub just read it for this very call (the same mode the call is then pinned to), never from a value
//! cached at session start. A folder whose `enforce` fell back to `off`, a mode that is `off` or `observe`, a
//! command the hub does not run through the wrapper (a background run, a shell whose output the decoder does
//! not read) and a sandbox flipped off since the last call all produce no cover, and every ask comes back.
//!
//! The list (user guide `18-sandbox.md` carries the same words):
//! 1. the unparseable-shell prompt;
//! 2. the unvetted-environment floor;
//! 3. the unresolved-argument floor;
//! 4. network egress asks, only while the folder's egress proxy is serving;
//! 5. the file-write-only deferral of a broad allow, only when every write target stays inside the
//!    sandbox's write scope.
//!
//! Never replaced, whatever the state: the protected-target floor, host-effect asks (`ExecOrAmbientGit`,
//! `DangerousCommand`, env injection, nested shells, special exec surfaces), user deny and ask rules, hook
//! asks, the peer guard, every non-shell tool. Those never reach [`card_replaces`]: they are decided before
//! the default prompt, or they put a [`AskCause::Kept`] in the ask's causes.

use crate::permission::sandbox_gate::SandboxPath;
use crate::sandbox::WorkspaceSandbox;
use fuigo_sandbox::command::SandboxMode;
use std::path::{Path, PathBuf};

/// What the sandbox guarantees for ONE call, built when the call is decided and dropped with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SandboxCover {
    /// The folder's egress proxy was bound and serving when the call was decided.
    proxy_serving: bool,
    /// The directories a wrapped command may write under, canonical.
    write_roots: Vec<PathBuf>,
}

impl SandboxCover {
    /// The cover for a call, or `None` when its command is not really wrapped by a backend under `enforce`.
    ///
    /// `mode` is the folder's mode as the hub read it for this call (after the folder engaged, so an
    /// `enforce` that fell back to `off` for want of a backend already reads `off`); `path` is the call's
    /// sandbox path (only a foreground shell whose output the decoder reads is `Gated`). The backend is
    /// asked once more, so a mode that says `enforce` with no backend behind it still yields no cover.
    pub(crate) fn for_call(
        sandbox: Option<&WorkspaceSandbox>,
        mode: Option<SandboxMode>,
        path: SandboxPath,
    ) -> Option<SandboxCover> {
        let sandbox = sandbox?;
        if path != SandboxPath::Gated
            || mode != Some(SandboxMode::Enforce)
            || sandbox.backend_name().is_none()
        {
            return None;
        }
        Some(SandboxCover {
            proxy_serving: sandbox.proxy().is_some(),
            write_roots: sandbox.write_scope_roots(),
        })
    }

    /// Whether a write to `path` stays inside the sandbox's write scope: every link followed (a missing
    /// leaf included), under one of the write roots, and not inside a `.git` directory. A path that cannot
    /// be resolved is outside.
    pub(crate) fn contains_write(&self, path: &Path) -> bool {
        let Some(target) = crate::permission::sandbox_gate::write_target(path) else {
            return false;
        };
        !target.components().any(|part| part.as_os_str() == ".git")
            && self.write_roots.iter().any(|root| target.starts_with(root))
    }

    #[cfg(test)]
    pub(crate) fn for_test(proxy_serving: bool, write_roots: Vec<PathBuf>) -> SandboxCover {
        SandboxCover {
            proxy_serving,
            write_roots,
        }
    }
}

/// Why a shell command would be asked about: one entry per distinct reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AskCause {
    /// The script could not be decomposed (or only recovered).
    UnparseableShell,
    /// An environment assignment outside the known-safe set.
    UnvettedEnv,
    /// Argument values that depend on shell expansion.
    UnresolvedArgument,
    /// A segment that is a plain network client (`curl`, `wget`) and nothing else needs a decision.
    NetworkEgress,
    /// A configured broad allow deferred to the floor for a file write, the write being the only finding.
    /// `inside_scope`: every write target is concrete and inside the sandbox's write scope.
    FileWriteDeferral { inside_scope: bool },
    /// Anything else. Named for the debug log; never replaced.
    Kept(&'static str),
}

/// The asks of the list, by name (also what the user guide prints, in this order).
pub(crate) const REPLACED_ASKS: [&str; 5] = [
    "unparseable shell",
    "unvetted environment",
    "unresolved argument",
    "network egress",
    "file write inside the sandbox's write scope",
];

/// THE RULE. Whether the sandbox card replaces the ask whose causes are `causes`: yes only when there is a
/// cover and EVERY cause is on the list (one cause off it keeps the whole ask). Returns the names of the
/// replaced asks when it does, and logs each at debug with its reason; `None` keeps the ask.
pub(crate) fn card_replaces(
    causes: &[AskCause],
    cover: Option<&SandboxCover>,
) -> Option<Vec<&'static str>> {
    let cover = cover?;
    if causes.is_empty() {
        return None;
    }
    let mut replaced = Vec::with_capacity(causes.len());
    for cause in causes {
        let verdict: Result<(&'static str, &'static str), &'static str> = match cause {
            AskCause::UnparseableShell => Ok((
                REPLACED_ASKS[0],
                "the wrapper confines whatever the script runs",
            )),
            AskCause::UnvettedEnv => Ok((
                REPLACED_ASKS[1],
                "the wrapper filters the environment and confines the command",
            )),
            AskCause::UnresolvedArgument => Ok((
                REPLACED_ASKS[2],
                "the wrapper confines whatever the arguments expand to",
            )),
            AskCause::NetworkEgress if cover.proxy_serving => Ok((
                REPLACED_ASKS[3],
                "the egress proxy serves this command and asks per host",
            )),
            AskCause::NetworkEgress => Err("the egress proxy is not serving this command"),
            AskCause::FileWriteDeferral { inside_scope: true } => Ok((
                REPLACED_ASKS[4],
                "every write target is inside the sandbox's write scope",
            )),
            AskCause::FileWriteDeferral {
                inside_scope: false,
            } => Err("a write target is not known to stay inside the sandbox's write scope"),
            AskCause::Kept(why) => Err(why),
        };
        match verdict {
            Ok(replacement) => replaced.push(replacement),
            Err(why) => {
                tracing::debug!(why, "sandbox card does not replace the ask");
                return None;
            }
        }
    }
    for (ask, reason) in &replaced {
        tracing::debug!(
            ask = *ask,
            reason = *reason,
            "sandbox card replaces the ask"
        );
    }
    Some(replaced.into_iter().map(|(ask, _)| ask).collect())
}

#[cfg(test)]
#[path = "sandbox_card_tests.rs"]
mod tests;
