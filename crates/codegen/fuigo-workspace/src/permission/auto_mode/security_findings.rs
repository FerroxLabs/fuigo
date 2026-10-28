//! A finding is a fixed enum token naming a static-analysis risk the built-in Bash gate detected, plus a fixed harness-owned description.
//! Both are static constants that never carry a command, path, or argument; those stay in the untrusted proposed action.
//! An attacker therefore cannot steer the classifier by smuggling text through a finding.
//! Nonempty findings force the model path (the heuristic pre-pass may not auto-Allow), so the classifier always sees them before approving.

use std::collections::BTreeSet;

/// One built-in Bash security finding; each variant renders to a single stable wire token.
/// `Ord` fixes the canonical render order (variant order below), so [`BashSecurityAssessment`] renders deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClassifierSecurityFinding {
    /// Managed-policy analysis failed closed with no explicit rule match.
    FailClosedPolicy,
    /// Shell structure the parser could not decompose to check.
    UnparseableShell,
    /// Argument values depend on shell expansion.
    UnresolvedArgument,
    /// Nested/opaque shell execution (`bash -c "$X"`, `eval …`).
    OpaqueShell,
    /// Execution callback or ambient Git-config exec risk.
    ExecOrAmbientGit,
    /// Environment injection key (LD_PRELOAD, DYLD_*, GIT_CONFIG*, …).
    EnvInjection,
    /// Environment assignment outside the cosmetic-safe allowlist.
    UnvettedEnv,
    /// Write to a real (non-sink) file.
    FileWrite,
    /// Dangerous command segment (`rm`, `chmod`, `git push`, …).
    DangerousCommand,
    /// Special executable/disclosure surface (`rg --pre`, Git drivers/pagers, kubectl config/auth overrides, process-environment dump).
    SpecialExecSurface,
    /// u35 g8: the inherited environment can change which program runs or what it loads (`PATH` not clean, a
    /// steering variable set). Not a grant floor: it switches off only approval without a grant (the read-only lists,
    /// the Auto mode fast path and heuristic pre-pass; an Auto mode classifier allow is approval without a grant too,
    /// which the shell runner checks against the call's own environment, and u35 g12 (Astra r11 High) asks the user
    /// instead); every grant the user gave still applies.
    InheritedEnvironment,
    /// u35 g10 (Astra r9 High): a git command that is not a read-only query runs in a repository with hooks of its own
    /// (`pre-commit`, `post-checkout`, ...). Like `InheritedEnvironment` not a grant floor: it switches off only approval
    /// without a grant (the Auto mode fast path, heuristic pre-pass and, u35 g11 (Grok r10 Medium), a classifier allow,
    /// which asks the user instead); every grant the user gave still applies.
    RepositoryHook,
}

impl ClassifierSecurityFinding {
    /// Every finding variant, in canonical order.
    /// Cross-crate consumers (telemetry tokens) assert coverage against this list rather than a hand-copied one.
    pub const ALL: &'static [Self] = &[
        Self::FailClosedPolicy,
        Self::UnparseableShell,
        Self::UnresolvedArgument,
        Self::OpaqueShell,
        Self::ExecOrAmbientGit,
        Self::EnvInjection,
        Self::UnvettedEnv,
        Self::FileWrite,
        Self::DangerousCommand,
        Self::SpecialExecSurface,
        Self::InheritedEnvironment,
        Self::RepositoryHook,
    ];

    /// Stable wire token rendered into the classifier system message.
    /// Never changes without a matching classifier-prompt update.
    pub const fn token(self) -> &'static str {
        match self {
            Self::FailClosedPolicy => "fail_closed_policy",
            Self::UnparseableShell => "unparseable_shell",
            Self::UnresolvedArgument => "unresolved_argument",
            Self::OpaqueShell => "opaque_shell",
            Self::ExecOrAmbientGit => "exec_or_ambient_git",
            Self::EnvInjection => "env_injection",
            Self::UnvettedEnv => "unvetted_env",
            Self::FileWrite => "file_write",
            Self::DangerousCommand => "dangerous_command",
            Self::SpecialExecSurface => "special_exec_surface",
            Self::InheritedEnvironment => "inherited_environment",
            Self::RepositoryHook => "repository_hook",
        }
    }

    /// Fixed, harness-owned explanation of the token.
    /// Like [`token`](Self::token) it is a static string carrying no command, path, argument, or user text, so it cannot inject instructions.
    pub const fn description(self) -> &'static str {
        match self {
            Self::FailClosedPolicy => {
                "permission policy could not determine whether a rule applies"
            }
            Self::UnparseableShell => "shell structure could not be fully parsed",
            Self::UnresolvedArgument => "argument values depend on shell expansion",
            Self::OpaqueShell => "invokes a nested or dynamically supplied shell command",
            Self::ExecOrAmbientGit => {
                "may run code via an execution callback or ambient Git configuration"
            }
            Self::EnvInjection => "sets environment variables that can change which code executes",
            Self::UnvettedEnv => "sets environment variables outside the known-safe set",
            Self::FileWrite => "writes to a real file rather than a sink",
            Self::DangerousCommand => "a destructive or high-impact command",
            Self::SpecialExecSurface => {
                "options or tools that can write arbitrary output, execute code, override config/identity, or disclose the process environment"
            }
            Self::InheritedEnvironment => {
                "the environment the command inherits can change which program runs or what it loads"
            }
            Self::RepositoryHook => "the repository has git hooks of its own, which this git command can run",
        }
    }

    /// Whether this finding floors every broad authority, a configured catch-all allow rule included: effects a broad
    /// grant cannot vouch for, so their presence must reach the classifier or a prompt rather than auto-allow.
    /// `FailClosedPolicy` is handled by its own decision arm.
    const fn is_grant_floor(self) -> bool {
        matches!(
            self,
            Self::FileWrite
                | Self::UnvettedEnv
                | Self::EnvInjection
                | Self::OpaqueShell
                | Self::ExecOrAmbientGit
                | Self::SpecialExecSurface
        )
    }

    /// Whether this finding floors a session grant: a prefix/glob grant, the session blanket (`allow_bash_execute`),
    /// sandbox auto-allow and the auto-mode fast path. On top of [`Self::is_grant_floor`], a destructive command and a
    /// command the classifier cannot fully model (an argument only the shell resolves, structure it cannot decompose)
    /// are not covered by a grant given for other commands. A configured catch-all allow rule keeps the narrower
    /// [`Self::is_grant_floor`] set: it is a documented explicit override.
    const fn is_session_grant_floor(self) -> bool {
        self.is_grant_floor()
            || matches!(
                self,
                Self::DangerousCommand | Self::UnresolvedArgument | Self::UnparseableShell
            )
    }
}

/// The single canonical, ordered, deduplicated finding set for one request.
///
/// The `BTreeSet` encodes the ordering/dedup invariant in the type itself, so no caller can supply duplicates or arbitrary order.
/// Built once at the detector sites in `evaluate_bash`; the manager clones it and adds `FailClosedPolicy` when a managed-policy gate failed closed.
/// `Default` is the empty assessment (non-Bash access, or a fully safe command).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BashSecurityAssessment(BTreeSet<ClassifierSecurityFinding>);

impl BashSecurityAssessment {
    pub(crate) fn insert(&mut self, finding: ClassifierSecurityFinding) {
        self.0.insert(finding);
    }

    /// No findings: the command is fully safe by static analysis.
    /// A broad policy Allow or fast path may only skip the classifier when this holds.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether the given finding is present (readable across the crate boundary for callers that key behavior on one specific finding, e.g. tests).
    pub fn contains(&self, finding: ClassifierSecurityFinding) -> bool {
        self.0.contains(&finding)
    }

    /// Whether any finding constrains a broad grant or sandbox auto-allow; the single source for `bash_request_floor_requires_prompt`.
    pub(crate) fn constrains_broad_grant(&self) -> bool {
        self.0
            .iter()
            .copied()
            .any(ClassifierSecurityFinding::is_grant_floor)
    }

    /// Whether any finding floors a session grant, sandbox auto-allow or the auto fast path (see
    /// [`ClassifierSecurityFinding::is_session_grant_floor`]).
    pub(crate) fn constrains_session_grant(&self) -> bool {
        self.0
            .iter()
            .copied()
            .any(ClassifierSecurityFinding::is_session_grant_floor)
    }

    /// u35 g8: whether `InheritedEnvironment` is the only finding (it is not a grant floor). u35 g10: so may
    /// `RepositoryHook` be; neither stops a grant.
    pub(crate) fn is_inherited_environment_only(&self) -> bool {
        !self.0.is_empty()
            && self.0.iter().all(|finding| {
                matches!(
                    finding,
                    ClassifierSecurityFinding::InheritedEnvironment | ClassifierSecurityFinding::RepositoryHook
                )
            })
    }

    /// Whether `FileWrite` is the only finding, the one floor a narrow allow rule naming a write-capable command can vouch for.
    /// Mixed assessments never qualify.
    pub(crate) fn is_file_write_only(&self) -> bool {
        self.0.len() == 1 && self.0.contains(&ClassifierSecurityFinding::FileWrite)
    }

    /// Compact `[token, token]` list in canonical order, for tests to pin the ordered/deduplicated invariant.
    /// The system message uses `render_glossary`.
    #[cfg(test)]
    pub(crate) fn render_tokens(&self) -> String {
        let tokens: Vec<&str> = self.0.iter().map(|f| f.token()).collect();
        format!("[{}]", tokens.join(", "))
    }

    /// Stable, ordered, deduplicated wire tokens for one request; manager telemetry and trace evidence consume this same set the classifier saw.
    /// Crate-private so the finding set never crosses the crate boundary (external OTEL must not gain finding fields).
    pub(crate) fn tokens(&self) -> Vec<String> {
        self.0.iter().map(|f| f.token().to_owned()).collect()
    }

    /// One `- token: description` line per present finding, in canonical order.
    pub(crate) fn render_glossary(&self) -> String {
        self.0
            .iter()
            .map(|f| format!("- {}: {}", f.token(), f.description()))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl FromIterator<ClassifierSecurityFinding> for BashSecurityAssessment {
    fn from_iter<I: IntoIterator<Item = ClassifierSecurityFinding>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(test)]
#[path = "security_findings_tests.rs"]
mod tests;
