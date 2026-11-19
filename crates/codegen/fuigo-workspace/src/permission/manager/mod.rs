use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use crate::permission::peer_guard::PeerInfluence;
use parking_lot::Mutex;

use agent_client_protocol as acp;
use chrono::Utc;
use fuigo_acp_lib::AcpAgentGatewaySender as GatewaySender;
use tokio::sync::{mpsc, oneshot};

use crate::permission::auto_mode::{
    BashSecurityAssessment, ClassifierSecurityFinding, ClassifierVerdict, EnvRisk,
    kubectl_word_is_unsafe_flag, rg_has_unsafe_flag, script_env_risk,
};
use crate::permission::bash_command_splitting::{
    argv_starts_with_words, is_setup_command, program_identity_is_plain, try_parse_shell,
    try_parse_word_only_commands_sequence, unwrap_wrappers,
};
use crate::permission::bash_permission_script::PermissionScript;
use crate::permission::branch_switch::{
    BranchSwitchPlan, GitTreeLister, TreeLister, plan_keeps_floor,
};
use crate::permission::exec_risk::{
    AmbientGitRisk, AmbientScanPlan, SAFE_GIT_SUBCOMMANDS, ambient_git_risk_from_plan,
    ambient_git_risk_from_plan_in, ambient_scan_plan_from_segments, branch_switch_plan_with,
    git_words_are_read_only_query, git_words_have_unsafe_query_option, script_may_invoke_git,
    segment_exec_facts,
};
use crate::permission::exec_surface::segment_has_exec_surface;
use crate::permission::gate_preflight::{EditTargetSpellings, GatePreflight};
use crate::permission::policy::{CompiledPolicy, ShellWord};
use crate::permission::prompter::{AcpPrompter, PromptOutcome, PromptOutcomeKind};
use crate::permission::shell_access::{
    command_write_paths_split, edit_target_protection, is_creation_program, is_safe_write_sink,
    tree_has_opaque_shell, words_are_opaque_shell,
};
use crate::permission::state::{PermissionState, persist_state, replace_state_on_disk};
use crate::permission::types::{
    AccessKind, ClientType, Decision, EditPolicy, EditTargets, PermissionCommand, PermissionEvent,
    PermissionRequest, PermissionResolution, PromptPolicy, describe_edit_targets,
    describe_read_targets,
};
use fuigo_mcp::servers::parse_mcp_qualified_name;
use fuigo_paths::AbsPathBuf;
use fuigo_tools::implementations::fuigo_build::web_fetch::{
    DomainMatcher, config::DEFAULT_ALLOWED_DOMAINS, domain::normalize_domain,
};
use fuigo_tools::types::resources::resolve_model_path;
use std::path::Path;

#[cfg(test)]
mod apply_patch_target_tests;
mod bash_grants;
mod bash_policy_allow;
#[cfg(test)]
mod p166_r10_tests;
#[cfg(test)]
mod p166_r11_tests;
#[cfg(test)]
mod p166_r12_fp_tests;
#[cfg(test)]
mod p166_r12_tests;
#[cfg(test)]
mod p166_r13_tests;
#[cfg(test)]
pub(crate) mod p166_r13b_branch_tests;
#[cfg(test)]
mod p166_r13b_tests;
#[cfg(test)]
mod p166_r7_sweep_tests;
#[cfg(test)]
mod p166_r7_tests;
#[cfg(test)]
mod p166_r8_sweep_tests;
#[cfg(test)]
mod p166_r8_tests;
#[cfg(test)]
mod p166_r8b_tests;
#[cfg(test)]
mod p166_r9_fp_tests;
#[cfg(test)]
mod p166_r9_tests;
#[cfg(test)]
mod p175_tests;
#[cfg(test)]
mod peer_denials_tests;
#[cfg(test)]
mod peer_guard_shell_tests;
#[cfg(test)]
mod peer_guard_tests;
#[cfg(test)]
mod peer_note_tests;
#[cfg(test)]
mod read_target_tests;
pub mod reasons;
mod request_classification;
#[cfg(test)]
mod u35_classify_tests;

mod sandbox_card_causes;
pub use bash_grants::{always_allow_row_is_effective, always_allow_scope_persists};
use bash_grants::{
    bash_glob_covers_script, bash_grant_segments, persist_bash_always_allow, whole_script_grant,
};
use bash_policy_allow::{
    broad_allow_deferred, configured_filename_allow, requires_recovered_classification,
};

pub use request_classification::{AUTO_DENY_CONSECUTIVE_LIMIT, AUTO_DENY_TOTAL_LIMIT};
use request_classification::{
    AUTO_DENY_GUIDANCE, ClassificationOutcome, ClassificationSource, DenialCounters,
    RequestClassification, permission_mode_artifact_str,
};

/// Increments the in-flight permission-request counter on construction and decrements it on drop, so every `request()` return path stays balanced.
struct InFlightGuard(Arc<AtomicUsize>);

impl InFlightGuard {
    fn new(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter.clone())
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// What `effective_mode()` needs beyond the yolo/auto flags. `base` is fixed at spawn from the resolved config;
/// `session_edit_grant` mirrors the actor's `allow_edits_for_session` (set on `AllowEditsForSession`, cleared on `ResetState`).
#[derive(Clone)]
pub struct ModeView {
    /// Fixed at spawn from the resolved config. The rule set it is derived from (incl. the catch-all `Allow Any`
    /// check) cannot change afterwards: `compiled_policy` is an immutable `let` in the actor (below), "always
    /// allow" answers write `PermissionState` and never rules, and no `PermissionCommand` carries a rule.
    pub base: crate::permission::types::EffectivePermissionMode,
    pub session_edit_grant: Arc<AtomicBool>,
    /// yolo (bit 0) and auto (bit 1) in ONE atomic so a reader can never see a torn pair. Every writer of
    /// `yolo_state` / `auto_state` also updates this through `pair_set_yolo` / `pair_set_auto`, each a single
    /// `fetch_update`. Only the states those operations produce are ever stored, and a reader takes one load,
    /// so it observes exactly one state that existed: never "neither" while moving between yolo and auto.
    pub mode_pair: Arc<AtomicU8>,
    /// Peer-influenced flag (S6.1), read by the guard on every request.
    pub peer_influence: PeerInfluence,
    /// Where a relative model path resolves when a request carries no path context (the session cwd at spawn).
    pub fallback_cwd: Option<std::path::PathBuf>,
    /// 1.0.36 item a: the session's own launch policy file (pinned), carried so subagents and workflows that build their
    /// own actor get the same snapshot. `None` for an ungoverned session.
    pub launch_policy: Option<Arc<crate::permission::launch_policy::LaunchPolicy>>,
}

const PAIR_YOLO: u8 = 0b01;
const PAIR_AUTO: u8 = 0b10;

fn pair_set_yolo(pair: &AtomicU8, clamped: bool) {
    let _ = pair.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
        Some(if clamped {
            (v | PAIR_YOLO) & !PAIR_AUTO
        } else {
            v & !PAIR_YOLO
        })
    });
}

fn pair_set_auto(pair: &AtomicU8, enabled: bool) {
    let _ = pair.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
        Some(if enabled {
            (v | PAIR_AUTO) & !PAIR_YOLO
        } else {
            v & !PAIR_AUTO
        })
    });
}

impl Default for ModeView {
    fn default() -> Self {
        Self {
            base: crate::permission::types::EffectivePermissionMode::Default,
            session_edit_grant: Arc::new(AtomicBool::new(false)),
            mode_pair: Arc::new(AtomicU8::new(0)),
            peer_influence: PeerInfluence::new(),
            fallback_cwd: None,
            launch_policy: None,
        }
    }
}

#[derive(Clone)]
pub enum PermissionHandle {
    Actor {
        cmd_tx: mpsc::UnboundedSender<PermissionCommand>,
        yolo_state: Arc<AtomicBool>,
        /// Auto mode (LLM classifier), mutually exclusive with yolo at runtime.
        auto_state: Arc<AtomicBool>,
        /// True when the installed auto classifier has a live `ClassifyTextFn` (session sampling side-query).
        /// False for heuristic-only fallbacks.
        side_query_wired: Arc<AtomicBool>,
        /// Managed-policy pin cached at spawn.
        /// When `Some`, the agent re-clamps every client-supplied yolo to non-yolo; `None` means no pin.
        yolo_pin: Option<&'static str>,
        /// Grep Read-deny globs, carried so subagents inherit the parent's excludes.
        deny_read_globs: Arc<Vec<String>>,
        /// Concurrent in-flight permission requests.
        /// Shared across handle clones (subagents), so the actor can gauge overlapping requests for telemetry.
        in_flight: Arc<AtomicUsize>,
        /// Prompt-start only; auto-allow paths never send.
        user_prompt_notify: Arc<Mutex<Option<mpsc::UnboundedSender<()>>>>,
        /// Read-only view of the configured mode and the session edit grant, for `effective_mode()`.
        mode_view: ModeView,
    },
    /// Allows everything, except what the peer guard denies: it carries the session's peer-influenced flag.
    AllowAll(PeerInfluence),
}

/// True iff `name` is a valid qualified MCP ID whose server is in `servers`.
/// Malformed names fail closed, including `{""}` or names like `"__tool"`.
fn mcp_server_prefix_allowed(name: &str, servers: &HashSet<String>) -> bool {
    !servers.is_empty()
        && parse_mcp_qualified_name(name).is_some_and(|(_, server, _)| servers.contains(server))
}

/// Audit S6-F4: what [`note_mcp_definition`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpDefinitionNote {
    /// No definition known for the call, or not a qualified MCP name: nothing checked.
    Unknown,
    /// The definition recorded for the server.
    Same,
    /// None was recorded (a grant from before definitions were recorded): recorded now.
    Recorded,
    /// Not the recorded definition: warned about, and recorded.
    Changed,
}

/// Audit S6-F4: a remembered MCP grant is keyed by name. The definition the server had when the grant was given or last
/// used is recorded with it, and a call that reaches a different definition under that name is warned about loudly.
/// Warning only: the grant still applies (peers key MCP approvals by name too), and the new definition is recorded, so
/// the warning is given once per change.
fn note_mcp_definition(
    state: &mut PermissionState,
    name: &str,
    definition: Option<&str>,
    legacy: Option<&str>,
) -> McpDefinitionNote {
    let (Some(definition), Some((_, server, _))) = (definition, parse_mcp_qualified_name(name))
    else {
        return McpDefinitionNote::Unknown;
    };
    match state
        .mcp_server_definitions
        .insert(server.to_owned(), definition.to_owned())
    {
        Some(old) if old == definition => McpDefinitionNote::Same,
        None => McpDefinitionNote::Recorded,
        // A grant recorded by 1.0.45 holds the fingerprint that release computed: the definition did not change, the
        // fingerprint rule did. Re-recorded (already done by the insert above) without a message.
        Some(old) if legacy == Some(old.as_str()) => McpDefinitionNote::Recorded,
        Some(_) => {
            tracing::warn!(%server, "MCP server definition changed since its always-allow grant; the grant still applies");
            let warning = format!(
                "the MCP server `{server}` has an \"always allow\" grant, but its definition (command or URL) \
                 changed since then; its tools still run without asking. If you did not change it, check where the \
                 server is defined (a project config can define a server under the same name)."
            );
            // The TUI discards stderr, so the same text also goes through the notice list the session shows.
            fuigo_config::mcp_bearer_file::record_note(warning.clone());
            fuigo_tty_utils::cli_eprintln!("warning: {warning}");
            McpDefinitionNote::Changed
        }
    }
}

/// Audit S6-F4: record the definition an "always allow" MCP grant is given for (no warning: the user just answered).
fn record_mcp_definition(state: &mut PermissionState, name: &str, definition: Option<&str>) {
    if let (Some(definition), Some((_, server, _))) = (definition, parse_mcp_qualified_name(name)) {
        state
            .mcp_server_definitions
            .insert(server.to_owned(), definition.to_owned());
    }
}

/// Pre-decision lookup for an MCP tool.
/// A remembered "never allow" rejects, checked before the `ask`-floor early return so a deny wins over any grant (mirroring the bash disallow path).
/// A tool or server-prefix grant allows; anything else returns `None` and falls through to the prompt.
///
/// An `ask` policy rule (`policy_forced_prompt`) normally overrides a grant and forces a re-prompt.
/// With `remember_tool_approvals` on, an existing grant instead satisfies the rule (ask once, then remember); ungranted tools still prompt.
fn mcp_pre_decision(
    name: &str,
    state: &PermissionState,
    policy_forced_prompt: bool,
    remember_tool_approvals: bool,
) -> Option<Decision> {
    // Exact qualified `server__tool` match, same lookup key as `allowed_mcp_tools`
    if state.disallowed_mcp_tools.contains(name) {
        tracing::debug!(%name, source = "session_denylist_tool", "MCP tool auto-rejected");
        return Some(Decision::Reject(format!(
            "User previously rejected `{name}` in this project"
        )));
    }
    if policy_forced_prompt && !remember_tool_approvals {
        return None;
    }
    if state.allowed_mcp_tools.contains(name) {
        tracing::debug!(
            %name,
            source = "session_allowlist_tool",
            "MCP tool auto-approved"
        );
        return Some(Decision::Allow);
    }
    if mcp_server_prefix_allowed(name, &state.allowed_mcp_servers) {
        tracing::debug!(
            %name,
            source = "session_allowlist_server",
            "MCP tool auto-approved"
        );
        return Some(Decision::Allow);
    }
    None
}

/// Canonical key for a persisted web_fetch deny: the host lowercased with the trailing dot trimmed.
/// `www.` stays, unlike in the allow side's `normalize_domain`.
/// The deny matcher covers subdomains, so `www.com` stored as `com` would deny every `.com` host.
/// Entry `example.com` still denies `www.example.com`, because `www.` is an ordinary subdomain label to the matcher.
pub(crate) fn web_fetch_deny_key(host: &str) -> String {
    host.trim().trim_end_matches('.').to_lowercase()
}

/// [`web_fetch_deny_key`] of a raw URL's host, if it parses to a non-empty one.
pub(crate) fn web_fetch_deny_key_from_url(url: &str) -> Option<String> {
    let key = web_fetch_deny_key(url::Url::parse(url).ok()?.host_str()?);
    (!key.is_empty()).then_some(key)
}

/// The persisted "never allow" entry matching a web_fetch host, if any.
/// A deny covers the exact host and its subdomains, but never a parent of the entry.
/// That is broader than the exact-match allow lookup on purpose: denies fail safe.
/// Returns the matched entry so the rejection reason names the persisted key.
pub(crate) fn denied_web_fetch_domain<'a>(
    host: &str,
    disallowed: &'a HashSet<String>,
) -> Option<&'a str> {
    if disallowed.is_empty() {
        return None;
    }
    let domain = web_fetch_deny_key(host);
    disallowed
        .iter()
        .find(|denied| {
            // A hand-edited empty entry must never match (it would match any host ending in '.')
            !denied.is_empty()
                && (domain == **denied
                    || (domain.len() > denied.len() + 1
                        && domain.ends_with(denied.as_str())
                        && domain.as_bytes()[domain.len() - denied.len() - 1] == b'.'))
        })
        .map(String::as_str)
}

/// Session-deny pre-decision for a web_fetch URL: `Some(Reject)` when the host (or a parent domain of it) is on `disallowed_web_fetch_domains`.
/// Consulted before every allow source (static allowlist, persisted grant), so a remembered deny wins over grants, mirroring the bash disallow path.
fn web_fetch_deny_pre_decision(parsed_url: &url::Url, state: &PermissionState) -> Option<Decision> {
    let denied =
        denied_web_fetch_domain(parsed_url.host_str()?, &state.disallowed_web_fetch_domains)?;
    tracing::debug!(
        url = %parsed_url,
        %denied,
        source = "session_denylist",
        "web_fetch domain auto-rejected"
    );
    Some(Decision::Reject(format!(
        "User previously rejected `{denied}` in this project"
    )))
}

/// True when `words` is a `kubectl` invocation that selects a caller-controlled kubeconfig, endpoint, auth, or identity.
///
/// A kubeconfig `users[].user.exec` credential plugin runs an arbitrary local process.
/// A read verb like `get`/`logs`/`describe` is not side-effect-free once any of these flags point kubectl at attacker-supplied config/auth.
/// Such invocations must not ride the safe-command auto-allow (nor a broader whitelist *prefix* grant, see `evaluate_bash`).
/// The flag test is [`kubectl_word_is_unsafe_flag`] (over `KUBECTL_UNSAFE_FLAGS`) so the two classifiers cannot drift.
fn kubectl_has_unsafe_flag(words: &[String]) -> bool {
    if crate::permission::policy::normalized_command_head(words).as_deref() != Some("kubectl") {
        return false;
    }
    words.iter().skip(1).any(|w| kubectl_word_is_unsafe_flag(w))
}

/// True when `words` is a `ps` that dumps process environments.
///
/// Dashless `e`/`E` dumps env on BSD/macOS/Linux (`ps e`, `ps auxe`).
/// Uppercase `E` dumps env on macOS (`-E`); we prompt on any `E` on all platforms because the runtime OS is unknown (fail-safe).
/// Lowercase `-e` stays select-all.
/// Linux procps reinterprets dash clusters containing the lowercase BSD selectors `a`/`x` as BSD mode, so `-auxe`/`-axe` dump env.
/// Plain UNIX `-e`/`-ef`/`-Ae` stay select-all; the `a`/`x` match is deliberately case-sensitive so `-Ae` is not treated as BSD.
/// Value operands of format/select flags (`-o etime`, `o command`, `-eo pid,cmd`) are skipped so they are not mistaken for option clusters.
fn ps_dumps_environment(words: &[String]) -> bool {
    if crate::permission::policy::normalized_command_head(words).as_deref() != Some("ps") {
        return false;
    }
    let mut skip_next = false;
    for w in words.iter().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        let s = w.as_str();
        if s.starts_with("--format=") || s.starts_with("--sort=") {
            continue;
        }
        // Only flags whose VALUES can contain e/E need listing; an omission merely over-prompts (never leaks)
        // Skipping only ever swallows a ps operand
        if matches!(
            s,
            "-o" | "-O"
                | "--format"
                | "--sort"
                | "-p"
                | "-q"
                | "-t"
                | "-u"
                | "-U"
                | "-g"
                | "-G"
                | "-C"
                | "-s"
                | "--pid"
                | "--ppid"
                | "--sid"
                | "--tty"
                | "--user"
                | "--group"
                | "--cols"
                | "--columns"
                | "--width"
                // BSD dashless format selectors take a following format list.
                | "o"
                | "O"
        ) {
            skip_next = true;
            continue;
        }
        // Attached short form: `-oetime`, `-Opid`, …
        if s.starts_with("-o") || s.starts_with("-O") {
            continue;
        }

        // Env-dump option letters (checked before the trailing-o skip so `-Eo`/`-axeo` still force a prompt)
        let has_upper_e = s.contains('E');
        let has_lower_e = s.contains('e');
        let dashless = !s.starts_with('-');
        // Lowercase a/x only: `-Ae` is UNIX select-all, `-AE` has an E and dumps env
        let bsd_selector_cluster =
            s.starts_with('-') && !s.starts_with("--") && s.contains(['a', 'x']);
        if has_upper_e || (has_lower_e && (dashless || bsd_selector_cluster)) {
            return true;
        }

        // Short cluster ending in arg-taking `o`/`O` (`-eo etime`, `-axo cmd`): the next word is the format list, not an option cluster
        if s.starts_with('-') && !s.starts_with("--") && s.ends_with(['o', 'O']) {
            skip_next = true;
            continue;
        }
    }
    false
}

/// Check whether the command words (already parsed by tree-sitter) match one of the known safe command prefixes.
fn is_safe_command_words(words: &[String]) -> bool {
    if words.is_empty() {
        return false;
    }
    // `rg --pre` / `--hostname-bin` stay one bash segment whose primary is still `rg`, so they must not ride the safe-command auto-allow
    if rg_has_unsafe_flag(words) {
        return false;
    }
    if kubectl_has_unsafe_flag(words) {
        return false;
    }
    if ps_dumps_environment(words) {
        return false;
    }
    // u35 g3: a listed program in a form that writes, changes state or reads an unnamed file is not read-only.
    if crate::permission::safe_forms::listed_form_needs_approval(words) {
        return false;
    }
    // Git rides its own shared decision helper (verb allowlist and unsafe-option table in `exec_risk.rs`), not the string prefixes below
    if words.first().map(String::as_str) == Some("git") {
        return git_words_are_read_only_query(words);
    }
    // u35 r1: matched on argv boundaries, so one word with a space in it is not a command plus operands.
    safe_command_prefixes_match(|pattern| argv_starts_with_words(words, pattern, false))
}

fn matches_command_prefix(cmd: &str, pattern: &str) -> bool {
    cmd == pattern || (cmd.starts_with(pattern) && cmd.as_bytes().get(pattern.len()) == Some(&b' '))
}

/// `git <read-only verb>` prefix match, derived from the single [`SAFE_GIT_SUBCOMMANDS`] verb table.
/// String-level only (whitelist scope and fallback); the words paths decide via [`git_words_are_read_only_query`], which also rejects unsafe options.
fn is_safe_git_query_prefix(cmd: &str) -> bool {
    cmd.strip_prefix("git ").is_some_and(|rest| {
        SAFE_GIT_SUBCOMMANDS
            .iter()
            .any(|verb| matches_command_prefix(rest, verb))
    })
}

/// Shared prefix check used by both the tree-sitter path and the fallback path.
fn is_safe_command_words_str(cmd: &str) -> bool {
    is_safe_git_query_prefix(cmd)
        || SAFE_COMMAND_PREFIXES
            .iter()
            .any(|pattern| matches_command_prefix(cmd, pattern))
}

/// Read-only command prefixes, matched on a word boundary (string form) or argv boundaries (words form).
/// Git read-only queries ride `is_safe_git_query_prefix` / `git_words_are_read_only_query` instead.
/// `echo` / `printf` are stdout-only; a redirect to a real file floors the script as a request-level `FileWrite` before
/// the safe-list allow. Without them, an `…; echo saved` tail makes the whole chain impossible to cover with a grant.
/// CWE-863: `tee` is not safe-listed; it writes stdin to arbitrary files, so pipelines like `cat data | tee /target`
/// could bypass edit permissions.
/// `rg --pre` / `--hostname-bin` are excluded at the words level via [`rg_has_unsafe_flag`]; the string form here cannot
/// see flag structure reliably after join.
const SAFE_COMMAND_PREFIXES: &[&str] = &[
    "ls",
    "cat",
    "pwd",
    "date",
    "whoami",
    "hostname",
    "uptime",
    "grep",
    "rg",
    "kubectl get",
    "kubectl logs",
    "kubectl describe",
    "ps",
    "bin/explorer ls",
    "head",
    "tail",
    "wc",
    "sort",
    "uniq",
    "tr",
    "cut",
    "echo",
    "printf",
];

/// The argv form of [`is_safe_command_words_str`]'s prefix list.
fn safe_command_prefixes_match(matches: impl Fn(&str) -> bool) -> bool {
    SAFE_COMMAND_PREFIXES.iter().any(|pattern| matches(pattern))
}

/// Commands which are always safe to execute and should never prompt the user.
/// This list is checked against the primary command after bash command splitting/parsing.
const ALWAYS_SAFE_COMMANDS: &[&str] = &[
    // Read-only filesystem commands
    "ls",
    "cat",
    "pwd",
    "date",
    "whoami",
    "hostname",
    "uptime",
    "ps",
    // Git read-only queries are NOT listed here
    // They go through `exec_risk::git_words_are_read_only_query` (shared verb and unsafe-option tables) in `is_always_safe_command_words`
    // Search commands
    "grep",
    "rg",
    // Kubernetes read-only commands
    "kubectl get",
    "kubectl logs",
    "kubectl describe",
    // Internal tooling
    "bin/explorer ls",
];

/// Auto-allow bare `mkdir`/`touch`. Bare name only: `/bin/mkdir` still classifies (fail-safe).
fn is_safe_creation_command(words: &[String]) -> bool {
    words
        .first()
        .map(String::as_str)
        .is_some_and(is_creation_program)
}

/// Check whether parsed command words match the always-safe list.
///
/// Applied per chained segment so that scripts like `ls && rm -rf /` cannot auto-approve via the always-safe primary alone.
/// Every non-setup segment must independently pass this check (or the broader `is_safe_command_words`, or a user whitelist).
fn is_always_safe_command_words(words: &[String]) -> bool {
    if words.is_empty() {
        return false;
    }
    if rg_has_unsafe_flag(words) {
        return false;
    }
    if kubectl_has_unsafe_flag(words) {
        return false;
    }
    if ps_dumps_environment(words) {
        return false;
    }
    if crate::permission::safe_forms::listed_form_needs_approval(words) {
        return false;
    }
    // Git rides its own shared decision helper (verb allowlist and unsafe-option table in `exec_risk.rs`), not the prefix list below
    if words.first().map(String::as_str) == Some("git") {
        return git_words_are_read_only_query(words);
    }

    // CWE-183 / u35 r1: matched on argv boundaries, so "tr" never matches "truncate" and one word with a space in it
    // (`'ls -la'`) is not a command plus operands.
    for safe_pattern in ALWAYS_SAFE_COMMANDS {
        if argv_starts_with_words(words, safe_pattern, false) {
            return true;
        }
    }

    false
}

/// Whether an always-allow grant for `words` must pin to the exact full command instead of a narrower prefix.
/// Dangerous verbs (`rm`, `git push`, …) qualify because enforcement honors them only as exact whole-command grants.
/// Exec vehicles (interpreters, package runners, `sudo`/`ssh`) qualify because a bare `python3`/`sudo git` prefix would authorize any arguments.
/// Both [`default_always_allow_scope`] and [`minimum_always_allow_scope`] pin to the full command for these.
/// The offered default scope is never below the minimum, so the two cannot drift.
/// [`always_allow_scope_persists`] is the predicate the prompt arrows use.
fn always_allow_scope_pinned(words: &[String]) -> bool {
    // `sed` writes via script content (`-i`, `1w/path`), not a word prefix, so a `sed -n` prefix grant would silently cover those writes; pin it
    is_dangerous_command_words(words)
        || crate::permission::policy::head_is_exec_vehicle(words)
        || crate::permission::policy::normalized_command_head(words).as_deref() == Some("sed")
}

/// Default always-allow whitelist scope (word count) for a parsed command.
///
/// Safe-listed prefixes (`ls`, `grep`, `git status`, `kubectl get`, …) scope to exactly the safe prefix.
/// Persisting the prefix grants nothing beyond the built-in safe-command auto-allow.
/// Baking the first path or pattern into the prefix made every different-arg invocation re-prompt.
/// Everything else keeps the first-two-words-plus-flags default.
///
/// Scope narrowing applies only when the **full** invocation is safe-listed.
/// Otherwise a non-auto-allowed form like `rg --pre …` would still scope to bare `rg`, and "Always allow" would re-open the preprocessor exec hole.
pub fn default_always_allow_scope(words: &[String]) -> usize {
    if words.is_empty() {
        return 0;
    }
    // Pinned commands (dangerous verbs, exec vehicles) offer only the full command
    // A narrowed default like "Always allow: git push" would save a rule that can never match
    // "Always allow: sudo git" or "python3" would authorize arbitrary arguments
    // Wrapped/chained forms whose full-scope grant still cannot match get no row at all (`always_allow_row_is_effective`)
    if always_allow_scope_pinned(words) {
        return words.len();
    }
    if let Some(n) = gh_always_allow_scope(words) {
        return n;
    }
    base_scope(words)
}

/// `gh`'s remote-mutating verb is its third word (`gh pr merge`), so a narrower `gh pr` prefix would cover it.
/// Scope to group and action, else pin to the full command.
/// Both the default and the minimum use this, so the left arrow can't narrow below it.
fn gh_always_allow_scope(words: &[String]) -> Option<usize> {
    if crate::permission::policy::normalized_command_head(words).as_deref() != Some("gh") {
        return None;
    }
    Some(match (words.get(1), words.get(2)) {
        (Some(group), Some(verb)) if !group.starts_with('-') && !verb.starts_with('-') => 3,
        _ => words.len(),
    })
}

/// Default "Never allow" scope (word count) for a parsed command.
/// Denies honor prefixes for every command, so the dangerous full-command pin does not apply.
/// "Never allow: git push" blocking all pushes is the point.
pub fn default_always_deny_scope(words: &[String]) -> usize {
    if words.is_empty() {
        return 0;
    }
    base_scope(words)
}

/// Verb-plus-flags scope shared by the allow default (non-dangerous arm) and the deny default.
fn base_scope(words: &[String]) -> usize {
    if is_safe_command_words(words) {
        if is_safe_command_words_str(&words[0]) {
            return 1;
        }
        if words.len() >= 2 && is_safe_command_words_str(&words[..2].join(" ")) {
            return 2;
        }
    }
    let mut n = words.len().min(2);
    while n < words.len() && words[n].starts_with('-') {
        n += 1;
    }
    n
}

/// Narrowest always-allow scope (word count) the prompt may offer for a parsed command.
/// Pinned commands ([`always_allow_scope_pinned`]: dangerous verbs and exec vehicles) are held at the full command.
/// Only the exact command the user saw may persist.
/// Everything else narrows down to one word.
/// Deny scopes are not pinned (see [`default_always_deny_scope`]).
pub fn minimum_always_allow_scope(words: &[String]) -> usize {
    if always_allow_scope_pinned(words) {
        return words.len();
    }
    // Narrowing `gh` broadens the grant (fewer words cover more subcommands), so the floor equals the default: the left arrow cannot reach `gh pr`
    gh_always_allow_scope(words).unwrap_or(1)
}

/// Check whether parsed command words begin with a known dangerous command.
///
/// Applied per chained segment, not only the start of the script.
/// A segment matching this check is NEVER auto-approved via a user whitelist; the user must always be prompted for it.
fn is_dangerous_command_words(words: &[String]) -> bool {
    // Match on the normalized basename so `/bin/rm`, `RM`, and `rm.exe` are all caught (consistent with `head_is_exec_vehicle` and the sed pin)
    let Some(head) = crate::permission::policy::normalized_command_head(words) else {
        return false;
    };
    let joined = if words.len() == 1 {
        head
    } else {
        format!("{head} {}", words[1..].join(" "))
    };
    matches_command_prefix(&joined, "rm")
        || matches_command_prefix(&joined, "chmod")
        || matches_command_prefix(&joined, "chown")
        || matches_command_prefix(&joined, "chgrp")
        || matches_command_prefix(&joined, "chattr")
        || matches_command_prefix(&joined, "pkill")
        || matches_command_prefix(&joined, "kill")
        || matches_command_prefix(&joined, "killall")
        || matches_command_prefix(&joined, "git push")
        // u35 r3 (Astra r2 H7): `git --no-pager push`, `git -C dir push`: the verb past the global options.
        || crate::permission::exec_risk::git_subcommand(words) == Some("push")
        // u35 t1 (design d2 T11): `fuigo --trust` trusts a folder; only the user decides that.
        || (joined.starts_with("fuigo ") && words[1..].iter().any(|w| is_trust_flag(w)))
}

/// u35 t1: a Fuigo option that trusts a folder (`--trust`, `--trust-folder`, `--trust=...`).
fn is_trust_flag(word: &str) -> bool {
    let name = word.split_once('=').map_or(word, |(name, _)| name);
    matches!(name, "--trust" | "--trust-folder")
}

/// Uses `matches_command_prefix` so user allow/deny entries enforce a word boundary after the prefix.
/// That keeps a "git" entry from matching "gitleaks" (CWE-183).
/// Metacharacters in a literal grant stay literal; glob patterns live in `allowed_bash_globs`, matched separately (see [`matches_bash_glob`]).
fn matches_whitelist_prefix(segment_str: &str, allowed_prefix: &str) -> bool {
    matches_command_prefix(segment_str, allowed_prefix)
}

/// Whether a user-authored glob grant (`allowed_bash_globs`) authorizes `segment_str`.
/// Uses the same matcher as the config `[permission]` rules and the pattern-editor preview, so what the user previewed is what auto-allows.
fn matches_bash_glob(segment_str: &str, pattern: &str) -> bool {
    super::policy::bash_pattern_matches_command(pattern, segment_str)
}

/// Ordinary command-segment outcome, before script-level effect floors.
#[derive(Debug)]
pub(crate) enum SegmentEvaluation {
    /// All non-setup segments safe/always-safe or on an allow-prefix.
    /// `via_session_grant`: at least one segment hit `allowed_bash_commands`.
    AutoAllow { via_session_grant: bool },
    /// Disallow-prefix matched; reject without prompting.
    Reject(String),
    /// One or more segments need a user decision.
    NeedsPrompts {
        #[allow(dead_code)]
        segments: Vec<String>,
    },
    /// Tree-sitter could not decompose the script (heredoc, `$(…)`, backtick, single `&` background, …).
    /// Caller should fall back to a single conservative prompt with the full script.
    Unparseable,
}

/// u35 t1 (design d2 §3.4): the session's compiled policy with the session folder's project tier (`project`, when that
/// folder is trusted) and without any (`base`), and the trust generation they were built under.
struct TrustPolicies {
    generation: u64,
    project: Option<CompiledPolicy>,
    project_prompt: PromptPolicy,
    base: Option<CompiledPolicy>,
    base_prompt: PromptPolicy,
}

impl TrustPolicies {
    /// One policy for every command (no session inputs: tests, configs built by hand).
    fn fixed(config: Option<crate::permission::types::PermissionConfig>) -> Self {
        let prompt = config.as_ref().map(|c| c.prompt_policy).unwrap_or_default();
        Self {
            generation: 0,
            base: config.clone().map(CompiledPolicy::new),
            base_prompt: prompt,
            project: config.map(CompiledPolicy::new),
            project_prompt: prompt,
        }
    }

    /// Both policies from the session's inputs, under the current folder trust.
    async fn resolve(inputs: &crate::permission::resolution::SessionPolicyInputs) -> Self {
        use crate::permission::resolution::resolve_session_policy;
        let generation = crate::folder_trust::trust_generation();
        let base = resolve_session_policy(inputs, false).await;
        let project = if crate::folder_trust::dir_trust(&inputs.cwd).is_trusted() {
            resolve_session_policy(inputs, true).await
        } else {
            base.clone()
        };
        let prompt = |c: &Option<crate::permission::types::PermissionConfig>| {
            c.as_ref().map(|c| c.prompt_policy).unwrap_or_default()
        };
        Self {
            generation,
            base_prompt: prompt(&base),
            project_prompt: prompt(&project),
            base: base.map(CompiledPolicy::new),
            project: project.map(CompiledPolicy::new),
        }
    }

    fn policy_for(&self, untrusted: bool) -> &Option<CompiledPolicy> {
        if untrusted { &self.base } else { &self.project }
    }

    fn prompt_policy_for(&self, untrusted: bool) -> PromptPolicy {
        if untrusted {
            self.base_prompt
        } else {
            self.project_prompt
        }
    }

    /// 1.0.36 item a: whether a launch policy contributed rules (to either policy).
    fn has_launch_policy(&self) -> bool {
        [&self.project, &self.base].into_iter().any(|policy| {
            policy
                .as_ref()
                .is_some_and(CompiledPolicy::has_launch_policy)
        })
    }
}

/// 1.0.36 item a (R3): a request's answer held back so the launch-ask clamp can replace it before it is sent: the
/// resolution, the real reply channel and the folder-trust flag [`FinalShellSend`] checks.
type HeldAnswer = (
    PermissionResolution,
    tokio::sync::oneshot::Sender<PermissionResolution>,
    bool,
);

/// What the launch-ask clamp needs to ask the client itself (captured when the preflight finds a launch ask).
struct LaunchClamp {
    access: AccessKind,
    prompt_update: acp::ToolCallUpdate,
    protected_edit: Option<crate::permission::ProtectedEditReason>,
    hook_ask: Option<crate::permission::types::HookAsk>,
}

/// An answer to a launch-policy ask, an agent message or a side-effecting tool applies to this one call: every
/// "always" answer becomes its once form, so nothing is remembered.
fn once_only(outcome: PromptOutcome) -> PromptOutcome {
    match outcome {
        PromptOutcome::AllowOnce
        | PromptOutcome::AllowAlways
        | PromptOutcome::AllowEditsForSession
        | PromptOutcome::AllowAlwaysBashCommand(_)
        | PromptOutcome::AllowAlwaysBashGlob(_)
        | PromptOutcome::AllowAlwaysDomain(_)
        | PromptOutcome::AllowAlwaysMcpTool(_)
        | PromptOutcome::AllowAlwaysMcpServer(_) => PromptOutcome::AllowOnce,
        PromptOutcome::RejectOnce
        | PromptOutcome::RejectAlwaysBashCommand(_)
        | PromptOutcome::RejectAlwaysMcpTool(_)
        | PromptOutcome::RejectAlwaysDomain(_) => PromptOutcome::RejectOnce,
        other => other,
    }
}

/// Whether the clamp replaces this answer: an Allow the client did not give, or the dontAsk refusal. A deny or a guard
/// refusal stands.
fn launch_clamp_applies(resolution: &PermissionResolution) -> bool {
    let event = resolution.event.as_ref();
    match &resolution.decision {
        Decision::Allow => !event.is_some_and(|e| e.user_prompted),
        Decision::PolicyDeny(_) => {
            event.and_then(|e| e.decision_reason.as_deref()) == Some(reasons::PROMPT_DENY)
        }
        _ => false,
    }
}

/// u35 t1 (design d2 §3.3 step 7): the actor's answer to a request, checked before it is sent: a shell command
/// approved without a grant (or with no event to say how it was approved) in a folder that is not trusted is refused.
/// The routing above means this never fires; it is the last line, beside the shell runner's own check.
struct FinalShellSend {
    inner: tokio::sync::oneshot::Sender<PermissionResolution>,
    untrusted: bool,
    /// 1.0.36 item a: under a launch policy the answer is held here for the launch-ask clamp instead of being sent.
    held: Option<std::rc::Rc<std::cell::RefCell<Option<HeldAnswer>>>>,
}

impl FinalShellSend {
    fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    async fn closed(&mut self) {
        self.inner.closed().await;
    }

    // The same signature as the oneshot sender it wraps.
    #[allow(clippy::result_large_err)]
    fn send(self, mut resolution: PermissionResolution) -> Result<(), PermissionResolution> {
        if let Some(held) = self.held {
            *held.borrow_mut() = Some((resolution, self.inner, self.untrusted));
            return Ok(());
        }
        let without_grant = resolution
            .event
            .as_ref()
            .and_then(|event| event.approved_without_grant);
        if let Some(refusal) =
            final_shell_check(self.untrusted, &resolution.decision, without_grant)
        {
            resolution.decision = refusal;
        }
        self.inner.send(resolution)
    }
}

/// [`FinalShellSend`]'s check: the refusal that replaces `decision`, if any. `without_grant`: the event's
/// [`approved_without_grant`] (`None`, not said, counts as without a grant).
fn final_shell_check(
    untrusted: bool,
    decision: &Decision,
    without_grant: Option<bool>,
) -> Option<Decision> {
    if untrusted && matches!(decision, Decision::Allow) && without_grant.unwrap_or(true) {
        tracing::error!(
            "internal: a shell command approved without a grant in a folder that is not trusted; refused"
        );
        return Some(Decision::Reject(
            "internal: ungranted shell command in an untrusted folder".to_owned(),
        ));
    }
    None
}

/// One request's parsed Bash authorization facts.
#[derive(Debug)]
struct BashEvaluation {
    segments: SegmentEvaluation,
    exact_grant: bool,
    all_segments_granted: bool,
    /// Canonical, ordered, deduplicated security findings for this request.
    /// The single source for grant/sandbox floor disposition and classifier evidence.
    /// `ExecOrAmbientGit` may be added later by the ambient git scan.
    assessment: BashSecurityAssessment,
    /// An unsafe write target came from a redirect (`> f`), which allow-rule word matching cannot see; no configured allow rule may vouch for it.
    /// `true` (fail closed) on undecomposable scripts.
    redirect_write: bool,
    /// Raw segment word lists for ambient cwd tracking (git present, flags clean).
    ambient_segments: Option<Vec<Vec<String>>>,
    /// Every write target (redirects, writer operands, `mkdir`/`touch` operands, directory-destination writes) with its
    /// position and the script's cwd changes, for the manager's protected-target floor.
    /// P166/S5: before, only `mkdir`/`touch` operands reached it, so `echo … > ~/.fuigo/mcp.json` was not a protected edit.
    write_facts: crate::permission::shell_access::ShellWriteFacts,
    /// Strict decomposition failed but every command is a reviewed reader with understood filename positions.
    recovered_eligible: bool,
    /// u35 r3: prompted segments that the read-only list would cover but for the plain-text gate (the whole script
    /// when only setup commands ran), so the sandbox card can name the reason as unplain structure.
    gated_segments: Vec<String>,
    /// u35 g6/g7: every command's normalised words, for the inherited-environment check the hub and the manager run with
    /// the request's directory ([`add_inherited_env_finding`]).
    env_reader_segments: Vec<Vec<String>>,
    /// u35 g7 (Fable r6 Medium): the inherited variable that switched no-grant auto-approval off, for the ask's log.
    env_steering: Option<&'static str>,
    /// u35 g11 (owner decision): the shell the runner will run the command in, when it does not read bash syntax
    /// (PowerShell or cmd.exe on Windows; [`unvouched_runner_shell`]). The plain-text gate and the read-only lists judge
    /// bash syntax, so for such a shell no command is approved without a grant.
    unvouched_shell: Option<&'static str>,
    /// u35 g12 (Astra r11 High): a git command runs in a repository the ambient scan did not read, so whatever its
    /// configuration runs is unknown: the command's own git exec option or `GIT_DIR`-style assignment, a `cd` that
    /// leaves the directory uncertain, or a script not decomposed to words that names git.
    unscanned_git: bool,
    /// u35 g12 (Astra r11 High): the ambient scan found repository configuration that runs a program for this git
    /// command (`core.fsmonitor`, a driver, an alias, a safe-verb hook, ...), or could not read it (fail closed).
    repository_config_runs: bool,
    /// u35 g13 (Astra r12 High): a command loads a configuration file the command does not show and which can make it
    /// run a program (`grep --config` reading a repository `.ugrep`, `cargo --config FILE`, `ssh -F FILE`;
    /// [`crate::permission::exec_surface::segment_loads_config_file`]), the repository part of a `SpecialExecSurface`;
    /// or (Grok r12 High) a routine tool loads such a file of the project by default (`.npmrc`, `.yarnrc.yml`, a Cargo
    /// `[alias]`, `.bazelrc`; [`add_tool_config_finding`]).
    loads_config_file: bool,
    /// u35 g14: each command as the project configuration scan reads it ([`add_tool_config_finding`]).
    tool_segments: Vec<crate::permission::safe_forms::ToolSegment>,
    /// u35 g14 (Astra/Grok r13 High): a configuration tool runs where no scan looked ([`names_hidden_tool`]); like
    /// `unscanned_git`, it stops only a classifier allow, so a listed reader naming the tool (`rg npm`) is unaffected.
    hidden_tool: bool,
    /// u35 t1 (design d2 §3.3): some directory the command starts in is not in a trusted folder
    /// ([`crate::permission::run_dirs::run_dirs_trust`]; u35 t3: folders the command names do not count). No approval without a grant stands: the read-only
    /// lists, the Auto mode fast path and classifier and sandbox auto-allow approve nothing; grants, allow rules of the
    /// user, the user's answer and the catch-all overrides still do.
    untrusted_folder: bool,
}

/// u35 g7: the inherited environment can steer what the script runs (`PATH` not clean, or a variable of
/// [`crate::permission::exec_risk::inherited_env_steers`] set).
///
/// u35 g8 (release gate: a grant is never disabled by the presence rule): the request carries
/// `InheritedEnvironment`, which is not a grant floor. It switches off only approval without a grant: the read-only
/// lists ([`no_grant_approval_switched_off`]) and the Auto mode fast path and heuristic pre-pass (the assessment is not
/// empty, so the classifier sees the finding). Prefix, glob and exact grants, the session blanket, sandbox auto-allow
/// and configured allow rules still apply.
fn add_inherited_env_finding(evaluation: &mut BashEvaluation, cwd: &std::path::Path) {
    // u35 g9: the shell runner judges, by the same rule, the environment it builds for each call approved without a
    // grant (a login `PATH`, a persistent shell's exports); also installed at manager start.
    install_runner_env_judge();
    // u35 g11: judged in each directory the command can run in; the first variable found is the one named.
    if let Some(var) = crate::permission::exec_risk::inherited_env_steers_script(
        &evaluation.env_reader_segments,
        cwd,
    ) {
        evaluation.env_steering.get_or_insert(var);
        evaluation
            .assessment
            .insert(ClassifierSecurityFinding::InheritedEnvironment);
    }
}

/// u35 g11 (Astra r10 High): the directories a bash request's command can run in: the request's directory, and the
/// tool's own working directory when it names another (OpenCode bash `workdir`, relative to the request's). Judged as
/// well as, never instead of, the request's directory, as the hub judges a `workdir`; the last one is where it runs.
fn bash_run_dirs(
    request_cwd: &std::path::Path,
    exec_cwd: Option<&std::path::Path>,
) -> Vec<std::path::PathBuf> {
    let mut dirs = vec![request_cwd.to_path_buf()];
    dirs.extend(
        exec_cwd
            .map(|dir| request_cwd.join(dir))
            .filter(|dir| dir.as_path() != request_cwd),
    );
    dirs
}

/// u35 g13 (Grok r12 High): a routine tool of the command loads a configuration file of the project that can make it
/// run a program (`.npmrc` `onload-script`, `.yarnrc.yml` `yarnPath`, a Cargo `[alias]` for `fmt`, a `.bazelrc`
/// startup option; [`crate::permission::safe_forms::repository_tool_config_runs`]): repository execution, so no
/// approval without a grant (the read-only lists, the Auto mode heuristic and model) stands.
///
/// u35 g14 (Astra/Grok r13 High): judged in the folder each command runs in (after `cd`, `cargo -C`, `npm --prefix`,
/// ...), and for the commands of an opaque shell script too (Fable r13 Low).
fn add_tool_config_finding(evaluation: &mut BashEvaluation, dir: &std::path::Path) {
    if crate::permission::safe_forms::repository_tool_config_runs(&evaluation.tool_segments, dir) {
        evaluation.loads_config_file = true;
    }
}

/// The ambient git scan's findings: repository config that runs a program (`ExecOrAmbientGit`, a grant floor) and,
/// u35 g10 (Astra r9 High), the repository's own hooks under a git command that is not a read-only query
/// (`RepositoryHook`, which switches off only approval without a grant).
fn add_ambient_git_findings(evaluation: &mut BashEvaluation, risk: AmbientGitRisk) {
    if risk.exec {
        evaluation
            .assessment
            .insert(ClassifierSecurityFinding::ExecOrAmbientGit);
        evaluation.repository_config_runs = true;
    }
    if risk.hook {
        evaluation
            .assessment
            .insert(ClassifierSecurityFinding::RepositoryHook);
    }
}

/// u35 g9: install the shell runner's check for calls approved without a grant ([`child_env_steers`]).
///
/// u35 g11 (Fable/Grok r10 Low): the runner refuses such a call when no check is installed. This crate's tests test
/// the rule directly and judge nothing at the runner, so they install one that passes every environment.
pub(crate) fn install_runner_env_judge() {
    #[cfg(not(test))]
    fuigo_tools::sandbox_launch::install_env_judge(child_env_steers);
    #[cfg(test)]
    fuigo_tools::sandbox_launch::install_env_judge(|_, _, _| None);
}

/// u35 t1 (design d2 §3.6): install the shell runner's folder-trust backstop ([`runner_trust_judge`]).
pub(crate) fn install_runner_trust_judge() {
    fuigo_tools::sandbox_launch::install_trust_judge(runner_trust_judge);
}

/// u35 t1: the shell runner's folder-trust rule ([`fuigo_tools::sandbox_launch::TrustJudge`]): the permission check's
/// own ([`crate::permission::run_dirs::run_dirs_trust`]) over the directories the runner was given. u35 t3: the
/// command's text does not change the answer (a folder it names does not count).
pub(crate) fn runner_trust_judge(_command: &str, dirs: &[&std::path::Path]) -> bool {
    let run_dirs: Vec<std::path::PathBuf> = dirs.iter().map(|dir| dir.to_path_buf()).collect();
    crate::permission::run_dirs::run_dirs_trust(&run_dirs).is_trusted()
}

/// u35 g9 (lead decision after r8): the shell runner's check ([`fuigo_tools::sandbox_launch::EnvJudge`]): the
/// classifier's own rule ([`crate::permission::exec_risk::inherited_env_steers_script`]) for `command`'s programs,
/// over `env`, the exact environment the runner builds for a call approved without a grant, in place of Fuigo's.
pub(crate) fn child_env_steers(
    command: &str,
    env: &[(String, String)],
    dir: &std::path::Path,
) -> Option<String> {
    crate::permission::exec_risk::with_env_view(env, || env_steering_of(command, dir))
        .map(str::to_owned)
}

/// u35 g9: the inherited variable that makes `command` ask in `dir`, if any (the classifier's rule for its programs).
pub(crate) fn env_steering_of(command: &str, dir: &std::path::Path) -> Option<&'static str> {
    let evaluation = evaluate_bash(command, &PermissionState::default(), true);
    crate::permission::exec_risk::inherited_env_steers_script(&evaluation.env_reader_segments, dir)
}

/// u35 g8: the inherited environment steers and no grant covers every segment, so the read-only lists do not approve.
/// u35 g11 (owner decision): the same when the runner's shell does not read bash syntax ([`unvouched_runner_shell`]).
/// u35 g13 (Grok r12 High): the same when a program loads a configuration file that can make it run a program
/// ([`BashEvaluation::loads_config_file`]).
///
/// u35 t1 (design d2 D3): a configuration file a program loads no longer switches it off in a trusted folder (its
/// content is the trusted folder's); in a folder that is not trusted ([`BashEvaluation::untrusted_folder`]) nothing
/// is approved without a grant.
fn no_grant_approval_switched_off(evaluation: &BashEvaluation) -> bool {
    (evaluation.env_steering.is_some()
        || evaluation.unvouched_shell.is_some()
        || evaluation.untrusted_folder)
        && !evaluation.all_segments_granted
        && !evaluation.exact_grant
}

/// u35 g11 (owner decision): on Windows, when commands run in PowerShell (`pwsh` or `powershell.exe`) or cmd.exe, the
/// shell's display name. Fuigo's plain-text gate and read-only lists judge a command as bash reads it; those shells
/// read the same text with other quoting, separators and redirects (cmd.exe does not treat `'` as a quote, so
/// `echo 'x & y'` runs `y`), so neither can vouch for a command there. Every command without a grant then asks: the
/// read-only lists, the Auto mode fast path and its classifier approve nothing; grants, allow rules (`--allow`), the
/// user's answer and the catch-all overrides still apply. Git Bash and every Unix shell are unchanged.
pub(crate) fn unvouched_runner_shell() -> Option<&'static str> {
    unvouched_shell(runner_shell_family())
}

/// u35 g11: [`unvouched_runner_shell`] for a given runner shell (`None`: a Unix shell).
pub(crate) fn unvouched_shell(
    shell: Option<fuigo_config::shell::WindowsShellFamily>,
) -> Option<&'static str> {
    shell
        .filter(|family| !family.reads_bash_syntax())
        .map(|family| family.name())
}

/// The Windows shell the command runner uses (`None` on Unix); in this crate's tests, the one a test set
/// ([`TestRunnerShell`]).
fn runner_shell_family() -> Option<fuigo_config::shell::WindowsShellFamily> {
    #[cfg(test)]
    if let Some(shell) = TEST_RUNNER_SHELL.with(std::cell::Cell::get) {
        return shell;
    }
    fuigo_config::shell::runner_windows_shell_family()
}

#[cfg(test)]
thread_local! {
    static TEST_RUNNER_SHELL: std::cell::Cell<Option<Option<fuigo_config::shell::WindowsShellFamily>>> =
        const { std::cell::Cell::new(None) };
}

/// u35 g11: until dropped, this thread's checks see the command runner use `shell` (`None`: a Unix shell). A manager
/// on a `LocalSet` runs on the test's thread, so it sees it too.
#[cfg(test)]
pub(crate) struct TestRunnerShell(Option<Option<fuigo_config::shell::WindowsShellFamily>>);

#[cfg(test)]
impl TestRunnerShell {
    pub(crate) fn set(shell: Option<fuigo_config::shell::WindowsShellFamily>) -> Self {
        Self(TEST_RUNNER_SHELL.with(|cell| cell.replace(Some(shell))))
    }
}

#[cfg(test)]
impl Drop for TestRunnerShell {
    fn drop(&mut self) {
        TEST_RUNNER_SHELL.with(|cell| cell.set(self.0));
    }
}

/// u35 g11 (owner decision): in Auto mode a command no grant covers in full is asked about, without the fast path or
/// the classifier, when the runner's shell does not read bash syntax ([`unvouched_runner_shell`]).
///
/// u35 t1: the same in a folder that is not trusted ([`BashEvaluation::untrusted_folder`]).
fn shell_switches_off_auto(evaluation: Option<&BashEvaluation>) -> bool {
    evaluation.is_some_and(|e| {
        (e.unvouched_shell.is_some() || e.untrusted_folder)
            && !e.all_segments_granted
            && !e.exact_grant
    })
}

/// u35 g12 (Astra r11 High): why Fuigo knows content the repository controls runs for a command
/// ([`repository_execution`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepositoryExecution {
    /// Repository git configuration runs a program for this git command (`core.fsmonitor`, a driver, an alias, a
    /// safe-verb hook, `log.showSignature`, ...), or the ambient scan could not read it.
    GitConfig,
    /// The repository's own hooks run for this git command (`RepositoryHook`).
    GitHooks,
    /// A git command runs in a repository the ambient scan did not read.
    UnscannedGit,
    /// u35 g13 (Astra r12 High): a program loads a configuration file that can make it run a program
    /// ([`BashEvaluation::loads_config_file`]).
    ConfigFile,
    /// The inherited environment chooses which program runs or what it loads (`InheritedEnvironment`): a `PATH` entry
    /// that is relative or in the project, a selector naming a file in it, or a steering variable.
    Environment,
}

/// u35 g12 (Astra r11 High; lead decision): the repository-controlled execution Fuigo detected for this command, if
/// any. Every finding is placed on one side by an exhaustive match: those that say content the repository (or the
/// environment) controls will run, and those about the command's own text, which the Auto mode model reads and judges
/// (an opaque or rich script, a write, a destructive command). `ExecOrAmbientGit` is both kinds (an execution
/// callback in the command's text, or the repository's git configuration), so its repository part is recorded apart
/// by the ambient scan ([`BashEvaluation::repository_config_runs`], [`BashEvaluation::unscanned_git`]). So is
/// `SpecialExecSurface` (u35 g13, Astra r12 High): its repository part, a configuration file a program loads, is
/// [`BashEvaluation::loads_config_file`].
fn repository_execution(evaluation: &BashEvaluation) -> Option<RepositoryExecution> {
    use ClassifierSecurityFinding as F;
    let present = F::ALL
        .iter()
        .copied()
        .filter(|finding| evaluation.assessment.contains(*finding));
    let from_findings = present.into_iter().find_map(|finding| match finding {
        F::RepositoryHook => Some(RepositoryExecution::GitHooks),
        F::InheritedEnvironment => Some(RepositoryExecution::Environment),
        F::FailClosedPolicy
        | F::UnparseableShell
        | F::UnresolvedArgument
        | F::OpaqueShell
        | F::ExecOrAmbientGit
        | F::EnvInjection
        | F::UnvettedEnv
        | F::FileWrite
        | F::DangerousCommand
        | F::SpecialExecSurface => None,
    });
    from_findings
        .or_else(|| {
            evaluation
                .repository_config_runs
                .then_some(RepositoryExecution::GitConfig)
        })
        .or_else(|| {
            evaluation
                .unscanned_git
                .then_some(RepositoryExecution::UnscannedGit)
        })
        .or_else(|| {
            (evaluation.loads_config_file || evaluation.hidden_tool)
                .then_some(RepositoryExecution::ConfigFile)
        })
}

/// u35 g14 (Astra/Grok r13 High): a segment names a configuration tool ([`crate::permission::safe_forms::is_config_tool`])
/// as a word but is not that tool's own pinned command, so the tool may run where the configuration scan did not look
/// (`taskset -c 0 npm ls`, `find . -execdir cargo fmt ;`, an `env -S` the normaliser cannot pin). Fail closed on the
/// word rather than model each wrapper. A `cd` and a listed reader (`which cargo`, `rg npm`) never run their operands;
/// an opaque shell script is split and scanned instead ([`crate::permission::safe_forms::ToolSegment::Nested`]).
fn names_hidden_tool(raw_words: &[String], floors: &SegmentFloors<'_>) -> bool {
    use crate::permission::safe_forms::is_config_tool;
    let inner = floors.inner;
    let head = inner
        .first()
        .map(|head| crate::permission::exec_surface::program_name(head));
    let pinned_tool = floors.pinned && inner.first().is_some_and(|head| is_config_tool(head));
    !pinned_tool
        && !floors.opaque
        && !matches!(head.as_deref(), Some("cd" | "pushd" | "popd"))
        && !(floors.pinned && (is_safe_command_words(inner) || is_always_safe_command_words(inner)))
        && raw_words.iter().any(|word| is_config_tool(word))
}

/// u35 g14: the configuration scan's view of one segment ([`crate::permission::safe_forms::ToolSegment`]).
fn tool_segment_of(
    raw_words: &[String],
    floors: &SegmentFloors<'_>,
) -> Option<crate::permission::safe_forms::ToolSegment> {
    use crate::permission::safe_forms::ToolSegment;
    if floors.opaque {
        Some(ToolSegment::Nested(
            crate::permission::exec_surface::split_script_text(raw_words),
        ))
    } else {
        floors.pinned.then(|| ToolSegment::Command {
            words: floors.inner.to_vec(),
            moved: floors.moved,
        })
    }
}

/// u35 g14: the configuration findings of a script the parser could not decompose: a configuration-loading option
/// anywhere in it (Grok r13 Low), and a configuration tool named in it.
fn unparseable_config_findings(cmd: &str) -> (bool, bool) {
    let hidden_tool = crate::permission::exec_surface::split_script_text(&[cmd.to_owned()])
        .iter()
        .flatten()
        .any(|word| crate::permission::safe_forms::is_config_tool(word));
    (
        crate::permission::exec_surface::text_may_load_config_file(cmd),
        hidden_tool,
    )
}

/// u35 g11 (Grok r10 Medium), u35 g12 (Astra r11 High; lead decision): a classifier allow is approval without a grant.
/// When Fuigo detected that content the repository controls runs for this command ([`repository_execution`]: its git
/// configuration or hooks, a repository it could not scan, an environment that steers what runs), unless a grant
/// covers it in full the user is asked. Otherwise the model's allow stands: in Auto mode the model judges the commands
/// the plain-text gate cannot read (an opaque or rich script, a routine build). Not a grant floor: a grant, an allow
/// rule or "allow all commands" still approves it before the classifier.
///
/// u35 t1 (design d2 D3): in a trusted folder the repository's own configuration (git config and hooks, an unscanned
/// repository, a tool's configuration file) is the trusted folder's content and no longer stops the model's allow; an
/// environment that steers what runs still does. In a folder that is not trusted no classifier allow stands.
fn classifier_allow_needs_user(evaluation: Option<&BashEvaluation>) -> bool {
    evaluation.is_some_and(|e| {
        (e.untrusted_folder
            || e.assessment
                .contains(ClassifierSecurityFinding::InheritedEnvironment))
            && !e.all_segments_granted
            && !e.exact_grant
    })
}

/// u35 g8 (Fable r7 Medium): the prompt for a command asked about because of the environment names the variable, so a
/// user can tell why `git status` started asking (`GIT_ASKPASS` from an editor terminal, `LESSOPEN` from a stock
/// `~/.bashrc`).
fn with_env_steering_note(update: &acp::ToolCallUpdate, var: Option<&str>) -> acp::ToolCallUpdate {
    let mut update = update.clone();
    if let Some(var) = var {
        let title = update
            .fields
            .title
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .unwrap_or("this command");
        update.fields.title = Some(format!(
            "{title} (asks because of {var} in your environment)"
        ));
    }
    update
}

fn unparseable_exec_risk(cmd: &str) -> bool {
    // WHY: word-only decomposition failed; ambient git never ran
    // Fail closed when the script may still invoke git so sandbox/Auto cannot auto-allow
    script_may_invoke_git(cmd)
}

/// Map an unsafe-environment risk tier to its finding (`Safe` maps to none).
fn env_risk_finding(env_risk: EnvRisk) -> Option<ClassifierSecurityFinding> {
    match env_risk {
        EnvRisk::Injection => Some(ClassifierSecurityFinding::EnvInjection),
        EnvRisk::Unvetted => Some(ClassifierSecurityFinding::UnvettedEnv),
        EnvRisk::Safe => None,
    }
}

/// A persisted deny matching the raw script text (word-boundary prefix, the deny regime everywhere else).
/// Unparseable scripts never reach per-segment deny matching, so without this their "don't ask again" denies would be silently inert.
/// Matching the raw text can only over-block (deny-safe).
fn raw_deny_rejection(cmd: &str, state: &PermissionState) -> Option<SegmentEvaluation> {
    state
        .disallowed_bash_commands
        .iter()
        .find(|d| matches_whitelist_prefix(cmd, d))
        .map(|d| {
            SegmentEvaluation::Reject(format!("User previously rejected `{d}` in this project"))
        })
}

/// The protected-edit reason for a Bash request's write targets (P166/S5), resolved like the edit tools resolve paths.
fn bash_protected_write_target(
    evaluation: &BashEvaluation,
    real_cwd: &std::path::Path,
    display_cwd: Option<&std::path::Path>,
) -> Option<crate::permission::shell_access::ProtectedEditReason> {
    evaluation.write_facts.protection(real_cwd, |base, path| {
        if base == real_cwd {
            resolve_model_path(base, display_cwd, path)
        } else {
            resolve_model_path(base, None, path)
        }
    })
}

/// u35 r1: one segment's floor checks, run on the canonical-wrapper-peeled words AND on the one classifier
/// normalisation ([`crate::permission::shell_access::normalize_for_classification`]), so `command`, `builtin`, `exec`,
/// `time`, `nohup` and the other transparent wrappers hide no floor. An argv the normaliser cannot pin is floored.
struct SegmentFloors<'a> {
    /// The command that runs, after the normalisation.
    inner: &'a [String],
    /// A launcher was peeled: no positive approval rides through it.
    launched: bool,
    dangerous: bool,
    /// Exec surface, environment dump, unsafe tool flag, or an unpinnable / exec-vehicle wrapper.
    special: bool,
    opaque: bool,
    /// u35 r3: the segment changes how bash reads later words (see `changes_shell_parsing`).
    parsing_changed: bool,
    /// u35 g13: a program loads a configuration file the command does not show (`segment_loads_config_file`).
    config_file: bool,
    /// u35 g14: the normaliser pinned the program (`inner` is the command that runs).
    pinned: bool,
    /// u35 g14: a wrapper moved the working directory (`env -C`, `sudo -D`).
    moved: bool,
}

impl<'a> SegmentFloors<'a> {
    /// `marked` is `raw` with every word the normaliser could not pin replaced by the unresolved marker (u35 r2): the
    /// exec-surface check runs on it too, so an unpinned script, program text or format fails closed.
    fn of(raw: &'a [String], marked: &[String]) -> Self {
        let peeled = unwrap_wrappers(raw);
        let norm = crate::permission::shell_access::normalize_for_classification(raw);
        let inner = norm.words;
        let forms = [peeled, inner];
        let marked_norm = crate::permission::shell_access::normalize_for_classification(marked);
        let marked_special = segment_has_exec_surface(unwrap_wrappers(marked))
            || segment_has_exec_surface(marked_norm.words);
        let loads_config = crate::permission::exec_surface::segment_loads_config_file;
        let config_file = loads_config(unwrap_wrappers(marked))
            || loads_config(marked_norm.words)
            || forms.iter().any(|words| loads_config(words));
        let special_in = |words: &[String]| {
            kubectl_has_unsafe_flag(words)
                || rg_has_unsafe_flag(words)
                || ps_dumps_environment(words)
                || git_words_have_unsafe_query_option(words)
                || segment_has_exec_surface(words)
        };
        let opaque_in = |words: &[String]| {
            let shell_words: Vec<ShellWord<'_>> = words.iter().map(ShellWord::from).collect();
            words_are_opaque_shell(&shell_words)
        };
        SegmentFloors {
            inner,
            launched: norm.launched,
            dangerous: forms.iter().any(|words| is_dangerous_command_words(words)),
            special: norm.fail_closed
                || norm.vehicle
                || marked_special
                || forms.iter().any(|words| special_in(words)),
            opaque: forms.iter().any(|words| opaque_in(words)),
            parsing_changed: forms
                .iter()
                .any(|words| crate::permission::exec_surface::changes_shell_parsing(words)),
            config_file,
            pinned: !norm.fail_closed,
            moved: norm.moved,
        }
    }
}

/// u35 r1: whether a saved prefix grant covers `words` on an argv boundary: the grant is a prefix of the joined argv
/// that ends where an argv word ends, and the program word is one unambiguous word (no whitespace).
fn grant_prefix_matches_argv(words: &[String], grant: &str) -> bool {
    let joined = words.join(" ");
    if !matches_whitelist_prefix(&joined, grant) {
        return false;
    }
    if words
        .first()
        .is_none_or(|head| head.is_empty() || head.chars().any(char::is_whitespace))
    {
        return false;
    }
    let mut end = 0usize;
    for (i, word) in words.iter().enumerate() {
        end += word.len() + usize::from(i > 0);
        if end == grant.len() {
            return true;
        }
        if end > grant.len() {
            return false;
        }
    }
    false
}

/// Parse and classify one Bash request once.
/// Ordinary segment outcome stays separate from the script-level real-file-write and unsafe-environment floors.
fn evaluate_bash(cmd: &str, state: &PermissionState, honor_safe_lists: bool) -> BashEvaluation {
    use ClassifierSecurityFinding as Finding;
    // u35 r3: the strict plain-text gate, checked first. A built-in read-only list may approve a segment only when the
    // whole command is plain text; a user grant does not need it.
    let plain_text = crate::permission::plain_text_gate::is_plain_text_command(cmd);
    // u35 g11 (owner decision): the one check of the shell the runner will use; see `unvouched_runner_shell`.
    let unvouched_shell = unvouched_runner_shell();
    let exact_grant = state.allowed_bash_commands.contains(cmd);
    let mut assessment = BashSecurityAssessment::default();
    let Some(tree) = try_parse_shell(cmd) else {
        // Undecomposable at the top level: unparseable structure, plus fail closed on ambient git exec risk (word-only decomposition never ran)
        assessment.insert(Finding::UnparseableShell);
        if unparseable_exec_risk(cmd) {
            assessment.insert(Finding::ExecOrAmbientGit);
        }
        let (loads_config_file, hidden_tool) = unparseable_config_findings(cmd);
        return BashEvaluation {
            segments: raw_deny_rejection(cmd, state).unwrap_or(SegmentEvaluation::Unparseable),
            exact_grant,
            all_segments_granted: false,
            assessment,
            redirect_write: true,
            ambient_segments: None,
            write_facts: Default::default(),
            recovered_eligible: false,
            gated_segments: Vec::new(),
            env_reader_segments: Vec::new(),
            env_steering: None,
            unvouched_shell,
            unscanned_git: unparseable_exec_risk(cmd)
                || crate::permission::exec_risk::script_may_invoke_gh(cmd),
            repository_config_runs: false,
            loads_config_file,
            tool_segments: Vec::new(),
            hidden_tool,
            untrusted_folder: false,
        };
    };
    let writes = command_write_paths_split(tree.root_node(), cmd);
    let write_facts =
        crate::permission::shell_access::ShellWriteFacts::from_tree(tree.root_node(), cmd);
    // An unextractable write-redirect target (`> $OUT`) is a write nothing can vouch for: it both counts as FileWrite and pins `redirect_write`
    let redirect_write = writes.unextracted_write_redirect
        || writes
            .redirect_paths
            .iter()
            .any(|path| !is_safe_write_sink(path));
    // P166 r8B: a branch switch, `pull`, `stash pop`, ... rewrites unspecified working-tree files: the ordinary FileWrite floor
    if redirect_write
        || writes.worktree_rewrite
        || writes
            .word_paths
            .iter()
            .any(|path| !is_safe_write_sink(path))
    {
        assessment.insert(Finding::FileWrite);
    }
    // P166 r9: `GIT_DIR=`/`GIT_WORK_TREE=`/`GIT_EXEC_PATH=`/... assignments are the same exec class as the matching flags.
    // u35 g12: such an assignment points git at a repository the ambient scan does not read (`unscanned_git`).
    let git_env_assignment =
        crate::permission::shell_access::tree_has_git_exec_env_assignment(tree.root_node(), cmd);
    if git_env_assignment {
        assessment.insert(Finding::ExecOrAmbientGit);
    }
    // u35: a redirect to `/dev/tcp/…` or `/dev/udp/…` opens a network socket (read or write), not a file. u35 r1: judged
    // on the normalised destination; one the normaliser cannot pin is an unresolved argument.
    let redirect_risk =
        crate::permission::shell_access::tree_redirect_destination_risk(tree.root_node(), cmd);
    // u35 r2: a redirect reading a process environment (`< /proc/self/environ`) is an environment dump.
    if redirect_risk.socket || redirect_risk.environ {
        assessment.insert(Finding::SpecialExecSurface);
    }
    if redirect_risk.unresolved {
        assessment.insert(Finding::UnresolvedArgument);
    }
    // u35 r2: a declaration that prints variables (`declare -p NAME`, `export -p`, `typeset`) is an environment dump.
    if crate::permission::shell_access::tree_has_environment_dump_declaration(tree.root_node(), cmd)
    {
        assessment.insert(Finding::SpecialExecSurface);
    }
    // u35: a `cd` in a pipeline, subshell or `||` list leaves the directory a later git runs in uncertain.
    let uncertain_cwd =
        crate::permission::shell_access::tree_has_uncertain_cwd_change(tree.root_node(), cmd);
    let segments = try_parse_word_only_commands_sequence(&tree, cmd);
    if let Some(finding) = env_risk_finding(script_env_risk(
        tree.root_node(),
        cmd,
        segments.as_deref().unwrap_or_default(),
    )) {
        assessment.insert(finding);
    }
    let Some(segments) = segments else {
        // Recover the shape of a quoted-filename-variable script: unknown argv positions are kept as written and
        // never guessed, and a dangerous or exec-capable projection is flagged exactly as a decomposed segment is.
        let recovery = PermissionScript::analyze(&tree, cmd);
        if recovery.has_unresolved() {
            assessment.insert(Finding::UnresolvedArgument);
        }
        let projections = recovery.projections();
        let floor_projections = recovery.floor_projections();
        let mut env_reader_segments: Vec<Vec<String>> = Vec::new();
        let mut loads_config_file = false;
        let mut tool_segments = Vec::new();
        let mut hidden_tool = false;
        // u35 g14 (Grok r13 High): a recovered `gh` command (`out=$(gh pr view 1)`) is scanned like a git command; a
        // `gh` word in no recovered `gh` command runs where no scan looked.
        let mut gh_planned = false;
        let mut hidden_gh = false;
        for (words, marked) in projections.iter().zip(&floor_projections) {
            if crate::permission::exec_risk::is_planned_gh_segment(words) {
                gh_planned = true;
            } else if words
                .iter()
                .any(|word| crate::permission::exec_risk::script_may_invoke_gh(word))
            {
                hidden_gh = true;
            }
            let floors = SegmentFloors::of(words, marked);
            env_reader_segments.push(floors.inner.to_vec());
            tool_segments.extend(tool_segment_of(words, &floors));
            hidden_tool |= names_hidden_tool(words, &floors);
            if floors.dangerous {
                assessment.insert(Finding::DangerousCommand);
            }
            if floors.special {
                assessment.insert(Finding::SpecialExecSurface);
            }
            loads_config_file |= floors.config_file;
            if floors.opaque {
                assessment.insert(Finding::OpaqueShell);
            }
            if floors.parsing_changed {
                assessment.insert(Finding::UnparseableShell);
            }
            if segment_exec_facts(unwrap_wrappers(words)).exec_risk {
                assessment.insert(Finding::ExecOrAmbientGit);
            }
        }
        // WHY: undecomposable dynamic `bash -c "$X"`/`eval` is still opaque shell.
        if !recovery.is_eligible() {
            assessment.insert(Finding::UnparseableShell);
        }
        if tree_has_opaque_shell(tree.root_node(), cmd) {
            assessment.insert(Finding::OpaqueShell);
        }
        if unparseable_exec_risk(cmd) {
            assessment.insert(Finding::ExecOrAmbientGit);
        }
        hidden_gh |= !gh_planned && crate::permission::exec_risk::script_may_invoke_gh(cmd);
        let ambient_segments = (gh_planned && !unparseable_exec_risk(cmd)).then(|| {
            projections
                .iter()
                .map(|words| words.to_vec())
                .collect::<Vec<Vec<String>>>()
        });
        return BashEvaluation {
            // A persisted deny also matches each recovered command (a wrapped `timeout 5 rm "$LOG"` included).
            segments: raw_deny_rejection(cmd, state)
                .or_else(|| {
                    projections.iter().find_map(|words| {
                        raw_deny_rejection(&unwrap_wrappers(words).join(" "), state)
                    })
                })
                .unwrap_or(SegmentEvaluation::Unparseable),
            exact_grant,
            all_segments_granted: false,
            assessment,
            redirect_write: redirect_write || !recovery.is_eligible(),
            ambient_segments,
            // The tree parsed, so its write targets are known even though word-level decomposition failed (`cd "$X" && …`).
            write_facts,
            recovered_eligible: recovery.is_eligible(),
            gated_segments: Vec::new(),
            env_reader_segments,
            env_steering: None,
            unvouched_shell,
            unscanned_git: unparseable_exec_risk(cmd) || hidden_gh,
            repository_config_runs: false,
            loads_config_file,
            tool_segments,
            hidden_tool,
            untrusted_folder: false,
        };
    };
    // Upgrade the raw-string compare with the dequoted single-command form now that the parse is available (see `whole_script_grant`)
    let exact_grant = whole_script_grant(cmd, &segments, state);
    let mut needs_prompt: Vec<String> = Vec::new();
    // u35 r3: segments that ask only because the script is not plain text (the read-only list would cover them).
    let mut gated_segments: Vec<String> = Vec::new();
    let mut via_session_grant = false;
    // u35 g10 (Astra/Grok r9 High): "fully granted" is proved, never assumed. It holds only when some segment matched a
    // grant and no segment that starts a program (a setup one included: `sleep` is a program; the builtin `cd` is
    // not) went without one, so a call made only of setup segments, or a granted command plus an ungranted `sleep`,
    // is approved without a grant.
    let mut granted_segments = 0usize;
    let mut ungranted_segment = false;
    let mut exec_risk = false;
    let mut has_git_command = false;
    // u35 g13 (Astra r12 High): git named by a segment the ambient scan does not model as a git command.
    let mut hidden_git = false;
    let mut loads_config_file = false;
    let mut tool_segments = Vec::new();
    let mut hidden_tool = false;
    let mut ambient_raw: Vec<Vec<String>> = Vec::new();
    let mut env_reader_segments: Vec<Vec<String>> = Vec::new();
    for parsed in segments {
        let raw_words = parsed.words();
        ambient_raw.push(raw_words.to_vec());
        // A word kept as spelled (glob, over-cap brace expansion) proves nothing about the argv that runs.
        let unresolved = parsed.has_unresolved_word();
        if unresolved {
            assessment.insert(Finding::UnresolvedArgument);
        }
        // Peel wrapper commands like `timeout 30 …`, `env FOO=1 …`, `nice -n 5 …` so we classify the *inner* program
        // Without this, `timeout 30 rm -rf /tmp/foo` would be treated as a benign `timeout` invocation and silently auto-allowed
        // `words` (canonical wrappers peeled) is the form grants match; every floor check below runs on `floors`, the
        // one classifier normalisation (u35 r1: `command`/`builtin`/`exec` and the launchers peeled too).
        let words = unwrap_wrappers(raw_words);
        let floors = SegmentFloors::of(raw_words, parsed.floor_words());
        env_reader_segments.push(floors.inner.to_vec());
        tool_segments.extend(tool_segment_of(raw_words, &floors));
        hidden_tool |= names_hidden_tool(raw_words, &floors);
        if floors.opaque {
            assessment.insert(Finding::OpaqueShell);
        }
        // u35 r3: a segment that changes how later words are read (`set +B`, `shopt -s extglob`, `alias`) leaves every
        // later word modelled with the wrong rules.
        if floors.parsing_changed {
            assessment.insert(Finding::UnparseableShell);
        }
        // Raw words: interleaved normalize lives in segment_exec_facts.
        let facts = segment_exec_facts(raw_words);
        if facts.exec_risk {
            exec_risk = true;
            assessment.insert(Finding::ExecOrAmbientGit);
        }
        // u35 g14 (Grok r13 High): `gh` runs git in its directory (`gh status`, `gh pr checkout`), so the ambient scan
        // reads the repository there as for a git command.
        let gh_command = crate::permission::exec_risk::is_planned_gh_segment(raw_words);
        if facts.has_git || gh_command {
            has_git_command = true;
        }
        // u35 g13 (Astra r12 High), g14 (Fable r13 H1, Astra r13 H3): a segment that names git (or `gh`) but is not a
        // git command the ambient scan models runs git where no scan looked: a wrapper the normaliser cannot peel, one
        // that changes directory (`env -C dir git status`), a launcher (`time`, `caffeinate`, `taskset`), or a program
        // that runs another (`sudo`, `xargs`, `find -exec`, `sh -c`). Fail closed on ANY such word rather than model
        // each wrapper; a `cd git` or `echo git` then asks after a model allow, and nothing else changes.
        if !facts.has_git
            && !gh_command
            && raw_words.iter().any(|word| {
                script_may_invoke_git(word)
                    || crate::permission::exec_risk::script_may_invoke_gh(word)
            })
        {
            hidden_git = true;
        }
        loads_config_file |= floors.config_file;
        // `set` / `export` with no operand print every variable: not setup, so they reach the checks below.
        if is_setup_command(words) && !floors.special {
            // A shell builtin (`cd`, `export`, ...) runs no program, so it neither grants nor withholds; a setup
            // program (`sleep`, `timeout`) is a program the runner would start.
            if setup_runs_a_program(words) {
                if segment_matches_grant(words, state) {
                    granted_segments += 1;
                } else {
                    ungranted_segment = true;
                }
            }
            continue;
        }
        let s = words.join(" ");
        let inner_s = floors.inner.join(" ");

        // 1. Disallow takes priority: reject the whole script (the normalised form too: `command rm …`).
        if let Some(d) = state
            .disallowed_bash_commands
            .iter()
            .find(|d| matches_whitelist_prefix(&s, d) || matches_whitelist_prefix(&inner_s, d))
        {
            return BashEvaluation {
                segments: SegmentEvaluation::Reject(format!(
                    "User previously rejected `{d}` in this project"
                )),
                exact_grant,
                all_segments_granted: false,
                assessment: std::mem::take(&mut assessment),
                redirect_write,
                ambient_segments: None,
                write_facts: Default::default(),
                recovered_eligible: false,
                gated_segments: Vec::new(),
                env_reader_segments: Vec::new(),
                env_steering: None,
                unvouched_shell,
                unscanned_git: false,
                repository_config_runs: false,
                loads_config_file: false,
                tool_segments: Vec::new(),
                hidden_tool: false,
                untrusted_folder: false,
            };
        }

        let matched_grant = segment_matches_grant(words, state);
        if matched_grant {
            granted_segments += 1;
        } else {
            ungranted_segment = true;
        }

        // 2. Dangerous commands must be prompted even if a whitelist prefix would otherwise match.
        if floors.dangerous {
            assessment.insert(Finding::DangerousCommand);
            needs_prompt.push(s);
            continue;
        }

        // kubectl config/auth flags, `rg --pre` / `--hostname-bin`, and env-dumping `ps` (BSD `e`/`E`) must prompt even under a whitelist prefix or blanket grant
        // So must a tool in a mode that runs another program or script (`sed e`, `awk system()`, `python -c`, `xargs`, `rsync -e`, ...)
        // So must the git driver/write options (`--textconv`, `--filters`, `--output`, `--ext-diff`, `grep -O`)
        // Always-allow persists only the verb prefix (e.g. "kubectl get", "git cat-file", or a bare "ps" from approving `ps aux`).
        // So a prefix grant cannot be trusted to auto-allow these secret-exposing or exec-capable variants
        // An exact segment grant still auto-allows the segment, but (u35 r1) the finding is always recorded: only an
        // exact WHOLE-SCRIPT grant clears a floor, so a grant for one segment cannot carry a script appended to it.
        // Do NOT insert DangerousCommand; that would also block exact grants
        if floors.special {
            assessment.insert(Finding::SpecialExecSurface);
            if !state.allowed_bash_commands.contains(&s) {
                needs_prompt.push(s);
                continue;
            }
        }

        // 3. Auto-allow conditions. Built-in safe lists count only when `honor_safe_lists` is set; an explicit user grant always counts.
        // A path-qualified or case-variant program (or wrapper) is not the program the list names.
        // u35 r1: matched on the normalised argv, never through a launcher (`time`, `nohup`, `sudo`).
        let inner = floors.inner;
        let listed = honor_safe_lists
            && !unresolved
            && !floors.launched
            && program_identity_is_plain(raw_words)
            && (is_safe_command_words(inner)
                || is_always_safe_command_words(inner)
                || is_safe_creation_command(inner));
        let matched_safe = plain_text && listed;
        if matched_grant || matched_safe {
            if matched_grant {
                via_session_grant = true;
            }
            continue;
        }

        // 4. Otherwise: prompt for this segment.
        if listed {
            gated_segments.push(s.clone());
        }
        needs_prompt.push(s);
    }
    // u35 r3: setup segments (`cd`, `sleep`, ...) are skipped above; a script that is not plain text and that no user
    // grant covered must not auto-allow through them alone (`cd /tmp && sleep 5`).
    if needs_prompt.is_empty() && !plain_text && !via_session_grant {
        gated_segments.push(cmd.to_owned());
        needs_prompt.push(cmd.to_owned());
    }
    if has_git_command && uncertain_cwd {
        exec_risk = true;
        assessment.insert(Finding::ExecOrAmbientGit);
    }
    // u35 r1: a redirect destination the normaliser cannot pin is not covered by a read-only list.
    if redirect_risk.unresolved {
        needs_prompt.push(cmd.to_owned());
    }
    let all_segments_granted = granted_segments > 0 && !ungranted_segment;
    let segments = if needs_prompt.is_empty() {
        SegmentEvaluation::AutoAllow { via_session_grant }
    } else {
        SegmentEvaluation::NeedsPrompts {
            segments: needs_prompt,
        }
    };
    let ambient_segments = if has_git_command && !exec_risk {
        Some(ambient_raw)
    } else {
        None
    };
    BashEvaluation {
        segments,
        exact_grant,
        all_segments_granted,
        assessment,
        redirect_write,
        ambient_segments,
        write_facts,
        recovered_eligible: false,
        gated_segments,
        env_reader_segments,
        env_steering: None,
        unvouched_shell,
        unscanned_git: (has_git_command && (exec_risk || git_env_assignment)) || hidden_git,
        repository_config_runs: false,
        loads_config_file,
        tool_segments,
        hidden_tool,
        untrusted_folder: false,
    }
}

/// u35 g10: a setup segment ([`is_setup_command`]) that starts a program, as opposed to a shell builtin.
fn setup_runs_a_program(words: &[String]) -> bool {
    words.first().is_some_and(|head| {
        !matches!(
            head.as_str(),
            "cd" | "pushd" | "popd" | "export" | "unset" | "set"
        )
    })
}

/// Whether a remembered command or glob grant covers one segment (`words`, canonical wrappers peeled).
/// Pinned commands run whatever argv follows, so a prefix grant would widen
/// `docker run nginx` must not match `... --privileged`, nor `sed -n 1p f` match `sed -n 1p f -e 'w /tmp/x'`.
/// Their saved scope is the full command, so enforce it on the exact segment only
/// u35 r1: a prefix grant matches on argv boundaries (`ls` does not cover the one word `'ls -la'`).
fn segment_matches_grant(words: &[String], state: &PermissionState) -> bool {
    let s = words.join(" ");
    let head_unambiguous = words
        .first()
        .is_some_and(|head| !head.is_empty() && !head.chars().any(char::is_whitespace));
    let matched_command_grant = head_unambiguous
        && if always_allow_scope_pinned(words) {
            state.allowed_bash_commands.contains(s.as_str())
        } else {
            state
                .allowed_bash_commands
                .iter()
                .any(|a| grant_prefix_matches_argv(words, a))
        };
    matched_command_grant
        || state
            .allowed_bash_globs
            .iter()
            .any(|g| matches_bash_glob(&s, g))
}

/// The protected-target floor for one request: a direct edit of a protected path (`.git/hooks`, `.ssh`, shell
/// startup files, Fuigo/Claude config, `/etc`, ...) or a `mkdir`/`touch` of one. Relative paths resolve against
/// `real_cwd` (shown as `display_cwd`). Shared by the manager and the hub path so both see the same floor (P173).
fn protected_target(
    access: &AccessKind,
    bash_evaluation: Option<&BashEvaluation>,
    real_cwd: &std::path::Path,
    display_cwd: Option<&std::path::Path>,
) -> Option<crate::permission::shell_access::ProtectedEditReason> {
    match access {
        AccessKind::Edit(path) => {
            edit_target_protection(&resolve_model_path(real_cwd, display_cwd, path))
        }
        AccessKind::Bash(_) => {
            bash_evaluation.and_then(|e| bash_protected_write_target(e, real_cwd, display_cwd))
        }
        _ => None,
    }
}

/// S6.4: the peer guard's verdict for a shell command of a peer-influenced session. Write targets (redirects, `tee`,
/// `cp`/`mv`/`ln` destinations, `sed -i`, rename-over, `git config`, ...) go through the same evaluator and resolver as the
/// protected floor, with the peer-extended set added; a script the evaluator cannot parse counts as touching the set.
pub(crate) fn peer_bash_denial(
    cmd: &str,
    real_cwd: &std::path::Path,
    display_cwd: Option<&std::path::Path>,
) -> Option<String> {
    crate::permission::shell_access::with_peer_extended_set(|| {
        let evaluation = evaluate_bash(cmd, &PermissionState::default(), true);
        let unparseable = matches!(evaluation.segments, SegmentEvaluation::Unparseable);
        let hit = bash_protected_write_target(&evaluation, real_cwd, display_cwd).is_some();
        if unparseable || (hit && evaluation.write_facts.has_unresolved()) {
            // The command could not be analysed: a distinct text, so a stalled lane is told how to go on.
            return Some(crate::permission::peer_guard::peer_unanalysable_denial_text());
        }
        hit.then(|| {
            crate::permission::peer_guard::peer_guard_denial_text("the command's write target")
        })
    })
}

/// [`protected_target`] for a hub-routed call, which has no session grants: the bash command is classified against
/// empty state, which only decides the protected floor here (P173).
pub(crate) fn hub_protected_target(
    access: &AccessKind,
    cwd: &std::path::Path,
) -> Option<crate::permission::shell_access::ProtectedEditReason> {
    let evaluation = match access {
        AccessKind::Bash(cmd) => Some(evaluate_bash(cmd, &PermissionState::default(), true)),
        _ => None,
    };
    protected_target(access, evaluation.as_ref(), cwd, None)
}

/// The one tool that is `AccessKind::Tool` yet never prompts (design row 3a). A deny or ask rule still binds it: the policy
/// step runs before the pre-decision that consults this.
pub(crate) fn is_auto_allowed_tool(name: &str) -> bool {
    name == "send_message"
}

/// What the local manager does, with no session grants, for a request that no rule denied or asked about and that is
/// not protected (P173). `policy_allows`: a configured allow rule matched it. `true` means it would prompt (or, under
/// dontAsk, refuse); `false` means it allows the request by itself: a read, a safe-listed command, or an allow rule
/// that also clears the bash request floor. A fetch prompts unless a rule allows it (the built-in fetch allowlist is
/// not consulted here, which only ever asks more).
///
/// Blocking: a command that may run git gets the local manager's ambient repository-config scan, anchored to `cwd`.
pub(crate) fn hub_needs_default_prompt(
    access: &AccessKind,
    policy: Option<&CompiledPolicy>,
    policy_allows: bool,
    cwd: &std::path::Path,
) -> bool {
    hub_default_prompt(access, policy, policy_allows, cwd, None).needs
}

/// What [`hub_needs_default_prompt`] decided, and why when `cover` (the sandbox's cover for this call, if any)
/// was supplied: the reasons the sandbox-card rule weighs. Without a cover `causes` stays empty and `needs`
/// is exactly what `hub_needs_default_prompt` always answered.
pub(crate) struct HubDefaultPrompt {
    pub(crate) needs: bool,
    pub(crate) causes: Vec<crate::permission::AskCause>,
}

pub(crate) fn hub_default_prompt(
    access: &AccessKind,
    policy: Option<&CompiledPolicy>,
    policy_allows: bool,
    cwd: &std::path::Path,
    cover: Option<&crate::permission::SandboxCover>,
) -> HubDefaultPrompt {
    let plain = |needs: bool| HubDefaultPrompt {
        needs,
        causes: Vec::new(),
    };
    match access {
        // u35 g8 (Astra r7): the program Fuigo's grep tool runs is chosen by the environment
        AccessKind::Grep { .. }
            if crate::permission::exec_risk::grep_tool_env_steers(cwd).is_some() =>
        {
            plain(true)
        }
        AccessKind::Read(_)
        | AccessKind::Session
        | AccessKind::Grep { .. }
        | AccessKind::WebSearch(_) => plain(false),
        AccessKind::Tool(name) if is_auto_allowed_tool(name) => plain(false),
        AccessKind::Bash(cmd) => {
            let mut evaluation = evaluate_bash(cmd, &PermissionState::default(), true);
            // u35 g7: the same inherited-environment check as the local manager, before the scan runs any git.
            add_inherited_env_finding(&mut evaluation, cwd);
            add_tool_config_finding(&mut evaluation, cwd);
            // The same ambient git scan the manager runs before any grant or allow decision (`git status` in a repo
            // whose config runs a program is not safe).
            let mut branch_plan = BranchSwitchPlan::NotApplicable;
            if let Some(raw) = evaluation.ambient_segments.take() {
                branch_plan = branch_switch_plan_with(&raw, cwd, Some(&evaluation.write_facts));
                add_ambient_git_findings(
                    &mut evaluation,
                    ambient_git_risk_from_plan(&ambient_scan_plan_from_segments(&raw, cwd)),
                );
            }
            let floor = bash_request_floor_requires_prompt(Some(&evaluation));
            let needs = if policy_allows {
                // P166 r13B: the same branch-switch check as the local manager (shared pair of functions).
                let kept = floor
                    && branch_switch_floor_kept_blocking(
                        &branch_plan,
                        &evaluation,
                        policy,
                        access,
                        &GitTreeLister,
                    );
                broad_allow_deferred(Some(&evaluation), policy, access, true, kept)
            } else {
                floor
                    || !matches!(evaluation.segments, SegmentEvaluation::AutoAllow { .. })
                    || no_grant_approval_switched_off(&evaluation)
            };
            let causes = match cover {
                Some(cover) if needs => sandbox_card_causes::bash_ask_causes(
                    &evaluation,
                    policy_allows,
                    &branch_plan,
                    cwd,
                    cover,
                ),
                _ => Vec::new(),
            };
            HubDefaultPrompt { needs, causes }
        }
        AccessKind::Edit(_)
        | AccessKind::MCPTool { .. }
        | AccessKind::WebFetch(_)
        | AccessKind::AgentMessage { .. }
        | AccessKind::Tool(_) => plain(!policy_allows),
    }
}

/// u35 t1 (design d2 §4.3): [`hub_default_prompt`] for a Bash command whose folder is not trusted. Nothing is approved
/// without a grant; an allow rule that covers the command (`policy_allows`) still runs it under the floors, which are
/// judged without running anything the folder configures: the in-process git reader only, and the branch-switch
/// floor stays.
pub(crate) fn hub_untrusted_bash_needs_prompt(
    cmd: &str,
    policy: Option<&CompiledPolicy>,
    policy_allows: bool,
    cwd: &std::path::Path,
) -> bool {
    if !policy_allows {
        return true;
    }
    let access = AccessKind::Bash(cmd.to_owned());
    let mut evaluation = evaluate_bash(cmd, &PermissionState::default(), true);
    evaluation.untrusted_folder = true;
    add_inherited_env_finding(&mut evaluation, cwd);
    add_tool_config_finding(&mut evaluation, cwd);
    if let Some(raw) = evaluation.ambient_segments.take() {
        add_ambient_git_findings(
            &mut evaluation,
            ambient_git_risk_from_plan_in(&ambient_scan_plan_from_segments(&raw, cwd), false),
        );
    }
    let floor = bash_request_floor_requires_prompt(Some(&evaluation));
    broad_allow_deferred(Some(&evaluation), policy, &access, true, floor)
}

#[cfg(test)]
pub(crate) fn evaluate_bash_segments(cmd: &str, state: &PermissionState) -> SegmentEvaluation {
    evaluate_bash(cmd, state, true).segments
}

#[cfg(test)]
pub(crate) fn evaluate_bash_segments_inner(
    cmd: &str,
    state: &PermissionState,
    honor_safe_lists: bool,
) -> SegmentEvaluation {
    evaluate_bash(cmd, state, honor_safe_lists).segments
}

impl PermissionHandle {
    pub fn allow_all() -> Self {
        PermissionHandle::AllowAll(PeerInfluence::new())
    }

    /// The live peer-influenced flag of this session (S6.1), shared by every clone of the handle.
    pub fn peer_influence(&self) -> PeerInfluence {
        match self {
            PermissionHandle::AllowAll(flag) => flag.clone(),
            PermissionHandle::Actor { mode_view, .. } => mode_view.peer_influence.clone(),
        }
    }

    pub fn is_peer_influenced(&self) -> bool {
        match self {
            PermissionHandle::AllowAll(flag) => flag.is_set(),
            PermissionHandle::Actor { mode_view, .. } => mode_view.peer_influence.is_set(),
        }
    }

    pub fn set_peer_influenced(&self, influenced: bool) {
        self.peer_influence().set(influenced);
    }

    /// Replace the flag with a shared one (right after spawn, before the handle is cloned), so the session's other
    /// holders of the flag see the same value.
    pub fn with_peer_influence(mut self, shared: PeerInfluence) -> Self {
        match &mut self {
            PermissionHandle::AllowAll(flag) => *flag = shared,
            PermissionHandle::Actor { mode_view, .. } => mode_view.peer_influence = shared,
        }
        self
    }

    /// `Some(reason)` when the peer guard denies this request (S6.3). `None` for a session that is not peer-influenced.
    pub fn peer_guard_denial_for(&self, request: &PermissionRequest) -> Option<String> {
        if !self.is_peer_influenced() {
            return None;
        }
        let fallback = match self {
            PermissionHandle::Actor { mode_view, .. } => mode_view.fallback_cwd.clone(),
            PermissionHandle::AllowAll(_) => None,
        };
        let (real, display) = match &request.path_context {
            Some(c) => (c.real_cwd.clone(), c.display_cwd.clone()),
            None => (
                fallback
                    .or_else(|| std::env::current_dir().ok())
                    .unwrap_or_else(|| std::path::PathBuf::from("/")),
                None,
            ),
        };
        crate::permission::peer_guard::peer_guard_denial(
            &request.access,
            request.edit_targets.as_ref(),
            &real,
            display.as_deref(),
        )
    }

    pub fn set_yolo_mode(&self, enabled: bool) {
        if let PermissionHandle::Actor {
            cmd_tx,
            yolo_state,
            auto_state,
            yolo_pin,
            mode_view,
            ..
        } = self
        {
            // Clamp the Arc synchronously so `is_yolo_mode()` is correct immediately (no optimistic-true window)
            // The raw request is still forwarded so the actor logs the refusal once and re-clamps
            let clamped = clamp_yolo(enabled, *yolo_pin);
            yolo_state.store(clamped, Ordering::Relaxed);
            if clamped {
                auto_state.store(false, Ordering::Relaxed);
            }
            pair_set_yolo(&mode_view.mode_pair, clamped);
            if let Err(e) = cmd_tx.send(PermissionCommand::SetYoloMode(enabled)) {
                tracing::error!(?e, "failed to send yolo mode command");
            }
        }
    }

    /// Enable or disable auto mode (LLM classifier).
    /// Enabling auto clears yolo and installs the default conversation-aware classifier when none is set.
    pub fn set_auto_mode(&self, enabled: bool) {
        if let PermissionHandle::Actor {
            cmd_tx,
            yolo_state,
            auto_state,
            mode_view,
            ..
        } = self
        {
            auto_state.store(enabled, Ordering::Relaxed);
            if enabled {
                yolo_state.store(false, Ordering::Relaxed);
            }
            pair_set_auto(&mode_view.mode_pair, enabled);
            if let Err(e) = cmd_tx.send(PermissionCommand::SetAutoMode(enabled)) {
                tracing::error!(?e, "failed to send auto mode command");
            }
        }
    }

    /// Install a classifier implementation for auto mode (tests and production).
    /// Clears [`Self::has_llm_side_query`] unless you also call [`Self::set_llm_side_query_wired`].
    /// Prefer [`Self::set_classifier_with_side_query`] when installing a live sampler.
    pub fn set_classifier(
        &self,
        classifier: Option<crate::permission::auto_mode::SharedClassifier>,
    ) {
        if let PermissionHandle::Actor {
            cmd_tx,
            side_query_wired,
            ..
        } = self
        {
            // Opaque trait object; assume no side-query unless the caller marks it
            side_query_wired.store(false, Ordering::Relaxed);
            if let Err(e) = cmd_tx.send(PermissionCommand::SetClassifier(classifier)) {
                tracing::error!(?e, "failed to send set classifier command");
            }
        }
    }

    /// Install classifier and record whether it has a live `ClassifyTextFn`.
    pub fn set_classifier_with_side_query(
        &self,
        classifier: crate::permission::auto_mode::SharedClassifier,
        has_side_query: bool,
    ) {
        if let PermissionHandle::Actor {
            cmd_tx,
            side_query_wired,
            ..
        } = self
        {
            side_query_wired.store(has_side_query, Ordering::Relaxed);
            if let Err(e) = cmd_tx.send(PermissionCommand::SetClassifier(Some(classifier))) {
                tracing::error!(?e, "failed to send set classifier command");
            }
        }
    }

    /// Mark whether the current auto classifier uses a live LLM side-query.
    pub fn set_llm_side_query_wired(&self, wired: bool) {
        if let PermissionHandle::Actor {
            side_query_wired, ..
        } = self
        {
            side_query_wired.store(wired, Ordering::Relaxed);
        }
    }

    /// Update recent transcript turns used by the auto-mode classifier.
    pub fn set_classifier_transcript(
        &self,
        turns: Vec<crate::permission::auto_mode::ClassifierTurn>,
    ) {
        if let PermissionHandle::Actor { cmd_tx, .. } = self
            && let Err(e) = cmd_tx.send(PermissionCommand::SetClassifierTranscript(turns))
        {
            tracing::error!(?e, "failed to send classifier transcript command");
        }
    }

    /// Update the project AGENTS.md instructions used by the auto-mode classifier.
    pub fn set_project_instructions(&self, instructions: Option<String>) {
        if let PermissionHandle::Actor { cmd_tx, .. } = self
            && let Err(e) = cmd_tx.send(PermissionCommand::SetProjectInstructions(instructions))
        {
            tracing::error!(?e, "failed to send project instructions command");
        }
    }

    /// u35 t1 (design d2 §3.4): what this session's policy was built from ([`crate::permission::resolution::
    /// resolve_session_policy`]). Sent right after the manager is spawned, before any request. A command whose folder
    /// is not trusted is then judged without the project tier, and the policy is rebuilt when folder trust changes.
    pub fn set_session_policy_inputs(
        &self,
        inputs: crate::permission::resolution::SessionPolicyInputs,
    ) {
        if let PermissionHandle::Actor { cmd_tx, .. } = self
            && let Err(e) = cmd_tx.send(PermissionCommand::SetSessionPolicyInputs(Arc::new(inputs)))
        {
            tracing::error!(?e, "failed to send session policy inputs");
        }
    }

    /// Reset per-tool permission state back to defaults.
    pub fn reset_state(&self) {
        // Clear the mirrored grant here too so the very next report cannot still show it; the actor clears its own copy.
        if let PermissionHandle::Actor { mode_view, .. } = self {
            mode_view.session_edit_grant.store(false, Ordering::SeqCst);
        }
        if let PermissionHandle::Actor { cmd_tx, .. } = self
            && let Err(e) = cmd_tx.send(PermissionCommand::ResetState)
        {
            tracing::error!(?e, "failed to send reset state command");
        }
    }

    /// First writer wins so a cloned (subagent) handle cannot replace the owner.
    /// A closed sender is treated as vacant: the owner listener holds a `Weak` and drops `rx` when the session dies, so a later owner can re-wire.
    pub fn set_user_prompt_notify(&self, tx: mpsc::UnboundedSender<()>) {
        if let PermissionHandle::Actor {
            user_prompt_notify, ..
        } = self
        {
            let mut slot = user_prompt_notify.lock();
            if slot.as_ref().is_some_and(|existing| !existing.is_closed()) {
                tracing::debug!("user_prompt_notify already set; first writer wins");
                return;
            }
            *slot = Some(tx);
        }
    }

    pub fn is_yolo_mode(&self) -> bool {
        match self {
            PermissionHandle::AllowAll(_) => true,
            PermissionHandle::Actor { yolo_state, .. } => yolo_state.load(Ordering::Relaxed),
        }
    }

    /// The base mode right now, read from the live state on every call (never cached).
    /// Order mirrors the actor: always-approve beats everything (even `dontAsk`, see the warn in spawn), then auto,
    /// then the configured base. yolo/auto come from one packed atomic load (see [`ModeView::mode_pair`]).
    /// Plan and the edit grant are separate dimensions: see [`Self::effective_peer_mode`].
    pub fn effective_mode(&self) -> crate::permission::types::EffectivePermissionMode {
        use crate::permission::types::EffectivePermissionMode as M;
        match self {
            PermissionHandle::AllowAll(_) => M::AllowAll,
            PermissionHandle::Actor { mode_view, .. } => {
                let pair = mode_view.mode_pair.load(Ordering::SeqCst);
                if pair & PAIR_YOLO != 0 {
                    M::Yolo
                } else if pair & PAIR_AUTO != 0 {
                    M::Auto
                } else {
                    mode_view.base
                }
            }
        }
    }

    /// Whether the "allow edits for this session" answer is in force (live, every call).
    pub fn session_edit_grant(&self) -> bool {
        match self {
            PermissionHandle::AllowAll(_) => false,
            PermissionHandle::Actor { mode_view, .. } => {
                mode_view.session_edit_grant.load(Ordering::SeqCst)
            }
        }
    }

    /// The full report with the plan flag supplied by the session (plan state lives outside the permission layer).
    pub fn effective_peer_mode(
        &self,
        plan_active: bool,
    ) -> crate::permission::types::EffectivePeerMode {
        crate::permission::types::EffectivePeerMode {
            plan_active,
            base: self.effective_mode(),
            session_edit_grant: self.session_edit_grant(),
        }
    }

    pub fn is_auto_mode(&self) -> bool {
        match self {
            PermissionHandle::AllowAll(_) => false,
            PermissionHandle::Actor { auto_state, .. } => auto_state.load(Ordering::Relaxed),
        }
    }

    /// Whether the installed auto classifier has a live LLM `ClassifyTextFn` (session sampling).
    /// False when only the heuristic fallback is active.
    pub fn has_llm_side_query(&self) -> bool {
        match self {
            PermissionHandle::AllowAll(_) => false,
            PermissionHandle::Actor {
                side_query_wired, ..
            } => side_query_wired.load(Ordering::Relaxed),
        }
    }

    /// Grep Read-deny globs; empty for `AllowAll`.
    /// Subagents inherit these via the shared handle.
    /// 1.0.36 item a: attach the session's launch policy file (the one its config was resolved with).
    pub fn with_launch_policy(
        mut self,
        policy: Option<Arc<crate::permission::launch_policy::LaunchPolicy>>,
    ) -> Self {
        if let PermissionHandle::Actor { mode_view, .. } = &mut self {
            mode_view.launch_policy = policy;
        }
        self
    }

    /// 1.0.36 item a: the session's own launch policy file, for a subagent or workflow that builds its own actor.
    pub fn launch_policy(&self) -> Option<Arc<crate::permission::launch_policy::LaunchPolicy>> {
        match self {
            PermissionHandle::AllowAll(_) => None,
            PermissionHandle::Actor { mode_view, .. } => mode_view.launch_policy.clone(),
        }
    }

    /// 1.0.36 item a: whether a launch policy governs this session (the process's or its own).
    pub fn has_launch_policy(&self) -> bool {
        crate::permission::launch_policy::has_process_policy() || self.launch_policy().is_some()
    }

    pub fn deny_read_globs(&self) -> Vec<String> {
        match self {
            PermissionHandle::AllowAll(_) => Vec::new(),
            PermissionHandle::Actor {
                deny_read_globs, ..
            } => deny_read_globs.as_ref().clone(),
        }
    }

    /// Decide only (bang-controls): the reason of the configured rules/policy DENY for `access`, else `None`.
    /// It is the same evaluation `request` runs before YOLO (`GatePreflight::policy_decision`), but it never prompts and
    /// treats ask rules, `dontAsk`, plan mode and auto mode as "no refusal". Fails closed if the manager is gone.
    pub async fn configured_deny(
        &self,
        access: AccessKind,
        cwd: std::path::PathBuf,
    ) -> Option<String> {
        match self {
            PermissionHandle::AllowAll(_) => None,
            PermissionHandle::Actor { cmd_tx, .. } => {
                let (tx, rx) = oneshot::channel();
                let msg = PermissionCommand::DecideOnly {
                    access,
                    cwd,
                    respond_to: tx,
                };
                if cmd_tx.send(msg).is_err() {
                    return Some("permission manager unavailable".to_owned());
                }
                match rx.await {
                    Ok(verdict) => verdict,
                    Err(_) => Some("failed to receive permission decision".to_owned()),
                }
            }
        }
    }

    /// Decide a request, then remember a denial in the session's ring (S7.1: by the human, by policy, by `dontAsk` or by the
    /// peer guard). The ring holds the tool kind and a hash only, in memory.
    pub async fn request(&self, request: PermissionRequest) -> PermissionResolution {
        use crate::permission::peer_denials as pd;
        let denials = self.peer_influence().denials().clone();
        // Keys are computed lazily: for the carried-list match (only when a list is carried), or for a denial to record.
        // The match uses BOTH spellings of every path (`match_keys`); a denial is RECORDED with one key per target
        // (`KeyBasis::keys`), so the two sets are computed apart.
        let carried_keys = denials.has_carried().then(|| pd::match_keys(&request));
        let basis = pd::KeyBasis::of(&request);
        let resolution = self.request_decided(request, carried_keys.as_deref()).await;
        if is_recordable_denial(&resolution) {
            denials.record_keys(basis.keys(), pd::mono_secs());
        }
        resolution
    }

    async fn request_decided(
        &self,
        mut request: PermissionRequest,
        carried_keys: Option<&[crate::permission::peer_denials::DenialKey]>,
    ) -> PermissionResolution {
        // S6.7: the classifier sees the session's own state, never what a caller put in the request.
        request.peer_note = self.peer_influence().payload_note();
        // S6.3: the peer guard runs before every approving path below (allow-all, yolo, auto, grants, rules,
        // the classifier). It can only deny; a session that is not peer-influenced skips it after one atomic load.
        // It runs first, so a protected write keeps the guard's refusal text.
        if let Some(reason) = self.peer_guard_denial_for(&request) {
            return PermissionResolution {
                decision: Decision::PolicyDeny(reason),
                event: None,
            };
        }
        // S7.3: a request that matches a denial carried by a released peer message is denied before every approving path
        // (allow-all, yolo, auto, grants, rules, the classifier), whatever the mode. A session that carries nothing has no
        // keys here and finds nothing.
        if let Some(keys) = carried_keys
            && let Some(hit) = self.peer_influence().denials().match_carried_any(keys)
        {
            return PermissionResolution {
                decision: Decision::PolicyDeny(
                    crate::permission::peer_denials::laundering_refused_text(&hit.kind),
                ),
                event: None,
            };
        }
        match self {
            PermissionHandle::AllowAll(_) => {
                if let Some(ask) = &request.hook_ask {
                    tracing::debug!(
                        hook_name = %ask.hook_name,
                        "hook ask dropped: this permission handle cannot prompt"
                    );
                }
                PermissionResolution {
                    decision: Decision::Allow,
                    event: None,
                }
            }
            PermissionHandle::Actor {
                cmd_tx, in_flight, ..
            } => {
                let _in_flight_guard = InFlightGuard::new(in_flight);
                let (tx, rx) = oneshot::channel::<PermissionResolution>();
                let msg = PermissionCommand::Request {
                    request,
                    respond_to: tx,
                };
                if let Err(e) = cmd_tx.send(msg) {
                    tracing::error!(?e, "failed to send permission request");
                    return PermissionResolution {
                        decision: Decision::Reject("permission manager unavailable".to_owned()),
                        event: None,
                    };
                }

                match rx.await {
                    Ok(resolution) => resolution,
                    Err(e) => {
                        tracing::error!(?e, "failed to receive permission decision");
                        PermissionResolution {
                            decision: Decision::Reject(
                                "failed to receive permission decision".to_owned(),
                            ),
                            event: None,
                        }
                    }
                }
            }
        }
    }
}

/// S7.1: what a resolution says about how the request ended, for the one recording rule ([`records_denial`]) the hub path
/// shares. "Shown" is inferred (the prompt section ran and the requester stayed): the prompter reports no display signal.
fn denial_cause(r: &PermissionResolution) -> Option<crate::permission::DenialCause> {
    use crate::permission::DenialCause as C;
    Some(match &r.decision {
        Decision::PolicyDeny(_) => C::Policy,
        Decision::FollowupMessage(_) => C::HumanFollowup,
        Decision::Reject(_)
            if r.event
                .as_ref()
                .is_some_and(|e| e.prompt_outcome.as_deref() == Some("error")) =>
        {
            C::PromptError
        }
        Decision::Reject(text)
            if r.event.is_none()
                && matches!(
                    text.as_str(),
                    "permission manager unavailable" | "failed to receive permission decision"
                ) =>
        {
            C::ManagerFailure
        }
        Decision::Reject(_) => C::HumanReject,
        Decision::Cancelled => match r.event.as_ref() {
            Some(e) if e.decision_reason.as_deref() == Some(reasons::REQUESTER_GONE) => {
                C::RequesterGone
            }
            Some(e) if e.user_prompted && e.prompt_outcome.as_deref() == Some("cancelled") => {
                C::ShownThenCancelled
            }
            _ => C::NotShown,
        },
        Decision::Allow | Decision::Ask => return None,
    })
}

fn is_recordable_denial(r: &PermissionResolution) -> bool {
    denial_cause(r).is_some_and(crate::permission::records_denial)
}

/// Clamp requested yolo against the pin: the pin wins, so a client can never enable always-approve while it is set.
fn clamp_yolo(requested: bool, yolo_pin: Option<&'static str>) -> bool {
    requested && yolo_pin.is_none()
}

const MAX_RECORDED_PERMISSION_DECISIONS: usize = 12;

fn prompted_decision_approved(decision: &Decision, outcome_str: &str) -> Option<bool> {
    match decision {
        Decision::Allow => Some(true),
        Decision::Reject(_) if outcome_str != "error" => Some(false),
        _ => None,
    }
}

/// Whether an auto-forced prompt must neutralize a pre-decided `Allow`; true for every non-bash access.
/// Session grants short-circuit before classify, so this is defense-in-depth for leftover non-grant Allows.
/// Bash is carved out: its post-classify grant path is gated on `!auto_forced_prompt` upstream.
fn auto_prompt_blocks_allow(access: &AccessKind) -> bool {
    !matches!(access, AccessKind::Bash(_))
}

/// Whether persisted state auto-approves bash `cmd`.
/// The user-writable `allow_bash_execute` is clamped under the pin so it can't substitute for `--yolo`.
/// Explicit `allowed_bash_commands` grants still apply.
fn persisted_bash_auto_allows(
    state: &PermissionState,
    cmd: &str,
    yolo_pin: Option<&'static str>,
) -> bool {
    (state.allow_bash_execute && yolo_pin.is_none()) || state.allowed_bash_commands.contains(cmd)
}

/// A broad grant must prompt rather than auto-allow when the request's assessment carries a grant-floor finding.
/// Broad covers the session `allow_bash_execute` blanket, prefix/glob grants, and sandbox auto-allow.
/// It also covers a broad configured policy Allow deferred to the confirmation floor.
/// An exact whole-command grant is explicit user authority and bypasses this.
/// Delegates to the single canonical [`BashSecurityAssessment`]; no re-derivation of per-effect fields.
fn bash_request_floor_requires_prompt(evaluation: Option<&BashEvaluation>) -> bool {
    evaluation.is_some_and(|e| !e.exact_grant && e.assessment.constrains_broad_grant())
}

/// u35: the floor for session grants (prefix/glob grants and the `allow_bash_execute` blanket) and sandbox auto-allow.
/// On top of [`bash_request_floor_requires_prompt`], a destructive command (`DangerousCommand`), an argument only the
/// shell resolves (`UnresolvedArgument`) and structure the classifier cannot decompose (`UnparseableShell`) are not
/// covered by a grant given for other commands. An exact whole-command grant is the user's authority for this command
/// and bypasses it. Configured allow rules keep [`bash_request_floor_requires_prompt`]: a narrow rule naming a
/// destructive command clears `DangerousCommand`, and the catch-all rule is a documented explicit override.
fn bash_session_floor_requires_prompt(evaluation: Option<&BashEvaluation>) -> bool {
    evaluation.is_some_and(|e| !e.exact_grant && e.assessment.constrains_session_grant())
}

/// Whether a configured allow rule clears the bash request floor in ask/dontAsk.
/// Requires ALL of the following.
/// The assessment is `FileWrite`-only (other floor findings describe effects outside the rule's matched words).
/// The writes are command-word operands rather than redirects (which word matching cannot see).
/// Narrow allow rules authorize every segment (`Bash(*)` catch-alls stay floored).
/// Auto mode instead routes floored commands to its classifier.
///
/// P166 r13B: `branch_floor_kept` is the branch-switch verdict (`branch_switch_floor_kept`): a tracked protected name in
/// a tree the verb involves, or a tree that could not be determined, keeps the floor.
fn narrow_allow_clears_write_floor(
    evaluation: Option<&BashEvaluation>,
    policy: Option<&CompiledPolicy>,
    access: &AccessKind,
    branch_floor_kept: bool,
) -> bool {
    !branch_floor_kept && narrow_allow_would_clear(evaluation, policy, access)
}

/// The preconditions of [`narrow_allow_clears_write_floor`] before the branch-switch check.
fn narrow_allow_would_clear(
    evaluation: Option<&BashEvaluation>,
    policy: Option<&CompiledPolicy>,
    access: &AccessKind,
) -> bool {
    evaluation.is_some_and(|e| e.assessment.is_file_write_only() && !e.redirect_write)
        && policy.is_some_and(|p| p.narrow_allow_authorizes(access))
}

/// P166 r13B: whether the branch-switch check keeps the floor. Git is asked only when ALL hold: the plan names a listed
/// verb, the floor is the whole story (FileWrite-only), and a narrow allow is about to clear it.
async fn branch_switch_floor_kept(
    plan: &BranchSwitchPlan,
    evaluation: Option<&BashEvaluation>,
    policy: Option<&CompiledPolicy>,
    access: &AccessKind,
) -> bool {
    match plan {
        BranchSwitchPlan::NotApplicable => false,
        _ if !narrow_allow_would_clear(evaluation, policy, access) => false,
        BranchSwitchPlan::Undetermined => true,
        BranchSwitchPlan::Probe(_) => {
            let plan = plan.clone();
            let work = tokio::task::spawn_blocking(move || plan_keeps_floor(&plan, &GitTreeLister));
            match tokio::time::timeout(BRANCH_CHECK_TIMEOUT, work).await {
                Ok(Ok(kept)) => kept,
                _ => true,
            }
        }
    }
}

/// Blocking form for the hub path (`hub_needs_default_prompt` is documented as blocking).
fn branch_switch_floor_kept_blocking(
    plan: &BranchSwitchPlan,
    evaluation: &BashEvaluation,
    policy: Option<&CompiledPolicy>,
    access: &AccessKind,
    lister: &dyn TreeLister,
) -> bool {
    match plan {
        BranchSwitchPlan::NotApplicable => false,
        _ if !narrow_allow_would_clear(Some(evaluation), policy, access) => false,
        plan => plan_keeps_floor(plan, lister),
    }
}

const BRANCH_CHECK_TIMEOUT: std::time::Duration = crate::permission::branch_switch::CHECK_TIMEOUT;

/// u35 g9: what decides, besides the reason, whether a Bash call was approved without a grant.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct NoGrantFacts {
    /// A grant or an override covers the whole call: a grant for every segment, an exact grant, the session's "allow all
    /// commands" (or a remembered whole command), or a configured allow rule that matches it (`--allow Bash`).
    pub(crate) call_granted: bool,
    /// A session grant approved some segments and the read-only lists the rest (`SegmentEvaluation::AutoAllow` with
    /// `via_session_grant`): approved as `SESSION_GRANT`, but not wholly by the grant.
    pub(crate) partly_granted: bool,
}

impl NoGrantFacts {
    fn of(
        cmd: &str,
        evaluation: &BashEvaluation,
        state: &PermissionState,
        yolo_pin: Option<&'static str>,
        policy_allows: bool,
    ) -> Self {
        Self {
            call_granted: evaluation.all_segments_granted
                || evaluation.exact_grant
                || persisted_bash_auto_allows(state, cmd, yolo_pin)
                || policy_allows,
            partly_granted: matches!(
                evaluation.segments,
                SegmentEvaluation::AutoAllow {
                    via_session_grant: true
                }
            ),
        }
    }
}

/// u35 g9 (lead decision after r8): the one flag an allowed call carries to the shell runner
/// ([`fuigo_tools::sandbox_launch::ApprovedWithoutGrant`]): `true` iff some part of the call was approved without a
/// grant (the read-only lists, the Auto mode fast path, or the Auto mode classifier, heuristic or model, all of which
/// judged Fuigo's own environment) and no grant or override covers the whole call. A grant, a user's answer (any
/// prompt), a hook, yolo, a policy allow and sandbox auto-allow give `false`. Not an allow: `true` (the call does not
/// run).
///
/// u35 g10 (Astra/Grok r9 High): the reason is matched exhaustively with no wildcard, so a new reason must say which
/// side it is on; a reason Fuigo does not know (or none) is `true`.
pub(crate) fn approved_without_grant(
    decision: &Decision,
    user_prompted: bool,
    reason: Option<&str>,
    facts: NoGrantFacts,
) -> bool {
    use fuigo_telemetry::events::PermissionDecisionReason as R;
    if !matches!(decision, Decision::Allow) {
        return true;
    }
    if user_prompted {
        return false;
    }
    let Some(reason) = reason.and_then(|r| R::try_from(r).ok()) else {
        return true;
    };
    let without_grant = match reason {
        // Approved on what the command is, judged on Fuigo's own environment.
        R::SafeCommand | R::AutoFastPath | R::AutoClassifierAllow => true,
        // A session grant that covered only some segments, the read-only lists the rest.
        R::SessionGrant => facts.partly_granted,
        // The user's grant or answer, or an override the user configured or switched on.
        R::Yolo
        | R::PolicyAllow
        | R::SandboxAuto
        | R::PersistedGrant
        | R::StaticAllowlist
        | R::PromptAllow => false,
        // Reasons that never approve: an allow under one of them was not granted.
        R::PolicyDeny
        | R::PolicyAsk
        | R::BashCommandGateAsk
        | R::ShellFileGateAsk
        | R::AutoClassifierDeny
        | R::AutoClassifierTimeout
        | R::AutoClassifierUnavailable
        | R::AutoDenialLimit
        | R::SessionDeny
        | R::PromptDeny
        | R::NeedsUser
        | R::BashRequestFloor
        | R::OpaqueShell
        | R::HookAsk
        | R::RequesterGone => true,
    };
    without_grant && !facts.call_granted
}

/// A request has no static-analysis findings at all: the only case where a broad configured policy Allow may bypass the classifier.
/// Non-Bash access has no Bash findings and is always clear here.
/// u35 g8: `InheritedEnvironment` alone does not stop a configured allow rule (a grant).
fn bash_assessment_is_clear(evaluation: Option<&BashEvaluation>) -> bool {
    evaluation
        .is_none_or(|e| e.assessment.is_empty() || e.assessment.is_inherited_environment_only())
}

/// The trusted classifier assessment for one request.
/// The request's canonical findings, plus the managed-policy fail-closed finding when a gate could not decompose the command to match a rule.
/// Non-Bash access carries no findings.
fn classifier_assessment(
    evaluation: Option<&BashEvaluation>,
    fail_closed_policy: bool,
) -> BashSecurityAssessment {
    let mut assessment = evaluation.map(|e| e.assessment.clone()).unwrap_or_default();
    if fail_closed_policy {
        assessment.insert(ClassifierSecurityFinding::FailClosedPolicy);
    }
    assessment
}

/// u35 t1 (design d2 D1): never in a folder that is not trusted.
fn sandbox_may_auto_allow_bash(evaluation: Option<&BashEvaluation>, sandbox_active: bool) -> bool {
    sandbox_active
        && !bash_session_floor_requires_prompt(evaluation)
        && !evaluation.is_some_and(|e| e.untrusted_folder)
}

/// Policy knobs for [`bash_grant_pre_decision`].
#[derive(Clone, Copy)]
struct BashGrantOpts {
    honor_safe_lists: bool,
    allow_blanket: bool,
    conservative_blanket: bool,
}

impl BashGrantOpts {
    const PRE_CLASSIFIER: Self = Self {
        honor_safe_lists: true,
        allow_blanket: true,
        conservative_blanket: true,
    };
    const ASK_FLOOR_REMEMBER: Self = Self {
        honor_safe_lists: false,
        allow_blanket: false,
        conservative_blanket: false,
    };
    fn post_classify(auto_forced_prompt: bool) -> Self {
        Self {
            honor_safe_lists: true,
            allow_blanket: !auto_forced_prompt,
            conservative_blanket: false,
        }
    }
}

fn grant_allow(reason: &'static str) -> Option<(Decision, &'static str)> {
    Some((Decision::Allow, reason))
}

fn bash_grant_pre_decision(
    cmd: &str,
    evaluation: &BashEvaluation,
    state: &PermissionState,
    yolo_pin: Option<&'static str>,
    opts: BashGrantOpts,
) -> Option<(Decision, &'static str)> {
    if let SegmentEvaluation::Reject(reason) = &evaluation.segments {
        return Some((Decision::Reject(reason.to_owned()), reasons::SESSION_DENY));
    }
    if bash_session_floor_requires_prompt(Some(evaluation)) {
        return None;
    }
    match &evaluation.segments {
        SegmentEvaluation::Reject(_) => unreachable!(),
        // u35 g8: with a steering environment the read-only lists approve nothing; the session blanket still does
        SegmentEvaluation::AutoAllow { .. } if no_grant_approval_switched_off(evaluation) => {
            (opts.allow_blanket && persisted_bash_auto_allows(state, cmd, yolo_pin))
                .then_some((Decision::Allow, reasons::SESSION_GRANT))
        }
        SegmentEvaluation::AutoAllow { via_session_grant } => {
            if !opts.honor_safe_lists && !evaluation.all_segments_granted {
                None
            } else {
                grant_allow(if *via_session_grant {
                    reasons::SESSION_GRANT
                } else {
                    reasons::SAFE_COMMAND
                })
            }
        }
        SegmentEvaluation::NeedsPrompts { .. } => {
            if !opts.allow_blanket {
                None
            } else if opts.conservative_blanket
                && evaluation
                    .assessment
                    .contains(ClassifierSecurityFinding::DangerousCommand)
            {
                // An exact whole-command grant is explicit user authority for THIS command, so the auto classifier must not silent-deny it
                // (It would make auto mode stricter than ask mode for the same persisted grant.)
                // Blanket/prefix grants stay excluded; a dangerous verb prefix like `git push` is never trusted
                evaluation
                    .exact_grant
                    .then_some((Decision::Allow, reasons::SESSION_GRANT))
            } else {
                persisted_bash_auto_allows(state, cmd, yolo_pin)
                    .then_some((Decision::Allow, reasons::SESSION_GRANT))
            }
        }
        SegmentEvaluation::Unparseable => {
            if !opts.allow_blanket {
                None
            } else {
                let allowed = if opts.conservative_blanket {
                    evaluation.exact_grant
                } else {
                    persisted_bash_auto_allows(state, cmd, yolo_pin)
                };
                allowed.then_some((Decision::Allow, reasons::SESSION_GRANT))
            }
        }
    }
}

/// Session always-allow consulted before the auto classifier.
/// Caller must skip under policy/shell Ask floors.
///
/// `honor_static_web_allowlist` is false when auto mode must classify built-in-default web-fetch domains instead of granting them.
/// The default list is an egress boundary, not a user grant.
/// User-configured lists and session grants keep short-circuiting.
fn session_grant_pre_decision(
    access: &AccessKind,
    bash_evaluation: Option<&BashEvaluation>,
    state: &PermissionState,
    allow_edits_for_session: bool,
    static_domain_matcher: &DomainMatcher,
    honor_static_web_allowlist: bool,
    yolo_pin: Option<&'static str>,
) -> Option<(Decision, &'static str)> {
    match access {
        AccessKind::MCPTool { name, .. } => mcp_pre_decision(name, state, false, false).map(|d| {
            let reason = if matches!(d, Decision::Reject(_)) {
                reasons::SESSION_DENY
            } else {
                reasons::SESSION_GRANT
            };
            (d, reason)
        }),
        AccessKind::WebFetch(url) => {
            let Ok(parsed_url) = url::Url::parse(url) else {
                return None;
            };
            // Remembered deny wins over the static allowlist and any grant.
            if let Some(reject) = web_fetch_deny_pre_decision(&parsed_url, state) {
                return Some((reject, reasons::SESSION_DENY));
            }
            if honor_static_web_allowlist && static_domain_matcher.check(&parsed_url).is_none() {
                return grant_allow(reasons::STATIC_ALLOWLIST);
            }
            let domain = normalize_domain(parsed_url.host_str()?);
            if state.allowed_web_fetch_domains.contains(&domain) {
                grant_allow(reasons::SESSION_GRANT)
            } else {
                None
            }
        }
        AccessKind::Edit(_) if allow_edits_for_session => grant_allow(reasons::SESSION_GRANT),
        AccessKind::Bash(cmd) => bash_grant_pre_decision(
            cmd,
            bash_evaluation?,
            state,
            yolo_pin,
            BashGrantOpts::PRE_CLASSIFIER,
        ),
        // A side-effecting tool has no session grant: an edit grant or an "always" answer never pre-approves it (P165).
        AccessKind::Read(_)
        | AccessKind::Session
        | AccessKind::Grep { .. }
        | AccessKind::WebSearch(_)
        | AccessKind::Edit(_)
        | AccessKind::AgentMessage { .. }
        | AccessKind::Tool(_) => None,
    }
}

/// How long the manager waits to resolve one read target before judging it unresolved (P174).
pub(crate) const READ_TARGET_RESOLVE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);

/// One read target in every spelling the reader opens, bounded by [`READ_TARGET_RESOLVE_TIMEOUT`]. A filesystem that
/// does not answer cannot stall the caller: the target is then judged as spelled and as unresolved (refused). The
/// local manager and the hub path both resolve through this, so they cannot drift (P198 r2).
pub(crate) async fn resolve_read_target(
    cwd: &Path,
    display_cwd: Option<&Path>,
    path: &str,
    resolution: crate::permission::types::ReadResolution,
) -> (Vec<String>, bool) {
    match tokio::time::timeout(
        READ_TARGET_RESOLVE_TIMEOUT,
        read_target_spellings(cwd, display_cwd, path, resolution),
    )
    .await
    {
        Ok(resolved) => (resolved, true),
        Err(_) => (vec![path.to_owned()], false),
    }
}

/// Every spelling of the file a read target opens (P174), the model's spelling first: the file the tool resolves it to
/// (for the Fuigo reader: `resolve_model_path`, symlinks, the Unicode-confusable fallback) and that path with symlinks
/// followed literally (no separator rewriting, so a Unix name containing `\` is followed as the reader follows it). A
/// deny or ask on any spelling binds (`GatePreflight::evaluate_read_targets`).
pub(crate) async fn read_target_spellings(
    cwd: &Path,
    display_cwd: Option<&Path>,
    path: &str,
    resolution: crate::permission::types::ReadResolution,
) -> Vec<String> {
    use crate::permission::types::ReadResolution;
    let opened = match resolution {
        ReadResolution::ModelPath => {
            fuigo_tools::implementations::fuigo_build::read_file::resolve_read_target(
                cwd,
                display_cwd,
                path,
            )
            .await
        }
        ReadResolution::Literal => cwd.join(path),
    };
    // Off the actor thread, so the caller's timeout bounds it (a stalled filesystem blocks a blocking-pool thread).
    let physical = {
        let opened = opened.clone();
        tokio::task::spawn_blocking(move || {
            crate::permission::policy::resolve_following_symlinks(&opened)
        })
        .await
        .ok()
        .flatten()
    };
    let mut spellings = vec![path.to_owned()];
    for spelling in std::iter::once(opened).chain(physical) {
        let spelling = spelling.to_string_lossy().into_owned();
        if !spellings.contains(&spelling) {
            spellings.push(spelling);
        }
    }
    spellings
}

/// The prompt for a multi-file edit names every target (P184): each one as a location, and in the title.
fn with_edit_target_locations(
    update: acp::ToolCallUpdate,
    paths: &[String],
) -> acp::ToolCallUpdate {
    with_target_locations(update, paths, &describe_edit_targets(paths), "Apply patch")
}

/// The prompt for a multi-file read names every file (P174): each one as a location, and in the title.
fn with_read_target_locations(
    update: acp::ToolCallUpdate,
    paths: &[String],
) -> acp::ToolCallUpdate {
    with_target_locations(update, paths, &describe_read_targets(paths), "Read")
}

fn with_target_locations(
    mut update: acp::ToolCallUpdate,
    paths: &[String],
    listed: &str,
    default_title: &str,
) -> acp::ToolCallUpdate {
    let title = match update.fields.title.take() {
        Some(title) if !title.is_empty() => format!("{title}: {listed}"),
        _ => format!("{default_title}: {listed}"),
    };
    update.fields.title = Some(title);
    update.fields.locations = Some(
        paths
            .iter()
            .map(|path| acp::ToolCallLocation::new(std::path::PathBuf::from(path)))
            .collect(),
    );
    update
}

/// Spawns the permission manager actor, returning a handle and the telemetry event receiver.
pub fn spawn_permission_manager(
    session_id: acp::SessionId,
    gateway: GatewaySender,
    cwd: AbsPathBuf,
    client_type: ClientType,
    // Permission policy from config; None loads from global Config.
    permission_config: Option<crate::permission::types::PermissionConfig>,
    // Grep Read-deny globs, stored on the handle for subagents to inherit.
    deny_read_globs: Vec<String>,
    // web_fetch allowlist from the resolved `WebFetchConfig`; empty when disabled.
    web_fetch_allowed_domains: Vec<String>,
    initial_yolo: bool,
    client_identifier: Option<String>,
) -> (PermissionHandle, mpsc::UnboundedReceiver<PermissionEvent>) {
    spawn_permission_manager_with_hub(
        session_id,
        gateway,
        cwd,
        client_type,
        permission_config,
        deny_read_globs,
        web_fetch_allowed_domains,
        initial_yolo,
        client_identifier,
        // Legacy/test entry point: preserve the full option set
        // Production uses `spawn_permission_manager_with_hub` with the resolved gate
        true,
        None,
    )
}

/// Like [`spawn_permission_manager`] but routes the permission prompt to chat over the server (the HITL live path) when `hub_permission` is `Some`.
/// The caller builds the transport only when [`hitl_permission_live_enabled`] and a server is connected; `None` keeps the local ACP prompt.
///
/// [`hitl_permission_live_enabled`]: crate::permission::hitl_permission_live_enabled
#[allow(clippy::too_many_arguments)]
pub fn spawn_permission_manager_with_hub(
    session_id: acp::SessionId,
    gateway: GatewaySender,
    cwd: AbsPathBuf,
    client_type: ClientType,
    permission_config: Option<crate::permission::types::PermissionConfig>,
    deny_read_globs: Vec<String>,
    web_fetch_allowed_domains: Vec<String>,
    initial_yolo: bool,
    client_identifier: Option<String>,
    // Resolved `remember_tool_approvals` gate
    // Shows the per-tool always-allow options and lets an explicit grant satisfy an `ask` rule (ask once, remember)
    remember_tool_approvals: bool,
    hub_permission: Option<Arc<dyn crate::permission::PermissionHookTransport>>,
) -> (PermissionHandle, mpsc::UnboundedReceiver<PermissionEvent>) {
    // Read the pin ONCE (file I/O) and cache it; never re-read per tool-call.
    // Every path that sets yolo goes through construction or SetYoloMode
    spawn_permission_manager_with_pin(
        session_id,
        gateway,
        cwd,
        client_type,
        permission_config,
        deny_read_globs,
        web_fetch_allowed_domains,
        initial_yolo,
        client_identifier,
        remember_tool_approvals,
        crate::permission::resolution::yolo_disabled_by_policy(),
        hub_permission,
    )
}

#[allow(clippy::too_many_arguments)]
fn spawn_permission_manager_with_pin(
    session_id: acp::SessionId,
    gateway: GatewaySender,
    cwd: AbsPathBuf,
    client_type: ClientType,
    permission_config: Option<crate::permission::types::PermissionConfig>,
    deny_read_globs: Vec<String>,
    web_fetch_allowed_domains: Vec<String>,
    initial_yolo: bool,
    client_identifier: Option<String>,
    remember_tool_approvals: bool,
    yolo_pin: Option<&'static str>,
    hub_permission: Option<Arc<dyn crate::permission::PermissionHookTransport>>,
) -> (PermissionHandle, mpsc::UnboundedReceiver<PermissionEvent>) {
    // u35 g9 (Fable r8 Low): the shell runner's check for calls approved without a grant is installed before this
    // manager approves anything, not on the first Bash evaluation.
    install_runner_env_judge();
    install_runner_trust_judge();
    let (tx, mut rx) = mpsc::unbounded_channel::<PermissionCommand>();
    let (event_tx, event_rx) = mpsc::unbounded_channel::<PermissionEvent>();
    let initial_yolo = clamp_yolo(initial_yolo, yolo_pin);
    let yolo_state = Arc::new(AtomicBool::new(initial_yolo));
    let yolo_state_actor = yolo_state.clone();
    let seed_auto = !initial_yolo
        && permission_config
            .as_ref()
            .is_some_and(|c| matches!(c.prompt_policy, PromptPolicy::Auto));
    if initial_yolo
        && permission_config
            .as_ref()
            .is_some_and(|c| matches!(c.prompt_policy, PromptPolicy::Deny))
    {
        tracing::warn!(
            "always-approve is active while prompt_policy is dontAsk (Deny); \
             unapproved tools will not be auto-denied until always-approve is off. \
             Pin always-approve off with requirements.toml \
             ([ui] disable_bypass_permissions_mode = true) to enforce managed dontAsk."
        );
    }
    let mode_view = ModeView {
        base: crate::permission::types::base_mode_of(permission_config.as_ref()),
        session_edit_grant: Arc::new(AtomicBool::new(false)),
        mode_pair: Arc::new(AtomicU8::new(
            (if initial_yolo { PAIR_YOLO } else { 0 }) | (if seed_auto { PAIR_AUTO } else { 0 }),
        )),
        peer_influence: PeerInfluence::new(),
        fallback_cwd: Some(cwd.as_path().to_path_buf()),
        launch_policy: None,
    };
    let edit_grant_actor = mode_view.session_edit_grant.clone();
    let mode_pair_actor = mode_view.mode_pair.clone();
    let auto_state = Arc::new(AtomicBool::new(seed_auto));
    let auto_state_actor = auto_state.clone();
    let side_query_wired = Arc::new(AtomicBool::new(false));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let in_flight_actor = in_flight.clone();
    let user_prompt_notify = Arc::new(Mutex::new(None::<mpsc::UnboundedSender<()>>));
    let user_prompt_notify_actor = user_prompt_notify.clone();

    let _task = tokio::task::spawn_local(async move {
        let client_id_ref = client_identifier.as_deref();
        let (mut store, mut state) =
            crate::permission::state::CachedStateStore::resolve_and_load(&cwd, client_id_ref).await;

        if state.edit_policy == EditPolicy::Allow {
            tracing::info!(
                "Migrating legacy persisted edit_policy=Allow → Ask \
                 (previously set by the 'allow edits for this session' option)"
            );
            state.edit_policy = EditPolicy::Ask;
            persist_state(&cwd, &state, client_id_ref).await;
        }

        let prompter = AcpPrompter::new(session_id.clone(), gateway.clone(), client_type)
            .with_hub_permission(hub_permission)
            .with_remember_tool_approvals(remember_tool_approvals);
        let mut yolo_mode = initial_yolo;
        let mut auto_mode = seed_auto;
        if seed_auto {
            tracing::info!("auto permission mode seeded from Claude defaultMode / prompt_policy");
        }
        let mut auto_classifier: Option<crate::permission::auto_mode::SharedClassifier> =
            Some(crate::permission::auto_mode::default_auto_mode_classifier());
        let mut auto_consecutive_denials: u32 = 0;
        let mut auto_total_denials: u32 = 0;
        let mut classifier_turns: Vec<crate::permission::auto_mode::ClassifierTurn> = Vec::new();
        let mut recorded_permission_decisions: Vec<crate::permission::auto_mode::ClassifierTurn> =
            Vec::new();
        let mut project_instructions: Option<String> = None;
        let mut pin_refusal_logged = false;
        let mut allow_edits_for_session = false;
        // u35 t1 (design d2 §3.4): the session policy (`project`: with the session folder's project tier when that
        // folder was trusted) and the same without any project tier (`base`), for a command whose folder is not
        // trusted. Without session inputs (tests, configs built by hand) both are the given config.
        let mut policies = TrustPolicies::fixed(permission_config);
        let mut session_inputs: Option<Arc<crate::permission::resolution::SessionPolicyInputs>> =
            None;
        let static_domain_matcher = DomainMatcher::new(&web_fetch_allowed_domains);
        let web_fetch_allowlist_is_default = web_fetch_allowed_domains
            .iter()
            .map(String::as_str)
            .eq(DEFAULT_ALLOWED_DOMAINS.iter().copied());
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PermissionCommand::DecideOnly {
                    access,
                    cwd: decide_cwd,
                    respond_to,
                } => {
                    let verdict = match GatePreflight::evaluate(
                        policies.project.as_ref(),
                        &access,
                        &decide_cwd,
                        false,
                    )
                    .policy_decision()
                    {
                        Some(Decision::Reject(reason)) => Some(reason),
                        _ => None,
                    };
                    let _ = respond_to.send(verdict);
                }
                PermissionCommand::SetYoloMode(enabled) => {
                    let clamped = clamp_yolo(enabled, yolo_pin);
                    if enabled && !clamped && !pin_refusal_logged {
                        tracing::warn!(
                            reason = yolo_pin.unwrap_or_default(),
                            "always-approve enable refused: always-approve is locked off"
                        );
                        pin_refusal_logged = true;
                    }
                    tracing::info!("always-approve set to: {}", clamped);
                    yolo_mode = clamped;
                    yolo_state_actor.store(clamped, Ordering::Relaxed);
                    if clamped {
                        auto_mode = false;
                        auto_state_actor.store(false, Ordering::Relaxed);
                    }
                    pair_set_yolo(&mode_pair_actor, clamped);
                }
                PermissionCommand::SetAutoMode(enabled) => {
                    tracing::info!("auto permission mode set to: {}", enabled);
                    auto_mode = enabled;
                    auto_state_actor.store(enabled, Ordering::Relaxed);
                    pair_set_auto(&mode_pair_actor, enabled);
                    if enabled {
                        yolo_mode = false;
                        yolo_state_actor.store(false, Ordering::Relaxed);
                        if auto_classifier.is_none() {
                            auto_classifier =
                                Some(crate::permission::auto_mode::default_auto_mode_classifier());
                        }
                    }
                }
                PermissionCommand::SetClassifier(classifier) => {
                    auto_classifier = classifier;
                }
                PermissionCommand::SetClassifierTranscript(turns) => {
                    classifier_turns = turns;
                }
                PermissionCommand::SetProjectInstructions(instructions) => {
                    project_instructions = instructions;
                }
                PermissionCommand::SetSessionPolicyInputs(inputs) => {
                    policies = TrustPolicies::resolve(&inputs).await;
                    session_inputs = Some(inputs);
                }
                PermissionCommand::ResetState => {
                    state = PermissionState::default();
                    replace_state_on_disk(&cwd, &state, client_id_ref).await;
                    allow_edits_for_session = false;
                    edit_grant_actor.store(false, Ordering::Relaxed);
                    tracing::info!(
                        "Permission state reset to defaults (including session edit allow)"
                    );
                }
                PermissionCommand::Request {
                    request,
                    respond_to,
                } => {
                    // 1.0.36 item a (R3): under a launch policy the body's answer is held, and its events buffered, so
                    // the launch-ask clamp below can replace an answer the client did not give. Without one, nothing
                    // is held and the body runs exactly as before.
                    let launch_hold: Option<std::rc::Rc<std::cell::RefCell<Option<HeldAnswer>>>> =
                        policies.has_launch_policy().then(Default::default);
                    let mut launch_events: Option<mpsc::UnboundedReceiver<PermissionEvent>> = None;
                    let event_tx_actor = &event_tx;
                    let launch_event_tx;
                    let event_tx: &mpsc::UnboundedSender<PermissionEvent> = if launch_hold.is_some()
                    {
                        let (tx, rx) = mpsc::unbounded_channel();
                        launch_events = Some(rx);
                        launch_event_tx = tx;
                        prompter.set_launch_ask(false);
                        &launch_event_tx
                    } else {
                        &event_tx
                    };
                    let mut launch_clamp: Option<LaunchClamp> = None;
                    // The request body below runs once; its early exits (`continue`) end it, and the clamp runs after.
                    let mut pending = Some((request, respond_to));
                    loop {
                        let Some((
                            PermissionRequest {
                                access,
                                tool_call_update,
                                path_context,
                                session_id: request_session_id,
                                subagent_type: request_subagent_type,
                                subagent_description: request_subagent_description,
                                hook_ask,
                                edit_targets,
                                read_targets,
                                peer_note,
                                exec_cwd,
                                parent_run_dir,
                                shell_run_dir,
                                mcp_definition,
                                mcp_definition_legacy,
                            },
                            respond_to,
                        )) = pending.take()
                        else {
                            break;
                        };
                        let request_received = std::time::Instant::now();
                        let mut respond_to = FinalShellSend {
                            inner: respond_to,
                            untrusted: false,
                            held: launch_hold.clone(),
                        };
                        // u35 t1 (design d2 §3.4): folder trust changed since the policy was built (a grant, a decline,
                        // `/untrust`, another process's answer): rebuild it.
                        if let Some(inputs) = &session_inputs
                            && policies.generation != crate::folder_trust::trust_generation()
                        {
                            policies = TrustPolicies::resolve(inputs).await;
                        }
                        // P184: a multi-file edit (`apply_patch`) is judged per target. The prompt, the events and the
                        // classifier see an `Edit` naming every target; the policy and the protected-edit floor judge
                        // each target; a patch that does not parse (or writes nothing) is refused below.
                        let (access, patch_targets, patch_refusal) = match edit_targets {
                            None => (access, None, None),
                            Some(EditTargets::Paths(paths)) if !paths.is_empty() => (
                                AccessKind::Edit(describe_edit_targets(&paths)),
                                Some(paths),
                                None,
                            ),
                            Some(EditTargets::Paths(_)) => (
                                access,
                                None,
                                Some("the patch has no file operations".to_owned()),
                            ),
                            Some(EditTargets::Unparseable(message)) => {
                                (access, None, Some(message))
                            }
                        };
                        // P174: a tool that reads several files (or a tool that also opens local files) is judged per
                        // file as a Read; the prompt names every file.
                        let read_targets = read_targets
                            .filter(|targets| patch_targets.is_none() && !targets.paths.is_empty());
                        // A single-path read already names its file (Astra r2: every other read lists its files).
                        let read_names_its_file =
                            |targets: &crate::permission::types::ReadTargets| matches!(&access, AccessKind::Read(Some(path)) if targets.paths == [path.clone()]);
                        let tool_call_update = match (&patch_targets, &read_targets) {
                            (Some(paths), _) => with_edit_target_locations(tool_call_update, paths),
                            (None, Some(targets)) if !read_names_its_file(targets) => {
                                with_read_target_locations(tool_call_update, &targets.paths)
                            }
                            _ => tool_call_update,
                        };
                        let request_cwd = path_context
                            .as_ref()
                            .map(|context| context.real_cwd.as_path())
                            .unwrap_or_else(|| cwd.as_path());
                        let permission_mode = if yolo_mode {
                            fuigo_telemetry::enums::PermissionMode::AlwaysApprove
                        } else if auto_mode {
                            fuigo_telemetry::enums::PermissionMode::Auto
                        } else {
                            fuigo_telemetry::enums::PermissionMode::Ask
                        };
                        let tool_id = tool_call_update.tool_call_id.to_string();
                        let tool_name = crate::permission::prompter::tool_name_for_access(&access);
                        let (access_kind_str, access_detail) = match &access {
                            AccessKind::Read(_) | AccessKind::Session => ("read".to_string(), None),
                            AccessKind::Grep { path, glob: _ } => {
                                ("grep".to_string(), path.clone())
                            }
                            AccessKind::Edit(path) => ("edit".to_string(), Some(path.clone())),
                            AccessKind::Bash(cmd) => ("bash".to_string(), Some(cmd.clone())),
                            AccessKind::MCPTool { name, input } => (
                                "mcp".to_string(),
                                Some(crate::permission::auto_mode::mcp_access_detail(name, input)),
                            ),
                            AccessKind::WebFetch(url) => {
                                ("web_fetch".to_owned(), Some(url.clone()))
                            }
                            AccessKind::WebSearch(query) => {
                                ("web_search".to_owned(), Some(query.clone()))
                            }
                            AccessKind::AgentMessage { subagent_id } => {
                                ("agent_message".to_owned(), Some(subagent_id.clone()))
                            }
                            AccessKind::Tool(name) => ("tool".to_owned(), Some(name.clone())),
                        };

                        let denials = std::cell::Cell::new(DenialCounters {
                            consecutive: auto_consecutive_denials,
                            total: auto_total_denials,
                        });
                        let classification: std::cell::RefCell<RequestClassification> =
                            std::cell::RefCell::new(RequestClassification::NotClassified);
                        // u35 g9: what the approved call carries to the shell runner. Set once the command and the policy
                        // are judged, below: a grant or override covers the whole call, or a session grant approved only
                        // some of its segments (the rest by the read-only lists).
                        let no_grant = std::cell::Cell::new(NoGrantFacts::default());
                        let emit_event = |decision: &Decision,
                                          auto_approved: bool,
                                          user_prompted: bool,
                                          prompt_outcome: Option<&str>,
                                          decision_reason: Option<&str>|
                         -> PermissionEvent {
                            let (decision_str, reject_reason) = match decision {
                                Decision::Allow => ("allow".to_string(), None),
                                Decision::Ask => ("ask".to_string(), None),
                                Decision::Reject(reason) | Decision::PolicyDeny(reason) => {
                                    ("reject".to_string(), Some(reason.clone()))
                                }
                                Decision::FollowupMessage(_) => ("followup".to_string(), None),
                                Decision::Cancelled => ("cancelled".to_string(), None),
                            };

                            let denials = denials.get();
                            let classification = classification.borrow();
                            let event = PermissionEvent {
                                tool_id: tool_id.clone(),
                                tool_name: tool_name.clone(),
                                access_kind: access_kind_str.clone(),
                                access_detail: access_detail.clone(),
                                yolo_mode,
                                auto_approved,
                                user_prompted,
                                decision: decision_str,
                                prompt_outcome: prompt_outcome.map(|s| s.to_string()),
                                reject_reason,
                                timestamp: Utc::now(),
                                subagent_session_id: request_session_id.clone(),
                                subagent_type: request_subagent_type.clone(),
                                subagent_description: request_subagent_description.clone(),
                                permission_mode: Some(
                                    permission_mode_artifact_str(permission_mode).to_string(),
                                ),
                                decision_reason: decision_reason.map(|s| s.to_string()),
                                classifier_source: classification
                                    .classifier_source()
                                    .map(|k| k.wire_str().to_owned()),
                                classifier_latency_ms: classification.classifier_latency_ms(),
                                auto_denials_consecutive: auto_mode.then_some(denials.consecutive),
                                auto_denials_total: auto_mode.then_some(denials.total),
                                wait_ms: Some(request_received.elapsed().as_millis() as u64),
                                queue_depth: Some(in_flight_actor.load(Ordering::Relaxed) as u32),
                                security_findings: classification.security_findings_tokens(),
                                classifier_verdict: classification
                                    .classifier_verdict()
                                    .map(|v| v.wire_str().to_owned()),
                                remember_tool_approvals: Some(remember_tool_approvals),
                                approved_without_grant: Some(approved_without_grant(
                                    decision,
                                    user_prompted,
                                    decision_reason,
                                    no_grant.get(),
                                )),
                            };
                            let _ = event_tx.send(event.clone());
                            event
                        };

                        if respond_to.is_closed() {
                            tracing::info!(tool = %tool_name, "permission requester gone; skipped at dequeue");
                            emit_event(
                                &Decision::Cancelled,
                                false,
                                false,
                                None,
                                Some(reasons::REQUESTER_GONE),
                            );
                            continue;
                        }

                        if let Some(message) = patch_refusal {
                            tracing::info!(tool = %tool_name, "apply_patch refused: the patch does not parse");
                            let decision = Decision::PolicyDeny(format!(
                                "the patch was refused because its target files could not be determined: {message}"
                            ));
                            let event = emit_event(
                                &decision,
                                false,
                                false,
                                None,
                                Some(reasons::POLICY_DENY),
                            );
                            let _ = respond_to.send(PermissionResolution {
                                decision,
                                event: Some(event),
                            });
                            continue;
                        }

                        if matches!(
                            &access,
                            AccessKind::Bash(_)
                                | AccessKind::MCPTool { .. }
                                | AccessKind::WebFetch(_)
                        ) && let Some(fresh) = store.reload_if_changed().await
                        {
                            state.merge_grants_from(fresh);
                        }
                        let mut branch_plan = BranchSwitchPlan::NotApplicable;
                        // u35 t1 (design d2 §3.3): the folder trust of a Bash command: Trusted only when every directory
                        // it starts in is in a trusted folder (u35 t3: a folder it names does not count). Nothing runs
                        // before it.
                        let mut bash_trust: Option<crate::folder_trust::CommandTrust> = None;
                        let bash_evaluation = match &access {
                            AccessKind::Bash(cmd) => {
                                // u35 g11 (Astra r10 High): every directory the command can run in, the tool's own
                                // working directory (OpenCode bash `workdir`) included, gets every repository check.
                                let mut run_dirs = bash_run_dirs(request_cwd, exec_cwd.as_deref());
                                // Audit S3-F2: a persistent shell starts the command in the directory it has moved to.
                                if let Some(dir) =
                                    shell_run_dir.as_ref().filter(|dir| !run_dirs.contains(dir))
                                {
                                    run_dirs.push(dir.clone());
                                }
                                // Audit X2-F1: a subagent's command is also judged in its parent session's folder.
                                if let Some(parent) = parent_run_dir
                                    .as_ref()
                                    .filter(|dir| !run_dirs.contains(dir))
                                {
                                    run_dirs.push(parent.clone());
                                }
                                let trust = crate::permission::run_dirs::run_dirs_trust(&run_dirs);
                                let folder_trusted = trust.is_trusted();
                                if !folder_trusted {
                                    tracing::info!(tool = %tool_name, ?trust, "shell command outside a trusted folder");
                                }
                                bash_trust = Some(trust);
                                let mut evaluation = evaluate_bash(cmd, &state, true);
                                evaluation.untrusted_folder = !folder_trusted;
                                // u35 g7 (Astra/Grok r6): an inherited environment that can steer what runs (`PATH`
                                // not clean, `LD_PRELOAD`, `GIT_*`, ...), judged before the ambient scan runs any git.
                                for dir in &run_dirs {
                                    add_inherited_env_finding(&mut evaluation, dir);
                                    add_tool_config_finding(&mut evaluation, dir);
                                }
                                if let Some(raw) = evaluation.ambient_segments.take() {
                                    let run_cwd = run_dirs
                                        .last()
                                        .cloned()
                                        .unwrap_or_else(|| request_cwd.to_path_buf());
                                    branch_plan = branch_switch_plan_with(
                                        &raw,
                                        &run_cwd,
                                        Some(&evaluation.write_facts),
                                    );
                                    let plans: Vec<AmbientScanPlan> = run_dirs
                                        .iter()
                                        .map(|dir| ambient_scan_plan_from_segments(&raw, dir))
                                        .collect();
                                    let fail_closed = AmbientGitRisk {
                                        exec: true,
                                        hook: false,
                                    };
                                    let ambient_risk = if plans
                                        .iter()
                                        .any(|plan| matches!(plan, AmbientScanPlan::FailClosed))
                                    {
                                        fail_closed
                                    } else {
                                        // u35 t1: outside a trusted folder only the in-process reader looks; nothing
                                        // the repository configures runs.
                                        tokio::task::spawn_blocking(move || {
                                            plans
                                                .iter()
                                                .map(|plan| {
                                                    ambient_git_risk_from_plan_in(
                                                        plan,
                                                        folder_trusted,
                                                    )
                                                })
                                                .fold(AmbientGitRisk::default(), |all, one| {
                                                    AmbientGitRisk {
                                                        exec: all.exec || one.exec,
                                                        hook: all.hook || one.hook,
                                                    }
                                                })
                                        })
                                        .await
                                        .unwrap_or(fail_closed)
                                    };
                                    if respond_to.is_closed() {
                                        tracing::info!(
                                            tool = %tool_name,
                                            "permission requester gone; ambient scan abandoned"
                                        );
                                        emit_event(
                                            &Decision::Cancelled,
                                            false,
                                            false,
                                            None,
                                            Some(reasons::REQUESTER_GONE),
                                        );
                                        continue;
                                    }
                                    add_ambient_git_findings(&mut evaluation, ambient_risk);
                                }
                                Some(evaluation)
                            }
                            _ => None,
                        };
                        // u35 t1 (design d2 §3.4): a command whose folder is not trusted is judged without any project tier
                        // (a trusted repository's `Bash(make *)` does not cover `make` with `workdir` in an untrusted folder).
                        let untrusted_command =
                            bash_trust.as_ref().is_some_and(|t| !t.is_trusted());
                        respond_to.untrusted = untrusted_command;
                        let compiled_policy = policies.policy_for(untrusted_command);
                        let prompt_policy = policies.prompt_policy_for(untrusted_command);
                        // A recovered filename script (`LOG=/x; ls "$LOG"`) must be classified in auto mode unless an exact
                        // whole-script grant already authorizes it: no blanket, prefix, glob, sandbox or prompt-policy allow
                        // may vouch for argument values nobody resolved.
                        let recovered_classification = auto_mode
                            && requires_recovered_classification(bash_evaluation.as_ref());
                        // P184: each patch target as the tool writes it (`cwd.join(path)`, uncollapsed, as
                        // `ApplyPatchTool` resolves it) and as the model spelled it.
                        let patch_spellings: Option<Vec<EditTargetSpellings>> =
                            patch_targets.as_ref().map(|paths| {
                                paths
                                    .iter()
                                    .map(|path| EditTargetSpellings::new(request_cwd, path))
                                    .collect()
                            });
                        // P184: a multi-file edit is protected when any target is (the first one names the reason, except that
                        // a pinned launch policy file outranks every other reason: 1.0.36 item a).
                        // P173: every other access goes through the floor the hub path shares (`protected_target`).
                        let protected_edit = match (&patch_spellings, path_context.as_ref()) {
                            (Some(targets), _) => {
                                crate::permission::shell_access::strongest_protection(
                                    targets.iter().map(|target| {
                                        edit_target_protection(Path::new(&target.written))
                                    }),
                                )
                            }
                            (None, Some(context)) => protected_target(
                                &access,
                                bash_evaluation.as_ref(),
                                &context.real_cwd,
                                context.display_cwd.as_deref(),
                            ),
                            (None, None) => protected_target(
                                &access,
                                bash_evaluation.as_ref(),
                                cwd.as_path(),
                                None,
                            ),
                        };

                        let preflight = match (&patch_spellings, &read_targets) {
                            (Some(targets), _) => GatePreflight::evaluate_edit_targets(
                                compiled_policy.as_ref(),
                                targets,
                                request_cwd,
                            ),
                            // No policy: nothing to judge, so no filesystem work in the actor (Astra r2).
                            (None, Some(targets)) if compiled_policy.is_some() => {
                                // Each file in every spelling of the file the tool opens.
                                let display_cwd = path_context
                                    .as_ref()
                                    .and_then(|context| context.display_cwd.as_deref());
                                let mut spellings: Vec<(Vec<String>, bool)> =
                                    Vec::with_capacity(targets.paths.len());
                                for path in &targets.paths {
                                    spellings.push(
                                        resolve_read_target(
                                            request_cwd,
                                            display_cwd,
                                            path,
                                            targets.resolution,
                                        )
                                        .await,
                                    );
                                }
                                GatePreflight::evaluate_read_targets(
                                    compiled_policy.as_ref(),
                                    &access,
                                    &spellings,
                                    request_cwd,
                                    auto_mode,
                                )
                            }
                            (None, _) => GatePreflight::evaluate(
                                compiled_policy.as_ref(),
                                &access,
                                request_cwd,
                                auto_mode,
                            ),
                        };
                        let policy_decision = preflight.policy_decision();
                        // 1.0.36 item a (R3): a launch-policy ask; the clamp after this block makes sure the client answers it.
                        if preflight.launch_ask_match() {
                            prompter.set_launch_ask(true);
                            launch_clamp = Some(LaunchClamp {
                                access: access.clone(),
                                prompt_update: match &access {
                                    AccessKind::Bash(_) => with_env_steering_note(
                                        &tool_call_update,
                                        bash_evaluation.as_ref().and_then(|e| e.env_steering),
                                    ),
                                    _ => tool_call_update.clone(),
                                },
                                protected_edit,
                                hook_ask: hook_ask.clone(),
                            });
                        }
                        if let (AccessKind::Bash(cmd), Some(evaluation)) =
                            (&access, bash_evaluation.as_ref())
                        {
                            no_grant.set(NoGrantFacts::of(
                                cmd,
                                evaluation,
                                &state,
                                yolo_pin,
                                matches!(policy_decision, Some(Decision::Allow)),
                            ));
                        }
                        let policy_forced_prompt = preflight.policy_forced_prompt();
                        let shell_forced_prompt = preflight.shell_forced_prompt();
                        let hook_forced_prompt = hook_ask.is_some();
                        let pre_classifier_forced_prompt =
                            policy_forced_prompt || shell_forced_prompt || hook_forced_prompt;
                        let mut auto_forced_prompt = false;
                        let mut auto_prompt_reason: Option<&'static str> = None;

                        if let Some(Decision::Reject(reason)) = policy_decision {
                            tracing::info!(
                                tool = ?tool_name,
                                source = "policy",
                                "permission policy: deny rule matched (enforced before YOLO)"
                            );
                            let decision = Decision::PolicyDeny(reason);
                            let event = emit_event(
                                &decision,
                                false,
                                false,
                                None,
                                Some(reasons::POLICY_DENY),
                            );
                            let _ = respond_to.send(PermissionResolution {
                                decision,
                                event: Some(event),
                            });
                            continue;
                        }

                        // 1.0.36 item a: a pinned launch policy file is never the agent's to edit, in any mode.
                        if matches!(
                            protected_edit,
                            Some(crate::permission::ProtectedEditReason::LaunchPolicy)
                        ) {
                            let decision = Decision::PolicyDeny(
                                "the launch permission policy file cannot be edited".to_owned(),
                            );
                            let event = emit_event(
                                &decision,
                                false,
                                false,
                                None,
                                Some(reasons::POLICY_DENY),
                            );
                            let _ = respond_to.send(PermissionResolution {
                                decision,
                                event: Some(event),
                            });
                            continue;
                        }

                        if yolo_mode && !shell_forced_prompt && !hook_forced_prompt {
                            tracing::debug!("YOLO mode: auto-approving permission request");
                            let decision = Decision::Allow;
                            let event =
                                emit_event(&decision, true, false, None, Some(reasons::YOLO));
                            let _ = respond_to.send(PermissionResolution {
                                decision,
                                event: Some(event),
                            });
                            continue;
                        }

                        if !pre_classifier_forced_prompt
                            && protected_edit.is_none()
                            && let Some((decision, reason)) = session_grant_pre_decision(
                                &access,
                                bash_evaluation.as_ref(),
                                &state,
                                allow_edits_for_session,
                                &static_domain_matcher,
                                !(auto_mode && web_fetch_allowlist_is_default),
                                yolo_pin,
                            )
                            && (!recovered_classification || !matches!(decision, Decision::Allow))
                        {
                            tracing::debug!(
                                tool = %tool_name,
                                %reason,
                                "session grant short-circuit before auto classifier"
                            );
                            // Audit S6-F4: a call a remembered MCP grant allows checks the server's definition against the
                            // grant's (the usual path for a grant; the pre-decision below covers the ask-rule case).
                            if let (Decision::Allow, AccessKind::MCPTool { name, .. }) =
                                (&decision, &access)
                                && matches!(
                                    note_mcp_definition(
                                        &mut state,
                                        name,
                                        mcp_definition.as_deref(),
                                        mcp_definition_legacy.as_deref()
                                    ),
                                    McpDefinitionNote::Recorded | McpDefinitionNote::Changed
                                )
                            {
                                persist_state(&cwd, &state, client_id_ref).await;
                            }
                            let event = emit_event(&decision, true, false, None, Some(reason));
                            let _ = respond_to.send(PermissionResolution {
                                decision,
                                event: Some(event),
                            });
                            continue;
                        }

                        let covering_filename_allow =
                            configured_filename_allow(bash_evaluation.as_ref());
                        if auto_mode
                            && (covering_filename_allow || !recovered_classification)
                            && !pre_classifier_forced_prompt
                            && protected_edit.is_none()
                            && matches!(policy_decision, Some(Decision::Allow))
                            && (covering_filename_allow
                                || bash_assessment_is_clear(bash_evaluation.as_ref())
                                || (!bash_request_floor_requires_prompt(bash_evaluation.as_ref())
                                    && compiled_policy
                                        .as_ref()
                                        .is_some_and(|p| p.narrow_allow_authorizes(&access))))
                        {
                            tracing::info!(
                                tool = ?tool_name,
                                source = "policy",
                                "permission policy: allow rule matched (before auto classifier)"
                            );
                            let decision = Decision::Allow;
                            let event = emit_event(
                                &decision,
                                true,
                                false,
                                None,
                                Some(reasons::POLICY_ALLOW),
                            );
                            let _ = respond_to.send(PermissionResolution {
                                decision,
                                event: Some(event),
                            });
                            continue;
                        }

                        // The built-in `send_message` is decided before the classifier (design row 3a: auto-allowed in every mode):
                        // the classifier is never asked about it. Rules, hooks and the peer guard have already run above.
                        let auto_exempt =
                            matches!(&access, AccessKind::Tool(name) if is_auto_allowed_tool(name));
                        if auto_mode && !auto_exempt && preflight.admits_auto_classifier() {
                            use crate::permission::auto_mode::{
                                AutoFastPath, access_requires_user_interaction, auto_mode_fast_path,
                            };
                            // u35 g12 (Astra r11 High): the program Fuigo's grep tool runs is chosen by the
                            // environment (`RG_BIN_PATH`, `RUNFILES_DIR` in the project): asked about, as in Ask mode,
                            // never fast-path allowed.
                            let grep_tool_steered = matches!(&access, AccessKind::Grep { .. })
                                && crate::permission::exec_risk::grep_tool_env_steers(request_cwd)
                                    .is_some();
                            let needs_user = protected_edit.is_some()
                                || grep_tool_steered
                                || access_requires_user_interaction(&tool_name, &access);
                            // u35 g11 (owner decision): under PowerShell or cmd.exe nothing in Auto mode approves a
                            // command without a grant, so it is asked about without the fast path or the classifier.
                            let fast = if shell_switches_off_auto(bash_evaluation.as_ref()) {
                                AutoFastPath::PromptUser
                            } else {
                                auto_mode_fast_path(&access, &tool_name, needs_user)
                            };
                            match fast {
                                AutoFastPath::Allow if hook_forced_prompt => {}
                                AutoFastPath::Allow => {
                                    *classification.borrow_mut() = RequestClassification::FastPath;
                                    tracing::debug!(
                                        tool = %tool_name,
                                        "auto mode: fast-path allow (allowlist / accept-edits)"
                                    );
                                    let decision = Decision::Allow;
                                    let event = emit_event(
                                        &decision,
                                        true,
                                        false,
                                        None,
                                        Some(reasons::AUTO_FAST_PATH),
                                    );
                                    let _ = respond_to.send(PermissionResolution {
                                        decision,
                                        event: Some(event),
                                    });
                                    continue;
                                }
                                AutoFastPath::PromptUser => {
                                    auto_forced_prompt = true;
                                    auto_prompt_reason = Some(reasons::NEEDS_USER);
                                }
                                AutoFastPath::Classify => {
                                    let assessment = classifier_assessment(
                                        bash_evaluation.as_ref(),
                                        preflight.defers_gate_ask(),
                                    );
                                    let classify_started = std::time::Instant::now();
                                    enum RouteResult {
                                        Completed(crate::permission::auto_mode::ClassifierOutcome),
                                        NotWired,
                                        Abandoned,
                                    }
                                    let route = if let Some(ref clf) = auto_classifier {
                                        use crate::permission::auto_mode::ClassifierContext;
                                        let mut turns = classifier_turns.clone();
                                        turns.extend(recorded_permission_decisions.iter().cloned());
                                        let classify = clf.classify(
                                            &tool_name,
                                            &access,
                                            access_detail.as_deref(),
                                            ClassifierContext {
                                                turns,
                                                project_instructions: project_instructions.clone(),
                                                security_findings: assessment.clone(),
                                                peer: peer_note.clone(),
                                            },
                                        );
                                        tokio::select! {
                                            verdict = classify => RouteResult::Completed(verdict),
                                            _ = respond_to.closed() => RouteResult::Abandoned,
                                        }
                                    } else if matches!(&access, AccessKind::AgentMessage { .. }) {
                                        RouteResult::Completed(
                                            crate::permission::auto_mode::ClassifierVerdict::Block
                                                .into(),
                                        )
                                    } else {
                                        RouteResult::NotWired
                                    };
                                    let classifier_latency_ms =
                                        u64::try_from(classify_started.elapsed().as_millis())
                                            .unwrap_or(u64::MAX);
                                    let outcome: Option<
                                        crate::permission::auto_mode::ClassifierOutcome,
                                    > = match route {
                                        RouteResult::Abandoned => {
                                            *classification.borrow_mut() =
                                                RequestClassification::Classified {
                                                    assessment,
                                                    outcome: None,
                                                };
                                            tracing::info!(tool = %tool_name, "permission requester gone; classify abandoned");
                                            emit_event(
                                                &Decision::Cancelled,
                                                false,
                                                false,
                                                None,
                                                Some(reasons::REQUESTER_GONE),
                                            );
                                            continue;
                                        }
                                        RouteResult::NotWired => {
                                            *classification.borrow_mut() =
                                                RequestClassification::Classified {
                                                    assessment,
                                                    outcome: Some(ClassificationOutcome {
                                                        verdict: ClassifierVerdict::Unavailable,
                                                        source: ClassificationSource::NotWired,
                                                        latency_ms: None,
                                                    }),
                                                };
                                            None
                                        }
                                        RouteResult::Completed(o) => {
                                            *classification.borrow_mut() =
                                                RequestClassification::Classified {
                                                    assessment,
                                                    outcome: Some(ClassificationOutcome {
                                                        verdict: o.verdict(),
                                                        source: ClassificationSource::Classifier(
                                                            o.source(),
                                                        ),
                                                        latency_ms: Some(classifier_latency_ms),
                                                    }),
                                                };
                                            Some(o)
                                        }
                                    };
                                    let verdict = outcome
                                        .as_ref()
                                        .map_or(ClassifierVerdict::Unavailable, |o| o.verdict());
                                    let is_timeout =
                                        outcome.as_ref().is_some_and(|o| o.is_timeout());
                                    tracing::info!(
                                        tool = %tool_name,
                                        verdict = ?verdict,
                                        classifier_latency_ms,
                                        "auto mode: classifier route completed"
                                    );
                                    match verdict {
                                        ClassifierVerdict::Allow => {
                                            tracing::debug!(
                                                tool = %tool_name,
                                                "auto mode: classifier allow"
                                            );
                                            auto_consecutive_denials = 0;
                                            denials.set(DenialCounters {
                                                consecutive: auto_consecutive_denials,
                                                total: auto_total_denials,
                                            });
                                            if !hook_forced_prompt
                                                && classifier_allow_needs_user(
                                                    bash_evaluation.as_ref(),
                                                )
                                            {
                                                // u35 g11, u35 t1: a steering environment, or a folder that is not
                                                // trusted; ask.
                                                auto_forced_prompt = true;
                                                auto_prompt_reason = Some(reasons::NEEDS_USER);
                                            } else if !hook_forced_prompt {
                                                if let Some(kind) = bash_evaluation
                                                    .as_ref()
                                                    .and_then(repository_execution)
                                                {
                                                    // u35 t1 (D3): the trusted folder's own content runs; the model's
                                                    // allow stands.
                                                    tracing::debug!(tool = %tool_name, ?kind, "auto mode: repository content runs in a trusted folder");
                                                }
                                                let decision = Decision::Allow;
                                                let event = emit_event(
                                                    &decision,
                                                    true,
                                                    false,
                                                    None,
                                                    Some(reasons::AUTO_CLASSIFIER_ALLOW),
                                                );
                                                let _ = respond_to.send(PermissionResolution {
                                                    decision,
                                                    event: Some(event),
                                                });
                                                continue;
                                            }
                                        }
                                        ClassifierVerdict::Block
                                            if client_type.can_present_permission_prompt() =>
                                        {
                                            tracing::info!(
                                                tool = %tool_name,
                                                "auto mode: classifier blocked — prompting user"
                                            );
                                            auto_forced_prompt = true;
                                            auto_prompt_reason =
                                                Some(reasons::AUTO_CLASSIFIER_DENY);
                                        }
                                        ClassifierVerdict::Block
                                            if auto_consecutive_denials
                                                < AUTO_DENY_CONSECUTIVE_LIMIT
                                                && auto_total_denials < AUTO_DENY_TOTAL_LIMIT =>
                                        {
                                            auto_consecutive_denials += 1;
                                            auto_total_denials += 1;
                                            denials.set(DenialCounters {
                                                consecutive: auto_consecutive_denials,
                                                total: auto_total_denials,
                                            });
                                            tracing::info!(
                                                tool = %tool_name,
                                                consecutive = auto_consecutive_denials,
                                                total = auto_total_denials,
                                                "auto mode: classifier blocked — denying and continuing"
                                            );
                                            let reason =
                                                match outcome.as_ref().and_then(|o| o.reason()) {
                                                    Some(r) => format!(
                                                        "Auto mode blocked this action ({}). \
                                                 {AUTO_DENY_GUIDANCE}",
                                                        r.trim_end_matches('.')
                                                    ),
                                                    None => format!(
                                                        "Auto mode blocked this action. \
                                                 {AUTO_DENY_GUIDANCE}"
                                                    ),
                                                };
                                            let decision = Decision::PolicyDeny(reason);
                                            let event = emit_event(
                                                &decision,
                                                false,
                                                false,
                                                None,
                                                Some(reasons::AUTO_CLASSIFIER_DENY),
                                            );
                                            let _ = respond_to.send(PermissionResolution {
                                                decision,
                                                event: Some(event),
                                            });
                                            continue;
                                        }
                                        ClassifierVerdict::Block => {
                                            tracing::info!(
                                                tool = %tool_name,
                                                consecutive = auto_consecutive_denials,
                                                total = auto_total_denials,
                                                "auto mode: denial limit reached — prompting user"
                                            );
                                            auto_forced_prompt = true;
                                            auto_prompt_reason = Some(reasons::AUTO_DENIAL_LIMIT);
                                        }
                                        ClassifierVerdict::Unavailable if is_timeout => {
                                            tracing::info!(
                                                tool = %tool_name,
                                                "auto mode: classifier timed out — prompting user"
                                            );
                                            auto_forced_prompt = true;
                                            auto_prompt_reason =
                                                Some(reasons::AUTO_CLASSIFIER_TIMEOUT);
                                        }
                                        ClassifierVerdict::Unavailable => {
                                            tracing::info!(
                                                tool = %tool_name,
                                                "auto mode: classifier unavailable — prompting user"
                                            );
                                            auto_forced_prompt = true;
                                            auto_prompt_reason =
                                                Some(reasons::AUTO_CLASSIFIER_UNAVAILABLE);
                                        }
                                    }
                                }
                            }
                        }

                        if matches!(&access, AccessKind::Bash(_))
                            && !recovered_classification
                            && sandbox_may_auto_allow_bash(
                                bash_evaluation.as_ref(),
                                fuigo_sandbox::should_auto_allow_bash(),
                            )
                            && !policy_forced_prompt
                            && !auto_forced_prompt
                            && !hook_forced_prompt
                            && protected_edit.is_none()
                        {
                            tracing::debug!("sandbox: auto-approving bash");
                            let decision = Decision::Allow;
                            let event = emit_event(
                                &decision,
                                true,
                                false,
                                None,
                                Some(reasons::SANDBOX_AUTO),
                            );
                            let _ = respond_to.send(PermissionResolution {
                                decision,
                                event: Some(event),
                            });
                            continue;
                        }

                        // P166 r13B: git is asked (off the actor) only for a listed branch-moving verb whose floor a
                        // narrow allow is about to clear.
                        let branch_floor_kept = if matches!(policy_decision, Some(Decision::Allow))
                            && protected_edit.is_none()
                            && !auto_forced_prompt
                            && !hook_forced_prompt
                            && bash_request_floor_requires_prompt(bash_evaluation.as_ref())
                        {
                            // u35 t1 (design d2 §3.3): outside a trusted folder git is not asked; the floor stays.
                            bash_trust.as_ref().is_some_and(|t| !t.is_trusted())
                                || branch_switch_floor_kept(
                                    &branch_plan,
                                    bash_evaluation.as_ref(),
                                    compiled_policy.as_ref(),
                                    &access,
                                )
                                .await
                        } else {
                            false
                        };
                        match policy_decision {
                            Some(Decision::Ask) => {
                                tracing::info!(
                                    tool = ?tool_name,
                                    source = "policy",
                                    "permission policy: ask rule matched, prompting user"
                                );
                            }
                            Some(Decision::Allow)
                                if protected_edit.is_some()
                                    || auto_forced_prompt
                                    || hook_forced_prompt
                                    || recovered_classification
                                    || broad_allow_deferred(
                                        bash_evaluation.as_ref(),
                                        compiled_policy.as_ref(),
                                        &access,
                                        prompt_policy != PromptPolicy::Deny,
                                        branch_floor_kept,
                                    ) =>
                            {
                                tracing::info!(
                                    tool = ?tool_name,
                                    source = "policy",
                                    "permission policy allow deferred to confirmation floor"
                                );
                            }
                            Some(decision) => {
                                tracing::info!(
                                    tool = ?tool_name,
                                    source = "policy",
                                    decision = ?match &decision {
                                        Decision::Allow => "allow",
                                        Decision::Reject(_) => "deny",
                                        _ => "other",
                                    },
                                    "permission policy decision"
                                );
                                let event = emit_event(
                                    &decision,
                                    true,
                                    false,
                                    None,
                                    Some(reasons::POLICY_ALLOW),
                                );
                                let _ = respond_to.send(PermissionResolution {
                                    decision,
                                    event: Some(event),
                                });
                                continue;
                            }
                            None => {}
                        }

                        let mut pre_decision: Option<(Decision, &'static str)> = match &access {
                            AccessKind::Read(_) | AccessKind::Session | AccessKind::Grep { .. }
                                if policy_forced_prompt =>
                            {
                                None
                            }
                            AccessKind::Read(_) | AccessKind::Session => {
                                Some((Decision::Allow, reasons::SAFE_COMMAND))
                            }
                            // An ask rule binds over the built-in safe-listing, as it does for reads
                            AccessKind::WebSearch(_) if policy_forced_prompt => None,
                            AccessKind::WebSearch(_) => {
                                Some((Decision::Allow, reasons::SAFE_COMMAND))
                            }
                            // u35 g8 (Astra r7): the program Fuigo's grep tool runs is chosen by the environment
                            AccessKind::Grep { .. }
                                if crate::permission::exec_risk::grep_tool_env_steers(
                                    request_cwd,
                                )
                                .is_some() =>
                            {
                                None
                            }
                            AccessKind::Grep { .. } => {
                                Some((Decision::Allow, reasons::SAFE_COMMAND))
                            }
                            // Peer messaging (design row 3a): `send_message` is auto-allowed in every mode, but only here, after the
                            // policy step above: a deny rule has already rejected it and an ask rule (`policy_forced_prompt`) still prompts.
                            AccessKind::Tool(name)
                                if is_auto_allowed_tool(name) && !policy_forced_prompt =>
                            {
                                Some((Decision::Allow, reasons::SAFE_COMMAND))
                            }
                            AccessKind::MCPTool { name, .. } => mcp_pre_decision(
                                name,
                                &state,
                                policy_forced_prompt,
                                remember_tool_approvals,
                            )
                            .map(|d| {
                                let reason = if matches!(d, Decision::Reject(_)) {
                                    reasons::SESSION_DENY
                                } else {
                                    reasons::PERSISTED_GRANT
                                };
                                (d, reason)
                            }),
                            AccessKind::Edit(_) => {
                                // An Ask rule binds over the session edit grant (P184), as it does for reads and MCP.
                                if allow_edits_for_session
                                    && protected_edit.is_none()
                                    && !policy_forced_prompt
                                {
                                    Some((Decision::Allow, reasons::PERSISTED_GRANT))
                                } else {
                                    match state.edit_policy {
                                        EditPolicy::Reject => Some((
                                            Decision::Reject("edits prohibited".to_owned()),
                                            reasons::SESSION_DENY,
                                        )),
                                        EditPolicy::Ask | EditPolicy::Allow => None,
                                    }
                                }
                            }
                            AccessKind::Bash(cmd) => {
                                if protected_edit.is_some()
                                    || bash_request_floor_requires_prompt(bash_evaluation.as_ref())
                                {
                                    None
                                } else if policy_forced_prompt {
                                    if remember_tool_approvals
                                        && !auto_forced_prompt
                                        && !preflight.shell_file_forced_prompt()
                                    {
                                        bash_grant_pre_decision(
                                            cmd,
                                            bash_evaluation
                                                .as_ref()
                                                .expect("Bash access has evaluation"),
                                            &state,
                                            yolo_pin,
                                            BashGrantOpts::ASK_FLOOR_REMEMBER,
                                        )
                                    } else {
                                        None
                                    }
                                } else {
                                    bash_grant_pre_decision(
                                        cmd,
                                        bash_evaluation
                                            .as_ref()
                                            .expect("Bash access has evaluation"),
                                        &state,
                                        yolo_pin,
                                        BashGrantOpts::post_classify(auto_forced_prompt),
                                    )
                                }
                            }
                            // P165 (S1): side-effecting tools always reach the prompt (or prompt_policy) below.
                            AccessKind::AgentMessage { .. } | AccessKind::Tool(_) => None,
                            AccessKind::WebFetch(url) => match url::Url::parse(url) {
                                Ok(parsed_url) => {
                                    if let Some(reject) =
                                        web_fetch_deny_pre_decision(&parsed_url, &state)
                                    {
                                        Some((reject, reasons::SESSION_DENY))
                                    } else if policy_forced_prompt {
                                        // An ask rule binds over the allowlists: only the user's answer runs the fetch
                                        None
                                    } else if static_domain_matcher.check(&parsed_url).is_none() {
                                        tracing::debug!(
                                            url = %url,
                                            source = "static_allowlist",
                                            "web_fetch domain auto-approved"
                                        );
                                        Some((Decision::Allow, reasons::STATIC_ALLOWLIST))
                                    } else if let Some(host) = parsed_url.host_str() {
                                        let domain = normalize_domain(host);
                                        if state.allowed_web_fetch_domains.contains(&domain) {
                                            tracing::debug!(
                                                url = %url,
                                                %domain,
                                                source = "session_allowlist",
                                                "web_fetch domain auto-approved"
                                            );
                                            Some((Decision::Allow, reasons::PERSISTED_GRANT))
                                        } else {
                                            tracing::debug!(
                                                url = %url,
                                                %domain,
                                                source = "prompt",
                                                "web_fetch domain not in allowlist, prompting user"
                                            );
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        url = %url,
                                        error = %e,
                                        "web_fetch URL unparseable, prompting user"
                                    );
                                    None
                                }
                            },
                        };
                        let classifier_absent = auto_prompt_reason
                            == Some(reasons::AUTO_CLASSIFIER_TIMEOUT)
                            || auto_prompt_reason == Some(reasons::AUTO_CLASSIFIER_UNAVAILABLE);
                        let webfetch_static_fallback = classifier_absent
                            && matches!(&access, AccessKind::WebFetch(_))
                            && matches!(
                                &pre_decision,
                                Some((Decision::Allow, reason))
                                    if *reason == reasons::STATIC_ALLOWLIST
                                        || *reason == reasons::PERSISTED_GRANT
                            );
                        if (recovered_classification
                            || (auto_forced_prompt && auto_prompt_blocks_allow(&access)))
                            && matches!(pre_decision, Some((Decision::Allow, _)))
                            && !webfetch_static_fallback
                        {
                            pre_decision = None;
                        }
                        if hook_forced_prompt && matches!(pre_decision, Some((Decision::Allow, _)))
                        {
                            pre_decision = None;
                        }
                        // Audit S6-F4: a call a remembered MCP grant allows checks the server's definition against the grant's.
                        if let (Some((Decision::Allow, reason)), AccessKind::MCPTool { name, .. }) =
                            (&pre_decision, &access)
                            && *reason == reasons::PERSISTED_GRANT
                            && matches!(
                                note_mcp_definition(
                                    &mut state,
                                    name,
                                    mcp_definition.as_deref(),
                                    mcp_definition_legacy.as_deref()
                                ),
                                McpDefinitionNote::Recorded | McpDefinitionNote::Changed
                            )
                        {
                            persist_state(&cwd, &state, client_id_ref).await;
                        }
                        if let Some((decision, reason)) = pre_decision {
                            let event = emit_event(&decision, true, false, None, Some(reason));
                            let _ = respond_to.send(PermissionResolution {
                                decision,
                                event: Some(event),
                            });
                            continue;
                        }

                        if prompt_policy == crate::permission::types::PromptPolicy::Deny {
                            tracing::debug!(tool = ?tool_name, "prompt_policy=deny: rejected");
                            // u35 t1 (design d2 §5.4): a command refused because its folder is not trusted says so.
                            let decision = Decision::PolicyDeny(match &bash_trust {
                                Some(crate::folder_trust::CommandTrust::Untrusted(reason)) => {
                                    crate::folder_trust::untrusted_command_refusal(reason)
                                }
                                _ => "denied by prompt policy (tool not pre-approved)".to_owned(),
                            });
                            let event = emit_event(
                                &decision,
                                false,
                                false,
                                None,
                                Some(reasons::PROMPT_DENY),
                            );
                            let _ = respond_to.send(PermissionResolution {
                                decision,
                                event: Some(event),
                            });
                            continue;
                        }

                        if prompt_policy == crate::permission::types::PromptPolicy::Allow
                            && !recovered_classification
                            && !hook_forced_prompt
                        {
                            tracing::info!(
                                tool = ?tool_name,
                                "prompt_policy=allow: auto-approved without prompting"
                            );
                            let decision = Decision::Allow;
                            let event = emit_event(
                                &decision,
                                true,
                                false,
                                None,
                                Some(reasons::PROMPT_ALLOW),
                            );
                            let _ = respond_to.send(PermissionResolution {
                                decision,
                                event: Some(event),
                            });
                            continue;
                        }

                        let opaque_floor = bash_evaluation.as_ref().is_some_and(|e| {
                            !e.exact_grant
                                && e.assessment
                                    .contains(ClassifierSecurityFinding::OpaqueShell)
                        });
                        let prompt_trigger = preflight
                            .prompt_trigger(auto_prompt_reason)
                            .unwrap_or(if hook_forced_prompt {
                                reasons::HOOK_ASK
                            } else if opaque_floor {
                                reasons::OPAQUE_SHELL
                            } else if bash_request_floor_requires_prompt(bash_evaluation.as_ref()) {
                                reasons::BASH_REQUEST_FLOOR
                            } else {
                                reasons::NEEDS_USER
                            });
                        if respond_to.is_closed() {
                            tracing::info!(tool = %tool_name, "permission requester gone; prompt suppressed");
                            emit_event(
                                &Decision::Cancelled,
                                false,
                                false,
                                None,
                                Some(reasons::REQUESTER_GONE),
                            );
                            continue;
                        }
                        {
                            let slot = user_prompt_notify_actor.lock();
                            if let Some(tx) = slot.as_ref() {
                                let _ = tx.send(());
                            }
                        }
                        let (decision, outcome_str, user_prompted) = match &access {
                            AccessKind::Bash(cmd) => {
                                let prompt_update = with_env_steering_note(
                                    &tool_call_update,
                                    bash_evaluation.as_ref().and_then(|e| e.env_steering),
                                );
                                let prompt_outcome = tokio::select! {
                                    outcome = prompter.request(&access, &prompt_update, protected_edit, hook_ask.as_ref()) => outcome,
                                    _ = respond_to.closed() => PromptOutcome::Cancelled,
                                };
                                // 1.0.36 item a: answering a launch-policy ask remembers nothing.
                                let prompt_outcome = if launch_clamp.is_some() {
                                    once_only(prompt_outcome)
                                } else {
                                    prompt_outcome
                                };

                                let mut effective_kind = prompt_outcome.kind();
                                let decision = match prompt_outcome {
                                    PromptOutcome::AllowOnce => Decision::Allow,
                                    PromptOutcome::AllowAlways => {
                                        state.allowed_bash_commands.insert(cmd.clone());
                                        state
                                            .allowed_bash_commands
                                            .extend(bash_grant_segments(cmd));
                                        persist_state(&cwd, &state, client_id_ref).await;
                                        Decision::Allow
                                    }
                                    PromptOutcome::AllowAlwaysBashCommand(prefix) => {
                                        persist_bash_always_allow(&mut state, cmd, &prefix);
                                        persist_state(&cwd, &state, client_id_ref).await;
                                        Decision::Allow
                                    }
                                    PromptOutcome::AllowAlwaysBashGlob(pattern) => {
                                        if bash_glob_covers_script(cmd, &pattern) {
                                            state.allowed_bash_globs.insert(pattern.clone());
                                            persist_state(&cwd, &state, client_id_ref).await;
                                        } else {
                                            tracing::warn!(
                                                glob = %pattern,
                                                "always-allow glob does not match the prompted script; not persisted"
                                            );
                                        }
                                        Decision::Allow
                                    }
                                    PromptOutcome::AllowAlwaysDomain(_)
                                    | PromptOutcome::AllowAlwaysMcpTool(_)
                                    | PromptOutcome::AllowAlwaysMcpServer(_)
                                    | PromptOutcome::AllowEditsForSession => {
                                        effective_kind = PromptOutcomeKind::AllowOnce;
                                        Decision::Allow
                                    }
                                    PromptOutcome::RejectOnce => {
                                        Decision::Reject("User rejected the execution".to_owned())
                                    }
                                    PromptOutcome::RejectAlwaysBashCommand(prefix) => {
                                        state.disallowed_bash_commands.insert(prefix.clone());
                                        persist_state(&cwd, &state, client_id_ref).await;
                                        Decision::Reject(format!(
                                            "User rejected the execution and excluded `{prefix}` from future runs in this project"
                                        ))
                                    }
                                    PromptOutcome::RejectAlwaysMcpTool(_)
                                    | PromptOutcome::RejectAlwaysDomain(_) => {
                                        effective_kind = PromptOutcomeKind::RejectOnce;
                                        Decision::Reject("User rejected the execution".to_owned())
                                    }
                                    PromptOutcome::Cancelled => Decision::Cancelled,
                                    PromptOutcome::FollowupMessage(msg) => {
                                        Decision::FollowupMessage(msg)
                                    }
                                    PromptOutcome::Error(e) => Decision::Reject(format!(
                                        "Failed to request permission from user: {e}"
                                    )),
                                };
                                let outcome_str = effective_kind.wire_str();

                                (decision, outcome_str, true)
                            }
                            _ => {
                                let prompt_outcome = tokio::select! {
                                    outcome = prompter.request(&access, &tool_call_update, protected_edit, hook_ask.as_ref()) => outcome,
                                    _ = respond_to.closed() => PromptOutcome::Cancelled,
                                };
                                // One call only: an "always" answer for an agent message or a side-effecting tool is an allow-once
                                // (no grant exists for them), and must never flip the session edit grant.
                                // 1.0.36 item a: so is an answer to a launch-policy ask.
                                let prompt_outcome = if matches!(
                                    &access,
                                    AccessKind::AgentMessage { .. } | AccessKind::Tool(_)
                                ) || launch_clamp.is_some()
                                {
                                    once_only(prompt_outcome)
                                } else {
                                    prompt_outcome
                                };
                                let mut effective_kind = prompt_outcome.kind();
                                let decision = match &prompt_outcome {
                                    PromptOutcome::AllowOnce => Decision::Allow,
                                    PromptOutcome::AllowEditsForSession => {
                                        allow_edits_for_session = true;
                                        edit_grant_actor.store(true, Ordering::Relaxed);
                                        Decision::Allow
                                    }
                                    PromptOutcome::AllowAlways => {
                                        if let AccessKind::MCPTool { name, .. } = &access {
                                            state.allowed_mcp_tools.insert(name.clone());
                                            record_mcp_definition(
                                                &mut state,
                                                name,
                                                mcp_definition.as_deref(),
                                            );
                                        }
                                        persist_state(&cwd, &state, client_id_ref).await;
                                        Decision::Allow
                                    }
                                    PromptOutcome::AllowAlwaysBashCommand(_)
                                    | PromptOutcome::AllowAlwaysBashGlob(_) => {
                                        effective_kind = PromptOutcomeKind::AllowAlwaysBash;
                                        Decision::Allow
                                    }
                                    PromptOutcome::AllowAlwaysDomain(client_domain) => {
                                        if let AccessKind::WebFetch(url) = &access
                                            && let Ok(parsed) = url::Url::parse(url)
                                            && let Some(host) = parsed.host_str()
                                        {
                                            let domain = normalize_domain(host);
                                            if domain != *client_domain {
                                                tracing::warn!(
                                                    client_supplied = %client_domain,
                                                    access_domain = %domain,
                                                    "AllowAlwaysDomain mismatch; persisting access-URL domain"
                                                );
                                            }
                                            state.allowed_web_fetch_domains.insert(domain);
                                            persist_state(&cwd, &state, client_id_ref).await;
                                        }
                                        Decision::Allow
                                    }
                                    PromptOutcome::AllowAlwaysMcpTool(tool_name) => {
                                        if let AccessKind::MCPTool {
                                            name: access_name, ..
                                        } = &access
                                        {
                                            if tool_name != access_name {
                                                tracing::warn!(
                                                    client_supplied = %tool_name,
                                                    access_name = %access_name,
                                                    "AllowAlwaysMcpTool tool_name mismatch; persisting access-kind name"
                                                );
                                            }
                                            state.allowed_mcp_tools.insert(access_name.clone());
                                            record_mcp_definition(
                                                &mut state,
                                                access_name,
                                                mcp_definition.as_deref(),
                                            );
                                            persist_state(&cwd, &state, client_id_ref).await;
                                        }
                                        Decision::Allow
                                    }
                                    PromptOutcome::AllowAlwaysMcpServer(server_prefix) => {
                                        if let AccessKind::MCPTool {
                                            name: access_name, ..
                                        } = &access
                                        {
                                            let canonical = parse_mcp_qualified_name(access_name)
                                                .map(|(_, server, _)| server);
                                            match canonical {
                                                Some(canonical) if canonical == server_prefix => {
                                                    state
                                                        .allowed_mcp_servers
                                                        .insert(canonical.to_owned());
                                                    record_mcp_definition(
                                                        &mut state,
                                                        access_name,
                                                        mcp_definition.as_deref(),
                                                    );
                                                    tracing::info!(
                                                        server = %canonical,
                                                        count = state.allowed_mcp_servers.len(),
                                                        "added MCP server to session allowlist"
                                                    );
                                                    persist_state(&cwd, &state, client_id_ref)
                                                        .await;
                                                }
                                                _ => {
                                                    tracing::warn!(
                                                        client_supplied = %server_prefix,
                                                        access_name = %access_name,
                                                        "AllowAlwaysMcpServer prefix mismatch; downgrading to tool-scope"
                                                    );
                                                    state
                                                        .allowed_mcp_tools
                                                        .insert(access_name.clone());
                                                    record_mcp_definition(
                                                        &mut state,
                                                        access_name,
                                                        mcp_definition.as_deref(),
                                                    );
                                                    persist_state(&cwd, &state, client_id_ref)
                                                        .await;
                                                }
                                            }
                                        }
                                        Decision::Allow
                                    }
                                    PromptOutcome::RejectAlwaysBashCommand(_) => {
                                        Decision::Reject("User rejected the execution".to_owned())
                                    }
                                    PromptOutcome::RejectAlwaysMcpTool(tool_name) => {
                                        if let AccessKind::MCPTool {
                                            name: access_name, ..
                                        } = &access
                                        {
                                            if tool_name != access_name {
                                                tracing::warn!(
                                                    client_supplied = %tool_name,
                                                    access_name = %access_name,
                                                    "RejectAlwaysMcpTool tool_name mismatch; persisting access-kind name"
                                                );
                                            }
                                            state.disallowed_mcp_tools.insert(access_name.clone());
                                            persist_state(&cwd, &state, client_id_ref).await;
                                            Decision::Reject(format!(
                                                "User rejected the execution and excluded `{access_name}` from future runs in this project"
                                            ))
                                        } else {
                                            effective_kind = PromptOutcomeKind::RejectOnce;
                                            Decision::Reject(
                                                "User rejected the execution".to_owned(),
                                            )
                                        }
                                    }
                                    PromptOutcome::RejectAlwaysDomain(client_domain) => {
                                        if let Some(domain) = match &access {
                                            AccessKind::WebFetch(url) => {
                                                web_fetch_deny_key_from_url(url)
                                            }
                                            _ => None,
                                        } {
                                            if domain != *client_domain {
                                                tracing::warn!(
                                                    client_supplied = %client_domain,
                                                    access_domain = %domain,
                                                    "RejectAlwaysDomain mismatch; persisting access-URL domain"
                                                );
                                            }
                                            state
                                                .disallowed_web_fetch_domains
                                                .insert(domain.clone());
                                            persist_state(&cwd, &state, client_id_ref).await;
                                            Decision::Reject(format!(
                                                "User rejected the execution and excluded `{domain}` from future runs in this project"
                                            ))
                                        } else {
                                            effective_kind = PromptOutcomeKind::RejectOnce;
                                            Decision::Reject(
                                                "User rejected the execution".to_owned(),
                                            )
                                        }
                                    }
                                    PromptOutcome::RejectOnce => {
                                        Decision::Reject("User rejected the execution".to_owned())
                                    }
                                    PromptOutcome::Cancelled => Decision::Cancelled,
                                    PromptOutcome::Error(e) => Decision::Reject(format!(
                                        "Failed to request permission from user: {e}"
                                    )),
                                    PromptOutcome::FollowupMessage(followup_message) => {
                                        Decision::FollowupMessage(followup_message.clone())
                                    }
                                };
                                let outcome_str = effective_kind.wire_str();
                                (decision, outcome_str, true)
                            }
                        };
                        if user_prompted
                            && let Some(approved) =
                                prompted_decision_approved(&decision, outcome_str)
                        {
                            recorded_permission_decisions.push(
                                crate::permission::auto_mode::ClassifierTurn::PermissionDecision {
                                    tool: tool_name.clone(),
                                    args: crate::permission::auto_mode::permission_decision_args(
                                        &access,
                                        access_detail.as_deref(),
                                    ),
                                    approved,
                                },
                            );
                            let len = recorded_permission_decisions.len();
                            if len > MAX_RECORDED_PERMISSION_DECISIONS {
                                recorded_permission_decisions
                                    .drain(..len - MAX_RECORDED_PERMISSION_DECISIONS);
                            }
                        }
                        let requester_gone =
                            matches!(decision, Decision::Cancelled) && respond_to.is_closed();
                        let trigger = if requester_gone {
                            tracing::info!(tool = %tool_name, "permission requester gone; open prompt abandoned");
                            reasons::REQUESTER_GONE
                        } else {
                            prompt_trigger
                        };
                        let event = emit_event(
                            &decision,
                            false,
                            user_prompted,
                            Some(outcome_str),
                            Some(trigger),
                        );
                        if user_prompted && outcome_str != "error" && !requester_gone {
                            auto_consecutive_denials = 0;
                            auto_total_denials = 0;
                        }
                        let _ = respond_to.send(PermissionResolution {
                            decision,
                            event: Some(event),
                        });
                    }
                    // 1.0.36 item a (R3): the one terminal clamp. A launch-policy ask the client did not answer (an
                    // Allow from any fast path, or the dontAsk refusal) is asked of the client now; its answer is
                    // the decision and remembers nothing. A deny or guard refusal stands.
                    if let Some(held) = launch_hold {
                        let mut events: Vec<PermissionEvent> = Vec::new();
                        if let Some(rx) = launch_events.as_mut() {
                            while let Ok(event) = rx.try_recv() {
                                events.push(event);
                            }
                        }
                        let held = held.borrow_mut().take();
                        if let Some((mut resolution, mut inner, untrusted)) = held {
                            if let Some(clamp) = launch_clamp.take()
                                && launch_clamp_applies(&resolution)
                            {
                                {
                                    let slot = user_prompt_notify_actor.lock();
                                    if let Some(tx) = slot.as_ref() {
                                        let _ = tx.send(());
                                    }
                                }
                                let outcome = tokio::select! {
                                    outcome = prompter.request(&clamp.access, &clamp.prompt_update, clamp.protected_edit, clamp.hook_ask.as_ref()) => outcome,
                                    _ = inner.closed() => PromptOutcome::Cancelled,
                                };
                                let outcome = once_only(outcome);
                                let kind = outcome.kind();
                                let decision = match outcome {
                                    PromptOutcome::AllowOnce => Decision::Allow,
                                    PromptOutcome::Cancelled => Decision::Cancelled,
                                    PromptOutcome::FollowupMessage(msg) => {
                                        Decision::FollowupMessage(msg)
                                    }
                                    PromptOutcome::Error(e) => Decision::Reject(format!(
                                        "Failed to request permission from user: {e}"
                                    )),
                                    _ => Decision::Reject("User rejected the execution".to_owned()),
                                };
                                tracing::info!(
                                    tool = %crate::permission::prompter::tool_name_for_access(&clamp.access),
                                    "launch permission policy ask: answered by the client"
                                );
                                let event = resolution.event.take().map(|mut event| {
                                    let (decision_str, reject_reason) = match &decision {
                                        Decision::Allow => ("allow", None),
                                        Decision::Ask => ("ask", None),
                                        Decision::Reject(reason) | Decision::PolicyDeny(reason) => {
                                            ("reject", Some(reason.clone()))
                                        }
                                        Decision::FollowupMessage(_) => ("followup", None),
                                        Decision::Cancelled => ("cancelled", None),
                                    };
                                    event.auto_approved = false;
                                    event.user_prompted = true;
                                    event.decision = decision_str.to_owned();
                                    event.reject_reason = reject_reason;
                                    event.prompt_outcome = Some(kind.wire_str().to_owned());
                                    event.decision_reason = Some(reasons::POLICY_ASK.to_owned());
                                    event.approved_without_grant =
                                        Some(!matches!(decision, Decision::Allow));
                                    event
                                });
                                // The held answer's own event is replaced by the client's.
                                if let Some(new_event) = &event
                                    && let Some(last) = events.last_mut()
                                {
                                    *last = new_event.clone();
                                }
                                resolution = PermissionResolution { decision, event };
                            }
                            for event in events {
                                let _ = event_tx_actor.send(event);
                            }
                            let _ = FinalShellSend {
                                inner,
                                untrusted,
                                held: None,
                            }
                            .send(resolution);
                        } else {
                            for event in events {
                                let _ = event_tx_actor.send(event);
                            }
                        }
                    }
                }

                PermissionCommand::Shutdown => break,
            }
        }
    });

    (
        PermissionHandle::Actor {
            cmd_tx: tx,
            yolo_state,
            auto_state,
            side_query_wired,
            yolo_pin,
            deny_read_globs: Arc::new(deny_read_globs),
            in_flight,
            user_prompt_notify,
            mode_view,
        },
        event_rx,
    )
}

#[cfg(test)]
mod tests;
