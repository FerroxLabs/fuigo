pub mod auto_mode;
pub mod bash_command_splitting;
mod bash_permission_script;
mod branch_switch;
/// The branch-switch listing child, for the folder-trust gate test (`repo_exec_gate_tests`).
#[cfg(test)]
pub(crate) use branch_switch::hardened_git_command as hardened_git_command_for_gate_tests;
pub mod claude_settings;
pub(crate) mod exec_risk;
mod exec_surface;
mod gate_preflight;
mod hub_permission;
mod manager;
pub mod peer_denials;
pub mod peer_guard;
pub(crate) mod plain_text_gate;
mod safe_forms;
mod run_dirs;
mod policy;
#[cfg(test)]
mod policy_bash_recovery_tests;
mod prompter;
mod sandbox_card;
mod sandbox_gate;
mod sandbox_network;
pub mod sandbox_wire;
pub mod resolution;
pub mod rules;
mod shell_access;
pub(crate) mod shell_words;
mod state;
pub mod types;

macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($variant:ident => $wire:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $vis enum $name {
            $($variant),+
        }

        impl $name {
            $vis const ALL: &'static [Self] = &[$(Self::$variant),+];

            $vis const fn wire_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire),+
                }
            }
        }
    };
}
pub(crate) use wire_enum;

pub use auto_mode::{
    AUTO_MODE_CLASSIFIER_SYSTEM_PROMPT, AutoFastPath, BashSecurityAssessment,
    CLASSIFIER_TURN_MAX_LEN, ClassifierContext, ClassifierFailure, ClassifierMessage,
    ClassifierMessageRole, ClassifierOutcome, ClassifierPromptType, ClassifierSecurityFinding,
    ClassifierSource, ClassifierSourceKind, ClassifierTurn, ClassifierVerdict, ClassifyTextChannel,
    ClassifyTextFn, FixedClassifier, HeuristicPermissionClassifier, LlmPermissionClassifier,
    PermissionClassifier, SharedClassifier, access_requires_user_interaction, auto_mode_fast_path,
    build_classifier_messages, classifier_output_json_schema, default_auto_mode_classifier,
    is_auto_mode_allowlisted_access, is_auto_mode_allowlisted_tool_name,
    parse_classifier_model_output, parse_classifier_model_text, permission_decision_args,
};
#[cfg(not(test))]
pub(crate) use manager::child_env_steers;
pub(crate) use manager::install_runner_env_judge;
#[cfg(test)]
pub(crate) use hub_permission::build_permission_payload_for_test;
pub(crate) use hub_permission::{
    HubCallVerdict, HubPolicyContext, HubReadSpelling, hub_read_spellings, hub_input_accesses, hub_input_is_generic, hub_patch_targets,
    hub_patch_targets_by_name, hub_policy_accesses, hub_policy_verdict_all, hub_verdict_over_run_dirs, hub_searches_need_walk,
    settle_hub_asks, settle_hub_asks_caused, hub_denial_cause,
};
pub use hub_permission::{
    PermissionHookTransport, ToolServerPermissionTransport, access_kind_for_hub_tool,
    hitl_permission_live_enabled, prompt_outcome_allows, request_permission_via_hub,
};

pub(crate) fn init_metrics() {
    hub_permission::init_metrics();
}
pub use manager::{
    AUTO_DENY_CONSECUTIVE_LIMIT, AUTO_DENY_TOTAL_LIMIT, ModeView, PermissionHandle,
    always_allow_scope_persists, default_always_allow_scope, default_always_deny_scope,
    minimum_always_allow_scope, reasons, spawn_permission_manager,
    spawn_permission_manager_with_hub,
};
pub use policy::{
    CompiledPolicy, bash_glob_is_catchall, bash_pattern_is_broad, bash_pattern_matches_command,
};
pub use prompter::{
    ALLOW_EDITS_SESSION_OPTION_ID, AcpPrompter, BashCommandPermission, BashCommandSelectedTerms,
    ENABLE_ALWAYS_APPROVE_OPTION_ID, MCP_TOOL_NAME_DELIMITER, McpScopeSelection, McpToolPermission,
    PromptOutcome, PromptOutcomeKind, is_enable_always_approve_option,
    mcp_pretty_name_if_qualified, mcp_titleize_segment, mcp_tool_action, mcp_tool_display_name,
    tool_name_for_access as prompter_tool_name_for_access,
};
pub use peer_denials::{
    CarriedStats, DenialCause, DenialKey, DenialLog, KeyBasis, LaunderingHit, MANY_TARGETS_HASH, MAX_KEYS_PER_DENIAL, cap_keys, records_denial, denial_key, denial_keys, denial_keys_for, match_keys, match_keys_for, laundering_refused_text, mono_secs};
pub use peer_guard::{PeerInfluence, PeerPayloadNote, is_peer_protected_path, peer_guard_denial_text};
pub(crate) use sandbox_card::{AskCause, SandboxCover, card_replaces};
pub(crate) use sandbox_gate::{
    SandboxPath, SettleContext, ViolationSettlement, refuse_mode_layer_write, settle_violation,
};
pub use sandbox_network::{
    GrantView, HoldAnswer, SandboxNetworkDecider, SandboxNetworkDeciderConfig, ViolationSink,
    WebFetchDomainFile, WebFetchDomains,
};
pub use shell_access::{ProtectedEditPermission, ProtectedEditReason};
pub use state::PermissionState;
pub use state::cleanup_stale_permission_state;
pub use types::{
    AccessKind, ClientType, Decision, EditTargets, HOOK_ASK_META_KEY, HookAsk, PermissionCommand,
    EffectivePeerMode, EffectivePermissionMode, PermissionConfig, PermissionEvent, PermissionRequest, ResolvedBaseMode, PermissionResolution, ReadResolution, ReadTargets, bash_exec_cwd_for, edit_targets_for,
    read_targets_for,
};

/// u35 t1 (design d2 §3.6): install the shell runner's folder-trust backstop for calls approved without a grant.
pub(crate) fn install_runner_trust_judge() {
    manager::install_runner_trust_judge();
}
