//! Config file loading for Fuigo.
//!
//! Merge order (lowest to highest priority):
//! 1. `/etc/fuigo/managed_config.toml`
//! 2. `$FUIGO_HOME/managed_config.toml`
//! 3. `$FUIGO_HOME/config.toml`
//! 4. `$FUIGO_HOME/requirements.toml` (cloud cache; Ed25519-signed at rest once a key is embedded, see [`signed_policy`])
//! 5. `/etc/fuigo/requirements.toml`
//! 6. macOS MDM managed preferences (`ai.x.grok`, admin-forced), macOS only
//!
//! Each layer applies its own [`[[version_overrides]]`](version_overrides) before merge.
//! Requirements layers (#4 through #6) may opt into fail-closed startup; see [`validate_requirements`].

pub mod campaigns;
mod config_layers;
pub mod config_override;
pub mod credential_env;
mod env_overlay;
pub mod fs_atomic;
pub mod global_hook_sources;
pub mod key_naming;
#[cfg(test)]
mod credential_env_k13_tests;
#[cfg(test)]
mod key_naming_tests;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod p147_tests;
mod loader;
mod macos_managed;
mod managed_cache;
pub mod managed_text;
mod paths;
pub mod policy_sources;
pub mod shell;
pub mod signed_policy;
mod validation;
pub mod version_overrides;
pub mod write_through;

// Only the campaign items other crates need are re-exported at the root
// The rest stays reachable via the `pub mod` paths, keeping the root API narrow
pub use campaigns::{
    CampaignEntry, CampaignOverrides, filter_active_campaigns, ids_touching_paths,
};
pub use credential_env::{
    FIRST_PARTY_KEY_ENV_VAR, apply_first_party_key_defaults, install_credential_env_resolver, resolve_credential_env_var,
    read_first_party_key_references, resolve_first_party_key_references,
};
pub use global_hook_sources::{
    GlobalHookSource, GlobalHookSourceError, GlobalHookSourceKind, ResolvedGlobalHookSources,
    TRUST_BOUNDARY_FILENAMES, ensure_fuigo_hook_slots, existing_ancestor_chain,
    is_direct_hook_json_name, list_direct_hook_json_files, missing_configured_sources,
    path_has_symlink_component, resolve_global_hook_sources, resolve_trust_boundary_sources,
    unique_ancestors_rootward,
};

pub use config_layers::{
    CampaignsState, ConfigLayers, campaigns_application_disabled, campaigns_state_path,
    load_dismissed_ids_from_home, load_effective_config_disk_only,
};
pub use env_overlay::{
    FUIGO_CONFIG_ENV, FUIGO_CONFIG_PATH_ENV, OverlaySource, ResolvedOverlay, resolved_env_overlay,
};
#[cfg(unix)]
pub use global_hook_sources::{
    validate_direct_hook_json_file, validated_hook_json_files_for_sources,
};
pub use loader::{
    HookConfigLayer, HookProvenance, MANAGED_CONFIG_FILENAME, ManagedConfigLayer,
    REQUIREMENTS_FILENAME, SANDBOX_CONFIG_FILENAME, TRUSTED_FOLDERS_FILENAME,
    TRUSTED_HOOK_PROJECTS_FILENAME, TRUSTED_PLUGINS_FILENAME, USER_CONFIG_FILENAME,
    apply_version_overrides_with_registered, deep_merge_toml, merge_requirements_toml, policy_semver, expand_env_vars_in_string,
    expand_env_vars_in_toml, hook_config_layers, hook_config_layers_at, load_config_file,
    load_config_file_with_key_naming,
    load_from_disk, load_managed_config, load_system_managed_config, load_toml_file,
    managed_config_layers, managed_config_layers_at, parse_user_config_layer, toml_error_detail,
};
pub use macos_managed::MDM_REQUIREMENTS_SOURCE;
pub use managed_cache::{
    managed_marker_records_file,
    MANAGED_CONFIG_CACHE_FILE, ServingIdentity, SyncMarker, bump_rollback_floor,
    bump_rollback_floor_with_now, confirmed_team_switch, confirmed_team_switch_at,
    fail_closed_policy_armed_at, is_managed_config_hard_stale_for, is_managed_config_stale_for,
    managed_config_identity_changed_at, managed_config_synced_at, managed_deployment_id,
    managed_policy_compromised_for, mark_managed_config_synced, mark_managed_config_synced_at,
    normalize_identity,
};
pub use paths::{
    claude_managed_settings_path, claude_managed_settings_probe_path, create_dir_all_owner_only,
    create_file_owner_only, owner_only_file_options, tighten_file_owner_only, tighten_own_regular_file_owner_only,
    write_file_owner_only,
    decode_cwd_from_dirname, default_fuigo_home, encode_cwd_dirname, ensure_sessions_cwd_dir,
    ensure_sessions_cwd_dir_in, fuigo_application, fuigo_application_in, fuigo_home, sessions_cwd_dir,
    sessions_cwd_dir_in, set_dir_owner_only, system_config_dir, user_fuigo_home,
};
#[cfg(feature = "test-seams")]
pub use paths::admin_root_override;
/// Test seam: a hook run at the blank re-check wait (see `loader::confirm_blank_with`), per thread.
#[cfg(feature = "test-seams")]
pub use loader::blank_hook as blank_recheck_seam;
#[cfg(feature = "test-seams")]
pub use macos_managed::mdm_override;
pub use validation::{
    RequirementsError, RequirementsLayer, RequirementsSource, load_merged_requirements,
    BrokenAdminFile, AdminLockdown, admin_lockdowns, admin_lockdowns_at, admin_lockdown_lifted_notice, admin_lockdown_ended_invalid_notice, admin_lockdown_emptied_notice, admin_lockdown_gone_notice, admin_policy_valid_in_force_notice, AdminFileClass, AdminFileState, admin_policy_states_at, admin_policy_reader, RequirementsBroken, admin_lockdown_requirements, admin_lockdown_managed_config, admin_requirements_copy_exists, admin_requirements_copy_id, lockdown_entries, LOCKDOWN_UNSET, broken_admin_files, requirements_layers, requirements_layers_checked, REQUIREMENTS_BOOL_FEATURES, requirements_file_load_error, validate_requirements, validate_requirements_for_dirs,
    validate_requirements_with_warnings,
};
// P183 round 7: the shapes other crates' policy readers decode (kept in step by tests there), and the managed-settings reader
pub use validation::{
    ManagedSettingsJson, PERMISSION_PATTERN_MODES, PERMISSION_RULE_ACTIONS, PERMISSION_RULE_TOOLS,
    TELEMETRY_MODE_STRINGS, hook_event_shape_ok, managed_settings_json, managed_settings_policy_errors,
    permission_rule_shape_ok,
};
pub use version_overrides::{VersionOverrideError, apply_version_overrides};

/// Parse an env var as a boolean; returns `None` if unset or unrecognized.
pub fn env_bool(name: &str) -> Option<bool> {
    let value = std::env::var(name).ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "" => None,
        "1" | "true" | "yes" | "on" | "enabled" => Some(true),
        "0" | "false" | "no" | "off" | "disabled" => Some(false),
        _ => None,
    }
}
