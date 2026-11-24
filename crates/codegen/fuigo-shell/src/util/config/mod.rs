// `McpOAuthConfig` / `McpOAuthConfigMap` are re-exported via `mcp` (see `mcp.rs`)

#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there"
)]
#[cfg(test)]
pub(crate) mod admin_seam_test_support;
mod announcements;
mod campaigns;
mod consent;
mod hints;
mod load;
mod mcp;
pub(crate) mod mcp_approvals;
mod mcp_reenable;
mod permissions;
mod persist;
mod resolve;
mod self_writes;
mod settings_writes;
mod tips;
mod worktree;

pub use announcements::*;
pub use campaigns::{
    CampaignModelsDefault, campaign_driven_models_default, effective_config_for_remote_settings,
    effective_config_from_layers, last_good_config_layers, load_effective_config,
    load_effective_config_and_user_layer, load_effective_config_disk_only,
    load_effective_config_with_campaign_free, persist_models_default,
    remote_campaigns_from_settings, set_remote_campaigns_from_settings, sync_campaign_fields,
};
pub use consent::*;
pub use hints::*;
pub use load::*;
pub use mcp::*;
pub use mcp_approvals::reset_mcp_approvals;
pub(crate) use mcp_reenable::{
    McpDefinitionIndex, needs_definition_scan, reenableable_disabled_stubs,
};
pub use permissions::*;
pub use persist::*;
// These types live in `fuigo-config-types`; the re-export keeps `crate::util::config::{RemoteSettings, GoalRoleModel}` working
pub use fuigo_config_types::{
    CampaignOverride, ConsentGate, ContextualHintsRemote, DisplayRefreshSettings,
    DoomLoopRecoverySettings, GoalRoleModel, RemoteSettings, WorktreeAutoGcSettings,
    WorktreeKindMaxAge, deserialize_tolerant,
};
pub use resolve::*;
pub use self_writes::sha256_hex;
pub(crate) use self_writes::{current_seq, newest_matching_since, record_own_write};
pub use settings_writes::*;
pub use tips::*;
pub use worktree::*;
