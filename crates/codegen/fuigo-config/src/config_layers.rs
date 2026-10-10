//! The layer *files* are read by [`crate::loader`].
//! This module owns how those layers combine into the effective config: layer precedence, the `FUIGO_CONFIG` overlay, and campaign resolution.

use crate::loader::{
    deep_merge_toml, load_from_disk, load_managed_config, load_system_managed_config,
    normalize_config_layer,
};
use crate::validation::{load_requirements, load_system_requirements};

/// Whether a layer merge includes the `FUIGO_CONFIG` overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlayInclusion {
    Include,
    Exclude,
}

/// Layers from lowest to highest priority. `[[campaigns]]` is taken off each layer at load.
#[derive(Clone)]
pub struct ConfigLayers {
    pub system_managed: toml::Value,
    pub managed: toml::Value,
    pub user: toml::Value,
    /// `FUIGO_CONFIG` / `FUIGO_CONFIG_PATH` overlay, above user but below requirements.
    /// Soft settings only; this doc is the canonical source of truth for what the overlay can and cannot reach.
    ///
    /// Values are confined at [`crate::env_overlay`]'s `finalize_overlay` choke point.
    /// Both producers return confined overlays.
    /// `load_env_overlay` feeds the merge path via [`Self::load`].
    /// `resolved_env_overlay` serves hints (which constructs this field directly) and `fuigo inspect`.
    /// Construct this field only from one of those producers.
    /// Tests that assign an unconfined value do so deliberately, to exercise a gate independent of the allowlist.
    ///
    /// The overlay is confined to an allowlist of soft paths ([`crate::config_override::OVERLAY_ALLOW_PATHS`]).
    /// The allowlist holds the `models` and `features` tables, a narrowed `toolset`, and a filtered `shell_environment_policy`.
    /// `toolset` keeps only `[toolset.bash] login_shell_capture` and the `[toolset.web_search]` domain lists.
    /// `shell_environment_policy` keeps only its filter fields (`inherit`, `exclude`, `include_only`, `ignore_default_excludes`).
    /// `plugins` keeps only `auto_discover`, and only when it is `false`: the overlay can turn implicit plugin discovery off,
    /// never on (a host embedding Fuigo uses it to keep the machine owner's plugins out of its sessions).
    /// Every other table, plus the shell-env `set` field, is dropped at the choke point.
    /// This is fail-closed: every code-exec, auth, egress, trust, or discovery table is absent from the allowlist and dropped by default.
    /// A newly added dangerous table stays out until it is explicitly allowlisted.
    /// The overlay therefore cannot spawn a new command sink, set auth policy, redirect egress, elevate trust, or add a discovery source.
    /// `shell_environment_policy` cannot inject an env value (`set` is dropped).
    /// Its remaining fields only select among env names the launcher already controls.
    /// Relative to a lower layer they may loosen or tighten what a subprocess inherits but never introduce a value.
    /// A launcher that must add an env var sets it on the process directly.
    /// `sandbox` and `telemetry` are likewise not allowlisted (set them via `FUIGO_SANDBOX` / `OTEL_*`).
    /// `[features] telemetry` is the master switch and is allowlisted.
    ///
    /// Even on the allowlisted tables, security gates read overlay-free; requirements/MDM clamp on top.
    /// They read the raw disk layers via [`Self::effective_config_base_without_overlay`], explicit per-layer values, or the raw config files.
    /// Those gates cover permission mode, plan approval, auto permission mode plus its classifier, and remember tool approvals.
    /// They also cover `remote_fetch`, managed-config fetch, marketplace `require_sha`, ZDR access, and folder trust.
    /// `[permission]` allow/deny rules and the `[cli]` version bounds are read overlay-free as well.
    pub env_overlay: Option<toml::Value>,
    pub user_requirements: Option<toml::Value>,
    pub system_requirements: Option<toml::Value>,
    /// macOS MDM requirements; highest requirements tier when present.
    pub mdm_requirements: Option<toml::Value>,
    pub campaigns: crate::campaigns::CampaignOverrides,
}

impl Default for ConfigLayers {
    fn default() -> Self {
        Self {
            system_managed: toml::Value::Table(Default::default()),
            managed: toml::Value::Table(Default::default()),
            user: toml::Value::Table(Default::default()),
            env_overlay: None,
            user_requirements: None,
            system_requirements: None,
            mdm_requirements: None,
            campaigns: crate::campaigns::CampaignOverrides::default(),
        }
    }
}

impl ConfigLayers {
    pub fn load() -> std::io::Result<Self> {
        use crate::campaigns::{CampaignOverrides, take_campaign_entries};

        let mut system_managed = load_system_managed_config()?;
        let system_managed_campaigns = take_campaign_entries(&mut system_managed, "system_managed");

        let mut managed = load_managed_config()?;
        let managed_campaigns = take_campaign_entries(&mut managed, "managed");

        let mut user = load_from_disk()?;
        let user_campaigns = take_campaign_entries(&mut user, "user");

        let env_overlay = crate::env_overlay::load_env_overlay();

        let mut user_requirements = load_requirements();
        let mut system_requirements = load_system_requirements();
        let mut mdm_requirements = crate::validation::mdm_requirements_value();

        // Highest-authority tier first: `merge_campaign_entries` is first-id-wins, so a duplicate campaign id must resolve mdm > system > user
        // That matches the layer precedence in `effective_config_base`, where mdm is merged last/highest
        let mut requirements_campaigns = Vec::new();
        if let Some(ref mut req) = mdm_requirements {
            requirements_campaigns.extend(take_campaign_entries(req, "requirements"));
        }
        if let Some(ref mut req) = system_requirements {
            requirements_campaigns.extend(take_campaign_entries(req, "requirements"));
        }
        if let Some(ref mut req) = user_requirements {
            requirements_campaigns.extend(take_campaign_entries(req, "requirements"));
        }

        // Normalize each layer before any merge, so `[toolset.web_search]`'s `allowed_domains` / `excluded_domains` travel together
        // A layer that sets one clears the other to `[]`
        // That makes `deep_merge_toml` replace the whole policy from the winning layer instead of mixing keys across layers
        normalize_config_layer(&mut system_managed);
        normalize_config_layer(&mut managed);
        normalize_config_layer(&mut user);
        for req in [
            &mut user_requirements,
            &mut system_requirements,
            &mut mdm_requirements,
        ]
        .into_iter()
        .flatten()
        {
            normalize_config_layer(req);
        }

        Ok(Self {
            system_managed,
            managed,
            user,
            env_overlay,
            user_requirements,
            system_requirements,
            mdm_requirements,
            campaigns: CampaignOverrides {
                requirements: requirements_campaigns,
                user: user_campaigns,
                managed: managed_campaigns,
                system_managed: system_managed_campaigns,
            },
        })
    }

    /// Layer merge (no campaigns), including the `FUIGO_CONFIG` overlay.
    ///
    /// Overlay-inclusive: security gates must not read this.
    /// Use [`Self::effective_config_base_without_overlay`] for any gate (the overlay-free set is enumerated on [`Self::env_overlay`]).
    pub fn effective_config_base(&self) -> toml::Value {
        self.merge(OverlayInclusion::Include)
    }

    /// Layer merge excluding the `FUIGO_CONFIG` overlay, for security gates.
    pub fn effective_config_base_without_overlay(&self) -> toml::Value {
        self.merge(OverlayInclusion::Exclude)
    }

    fn merge(&self, inclusion: OverlayInclusion) -> toml::Value {
        let Self {
            system_managed,
            managed,
            user,
            env_overlay,
            user_requirements: _,
            system_requirements: _,
            mdm_requirements: _,
            campaigns: _,
        } = self;
        let mut merged = self.non_user_layer(system_managed);
        deep_merge_toml(&mut merged, &self.non_user_layer(managed));
        deep_merge_toml(&mut merged, user);
        if let (OverlayInclusion::Include, Some(overlay)) = (inclusion, env_overlay) {
            deep_merge_toml(&mut merged, overlay);
        }
        if let Some(r) = self.merged_requirements() {
            deep_merge_toml(&mut merged, &r);
        }
        merged
    }

    /// A non-user layer as it enters the merge: without subscription authority (P192; see
    /// [`crate::config_override::strip_subscription_authority`]).
    fn non_user_layer(&self, layer: &toml::Value) -> toml::Value {
        let mut layer = layer.clone();
        crate::config_override::strip_subscription_authority(&mut layer, &self.user);
        layer
    }

    fn requirements_in_order(&self) -> impl Iterator<Item = &toml::Value> {
        [
            &self.user_requirements,
            &self.system_requirements,
            &self.mdm_requirements,
        ]
        .into_iter()
        .flatten()
    }

    /// Campaign source slices in priority order (first id wins): requirements > remote > user > managed > system_managed.
    /// This is the single source of truth for the precedence; both this crate and the shell resolver consume it.
    pub fn campaign_source_slices<'a>(
        &'a self,
        remote_campaigns: &'a [crate::campaigns::CampaignEntry],
    ) -> [&'a [crate::campaigns::CampaignEntry]; 5] {
        [
            &self.campaigns.requirements,
            remote_campaigns,
            &self.campaigns.user,
            &self.campaigns.managed,
            &self.campaigns.system_managed,
        ]
    }

    /// Active campaigns against `base`: the kill switch, then the priority merge (first-id-wins), then dropping dismissed ids.
    /// This is the one place that resolves disk campaigns; the shell wraps it with the `FUIGO_CAMPAIGNS_OVERRIDE` env layer.
    pub fn resolve_campaigns(
        &self,
        base: &toml::Value,
        remote_campaigns: &[crate::campaigns::CampaignEntry],
        dismissed_ids: &std::collections::HashSet<String>,
    ) -> Vec<crate::campaigns::CampaignEntry> {
        if campaigns_application_disabled(base) {
            return Vec::new();
        }
        let merged = crate::campaigns::merge_campaign_entries(
            &self.campaign_source_slices(remote_campaigns),
        );
        crate::campaigns::filter_active_campaigns(merged, dismissed_ids)
    }

    /// Re-merge the requirements layers so an admin's `requirements.toml` always wins over a campaign overlay, whatever the campaign's source layer.
    /// Campaigns are full-power (any field), so this is the structural guarantee that a lower-trust campaign can't override an admin-set field.
    fn reapply_requirements(&self, merged: &mut toml::Value) {
        if let Some(r) = self.merged_requirements() {
            deep_merge_toml(merged, &r);
        }
    }

    /// P183 round 4: the requirements layers merged among themselves type-preservingly (a wrong-type higher value cannot erase
    /// a lower typed pin), to be laid over the config of any type.
    fn merged_requirements(&self) -> Option<toml::Value> {
        let mut layers = self.requirements_in_order();
        let mut merged = self.non_user_layer(layers.next()?);
        for req in layers {
            crate::loader::merge_requirements_toml(&mut merged, &self.non_user_layer(req));
        }
        Some(merged)
    }

    /// Apply campaign patches, re-apply the `FUIGO_CONFIG` overlay, then restore requirements.
    pub fn apply_campaign_overrides(
        &self,
        merged: &mut toml::Value,
        active: &[crate::campaigns::CampaignEntry],
    ) {
        crate::campaigns::apply_active_campaign_patches(merged, active);
        if let Some(overlay) = &self.env_overlay {
            deep_merge_toml(merged, overlay);
        }
        self.reapply_requirements(merged);
    }

    /// Layer merge and disk/remote campaign overlay, honoring the kill switch.
    /// The shell's `load_effective_config` is the remote/override-aware path; this is used by `effective_config_disk_only` and tests.
    pub fn effective_config_with_campaigns(
        &self,
        remote_campaigns: &[crate::campaigns::CampaignEntry],
        dismissed_ids: &std::collections::HashSet<String>,
    ) -> toml::Value {
        let mut merged = self.effective_config_base();
        let active = self.resolve_campaigns(&merged, remote_campaigns, dismissed_ids);
        self.apply_campaign_overrides(&mut merged, &active);
        merged
    }

    /// Disk campaigns and on-disk dismiss (`campaigns_state.json`); **no remote, no env override**.
    /// The name makes the divergence from the shell's remote-aware `load_effective_config` explicit at every call site.
    pub fn effective_config_disk_only(&self) -> toml::Value {
        self.effective_config_with_campaigns(&[], &load_dismissed_ids_from_home())
    }

    pub fn has_managed(&self) -> bool {
        self.managed.as_table().is_some_and(|t| !t.is_empty())
            || self
                .system_managed
                .as_table()
                .is_some_and(|t| !t.is_empty())
    }

    pub fn has_system_managed(&self) -> bool {
        self.system_managed
            .as_table()
            .is_some_and(|t| !t.is_empty())
    }
}

/// `FUIGO_CAMPAIGNS=0` or `[features] campaigns = false` on pre-campaign base.
pub fn campaigns_application_disabled(base_effective: &toml::Value) -> bool {
    campaigns_application_disabled_for(crate::env_bool("FUIGO_CAMPAIGNS"), base_effective)
}

/// [`campaigns_application_disabled`] with the parsed `FUIGO_CAMPAIGNS` value passed in, so the
/// rule is testable without writing the process environment (every campaign test reads it).
fn campaigns_application_disabled_for(env: Option<bool>, base_effective: &toml::Value) -> bool {
    if env == Some(false) {
        return true;
    }
    base_effective
        .get("features")
        .and_then(|f| f.get("campaigns"))
        .and_then(|c| c.as_bool())
        == Some(false)
}

/// Disk layers only (no remote, no env override).
/// Prefer `fuigo_shell::util::config::load_effective_config` when remote campaigns or `FUIGO_CAMPAIGNS_OVERRIDE` must be honored.
/// The name mirrors [`ConfigLayers::effective_config_disk_only`] so the divergence from the remote-aware loader is explicit at every call site.
pub fn load_effective_config_disk_only() -> std::io::Result<toml::Value> {
    Ok(ConfigLayers::load()?.effective_config_disk_only())
}

/// On-disk campaign dismiss state.
/// This is the single source of truth for the file's name, location, and JSON shape.
/// The shell's writer reuses these so the read and write sides can't drift.
pub const CAMPAIGNS_STATE_FILE: &str = "campaigns_state.json";

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CampaignsState {
    #[serde(default)]
    pub dismissed_ids: Vec<String>,
}

/// Path to `$FUIGO_HOME/campaigns_state.json` under `home`.
pub fn campaigns_state_path(home: &std::path::Path) -> std::path::PathBuf {
    home.join(CAMPAIGNS_STATE_FILE)
}

/// Fail-open dismissed ids from `$FUIGO_HOME/campaigns_state.json`.
pub fn load_dismissed_ids_from_home() -> std::collections::HashSet<String> {
    let Some(home) = crate::user_fuigo_home() else {
        return std::collections::HashSet::new();
    };
    let Ok(contents) = std::fs::read_to_string(campaigns_state_path(&home)) else {
        return std::collections::HashSet::new();
    };
    serde_json::from_str::<CampaignsState>(&contents)
        .map(|s| s.dismissed_ids.into_iter().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p192_toml(s: &str) -> toml::Value {
        toml::from_str(s).unwrap()
    }

    fn p192_model<'a>(merged: &'a toml::Value, id: &str) -> Option<&'a toml::Value> {
        merged.get("model").and_then(|m| m.get(id))
    }

    /// P192 (Grok HIGH, example 1): requirements (and MDM, the highest tier) cannot retarget the
    /// user's own model to a subscription vendor host, where it would be bound to the subscription.
    #[test]
    fn p192_requirements_cannot_retarget_a_user_model_to_a_vendor_host() {
        let user =
            "[model.work]\nmodel = \"grok-4.7\"\nbase_url = \"https://api.fluxrouter.ai/v1\"\n";
        let retarget = "[model.work]\nbase_url = \"https://api.x.ai/v1\"\n";
        for layers in [
            ConfigLayers {
                user: p192_toml(user),
                user_requirements: Some(p192_toml(retarget)),
                ..Default::default()
            },
            ConfigLayers {
                user: p192_toml(user),
                system_requirements: Some(p192_toml(retarget)),
                ..Default::default()
            },
            ConfigLayers {
                user: p192_toml(user),
                mdm_requirements: Some(p192_toml(retarget)),
                ..Default::default()
            },
        ] {
            for merged in [
                layers.effective_config_base(),
                layers.effective_config_disk_only(),
            ] {
                assert_eq!(
                    p192_model(&merged, "work")
                        .and_then(|m| m.get("base_url"))
                        .and_then(|v| v.as_str()),
                    Some("https://api.fluxrouter.ai/v1"),
                );
            }
        }
    }

    /// P192 (Grok HIGH, example 2): managed config cannot plant a new vendor model (and make it
    /// the default); nor can system-managed config or requirements.
    #[test]
    fn p192_non_user_layers_cannot_plant_a_vendor_model() {
        let planted = "[models]\ndefault = \"planted\"\n\n[model.planted]\nmodel = \"grok-4.7\"\nbase_url = \"https://api.x.ai/v1\"\n";
        for layers in [
            ConfigLayers {
                managed: p192_toml(planted),
                ..Default::default()
            },
            ConfigLayers {
                system_managed: p192_toml(planted),
                ..Default::default()
            },
            ConfigLayers {
                user_requirements: Some(p192_toml(planted)),
                ..Default::default()
            },
            ConfigLayers {
                mdm_requirements: Some(p192_toml(planted)),
                ..Default::default()
            },
        ] {
            assert!(p192_model(&layers.effective_config_base(), "planted").is_none());
            assert!(p192_model(&layers.effective_config_disk_only(), "planted").is_none());
        }
        // An encoded spelling of the host is the same host.
        let encoded = "[model.planted]\nmodel = \"gpt-5.5\"\napi_base_url = \"https://chat%67pt.com/backend-api/codex\"\n";
        let layers = ConfigLayers {
            managed: p192_toml(encoded),
            ..Default::default()
        };
        assert!(p192_model(&layers.effective_config_base(), "planted").is_none());
    }

    /// P192 (Grok HIGH): a requirements `base_url = "${VAR}"` is expanded at layer load, before the
    /// merge; the expanded vendor URL is caught all the same.
    #[test]
    fn p192_env_expanded_requirements_vendor_url_is_dropped() {
        unsafe { std::env::set_var("P192_REQ_VENDOR_URL", "https://api.x.ai/v1") };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("requirements.toml");
        std::fs::write(&path, "[model.work]\nbase_url = \"${P192_REQ_VENDOR_URL}\"\n\n[model.planted]\nmodel = \"grok-4.7\"\nbase_url = \"${P192_REQ_VENDOR_URL}\"\n").unwrap();
        let req = crate::validation::load_requirements_layer(&path).expect("requirements layer");
        assert_eq!(
            p192_model(&req, "planted")
                .and_then(|m| m.get("base_url"))
                .and_then(|v| v.as_str()),
            Some("https://api.x.ai/v1"),
            "fixture: the layer is expanded at load"
        );
        let layers = ConfigLayers {
            user: p192_toml(
                "[model.work]\nmodel = \"grok-4.7\"\nbase_url = \"https://api.fluxrouter.ai/v1\"\n",
            ),
            user_requirements: Some(req),
            ..Default::default()
        };
        let merged = layers.effective_config_disk_only();
        assert!(p192_model(&merged, "planted").is_none());
        assert_eq!(
            p192_model(&merged, "work")
                .and_then(|m| m.get("base_url"))
                .and_then(|v| v.as_str()),
            Some("https://api.fluxrouter.ai/v1"),
        );
    }

    /// P192 (Grok MEDIUM): requirements cannot pin an explicit subscription provider either.
    #[test]
    fn p192_requirements_cannot_pin_a_subscription_provider() {
        let req = "[auth_provider.xai]\nsubscription = \"xai\"\n\n[model.planted]\nmodel = \"grok-4.7\"\nbase_url = \"https://api.x.ai/v1\"\nauth_provider = \"xai\"\n\n[model.flux]\nmodel = \"grok-4.7\"\nbase_url = \"https://api.fluxrouter.ai/v1\"\nauth_provider = \"xai\"\n";
        for layers in [
            ConfigLayers {
                user_requirements: Some(p192_toml(req)),
                ..Default::default()
            },
            ConfigLayers {
                managed: p192_toml(req),
                ..Default::default()
            },
            ConfigLayers {
                mdm_requirements: Some(p192_toml(req)),
                ..Default::default()
            },
        ] {
            let merged = layers.effective_config_disk_only();
            assert!(p192_model(&merged, "planted").is_none());
            assert!(
                merged
                    .get("auth_provider")
                    .and_then(|p| p.get("xai"))
                    .and_then(|p| p.get("subscription"))
                    .is_none(),
                "a non-user layer's provider never carries `subscription`"
            );
        }
    }

    /// P192 (Grok r2 HIGH): a non-user layer cannot plant a `[model_providers.*]` entry on a
    /// vendor host carrying an inline `auth.subscription` (Grok's exact requirements example, and
    /// the ChatGPT shape), from any requirements tier or from managed config.
    #[test]
    fn p192_non_user_layers_cannot_plant_a_subscription_model_provider() {
        let xai = "[models]\ndefault = \"planted\"\n\n[model_providers.planted]\nbase_url = \"https://api.x.ai/v1\"\n\n[model_providers.planted.auth]\nsubscription = \"xai\"\n\n[model.planted]\nmodel = \"grok-4.7\"\nmodel_provider = \"planted\"\n";
        let chatgpt = "[models]\ndefault = \"planted\"\n\n[model_providers.planted]\napi_base_url = \"https://chatgpt.com/backend-api/codex\"\n\n[model_providers.planted.auth]\nsubscription = \"chatgpt\"\n\n[model.planted]\nmodel = \"gpt-5.5\"\nmodel_provider = \"planted\"\n";
        let user = "[model.work]\nmodel = \"grok-4.7\"\nbase_url = \"https://api.fluxrouter.ai/v1\"\n";
        for layer in [xai, chatgpt] {
            for layers in [
                ConfigLayers {
                    user: p192_toml(user),
                    user_requirements: Some(p192_toml(layer)),
                    ..Default::default()
                },
                ConfigLayers {
                    user: p192_toml(user),
                    system_requirements: Some(p192_toml(layer)),
                    ..Default::default()
                },
                ConfigLayers {
                    user: p192_toml(user),
                    mdm_requirements: Some(p192_toml(layer)),
                    ..Default::default()
                },
                ConfigLayers {
                    user: p192_toml(user),
                    managed: p192_toml(layer),
                    ..Default::default()
                },
                ConfigLayers {
                    user: p192_toml(user),
                    system_managed: p192_toml(layer),
                    ..Default::default()
                },
            ] {
                for merged in [
                    layers.effective_config_base(),
                    layers.effective_config_disk_only(),
                ] {
                    assert!(p192_model(&merged, "planted").is_none(), "{layer}");
                    assert!(
                        merged
                            .get("model_providers")
                            .and_then(|p| p.get("planted"))
                            .is_none(),
                        "{layer}"
                    );
                }
            }
        }
    }

    /// P192 (Grok r2 HIGH): from a non-user layer, a provider loses `auth.subscription` and an
    /// `auth_provider` naming a user subscription provider (synthetic `model_provider:<id>` names
    /// included); a provider id the user routes a subscription through keeps the user's routing
    /// and auth; and no non-user model is pointed at that provider.
    #[test]
    fn p192_non_user_layers_cannot_lend_subscription_through_model_providers() {
        let user = "[auth_provider.mine]\nsubscription = \"xai\"\n\n[model_providers.sub]\nbase_url = \"https://api.x.ai/v1\"\n\n[model_providers.sub.auth]\nsubscription = \"xai\"\n\n[model.work]\nmodel = \"grok-4.7\"\nmodel_provider = \"sub\"\n\n[model_providers.gw]\nbase_url = \"https://api.fluxrouter.ai/v1\"\n\n[model.viagw]\nmodel = \"grok-4.7\"\nmodel_provider = \"gw\"\nauth_provider = \"mine\"\n";
        let req = "[model_providers.gw]\nbase_url = \"https://evil.example/v1\"\n\n[model_providers.flux]\nbase_url = \"https://api.fluxrouter.ai/v1\"\n\n[model_providers.flux.auth]\nsubscription = \"xai\"\n\n[model_providers.pinned]\nbase_url = \"https://api.fluxrouter.ai/v1\"\nauth_provider = \"mine\"\n\n[model_providers.syn]\nbase_url = \"https://api.fluxrouter.ai/v1\"\nauth_provider = \"model_provider:sub\"\n\n[model_providers.sub]\nbase_url = \"https://api.fluxrouter.ai/v1\"\nauth_provider = \"corp\"\ncontext_window = 1000\n\n[model_providers.sub.auth]\ncommand = \"/bin/echo\"\n\n[model.borrow]\nmodel = \"grok-4.7\"\nmodel_provider = \"sub\"\n\n[model.work]\nmodel_provider = \"flux\"\n";
        for layers in [
            ConfigLayers {
                user: p192_toml(user),
                user_requirements: Some(p192_toml(req)),
                ..Default::default()
            },
            ConfigLayers {
                user: p192_toml(user),
                managed: p192_toml(req),
                ..Default::default()
            },
            ConfigLayers {
                user: p192_toml(user),
                mdm_requirements: Some(p192_toml(req)),
                ..Default::default()
            },
        ] {
            let merged = layers.effective_config_disk_only();
            let providers = &merged["model_providers"];
            assert!(
                providers["flux"]
                    .get("auth")
                    .and_then(|a| a.get("subscription"))
                    .is_none(),
                "a non-user provider never carries `auth.subscription`"
            );
            assert!(providers["pinned"].get("auth_provider").is_none());
            assert!(providers["syn"].get("auth_provider").is_none());
            let sub = &providers["sub"];
            assert_eq!(sub["base_url"].as_str(), Some("https://api.x.ai/v1"));
            assert_eq!(sub["auth"]["subscription"].as_str(), Some("xai"));
            assert!(sub["auth"].get("command").is_none());
            assert!(sub.get("auth_provider").is_none());
            assert_eq!(sub["context_window"].as_integer(), Some(1000), "other fields still merge");
            assert_eq!(
                providers["gw"]["base_url"].as_str(),
                Some("https://api.fluxrouter.ai/v1"),
                "a provider a user subscription model routes through keeps the user's URL"
            );
            assert!(p192_model(&merged, "borrow").unwrap().get("model_provider").is_none());
            assert_eq!(
                p192_model(&merged, "work").unwrap()["model_provider"].as_str(),
                Some("sub")
            );
        }
    }

    /// P192: the user's own subscription model and provider stay exactly as the user wrote them:
    /// no other layer changes the (wire id, endpoint) pair, the provider reference, or the
    /// provider table, nor points another model at the user's subscription provider. Other
    /// fields and non-vendor models still merge as before.
    #[test]
    fn p192_user_subscription_model_keeps_its_own_pair_and_provider() {
        let user = "[auth_provider.mine]\nsubscription = \"xai\"\n\n[model.sub]\nmodel = \"grok-4.7\"\nbase_url = \"https://api.fluxrouter.ai/v1\"\nauth_provider = \"mine\"\n\n[model.bare]\nmodel = \"grok-4.7\"\nbase_url = \"https://api.x.ai/v1\"\n";
        let req = "[auth_provider.mine]\ncommand = \"/bin/echo\"\n\n[model.sub]\nmodel = \"other\"\nauth_provider = \"corp\"\ncontext_window = 1000\n\n[model.bare]\nmodel = \"other\"\nbase_url = \"https://api.fluxrouter.ai/v1\"\n\n[model.corp]\nmodel = \"m\"\nbase_url = \"https://api.fluxrouter.ai/v1\"\nauth_provider = \"mine\"\n";
        let layers = ConfigLayers {
            user: p192_toml(user),
            user_requirements: Some(p192_toml(req)),
            ..Default::default()
        };
        let merged = layers.effective_config_disk_only();
        let sub = p192_model(&merged, "sub").unwrap();
        assert_eq!(sub["model"].as_str(), Some("grok-4.7"));
        assert_eq!(sub["auth_provider"].as_str(), Some("mine"));
        assert_eq!(
            sub["context_window"].as_integer(),
            Some(1000),
            "other fields still merge"
        );
        let bare = p192_model(&merged, "bare").unwrap();
        assert_eq!(bare["model"].as_str(), Some("grok-4.7"));
        assert_eq!(bare["base_url"].as_str(), Some("https://api.x.ai/v1"));
        assert!(merged["auth_provider"]["mine"].get("command").is_none());
        assert_eq!(
            merged["auth_provider"]["mine"]["subscription"].as_str(),
            Some("xai")
        );
        let corp = p192_model(&merged, "corp").unwrap();
        assert!(
            corp.get("auth_provider").is_none(),
            "only the user file points a model at a subscription"
        );
        assert_eq!(
            corp["base_url"].as_str(),
            Some("https://api.fluxrouter.ai/v1")
        );
    }

    #[test]
    fn effective_config_mdm_requirements_win_over_system_and_user() {
        // MDM is merged last, so an admin-forced value clamps the effective config over both the user config and the system requirements layer
        let layers = ConfigLayers {
            user: toml::from_str("[features]\nweb_fetch = true\n").unwrap(),
            system_requirements: Some(toml::from_str("[features]\nweb_fetch = true\n").unwrap()),
            mdm_requirements: Some(toml::from_str("[features]\nweb_fetch = false\n").unwrap()),
            ..Default::default()
        };
        assert_eq!(
            layers.effective_config_disk_only()["features"]["web_fetch"].as_bool(),
            Some(false),
        );
    }

    /// P183 round 4 (Grok M6): a higher requirements layer's wrong-type value does not erase a lower layer's typed pin.
    #[test]
    fn requirements_merge_keeps_lower_typed_pin_p183r4() {
        let layers = ConfigLayers {
            user: toml::from_str("[ui]\nyolo = true\n").unwrap(),
            system_requirements: Some(
                toml::from_str("[ui]\nyolo = false\n[features]\nweb_fetch = false\n").unwrap(),
            ),
            mdm_requirements: Some(
                toml::from_str("ui = \"x\"\n[features]\nweb_fetch = \"true\"\n").unwrap(),
            ),
            ..Default::default()
        };
        let eff = layers.effective_config_disk_only();
        assert_eq!(eff["ui"]["yolo"].as_bool(), Some(false));
        assert_eq!(eff["features"]["web_fetch"].as_bool(), Some(false));
        // A requirements pin still overrides the user's own config of another type
        let layers = ConfigLayers {
            user: toml::from_str("[features]\nweb_fetch = \"yes\"\n").unwrap(),
            system_requirements: Some(toml::from_str("[features]\nweb_fetch = false\n").unwrap()),
            ..Default::default()
        };
        assert_eq!(
            layers.effective_config_disk_only()["features"]["web_fetch"].as_bool(),
            Some(false)
        );
    }

    /// P183 round 5 (Grok r2 H1): a LOWER layer's wrong-type value must not block a typed higher pin.
    #[test]
    fn requirements_merge_higher_typed_pin_beats_lower_wrong_type_p183r5() {
        let layers = ConfigLayers {
            user_requirements: Some(
                toml::from_str("[auto_mode]\nenabled = \"yes\"\n[sandbox]\nprofile = 1\n").unwrap(),
            ),
            system_requirements: Some(
                toml::from_str("[auto_mode]\nenabled = false\n[sandbox]\nprofile = \"strict\"\n")
                    .unwrap(),
            ),
            ..Default::default()
        };
        let eff = layers.effective_config_disk_only();
        assert_eq!(eff["auto_mode"]["enabled"].as_bool(), Some(false));
        assert_eq!(eff["sandbox"]["profile"].as_str(), Some("strict"));
        // ...and a wrong-type MDM value still cannot erase the system's typed pin
        let layers = ConfigLayers {
            system_requirements: Some(toml::from_str("[sandbox]\nprofile = \"strict\"\n").unwrap()),
            mdm_requirements: Some(toml::from_str("[sandbox]\nprofile = 1\n").unwrap()),
            ..Default::default()
        };
        assert_eq!(
            layers.effective_config_disk_only()["sandbox"]["profile"].as_str(),
            Some("strict")
        );
    }

    /// `FUIGO_CAMPAIGNS=0` disables campaign application regardless of config.
    ///
    /// Through the pure core, not by writing `FUIGO_CAMPAIGNS`: the old version set the variable
    /// process-wide under a module-local mutex on the claim that no other test reads it, but every
    /// `effective_config_with_campaigns` test reads it, so `campaigns::tests::effective_config_
    /// honors_dismiss` saw the kill switch and its managed campaign never applied.
    #[test]
    fn kill_switch_env_var_disables() {
        let empty = toml::Value::Table(Default::default());
        assert!(campaigns_application_disabled_for(Some(false), &empty));
        assert!(!campaigns_application_disabled_for(None, &empty));
        assert!(!campaigns_application_disabled_for(Some(true), &empty));
        let feature_off: toml::Value = toml::from_str("[features]\ncampaigns = false\n").unwrap();
        assert!(campaigns_application_disabled_for(None, &feature_off));
        assert!(campaigns_application_disabled_for(Some(true), &feature_off));
    }

    #[test]
    fn env_overlay_precedence_and_overlay_free_merge() {
        let mut layers = ConfigLayers {
            user: toml::from_str("[models]\ndefault = \"user\"\n[telemetry]\nmode = \"on\"\n")
                .unwrap(),
            env_overlay: Some(
                toml::from_str(
                    "[models]\ndefault = \"overlay\"\ndefault_reasoning_effort = \"high\"\n",
                )
                .unwrap(),
            ),
            ..Default::default()
        };
        layers.campaigns.managed = vec![crate::campaigns::CampaignEntry {
            id: "c1".into(),
            patch: toml::from_str("[models]\ndefault = \"campaign\"\n").unwrap(),
        }];
        let none = std::collections::HashSet::new();

        let with_overlay: toml::Value = toml::from_str(
            "[models]\ndefault = \"overlay\"\ndefault_reasoning_effort = \"high\"\n\
             [telemetry]\nmode = \"on\"\n",
        )
        .unwrap();
        assert_eq!(
            layers.effective_config_with_campaigns(&[], &none),
            with_overlay
        );

        let overlay_free: toml::Value =
            toml::from_str("[models]\ndefault = \"user\"\n[telemetry]\nmode = \"on\"\n").unwrap();
        assert_eq!(layers.effective_config_base_without_overlay(), overlay_free);

        layers.user_requirements =
            Some(toml::from_str("[models]\ndefault = \"pinned\"\n").unwrap());
        let clamped: toml::Value = toml::from_str(
            "[models]\ndefault = \"pinned\"\ndefault_reasoning_effort = \"high\"\n\
             [telemetry]\nmode = \"on\"\n",
        )
        .unwrap();
        assert_eq!(layers.effective_config_with_campaigns(&[], &none), clamped);
    }


    /// P192 (Grok r3 LOW): every non-user layer that can reach a user subscription model.
    fn p192_requirement_layers(user: &str, req: &str) -> Vec<ConfigLayers> {
        vec![
            ConfigLayers {
                user: p192_toml(user),
                user_requirements: Some(p192_toml(req)),
                ..Default::default()
            },
            ConfigLayers {
                user: p192_toml(user),
                managed: p192_toml(req),
                ..Default::default()
            },
            ConfigLayers {
                user: p192_toml(user),
                mdm_requirements: Some(p192_toml(req)),
                ..Default::default()
            },
        ]
    }

    /// P192 (Grok r3 LOW): requirements cannot switch a user subscription model's wire protocol.
    #[test]
    fn p192_requirements_cannot_change_a_subscription_models_api_backend() {
        let user = "[model.mine]\nmodel = \"grok-4.7\"\nbase_url = \"https://api.x.ai/v1\"\napi_backend = \"chat_completions\"\n";
        let req = "[model.mine]\napi_backend = \"responses\"\n";
        for layers in p192_requirement_layers(user, req) {
            for merged in [layers.effective_config_base(), layers.effective_config_disk_only()] {
                assert_eq!(
                    p192_model(&merged, "mine").and_then(|m| m.get("api_backend")).and_then(|v| v.as_str()),
                    Some("chat_completions"),
                );
            }
        }
    }

    /// P192 (Grok r3 LOW): requirements cannot add query parameters to a user subscription model's requests.
    #[test]
    fn p192_requirements_cannot_change_a_subscription_models_query_params() {
        let user = "[model.mine]\nmodel = \"grok-4.7\"\nbase_url = \"https://api.x.ai/v1\"\n\n[model.mine.query_params]\nmine = \"1\"\n";
        let req = "[model.mine.query_params]\nplanted = \"1\"\n";
        for layers in p192_requirement_layers(user, req) {
            for merged in [layers.effective_config_base(), layers.effective_config_disk_only()] {
                let params = p192_model(&merged, "mine").and_then(|m| m.get("query_params"));
                assert_eq!(params.and_then(|p| p.get("mine")).and_then(|v| v.as_str()), Some("1"));
                assert!(params.and_then(|p| p.get("planted")).is_none(), "{params:?}");
            }
        }
    }

    /// P192 (Grok r3 LOW): the same two keys on a user subscription provider.
    #[test]
    fn p192_requirements_cannot_change_a_subscription_providers_backend_or_query_params() {
        let user = "[model_providers.sub]\nbase_url = \"https://api.x.ai/v1\"\napi_backend = \"chat_completions\"\n\n[model_providers.sub.query_params]\nmine = \"1\"\n\n[model.work]\nmodel = \"grok-4.7\"\nmodel_provider = \"sub\"\n";
        let req = "[model_providers.sub]\napi_backend = \"responses\"\n\n[model_providers.sub.query_params]\nplanted = \"1\"\n";
        for layers in p192_requirement_layers(user, req) {
            for merged in [layers.effective_config_base(), layers.effective_config_disk_only()] {
                let sub = &merged["model_providers"]["sub"];
                assert_eq!(sub.get("api_backend").and_then(|v| v.as_str()), Some("chat_completions"));
                assert!(sub["query_params"].get("planted").is_none(), "{sub:?}");
                assert_eq!(sub["query_params"]["mine"].as_str(), Some("1"));
            }
        }
    }
}
