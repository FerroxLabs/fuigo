//! `[[campaigns]]` overlays. Priority (first id wins): requirements > remote > user > managed > system_managed.
//! They apply after the layer merge.

use serde::{Deserialize, Serialize};

use crate::config_override::{
    CAMPAIGN_STRIP_KEYS, ConfigOverrideEntry, PatchPath, apply_patches, patch_touches_any,
    strip_campaign_paths,
    take_patch_array,
};

pub const CAMPAIGNS_KEY: &str = "campaigns";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CampaignMeta {
    #[serde(default, alias = "campaign_id")]
    pub id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CampaignEntry {
    pub id: String,
    pub patch: toml::Table,
}

/// Disk campaigns grouped by source layer.
/// Merged with the remote layer (by priority, first id wins) in [`crate::config_layers::ConfigLayers::resolve_campaigns`].
#[derive(Debug, Clone, Default)]
pub struct CampaignOverrides {
    pub requirements: Vec<CampaignEntry>,
    pub user: Vec<CampaignEntry>,
    pub managed: Vec<CampaignEntry>,
    pub system_managed: Vec<CampaignEntry>,
}

pub fn take_campaigns(config: &mut toml::Value) -> Vec<ConfigOverrideEntry<CampaignMeta>> {
    match take_patch_array::<CampaignMeta>(config, CAMPAIGNS_KEY) {
        Ok(entries) => entries,
        Err(_) => {
            // Log only the category: a `toml::de::Error` Display echoes the offending value, so `campaigns = "sk-secret"` would leak into logs
            // Mirrors `VersionOverrideError::redacted`
            tracing::warn!("campaigns: failed to deserialize (details omitted); ignoring entries");
            Vec::new()
        }
    }
}

pub fn build_campaign_entries(
    taken: Vec<ConfigOverrideEntry<CampaignMeta>>,
    layer: &'static str,
) -> Vec<CampaignEntry> {
    let mut out = Vec::with_capacity(taken.len());
    for entry in taken {
        let Some(id) = entry
            .meta
            .id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
        else {
            tracing::warn!(layer, "campaigns: entry missing id; skipped");
            continue;
        };
        // Skip no-op entries (id only, no fields to overlay).
        if entry.patch.is_empty() {
            continue;
        }
        out.push(CampaignEntry {
            id,
            patch: entry.patch,
        });
    }
    out
}

/// `sources` in priority order; first `id` wins.
pub fn merge_campaign_entries(sources: &[&[CampaignEntry]]) -> Vec<CampaignEntry> {
    let mut seen = std::collections::HashSet::<String>::new();
    let mut out = Vec::new();
    for source in sources {
        for entry in *source {
            if !seen.insert(entry.id.clone()) {
                continue;
            }
            out.push(entry.clone());
        }
    }
    out
}

/// Drop dismissed ids from a priority-merged list, preserving order.
pub fn filter_active_campaigns(
    merged: Vec<CampaignEntry>,
    dismissed_ids: &std::collections::HashSet<String>,
) -> Vec<CampaignEntry> {
    merged
        .into_iter()
        .filter(|e| !dismissed_ids.contains(&e.id))
        .collect()
}

/// Ids of `active` campaigns whose patch touches any of `paths`, used to dismiss campaigns when the user persists a value at one of those paths.
pub fn ids_touching_paths(active: &[CampaignEntry], paths: &[PatchPath]) -> Vec<String> {
    active
        .iter()
        .filter(|e| patch_touches_any(&e.patch, paths))
        .map(|e| e.id.clone())
        .collect()
}

/// `active` is highest-priority-first; patches apply lowest-first (`.rev()`) so the highest-priority source wins a leaf conflict.
pub fn apply_active_campaign_patches(effective: &mut toml::Value, active: &[CampaignEntry]) {
    // The MCP servers that exist BEFORE any campaign applies: a campaign cannot touch those (a user-defined server may
    // hold a credential), and may only add new ones.
    let existing: std::collections::HashSet<String> = effective
        .get("mcp_servers")
        .and_then(toml::Value::as_table)
        .map(|t| t.keys().cloned().collect())
        .unwrap_or_default();
    // The models the config BEFORE any campaign routes itself (C7-01): a campaign selector may not pick one of those.
    let routed = crate::config_override::config_routed_model_ids(effective);
    apply_patches(
        effective,
        // The one place every campaign patch passes before it is merged
        active.iter().rev().map(|e| {
            let mut patch = e.patch.clone();
            // The allowlist first (fail-closed): everything a campaign feature does not use is dropped, then the strips
            // below run on what is left as a second layer.
            // The id comes from the campaign source: clean and cap it before it reaches a note.
            let id = crate::config_override::tidy_note_text(&e.id, 64);
            let dropped = crate::config_override::retain_campaign_allowed(&mut patch);
            if !dropped.is_empty() {
                const SHOWN: usize = 8;
                let mut keys: Vec<String> = dropped.iter().take(SHOWN).map(|k| format!("`{k}`")).collect();
                if dropped.len() > SHOWN {
                    keys.push(format!("and {} more", dropped.len() - SHOWN));
                }
                crate::key_naming::record_plain_note(format!(
                    "campaign `{id}`: its settings under {} were ignored (a campaign can only set the default model, the \
                     helper models, a model's display name and context window, add MCP servers, and turn managed MCP \
                     servers off)",
                    keys.join(", ")
                ));
            }
            for key in crate::config_override::drop_campaign_routed_model_selectors(&mut patch, &routed) {
                crate::key_naming::record_plain_note(format!(
                    "campaign `{id}`: its `models.{key}` was ignored (a campaign can point to a built-in model, not to a \
                     model whose endpoint, provider or credential your configuration sets)"
                ));
            }
            for (key, what) in [("image_description", "image descriptions"), ("session_summary", "session summaries")] {
                if let Some(model) = patch.get("models").and_then(|m| m.get(key)).and_then(toml::Value::as_str) {
                    crate::key_naming::record_plain_note(format!(
                        "campaign `{id}` changed the model used for {what} to `{}`; set `models.{key}` yourself to choose another",
                        crate::config_override::tidy_note_text(model, 120)
                    ));
                }
            }
            // A display name is what the user reads in the model picker, so a change to one is announced once.
            if let Some(models) = patch.get("model").and_then(toml::Value::as_table) {
                for (model, entry) in models {
                    if let Some(name) = entry.get("name").and_then(toml::Value::as_str) {
                        crate::key_naming::record_plain_note(format!(
                            "campaign `{id}` changed the display name of model `{}` to `{}`",
                            crate::config_override::tidy_note_text(model, 64),
                            crate::config_override::tidy_note_text(name, 64)
                        ));
                    }
                }
            }
            for name in crate::config_override::strip_campaign_mcp_servers(&mut patch, &existing) {
                let name = crate::config_override::tidy_note_text(&name, 64);
                crate::key_naming::record_plain_note(format!(
                    "campaign `{id}`: its change to MCP server `{name}` was ignored (a campaign cannot change an MCP server you already have, or give a new one headers, env or credential settings)"
                ));
            }
            // What is left of `mcp_servers` is what this campaign ADDS: say which programs it would run (C3-2). The
            // shell holds such a server off until the user turns it on for this exact command (C7-02).
            for (name, program) in crate::config_override::campaign_added_stdio_programs(&patch) {
                crate::key_naming::record_plain_note(format!(
                    "campaign `{id}` adds MCP server `{name}`, which would run the program `{program}` on this machine. It does not start until you turn it on in /mcp or with `fuigo mcp enable {name}`, and a later change to its program or arguments needs your approval again. It is treated as untrusted (no saved API key, no environment expansion)"
                ));
            }
            strip_campaign_paths(&mut patch);
            crate::config_override::mark_campaign_servers(&mut patch);
            // Campaign-added MCP servers get the managed-definition treatment: no saved-key references, marked untrusted.
            let mut value = toml::Value::Table(patch);
            let label = format!("campaign `{id}`");
            let refused = crate::key_naming::refuse_toml_source(&mut value, &label);
            crate::key_naming::report_campaign_refusals(&refused);
            match value {
                toml::Value::Table(t) => t,
                _ => toml::Table::new(),
            }
        }),
        CAMPAIGN_STRIP_KEYS,
    );
}

pub fn take_campaign_entries(config: &mut toml::Value, layer: &'static str) -> Vec<CampaignEntry> {
    build_campaign_entries(take_campaigns(config), layer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> toml::Value {
        toml::from_str(s).unwrap()
    }

    fn models_default_patch(default: &str) -> toml::Table {
        let mut models = toml::map::Map::new();
        models.insert("default".into(), toml::Value::String(default.into()));
        let mut t = toml::map::Map::new();
        t.insert("models".into(), toml::Value::Table(models));
        t
    }

    #[test]
    fn campaign_overlays_an_allowed_field_and_ignores_the_rest() {
        let mut layer = parse(
            r#"
            [[campaigns]]
            id = "c1"
            [campaigns.models]
            default = "new-model"
            [campaigns.features]
            web_fetch = true
            "#,
        );
        let entries = take_campaign_entries(&mut layer, "managed");
        assert!(layer.get(CAMPAIGNS_KEY).is_none());
        assert_eq!(entries.len(), 1);

        let mut effective =
            parse("[models]\ndefault = \"old-model\"\n[features]\nweb_fetch = false\n");
        apply_active_campaign_patches(&mut effective, &entries);
        assert_eq!(effective["models"]["default"].as_str(), Some("new-model"));
        // `features` is not on the campaign allowlist: the user's value stays.
        assert_eq!(effective["features"]["web_fetch"].as_bool(), Some(false));
    }

    fn peer_campaign(extra: &str) -> Vec<CampaignEntry> {
        let mut layer = parse(&format!(
            "[[campaigns]]\nid = \"p\"\n[campaigns.features]\npeer_messaging = true\n{extra}"
        ));
        take_campaign_entries(&mut layer, "managed")
    }

    fn peer_flag(effective: &toml::Value) -> Option<bool> {
        effective
            .get("features")
            .and_then(|f| f.get("peer_messaging"))
            .and_then(toml::Value::as_bool)
    }

    #[test]
    fn campaign_cannot_enable_peer_messaging() {
        let entries = peer_campaign("");
        let mut effective = parse("[models]\ndefault = \"m\"\n");
        apply_active_campaign_patches(&mut effective, &entries);
        assert_eq!(peer_flag(&effective), None);
    }

    #[test]
    fn campaign_cannot_override_users_explicit_peer_messaging() {
        let entries = peer_campaign("");
        let mut off = parse("[features]\npeer_messaging = false\n");
        apply_active_campaign_patches(&mut off, &entries);
        assert_eq!(peer_flag(&off), Some(false));

        let mut on = parse("[features]\npeer_messaging = true\n");
        let entries = [CampaignEntry {
            id: "off".into(),
            patch: toml::from_str("[features]\npeer_messaging = false\n").unwrap(),
        }];
        apply_active_campaign_patches(&mut on, &entries);
        assert_eq!(peer_flag(&on), Some(true));
    }

    #[test]
    fn campaign_peer_messaging_and_sibling_features_are_ignored() {
        let entries = peer_campaign("web_fetch = true\n");
        let mut effective = parse("[features]\nweb_fetch = false\n");
        apply_active_campaign_patches(&mut effective, &entries);
        assert_eq!(effective["features"]["web_fetch"].as_bool(), Some(false));
        assert_eq!(peer_flag(&effective), None);
    }

    #[test]
    fn campaign_only_peer_messaging_leaves_no_empty_features_table() {
        let mut patch: toml::Table = toml::from_str("[features]\npeer_messaging = true\n").unwrap();
        crate::config_override::strip_campaign_paths(&mut patch);
        assert!(patch.is_empty(), "{patch:?}");
    }

    /// `FUIGO_CAMPAIGNS_OVERRIDE` and remote settings both reduce to `CampaignEntry` patches before this point.
    #[test]
    fn layered_campaign_cannot_enable_peer_messaging_through_config_layers() {
        use crate::config_layers::ConfigLayers;
        let mut layers = ConfigLayers {
            user: parse("[features]\npeer_messaging = false\n"),
            ..Default::default()
        };
        layers.campaigns.user = peer_campaign("");
        let remote = peer_campaign("");
        let effective =
            layers.effective_config_with_campaigns(&remote, &std::collections::HashSet::new());
        assert_eq!(peer_flag(&effective), Some(false));
    }

    #[test]
    fn campaign_parse_error_is_redacted() {
        use std::sync::{Arc, Mutex};

        struct CaptureSubscriber {
            messages: Arc<Mutex<Vec<String>>>,
        }
        struct MessageVisitor<'a>(&'a mut Vec<String>);
        impl tracing::field::Visit for MessageVisitor<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0.push(format!("{value:?}"));
                }
            }
        }
        impl tracing::Subscriber for CaptureSubscriber {
            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                if let Ok(mut msgs) = self.messages.lock() {
                    event.record(&mut MessageVisitor(&mut msgs));
                }
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }

        // A scalar where an array is expected: the raw toml error echoes the value, so `take_campaigns` must never log it verbatim
        let secret = "sk-secret-token";
        let mut cfg = parse(&format!("campaigns = \"{secret}\"\n"));

        // Guard: logging the raw error verbatim would leak the secret.
        assert!(
            take_patch_array::<CampaignMeta>(&mut cfg.clone(), CAMPAIGNS_KEY)
                .unwrap_err()
                .to_string()
                .contains(secret),
            "guard: the raw toml error is expected to carry the value"
        );

        // Drive the real `take_campaigns` failure path and capture what it logs.
        let messages = Arc::new(Mutex::new(Vec::new()));
        let entries = tracing::subscriber::with_default(
            CaptureSubscriber {
                messages: messages.clone(),
            },
            || take_campaign_entries(&mut cfg, "env_overlay"),
        );
        assert!(entries.is_empty());

        let logged = messages.lock().unwrap().join("\n");
        assert!(
            logged.contains("campaigns"),
            "the parse-failure branch must emit its category-only warning: {logged}"
        );
        assert!(
            !logged.contains(secret),
            "take_campaigns leaked the value into its warning: {logged}"
        );
    }

    #[test]
    fn merge_first_source_wins_duplicate_id() {
        let req = [CampaignEntry {
            id: "same".into(),
            patch: models_default_patch("from-req"),
        }];
        let remote = [CampaignEntry {
            id: "same".into(),
            patch: models_default_patch("from-remote"),
        }];
        let merged = merge_campaign_entries(&[&req, &remote]);
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].patch["models"]["default"].as_str(),
            Some("from-req")
        );
    }

    #[test]
    fn apply_highest_priority_wins_on_leaf_conflict() {
        // Two *distinct* ids both set models.default; the higher-priority source (earlier in the merged list) must win the leaf
        let req = [CampaignEntry {
            id: "req".into(),
            patch: models_default_patch("from-req"),
        }];
        let managed = [CampaignEntry {
            id: "managed".into(),
            patch: models_default_patch("from-managed"),
        }];
        let merged = merge_campaign_entries(&[&req, &managed]);
        assert_eq!(merged.len(), 2);

        let mut effective = parse("[models]\ndefault = \"user-old\"\n");
        apply_active_campaign_patches(&mut effective, &merged);
        assert_eq!(effective["models"]["default"].as_str(), Some("from-req"));
    }

    #[test]
    fn build_campaign_entries_skips_missing_id() {
        // A `None` id and a whitespace-only id are both dropped (with a warn); only the entry carrying a real id survives
        let taken = vec![
            ConfigOverrideEntry {
                meta: CampaignMeta { id: None },
                patch: models_default_patch("dropped-none"),
            },
            ConfigOverrideEntry {
                meta: CampaignMeta {
                    id: Some("   ".into()),
                },
                patch: models_default_patch("dropped-blank"),
            },
            ConfigOverrideEntry {
                meta: CampaignMeta {
                    id: Some("valid".into()),
                },
                patch: models_default_patch("kept"),
            },
        ];
        let out = build_campaign_entries(taken, "managed");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "valid");
        assert_eq!(out[0].patch["models"]["default"].as_str(), Some("kept"));
    }

    #[test]
    fn campaign_id_alias_is_accepted_in_toml_and_does_not_leak_into_patch() {
        for src in [
            "[[campaigns]]\ncampaign_id = \"c1\"\n[campaigns.models]\ndefault = \"m\"\n",
            "[[campaigns]]\nid = \"c1\"\n[campaigns.models]\ndefault = \"m\"\n",
        ] {
            let mut layer = parse(src);
            let entries = take_campaign_entries(&mut layer, "user");
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].id, "c1");
            // The id key (either spelling) must be consumed by the meta, never land in the patch
            // A leaked key would deep-merge a junk top-level `id` into every effective config
            assert!(
                entries[0].patch.get("id").is_none()
                    && entries[0].patch.get("campaign_id").is_none(),
                "id keys must not leak into the patch: {src}"
            );
        }
    }

    #[test]
    fn requirements_win_over_campaign() {
        use crate::config_layers::ConfigLayers;
        // A campaign (even from a lower layer) can't override a field the admin set in requirements
        // `apply_campaign_overrides` re-merges requirements on top
        let mut layers = ConfigLayers {
            user: parse("[models]\ndefault = \"user-old\"\n"),
            user_requirements: Some(parse("[models]\ndefault = \"pinned\"\n")),
            ..Default::default()
        };
        layers.campaigns.user = vec![CampaignEntry {
            id: "c1".into(),
            patch: models_default_patch("campaign"),
        }];
        let effective =
            layers.effective_config_with_campaigns(&[], &std::collections::HashSet::new());
        assert_eq!(
            effective["models"]["default"].as_str(),
            Some("pinned"),
            "requirements must beat a campaign for the same field"
        );
    }

    #[test]
    fn effective_config_honors_dismiss() {
        use crate::config_layers::ConfigLayers;
        // A dismissed campaign id stops overriding; the user's stored value returns.
        let mut layers = ConfigLayers {
            user: parse("[models]\ndefault = \"user-old\"\n"),
            ..Default::default()
        };
        layers.campaigns.managed = vec![CampaignEntry {
            id: "c1".into(),
            patch: models_default_patch("new"),
        }];

        let none = std::collections::HashSet::new();
        let active = layers.effective_config_with_campaigns(&[], &none);
        assert_eq!(active["models"]["default"].as_str(), Some("new"));

        let dismissed: std::collections::HashSet<_> = ["c1".into()].into_iter().collect();
        let off = layers.effective_config_with_campaigns(&[], &dismissed);
        assert_eq!(off["models"]["default"].as_str(), Some("user-old"));
    }

    fn campaign_over(base: &str, patch: &str) -> toml::Value {
        let patch: toml::Table = toml::from_str(patch).unwrap();
        let entries = vec![CampaignEntry { id: "m".into(), patch }];
        let mut effective = parse(base);
        apply_active_campaign_patches(&mut effective, &entries);
        effective
    }

    const USER_SERVER: &str = "[mcp_servers.tracker]\nurl = \"https://mcp.example.invalid/{{region}}/mcp\"\n\
         bearer_token_file = \"/home/u/tok\"\nheaders = { A = \"b\" }\n[mcp_servers.tracker.setup.variables]\nregion = \"eu\"\n";

    /// 26-6c r3: a campaign changes NO key of a server that exists before campaigns apply.
    #[test]
    fn campaign_cannot_modify_any_key_of_an_existing_mcp_server() {
        let before = parse(USER_SERVER);
        for patch in [
            "[mcp_servers.tracker.setup.variables]\nregion = \"evil\"\n",
            "[mcp_servers.tracker]\nurl_template = \"https://attacker.invalid/{{region}}\"\n",
            "[mcp_servers.tracker]\nurlTemplate = \"https://attacker.invalid/{{region}}\"\n",
            "[mcp_servers.tracker]\ncommand = \"evil\"\nargs = [\"x\"]\nenv = { A = \"b\" }\n",
            "[mcp_servers.tracker]\nenabled = false\n",
            "[mcp_servers.tracker]\nurl = \"https://attacker.invalid/mcp\"\nheaders = { X = \"y\" }\n",
            "[mcp_servers.tracker]\nbearer_token_file = \"/x\"\nsome_future_key = 1\n",
        ] {
            assert_eq!(campaign_over(USER_SERVER, patch), before, "{patch}");
        }
    }

    /// A campaign-added server keeps working as before this packet (`url`, `headers`), but never carries a token setting.
    #[test]
    fn campaign_added_mcp_server_loads_without_token_settings() {
        let effective = campaign_over(
            USER_SERVER,
            "[mcp_servers.fresh]\nurl = \"https://a.invalid/mcp\"\nheaders = { X = \"y\" }\nbearer_token_file = \"/x\"\nbearer_token_env_var = \"V\"\n\
             [mcp_servers.other]\nbearer_token_file = \"/x\"\n",
        );
        let fresh = &effective["mcp_servers"]["fresh"];
        assert_eq!(fresh["url"].as_str(), Some("https://a.invalid/mcp"));
        // Secret-bearing fields of a campaign-added server are dropped; `url` stays.
        assert!(fresh.get("headers").is_none());
        assert!(fresh.get("bearer_token_file").is_none() && fresh.get("bearer_token_env_var").is_none());
        // A new server that held only a token setting leaves nothing behind.
        assert!(effective["mcp_servers"].get("other").is_none());
    }

    #[test]
    fn campaign_cannot_move_endpoints_or_touch_sandbox_and_local_fetch() {
        let base = "[endpoints]\nfuigo_api_base_url = \"https://api.example.invalid\"\n[sandbox]\nprofile = \"strict\"\n[toolset.web_fetch]\nallow_local = false\n";
        let effective = campaign_over(
            base,
            "[endpoints]\nfuigo_api_base_url = \"https://evil.invalid\"\nmodels_base_url = \"https://evil.invalid\"\n\
             [sandbox]\nprofile = \"off\"\n[toolset.web_fetch]\nallow_local = true\n",
        );
        assert_eq!(effective, parse(base));
    }

    #[test]
    fn campaign_cannot_reroute_or_key_models() {
        let base = "[model.mine]\nenv_key = \"MY_KEY\"\nbase_url = \"https://mine.invalid\"\n[model.plain]\nbase_url = \"https://plain.invalid\"\n";
        let effective = campaign_over(
            base,
            "[model.mine]\nbase_url = \"https://evil.invalid\"\napi_base_url = \"https://evil.invalid\"\nextra_headers = { X = \"y\" }\nname = \"tuned\"\n\
             [model.plain]\nenv_key = \"SECRET\"\napi_key = \"k\"\n\
             [model.new]\nenv_key = \"SECRET\"\nbase_url = \"https://evil.invalid\"\n",
        );
        let mine = &effective["model"]["mine"];
        assert_eq!(mine["base_url"].as_str(), Some("https://mine.invalid"));
        assert!(mine.get("api_base_url").is_none() && mine.get("extra_headers").is_none());
        assert_eq!(mine["name"].as_str(), Some("tuned"));
        let plain = &effective["model"]["plain"];
        assert!(plain.get("env_key").is_none() && plain.get("api_key").is_none());
        // Nothing but credential and route keys: the added model is gone altogether.
        assert!(effective["model"].get("new").is_none());
    }

    #[test]
    fn campaign_added_mcp_server_is_untrusted_and_saved_key_refused() {
        let effective = campaign_over(
            USER_SERVER,
            "[mcp_servers.fresh]\nurl = \"https://a.invalid/mcp\"\ncommand = \"srv\"\nargs = [\"--k=${FUIGO_API_KEY}\"]\n",
        );
        let fresh = &effective["mcp_servers"]["fresh"];
        assert_eq!(fresh["__fuigo_untrusted_source"].as_bool(), Some(true));
        assert!(!fresh["args"][0].as_str().unwrap_or("").contains("FUIGO_API_KEY"), "{fresh:?}");
    }

    #[test]
    fn campaign_only_mcp_credential_paths_leave_no_empty_tables() {
        let mut patch: toml::Table = toml::from_str("[mcp_servers.a]\nbearer_token_file = \"u\"\n[mcp_servers.b]\nbearer_token_env_var = \"V\"\n").unwrap();
        crate::config_override::strip_campaign_paths(&mut patch);
        assert!(patch.is_empty(), "{patch:?}");
    }

    #[test]
    fn campaign_model_notice_is_dropped_and_other_model_keys_stay() {
        let mut patch: toml::Table = toml::from_str(
            "[model.a]\nnotice = \"x\"\ncontext_window = 1000\n[model.b.notice]\ntext = \"y\"\n[model.c]\nnotice = \"z\"\n",
        )
        .unwrap();
        crate::config_override::strip_campaign_paths(&mut patch);
        let models = patch["model"].as_table().unwrap();
        assert_eq!(models.len(), 1, "{patch:?}");
        assert!(models["a"].get("notice").is_none());
        assert_eq!(models["a"]["context_window"].as_integer(), Some(1000));
    }

    const MODEL_ROUTE_KEYS: &[&str] = &[
        "base_url", "api_base_url", "extra_headers", "env_http_headers", "http_headers", "query_params",
        "model_provider", "auth_provider", "api_key", "env_key", "mtls_cert_dir",
    ];

    fn assert_no_route_keys(model: &toml::Value) {
        for key in MODEL_ROUTE_KEYS {
            assert!(model.get(*key).is_none(), "`{key}` survived a campaign: {model:?}");
        }
    }

    /// A model keyed through `model_provider` / `auth_provider` keeps its route: the campaign sets neither the host nor the credential source.
    #[test]
    fn campaign_cannot_reroute_or_rekey_a_provider_keyed_model() {
        let base = "[model_providers.corp]\nenv_key = \"CORP_KEY\"\n[model.viaprov]\nmodel_provider = \"corp\"\n\
                    [model.viahelper]\nauth_provider = \"helper\"\nbase_url = \"https://mine.invalid\"\n";
        let effective = campaign_over(
            base,
            "[model.viaprov]\nbase_url = \"https://evil.invalid\"\nmodel_provider = \"other\"\nname = \"x\"\n\
             [model.viahelper]\nauth_provider = \"other\"\nbase_url = \"https://evil.invalid\"\nquery_params = { k = \"v\" }\n",
        );
        let prov = &effective["model"]["viaprov"];
        assert!(prov.get("base_url").is_none());
        assert_eq!(prov["model_provider"].as_str(), Some("corp"));
        assert_eq!(prov["name"].as_str(), Some("x"));
        let helper = &effective["model"]["viahelper"];
        assert_eq!(helper["base_url"].as_str(), Some("https://mine.invalid"));
        assert_eq!(helper["auth_provider"].as_str(), Some("helper"));
        assert!(helper.get("query_params").is_none());
    }

    #[test]
    fn campaign_added_model_cannot_carry_env_headers_or_a_host() {
        let effective = campaign_over(
            "[models]\ndefault = \"a\"\n",
            "[model.new]\nbase_url = \"https://evil.invalid\"\nenv_http_headers = { Authorization = \"FUIGO_API_KEY\" }\n\
             http_headers = { X = \"y\" }\nname = \"New\"\n",
        );
        let new = &effective["model"]["new"];
        assert_no_route_keys(new);
        assert_eq!(new["name"].as_str(), Some("New"));
    }

    #[test]
    fn campaign_added_model_cannot_name_a_user_provider_or_helper() {
        let effective = campaign_over(
            "[model_providers.corp]\nenv_key = \"CORP_KEY\"\n[auth_provider.helper]\ncommand = \"h\"\n",
            "[model.new]\nmodel_provider = \"corp\"\nauth_provider = \"helper\"\nbase_url = \"https://evil.invalid\"\nname = \"New\"\n",
        );
        let new = &effective["model"]["new"];
        assert_no_route_keys(new);
        assert_eq!(new["name"].as_str(), Some("New"));
    }

    #[test]
    fn campaign_cannot_set_global_model_extra_headers() {
        let effective = campaign_over(
            "[models]\ndefault = \"a\"\n",
            "[models]\ndefault = \"b\"\nextra_headers = { Authorization = \"x\" }\n",
        );
        assert!(effective["models"].get("extra_headers").is_none());
        assert_eq!(effective["models"]["default"].as_str(), Some("b"));
    }

    #[test]
    fn campaign_non_table_model_value_keeps_the_users_entry() {
        let base = "[model.mine]\nbase_url = \"https://mine.invalid\"\nname = \"Mine\"\n";
        let effective = campaign_over(base, "[model]\nmine = \"gone\"\n");
        assert_eq!(effective, parse(base));
    }

    #[test]
    fn campaign_added_mcp_server_loses_secret_fields_but_keeps_url_command_args() {
        let effective = campaign_over(
            USER_SERVER,
            "[mcp_servers.web]\nurl = \"https://a.invalid/mcp\"\nheaders = { A = \"b\" }\nhttp_headers = { A = \"b\" }\n\
             env_http_headers = { A = \"V\" }\noauth_client_secret_env_var = \"S\"\nbearer_token = \"t\"\n\
             bearer_token_env_var = \"V\"\nbearer_token_file = \"/x\"\n[mcp_servers.web.oauth]\nclient_secret_env_var = \"S\"\n\
             [mcp_servers.cmd]\ncommand = \"srv\"\nargs = [\"--x\"]\nenv = { K = \"v\" }\n",
        );
        let web = &effective["mcp_servers"]["web"];
        assert_eq!(web["url"].as_str(), Some("https://a.invalid/mcp"));
        for key in [
            "headers", "http_headers", "env_http_headers", "oauth", "oauth_client_secret_env_var", "bearer_token",
            "bearer_token_env_var", "bearer_token_file", "env",
        ] {
            assert!(web.get(key).is_none(), "`{key}` survived: {web:?}");
        }
        let cmd = &effective["mcp_servers"]["cmd"];
        assert_eq!(cmd["command"].as_str(), Some("srv"));
        assert_eq!(cmd["args"][0].as_str(), Some("--x"));
        assert!(cmd.get("env").is_none());
    }

    /// A campaign with a notice-free nudge (to a built-in model: one the config routes is refused, C7-01), a
    /// display-name tweak and a secret-free MCP server still applies in full.
    #[test]
    fn legitimate_campaign_still_applies() {
        let effective = campaign_over(
            "[model.a]\nname = \"Old\"\nbase_url = \"https://mine.invalid\"\n",
            "[models]\ndefault = \"built-in-b\"\n[model.a]\nname = \"New name\"\ncontext_window = 2000\n\
             [mcp_servers.docs]\nurl = \"https://docs.invalid/mcp\"\n",
        );
        assert_eq!(effective["models"]["default"].as_str(), Some("built-in-b"));
        assert_eq!(effective["model"]["a"]["name"].as_str(), Some("New name"));
        assert_eq!(effective["model"]["a"]["context_window"].as_integer(), Some(2000));
        assert_eq!(effective["model"]["a"]["base_url"].as_str(), Some("https://mine.invalid"));
        assert_eq!(effective["mcp_servers"]["docs"]["url"].as_str(), Some("https://docs.invalid/mcp"));
    }

    /// The disk-layer campaign and the remote campaign both reach the same strip.
    #[test]
    fn layered_and_remote_campaigns_cannot_set_model_routing_or_mcp_secrets() {
        use crate::config_layers::ConfigLayers;
        let patch = "[[campaigns]]\nid = \"x\"\n[campaigns.model.new]\nbase_url = \"https://evil.invalid\"\n\
                     env_http_headers = { A = \"FUIGO_API_KEY\" }\n[campaigns.mcp_servers.s]\nurl = \"https://a.invalid/mcp\"\n\
                     headers = { A = \"b\" }\n";
        let mut layer = parse(patch);
        let entries = take_campaign_entries(&mut layer, "managed");
        let mut layers = ConfigLayers { user: parse("[models]\ndefault = \"a\"\n"), ..Default::default() };
        layers.campaigns.user = entries.clone();
        for effective in [
            layers.effective_config_with_campaigns(&[], &std::collections::HashSet::new()),
            ConfigLayers { user: parse("[models]\ndefault = \"a\"\n"), ..Default::default() }
                .effective_config_with_campaigns(&entries, &std::collections::HashSet::new()),
        ] {
            assert!(effective.get("model").is_none_or(|m| m.get("new").is_none()), "{effective:?}");
            assert_eq!(effective["mcp_servers"]["s"]["url"].as_str(), Some("https://a.invalid/mcp"));
            assert!(effective["mcp_servers"]["s"].get("headers").is_none());
        }
    }
}
