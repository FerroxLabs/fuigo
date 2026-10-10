//! P169: managed policy features in the shell. S16 (`requirements.toml` `[models] allowed_models`), the S15 inspect and
//! `mcp doctor` policy rows, and the S11 inspect row. Ported/adapted from upstream 72a61251
//! (`agent/models/tests.rs` fleet-pin cases, `inspect` policy rows, `mcp_doctor` rows).

use std::path::{Path, PathBuf};

use crate::agent::config::{AllowlistPin, Config};
use crate::agent::models::{
    allowlist_denied_message, allowlist_excludes_all_message, allowlist_matches_nothing,
    effective_allowlist, resolve_model_catalog, validate_selectable,
};
use crate::config::RequirementSource;

fn config_from_toml(toml: &str) -> Config {
    Config::new_from_toml_cfg(&toml::from_str(toml).unwrap()).unwrap()
}

const TWO_MODELS: &str = r#"
[models]
default = "beta-1"
allowed_models = ["beta-*"]
[model.alpha-1]
model = "alpha-1"
base_url = "https://api.example.com/v1"
context_window = 256000
[model.beta-1]
model = "beta-1"
base_url = "https://api.example.com/v1"
context_window = 256000
"#;

fn pin(cfg: &mut Config, value: AllowlistPin) {
    cfg.requirements.allowed_models.pin(
        value,
        RequirementSource::Requirements {
            path: PathBuf::from("/etc/fuigo/requirements.toml"),
        },
    );
}

fn selectable(cfg: &Config) -> Vec<String> {
    resolve_model_catalog(cfg, None)
        .into_iter()
        .filter(|(_, e)| e.info.user_selectable)
        .map(|(k, _)| k)
        .collect()
}

/// The fleet pin REPLACES the user list: a user list can never widen it.
#[test]
fn fleet_pin_replaces_the_user_allowlist() {
    let mut cfg = config_from_toml(TWO_MODELS);
    assert_eq!(
        selectable(&cfg),
        vec!["beta-1".to_string()],
        "user list alone"
    );
    pin(&mut cfg, AllowlistPin::List(vec!["alpha-*".to_string()]));
    assert_eq!(
        selectable(&cfg),
        vec!["alpha-1".to_string()],
        "the pin wins over the user list"
    );
    assert!(effective_allowlist(&cfg).is_fleet());
    // The user's default (beta-1) is now outside the pinned list: the startup check refuses it, naming the policy.
    let catalog = resolve_model_catalog(&cfg, None);
    let err = validate_selectable(&cfg, &catalog).unwrap_err();
    assert!(
        err.contains("beta-1") && err.contains("organization's policy"),
        "{err}"
    );
}

/// A fleet pattern matches the model id only, so a user `[model.<key>]` named to match it cannot satisfy it.
#[test]
fn fleet_pin_matches_the_model_id_not_the_user_catalog_key() {
    let mut cfg = config_from_toml(
        r#"
[model.approved-alias]
model = "something-else"
base_url = "https://api.example.com/v1"
context_window = 256000
"#,
    );
    pin(&mut cfg, AllowlistPin::List(vec!["approved-*".to_string()]));
    assert!(selectable(&cfg).is_empty(), "{:?}", selectable(&cfg));
}

/// An unreadable pin fails closed: nothing is selectable, every choice is refused with the policy message.
#[test]
fn fail_closed_pin_selects_nothing() {
    let mut cfg = config_from_toml(TWO_MODELS);
    pin(&mut cfg, AllowlistPin::FailClosed);
    assert!(selectable(&cfg).is_empty());
    let catalog = resolve_model_catalog(&cfg, None);
    assert!(allowlist_matches_nothing(&cfg, &catalog));
    let err = validate_selectable(&cfg, &catalog).unwrap_err();
    assert!(
        err.contains("invalid or unreadable") && err.contains("/etc/fuigo/requirements.toml"),
        "{err}"
    );
    assert!(allowlist_excludes_all_message(&cfg).contains("organization model policy"));
    assert!(allowlist_denied_message(&cfg).contains("organization's policy"));
}

/// An empty pinned list means unrestricted (upstream semantics), and replaces the user list too.
#[test]
fn empty_pinned_list_is_unrestricted() {
    let mut cfg = config_from_toml(TWO_MODELS);
    pin(&mut cfg, AllowlistPin::List(vec![]));
    let catalog = resolve_model_catalog(&cfg, None);
    assert!(
        catalog.values().all(|e| e.info.user_selectable),
        "every model is selectable"
    );
    assert!(
        catalog.contains_key("alpha-1"),
        "the user's narrower list no longer applies"
    );
    assert!(effective_allowlist(&cfg).is_unrestricted());
}

/// The `-m` override outside the pinned list is refused at startup (the CLI `-m` path).
#[test]
fn cli_model_override_outside_the_pin_is_refused() {
    let mut cfg = config_from_toml(TWO_MODELS);
    pin(&mut cfg, AllowlistPin::List(vec!["beta-*".to_string()]));
    cfg.default_model_override = Some("alpha-1".to_string());
    let catalog = resolve_model_catalog(&cfg, None);
    let err = validate_selectable(&cfg, &catalog).unwrap_err();
    assert!(err.contains("alpha-1") && err.contains("-m flag"), "{err}");
    cfg.default_model_override = Some("beta-1".to_string());
    assert!(validate_selectable(&cfg, &catalog).is_ok());
}

/// Without a pin the user's own wording stays (no behaviour change for user lists).
#[test]
fn user_list_messages_unchanged() {
    let cfg = config_from_toml(TWO_MODELS);
    assert!(!effective_allowlist(&cfg).is_fleet());
    assert_eq!(
        allowlist_denied_message(&cfg),
        "This model isn't allowed by your allowed_models setting."
    );
}

#[test]
fn inspect_allowed_models_row() {
    let mut cfg = config_from_toml(TWO_MODELS);
    assert!(crate::inspect::allowed_models_row(&cfg).is_none());
    pin(&mut cfg, AllowlistPin::List(vec!["beta-*".to_string()]));
    let row = crate::inspect::allowed_models_row(&cfg).unwrap();
    assert_eq!(row.kind, "allowedModels");
    assert_eq!(row.detail, "allowed models: beta-*");
    assert!(
        row.source.contains("/etc/fuigo/requirements.toml"),
        "{}",
        row.source
    );
    pin(&mut cfg, AllowlistPin::FailClosed);
    assert!(
        crate::inspect::allowed_models_row(&cfg)
            .unwrap()
            .detail
            .contains("no model is selectable")
    );
}

fn policy_ms() -> fuigo_workspace::permission::resolution::ManagedSettings {
    use fuigo_workspace::permission::resolution::{
        AllowedMcpServer, ManagedSettings, MarketplaceAllowlist, McpServerAllowlist,
        PolicyLayerOwnership, PolicyPin,
    };
    let mut ms = ManagedSettings::default();
    ms.mcp_allowlist.sources.push(
        McpServerAllowlist::new(
            vec![AllowedMcpServer::Name { name: "a".into() }],
            vec![AllowedMcpServer::Name { name: "b".into() }],
            Some(PathBuf::from("/etc/fuigo/managed_config.toml")),
        )
        .with_managed_only(),
    );
    ms.mcp_allowlist.sources.push(
        McpServerAllowlist::new(
            vec![],
            vec![],
            Some(PathBuf::from("/home/u/.fuigo/requirements.toml")),
        )
        .with_lockdown(),
    );
    // An unrestricted source produces no row.
    ms.mcp_allowlist.sources.push(McpServerAllowlist::new(
        vec![],
        vec![],
        Some(PathBuf::from("/nowhere")),
    ));
    ms.marketplace_allowlist.sources.push(MarketplaceAllowlist {
        allowed_urls: vec![],
        source_path: Some(PathBuf::from("/etc/fuigo/requirements.toml")),
    });
    ms.project_mcp = PolicyPin::Disabled {
        source: PathBuf::from("/etc/fuigo/requirements.toml"),
        ownership: PolicyLayerOwnership::Admin,
    };
    ms.non_managed_hooks = PolicyPin::Disabled {
        source: PathBuf::from("/etc/fuigo/managed_config.toml"),
        ownership: PolicyLayerOwnership::Admin,
    };
    ms
}

#[test]
fn inspect_policy_rows_name_every_enforcing_source() {
    let rows = crate::inspect::managed_policy_rows(&policy_ms());
    let got: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|r| (r.kind, r.source.as_str(), r.detail.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![
            (
                "mcpServers",
                "/etc/fuigo/managed_config.toml",
                "allow 1, deny 1, managed servers only"
            ),
            (
                "mcpServers",
                "/home/u/.fuigo/requirements.toml",
                "lockdown: every MCP server blocked"
            ),
            (
                "marketplaces",
                "/etc/fuigo/requirements.toml",
                "lockdown: every marketplace blocked"
            ),
            (
                "projectMcp",
                "/etc/fuigo/requirements.toml",
                "project MCP servers blocked unless allowed (enable_all_project_mcp_servers = false)"
            ),
            (
                "managedHooksOnly",
                "/etc/fuigo/managed_config.toml",
                "only managed hooks run (allow_managed_hooks_only = true)"
            ),
        ]
    );
    assert!(
        crate::inspect::managed_policy_rows(&Default::default()).is_empty(),
        "no policy, no rows"
    );
}

#[test]
fn mcp_doctor_policy_rows() {
    let rows = crate::mcp_doctor::policy_source_rows(&policy_ms());
    let paths: Vec<&str> = rows.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "MCP policy (/etc/fuigo/managed_config.toml)",
            "MCP policy (/home/u/.fuigo/requirements.toml)",
            "project MCP pin (/etc/fuigo/requirements.toml)",
        ]
    );
    let json = serde_json::to_value(&rows[1]).unwrap();
    assert_eq!(json["status"]["status"], "policy");
    assert_eq!(json["status"]["detail"], "lockdown: every server blocked");
    assert!(crate::mcp_doctor::policy_source_rows(&Default::default()).is_empty());
}

#[test]
fn policy_source_path_helper_is_name_only() {
    assert_eq!(
        fuigo_workspace::permission::resolution::user_facing_policy_source(Path::new(
            "/etc/fuigo/managed_config.toml"
        )),
        "managed_config.toml"
    );
}

/// Astra r1 #7: before a real catalog, a fail-closed pin refuses and a fleet pin refuses an explicit disallowed choice.
#[test]
fn fleet_pin_is_checked_before_the_catalog_arrives() {
    use crate::agent::models::validate_fleet_pin_pre_catalog;
    let mut cfg = config_from_toml(TWO_MODELS);
    let catalog = resolve_model_catalog(&cfg, None);
    assert!(
        validate_fleet_pin_pre_catalog(&cfg, &catalog).is_ok(),
        "user lists wait for the catalog"
    );
    pin(&mut cfg, AllowlistPin::List(vec!["beta-*".to_string()]));
    cfg.default_model_override = Some("not-in-any-catalog".to_string());
    let err = validate_fleet_pin_pre_catalog(&cfg, &catalog).unwrap_err();
    assert!(
        err.contains("not-in-any-catalog") && err.contains("-m flag"),
        "{err}"
    );
    cfg.default_model_override = Some("beta-1".to_string());
    assert!(validate_fleet_pin_pre_catalog(&cfg, &catalog).is_ok());
    pin(&mut cfg, AllowlistPin::FailClosed);
    assert!(validate_fleet_pin_pre_catalog(&cfg, &catalog).is_err());
}

/// Astra r1 #6: a reasoning-effort route to a model id the fleet pin excludes is not taken.
#[test]
fn effort_routes_obey_the_fleet_pin() {
    use crate::agent::models::effort_route_allowed;
    let mut cfg = config_from_toml(TWO_MODELS);
    assert!(
        effort_route_allowed(&cfg, "anything"),
        "a user list does not judge effort routes"
    );
    pin(&mut cfg, AllowlistPin::List(vec!["beta-*".to_string()]));
    assert!(effort_route_allowed(&cfg, "beta-high"));
    assert!(!effort_route_allowed(&cfg, "alpha-high"));
}

/// Astra r2: with a real catalog, an explicit choice the catalog does not know is refused under a fleet pin, not
/// silently replaced.
#[test]
fn fleet_pin_refuses_an_unknown_explicit_choice() {
    let mut cfg = config_from_toml(TWO_MODELS);
    pin(&mut cfg, AllowlistPin::List(vec!["beta-*".to_string()]));
    cfg.default_model_override = Some("blocked-missing".to_string());
    let catalog = resolve_model_catalog(&cfg, None);
    let err = validate_selectable(&cfg, &catalog).unwrap_err();
    assert!(err.contains("blocked-missing"), "{err}");
    cfg.default_model_override = Some("beta-unknown".to_string());
    assert!(
        validate_selectable(&cfg, &catalog).is_ok(),
        "an allowed id the catalog lacks is not refused"
    );
}

// ── Grok 4.7 #1: strictKnownMarketplaces binds plugins at load ──────────────────────────────────────────────────

fn write_hook_mcp_plugin(root: &Path, name: &str) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(
        root.join("plugin.json"),
        serde_json::json!({
            "name": name,
            "hooks": {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "true"}]}]}},
            "mcpServers": {format!("p169g-srv-{name}"): {"command": "true"}}
        })
        .to_string(),
    )
    .unwrap();
}

/// Our plugins (by hook spec name) among `specs`; ambient plugins on the host are ignored.
fn our_hook_plugins(specs: &[fuigo_hooks::config::HookSpec]) -> Vec<String> {
    let mut names: Vec<String> = specs
        .iter()
        .filter_map(|s| s.name.strip_prefix("plugin/"))
        .filter_map(|rest| rest.split('/').next())
        .filter(|name| ["demo", "cliplug", "cfgplug", "sessplug"].contains(name))
        .map(str::to_owned)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Our plugin MCP servers the session merge would start (`merge_managed_mcp_servers_sourced`, the spawn path's source).
fn our_mcp_servers(registry: Option<&fuigo_agent::plugins::PluginRegistry>) -> Vec<String> {
    let cwd = tempfile::tempdir().unwrap();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let merged =
        crate::session::managed_mcp::merge_managed_mcp_servers_sourced(cwd.path(), registry, &compat);
    let mut names: Vec<String> = merged
        .iter()
        .map(|(s, _)| crate::session::managed_mcp::mcp_server_name(s).to_string())
        .filter(|n| n.contains("p169g-srv-"))
        .collect();
    names.sort();
    names
}

/// P169 (Grok 4.7 #1): with marketplaces restricted, a plugin already listed in `[plugins].enabled` (by full id), a
/// Claude-imported bare name, a `[plugins].paths` plugin, a `--plugin-dir` plugin and a session `pluginDirs` plugin
/// do not load at session build, so none of their hooks or MCP servers reach the session. Unrestricted they all do.
#[test]
fn restricted_marketplaces_load_no_unverifiable_plugin_hooks_or_mcp() {
    use crate::session::acp_session::SessionActor;
    use fuigo_agent::plugins::{PluginSourceRestriction, SharedPluginRegistryHandle};
    let repo = tempfile::tempdir().unwrap();
    git2::Repository::init(repo.path()).unwrap();
    write_hook_mcp_plugin(&repo.path().join(".fuigo/plugins/demo"), "demo");
    let local = tempfile::tempdir().unwrap();
    let cfg_plugin = local.path().join("cfgplug");
    write_hook_mcp_plugin(&cfg_plugin, "cfgplug");
    let cli_plugin = local.path().join("cliplug");
    write_hook_mcp_plugin(&cli_plugin, "cliplug");
    let session_plugin = local.path().join("sessplug");
    write_hook_mcp_plugin(&session_plugin, "sessplug");

    let trust = fuigo_agent::plugins::TrustStore::load_from(local.path().join("trust"));
    let demo_id = fuigo_agent::plugins::discover_plugins(
        Some(repo.path()),
        &fuigo_agent::plugins::discovery::DiscoveryConfig::default(),
        &trust,
        true,
    )
    .into_iter()
    .find(|p| p.plugin_name() == "demo")
    .map(|p| p.id.0)
    .expect("fixture: the project plugin is discovered");

    let plugins_cfg = crate::agent::config::PluginsConfig {
        paths: vec![cfg_plugin.display().to_string()],
        // `demo` by its full id (already listed) and by the bare name a Claude `enabledPlugins` import writes.
        enabled: vec![
            demo_id.clone(),
            "demo".to_string(),
            "cfgplug".to_string(),
            "cliplug".to_string(),
            "sessplug".to_string(),
        ],
        cli_plugin_dirs: vec![cli_plugin.clone()],
        ..Default::default()
    };
    let handle = SharedPluginRegistryHandle::new(None, vec![cli_plugin.clone()]);

    let open = handle.build_for_cwd(
        repo.path(),
        &plugins_cfg.to_discovery_config_with(None),
        std::slice::from_ref(&session_plugin),
        true,
    );
    assert_eq!(
        our_hook_plugins(&SessionActor::plugin_hook_specs(open.as_deref(), true))
            .iter()
            .filter(|n| ["demo", "cliplug", "sessplug"].contains(&n.as_str()))
            .count(),
        3,
        "fixture: unrestricted, the project, CLI and session plugins contribute hooks"
    );
    assert!(
        !our_mcp_servers(open.as_deref()).is_empty(),
        "fixture: unrestricted, plugin MCP servers load"
    );

    // An allowed install of another plugin named `demo` exists elsewhere: its id is all the restriction admits.
    let restriction = PluginSourceRestriction {
        allowed_ids: vec!["user/0badc0de/demo".to_string()],
    };
    let dc = plugins_cfg.to_discovery_config_with(Some(restriction));
    assert!(dc.enabled.is_empty(), "no bare name or unallowed id survives: {:?}", dc.enabled);
    assert!(dc.config_paths.is_empty() && dc.cli_plugin_dirs.is_empty());
    let locked = handle.build_for_cwd(
        repo.path(),
        &dc,
        std::slice::from_ref(&session_plugin),
        true,
    );
    let ours: Vec<String> = locked
        .as_deref()
        .map(|r| {
            r.list()
                .into_iter()
                .map(|p| p.name.clone())
                .filter(|n| ["demo", "cfgplug", "cliplug", "sessplug"].contains(&n.as_str()))
                .collect()
        })
        .unwrap_or_default();
    assert!(ours.is_empty(), "no unverifiable plugin may load: {ours:?}");
    assert!(
        our_hook_plugins(&SessionActor::plugin_hook_specs(locked.as_deref(), true)).is_empty(),
        "no plugin hook may run"
    );
    assert!(our_mcp_servers(locked.as_deref()).is_empty(), "no plugin MCP server may start");
    for name in ["demo", "cfgplug", "cliplug", "sessplug"] {
        let server = format!("p169g-srv-{name}");
        assert!(locked
            .as_deref()
            .and_then(|r| r.mcp_server_owner(&server))
            .is_none());
    }
}

// ---- Round 6 (Grok round-5 HIGH): a fleet `allowed_models` pin binds helper (side-call) sampling ----

const HELPER_MODELS: &str = r#"
[models]
default = "beta-1"
[model.alpha-1]
model = "alpha-1"
base_url = "https://api.example.com/v1"
api_key = "k-alpha"
context_window = 256000
[model.beta-1]
model = "beta-1"
base_url = "https://api.example.com/v1"
api_key = "k-beta"
context_window = 256000
"#;

fn helper_cfg(pin_value: Option<AllowlistPin>) -> Config {
    let mut cfg = config_from_toml(HELPER_MODELS);
    if let Some(v) = pin_value {
        pin(&mut cfg, v);
    }
    cfg
}

fn deployment_endpoints() -> crate::agent::config::EndpointsConfig {
    crate::agent::config::EndpointsConfig {
        deployment_key: Some("deployment-key".into()),
        ..crate::agent::config::EndpointsConfig::default()
    }
}

fn aux(
    cfg: &Config,
    slug: &str,
    choice: crate::agent::config::HelperModelChoice,
) -> Option<fuigo_sampler::SamplerConfig> {
    let catalog = resolve_model_catalog(cfg, None);
    crate::agent::config::resolve_aux_model_sampling_config_for_held(
        slug,
        &catalog,
        &deployment_endpoints(),
        None,
        false,
        None,
        None,
        choice,
        &effective_allowlist(cfg),
    )
}

/// A helper slug the fleet pin excludes (catalog entry, or an id the catalog has never heard of that the Ferrox
/// fallthrough would synthesize) is never sampled; the caller falls back to the admitted session model.
#[test]
fn fleet_pin_binds_helper_aux_sampling() {
    use crate::agent::config::HelperModelChoice::{Default, Explicit};
    let cfg = helper_cfg(Some(AllowlistPin::List(vec!["beta-*".into()])));
    for choice in [Default, Explicit] {
        assert!(
            aux(&cfg, "alpha-1", choice).is_none(),
            "a catalog entry outside the pin must not sample ({choice:?})"
        );
        assert!(
            aux(&cfg, "claude-opus-4-7", choice).is_none(),
            "an id off the catalog must not be synthesized onto the inference route ({choice:?})"
        );
        let ok = aux(&cfg, "beta-1", choice).expect("an admitted entry still resolves");
        assert_eq!(ok.model, "beta-1");
    }
    // An unreadable pin admits nothing.
    let closed = helper_cfg(Some(AllowlistPin::FailClosed));
    assert!(aux(&closed, "beta-1", Default).is_none());
}

/// Control: with no fleet pin helpers resolve as before; a USER list does not bind them (the user chose them).
#[test]
fn helper_sampling_is_unbound_without_a_fleet_pin() {
    use crate::agent::config::HelperModelChoice::Default;
    let none = helper_cfg(None);
    assert!(aux(&none, "alpha-1", Default).is_some());
    assert!(aux(&none, "claude-opus-4-7", Default).is_some());
    let mut user = helper_cfg(None);
    user.models.allowed_models = Some(vec!["beta-*".into()]);
    assert!(aux(&user, "alpha-1", Default).is_some(), "a user list never binds helpers");
    let empty = helper_cfg(Some(AllowlistPin::List(vec![])));
    assert!(aux(&empty, "alpha-1", Default).is_some(), "an empty pin is unrestricted");
}

/// Web search runs on its own resolver; the pin binds it too (disabled, not rerouted).
#[test]
fn fleet_pin_binds_web_search_sampling() {
    let cfg = helper_cfg(Some(AllowlistPin::List(vec!["beta-*".into()])));
    let catalog = resolve_model_catalog(&cfg, None);
    let search = |slug: &str| {
        crate::agent::config::resolve_web_search_sampling_config(
            slug,
            &catalog,
            None,
            false,
            None,
            None,
            &deployment_endpoints(),
            &effective_allowlist(&cfg),
        )
    };
    assert!(search("alpha-1").is_none(), "an excluded web-search model is disabled");
    assert!(
        search(crate::models::default_web_search_model()).is_none(),
        "the hidden default web-search model is not admitted by the pin"
    );
    assert!(search("beta-1").is_some());
    let open = helper_cfg(None);
    assert!(
        crate::agent::config::resolve_web_search_sampling_config(
            "alpha-1",
            &resolve_model_catalog(&open, None),
            None,
            false,
            None,
            None,
            &deployment_endpoints(),
            &effective_allowlist(&open),
        )
        .is_some()
    );
}

/// The manager-level predicate the session sites (image description, classifier, prompt suggestion) share.
#[test]
fn manager_helper_admission_follows_the_fleet_pin() {
    use crate::auth::{AuthManager, FuigoComConfig};
    let tmp = tempfile::TempDir::new().unwrap();
    let auth = std::sync::Arc::new(AuthManager::new(tmp.path(), FuigoComConfig::default()));
    let cfg = helper_cfg(Some(AllowlistPin::List(vec!["beta-*".into()])));
    let mgr = crate::agent::models::ModelsManager::from_config(&cfg, None, auth.clone()).unwrap();
    assert!(mgr.helper_model_admitted("beta-1"));
    assert!(!mgr.helper_model_admitted("alpha-1"), "in the catalog but outside the pin");
    assert!(!mgr.helper_model_admitted("claude-opus-4-7"), "not in the catalog");
    let open = helper_cfg(None);
    let mgr = crate::agent::models::ModelsManager::from_config(&open, None, auth).unwrap();
    assert!(mgr.helper_model_admitted("alpha-1") && mgr.helper_model_admitted("claude-opus-4-7"));
}

// ---- Round 7: the model on the wire follows the entry the fleet pin admitted (audit: grok-p169-r6.md) ----

/// Fleet pin `["beta-*"]`; catalog: `alpha-1`, `beta-1`, and a user key `claude-opus-4-7` whose model id is `beta-1`.
fn wire_fixture() -> (Config, indexmap::IndexMap<String, crate::agent::config::ModelEntry>) {
    let mut cfg = config_from_toml(
        r#"
[models]
default = "beta-1"
[model.alpha-1]
model = "alpha-1"
base_url = "https://api.example.com/v1"
context_window = 256000
[model.beta-1]
model = "beta-1"
base_url = "https://api.example.com/v1"
context_window = 256000
[model.claude-opus-4-7]
model = "beta-1"
base_url = "https://api.example.com/v1"
context_window = 256000
"#,
    );
    pin(&mut cfg, AllowlistPin::List(vec!["beta-*".to_string()]));
    let catalog = resolve_model_catalog(&cfg, None);
    (cfg, catalog)
}

/// Audit HIGH 1: pin `["beta-*"]`, session on `beta-1`, `aiModel` = `claude-opus-4-7` (off the catalog as a model id).
#[test]
fn ai_suggest_sends_only_a_pin_admitted_model() {
    use crate::agent::models::ai_suggest_wire_model as wire;
    let (cfg, cat) = wire_fixture();
    let a = effective_allowlist(&cfg);
    assert_eq!(wire(&a, &cat, Some("claude-opus-4-7"), Some("beta-1")).as_deref(), Some("beta-1"));
    assert_eq!(wire(&a, &cat, Some("alpha-1"), Some("beta-1")).as_deref(), Some("beta-1"), "outside the pin");
    assert_eq!(wire(&a, &cat, Some("not-in-catalog"), Some("beta-1")).as_deref(), Some("beta-1"));
    assert_eq!(wire(&a, &cat, None, Some("beta-1")).as_deref(), Some("beta-1"), "no literal grok-4.6 under a pin");
    assert_eq!(wire(&a, &cat, None, None), None, "no session model: skip");
    let open = helper_cfg(None);
    let open_cat = resolve_model_catalog(&open, None);
    let a = effective_allowlist(&open);
    assert_eq!(wire(&a, &open_cat, Some("claude-opus-4-7"), Some("beta-1")).as_deref(), Some("claude-opus-4-7"));
    assert_eq!(wire(&a, &open_cat, None, Some("beta-1")).as_deref(), Some("grok-4.6"), "unpinned: unchanged");
}

/// Audit HIGH 2: pin `["beta-*"]`, session on `beta-1`, user rewrites a memory note.
#[test]
fn memory_note_rewrite_sends_only_a_pin_admitted_model() {
    use crate::agent::models::rewrite_note_wire_model as wire;
    let (cfg, cat) = wire_fixture();
    let a = effective_allowlist(&cfg);
    assert_eq!(wire(&a, &cat, Some("beta-1")).as_deref(), Some("beta-1"), "no literal grok-4.6 under a pin");
    assert_eq!(wire(&a, &cat, None), None, "no session model: skip");
    let open = helper_cfg(None);
    let open_cat = resolve_model_catalog(&open, None);
    assert_eq!(wire(&effective_allowlist(&open), &open_cat, Some("beta-1")).as_deref(), Some("grok-4.6"));
}

/// Audit HIGH 3: pin `["beta-*"]` and `[compaction.memory_flush] flush_model = "claude-opus-4-7"`.
#[test]
fn memory_flush_sends_only_a_pin_admitted_model() {
    use crate::agent::models::flush_wire_model as wire;
    let (cfg, cat) = wire_fixture();
    let a = effective_allowlist(&cfg);
    assert_eq!(wire(&a, &cat, Some("not-in-catalog"), Some("beta-1")).as_deref(), Some("beta-1"));
    assert_eq!(wire(&a, &cat, Some("alpha-1"), Some("beta-1")).as_deref(), Some("beta-1"), "outside the pin");
    assert_eq!(wire(&a, &cat, None, Some("beta-1")).as_deref(), Some("beta-1"));
    assert_eq!(wire(&a, &cat, Some("not-in-catalog"), None), None, "no session model: skip the flush");
    let open = helper_cfg(None);
    let open_cat = resolve_model_catalog(&open, None);
    let a = effective_allowlist(&open);
    assert_eq!(wire(&a, &open_cat, Some("not-in-catalog"), Some("beta-1")).as_deref(), Some("not-in-catalog"));
    assert_eq!(wire(&a, &open_cat, None, Some("beta-1")).as_deref(), Some("beta-1"));
}

/// Audit HIGH 4: pin `["beta-*"]`; user `[model.claude-opus-4-7]` has `model = "beta-1"`; the hint is the key. The pin
/// admits the entry (by its model id `beta-1`), so the wire model is `beta-1`, not the key.
#[test]
fn prompt_suggestion_sends_the_admitted_entrys_model_id() {
    use crate::agent::models::suggest_prompt_wire_model as wire;
    let (cfg, cat) = wire_fixture();
    let a = effective_allowlist(&cfg);
    assert_eq!(wire(&a, &cat, "claude-opus-4-7", Some("beta-1")).as_deref(), Some("beta-1"));
    assert_eq!(wire(&a, &cat, "beta-1", Some("beta-1")).as_deref(), Some("beta-1"));
    assert_eq!(wire(&a, &cat, "alpha-1", Some("beta-1")).as_deref(), Some("beta-1"), "outside the pin");
    let open = helper_cfg(None);
    let open_cat = resolve_model_catalog(&open, None);
    assert_eq!(
        wire(&effective_allowlist(&open), &open_cat, "claude-opus-4-7", Some("beta-1")).as_deref(),
        Some("claude-opus-4-7"),
        "unpinned: unchanged"
    );
}

// ---- Round 8: laziness classifier, goal evaluator, session fallback, unpinned flush (audit: grok-p169-r7.md) ----

fn r8_manager(pinned: bool) -> crate::agent::models::ModelsManager {
    use crate::auth::{AuthManager, FuigoComConfig};
    let tmp = tempfile::TempDir::new().unwrap();
    let auth = std::sync::Arc::new(AuthManager::new(tmp.path(), FuigoComConfig::default()));
    let mut cfg = config_from_toml(
        r#"
[models]
default = "beta-1"
[model.alpha-1]
model = "alpha-1"
base_url = "https://api.example.com/v1"
context_window = 256000
[model.beta-1]
model = "beta-1"
base_url = "https://api.example.com/v1"
context_window = 256000
[model.claude-opus-4-7]
model = "beta-1"
base_url = "https://api.example.com/v1"
context_window = 256000
"#,
    );
    if pinned {
        pin(&mut cfg, AllowlistPin::List(vec!["beta-*".to_string()]));
    }
    let mgr = crate::agent::models::ModelsManager::from_config(&cfg, None, auth).unwrap();
    // The detector config reaches an entry through the catalog; enable it on the aliasing entry.
    let mut entry = mgr.models().get("claude-opus-4-7").cloned().expect("aliasing entry");
    entry.info.laziness_detector.enabled = true;
    mgr.insert_test_entry("claude-opus-4-7", entry);
    mgr
}

/// Audit HIGH A: pin `["beta-*"]`, user entry `[model.claude-opus-4-7] model = "beta-1"` with the detector enabled on the entry.
/// The classifier request carries the admitted entry's model id and the detector config of that same entry.
#[test]
fn laziness_classifier_sends_the_admitted_entrys_model_id() {
    let mgr = r8_manager(true);
    let (wire, cfg) = mgr.laziness_target("claude-opus-4-7").expect("admitted");
    assert_eq!(wire, "beta-1", "the wire id, not the catalog key");
    assert!(cfg.enabled, "detector config comes from the selected entry");
    assert!(mgr.laziness_target("alpha-1").is_none(), "outside the pin: skip the call");
    assert!(mgr.laziness_target("not-in-catalog").is_none(), "off the catalog under a pin: skip the call");
    let open = r8_manager(false);
    assert_eq!(open.laziness_target("alpha-1").map(|(w, _)| w).as_deref(), Some("alpha-1"), "unpinned: unchanged");
}

/// Audit LOW B: the goal evaluator's empty-session-model fallback is the admitted entry's model id, or none.
#[test]
fn goal_evaluator_fallback_is_the_admitted_entrys_model_id() {
    let mgr = r8_manager(true);
    assert_eq!(mgr.selected_wire_model("claude-opus-4-7").as_deref(), Some("beta-1"));
    assert_eq!(mgr.selected_wire_model("alpha-1"), None);
    assert_eq!(mgr.selected_wire_model("not-in-catalog"), None);
    let open = r8_manager(false);
    assert_eq!(open.selected_wire_model("claude-opus-4-7").as_deref(), Some("claude-opus-4-7"), "unpinned: unchanged");
}

/// Audit LOW C: under a fleet pin the session-model fallback is re-checked for admission.
#[test]
fn session_model_fallback_is_rechecked_under_a_pin() {
    use crate::agent::models::ai_suggest_wire_model as wire;
    let (cfg, cat) = wire_fixture();
    let a = effective_allowlist(&cfg);
    assert_eq!(wire(&a, &cat, None, Some("alpha-1")), None, "session model outside the pin");
    assert_eq!(wire(&a, &cat, None, Some("not-in-catalog")), None, "session model off the catalog");
    assert_eq!(wire(&a, &cat, None, Some("beta-1")).as_deref(), Some("beta-1"));
    let failed = helper_cfg(Some(AllowlistPin::List(vec!["nothing-*".to_string()])));
    let failed_cat = resolve_model_catalog(&failed, None);
    let a = effective_allowlist(&failed);
    assert_eq!(wire(&a, &failed_cat, None, Some("beta-1")), None, "nothing admitted: skip");
}

/// Audit LOW D: no pin, no `flush_model`, no sampling config: the flush sends the empty model as before the refactor.
#[test]
fn unpinned_flush_without_any_model_keeps_the_previous_request() {
    use crate::agent::models::flush_wire_model as wire;
    let open = helper_cfg(None);
    let open_cat = resolve_model_catalog(&open, None);
    assert_eq!(wire(&effective_allowlist(&open), &open_cat, None, None).as_deref(), Some(""));
    let (cfg, cat) = wire_fixture();
    assert_eq!(wire(&effective_allowlist(&cfg), &cat, None, None), None, "pinned: still skipped");
}
