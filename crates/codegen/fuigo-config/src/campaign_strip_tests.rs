//! A campaign cannot set a credential destination or an execution policy; a secret-free campaign still applies.

use crate::campaigns::{CampaignEntry, apply_active_campaign_patches};

fn set_path(root: &mut toml::Table, path: &[&str], value: toml::Value) {
    match path {
        [leaf] => {
            root.insert((*leaf).to_owned(), value);
        }
        [head, rest @ ..] => {
            let entry = root
                .entry((*head).to_owned())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            set_path(entry.as_table_mut().expect("table"), rest, value);
        }
        [] => {}
    }
}

fn get_path<'a>(root: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Value> {
    path.iter().try_fold(root, |cur, seg| cur.get(*seg))
}

/// Every key the campaign boundary newly closes: (dotted path, whether the user's value must also survive).
const NEWLY_STRIPPED: &[&str] = &[
    "hub.url",
    "shell_environment_policy.set.VISIBLE",
    "shell_environment_policy.inherit",
    "toolset.bash.cmd_prefix",
    "toolset.web_fetch.proxy_endpoint",
    "toolset.web_search.base_url",
    "toolset.web_search.api_key",
    "toolset.web_search.flux_base_url",
    "toolset.web_search.extra_headers.X",
    "toolset.web_search.env_http_headers.X",
    "toolset.web_search.mtls_cert_dir",
    "telemetry.events_url",
    "telemetry.events_api_key",
    "telemetry.mixpanel_token",
    "telemetry.otel_endpoint",
    "telemetry.otel_enabled",
    "telemetry.otel_logs_exporter",
    "telemetry.otel_metrics_exporter",
    "telemetry.otel_log_user_prompts",
    "telemetry.otel_log_tool_details",
    "telemetry.otel_client_key",
    "telemetry.otel_certificate",
    "telemetry.otel_client_certificate",
    "telemetry.otel_protocol",
    "feedback.user.command",
    "tools.zdr_video_output_s3.endpoint",
    "tools.zdr_video_output_s3.read_write.secret_access_key",
    "cli.installer",
    "cli.npm_registry",
    "cli.session_registry",
    "paths.extra_rule_dirs",
    "paths.extra_skill_dirs",
    "plugins.paths",
    "skills.bundled_skill_dirs",
    "skills.paths",
    "skills.server_skill_dirs",
    "agent.definition",
    "plugins.enabled",
    "plugins.disabled",
    "plugins.auto_discover",
    "marketplace.sources",
    "skills.auto_discover",
    "telemetry.trace_upload",
    "telemetry.otel_transport",
    "features.telemetry",
    "features.lsp_tools",
    "agent.name",
    "disabled_mcp_servers",
    "subagents.roles.r.prompt_file",
    "subagents.personas.p.instructions_file",
];

#[test]
fn campaign_cannot_set_credential_destinations_or_execution_policy() {
    for path in NEWLY_STRIPPED {
        let segs: Vec<&str> = path.split('.').collect();
        // The user set the key: the campaign must leave their value.
        let mut user = toml::Table::new();
        set_path(&mut user, &segs, toml::Value::String("user-value".into()));
        let mut patch = toml::Table::new();
        set_path(
            &mut patch,
            &segs,
            toml::Value::String("campaign-value".into()),
        );
        let mut effective = toml::Value::Table(user);
        apply_active_campaign_patches(
            &mut effective,
            &[CampaignEntry {
                id: "c".into(),
                patch,
            }],
        );
        assert_eq!(
            get_path(&effective, &segs).and_then(toml::Value::as_str),
            Some("user-value"),
            "campaign overwrote `{path}`: {effective:?}"
        );
        // The user did not set it: the campaign must not introduce it.
        let mut patch = toml::Table::new();
        set_path(
            &mut patch,
            &segs,
            toml::Value::String("campaign-value".into()),
        );
        let mut effective = toml::Value::Table(toml::Table::new());
        apply_active_campaign_patches(
            &mut effective,
            &[CampaignEntry {
                id: "c".into(),
                patch,
            }],
        );
        assert!(
            get_path(&effective, &segs).is_none(),
            "campaign introduced `{path}`: {effective:?}"
        );
    }
}

/// A whole-table or non-table campaign value for a stripped key cannot clobber the user's table either.
#[test]
fn campaign_cannot_replace_a_stripped_table_wholesale() {
    let mut effective: toml::Value = toml::from_str(
        "[shell_environment_policy]\ninherit = \"core\"\n[hub]\nurl = \"wss://mine.invalid\"\n",
    )
    .unwrap();
    let before = effective.clone();
    let patch: toml::Table =
        toml::from_str("shell_environment_policy = \"none\"\nhub = 1\n").unwrap();
    apply_active_campaign_patches(
        &mut effective,
        &[CampaignEntry {
            id: "c".into(),
            patch,
        }],
    );
    assert_eq!(effective, before);
}

/// The secret-free parts of a campaign still apply in full, next to stripped ones.
#[test]
fn secret_free_campaign_still_applies_beside_stripped_keys() {
    let mut effective: toml::Value = toml::from_str(
        "[models]\ndefault = \"old\"\n[model.a]\nname = \"Old\"\n[hub]\nurl = \"wss://mine.invalid\"\n[telemetry]\notel_endpoint = \"https://mine.invalid\"\n",
    )
    .unwrap();
    let patch: toml::Table = toml::from_str(
        "[models]\ndefault = \"a\"\n[model.a]\nname = \"New name\"\n\
         [features]\nweb_fetch = true\n[hub]\nurl = \"wss://campaign.invalid\"\n\
         [telemetry]\notel_endpoint = \"https://campaign.invalid\"\n\
         [mcp_servers.docs]\nurl = \"https://docs.invalid/mcp\"\ncommand = \"docs-srv\"\nargs = [\"--plain\", \"--mode=${MODE}\"]\n",
    )
    .unwrap();
    apply_active_campaign_patches(
        &mut effective,
        &[CampaignEntry {
            id: "c".into(),
            patch,
        }],
    );
    assert_eq!(effective["models"]["default"].as_str(), Some("a"));
    assert_eq!(effective["model"]["a"]["name"].as_str(), Some("New name"));
    // `features` is not on the campaign allowlist.
    assert!(effective.get("features").is_none(), "{effective:?}");
    assert_eq!(effective["hub"]["url"].as_str(), Some("wss://mine.invalid"));
    assert_eq!(
        effective["telemetry"]["otel_endpoint"].as_str(),
        Some("https://mine.invalid")
    );
    let docs = &effective["mcp_servers"]["docs"];
    assert_eq!(docs["url"].as_str(), Some("https://docs.invalid/mcp"));
    assert_eq!(docs["args"][1].as_str(), Some("--mode=${MODE}"));
}

fn apply_one(base: &str, id: &str, patch: &str) -> toml::Value {
    let mut effective: toml::Value = toml::from_str(base).unwrap();
    let patch: toml::Table = toml::from_str(patch).unwrap();
    apply_active_campaign_patches(
        &mut effective,
        &[CampaignEntry {
            id: id.into(),
            patch,
        }],
    );
    effective
}

/// Allowlist: a key no campaign uses is ignored, whatever its name looks like (review rounds c1 to c6 found such
/// switches one at a time; the boundary is now the list of keys campaigns use, not a list of keys they may not).
#[test]
fn campaign_unlisted_keys_change_nothing() {
    let base = "[models]\ndefault = \"mine\"\n[features]\nweb_fetch = false\n[ui]\nyolo = false\n";
    for patch in [
        "[features]\ntelemetry = \"on\"\n",
        "[features]\nweb_fetch = true\n",
        "[agent]\nname = \"other\"\n",
        "disabled_mcp_servers = [\"mine\"]\n",
        "[skills]\ndisabled = [\"mine\"]\n",
        "[ui]\nyolo = true\n",
        "[ui]\npermission_mode = \"always-approve\"\n",
        "[toolset.web_search]\nexcluded_domains = [\"x.invalid\"]\n",
        "[brand_new_table]\nanything = 1\n[brand_new_table.nested]\nmore = \"x\"\n",
        "brand_new_scalar = true\n",
        "[models]\nallowed_models = [\"x\"]\ndefault_reasoning_effort = \"high\"\n",
        "[model.a]\nmodel = \"other-wire-id\"\ntemperature = 2.0\n",
        "[mcpServers.docs]\nurl = \"https://docs.invalid/mcp\"\n",
        "[version_overrides.x]\n[version_overrides.x.models]\ndefault = \"x\"\n",
        "[[campaigns]]\nid = \"nested\"\n[campaigns.models]\ndefault = \"x\"\n",
    ] {
        assert_eq!(
            apply_one(base, "u", patch),
            toml::from_str::<toml::Value>(base).unwrap(),
            "{patch}"
        );
    }
}

/// Every key the inventory shows campaigns use still applies.
#[test]
fn campaign_allowed_paths_still_apply() {
    let effective = apply_one(
        "[models]\ndefault = \"mine\"\n[model.a]\nname = \"Old\"\n",
        "ok",
        "[models]\ndefault = \"a\"\nimage_description = \"a\"\nsession_summary = \"a\"\n\
         [model.a]\nname = \"New\"\ncontext_window = 2000\n[model.added]\nname = \"Added\"\n\
         [mcp_servers.docs]\nurl = \"https://docs.invalid/mcp\"\n[managed_mcps]\nenabled = false\n",
    );
    assert_eq!(effective["models"]["default"].as_str(), Some("a"));
    assert_eq!(effective["models"]["image_description"].as_str(), Some("a"));
    assert_eq!(effective["models"]["session_summary"].as_str(), Some("a"));
    assert_eq!(effective["model"]["a"]["name"].as_str(), Some("New"));
    assert_eq!(
        effective["model"]["a"]["context_window"].as_integer(),
        Some(2000)
    );
    assert_eq!(effective["model"]["added"]["name"].as_str(), Some("Added"));
    assert_eq!(
        effective["mcp_servers"]["docs"]["url"].as_str(),
        Some("https://docs.invalid/mcp")
    );
    assert_eq!(effective["managed_mcps"]["enabled"].as_bool(), Some(false));
}

/// Value constraints on allowed paths: a value of the wrong kind, or a switch turned ON, is dropped.
#[test]
fn campaign_allowed_paths_keep_only_their_constrained_values() {
    let base = "[models]\ndefault = \"mine\"\n[model.a]\nname = \"Old\"\ncontext_window = 10\n[managed_mcps]\nenabled = false\n";
    for patch in [
        "[managed_mcps]\nenabled = true\n",
        "[managed_mcps]\nenabled = \"yes\"\n",
        "[models]\ndefault = 5\n",
        "[models]\ndefault = { x = 1 }\n",
        "[models]\nimage_description = [\"a\"]\n",
        "[model.a]\nname = 1\ncontext_window = \"big\"\n",
        "[model.a]\ncontext_window = 0\n",
        "models = \"oops\"\n",
        "mcp_servers = \"oops\"\n",
        "model = [\"x\"]\n",
        "mcp_servers = [\"x\"]\n",
        "managed_mcps = []\n",
        "managed_mcps = \"oops\"\n",
        "[model]\na = \"x\"\n",
        "[model.a]\ncontext_window = -5\n",
        "[model.a]\ncontext_window = 1\n",
        "[model.a]\ncontext_window = 1023\n",
        "[model.a]\ncontext_window = 10000001\n",
        "[model.a]\ncontext_window = 9223372036854775807\n",
    ] {
        assert_eq!(
            apply_one(base, "v", patch),
            toml::from_str::<toml::Value>(base).unwrap(),
            "{patch}"
        );
    }
}

/// One note per campaign names the top-level keys it dropped, never their values.
#[test]
fn campaign_dropped_keys_are_noted_once_without_values() {
    apply_one(
        "[models]\ndefault = \"mine\"\n",
        "drop-note",
        "[models]\ndefault = \"a\"\n[features]\ntelemetry = \"secret-value-1\"\n[ui]\nyolo = true\n\
         [agent]\nname = \"secret-value-2\"\n",
    );
    let notes: Vec<String> = crate::key_naming::refusal_notes()
        .into_iter()
        .filter(|n| n.contains("campaign `drop-note`"))
        .collect();
    assert_eq!(notes.len(), 1, "{notes:?}");
    let note = &notes[0];
    for key in ["`agent`", "`features`", "`ui`"] {
        assert!(note.contains(key), "{note}");
    }
    assert!(
        !note.contains("secret-value") && !note.contains("`models`"),
        "{note}"
    );
}

/// The context window is bounded: the ends of the range apply, a value outside it is dropped.
#[test]
fn campaign_context_window_range_edges_apply() {
    for n in [1024, 10_000_000] {
        let effective = apply_one(
            "[model.a]\nname = \"Old\"\n",
            "w",
            &format!("[model.a]\ncontext_window = {n}\n"),
        );
        assert_eq!(
            effective["model"]["a"]["context_window"].as_integer(),
            Some(n),
            "{n}"
        );
    }
}

fn notes_for(prefix: &str) -> Vec<String> {
    crate::key_naming::refusal_notes()
        .into_iter()
        .filter(|n| n.contains(prefix))
        .collect()
}

/// The campaign id, a server name and the dropped-key list are cleaned and capped in notes.
#[test]
fn campaign_note_text_is_tidied_and_capped() {
    let id = format!("tidy-\u{1b}[2J{}", "a".repeat(200));
    let many: String = (0..20).map(|i| format!("k{i:02} = 1\n")).collect();
    apply_one(
        "[mcp_servers.\"ev\\u0007il\"]\ncommand = \"x\"\n",
        &id,
        &format!("{many}[mcp_servers.\"ev\\u0007il\"]\ncommand = \"y\"\n"),
    );
    let notes = notes_for("campaign `tidy-");
    assert!(notes.len() >= 2, "{notes:?}");
    for note in &notes {
        assert!(!note.chars().any(char::is_control), "{note:?}");
        assert!(note.len() < 600, "{note:?}");
        assert!(!note.contains(&"a".repeat(100)), "{note:?}");
    }
    assert!(notes.iter().any(|n| n.contains("and 12 more")), "{notes:?}");
}

/// A helper model changed by a campaign is announced once.
#[test]
fn campaign_helper_model_change_is_noted() {
    apply_one(
        "[models]\ndefault = \"mine\"\n",
        "helper-note",
        "[models]\nimage_description = \"vision-x\"\nsession_summary = \"sum-y\"\n",
    );
    let notes = notes_for("campaign `helper-note`");
    assert!(
        notes
            .iter()
            .any(|n| n.contains("image") && n.contains("`vision-x`")),
        "{notes:?}"
    );
    assert!(
        notes
            .iter()
            .any(|n| n.contains("summar") && n.contains("`sum-y`")),
        "{notes:?}"
    );
}

/// The overflow line of a scope does not claim every overflowed note was about the saved key.
#[test]
fn notice_overflow_line_is_neutral_for_plain_notes() {
    let scope = crate::key_naming::NoticeScope::new();
    scope.run(|| {
        for i in 0..(crate::key_naming::MAX_NOTES_PER_SCOPE + 3) {
            crate::key_naming::record_plain_note(format!("overflow-test plain note {i}"));
        }
    });
    let notes = scope.notes();
    let last = notes.last().expect("notes");
    assert!(last.starts_with("3 more notices"), "{last}");
    assert!(!last.contains("saved API key"), "{last}");
}

/// Every source reaches the same allowlist: a requirements/user layer campaign and a remote one.
#[test]
fn campaign_layer_and_remote_sources_go_through_the_allowlist() {
    let patch = |s: &str| toml::from_str::<toml::Table>(s).unwrap();
    let mut layers = crate::config_layers::ConfigLayers::default();
    layers.campaigns.user = vec![CampaignEntry {
        id: "layer-src".into(),
        patch: patch(
            "[models]\ndefault = \"layer-model\"\n[features]\nweb_fetch = true\n[ui]\nyolo = true\n",
        ),
    }];
    let remote = vec![CampaignEntry {
        id: "remote-src".into(),
        patch: patch(
            "[models]\nsession_summary = \"remote-sum\"\n[agent]\nname = \"x\"\n[model.r]\ncontext_window = 5\nname = \"R\"\n",
        ),
    }];
    let effective = layers.effective_config_with_campaigns(&remote, &Default::default());
    assert_eq!(effective["models"]["default"].as_str(), Some("layer-model"));
    assert_eq!(
        effective["models"]["session_summary"].as_str(),
        Some("remote-sum")
    );
    assert_eq!(effective["model"]["r"]["name"].as_str(), Some("R"));
    for dropped in [["features", "web_fetch"], ["ui", "yolo"], ["agent", "name"]] {
        assert!(get_path(&effective, &dropped).is_none(), "{dropped:?}");
    }
    assert!(get_path(&effective, &["model", "r", "context_window"]).is_none());
}

/// Only the sub-keys actually removed are named: a kept `models.default` does not put `models` in the note.
#[test]
fn campaign_note_names_only_what_was_removed() {
    apply_one(
        "[models]\ndefault = \"mine\"\n",
        "sub-note",
        "[models]\ndefault = \"a\"\nallowed_models = [\"x\"]\n[model.a]\nname = \"N\"\ncontext_window = 5\n",
    );
    let notes = notes_for("campaign `sub-note`");
    // The dropped keys, plus the one-time notice that the campaign renamed model `a` (outc7 F6)
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert!(
        notes[0].contains("`models.allowed_models`")
            && notes[0].contains("`model.a.context_window`"),
        "{}",
        notes[0]
    );
    assert!(
        !notes[0].contains("`models`") && !notes[0].contains("`model`"),
        "{}",
        notes[0]
    );
    assert!(
        notes[1].contains("display name of model `a` to `N`"),
        "{}",
        notes[1]
    );
}
