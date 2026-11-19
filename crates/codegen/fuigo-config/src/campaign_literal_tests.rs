//! Campaign values are literals: a `${VAR}` in a `[[campaigns]]` entry is never read from the environment, on load or
//! at use. `PATH` is the reference: it is set in every test environment, so an expansion would show.

use crate::campaigns::{CampaignEntry, apply_active_campaign_patches, take_campaign_entries};
use crate::config_layers::ConfigLayers;

fn parse(s: &str) -> toml::Value {
    toml::from_str(s).unwrap()
}

const CAMPAIGN_SERVER: &str = "[mcp_servers.fresh]\nurl = \"https://h.invalid/mcp?k=${PATH}\"\n\
     command = \"srv\"\nargs = [\"--k=${PATH}\", \"$PATH\"]\ncwd = \"${PATH}\"\n";

fn assert_literal(effective: &toml::Value) {
    let fresh = &effective["mcp_servers"]["fresh"];
    assert_eq!(
        fresh["url"].as_str(),
        Some("https://h.invalid/mcp?k=${PATH}"),
        "{fresh:?}"
    );
    assert_eq!(fresh["args"][0].as_str(), Some("--k=${PATH}"), "{fresh:?}");
    assert_eq!(fresh["args"][1].as_str(), Some("$PATH"), "{fresh:?}");
    assert_eq!(fresh["cwd"].as_str(), Some("${PATH}"), "{fresh:?}");
}

/// A user-layer campaign survives the disk loader's expansion unchanged; the user's own entries still expand.
#[test]
fn user_layer_campaign_strings_stay_literal_through_load_and_merge() {
    for layer_name in ["user", "managed"] {
        let mut layer = parse(&format!(
            "[mcp_servers.own]\nurl = \"https://own.invalid/mcp?k=${{PATH}}\"\n\
             [[campaigns]]\nid = \"c\"\n[campaigns.models]\ndefault = \"${{PATH}}\"\n{}",
            CAMPAIGN_SERVER.replace("[mcp_servers.fresh]", "[campaigns.mcp_servers.fresh]")
        ));
        crate::expand_env_vars_in_toml(&mut layer);
        let own = layer["mcp_servers"]["own"]["url"].as_str().unwrap();
        assert!(
            !own.contains("${PATH}"),
            "the user's own server must still expand: {own}"
        );
        let entries = take_campaign_entries(
            &mut layer,
            if layer_name == "user" {
                "user"
            } else {
                "managed"
            },
        );
        assert_eq!(entries.len(), 1);
        let mut layers = ConfigLayers {
            user: layer,
            ..Default::default()
        };
        layers.campaigns.user = entries;
        let effective =
            layers.effective_config_with_campaigns(&[], &std::collections::HashSet::new());
        assert_literal(&effective);
        assert_eq!(effective["models"]["default"].as_str(), Some("${PATH}"));
    }
}

/// A remote or `FUIGO_CAMPAIGNS_OVERRIDE`-shaped entry (a patch handed over directly) keeps its strings too.
#[test]
fn remote_shaped_campaign_strings_stay_literal() {
    let patch: toml::Table = toml::from_str(CAMPAIGN_SERVER).unwrap();
    let entries = vec![CampaignEntry {
        id: "r".into(),
        patch,
    }];
    let mut effective = parse("[models]\ndefault = \"a\"\n");
    apply_active_campaign_patches(&mut effective, &entries);
    assert_literal(&effective);
    assert_eq!(
        effective["mcp_servers"]["fresh"]["__fuigo_campaign_source"].as_bool(),
        Some(true)
    );
}

fn entry(id: &str, toml_src: &str) -> Vec<CampaignEntry> {
    vec![CampaignEntry {
        id: id.into(),
        patch: toml::from_str(toml_src).unwrap(),
    }]
}

/// review C3-2: a campaign may still ADD a stdio server, and the user is told which program it runs.
#[test]
fn campaign_added_stdio_server_is_kept_and_names_its_program() {
    let entries = entry(
        "c32",
        "[mcp_servers.helper]\ncommand = \"c32-program\"\nargs = [\"--x\"]\n",
    );
    let mut effective = parse("[models]\ndefault = \"a\"\n");
    apply_active_campaign_patches(&mut effective, &entries);
    assert_eq!(
        effective["mcp_servers"]["helper"]["command"].as_str(),
        Some("c32-program")
    );
    assert_eq!(
        effective["mcp_servers"]["helper"]["__fuigo_campaign_source"].as_bool(),
        Some(true)
    );
    let notes = crate::key_naming::refusal_notes();
    let note = notes
        .iter()
        .find(|n| n.contains("campaign `c32`"))
        .expect("a notice for the added program");
    assert!(
        note.contains("`helper`") && note.contains("`c32-program`"),
        "{note}"
    );
    assert!(!note.contains("--x"), "arguments are not echoed: {note}");
}

/// review C3-2: an HTTP-only campaign server runs no program and gets no program notice.
#[test]
fn campaign_added_http_server_gets_no_program_notice() {
    let entries = entry(
        "c32h",
        "[mcp_servers.web]\nurl = \"https://h.invalid/mcp\"\n",
    );
    let mut effective = parse("[models]\ndefault = \"a\"\n");
    apply_active_campaign_patches(&mut effective, &entries);
    assert_eq!(
        effective["mcp_servers"]["web"]["url"].as_str(),
        Some("https://h.invalid/mcp")
    );
    assert!(
        !crate::key_naming::refusal_notes()
            .iter()
            .any(|n| n.contains("campaign `c32h`"))
    );
}

/// review R3-5: the campaign marker is honoured only when the campaign merge set it; any other layer loses it.
#[test]
fn campaign_marker_in_a_non_campaign_layer_is_dropped() {
    let forged = "[mcp_servers.mine]\nurl = \"https://own.invalid/mcp?k=${PATH}\"\n__fuigo_campaign_source = true\n";
    let layers = ConfigLayers {
        user: parse(forged),
        managed: parse(forged),
        system_managed: parse(forged),
        env_overlay: Some(parse(forged)),
        ..Default::default()
    };
    let effective = layers.effective_config_with_campaigns(&[], &std::collections::HashSet::new());
    assert!(
        effective["mcp_servers"]["mine"]
            .get("__fuigo_campaign_source")
            .is_none(),
        "{effective:?}"
    );
    let base = layers.effective_config_base_without_overlay();
    assert!(
        base["mcp_servers"]["mine"]
            .get("__fuigo_campaign_source")
            .is_none(),
        "{base:?}"
    );
}

/// review C1-5: a campaign's refusal note does not send the user to edit an entry that is not in their file.
#[test]
fn campaign_saved_key_refusal_note_is_campaign_specific() {
    let entries = entry(
        "c15",
        &format!(
            "[mcp_servers.k]\ncommand = \"srv\"\nargs = [\"${{{}}}\"]\n",
            crate::credential_env::FIRST_PARTY_KEY_ENV_VAR
        ),
    );
    let mut effective = parse("[models]\ndefault = \"a\"\n");
    apply_active_campaign_patches(&mut effective, &entries);
    let notes = crate::key_naming::refusal_notes();
    let note = notes
        .iter()
        .find(|n| n.contains("`mcp_servers.k.args[0]`"))
        .expect("a refusal note for the campaign");
    assert!(
        note.contains("campaign `c15`") && note.contains("which a campaign may not use"),
        "{note}"
    );
    assert!(
        !note.contains("delete the marker line") && !note.contains("Move this entry"),
        "{note}"
    );
}

/// Grok C4: a project `.fuigo/config.toml` cannot carry the campaign marker either (it would skip env expansion).
#[test]
fn campaign_marker_in_a_project_file_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_dir = dir.path().join(".fuigo");
    #[allow(clippy::disallowed_methods, reason = "test fixture in a temp dir")]
    {
        std::fs::create_dir_all(&cfg_dir).unwrap();
        std::fs::write(
            cfg_dir.join("config.toml"),
            "[mcp_servers.p]\nurl = \"https://h.invalid/mcp\"\n__fuigo_campaign_source = true\n",
        )
        .unwrap();
    }
    let loaded = crate::loader::load_project_config_file(&cfg_dir.join("config.toml")).unwrap();
    assert!(
        loaded["mcp_servers"]["p"]
            .get("__fuigo_campaign_source")
            .is_none(),
        "{loaded:?}"
    );
}
