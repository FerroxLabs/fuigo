//! review C7-01: a campaign model selector (`models.default`, `models.image_description`, `models.session_summary`)
//! may name a built-in or catalog model, but not one whose route the user (or their administrator) configured: that
//! would move the user's content to a destination they set up for something else.

use crate::campaigns::{CampaignEntry, apply_active_campaign_patches};

const SELECTORS: &[&str] = &["default", "image_description", "session_summary"];

/// Every `[model.<id>]` key that chooses where a request goes or what credential it carries.
const ROUTES: &[&str] = &[
    "base_url = \"https://mine.invalid/v1\"",
    "api_base_url = \"https://mine.invalid/v1\"",
    "model_provider = \"corp\"",
    "auth_provider = \"helper\"",
    "api_key = \"c701-not-a-real-key\"",
    "env_key = \"C701_KEY\"",
    "extra_headers = { X-C701 = \"v\" }",
    "env_http_headers = { X-C701 = \"C701_VAR\" }",
    "http_headers = { X-C701 = \"v\" }",
    "query_params = { c701 = \"v\" }",
    "mtls_cert_dir = \"/c701/certs\"",
];

fn apply(id: &str, base: &str, patch: &str) -> toml::Value {
    let mut effective: toml::Value = toml::from_str(base).unwrap();
    let patch: toml::Table = toml::from_str(patch).unwrap();
    apply_active_campaign_patches(&mut effective, &[CampaignEntry { id: id.into(), patch }]);
    effective
}

fn selector(effective: &toml::Value, sel: &str) -> Option<String> {
    effective.get("models")?.get(sel)?.as_str().map(str::to_owned)
}

#[test]
fn campaign_selector_naming_a_user_routed_model_is_dropped() {
    for route in ROUTES {
        for sel in SELECTORS {
            let base = format!("[models]\n{sel} = \"builtin-a\"\n[model.private]\n{route}\n");
            let effective = apply("c701-drop", &base, &format!("[models]\n{sel} = \"private\"\n"));
            assert_eq!(selector(&effective, sel).as_deref(), Some("builtin-a"), "{route} / {sel}");
            // With nothing set by the user the selector stays unset.
            let effective = apply("c701-drop", &format!("[model.private]\n{route}\n"), &format!("[models]\n{sel} = \"private\"\n"));
            assert_eq!(selector(&effective, sel), None, "{route} / {sel}");
        }
    }
    let notes = crate::key_naming::refusal_notes();
    let note = notes.iter().find(|n| n.contains("campaign `c701-drop`")).expect("a note for the dropped selector");
    assert!(note.contains("`models.default`") || note.contains("`models.image_description`") || note.contains("`models.session_summary`"), "{note}");
    assert!(!note.contains("private") && !note.contains("mine.invalid"), "the note names the key only: {note}");
}

#[test]
fn campaign_selector_naming_a_built_in_model_still_applies() {
    for sel in SELECTORS {
        // A model the user's config does not route (absent, or only display metadata) is the legitimate nudge.
        let base = format!("[models]\n{sel} = \"builtin-a\"\n[model.builtin-b]\nname = \"B\"\ncontext_window = 1000\n");
        let effective = apply("c701-keep", &base, &format!("[models]\n{sel} = \"builtin-b\"\n"));
        assert_eq!(selector(&effective, sel).as_deref(), Some("builtin-b"), "{sel}");
        let effective = apply("c701-keep", &base, &format!("[models]\n{sel} = \"catalog-c\"\n"));
        assert_eq!(selector(&effective, sel).as_deref(), Some("catalog-c"), "{sel}");
    }
    // No drop note (the helper-model change notice is expected).
    assert!(!crate::key_naming::refusal_notes().iter().any(|n| n.contains("campaign `c701-keep`") && n.contains("was ignored")));
}

/// Review M-2: the shell resolves a selector by table key and then by the wire name an entry sends (`model`, a
/// variant's `model_id`, an explicit `id`). Wire names are public, so a campaign must not reach a routed entry through
/// them either.
#[test]
fn campaign_selector_naming_a_routed_entrys_wire_name_is_dropped() {
    let base = "[models]\ndefault = \"builtin-a\"\n\
                [model.work]\nmodel = \"wire-name\"\nid = \"work-id\"\nbase_url = \"https://gw.invalid/v1\"\napi_key = \"c701-not-a-real-key\"\n\
                variants = [{ effort = \"high\", model_id = \"wire-name-high\" }]\n";
    for (sel, name) in SELECTORS.iter().flat_map(|sel| ["wire-name", "wire-name-high", "work-id"].map(|n| (*sel, n))) {
        let effective = apply("c701-wire", base, &format!("[models]\n{sel} = \"{name}\"\n"));
        let expected = (sel == "default").then_some("builtin-a");
        assert_eq!(selector(&effective, sel).as_deref(), expected, "{sel} = {name}");
    }
    // An unrouted entry's wire name is still a legitimate nudge.
    let base = "[model.plain]\nmodel = \"plain-wire\"\nname = \"Plain\"\n";
    let effective = apply("c701-wire-keep", base, "[models]\ndefault = \"plain-wire\"\n");
    assert_eq!(selector(&effective, "default").as_deref(), Some("plain-wire"));
}

/// Audit outc7 F6: a campaign that changes a model's display name says so once, naming the model and the new name.
#[test]
fn campaign_display_name_change_is_announced_once() {
    apply("f6-name", "[model.a]\nname = \"Old\"\n", "[model.a]\nname = \"Renamed F6\"\n");
    let notes = crate::key_naming::refusal_notes();
    let hits = notes
        .iter()
        .filter(|n| n.contains("campaign `f6-name`") && n.contains("display name of model `a`") && n.contains("Renamed F6"))
        .count();
    assert_eq!(hits, 1, "{notes:?}");
}
