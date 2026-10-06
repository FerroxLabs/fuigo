//! Parsing a config is not authority over the trust set.
//!
//! RENAMED from `trusted_origins_cannot_widen.rs`. That name, and the doc comment that
//! stood here, both claimed the trust set cannot widen. It can, and this file never tested
//! that it couldn't. An adversarial audit read the old name as evidence of immutability and
//! filed it as a test that "manufactures confidence in a path that does not execute" — half
//! right: the assertions below are sound, the name and the framing were not.
//!
//! WHAT IS PROVED HERE. Neither of the two non-authoritative routes can move the
//! process-wide set:
//!   * `Config::new_from_toml_cfg` — merely PARSING an attacker-supplied config changes
//!     nothing, however the endpoints are spelled.
//!   * `set_trusted_api_origins` — the seed entry point stays first-write-wins and is inert
//!     once a set exists or an authority has been claimed.
//! Both are real properties worth pinning, and they are the properties this file tests.
//!
//! WHAT IS NOT PROVED HERE, deliberately. That the set cannot widen at all. The
//! authoritative path — `resolve_runtime_fields` / `re_resolve_runtime_fields`, reached at
//! startup and from the background settings reapply that session creation spawns (once auth
//! resolves; coalesced while one is in flight) — republishes reloaded origins BY DESIGN,
//! because otherwise an endpoint the user edits goes on being refused the credential it was
//! issued for. Its sibling
//! `trusted_origins_follow_config.rs` asserts that widening as the intended fix.
//!
//! So the guarantee is about the AUTHORITY, not the value: `claim_trusted_origin_authority`
//! yields `Some` once and `None` forever after, and the config layer claims it at startup
//! before any plugin, MCP server or extension runs. Code arriving later cannot publish. The
//! config layer itself can, and every write it makes — seed or publish — is recorded, as what
//! the set admits per matcher tier, as a `TrustSetChange`: a `tracing` event, plus a unified-log
//! record that no tracing filter can suppress (asserted in `trusted_origins_follow_config.rs`).
//! Detection, since prevention here would break the feature.
//!
//! Read this file and `trusted_origins_follow_config.rs` together. Neither is complete alone.

use fuigo_shell::agent::config::{Config, RuntimeResolutionContext};
use fuigo_shell::util::{
    claim_trusted_origin_authority, is_configured_api_origin, is_fuigo_api_bearer_url,
    is_fuigo_api_url, set_trusted_api_origins, trusted_api_origins,
};

const CONFIGURED: &str = "https://gw.corp.example/v1";
const ATTACKER: &str = "https://attacker.example/v1";

#[test]
fn parsing_a_config_or_seeding_after_startup_cannot_move_the_trust_set() {
    // This binary drives the production publish path, which writes trust records to the
    // unified log; keep them out of the real `$FUIGO_HOME`.
    fuigo_telemetry::unified_log::redirect_to_temp_for_tests();
    unsafe {
        for var in [
            "FUIGO_API_BASE_URL",
            "FUIGO_MODELS_BASE_URL",
            "FUIGO_CLI_CHAT_PROXY_BASE_URL",
        ] {
            std::env::remove_var(var);
        }
    }

    let raw: toml::Value = toml::from_str(&format!(
        "[endpoints]\nfuigo_api_base_url = \"{CONFIGURED}\"\n"
    ))
    .unwrap();
    let mut config = Config::new_from_toml_cfg(&raw).expect("config should parse");
    config.resolve_runtime_fields(&RuntimeResolutionContext {
        raw_config: &raw,
        remote_settings: None,
        is_headless: true,
        cli_subagents: None,
        cli_web_search_model: None,
        cli_session_summary_model: None,
        memory_enabled_override: None,
        disable_web_search: false,
        todo_gate: false,
        laziness_debug_log: None,
        storage_mode: None,
        campaign_free_config: None,
    });
    assert!(is_fuigo_api_bearer_url(CONFIGURED));

    // The authority is one-shot, and the config layer took it at startup —
    // before any plugin, MCP server or extension code runs. Code that runs
    // later cannot obtain one, so it cannot publish.
    assert!(
        claim_trusted_origin_authority().is_none(),
        "a second publishing authority must never be issued"
    );

    // The seed entry point stays first-write-wins, so it cannot widen either.
    assert!(
        set_trusted_api_origins([ATTACKER.to_string()]).is_none(),
        "a seed after the authority is claimed must be inert, and report itself as such"
    );
    assert!(
        !is_fuigo_api_url(ATTACKER),
        "refusal path trusted {ATTACKER}"
    );
    assert!(
        !is_fuigo_api_bearer_url(ATTACKER),
        "bearer path trusted {ATTACKER}"
    );
    assert!(!is_configured_api_origin(ATTACKER));
    assert_eq!(trusted_api_origins(), vec![CONFIGURED.to_string()]);

    // Nor can a later `Config` parse: parsing is not authority.
    let widened: toml::Value = toml::from_str(&format!(
        "[endpoints]\nfuigo_api_base_url = \"{ATTACKER}\"\n"
    ))
    .unwrap();
    let _ = Config::new_from_toml_cfg(&widened).expect("config should parse");
    assert!(!is_fuigo_api_bearer_url(ATTACKER));
    assert!(is_fuigo_api_bearer_url(CONFIGURED));
}
