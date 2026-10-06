//! A configuration reload must move the user-configured API origin set (credential delivery) with it.
//!
//! ITS OWN PROCESS, TWICE OVER.
//! The trust set has a process-wide default, so a test that installs one
//! decides the answer for every other test in the same binary — which is why
//! `fuigo-shell-base/tests/credential_origins.rs` and `tests/trust_fails_closed.rs`
//! are separate files, and why this one is too.
//!
//! It also has to be an INTEGRATION test rather than a unit test. `Config::
//! install_trusted_api_origins` is `#[cfg(test)]`-pinned to a fixture set, so
//! no unit test in `fuigo-shell` can reach the arm that turns `[endpoints]`
//! into the trust set. An integration test links the library compiled WITHOUT
//! `cfg(test)`, so this is the production path.
//!
//! THE DEFECT THIS PINS
//! The store used to be a `OnceLock`, so a `Config` that became live with other
//! endpoints than the first one could not move the process-wide set:
//! `session_may_be_sent_to` and `env_api_key_may_be_sent_to` then returned false
//! against the stale set, the credential was silently dropped, and every request
//! went out unauthenticated — 401, with only a `tracing::warn`, until a restart.
//! (P150: the set published is always the one for the endpoints that `Config`
//! sends to; a re-read `[endpoints]` edit does not move a running agent's
//! endpoints, so it does not move the set either. See
//! `an_endpoints_edit_keeps_credentials_on_the_endpoint_in_use`.)
//!
//! THE RECORD THIS ALSO PINS
//! The set can move — that is the fix — so every write to it is recorded. The
//! record that counts is the unified log (`$FUIGO_HOME/logs/unified.jsonl`): it is
//! written in every mode and has no level filter, where the default `tracing`
//! subscribers drop most events (headless stderr is `off`). Step 6 asserts that the
//! process baseline and every movement land there, as what the set admits per matcher
//! tier, and that nothing a configured endpoint can carry beyond its origin ever does.

use fuigo_shell::agent::config::{Config, RuntimeResolutionContext};
use fuigo_shell::util::{is_configured_api_origin, is_fuigo_api_bearer_url, is_fuigo_api_url};

const FIRST: &str = "https://first.gateway.example/v1";
const SECOND: &str = "https://second.gateway.example/v1";

fn config_for(base_url: &str) -> Config {
    let raw: toml::Value = toml::from_str(&format!(
        "[endpoints]\nfuigo_api_base_url = \"{base_url}\"\n"
    ))
    .expect("fixture parses");
    Config::new_from_toml_cfg(&raw).expect("config should parse")
}

fn make_live(config: &mut Config, raw: &toml::Value) {
    config.resolve_runtime_fields(&RuntimeResolutionContext {
        raw_config: raw,
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
}

#[test]
fn a_reloaded_endpoint_becomes_first_party() {
    // Trust records go to the unified log; send them to a private temp file so this
    // test can read them back, and so they stay out of the real `$FUIGO_HOME`.
    fuigo_telemetry::unified_log::redirect_to_temp_for_tests();

    // Inherited endpoint env would widen `[endpoints]` behind the fixture.
    unsafe {
        for var in [
            "FUIGO_API_BASE_URL",
            "FUIGO_MODELS_BASE_URL",
            "FUIGO_CLI_CHAT_PROXY_BASE_URL",
        ] {
            std::env::remove_var(var);
        }
    }

    // 1. Startup. The first config publishes its origins.
    let first_raw: toml::Value =
        toml::from_str(&format!("[endpoints]\nfuigo_api_base_url = \"{FIRST}\"\n")).unwrap();
    let mut first = config_for(FIRST);
    make_live(&mut first, &first_raw);
    assert!(
        is_fuigo_api_bearer_url(FIRST),
        "the configured endpoint must be a configured API origin at startup"
    );
    assert!(is_fuigo_api_url(FIRST));
    assert!(is_configured_api_origin(FIRST));

    // 2. The INJECTABLE set follows the config with no global involved at all,
    //    which is what makes the mapping assertable in any order.
    let second = config_for(SECOND);
    assert!(second.trusted_origins().is_fuigo_api_bearer_url(SECOND));
    assert!(!second.trusted_origins().is_fuigo_api_bearer_url(FIRST));
    assert!(first.trusted_origins().is_fuigo_api_bearer_url(FIRST));

    // 3. Merely PARSING a config must not move the process-wide set. The
    //    reloader parses an OLD config to diff it against a new one, and
    //    one-shot commands parse stripped tables; none of those is authority.
    assert!(
        !is_fuigo_api_bearer_url(SECOND),
        "a bare `new_from_toml_cfg` must not be able to widen the trust set"
    );

    // 4. THE FIX. The authoritative path — startup, and the settings-reapply
    //    path via `re_resolve_runtime_fields` — republishes, so the credential
    //    guards follow the user's own endpoint instead of 401ing against a
    //    frozen one.
    let second_raw: toml::Value =
        toml::from_str(&format!("[endpoints]\nfuigo_api_base_url = \"{SECOND}\"\n")).unwrap();
    let mut second = second;
    make_live(&mut second, &second_raw);
    assert!(
        is_fuigo_api_bearer_url(SECOND),
        "a reloaded endpoint must become a configured API origin: this is the silent-401 bug"
    );
    assert!(
        is_configured_api_origin(SECOND),
        "FUIGO_API_KEY must be attachable to the reloaded endpoint"
    );

    // 5. And the superseded origin stops being a configured API origin: a reload REPLACES
    //    the set, it does not accumulate one.
    assert!(
        !is_fuigo_api_bearer_url(FIRST),
        "the superseded endpoint must not stay trusted: trust must not accumulate"
    );

    // 6. THE RECORD. A third reload to an endpoint whose string carries userinfo, a
    //    query-string token and a path — everything an origin is not.
    const THIRD: &str =
        "https://alice:hunter2@third.gateway.example/v1/tenant-9f3a?api_key=sk-live-123";
    let third_raw: toml::Value =
        toml::from_str(&format!("[endpoints]\nfuigo_api_base_url = \"{THIRD}\"\n")).unwrap();
    let mut third = Config::new_from_toml_cfg(&third_raw).expect("config should parse");
    make_live(&mut third, &third_raw);

    let log = String::from_utf8(
        fuigo_telemetry::unified_log::snapshot_log().expect("the unified log was written"),
    )
    .expect("unified log is UTF-8");
    let records: Vec<serde_json::Value> = log
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|r| {
            r["msg"]
                .as_str()
                .is_some_and(|m| m.starts_with("trusted API origins"))
        })
        .collect();
    let summary: Vec<(String, serde_json::Value)> = records
        .iter()
        .map(|r| {
            (
                r["msg"].as_str().unwrap_or_default().to_owned(),
                r["ctx"].clone(),
            )
        })
        .collect();
    // Each record says what the set ADMITS, per matcher tier: `origins` for the
    // strict credential tier, `hosts` for the host-only tier.
    let expected = vec![
        // Installed by the SEED path at the first parse: the process baseline.
        (
            "trusted API origins: process baseline".to_owned(),
            serde_json::json!({ "via": "seed", "current": {
                "origins": ["https://first.gateway.example"],
                "hosts": ["first.gateway.example"],
            }}),
        ),
        // Step 4's reload.
        (
            "trusted API origins WIDENED".to_owned(),
            serde_json::json!({
                "via": "authority",
                "added": { "origins": ["https://second.gateway.example"], "hosts": ["second.gateway.example"] },
                "removed": { "origins": ["https://first.gateway.example"], "hosts": ["first.gateway.example"] },
                "previous": { "origins": ["https://first.gateway.example"], "hosts": ["first.gateway.example"] },
                "current": { "origins": ["https://second.gateway.example"], "hosts": ["second.gateway.example"] },
            }),
        ),
        // Step 6's reload. The endpoint carries userinfo, so the strict tier admits
        // NOTHING for it -- only its host is admitted, by the host-only tier.
        (
            "trusted API origins WIDENED".to_owned(),
            serde_json::json!({
                "via": "authority",
                "added": { "origins": [], "hosts": ["third.gateway.example"] },
                "removed": { "origins": ["https://second.gateway.example"], "hosts": ["second.gateway.example"] },
                "previous": { "origins": ["https://second.gateway.example"], "hosts": ["second.gateway.example"] },
                "current": { "origins": [], "hosts": ["third.gateway.example"] },
            }),
        ),
    ];
    assert_eq!(
        summary, expected,
        "exactly one baseline and one record per movement; unchanged republishes \
         (startup, step 3's parse) are not recorded"
    );
    // These strings exist only inside the configured endpoint, so they must appear
    // nowhere in the log; the path is checked on the trust records themselves, since
    // other components may legitimately log a URL path of their own.
    for leaked in ["alice", "hunter2", "tenant-9f3a", "api_key", "sk-live"] {
        assert!(
            !log.contains(leaked),
            "the unified log must never carry `{leaked}` from a configured endpoint"
        );
    }
    let recorded = serde_json::to_string(&records).expect("records serialize");
    assert!(
        !recorded.contains("/v1"),
        "a trust record carried a path: {recorded}"
    );
}
