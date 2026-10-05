//! P133: the saved key is bound to what a header's CONFIGURED text names, before the session id is substituted, so a
//! client-chosen session id cannot complete a reference after the saved-key refusal has run. Red first.

use super::*;

const KEY: &str = "p133-header-FAKE-0001";

#[test]
fn a_session_id_cannot_complete_a_key_reference_in_a_header() {
    // `${${session_id}}` holds no reference; with the id `FUIGO_API_KEY` the substitution would spell `${FUIGO_API_KEY}`.
    let headers = http_headers_for_server(
        vec![acp::HttpHeader::new("Authorization", "Bearer ${${session_id}}")],
        Some("FUIGO_API_KEY"),
        Some(KEY),
    );
    assert!(!headers[0].1.contains(KEY), "the saved key was bound to a reference the session id completed: {headers:?}");
}

#[test]
fn a_configured_reference_is_still_bound_and_the_session_id_still_substituted() {
    let headers = http_headers_for_server(
        vec![
            acp::HttpHeader::new("Authorization", "Bearer ${FUIGO_API_KEY}"),
            acp::HttpHeader::new("X-Session", "${session_id}"),
        ],
        Some("sess-1"),
        Some(KEY),
    );
    assert_eq!(headers[0].1, format!("Bearer {KEY}"));
    assert_eq!(headers[1].1, "sess-1");
}

/// P147 (e2e C1, B28): a trusted config's `${FUIGO_API_KEY:-dflt}` (key saved, not exported) reaches the server as the
/// saved key, not the default: the config loader keeps the reference and the header builder reads it. With no key at
/// all the default is sent, as in 1.0.20.
#[test]
fn a_defaulted_reference_in_a_header_sends_the_saved_key() {
    assert!(std::env::var_os("FUIGO_API_KEY").is_none(), "this test needs FUIGO_API_KEY unexported");
    let loaded = fuigo_config::expand_env_vars_in_string("Bearer ${FUIGO_API_KEY:-dflt}");
    assert_eq!(fuigo_config::expand_env_vars_in_string(&loaded), loaded, "a second load pass changed it");
    let with_key = http_headers_for_server(vec![acp::HttpHeader::new("Authorization", &loaded)], None, Some(KEY));
    assert_eq!(with_key[0].1, format!("Bearer {KEY}"), "loaded as {loaded:?}");
    let without = http_headers_for_server(vec![acp::HttpHeader::new("Authorization", &loaded)], None, None);
    assert_eq!(without[0].1, "Bearer dflt");
}
