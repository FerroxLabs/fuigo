//! The trust set must fail CLOSED before configuration is loaded.
//!
//! This needs its own process: `TRUSTED_API_ORIGINS` is a `OnceLock`, so any
//! test that installs a value would poison an in-crate test of the
//! uninitialised state. Nothing here calls `set_trusted_api_origins`.
//!
//! The failure direction matters. Uninitialised means session-bearer auth does
//! not engage until config loads — inconvenient. The opposite default would
//! mean attaching a credential to an unvetted host.

use fuigo_shell_base::util::{
    is_fuigo_api_bearer_url, is_fuigo_api_url, is_trusted_fuigo_https_url, trusted_api_origins,
};

#[test]
fn trust_set_is_empty_before_configuration() {
    assert!(
        trusted_api_origins().is_empty(),
        "nothing may be trusted before configuration is installed"
    );
}

#[test]
fn no_host_is_first_party_before_configuration() {
    for url in [
        // The vendor this code was forked from must not be special.
        "https://api.x.ai/v1",
        "https://x.ai",
        "https://auth.x.ai/token",
        // Nor the router we actually ship against, until it is configured.
        "https://api.fluxrouter.ai/v1",
        "https://api.openai.com/v1",
        "https://api.anthropic.com/v1",
    ] {
        assert!(!is_fuigo_api_url(url), "refusal path trusted {url}");
        assert!(!is_fuigo_api_bearer_url(url), "bearer path trusted {url}");
        assert!(!is_trusted_fuigo_https_url(url), "https path trusted {url}");
    }
}
