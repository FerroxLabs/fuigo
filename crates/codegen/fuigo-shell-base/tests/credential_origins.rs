//! A separate process owns this OnceLock fixture; it cannot widen other tests' trust.
use fuigo_shell_base::util::{is_configured_api_origin, set_trusted_api_origins};

#[test]
fn credential_admission_requires_exact_http_origin() {
    set_trusted_api_origins([
        "https://gateway.example/v1".to_string(),
        "https://custom.example:8443/v1".to_string(),
        "http://localhost:8080/v1".to_string(),
        "http://127.0.0.1:8081/v1".to_string(),
        "http://[::1]:8082/v1".to_string(),
        "https://user:password@invalid-owner.example/v1".to_string(),
    ]);
    for allowed in [
        "https://gateway.example/v1/chat/completions",
        "https://GATEWAY.example:443/another/path",
        "https://gateway.example./v1",
        "https://custom.example:8443/v1",
        "http://localhost:8080/v1",
        "http://127.0.0.1:8081/v1",
        "http://[::1]:8082/v1",
    ] {
        assert!(
            is_configured_api_origin(allowed),
            "rejected configured origin: {allowed}"
        );
    }
    for forbidden in [
        "https://gateway.example:9443/v1",
        "http://gateway.example/v1",
        "https://custom.example/v1",
        "http://localhost:9999/v1",
        "https://localhost:8080/v1",
        "http://127.0.0.1:8080/v1",
        "http://[::1]:8081/v1",
        "ftp://localhost:8080/v1",
        "ws://localhost:8080/v1",
        "https://user@gateway.example/v1",
        "https://user:password@gateway.example/v1",
        "https://gateway.example@attacker.example/v1",
        "https://gateway.example.attacker.example/v1",
        "https://invalid-owner.example/v1",
        "not-a-url",
    ] {
        assert!(
            !is_configured_api_origin(forbidden),
            "authorized unconfigured recipient: {forbidden}"
        );
    }
}
