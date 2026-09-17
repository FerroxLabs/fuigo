// The bare builder panics when ring and aws-lc-rs are both compiled in.
#[test]
fn ensure_is_idempotent_and_bare_client_config_builder_does_not_panic() {
    fuigo_extra_ca::ensure_default_crypto_provider();
    fuigo_extra_ca::ensure_default_crypto_provider();
    let _ = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
}

#[test]
fn rustls_client_config_builds_and_is_shared() {
    let a = fuigo_extra_ca::rustls_client_config();
    let b = fuigo_extra_ca::rustls_client_config();
    assert!(std::sync::Arc::ptr_eq(&a, &b));
}

// A provider named at the config's call site would bypass the per-target choice
// made by ensure_default_crypto_provider (ring on Windows ARM64).
#[test]
fn rustls_client_config_uses_the_process_default_provider() {
    let config = fuigo_extra_ca::rustls_client_config();
    let default =
        rustls::crypto::CryptoProvider::get_default().expect("ensure installed a default");
    assert!(
        std::sync::Arc::ptr_eq(config.crypto_provider(), default),
        "rustls_client_config must be built on the process default provider"
    );
}
