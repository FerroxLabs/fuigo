use std::sync::atomic::{AtomicUsize, Ordering};

use super::{cached_client, client, client_cache_key};

#[test]
fn cache_key_changes_for_rotated_material_and_protocol() {
    let original = client_cache_key(b"certificate", b"private-key", false);
    assert!(original != client_cache_key(b"certificate-2", b"private-key", false));
    assert!(original != client_cache_key(b"certificate", b"private-key-2", false));
    assert!(original != client_cache_key(b"certificate", b"private-key", true));
}

#[test]
fn clients_are_reused_for_the_same_identity() {
    static BUILD_CALLS: AtomicUsize = AtomicUsize::new(0);
    let key = client_cache_key(b"cache-test-certificate", b"cache-test-key", false);
    let build = || {
        BUILD_CALLS.fetch_add(1, Ordering::SeqCst);
        reqwest::Client::builder().build()
    };
    assert!(cached_client(key.clone(), build).is_ok());
    assert!(
        cached_client(key, || -> Result<reqwest::Client, reqwest::Error> {
            panic!("cached client must be reused")
        })
        .is_ok()
    );
    assert_eq!(BUILD_CALLS.load(Ordering::SeqCst), 1);
}

/// A configured `mtls_cert_dir` whose identity cannot be read is a non-retryable `MtlsConfiguration` error,
/// never a silent fall-through to the uncredentialed shared client.
#[test]
fn unreadable_identity_dir_is_a_non_retryable_mtls_configuration_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no-such-identity");
    let error = client(&missing, false).expect_err("missing identity must fail");
    assert!(
        matches!(&error, fuigo_sampling_types::SamplingError::MtlsConfiguration(detail) if detail.contains("tls.crt")),
        "got {error:?}"
    );
    assert!(!error.is_retryable(), "an mTLS configuration error must not be retried");

    std::fs::write(dir.path().join("client.crt"), "not a certificate").unwrap();
    std::fs::write(dir.path().join("client.key"), "not a key").unwrap();
    let error = client(dir.path(), true).expect_err("garbage identity must fail");
    assert!(
        matches!(&error, fuigo_sampling_types::SamplingError::MtlsConfiguration(detail) if detail.contains("client.crt")),
        "got {error:?}"
    );
}
