//! For a token that is not a JWT, `parse_jwt_expiration` returns `None` and `is_jwt_expired_or_near` returns `false`.

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

/// Install a JWT crypto provider exactly once per process.
///
/// `jsonwebtoken` 10 panics rather than erroring when it cannot pick a provider
/// from its own features, so exactly one of `rust_crypto` and `aws_lc_rs` must
/// be enabled in a process. Until the `jwt-rust-crypto` change to
/// `[workspace.dependencies] gcloud-storage` and to the vendored
/// `gcloud-auth-1.3.0` manifest, BOTH were: `fuigo-shell` asked for
/// `rust_crypto` while `fuigo-file-utils -> gcloud-storage -> gcloud-auth`
/// turned on `jsonwebtoken/aws_lc_rs`. Cargo unified them,
/// `CryptoProvider::from_crate_features` matched neither `cfg` arm, and every
/// signature -- including the service-account JWT the GCS upload path signs in
/// the shipped binary -- hit its panicking placeholder provider.
///
/// The feature choice now makes `from_crate_features` resolve to `rust_crypto`
/// on its own, so this call is no longer what stands between a token and a
/// panic. It is kept because it is explicit and free: `install_default` returns
/// Err if a provider is already installed, which is ignored -- first install
/// wins, and it installs the same backend the features select.
pub fn ensure_jwt_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
    });
}

#[derive(Deserialize)]
struct Claims {
    exp: Option<i64>,
}

pub fn parse_jwt_expiration(token: &str) -> Option<DateTime<Utc>> {
    ensure_jwt_crypto_provider();
    jsonwebtoken::dangerous::insecure_decode::<Claims>(token)
        .ok()
        .and_then(|data| data.claims.exp)
        .and_then(|ts| DateTime::from_timestamp(ts, 0))
}

pub fn is_jwt_expired_or_near(token: &str, threshold: Duration) -> bool {
    parse_jwt_expiration(token)
        .map(|exp| exp <= Utc::now() + threshold)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tokens with an `aud` claim must parse successfully.
    /// `jsonwebtoken::Validation::default()` enables audience validation which silently rejects these tokens unless `validate_aud = false` is set.
    #[test]
    fn parses_jwt_with_aud_claim() {
        let token = build_test_jwt(r#"{"aud":["some-audience"],"exp":1772575524}"#);
        let exp = parse_jwt_expiration(&token);
        assert_eq!(exp.unwrap().timestamp(), 1772575524);
    }

    fn build_test_jwt(payload_json: &str) -> String {
        use base64::Engine;
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = enc.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = enc.encode(payload_json);
        format!("{header}.{payload}.fake-signature")
    }
}
