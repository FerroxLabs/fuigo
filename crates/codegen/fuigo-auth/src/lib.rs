//! Auth traits shared between `fuigo-file-utils` (the holder) and `fuigo-shell` (the implementer).
//! Keeps shell types out of data-collector's import graph while still letting refresh-aware token resolution drive HTTP requests.

pub mod auth_provider;
pub mod bearer_fragment;
#[cfg(feature = "middleware")]
pub mod retry_middleware;
pub mod visibility;

pub use auth_provider::{
    AuthCredentialProvider, BearerDestination, BearerDestinationRefused, BearerRule,
    CredentialSnapshot, StaticAuthCredentialProvider,
};
pub use bearer_fragment::{
    BearerFingerprint, FINGERPRINT_HEX_LEN, bearer_fingerprint, redact_url, redact_urls_in_text,
};
#[cfg(feature = "middleware")]
pub use retry_middleware::{
    AuthRetryMiddleware, EgressMiddleware, StampedBearerFingerprint, execute_with_stamp,
    find_bearer_refusal,
};
pub use visibility::HttpAuth;
