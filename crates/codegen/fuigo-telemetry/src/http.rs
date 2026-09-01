//! Origin/client identification used by the telemetry engine.
//!
//! [`OriginClientInfo`] is owned by `fuigo-sampler` (so `SamplerConfig` can use it without depending on shell).
//! Re-exported here so the telemetry engine can label events without depending on shell or sampler internals beyond the type itself.

pub use fuigo_sampler::OriginClientInfo;

/// Construct an [`OriginClientInfo`] from the `FUIGO_CLIENT_NAME` / `FUIGO_CLIENT_VERSION` env vars.
/// Returns `None` when `FUIGO_CLIENT_NAME` is unset.
/// This is a free function rather than an inherent method because the type lives in another crate.
pub fn origin_client_info_from_env() -> Option<OriginClientInfo> {
    std::env::var("FUIGO_CLIENT_NAME")
        .ok()
        .map(|product| OriginClientInfo {
            product,
            version: std::env::var("FUIGO_CLIENT_VERSION").ok(),
        })
}
