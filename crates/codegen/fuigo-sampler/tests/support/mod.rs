//! Sampler-specific helpers for the shared-HTTP-client integration binaries: config and request drivers for real `SamplingClient`s.
//! The generic connection-counting server lives in `fuigo_test_support`.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::Once;

use fuigo_sampler::{SamplerConfig, SamplingClient};
use fuigo_sampling_types::{ContentPart, ConversationItem, ConversationRequest, UserItem};

/// These wire tests own a dedicated binary: the pinned env latches
/// process-wide at first use and must not leak into or be poisoned by other
/// test binaries.
pub fn pin_env() {
    static PIN: Once = Once::new();
    // SAFETY: runs before any test builds a client; the kill switch, pool knobs, and OnceLock'd pool_idle_timeout latch once at first use, and racing tests block on the Once.
    PIN.call_once(|| unsafe {
        std::env::remove_var("FUIGO_SAMPLER_SHARED_CLIENT");
        std::env::set_var("FUIGO_POOL_MAX_IDLE", "2");
        std::env::set_var("FUIGO_POOL_IDLE_TIMEOUT_SECS", "90");
    });
}

pub async fn settle_pool() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

pub fn test_config(base_url: &str, api_key: &str) -> SamplerConfig {
    SamplerConfig {
        api_key: Some(api_key.to_string()),
        base_url: base_url.to_string(),
        model: "test-model".to_string(),
        ..SamplerConfig::default()
    }
}

/// Drive one POST through the client; the canned `{}` body is not a valid completion, but only the wire-level request matters here.
pub async fn send_one(client: &SamplingClient) {
    let request = ConversationRequest {
        items: vec![ConversationItem::User(UserItem {
            content: vec![ContentPart::Text {
                text: Arc::<str>::from("hi"),
            }],
            ..Default::default()
        })],
        ..Default::default()
    };
    let _ = client.conversation(request).await;
}
