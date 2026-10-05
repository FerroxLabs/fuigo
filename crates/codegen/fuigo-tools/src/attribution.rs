//! 401 attribution: callback hook + shared helpers for tool HTTP clients.

use std::sync::Arc;

pub use fuigo_auth::BearerFingerprint;

/// Which tool endpoint produced the 401.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolConsumer {
    ImageGen,
    VideoGenStart,
    VideoGenPoll,
    WebSearch,
}

impl ToolConsumer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ImageGen => "ImageGen",
            Self::VideoGenStart => "VideoGen.start",
            Self::VideoGenPoll => "VideoGen.poll",
            Self::WebSearch => "WebSearch",
        }
    }
}

/// 401 attribution callback. Shell wires this to emit telemetry.
pub trait Auth401AttributionCallback: Send + Sync + std::fmt::Debug {
    /// `sent_bearer` is the [`BearerFingerprint`] of the bearer that was sent: neither the bearer nor any fragment of
    /// it crosses this boundary. `None` = no bearer was sent.
    fn record_401(&self, consumer: ToolConsumer, sent_bearer: Option<&BearerFingerprint>);
}

/// Shared, cheap-to-clone alias for the attribution callback.
pub type SharedAttributionCallback = Arc<dyn Auth401AttributionCallback>;

/// Record a 401 if a callback is wired, fingerprinting the bearer first so only
/// the fingerprint ever reaches the callback.
pub(crate) fn emit_401(
    callback: Option<&SharedAttributionCallback>,
    consumer: ToolConsumer,
    sent_bearer: Option<&str>,
) {
    if let Some(cb) = callback {
        let fingerprint = sent_bearer.map(BearerFingerprint::of);
        cb.record_401(consumer, fingerprint.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_consumer_as_str_stable_identifiers() {
        assert_eq!(ToolConsumer::ImageGen.as_str(), "ImageGen");
        assert_eq!(ToolConsumer::VideoGenStart.as_str(), "VideoGen.start");
        assert_eq!(ToolConsumer::VideoGenPoll.as_str(), "VideoGen.poll");
        assert_eq!(ToolConsumer::WebSearch.as_str(), "WebSearch");
    }
}
