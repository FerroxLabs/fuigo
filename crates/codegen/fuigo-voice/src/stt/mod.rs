//! Streaming speech-to-text over the configured voice endpoint's `/v1/stt`
//! WebSocket route. There is no default host: see `VoiceConfig::default`.

pub mod batch;
mod streaming;
mod types;

pub use streaming::{StreamingSttEvent, StreamingSttSession};
pub use types::{SttServerEvent, SttTranscriptPartial};
