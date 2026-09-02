//! Batch speech-to-text over an OpenAI-compatible `/v1/audio/transcriptions`
//! endpoint.
//!
//! A second transport, not a replacement. The streaming path
//! ([`super::StreamingSttSession`]) speaks a WebSocket protocol with interim
//! results; FluxRouter offers batch HTTP multipart and **explicitly refuses
//! streaming** -- probed against the live API:
//!
//! ```text
//! {"error":{"message":"streaming transcription is not supported",
//!           "type":"invalid_request_error","param":"stream"}}
//! ```
//!
//! So the shapes genuinely differ: audio is buffered for the whole utterance
//! and transcribed once on release. There is no live partial transcript.
//!
//! ## Verified request contract
//!
//! Probed against `api.fluxrouter.ai`, not inferred from documentation:
//!
//! | parameter | behaviour |
//! |---|---|
//! | `model` | `flux-voice`, `flux-voice-fast`, `flux-voice-accurate` all work |
//! | `response_format` | `json`, `text`, `verbose_json` only |
//! | `language=en` | honoured |
//! | `language` omitted | auto-detects (`"language":"English"`) |
//! | `language=auto` | **HTTP 502** -- a server error, not a clean rejection |
//!
//! The last row is why this does not reuse `crate::language_for_api`. That
//! helper resolves `auto` to a concrete code because the *WebSocket* API
//! rejects `auto`; here the parameter must be **omitted** instead. Sending a
//! concrete language when the user asked for auto is not harmless either --
//! `language=ja` on English audio returned `"language":"Japanese"` with the
//! English text, i.e. a confidently mislabelled result.

use crate::VoiceError;
use crate::config::VoiceConfig;

/// PCM format the mic capture produces, and therefore what the WAV header
/// written by [`pcm_to_wav`] must declare.
const BITS_PER_SAMPLE: u16 = 16;
const CHANNELS: u16 = 1;

/// Wrap raw little-endian 16-bit mono PCM in a minimal WAV container.
///
/// The capture path yields bare PCM, and the transcription endpoint needs a
/// container it can identify. A 44-byte canonical header is enough; no
/// dependency and no copy beyond the one allocation.
pub fn pcm_to_wav(pcm: &[u8], sample_rate: u32) -> Vec<u8> {
    let byte_rate = sample_rate * u32::from(CHANNELS) * u32::from(BITS_PER_SAMPLE) / 8;
    let block_align = CHANNELS * BITS_PER_SAMPLE / 8;
    let data_len = pcm.len() as u32;

    let mut wav = Vec::with_capacity(44 + pcm.len());
    wav.extend_from_slice(b"RIFF");
    // Everything after this field: 36 + data.
    wav.extend_from_slice(&(36 + data_len).to_le_bytes());
    wav.extend_from_slice(b"WAVE");
    wav.extend_from_slice(b"fmt ");
    wav.extend_from_slice(&16u32.to_le_bytes()); // PCM fmt chunk size
    wav.extend_from_slice(&1u16.to_le_bytes()); // format = PCM
    wav.extend_from_slice(&CHANNELS.to_le_bytes());
    wav.extend_from_slice(&sample_rate.to_le_bytes());
    wav.extend_from_slice(&byte_rate.to_le_bytes());
    wav.extend_from_slice(&block_align.to_le_bytes());
    wav.extend_from_slice(&BITS_PER_SAMPLE.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_len.to_le_bytes());
    wav.extend_from_slice(pcm);
    wav
}

/// The transcription endpoint for a configured voice base URL.
///
/// Refuses an unset base for the same reason `ws_url` does: this carries a
/// live microphone, so an unconfigured endpoint must be an explicit failure
/// rather than a guess or a malformed URL that fails later.
pub fn transcription_url(config: &VoiceConfig) -> Result<String, VoiceError> {
    let base = config.api_base.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err(VoiceError::Config(
            "voice endpoint is not configured: set `[voice].api_base` or \
             `[endpoints].fuigo_api_base_url` to the host that should receive \
             your microphone audio."
                .into(),
        ));
    }
    if base.starts_with("http://") {
        return Err(VoiceError::Config(format!(
            "insecure voice api_base {base:?}: voice requires TLS. Refusing to \
             send the bearer token, or your microphone audio, over a plaintext \
             connection."
        )));
    }
    let base = if base.starts_with("https://") {
        base.to_owned()
    } else {
        format!("https://{base}")
    };
    // Bases are commonly `.../v1` already; do not double it.
    if base.ends_with("/v1") {
        Ok(format!("{base}/audio/transcriptions"))
    } else {
        Ok(format!("{base}/v1/audio/transcriptions"))
    }
}

/// The `language` form field, or `None` when the endpoint should auto-detect.
///
/// `auto` must be OMITTED, never sent: the live API answers `language=auto`
/// with a 502. See the module docs.
pub fn language_field(config: &VoiceConfig) -> Option<&str> {
    let lang = config.language.trim();
    if lang.is_empty() || lang.eq_ignore_ascii_case("auto") {
        None
    } else {
        Some(lang)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(api_base: &str, language: &str) -> VoiceConfig {
        VoiceConfig {
            api_base: api_base.into(),
            language: language.into(),
            ..VoiceConfig::default()
        }
    }

    #[test]
    fn wav_header_is_canonical_and_declares_the_pcm_format() {
        let pcm = vec![0u8; 320];
        let wav = pcm_to_wav(&pcm, 16_000);
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[12..16], b"fmt ");
        assert_eq!(&wav[36..40], b"data");
        assert_eq!(wav.len(), 44 + pcm.len());
        // RIFF size counts everything after the size field itself.
        assert_eq!(
            u32::from_le_bytes(wav[4..8].try_into().unwrap()),
            36 + pcm.len() as u32
        );
        assert_eq!(u32::from_le_bytes(wav[40..44].try_into().unwrap()), 320);
        // 16 kHz, mono, 16-bit => 32000 bytes/sec
        assert_eq!(u32::from_le_bytes(wav[24..28].try_into().unwrap()), 16_000);
        assert_eq!(u32::from_le_bytes(wav[28..32].try_into().unwrap()), 32_000);
        assert_eq!(u16::from_le_bytes(wav[22..24].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(wav[34..36].try_into().unwrap()), 16);
    }

    #[test]
    fn empty_pcm_still_produces_a_valid_header() {
        let wav = pcm_to_wav(&[], 16_000);
        assert_eq!(wav.len(), 44);
        assert_eq!(u32::from_le_bytes(wav[40..44].try_into().unwrap()), 0);
    }

    #[test]
    fn url_appends_the_route_without_doubling_v1() {
        assert_eq!(
            transcription_url(&cfg("https://api.fluxrouter.ai/v1", "en")).unwrap(),
            "https://api.fluxrouter.ai/v1/audio/transcriptions"
        );
        assert_eq!(
            transcription_url(&cfg("https://api.example.com", "en")).unwrap(),
            "https://api.example.com/v1/audio/transcriptions"
        );
        assert_eq!(
            transcription_url(&cfg("https://api.example.com/", "en")).unwrap(),
            "https://api.example.com/v1/audio/transcriptions"
        );
        // Scheme-less bases are accepted and upgraded, as the WS path does.
        assert_eq!(
            transcription_url(&cfg("api.example.com/v1", "en")).unwrap(),
            "https://api.example.com/v1/audio/transcriptions"
        );
    }

    #[test]
    fn unset_endpoint_refuses_rather_than_guessing() {
        let err = transcription_url(&cfg("", "en")).unwrap_err();
        assert!(format!("{err}").contains("not configured"), "{err}");
        let err = transcription_url(&cfg("   ", "en")).unwrap_err();
        assert!(format!("{err}").contains("not configured"), "{err}");
    }

    #[test]
    fn plaintext_endpoint_is_refused() {
        let err = transcription_url(&cfg("http://api.example.com/v1", "en")).unwrap_err();
        assert!(format!("{err}").contains("TLS"), "{err}");
    }

    /// The live API answers `language=auto` with a 502, so it must never be
    /// sent. Omitting the field is what triggers auto-detection.
    #[test]
    fn auto_language_is_omitted_not_forwarded() {
        assert_eq!(language_field(&cfg("https://h/v1", "auto")), None);
        assert_eq!(language_field(&cfg("https://h/v1", "AUTO")), None);
        assert_eq!(language_field(&cfg("https://h/v1", "  auto  ")), None);
        assert_eq!(language_field(&cfg("https://h/v1", "")), None);
    }

    #[test]
    fn concrete_languages_are_forwarded() {
        assert_eq!(language_field(&cfg("https://h/v1", "en")), Some("en"));
        assert_eq!(language_field(&cfg("https://h/v1", "ja")), Some("ja"));
    }
}
