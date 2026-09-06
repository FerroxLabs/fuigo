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
    // Case-insensitively, because RFC 3986 schemes are: `HTTP://` must hit the
    // plaintext rejection and `HTTPS://` must be recognised rather than being
    // treated as scheme-less and rewritten to `https://HTTPS://...`. The
    // streaming path already did this; batch did not, so the same `api_base`
    // worked on one transport and produced an opaque parse error on the other.
    let starts_with_ci = |s: &str, prefix: &str| {
        s.get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
    };
    if starts_with_ci(base, "http://") {
        return Err(VoiceError::Config(format!(
            "insecure voice api_base {base:?}: voice requires TLS. Refusing to \
             send the bearer token, or your microphone audio, over a plaintext \
             connection."
        )));
    }
    let base = if starts_with_ci(base, "https://") {
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

/// Hard ceiling on the transcription response body.
///
/// A transcription response is a few hundred bytes of JSON. Reading it
/// unbounded would let a hostile or broken endpoint stream until the pager
/// runs out of memory, and there is no legitimate body anywhere near this.
const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// How long the TCP+TLS connect may take before the attempt is abandoned.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long the whole request may take, upload included.
///
/// Batch transcription is record-then-send, so this covers uploading up to the
/// recording cap and waiting for the model. It is deliberately generous, and
/// deliberately finite: without it a stalled endpoint leaves the user staring
/// at a "transcribing" state with no way to learn it will never finish.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// A client for `POST /v1/audio/transcriptions`.
///
/// Built at most once for the lifetime of a voice pipeline (the caller holds it
/// in a `OnceCell`), not per utterance, so the TLS session and connection pool
/// survive across every press.
#[derive(Debug, Clone)]
pub struct BatchSttClient {
    http: reqwest::Client,
}

impl BatchSttClient {
    /// Build the client through the sanctioned constructor.
    ///
    /// `build_reqwest_client` installs the egress guard resolver and the shared
    /// root store, and it installs the resolver *after* this closure runs so
    /// the configuration below cannot displace it.
    ///
    /// Redirects are disabled outright. reqwest does strip `Authorization` when
    /// a redirect crosses hosts, so the credential is not the exposure here --
    /// the recording is. A 307 or 308 replays the request body, so a redirect
    /// would send the user's microphone audio to a host chosen by the server's
    /// response rather than by their config, after the endpoint check in
    /// [`crate::auth`] had already passed on the original URL.
    pub fn new() -> Result<Self, VoiceError> {
        let http = fuigo_extra_ca::build_reqwest_client(|builder| {
            builder
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
        })
        .map_err(|e| VoiceError::Stt(format!("could not build the transcription client: {e}")))?;
        Ok(Self { http })
    }

    /// Transcribe one complete utterance.
    ///
    /// `wav` is a full WAV file, normally from [`pcm_to_wav`]. The request is
    /// sent exactly once: a POST carrying a recording is not idempotent from
    /// the endpoint's point of view (it is metered, and may be logged), so a
    /// transparent retry would duplicate a charge and a copy of the user's
    /// audio. A caller who wants a second attempt has to ask for one.
    pub async fn transcribe(
        &self,
        config: &VoiceConfig,
        bearer: &str,
        wav: Vec<u8>,
    ) -> Result<String, VoiceError> {
        let url = transcription_url(config)?;

        let part = reqwest::multipart::Part::bytes(wav)
            .file_name("audio.wav")
            .mime_str("audio/wav")
            .map_err(|e| VoiceError::Stt(format!("multipart: {e}")))?;
        let mut form = reqwest::multipart::Form::new()
            .part("file", part)
            .text("model", config.stt_model.clone())
            .text("response_format", "json");
        // Omitted, never sent as `auto`: the live endpoint answers
        // `language=auto` with a 502. See the module docs.
        if let Some(language) = language_field(config) {
            form = form.text("language", language.to_owned());
        }

        let mut request = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {bearer}"));
        // Attribution headers, matching the streaming transport. Skipped when
        // empty (the probe binary and tests); their absence is never fatal.
        if !config.client_identifier.is_empty() {
            request = request.header("x-fuigo-client-identifier", &config.client_identifier);
        }
        if !config.user_agent.is_empty() {
            request = request.header("User-Agent", &config.user_agent);
        }

        let response = fuigo_extra_ca::dispatch::send(request.multipart(form))
            .await
            .map_err(|e| {
                // `reqwest`'s Display for a timeout is opaque; name it, because
                // "the endpoint never answered" and "the endpoint refused" need
                // different things from the user.
                if e.is_timeout() {
                    VoiceError::Stt(format!(
                        "transcription timed out after {}s",
                        REQUEST_TIMEOUT.as_secs()
                    ))
                } else if e.is_connect() {
                    VoiceError::Stt(format!("could not reach the voice endpoint: {e}"))
                } else {
                    VoiceError::Stt(format!("transcription request failed: {e}"))
                }
            })?;

        let status = response.status();
        let body = read_bounded(response).await?;
        if !status.is_success() {
            return Err(status_error(status, &body));
        }

        let parsed: TranscriptionResponse = serde_json::from_slice(&body).map_err(|e| {
            VoiceError::Stt(format!(
                "could not parse the transcription response: {e} (body: {})",
                String::from_utf8_lossy(&body[..body.len().min(200)])
            ))
        })?;
        Ok(parsed.text)
    }
}

/// The `json` response format's shape. Other fields (`language`, `duration`)
/// are ignored rather than modelled: only the transcript is used.
#[derive(serde::Deserialize)]
struct TranscriptionResponse {
    text: String,
}

/// Read at most [`MAX_RESPONSE_BYTES`], refusing rather than truncating.
///
/// Truncating would hand a partial JSON document to the parser and produce a
/// parse error that hides the real problem.
async fn read_bounded(mut response: reqwest::Response) -> Result<Vec<u8>, VoiceError> {
    // Trust the advertised length only to refuse early; never to size the
    // buffer, since a header can claim anything.
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        return Err(VoiceError::Stt(
            "transcription response is implausibly large; refusing to read it".into(),
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| VoiceError::Stt(format!("reading the transcription response: {e}")))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(VoiceError::Stt(
                "transcription response is implausibly large; refusing to read it".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Map a non-2xx status onto an error the user can act on.
///
/// Split by what the user has to do about it, not by status class: an expired
/// credential means re-authenticate, a 429 means wait, a 5xx means it is not
/// their fault.
pub(crate) fn status_error(status: reqwest::StatusCode, body: &[u8]) -> VoiceError {
    let detail = server_message(body);
    let suffix = detail.map(|d| format!(": {d}")).unwrap_or_default();
    match status.as_u16() {
        401 | 403 => VoiceError::Auth(format!(
            "the voice endpoint rejected the credential ({status}){suffix}. \
             Run `fuigo login` or check your API key."
        )),
        404 => VoiceError::Stt(format!(
            "the voice endpoint has no transcription route ({status}){suffix}. \
             Check `[voice].api_base`."
        )),
        413 => VoiceError::Stt(format!(
            "the recording was rejected as too large ({status}){suffix}."
        )),
        429 => VoiceError::Stt(format!(
            "the voice endpoint is rate limiting this request ({status}){suffix}. \
             Wait a moment and try again."
        )),
        500..=599 => VoiceError::Stt(format!(
            "the voice endpoint failed ({status}){suffix}. This is not a problem \
             with your audio; try again."
        )),
        _ => VoiceError::Stt(format!("transcription failed ({status}){suffix}")),
    }
}

/// The server's own error text, if the body is the usual
/// `{"error":{"message":...}}` or `{"error":"..."}` shape.
///
/// Bounded, because this text is echoed into a toast: a hostile endpoint must
/// not be able to write an arbitrarily long message into the UI.
fn server_message(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let error = value.get("error")?;
    let message = error
        .get("message")
        .and_then(serde_json::Value::as_str)
        .or_else(|| error.as_str())?;
    let message = message.trim();
    if message.is_empty() {
        return None;
    }
    Some(crate::truncate_for_display(message, 200))
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
        for base in ["http://api.example.com/v1", "HTTP://api.example.com/v1"] {
            let err = transcription_url(&cfg(base, "en")).unwrap_err();
            assert!(format!("{err}").contains("TLS"), "{base}: {err}");
        }
    }

    /// Schemes are case-insensitive, and the streaming path already treated them
    /// that way. Before this, `HTTPS://...` was taken for a scheme-less host and
    /// rewritten to `https://HTTPS://...`, so one transport worked and the other
    /// failed on the same `[voice].api_base`.
    #[test]
    fn an_uppercase_scheme_is_recognised_not_rewritten() {
        assert_eq!(
            transcription_url(&cfg("HTTPS://api.example.com/v1", "en")).unwrap(),
            "HTTPS://api.example.com/v1/audio/transcriptions"
        );
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
