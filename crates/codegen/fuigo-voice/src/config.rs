use serde::{Deserialize, Serialize};

use crate::error::VoiceError;

/// Default STT capture rate (Hz). Shared with the `__mic-capture` helper's argv default so parent and child agree when `--rate` is omitted.
pub const DEFAULT_SAMPLE_RATE: u32 = 16_000;

/// Default batch transcription model. The fast lane, because voice input is
/// short and latency-sensitive; `flux-voice-accurate` is the other end.
pub const DEFAULT_STT_MODEL: &str = "flux-voice-fast";

/// Which speech-to-text transport to use.
///
/// These are different protocols, not two URLs. Streaming is a WebSocket with
/// interim results; batch is one HTTP multipart POST after the utterance ends.
/// FluxRouter offers batch and explicitly refuses `stream=true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SttMode {
    /// WebSocket streaming with live partial transcripts.
    Streaming,
    /// Buffer the utterance, then one `POST /v1/audio/transcriptions`.
    /// No live partial transcript.
    #[default]
    Batch,
}

/// Voice settings for the STT transport.
///
/// Prefer **https** `api_base` (same shape as chat). [`Self::stt_ws_url`] derives
/// `wss://`. When `[voice].api_base` is unset, inherits
/// `[endpoints].fuigo_api_base_url` so enterprise proxies need no second knob.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct VoiceConfig {
    /// HTTPS API root (or bare host).
    /// Bases may end in `/v1` or `/fuigo/v1`; the default STT path de-duplicates a leading `v1/` so both become `…/v1/stt`.
    pub api_base: String,
    pub stt_ws_path: String,
    /// Preferred STT language (catalog code or `"auto"`). [`crate::language_for_api`] resolves it at connect time.
    pub language: String,
    pub sample_rate: u32,
    pub stt_endpointing_ms: u32,
    /// Only meaningful for [`SttMode::Streaming`]; batch has no interim
    /// transcript to deliver.
    pub stt_interim_results: bool,
    /// Which STT transport to use.
    ///
    /// An explicit switch rather than capability detection. Nothing in this
    /// crate can probe what an endpoint speaks: `stt_ws_url` mechanically
    /// derives `wss://` from any https base and never negotiates, so
    /// "try streaming, fall back" would mean opening a socket to find out.
    pub stt_mode: SttMode,
    /// Transcription model for [`SttMode::Batch`], e.g. `flux-voice-fast`.
    /// Ignored by the streaming transport, which has no model parameter.
    pub stt_model: String,

    /// The pager stamps this request identity; `serde(skip)` keeps user config from setting it.
    #[serde(skip)]
    pub client_identifier: String,
    #[serde(skip)]
    pub user_agent: String,
}

impl Default for VoiceConfig {
    fn default() -> Self {
        Self {
            // Empty, matching every other endpoint in fuigo-env's
            // PRODUCTION_ENDPOINTS. This defaulted to `https://api.x.ai`, which
            // was missed when the rest were severed -- so with voice enabled
            // and nothing configured, microphone audio streamed to
            // `wss://api.x.ai/v1/stt`. That is the one egress path in this
            // codebase carrying raw user audio, so it fails closed now:
            // `stt_ws_url()` errors on an empty base, and voice is unusable
            // until `[voice].api_base` or `[endpoints].fuigo_api_base_url`
            // names a host the user chose.
            api_base: String::new(),
            stt_ws_path: "/v1/stt".into(),
            language: "en".into(),
            sample_rate: DEFAULT_SAMPLE_RATE,
            stt_endpointing_ms: 400,
            stt_interim_results: true,
            // Batch by default: it is what the shipped endpoint (FluxRouter)
            // actually supports. Streaming remains available for endpoints
            // that speak the WebSocket protocol.
            stt_mode: SttMode::Batch,
            stt_model: DEFAULT_STT_MODEL.to_owned(),
            client_identifier: String::new(),
            user_agent: String::new(),
        }
    }
}

impl VoiceConfig {
    /// Streaming STT WebSocket URL. Rejects plaintext `http://` / `ws://`.
    pub fn stt_ws_url(&self) -> Result<String, VoiceError> {
        ws_url(&self.api_base, &self.stt_ws_path)
    }

    /// `api_base`: non-empty `[voice].api_base`, else `[endpoints].fuigo_api_base_url` from `root`, else `resolved_endpoints_base`, else the default.
    ///
    /// `resolved_endpoints_base` carries the caller's env/CLI overrides; it ranks below the raw table so config keeps beating env (shell precedence).
    pub fn from_config_table(root: &toml::Table, resolved_endpoints_base: Option<&str>) -> Self {
        let voice_table = root.get("voice").and_then(|v| v.as_table());
        let mut cfg: Self = voice_table
            .and_then(|t| toml::Value::Table(t.clone()).try_into().ok())
            .unwrap_or_default();

        // Read `[voice].api_base` from the raw table, not `cfg`: serde default makes "unset" and an explicit host indistinguishable
        cfg.api_base = non_empty_str(
            voice_table
                .and_then(|t| t.get("api_base"))
                .and_then(|v| v.as_str()),
        )
        .or_else(|| {
            non_empty_str(
                root.get("endpoints")
                    .and_then(|e| e.get("fuigo_api_base_url"))
                    .and_then(|v| v.as_str()),
            )
        })
        .or_else(|| non_empty_str(resolved_endpoints_base))
        .map(|base| base.trim_end_matches('/').to_owned())
        .unwrap_or_else(|| Self::default().api_base);
        cfg
    }
}

fn non_empty_str(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}

/// `strip_prefix` ignoring ASCII case: RFC 3986 schemes are case-insensitive.
/// `HTTP://` must hit the plaintext rejection and `HTTPS://` must work.
fn strip_scheme<'a>(s: &'a str, scheme: &str) -> Option<&'a str> {
    s.get(..scheme.len())
        .filter(|p| p.eq_ignore_ascii_case(scheme))
        .map(|_| &s[scheme.len()..])
}

fn ws_url(api_base: &str, path: &str) -> Result<String, VoiceError> {
    let base = api_base.trim().trim_end_matches('/');
    let path = path.trim().trim_start_matches('/');
    // Fail closed, and legibly. With no base this used to return
    // Ok("wss:///v1/stt") -- a malformed URL that surfaces much later as an
    // opaque parse error. Voice carries raw microphone audio, so an unset
    // endpoint must be a clear refusal rather than a guess.
    if base.is_empty() {
        return Err(VoiceError::Config(
            "voice endpoint is not configured: set `[voice].api_base` or \
             `[endpoints].fuigo_api_base_url` to the host that should receive \
             your microphone audio."
                .into(),
        ));
    }
    if strip_scheme(base, "http://").is_some() || strip_scheme(base, "ws://").is_some() {
        return Err(VoiceError::Config(format!(
            "insecure voice api_base {api_base:?}: voice requires a TLS endpoint \
             (https:// / wss://). Refusing to send the bearer token over a \
             plaintext connection."
        )));
    }
    let rest = strip_scheme(base, "https://")
        .or_else(|| strip_scheme(base, "wss://"))
        .unwrap_or(base);
    // The default path is `/v1/stt`; bases often end in `/v1` or `/fuigo/v1`
    let path = match (rest.ends_with("/v1"), path.strip_prefix("v1/")) {
        (true, Some(rest_path)) => rest_path,
        _ => path,
    };
    Ok(format!("wss://{rest}/{path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default must name NO host. This test previously pinned
    /// `wss://api.x.ai/v1/stt`, which is how the vendor default survived the
    /// severance of every other endpoint: the test asserted it was correct.
    #[test]
    fn default_has_no_endpoint_and_fails_closed() {
        assert!(VoiceConfig::default().api_base.is_empty());
        let err = VoiceConfig::default().stt_ws_url().unwrap_err();
        assert!(
            format!("{err}").contains("not configured"),
            "unset voice endpoint must refuse clearly, got: {err}"
        );
    }

    #[test]
    fn configured_base_still_builds_a_wss_url() {
        let cfg = VoiceConfig {
            api_base: "https://api.example.com".into(),
            ..VoiceConfig::default()
        };
        assert_eq!(cfg.stt_ws_url().unwrap(), "wss://api.example.com/v1/stt");
    }

    #[test]
    fn scheme_less_and_wss_bases() {
        for base in [
            "api.example.com",
            "wss://api.example.com",
            "HTTPS://api.example.com",
        ] {
            let cfg = VoiceConfig {
                api_base: base.into(),
                ..VoiceConfig::default()
            };
            assert_eq!(cfg.stt_ws_url().unwrap(), "wss://api.example.com/v1/stt");
        }
    }

    #[test]
    fn v1_base_dedupes_default_path() {
        let cfg = VoiceConfig {
            api_base: "https://proxy.example.com/v1".into(),
            ..VoiceConfig::default()
        };
        assert_eq!(cfg.stt_ws_url().unwrap(), "wss://proxy.example.com/v1/stt");
    }

    #[test]
    fn fuigo_v1_base_preserves_prefix() {
        let cfg = VoiceConfig {
            api_base: "https://proxy.example.com/fuigo/v1".into(),
            ..VoiceConfig::default()
        };
        assert_eq!(
            cfg.stt_ws_url().unwrap(),
            "wss://proxy.example.com/fuigo/v1/stt"
        );
    }

    #[test]
    fn rejects_plaintext_bases() {
        for base in [
            "http://localhost:8080",
            "ws://localhost:8080",
            "HTTP://localhost:8080",
            "Ws://localhost:8080",
        ] {
            let cfg = VoiceConfig {
                api_base: base.into(),
                ..VoiceConfig::default()
            };
            assert!(matches!(cfg.stt_ws_url(), Err(VoiceError::Config(_))));
        }
    }

    #[test]
    fn inherits_endpoints_when_voice_api_base_unset() {
        let table: toml::Table = toml::from_str(
            r#"
[endpoints]
fuigo_api_base_url = "https://proxy.example.com/fuigo/v1"
"#,
        )
        .unwrap();
        let cfg = VoiceConfig::from_config_table(&table, None);
        assert_eq!(cfg.api_base, "https://proxy.example.com/fuigo/v1");
        assert_eq!(
            cfg.stt_ws_url().unwrap(),
            "wss://proxy.example.com/fuigo/v1/stt"
        );
    }

    #[test]
    fn empty_voice_api_base_still_inherits_endpoints() {
        let table: toml::Table = toml::from_str(
            r#"
[endpoints]
fuigo_api_base_url = "https://proxy.example.com/fuigo/v1"
[voice]
api_base = "  "
language = "fr"
"#,
        )
        .unwrap();
        let cfg = VoiceConfig::from_config_table(&table, None);
        assert_eq!(cfg.api_base, "https://proxy.example.com/fuigo/v1");
        assert_eq!(cfg.language, "fr");
    }

    #[test]
    /// Whitespace-only `api_base` is treated as unset. With nothing else to
    /// fall back to that now means "no endpoint", not "the vendor's endpoint".
    fn whitespace_voice_api_base_without_endpoints_falls_back_to_unset() {
        let table: toml::Table = toml::from_str(
            r#"
[voice]
api_base = "  "
"#,
        )
        .unwrap();
        let cfg = VoiceConfig::from_config_table(&table, None);
        assert_eq!(cfg.api_base, VoiceConfig::default().api_base);
        assert!(cfg.api_base.is_empty(), "must not inherit a vendor host");
        assert!(cfg.stt_ws_url().is_err(), "unset endpoint must refuse");
    }

    #[test]
    fn resolved_endpoints_base_used_when_table_has_none() {
        let cfg = VoiceConfig::from_config_table(
            &toml::Table::new(),
            Some("https://proxy.example.com/v1/"),
        );
        assert_eq!(cfg.api_base, "https://proxy.example.com/v1");
        assert_eq!(cfg.stt_ws_url().unwrap(), "wss://proxy.example.com/v1/stt");

        // Whitespace-only resolved base falls through to the default.
        let cfg = VoiceConfig::from_config_table(&toml::Table::new(), Some("  "));
        assert_eq!(cfg.api_base, VoiceConfig::default().api_base);
    }

    /// config.toml beats the env/CLI fallback, matching the shell's endpoints precedence.
    #[test]
    fn table_endpoints_beat_resolved_endpoints_base() {
        let table: toml::Table = toml::from_str(
            r#"
[endpoints]
fuigo_api_base_url = "https://config.example.com"
"#,
        )
        .unwrap();
        let cfg = VoiceConfig::from_config_table(&table, Some("https://env.example.com"));
        assert_eq!(cfg.api_base, "https://config.example.com");
    }

    #[test]
    fn voice_api_base_overrides_endpoints() {
        let table: toml::Table = toml::from_str(
            r#"
[endpoints]
fuigo_api_base_url = "https://proxy.example.com/fuigo/v1"
[voice]
api_base = "https://api.example.com"
language = "es"
"#,
        )
        .unwrap();
        let cfg = VoiceConfig::from_config_table(&table, None);
        assert_eq!(cfg.api_base, "https://api.example.com");
        assert_eq!(cfg.language, "es");
        assert_eq!(cfg.stt_ws_url().unwrap(), "wss://api.example.com/v1/stt");
    }

    #[test]
    fn ignores_unknown_and_identity_fields() {
        let table: toml::Table = toml::from_str(
            r#"
[voice]
enabled = false
client_identifier = "spoofed"
user_agent = "malicious/9.9"
language = "es"
"#,
        )
        .unwrap();
        let cfg = VoiceConfig::from_config_table(&table, None);
        assert_eq!(cfg.language, "es");
        assert!(cfg.client_identifier.is_empty());
        assert!(cfg.user_agent.is_empty());
    }
}
