//! Live end-to-end for the batch transcription path.
//!
//! `#[ignore]`d: it needs a real endpoint and a real key, so it does not run in
//! CI. Run it deliberately:
//!
//! ```sh
//! FUIGO_VOICE_LIVE_BASE=https://api.fluxrouter.ai/v1 \
//! FUIGO_VOICE_LIVE_KEY="$(cat .fuigo-dev/key)" \
//!   cargo test -p fuigo-voice --test live_batch_stt -- --ignored --nocapture
//! ```
//!
//! What it is for: every other test in this crate stubs the network. This one
//! answers "does the thing we shipped actually transcribe" against the endpoint
//! users will hit, including the multipart shape, the omitted `language` field,
//! and the response parse.

use fuigo_voice::config::{SttMode, VoiceConfig};
use fuigo_voice::speech;
use fuigo_voice::stt::batch::{BatchSttClient, pcm_to_wav};

fn live_config() -> Option<(VoiceConfig, String)> {
    let base = std::env::var("FUIGO_VOICE_LIVE_BASE").ok()?;
    let key = std::env::var("FUIGO_VOICE_LIVE_KEY").ok()?;
    Some((
        VoiceConfig {
            api_base: base,
            stt_mode: SttMode::Batch,
            language: "auto".into(),
            ..VoiceConfig::default()
        },
        key,
    ))
}

/// Read a fixture's sample rate and PCM, walking the chunk list.
fn fixture(name: &str) -> (u32, Vec<u8>) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let sample_rate = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    let mut offset = 12;
    while offset + 8 <= bytes.len() {
        let id = &bytes[offset..offset + 4];
        let len = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let body = offset + 8;
        if id == b"data" {
            return (
                sample_rate,
                bytes[body..(body + len).min(bytes.len())].to_vec(),
            );
        }
        offset = body + len + (len % 2);
    }
    panic!("{name}: no data chunk");
}

#[tokio::test]
#[ignore = "hits a live endpoint; needs FUIGO_VOICE_LIVE_BASE and FUIGO_VOICE_LIVE_KEY"]
async fn real_speech_round_trips_through_the_batch_transport() {
    let Some((config, key)) = live_config() else {
        panic!("set FUIGO_VOICE_LIVE_BASE and FUIGO_VOICE_LIVE_KEY");
    };
    let (rate, pcm) = fixture("speech.wav");

    assert!(
        speech::contains_speech(&pcm, rate),
        "the gate must let a real utterance through, or nothing is sent"
    );

    let client = BatchSttClient::new().expect("client builds");
    let wav = pcm_to_wav(&pcm, rate);
    let text = client
        .transcribe(&config, &key, wav)
        .await
        .expect("live transcription should succeed");

    println!("live transcript: {text:?}");
    let lowered = text.to_lowercase();
    for word in ["refactor", "authentication", "unit test"] {
        assert!(
            lowered.contains(word),
            "expected {word:?} in the live transcript, got {text:?}"
        );
    }
}

/// The property the whole gate exists for, proven against the live endpoint:
/// silence transcribes as a plausible sentence, and the gate is what stops it
/// from ever being sent.
#[tokio::test]
#[ignore = "hits a live endpoint; needs FUIGO_VOICE_LIVE_BASE and FUIGO_VOICE_LIVE_KEY"]
async fn silence_would_hallucinate_but_the_gate_stops_the_request() {
    let Some((config, key)) = live_config() else {
        panic!("set FUIGO_VOICE_LIVE_BASE and FUIGO_VOICE_LIVE_KEY");
    };
    let (rate, pcm) = fixture("silence.wav");

    assert!(
        !speech::contains_speech(&pcm, rate),
        "silence must never reach the endpoint"
    );

    // Now show what the gate is protecting against, by bypassing it.
    let client = BatchSttClient::new().expect("client builds");
    let wav = pcm_to_wav(&pcm, rate);
    let text = client
        .transcribe(&config, &key, wav)
        .await
        .expect("the endpoint answers happily -- that is the problem");

    println!("what silence transcribes as, unguarded: {text:?}");
    assert!(
        !text.trim().is_empty(),
        "if the endpoint ever starts returning empty for silence this test should be revisited, \
         but as of the probe it returns a stock phrase"
    );
}

/// A wrong credential must become a legible auth error, not a hang or a panic.
#[tokio::test]
#[ignore = "hits a live endpoint; needs FUIGO_VOICE_LIVE_BASE"]
async fn a_bad_key_is_reported_as_an_auth_error() {
    let Ok(base) = std::env::var("FUIGO_VOICE_LIVE_BASE") else {
        panic!("set FUIGO_VOICE_LIVE_BASE");
    };
    let config = VoiceConfig {
        api_base: base,
        stt_mode: SttMode::Batch,
        ..VoiceConfig::default()
    };
    let (rate, pcm) = fixture("speech.wav");
    let client = BatchSttClient::new().expect("client builds");
    let err = client
        .transcribe(
            &config,
            "sk-definitely-not-a-real-key",
            pcm_to_wav(&pcm, rate),
        )
        .await
        .expect_err("a bad key must not succeed");
    println!("bad-key error: {err}");
    let text = err.to_string();
    assert!(
        text.contains("credential") || text.contains("auth"),
        "the error must tell the user it is about their credential: {text}"
    );
}
