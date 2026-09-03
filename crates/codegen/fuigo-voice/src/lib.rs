//! Voice input for Fuigo CLI: an Ferrox Labs streaming STT client and the [`run_voice_pipeline`] task that emits [`VoiceEvent`]s for the pager.
//!
//! Voice is dictation only: the mic streams to STT and the transcript lands in the prompt box.
//!
//! On macOS and Linux the mic is opened in a short-lived subprocess, so the long-lived TUI never pays the audio stack's permanent memory cost.
//! See [`audio`] and [`maybe_run_capture_subprocess`].

#[cfg(feature = "audio")]
pub mod audio;
pub mod auth;
pub mod config;
pub mod error;
pub mod event;
pub mod language;
pub mod pipeline;
pub mod probe;
pub mod speech;
pub mod stt;

pub use auth::{SharedVoiceAuth, StaticVoiceAuth, VoiceAuthProvider};
pub use config::{SttMode, VoiceConfig};
pub use error::VoiceError;
pub use event::VoiceEvent;
pub use language::{
    STT_LANGUAGE_AUTO, STT_LANGUAGE_DEFAULT, STT_LANGUAGES, SttLanguage, canonicalize_stt_language,
    language_for_api, stt_language_by_code,
};
pub use pipeline::{MAX_IN_FLIGHT_UPLOADS, VoiceCommand, run_voice_pipeline};
#[cfg(feature = "audio")]
pub use probe::run_mic_only_probe;
pub use probe::{
    InputDeviceInfo, VoiceProbeOptions, VoiceProbeReport, format_probe_report, input_device_info,
    run_streaming_probe,
};
pub use speech::contains_speech;

/// Truncate `text` to `max_chars` characters, appending an ellipsis when cut.
///
/// Used on strings that came from a remote endpoint before they reach the UI:
/// a server-supplied error message is untrusted text, and a toast is not a
/// place an arbitrary length belongs. Slices on char boundaries, so multi-byte
/// UTF-8 never panics.
pub(crate) fn truncate_for_display(text: &str, max_chars: usize) -> String {
    match text.char_indices().nth(max_chars) {
        Some((byte, _)) => format!("{}...", &text[..byte]),
        None => text.to_owned(),
    }
}

/// Whether this build can capture microphone audio (the `audio` feature).
/// Production CLI builds enable it on every OS: macOS and Windows link `cpal` (coreaudio/wasapi).
/// Linux shells out to a system recorder (`pw-record`/`parec`/`arecord`) so the static-musl binary links no audio library.
/// Bazel builds drop `audio` (no capture in the test sandbox).
///
/// On Linux a `true` value means capture is *compiled in*; whether a recorder is actually installed is reported when a session starts.
/// Consumers gate voice on this so a no-audio build never advertises a mic it can't open.
pub const AUDIO_SUPPORTED: bool = cfg!(feature = "audio");

/// Hidden subcommand consumers re-exec themselves with to capture microphone audio in a short-lived helper process on macOS.
/// See [`audio::capture_subprocess`](audio) for why capture is out of process.
/// Intercepted via [`maybe_run_capture_subprocess`] at the very top of `main`, before any TUI/agent/tokio init, so the child stays minimal.
pub const MIC_CAPTURE_SUBCOMMAND: &str = "__mic-capture";

/// If this process was re-exec'd as the hidden mic-capture helper, run it and return `Some(exit_code)`; otherwise `None` (a normal invocation).
/// Call at the very top of `main` in every binary that links this crate with `audio` (the pager composition root and `voice-probe`).
/// This mirrors the pager's mermaid render child intercept.
pub fn maybe_run_capture_subprocess() -> Option<i32> {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if !is_capture_subcommand(&argv) {
        return None;
    }
    #[cfg(all(feature = "audio", not(target_os = "linux")))]
    {
        // Skip argv[0] (binary) and argv[1] (subcommand); the rest are flags.
        let args: Vec<String> = argv
            .into_iter()
            .skip(2)
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        Some(audio::run_capture_child_cli(args))
    }
    #[cfg(not(all(feature = "audio", not(target_os = "linux"))))]
    {
        // This build's own parent backend never spawns the helper (Linux uses system recorders; no-audio builds have no capture)
        // Only a hand-typed invocation reaches here
        // `write!` instead of `println!` so a closed pipe never panics
        use std::io::Write;
        let _ = writeln!(
            std::io::stdout(),
            "ERR mic-capture helper unavailable in this build"
        );
        Some(2)
    }
}

/// Whether `argv` (the full process argv, including argv[0]) invokes the hidden mic-capture helper, i.e. argv[1] is [`MIC_CAPTURE_SUBCOMMAND`].
/// Pure so the dispatch decision is unit-testable without mutating the process's real args.
fn is_capture_subcommand(argv: &[std::ffi::OsString]) -> bool {
    argv.get(1).and_then(|a| a.to_str()) == Some(MIC_CAPTURE_SUBCOMMAND)
}

#[cfg(test)]
mod intercept_tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<std::ffi::OsString> {
        items.iter().map(std::ffi::OsString::from).collect()
    }

    #[test]
    fn capture_subcommand_matches_only_argv1() {
        assert!(is_capture_subcommand(&argv(&["fuigo", "__mic-capture"])));
        assert!(is_capture_subcommand(&argv(&[
            "fuigo",
            "__mic-capture",
            "--rate",
            "16000"
        ])));
        assert!(!is_capture_subcommand(&argv(&["fuigo"])));
        assert!(!is_capture_subcommand(&argv(&["fuigo", "chat"])));
        assert!(!is_capture_subcommand(&argv(&[
            "fuigo",
            "chat",
            "__mic-capture"
        ])));
    }
}

#[cfg(test)]
mod truncate_tests {
    use super::truncate_for_display;

    #[test]
    fn short_text_is_unchanged() {
        assert_eq!(truncate_for_display("rate limited", 200), "rate limited");
    }

    #[test]
    fn long_text_is_cut_and_marked() {
        let long = "x".repeat(500);
        let out = truncate_for_display(&long, 10);
        assert_eq!(out, format!("{}...", "x".repeat(10)));
    }

    /// The bytes that reach this are whatever a remote endpoint sent, so a
    /// multi-byte boundary must not panic.
    #[test]
    fn multibyte_text_is_cut_on_a_char_boundary() {
        let text = "\u{e9}".repeat(50);
        let out = truncate_for_display(&text, 3);
        assert_eq!(out, "\u{e9}\u{e9}\u{e9}...");
    }
}
