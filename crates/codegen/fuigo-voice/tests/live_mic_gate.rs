//! What does the real microphone actually measure?
//!
//! `#[ignore]`d: it opens the machine's microphone. Run it deliberately:
//!
//! ```sh
//! cargo test -p fuigo-voice --test live_mic_gate -- --ignored --nocapture
//! ```
//!
//! The speech gate's thresholds were set from recorded fixtures. This reports
//! what a live, quiet room measures on this machine, which is the number that
//! decides whether the no-speech watchdog can ever fire.

#![cfg(feature = "audio")]

use fuigo_voice::speech::{MIN_CROSSING_HZ, RMS_FLOOR, classify};

#[test]
#[ignore = "opens the microphone"]
fn measure_a_quiet_room() {
    let seconds = 5;
    let (pcm, rate) =
        fuigo_voice::audio::capture_pcm_for_duration(16_000, seconds).expect("mic should open");
    let analysis = classify(&pcm, rate);
    println!(
        "{seconds}s of room tone @{rate}Hz: {} bytes, peak_frame_rms={:.6} (floor {RMS_FLOOR}), \
         crossing={:.1}Hz (floor {MIN_CROSSING_HZ}), frames={} => is_speech={}",
        pcm.len(),
        analysis.peak_frame_rms,
        analysis.loud_frame_crossing_hz,
        analysis.frames,
        analysis.is_speech()
    );
}
