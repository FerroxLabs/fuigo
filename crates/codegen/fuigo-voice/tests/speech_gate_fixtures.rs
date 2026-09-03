//! The speech gate against real recordings.
//!
//! These are not synthetic props. `silence.wav` and `noise.wav` were POSTed to
//! the live FluxRouter `/v1/audio/transcriptions` endpoint with
//! `flux-voice-fast`, and the answers were
//!
//! ```text
//! silence.wav -> {"text":" Thank you."}
//! noise.wav   -> {"text":" ."}
//! ```
//!
//! `speech.wav` is real speech (macOS `say`, resampled to the capture format)
//! and the same endpoint returned its content verbatim:
//!
//! ```text
//! speech.wav  -> {"text":" Refactor the authentication module and add a unit test."}
//! ```
//!
//! `room.wav` is this machine's own microphone recording an empty room, taken
//! through the same `__mic-capture` helper the pager uses. `male.wav`,
//! `male2.wav`, `fricative.wav` and `short.wav` cover the voices and phonetics
//! a single female TTS sample does not.
//!
//! `quiet.wav` and `quiet_short.wav` are the same microphone and the same
//! helper as `room.wav`, recording a sentence and the single word "yes" played
//! back across the room from the speakers at low volume. They exist because
//! turning a loud fixture's gain down is not the same experiment: scaling
//! attenuates the recording's own noise floor along with the speech and keeps
//! an SNR no quiet capture ever has. In these two the room's own noise floor
//! stayed where it is -- re-recorded alongside them it measured 0.0028 over
//! 2 s, against `room.wav`'s 0.0023 -- while the voice got small. They peak at
//! 0.0087 and 0.0081, and the energy floor that shipped before them (0.01) gave
//! both of them zero active frames.
//!
//! This file pins the property the transcript cannot give us: the gate rejects
//! both hallucination sources and the real room, and accepts every real
//! utterance -- including one quiet enough that the old floor threw it away --
//! without contacting anything.

use fuigo_voice::speech::{MIN_ACTIVE_FRAMES, MIN_CROSSING_HZ, RMS_FLOOR, classify};

/// Read a 16-bit mono PCM WAV fixture, returning its sample rate and raw `data`.
///
/// Walks the chunk list rather than assuming `data` starts at byte 44:
/// `afconvert` writes an extra chunk ahead of it.
fn read_fixture(name: &str) -> (u32, Vec<u8>) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert_eq!(&bytes[0..4], b"RIFF", "{name} is not a RIFF file");
    assert_eq!(&bytes[8..12], b"WAVE", "{name} is not a WAVE file");

    let channels = u16::from_le_bytes(bytes[22..24].try_into().unwrap());
    let sample_rate = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    let bits = u16::from_le_bytes(bytes[34..36].try_into().unwrap());
    assert_eq!(channels, 1, "{name}: fixtures must be mono");
    assert_eq!(bits, 16, "{name}: fixtures must be 16-bit");

    let mut offset = 12;
    while offset + 8 <= bytes.len() {
        let id = &bytes[offset..offset + 4];
        let len = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let body = offset + 8;
        if id == b"data" {
            let end = (body + len).min(bytes.len());
            return (sample_rate, bytes[body..end].to_vec());
        }
        // Chunks are word-aligned; an odd length is followed by a pad byte.
        offset = body + len + (len % 2);
    }
    panic!("{name}: no data chunk");
}

/// Every real utterance must pass, across voices, phonetics and levels.
///
/// `short.wav` is the important row for frequency. It is the single word "yes",
/// which is mostly consonant and measures a zero-crossing rate of 0.282 --
/// above the 0.25 ceiling this gate originally shipped with. That ceiling
/// silently discarded one-word commands.
///
/// `quiet.wav` and `quiet_short.wav` are the important rows for energy: real
/// captures of a quiet voice, both of which the 0.01 energy floor rejected
/// outright.
#[test]
fn every_real_utterance_is_accepted() {
    for name in [
        "speech.wav",
        "male.wav",
        "male2.wav",
        "fricative.wav",
        "short.wav",
        "quiet.wav",
        "quiet_short.wav",
    ] {
        let (rate, pcm) = read_fixture(name);
        let analysis = classify(&pcm, rate);
        assert!(
            analysis.is_speech(),
            "{name} is a real utterance and must pass the gate: {analysis:?}"
        );
    }
}

#[test]
fn silence_that_transcribes_as_thank_you_is_rejected() {
    let (rate, pcm) = read_fixture("silence.wav");
    let analysis = classify(&pcm, rate);
    assert!(
        !analysis.is_speech(),
        "6s of digital silence must not reach the endpoint (it answers \" Thank you.\"): {analysis:?}"
    );
    assert_eq!(analysis.active_frames, 0, "{analysis:?}");
}

/// The failure mode that actually happens: a real microphone in a real quiet
/// room. Nothing here should ever be uploaded.
#[test]
fn a_real_microphone_in_an_empty_room_is_rejected() {
    let (rate, pcm) = read_fixture("room.wav");
    let analysis = classify(&pcm, rate);
    assert!(!analysis.is_speech(), "{analysis:?}");
    assert_eq!(
        analysis.active_frames, 0,
        "room tone must not clear the energy floor: {analysis:?}"
    );
}

/// Quiet white noise is ACCEPTED, and that is the price of the energy floor.
///
/// This test used to be called `white_noise_is_rejected_by_the_zero_crossing_test`
/// and then assert rejection by *energy*, which the zero-crossing test had
/// nothing to do with: `noise.wav` measures 4017 Hz, far above
/// `MIN_CROSSING_HZ`, and only ever failed because its peak frame RMS of
/// 0.00999 missed the old 0.01 floor by a hair. Lowering the floor to accept
/// real quiet speech moved it to the other side, so the name and the assertion
/// now say what actually happens.
///
/// The trade is deliberate. The floor that rejected this clip also rejected
/// `quiet.wav`, a real recording of a quietly spoken sentence. Accepting six
/// seconds of hiss costs one request whose result the user can see and delete;
/// rejecting `quiet.wav` costs a dictation with no explanation. If a later
/// change makes this reject again, check `quiet.wav` still passes before
/// celebrating.
#[test]
fn quiet_white_noise_is_accepted_and_that_is_the_documented_trade() {
    let (rate, pcm) = read_fixture("noise.wav");
    let analysis = classify(&pcm, rate);
    assert!(
        analysis.peak_frame_rms > RMS_FLOOR,
        "noise.wav peaks at 0.00999 and must clear the floor: {analysis:?}"
    );
    assert!(
        analysis.loud_frame_crossing_hz > MIN_CROSSING_HZ,
        "broadband noise sits far above the frequency floor, so that test \
         cannot reject it either: {analysis:?}"
    );
    assert!(
        analysis.is_speech(),
        "documented limitation; if this ever changes, update the module docs \
         and confirm quiet.wav still passes: {analysis:?}"
    );
}

/// The clip the old floor destroyed.
///
/// `quiet.wav` is a real acoustic capture, not a scaled fixture: a sentence
/// played across the room and recorded on this machine's microphone, so the
/// room noise floor underneath it is the one `room.wav` measures and the voice
/// peaks only ~3.7x above it (0.0087 against 0.0023). At the 0.01 floor this
/// file shipped with, it produced ZERO active frames out of 174 -- the entire
/// dictation discarded, with no request sent and nothing on screen to explain
/// it.
#[test]
fn a_quiet_real_capture_clears_the_floor_with_frames_to_spare() {
    let (rate, pcm) = read_fixture("quiet.wav");
    let analysis = classify(&pcm, rate);
    assert!(analysis.is_speech(), "{analysis:?}");
    // 0.0087 measured, against a 0.005 floor.
    assert!(
        analysis.peak_frame_rms > RMS_FLOOR * 1.5,
        "quiet.wav must keep real margin over the energy floor, not scrape it: {analysis:?}"
    );
    // 44 measured, against a minimum of 4.
    assert!(
        analysis.active_frames >= MIN_ACTIVE_FRAMES * 4,
        "a whole spoken sentence must be far past the frame minimum: {analysis:?}"
    );
}

/// The shortest thing anyone dictates, captured quietly for real.
///
/// This is why [`MIN_ACTIVE_FRAMES`] is 4 and not 6. `quiet_short.wav` is the
/// single word "yes" recorded at a comparable low level to `quiet.wav`
/// (peaking at 0.0081 against its 0.0087), and it
/// clears the energy floor in exactly 6 frames. At a minimum of 6 it would pass
/// with no margin at all, and a word a shade quieter or shorter would be
/// silently thrown away.
#[test]
fn the_shortest_quiet_utterance_keeps_a_margin_over_the_frame_minimum() {
    let (rate, pcm) = read_fixture("quiet_short.wav");
    let analysis = classify(&pcm, rate);
    assert!(analysis.is_speech(), "{analysis:?}");
    // 6 measured, against a minimum of 4: 1.5x, and the tightest margin in the
    // gate. If a change pushes this to exactly MIN_ACTIVE_FRAMES, the next
    // quiet one-word command is the one that gets destroyed.
    assert!(
        analysis.active_frames > MIN_ACTIVE_FRAMES,
        "the shortest real quiet utterance must not sit exactly on the frame \
         minimum: {analysis:?}"
    );
}

/// A short utterance inside a long recording must still be found.
///
/// This is the toggle-mode case (`/voice`, `Ctrl+Shift+M`): the microphone is
/// open while the user thinks, and the speech is a small fraction of the clip.
/// Judging on the loudest *decile of the whole clip* rejected exactly this.
#[test]
fn a_short_utterance_padded_with_quiet_is_still_speech() {
    let (rate, speech) = read_fixture("speech.wav");
    // 20s before and 25s after, of digital silence. (Real room tone is used
    // for the padding in `leading_and_trailing_room_tone_cannot_change_a_verdict`;
    // here the point is only that a long clip must not dilute a short utterance.)
    let quiet = |secs: usize| vec![0u8; (rate as usize) * 2 * secs];
    let mut padded = quiet(20);
    padded.extend_from_slice(&speech);
    padded.extend_from_slice(&quiet(25));

    let bare = classify(&speech, rate);
    let analysis = classify(&padded, rate);
    assert!(
        analysis.is_speech(),
        "3s of speech in a 48s recording must still be found: {analysis:?}"
    );
    // Not identical: 20 s of padding is not a whole number of 30 ms frames, so
    // the analysis window lands on different sample boundaries and a couple of
    // frames at the edges of the utterance change classification. 10% bounds
    // that, and is far tighter than the dilution this test exists to catch --
    // which moved the measurement from 326 Hz to beyond the ceiling entirely.
    let drift = (analysis.loud_frame_crossing_hz - bare.loud_frame_crossing_hz).abs();
    assert!(
        drift < bare.loud_frame_crossing_hz * 0.10,
        "padding moved the measurement by {drift:.1} Hz: bare={bare:?} padded={analysis:?}"
    );
}

/// Padding must not change a verdict.
///
/// Every real push-to-talk recording begins and ends with the user not yet
/// talking, so the padded case is the only one that occurs in production. An
/// earlier version of this gate measured amplitude variation across the whole
/// clip, which meant the padding itself supplied the "variation": a 440 Hz tone
/// scored 0.004 unpadded and 0.348 with 0.2 s of room tone at each end, and was
/// reclassified from noise to speech by silence alone.
#[test]
fn leading_and_trailing_room_tone_cannot_change_a_verdict() {
    let (rate, room) = read_fixture("room.wav");
    let pad: Vec<u8> = room
        .iter()
        .copied()
        .take((rate as usize) * 2 / 2) // 0.5 s
        .collect();

    for name in [
        "silence.wav",
        "noise.wav",
        "room.wav",
        "speech.wav",
        "short.wav",
        "quiet.wav",
        "quiet_short.wav",
    ] {
        let (fixture_rate, pcm) = read_fixture(name);
        let bare = classify(&pcm, fixture_rate);

        let mut padded = pad.clone();
        padded.extend_from_slice(&pcm);
        padded.extend_from_slice(&pad);
        let padded = classify(&padded, fixture_rate);

        assert_eq!(
            bare.is_speech(),
            padded.is_speech(),
            "{name} changed verdict when padded with real room tone: \
             bare={bare:?} padded={padded:?}"
        );
    }
}

/// The thresholds are only trustworthy if the classes stay apart. If a change
/// narrows a margin, this fails before the behaviour does.
#[test]
fn the_thresholds_keep_their_measured_margins() {
    let (rate, speech) = read_fixture("speech.wav");
    let (_, short) = read_fixture("short.wav");
    let (_, quiet) = read_fixture("quiet.wav");
    let (_, room) = read_fixture("room.wav");

    let speech = classify(&speech, rate);
    let short = classify(&short, rate);
    let quiet = classify(&quiet, rate);
    let room = classify(&room, rate);

    // Energy, on the pair the floor actually sits between. Both sides are the
    // same microphone in the same room, so this is a margin and not an artefact
    // of scaling one recording to imitate another: room.wav peaks at 0.0023 and
    // quiet.wav at 0.0087, giving 2.2x below the floor and 1.7x above it. These
    // are the tightest margins in the gate; everything else has more.
    assert!(
        room.peak_frame_rms * 2.0 < RMS_FLOOR,
        "room tone margin too thin: {room:?}"
    );
    assert!(
        quiet.peak_frame_rms > RMS_FLOOR * 1.5,
        "the quietest accepted capture sits too close to the energy floor: {quiet:?}"
    );
    // The loud fixtures are 30-55x over it and should stay there.
    assert!(
        speech.peak_frame_rms > RMS_FLOOR * 20.0,
        "speech energy margin too thin: {speech:?}"
    );
    assert!(
        short.peak_frame_rms > RMS_FLOOR * 20.0,
        "the loudest one-word fixture sits too close to the energy floor: {short:?}"
    );
    // Zero-crossing rate: real speech must sit inside the band with room to
    // spare. `speech.wav` is the low end of it, at 326 Hz against a 160 Hz
    // floor.
    assert!(
        speech.loud_frame_crossing_hz > MIN_CROSSING_HZ * 1.5,
        "speech sits too close to the low-frequency floor: {speech:?}"
    );
    // There is no margin to assert for `noise.wav`: at 0.0100 it clears the
    // energy floor and at 4017 Hz it clears the frequency floor, so nothing in
    // this gate rejects it. That is asserted directly, as a decision, in
    // `quiet_white_noise_is_accepted_and_that_is_the_documented_trade`.
}
