//! FFmpeg PATH probes and the "install ffmpeg" banner for inline video posters.

use crate::prompt_images::InlineMediaInfo;

pub const FFMPEG_HINT_TEXT: &str = "Install ffmpeg to view inline";

/// How long a failed probe is trusted before PATH is scanned again.
const FAILED_PROBE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Default)]
struct ProbeState {
    found: bool,
    failed_at: Option<std::time::Instant>,
    probing: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum ProbePlan {
    Answer(bool),
    /// Nothing is known yet, or the cached failure expired: answer "missing" now and probe on a background thread.
    ProbeBackground,
}

fn plan_probe(state: &mut ProbeState, now: std::time::Instant) -> ProbePlan {
    if state.found {
        return ProbePlan::Answer(true);
    }
    if state.probing {
        return ProbePlan::Answer(false);
    }
    match state.failed_at {
        Some(at) if now.duration_since(at) < FAILED_PROBE_TTL => ProbePlan::Answer(false),
        _ => {
            state.probing = true;
            ProbePlan::ProbeBackground
        }
    }
}

fn finish_probe(state: &mut ProbeState, available: bool, now: std::time::Instant) {
    state.probing = false;
    if available {
        state.found = true;
    } else {
        state.failed_at = Some(now);
    }
}

/// Caches the first success and re-probes a failure at most every [`FAILED_PROBE_TTL`], so installing ffmpeg mid-session still recovers posters.
/// Render calls this for every visible video placeholder and it never scans PATH itself: the first probe and every refresh run on a worker thread.
/// Until the first probe answers, ffmpeg counts as missing (the placeholder banner shows) and the next render after it finishes picks up the result.
pub fn ffmpeg_available() -> bool {
    #[cfg(test)]
    if let Some(v) = TEST_FFMPEG_OVERRIDE.with(|c| c.get()) {
        return v;
    }

    use std::sync::{Arc, Mutex, OnceLock};
    static STATE: OnceLock<Arc<Mutex<ProbeState>>> = OnceLock::new();
    let state = STATE.get_or_init(|| Arc::new(Mutex::new(ProbeState::default())));
    cached_available(state, || {
        fuigo_config::shell::is_command_available("ffmpeg")
    })
}

/// [`ffmpeg_available`] over an explicit state and probe, so the no-blocking contract is testable.
fn cached_available(
    state: &std::sync::Arc<std::sync::Mutex<ProbeState>>,
    probe: impl FnOnce() -> bool + Send + 'static,
) -> bool {
    let now = std::time::Instant::now();
    let plan = match state.lock() {
        Ok(mut s) => plan_probe(&mut s, now),
        Err(_) => return false,
    };
    match plan {
        ProbePlan::Answer(v) => v,
        ProbePlan::ProbeBackground => {
            let worker_state = std::sync::Arc::clone(state);
            let spawned = std::thread::Builder::new()
                .name("ffmpeg-probe".into())
                .spawn(move || {
                    let available = probe();
                    if let Ok(mut s) = worker_state.lock() {
                        finish_probe(&mut s, available, std::time::Instant::now());
                    }
                });
            if spawned.is_err()
                && let Ok(mut s) = state.lock()
            {
                finish_probe(&mut s, false, std::time::Instant::now());
            }
            false
        }
    }
}

#[cfg(test)]
thread_local! {
    static TEST_FFMPEG_OVERRIDE: std::cell::Cell<Option<bool>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_ffmpeg_available_for_test(available: bool) -> FfmpegTestGuard {
    TEST_FFMPEG_OVERRIDE.with(|c| c.set(Some(available)));
    FfmpegTestGuard
}

#[cfg(test)]
pub(crate) struct FfmpegTestGuard;

#[cfg(test)]
impl Drop for FfmpegTestGuard {
    fn drop(&mut self) {
        TEST_FFMPEG_OVERRIDE.with(|c| c.set(None));
    }
}

/// The first package manager found on PATH wins; when none is found the banner shows only the hint, no install line.
fn ffmpeg_install_candidates() -> &'static [(&'static str, &'static str)] {
    if cfg!(target_os = "macos") {
        &[("brew", "! brew install ffmpeg")]
    } else if cfg!(target_os = "windows") {
        &[
            ("winget", "! winget install ffmpeg"),
            ("choco", "! choco install ffmpeg"),
            ("scoop", "! scoop install ffmpeg"),
        ]
    } else {
        &[
            ("apt", "! sudo apt install ffmpeg"),
            ("apt-get", "! sudo apt-get install ffmpeg"),
            ("dnf", "! sudo dnf install ffmpeg"),
            ("pacman", "! sudo pacman -S ffmpeg"),
            ("zypper", "! sudo zypper install ffmpeg"),
            ("apk", "! sudo apk add ffmpeg"),
        ]
    }
}

/// Caches the first success and keeps re-probing failures, so installing a package manager mid-session recovers the install line.
pub fn ffmpeg_install_cmd() -> Option<&'static str> {
    #[cfg(test)]
    if let Some(v) = TEST_FFMPEG_INSTALL_CMD_OVERRIDE.with(|c| c.get()) {
        return v;
    }

    use std::sync::OnceLock;
    static FOUND: OnceLock<&'static str> = OnceLock::new();
    if let Some(cmd) = FOUND.get() {
        return Some(*cmd);
    }
    for (manager, cmd) in ffmpeg_install_candidates() {
        if fuigo_config::shell::is_command_available(manager) {
            let _ = FOUND.set(*cmd);
            return Some(*cmd);
        }
    }
    None
}

#[cfg(test)]
thread_local! {
    static TEST_FFMPEG_INSTALL_CMD_OVERRIDE: std::cell::Cell<Option<Option<&'static str>>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_ffmpeg_install_cmd_for_test(
    cmd: Option<&'static str>,
) -> FfmpegInstallCmdTestGuard {
    TEST_FFMPEG_INSTALL_CMD_OVERRIDE.with(|c| c.set(Some(cmd)));
    FfmpegInstallCmdTestGuard
}

#[cfg(test)]
pub(crate) struct FfmpegInstallCmdTestGuard;

#[cfg(test)]
impl Drop for FfmpegInstallCmdTestGuard {
    fn drop(&mut self) {
        TEST_FFMPEG_INSTALL_CMD_OVERRIDE.with(|c| c.set(None));
    }
}

fn ffmpeg_hint_banner_rows() -> u16 {
    if ffmpeg_install_cmd().is_some() { 2 } else { 1 }
}

/// `(image_area, total)` rows for an inline-media preview.
/// Shared by the code that reserves entry height and the code that places the block, so the two cannot drift.
pub fn inline_media_reserved_rows(info: &InlineMediaInfo, content_width: u16) -> (u16, u16) {
    use crate::terminal::image::fit_image_to_cells;

    if info.is_video && !ffmpeg_available() {
        let banner_rows = ffmpeg_hint_banner_rows();
        return (banner_rows, banner_rows + 1);
    }
    let max_cols = content_width.saturating_sub(2);
    let max_rows = (content_width / 2).clamp(4, 20);
    let (_cols, rows) = fit_image_to_cells(info.width, info.height, max_cols, max_rows);
    (rows, rows + 3)
}

#[cfg(test)]
mod probe_cache_tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn failed_probe_is_cached_then_refreshed_in_background() {
        let t0 = Instant::now();
        let mut st = ProbeState::default();
        assert_eq!(plan_probe(&mut st, t0), ProbePlan::ProbeBackground);
        // While the first probe runs, concurrent callers just get "missing"
        assert_eq!(plan_probe(&mut st, t0), ProbePlan::Answer(false));
        finish_probe(&mut st, false, t0);
        // Many render calls inside the TTL never scan PATH again
        for ms in [1u64, 500, 29_000] {
            assert_eq!(
                plan_probe(&mut st, t0 + Duration::from_millis(ms)),
                ProbePlan::Answer(false)
            );
        }
        // Expired: refresh off the render path, answer from the cache meanwhile
        let later = t0 + FAILED_PROBE_TTL + Duration::from_secs(1);
        assert_eq!(plan_probe(&mut st, later), ProbePlan::ProbeBackground);
        assert_eq!(plan_probe(&mut st, later), ProbePlan::Answer(false));
        finish_probe(&mut st, true, later);
        // Installing ffmpeg mid-session is picked up, and success is permanent
        assert_eq!(plan_probe(&mut st, later), ProbePlan::Answer(true));
    }

    /// The render path never waits on the probe, not even the first one: a probe stuck on a slow PATH leaves the caller with an immediate "missing".
    #[test]
    fn first_probe_never_blocks_the_caller() {
        use std::sync::{Arc, Mutex, mpsc};
        let state = Arc::new(Mutex::new(ProbeState::default()));
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (started_tx, started_rx) = mpsc::channel::<()>();
        // The probe stays stuck until the test lets go, so a caller that waited on it would hang here
        let first = cached_available(&state, move || {
            started_tx.send(()).unwrap();
            let _ = release_rx.recv();
            true
        });
        assert!(!first, "unknown yet counts as missing");
        started_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("probe runs on a worker");
        // Still probing: further calls answer immediately and start nothing new
        assert!(!cached_available(&state, || panic!("second probe")));
        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cached_available(&state, || panic!("no re-probe once found")) {
            assert!(Instant::now() < deadline, "result never became visible");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffmpeg_install_candidates_are_runnable_prompt_hints() {
        for (manager, cmd) in ffmpeg_install_candidates() {
            assert!(!manager.is_empty(), "empty manager name");
            assert!(cmd.starts_with("! "), "not prompt-runnable: {cmd:?}");
            assert!(cmd.contains("ffmpeg"), "missing package: {cmd:?}");
        }
    }

    #[test]
    fn ffmpeg_install_cmd_override_none_omits_command() {
        let _no_pm = set_ffmpeg_install_cmd_for_test(None);
        assert_eq!(ffmpeg_install_cmd(), None);
    }

    #[test]
    fn ffmpeg_install_cmd_override_some_returns_command() {
        let _pm = set_ffmpeg_install_cmd_for_test(Some("! brew install ffmpeg"));
        assert_eq!(ffmpeg_install_cmd(), Some("! brew install ffmpeg"));
    }

    fn media(is_video: bool) -> InlineMediaInfo {
        InlineMediaInfo {
            path: std::path::PathBuf::from("/tmp/x"),
            width: 640,
            height: 480,
            is_video,
            alt_text: String::new(),
        }
    }

    #[test]
    fn reserved_rows_image_is_full_poster_plus_button() {
        let _no_ffmpeg = set_ffmpeg_available_for_test(false);
        let (image_rows, total_rows) = inline_media_reserved_rows(&media(false), 80);
        assert!(
            (4..=20).contains(&image_rows),
            "poster budget: {image_rows}"
        );
        assert_eq!(total_rows, image_rows + 3);
    }

    #[test]
    fn reserved_rows_video_shrinks_to_two_line_banner_with_install_cmd() {
        let _no_ffmpeg = set_ffmpeg_available_for_test(false);
        let _cmd = set_ffmpeg_install_cmd_for_test(Some("! brew install ffmpeg"));
        assert_eq!(inline_media_reserved_rows(&media(true), 80), (2, 3));
    }

    #[test]
    fn reserved_rows_video_shrinks_to_one_line_banner_without_install_cmd() {
        let _no_ffmpeg = set_ffmpeg_available_for_test(false);
        let _no_pm = set_ffmpeg_install_cmd_for_test(None);
        assert_eq!(inline_media_reserved_rows(&media(true), 80), (1, 2));
    }

    #[test]
    fn reserved_rows_video_is_full_poster_with_ffmpeg() {
        let _ffmpeg = set_ffmpeg_available_for_test(true);
        let (image_rows, total_rows) = inline_media_reserved_rows(&media(true), 80);
        assert!(
            (4..=20).contains(&image_rows),
            "poster budget: {image_rows}"
        );
        assert_eq!(total_rows, image_rows + 3);
    }
}
