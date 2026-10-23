//! The Wind mark's one-time spin: a clock, a timeline and the guards that decide whether it plays.
//!
//! On entry to the welcome screen the mark does one 3D turn about its vertical axis (about 5 s per revolution at cruise), eases to rest facing
//! forward, and plays the ember gust once as it settles. After that it is static and the frame counter is constant, so nothing repaints.
//!
//! The spin is skipped (the settled frame is shown from the first paint) when `SSH_CONNECTION` or `SSH_TTY` is set, `NO_COLOR` is set,
//! `ui.animations` or `ui.background_mark_animate` is false, or the terminal has lost focus (until it returns). Any key press snaps it to rest.
//! Returning to the welcome screen after being away replays it.
//!
//! Everything time-dependent takes `now` explicitly so tests drive it without sleeping.

use std::f32::consts::TAU;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Redraw cadence while the spin plays, in frames per second.
pub(super) const SPIN_FPS: f32 = 12.0;
/// Seconds per revolution at cruising speed.
const REV_SECS: f32 = 5.0;
/// Seconds at cruising speed before the ease-out starts.
const CRUISE_SECS: f32 = 3.75;
/// Seconds of constant deceleration to rest. One revolution in total: 3.75/5 + 2.5/10 = 1.
const EASE_SECS: f32 = 2.5;
/// Seconds from entry to rest.
pub(super) const SPIN_TOTAL_SECS: f32 = CRUISE_SECS + EASE_SECS;
/// The gust plays during the last stretch of the ease, ending exactly at rest.
pub(super) const GUST_SECS: f32 = 0.9;
const GUST_START_SECS: f32 = SPIN_TOTAL_SECS - GUST_SECS;
/// The constant [`Anim::frame`] value at rest; no animated frame can equal it.
pub(super) const REST_FRAME: u64 = 1_000;
/// Time away from the welcome screen after which returning to it replays the spin.
const REPLAY_GAP: Duration = Duration::from_secs(1);

/// What to draw: the angle about the vertical axis (0 faces forward) and the gust progress in `[0, 1)`, if the gust is playing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct Pose {
    pub(super) theta: f32,
    pub(super) gust: Option<f32>,
}

impl Pose {
    /// Facing forward, no gust: the settled look.
    pub(super) const REST: Pose = Pose {
        theta: 0.0,
        gust: None,
    };
}

/// Angle in radians after `secs` of spin; exactly 0 once the spin is over.
pub(super) fn angle_at(secs: f32) -> f32 {
    if secs <= 0.0 || secs >= SPIN_TOTAL_SECS {
        return 0.0;
    }
    let cruise_speed = TAU / REV_SECS;
    if secs < CRUISE_SECS {
        return cruise_speed * secs;
    }
    let u = secs - CRUISE_SECS;
    cruise_speed * (CRUISE_SECS + u - u * u / (2.0 * EASE_SECS))
}

/// The pose `secs` into the timeline.
pub(super) fn pose_at(secs: f32) -> Pose {
    if secs >= SPIN_TOTAL_SECS {
        return Pose::REST;
    }
    let gust = (secs >= GUST_START_SECS).then(|| ((secs - GUST_START_SECS) / GUST_SECS).min(0.999));
    Pose {
        theta: angle_at(secs),
        gust,
    }
}

/// Which guards say the spin must not play.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AnimEnv {
    pub(super) ssh: bool,
    pub(super) no_color: bool,
    pub(super) config_off: bool,
}

impl AnimEnv {
    fn detect() -> Self {
        Self::from_vars(
            |k| std::env::var_os(k).is_some(),
            !(crate::appearance::cache::load_animations()
                && crate::appearance::cache::load_background_mark_animate()),
        )
    }

    /// `is_set` answers whether an environment variable is set (to anything).
    pub(super) fn from_vars(is_set: impl Fn(&str) -> bool, config_off: bool) -> Self {
        Self {
            ssh: is_set("SSH_CONNECTION") || is_set("SSH_TTY"),
            no_color: is_set("NO_COLOR"),
            config_off,
        }
    }

    pub(super) fn disabled_reason(&self) -> Option<&'static str> {
        if self.ssh {
            Some("ssh session")
        } else if self.no_color {
            Some("NO_COLOR")
        } else if self.config_off {
            Some("ui.animations / ui.background_mark_animate = false")
        } else {
            None
        }
    }

    pub(super) fn allows_animation(&self) -> bool {
        self.disabled_reason().is_none()
    }
}

/// The spin's clock and its overrides. Pure: every method takes `now`.
#[derive(Debug, Clone)]
pub(super) struct Anim {
    start: Instant,
    /// A key was pressed: held at rest until the next replay.
    stopped: bool,
    /// Set while the terminal is unfocused.
    unfocused_since: Option<Instant>,
    /// Last time the welcome screen reported itself visible.
    last_seen: Instant,
}

impl Anim {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            start: now,
            stopped: false,
            unfocused_since: None,
            last_seen: now,
        }
    }

    pub(super) fn restart(&mut self, now: Instant) {
        self.start = now;
        self.stopped = false;
        if self.unfocused_since.is_some() {
            self.unfocused_since = Some(now);
        }
    }

    /// The welcome screen is on screen at `now`; replays the spin when it has been away.
    pub(super) fn note_visible(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_seen) > REPLAY_GAP {
            self.restart(now);
        }
        self.last_seen = now;
    }

    /// Any key press: jump to the settled frame and stay there.
    pub(super) fn snap_to_rest(&mut self) {
        self.stopped = true;
    }

    /// Focus events. The clock stops while unfocused (the settled frame shows) and resumes where it left off.
    pub(super) fn set_focused(&mut self, now: Instant, focused: bool) {
        match (focused, self.unfocused_since) {
            (false, None) => self.unfocused_since = Some(now),
            (true, Some(since)) => {
                self.start += now.saturating_duration_since(since);
                self.unfocused_since = None;
            }
            _ => {}
        }
    }

    /// Seconds into the timeline, or None when the mark is at rest.
    fn secs(&self, now: Instant, allowed: bool) -> Option<f32> {
        if !allowed || self.stopped || self.unfocused_since.is_some() {
            return None;
        }
        let secs = now.saturating_duration_since(self.start).as_secs_f32();
        (secs < SPIN_TOTAL_SECS).then_some(secs)
    }

    pub(super) fn pose(&self, now: Instant, allowed: bool) -> Pose {
        self.secs(now, allowed).map_or(Pose::REST, pose_at)
    }

    /// Throttled frame counter: advances at [`SPIN_FPS`] while playing and is the constant [`REST_FRAME`] at rest.
    pub(super) fn frame(&self, now: Instant, allowed: bool) -> u64 {
        self.secs(now, allowed)
            .map_or(REST_FRAME, |s| (s * SPIN_FPS) as u64)
    }
}

static ANIM: Mutex<Option<Anim>> = Mutex::new(None);

fn with_anim<R>(f: impl FnOnce(&mut Anim, Instant) -> R) -> R {
    let now = Instant::now();
    let mut guard = ANIM.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(|| Anim::new(now)), now)
}

/// Whether the spin may play in this process. Unit tests never spin, so frames rendered through the live path are deterministic.
fn animation_allowed() -> bool {
    #[cfg(test)]
    {
        false
    }
    #[cfg(not(test))]
    {
        use std::sync::OnceLock;
        static ALLOWED: OnceLock<bool> = OnceLock::new();
        *ALLOWED.get_or_init(|| AnimEnv::detect().allows_animation())
    }
}

/// The pose to draw now.
pub(super) fn current_pose() -> Pose {
    let allowed = animation_allowed();
    with_anim(|a, now| a.pose(now, allowed))
}

/// Quantized frame for the current wall-clock phase. The welcome screen redraws only when this advances, so the spin repaints at about
/// [`SPIN_FPS`] and a settled mark repaints nothing: the value is constant at rest, whenever animation is disabled, and while the mark is not on screen.
pub fn mark_frame() -> u64 {
    let painted_at = *PAINTED_AT.lock().unwrap_or_else(|e| e.into_inner());
    // A mark that is not on screen (hidden while typing, too small, no colour) must not drive redraws; the next paint resumes it
    if !still_visible(painted_at, Instant::now()) {
        return REST_FRAME;
    }
    let allowed = animation_allowed();
    with_anim(|a, now| a.frame(now, allowed))
}

/// How long after the last paint the mark still counts as on screen.
const PAINT_FRESH: Duration = Duration::from_millis(400);

static PAINTED_AT: Mutex<Option<Instant>> = Mutex::new(None);

/// Whether a mark painted at `painted_at` is still on screen at `now`: the spin only advances frames while it is.
pub(super) fn still_visible(painted_at: Option<Instant>, now: Instant) -> bool {
    painted_at.is_some_and(|t| now.saturating_duration_since(t) <= PAINT_FRESH)
}

/// Called by the painter each time the mark is drawn.
pub(super) fn note_painted() {
    *PAINTED_AT.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
}

/// Whether the mark's spin is playing now, or has not started yet (its first paint starts it). False once the mark rests,
/// whenever animation is off, and while it is stopped or the terminal is unfocused: then nothing on the welcome screen
/// moves and the screen only needs a heartbeat.
pub(crate) fn spin_pending() -> bool {
    let allowed = animation_allowed();
    match &*ANIM.lock().unwrap_or_else(|e| e.into_inner()) {
        None => allowed,
        Some(anim) => anim.secs(Instant::now(), allowed).is_some(),
    }
}

/// Called every welcome tick: replays the spin when the screen is returned to.
pub(crate) fn note_visible() {
    with_anim(|a, now| a.note_visible(now));
}

/// Called on any key press on the welcome screen: the mark snaps to rest and stays there.
pub(crate) fn snap_to_rest() {
    with_anim(|a, _| a.snap_to_rest());
}

/// Called on terminal focus events.
pub(crate) fn set_focused(focused: bool) {
    with_anim(|a, now| a.set_focused(now, focused));
}

#[cfg(test)]
#[path = "wind_spin_tests.rs"]
mod tests;
