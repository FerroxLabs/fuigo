//! Cadences painted from `spinner_tick`, and the tick gate that turns them into redraws.
//!
//! The renderer records which animations it actually painted this frame ([`PaintedAnimations`]); a projected
//! row that was not painted (filtered out, in a collapsed section, past the `… N more` fold) does not count.
//! [`DashboardState::tick`] then reports a redraw only on a tick where one of the painted cadences changes
//! frame, so an idle spinner tick or a hidden working row never repaints an identical frame.

use super::state::{DashboardState, RowState};

/// Show each spinner frame for this many `spinner_tick` ticks.
/// The frames come from [`crate::glyphs::dot_spinner_frames`] so they degrade to an ASCII pulse on legacy Windows consoles.
pub(crate) const SPINNER_DIVISOR: u64 = 4;

/// How many ticks each phase of the `NeedsInput` bullet blink lasts.
/// At the ~30 Hz dashboard tick this toggles roughly every 0.33 s, about a 1.5 Hz blink.
pub(crate) const NEEDS_INPUT_BLINK_DIVISOR: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Animation {
    Spinner,
    Blink,
}

impl Animation {
    fn on_boundary(self, tick: u64) -> bool {
        let divisor = match self {
            Self::Spinner => SPINNER_DIVISOR,
            Self::Blink => NEEDS_INPUT_BLINK_DIVISOR,
        };
        tick.is_multiple_of(divisor)
    }
}

/// Which cadences the last frame painted. Reset at the top of every `render_dashboard` and marked by the row,
/// narrow-row and header-chip painters as they put an animated glyph on screen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PaintedAnimations {
    pub(crate) spinner: bool,
    pub(crate) blink: bool,
}

impl PaintedAnimations {
    pub(crate) fn mark(&mut self, animation: Animation) {
        match animation {
            Animation::Spinner => self.spinner = true,
            Animation::Blink => self.blink = true,
        }
    }

    pub(crate) fn any(self) -> bool {
        self.spinner || self.blink
    }

    fn changes_at(self, tick: u64) -> bool {
        (self.spinner && Animation::Spinner.on_boundary(tick))
            || (self.blink && Animation::Blink.on_boundary(tick))
    }
}

impl RowState {
    /// Wide-layout icon cadence. Narrow NeedsInput is a static diamond.
    pub(crate) fn animation(self) -> Option<Animation> {
        match self {
            Self::Working => Some(Animation::Spinner),
            Self::NeedsInput => Some(Animation::Blink),
            Self::Idle | Self::Inactive | Self::Completed | Self::Failed => None,
        }
    }
}

impl DashboardState {
    /// Advance the animation counter. Returns whether the frame painted last time changes at this tick.
    pub(crate) fn tick(&mut self) -> bool {
        self.spinner_tick = self.spinner_tick.wrapping_add(1);
        self.painted_animations.changes_at(self.spinner_tick)
    }
}
