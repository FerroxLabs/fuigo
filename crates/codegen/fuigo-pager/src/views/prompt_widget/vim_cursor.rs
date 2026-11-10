//! Terminal cursor shape for prompt vim: a block in Normal mode, a bar in Insert mode.
//!
//! The shape is a DECSCUSR escape appended to the frame's post-flush bytes.
//! It is emitted only when the wanted shape changes, and never while prompt vim is off (so the default path writes nothing).
//! Turning vim off after a shape was set emits the "default shape" escape once.

use std::cell::Cell;

use super::vim::VimMode;

thread_local! {
    static LAST: Cell<Option<&'static str>> = const { Cell::new(None) };
}

const DEFAULT_SHAPE: &str = "\x1b[0 q";

/// The escape to write for this frame, if the wanted shape changed since the last one written.
///
/// `blink` follows `[ui].cursor_blink = true`; otherwise the shapes are steady.
pub(crate) fn shape_escape(enabled: bool, mode: VimMode, blink: bool) -> Option<&'static str> {
    let want = enabled.then_some(match (mode, blink) {
        (VimMode::Normal, false) => "\x1b[2 q",
        (VimMode::Normal, true) => "\x1b[1 q",
        (VimMode::Insert, false) => "\x1b[6 q",
        (VimMode::Insert, true) => "\x1b[5 q",
    });
    LAST.with(|last| {
        if last.get() == want {
            return None;
        }
        last.set(want);
        Some(want.unwrap_or(DEFAULT_SHAPE))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_writes_nothing() {
        assert_eq!(shape_escape(false, VimMode::Insert, false), None);
        assert_eq!(shape_escape(false, VimMode::Normal, true), None);
    }

    #[test]
    fn block_in_normal_bar_in_insert_emitted_on_change_only() {
        assert_eq!(shape_escape(true, VimMode::Insert, false), Some("\x1b[6 q"));
        assert_eq!(shape_escape(true, VimMode::Insert, false), None);
        assert_eq!(shape_escape(true, VimMode::Normal, false), Some("\x1b[2 q"));
        assert_eq!(shape_escape(true, VimMode::Normal, false), None);
        assert_eq!(shape_escape(true, VimMode::Insert, false), Some("\x1b[6 q"));
    }

    #[test]
    fn blinking_variants_follow_cursor_blink() {
        assert_eq!(shape_escape(true, VimMode::Normal, true), Some("\x1b[1 q"));
        assert_eq!(shape_escape(true, VimMode::Insert, true), Some("\x1b[5 q"));
    }

    #[test]
    fn turning_vim_off_restores_the_default_shape_once() {
        assert_eq!(shape_escape(true, VimMode::Normal, false), Some("\x1b[2 q"));
        assert_eq!(shape_escape(false, VimMode::Normal, false), Some("\x1b[0 q"));
        assert_eq!(shape_escape(false, VimMode::Normal, false), None);
    }
}
