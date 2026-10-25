//! Platform-neutral core of the macOS modifier probe: decode CoreGraphics flag bits, and refuse to ask CoreGraphics
//! at all when this process has no GUI session.
//!
//! `CGEventSourceFlagsState` talks to the window server. A process in a session with no window-server access (a login
//! over SSH with nobody at the console) can block in that call for as long as the connection lives, which hangs
//! `fuigo` on its first modifier-key check. The caller supplies both the "does this session have graphic access" probe
//! and the flag reader as closures, so the gate is unit-testable on any OS: a session without a GUI never reaches the
//! reader.

// Only the macOS probe calls this outside tests; the tests exercise it on every OS.
#![cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]

use super::ModifierState;

// CGEventFlags bitmask constants from <CoreGraphics/CGEventTypes.h>
pub(crate) const K_CG_EVENT_FLAG_MASK_SHIFT: u64 = 0x0002_0000;
pub(crate) const K_CG_EVENT_FLAG_MASK_CONTROL: u64 = 0x0004_0000;
pub(crate) const K_CG_EVENT_FLAG_MASK_ALTERNATE: u64 = 0x0008_0000; // Option key
pub(crate) const K_CG_EVENT_FLAG_MASK_COMMAND: u64 = 0x0010_0000;

/// All modifier bits decoded from a CoreGraphics flag word.
pub(crate) fn decode(flags: u64) -> ModifierState {
    ModifierState {
        command: flags & K_CG_EVENT_FLAG_MASK_COMMAND != 0,
        option: flags & K_CG_EVENT_FLAG_MASK_ALTERNATE != 0,
        shift: flags & K_CG_EVENT_FLAG_MASK_SHIFT != 0,
        control: flags & K_CG_EVENT_FLAG_MASK_CONTROL != 0,
    }
}

/// Modifier state, or "none held" without calling `read_flags` when `has_gui` reports no graphic session.
pub(crate) fn snapshot_with(
    has_gui: impl FnOnce() -> bool,
    read_flags: impl FnOnce() -> u64,
) -> ModifierState {
    if !has_gui() {
        return ModifierState::default();
    }
    decode(read_flags())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn no_gui_session_never_calls_coregraphics_and_reports_no_modifiers() {
        let calls = Cell::new(0u32);
        let state = snapshot_with(
            || false,
            || {
                calls.set(calls.get() + 1);
                u64::MAX
            },
        );
        assert_eq!(calls.get(), 0, "CGEventSourceFlagsState must not be called without a GUI session");
        assert_eq!(state, ModifierState::default());
    }

    #[test]
    fn gui_session_reads_and_decodes_flags() {
        let state = snapshot_with(
            || true,
            || K_CG_EVENT_FLAG_MASK_SHIFT | K_CG_EVENT_FLAG_MASK_COMMAND,
        );
        assert_eq!(
            state,
            ModifierState { command: true, option: false, shift: true, control: false }
        );
    }

    #[test]
    fn gui_probe_runs_before_flags_are_read() {
        let order = std::cell::RefCell::new(Vec::new());
        let _ = snapshot_with(
            || {
                order.borrow_mut().push("probe");
                true
            },
            || {
                order.borrow_mut().push("read");
                0
            },
        );
        assert_eq!(*order.borrow(), vec!["probe", "read"]);
    }
}
