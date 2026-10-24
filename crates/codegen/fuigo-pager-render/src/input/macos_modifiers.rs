//! Native macOS modifier key detection via CoreGraphics.
//!
//! Reads modifier state straight from the OS rather than from the PTY's key events.
//!
//! CoreGraphics is only asked when this process's security session has graphic (window server) access. A login over SSH
//! with nobody at the console has no such session, and `CGEventSourceFlagsState` can block there for as long as the
//! connection lives, which hung `fuigo` on its first modifier check. Without a GUI session no modifier can be held on
//! this process's behalf anyway, so the answer is "none" and CoreGraphics is never called. The decision logic lives in
//! [`super::modifier_gate`] so it is unit-tested on every OS.

use super::modifier_gate;

// CoreGraphics CGEventSourceFlagsState returns the current global modifier flags without requiring any special permissions
#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGEventSourceFlagsState(stateID: i32) -> u64;
}

// Security.framework <Security/AuthSession.h>. SessionGetInfo reads this process's own session attributes from the
// kernel/securityd session table; it does not talk to the window server, so it cannot hang the way the CG call can.
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SessionGetInfo(
        caller_security_session: u32,
        session_id: *mut u32,
        attributes: *mut u32,
    ) -> i32;
}

const K_CG_EVENT_SOURCE_STATE_HID_SYSTEM_STATE: i32 = 1;
/// `callerSecuritySession` (-1): ask about the calling process's own session.
const CALLER_SECURITY_SESSION: u32 = u32::MAX;
/// `sessionHasGraphicAccess`: the session may use the window server (an Aqua login session).
const SESSION_HAS_GRAPHIC_ACCESS: u32 = 0x0010;

fn flags() -> u64 {
    // SAFETY: CGEventSourceFlagsState is a stable, public CoreGraphics API
    // available since macOS 10.4. Integer in, integer out, no pointers
    // cross the boundary.
    unsafe { CGEventSourceFlagsState(K_CG_EVENT_SOURCE_STATE_HID_SYSTEM_STATE) }
}

/// Whether this process's security session has window-server access. Any error counts as "no": the modifier rescue is
/// a convenience, and a false "no" costs nothing while a false "yes" can hang startup.
fn session_has_graphic_access() -> bool {
    let mut session_id: u32 = 0;
    let mut attributes: u32 = 0;
    // SAFETY: both out-pointers refer to live, writable u32 locals for the duration of the call.
    let status =
        unsafe { SessionGetInfo(CALLER_SECURITY_SESSION, &mut session_id, &mut attributes) };
    status == 0 && attributes & SESSION_HAS_GRAPHIC_ACCESS != 0
}

/// The session's graphic access cannot change under a running process, so it is read once.
fn has_gui_session() -> bool {
    static HAS_GUI: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *HAS_GUI.get_or_init(session_has_graphic_access)
}

/// One CG syscall (skipped without a GUI session), all modifier bits decoded.
pub fn snapshot() -> super::ModifierState {
    modifier_gate::snapshot_with(has_gui_session, flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_test_modifier_detection() {
        let s = snapshot();
        let _ = s.command;
        let _ = s.option;
        let _ = s.shift;
        let _ = s.control;
    }
}
