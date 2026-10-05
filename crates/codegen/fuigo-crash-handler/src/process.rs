//! Process identity for per-process crash slots.
//!
//! A slot is named after its owner's pid AND an OS start-time token, so a
//! reader can tell a live session (leave its slot alone) from a dead one
//! (report its blob), and a recycled pid (the token differs) from the
//! original owner.

/// Whether the owner of a slot is still running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// The process with this pid and start token is running.
    Alive,
    /// A process with this pid is running but its start time could not be
    /// verified (no token recorded, or the token was unreadable). Treated as
    /// alive so a live session's slot is never touched.
    AliveUnverified,
    /// No such process, or the pid now belongs to a different process.
    Dead,
}

/// An opaque per-process start-time token, stable for the life of the
/// process and identical whichever process reads it. `None` when the OS
/// does not expose it (or the process does not exist).
pub fn start_token(pid: u32) -> Option<u64> {
    imp::start_token(pid).filter(|&t| t != 0)
}

/// Decide whether the slot owner `(pid, token)` is still running.
/// `token == 0` means the owner recorded no token.
pub fn owner_state(pid: u32, token: u64) -> Owner {
    if pid == 0 {
        return Owner::Dead;
    }
    if token != 0 {
        match start_token(pid) {
            Some(t) if t == token => return Owner::Alive,
            Some(_) => return Owner::Dead, // pid recycled by another process
            None => {}
        }
    }
    if imp::pid_exists(pid) {
        Owner::AliveUnverified
    } else {
        Owner::Dead
    }
}

#[cfg(target_os = "linux")]
mod imp {
    /// Field 22 of `/proc/<pid>/stat`: start time in clock ticks since boot.
    pub(super) fn start_token(pid: u32) -> Option<u64> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // `comm` (field 2) may contain spaces and parentheses; fields after
        // the last ')' are well-formed. Field 3 is index 0 there, so field 22
        // is index 19.
        let rest = &stat[stat.rfind(')')? + 1..];
        rest.split_whitespace().nth(19)?.parse().ok()
    }

    pub(super) fn pid_exists(pid: u32) -> bool {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

#[cfg(target_os = "macos")]
mod imp {
    pub(super) fn start_token(pid: u32) -> Option<u64> {
        let pid = libc::c_int::try_from(pid).ok()?;
        unsafe {
            let mut info: libc::proc_bsdinfo = std::mem::zeroed();
            let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
            let n = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut libc::proc_bsdinfo as *mut libc::c_void,
                size,
            );
            if n != size {
                return None;
            }
            Some(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
        }
    }

    pub(super) fn pid_exists(pid: u32) -> bool {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
mod imp {
    pub(super) fn start_token(_pid: u32) -> Option<u64> {
        None
    }

    pub(super) fn pid_exists(pid: u32) -> bool {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, FILETIME, GetLastError,
    };
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, GetProcessTimes, OpenProcess};

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;

    pub(super) fn start_token(pid: u32) -> Option<u64> {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut code: u32 = 0;
            let running = GetExitCodeProcess(h, &mut code) != 0 && code == STILL_ACTIVE;
            let zero = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };
            let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
            let ok = GetProcessTimes(h, &mut created, &mut exited, &mut kernel, &mut user) != 0;
            CloseHandle(h);
            if !ok || !running {
                return None;
            }
            Some((created.dwHighDateTime as u64) << 32 | created.dwLowDateTime as u64)
        }
    }

    pub(super) fn pid_exists(pid: u32) -> bool {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return GetLastError() == ERROR_ACCESS_DENIED;
            }
            let mut code: u32 = 0;
            let running = GetExitCodeProcess(h, &mut code) != 0 && code == STILL_ACTIVE;
            CloseHandle(h);
            running
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub(super) fn start_token(_pid: u32) -> Option<u64> {
        None
    }
    pub(super) fn pid_exists(_pid: u32) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn own_token_is_stable_and_alive() {
        let me = std::process::id();
        let t1 = start_token(me).expect("own start token");
        let t2 = start_token(me).expect("own start token");
        assert_eq!(t1, t2);
        assert_eq!(owner_state(me, t1), Owner::Alive);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn recycled_pid_is_dead() {
        let me = std::process::id();
        let t = start_token(me).expect("own start token");
        // Same pid, different start time: a different process owns the pid now.
        assert_eq!(owner_state(me, t.wrapping_add(1)), Owner::Dead);
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::disallowed_methods)] // `true` is waited on immediately
    fn reaped_child_is_dead() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = child.id();
        child.wait().expect("wait");
        assert_eq!(owner_state(pid, 12345), Owner::Dead);
        assert_eq!(owner_state(pid, 0), Owner::Dead);
    }

    #[cfg(windows)]
    #[test]
    #[allow(clippy::disallowed_methods)] // waited on immediately
    fn reaped_child_is_dead_windows() {
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .spawn()
            .expect("spawn cmd");
        let pid = child.id();
        child.wait().expect("wait");
        assert_eq!(owner_state(pid, 12345), Owner::Dead);
    }

    #[test]
    fn pid_zero_is_dead() {
        assert_eq!(owner_state(0, 1), Owner::Dead);
    }
}
