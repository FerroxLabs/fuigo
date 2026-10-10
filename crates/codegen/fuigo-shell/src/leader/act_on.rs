//! The one process an eviction may signal or terminate.
//!
//! Unix: the pid in the lock file, exactly as before packet 2 round 2 (`kill_process_by_pid`, `is_process_alive`).
//!
//! Windows: the lock file cannot be read while its lock is held, and the pid inside a `GetLeaderInfo` payload is written by
//! whoever serves the pipe, so it is only ever DISPLAYED. The pid to act on comes from the OS (`GetNamedPipeServerProcessId`
//! on the client's own connection) and the process is opened ONCE with `PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION`;
//! its image is checked on that handle and `TerminateProcess` goes through the same handle, so the process that passed
//! the check is the process that is terminated (a recycled pid cannot slip in between).
use std::io;

/// A process that is safe to act on. Obtain one with [`ActTarget::from_lock_pid`] (unix) or [`ActTarget::from_os_server_pid`] (Windows).
pub(super) struct ActTarget {
    pid: u32,
    #[cfg(windows)]
    process: win::CheckedProcess,
}

impl ActTarget {
    pub(super) fn pid(&self) -> u32 {
        self.pid
    }
    /// Unix: the pid read from the lock file, unchanged from before.
    #[cfg(not(windows))]
    pub(super) fn from_lock_pid(pid: u32) -> Self {
        Self { pid }
    }
    /// Windows: open `pid` (an OS-reported pipe-server pid), refuse it unless its image is a Fuigo binary, keep the handle.
    #[cfg(windows)]
    pub(super) fn from_os_server_pid(pid: u32) -> Option<Self> {
        let process = win::CheckedProcess::open_if(pid, win::is_fuigo_image)?;
        Some(Self { pid, process })
    }
    #[cfg(windows)]
    pub(super) fn terminate(&self) -> io::Result<()> {
        self.process.terminate()
    }
    #[cfg(not(windows))]
    pub(super) fn terminate(&self) -> io::Result<()> {
        crate::util::kill_process_by_pid(self.pid)
    }
    #[cfg(windows)]
    pub(super) fn is_alive(&self) -> bool {
        self.process.is_alive()
    }
    #[cfg(not(windows))]
    pub(super) fn is_alive(&self) -> bool {
        crate::util::is_process_alive(self.pid)
    }
}

/// The pid an eviction may open: the one recorded at connect, only if the OS still reports the same one when asked again
/// immediately before opening. A failed re-query or a different pid means "do not act" (the pid may have been recycled).
#[cfg(any(windows, test))]
pub(super) fn pid_to_act_on(recorded_at_connect: Option<u32>, requeried_now: Option<u32>) -> Option<u32> {
    match (recorded_at_connect, requeried_now) {
        (Some(a), Some(b)) if a == b => Some(a),
        _ => None,
    }
}

/// Read a process image path with a buffer of 1024 units and, if the OS says it is too small, once more with 32768.
/// `call` fills the buffer, sets the length written, and returns the Win32 error code on failure.
#[cfg(any(windows, test))]
pub(super) fn read_image_with_retry(mut call: impl FnMut(&mut [u16], &mut u32) -> Result<(), u32>) -> Option<String> {
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    for capacity in [1024usize, 32768] {
        let mut buffer = vec![0u16; capacity];
        let mut size = capacity as u32;
        match call(&mut buffer, &mut size) {
            Ok(()) => return Some(String::from_utf16_lossy(&buffer[..(size as usize).min(capacity)])),
            Err(ERROR_INSUFFICIENT_BUFFER) => continue,
            Err(_) => return None,
        }
    }
    None
}

#[cfg(windows)]
pub(super) mod win {
    use std::io;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
        QueryFullProcessImageNameW, TerminateProcess,
    };
    use windows::core::PWSTR;

    const STILL_ACTIVE: u32 = 259;

    /// What counts as a Fuigo image: the FILE NAME of the executable (not the directory) starts with `fuigo` and ends with
    /// `.exe`, case-insensitively. An arbitrary program (`cmd.exe`, `notepad.exe`) is refused, and so is one that merely sits in a
    /// directory with `fuigo` in its name. Another Fuigo binary of the same user (a second install) is accepted on purpose.
    /// This is stricter than `util::is_fuigo_process`, which looks for `fuigo` anywhere in the full path.
    pub(in crate::leader) fn is_fuigo_image(image_path: &str) -> bool {
        let name = image_path.rsplit(['\\', '/']).next().unwrap_or("").to_ascii_lowercase();
        name.starts_with("fuigo") && name.ends_with(".exe")
    }

    /// An open process handle whose image has passed a check; terminating goes through this same handle.
    pub(in crate::leader) struct CheckedProcess(HANDLE);
    // SAFETY: a process HANDLE is a kernel object reference, valid from any thread.
    unsafe impl Send for CheckedProcess {}
    unsafe impl Sync for CheckedProcess {}

    impl CheckedProcess {
        /// Open `pid` once and keep the handle only when `accept(image path)` is true. `None` if the process is gone, cannot be
        /// opened or queried, or is refused.
        pub(in crate::leader) fn open_if(pid: u32, accept: impl Fn(&str) -> bool) -> Option<Self> {
            // SAFETY: plain Win32 call; the returned handle is owned by `CheckedProcess` and closed in `Drop`.
            let handle = unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
            let process = Self(handle);
            let image = super::read_image_with_retry(|buffer, size| {
                // SAFETY: the handle is live; `buffer` holds `*size` u16.
                unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), size) }
                    .map_err(|e| (e.code().0 as u32) & 0xFFFF)
            })?;
            accept(&image).then_some(process)
        }
        pub(in crate::leader) fn terminate(&self) -> io::Result<()> {
            if !self.is_alive() {
                return Ok(());
            }
            // SAFETY: the handle is live and has PROCESS_TERMINATE.
            unsafe { TerminateProcess(self.0, 0) }.map_err(|e| io::Error::other(format!("TerminateProcess: {e}")))
        }
        pub(in crate::leader) fn is_alive(&self) -> bool {
            let mut code = 0u32;
            // SAFETY: the handle is live and has PROCESS_QUERY_LIMITED_INFORMATION.
            unsafe { GetExitCodeProcess(self.0, &mut code) }.is_ok() && code == STILL_ACTIVE
        }
    }
    impl Drop for CheckedProcess {
        fn drop(&mut self) {
            // SAFETY: the handle was opened by `open_if` and is closed once.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::win::{CheckedProcess, is_fuigo_image};
    use super::ActTarget;

    #[test]
    fn only_a_fuigo_file_name_is_a_fuigo_image() {
        assert!(is_fuigo_image(r"C:\Users\a\AppData\Local\Fuigo\bin\fuigo.exe"));
        assert!(is_fuigo_image(r"C:\t\target\debug\deps\fuigo_shell-1a2b.exe"));
        assert!(!is_fuigo_image(r"C:\Windows\System32\cmd.exe"));
        assert!(!is_fuigo_image(r"C:\Users\fuigo\evil.exe"), "a directory name does not count");
        assert!(!is_fuigo_image(r"C:\x\fuigo.txt"));
        assert!(!is_fuigo_image(""));
    }

    /// The candidate is a child this test spawned; its image is `PING.EXE`, not Fuigo, so no handle is returned to terminate with.
    /// The test then ends its own child by the handle it owns.
    #[test]
    fn a_process_that_is_not_fuigo_is_refused_and_keeps_running() {
        let mut child = std::process::Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn the harmless child");
        let refused = ActTarget::from_os_server_pid(child.id()).is_none();
        let still_running = child.try_wait().unwrap().is_none();
        child.kill().unwrap();
        let _ = child.wait();
        assert!(refused, "a non-Fuigo image must be refused");
        assert!(still_running, "refusing must not touch the process");
    }

    #[test]
    fn a_gone_process_gives_no_target_and_this_fuigo_test_binary_is_accepted() {
        let mut child = std::process::Command::new("cmd").args(["/C", "exit", "0"]).spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        // Either the process cannot be opened any more, or the handle reports it as exited.
        assert!(CheckedProcess::open_if(pid, |_| true).is_none_or(|p| !p.is_alive()));
        // Only built, never terminated: this process is the test runner.
        let me = ActTarget::from_os_server_pid(std::process::id()).expect("the test binary is named fuigo_shell-*.exe");
        assert!(me.is_alive());
    }
}

/// Items (h) and (i) of the W-pipe packet: decisions with seams, on every platform.
#[cfg(test)]
mod pure_tests {
    use super::{pid_to_act_on, read_image_with_retry};

    #[test]
    fn h_the_pid_is_acted_on_only_if_the_os_still_reports_the_same_one() {
        assert_eq!(pid_to_act_on(Some(10), Some(10)), Some(10));
        assert_eq!(pid_to_act_on(Some(10), Some(11)), None, "a changed pid is not acted on");
        assert_eq!(pid_to_act_on(Some(10), None), None, "a failed re-query is not acted on");
        assert_eq!(pid_to_act_on(None, Some(10)), None);
        assert_eq!(pid_to_act_on(None, None), None);
    }

    fn fake_query(path_len: usize) -> impl FnMut(&mut [u16], &mut u32) -> Result<(), u32> {
        move |buf, size| {
            if buf.len() < path_len + 1 {
                return Err(122); // ERROR_INSUFFICIENT_BUFFER
            }
            for u in buf.iter_mut().take(path_len) {
                *u = u16::from(b'a');
            }
            *size = path_len as u32;
            Ok(())
        }
    }

    #[test]
    fn i_a_long_image_path_is_read_after_one_retry() {
        let short = read_image_with_retry(fake_query(100)).unwrap();
        assert_eq!(short.len(), 100);
        let long = read_image_with_retry(fake_query(2000)).unwrap();
        assert_eq!(long.len(), 2000, "a path longer than 1024 units is read on the retry");
    }

    #[test]
    fn i_other_errors_and_an_oversized_path_give_none() {
        assert!(read_image_with_retry(|_, _| Err(5)).is_none(), "access denied is not retried");
        assert!(read_image_with_retry(fake_query(40000)).is_none(), "still too long after the retry");
    }
}
