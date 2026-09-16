//! Windows counterpart of `PR_SET_PDEATHSIG` for the *current* process.
//!
//! Windows has no kernel parent-death signal, so the binding is a watcher:
//! find the parent's pid ([`CreateToolhelp32Snapshot`]), open a waitable
//! handle to it, and park a thread on that handle. When the parent exits the
//! thread runs the hook registered with [`crate::set_parent_death_hook`] for
//! at most [`crate::PARENT_DEATH_HOOK_BOUND`] (the binary's log line and
//! telemetry flush), reaps [`crate::global_process_scope`] (what fuigo's own
//! SIGTERM handler does on Linux) and terminates this process with
//! [`PARENT_DEATH_EXIT_CODE`]. Termination closes every handle the process
//! holds, so each [`crate::ProcessGroup`] Job Object
//! (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) takes its child tree down with it.
//!
//! # Why no process-wide Job Object
//!
//! Joining this process to its own kill-on-close job would also catch the
//! children that are designed to outlive it: the non-blocking `fuigo update`
//! download the stdio agent starts, and a leader daemon the stdio bridge
//! respawns on reconnect. `CREATE_BREAKAWAY_FROM_JOB` cannot rescue them —
//! it fails with `ERROR_ACCESS_DENIED` whenever an embedder's outer job lacks
//! `JOB_OBJECT_LIMIT_BREAKAWAY_OK` — so they would die silently with the
//! agent. Every child fuigo owns already sits in its own kill-on-close job
//! ([`crate::ProcessGroup`]: MCP servers, LSP servers, hooks, terminals), and
//! those jobs die with this process, so the watcher is the missing piece.

use std::io;
use std::sync::Mutex;

use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, INFINITE, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, TerminateProcess, WaitForSingleObject,
};

/// Exit code of a process torn down because its parent exited: 128 + SIGTERM,
/// the code fuigo's Linux SIGTERM handler exits with for the same event.
pub const PARENT_DEATH_EXIT_CODE: u32 = 143;

/// A Win32 handle closed on drop.
struct OwnedHandle(HANDLE);

// SAFETY: a process handle is a kernel object reference usable from any thread.
unsafe impl Send for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle is owned, valid, and closed exactly once here.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Whether the watcher is already running; arming twice must not start two.
static ARMED: Mutex<bool> = Mutex::new(false);

/// Arm the watcher. See the [module docs](self).
///
/// # Errors
///
/// Fails, leaving nothing armed, when the parent cannot be found or opened,
/// when it already exited (its pid is gone, its process object is already
/// signalled because someone still holds its handle, or its pid now names a
/// process younger than this one), or when the watcher thread cannot start.
/// Idempotent: a second call after a successful one returns `Ok(())`.
pub(crate) fn arm() -> io::Result<()> {
    let mut armed = ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if *armed {
        return Ok(());
    }
    let parent = open_parent()?;
    std::thread::Builder::new()
        .name("fuigo-parent-death".into())
        .spawn(move || watch(parent))?;
    *armed = true;
    Ok(())
}

/// Block until `parent` exits, then take this process down.
fn watch(parent: OwnedHandle) {
    // SAFETY: `parent` is a valid handle opened with SYNCHRONIZE.
    if unsafe { WaitForSingleObject(parent.0, INFINITE) } != WAIT_OBJECT_0 {
        // WAIT_FAILED: the binding is lost; stdin EOF remains the cleanup.
        return;
    }
    // Record and flush first (bounded), then reap owned trees and exit.
    crate::run_parent_death_hook();
    crate::global_process_scope().kill_all();
    // SAFETY: terminating the current process; the handle needs no closing.
    let _ = unsafe { TerminateProcess(GetCurrentProcess(), PARENT_DEATH_EXIT_CODE) };
}

/// A waitable handle to the process that spawned this one.
fn open_parent() -> io::Result<OwnedHandle> {
    let parent_pid = parent_pid()?;
    // SAFETY: plain FFI call; the returned handle is owned below.
    let handle = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            parent_pid,
        )
    }
    .map_err(|e| {
        io::Error::other(format!(
            "OpenProcess(parent {parent_pid}): {e} (the parent may already have exited)"
        ))
    })?;
    let parent = OwnedHandle(handle);
    // A pid stays reserved only while some handle to its process object is
    // open, so a parent that already exited is still openable whenever a third
    // party holds its handle — the real topology here, where the client that
    // spawned this process's parent keeps the `Child` it got back. Arming on
    // such a handle makes the watcher fire at once and terminate this process
    // at startup, so an already signalled parent is refused exactly like a
    // gone pid (on Linux `PR_SET_PDEATHSIG` never fires for a parent that is
    // already dead, and the caller falls back to stdin-EOF cleanup).
    // SAFETY: `parent.0` is a valid handle opened with SYNCHRONIZE.
    if unsafe { WaitForSingleObject(parent.0, 0) } == WAIT_OBJECT_0 {
        return Err(io::Error::other(format!(
            "parent {parent_pid} already exited (its process object is still open)"
        )));
    }
    // A pid is recycled once its process exits: a "parent" created after this
    // process is an unrelated process that inherited the dead parent's pid.
    // SAFETY: both handles are valid for the duration of the calls.
    let (parent_created, own_created) = unsafe {
        (
            creation_time(parent.0)?,
            creation_time(GetCurrentProcess())?,
        )
    };
    if parent_created > own_created {
        return Err(io::Error::other(format!(
            "parent {parent_pid} already exited (its pid now names a newer process)"
        )));
    }
    Ok(parent)
}

/// The creation time of `process` in 100 ns ticks.
///
/// # Safety
///
/// `process` must be a valid handle with query access.
unsafe fn creation_time(process: HANDLE) -> io::Result<u64> {
    let mut created = FILETIME::default();
    let mut unused = [FILETIME::default(); 3];
    let [exit, kernel, user] = &mut unused;
    // SAFETY: the caller guarantees the handle; every out-pointer is live.
    unsafe { GetProcessTimes(process, &mut created, exit, kernel, user) }
        .map_err(|e| io::Error::other(format!("GetProcessTimes: {e}")))?;
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// The pid of the process that spawned this one.
fn parent_pid() -> io::Result<u32> {
    // SAFETY: plain FFI call; the snapshot handle is owned below.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| io::Error::other(format!("CreateToolhelp32Snapshot: {e}")))?;
    let snapshot = OwnedHandle(snapshot);
    // SAFETY: plain FFI call with no arguments.
    let own_pid = unsafe { GetCurrentProcessId() };
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: the snapshot is valid and `entry.dwSize` is initialised as required.
    let mut next = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    while next.is_ok() {
        if entry.th32ProcessID == own_pid {
            return Ok(entry.th32ParentProcessID);
        }
        // SAFETY: as above.
        next = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    Err(io::Error::other(format!(
        "process {own_pid} is missing from its own process snapshot"
    )))
}
