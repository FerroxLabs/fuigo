//! How the updater starts npm (P145).
//!
//! On Unix `npm` is an executable script on `PATH`, so `Command::new("npm")` works and is kept as it was.
//!
//! On Windows npm is not an `.exe`: Node's installer ships `npm.cmd` (plus `npm.ps1` and a shell script). `CreateProcessW`
//! only appends `.exe` to a bare name and ignores `PATHEXT`, so `Command::new("npm")` failed with "program not found" and
//! `fuigo update`, `fuigo update --check` and auto-update could never run on a Windows npm install (1.0.20 and earlier too).
//!
//! The fix resolves npm the way `cmd.exe` would (each absolute `PATH` directory in order, each launchable `PATHEXT`
//! extension in order) and then avoids `cmd.exe` where it can:
//! - `npm.exe` / `npm.com` (Volta and similar shims): run it directly.
//! - `npm.cmd` / `npm.bat` with `node_modules\npm\bin\npm-cli.js` beside it (the Node installer, nvm-windows, a global
//!   prefix): run `node.exe <npm-cli.js> ...` without any shell, the same thing `scripts/pinned-npm.js` does. `node.exe` is
//!   the one beside the shim, else the first `node.exe` on `PATH`. No argument ever passes through `cmd.exe`, so a
//!   registry URL or path containing `&`, `|`, `%` or quotes cannot be reinterpreted.
//! - any other batch shim: run its absolute path. Rust's standard library runs a `.cmd`/`.bat` through `cmd.exe` with
//!   its hardened batch-argument escaping (CVE-2024-24576) and refuses an argument it cannot escape safely.
//!
//! Relative and empty `PATH` entries are skipped, and the current directory is never searched, so a repository that
//! plants `npm.cmd` in the working directory is not run.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The launchable extensions `PATHEXT` may name. Others (`.ps1`, `.js`, `.vbs`, ...) cannot be started by
/// `CreateProcessW` and are skipped.
const LAUNCHABLE: &[&str] = &[".com", ".exe", ".bat", ".cmd"];

/// `PATHEXT` when the variable is unset or empty (the Windows default, launchable part).
const DEFAULT_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";

/// The program and leading arguments that start npm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NpmInvocation {
    pub(crate) program: PathBuf,
    pub(crate) prefix_args: Vec<OsString>,
}

impl NpmInvocation {
    /// `npm` by bare name (Unix).
    fn bare() -> Self {
        Self {
            program: PathBuf::from("npm"),
            prefix_args: Vec::new(),
        }
    }

    pub(crate) fn tokio_command(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(&self.prefix_args);
        cmd
    }
}

/// What a bounded npm run ended with.
pub(crate) enum Bounded {
    Done(std::process::Output),
    /// The bound fired; the whole process tree was killed and the direct child reaped.
    TimedOut,
}

/// npm's whole process tree: its Unix process group (the child is a session leader via `detach_command`'s `setsid`), or
/// a Windows job object the child joined before it ran a single instruction.
struct Tree {
    #[cfg(unix)]
    group: fuigo_tty_utils::ProcessGroup,
    #[cfg(windows)]
    job: win::Job,
}

impl Tree {
    /// Contain `child`. Fails closed: an npm that cannot be contained is not run (it was spawned suspended on Windows,
    /// and is killed by the caller).
    fn enroll(child: &tokio::process::Child) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            let mut group = fuigo_tty_utils::ProcessGroup::new()?;
            group.attach(child)?;
            Ok(Self { group })
        }
        #[cfg(windows)]
        {
            let job = win::Job::new()?;
            job.assign_and_resume(child)?;
            Ok(Self { job })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = child;
            Err(std::io::Error::other("no process-tree containment on this platform"))
        }
    }

    /// Kill every process in the tree and, on Windows, wait (bounded) until the job is empty.
    async fn kill(&self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            self.group.kill()
        }
        #[cfg(windows)]
        {
            self.job.terminate_and_wait(std::time::Duration::from_secs(5)).await
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(())
        }
    }
}

/// Kills the tree on drop unless disarmed: a cancelled caller (the leader's own cancellation, a dropped update future)
/// must not leave npm or its lifecycle scripts running (Astra P145 r1 #2). Disarmed only while the Unix group id is
/// still owned (its leader not yet reaped), so a signal can never reach a recycled group (Astra P145 r2 #1).
struct TreeGuard {
    tree: Tree,
    armed: bool,
}

impl Drop for TreeGuard {
    fn drop(&mut self) {
        if self.armed {
            #[cfg(unix)]
            let _ = self.tree.group.kill();
            #[cfg(windows)]
            self.tree.job.terminate();
        }
    }
}

/// Run npm with a wall-clock bound, killing the WHOLE process tree on timeout or cancellation (P145).
///
/// `kill_on_drop` alone kills only the direct child: `cmd.exe` for a batch shim, or npm while its `node
/// bin/postinstall.js` keeps writing the install. Containment comes first and fails closed:
/// - Unix: the child leads its own session/process group (`detach_command`); killed with SIGKILL to the group. The
///   output pipes are drained BEFORE the child is reaped, so the group id stays owned (a zombie leader still holds
///   it) until the last possible signal (r2 #1).
/// - Windows: the child is created suspended, assigned to a kill-on-close job, then resumed, so no grandchild can start
///   outside the job (r2 #2); at the bound the job is terminated and awaited until empty.
pub(crate) async fn run_tree_bounded(
    cmd: &mut tokio::process::Command,
    timeout: std::time::Duration,
) -> std::io::Result<Bounded> {
    use tokio::io::AsyncReadExt as _;
    cmd.kill_on_drop(true);
    #[cfg(windows)]
    {
        use windows::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};
        cmd.creation_flags(CREATE_NO_WINDOW.0 | CREATE_SUSPENDED.0);
    }
    #[allow(clippy::disallowed_methods)] // contained in its own process group / job right below; killed as a tree
    let mut child = cmd.spawn()?;
    let tree = match Tree::enroll(&child) {
        Ok(tree) => tree,
        Err(e) => {
            let _ = child.kill().await;
            return Err(std::io::Error::other(format!(
                "could not run npm in its own process group/job, so a stalled npm could not be stopped: {e}"
            )));
        }
    };
    let mut guard = TreeGuard { tree, armed: true };
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let waited = tokio::time::timeout(timeout, async {
        let read_out = async {
            let mut buf = Vec::new();
            if let Some(pipe) = stdout.as_mut() {
                pipe.read_to_end(&mut buf).await?;
            }
            std::io::Result::Ok(buf)
        };
        let read_err = async {
            let mut buf = Vec::new();
            if let Some(pipe) = stderr.as_mut() {
                pipe.read_to_end(&mut buf).await?;
            }
            std::io::Result::Ok(buf)
        };
        // Drain first, reap last: until `wait` reaps it, the child (possibly a zombie) keeps its pid and group id.
        let (out, err) = tokio::join!(read_out, read_err);
        let status = child.wait().await;
        (status, out, err)
    })
    .await;
    match waited {
        Ok((status, out, err)) => {
            // Reaped in this same poll: disarm before any await, so no later signal targets the released id.
            guard.armed = false;
            Ok(Bounded::Done(std::process::Output {
                status: status?,
                stdout: out?,
                stderr: err?,
            }))
        }
        Err(_) => {
            let killed = guard.tree.kill().await;
            guard.armed = false;
            // The reap is bounded too (Astra P145 r3): Windows may keep a terminated process alive while I/O is pending.
            let reaped = tokio::time::timeout(std::time::Duration::from_secs(5), child.kill()).await;
            killed.map_err(|e| std::io::Error::other(format!("npm timed out and could not be stopped: {e}")))?;
            if reaped.is_err() {
                return Err(std::io::Error::other(
                    "npm timed out and was killed, but had not exited 5 s later",
                ));
            }
            Ok(Bounded::TimedOut)
        }
    }
}

#[cfg(windows)]
mod win {
    use std::io;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};

    /// A kill-on-close job object owning npm's whole tree.
    pub(super) struct Job(HANDLE);

    // SAFETY: a job handle is a kernel handle usable from any thread.
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    impl Job {
        pub(super) fn new() -> io::Result<Self> {
            use std::mem::{size_of, zeroed};
            use windows::Win32::System::JobObjects::{
                CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JobObjectExtendedLimitInformation, SetInformationJobObject,
            };
            use windows::core::PCWSTR;
            // SAFETY: plain Win32 calls on handles this function owns.
            unsafe {
                let job = CreateJobObjectW(None, PCWSTR::null()).map_err(|e| io::Error::other(format!("CreateJobObjectW: {e}")))?;
                let job = Self(job);
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
                .map_err(|e| io::Error::other(format!("SetInformationJobObject: {e}")))?;
                Ok(job)
            }
        }

        /// Assign the (suspended) child through its own process handle, then resume its threads.
        pub(super) fn assign_and_resume(&self, child: &tokio::process::Child) -> io::Result<()> {
            use windows::Win32::System::Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
            };
            use windows::Win32::System::JobObjects::AssignProcessToJobObject;
            use windows::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};
            let raw = child.raw_handle().ok_or_else(|| io::Error::other("npm exited before it ran"))?;
            let pid = child.id().ok_or_else(|| io::Error::other("npm exited before it ran"))?;
            // SAFETY: `raw` is the child's live process handle, owned by `child` for the duration of the call; the
            // snapshot and thread handles are closed on every path.
            unsafe {
                AssignProcessToJobObject(self.0, HANDLE(raw)).map_err(|e| io::Error::other(format!("AssignProcessToJobObject: {e}")))?;
                let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                    .map_err(|e| io::Error::other(format!("CreateToolhelp32Snapshot: {e}")))?;
                let mut entry = THREADENTRY32 {
                    dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                    ..Default::default()
                };
                let mut resumed = 0usize;
                let mut more = Thread32First(snap, &mut entry).is_ok();
                while more {
                    if entry.th32OwnerProcessID == pid
                        && let Ok(thread) = OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
                    {
                        if ResumeThread(thread) != u32::MAX {
                            resumed += 1;
                        }
                        let _ = CloseHandle(thread);
                    }
                    more = Thread32Next(snap, &mut entry).is_ok();
                }
                let _ = CloseHandle(snap);
                if resumed == 0 {
                    return Err(io::Error::other("could not resume npm's main thread"));
                }
            }
            Ok(())
        }

        pub(super) fn terminate(&self) {
            use windows::Win32::System::JobObjects::TerminateJobObject;
            // SAFETY: valid job handle.
            let _ = unsafe { TerminateJobObject(self.0, 1) };
        }

        fn active_processes(&self) -> io::Result<u32> {
            use windows::Win32::System::JobObjects::{
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation, QueryInformationJobObject,
            };
            let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            // SAFETY: `info` is a correctly sized out-buffer for this information class.
            unsafe {
                QueryInformationJobObject(
                    Some(self.0),
                    JobObjectBasicAccountingInformation,
                    (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    None,
                )
            }
            .map_err(|e| io::Error::other(format!("QueryInformationJobObject: {e}")))?;
            Ok(info.ActiveProcesses)
        }

        /// Terminate every process in the job and wait until none is left (termination is asynchronous), bounded.
        pub(super) async fn terminate_and_wait(&self, bound: std::time::Duration) -> io::Result<()> {
            use windows::Win32::System::JobObjects::TerminateJobObject;
            // SAFETY: valid job handle.
            unsafe { TerminateJobObject(self.0, 1) }.map_err(|e| io::Error::other(format!("TerminateJobObject: {e}")))?;
            let deadline = std::time::Instant::now() + bound;
            loop {
                let left = self.active_processes()?;
                if left == 0 {
                    return Ok(());
                }
                if std::time::Instant::now() >= deadline {
                    return Err(io::Error::other(format!("{left} npm process(es) still running after {} s", bound.as_secs())));
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // Kill-on-close: anything npm left behind ends with the handle.
            // SAFETY: closed exactly once.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

/// How this process starts npm: by bare name on Unix, resolved on Windows. An error names what was looked for.
pub(crate) fn npm_invocation() -> anyhow::Result<NpmInvocation> {
    if !cfg!(windows) {
        return Ok(NpmInvocation::bare());
    }
    let dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    let pathext = std::env::var("PATHEXT").ok();
    resolve_windows_npm(&dirs, pathext.as_deref(), |p| p.is_file()).ok_or_else(|| {
        anyhow::anyhow!(
            "npm was not found on PATH (looked for npm.exe and npm.cmd). \
             Install Node.js (which includes npm), or reinstall Fuigo with: npm i -g fuigo"
        )
    })
}

/// The launchable `PATHEXT` extensions, lowercased, in order; the default when unset or empty.
pub(crate) fn launchable_extensions(pathext: Option<&str>) -> Vec<String> {
    let raw = pathext
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(DEFAULT_PATHEXT);
    let mut out: Vec<String> = Vec::new();
    for ext in raw.split(';') {
        let ext = ext.trim().to_ascii_lowercase();
        if LAUNCHABLE.contains(&ext.as_str()) && !out.contains(&ext) {
            out.push(ext);
        }
    }
    out
}

/// Windows resolution of npm, pure: `dirs` is `PATH` already split, `is_file` answers for a path. See the module docs.
pub(crate) fn resolve_windows_npm(
    dirs: &[PathBuf],
    pathext: Option<&str>,
    is_file: impl Fn(&Path) -> bool,
) -> Option<NpmInvocation> {
    let dirs: Vec<&Path> = dirs
        .iter()
        .map(PathBuf::as_path)
        .filter(|dir| is_usable_dir(dir))
        .collect();
    let exts = launchable_extensions(pathext);
    let (dir, shim, ext) = dirs.iter().find_map(|dir| {
        exts.iter().find_map(|ext| {
            let candidate = dir.join(format!("npm{ext}"));
            is_file(&candidate).then_some((*dir, candidate, ext.as_str()))
        })
    })?;
    if ext == ".exe" || ext == ".com" {
        return Some(NpmInvocation {
            program: shim,
            prefix_args: Vec::new(),
        });
    }
    let cli = dir
        .join("node_modules")
        .join("npm")
        .join("bin")
        .join("npm-cli.js");
    if is_file(&cli) {
        let beside = dir.join("node.exe");
        let node = if is_file(&beside) {
            Some(beside)
        } else {
            dirs.iter()
                .map(|d| d.join("node.exe"))
                .find(|candidate| is_file(candidate))
        };
        if let Some(node) = node {
            return Some(NpmInvocation {
                program: node,
                prefix_args: vec![cli.into_os_string()],
            });
        }
    }
    Some(NpmInvocation {
        program: shim,
        prefix_args: Vec::new(),
    })
}

/// Only absolute directories are searched: an empty or relative `PATH` entry would resolve against the current
/// directory, which a repository controls.
fn is_usable_dir(dir: &Path) -> bool {
    !dir.as_os_str().is_empty() && (dir.is_absolute() || looks_like_windows_absolute(dir))
}

/// `C:\x` and `\\server\share` are absolute on Windows; the Linux tests use real absolute paths, so this only matters
/// on Windows, where `Path::is_absolute` already says so. Kept explicit so the rule reads the same on both.
fn looks_like_windows_absolute(dir: &Path) -> bool {
    let s = dir.to_string_lossy();
    let b = s.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || s.starts_with(r"\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"").unwrap();
    }

    fn is_file(p: &Path) -> bool {
        p.is_file()
    }

    /// Node's Windows installer layout: npm.cmd, node.exe and the bundled npm-cli.js in one directory.
    #[test]
    fn p145_node_installer_layout_runs_node_with_npm_cli_js_and_no_shell() {
        let tmp = tempfile::tempdir().unwrap();
        let nodejs = tmp.path().join("nodejs");
        touch(&nodejs.join("npm.cmd"));
        touch(&nodejs.join("npm"));
        touch(&nodejs.join("npm.ps1"));
        touch(&nodejs.join("node.exe"));
        let cli = nodejs.join("node_modules/npm/bin/npm-cli.js");
        touch(&cli);

        let got = resolve_windows_npm(std::slice::from_ref(&nodejs), Some(".COM;.EXE;.BAT;.CMD;.VBS;.JS"), is_file)
            .expect("npm resolves");
        assert_eq!(got.program, nodejs.join("node.exe"));
        assert_eq!(got.prefix_args, vec![cli.into_os_string()]);
    }

    /// A global-prefix npm (`%APPDATA%\npm`) has npm.cmd and npm-cli.js but no node.exe: node comes from PATH.
    #[test]
    fn p145_prefix_shim_without_node_uses_node_from_path() {
        let tmp = tempfile::tempdir().unwrap();
        let prefix = tmp.path().join("appdata-npm");
        let nodejs = tmp.path().join("nodejs");
        touch(&prefix.join("npm.cmd"));
        let cli = prefix.join("node_modules/npm/bin/npm-cli.js");
        touch(&cli);
        touch(&nodejs.join("node.exe"));

        let got = resolve_windows_npm(&[prefix.clone(), nodejs.clone()], None, is_file).unwrap();
        assert_eq!(got.program, nodejs.join("node.exe"));
        assert_eq!(got.prefix_args, vec![cli.into_os_string()]);
    }

    /// An `npm.exe` shim earlier on PATH runs directly, before a later `npm.cmd`.
    #[test]
    fn p145_npm_exe_runs_directly_and_path_order_wins() {
        let tmp = tempfile::tempdir().unwrap();
        let (shim, nodejs) = (tmp.path().join("shim"), tmp.path().join("nodejs"));
        touch(&shim.join("npm.exe"));
        touch(&nodejs.join("npm.cmd"));
        touch(&nodejs.join("node.exe"));
        touch(&nodejs.join("node_modules/npm/bin/npm-cli.js"));

        let got = resolve_windows_npm(&[shim.clone(), nodejs.clone()], None, is_file).unwrap();
        assert_eq!(got, NpmInvocation { program: shim.join("npm.exe"), prefix_args: vec![] });
        let got = resolve_windows_npm(&[nodejs.clone(), shim], None, is_file).unwrap();
        assert_eq!(got.program, nodejs.join("node.exe"));
    }

    /// PATHEXT order decides between npm.cmd and npm.exe in one directory (cmd.exe semantics).
    #[test]
    fn p145_pathext_order_is_honoured_within_a_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        touch(&dir.join("npm.exe"));
        touch(&dir.join("npm.cmd"));
        let got = resolve_windows_npm(std::slice::from_ref(&dir), Some(".CMD;.EXE"), is_file).unwrap();
        assert_eq!(got.program, dir.join("npm.cmd"), "no npm-cli.js beside it: the shim itself");
        let got = resolve_windows_npm(std::slice::from_ref(&dir), Some(".EXE;.CMD"), is_file).unwrap();
        assert_eq!(got.program, dir.join("npm.exe"));
    }

    /// A batch shim with no npm-cli.js beside it (or no node.exe anywhere) is run by its absolute path.
    #[test]
    fn p145_unknown_batch_shim_runs_by_absolute_path() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("scoop-shims");
        touch(&dir.join("npm.bat"));
        let got = resolve_windows_npm(std::slice::from_ref(&dir), None, is_file).unwrap();
        assert_eq!(got, NpmInvocation { program: dir.join("npm.bat"), prefix_args: vec![] });

        let lone = tmp.path().join("lone");
        touch(&lone.join("npm.cmd"));
        touch(&lone.join("node_modules/npm/bin/npm-cli.js"));
        let got = resolve_windows_npm(std::slice::from_ref(&lone), None, is_file).unwrap();
        assert_eq!(got.program, lone.join("npm.cmd"), "npm-cli.js but no node.exe: fall back to the shim");
    }

    /// Relative and empty PATH entries are never searched (they resolve against the current directory), and a
    /// non-launchable extension such as .ps1 is never chosen.
    #[test]
    fn p145_relative_entries_and_unlaunchable_extensions_are_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let rel = PathBuf::from("node_modules/.bin");
        let dir = tmp.path().join("only-ps1");
        touch(&dir.join("npm.ps1"));
        let saw_relative = std::cell::Cell::new(false);
        let got = resolve_windows_npm(&[PathBuf::new(), rel, dir], Some(".PS1;.CMD"), |p| {
            if !p.is_absolute() {
                saw_relative.set(true);
            }
            p.is_file()
        });
        assert_eq!(got, None);
        assert!(!saw_relative.get(), "a relative PATH entry was probed");
    }

    #[test]
    fn p145_launchable_extensions_parse() {
        assert_eq!(launchable_extensions(None), vec![".com", ".exe", ".bat", ".cmd"]);
        assert_eq!(launchable_extensions(Some("  ")), vec![".com", ".exe", ".bat", ".cmd"]);
        assert_eq!(launchable_extensions(Some(".CMD; .js ;.EXE;.cmd")), vec![".cmd", ".exe"]);
    }

    #[test]
    fn p145_windows_absolute_shapes() {
        assert!(looks_like_windows_absolute(Path::new(r"C:\Program Files\nodejs")));
        assert!(looks_like_windows_absolute(Path::new(r"\\server\share\bin")));
        assert!(!looks_like_windows_absolute(Path::new(r"bin\npm")));
        assert!(!looks_like_windows_absolute(Path::new(r"C:relative")));
    }

    /// Off Windows the updater keeps spawning `npm` by bare name, so the PATH-based fakes in tests/ keep working.
    #[cfg(not(windows))]
    #[test]
    fn p145_unix_keeps_bare_npm() {
        assert_eq!(npm_invocation().unwrap(), NpmInvocation::bare());
    }
}
