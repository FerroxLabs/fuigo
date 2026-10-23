use std::path::{Path, PathBuf};

#[cfg(unix)]
fn pid_alive_from_kill(ret: i32, errno: i32) -> bool {
    ret == 0 || errno != libc::ESRCH
}

// `libc::kill(pid, 0)` is the liveness probe: signal 0 checks the process exists
// without sending anything (not swapped for `nix`, which would need a new feature).
pub(super) fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        if pid == 0 {
            return false;
        }
        // SAFETY: signal 0 sends nothing; pid is range-checked above.
        let ret = unsafe { libc::kill(pid, 0) };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        pid_alive_from_kill(ret, errno)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LiveCwdScan {
    Ok(Vec<PathBuf>),
    // Never constructed on the scanning platforms, but a distinct state from Failed.
    #[cfg_attr(any(target_os = "linux", target_os = "macos"), allow(dead_code))]
    Unsupported,
    Failed,
}

pub(crate) fn usable_cwds(scan: &LiveCwdScan, force: bool) -> Option<&[PathBuf]> {
    match scan {
        LiveCwdScan::Ok(cwds) => Some(cwds),
        LiveCwdScan::Unsupported => Some(&[]),
        LiveCwdScan::Failed => force.then_some(&[][..]),
    }
}

#[cfg(test)]
fn scan_contains_cwd(cwds: &[PathBuf], path: &Path) -> bool {
    let path_canon = dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    cwds.iter().any(|c| {
        c.as_path() == path
            || c == &path_canon
            || dunce::canonicalize(c).is_ok_and(|cc| cc == path_canon)
    })
}

/// A scan that never read this process's own working directory cannot be trusted to have read anyone else's (a
/// `/proc` that hides or refuses `cwd` links), so it fails closed. "Read" is judged inside the scan itself: comparing
/// it with `std::env::current_dir()` afterwards is a race, because another thread can chdir in between and a good
/// scan would then read as `Failed`.
fn validate_cwd_scan(cwds: Vec<PathBuf>, saw_own_cwd: bool) -> LiveCwdScan {
    if saw_own_cwd {
        LiveCwdScan::Ok(cwds)
    } else {
        LiveCwdScan::Failed
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn live_process_cwds() -> LiveCwdScan {
    scan_proc_dir(Path::new("/proc"), std::process::id())
}

#[cfg(target_os = "linux")]
fn scan_proc_dir(proc_root: &Path, own_pid: u32) -> LiveCwdScan {
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return LiveCwdScan::Failed;
    };
    let mut saw_own_cwd = false;
    let mut cwds = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if let Ok(cwd) = std::fs::read_link(entry.path().join("cwd")) {
            saw_own_cwd |= pid == own_pid;
            cwds.push(cwd);
        }
    }
    validate_cwd_scan(cwds, saw_own_cwd)
}

#[cfg(target_os = "macos")]
pub(crate) fn live_process_cwds() -> LiveCwdScan {
    macos_live_process_cwds()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn live_process_cwds() -> LiveCwdScan {
    LiveCwdScan::Unsupported
}

#[cfg(target_os = "macos")]
const VIP_PATH_LEN: usize = 1024;

#[cfg(target_os = "macos")]
fn vip_path_to_pathbuf(path: &[[libc::c_char; 32]; 32]) -> Option<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: `path` is 32*32 contiguous `c_char`s, so reading exactly
    // VIP_PATH_LEN (1024) bytes from its start stays within the array.
    let bytes = unsafe { std::slice::from_raw_parts(path.as_ptr().cast::<u8>(), VIP_PATH_LEN) };
    let nul = bytes.iter().position(|&b| b == 0)?;
    let s = &bytes[..nul];
    if s.is_empty() {
        return None;
    }
    Some(PathBuf::from(OsStr::from_bytes(s)))
}

// Hand-rolled `proc_pidinfo` FFI rather than `sysinfo`: `sysinfo` has no batched
// per-process cwd read (its per-process `cwd()` is costly) and pulling it in would
// add a mandatory dependency for this one scan.
#[cfg(target_os = "macos")]
fn macos_live_process_cwds() -> LiveCwdScan {
    let Some(pids) = macos_list_all_pids() else {
        return LiveCwdScan::Failed;
    };
    let Ok(expected) = i32::try_from(std::mem::size_of::<libc::proc_vnodepathinfo>()) else {
        return LiveCwdScan::Failed;
    };
    let own_pid = i32::try_from(std::process::id()).unwrap_or(-1);
    let mut saw_own_cwd = false;
    let mut out = Vec::with_capacity(pids.len());
    for pid in pids {
        if pid <= 0 {
            continue;
        }
        // SAFETY: proc_vnodepathinfo is a C POD struct with no niches, so an
        // all-zero bit pattern is a valid value; the kernel overwrites it below.
        let mut info = unsafe { std::mem::zeroed::<libc::proc_vnodepathinfo>() };
        // SAFETY: `info` is the size `expected` declares, and the kernel writes
        // at most `expected` bytes into it.
        let ret = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDVNODEPATHINFO,
                0,
                (&raw mut info).cast(),
                expected,
            )
        };
        if ret != expected || info.pvi_cdir.vip_vi.vi_stat.vst_dev == 0 {
            continue;
        }
        if let Some(p) = vip_path_to_pathbuf(&info.pvi_cdir.vip_path) {
            saw_own_cwd |= pid == own_pid;
            out.push(p);
        }
    }
    validate_cwd_scan(out, saw_own_cwd)
}

#[cfg(target_os = "macos")]
fn macos_list_all_pids() -> Option<Vec<i32>> {
    const PID_SIZE: usize = std::mem::size_of::<i32>();
    // SAFETY: null + size 0 is the documented size probe (returns bytes needed).
    let bytes_needed = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if bytes_needed < 1 {
        return None;
    }
    // `proc_listallpids` reports a *byte* count, not a pid count, so divide by
    // `size_of::<pid_t>()`.
    let mut capacity_pids = usize::try_from(bytes_needed).unwrap_or(0) / PID_SIZE;
    if capacity_pids < 1 {
        return None;
    }
    // A returned count that fills the whole buffer means pids were likely
    // truncated, so grow the buffer and retry.
    for _ in 0..4 {
        capacity_pids = capacity_pids
            .saturating_add(capacity_pids / 4)
            .max(capacity_pids + 32);
        let mut pids = vec![0i32; capacity_pids];
        let buf_bytes = i32::try_from(pids.len() * PID_SIZE).ok()?;
        // SAFETY: kernel writes at most `buf_bytes` into `pids`; return is byte count.
        let n_bytes = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), buf_bytes) };
        if n_bytes < 1 {
            return None;
        }
        let n_pids = usize::try_from(n_bytes).unwrap_or(0) / PID_SIZE;
        if n_pids < pids.len() {
            pids.truncate(n_pids);
            return Some(pids);
        }
        capacity_pids = n_pids;
    }
    None
}

pub(super) fn cwd_within(wt_path: &Path, live_cwds: &[PathBuf]) -> bool {
    let wt_canon = dunce::canonicalize(wt_path).unwrap_or_else(|_| wt_path.to_path_buf());
    live_cwds.iter().any(|cwd| {
        if cwd.starts_with(wt_path) || cwd.starts_with(&wt_canon) {
            return true;
        }
        match dunce::canonicalize(cwd) {
            Ok(cwd_canon) => cwd_canon.starts_with(wt_path) || cwd_canon.starts_with(&wt_canon),
            Err(_) => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn pid_alive_from_kill_decodes_errno() {
        assert!(pid_alive_from_kill(0, 0), "ret==0 ⇒ alive");
        assert!(!pid_alive_from_kill(-1, libc::ESRCH), "ESRCH ⇒ dead");
        assert!(
            pid_alive_from_kill(-1, libc::EPERM),
            "EPERM ⇒ alive (owned by another user)"
        );
        assert!(pid_alive_from_kill(-1, libc::EACCES), "EACCES ⇒ alive");
    }

    #[cfg(unix)]
    #[test]
    fn is_pid_alive_true_for_running_processes() {
        assert!(is_pid_alive(std::process::id()));
        assert!(is_pid_alive(1), "pid 1 must be detected as alive");
    }

    #[cfg(not(unix))]
    #[test]
    fn is_pid_alive_never_false_alive_on_non_unix() {
        assert!(!is_pid_alive(std::process::id()));
        assert!(!is_pid_alive(0));
        assert!(!is_pid_alive(u32::MAX));
    }

    #[cfg(unix)]
    #[test]
    fn is_pid_alive_false_for_invalid_pids() {
        assert!(!is_pid_alive(0));
        assert!(!is_pid_alive(u32::MAX));
    }

    #[cfg(unix)]
    #[test]
    fn is_pid_alive_false_for_reaped_child() {
        #[allow(clippy::disallowed_methods)]
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn `true`");
        let pid = child.id();
        child.wait().expect("wait on `true`");
        assert!(!is_pid_alive(pid));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn live_process_cwds_includes_own_cwd_after_chdir() {
        let _cwd_lock = crate::api::cwd_test_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = dunce::canonicalize(tmp.path()).unwrap();
        let _cwd = crate::api::CwdGuard(std::env::current_dir().unwrap());
        std::env::set_current_dir(&dir).expect("chdir into temp");
        let LiveCwdScan::Ok(cwds) = live_process_cwds() else {
            panic!("CWD scan must succeed on this OS after chdir");
        };
        assert!(
            scan_contains_cwd(&cwds, &dir),
            "own CWD {dir:?} must appear in live_process_cwds (got {} entries)",
            cwds.len()
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn live_process_cwds_ok_and_nonempty_on_supported_os() {
        let _cwd_lock = crate::api::cwd_test_guard();
        match live_process_cwds() {
            LiveCwdScan::Ok(cwds) => assert!(
                !cwds.is_empty(),
                "process CWD scan must observe at least one CWD on this OS"
            ),
            other => panic!("expected LiveCwdScan::Ok on supported OS, got {other:?}"),
        }
    }

    /// The scan is judged on what it read, not against `std::env::current_dir()` afterwards: another thread can
    /// chdir in between, which made a good scan `Failed` and the age pass skip every worktree
    /// (`per_kind_age_expiry_reclaims_listed_kinds_and_keeps_the_rest` saw `expired_removed` 0 instead of 1). A fake
    /// `/proc` pins this without touching the real process cwd (a test that chdir'd in a loop would itself break the
    /// tests that read `current_dir()` unlocked).
    #[cfg(target_os = "linux")]
    #[test]
    fn scan_is_judged_on_its_own_pid_entry_not_on_current_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let proc_root = tmp.path();
        for (pid, cwd) in [
            ("101", "/elsewhere/a"),
            ("202", "/elsewhere/own"),
            ("303", "/elsewhere/b"),
        ] {
            let dir = proc_root.join(pid);
            std::fs::create_dir(&dir).unwrap();
            std::os::unix::fs::symlink(cwd, dir.join("cwd")).unwrap();
        }
        std::fs::create_dir(proc_root.join("sys")).unwrap();
        // The process's real cwd is nowhere in this fake /proc, and the scan is still good.
        let LiveCwdScan::Ok(mut cwds) = scan_proc_dir(proc_root, 202) else {
            panic!("a scan that read its own pid's cwd must be usable");
        };
        cwds.sort();
        assert_eq!(
            cwds,
            [
                PathBuf::from("/elsewhere/a"),
                PathBuf::from("/elsewhere/b"),
                PathBuf::from("/elsewhere/own")
            ]
        );
        assert_eq!(
            scan_proc_dir(proc_root, 404),
            LiveCwdScan::Failed,
            "no entry for the scanner's own pid => the scan cannot be trusted"
        );
        std::fs::remove_file(proc_root.join("202").join("cwd")).unwrap();
        assert_eq!(
            scan_proc_dir(proc_root, 202),
            LiveCwdScan::Failed,
            "own pid listed but its cwd unreadable => fail closed"
        );
    }

    #[test]
    fn validate_cwd_scan_fails_closed_when_self_missing() {
        assert!(
            matches!(validate_cwd_scan(Vec::new(), false), LiveCwdScan::Failed),
            "empty scan cannot observe self CWD"
        );
        assert!(
            matches!(
                validate_cwd_scan(vec![PathBuf::from("/no/such/unrelated/cwd")], false),
                LiveCwdScan::Failed
            ),
            "other processes' paths only, own cwd never read => unusable scan"
        );
        let own = PathBuf::from("/some/own/cwd");
        match validate_cwd_scan(vec![own.clone()], true) {
            LiveCwdScan::Ok(v) => assert_eq!(v, vec![own]),
            other => panic!("a scan that read its own cwd must validate: {other:?}"),
        }
    }

    #[test]
    fn a_scan_that_cannot_say_stops_the_age_path() {
        assert_eq!(
            usable_cwds(&LiveCwdScan::Failed, false),
            None,
            "a scan that failed must block the age path"
        );
        assert_eq!(
            usable_cwds(&LiveCwdScan::Failed, true),
            Some(&[][..]),
            "force accepts a scan that failed"
        );
        let one = LiveCwdScan::Ok(vec![PathBuf::from("/")]);
        assert_eq!(usable_cwds(&one, false), Some(&[PathBuf::from("/")][..]));
        assert_eq!(
            usable_cwds(&LiveCwdScan::Unsupported, false),
            Some(&[][..]),
            "an OS with no enumerator is not an OS that failed"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn vip_path_to_pathbuf_respects_nul_bound() {
        let mut raw = [[0 as libc::c_char; 32]; 32];
        raw[0][0] = b'a' as libc::c_char;
        raw[0][1] = b'b' as libc::c_char;
        raw[0][2] = 0;
        raw[0][3] = b'x' as libc::c_char;
        let p = vip_path_to_pathbuf(&raw).expect("path");
        assert_eq!(p, PathBuf::from("ab"));
        assert!(vip_path_to_pathbuf(&[[0 as libc::c_char; 32]; 32]).is_none());
        let no_nul = [[b'z' as libc::c_char; 32]; 32];
        assert!(vip_path_to_pathbuf(&no_nul).is_none());
    }

    #[test]
    fn cwd_within_matches_nested_and_canonical_paths() {
        let tmp = tempfile::TempDir::new().unwrap();
        let wt = tmp.path().join("wt");
        std::fs::create_dir_all(wt.join("a").join("b")).unwrap();
        assert!(cwd_within(&wt, &[wt.join("a").join("b")]));
        assert!(!cwd_within(&wt, &[tmp.path().join("other")]));
        assert!(!cwd_within(&wt, &[]));
        let nested = wt.join("a").join("b");
        let nested_canon = dunce::canonicalize(&nested).unwrap();
        let wt_canon = dunce::canonicalize(&wt).unwrap();
        assert!(cwd_within(&wt_canon, &[nested]));
        assert!(cwd_within(&wt, &[nested_canon]));
    }
}
