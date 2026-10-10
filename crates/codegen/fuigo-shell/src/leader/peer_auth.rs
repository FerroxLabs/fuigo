//! Who may talk to the leader, and whose leader a client may talk to (Windows named pipe).
//!
//! The pipe a leader serves is created with a descriptor that names the current user (owner) and allows only that user and
//! SYSTEM. A client checks, right after it connects and BEFORE it sends anything, that the other end belongs to its own user.
//! The decision is a pure function over strings so it is tested everywhere with fake account ids; the Win32 calls that fill
//! it in are in [`win`]. Unix is unchanged: the unix socket has its own rules (see `transport.rs`).
#![cfg_attr(not(windows), allow(dead_code))]

/// What the user sees when a window refuses a leader it cannot confirm as the same user's: another account, or (during an
/// upgrade) an older leader started as administrator, whose connection is owned by the Administrators group.
pub(crate) const PEER_REFUSED_MESSAGE: &str = "A Fuigo background process that this window cannot confirm as yours is already running on this computer. It may belong to another user account, or be an older Fuigo that was started as administrator. Quit that Fuigo and try again.";

/// What the OS told us about the two ends of one connection. `Err(code)` is the Win32 error of the failed call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PeerFacts {
    /// The user account of this process.
    pub ours: Result<String, u32>,
    /// The user account of the process serving the pipe (its token), when it could be read.
    pub peer_token: Result<String, u32>,
    /// The owner recorded on the pipe object itself.
    pub pipe_owner: Result<String, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Accept,
    Refuse,
}

/// The one acceptance rule.
///
/// - our own account unknown: Refuse
/// - the serving process's token readable: Accept iff it is our account AND the pipe owner is our account too (every
///   product pipe is created with owner = current user; an unreadable or different owner refuses)
/// - the token unreadable (e.g. an elevated process of the same user): Accept iff the pipe owner is our account
/// - everything else: Refuse
pub(crate) fn decide(facts: &PeerFacts) -> Verdict {
    let Ok(ours) = &facts.ours else {
        return Verdict::Refuse;
    };
    match &facts.peer_token {
        Ok(peer) => {
            if peer == ours && matches!(&facts.pipe_owner, Ok(owner) if owner == ours) {
                Verdict::Accept
            } else {
                Verdict::Refuse
            }
        }
        Err(_) => match &facts.pipe_owner {
            Ok(owner) if owner == ours => Verdict::Accept,
            _ => Verdict::Refuse,
        },
    }
}

/// A client stream without an OS handle cannot be checked: fail closed.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn missing_handle_result() -> Result<(), super::client::ClientError> {
    Err(super::client::ClientError::PeerRefused)
}

/// Check the connected stream before anything is written to it. Unix: always `Ok` (unchanged behaviour).
pub(super) fn verify_connected(stream: &super::transport::LeaderStream) -> Result<(), super::client::ClientError> {
    #[cfg(windows)]
    {
        let Some(handle) = stream.client_raw_handle() else {
            return missing_handle_result();
        };
        let facts = win::gather_facts(handle);
        verdict_to_result(&facts)
    }
    #[cfg(not(windows))]
    {
        let _ = stream;
        Ok(())
    }
}

/// Apply [`decide`] and log (error codes only, never an account id) when refusing.
pub(super) fn verdict_to_result(facts: &PeerFacts) -> Result<(), super::client::ClientError> {
    match decide(facts) {
        Verdict::Accept => Ok(()),
        Verdict::Refuse => {
            tracing::debug!(
                our_account_error = ?facts.ours.as_ref().err(),
                peer_token_error = ?facts.peer_token.as_ref().err(),
                pipe_owner_error = ?facts.pipe_owner.as_ref().err(),
                "Refusing the leader: its account is not ours or could not be established"
            );
            Err(super::client::ClientError::PeerRefused)
        }
    }
}

#[cfg(windows)]
pub(crate) mod win {
    use super::PeerFacts;
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::RawHandle;
    use windows::Win32::Foundation::{CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
        SDDL_REVISION_1, SE_KERNEL_OBJECT,
    };
    use windows::Win32::Security::{
        GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    };
    use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::core::{PCWSTR, PWSTR};

    fn code(e: &windows::core::Error) -> u32 {
        (e.code().0 as u32) & 0xFFFF
    }

    struct Owned(HANDLE);
    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: the handle was opened by this module and is closed once.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    /// `S-1-...` text of a SID.
    fn sid_to_string(sid: PSID) -> Result<String, u32> {
        let mut text = PWSTR::null();
        // SAFETY: `sid` points at a valid SID owned by the caller; `text` receives a LocalAlloc'd string.
        unsafe { ConvertSidToStringSidW(sid, &mut text) }.map_err(|e| code(&e))?;
        // SAFETY: on success `text` is a NUL-terminated wide string.
        let s = unsafe { text.to_string() }.map_err(|_| 0u32);
        // SAFETY: the string was allocated by the call above with LocalAlloc.
        let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
        s
    }

    /// The token user SID text of the process behind `process` (needs `PROCESS_QUERY_LIMITED_INFORMATION`).
    fn process_token_user_sid(process: HANDLE) -> Result<String, u32> {
        let mut token = HANDLE::default();
        // SAFETY: `process` is a live process handle; `token` is writable.
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.map_err(|e| code(&e))?;
        let token = Owned(token);
        let mut needed = 0u32;
        // SAFETY: size probe; the expected failure is "insufficient buffer" and sets `needed`.
        let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut needed) };
        if needed == 0 {
            return Err(0);
        }
        // u64 elements: the buffer is at least 8-byte aligned for TOKEN_USER.
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        // SAFETY: `buf` holds at least `needed` bytes.
        unsafe {
            GetTokenInformation(token.0, TokenUser, Some(buf.as_mut_ptr().cast()), needed, &mut needed)
        }
        .map_err(|e| code(&e))?;
        // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points into the same buffer.
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        sid_to_string(sid)
    }

    /// The user account of this process.
    pub(crate) fn own_sid() -> Result<String, u32> {
        // SAFETY: the pseudo handle of the current process needs no closing.
        process_token_user_sid(unsafe { GetCurrentProcess() })
    }

    /// The user account of process `pid`, from its token. Opening uses the least access (`PROCESS_QUERY_LIMITED_INFORMATION`).
    fn peer_token_sid(pid: u32) -> Result<String, u32> {
        // SAFETY: plain Win32 call; the handle is owned by `Owned`.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.map_err(|e| code(&e))?;
        let process = Owned(process);
        process_token_user_sid(process.0)
    }

    /// The owner SID text recorded on a kernel object (the connected pipe).
    pub(crate) fn object_owner_sid(handle: RawHandle) -> Result<String, u32> {
        let mut owner = PSID::default();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `handle` is a live pipe handle; the owner SID points into `sd`, which is freed after the copy.
        let status = unsafe {
            GetSecurityInfo(HANDLE(handle), SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, Some(&mut owner), None, None, None, Some(&mut sd))
        };
        if status.0 != 0 {
            return Err(status.0);
        }
        let text = sid_to_string(owner);
        // SAFETY: `sd` was allocated by GetSecurityInfo with LocalAlloc.
        let _ = unsafe { LocalFree(Some(HLOCAL(sd.0))) };
        text
    }

    /// The OS pid of the process serving the pipe a client handle is connected to.
    pub(crate) fn server_pid(handle: RawHandle) -> Result<u32, u32> {
        let mut pid = 0u32;
        // SAFETY: `handle` is a live pipe handle; `pid` is writable.
        unsafe { GetNamedPipeServerProcessId(HANDLE(handle), &mut pid) }.map_err(|e| code(&e))?;
        if pid == 0 { Err(0) } else { Ok(pid) }
    }

    /// A private duplicate of the client's pipe handle, kept so the serving pid can be asked again later (immediately
    /// before a process is opened to be terminated) from the same connection.
    pub(crate) struct DupHandle(HANDLE);
    // SAFETY: a kernel handle is valid from any thread.
    unsafe impl Send for DupHandle {}
    unsafe impl Sync for DupHandle {}
    impl DupHandle {
        pub(crate) fn of(raw: RawHandle) -> Option<Self> {
            let mut out = HANDLE::default();
            // SAFETY: `raw` is a live handle of this process; the duplicate is owned and closed in `Drop`.
            unsafe {
                let me = GetCurrentProcess();
                DuplicateHandle(me, HANDLE(raw), me, &mut out, 0, false, DUPLICATE_SAME_ACCESS)
            }
            .ok()?;
            Some(Self(out))
        }
        /// The pid serving the pipe NOW (`None` if the OS call fails).
        pub(crate) fn server_pid_now(&self) -> Option<u32> {
            server_pid(self.0.0).ok()
        }
    }
    impl Drop for DupHandle {
        fn drop(&mut self) {
            // SAFETY: owned duplicate, closed once.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    /// Ask the OS about both ends of the connection behind `handle`. No bytes are sent.
    pub(crate) fn gather_facts(handle: RawHandle) -> PeerFacts {
        let ours = own_sid();
        let peer_token = server_pid(handle).and_then(peer_token_sid);
        let pipe_owner = object_owner_sid(handle);
        PeerFacts { ours, peer_token, pipe_owner }
    }

    /// A security descriptor for the leader pipe: owner = this user, protected DACL with full access for this user and SYSTEM only.
    pub(crate) struct PipeSecurity {
        sd: PSECURITY_DESCRIPTOR,
        attrs: SECURITY_ATTRIBUTES,
    }

    impl PipeSecurity {
        pub(crate) fn for_current_user() -> io::Result<Self> {
            let me = own_sid().map_err(|c| io::Error::other(format!("cannot read the current user account (Win32 error {c})")))?;
            Self::from_sddl(&format!("O:{me}D:P(A;;GA;;;SY)(A;;GA;;;{me})"))
        }

        fn from_sddl(sddl: &str) -> io::Result<Self> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut sd = PSECURITY_DESCRIPTOR::default();
            // SAFETY: `wide` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor freed in `Drop`.
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(wide.as_ptr()), SDDL_REVISION_1, &mut sd, None)
            }
            .map_err(|e| io::Error::other(format!("cannot build the pipe security descriptor (Win32 error {})", code(&e))))?;
            let attrs = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            };
            Ok(Self { sd, attrs })
        }

        fn as_raw(&mut self) -> *mut c_void {
            (&mut self.attrs as *mut SECURITY_ATTRIBUTES).cast()
        }
    }

    impl Drop for PipeSecurity {
        fn drop(&mut self) {
            // SAFETY: `sd` was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW with LocalAlloc.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.sd.0))) };
        }
    }

    /// The ONE place a leader pipe instance is created: every instance (first and later) gets the same restricted descriptor.
    /// Fails (instead of falling back to the default descriptor) when the descriptor cannot be built.
    pub(crate) fn create_secure_server(
        name: &std::ffi::OsStr,
        first: bool,
    ) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        let mut security = PipeSecurity::for_current_user()?;
        let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
        if first {
            options.first_pipe_instance(true);
        }
        // SAFETY: `as_raw` points at a SECURITY_ATTRIBUTES whose descriptor lives until `security` drops, after the call.
        unsafe { options.create_with_security_attributes_raw(name, security.as_raw()) }
    }
}

#[cfg(test)]
mod decision_tests {
    use super::*;

    const ME: &str = "S-1-5-21-111-222-333-1001";
    const OTHER: &str = "S-1-5-21-1-2-3-1001";
    const SYSTEM: &str = "S-1-5-18";

    fn facts(ours: Result<&str, u32>, token: Result<&str, u32>, owner: Result<&str, u32>) -> PeerFacts {
        let s = |r: Result<&str, u32>| r.map(String::from);
        PeerFacts { ours: s(ours), peer_token: s(token), pipe_owner: s(owner) }
    }

    #[test]
    fn token_equal_but_pipe_owner_different_or_unreadable_is_refused() {
        assert_eq!(decide(&facts(Ok(ME), Ok(ME), Ok(OTHER))), Verdict::Refuse);
        assert_eq!(decide(&facts(Ok(ME), Ok(ME), Ok(SYSTEM))), Verdict::Refuse);
        assert_eq!(decide(&facts(Ok(ME), Ok(ME), Err(5))), Verdict::Refuse);
    }

    #[test]
    fn a_missing_client_handle_is_refused() {
        assert!(matches!(missing_handle_result(), Err(crate::leader::client::ClientError::PeerRefused)));
    }

    #[test]
    fn same_user_is_accepted() {
        assert_eq!(decide(&facts(Ok(ME), Ok(ME), Ok(ME))), Verdict::Accept);
    }

    #[test]
    fn another_account_is_refused() {
        assert_eq!(decide(&facts(Ok(ME), Ok(OTHER), Ok(OTHER))), Verdict::Refuse);
        assert_eq!(decide(&facts(Ok(ME), Ok(SYSTEM), Ok(SYSTEM))), Verdict::Refuse);
    }

    #[test]
    fn a_readable_token_of_another_account_is_not_rescued_by_the_pipe_owner() {
        assert_eq!(decide(&facts(Ok(ME), Ok(OTHER), Ok(ME))), Verdict::Refuse);
    }

    #[test]
    fn an_unreadable_token_falls_back_to_the_pipe_owner() {
        assert_eq!(decide(&facts(Ok(ME), Err(5), Ok(ME))), Verdict::Accept, "elevated same-user leader");
        assert_eq!(decide(&facts(Ok(ME), Err(5), Ok(OTHER))), Verdict::Refuse);
        assert_eq!(decide(&facts(Ok(ME), Err(5), Ok(SYSTEM))), Verdict::Refuse);
    }

    #[test]
    fn unreadable_everything_is_refused() {
        assert_eq!(decide(&facts(Ok(ME), Err(5), Err(5))), Verdict::Refuse);
        assert_eq!(decide(&facts(Err(5), Err(5), Err(5))), Verdict::Refuse);
    }

    #[test]
    fn our_own_account_unknown_is_refused_even_if_the_peer_looks_equal() {
        assert_eq!(decide(&facts(Err(5), Ok(ME), Ok(ME))), Verdict::Refuse);
    }

    #[test]
    fn the_refusal_text_is_plain_and_has_no_technical_detail() {
        let lower = PEER_REFUSED_MESSAGE.to_lowercase();
        assert!(PEER_REFUSED_MESSAGE.contains("another user account") && PEER_REFUSED_MESSAGE.contains("started as administrator"));
        assert!(!lower.contains("pipe") && !lower.contains("sid") && !lower.contains("token"));
    }
}
