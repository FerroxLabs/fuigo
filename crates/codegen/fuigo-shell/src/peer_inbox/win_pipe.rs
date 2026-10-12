//! Windows named-pipe inbox and dialer (packet 10; DESIGN S3.8). Windows only; nothing calls it until packet 8e.
//!
//! NEVER RUN ON WINDOWS BY ITS BUILDER: it is only compile-checked. The decisions are in `win_policy.rs` (pure, tested
//! everywhere); this file only reads the OS facts that feed them and moves bytes through 8c's `serve_one`/`exchange`.
//!
//! Server: every instance is made by [`create_instance`] (`CreateNamedPipeW` directly, so the handle carries
//! the default `READ_CONTROL` of a duplex handle; owner-only descriptor, remote clients rejected, no handle
//! inheritance, first instance claimed with `FILE_FLAG_FIRST_PIPE_INSTANCE`), read back and checked. After
//! `ConnectNamedPipe` the client's token is read on a blocking thread (impersonate, open the thread token, revert) and
//! `win_peer_verdict` runs BEFORE one byte is read. Client: the pipe is opened with `SECURITY_IDENTIFICATION`; the
//! server's token user and the pipe owner must both be ours BEFORE anything is written.
// Inert until packet 8e.
#![allow(dead_code)]

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fuigo_peer::{Hello, HostId, Op, Reply};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use windows::Win32::Foundation::{HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree};
use windows::Win32::Security::Authorization::{
    GetSecurityInfo, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, GetAce,
    GetAclInformation, GetSecurityDescriptorControl, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SECURITY_ATTRIBUTES,
    SID_AND_ATTRIBUTES,
    TOKEN_GROUPS, TOKEN_QUERY, TokenGroups, TokenImpersonationLevel,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_TYPE_PIPE, GetFileType,
    PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, GetNamedPipeClientComputerNameW, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
use windows::core::{PCWSTR, PWSTR};

use super::conn::{self, ConnError};
use super::directory::{ConnHost, PeerDirectory};
use super::win_policy::{
    AceSummary, DaclSummary, Fact, RawAce, dacl_summary_from_binary, ImpLevel, MAX_INSTANCES, OurIdentity, PipePeerFacts, Refusal, ServerFacts, ServerRefusal,
    Verdict, WinUnavailable, dacl_owner_only, evidence_open_sddl, owner_only_sddl, pipe_name, PIPE_PREFIX, sids_are_anonymous,
    sids_are_network, sids_are_system_or_service, win_peer_verdict, win_server_verdict,
};
use crate::leader::peer_auth::win as auth;
use crate::session::peer_message::peer_messaging_enabled;

/// Concurrent connections served at once (same as the unix inbox, S5.5).
pub(crate) const MAX_CONNECTIONS: usize = 32;
/// Longest a connect may take (S3.2).
pub(crate) const CONNECT_DEADLINE: Duration = Duration::from_secs(2);
const ERROR_PIPE_BUSY: i32 = 231;
const ERROR_PIPE_LOCAL: u32 = 229;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_ALREADY_EXISTS: i32 = 183;

/// What the OS says about one connected client. Filled on a blocking thread.
struct ClientPart {
    user: Fact<String>,
    system_or_service: Fact<bool>,
    anonymous: Fact<bool>,
    level: Fact<ImpLevel>,
    remote: Fact<bool>,
}

/// Reads of the OS. Every function returns plain data or a Win32 error code; none returns peer-supplied text.
pub(super) mod sys {
    use super::*;

    /// While alive, this thread acts as the connected pipe client. Dropping reverts, and a failed revert ABORTS the
    /// process (standard rule for impersonation). Thread-local: only ever created and dropped on one blocking thread,
    /// never across an `.await`.
    struct Impersonating;

    impl Impersonating {
        fn begin(pipe: HANDLE) -> Fact<Self> {
            // SAFETY: `pipe` is the live server end of a connected instance, owned by the caller for the whole call.
            unsafe { ImpersonateNamedPipeClient(pipe) }.map_err(|e| auth::code(&e))?;
            Ok(Self)
        }
    }

    impl Drop for Impersonating {
        fn drop(&mut self) {
            // SAFETY: plain call that ends impersonation on this thread.
            if unsafe { RevertToSelf() }.is_err() {
                // The thread would go back to the shared blocking pool still acting as the client, and the client
                // chose the impersonation level. There is no safe way on: end the process. Fixed text, no peer data.
                tracing::error!("peer inbox: could not end client impersonation; aborting the process");
                std::process::abort();
            }
        }
    }

    /// Open the impersonated thread token. `OpenAsSelf = TRUE`: the access check uses OUR process token, so a client
    /// that connected at identification level still gives a queryable token.
    fn thread_token() -> Fact<auth::Owned> {
        let mut token = HANDLE::default();
        // SAFETY: the pseudo handle of the current thread needs no closing; `token` is writable.
        unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) }.map_err(|e| auth::code(&e))?;
        Ok(auth::Owned(token))
    }

    /// `TOKEN_GROUPS` is `{ GroupCount: u32, Groups: [SID_AND_ATTRIBUTES; ANYSIZE_ARRAY] }`: a count, then a
    /// variable-length array that really holds `GroupCount` entries (the declared length of 1 is only a placeholder).
    /// `SID_AND_ATTRIBUTES` is `{ Sid: PSID, Attributes: u32 }`, so the array starts at an offset that depends on pointer
    /// alignment; it is taken from `offset_of!`, not assumed. The buffer from `token_info_buf` is a `Vec<u64>`, so it is
    /// 8-byte aligned, which satisfies both the `u32` count and the pointer-aligned entries.
    fn token_groups(token: HANDLE) -> Fact<Vec<String>> {
        let buf = auth::token_info_buf(token, TokenGroups)?;
        let bytes = buf.len() * 8;
        let header = std::mem::offset_of!(TOKEN_GROUPS, Groups);
        if bytes < header {
            return Err(0);
        }
        let g = buf.as_ptr().cast::<TOKEN_GROUPS>();
        // SAFETY: `GroupCount` is the `u32` at offset 0 and the buffer holds at least `header` (>= 4) bytes, checked
        // above, and is 8-byte aligned. Only those four bytes are read: no reference to a whole `TOKEN_GROUPS` is made.
        let count = unsafe { buf.as_ptr().cast::<u32>().read() } as usize;
        if count.saturating_mul(std::mem::size_of::<SID_AND_ATTRIBUTES>()) > bytes - header {
            return Err(0);
        }
        // SAFETY: `count` entries lie inside the buffer (checked above) starting at `offset_of!(Groups)`, which is
        // aligned for `SID_AND_ATTRIBUTES` within an 8-byte aligned buffer; the raw pointer keeps the whole buffer's
        // provenance (no reference to the one-element array). The entries' SID pointers point into the same buffer,
        // which outlives the `sid_to_string` calls below.
        let entries = unsafe {
            std::slice::from_raw_parts(std::ptr::addr_of!((*g).Groups).cast::<SID_AND_ATTRIBUTES>(), count)
        };
        entries.iter().map(|e| auth::sid_to_string(e.Sid)).collect()
    }

    /// Does OUR process token carry the NETWORK group (a network logon, for example an ssh session)? Then no client of our
    /// own pipe could pass the remote-client check, so the inbox is reported unavailable instead of silently useless.
    pub(in crate::peer_inbox) fn own_token_is_network() -> Fact<bool> {
        let mut token = HANDLE::default();
        // SAFETY: the pseudo handle of the current process needs no closing; `token` is writable.
        unsafe { windows::Win32::System::Threading::OpenProcessToken(windows::Win32::System::Threading::GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(|e| auth::code(&e))?;
        let token = auth::Owned(token);
        Ok(sids_are_network(&token_groups(token.0)?))
    }

    fn token_level(token: HANDLE) -> Fact<ImpLevel> {
        let buf = auth::token_info_buf(token, TokenImpersonationLevel)?;
        match buf.first().map(|v| (*v & 0xFFFF_FFFF) as u32) {
            Some(0) => Ok(ImpLevel::Anonymous),
            Some(1) => Ok(ImpLevel::Identification),
            Some(2) => Ok(ImpLevel::Impersonation),
            Some(3) => Ok(ImpLevel::Delegation),
            _ => Err(0),
        }
    }

    /// `Ok(true)` when the OS reports a client computer name, `Ok(false)` for `ERROR_PIPE_LOCAL`.
    fn client_computer_is_remote(pipe: HANDLE) -> Fact<bool> {
        let mut name = [0u16; 260];
        // SAFETY: `pipe` is a live server pipe handle; `name` is writable for `name.len()` UTF-16 units.
        let r = unsafe { GetNamedPipeClientComputerNameW(pipe, PWSTR(name.as_mut_ptr()), name.len() as u32) };
        match r.ok() {
            Ok(()) => Ok(true),
            Err(e) if auth::code(&e) == ERROR_PIPE_LOCAL => Ok(false),
            Err(e) => Err(auth::code(&e)),
        }
    }

    /// Everything about the client of a connected instance. `raw` is its handle value; the caller keeps the pipe
    /// alive until this returns.
    pub(super) fn read_client(raw: usize) -> ClientPart {
        let pipe = HANDLE(raw as *mut c_void);
        let by_name = client_computer_is_remote(pipe);
        // The guard lives only while the token is opened; the queries run on the (valid) token after reverting.
        let token = {
            let guard = Impersonating::begin(pipe);
            match guard {
                Ok(_g) => thread_token(),
                Err(c) => Err(c),
            }
        };
        let token = match token {
            Ok(t) => t,
            Err(c) => {
                return ClientPart {
                    user: Err(c),
                    system_or_service: Err(c),
                    anonymous: Err(c),
                    level: Err(c),
                    remote: by_name.and(Err(c)),
                };
            }
        };
        let user = auth::token_user_sid(token.0);
        let groups = token_groups(token.0);
        let (system_or_service, anonymous, remote) = match (&user, &groups) {
            (Ok(u), Ok(g)) => (
                Ok(sids_are_system_or_service(u, g)),
                Ok(sids_are_anonymous(u, g)),
                by_name.map(|r| r || sids_are_network(g)),
            ),
            (Err(c), _) | (_, Err(c)) => (Err(*c), Err(*c), by_name.and(Err(*c))),
        };
        ClientPart { user, system_or_service, anonymous, level: token_level(token.0), remote }
    }

    /// Owner and DACL of a kernel object, read from the BINARY descriptor (no SDDL text, so no well-known-SID aliases):
    /// the owner and every trustee are rendered with `ConvertSidToStringSidW`, the ACE type, flags and mask are the
    /// numbers in the ACL, and "protected" is the `SE_DACL_PROTECTED` control bit. Any shape we do not understand is an error.
    pub(in super::super) fn owner_and_dacl(handle: HANDLE) -> Fact<(String, DaclSummary)> {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        // SAFETY: `handle` is a live pipe handle; `owner` and `dacl` point into `sd`, a LocalAlloc'd descriptor that is
        // freed only after the last use below.
        let status =
            unsafe { GetSecurityInfo(handle, SE_KERNEL_OBJECT, info, Some(&mut owner), None, Some(&mut dacl), None, Some(&mut sd)) };
        if status.0 != 0 {
            return Err(status.0);
        }
        let r = read_owner_dacl(sd, owner, dacl);
        // SAFETY: `sd` was allocated by GetSecurityInfo with LocalAlloc and nothing borrowed from it is used again.
        let _ = unsafe { LocalFree(Some(HLOCAL(sd.0))) };
        r
    }

    /// The part of [`owner_and_dacl`] that borrows from the descriptor. `dacl` NULL (no DACL = everyone) is an error.
    pub(in crate::peer_inbox) fn read_owner_dacl(sd: PSECURITY_DESCRIPTOR, owner: PSID, dacl: *mut ACL) -> Fact<(String, DaclSummary)> {
        if owner.0.is_null() || dacl.is_null() {
            return Err(0);
        }
        let owner_text = auth::sid_to_string(owner)?;
        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: `sd` is the live descriptor from GetSecurityInfo; both out pointers are writable locals.
        unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) }.map_err(|e| auth::code(&e))?;
        let mut size = ACL_SIZE_INFORMATION::default();
        // SAFETY: `dacl` is a valid ACL inside `sd`; `size` is a writable ACL_SIZE_INFORMATION of the stated length.
        unsafe {
            GetAclInformation(
                dacl,
                (&mut size as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        }
        .map_err(|e| auth::code(&e))?;
        if size.AceCount > 16 {
            return Err(0);
        }
        let min = (std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8) as u16;
        let mut aces = Vec::new();
        for i in 0..size.AceCount {
            let mut p: *mut c_void = std::ptr::null_mut();
            // SAFETY: `dacl` is valid and `i` is below the AceCount just read; `p` receives a pointer INTO the ACL.
            unsafe { GetAce(dacl, i, &mut p) }.map_err(|e| auth::code(&e))?;
            if p.is_null() {
                return Err(0);
            }
            // SAFETY: every ACE starts with an ACE_HEADER; `p` points at one inside the live ACL (alignment 4).
            let header = unsafe { p.cast::<ACE_HEADER>().read() };
            if header.AceSize < min {
                return Err(0);
            }
            // Only the two basic ACE kinds (ACCESS_ALLOWED_ACE_TYPE = 0, ACCESS_DENIED_ACE_TYPE = 1) have the layout
            // { Header, Mask, Sid }. Object ACEs and anything unknown are reported by type alone: no Mask and no SID is
            // read from them, and the policy refuses every type that is not a plain allow.
            if header.AceType > 1 {
                aces.push(RawAce { ace_type: header.AceType, flags: header.AceFlags, mask: 0, trustee_sid: String::new() });
                continue;
            }
            let ace = p.cast::<ACCESS_ALLOWED_ACE>();
            // SAFETY: the header says the ACE is at least `min` bytes, which covers Header, Mask and the first 8 SID bytes.
            let mask = unsafe { std::ptr::addr_of!((*ace).Mask).read() };
            // SAFETY: only the address of `SidStart` is taken (no read); it lies inside the `min` bytes checked above.
            let sid_ptr = unsafe { std::ptr::addr_of_mut!((*ace).SidStart) }.cast::<u8>();
            // A SID is { Revision: u8, SubAuthorityCount: u8, IdentifierAuthority: [u8; 6], SubAuthority: [u32; count] }.
            // SAFETY: byte 1 of the SID is inside the first 8 SID bytes, which `min` guarantees are inside the ACE.
            let sub_count = usize::from(unsafe { sid_ptr.add(1).read() });
            let sid_len = 8 + 4 * sub_count;
            let sid_off = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            // The whole SID must lie inside this ACE before anything walks it (at most 15 sub-authorities exist).
            if sub_count > 15 || sid_off + sid_len > usize::from(header.AceSize) {
                return Err(0);
            }
            let sid = PSID(sid_ptr.cast::<c_void>());
            // A SID that does not convert makes the trustee empty, which matches nothing (fails closed).
            let trustee_sid = auth::sid_to_string(sid).unwrap_or_default();
            aces.push(RawAce { ace_type: header.AceType, flags: header.AceFlags, mask, trustee_sid });
        }
        Ok((owner_text, dacl_summary_from_binary(control & 0x1000 != 0, &aces)))
    }

    /// What the client learns about the server behind `handle` (no byte is sent).
    pub(super) fn server_facts(raw: std::os::windows::io::RawHandle) -> ServerFacts {
        // SAFETY: `raw` is a live handle owned by the caller; the call only reads its type.
        let kind = unsafe { GetFileType(HANDLE(raw)) };
        ServerFacts {
            is_pipe: Ok(kind == FILE_TYPE_PIPE),
            server_user: auth::server_pid(raw).and_then(auth::peer_token_sid),
            pipe_owner: auth::object_owner_sid(raw),
        }
    }
}

/// Owner and DACL of one instance as read back.
#[derive(Clone)]
struct Readback {
    owner: Fact<String>,
    dacl: Fact<DaclSummary>,
}

fn readback(server: &NamedPipeServer) -> Readback {
    match sys::owner_and_dacl(HANDLE(server.as_raw_handle())) {
        Ok((owner, dacl)) => Readback { owner: Ok(owner), dacl: Ok(dacl) },
        Err(c) => Readback { owner: Err(c), dacl: Err(c) },
    }
}

/// `CreateNamedPipeW` for one instance, handed to tokio. Done here and not through `ServerOptions` so the handle
/// can add `FILE_FLAG_FIRST_PIPE_INSTANCE`. `READ_CONTROL` is NOT an open-mode flag (passing it is
/// `ERROR_INVALID_PARAMETER`, verified on Windows Server 2022); a `PIPE_ACCESS_DUPLEX` server handle already carries it
/// (GENERIC_READ includes STANDARD_RIGHTS_READ), which is what `GetSecurityInfo` needs. A failed read-back refuses start.
fn create_raw(name: &str, first: bool, security: &mut auth::PipeSecurity) -> std::io::Result<NamedPipeServer> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut open = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        open |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    let attrs = security.as_raw().cast::<SECURITY_ATTRIBUTES>().cast_const();
    // SAFETY: `wide` is NUL-terminated and outlives the call; `attrs` points at a SECURITY_ATTRIBUTES (inheritance
    // off) whose descriptor lives until `security` drops, after the call.
    let h = unsafe {
        CreateNamedPipeW(PCWSTR(wide.as_ptr()), open, mode, u32::from(MAX_INSTANCES), 65536, 65536, 0, Some(attrs))
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `h` is a fresh overlapped server pipe handle that nothing else owns; tokio takes ownership and closes it
    // on drop. Needs a tokio runtime with IO enabled (all callers are async).
    // On error tokio has ALREADY taken the handle: `from_raw_handle` moves it into the mio pipe before registering it,
    // and a failed registration drops that pipe, which closes the handle. Closing it here again would be a double
    // close (and could close an unrelated handle that reused the value), so the error is returned as is.
    unsafe { NamedPipeServer::from_raw_handle(h.0) }
}

/// The ONE place a peer pipe instance is created. `first` claims the name with `FILE_FLAG_FIRST_PIPE_INSTANCE`:
/// if anything already holds the name this fails (`NameInUse`) and nothing falls back. The instance's owner and
/// DACL are read back and must be exactly ours. `widen` is the debug-only evidence switch, passed through
/// `evidence_open_sddl`, which is `None` in a release build; when it applies, the DACL fact handed on is replaced by the
/// owner-only summary so the case reaches the client-identity checks of the verdict (see `win_evidence`).
fn create_instance(name: &str, first: bool, sid: &str, widen: bool) -> Result<(NamedPipeServer, Readback), WinUnavailable> {
    let widened = evidence_open_sddl(sid, widen);
    let sddl = match &widened {
        Some(w) => w.clone(),
        None => owner_only_sddl(sid).ok_or(WinUnavailable::IdentityUnreadable)?,
    };
    let mut security = auth::PipeSecurity::from_sddl(&sddl).map_err(|_| WinUnavailable::ReadbackFailed)?;
    let server = create_raw(name, first, &mut security).map_err(|e| match e.raw_os_error() {
        Some(ERROR_ACCESS_DENIED | ERROR_ALREADY_EXISTS | ERROR_PIPE_BUSY) if first => WinUnavailable::NameInUse,
        Some(c) => WinUnavailable::CreateFailed(c as u32),
        None => WinUnavailable::CreateFailed(0),
    })?;
    let mut rb = readback(&server);
    if widened.is_some() {
        // Evidence build only: the owner must still be ours; the DACL is the one we asked for, widened on purpose.
        let ok = matches!(&rb.owner, Ok(o) if o == sid);
        rb.dacl = Ok(owner_only_summary(sid));
        return if ok { Ok((server, rb)) } else { Err(WinUnavailable::ReadbackFailed) };
    }
    let ok = matches!((&rb.owner, &rb.dacl), (Ok(o), Ok(d)) if o == sid && dacl_owner_only(d, sid));
    if ok { Ok((server, rb)) } else { Err(WinUnavailable::ReadbackFailed) }
}

/// What a correct owner-only read-back looks like (used only to stand in for the DACL fact in the evidence case).
fn owner_only_summary(sid: &str) -> DaclSummary {
    DaclSummary {
        flags: "P".to_owned(),
        aces: vec![AceSummary {
            kind: "A".to_owned(),
            flags: String::new(),
            rights: "GA".to_owned(),
            trustee: sid.to_owned(),
        }],
    }
}

/// Counters the evidence program reads. Fixed data only.
#[derive(Default)]
pub(crate) struct Stats {
    pub accepted: AtomicU64,
    pub refused: AtomicU64,
    last_refusal: Mutex<Option<Refusal>>,
}

impl Stats {
    pub(crate) fn last_refusal(&self) -> Option<Refusal> {
        *self.last_refusal.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn refuse(&self, why: Refusal) {
        self.refused.fetch_add(1, Ordering::SeqCst);
        *self.last_refusal.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(why);
    }
}

/// Start-up input; tests pass their own.
#[derive(Debug, Clone)]
pub(crate) struct StartOptions {
    /// `features.peer_messaging`.
    pub enabled: bool,
    /// Debug-only evidence switch (see `win_evidence`). Production code always passes `false`, and in a release build
    /// `evidence_open_sddl` ignores it.
    pub evidence_open_acl: bool,
}

fn mint_host_id() -> HostId {
    let n: u128 = rand::random();
    HostId::new(&format!("{n:032x}")).unwrap_or_else(|_| unreachable!("32 lower-case hex characters"))
}

/// A running Windows inbox. Same API names as the unix `PeerInbox`: `start`, `shutdown`, `host_id`, `directory`.
pub(crate) struct WinPeerInbox {
    host_id: HostId,
    directory: Arc<PeerDirectory>,
    pipe_name: String,
    stats: Arc<Stats>,
    token: CancellationToken,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    closed: AtomicBool,
}

impl WinPeerInbox {
    /// Start with the process settings. `home` is unused here (the pipe name replaces the socket path).
    pub(crate) async fn start(home: &Path) -> Result<WinPeerInbox, WinUnavailable> {
        Self::start_with(home, StartOptions { enabled: peer_messaging_enabled(), evidence_open_acl: false }).await
    }

    pub(crate) async fn start_with(_home: &Path, opts: StartOptions) -> Result<WinPeerInbox, WinUnavailable> {
        Self::start_inner(opts, mint_host_id()).await
    }

    pub(crate) async fn start_inner(opts: StartOptions, host_id: HostId) -> Result<WinPeerInbox, WinUnavailable> {
        // Before ANY OS call.
        if !opts.enabled {
            return Err(WinUnavailable::FeatureOff);
        }
        let sid = auth::own_sid().map_err(|_| WinUnavailable::IdentityUnreadable)?;
        let name = pipe_name(&host_id, &sid).map_err(|_| WinUnavailable::IdentityUnreadable)?;
        let first = create_instance(&name, true, &sid, opts.evidence_open_acl)?;
        // Established ONCE, here: the first instance of the name was just created by us with
        // `FILE_FLAG_FIRST_PIPE_INSTANCE` (a squatter would have made that fail).
        let listener_owns_name = true;
        let directory = PeerDirectory::new(host_id.clone());
        let stats = Arc::new(Stats::default());
        let token = CancellationToken::new();
        let task = tokio::spawn(accept_loop(
            first,
            name.clone(),
            sid,
            listener_owns_name,
            opts.evidence_open_acl,
            Hello::new(host_id.clone()),
            directory.clone(),
            stats.clone(),
            token.clone(),
        ));
        Ok(WinPeerInbox {
            host_id,
            directory,
            pipe_name: name,
            stats,
            token,
            task: Mutex::new(Some(task)),
            closed: AtomicBool::new(false),
        })
    }

    pub(crate) fn host_id(&self) -> &HostId {
        &self.host_id
    }

    pub(crate) fn directory(&self) -> &Arc<PeerDirectory> {
        &self.directory
    }

    pub(crate) fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    pub(crate) fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    /// Stop accepting; the pipe name goes away when the last instance closes. Idempotent.
    pub(crate) async fn shutdown(&self) {
        self.stop();
    }

    fn stop(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.token.cancel();
        if let Some(t) = self.task.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take() {
            t.abort();
        }
    }
}

impl Drop for WinPeerInbox {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn accept_loop(
    first: (NamedPipeServer, Readback),
    name: String,
    sid: String,
    mut listener_owns_name: bool,
    widen: bool,
    our: Hello,
    directory: Arc<PeerDirectory>,
    stats: Arc<Stats>,
    token: CancellationToken,
) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let ours = OurIdentity { user_sid: Ok(sid.clone()) };
    let mut waiting: Option<(NamedPipeServer, Readback)> = Some(first);
    loop {
        let (server, rb) = match waiting.take() {
            Some(w) => w,
            None => {
                // The listener holds NO instance now, so the name could have been taken: claim it again as the
                // first instance. If anything else holds it this fails and we retry; nothing falls back.
                listener_owns_name = false;
                match create_instance(&name, true, &sid, widen) {
                    Ok(w) => {
                        listener_owns_name = true;
                        w
                    }
                    Err(_) => {
                        tokio::select! {
                            () = token.cancelled() => return,
                            () = tokio::time::sleep(Duration::from_millis(50)) => continue,
                        }
                    }
                }
            }
        };
        let connected = tokio::select! {
            () = token.cancelled() => return,
            r = server.connect() => r,
        };
        if connected.is_err() {
            // The instance is unusable: drop it and make a new one.
            continue;
        }
        // Make the next waiting instance BEFORE serving, so the name never has zero listeners. `server` (the connected
        // instance) is still held here, so the listener holds the name and this later instance cannot be a squatter's.
        waiting = create_instance(&name, false, &sid, widen).ok();
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            // Over capacity: close at once, unread.
            drop(server);
            continue;
        };
        let (ours, our, directory, stats, token) =
            (ours.clone(), our.clone(), directory.clone(), stats.clone(), token.clone());
        // One task per connection; a panic stays inside it.
        tokio::spawn(async move {
            let _permit = permit;
            // The blocking closure OWNS `server`, so the handle cannot be closed under it (a cancelled task cannot
            // drop it early); it hands the server back with the facts.
            let Ok((server, part)) = tokio::task::spawn_blocking(move || {
                let raw = server.as_raw_handle() as usize;
                let part = sys::read_client(raw);
                (server, part)
            })
            .await
            else {
                return;
            };
            let facts = PipePeerFacts {
                client_user: part.user,
                client_system_or_service: part.system_or_service,
                client_anonymous: part.anonymous,
                client_level: part.level,
                client_remote: part.remote,
                listener_owns_name,
                pipe_owner: rb.owner,
                pipe_dacl: rb.dacl,
            };
            match win_peer_verdict(&facts, &ours) {
                Verdict::Refuse(why) => {
                    stats.refuse(why);
                    tracing::debug!(reason = ?why, "peer inbox: refused a pipe client before reading");
                }
                Verdict::Accept => {
                    stats.accepted.fetch_add(1, Ordering::SeqCst);
                    let host = ConnHost::new(directory);
                    tokio::select! {
                        () = token.cancelled() => {}
                        r = conn::serve_one(server, our, &host) => { let _ = r; }
                    }
                }
            }
        });
    }
}

pub(crate) use super::win_policy::WinDialError;

impl From<ConnError> for WinDialError {
    fn from(e: ConnError) -> Self {
        match e {
            ConnError::WriteTimeout | ConnError::ExchangeTimeout => Self::Timeout,
            ConnError::VersionMismatch => Self::VersionMismatch,
            ConnError::HostMismatch => Self::ForeignHello,
            _ => Self::Other,
        }
    }
}

async fn open_client(path: &str) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, WinDialError> {
    let deadline = tokio::time::Instant::now() + CONNECT_DEADLINE;
    loop {
        // SECURITY_IDENTIFICATION: the server may learn who we are, never act as us.
        match ClientOptions::new().security_qos_flags(SECURITY_IDENTIFICATION.0).open(path) {
            Ok(c) => return Ok(c),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(WinDialError::Timeout);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound) => return Err(WinDialError::NoServer),
            Err(_) => return Err(WinDialError::Other),
        }
    }
}

/// One operation against the host `host_id` on this machine: open the pipe named from our own SID, check the
/// server, hello, the operation, one reply.
pub(crate) async fn dial(our: &HostId, host_id: &HostId, op: Op) -> Result<Reply, WinDialError> {
    let sid = auth::own_sid().map_err(|_| WinDialError::IdentityUnreadable)?;
    let name = pipe_name(host_id, &sid).map_err(|_| WinDialError::IdentityUnreadable)?;
    dial_checked(&name, our, host_id, op).await
}

/// The dial body. `dial` reaches it only with a name built by `pipe_name`, which always starts with the pipe prefix
/// and holds no separator after it; the prefix is re-checked here, so a path that is not under `\\.\pipe\` (a file,
/// a junction, a UNC name) can never be opened by the production path. The open follows no filesystem path, so there
/// is no reparse point to follow: the namespace after `\\.\pipe\` is flat.
async fn dial_checked(path: &str, our: &HostId, host_id: &HostId, op: Op) -> Result<Reply, WinDialError> {
    if !path.starts_with(PIPE_PREFIX) {
        return Err(WinDialError::NotAPipe);
    }
    dial_open(path, our, host_id, op).await
}

/// `dial` against an explicit path (the evidence program points it at a file, a junction or a network path to prove it
/// is refused). DEBUG BUILDS ONLY: a release build has no way to dial a name that `pipe_name` did not build.
#[cfg(debug_assertions)]
pub(crate) async fn dial_at(path: &str, our: &HostId, host_id: &HostId, op: Op) -> Result<Reply, WinDialError> {
    dial_open(path, our, host_id, op).await
}

async fn dial_open(path: &str, our: &HostId, host_id: &HostId, op: Op) -> Result<Reply, WinDialError> {
    let ours = OurIdentity { user_sid: auth::own_sid() };
    let client = open_client(path).await?;
    let facts = sys::server_facts(client.as_raw_handle());
    match win_server_verdict(&facts, &ours) {
        Ok(()) => {}
        Err(ServerRefusal::NotAPipe) => return Err(WinDialError::NotAPipe),
        Err(ServerRefusal::OurIdentityUnknown) => return Err(WinDialError::IdentityUnreadable),
        Err(other) => return Err(WinDialError::WrongServer(other)),
    }
    Ok(conn::exchange(client, Hello::new(our.clone()), host_id, op).await?)
}
