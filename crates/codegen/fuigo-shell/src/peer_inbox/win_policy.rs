//! Windows peer inbox: the pure decisions (packet 10; DESIGN S3.8). Compiled and tested on every OS.
//!
//! Plain data in, a verdict out. The Win32 code that fills [`PipePeerFacts`] lives in `win_pipe.rs` (Windows only);
//! nothing here touches the OS. Every fact is a `Result<_, u32>` where `Err(code)` means "the OS call failed or was
//! not possible", and every `Err` refuses (fail closed). No value in this file is built from peer-supplied bytes
//! except the SID strings the OS itself rendered; they are never put into an error or a log line.
#![cfg_attr(not(windows), allow(dead_code))]

use fuigo_peer::HostId;
use sha2::{Digest, Sha256};

/// A fact the OS reported, or the Win32 error code of the call that failed.
pub(crate) type Fact<T> = Result<T, u32>;

/// Prefix of every pipe name this module builds.
pub(crate) const PIPE_PREFIX: &str = r"\\.\pipe\fuigo-peer-";
/// Pipe instances at once: 32 served connections plus the one waiting for the next client.
pub(crate) const MAX_INSTANCES: u8 = 33;

/// Who we are (read from our own process token by the caller).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OurIdentity {
    pub user_sid: Fact<String>,
}

/// The impersonation level of the token the OS gave us for the connected client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImpLevel {
    Anonymous,
    Identification,
    Impersonation,
    Delegation,
}

/// One ACE of the DACL read back from the pipe: type, flags and trustee, as the OS rendered them in SDDL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AceSummary {
    pub kind: String,
    pub flags: String,
    /// The access mask as the OS rendered it in SDDL (`GA`, `FA`, `GRGW`, `0x...`).
    pub rights: String,
    pub trustee: String,
}

/// The DACL of the pipe instance as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DaclSummary {
    /// The DACL control flags text (`P` = protected, `AI` = auto-inherited, ...).
    pub flags: String,
    pub aces: Vec<AceSummary>,
}

/// Everything known about one connected client and the pipe it connected to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PipePeerFacts {
    /// User SID of the client token (from the impersonation token of THIS connection).
    pub client_user: Fact<String>,
    /// The client token is SYSTEM, LOCAL SERVICE, NETWORK SERVICE, a service SID or has the SERVICE group.
    pub client_system_or_service: Fact<bool>,
    /// The client token is the anonymous token.
    pub client_anonymous: Fact<bool>,
    /// Impersonation level the OS granted the server for this client.
    pub client_level: Fact<ImpLevel>,
    /// The client is remote: a network logon, or `GetNamedPipeClientComputerName` did not say "local".
    pub client_remote: Fact<bool>,
    /// A fact about the LISTENER, established at start and not per instance: the first instance of the name was
    /// created by this listener with `FILE_FLAG_FIRST_PIPE_INSTANCE`, and every later instance is created by the same
    /// listener only while it still holds at least one instance, so nobody else can have taken the name in between.
    pub listener_owns_name: bool,
    /// Owner SID of the pipe instance as read back.
    pub pipe_owner: Fact<String>,
    /// DACL of the pipe instance as read back.
    pub pipe_dacl: Fact<DaclSummary>,
}

/// Why a client was refused. Fixed variants only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    OurIdentityUnknown,
    ListenerDoesNotOwnName,
    PipeOwnerNotUs,
    PipeDaclNotOwnerOnly,
    ClientUnreadable,
    ClientRemote,
    ClientSystemOrService,
    ClientAnonymous,
    ClientLevelUnknown,
    DifferentAccount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Accept,
    Refuse(Refusal),
}

/// Text that looks like a SID: `S-1-` then digits and dashes only, 5 to 184 characters, no empty part.
pub(crate) fn is_sid_text(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("S-1-") else {
        return false;
    };
    s.len() <= 184
        && !rest.is_empty()
        && rest.split('-').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// One ACE as read from the binary ACL (`GetAce`): numeric type, flags and mask, and the trustee as a FULL SID string
/// (`ConvertSidToStringSidW`, which never renders aliases such as `LA`, `LG`, `BA`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawAce {
    pub ace_type: u8,
    pub flags: u8,
    pub mask: u32,
    pub trustee_sid: String,
}

/// Build the [`DaclSummary`] the policy judges from the binary descriptor: `protected` is the `SE_DACL_PROTECTED` control
/// bit (not SDDL text). ACCESS_ALLOWED_ACE_TYPE (0) is `A`; any other type is its hex number, which never matches.
/// Flags are empty when zero, else hex (so any inherit or audit flag fails). The mask is `0x...` lowercase hex.
pub(crate) fn dacl_summary_from_binary(protected: bool, aces: &[RawAce]) -> DaclSummary {
    DaclSummary {
        flags: if protected { "P".to_owned() } else { String::new() },
        aces: aces
            .iter()
            .map(|a| AceSummary {
                kind: if a.ace_type == 0 { "A".to_owned() } else { format!("0x{:x}", a.ace_type) },
                flags: if a.flags == 0 { String::new() } else { format!("0x{:x}", a.flags) },
                rights: format!("0x{:x}", a.mask),
                trustee: a.trustee_sid.clone(),
            })
            .collect(),
    }
}

/// The rights `start` grants: generic all (`GA`), which the object manager may map to the pipe's specific
/// all-access mask (`FA`, 0x1f01ff). The same two masks in raw form are accepted. Anything else (narrower or broader,
/// `GR`, `WD`, `0x1f01ff|WRITE_OWNER` ...) is not what we set.
pub(crate) fn rights_are_ours(rights: &str) -> bool {
    let r = rights.to_ascii_lowercase();
    matches!(r.as_str(), "ga" | "fa" | "0x10000000" | "0x1f01ff")
}

/// Exactly one ACE: a plain (not object, not inherited) allow of the rights we set, for our SID; protected DACL.
/// A NULL DACL (`NO_ACCESS_CONTROL`, which the parser refuses), an empty DACL, a deny ACE, an inherited ACE and
/// any other trustee or mask all fail.
pub(crate) fn dacl_owner_only(d: &DaclSummary, ours: &str) -> bool {
    d.flags == "P"
        && d.aces.len() == 1
        && d.aces[0].kind == "A"
        && d.aces[0].flags.is_empty()
        && rights_are_ours(&d.aces[0].rights)
        && d.aces[0].trustee == ours
}

/// The S3.8 server-side rule. Same user accepts; everything else, and everything unknown, refuses. Checks run in a
/// fixed order, so a SYSTEM client reports `ClientSystemOrService` and not `DifferentAccount`.
pub(crate) fn win_peer_verdict(facts: &PipePeerFacts, ours: &OurIdentity) -> Verdict {
    use Refusal::*;
    let Ok(me) = &ours.user_sid else { return Verdict::Refuse(OurIdentityUnknown) };
    if !is_sid_text(me) {
        return Verdict::Refuse(OurIdentityUnknown);
    }
    if !facts.listener_owns_name {
        return Verdict::Refuse(ListenerDoesNotOwnName);
    }
    if !matches!(&facts.pipe_owner, Ok(o) if o == me) {
        return Verdict::Refuse(PipeOwnerNotUs);
    }
    if !matches!(&facts.pipe_dacl, Ok(d) if dacl_owner_only(d, me)) {
        return Verdict::Refuse(PipeDaclNotOwnerOnly);
    }
    let Ok(user) = &facts.client_user else { return Verdict::Refuse(ClientUnreadable) };
    if !is_sid_text(user) {
        return Verdict::Refuse(ClientUnreadable);
    }
    match facts.client_remote {
        Ok(false) => {}
        Ok(true) => return Verdict::Refuse(ClientRemote),
        Err(_) => return Verdict::Refuse(ClientUnreadable),
    }
    match facts.client_system_or_service {
        Ok(false) => {}
        Ok(true) => return Verdict::Refuse(ClientSystemOrService),
        Err(_) => return Verdict::Refuse(ClientUnreadable),
    }
    match facts.client_anonymous {
        Ok(false) => {}
        Ok(true) => return Verdict::Refuse(ClientAnonymous),
        Err(_) => return Verdict::Refuse(ClientUnreadable),
    }
    match facts.client_level {
        Ok(ImpLevel::Anonymous) => return Verdict::Refuse(ClientAnonymous),
        Ok(_) => {}
        Err(_) => return Verdict::Refuse(ClientLevelUnknown),
    }
    if user == me { Verdict::Accept } else { Verdict::Refuse(DifferentAccount) }
}

/// What the client learns about the server it connected to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerFacts {
    /// The handle is a pipe (`GetFileType` = `FILE_TYPE_PIPE`).
    pub is_pipe: Fact<bool>,
    /// User SID of the token of the process serving the pipe.
    pub server_user: Fact<String>,
    /// Owner SID of the pipe object.
    pub pipe_owner: Fact<String>,
}

/// Why a dial failed. No variant carries text from the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WinDialError {
    IdentityUnreadable,
    /// No pipe of that name.
    NoServer,
    Timeout,
    /// The name is not a pipe (a file, a directory or a reparse point).
    NotAPipe,
    /// The server (token or pipe owner) is not our user; nothing was written to it.
    WrongServer(ServerRefusal),
    ForeignHello,
    VersionMismatch,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerRefusal {
    OurIdentityUnknown,
    NotAPipe,
    ServerUnreadable,
    OwnerUnreadable,
    ServerNotUs,
    OwnerNotUs,
}

/// The S3.8 client-side rule: the server's token AND the pipe's owner must both be our user. Unlike the leader's
/// `peer_auth::decide`, an unreadable server token is NOT rescued by a matching owner.
pub(crate) fn win_server_verdict(facts: &ServerFacts, ours: &OurIdentity) -> Result<(), ServerRefusal> {
    use ServerRefusal::*;
    let Ok(me) = &ours.user_sid else { return Err(OurIdentityUnknown) };
    if !is_sid_text(me) {
        return Err(OurIdentityUnknown);
    }
    match facts.is_pipe {
        Ok(true) => {}
        _ => return Err(NotAPipe),
    }
    let Ok(server) = &facts.server_user else { return Err(ServerUnreadable) };
    let Ok(owner) = &facts.pipe_owner else { return Err(OwnerUnreadable) };
    if server != me {
        return Err(ServerNotUs);
    }
    if owner != me {
        return Err(OwnerNotUs);
    }
    Ok(())
}

/// Token classification from SID text (pure; the Win32 code only lists the SIDs).
pub(crate) fn sids_are_system_or_service(user: &str, groups: &[String]) -> bool {
    matches!(user, "S-1-5-18" | "S-1-5-19" | "S-1-5-20")
        || user.starts_with("S-1-5-80-")
        || groups.iter().any(|g| g == "S-1-5-6" || g == "S-1-5-18" || g.starts_with("S-1-5-80-"))
}

pub(crate) fn sids_are_anonymous(user: &str, groups: &[String]) -> bool {
    user == "S-1-5-7" || groups.iter().any(|g| g == "S-1-5-7")
}

/// A network-logon token carries the NETWORK group (S-1-5-2).
pub(crate) fn sids_are_network(groups: &[String]) -> bool {
    groups.iter().any(|g| g == "S-1-5-2")
}

/// Why a pipe name could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameError {
    BadSid,
}

/// `\\.\pipe\fuigo-peer-<32 hex of SHA-256(SID)>-<host-id>`. The only way a peer pipe name is built.
pub(crate) fn pipe_name(host: &HostId, user_sid: &str) -> Result<String, NameError> {
    if !is_sid_text(user_sid) {
        return Err(NameError::BadSid);
    }
    let digest = Sha256::digest(user_sid.as_bytes());
    let mut hash = String::with_capacity(32);
    for b in &digest[..16] {
        hash.push_str(&format!("{b:02x}"));
    }
    Ok(format!("{PIPE_PREFIX}{hash}-{}", host.as_str()))
}

/// Parse the SDDL text `ConvertSecurityDescriptorToStringSecurityDescriptor` gives for OWNER|DACL:
/// `O:<sid>D:<flags>(<type>;<flags>;<rights>;<guid>;<inherit guid>;<trustee>)...`. Anything else is `Err(0)`.
pub(crate) fn parse_owner_dacl_sddl(sddl: &str) -> Fact<(String, DaclSummary)> {
    let rest = sddl.strip_prefix("O:").ok_or(0u32)?;
    let d = rest.find("D:").ok_or(0u32)?;
    let owner = &rest[..d];
    if !is_sid_text(owner) {
        return Err(0);
    }
    let dacl = &rest[d + 2..];
    let open = dacl.find('(').unwrap_or(dacl.len());
    let flags = dacl[..open].to_owned();
    if !flags.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(0);
    }
    let mut aces = Vec::new();
    let mut tail = &dacl[open..];
    while !tail.is_empty() {
        let body = tail.strip_prefix('(').ok_or(0u32)?;
        let close = body.find(')').ok_or(0u32)?;
        let parts: Vec<&str> = body[..close].split(';').collect();
        if parts.len() != 6 {
            return Err(0);
        }
        aces.push(AceSummary {
            kind: parts[0].to_owned(),
            flags: parts[1].to_owned(),
            rights: parts[2].to_owned(),
            trustee: parts[5].to_owned(),
        });
        tail = &body[close + 1..];
    }
    Ok((owner.to_owned(), DaclSummary { flags, aces }))
}

/// The SDDL the pipe is created with: owner = us, protected DACL, ONE allow ACE for us, nothing inherited, no SYSTEM.
pub(crate) fn owner_only_sddl(user_sid: &str) -> Option<String> {
    is_sid_text(user_sid).then(|| format!("O:{user_sid}D:P(A;;GA;;;{user_sid})"))
}

/// Name of the evidence-only switch. Read by `win_evidence` only, never by `win_pipe`.
pub(crate) const EVIDENCE_OPEN_ACL_VAR: &str = "FUIGO_P10_EVIDENCE_OPEN_ACL";

/// The evidence-only DACL that ALSO lets Authenticated Users and SYSTEM connect, so a foreign token reaches the
/// server's verdict function. Debug builds only: in a release build this is `None` whatever is asked.
pub(crate) fn evidence_open_sddl(user_sid: &str, requested: bool) -> Option<String> {
    (cfg!(debug_assertions) && requested && is_sid_text(user_sid))
        .then(|| format!("O:{user_sid}D:P(A;;GA;;;{user_sid})(A;;GRGW;;;AU)(A;;GRGW;;;SY)"))
}

/// Does the environment ask for the evidence DACL? `get` reads one variable. Always false in a release build.
pub(crate) fn evidence_open_acl_requested(get: impl Fn(&str) -> Option<String>) -> bool {
    cfg!(debug_assertions) && get(EVIDENCE_OPEN_ACL_VAR).as_deref() == Some("1")
}

/// Why the Windows inbox is not running. Fixed variants; [`WinUnavailable::reason_text`] is the only text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WinUnavailable {
    /// `features.peer_messaging` is off.
    FeatureOff,
    /// Built for a platform without named pipes.
    NotWindows,
    /// Our own account could not be read.
    IdentityUnreadable,
    /// This process runs in a network (remote) logon session: no client of its own pipe passes the remote check.
    NetworkLogon,
    /// The pipe name already exists (a pre-created pipe), or it could not be claimed as the first instance.
    NameInUse,
    /// Another pipe-creation failure, with its Win32 code.
    CreateFailed(u32),
    /// The instance's owner or DACL could not be read back, or is not what we asked for.
    ReadbackFailed,
}

impl WinUnavailable {
    pub(crate) fn reason_text(&self) -> &'static str {
        match self {
            Self::FeatureOff => "peer messaging is unavailable: the feature is off",
            Self::NotWindows => "peer messaging is unavailable: unsupported platform",
            Self::IdentityUnreadable => "peer messaging is unavailable: this user account could not be read",
            Self::NetworkLogon => "peer messaging is unavailable in a remote (network) logon session",
            Self::NameInUse => "peer messaging is unavailable: the inbox pipe name is already in use",
            Self::CreateFailed(_) => "peer messaging is unavailable: the inbox pipe could not be created",
            Self::ReadbackFailed => "peer messaging is unavailable: the inbox pipe failed its safety checks",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "S-1-5-21-111-222-333-1001";
    const OTHER: &str = "S-1-5-21-111-222-333-1002";
    const SYSTEM: &str = "S-1-5-18";

    fn us() -> OurIdentity {
        OurIdentity { user_sid: Ok(ME.into()) }
    }

    fn ace(kind: &str, flags: &str, rights: &str, who: &str) -> AceSummary {
        AceSummary { kind: kind.into(), flags: flags.into(), rights: rights.into(), trustee: who.into() }
    }

    fn good_dacl() -> DaclSummary {
        DaclSummary { flags: "P".into(), aces: vec![ace("A", "", "GA", ME)] }
    }

    fn good() -> PipePeerFacts {
        PipePeerFacts {
            client_user: Ok(ME.into()),
            client_system_or_service: Ok(false),
            client_anonymous: Ok(false),
            client_level: Ok(ImpLevel::Identification),
            client_remote: Ok(false),
            listener_owns_name: true,
            pipe_owner: Ok(ME.into()),
            pipe_dacl: Ok(good_dacl()),
        }
    }

    fn refused(f: &PipePeerFacts, why: Refusal) {
        assert_eq!(win_peer_verdict(f, &us()), Verdict::Refuse(why));
    }

    #[test]
    fn same_user_accepts() {
        assert_eq!(win_peer_verdict(&good(), &us()), Verdict::Accept);
        for l in [ImpLevel::Identification, ImpLevel::Impersonation, ImpLevel::Delegation] {
            let mut f = good();
            f.client_level = Ok(l);
            assert_eq!(win_peer_verdict(&f, &us()), Verdict::Accept);
        }
    }

    #[test]
    fn a_different_account_refuses() {
        let mut f = good();
        f.client_user = Ok(OTHER.into());
        refused(&f, Refusal::DifferentAccount);
    }

    #[test]
    fn system_refuses_by_user_and_by_flag() {
        let mut f = good();
        f.client_user = Ok(SYSTEM.into());
        f.client_system_or_service = Ok(true);
        refused(&f, Refusal::ClientSystemOrService);
        // The same user's token carrying the SERVICE group.
        let mut g = good();
        g.client_system_or_service = Ok(true);
        refused(&g, Refusal::ClientSystemOrService);
        // The user is SYSTEM but the flag was (wrongly) false: still a different account.
        let mut h = good();
        h.client_user = Ok(SYSTEM.into());
        refused(&h, Refusal::DifferentAccount);
    }

    #[test]
    fn anonymous_refuses() {
        let mut f = good();
        f.client_anonymous = Ok(true);
        refused(&f, Refusal::ClientAnonymous);
        let mut g = good();
        g.client_level = Ok(ImpLevel::Anonymous);
        refused(&g, Refusal::ClientAnonymous);
    }

    #[test]
    fn remote_refuses() {
        let mut f = good();
        f.client_remote = Ok(true);
        refused(&f, Refusal::ClientRemote);
    }

    #[test]
    fn every_unreadable_fact_refuses() {
        let mut f = good();
        f.client_user = Err(5);
        refused(&f, Refusal::ClientUnreadable);
        let mut f = good();
        f.client_system_or_service = Err(5);
        refused(&f, Refusal::ClientUnreadable);
        let mut f = good();
        f.client_anonymous = Err(5);
        refused(&f, Refusal::ClientUnreadable);
        let mut f = good();
        f.client_remote = Err(5);
        refused(&f, Refusal::ClientUnreadable);
        let mut f = good();
        f.client_level = Err(5);
        refused(&f, Refusal::ClientLevelUnknown);
        let mut f = good();
        f.pipe_owner = Err(5);
        refused(&f, Refusal::PipeOwnerNotUs);
        let mut f = good();
        f.pipe_dacl = Err(5);
        refused(&f, Refusal::PipeDaclNotOwnerOnly);
        let o = OurIdentity { user_sid: Err(5) };
        assert_eq!(win_peer_verdict(&good(), &o), Verdict::Refuse(Refusal::OurIdentityUnknown));
    }

    #[test]
    fn a_garbage_sid_is_unreadable() {
        let mut f = good();
        f.client_user = Ok("not a sid".into());
        refused(&f, Refusal::ClientUnreadable);
        let o = OurIdentity { user_sid: Ok("x".into()) };
        assert_eq!(win_peer_verdict(&good(), &o), Verdict::Refuse(Refusal::OurIdentityUnknown));
    }

    #[test]
    fn a_listener_that_does_not_own_the_name_refuses() {
        let mut f = good();
        f.listener_owns_name = false;
        refused(&f, Refusal::ListenerDoesNotOwnName);
    }

    #[test]
    fn a_pipe_owned_by_someone_else_refuses() {
        for owner in [OTHER, SYSTEM, "S-1-5-32-544"] {
            let mut f = good();
            f.pipe_owner = Ok(owner.into());
            refused(&f, Refusal::PipeOwnerNotUs);
        }
    }

    #[test]
    fn a_dacl_that_grants_anyone_else_refuses() {
        let a = |k: &str, f: &str, r: &str, w: &str| ace(k, f, r, w);
        let cases = [
            // empty DACL
            DaclSummary { flags: "P".into(), aces: vec![] },
            // not protected / auto-inherited
            DaclSummary { flags: String::new(), aces: good_dacl().aces },
            DaclSummary { flags: "PAI".into(), aces: good_dacl().aces },
            DaclSummary { flags: "AI".into(), aces: good_dacl().aces },
            // extra or other trustees
            DaclSummary { flags: "P".into(), aces: vec![a("A", "", "GA", ME), a("A", "", "GA", SYSTEM)] },
            DaclSummary { flags: "P".into(), aces: vec![a("A", "", "GA", ME), a("A", "", "GA", "WD")] },
            DaclSummary { flags: "P".into(), aces: vec![a("A", "", "GA", SYSTEM)] },
            DaclSummary { flags: "P".into(), aces: vec![a("A", "", "GA", "WD")] },
            // inherited / inheriting ACEs
            DaclSummary { flags: "P".into(), aces: vec![a("A", "OICI", "GA", ME)] },
            DaclSummary { flags: "P".into(), aces: vec![a("A", "ID", "GA", ME)] },
            // deny and object ACEs
            DaclSummary { flags: "P".into(), aces: vec![a("D", "", "GA", ME)] },
            DaclSummary { flags: "P".into(), aces: vec![a("OA", "", "GA", ME)] },
            DaclSummary { flags: "P".into(), aces: vec![a("D", "", "GA", ME), a("A", "", "GA", ME)] },
            // wrong access mask for our own SID: broader or different than what start set
            DaclSummary { flags: "P".into(), aces: vec![a("A", "", "GRGW", ME)] },
            DaclSummary { flags: "P".into(), aces: vec![a("A", "", "GR", ME)] },
            DaclSummary { flags: "P".into(), aces: vec![a("A", "", "FAWO", ME)] },
            DaclSummary { flags: "P".into(), aces: vec![a("A", "", "0x1f01ff0", ME)] },
            DaclSummary { flags: "P".into(), aces: vec![a("A", "", "", ME)] },
        ];
        for d in cases {
            assert!(!dacl_owner_only(&d, ME), "{d:?}");
            let mut f = good();
            f.pipe_dacl = Ok(d);
            refused(&f, Refusal::PipeDaclNotOwnerOnly);
        }
    }

    #[test]
    fn the_masks_start_sets_pass() {
        for r in ["GA", "FA", "0x10000000", "0x1F01FF", "0x1f01ff"] {
            let d = DaclSummary { flags: "P".into(), aces: vec![ace("A", "", r, ME)] };
            assert!(dacl_owner_only(&d, ME), "{r}");
        }
    }

    #[test]
    fn a_null_dacl_does_not_parse() {
        // SDDL renders a NULL DACL as `D:NO_ACCESS_CONTROL`: not a protected owner-only list, and it does not parse.
        assert!(parse_owner_dacl_sddl("O:S-1-5-21-1-2-3-1001D:NO_ACCESS_CONTROL").is_err());
        // A deny ACE and an inherited ACE parse and then fail the check.
        let (_, d) = parse_owner_dacl_sddl("O:S-1-5-21-1-2-3-1001D:P(D;;GA;;;S-1-5-21-1-2-3-1001)").unwrap();
        assert!(!dacl_owner_only(&d, "S-1-5-21-1-2-3-1001"));
        let (_, d) = parse_owner_dacl_sddl("O:S-1-5-21-1-2-3-1001D:(A;ID;FA;;;S-1-5-21-1-2-3-1001)").unwrap();
        assert!(!dacl_owner_only(&d, "S-1-5-21-1-2-3-1001"));
    }

    #[test]
    fn evidence_switch_is_debug_only_and_production_never_widens() {
        let on = |_: &str| Some("1".to_owned());
        let off = |_: &str| None;
        let other = |_: &str| Some("yes".to_owned());
        assert_eq!(evidence_open_acl_requested(on), cfg!(debug_assertions));
        assert!(!evidence_open_acl_requested(off));
        assert!(!evidence_open_acl_requested(other));
        // Not requested: never widened. The production SDDL is the owner-only one and has no other trustee.
        assert!(evidence_open_sddl(ME, false).is_none());
        let prod = owner_only_sddl(ME).unwrap();
        assert!(!prod.contains("AU") && !prod.contains("SY") && !prod.contains("WD"));
        // In a release build even a request yields nothing.
        assert_eq!(evidence_open_sddl(ME, true).is_some(), cfg!(debug_assertions));
        assert!(evidence_open_sddl("bad", true).is_none());
    }

    #[test]
    fn win_pipe_never_reads_the_evidence_switch() {
        // The production module must not mention the switch or read the environment at all.
        let src = include_str!("win_pipe.rs");
        assert!(!src.contains(EVIDENCE_OPEN_ACL_VAR));
        assert!(!src.contains("env::var"));
        assert!(!src.contains("evidence_open_acl_requested"));
    }

    #[test]
    fn server_verdict_table() {
        let sf = |p: Fact<bool>, s: Fact<&str>, o: Fact<&str>| ServerFacts {
            is_pipe: p,
            server_user: s.map(String::from),
            pipe_owner: o.map(String::from),
        };
        assert_eq!(win_server_verdict(&sf(Ok(true), Ok(ME), Ok(ME)), &us()), Ok(()));
        assert_eq!(win_server_verdict(&sf(Ok(true), Ok(OTHER), Ok(OTHER)), &us()), Err(ServerRefusal::ServerNotUs));
        assert_eq!(win_server_verdict(&sf(Ok(true), Ok(ME), Ok(OTHER)), &us()), Err(ServerRefusal::OwnerNotUs));
        assert_eq!(win_server_verdict(&sf(Ok(true), Ok(OTHER), Ok(ME)), &us()), Err(ServerRefusal::ServerNotUs));
        assert_eq!(win_server_verdict(&sf(Ok(true), Ok(SYSTEM), Ok(SYSTEM)), &us()), Err(ServerRefusal::ServerNotUs));
        // The leader's fallback (unreadable token, matching owner) is NOT used.
        assert_eq!(win_server_verdict(&sf(Ok(true), Err(5), Ok(ME)), &us()), Err(ServerRefusal::ServerUnreadable));
        assert_eq!(win_server_verdict(&sf(Ok(true), Ok(ME), Err(5)), &us()), Err(ServerRefusal::OwnerUnreadable));
        assert_eq!(win_server_verdict(&sf(Ok(false), Ok(ME), Ok(ME)), &us()), Err(ServerRefusal::NotAPipe));
        assert_eq!(win_server_verdict(&sf(Err(6), Ok(ME), Ok(ME)), &us()), Err(ServerRefusal::NotAPipe));
        let none = OurIdentity { user_sid: Err(5) };
        assert_eq!(win_server_verdict(&sf(Ok(true), Ok(ME), Ok(ME)), &none), Err(ServerRefusal::OurIdentityUnknown));
    }

    #[test]
    fn sid_classification() {
        let g = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(sids_are_system_or_service("S-1-5-18", &[]));
        assert!(sids_are_system_or_service("S-1-5-19", &[]));
        assert!(sids_are_system_or_service("S-1-5-20", &[]));
        assert!(sids_are_system_or_service("S-1-5-80-1-2-3-4-5", &[]));
        assert!(sids_are_system_or_service(ME, &g(&["S-1-1-0", "S-1-5-6"])));
        assert!(!sids_are_system_or_service(ME, &g(&["S-1-1-0", "S-1-5-32-545"])));
        assert!(sids_are_anonymous("S-1-5-7", &[]));
        assert!(!sids_are_anonymous(ME, &g(&["S-1-1-0"])));
        assert!(sids_are_network(&g(&["S-1-5-2"])));
        assert!(!sids_are_network(&g(&["S-1-5-4"])));
    }

    #[test]
    fn sid_text_check() {
        assert!(is_sid_text(ME));
        assert!(is_sid_text("S-1-5-18"));
        for bad in ["", "S-1-", "S-1--5", "S-2-5-18", "s-1-5-18", "S-1-5-18\\x", "S-1-5-1a", "S-1-5-18 ", "S-1-5-\u{660}"] {
            assert!(!is_sid_text(bad), "{bad:?}");
        }
        assert!(!is_sid_text(&format!("S-1-{}", "5-".repeat(100) + "1")));
    }

    #[test]
    fn pipe_name_has_the_prefix_and_hides_the_sid() {
        let host = HostId::new(&"ab".repeat(16)).unwrap();
        let n = pipe_name(&host, ME).unwrap();
        assert!(n.starts_with(PIPE_PREFIX));
        assert!(n.ends_with(&format!("-{}", host.as_str())));
        assert!(!n.contains(ME) && !n.contains("S-1-5"));
        assert_ne!(n, pipe_name(&host, OTHER).unwrap());
        let other_host = HostId::new(&"cd".repeat(16)).unwrap();
        assert_ne!(n, pipe_name(&other_host, ME).unwrap());
        // after the prefix: 32 hex, a dash, 32 hex; nothing else
        let tail = &n[PIPE_PREFIX.len()..];
        assert_eq!(tail.len(), 32 + 1 + 32);
        assert!(tail.bytes().all(|b| b == b'-' || b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }

    #[test]
    fn no_input_makes_a_name_outside_the_prefix() {
        let host = HostId::new(&"0f".repeat(16)).unwrap();
        for sid in ["", "..", r"\\.\pipe\evil", "S-1-5-1\\..\\x", "S-1-5-18/../..", "S-1-5-\0", "\u{0}", "S-1-5-1\n", "  "] {
            if let Ok(n) = pipe_name(&host, sid) {
                assert!(n.starts_with(PIPE_PREFIX));
                assert!(!n[PIPE_PREFIX.len()..].contains(['\\', '/', '.', '\0']));
            }
        }
        // Everything that is not SID text is refused outright.
        assert_eq!(pipe_name(&host, r"\\.\pipe\evil"), Err(NameError::BadSid));
        assert_eq!(pipe_name(&host, ""), Err(NameError::BadSid));
    }

    #[test]
    fn binary_summary_for_builtin_administrator_passes() {
        // The built-in Administrator (RID 500): SDDL text would say `LA`; the binary path gives the full SID.
        let admin = "S-1-5-21-1111111111-2222222222-3333333333-500";
        let raw = vec![RawAce { ace_type: 0, flags: 0, mask: 0x1f_01ff, trustee_sid: admin.to_owned() }];
        let d = dacl_summary_from_binary(true, &raw);
        assert!(dacl_owner_only(&d, admin));
        // Not protected, inherited flag, deny type, wrong mask, wrong trustee, extra ACE: all refuse.
        assert!(!dacl_owner_only(&dacl_summary_from_binary(false, &raw), admin));
        let mut r = raw.clone();
        r[0].flags = 0x10;
        assert!(!dacl_owner_only(&dacl_summary_from_binary(true, &r), admin));
        r = raw.clone();
        r[0].ace_type = 1;
        assert!(!dacl_owner_only(&dacl_summary_from_binary(true, &r), admin));
        r = raw.clone();
        r[0].mask = 0x1f_01ff | 0x0100_0000;
        assert!(!dacl_owner_only(&dacl_summary_from_binary(true, &r), admin));
        r = raw.clone();
        r[0].trustee_sid = "S-1-5-21-1111111111-2222222222-3333333333-501".to_owned();
        assert!(!dacl_owner_only(&dacl_summary_from_binary(true, &r), admin));
        r = raw.clone();
        r.push(raw[0].clone());
        assert!(!dacl_owner_only(&dacl_summary_from_binary(true, &r), admin));
        assert!(!dacl_owner_only(&dacl_summary_from_binary(true, &[]), admin));
    }

    #[test]
    fn aliased_sddl_text_never_passes() {
        // Production no longer parses SDDL; if text with aliases is ever fed to the old parser it fails closed.
        assert!(parse_owner_dacl_sddl("O:LAD:P(A;;FA;;;LA)").is_err());
    }

    #[test]
    fn sddl_round_trip() {
        let sddl = owner_only_sddl(ME).unwrap();
        let (owner, dacl) = parse_owner_dacl_sddl(&sddl).unwrap();
        assert_eq!(owner, ME);
        assert!(dacl_owner_only(&dacl, ME));
        assert!(owner_only_sddl("S-1-5-1)(A;;GA;;;WD").is_none());
        assert!(owner_only_sddl("").is_none());
    }

    #[test]
    fn sddl_parse_rejects_malformed_and_reads_extra_aces() {
        for bad in ["", "D:P", "O:x", "O:S-1-5-18", "O:S-1-5-18D:P(A;;GA;;;S-1-5-18", "O:S-1-5-18D:P(A;;GA;;S-1-5-18)", "O:S-1-5-18D:P(A;;GA;;;S-1-5-18)junk", "O:S-1-5-18D:p"] {
            assert!(parse_owner_dacl_sddl(bad).is_err(), "{bad:?}");
        }
        let (_, d) = parse_owner_dacl_sddl("O:S-1-5-18D:PAI(A;;FA;;;SY)(A;OICI;FA;;;BA)").unwrap();
        assert_eq!(d.flags, "PAI");
        assert_eq!(d.aces.len(), 2);
        assert!(!dacl_owner_only(&d, ME));
        // An empty DACL parses to no ACEs (and then refuses).
        let (_, e) = parse_owner_dacl_sddl("O:S-1-5-18D:P").unwrap();
        assert!(e.aces.is_empty());
    }

    #[test]
    fn reasons_are_fixed_text() {
        for r in [
            WinUnavailable::FeatureOff,
            WinUnavailable::NotWindows,
            WinUnavailable::IdentityUnreadable,
            WinUnavailable::NameInUse,
            WinUnavailable::CreateFailed(5),
            WinUnavailable::ReadbackFailed,
        ] {
            assert!(r.reason_text().starts_with("peer messaging is unavailable: "));
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Packet 15a: the pure decisions of the Windows `CheckedDir` (`win_dirs.rs`). Compiled and tested on every OS.
// ---------------------------------------------------------------------------------------------------------------

use super::Disabled;

/// Access-mask bits (winnt.h values, spelled out so this file needs no Windows crate).
pub(crate) mod rights {
    pub(crate) const FILE_WRITE_DATA: u32 = 0x2; // FILE_ADD_FILE on a directory
    pub(crate) const FILE_APPEND_DATA: u32 = 0x4; // FILE_ADD_SUBDIRECTORY on a directory
    pub(crate) const FILE_WRITE_EA: u32 = 0x10;
    pub(crate) const FILE_DELETE_CHILD: u32 = 0x40;
    pub(crate) const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    pub(crate) const DELETE: u32 = 0x1_0000;
    pub(crate) const WRITE_DAC: u32 = 0x4_0000;
    pub(crate) const WRITE_OWNER: u32 = 0x8_0000;
    pub(crate) const GENERIC_ALL: u32 = 0x1000_0000;
    pub(crate) const GENERIC_WRITE: u32 = 0x4000_0000;
    pub(crate) const FILE_ALL_ACCESS: u32 = 0x1f_01ff;
    /// Anything that lets a principal change, add, remove or re-permission entries of this directory. Generic bits are
    /// counted as writers outright (GENERIC_WRITE and GENERIC_ALL both map onto several of the bits above).
    pub(crate) const ANY_WRITE: u32 = FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | FILE_DELETE_CHILD
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_WRITE
        | GENERIC_ALL;
    /// What lets a stranger replace or re-own an EXISTING directory below an ancestor (creating a new sibling is fine).
    pub(crate) const ANCESTOR_REPLACE: u32 = FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE;
}

pub(crate) const SID_SYSTEM: &str = "S-1-5-18";
pub(crate) const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
/// ACE flag: the ACE does not apply to the object it is on, only to children.
pub(crate) const ACE_INHERIT_ONLY: u8 = 0x08;

/// Which directory a DACL is judged for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirRole {
    Home,
    /// `<home>/peers`: strict, only our SID may have any access.
    Peers,
    /// ANY ancestor of the home (drive root down to the directory holding the home): a stranger may not hold
    /// `DELETE` (or the other replace rights) on it, at any depth (round 1: a non-parent `DELETE` holder could rename
    /// the ancestor and plant a junction).
    Ancestor,
}

/// The DACL of one directory as read back from its handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirDacl<'a> {
    /// No DACL at all: everyone has full access.
    Null,
    Aces { protected: bool, aces: &'a [RawAce] },
}

/// Deny-like ACE types (plain 1, object 6, callback 10, callback object 12): they never make a directory safer, so
/// they are ignored. Every other type except plain allow (0) fails closed.
fn is_deny_type(t: u8) -> bool {
    matches!(t, 1 | 6 | 10 | 12)
}

/// Is the DACL of `role` acceptable? `ours` is our user SID text. Fail closed on anything not understood.
/// Home / ancestor: no principal other than us, SYSTEM and BUILTIN\Administrators may hold a forbidden right through
/// an ACE that applies to the object (inherit-only ACEs are ignored). Peers: only our SID has any access at all
/// (inherit-only ACEs for others also refuse, because they would reach the files created inside), the DACL is
/// protected, and we hold full control.
pub(crate) fn dir_dacl_acceptable(role: DirRole, dacl: &DirDacl<'_>, ours: &str) -> bool {
    let (protected, aces) = match dacl {
        DirDacl::Null => return false,
        DirDacl::Aces { protected, aces } => (*protected, *aces),
    };
    if ours.is_empty() || !is_sid_text(ours) {
        return false;
    }
    let forbidden = match role {
        DirRole::Home | DirRole::Peers => rights::ANY_WRITE,
        DirRole::Ancestor => rights::ANCESTOR_REPLACE | rights::DELETE,
    };
    let mut we_have_full = false;
    for a in aces {
        if is_deny_type(a.ace_type) {
            continue;
        }
        if a.ace_type != 0 {
            return false; // object / callback / compound allow, or anything unknown
        }
        let inherit_only = a.flags & ACE_INHERIT_ONLY != 0;
        let is_ours = a.trustee_sid == ours;
        if role == DirRole::Peers {
            if !is_ours {
                if a.mask != 0 {
                    return false;
                }
            } else if !inherit_only
                && (a.mask & rights::FILE_ALL_ACCESS == rights::FILE_ALL_ACCESS || a.mask & rights::GENERIC_ALL != 0)
            {
                we_have_full = true;
            }
            continue;
        }
        if inherit_only {
            continue;
        }
        let trusted = is_ours || a.trustee_sid == SID_SYSTEM || a.trustee_sid == SID_ADMINISTRATORS;
        if !trusted && a.mask & forbidden != 0 {
            return false;
        }
    }
    role != DirRole::Peers || (protected && we_have_full)
}

/// Owner rule: we own it, or BUILTIN\Administrators does while our token is elevated with that group enabled
/// (files and directories created by an elevated administrator are owned by the Administrators group by default).
pub(crate) fn owner_acceptable(is_us: bool, is_administrators: bool, administrators_usable: bool) -> bool {
    is_us || (is_administrators && administrators_usable)
}

/// The volume keeps ACLs (`FILE_PERSISTENT_ACLS`). Without it (FAT, exFAT) nothing here can be private.
pub(crate) fn volume_has_acls(fs_flags: u32) -> bool {
    fs_flags & 0x0000_0008 != 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirKind {
    Reparse,
    NotDirectory,
    Directory,
}

/// Classify the attribute bits of an OPEN HANDLE (opened with `FILE_FLAG_OPEN_REPARSE_POINT`): a reparse point of any
/// kind (symlink, junction, mount point) first, then non-directories.
pub(crate) fn dir_kind_from_attrs(attrs: u32) -> DirKind {
    if attrs & 0x0000_0400 != 0 {
        DirKind::Reparse
    } else if attrs & 0x0000_0010 == 0 {
        DirKind::NotDirectory
    } else {
        DirKind::Directory
    }
}

fn is_reserved_device(comp: &str) -> bool {
    let stem = comp.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

/// Judge the home path text and return the chain of directories to inspect, drive root first and the home last
/// (`C:\`, `C:\Users`, `C:\Users\me`, `C:\Users\me\.fuigo`), spelled with backslashes. Pure: no OS call.
/// Refused: UNC and device/extended paths (`\\server\share`, `\\.\`, `\\?\`, `\??\`), relative, rooted-without-drive and
/// drive-relative paths, `.`/`..`, empty parts, characters Windows would reinterpret (`:` alternate data streams,
/// wildcards, control characters), trailing dots or spaces, reserved device names, and an over-long path.
pub(crate) fn parse_home_path(s: &str) -> Result<Vec<String>, Disabled> {
    let is_sep = |c: char| c == '\\' || c == '/';
    if s.contains('\0') {
        return Err(Disabled::HomePathNotNormal);
    }
    if s.starts_with(is_sep) && (s.chars().nth(1).is_some_and(is_sep) || s.starts_with("\\??\\")) {
        return Err(Disabled::HomePathNotNormal);
    }
    let b = s.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && is_sep(b[2] as char) {
        // drive-absolute: below
    } else {
        return Err(Disabled::HomeNotAbsolute);
    }
    if s.len() > 240 {
        return Err(Disabled::HomePathNotNormal);
    }
    let rest = &s[3..];
    let rest = rest.strip_suffix(is_sep).unwrap_or(rest);
    let mut chain = vec![format!("{}:\\", (b[0] as char).to_ascii_uppercase())];
    for comp in rest.split(is_sep) {
        let bad = comp.is_empty()
            || comp == "."
            || comp == ".."
            || comp.len() > 255
            || comp.ends_with('.')
            || comp.ends_with(' ')
            || comp.chars().any(|c| c.is_control() || "<>:\"|?*".contains(c))
            || is_reserved_device(comp);
        if bad {
            return Err(Disabled::HomePathNotNormal);
        }
        let prev = chain.last().cloned().unwrap_or_default();
        let sep = if prev.ends_with('\\') { "" } else { "\\" };
        chain.push(format!("{prev}{sep}{comp}"));
    }
    if chain.len() < 2 {
        return Err(Disabled::HomePathNotNormal); // the home cannot be a drive root
    }
    Ok(chain)
}

/// Turn a [`DaclSummary`] (as `dacl_summary_from_binary` renders it) back into numeric ACEs. `None` for any text that
/// does not round-trip, which refuses.
pub(crate) fn raw_aces_from_summary(d: &DaclSummary) -> Option<(bool, Vec<RawAce>)> {
    fn hex(s: &str) -> Option<u32> {
        u32::from_str_radix(s.strip_prefix("0x")?, 16).ok()
    }
    let mut out = Vec::with_capacity(d.aces.len());
    for a in &d.aces {
        let ace_type = if a.kind == "A" { 0 } else { u8::try_from(hex(&a.kind)?).ok()? };
        let flags = if a.flags.is_empty() { 0 } else { u8::try_from(hex(&a.flags)?).ok()? };
        let mask = hex(&a.rights)?;
        out.push(RawAce { ace_type, flags, mask, trustee_sid: a.trustee.clone() });
    }
    Some((d.flags == "P", out))
}

#[cfg(test)]
mod dir_tests {
    use super::*;

    const ME: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    const OTHER: &str = "S-1-5-21-1111111111-2222222222-3333333333-1002";
    const USERS: &str = "S-1-5-32-545";
    const AUTH_USERS: &str = "S-1-5-11";
    const EVERYONE: &str = "S-1-1-0";
    const FA: u32 = 0x1f_01ff;
    const RX: u32 = 0x12_00a9;
    const MODIFY: u32 = 0x13_01bf;

    fn a(flags: u8, mask: u32, sid: &str) -> RawAce {
        RawAce { ace_type: 0, flags, mask, trustee_sid: sid.to_owned() }
    }
    fn ok(role: DirRole, aces: &[RawAce]) -> bool {
        dir_dacl_acceptable(role, &DirDacl::Aces { protected: true, aces }, ME)
    }
    const HOME: DirRole = DirRole::Home;

    #[test]
    fn writer_rule_allows_us_system_administrators() {
        let aces = [a(0x3, FA, ME), a(0x3, FA, SID_SYSTEM), a(0x3, FA, SID_ADMINISTRATORS)];
        assert!(ok(HOME, &aces));
    }

    #[test]
    fn writer_rule_refuses_each_write_right_for_a_stranger() {
        for who in [USERS, AUTH_USERS, EVERYONE, OTHER] {
            for bit in [0x2u32, 0x4, 0x10, 0x40, 0x100, 0x1_0000, 0x4_0000, 0x8_0000, 0x4000_0000, 0x1000_0000, FA, MODIFY] {
                assert!(!ok(HOME, &[a(0, FA, ME), a(0, bit, who)]), "{who} {bit:#x}");
            }
        }
    }

    #[test]
    fn writer_rule_allows_read_only_strangers_and_ignores_deny_and_inherit_only() {
        assert!(ok(HOME, &[a(0, FA, ME), a(0, RX, USERS), a(0, RX, EVERYONE)]));
        // inherit-only (for example CREATOR OWNER or a child-only Modify) does not apply to the object itself
        assert!(ok(HOME, &[a(0, FA, ME), a(0x0b, MODIFY, AUTH_USERS), a(0x0b, FA, "S-1-3-0")]));
        // a deny ACE never makes it safer, and never makes it worse
        let deny = RawAce { ace_type: 1, flags: 0, mask: FA, trustee_sid: USERS.to_owned() };
        assert!(ok(HOME, &[a(0, FA, ME), deny.clone()]));
        // ... but it also does not cancel an allow
        assert!(!ok(HOME, &[a(0, MODIFY, USERS), deny]));
    }

    #[test]
    fn writer_rule_null_dacl_unknown_types_and_bad_input() {
        assert!(!dir_dacl_acceptable(HOME, &DirDacl::Null, ME));
        for t in [2u8, 3, 4, 5, 7, 8, 9, 11, 13, 0x11, 0x40] {
            let weird = RawAce { ace_type: t, flags: 0, mask: 0, trustee_sid: String::new() };
            assert!(!ok(HOME, &[a(0, FA, ME), weird]), "type {t}");
        }
        for t in [6u8, 10, 12] {
            let deny = RawAce { ace_type: t, flags: 0, mask: 0, trustee_sid: String::new() };
            assert!(ok(HOME, &[a(0, FA, ME), deny]), "deny type {t}");
        }
        // unreadable trustee (empty text) with a write right is a stranger
        assert!(!ok(HOME, &[a(0, MODIFY, "")]));
        assert!(!dir_dacl_acceptable(HOME, &DirDacl::Aces { protected: true, aces: &[] }, ""));
        // an empty DACL grants nobody anything: acceptable for home
        assert!(ok(HOME, &[]));
    }

    #[test]
    fn peers_rule_is_strict() {
        let p = DirRole::Peers;
        assert!(ok(p, &[a(0x3, FA, ME)]));
        assert!(!dir_dacl_acceptable(p, &DirDacl::Aces { protected: false, aces: &[a(0x3, FA, ME)] }, ME));
        // SYSTEM and Administrators are NOT allowed in peers, not even read-only, not even inherit-only
        assert!(!ok(p, &[a(0x3, FA, ME), a(0, RX, SID_SYSTEM)]));
        assert!(!ok(p, &[a(0x3, FA, ME), a(0, FA, SID_ADMINISTRATORS)]));
        assert!(!ok(p, &[a(0x3, FA, ME), a(0x0b, RX, USERS)]));
        // we must hold full control
        assert!(!ok(p, &[]));
        assert!(!ok(p, &[a(0, RX, ME)]));
        assert!(!dir_dacl_acceptable(p, &DirDacl::Null, ME));
    }

    // Realistic default ACLs (icacls) of a Windows 10/11 drive root, C:\Users and a profile directory.
    fn c_root() -> Vec<RawAce> {
        vec![
            a(0x03, FA, SID_ADMINISTRATORS),
            a(0x03, FA, SID_SYSTEM),
            a(0x03, RX, USERS),
            a(0x0b, MODIFY, AUTH_USERS), // (OI)(CI)(IO)(M)
            a(0x00, 0x4, AUTH_USERS),    // (AD)
        ]
    }
    fn c_users() -> Vec<RawAce> {
        vec![
            a(0x03, FA, SID_ADMINISTRATORS),
            a(0x03, FA, SID_SYSTEM),
            a(0x03, RX, USERS),
            a(0x00, RX, EVERYONE),
            a(0x02, 0x4, USERS), // (CI)(AD)... "Users:(CI)(S,AD)"
        ]
    }
    fn profile() -> Vec<RawAce> {
        vec![a(0x13, FA, SID_ADMINISTRATORS), a(0x13, FA, SID_SYSTEM), a(0x13, FA, ME)]
    }

    #[test]
    fn ancestor_table_of_default_acls() {
        let anc = |_direct_parent: bool| DirRole::Ancestor;
        let mut more_c = c_root();
        more_c.push(a(0, 0x40, USERS)); // DELETE_CHILD on the drive root
        let mut users_delete = c_users();
        users_delete.push(a(0, 0x1_0000, USERS)); // DELETE on C:\Users (not the direct parent)
        let mut profile_delete = profile();
        profile_delete.push(a(0, 0x1_0000, OTHER));
        let mut profile_dac = profile();
        profile_dac.push(a(0, 0x4_0000, AUTH_USERS));
        let mut users_gw = c_users();
        users_gw.push(a(0, 0x4000_0000, EVERYONE));
        let mut gp_io_delete = c_users();
        gp_io_delete.push(a(0x0b, 0x1_0000, USERS)); // (OI)(CI)(IO) DELETE: inherit-only, does not apply to C:\Users itself
        let mut gp_delete_other = c_root();
        gp_delete_other.push(a(0, 0x1_0000, OTHER)); // DELETE for any stranger on a grandparent
        let table: Vec<(&str, DirRole, Vec<RawAce>, bool)> = vec![
            ("grandparent with DELETE for a stranger", anc(false), gp_delete_other, false),
            ("grandparent with inherit-only DELETE is ignored", anc(false), gp_io_delete, true),
            ("C:\\ default", anc(false), c_root(), true),
            ("C:\\Users default", anc(false), c_users(), true),
            ("C:\\Users\\me default, direct parent", anc(true), profile(), true),
            ("C:\\ with DELETE_CHILD for Users", anc(false), more_c, false),
            ("C:\\Users with DELETE for Users (not direct parent): now refused", anc(false), users_delete.clone(), false),
            ("same, direct parent", anc(true), users_delete, false),
            ("profile with DELETE for another user, direct parent", anc(true), profile_delete, false),
            ("profile with WRITE_DAC for Authenticated Users", anc(true), profile_dac, false),
            ("C:\\Users with GENERIC_WRITE for Everyone", anc(false), users_gw, false),
        ];
        for (name, role, aces, want) in table {
            assert_eq!(ok(role, &aces), want, "{name}");
        }
        assert!(!dir_dacl_acceptable(anc(false), &DirDacl::Null, ME));
    }

    #[test]
    fn path_rules() {
        let chain = parse_home_path(r"C:\Users\me\.fuigo").unwrap();
        assert_eq!(chain, vec![r"C:\", r"C:\Users", r"C:\Users\me", r"C:\Users\me\.fuigo"]);
        assert_eq!(parse_home_path("c:/Users/me/.fuigo/").unwrap().last().unwrap(), r"C:\Users\me\.fuigo");
        for s in [r"\\server\share\x", r"\\.\C:\x", r"\\?\C:\Users\me", r"//server/share/x", r"\??\C:\x"] {
            assert_eq!(parse_home_path(s), Err(Disabled::HomePathNotNormal), "{s}");
        }
        for s in ["", "me", r"Users\me", r"\Users\me", "C:me", "C:", r"..\x"] {
            assert_eq!(parse_home_path(s), Err(Disabled::HomeNotAbsolute), "{s}");
        }
        for s in [
            r"C:\Users\..\me", r"C:\Users\.\me", r"C:\a\\b", r"C:\a\b:stream", r"C:\a\b*", r"C:\a\b.", r"C:\a\b ",
            r"C:\a\CON", r"C:\a\nul.txt", r"C:\a\LPT1", "C:\\", "C:\\a\\b\0",
        ] {
            assert_eq!(parse_home_path(s), Err(Disabled::HomePathNotNormal), "{s:?}");
        }
        assert!(parse_home_path(r"C:\a\COM10").is_ok());
        assert_eq!(parse_home_path(&format!("C:\\{}", "a".repeat(300))), Err(Disabled::HomePathNotNormal));
    }

    #[test]
    fn handle_facts() {
        assert_eq!(dir_kind_from_attrs(0x10), DirKind::Directory);
        assert_eq!(dir_kind_from_attrs(0x10 | 0x400), DirKind::Reparse);
        assert_eq!(dir_kind_from_attrs(0x400), DirKind::Reparse);
        assert_eq!(dir_kind_from_attrs(0x20), DirKind::NotDirectory);
        assert!(volume_has_acls(0x8 | 0x1));
        assert!(!volume_has_acls(0x7));
        assert!(owner_acceptable(true, false, false));
        assert!(owner_acceptable(false, true, true));
        assert!(!owner_acceptable(false, true, false));
        assert!(!owner_acceptable(false, false, true));
    }

    #[test]
    fn summary_round_trip() {
        let raw = vec![a(0x13, FA, ME), RawAce { ace_type: 5, flags: 0, mask: 0, trustee_sid: String::new() }];
        let (prot, back) = raw_aces_from_summary(&dacl_summary_from_binary(true, &raw)).unwrap();
        assert!(prot);
        assert_eq!(back, raw);
        let mut bad = dacl_summary_from_binary(false, &raw);
        bad.aces[0].rights = "GA".to_owned();
        assert!(raw_aces_from_summary(&bad).is_none());
    }
}


/// May this owner own a locator file? Us; BUILTIN\Administrators only when our token is elevated (Windows gives such a
/// process that owner by default).
pub(crate) fn locator_owner_ok(owner: &str, ours: &str, elevated: bool) -> bool {
    is_sid_text(ours) && (owner == ours || (elevated && owner == SID_ADMINISTRATORS))
}

/// May this DACL guard a locator file? Every ACE is a plain allow (no deny, no object ACE, no audit or inherit-only
/// flag; the inherited flag alone is fine) for us, SYSTEM or BUILTIN\Administrators. Anyone else makes it fail.
pub(crate) fn locator_dacl_ok(d: &DaclSummary, ours: &str) -> bool {
    is_sid_text(ours)
        && d.aces.iter().all(|a| {
            a.kind == "A"
                && (a.flags.is_empty() || a.flags == "0x10")
                && (a.trustee == ours || a.trustee == SID_SYSTEM || a.trustee == SID_ADMINISTRATORS)
        })
}

#[cfg(test)]
mod locator_policy_tests {
    use super::*;

    const ME: &str = "S-1-5-21-1-2-3-1001";

    fn ace(kind: &str, flags: &str, who: &str) -> AceSummary {
        AceSummary { kind: kind.into(), flags: flags.into(), rights: "0x1f01ff".into(), trustee: who.into() }
    }

    #[test]
    fn owner_rule() {
        assert!(locator_owner_ok(ME, ME, false));
        assert!(!locator_owner_ok(SID_ADMINISTRATORS, ME, false));
        assert!(locator_owner_ok(SID_ADMINISTRATORS, ME, true));
        assert!(!locator_owner_ok("S-1-5-32-545", ME, true));
        assert!(!locator_owner_ok(ME, "junk", true));
    }

    #[test]
    fn dacl_rule() {
        let d = |aces| DaclSummary { flags: "P".into(), aces };
        assert!(locator_dacl_ok(&d(vec![ace("A", "", ME)]), ME));
        assert!(locator_dacl_ok(&d(vec![ace("A", "0x10", ME), ace("A", "0x10", SID_SYSTEM), ace("A", "", SID_ADMINISTRATORS)]), ME));
        assert!(locator_dacl_ok(&d(vec![]), ME));
        assert!(!locator_dacl_ok(&d(vec![ace("A", "", ME), ace("A", "", "S-1-5-32-545")]), ME));
        assert!(!locator_dacl_ok(&d(vec![ace("A", "", "S-1-1-0")]), ME));
        assert!(!locator_dacl_ok(&d(vec![ace("0x1", "", ME)]), ME));
        assert!(!locator_dacl_ok(&d(vec![ace("A", "0x8", ME)]), ME));
        assert!(!locator_dacl_ok(&d(vec![ace("A", "", ME)]), "junk"));
    }
}
