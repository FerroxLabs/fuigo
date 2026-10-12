//! Hooks for the Windows evidence program `tests/win_peer_inbox_evidence.rs` (packet 10). Windows only, doc-hidden,
//! reachable from no host code: an integration test cannot see the crate-private inbox, so this is the narrow door.
//! Everything returned is plain data or fixed text.
#![allow(dead_code)]

use fuigo_peer::{HostId, Op, Reply};

use super::win_pipe::{self, StartOptions, WinPeerInbox};
use super::win_policy::{EVIDENCE_OPEN_ACL_VAR, evidence_open_acl_requested, pipe_name};
use crate::leader::peer_auth::win as auth;

/// A running inbox for the evidence program.
pub struct EvidenceInbox {
    inner: WinPeerInbox,
}

/// Start the inbox for `host_id` with the feature forced on. `Err` is the fixed reason text.
pub async fn start(host_id: &HostId) -> Result<EvidenceInbox, String> {
    match WinPeerInbox::start_inner(StartOptions { enabled: true, evidence_open_acl: false }, host_id.clone()).await {
        Ok(inner) => Ok(EvidenceInbox { inner }),
        Err(r) => Err(r.reason_text().to_owned()),
    }
}

/// DEBUG BUILDS ONLY. Start the inbox with a pipe DACL that ALSO lets Authenticated Users and SYSTEM connect, so a
/// foreign token gets past the pipe's own access list and reaches the server's verdict function. Refuses to start
/// unless the process environment has `FUIGO_P10_EVIDENCE_OPEN_ACL=1`. This is the only reader of that variable;
/// production start never reads it and a release build does not compile this function.
#[cfg(debug_assertions)]
pub async fn start_open_acl(host_id: &HostId) -> Result<EvidenceInbox, String> {
    if !evidence_open_acl_requested(|k| std::env::var(k).ok()) {
        return Err(format!("set {EVIDENCE_OPEN_ACL_VAR}=1 to run the open-ACL evidence case"));
    }
    match WinPeerInbox::start_inner(StartOptions { enabled: true, evidence_open_acl: true }, host_id.clone()).await {
        Ok(inner) => Ok(EvidenceInbox { inner }),
        Err(r) => Err(r.reason_text().to_owned()),
    }
}

/// Start with the feature off: must fail without touching the OS.
pub async fn start_disabled(host_id: &HostId) -> Result<EvidenceInbox, String> {
    match WinPeerInbox::start_inner(StartOptions { enabled: false, evidence_open_acl: false }, host_id.clone()).await {
        Ok(inner) => Ok(EvidenceInbox { inner }),
        Err(r) => Err(r.reason_text().to_owned()),
    }
}

impl EvidenceInbox {
    pub fn pipe_name(&self) -> String {
        self.inner.pipe_name().to_owned()
    }

    pub fn accepted(&self) -> u64 {
        self.inner.stats().accepted.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn refused(&self) -> u64 {
        self.inner.stats().refused.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The fixed name of the last refusal reason.
    pub fn last_refusal(&self) -> Option<String> {
        self.inner.stats().last_refusal().map(|r| format!("{r:?}"))
    }

    pub async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}

/// The pipe name for `host_id` and the current user.
pub fn pipe_name_for(host_id: &HostId) -> Result<String, String> {
    let sid = auth::own_sid().map_err(|c| format!("own account unreadable (Win32 {c})"))?;
    pipe_name(host_id, &sid).map_err(|_| "bad sid".to_owned())
}

fn describe(r: Result<Reply, win_pipe::WinDialError>) -> Result<usize, String> {
    match r {
        Ok(Reply::List { rows, .. }) => Ok(rows.len()),
        Ok(_) => Err("unexpected reply kind".to_owned()),
        Err(e) => Err(format!("{e:?}")),
    }
}

/// List the sessions of `host_id` through the production dialer: Ok(row count) or the fixed error name.
pub async fn dial_list(our: &HostId, host_id: &HostId) -> Result<usize, String> {
    describe(win_pipe::dial(our, host_id, Op::List { page: 0 }).await)
}

/// The same against an explicit path (a file, a junction, a remote name). DEBUG BUILDS ONLY.
#[cfg(debug_assertions)]
pub async fn dial_list_at(path: &str, our: &HostId, host_id: &HostId) -> Result<usize, String> {
    describe(win_pipe::dial_at(path, our, host_id, Op::List { page: 0 }).await)
}
