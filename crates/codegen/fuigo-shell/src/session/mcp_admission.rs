//! MC-03 launch gate: the one check every shell MCP launch passes (see `util::config::mcp_approvals`).
//!
//! The launch wrappers in `session::mcp_servers` take [`AdmittedMcpLaunch`], whose only constructors are the gate
//! ([`admit_mcp_launch`] and its variants) and [`admit_installed`] for objects the gate already installed, so a launch
//! that skips the gate does not compile. The gate runs on the exact list about to be installed, after every overlay,
//! on the blocking pool before any session-state lock (review Astra M4); a server's admission stamp (key + digest of
//! the definition it was built from, in the same read) decides:
//! * marked uncovered (plugin, client-supplied, managed/system layer): admitted;
//! * neither a stamp nor that mark, or a stamp that does not parse: held (a covered loader always stamps);
//! * store Unavailable: held (fail closed), one notice;
//! * digest in the key's approved set: admitted, nothing written;
//! * key missing: compare-or-insert under the store lock (first sight is silent);
//! * key present without the digest: held, with a user-facing notice (never the model's context).
//!
//! Bypass mode is not involved: this is a launch gate, not a tool permission.

use std::collections::BTreeMap;
use std::sync::Mutex;

use agent_client_protocol as acp;

use crate::session::mcp_servers::mcp_server_name;
use crate::util::config::McpOAuthConfig;
use crate::util::config::mcp_approvals as ap;

/// A server that passed [`admit_mcp_launch`]. Covered servers carry the OAuth settings admitted with them; connect uses
/// those, never a fresh read of the config files.
#[derive(Debug, Clone)]
pub(crate) struct AdmittedMcpLaunch {
    server: acp::McpServer,
    /// `Some(oauth)` for a covered server (its admitted OAuth, possibly none); `None` for an uncovered one, which
    /// keeps the caller's OAuth map (plugin OAuth).
    covered_oauth: Option<Option<McpOAuthConfig>>,
}

impl AdmittedMcpLaunch {
    pub(crate) fn server(&self) -> &acp::McpServer {
        &self.server
    }

    pub(crate) fn into_server(self) -> acp::McpServer {
        self.server
    }

    pub(crate) fn name(&self) -> &str {
        mcp_server_name(&self.server)
    }

    /// Whether the approval gate covers this server (its OAuth comes from the admission, not the caller's map).
    pub(crate) fn is_covered(&self) -> bool {
        self.covered_oauth.is_some()
    }

    /// The OAuth settings to connect with: the admitted ones for a covered server, else `fallback`.
    pub(crate) fn oauth<'a>(
        &'a self,
        fallback: Option<&'a McpOAuthConfig>,
    ) -> Option<&'a McpOAuthConfig> {
        match &self.covered_oauth {
            Some(admitted) => admitted.as_ref(),
            None => fallback,
        }
    }
}

/// A covered server the gate did not start.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HeldMcpServer {
    pub name: String,
    pub key: String,
    pub digest: String,
    /// Where the definition lives.
    pub origin: String,
    /// What it will run or connect to (`runs: ...` / `connects to: ...`).
    pub display: String,
    /// Held because the approvals file could not be read (approving cannot help until it is repaired).
    pub store_unavailable: bool,
}

#[derive(Debug, Default)]
pub(crate) struct Admission {
    pub admitted: Vec<AdmittedMcpLaunch>,
    pub held: Vec<HeldMcpServer>,
    /// User-facing notices (the notice list and the client's config notices); never added to the model's context.
    pub notices: Vec<String>,
}

impl Admission {
    /// The admitted launch objects, for `McpState::configs`.
    pub(crate) fn servers(&self) -> Vec<acp::McpServer> {
        self.admitted.iter().map(|a| a.server.clone()).collect()
    }
}

/// The held servers the gate last saw, by session and approval key (scope and name): what turning one on in that
/// session's `/mcp` approves (exactly the digest that session's gate held, not a fresh read). Keyed by scope so a toggle
/// in one project can never approve another project's same-named server (review Fable M2), and by session so one
/// session's toggle never approves a definition only another session held (review Astra H1). Passes with no session
/// (doctor, the sessionless pool) are kept under `""`, which no toggle names.
static HELD: Mutex<BTreeMap<(String, String), HeldMcpServer>> = Mutex::new(BTreeMap::new());

pub(crate) fn held_mcp_server(session: &str, key: &str) -> Option<HeldMcpServer> {
    HELD.lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(session.to_owned(), key.to_owned()))
        .cloned()
}

pub(crate) fn held_mcp_servers() -> Vec<HeldMcpServer> {
    HELD.lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .cloned()
        .collect()
}

/// The servers held in `session` (every session's when `None`).
pub(crate) fn held_mcp_servers_in(session: Option<&str>) -> Vec<HeldMcpServer> {
    HELD.lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|((s, _), _)| session.is_none_or(|session| s == session))
        .map(|(_, held)| held.clone())
        .collect()
}

/// The approval key of the server named `name` that `session` holds, if any: its covered identity while it is not in
/// the session's admitted list (a child's same-named inline server is keyed to it; review Astra/Fable confirm H2).
pub(crate) fn held_key_by_name(session: &str, name: &str) -> Option<String> {
    HELD.lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .find(|((s, _), held)| s == session && held.name == name)
        .map(|((_, key), _)| key.clone())
}

fn remember(session: &str, admission: &Admission) {
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    for a in &admission.admitted {
        if let Some(stamp) = ap::read_stamp(&a.server) {
            held.remove(&(session.to_owned(), stamp.key));
        }
    }
    for h in &admission.held {
        held.insert((session.to_owned(), h.key.clone()), h.clone());
    }
}

/// The gate, for a pass that belongs to no session (doctor, the sessionless pool). Reads the store once per pass;
/// writes only for a first-seen key.
pub(crate) fn admit_mcp_launch(candidates: Vec<acp::McpServer>) -> Admission {
    admit_for_session("", candidates)
}

/// The gate for session `session`: its held servers are what that session's `/mcp` toggle can approve.
pub(crate) fn admit_for_session(session: &str, candidates: Vec<acp::McpServer>) -> Admission {
    let store = ap::store_path();
    admit_in(session, candidates, &store, None)
}

/// [`admit_for_session`] on the blocking pool (store reads and a first-seen write are blocking file I/O; review Astra
/// M4), for a caller on the session's reactor. Callers take the `McpState` lock only after this returns.
pub(crate) async fn admit_off_reactor(
    session: String,
    candidates: Vec<acp::McpServer>,
) -> Admission {
    let retry = candidates.clone();
    match tokio::task::spawn_blocking({
        let session = session.clone();
        move || admit_for_session(&session, candidates)
    })
    .await
    {
        Ok(admission) => admission,
        // The pool refused or the task was cancelled: gate in place, as before.
        Err(_) => admit_for_session(&session, retry),
    }
}

pub(crate) fn admit_with_store(
    candidates: Vec<acp::McpServer>,
    store: &std::path::Path,
) -> Admission {
    admit_in("", candidates, store, None)
}

/// The gate body. `state` is the store as first read; `None` reads it now (tests pass a stale snapshot to reach the
/// locked re-read with a store that changed meanwhile).
pub(crate) fn admit_in(
    session: &str,
    candidates: Vec<acp::McpServer>,
    store: &std::path::Path,
    state: Option<ap::StoreState>,
) -> Admission {
    let mut out = Admission::default();
    if candidates.is_empty() {
        return out;
    }
    let state = state.unwrap_or_else(|| ap::load_store_at(store));
    let mut unavailable_noted = false;
    for server in candidates {
        let Some(stamp) = ap::read_stamp(&server) else {
            if ap::uncovered_source(&server).is_some() {
                out.admitted.push(AdmittedMcpLaunch {
                    server,
                    covered_oauth: None,
                });
                continue;
            }
            // Fail closed: only plugin, client and managed servers are uncovered, and they say so; any other object
            // without a readable stamp says nothing about what was approved.
            let name = mcp_server_name(&server).to_owned();
            out.notices.push(format!(
                "warning: MCP server `{}` was not started: its approval record is missing or could not be read. Restart the session; if it persists, run `fuigo mcp approvals reset`.",
                fuigo_config::config_override::tidy_note_text(&name, 64)
            ));
            continue;
        };
        let name = mcp_server_name(&server).to_owned();
        let hold = |out: &mut Admission, store_unavailable: bool| {
            out.held.push(HeldMcpServer {
                name: name.clone(),
                key: stamp.key.clone(),
                digest: stamp.digest.clone(),
                origin: stamp.origin.clone(),
                display: ap::launch_display(&server),
                store_unavailable,
            });
        };
        let admit = |out: &mut Admission, server: acp::McpServer| {
            let covered_oauth = Some(stamp.oauth_config());
            out.admitted.push(AdmittedMcpLaunch {
                server,
                covered_oauth,
            });
        };
        if let ap::StoreState::Unavailable(reason) = &state {
            hold(&mut out, true);
            if !unavailable_noted {
                unavailable_noted = true;
                out.notices.push(ap::unavailable_store_notice(reason));
            }
            continue;
        }
        match state.digests(&stamp.key) {
            Some(set) if set.contains(&stamp.digest) => admit(&mut out, server),
            Some(_) => {
                hold(&mut out, false);
                out.notices.push(ap::held_notice(&name, &stamp.origin));
            }
            None => match ap::record_first_seen_at(store, &stamp.key, &stamp.digest) {
                Ok(ap::FirstSeen::Recorded | ap::FirstSeen::Approved) => admit(&mut out, server),
                Ok(ap::FirstSeen::Held) => {
                    hold(&mut out, false);
                    out.notices.push(ap::held_notice(&name, &stamp.origin));
                }
                // Review Astra M2: the locked re-read failed, so absence is not established: hold, never allow.
                Ok(ap::FirstSeen::Unavailable(reason)) => {
                    hold(&mut out, true);
                    if !unavailable_noted {
                        unavailable_noted = true;
                        out.notices.push(ap::unavailable_store_notice(&reason));
                    }
                }
                Err(e) => {
                    // A new server starts as it does today; nothing is lost: it is first seen again next time.
                    tracing::warn!(server = %name, error = %e, "could not record a first-seen MCP definition");
                    out.notices.push(format!(
                        "warning: MCP server `{}` started, but its definition could not be recorded in the approvals file: {e}",
                        fuigo_config::config_override::tidy_note_text(&name, 64)
                    ));
                    admit(&mut out, server);
                }
            },
        }
    }
    for notice in &out.notices {
        fuigo_config::mcp_bearer_file::record_note(notice.clone());
    }
    remember(session, &out);
    out
}

/// The admitted snapshots of servers already installed in `McpState::configs` (init, restart, retry, OAuth rebuild).
/// `McpState::configs` is only ever written with [`Admission::servers`], so each object there passed the gate; its
/// stamp carries the admitted OAuth. No file I/O, so this is safe on the reactor and under the state lock (review Astra
/// M4). Re-reading the store here would change nothing: the store only grows (a reset empties it, and a first sight is
/// then recorded and admitted). A changed definition reaches a session only through a reload, which runs the gate.
/// An object with neither a stamp nor an uncovered mark is still dropped (fail closed).
pub(crate) fn admit_installed(servers: &[acp::McpServer]) -> Vec<AdmittedMcpLaunch> {
    servers
        .iter()
        .filter_map(|server| {
            let covered_oauth = match ap::read_stamp(server) {
                Some(stamp) => Some(stamp.oauth_config()),
                None if ap::uncovered_source(server).is_some() => None,
                None => {
                    tracing::warn!(server = %mcp_server_name(server), "installed MCP server has no admission stamp; not started");
                    return None;
                }
            };
            Some(AdmittedMcpLaunch {
                server: server.clone(),
                covered_oauth,
            })
        })
        .collect()
}

/// `McpState::update_configs_diff` on the admitted part of `candidates`, returning the diff and the admission (its
/// notices for the caller to send to the client).
#[cfg(test)]
pub(crate) fn install_admitted_diff(
    session: &str,
    state: &mut crate::session::mcp_servers::McpState,
    candidates: Vec<acp::McpServer>,
) -> (
    Option<crate::session::mcp_servers::McpConfigDiff>,
    Admission,
) {
    let admission = admit_for_session(session, candidates);
    let diff = state.update_configs_diff(admission.servers());
    (diff, admission)
}

/// What a toggle of `server` answers after its gate pass: turned on but still held is an error saying why, never ok
/// (review Fable confirm 2).
pub(crate) fn toggle_outcome(
    admission: &Admission,
    server: &str,
    enabled: bool,
) -> Result<(), String> {
    match admission.held.iter().find(|h| enabled && h.name == server) {
        Some(held) => Err(still_held_message(held)),
        None => Ok(()),
    }
}

fn still_held_message(held: &HeldMcpServer) -> String {
    let name = fuigo_config::config_override::tidy_note_text(&held.name, 64);
    if held.store_unavailable {
        format!(
            "MCP server `{name}` is still not started: the approvals file could not be read, so no definition can be approved. Fix the file, or run `fuigo mcp approvals reset`."
        )
    } else {
        format!(
            "MCP server `{name}` is still not started: the definition it would launch is not the one approved (it changed again, or was not the one shown). Review it in /mcp, or approve it with `fuigo mcp enable {name}`."
        )
    }
}

/// What the gate would hold now, without writing (the store is only read). For the CLI, `/mcp` and doctor; it decides
/// nothing: the gate stays the authority.
pub(crate) fn preview_held(candidates: &[acp::McpServer]) -> Vec<HeldMcpServer> {
    let state = ap::load_store();
    candidates
        .iter()
        .filter_map(|server| {
            let stamp = ap::read_stamp(server)?;
            let unavailable = matches!(state, ap::StoreState::Unavailable(_));
            let held = unavailable
                || state
                    .digests(&stamp.key)
                    .is_some_and(|set| !set.contains(&stamp.digest));
            held.then(|| HeldMcpServer {
                name: mcp_server_name(server).to_owned(),
                key: stamp.key,
                digest: stamp.digest,
                origin: stamp.origin,
                display: ap::launch_display(server),
                store_unavailable: unavailable,
            })
        })
        .collect()
}

/// Approve the definition behind `server`'s stamp (the object the caller shows or is about to install). `Ok(false)`
/// when it carries none (nothing to approve).
pub(crate) fn approve_stamped(server: &acp::McpServer) -> anyhow::Result<bool> {
    let Some(stamp) = ap::read_stamp(server) else {
        return Ok(false);
    };
    ap::approve_mcp_definition(&stamp.key, &stamp.digest)?;
    Ok(true)
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there"
)]
#[path = "mcp_admission_tests.rs"]
mod tests;

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there"
)]
#[path = "mcp_admission_review_tests.rs"]
mod review_tests;
