//! What drives the sessions of this host process (DESIGN line 290: "default inbound: TUI on with the flag; ACP and headless
//! opt in"). The entry point that arms the peer host says which it is; nothing else decides it.
//!
//! The interactive pager (its own agent, or behind the leader) is opted in when `features.peer_messaging` is on. An ACP stdio
//! agent and a headless run never arm as interactive, so their sessions stay NOT opted in (packet 13 opts them in).

use std::sync::OnceLock;

use crate::session::peer_admission::{OperatorPresence, PeerAdmissionConfig};
use crate::session::peer_message::peer_messaging_enabled;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Driver {
    /// The pager with its in-process agent: a window is attached.
    Pager,
    /// The leader behind pager windows: a session may have no window attached.
    Leader,
}

static DRIVER: OnceLock<Driver> = OnceLock::new();

impl Driver {
    pub(crate) fn admission(self) -> PeerAdmissionConfig {
        let operator = match self {
            Self::Pager => OperatorPresence::Present,
            Self::Leader => OperatorPresence::MayReturn,
        };
        PeerAdmissionConfig { opted_in: true, operator, ..PeerAdmissionConfig::default() }
    }
}

/// The admission a new session starts with, as a pure function of the four facts that decide it: `Some` only for a main
/// session of an interactive host (`driver` is armed by the pager or the leader) with the flag on. ACP stdio and headless
/// never arm a driver; a subagent is never opted in.
pub(crate) fn admission_for(
    flag_on: bool,
    driver: Option<Driver>,
    is_subagent: bool,
    remote_attached: bool,
) -> Option<PeerAdmissionConfig> {
    // S4.1: a leader with a remote client attached opts nothing in.
    if !flag_on || is_subagent || (remote_attached && driver == Some(Driver::Leader)) {
        return None;
    }
    driver.map(Driver::admission)
}

/// The admission a new session starts with in this process (see [`admission_for`]).
pub(crate) fn default_admission(is_subagent: bool) -> Option<PeerAdmissionConfig> {
    admission_for(peer_messaging_enabled(), DRIVER.get().copied(), is_subagent, remote_attached())
}

fn arm_as(driver: Driver) {
    if peer_messaging_enabled() {
        let _ = DRIVER.set(driver);
        super::host::global().arm(crate::util::fuigo_home::fuigo_home());
    }
}

/// The leader (pager windows attach to it).
pub fn arm_peer_host_leader() {
    arm_as(Driver::Leader);
}

/// The pager's own in-process agent (leader off).
pub fn arm_peer_host_pager() {
    arm_as(Driver::Pager);
}

// ---- S4.1: a remote client attached to a leader --------------------------------------------------------------------------
//
// ONE process-level rule, no inspection of message text. The leader serves local pager windows (IPC) AND remote / relay
// clients through ONE agent, and the relay socket receives every agent update of the leader. So while a relay is attached to
// this leader process, NONE of its sessions can send or receive peer messages: every gate is closed (not listed, a send
// answers `unavailable`), `send_message` from a session is refused, and `peer_inbox_status()` is
// `Unavailable(RemoteClientAttached)`. The leader sets the fact where it installs the relay connection and clears it where
// that connection is stopped or dropped (`agent/relay.rs` `RelayHandle`). Reading used: "the relay is installed" (fail closed):
// the relay session exposes no reliable connected / authenticated state, and it already receives every update once installed.
// Flag off: the fact is never consulted.

#[cfg(not(test))]
static REMOTE_ATTACHED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
// Tests scope the fact to the test thread (like the flag override), so parallel tests never see each other's.
#[cfg(test)]
thread_local! {
    static REMOTE_ATTACHED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn adjust_attached(up: bool) {
    #[cfg(not(test))]
    {
        use std::sync::atomic::Ordering::SeqCst;
        if up {
            REMOTE_ATTACHED.fetch_add(1, SeqCst);
        } else {
            let _ = REMOTE_ATTACHED.fetch_update(SeqCst, SeqCst, |n| n.checked_sub(1));
        }
    }
    #[cfg(test)]
    REMOTE_ATTACHED.with(|c| c.set(if up { c.get() + 1 } else { c.get().saturating_sub(1) }));
}

fn attached_count() -> usize {
    #[cfg(not(test))]
    {
        REMOTE_ATTACHED.load(std::sync::atomic::Ordering::SeqCst)
    }
    #[cfg(test)]
    REMOTE_ATTACHED.with(std::cell::Cell::get)
}

/// A remote / relay client connection is attached to this leader process while the guard lives.
#[derive(Debug)]
pub(crate) struct RemoteAttachGuard(());

/// Set the fact (the leader calls this where it installs the relay connection). Dropping the guard clears it.
pub(crate) fn attach_remote() -> RemoteAttachGuard {
    adjust_attached(true);
    RemoteAttachGuard(())
}

impl Drop for RemoteAttachGuard {
    fn drop(&mut self) {
        adjust_attached(false);
    }
}

/// True while a remote client is attached to this process. Flag off: false, and the fact is not read.
pub(crate) fn remote_attached() -> bool {
    peer_messaging_enabled() && attached_count() > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_inbox::directory::{ConnHost, PeerDirectory};
    use crate::peer_inbox::conn::InboxHost;
    use fuigo_peer::{DeliveryOutcome, HostId, RejectReason};
    use crate::session::message_delivery::peer_test_session;

    #[test]
    fn only_a_flagged_interactive_main_session_is_opted_in() {
        let pager = admission_for(true, Some(Driver::Pager), false, false).expect("pager opts in");
        assert!(pager.opted_in && pager.operator == OperatorPresence::Present);
        let leader = admission_for(true, Some(Driver::Leader), false, false).expect("leader opts in");
        assert!(leader.opted_in && leader.operator == OperatorPresence::MayReturn);
        // ACP stdio and headless never arm a driver.
        assert!(admission_for(true, None, false, false).is_none(), "ACP stdio / headless are not opted in");
        // A subagent never is.
        for d in [None, Some(Driver::Pager), Some(Driver::Leader)] {
            assert!(admission_for(true, d, true, false).is_none(), "subagent {d:?}");
        }
        // Nothing is opted in with the flag off.
        for d in [None, Some(Driver::Pager), Some(Driver::Leader)] {
            for sub in [false, true] {
                assert!(admission_for(false, d, sub, false).is_none(), "flag off {d:?} {sub}");
            }
        }
    }

    #[test]
    fn a_leader_with_a_remote_client_attached_opts_nothing_in_the_pager_is_unchanged() {
        assert!(admission_for(true, Some(Driver::Leader), false, true).is_none());
        assert!(admission_for(true, Some(Driver::Pager), false, true).is_some(), "pager (leader off) unchanged");
    }

    #[test]
    fn the_fact_follows_the_guard_and_is_never_read_with_the_flag_off() {
        let _on = crate::session::peer_message::force_peer_messaging_for_test(true);
        assert!(!remote_attached());
        let g = attach_remote();
        let g2 = attach_remote();
        assert!(remote_attached());
        drop(g);
        assert!(remote_attached(), "two connections: still attached");
        drop(g2);
        assert!(!remote_attached());
        let _held = attach_remote();
        let _off = crate::session::peer_message::force_peer_messaging_for_test(false);
        assert!(!remote_attached(), "flag off: not consulted");
    }

    #[tokio::test]
    async fn a_remote_client_attached_closes_every_session_and_clearing_it_reopens() {
        let _on = crate::session::peer_message::force_peer_messaging_for_test(true);
        let host = HostId::new("0123456789abcdef0123456789abcdef").unwrap();
        let dir = PeerDirectory::new(host);
        let (h, _r) = peer_test_session("t-1", Some(crate::session::peer_admission::PeerSubmit::Outcome(DeliveryOutcome::Delivered {})));
        let addr = dir.register("t-1", h.clone(), "", "r").unwrap();
        let ids = |d: &PeerDirectory| d.list_page(0).0.into_iter().map(|r| r.address.session_id().to_owned()).collect::<Vec<_>>();
        let conn = ConnHost::new(dir.clone());
        let env = crate::session::peer_message::test_envelope("m1", "x", "hi");
        conn.peer_hello(&HostId::of(&env.from));
        assert_eq!(ids(&dir), vec!["t-1".to_owned()]);
        assert_eq!(conn.send(addr.clone(), env.clone()).await, DeliveryOutcome::Delivered {});
        let g = attach_remote();
        assert!(ids(&dir).is_empty(), "attached: not listed");
        assert_eq!(conn.send(addr.clone(), env.clone()).await, DeliveryOutcome::Rejected { reason: RejectReason::Unavailable });
        assert!(matches!(
            crate::peer_inbox::host::peer_inbox_status(),
            crate::peer_inbox::host::PeerInboxStatus::Unavailable { reason: crate::peer_inbox::Disabled::RemoteClientAttached }
        ));
        // A local prompt while attached (re-opting the session in, as a prompt-time configure would) does not reopen it.
        h.peer_gate().set_opted_in(true);
        assert!(ids(&dir).is_empty(), "a local action while attached does not reopen");
        assert_eq!(conn.send(addr.clone(), env.clone()).await, DeliveryOutcome::Rejected { reason: RejectReason::Unavailable });
        drop(g);
        assert_eq!(ids(&dir), vec!["t-1".to_owned()], "cleared: reopened");
        assert_eq!(conn.send(addr, env).await, DeliveryOutcome::Delivered {});
    }

    #[test]
    fn the_status_text_is_fixed() {
        assert_eq!(
            crate::peer_inbox::Disabled::RemoteClientAttached.reason_text(),
            "peer messaging is unavailable: a remote client is connected to this Fuigo"
        );
    }

    #[test]
    fn no_code_reads_or_writes_the_driver_meta_tag() {
        // Source pin: the tag text occurs in no non-test source of this crate (this file's tests build it from parts).
        fn walk(dir: &std::path::Path, hits: &mut Vec<String>) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, hits);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    let name = p.file_name().unwrap().to_string_lossy().into_owned();
                    if name.contains("test") || name == "tests.rs" {
                        continue;
                    }
                    let text = std::fs::read_to_string(&p).unwrap();
                    let body = text.rsplit_once("\n#[cfg(test)]\nmod tests").map_or(text.as_str(), |(a, _)| a);
                    if body.to_lowercase().contains(&["fuigo", "driver"].concat()) {
                        hits.push(p.display().to_string());
                    }
                }
            }
        }
        let mut hits = Vec::new();
        walk(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut hits);
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn the_leader_ingress_pumps_do_not_parse_acp_or_call_the_peer_inbox() {
        let text = include_str!("../agent/app.rs");
        let body = text.rsplit_once("\n#[cfg(test)]\nmod tests").map_or(text, |(a, _)| a);
        for marker in ["ipc_to_agent_rx.recv()", "ws_to_agent_rx.recv()"] {
            let at = body.find(marker).unwrap_or_else(|| panic!("pump {marker} not found"));
            let pump: String = body[at..].lines().take(6).collect::<Vec<_>>().join("\n");
            assert!(pump.contains("write_all(msg.as_bytes())"), "{marker}: forwards the line as is");
            for banned in ["peer_inbox", "from_str", "from_slice", "serde_json", "Value"] {
                assert!(!pump.contains(banned), "{marker}: pump touches `{banned}`:\n{pump}");
            }
        }
        // The only peer_inbox calls in the leader app are the arm calls and the attach hook.
        for (i, l) in body.lines().enumerate() {
            if l.contains("peer_inbox::") && !l.trim_start().starts_with("//") {
                assert!(l.contains("arm_peer_host") || l.contains("shutdown_peer_host") || l.contains("driver::attach_remote"), "app.rs:{}: {l}", i + 1);
            }
        }
    }
}
