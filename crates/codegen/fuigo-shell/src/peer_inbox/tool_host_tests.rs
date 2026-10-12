use fuigo_peer::Address;
use fuigo_peer::host::*;

use super::tool_host::*;

const H: &str = "0123456789abcdef0123456789abcdef";

struct Fake;
impl PeerHost for Fake {
    fn status(&self) -> PeerInboxStatus {
        PeerInboxStatus::Ready
    }
    fn this_session(&self) -> Option<SelfInfo> {
        Some(SelfInfo { address: Address::new(H, "me", 1).unwrap(), name: "me".into(), session_ref: "mmmmmmmm".into(), is_subagent: false })
    }
    fn list(&self, _p: u32) -> HostFuture<'_, Result<PeerPage, PeerHostError>> {
        Box::pin(async {
            Ok(PeerPage {
                rows: vec![PeerRow {
                    address: Address::new(H, "s1", 1).unwrap(),
                    name: "<script>\u{202E}x".into(),
                    session_ref: "aaaaaaaa".into(),
                    relation: Relation::Peer,
                }],
                more: false,
            })
        })
    }
    fn send(&self, _r: SendRequest) -> HostFuture<'_, Result<fuigo_peer::DeliveryOutcome, PeerHostError>> {
        Box::pin(async { Err(PeerHostError::Failed) })
    }
}

#[tokio::test]
async fn peers_list_escapes_peer_names() {
    let t = peers_command("list", &Fake).await;
    assert!(t.starts_with("This session is me"), "{t}");
    assert!(!t.contains("<script>") && !t.contains('\u{202E}'), "{t}");
    assert!(t.contains("&lt;script&gt;"), "{t}");
}

#[tokio::test]
async fn peers_status_and_list_give_the_typed_reason_when_unavailable() {
    let host: std::sync::Arc<dyn PeerHost> = std::sync::Arc::new(UnavailableHost::new(NOT_STARTED));
    assert!(peers_command("status", &*host).await.contains(NOT_STARTED));
    assert!(peers_command("list", &*host).await.contains(NOT_STARTED));
    let sym = UnavailableHost::new("the Fuigo home is a symbolic link");
    assert_eq!(peers_command("status", &sym).await, "Peer inbox: unavailable (the Fuigo home is a symbolic link).");
}

#[tokio::test]
async fn peers_status_ready() {
    assert_eq!(peers_command("status", &Fake).await, "Peer inbox: ready.");
}

mod p9b_conversation {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn host(turn: Arc<Mutex<Option<(String, u32)>>>, ring: fuigo_workspace::permission::DenialLog) -> SessionPeerHost {
        let mode = Arc::new(|| fuigo_peer::PeerMode::new(false, fuigo_peer::PeerBase::AcceptEdits, false));
        let conv = Arc::new(move || turn.lock().unwrap().clone());
        SessionPeerHost::new("sess".into(), ring, mode, conv, Arc::new(|| fuigo_peer::OperatorKind::Human))
    }

    fn build(h: &SessionPeerHost, id: &str) -> fuigo_peer::Envelope {
        h.build_envelope(Address::new(H, "sess", 1).unwrap(), "me".into(), "3f2a9c10".into(), id.into(), 1, "hi".into())
    }

    /// S5.6: a human-started turn starts a new conversation at hop 0; a peer-started turn continues the received conversation
    /// one hop further; the chain ends at the receiver's hop budget (8) with the existing reason.
    #[test]
    fn hop_and_conversation_come_from_the_turn_state() {
        let turn = Arc::new(Mutex::new(None));
        let h = host(turn.clone(), Default::default());
        let first = build(&h, "m1");
        assert_eq!((first.hop, first.conversation_id.as_str()), (0, "m1"), "human turn: new conversation, hop 0");
        *turn.lock().unwrap() = Some(("conv-a".into(), 0));
        let reply = build(&h, "m2");
        assert_eq!((reply.hop, reply.conversation_id.as_str()), (1, "conv-a"), "peer-started turn: same conversation, hop + 1");
        *turn.lock().unwrap() = Some(("conv-a".into(), 7));
        let last = build(&h, "m3");
        assert_eq!(last.hop, 8);
        assert!(fuigo_peer::hop_exhausted(last.hop), "the receiver holds it at the hop budget");
        assert!(!fuigo_peer::hop_exhausted(reply.hop));
        *turn.lock().unwrap() = Some(("conv-a".into(), u32::MAX));
        assert_eq!(build(&h, "m4").hop, u32::MAX, "no overflow");
    }

    /// S2.5: the tool input has no field for hop, conversation or notify_when_idle; the host reads neither from the request.
    #[test]
    fn a_model_cannot_set_hop_or_conversation_through_the_tool_input() {
        for field in ["hop", "conversation_id", "conversation", "notify_when_idle"] {
            let input = serde_json::json!({ "to": "x", "message": "m", field: 1 });
            assert!(
                serde_json::from_value::<fuigo_tools::implementations::fuigo_build::peer_tools::SendMessageInput>(input).is_err(),
                "{field} must be an unknown field"
            );
        }
    }

    /// S7.2 through the host's own constructor path: a sender with a recent denial stamps its outgoing envelope.
    #[test]
    fn an_outgoing_envelope_is_stamped_when_the_sender_has_a_recent_denial() {
        let ring = fuigo_workspace::permission::DenialLog::default();
        let h = host(Arc::new(Mutex::new(None)), ring.clone());
        assert!(build(&h, "a").denied_recently.is_empty(), "no denial: no stamp");
        ring.record(fuigo_workspace::permission::DenialKey { kind: "edit".into(), hash: "abc".into() }, fuigo_workspace::permission::mono_secs());
        let env = build(&h, "b");
        assert_eq!(env.denied_recently.len(), 1);
        assert_eq!(env.denied_recently[0].tool_kind, "edit");
    }

    /// The outgoing envelope states the session's REAL operator kind, not a constant `Human` (ACP and headless sessions are
    /// also offered the send tool, and the receiver's admission compares (mode, operator)).
    #[test]
    fn from_operator_is_the_sessions_real_operator_kind() {
        use crate::session::peer_admission::{OperatorPresence, PeerAdmissionConfig, PeerAdmissionState};
        for presence in OperatorPresence::ALL {
            let state = PeerAdmissionState::unmetered();
            // A session no host configured fails closed to `None`.
            assert_eq!((state.operator_kind_handle())(), fuigo_peer::OperatorKind::None);
            state.configure(PeerAdmissionConfig { opted_in: true, operator: presence, ..Default::default() });
            let mode = Arc::new(|| fuigo_peer::PeerMode::new(false, fuigo_peer::PeerBase::AcceptEdits, false));
            let h = SessionPeerHost::new("sess".into(), Default::default(), mode, Arc::new(|| None), state.operator_kind_handle());
            assert_eq!(build(&h, "m").from_operator, presence.kind(), "{presence:?}");
        }
    }

    /// `list` page 0 never returns more rows than the documented total, however many other hosts answer.
    #[test]
    fn merged_list_rows_are_capped_at_the_documented_total() {
        let row = |i: usize| fuigo_peer::host::PeerRow {
            address: Address::new(H, &format!("s{i}"), 1).unwrap(),
            name: String::new(),
            session_ref: format!("r{i}"),
            relation: fuigo_peer::host::Relation::Peer,
        };
        let local: Vec<_> = (0..64).map(row).collect();
        let remote: Vec<_> = (64..64 + 8 * 64).map(row).collect();
        let merged = crate::peer_inbox::tool_host::merge_rows(local, remote);
        assert_eq!(merged.len(), fuigo_peer::limits::MAX_LIST_ROWS);
        assert_eq!(merged[0].session_ref, "r0", "the local rows come first");
    }
}

mod p9c_remote_attached {
    use super::*;

    /// S4.1 follow-up: with a remote client attached a session of this process can neither list nor send, and says why.
    #[tokio::test]
    async fn send_and_list_from_a_session_are_refused_with_the_typed_reason_while_attached() {
        let _on = crate::session::peer_message::force_peer_messaging_for_test(true);
        let mode = std::sync::Arc::new(|| fuigo_peer::PeerMode::new(false, fuigo_peer::PeerBase::AcceptEdits, false));
        let h = SessionPeerHost::new("sess".into(), Default::default(), mode, std::sync::Arc::new(|| None), std::sync::Arc::new(|| fuigo_peer::OperatorKind::Human));
        let req = || SendRequest { to: Address::new(H, "other", 1).unwrap(), message: "hi".into(), summary: None, watch: false };
        let g = crate::peer_inbox::driver::attach_remote();
        assert!(matches!(h.send(req()).await, Err(PeerHostError::Unavailable(r)) if r == REMOTE_ATTACHED));
        assert!(matches!(h.list(0).await, Err(PeerHostError::Unavailable(r)) if r == REMOTE_ATTACHED));
        assert_eq!(h.status(), PeerInboxStatus::Unavailable(REMOTE_ATTACHED.to_owned()));
        drop(g);
        // Cleared: the refusal is gone (what is left is the ordinary "not started" answer of a test process).
        assert!(!matches!(h.send(req()).await, Err(PeerHostError::Unavailable(r)) if r == REMOTE_ATTACHED));
    }
}
