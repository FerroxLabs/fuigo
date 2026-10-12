use super::*;
use crate::session::plan_mode::PromptMode;
#[test]
fn human_unsupported_operation_rejects_without_command() {
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let handle = MessageDeliveryHandle::new(cmd_tx, "resident".to_owned());
    let (respond_to, _) = oneshot::channel();
    let content = HumanPromptContent {
        prompt_blocks: vec![agent_client_protocol::ContentBlock::Text(
            agent_client_protocol::TextContent::new("hello"),
        )],
        prompt_mode: PromptMode::Agent,
        artifact_upload_ctx: None,
        client_identifier: None,
        screen_mode: None,
        verbatim: false,
        traceparent: None,
        json_schema: None,
        tool_overrides_update: None,
        origin: crate::session::PromptOrigin::User,
        respond_to,
        parsed_prompt_tx: None,
    };
    let envelope = DeliveryEnvelope::from_human(
        Operation::Interject,
        content,
        human_delivery_identity("prompt".to_owned()),
        ResidentHumanGrant::new("resident".to_owned()),
    );

    assert!(matches!(
        handle.send_human(envelope),
        Err(HumanDeliveryError::Unsupported)
    ));
    assert!(cmd_rx.try_recv().is_err());
}

/// 8f finding 8: a stalled session actor never has more than 32 peer envelopes queued; the rest answer `rate_limited`
/// without queueing, and the slots come back when the actor is done with (or drops) the commands.
#[tokio::test]
async fn xs_p8f_a_stalled_actor_receives_at_most_32_queued_envelopes() {
    let _on = crate::session::peer_message::force_peer_messaging_for_test(true);
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let handle = MessageDeliveryHandle::new(cmd_tx, "stalled".to_owned());
    let from = fuigo_peer::Address::new("a".repeat(32).as_str(), "s", 1).unwrap();
    let mk = |i: usize| crate::session::peer_message::test_envelope(&format!("m{i}"), "lane a", "hi");
    let _ = &from;
    let futs: Vec<_> = (0..40).map(|i| handle.deliver_peer_message(mk(i))).collect();
    // The actor never answers: the 32 admitted calls stay pending, the other 8 return at once.
    let all = futures::future::join_all(futs);
    let timed_out = tokio::time::timeout(std::time::Duration::from_millis(300), all).await;
    assert!(timed_out.is_err(), "32 calls are still waiting for the stalled actor");
    let mut queued = 0;
    while cmd_rx.try_recv().is_ok_and(|c| matches!(c, SessionCommand::PeerMessage { .. })) {
        queued += 1;
    }
    assert_eq!(queued, 32, "exactly the cap reached the channel");
    // Dropping the commands (the actor is gone) returns every slot.
    assert_eq!(handle.peer_gate().in_flight(), 0);
}

/// An abandoned send (the caller's deadline) still counts while its command sits unread in the channel.
#[tokio::test]
async fn xs_p8f_an_abandoned_send_keeps_its_slot_until_the_actor_is_done() {
    let _on = crate::session::peer_message::force_peer_messaging_for_test(true);
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let handle = MessageDeliveryHandle::new(cmd_tx, "stalled".to_owned());
    for i in 0..32 {
        let fut = handle.deliver_peer_message(crate::session::peer_message::test_envelope(&format!("m{i}"), "lane a", "hi"));
        let _ = tokio::time::timeout(std::time::Duration::from_millis(1), fut).await;
    }
    assert_eq!(handle.peer_gate().in_flight(), 32, "queued commands still hold their slots");
    let r = handle.deliver_peer_message(crate::session::peer_message::test_envelope("m33", "lane a", "hi")).await;
    assert_eq!(
        r,
        crate::session::peer_admission::PeerSubmit::Outcome(fuigo_peer::DeliveryOutcome::Rejected {
            reason: fuigo_peer::RejectReason::RateLimited
        })
    );
    while cmd_rx.try_recv().is_ok() {}
    assert_eq!(handle.peer_gate().in_flight(), 0, "the actor consuming the commands frees the slots");
}
