use std::io;

use fuigo_chat_state::{ChatPersistence, StrictAppendAck, StrictAppendError};
use fuigo_sampling_types::ConversationItem;
use tokio::sync::{mpsc, oneshot};

use super::persistence::PersistenceMsg;

/// Production `ChatPersistence` that sends to the existing session persistence channel.
pub(crate) struct ChannelChatPersistence {
    tx: mpsc::UnboundedSender<PersistenceMsg>,
}

impl ChannelChatPersistence {
    pub(crate) fn new(tx: mpsc::UnboundedSender<PersistenceMsg>) -> Self {
        Self { tx }
    }
}

impl ChannelChatPersistence {
    /// Queue a history replacement for the persistence actor; `Err` when the actor is gone and the replacement was
    /// therefore dropped (the same `BrokenPipe` the acknowledged variant hands its caller).
    fn try_replace_history(&mut self, items: &[ConversationItem]) -> io::Result<()> {
        self.tx
            .send(PersistenceMsg::ReplaceChatHistory(items.to_vec()))
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "session persistence actor unavailable for the chat history replacement",
                )
            })
    }
}

impl ChatPersistence for ChannelChatPersistence {
    fn persist_message(&mut self, item: &ConversationItem) {
        let _ = self.tx.send(PersistenceMsg::Chat(item.clone()));
    }

    fn persist_working_directory_switch_and_ack(
        &mut self,
        item: &ConversationItem,
    ) -> oneshot::Receiver<Result<StrictAppendAck, StrictAppendError>> {
        let (reply, receiver) = oneshot::channel();
        if self
            .tx
            .send(PersistenceMsg::AppendCwdSwitchAndAck {
                item: item.clone(),
                respond_to: reply,
            })
            .is_err()
        {
            let (reply, receiver) = oneshot::channel();
            let _ = reply.send(Err(StrictAppendError::Indeterminate(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session persistence actor unavailable; retry by generation",
            ))));
            return receiver;
        }
        receiver
    }

    fn replace_history(&mut self, items: &[ConversationItem]) {
        // Fire-and-forget by contract (compaction / rewind callers hold the in-memory history and cannot act on a disk
        // failure), but a dropped replacement must not vanish: the acknowledged variant reports an unreachable actor as an
        // error to its caller, and a write failure inside the actor is logged and latched for the next flush barrier.
        // The only failure visible here is the unreachable actor, so it is logged at warn like the actor's own failure.
        if let Err(error) = self.try_replace_history(items) {
            tracing::warn!(%error, "failed to replace chat history");
        }
    }

    fn replace_history_and_ack(
        &mut self,
        items: &[ConversationItem],
    ) -> oneshot::Receiver<io::Result<()>> {
        let (respond_to, receiver) = oneshot::channel();
        if self
            .tx
            .send(PersistenceMsg::ReplaceChatHistoryAndAck {
                messages: items.to_vec(),
                respond_to,
            })
            .is_err()
        {
            let (reply, receiver) = oneshot::channel();
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session persistence actor unavailable for the chat history replacement",
            )));
            return receiver;
        }
        receiver
    }

    fn replace_history_for_strip_and_ack(
        &mut self,
        items: &[ConversationItem],
    ) -> oneshot::Receiver<io::Result<()>> {
        let (respond_to, receiver) = oneshot::channel();
        if self
            .tx
            .send(PersistenceMsg::ReplaceChatHistoryForStripAndAck {
                messages: items.to_vec(),
                respond_to,
            })
            .is_err()
        {
            let (reply, receiver) = oneshot::channel();
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session persistence actor unavailable for strip rewrite",
            )));
            return receiver;
        }
        receiver
    }

    fn flush(&mut self) {
        let _ = self.tx.send(PersistenceMsg::Flush);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A replacement queued after the actor is gone is reported, not silently dropped (same error as the acked path).
    #[tokio::test]
    async fn non_ack_replace_history_surfaces_an_unavailable_actor() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut persistence = ChannelChatPersistence::new(tx);
        let items = [ConversationItem::system("compacted")];
        persistence.try_replace_history(&items).expect("actor alive: queued");
        drop(rx);
        let error = persistence
            .try_replace_history(&items)
            .expect_err("the actor is gone: the replacement must be reported");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        let acked = persistence
            .replace_history_and_ack(&items)
            .await
            .expect("the ack channel is answered")
            .expect_err("the acked path reports the same condition");
        assert_eq!(acked.kind(), error.kind());
        // The trait method must not panic on the same failure
        persistence.replace_history(&items);
    }

    #[tokio::test]
    async fn channel_persistence_sends_chat_messages() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut persistence = ChannelChatPersistence::new(tx);
        let item = ConversationItem::user("test");
        persistence.persist_message(&item);
        let msg = rx.recv().await.unwrap();
        assert!(matches!(msg, PersistenceMsg::Chat(_)));
    }

    #[tokio::test]
    async fn channel_persistence_sends_acknowledged_chat_append() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut persistence = ChannelChatPersistence::new(tx);
        let item = ConversationItem::working_directory_switch("moved", 1);
        let ack = persistence.persist_working_directory_switch_and_ack(&item);
        let msg = rx.recv().await.unwrap();
        let PersistenceMsg::AppendCwdSwitchAndAck {
            item: persisted,
            respond_to,
        } = msg
        else {
            panic!("expected acknowledged chat append");
        };
        assert_eq!(
            serde_json::to_vec(&persisted).unwrap(),
            serde_json::to_vec(&item).unwrap()
        );
        respond_to.send(Ok(StrictAppendAck::Appended)).unwrap();
        assert!(matches!(
            ack.await.unwrap().unwrap(),
            StrictAppendAck::Appended
        ));
    }

    #[tokio::test]
    async fn channel_persistence_sends_replace_history() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut persistence = ChannelChatPersistence::new(tx);
        persistence.replace_history(&[ConversationItem::system("compacted")]);
        let msg = rx.recv().await.unwrap();
        assert!(matches!(msg, PersistenceMsg::ReplaceChatHistory(_)));
    }

    #[tokio::test]
    async fn channel_persistence_sends_acked_strip_rewrite() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut persistence = ChannelChatPersistence::new(tx);
        let ack = persistence.replace_history_for_strip_and_ack(&[ConversationItem::system("s")]);
        let msg = rx.recv().await.unwrap();
        let PersistenceMsg::ReplaceChatHistoryForStripAndAck { respond_to, .. } = msg else {
            panic!("expected acked strip rewrite, got {msg:?}");
        };
        respond_to.send(Ok(())).unwrap();
        assert!(ack.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn channel_persistence_acks_strip_error_when_actor_gone() {
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx);
        let mut persistence = ChannelChatPersistence::new(tx);
        let ack = persistence.replace_history_for_strip_and_ack(&[ConversationItem::system("s")]);
        assert!(
            ack.await.unwrap().is_err(),
            "dead persistence actor must ack an error, not hang or succeed"
        );
    }

    #[tokio::test]
    async fn channel_persistence_sends_flush() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut persistence = ChannelChatPersistence::new(tx);
        persistence.flush();
        let msg = rx.recv().await.unwrap();
        assert!(matches!(msg, PersistenceMsg::Flush));
    }
}
