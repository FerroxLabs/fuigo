//! Refused prompts hold automatic wakes until the next user turn.
use super::*;
use serde::{Deserialize, Serialize};

// Match the existing pending-notification cap.
pub(crate) const HELD_WAKE_CAP: usize = super::notification_drain::MAX_PENDING_NOTIFICATIONS;
pub(crate) const HELD_WAKE_FILE: &str = "held_wakes.json";
const HELD_WAKE_QUARANTINE: &str = "held_wakes.json.bad";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HeldWake {
    pub prompt_id: String,
    #[serde(deserialize_with = "deserialize_origin")]
    pub origin: crate::session::PromptOrigin,
    pub blocks: Vec<acp::ContentBlock>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HeldWakes {
    #[serde(default)]
    pub(crate) terminal: bool,
    pub(crate) wakes: VecDeque<HeldWake>,
}

/// Older 1.0.43 files used Debug strings. Preserve their authority even though
/// those strings did not have a stable encoding for the origin's identifiers.
fn deserialize_origin<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<crate::session::PromptOrigin, D::Error> {
    use crate::session::PromptOrigin as O;
    let value = serde_json::Value::deserialize(d)?;
    if let Ok(origin) = serde_json::from_value(value.clone()) {
        return Ok(origin);
    }
    let name = value
        .as_str()
        .and_then(|s| s.split(" {").next())
        .unwrap_or("");
    let origin = match name {
        "TaskCompleted" => O::TaskCompleted {
            task_id: String::new(),
        },
        "SubagentCompleted" => O::SubagentCompleted {
            subagent_id: String::new(),
        },
        "ParentAgentMessage" => O::ParentAgentMessage {
            message_id: String::new(),
            sender_session_id: String::new(),
        },
        "PeerMessage" => O::PeerMessage {
            message_id: String::new(),
            from: String::new(),
        },
        "WorkflowCompleted" => O::WorkflowCompleted {
            completion_id: String::new(),
        },
        "PeerNotice" => O::PeerNotice {
            message_id: String::new(),
        },
        "User" => O::User,
        "NotificationDrain" => O::NotificationDrain,
        "GoalSummary" => O::GoalSummary,
        "GoalClassifierNudge" => O::GoalClassifierNudge,
        "SchedulerFired" => O::SchedulerFired,
        "PlanResume" => O::PlanResume,
        "SubagentTask" => O::SubagentTask,
        "UnverifiedScheduled" => O::UnverifiedScheduled,
        _ => return Err(serde::de::Error::custom("unknown held wake origin")),
    };
    Ok(origin)
}

pub(super) fn item_for_origin(
    origin: &crate::session::PromptOrigin,
    text: String,
) -> ConversationItem {
    use crate::session::PromptOrigin as O;
    match origin {
        O::TaskCompleted { .. } => ConversationItem::task_completed(text),
        O::SubagentCompleted { .. } => ConversationItem::subagent_completed(text),
        O::ParentAgentMessage { .. } => ConversationItem::agent_message(text),
        O::PeerMessage { .. } => ConversationItem::peer_message(text),
        O::WorkflowCompleted { .. } | O::PeerNotice { .. } | O::NotificationDrain => {
            ConversationItem::notification_drain(text)
        }
        O::GoalSummary => ConversationItem::goal_summary(text),
        O::GoalClassifierNudge => ConversationItem::goal_classifier_nudge(text),
        O::SchedulerFired | O::UnverifiedScheduled => ConversationItem::scheduler_fired(text),
        O::PlanResume | O::User | O::SubagentTask => ConversationItem::user(text),
    }
}

impl HeldWakes {
    pub(crate) fn refusal_prompt(&self) -> fuigo_sampling_types::refusal::PromptSM {
        let mut prompt = fuigo_sampling_types::refusal::PromptSM::new(false);
        if self.terminal {
            prompt.state = fuigo_sampling_types::refusal::PromptState::Terminal;
        }
        prompt
    }
    /// Load the held-wake queue from `dir`. An unreadable file is quarantined as `held_wakes.json.bad` through `writer`
    /// (the session folder is written only by its `SessionWriter`), and the prompt stays terminal.
    pub(crate) fn load(dir: &std::path::Path, writer: &fuigo_session_writer::SessionWriter) -> std::io::Result<Self> {
        let path = dir.join(HELD_WAKE_FILE);
        let loaded = match std::fs::read(&path) {
            Ok(bytes) => (|| {
                let value: serde_json::Value = serde_json::from_slice(&bytes)?;
                let legacy = value.get("terminal").is_none();
                // One unreadable entry is dropped; it never costs the whole file.
                let entries = value
                    .get("wakes")
                    .and_then(|w| w.as_array())
                    .ok_or_else(|| std::io::Error::other("held wakes file has no wakes array"))?
                    .clone();
                let mut queue = Self {
                    terminal: match value.get("terminal") {
                        None => false,
                        Some(t) => t.as_bool().ok_or_else(|| std::io::Error::other("held wakes `terminal` is not a bool"))?,
                    },
                    wakes: VecDeque::new(),
                };
                for entry in &entries {
                    match serde_json::from_value::<HeldWake>(entry.clone()) {
                        Ok(wake) => queue.wakes.push_back(wake),
                        Err(error) => tracing::warn!(%error, "Dropping unreadable held wake entry"),
                    }
                }
                if legacy {
                    queue.terminal = !entries.is_empty();
                }
                Ok::<_, std::io::Error>(queue)
            })(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    terminal: dir.join(HELD_WAKE_QUARANTINE).exists(),
                    ..Default::default()
                });
            }
            Err(e) => Err(e),
        };
        match loaded {
            Ok(mut queue) => {
                queue.trim();
                Ok(queue)
            }
            Err(error) => {
                tracing::warn!(%error, "Quarantining unreadable held wakes; prompt stays terminal");
                if let Err(rename_error) = writer.rename_sync(HELD_WAKE_FILE, HELD_WAKE_QUARANTINE) {
                    tracing::warn!(%rename_error, "Could not quarantine held wakes");
                }
                Ok(Self {
                    terminal: true,
                    ..Default::default()
                })
            }
        }
    }
    fn trim(&mut self) {
        let mut dropped = 0;
        while self.wakes.len() > HELD_WAKE_CAP
            || (!self.wakes.is_empty()
                && serde_json::to_vec(self)
                    .expect("held wake serialization")
                    .len()
                    > 1024 * 1024)
        {
            self.wakes.pop_front();
            dropped += 1;
        }
        if dropped > 0 {
            tracing::warn!(
                dropped,
                "Dropped oldest held terminal wakes at count or byte cap"
            );
        }
    }
    fn push(&mut self, wake: HeldWake) {
        self.wakes.push_back(wake);
        self.trim();
    }
    pub(crate) fn save(&self, writer: &fuigo_session_writer::SessionWriter) -> std::io::Result<()> {
        writer.replace_atomic_sync(HELD_WAKE_FILE, &serde_json::to_vec(self)?)
    }
}

impl SessionActor {
    pub(super) fn persist_terminal_prompt(&self) {
        let mut queue = self.held_wakes.lock().unwrap();
        queue.terminal = true;
        if let Some(writer) = &self.rebuild_spec.session_writer
            && let Err(error) = queue.save(writer)
        {
            tracing::error!(%error, "Could not persist terminal prompt");
        }
    }
    pub(super) fn clear_terminal_prompt(&self) -> Result<(), acp::Error> {
        let mut queue = self.held_wakes.lock().unwrap();
        if queue.terminal {
            let mut next = queue.clone();
            next.terminal = false;
            if let Some(writer) = &self.rebuild_spec.session_writer {
                next.save(writer).map_err(|e| {
                    crate::acp_error::internal_error(format!("Could not start new prompt: {e}"))
                })?;
            }
            *queue = next;
        }
        Ok(())
    }

    async fn persist_held_wakes(&self, queue: &HeldWakes) -> Result<(), acp::Error> {
        let (tx, rx) = oneshot::channel();
        self.notifications
            .persistence_tx
            .send(PersistenceMsg::HeldWakes {
                queue: queue.clone(),
                respond_to: tx,
            })
            .map_err(|_| {
                crate::acp_error::internal_error("Could not save held wakes: session writer closed")
            })?;
        rx.await
            .map_err(|_| {
                crate::acp_error::internal_error("Could not save held wakes: session writer closed")
            })?
            .map_err(|e| {
                crate::acp_error::internal_error(format!("Could not save held wakes: {e}"))
            })
    }
    pub(super) async fn hold_terminal_wake(
        &self,
        request: &TurnInputRequest,
    ) -> Result<(), acp::Error> {
        let queue = {
            let mut queue = self.held_wakes.lock().unwrap();
            queue.terminal = true;
            queue.push(HeldWake {
                prompt_id: request.prompt_id.clone(),
                origin: request.input_origin.as_prompt_origin().clone(),
                blocks: request.prompt_blocks.clone(),
            });
            queue.clone()
        };
        self.persist_held_wakes(&queue).await
    }
    pub(super) async fn deliver_held_wakes(&self) -> Result<(), acp::Error> {
        let queue = self.held_wakes.lock().unwrap().clone();
        if queue.wakes.is_empty() {
            return Ok(());
        }
        for wake in &queue.wakes {
            // Keep non-text blocks too. This context remains synthetic/model-authored,
            // never promoted to human input or interpreted as a slash command.
            let body = wake
                .blocks
                .iter()
                .map(|block| match block {
                    acp::ContentBlock::Text(text) => text.text.clone(),
                    other => serde_json::to_string(other).expect("content block serialization"),
                })
                .collect::<Vec<_>>()
                .join("\n");
            let item = item_for_origin(&wake.origin, body);
            if self
                .chat_state_handle
                .push_user_message_and_ack(item)
                .await
                .is_none()
            {
                return Err(crate::acp_error::internal_error(
                    "Could not deliver held wakes: chat state closed",
                ));
            }
        }
        // Persist the delivered context before clearing its durable queue. A failed
        // barrier retains the wakes, preferring replay to losing completion data.
        let (tx, rx) = oneshot::channel();
        self.notifications
            .persistence_tx
            .send(PersistenceMsg::FlushAndAck { respond_to: tx })
            .map_err(|_| crate::acp_error::internal_error("Could not commit held wakes"))?;
        rx.await
            .map_err(|_| crate::acp_error::internal_error("Could not commit held wakes"))?
            .map_err(|e| {
                crate::acp_error::internal_error(format!("Could not commit held wakes: {e}"))
            })?;
        let mut delivered = queue;
        delivered.wakes.clear();
        self.persist_held_wakes(&delivered).await?;
        *self.held_wakes.lock().unwrap() = delivered;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn r7_cap_and_durable_save_load_preserve_newest_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let writer =
            fuigo_session_writer::SessionWriter::try_claim("held-wake-test", dir.path()).unwrap();
        let mut queue = HeldWakes::default();
        for i in 0..HELD_WAKE_CAP + 7 {
            queue.push(HeldWake {
                prompt_id: i.to_string(),
                origin: crate::session::PromptOrigin::TaskCompleted {
                    task_id: "task".into(),
                },
                blocks: vec![acp::ContentBlock::Text(acp::TextContent::new(format!(
                    "payload {i}"
                )))],
            });
        }
        assert_eq!(queue.wakes.len(), HELD_WAKE_CAP);
        queue.save(&writer).unwrap();
        drop(queue);
        let restored = HeldWakes::load(dir.path(), &writer).unwrap();
        assert_eq!(restored.wakes.len(), HELD_WAKE_CAP);
        for (i, wake) in restored.wakes.iter().enumerate() {
            assert_eq!(wake.prompt_id, (i + 7).to_string());
            let acp::ContentBlock::Text(text) = &wake.blocks[0] else {
                panic!("text lost")
            };
            assert_eq!(text.text, format!("payload {}", i + 7));
        }
        HeldWakes::default().save(&writer).unwrap();
        assert!(HeldWakes::load(dir.path(), &writer).unwrap().wakes.is_empty());
    }
    #[test]
    fn r2_corrupt_queue_recovers_terminal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(HELD_WAKE_FILE), b"not json").unwrap();
        let writer = fuigo_session_writer::SessionWriter::try_claim("corrupt-queue", dir.path()).unwrap();
        let queue = HeldWakes::load(dir.path(), &writer)
            .expect("corrupt queue must not prevent session load");
        assert!(queue.wakes.is_empty());
        assert_eq!(serde_json::to_value(&queue).unwrap()["terminal"], true);
        assert!(dir.path().join("held_wakes.json.bad").exists());
        assert!(!dir.path().join(HELD_WAKE_FILE).exists());
    }

    /// The quarantine is a `SessionWriter` operation, not a raw `std::fs::rename`: the writer's own attribution marks
    /// (`b.`/`e.` per path, on this thread) name both the corrupt file and its `.bad` destination.
    #[test]
    fn r2_quarantine_goes_through_the_session_writer() {
        let dir = tempfile::tempdir().unwrap();
        let marks = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(HELD_WAKE_FILE), b"not json").unwrap();
        let writer = fuigo_session_writer::SessionWriter::try_claim("quarantine-via-writer", dir.path()).unwrap();
        fuigo_session_writer::trace::set_test_trace_dir(Some(marks.path().to_path_buf()));
        let queue = HeldWakes::load(dir.path(), &writer);
        fuigo_session_writer::trace::set_test_trace_dir(None);
        assert!(queue.unwrap().terminal);
        assert!(dir.path().join("held_wakes.json.bad").exists());
        let names: Vec<String> = std::fs::read_dir(marks.path())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        for rel in [HELD_WAKE_FILE, "held_wakes.json.bad"] {
            let hash = fuigo_session_writer::trace::path_hash(&writer.dir().join(rel));
            for kind in ["b.", "e."] {
                assert!(
                    names.iter().any(|n| n.starts_with(kind) && n.ends_with(&format!(".{hash}"))),
                    "no {kind} writer mark for {rel}: {names:?}"
                );
            }
        }
    }

    /// A writer that was told to stop (session deleted) refuses the quarantine and nothing is renamed behind its back.
    #[test]
    fn r2_quarantine_is_refused_when_the_writer_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let session = dir.path().join("session");
        std::fs::create_dir(&session).unwrap();
        std::fs::write(session.join(HELD_WAKE_FILE), b"not json").unwrap();
        let writer = fuigo_session_writer::SessionWriter::try_claim("quarantine-gone", &session).unwrap();
        writer.delete_tree_sync().unwrap();
        // The folder is gone with the session; recreate the corrupt file where a raw rename would have reached it.
        std::fs::create_dir(&session).unwrap();
        std::fs::write(session.join(HELD_WAKE_FILE), b"not json").unwrap();
        let queue = HeldWakes::load(&session, &writer).unwrap();
        assert!(queue.terminal);
        assert!(session.join(HELD_WAKE_FILE).exists(), "a gone writer must not rename");
        assert!(!session.join("held_wakes.json.bad").exists());
    }

    #[test]
    fn r2_held_queue_byte_cap() {
        let mut queue = HeldWakes::default();
        for i in 0..8 {
            queue.push(HeldWake {
                prompt_id: i.to_string(),
                origin: crate::session::PromptOrigin::TaskCompleted {
                    task_id: "task".into(),
                },
                blocks: vec![acp::ContentBlock::Text(acp::TextContent::new(
                    "x".repeat(300_000),
                ))],
            });
        }
        assert!(serde_json::to_vec(&queue).unwrap().len() <= 1024 * 1024);
        assert_eq!(queue.wakes.back().unwrap().prompt_id, "7");
    }

    #[test]
    fn r2_legacy_peer_file_round_trip_keeps_authority() {
        use crate::session::{InputAuthority, PromptOrigin};
        let dir = tempfile::tempdir().unwrap();
        // The Debug-origin shape written by the first 1.0.43 candidate.
        let legacy = serde_json::json!({"wakes":[{
            "prompt_id":"peer-wake",
            "origin":r#"PeerMessage { message_id: "message", from: "peer" }"#,
            "blocks":[{"type":"text","text":"untrusted peer payload"}]
        }]});
        std::fs::write(
            dir.path().join(HELD_WAKE_FILE),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let writer =
            fuigo_session_writer::SessionWriter::try_claim("legacy-peer", dir.path()).unwrap();
        let queue = HeldWakes::load(dir.path(), &writer).unwrap();
        assert!(queue.terminal);
        assert_eq!(
            queue.wakes[0].origin.policy().authority,
            InputAuthority::PeerUntrusted
        );
        queue.save(&writer).unwrap();
        let restored = HeldWakes::load(dir.path(), &writer).unwrap();
        assert!(matches!(
            restored.wakes[0].origin,
            PromptOrigin::PeerMessage { .. }
        ));
        assert_eq!(
            restored.wakes[0].origin.policy().authority,
            InputAuthority::PeerUntrusted
        );
        assert_eq!(
            serde_json::to_value(item_for_origin(
                &restored.wakes[0].origin,
                "untrusted peer payload".into()
            ))
            .unwrap(),
            serde_json::to_value(ConversationItem::peer_message("untrusted peer payload")).unwrap()
        );
        let wire: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join(HELD_WAKE_FILE)).unwrap())
                .unwrap();
        assert!(
            wire["wakes"][0]["origin"].is_object(),
            "new files store a typed origin"
        );
    }

    #[test]
    fn r2_unreadable_queue_recovers_terminal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(HELD_WAKE_FILE)).unwrap();
        let writer = fuigo_session_writer::SessionWriter::try_claim("unreadable-queue", dir.path()).unwrap();
        let queue = HeldWakes::load(dir.path(), &writer).unwrap();
        assert!(queue.terminal && queue.wakes.is_empty());
        assert!(dir.path().join("held_wakes.json.bad").is_dir());
        // Quarantining cannot accidentally reopen the next load.
        assert!(HeldWakes::load(dir.path(), &writer).unwrap().terminal);
    }
}
