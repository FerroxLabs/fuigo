//! Headless half of the prompt-acknowledgment fail-safe: the single `-p` prompt is bounded the same
//! way a TUI prompt would be, but the only recovery is a bounded rewind cancel and a non-zero exit.

use std::time::Duration;

use agent_client_protocol as acp;
use fuigo_acp_lib::{AcpAgentTx, AcpClientMessageBox, acp_send};

use crate::app::prompt_ack::{AckSignal, PromptAckDeadlines, queue_changed_acks};

/// Bounds the rewind cancel and the final log flush after an unacknowledged prompt: a wedged
/// in-process shell holds the dispatch lock its `cancel()` also needs.
pub(super) const HEADLESS_ABORT_SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// Machine-greppable prefix on the exit error so integrations can tell this apart from a model failure.
const PROMPT_ACK_TIMEOUT_ERROR_PREFIX: &str = "prompt_ack_timeout";

/// Classify an inbound client message as an acknowledgment of `prompt_id` (single session, single prompt).
/// Replayed updates and notifications without a prompt id never count.
pub(super) fn headless_ack_signal(
    msg: &AcpClientMessageBox,
    session_id: &acp::SessionId,
    prompt_id: &str,
) -> Option<AckSignal> {
    match msg {
        AcpClientMessageBox::SessionNotification(notif) => {
            if notif.request.session_id != *session_id {
                return None;
            }
            let meta = crate::acp::meta::NotificationMeta::from_json(notif.request.meta.as_ref());
            (!meta.is_replay && meta.prompt_id.as_deref() == Some(prompt_id))
                .then_some(AckSignal::SessionUpdate)
        }
        AcpClientMessageBox::ExtNotification(notif) => {
            if notif.request.method.as_ref()
                != fuigo_shell::session::prompt_queue::QUEUE_CHANGED_METHOD
            {
                return None;
            }
            let changed = match serde_json::from_str::<crate::app::prompt_queue::QueueChanged>(
                notif.request.params.get(),
            ) {
                Ok(changed) => changed,
                Err(error) => {
                    tracing::warn!(%error, "headless: unparsable fuigo/queue/changed payload");
                    return None;
                }
            };
            (changed.session_id == session_id.0.as_ref() && queue_changed_acks(&changed, prompt_id))
                .then_some(AckSignal::QueueChanged)
        }
        AcpClientMessageBox::RequestPermission(_)
        | AcpClientMessageBox::ReadTextFile(_)
        | AcpClientMessageBox::WriteTextFile(_)
        | AcpClientMessageBox::CreateTerminal(_)
        | AcpClientMessageBox::TerminalOutput(_)
        | AcpClientMessageBox::ReleaseTerminal(_)
        | AcpClientMessageBox::WaitForTerminalExit(_)
        | AcpClientMessageBox::KillTerminalCommand(_)
        | AcpClientMessageBox::ExtMethod(_) => None,
    }
}

/// Report the unacknowledged prompt and ask the shell to rewind it, then hand back the exit error.
pub(super) async fn abort_unacknowledged_prompt(
    acp_tx: &AcpAgentTx,
    session_id: &acp::SessionId,
    prompt_id: &str,
    waited: Duration,
    deadlines: &PromptAckDeadlines,
) -> acp::Error {
    let waited_ms = waited.as_millis() as u64;
    let limit_ms = deadlines.hard.as_millis() as u64;
    tracing::warn!(
        prompt_id,
        waited_ms,
        limit_ms,
        "headless: the agent never acknowledged the prompt; aborting"
    );
    // Written directly: the buffered forwarder needs the very shell that stopped answering
    crate::unified_log::write_direct_warn(
        "prompt.ack_timeout",
        Some(session_id.0.as_ref()),
        Some(serde_json::json!({
            "prompt_id": prompt_id,
            "waited_ms": waited_ms,
            "limit_ms": limit_ms,
            "surface": "headless",
        })),
    );
    // A prompt that lands late is trimmed shell-side instead of running unobserved
    // Same shape the TUI cancel effect sends: rewind the prompt if it produced nothing
    let meta = serde_json::json!({
        "cancelSubagents": false,
        "rewindIfNoOutput": true,
        "rewindIfPristine": true,
        "promptId": prompt_id,
    });
    let cancel =
        acp::CancelNotification::new(session_id.clone()).meta(meta.as_object().cloned());
    match tokio::time::timeout(HEADLESS_ABORT_SEND_TIMEOUT, acp_send(cancel, acp_tx)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::warn!(%error, "headless: rewind cancel for the unacknowledged prompt failed");
        }
        Err(_elapsed) => {
            tracing::warn!("headless: rewind cancel for the unacknowledged prompt timed out");
        }
    }
    let limit_secs = deadlines.hard.as_secs();
    fuigo_acp_lib::acp_internal_error(format!(
        "{PROMPT_ACK_TIMEOUT_ERROR_PREFIX}: the agent did not acknowledge the prompt within {limit_secs}s"
    ))
}

#[cfg(test)]
#[path = "prompt_ack_tests.rs"]
mod tests;
