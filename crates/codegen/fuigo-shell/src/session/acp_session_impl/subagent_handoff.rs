//! A turn that ended (user stop, or a send-now message) while a foreground `task` call was blocked on its child.
//! The child is moved to the background and the call's tool result says so, instead of the generic
//! "the tool was not executed" that would make the model spawn it again.
use super::*;
use fuigo_tool_types::ForegroundSpawnInterrupt;
use fuigo_tools::bridge::BackgroundNoticeNames;
use fuigo_tools::implementations::fuigo_build::task::backend::ChannelBackend;
use std::collections::HashMap;

/// Upper bound on each coordinator round trip; a stalled coordinator must not hold up the cancel.
const HAND_OFF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

impl SessionActor {
    /// Hand off `prompt_id`'s foreground subagents and return the tool result text for each model `task` call
    /// (keyed by tool call id). Empty when there is nothing to hand off or the coordinator does not answer in time;
    /// the calls then keep the generic repair text.
    pub(super) async fn hand_off_foreground_subagents(
        &self,
        prompt_id: &str,
        interrupt: ForegroundSpawnInterrupt,
    ) -> HashMap<String, String> {
        let Some(event_tx) = self.tool_context.subagent_event_tx.clone() else {
            return HashMap::new();
        };
        let backend = ChannelBackend::for_session(event_tx, self.session_id_string());
        let handed_off = match tokio::time::timeout(
            HAND_OFF_TIMEOUT,
            backend.hand_off_foreground_for_prompt(prompt_id),
        )
        .await
        {
            Ok(handed_off) => handed_off,
            Err(_) => {
                tracing::warn!(
                    prompt_id,
                    "subagent coordinator did not answer the foreground handoff; keeping the generic cancel text"
                );
                return HashMap::new();
            }
        };
        if handed_off.is_empty() {
            return HashMap::new();
        }
        // The children are already backgrounded here; a slow resources lock must not cost the honest answers,
        // so fall back to the canonical names and under-promise on completion notices.
        let names = tokio::time::timeout(
            HAND_OFF_TIMEOUT,
            self.tool_bridge_handle().background_notice_naming(),
        )
        .await
        .unwrap_or_else(|_| {
            let canonical = fuigo_tool_types::BackgroundNoticeNaming::CANONICAL;
            BackgroundNoticeNames {
                task_output_tool: canonical.task_output_tool.to_owned(),
                task_ids_param: canonical.task_ids_param.to_owned(),
                timeout_ms_param: canonical.timeout_ms_param.to_owned(),
                notified_on_completion: false,
            }
        });
        let subagent_ids: Vec<&str> = handed_off.iter().map(|c| c.subagent_id.as_str()).collect();
        let tool_call_ids: Vec<&str> = handed_off.iter().map(|c| c.tool_call_id.as_str()).collect();
        let states: Vec<&str> = handed_off.iter().map(|c| c.state.as_str()).collect();
        fuigo_telemetry::unified_log::info(
            "shell.cancel.subagents_handed_off",
            Some(self.session_info.id.0.as_ref()),
            Some(serde_json::json!({
                "prompt_id": prompt_id,
                "subagent_ids": subagent_ids,
                "tool_call_ids": tool_call_ids,
                "states": states,
                "trigger": interrupt.as_str(),
            })),
        );
        handed_off
            .into_iter()
            .map(|child| {
                let text = fuigo_tool_types::format_subagent_backgrounded_on_turn_end(
                    &child.subagent_id,
                    &child.subagent_type,
                    &child.description,
                    &names.naming(),
                    interrupt,
                    child.state,
                    names.notified_on_completion,
                );
                (child.tool_call_id, text)
            })
            .collect()
    }
}
