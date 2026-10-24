use super::*;
use fuigo_hooks::dispatcher::{
    AdditionalContext, OutputReplacement, PostToolUseBlock, PostToolUseResult, RejectedReplacement, ReplacementChoice, ReplacementKind,
    SelectedReplacement,
};
use fuigo_hooks::event::{MAX_HOOK_OUTPUT_REPLACEMENT_CHARS, clip_text};
use fuigo_hooks::result::HookRunResult;

#[derive(Debug, Default, PartialEq)]
pub(super) struct PostToolUseDelivery {
    pub model_output: Option<String>,
    pub additional_context: Vec<AdditionalContext>,
    pub blocks: Vec<PostToolUseBlock>,
    /// A hook answered `continue: false`: the turn ends after this tool call.
    pub stop: Option<fuigo_hooks::dispatcher::PostToolUseStop>,
}

pub(super) fn plan_post_tool_use_delivery(
    mut result: PostToolUseResult,
    output: &ToolsToolOutput,
    reminder_tag: &str,
    results: &mut [HookRunResult],
) -> PostToolUseDelivery {
    let tool_kind = if matches!(output, ToolsToolOutput::MCP(_)) {
        ReplacementKind::Mcp
    } else {
        ReplacementKind::Builtin
    };
    let ReplacementChoice { chosen, rejected } = result.take_replacement(tool_kind);
    let (model_output, unrendered) = post_tool_use_model_output(chosen, output, reminder_tag);
    for rejection in rejected.into_iter().chain(unrendered) {
        downgrade_run(results, rejection);
    }
    PostToolUseDelivery {
        model_output,
        additional_context: result.additional_context,
        blocks: result.blocks,
        stop: result.force_stop,
    }
}

fn downgrade_run(results: &mut [HookRunResult], rejection: RejectedReplacement) {
    let RejectedReplacement { hook_name: rejected_hook, run_index, reason } = rejection;
    tracing::warn!(
        hook_name = %rejected_hook,
        reason = %reason,
        "post_tool_use output replacement rejected; the model keeps the tool's output"
    );
    if let Some(slot) = results.get_mut(run_index)
        && let HookRunResult::Success {
            hook_name,
            elapsed,
            http_info,
            system_message,
        } = slot
    {
        *slot = HookRunResult::Failed {
            hook_name: hook_name.clone(),
            error: reason,
            elapsed: *elapsed,
            http_info: http_info.clone(),
            system_message: system_message.clone(),
        };
    }
}

fn post_tool_use_model_output(
    selected: Option<SelectedReplacement>,
    output: &ToolsToolOutput,
    reminder_tag: &str,
) -> (Option<String>, Option<RejectedReplacement>) {
    let Some(SelectedReplacement {
        replacement,
        run_index,
    }) = selected
    else {
        return (None, None);
    };
    let rejected_hook = replacement.hook_name.clone();
    match post_tool_use_rendered_replacement(replacement, output) {
        RenderedReplacement::Replace {
            hook_name,
            rendered,
        } => {
            if rendered.trim().is_empty() {
                tracing::warn!(
                    hook_name = %hook_name,
                    "post_tool_use output replacement renders empty"
                );
            }
            (
                Some(super::reminders::escape_reminder_tags(
                    &rendered,
                    reminder_tag,
                )),
                None,
            )
        }
        RenderedReplacement::Rejected { reason } => (
            None,
            Some(RejectedReplacement { hook_name: rejected_hook, run_index, reason }),
        ),
    }
}

enum RenderedReplacement {
    Replace { hook_name: String, rendered: String },
    Rejected { reason: String },
}

fn post_tool_use_rendered_replacement(
    replacement: OutputReplacement,
    output: &ToolsToolOutput,
) -> RenderedReplacement {
    let OutputReplacement {
        hook_name, value, ..
    } = replacement;

    if matches!(output, ToolsToolOutput::MCP(_)) {
        let rendered = match value {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        };
        return RenderedReplacement::Replace {
            hook_name,
            rendered: clip_text(&rendered, MAX_HOOK_OUTPUT_REPLACEMENT_CHARS),
        };
    }

    match serde_json::from_value::<ToolsToolOutput>(value) {
        Ok(candidate) if std::mem::discriminant(&candidate) == std::mem::discriminant(output) => {
            RenderedReplacement::Replace {
                hook_name,
                rendered: clip_text(
                    &candidate.to_prompt_format(),
                    MAX_HOOK_OUTPUT_REPLACEMENT_CHARS,
                ),
            }
        }
        Ok(_) => {
            tracing::warn!(
                hook_name = %hook_name,
                "post_tool_use updatedToolOutput does not match the tool's output shape; keeping original"
            );
            RenderedReplacement::Rejected {
                reason: "updatedToolOutput does not match the tool's output shape".to_string(),
            }
        }
        Err(err) => {
            tracing::warn!(
                hook_name = %hook_name,
                %err,
                "post_tool_use updatedToolOutput failed to parse; keeping original"
            );
            RenderedReplacement::Rejected {
                reason: format!("updatedToolOutput failed to parse: {err}"),
            }
        }
    }
}

pub(super) fn substitute_rendered_output(
    prompt_text: &str,
    output: &ToolsToolOutput,
    replacement: String,
) -> String {
    let original = output.to_prompt_format();
    if original.is_empty() {
        return if prompt_text.is_empty() {
            replacement
        } else {
            format!("{replacement}\n\n{prompt_text}")
        };
    }
    match prompt_text.strip_prefix(&original) {
        Some(reminders) => format!("{replacement}{reminders}"),
        None => {
            tracing::warn!(
                "post_tool_use replacement: tool prompt did not start with its own output; dropping reminders"
            );
            debug_assert!(false, "tool prompt text did not start with its own output");
            replacement
        }
    }
}

#[cfg(test)]
#[path = "post_tool_use_delivery_tests.rs"]
mod tests;
