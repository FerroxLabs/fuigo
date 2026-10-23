//! Presentation policy for the model-facing `model` argument of the task tool.
//!
//! A session can lock its subagents to the parent model ([`TaskModelSelection::Inherited`]). The schema then leaves
//! the `model` argument out, the description stops offering model slugs, and a call that names a model anyway is
//! refused with [`hidden_selection_message`] before any child work starts.

use crate::types::definition::ToolDefinition;
use crate::types::template_renderer::TemplateRenderer;

/// Canonical name of the model argument, before any client parameter remapping.
pub const MODEL_PARAM: &str = "model";

/// Whether the model may pick a child model explicitly or every child inherits the parent model.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskModelSelection {
    #[default]
    Selectable,
    Inherited,
}

/// Task tool configuration, stored as `Params<TaskParams>`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaskParams {
    #[serde(default)]
    pub model_selection: TaskModelSelection,
}

crate::register_resource!("fuigo_build", "TaskParams", TaskParams);

/// `ToolMetadata::versioned_definition` for the task tool, over the schema filtered by `TaskParams`.
pub fn task_versioned_definition(
    client_name: &str,
    description_override: Option<&str>,
    description_template: &str,
    renderer: &TemplateRenderer,
    param_map: &std::collections::HashMap<String, String>,
    input_schema: &serde_json::Value,
    effective_params: &serde_json::Value,
) -> ToolDefinition {
    let raw_desc = description_override.unwrap_or(description_template);
    let description = renderer.render(raw_desc).unwrap_or_else(|e| {
        crate::types::template_renderer::strip_markers_on_render_failure(raw_desc, &e)
    });
    let exported = exported_input_schema(input_schema, &task_params_from(effective_params));
    let remapped = if param_map.is_empty() {
        exported
    } else {
        crate::util::remap::remap_schema_properties(&exported, param_map)
    };
    ToolDefinition::function(client_name, Some(&description), remapped)
}

/// Finalize validated the params before merging, so a parse failure here only logs.
fn task_params_from(effective_params: &serde_json::Value) -> TaskParams {
    match serde_json::from_value::<TaskParams>(effective_params.clone()) {
        Ok(params) => params,
        Err(error) => {
            tracing::warn!(%error, "task params did not parse; keeping the default task schema");
            TaskParams::default()
        }
    }
}

/// Runs before parameter remapping. Its keys are the canonical names.
fn exported_input_schema(input_schema: &serde_json::Value, params: &TaskParams) -> serde_json::Value {
    let mut schema = input_schema.clone();
    let Some(obj) = schema.as_object_mut() else {
        return schema;
    };
    if params.model_selection == TaskModelSelection::Inherited {
        if let Some(props) = obj.get_mut("properties").and_then(|p| p.as_object_mut()) {
            props.remove(MODEL_PARAM);
        }
        if let Some(required) = obj.get_mut("required").and_then(|r| r.as_array_mut()) {
            required.retain(|name| name.as_str() != Some(MODEL_PARAM));
        }
    }
    schema
}

/// `param_name` is the client-facing spelling.
pub fn hidden_selection_message(param_name: &str) -> String {
    format!(
        "Explicit subagent model selection is unavailable in this session: subagents use the parent model. \
         Retry without the {param_name} argument."
    )
}

#[cfg(test)]
#[path = "model_policy_tests.rs"]
mod tests;
