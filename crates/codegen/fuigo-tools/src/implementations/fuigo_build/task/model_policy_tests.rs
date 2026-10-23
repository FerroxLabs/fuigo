use super::*;
use crate::types::tool::ToolKind;
use serde_json::json;
use std::collections::HashMap;

fn task_schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(fuigo_tool_types::TaskToolInput)).unwrap()
}

fn definition(
    params: &serde_json::Value,
    param_map: &HashMap<String, String>,
) -> ToolDefinition {
    let renderer = TemplateRenderer::new(
        [(ToolKind::Task, "spawn_subagent".to_string())].into(),
        Default::default(),
    );
    task_versioned_definition(
        "spawn_subagent",
        Some("Start a subagent."),
        "unused template",
        &renderer,
        param_map,
        &task_schema(),
        params,
    )
}

fn properties(def: &ToolDefinition) -> Vec<String> {
    def.function.parameters["properties"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect()
}

#[test]
fn selectable_keeps_the_model_argument() {
    let def = definition(&json!({"model_selection": "selectable"}), &HashMap::new());
    assert!(properties(&def).contains(&"model".to_string()));
}

#[test]
fn inherited_leaves_the_model_argument_out_of_the_schema() {
    let def = definition(&json!({"model_selection": "inherited"}), &HashMap::new());
    let props = properties(&def);
    assert!(!props.contains(&"model".to_string()), "{props:?}");
    // Every other argument stays.
    for kept in ["prompt", "description", "run_in_background", "resume_from", "cwd"] {
        assert!(props.contains(&kept.to_string()), "{kept} missing from {props:?}");
    }
    let required = def.function.parameters["required"].as_array().cloned().unwrap_or_default();
    assert!(!required.iter().any(|name| name == "model"));
}

#[test]
fn inherited_schema_is_filtered_before_the_client_rename() {
    let map: HashMap<String, String> = [("model".to_string(), "llm".to_string())].into();
    let def = definition(&json!({"model_selection": "inherited"}), &map);
    let props = properties(&def);
    assert!(!props.contains(&"llm".to_string()) && !props.contains(&"model".to_string()), "{props:?}");
    let renamed = definition(&json!({"model_selection": "selectable"}), &map);
    assert!(properties(&renamed).contains(&"llm".to_string()));
}

#[test]
fn description_override_is_kept_under_inheritance() {
    let def = definition(&json!({"model_selection": "inherited"}), &HashMap::new());
    assert_eq!(def.function.description.as_deref(), Some("Start a subagent."));
}

#[test]
fn unparsable_params_keep_the_default_schema() {
    let def = definition(&json!({"model_selection": 7}), &HashMap::new());
    assert!(properties(&def).contains(&"model".to_string()));
}

#[test]
fn params_roundtrip_and_default_to_selectable() {
    assert_eq!(TaskParams::default().model_selection, TaskModelSelection::Selectable);
    let parsed: TaskParams = serde_json::from_value(json!({"model_selection": "inherited"})).unwrap();
    assert_eq!(parsed.model_selection, TaskModelSelection::Inherited);
    assert_eq!(
        serde_json::to_value(TaskParams::default()).unwrap(),
        json!({"model_selection": "selectable"})
    );
}

#[test]
fn hidden_selection_message_names_the_client_facing_argument() {
    let message = hidden_selection_message("llm");
    assert!(message.contains("without the llm argument"), "{message}");
}
