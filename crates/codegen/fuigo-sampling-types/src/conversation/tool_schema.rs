//! Additive completion of MCP tool input schemas for the Chat Completions path.
//!
//! Strict Chat Completions validators reject a schema whose root lacks `type: "object"`, an object node without
//! `properties`, and an array node without `items`. This pass fills in exactly those three gaps and nothing else:
//! it never resolves, inlines, merges, deletes or reorders anything, so `$ref`, unions, tuples, booleans and nulls
//! are left as published. It is applied to MCP tools on the Chat Completions request path only.

use serde_json::{Map, Value, json};

const MAX_DEPTH: usize = 64;

/// MCP tools are advertised as `server__tool`. Built-in tool names (registry tools, `StructuredOutput`, the
/// `__fuigo_ptc_*` carriers, which start with the delimiter) never carry an interior `__`.
pub(crate) fn is_mcp_tool_name(name: &str) -> bool {
    name.find(fuigo_workspace_types::MCP_TOOL_NAME_DELIMITER)
        .is_some_and(|i| i > 0)
}

fn fallback() -> Value {
    json!({"type": "object", "properties": {}})
}

/// Fill in the missing `type`/`properties`/`items` of one MCP tool's input schema. Infallible: a non-object root or
/// pathological nesting yields an empty object schema with a warn log (the tool is never dropped).
pub(crate) fn complete_mcp_tool_schema(tool: &str, mut schema: Value) -> Value {
    let Some(root) = schema.as_object_mut() else {
        tracing::warn!(
            tool,
            "MCP tool schema is not an object; using an empty object schema"
        );
        return fallback();
    };
    // `items: {}` evaluates every remaining element, which would disable an `unevaluatedItems` restriction anywhere
    // in the tool's schema (adjacent, or through `allOf`/`$ref`), so items are never synthesised for such a tool.
    let Ok(synth_items) = mentions_unevaluated_items(root, 0).map(|m| !m) else {
        tracing::warn!(
            tool,
            "MCP tool schema is nested too deeply; using an empty object schema"
        );
        return fallback();
    };
    root.entry("type").or_insert_with(|| json!("object"));
    if walk_node(root, 0, synth_items).is_err() {
        tracing::warn!(
            tool,
            "MCP tool schema is nested too deeply; using an empty object schema"
        );
        return fallback();
    }
    schema
}

/// The schema-valued children of `node`, by keyword position only (never `enum`/`const`/`default`/`examples` data
/// and never property names).
fn schema_children(node: &mut Map<String, Value>) -> Vec<&mut Value> {
    let mut out = Vec::new();
    for (key, value) in node.iter_mut() {
        match key.as_str() {
            // One schema.
            "additionalProperties"
            | "additionalItems"
            | "not"
            | "contains"
            | "if"
            | "then"
            | "else"
            | "propertyNames"
            | "unevaluatedItems"
            | "unevaluatedProperties" => out.push(value),
            // One schema or a tuple of schemas.
            "items" => match value {
                Value::Array(a) => out.extend(a.iter_mut()),
                v => out.push(v),
            },
            // A list of schemas.
            "prefixItems" | "anyOf" | "oneOf" | "allOf" => {
                if let Value::Array(a) = value {
                    out.extend(a.iter_mut());
                }
            }
            // A map of name -> schema (names are never treated as keywords).
            "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas"
            | "dependencies" => {
                if let Value::Object(m) = value {
                    out.extend(m.values_mut());
                }
            }
            _ => {}
        }
    }
    out
}

fn mentions_unevaluated_items(node: &mut Map<String, Value>, depth: usize) -> Result<bool, ()> {
    if depth > MAX_DEPTH {
        return Err(());
    }
    if node.contains_key("unevaluatedItems") {
        return Ok(true);
    }
    for child in schema_children(node) {
        if let Value::Object(m) = child
            && mentions_unevaluated_items(m, depth + 1)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn walk_node(node: &mut Map<String, Value>, depth: usize, synth_items: bool) -> Result<(), ()> {
    if depth > MAX_DEPTH {
        return Err(());
    }
    let is_object = match node.get("type") {
        Some(Value::String(t)) => t == "object",
        Some(_) => false,
        None => node.contains_key("properties") || node.contains_key("required"),
    };
    if is_object {
        node.entry("properties").or_insert_with(|| json!({}));
    }
    if synth_items
        && node.get("type").and_then(Value::as_str) == Some("array")
        && !node.contains_key("prefixItems")
    {
        node.entry("items").or_insert_with(|| json!({}));
    }
    for child in schema_children(node) {
        if let Value::Object(m) = child {
            walk_node(m, depth + 1, synth_items)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fix(v: Value) -> Value {
        complete_mcp_tool_schema("srv__tool", v)
    }

    fn assert_unchanged(v: Value) {
        let out = fix(v.clone());
        assert_eq!(
            serde_json::to_string(&out).unwrap(),
            serde_json::to_string(&v).unwrap()
        );
    }

    fn untouched_fixtures() -> Vec<Value> {
        vec![
            json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "limit": {"type": "integer", "minimum": 1},
                    "mode": {"type": "string", "enum": ["a", "b"]},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "opts": {"type": "object", "properties": {"deep": {"type": "boolean"}},
                             "required": ["deep"], "additionalProperties": false}
                },
                "required": ["path"],
                "additionalProperties": false
            }),
            // `unevaluatedItems` restrictions must survive: no `items` is synthesised next to or around them.
            json!({"type": "object", "properties": {
                "t": {"type": "array", "prefixItems": [{"type": "number"}], "unevaluatedItems": false},
                "u": {"type": "array", "prefixItems": [{"type": "number"}]}}}),
            json!({"type": "object", "allOf": [{"unevaluatedItems": false}],
                   "properties": {"l": {"type": "array", "allOf": [{"prefixItems": [{"type": "number"}]}]}}}),
            // Tuples, allOf, $ref/$defs, unions, booleans, nulls: all left exactly as published.
            json!({
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "properties": {
                    "pair": {"type": "array", "items": [{"type": "number"}, {"type": "string"}]},
                    "pos": {"type": "array", "prefixItems": [{"type": "number"}], "items": false},
                    "ref": {"$ref": "#/$defs/Target", "description": "where"},
                    "all": {"allOf": [{"type": "object", "properties": {"a": {"type": "string"}}}, {"required": ["a"], "properties": {"b": true}}]},
                    "opt": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "multi": {"type": ["string", "null"]},
                    "any": true,
                    "never": false,
                    "nil": null,
                    "dflt": {"type": "string", "default": null, "enum": ["x", null]}
                },
                "additionalProperties": true,
                "$defs": {"Target": {"type": "object", "properties": {"id": {"type": "string"}}}}
            }),
        ]
    }

    #[test]
    fn clean_and_non_additive_schemas_are_byte_identical() {
        for f in untouched_fixtures() {
            assert_unchanged(f);
        }
    }

    #[test]
    fn root_without_type_gets_object_and_properties() {
        assert_eq!(fix(json!({})), json!({"type": "object", "properties": {}}));
        assert_eq!(
            fix(json!({"properties": {"a": {"type": "string"}}})),
            json!({"properties": {"a": {"type": "string"}}, "type": "object"})
        );
        assert_eq!(fix(json!({"required": ["a"]}))["properties"], json!({}));
    }

    #[test]
    fn object_without_properties_gets_empty_properties() {
        let out = fix(json!({"type": "object", "properties": {
            "o": {"type": "object"},
            "r": {"required": ["x"]},
            "deep": {"type": "object", "properties": {"in": {"type": "object", "description": "d"}}}
        }}));
        assert_eq!(
            out["properties"]["o"],
            json!({"type": "object", "properties": {}})
        );
        assert_eq!(
            out["properties"]["r"],
            json!({"required": ["x"], "properties": {}})
        );
        assert_eq!(
            out["properties"]["deep"]["properties"]["in"]["properties"],
            json!({})
        );
    }

    #[test]
    fn array_without_items_gets_empty_items() {
        let out = fix(json!({"type": "object", "properties": {
            "list": {"type": "array"},
            "nested": {"type": "array", "items": {"type": "array"}}
        }}));
        assert_eq!(
            out["properties"]["list"],
            json!({"type": "array", "items": {}})
        );
        assert_eq!(
            out["properties"]["nested"]["items"],
            json!({"type": "array", "items": {}})
        );
    }

    #[test]
    fn every_schema_bearing_keyword_is_traversed() {
        let bare = || json!({"type": "object"});
        let out = fix(json!({
            "type": "object",
            "properties": {"p": bare()},
            "patternProperties": {"^x": bare()},
            "additionalProperties": bare(),
            "$defs": {"d": bare()},
            "definitions": {"e": bare()},
            "anyOf": [bare()], "oneOf": [bare()], "allOf": [bare()],
            "not": bare(), "contains": bare(), "if": bare(), "then": bare(), "else": bare(),
            "dependentSchemas": {"k": bare()},
            "prefixItems": [bare()],
            "items": [bare()]
        }));
        let want = json!({"type": "object", "properties": {}});
        for ptr in [
            "/properties/p",
            "/patternProperties/^x",
            "/additionalProperties",
            "/$defs/d",
            "/definitions/e",
            "/anyOf/0",
            "/oneOf/0",
            "/allOf/0",
            "/not",
            "/contains",
            "/if",
            "/then",
            "/else",
            "/dependentSchemas/k",
            "/prefixItems/0",
            "/items/0",
        ] {
            assert_eq!(out.pointer(ptr), Some(&want), "{ptr}");
        }
    }

    #[test]
    fn property_names_and_values_are_not_mistaken_for_keywords() {
        // A property literally called "type"/"items" is a name, and enum/default payloads are data.
        assert_unchanged(json!({"type": "object", "properties": {
            "type": {"type": "string"}, "items": {"type": "string"}, "properties": {"type": "string"}},
            "default": {"type": "object"}, "examples": [{"type": "array"}]}));
    }

    #[test]
    fn unevaluated_items_in_key_position_only_disables_items_synthesis() {
        // Mentioned as data (default/enum/const/examples) or as a property name: items are still synthesised.
        let out = fix(json!({"type": "object", "properties": {
            "unevaluatedItems": {"type": "string"}, "l": {"type": "array"}},
            "default": {"unevaluatedItems": false}, "examples": [{"unevaluatedItems": false}]}));
        assert_eq!(out["properties"]["l"]["items"], json!({}));
        // Objects still get `properties` in a tool that disables items synthesis.
        let out = fix(
            json!({"unevaluatedItems": false, "properties": {"o": {"type": "object"}, "l": {"type": "array"}}}),
        );
        assert_eq!(out["properties"]["o"]["properties"], json!({}));
        assert!(out["properties"]["l"].get("items").is_none());
    }

    #[test]
    fn pass_is_idempotent_over_all_fixtures() {
        let mut all = untouched_fixtures();
        all.push(json!({"properties": {"o": {"type": "object"}, "l": {"type": "array"}}, "$defs": {"X": {"type": "array"}}}));
        all.push(json!({}));
        for f in all {
            let once = fix(f);
            assert_eq!(fix(once.clone()), once);
        }
    }

    #[test]
    fn non_object_root_and_pathological_depth_fall_back() {
        for bad in [json!(null), json!("s"), json!(true), json!([1])] {
            assert_eq!(fix(bad), fallback());
        }
        let mut deep = json!({"type": "string"});
        for _ in 0..(MAX_DEPTH + 8) {
            deep = json!({"type": "object", "properties": {"x": deep}});
        }
        assert_eq!(fix(deep), fallback());
        // Reasonable nesting is fine.
        let mut ok = json!({"type": "object"});
        for _ in 0..20 {
            ok = json!({"type": "object", "properties": {"x": ok}});
        }
        assert_ne!(fix(ok), fallback());
    }

    #[test]
    fn mcp_names_are_recognised_by_an_interior_delimiter() {
        assert!(is_mcp_tool_name("github__create_issue"));
        assert!(!is_mcp_tool_name("read_file"));
        assert!(!is_mcp_tool_name("StructuredOutput"));
        assert!(!is_mcp_tool_name("__fuigo_ptc_program"));
    }
}
