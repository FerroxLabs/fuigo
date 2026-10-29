//! The Chat Completions request that carries MCP tools: a real `SamplingClient` dispatch against a local mock records
//! the body actually sent. Strict providers reject an MCP schema that lacks a root `type`, an object's `properties`
//! or an array's `items`; the wire body must carry those, and built-in tools must stay byte-identical.

use fuigo_sampler::{SamplerConfig, SamplingClient};
use fuigo_sampling_types::{ConversationItem, ConversationRequest, ToolSpec};
use fuigo_test_support::{MockInferenceServer, ScriptedResponse};
use serde_json::{Value, json};

fn spec(name: &str, parameters: Value) -> ToolSpec {
    ToolSpec {
        name: name.to_owned(),
        description: None,
        parameters,
        freeform: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chat_completions_wire_body_completes_mcp_schemas_only() {
    let gappy = json!({
        "properties": {
            "opts": {"type": "object"},
            "ids": {"type": "array"},
            "target": {"$ref": "#/$defs/T"},
            "pair": {"type": "array", "items": [{"type": "number"}]}
        },
        "$defs": {"T": {"type": "string"}}
    });
    let server = MockInferenceServer::start().await.expect("start mock");
    server.enqueue_response(
        "/v1/chat/completions",
        ScriptedResponse::text(
            400,
            r#"{"error":{"message":"stop","type":"invalid_request_error"}}"#,
        ),
    );
    let cfg = SamplerConfig {
        api_key: Some("test-key".to_owned()),
        base_url: server.url(),
        model: "test-model".to_owned(),
        max_retries: Some(0),
        ..SamplerConfig::default()
    };
    let client = SamplingClient::new(cfg).expect("client");
    let request =
        ConversationRequest::from_items(vec![ConversationItem::user("go")]).with_tools(vec![
            spec("srv__lookup", gappy.clone()),
            spec("Builtin", gappy.clone()),
        ]);
    let _ = client.conversation_stream(request).await;

    let bodies = server.request_bodies();
    let tools = bodies
        .iter()
        .find_map(|b| b.get("tools"))
        .and_then(Value::as_array)
        .expect("chat request carried tools");
    let params = |name: &str| {
        tools
            .iter()
            .find(|t| t["function"]["name"] == name)
            .map(|t| t["function"]["parameters"].clone())
            .expect("tool on the wire")
    };
    let mcp = params("srv__lookup");
    assert_eq!(mcp["type"], "object");
    assert_eq!(
        mcp["properties"]["opts"],
        json!({"type": "object", "properties": {}})
    );
    assert_eq!(
        mcp["properties"]["ids"],
        json!({"type": "array", "items": {}})
    );
    assert_eq!(mcp["properties"]["target"], gappy["properties"]["target"]);
    assert_eq!(mcp["properties"]["pair"], gappy["properties"]["pair"]);
    assert_eq!(params("Builtin"), gappy);
}
