//! The `mcp_tool` handler: call a tool on one of the session's configured MCP servers with the event, and read its text
//! result exactly as a command hook's stdout on exit 0.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use super::{GateKind, HookRunnerResult, RunContext};
use crate::config::HookSpec;
use crate::event::{HookEventEnvelope, clip_reason};

/// What an MCP tool sent back: its text content, joined, and whether it flagged the result as an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolReply {
    pub text: String,
    pub is_error: bool,
}

pub type McpCallFuture<'a> =
    Pin<Box<dyn Future<Output = Result<McpToolReply, String>> + Send + 'a>>;

/// The session's MCP client, as the hook runner sees it (the shell supplies it; no new connection is ever made).
pub trait McpToolCaller: Send + Sync {
    fn call<'a>(
        &'a self,
        server: &'a str,
        tool: &'a str,
        arguments: serde_json::Value,
    ) -> McpCallFuture<'a>;
}

pub async fn run_mcp_tool_hook(
    spec: &HookSpec,
    envelope: &HookEventEnvelope,
    ctx: &RunContext<'_>,
    mode: GateKind,
) -> (HookRunnerResult, Duration, Option<String>) {
    let start = Instant::now();
    let failed = |error: String| (HookRunnerResult::Failed(error), start.elapsed(), None);
    let Some(target) = spec.mcp_tool.as_ref() else {
        return failed("mcp_tool hook has no server and tool".to_string());
    };
    let Some(caller) = ctx.mcp.as_ref() else {
        return failed("no MCP client is available in this session".to_string());
    };
    let event = envelope.to_hook_json();
    let arguments = match &target.input {
        Some(input) => substitute(input, &event),
        None => event,
    };
    let call = caller.call(&target.server, &target.tool, arguments);
    let reply = match tokio::time::timeout(Duration::from_millis(spec.timeout_ms), call).await {
        Err(_) => return failed(format!("timed out after {}ms", spec.timeout_ms)),
        Ok(Err(error)) => {
            return failed(format!(
                "MCP tool {}:{} could not be called: {}",
                target.server,
                target.tool,
                clip_reason(&error)
            ));
        }
        Ok(Ok(reply)) => reply,
    };
    let elapsed = start.elapsed();
    if reply.is_error {
        return (
            HookRunnerResult::Failed(format!(
                "MCP tool {}:{} returned an error: {}",
                target.server,
                target.tool,
                clip_reason(&reply.text)
            )),
            elapsed,
            None,
        );
    }
    let system_message = super::extract_system_message(&reply.text);
    let (result, elapsed) =
        super::command::parse_hook_output(mode, envelope, &reply.text, "", 0, &spec.name, elapsed);
    let flaw = super::gate_output_flaw(mode, reply.text.as_bytes(), false, false);
    let result = super::enforce_fail_closed(spec, mode, result, flaw, None);
    (result, elapsed, system_message)
}

/// Fill every `${path}` in the input's string values from the event JSON (`tool_input.file_path`: dot-separated keys).
/// A string value is inserted as is, any other value as its JSON text, and a path that is not there as an empty string.
fn substitute(input: &serde_json::Value, event: &serde_json::Value) -> serde_json::Value {
    match input {
        serde_json::Value::String(text) => serde_json::Value::String(fill(text, event)),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(|item| substitute(item, event)).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), substitute(value, event)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn fill(text: &str, event: &serde_json::Value) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(open) = rest.find("${") {
        let Some(close) = rest[open + 2..].find('}') else {
            break;
        };
        out.push_str(&rest[..open]);
        let path = &rest[open + 2..open + 2 + close];
        match path.split('.').try_fold(event, |value, key| value.get(key)) {
            Some(serde_json::Value::String(value)) => out.push_str(value),
            Some(value) => out.push_str(&value.to_string()),
            None => {}
        }
        rest = &rest[open + 3 + close..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::HookDecision;
    use std::sync::{Arc, Mutex};

    /// Answers every call with `reply` and records what it was asked.
    struct FakeMcp {
        reply: Result<McpToolReply, String>,
        calls: Mutex<Vec<(String, String, serde_json::Value)>>,
    }

    impl McpToolCaller for FakeMcp {
        fn call<'a>(
            &'a self,
            server: &'a str,
            tool: &'a str,
            arguments: serde_json::Value,
        ) -> McpCallFuture<'a> {
            self.calls
                .lock()
                .unwrap()
                .push((server.into(), tool.into(), arguments));
            let reply = self.reply.clone();
            Box::pin(async move { reply })
        }
    }

    fn fake(text: &str, is_error: bool) -> Arc<FakeMcp> {
        Arc::new(FakeMcp {
            reply: Ok(McpToolReply {
                text: text.into(),
                is_error,
            }),
            calls: Mutex::new(Vec::new()),
        })
    }

    async fn pre_tool_use(
        mcp: Option<Arc<FakeMcp>>,
        input: Option<serde_json::Value>,
    ) -> crate::dispatcher::PreToolUseResult {
        let json = serde_json::json!({ "hooks": { "PreToolUse": [ { "hooks": [{
            "type": "mcp_tool", "server": "guard", "tool": "check", "input": input
        }] } ] } });
        let (specs, errors) = crate::config::parse_hook_file(
            &json.to_string(),
            std::path::Path::new("/tmp/mcp.json"),
        );
        assert!(errors.is_empty(), "{errors:?}");
        let (mut registry, _) = crate::discovery::load_hooks(None, None);
        registry.append_specs(specs);
        let envelope = HookEventEnvelope {
            hook_event_name: crate::event::HookEventName::PreToolUse,
            session_id: "mcp-session".into(),
            cwd: "/tmp".into(),
            workspace_root: "/tmp".into(),
            timestamp: "2025-01-01T00:00:00Z".into(),
            transcript_path: None,
            client_identifier: None,
            prompt_id: None,
            permission_mode: None,
            payload: crate::event::HookPayload::PreToolUse {
                tool_name: "run_terminal_cmd".into(),
                tool_use_id: "tu-1".into(),
                tool_input: serde_json::json!({ "command": "rm -rf /" }),
                tool_input_truncated: false,
                subagent_type: None,
                origin: None,
                peer_influenced: None,
            },
        };
        let ctx = RunContext {
            session_id: "mcp-session",
            workspace_root: "/tmp",
            process_scope: None,
            mcp: mcp.map(|m| m as Arc<dyn McpToolCaller>),
        };
        crate::dispatcher::dispatch_pre_tool_use(&registry, &envelope, &ctx).await
    }

    #[tokio::test]
    async fn the_tool_result_is_the_hook_output() {
        let mcp = fake(
            r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"blocked by scan"}}"#,
            false,
        );
        let result = pre_tool_use(
            Some(mcp.clone()),
            Some(serde_json::json!({ "cmd": "${tool_input.command}" })),
        )
        .await;
        assert!(matches!(
            result.decision,
            HookDecision::Deny { ref reason, .. } if reason == "blocked by scan"
        ));
        let calls = mcp.calls.lock().unwrap();
        assert_eq!(
            calls[0],
            (
                "guard".to_string(),
                "check".to_string(),
                serde_json::json!({ "cmd": "rm -rf /" })
            )
        );
    }

    #[tokio::test]
    async fn without_input_the_tool_gets_the_event_json() {
        let mcp = fake("", false);
        let result = pre_tool_use(Some(mcp.clone()), None).await;
        assert_eq!(result.decision, HookDecision::Allow);
        let calls = mcp.calls.lock().unwrap();
        assert_eq!(calls[0].2["hook_event_name"], "PreToolUse");
        assert_eq!(calls[0].2["tool_input"]["command"], "rm -rf /");
    }

    #[tokio::test]
    async fn an_error_result_or_no_client_fails_open() {
        let error = fake(
            r#"{"hookSpecificOutput":{"permissionDecision":"deny"}}"#,
            true,
        );
        let result = pre_tool_use(Some(error), None).await;
        assert_eq!(result.decision, HookDecision::Allow);
        assert!(matches!(
            result.results[0],
            crate::result::HookRunResult::Failed { ref error, .. } if error.contains("returned an error")
        ));
        let unreachable = Arc::new(FakeMcp {
            reply: Err("server 'guard' not found".into()),
            calls: Mutex::new(Vec::new()),
        });
        assert_eq!(
            pre_tool_use(Some(unreachable), None).await.decision,
            HookDecision::Allow
        );
        assert_eq!(pre_tool_use(None, None).await.decision, HookDecision::Allow);
    }

    #[test]
    fn substitute_fills_paths_from_the_event() {
        let event = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_input": { "file_path": "/a.rs", "limit": 3 }
        });
        let input = serde_json::json!({
            "file_path": "${tool_input.file_path}",
            "note": "${hook_event_name} on ${tool_input.file_path} x${tool_input.limit}${missing.key}",
            "keep": 7,
            "list": ["${tool_input.limit}"],
            "open": "${unclosed"
        });
        assert_eq!(
            substitute(&input, &event),
            serde_json::json!({
                "file_path": "/a.rs",
                "note": "PreToolUse on /a.rs x3",
                "keep": 7,
                "list": ["3"],
                "open": "${unclosed"
            })
        );
    }
}
