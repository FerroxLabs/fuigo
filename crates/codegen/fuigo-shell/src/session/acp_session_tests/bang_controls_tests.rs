//! `!` shell lines obey admin denials and never prompt (decision 40, bang-controls).
//! Each test drives `handle_direct_bash_command` on a real actor, a real permission manager and real command hooks.

use super::support::*;
use super::*;
use fuigo_workspace::permission::PermissionConfig;
use fuigo_workspace::permission::types::{PatternMode, PermissionRule, PromptPolicy, RuleAction, ToolFilter};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct CountingTerminal {
    commands: Arc<std::sync::Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl crate::terminal::AsyncTerminalRunner for CountingTerminal {
    async fn run(
        &self,
        request: crate::terminal::runner::TerminalRunRequest,
    ) -> Result<crate::terminal::runner::TerminalRunResult, crate::terminal::runner::TerminalError>
    {
        self.commands.lock().unwrap().push(request.command);
        Ok(crate::terminal::runner::TerminalRunResult {
            combined_output: "ok".into(),
            exit_code: Some(0),
            truncated: false,
            signal: None,
            timed_out: false,
        })
    }
}

/// `BashOutput::output` travels as a JSON array of byte values; append its text so a test can read what the user sees.
fn decode_output_bytes(json: &str) -> String {
    fn walk(v: &serde_json::Value, out: &mut String) {
        match v {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::Array(bytes)) = map.get("output") {
                    let raw: Vec<u8> = bytes.iter().filter_map(|b| b.as_u64().map(|n| n as u8)).collect();
                    out.push_str(&format!("\n[output] {}", String::from_utf8_lossy(&raw)));
                }
                map.values().for_each(|c| walk(c, out));
            }
            serde_json::Value::Array(items) => items.iter().for_each(|c| walk(c, out)),
            _ => {}
        }
    }
    let mut out = json.to_owned();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(json) {
        walk(&value, &mut out);
    }
    out
}

struct Harness {
    actor: SessionActor,
    commands: Arc<std::sync::Mutex<Vec<String>>>,
    prompts: Arc<AtomicUsize>,
    seen: Arc<std::sync::Mutex<Vec<String>>>,
}

fn rule(action: RuleAction, tool: ToolFilter, pattern: Option<&str>) -> PermissionRule {
    PermissionRule {
        action,
        tool,
        pattern: pattern.map(str::to_owned),
        pattern_mode: PatternMode::Glob,
    }
}

fn prompt_submit_spec(name: &str, script: &str) -> fuigo_hooks::config::HookSpec {
    fuigo_hooks::config::HookSpec {
        event: fuigo_hooks::event::HookEventName::UserPromptSubmit,
        ..pre_tool_use_spec(name, None, script)
    }
}

async fn harness(
    config: Option<PermissionConfig>,
    specs: Vec<fuigo_hooks::config::HookSpec>,
) -> Harness {
    let (gateway_tx, mut gateway_rx) = tokio::sync::mpsc::unbounded_channel();
    let (persistence_tx, persistence_rx) = tokio::sync::mpsc::unbounded_channel();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let persisted = seen.clone();
    super::disk_full_tests::spawn_persistence_stub_observing(persistence_rx, || Ok(()), move |message| {
        if let PersistenceMsg::Update(crate::session::storage::SessionUpdate::Acp(n)) = message {
            let text = serde_json::to_string(&**n).unwrap_or_default();
            persisted.lock().unwrap().push(decode_output_bytes(&text));
        }
    });
    let commands = Arc::new(std::sync::Mutex::new(Vec::new()));
    let terminal = Arc::new(CountingTerminal { commands: commands.clone() });
    let hook_gateway = fuigo_acp_lib::AcpAgentGatewaySender::new(gateway_tx.clone());
    let (mut actor, _ev) =
        create_test_actor_with_terminal(0, 256_000, 85, gateway_tx, persistence_tx, terminal).await;
    let prompts = Arc::new(AtomicUsize::new(0));
    let (p, s) = (prompts.clone(), seen.clone());
    tokio::task::spawn_local(async move {
        while let Some(msg) = gateway_rx.recv().await {
            match msg {
                fuigo_acp_lib::AcpClientMessage::RequestPermission(args) => {
                    p.fetch_add(1, Ordering::SeqCst);
                    let _ = args.response_tx.send(Ok(acp::RequestPermissionResponse::new(
                        acp::RequestPermissionOutcome::Cancelled,
                    )));
                }
                fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                    let text = serde_json::to_string(&args.request).unwrap_or_default();
                    s.lock().unwrap().push(decode_output_bytes(&text));
                    let _ = args.response_tx.send(Ok(()));
                }
                fuigo_acp_lib::AcpClientMessage::ExtNotification(args) => {
                    s.lock().unwrap().push(decode_output_bytes(args.request.params.get()));
                }
                _ => {}
            }
        }
    });
    {
        use fuigo_paths::AbsPathBuf;
        let cwd = AbsPathBuf::new(std::path::PathBuf::from(actor.session_info.cwd.clone()))
            .unwrap_or_else(|_| AbsPathBuf::new(crate::test_support::abs_tmp()).unwrap());
        let (handle, _ev) = fuigo_workspace::permission::spawn_permission_manager(
            actor.session_info.id.clone(),
            hook_gateway,
            cwd,
            fuigo_workspace::permission::ClientType::Generic,
            config,
            vec![],
            vec![],
            false,
            None,
        );
        actor.permissions = handle;
    }
    if !specs.is_empty() {
        install_pre_tool_use_hooks(&mut actor, specs);
    }
    Harness { actor, commands, prompts, seen }
}

impl Harness {
    async fn bang(&self, command: &str) {
        let blocks = [acp::ContentBlock::Text(acp::TextContent::new(format!("!{command}")))];
        let result = self.actor.handle_direct_bash_command("bang-1", command.to_owned(), &blocks).await;
        assert!(result.is_ok(), "the turn must end normally: {result:?}");
    }
    fn ran(&self) -> Vec<String> {
        self.commands.lock().unwrap().clone()
    }
    /// The one refusal line the user sees (what `bang_refusal` returns), or "" when nothing refuses.
    async fn refusal(&self, command: &str) -> String {
        let input = fuigo_tools::types::ToolInput::Bash(fuigo_tools::implementations::BashToolInput {
            command: command.to_owned(),
            timeout: None,
            description: command.to_owned(),
            is_background: false,
            block_until_ms: None,
            workdir: None,
        });
        self.actor
            .bang_refusal("bang-1", command, &acp::ToolCallId::from("bash-mode-t"), "Bash", &input)
            .await
            .unwrap_or_default()
    }
    async fn model_items(&self) -> String {
        format!("{:?}", self.actor.chat_state_handle.get_conversation().await)
    }
}

macro_rules! local_test {
    ($name:ident, $body:expr) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() {
            let local = tokio::task::LocalSet::new();
            local.run_until(async { $body.await }).await;
        }
    };
}

local_test!(no_rule_no_hook_runs_as_before, async {
    let h = harness(None, vec![]).await;
    h.bang("echo hi").await;
    assert_eq!(h.ran(), vec!["echo hi".to_owned()]);
    let items = h.model_items().await;
    assert!(
        items.contains("I executed a terminal command: `echo hi`\\n\\nOutput:\\n```\\nok\\n```"),
        "{items}"
    );
    assert_eq!(h.refusal("echo hi").await, "", "nothing objects, nothing refuses");
    assert_eq!(h.prompts.load(Ordering::SeqCst), 0);
});

local_test!(bash_deny_rule_refuses_and_names_the_rule, async {
    let config = PermissionConfig::new(vec![rule(RuleAction::Deny, ToolFilter::Bash, Some("rm *"))]);
    let h = harness(Some(config), vec![]).await;
    h.bang("rm -rf /tmp/x").await;
    assert!(h.ran().is_empty(), "a denied command must not run");
    let screen = h.refusal("rm -rf /tmp/x").await;
    assert!(screen.starts_with("Refused: Denied by permission policy: deny rule on bash matching"), "{screen}");
    let items = h.model_items().await;
    assert!(items.contains("refused by policy and did not run"), "{items}");
    assert!(!items.contains("deny rule"), "the model must not see the rule: {items}");
    assert_eq!(h.prompts.load(Ordering::SeqCst), 0);
});

local_test!(locked_down_policy_refuses, async {
    let config = PermissionConfig::new(vec![rule(RuleAction::Deny, ToolFilter::Any, None)]);
    let h = harness(Some(config), vec![]).await;
    h.bang("echo hi").await;
    assert!(h.ran().is_empty());
    assert!(h.refusal("echo hi").await.starts_with("Refused: Denied by permission policy"));
});

local_test!(write_into_a_deny_ruled_path_refuses, async {
    let config = PermissionConfig::new(vec![rule(RuleAction::Deny, ToolFilter::Edit, Some("/tmp/bang-denied/**"))]);
    let h = harness(Some(config), vec![]).await;
    h.bang("echo x > /tmp/bang-denied/file").await;
    assert!(h.ran().is_empty(), "a shell write into a deny-ruled path must not run");
    assert!(h.refusal("echo x > /tmp/bang-denied/file").await.starts_with("Refused:"));
});

local_test!(ask_rule_and_ask_everything_modes_never_prompt_and_run, async {
    let mut ask = PermissionConfig::new(vec![rule(RuleAction::Ask, ToolFilter::Bash, Some("echo *"))]);
    ask.prompt_policy = PromptPolicy::Ask;
    let h = harness(Some(ask), vec![]).await;
    h.bang("echo hi").await;
    assert_eq!(h.ran(), vec!["echo hi".to_owned()]);
    assert_eq!(h.prompts.load(Ordering::SeqCst), 0, "an ask rule must not prompt for a ! line");

    let mut dont_ask = PermissionConfig::new(vec![rule(RuleAction::Ask, ToolFilter::Bash, Some("echo *"))]);
    dont_ask.prompt_policy = PromptPolicy::Deny;
    let h = harness(Some(dont_ask), vec![]).await;
    h.bang("echo hi").await;
    assert_eq!(h.ran(), vec!["echo hi".to_owned()], "dontAsk must not refuse a ! line");
    assert_eq!(h.prompts.load(Ordering::SeqCst), 0);

    let mut auto = PermissionConfig::new(vec![]);
    auto.prompt_policy = PromptPolicy::Auto;
    let h = harness(Some(auto), vec![]).await;
    h.bang("echo hi").await;
    assert_eq!(h.ran(), vec!["echo hi".to_owned()]);
    assert_eq!(h.prompts.load(Ordering::SeqCst), 0);
});

local_test!(plan_mode_does_not_refuse, async {
    let h = harness(None, vec![]).await;
    activate_plan_mode(&h.actor);
    h.bang("echo hi").await;
    assert_eq!(h.ran(), vec!["echo hi".to_owned()]);
});

const DENY_HOOK: &str = r#"echo '{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"hook says no"}}'"#;
const ASK_HOOK: &str = r#"echo '{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"Confirm this run"}}'"#;
const REWRITE_HOOK: &str = r#"echo '{"hookSpecificOutput":{"updatedInput":{"command":"echo rewritten"}}}'"#;

local_test!(denying_pre_tool_use_hook_refuses, async {
    let h = harness(None, vec![pre_tool_use_spec("test/deny", None, DENY_HOOK)]).await;
    h.bang("echo hi").await;
    assert!(h.ran().is_empty());
    let screen = h.refusal("echo hi").await;
    assert!(screen.contains("Refused: a PreToolUse hook (") && screen.contains("hook says no"), "{screen}");
    let items = h.model_items().await;
    assert!(!items.contains("hook says no"), "the hook message must not reach the model: {items}");
});

local_test!(asking_or_rewriting_pre_tool_use_hook_neither_prompts_nor_changes_the_command, async {
    let h = harness(None, vec![pre_tool_use_spec("test/ask", None, ASK_HOOK)]).await;
    h.bang("echo hi").await;
    assert_eq!(h.ran(), vec!["echo hi".to_owned()]);
    assert_eq!(h.prompts.load(Ordering::SeqCst), 0);
    let h = harness(None, vec![pre_tool_use_spec("test/rewrite", None, REWRITE_HOOK)]).await;
    h.bang("echo hi").await;
    assert_eq!(h.ran(), vec!["echo hi".to_owned()], "a hook cannot rewrite a ! line");
});

local_test!(blocking_user_prompt_submit_hook_refuses, async {
    let spec = prompt_submit_spec("test/gate", "echo 'no shell today' >&2; exit 2");
    let h = harness(None, vec![spec]).await;
    h.bang("echo hi").await;
    assert!(h.ran().is_empty());
    let screen = h.refusal("echo hi").await;
    assert!(screen.contains("Refused: a UserPromptSubmit hook (") && screen.contains("no shell today"), "{screen}");
});

local_test!(post_tool_use_fires_after_the_command, async {
    let marker = std::env::temp_dir().join(format!("bang-post-{}", uuid::Uuid::new_v4()));
    let script = format!("cat > {}", marker.display());
    let spec = fuigo_hooks::config::HookSpec {
        event: fuigo_hooks::event::HookEventName::PostToolUse,
        ..pre_tool_use_spec("test/post", None, &script)
    };
    let h = harness(None, vec![spec]).await;
    h.bang("echo hi").await;
    assert_eq!(h.ran(), vec!["echo hi".to_owned()]);
    let payload = std::fs::read_to_string(&marker).expect("PostToolUse hook must run for a ! line");
    let _ = std::fs::remove_file(&marker);
    assert!(payload.contains("echo hi"), "{payload}");
});

local_test!(prompt_submit_payload_carries_the_shell_command, async {
    let marker = std::env::temp_dir().join(format!("bang-ups-{}", uuid::Uuid::new_v4()));
    let script = format!("cat > {}", marker.display());
    let h = harness(None, vec![prompt_submit_spec("test/ups", &script)]).await;
    h.bang("echo hi").await;
    let payload = std::fs::read_to_string(&marker).expect("UserPromptSubmit hook must run for a ! line");
    let _ = std::fs::remove_file(&marker);
    assert!(payload.contains("\"shellCommand\":\"echo hi\""), "{payload}");
});
