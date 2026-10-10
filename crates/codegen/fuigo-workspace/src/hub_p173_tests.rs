//! P173: a tool call routed through the hub answers to the workspace's local permission policy, with or without
//! `FUIGO_HITL_PERMISSION_LIVE`. Deny rules and protected paths refuse the call; an ask rule or a side-effecting
//! tool needs the hub prompt and is refused when there is none. Red first.

use super::SessionRoutedToolHandler;
use crate::handle::WorkspaceHandle;
use fuigo_tool_runtime::{
    SessionContext, ToolCallContext, ToolCallId, ToolErrorKind, ToolStreamItem, TypedToolOutput,
};
use fuigo_tool_types::ToolDescription;
use fuigo_tools::types::tool::ToolKind;
use fuigo_tools::types::tool_metadata::ToolMetadata;
use futures::StreamExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Records that it ran, so a refused call is told apart from one that ran and failed.
#[derive(Debug, Clone)]
struct RanStub {
    name: String,
    runs: Arc<AtomicUsize>,
}
impl ToolMetadata for RanStub {
    fn kind(&self) -> ToolKind {
        ToolKind::Other
    }
    fn tool_namespace(&self) -> fuigo_tools::types::tool::ToolNamespace {
        fuigo_tools::types::tool::ToolNamespace::MCP
    }
    fn description_template(&self) -> &str {
        "p173 stub"
    }
}
impl fuigo_tool_runtime::Tool for RanStub {
    type Args = serde_json::Value;
    type Output = String;
    fn id(&self) -> fuigo_tool_protocol::ToolId {
        fuigo_tool_protocol::ToolId::new(self.name.clone()).expect("valid tool id")
    }
    fn description(&self, _ctx: &fuigo_tool_runtime::ListToolsContext) -> ToolDescription {
        ToolDescription::new(self.name.clone(), "p173 stub")
    }
    async fn run(
        &self,
        _ctx: ToolCallContext,
        _input: serde_json::Value,
    ) -> Result<String, fuigo_tool_runtime::ToolError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        Ok("ran".into())
    }
}

struct Fixture {
    handle: WorkspaceHandle,
    runs: Arc<AtomicUsize>,
}
impl Fixture {
    /// A workspace whose `main` session has the project permission config `config_toml` (empty: no rules) and the
    /// given stub tools registered.
    fn new(config_toml: &str, tools: &[&str]) -> Self {
        assert!(
            std::env::var("FUIGO_HITL_PERMISSION_LIVE").is_err(),
            "these tests pin the default (FUIGO_HITL_PERMISSION_LIVE unset); the flag's prompts are covered in \
             permission::hub_permission::tests"
        );
        let handle = crate::handle::tests::make_handle();
        let session = handle.session("main").expect("main session");
        if !config_toml.is_empty() {
            let dir = session.cwd().join(".fuigo");
            std::fs::create_dir_all(&dir).expect("mkdir .fuigo");
            std::fs::write(dir.join("config.toml"), config_toml).expect("write config.toml");
        }
        let runs = Arc::new(AtomicUsize::new(0));
        for name in tools {
            session
                .toolset()
                .register_tool(
                    (*name).to_owned(),
                    RanStub {
                        name: (*name).to_owned(),
                        runs: runs.clone(),
                    },
                    Some(serde_json::json!({"type": "object"})),
                )
                .expect("register stub");
        }
        Self { handle, runs }
    }
    fn cwd(&self) -> std::path::PathBuf {
        self.handle
            .session("main")
            .expect("main session")
            .cwd()
            .to_path_buf()
    }
    fn set_yolo(&self, on: bool) {
        self.handle
            .session("main")
            .expect("main session")
            .set_yolo_mode(on);
    }
    async fn call(
        &self,
        tool: &str,
        args: serde_json::Value,
    ) -> Result<TypedToolOutput, fuigo_tool_runtime::ToolError> {
        self.call_in("main", tool, args).await
    }
    async fn call_in(
        &self,
        session: &str,
        tool: &str,
        args: serde_json::Value,
    ) -> Result<TypedToolOutput, fuigo_tool_runtime::ToolError> {
        let handler = SessionRoutedToolHandler::new(
            tool.to_owned(),
            ToolDescription::new(tool.to_owned(), String::new()),
            None,
            None,
            self.handle.clone(),
        )
        .expect("handler");
        let mut ctx = ToolCallContext::new(ToolCallId::new_v7());
        ctx.insert(SessionContext(session.to_owned()));
        let mut stream = fuigo_computer_hub_sdk::ToolServerHandler::handle_call(&handler, ctx, args).await;
        let mut terminal = None;
        while let Some(item) = stream.next().await {
            if let ToolStreamItem::Terminal(t) = item {
                terminal = Some(t);
            }
        }
        terminal.expect("a terminal item")
    }
    fn runs(&self) -> usize {
        self.runs.load(Ordering::SeqCst)
    }
}

#[track_caller]
fn assert_refused(result: &Result<TypedToolOutput, fuigo_tool_runtime::ToolError>, what: &str) {
    match result {
        Err(e) => assert_eq!(
            e.kind,
            ToolErrorKind::PermissionDenied,
            "{what}: expected PermissionDenied, got {e:?}"
        ),
        Ok(out) => panic!("{what}: the hub call ran: {:?}", out.value),
    }
}

const DENY_RM: &str = "[permission]\ndeny = [\"Bash(rm *)\"]\n";

#[tokio::test]
async fn hub_call_matching_a_local_deny_rule_is_refused() {
    let fx = Fixture::new(DENY_RM, &["run_terminal_command"]);
    let result = fx
        .call(
            "run_terminal_command",
            serde_json::json!({"command": "rm -rf build"}),
        )
        .await;
    assert_refused(&result, "deny rule");
    assert_eq!(fx.runs(), 0, "a denied call must not run");
}

#[tokio::test]
async fn hub_yolo_session_still_honours_a_local_deny_rule() {
    let fx = Fixture::new(DENY_RM, &["run_terminal_command"]);
    fx.set_yolo(true);
    let result = fx
        .call(
            "run_terminal_command",
            serde_json::json!({"command": "rm -rf build"}),
        )
        .await;
    assert_refused(&result, "deny rule under hub yolo");
    assert_eq!(fx.runs(), 0);
}

#[tokio::test]
async fn hub_edit_of_a_protected_path_is_refused_without_a_hub_prompt() {
    let fx = Fixture::new("", &["write"]);
    let target = fx.cwd().join(".git").join("hooks").join("pre-commit");
    let result = fx
        .call(
            "write",
            serde_json::json!({"file_path": target.to_string_lossy(), "content": "#!/bin/sh\n"}),
        )
        .await;
    assert_refused(&result, "protected path");
    assert_eq!(fx.runs(), 0);
}

#[tokio::test]
async fn hub_yolo_does_not_waive_the_protected_path_floor() {
    let fx = Fixture::new("", &["write"]);
    fx.set_yolo(true);
    let target = fx.cwd().join(".git").join("hooks").join("pre-commit");
    let result = fx
        .call(
            "write",
            serde_json::json!({"file_path": target.to_string_lossy(), "content": "#!/bin/sh\n"}),
        )
        .await;
    assert_refused(&result, "protected path under hub yolo");
    assert_eq!(fx.runs(), 0);
}

#[tokio::test]
async fn hub_side_effecting_tool_is_refused_without_a_hub_prompt() {
    for tool in ["image_gen", "scheduler_create"] {
        let fx = Fixture::new("", &[tool]);
        let result = fx.call(tool, serde_json::json!({})).await;
        assert_refused(&result, tool);
        assert_eq!(fx.runs(), 0, "{tool} must not run");
    }
}

#[tokio::test]
async fn hub_call_matching_a_local_ask_rule_is_refused_without_a_hub_prompt() {
    let fx = Fixture::new(
        "[permission]\nask = [\"Bash(git push*)\"]\n",
        &["run_terminal_command"],
    );
    let result = fx
        .call(
            "run_terminal_command",
            serde_json::json!({"command": "git push origin main"}),
        )
        .await;
    assert_refused(&result, "ask rule");
    assert_eq!(fx.runs(), 0);
}

#[tokio::test]
async fn hub_read_matching_a_local_read_deny_rule_is_refused() {
    let fx = Fixture::new("[permission]\ndeny = [\"Read(**/secrets/**)\"]\n", &[]);
    let target = fx.cwd().join("secrets").join("token.txt");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(&target, "hunter2").unwrap();
    let result = fx
        .call(
            "read_file",
            serde_json::json!({"target_file": target.to_string_lossy()}),
        )
        .await;
    assert_refused(&result, "read deny rule");
}

// ---- Legitimate hub use keeps working (these pass before and after the fix). ----

#[tokio::test]
async fn hub_calls_without_local_rules_still_run() {
    let fx = Fixture::new("", &["run_terminal_command", "write"]);
    let bash = fx
        .call(
            "run_terminal_command",
            serde_json::json!({"command": "echo hi"}),
        )
        .await;
    assert!(bash.is_ok(), "plain bash must run: {bash:?}");
    let target = fx.cwd().join("notes.txt");
    let edit = fx
        .call(
            "write",
            serde_json::json!({"file_path": target.to_string_lossy(), "content": "x"}),
        )
        .await;
    assert!(edit.is_ok(), "plain edit must run: {edit:?}");
    assert_eq!(fx.runs(), 2);
}

#[tokio::test]
async fn hub_call_outside_a_deny_rule_still_runs() {
    let fx = Fixture::new(DENY_RM, &["run_terminal_command"]);
    let result = fx
        .call("run_terminal_command", serde_json::json!({"command": "ls"}))
        .await;
    assert!(result.is_ok(), "ls is not denied: {result:?}");
    assert_eq!(fx.runs(), 1);
}

#[tokio::test]
async fn hub_read_only_tool_runs_under_default_rules() {
    let fx = Fixture::new("", &[]);
    let target = fx.cwd().join("readme.txt");
    std::fs::write(&target, "hello").unwrap();
    let result = fx
        .call(
            "read_file",
            serde_json::json!({"target_file": target.to_string_lossy()}),
        )
        .await;
    assert!(result.is_ok(), "read under default rules must run: {result:?}");
}

// ---- Astra r1: session MCP tools and search results answer to the policy too. ----

/// A session MCP server's tool, as the bridge advertises it: bare tool id, server in the namespace.
struct McpStub {
    runs: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl fuigo_computer_hub_sdk::ToolServerHandler for McpStub {
    fn tool_id(&self) -> fuigo_tool_protocol::ToolId {
        fuigo_tool_protocol::ToolId::new("create_issue").expect("valid tool id")
    }
    fn description(&self) -> ToolDescription {
        let mut desc = ToolDescription::new("create_issue", "mcp stub");
        desc.namespace = Some("github".to_owned());
        desc
    }
    fn input_schema(&self) -> Option<serde_json::Value> {
        None
    }
    async fn handle_call(
        &self,
        _ctx: ToolCallContext,
        _args: serde_json::Value,
    ) -> fuigo_tool_runtime::ToolStream<TypedToolOutput> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        fuigo_tool_runtime::terminal_only(Err(fuigo_tool_runtime::ToolError::new(
            ToolErrorKind::TerminalError,
            "mcp stub ran",
        )))
    }
}

async fn call_mcp(fx: &Fixture) -> Result<TypedToolOutput, fuigo_tool_runtime::ToolError> {
    let gated = super::McpPolicyGatedHandler::new(
        Arc::new(McpStub {
            runs: fx.runs.clone(),
        }),
        fx.handle.clone(),
    );
    let mut ctx = ToolCallContext::new(ToolCallId::new_v7());
    ctx.insert(SessionContext("main".to_owned()));
    let mut stream =
        fuigo_computer_hub_sdk::ToolServerHandler::handle_call(&gated, ctx, serde_json::json!({"title": "x"}))
            .await;
    let mut terminal = None;
    while let Some(item) = stream.next().await {
        if let ToolStreamItem::Terminal(t) = item {
            terminal = Some(t);
        }
    }
    terminal.expect("a terminal item")
}

#[tokio::test]
async fn hub_session_mcp_tool_matching_a_local_deny_rule_is_refused() {
    let fx = Fixture::new("[permission]\ndeny = [\"mcp__github\"]\n", &[]);
    let result = call_mcp(&fx).await;
    assert_refused(&result, "mcp deny rule");
    assert_eq!(fx.runs(), 0, "a denied MCP call must not reach the server");
}

#[tokio::test]
async fn hub_session_mcp_tool_without_rules_still_runs() {
    let fx = Fixture::new("", &[]);
    let result = call_mcp(&fx).await;
    assert!(
        matches!(&result, Err(e) if e.detail == "mcp stub ran"),
        "the MCP call must reach the server: {result:?}"
    );
    assert_eq!(fx.runs(), 1);
}

#[tokio::test]
async fn hub_grep_skips_files_a_read_rule_denies() {
    let fx = Fixture::new("[permission]\ndeny = [\"Read(**/secrets/**)\"]\n", &[]);
    let cwd = fx.cwd();
    std::fs::create_dir_all(cwd.join("secrets")).unwrap();
    std::fs::write(cwd.join("secrets").join("token.txt"), "needle-p173\n").unwrap();
    std::fs::write(cwd.join("open.txt"), "needle-p173\n").unwrap();
    let result = fx
        .call(
            "grep",
            serde_json::json!({"pattern": "needle-p173", "path": cwd.to_string_lossy()}),
        )
        .await;
    let out = result.expect("grep under a permitted root runs");
    let text = format!("{:?} {:?}", out.value, out.model_output);
    assert!(text.contains("open.txt"), "the permitted match is found: {text}");
    assert!(
        !text.contains("token.txt"),
        "a Read-denied file must not appear in hub grep results: {text}"
    );
}

/// Astra r1: the policy sees the call as the toolset parses it. A `read_file` exposed under another name with a renamed
/// path parameter is still a read of that path; no name-based mapping knows `fetch_text` or `location`.
#[tokio::test]
async fn hub_read_under_a_renamed_tool_and_parameter_still_meets_the_read_rule() {
    let fx = Fixture::new("[permission]\ndeny = [\"Read(**/secrets/**)\"]\n", &[]);
    let cwd = fx.cwd();
    let target = cwd.join("secrets").join("token.txt");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(&target, "hunter2").unwrap();
    let mut config = crate::session::tool_config::test_support::baseline_config();
    for tool in &mut config.tools {
        if tool.id == "FuigoBuild:read_file" {
            tool.name_override = Some("fetch_text".to_owned());
            tool.params_name_overrides = Some(std::collections::HashMap::from([(
                "target_file".to_owned(),
                "location".to_owned(),
            )]));
        }
    }
    fx.handle
        .create_session_with_config(
            "renamed",
            Some(cwd.clone()),
            Some(config),
            crate::capability::CapabilityMode::All,
            None,
            false,
        )
        .expect("session with renamed read_file");
    let open = cwd.join("open.txt");
    std::fs::write(&open, "fine").unwrap();
    let allowed = fx
        .call_in(
            "renamed",
            "fetch_text",
            serde_json::json!({"location": open.to_string_lossy()}),
        )
        .await;
    assert!(allowed.is_ok(), "the renamed tool works for a permitted path: {allowed:?}");
    let denied = fx
        .call_in(
            "renamed",
            "fetch_text",
            serde_json::json!({"location": target.to_string_lossy()}),
        )
        .await;
    assert_refused(&denied, "renamed read_file on a Read-denied path");
}

// ---- Astra r2 ----

/// One tool of [`bind_session`]: registry id, exposed name, parameter renames (canonical -> exposed).
type BoundTool<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)]);

/// A session `name` whose only tools are `tools`.
fn bind_session(fx: &Fixture, name: &str, tools: &[BoundTool<'_>]) {
    use fuigo_tools::registry::types::{ToolConfig, ToolServerConfig};
    let config = ToolServerConfig {
        tools: tools
            .iter()
            .map(|(id, exposed, renames)| ToolConfig {
                id: (*id).to_owned(),
                params: None,
                name_override: Some((*exposed).to_owned()),
                params_name_overrides: (!renames.is_empty()).then(|| {
                    renames
                        .iter()
                        .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
                        .collect()
                }),
                description_override: None,
                behavior_version: None,
                kind: None,
            })
            .collect(),
        behavior_preset: None,
    };
    fx.handle
        .create_session_with_config(
            name,
            Some(fx.cwd()),
            Some(config),
            crate::capability::CapabilityMode::All,
            None,
            false,
        )
        .expect("bind session");
}

/// A (renamed) codex `read_file` reading a batch: every entry meets the Read rules, not just `file_path`.
#[tokio::test]
async fn hub_renamed_codex_read_file_batch_entries_meet_the_read_rule() {
    let fx = Fixture::new("[permission]\ndeny = [\"Read(**/secrets/**)\"]\n", &[]);
    let secret = fx.cwd().join("secrets").join("token.txt");
    std::fs::create_dir_all(secret.parent().unwrap()).unwrap();
    std::fs::write(&secret, "hunter2").unwrap();
    bind_session(&fx, "codex", &[("Codex:read_file", "fetch_text", &[])]);
    let result = fx
        .call_in(
            "codex",
            "fetch_text",
            serde_json::json!({"files": [{"path": secret.to_string_lossy()}]}),
        )
        .await;
    assert_refused(&result, "batch entry under a Read deny");
}

/// A (renamed) `apply_patch` with a renamed `patch` parameter: its targets still meet the protected-path floor.
#[tokio::test]
async fn hub_renamed_apply_patch_still_meets_the_protected_floor() {
    let fx = Fixture::new("", &[]);
    bind_session(&fx, "patch", &[("Codex:apply_patch", "patcher", &[("patch", "delta")])]);
    let hook = fx.cwd().join(".git").join("hooks").join("pre-commit");
    let patch = format!(
        "*** Begin Patch\n*** Add File: {}\n+#!/bin/sh\n*** End Patch\n",
        hook.display()
    );
    let result = fx
        .call_in("patch", "patcher", serde_json::json!({"delta": patch}))
        .await;
    assert_refused(&result, "patch adding a git hook");
    assert!(!hook.exists(), "the refused patch must not write the hook");
}

/// A typed tool with a renamed parameter is judged by its parsed input alone: no name-based placeholder (such as an
/// `Edit("unknown")` for a `write` whose `file_path` is exposed as `location`) is added to it.
#[tokio::test]
async fn hub_typed_tool_accesses_come_from_its_parsed_input_only() {
    let fx = Fixture::new("", &[]);
    bind_session(&fx, "typed", &[("OpenCode:write", "write", &[("file_path", "location")])]);
    let handler = SessionRoutedToolHandler::new(
        "write".to_owned(),
        ToolDescription::new("write", String::new()),
        None,
        None,
        fx.handle.clone(),
    )
    .expect("handler");
    let toolset = fx.handle.session("typed").expect("typed session").toolset();
    let accesses = handler
        .policy_accesses(
            &toolset,
            &serde_json::json!({"location": "notes.txt", "content": "x"}),
        )
        .await
        .expect("parses");
    assert!(
        matches!(accesses.as_slice(), [crate::permission::AccessKind::Edit(p)] if p == "notes.txt"),
        "{accesses:?}"
    );
}

/// Removing a Read deny from the config stops hiding those files from hub search on the next call.
#[tokio::test]
async fn hub_grep_shows_files_again_once_the_read_deny_is_removed() {
    let fx = Fixture::new("[permission]\ndeny = [\"Read(**/secrets/**)\"]\n", &[]);
    let cwd = fx.cwd();
    std::fs::create_dir_all(cwd.join("secrets")).unwrap();
    std::fs::write(cwd.join("secrets").join("token.txt"), "needle-p173\n").unwrap();
    let grep = || {
        fx.call(
            "grep",
            serde_json::json!({"pattern": "needle-p173", "path": cwd.to_string_lossy()}),
        )
    };
    let hidden = grep().await.expect("grep runs");
    assert!(!format!("{:?}", hidden.model_output).contains("token.txt"));
    std::fs::write(cwd.join(".fuigo").join("config.toml"), "").unwrap();
    let shown = grep().await.expect("grep runs");
    assert!(
        format!("{:?}", shown.model_output).contains("token.txt"),
        "the file is searchable again once the deny is gone: {:?}",
        shown.model_output
    );
}

// ---- Astra r3 (self-verified after the round cap) ----

/// G: a Read deny written as an absolute path, which a ripgrep exclude cannot express, still keeps a hub search under
/// a permitted root away from the file.
#[tokio::test]
async fn hub_grep_under_an_absolute_read_deny_does_not_read_the_file() {
    let fx = Fixture::new("", &[]);
    let cwd = fx.cwd();
    std::fs::create_dir_all(cwd.join(".fuigo")).unwrap();
    std::fs::write(
        cwd.join(".fuigo").join("config.toml"),
        format!("[permission]\ndeny = [\"Read({}/secrets/**)\"]\n", cwd.display()),
    )
    .unwrap();
    std::fs::create_dir_all(cwd.join("secrets")).unwrap();
    std::fs::write(cwd.join("secrets").join("token.txt"), "needle-p173\n").unwrap();
    let result = fx
        .call(
            "grep",
            serde_json::json!({"pattern": "needle-p173", "path": cwd.to_string_lossy()}),
        )
        .await;
    match &result {
        Ok(out) => assert!(
            !format!("{:?} {:?}", out.value, out.model_output).contains("token.txt"),
            "the denied file leaked into hub grep results"
        ),
        Err(e) => assert_eq!(e.kind, ToolErrorKind::PermissionDenied, "{e:?}"),
    }
}

/// J: a Read ask rule below the search root needs approval; there is no hub prompt here, so the search is refused.
#[tokio::test]
async fn hub_grep_over_files_a_read_ask_rule_covers_needs_approval() {
    let fx = Fixture::new("[permission]\nask = [\"Read(**/secrets/**)\"]\n", &[]);
    let cwd = fx.cwd();
    std::fs::create_dir_all(cwd.join("secrets")).unwrap();
    std::fs::write(cwd.join("secrets").join("token.txt"), "needle-p173\n").unwrap();
    let result = fx
        .call(
            "grep",
            serde_json::json!({"pattern": "needle-p173", "path": cwd.to_string_lossy()}),
        )
        .await;
    assert_refused(&result, "search over an ask-ruled file");
}

/// H: a patch that adds an ask-ruled file and a git hook needs approval for both; without a prompt it is refused and
/// writes nothing.
#[tokio::test]
async fn hub_patch_with_several_targets_needing_approval_is_refused_whole() {
    let fx = Fixture::new("[permission]\nask = [\"Edit(**/notes.txt)\"]\n", &[]);
    bind_session(&fx, "patch2", &[("Codex:apply_patch", "apply_patch", &[])]);
    let cwd = fx.cwd();
    let notes = cwd.join("notes.txt");
    let hook = cwd.join(".git").join("hooks").join("pre-commit");
    let patch = format!(
        "*** Begin Patch\n*** Add File: {}\n+n\n*** Add File: {}\n+#!/bin/sh\n*** End Patch\n",
        notes.display(),
        hook.display()
    );
    let result = fx
        .call_in("patch2", "apply_patch", serde_json::json!({"patch": patch}))
        .await;
    assert_refused(&result, "patch with two targets needing approval");
    assert!(!notes.exists() && !hook.exists());
}

/// I: an OpenCode bash is judged in its `workdir`: `touch pre-commit` there writes a git hook.
#[tokio::test]
async fn hub_opencode_bash_is_judged_in_its_workdir() {
    let fx = Fixture::new("", &[]);
    bind_session(&fx, "oc", &[("OpenCode:bash", "bash", &[])]);
    let hooks = fx.cwd().join(".git").join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    let result = fx
        .call_in(
            "oc",
            "bash",
            serde_json::json!({
                "command": "touch pre-commit",
                "workdir": hooks.to_string_lossy(),
                "description": "touch",
            }),
        )
        .await;
    assert_refused(&result, "touch of a git hook through workdir");
    assert!(!hooks.join("pre-commit").exists(), "the hook must not be created");
}

/// A `workdir` is judged in addition to the session cwd: a bash tool that ignores the argument runs in the session cwd,
/// so a hub cannot point the check at a harmless directory.
#[tokio::test]
async fn hub_bash_workdir_does_not_replace_the_session_cwd_in_the_check() {
    let fx = Fixture::new("", &["run_terminal_command"]);
    let cwd = fx.cwd();
    std::fs::create_dir_all(cwd.join(".fuigo")).unwrap();
    std::fs::write(
        cwd.join(".fuigo").join("config.toml"),
        format!("[permission]\ndeny = [\"Edit({}/notes.txt)\"]\n", cwd.display()),
    )
    .unwrap();
    std::fs::create_dir_all(cwd.join("sub")).unwrap();
    let result = fx
        .call(
            "run_terminal_command",
            serde_json::json!({
                "command": "echo x > notes.txt",
                "workdir": cwd.join("sub").to_string_lossy(),
            }),
        )
        .await;
    assert_refused(&result, "redirect into a denied file, judged elsewhere via workdir");
    assert_eq!(fx.runs(), 0);
}

// ---- Grok 4.7 review (round 4) ----

/// Write `deny`/`ask` rules into the fixture's project config.
fn write_config(fx: &Fixture, toml: &str) {
    let dir = fx.cwd().join(".fuigo");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.toml"), toml).unwrap();
}

#[track_caller]
fn assert_refused_or_hidden(
    result: &Result<TypedToolOutput, fuigo_tool_runtime::ToolError>,
    leaked: &str,
    what: &str,
) {
    match result {
        Ok(out) => assert!(
            !format!("{:?} {:?}", out.value, out.model_output).contains(leaked),
            "{what}: {leaked} leaked into the results: {:?}",
            out.model_output
        ),
        Err(e) => assert_eq!(e.kind, ToolErrorKind::PermissionDenied, "{what}: {e:?}"),
    }
}

/// Grok #1: the search root is resolved the way the tool resolves it (`~` expanded), so a tilde path under an
/// absolute Read deny is refused.
#[tokio::test]
async fn hub_grep_tilde_path_under_an_absolute_read_deny_is_refused() {
    let home = std::path::PathBuf::from(std::env::var("HOME").expect("HOME is set"));
    let outside = tempfile::Builder::new()
        .prefix("p173-tilde-")
        .tempdir_in(&home)
        .expect("tempdir under HOME");
    let secrets = outside.path().join("secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    std::fs::write(secrets.join("token.txt"), "needle-p173\n").unwrap();
    let fx = Fixture::new("", &[]);
    write_config(
        &fx,
        &format!("[permission]\ndeny = [\"Read({}/**)\"]\n", secrets.display()),
    );
    let name = outside.path().file_name().unwrap().to_string_lossy().into_owned();
    let result = fx
        .call(
            "grep",
            serde_json::json!({"pattern": "needle-p173", "path": format!("~/{name}")}),
        )
        .await;
    assert_refused(&result, "tilde search root over an absolute Read deny");
}

/// Grok #1: a path written without its leading slash resolves to the absolute path under the cwd (the tool's
/// `/{path}` remap), so the walk must look there too.
#[tokio::test]
async fn hub_grep_path_missing_its_leading_slash_under_an_absolute_read_deny_is_refused() {
    let fx = Fixture::new("", &[]);
    let cwd = fx.cwd();
    write_config(
        &fx,
        &format!("[permission]\ndeny = [\"Read({}/secrets/**)\"]\n", cwd.display()),
    );
    std::fs::create_dir_all(cwd.join("secrets")).unwrap();
    std::fs::write(cwd.join("secrets").join("token.txt"), "needle-p173\n").unwrap();
    let no_slash = cwd.to_string_lossy().trim_start_matches('/').to_owned();
    let result = fx
        .call(
            "grep",
            serde_json::json!({"pattern": "needle-p173", "path": no_slash}),
        )
        .await;
    assert_refused(&result, "search root missing its leading slash over an absolute Read deny");
}

/// Grok #2: OpenCode `glob` lists files with ripgrep; a `**/` Read deny must keep the file out of its listing.
#[tokio::test]
async fn hub_opencode_glob_under_a_starstar_read_deny_does_not_list_the_file() {
    let fx = Fixture::new("[permission]\ndeny = [\"Read(**/secrets/**)\"]\n", &[]);
    bind_session(&fx, "ocglob", &[("OpenCode:glob", "glob", &[])]);
    let cwd = fx.cwd();
    std::fs::create_dir_all(cwd.join("secrets")).unwrap();
    std::fs::write(cwd.join("secrets").join("token.txt"), "needle-p173\n").unwrap();
    std::fs::write(cwd.join("visible.txt"), "x\n").unwrap();
    let result = fx
        .call_in(
            "ocglob",
            "glob",
            serde_json::json!({"pattern": "**/*.txt", "path": cwd.to_string_lossy()}),
        )
        .await;
    assert_refused_or_hidden(&result, "token.txt", "OpenCode glob under a **/ Read deny");
}

/// Grok #3: a renamed `workdir` is the directory the OpenCode bash runs in; `touch pre-commit` there writes a git hook.
#[tokio::test]
async fn hub_renamed_opencode_bash_workdir_is_judged() {
    let fx = Fixture::new("", &[]);
    bind_session(&fx, "ocwd", &[("OpenCode:bash", "bash", &[("workdir", "dir")])]);
    let hooks = fx.cwd().join(".git").join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    let result = fx
        .call_in(
            "ocwd",
            "bash",
            serde_json::json!({
                "command": "touch pre-commit",
                "dir": hooks.to_string_lossy(),
                "description": "touch",
            }),
        )
        .await;
    assert_refused(&result, "touch of a git hook through a renamed workdir");
    assert!(!hooks.join("pre-commit").exists(), "the hook must not be created");
}

/// Grok #3: a renamed OpenCode grep `path` is judged at the path the tool searches.
#[tokio::test]
async fn hub_renamed_opencode_grep_path_under_an_absolute_read_deny_is_refused() {
    let outside = tempfile::tempdir().expect("tempdir");
    let secrets = outside.path().join("secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    std::fs::write(secrets.join("token.txt"), "needle-p173\n").unwrap();
    let fx = Fixture::new("", &[]);
    write_config(
        &fx,
        &format!("[permission]\ndeny = [\"Read({}/**)\"]\n", secrets.display()),
    );
    bind_session(&fx, "ocgrep", &[("OpenCode:grep", "grep", &[("path", "dir")])]);
    let result = fx
        .call_in(
            "ocgrep",
            "grep",
            serde_json::json!({"pattern": "needle-p173", "dir": outside.path().to_string_lossy()}),
        )
        .await;
    assert_refused(&result, "renamed OpenCode grep path over an absolute Read deny");
}

/// Grok #4: a Grep ask rule over a file below the search root needs approval (refused without a hub prompt).
#[tokio::test]
async fn hub_grep_ask_over_a_descendant_needs_approval() {
    let fx = Fixture::new("[permission]\nask = [\"Grep(**/secrets/**)\"]\n", &[]);
    let cwd = fx.cwd();
    std::fs::create_dir_all(cwd.join("secrets")).unwrap();
    std::fs::write(cwd.join("secrets").join("token.txt"), "needle-p173\n").unwrap();
    let result = fx
        .call(
            "grep",
            serde_json::json!({"pattern": "needle-p173", "path": cwd.to_string_lossy()}),
        )
        .await;
    assert_refused(&result, "search over a Grep-ask-ruled file");
}

/// Grok #4: an absolute Grep deny over a file below the search root refuses the search.
#[tokio::test]
async fn hub_grep_absolute_deny_refuses_the_search() {
    let fx = Fixture::new("", &[]);
    let cwd = fx.cwd();
    write_config(
        &fx,
        &format!("[permission]\ndeny = [\"Grep({}/secrets/**)\"]\n", cwd.display()),
    );
    std::fs::create_dir_all(cwd.join("secrets")).unwrap();
    std::fs::write(cwd.join("secrets").join("token.txt"), "needle-p173\n").unwrap();
    let result = fx
        .call(
            "grep",
            serde_json::json!({"pattern": "needle-p173", "path": cwd.to_string_lossy()}),
        )
        .await;
    assert_refused(&result, "search over an absolute Grep deny");
}

/// Grok #3 (same class): an OpenCode grep the hub exposes under another name is still judged as a search of its path.
#[tokio::test]
async fn hub_opencode_grep_under_another_name_is_judged_as_a_search() {
    let outside = tempfile::tempdir().expect("tempdir");
    let secrets = outside.path().join("secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    std::fs::write(secrets.join("token.txt"), "needle-p173\n").unwrap();
    let fx = Fixture::new("", &[]);
    write_config(
        &fx,
        &format!("[permission]\ndeny = [\"Read({}/**)\"]\n", secrets.display()),
    );
    bind_session(&fx, "ocsearch", &[("OpenCode:grep", "search_text", &[])]);
    let result = fx
        .call_in(
            "ocsearch",
            "search_text",
            serde_json::json!({"pattern": "needle-p173", "path": outside.path().to_string_lossy()}),
        )
        .await;
    assert_refused(&result, "renamed OpenCode grep over an absolute Read deny");
}

/// P173 on P184: a hub-routed `apply_patch` is judged per file like a local one. A patch with one target under a
/// deny rule is refused whole, and writes nothing (not even its ordinary target).
#[tokio::test]
async fn hub_apply_patch_touching_a_denied_path_is_refused() {
    let fx = Fixture::new("[permission]\ndeny = [\"Edit(secrets/**)\"]\n", &[]);
    bind_session(&fx, "patch-deny", &[("Codex:apply_patch", "apply_patch", &[])]);
    let cwd = fx.cwd();
    std::fs::create_dir_all(cwd.join("secrets")).unwrap();
    std::fs::write(cwd.join("secrets/x"), "k=1\n").unwrap();
    let patch = "*** Begin Patch\n*** Add File: src/ok.rs\n+ok\n*** Update File: secrets/x\n@@\n-k=1\n+k=2\n*** End Patch\n";
    let result = fx
        .call_in("patch-deny", "apply_patch", serde_json::json!({"patch": patch}))
        .await;
    assert_refused(&result, "patch updating a denied file");
    assert!(!cwd.join("src/ok.rs").exists(), "the refused patch must write nothing");
    assert_eq!(std::fs::read_to_string(cwd.join("secrets/x")).unwrap(), "k=1\n");
}

/// P173 on P184: a hub patch target is judged in every spelling of the file the tool writes, as a local one is. A
/// directory entry literally named `safe\alias` (a Unix symlink into `secrets/`) is followed as the writer follows it,
/// so the deny binds.
#[tokio::test]
#[cfg(unix)]
async fn hub_apply_patch_target_is_judged_where_the_tool_writes_it() {
    let fx = Fixture::new("[permission]\ndeny = [\"Edit(secrets/**)\"]\n", &[]);
    bind_session(&fx, "patch-link", &[("Codex:apply_patch", "apply_patch", &[])]);
    let cwd = fx.cwd();
    std::fs::create_dir_all(cwd.join("secrets")).unwrap();
    std::os::unix::fs::symlink(cwd.join("secrets"), cwd.join("safe\\alias")).unwrap();
    let patch = "*** Begin Patch\n*** Add File: safe\\alias/key\n+x\n*** End Patch\n";
    let result = fx
        .call_in("patch-link", "apply_patch", serde_json::json!({"patch": patch}))
        .await;
    assert_refused(&result, "patch writing a denied file through a backslash-named symlink");
    assert!(!cwd.join("secrets/key").exists(), "the refused patch must not write the denied file");
}

/// P173 on P184: a hub patch that does not parse is refused by the policy (no `Edit("apply_patch")` sentinel is
/// judged in its place), as a local one is.
#[tokio::test]
async fn hub_unparseable_apply_patch_is_refused() {
    let fx = Fixture::new("", &[]);
    bind_session(&fx, "patch-junk", &[("Codex:apply_patch", "apply_patch", &[])]);
    let result = fx
        .call_in("patch-junk", "apply_patch", serde_json::json!({"patch": "not a patch"}))
        .await;
    assert_refused(&result, "unparseable patch");
}
