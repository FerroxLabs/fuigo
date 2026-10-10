use crate::permission::prompter::{PromptOutcome, tool_name_for_access};
use crate::permission::types::{AccessKind, EditTargets, HookAsk};
use async_trait::async_trait;
use prometheus::{HistogramVec, IntCounter, register_histogram_vec, register_int_counter};
use serde_json::Value;
use std::sync::LazyLock;
use fuigo_computer_hub_sdk::harness::PERMISSION_REQUEST_KIND;
use fuigo_computer_hub_sdk::{ToolServer, WeakToolServer};
use fuigo_tool_protocol::SessionId;
static PERMISSION_REPLY_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "fuigo_workspace_permission_reply_seconds",
        "Wall-clock time awaiting chat's reply to a permission_request hook",
        &["outcome"],
        vec![0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0]
    )
    .expect("fuigo_workspace_permission_reply_seconds must register once")
});
static PERMISSION_TIMEOUT_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "fuigo_workspace_permission_timeout_total",
        "permission_request hooks whose reply timed out (backstop deadline fired)"
    )
    .expect("fuigo_workspace_permission_timeout_total must register once")
});
pub(crate) fn init_metrics() {
    for outcome in ["ok", "error"] {
        let _ = PERMISSION_REPLY_DURATION.with_label_values(&[outcome]);
    }
    PERMISSION_TIMEOUT_TOTAL.inc_by(0);
}
fn is_timeout_err(msg: &str) -> bool {
    msg.contains("timed out")
}
/// Opt-in: also send the hub permission prompt for hub-routed calls that the local policy would only prompt for by
/// default (a shell command, an edit, an MCP call, a fetch, an agent message, a task, with no rule about them).
///
/// Off by default, because the agent on the hub side asks its own user for those. What the local policy says
/// explicitly is enforced on every hub-routed call with or without this flag (P173): a deny rule refuses the call; an
/// ask rule, a protected path, a shell gate, and a side-effecting tool need the hub prompt and are refused without
/// one. See [`hub_policy_verdict`].
pub const HITL_PERMISSION_LIVE_ENV: &str = "FUIGO_HITL_PERMISSION_LIVE";
pub fn hitl_permission_live_enabled() -> bool {
    match std::env::var(HITL_PERMISSION_LIVE_ENV) {
        Ok(v) => {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        }
        Err(_) => false,
    }
}
#[async_trait]
pub trait PermissionHookTransport: Send + Sync {
    async fn request_permission(&self, payload: Value) -> Result<Value, String>;
}
pub struct ToolServerPermissionTransport {
    server: WeakToolServer,
    session_id: SessionId,
}
impl ToolServerPermissionTransport {
    pub fn new(server: ToolServer, session_id: SessionId) -> Self {
        Self {
            server: server.downgrade(),
            session_id,
        }
    }
    pub fn from_session_id(server: ToolServer, session_id: &str) -> Option<Self> {
        SessionId::new(session_id)
            .ok()
            .map(|sid| Self::new(server, sid))
    }
}
#[async_trait]
impl PermissionHookTransport for ToolServerPermissionTransport {
    async fn request_permission(&self, payload: Value) -> Result<Value, String> {
        let start = std::time::Instant::now();
        let Some(server) = self.server.upgrade() else {
            PERMISSION_REPLY_DURATION
                .with_label_values(&["error"])
                .observe(start.elapsed().as_secs_f64());
            return Err("tool server gone (weak upgrade failed)".to_owned());
        };
        let reply_result = server
            .request_hook(
                self.session_id.clone(),
                PERMISSION_REQUEST_KIND.to_owned(),
                payload,
            )
            .await;
        let outcome = match &reply_result {
            Ok(_) => "ok",
            Err(e) => {
                if is_timeout_err(&e.to_string()) {
                    PERMISSION_TIMEOUT_TOTAL.inc();
                }
                "error"
            }
        };
        PERMISSION_REPLY_DURATION
            .with_label_values(&[outcome])
            .observe(start.elapsed().as_secs_f64());
        reply_result.map_err(|e| e.to_string())
    }
}
fn scope_for_access(access: &AccessKind) -> &'static str {
    match access {
        AccessKind::Bash(_)
        | AccessKind::Edit(_)
        | AccessKind::MCPTool { .. }
        | AccessKind::AgentMessage { .. }
        | AccessKind::Tool(_) => "write",
        AccessKind::Read(_)
        | AccessKind::Grep { .. }
        | AccessKind::WebFetch(_)
        | AccessKind::WebSearch(_) => "read",
    }
}
fn describe_access(access: &AccessKind) -> String {
    match access {
        AccessKind::Bash(_) => "Run a terminal command".to_owned(),
        AccessKind::Edit(path) => format!("Edit {path}"),
        AccessKind::MCPTool { name, .. } => format!("Run MCP tool {name}"),
        AccessKind::WebFetch(url) => format!("Fetch {url}"),
        AccessKind::WebSearch(query) => format!("Search the web for {query}"),
        AccessKind::Read(_) => "Read a file".to_owned(),
        AccessKind::Grep { .. } => "Search file contents".to_owned(),
        AccessKind::AgentMessage { subagent_id } => {
            format!("Send a message to subagent {subagent_id}")
        }
        AccessKind::Tool(name) => format!("Run {name}"),
    }
}
pub(crate) fn build_permission_payload(
    access: &AccessKind,
    tool_call_id: &str,
    hook_ask: Option<&HookAsk>,
) -> Value {
    let description = match hook_ask {
        Some(ask) => ask.prompt_header(&describe_access(access)),
        None => describe_access(access),
    };
    let mut payload = serde_json::json!({
        "tool_call_id": tool_call_id,
        "tool_name": tool_name_for_access(access),
        "description": description,
        "scope": scope_for_access(access),
    });
    if let Some(map) = payload.as_object_mut() {
        match access {
            AccessKind::Bash(command) => {
                map.insert("bash_command".to_owned(), Value::from(command.clone()));
            }
            AccessKind::AgentMessage { subagent_id } => {
                map.insert("subagent_id".to_owned(), Value::from(subagent_id.clone()));
            }
            AccessKind::Edit(path) => {
                map.insert(
                    "edit_file_paths".to_owned(),
                    Value::from(vec![path.clone()]),
                );
            }
            _ => {}
        }
    }
    payload
}
#[cfg(test)]
pub(crate) fn build_permission_payload_for_test(access: &AccessKind, tool_call_id: &str) -> Value {
    build_permission_payload(access, tool_call_id, None)
}
pub(crate) fn reply_to_outcome(reply: &Value) -> PromptOutcome {
    let outcome = match reply.get("outcome") {
        Some(Value::String(s)) => s.as_str(),
        Some(Value::Number(n)) => match n.as_i64() {
            Some(1) => "approve",
            Some(2) => "reject",
            Some(3) => "always_approve",
            Some(4) => "always_reject",
            _ => "",
        },
        _ => "",
    };
    let followup = reply
        .get("followup_message")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    match outcome {
        "approve" => PromptOutcome::AllowOnce,
        "always_approve" => match scope_kind_value(reply) {
            Some(("bash_command", Some(value))) => PromptOutcome::AllowAlwaysBashCommand(value),
            Some(("bash_glob", Some(value))) => PromptOutcome::AllowAlwaysBashGlob(value),
            Some(("server_prefix", Some(value))) => PromptOutcome::AllowAlwaysMcpServer(value),
            Some(("domain", Some(value))) => PromptOutcome::AllowAlwaysDomain(value),
            _ => PromptOutcome::AllowAlways,
        },
        "reject" => match followup {
            Some(message) => PromptOutcome::FollowupMessage(message.to_owned()),
            None => PromptOutcome::RejectOnce,
        },
        "always_reject" => match scope_kind_value(reply) {
            Some(("bash_command", Some(value))) => PromptOutcome::RejectAlwaysBashCommand(value),
            _ => PromptOutcome::RejectOnce,
        },
        "cancelled" => PromptOutcome::Cancelled,
        _ => PromptOutcome::RejectOnce,
    }
}
fn scope_kind_value(reply: &Value) -> Option<(&str, Option<String>)> {
    let scope = reply.get("scope")?;
    let kind = scope.get("kind").and_then(Value::as_str)?;
    let value = scope
        .get("value")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some((kind, value))
}
pub fn access_kind_for_hub_tool(
    kind: Option<fuigo_tools::types::tool::ToolKind>,
    tool_name: &str,
    args: &Value,
) -> Option<AccessKind> {
    if kind == Some(fuigo_tools::types::tool::ToolKind::ActiveAgentMessage) {
        return Some(AccessKind::AgentMessage {
            subagent_id: args
                .get("subagent_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
        });
    }
    access_kind_for_hub_tool_name(tool_name, args)
}
fn access_kind_for_hub_tool_name(tool_name: &str, args: &Value) -> Option<AccessKind> {
    let name = tool_name.rsplit(':').next().unwrap_or(tool_name);
    let name = name.strip_prefix("FuigoBuild:").unwrap_or(name);
    match name {
        "run_terminal_command" | "run_terminal_cmd" | "bash" | "shell" => {
            let cmd = args
                .get("command")
                .or_else(|| args.get("full_command"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            Some(AccessKind::Bash(cmd))
        }
        "search_replace" | "hashline_edit" | "edit" => {
            let path = args
                .get("file_path")
                .or_else(|| args.get("filePath"))
                .or_else(|| args.get("path"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned();
            Some(AccessKind::Edit(path))
        }
        "write" | "write_file" => {
            let path = args
                .get("file_path")
                .or_else(|| args.get("filePath"))
                .or_else(|| args.get("path"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned();
            Some(AccessKind::Edit(path))
        }
        "apply_patch" => Some(crate::permission::types::apply_patch_hub_access(args)),
        // P165 (S1): side-effecting tools are gated here too, as they are in the shell.
        "scheduler_create" | "scheduler_delete" | "image_gen" | "image_edit" | "image_to_video"
        | "reference_to_video" => Some(AccessKind::Tool(name.to_owned())),
        // A workflow dry run (`validate_only`) is a read, ungated like the other reads; anything else, including
        // arguments that do not parse, is gated (fail closed).
        "workflow" => match serde_json::from_value::<
            fuigo_tools::implementations::fuigo_build::workflow::WorkflowToolInput,
        >(args.clone())
        {
            Ok(input)
                if matches!(
                    crate::permission::types::workflow_access(&input),
                    AccessKind::Read(_)
                ) =>
            {
                None
            }
            _ => Some(AccessKind::Tool("workflow".to_owned())),
        },
        fuigo_tools::implementations::fuigo_build::SEND_SUBAGENT_MESSAGE_TOOL_NAME => {
            Some(AccessKind::AgentMessage {
                subagent_id: args
                    .get("subagent_id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
            })
        }
        "task" | "Task" | "spawn_subagent" => {
            let kind = args
                .get("subagent_type")
                .and_then(Value::as_str)
                .unwrap_or("task");
            Some(AccessKind::Edit(format!("task:{kind}")))
        }
        "web_fetch" => {
            let url = args
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            Some(AccessKind::WebFetch(url))
        }
        n if n.contains("__") || n.starts_with("mcp") => Some(AccessKind::MCPTool {
            name: tool_name.to_owned(),
            input: args.clone(),
        }),
        _ => None,
    }
}
/// Name-based accesses of a hub-routed call, for the local policy: the gated access of [`access_kind_for_hub_tool`],
/// a `Read`/`Grep` per path for the read tools (every `read_file` `files[]` entry included), and an `Edit` per target
/// of an `apply_patch` patch (P173). The handler adds the toolset's own classification of the parsed input on top
/// ([`AccessKind::from`]); this list only ever adds accesses to judge, so a spelling it does not know costs nothing.
pub(crate) fn hub_policy_accesses(
    kind: Option<fuigo_tools::types::tool::ToolKind>,
    tool_name: &str,
    args: &Value,
) -> Vec<AccessKind> {
    let mut out: Vec<AccessKind> = access_kind_for_hub_tool(kind, tool_name, args)
        .into_iter()
        .collect();
    let str_arg = |keys: &[&str]| {
        keys.iter()
            .find_map(|k| args.get(*k).and_then(Value::as_str))
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let name = tool_name.rsplit(':').next().unwrap_or(tool_name);
    match name {
        "read_file" | "read" => {
            let mut paths: Vec<String> = ["target_file", "file_path", "filePath", "path"]
                .iter()
                .filter_map(|k| str_arg(&[k]))
                .collect();
            if let Some(files) = args.get("files").and_then(Value::as_array) {
                paths.extend(
                    files
                        .iter()
                        .filter_map(|f| f.get("path").and_then(Value::as_str))
                        .map(str::to_owned),
                );
            }
            if paths.is_empty() {
                out.push(AccessKind::Read(None));
            }
            out.extend(paths.into_iter().map(|p| AccessKind::Read(Some(p))));
        }
        "list_dir" => out.push(AccessKind::Read(str_arg(&[
            "target_directory",
            "dir_path",
            "path",
        ]))),
        "memory_get" => out.push(AccessKind::Read(str_arg(&["path"]))),
        "lsp" => out.push(AccessKind::Read(str_arg(&["file_path", "filePath"]))),
        "grep" | "grep_files" | "glob" => out.push(AccessKind::Grep {
            path: str_arg(&["path"]),
            glob: str_arg(&["glob", "include"]),
        }),
        // P184: a patch is judged per target. The prompt access (every target joined, or the placeholder) names no
        // file, so it is not judged; a patch that does not parse is refused ([`hub_patch_targets_by_name`]).
        "apply_patch" => {
            out.retain(|a| !matches!(a, AccessKind::Edit(_)));
            if let Some(Ok(paths)) = hub_patch_targets_by_name(tool_name, args) {
                out.extend(paths.into_iter().map(AccessKind::Edit));
            }
        }
        _ => {}
    }
    out
}

/// The files a hub call's `apply_patch` writes, judged per file exactly as a local `apply_patch` is (P184): the
/// targets of [`crate::permission::types::apply_patch_edit_targets`], or why the patch is refused (it does not
/// parse, or writes nothing), as the local permission manager refuses it.
fn patch_targets_or_refusal(targets: EditTargets) -> Result<Vec<String>, String> {
    match targets {
        EditTargets::Paths(paths) if !paths.is_empty() => Ok(paths),
        EditTargets::Paths(_) => Err("the patch has no file operations".to_owned()),
        EditTargets::Unparseable(message) => Err(message),
    }
}

/// [`patch_targets_or_refusal`] of a parsed hub call; `None` when the call is not an `apply_patch`.
pub(crate) fn hub_patch_targets(
    input: &fuigo_tools::types::ToolInput,
) -> Option<Result<Vec<String>, String>> {
    crate::permission::types::edit_targets_for(input).map(patch_targets_or_refusal)
}

/// [`patch_targets_or_refusal`] of a call known only by name (a generic tool, or one the toolset does not know) named
/// `apply_patch`, read from its arguments in any envelope the tool accepts; `None` for any other name.
pub(crate) fn hub_patch_targets_by_name(
    tool_name: &str,
    args: &Value,
) -> Option<Result<Vec<String>, String>> {
    if tool_name.rsplit(':').next().unwrap_or(tool_name) != "apply_patch" {
        return None;
    }
    let input = serde_json::from_value::<
        fuigo_tools::implementations::codex::apply_patch::ApplyPatchInput,
    >(args.clone());
    Some(match input {
        Ok(input) => patch_targets_or_refusal(crate::permission::types::apply_patch_edit_targets(
            &input.patch,
        )),
        Err(e) => Err(format!("Invalid patch: {e}")),
    })
}

/// Accesses of a call as the toolset parsed it (after parameter renames, for the implementation behind the name): the
/// local classification [`AccessKind::from`], plus what that single access cannot carry: every entry of a multi-file
/// read and every target of a patch (P173).
pub(crate) fn hub_input_accesses(input: &fuigo_tools::types::ToolInput) -> Vec<AccessKind> {
    use fuigo_tools::types::ToolInput;
    let mut out = vec![AccessKind::from(input)];
    match input {
        ToolInput::ReadFile(r) => out.extend(
            r.files
                .iter()
                .flatten()
                .map(|f| AccessKind::Read(Some(f.path.clone()))),
        ),
        ToolInput::CodexReadFile(r) => out.extend(
            r.files
                .iter()
                .flatten()
                .map(|f| AccessKind::Read(Some(f.path.clone()))),
        ),
        // A patch is judged by its real targets alone (Astra r3 L), as P184 judges a local one; one that does not
        // parse has none and is refused before any access is judged ([`hub_patch_targets`]).
        ToolInput::ApplyPatch(p) => {
            out = match crate::permission::types::apply_patch_edit_targets(&p.patch) {
                EditTargets::Paths(paths) => paths.into_iter().map(AccessKind::Edit).collect(),
                EditTargets::Unparseable(_) => Vec::new(),
            };
        }
        _ => {}
    }
    out
}

/// Whether the toolset's classification of a parsed call is generic (a runtime-registered or MCP tool), so the
/// name-based accesses of [`hub_policy_accesses`] are added to it. A typed built-in is judged by its parsed input alone.
pub(crate) fn hub_input_is_generic(input: &fuigo_tools::types::ToolInput) -> bool {
    matches!(
        input,
        fuigo_tools::types::ToolInput::MCPTool(_) | fuigo_tools::types::ToolInput::Dynamic(_)
    )
}

/// Why a hub-routed call needs the user's approval.
pub(crate) mod hub_ask_reason {
    pub(crate) const ASK_RULE: &str = "an ask rule matches it";
    pub(crate) const SHELL_GATE: &str = "a shell command rule or the shell gate asks for it";
    pub(crate) const PROTECTED_PATH: &str = "it writes a protected path";
    pub(crate) const SIDE_EFFECTING_TOOL: &str = "it is a side-effecting tool";
    pub(crate) const SEARCH_COVERS_ASK: &str = "the search would read files an ask rule covers";
    pub(crate) const DEFAULT_PROMPT: &str =
        "the local policy would prompt for it and FUIGO_HITL_PERMISSION_LIVE is set";
}

/// What the workspace's local permission policy says about one hub-routed access (P173).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HubPolicyVerdict {
    Allow,
    Deny(String),
    /// Needs the user's approval through the hub permission prompt; refused when there is none.
    Ask(&'static str),
}

/// The local state a hub-routed call is judged against.
pub(crate) struct HubPolicyContext<'a> {
    pub(crate) policy: Option<&'a crate::permission::policy::CompiledPolicy>,
    pub(crate) prompt_policy: crate::permission::types::PromptPolicy,
    /// The session's real working directory (path rules and relative paths anchor here).
    pub(crate) cwd: &'a std::path::Path,
    /// The toolset's display cwd ([`fuigo_tools::types::resources::DisplayCwd`]), which the tools resolve model paths
    /// against.
    pub(crate) display_cwd: Option<&'a std::path::Path>,
    /// The session's always-approve state, already clamped by the managed pin.
    pub(crate) yolo: bool,
    /// [`hitl_permission_live_enabled`].
    pub(crate) default_prompts: bool,
    /// The Read-deny patterns the search tools exclude (`--glob !<pattern>`).
    pub(crate) search_excludes: &'a [String],
    /// Whether the search tool behind this call applies `search_excludes` itself (the native grep, codex
    /// `grep_files`, OpenCode `grep` and `glob`). When it does not, the walk does not apply them either.
    pub(crate) search_excludes_applied: bool,
    /// Whether content searches are walked file by file (`hub_search_scope_verdict`): see [`hub_searches_need_walk`].
    pub(crate) walk_searches: bool,
    /// The targets of the call's `apply_patch` patch, as the patch spells them ([`hub_patch_targets`]). An `Edit` of
    /// one of them is judged as P184 judges a local patch target: in every spelling of the file the tool writes
    /// (`cwd.join(path)`, the model's spelling, the physical path), with the protected floor on the written path.
    pub(crate) patch_targets: &'a [String],
    /// Every spelling of each file a read of the call opens (P198), resolved as the reader resolves it
    /// ([`hub_read_spellings`]); a `Read` access whose path is listed is judged in all of them, as a local read is.
    pub(crate) read_spellings: &'a [HubReadSpelling],
}

/// One file a hub-routed read opens, in every spelling the policy must judge (P198; see
/// `GatePreflight::evaluate_read_targets`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HubReadSpelling {
    /// The path as the `Read` access spells it.
    pub(crate) path: String,
    /// The model's spelling first, then the file the reader resolves it to and its symlink target.
    pub(crate) spellings: Vec<String>,
    /// `false` when the file could not be resolved in time: such a read is refused.
    pub(crate) resolved: bool,
}

/// The spellings of every file `targets` opens (P198), each bounded by the local manager's resolve timeout. Nothing
/// is resolved without a policy: with no rules there is nothing to judge.
pub(crate) async fn hub_read_spellings(
    policy_present: bool,
    cwd: &std::path::Path,
    display_cwd: Option<&std::path::Path>,
    targets: Option<&crate::permission::types::ReadTargets>,
) -> Vec<HubReadSpelling> {
    let Some(targets) = targets.filter(|_| policy_present) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(targets.paths.len());
    for path in &targets.paths {
        let (spellings, resolved) = crate::permission::manager::resolve_read_target(
            cwd,
            display_cwd,
            path,
            targets.resolution,
        )
        .await;
        out.push(HubReadSpelling { path: path.clone(), spellings, resolved });
    }
    out
}

/// Whether a config's Read/Grep rules need content searches walked file by file (see
/// [`HubPolicyContext::walk_searches`]): a patterned ask rule, or a patterned deny rule, except an any-depth `**/...`
/// deny when the search tool applies the Read-deny excludes itself (ripgrep then never reads those files). A tool that
/// does not apply them is walked for every patterned deny (Grok #2).
pub(crate) fn hub_searches_need_walk(
    config: &crate::permission::types::PermissionConfig,
    search_excludes_applied: bool,
) -> bool {
    use crate::permission::types::{RuleAction, ToolFilter};
    config.rules.iter().any(|r| {
        matches!(r.tool, ToolFilter::Read | ToolFilter::Grep | ToolFilter::Any)
            && r.pattern.as_deref().is_some_and(|p| {
                r.action == RuleAction::Ask
                    || (r.action == RuleAction::Deny
                        && !(search_excludes_applied && p.starts_with("**/")))
            })
    })
}

/// The directories a content search with `path` could read: the root the search tools resolve
/// (`resolve_model_path`: `~` expanded, quotes stripped, a relative `/{path}` under the cwd remapped, a display-cwd
/// path mapped to the real one), and the plain absolute-or-joined root the codex and OpenCode `grep` use. Both are
/// judged (Grok #1).
fn hub_search_roots(path: Option<&str>, ctx: &HubPolicyContext<'_>) -> Vec<std::path::PathBuf> {
    let raw = path.filter(|p| !p.is_empty());
    let joined = match raw {
        Some(p) if std::path::Path::new(p).is_absolute() => std::path::PathBuf::from(p),
        Some(p) => ctx.cwd.join(p),
        None => ctx.cwd.to_path_buf(),
    };
    let resolved: std::path::PathBuf =
        fuigo_tools::types::resources::resolve_model_path(ctx.cwd, ctx.display_cwd, raw.unwrap_or(""))
            .components()
            .collect();
    let joined: std::path::PathBuf = joined.components().collect();
    let mut roots = vec![resolved];
    if !roots.contains(&joined) {
        roots.push(joined);
    }
    roots
}

/// The stricter of two verdicts: a deny wins, then a need for approval.
fn stricter(a: HubPolicyVerdict, b: HubPolicyVerdict) -> HubPolicyVerdict {
    match (a, b) {
        (d @ HubPolicyVerdict::Deny(_), _) | (_, d @ HubPolicyVerdict::Deny(_)) => d,
        (q @ HubPolicyVerdict::Ask(_), _) | (_, q @ HubPolicyVerdict::Ask(_)) => q,
        _ => HubPolicyVerdict::Allow,
    }
}

/// Judge one hub-routed access by the local policy, in the local permission manager's order (with no session
/// grants, which a hub session does not have). Blocking (the bash default runs the ambient git scan):
/// - a deny rule refuses, in every mode (local deny rules are enforced before always-approve);
/// - the shell gate (a Bash ask rule, or a command it cannot clear against the rules) needs approval in every mode,
///   as locally; so does a protected path. The hub asserts always-approve per session, so unlike a local
///   `--always-approve` it does not waive the protected floor;
/// - under always-approve everything else runs, as locally;
/// - otherwise an ask rule needs approval; a side-effecting tool (P165) needs approval unless an allow rule names it;
/// - what the local manager would prompt for by default (no rule, or a broad allow rule the bash floor defers) is
///   refused under dontAsk, allowed under bypassPermissions, sent to the hub prompt under
///   `FUIGO_HITL_PERMISSION_LIVE`, and otherwise left to the agent on the hub side, which asks its own user;
/// - `prompt_policy` dontAsk refuses, and bypassPermissions allows, whatever would need approval, as locally.
pub(crate) fn hub_policy_verdict(
    access: &AccessKind,
    ctx: &HubPolicyContext<'_>,
) -> HubPolicyVerdict {
    let verdict = hub_access_verdict(access, ctx);
    let AccessKind::Grep { path, glob } = access else {
        return verdict;
    };
    // The search root as the tool resolves it is judged too, not only the literal argument (Grok #1).
    let roots = hub_search_roots(path.as_deref(), ctx);
    let verdict = roots.iter().fold(verdict, |verdict, root| {
        let resolved = AccessKind::Grep {
            path: Some(root.to_string_lossy().into_owned()),
            glob: glob.clone(),
        };
        stricter(verdict, hub_access_verdict(&resolved, ctx))
    });
    // A root that only needs approval still has its files walked: a denied descendant must refuse the search, or
    // approving the prompt would release it (Grok r2).
    if !ctx.walk_searches || matches!(verdict, HubPolicyVerdict::Deny(_)) {
        return verdict;
    }
    let walked = roots
        .iter()
        .map(|root| hub_search_scope_verdict(root, glob.as_deref(), ctx))
        .fold(HubPolicyVerdict::Allow, stricter);
    // A walk's need for approval goes through `prompt_policy` like any explicit ask.
    let walked = match walked {
        HubPolicyVerdict::Ask(reason) => settle_prompt_policy(reason, ctx),
        other => other,
    };
    stricter(verdict, walked)
}

/// An explicit need for approval under `prompt_policy`: dontAsk refuses, bypassPermissions allows (as locally).
fn settle_prompt_policy(reason: &'static str, ctx: &HubPolicyContext<'_>) -> HubPolicyVerdict {
    use crate::permission::types::PromptPolicy;
    match ctx.prompt_policy {
        PromptPolicy::Deny => {
            HubPolicyVerdict::Deny("denied by prompt policy (tool not pre-approved)".to_owned())
        }
        PromptPolicy::Allow => HubPolicyVerdict::Allow,
        PromptPolicy::Ask | PromptPolicy::Auto => HubPolicyVerdict::Ask(reason),
    }
}

fn hub_access_verdict(access: &AccessKind, ctx: &HubPolicyContext<'_>) -> HubPolicyVerdict {
    use crate::permission::types::{Decision, PromptPolicy};
    const DONT_ASK: &str = "denied by prompt policy (tool not pre-approved)";
    use crate::permission::gate_preflight::{EditTargetSpellings, GatePreflight};
    let patch_target = match access {
        AccessKind::Edit(path) if ctx.patch_targets.contains(path) => {
            Some(EditTargetSpellings::new(ctx.cwd, path))
        }
        _ => None,
    };
    let preflight = match &patch_target {
        Some(target) => {
            GatePreflight::evaluate_edit_targets(ctx.policy, std::slice::from_ref(target), ctx.cwd)
        }
        None if !ctx.read_spellings.is_empty() => {
            // P198 r2: every file the tool reads is judged in every spelling, whatever the access kind (an image tool is an
            // `AccessKind::Tool`), as the local manager does. A `Read` whose path the table lacks cannot be judged in the
            // reader's spellings: it fails closed as unresolved.
            let mut targets: Vec<(Vec<String>, bool)> = ctx
                .read_spellings
                .iter()
                .map(|r| (r.spellings.clone(), r.resolved))
                .collect();
            if let AccessKind::Read(Some(path)) = access
                && !ctx.read_spellings.iter().any(|r| r.path == *path)
            {
                targets.push((vec![path.clone()], false));
            }
            GatePreflight::evaluate_read_targets(ctx.policy, access, &targets, ctx.cwd, false)
        }
        None => GatePreflight::evaluate(ctx.policy, access, ctx.cwd, false),
    };
    let protected = match &patch_target {
        Some(target) => crate::permission::shell_access::edit_target_protection(
            std::path::Path::new(&target.written),
        )
        .is_some(),
        None => crate::permission::manager::hub_protected_target(access, ctx.cwd).is_some(),
    };
    let decision = preflight.policy_decision();
    if let Some(Decision::Reject(reason) | Decision::PolicyDeny(reason)) = &decision {
        return HubPolicyVerdict::Deny(reason.clone());
    }
    let explicit_ask = if preflight.shell_forced_prompt() {
        Some(hub_ask_reason::SHELL_GATE)
    } else if protected {
        Some(hub_ask_reason::PROTECTED_PATH)
    } else if ctx.yolo {
        return HubPolicyVerdict::Allow;
    } else if preflight.policy_forced_prompt() {
        Some(hub_ask_reason::ASK_RULE)
    } else if matches!(access, AccessKind::Tool(_))
        && !matches!(decision, Some(Decision::Allow))
    {
        Some(hub_ask_reason::SIDE_EFFECTING_TOOL)
    } else {
        None
    };
    if let Some(reason) = explicit_ask {
        return settle_prompt_policy(reason, ctx);
    }
    let policy_allows = matches!(decision, Some(Decision::Allow));
    if !crate::permission::manager::hub_needs_default_prompt(access, ctx.policy, policy_allows, ctx.cwd) {
        return HubPolicyVerdict::Allow;
    }
    match ctx.prompt_policy {
        PromptPolicy::Deny => HubPolicyVerdict::Deny(DONT_ASK.to_owned()),
        PromptPolicy::Allow => HubPolicyVerdict::Allow,
        PromptPolicy::Ask | PromptPolicy::Auto if ctx.default_prompts => {
            HubPolicyVerdict::Ask(hub_ask_reason::DEFAULT_PROMPT)
        }
        PromptPolicy::Ask | PromptPolicy::Auto => HubPolicyVerdict::Allow,
    }
}

/// [`hub_policy_verdict`] over every access of one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HubCallVerdict {
    /// The first access the policy refuses, which refuses the whole call.
    pub(crate) denied: Option<(String, usize)>,
    /// Every access that needs approval (reason, index), each asked for on its own, deduplicated: approving one
    /// target never releases another (Astra r3 H).
    pub(crate) asks: Vec<(&'static str, usize)>,
}

pub(crate) fn hub_policy_verdict_all(
    accesses: &[AccessKind],
    ctx: &HubPolicyContext<'_>,
) -> HubCallVerdict {
    let mut asks: Vec<(&'static str, usize)> = Vec::new();
    let mut asked: Vec<String> = Vec::new();
    for (i, access) in accesses.iter().enumerate() {
        match hub_policy_verdict(access, ctx) {
            HubPolicyVerdict::Deny(reason) => {
                return HubCallVerdict {
                    denied: Some((reason, i)),
                    asks: Vec::new(),
                };
            }
            HubPolicyVerdict::Ask(reason) => {
                let key = format!("{access:?}");
                if !asked.contains(&key) {
                    asked.push(key);
                    asks.push((reason, i));
                }
            }
            HubPolicyVerdict::Allow => {}
        }
    }
    HubCallVerdict { denied: None, asks }
}

/// Astra r3 G/J: a content search under a permitted root reads every file below it. Walk what ripgrep would search
/// (ripgrep's own walker, with the same `--glob` overrides the search tool passes: the caller's glob and, when the tool
/// applies them, the Read-deny excludes) and judge every file as a search of it with the policy's own path matcher: a file a deny rule covers refuses the search,
/// one an ask rule covers needs approval (waived under always-approve, as locally). Hidden files are walked too, which
/// covers every backend. Past `SEARCH_WALK_CAP` entries, or with a glob ripgrep cannot parse, the search is refused.
fn hub_search_scope_verdict(
    root: &std::path::Path,
    glob: Option<&str>,
    ctx: &HubPolicyContext<'_>,
) -> HubPolicyVerdict {
    hub_search_scope_verdict_capped(root, glob, ctx, SEARCH_WALK_CAP)
}

/// Entries a search walk visits before it gives up.
const SEARCH_WALK_CAP: usize = 100_000;

/// [`hub_search_scope_verdict`] with the walk cap as a parameter (tests use a small one).
fn hub_search_scope_verdict_capped(
    root: &std::path::Path,
    glob: Option<&str>,
    ctx: &HubPolicyContext<'_>,
    walk_cap: usize,
) -> HubPolicyVerdict {
    use crate::permission::types::Decision;
    // Only excludes the search tool itself applies may shrink the walk (Grok #2).
    let excludes: &[String] = if ctx.search_excludes_applied {
        ctx.search_excludes
    } else {
        &[]
    };
    // Rooted at the search directory, as ripgrep reads `--glob` relative to the directory it searches.
    let mut overrides = ignore::overrides::OverrideBuilder::new(root);
    let mut add = |g: &str| overrides.add(g).map(|_| ());
    let added = glob
        .filter(|g| !g.is_empty())
        .map_or(Ok(()), &mut add)
        .and_then(|()| excludes.iter().try_for_each(|deny| add(&format!("!{deny}"))));
    // A walk that cannot finish cannot show the search reads nothing denied: refuse it (Grok r2).
    let Ok(overrides) = added.and_then(|()| overrides.build()) else {
        return HubPolicyVerdict::Deny(
            "the search glob could not be checked against the local Read rules; narrow or fix the glob".to_owned(),
        );
    };
    let mut walker = ignore::WalkBuilder::new(root);
    walker
        .hidden(false)
        .follow_links(false)
        // A caller glob overrides ignore files in ripgrep, so it can reach ignored files: walk those too.
        .standard_filters(glob.is_none_or(str::is_empty))
        .hidden(false)
        .overrides(overrides);
    let mut asks = false;
    for (seen, entry) in walker.build().flatten().enumerate() {
        if seen >= walk_cap {
            return HubPolicyVerdict::Deny(format!(
                "the search covers more than {walk_cap} entries, too many to check against the local Read rules; narrow the path or glob"
            ));
        }
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let file = entry.path().to_string_lossy().into_owned();
        // Judged as the search it is: Grep rules match it, and Read rules match a Grep access too (Grok #4).
        let searched = AccessKind::Grep {
            path: Some(file.clone()),
            glob: None,
        };
        match crate::permission::gate_preflight::GatePreflight::evaluate(ctx.policy, &searched, ctx.cwd, false)
            .policy_decision()
        {
            Some(Decision::Reject(_) | Decision::PolicyDeny(_)) => {
                return HubPolicyVerdict::Deny(format!(
                    "the search would read {file}, which the local policy denies reading; narrow the path or glob"
                ));
            }
            Some(Decision::Ask) => asks = true,
            _ => {}
        }
    }
    if asks && !ctx.yolo {
        HubPolicyVerdict::Ask(hub_ask_reason::SEARCH_COVERS_ASK)
    } else {
        HubPolicyVerdict::Allow
    }
}

/// Settle every access of one call that needs approval, each on its own prompt and in order; the first refusal
/// refuses the call (Astra r3 H). `prompt_accesses[i]` is what the prompt shows for `accesses[i]` (the model view).
pub(crate) async fn settle_hub_asks(
    transport: Option<&dyn PermissionHookTransport>,
    asks: &[(&'static str, usize)],
    accesses: &[AccessKind],
    prompt_accesses: &[AccessKind],
    tool_call_id: &str,
    tool_name: &str,
) -> Result<(), fuigo_tool_runtime::ToolError> {
    for &(reason, index) in asks {
        let prompt_access = prompt_accesses.get(index).unwrap_or(&accesses[index]);
        settle_hub_ask(transport, prompt_access, tool_call_id, tool_name, reason).await?;
    }
    Ok(())
}

/// Settle a hub-routed call that needs approval: ask through the hub permission prompt, or refuse when there is no
/// prompt to ask through. Never runs the call silently (P173).
pub(crate) async fn settle_hub_ask(
    transport: Option<&dyn PermissionHookTransport>,
    access: &AccessKind,
    tool_call_id: &str,
    tool_name: &str,
    reason: &str,
) -> Result<(), fuigo_tool_runtime::ToolError> {
    use fuigo_tool_runtime::{ToolError, ToolErrorKind};
    let Some(transport) = transport else {
        tracing::warn!(
            tool = %tool_name,
            reason,
            "hub tool call needs approval under the local permission policy, but there is no hub permission prompt; refusing"
        );
        return Err(ToolError::new(
            ToolErrorKind::PermissionDenied,
            format!(
                "tool permission unavailable: {tool_name} needs approval because {reason}, and no hub permission prompt is available"
            ),
        ));
    };
    let outcome = request_permission_via_hub(transport, access, tool_call_id, None).await;
    if prompt_outcome_allows(&outcome) {
        return Ok(());
    }
    tracing::info!(
        tool = %tool_name,
        call_id = %tool_call_id,
        ?outcome,
        "tool-permission denied via hub; rejecting tool call"
    );
    let detail = match &outcome {
        PromptOutcome::FollowupMessage(msg) => format!("tool permission redirected: {msg}"),
        _ => format!("tool permission denied for {tool_name}"),
    };
    Err(ToolError::new(ToolErrorKind::PermissionDenied, detail))
}

pub fn prompt_outcome_allows(outcome: &PromptOutcome) -> bool {
    matches!(
        outcome,
        PromptOutcome::AllowOnce
            | PromptOutcome::AllowAlways
            | PromptOutcome::AllowEditsForSession
            | PromptOutcome::AllowAlwaysBashCommand(_)
            | PromptOutcome::AllowAlwaysBashGlob(_)
            | PromptOutcome::AllowAlwaysDomain(_)
            | PromptOutcome::AllowAlwaysMcpTool(_)
            | PromptOutcome::AllowAlwaysMcpServer(_)
    )
}
pub async fn request_permission_via_hub(
    transport: &dyn PermissionHookTransport,
    access: &AccessKind,
    tool_call_id: &str,
    hook_ask: Option<&HookAsk>,
) -> PromptOutcome {
    let payload = build_permission_payload(access, tool_call_id, hook_ask);
    match transport.request_permission(payload).await {
        Ok(reply) => match reply_to_outcome(&reply) {
            PromptOutcome::AllowAlways if matches!(access, AccessKind::Edit(_)) => {
                PromptOutcome::AllowEditsForSession
            }
            PromptOutcome::AllowAlways
                if matches!(
                    access,
                    AccessKind::AgentMessage { .. } | AccessKind::Tool(_)
                ) =>
            {
                PromptOutcome::AllowOnce
            }
            other => other,
        },
        Err(e) => {
            tracing::error!(error = %e, "hub permission request failed; rejecting");
            PromptOutcome::Error(format!("hub permission request failed: {e}"))
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    #[test]
    fn is_timeout_err_matches_backstop_wording_only() {
        assert!(is_timeout_err("request timed out after 600s"));
        assert!(is_timeout_err("request timed out after 600.0s"));
        assert!(!is_timeout_err("connection lost"));
        assert!(!is_timeout_err("tool server gone (weak upgrade failed)"));
    }
    #[test]
    fn payload_for_bash_carries_command_and_write_scope() {
        let payload =
            build_permission_payload(&AccessKind::Bash("rm -rf /tmp/x".into()), "tc-1", None);
        assert_eq!(payload["tool_call_id"], "tc-1");
        assert_eq!(payload["tool_name"], "run_terminal_command");
        assert_eq!(payload["description"], "Run a terminal command");
        assert_eq!(payload["scope"], "write");
        assert_eq!(payload["bash_command"], "rm -rf /tmp/x");
        assert!(payload.get("edit_file_paths").is_none());
    }
    #[test]
    fn payload_description_carries_the_hook_ask() {
        let payload = build_permission_payload(
            &AccessKind::Bash("deploy".into()),
            "tc-ask",
            Some(&HookAsk {
                hook_name: "guard".to_owned(),
                reason: Some("confirm this".to_owned()),
            }),
        );
        assert_eq!(
            payload["description"],
            "Run a terminal command — hook 'guard' asks: confirm this"
        );
    }
    #[test]
    fn payload_for_agent_message_has_dedicated_content_free_identity() {
        let payload = build_permission_payload(
            &AccessKind::AgentMessage {
                subagent_id: "sub-1".into(),
            },
            "tc-message",
            None,
        );
        assert_eq!(payload["tool_name"], "send_subagent_message");
        assert_eq!(payload["description"], "Send a message to subagent sub-1");
        assert_eq!(payload["scope"], "write");
        assert_eq!(payload["subagent_id"], "sub-1");
        assert!(payload.get("edit_file_paths").is_none());
        assert!(payload.get("bash_command").is_none());
    }
    #[test]
    fn payload_for_edit_carries_file_paths() {
        let payload =
            build_permission_payload(&AccessKind::Edit("src/main.rs".into()), "tc-2", None);
        assert_eq!(payload["tool_name"], "search_replace");
        assert_eq!(payload["description"], "Edit src/main.rs");
        assert_eq!(payload["scope"], "write");
        assert_eq!(
            payload["edit_file_paths"],
            serde_json::json!(["src/main.rs"])
        );
        assert!(payload.get("bash_command").is_none());
        assert!(payload.get("edit_kind").is_none());
    }
    #[test]
    fn hub_maps_agent_message_without_content() {
        let args = serde_json::json!({
            "subagent_id": "sub-1",
            "text": "private follow-up",
        });
        let Some(AccessKind::AgentMessage { subagent_id }) =
            access_kind_for_hub_tool(None, "send_subagent_message", &args)
        else {
            panic!("expected dedicated agent-message access")
        };
        assert_eq!(subagent_id, "sub-1");
        assert!(!subagent_id.contains("private follow-up"));
    }
    #[test]
    fn hub_gates_edit_and_task() {
        assert!(matches!(
            access_kind_for_hub_tool(
                None,
                "opencode:edit",
                &serde_json::json!({
                    "filePath": "/tmp/denied.txt",
                    "oldString": "ORIGINAL",
                    "newString": "BYPASS",
                }),
            ),
            Some(AccessKind::Edit(p)) if p == "/tmp/denied.txt"
        ));
        for name in ["spawn_subagent", "Task", "task"] {
            assert!(
                matches!(
                    access_kind_for_hub_tool(
                        None,
                        name,
                        &serde_json::json!({
                            "subagent_type": "general-purpose",
                            "prompt": "edit config.toml",
                        }),
                    ),
                    Some(AccessKind::Edit(p)) if p == "task:general-purpose"
                ),
                "hub must gate {name:?}"
            );
        }
    }
    /// P165 (S1): the hub HITL path gates the side-effecting tools too, including their namespaced spellings.
    #[test]
    fn hub_gates_side_effecting_tools() {
        for name in [
            "scheduler_create",
            "scheduler_delete",
            "workflow",
            "image_gen",
            "image_edit",
            "image_to_video",
            "reference_to_video",
        ] {
            for spelling in [name.to_owned(), format!("FuigoBuild:{name}")] {
                let access = access_kind_for_hub_tool(None, &spelling, &serde_json::json!({}));
                assert!(
                    !matches!(
                        access,
                        None | Some(AccessKind::Read(_))
                            | Some(AccessKind::Grep { .. })
                            | Some(AccessKind::WebSearch(_))
                    ),
                    "hub must gate {spelling:?}, got {access:?}"
                );
            }
        }
    }
    /// P165 (Astra r2 MEDIUM): on the hub path too, a workflow dry run is not gated; a launch, a control op, or
    /// arguments that do not parse are.
    #[test]
    fn hub_leaves_workflow_dry_runs_ungated() {
        let validate = serde_json::json!({
            "source": {"type": "script_path", "script_path": "/w/flow.rhai"}, "validate_only": true
        });
        assert!(access_kind_for_hub_tool(None, "workflow", &validate).is_none());
        for args in [
            serde_json::json!({"source": {"type": "script_path", "script_path": "/w/flow.rhai"}}),
            serde_json::json!({"source": {"type": "stop", "run_id": "run-1"}}),
            serde_json::json!({"source": 7, "validate_only": true}),
        ] {
            assert!(
                matches!(
                    access_kind_for_hub_tool(None, "workflow", &args),
                    Some(AccessKind::Tool(ref n)) if n == "workflow"
                ),
                "hub must gate workflow {args}"
            );
        }
    }
    #[test]
    fn payload_for_mcp_has_no_tool_context() {
        let payload = build_permission_payload(
            &AccessKind::MCPTool {
                name: "linear__list".into(),
                input: serde_json::Value::Null,
            },
            "tc-3",
            None,
        );
        assert_eq!(payload["tool_name"], "mcp:linear__list");
        assert_eq!(payload["description"], "Run MCP tool linear__list");
        assert_eq!(payload["scope"], "write");
        assert!(payload.get("bash_command").is_none());
        assert!(payload.get("edit_file_paths").is_none());
    }
    #[test]
    fn reply_outcomes_map_to_prompt_outcomes() {
        assert!(matches!(
            reply_to_outcome(&serde_json::json!({ "outcome": "approve" })),
            PromptOutcome::AllowOnce
        ));
        assert!(matches!(
            reply_to_outcome(&serde_json::json!({ "outcome": "reject" })),
            PromptOutcome::RejectOnce
        ));
        assert!(matches!(
            reply_to_outcome(&serde_json::json!({ "outcome": "cancelled" })),
            PromptOutcome::Cancelled
        ));
        assert!(matches!(
            reply_to_outcome(&serde_json::json!({ "outcome": "unspecified" })),
            PromptOutcome::RejectOnce
        ));
        assert!(matches!(
            reply_to_outcome(&serde_json::json!({})),
            PromptOutcome::RejectOnce
        ));
    }
    #[test]
    fn reject_with_followup_routes_message_to_model() {
        let reply =
            serde_json::json!({ "outcome": "reject", "followup_message": "use cargo instead" });
        match reply_to_outcome(&reply) {
            PromptOutcome::FollowupMessage(m) => assert_eq!(m, "use cargo instead"),
            other => panic!("expected FollowupMessage, got {other:?}"),
        }
    }
    #[test]
    fn always_approve_maps_scope_to_persistent_outcome() {
        let bash = serde_json::json!({
            "outcome": "always_approve",
            "scope": { "kind": "bash_command", "value": "cargo build" },
        });
        match reply_to_outcome(&bash) {
            PromptOutcome::AllowAlwaysBashCommand(v) => assert_eq!(v, "cargo build"),
            other => panic!("expected AllowAlwaysBashCommand, got {other:?}"),
        }
        let server = serde_json::json!({
            "outcome": "always_approve",
            "scope": { "kind": "server_prefix", "value": "linear" },
        });
        match reply_to_outcome(&server) {
            PromptOutcome::AllowAlwaysMcpServer(v) => assert_eq!(v, "linear"),
            other => panic!("expected AllowAlwaysMcpServer, got {other:?}"),
        }
        assert!(matches!(
            reply_to_outcome(&serde_json::json!({ "outcome": "always_approve" })),
            PromptOutcome::AllowAlways
        ));
    }
    #[test]
    fn always_reject_with_bash_scope_persists_the_denied_prefix() {
        let reply = serde_json::json!({
            "outcome": "always_reject",
            "scope": { "kind": "bash_command", "value": "curl" },
        });
        match reply_to_outcome(&reply) {
            PromptOutcome::RejectAlwaysBashCommand(v) => assert_eq!(v, "curl"),
            other => panic!("expected RejectAlwaysBashCommand, got {other:?}"),
        }
    }
    struct StubTransport {
        reply: Result<Value, String>,
        seen: Mutex<Option<Value>>,
    }
    #[async_trait]
    impl PermissionHookTransport for StubTransport {
        async fn request_permission(&self, payload: Value) -> Result<Value, String> {
            *self.seen.lock().unwrap() = Some(payload);
            self.reply.clone()
        }
    }
    #[tokio::test]
    async fn request_sends_payload_and_decodes_reply() {
        let transport = StubTransport {
            reply: Ok(serde_json::json!({ "outcome": "approve" })),
            seen: Mutex::new(None),
        };
        let outcome = request_permission_via_hub(
            &transport,
            &AccessKind::Bash("ls -la".into()),
            "tc-7",
            None,
        )
        .await;
        assert!(matches!(outcome, PromptOutcome::AllowOnce));
        let seen = transport
            .seen
            .lock()
            .unwrap()
            .clone()
            .expect("payload sent");
        assert_eq!(seen["tool_call_id"], "tc-7");
        assert_eq!(seen["bash_command"], "ls -la");
    }
    #[tokio::test]
    async fn transport_error_fails_closed() {
        let transport = StubTransport {
            reply: Err("connection lost".to_owned()),
            seen: Mutex::new(None),
        };
        let outcome =
            request_permission_via_hub(&transport, &AccessKind::Edit("a.rs".into()), "tc-8", None)
                .await;
        assert!(matches!(outcome, PromptOutcome::Error(_)));
    }
    #[tokio::test]
    async fn edit_always_approve_maps_to_session_scope() {
        let transport = StubTransport {
            reply: Ok(serde_json::json!({ "outcome": "always_approve" })),
            seen: Mutex::new(None),
        };
        let outcome =
            request_permission_via_hub(&transport, &AccessKind::Edit("a.rs".into()), "tc-9", None)
                .await;
        assert!(matches!(outcome, PromptOutcome::AllowEditsForSession));
        let transport = StubTransport {
            reply: Ok(serde_json::json!({ "outcome": "always_approve" })),
            seen: Mutex::new(None),
        };
        let outcome = request_permission_via_hub(
            &transport,
            &AccessKind::AgentMessage {
                subagent_id: "sub-1".into(),
            },
            "tc-message",
            None,
        )
        .await;
        assert!(matches!(outcome, PromptOutcome::AllowOnce));
        let transport = StubTransport {
            reply: Ok(serde_json::json!({ "outcome": "always_approve" })),
            seen: Mutex::new(None),
        };
        let outcome = request_permission_via_hub(
            &transport,
            &AccessKind::MCPTool {
                name: "x".into(),
                input: serde_json::Value::Null,
            },
            "tc-10",
            None,
        )
        .await;
        assert!(matches!(outcome, PromptOutcome::AllowAlways));
    }
    // ---- P173: local policy for hub-routed calls ----

    fn compiled(toml: &str) -> crate::permission::policy::CompiledPolicy {
        let value: toml::Value = toml::from_str(toml).expect("toml");
        let rules = crate::permission::resolution::parse_toml_permission_section_for_test(
            value.get("permission").expect("[permission]"),
        );
        crate::permission::policy::CompiledPolicy::new(crate::permission::types::PermissionConfig::new(
            rules,
        ))
    }

    fn ctx<'a>(
        policy: Option<&'a crate::permission::policy::CompiledPolicy>,
        cwd: &'a std::path::Path,
        yolo: bool,
        default_prompts: bool,
    ) -> HubPolicyContext<'a> {
        HubPolicyContext {
            policy,
            prompt_policy: crate::permission::types::PromptPolicy::Ask,
            cwd,
            display_cwd: None,
            yolo,
            default_prompts,
            search_excludes: &[],
            search_excludes_applied: false,
            walk_searches: false,
            patch_targets: &[],
            read_spellings: &[],
        }
    }

    #[test]
    fn hub_verdict_follows_the_local_order() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        let policy = compiled(
            "[permission]\ndeny = [\"Bash(rm *)\"]\nask = [\"Bash(git push*)\", \"scheduler_delete\"]\nallow = [\"image_gen\"]\n",
        );
        let bash = |c: &str| AccessKind::Bash(c.to_owned());
        let hook = AccessKind::Edit(cwd.join(".git/hooks/pre-commit").to_string_lossy().into_owned());
        let plain_edit = AccessKind::Edit(cwd.join("notes.txt").to_string_lossy().into_owned());
        let tool = |n: &str| AccessKind::Tool(n.to_owned());
        for yolo in [false, true] {
            for default_prompts in [false, true] {
                let c = ctx(Some(&policy), cwd, yolo, default_prompts);
                let label = format!("yolo={yolo} default_prompts={default_prompts}");
                assert!(
                    matches!(hub_policy_verdict(&bash("rm -rf x"), &c), HubPolicyVerdict::Deny(_)),
                    "deny rule refuses: {label}"
                );
                assert_eq!(
                    hub_policy_verdict(&hook, &c),
                    HubPolicyVerdict::Ask(hub_ask_reason::PROTECTED_PATH),
                    "protected path needs approval: {label}"
                );
                assert_eq!(
                    hub_policy_verdict(&tool("image_gen"), &c),
                    HubPolicyVerdict::Allow,
                    "a bare allow rule pre-approves a side-effecting tool: {label}"
                );
                assert_eq!(
                    hub_policy_verdict(&AccessKind::Read(Some("a.rs".into())), &c),
                    HubPolicyVerdict::Allow,
                    "reads run: {label}"
                );
            }
            // A Bash ask rule goes through the bash command gate, which always-approve does not waive (as locally).
            let c = ctx(Some(&policy), cwd, yolo, false);
            assert_eq!(
                hub_policy_verdict(&bash("git push origin main"), &c),
                HubPolicyVerdict::Ask(hub_ask_reason::SHELL_GATE),
                "yolo={yolo}"
            );
            // Any other ask rule, and a side-effecting tool: approval unless always-approve (as locally).
            let expect = |reason| {
                if yolo {
                    HubPolicyVerdict::Allow
                } else {
                    HubPolicyVerdict::Ask(reason)
                }
            };
            assert_eq!(
                hub_policy_verdict(&tool("scheduler_delete"), &c),
                expect(hub_ask_reason::ASK_RULE)
            );
            assert_eq!(
                hub_policy_verdict(&tool("scheduler_create"), &c),
                expect(hub_ask_reason::SIDE_EFFECTING_TOOL)
            );
            // Default prompts only with the flag, never under always-approve.
            assert_eq!(hub_policy_verdict(&plain_edit, &c), HubPolicyVerdict::Allow);
            assert_eq!(hub_policy_verdict(&bash("ls"), &c), HubPolicyVerdict::Allow);
            let flagged = ctx(Some(&policy), cwd, yolo, true);
            assert_eq!(
                hub_policy_verdict(&plain_edit, &flagged),
                expect(hub_ask_reason::DEFAULT_PROMPT)
            );
            assert_eq!(
                hub_policy_verdict(&AccessKind::Grep { path: None, glob: None }, &flagged),
                HubPolicyVerdict::Allow
            );
        }
        // No policy at all still has the protected and side-effecting floors.
        let none = ctx(None, cwd, false, false);
        assert_eq!(
            hub_policy_verdict(&hook, &none),
            HubPolicyVerdict::Ask(hub_ask_reason::PROTECTED_PATH)
        );
        assert_eq!(
            hub_policy_verdict(&tool("image_edit"), &none),
            HubPolicyVerdict::Ask(hub_ask_reason::SIDE_EFFECTING_TOOL)
        );
        assert_eq!(hub_policy_verdict(&bash("rm -rf x"), &none), HubPolicyVerdict::Allow);
    }

    /// P166 on the hub path: the shell write classifier's protected targets (Grok r4/r5 writers, redirects, wrapped
    /// commands) reach the same `PROTECTED_PATH` ask through `hub_policy_verdict` as through the local manager, with and
    /// without always-approve and with no policy installed. Ordinary project writes do not.
    #[cfg(unix)]
    #[test]
    fn hub_applies_the_protected_write_floor_to_every_writer() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        std::fs::create_dir_all(cwd.join("src")).unwrap();
        std::fs::create_dir_all(cwd.join("out")).unwrap();
        let bash = |c: &str| AccessKind::Bash(c.to_owned());
        let protected = [
            "patch -o .mcp.json p.diff",
            "git checkout -- .mcp.json",
            "git apply p.diff",
            "pax -rw payload .fuigo",
            "scp evil .mcp.json",
            "tar -xf payload.tar",
            "sed -n 'w .mcp.json' /dev/null",
            "curl -o .mcp.json https://example.com/x",
            "cp evil .mcp.json",
            "tee .fuigo/lsp.json",
            "echo {} > .mcp.json",
            "bash -c 'echo {} > .mcp.json'",
            "sudo cp evil .mcp.json",
            // P166 r7: the class tripwire is the same one Bash floor on the hub path.
            "python3 -c \"open('.mcp.json','w')\"",
            "git config core.hooksPath /tmp/evil-hooks",
            // P166 r8B: attached `-c` and abbreviated `--config-env` redirect hooks and are protected hits on the hub too
            "git -ccore.hooksPath=/tmp/evil commit",
            "git --config-e=core.hooksPath=/tmp/evil commit",
        ];
        let ordinary = ["ls", "git status", "cp src/a.rs out/b.rs", "sed -n 's/a/b/p' in", "echo ok > out/log.txt"];
        for yolo in [false, true] {
            let c = ctx(None, cwd, yolo, false);
            for cmd in protected {
                assert_eq!(
                    hub_policy_verdict(&bash(cmd), &c),
                    HubPolicyVerdict::Ask(hub_ask_reason::PROTECTED_PATH),
                    "yolo={yolo}: {cmd}"
                );
            }
            for cmd in ordinary {
                assert_eq!(hub_policy_verdict(&bash(cmd), &c), HubPolicyVerdict::Allow, "yolo={yolo}: {cmd}");
            }
        }
    }

    #[test]
    fn hub_verdict_honours_prompt_policy_and_shell_gate() {
        use crate::permission::types::PromptPolicy;
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        let policy = compiled("[permission]\ndeny = [\"Bash(rm *)\"]\n");
        let tool = AccessKind::Tool("image_gen".to_owned());
        let mut c = ctx(Some(&policy), cwd, false, false);
        c.prompt_policy = PromptPolicy::Deny;
        assert!(matches!(hub_policy_verdict(&tool, &c), HubPolicyVerdict::Deny(_)));
        c.prompt_policy = PromptPolicy::Allow;
        assert_eq!(hub_policy_verdict(&tool, &c), HubPolicyVerdict::Allow);
        assert!(
            matches!(
                hub_policy_verdict(&AccessKind::Bash("rm -rf x".into()), &c),
                HubPolicyVerdict::Deny(_)
            ),
            "bypassPermissions never waives a deny rule"
        );
        // A command the shell gate cannot decompose against the deny rule needs approval, even under always-approve.
        for yolo in [false, true] {
            let c = ctx(Some(&policy), cwd, yolo, false);
            assert_eq!(
                hub_policy_verdict(&AccessKind::Bash("echo \"$(date)\"".into()), &c),
                HubPolicyVerdict::Ask(hub_ask_reason::SHELL_GATE),
                "yolo={yolo}"
            );
        }
    }

    /// Astra r1: what the local manager prompts for by default is refused under dontAsk with or without the flag, and a
    /// broad allow rule the bash floor defers still prompts under the flag; safe commands and reads run.
    #[test]
    fn hub_verdict_follows_local_default_prompts() {
        use crate::permission::types::PromptPolicy;
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        let edit = AccessKind::Edit(cwd.join("notes.txt").to_string_lossy().into_owned());
        let read = AccessKind::Read(Some("notes.txt".into()));
        for default_prompts in [false, true] {
            let mut c = ctx(None, cwd, false, default_prompts);
            c.prompt_policy = PromptPolicy::Deny;
            assert!(
                matches!(hub_policy_verdict(&edit, &c), HubPolicyVerdict::Deny(_)),
                "dontAsk refuses an unapproved edit (flag={default_prompts})"
            );
            assert_eq!(hub_policy_verdict(&AccessKind::Bash("ls".into()), &c), HubPolicyVerdict::Allow);
            assert_eq!(hub_policy_verdict(&read, &c), HubPolicyVerdict::Allow);
        }
        let broad = compiled("[permission]\nallow = [\"Bash(*)\"]\n");
        let redirect = AccessKind::Bash("echo x > notes.txt".into());
        assert_eq!(
            hub_policy_verdict(&redirect, &ctx(Some(&broad), cwd, false, true)),
            HubPolicyVerdict::Ask(hub_ask_reason::DEFAULT_PROMPT),
            "the bash floor defers a broad allow, as locally"
        );
        assert_eq!(
            hub_policy_verdict(&redirect, &ctx(Some(&broad), cwd, false, false)),
            HubPolicyVerdict::Allow
        );
        assert_eq!(
            hub_policy_verdict(&AccessKind::Bash("ls".into()), &ctx(Some(&broad), cwd, false, true)),
            HubPolicyVerdict::Allow
        );
    }

    /// Astra r2 C: `git status` in a repository whose config runs a program is not a safe command for the hub either.
    #[test]
    fn hub_default_prompt_runs_the_ambient_git_scan() {
        use crate::permission::types::PromptPolicy;
        let risky = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(risky.path()).unwrap();
        repo.config().unwrap().set_str("core.fsmonitor", "/bin/true").unwrap();
        let clean = tempfile::tempdir().unwrap();
        git2::Repository::init(clean.path()).unwrap();
        let status = AccessKind::Bash("git status".into());
        assert_eq!(
            hub_policy_verdict(&status, &ctx(None, risky.path(), false, true)),
            HubPolicyVerdict::Ask(hub_ask_reason::DEFAULT_PROMPT)
        );
        let mut dont_ask = ctx(None, risky.path(), false, false);
        dont_ask.prompt_policy = PromptPolicy::Deny;
        assert!(matches!(hub_policy_verdict(&status, &dont_ask), HubPolicyVerdict::Deny(_)));
        assert_eq!(
            hub_policy_verdict(&status, &ctx(None, clean.path(), false, true)),
            HubPolicyVerdict::Allow,
            "plain git status in a clean repository stays a safe command"
        );
    }

    /// Astra r3 H: every access that needs approval is asked for on its own (deduplicated), so approving one target
    /// never releases another.
    #[test]
    fn hub_verdict_all_asks_for_every_target() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        let policy = compiled("[permission]\nask = [\"Edit(**/notes.txt)\"]\n");
        let c = ctx(Some(&policy), cwd, false, false);
        let notes = AccessKind::Edit(cwd.join("notes.txt").to_string_lossy().into_owned());
        let hook = AccessKind::Edit(cwd.join(".git/hooks/pre-commit").to_string_lossy().into_owned());
        let verdict = hub_policy_verdict_all(&[notes.clone(), hook, notes], &c);
        assert_eq!(verdict.denied, None);
        assert_eq!(
            verdict.asks,
            vec![
                (hub_ask_reason::ASK_RULE, 0),
                (hub_ask_reason::PROTECTED_PATH, 1)
            ]
        );
    }

    /// Astra r3 L: a parsed patch is judged by its real targets, without the `Edit("apply_patch")` sentinel.
    #[test]
    fn parsed_patch_is_judged_by_its_targets_alone() {
        let input = fuigo_tools::types::ToolInput::ApplyPatch(
            fuigo_tools::implementations::codex::apply_patch::ApplyPatchInput {
                patch: "*** Begin Patch\n*** Add File: src/a.rs\n+x\n*** End Patch\n".to_owned(),
            },
        );
        let accesses = hub_input_accesses(&input);
        assert!(
            matches!(accesses.as_slice(), [AccessKind::Edit(p)] if p == "src/a.rs"),
            "{accesses:?}"
        );
        let broken = fuigo_tools::types::ToolInput::ApplyPatch(
            fuigo_tools::implementations::codex::apply_patch::ApplyPatchInput {
                patch: "not a patch".to_owned(),
            },
        );
        // No `Edit("apply_patch")` sentinel: the unparseable patch has no accesses and is refused whole (P184).
        assert!(hub_input_accesses(&broken).is_empty());
        assert!(matches!(hub_patch_targets(&broken), Some(Err(_))));
        assert_eq!(hub_patch_targets(&input), Some(Ok(vec!["src/a.rs".to_owned()])));
    }

    /// Astra r3 G/J: a content search is judged by every file it would read, with the policy's own matcher: an
    /// absolute Read deny the ripgrep excludes cannot express refuses it; a Read ask rule needs approval; files the
    /// excludes already remove do not count.
    #[test]
    fn hub_search_is_judged_by_the_files_it_would_read() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        std::fs::create_dir_all(cwd.join("secrets")).unwrap();
        std::fs::write(cwd.join("secrets/token.txt"), "x").unwrap();
        std::fs::create_dir_all(cwd.join("notes")).unwrap();
        std::fs::write(cwd.join("notes/a.md"), "x").unwrap();
        std::fs::write(cwd.join("open.txt"), "x").unwrap();
        let search = AccessKind::Grep {
            path: None,
            glob: None,
        };
        let abs_deny = compiled(&format!(
            "[permission]\ndeny = [\"Read({}/secrets/**)\"]\n",
            cwd.display()
        ));
        let config = |toml: &str| {
            let value: toml::Value = toml::from_str(toml).unwrap();
            crate::permission::types::PermissionConfig::new(
                crate::permission::resolution::parse_toml_permission_section_for_test(
                    value.get("permission").unwrap(),
                ),
            )
        };
        for applied in [false, true] {
            assert!(hub_searches_need_walk(
                &config(&format!(
                    "[permission]\ndeny = [\"Read({}/secrets/**)\"]\n",
                    cwd.display()
                )),
                applied
            ));
        }
        let mut c = ctx(Some(&abs_deny), cwd, false, false);
        c.walk_searches = true;
        assert!(
            matches!(hub_policy_verdict(&search, &c), HubPolicyVerdict::Deny(_)),
            "an absolute Read deny under the search root refuses the search"
        );
        let narrowed = AccessKind::Grep {
            path: Some("notes".into()),
            glob: None,
        };
        assert_eq!(hub_policy_verdict(&narrowed, &c), HubPolicyVerdict::Allow);

        let ask = compiled("[permission]\nask = [\"Read(**/notes/**)\"]\n");
        for yolo in [false, true] {
            let mut c = ctx(Some(&ask), cwd, yolo, false);
            c.walk_searches = true;
            let expected = if yolo {
                HubPolicyVerdict::Allow
            } else {
                HubPolicyVerdict::Ask(hub_ask_reason::SEARCH_COVERS_ASK)
            };
            assert_eq!(hub_policy_verdict(&search, &c), expected, "yolo={yolo}");
        }

        // An any-depth deny is excluded from the search by ripgrep when the tool applies the excludes: it neither needs
        // the walk nor refuses the search.
        let any_depth_config = config("[permission]\ndeny = [\"Read(**/secrets/**)\"]\n");
        assert!(!hub_searches_need_walk(&any_depth_config, true));
        let any_depth = compiled("[permission]\ndeny = [\"Read(**/secrets/**)\"]\nask = [\"Read(**/nothing/**)\"]\n");
        let excludes = vec!["**/secrets/**".to_owned()];
        let mut c = ctx(Some(&any_depth), cwd, false, false);
        c.walk_searches = true;
        c.search_excludes = &excludes;
        c.search_excludes_applied = true;
        assert_eq!(hub_policy_verdict(&search, &c), HubPolicyVerdict::Allow);
        // Grok #2: a search tool that does not apply the excludes is walked for an any-depth deny too, without them.
        assert!(hub_searches_need_walk(&any_depth_config, false));
        c.search_excludes_applied = false;
        assert!(
            matches!(hub_policy_verdict(&search, &c), HubPolicyVerdict::Deny(_)),
            "a tool that ignores the excludes would read the denied file"
        );
    }

    /// Grok #1: the search root is judged where the tools resolve it: `~` expanded, and a relative path that is the
    /// absolute path missing its leading slash mapped back under the cwd.
    #[test]
    fn hub_search_roots_resolve_like_the_search_tools() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        std::fs::create_dir_all(cwd.join("secrets")).unwrap();
        std::fs::write(cwd.join("secrets/token.txt"), "x").unwrap();
        let c = ctx(None, cwd, false, false);
        let no_slash = cwd.to_string_lossy().trim_start_matches('/').to_owned();
        let roots = hub_search_roots(Some(&no_slash), &c);
        assert!(roots.iter().any(|r| r == cwd), "{roots:?}");
        let home = std::path::PathBuf::from(std::env::var("HOME").unwrap());
        let roots = hub_search_roots(Some("~/p173-root"), &c);
        assert!(roots.contains(&home.join("p173-root")), "{roots:?}");
        assert_eq!(hub_search_roots(None, &c), vec![cwd.to_path_buf()]);

        let deny = compiled(&format!(
            "[permission]\ndeny = [\"Read({}/secrets/**)\"]\n",
            cwd.display()
        ));
        let mut c = ctx(Some(&deny), cwd, false, false);
        c.walk_searches = true;
        let search = AccessKind::Grep {
            path: Some(no_slash),
            glob: None,
        };
        assert!(
            matches!(hub_policy_verdict(&search, &c), HubPolicyVerdict::Deny(_)),
            "the walk runs at the resolved root"
        );
        // The resolved root itself is judged too (no walk needed): a deny on that directory refuses a search rooted
        // there, while the literal `~/...` would be read as a directory under the cwd.
        let dir_deny = compiled(&format!(
            "[permission]\ndeny = [\"Grep({}/p173-root/**)\"]\n",
            home.display()
        ));
        let c = ctx(Some(&dir_deny), cwd, false, false);
        let rooted = AccessKind::Grep {
            path: Some("~/p173-root/sub".to_owned()),
            glob: None,
        };
        assert!(matches!(hub_policy_verdict(&rooted, &c), HubPolicyVerdict::Deny(_)));
    }

    /// Grok r2 HIGH: a root that only needs approval (a broad ask rule) does not skip the walk: a denied descendant
    /// still refuses the search, so approving the prompt cannot release it.
    #[test]
    fn hub_grep_root_ask_does_not_skip_an_absolute_descendant_deny() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        std::fs::create_dir_all(cwd.join("secrets")).unwrap();
        std::fs::write(cwd.join("secrets/token.txt"), "x").unwrap();
        std::fs::write(cwd.join("open.txt"), "x").unwrap();
        for rule in ["Read(**)", "Grep(**)"] {
            let policy = compiled(&format!(
                "[permission]\nask = [\"{rule}\"]\ndeny = [\"Read({}/secrets/**)\"]\n",
                cwd.display()
            ));
            let mut c = ctx(Some(&policy), cwd, false, false);
            c.walk_searches = true;
            let search = AccessKind::Grep {
                path: None,
                glob: None,
            };
            assert!(
                matches!(hub_policy_verdict(&search, &c), HubPolicyVerdict::Deny(_)),
                "{rule}: the denied descendant must refuse the search, got {:?}",
                hub_policy_verdict(&search, &c)
            );
        }
        // The root's own ask survives a walk that finds nothing ruled.
        let root_only = compiled(&format!("[permission]\nask = [\"Grep({})\"]\n", cwd.display()));
        let mut c = ctx(Some(&root_only), cwd, false, false);
        c.walk_searches = true;
        let search = AccessKind::Grep {
            path: None,
            glob: None,
        };
        assert_eq!(hub_policy_verdict(&search, &c), HubPolicyVerdict::Ask(hub_ask_reason::ASK_RULE));
    }

    /// Grok r2 MEDIUM: a walk that cannot finish (past the cap, or a glob it cannot parse) refuses the search; only a
    /// finished walk that meets an ask rule needs approval.
    #[test]
    fn hub_search_walk_that_cannot_finish_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        for name in ["a.txt", "b.txt", "c.txt"] {
            std::fs::write(cwd.join(name), "x").unwrap();
        }
        let policy = compiled("[permission]\nask = [\"Read(**/nothing/**)\"]\n");
        let mut c = ctx(Some(&policy), cwd, false, false);
        c.walk_searches = true;
        assert!(matches!(
            hub_search_scope_verdict_capped(cwd, None, &c, 1),
            HubPolicyVerdict::Deny(_)
        ));
        assert_eq!(
            hub_search_scope_verdict_capped(cwd, None, &c, 100),
            HubPolicyVerdict::Allow,
            "a finished walk with nothing ruled runs"
        );
        let bad_glob = AccessKind::Grep {
            path: None,
            glob: Some("[abc".to_owned()),
        };
        assert!(
            matches!(hub_policy_verdict(&bad_glob, &c), HubPolicyVerdict::Deny(_)),
            "an unparseable glob refuses, got {:?}",
            hub_policy_verdict(&bad_glob, &c)
        );
    }

    /// Grok #4: the walk judges each file as a search of it, so Grep rules apply (and Read rules still do).
    #[test]
    fn hub_search_walk_applies_grep_rules() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        std::fs::create_dir_all(cwd.join("secrets")).unwrap();
        std::fs::write(cwd.join("secrets/token.txt"), "x").unwrap();
        let search = AccessKind::Grep {
            path: None,
            glob: None,
        };
        let ask = compiled("[permission]\nask = [\"Grep(**/secrets/**)\"]\n");
        let mut c = ctx(Some(&ask), cwd, false, false);
        c.walk_searches = true;
        assert_eq!(
            hub_policy_verdict(&search, &c),
            HubPolicyVerdict::Ask(hub_ask_reason::SEARCH_COVERS_ASK)
        );
        let deny = compiled(&format!(
            "[permission]\ndeny = [\"Grep({}/secrets/**)\"]\n",
            cwd.display()
        ));
        let mut c = ctx(Some(&deny), cwd, false, false);
        c.walk_searches = true;
        assert!(matches!(hub_policy_verdict(&search, &c), HubPolicyVerdict::Deny(_)));
    }

    #[test]
    fn hub_policy_accesses_include_every_apply_patch_target() {
        let patch = "*** Begin Patch\n*** Add File: .git/hooks/pre-commit\n+#!/bin/sh\n*** Update File: src/a.rs\n*** Move to: src/b.rs\n@@\n-x\n+y\n*** End Patch\n";
        for args in [serde_json::json!({"patch": patch}), serde_json::json!({"input": patch}), serde_json::json!(patch)] {
            let accesses = hub_policy_accesses(None, "apply_patch", &args);
            let edits: Vec<&str> = accesses
                .iter()
                .filter_map(|a| match a {
                    AccessKind::Edit(p) => Some(p.as_str()),
                    _ => None,
                })
                .collect();
            for target in [".git/hooks/pre-commit", "src/a.rs", "src/b.rs"] {
                assert!(edits.contains(&target), "{target} missing from {edits:?} for {args}");
            }
        }
    }

    #[test]
    fn hub_policy_accesses_cover_reads_per_path() {
        let read = hub_policy_accesses(
            None,
            "read_file",
            &serde_json::json!({"target_file": "a.rs", "files": [{"path": "b.rs"}]}),
        );
        assert!(
            matches!(
                read.as_slice(),
                [AccessKind::Read(Some(a)), AccessKind::Read(Some(b))] if a == "a.rs" && b == "b.rs"
            ),
            "{read:?}"
        );
        assert!(matches!(
            hub_policy_accesses(None, "FuigoBuild:list_dir", &serde_json::json!({"target_directory": "src"})).as_slice(),
            [AccessKind::Read(Some(p))] if p == "src"
        ));
        assert!(matches!(
            hub_policy_accesses(None, "grep", &serde_json::json!({"pattern": "x", "path": "src", "glob": "*.rs"})).as_slice(),
            [AccessKind::Grep { path: Some(p), glob: Some(g) }] if p == "src" && g == "*.rs"
        ));
        assert!(matches!(
            hub_policy_accesses(None, "run_terminal_command", &serde_json::json!({"command": "ls"})).as_slice(),
            [AccessKind::Bash(c)] if c == "ls"
        ));
        assert!(hub_policy_accesses(None, "todo_write", &serde_json::json!({})).is_empty());
    }

    #[test]
    fn hub_verdict_all_lets_any_deny_win() {
        let dir = tempfile::tempdir().unwrap();
        let policy = compiled("[permission]\ndeny = [\"Read(**/secret.txt)\"]\n");
        let c = ctx(Some(&policy), dir.path(), false, false);
        let ok = AccessKind::Read(Some(dir.path().join("a.rs").to_string_lossy().into_owned()));
        let bad = AccessKind::Read(Some(dir.path().join("secret.txt").to_string_lossy().into_owned()));
        assert!(matches!(
            hub_policy_verdict_all(&[ok.clone(), bad], &c),
            HubCallVerdict {
                denied: Some((_, 1)),
                ..
            }
        ));
        assert_eq!(
            hub_policy_verdict_all(&[ok], &c),
            HubCallVerdict {
                denied: None,
                asks: Vec::new()
            }
        );
    }

    #[tokio::test]
    async fn hub_ask_goes_through_the_transport_or_is_refused() {
        use fuigo_tool_runtime::ToolErrorKind;
        let access = AccessKind::Tool("image_gen".into());
        let err = settle_hub_ask(None, &access, "tc-1", "image_gen", hub_ask_reason::SIDE_EFFECTING_TOOL)
            .await
            .expect_err("no transport refuses");
        assert_eq!(err.kind, ToolErrorKind::PermissionDenied);
        for (reply, allowed) in [
            (Ok(serde_json::json!({"outcome": "approve"})), true),
            (Ok(serde_json::json!({"outcome": "always_approve"})), true),
            (Ok(serde_json::json!({"outcome": "reject"})), false),
            (Ok(serde_json::json!({"outcome": "cancelled"})), false),
            (Err("connection lost".to_owned()), false),
        ] {
            let transport = StubTransport {
                reply: reply.clone(),
                seen: Mutex::new(None),
            };
            let result = settle_hub_ask(
                Some(&transport),
                &access,
                "tc-2",
                "image_gen",
                hub_ask_reason::SIDE_EFFECTING_TOOL,
            )
            .await;
            assert_eq!(result.is_ok(), allowed, "reply {reply:?}");
            if let Err(e) = result {
                assert_eq!(e.kind, ToolErrorKind::PermissionDenied);
            }
            let seen = transport.seen.lock().unwrap().clone().expect("prompt sent");
            assert_eq!(seen["tool_call_id"], "tc-2");
            assert_eq!(seen["tool_name"], "image_gen");
        }
    }

    /// Answers each prompt from a script, in order, and records the prompts.
    struct ScriptedTransport {
        replies: Mutex<std::collections::VecDeque<serde_json::Value>>,
        seen: Mutex<Vec<serde_json::Value>>,
    }
    #[async_trait]
    impl PermissionHookTransport for ScriptedTransport {
        async fn request_permission(&self, payload: serde_json::Value) -> Result<serde_json::Value, String> {
            self.seen.lock().unwrap().push(payload);
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| "no scripted reply".to_owned())
        }
    }

    /// Grok #8: every ask of a call is settled: approving the first does not release the second.
    #[tokio::test]
    async fn settle_hub_asks_settles_every_ask() {
        use fuigo_tool_runtime::ToolErrorKind;
        let notes = AccessKind::Edit("/p/notes.txt".into());
        let hook = AccessKind::Edit("/p/.git/hooks/pre-commit".into());
        let accesses = [notes, hook];
        let asks = [
            (hub_ask_reason::ASK_RULE, 0),
            (hub_ask_reason::PROTECTED_PATH, 1),
        ];
        let script = |outcomes: &[&str]| ScriptedTransport {
            replies: Mutex::new(
                outcomes
                    .iter()
                    .map(|o| serde_json::json!({ "outcome": o }))
                    .collect(),
            ),
            seen: Mutex::new(Vec::new()),
        };
        let approve_then_deny = script(&["approve", "reject"]);
        let err = settle_hub_asks(Some(&approve_then_deny), &asks, &accesses, &accesses, "tc", "apply_patch")
            .await
            .expect_err("the second ask is refused, so the call is");
        assert_eq!(err.kind, ToolErrorKind::PermissionDenied);
        let seen = approve_then_deny.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2, "both asks were sent: {seen:?}");
        assert_eq!(seen[1]["edit_file_paths"][0], "/p/.git/hooks/pre-commit");

        let both = script(&["approve", "approve"]);
        settle_hub_asks(Some(&both), &asks, &accesses, &accesses, "tc", "apply_patch")
            .await
            .expect("both approved");
        assert_eq!(both.seen.lock().unwrap().len(), 2);

        let deny_first = script(&["reject", "approve"]);
        settle_hub_asks(Some(&deny_first), &asks, &accesses, &accesses, "tc", "apply_patch")
            .await
            .expect_err("the first refusal refuses the call");
        assert_eq!(deny_first.seen.lock().unwrap().len(), 1, "nothing is asked after a refusal");
    }

    #[test]
    fn hitl_permission_live_defaults_off_without_env() {
        if std::env::var(HITL_PERMISSION_LIVE_ENV).is_err() {
            assert!(!hitl_permission_live_enabled());
        }
    }
    /// P166 r13B feature 1, hub path: the hub applies the same branch-switch check as the local manager
    /// (`hub_needs_default_prompt` calls the shared pair), so a narrow `Bash(git:*)` allow no longer clears the floor of
    /// a branch switch in a repository that tracks a protected name.
    #[test]
    fn p166_r13b_hub_branch_switch_follows_the_local_check() {
        use crate::permission::manager::p166_r13b_branch_tests::table_repo;
        let policy = compiled("[permission]\nallow = [\"Bash(git:*)\"]\n");
        let bash = |c: &str| AccessKind::Bash(c.to_owned());
        let none = table_repo(false);
        let tracked = table_repo(true);
        let c = ctx(Some(&policy), none.path(), false, true);
        for cmd in ["git checkout main", "git pull", "git stash pop", "git status", "git switch -c x"] {
            assert_eq!(hub_policy_verdict(&bash(cmd), &c), HubPolicyVerdict::Allow, "no protected name: {cmd}");
        }
        let c = ctx(Some(&policy), tracked.path(), false, true);
        for cmd in ["git checkout main", "git pull", "git stash pop"] {
            assert_eq!(
                hub_policy_verdict(&bash(cmd), &c),
                HubPolicyVerdict::Ask(hub_ask_reason::DEFAULT_PROMPT),
                "tracked .mcp.json: {cmd}"
            );
        }
        for cmd in ["git status", "git log", "git diff", "git add -A", "git commit -m x", "git fetch", "git push", "git switch -c x"] {
            assert_eq!(hub_policy_verdict(&bash(cmd), &c), HubPolicyVerdict::Allow, "unchanged: {cmd}");
        }
        // `merge` and `rebase` already carry the unpinned protected floor (r8B): they ask in every repository.
        for dir in [none.path(), tracked.path()] {
            let c = ctx(Some(&policy), dir, false, true);
            for cmd in ["git merge feature", "git rebase main"] {
                assert_eq!(
                    hub_policy_verdict(&bash(cmd), &c),
                    HubPolicyVerdict::Ask(hub_ask_reason::PROTECTED_PATH),
                    "unchanged: {cmd}"
                );
            }
        }
    }
    /// P198: a hub-routed read is judged in every spelling of the file the reader opens, as a local read is (P174): a
    /// symlink to a denied file, and the Unicode-confusable sibling the reader falls back to.
    #[cfg(unix)]
    #[tokio::test]
    async fn hub_read_is_judged_in_every_spelling_of_the_file_the_reader_opens() {
        use crate::permission::types::{ReadResolution, ReadTargets};
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        std::fs::create_dir_all(cwd.join("secrets")).unwrap();
        std::fs::create_dir_all(cwd.join("public")).unwrap();
        std::fs::write(cwd.join("secrets/key"), "k").unwrap();
        std::os::unix::fs::symlink(cwd.join("secrets"), cwd.join("alias")).unwrap();
        std::os::unix::fs::symlink(cwd.join("secrets/key"), cwd.join("public/k\u{a0}ey")).unwrap();
        let policy = compiled("[permission]\ndeny = [\"Read(secrets/**)\"]\nask = [\"Read(asked/**)\"]\n");
        for path in ["alias/key", "public/k ey", "secrets/key", "public/../secrets/key"] {
            let targets = ReadTargets { paths: vec![path.to_owned()], resolution: ReadResolution::ModelPath };
            let spellings = hub_read_spellings(true, cwd, None, Some(&targets)).await;
            let mut c = ctx(Some(&policy), cwd, false, false);
            c.read_spellings = &spellings;
            assert!(
                matches!(hub_policy_verdict(&AccessKind::Read(Some(path.to_owned())), &c), HubPolicyVerdict::Deny(_)),
                "{path}: a hub read of a denied file in another spelling must be refused, got {:?}",
                hub_policy_verdict(&AccessKind::Read(Some(path.to_owned())), &c)
            );
        }
        // An ordinary file is still read, and with no policy nothing is resolved at all.
        std::fs::write(cwd.join("public/ok.txt"), "o").unwrap();
        let targets = ReadTargets { paths: vec!["public/ok.txt".to_owned()], resolution: ReadResolution::ModelPath };
        let spellings = hub_read_spellings(true, cwd, None, Some(&targets)).await;
        let mut c = ctx(Some(&policy), cwd, false, false);
        c.read_spellings = &spellings;
        assert_eq!(
            hub_policy_verdict(&AccessKind::Read(Some("public/ok.txt".to_owned())), &c),
            HubPolicyVerdict::Allow
        );
        assert!(hub_read_spellings(false, cwd, None, Some(&targets)).await.is_empty());
    }

    /// P198 r2: a tool that reads a file but is an `AccessKind::Tool` (an image edit) is judged in the file's spellings.
    #[tokio::test]
    async fn hub_tool_that_reads_a_denied_file_is_refused() {
        use crate::permission::types::{ReadResolution, ReadTargets};
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        std::fs::create_dir_all(cwd.join("secrets")).unwrap();
        std::fs::write(cwd.join("secrets/key.png"), "k").unwrap();
        std::fs::write(cwd.join("ok.png"), "o").unwrap();
        let policy = compiled("[permission]\ndeny = [\"Read(secrets/**)\"]\nallow = [\"image_edit\"]\n");
        let policy_ref = &policy;
        let verdict = |path: &str| {
            let targets = ReadTargets { paths: vec![path.to_owned()], resolution: ReadResolution::ModelPath };
            async move {
                let spellings = hub_read_spellings(true, cwd, None, Some(&targets)).await;
                let mut c = ctx(Some(policy_ref), cwd, false, false);
                c.read_spellings = &spellings;
                hub_policy_verdict(&AccessKind::Tool("image_edit".to_owned()), &c)
            }
        };
        let denied = verdict("secrets/key.png").await;
        assert!(matches!(denied, HubPolicyVerdict::Deny(_)), "{denied:?}");
        assert_eq!(verdict("ok.png").await, HubPolicyVerdict::Allow);
        // A `Read` whose path is not among the resolved targets fails closed.
        let targets = ReadTargets { paths: vec!["ok.png".to_owned()], resolution: ReadResolution::ModelPath };
        let spellings = hub_read_spellings(true, cwd, None, Some(&targets)).await;
        let mut c = ctx(Some(&policy), cwd, false, false);
        c.read_spellings = &spellings;
        assert!(matches!(
            hub_policy_verdict(&AccessKind::Read(Some("other.txt".to_owned())), &c),
            HubPolicyVerdict::Deny(_)
        ));
    }

    /// P198 r2: the tools' filter and the policy agree on every path (one matcher).
    #[test]
    fn read_deny_filter_agrees_with_the_policy() {
        let cwd = std::path::Path::new("/abs/proj");
        for (rule, globs) in [("/abs/proj/secrets/**", "/abs/proj/secrets/**"), ("secret", "secret"), ("secrets/**", "secrets/**")] {
            let policy = compiled(&format!("[permission]\ndeny = [\"Read({rule})\"]\nallow = [\"Read(**)\"]\n"));
            let filter = fuigo_tools::util::read_deny::ReadDenyFilter::new(cwd, &[globs.to_owned()]).unwrap();
            for path in ["secrets/key", "secret", "secret/notes.txt", "secrets-public/x", "src/a.rs", "/abs/proj/secrets/key"] {
                let denied = matches!(
                    policy.evaluate_with_cwd(&AccessKind::Read(Some(path.to_owned())), Some(cwd)),
                    Some(crate::permission::types::Decision::Reject(_) | crate::permission::types::Decision::PolicyDeny(_))
                );
                assert_eq!(filter.denies(std::path::Path::new(path), false), denied, "rule {rule}, path {path}");
            }
        }
    }

    /// P198 r2: the verdicts the tool-level tests (`read_rules_follow_the_policy_matcher` in the list and grep tools) rely
    /// on, asked of the policy itself for the same paths.
    #[test]
    fn bare_name_and_sibling_verdicts() {
        let cwd = std::path::Path::new("/abs/proj");
        let denied = |rule: &str, path: &str| {
            let policy = compiled(&format!("[permission]\ndeny = [\"Read({rule})\"]\nallow = [\"Read(**)\"]\n"));
            matches!(
                policy.evaluate_with_cwd(&AccessKind::Read(Some(path.to_owned())), Some(cwd)),
                Some(crate::permission::types::Decision::Reject(_) | crate::permission::types::Decision::PolicyDeny(_))
            )
        };
        // bare name: only that exact path
        assert!(!denied("secret", "secret/notes.txt"));
        assert!(denied("secret", "secret"));
        // siblings with a common prefix
        assert!(!denied("secret/**", "secrets-public/x.txt"));
        assert!(!denied("secrets/**", "secrets-public/x.txt"));
        assert!(!denied("secrets/**", "secret/notes.txt"));
        assert!(!denied("secret/**", "secrets/key_material.txt"));
        assert!(denied("secrets/**", "secrets/key_material.txt"));
        assert!(denied("secret/**", "secret/notes.txt"));
        // an absolute rule, read through the cwd-relative and the absolute spelling
        assert!(denied("/abs/proj/secrets/**", "secrets/key_material.txt"));
        assert!(denied("/abs/proj/secrets/**", "/abs/proj/secrets/key_material.txt"));
        assert!(!denied("/abs/other/**", "secrets/key_material.txt"));
    }
}
