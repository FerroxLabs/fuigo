use agent_client_protocol as acp;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionEvent {
    pub tool_id: String,
    pub tool_name: String,
    pub access_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_detail: Option<String>,
    pub yolo_mode: bool,
    pub auto_approved: bool,
    pub user_prompted: bool,
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
    pub timestamp: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subagent_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subagent_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subagent_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier_latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_denials_consecutive: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_denials_total: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_depth: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_findings: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier_verdict: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remember_tool_approvals: Option<bool>,
}
#[derive(Debug, Clone)]
pub struct PermissionResolution {
    pub decision: Decision,
    pub event: Option<PermissionEvent>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum ClientType {
    #[default]
    #[serde(rename = "generic", alias = "fuigo-shell", alias = "fuigo_shell")]
    Generic,
    #[serde(rename = "fuigo-tui", alias = "fuigo_tui")]
    FuigoTUI,
    #[serde(rename = "fuigo_web")]
    FuigoWeb,
    #[serde(rename = "nebula")]
    Nebula,
    #[serde(rename = "extension")]
    Extension,
    #[serde(rename = "fuigo-pager", alias = "fuigo_pager")]
    FuigoPager,
    #[serde(rename = "fuigo_desktop")]
    Desktop,
}
impl ClientType {
    pub fn user_agent_label(&self) -> &'static str {
        match self {
            Self::Generic => "fuigo-shell",
            Self::FuigoTUI => "fuigo-tui",
            Self::FuigoWeb => "fuigo-web",
            Self::Nebula => "nebula",
            Self::Extension => "fuigo-code-extension",
            Self::FuigoPager => "fuigo-pager",
            Self::Desktop => "fuigo-desktop",
        }
    }
    pub fn from_client_identifier(id: Option<&str>) -> Self {
        match id {
            Some("fuigo-web") => Self::FuigoWeb,
            Some("nebula") => Self::Nebula,
            Some("fuigo-code-extension") => Self::Extension,
            Some("fuigo-desktop") => Self::Desktop,
            Some("fuigo-pager") => Self::FuigoPager,
            _ => Self::Generic,
        }
    }
    pub fn feedback_label(&self) -> &'static str {
        match self {
            Self::FuigoTUI | Self::FuigoPager => "tui",
            Self::FuigoWeb => "web",
            Self::Nebula => "nebula",
            Self::Extension => "extension",
            Self::Generic => "agent",
            Self::Desktop => "desktop",
        }
    }
    pub const fn can_present_permission_prompt(self) -> bool {
        !matches!(self, Self::Generic)
    }
}
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum AccessKind {
    Read(Option<String>),
    Grep {
        path: Option<String>,
        glob: Option<String>,
    },
    Edit(String),
    Bash(String),
    MCPTool {
        name: String,
        input: serde_json::Value,
    },
    WebFetch(String),
    WebSearch(String),
    AgentMessage {
        subagent_id: String,
    },
    /// A built-in tool with side effects outside the file/shell/web kinds above (scheduling, workflows, image and video
    /// generation), named by its tool id. It always prompts: no session grant or "always" answer pre-approves it, only
    /// always-approve mode, an allow rule naming it, or the auto-mode classifier. A tool-wide `Edit` deny/ask also reaches it.
    /// It is also the fail-closed kind for a tool input this crate cannot classify.
    Tool(String),
}
/// Tool id used for a tool input of a shape [`AccessKind`] cannot classify (fail closed: it prompts).
pub const UNCLASSIFIED_TOOL_ID: &str = "unclassified_tool";
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Ask,
    FollowupMessage(String),
    Reject(String),
    PolicyDeny(String),
    Cancelled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EditPolicy {
    #[default]
    Ask,
    Allow,
    Reject,
}
impl Serialize for EditPolicy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::Ask => "ask",
            Self::Allow => "allow",
            Self::Reject => "reject",
        })
    }
}
impl<'de> Deserialize<'de> for EditPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = EditPolicy;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("one of: ask, allow, reject")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<EditPolicy, E> {
                match v {
                    "ask" => Ok(EditPolicy::Ask),
                    "allow" => Ok(EditPolicy::Allow),
                    "reject" => Ok(EditPolicy::Reject),
                    other => Err(E::unknown_variant(other, &["ask", "allow", "reject"])),
                }
            }
        }
        deserializer.deserialize_str(V)
    }
}
#[derive(Debug, Clone)]
pub struct RequestPathContext {
    pub real_cwd: std::path::PathBuf,
    pub display_cwd: Option<std::path::PathBuf>,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookAsk {
    pub hook_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
pub const HOOK_ASK_META_KEY: &str = "hookAsk";
const HOOK_ASK_SEPARATOR: &str = " — ";
impl HookAsk {
    pub fn ask_line(&self) -> String {
        let hook_name = &self.hook_name;
        let reason = self.reason.as_deref().unwrap_or_default();
        let reason = reason.split_whitespace().collect::<Vec<_>>().join(" ");
        if reason.is_empty() {
            format!("hook '{hook_name}' asks for confirmation")
        } else {
            format!("hook '{hook_name}' asks: {reason}")
        }
    }
    pub fn prompt_header(&self, action: &str) -> String {
        format!("{action}{HOOK_ASK_SEPARATOR}{}", self.ask_line())
    }
    pub fn strip_prompt_header<'a>(&self, title: &'a str) -> &'a str {
        title
            .strip_suffix(self.ask_line().as_str())
            .and_then(|action| action.strip_suffix(HOOK_ASK_SEPARATOR))
            .unwrap_or(title)
    }
}
#[derive(Debug, Clone)]
pub struct PermissionRequest {
    pub access: AccessKind,
    pub tool_call_update: acp::ToolCallUpdate,
    pub path_context: Option<RequestPathContext>,
    pub session_id: Option<String>,
    pub subagent_type: Option<String>,
    pub subagent_description: Option<String>,
    pub hook_ask: Option<HookAsk>,
    /// The files a multi-file edit really writes (`apply_patch`), judged one `Edit` each; `None` for every other tool.
    /// Build it with [`edit_targets_for`] from the same input that runs (P184).
    pub edit_targets: Option<EditTargets>,
    /// Every file a `read_file` call (or a non-read tool that also opens local files) really reads, judged one `Read`
    /// each, the strictest result winning; `None` for every other tool. Build it with [`read_targets_for`] from the same
    /// input that runs (P174).
    pub read_targets: Option<ReadTargets>,
}
impl PermissionRequest {
    pub fn new(access: AccessKind, tool_call_update: acp::ToolCallUpdate) -> Self {
        Self {
            access,
            tool_call_update,
            path_context: None,
            session_id: None,
            subagent_type: None,
            subagent_description: None,
            hook_ask: None,
            edit_targets: None,
            read_targets: None,
        }
    }
}
/// Per-file targets of a multi-file edit (P184). `apply_patch` classifies as one `Edit("apply_patch")` placeholder,
/// which no path rule, protected path or workspace check can match; the manager judges these targets instead, the
/// strictest result winning, and refuses an unparseable patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditTargets {
    /// Every path the patch adds, updates, deletes, moves from or moves to, as the model spelled it (the tool resolves
    /// each with the edit tools' shared resolver, as the manager does).
    Paths(Vec<String>),
    /// The patch does not parse; the message says why. Refused, never allowed.
    Unparseable(String),
}
/// The per-file targets of a tool input that writes several files (`apply_patch`); `None` for single-target tools.
pub fn edit_targets_for(input: &fuigo_tools::types::ToolInput) -> Option<EditTargets> {
    match input {
        fuigo_tools::types::ToolInput::ApplyPatch(patch) => Some(apply_patch_edit_targets(&patch.patch)),
        _ => None,
    }
}
/// The files a tool call opens (P174), and how the tool resolves each spelling to the file it opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadTargets {
    /// Every file, in read order, each once, as the model spelled it.
    pub paths: Vec<String>,
    pub resolution: ReadResolution,
}
/// How a tool turns a [`ReadTargets`] spelling into the file it opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadResolution {
    /// The Fuigo reader: `resolve_model_path` against the session cwd (display-cwd mapping, quotes, `~`), then the
    /// Unicode-confusable fallback (`fuigo_tools::implementations::fuigo_build::read_file::resolve_read_target`).
    ModelPath,
    /// Opened exactly as spelled (the codex reader, which takes absolute paths only; the image tools, whose relative
    /// paths are made absolute against this process's cwd here).
    Literal,
}
/// The files a tool input opens, each judged as a `Read` (P174); `None` for a tool that opens no file its `access`
/// does not already name.
/// - `read_file` (codex and Fuigo forms): `file_path` / `target_file` and every `files[].path`, from the tool's own
///   read plan, so the tool reads no path that was not judged.
/// - `image_edit`, `image_to_video`, `reference_to_video`: every local image file the tool opens (relative paths
///   made absolute against this process's cwd, which is what the tool's `tokio::fs::read` resolves them against).
pub fn read_targets_for(input: &fuigo_tools::types::ToolInput) -> Option<ReadTargets> {
    use fuigo_tools::implementations::{codex, fuigo_build};
    use fuigo_tools::types::ToolInput;
    let (paths, resolution) = match input {
        ToolInput::CodexReadFile(r) => (
            codex::read_file::tool::read_target_paths(r),
            ReadResolution::Literal,
        ),
        ToolInput::ReadFile(r) => (
            fuigo_build::read_file::read_target_paths(r),
            ReadResolution::ModelPath,
        ),
        ToolInput::ImageEdit(i) => (
            process_cwd_absolute(fuigo_build::image_edit::local_image_paths(&i.image)),
            ReadResolution::Literal,
        ),
        ToolInput::ImageToVideo(i) => (
            process_cwd_absolute(fuigo_build::video_gen::local_image_paths(std::iter::once(&i.image))),
            ReadResolution::Literal,
        ),
        ToolInput::ReferenceToVideo(i) => (
            process_cwd_absolute(fuigo_build::video_gen::local_image_paths(&i.images)),
            ReadResolution::Literal,
        ),
        _ => return None,
    };
    (!paths.is_empty()).then_some(ReadTargets { paths, resolution })
}
/// Relative paths made absolute against this process's cwd (where a bare `tokio::fs::read` resolves them).
fn process_cwd_absolute(paths: Vec<String>) -> Vec<String> {
    let cwd = std::env::current_dir().ok();
    paths
        .into_iter()
        .map(|path| match &cwd {
            Some(cwd) if !std::path::Path::new(&path).is_absolute() => {
                cwd.join(&path).to_string_lossy().into_owned()
            }
            _ => path,
        })
        .collect()
}
/// How a prompt names the files of a multi-file read: every path, in read order.
pub fn describe_read_targets(paths: &[String]) -> String {
    paths.join(", ")
}
/// [`EditTargets`] of an `apply_patch` patch text.
pub fn apply_patch_edit_targets(patch: &str) -> EditTargets {
    match fuigo_tools::implementations::codex::apply_patch::patch_edit_targets(patch) {
        Ok(paths) => EditTargets::Paths(paths),
        Err(message) => EditTargets::Unparseable(message),
    }
}
/// How a prompt names the targets of a multi-file edit: every path, in patch order.
pub fn describe_edit_targets(paths: &[String]) -> String {
    paths.join(", ")
}
/// The access the hub's `apply_patch` permission prompt shows: an `Edit` naming every target of the patch in `args`
/// (a bare string or the `patch` / `raw` / `input` envelope), or the placeholder when it does not parse.
pub(crate) fn apply_patch_hub_access(args: &serde_json::Value) -> AccessKind {
    let targets = serde_json::from_value::<fuigo_tools::implementations::codex::apply_patch::ApplyPatchInput>(
        args.clone(),
    )
    .ok()
    .map(|input| apply_patch_edit_targets(&input.patch));
    match targets {
        Some(EditTargets::Paths(paths)) if !paths.is_empty() => {
            AccessKind::Edit(describe_edit_targets(&paths))
        }
        _ => AccessKind::Edit(APPLY_PATCH_PLACEHOLDER.to_owned()),
    }
}
/// The single `Edit` path `apply_patch` classifies as; its real targets travel in [`PermissionRequest::edit_targets`].
pub const APPLY_PATCH_PLACEHOLDER: &str = "apply_patch";
#[allow(clippy::large_enum_variant)]
pub enum PermissionCommand {
    Request {
        request: PermissionRequest,
        respond_to: oneshot::Sender<PermissionResolution>,
    },
    SetYoloMode(bool),
    SetAutoMode(bool),
    SetClassifier(Option<std::sync::Arc<dyn super::auto_mode::PermissionClassifier>>),
    SetClassifierTranscript(Vec<super::auto_mode::ClassifierTurn>),
    SetProjectInstructions(Option<String>),
    ResetState,
    Shutdown,
}
/// Classification is an allowlist of reads: a tool is `Read`/`Grep`/`WebSearch` (auto-allowed) only when it reads state or
/// touches nothing but the session's own bookkeeping. Every other tool prompts as an edit, a command, an MCP call, a fetch,
/// an agent message, or a [`AccessKind::Tool`].
/// The match is exhaustive with no catch-all on purpose: a new `ToolInput` variant does not compile until it is classified here,
/// so it can never default to an auto-allowed read (P165, S1).
impl From<&fuigo_tools::types::ToolInput> for AccessKind {
    fn from(input: &fuigo_tools::types::ToolInput) -> Self {
        use fuigo_tools::types::ToolInput;
        match input {
            ToolInput::ReadFile(r) => AccessKind::Read(Some(r.path.clone())),
            ToolInput::ListDir(l) => AccessKind::Read(Some(l.target_directory.clone())),
            // Path-carrying reads keep their path so path-scoped Read rules reach them.
            ToolInput::CodexReadFile(r) => {
                AccessKind::Read(Some(r.file_path.clone()).filter(|p| !p.is_empty()))
            }
            ToolInput::CodexListDir(l) => AccessKind::Read(Some(l.dir_path.clone())),
            ToolInput::MemoryGet(m) => AccessKind::Read(Some(m.path.clone())),
            ToolInput::Lsp(l) => AccessKind::Read(l.file_path.clone()),
            ToolInput::Grep(g) => AccessKind::Grep {
                path: g.path.clone(),
                glob: g.glob.clone(),
            },
            ToolInput::CodexGrepFiles(g) => AccessKind::Grep {
                path: g.path.clone(),
                glob: g.include.clone(),
            },
            // Reads of session state, or the session's own bookkeeping.
            ToolInput::TodoWrite(_)
            | ToolInput::TaskOutput(_)
            | ToolInput::WaitTasks(_)
            | ToolInput::KillTask(_)
            | ToolInput::Skill(_)
            | ToolInput::MemorySearch(_)
            | ToolInput::SearchTool(_)
            | ToolInput::SchedulerList(_)
            | ToolInput::EnterPlanMode(_)
            | ToolInput::ExitPlanMode(_)
            | ToolInput::AskUserQuestion(_)
            | ToolInput::UpdateGoal(_) => AccessKind::Read(None),
            ToolInput::Task(t) => AccessKind::Edit(format!("task:{}", t.subagent_type)),
            // Side effects outside the file/shell/web kinds: they always prompt.
            ToolInput::SchedulerCreate(_) => AccessKind::Tool("scheduler_create".to_owned()),
            ToolInput::SchedulerDelete(_) => AccessKind::Tool("scheduler_delete".to_owned()),
            ToolInput::Workflow(w) => workflow_access(w),
            ToolInput::ImageGen(_) => AccessKind::Tool("image_gen".to_owned()),
            ToolInput::ImageEdit(_) => AccessKind::Tool("image_edit".to_owned()),
            ToolInput::ImageToVideo(_) => AccessKind::Tool("image_to_video".to_owned()),
            ToolInput::ReferenceToVideo(_) => AccessKind::Tool("reference_to_video".to_owned()),
            ToolInput::SendSubagentMessage(message) => AccessKind::AgentMessage {
                subagent_id: message.subagent_id.clone(),
            },
            ToolInput::WebSearch(ws) => AccessKind::WebSearch(ws.query.clone()),
            ToolInput::SearchReplace(search_replace) => {
                AccessKind::Edit(search_replace.file_path.to_string())
            }
            // One placeholder: the per-file targets travel in `PermissionRequest::edit_targets` (P184).
            ToolInput::ApplyPatch(_) => AccessKind::Edit(APPLY_PATCH_PLACEHOLDER.to_string()),
            ToolInput::HashlineEdit(he) => AccessKind::Edit(he.file_path.to_string()),
            ToolInput::Write(w) => AccessKind::Edit(w.file_path.clone()),
            ToolInput::Bash(bash) => AccessKind::Bash(bash.command.to_string()),
            ToolInput::Monitor(m) => AccessKind::Bash(m.command.clone()),
            ToolInput::MCPTool(mcp) => AccessKind::MCPTool {
                name: mcp.tool_name.to_string(),
                input: mcp.tool_input.clone(),
            },
            ToolInput::UseTool(u) => AccessKind::MCPTool {
                name: u.tool_name.clone(),
                input: u.tool_input.clone(),
            },
            ToolInput::WebFetch(wf) => AccessKind::WebFetch(wf.url.clone()),
            ToolInput::Dynamic(value) => access_kind_from_dynamic(value),
        }
    }
}
/// A workflow launch (and a resume, pause or stop) is a side effect and prompts. `validate_only` on a named, inline or
/// on-disk script is a dry run against stub agents, stub writes and an in-memory journal (`fuigo_workflow::validate`), so it
/// is a read; the on-disk script keeps its path for Read rules. Resume/pause/stop act on a live run even when
/// `validate_only` is set (the shell handles them before the validate branch), so they always prompt.
pub(crate) fn workflow_access(
    input: &fuigo_tools::implementations::fuigo_build::workflow::WorkflowToolInput,
) -> AccessKind {
    use fuigo_tools::implementations::fuigo_build::workflow::WorkflowSource;
    match (&input.source, input.validate_only) {
        (WorkflowSource::Name { .. } | WorkflowSource::Script { .. }, true) => {
            AccessKind::Read(None)
        }
        (WorkflowSource::ScriptPath { script_path }, true) => {
            AccessKind::Read(Some(script_path.clone()))
        }
        (
            WorkflowSource::Name { .. }
            | WorkflowSource::Script { .. }
            | WorkflowSource::ScriptPath { .. }
            | WorkflowSource::Resume { .. }
            | WorkflowSource::Pause { .. }
            | WorkflowSource::Stop { .. },
            _,
        ) => AccessKind::Tool("workflow".to_owned()),
    }
}
fn dynamic_string_field(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    let object = value.as_object()?;
    keys.iter()
        .find_map(|key| object.get(*key).and_then(serde_json::Value::as_str))
        .map(str::to_owned)
}
fn dynamic_has_field(value: &serde_json::Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|object| keys.iter().any(|key| object.contains_key(*key)))
}
/// True when `value` is an object that has `required` and no key outside `allowed`.
fn dynamic_shape_is(value: &serde_json::Value, required: &str, allowed: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.contains_key(required) && object.keys().all(|key| allowed.contains(&key.as_str()))
    })
}
const DYNAMIC_PATH_KEYS: &[&str] = &["filePath", "file_path", "path"];
/// Runtime-registered (opencode) inputs arrive as raw JSON. A mutation of a path is an edit and a `command` is a shell
/// command; a read is recognized only by the exact key sets of the read-only tools (read, glob, grep, todowrite, skill).
/// Any other shape fails closed to [`AccessKind::Tool`] so it prompts (P165, S1).
fn access_kind_from_dynamic(value: &serde_json::Value) -> AccessKind {
    if let Some(path) = dynamic_string_field(value, DYNAMIC_PATH_KEYS)
        && dynamic_has_field(
            value,
            &[
                "oldString",
                "old_string",
                "newString",
                "new_string",
                "content",
                "edits",
                "replaceAll",
                "replace_all",
            ],
        )
    {
        return AccessKind::Edit(path);
    }
    if let Some(command) = dynamic_string_field(value, &["command"]) {
        return AccessKind::Bash(command);
    }
    // opencode `read`: {filePath, offset?, limit?}
    for path_key in ["filePath", "file_path"] {
        if dynamic_shape_is(value, path_key, &[path_key, "offset", "limit"])
            && let Some(path) = dynamic_string_field(value, &[path_key])
        {
            return AccessKind::Read(Some(path));
        }
    }
    // opencode `glob` {pattern, path?} and `grep` {pattern, path?, include?}
    if dynamic_shape_is(value, "pattern", &["pattern", "path", "include"]) {
        return AccessKind::Read(dynamic_string_field(value, &["path"]));
    }
    // opencode `todowrite` {todos} and `skill` {name}
    if dynamic_shape_is(value, "todos", &["todos"]) || dynamic_shape_is(value, "name", &["name"]) {
        return AccessKind::Read(None);
    }
    AccessKind::Tool(UNCLASSIFIED_TOOL_ID.to_owned())
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PermissionConfig {
    pub rules: Vec<PermissionRule>,
    #[serde(default)]
    pub prompt_policy: PromptPolicy,
    #[serde(default)]
    pub default_mode_configured: bool,
}
impl PermissionConfig {
    pub fn new(rules: Vec<PermissionRule>) -> Self {
        Self {
            rules,
            prompt_policy: PromptPolicy::Ask,
            default_mode_configured: false,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PromptPolicy {
    #[default]
    Ask,
    Deny,
    Auto,
    Allow,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRule {
    pub action: RuleAction,
    #[serde(default)]
    pub tool: ToolFilter,
    pub pattern: Option<String>,
    #[serde(default)]
    pub pattern_mode: PatternMode,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PatternMode {
    #[default]
    Glob,
    Domain,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    #[default]
    Deny,
    Ask,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ToolFilter {
    #[default]
    Any,
    Bash,
    Edit,
    Read,
    Grep,
    Mcp,
    WebFetch,
    WebSearch,
    #[serde(rename = "agent_message", alias = "agentmessage")]
    AgentMessage,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequirementSource {
    Unknown,
    Requirements { path: std::path::PathBuf },
    SystemRequirements { path: std::path::PathBuf },
    ManagedSettings { path: std::path::PathBuf },
    ManagedConfig { path: std::path::PathBuf },
    Config { path: std::path::PathBuf },
    Settings { path: std::path::PathBuf },
}
impl std::fmt::Display for RequirementSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => f.write_str("<unknown>"),
            Self::Requirements { path } => write!(f, "{} (requirements)", path.display()),
            Self::SystemRequirements { path } => {
                write!(f, "{} (system requirements)", path.display())
            }
            Self::ManagedSettings { path } => {
                write!(f, "{} (managed-settings)", path.display())
            }
            Self::ManagedConfig { path } => {
                write!(f, "{} (managed config)", path.display())
            }
            Self::Config { path } => write!(f, "{} (config)", path.display()),
            Self::Settings { path } => write!(f, "{} (settings)", path.display()),
        }
    }
}
#[derive(Debug, Clone)]
pub struct Sourced<T> {
    pub value: T,
    pub source: RequirementSource,
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    /// P184: `apply_patch` keeps its placeholder access; its real targets come from `edit_targets_for`, built from the
    /// same input. Other tools carry none.
    #[test]
    fn apply_patch_request_carries_its_parsed_targets() {
        use fuigo_tools::implementations::codex::apply_patch::ApplyPatchInput;
        let input = fuigo_tools::types::ToolInput::ApplyPatch(ApplyPatchInput {
            patch: "*** Begin Patch\n*** Add File: .git/hooks/pre-commit\n+x\n*** Update File: a.rs\n*** Move to: b.rs\n@@\n-a\n+b\n*** End Patch".to_owned(),
        });
        assert!(matches!(AccessKind::from(&input), AccessKind::Edit(p) if p == APPLY_PATCH_PLACEHOLDER));
        assert_eq!(
            edit_targets_for(&input),
            Some(EditTargets::Paths(vec![
                ".git/hooks/pre-commit".to_owned(),
                "a.rs".to_owned(),
                "b.rs".to_owned(),
            ]))
        );
        let bad = fuigo_tools::types::ToolInput::ApplyPatch(ApplyPatchInput {
            patch: "rm -rf /".to_owned(),
        });
        assert!(matches!(edit_targets_for(&bad), Some(EditTargets::Unparseable(_))));
        let write = fuigo_tools::types::ToolInput::Write(
            serde_json::from_value(serde_json::json!({"file_path": "a.rs", "content": "x"})).unwrap(),
        );
        assert_eq!(edit_targets_for(&write), None);
    }
    /// The hub's `apply_patch` prompt names every target of the patch, in any argument envelope.
    #[test]
    fn hub_apply_patch_access_names_every_target() {
        let text = "*** Begin Patch\n*** Add File: src/a.rs\n+a\n*** Delete File: .git/hooks/pre-push\n*** End Patch";
        for args in [
            serde_json::json!({ "patch": text }),
            serde_json::json!({ "input": text }),
            serde_json::Value::String(text.to_owned()),
        ] {
            let access = crate::permission::access_kind_for_hub_tool(None, "apply_patch", &args);
            assert!(
                matches!(&access, Some(AccessKind::Edit(p)) if p == "src/a.rs, .git/hooks/pre-push"),
                "{args}: {access:?}"
            );
        }
        let junk = crate::permission::access_kind_for_hub_tool(
            None,
            "apply_patch",
            &serde_json::json!({"patch": "junk"}),
        );
        assert!(matches!(&junk, Some(AccessKind::Edit(p)) if p == APPLY_PATCH_PLACEHOLDER), "{junk:?}");
    }
    #[test]
    fn hook_ask_header_keeps_the_action_and_names_the_hook() {
        let with_reason = HookAsk {
            hook_name: "guard".to_owned(),
            reason: Some("confirm this".to_owned()),
        };
        let header = with_reason.prompt_header("Run `deploy`");
        assert_eq!(header, "Run `deploy` — hook 'guard' asks: confirm this");
        assert_eq!(with_reason.strip_prompt_header(&header), "Run `deploy`");
        let bare = HookAsk {
            hook_name: "guard".to_owned(),
            reason: None,
        };
        assert_eq!(
            bare.prompt_header("Run `deploy`"),
            "Run `deploy` — hook 'guard' asks for confirmation"
        );
        let blank = HookAsk {
            hook_name: "guard".to_owned(),
            reason: Some("  \n".to_owned()),
        };
        assert_eq!(blank.ask_line(), bare.ask_line());
        let multiline = HookAsk {
            hook_name: "guard".to_owned(),
            reason: Some("confirm\nthis".to_owned()),
        };
        assert_eq!(multiline.ask_line(), with_reason.ask_line());
    }
    #[test]
    fn agent_message_tool_filter_serde_is_dedicated_and_unknown_is_rejected() {
        let filter: ToolFilter = serde_json::from_str(r#""agent_message""#).unwrap();
        assert_eq!(filter, ToolFilter::AgentMessage);
        assert_eq!(
            serde_json::to_string(&filter).unwrap(),
            r#""agent_message""#
        );
        assert!(serde_json::from_str::<ToolFilter>(r#""future_tool""#).is_err());
    }
    #[test]
    fn permission_event_subagent_fields_default_to_none() {
        let json = r#"{
            "tool_id": "tc1",
            "tool_name": "bash",
            "access_kind": "bash",
            "yolo_mode": false,
            "auto_approved": false,
            "user_prompted": true,
            "decision": "allow",
            "timestamp": "2026-03-24T00:00:00Z"
        }"#;
        let event: PermissionEvent = serde_json::from_str(json).unwrap();
        assert!(event.subagent_session_id.is_none());
        assert!(event.subagent_type.is_none());
        assert!(event.subagent_description.is_none());
        assert!(event.permission_mode.is_none());
        assert!(event.decision_reason.is_none());
        assert!(event.classifier_source.is_none());
        assert!(event.classifier_latency_ms.is_none());
        assert!(event.auto_denials_consecutive.is_none());
        assert!(event.auto_denials_total.is_none());
        assert!(event.wait_ms.is_none());
        assert!(event.queue_depth.is_none());
        assert!(event.security_findings.is_none());
        assert!(event.classifier_verdict.is_none());
    }
    #[test]
    fn permission_event_findings_none_vs_some_empty_are_distinct() {
        let base = r#"{
            "tool_id": "tc1",
            "tool_name": "bash",
            "access_kind": "bash",
            "yolo_mode": false,
            "auto_approved": false,
            "user_prompted": true,
            "decision": "allow",
            "timestamp": "2026-03-24T00:00:00Z",
            "security_findings": [],
            "classifier_verdict": "block"
        }"#;
        let event: PermissionEvent = serde_json::from_str(base).unwrap();
        assert_eq!(event.security_findings.as_deref(), Some(&[][..]));
        assert_eq!(event.classifier_verdict.as_deref(), Some("block"));
        let with_tokens: PermissionEvent = serde_json::from_str(&base.replace(
            "\"security_findings\": []",
            "\"security_findings\": [\"opaque_shell\"]",
        ))
        .unwrap();
        assert_eq!(
            with_tokens.security_findings.as_deref(),
            Some(&["opaque_shell".to_owned()][..])
        );
    }
    #[test]
    fn permission_event_with_subagent_attribution() {
        let event = PermissionEvent {
            tool_id: "tc1".into(),
            tool_name: "bash".into(),
            access_kind: "bash".into(),
            access_detail: None,
            yolo_mode: false,
            auto_approved: false,
            user_prompted: true,
            decision: "allow".into(),
            prompt_outcome: None,
            reject_reason: None,
            timestamp: Utc::now(),
            subagent_session_id: Some("child-1".into()),
            subagent_type: Some("explore".into()),
            subagent_description: Some("Find endpoints".into()),
            permission_mode: Some("ask".into()),
            decision_reason: Some("needs_user".into()),
            classifier_source: Some("llm".into()),
            classifier_latency_ms: Some(42),
            auto_denials_consecutive: Some(2),
            auto_denials_total: Some(5),
            wait_ms: Some(1234),
            queue_depth: Some(3),
            security_findings: Some(vec!["opaque_shell".into()]),
            classifier_verdict: Some("block".into()),
            remember_tool_approvals: Some(true),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["subagent_session_id"], "child-1");
        assert_eq!(json["subagent_type"], "explore");
        assert_eq!(json["subagent_description"], "Find endpoints");
        assert_eq!(json["permission_mode"], "ask");
        assert_eq!(json["decision_reason"], "needs_user");
        assert_eq!(json["classifier_source"], "llm");
        assert_eq!(json["classifier_latency_ms"], 42);
        assert_eq!(json["auto_denials_consecutive"], 2);
        assert_eq!(json["auto_denials_total"], 5);
        assert_eq!(json["wait_ms"], 1234);
        assert_eq!(json["queue_depth"], 3);
        assert_eq!(json["security_findings"][0], "opaque_shell");
        assert_eq!(json["classifier_verdict"], "block");
        assert_eq!(json["remember_tool_approvals"], true);
    }
    #[test]
    fn permission_event_skips_none_optional_fields() {
        let event = PermissionEvent {
            tool_id: "tc1".into(),
            tool_name: "bash".into(),
            access_kind: "bash".into(),
            access_detail: None,
            yolo_mode: false,
            auto_approved: true,
            user_prompted: false,
            decision: "allow".into(),
            prompt_outcome: None,
            reject_reason: None,
            timestamp: Utc::now(),
            subagent_session_id: None,
            subagent_type: None,
            subagent_description: None,
            permission_mode: None,
            decision_reason: None,
            classifier_source: None,
            classifier_latency_ms: None,
            auto_denials_consecutive: None,
            auto_denials_total: None,
            wait_ms: None,
            queue_depth: None,
            security_findings: None,
            classifier_verdict: None,
            remember_tool_approvals: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("subagent_session_id"));
        assert!(!json.contains("subagent_type"));
        assert!(!json.contains("permission_mode"));
        assert!(!json.contains("decision_reason"));
        assert!(!json.contains("classifier_source"));
        assert!(!json.contains("classifier_latency_ms"));
        assert!(!json.contains("auto_denials_consecutive"));
        assert!(!json.contains("auto_denials_total"));
        assert!(!json.contains("wait_ms"));
        assert!(!json.contains("queue_depth"));
        assert!(!json.contains("security_findings"));
        assert!(!json.contains("classifier_verdict"));
        assert!(!json.contains("remember_tool_approvals"));
    }
    #[test]
    fn hashline_edit_maps_to_edit_access() {
        use fuigo_tools::implementations::fuigo_build_hashline::edit::types::HashlineEditInput;
        use fuigo_tools::types::ToolInput;
        let input = ToolInput::HashlineEdit(HashlineEditInput {
            file_path: "src/main.rs".into(),
            edits: vec![],
        });
        let access = AccessKind::from(&input);
        assert!(
            matches!(access, AccessKind::Edit(ref p) if p == "src/main.rs"),
            "HashlineEdit should produce AccessKind::Edit with the file path, got {access:?}"
        );
    }
    #[test]
    fn bash_maps_to_bash_access() {
        use fuigo_tools::implementations::fuigo_build::bash::BashToolInput;
        use fuigo_tools::types::ToolInput;
        let input = ToolInput::Bash(BashToolInput {
            command: "cargo test".into(),
            timeout: None,
            description: "run tests".into(),
            is_background: false,
            workdir: None,
        });
        let access = AccessKind::from(&input);
        assert!(
            matches!(access, AccessKind::Bash(ref cmd) if cmd == "cargo test"),
            "Bash should produce AccessKind::Bash with the command, got {access:?}"
        );
    }
    #[test]
    fn active_agent_message_maps_to_dedicated_access_without_text() {
        use fuigo_tools::implementations::fuigo_build::send_subagent_message::SendSubagentMessageInput;
        use fuigo_tools::types::ToolInput;
        let text = "private follow-up";
        let access = AccessKind::from(&ToolInput::SendSubagentMessage(SendSubagentMessageInput {
            subagent_id: "sub-1".into(),
            text: text.into(),
            delivery: None,
        }));
        let AccessKind::AgentMessage { subagent_id } = access else {
            panic!("active agent messages must use dedicated access")
        };
        assert_eq!(subagent_id, "sub-1");
        assert!(!subagent_id.contains(text));
    }
    #[test]
    fn use_tool_maps_to_mcp_tool_access() {
        use fuigo_tools::implementations::use_tool::UseToolInput;
        use fuigo_tools::types::ToolInput;
        let input = ToolInput::UseTool(UseToolInput {
            tool_name: "linear__save_issue".into(),
            tool_input: serde_json::json!({ "title" : "test" }),
        });
        let access = AccessKind::from(&input);
        assert!(
            matches!(
                access,
                AccessKind::MCPTool { ref name, ref input }
                    if name == "linear__save_issue" && input["title"] == "test"
            ),
            "UseTool should produce AccessKind::MCPTool carrying the inner tool name and args, got {access:?}"
        );
    }
    #[test]
    fn monitor_maps_to_bash_access() {
        use fuigo_tools::implementations::fuigo_build::monitor::types::MonitorInput;
        use fuigo_tools::types::ToolInput;
        let input = ToolInput::Monitor(MonitorInput {
            command: "tail -f /var/log/syslog".into(),
            description: "watch syslog".into(),
            timeout_ms: None,
            persistent: false,
        });
        let access = AccessKind::from(&input);
        assert!(
            matches!(access, AccessKind::Bash(ref cmd) if cmd == "tail -f /var/log/syslog"),
            "Monitor runs shell and must map to AccessKind::Bash (not Read), got {access:?}"
        );
    }
    #[test]
    fn search_replace_maps_to_edit_access() {
        use fuigo_tools::implementations::fuigo_build::search_replace::SearchReplaceInput;
        use fuigo_tools::types::ToolInput;
        let input = ToolInput::SearchReplace(SearchReplaceInput {
            file_path: "lib.rs".into(),
            old_string: "old".into(),
            new_string: "new".into(),
            replace_all: false,
        });
        let access = AccessKind::from(&input);
        assert!(
            matches!(access, AccessKind::Edit(ref p) if p == "lib.rs"),
            "SearchReplace should produce AccessKind::Edit, got {access:?}"
        );
    }
    #[test]
    fn web_fetch_maps_to_web_fetch_access() {
        use fuigo_tools::implementations::fuigo_build::web_fetch::WebFetchInput;
        use fuigo_tools::types::ToolInput;
        let input = ToolInput::WebFetch(WebFetchInput {
            url: "https://custom.example.com/api".into(),
        });
        let access = AccessKind::from(&input);
        assert!(
            matches!(access, AccessKind::WebFetch(ref u) if u == "https://custom.example.com/api"),
            "WebFetch should produce AccessKind::WebFetch with the URL, got {access:?}"
        );
    }
    #[test]
    fn web_search_maps_to_web_search_access() {
        use fuigo_tools::implementations::fuigo_build::web_search::WebSearchInput;
        use fuigo_tools::types::ToolInput;
        let input = ToolInput::WebSearch(WebSearchInput {
            query: "rust lang".into(),
            allowed_domains: None,
        });
        let access = AccessKind::from(&input);
        assert!(
            matches!(access, AccessKind::WebSearch(ref q) if q == "rust lang"),
            "WebSearch should produce AccessKind::WebSearch with the query, got {access:?}"
        );
    }
    #[test]
    fn apply_patch_maps_to_edit_access() {
        use fuigo_tools::implementations::codex::apply_patch::ApplyPatchInput;
        use fuigo_tools::types::ToolInput;
        let input = ToolInput::ApplyPatch(ApplyPatchInput {
            patch: String::new(),
        });
        let access = AccessKind::from(&input);
        assert!(
            matches!(access, AccessKind::Edit(_)),
            "ApplyPatch should produce AccessKind::Edit, got {access:?}"
        );
    }
    #[test]
    fn write_tool_maps_to_edit_access() {
        use fuigo_tools::implementations::opencode::write::WriteInput;
        use fuigo_tools::types::ToolInput;
        let input = ToolInput::Write(WriteInput {
            file_path: "/tmp/secret.txt".into(),
            content: "overwritten".into(),
        });
        let access = AccessKind::from(&input);
        assert!(
            matches!(access, AccessKind::Edit(ref p) if p == "/tmp/secret.txt"),
            "Write should produce AccessKind::Edit with the file path, got {access:?}"
        );
    }
    #[test]
    fn write_scoped_and_dynamic_inputs_map_to_edit_not_read() {
        use fuigo_tools::implementations::opencode::edit::EditInput;
        use fuigo_tools::types::ToolInput;
        use fuigo_tool_types::TaskToolInput;
        let edit = ToolInput::from(EditInput {
            file_path: "/tmp/denied.txt".into(),
            old_string: "ORIGINAL".into(),
            new_string: "BYPASS".into(),
            replace_all: false,
        });
        assert!(matches!(
            &edit,
            ToolInput::SearchReplace(sr) if sr.file_path == "/tmp/denied.txt"
        ));
        assert!(matches!(
            AccessKind::from(&edit),
            AccessKind::Edit(p) if p == "/tmp/denied.txt"
        ));
        assert!(matches!(
            AccessKind::from(&ToolInput::Task(TaskToolInput {
                prompt: "edit config.toml".into(),
                description: "spawn".into(),
                subagent_type: "general-purpose".into(),
                run_in_background: false,
                capability_mode: None,
                isolation: None,
                resume_from: None,
                cwd: None,
                model: None,
                task_id: None,
            })),
            AccessKind::Edit(p) if p == "task:general-purpose"
        ));
        assert!(matches!(
            AccessKind::from(&ToolInput::Dynamic(serde_json::json!({
                "filePath": "/tmp/denied.txt",
                "oldString": "a",
                "newString": "b",
            }))),
            AccessKind::Edit(p) if p == "/tmp/denied.txt"
        ));
        assert!(matches!(
            AccessKind::from(&ToolInput::Dynamic(serde_json::json!({
                "filePath": "src/main.rs"
            }))),
            AccessKind::Read(Some(p)) if p == "src/main.rs"
        ));
        assert!(matches!(
            AccessKind::from(&ToolInput::Dynamic(serde_json::json!({
                "command": "rm -rf /"
            }))),
            AccessKind::Bash(c) if c == "rm -rf /"
        ));
    }
    /// P165 (S1): one wire fixture per side-effecting built-in tool (scheduler, workflow, image and video generation).
    pub(crate) fn side_effecting_tool_inputs() -> Vec<(&'static str, fuigo_tools::types::ToolInput)>
    {
        [
            (
                "scheduler_create",
                serde_json::json!({"variant": "SchedulerCreate", "prompt": "run the report", "interval": "5m"}),
            ),
            (
                "scheduler_delete",
                serde_json::json!({"variant": "SchedulerDelete", "id": "task-1"}),
            ),
            (
                "workflow",
                serde_json::json!({"variant": "Workflow", "source": {"type": "name", "name": "ship"}}),
            ),
            (
                "image_gen",
                serde_json::json!({"variant": "ImageGen", "prompt": "a cat"}),
            ),
            (
                "image_edit",
                serde_json::json!({"variant": "ImageEdit", "prompt": "a hat", "image": ["/tmp/cat.png"]}),
            ),
            (
                "image_to_video",
                serde_json::json!({"variant": "ImageToVideo", "image": "/tmp/cat.png"}),
            ),
            (
                "reference_to_video",
                serde_json::json!({"variant": "ReferenceToVideo", "prompt": "a cat", "aspect_ratio": "16:9"}),
            ),
        ]
        .into_iter()
        .map(|(name, wire)| {
            let input = serde_json::from_value(wire.clone())
                .unwrap_or_else(|e| panic!("{name} fixture must parse: {e}: {wire}"));
            (name, input)
        })
        .collect()
    }

    /// P165 (S1): a tool that schedules, runs a workflow or generates media is not a read.
    /// Before the fix every one of these fell through the catch-all arm to `Read(None)`, which the manager auto-allows.
    #[test]
    fn side_effecting_tools_never_map_to_an_auto_allowed_kind() {
        for (name, input) in side_effecting_tool_inputs() {
            let access = AccessKind::from(&input);
            assert!(
                !matches!(
                    access,
                    AccessKind::Read(_) | AccessKind::Grep { .. } | AccessKind::WebSearch(_)
                ),
                "{name} must not map to an auto-allowed access kind, got {access:?}"
            );
        }
    }

    /// P165 (Astra r1 MEDIUM): a workflow dry run (`validate_only` on a named, inline or on-disk script) is a read and does
    /// not prompt; a launch, a resume, a pause or a stop prompts even with `validate_only` set.
    #[test]
    fn workflow_validate_only_is_a_read_but_control_and_launch_prompt() {
        use fuigo_tools::types::ToolInput;
        let access = |wire: serde_json::Value| {
            let input: ToolInput = serde_json::from_value(wire.clone())
                .unwrap_or_else(|e| panic!("workflow fixture must parse: {e}: {wire}"));
            AccessKind::from(&input)
        };
        for source in [
            serde_json::json!({"type": "name", "name": "ship"}),
            serde_json::json!({"type": "script", "script": "let meta = #{ name: \"x\", description: \"y\" };"}),
        ] {
            let validate = access(
                serde_json::json!({"variant": "Workflow", "source": source.clone(), "validate_only": true}),
            );
            assert!(
                matches!(validate, AccessKind::Read(None)),
                "{source}: got {validate:?}"
            );
            let launch =
                access(serde_json::json!({"variant": "Workflow", "source": source.clone()}));
            assert!(
                matches!(launch, AccessKind::Tool(ref n) if n == "workflow"),
                "{source}: got {launch:?}"
            );
        }
        let by_path = access(serde_json::json!({
            "variant": "Workflow", "source": {"type": "script_path", "script_path": "/w/flow.rhai"}, "validate_only": true
        }));
        assert!(
            matches!(by_path, AccessKind::Read(Some(ref p)) if p == "/w/flow.rhai"),
            "got {by_path:?}"
        );
        for source in [
            serde_json::json!({"type": "resume", "resume_from_run_id": "run-1"}),
            serde_json::json!({"type": "pause", "run_id": "run-1"}),
            serde_json::json!({"type": "stop", "run_id": "run-1"}),
        ] {
            let control = access(
                serde_json::json!({"variant": "Workflow", "source": source.clone(), "validate_only": true}),
            );
            assert!(
                matches!(control, AccessKind::Tool(ref n) if n == "workflow"),
                "{source}: got {control:?}"
            );
        }
    }

    /// P165 (S1): a runtime (opencode) input of an unrecognized shape fails closed instead of reading as `Read(None)`.
    /// The read-only opencode shapes (todo list, glob/grep pattern, skill load) keep their read classification.
    #[test]
    fn dynamic_input_of_unknown_shape_fails_closed() {
        use fuigo_tools::types::ToolInput;
        for unknown in [
            serde_json::json!({"target": "prod", "action": "deploy"}),
            serde_json::json!({}),
            serde_json::json!("not-an-object"),
        ] {
            let access = AccessKind::from(&ToolInput::Dynamic(unknown.clone()));
            assert!(
                !matches!(
                    access,
                    AccessKind::Read(_) | AccessKind::Grep { .. } | AccessKind::WebSearch(_)
                ),
                "unknown dynamic shape {unknown} must not be auto-allowed, got {access:?}"
            );
        }
        for read_only in [
            serde_json::json!({"todos": []}),
            serde_json::json!({"pattern": "*.rs"}),
            serde_json::json!({"pattern": "fn main", "include": "*.rs"}),
            serde_json::json!({"name": "create-workflow"}),
        ] {
            let access = AccessKind::from(&ToolInput::Dynamic(read_only.clone()));
            assert!(
                matches!(access, AccessKind::Read(_) | AccessKind::Grep { .. }),
                "read-only opencode shape {read_only} must stay a read, got {access:?}"
            );
        }
    }

    /// P165 (S1): the codex/memory/LSP read tools carry their path, so path-scoped Read rules reach them.
    #[test]
    fn path_reading_tools_carry_their_path() {
        use fuigo_tools::types::ToolInput;
        let cases = [
            (
                serde_json::json!({"variant": "CodexReadFile", "file_path": "/w/.env"}),
                Some("/w/.env"),
            ),
            (
                serde_json::json!({"variant": "CodexListDir", "dir_path": "/w/secrets"}),
                Some("/w/secrets"),
            ),
            (
                serde_json::json!({"variant": "MemoryGet", "path": "notes.md"}),
                Some("notes.md"),
            ),
            (
                serde_json::json!({"variant": "Lsp", "operation": "hover", "file_path": "/w/src/main.rs"}),
                Some("/w/src/main.rs"),
            ),
        ];
        for (wire, want) in cases {
            let input: ToolInput = serde_json::from_value(wire.clone())
                .unwrap_or_else(|e| panic!("fixture must parse: {e}: {wire}"));
            let access = AccessKind::from(&input);
            assert!(
                matches!(&access, AccessKind::Read(got) if got.as_deref() == want),
                "{wire} must map to Read({want:?}), got {access:?}"
            );
        }
        let grep: ToolInput = serde_json::from_value(serde_json::json!({
            "variant": "CodexGrepFiles", "pattern": "KEY", "path": "/w/secrets", "include": "*.env"
        }))
        .expect("codex grep fixture parses");
        assert!(
            matches!(
                AccessKind::from(&grep),
                AccessKind::Grep { path: Some(ref p), glob: Some(ref g) } if p == "/w/secrets" && g == "*.env"
            ),
            "CodexGrepFiles must map to Grep with its path and include"
        );
    }

    #[test]
    fn client_type_deserializes_fuigo_shell_as_generic() {
        assert_eq!(
            serde_json::from_value::<ClientType>("fuigo-shell".into()).unwrap(),
            ClientType::Generic,
        );
        assert_eq!(
            serde_json::from_value::<ClientType>("fuigo_shell".into()).unwrap(),
            ClientType::Generic,
        );
        assert_eq!(
            serde_json::from_value::<ClientType>("generic".into()).unwrap(),
            ClientType::Generic,
        );
    }
}
