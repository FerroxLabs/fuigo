pub mod command;
pub mod http;

use std::time::Duration;

use crate::config::HookSpec;
use crate::event::{HookEventEnvelope, MAX_HOOK_FEEDBACK_CHARS, clip_reason, clip_text};
use serde::Deserialize;

use crate::result::{
    HttpInfo, OutputReplacement, PostToolUseHookOutcome, ReplacementKind, StopHookOutcome,
};

pub use crate::event::GateKind;

pub struct RunContext<'a> {
    pub session_id: &'a str,
    pub workspace_root: &'a str,
    pub process_scope: Option<fuigo_tools::util::ProcessScope>,
}

#[derive(Debug)]
pub enum HookRunnerResult {
    Allow {
        updated_input: Option<serde_json::Map<String, serde_json::Value>>,
        additional_context: Option<String>,
    },
    Ask {
        reason: Option<String>,
        updated_input: Option<serde_json::Map<String, serde_json::Value>>,
        additional_context: Option<String>,
    },
    Defer,
    Deny {
        reason: String,
        hook_name: String,
    },
    Block {
        reason: String,
        hook_name: String,
    },
    Stop(StopHookOutcome),
    /// A tool gate answered `continue: false`: the call is refused and the turn ends.
    GateStop {
        reason: String,
        hook_name: String,
    },
    PostToolUse {
        outcome: PostToolUseHookOutcome,
        failure: Option<String>,
    },
    Success,
    Failed(String),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GateHookJson {
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    hook_specific_output: Option<GateHookSpecificOutputJson>,
    #[serde(flatten)]
    rest: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GateHookSpecificOutputJson {
    #[serde(default)]
    permission_decision: Option<String>,
    #[serde(default)]
    permission_decision_reason: Option<String>,
    #[serde(default)]
    updated_input: Option<serde_json::Value>,
    #[serde(default)]
    additional_context: Option<serde_json::Value>,
    #[serde(flatten)]
    rest: serde_json::Map<String, serde_json::Value>,
}

struct NonObjectRewrite;

impl GateHookJson {
    fn is_gate_document(&self) -> bool {
        self.decision.is_some()
            || self.hook_specific_output.is_some()
            || self.rest.keys().any(|key| {
                matches!(
                    key.as_str(),
                    "updatedInput"
                        | "permissionDecision"
                        | "permissionDecisionReason"
                        | "continue"
                        | "additionalContext"
                )
            })
    }

    /// A key this document carries that Fuigo does not recognise on a tool gate, at the top level or inside
    /// `hookSpecificOutput`: the flattened `rest` maps hold exactly the keys the typed fields did not take.
    fn unknown_key(&self) -> Option<String> {
        if let Some(key) = first_unknown(&self.rest, RECOGNISED_EXTRA_TOP_LEVEL_KEYS, &[]) {
            return Some(key);
        }
        let nested = self.hook_specific_output.as_ref()?;
        first_unknown(&nested.rest, &["hookEventName"], &[]).map(|key| format!("hookSpecificOutput.{key}"))
    }

    fn permission_decision(&self) -> Option<&str> {
        non_empty(
            self.hook_specific_output
                .as_ref()
                .and_then(|output| output.permission_decision.as_deref()),
        )
    }

    fn permission_decision_reason(&self) -> Option<&str> {
        self.hook_specific_output
            .as_ref()
            .and_then(|output| output.permission_decision_reason.as_deref())
    }

    fn resolve_decision(&self) -> GateDecision {
        let (field, decision_str) = match (
            self.permission_decision(),
            non_empty(self.decision.as_deref()),
        ) {
            (Some(token), _) => (DecisionField::HookSpecific, Some(token)),
            (None, legacy) => (DecisionField::TopLevel, legacy),
        };
        let token = decision_str.map_or(DecisionToken::Allow, |token| {
            DecisionToken::classify(field, token)
        });
        let reason = non_empty(self.permission_decision_reason())
            .or(non_empty(self.reason.as_deref()))
            .map(str::to_string);
        GateDecision { token, reason }
    }

    fn take_updated_input(
        self,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, NonObjectRewrite> {
        match self
            .hook_specific_output
            .and_then(|output| output.updated_input)
        {
            None => Ok(None),
            Some(serde_json::Value::Object(input)) => Ok(Some(input)),
            Some(_) => Err(NonObjectRewrite),
        }
    }

    fn ignored_parts(&self, decision: &DecisionToken) -> Vec<String> {
        let top = self
            .rest
            .keys()
            .filter(|key| !SILENTLY_IGNORED_TOP_LEVEL_KEYS.contains(&key.as_str()))
            .cloned();
        let nested = self
            .hook_specific_output
            .iter()
            .flat_map(|output| output.rest.keys())
            .filter(|key| !SILENTLY_IGNORED_NESTED_KEYS.contains(&key.as_str()))
            .map(|key| format!("hookSpecificOutput.{key}"));
        let unread_reason = (matches!(decision, DecisionToken::Allow | DecisionToken::Defer)
            && (non_empty(self.reason.as_deref()).is_some()
                || non_empty(self.permission_decision_reason()).is_some()))
        .then(|| "reason (only a deny or an ask has one)".to_string());
        let nested_output = self.hook_specific_output.as_ref();
        let deferred_rewrite = (matches!(decision, DecisionToken::Defer)
            && nested_output.is_some_and(|output| output.updated_input.is_some()))
        .then(|| "hookSpecificOutput.updatedInput".to_string());
        let bad_context = self
            .raw_additional_context()
            .is_some_and(|value| !value.is_string());
        let unread_valid_context = matches!(decision, DecisionToken::Defer | DecisionToken::Deny)
            && self.additional_context().is_some();
        let unread_context = (bad_context || unread_valid_context)
            .then(|| "hookSpecificOutput.additionalContext".to_string());
        top.chain(nested)
            .chain(unread_reason)
            .chain(deferred_rewrite)
            .chain(unread_context)
            .collect()
    }

    fn raw_additional_context(&self) -> Option<&serde_json::Value> {
        self.hook_specific_output
            .as_ref()
            .and_then(|output| output.additional_context.as_ref())
    }

    fn additional_context(&self) -> Option<String> {
        let text = self.raw_additional_context()?.as_str()?;
        (!text.trim().is_empty()).then(|| clip_text(text, MAX_HOOK_FEEDBACK_CHARS))
    }
}

/// Keys Fuigo reads or knowingly ignores that the typed gate/prompt structs do not hold as fields (they arrive in the
/// flattened `rest` map): the event name, the stop request and its reason, and the two message keys.
const RECOGNISED_EXTRA_TOP_LEVEL_KEYS: &[&str] =
    &["hookEventName", "continue", "stopReason", "systemMessage", "suppressOutput"];
/// What a prompt hook's `hookSpecificOutput` may hold (the upstream shape carries context).
const PROMPT_NESTED_KEYS: &[&str] = &["hookEventName", "additionalContext"];

fn first_unknown(
    rest: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    also_allowed: &[&str],
) -> Option<String> {
    rest.keys()
        .find(|key| !allowed.contains(&key.as_str()) && !also_allowed.contains(&key.as_str()))
        .map(|key| key.chars().take(60).collect())
}

const SILENTLY_IGNORED_TOP_LEVEL_KEYS: &[&str] =
    &["hookEventName", "continue", "stopReason", "systemMessage", "suppressOutput"];
const SILENTLY_IGNORED_NESTED_KEYS: &[&str] = &["hookEventName"];

fn non_empty(text: Option<&str>) -> Option<&str> {
    let trimmed = text?.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// Extract a hook's top-level `systemMessage` warning from its stdout JSON.
pub(crate) fn extract_system_message(stdout: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
    non_empty(
        value
            .get("systemMessage")
            .and_then(serde_json::Value::as_str),
    )
    .map(crate::event::clip_reason)
}

#[derive(Debug, PartialEq, Eq)]
enum DecisionToken {
    Allow,
    Deny,
    Ask,
    Defer,
    Unknown { field: DecisionField, token: String },
}

impl DecisionToken {
    fn classify(field: DecisionField, token: &str) -> Self {
        match token {
            "allow" | "approve" => Self::Allow,
            "deny" | "block" => Self::Deny,
            "ask" => Self::Ask,
            "defer" => Self::Defer,
            other => Self::Unknown {
                field,
                token: other.to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecisionField {
    TopLevel,
    HookSpecific,
}

impl DecisionField {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::TopLevel => "decision",
            Self::HookSpecific => "hookSpecificOutput.permissionDecision",
        }
    }
}

struct GateDecision {
    token: DecisionToken,
    reason: Option<String>,
}

pub(crate) enum GateOutcome {
    Allow {
        updated_input: Option<serde_json::Map<String, serde_json::Value>>,
        additional_context: Option<String>,
    },
    Ask {
        reason: Option<String>,
        updated_input: Option<serde_json::Map<String, serde_json::Value>>,
        additional_context: Option<String>,
    },
    Defer,
    Deny(String),
    /// `continue: false`: the call is refused and the turn ends; the string is what the user is shown.
    Stop(String),
    Failed(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookHealth {
    Healthy,
    Broken,
}

impl HookHealth {
    pub(crate) fn from_success(success: bool) -> Self {
        if success { Self::Healthy } else { Self::Broken }
    }
}

pub(crate) fn gate_outcome(
    json: GateHookJson,
    hook_name: &str,
    fallback_reason: Option<&str>,
    health: HookHealth,
) -> GateOutcome {
    let GateDecision { token, reason } = json.resolve_decision();
    // `continue: false` ends the run; at a tool gate the call is not made, and the stop reason is what the model is told
    let stop_requested = json.rest.get("continue") == Some(&serde_json::Value::Bool(false));
    let stop_reason = json
        .rest
        .get("stopReason")
        .and_then(serde_json::Value::as_str)
        .and_then(|text| non_empty(Some(text)))
        .map(clip_reason);
    let mut ignored = json.ignored_parts(&token);
    let additional_context = json.additional_context();
    let updated_input = resolve_rewrite(json, hook_name, health, &mut ignored);

    if !ignored.is_empty() {
        tracing::warn!(
            hook_name,
            ignored = %ignored.join(", "),
            "ignoring parts of a gate hook document"
        );
    }

    if stop_requested && !matches!(token, DecisionToken::Unknown { .. }) {
        let denial = matches!(token, DecisionToken::Deny)
            .then(|| reason.as_deref().and_then(|text| non_empty(Some(text))).map(clip_reason))
            .flatten();
        return GateOutcome::Stop(
            stop_reason
                .or(denial)
                .unwrap_or_else(|| format!("stopped by hook '{hook_name}' (continue: false)")),
        );
    }

    match token {
        DecisionToken::Deny => GateOutcome::Deny(clip_reason(
            &reason
                .or_else(|| fallback_reason.map(str::to_string))
                .unwrap_or_else(|| format!("denied by hook '{hook_name}'")),
        )),
        DecisionToken::Unknown { field, token } => GateOutcome::Failed(format!(
            "unknown decision value '{}' in '{}' from hook '{hook_name}'",
            clip_reason(&token),
            field.wire_name()
        )),
        DecisionToken::Ask => GateOutcome::Ask {
            reason: reason.as_deref().map(clip_reason),
            updated_input,
            additional_context: drop_if_broken(
                additional_context,
                hook_name,
                "additionalContext",
                health,
            ),
        },
        DecisionToken::Defer => GateOutcome::Defer,
        DecisionToken::Allow => GateOutcome::Allow {
            updated_input,
            additional_context: drop_if_broken(
                additional_context,
                hook_name,
                "additionalContext",
                health,
            ),
        },
    }
}

fn resolve_rewrite(
    json: GateHookJson,
    hook_name: &str,
    health: HookHealth,
    ignored: &mut Vec<String>,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let updated_input = match json.take_updated_input() {
        Ok(updated_input) => updated_input,
        Err(NonObjectRewrite) => {
            ignored.push("hookSpecificOutput.updatedInput (not an object)".to_string());
            None
        }
    };
    drop_if_broken(updated_input, hook_name, "updatedInput", health)
}

fn drop_if_broken<T>(
    value: Option<T>,
    hook_name: &str,
    wire_field: &str,
    health: HookHealth,
) -> Option<T> {
    if value.is_some() && health == HookHealth::Broken {
        tracing::warn!(hook_name, wire_field, "dropping a failed hook's field");
        return None;
    }
    value
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PromptHookJson {
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    /// `false` stops the prompt from running, as a block does.
    #[serde(default, rename = "continue")]
    pub continue_: Option<bool>,
    #[serde(default, rename = "stopReason")]
    pub stop_reason: Option<String>,
    /// Every other key, kept only so a `failClosed` hook can be judged on keys Fuigo does not read.
    #[serde(flatten)]
    rest: serde_json::Map<String, serde_json::Value>,
}

impl PromptHookJson {
    /// A key this document carries that Fuigo does not recognise on a prompt hook, at the top level or inside
    /// `hookSpecificOutput`.
    fn unknown_key(&self) -> Option<String> {
        if let Some(key) = first_unknown(&self.rest, RECOGNISED_EXTRA_TOP_LEVEL_KEYS, &["hookSpecificOutput"]) {
            return Some(key);
        }
        match self.rest.get("hookSpecificOutput")? {
            serde_json::Value::Object(nested) => first_unknown(nested, PROMPT_NESTED_KEYS, &[])
                .map(|key| format!("hookSpecificOutput.{key}")),
            _ => Some("hookSpecificOutput".to_string()),
        }
    }
}

pub(crate) fn prompt_json_to_block(
    json: &PromptHookJson,
    hook_name: &str,
    fallback_reason: Option<&str>,
) -> Result<Option<String>, String> {
    match json.decision.as_deref() {
        Some("block") => Ok(Some(
            json.reason
                .clone()
                .filter(|r| !r.trim().is_empty())
                .or_else(|| fallback_reason.map(str::to_string))
                .unwrap_or_else(|| format!("Prompt blocked by hook '{hook_name}'")),
        )),
        None | Some("approve") => Ok(
            (json.continue_ == Some(false)).then(|| {
                non_empty(json.stop_reason.as_deref())
                    .or_else(|| non_empty(json.reason.as_deref()))
                    .or_else(|| non_empty(fallback_reason))
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("Prompt stopped by hook '{hook_name}' (continue: false)"))
            }),
        ),
        Some(other) => Err(format!(
            "unknown decision value '{other}' from hook '{hook_name}'"
        )),
    }
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct StopHookJson {
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default, rename = "continue")]
    pub continue_: Option<bool>,
    #[serde(default, rename = "stopReason")]
    pub stop_reason: Option<String>,
    #[serde(default, rename = "hookSpecificOutput")]
    pub hook_specific_output: Option<StopHookSpecificOutputJson>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct StopHookSpecificOutputJson {
    #[serde(default, rename = "additionalContext")]
    pub additional_context: Option<String>,
}

pub(crate) fn stop_json_to_outcome(
    json: StopHookJson,
    hook_name: &str,
) -> Result<StopHookOutcome, String> {
    let block_reason = match json.decision.as_deref() {
        Some("block") => Some(
            json.reason
                .filter(|reason| !reason.trim().is_empty())
                .unwrap_or_else(|| format!("Blocked by stop hook '{hook_name}'")),
        ),
        Some("approve") | None => None,
        Some(other) => {
            return Err(format!(
                "unknown decision value '{other}' from hook '{hook_name}'"
            ));
        }
    };
    Ok(StopHookOutcome {
        block_reason,
        additional_context: json
            .hook_specific_output
            .and_then(|output| output.additional_context)
            .filter(|context| !context.trim().is_empty())
            .map(|context| clip_text(&context, MAX_HOOK_FEEDBACK_CHARS)),
        force_stop: (json.continue_ == Some(false)).then_some(crate::result::StopOverride {
            reason: json.stop_reason,
        }),
    })
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PostToolUseHookJson {
    pub decision: Option<String>,
    pub reason: Option<String>,
    pub hook_specific_output: Option<PostToolUseHookSpecificOutputJson>,
    /// `false` ends the turn after this tool call.
    #[serde(rename = "continue")]
    pub continue_: Option<bool>,
    pub stop_reason: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PostToolUseHookSpecificOutputJson {
    pub additional_context: Option<String>,
    pub updated_tool_output: Option<serde_json::Value>,
    #[serde(rename = "updatedMCPToolOutput")]
    pub updated_mcp_tool_output: Option<serde_json::Value>,
}

#[derive(Debug, Default)]
pub(crate) struct PostToolUseParse {
    pub outcome: PostToolUseHookOutcome,
    pub failure: Option<String>,
}

pub(crate) fn post_tool_use_json_to_outcome(
    json: PostToolUseHookJson,
    hook_name: &str,
    health: HookHealth,
) -> PostToolUseParse {
    let mut failure = None;
    let force_stop = (json.continue_ == Some(false)).then(|| crate::result::StopOverride {
        reason: json
            .stop_reason
            .as_deref()
            .and_then(|text| non_empty(Some(text)))
            .map(|text| clip_text(text, MAX_HOOK_FEEDBACK_CHARS)),
    });
    let block_reason = match json.decision.as_deref() {
        Some("block") => Some(
            json.reason
                .filter(|reason| !reason.trim().is_empty())
                .map(|reason| clip_text(&reason, MAX_HOOK_FEEDBACK_CHARS))
                .unwrap_or_else(|| format!("Blocked by post_tool_use hook '{hook_name}'")),
        ),
        Some("approve") | None => None,
        Some(other) => {
            tracing::warn!(
                hook_name,
                decision = %other,
                "post_tool_use hook set an unrecognized decision; only \"block\" is honored"
            );
            failure = Some(format!(
                "post_tool_use hook '{hook_name}' set an unrecognized decision value '{}'; only \"block\" is honored",
                clip_reason(other)
            ));
            None
        }
    };
    let output = json.hook_specific_output.unwrap_or_default();
    let additional_context = output
        .additional_context
        .filter(|context| !context.trim().is_empty())
        .map(|context| clip_text(&context, MAX_HOOK_FEEDBACK_CHARS));
    let builtin = output.updated_tool_output;
    let mcp = output.updated_mcp_tool_output;
    let (kind, value) = match (builtin, mcp) {
        (Some(value), Some(_)) => {
            tracing::warn!(
                hook_name,
                "hook set both updatedToolOutput and updatedMCPToolOutput; keeping updatedToolOutput"
            );
            (ReplacementKind::Builtin, Some(value))
        }
        (Some(value), None) => (ReplacementKind::Builtin, Some(value)),
        (None, Some(value)) => (ReplacementKind::Mcp, Some(value)),
        (None, None) => (ReplacementKind::Builtin, None),
    };
    let output_replacement = value.map(|value| OutputReplacement {
        kind,
        hook_name: hook_name.to_string(),
        value,
    });
    let output_replacement = output_replacement.and_then(|replacement| {
        if health == HookHealth::Broken {
            tracing::warn!(
                hook_name,
                wire_field = replacement.wire_field(),
                "dropping a field of a hook that failed"
            );
            None
        } else {
            Some(replacement)
        }
    });
    PostToolUseParse {
        outcome: PostToolUseHookOutcome {
            block_reason,
            additional_context: drop_if_broken(
                additional_context,
                hook_name,
                "additionalContext",
                health,
            ),
            output_replacement,
            force_stop,
        },
        failure,
    }
}

pub type HookRunOutput = (HookRunnerResult, Duration, Option<HttpInfo>, Option<String>);

const FLAW_TRUNCATED: &str = "output was cut off by the size cap";
const FLAW_UNPARSED: &str = "printed a decision that could not be parsed";
const FLAW_UNKNOWN_KEY: &str = "printed a JSON object with a key Fuigo does not recognise";
const FLAW_NOT_UTF8: &str = "printed output that is not valid UTF-8";
const FLAW_DUPLICATE_KEY: &str = "printed a JSON object with a duplicate key";

/// What is wrong with a `PreToolUse` / `UserPromptSubmit` hook's output, for a `failClosed` hook: `None` when it is
/// fine. It judges the RAW bytes the hook sent, before any lenient decoding: normal handling reads a lossy UTF-8 copy
/// and keeps the last of duplicate keys, so a flaw judged on that copy can be repaired away. `truncated` is the reader's
/// own flag that the size cap cut the output off (never guessed from the text): what was kept may be a complete-looking
/// allow in front of a decision that was lost. Bytes that are not valid UTF-8 are a flaw. A command hook's plain text on
/// exit 0 is not a decision (it never was), so `strict` is false there and only output that starts like a JSON object
/// counts; an HTTP hook answers in JSON, so with `strict` any non-empty body counts. Output that counts must be exactly
/// one JSON value with no duplicate key at any depth and nothing after it, and an object fails closed when it holds any
/// key Fuigo does not recognise for the event, at the top level or inside `hookSpecificOutput` (a typo such as `decison`
/// or `permissionDecison`); a document of recognised keys only follows normal handling, and one that decides nothing is
/// an allow.
pub(crate) fn gate_output_flaw(
    mode: GateKind,
    raw: &[u8],
    strict: bool,
    truncated: bool,
) -> Option<String> {
    if truncated {
        return Some(FLAW_TRUNCATED.to_string());
    }
    if !matches!(mode, GateKind::Tool | GateKind::Prompt) {
        return None;
    }
    let Ok(text) = std::str::from_utf8(raw) else {
        return Some(FLAW_NOT_UTF8.to_string());
    };
    // Judge the text with only JSON whitespace trimmed: the lenient parser accepts nothing else around a document, so
    // any other leading or trailing character (form feed, NBSP, U+2028) must reach the strict parser and be a flaw.
    let text = text.trim_matches(|c| matches!(c, ' ' | '\t' | '\n' | '\r'));
    // "Looks like JSON" (command hooks): after any run of invisible characters (whitespace, control characters,
    // Unicode format characters such as a BOM or a zero-width space), an object opens.
    let looks_like_json = text.trim_start_matches(is_invisible_prefix_char).starts_with('{');
    if text.is_empty() || !(strict || looks_like_json) {
        return None;
    }
    let value = match strict_json_value(text) {
        Ok(value) => value,
        Err(StrictJsonError::DuplicateKey(key)) => {
            return Some(format!("{FLAW_DUPLICATE_KEY} ('{key}')"));
        }
        Err(StrictJsonError::Invalid) => return Some(FLAW_UNPARSED.to_string()),
    };
    // The value holds every key exactly once, so the typed documents built from it are faithful to what was sent.
    let unknown = match mode {
        GateKind::Tool => match serde_json::from_value::<GateHookJson>(value) {
            Ok(json) => json.unknown_key().map(KeyFlaw::Unknown).or_else(|| wrong_typed_key(&json.rest)),
            Err(_) => return Some(FLAW_UNPARSED.to_string()),
        },
        _ => match serde_json::from_value::<PromptHookJson>(value) {
            Ok(json) => json.unknown_key().map(KeyFlaw::Unknown).or_else(|| wrong_typed_key(&json.rest)),
            Err(_) => return Some(FLAW_UNPARSED.to_string()),
        },
    };
    match unknown {
        Some(KeyFlaw::WrongType(key)) => Some(format!("{FLAW_WRONG_TYPE} ('{key}')")),
        Some(KeyFlaw::Unknown(key)) => Some(format!("{FLAW_UNKNOWN_KEY} ('{key}')")),
        None => None,
    }
}

const FLAW_WRONG_TYPE: &str = "printed a recognised key with the wrong JSON type";

/// What the key check found: a key Fuigo does not recognise, or a recognised key with the wrong JSON type.
enum KeyFlaw {
    Unknown(String),
    WrongType(String),
}

/// A character that shows nothing when printed: whitespace, a control character, or a Unicode format character (Cf).
fn is_invisible_prefix_char(c: char) -> bool {
    c.is_whitespace()
        || c.is_control()
        || matches!(c,
            '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}' | '\u{180E}'
            | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{110BD}' | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}' | '\u{E0020}'..='\u{E007F}')
}

/// A recognised extra top-level key (it sits in the flattened `rest` map, so serde did not type it) whose JSON type is
/// not the one Fuigo reads: `continue` and `suppressOutput` are booleans, `stopReason` and `systemMessage` strings.
fn wrong_typed_key(rest: &serde_json::Map<String, serde_json::Value>) -> Option<KeyFlaw> {
    rest.iter().find_map(|(key, value)| {
        let ok = match key.as_str() {
            "continue" | "suppressOutput" => value.is_boolean(),
            "stopReason" | "systemMessage" | "hookEventName" => value.is_string(),
            _ => true,
        };
        (!ok).then(|| KeyFlaw::WrongType(key.clone()))
    })
}

#[derive(Debug, PartialEq, Eq)]
enum StrictJsonError {
    /// The first key seen twice in one object (clipped), at any depth.
    DuplicateKey(String),
    /// Not exactly one JSON value (a syntax error, a lone surrogate escape, trailing bytes, too deep).
    Invalid,
}

/// Parse `text` as exactly one JSON value, refusing a key repeated in any object at any depth and anything after the
/// value but whitespace.
fn strict_json_value(text: &str) -> Result<serde_json::Value, StrictJsonError> {
    use serde::de::DeserializeSeed;
    let duplicate = std::cell::RefCell::new(None);
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let parsed = StrictValue { duplicate: &duplicate }
        .deserialize(&mut deserializer)
        .and_then(|value| deserializer.end().map(|()| value));
    match (parsed, duplicate.into_inner()) {
        (_, Some(key)) => Err(StrictJsonError::DuplicateKey(key)),
        (Ok(value), None) => Ok(value),
        (Err(_), None) => Err(StrictJsonError::Invalid),
    }
}

/// Builds a `serde_json::Value` as `Value`'s own deserializer does, except that an object with a repeated key is an
/// error (recorded in `duplicate`) instead of keeping the last copy.
#[derive(Clone, Copy)]
struct StrictValue<'a> {
    duplicate: &'a std::cell::RefCell<Option<String>>,
}

impl<'de> serde::de::DeserializeSeed<'de> for StrictValue<'_> {
    type Value = serde_json::Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> serde::de::Visitor<'de> for StrictValue<'_> {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::from(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::from(value))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("a number that is not finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(self)? {
            items.push(item);
        }
        Ok(serde_json::Value::Array(items))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                let clipped: String = key.chars().take(60).collect();
                *self.duplicate.borrow_mut() = Some(clipped.clone());
                return Err(serde::de::Error::custom(format!("duplicate key '{clipped}'")));
            }
            let value = map.next_value_seed(self)?;
            object.insert(key, value);
        }
        Ok(serde_json::Value::Object(object))
    }
}

/// Opt-in `failClosed` enforcement, applied after the output is parsed and before a result that lets the call or prompt
/// through (allow, ask, defer, plain success) is accepted. Only an allowing result is overridden: a denial or block is
/// already the safe answer. `exec_failure` is the execution failure (killed by a signal, a non-zero exit that is not the
/// gate's exit 2, a non-success HTTP status) carried apart from the parsed output, so a decision printed before the crash
/// cannot launder it. `flaw` is what `gate_output_flaw` found wrong with the output (unreadable, truncated, not a decision). Without `fail_closed` the result is returned untouched.
pub(crate) fn enforce_fail_closed(
    spec: &HookSpec,
    mode: GateKind,
    result: HookRunnerResult,
    flaw: Option<String>,
    exec_failure: Option<String>,
) -> HookRunnerResult {
    if !spec.fail_closed || !matches!(mode, GateKind::Tool | GateKind::Prompt) {
        return result;
    }
    // A `continue: false` stop is a refusal, but one printed before the hook crashed or exited badly is still a
    // run-time failure and is reported as one.
    if matches!(result, HookRunnerResult::GateStop { .. }) {
        return exec_failure.map_or(result, HookRunnerResult::Failed);
    }
    if !matches!(
        result,
        HookRunnerResult::Allow { .. }
            | HookRunnerResult::Ask { .. }
            | HookRunnerResult::Defer
            | HookRunnerResult::Success
    ) {
        return result;
    }
    if let Some(failure) = exec_failure {
        return HookRunnerResult::Failed(failure);
    }
    if let Some(flaw) = flaw {
        return HookRunnerResult::Failed(format!("hook '{}' {flaw}", spec.name));
    }
    result
}

pub async fn run_hook(
    spec: &HookSpec,
    envelope: &HookEventEnvelope,
    ctx: &RunContext<'_>,
    mode: GateKind,
) -> HookRunOutput {
    let output = match spec.handler_type {
        crate::config::HandlerType::Command => {
            let (result, elapsed, system_message) =
                command::run_command_hook(spec, envelope, ctx, mode).await;
            (result, elapsed, None, system_message)
        }
        crate::config::HandlerType::Http => http::run_http_hook(spec, envelope, ctx, mode).await,
    };
    // Remember what this run proved about the hook: a CONFIG failure means skip it from now on (and say so once), and the
    // last RUNTIME error is what `/hooks` lists. A blocking denial is a successful run, not a failure.
    crate::health::note_result(ctx.session_id, &spec.name, &output.0);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_system_message_trims_and_ignores_blank_or_absent() {
        assert_eq!(
            extract_system_message(r#"{"systemMessage":"  heads up  ","decision":"allow"}"#),
            Some("heads up".to_string())
        );
        assert_eq!(extract_system_message(r#"{"decision":"allow"}"#), None);
        assert_eq!(extract_system_message(r#"{"systemMessage":"   "}"#), None);
        assert_eq!(extract_system_message(""), None);
        assert_eq!(extract_system_message("not json"), None);
    }

    #[test]
    fn ignored_parts_names_what_changed_nothing() {
        for (json, expected) in [
            (
                r#"{"decision":"allow","hookSpecificOutput":{"updateInput":{}}}"#,
                vec!["hookSpecificOutput.updateInput"],
            ),
            (
                r#"{"permissionDecision":"deny"}"#,
                vec!["permissionDecision"],
            ),
            (r#"{"decision":"allow","continue":false}"#, vec![]),
            (r#"{"decision":"allow","suppressOutput":true}"#, vec![]),
            (
                r#"{"decision":"allow","reason":"why"}"#,
                vec!["reason (only a deny or an ask has one)"],
            ),
            (r#"{"decision":"deny","reason":"why"}"#, vec![]),
            (
                r#"{"decision":"deny","reason":"why","hookSpecificOutput":{"additionalContext":"note"}}"#,
                vec!["hookSpecificOutput.additionalContext"],
            ),
            (
                r#"{"hookSpecificOutput":{"permissionDecision":"defer","updatedInput":{"command":"x"},"additionalContext":"note"}}"#,
                vec![
                    "hookSpecificOutput.updatedInput",
                    "hookSpecificOutput.additionalContext",
                ],
            ),
        ] {
            let document: GateHookJson = serde_json::from_str(json).expect("valid gate JSON");
            let decision = document.resolve_decision().token;
            assert_eq!(document.ignored_parts(&decision), expected, "for {json}");
        }
    }

    fn gate(json: &str) -> GateOutcome {
        let document: GateHookJson = serde_json::from_str(json).expect("valid gate JSON");
        gate_outcome(document, "stopper", None, HookHealth::Healthy)
    }

    #[test]
    fn continue_false_at_a_tool_gate_stops_the_call_with_the_stop_reason() {
        for json in [
            r#"{"continue":false,"stopReason":"enough"}"#,
            r#"{"decision":"allow","continue":false,"stopReason":"enough"}"#,
            r#"{"hookSpecificOutput":{"permissionDecision":"ask"},"continue":false,"stopReason":"enough"}"#,
        ] {
            assert!(matches!(gate(json), GateOutcome::Stop(ref reason) if reason == "enough"), "for {json}");
        }
        assert!(
            matches!(gate(r#"{"continue":false}"#), GateOutcome::Stop(ref reason) if reason.contains("continue: false")),
            "without a stop reason the hook is named"
        );
        assert!(matches!(gate(r#"{"continue":true,"stopReason":"enough"}"#), GateOutcome::Allow { .. }));
        assert!(matches!(gate(r#"{"decision":"allow"}"#), GateOutcome::Allow { .. }));
    }

    #[test]
    fn continue_false_stops_a_prompt_and_a_post_tool_call() {
        let prompt: PromptHookJson =
            serde_json::from_str(r#"{"continue":false,"stopReason":"not today"}"#).unwrap();
        assert_eq!(prompt_json_to_block(&prompt, "h", None), Ok(Some("not today".to_string())));
        let prompt: PromptHookJson = serde_json::from_str(r#"{"continue":true}"#).unwrap();
        assert_eq!(prompt_json_to_block(&prompt, "h", None), Ok(None));

        let post: PostToolUseHookJson =
            serde_json::from_str(r#"{"continue":false,"stopReason":"enough"}"#).unwrap();
        let parsed = post_tool_use_json_to_outcome(post, "h", HookHealth::Healthy);
        assert_eq!(parsed.outcome.force_stop.and_then(|stop| stop.reason).as_deref(), Some("enough"));
        let post: PostToolUseHookJson = serde_json::from_str(r#"{"continue":true}"#).unwrap();
        assert!(post_tool_use_json_to_outcome(post, "h", HookHealth::Healthy).outcome.force_stop.is_none());
    }

    #[test]
    fn blank_permission_decision_falls_back_to_legacy_decision() {
        for (json, expected) in [
            (
                r#"{"decision":"deny","hookSpecificOutput":{"permissionDecision":"  "}}"#,
                DecisionToken::Deny,
            ),
            (
                r#"{"hookSpecificOutput":{"permissionDecision":"  "}}"#,
                DecisionToken::Allow,
            ),
            (
                r#"{"hookSpecificOutput":{"permissionDecision":""}}"#,
                DecisionToken::Allow,
            ),
        ] {
            let document: GateHookJson = serde_json::from_str(json).expect("valid gate JSON");
            assert_eq!(document.resolve_decision().token, expected, "for {json}");
        }
    }

    #[test]
    fn ask_with_non_object_updated_input_keeps_asking() {
        let json = r#"{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"confirm","updatedInput":"nope"}}"#;

        let document: GateHookJson = serde_json::from_str(json).expect("valid gate JSON");
        let mut ignored = Vec::new();
        let rewrite = resolve_rewrite(document, "h", HookHealth::Healthy, &mut ignored);
        assert!(
            rewrite.is_none(),
            "a non-object updatedInput must drop the rewrite"
        );
        assert!(
            ignored.iter().any(|part| part.contains("updatedInput")),
            "the dropped rewrite must be named in ignored_parts, got {ignored:?}"
        );

        let document: GateHookJson = serde_json::from_str(json).expect("valid gate JSON");
        let outcome = gate_outcome(document, "h", None, HookHealth::Healthy);
        assert!(
            matches!(
                outcome,
                GateOutcome::Ask {
                    updated_input: None,
                    ..
                }
            ),
            "ask + non-object updatedInput must stay an Ask with no rewrite, not fail open"
        );
    }

    #[test]
    fn deny_with_array_additional_context_still_denies() {
        let json = r#"{"decision":"deny","reason":"blocked","hookSpecificOutput":{"permissionDecision":"deny","additionalContext":["a","b"]}}"#;
        let document: GateHookJson =
            serde_json::from_str(json).expect("a non-string additionalContext must still parse");
        assert!(
            document.is_gate_document(),
            "the document must still be recognized as a gate"
        );
        let outcome = gate_outcome(document, "h", None, HookHealth::Healthy);
        assert!(
            matches!(outcome, GateOutcome::Deny(ref reason) if reason == "blocked"),
            "a deny must land despite an array additionalContext"
        );
    }

    #[test]
    fn bad_additional_context_is_dropped_and_named_and_the_decision_survives() {
        for (json, expected) in [
            (
                r#"{"hookSpecificOutput":{"permissionDecision":"ask","additionalContext":[1,2]}}"#,
                "ask",
            ),
            (
                r#"{"hookSpecificOutput":{"permissionDecision":"defer","additionalContext":1}}"#,
                "defer",
            ),
            (
                r#"{"hookSpecificOutput":{"permissionDecision":"block","additionalContext":{}}}"#,
                "deny",
            ),
        ] {
            let document: GateHookJson = serde_json::from_str(json).expect("valid gate JSON");
            let decision = document.resolve_decision().token;
            assert!(
                document
                    .ignored_parts(&decision)
                    .iter()
                    .any(|part| part == "hookSpecificOutput.additionalContext"),
                "a bad additionalContext must be named in ignored_parts, for {json}"
            );

            let document: GateHookJson = serde_json::from_str(json).expect("valid gate JSON");
            let got = match gate_outcome(document, "h", None, HookHealth::Healthy) {
                GateOutcome::Ask {
                    additional_context, ..
                } => {
                    assert!(
                        additional_context.is_none(),
                        "the bad context must be dropped, for {json}"
                    );
                    "ask"
                }
                GateOutcome::Defer => "defer",
                GateOutcome::Deny(_) => "deny",
                GateOutcome::Stop(_) => "stop",
                GateOutcome::Allow { .. } => "allow",
                GateOutcome::Failed(_) => "failed",
            };
            assert_eq!(got, expected, "the token must survive, for {json}");
        }
    }

    #[test]
    fn top_level_additional_context_is_a_recognized_gate_document_and_is_named() {
        let document: GateHookJson =
            serde_json::from_str(r#"{"additionalContext":"note"}"#).expect("valid JSON");
        assert!(
            document.is_gate_document(),
            "a top-level additionalContext must mark a gate document"
        );
        let decision = document.resolve_decision().token;
        assert_eq!(document.ignored_parts(&decision), vec!["additionalContext"]);
    }

    /// A command hook\u{27}s output that opens like a JSON object after a byte-order mark and/or Unicode whitespace is
    /// judged as JSON (and is a flaw under the flag), not dismissed as plain text; plain text still is not.
    #[test]
    fn gate_output_flaw_command_bom_and_unicode_whitespace_look_like_json() {
        for mode in [GateKind::Tool, GateKind::Prompt] {
            for doc in [
                "\u{FEFF}{\"decision\":\"deny\"}",
                "\n\u{FEFF}{\"decision\":\"deny\"}\n",
                " \u{FEFF} {\"decision\":\"deny\"}",
                "\u{a0}{\"decision\":\"deny\"}",
                "\u{0c}{\"decision\":\"deny\"}",
                "{\"decision\":\"deny\"}\u{2028}",
            ] {
                assert_eq!(
                    gate_output_flaw(mode, doc.as_bytes(), false, false).as_deref(),
                    Some(FLAW_UNPARSED),
                    "{mode:?} {doc:?}"
                );
            }
            for text in ["\u{FEFF}hello", "plain text", "\u{FEFF}", "  \u{a0} "] {
                assert_eq!(gate_output_flaw(mode, text.as_bytes(), false, false), None, "{mode:?} {text:?}");
            }
        }
    }

    /// Any number of byte-order marks mixed with Unicode whitespace before the opening brace still reads as JSON.
    #[test]
    fn gate_output_flaw_command_multiple_boms_look_like_json() {
        for mode in [GateKind::Tool, GateKind::Prompt] {
            for doc in [
                "\u{FEFF}\u{FEFF}{\"decision\":\"deny\"}",
                "\u{FEFF} \u{FEFF}{\"decision\":\"deny\"}",
                "\u{FEFF}\u{a0}\u{FEFF}\n{\"decision\":\"deny\"}",
                "\u{FEFF}\u{FEFF}\u{FEFF}{\"decision\":\"deny\"}",
            ] {
                assert_eq!(
                    gate_output_flaw(mode, doc.as_bytes(), false, false).as_deref(),
                    Some(FLAW_UNPARSED),
                    "{mode:?} {doc:?}"
                );
            }
            for text in ["\u{FEFF}\u{FEFF}hello", "\u{FEFF}\u{FEFF}"] {
                assert_eq!(gate_output_flaw(mode, text.as_bytes(), false, false), None, "{mode:?} {text:?}");
            }
        }
    }

    /// Every invisible prefix character (format characters, control characters) before the brace still reads as JSON,
    /// on both gates; plain text that starts with them and has no `{` stays plain.
    #[test]
    fn gate_output_flaw_command_invisible_prefix_chars_look_like_json() {
        let invisible = ["\u{200B}", "\u{2060}", "\u{180E}", "\u{00AD}", "\u{202E}", "\u{0}", "\u{E0020}", "\u{1D173}"];
        for mode in [GateKind::Tool, GateKind::Prompt] {
            for ch in invisible {
                for doc in [
                    format!("{ch}{{\"decision\":\"deny\"}}"),
                    format!("\u{FEFF}{ch}\u{FEFF}{{\"decision\":\"deny\"}}"),
                    format!("{ch}{ch} \u{FEFF}{ch}{{\"decision\":\"deny\"}}"),
                ] {
                    assert_eq!(
                        gate_output_flaw(mode, doc.as_bytes(), false, false).as_deref(),
                        Some(FLAW_UNPARSED),
                        "{mode:?} {doc:?}"
                    );
                }
                for text in [format!("{ch}hello"), format!("\u{FEFF}{ch}"), format!("{ch}{ch}")] {
                    assert_eq!(gate_output_flaw(mode, text.as_bytes(), false, false), None, "{mode:?} {text:?}");
                }
            }
        }
    }

    /// An unknown key that literally starts with the old internal marker text is still worded as unknown.
    #[test]
    fn gate_output_flaw_unknown_key_named_like_the_old_marker_is_worded_unknown() {
        let doc = "{\"\\u0000wrong-type:x\":1}";
        for mode in [GateKind::Tool, GateKind::Prompt] {
            let flaw = gate_output_flaw(mode, doc.as_bytes(), false, false).unwrap();
            assert!(flaw.starts_with(FLAW_UNKNOWN_KEY), "{mode:?} {flaw}");
            assert!(!flaw.starts_with(FLAW_WRONG_TYPE), "{mode:?} {flaw}");
        }
    }

    fn spec_with_flag(fail_closed: bool) -> HookSpec {
        HookSpec {
            name: "typed".into(),
            event: crate::event::HookEventName::PreToolUse,
            handler_type: crate::config::HandlerType::Command,
            configured_matcher: None,
            matcher: None,
            enabled: true,
            command: None,
            command_raw: None,
            args: None,
            shell: None,
            url: None,
            url_raw: None,
            timeout_ms: 1000,
            fail_closed,
            source_dir: std::env::temp_dir(),
            extra_env: Default::default(),
            layer: crate::config::HookProvenance::File,
        }
    }

    /// A recognised extra key with the wrong JSON type is a flaw on the tool gate under the flag (it used to resolve to an
    /// allow), the same document is unchanged without the flag, and correctly typed keys still behave as before.
    #[test]
    fn gate_output_flaw_wrong_typed_recognised_keys_fail_closed_on_the_tool_gate() {
        let allow = || HookRunnerResult::Allow { updated_input: None, additional_context: None };
        for doc in [
            r#"{"continue":"false"}"#,
            r#"{"continue":0}"#,
            r#"{"systemMessage":5}"#,
            r#"{"suppressOutput":"yes"}"#,
            r#"{"stopReason":false}"#,
        ] {
            let flaw = gate_output_flaw(GateKind::Tool, doc.as_bytes(), false, false);
            assert!(flaw.as_deref().is_some_and(|f| f.starts_with(FLAW_WRONG_TYPE)), "{doc}: {flaw:?}");
            let on = enforce_fail_closed(&spec_with_flag(true), GateKind::Tool, allow(), flaw.clone(), None);
            assert!(matches!(on, HookRunnerResult::Failed(_)), "flag on denies {doc}");
            let off = enforce_fail_closed(&spec_with_flag(false), GateKind::Tool, allow(), flaw, None);
            assert!(matches!(off, HookRunnerResult::Allow { .. }), "flag off unchanged {doc}");
            assert!(matches!(gate(doc), GateOutcome::Allow { .. }), "normal handling unchanged {doc}");
        }
        for doc in [r#"{"systemMessage":"x"}"#, r#"{"continue":true}"#, r#"{"suppressOutput":true,"stopReason":"r"}"#] {
            assert_eq!(gate_output_flaw(GateKind::Tool, doc.as_bytes(), false, false), None, "{doc}");
            assert!(matches!(gate(doc), GateOutcome::Allow { .. }), "{doc}");
        }
        let stop = r#"{"continue":false}"#;
        assert_eq!(gate_output_flaw(GateKind::Tool, stop.as_bytes(), false, false), None);
        assert!(matches!(gate(stop), GateOutcome::Stop(_)));
        // the prompt gate already rejected typed `continue`; the untyped keys now match
        for doc in [r#"{"continue":"false"}"#, r#"{"systemMessage":5}"#] {
            assert!(gate_output_flaw(GateKind::Prompt, doc.as_bytes(), false, false).is_some(), "{doc}");
        }
    }

    /// `failClosed` judges the raw bytes: invalid UTF-8 and a key repeated at any depth are flaws on both gates, in both
    /// the lenient (command) and strict (HTTP) modes, while valid non-ASCII UTF-8 and a clean document are not.
    #[test]
    fn gate_output_flaw_judges_raw_bytes_strictly() {
        let bad_utf8: &[u8] = b"{\"decision\":\"allow\",\"reason\":\"\xff\"}";
        let duplicates: &[(&str, &str)] = &[
            (r#"{"hookSpecificOutput":{"permissionDecison":"deny"},"hookSpecificOutput":{}}"#, "hookSpecificOutput"),
            (r#"{"systemMessage":"a","systemMessage":"b"}"#, "systemMessage"),
            (r#"{"hookSpecificOutput":{"additionalContext":"a","additionalContext":"b"}}"#, "additionalContext"),
            (
                r#"{"hookSpecificOutput":{"updatedInput":{"command":"rm -rf /","command":"ls"}},"decision":"allow"}"#,
                "command",
            ),
            (r#"{"decision":"allow","x":[{"a":1,"a":2}]}"#, "a"),
        ];
        for mode in [GateKind::Tool, GateKind::Prompt] {
            for strict in [true, false] {
                let flaw = gate_output_flaw(mode, bad_utf8, strict, false);
                assert_eq!(flaw.as_deref(), Some(FLAW_NOT_UTF8), "{mode:?} strict={strict}");
                for &(doc, key) in duplicates {
                    let flaw = gate_output_flaw(mode, doc.as_bytes(), strict, false).unwrap_or_default();
                    assert_eq!(flaw, format!("{FLAW_DUPLICATE_KEY} ('{key}')"), "{mode:?} strict={strict} {doc}");
                }
                for ok in [r#"{"decision":"block","reason":"café — 日本語 ✓"}"#, r#"{"systemMessage":"naïve"}"#, "{}"] {
                    let flaw = gate_output_flaw(mode, ok.as_bytes(), strict, false);
                    assert_eq!(flaw, None, "{mode:?} strict={strict} {ok}");
                }
            }
        }
        // a lone surrogate escape is not a string JSON can carry; trailing bytes are not one value
        for doc in [r#"{"decision":"allow","reason":"\ud800"}"#, r#"{"decision":"allow"} {}"#] {
            assert_eq!(gate_output_flaw(GateKind::Tool, doc.as_bytes(), true, false).as_deref(), Some(FLAW_UNPARSED));
        }
        // the decoded key is what counts: an escaped spelling of the same key is still a duplicate
        assert_eq!(
            strict_json_value(r#"{"decision":"allow","decision":"deny"}"#),
            Err(StrictJsonError::DuplicateKey("decision".into()))
        );
        assert_eq!(strict_json_value(r#"[1,{"a":null}]"#), Ok(serde_json::json!([1, {"a": null}])));
    }

    #[test]
    fn valid_additional_context_flows_through() {
        let json =
            r#"{"hookSpecificOutput":{"permissionDecision":"allow","additionalContext":"note"}}"#;
        let document: GateHookJson = serde_json::from_str(json).expect("valid gate JSON");
        match gate_outcome(document, "h", None, HookHealth::Healthy) {
            GateOutcome::Allow {
                additional_context, ..
            } => assert_eq!(additional_context.as_deref(), Some("note")),
            _ => panic!("a valid additionalContext must flow through an allow"),
        }
    }
}
