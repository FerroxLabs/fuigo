//! Wire mirror of the `workspace.hook_registry` response.
//! It is kept byte-identical to the upstream serde shape so this lean crate avoids the heavy `fuigo_hooks` dep.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{RpcActivityClass, WorkspaceRpc};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookRegistryReq {}

impl WorkspaceRpc for HookRegistryReq {
    const METHOD: &'static str = "workspace.hook_registry";
    const ACTIVITY: RpcActivityClass = RpcActivityClass::Read;
    type Response = HookRegistryWire;
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookRegistryWire {
    pub hooks: HashMap<HookEventNameWire, Vec<HookSpecWire>>,
}

/// Shown once when a workspace server sends gate hooks without the `fail_closed` field: it predates `failClosed`, so a
/// hook configured fail-closed would run fail-open.
pub const FAIL_CLOSED_NOT_ENFORCED_WARNING: &str =
    "this workspace server predates failClosed hooks: a hook set to \"failClosed\": true is not enforced by it and fails open";

impl HookRegistryWire {
    /// Whether any `pre_tool_use` / `user_prompt_submit` hook (the only events `failClosed` applies to) arrived without the
    /// `fail_closed` field, i.e. from a server that predates it.
    pub fn gate_hooks_without_fail_closed(&self) -> bool {
        self.hooks.iter().any(|(event, specs)| {
            matches!(event, HookEventNameWire::PreToolUse | HookEventNameWire::UserPromptSubmit)
                && specs.iter().any(|spec| spec.fail_closed.is_none())
        })
    }
}

/// The compiled `matcher` is omitted; the `hook_spec_wire_covers_all_upstream_fields` test guards against drift.
#[derive(Clone, Serialize, Deserialize)]
pub struct HookSpecWire {
    pub name: String,
    pub event: HookEventNameWire,
    pub handler_type: String,
    pub configured_matcher: Option<String>,
    pub enabled: bool,
    pub command: Option<PathBuf>,
    pub command_raw: Option<String>,
    /// The `command` + `args` form (run without a shell). Absent on the wire for the shell form and from older servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    /// The shell a shell-form command runs in (`"bash"`). Absent on the wire for the default `sh` and from older servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    pub url: Option<String>,
    pub url_raw: Option<String>,
    pub timeout_ms: u64,
    /// `"failClosed": true` hook: a failure blocks instead of failing open. Serialized as before when set; `None` means the
    /// server predates this field, so whether the hook was fail-closed is unknown (see
    /// [`HookRegistryWire::gate_hooks_without_fail_closed`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_closed: Option<bool>,
    pub source_dir: PathBuf,
    pub extra_env: HashMap<String, String>,
    /// `default` decodes a server that predates this field as `file`.
    #[serde(default = "default_layer")]
    pub layer: String,
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them. Environment values print by name only: users put API keys there. This leaf crate has no URL redactor, so the hook URL prints as present / absent.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for HookSpecWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            name,
            event,
            handler_type,
            configured_matcher,
            enabled,
            command,
            command_raw,
            args,
            shell,
            url,
            url_raw,
            timeout_ms,
            fail_closed,
            source_dir,
            extra_env,
            layer,
        } = self;
        f.debug_struct("HookSpecWire")
            .field("name", name)
            .field("event", event)
            .field("handler_type", handler_type)
            .field("configured_matcher", configured_matcher)
            .field("enabled", enabled)
            .field("command", &command.as_ref().map(|_| "<redacted>"))
            .field("command_raw", &command_raw.as_ref().map(|_| "<redacted>"))
            .field("args", &args.as_ref().map(Vec::len))
            .field("shell", shell)
            .field("url", &url.as_ref().map(|_| "<redacted>"))
            .field("url_raw", &url_raw.as_ref().map(|_| "<redacted>"))
            .field("timeout_ms", timeout_ms)
            .field("fail_closed", fail_closed)
            .field("source_dir", source_dir)
            .field("extra_env", &extra_env.keys().map(|k| (k, "<redacted>")).collect::<Vec<_>>())
            .field("layer", layer)
            .finish()
    }
}

fn default_layer() -> String {
    "file".to_string()
}

/// Snake_case JSON map key.
/// Hand-written serde keeps an unknown event lossless in [`Unknown`](Self::Unknown) so decode never fails under deploy skew.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HookEventNameWire {
    SessionStart,
    SessionEnd,
    Stop,
    StopFailure,
    StopCancelled,
    PreToolUse,
    PostToolUse,
    PostToolUseFailure,
    PermissionDenied,
    UserPromptSubmit,
    Notification,
    SubagentStart,
    SubagentStop,
    SubagentEnd,
    PreCompact,
    PostCompact,
    Unknown(String),
}

impl HookEventNameWire {
    pub fn as_str(&self) -> &str {
        match self {
            Self::SessionStart => "session_start",
            Self::SessionEnd => "session_end",
            Self::Stop => "stop",
            Self::StopFailure => "stop_failure",
            Self::StopCancelled => "stop_cancelled",
            Self::PreToolUse => "pre_tool_use",
            Self::PostToolUse => "post_tool_use",
            Self::PostToolUseFailure => "post_tool_use_failure",
            Self::PermissionDenied => "permission_denied",
            Self::UserPromptSubmit => "user_prompt_submit",
            Self::Notification => "notification",
            Self::SubagentStart => "subagent_start",
            Self::SubagentStop => "subagent_stop",
            Self::SubagentEnd => "subagent_end",
            Self::PreCompact => "pre_compact",
            Self::PostCompact => "post_compact",
            Self::Unknown(s) => s,
        }
    }
}

impl Serialize for HookEventNameWire {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HookEventNameWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "session_start" => Self::SessionStart,
            "session_end" => Self::SessionEnd,
            "stop" => Self::Stop,
            "stop_failure" => Self::StopFailure,
            "stop_cancelled" => Self::StopCancelled,
            "pre_tool_use" => Self::PreToolUse,
            "post_tool_use" => Self::PostToolUse,
            "post_tool_use_failure" => Self::PostToolUseFailure,
            "permission_denied" => Self::PermissionDenied,
            "user_prompt_submit" => Self::UserPromptSubmit,
            "notification" => Self::Notification,
            "subagent_start" => Self::SubagentStart,
            "subagent_stop" => Self::SubagentStop,
            "subagent_end" => Self::SubagentEnd,
            "pre_compact" => Self::PreCompact,
            "post_compact" => Self::PostCompact,
            _ => Self::Unknown(s),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_constant() {
        assert_eq!(HookRegistryReq::METHOD, "workspace.hook_registry");
    }

    /// Mirrors `event_name_deser_all_variants` in fuigo-hooks; the two lists move together.
    #[test]
    fn hook_event_name_wire_snake_case_round_trip() {
        for (variant, wire) in [
            (HookEventNameWire::SessionStart, "session_start"),
            (HookEventNameWire::SessionEnd, "session_end"),
            (HookEventNameWire::Stop, "stop"),
            (HookEventNameWire::StopFailure, "stop_failure"),
            (HookEventNameWire::StopCancelled, "stop_cancelled"),
            (HookEventNameWire::PreToolUse, "pre_tool_use"),
            (HookEventNameWire::PostToolUse, "post_tool_use"),
            (
                HookEventNameWire::PostToolUseFailure,
                "post_tool_use_failure",
            ),
            (HookEventNameWire::PermissionDenied, "permission_denied"),
            (HookEventNameWire::UserPromptSubmit, "user_prompt_submit"),
            (HookEventNameWire::Notification, "notification"),
            (HookEventNameWire::SubagentStart, "subagent_start"),
            (HookEventNameWire::SubagentStop, "subagent_stop"),
            (HookEventNameWire::SubagentEnd, "subagent_end"),
            (HookEventNameWire::PreCompact, "pre_compact"),
            (HookEventNameWire::PostCompact, "post_compact"),
        ] {
            assert_eq!(
                serde_json::to_value(&variant).unwrap(),
                serde_json::json!(wire)
            );
            let parsed: HookEventNameWire =
                serde_json::from_value(serde_json::json!(wire)).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn hook_event_name_wire_unknown_round_trips_losslessly() {
        // A newer server's event must decode (not error) and preserve its raw value so it stays a distinct map key
        let v: HookEventNameWire =
            serde_json::from_value(serde_json::json!("future_event")).unwrap();
        assert_eq!(v, HookEventNameWire::Unknown("future_event".to_string()));
        assert_eq!(
            serde_json::to_value(&v).unwrap(),
            serde_json::json!("future_event")
        );
    }

    #[test]
    fn hook_registry_wire_round_trips_server_json() {
        // A representative server-side `HookRegistry` serialization.
        let json = serde_json::json!({
            "hooks": {
                "pre_tool_use": [{
                    "name": "global/safety",
                    "event": "pre_tool_use",
                    "handler_type": "command",
                    "configured_matcher": "Bash",
                    "enabled": true,
                    "command": "/bin/check.sh",
                    "command_raw": "${X}/check.sh",
                    "url": null,
                    "url_raw": null,
                    "timeout_ms": 5000,
                    "source_dir": "/home/u/.fuigo/hooks",
                    "extra_env": { "FOO": "bar" },
                    "layer": "file"
                }]
            }
        });
        let wire: HookRegistryWire = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&wire).unwrap(), json);
    }

    /// A server that sends `fail_closed` round-trips it unchanged; one that omits it (it predates the field) decodes as
    /// unknown, stays omitted on re-serialization, and is flagged for the not-enforced warning on gate events only.
    #[test]
    fn fail_closed_present_round_trips_and_omitted_is_flagged() {
        let spec = |fail_closed: Option<bool>| {
            let mut spec = serde_json::json!({
                "name": "h", "event": "pre_tool_use", "handler_type": "command", "configured_matcher": null,
                "enabled": true, "command": "/bin/h.sh", "command_raw": "/bin/h.sh", "url": null, "url_raw": null,
                "timeout_ms": 5000, "source_dir": "/tmp", "extra_env": {}, "layer": "file"
            });
            if let Some(flag) = fail_closed {
                spec["fail_closed"] = serde_json::json!(flag);
            }
            spec
        };
        for flag in [true, false] {
            let json = serde_json::json!({ "hooks": { "pre_tool_use": [spec(Some(flag))] } });
            let wire: HookRegistryWire = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(wire.hooks[&HookEventNameWire::PreToolUse][0].fail_closed, Some(flag));
            assert_eq!(serde_json::to_value(&wire).unwrap(), json);
            assert!(!wire.gate_hooks_without_fail_closed());
        }
        for event in ["pre_tool_use", "user_prompt_submit"] {
            let json = serde_json::json!({ "hooks": { event: [spec(None)] } });
            let wire: HookRegistryWire = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(wire.hooks.values().next().unwrap()[0].fail_closed, None);
            assert_eq!(serde_json::to_value(&wire).unwrap(), json);
            assert!(wire.gate_hooks_without_fail_closed(), "{event}");
        }
        let json = serde_json::json!({ "hooks": { "session_start": [spec(None)] } });
        let wire: HookRegistryWire = serde_json::from_value(json).unwrap();
        assert!(!wire.gate_hooks_without_fail_closed(), "failClosed does not apply to other events");
        assert!(!HookRegistryWire::default().gate_hooks_without_fail_closed());
    }
}
