//! Resolves the per-model opt-in for OpenAI Responses programmatic tool calling (PTC).
//!
//! Wire contract and design: `docs/ptc-contract.md`.
//! The resolved flag travels on `fuigo_sampler::SamplerConfig::programmatic_tool_calling` to the session actor,
//! which adds `HostedTool::ProgrammaticToolCalling` to agent turns.

use crate::agent::config::{ApiBackend, ModelInfo};

/// Environment override: `1|true|on|yes` forces PTC on for every model, `0|false|off|no` forces it off.
/// Any other value (or unset) defers to the model entry.
pub const ENV_FLAG: &str = "FUIGO_PROGRAMMATIC_TOOL_CALLING";

fn parse_flag(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Some(true),
        "0" | "false" | "off" | "no" => Some(false),
        _ => None,
    }
}

/// The environment override, if any.
pub fn env_override() -> Option<bool> {
    std::env::var(ENV_FLAG).ok().as_deref().and_then(parse_flag)
}

/// Whether PTC is on for `info`: the entry's `programmatic_tool_calling` (or the env override), gated on the Responses
/// backend and an OpenAI-family model. Other backends and providers never see the tool type.
pub fn enabled_for(info: &ModelInfo) -> bool {
    enabled_for_with(info, env_override())
}

/// [`enabled_for`] with an explicit override in place of the environment (tests).
pub fn enabled_for_with(info: &ModelInfo, env_override: Option<bool>) -> bool {
    let requested = env_override.unwrap_or(info.programmatic_tool_calling);
    requested && info.api_backend == ApiBackend::Responses && info.is_openai_model()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(slug: &str, backend: ApiBackend, flag: bool) -> ModelInfo {
        let mut info = ModelInfo::fallback(slug);
        info.api_backend = backend;
        info.programmatic_tool_calling = flag;
        info
    }

    #[test]
    fn off_by_default() {
        assert!(!enabled_for_with(
            &model("gpt-5.6", ApiBackend::Responses, false),
            None
        ));
    }

    #[test]
    fn on_for_openai_responses_entry() {
        assert!(enabled_for_with(
            &model("gpt-5.6-sol", ApiBackend::Responses, true),
            None
        ));
        assert!(enabled_for_with(
            &model("openai/gpt-5.6", ApiBackend::Responses, true),
            None
        ));
    }

    #[test]
    fn gated_on_backend_and_family() {
        assert!(!enabled_for_with(
            &model("gpt-5.6", ApiBackend::ChatCompletions, true),
            None
        ));
        assert!(!enabled_for_with(
            &model("gpt-5.6", ApiBackend::Messages, true),
            None
        ));
        assert!(!enabled_for_with(
            &model("grok-4", ApiBackend::Responses, true),
            None
        ));
        let mut family = model("some-router-slug", ApiBackend::Responses, true);
        family.model_family = Some("openai".to_owned());
        assert!(enabled_for_with(&family, None));
    }

    #[test]
    fn env_override_wins_both_ways() {
        assert!(enabled_for_with(
            &model("gpt-5.6", ApiBackend::Responses, false),
            Some(true)
        ));
        assert!(!enabled_for_with(
            &model("gpt-5.6", ApiBackend::Responses, true),
            Some(false)
        ));
        // The override never lifts the backend/family gate
        assert!(!enabled_for_with(
            &model("grok-4", ApiBackend::Responses, false),
            Some(true)
        ));
    }

    #[test]
    fn parses_flag_spellings() {
        for on in ["1", "true", "ON", "yes"] {
            assert_eq!(parse_flag(on), Some(true), "{on}");
        }
        for off in ["0", "false", "Off", "no"] {
            assert_eq!(parse_flag(off), Some(false), "{off}");
        }
        assert_eq!(parse_flag("maybe"), None);
    }
}
