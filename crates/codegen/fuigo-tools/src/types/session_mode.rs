//! Canonical session-mode enum shared between the agent and pager.
//!
//! ACP carries the mode as an opaque [`acp::SessionModeId`] (`Arc<str>`).
//! This enum is the typed counterpart both crates parse into / serialize
//! out of, so plan-mode state is driven by the closed set of variants
//! instead of by ad-hoc string matching at each boundary.

/// Wire id of the browser-use mode. Not a [`SessionMode`] variant: it adds browsing instructions to the session's own
/// prompt while it is on and runs in agent prompt mode.
pub const BROWSER_USE_MODE_ID: &str = "browser_use";

/// Every mode id `session/set_mode` accepts. Anything else is refused at the protocol edge.
pub const SUPPORTED_MODE_IDS: [&str; 4] = ["default", "plan", "ask", BROWSER_USE_MODE_ID];

/// Exact, case-sensitive membership in [`SUPPORTED_MODE_IDS`].
/// Unlike [`SessionMode::from_id`] there is no fallback: `PLAN`, `browser-use`, `explore` and `""` are not mode ids.
pub fn is_supported_mode_id(id: &str) -> bool {
    SUPPORTED_MODE_IDS.contains(&id)
}

/// Wire representation is the snake-cased variant name (`default`, `plan`,
/// `ask`) via [`strum`]. Unknown ids parse back to [`SessionMode::Default`]
/// so newer modes added on the agent side don't brick older pagers.
#[derive(Debug, Clone, PartialEq, Eq, strum::EnumString, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum SessionMode {
    Default,
    Plan,
    Ask,
}

impl SessionMode {
    /// Parse from the wire id. Unknown ids fall back to [`SessionMode::Default`].
    pub fn from_id(id: &str) -> Self {
        id.parse().unwrap_or(Self::Default)
    }

    /// The canonical wire id for this mode (snake_case).
    pub fn as_id(&self) -> &'static str {
        self.into()
    }

    pub fn is_plan(&self) -> bool {
        matches!(self, Self::Plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_known_ids() {
        for &id in &["default", "plan", "ask"] {
            let mode = SessionMode::from_id(id);
            assert_eq!(mode.as_id(), id, "round-trip failed for {id}");
        }
    }

    #[test]
    fn unknown_id_falls_back_to_default() {
        assert_eq!(SessionMode::from_id("browser_use"), SessionMode::Default);
        assert_eq!(SessionMode::from_id(""), SessionMode::Default);
        assert_eq!(SessionMode::from_id("PLAN"), SessionMode::Default); // case-sensitive
    }

    #[test]
    fn supported_mode_ids_are_exact() {
        for id in ["default", "plan", "ask", "browser_use"] {
            assert!(is_supported_mode_id(id), "{id} must be supported");
        }
        for id in [
            "PLAN",
            "Default",
            "browser-use",
            "explore",
            "codex",
            "evil",
            "",
            " plan",
            "../.fuigo/agents/evil",
        ] {
            assert!(!is_supported_mode_id(id), "{id:?} must be rejected");
        }
        assert_eq!(BROWSER_USE_MODE_ID, "browser_use");
        assert_eq!(SUPPORTED_MODE_IDS.len(), 4);
    }

    #[test]
    fn is_plan_only_for_plan_variant() {
        assert!(SessionMode::Plan.is_plan());
        assert!(!SessionMode::Default.is_plan());
        assert!(!SessionMode::Ask.is_plan());
    }
}
