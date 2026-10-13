use agent_client_protocol as acp;
use fuigo_shell::sampling::types::{
    ModelNotice, ReasoningEffort, ReasoningEffortOption, parse_context_window_meta,
    parse_context_windows_meta, parse_model_notice_meta, parse_reasoning_effort_meta, parse_reasoning_efforts_meta, supports_reasoning_effort_meta,
};
use indexmap::IndexMap;

use crate::slash::commands::effort_levels::legacy_effort_options;

/// Why an effort token could not be applied to a model.
/// Shared by `/effort`, the CLI deferred switch, and headless so they classify the same input identically and differ only in how they report the error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EffortTokenError {
    /// The target model does not advertise `supportsReasoningEffort`.
    Unsupported,
    /// The token is neither a menu id nor a canonical value offered by this model's menu.
    /// `offered` lists only the option ids this model's menu accepts, so `none`/`minimal` are not advertised when the model does not offer them.
    UnknownToken { token: String, offered: Vec<String> },
    /// No active model to resolve the effort against.
    NoActiveModel,
}

impl EffortTokenError {
    pub(crate) fn message(&self) -> String {
        match self {
            Self::Unsupported => "current model does not support reasoning effort".to_string(),
            Self::UnknownToken { token, offered } => {
                if offered.is_empty() {
                    format!(
                        "unknown effort level '{token}'; this model has no selectable effort levels"
                    )
                } else {
                    format!(
                        "unknown effort level '{token}'; use one of: {}",
                        offered.join(", ")
                    )
                }
            }
            Self::NoActiveModel => "no active model to apply effort to".to_string(),
        }
    }
}

/// Per-agent model state.
#[derive(Debug, Clone, Default)]
pub struct ModelState {
    pub available: IndexMap<acp::ModelId, acp::ModelInfo>,
    pub current: Option<acp::ModelId>,
    pub reasoning_effort: Option<ReasoningEffort>,
    /// External override for the context window size (tokens).
    /// When set, `get_context_window()` returns this instead of reading from the current model's metadata.
    /// Used for subagent views where SubagentProgress reports the actual window size.
    context_window_override: Option<u64>,
    /// The window the session selected with `/context-window`; `None` means the model default.
    pub(crate) context_window_selection: Option<u64>,
    /// Set when a `ModelChanged` arrives while a local switch is in flight, so its completion keeps the broadcast selection.
    pub(crate) model_changed_during_switch: bool,
}

impl ModelState {
    pub fn is_empty(&self) -> bool {
        self.available.is_empty()
    }

    /// Display name for the current model.
    pub fn current_model_name(&self) -> Option<String> {
        let current = self.current.as_ref()?;
        if let Some(model_info) = self.available.get(current) {
            Some(model_info.name.clone())
        } else {
            Some(current.0.to_string())
        }
    }

    /// Machine-readable model ID string for the current model (e.g. "grok-4.5").
    pub fn current_model_id_str(&self) -> Option<&str> {
        Some(self.current.as_ref()?.0.as_ref())
    }

    /// Whether the current model accepts image input, read from the model's `meta` (the ACP extension point, same source as `totalContextTokens`).
    /// Honors an explicit `acceptsImages` bool, else an `inputModalities` array containing `"image"`.
    /// DEFAULTS TO `true` when neither key is present: all current Fuigo models accept images, so nothing is suppressed today.
    /// Once the ACP server populates the key, non-vision models get suppressed.
    pub fn current_model_accepts_images(&self) -> bool {
        let Some(meta) = self
            .current
            .as_ref()
            .and_then(|id| self.available.get(id))
            .and_then(|info| info.meta.as_ref())
        else {
            return true;
        };
        if let Some(accepts) = meta.get("acceptsImages").and_then(|v| v.as_bool()) {
            return accepts;
        }
        if let Some(modalities) = meta.get("inputModalities").and_then(|v| v.as_array()) {
            return modalities
                .iter()
                .any(|m| m.as_str().is_some_and(|s| s.eq_ignore_ascii_case("image")));
        }
        true
    }

    /// Returns the override, else the selection if the current model supports it, else the model default.
    pub fn get_context_window(&self) -> Option<u64> {
        if let Some(window) = self.context_window_override {
            return Some(window);
        }
        let id = self.current.as_ref()?;
        let default = self.model_default_window(id);
        match self.context_window_selection {
            Some(selection)
                if default == Some(selection)
                    || self.context_window_options_for(id).contains(&selection) =>
            {
                Some(selection)
            }
            _ => default,
        }
    }

    /// The window a switch to `id` uses without a pick: the selection if `id` lists it, else its default.
    pub(crate) fn window_after_switch_to(&self, id: &acp::ModelId) -> Option<u64> {
        self.context_window_selection
            .filter(|selection| self.context_window_options_for(id).contains(selection))
            .or_else(|| self.model_default_window(id))
    }

    /// The model's catalog default (`totalContextTokens`).
    pub(crate) fn model_default_window(&self, id: &acp::ModelId) -> Option<u64> {
        self.available
            .get(id)
            .and_then(|info| info.meta.as_ref())
            .and_then(|meta| meta.get("totalContextTokens"))
            .and_then(|value| value.as_u64())
    }

    /// The notice the current model carries in `meta.notice`, if any.
    /// It arrives over ACP from the agent, so it is scrubbed again here as untrusted text before it is held.
    pub fn current_notice(&self) -> Option<ModelNotice> {
        let info = self.available.get(self.current.as_ref()?)?;
        crate::views::model_notice_banner::sanitize(parse_model_notice_meta(info.meta.as_ref())?)
    }

    /// The selectable windows for the current model, empty when the catalog lists none.
    pub fn context_window_options(&self) -> Vec<u64> {
        match self.current.as_ref() {
            Some(id) => self.context_window_options_for(id),
            None => Vec::new(),
        }
    }

    pub(crate) fn context_window_options_for(&self, id: &acp::ModelId) -> Vec<u64> {
        self.available
            .get(id)
            .and_then(|info| parse_context_windows_meta(info.meta.as_ref()))
            .map(|windows| windows.into_iter().map(|w| w.get()).collect())
            .unwrap_or_default()
    }

    /// Used for subagent views where SubagentProgress reports an actual window that may differ from the inherited model's metadata.
    pub fn override_context_window(&mut self, tokens: u64) {
        self.context_window_override = Some(tokens);
    }

    /// Replace the available-model list.
    /// Leaves `current` and `reasoning_effort` alone; those change only via `/model`, create, or load.
    pub fn update_catalog(&mut self, new_available: IndexMap<acp::ModelId, acp::ModelInfo>) {
        self.available = new_available;
    }

    /// Set the current model and resolve reasoning effort from catalog meta.
    pub fn set_current(
        &mut self,
        model_id: acp::ModelId,
        effort_override: Option<ReasoningEffort>,
    ) {
        self.current = Some(model_id.clone());
        self.reasoning_effort = effort_override.or_else(|| {
            self.available
                .get(&model_id)
                .and_then(|info| parse_reasoning_effort_meta(info.meta.as_ref()))
        });
    }

    /// The reasoning-effort menu for the current model. An unset or unsupported model yields no menu.
    /// A supported model uses the server list when present, else the built-in fallback.
    pub fn reasoning_effort_options(&self) -> Vec<ReasoningEffortOption> {
        match self.current.as_ref() {
            Some(id) => self.reasoning_effort_options_for(id),
            None => Vec::new(),
        }
    }

    /// Menu for a specific catalog model id (used by `/model`'s effort phase).
    /// `parse_reasoning_efforts_meta` returns `None` when the list is absent, not an array, or present but unusable.
    /// All of those fall back to the built-in menu, exactly as the shell's session picker does.
    pub(crate) fn reasoning_effort_options_for(
        &self,
        id: &acp::ModelId,
    ) -> Vec<ReasoningEffortOption> {
        let Some(info) = self.available.get(id) else {
            return Vec::new();
        };
        if !supports_reasoning_effort_meta(info.meta.as_ref()) {
            return Vec::new();
        }
        parse_reasoning_efforts_meta(info.meta.as_ref()).unwrap_or_else(legacy_effort_options)
    }

    /// Map a typed or selected effort token to its canonical value for the current model.
    /// Accepts a menu option id (case-insensitive) or a canonical level that appears as a value in that model's menu.
    /// Levels the model does not offer (e.g. `none` on grok-4.5) are rejected so the TUI fails instead of sending a blocked effort to the API.
    pub fn resolve_effort_token(&self, token: &str) -> Option<ReasoningEffort> {
        match self.current.as_ref() {
            Some(id) => self.resolve_effort_token_for(id, token),
            // No model yet: still parse so the deferred CLI switch can hold a token
            // It is re-validated with `resolve_effort_for_model` once a model is active
            None => token.parse::<ReasoningEffort>().ok(),
        }
    }

    /// [`Self::resolve_effort_token`] scoped to a specific catalog model id.
    pub(crate) fn resolve_effort_token_for(
        &self,
        id: &acp::ModelId,
        token: &str,
    ) -> Option<ReasoningEffort> {
        let options = self.reasoning_effort_options_for(id);
        if let Some(option) = options
            .iter()
            .find(|opt| opt.id.eq_ignore_ascii_case(token))
        {
            return Some(option.value);
        }
        let parsed = token.parse::<ReasoningEffort>().ok()?;
        options
            .iter()
            .find(|opt| opt.value == parsed)
            .map(|o| o.value)
    }

    /// Gate on the model's support flag first, then resolve the token (menu id or canonical level).
    /// This one decision is shared by `/effort`, the CLI deferred switch, and headless.
    /// Each caller only maps the [`EffortTokenError`] to its own error message.
    pub(crate) fn resolve_effort_for_model(
        &self,
        id: &acp::ModelId,
        token: &str,
    ) -> Result<ReasoningEffort, EffortTokenError> {
        let supports = self
            .available
            .get(id)
            .map(|info| supports_reasoning_effort_meta(info.meta.as_ref()))
            .unwrap_or(false);
        if !supports {
            return Err(EffortTokenError::Unsupported);
        }
        self.resolve_effort_token_for(id, token)
            .ok_or_else(|| EffortTokenError::UnknownToken {
                token: token.to_string(),
                // The offered list holds menu option ids only, matching `/effort` autocomplete
                // It never invents levels (none/minimal/…) the model does not offer
                offered: self
                    .reasoning_effort_options_for(id)
                    .into_iter()
                    .map(|opt| opt.id)
                    .collect(),
            })
    }

    /// Resolve a user-supplied name to a `ModelId` via case-insensitive ASCII match against the catalog.
    pub fn resolve_by_name_or_id(&self, query: &str) -> Option<acp::ModelId> {
        self.available.iter().find_map(|(id, info)| {
            if info.name.eq_ignore_ascii_case(query) || id.0.as_ref().eq_ignore_ascii_case(query) {
                Some(id.clone())
            } else {
                None
            }
        })
    }

    pub fn display_name_for(&self, id: &acp::ModelId) -> String {
        self.available
            .get(id)
            .map(|info| info.name.clone())
            .unwrap_or_else(|| id.0.to_string())
    }

    /// Cycle to the next model.
    pub fn next_model(&self) -> Option<acp::ModelId> {
        if self.available.is_empty() {
            None
        } else if let Some(ref current) = self.current {
            let idx = self.available.get_index_of(current)?;
            let idx = (idx + 1) % self.available.len();
            Some(self.available.get_index(idx)?.0.clone())
        } else {
            Some(self.available.first()?.0.clone())
        }
    }
}

impl From<Option<acp::SessionModelState>> for ModelState {
    fn from(state: Option<acp::SessionModelState>) -> Self {
        state
            .map(|state| {
                let mut models = IndexMap::new();
                for model in state.available_models {
                    models.insert(model.model_id.clone(), model);
                }
                let current_model = models
                    .contains_key(&state.current_model_id)
                    .then_some(state.current_model_id);
                let reasoning_effort = current_model
                    .as_ref()
                    .and_then(|id| models.get(id))
                    .and_then(|info| parse_reasoning_effort_meta(info.meta.as_ref()));
                let context_window_selection = current_model
                    .as_ref()
                    .and_then(|id| models.get(id))
                    .and_then(|info| parse_context_window_meta(info.meta.as_ref()))
                    .map(std::num::NonZeroU64::get);
                Self {
                    available: models,
                    current: current_model,
                    reasoning_effort,
                    context_window_override: None,
                    context_window_selection,
                    model_changed_during_switch: false,
                }
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn sample_models() -> ModelState {
        let mut state = ModelState::default();
        let id_a = acp::ModelId::new(Arc::from("model-a"));
        let id_b = acp::ModelId::new(Arc::from("model-b"));
        state.available.insert(
            id_a.clone(),
            acp::ModelInfo::new(id_a.clone(), "Model A".to_string()),
        );
        state.available.insert(
            id_b.clone(),
            acp::ModelInfo::new(id_b.clone(), "Model B".to_string()),
        );
        state.current = Some(id_a);
        state
    }

    #[test]
    fn test_current_model_name() {
        let state = sample_models();
        assert_eq!(state.current_model_name(), Some("Model A".to_string()));
    }

    #[test]
    fn test_next_model_cycles() {
        let state = sample_models();
        let next = state.next_model().unwrap();
        assert_eq!(next.0.as_ref(), "model-b");
    }

    #[test]
    fn test_next_model_wraps() {
        let mut state = sample_models();
        state.current = Some(acp::ModelId::new(Arc::from("model-b")));
        let next = state.next_model().unwrap();
        assert_eq!(next.0.as_ref(), "model-a");
    }

    #[test]
    fn test_empty_state() {
        let state = ModelState::default();
        assert!(state.is_empty());
        assert!(state.current_model_name().is_none());
        assert!(state.next_model().is_none());
    }

    fn state_with_meta(meta: Option<serde_json::Value>) -> ModelState {
        let id = acp::ModelId::new(Arc::from("m"));
        let mut state = ModelState::default();
        state.available.insert(
            id.clone(),
            acp::ModelInfo::new(id.clone(), "M".to_string())
                .meta(meta.and_then(|v| v.as_object().cloned())),
        );
        state.current = Some(id);
        state
    }

    #[test]
    fn accepts_images_defaults_true_when_meta_absent() {
        // No current model, empty meta, and a meta without the key all default to `true`; a no-op until the server populates the key
        assert!(ModelState::default().current_model_accepts_images());
        assert!(state_with_meta(None).current_model_accepts_images());
        assert!(
            state_with_meta(Some(serde_json::json!({ "totalContextTokens": 256000 })))
                .current_model_accepts_images()
        );
    }

    #[test]
    fn reasoning_effort_options_renders_server_list() {
        let state = state_with_meta(Some(serde_json::json!({
            "supportsReasoningEffort": true,
            "reasoningEfforts": [
                { "id": "balanced", "value": "medium", "label": "Balanced" },
                { "id": "deep", "value": "xhigh", "label": "Deep", "description": "Max" },
            ],
        })));
        let opts = state.reasoning_effort_options();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].label, "Balanced");
        assert_eq!(opts[0].value, ReasoningEffort::Medium);
        assert_eq!(opts[1].id, "deep");
        assert_eq!(opts[1].description.as_deref(), Some("Max"));
    }

    #[test]
    fn reasoning_effort_options_gate_first_empty_when_unsupported() {
        // A default state has no current model, so no menu
        assert!(ModelState::default().reasoning_effort_options().is_empty());
        // A model that does not support effort gets no menu, even with a list present
        let state = state_with_meta(Some(serde_json::json!({
            "reasoningEfforts": [{ "value": "high" }],
        })));
        assert!(state.reasoning_effort_options().is_empty());
    }

    #[test]
    fn reasoning_effort_options_falls_back_to_builtin_menu() {
        // Supported but no server list falls back to today's four-row built-in menu
        let state = state_with_meta(Some(serde_json::json!({
            "supportsReasoningEffort": true,
        })));
        let ids: Vec<_> = state
            .reasoning_effort_options()
            .into_iter()
            .map(|o| o.id)
            .collect();
        assert_eq!(ids, ["xhigh", "high", "medium", "low"]);
    }

    #[test]
    fn reasoning_effort_options_falls_back_when_list_present_but_unusable() {
        // An explicit empty list, and a list whose every entry was skipped as invalid under version skew, both fall back to the built-in menu
        // Falling back rather than silently vanishing matches the shell picker
        for meta in [
            serde_json::json!({ "supportsReasoningEffort": true, "reasoningEfforts": [] }),
            serde_json::json!({
                "supportsReasoningEffort": true,
                "reasoningEfforts": [{ "value": "quantum" }],
            }),
        ] {
            let ids: Vec<_> = state_with_meta(Some(meta.clone()))
                .reasoning_effort_options()
                .into_iter()
                .map(|o| o.id)
                .collect();
            assert_eq!(ids, ["xhigh", "high", "medium", "low"], "for meta {meta}");
        }
    }

    #[test]
    fn resolve_effort_token_maps_remap_id_to_canonical_value() {
        let state = state_with_meta(Some(serde_json::json!({
            "supportsReasoningEffort": true,
            "reasoningEfforts": [
                { "id": "deep", "value": "xhigh", "label": "Deep" },
                { "id": "high", "value": "high", "label": "High" },
            ],
        })));
        // The typed id resolves to its canonical wire value
        assert_eq!(
            state.resolve_effort_token("deep"),
            Some(ReasoningEffort::Xhigh)
        );
        assert_eq!(
            state.resolve_effort_token("DEEP"),
            Some(ReasoningEffort::Xhigh)
        );
        // Canonical level offered by the menu is accepted by value.
        assert_eq!(
            state.resolve_effort_token("high"),
            Some(ReasoningEffort::High)
        );
        // Levels the model does not offer (none/minimal on 4.5-style menus) are rejected; better than a server-side 400
        assert!(state.resolve_effort_token("minimal").is_none());
        assert!(state.resolve_effort_token("none").is_none());
        assert!(state.resolve_effort_token("bogus").is_none());
    }

    #[test]
    fn resolve_effort_token_accepts_none_only_when_menu_offers_it() {
        let with_none = state_with_meta(Some(serde_json::json!({
            "supportsReasoningEffort": true,
            "reasoningEfforts": [
                { "value": "none", "label": "None", "default": true },
                { "value": "high", "label": "High" },
            ],
        })));
        assert_eq!(
            with_none.resolve_effort_token("none"),
            Some(ReasoningEffort::None)
        );

        let without_none = state_with_meta(Some(serde_json::json!({
            "supportsReasoningEffort": true,
            "reasoningEfforts": [
                { "value": "high", "label": "High", "default": true },
                { "value": "low", "label": "Low" },
            ],
        })));
        assert!(without_none.resolve_effort_token("none").is_none());
        let err = without_none
            .resolve_effort_for_model(without_none.current.as_ref().unwrap(), "none")
            .unwrap_err();
        assert_eq!(
            err,
            EffortTokenError::UnknownToken {
                token: "none".to_string(),
                offered: vec!["high".to_string(), "low".to_string()],
            }
        );
        // The error copy must list only this model's options, never a hardcoded none/minimal/…
        // The rejected token may still appear quoted in "unknown effort level '…'"
        let msg = err.message();
        assert!(msg.contains("use one of: high, low"), "msg={msg}");
        let offered_half = msg
            .split_once("; ")
            .map(|(_, rest)| rest)
            .expect("message should have '; ' separator");
        assert!(
            !offered_half.contains("none"),
            "must not advertise blocked level: {msg}"
        );
        assert!(
            !offered_half.contains("minimal"),
            "must not advertise blocked level: {msg}"
        );
        assert!(
            !msg.contains("unset"),
            "unset is log-only, not a user token: {msg}"
        );
    }

    #[test]
    fn resolve_effort_token_legacy_menu_rejects_none() {
        // supportsReasoningEffort without a server list means the built-in low..xhigh menu
        let state = state_with_meta(Some(serde_json::json!({
            "supportsReasoningEffort": true,
        })));
        assert!(state.resolve_effort_token("none").is_none());
        assert!(state.resolve_effort_token("minimal").is_none());
        assert_eq!(
            state.resolve_effort_token("low"),
            Some(ReasoningEffort::Low)
        );
    }

    #[test]
    fn accepts_images_honors_explicit_meta() {
        assert!(
            !state_with_meta(Some(serde_json::json!({ "acceptsImages": false })))
                .current_model_accepts_images()
        );
        assert!(
            state_with_meta(Some(serde_json::json!({ "acceptsImages": true })))
                .current_model_accepts_images()
        );
        // inputModalities array form.
        assert!(
            state_with_meta(Some(
                serde_json::json!({ "inputModalities": ["text", "image"] })
            ))
            .current_model_accepts_images()
        );
        assert!(
            !state_with_meta(Some(serde_json::json!({ "inputModalities": ["text"] })))
                .current_model_accepts_images()
        );
    }

    fn windowed_state() -> ModelState {
        let mut state = state_with_meta(Some(serde_json::json!({
            "totalContextTokens": 100_000,
            "contextWindows": [100_000, 400_000],
        })));
        state.current = state.available.keys().next().cloned();
        state
    }

    #[test]
    fn context_window_defaults_to_the_model_and_follows_a_listed_selection() {
        let mut state = windowed_state();
        assert_eq!(state.context_window_options(), vec![100_000, 400_000]);
        assert_eq!(state.get_context_window(), Some(100_000));
        state.context_window_selection = Some(400_000);
        assert_eq!(state.get_context_window(), Some(400_000));
        // A selection the model does not list is not shown
        state.context_window_selection = Some(250_000);
        assert_eq!(state.get_context_window(), Some(100_000));
        // The subagent override still wins
        state.context_window_selection = Some(400_000);
        state.override_context_window(77_000);
        assert_eq!(state.get_context_window(), Some(77_000));
    }

    #[test]
    fn window_after_switch_keeps_a_selection_only_when_the_target_lists_it() {
        let mut state = windowed_state();
        let a = state.current.clone().unwrap();
        let other = acp::ModelId::new(Arc::from("other"));
        let mut info = acp::ModelInfo::new(other.clone(), "Other".to_string());
        info.meta = serde_json::json!({
            "totalContextTokens": 128_000,
            "contextWindows": [128_000, 400_000],
        })
        .as_object()
        .cloned();
        state.available.insert(other.clone(), info);
        let plain = acp::ModelId::new(Arc::from("plain"));
        let mut info = acp::ModelInfo::new(plain.clone(), "Plain".to_string());
        info.meta = serde_json::json!({ "totalContextTokens": 64_000 }).as_object().cloned();
        state.available.insert(plain.clone(), info);

        state.context_window_selection = Some(400_000);
        assert_eq!(state.window_after_switch_to(&a), Some(400_000));
        assert_eq!(state.window_after_switch_to(&other), Some(400_000));
        assert_eq!(state.window_after_switch_to(&plain), Some(64_000));
    }

    #[test]
    fn selection_comes_from_the_current_models_meta_on_load() {
        let id = acp::ModelId::new(Arc::from("m"));
        let mut info = acp::ModelInfo::new(id.clone(), "M".to_string());
        info.meta = serde_json::json!({
            "totalContextTokens": 100_000,
            "contextWindows": [100_000, 400_000],
            "contextWindow": 400_000,
        })
        .as_object()
        .cloned();
        let state: ModelState =
            Some(acp::SessionModelState::new(id, vec![info])).into();
        assert_eq!(state.context_window_selection, Some(400_000));
        assert_eq!(state.get_context_window(), Some(400_000));
    }
}
