//! `/model` (alias `/m`): switch the model and optionally its reasoning effort.
//! Chained autocomplete: after picking a reasoning-supported model, the trailing space re-opens the dropdown into a `low|medium|high|xhigh` sub-menu.

use agent_client_protocol as acp;
use fuigo_shell::sampling::types::supports_reasoning_effort_meta;

use crate::acp::model_state::ModelState;
use crate::app::actions::Action;
use crate::slash::command::{
    AppCtx, ArgItem, CommandExecCtx, CommandResult, SlashCommand, slash_meta,
};
use crate::slash::commands::effort_levels::build_effort_arg_items;

/// Switch the active model (and optionally its reasoning effort).
pub struct ModelCommand;

impl SlashCommand for ModelCommand {
    slash_meta! {
        name: "model",
        aliases: ["m"],
        description: "Switch the active model",
        usage: "/model <name> [effort]",
        takes_args: true,
        args_required: true,
        session_scoped: true,
        // The dashboard offers `/model` to pick the model for the next spawned agent (intercepted in `dispatch_dashboard_dispatch_slash`).
        offered_when_session_less: true,
        arg_placeholder: "<model> [effort]",
    }

    fn suggest_args(&self, ctx: &AppCtx, args_query: &str) -> Option<Vec<ArgItem>> {
        if ctx.models.is_empty() {
            return None;
        }

        // Route phase: "<model> via " lists the other ways of reaching that model.
        if let Some(items) = build_route_items(ctx.models, args_query) {
            return Some(items);
        }

        // Effort phase if input is "<reasoning-model> ", else model phase.
        if let Some(model_id) = detect_effort_phase(ctx.models, args_query) {
            return Some(build_effort_items(ctx.models, &model_id));
        }
        Some(build_model_items(ctx.models))
    }

    fn run(&self, ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        let trimmed = args.trim();
        if trimmed.is_empty() {
            return CommandResult::Error("Usage: /model <name> [effort]".into());
        }

        // "<model> via <route>": pick a route other than the one Fuigo ranked first.
        if let Some((name, word)) = trimmed.rsplit_once(" via ") {
            return match ctx.models.resolve_route(name.trim(), word) {
                Ok(id) => CommandResult::Action(Action::SetDefaultModel(id)),
                Err(words) if words.is_empty() => {
                    CommandResult::Error(format!("Unknown model: {}", name.trim()))
                }
                Err(words) => CommandResult::Error(format!(
                    "{} has no `{}` route. Routes: {}",
                    name.trim(),
                    word.trim(),
                    words.join(", ")
                )),
            };
        }

        // Prefer an exact full-string catalog match first. Model display names often contain spaces ("Grok 4.5").
        // If we split on the last token first, a shorter catalog entry ("Fuigo") would steal the prefix and treat "4.5" as an effort level
        if let Some(id) = ctx.models.resolve_by_name_or_id(trimmed) {
            return CommandResult::Action(Action::SetDefaultModel(id));
        }

        // A trailing effort token on a reasoning model makes a session-scoped switch (not persisted as default)
        // Resolve via the shared gate so a rejected level (e.g. `none` on grok-4.5) reports the effort error with the model's offered ids.
        // Without it the fall-through reports "Unknown model: … none"
        if let Some((prefix, token)) = split_trailing_token(trimmed)
            && let Some(id) = resolve_model(ctx.models, prefix)
            && ctx
                .models
                .available
                .get(&id)
                .map(supports_reasoning_effort)
                .unwrap_or(false)
        {
            return match ctx.models.resolve_effort_for_model(&id, token) {
                Ok(effort) => CommandResult::Action(Action::SwitchModel {
                    model_id: id,
                    effort: Some(effort),
                }),
                Err(err) => CommandResult::Error(err.message()),
            };
        }

        CommandResult::Error(format!("Unknown model: {trimmed}"))
    }
}

/// Look up a model by case-insensitive display name OR model id match.
fn resolve_model(models: &ModelState, name: &str) -> Option<acp::ModelId> {
    models.resolve_by_name_or_id(name)
}

fn supports_reasoning_effort(info: &acp::ModelInfo) -> bool {
    supports_reasoning_effort_meta(info.meta.as_ref())
}

/// Split `args` into `(prefix, last_token)` on the final whitespace run.
/// Returns `None` when there is no interior whitespace to split on.
/// The token is resolved to an effort against the picked model's options by the caller.
fn split_trailing_token(args: &str) -> Option<(&str, &str)> {
    let (prefix, last) = args.rsplit_once(char::is_whitespace)?;
    let prefix = prefix.trim_end();
    if prefix.is_empty() || last.is_empty() {
        return None;
    }
    Some((prefix, last))
}

/// Returns the matched model id when `args_query` is `"<reasoning-model> ..."`.
/// Candidates are tried longest name first to disambiguate names that share a prefix.
fn detect_effort_phase(models: &ModelState, args_query: &str) -> Option<acp::ModelId> {
    let mut candidates: Vec<(&acp::ModelId, &str)> = models
        .available
        .iter()
        .filter(|(_, info)| supports_reasoning_effort(info))
        .map(|(id, info)| (id, info.name.as_str()))
        .collect();
    candidates.sort_by_key(|(_, name)| std::cmp::Reverse(name.len()));

    for (id, name) in candidates {
        if args_query.len() > name.len()
            && args_query.is_char_boundary(name.len())
            && args_query[..name.len()].eq_ignore_ascii_case(name)
            && args_query[name.len()..].starts_with(char::is_whitespace)
        {
            return Some(id.clone());
        }
    }
    None
}

/// One row per logical model.
/// A model reachable more than one way is ONE row, naming the route Fuigo will use ("included in your Grok
/// subscription"); its other routes sit behind `<model> via ` (see [`build_route_items`]). A model no route
/// reaches is listed after the ones that work, saying what to connect.
/// Reasoning models get a trailing space in `insert_text` so the prompt widget chains into the effort sub-menu.
fn build_model_items(models: &ModelState) -> Vec<ArgItem> {
    use crate::acp::model_state::{alt_route_of, connect_hint, routes_of};
    let current_id = models.current.as_ref();
    let mut items: Vec<ArgItem> = Vec::with_capacity(models.available.len());
    for (id, info) in &models.available {
        // An alternate route to a model already listed under its primary route.
        if alt_route_of(info).is_some() {
            continue;
        }
        let is_current = current_id == Some(id)
            || current_id
                .and_then(|c| models.available.get(c))
                .and_then(alt_route_of)
                .is_some_and(|primary| primary == id.0.as_ref());
        let supports = supports_reasoning_effort(info);
        let routes = routes_of(info);
        let connect = connect_hint(info);

        let mut display = info.name.clone();
        // Every row names the route Fuigo will use (Flux Router's badge is implied when the agent sends none),
        // the same badge the welcome "Pick a model:" list shows.
        let badge = crate::acp::model_state::badge_of(info);
        if connect.is_some() {
            display = format!("{display} \u{b7} connect");
        } else {
            display = format!("{display} \u{b7} {badge}");
        }
        if is_current {
            display = format!("{display} (current)");
        }

        // A trailing space on reasoning models signals "more input expected" to the prompt widget
        // Enter then advances to the effort phase instead of submitting
        let insert_text = if supports {
            format!("{} ", info.name)
        } else {
            info.name.clone()
        };

        let mut description = info.description.clone().unwrap_or_default();
        if let Some(hint) = connect {
            description = format!("connect: {hint}");
        } else if routes.len() > 1 {
            let others: Vec<&str> = routes.iter().skip(1).map(|r| r.word.as_str()).collect();
            description = format!(
                "also via {}: press Right or Tab to choose a route",
                others.join(", "),
            );
        }

        items.push(ArgItem {
            display,
            match_text: info.name.clone(),
            insert_text,
            description,
        });
    }
    items
}

/// `"<model> via "` lists that model's routes, best first, each with its one-line reason.
/// `None` when `args_query` is not in the route phase or the model has a single route.
fn build_route_items(models: &ModelState, args_query: &str) -> Option<Vec<ArgItem>> {
    use crate::acp::model_state::routes_of;
    let (name, rest) = args_query.rsplit_once(" via")?;
    if !(rest.is_empty() || rest.starts_with(char::is_whitespace)) {
        return None;
    }
    let id = models.resolve_by_name_or_id(name.trim())?;
    let info = models.available.get(&id)?;
    let routes = routes_of(info);
    if routes.len() < 2 {
        return None;
    }
    Some(
        routes
            .into_iter()
            .map(|r| ArgItem {
                display: r.badge.clone(),
                // Ranked against the whole typed text (`Grok 4.7 via g`), so the route word alone would never match.
                match_text: format!("{} via {}", name.trim(), r.word),
                insert_text: format!("{} via {}", name.trim(), r.word),
                description: r.reason,
            })
            .collect(),
    )
}

/// The route rows for `model_name` (a display name), as the `/model` picker opens them on Right or Tab.
/// `None` when the model has a single route.
pub(crate) fn route_items_for(models: &ModelState, model_name: &str) -> Option<Vec<ArgItem>> {
    build_route_items(models, &format!("{} via ", model_name.trim()))
}

/// One row per effort level for the `/model` chained effort phase.
/// `insert_text` is `"ModelName high"` so selecting a row completes both tokens.
fn build_effort_items(models: &ModelState, model_id: &acp::ModelId) -> Vec<ArgItem> {
    let info = match models.available.get(model_id) {
        Some(info) => info,
        None => return Vec::new(),
    };
    let model_name = info.name.clone();
    let is_current_model = models.current.as_ref() == Some(model_id);
    let options = models.reasoning_effort_options_for(model_id);
    build_effort_arg_items(
        &options,
        models.reasoning_effort,
        is_current_model,
        |option| format!("{model_name} {}", option.id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuigo_shell::sampling::types::ReasoningEffort;
    use std::sync::Arc;

    // ---- one list that chooses for you ----

    fn routed(id: &str, name: &str, routes: &[(&str, &str, &str, bool)], alt_of: Option<&str>, connect: Option<&str>)
        -> (acp::ModelId, acp::ModelInfo)
    {
        let mut meta = serde_json::Map::new();
        if alt_of.is_none() {
            meta.insert(
                "routes".into(),
                serde_json::Value::Array(
                    routes
                        .iter()
                        .map(|(key, word, badge, ready)| {
                            serde_json::json!({
                                "key": key, "label": word, "badge": badge,
                                "reason": format!("reason for {word}"), "word": word, "ready": ready
                            })
                        })
                        .collect(),
                ),
            );
        }
        if let Some(primary) = alt_of {
            meta.insert("altRouteOf".into(), serde_json::json!(primary));
        }
        if let Some(c) = connect {
            meta.insert("connect".into(), serde_json::json!(c));
        }
        let id = acp::ModelId::new(std::sync::Arc::from(id));
        (id.clone(), acp::ModelInfo::new(id, name.to_string()).meta(Some(meta)))
    }

    fn state(entries: Vec<(acp::ModelId, acp::ModelInfo)>, current: &str) -> ModelState {
        let mut s = ModelState::default();
        for (id, info) in entries {
            s.available.insert(id, info);
        }
        s.current = Some(acp::ModelId::new(std::sync::Arc::from(current)));
        s
    }

    fn three_way() -> ModelState {
        let routes = [
            ("grok-4.7", "flux", "via Flux Router", true),
            ("xai/grok-4.7", "grok", "included in your Grok subscription", true),
            ("k/grok-4.7", "xai", "your xAI key", true),
        ];
        state(
            vec![
                routed("grok-4.7", "Grok 4.7", &routes, None, None),
                routed("xai/grok-4.7", "grok-4.7 (Grok subscription)", &[], Some("grok-4.7"), None),
                routed("k/grok-4.7", "grok-4.7 (xAI key)", &[], Some("grok-4.7"), None),
                routed("flux-only", "Flux Only", &[("flux-only", "flux", "via Flux Router", false)], None, Some("needs a Flux Router key (fluxrouter.ai)")),
            ],
            "grok-4.7",
        )
    }

    #[test]
    fn a_model_reachable_three_ways_is_one_row_naming_the_route_fuigo_will_use() {
        let items = build_model_items(&three_way());
        let grok: Vec<&ArgItem> = items.iter().filter(|i| i.match_text.contains("rok")).collect();
        assert_eq!(grok.len(), 1, "one row, not three: {:?}", items.iter().map(|i| &i.display).collect::<Vec<_>>());
        assert_eq!(grok[0].display, "Grok 4.7 \u{b7} via Flux Router (current)");
        assert!(grok[0].description.contains("also via grok, xai"), "{}", grok[0].description);
    }

    /// Every row names its route: a single-route key model carries its own badge, and once the list
    /// holds any non-Flux route an unmarked row reads "via Flux Router".
    #[test]
    fn single_route_rows_carry_a_badge_too() {
        let mut meta = serde_json::Map::new();
        meta.insert(
            "route".into(),
            serde_json::json!({ "label": "OpenAI key from OPENAI_API_KEY", "badge": "your OpenAI key", "kind": "Key" }),
        );
        let key_id = acp::ModelId::new(std::sync::Arc::from("openai-key/gpt-5"));
        let key_row = (key_id.clone(), acp::ModelInfo::new(key_id, "gpt-5".to_string()).meta(Some(meta)));
        let plain_id = acp::ModelId::new(std::sync::Arc::from("flux-model"));
        let plain = (plain_id.clone(), acp::ModelInfo::new(plain_id, "Flux Model".to_string()));
        let items = build_model_items(&state(vec![plain.clone(), key_row], "flux-model"));
        assert_eq!(items[0].display, "Flux Model \u{b7} via Flux Router (current)");
        assert_eq!(items[1].display, "gpt-5 \u{b7} your OpenAI key");
        // A list of Flux models only names the route too (it used to be left bare).
        let only = build_model_items(&state(vec![plain], "flux-model"));
        assert_eq!(only[0].display, "Flux Model \u{b7} via Flux Router (current)");
    }

    /// 125 Flux models from `FUIGO_API_KEY` showed as bare ids with no route text. Every row says "via Flux
    /// Router", whatever else is or is not in the list.
    #[test]
    fn a_list_of_only_flux_models_badges_every_row() {
        let rows: Vec<_> = (0..125)
            .map(|n| {
                let id = acp::ModelId::new(std::sync::Arc::from(format!("model-{n}")));
                (id.clone(), acp::ModelInfo::new(id, format!("Model {n}")))
            })
            .collect();
        let items = build_model_items(&state(rows, "model-0"));
        assert_eq!(items.len(), 125);
        for item in &items {
            assert!(item.display.contains("\u{b7} via Flux Router"), "no badge on {:?}", item.display);
        }
    }

    /// The welcome "Pick a model:" list and `/model` are one list: the same models, in the same order, each with
    /// the same route badge.
    #[test]
    fn the_welcome_list_matches_the_model_list() {
        let mut plain_rows = Vec::new();
        for n in 0..3 {
            let id = acp::ModelId::new(std::sync::Arc::from(format!("plain-{n}")));
            plain_rows.push((id.clone(), acp::ModelInfo::new(id, format!("Plain {n}"))));
        }
        for models in [state(plain_rows, "plain-0"), three_way()] {
            let welcome: Vec<String> = models
                .usable_models()
                .into_iter()
                .map(|m| format!("{} \u{b7} {}", m.name, m.badge))
                .collect();
            let listed: Vec<String> = build_model_items(&models)
                .into_iter()
                .filter(|i| !i.display.contains("\u{b7} connect"))
                .map(|i| i.display.trim_end_matches(" (current)").to_owned())
                .collect();
            assert!(!welcome.is_empty());
            assert_eq!(welcome, listed, "welcome and /model disagree");
            assert!(welcome.iter().all(|row| !row.ends_with("\u{b7} ")), "an empty badge: {welcome:?}");
        }
    }

    #[test]
    fn a_model_no_route_reaches_says_what_to_connect() {
        let items = build_model_items(&three_way());
        let flux_only = items.iter().find(|i| i.match_text == "Flux Only").unwrap();
        assert_eq!(flux_only.description, "connect: needs a Flux Router key (fluxrouter.ai)");
        assert!(flux_only.display.ends_with("connect"), "{}", flux_only.display);
    }

    #[test]
    fn via_lists_the_other_routes_each_with_its_reason() {
        let items = build_route_items(&three_way(), "Grok 4.7 via ").expect("route phase");
        // The dropdown ranks rows against the whole typed text (`Grok 4.7 via `), so match_text is the
        // full `<model> via <route>`; the bare route word matched nothing there.
        let words: Vec<&str> = items.iter().map(|i| i.match_text.as_str()).collect();
        assert_eq!(words, ["Grok 4.7 via flux", "Grok 4.7 via grok", "Grok 4.7 via xai"]);
        assert_eq!(items[1].insert_text, "Grok 4.7 via grok");
        assert_eq!(items[1].display, "included in your Grok subscription");
        assert_eq!(items[1].description, "reason for grok");
        // Not in the route phase, or a model with one route: nothing to offer.
        assert!(build_route_items(&three_way(), "Grok 4.7").is_none());
        assert!(build_route_items(&three_way(), "Flux Only via ").is_none());
    }

    #[test]
    fn choosing_a_route_switches_to_that_routes_entry() {
        let models = three_way();
        let result = run_with(&models, "Grok 4.7 via grok");
        match result {
            CommandResult::Action(Action::SetDefaultModel(id)) => assert_eq!(id.0.as_ref(), "xai/grok-4.7"),
            other => panic!("expected SetDefaultModel, got {other:?}"),
        }
        match run_with(&models, "Grok 4.7 via nope") {
            CommandResult::Error(e) => {
                assert!(e.contains("no `nope` route") && e.contains("flux, grok, xai"), "{e}")
            }
            other => panic!("expected an error, got {other:?}"),
        }
    }

    fn run_with(models: &ModelState, args: &str) -> CommandResult {
        let bundle = crate::app::bundle::BundleState::default();
        let mut ctx = CommandExecCtx {
            models,
            session_id: None,
            bundle_state: &bundle,
            screen_mode: crate::app::ScreenMode::Inline,
            billing_surface_visible: true,
            usage_command_visible: true,
            pager_state: crate::settings::PagerLocalSnapshot::default(),
        };
        ModelCommand.run(&mut ctx, args)
    }

    fn model_with_reasoning(id: &str, name: &str) -> (acp::ModelId, acp::ModelInfo) {
        let id = acp::ModelId::new(Arc::from(id));
        let mut meta = serde_json::Map::new();
        meta.insert(
            "supportsReasoningEffort".into(),
            serde_json::Value::Bool(true),
        );
        let info = acp::ModelInfo::new(id.clone(), name.to_string())
            .meta(serde_json::Value::Object(meta).as_object().cloned());
        (id, info)
    }

    fn plain_model(id: &str, name: &str) -> (acp::ModelId, acp::ModelInfo) {
        let id = acp::ModelId::new(Arc::from(id));
        let info = acp::ModelInfo::new(id.clone(), name.to_string());
        (id, info)
    }

    static EMPTY_BUNDLE: crate::app::bundle::BundleState = crate::app::bundle::BundleState {
        has_cache: false,
        version: String::new(),
        personas: Vec::new(),
        roles: Vec::new(),
        agents: Vec::new(),
        skills: Vec::new(),
        persona_details: Vec::new(),
        role_details: Vec::new(),
    };

    fn dummy_exec_ctx(models: &ModelState) -> CommandExecCtx<'_> {
        CommandExecCtx {
            models,
            session_id: None,
            bundle_state: &EMPTY_BUNDLE,
            screen_mode: crate::app::ScreenMode::Inline,
            billing_surface_visible: true,
            usage_command_visible: true,
            pager_state: crate::settings::PagerLocalSnapshot {
                multiline_mode: false,
                yolo_mode: false,
                ..crate::settings::PagerLocalSnapshot::default()
            },
        }
    }

    #[test]
    fn split_trailing_token_splits_on_final_whitespace() {
        assert_eq!(
            split_trailing_token("Reasoning X high"),
            Some(("Reasoning X", "high"))
        );
        assert_eq!(
            split_trailing_token("reasoning-x  xhigh"),
            Some(("reasoning-x", "xhigh"))
        );
        // No interior whitespace, so nothing to split off
        assert!(split_trailing_token("reasoning-x-pro").is_none());
    }

    #[test]
    fn empty_query_returns_one_row_per_logical_model() {
        let mut state = ModelState::default();
        let (rid, rinfo) = model_with_reasoning("reasoning-x", "Reasoning X");
        let (pid, pinfo) = plain_model("grok-4.5", "Grok 4.5");
        state.available.insert(rid, rinfo);
        state.available.insert(pid, pinfo);

        let cmd = ModelCommand;
        let ctx = AppCtx {
            models: &state,
            cwd: std::path::Path::new("."),
            has_session_announcements: false,
            billing_surface_visible: true,
            usage_command_visible: true,
            workflows_available: true,
            saved_workflows: &[],
            workflow_runs: &[],
            screen_mode: crate::app::ScreenMode::Fullscreen,
            current_title: None,
        };
        let items = cmd.suggest_args(&ctx, "").unwrap();
        assert_eq!(items.len(), 2, "model phase: one row per logical model");

        // A reasoning model has a trailing space in insert_text
        // The prompt widget reads it to keep the dropdown open after Enter so the effort sub-menu can render
        let reasoning = items
            .iter()
            .find(|i| i.match_text == "Reasoning X")
            .unwrap();
        assert_eq!(reasoning.insert_text, "Reasoning X ");

        // A plain model has no trailing space, so Enter commits immediately
        let plain = items.iter().find(|i| i.match_text == "Grok 4.5").unwrap();
        assert_eq!(plain.insert_text, "Grok 4.5");
    }

    #[test]
    fn trailing_space_after_reasoning_model_enters_effort_phase() {
        let mut state = ModelState::default();
        let (id, info) = model_with_reasoning("reasoning-x", "Reasoning X");
        state.available.insert(id, info);

        let cmd = ModelCommand;
        let ctx = AppCtx {
            models: &state,
            cwd: std::path::Path::new("."),
            has_session_announcements: false,
            billing_surface_visible: true,
            usage_command_visible: true,
            workflows_available: true,
            saved_workflows: &[],
            workflow_runs: &[],
            screen_mode: crate::app::ScreenMode::Fullscreen,
            current_title: None,
        };
        // The args query has a trailing space, so this is the effort phase
        // Items come out ordered xhigh to low (strongest first) per EFFORT_LEVELS
        let items = cmd.suggest_args(&ctx, "Reasoning X ").unwrap();
        assert_eq!(items.len(), 4);
        assert_eq!(items[0].insert_text, "Reasoning X xhigh");
        assert_eq!(items[1].insert_text, "Reasoning X high");
        assert_eq!(items[2].insert_text, "Reasoning X medium");
        assert_eq!(items[3].insert_text, "Reasoning X low");
        // Display is just the level so the user sees a clean column.
        assert_eq!(items[0].display, "xhigh");
        // match_text carries the sort-key prefix that forces the matcher's alphabetical tiebreak to render rows in EFFORT_LEVELS order
        assert!(items[0].match_text.starts_with("a "));
        assert!(items[3].match_text.starts_with("d "));
    }

    #[test]
    fn partial_effort_query_still_in_effort_phase() {
        let mut state = ModelState::default();
        let (id, info) = model_with_reasoning("reasoning-x", "Reasoning X");
        state.available.insert(id, info);

        let cmd = ModelCommand;
        let ctx = AppCtx {
            models: &state,
            cwd: std::path::Path::new("."),
            has_session_announcements: false,
            billing_surface_visible: true,
            usage_command_visible: true,
            workflows_available: true,
            saved_workflows: &[],
            workflow_runs: &[],
            screen_mode: crate::app::ScreenMode::Fullscreen,
            current_title: None,
        };
        // Still in effort phase; the matcher upstream narrows to high and xhigh
        let items = cmd.suggest_args(&ctx, "Reasoning X h").unwrap();
        assert_eq!(items.len(), 4);
    }

    #[test]
    fn partial_model_query_stays_in_model_phase() {
        let mut state = ModelState::default();
        let (id, info) = model_with_reasoning("reasoning-x", "Reasoning X");
        state.available.insert(id, info);

        let cmd = ModelCommand;
        let ctx = AppCtx {
            models: &state,
            cwd: std::path::Path::new("."),
            has_session_announcements: false,
            billing_surface_visible: true,
            usage_command_visible: true,
            workflows_available: true,
            saved_workflows: &[],
            workflow_runs: &[],
            screen_mode: crate::app::ScreenMode::Fullscreen,
            current_title: None,
        };
        // No trailing space: the user is still typing the model name
        let items = cmd.suggest_args(&ctx, "Reason").unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].insert_text, "Reasoning X ");
    }

    #[test]
    fn run_parses_model_plus_effort_when_supported() {
        let mut state = ModelState::default();
        let (id, info) = model_with_reasoning("reasoning-x", "Reasoning X");
        state.available.insert(id, info);
        let mut ctx = dummy_exec_ctx(&state);
        let result = ModelCommand.run(&mut ctx, "Reasoning X xhigh");
        match result {
            CommandResult::Action(Action::SwitchModel { model_id, effort }) => {
                assert_eq!(model_id.0.as_ref(), "reasoning-x");
                assert_eq!(effort, Some(ReasoningEffort::Xhigh));
            }
            other => panic!("expected SwitchModel with effort, got {other:?}"),
        }
    }

    #[test]
    fn run_rejects_unoffered_effort_with_effort_error_not_unknown_model() {
        // Regression: previously `resolve_effort_token_for` returned None and the handler fell through to `Unknown model: Reasoning X none`
        let mut state = ModelState::default();
        let (id, info) = model_with_reasoning("reasoning-x", "Reasoning X");
        state.available.insert(id, info);
        let mut ctx = dummy_exec_ctx(&state);
        let result = ModelCommand.run(&mut ctx, "Reasoning X none");
        match result {
            CommandResult::Error(msg) => {
                assert!(
                    msg.contains("unknown effort level 'none'"),
                    "expected effort error, got {msg}"
                );
                assert!(
                    msg.contains("use one of:"),
                    "expected offered levels in message, got {msg}"
                );
                assert!(
                    !msg.to_lowercase().contains("unknown model"),
                    "must not misreport as unknown model: {msg}"
                );
                let offered = msg.split_once("; ").map(|(_, r)| r).unwrap_or("");
                assert!(
                    !offered.contains("none"),
                    "must not list none as offered: {msg}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn run_prefers_full_multi_word_model_name_over_prefix_plus_effort() {
        // The catalog has both "Fuigo" (reasoning) and "Grok 4.5"
        // `/model Grok 4.5` must select the full name, not treat "4.5" as an effort on "Fuigo"
        let mut state = ModelState::default();
        let (short_id, short_info) = model_with_reasoning("fuigo", "Fuigo");
        let (long_id, long_info) = model_with_reasoning("grok-4.5", "Grok 4.5");
        state.available.insert(short_id, short_info);
        state.available.insert(long_id.clone(), long_info);
        let mut ctx = dummy_exec_ctx(&state);
        let result = ModelCommand.run(&mut ctx, "Grok 4.5");
        match result {
            CommandResult::Action(Action::SetDefaultModel(resolved_id)) => {
                assert_eq!(resolved_id, long_id);
            }
            other => panic!("expected SetDefaultModel(Grok 4.5), got {other:?}"),
        }
    }

    #[test]
    fn run_rejects_effort_for_non_reasoning_model() {
        let mut state = ModelState::default();
        let (id, info) = plain_model("grok-4.5", "Grok 4.5");
        state.available.insert(id, info);
        let mut ctx = dummy_exec_ctx(&state);
        let result = ModelCommand.run(&mut ctx, "Grok 4.5 high");
        // Falls through to "is the whole string a model name?", which it isn't, so we get an Unknown error
        assert!(matches!(result, CommandResult::Error(_)));
    }

    /// The bare `/model <name>` form dispatches `Action::SetDefaultModel(<ModelId>)` instead of the legacy `Action::SwitchModel { effort: None }`.
    /// The dispatcher routes it through both `Effect::SwitchModel` (session mutation) and `Effect::PersistSetting` (next-session default).
    ///
    /// The payload is the typed `acp::ModelId` (resolved at the slash boundary), not a String.
    #[test]
    fn run_bare_model_name_dispatches_set_default_model() {
        let mut state = ModelState::default();
        let (id, info) = plain_model("grok-4.5", "Grok 4.5");
        state.available.insert(id.clone(), info);
        let mut ctx = dummy_exec_ctx(&state);
        let result = ModelCommand.run(&mut ctx, "Grok 4.5");
        match result {
            CommandResult::Action(Action::SetDefaultModel(resolved_id)) => {
                assert_eq!(resolved_id, id);
            }
            other => panic!("expected Action::SetDefaultModel(<id>), got {other:?}"),
        }
    }

    /// Case-insensitive matching against the catalog: `/model grok 4.5` resolves
    /// to the same `ModelId` as `/model Grok 4.5`.
    ///
    /// The catalog entry is a protected wire value the rebrand left as
    /// "grok-4.5"/"Grok 4.5"; the transform rewrote the lookup ARGUMENT anyway,
    /// since there it is only a string, and the test started asking for a model
    /// that is not in the catalog.
    #[test]
    fn run_set_default_model_resolves_case_insensitively() {
        let mut state = ModelState::default();
        let (id, info) = plain_model("grok-4.5", "Grok 4.5");
        state.available.insert(id.clone(), info);
        let mut ctx = dummy_exec_ctx(&state);
        let result = ModelCommand.run(&mut ctx, "grok 4.5");
        match result {
            CommandResult::Action(Action::SetDefaultModel(resolved_id)) => {
                assert_eq!(resolved_id, id);
            }
            other => panic!("expected Action::SetDefaultModel(<id>), got {other:?}"),
        }
    }
}
