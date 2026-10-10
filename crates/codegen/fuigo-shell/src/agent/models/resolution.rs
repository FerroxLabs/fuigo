use super::*;

/// Map a model id (catalog key or routing slug) to its catalog key.
pub(crate) fn resolve_catalog_key(
    models: &IndexMap<String, ModelEntry>,
    id: &acp::ModelId,
) -> Option<acp::ModelId> {
    let id_str = id.0.as_ref();
    if models.contains_key(id_str) {
        return Some(id.clone());
    }
    models
        .iter()
        .rev()
        .find(|(_, entry)| entry.info.has_model_id(id_str))
        .map(|(key, _)| acp::ModelId::new(key.clone()))
}

/// Catalog key for a persisted session model id, restricted to **selectable** entries.
pub(crate) fn selectable_catalog_key_for_persisted(
    models: &IndexMap<String, ModelEntry>,
    available: &IndexMap<acp::ModelId, acp::ModelInfo>,
    id: &acp::ModelId,
) -> Option<acp::ModelId> {
    if available.contains_key(id) {
        return Some(id.clone());
    }
    let id_str = id.0.as_ref();
    if let Some((key, _)) = models.iter().rev().find(|(key, entry)| {
        available.contains_key(&acp::ModelId::new((*key).clone()))
            && entry.info.has_model_id(id_str)
    }) {
        return Some(acp::ModelId::new(key.clone()));
    }
    resolve_catalog_key(models, id).filter(|key| available.contains_key(key))
}

/// A "campaign-only" preferred flip: the default changed and either side's value is an active campaign default.
pub(crate) fn is_campaign_only_flip(
    old_preferred: &Option<String>,
    new_preferred: &Option<String>,
    campaign_defaults: &std::collections::HashSet<String>,
) -> bool {
    if new_preferred == old_preferred || new_preferred.is_none() {
        return false;
    }
    new_preferred
        .as_ref()
        .is_some_and(|p| campaign_defaults.contains(p))
        || old_preferred
            .as_ref()
            .is_some_and(|p| campaign_defaults.contains(p))
}

/// Pick the default model: CLI > env > config > remote-settings hint, falling back to the first visible model, then the bundled default.
pub(crate) fn resolve_default_model(
    cfg: &config::Config,
    catalog: &IndexMap<String, ModelEntry>,
    is_session_auth: bool,
) -> (String, ModelEntry, config::ConfigSource) {
    let visible: IndexMap<String, ModelEntry> = catalog
        .iter()
        .filter(|(_, e)| e.info.visible_for_auth(is_session_auth) && e.info.user_selectable)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let model_pref = config::resolve_string_flag(
        cfg.default_model_override.as_deref(),
        "FUIGO_DEFAULT_MODEL",
        cfg.models.default.as_deref(),
        cfg.remote_settings
            .as_ref()
            .and_then(|rs| rs.default_model.as_deref()),
    );

    let first_or_fallback = || -> (String, ModelEntry) {
        // The BAKED default outranks "whatever the catalogue listed first".
        //
        // Upstream reached the bundled default only when nothing was visible,
        // because their remote settings always supplied a `default_model` hint
        // above this point. FluxRouter's /v1/models has no such field, so with
        // a key on a fresh install the fetched catalogue replaced the baked
        // list and the default silently became its first entry -- `flux-fast`,
        // the cheapest tier, for a coding agent. That is server ordering, not a
        // product decision.
        //
        // Everything above still wins: CLI flag, env, config, remote hint. This
        // only changes which of the two FALLBACKS applies first, and it falls
        // through to the old behaviour whenever the baked default is not in the
        // catalogue.
        let baked = crate::models::default_model();
        if let Some((key, entry)) = visible
            .get_key_value(baked)
            .or_else(|| visible.iter().find(|(_, m)| m.has_model_id(baked)))
        {
            return (key.clone(), entry.clone());
        }
        if let Some((key, first)) = visible.first() {
            return (key.clone(), first.clone());
        }
        if let Some((key, entry)) = catalog.iter().find(|(_, e)| e.info.user_selectable) {
            tracing::warn!("no auth-visible selectable model; using first selectable entry");
            return (key.clone(), entry.clone());
        }
        tracing::warn!("no selectable models; falling back to bundled default (pre-catalog)");
        let default_id = crate::models::default_model().to_string();
        let mut entry = ModelEntry::fallback(&default_id, &cfg.endpoints);
        entry.info.user_selectable = effective_allowlist(cfg).is_selected(&default_id, &default_id);
        (default_id, entry)
    };

    match &model_pref {
        None => {
            let (key, first) = first_or_fallback();
            (key, first, config::ConfigSource::Default)
        }
        Some(pref) => {
            let found = visible
                .get_key_value(&pref.value)
                .or_else(|| visible.iter().find(|(_, m)| m.has_model_id(&pref.value)));

            if let Some((key, entry)) = found {
                (key.clone(), entry.clone(), pref.source)
            } else {
                let is_explicit = matches!(
                    pref.source,
                    config::ConfigSource::Cli
                        | config::ConfigSource::Env
                        | config::ConfigSource::Config
                );
                if is_explicit {
                    tracing::warn!(
                        model_id = %pref.value, source = %pref.source,
                        "preferred model not in available models, falling back"
                    );
                } else {
                    tracing::debug!(
                        model_id = %pref.value, source = %pref.source,
                        "remote default_model not in available models, skipping"
                    );
                }
                let campaign_pref_missing = cfg.models.default_is_campaign_driven
                    && matches!(pref.source, config::ConfigSource::Config);
                if campaign_pref_missing
                    && let Some(prev) = cfg
                        .models
                        .pre_campaign_default
                        .as_deref()
                        .filter(|s| !s.is_empty())
                    && let Some((key, entry)) = visible
                        .get_key_value(prev)
                        .or_else(|| visible.iter().find(|(_, m)| m.has_model_id(prev)))
                {
                    tracing::info!(
                        unavailable = %pref.value, fallback = %prev,
                        "campaign-driven default unavailable in catalog; recovering the pre-campaign default"
                    );
                    return (key.clone(), entry.clone(), config::ConfigSource::Config);
                }
                let (key, first) = first_or_fallback();
                (key, first, config::ConfigSource::Default)
            }
        }
    }
}

/// Filter hidden and auth-gated entries out of `catalog` and convert to ACP wire format.
pub(crate) fn available_models(
    catalog: &IndexMap<String, ModelEntry>,
    is_session_auth: bool,
) -> IndexMap<acp::ModelId, acp::ModelInfo> {
    let visible: IndexMap<String, ModelEntry> = catalog
        .iter()
        .filter(|(_, e)| e.info.visible_for_auth(is_session_auth))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    config::to_acp_model_info(&visible)
}

/// Compiled glob matcher shared by `allowed_models`, `disabled_models`, and `hidden_models` (matched against catalog key or model id).
pub(crate) struct ModelGlobSet(GlobSet);

impl ModelGlobSet {
    /// Compile a filter list (`Ok(None)` for `None`/empty). Fails **closed**: an invalid pattern returns `Err` listing every bad one.
    pub(crate) fn compile(patterns: Option<&Vec<String>>) -> Result<Option<Self>, Vec<String>> {
        let patterns = match patterns {
            Some(p) if !p.is_empty() => p,
            _ => return Ok(None),
        };
        let mut builder = GlobSetBuilder::new();
        let mut invalid = Vec::new();
        for pat in patterns {
            match Glob::new(pat) {
                Ok(glob) => {
                    builder.add(glob);
                }
                Err(_) => invalid.push(pat.clone()),
            }
        }
        if !invalid.is_empty() {
            return Err(invalid);
        }
        builder
            .build()
            .map(|set| Some(Self(set)))
            .map_err(|e| vec![e.to_string()])
    }

    fn matches(&self, key: &str, model: &str) -> bool {
        self.0.is_match(key) || self.0.is_match(model)
    }

    fn matches_model(&self, model: &str) -> bool {
        self.0.is_match(model)
    }
}

/// The allowlist in force (P169): the fleet pin from `requirements.toml` replaces the user/project list.
pub(crate) enum EffectiveAllowlist<'a> {
    Unrestricted,
    /// The pin is present but unreadable (or its requirements file is): nothing is selectable.
    Invalid,
    User(&'a Vec<String>),
    Fleet(&'a Vec<String>),
}

pub(crate) fn effective_allowlist(cfg: &config::Config) -> EffectiveAllowlist<'_> {
    use crate::agent::config::AllowlistPin;
    match cfg.requirements.allowed_models.pin_ref() {
        Some(AllowlistPin::FailClosed) => EffectiveAllowlist::Invalid,
        Some(AllowlistPin::List(patterns)) if patterns.is_empty() => {
            EffectiveAllowlist::Unrestricted
        }
        Some(AllowlistPin::List(patterns)) => EffectiveAllowlist::Fleet(patterns),
        None => match cfg.models.allowed_models.as_ref() {
            Some(patterns) if !patterns.is_empty() => EffectiveAllowlist::User(patterns),
            _ => EffectiveAllowlist::Unrestricted,
        },
    }
}

impl EffectiveAllowlist<'_> {
    pub(crate) fn is_unrestricted(&self) -> bool {
        matches!(self, Self::Unrestricted)
    }

    /// Set by policy (a fleet list or an unreadable pin), not by the user.
    pub(crate) fn is_fleet(&self) -> bool {
        matches!(self, Self::Fleet(_) | Self::Invalid)
    }

    /// Whether a catalog entry is selectable. A fleet pin matches the model id only, so a user `[model.<key>]` whose
    /// key happens to match a fleet pattern cannot satisfy it; a user list matches the key or the model id.
    pub(crate) fn is_selected(&self, key: &str, model: &str) -> bool {
        self.selector()(key, model)
    }

    /// [`Self::is_selected`] with the glob set compiled once, for a pass over the whole catalog.
    pub(crate) fn selector(&self) -> impl Fn(&str, &str) -> bool + '_ {
        enum Compiled {
            All,
            None,
            Fleet(ModelGlobSet),
            User(ModelGlobSet),
        }
        let compiled = match self {
            Self::Unrestricted => Compiled::All,
            Self::Invalid => Compiled::None,
            Self::Fleet(patterns) | Self::User(patterns) => {
                match ModelGlobSet::compile(Some(*patterns)) {
                    Ok(None) => Compiled::All,
                    Ok(Some(set)) if matches!(self, Self::Fleet(_)) => Compiled::Fleet(set),
                    Ok(Some(set)) => Compiled::User(set),
                    Err(bad) => {
                        tracing::error!(patterns = ?bad, "allowed_models: invalid glob(s); marking nothing selectable");
                        Compiled::None
                    }
                }
            }
        };
        move |key, model| match &compiled {
            Compiled::All => true,
            Compiled::None => false,
            Compiled::Fleet(set) => set.matches_model(model),
            Compiled::User(set) => set.matches(key, model),
        }
    }
}

/// Whether a side call (title, image description, web search, classifier, prompt suggestion) may sample `slug`.
/// Only a fleet pin binds it (the user's own list is the user's choice to widen or narrow for helpers): then the slug
/// must be a catalog entry whose model id the pin admits. An id off the catalog is refused, never synthesized onto
/// the inference route. Callers fall back to the admitted session model, or skip the call.
pub(crate) fn helper_model_admitted(
    allowlist: &EffectiveAllowlist<'_>,
    models: &IndexMap<String, ModelEntry>,
    slug: &str,
) -> bool {
    if !allowlist.is_fleet() {
        return true;
    }
    config::find_model_by_id(models, slug)
        .is_some_and(|entry| allowlist.is_selected(slug, &entry.model))
}

/// The model id a side call puts on the wire (P169 round 7). Admission alone is not enough: the request must carry
/// the `model` of the catalog entry the pin admitted, never the slug that located it (a user `[model.<key>]` can map
/// any key onto a pinned model id). Without a fleet pin: `preferred`, else `unpinned_default`, else the session model
/// (behaviour unchanged). Under one: the admitted entry's model id for `preferred`, else the session model; `None`
/// when there is neither, and the caller skips the call.
pub(crate) fn helper_wire_model(
    allowlist: &EffectiveAllowlist<'_>,
    models: &IndexMap<String, ModelEntry>,
    preferred: Option<&str>,
    unpinned_default: Option<&str>,
    session_model: Option<&str>,
) -> Option<String> {
    let preferred = preferred.map(str::trim).filter(|s| !s.is_empty());
    if !allowlist.is_fleet() {
        return preferred
            .or(unpinned_default)
            .or(session_model)
            .map(str::to_owned);
    }
    let admitted = preferred.and_then(|slug| {
        config::find_model_by_id(models, slug)
            .filter(|entry| allowlist.is_selected(slug, &entry.model))
            .map(|entry| entry.model.clone())
    });
    // The session model is a wire id: it is re-judged, because the pin can have changed (or failed closed) since it was set.
    admitted.or_else(|| {
        session_model
            .filter(|model| helper_model_admitted(allowlist, models, model))
            .map(str::to_owned)
    })
}

/// The model id a helper puts on the wire for the session's selected catalog key (P169 round 8). Without a fleet pin the
/// key is returned unchanged (behaviour unchanged). Under one: the `model` of the entry the pin admits, `None` otherwise.
pub(crate) fn selected_wire_model(
    allowlist: &EffectiveAllowlist<'_>,
    models: &IndexMap<String, ModelEntry>,
    catalog_key: &str,
) -> Option<String> {
    if !allowlist.is_fleet() {
        return Some(catalog_key.to_owned());
    }
    config::find_model_by_id(models, catalog_key)
        .filter(|entry| allowlist.is_selected(catalog_key, &entry.model))
        .map(|entry| entry.model.clone())
}

/// Shell AI suggest (`handle_ai_suggest`): the client's `aiModel` hint, else `grok-4.6`.
pub(crate) fn ai_suggest_wire_model(
    allowlist: &EffectiveAllowlist<'_>,
    models: &IndexMap<String, ModelEntry>,
    model_override: Option<&str>,
    session_model: Option<&str>,
) -> Option<String> {
    helper_wire_model(allowlist, models, model_override, Some("grok-4.6"), session_model)
}

/// Memory-note rewrite (`handle_rewrite_memory_note`): `grok-4.6`.
pub(crate) fn rewrite_note_wire_model(
    allowlist: &EffectiveAllowlist<'_>,
    models: &IndexMap<String, ModelEntry>,
    session_model: Option<&str>,
) -> Option<String> {
    helper_wire_model(allowlist, models, None, Some("grok-4.6"), session_model)
}

/// Memory flush (`run_memory_flush`): `[compaction.memory_flush] flush_model`, else the session model.
pub(crate) fn flush_wire_model(
    allowlist: &EffectiveAllowlist<'_>,
    models: &IndexMap<String, ModelEntry>,
    flush_model: Option<&str>,
    session_model: Option<&str>,
) -> Option<String> {
    helper_wire_model(allowlist, models, flush_model, None, session_model)
        // No pin and nothing configured: the request goes out with an empty model, as it always did (P169 round 8).
        .or_else(|| (!allowlist.is_fleet()).then(String::new))
}

/// Prompt suggestion (`handle_suggest_prompt`): the slug already chosen by `effective_suggest_model`.
pub(crate) fn suggest_prompt_wire_model(
    allowlist: &EffectiveAllowlist<'_>,
    models: &IndexMap<String, ModelEntry>,
    slug: &str,
    session_model: Option<&str>,
) -> Option<String> {
    helper_wire_model(allowlist, models, Some(slug), None, session_model)
}

/// Whether a reasoning-effort route to model id `routed` is allowed: only a fleet pin judges it (by model id).
pub(crate) fn effort_route_allowed(cfg: &config::Config, routed: &str) -> bool {
    let allowlist = effective_allowlist(cfg);
    !allowlist.is_fleet() || allowlist.is_selected(routed, routed)
}

/// The refusal for choosing a model the allowlist excludes.
pub(crate) fn allowlist_denied_message(cfg: &config::Config) -> &'static str {
    if effective_allowlist(cfg).is_fleet() {
        "This model isn't allowed by your organization's policy (requirements.toml allowed_models)."
    } else {
        "This model isn't allowed by your allowed_models setting."
    }
}

/// The message when the allowlist leaves no selectable model.
pub(crate) fn allowlist_excludes_all_message(cfg: &config::Config) -> String {
    match effective_allowlist(cfg) {
        EffectiveAllowlist::Invalid => format!(
            "The organization model policy (requirements.toml allowed_models) is invalid or unreadable{}, so no model \
             can be selected. Fix the file or contact your administrator.",
            pin_source_suffix(cfg)
        ),
        EffectiveAllowlist::Fleet(_) => format!(
            "None of your models are allowed by your organization's policy (requirements.toml allowed_models{}). \
             Contact your administrator.",
            pin_source_suffix(cfg)
        ),
        _ => "None of your models are allowed by allowed_models. \
              Broaden it or remove it from your config, then restart."
            .to_owned(),
    }
}

fn pin_source_suffix(cfg: &config::Config) -> String {
    cfg.requirements
        .allowed_models
        .source()
        .and_then(|s| s.path())
        .map(|p| format!(" in {}", p.display()))
        .unwrap_or_default()
}

/// Single source of truth for the catalog: applies `disabled_models`, then `allowed_models`, then `hidden_models`.
pub(crate) fn resolve_model_catalog(
    cfg: &config::Config,
    prefetched: Option<IndexMap<String, ModelEntry>>,
) -> IndexMap<String, ModelEntry> {
    let mut catalog: IndexMap<String, ModelEntry> = config::resolve_model_list(cfg, prefetched);

    if let Ok(Some(disabled)) = ModelGlobSet::compile(cfg.models.disabled_models.as_ref()) {
        let before = catalog.len();
        catalog.retain(|key, entry| !disabled.matches(key, &entry.model));
        let removed = before - catalog.len();
        if removed > 0 {
            tracing::info!(count = removed, "disabled_models: removed from catalog");
        }
    }

    let allowlist = effective_allowlist(cfg);
    let selected = allowlist.selector();
    for (key, entry) in catalog.iter_mut() {
        entry.info.user_selectable = selected(key, &entry.model);
    }

    if let Ok(Some(hidden)) = ModelGlobSet::compile(cfg.models.hidden_models.as_ref()) {
        for (key, entry) in catalog.iter_mut() {
            if hidden.matches(key, &entry.model) {
                entry.info.hidden = true;
            }
        }
    }

    if let Some(effort) = cfg.models.default_reasoning_effort
        && let Some(default_id) = cfg.models.default.as_deref()
        && let Some(entry) = catalog.get_mut(default_id)
        && entry.info.supports_reasoning_effort
    {
        stamp_effort(&mut entry.info, effort);
    }

    if let Some(effort) = cfg.reasoning_effort_override {
        for entry in catalog.values_mut() {
            if model_offers_reasoning_effort(&entry.info, effort) {
                stamp_effort(&mut entry.info, effort);
            }
        }
    }

    catalog
}

/// The entry keeps its own model id, and `model_at` picks the id for this effort when a request is prepared.
fn stamp_effort(info: &mut config::ModelInfo, effort: ReasoningEffort) {
    info.reasoning_effort = Some(effort);
}

/// Whether `effort` is a value this model will accept on the wire.
fn model_offers_reasoning_effort(info: &config::ModelInfo, effort: ReasoningEffort) -> bool {
    if !info.supports_reasoning_effort {
        return false;
    }
    if info.reasoning_efforts.is_empty() {
        matches!(
            effort,
            ReasoningEffort::Low
                | ReasoningEffort::Medium
                | ReasoningEffort::High
                | ReasoningEffort::Xhigh
        )
    } else {
        info.reasoning_efforts.iter().any(|opt| opt.value == effort)
    }
}

/// True when an active `allowed_models` allowlist leaves no selectable model.
pub(crate) fn allowlist_matches_nothing(
    cfg: &config::Config,
    catalog: &IndexMap<String, ModelEntry>,
) -> bool {
    !effective_allowlist(cfg).is_unrestricted() && !catalog.values().any(|e| e.info.user_selectable)
}

/// Reject an `allowed_models` allowlist that leaves no selectable model, or excludes an explicitly configured default.
/// Run only against a real catalog.
/// Before a real catalog is fetched (P169, Astra r1 #7): a fail-closed pin refuses outright, and under a fleet pin an
/// explicit default or `-m` whose model id the pin does not allow is refused instead of falling back. A user list keeps
/// its old behaviour (checked once the catalog arrives).
pub(crate) fn validate_fleet_pin_pre_catalog(
    cfg: &config::Config,
    catalog: &IndexMap<String, ModelEntry>,
) -> Result<(), String> {
    let allowlist = effective_allowlist(cfg);
    let patterns = match &allowlist {
        EffectiveAllowlist::Invalid => return Err(allowlist_excludes_all_message(cfg)),
        EffectiveAllowlist::Fleet(p) => p.join(", "),
        EffectiveAllowlist::Unrestricted | EffectiveAllowlist::User(_) => return Ok(()),
    };
    for (src, id) in [
        ("default", cfg.models.default.as_deref()),
        ("-m flag", cfg.default_model_override.as_deref()),
    ] {
        let Some(id) = id else { continue };
        let model = catalog
            .get(id)
            .or_else(|| catalog.values().find(|e| e.has_model_id(id)))
            .map_or(id, |entry| entry.model.as_str());
        if !allowlist.is_selected(id, model) {
            return Err(format!(
                "\"{id}\" (your {src}) isn't allowed by your organization's policy \
                 (requirements.toml allowed_models: {patterns}). Choose an allowed model."
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_selectable(
    cfg: &config::Config,
    catalog: &IndexMap<String, ModelEntry>,
) -> Result<(), String> {
    let allowlist = effective_allowlist(cfg);
    let patterns = match &allowlist {
        EffectiveAllowlist::Unrestricted => return Ok(()),
        EffectiveAllowlist::Invalid => return Err(allowlist_excludes_all_message(cfg)),
        EffectiveAllowlist::Fleet(p) | EffectiveAllowlist::User(p) => p.join(", "),
    };
    if !catalog.values().any(|e| e.info.user_selectable) {
        return Err(if allowlist.is_fleet() {
            allowlist_excludes_all_message(cfg)
        } else {
            format!(
                "None of your available models match allowed_models ({patterns}). \
                 Broaden the patterns or remove allowed_models, then try again."
            )
        });
    }
    for (src, id) in [
        ("default", cfg.models.default.as_deref()),
        ("-m flag", cfg.default_model_override.as_deref()),
    ] {
        let Some(id) = id else { continue };
        let entry = catalog
            .get(id)
            .or_else(|| catalog.values().find(|e| e.has_model_id(id)));
        // P169 (Astra r2): under a fleet pin a choice the catalog does not know is judged by its id, not dropped.
        let refused = match entry {
            Some(entry) => !entry.info.user_selectable,
            None => allowlist.is_fleet() && !allowlist.is_selected(id, id),
        };
        if refused {
            return Err(if allowlist.is_fleet() {
                format!(
                    "\"{id}\" (your {src}) isn't allowed by your organization's policy \
                     (requirements.toml allowed_models: {patterns}). Choose an allowed model."
                )
            } else {
                format!(
                    "\"{id}\" (your {src}) isn't allowed by allowed_models ({patterns}). \
                     Add it to allowed_models, or set a different model."
                )
            });
        }
    }
    Ok(())
}
