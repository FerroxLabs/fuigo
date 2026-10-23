//! One model list that chooses for you.
//!
//! The same model can be reachable three ways: through Flux Router, through a signed-in subscription,
//! and through a provider key the user holds. The list shows it ONCE, with the route Fuigo will use,
//! picked by a fixed ranking:
//!
//! 1. Flux Router, when it is set up and serves the model.
//! 2. A signed-in subscription that includes the model.
//! 3. A direct provider key.
//!
//! Ties keep catalogue order. Models reachable by some route come first; models that need a connection
//! follow, each saying what to connect. Nothing here switches route on its own: a route is chosen once,
//! shown in the row and the status line, and an error on it is reported on it (see
//! `subscription::inference::auth_error`), never retried on another.

use crate::auth::provider_status::{Route, RouteKind};
use crate::agent::config::{ModelEntry, ModelPrice};
use indexmap::IndexMap;

/// `vendor/model` and `model` are the same model; case is not significant.
pub(crate) fn canonical_model_id(wire: &str) -> String {
    let t = wire.trim().to_ascii_lowercase();
    t.rsplit('/').next().unwrap_or(&t).to_string()
}

/// One way of reaching a model.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RouteChoice {
    /// Catalogue key of the entry that uses this route.
    pub key: String,
    pub route: Route,
    /// Usable right now.
    pub ready: bool,
    /// List price per million tokens, when this entry's catalogue publishes one.
    pub price: Option<ModelPrice>,
}

impl RouteChoice {
    /// The one-line reason shown beside the route.
    pub(crate) fn reason(&self) -> String {
        // The price, where the catalogue knows it, is the point of comparing routes.
        let priced = |base: String| match self.price {
            Some(p) => format!("{base}: {}", p.summary()),
            None => base,
        };
        match (self.route.kind, self.ready) {
            (RouteKind::Flux, true) => match self.price {
                Some(p) => format!("via Flux Router: {}", p.summary()),
                None => "via Flux Router: one key, every model".to_string(),
            },
            (RouteKind::Flux, false) => priced("needs a Flux Router key (fluxrouter.ai)".to_string()),
            (RouteKind::Subscription, _) => {
                format!("included in your {}: no per-token charge", self.route.label)
            }
            (RouteKind::Key, true) => priced(format!("billed to your {}", self.route.label)),
            (RouteKind::Key, false) => priced(format!("needs {}", self.route.label)),
        }
    }

    /// The word typed after `via` to pick this route: `flux`, `grok`, `chatgpt`, `openai`, ...
    pub(crate) fn word(&self) -> String {
        match self.route.kind {
            RouteKind::Flux => "flux".to_string(),
            _ => self
                .route
                .label
                .split_whitespace()
                .next()
                .unwrap_or("route")
                .to_ascii_lowercase(),
        }
    }
}

/// A model with every route to it, best first.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RankedModel {
    pub canonical: String,
    pub choices: Vec<RouteChoice>,
}

impl RankedModel {
    pub(crate) fn primary(&self) -> &RouteChoice {
        &self.choices[0]
    }
    /// Reachable by at least one route.
    pub(crate) fn reachable(&self) -> bool {
        self.primary().ready
    }
}

fn entry_ready(entry: &ModelEntry, kind: RouteKind, flux_ready: bool) -> bool {
    match kind {
        RouteKind::Flux => flux_ready,
        // A subscription entry exists only for a signed-in account (or a table the user wrote for one).
        RouteKind::Subscription => true,
        RouteKind::Key => entry.own_credential().is_some(),
    }
}

/// Group `catalog` by model, rank each model's routes, and order the models: reachable first, then the
/// ones that need a connection, each in catalogue order.
pub(crate) fn rank_catalog(
    catalog: &IndexMap<String, ModelEntry>,
    flux_ready: bool,
) -> Vec<RankedModel> {
    let mut groups: IndexMap<String, Vec<RouteChoice>> = IndexMap::new();
    for (key, entry) in catalog {
        let route = entry.route();
        let ready = entry_ready(entry, route.kind, flux_ready);
        groups
            .entry(canonical_model_id(&entry.info.model))
            .or_default()
            .push(RouteChoice {
                key: key.clone(),
                route,
                ready,
                price: entry.info.price,
            });
    }
    let mut ranked: Vec<RankedModel> = groups
        .into_iter()
        .map(|(canonical, mut choices)| {
            // Ready routes first, then by kind (Flux, subscription, key); the sort is stable, so ties keep
            // catalogue order.
            choices.sort_by_key(|c| (!c.ready, c.route.kind));
            RankedModel { canonical, choices }
        })
        .collect();
    ranked.sort_by_key(|m| !m.reachable());
    ranked
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::config::{EndpointsConfig, EnvKeys};
    use crate::auth::subscription::SubscriptionProvider;

    fn entry(wire: &str) -> ModelEntry {
        ModelEntry::fallback(wire, &EndpointsConfig::default())
    }

    fn flux_entry(wire: &str) -> ModelEntry {
        entry(wire)
    }

    fn subscription_entry(wire: &str, provider: SubscriptionProvider) -> ModelEntry {
        let mut e = entry(wire);
        let mut binding = crate::auth::AuthProviderRef::unresolved(format!("{} binding", provider.name()));
        binding.attach_trusted_config(Some(&crate::auth::AuthProviderConfig {
            subscription: Some(provider),
            ..Default::default()
        }));
        e.auth_provider = Some(binding);
        e
    }

    fn key_entry(wire: &str, var: &str) -> ModelEntry {
        let mut e = entry(wire);
        e.env_key = Some(EnvKeys::single(var));
        e
    }

    fn catalog(entries: Vec<(&str, ModelEntry)>) -> IndexMap<String, ModelEntry> {
        entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    #[test]
    fn canonical_ids_ignore_vendor_prefix_and_case() {
        assert_eq!(canonical_model_id("xai/Grok-4.7"), "grok-4.7");
        assert_eq!(canonical_model_id("grok-4.7"), "grok-4.7");
        assert_eq!(canonical_model_id(" openai/gpt-5 "), "gpt-5");
    }

    /// A model reachable through Flux, a subscription and a key appears ONCE, with all three routes.
    #[test]
    fn a_model_reachable_three_ways_is_listed_once() {
        let cat = catalog(vec![
            ("grok-4.7", flux_entry("grok-4.7")),
            ("xai/grok-4.7", subscription_entry("grok-4.7", SubscriptionProvider::Xai)),
            ("xai-key/grok-4.7", key_entry("grok-4.7", "XAI_API_KEY")),
        ]);
        let ranked = rank_catalog(&cat, true);
        assert_eq!(ranked.len(), 1, "one model, one row");
        let kinds: Vec<RouteKind> = ranked[0].choices.iter().map(|c| c.route.kind).collect();
        assert_eq!(kinds, vec![RouteKind::Flux, RouteKind::Subscription, RouteKind::Key]);
    }

    /// Every combination of Flux, subscription and key picks the best route that is ready.
    #[test]
    #[serial_test::serial]
    fn ranking_order_for_each_combination() {
        // (flux ready, has subscription entry, key env set) -> expected primary kind
        let cases = [
            (true, true, true, Some(RouteKind::Flux)),
            (true, true, false, Some(RouteKind::Flux)),
            (true, false, true, Some(RouteKind::Flux)),
            (true, false, false, Some(RouteKind::Flux)),
            (false, true, true, Some(RouteKind::Subscription)),
            (false, true, false, Some(RouteKind::Subscription)),
            (false, false, true, Some(RouteKind::Key)),
            (false, false, false, None),
        ];
        for (flux, sub, key, want) in cases {
            let var = "FUIGO_TEST_RANKING_KEY";
            let _guard = fuigo_test_support::EnvGuard::set(var, "sk-ranking-test-key-123456");
            let mut entries = vec![("grok-4.7", flux_entry("grok-4.7"))];
            if sub {
                entries.push(("xai/grok-4.7", subscription_entry("grok-4.7", SubscriptionProvider::Xai)));
            }
            if key {
                entries.push(("k/grok-4.7", key_entry("grok-4.7", var)));
            }
            let ranked = rank_catalog(&catalog(entries), flux);
            let primary = ranked[0].primary();
            match want {
                Some(kind) => {
                    assert!(primary.ready, "flux={flux} sub={sub} key={key}");
                    assert_eq!(primary.route.kind, kind, "flux={flux} sub={sub} key={key}");
                }
                None => assert!(!ranked[0].reachable(), "nothing ready: needs a connection"),
            }
        }
    }

    #[test]
    fn ties_keep_catalogue_order_and_reachable_models_come_first() {
        let cat = catalog(vec![
            ("needs-flux", flux_entry("alpha")),
            ("xai/beta", subscription_entry("beta", SubscriptionProvider::Xai)),
            ("chatgpt/gamma", subscription_entry("gamma", SubscriptionProvider::Chatgpt)),
            ("also-needs-flux", flux_entry("delta")),
        ]);
        let order: Vec<String> = rank_catalog(&cat, false).into_iter().map(|m| m.canonical).collect();
        assert_eq!(order, ["beta", "gamma", "alpha", "delta"]);
        // With Flux set up everything is reachable and the catalogue order stands.
        let order: Vec<String> = rank_catalog(&cat, true).into_iter().map(|m| m.canonical).collect();
        assert_eq!(order, ["alpha", "beta", "gamma", "delta"]);
    }

    /// The one-line reason carries the price per 1M tokens where the catalogue knows it, and says
    /// "included" for a subscription.
    #[test]
    fn route_reasons_show_the_price_where_the_catalogue_knows_it() {
        let mut flux = flux_entry("grok-4.7");
        flux.info.price = Some(ModelPrice { input_per_million: 2.5, output_per_million: 10.0 });
        let cat = catalog(vec![
            ("grok-4.7", flux),
            ("xai/grok-4.7", subscription_entry("grok-4.7", SubscriptionProvider::Xai)),
            ("k/grok-4.7", key_entry("grok-4.7", "XAI_API_KEY")),
        ]);
        let ranked = rank_catalog(&cat, true);
        let reasons: Vec<String> = ranked[0].choices.iter().map(|c| c.reason()).collect();
        assert_eq!(reasons[0], "via Flux Router: $2.5 in / $10 out per 1M tokens");
        assert_eq!(reasons[1], "included in your Grok subscription: no per-token charge");
        assert!(reasons[2].starts_with("needs ") || reasons[2].starts_with("billed to your "), "{reasons:?}");
        // No price published: the old wording stands.
        let cat = catalog(vec![("grok-4.7", flux_entry("grok-4.7"))]);
        assert_eq!(rank_catalog(&cat, true)[0].choices[0].reason(), "via Flux Router: one key, every model");
    }

    #[test]
    fn reasons_and_badges_name_the_route() {
        let cat = catalog(vec![
            ("grok-4.7", flux_entry("grok-4.7")),
            ("xai/grok-4.7", subscription_entry("grok-4.7", SubscriptionProvider::Xai)),
            ("k/grok-4.7", key_entry("grok-4.7", "OPENAI_API_KEY")),
        ]);
        let ranked = rank_catalog(&cat, false);
        let choices = &ranked[0].choices;
        assert_eq!(choices[0].route.badge(), "included in your Grok subscription");
        assert!(choices[0].reason().contains("no per-token charge"));
        let flux = choices.iter().find(|c| c.route.kind == RouteKind::Flux).unwrap();
        assert!(!flux.ready);
        assert!(flux.reason().contains("needs a Flux Router key"));
        assert_eq!(flux.word(), "flux");
        assert_eq!(choices[0].word(), "grok");
    }

    /// A provider key's listed models need no TOML: they join the ranked list under the same rule, so a
    /// model Flux Router also serves is ONE row with Flux first and the key behind it.
    #[tokio::test]
    #[serial_test::serial]
    async fn models_listed_for_a_provider_key_join_the_ranked_list_below_flux() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let home = fuigo_test_support::FuigoHome::new();
        let _k = fuigo_test_support::EnvGuard::set("OPENAI_API_KEY", "sk-test-openai-key-0123456789");
        let _a = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
        let _b = fuigo_test_support::EnvGuard::unset("FUIGO_CODE_API_KEY");
        crate::auth::key_models::write_cached_model_ids(
            home.path(),
            "openai",
            &["gpt-5".to_owned(), "only-on-the-key".to_owned()],
        )
        .unwrap();
        let mut resolved = crate::agent::config::resolve_model_list(&crate::agent::config::Config::default(), None);
        let listed = resolved.get("openai-key/gpt-5").expect("the key's model is listed with no TOML");
        assert_eq!(listed.info.model, "gpt-5");
        assert_eq!(listed.route().kind, RouteKind::Key);
        assert!(listed.route().label.contains("OpenAI key from OPENAI_API_KEY"), "{}", listed.route().label);
        assert!(listed.api_key.is_none(), "the secret is not copied into the entry");
        // Without Flux, the key is the route and the model is usable.
        let ranked = rank_catalog(&resolved, false);
        let only = ranked.iter().find(|m| m.canonical == "only-on-the-key").expect("listed");
        assert!(only.reachable() && only.primary().route.kind == RouteKind::Key);
        // With Flux serving gpt-5 too: one row, Flux first, the key as the alternate.
        resolved.insert("gpt-5".to_owned(), flux_entry("gpt-5"));
        let ranked = rank_catalog(&resolved, true);
        let rows: Vec<&RankedModel> = ranked.iter().filter(|m| m.canonical == "gpt-5").collect();
        assert_eq!(rows.len(), 1, "de-duplicated across Flux and the key");
        let kinds: Vec<RouteKind> = rows[0].choices.iter().map(|c| c.route.kind).collect();
        assert_eq!(kinds, vec![RouteKind::Flux, RouteKind::Key]);
    }

    // ---- the ACP list the clients paint ----

    fn meta_of<'a>(
        infos: &'a IndexMap<agent_client_protocol::ModelId, agent_client_protocol::ModelInfo>,
        key: &str,
    ) -> &'a serde_json::Map<String, serde_json::Value> {
        infos
            .get(&agent_client_protocol::ModelId::new(key.to_owned()))
            .unwrap_or_else(|| panic!("{key} listed"))
            .meta
            .as_ref()
            .expect("meta")
    }

    fn three_routes() -> IndexMap<String, ModelEntry> {
        catalog(vec![
            ("grok-4.7", flux_entry("grok-4.7")),
            ("xai/grok-4.7", subscription_entry("grok-4.7", SubscriptionProvider::Xai)),
            ("flux-only", flux_entry("flux-only")),
        ])
    }

    #[test]
    fn the_acp_list_carries_every_route_on_the_primary_and_marks_the_others() {
        // Session auth: Flux Router is set up, so it ranks first.
        let infos = super::super::resolution::available_models(&three_routes(), true);
        let primary = meta_of(&infos, "grok-4.7");
        let routes = primary["routes"].as_array().expect("routes");
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0]["word"], "flux");
        assert_eq!(routes[0]["badge"], "via Flux Router");
        assert_eq!(routes[1]["badge"], "included in your Grok subscription");
        assert_eq!(meta_of(&infos, "xai/grok-4.7")["altRouteOf"], "grok-4.7");
        assert!(!primary.contains_key("connect"));
    }

    #[test]
    #[serial_test::serial]
    fn without_flux_the_subscription_leads_and_flux_only_models_say_what_to_connect() {
        let _a = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
        let _b = fuigo_test_support::EnvGuard::unset("FUIGO_CODE_API_KEY");
        let infos = super::super::resolution::available_models(&three_routes(), false);
        let order: Vec<&str> = infos.keys().map(|k| k.0.as_ref()).collect();
        assert_eq!(order, ["xai/grok-4.7", "grok-4.7", "flux-only"], "reachable first, then connect");
        let primary = meta_of(&infos, "xai/grok-4.7");
        assert_eq!(primary["routes"][0]["badge"], "included in your Grok subscription");
        assert_eq!(meta_of(&infos, "grok-4.7")["altRouteOf"], "xai/grok-4.7");
        let connect = meta_of(&infos, "flux-only")["connect"].as_str().unwrap().to_owned();
        assert!(connect.contains("Flux Router key") && connect.contains("fluxrouter.ai"), "{connect}");
    }
}
