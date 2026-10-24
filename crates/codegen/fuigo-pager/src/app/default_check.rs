//! An explicit default model that cannot be reached while another connection can.
//!
//! The user set `[models] default` to a model that is reached through Flux Router, Flux Router is not
//! set up, and a subscription IS signed in. Fuigo never overrides an explicit default, so the first
//! prompt would fail with an authentication error. Say why at startup and offer the signed-in models.

use fuigo_shell::auth::provider_status::{ProviderStatus, RouteKind};

/// The warning text, or `None` when the default is usable (or unset, or nothing else is connected).
///
/// `explicit_default` is `[models] default` exactly as the user wrote it; `route_kind` is the route of
/// that model in the session's catalog (`None` when the catalog does not list it).
pub fn unusable_default_note(
    status: &ProviderStatus,
    explicit_default: Option<&str>,
    route_kind: Option<RouteKind>,
) -> Option<String> {
    let default = explicit_default?;
    if route_kind != Some(RouteKind::Flux) || status.flux_ready() {
        return None;
    }
    let signed_in: Vec<&str> = status
        .subscriptions
        .iter()
        .map(|s| s.provider.label())
        .collect();
    if signed_in.is_empty() {
        return None;
    }
    Some(format!(
        "Your default model {default} is reached through Flux Router, which is not set up. \
         You are signed in to {}: pick one of its models with /model, or add a Flux Router key with /login.",
        signed_in.join(" and ")
    ))
}

/// The route kind recorded in a model's `route` meta (see `fuigo_shell::agent::config::ROUTE_META_KEY`).
pub fn route_kind_of(info: &agent_client_protocol::ModelInfo) -> Option<RouteKind> {
    // No route on the model means Flux Router: only a subscription or a provider key says otherwise.
    let Some(kind) = info
        .meta
        .as_ref()
        .and_then(|m| m.get(fuigo_shell::agent::config::ROUTE_META_KEY))
        .and_then(|r| r.get("kind"))
        .and_then(|k| k.as_str())
    else {
        return Some(RouteKind::Flux);
    };
    match kind {
        "Subscription" => Some(RouteKind::Subscription),
        "Key" => Some(RouteKind::Key),
        _ => Some(RouteKind::Flux),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuigo_shell::auth::provider_status::FluxState;
    use fuigo_shell::auth::subscription::SubscriptionProvider;
    use fuigo_shell::auth::subscription::catalog::SignedIn;

    fn status(flux: FluxState, signed_in: bool) -> ProviderStatus {
        ProviderStatus {
            flux,
            subscriptions: if signed_in {
                vec![SignedIn {
                    provider: SubscriptionProvider::Xai,
                    accounts: vec!["acct".into()],
                    model_ids: vec!["grok-4.7".into()],
                }]
            } else {
                vec![]
            },
            env_keys: vec![],
            sso_configured: false,
        }
    }

    #[test]
    fn an_explicit_flux_default_with_no_flux_but_a_subscription_is_explained() {
        let note = unusable_default_note(
            &status(FluxState::NotSet, true),
            Some("flux-auto"),
            Some(RouteKind::Flux),
        )
        .expect("a note");
        assert!(note.contains("flux-auto") && note.contains("Flux Router"), "{note}");
        assert!(note.contains("Grok subscription") && note.contains("/model"), "{note}");
        assert!(!note.to_lowercase().contains("needs an api key"), "{note}");
    }

    #[test]
    fn nothing_to_say_when_the_default_is_usable_unset_or_alone() {
        let ready = FluxState::Saved { masked: "••••1234".into() };
        assert_eq!(
            unusable_default_note(&status(ready, true), Some("flux-auto"), Some(RouteKind::Flux)),
            None,
            "Flux is set up"
        );
        assert_eq!(
            unusable_default_note(&status(FluxState::NotSet, true), None, Some(RouteKind::Flux)),
            None,
            "an unset default is chosen by Fuigo, not blamed on the user"
        );
        assert_eq!(
            unusable_default_note(
                &status(FluxState::NotSet, true),
                Some("xai/grok-4.7"),
                Some(RouteKind::Subscription)
            ),
            None,
            "a subscription default is reachable"
        );
        assert_eq!(
            unusable_default_note(&status(FluxState::NotSet, false), Some("flux-auto"), Some(RouteKind::Flux)),
            None,
            "nothing else is connected: the picker is the answer, not a warning"
        );
    }

    #[test]
    fn the_route_kind_is_read_from_the_models_meta() {
        let mut meta = serde_json::Map::new();
        meta.insert(
            fuigo_shell::agent::config::ROUTE_META_KEY.to_owned(),
            serde_json::json!({ "label": "Grok subscription", "kind": "Subscription" }),
        );
        let info = agent_client_protocol::ModelInfo::new("xai/grok", "Grok").meta(Some(meta));
        assert_eq!(route_kind_of(&info), Some(RouteKind::Subscription));
        // No route on the wire means Flux Router.
        assert_eq!(
            route_kind_of(&agent_client_protocol::ModelInfo::new("x", "x")),
            Some(RouteKind::Flux)
        );
    }
}
